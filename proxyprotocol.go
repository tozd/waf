package waf

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/pires/go-proxyproto"
	"github.com/rs/zerolog"
	"gitlab.com/tozd/go/errors"
	"golang.org/x/net/idna"
)

const (
	proxyProtocolRefreshInterval    = 5 * time.Second
	proxyProtocolMinRefreshInterval = time.Second
	proxyProtocolLookupTimeout      = 5 * time.Second
)

// proxyProtocolSources decides for each accepted connection, based on the connection's source address,
// whether the connection has to start with the PROXY protocol header.
//
// Sources are IP addresses, CIDR networks, and hostnames. Hostnames are resolved by Refresh and Run,
// so that sources which change their addresses (e.g., Docker containers) can be configured by their hostnames.
type proxyProtocolSources struct {
	Logger zerolog.Logger

	// Lookup resolves a hostname to its IP addresses.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)

	prefixes []netip.Prefix
	hosts    []string

	// Addresses of hosts from their last successful lookups. Protected by mu.
	hostAddrs map[string][]netip.Addr
	mu        sync.Mutex

	// Prefixes and addresses of hosts against which source addresses are matched.
	current atomic.Pointer[[]netip.Prefix]

	// Requests to resolve hosts again.
	refresh chan struct{}
}

// newProxyProtocolSources parses sources, each of which is an IP address, a CIDR network, or a hostname.
// It does not resolve hostnames. It returns nil if there are no sources.
func newProxyProtocolSources(logger zerolog.Logger, sources []string) (*proxyProtocolSources, errors.E) {
	if len(sources) == 0 {
		return nil, nil //nolint:nilnil
	}

	p := &proxyProtocolSources{
		Logger:    logger,
		Lookup:    lookupNetIP,
		prefixes:  nil,
		hosts:     nil,
		hostAddrs: map[string][]netip.Addr{},
		mu:        sync.Mutex{},
		current:   atomic.Pointer[[]netip.Prefix]{},
		refresh:   make(chan struct{}, 1),
	}

	for _, source := range sources {
		prefix, host, errE := parseProxyProtocolSource(source)
		if errE != nil {
			return nil, errE
		}
		if host != "" {
			p.hosts = append(p.hosts, host)
		} else {
			p.prefixes = append(p.prefixes, prefix)
		}
	}

	p.update()

	return p, nil
}

func lookupNetIP(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	return addrs, errors.WithStack(err)
}

// parseProxyProtocolSource returns the prefix for an IP address or a CIDR network, or the hostname otherwise.
func parseProxyProtocolSource(source string) (netip.Prefix, string, errors.E) {
	if strings.Contains(source, "/") {
		prefix, err := netip.ParsePrefix(source)
		if err != nil {
			errE := errors.WithMessage(err, "invalid PROXY protocol source")
			errors.Details(errE)["source"] = source
			return netip.Prefix{}, "", errE
		}
		prefix = prefix.Masked()
		// We match unmapped addresses, so a prefix of IPv4-mapped IPv6 addresses is converted to an IPv4 prefix.
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96) //nolint:mnd
		}
		return prefix, "", nil
	}

	addr, err := netip.ParseAddr(source)
	if err == nil {
		addr = normalizeAddr(addr)
		return netip.PrefixFrom(addr, addr.BitLen()), "", nil
	}

	if source == "" {
		return netip.Prefix{}, "", errors.New("empty PROXY protocol source")
	}
	if strings.ContainsFunc(source, unicode.IsSpace) {
		errE := errors.New("invalid PROXY protocol source")
		errors.Details(errE)["source"] = source
		return netip.Prefix{}, "", errE
	}

	// Hostnames of Docker containers can contain underscores, so we do not limit hostnames to letters,
	// digits, and hyphens.
	host, err := idna.New(idna.MapForLookup(), idna.StrictDomainName(false)).ToASCII(source)
	if err != nil {
		errE := errors.WithMessage(err, "invalid PROXY protocol source")
		errors.Details(errE)["source"] = source
		return netip.Prefix{}, "", errE
	}

	return netip.Prefix{}, host, nil
}

// normalizeAddr returns addr in the form in which source addresses are matched.
func normalizeAddr(addr netip.Addr) netip.Addr {
	// A dual-stack listener reports IPv4 clients with IPv4-mapped IPv6 addresses.
	// Prefix.Contains does not match addresses with a zone.
	return addr.Unmap().WithZone("")
}

// update makes prefixes and the current addresses of hosts the ones against which source addresses are matched.
func (p *proxyProtocolSources) update() {
	current := make([]netip.Prefix, 0, len(p.prefixes)+len(p.hostAddrs))
	current = append(current, p.prefixes...)
	for _, host := range p.hosts {
		for _, addr := range p.hostAddrs[host] {
			current = append(current, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	p.current.Store(&current)
}

// Policy returns proxyproto.REQUIRE for connections from sources and proxyproto.SKIP for other connections.
// It never blocks and never returns an error, because proxyproto.Listener calls it in Accept.
//
// For a connection from an address which does not match, it requests Run to resolve hostnames again,
// because the address could be a new address of a hostname.
func (p *proxyProtocolSources) Policy(options proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
	// Upstream is the connection's source address.
	tcpAddr, ok := options.Upstream.(*net.TCPAddr)
	if !ok {
		return proxyproto.SKIP, nil
	}
	addr := normalizeAddr(tcpAddr.AddrPort().Addr())

	for _, prefix := range *p.current.Load() {
		if prefix.Contains(addr) {
			return proxyproto.REQUIRE, nil
		}
	}

	if len(p.hosts) > 0 {
		select {
		case p.refresh <- struct{}{}:
		default:
		}
	}

	return proxyproto.SKIP, nil
}

// Refresh resolves hostnames again. If resolving a hostname fails, its addresses from the last
// successful lookup are kept, unless the hostname does not exist anymore. Failures are logged.
func (p *proxyProtocolSources) Refresh(ctx context.Context) {
	if len(p.hosts) == 0 {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, host := range p.hosts {
		addrs, err := p.lookup(ctx, host)
		if ctx.Err() != nil {
			// We are stopping.
			return
		}
		if err != nil {
			errE := errors.WithMessage(err, "unable to resolve PROXY protocol source")
			errors.Details(errE)["host"] = host
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				delete(p.hostAddrs, host)
			} else {
				errors.Details(errE)["kept"] = len(p.hostAddrs[host])
			}
			p.Logger.Warn().Err(errE).Send()
			continue
		}
		normalized := make([]netip.Addr, 0, len(addrs))
		for _, addr := range addrs {
			normalized = append(normalized, normalizeAddr(addr))
		}
		p.hostAddrs[host] = normalized
	}

	p.update()
}

func (p *proxyProtocolSources) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, proxyProtocolLookupTimeout)
	defer cancel()
	return p.Lookup(ctx, host)
}

// Run resolves hostnames again periodically and when Policy requests it, until ctx is canceled.
// It expects that Refresh has been called just before.
func (p *proxyProtocolSources) Run(ctx context.Context) {
	if len(p.hosts) == 0 {
		return
	}

	ticker := time.NewTicker(proxyProtocolRefreshInterval)
	defer ticker.Stop()

	lastRefresh := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-p.refresh:
			// Requests from Policy are rate limited because connections from any address can make them.
			wait := time.Until(lastRefresh.Add(proxyProtocolMinRefreshInterval))
			if wait > 0 {
				timer := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}
		p.Refresh(ctx)
		lastRefresh = time.Now()
	}
}

// listen listens on TCP address addr, or on defaultAddr if addr is empty. If sources is not nil, connections
// from sources have to start with the PROXY protocol header, and the client's address from the header is used
// as their remote address.
func listen(ctx context.Context, addr, defaultAddr string, sources *proxyProtocolSources) (net.Listener, errors.E) {
	if addr == "" {
		addr = defaultAddr
	}

	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if sources == nil {
		return listener, nil
	}

	// Policy field is deprecated in favor of ConnPolicy.
	return &proxyproto.Listener{ //nolint:exhaustruct
		Listener:          listener,
		ConnPolicy:        sources.Policy,
		ValidateHeader:    nil,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadBufferSize:    0,
	}, nil
}
