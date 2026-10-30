package waf

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/rs/zerolog"
	"gitlab.com/tozd/go/errors"
	"golang.org/x/net/idna"
)

const (
	hostResolverRefreshInterval    = 5 * time.Second
	hostResolverMinRefreshInterval = time.Second
	hostResolverLookupTimeout      = 5 * time.Second
)

// trustedSources matches addresses against sources trusted for a feature, e.g., for sending the PROXY protocol header.
//
// Sources are IP addresses, CIDR networks, and hostnames. Addresses of hostnames are provided by a hostResolver,
// so that sources which change their addresses (e.g., Docker containers) can be configured by their hostnames.
type trustedSources struct {
	// Feature for which sources are trusted, used in error messages.
	Feature string

	prefixes []netip.Prefix
	hosts    []string

	// Set by newHostResolver. Without it, hostnames do not match any address.
	resolver *hostResolver
}

// newTrustedSources parses sources trusted for feature (e.g., "PROXY protocol"), each of which is an IP address,
// a CIDR network, or a hostname. Feature is used in error messages. It does not resolve hostnames.
// It returns nil if there are no sources.
func newTrustedSources(feature string, sources []string) (*trustedSources, errors.E) {
	if len(sources) == 0 {
		return nil, nil //nolint:nilnil
	}

	t := &trustedSources{
		Feature:  feature,
		prefixes: nil,
		hosts:    nil,
		resolver: nil,
	}

	for _, source := range sources {
		prefix, host, errE := parseTrustedSource(feature, source)
		if errE != nil {
			return nil, errE
		}
		if host != "" {
			t.hosts = append(t.hosts, host)
		} else {
			t.prefixes = append(t.prefixes, prefix)
		}
	}

	return t, nil
}

// parseTrustedSource returns the prefix for an IP address or a CIDR network, or the hostname otherwise.
func parseTrustedSource(feature, source string) (netip.Prefix, string, errors.E) {
	if strings.Contains(source, "/") {
		prefix, err := netip.ParsePrefix(source)
		if err != nil {
			errE := errors.WithMessage(err, "invalid "+feature+" source")
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
		return netip.Prefix{}, "", errors.New("empty " + feature + " source")
	}
	if strings.ContainsFunc(source, unicode.IsSpace) {
		errE := errors.New("invalid " + feature + " source")
		errors.Details(errE)["source"] = source
		return netip.Prefix{}, "", errE
	}

	// Hostnames of Docker containers can contain underscores, so we do not limit hostnames to letters,
	// digits, and hyphens.
	host, err := idna.New(idna.MapForLookup(), idna.StrictDomainName(false)).ToASCII(source)
	if err != nil {
		errE := errors.WithMessage(err, "invalid "+feature+" source")
		errors.Details(errE)["source"] = source
		return netip.Prefix{}, "", errE
	}

	return netip.Prefix{}, host, nil
}

// normalizeAddr returns addr in the form in which addresses are matched.
func normalizeAddr(addr netip.Addr) netip.Addr {
	// A dual-stack listener reports IPv4 clients with IPv4-mapped IPv6 addresses.
	// Prefix.Contains does not match addresses with a zone.
	return addr.Unmap().WithZone("")
}

// Contains reports whether addr matches one of the sources.
func (t *trustedSources) Contains(addr netip.Addr) bool {
	addr = normalizeAddr(addr)
	for _, prefix := range t.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}

	if t.resolver != nil {
		hostAddrs := *t.resolver.current.Load()
		for _, host := range t.hosts {
			if slices.Contains(hostAddrs[host], addr) {
				return true
			}
		}
	}

	return false
}

// Trusts reports whether addr matches one of the sources, like Contains. Use it for the address of the peer
// of a connection: if the address does not match, Trusts requests the resolver to resolve hostnames again,
// because the address could be a new address of a hostname. It never blocks.
func (t *trustedSources) Trusts(addr netip.Addr) bool {
	if t.Contains(addr) {
		return true
	}

	if t.resolver != nil && len(t.hosts) > 0 {
		t.resolver.requestRefresh()
	}

	return false
}

// hostResolver resolves hostnames of trusted sources, with Refresh and Run. Each hostname is resolved once,
// even if multiple trusted sources use it.
type hostResolver struct {
	Logger zerolog.Logger

	// Lookup resolves a hostname to its IP addresses.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)

	hosts []string

	// Addresses of hosts from their last successful lookups. Protected by mu.
	hostAddrs map[string][]netip.Addr
	mu        sync.Mutex

	// A copy of hostAddrs which trusted sources read. It is replaced and never modified.
	current atomic.Pointer[map[string][]netip.Addr]

	// Requests to resolve hosts again.
	refresh chan struct{}
}

// newHostResolver returns a resolver for hostnames of all sources and makes sources use it.
// Nil sources are skipped. It does not resolve hostnames. It returns nil if there are no hostnames.
func newHostResolver(logger zerolog.Logger, sources ...*trustedSources) *hostResolver {
	r := &hostResolver{
		Logger:    logger,
		Lookup:    lookupNetIP,
		hosts:     nil,
		hostAddrs: map[string][]netip.Addr{},
		mu:        sync.Mutex{},
		current:   atomic.Pointer[map[string][]netip.Addr]{},
		refresh:   make(chan struct{}, 1),
	}
	r.current.Store(&map[string][]netip.Addr{})

	for _, s := range sources {
		if s == nil || len(s.hosts) == 0 {
			continue
		}
		s.resolver = r
		for _, host := range s.hosts {
			if !slices.Contains(r.hosts, host) {
				r.hosts = append(r.hosts, host)
			}
		}
	}

	if len(r.hosts) == 0 {
		return nil
	}

	return r
}

func lookupNetIP(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	return addrs, errors.WithStack(err)
}

// requestRefresh requests Run to resolve hostnames again. It never blocks.
func (r *hostResolver) requestRefresh() {
	select {
	case r.refresh <- struct{}{}:
	default:
	}
}

// Refresh resolves hostnames again. If resolving a hostname fails, its addresses from the last
// successful lookup are kept, unless the hostname does not exist anymore. Failures are logged.
func (r *hostResolver) Refresh(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, host := range r.hosts {
		addrs, err := r.lookup(ctx, host)
		if ctx.Err() != nil {
			// We are stopping.
			return
		}
		if err != nil {
			errE := errors.WithMessage(err, "unable to resolve trusted source")
			errors.Details(errE)["host"] = host
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				delete(r.hostAddrs, host)
			} else {
				errors.Details(errE)["kept"] = len(r.hostAddrs[host])
			}
			r.Logger.Warn().Err(errE).Send()
			continue
		}
		normalized := make([]netip.Addr, 0, len(addrs))
		for _, addr := range addrs {
			normalized = append(normalized, normalizeAddr(addr))
		}
		r.hostAddrs[host] = normalized
	}

	current := make(map[string][]netip.Addr, len(r.hostAddrs))
	for host, addrs := range r.hostAddrs {
		current[host] = slices.Clone(addrs)
	}
	r.current.Store(&current)
}

func (r *hostResolver) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, hostResolverLookupTimeout)
	defer cancel()
	return r.Lookup(ctx, host)
}

// Run resolves hostnames again periodically and when trusted sources request it, until ctx is canceled.
// It expects that Refresh has been called just before.
func (r *hostResolver) Run(ctx context.Context) {
	ticker := time.NewTicker(hostResolverRefreshInterval)
	defer ticker.Stop()

	lastRefresh := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-r.refresh:
			// Requests from trusted sources are rate limited because connections from any address can make them.
			wait := time.Until(lastRefresh.Add(hostResolverMinRefreshInterval))
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
		r.Refresh(ctx)
		lastRefresh = time.Now()
	}
}
