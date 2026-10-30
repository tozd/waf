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

	"github.com/rs/zerolog"
	"gitlab.com/tozd/go/errors"
	"golang.org/x/net/idna"
)

const (
	trustedSourcesRefreshInterval    = 5 * time.Second
	trustedSourcesMinRefreshInterval = time.Second
	trustedSourcesLookupTimeout      = 5 * time.Second
)

// trustedSources matches addresses against sources trusted for a feature, e.g., for sending the PROXY protocol header.
//
// Sources are IP addresses, CIDR networks, and hostnames. Hostnames are resolved by Refresh and Run,
// so that sources which change their addresses (e.g., Docker containers) can be configured by their hostnames.
type trustedSources struct {
	Logger zerolog.Logger

	// Lookup resolves a hostname to its IP addresses.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)

	// Feature for which sources are trusted, used in error messages.
	Feature string

	prefixes []netip.Prefix
	hosts    []string

	// Addresses of hosts from their last successful lookups. Protected by mu.
	hostAddrs map[string][]netip.Addr
	mu        sync.Mutex

	// Prefixes and addresses of hosts against which addresses are matched.
	current atomic.Pointer[[]netip.Prefix]

	// Requests to resolve hosts again.
	refresh chan struct{}
}

// newTrustedSources parses sources trusted for feature (e.g., "PROXY protocol"), each of which is an IP address,
// a CIDR network, or a hostname. Feature is used in error messages. It does not resolve hostnames.
// It returns nil if there are no sources.
func newTrustedSources(logger zerolog.Logger, feature string, sources []string) (*trustedSources, errors.E) {
	if len(sources) == 0 {
		return nil, nil //nolint:nilnil
	}

	t := &trustedSources{
		Logger:    logger,
		Lookup:    lookupNetIP,
		Feature:   feature,
		prefixes:  nil,
		hosts:     nil,
		hostAddrs: map[string][]netip.Addr{},
		mu:        sync.Mutex{},
		current:   atomic.Pointer[[]netip.Prefix]{},
		refresh:   make(chan struct{}, 1),
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

	t.update()

	return t, nil
}

func lookupNetIP(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	return addrs, errors.WithStack(err)
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

// update makes prefixes and the current addresses of hosts the ones against which addresses are matched.
func (t *trustedSources) update() {
	current := make([]netip.Prefix, 0, len(t.prefixes)+len(t.hostAddrs))
	current = append(current, t.prefixes...)
	for _, host := range t.hosts {
		for _, addr := range t.hostAddrs[host] {
			current = append(current, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	t.current.Store(&current)
}

// Contains reports whether addr matches one of the sources.
func (t *trustedSources) Contains(addr netip.Addr) bool {
	addr = normalizeAddr(addr)
	for _, prefix := range *t.current.Load() {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Trusts reports whether addr matches one of the sources, like Contains. Use it for the address of the peer
// of a connection: if the address does not match, Trusts requests Run to resolve hostnames again, because
// the address could be a new address of a hostname. It never blocks.
func (t *trustedSources) Trusts(addr netip.Addr) bool {
	if t.Contains(addr) {
		return true
	}

	if len(t.hosts) > 0 {
		select {
		case t.refresh <- struct{}{}:
		default:
		}
	}

	return false
}

// Refresh resolves hostnames again. If resolving a hostname fails, its addresses from the last
// successful lookup are kept, unless the hostname does not exist anymore. Failures are logged.
func (t *trustedSources) Refresh(ctx context.Context) {
	if len(t.hosts) == 0 {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	for _, host := range t.hosts {
		addrs, err := t.lookup(ctx, host)
		if ctx.Err() != nil {
			// We are stopping.
			return
		}
		if err != nil {
			errE := errors.WithMessage(err, "unable to resolve "+t.Feature+" source")
			errors.Details(errE)["host"] = host
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				delete(t.hostAddrs, host)
			} else {
				errors.Details(errE)["kept"] = len(t.hostAddrs[host])
			}
			t.Logger.Warn().Err(errE).Send()
			continue
		}
		normalized := make([]netip.Addr, 0, len(addrs))
		for _, addr := range addrs {
			normalized = append(normalized, normalizeAddr(addr))
		}
		t.hostAddrs[host] = normalized
	}

	t.update()
}

func (t *trustedSources) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, trustedSourcesLookupTimeout)
	defer cancel()
	return t.Lookup(ctx, host)
}

// Run resolves hostnames again periodically and when Trusts requests it, until ctx is canceled.
// It expects that Refresh has been called just before.
func (t *trustedSources) Run(ctx context.Context) {
	if len(t.hosts) == 0 {
		return
	}

	ticker := time.NewTicker(trustedSourcesRefreshInterval)
	defer ticker.Stop()

	lastRefresh := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-t.refresh:
			// Requests from Trusts are rate limited because connections from any address can make them.
			wait := time.Until(lastRefresh.Add(trustedSourcesMinRefreshInterval))
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
		t.Refresh(ctx)
		lastRefresh = time.Now()
	}
}
