package waf

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
)

// forwardedForFeature names the X-Forwarded-For header in errors about its trusted sources.
const forwardedForFeature = "X-Forwarded-For"

// forwardedForProxyContextKey provides the address of the proxy which sent the request on behalf of the client.
var forwardedForProxyContextKey = &contextKey{"forwarded-for-proxy"} //nolint:gochecknoglobals

// forwardedForHandler uses the client's address from the X-Forwarded-For header as the remote address of requests
// from sources, keeping the port of the proxy's connection. Other requests are passed on unchanged.
//
// The address of the proxy is stored in the request's context, so that forwardedForProxyHandler can log it.
func forwardedForHandler(sources *trustedSources, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		peer, err := netip.ParseAddrPort(req.RemoteAddr)
		if err != nil || !sources.Trusts(peer.Addr()) {
			next.ServeHTTP(w, req)
			return
		}

		client, ok := forwardedForClient(sources, req.Header.Values("X-Forwarded-For"))
		if !ok {
			next.ServeHTTP(w, req)
			return
		}

		req = req.WithContext(context.WithValue(req.Context(), forwardedForProxyContextKey, normalizeAddr(peer.Addr())))
		req.RemoteAddr = netip.AddrPortFrom(client, peer.Port()).String()
		next.ServeHTTP(w, req)
	})
}

// forwardedForClient returns the client's address from values of X-Forwarded-For headers. It is the right-most
// address which does not match sources, or the left-most address if all of them match. It returns false if there
// are no addresses, or if an address which would have to be checked cannot be parsed.
func forwardedForClient(sources *trustedSources, values []string) (netip.Addr, bool) {
	entries := []string{}
	for _, value := range values {
		for entry := range strings.SplitSeq(value, ",") {
			entry = strings.TrimSpace(entry)
			if entry != "" {
				entries = append(entries, entry)
			}
		}
	}

	// Proxies append addresses on the right, so addresses on the left can be set by the client to anything.
	// We skip addresses of trusted proxies from the right and use the first other address.
	for i, entry := range slices.Backward(entries) {
		addr, ok := parseForwardedForAddr(entry)
		if !ok {
			return netip.Addr{}, false
		}
		if i == 0 || !sources.Contains(addr) {
			return addr, true
		}
	}

	return netip.Addr{}, false
}

// parseForwardedForAddr parses an address from X-Forwarded-For header, which can also include a port.
func parseForwardedForAddr(entry string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(entry)
	if err == nil {
		return normalizeAddr(addr), true
	}
	addrPort, err := netip.ParseAddrPort(entry)
	if err == nil {
		return normalizeAddr(addrPort.Addr()), true
	}
	if strings.HasPrefix(entry, "[") && strings.HasSuffix(entry, "]") {
		addr, err = netip.ParseAddr(entry[1 : len(entry)-1])
		if err == nil {
			return normalizeAddr(addr), true
		}
	}
	return netip.Addr{}, false
}

// forwardedForProxyHandler logs the address of the proxy which sent the request on behalf of the client,
// when the client's address has been taken from the X-Forwarded-For header.
func forwardedForProxyHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		proxy, ok := req.Context().Value(forwardedForProxyContextKey).(netip.Addr)
		if ok {
			logger := hlog.FromRequest(req)
			logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
				return c.Str("proxy", proxy.String())
			})
		}
		next.ServeHTTP(w, req)
	})
}
