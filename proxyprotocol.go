package waf

import (
	"context"
	"net"

	"github.com/pires/go-proxyproto"
	"gitlab.com/tozd/go/errors"
)

// proxyProtocolFeature names the PROXY protocol in errors about its trusted sources.
const proxyProtocolFeature = "PROXY protocol"

// ProxyProtocolPolicy returns proxyproto.REQUIRE for connections from sources and proxyproto.SKIP for other
// connections. It never blocks and never returns an error, because proxyproto.Listener calls it in Accept.
func (t *trustedSources) ProxyProtocolPolicy(options proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
	// Upstream is the connection's source address.
	tcpAddr, ok := options.Upstream.(*net.TCPAddr)
	if !ok {
		return proxyproto.SKIP, nil
	}

	if t.Trusts(tcpAddr.AddrPort().Addr()) {
		return proxyproto.REQUIRE, nil
	}

	return proxyproto.SKIP, nil
}

// listen listens on TCP address addr, or on defaultAddr if addr is empty. If sources is not nil, connections
// from sources have to start with the PROXY protocol header, and the client's address from the header is used
// as their remote address.
func listen(ctx context.Context, addr, defaultAddr string, sources *trustedSources) (net.Listener, errors.E) {
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
		ConnPolicy:        sources.ProxyProtocolPolicy,
		ValidateHeader:    nil,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadBufferSize:    0,
	}, nil
}
