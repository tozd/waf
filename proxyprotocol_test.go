package waf_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/pires/go-proxyproto"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"golang.org/x/sync/errgroup"

	"gitlab.com/tozd/waf"
)

func policyFor(t *testing.T, policy func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error), addr net.Addr) proxyproto.Policy {
	t.Helper()

	p, err := policy(proxyproto.ConnPolicyOptions{Upstream: addr, Downstream: nil})
	require.NoError(t, err)
	return p
}

func tcpAddr(addr string) *net.TCPAddr {
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(addr), 12345))
}

func TestProxyProtocolSourcesPolicy(t *testing.T) {
	t.Parallel()

	sources, errE := waf.TestingNewTrustedSources("PROXY protocol", []string{"127.0.0.1", "10.0.0.0/8", "::1", "::ffff:192.168.0.0/112", "fd00::/8"})
	require.NoError(t, errE, "% -+#.1v", errE)

	for _, tt := range []struct {
		Addr     net.Addr
		Expected proxyproto.Policy
	}{
		{tcpAddr("127.0.0.1"), proxyproto.REQUIRE},
		{tcpAddr("127.0.0.2"), proxyproto.SKIP},
		{tcpAddr("10.1.2.3"), proxyproto.REQUIRE},
		{tcpAddr("11.1.2.3"), proxyproto.SKIP},
		{tcpAddr("::1"), proxyproto.REQUIRE},
		{tcpAddr("::2"), proxyproto.SKIP},
		// IPv4-mapped IPv6 addresses match as IPv4 addresses.
		{tcpAddr("::ffff:127.0.0.1"), proxyproto.REQUIRE},
		{tcpAddr("::ffff:10.1.2.3"), proxyproto.REQUIRE},
		{tcpAddr("192.168.1.1"), proxyproto.REQUIRE},
		{tcpAddr("192.169.1.1"), proxyproto.SKIP},
		// Zones are ignored.
		{tcpAddr("fd00::1%eth0"), proxyproto.REQUIRE},
		{&net.UnixAddr{Name: "/tmp/test.sock", Net: "unix"}, proxyproto.SKIP},
	} {
		t.Run(tt.Addr.String(), func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.Expected, policyFor(t, sources.ProxyProtocolPolicy, tt.Addr))
		})
	}
}

func TestProxyProtocolSourcesInvalid(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		Source string
		Error  string
	}{
		{"", "empty PROXY protocol source"},
		{"10.0.0.0/33", `invalid PROXY protocol source: netip.ParsePrefix("10.0.0.0/33"): prefix length out of range`},
		{"example.com/8", `invalid PROXY protocol source: netip.ParsePrefix("example.com/8"): ParseAddr("example.com"): unexpected character (at "example.com")`},
		{"exa mple.com", "invalid PROXY protocol source"},
		{"exa\tmple.com", "invalid PROXY protocol source"},
	} {
		t.Run(tt.Source, func(t *testing.T) {
			t.Parallel()

			httpsConfig := waf.HTTPS{ProxyProtocol: []string{"127.0.0.1", tt.Source}}
			assert.EqualError(t, httpsConfig.Validate(), tt.Error)

			httpConfig := waf.HTTP{ProxyProtocol: []string{tt.Source}}
			assert.EqualError(t, httpConfig.Validate(), tt.Error)
		})
	}

	httpsConfig := waf.HTTPS{ProxyProtocol: []string{"127.0.0.1", "10.0.0.0/8", "::1", "example.com", "project_proxy_1"}}
	assert.NoError(t, httpsConfig.Validate())
}

func TestProxyProtocolSourcesHostname(t *testing.T) {
	t.Parallel()

	sources, errE := waf.TestingNewTrustedSources("PROXY protocol", []string{"proxy.example.com"})
	require.NoError(t, errE, "% -+#.1v", errE)
	resolver := waf.TestingNewHostResolver(zerolog.Nop(), sources)

	var addrs atomic.Pointer[[]netip.Addr]
	addrs.Store(&[]netip.Addr{netip.MustParseAddr("172.18.0.5")})
	// When set, lookups fail with it.
	var lookupErr atomic.Pointer[net.DNSError]
	var lookups atomic.Int64
	resolver.Lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		assert.Equal(t, "proxy.example.com", host)
		lookups.Add(1)
		err := lookupErr.Load()
		if err != nil {
			return nil, err
		}
		return *addrs.Load(), nil
	}

	// Hostnames are not resolved before Refresh.
	assert.Equal(t, proxyproto.SKIP, policyFor(t, sources.ProxyProtocolPolicy, tcpAddr("172.18.0.5")))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	resolver.Refresh(ctx)
	assert.Equal(t, proxyproto.REQUIRE, policyFor(t, sources.ProxyProtocolPolicy, tcpAddr("172.18.0.5")))
	assert.Equal(t, proxyproto.SKIP, policyFor(t, sources.ProxyProtocolPolicy, tcpAddr("172.18.0.9")))

	// When resolving fails, the last addresses are kept.
	lookupErr.Store(&net.DNSError{Err: "server misbehaving", Name: "proxy.example.com", IsTemporary: true})
	resolver.Refresh(ctx)
	assert.Equal(t, proxyproto.REQUIRE, policyFor(t, sources.ProxyProtocolPolicy, tcpAddr("172.18.0.5")))

	// When the hostname does not exist anymore, its addresses are removed.
	lookupErr.Store(&net.DNSError{Err: "no such host", Name: "proxy.example.com", IsNotFound: true})
	resolver.Refresh(ctx)
	assert.Equal(t, proxyproto.SKIP, policyFor(t, sources.ProxyProtocolPolicy, tcpAddr("172.18.0.5")))

	lookupErr.Store(nil)
	resolver.Refresh(ctx)
	assert.Equal(t, proxyproto.REQUIRE, policyFor(t, sources.ProxyProtocolPolicy, tcpAddr("172.18.0.5")))

	go resolver.Run(ctx)

	// The hostname has a new address. A connection from it requests Run to resolve the hostname again.
	addrs.Store(&[]netip.Addr{netip.MustParseAddr("::ffff:172.18.0.9")})
	before := lookups.Load()
	assert.Equal(t, proxyproto.SKIP, policyFor(t, sources.ProxyProtocolPolicy, tcpAddr("172.18.0.9")))
	assert.Eventually(t, func() bool {
		return lookups.Load() > before
	}, 5*time.Second, 10*time.Millisecond)
	assert.Eventually(t, func() bool {
		return policyFor(t, sources.ProxyProtocolPolicy, tcpAddr("172.18.0.9")) == proxyproto.REQUIRE
	}, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, proxyproto.SKIP, policyFor(t, sources.ProxyProtocolPolicy, tcpAddr("172.18.0.5")))
}

// proxyProtocolClient returns an HTTP client which connects to addr from localIP (any address if empty)
// and sends header (if not empty) at the start of each connection.
func proxyProtocolClient(t *testing.T, addr, localIP, header, certPath string) *http.Client {
	t.Helper()

	certificate, err := os.ReadFile(certPath) //nolint:gosec
	require.NoError(t, err)
	rootCAs := x509.NewCertPool()
	require.True(t, rootCAs.AppendCertsFromPEM(certificate))

	dialer := &net.Dialer{}
	if localIP != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(localIP), Port: 0, Zone: ""}
	}

	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				conn, err := dialer.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				if header != "" {
					_, err = conn.Write([]byte(header))
					if err != nil {
						conn.Close() //nolint:errcheck,gosec
						return nil, err
					}
				}
				return conn, nil
			},
			TLSClientConfig: &tls.Config{
				RootCAs:    rootCAs,
				MinVersion: tls.VersionTLS12,
			},
			DisableKeepAlives: true,
		},
		// We do not follow redirects automatically.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// get makes a GET request with header (if not nil) and returns the response's status code.
func get(t *testing.T, client *http.Client, url string, header http.Header) (int, error) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	require.NoError(t, err)
	maps.Copy(req.Header, header)
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close() //nolint:errcheck
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, nil
}

func TestServerProxyProtocol(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "test_cert.pem")
	keyPath := filepath.Join(tempDir, "test_key.pem")

	errE := x.CreateTempCertificateFiles(certPath, keyPath, []string{"localhost"})
	require.NoError(t, errE, "% -+#.1v", errE)

	logs := &bytes.Buffer{}

	server := &waf.Server[*waf.Site]{
		Logger: zerolog.New(zerolog.SyncWriter(logs)),
		HTTPS: waf.HTTPS{
			CertFile:      certPath,
			KeyFile:       keyPath,
			Listen:        "127.0.0.1:0",
			ProxyProtocol: []string{"127.0.0.1"},
		},
		HTTP: waf.HTTP{
			Listen: "127.0.0.1:0",
			// It resolves to 127.0.0.1 (and possibly ::1).
			ProxyProtocol: []string{"localhost"},
		},
	}
	_, errE = server.Init(nil)
	require.NoError(t, errE, "% -+#.1v", errE)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	g := errgroup.Group{}

	// Remote address of the last request.
	var remoteAddr atomic.Pointer[string]

	g.Go(func() error {
		return server.Run(ctx, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			addr := req.RemoteAddr
			remoteAddr.Store(&addr)
			w.WriteHeader(http.StatusOK)
		}))
	})

	httpsAddr := server.ListenAddrHTTPS()
	require.NotEmpty(t, httpsAddr)
	httpAddr := server.ListenAddrHTTP()
	require.NotEmpty(t, httpAddr)

	_, httpsPort, err := net.SplitHostPort(httpsAddr)
	require.NoError(t, err)
	_, httpPort, err := net.SplitHostPort(httpAddr)
	require.NoError(t, err)
	httpsURL := "https://localhost:" + httpsPort + "/"
	httpURL := "http://localhost:" + httpPort + "/"

	// A connection from a source has to start with the header, and the client's address from it is used.
	code, err := get(t, proxyProtocolClient(t, httpsAddr, "127.0.0.1", "PROXY TCP4 203.0.113.45 127.0.0.1 51402 443\r\n", certPath), httpsURL, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "203.0.113.45:51402", *remoteAddr.Load())

	code, err = get(t, proxyProtocolClient(t, httpsAddr, "127.0.0.1", "PROXY TCP6 2001:db8::7 ::1 51402 443\r\n", certPath), httpsURL, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "[2001:db8::7]:51402", *remoteAddr.Load())

	_, err = get(t, proxyProtocolClient(t, httpsAddr, "127.0.0.1", "", certPath), httpsURL, nil)
	assert.Error(t, err)

	// A connection from another address does not use the PROXY protocol.
	code, err = get(t, proxyProtocolClient(t, httpsAddr, "127.0.0.2", "", certPath), httpsURL, nil)
	if errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Skip("127.0.0.2 is not available")
	}
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.True(t, strings.HasPrefix(*remoteAddr.Load(), "127.0.0.2:"), *remoteAddr.Load())

	_, err = get(t, proxyProtocolClient(t, httpsAddr, "127.0.0.2", "PROXY TCP4 203.0.113.45 127.0.0.1 51402 443\r\n", certPath), httpsURL, nil)
	assert.Error(t, err)

	// The HTTP server uses the PROXY protocol for its sources as well, and the client's address is logged.
	code, err = get(t, proxyProtocolClient(t, httpAddr, "127.0.0.1", "PROXY TCP4 198.51.100.7 127.0.0.1 40000 80\r\n", certPath), httpURL, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusPermanentRedirect, code)

	cancel()

	err = g.Wait()
	require.NoError(t, err, "% -+#.1v", err)

	clients := []string{}
	scanner := bufio.NewScanner(logs)
	for scanner.Scan() {
		var line struct {
			Message string `json:"message"`
			Client  string `json:"client"`
		}
		err := json.Unmarshal(scanner.Bytes(), &line)
		require.NoError(t, err)
		if line.Message == "RedirectHTTP" {
			clients = append(clients, line.Client)
		}
	}
	require.NoError(t, scanner.Err())
	assert.Equal(t, []string{"198.51.100.7"}, clients)
}

type proxyProtocolConfig struct {
	waf.Server[*waf.Site]
}

func (c *proxyProtocolConfig) Validate() error {
	// We have to call Validate on kong-embedded structs ourselves.
	// See: https://github.com/alecthomas/kong/issues/90
	err := c.HTTPS.Validate()
	if err != nil {
		return err
	}
	return c.HTTP.Validate()
}

func TestProxyProtocolKong(t *testing.T) {
	t.Parallel()

	vars := kong.Vars{
		"defaultListen":       ":8080",
		"defaultProxyTo":      "http://localhost:5173",
		"developmentModeHelp": "",
	}

	var config proxyProtocolConfig
	k, err := kong.New(&config, vars)
	require.NoError(t, err)
	_, err = k.Parse([]string{
		"--https.proxy-protocol", "127.0.0.1",
		"--https.proxy-protocol=reverse-proxy",
		"--https.proxy-protocol=10.0.0.0/8,::1",
		"--http.proxy-protocol", "localhost",
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"127.0.0.1", "reverse-proxy", "10.0.0.0/8", "::1"}, config.HTTPS.ProxyProtocol)
	assert.Equal(t, []string{"localhost"}, config.HTTP.ProxyProtocol)

	for _, args := range [][]string{
		{"--https.proxy-protocol", "10.0.0.0/33"},
		{"--http.proxy-protocol", "10.0.0.0/33"},
	} {
		var invalid proxyProtocolConfig
		k, err := kong.New(&invalid, vars)
		require.NoError(t, err)
		_, err = k.Parse(args)
		assert.EqualError(t, err, `invalid PROXY protocol source: netip.ParsePrefix("10.0.0.0/33"): prefix length out of range`)
	}
}

func TestServerProxyProtocolInvalid(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "test_cert.pem")
	keyPath := filepath.Join(tempDir, "test_key.pem")

	errE := x.CreateTempCertificateFiles(certPath, keyPath, []string{"localhost"})
	require.NoError(t, errE, "% -+#.1v", errE)

	server := &waf.Server[*waf.Site]{
		Logger: zerolog.Nop(),
		HTTPS: waf.HTTPS{
			CertFile:      certPath,
			KeyFile:       keyPath,
			ProxyProtocol: []string{"10.0.0.0/33"},
		},
	}
	_, errE = server.Init(nil)
	assert.EqualError(t, errE, `invalid PROXY protocol source: netip.ParsePrefix("10.0.0.0/33"): prefix length out of range`)
	assert.Equal(t, map[string]interface{}{"source": "10.0.0.0/33"}, errors.Details(errE))

	server = &waf.Server[*waf.Site]{
		Logger: zerolog.Nop(),
		HTTPS: waf.HTTPS{
			CertFile: certPath,
			KeyFile:  keyPath,
		},
		HTTP: waf.HTTP{
			ProxyProtocol: []string{""},
		},
	}
	_, errE = server.Init(nil)
	assert.EqualError(t, errE, "empty PROXY protocol source")
}

func TestHostResolverShared(t *testing.T) {
	t.Parallel()

	proxyProtocol, errE := waf.TestingNewTrustedSources("PROXY protocol", []string{"proxy.example.com", "10.0.0.0/8"})
	require.NoError(t, errE, "% -+#.1v", errE)
	forwardedFor, errE := waf.TestingNewTrustedSources("X-Forwarded-For", []string{"proxy.example.com", "other.example.com"})
	require.NoError(t, errE, "% -+#.1v", errE)
	// Sources without hostnames do not need a resolver.
	withoutHostnames, errE := waf.TestingNewTrustedSources("X-Forwarded-For", []string{"192.0.2.1"})
	require.NoError(t, errE, "% -+#.1v", errE)

	resolver := waf.TestingNewHostResolver(zerolog.Nop(), proxyProtocol, nil, forwardedFor, withoutHostnames)
	require.NotNil(t, resolver)

	var mu sync.Mutex
	lookups := map[string]int{}
	resolver.Lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		mu.Lock()
		defer mu.Unlock()
		lookups[host]++
		if host == "proxy.example.com" {
			return []netip.Addr{netip.MustParseAddr("172.18.0.5")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("172.18.0.6")}, nil
	}

	resolver.Refresh(t.Context())

	// Each hostname is resolved once, even if multiple sources use it.
	assert.Equal(t, map[string]int{"proxy.example.com": 1, "other.example.com": 1}, lookups)

	assert.True(t, proxyProtocol.Contains(netip.MustParseAddr("172.18.0.5")))
	assert.False(t, proxyProtocol.Contains(netip.MustParseAddr("172.18.0.6")))
	assert.True(t, forwardedFor.Contains(netip.MustParseAddr("172.18.0.5")))
	assert.True(t, forwardedFor.Contains(netip.MustParseAddr("172.18.0.6")))
	assert.True(t, withoutHostnames.Contains(netip.MustParseAddr("192.0.2.1")))
	assert.False(t, withoutHostnames.Contains(netip.MustParseAddr("172.18.0.5")))

	// No resolver is needed without any hostnames.
	assert.Nil(t, waf.TestingNewHostResolver(zerolog.Nop(), withoutHostnames, nil))
}
