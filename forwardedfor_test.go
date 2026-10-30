package waf_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"golang.org/x/sync/errgroup"

	"gitlab.com/tozd/waf"
)

func TestForwardedForHandler(t *testing.T) {
	t.Parallel()

	sources, errE := waf.TestingNewTrustedSources("X-Forwarded-For", []string{"127.0.0.1", "10.0.0.0/8", "::1"})
	require.NoError(t, errE, "% -+#.1v", errE)

	for _, tt := range []struct {
		Name     string
		Peer     string
		Headers  []string
		Expected string
	}{
		{"single", "127.0.0.1:1234", []string{"203.0.113.45"}, "203.0.113.45:1234"},
		{"ipv6", "[::1]:1234", []string{"2001:db8::7"}, "[2001:db8::7]:1234"},
		{"ipv4 mapped peer", "[::ffff:127.0.0.1]:1234", []string{"203.0.113.45"}, "203.0.113.45:1234"},
		{"ipv4 mapped client", "127.0.0.1:1234", []string{"::ffff:203.0.113.45"}, "203.0.113.45:1234"},
		// The client can put anything on the left.
		{"spoofed", "127.0.0.1:1234", []string{"198.51.100.1, 203.0.113.45"}, "203.0.113.45:1234"},
		{"trusted proxies", "127.0.0.1:1234", []string{"203.0.113.45, 10.0.0.5, 10.0.0.6"}, "203.0.113.45:1234"},
		{"multiple headers", "127.0.0.1:1234", []string{"198.51.100.1", "203.0.113.45, 10.0.0.5"}, "203.0.113.45:1234"},
		{"all trusted", "127.0.0.1:1234", []string{"10.0.0.5, 10.0.0.6"}, "10.0.0.5:1234"},
		{"port", "127.0.0.1:1234", []string{"203.0.113.45:8080"}, "203.0.113.45:1234"},
		{"ipv6 port", "127.0.0.1:1234", []string{"[2001:db8::7]:8080"}, "[2001:db8::7]:1234"},
		{"ipv6 brackets", "127.0.0.1:1234", []string{"[2001:db8::7]"}, "[2001:db8::7]:1234"},
		{"invalid client", "127.0.0.1:1234", []string{"203.0.113.45, invalid"}, "127.0.0.1:1234"},
		{"invalid on the left", "127.0.0.1:1234", []string{"invalid, 203.0.113.45"}, "203.0.113.45:1234"},
		{"empty", "127.0.0.1:1234", []string{" , "}, "127.0.0.1:1234"},
		{"no header", "127.0.0.1:1234", nil, "127.0.0.1:1234"},
		{"untrusted peer", "192.0.2.9:1234", []string{"203.0.113.45"}, "192.0.2.9:1234"},
	} {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			var remoteAddr string
			handler := waf.TestingForwardedForHandler(sources, http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
				remoteAddr = req.RemoteAddr
			}))

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			req.RemoteAddr = tt.Peer
			for _, header := range tt.Headers {
				req.Header.Add("X-Forwarded-For", header)
			}
			handler.ServeHTTP(httptest.NewRecorder(), req)

			assert.Equal(t, tt.Expected, remoteAddr)
		})
	}
}

func TestForwardedForSourcesInvalid(t *testing.T) {
	t.Parallel()

	httpsConfig := waf.HTTPS{ForwardedFor: []string{"10.0.0.0/33"}}
	assert.EqualError(t, httpsConfig.Validate(), `invalid X-Forwarded-For source: netip.ParsePrefix("10.0.0.0/33"): prefix length out of range`)

	httpConfig := waf.HTTP{ForwardedFor: []string{""}}
	assert.EqualError(t, httpConfig.Validate(), "empty X-Forwarded-For source")
}

func TestServerForwardedFor(t *testing.T) {
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
			CertFile:     certPath,
			KeyFile:      keyPath,
			Listen:       "127.0.0.1:0",
			ForwardedFor: []string{"127.0.0.1"},
		},
		HTTP: waf.HTTP{
			Listen: "127.0.0.1:0",
			// It resolves to 127.0.0.1 (and possibly ::1).
			ForwardedFor: []string{"localhost"},
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

	forwardedFor := func(addr string) http.Header {
		return http.Header{"X-Forwarded-For": []string{addr}}
	}

	// A request from a trusted proxy uses the client's address from the header.
	code, err := get(t, proxyProtocolClient(t, httpsAddr, "127.0.0.1", "", certPath), httpsURL, forwardedFor("203.0.113.45"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.True(t, strings.HasPrefix(*remoteAddr.Load(), "203.0.113.45:"), *remoteAddr.Load())

	// The HTTP server uses the header from its trusted proxies as well, and logs both addresses.
	code, err = get(t, proxyProtocolClient(t, httpAddr, "127.0.0.1", "", certPath), httpURL, forwardedFor("198.51.100.7"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusPermanentRedirect, code)

	// Without the header, the proxy's address is used and no proxy address is logged.
	code, err = get(t, proxyProtocolClient(t, httpAddr, "127.0.0.1", "", certPath), httpURL, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusPermanentRedirect, code)

	// A request from another address does not use the header.
	code, err = get(t, proxyProtocolClient(t, httpsAddr, "127.0.0.2", "", certPath), httpsURL, forwardedFor("203.0.113.45"))
	if errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Skip("127.0.0.2 is not available")
	}
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.True(t, strings.HasPrefix(*remoteAddr.Load(), "127.0.0.2:"), *remoteAddr.Load())

	cancel()

	err = g.Wait()
	require.NoError(t, err, "% -+#.1v", err)

	type logLine struct {
		Client string `json:"client"`
		Proxy  string `json:"proxy"`
	}
	lines := []logLine{}
	scanner := bufio.NewScanner(logs)
	for scanner.Scan() {
		var line struct {
			logLine

			Message string `json:"message"`
		}
		err := json.Unmarshal(scanner.Bytes(), &line)
		require.NoError(t, err)
		if line.Message == "RedirectHTTP" {
			lines = append(lines, line.logLine)
		}
	}
	require.NoError(t, scanner.Err())
	assert.Equal(t, []logLine{{Client: "198.51.100.7", Proxy: "127.0.0.1"}, {Client: "127.0.0.1", Proxy: ""}}, lines)
}
