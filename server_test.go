package waf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"golang.org/x/sync/errgroup"
)

func TestServer(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "test_cert.pem")
	keyPath := filepath.Join(tempDir, "test_key.pem")

	errE := x.CreateTempCertificateFiles(certPath, keyPath, []string{})
	require.NoError(t, errE)

	server := &Server[*Site]{
		Logger: zerolog.Nop(),
		HTTPS: HTTPS{
			CertFile: certPath,
			KeyFile:  keyPath,
		},
	}
	_, errE = server.Init(nil)
	assert.EqualError(t, errE, "certificate is not valid for any domain")

	errE = x.CreateTempCertificateFiles(certPath, keyPath, []string{"example.com", "localhost"})
	require.NoError(t, errE)

	ctx := context.Background()

	server = &Server[*Site]{}
	errE = server.Run(ctx, nil)
	assert.EqualError(t, errE, "server not configured")

	server = &Server[*Site]{}
	_, errE = server.Init(nil)
	assert.EqualError(t, errE, "missing file or Let's Encrypt's certificate configuration")

	server = &Server[*Site]{
		Logger: zerolog.Nop(),
		HTTPS: HTTPS{
			CertFile: certPath,
			KeyFile:  keyPath,
		},
		ProxyTo: "http://localhost:8000",
	}
	sites, errE := server.Init(nil)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, map[string]*Site{
		"example.com": {Domain: "example.com"},
		"localhost":   {Domain: "localhost"},
	}, sites)

	assert.Empty(t, server.ProxyToInDevelopment())

	server = &Server[*Site]{
		Logger: zerolog.Nop(),
		HTTPS: HTTPS{
			CertFile: certPath,
			KeyFile:  keyPath,
		},
		ProxyTo:     "http://localhost:8000",
		Development: true,
	}
	sites, errE = server.Init(nil)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, map[string]*Site{
		"example.com": {Domain: "example.com"},
		"localhost":   {Domain: "localhost"},
	}, sites)

	assert.Equal(t, "http://localhost:8000", server.ProxyToInDevelopment())

	server = &Server[*Site]{
		Logger: zerolog.Nop(),
		HTTPS: HTTPS{
			CertFile: certPath,
			KeyFile:  keyPath,
		},
		ProxyTo:     "",
		Development: true,
	}
	sites, errE = server.Init(nil)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, map[string]*Site{
		"example.com": {Domain: "example.com"},
		"localhost":   {Domain: "localhost"},
	}, sites)

	assert.Empty(t, server.ProxyToInDevelopment())

	server = &Server[*Site]{
		Logger: zerolog.Nop(),
	}
	sites, errE = server.Init(map[string]*Site{
		"example.com": {Domain: "example.com", CertFile: certPath, KeyFile: keyPath},
		"localhost":   {Domain: "localhost", CertFile: certPath, KeyFile: keyPath},
	})
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, map[string]*Site{
		"example.com": {Domain: "example.com", CertFile: certPath, KeyFile: keyPath},
		"localhost":   {Domain: "localhost", CertFile: certPath, KeyFile: keyPath},
	}, sites)

	server = &Server[*Site]{
		Logger: zerolog.Nop(),
	}
	_, errE = server.Init(map[string]*Site{
		"example.com": {Domain: "something.com", CertFile: certPath, KeyFile: keyPath},
	})
	assert.EqualError(t, errE, "domain does not match site's domain")

	server = &Server[*Site]{
		Logger: zerolog.Nop(),
	}
	_, errE = server.Init(map[string]*Site{
		"": {Domain: "something.com", CertFile: certPath, KeyFile: keyPath},
	})
	assert.EqualError(t, errE, "domain does not match site's domain")

	server = &Server[*Site]{
		Logger: zerolog.Nop(),
	}
	_, errE = server.Init(map[string]*Site{
		"example.com": {Domain: "", CertFile: certPath, KeyFile: keyPath},
	})
	assert.EqualError(t, errE, "site's domain is required")

	server = &Server[*Site]{
		Logger: zerolog.Nop(),
	}
	_, errE = server.Init(map[string]*Site{
		"something.com": {Domain: "something.com", CertFile: certPath, KeyFile: keyPath},
	})
	assert.EqualError(t, errE, "certificate is not valid for domain")

	server = &Server[*Site]{
		Logger: zerolog.Nop(),
		HTTPS: HTTPS{
			CertFile: certPath,
			KeyFile:  keyPath,
		},
	}
	sites, errE = server.Init(map[string]*Site{
		"example.com": {Domain: "example.com"},
		"localhost":   {Domain: "localhost"},
	})
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, map[string]*Site{
		"example.com": {Domain: "example.com"},
		"localhost":   {Domain: "localhost"},
	}, sites)

	server = &Server[*Site]{
		Logger: zerolog.Nop(),
		HTTPS: HTTPS{
			CertFile: certPath,
			KeyFile:  keyPath,
		},
	}
	_, errE = server.Init(map[string]*Site{
		"something.com": {Domain: "something.com"},
	})
	assert.EqualError(t, errE, "certificate is not valid for domain")

	pipeR, pipeW, err := os.Pipe()
	t.Cleanup(func() {
		// We might double close but we do not care.
		pipeR.Close() //nolint:errcheck,gosec
		pipeW.Close() //nolint:errcheck,gosec
	})
	require.NoError(t, err)

	server = &Server[*Site]{
		Logger: zerolog.New(pipeW),
		HTTPS: HTTPS{
			CertFile: certPath,
			KeyFile:  keyPath,
			// We bind the HTTPS server to any localhost port.
			Listen: "localhost:0",
		},
		HTTP: HTTP{
			// We bind the HTTP server to any localhost port.
			Listen: "localhost:0",
		},
	}
	sites, errE = server.Init(nil)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, map[string]*Site{
		"example.com": {Domain: "example.com"},
		"localhost":   {Domain: "localhost"},
	}, sites)

	assert.Empty(t, server.ProxyToInDevelopment())

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	g := errgroup.Group{}

	g.Go(func() error {
		return server.Run(ctx, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("test"))
			w.WriteHeader(http.StatusOK)
		}))
	})

	// We wait for the server to start.
	assert.NotEmpty(t, server.ListenAddrHTTPS())
	assert.NotEmpty(t, server.ListenAddrHTTP())

	// For "server starting" to be logged.
	time.Sleep(time.Second)

	_, httpsPort, err := net.SplitHostPort(server.ListenAddrHTTPS())
	require.NoError(t, err)
	_, httpPort, err := net.SplitHostPort(server.ListenAddrHTTP())
	require.NoError(t, err)

	transport := cleanhttp.DefaultTransport()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// We map everything to localhost.
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		addr = "localhost:" + port
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	httpClient := &http.Client{
		Transport: transport,
		// We do not follow redirects automatically.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, tt := range []struct {
		From string
		To   string
	}{{
		From: "http://example.com:" + httpPort + "/test.html",
		To:   "https://example.com:" + httpsPort + "/test.html",
	}, {
		From: "http://localhost:" + httpPort + "/test.html",
		To:   "https://localhost:" + httpsPort + "/test.html",
	}} {
		resp, err := httpClient.Get(tt.From) //nolint:noctx
		require.NoError(t, err)
		t.Cleanup(func() { resp.Body.Close() }) //nolint:errcheck,gosec
		_, err = io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusPermanentRedirect, resp.StatusCode)
		assert.Equal(t, 1, resp.ProtoMajor)
		assert.Equal(t, tt.To, resp.Header.Get("Location"))
	}

	// It redirects only for domains we have configured.
	resp, err := httpClient.Get("http://something.com:" + httpPort) //nolint:noctx
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() }) //nolint:errcheck,gosec
	_, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, 1, resp.ProtoMajor)

	cancel()

	err = g.Wait()
	require.NoError(t, err, "% -+#.1v", err)

	pipeW.Close() //nolint:errcheck,gosec
	out, err := io.ReadAll(pipeR)
	pipeR.Close() //nolint:errcheck,gosec
	require.NoError(t, err)

	// Order of log lines is not deterministic.
	assert.ElementsMatch(
		t,
		[]string{
			`{"level":"info","listenAddr":"` + server.ListenAddrHTTP() + `","domains":["example.com","localhost"],"message":"HTTP server starting"}`,
			`{"level":"info","listenAddr":"` + server.ListenAddrHTTPS() + `","domains":["example.com","localhost"],"message":"HTTPS server starting"}`,
			`{"level":"info","message":"HTTP server stopping"}`,
			`{"level":"info","message":"HTTPS server stopping"}`,
			// There is one extra empty string because we use strings.Split to split.
			``,
		},
		strings.Split(string(out), "\n"),
	)
}

func TestServerConnection(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "test_cert.pem")
	keyPath := filepath.Join(tempDir, "test_key.pem")

	errE := x.CreateTempCertificateFiles(certPath, keyPath, []string{"localhost"})
	require.NoError(t, errE)

	cert2Path := filepath.Join(tempDir, "test_cert2.pem")
	key2Path := filepath.Join(tempDir, "test_key2.pem")

	errE = x.CreateTempCertificateFiles(cert2Path, key2Path, []string{"example.com"})
	require.NoError(t, errE)

	server := &Server[*Site]{
		Logger: zerolog.New(zerolog.NewTestWriter(t)),
		HTTPS: HTTPS{
			CertFile: certPath,
			KeyFile:  keyPath,
		},
	}
	sites, errE := server.Init(map[string]*Site{
		"example.com": {Domain: "example.com", CertFile: cert2Path, KeyFile: key2Path},
		"localhost":   {Domain: "localhost"},
	})
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, map[string]*Site{
		"example.com": {Domain: "example.com", CertFile: cert2Path, KeyFile: key2Path},
		"localhost":   {Domain: "localhost"},
	}, sites)

	assert.Empty(t, server.ProxyToInDevelopment())

	ts := httptest.NewUnstartedServer(nil)
	ts.EnableHTTP2 = true
	t.Cleanup(ts.Close)

	ts.Config = server.HTTPSServer
	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := r.Context().Value(connectionIDContextKey).(identifier.Identifier)
		assert.True(t, ok)
		_, _ = w.Write([]byte("test"))
		w.WriteHeader(http.StatusOK)
	})
	ts.TLS = server.HTTPSServer.TLSConfig.Clone()
	// We have to call GetCertificate ourselves.
	// See: https://github.com/golang/go/issues/63812
	cert, err := ts.TLS.GetCertificate(&tls.ClientHelloInfo{
		ServerName: "localhost",
	})
	require.NoError(t, err, "% -+#.1v", err)
	cert2, err := ts.TLS.GetCertificate(&tls.ClientHelloInfo{
		ServerName: "example.com",
	})
	require.NoError(t, err, "% -+#.1v", err)
	// By setting Certificates, we force testing server and testing client to use our certificates.
	ts.TLS.Certificates = []tls.Certificate{*cert, *cert2}

	c, err := ts.TLS.GetCertificate(&tls.ClientHelloInfo{
		ServerName: "EXAMPLE.com",
	})
	require.NoError(t, err, "% -+#.1v", err)
	assert.NotNil(t, c)

	// This does not start server's managers, but that is OK for this test.
	ts.StartTLS()

	// Our certificate is for localhost domain and not 127.0.0.1 IP.
	ts.URL = strings.ReplaceAll(ts.URL, "127.0.0.1", "localhost")

	resp, err := ts.Client().Get(ts.URL) //nolint:noctx
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() }) //nolint:errcheck,gosec
	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, `test`, string(out))
}

func getACMERootCAs(t *testing.T) *x509.CertPool {
	t.Helper()

	acmeClient, errE := acmeClient("testdata/pebble.minica.pem")
	require.NoError(t, errE, "% -+#.1v", errE)

	resp, err := acmeClient.Get(fmt.Sprintf("https://%s/roots/0", net.JoinHostPort(os.Getenv("PEBBLE_HOST"), "15000"))) //nolint:noctx
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() }) //nolint:errcheck,gosec
	acmeRootCAsData, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	acmeRootCAs, errE := parseCertPool(acmeRootCAsData)
	require.NoError(t, errE, "% -+#.1v", errE)

	return acmeRootCAs
}

// We do not enable t.Parallel() here because it uses 5001 port
// and can conflict with other tests using the same port.
func TestServerACME(t *testing.T) { //nolint:paralleltest
	if os.Getenv("PEBBLE_HOST") == "" {
		t.Skip("PEBBLE_HOST is not available")
	}

	tempDir := t.TempDir()

	server := &Server[*Site]{
		Logger: zerolog.New(zerolog.NewTestWriter(t)),
		HTTPS: HTTPS{
			LetsEncryptCache: tempDir,
			// Pebble uses this port by default for the TLS-ALPN-01 challenge.
			Listen:               ":5001",
			ACMEDirectory:        fmt.Sprintf("https://%s/dir", net.JoinHostPort(os.Getenv("PEBBLE_HOST"), "14000")),
			ACMEDirectoryRootCAs: "testdata/pebble.minica.pem",
		},
	}
	sites, errE := server.Init(map[string]*Site{
		"site.test": {Domain: "site.test"},
	})
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, map[string]*Site{
		"site.test": {Domain: "site.test"},
	}, sites)

	assert.Empty(t, server.ProxyToInDevelopment())

	getCertificate := server.HTTPSServer.TLSConfig.GetCertificate
	server.HTTPSServer.TLSConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		t.Logf("clientHelloInfo: %+v", hello)
		return getCertificate(hello)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	g := errgroup.Group{}

	g.Go(func() error {
		return server.Run(ctx, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("test"))
			w.WriteHeader(http.StatusOK)
		}))
	})

	// We wait for the server to start.
	require.NotEmpty(t, server.ListenAddrHTTPS())
	t.Logf("ListenAddress: %s", server.ListenAddrHTTPS())

	transport := cleanhttp.DefaultTransport()
	transport.ForceAttemptHTTP2 = true
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == "site.test:443" {
			addr = server.ListenAddrHTTPS()
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	transport.TLSClientConfig = &tls.Config{ //nolint:gosec
		RootCAs: getACMERootCAs(t),
	}

	client := &http.Client{
		Transport: transport,
	}

	resp, err := client.Get("https://site.test") //nolint:noctx
	if assert.NoError(t, err) {
		t.Cleanup(func() { resp.Body.Close() }) //nolint:errcheck,gosec
		out, err := io.ReadAll(resp.Body)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, 2, resp.ProtoMajor)
			assert.Equal(t, `test`, string(out))
		}
	}

	cancel()

	err = g.Wait()
	require.NoError(t, err, "% -+#.1v", err)
}
