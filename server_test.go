package waf

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/identifier"
	"golang.org/x/sync/errgroup"
)

func TestServer(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "test_cert.pem")
	keyPath := filepath.Join(tempDir, "test_key.pem")

	err := createTempCertificateFiles(certPath, keyPath, []string{})
	require.NoError(t, err)

	server := &Server[*Site]{
		Logger: zerolog.Nop(),
		TLS: TLS{
			CertFile: certPath,
			KeyFile:  keyPath,
		},
	}
	_, errE := server.Init(nil)
	assert.ErrorContains(t, errE, "certificate is not valid for any domain")

	err = createTempCertificateFiles(certPath, keyPath, []string{"example.com", "localhost"})
	require.NoError(t, err)

	ctx := context.Background()

	server = &Server[*Site]{}
	errE = server.Run(ctx, nil)
	assert.ErrorContains(t, errE, "server not configured")

	server = &Server[*Site]{}
	_, errE = server.Init(nil)
	assert.ErrorContains(t, errE, "missing file or Let's Encrypt's certificate configuration")

	server = &Server[*Site]{
		Logger: zerolog.Nop(),
		TLS: TLS{
			CertFile: certPath,
			KeyFile:  keyPath,
		},
		ProxyTo: "http://localhost:8000",
		Title:   "example",
	}
	sites, errE := server.Init(nil)
	assert.NoError(t, errE)
	assert.Equal(t, map[string]*Site{
		"example.com": {Domain: "example.com", Title: "example"},
		"localhost":   {Domain: "localhost", Title: "example"},
	}, sites)

	assert.Equal(t, "", server.InDevelopment())

	server = &Server[*Site]{
		Logger: zerolog.Nop(),
		TLS: TLS{
			CertFile: certPath,
			KeyFile:  keyPath,
		},
		ProxyTo:     "http://localhost:8000",
		Development: true,
		Title:       "example",
	}
	sites, errE = server.Init(nil)
	assert.NoError(t, errE)
	assert.Equal(t, map[string]*Site{
		"example.com": {Domain: "example.com", Title: "example"},
		"localhost":   {Domain: "localhost", Title: "example"},
	}, sites)

	assert.Equal(t, "http://localhost:8000", server.InDevelopment())

	server = &Server[*Site]{
		Logger: zerolog.Nop(),
		TLS: TLS{
			CertFile: certPath,
			KeyFile:  keyPath,
		},
		ProxyTo:     "",
		Development: true,
		Title:       "example",
	}
	sites, errE = server.Init(nil)
	assert.NoError(t, errE)
	assert.Equal(t, map[string]*Site{
		"example.com": {Domain: "example.com", Title: "example"},
		"localhost":   {Domain: "localhost", Title: "example"},
	}, sites)

	assert.Equal(t, "", server.InDevelopment())

	server = &Server[*Site]{
		Logger: zerolog.Nop(),
	}
	sites, errE = server.Init(map[string]*Site{
		"example.com": {Domain: "example.com", Title: "example", CertFile: certPath, KeyFile: keyPath},
		"localhost":   {Domain: "localhost", Title: "localhost", CertFile: certPath, KeyFile: keyPath},
	})
	assert.NoError(t, errE)
	assert.Equal(t, map[string]*Site{
		"example.com": {Domain: "example.com", Title: "example", CertFile: certPath, KeyFile: keyPath},
		"localhost":   {Domain: "localhost", Title: "localhost", CertFile: certPath, KeyFile: keyPath},
	}, sites)

	server = &Server[*Site]{
		Logger: zerolog.Nop(),
	}
	_, errE = server.Init(map[string]*Site{
		"example.com": {Domain: "something.com", Title: "example", CertFile: certPath, KeyFile: keyPath},
	})
	assert.ErrorContains(t, errE, "domain does not match site's domain")

	server = &Server[*Site]{
		Logger: zerolog.Nop(),
	}
	_, errE = server.Init(map[string]*Site{
		"": {Domain: "something.com", Title: "example", CertFile: certPath, KeyFile: keyPath},
	})
	assert.ErrorContains(t, errE, "domain does not match site's domain")

	server = &Server[*Site]{
		Logger: zerolog.Nop(),
	}
	_, errE = server.Init(map[string]*Site{
		"example.com": {Domain: "", Title: "example", CertFile: certPath, KeyFile: keyPath},
	})
	assert.ErrorContains(t, errE, "site's domain is required")

	server = &Server[*Site]{
		Logger: zerolog.Nop(),
	}
	_, errE = server.Init(map[string]*Site{
		"something.com": {Domain: "something.com", Title: "example", CertFile: certPath, KeyFile: keyPath},
	})
	assert.ErrorContains(t, errE, "certificate is not valid for domain")

	server = &Server[*Site]{
		Logger: zerolog.Nop(),
		TLS: TLS{
			CertFile: certPath,
			KeyFile:  keyPath,
		},
	}
	sites, errE = server.Init(map[string]*Site{
		"example.com": {Domain: "example.com", Title: "example"},
		"localhost":   {Domain: "localhost", Title: "localhost"},
	})
	assert.NoError(t, errE)
	assert.Equal(t, map[string]*Site{
		"example.com": {Domain: "example.com", Title: "example"},
		"localhost":   {Domain: "localhost", Title: "localhost"},
	}, sites)

	server = &Server[*Site]{
		Logger: zerolog.Nop(),
		TLS: TLS{
			CertFile: certPath,
			KeyFile:  keyPath,
		},
	}
	_, errE = server.Init(map[string]*Site{
		"something.com": {Domain: "something.com", Title: "example"},
	})
	assert.ErrorContains(t, errE, "certificate is not valid for domain")

	out := &bytes.Buffer{}

	server = &Server[*Site]{
		Logger: zerolog.New(out),
		TLS: TLS{
			CertFile: certPath,
			KeyFile:  keyPath,
		},
		Title: "example",
	}
	sites, errE = server.Init(nil)
	assert.NoError(t, errE)
	assert.Equal(t, map[string]*Site{
		"example.com": {Domain: "example.com", Title: "example"},
		"localhost":   {Domain: "localhost", Title: "example"},
	}, sites)

	assert.Equal(t, "", server.InDevelopment())

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	g := errgroup.Group{}

	g.Go(func() error {
		return server.Run(ctx, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("test"))
			w.WriteHeader(http.StatusOK)
		}))
	})

	time.Sleep(time.Second)

	cancel()

	err = g.Wait()
	assert.NoError(t, err)

	assert.Equal(
		t,
		`{"level":"info","message":"server starting on :8080"}`+"\n"+
			`{"level":"info","message":"server stopping"}`+"\n",
		out.String(),
	)
}

func TestServerConnection(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "test_cert.pem")
	keyPath := filepath.Join(tempDir, "test_key.pem")

	err := createTempCertificateFiles(certPath, keyPath, []string{"localhost"})
	require.NoError(t, err)

	server := &Server[*Site]{
		Logger: zerolog.Nop(),
		TLS: TLS{
			CertFile: certPath,
			KeyFile:  keyPath,
		},
		Title: "example",
	}
	sites, errE := server.Init(nil)
	assert.NoError(t, errE)
	assert.Equal(t, map[string]*Site{
		"localhost": {Domain: "localhost", Title: "example"},
	}, sites)

	assert.Equal(t, "", server.InDevelopment())

	ts := httptest.NewUnstartedServer(nil)
	ts.EnableHTTP2 = true
	t.Cleanup(ts.Close)

	ts.Config = server.server
	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := r.Context().Value(connectionIDContextKey).(identifier.Identifier)
		assert.True(t, ok)
		_, _ = w.Write([]byte("test"))
		w.WriteHeader(http.StatusOK)
	})
	ts.TLS = server.server.TLSConfig.Clone()
	// We have to call GetCertificate ourselves.
	// See: https://github.com/golang/go/issues/63812
	cert, err := ts.TLS.GetCertificate(nil)
	require.NoError(t, err)
	// By setting Certificates, we force testing server and testing client to use our certificate.
	ts.TLS.Certificates = []tls.Certificate{*cert}

	// This does not start server.server's managers, but that is OK for this test.
	ts.StartTLS()

	// Our certificate is for localhost domain and not 127.0.0.1 IP.
	url := strings.ReplaceAll(ts.URL, "127.0.0.1", "localhost")
	resp, err := ts.Client().Get(url) //nolint:noctx
	if assert.NoError(t, err) {
		defer resp.Body.Close()
		out, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, `test`, string(out))
	}
}
