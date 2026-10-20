package waf_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gitlab.com/tozd/waf"
)

func TestNewHTTPServer(t *testing.T) {
	t.Parallel()

	server := waf.NewHTTPServer(zerolog.Nop(), nil)
	assert.Empty(t, server.Addr)
	assert.Nil(t, server.TLSConfig)
	assert.Positive(t, server.ReadHeaderTimeout)
	assert.Positive(t, server.IdleTimeout)
}

func TestNewHTTPServerErrorLog(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	server := waf.NewHTTPServer(zerolog.New(out), nil)
	server.ErrorLog.Print("failed")
	assert.JSONEq(t, `{"message":"failed"}`, out.String())
}

func TestNewHTTPServerConnectionID(t *testing.T) {
	t.Parallel()

	ts := httptest.NewUnstartedServer(nil)
	ts.Config = waf.NewHTTPServer(zerolog.Nop(), http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.WriteString(w, waf.MustConnectionID(req.Context()).String())
	}))
	ts.Start()
	t.Cleanup(ts.Close)

	get := func(client *http.Client) string {
		t.Helper()

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL, nil)
		require.NoError(t, err)
		res, err := client.Do(req)
		require.NoError(t, err)
		defer res.Body.Close() //nolint:errcheck
		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		return string(body)
	}

	// Requests made over the same connection have the same identifier.
	client := ts.Client()
	first := get(client)
	assert.NotEmpty(t, first)
	assert.Equal(t, first, get(client))

	// And a new connection has a new one.
	client.CloseIdleConnections()
	assert.NotEqual(t, first, get(client))
}

func TestConnectionIDMissing(t *testing.T) {
	t.Parallel()

	_, ok := waf.ConnectionID(context.Background())
	assert.False(t, ok)
	assert.Panics(t, func() {
		waf.MustConnectionID(context.Background())
	})
}
