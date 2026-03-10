package waf

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
)

// Based on zerolog/hlog/hlog_test.go, but with a punycode test case.
func TestGetHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"example.com:8080", "example.com"},
		{"example.com", "example.com"},
		{"invalid", "invalid"},
		{"192.168.0.1:8080", "192.168.0.1"},
		{"[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:8080", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
		{"こんにちは.com:8080", "こんにちは.com"},
		{"xn--28j2a3ar1p.com:8000", "こんにちは.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()

			result, errE := getHost(tt.input)
			require.NoError(t, errE, "% -+#.1v", errE)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParsePostForm(t *testing.T) {
	t.Parallel()

	queryString := "key1=value1&key2=value2"
	postBody := "key3=value3&key4=value4"
	req := httptest.NewRequest(http.MethodPost, "/example?"+queryString, strings.NewReader(postBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	errE := parsePostForm(req)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Nil(t, req.Form)

	require.NotNil(t, req.PostForm)
	assert.Len(t, req.PostForm, 2)
	assert.Equal(t, "value3", req.PostForm.Get("key3"))
	assert.Equal(t, "value4", req.PostForm.Get("key4"))
}

func TestCleanPathNoSlash(t *testing.T) {
	t.Parallel()

	// Empty path returns "/".
	assert.Equal(t, "/", cleanPath(""))

	// Path not starting with "/" gets "/" prepended.
	assert.Equal(t, "/foo", cleanPath("foo"))
	assert.Equal(t, "/foo/bar", cleanPath("foo/bar"))
}

func TestCanonicalLoggerMessagePanic(t *testing.T) {
	t.Parallel()

	// canonicalLoggerMessage panics when message key is absent from context.
	assert.Panics(t, func() {
		canonicalLoggerMessage(context.Background())
	})
}

func TestLogValuesEmpty(t *testing.T) {
	t.Parallel()

	// logValues returns the context unchanged for an empty values map.
	logger := zerolog.New(io.Discard)
	ctx := logger.With()
	result := logValues(ctx, "field", map[string][]string{})
	_ = result
}

func TestParsePostFormAlreadyParsed(t *testing.T) {
	t.Parallel()

	// When PostForm is already set, parsePostForm returns nil immediately.
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("key=val"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.PostForm = url.Values{"existing": {"value"}}
	errE := parsePostForm(req)
	require.NoError(t, errE)
	assert.Equal(t, url.Values{"existing": {"value"}}, req.PostForm)
}

func TestGetQueryFormAlreadyParsed(t *testing.T) {
	t.Parallel()

	// Form non-nil AND PostForm empty -> early return with Form as-is.
	req := httptest.NewRequest(http.MethodGet, "/example?q=1", nil)
	req.Form = url.Values{"q": {"1"}}
	// PostForm is nil (len==0) -> satisfies the short-circuit condition.

	queryForm, errE := getQueryForm(req)
	require.NoError(t, errE)
	assert.Equal(t, url.Values{"q": {"1"}}, queryForm)
}

func TestLogHandlerFuncNameEmpty(t *testing.T) {
	t.Parallel()

	// Empty name returns the handler unchanged.
	called := false
	h := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })
	result := logHTTPHandlerName("", h)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	result.ServeHTTP(w, r)
	assert.True(t, called)
}

func TestParseCertPoolFromInvalidPEM(t *testing.T) {
	t.Parallel()

	// File with non-PEM content triggers parseCertPool error.
	f, err := os.CreateTemp(t.TempDir(), "bad*.pem")
	require.NoError(t, err)
	_, err = f.WriteString("not valid PEM data")
	require.NoError(t, err)
	f.Close() //nolint:errcheck,gosec
	_, errE := parseCertPoolFrom(f.Name())
	assert.ErrorContains(t, errE, "PEM not parsed")
}

func TestParseCertPoolInvalidDER(t *testing.T) {
	t.Parallel()

	// Valid PEM structure but the DER content is not a certificate.
	pemData := []byte("-----BEGIN CERTIFICATE-----\nAAECBA==\n-----END CERTIFICATE-----\n")
	_, errE := parseCertPool(pemData)
	assert.ErrorContains(t, errE, "unable to parse certificates")
}

func TestPostFormParsedNoContentType(t *testing.T) {
	t.Parallel()

	// POST with no Content-Type defaults to application/octet-stream, not a form.
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("body"))
	assert.False(t, postFormParsed(req))

	// GET request with body is never a form.
	req2 := httptest.NewRequest(http.MethodGet, "/", strings.NewReader("body"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	assert.False(t, postFormParsed(req2))

	// nil body is never a form.
	req3 := httptest.NewRequest(http.MethodPost, "/", nil)
	req3.Body = nil
	assert.False(t, postFormParsed(req3))
}

func TestParseCertPool(t *testing.T) {
	t.Parallel()

	// Invalid PEM input returns an error.
	_, errE := parseCertPool([]byte("not valid PEM"))
	assert.EqualError(t, errE, "PEM not parsed")

	// Valid PEM certificate succeeds.
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "cert.pem")
	keyPath := filepath.Join(tempDir, "key.pem")
	errE = x.CreateTempCertificateFiles(certPath, keyPath, []string{"example.com"})
	require.NoError(t, errE, "% -+#.1v", errE)
	certData, err := os.ReadFile(certPath) //nolint:gosec
	require.NoError(t, err)
	pool, errE := parseCertPool(certData)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.NotNil(t, pool)
}

func TestParseCertPoolFrom(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "cert.pem")
	keyPath := filepath.Join(tempDir, "key.pem")
	errE := x.CreateTempCertificateFiles(certPath, keyPath, []string{"example.com"})
	require.NoError(t, errE, "% -+#.1v", errE)

	// Valid cert file succeeds.
	pool, errE := parseCertPoolFrom(certPath)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.NotNil(t, pool)

	// Non-existent file returns an error.
	_, errE = parseCertPoolFrom(filepath.Join(tempDir, "nonexistent.pem"))
	assert.ErrorContains(t, errE, "unable to read file")
}

func TestAcmeClient(t *testing.T) {
	t.Parallel()

	// Empty cert path - success, no custom cert pool.
	client, errE := acmeClient("")
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.NotNil(t, client)

	// Valid cert file - success.
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "cert.pem")
	keyPath := filepath.Join(tempDir, "key.pem")
	errE = x.CreateTempCertificateFiles(certPath, keyPath, []string{"example.com"})
	require.NoError(t, errE, "% -+#.1v", errE)
	client, errE = acmeClient(certPath)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.NotNil(t, client)

	// Non-existent file - error.
	_, errE = acmeClient(filepath.Join(tempDir, "nonexistent.pem"))
	assert.Error(t, errE)
}

func TestGetQueryForm(t *testing.T) {
	t.Parallel()

	queryString := "key1=value1&key2=value2"
	postBody := "key3=value3&key4=value4"
	req := httptest.NewRequest(http.MethodPost, "/example?"+queryString, strings.NewReader(postBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	queryForm, errE := getQueryForm(req)
	require.NoError(t, errE, "% -+#.1v", errE)

	assert.Len(t, queryForm, 2)
	assert.Equal(t, "value1", queryForm.Get("key1"))
	assert.Equal(t, "value2", queryForm.Get("key2"))

	assert.Nil(t, req.Form)
	assert.Nil(t, req.PostForm)

	errE = parsePostForm(req)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Nil(t, req.Form)

	require.NotNil(t, req.PostForm)
	assert.Len(t, req.PostForm, 2)
	assert.Equal(t, "value3", req.PostForm.Get("key3"))
	assert.Equal(t, "value4", req.PostForm.Get("key4"))

	queryForm, errE = getQueryForm(req)
	require.NoError(t, errE, "% -+#.1v", errE)

	assert.Len(t, queryForm, 2)
	assert.Equal(t, "value1", queryForm.Get("key1"))
	assert.Equal(t, "value2", queryForm.Get("key2"))

	assert.Nil(t, req.Form)
	assert.NotNil(t, req.PostForm)
	assert.Len(t, req.PostForm, 2)
	assert.Equal(t, "value3", req.PostForm.Get("key3"))
	assert.Equal(t, "value4", req.PostForm.Get("key4"))
}
