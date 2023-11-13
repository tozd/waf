package waf

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	servertiming "github.com/tozd/go-server-timing"
	"gitlab.com/tozd/go/errors"
)

var (
	compressibleData             = bytes.Repeat([]byte{0}, 32*1024)
	compressibleDataGzip         []byte
	nonCompressibleData          = make([]byte, 32*1024)
	nonCompressibleDataEtag      string
	nonCompressibleDataGzip      []byte
	semiCompressibleData         []byte
	semiCompressibleDataEtag     string
	semiCompressibleDataGzip     []byte
	semiCompressibleDataGzipEtag string
	testFiles                    fstest.MapFS
)

func init() {
	zerolog.DurationFieldInteger = true
	_, err := rand.Read(nonCompressibleData)
	if err != nil {
		panic(err)
	}
	nonCompressibleDataGzip, err = compress(compressionGzip, nonCompressibleData)
	if err != nil {
		panic(err)
	}
	nonCompressibleDataEtag = computeEtag(nonCompressibleData)
	semiCompressibleData = append([]byte{}, nonCompressibleData[:30*1024]...)
	semiCompressibleData = append(semiCompressibleData, bytes.Repeat([]byte{0}, 2*1024)...)
	semiCompressibleDataGzip, err = compress(compressionGzip, semiCompressibleData)
	if err != nil {
		panic(err)
	}
	semiCompressibleDataEtag = computeEtag(semiCompressibleData)
	semiCompressibleDataGzipEtag = computeEtag(semiCompressibleDataGzip)
	compressibleDataGzip, err = compress(compressionGzip, compressibleData)
	if err != nil {
		panic(err)
	}

	testFiles = fstest.MapFS{
		"assets/image.png": &fstest.MapFile{
			Data: []byte("test image"),
		},
		"data.txt": &fstest.MapFile{
			Data: []byte("test data"),
		},
		"compressible.bin": &fstest.MapFile{
			Data: compressibleData,
		},
		"noncompressible.bin": &fstest.MapFile{
			Data: nonCompressibleData,
		},
		"semicompressible.bin": &fstest.MapFile{
			Data: semiCompressibleData,
		},
		"index.html": &fstest.MapFile{
			Data: []byte(`<!DOCTYPE html><html><head><title>{{ .Site.Title }}</title></head><body>{{ .Site.Description }}</body></html>`),
		},
	}
}

type testSite struct {
	Site

	Description string `json:"description"`
}

type testService struct {
	Service[*testSite]
}

func (s *testService) HomeGetAPIGet(w http.ResponseWriter, req *http.Request, _ Params) {
	timing := servertiming.FromContext(req.Context())
	timing.NewMetric("test").Duration = 123456789 * time.Microsecond

	hlog.FromRequest(req).Info().Msg("test msg")

	s.serveStaticFile(w, req, "/index.json", false)
}

func (s *testService) HomeGet(w http.ResponseWriter, req *http.Request, _ Params) {
	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.serveStaticFile(w, req, "/index.html", false)
	}
}

func (s *testService) HelperGet(w http.ResponseWriter, req *http.Request, p Params) {
	switch p["name"] {
	case "NotFound":
		s.NotFound(w, req)
	case "NotFoundWithError":
		s.NotFoundWithError(w, req, errors.New("test"))
	case "MethodNotAllowed":
		s.MethodNotAllowed(w, req, []string{http.MethodDelete, http.MethodGet})
	case "InternalServerError":
		s.InternalServerError(w, req)
	case "InternalServerErrorWithError":
		s.InternalServerErrorWithError(w, req, errors.New("test"))
	case "Canceled":
		s.InternalServerErrorWithError(w, req, errors.WithStack(context.Canceled))
	case "DeadlineExceeded":
		s.InternalServerErrorWithError(w, req, errors.WithStack(context.DeadlineExceeded))
	case "Proxy":
		s.Proxy(w, req)
	default:
		s.BadRequest(w, req)
	}
}

func (s *testService) PanicAPIGet(_ http.ResponseWriter, _ *http.Request, _ Params) {
	panic(errors.New("test"))
}

func (s *testService) JSONAPIGet(w http.ResponseWriter, req *http.Request, _ Params) {
	s.WriteJSON(w, req, map[string]interface{}{"data": 123}, map[string]interface{}{"foobar": 42})
}

func (s *testService) JSONAPIPost(w http.ResponseWriter, req *http.Request, _ Params) {
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(req.Form.Encode()))
}

func newRequest(t *testing.T, method, url string, body io.Reader) *http.Request {
	t.Helper()

	req, err := http.NewRequest(method, url, body) //nolint:noctx
	require.NoError(t, err)
	return req
}

func newService(t *testing.T, logger zerolog.Logger, https2 bool, development string) (*testService, *httptest.Server) {
	t.Helper()

	service := &testService{
		Service: Service[*testSite]{
			Logger: logger,
			Files:  testFiles,
			Routes: []Route{
				{
					Name: "HomeGet",
					Path: "/",
					API:  true,
					Get:  true,
				},
				{
					Name: "HelperGet",
					Path: "/helper/:name",
					API:  false,
					Get:  true,
				},
				{
					Name: "Panic",
					Path: "/panic",
					API:  true,
					Get:  false,
				},
				{
					Name: "JSON",
					Path: "/json",
					API:  true,
					Get:  false,
				},
			},
			Sites: map[string]*testSite{
				"example.com": {
					Site: Site{
						Domain: "example.com",
						Title:  "test",
					},
					Description: "test site",
				},
			},
			Version:              "vTEST",
			Revision:             "abcde",
			BuildTimestamp:       "2023-11-03T00:51:07Z",
			MetadataHeaderPrefix: "Test-",
			Development:          development,
			IsImmutableFile: func(path string) bool {
				return strings.HasPrefix(path, "/assets/")
			},
			SkipStaticFile: func(path string) bool {
				return path == "/index.html" || path == contextPath
			},
		},
	}

	router := &Router{}
	handler, errE := service.RouteWith(service, router)
	require.NoError(t, errE, "% -+#.1v", errE)

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "test_cert.pem")
	keyPath := filepath.Join(tempDir, "test_key.pem")

	err := createTempCertificateFiles(certPath, keyPath, []string{"example.com", "other.example.com"})
	require.NoError(t, err)

	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)

	ts := httptest.NewUnstartedServer(handler)
	ts.EnableHTTP2 = https2
	ts.TLS = &tls.Config{ //nolint:gosec
		Certificates: []tls.Certificate{certificate},
	}
	ts.Config.ConnContext = (&Server[*testSite]{}).connContext
	t.Cleanup(ts.Close)
	ts.StartTLS()

	var listenAddr atomic.Value
	listenAddr.Store(ts.Listener.Addr().String())

	// We make a client version which maps example.com to the address ts is listening on.
	client := ts.Client()
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) { //nolint:forcetypeassert
		if addr == "example.com:443" || addr == "other.example.com:443" {
			addr = listenAddr.Load().(string) //nolint:forcetypeassert,errcheck
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}

	return service, ts
}

var logCleanupRegexp = regexp.MustCompile(`("proxied":")[^"]+(")|("connection":")[^"]+(")|("request":")[^"]+(")|("[tjc]":)[0-9]+`)

func logCleanup(t *testing.T, http2 bool, log string) string {
	t.Helper()

	if !http2 {
		log = strings.ReplaceAll(log, `"proto":"1.1"`, `"proto":"2.0"`)
		log = strings.ReplaceAll(log, `Go-http-client/1.1`, `Go-http-client/2.0`)
	}

	return logCleanupRegexp.ReplaceAllString(log, "$1$2$3$4$5$6$7")
}

var headerCleanupRegexp = regexp.MustCompile(`[0-9]+`)

func headerCleanup(t *testing.T, header http.Header) http.Header {
	t.Helper()

	for _, h := range []string{"Date", "Request-Id"} {
		dates, ok := header[h]
		if ok {
			header[h] = make([]string, len(dates))
		}
	}

	timing, ok := header["Server-Timing"]
	if ok {
		for i, t := range timing {
			timing[i] = headerCleanupRegexp.ReplaceAllString(t, "")
		}
		header["Server-Timing"] = timing
	}

	return header
}

func TestRouteWith(t *testing.T) {
	t.Parallel()

	s := &testService{}
	router := &Router{}
	_, errE := s.RouteWith(s, router)
	require.NoError(t, errE, "% -+#.1v", errE)
	_, errE = s.RouteWith(s, router)
	require.ErrorContains(t, errE, "RouteWith called more than once")
}

func TestServicePath(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}

	service, _ := newService(t, zerolog.New(out), false, "")

	p, errE := service.Path("HomeGet", nil, url.Values{"x": []string{"y"}, "a": []string{"b", "c"}, "b": []string{}})
	assert.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, `/?a=b&a=c&x=y`, p)

	p, errE = service.APIPath("HomeGet", nil, url.Values{"x": []string{"y"}, "a": []string{"b", "c"}, "b": []string{}})
	assert.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, `/api/?a=b&a=c&x=y`, p)

	_, errE = service.Path("HomeGet", Params{"x": "y"}, nil)
	assert.ErrorContains(t, errE, "extra parameters")

	_, errE = service.Path("HelperGet", nil, nil)
	assert.ErrorContains(t, errE, "parameter is missing")

	_, errE = service.Path("JSON", nil, nil)
	assert.ErrorContains(t, errE, "route has no GET handler")

	_, errE = service.Path("something", nil, nil)
	assert.ErrorContains(t, errE, "route does not exist")

	assert.Equal(t, `{"level":"debug","handler":"HomeGet","name":"HomeGet","path":"/","message":"route registration: handler found"}
{"level":"debug","handler":"HomeGetAPIGet","name":"HomeGet","path":"/","message":"route registration: API handler found"}
{"level":"debug","handler":"HomeGetAPIPost","name":"HomeGet","path":"/","message":"route registration: API handler not found"}
{"level":"debug","handler":"HomeGetAPIPut","name":"HomeGet","path":"/","message":"route registration: API handler not found"}
{"level":"debug","handler":"HomeGetAPIPatch","name":"HomeGet","path":"/","message":"route registration: API handler not found"}
{"level":"debug","handler":"HomeGetAPIDelete","name":"HomeGet","path":"/","message":"route registration: API handler not found"}
{"level":"debug","handler":"HomeGetAPIConnect","name":"HomeGet","path":"/","message":"route registration: API handler not found"}
{"level":"debug","handler":"HomeGetAPIOptions","name":"HomeGet","path":"/","message":"route registration: API handler not found"}
{"level":"debug","handler":"HomeGetAPITrace","name":"HomeGet","path":"/","message":"route registration: API handler not found"}
{"level":"debug","handler":"HelperGet","name":"HelperGet","path":"/helper/:name","message":"route registration: handler found"}
{"level":"debug","handler":"PanicAPIGet","name":"Panic","path":"/panic","message":"route registration: API handler found"}
{"level":"debug","handler":"PanicAPIPost","name":"Panic","path":"/panic","message":"route registration: API handler not found"}
{"level":"debug","handler":"PanicAPIPut","name":"Panic","path":"/panic","message":"route registration: API handler not found"}
{"level":"debug","handler":"PanicAPIPatch","name":"Panic","path":"/panic","message":"route registration: API handler not found"}
{"level":"debug","handler":"PanicAPIDelete","name":"Panic","path":"/panic","message":"route registration: API handler not found"}
{"level":"debug","handler":"PanicAPIConnect","name":"Panic","path":"/panic","message":"route registration: API handler not found"}
{"level":"debug","handler":"PanicAPIOptions","name":"Panic","path":"/panic","message":"route registration: API handler not found"}
{"level":"debug","handler":"PanicAPITrace","name":"Panic","path":"/panic","message":"route registration: API handler not found"}
{"level":"debug","handler":"JSONAPIGet","name":"JSON","path":"/json","message":"route registration: API handler found"}
{"level":"debug","handler":"JSONAPIPost","name":"JSON","path":"/json","message":"route registration: API handler found"}
{"level":"debug","handler":"JSONAPIPut","name":"JSON","path":"/json","message":"route registration: API handler not found"}
{"level":"debug","handler":"JSONAPIPatch","name":"JSON","path":"/json","message":"route registration: API handler not found"}
{"level":"debug","handler":"JSONAPIDelete","name":"JSON","path":"/json","message":"route registration: API handler not found"}
{"level":"debug","handler":"JSONAPIConnect","name":"JSON","path":"/json","message":"route registration: API handler not found"}
{"level":"debug","handler":"JSONAPIOptions","name":"JSON","path":"/json","message":"route registration: API handler not found"}
{"level":"debug","handler":"JSONAPITrace","name":"JSON","path":"/json","message":"route registration: API handler not found"}
{"level":"debug","path":"/compressible.bin","message":"unable to determine content type for file"}
{"level":"debug","path":"/noncompressible.bin","message":"unable to determine content type for file"}
{"level":"debug","path":"/semicompressible.bin","message":"unable to determine content type for file"}
`, out.String())
}

func TestService(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Request         func() *http.Request
		ExpectedStatus  int
		ExpectedBody    []byte
		ExpectedLog     string
		ExpectedHeader  http.Header
		ExpectedTrailer http.Header
	}{
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/", nil)
			},
			http.StatusOK,
			[]byte(`<!DOCTYPE html><html><head><title>test</title></head><body>test site</body></html>`),
			`{"level":"info","method":"GET","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"HomeGet","etag":"tN1X-esKHJy3BUQrWNN0YaiNCkUYVp_5YmywXfn0Kx8","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"responseBody":82,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"82"},
				"Content-Type":           {"text/html; charset=utf-8"},
				"Date":                   {""},
				"Etag":                   {`"tN1X-esKHJy3BUQrWNN0YaiNCkUYVp_5YmywXfn0Kx8"`},
				"Request-Id":             {""},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodPost, "https://example.com/", nil)
			},
			http.StatusMethodNotAllowed,
			[]byte("Method Not Allowed\n"),
			`{"level":"warn","method":"POST","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"MethodNotAllowed","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":405,"responseBody":19,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Allow":                  {"GET, HEAD"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"19"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/data.txt", nil)
				req.Header.Set("Referer", "https://example.com/")
				return req
			},
			http.StatusOK,
			[]byte(`test data`),
			`{"level":"info","method":"GET","path":"/data.txt","client":"127.0.0.1","agent":"Go-http-client/2.0","referer":"https://example.com/","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":"kW8AJ6V1B0znKjMXd8NHjWUT94alkb2JLaGld78jNfk","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"responseBody":9,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"9"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Etag":                   {`"kW8AJ6V1B0znKjMXd8NHjWUT94alkb2JLaGld78jNfk"`},
				"Request-Id":             {""},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodPost, "https://example.com/data.txt", nil)
			},
			http.StatusMethodNotAllowed,
			[]byte("Method Not Allowed\n"),
			`{"level":"warn","method":"POST","path":"/data.txt","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"MethodNotAllowed","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":405,"responseBody":19,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Allow":                  {"GET, HEAD"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"19"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/assets/image.png", nil)
			},
			http.StatusOK,
			[]byte(`test image`),
			`{"level":"info","method":"GET","path":"/assets/image.png","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"ImmutableFile","etag":"EYcyfG0PCwsZszqyEaVJAjqppB81nG0Kgn172Z-NWZQ","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"responseBody":10,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"public,max-age=31536000,immutable,stale-while-revalidate=86400"},
				"Content-Length":         {"10"},
				"Content-Type":           {"image/png"},
				"Date":                   {""},
				"Etag":                   {`"EYcyfG0PCwsZszqyEaVJAjqppB81nG0Kgn172Z-NWZQ"`},
				"Request-Id":             {""},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/compressible.bin", nil)
				req.Header.Add("Accept-Encoding", "identity")
				return req
			},
			http.StatusOK,
			compressibleData,
			`{"level":"info","method":"GET","path":"/compressible.bin","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"32768"},
				"Content-Type":           {"application/octet-stream"},
				"Date":                   {""},
				"Etag":                   {`"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk"`},
				"Request-Id":             {""},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/compressible.bin", nil)
				req.Header.Add("Accept-Encoding", "identity")
				// We just serve what we have and ignore the header.
				req.Header.Add("Accept", "application/something")
				return req
			},
			http.StatusOK,
			compressibleData,
			`{"level":"info","method":"GET","path":"/compressible.bin","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"32768"},
				"Content-Type":           {"application/octet-stream"},
				"Date":                   {""},
				"Etag":                   {`"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk"`},
				"Request-Id":             {""},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/compressible.bin", nil)
				// We just serve what we have and ignore the header.
				req.Header.Add("Accept-Encoding", "something")
				return req
			},
			http.StatusOK,
			compressibleData,
			`{"level":"info","method":"GET","path":"/compressible.bin","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"32768"},
				"Content-Type":           {"application/octet-stream"},
				"Date":                   {""},
				"Etag":                   {`"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk"`},
				"Request-Id":             {""},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/compressible.bin", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				return req
			},
			http.StatusOK,
			compressibleDataGzip,
			`{"level":"info","method":"GET","path":"/compressible.bin","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","encoding":"gzip","etag":"gNjs0DVDKzajatdVAcvGk2jBlyyj_v_ier840Jzmwig","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"responseBody":68,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"68"},
				"Content-Type":           {"application/octet-stream"},
				"Content-Encoding":       {"gzip"},
				"Date":                   {""},
				"Etag":                   {`"gNjs0DVDKzajatdVAcvGk2jBlyyj_v_ier840Jzmwig"`},
				"Request-Id":             {""},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				// It does not compress it because ratio is to bad.
				req := newRequest(t, http.MethodGet, "https://example.com/noncompressible.bin", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				return req
			},
			http.StatusOK,
			nonCompressibleData,
			`{"level":"info","method":"GET","path":"/noncompressible.bin","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":` + nonCompressibleDataEtag + `,"build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"32768"},
				"Content-Type":           {"application/octet-stream"},
				"Date":                   {""},
				"Etag":                   {nonCompressibleDataEtag},
				"Request-Id":             {""},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				// It does not compress it because the file is too small.
				req := newRequest(t, http.MethodGet, "https://example.com/data.txt", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				return req
			},
			http.StatusOK,
			[]byte(`test data`),
			`{"level":"info","method":"GET","path":"/data.txt","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":"kW8AJ6V1B0znKjMXd8NHjWUT94alkb2JLaGld78jNfk","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"responseBody":9,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"9"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Etag":                   {`"kW8AJ6V1B0znKjMXd8NHjWUT94alkb2JLaGld78jNfk"`},
				"Request-Id":             {""},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				// No compression because we explicitly do not ask for it (Go client by default does ask for it).
				req := newRequest(t, http.MethodGet, "https://example.com/semicompressible.bin", nil)
				req.Header.Add("Accept-Encoding", "identity")
				return req
			},
			http.StatusOK,
			semiCompressibleData,
			`{"level":"info","method":"GET","path":"/semicompressible.bin","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":` + semiCompressibleDataEtag + `,"build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"32768"},
				"Content-Type":           {"application/octet-stream"},
				"Date":                   {""},
				"Etag":                   {semiCompressibleDataEtag},
				"Request-Id":             {""},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/semicompressible.bin", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				return req
			},
			http.StatusOK,
			semiCompressibleDataGzip,
			`{"level":"info","method":"GET","path":"/semicompressible.bin","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","encoding":"gzip","etag":` + semiCompressibleDataGzipEtag + `,"build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"responseBody":` + strconv.Itoa(len(semiCompressibleDataGzip)) + `,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges": {"bytes"},
				"Cache-Control": {"no-cache"},
				// TODO: Uncomment. See: https://github.com/golang/go/pull/50904
				// "Content-Length": {strconv.Itoa(len(semiCompressibleDataGzip))},.
				"Content-Type":           {"application/octet-stream"},
				"Content-Encoding":       {"gzip"},
				"Date":                   {""},
				"Etag":                   {semiCompressibleDataGzipEtag},
				"Request-Id":             {""},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/missing", nil)
			},
			http.StatusNotFound,
			[]byte("Not Found\n"),
			`{"level":"warn","method":"GET","path":"/missing","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"NotFound","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":404,"responseBody":10,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"10"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/api/", nil)
			},
			http.StatusOK,
			[]byte(`{"site":{"domain":"example.com","title":"test","description":"test site"},"build":{"version":"vTEST","buildTimestamp":"2023-11-03T00:51:07Z","revision":"abcde"}}`),
			`{"level":"info","request":"","message":"test msg"}` + "\n" +
				`{"level":"info","method":"GET","path":"/api/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"HomeGetAPIGet","etag":"aj4IanxlXD_73WR2wutz11Tk3JWHdZqpvuIvB1ivNWk","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"responseBody":161,"requestBody":0,"metrics":{"test":123456,"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"161"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {`"aj4IanxlXD_73WR2wutz11Tk3JWHdZqpvuIvB1ivNWk"`},
				"Request-Id":             {""},
				"Server-Timing":          {"test;dur="},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/helper/NotFound", nil)
			},
			http.StatusNotFound,
			[]byte("Not Found\n"),
			`{"level":"warn","method":"GET","path":"/helper/NotFound","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"HelperGet","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":404,"responseBody":10,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"10"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/helper/NotFoundWithError", nil)
			},
			http.StatusNotFound,
			[]byte("Not Found\n"),
			`{"level":"warn","method":"GET","path":"/helper/NotFoundWithError","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"HelperGet","error":"test","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":404,"responseBody":10,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"10"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/helper/MethodNotAllowed", nil)
			},
			http.StatusMethodNotAllowed,
			[]byte("Method Not Allowed\n"),
			`{"level":"warn","method":"GET","path":"/helper/MethodNotAllowed","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"HelperGet","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":405,"responseBody":19,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Allow":                  {"DELETE, GET"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"19"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/helper/InternalServerError", nil)
			},
			http.StatusInternalServerError,
			[]byte("Internal Server Error\n"),
			`{"level":"error","method":"GET","path":"/helper/InternalServerError","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"HelperGet","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":500,"responseBody":22,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"22"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/helper/InternalServerErrorWithError", nil)
			},
			http.StatusInternalServerError,
			[]byte("Internal Server Error\n"),
			`{"level":"error","method":"GET","path":"/helper/InternalServerErrorWithError","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"HelperGet","error":"test","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":500,"responseBody":22,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"22"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/helper/Canceled", nil)
			},
			http.StatusRequestTimeout,
			[]byte("Request Timeout\n"),
			`{"level":"warn","method":"GET","path":"/helper/Canceled","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"HelperGet","context":"canceled","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":408,"responseBody":16,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"16"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/helper/DeadlineExceeded", nil)
			},
			http.StatusRequestTimeout,
			[]byte("Request Timeout\n"),
			`{"level":"warn","method":"GET","path":"/helper/DeadlineExceeded","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"HelperGet","context":"deadline exceeded","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":408,"responseBody":16,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"16"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/helper/Proxy", nil)
			},
			http.StatusInternalServerError,
			[]byte("Internal Server Error\n"),
			`{"level":"error","method":"GET","path":"/helper/Proxy","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"HelperGet","error":"Proxy called while not in development","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":500,"responseBody":22,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"22"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/helper/something", nil)
			}, http.StatusBadRequest,
			[]byte("Bad Request\n"),
			`{"level":"warn","method":"GET","path":"/helper/something","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"HelperGet","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":400,"responseBody":12,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"12"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/api/panic", nil)
			},
			http.StatusInternalServerError,
			[]byte("Internal Server Error\n"),
			`{"level":"error","method":"GET","path":"/api/panic","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"PanicAPIGet","panic":true,"error":"test","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":500,"responseBody":22,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"22"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://other.example.com/", nil)
			},
			http.StatusNotFound,
			[]byte("Not Found\n"),
			`{"level":"warn","method":"GET","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"other.example.com","error":"site not found for host","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":404,"responseBody":10,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"10"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/api/json", nil)
			},
			http.StatusOK,
			[]byte(`{"data":123}`),
			`{"level":"info","method":"GET","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"JSONAPIGet","etag":"j0Jw1Eosvc8TRxjb6f9Gy2tYjfHaVdlIoKpog0X2WKE","metadata":{"foobar":42},"build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"responseBody":12,"requestBody":0,"metrics":{"j":,"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"12"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {`"j0Jw1Eosvc8TRxjb6f9Gy2tYjfHaVdlIoKpog0X2WKE"`},
				"Request-Id":             {""},
				"Test-Metadata":          {"foobar=42"},
				"Server-Timing":          {"j;dur="},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://other.example.com/api/json", nil)
			},
			http.StatusNotFound,
			[]byte("Not Found\n"),
			`{"level":"warn","method":"GET","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"other.example.com","error":"site not found for host","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":404,"responseBody":10,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"10"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodPost, "https://example.com/api/json?foo=1", bytes.NewBufferString("data=abcde"))
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			http.StatusAccepted,
			[]byte(`data=abcde&foo=1`),
			`{"level":"info","method":"POST","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","query":{"foo":["1"]},"message":"JSONAPIPost","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":202,"responseBody":16,"requestBody":10,"metrics":{"t":}}` + "\n",
			http.Header{
				"Content-Length":         {"16"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodPatch, "https://example.com/api/json?foo=1", bytes.NewBufferString("data=abcde"))
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			http.StatusMethodNotAllowed,
			[]byte("Method Not Allowed\n"),
			`{"level":"warn","method":"PATCH","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","query":{"foo":["1"]},"message":"MethodNotAllowed","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":405,"responseBody":19,"requestBody":10,"metrics":{"t":}}` + "\n",
			http.Header{
				"Allow":                  {"GET, HEAD, POST"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"19"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
	}

	for k, tt := range tests {
		tt := tt

		for _, http2 := range []bool{false, true} {
			http2 := http2

			t.Run(fmt.Sprintf("case=%d/http2=%t", k, http2), func(t *testing.T) {
				t.Parallel()

				pipeR, pipeW, err := os.Pipe()
				t.Cleanup(func() {
					// We might double close but we do not care.
					pipeR.Close()
					pipeW.Close()
				})
				require.NoError(t, err)

				_, ts := newService(t, zerolog.New(pipeW).Level(zerolog.InfoLevel), http2, "")

				// Close pipeW after serving.
				h := ts.Config.Handler
				ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					h.ServeHTTP(w, r)
					pipeW.Close()
				})

				resp, err := ts.Client().Do(tt.Request())
				if assert.NoError(t, err) {
					t.Cleanup(func() { resp.Body.Close() })
					out, err := io.ReadAll(resp.Body)
					assert.NoError(t, err)
					log, err := io.ReadAll(pipeR)
					pipeR.Close()
					assert.NoError(t, err)
					assert.Equal(t, tt.ExpectedStatus, resp.StatusCode)
					assert.Equal(t, tt.ExpectedBody, out)
					assert.Equal(t, tt.ExpectedLog, logCleanup(t, http2, string(log)))
					assert.Equal(t, tt.ExpectedHeader, headerCleanup(t, resp.Header))
					if http2 {
						assert.Equal(t, 2, resp.ProtoMajor)
						assert.Equal(t, tt.ExpectedTrailer, headerCleanup(t, resp.Trailer))
					} else {
						assert.Equal(t, 1, resp.ProtoMajor)
						assert.Equal(t, http.Header(nil), resp.Trailer)
					}
				}
			})
		}
	}
}

func TestReverseProxy(t *testing.T) {
	t.Parallel()

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		assert.NoError(t, err)
		assert.NotEmpty(t, r.Header.Get("Request-Id"), "Request-Id")
		w.Header().Add("Test-Header", "foobar")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("test\n"))
		_, _ = w.Write([]byte("post data: "))
		_, _ = w.Write([]byte(r.PostForm.Encode()))
		_, _ = w.Write([]byte("\n"))
		_, _ = w.Write([]byte("data: "))
		_, _ = w.Write([]byte(r.Form.Encode()))
		_, _ = w.Write([]byte("\n"))
	}))
	t.Cleanup(proxy.Close)

	tests := []struct {
		Request         func() *http.Request
		ExpectedStatus  int
		ExpectedBody    []byte
		ExpectedLog     string
		ExpectedHeader  http.Header
		ExpectedTrailer http.Header
	}{
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/", nil)
			},
			http.StatusOK,
			[]byte("test\npost data: \ndata: \n"),
			`{"level":"info","method":"GET","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"HomeGet","proxied":"","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"responseBody":24,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Content-Length":         {"24"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"Test-Header":            {"foobar"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/data.txt", nil)
				req.Header.Set("Referer", "https://example.com/")
				return req
			},
			http.StatusOK,
			[]byte("test\npost data: \ndata: \n"),
			`{"level":"info","method":"GET","path":"/data.txt","client":"127.0.0.1","agent":"Go-http-client/2.0","referer":"https://example.com/","connection":"","request":"","proto":"2.0","host":"example.com","message":"Proxy","proxied":"","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"responseBody":24,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Content-Length":         {"24"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"Test-Header":            {"foobar"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/assets/image.png", nil)
			},
			http.StatusOK,
			[]byte("test\npost data: \ndata: \n"),
			`{"level":"info","method":"GET","path":"/assets/image.png","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"Proxy","proxied":"","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"responseBody":24,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Content-Length":         {"24"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"Test-Header":            {"foobar"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/missing", nil)
			},
			http.StatusOK,
			[]byte("test\npost data: \ndata: \n"),
			`{"level":"info","method":"GET","path":"/missing","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"Proxy","proxied":"","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"responseBody":24,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Content-Length":         {"24"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"Test-Header":            {"foobar"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/api/", nil)
			},
			http.StatusOK,
			[]byte(`{"site":{"domain":"example.com","title":"test","description":"test site"},"build":{"version":"vTEST","buildTimestamp":"2023-11-03T00:51:07Z","revision":"abcde"}}`),
			`{"level":"info","request":"","message":"test msg"}` + "\n" +
				`{"level":"info","method":"GET","path":"/api/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"HomeGetAPIGet","etag":"aj4IanxlXD_73WR2wutz11Tk3JWHdZqpvuIvB1ivNWk","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"responseBody":161,"requestBody":0,"metrics":{"test":123456,"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"161"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {`"aj4IanxlXD_73WR2wutz11Tk3JWHdZqpvuIvB1ivNWk"`},
				"Request-Id":             {""},
				"Server-Timing":          {"test;dur="},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://other.example.com/", nil)
			},
			http.StatusNotFound,
			[]byte("Not Found\n"),
			`{"level":"warn","method":"GET","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"other.example.com","error":"site not found for host","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":404,"responseBody":10,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"10"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/api/json", nil)
			},
			http.StatusOK,
			[]byte(`{"data":123}`),
			`{"level":"info","method":"GET","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"JSONAPIGet","etag":"j0Jw1Eosvc8TRxjb6f9Gy2tYjfHaVdlIoKpog0X2WKE","metadata":{"foobar":42},"build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"responseBody":12,"requestBody":0,"metrics":{"j":,"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"12"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {`"j0Jw1Eosvc8TRxjb6f9Gy2tYjfHaVdlIoKpog0X2WKE"`},
				"Request-Id":             {""},
				"Test-Metadata":          {"foobar=42"},
				"Server-Timing":          {"j;dur="},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodPatch, "https://example.com/api/json", nil)
			},
			http.StatusOK,
			[]byte("test\npost data: \ndata: \n"),
			`{"level":"info","method":"PATCH","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"Proxy","proxied":"","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"responseBody":24,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Content-Length":         {"24"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"Test-Header":            {"foobar"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodPost, "https://example.com/?foo=1", bytes.NewBufferString("data=abcde"))
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			http.StatusOK,
			[]byte("test\npost data: data=abcde\ndata: data=abcde&foo=1\n"),
			`{"level":"info","method":"POST","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","query":{"foo":["1"]},"message":"Proxy","proxied":"","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"responseBody":50,"requestBody":10,"metrics":{"t":}}` + "\n",
			http.Header{
				"Content-Length":         {"50"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
				"Request-Id":             {""},
				"Test-Header":            {"foobar"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
	}

	for k, tt := range tests {
		tt := tt

		for _, http2 := range []bool{false, true} {
			http2 := http2

			t.Run(fmt.Sprintf("case=%d/http2=%t", k, http2), func(t *testing.T) {
				t.Parallel()

				pipeR, pipeW, err := os.Pipe()
				t.Cleanup(func() {
					// We might double close but we do not care.
					pipeR.Close()
					pipeW.Close()
				})
				require.NoError(t, err)

				_, ts := newService(t, zerolog.New(pipeW).Level(zerolog.InfoLevel), http2, proxy.URL)

				// Close pipeW after serving.
				h := ts.Config.Handler
				ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					h.ServeHTTP(w, r)
					pipeW.Close()
				})

				resp, err := ts.Client().Do(tt.Request())
				if assert.NoError(t, err) {
					t.Cleanup(func() { resp.Body.Close() })
					out, err := io.ReadAll(resp.Body)
					assert.NoError(t, err)
					log, err := io.ReadAll(pipeR)
					pipeR.Close()
					assert.NoError(t, err)
					assert.Equal(t, tt.ExpectedStatus, resp.StatusCode)
					assert.Equal(t, tt.ExpectedBody, out)
					assert.Equal(t, tt.ExpectedLog, logCleanup(t, http2, string(log)))
					assert.Equal(t, tt.ExpectedHeader, headerCleanup(t, resp.Header))
					if http2 {
						assert.Equal(t, 2, resp.ProtoMajor)
						assert.Equal(t, tt.ExpectedTrailer, headerCleanup(t, resp.Trailer))
					} else {
						assert.Equal(t, 1, resp.ProtoMajor)
						assert.Equal(t, http.Header(nil), resp.Trailer)
					}
				}
			})
		}
	}
}
