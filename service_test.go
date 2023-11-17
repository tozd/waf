package waf

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	_ "embed"
	"encoding/json"
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

	// This is here because _examples/hello.go needs this dependency.
	_ "gitlab.com/tozd/go/cli"
)

//go:embed _examples/routes.json
var routesConfiguration []byte

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
	largeJSON                    []byte
	largeJSONEtag                string
	largeJSONGzip                []byte
	largeJSONGzipEtag            string
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
	largeJSON = []byte(fmt.Sprintf(`{"x":"%x"}`, nonCompressibleData))
	largeJSONGzip, err = compress(compressionGzip, largeJSON)
	if err != nil {
		panic(err)
	}
	largeJSONEtag = computeEtag(largeJSON)
	largeJSONGzipEtag = computeEtag(largeJSONGzip)

	testFiles = fstest.MapFS{
		"assets/image.png": &fstest.MapFile{
			Data: []byte("test image"),
		},
		"data.txt": &fstest.MapFile{
			Data: []byte("test data"),
		},
		"compressible.foobar": &fstest.MapFile{
			Data: compressibleData,
		},
		"noncompressible.foobar": &fstest.MapFile{
			Data: nonCompressibleData,
		},
		"semicompressible.foobar": &fstest.MapFile{
			Data: semiCompressibleData,
		},
		"index.html": &fstest.MapFile{
			Data: []byte(`<!DOCTYPE html><html><head><title>{{ .Title }}</title></head><body>{{ .Description }}</body></html>`),
		},
	}
}

type testSite struct {
	Site `yaml:",inline"`

	Title       string `json:"title"       yaml:"title"`
	Description string `json:"description" yaml:"description"`

	Version        string `json:"version,omitempty"        yaml:"-"`
	BuildTimestamp string `json:"buildTimestamp,omitempty" yaml:"-"`
	Revision       string `json:"revision,omitempty"       yaml:"-"`
}

type testService struct {
	Service[*testSite]
}

func (s *testService) HomeGet(w http.ResponseWriter, req *http.Request, _ Params) {
	timing := servertiming.FromContext(req.Context())
	timing.NewMetric("test").Duration = 123456789 * time.Microsecond

	hlog.FromRequest(req).Info().Msg("test msg")

	s.ServeStaticFile(w, req, "/index.json")
}

func (s *testService) Home(w http.ResponseWriter, req *http.Request, _ Params) {
	if s.Development != "" {
		s.Proxy(w, req)
	} else {
		s.ServeStaticFile(w, req, "/index.html")
	}
}

func (s *testService) Helper(w http.ResponseWriter, req *http.Request, p Params) {
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

func (s *testService) PanicGet(_ http.ResponseWriter, _ *http.Request, _ Params) {
	panic(errors.New("test"))
}

func (s *testService) JSONGet(w http.ResponseWriter, req *http.Request, _ Params) {
	s.WriteJSON(w, req, map[string]interface{}{"data": 123}, map[string]interface{}{"foobar": 42})
}

func (s *testService) JSONPost(w http.ResponseWriter, req *http.Request, _ Params) {
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(req.Form.Encode()))
}

func (s *testService) LargeGet(w http.ResponseWriter, req *http.Request, _ Params) {
	s.WriteJSON(w, req, json.RawMessage(largeJSON), nil)
}

func (s *testService) NonCompressibleJSONGet(w http.ResponseWriter, req *http.Request, _ Params) {
	// Do not do this. We are misusing support for []byte here to pass raw random bytes which are not valid JSON.
	// We need this to test the non-compressible code path in WriteJSON which seems it will never be taken
	// with valid JSON which seems to be always compressible.
	s.WriteJSON(w, req, nonCompressibleData, nil)
}

func (s *testService) InvalidHandlerTypeGet() {}

func newRequest(t *testing.T, method, url string, body io.Reader) *http.Request {
	t.Helper()

	req, err := http.NewRequest(method, url, body) //nolint:noctx
	require.NoError(t, err)
	return req
}

func newService(t *testing.T, logger zerolog.Logger, https2 bool, development string) (*testService, *httptest.Server) {
	t.Helper()

	build := zerolog.Dict()
	build = build.Str("r", "abcde")
	build = build.Str("t", "2023-11-03T00:51:07Z")
	build = build.Str("v", "vTEST")
	canonicalLogger := logger.With().Dict("build", build).Logger()

	service := &testService{
		Service: Service[*testSite]{
			Logger:          logger,
			CanonicalLogger: canonicalLogger,
			StaticFiles:     testFiles,
			Routes: []Route{
				{
					Name: "Home",
					Path: "/",
					API:  true,
					Get:  true,
				},
				{
					Name: "Helper",
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
				{
					Name: "Large",
					Path: "/large",
					API:  true,
					Get:  false,
				},
				{
					Name: "NonCompressibleJSON",
					Path: "/noncompressible",
					API:  true,
					Get:  false,
				},
			},
			Sites: map[string]*testSite{
				"example.com": {
					Site: Site{
						Domain: "example.com",
					},
					Title:          "test",
					Description:    "test site",
					Version:        "vTEST",
					Revision:       "abcde",
					BuildTimestamp: "2023-11-03T00:51:07Z",
				},
			},
			SiteContextPath:      "/index.json",
			MetadataHeaderPrefix: "Test-",
			Development:          development,
			IsImmutableFile: func(path string) bool {
				return strings.HasPrefix(path, "/assets/")
			},
			SkipServingFile: func(path string) bool {
				return path == "/index.html" || path == "/index.json"
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
	client.Transport.(*http.Transport).DisableCompression = true //nolint:forcetypeassert

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
	assert.ErrorContains(t, errE, "RouteWith called more than once")
}

func TestServiceConfigureRoutes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Routes []Route
		Err    string
	}{
		{
			nil,
			"",
		},
		{
			[]Route{
				{
					Name: "Home",
					Path: "/",
					API:  false,
					Get:  false,
				},
			},
			`at least one of "get" and "api" has to be true`,
		},
		{
			[]Route{
				{
					Name: "SomethingMissing",
					Path: "/",
					API:  false,
					Get:  true,
				},
			},
			`handler not found`,
		},
		{
			[]Route{
				{
					Name: "Proxy",
					Path: "/",
					API:  false,
					Get:  true,
				},
			},
			`invalid handler type`,
		},
		{
			[]Route{
				{
					Name: "SomethingMissing",
					Path: "/",
					API:  true,
					Get:  false,
				},
			},
			`no API handler found`,
		},
		{
			[]Route{
				{
					Name: "InvalidHandlerType",
					Path: "/",
					API:  true,
					Get:  false,
				},
			},
			`invalid API handler type`,
		},
	}

	for k, tt := range tests {
		tt := tt

		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			t.Parallel()

			s := &testService{
				Service: Service[*testSite]{
					router: &Router{},
					Routes: tt.Routes,
				},
			}

			errE := s.configureRoutes(s)
			if tt.Err != "" {
				assert.ErrorContains(t, errE, tt.Err)
			} else {
				assert.NoError(t, errE, "% -+#.1v", errE)
			}
		})
	}
}

func TestServiceReverse(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}

	service, _ := newService(t, zerolog.New(out), false, "")

	p, errE := service.Reverse("Home", nil, url.Values{"x": []string{"y"}, "a": []string{"b", "c"}, "b": []string{}})
	assert.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, `/?a=b&a=c&x=y`, p)

	p, errE = service.ReverseAPI("Home", nil, url.Values{"x": []string{"y"}, "a": []string{"b", "c"}, "b": []string{}})
	assert.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, `/api/?a=b&a=c&x=y`, p)

	_, errE = service.Reverse("Home", Params{"x": "y"}, nil)
	assert.ErrorContains(t, errE, "extra parameters")

	_, errE = service.Reverse("Helper", nil, nil)
	assert.ErrorContains(t, errE, "parameter is missing")

	_, errE = service.Reverse("JSON", nil, nil)
	assert.ErrorContains(t, errE, "route has no GET handler")

	_, errE = service.Reverse("something", nil, nil)
	assert.ErrorContains(t, errE, "route does not exist")

	assert.Equal(t, `{"level":"debug","handler":"Home","route":"Home","path":"/","message":"route registration: handler found"}
{"level":"debug","handler":"HomeGet","route":"Home","path":"/","message":"route registration: API handler found"}
{"level":"debug","handler":"HomePost","route":"Home","path":"/","message":"route registration: API handler not found"}
{"level":"debug","handler":"HomePut","route":"Home","path":"/","message":"route registration: API handler not found"}
{"level":"debug","handler":"HomePatch","route":"Home","path":"/","message":"route registration: API handler not found"}
{"level":"debug","handler":"HomeDelete","route":"Home","path":"/","message":"route registration: API handler not found"}
{"level":"debug","handler":"HomeConnect","route":"Home","path":"/","message":"route registration: API handler not found"}
{"level":"debug","handler":"HomeOptions","route":"Home","path":"/","message":"route registration: API handler not found"}
{"level":"debug","handler":"HomeTrace","route":"Home","path":"/","message":"route registration: API handler not found"}
{"level":"debug","handler":"Helper","route":"Helper","path":"/helper/:name","message":"route registration: handler found"}
{"level":"debug","handler":"PanicGet","route":"Panic","path":"/panic","message":"route registration: API handler found"}
{"level":"debug","handler":"PanicPost","route":"Panic","path":"/panic","message":"route registration: API handler not found"}
{"level":"debug","handler":"PanicPut","route":"Panic","path":"/panic","message":"route registration: API handler not found"}
{"level":"debug","handler":"PanicPatch","route":"Panic","path":"/panic","message":"route registration: API handler not found"}
{"level":"debug","handler":"PanicDelete","route":"Panic","path":"/panic","message":"route registration: API handler not found"}
{"level":"debug","handler":"PanicConnect","route":"Panic","path":"/panic","message":"route registration: API handler not found"}
{"level":"debug","handler":"PanicOptions","route":"Panic","path":"/panic","message":"route registration: API handler not found"}
{"level":"debug","handler":"PanicTrace","route":"Panic","path":"/panic","message":"route registration: API handler not found"}
{"level":"debug","handler":"JSONGet","route":"JSON","path":"/json","message":"route registration: API handler found"}
{"level":"debug","handler":"JSONPost","route":"JSON","path":"/json","message":"route registration: API handler found"}
{"level":"debug","handler":"JSONPut","route":"JSON","path":"/json","message":"route registration: API handler not found"}
{"level":"debug","handler":"JSONPatch","route":"JSON","path":"/json","message":"route registration: API handler not found"}
{"level":"debug","handler":"JSONDelete","route":"JSON","path":"/json","message":"route registration: API handler not found"}
{"level":"debug","handler":"JSONConnect","route":"JSON","path":"/json","message":"route registration: API handler not found"}
{"level":"debug","handler":"JSONOptions","route":"JSON","path":"/json","message":"route registration: API handler not found"}
{"level":"debug","handler":"JSONTrace","route":"JSON","path":"/json","message":"route registration: API handler not found"}
{"level":"debug","handler":"LargeGet","route":"Large","path":"/large","message":"route registration: API handler found"}
{"level":"debug","handler":"LargePost","route":"Large","path":"/large","message":"route registration: API handler not found"}
{"level":"debug","handler":"LargePut","route":"Large","path":"/large","message":"route registration: API handler not found"}
{"level":"debug","handler":"LargePatch","route":"Large","path":"/large","message":"route registration: API handler not found"}
{"level":"debug","handler":"LargeDelete","route":"Large","path":"/large","message":"route registration: API handler not found"}
{"level":"debug","handler":"LargeConnect","route":"Large","path":"/large","message":"route registration: API handler not found"}
{"level":"debug","handler":"LargeOptions","route":"Large","path":"/large","message":"route registration: API handler not found"}
{"level":"debug","handler":"LargeTrace","route":"Large","path":"/large","message":"route registration: API handler not found"}
{"level":"debug","handler":"NonCompressibleJSONGet","route":"NonCompressibleJSON","path":"/noncompressible","message":"route registration: API handler found"}
{"level":"debug","handler":"NonCompressibleJSONPost","route":"NonCompressibleJSON","path":"/noncompressible","message":"route registration: API handler not found"}
{"level":"debug","handler":"NonCompressibleJSONPut","route":"NonCompressibleJSON","path":"/noncompressible","message":"route registration: API handler not found"}
{"level":"debug","handler":"NonCompressibleJSONPatch","route":"NonCompressibleJSON","path":"/noncompressible","message":"route registration: API handler not found"}
{"level":"debug","handler":"NonCompressibleJSONDelete","route":"NonCompressibleJSON","path":"/noncompressible","message":"route registration: API handler not found"}
{"level":"debug","handler":"NonCompressibleJSONConnect","route":"NonCompressibleJSON","path":"/noncompressible","message":"route registration: API handler not found"}
{"level":"debug","handler":"NonCompressibleJSONOptions","route":"NonCompressibleJSON","path":"/noncompressible","message":"route registration: API handler not found"}
{"level":"debug","handler":"NonCompressibleJSONTrace","route":"NonCompressibleJSON","path":"/noncompressible","message":"route registration: API handler not found"}
{"level":"debug","path":"/compressible.foobar","message":"unable to determine content type for file"}
{"level":"debug","path":"/noncompressible.foobar","message":"unable to determine content type for file"}
{"level":"debug","path":"/semicompressible.foobar","message":"unable to determine content type for file"}
`, out.String())
}

func TestService(t *testing.T) {
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
		Development     string
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
			"",
			http.StatusOK,
			[]byte(`<!DOCTYPE html><html><head><title>test</title></head><body>test site</body></html>`),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"Home","etag":"tN1X-esKHJy3BUQrWNN0YaiNCkUYVp_5YmywXfn0Kx8","code":200,"responseBody":82,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			"",
			http.StatusMethodNotAllowed,
			[]byte("Method Not Allowed\n"),
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"POST","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"MethodNotAllowed","code":405,"responseBody":19,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			"",
			http.StatusOK,
			[]byte(`test data`),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/data.txt","client":"127.0.0.1","agent":"Go-http-client/2.0","referer":"https://example.com/","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":"kW8AJ6V1B0znKjMXd8NHjWUT94alkb2JLaGld78jNfk","code":200,"responseBody":9,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			"",
			http.StatusMethodNotAllowed,
			[]byte("Method Not Allowed\n"),
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"POST","path":"/data.txt","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"MethodNotAllowed","code":405,"responseBody":19,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			"",
			http.StatusOK,
			[]byte(`test image`),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/assets/image.png","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"ImmutableFile","etag":"EYcyfG0PCwsZszqyEaVJAjqppB81nG0Kgn172Z-NWZQ","code":200,"responseBody":10,"requestBody":0,"metrics":{"t":}}` + "\n",
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
				return newRequest(t, http.MethodGet, "https://example.com/compressible.foobar", nil)
			},
			"",
			http.StatusOK,
			compressibleData,
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/compressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk","code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":}}` + "\n",
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
				req := newRequest(t, http.MethodGet, "https://example.com/compressible.foobar", nil)
				// We just serve what we have and ignore the header.
				req.Header.Add("Accept", "application/something")
				return req
			},
			"",
			http.StatusOK,
			compressibleData,
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/compressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk","code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":}}` + "\n",
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
				req := newRequest(t, http.MethodGet, "https://example.com/compressible.foobar", nil)
				// We just serve what we have and ignore the header.
				req.Header.Add("Accept-Encoding", "something")
				return req
			},
			"",
			http.StatusOK,
			compressibleData,
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/compressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk","code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":}}` + "\n",
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
				req := newRequest(t, http.MethodGet, "https://example.com/compressible.foobar", nil)
				// We just serve what we have and ignore the header.
				req.Header.Add("Accept-Encoding", "identity;q=0.0")
				return req
			},
			"",
			http.StatusOK,
			compressibleData,
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/compressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk","code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":}}` + "\n",
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
				// It does not compress it because the file is too small.
				req := newRequest(t, http.MethodGet, "https://example.com/compressible.foobar", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				return req
			},
			"",
			http.StatusOK,
			compressibleDataGzip,
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/compressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","encoding":"gzip","etag":"gNjs0DVDKzajatdVAcvGk2jBlyyj_v_ier840Jzmwig","code":200,"responseBody":68,"requestBody":0,"metrics":{"t":}}` + "\n",
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
				req := newRequest(t, http.MethodGet, "https://example.com/noncompressible.foobar", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				return req
			},
			"",
			http.StatusOK,
			nonCompressibleData,
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/noncompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":` + nonCompressibleDataEtag + `,"code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			"",
			http.StatusOK,
			[]byte(`test data`),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/data.txt","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":"kW8AJ6V1B0znKjMXd8NHjWUT94alkb2JLaGld78jNfk","code":200,"responseBody":9,"requestBody":0,"metrics":{"t":}}` + "\n",
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
				return newRequest(t, http.MethodGet, "https://example.com/semicompressible.foobar", nil)
			},
			"",
			http.StatusOK,
			semiCompressibleData,
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":` + semiCompressibleDataEtag + `,"code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":}}` + "\n",
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
				req := newRequest(t, http.MethodGet, "https://example.com/semicompressible.foobar", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				return req
			},
			"",
			http.StatusOK,
			semiCompressibleDataGzip,
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","encoding":"gzip","etag":` + semiCompressibleDataGzipEtag + `,"code":200,"responseBody":` + strconv.Itoa(len(semiCompressibleDataGzip)) + `,"requestBody":0,"metrics":{"t":}}` + "\n",
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
				req := newRequest(t, http.MethodGet, "https://example.com/semicompressible.foobar", nil)
				req.Header.Add("If-None-Match", semiCompressibleDataEtag)
				return req
			},
			"",
			http.StatusNotModified,
			[]byte{},
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":` + semiCompressibleDataEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Cache-Control": {"no-cache"},
				"Date":          {""},
				"Etag":          {semiCompressibleDataEtag},
				"Vary":          {"Accept-Encoding"},
			},
			nil,
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/semicompressible.foobar", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				req.Header.Add("If-None-Match", semiCompressibleDataGzipEtag)
				return req
			},
			"",
			http.StatusNotModified,
			[]byte{},
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":` + semiCompressibleDataGzipEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Cache-Control": {"no-cache"},
				"Date":          {""},
				"Etag":          {semiCompressibleDataGzipEtag},
				"Vary":          {"Accept-Encoding"},
			},
			nil,
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/semicompressible.foobar", nil)
				req.Header.Add("Range", "bytes=100-200")
				return req
			},
			"",
			http.StatusPartialContent,
			semiCompressibleData[100:201],
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":` + semiCompressibleDataEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"101"},
				"Content-Range":          {"bytes 100-200/32768"},
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
				req := newRequest(t, http.MethodGet, "https://example.com/semicompressible.foobar", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				req.Header.Add("Range", "bytes=100-200")
				return req
			},
			"",
			http.StatusPartialContent,
			semiCompressibleDataGzip[100:201],
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","encoding":"gzip","etag":` + semiCompressibleDataGzipEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"101"},
				"Content-Range":          {"bytes 100-200/" + strconv.Itoa(len(semiCompressibleDataGzip))},
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
				req := newRequest(t, http.MethodGet, "https://example.com/semicompressible.foobar", nil)
				req.Header.Add("Range", "bytes=100-20000")
				return req
			},
			"",
			http.StatusPartialContent,
			semiCompressibleData[100:20001],
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":` + semiCompressibleDataEtag + `,"code":206,"responseBody":19901,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"19901"},
				"Content-Range":          {"bytes 100-20000/32768"},
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
				req := newRequest(t, http.MethodGet, "https://example.com/semicompressible.foobar", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				req.Header.Add("Range", "bytes=100-20000")
				return req
			},
			"",
			http.StatusPartialContent,
			semiCompressibleDataGzip[100:20001],
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","encoding":"gzip","etag":` + semiCompressibleDataGzipEtag + `,"code":206,"responseBody":19901,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges": {"bytes"},
				"Cache-Control": {"no-cache"},
				// TODO: Uncomment. See: https://github.com/golang/go/pull/50904
				// "Content-Length": {"19901"},.
				"Content-Range":          {"bytes 100-20000/" + strconv.Itoa(len(semiCompressibleDataGzip))},
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
				req := newRequest(t, http.MethodGet, "https://example.com/semicompressible.foobar", nil)
				req.Header.Add("Range", "bytes=100-200")
				req.Header.Add("If-None-Match", semiCompressibleDataEtag)
				return req
			},
			"",
			http.StatusNotModified,
			[]byte{},
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":` + semiCompressibleDataEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Cache-Control": {"no-cache"},
				"Date":          {""},
				"Etag":          {semiCompressibleDataEtag},
				"Vary":          {"Accept-Encoding"},
			},
			nil,
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/semicompressible.foobar", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				req.Header.Add("Range", "bytes=100-200")
				req.Header.Add("If-None-Match", semiCompressibleDataGzipEtag)
				return req
			},
			"",
			http.StatusNotModified,
			[]byte{},
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":` + semiCompressibleDataGzipEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Cache-Control": {"no-cache"},
				"Date":          {""},
				"Etag":          {semiCompressibleDataGzipEtag},
				"Vary":          {"Accept-Encoding"},
			},
			nil,
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/semicompressible.foobar", nil)
				req.Header.Add("Range", "bytes=100-200")
				req.Header.Add("If-None-Match", `"invalid"`)
				return req
			},
			"",
			http.StatusPartialContent,
			semiCompressibleData[100:201],
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":` + semiCompressibleDataEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"101"},
				"Content-Range":          {"bytes 100-200/32768"},
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
				req := newRequest(t, http.MethodGet, "https://example.com/semicompressible.foobar", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				req.Header.Add("Range", "bytes=100-200")
				req.Header.Add("If-None-Match", `"invalid"`)
				return req
			},
			"",
			http.StatusPartialContent,
			semiCompressibleDataGzip[100:201],
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","encoding":"gzip","etag":` + semiCompressibleDataGzipEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"101"},
				"Content-Range":          {"bytes 100-200/" + strconv.Itoa(len(semiCompressibleDataGzip))},
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
				req := newRequest(t, http.MethodGet, "https://example.com/semicompressible.foobar", nil)
				req.Header.Add("Range", "bytes=100-200")
				req.Header.Add("If-Range", semiCompressibleDataEtag)
				return req
			},
			"",
			http.StatusPartialContent,
			semiCompressibleData[100:201],
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":` + semiCompressibleDataEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"101"},
				"Content-Range":          {"bytes 100-200/32768"},
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
				req := newRequest(t, http.MethodGet, "https://example.com/semicompressible.foobar", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				req.Header.Add("Range", "bytes=100-200")
				req.Header.Add("If-Range", semiCompressibleDataGzipEtag)
				return req
			},
			"",
			http.StatusPartialContent,
			semiCompressibleDataGzip[100:201],
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","encoding":"gzip","etag":` + semiCompressibleDataGzipEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"101"},
				"Content-Range":          {"bytes 100-200/" + strconv.Itoa(len(semiCompressibleDataGzip))},
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
				req := newRequest(t, http.MethodGet, "https://example.com/semicompressible.foobar", nil)
				req.Header.Add("Range", "bytes=100-200")
				req.Header.Add("If-Range", `"invalid"`)
				return req
			},
			"",
			http.StatusOK,
			semiCompressibleData,
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","etag":` + semiCompressibleDataEtag + `,"code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":}}` + "\n",
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
				req := newRequest(t, http.MethodGet, "https://example.com/semicompressible.foobar", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				req.Header.Add("Range", "bytes=100-200")
				req.Header.Add("If-Range", `"invalid"`)
				return req
			},
			"",
			http.StatusOK,
			semiCompressibleDataGzip,
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"StaticFile","encoding":"gzip","etag":` + semiCompressibleDataGzipEtag + `,"code":200,"responseBody":` + strconv.Itoa(len(semiCompressibleDataGzip)) + `,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			"",
			http.StatusNotFound,
			[]byte("Not Found\n"),
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/missing","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"NotFound","code":404,"responseBody":10,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			"",
			http.StatusOK,
			[]byte(`{"domain":"example.com","title":"test","description":"test site","version":"vTEST","buildTimestamp":"2023-11-03T00:51:07Z","revision":"abcde"}`),
			`{"level":"info","request":"","message":"test msg"}` + "\n" +
				`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"HomeGet","etag":"L-2SWZmdBbqCzd6xOfS5Via-1_urwrPdsIWeC-2XAok","code":200,"responseBody":142,"requestBody":0,"metrics":{"test":123456,"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"142"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {`"L-2SWZmdBbqCzd6xOfS5Via-1_urwrPdsIWeC-2XAok"`},
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
			"",
			http.StatusNotFound,
			[]byte("Not Found\n"),
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/NotFound","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"Helper","code":404,"responseBody":10,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			"",
			http.StatusNotFound,
			[]byte("Not Found\n"),
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/NotFoundWithError","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"Helper","error":"test","code":404,"responseBody":10,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			"",
			http.StatusMethodNotAllowed,
			[]byte("Method Not Allowed\n"),
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/MethodNotAllowed","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"Helper","code":405,"responseBody":19,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			"",
			http.StatusInternalServerError,
			[]byte("Internal Server Error\n"),
			`{"level":"error","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/InternalServerError","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"Helper","code":500,"responseBody":22,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			"",
			http.StatusInternalServerError,
			[]byte("Internal Server Error\n"),
			`{"level":"error","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/InternalServerErrorWithError","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"Helper","error":"test","code":500,"responseBody":22,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			"",
			http.StatusRequestTimeout,
			[]byte("Request Timeout\n"),
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/Canceled","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"Helper","context":"canceled","code":408,"responseBody":16,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			"",
			http.StatusRequestTimeout,
			[]byte("Request Timeout\n"),
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/DeadlineExceeded","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"Helper","context":"deadline exceeded","code":408,"responseBody":16,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			"",
			http.StatusInternalServerError,
			[]byte("Internal Server Error\n"),
			`{"level":"error","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/Proxy","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"Helper","error":"Proxy called while not in development","code":500,"responseBody":22,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			},
			"",
			http.StatusBadRequest,
			[]byte("Bad Request\n"),
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/something","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"Helper","code":400,"responseBody":12,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			"",
			http.StatusInternalServerError,
			[]byte("Internal Server Error\n"),
			`{"level":"error","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/panic","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"PanicGet","panic":true,"error":"test","code":500,"responseBody":22,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			"",
			http.StatusNotFound,
			[]byte("Not Found\n"),
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"other.example.com","error":"site not found for host","code":404,"responseBody":10,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			"",
			http.StatusOK,
			[]byte(`{"data":123}`),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"JSONGet","etag":"j0Jw1Eosvc8TRxjb6f9Gy2tYjfHaVdlIoKpog0X2WKE","metadata":{"foobar":42},"code":200,"responseBody":12,"requestBody":0,"metrics":{"j":,"t":}}` + "\n",
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
				// It does not compress it because the content is too small.
				req := newRequest(t, http.MethodGet, "https://example.com/api/json", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				return req
			},
			"",
			http.StatusOK,
			[]byte(`{"data":123}`),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"JSONGet","etag":"j0Jw1Eosvc8TRxjb6f9Gy2tYjfHaVdlIoKpog0X2WKE","metadata":{"foobar":42},"code":200,"responseBody":12,"requestBody":0,"metrics":{"j":,"t":}}` + "\n",
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
			"",
			http.StatusNotFound,
			[]byte("Not Found\n"),
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"other.example.com","error":"site not found for host","code":404,"responseBody":10,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			"",
			http.StatusAccepted,
			[]byte(`data=abcde&foo=1`),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"POST","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","query":{"foo":["1"]},"message":"JSONPost","code":202,"responseBody":16,"requestBody":10,"metrics":{"t":}}` + "\n",
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
			"",
			http.StatusMethodNotAllowed,
			[]byte("Method Not Allowed\n"),
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"PATCH","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","query":{"foo":["1"]},"message":"MethodNotAllowed","code":405,"responseBody":19,"requestBody":10,"metrics":{"t":}}` + "\n",
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
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/api/large", nil)
			},
			"",
			http.StatusOK,
			largeJSON,
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"LargeGet","etag":` + largeJSONEtag + `,"code":200,"responseBody":65544,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"65544"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {largeJSONEtag},
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
				req := newRequest(t, http.MethodGet, "https://example.com/api/large", nil)
				// We just serve what we have and ignore the header.
				req.Header.Add("Accept-Encoding", "identity;q=0.0")
				return req
			},
			"",
			http.StatusOK,
			largeJSON,
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"LargeGet","etag":` + largeJSONEtag + `,"code":200,"responseBody":65544,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"65544"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {largeJSONEtag},
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
				req := newRequest(t, http.MethodGet, "https://example.com/api/large", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				return req
			},
			"",
			http.StatusOK,
			largeJSONGzip,
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"LargeGet","encoding":"gzip","etag":` + largeJSONGzipEtag + `,"code":200,"responseBody":` + strconv.Itoa(len(largeJSONGzip)) + `,"requestBody":0,"metrics":{"c":,"t":}}` + "\n",
			http.Header{
				"Accept-Ranges": {"bytes"},
				"Cache-Control": {"no-cache"},
				// TODO: Uncomment. See: https://github.com/golang/go/pull/50904
				// "Content-Length": {strconv.Itoa(len(largeJSONGzip))},.
				"Content-Type":           {"application/json"},
				"Content-Encoding":       {"gzip"},
				"Date":                   {""},
				"Etag":                   {largeJSONGzipEtag},
				"Request-Id":             {""},
				"Server-Timing":          {"c;dur="},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/api/large", nil)
				req.Header.Add("If-None-Match", largeJSONEtag)
				return req
			},
			"",
			http.StatusNotModified,
			[]byte{},
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"LargeGet","etag":` + largeJSONEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Cache-Control": {"no-cache"},
				"Date":          {""},
				"Etag":          {largeJSONEtag},
				"Vary":          {"Accept-Encoding"},
			},
			nil,
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/api/large", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				req.Header.Add("If-None-Match", largeJSONGzipEtag)
				return req
			},
			"",
			http.StatusNotModified,
			[]byte{},
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"LargeGet","etag":` + largeJSONGzipEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"c":,"t":}}` + "\n",
			http.Header{
				"Cache-Control": {"no-cache"},
				"Date":          {""},
				"Etag":          {largeJSONGzipEtag},
				"Vary":          {"Accept-Encoding"},
			},
			nil,
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/api/large", nil)
				req.Header.Add("Range", "bytes=100-200")
				return req
			},
			"",
			http.StatusPartialContent,
			largeJSON[100:201],
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"LargeGet","etag":` + largeJSONEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"101"},
				"Content-Range":          {"bytes 100-200/65544"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {largeJSONEtag},
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
				req := newRequest(t, http.MethodGet, "https://example.com/api/large", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				req.Header.Add("Range", "bytes=100-200")
				return req
			},
			"",
			http.StatusPartialContent,
			largeJSONGzip[100:201],
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"LargeGet","encoding":"gzip","etag":` + largeJSONGzipEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"c":,"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"101"},
				"Content-Range":          {"bytes 100-200/" + strconv.Itoa(len(largeJSONGzip))},
				"Content-Type":           {"application/json"},
				"Content-Encoding":       {"gzip"},
				"Date":                   {""},
				"Etag":                   {largeJSONGzipEtag},
				"Request-Id":             {""},
				"Server-Timing":          {"c;dur="},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/api/large", nil)
				req.Header.Add("Range", "bytes=100-20000")
				return req
			},
			"",
			http.StatusPartialContent,
			largeJSON[100:20001],
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"LargeGet","etag":` + largeJSONEtag + `,"code":206,"responseBody":19901,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"19901"},
				"Content-Range":          {"bytes 100-20000/65544"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {largeJSONEtag},
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
				req := newRequest(t, http.MethodGet, "https://example.com/api/large", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				req.Header.Add("Range", "bytes=100-20000")
				return req
			},
			"",
			http.StatusPartialContent,
			largeJSONGzip[100:20001],
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"LargeGet","encoding":"gzip","etag":` + largeJSONGzipEtag + `,"code":206,"responseBody":19901,"requestBody":0,"metrics":{"c":,"t":}}` + "\n",
			http.Header{
				"Accept-Ranges": {"bytes"},
				"Cache-Control": {"no-cache"},
				// TODO: Uncomment. See: https://github.com/golang/go/pull/50904
				// "Content-Length": {"19901"},.
				"Content-Range":          {"bytes 100-20000/" + strconv.Itoa(len(largeJSONGzip))},
				"Content-Type":           {"application/json"},
				"Content-Encoding":       {"gzip"},
				"Date":                   {""},
				"Etag":                   {largeJSONGzipEtag},
				"Request-Id":             {""},
				"Server-Timing":          {"c;dur="},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/api/large", nil)
				req.Header.Add("Range", "bytes=100-200")
				req.Header.Add("If-None-Match", largeJSONEtag)
				return req
			},
			"",
			http.StatusNotModified,
			[]byte{},
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"LargeGet","etag":` + largeJSONEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Cache-Control": {"no-cache"},
				"Date":          {""},
				"Etag":          {largeJSONEtag},
				"Vary":          {"Accept-Encoding"},
			},
			nil,
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/api/large", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				req.Header.Add("Range", "bytes=100-200")
				req.Header.Add("If-None-Match", largeJSONGzipEtag)
				return req
			},
			"",
			http.StatusNotModified,
			[]byte{},
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"LargeGet","etag":` + largeJSONGzipEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"c":,"t":}}` + "\n",
			http.Header{
				"Cache-Control": {"no-cache"},
				"Date":          {""},
				"Etag":          {largeJSONGzipEtag},
				"Vary":          {"Accept-Encoding"},
			},
			nil,
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/api/large", nil)
				req.Header.Add("Range", "bytes=100-200")
				req.Header.Add("If-None-Match", `"invalid"`)
				return req
			},
			"",
			http.StatusPartialContent,
			largeJSON[100:201],
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"LargeGet","etag":` + largeJSONEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"101"},
				"Content-Range":          {"bytes 100-200/65544"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {largeJSONEtag},
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
				req := newRequest(t, http.MethodGet, "https://example.com/api/large", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				req.Header.Add("Range", "bytes=100-200")
				req.Header.Add("If-None-Match", `"invalid"`)
				return req
			},
			"",
			http.StatusPartialContent,
			largeJSONGzip[100:201],
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"LargeGet","encoding":"gzip","etag":` + largeJSONGzipEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"c":,"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"101"},
				"Content-Range":          {"bytes 100-200/" + strconv.Itoa(len(largeJSONGzip))},
				"Content-Type":           {"application/json"},
				"Content-Encoding":       {"gzip"},
				"Date":                   {""},
				"Etag":                   {largeJSONGzipEtag},
				"Request-Id":             {""},
				"Server-Timing":          {"c;dur="},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/api/large", nil)
				req.Header.Add("Range", "bytes=100-200")
				req.Header.Add("If-Range", largeJSONEtag)
				return req
			},
			"",
			http.StatusPartialContent,
			largeJSON[100:201],
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"LargeGet","etag":` + largeJSONEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"101"},
				"Content-Range":          {"bytes 100-200/65544"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {largeJSONEtag},
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
				req := newRequest(t, http.MethodGet, "https://example.com/api/large", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				req.Header.Add("Range", "bytes=100-200")
				req.Header.Add("If-Range", largeJSONGzipEtag)
				return req
			},
			"",
			http.StatusPartialContent,
			largeJSONGzip[100:201],
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"LargeGet","encoding":"gzip","etag":` + largeJSONGzipEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"c":,"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"101"},
				"Content-Range":          {"bytes 100-200/" + strconv.Itoa(len(largeJSONGzip))},
				"Content-Type":           {"application/json"},
				"Content-Encoding":       {"gzip"},
				"Date":                   {""},
				"Etag":                   {largeJSONGzipEtag},
				"Request-Id":             {""},
				"Server-Timing":          {"c;dur="},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/api/large", nil)
				req.Header.Add("Range", "bytes=100-200")
				req.Header.Add("If-Range", `"invalid"`)
				return req
			},
			"",
			http.StatusOK,
			largeJSON,
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"LargeGet","etag":` + largeJSONEtag + `,"code":200,"responseBody":65544,"requestBody":0,"metrics":{"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"65544"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {largeJSONEtag},
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
				req := newRequest(t, http.MethodGet, "https://example.com/api/large", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				req.Header.Add("Range", "bytes=100-200")
				req.Header.Add("If-Range", `"invalid"`)
				return req
			},
			"",
			http.StatusOK,
			largeJSONGzip,
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"LargeGet","encoding":"gzip","etag":` + largeJSONGzipEtag + `,"code":200,"responseBody":` + strconv.Itoa(len(largeJSONGzip)) + `,"requestBody":0,"metrics":{"c":,"t":}}` + "\n",
			http.Header{
				"Accept-Ranges": {"bytes"},
				"Cache-Control": {"no-cache"},
				// TODO: Uncomment. See: https://github.com/golang/go/pull/50904
				// "Content-Length": {strconv.Itoa(len(largeJSONGzip))},.
				"Content-Type":           {"application/json"},
				"Content-Encoding":       {"gzip"},
				"Date":                   {""},
				"Etag":                   {largeJSONGzipEtag},
				"Request-Id":             {""},
				"Server-Timing":          {"c;dur="},
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
				req := newRequest(t, http.MethodGet, "https://example.com/api/noncompressible", nil)
				req.Header.Add("Accept-Encoding", "gzip")
				return req
			},
			"",
			http.StatusOK,
			nonCompressibleData,
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/noncompressible","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"NonCompressibleJSONGet","etag":` + nonCompressibleDataEtag + `,"code":200,"responseBody":32768,"requestBody":0,"metrics":{"c":,"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"32768"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {nonCompressibleDataEtag},
				"Request-Id":             {""},
				"Server-Timing":          {"c;dur="},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/", nil)
			},
			proxy.URL,
			http.StatusOK,
			[]byte("test\npost data: \ndata: \n"),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"Home","proxied":"","code":200,"responseBody":24,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			proxy.URL,
			http.StatusOK,
			[]byte("test\npost data: \ndata: \n"),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/data.txt","client":"127.0.0.1","agent":"Go-http-client/2.0","referer":"https://example.com/","connection":"","request":"","proto":"2.0","host":"example.com","message":"Proxy","proxied":"","code":200,"responseBody":24,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			proxy.URL,
			http.StatusOK,
			[]byte("test\npost data: \ndata: \n"),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/assets/image.png","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"Proxy","proxied":"","code":200,"responseBody":24,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			proxy.URL,
			http.StatusOK,
			[]byte("test\npost data: \ndata: \n"),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/missing","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"Proxy","proxied":"","code":200,"responseBody":24,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			proxy.URL,
			http.StatusOK,
			[]byte(`{"domain":"example.com","title":"test","description":"test site","version":"vTEST","buildTimestamp":"2023-11-03T00:51:07Z","revision":"abcde"}`),
			`{"level":"info","request":"","message":"test msg"}` + "\n" +
				`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"HomeGet","etag":"L-2SWZmdBbqCzd6xOfS5Via-1_urwrPdsIWeC-2XAok","code":200,"responseBody":142,"requestBody":0,"metrics":{"test":123456,"t":}}` + "\n",
			http.Header{
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"142"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {`"L-2SWZmdBbqCzd6xOfS5Via-1_urwrPdsIWeC-2XAok"`},
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
			proxy.URL,
			http.StatusNotFound,
			[]byte("Not Found\n"),
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"other.example.com","error":"site not found for host","code":404,"responseBody":10,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			proxy.URL,
			http.StatusOK,
			[]byte(`{"data":123}`),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"JSONGet","etag":"j0Jw1Eosvc8TRxjb6f9Gy2tYjfHaVdlIoKpog0X2WKE","metadata":{"foobar":42},"code":200,"responseBody":12,"requestBody":0,"metrics":{"j":,"t":}}` + "\n",
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
			proxy.URL,
			http.StatusOK,
			[]byte("test\npost data: \ndata: \n"),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"PATCH","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","message":"Proxy","proxied":"","code":200,"responseBody":24,"requestBody":0,"metrics":{"t":}}` + "\n",
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
			proxy.URL,
			http.StatusOK,
			[]byte("test\npost data: data=abcde\ndata: data=abcde&foo=1\n"),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"POST","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","query":{"foo":["1"]},"message":"Proxy","proxied":"","code":200,"responseBody":50,"requestBody":10,"metrics":{"t":}}` + "\n",
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

				_, ts := newService(t, zerolog.New(pipeW).Level(zerolog.InfoLevel), http2, tt.Development)

				// Close pipeW after serving.
				h := ts.Config.Handler
				ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer pipeW.Close()
					h.ServeHTTP(w, r)
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

func TestRoutesConfiguration(t *testing.T) {
	t.Parallel()

	var config struct {
		Routes []Route `json:"routes"`
	}
	err := json.Unmarshal(routesConfiguration, &config)
	assert.NoError(t, err)
	assert.Equal(t, []Route{
		{Name: "Home", Path: "/", API: false, Get: true},
	}, config.Routes)

	_ = &Service[*Site]{
		Routes: config.Routes,
	}
}
