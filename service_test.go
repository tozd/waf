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
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"

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
	ctx := req.Context()

	metrics := MustGetMetrics(ctx)
	metrics.Duration("test").Start().Duration = 123456789 * time.Microsecond

	zerolog.Ctx(ctx).Info().Msg("test msg")

	s.ServeStaticFile(w, req, "/index.json")
}

func (s *testService) Home(w http.ResponseWriter, req *http.Request, _ Params) {
	if s.ProxyStaticTo != "" {
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

func (s *testService) CORS(w http.ResponseWriter, req *http.Request, _ Params) {
	s.WriteJSON(w, req, json.RawMessage(`{}`), nil)
}

func (s *testService) CORSGet(w http.ResponseWriter, req *http.Request, _ Params) {
	s.WriteJSON(w, req, json.RawMessage(`{}`), nil)
}

func (s *testService) CORSPost(w http.ResponseWriter, req *http.Request, _ Params) {
	s.WriteJSON(w, req, json.RawMessage(`{}`), nil)
}

func (s *testService) CORSPatch(w http.ResponseWriter, req *http.Request, _ Params) {
	// This one does not have CORS on purpose.
	s.WriteJSON(w, req, json.RawMessage(`{}`), nil)
}

func (s *testService) CORSOptions(w http.ResponseWriter, _ *http.Request, _ Params) {
	w.WriteHeader(214)
}

func (s *testService) CORSNoOptionsPatch(w http.ResponseWriter, req *http.Request, _ Params) {
	s.WriteJSON(w, req, json.RawMessage(`{}`), nil)
}

func newRequest(t *testing.T, method, url string, body io.Reader) *http.Request {
	t.Helper()

	req, err := http.NewRequest(method, url, body) //nolint:noctx
	require.NoError(t, err)
	return req
}

func newService(t *testing.T, logger zerolog.Logger, https2 bool, proxyStaticTo string) (*testService, *httptest.Server) {
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
					API:  &RouteOptions{},
					Get:  &RouteOptions{},
				},
				{
					Name: "Helper",
					Path: "/helper/:name",
					API:  nil,
					Get:  &RouteOptions{},
				},
				{
					Name: "Panic",
					Path: "/panic",
					API:  &RouteOptions{},
					Get:  nil,
				},
				{
					Name: "JSON",
					Path: "/json",
					API:  &RouteOptions{},
					Get:  nil,
				},
				{
					Name: "Large",
					Path: "/large",
					API:  &RouteOptions{},
					Get:  nil,
				},
				{
					Name: "NonCompressibleJSON",
					Path: "/noncompressible",
					API:  &RouteOptions{},
					Get:  nil,
				},
				{
					Name: "CORS",
					Path: "/cors",
					API: &RouteOptions{
						CORS: &CORSOptions{
							AllowedOrigins:       []string{"https://other.example.com"},
							AllowedMethods:       []string{"GET", "POST"}, // HEAD should be added automatically.
							AllowedHeaders:       []string{"FooBar", "foo-zoo"},
							ExposedHeaders:       []string{"BarFoo", "zooFoo"},
							MaxAge:               54,
							AllowCredentials:     false,
							AllowPrivateNetwork:  true,
							OptionsSuccessStatus: 212, // Should not be returned because we have CORSOptions handler.
						},
					},
					Get: &RouteOptions{
						CORS: &CORSOptions{
							AllowedOrigins:       []string{"*"},
							AllowedMethods:       []string{}, // GET and HEAD should be added automatically.
							AllowedHeaders:       []string{},
							ExposedHeaders:       []string{},
							MaxAge:               55,
							AllowCredentials:     true,
							AllowPrivateNetwork:  false,
							OptionsSuccessStatus: 213,
						},
					},
				},
				{
					Name: "CORSNoOptions",
					Path: "/corsNoOptions",
					API: &RouteOptions{
						CORS: &CORSOptions{
							AllowedOrigins:       []string{"https://other.example.com"},
							AllowedMethods:       []string{"PATCH"},
							AllowedHeaders:       []string{"FooBar"},
							MaxAge:               56,
							AllowCredentials:     true,
							AllowPrivateNetwork:  false,
							OptionsSuccessStatus: 0,
						},
					},
					Get: nil,
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
			Middleware: []func(http.Handler) http.Handler{
				func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						w.Header().Add("Extra", "1234")
						next.ServeHTTP(w, req)
					})
				},
			},
			SiteContextPath:      "/index.json",
			MetadataHeaderPrefix: "Test-",
			ProxyStaticTo:        proxyStaticTo,
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

	errE = x.CreateTempCertificateFiles(certPath, keyPath, []string{"example.com", "other.example.com"})
	require.NoError(t, errE)

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
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) { //nolint:forcetypeassert,errcheck
		if addr == "example.com:443" || addr == "other.example.com:443" {
			addr = listenAddr.Load().(string) //nolint:forcetypeassert,errcheck
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	client.Transport.(*http.Transport).DisableCompression = true //nolint:forcetypeassert,errcheck

	return service, ts
}

var logCleanupRegexp = regexp.MustCompile(`("proxied":")[^"]+(")|("connection":")[^"]+(")|("request":")[^"]+(")|("time":")[^"]+(")|("[tjc]":)[0-9.]+`)

func logCleanup(t *testing.T, http2 bool, log string) string {
	t.Helper()

	if !http2 {
		log = strings.ReplaceAll(log, `"proto":"1.1"`, `"proto":"2.0"`)
		log = strings.ReplaceAll(log, `Go-http-client/1.1`, `Go-http-client/2.0`)
	}

	return logCleanupRegexp.ReplaceAllString(log, "$1$2$3$4$5$6$7$8$9")
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
	assert.EqualError(t, errE, "RouteWith called more than once")
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
					API:  nil,
					Get:  nil,
				},
			},
			`at least one of "get" and "api" has to be set`,
		},
		{
			[]Route{
				{
					Name: "SomethingMissing",
					Path: "/",
					API:  nil,
					Get:  &RouteOptions{},
				},
			},
			`handler not found`,
		},
		{
			[]Route{
				{
					Name: "Proxy",
					Path: "/",
					API:  nil,
					Get:  &RouteOptions{},
				},
			},
			`invalid handler type`,
		},
		{
			[]Route{
				{
					Name: "SomethingMissing",
					Path: "/",
					API:  &RouteOptions{},
					Get:  nil,
				},
			},
			`no API handler found`,
		},
		{
			[]Route{
				{
					Name: "InvalidHandlerType",
					Path: "/",
					API:  &RouteOptions{},
					Get:  nil,
				},
			},
			`invalid API handler type`,
		},
		{
			[]Route{
				{
					Name: "CORS",
					Path: "/cors",
					API:  nil,
					Get: &RouteOptions{
						CORS: &CORSOptions{
							AllowedMethods: []string{http.MethodPatch},
						},
					},
				},
			},
			`CORS allowed methods contain methods without handlers`,
		},
		{
			[]Route{
				{
					Name: "CORS",
					Path: "/cors",
					API: &RouteOptions{
						CORS: &CORSOptions{
							AllowedMethods: []string{http.MethodGet, http.MethodDelete},
						},
					},
					Get: nil,
				},
			},
			`CORS allowed methods contain methods without handlers`,
		},
	}

	for k, tt := range tests {
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
				assert.EqualError(t, errE, tt.Err)
			} else {
				require.NoError(t, errE, "% -+#.1v", errE)
			}
		})
	}
}

func TestServiceReverse(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}

	service, _ := newService(t, zerolog.New(out), false, "")

	p, errE := service.Reverse("Home", nil, url.Values{"x": []string{"y"}, "a": []string{"b", "c"}, "b": []string{}})
	if assert.NoError(t, errE, "% -+#.1v", errE) {
		assert.Equal(t, `/?a=b&a=c&x=y`, p)
	}

	p, errE = service.ReverseAPI("Home", nil, url.Values{"x": []string{"y"}, "a": []string{"b", "c"}, "b": []string{}})
	if assert.NoError(t, errE, "% -+#.1v", errE) {
		assert.Equal(t, `/api?a=b&a=c&x=y`, p)
	}

	_, errE = service.Reverse("Home", Params{"x": "y"}, nil)
	assert.EqualError(t, errE, "extra parameters")

	_, errE = service.Reverse("Helper", nil, nil)
	assert.EqualError(t, errE, "parameter is missing")

	_, errE = service.Reverse("JSON", nil, nil)
	assert.EqualError(t, errE, "route has no GET or OPTIONS handler")

	_, errE = service.Reverse("something", nil, nil)
	assert.EqualError(t, errE, "route does not exist")

	//nolint:testifylint
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
{"level":"debug","handler":"CORS","route":"CORS","path":"/cors","message":"route registration: handler found"}
{"level":"debug","handler":"CORSGet","route":"CORS","path":"/cors","message":"route registration: API handler found"}
{"level":"debug","handler":"CORSPost","route":"CORS","path":"/cors","message":"route registration: API handler found"}
{"level":"debug","handler":"CORSPut","route":"CORS","path":"/cors","message":"route registration: API handler not found"}
{"level":"debug","handler":"CORSPatch","route":"CORS","path":"/cors","message":"route registration: API handler found"}
{"level":"debug","handler":"CORSDelete","route":"CORS","path":"/cors","message":"route registration: API handler not found"}
{"level":"debug","handler":"CORSConnect","route":"CORS","path":"/cors","message":"route registration: API handler not found"}
{"level":"debug","handler":"CORSOptions","route":"CORS","path":"/cors","message":"route registration: API handler found"}
{"level":"debug","handler":"CORSTrace","route":"CORS","path":"/cors","message":"route registration: API handler not found"}
{"level":"debug","handler":"CORSNoOptionsGet","route":"CORSNoOptions","path":"/corsNoOptions","message":"route registration: API handler not found"}
{"level":"debug","handler":"CORSNoOptionsPost","route":"CORSNoOptions","path":"/corsNoOptions","message":"route registration: API handler not found"}
{"level":"debug","handler":"CORSNoOptionsPut","route":"CORSNoOptions","path":"/corsNoOptions","message":"route registration: API handler not found"}
{"level":"debug","handler":"CORSNoOptionsPatch","route":"CORSNoOptions","path":"/corsNoOptions","message":"route registration: API handler found"}
{"level":"debug","handler":"CORSNoOptionsDelete","route":"CORSNoOptions","path":"/corsNoOptions","message":"route registration: API handler not found"}
{"level":"debug","handler":"CORSNoOptionsConnect","route":"CORSNoOptions","path":"/corsNoOptions","message":"route registration: API handler not found"}
{"level":"debug","handler":"CORSNoOptionsOptions","route":"CORSNoOptions","path":"/corsNoOptions","message":"route registration: API handler not found"}
{"level":"debug","handler":"CORSNoOptionsTrace","route":"CORSNoOptions","path":"/corsNoOptions","message":"route registration: API handler not found"}
{"level":"debug","path":"/assets/image.png","message":"added file to static files"}
{"level":"debug","path":"/compressible.foobar","message":"unable to determine content type for static file"}
{"level":"debug","path":"/compressible.foobar","message":"added file to static files"}
{"level":"debug","path":"/data.txt","message":"added file to static files"}
{"level":"debug","path":"/index.html","message":"added file to static files"}
{"level":"debug","path":"/noncompressible.foobar","message":"unable to determine content type for static file"}
{"level":"debug","path":"/noncompressible.foobar","message":"added file to static files"}
{"level":"debug","path":"/semicompressible.foobar","message":"unable to determine content type for static file"}
{"level":"debug","path":"/semicompressible.foobar","message":"added file to static files"}
{"level":"debug","path":"/index.json","message":"added file to static files"}
`, out.String())
}

func TestService(t *testing.T) {
	t.Parallel()

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if !assert.NoError(t, err) {
			return
		}
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"tN1X-esKHJy3BUQrWNN0YaiNCkUYVp_5YmywXfn0Kx8","code":200,"responseBody":82,"requestBody":0,"metrics":{"t":},"message":"Home"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"POST","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":405,"responseBody":19,"requestBody":0,"metrics":{"t":},"message":"MethodNotAllowed"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/data.txt","client":"127.0.0.1","agent":"Go-http-client/2.0","referer":"https://example.com/","connection":"","request":"","proto":"2.0","host":"example.com","etag":"kW8AJ6V1B0znKjMXd8NHjWUT94alkb2JLaGld78jNfk","code":200,"responseBody":9,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"POST","path":"/data.txt","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":405,"responseBody":19,"requestBody":0,"metrics":{"t":},"message":"MethodNotAllowed"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/assets/image.png","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"EYcyfG0PCwsZszqyEaVJAjqppB81nG0Kgn172Z-NWZQ","code":200,"responseBody":10,"requestBody":0,"metrics":{"t":},"message":"ImmutableFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"max-age=31536000,immutable,stale-while-revalidate=86400"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/compressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk","code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/compressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk","code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/compressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk","code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/compressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk","code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/compressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":"gNjs0DVDKzajatdVAcvGk2jBlyyj_v_ier840Jzmwig","code":200,"responseBody":68,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/noncompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + nonCompressibleDataEtag + `,"code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/data.txt","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"kW8AJ6V1B0znKjMXd8NHjWUT94alkb2JLaGld78jNfk","code":200,"responseBody":9,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + semiCompressibleDataEtag + `,"code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + semiCompressibleDataGzipEtag + `,"code":200,"responseBody":` + strconv.Itoa(len(semiCompressibleDataGzip)) + `,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {strconv.Itoa(len(semiCompressibleDataGzip))},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + semiCompressibleDataEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":         {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + semiCompressibleDataGzipEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":         {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + semiCompressibleDataEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
				req.Header.Add("Range", "bytes=35000-37000")
				return req
			},
			"",
			http.StatusRequestedRangeNotSatisfiable,
			[]byte("invalid range: failed to overlap\n"),
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":416,"responseBody":33,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Content-Length":         {"33"},
				"Content-Range":          {"bytes */32768"},
				"Content-Type":           {"text/plain; charset=utf-8"},
				"Date":                   {""},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + semiCompressibleDataGzipEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + semiCompressibleDataEtag + `,"code":206,"responseBody":19901,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + semiCompressibleDataGzipEtag + `,"code":206,"responseBody":19901,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"19901"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + semiCompressibleDataEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":         {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + semiCompressibleDataGzipEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":         {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + semiCompressibleDataEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + semiCompressibleDataGzipEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + semiCompressibleDataEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + semiCompressibleDataGzipEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + semiCompressibleDataEtag + `,"code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + semiCompressibleDataGzipEtag + `,"code":200,"responseBody":` + strconv.Itoa(len(semiCompressibleDataGzip)) + `,"requestBody":0,"metrics":{"t":},"message":"StaticFile"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {strconv.Itoa(len(semiCompressibleDataGzip))},
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
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/missing","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":404,"responseBody":10,"requestBody":0,"metrics":{"t":},"message":"NotFound"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
				return newRequest(t, http.MethodGet, "https://example.com/api", nil)
			},
			"",
			http.StatusOK,
			[]byte(`{"domain":"example.com","title":"test","description":"test site","version":"vTEST","buildTimestamp":"2023-11-03T00:51:07Z","revision":"abcde"}`),
			`{"level":"info","request":"","message":"test msg"}` + "\n" +
				`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"L-2SWZmdBbqCzd6xOfS5Via-1_urwrPdsIWeC-2XAok","code":200,"responseBody":142,"requestBody":0,"metrics":{"t":,"test":123456},"message":"HomeGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"142"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {`"L-2SWZmdBbqCzd6xOfS5Via-1_urwrPdsIWeC-2XAok"`},
				"Request-Id":             {""},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur=,test;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/helper/NotFound", nil)
			},
			"",
			http.StatusNotFound,
			[]byte("Not Found\n"),
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/NotFound","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":404,"responseBody":10,"requestBody":0,"metrics":{"t":},"message":"Helper"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/NotFoundWithError","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","error":"test","code":404,"responseBody":10,"requestBody":0,"metrics":{"t":},"message":"Helper"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/MethodNotAllowed","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":405,"responseBody":19,"requestBody":0,"metrics":{"t":},"message":"Helper"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"error","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/InternalServerError","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":500,"responseBody":22,"requestBody":0,"metrics":{"t":},"message":"Helper"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"error","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/InternalServerErrorWithError","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","error":"test","code":500,"responseBody":22,"requestBody":0,"metrics":{"t":},"message":"Helper"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/Canceled","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","context":"canceled","code":408,"responseBody":16,"requestBody":0,"metrics":{"t":},"message":"Helper"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/DeadlineExceeded","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","context":"deadline exceeded","code":408,"responseBody":16,"requestBody":0,"metrics":{"t":},"message":"Helper"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"error","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/Proxy","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","error":"Proxy called without ProxyStaticTo config","code":500,"responseBody":22,"requestBody":0,"metrics":{"t":},"message":"Helper"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/something","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":400,"responseBody":12,"requestBody":0,"metrics":{"t":},"message":"Helper"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"error","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/panic","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","panic":true,"error":"test","code":500,"responseBody":22,"requestBody":0,"metrics":{"t":},"message":"PanicGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"other.example.com","error":"site not found for host","code":404,"responseBody":10,"requestBody":0,"metrics":{"t":},"message":"ValidateSite"}` + "\n",
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"j0Jw1Eosvc8TRxjb6f9Gy2tYjfHaVdlIoKpog0X2WKE","metadata":{"foobar":42},"code":200,"responseBody":12,"requestBody":0,"metrics":{"j":,"t":},"message":"JSONGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"12"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {`"j0Jw1Eosvc8TRxjb6f9Gy2tYjfHaVdlIoKpog0X2WKE"`},
				"Request-Id":             {""},
				"Test-Metadata":          {"foobar=42"},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"j;dur=,t;dur="},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"j0Jw1Eosvc8TRxjb6f9Gy2tYjfHaVdlIoKpog0X2WKE","metadata":{"foobar":42},"code":200,"responseBody":12,"requestBody":0,"metrics":{"j":,"t":},"message":"JSONGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"12"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {`"j0Jw1Eosvc8TRxjb6f9Gy2tYjfHaVdlIoKpog0X2WKE"`},
				"Request-Id":             {""},
				"Test-Metadata":          {"foobar=42"},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"j;dur=,t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://other.example.com/api/json", nil)
			},
			"",
			http.StatusNotFound,
			[]byte("Not Found\n"),
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"other.example.com","error":"site not found for host","code":404,"responseBody":10,"requestBody":0,"metrics":{"t":},"message":"ValidateSite"}` + "\n",
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"POST","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","query":{"foo":["1"]},"code":202,"responseBody":16,"requestBody":10,"metrics":{"t":},"message":"JSONPost"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"PATCH","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","query":{"foo":["1"]},"code":405,"responseBody":19,"requestBody":10,"metrics":{"t":},"message":"MethodNotAllowed"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONEtag + `,"code":200,"responseBody":65544,"requestBody":0,"metrics":{"t":},"message":"LargeGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONEtag + `,"code":200,"responseBody":65544,"requestBody":0,"metrics":{"t":},"message":"LargeGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + largeJSONGzipEtag + `,"code":200,"responseBody":` + strconv.Itoa(len(largeJSONGzip)) + `,"requestBody":0,"metrics":{"c":,"t":},"message":"LargeGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {strconv.Itoa(len(largeJSONGzip))},
				"Content-Type":           {"application/json"},
				"Content-Encoding":       {"gzip"},
				"Date":                   {""},
				"Etag":                   {largeJSONGzipEtag},
				"Request-Id":             {""},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"c;dur=,t;dur="},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"LargeGet"}` + "\n",
			http.Header{
				"Extra":         {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONGzipEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"c":,"t":},"message":"LargeGet"}` + "\n",
			http.Header{
				"Extra":         {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":},"message":"LargeGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + largeJSONGzipEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"c":,"t":},"message":"LargeGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"101"},
				"Content-Range":          {"bytes 100-200/" + strconv.Itoa(len(largeJSONGzip))},
				"Content-Type":           {"application/json"},
				"Content-Encoding":       {"gzip"},
				"Date":                   {""},
				"Etag":                   {largeJSONGzipEtag},
				"Request-Id":             {""},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"c;dur=,t;dur="},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONEtag + `,"code":206,"responseBody":19901,"requestBody":0,"metrics":{"t":},"message":"LargeGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + largeJSONGzipEtag + `,"code":206,"responseBody":19901,"requestBody":0,"metrics":{"c":,"t":},"message":"LargeGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"19901"},
				"Content-Range":          {"bytes 100-20000/" + strconv.Itoa(len(largeJSONGzip))},
				"Content-Type":           {"application/json"},
				"Content-Encoding":       {"gzip"},
				"Date":                   {""},
				"Etag":                   {largeJSONGzipEtag},
				"Request-Id":             {""},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"c;dur=,t;dur="},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"LargeGet"}` + "\n",
			http.Header{
				"Extra":         {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONGzipEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"c":,"t":},"message":"LargeGet"}` + "\n",
			http.Header{
				"Extra":         {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":},"message":"LargeGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + largeJSONGzipEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"c":,"t":},"message":"LargeGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"101"},
				"Content-Range":          {"bytes 100-200/" + strconv.Itoa(len(largeJSONGzip))},
				"Content-Type":           {"application/json"},
				"Content-Encoding":       {"gzip"},
				"Date":                   {""},
				"Etag":                   {largeJSONGzipEtag},
				"Request-Id":             {""},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"c;dur=,t;dur="},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":},"message":"LargeGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + largeJSONGzipEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"c":,"t":},"message":"LargeGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"101"},
				"Content-Range":          {"bytes 100-200/" + strconv.Itoa(len(largeJSONGzip))},
				"Content-Type":           {"application/json"},
				"Content-Encoding":       {"gzip"},
				"Date":                   {""},
				"Etag":                   {largeJSONGzipEtag},
				"Request-Id":             {""},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"c;dur=,t;dur="},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONEtag + `,"code":200,"responseBody":65544,"requestBody":0,"metrics":{"t":},"message":"LargeGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + largeJSONGzipEtag + `,"code":200,"responseBody":` + strconv.Itoa(len(largeJSONGzip)) + `,"requestBody":0,"metrics":{"c":,"t":},"message":"LargeGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {strconv.Itoa(len(largeJSONGzip))},
				"Content-Type":           {"application/json"},
				"Content-Encoding":       {"gzip"},
				"Date":                   {""},
				"Etag":                   {largeJSONGzipEtag},
				"Request-Id":             {""},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"c;dur=,t;dur="},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/noncompressible","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + nonCompressibleDataEtag + `,"code":200,"responseBody":32768,"requestBody":0,"metrics":{"c":,"t":},"message":"NonCompressibleJSONGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"32768"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {nonCompressibleDataEtag},
				"Request-Id":             {""},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"c;dur=,t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/", nil)
			},
			proxy.URL,
			http.StatusOK,
			[]byte("test\npost data: \ndata: \n"),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","proxied":"","code":200,"responseBody":24,"requestBody":0,"metrics":{"t":},"message":"Home"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/data.txt","client":"127.0.0.1","agent":"Go-http-client/2.0","referer":"https://example.com/","connection":"","request":"","proto":"2.0","host":"example.com","proxied":"","code":200,"responseBody":24,"requestBody":0,"metrics":{"t":},"message":"Proxy"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/assets/image.png","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","proxied":"","code":200,"responseBody":24,"requestBody":0,"metrics":{"t":},"message":"Proxy"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/missing","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","proxied":"","code":200,"responseBody":24,"requestBody":0,"metrics":{"t":},"message":"Proxy"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
				return newRequest(t, http.MethodGet, "https://example.com/api", nil)
			},
			proxy.URL,
			http.StatusOK,
			[]byte(`{"domain":"example.com","title":"test","description":"test site","version":"vTEST","buildTimestamp":"2023-11-03T00:51:07Z","revision":"abcde"}`),
			`{"level":"info","request":"","message":"test msg"}` + "\n" +
				`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"L-2SWZmdBbqCzd6xOfS5Via-1_urwrPdsIWeC-2XAok","code":200,"responseBody":142,"requestBody":0,"metrics":{"t":,"test":123456},"message":"HomeGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"142"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {`"L-2SWZmdBbqCzd6xOfS5Via-1_urwrPdsIWeC-2XAok"`},
				"Request-Id":             {""},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur=,test;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://other.example.com/", nil)
			},
			proxy.URL,
			http.StatusNotFound,
			[]byte("Not Found\n"),
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"other.example.com","error":"site not found for host","code":404,"responseBody":10,"requestBody":0,"metrics":{"t":},"message":"ValidateSite"}` + "\n",
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"j0Jw1Eosvc8TRxjb6f9Gy2tYjfHaVdlIoKpog0X2WKE","metadata":{"foobar":42},"code":200,"responseBody":12,"requestBody":0,"metrics":{"j":,"t":},"message":"JSONGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"12"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {`"j0Jw1Eosvc8TRxjb6f9Gy2tYjfHaVdlIoKpog0X2WKE"`},
				"Request-Id":             {""},
				"Test-Metadata":          {"foobar=42"},
				"Vary":                   {"Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"j;dur=,t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodPatch, "https://example.com/api/json", nil)
			},
			proxy.URL,
			http.StatusOK,
			[]byte("test\npost data: \ndata: \n"),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"PATCH","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","proxied":"","code":200,"responseBody":24,"requestBody":0,"metrics":{"t":},"message":"Proxy"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"POST","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","query":{"foo":["1"]},"proxied":"","code":200,"responseBody":50,"requestBody":10,"metrics":{"t":},"message":"Proxy"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/", nil)
				// Origin on non-CORS handler should not have any effect on the response.
				req.Header.Add("Origin", "https://other.example.com")
				return req
			},
			"",
			http.StatusOK,
			[]byte(`<!DOCTYPE html><html><head><title>test</title></head><body>test site</body></html>`),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"tN1X-esKHJy3BUQrWNN0YaiNCkUYVp_5YmywXfn0Kx8","code":200,"responseBody":82,"requestBody":0,"metrics":{"t":},"message":"Home"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
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
				return newRequest(t, http.MethodGet, "https://example.com/cors", nil)
			},
			"",
			http.StatusOK,
			[]byte(`{}`),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o","code":200,"responseBody":2,"requestBody":0,"metrics":{"t":},"message":"CORS"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"2"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {`"RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"`},
				"Request-Id":             {""},
				"Vary":                   {"Origin", "Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/cors", nil)
				req.Header.Add("Origin", "https://other.example.com")
				return req
			},
			"",
			http.StatusOK,
			[]byte(`{}`),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o","code":200,"responseBody":2,"requestBody":0,"metrics":{"t":},"message":"CORS"}` + "\n",
			http.Header{
				"Extra":                            {"1234"},
				"Accept-Ranges":                    {"bytes"},
				"Cache-Control":                    {"no-cache"},
				"Content-Length":                   {"2"},
				"Content-Type":                     {"application/json"},
				"Date":                             {""},
				"Etag":                             {`"RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"`},
				"Request-Id":                       {""},
				"Vary":                             {"Origin", "Accept-Encoding"},
				"X-Content-Type-Options":           {"nosniff"},
				"Access-Control-Allow-Credentials": {"true"},
				"Access-Control-Allow-Origin":      {"*"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodOptions, "https://example.com/cors", nil)
			},
			"",
			213,
			[]byte(``),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":213,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORS"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Content-Length":         {"0"},
				"Date":                   {""},
				"Request-Id":             {""},
				"Vary":                   {"Origin"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodOptions, "https://example.com/cors", nil)
				req.Header.Add("Origin", "https://other.example.com")
				req.Header.Add("Access-Control-Request-Method", "GET")
				return req
			},
			"",
			213,
			[]byte(``),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":213,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORS"}` + "\n",
			http.Header{
				"Extra":                            {"1234"},
				"Content-Length":                   {"0"},
				"Date":                             {""},
				"Request-Id":                       {""},
				"Vary":                             {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"},
				"X-Content-Type-Options":           {"nosniff"},
				"Access-Control-Allow-Credentials": {"true"},
				"Access-Control-Allow-Origin":      {"*"},
				"Access-Control-Max-Age":           {"55"},
				"Access-Control-Allow-Methods":     {"GET"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodOptions, "https://example.com/cors", nil)
				req.Header.Add("Origin", "https://other.example.com")
				req.Header.Add("Access-Control-Request-Method", "HEAD")
				return req
			},
			"",
			213,
			[]byte(``),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":213,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORS"}` + "\n",
			http.Header{
				"Extra":                            {"1234"},
				"Content-Length":                   {"0"},
				"Date":                             {""},
				"Request-Id":                       {""},
				"Vary":                             {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"},
				"X-Content-Type-Options":           {"nosniff"},
				"Access-Control-Allow-Credentials": {"true"},
				"Access-Control-Allow-Origin":      {"*"},
				"Access-Control-Max-Age":           {"55"},
				"Access-Control-Allow-Methods":     {"HEAD"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodOptions, "https://example.com/cors", nil)
				req.Header.Add("Origin", "https://other.example.com")
				req.Header.Add("Access-Control-Request-Method", "POST")
				return req
			},
			"",
			213,
			[]byte(``),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":213,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORS"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Content-Length":         {"0"},
				"Date":                   {""},
				"Request-Id":             {""},
				"Vary":                   {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},

		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/api/cors", nil)
			},
			"",
			http.StatusOK,
			[]byte(`{}`),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o","code":200,"responseBody":2,"requestBody":0,"metrics":{"t":},"message":"CORSGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"2"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {`"RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"`},
				"Request-Id":             {""},
				"Vary":                   {"Origin", "Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/api/cors", nil)
				req.Header.Add("Origin", "https://other.example.com")
				return req
			},
			"",
			http.StatusOK,
			[]byte(`{}`),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o","code":200,"responseBody":2,"requestBody":0,"metrics":{"t":},"message":"CORSGet"}` + "\n",
			http.Header{
				"Extra":                         {"1234"},
				"Accept-Ranges":                 {"bytes"},
				"Cache-Control":                 {"no-cache"},
				"Content-Length":                {"2"},
				"Content-Type":                  {"application/json"},
				"Date":                          {""},
				"Etag":                          {`"RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"`},
				"Request-Id":                    {""},
				"Vary":                          {"Origin", "Accept-Encoding"},
				"X-Content-Type-Options":        {"nosniff"},
				"Access-Control-Allow-Origin":   {"https://other.example.com"},
				"Access-Control-Expose-Headers": {"Barfoo, Zoofoo"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodGet, "https://example.com/api/cors", nil)
				req.Header.Add("Origin", "https://another.example.com")
				return req
			},
			"",
			http.StatusOK,
			[]byte(`{}`),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o","code":200,"responseBody":2,"requestBody":0,"metrics":{"t":},"message":"CORSGet"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Accept-Ranges":          {"bytes"},
				"Cache-Control":          {"no-cache"},
				"Content-Length":         {"2"},
				"Content-Type":           {"application/json"},
				"Date":                   {""},
				"Etag":                   {`"RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"`},
				"Request-Id":             {""},
				"Vary":                   {"Origin", "Accept-Encoding"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodOptions, "https://example.com/api/cors", nil)
			},
			"",
			214,
			[]byte(``),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/api/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":214,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSOptions"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Content-Length":         {"0"},
				"Date":                   {""},
				"Request-Id":             {""},
				"Vary":                   {"Origin"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodOptions, "https://example.com/api/cors", nil)
				req.Header.Add("Origin", "https://other.example.com")
				req.Header.Add("Access-Control-Request-Method", "GET")
				req.Header.Add("Access-Control-Request-Private-Network", "true")
				req.Header.Add("Access-Control-Request-Headers", "foo-zoo,foobar")
				return req
			},
			"",
			214,
			[]byte(``),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/api/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":214,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSOptions"}` + "\n",
			http.Header{
				"Extra":                                {"1234"},
				"Content-Length":                       {"0"},
				"Date":                                 {""},
				"Request-Id":                           {""},
				"Vary":                                 {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network"},
				"X-Content-Type-Options":               {"nosniff"},
				"Access-Control-Allow-Origin":          {"https://other.example.com"},
				"Access-Control-Max-Age":               {"54"},
				"Access-Control-Allow-Methods":         {"GET"},
				"Access-Control-Allow-Headers":         {"foo-zoo,foobar"},
				"Access-Control-Allow-Private-Network": {"true"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodOptions, "https://example.com/api/cors", nil)
				req.Header.Add("Origin", "https://other.example.com")
				req.Header.Add("Access-Control-Request-Method", "HEAD")
				req.Header.Add("Access-Control-Request-Private-Network", "true")
				req.Header.Add("Access-Control-Request-Headers", "foo-zoo,foobar")
				return req
			},
			"",
			214,
			[]byte(``),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/api/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":214,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSOptions"}` + "\n",
			http.Header{
				"Extra":                                {"1234"},
				"Content-Length":                       {"0"},
				"Date":                                 {""},
				"Request-Id":                           {""},
				"Vary":                                 {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network"},
				"X-Content-Type-Options":               {"nosniff"},
				"Access-Control-Allow-Origin":          {"https://other.example.com"},
				"Access-Control-Max-Age":               {"54"},
				"Access-Control-Allow-Methods":         {"HEAD"},
				"Access-Control-Allow-Headers":         {"foo-zoo,foobar"},
				"Access-Control-Allow-Private-Network": {"true"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodOptions, "https://example.com/api/cors", nil)
				req.Header.Add("Origin", "https://other.example.com")
				req.Header.Add("Access-Control-Request-Method", "POST")
				req.Header.Add("Access-Control-Request-Private-Network", "true")
				req.Header.Add("Access-Control-Request-Headers", "foo-zoo,foobar")
				return req
			},
			"",
			214,
			[]byte(``),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/api/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":214,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSOptions"}` + "\n",
			http.Header{
				"Extra":                                {"1234"},
				"Content-Length":                       {"0"},
				"Date":                                 {""},
				"Request-Id":                           {""},
				"Vary":                                 {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network"},
				"X-Content-Type-Options":               {"nosniff"},
				"Access-Control-Allow-Origin":          {"https://other.example.com"},
				"Access-Control-Max-Age":               {"54"},
				"Access-Control-Allow-Methods":         {"POST"},
				"Access-Control-Allow-Headers":         {"foo-zoo,foobar"},
				"Access-Control-Allow-Private-Network": {"true"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodOptions, "https://example.com/api/cors", nil)
				req.Header.Add("Origin", "https://other.example.com")
				req.Header.Add("Access-Control-Request-Method", "PATCH")
				req.Header.Add("Access-Control-Request-Private-Network", "true")
				req.Header.Add("Access-Control-Request-Headers", "foo-zoo,foobar")
				return req
			},
			"",
			214,
			[]byte(``),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/api/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":214,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSOptions"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Content-Length":         {"0"},
				"Date":                   {""},
				"Request-Id":             {""},
				"Vary":                   {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodOptions, "https://example.com/api/cors", nil)
				req.Header.Add("Origin", "https://another.example.com")
				req.Header.Add("Access-Control-Request-Method", "GET")
				req.Header.Add("Access-Control-Request-Private-Network", "true")
				req.Header.Add("Access-Control-Request-Headers", "foo-zoo,foobar")
				return req
			},
			"",
			214,
			[]byte(``),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/api/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":214,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSOptions"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Content-Length":         {"0"},
				"Date":                   {""},
				"Request-Id":             {""},
				"Vary":                   {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodOptions, "https://example.com/api/corsNoOptions", nil)
				req.Header.Add("Origin", "https://other.example.com")
				req.Header.Add("Access-Control-Request-Method", "PATCH")
				req.Header.Add("Access-Control-Request-Private-Network", "true")
				req.Header.Add("Access-Control-Request-Headers", "foo-zoo,foobar")
				return req
			},
			"",
			http.StatusNoContent,
			[]byte(``),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/api/corsNoOptions","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":204,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSNoOptionsOptions"}` + "\n",
			http.Header{
				"Extra":                  {"1234"},
				"Date":                   {""},
				"Request-Id":             {""},
				"Vary":                   {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"},
				"X-Content-Type-Options": {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodOptions, "https://example.com/api/corsNoOptions", nil)
				req.Header.Add("Origin", "https://other.example.com")
				req.Header.Add("Access-Control-Request-Method", "PATCH")
				req.Header.Add("Access-Control-Request-Private-Network", "true")
				req.Header.Add("Access-Control-Request-Headers", "foobar")
				return req
			},
			"",
			http.StatusNoContent,
			[]byte(``),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/api/corsNoOptions","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":204,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSNoOptionsOptions"}` + "\n",
			http.Header{
				"Extra":                            {"1234"},
				"Date":                             {""},
				"Request-Id":                       {""},
				"Vary":                             {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"},
				"X-Content-Type-Options":           {"nosniff"},
				"Access-Control-Allow-Origin":      {"https://other.example.com"},
				"Access-Control-Max-Age":           {"56"},
				"Access-Control-Allow-Methods":     {"PATCH"},
				"Access-Control-Allow-Headers":     {"foobar"},
				"Access-Control-Allow-Credentials": {"true"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodOptions, "https://example.com/api/corsNoOptions", nil)
				req.Header.Add("Origin", "https://other.example.com")
				req.Header.Add("Access-Control-Request-Method", "PATCH")
				return req
			},
			"",
			http.StatusNoContent,
			[]byte(``),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/api/corsNoOptions","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":204,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSNoOptionsOptions"}` + "\n",
			http.Header{
				"Extra":                            {"1234"},
				"Date":                             {""},
				"Request-Id":                       {""},
				"Vary":                             {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"},
				"X-Content-Type-Options":           {"nosniff"},
				"Access-Control-Allow-Origin":      {"https://other.example.com"},
				"Access-Control-Max-Age":           {"56"},
				"Access-Control-Allow-Methods":     {"PATCH"},
				"Access-Control-Allow-Credentials": {"true"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
	}

	for k, tt := range tests {
		for _, http2 := range []bool{false, true} {
			for _, logEnabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("case=%d/http2=%t/log=%t", k, http2, logEnabled), func(t *testing.T) {
					t.Parallel()

					pipeR, pipeW, err := os.Pipe()
					t.Cleanup(func() {
						// We might double close but we do not care.
						pipeR.Close() //nolint:errcheck,gosec
						pipeW.Close() //nolint:errcheck,gosec
					})
					require.NoError(t, err)

					l := zerolog.New(pipeW).Level(zerolog.InfoLevel)
					if !logEnabled {
						l = zerolog.Nop()
					}

					_, ts := newService(t, l, http2, tt.Development)

					// Close pipeW after serving.
					h := ts.Config.Handler
					ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						defer pipeW.Close() //nolint:errcheck
						h.ServeHTTP(w, r)
					})

					resp, err := ts.Client().Do(tt.Request())
					require.NoError(t, err)
					t.Cleanup(func() { resp.Body.Close() }) //nolint:errcheck,gosec
					out, err := io.ReadAll(resp.Body)
					require.NoError(t, err)

					if logEnabled {
						log, err := io.ReadAll(pipeR)
						pipeR.Close() //nolint:errcheck,gosec
						require.NoError(t, err)
						assert.Equal(t, tt.ExpectedLog, logCleanup(t, http2, string(log)))
					}

					assert.Equal(t, tt.ExpectedStatus, resp.StatusCode)
					assert.Equal(t, tt.ExpectedBody, out)
					if !assert.Equal(t, tt.ExpectedHeader, headerCleanup(t, resp.Header)) {
						t.Log("here")
					}
					if http2 {
						assert.Equal(t, 2, resp.ProtoMajor)
						assert.Equal(t, tt.ExpectedTrailer, headerCleanup(t, resp.Trailer))
					} else {
						assert.Equal(t, 1, resp.ProtoMajor)
						assert.Equal(t, http.Header(nil), resp.Trailer)
					}
				})
			}
		}
	}
}

func TestRoutesConfiguration(t *testing.T) {
	t.Parallel()

	var config struct {
		Routes []Route `json:"routes"`
	}
	err := json.Unmarshal(routesConfiguration, &config)
	require.NoError(t, err)
	assert.Equal(t, []Route{
		{Name: "Home", Path: "/", API: nil, Get: &RouteOptions{}},
	}, config.Routes)
}

// We do not enable t.Parallel() here because it uses 5001 port
// and can conflict with other tests using the same port.
func TestRunExamples(t *testing.T) { //nolint:paralleltest
	if os.Getenv("PEBBLE_HOST") == "" {
		t.Skip("PEBBLE_HOST is not available")
	}

	if os.Getenv("GOCOVERDIR") == "" {
		t.Skip("GOCOVERDIR is not available")
	}

	files, err := filepath.Glob("_examples/*.go")
	require.NoError(t, err)

	// We do not enable t.Parallel() here because it uses 5001 port
	// and can conflict with other tests using the same port.
	for _, path := range files { //nolint:paralleltest
		dir, file := filepath.Split(path)

		// TODO: Currently for all files we expect same calls to be made with same results. Change that.
		t.Run(file, func(t *testing.T) {
			base := strings.TrimSuffix(file, filepath.Ext(file))

			assert.Equal(t, "_examples/", dir)

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			output := &bytes.Buffer{}

			cmd := exec.CommandContext(ctx, "go", "run", "-race", "-cover", "-covermode", "atomic", file, "--config", base+".yml") //nolint:gosec
			cmd.Dir = dir
			cmd.Stdout = output
			cmd.Stderr = output
			// TODO: Remove workaround.
			//       Currently we hard-code GOCOVERDIR because GOCOVERDIR gets overridden.
			//       See: https://github.com/golang/go/issues/60182
			cmd.Env = append(os.Environ(), "GOCOVERDIR=../coverage")
			// We have to make a process group and send signals to the whole group.
			// See: https://github.com/golang/go/issues/40467
			cmd.SysProcAttr = &syscall.SysProcAttr{
				Setpgid: true,
			}
			cmd.Cancel = func() error {
				if cmd.Process.Pid < 1 {
					return nil
				}
				// We kill whole process group.
				e := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				if errors.Is(e, syscall.ESRCH) {
					return os.ErrProcessDone
				}
				return e
			}

			err = cmd.Start()
			require.NoError(t, err)

			time.Sleep(10 * time.Second)

			transport := cleanhttp.DefaultTransport()
			transport.ForceAttemptHTTP2 = true
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				if addr == "site.test:443" {
					addr = "localhost:5001"
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
				out, err := io.ReadAll(resp.Body)       //nolint:govet
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, 2, resp.ProtoMajor)
				assert.Equal(t, `<!DOCTYPE html>`+"\n"+
					`<html>`+"\n"+
					`  <head>`+"\n"+
					`    <title>Hello site</title>`+"\n"+
					`  </head>`+"\n"+
					`  <body>Hello world!</body>`+"\n"+
					`</html>`, string(out))
				assert.Equal(t, http.Header{
					"Server-Timing": {"t;dur="},
				}, headerCleanup(t, resp.Trailer))
				assert.Equal(t, http.Header{
					"Accept-Ranges":          {"bytes"},
					"Cache-Control":          {"no-cache"},
					"Content-Length":         {"107"},
					"Content-Type":           {"text/html; charset=utf-8"},
					"Date":                   {""},
					"Etag":                   {`"nltu2O-xBi-IMFP71Eouztmo9ltQ_ZjyIe3WvcvaP6Q"`},
					"Request-Id":             {""},
					"Vary":                   {"Accept-Encoding"},
					"X-Content-Type-Options": {"nosniff"},
				}, headerCleanup(t, resp.Header))
			}

			resp, err = client.Get("https://site.test/context.json") //nolint:noctx
			if assert.NoError(t, err) {
				t.Cleanup(func() { resp.Body.Close() }) //nolint:errcheck,gosec
				out, err := io.ReadAll(resp.Body)       //nolint:govet
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, 2, resp.ProtoMajor)
				assert.Equal(t, `{"domain":"site.test","title":"Hello site"}`, string(out)) //nolint:testifylint
				assert.Equal(t, http.Header{
					"Server-Timing": {"t;dur="},
				}, headerCleanup(t, resp.Trailer))
				assert.Equal(t, http.Header{
					"Accept-Ranges":          {"bytes"},
					"Cache-Control":          {"no-cache"},
					"Content-Length":         {"43"},
					"Content-Type":           {"application/json"},
					"Date":                   {""},
					"Etag":                   {`"j4ddcndeVVi9jvW5UpoBerhfZojNaRKhVcRnLmJdALE"`},
					"Request-Id":             {""},
					"Vary":                   {"Accept-Encoding"},
					"X-Content-Type-Options": {"nosniff"},
				}, headerCleanup(t, resp.Header))
			}

			err = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
			assert.NoError(t, err) //nolint:testifylint

			err = cmd.Wait()
			var exitError *exec.ExitError
			// TODO: Remove workaround.
			//       Currently "go run" does not return zero exit code when we send INT signal
			//       to the whole process group even if the child process exits with zero exit code.
			//       See: https://github.com/golang/go/issues/40467
			if errors.As(err, &exitError) && exitError.ExitCode() > 0 {
				assert.Equal(t, 1, exitError.ExitCode())
			} else {
				assert.NoError(t, err) //nolint:testifylint
			}

			//nolint:testifylint
			assert.Equal(t, `{"level":"debug","handler":"Home","route":"Home","path":"/","time":"","message":"route registration: handler found"}
{"level":"debug","path":"/index.html","time":"","message":"added file to static files"}
{"level":"debug","path":"/context.json","time":"","message":"added file to static files"}
{"level":"info","listenAddr":"[::]:5001","domains":["site.test"],"time":"","message":"server starting"}
{"level":"info","request":"","time":"","message":"hello from Home handler"}
{"level":"info","method":"GET","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"site.test","etag":"nltu2O-xBi-IMFP71Eouztmo9ltQ_ZjyIe3WvcvaP6Q","code":200,"responseBody":107,"requestBody":0,"metrics":{"t":},"time":"","message":"Home"}
{"level":"info","method":"GET","path":"/context.json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"site.test","etag":"j4ddcndeVVi9jvW5UpoBerhfZojNaRKhVcRnLmJdALE","code":200,"responseBody":43,"requestBody":0,"metrics":{"t":},"time":"","message":"StaticFile"}
{"level":"info","time":"","message":"server stopping"}
`, logCleanup(t, true, output.String()))
		})
	}
}
