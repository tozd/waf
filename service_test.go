package waf

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
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
	nonCompressibleDataEtag = x.ComputeEtag(nonCompressibleData)
	semiCompressibleData = append([]byte{}, nonCompressibleData[:30*1024]...)
	semiCompressibleData = append(semiCompressibleData, bytes.Repeat([]byte{0}, 2*1024)...)
	semiCompressibleDataGzip, err = compress(compressionGzip, semiCompressibleData)
	if err != nil {
		panic(err)
	}
	semiCompressibleDataEtag = x.ComputeEtag(semiCompressibleData)
	semiCompressibleDataGzipEtag = x.ComputeEtag(semiCompressibleDataGzip)
	compressibleDataGzip, err = compress(compressionGzip, compressibleData)
	if err != nil {
		panic(err)
	}
	largeJSON = []byte(fmt.Sprintf(`{"x":"%x"}`, nonCompressibleData))
	largeJSONGzip, err = compress(compressionGzip, largeJSON)
	if err != nil {
		panic(err)
	}
	largeJSONEtag = x.ComputeEtag(largeJSON)
	largeJSONGzipEtag = x.ComputeEtag(largeJSONGzip)

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
			Routes:          nil,
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
			RoutesPath:           "/routes.json",
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

	service.Routes = map[string]Route{
		"Home": {
			RouteOptions: RouteOptions{
				Handlers: map[string]Handler{
					http.MethodGet: service.Home,
				},
			},
			Path: "/",
			API: RouteOptions{
				Handlers: map[string]Handler{
					http.MethodGet: service.HomeGet,
				},
			},
		},
		"Helper": {
			RouteOptions: RouteOptions{
				Handlers: map[string]Handler{
					http.MethodGet: service.Helper,
				},
			},
			Path: "/helper/:name",
		},
		"Panic": {
			Path: "/panic",
			API: RouteOptions{
				Handlers: map[string]Handler{
					http.MethodGet: service.PanicGet,
				},
			},
		},
		"JSON": {
			Path: "/json",
			API: RouteOptions{
				Handlers: map[string]Handler{
					http.MethodGet:  service.JSONGet,
					http.MethodPost: service.JSONPost,
				},
			},
		},
		"Large": {
			Path: "/large",
			API: RouteOptions{
				Handlers: map[string]Handler{
					http.MethodGet: service.LargeGet,
				},
			},
		},
		"NonCompressibleJSON": {
			Path: "/noncompressible",
			API: RouteOptions{
				Handlers: map[string]Handler{
					http.MethodGet: service.NonCompressibleJSONGet,
				},
			},
		},
		"CORS": {
			RouteOptions: RouteOptions{
				Handlers: map[string]Handler{
					http.MethodGet: service.CORS,
				},
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
			Path: "/cors",
			API: RouteOptions{
				Handlers: map[string]Handler{
					http.MethodGet:     service.CORSGet,
					http.MethodPost:    service.CORSPost,
					http.MethodPatch:   service.CORSPatch,
					http.MethodOptions: service.CORSOptions,
				},
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
		},
		"CORSNoOptions": {
			Path: "/corsNoOptions",
			API: RouteOptions{
				Handlers: map[string]Handler{
					http.MethodPatch: service.CORSNoOptionsPatch,
				},
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
		},
	}

	router := &Router{}
	handler, errE := service.RouteWith(router)
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

func TestServeStaticFileErrors(t *testing.T) {
	t.Parallel()

	s := &testService{Service: Service[*testSite]{router: new(Router)}}

	// "no etag" error: inject a static file with empty Etag.
	t.Run("no etag", func(t *testing.T) {
		t.Parallel()
		site := &testSite{Site: Site{Domain: "example.com"}}
		site.initializeStaticFiles()
		site.staticFiles[compressionIdentity]["/noetag.txt"] = staticFile{
			Data:      []byte("content"),
			Etag:      "",
			MediaType: "text/plain",
		}
		r := httptest.NewRequest(http.MethodGet, "/noetag.txt", nil)
		r = r.WithContext(context.WithValue(r.Context(), siteContextKey, site))
		w := httptest.NewRecorder()
		h := setCanonicalLogger(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			s.ServeStaticFile(w, req, "/noetag.txt")
		}))
		h.ServeHTTP(w, r)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	// "no content type" error: inject a static file with empty MediaType.
	t.Run("no content type", func(t *testing.T) {
		t.Parallel()
		site := &testSite{Site: Site{Domain: "example.com"}}
		site.initializeStaticFiles()
		site.staticFiles[compressionIdentity]["/nomtype.txt"] = staticFile{
			Data:      []byte("content"),
			Etag:      `"abc"`,
			MediaType: "",
		}
		r := httptest.NewRequest(http.MethodGet, "/nomtype.txt", nil)
		r = r.WithContext(context.WithValue(r.Context(), siteContextKey, site))
		w := httptest.NewRecorder()
		h := setCanonicalLogger(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			s.ServeStaticFile(w, req, "/nomtype.txt")
		}))
		h.ServeHTTP(w, r)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestServeStaticFileMissing(t *testing.T) {
	t.Parallel()

	s := &testService{Service: Service[*testSite]{router: new(Router)}}
	site := &testSite{Site: Site{Domain: "example.com"}}
	site.initializeStaticFiles()

	r := httptest.NewRequest(http.MethodGet, "/missing.txt", nil)
	r = r.WithContext(context.WithValue(r.Context(), siteContextKey, site))
	w := httptest.NewRecorder()
	h := setCanonicalLogger(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s.ServeStaticFile(w, req, "/missing.txt")
	}))
	h.ServeHTTP(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestServeStaticFileImmutable(t *testing.T) {
	t.Parallel()

	s := &testService{Service: Service[*testSite]{
		router:          new(Router),
		IsImmutableFile: func(_ string) bool { return true },
	}}
	site := &testSite{Site: Site{Domain: "example.com"}}
	site.initializeStaticFiles()
	// Large enough data (>1024 bytes) so compression is attempted.
	errE := site.addStaticFile("/asset.js", "application/javascript", bytes.Repeat([]byte("x"), 1100))
	require.NoError(t, errE, "% -+#.1v", errE)

	r := httptest.NewRequest(http.MethodGet, "/asset.js", nil)
	r = r.WithContext(context.WithValue(r.Context(), siteContextKey, site))
	w := httptest.NewRecorder()
	h := setCanonicalLogger(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s.ServeStaticFile(w, req, "/asset.js")
	}))
	h.ServeHTTP(w, r)
	res := w.Result()
	t.Cleanup(func() { res.Body.Close() }) //nolint:errcheck,gosec
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Contains(t, res.Header.Get("Cache-Control"), "immutable")
}

func TestHandlePanic(t *testing.T) {
	t.Parallel()

	s := &testService{Service: Service[*testSite]{router: new(Router)}}

	// Panic with a string value - covers the case string: branch.
	t.Run("string", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		h := setCanonicalLogger(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			s.handlePanic(w, req, "string panic message")
		}))
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	// Panic with a non-error, non-string type - covers the c.Interface("panic", ...) branch.
	// Inject a real (non-disabled) logger so UpdateContext actually invokes the closure.
	t.Run("unknown type", func(t *testing.T) {
		t.Parallel()
		logger := zerolog.New(io.Discard)
		ctx := logger.WithContext(context.Background())
		req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
		w := httptest.NewRecorder()
		h := setCanonicalLogger(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			s.handlePanic(w, req, 42)
		}))
		h.ServeHTTP(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestGetAllowedMethodsWithHEAD(t *testing.T) {
	t.Parallel()

	// HEAD explicitly in AllowedMethods - covers hasHead = true branch.
	opts := &CORSOptions{AllowedMethods: []string{http.MethodHead, http.MethodPost}}
	methods := opts.GetAllowedMethods()
	assert.Contains(t, methods, http.MethodHead)
	assert.Contains(t, methods, http.MethodPost)
	// HEAD was explicit, so it should not be added again.
	count := 0
	for _, m := range methods {
		if m == http.MethodHead {
			count++
		}
	}
	assert.Equal(t, 1, count)
}

func TestAddMetadataNoContext(t *testing.T) {
	t.Parallel()

	s := &testService{Service: Service[*testSite]{router: new(Router)}}

	// Plain request without metadataContextKey - covers the ok=false path.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	b, errE := s.AddMetadata(w, r, map[string]interface{}{"key": 42})
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.NotNil(t, b)
	assert.NotEmpty(t, w.Header().Get("Metadata"))
}

func TestRegisterRoutesErrors(t *testing.T) {
	t.Parallel()

	// HEAD auto-generation fails when HEAD is already registered.
	t.Run("HEAD conflict", func(t *testing.T) {
		t.Parallel()

		s := &testService{Service: Service[*testSite]{router: &Router{}}}
		errE := s.router.Handle("TestRoute", http.MethodHead, "/test", false, func(_ http.ResponseWriter, _ *http.Request, _ Params) {})
		require.NoError(t, errE, "% -+#.1v", errE)
		errE = s.registerRoutes("TestRoute", "/test", false, RouteOptions{
			Handlers: map[string]Handler{
				http.MethodGet: func(_ http.ResponseWriter, _ *http.Request, _ Params) {},
			},
		})
		assert.Error(t, errE)
	})

	// OPTIONS auto-generation fails when OPTIONS is already registered.
	t.Run("OPTIONS conflict", func(t *testing.T) {
		t.Parallel()

		s := &testService{Service: Service[*testSite]{router: &Router{}}}
		errE := s.router.Handle("TestRoute2", http.MethodOptions, "/test2", false, func(_ http.ResponseWriter, _ *http.Request, _ Params) {})
		require.NoError(t, errE, "% -+#.1v", errE)
		errE = s.registerRoutes("TestRoute2", "/test2", false, RouteOptions{
			Handlers: map[string]Handler{
				http.MethodGet: func(_ http.ResponseWriter, _ *http.Request, _ Params) {},
			},
			CORS: &CORSOptions{},
		})
		assert.Error(t, errE)
	})
}

func TestAddMetadataEncodeError(t *testing.T) {
	t.Parallel()

	s := &testService{Service: Service[*testSite]{router: new(Router)}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	// Invalid key causes encodeMetadata to fail.
	_, errE := s.AddMetadata(w, r, map[string]interface{}{"1invalid": 42})
	assert.EqualError(t, errE, "unsupported dictionary key")
}

func TestRenderErrors(t *testing.T) {
	t.Parallel()

	s := &testService{}

	// Invalid template syntax returns a parse error.
	_, errE := s.render("/test.html", []byte("{{invalid"), &testSite{})
	assert.Error(t, errE)

	// Template accessing non-existent nested field returns an execute error.
	_, errE = s.render("/test.html", []byte("{{.NonExistentField.Sub}}"), &testSite{})
	assert.Error(t, errE)
}

func TestWriteJSONMarshalError(t *testing.T) {
	t.Parallel()

	s := &testService{Service: Service[*testSite]{router: new(Router)}}

	w := httptest.NewRecorder()
	// metricsMiddleware sets up the metrics context that WriteJSON requires.
	// setCanonicalLogger sets up the canonical logger for error logging.
	h := metricsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Channels cannot be marshaled to JSON - PrepareJSON returns nil.
		s.WriteJSON(w, req, make(chan int), nil)
	}))
	h = setCanonicalLogger(h)
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	res := w.Result()
	t.Cleanup(func() { res.Body.Close() }) //nolint:errcheck,gosec
	assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
}

func TestRouteWith(t *testing.T) {
	t.Parallel()

	s := &testService{}
	router := &Router{}
	_, errE := s.RouteWith(router)
	require.NoError(t, errE, "% -+#.1v", errE)
	_, errE = s.RouteWith(router)
	assert.EqualError(t, errE, "RouteWith called more than once")
}

func TestServiceConfigureRoutes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Routes map[string]Route
		Err    string
	}{
		{
			nil,
			"",
		},
		{
			map[string]Route{
				"Home": {
					Path: "/",
				},
			},
			"at least one handler has to be set",
		},
		{
			map[string]Route{
				"CORS": {
					Path: "/ors",
					RouteOptions: RouteOptions{
						Handlers: map[string]Handler{
							http.MethodGet: nil,
						},
						CORS: &CORSOptions{
							AllowedMethods: []string{http.MethodPatch},
						},
					},
				},
			},
			`CORS allowed methods contain methods without handlers`,
		},
		{
			map[string]Route{
				"CORS": {
					Path: "/ors",
					API: RouteOptions{
						Handlers: map[string]Handler{
							http.MethodGet:     nil,
							http.MethodPost:    nil,
							http.MethodPatch:   nil,
							http.MethodOptions: nil,
						},
						CORS: &CORSOptions{
							AllowedMethods: []string{http.MethodGet, http.MethodDelete},
						},
					},
				},
			},
			`CORS allowed methods contain methods without handlers`,
		},
		{
			// Invalid path (no leading "/") causes router.Handle to fail.
			map[string]Route{
				"BadPath": {
					Path: "invalid-no-slash",
					RouteOptions: RouteOptions{
						Handlers: map[string]Handler{
							http.MethodGet: func(_ http.ResponseWriter, _ *http.Request, _ Params) {},
						},
					},
				},
			},
			`parsing path failed: path does not start with "/"`,
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

			errE := s.configureRoutes()
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
	assert.EqualError(t, errE, "route has no non-API handlers")

	_, errE = service.Reverse("something", nil, nil)
	assert.EqualError(t, errE, "route does not exist")

	//nolint:testifylint
	assert.Equal(t, `{"level":"debug","path":"/assets/image.png","mediaType":"image/png","message":"added file to static files"}
{"level":"debug","path":"/compressible.foobar","mediaType":"application/octet-stream","message":"added file to static files"}
{"level":"debug","path":"/data.txt","mediaType":"text/plain; charset=utf-8","message":"added file to static files"}
{"level":"debug","path":"/index.html","mediaType":"text/html; charset=utf-8","message":"added file to static files"}
{"level":"debug","path":"/noncompressible.foobar","mediaType":"application/octet-stream","message":"added file to static files"}
{"level":"debug","path":"/semicompressible.foobar","mediaType":"application/octet-stream","message":"added file to static files"}
{"level":"debug","path":"/index.json","mediaType":"application/json","message":"added file to static files"}
{"level":"debug","path":"/routes.json","mediaType":"application/json","message":"added file to static files"}
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"tN1X-esKHJy3BUQrWNN0YaiNCkUYVp_5YmywXfn0Kx8","code":200,"responseBody":82,"requestBody":0,"metrics":{"t":},"message":"HomeGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"82"},
				"Content-Type":              {"text/html; charset=utf-8"},
				"Date":                      {""},
				"Etag":                      {`"tN1X-esKHJy3BUQrWNN0YaiNCkUYVp_5YmywXfn0Kx8"`},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
				"Extra":                     {"1234"},
				"Allow":                     {"GET, HEAD"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"19"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/data.txt","client":"127.0.0.1","agent":"Go-http-client/2.0","referer":"https://example.com/","connection":"","request":"","proto":"2.0","host":"example.com","etag":"kW8AJ6V1B0znKjMXd8NHjWUT94alkb2JLaGld78jNfk","code":200,"responseBody":9,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"9"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Etag":                      {`"kW8AJ6V1B0znKjMXd8NHjWUT94alkb2JLaGld78jNfk"`},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				// /index.json is not exposed because it is available under /api.
				return newRequest(t, http.MethodGet, "https://example.com/index.json", nil)
			},
			"",
			http.StatusNotFound,
			[]byte(`Not Found` + "\n"),
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/index.json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":404,"responseBody":10,"requestBody":0,"metrics":{"t":},"message":"NotFound"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"10"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
			},
			http.Header{
				"Server-Timing": {"t;dur="},
			},
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "https://example.com/routes.json", nil)
			},
			"",
			http.StatusOK,
			[]byte(`{"CORS":{"handlers":{"GET":true},"path":"/cors","api":{"handlers":{"GET":true,"OPTIONS":true,"PATCH":true,"POST":true}}},"CORSNoOptions":{"path":"/corsNoOptions","api":{"handlers":{"PATCH":true}}},"Helper":{"handlers":{"GET":true},"path":"/helper/:name"},"Home":{"handlers":{"GET":true},"path":"/","api":{"handlers":{"GET":true}}},"JSON":{"path":"/json","api":{"handlers":{"GET":true,"POST":true}}},"Large":{"path":"/large","api":{"handlers":{"GET":true}}},"NonCompressibleJSON":{"path":"/noncompressible","api":{"handlers":{"GET":true}}},"Panic":{"path":"/panic","api":{"handlers":{"GET":true}}}}`),
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/routes.json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"pEuoU9BluxFx_mYFLBTHI2R5iGSE5OvaTZPDdSeIP30","code":200,"responseBody":597,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"597"},
				"Content-Type":              {"application/json"},
				"Date":                      {""},
				"Etag":                      {`"pEuoU9BluxFx_mYFLBTHI2R5iGSE5OvaTZPDdSeIP30"`},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
				"Extra":                     {"1234"},
				"Allow":                     {"GET, HEAD"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"19"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/assets/image.png","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"EYcyfG0PCwsZszqyEaVJAjqppB81nG0Kgn172Z-NWZQ","code":200,"responseBody":10,"requestBody":0,"metrics":{"t":},"message":"ImmutableFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"max-age=31536000,immutable,stale-while-revalidate=86400"},
				"Content-Length":            {"10"},
				"Content-Type":              {"image/png"},
				"Date":                      {""},
				"Etag":                      {`"EYcyfG0PCwsZszqyEaVJAjqppB81nG0Kgn172Z-NWZQ"`},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/compressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk","code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"32768"},
				"Content-Type":              {"application/octet-stream"},
				"Date":                      {""},
				"Etag":                      {`"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk"`},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/compressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk","code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"32768"},
				"Content-Type":              {"application/octet-stream"},
				"Date":                      {""},
				"Etag":                      {`"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk"`},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/compressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk","code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"32768"},
				"Content-Type":              {"application/octet-stream"},
				"Date":                      {""},
				"Etag":                      {`"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk"`},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/compressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk","code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"32768"},
				"Content-Type":              {"application/octet-stream"},
				"Date":                      {""},
				"Etag":                      {`"w1AgRzrtG0ZCzXJsrXJ7Y__ygkrWjO3X_7c8fL2JBHk"`},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/compressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":"gNjs0DVDKzajatdVAcvGk2jBlyyj_v_ier840Jzmwig","code":200,"responseBody":68,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"68"},
				"Content-Type":              {"application/octet-stream"},
				"Content-Encoding":          {"gzip"},
				"Date":                      {""},
				"Etag":                      {`"gNjs0DVDKzajatdVAcvGk2jBlyyj_v_ier840Jzmwig"`},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/noncompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + nonCompressibleDataEtag + `,"code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"32768"},
				"Content-Type":              {"application/octet-stream"},
				"Date":                      {""},
				"Etag":                      {nonCompressibleDataEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/data.txt","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"kW8AJ6V1B0znKjMXd8NHjWUT94alkb2JLaGld78jNfk","code":200,"responseBody":9,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"9"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Etag":                      {`"kW8AJ6V1B0znKjMXd8NHjWUT94alkb2JLaGld78jNfk"`},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + semiCompressibleDataEtag + `,"code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"32768"},
				"Content-Type":              {"application/octet-stream"},
				"Date":                      {""},
				"Etag":                      {semiCompressibleDataEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + semiCompressibleDataGzipEtag + `,"code":200,"responseBody":` + strconv.Itoa(len(semiCompressibleDataGzip)) + `,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {strconv.Itoa(len(semiCompressibleDataGzip))},
				"Content-Type":              {"application/octet-stream"},
				"Content-Encoding":          {"gzip"},
				"Date":                      {""},
				"Etag":                      {semiCompressibleDataGzipEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + semiCompressibleDataEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + semiCompressibleDataGzipEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + semiCompressibleDataEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"101"},
				"Content-Range":             {"bytes 100-200/32768"},
				"Content-Type":              {"application/octet-stream"},
				"Date":                      {""},
				"Etag":                      {semiCompressibleDataEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":416,"responseBody":33,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Content-Length":            {"33"},
				"Content-Range":             {"bytes */32768"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + semiCompressibleDataGzipEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"101"},
				"Content-Range":             {"bytes 100-200/" + strconv.Itoa(len(semiCompressibleDataGzip))},
				"Content-Type":              {"application/octet-stream"},
				"Content-Encoding":          {"gzip"},
				"Date":                      {""},
				"Etag":                      {semiCompressibleDataGzipEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + semiCompressibleDataEtag + `,"code":206,"responseBody":19901,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"19901"},
				"Content-Range":             {"bytes 100-20000/32768"},
				"Content-Type":              {"application/octet-stream"},
				"Date":                      {""},
				"Etag":                      {semiCompressibleDataEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + semiCompressibleDataGzipEtag + `,"code":206,"responseBody":19901,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"19901"},
				"Content-Range":             {"bytes 100-20000/" + strconv.Itoa(len(semiCompressibleDataGzip))},
				"Content-Type":              {"application/octet-stream"},
				"Content-Encoding":          {"gzip"},
				"Date":                      {""},
				"Etag":                      {semiCompressibleDataGzipEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + semiCompressibleDataEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + semiCompressibleDataGzipEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + semiCompressibleDataEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"101"},
				"Content-Range":             {"bytes 100-200/32768"},
				"Content-Type":              {"application/octet-stream"},
				"Date":                      {""},
				"Etag":                      {semiCompressibleDataEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + semiCompressibleDataGzipEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"101"},
				"Content-Range":             {"bytes 100-200/" + strconv.Itoa(len(semiCompressibleDataGzip))},
				"Content-Type":              {"application/octet-stream"},
				"Content-Encoding":          {"gzip"},
				"Date":                      {""},
				"Etag":                      {semiCompressibleDataGzipEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + semiCompressibleDataEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"101"},
				"Content-Range":             {"bytes 100-200/32768"},
				"Content-Type":              {"application/octet-stream"},
				"Date":                      {""},
				"Etag":                      {semiCompressibleDataEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + semiCompressibleDataGzipEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"101"},
				"Content-Range":             {"bytes 100-200/" + strconv.Itoa(len(semiCompressibleDataGzip))},
				"Content-Type":              {"application/octet-stream"},
				"Content-Encoding":          {"gzip"},
				"Date":                      {""},
				"Etag":                      {semiCompressibleDataGzipEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + semiCompressibleDataEtag + `,"code":200,"responseBody":32768,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"32768"},
				"Content-Type":              {"application/octet-stream"},
				"Date":                      {""},
				"Etag":                      {semiCompressibleDataEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/semicompressible.foobar","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + semiCompressibleDataGzipEtag + `,"code":200,"responseBody":` + strconv.Itoa(len(semiCompressibleDataGzip)) + `,"requestBody":0,"metrics":{"t":},"message":"StaticFileGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {strconv.Itoa(len(semiCompressibleDataGzip))},
				"Content-Type":              {"application/octet-stream"},
				"Content-Encoding":          {"gzip"},
				"Date":                      {""},
				"Etag":                      {semiCompressibleDataGzipEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
				"Extra":                     {"1234"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"10"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
				`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"L-2SWZmdBbqCzd6xOfS5Via-1_urwrPdsIWeC-2XAok","code":200,"responseBody":142,"requestBody":0,"metrics":{"t":,"test":123456},"message":"HomeGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"142"},
				"Content-Type":              {"application/json"},
				"Date":                      {""},
				"Etag":                      {`"L-2SWZmdBbqCzd6xOfS5Via-1_urwrPdsIWeC-2XAok"`},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/NotFound","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":404,"responseBody":10,"requestBody":0,"metrics":{"t":},"message":"HelperGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"10"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/NotFoundWithError","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","error":"test","code":404,"responseBody":10,"requestBody":0,"metrics":{"t":},"message":"HelperGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"10"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/MethodNotAllowed","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":405,"responseBody":19,"requestBody":0,"metrics":{"t":},"message":"HelperGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Allow":                     {"DELETE, GET"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"19"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"error","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/InternalServerError","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":500,"responseBody":22,"requestBody":0,"metrics":{"t":},"message":"HelperGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"22"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"error","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/InternalServerErrorWithError","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","error":"test","code":500,"responseBody":22,"requestBody":0,"metrics":{"t":},"message":"HelperGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"22"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/Canceled","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","context":"canceled","code":408,"responseBody":16,"requestBody":0,"metrics":{"t":},"message":"HelperGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"16"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/DeadlineExceeded","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","context":"deadline exceeded","code":408,"responseBody":16,"requestBody":0,"metrics":{"t":},"message":"HelperGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"16"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"error","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/Proxy","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","error":"Proxy called without ProxyStaticTo config","code":500,"responseBody":22,"requestBody":0,"metrics":{"t":},"message":"HelperGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"22"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"warn","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/helper/something","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":400,"responseBody":12,"requestBody":0,"metrics":{"t":},"message":"HelperGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"12"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"error","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/panic","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","panic":true,"error":"test","code":500,"responseBody":22,"requestBody":0,"metrics":{"t":},"message":"PanicGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"22"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"10"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"j0Jw1Eosvc8TRxjb6f9Gy2tYjfHaVdlIoKpog0X2WKE","metadata":{"foobar":42},"code":200,"responseBody":12,"requestBody":0,"metrics":{"j":,"t":},"message":"JSONGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"12"},
				"Content-Type":              {"application/json"},
				"Date":                      {""},
				"Etag":                      {`"j0Jw1Eosvc8TRxjb6f9Gy2tYjfHaVdlIoKpog0X2WKE"`},
				"Request-Id":                {""},
				"Test-Metadata":             {"foobar=42"},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"j0Jw1Eosvc8TRxjb6f9Gy2tYjfHaVdlIoKpog0X2WKE","metadata":{"foobar":42},"code":200,"responseBody":12,"requestBody":0,"metrics":{"j":,"t":},"message":"JSONGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"12"},
				"Content-Type":              {"application/json"},
				"Date":                      {""},
				"Etag":                      {`"j0Jw1Eosvc8TRxjb6f9Gy2tYjfHaVdlIoKpog0X2WKE"`},
				"Request-Id":                {""},
				"Test-Metadata":             {"foobar=42"},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"10"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"POST","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","query":{"foo":["1"]},"code":202,"responseBody":16,"requestBody":10,"metrics":{"t":},"message":"JSONPostAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Content-Length":            {"16"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
				"Extra":                     {"1234"},
				"Allow":                     {"GET, HEAD, POST"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"19"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONEtag + `,"code":200,"responseBody":65544,"requestBody":0,"metrics":{"t":},"message":"LargeGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"65544"},
				"Content-Type":              {"application/json"},
				"Date":                      {""},
				"Etag":                      {largeJSONEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONEtag + `,"code":200,"responseBody":65544,"requestBody":0,"metrics":{"t":},"message":"LargeGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"65544"},
				"Content-Type":              {"application/json"},
				"Date":                      {""},
				"Etag":                      {largeJSONEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + largeJSONGzipEtag + `,"code":200,"responseBody":` + strconv.Itoa(len(largeJSONGzip)) + `,"requestBody":0,"metrics":{"c":,"t":},"message":"LargeGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {strconv.Itoa(len(largeJSONGzip))},
				"Content-Type":              {"application/json"},
				"Content-Encoding":          {"gzip"},
				"Date":                      {""},
				"Etag":                      {largeJSONGzipEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"LargeGetAPI"}` + "\n",
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONGzipEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"c":,"t":},"message":"LargeGetAPI"}` + "\n",
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":},"message":"LargeGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"101"},
				"Content-Range":             {"bytes 100-200/65544"},
				"Content-Type":              {"application/json"},
				"Date":                      {""},
				"Etag":                      {largeJSONEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + largeJSONGzipEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"c":,"t":},"message":"LargeGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"101"},
				"Content-Range":             {"bytes 100-200/" + strconv.Itoa(len(largeJSONGzip))},
				"Content-Type":              {"application/json"},
				"Content-Encoding":          {"gzip"},
				"Date":                      {""},
				"Etag":                      {largeJSONGzipEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONEtag + `,"code":206,"responseBody":19901,"requestBody":0,"metrics":{"t":},"message":"LargeGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"19901"},
				"Content-Range":             {"bytes 100-20000/65544"},
				"Content-Type":              {"application/json"},
				"Date":                      {""},
				"Etag":                      {largeJSONEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + largeJSONGzipEtag + `,"code":206,"responseBody":19901,"requestBody":0,"metrics":{"c":,"t":},"message":"LargeGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"19901"},
				"Content-Range":             {"bytes 100-20000/" + strconv.Itoa(len(largeJSONGzip))},
				"Content-Type":              {"application/json"},
				"Content-Encoding":          {"gzip"},
				"Date":                      {""},
				"Etag":                      {largeJSONGzipEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"LargeGetAPI"}` + "\n",
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONGzipEtag + `,"code":304,"responseBody":0,"requestBody":0,"metrics":{"c":,"t":},"message":"LargeGetAPI"}` + "\n",
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":},"message":"LargeGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"101"},
				"Content-Range":             {"bytes 100-200/65544"},
				"Content-Type":              {"application/json"},
				"Date":                      {""},
				"Etag":                      {largeJSONEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + largeJSONGzipEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"c":,"t":},"message":"LargeGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"101"},
				"Content-Range":             {"bytes 100-200/" + strconv.Itoa(len(largeJSONGzip))},
				"Content-Type":              {"application/json"},
				"Content-Encoding":          {"gzip"},
				"Date":                      {""},
				"Etag":                      {largeJSONGzipEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"t":},"message":"LargeGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"101"},
				"Content-Range":             {"bytes 100-200/65544"},
				"Content-Type":              {"application/json"},
				"Date":                      {""},
				"Etag":                      {largeJSONEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + largeJSONGzipEtag + `,"code":206,"responseBody":101,"requestBody":0,"metrics":{"c":,"t":},"message":"LargeGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"101"},
				"Content-Range":             {"bytes 100-200/" + strconv.Itoa(len(largeJSONGzip))},
				"Content-Type":              {"application/json"},
				"Content-Encoding":          {"gzip"},
				"Date":                      {""},
				"Etag":                      {largeJSONGzipEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + largeJSONEtag + `,"code":200,"responseBody":65544,"requestBody":0,"metrics":{"t":},"message":"LargeGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"65544"},
				"Content-Type":              {"application/json"},
				"Date":                      {""},
				"Etag":                      {largeJSONEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/large","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","encoding":"gzip","etag":` + largeJSONGzipEtag + `,"code":200,"responseBody":` + strconv.Itoa(len(largeJSONGzip)) + `,"requestBody":0,"metrics":{"c":,"t":},"message":"LargeGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {strconv.Itoa(len(largeJSONGzip))},
				"Content-Type":              {"application/json"},
				"Content-Encoding":          {"gzip"},
				"Date":                      {""},
				"Etag":                      {largeJSONGzipEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/noncompressible","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":` + nonCompressibleDataEtag + `,"code":200,"responseBody":32768,"requestBody":0,"metrics":{"c":,"t":},"message":"NonCompressibleJSONGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"32768"},
				"Content-Type":              {"application/json"},
				"Date":                      {""},
				"Etag":                      {nonCompressibleDataEtag},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","proxied":"","code":200,"responseBody":24,"requestBody":0,"metrics":{"t":},"message":"HomeGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Content-Length":            {"24"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Test-Header":               {"foobar"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
				"Extra":                     {"1234"},
				"Content-Length":            {"24"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Test-Header":               {"foobar"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
				"Extra":                     {"1234"},
				"Content-Length":            {"24"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Test-Header":               {"foobar"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
				"Extra":                     {"1234"},
				"Content-Length":            {"24"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Test-Header":               {"foobar"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
				`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"L-2SWZmdBbqCzd6xOfS5Via-1_urwrPdsIWeC-2XAok","code":200,"responseBody":142,"requestBody":0,"metrics":{"t":,"test":123456},"message":"HomeGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"142"},
				"Content-Type":              {"application/json"},
				"Date":                      {""},
				"Etag":                      {`"L-2SWZmdBbqCzd6xOfS5Via-1_urwrPdsIWeC-2XAok"`},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"10"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"j0Jw1Eosvc8TRxjb6f9Gy2tYjfHaVdlIoKpog0X2WKE","metadata":{"foobar":42},"code":200,"responseBody":12,"requestBody":0,"metrics":{"j":,"t":},"message":"JSONGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"12"},
				"Content-Type":              {"application/json"},
				"Date":                      {""},
				"Etag":                      {`"j0Jw1Eosvc8TRxjb6f9Gy2tYjfHaVdlIoKpog0X2WKE"`},
				"Request-Id":                {""},
				"Test-Metadata":             {"foobar=42"},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
				"Extra":                     {"1234"},
				"Content-Length":            {"24"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Test-Header":               {"foobar"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
				"Extra":                     {"1234"},
				"Content-Length":            {"50"},
				"Content-Type":              {"text/plain; charset=utf-8"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Test-Header":               {"foobar"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"tN1X-esKHJy3BUQrWNN0YaiNCkUYVp_5YmywXfn0Kx8","code":200,"responseBody":82,"requestBody":0,"metrics":{"t":},"message":"HomeGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"82"},
				"Content-Type":              {"text/html; charset=utf-8"},
				"Date":                      {""},
				"Etag":                      {`"tN1X-esKHJy3BUQrWNN0YaiNCkUYVp_5YmywXfn0Kx8"`},
				"Request-Id":                {""},
				"Vary":                      {"Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o","code":200,"responseBody":2,"requestBody":0,"metrics":{"t":},"message":"CORSGet"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"2"},
				"Content-Type":              {"application/json"},
				"Date":                      {""},
				"Etag":                      {`"RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"`},
				"Request-Id":                {""},
				"Vary":                      {"Origin", "Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o","code":200,"responseBody":2,"requestBody":0,"metrics":{"t":},"message":"CORSGet"}` + "\n",
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
				"Strict-Transport-Security":        {"max-age=31536000"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":213,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSOptions"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Content-Length":            {"0"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Vary":                      {"Origin"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":213,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSOptions"}` + "\n",
			http.Header{
				"Extra":                            {"1234"},
				"Content-Length":                   {"0"},
				"Date":                             {""},
				"Request-Id":                       {""},
				"Vary":                             {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"},
				"Strict-Transport-Security":        {"max-age=31536000"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":213,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSOptions"}` + "\n",
			http.Header{
				"Extra":                            {"1234"},
				"Content-Length":                   {"0"},
				"Date":                             {""},
				"Request-Id":                       {""},
				"Vary":                             {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"},
				"Strict-Transport-Security":        {"max-age=31536000"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":213,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSOptions"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Content-Length":            {"0"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Vary":                      {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o","code":200,"responseBody":2,"requestBody":0,"metrics":{"t":},"message":"CORSGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"2"},
				"Content-Type":              {"application/json"},
				"Date":                      {""},
				"Etag":                      {`"RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"`},
				"Request-Id":                {""},
				"Vary":                      {"Origin", "Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o","code":200,"responseBody":2,"requestBody":0,"metrics":{"t":},"message":"CORSGetAPI"}` + "\n",
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
				"Strict-Transport-Security":     {"max-age=31536000"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"GET","path":"/api/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","etag":"RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o","code":200,"responseBody":2,"requestBody":0,"metrics":{"t":},"message":"CORSGetAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Accept-Ranges":             {"bytes"},
				"Cache-Control":             {"no-cache"},
				"Content-Length":            {"2"},
				"Content-Type":              {"application/json"},
				"Date":                      {""},
				"Etag":                      {`"RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"`},
				"Request-Id":                {""},
				"Vary":                      {"Origin", "Accept-Encoding"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/api/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":214,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSOptionsAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Content-Length":            {"0"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Vary":                      {"Origin"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/api/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":214,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSOptionsAPI"}` + "\n",
			http.Header{
				"Extra":                                {"1234"},
				"Content-Length":                       {"0"},
				"Date":                                 {""},
				"Request-Id":                           {""},
				"Vary":                                 {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network"},
				"Strict-Transport-Security":            {"max-age=31536000"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/api/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":214,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSOptionsAPI"}` + "\n",
			http.Header{
				"Extra":                                {"1234"},
				"Content-Length":                       {"0"},
				"Date":                                 {""},
				"Request-Id":                           {""},
				"Vary":                                 {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network"},
				"Strict-Transport-Security":            {"max-age=31536000"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/api/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":214,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSOptionsAPI"}` + "\n",
			http.Header{
				"Extra":                                {"1234"},
				"Content-Length":                       {"0"},
				"Date":                                 {""},
				"Request-Id":                           {""},
				"Vary":                                 {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network"},
				"Strict-Transport-Security":            {"max-age=31536000"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/api/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":214,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSOptionsAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Content-Length":            {"0"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Vary":                      {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/api/cors","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":214,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSOptionsAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Content-Length":            {"0"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Vary":                      {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/api/corsNoOptions","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":204,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSNoOptionsOptionsAPI"}` + "\n",
			http.Header{
				"Extra":                     {"1234"},
				"Date":                      {""},
				"Request-Id":                {""},
				"Vary":                      {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"},
				"Strict-Transport-Security": {"max-age=31536000"},
				"X-Content-Type-Options":    {"nosniff"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/api/corsNoOptions","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":204,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSNoOptionsOptionsAPI"}` + "\n",
			http.Header{
				"Extra":                            {"1234"},
				"Date":                             {""},
				"Request-Id":                       {""},
				"Vary":                             {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"},
				"Strict-Transport-Security":        {"max-age=31536000"},
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
			`{"level":"info","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"method":"OPTIONS","path":"/api/corsNoOptions","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"example.com","code":204,"responseBody":0,"requestBody":0,"metrics":{"t":},"message":"CORSNoOptionsOptionsAPI"}` + "\n",
			http.Header{
				"Extra":                            {"1234"},
				"Date":                             {""},
				"Request-Id":                       {""},
				"Vary":                             {"Origin, Access-Control-Request-Method, Access-Control-Request-Headers"},
				"Strict-Transport-Security":        {"max-age=31536000"},
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
					assert.Equal(t, tt.ExpectedHeader, headerCleanup(t, resp.Header))
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
				out, err := io.ReadAll(resp.Body)
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
					"Accept-Ranges":             {"bytes"},
					"Cache-Control":             {"no-cache"},
					"Content-Length":            {"107"},
					"Content-Type":              {"text/html; charset=utf-8"},
					"Date":                      {""},
					"Etag":                      {`"nltu2O-xBi-IMFP71Eouztmo9ltQ_ZjyIe3WvcvaP6Q"`},
					"Request-Id":                {""},
					"Vary":                      {"Accept-Encoding"},
					"Strict-Transport-Security": {"max-age=31536000"},
					"X-Content-Type-Options":    {"nosniff"},
				}, headerCleanup(t, resp.Header))
			}

			resp, err = client.Get("https://site.test/context.json") //nolint:noctx
			if assert.NoError(t, err) {
				t.Cleanup(func() { resp.Body.Close() }) //nolint:errcheck,gosec
				out, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, 2, resp.ProtoMajor)
				assert.Equal(t, `{"domain":"site.test","title":"Hello site"}`, string(out)) //nolint:testifylint
				assert.Equal(t, http.Header{
					"Server-Timing": {"t;dur="},
				}, headerCleanup(t, resp.Trailer))
				assert.Equal(t, http.Header{
					"Accept-Ranges":             {"bytes"},
					"Cache-Control":             {"no-cache"},
					"Content-Length":            {"43"},
					"Content-Type":              {"application/json"},
					"Date":                      {""},
					"Etag":                      {`"j4ddcndeVVi9jvW5UpoBerhfZojNaRKhVcRnLmJdALE"`},
					"Request-Id":                {""},
					"Vary":                      {"Accept-Encoding"},
					"Strict-Transport-Security": {"max-age=31536000"},
					"X-Content-Type-Options":    {"nosniff"},
				}, headerCleanup(t, resp.Header))
			}

			resp, err = client.Get("https://site.test/routes.json") //nolint:noctx
			if assert.NoError(t, err) {
				t.Cleanup(func() { resp.Body.Close() }) //nolint:errcheck,gosec
				out, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, 2, resp.ProtoMajor)
				assert.Equal(t, `{"Home":{"handlers":{"GET":true},"path":"/"}}`, string(out)) //nolint:testifylint
				assert.Equal(t, http.Header{
					"Server-Timing": {"t;dur="},
				}, headerCleanup(t, resp.Trailer))
				assert.Equal(t, http.Header{
					"Accept-Ranges":             {"bytes"},
					"Cache-Control":             {"no-cache"},
					"Content-Length":            {"45"},
					"Content-Type":              {"application/json"},
					"Date":                      {""},
					"Etag":                      {`"KwxdKPyvPn9rzrPLFSPvokRhvVPm7S943P493VlISaU"`},
					"Request-Id":                {""},
					"Vary":                      {"Accept-Encoding"},
					"Strict-Transport-Security": {"max-age=31536000"},
					"X-Content-Type-Options":    {"nosniff"},
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
			assert.Equal(t, `{"level":"debug","path":"/index.html","time":"","message":"added file to static files"}
{"level":"debug","path":"/context.json","time":"","message":"added file to static files"}
{"level":"debug","path":"/routes.json","time":"","message":"added file to static files"}
{"level":"info","listenAddr":"[::]:5001","domains":["site.test"],"time":"","message":"HTTPS server starting"}
{"level":"info","request":"","time":"","message":"hello from Home handler"}
{"level":"info","method":"GET","path":"/","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"site.test","etag":"nltu2O-xBi-IMFP71Eouztmo9ltQ_ZjyIe3WvcvaP6Q","code":200,"responseBody":107,"requestBody":0,"metrics":{"t":},"time":"","message":"HomeGet"}
{"level":"info","method":"GET","path":"/context.json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"site.test","etag":"j4ddcndeVVi9jvW5UpoBerhfZojNaRKhVcRnLmJdALE","code":200,"responseBody":43,"requestBody":0,"metrics":{"t":},"time":"","message":"StaticFileGet"}
{"level":"info","method":"GET","path":"/routes.json","client":"127.0.0.1","agent":"Go-http-client/2.0","connection":"","request":"","proto":"2.0","host":"site.test","etag":"KwxdKPyvPn9rzrPLFSPvokRhvVPm7S943P493VlISaU","code":200,"responseBody":45,"requestBody":0,"metrics":{"t":},"time":"","message":"StaticFileGet"}
{"level":"info","time":"","message":"HTTPS server stopping"}
`, logCleanup(t, true, output.String()))
		})
	}
}
