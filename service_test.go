package waf

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	servertiming "github.com/mitchellh/go-server-timing"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/errors"
)

type testSite struct {
	Site

	Description string `json:"description"`
}

type testService struct {
	Service[*testSite]
}

func (s *testService) HomeGetAPIGet(w http.ResponseWriter, req *http.Request, _ Params) {
	timing := servertiming.FromContext(req.Context())
	timing.NewMetric("test").Duration = time.Second

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
		s.MethodNotAllowed(w, req)
	case "NotAcceptable":
		s.NotAcceptable(w, req)
	case "InternalServerError":
		s.InternalServerError(w, req)
	case "InternalServerErrorWithError":
		s.InternalServerErrorWithError(w, req, errors.New("test"))
	case "Canceled":
		s.InternalServerErrorWithError(w, req, errors.WithStack(context.Canceled))
	case "DeadlineExceeded":
		s.InternalServerErrorWithError(w, req, errors.WithStack(context.DeadlineExceeded))
	default:
		s.BadRequest(w, req)
	}
}

func (s *testService) PanicAPIGet(_ http.ResponseWriter, _ *http.Request, _ Params) {
	panic(errors.New("test"))
}

func (s *testService) JSONAPIGet(w http.ResponseWriter, req *http.Request, _ Params) {
	metadata := http.Header{}
	metadata.Set("foobar", "42")
	s.WriteJSON(w, req, compressionIdentity, map[string]interface{}{"data": 123}, metadata)
}

func (s *testService) JSONAPIPost(w http.ResponseWriter, req *http.Request, _ Params) {
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(req.Form.Encode()))
}

var testFiles = fstest.MapFS{ //nolint:gochecknoglobals
	"assets/image.png": &fstest.MapFile{
		Data: []byte("test image"),
	},
	"data.txt": &fstest.MapFile{
		Data: []byte("test data"),
	},
	"index.html": &fstest.MapFile{
		Data: []byte(`<!DOCTYPE html><html><head><title>{{ .Site.Title }}</title></head><body>{{ .Site.Description }}</body></html>`),
	},
}

func newRequest(t *testing.T, method, url string, body io.Reader) *http.Request {
	t.Helper()

	req, err := http.NewRequest(method, url, body) //nolint:noctx
	require.NoError(t, err)
	return req
}

func newService(t *testing.T, logger zerolog.Logger) (*testService, *httptest.Server) {
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
			MetadataHeaderPrefix: "test-",
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

	ts := httptest.NewUnstartedServer(handler)
	ts.Config.ConnContext = (&Server[*testSite]{}).connContext
	t.Cleanup(ts.Close)
	ts.Start()

	var listenAddr atomic.Value
	listenAddr.Store(ts.Listener.Addr().String())

	// We make a client version which maps example.com to the address ts is listening on.
	client := ts.Client()
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) { //nolint:forcetypeassert
		if addr == "example.com:80" || addr == "other.example.com:80" {
			addr = listenAddr.Load().(string) //nolint:forcetypeassert,errcheck
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}

	return service, ts
}

var logCleanupRegexp = regexp.MustCompile(`("connection":")[^"]+(")|("request":")[^"]+(")|("[tjc]":)[0-9.]+`)

func logCleanup(t *testing.T, log string) string {
	t.Helper()

	return logCleanupRegexp.ReplaceAllString(log, "$1$2$3$4$5")
}

func TestServicePath(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}

	service, _ := newService(t, zerolog.New(out))

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
`, out.String())
}

func TestService(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Request        func() *http.Request
		ExpectedStatus int
		ExpectedBody   string
		ExpectedLog    string
	}{
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "http://example.com/", nil)
			},
			http.StatusOK,
			`<!DOCTYPE html><html><head><title>test</title></head><body>test site</body></html>`,
			`{"level":"info","method":"GET","path":"/","client":"127.0.0.1","agent":"Go-http-client/1.1","connection":"","request":"","proto":"1.1","host":"example.com","message":"HomeGet","etag":"tN1X-esKHJy3BUQrWNN0YaiNCkUYVp_5YmywXfn0Kx8","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"size":82,"metrics":{"t":}}` + "\n",
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "http://example.com/api/", nil)
			},
			http.StatusOK,
			`{"site":{"domain":"example.com","title":"test","description":"test site"},"build":{"version":"vTEST","buildTimestamp":"2023-11-03T00:51:07Z","revision":"abcde"}}`,
			`{"level":"info","request":"","message":"test msg"}` + "\n" +
				`{"level":"info","method":"GET","path":"/api/","client":"127.0.0.1","agent":"Go-http-client/1.1","connection":"","request":"","proto":"1.1","host":"example.com","message":"HomeGetAPIGet","etag":"aj4IanxlXD_73WR2wutz11Tk3JWHdZqpvuIvB1ivNWk","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"size":161,"metrics":{"test":1000,"t":}}` + "\n",
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "http://example.com/helper/NotFound", nil)
			},
			http.StatusNotFound,
			"Not Found\n",
			`{"level":"warn","method":"GET","path":"/helper/NotFound","client":"127.0.0.1","agent":"Go-http-client/1.1","connection":"","request":"","proto":"1.1","host":"example.com","message":"HelperGet","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":404,"size":10,"metrics":{"t":}}` + "\n",
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "http://example.com/helper/NotFoundWithError", nil)
			},
			http.StatusNotFound,
			"Not Found\n",
			`{"level":"warn","method":"GET","path":"/helper/NotFoundWithError","client":"127.0.0.1","agent":"Go-http-client/1.1","connection":"","request":"","proto":"1.1","host":"example.com","message":"HelperGet","error":"test","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":404,"size":10,"metrics":{"t":}}` + "\n",
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "http://example.com/helper/MethodNotAllowed", nil)
			},
			http.StatusMethodNotAllowed,
			"Method Not Allowed\n",
			`{"level":"warn","method":"GET","path":"/helper/MethodNotAllowed","client":"127.0.0.1","agent":"Go-http-client/1.1","connection":"","request":"","proto":"1.1","host":"example.com","message":"HelperGet","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":405,"size":19,"metrics":{"t":}}` + "\n",
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "http://example.com/helper/NotAcceptable", nil)
			},
			http.StatusNotAcceptable,
			"Not Acceptable\n",
			`{"level":"warn","method":"GET","path":"/helper/NotAcceptable","client":"127.0.0.1","agent":"Go-http-client/1.1","connection":"","request":"","proto":"1.1","host":"example.com","message":"HelperGet","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":406,"size":15,"metrics":{"t":}}` + "\n",
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "http://example.com/helper/InternalServerError", nil)
			},
			http.StatusInternalServerError,
			"Internal Server Error\n",
			`{"level":"error","method":"GET","path":"/helper/InternalServerError","client":"127.0.0.1","agent":"Go-http-client/1.1","connection":"","request":"","proto":"1.1","host":"example.com","message":"HelperGet","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":500,"size":22,"metrics":{"t":}}` + "\n",
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "http://example.com/helper/InternalServerErrorWithError", nil)
			},
			http.StatusInternalServerError,
			"Internal Server Error\n",
			`{"level":"error","method":"GET","path":"/helper/InternalServerErrorWithError","client":"127.0.0.1","agent":"Go-http-client/1.1","connection":"","request":"","proto":"1.1","host":"example.com","message":"HelperGet","error":"test","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":500,"size":22,"metrics":{"t":}}` + "\n",
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "http://example.com/helper/Canceled", nil)
			},
			http.StatusRequestTimeout,
			"Request Timeout\n",
			`{"level":"warn","method":"GET","path":"/helper/Canceled","client":"127.0.0.1","agent":"Go-http-client/1.1","connection":"","request":"","proto":"1.1","host":"example.com","message":"HelperGet","context":"canceled","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":408,"size":16,"metrics":{"t":}}` + "\n",
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "http://example.com/helper/DeadlineExceeded", nil)
			},
			http.StatusRequestTimeout,
			"Request Timeout\n",
			`{"level":"warn","method":"GET","path":"/helper/DeadlineExceeded","client":"127.0.0.1","agent":"Go-http-client/1.1","connection":"","request":"","proto":"1.1","host":"example.com","message":"HelperGet","context":"deadline exceeded","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":408,"size":16,"metrics":{"t":}}` + "\n",
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "http://example.com/helper/something", nil)
			}, http.StatusBadRequest,
			"Bad Request\n",
			`{"level":"warn","method":"GET","path":"/helper/something","client":"127.0.0.1","agent":"Go-http-client/1.1","connection":"","request":"","proto":"1.1","host":"example.com","message":"HelperGet","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":400,"size":12,"metrics":{"t":}}` + "\n",
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "http://example.com/api/panic", nil)
			},
			http.StatusInternalServerError,
			"Internal Server Error\n",
			`{"level":"error","method":"GET","path":"/api/panic","client":"127.0.0.1","agent":"Go-http-client/1.1","connection":"","request":"","proto":"1.1","host":"example.com","message":"PanicAPIGet","error":"test","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":500,"size":22,"metrics":{"t":}}` + "\n",
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "http://other.example.com/", nil)
			},
			http.StatusNotFound,
			"Not Found\n",
			`{"level":"warn","method":"GET","path":"/","client":"127.0.0.1","agent":"Go-http-client/1.1","connection":"","request":"","proto":"1.1","host":"other.example.com","message":"HomeGet","error":"site not found for host","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":404,"size":10,"metrics":{"t":}}` + "\n",
		},
		{
			func() *http.Request {
				return newRequest(t, http.MethodGet, "http://example.com/api/json", nil)
			},
			http.StatusOK,
			`{"data":123}`,
			`{"level":"info","method":"GET","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/1.1","connection":"","request":"","proto":"1.1","host":"example.com","message":"JSONAPIGet","metadata":{"Foobar":["42"]},"etag":"KcFDb3C8-dK_3QADiV0TXFENFQxhaHDKRUNF8Gqc3dA","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":200,"size":12,"metrics":{"j":,"c":,"t":}}` + "\n",
		},
		{
			func() *http.Request {
				req := newRequest(t, http.MethodPost, "http://example.com/api/json?foo=1", bytes.NewBufferString("data=abcde"))
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			http.StatusAccepted,
			`data=abcde&foo=1`,
			`{"level":"info","method":"POST","path":"/api/json","client":"127.0.0.1","agent":"Go-http-client/1.1","connection":"","request":"","proto":"1.1","host":"example.com","query":{"foo":["1"]},"message":"JSONAPIPost","build":{"r":"abcde","t":"2023-11-03T00:51:07Z","v":"vTEST"},"code":202,"size":16,"metrics":{"t":}}` + "\n",
		},
	}

	for k, tt := range tests {
		tt := tt

		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			t.Parallel()

			log := &bytes.Buffer{}

			_, ts := newService(t, zerolog.New(log).Level(zerolog.InfoLevel))

			resp, err := ts.Client().Do(tt.Request())
			if assert.NoError(t, err) {
				defer resp.Body.Close()
				out, err := io.ReadAll(resp.Body)
				assert.NoError(t, err)
				assert.Equal(t, tt.ExpectedStatus, resp.StatusCode)
				assert.Equal(t, tt.ExpectedBody, string(out))
				assert.Equal(t, tt.ExpectedLog, logCleanup(t, log.String()))
			}
		})
	}
}

func TestReverseProxy(t *testing.T) {
}
