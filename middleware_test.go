package waf

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/identifier"
	"nhooyr.io/websocket"
)

func TestConnectionIDHandler(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	r := &http.Request{}
	s := Server[*Site]{}
	r = r.WithContext(s.connContext(context.Background(), nil))
	h := connectionIDHandler("connection")(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		l := hlog.FromRequest(r)
		l.Log().Msg("")
	}))
	h = setCanonicalLogger(h)
	h = hlog.NewHandler(zerolog.New(out))(h)
	h.ServeHTTP(nil, r)
	id, ok := r.Context().Value(connectionIDContextKey).(identifier.Identifier)
	assert.True(t, ok)
	assert.Equal(t, `{"connection":"`+id.String()+`"}`+"\n", out.String())
}

func TestRequestIDHandler(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	r := &http.Request{}
	h := requestIDHandler("request", "Request-Id")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		id := MustRequestID(r.Context())
		assert.Equal(t, id.String(), w.Header().Get("Request-Id"))
		l := hlog.FromRequest(r)
		l.Log().Msg("")
	}))
	h = setCanonicalLogger(h)
	h = hlog.NewHandler(zerolog.New(out))(h)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	res := w.Result()
	t.Cleanup(func() {
		res.Body.Close()
	})
	assert.Equal(t, `{"request":"`+res.Header.Get("Request-Id")+`"}`+"\n", out.String())
}

func TestURLHandler(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	r := &http.Request{
		URL: &url.URL{Path: "/path", RawQuery: "foo=bar"},
	}
	h := urlHandler("url")(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		l := hlog.FromRequest(r)
		l.Log().Msg("")
	}))
	h = setCanonicalLogger(h)
	h = hlog.NewHandler(zerolog.New(out))(h)
	h.ServeHTTP(nil, r)
	assert.Equal(t, `{"url":"/path"}`+"\n", out.String())
}

func TestAccessHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		handler  http.Handler
		expected string
	}{
		{
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.ReadAll(r.Body)
				w.WriteHeader(http.StatusOK)
			}),
			`{"code":200,"responseBody":0,"requestBody":4}`,
		},
		{
			http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				_, _ = io.ReadAll(r.Body)
			}),
			`{"code":0,"responseBody":0,"requestBody":4}`,
		},
		{
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.ReadAll(r.Body)
				Error(w, r, http.StatusNotFound)
			}),
			`{"code":404,"responseBody":10,"requestBody":4}`,
		},
	}

	for k, tt := range tests {
		tt := tt

		for _, protocol := range []int{1, 2} {
			protocol := protocol

			t.Run(fmt.Sprintf("case=%d/protocol=%d", k, protocol), func(t *testing.T) {
				t.Parallel()

				out := &bytes.Buffer{}
				w := httptest.NewRecorder()
				r := httptest.NewRequest(http.MethodGet, "/foo", bytes.NewBufferString("test"))
				r.ProtoMajor = protocol
				h := accessHandler(func(r *http.Request, code int, responseBody, requestBody int64, duration time.Duration) {
					l := hlog.FromRequest(r)
					l.Log().Int("code", code).Int64("responseBody", responseBody).Int64("requestBody", requestBody).Msg("")
					assert.Positive(t, duration)
				})(tt.handler)
				h = setCanonicalLogger(h)
				h = hlog.NewHandler(zerolog.New(out))(h)
				h.ServeHTTP(w, r)
				assert.Equal(t, tt.expected+"\n", out.String())
				res := w.Result()
				t.Cleanup(func() {
					res.Body.Close()
				})
				trailer := res.Trailer.Get(serverTimingHeader)
				if protocol > 1 {
					assert.True(t, strings.HasPrefix(trailer, "t;dur="), trailer)
				} else {
					assert.Equal(t, "", trailer)
				}
			})
		}
	}
}

func TestLogMetadata(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	w := httptest.NewRecorder()
	r := &http.Request{}
	h := logMetadata("test-")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("test-metadata", "foobar=1234")
		logMetadata := r.Context().Value(metadataContextKey).(map[string]interface{}) //nolint:errcheck,forcetypeassert
		logMetadata["foobar"] = 1234
		w.WriteHeader(http.StatusOK)
	}))
	h2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
		l := hlog.FromRequest(r)
		l.Log().Msg("")
	})
	h3 := setCanonicalLogger(h2)
	h3 = hlog.NewHandler(zerolog.New(out))(h3)
	h3.ServeHTTP(w, r)
	res := w.Result()
	t.Cleanup(func() {
		res.Body.Close()
	})
	assert.Equal(t, "foobar=1234", res.Header.Get("test-metadata"))
	assert.Equal(t, `{"metadata":{"foobar":1234}}`+"\n", out.String())

	out.Reset()
	w = httptest.NewRecorder()
	r = &http.Request{}
	h = logMetadata("test-")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("test-metadata", "foobar=1234")
		logMetadata := r.Context().Value(metadataContextKey).(map[string]interface{}) //nolint:errcheck,forcetypeassert
		logMetadata["foobar"] = 1234
		w.WriteHeader(http.StatusNotModified)
	}))
	h2 = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
		l := hlog.FromRequest(r)
		l.Log().Msg("")
	})
	h3 = setCanonicalLogger(h2)
	h3 = hlog.NewHandler(zerolog.New(out))(h3)
	h3.ServeHTTP(w, r)
	res = w.Result()
	t.Cleanup(func() {
		res.Body.Close()
	})
	assert.Equal(t, "", res.Header.Get("test-metadata"))
	assert.Equal(t, "{}\n", out.String())
}

func TestWebsocketHandlerHijack(t *testing.T) {
	t.Parallel()

	response := []byte("HTTP/1.1 232 Test\r\nConnection: Closed\r\nContent-Length: 0\r\n\r\n")

	var ts *httptest.Server
	pipeR, pipeW, err := os.Pipe()
	t.Cleanup(func() {
		// We might double close but we do not care.
		pipeR.Close()
		pipeW.Close()
	})
	require.NoError(t, err)
	h := websocketHandler("ws")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w) //nolint:bodyclose
		netConn, _, e := rc.Hijack()
		if e != nil {
			Error(w, r, http.StatusInternalServerError)
			return
		}
		defer func() {
			netConn.Close()
			ts.Config.ConnState(netConn, http.StateClosed)
		}()
		_, _ = netConn.Write(response)
	}))
	h2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer pipeW.Close()
		h.ServeHTTP(w, r)
		l := hlog.FromRequest(r)
		l.Log().Msg("")
	})
	h3 := setCanonicalLogger(h2)
	h3 = hlog.NewHandler(zerolog.New(pipeW))(h3)
	ts = httptest.NewServer(h3)
	t.Cleanup(ts.Close)
	resp, err := ts.Client().Get(ts.URL) //nolint:noctx
	if assert.NoError(t, err) {
		t.Cleanup(func() { resp.Body.Close() })
	}
	out, err := io.ReadAll(pipeR)
	pipeR.Close()
	assert.NoError(t, err)
	assert.Equal(t, 232, resp.StatusCode)
	assert.Equal(t, `{"wsFromClient":0,"wsToClient":`+strconv.Itoa(len(response))+`}`+"\n", string(out))
}

func TestWebsocketHandler(t *testing.T) {
	t.Parallel()

	pipeR, pipeW, err := os.Pipe()
	t.Cleanup(func() {
		// We might double close but we do not care.
		pipeR.Close()
		pipeW.Close()
	})
	require.NoError(t, err)
	h := websocketHandler("ws")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil) //nolint:govet
		if !assert.NoError(t, err) {
			return
		}
		defer func() { _ = c.CloseNow() }()

		ctx, cancel := context.WithCancel(r.Context())
		t.Cleanup(cancel)

		typ, d, err := c.Read(ctx)
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, websocket.MessageText, typ)
		assert.Equal(t, []byte("hi"), d)

		err = c.Write(ctx, typ, d)
		if !assert.NoError(t, err) {
			return
		}

		c.Close(websocket.StatusNormalClosure, "")
	}))
	h2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer pipeW.Close()
		h.ServeHTTP(w, r)
		l := hlog.FromRequest(r)
		l.Log().Msg("")
	})
	h3 := setCanonicalLogger(h2)
	h3 = hlog.NewHandler(zerolog.New(pipeW))(h3)

	ts := httptest.NewServer(h3)
	t.Cleanup(ts.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	c, _, err := websocket.Dial(ctx, strings.ReplaceAll(ts.URL, "http", "ws"), nil) //nolint:bodyclose
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.CloseNow() })

	err = c.Write(ctx, websocket.MessageText, []byte("hi"))
	require.NoError(t, err)

	typ, d, err := c.Read(ctx)
	require.NoError(t, err)

	assert.Equal(t, websocket.MessageText, typ)
	assert.Equal(t, []byte("hi"), d)

	c.Close(websocket.StatusNormalClosure, "")

	out, err := io.ReadAll(pipeR)
	pipeR.Close()
	assert.NoError(t, err)
	assert.Equal(t, `{"wsFromClient":16,"wsToClient":8}`+"\n", string(out))
}

func TestParseForm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		queryString string
		postBody    string
		postValues  url.Values
		formValues  url.Values
		expectedLog string
	}{
		{
			"key1=value1&key2=value2",
			"key3=value3&key4=value4",
			url.Values{"key3": []string{"value3"}, "key4": []string{"value4"}},
			url.Values{"key1": []string{"value1"}, "key2": []string{"value2"}, "key3": []string{"value3"}, "key4": []string{"value4"}},
			`{"query":{"key1":["value1"],"key2":["value2"]}}`,
		},
		{
			"key1=value1;key2=value2",
			"key3=value3&key4=value4",
			url.Values{"key3": []string{"value3"}, "key4": []string{"value4"}},
			url.Values{"key3": []string{"value3"}, "key4": []string{"value4"}},
			`{"error":"error parsing query string: invalid semicolon separator in query","rawQuery":"key1=value1;key2=value2"}`,
		},
		{
			"key1=value1&key2=value2",
			"key3=value3;key4=value4",
			url.Values{},
			url.Values{"key1": []string{"value1"}, "key2": []string{"value2"}},
			`{"error":"error parsing POST form: invalid semicolon separator in query","query":{"key1":["value1"],"key2":["value2"]}}`,
		},
		{
			"key1=value1;key2=value2",
			"key3=value3;key4=value4",
			url.Values{},
			url.Values{},
			`{"error":"error parsing POST form: invalid semicolon separator in query\nerror parsing query string: invalid semicolon separator in query","rawQuery":"key1=value1;key2=value2"}`,
		},
	}

	for k, tt := range tests {
		tt := tt

		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			t.Parallel()

			out := &bytes.Buffer{}
			w := httptest.NewRecorder()
			s := Service[*Site]{
				router: new(Router),
			}
			r := httptest.NewRequest(http.MethodPost, "/example?"+tt.queryString, strings.NewReader(tt.postBody))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			h := s.parseForm("query", "rawQuery")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				l := hlog.FromRequest(r)
				l.Log().Msg("")
				w.WriteHeader(http.StatusOK)
			}))
			h2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				h.ServeHTTP(w, r)
				_, err := r.Body.Read(nil)
				// Here we test for io.EOF and not http.ErrBodyReadAfterClose which would be
				// if the body was made by the http.Server.
				assert.ErrorIs(t, err, io.EOF)
				assert.Equal(t, tt.postValues, r.PostForm)
				assert.Equal(t, tt.formValues, r.Form)
				l := hlog.FromRequest(r)
				l.Log().Msg("")
			})
			h3 := setCanonicalLogger(h2)
			h3 = hlog.NewHandler(zerolog.New(out))(h3)
			h3.ServeHTTP(w, r)
			res := w.Result()
			t.Cleanup(func() {
				res.Body.Close()
			})
			// logValues do not produce deterministic JSON, so we use JSONEq here.
			assert.JSONEq(t, tt.expectedLog, strings.Split(out.String(), "\n")[0])
		})
	}
}

func TestParseFormRedirect(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	s := Service[*Site]{
		router: new(Router),
	}
	r := httptest.NewRequest(http.MethodPost, "/example?key2=value2&key1=value1", nil)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h := s.parseForm("query", "rawQuery")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	h = setCanonicalLogger(h)
	h = hlog.NewHandler(zerolog.New(zerolog.NewTestWriter(t)))(h)
	h.ServeHTTP(w, r)
	res := w.Result()
	t.Cleanup(func() {
		res.Body.Close()
	})
	assert.Equal(t, http.StatusTemporaryRedirect, res.StatusCode)
	assert.Equal(t, "/example?key1=value1&key2=value2", res.Header.Get("Location"))
}

func TestValidatePath(t *testing.T) {
	t.Parallel()

	s := Service[*Site]{
		router: new(Router),
	}
	h := s.validatePath(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	h = setCanonicalLogger(h)
	h = hlog.NewHandler(zerolog.New(zerolog.NewTestWriter(t)))(h)

	tests := []struct {
		In  string
		Out string
	}{
		{"/foo/../bar", "/bar"},
		{"/foo/../bar/", "/bar/"},
	}

	for k, tt := range tests {
		tt := tt

		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, tt.In, nil)
			h.ServeHTTP(w, r)
			res := w.Result()
			t.Cleanup(func() {
				res.Body.Close()
			})
			assert.Equal(t, http.StatusTemporaryRedirect, res.StatusCode)
			assert.Equal(t, tt.Out, res.Header.Get("Location"))
		})
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/foo%0Abar", nil)
	h.ServeHTTP(w, r)
	res := w.Result()
	t.Cleanup(func() {
		res.Body.Close()
	})
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/foo/", nil)
	h.ServeHTTP(w, r)
	res = w.Result()
	t.Cleanup(func() {
		res.Body.Close()
	})
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestValidateSite(t *testing.T) {
	t.Parallel()

	s := Service[*Site]{
		Sites: map[string]*Site{
			"localhost": {
				Domain: "localhost",
			},
		},
	}
	h := setCanonicalLogger(s.validateSite(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := GetSite[*Site](r.Context())
		if ok {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	})))

	tests := []struct {
		Site           string
		ExpectedStatus int
	}{
		{"localhost", http.StatusOK},
		{"example.com", http.StatusNotFound},
		{"localhost:8080", http.StatusOK},
	}

	for k, tt := range tests {
		tt := tt

		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Host = tt.Site
			h.ServeHTTP(w, r)
			res := w.Result()
			t.Cleanup(func() {
				res.Body.Close()
			})
			assert.Equal(t, tt.ExpectedStatus, res.StatusCode)
		})
	}
}

func TestSetCanonicalLogger(t *testing.T) {
	t.Parallel()

	out1 := &bytes.Buffer{}
	out2 := &bytes.Buffer{}
	r := &http.Request{}
	h := setCanonicalLogger(hlog.NewHandler(zerolog.New(out2))(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		l := hlog.FromRequest(r)
		l.Log().Msg("test1")
		l = canonicalLogger(r.Context())
		l.Log().Msg("test2")
	})))
	h = hlog.NewHandler(zerolog.New(out1))(h)
	h.ServeHTTP(nil, r)
	assert.Equal(t, `{"message":"test2"}`+"\n", out1.String())
	assert.Equal(t, `{"message":"test1"}`+"\n", out2.String())
}

func TestAddNosniffHeader(t *testing.T) {
	t.Parallel()

	h := addNosniffHeader(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(w, r)
	res := w.Result()
	t.Cleanup(func() {
		res.Body.Close()
	})
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "nosniff", res.Header.Get("X-Content-Type-Options"))

	h = addNosniffHeader(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(w, r)
	res = w.Result()
	t.Cleanup(func() {
		res.Body.Close()
	})
	assert.Equal(t, http.StatusNotModified, res.StatusCode)
	assert.Equal(t, "", res.Header.Get("X-Content-Type-Options"))
}

func TestRedirectToMainSite(t *testing.T) {
	t.Parallel()

	s := Service[*Site]{
		Sites: map[string]*Site{
			"example.com": {
				Domain: "example.com",
			},
			"www.example.com": {
				Domain: "www.example.com",
			},
		},
	}
	h := setCanonicalLogger(s.validateSite(s.RedirectToMainSite("example.com")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))))

	tests := []struct {
		Target           string
		Host             string
		ExpectedStatus   int
		ExpectedLocation string
	}{
		{"/foo?test=123", "example.com", http.StatusOK, ""},
		{"/foo?test=123", "www.example.com", http.StatusTemporaryRedirect, "https://example.com/foo?test=123"},
		{"/foo?test=123", "example.com:8080", http.StatusOK, ""},
		{"/foo?test=123", "www.example.com:8080", http.StatusTemporaryRedirect, "https://example.com:8080/foo?test=123"},
		{"/foo?test=123", "other.example.com", http.StatusNotFound, ""},
	}

	for k, tt := range tests {
		tt := tt

		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, tt.Target, nil)
			r.Host = tt.Host
			h.ServeHTTP(w, r)
			res := w.Result()
			t.Cleanup(func() {
				res.Body.Close()
			})
			assert.Equal(t, tt.ExpectedStatus, res.StatusCode)
			assert.Equal(t, tt.ExpectedLocation, res.Header.Get("Location"))
		})
	}
}

func TestMetricsMiddleware(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	r := &http.Request{}
	r.ProtoMajor = 2
	h := accessHandler(func(r *http.Request, _ int, _, _ int64, _ time.Duration) {
		ctx := r.Context()
		l := zerolog.Ctx(ctx)
		metrics := MustGetMetrics(ctx)
		l.Log().Object("metrics", metrics).Msg("")
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		metrics := MustGetMetrics(ctx)
		metrics.Counter("counter").Start().Add(42)
		metrics.Duration("duration").Start().Stop()
		metrics.Duration("foreverDuration").Start() // We do not stop on purpose.
		d := metrics.Durations("durations")
		d.Start().Stop()
		d.Start().Stop()
		metrics.DurationCounter("dc").Start().Add(43).Stop()
		metrics.DurationCounter("foreverDc").Start().Add(43) // We do not stop on purpose.
		w.WriteHeader(http.StatusOK)
	}))
	h = metricsMiddleware(h)
	h = setCanonicalLogger(h)
	h = hlog.NewHandler(zerolog.New(out))(h)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	res := w.Result()
	t.Cleanup(func() {
		res.Body.Close()
	})
	assert.Regexp(t, regexp.MustCompile(`\{"metrics":\{"counter":42,"dc":\{"dur":[0-9]+,"count":43,"rate":[0-9.]+},"duration":[0-9]+,"durations":{"min":[0-9]+,"max":[0-9]+,"dur":[0-9]+,"count":[0-9]+,"avg":[0-9]+}}}`), out.String())
	header := res.Header.Get(serverTimingHeader)
	assert.Equal(t, `dc;dur=,duration;dur=`, headerCleanupRegexp.ReplaceAllString(header, ""))
	trailer := res.Trailer.Get(serverTimingHeader)
	assert.Equal(t, `t;dur=`, headerCleanupRegexp.ReplaceAllString(trailer, ""))
}
