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
	"strconv"
	"strings"
	"testing"
	"time"

	servertiming "github.com/mitchellh/go-server-timing"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/identifier"
)

func TestConnectionIDHandler(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	r := &http.Request{}
	s := Server[*Site]{}
	r = r.WithContext(s.connContext(context.Background(), nil))
	h := connectionIDHandler("connection")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func TestHTTPVersionHandler(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	r := &http.Request{
		Proto: "HTTP/1.1",
	}
	h := httpVersionHandler("proto")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := hlog.FromRequest(r)
		l.Log().Msg("")
	}))
	h = setCanonicalLogger(h)
	h = hlog.NewHandler(zerolog.New(out))(h)
	h.ServeHTTP(nil, r)
	assert.Equal(t, `{"proto":"1.1"}`+"\n", out.String())
}

func TestRemoteAddrHandler(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	r := &http.Request{
		RemoteAddr: "1.2.3.4:1234",
	}
	h := remoteAddrHandler("ip")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := hlog.FromRequest(r)
		l.Log().Msg("")
	}))
	h = setCanonicalLogger(h)
	h = hlog.NewHandler(zerolog.New(out))(h)
	h.ServeHTTP(nil, r)
	assert.Equal(t, `{"ip":"1.2.3.4"}`+"\n", out.String())
}

func TestRemoteAddrHandlerIPv6(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	r := &http.Request{
		RemoteAddr: "[2001:db8:a0b:12f0::1]:1234",
	}
	h := remoteAddrHandler("ip")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := hlog.FromRequest(r)
		l.Log().Msg("")
	}))
	h = setCanonicalLogger(h)
	h = hlog.NewHandler(zerolog.New(out))(h)
	h.ServeHTTP(nil, r)
	assert.Equal(t, `{"ip":"2001:db8:a0b:12f0::1"}`+"\n", out.String())
}

func TestHostHandler(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	r := &http.Request{Host: "example.com:8080"}
	h := hostHandler("host")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := hlog.FromRequest(r)
		l.Log().Msg("")
	}))
	h = setCanonicalLogger(h)
	h = hlog.NewHandler(zerolog.New(out))(h)
	h.ServeHTTP(nil, r)
	assert.Equal(t, `{"host":"example.com"}`+"\n", out.String())
}

func TestRequestIDHandler(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	r := &http.Request{}
	h := requestIDHandler("request", "Request-Id")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := RequestID(r.Context())
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
	h := urlHandler("url")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := hlog.FromRequest(r)
		l.Log().Msg("")
	}))
	h = setCanonicalLogger(h)
	h = hlog.NewHandler(zerolog.New(out))(h)
	h.ServeHTTP(nil, r)
	assert.Equal(t, `{"url":"/path"}`+"\n", out.String())
}

func TestEtagHandler(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	w := httptest.NewRecorder()
	r := &http.Request{}
	h := etagHandler("etag")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Etag", `"abcdef"`)
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
	assert.Equal(t, `{"etag":"abcdef"}`+"\n", out.String())
}

func TestResponseHeaderHandler(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	w := httptest.NewRecorder()
	r := &http.Request{}
	h := responseHeaderHandler("encoding", "Content-Encoding")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", `gzip`)
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
	assert.Equal(t, `{"encoding":"gzip"}`+"\n", out.String())
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
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

			t.Run(fmt.Sprintf("case=#%d/protocol=%d", k, protocol), func(t *testing.T) {
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
				trailer := res.Trailer.Get(servertiming.HeaderKey)
				if protocol > 1 {
					assert.True(t, strings.HasPrefix(trailer, "t;dur="), trailer)
				} else {
					assert.Equal(t, "", trailer)
				}
			})
		}
	}
}

func TestRemoveMetadataHeaders(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	r := &http.Request{}
	h := removeMetadataHeaders("test-")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("test-foobar", "1234")
		w.WriteHeader(http.StatusOK)
	}))
	h.ServeHTTP(w, r)
	res := w.Result()
	t.Cleanup(func() {
		res.Body.Close()
	})
	assert.Equal(t, "1234", res.Header.Get("test-foobar"))

	w = httptest.NewRecorder()
	r = &http.Request{}
	h = removeMetadataHeaders("test-")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("test-foobar", "1234")
		w.WriteHeader(http.StatusNotModified)
	}))
	h.ServeHTTP(w, r)
	res = w.Result()
	t.Cleanup(func() {
		res.Body.Close()
	})
	assert.Equal(t, "", res.Header.Get("test-foobar"))
}

func TestWebsocketHandler(t *testing.T) {
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
		h.ServeHTTP(w, r)
		l := hlog.FromRequest(r)
		l.Log().Msg("")
		pipeW.Close()
	})
	h3 := setCanonicalLogger(h2)
	h3 = hlog.NewHandler(zerolog.New(pipeW))(h3)
	ts = httptest.NewServer(h3)
	defer ts.Close()
	resp, err := ts.Client().Get(ts.URL) //nolint:noctx
	if assert.NoError(t, err) {
		defer resp.Body.Close()
	}
	out, err := io.ReadAll(pipeR)
	pipeR.Close()
	assert.NoError(t, err)
	assert.Equal(t, 232, resp.StatusCode)
	assert.Equal(t, `{"ws":{"fromClient":0,"toClient":`+strconv.Itoa(len(response))+`}}`+"\n", string(out))
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

		t.Run(fmt.Sprintf("case=#%d", k), func(t *testing.T) {
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
	h := s.parseForm("query", "rawQuery")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	h := s.validatePath(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		t.Run(fmt.Sprintf("case=#%d", k), func(t *testing.T) {
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
