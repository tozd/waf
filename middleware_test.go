package waf

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	h = hlog.NewHandler(zerolog.New(out))(h)
	h.ServeHTTP(nil, r)
	assert.Equal(t, `{"host":"example.com"}`+"\n", out.String())
}

func TestRequestIDHandler(t *testing.T) {
	t.Parallel()

	out := &bytes.Buffer{}
	r := &http.Request{}
	h := requestIDHandler("request", "Request-Id")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := RequestID(r)
		require.True(t, ok, "missing request ID")
		assert.Equal(t, id.String(), w.Header().Get("Request-Id"))
		l := hlog.FromRequest(r)
		l.Log().Msg("")
	}))
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
	h3 := hlog.NewHandler(zerolog.New(out))(h2)
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
	h3 := hlog.NewHandler(zerolog.New(out))(h2)
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
				w.WriteHeader(http.StatusOK)
			}),
			`{"code":200,"size":0}`,
		},
		{
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			}),
			`{"code":0,"size":0}`,
		},
		{
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Error(w, r, http.StatusNotFound)
			}),
			`{"code":404,"size":10}`,
		},
	}

	for k, tt := range tests {
		tt := tt

		t.Run(fmt.Sprintf("case=#%d", k), func(t *testing.T) {
			t.Parallel()

			out := &bytes.Buffer{}
			w := httptest.NewRecorder()
			r := &http.Request{}
			h := accessHandler(func(r *http.Request, code int, size int64, duration time.Duration) {
				l := hlog.FromRequest(r).Log()
				l.Int("code", code).Int64("size", size).Msg("")
				assert.Positive(t, duration)
			})(tt.handler)
			h = hlog.NewHandler(zerolog.New(out))(h)
			h.ServeHTTP(w, r)
			assert.Equal(t, tt.expected+"\n", out.String())
			res := w.Result()
			t.Cleanup(func() {
				res.Body.Close()
			})
			trailer := res.Trailer.Get(servertiming.HeaderKey)
			assert.True(t, strings.HasPrefix(trailer, "t;dur="), trailer)
		})
	}
}
