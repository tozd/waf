package waf

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/felixge/httpsnoop"
	servertiming "github.com/mitchellh/go-server-timing"
	"github.com/rs/zerolog"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
)

func connectionIDHandler(fieldKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			id, ok := req.Context().Value(connectionIDContextKey).(string)
			if ok {
				logger := zerolog.Ctx(req.Context())
				logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str(fieldKey, id)
				})
			}
			next.ServeHTTP(w, req)
		})
	}
}

func protocolHandler(fieldKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			proto := strings.TrimPrefix(req.Proto, "HTTP/")
			logger := zerolog.Ctx(req.Context())
			logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
				return c.Str(fieldKey, proto)
			})
			next.ServeHTTP(w, req)
		})
	}
}

// remoteAddrHandler is similar to hlog.remoteAddrHandler, but logs only an IP, not a port.
func remoteAddrHandler(fieldKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ip := getHost(req.RemoteAddr)
			if ip != "" {
				logger := zerolog.Ctx(req.Context())
				logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str(fieldKey, ip)
				})
			}
			next.ServeHTTP(w, req)
		})
	}
}

func hostHandler(fieldKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			host := getHost(req.Host)
			if host != "" {
				logger := zerolog.Ctx(req.Context())
				logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str(fieldKey, host)
				})
			}
			next.ServeHTTP(w, req)
		})
	}
}

// requestIDHandler is similar to hlog.requestIDHandler, but uses identifier.NewRandom() for ID.
func requestIDHandler(fieldKey, headerName string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := req.Context()
			id, ok := idFromRequest(req)
			if !ok {
				id = identifier.New()
				ctx = context.WithValue(ctx, requestIDContextKey, id)
				req = req.WithContext(ctx)
			}
			if fieldKey != "" {
				logger := zerolog.Ctx(ctx)
				logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str(fieldKey, id.String())
				})
			}
			if headerName != "" {
				w.Header().Set(headerName, id.String())
			}
			next.ServeHTTP(w, req)
		})
	}
}

// urlHandler is similar to hlog.urlHandler, but it adds path and separate query string fields.
// It should be after the parseForm middleware as it uses req.Form.
func urlHandler(pathKey, queryKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			logger := zerolog.Ctx(req.Context())
			logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
				c = c.Str(pathKey, req.URL.Path)
				if len(req.Form) > 0 {
					c = logValues(c, queryKey, req.Form)
				}
				return c
			})
			next.ServeHTTP(w, req)
		})
	}
}

func etagHandler(fieldKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req)
			etag := w.Header().Get("Etag")
			if etag != "" {
				etag = strings.ReplaceAll(etag, `"`, "")
				logger := zerolog.Ctx(req.Context())
				logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str(fieldKey, etag)
				})
			}
		})
	}
}

func contentEncodingHandler(fieldKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req)
			contentEncoding := w.Header().Get("Content-Encoding")
			if contentEncoding != "" {
				logger := zerolog.Ctx(req.Context())
				logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str(fieldKey, contentEncoding)
				})
			}
		})
	}
}

// accessHandler is similar to hlog.accessHandler, but it uses github.com/felixge/httpsnoop.
// See: https://github.com/rs/zerolog/issues/417
// Afterwards, it was extended with Server-Timing trailer.
func accessHandler(f func(req *http.Request, code int, size int64, duration time.Duration)) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Trailer", servertiming.HeaderKey)
			// We initialize Metrics ourselves so that if Code is never set it is logged as zero.
			// This allows one to detect calls which has been canceled early and websocket upgrades.
			// See: https://github.com/felixge/httpsnoop/issues/17
			m := httpsnoop.Metrics{}
			m.CaptureMetrics(w, func(ww http.ResponseWriter) {
				next.ServeHTTP(ww, req)
			})
			milliseconds := float64(m.Duration) / float64(time.Millisecond)
			w.Header().Set(servertiming.HeaderKey, fmt.Sprintf("t;dur=%.1f", milliseconds))
			f(req, m.Code, m.Written, m.Duration)
		})
	}
}

// removeMetadataHeaders removes metadata headers in a response
// if the response is 304 Not Modified because clients will then use the cached
// version of the response (and metadata headers there). This works because metadata
// headers are included in the Etag, so 304 Not Modified means that metadata headers
// have not changed either.
func removeMetadataHeaders(metadataHeaderPrefix string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(httpsnoop.Wrap(w, httpsnoop.Hooks{
				WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
					return func(code int) {
						if code == http.StatusNotModified {
							headers := w.Header()
							for header := range headers {
								if strings.HasPrefix(strings.ToLower(header), metadataHeaderPrefix) {
									headers.Del(header)
								}
							}
						}
						next(code)
					}
				},
			}), req)
		})
	}
}

// websocketHandler records metrics about a websocket.
func websocketHandler(fieldKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var websocket bool
			var read int64
			var written int64
			next.ServeHTTP(httpsnoop.Wrap(w, httpsnoop.Hooks{
				Hijack: func(next httpsnoop.HijackFunc) httpsnoop.HijackFunc {
					return func() (net.Conn, *bufio.ReadWriter, error) {
						conn, bufrw, err := next()
						if err != nil {
							return conn, bufrw, err
						}
						websocket = true
						return &metricsConn{
							Conn:    conn,
							read:    &read,
							written: &written,
						}, bufrw, err
					}
				},
			}), req)
			if websocket {
				logger := zerolog.Ctx(req.Context())
				logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
					data := zerolog.Dict()
					data.Int64("fromClient", read)
					data.Int64("toClient", written)
					return c.Dict(fieldKey, data)
				})
			}
		})
	}
}

func (s *Service[SiteT]) parseForm(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		err := req.ParseForm()
		if err != nil {
			s.BadRequestWithError(w, req, errors.WithMessage(err, "error parsing form"))
			return
		}
		next.ServeHTTP(w, req)
	})
}
