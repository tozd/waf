package waf

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/felixge/httpsnoop"
	servertiming "github.com/mitchellh/go-server-timing"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
)

func connectionIDHandler(fieldKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			id, ok := req.Context().Value(connectionIDContextKey).(identifier.Identifier)
			if ok {
				logger := hlog.FromRequest(req)
				logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str(fieldKey, id.String())
				})
			}
			next.ServeHTTP(w, req)
		})
	}
}

// httpVersionHandler is similar to hlog.ProtoHandler, but it does not store the "HTTP/"
// prefix in the protocol name.
func httpVersionHandler(fieldKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			proto := strings.TrimPrefix(req.Proto, "HTTP/")
			logger := hlog.FromRequest(req)
			logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
				return c.Str(fieldKey, proto)
			})
			next.ServeHTTP(w, req)
		})
	}
}

// remoteAddrHandler is similar to hlog.RemoteAddrHandler, but logs only an IP, not a port.
func remoteAddrHandler(fieldKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ip := getHost(req.RemoteAddr)
			if ip != "" {
				logger := hlog.FromRequest(req)
				logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str(fieldKey, ip)
				})
			}
			next.ServeHTTP(w, req)
		})
	}
}

// hostHandler is similar to hlog.HostHandler, but it does not log the port.
func hostHandler(fieldKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			host := getHost(req.Host)
			if host != "" {
				logger := hlog.FromRequest(req)
				logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str(fieldKey, host)
				})
			}
			next.ServeHTTP(w, req)
		})
	}
}

// requestIDHandler is similar to hlog.RequestIDHandler, but uses identifier.NewRandom() for ID.
func requestIDHandler(fieldKey, headerName string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := req.Context()
			id, ok := ctx.Value(requestIDContextKey).(identifier.Identifier)
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

// urlHandler is similar to hlog.UrlHandler, but it logs only URL path.
// Query string is logged in parseForm.
func urlHandler(pathKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			logger := hlog.FromRequest(req)
			logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
				return c.Str(pathKey, req.URL.Path)
			})
			next.ServeHTTP(w, req)
		})
	}
}

func etagHandler(fieldKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			defer func() {
				etag := w.Header().Get("Etag")
				if etag != "" {
					etag = strings.ReplaceAll(etag, `"`, "")
					logger := hlog.FromRequest(req)
					logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
						return c.Str(fieldKey, etag)
					})
				}
			}()
			next.ServeHTTP(w, req)
		})
	}
}

func responseHeaderHandler(fieldKey, headerName string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			defer func() {
				value := w.Header().Get(headerName)
				if value != "" {
					logger := hlog.FromRequest(req)
					logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
						return c.Str(fieldKey, value)
					})
				}
			}()
			next.ServeHTTP(w, req)
		})
	}
}

// accessHandler is similar to hlog.accessHandler, but it uses github.com/felixge/httpsnoop.
// See: https://github.com/rs/zerolog/issues/417
// Afterwards, it was extended with Server-Timing trailer and counting of bytes read from the body.
// See: https://github.com/rs/zerolog/pull/562
// Trailers are added only on HTTP2 so that we are not required to use chunked transport encoding
// with HTTP1.1 to support trailers (which conflicts with us setting Content-Length response header).
func accessHandler(f func(req *http.Request, code int, responseBody, requestBody int64, duration time.Duration)) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// We use trailers only with http2.
			if req.ProtoMajor > 1 {
				w.Header().Set("Trailer", servertiming.HeaderKey)
			}
			// We initialize Metrics ourselves so that if Code is never set it is logged as zero.
			// This allows one to detect calls which has been canceled early and websocket upgrades.
			// See: https://github.com/felixge/httpsnoop/issues/17
			m := httpsnoop.Metrics{
				Code:     0,
				Duration: 0,
				Written:  0,
			}
			body := newCounterReadCloser(req.Body)
			req.Body = body
			defer func() {
				// We use trailers only with http2.
				if req.ProtoMajor > 1 {
					milliseconds := float64(m.Duration) / float64(time.Millisecond)
					// This writes the trailer.
					w.Header().Set(servertiming.HeaderKey, fmt.Sprintf("t;dur=%.1f", milliseconds))
				}
				f(req, m.Code, m.Written, body.(interface{ BytesRead() int64 }).BytesRead(), m.Duration) //nolint:forcetypeassert
			}()
			m.CaptureMetrics(w, func(ww http.ResponseWriter) {
				next.ServeHTTP(ww, req)
			})
		})
	}
}

// logMetadata logs metadata added to the response based on metadata accumulated in the context.
//
// It removes metadata from the response and does not log metadata if the
// response is 304 Not Modified because clients will then use the cached
// version of the response (and metadata header there). This works because metadata
// header is included in the Etag, so 304 Not Modified means that metadata header
// has not changed either.
func logMetadata(metadataHeaderPrefix string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			metadata := map[string]interface{}{}
			req = req.WithContext(context.WithValue(req.Context(), metadataContextKey, metadata))
			logMetadata := true
			defer func() {
				if logMetadata && len(metadata) > 0 {
					logger := canonicalLogger(req.Context())
					logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
						return c.Interface("metadata", metadata)
					})
				}
			}()
			next.ServeHTTP(httpsnoop.Wrap(w, httpsnoop.Hooks{ //nolint:exhaustruct
				WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
					return func(code int) {
						if code == http.StatusNotModified {
							logMetadata = false
							w.Header().Del(metadataHeaderPrefix + metadataHeader)
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
			var nc net.Conn
			defer func() {
				if nc != nil {
					logger := hlog.FromRequest(req)
					logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
						data := zerolog.Dict()
						data.Int64("fromClient", nc.(interface{ BytesRead() int64 }).BytesRead())     //nolint:forcetypeassert
						data.Int64("toClient", nc.(interface{ BytesWritten() int64 }).BytesWritten()) //nolint:forcetypeassert
						return c.Dict(fieldKey, data)
					})
				}
			}()
			next.ServeHTTP(httpsnoop.Wrap(w, httpsnoop.Hooks{ //nolint:exhaustruct
				Hijack: func(next httpsnoop.HijackFunc) httpsnoop.HijackFunc {
					return func() (net.Conn, *bufio.ReadWriter, error) {
						conn, bufrw, err := next()
						if err != nil {
							return conn, bufrw, err
						}
						nc = newCounterConn(conn)
						return nc, bufrw, err
					}
				},
			}), req)
		})
	}
}

// parseForm parses POST form and query string in a manner equivalent with
// http.Request's PostForm method, and logs parsed query string
// with queryKey field if query string parsing is successful, or raw query
// string with rawQueryKey field otherwise. After successful query string
// parsing, it checks that provided query string is canonical, i.e., that
// service's router's EncodeQuery encodes it in the same way. If not, it
// redirects to that canonical URL.
func (s *Service[SiteT]) parseForm(queryKey, rawQueryKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// TODO: Add limits on max time, max idle time, min speed, and max data for
			//       reading the whole body when parsing form. If a limit is reached, context
			//       should be canceled.
			postErr := parsePostForm(req)
			if postFormParsed(req) {
				// We parsed PostForm so we know we consumed the body and we can close it.
				// This can make errors visible sooner if a handler attempts to read it again.
				req.Body.Close()
			}
			queryForm, queryErr := getQueryForm(req)
			if queryErr != nil {
				if len(req.URL.RawQuery) > 0 {
					logger := hlog.FromRequest(req)
					logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
						return c.Str(rawQueryKey, req.URL.RawQuery)
					})
				}
			} else if len(queryForm) > 0 {
				logger := hlog.FromRequest(req)
				logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return logValues(c, queryKey, queryForm)
				})
			}

			// Based on ParseForm method from net/http/request.go.
			if req.Form == nil {
				if len(req.PostForm) > 0 {
					req.Form = make(url.Values)
					copyValues(req.Form, req.PostForm)
				}
				if queryForm == nil {
					queryForm = make(url.Values)
				}
				if req.Form == nil {
					req.Form = queryForm
				} else {
					copyValues(req.Form, queryForm)
				}
			}

			err := errors.Join(
				errors.WithMessage(postErr, "error parsing POST form"),
				errors.WithMessage(queryErr, "error parsing query string"),
			)
			if err != nil {
				s.BadRequestWithError(w, req, err)
				return
			}

			if len(queryForm) > 0 {
				var qs string
				if s.router.EncodeQuery != nil {
					qs = s.router.EncodeQuery(queryForm)
				} else {
					qs = queryForm.Encode()
				}
				if qs != req.URL.RawQuery {
					req.URL.RawQuery = qs
					s.TemporaryRedirect(w, req, req.URL.String())
					return
				}
			}

			next.ServeHTTP(w, req)
		})
	}
}

// validatePath checks that path does not contain non-printable characters.
// It also checks that the path is canonical. If not, it redirects to that
// canonical URL.
func (s *Service[SiteT]) validatePath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Check URL path for non-printable characters.
		// Copied from https://github.com/hashicorp/go-cleanhttp/blob/master/handlers.go.
		idx := strings.IndexFunc(req.URL.Path, func(c rune) bool {
			return !unicode.IsPrint(c)
		})
		if idx != -1 {
			s.BadRequest(w, req)
			return
		}

		// Check canonical path.
		path := cleanPath(req.URL.Path)
		if path != req.URL.Path {
			req.URL.Path = path
			s.TemporaryRedirect(w, req, req.URL.String())
			return
		}

		next.ServeHTTP(w, req)
	})
}

// validateSite checks that host matches a known site. If site is found, it is
// set in context.
func (s *Service[SiteT]) validateSite(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		siteT, err := s.site(req)
		if err != nil {
			s.NotFoundWithError(w, req, err)
			return
		}

		ctx := context.WithValue(req.Context(), siteContextKey, siteT)
		req = req.WithContext(ctx)

		next.ServeHTTP(w, req)
	})
}

// setCanonicalLogger sets context logger under canonical logger context key as well.
func setCanonicalLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		l := zerolog.Ctx(ctx)
		ctx = context.WithValue(ctx, canonicalLoggerContextKey, l)
		req = req.WithContext(ctx)
		next.ServeHTTP(w, req)
	})
}

// addNosniffHeader sets nosniff header on all responses.
func addNosniffHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, req)
	})
}
