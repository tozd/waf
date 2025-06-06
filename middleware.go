package waf

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/felixge/httpsnoop"
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

// requestIDHandler is similar to hlog.RequestIDHandler, but uses identifier.NewRandom() for ID.
//
// It does not set headerName header on 304 responses.
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
				headerWritten := false
				headers := w.Header()
				defer func() {
					if !headerWritten {
						headerWritten = true
						headers.Set(headerName, id.String())
					}
				}()
				w = httpsnoop.Wrap(w, httpsnoop.Hooks{ //nolint:exhaustruct
					WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
						return func(code int) {
							headerWritten = true
							if code != http.StatusNotModified {
								headers.Set(headerName, id.String())
							}
							next(code)
						}
					},
					Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
						return func(b []byte) (int, error) {
							if !headerWritten {
								// Calling Write without WriteHeader is the same as first
								// calling WriteHeader(http.StatusOK), so we set the header.
								headerWritten = true
								headers.Set(headerName, id.String())
							}
							return next(b)
						}
					},
				})
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

// accessHandler is similar to hlog.accessHandler, but it uses github.com/felixge/httpsnoop
// and counts bytes read from the body.
// See: https://github.com/rs/zerolog/issues/417
// See: https://github.com/rs/zerolog/pull/562
func accessHandler(f func(req *http.Request, code int, responseBody, requestBody int64, duration time.Duration)) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
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
			// We use a closure so that m is accessed when function closure runs.
			defer func() { f(req, m.Code, m.Written, body.(interface{ BytesRead() int64 }).BytesRead(), m.Duration) }() //nolint:forcetypeassert,errcheck
			m.CaptureMetrics(w, func(w http.ResponseWriter) {
				next.ServeHTTP(w, req)
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
			defer func() { //nolint:contextcheck
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
func websocketHandler(fieldKeyPrefix string) func(next http.Handler) http.Handler {
	fromClient := "fromClient"
	toClient := "toClient"
	if fieldKeyPrefix != "" {
		fromClient = fieldKeyPrefix + "FromClient"
		toClient = fieldKeyPrefix + "ToClient"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var nc net.Conn
			buffered := 0
			defer func() {
				if nc != nil {
					logger := hlog.FromRequest(req)
					logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
						c = c.Int64(fromClient, nc.(interface{ BytesRead() int64 }).BytesRead())                     //nolint:forcetypeassert,errcheck
						c = c.Int64(toClient, int64(buffered)+nc.(interface{ BytesWritten() int64 }).BytesWritten()) //nolint:forcetypeassert,errcheck
						return c
					})
				}
			}()
			next.ServeHTTP(httpsnoop.Wrap(w, httpsnoop.Hooks{ //nolint:exhaustruct
				Hijack: func(next httpsnoop.HijackFunc) httpsnoop.HijackFunc {
					return func() (net.Conn, *bufio.ReadWriter, error) {
						conn, bufrw, err := next()
						if err != nil {
							return conn, bufrw, errors.WithStack(err)
						}
						// We first make sure anything pending to write is flushed
						// (and we count bytes we flushed).
						buffered = bufrw.Writer.Buffered()
						err = bufrw.Writer.Flush()
						if err != nil {
							return conn, bufrw, errors.WithStack(err)
						}
						// We wrap the connection so that we can count bytes read and written.
						nc = newCounterConn(conn)
						// And we set it as underlying writer so that writing to the buffer
						// goes to our wrapped connection and not the original connection.
						bufrw.Writer.Reset(nc)
						// We read any buffered data pending reading.
						b, _ := bufrw.Reader.Peek(bufrw.Reader.Buffered())
						// We count bytes buffered.
						buffered += len(b)
						// And then we set the underlying reader with our wrapped connection
						// with buffered data prefixed.
						bufrw.Reader.Reset(io.MultiReader(bytes.NewReader(b), nc))
						return nc, bufrw, nil
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
			// We set the message to the name of the middleware so that
			// it is logged in the case of an error.
			*canonicalLoggerMessage(req.Context()) = "ParseForm"

			// TODO: Add limits on max time, max idle time, min speed, and max data for
			//       reading the whole body when parsing form. If a limit is reached, context
			//       should be canceled.
			postErr := parsePostForm(req)
			if postFormParsed(req) {
				// We parsed PostForm so we know we consumed the body and we can close it.
				// This can make errors visible sooner if a handler attempts to read it again.
				// We first still attempt to discard anything left in the body (an error might
				// prevent the body from being fully read).
				io.Copy(io.Discard, req.Body) //nolint:errcheck
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
					s.TemporaryRedirectSameMethod(w, req, req.URL.String())
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
		// We set the message to the name of the middleware so that
		// it is logged in the case of an error.
		*canonicalLoggerMessage(req.Context()) = "ValidatePath"

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
			s.TemporaryRedirectSameMethod(w, req, req.URL.String())
			return
		}

		next.ServeHTTP(w, req)
	})
}

// validateSite checks that host matches a known site. If site is found, it is
// set in context.
func (s *Service[SiteT]) validateSite(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// We set the message to the name of the middleware so that
		// it is logged in the case of an error.
		*canonicalLoggerMessage(req.Context()) = "ValidateSite"

		siteT, err := s.site(req)
		if err != nil {
			s.WithError(req.Context(), err)
			s.NotFound(w, req)
			return
		}

		ctx := context.WithValue(req.Context(), siteContextKey, siteT)
		req = req.WithContext(ctx)

		next.ServeHTTP(w, req)
	})
}

// setCanonicalLogger sets context logger under canonical logger context key as well.
// It also adds message for the canonical log line to the context.
func setCanonicalLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		l := zerolog.Ctx(ctx)
		ctx = context.WithValue(ctx, canonicalLoggerContextKey, l)
		var message string
		ctx = context.WithValue(ctx, canonicalLoggerMessageContextKey, &message)
		req = req.WithContext(ctx)
		next.ServeHTTP(w, req)
	})
}

// addNosniffHeader sets nosniff header on all responses except 304 responses.
func addNosniffHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		headerWritten := false
		defer func() {
			if !headerWritten {
				headerWritten = true
				w.Header().Set("X-Content-Type-Options", "nosniff")
			}
		}()
		next.ServeHTTP(httpsnoop.Wrap(w, httpsnoop.Hooks{ //nolint:exhaustruct
			WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
				return func(code int) {
					headerWritten = true
					if code != http.StatusNotModified {
						w.Header().Set("X-Content-Type-Options", "nosniff")
					}
					next(code)
				}
			},
			Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
				return func(b []byte) (int, error) {
					if !headerWritten {
						// Calling Write without WriteHeader is the same as first
						// calling WriteHeader(http.StatusOK), so we set the header.
						headerWritten = true
						w.Header().Set("X-Content-Type-Options", "nosniff")
					}
					return next(b)
				}
			},
		}), req)
	})
}

// RedirectToMainSite is a middleware which redirects all requests to the site with mainDomain
// if they are made for another site on non-main domain.
func (s *Service[SiteT]) RedirectToMainSite(mainDomain string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// We set the message to the name of the middleware so that
			// it is logged in the case of an error.
			*canonicalLoggerMessage(req.Context()) = "RedirectToMainSite"

			// We can use MustGetSite because this middleware is used after validateSite middleware.
			site := MustGetSite[*Site](req.Context())
			if site.Domain != mainDomain {
				req.URL.Scheme = "https"
				_, port, err := net.SplitHostPort(req.Host)
				if err != nil && !strings.Contains(err.Error(), "missing port in address") {
					// This probably cannot be reached because validateSite short-circuits bad
					// host values (which probably do not match any site) with an 404.
					s.BadRequestWithError(w, req, errors.WithStack(err))
					return
				}
				if port != "" {
					req.URL.Host = net.JoinHostPort(mainDomain, port)
				} else {
					req.URL.Host = mainDomain
				}
				s.TemporaryRedirectSameMethod(w, req, req.URL.String())
				return
			}
			next.ServeHTTP(w, req)
		})
	}
}

// metricsMiddleware add metrics to the context and on HTTP2 adds Server-Timing trailer to
// responses (unless a response is 304 Not Modified).
//
// It uses a trailer for all metrics to simplify the logic. Otherwise we could issue
// completed durations when headers are written (but cannot counters because we do not
// know when they have finished counting and some could continue counting even after
// headers are written in the request handler, e.g., in defer) and the rest of metrics
// in a trailer. But it does not seem worth making the logic (and ServerTimingString method
// to support this) more complicated.
func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		metrics := NewMetrics()
		req = req.WithContext(context.WithValue(req.Context(), metricsContextKey, metrics))
		addTrailer := true
		defer func() {
			// Trailers are added only on HTTP2 so that we are not required to use chunked transport encoding
			// with HTTP1.1 to support trailers (which conflicts with us setting Content-Length response header).
			if req.ProtoMajor > 1 && addTrailer {
				t := metrics.ServerTimingString()
				if t != "" {
					// This writes the trailer.
					w.Header().Set(http.TrailerPrefix+serverTimingHeader, t)
				}
			}
		}()
		next.ServeHTTP(httpsnoop.Wrap(w, httpsnoop.Hooks{ //nolint:exhaustruct
			WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
				return func(code int) {
					// We add trailers only when status is not 304.
					if code == http.StatusNotModified {
						addTrailer = false
					}
					next(code)
				}
			},
		}), req)
	})
}
