package waf

import (
	"bufio"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/justinas/alice"
	servertiming "github.com/mitchellh/go-server-timing"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"

	"gitlab.com/tozd/identifier"
)

//go:embed routes.json
var routesConfiguration []byte

//go:embed dist
var distFiles embed.FS

type routes struct {
	Routes []struct {
		Name string `json:"name"`
		Path string `json:"path"`
		API  bool   `json:"api,omitempty"`
		Get  bool   `json:"get,omitempty"`
	} `json:"routes"`
}

type Site struct {
	Domain   string `json:"domain"         yaml:"domain"`
	Title    string `json:"title"          yaml:"title"`
	CertFile string `json:"cert,omitempty" yaml:"cert,omitempty"`
	KeyFile  string `json:"key,omitempty"  yaml:"key,omitempty"`

	// Maps between content types, paths, and content/etags.
	// They are per site because they can include rendered per-site content.
	compressedFiles      map[string]map[string][]byte
	compressedFilesEtags map[string]map[string]string
}

type Service struct {
	Logger         zerolog.Logger
	Sites          map[string]Site
	Version        string
	BuildTimestamp string
	Revision       string
	Router         *Router

	// It should be kept all lower case so that it is easier to
	// compare against in the case insensitive manner.
	MetadataHeaderPrefix string

	reverseProxy *httputil.ReverseProxy
}

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
					c = logValues(c, "query", req.Form)
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

func logHandlerName(name string, h Handler) Handler {
	if name == "" {
		return h
	}

	return func(w http.ResponseWriter, req *http.Request, params Params) {
		logger := zerolog.Ctx(req.Context())
		logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Str(zerolog.MessageFieldName, name)
		})
		h(w, req, params)
	}
}

func autoName(h Handler) string {
	fn := runtime.FuncForPC(reflect.ValueOf(h).Pointer())
	if fn == nil {
		return ""
	}
	name := fn.Name()
	i := strings.LastIndex(name, ".")
	if i != -1 {
		name = name[i+1:]
	}
	name = strings.TrimSuffix(name, "-fm")
	return name
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

// TODO: Move to Router struct, accepting interface{} as an object on which to search for handlers.

func (s *Service) configureRoutes(router *Router) errors.E {
	var rs routes
	errE := x.UnmarshalWithoutUnknownFields(routesConfiguration, &rs)
	if errE != nil {
		return errE
	}

	v := reflect.ValueOf(s)

	for _, route := range rs.Routes {
		if !route.Get && !route.API {
			errE := errors.New(`at least one of "get" and "api" has to be true`)
			errors.Details(errE)["name"] = route.Name
			errors.Details(errE)["path"] = route.Path
			return errE
		}

		if route.Get {
			handlerName := route.Name
			m := v.MethodByName(handlerName)
			if !m.IsValid() {
				errE := errors.New("handler not found")
				errors.Details(errE)["handler"] = handlerName
				errors.Details(errE)["name"] = route.Name
				errors.Details(errE)["path"] = route.Path
				return errE
			}
			s.Logger.Debug().Str("handler", handlerName).Str("name", route.Name).Str("path", route.Path).Msg("route registration: handler found")
			// We cannot use Handler here because it is a named type.
			h, ok := m.Interface().(func(http.ResponseWriter, *http.Request, Params))
			if !ok {
				errE := errors.Errorf("invalid route handler type: %T", m.Interface())
				errors.Details(errE)["handler"] = handlerName
				errors.Details(errE)["name"] = route.Name
				errors.Details(errE)["path"] = route.Path
				return errE
			}
			h = logHandlerName(handlerName, h)
			errE := router.Handle(route.Name, http.MethodGet, route.Path, false, h)
			if errE != nil {
				errors.Details(errE)["handler"] = handlerName
				errors.Details(errE)["name"] = route.Name
				errors.Details(errE)["path"] = route.Path
				return errE
			}
		}
		if route.API {
			foundAnyAPIHandler := false
			// MethodHead is handled by MethodGet handled.
			for _, method := range []string{
				http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch,
				http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace,
			} {
				handlerName := fmt.Sprintf("%sAPI%s", route.Name, strings.Title(strings.ToLower(method))) //nolint:staticcheck
				m := v.MethodByName(handlerName)
				if !m.IsValid() {
					s.Logger.Debug().Str("handler", handlerName).Str("name", route.Name).Str("path", route.Path).Msg("route registration: API handler not found")
					continue
				}
				s.Logger.Debug().Str("handler", handlerName).Str("name", route.Name).Str("path", route.Path).Msg("route registration: API handler found")
				foundAnyAPIHandler = true
				// We cannot use Handler here because it is a named type.
				h, ok := m.Interface().(func(http.ResponseWriter, *http.Request, Params))
				if !ok {
					errE := errors.Errorf("invalid route handler type: %T", m.Interface())
					errors.Details(errE)["handler"] = handlerName
					errors.Details(errE)["name"] = route.Name
					errors.Details(errE)["path"] = route.Path
					return errE
				}
				h = logHandlerName(handlerName, h)
				errE := router.Handle(route.Name, method, route.Path, true, h)
				if errE != nil {
					errors.Details(errE)["handler"] = handlerName
					errors.Details(errE)["name"] = route.Name
					errors.Details(errE)["path"] = route.Path
					return errE
				}
				if method == http.MethodGet {
					errE := router.Handle(route.Name, http.MethodHead, route.Path, true, h)
					if errE != nil {
						errors.Details(errE)["handler"] = handlerName
						errors.Details(errE)["name"] = route.Name
						errors.Details(errE)["path"] = route.Path
						return errE
					}
				}
			}
			if !foundAnyAPIHandler {
				errE := errors.Errorf("no route API handler found")
				errors.Details(errE)["name"] = route.Name
				errors.Details(errE)["path"] = route.Path
				return errE
			}
		}
	}

	return nil
}

func (s *Service) RouteWith(router *Router, development string) (http.Handler, errors.E) {
	if s.Router != nil {
		panic(errors.New("RouteWith called more than once"))
	}
	s.Router = router

	errE := s.configureRoutes(router)
	if errE != nil {
		return nil, errE
	}

	if development != "" {
		errE := s.renderAndCompressContext()
		if errE != nil {
			return nil, errE
		}
		errE = s.computeEtags()
		if errE != nil {
			return nil, errE
		}
		errE = s.makeReverseProxy(development)
		if errE != nil {
			return nil, errE
		}
		router.NotFound = logHandlerName(autoName(s.Proxy), s.Proxy)
		router.MethodNotAllowed = logHandlerName(autoName(s.Proxy), s.Proxy)
		router.NotAcceptable = logHandlerName(autoName(s.Proxy), s.Proxy)
	} else {
		errE := s.renderAndCompressFiles()
		if errE != nil {
			return nil, errE
		}
		errE = s.renderAndCompressContext()
		if errE != nil {
			return nil, errE
		}
		errE = s.computeEtags()
		if errE != nil {
			return nil, errE
		}
		errE = s.serveStaticFiles(router)
		if errE != nil {
			return nil, errE
		}
		router.NotFound = logHandlerName(autoName(s.NotFound), s.NotFound)
		router.MethodNotAllowed = logHandlerName(autoName(s.MethodNotAllowed), s.MethodNotAllowed)
		router.NotAcceptable = logHandlerName(autoName(s.NotAcceptable), s.NotAcceptable)
	}
	router.Panic = s.handlePanic

	c := alice.New()

	c = c.Append(hlog.NewHandler(s.Logger))
	// It has to be before accessHandler so that it can access the timing context.
	c = c.Append(func(next http.Handler) http.Handler {
		return servertiming.Middleware(next, nil)
	})
	c = c.Append(accessHandler(func(req *http.Request, code int, size int64, duration time.Duration) {
		level := zerolog.InfoLevel
		if code >= http.StatusBadRequest {
			level = zerolog.WarnLevel
		}
		if code >= http.StatusInternalServerError {
			level = zerolog.ErrorLevel
		}
		timing := servertiming.FromContext(req.Context())
		metrics := zerolog.Dict()
		for _, metric := range timing.Metrics {
			metrics.Dur(metric.Name, metric.Duration)
		}
		metrics.Dur("t", duration)
		l := zerolog.Ctx(req.Context()).WithLevel(level)
		if s.Version != "" {
			l = l.Str("version", s.Version)
		}
		if s.BuildTimestamp != "" {
			l = l.Str("buildTimestamp", s.BuildTimestamp)
		}
		if s.Revision != "" {
			l = l.Str("revision", s.Revision)
		}
		if code != 0 {
			l = l.Int("code", code)
		}
		l.Int64("size", size).
			Dict("metrics", metrics).
			Send()
	}))
	c = c.Append(removeMetadataHeaders(s.MetadataHeaderPrefix))
	c = c.Append(websocketHandler("ws"))
	c = c.Append(hlog.MethodHandler("method"))
	c = c.Append(remoteAddrHandler("client"))
	c = c.Append(hlog.UserAgentHandler("agent"))
	c = c.Append(hlog.RefererHandler("referer"))
	c = c.Append(connectionIDHandler("connection"))
	c = c.Append(requestIDHandler("request", "Request-ID"))
	c = c.Append(protocolHandler("proto"))
	c = c.Append(hostHandler("host"))
	c = c.Append(etagHandler("etag"))
	c = c.Append(contentEncodingHandler("encoding"))
	// parseForm should be as late as possible because it can fail
	// and we want other fields to be logged.
	c = c.Append(s.parseForm)
	// URLHandler should be after the parseForm middleware.
	c = c.Append(urlHandler("path", "query"))

	return c.Then(router), nil
}

func (s *Service) renderAndCompressFiles() errors.E {
	for domain, site := range s.Sites {
		if site.compressedFiles != nil {
			return errors.New("renderAndCompressFiles called more than once")
		}

		site.compressedFiles = make(map[string]map[string][]byte)

		for _, compression := range allCompressions {
			site.compressedFiles[compression] = make(map[string][]byte)

			err := fs.WalkDir(distFiles, "dist", func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return errors.WithStack(err)
				}
				if d.IsDir() {
					return nil
				}

				data, err := distFiles.ReadFile(path)
				if err != nil {
					return errors.WithStack(err)
				}
				path = strings.TrimPrefix(path, "dist")

				var errE errors.E
				if strings.HasSuffix(path, ".html") {
					data, errE = s.render(path, data, site)
					if errE != nil {
						return errE
					}
				}

				data, errE = compress(compression, data)
				if errE != nil {
					return errE
				}

				site.compressedFiles[compression][path] = data
				return nil
			})
			if err != nil {
				return errors.WithStack(err)
			}
		}

		// Map cannot be modified directly, so we modify the copy
		// and store it back into the map.
		s.Sites[domain] = site
	}

	return nil
}

func (s *Service) renderAndCompressContext() errors.E {
	for domain, site := range s.Sites {
		// In development, this method could be called first and compressedFiles are not yet
		// initialized (as requests for other files are proxied to Vite), while in production
		// compressedFiles has already been initialized and populated by built static files.
		if site.compressedFiles == nil {
			site.compressedFiles = make(map[string]map[string][]byte)
		}

		for _, compression := range allCompressions {
			if _, ok := site.compressedFiles[compression]; !ok {
				site.compressedFiles[compression] = make(map[string][]byte)
			}

			data, errE := x.MarshalWithoutEscapeHTML(s.getSiteContext(site))
			if errE != nil {
				return errE
			}

			data, errE = compress(compression, data)
			if errE != nil {
				return errE
			}

			site.compressedFiles[compression]["/index.json"] = data
		}

		// Map cannot be modified directly, so we modify the copy
		// and store it back into the map.
		s.Sites[domain] = site
	}

	return nil
}

func (s *Service) computeEtags() errors.E {
	for domain, site := range s.Sites {
		if site.compressedFilesEtags != nil {
			return errors.New("computeEtags called more than once")
		}

		site.compressedFilesEtags = make(map[string]map[string]string)

		for compression, files := range site.compressedFiles {
			site.compressedFilesEtags[compression] = make(map[string]string)

			for path, data := range files {
				hash := sha256.New()
				_, _ = hash.Write(data)
				etag := `"` + base64.RawURLEncoding.EncodeToString(hash.Sum(nil)) + `"`
				site.compressedFilesEtags[compression][path] = etag
			}
		}

		// Map cannot be modified directly, so we modify the copy
		// and store it back into the map.
		s.Sites[domain] = site
	}

	return nil
}

type siteContext struct {
	Site           Site   `json:"site"`
	Version        string `json:"version,omitempty"`
	BuildTimestamp string `json:"buildTimestamp,omitempty"`
	Revision       string `json:"revision,omitempty"`
}

func (s *Service) getSiteContext(site Site) siteContext {
	return siteContext{
		Site:           site,
		Version:        s.Version,
		BuildTimestamp: s.BuildTimestamp,
		Revision:       s.Revision,
	}
}

func (s *Service) getSite(req *http.Request) (Site, errors.E) {
	if site, ok := s.Sites[req.Host]; req.Host != "" && ok {
		return site, nil
	}
	return Site{}, errors.Errorf(`site not found for host "%s"`, req.Host)
}
