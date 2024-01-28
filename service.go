package waf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/justinas/alice"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	servertiming "github.com/tozd/go-server-timing"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	z "gitlab.com/tozd/go/zerolog"
)

// TODO: Use cors.Options directly once it has JSON struct tags.
//       See: https://github.com/rs/cors/pull/164

// CorsOptions is a subset of cors.Options.
//
// See description of fields in cors.Options.
type CorsOptions struct {
	AllowedOrigins       []string `json:"allowedOrigins,omitempty"`
	AllowedMethods       []string `json:"allowedMethods,omitempty"`
	AllowedHeaders       []string `json:"allowedHeaders,omitempty"`
	ExposedHeaders       []string `json:"exposedHeaders,omitempty"`
	MaxAge               int      `json:"maxAge,omitempty"`
	AllowCredentials     bool     `json:"allowCredentials,omitempty"`
	AllowPrivateNetwork  bool     `json:"allowPrivateNetwork,omitempty"`
	OptionsSuccessStatus int      `json:"optionsSuccessStatus,omitempty"`
}

func (c *CorsOptions) GetAllowedMethods() []string {
	allowedMethods := []string{}
	hasGet := false
	hasHead := false
	for _, method := range c.AllowedMethods {
		method := strings.ToUpper(method)
		allowedMethods = append(allowedMethods, method)
		if method == "GET" {
			hasGet = true
		} else if method == "HEAD" {
			hasHead = true
		}
	}

	if hasGet && !hasHead {
		allowedMethods = append(allowedMethods, "HEAD")
	}

	sort.Strings(allowedMethods)

	return allowedMethods
}

// Route is a high-level route definition which is used by a service
// to register handlers with the router. It can also be used by Vue Router
// to register routes there.
type Route struct {
	// Name of the route. It should be unique.
	Name string `json:"name"`

	// Path for the route. It can contain parameters.
	Path string `json:"path"`

	// Does this route support API handlers.
	// API paths are automatically prefixed with /api.
	API bool `json:"api,omitempty"`

	// Does this route have a non-API handler.
	Get bool `json:"get,omitempty"`

	// Enable CORS on API handlers?
	APICors *CorsOptions `json:"apiCors,omitempty"`

	// Enable CORS on non-API handler?
	GetCors *CorsOptions `json:"getCors,omitempty"`
}

type staticFile struct {
	Data      []byte
	Etag      string
	MediaType string
}

// Site describes the site at a domain.
//
// A service can have multiple sites which share static files and handlers,
// but have different configuration and rendered HTML files. Core
// such configuration is site's domain, but you can provide your own
// site struct and embed Site to add additional configuration.
// Your site struct is then used when rendering HTML files and
// as site context to the frontend at SiteContextPath URL path.
//
// Certificate and key file paths are not exposed in site context JSON.
type Site struct {
	Domain string `json:"domain" yaml:"domain"`

	// Certificate file path for the site. It should be valid for the domain.
	// Used when Let's Encrypt is not configured.
	CertFile string `json:"-" yaml:"cert,omitempty"`

	// Key file path. Used when Let's Encrypt is not configured.
	KeyFile string `json:"-" yaml:"key,omitempty"`

	// Maps between content types, paths, and data/etag/media type.
	// They are per site because they can include rendered per-site data.
	// File contents are deduplicated between sites if they are the same.
	staticFiles map[string]map[string]staticFile
}

// GetSite returns Site. This is used when you want to provide your own
// site struct to access the Site struct. If you embed Site inside your
// site struct then this method propagates to your site struct and does
// the right thing automatically.
func (s *Site) GetSite() *Site {
	return s
}

func (s *Site) initializeStaticFiles() {
	s.staticFiles = make(map[string]map[string]staticFile)

	for _, compression := range allCompressions {
		s.staticFiles[compression] = make(map[string]staticFile)
	}
}

func (s *Site) addStaticFile(path, mediaType string, data []byte) errors.E {
	if !strings.HasPrefix(path, "/") {
		errE := errors.New(`path does not start with "/"`)
		errors.Details(errE)["path"] = path
		return errE
	}

	_, ok := s.staticFiles[compressionIdentity][path]
	if ok {
		errE := errors.New(`static file for path already exists`)
		errors.Details(errE)["path"] = path
		return errE
	}

	compressions := allCompressions
	if len(data) <= minCompressionSize {
		compressions = []string{compressionIdentity}
	}

	for _, compression := range compressions {
		d, errE := compress(compression, data)
		if errE != nil {
			errors.Details(errE)["path"] = path
			return errE
		}

		// len(data) cannot be 0 for compression != compressionIdentity because
		// 0 <= minCompressionSize and only compressionIdentity is tried then.
		if compression != compressionIdentity && float64(len(d))/float64(len(data)) >= minCompressionRatio {
			// No need to compress noncompressible files.
			continue
		}

		s.staticFiles[compression][path] = staticFile{
			Data:      d,
			Etag:      computeEtag(d),
			MediaType: mediaType,
		}
	}

	return nil
}

type hasSite interface {
	GetSite() *Site
}

// We use a helper to create SiteT and a pointer to its internal Site
// to make it work with current Go type system limitations. Because we
// do not use this in critical paths, use of reflect seems reasonable.
//
// See: https://go.dev/play/p/j0GRRI96WMM
// See: https://github.com/golang/go/issues/63708
func newSiteT[SiteT hasSite]() (SiteT, *Site) { //nolint:ireturn
	typ := reflect.TypeOf((*SiteT)(nil)).Elem().Elem()
	st := reflect.New(typ).Interface().(SiteT) //nolint:forcetypeassert,errcheck
	site := st.GetSite()
	return st, site
}

func newCors(options *CorsOptions) *cors.Cors {
	if options == nil {
		return nil
	}

	return cors.New(cors.Options{ //nolint:exhaustruct
		AllowedOrigins:       options.AllowedOrigins,
		AllowedMethods:       options.GetAllowedMethods(),
		AllowedHeaders:       options.AllowedHeaders,
		ExposedHeaders:       options.ExposedHeaders,
		MaxAge:               options.MaxAge,
		AllowCredentials:     options.AllowCredentials,
		AllowPrivateNetwork:  options.AllowPrivateNetwork,
		OptionsSuccessStatus: options.OptionsSuccessStatus,
		// We always passthrough and call w.WriteHeader ourselves,
		// unless there is API OPTIONS handler which we then call instead.
		OptionsPassthrough: true,
	})
}

func wrapGetCors(options *CorsOptions, h func(http.ResponseWriter, *http.Request, Params)) (
	func(http.ResponseWriter, *http.Request, Params),
	func(http.ResponseWriter, *http.Request, Params),
) {
	c := newCors(options)
	optionsSuccessStatus := options.OptionsSuccessStatus
	if optionsSuccessStatus == 0 {
		optionsSuccessStatus = http.StatusNoContent
	}
	return func(w http.ResponseWriter, r *http.Request, params Params) {
			// Non-OPTIONS request.
			c.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				h(w, r, params)
			})).ServeHTTP(w, r)
		}, func(w http.ResponseWriter, r *http.Request, params Params) {
			// OPTIONS request.
			c.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// We do nothing after OPTIONS request has been handled,
				// even if it was not a CORS OPTIONS request.
				w.WriteHeader(optionsSuccessStatus)
			})).ServeHTTP(w, r)
		}
}

func wrapCors(c *cors.Cors, h func(http.ResponseWriter, *http.Request, Params)) func(http.ResponseWriter, *http.Request, Params) {
	return func(w http.ResponseWriter, r *http.Request, params Params) {
		c.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h(w, r, params)
		})).ServeHTTP(w, r)
	}
}

func methodsSubset(options *CorsOptions, methodsWithHandlers []string) errors.E {
	allowedMethods := mapset.NewThreadUnsafeSet[string]()
	allowedMethods.Append(options.GetAllowedMethods()...)

	methods := mapset.NewThreadUnsafeSet[string]()
	methods.Append(methodsWithHandlers...)

	extraMethods := allowedMethods.Difference(methods)
	if extraMethods.Cardinality() > 0 {
		errE := errors.New("CORS allowed methods contains methods without handlers")
		errors.Details(errE)["extra"] = extraMethods.ToSlice()
		return errE
	}
	return nil
}

// Service defines the application logic for your service.
//
// You should embed the Service struct inside your service struct on which
// you define handlers as methods with [Handler] signature. Handlers together
// with StaticFiles, Routes and Sites define how should the service handle HTTP
// requests.
type Service[SiteT hasSite] struct {
	// General logger for the service.
	Logger zerolog.Logger

	// Canonical log line logger for the service which logs one log entry per
	// request. It is automatically populated with data about the request.
	CanonicalLogger zerolog.Logger

	// WithContext is a function which adds to the context a logger.
	// It is then accessible using zerolog.Ctx(ctx).
	// The first function is called when the request is handled and allows
	// any cleanup necessary. The second function is called on panic.
	// If WithContext is not set, Logger is used instead.
	WithContext func(context.Context) (context.Context, func(), func()) `exhaustruct:"optional"`

	// StaticFiles to be served by the service. All paths are anchored at / when served.
	// HTML files (those with ".html" extension) are rendered using html/template
	// with site struct as data. Other files are served as-is.
	StaticFiles fs.ReadFileFS

	// Routes to be handled by the service and mapped to its Handler methods.
	Routes []Route

	// Sites configured for the service. Key in the map must match site's domain.
	// This should generally be set to sites returned from Server.Init method.
	Sites map[string]SiteT

	// Middleware is a chain of additional middleware to append before the router.
	Middleware []func(http.Handler) http.Handler `exhaustruct:"optional"`

	// SiteContextPath is the path at which site context (JSON of site struct)
	// should be added to static files.
	SiteContextPath string `exhaustruct:"optional"`

	// MetadataHeaderPrefix is an optional prefix to the Metadata response header.
	MetadataHeaderPrefix string `exhaustruct:"optional"`

	// Development is a base URL to proxy to during development, if set.
	// This should generally be set to result of Server.InDevelopment method.
	// If set, StaticFiles are not served by the service so that they can be proxied instead.
	Development string `exhaustruct:"optional"`

	// IsImmutableFile should return true if the static file is immutable and
	// should have such caching headers. Static files are those which do not change
	// during a runtime of the program. Immutable files are those which are never changed.
	IsImmutableFile func(path string) bool `exhaustruct:"optional"`

	// SkipServingFile should return true if the static file should not be automatically
	// registered with the router to be served. It can still be served using ServeStaticFile.
	SkipServingFile func(path string) bool `exhaustruct:"optional"`

	router       *Router                `exhaustruct:"optional"`
	reverseProxy *httputil.ReverseProxy `exhaustruct:"optional"`
}

// RouteWith registers static files and handlers with the router based on Routes and service [Handler]
// methods and returns a [http.Handler] to be used with the [Server].
//
// You should generally pass your service struct with embedded Service struct as service
// parameter so that handler methods can be detected. Non-API handler methods should
// have the same name as the route. While API handler methods should have the name
// matching the route name with HTTP method name as suffix (e.g., "CommentPost" for
// route with name "Comment" and POST HTTP method).
func (s *Service[SiteT]) RouteWith(service interface{}, router *Router) (http.Handler, errors.E) {
	if s.router != nil {
		return nil, errors.New("RouteWith called more than once")
	}
	s.router = router

	errE := s.configureRoutes(service)
	if errE != nil {
		return nil, errE
	}

	if s.Development != "" {
		s.Logger.Debug().Str("proxy", s.Development).Msg("running in development mode")
		errE := s.renderAndCompressSiteContext()
		if errE != nil {
			return nil, errE
		}
		errE = s.serveStaticFiles()
		if errE != nil {
			return nil, errE
		}
		errE = s.makeReverseProxy()
		if errE != nil {
			return nil, errE
		}
		p := logHandlerFuncName("Proxy", s.Proxy)
		s.router.NotFound = p
		s.router.MethodNotAllowed = func(w http.ResponseWriter, req *http.Request, _ Params, _ []string) {
			p(w, req)
		}
	} else {
		errE := s.renderAndCompressStaticFiles()
		if errE != nil {
			return nil, errE
		}
		errE = s.renderAndCompressSiteContext()
		if errE != nil {
			return nil, errE
		}
		errE = s.serveStaticFiles()
		if errE != nil {
			return nil, errE
		}
		if s.router.NotFound == nil {
			s.router.NotFound = logHandlerFuncName("NotFound", s.NotFound)
		} else {
			s.router.NotFound = logHandlerFuncName("NotFound", s.router.NotFound)
		}
		if s.router.MethodNotAllowed == nil {
			s.router.MethodNotAllowed = func(w http.ResponseWriter, req *http.Request, _ Params, allow []string) {
				logger := canonicalLogger(req.Context())
				logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str(zerolog.MessageFieldName, "MethodNotAllowed")
				})
				s.MethodNotAllowed(w, req, allow)
			}
		} else {
			m := s.router.MethodNotAllowed
			s.router.MethodNotAllowed = func(w http.ResponseWriter, req *http.Request, params Params, allow []string) {
				logger := canonicalLogger(req.Context())
				logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str(zerolog.MessageFieldName, "MethodNotAllowed")
				})
				m(w, req, params, allow)
			}
		}
	}
	if s.router.Panic == nil {
		s.router.Panic = s.handlePanic
	}

	c := alice.New()

	// We first create a canonical log line logger as context logger.
	c = c.Append(hlog.NewHandler(s.CanonicalLogger))
	// Then we set the canonical log line logger under its own context key as well.
	c = c.Append(setCanonicalLogger)
	// It has to be before accessHandler so that it can access the timing context.
	c = c.Append(func(next http.Handler) http.Handler {
		return servertiming.Middleware(next, nil)
	})

	// Is logger enabled at all (not zerolog.Nop or zero zerolog struct)?
	// See: https://github.com/rs/zerolog/pull/617
	if l := s.CanonicalLogger.Sample(nil); l.Info().Enabled() { //nolint:zerologlint
		c = c.Append(accessHandler(func(req *http.Request, code int, responseBody, requestBody int64, duration time.Duration) {
			level := zerolog.InfoLevel
			if code >= http.StatusBadRequest {
				level = zerolog.WarnLevel
			}
			if code >= http.StatusInternalServerError {
				level = zerolog.ErrorLevel
			}
			timing := servertiming.FromContext(req.Context())
			metrics := zerolog.Dict()
			seenMetrics := mapset.NewThreadUnsafeSet[string]()
			for _, metric := range timing.Metrics {
				// We log only really measured durations and not just initialized
				// (it is impossible to both start and end the measurement with 0 duration).
				if metric != nil && metric.Duration > 0 {
					metrics.Dur(metric.Name, metric.Duration)
					if !seenMetrics.Add(metric.Name) {
						s.Logger.Warn().Str("metric", metric.Name).Msg("duplicate metric")
					}
				}
			}
			// Full duration is added to the response as a trailer in accessHandler for HTTP2,
			// but it is not added to timing.Metrics. So we add it here to the log.
			metrics.Dur("t", duration)
			l := hlog.FromRequest(req).WithLevel(level)
			if code != 0 {
				l = l.Int("code", code)
			}
			l.Int64("responseBody", responseBody).
				Int64("requestBody", requestBody).
				Dict("metrics", metrics).
				Send()
		}))
		c = c.Append(logMetadata(s.MetadataHeaderPrefix))
		c = c.Append(websocketHandler("ws"))
		c = c.Append(hlog.MethodHandler("method"))
		c = c.Append(urlHandler("path"))
		c = c.Append(hlog.RemoteIPHandler("client"))
		c = c.Append(hlog.UserAgentHandler("agent"))
		c = c.Append(hlog.RefererHandler("referer"))
		c = c.Append(connectionIDHandler("connection"))
		c = c.Append(requestIDHandler("request", "Request-Id"))
		c = c.Append(hlog.HTTPVersionHandler("proto"))
		c = c.Append(hlog.HostHandler("host", true))
		c = c.Append(hlog.EtagHandler("etag"))
		c = c.Append(hlog.ResponseHeaderHandler("encoding", "Content-Encoding"))
	} else {
		c = c.Append(accessHandler(func(req *http.Request, code int, responseBody, requestBody int64, duration time.Duration) {}))
		c = c.Append(requestIDHandler("", "Request-Id"))
	}

	c = c.Append(addNosniffHeader)
	// parseForm should be towards the end because it can fail or redirect
	// and we want other fields to be logged. It also logs query string and
	// redirects to canonical query strings.
	c = c.Append(s.parseForm("query", "rawQuery"))
	// validatePath should be towards the end because it can fail or redirect
	// and we want other fields to be logged. It redirects to canonical path.
	c = c.Append(s.validatePath)
	// validateSite should be towards the end because it can fail and we want
	// other fields to be logged.
	c = c.Append(s.validateSite)

	// We replace the canonical log line logger with a new context logger, but with associated request ID.
	// The canonical log line logger is still available under its own context key.
	if s.WithContext != nil {
		c = c.Append(z.NewHandler(s.WithContext))
	} else {
		c = c.Append(hlog.NewHandler(s.Logger))
	}
	c = c.Append(requestIDHandler("request", ""))

	for _, m := range s.Middleware {
		c = c.Append(m)
	}

	return c.Then(s.router), nil
}

func (s *Service[SiteT]) configureRoutes(service interface{}) errors.E {
	v := reflect.ValueOf(service)

	for _, route := range s.Routes {
		if !route.Get && !route.API {
			errE := errors.New(`at least one of "get" and "api" has to be true`)
			errors.Details(errE)["route"] = route.Name
			errors.Details(errE)["path"] = route.Path
			return errE
		}

		if route.Get {
			handlerName := route.Name
			m := v.MethodByName(handlerName)
			if !m.IsValid() {
				errE := errors.New("handler not found")
				errors.Details(errE)["handler"] = handlerName
				errors.Details(errE)["route"] = route.Name
				errors.Details(errE)["path"] = route.Path
				return errE
			}
			s.Logger.Debug().Str("handler", handlerName).Str("route", route.Name).Str("path", route.Path).Msg("route registration: handler found")
			// We cannot use Handler here because it is a named type.
			h, ok := m.Interface().(func(http.ResponseWriter, *http.Request, Params))
			if !ok {
				errE := errors.New("invalid handler type")
				errors.Details(errE)["handler"] = handlerName
				errors.Details(errE)["route"] = route.Name
				errors.Details(errE)["path"] = route.Path
				errors.Details(errE)["type"] = fmt.Sprintf("%T", m.Interface())
				return errE
			}
			if route.GetCors != nil {
				errE := methodsSubset(route.GetCors, []string{"GET", "HEAD"})
				if errE != nil {
					errors.Details(errE)["handler"] = handlerName
					errors.Details(errE)["route"] = route.Name
					errors.Details(errE)["path"] = route.Path
					return errE
				}
				var optionsH func(http.ResponseWriter, *http.Request, Params)
				h, optionsH = wrapGetCors(route.GetCors, h)
				optionsH = logHandlerName(handlerName, optionsH)
				errE = s.router.Handle(route.Name, http.MethodOptions, route.Path, false, optionsH)
				if errE != nil {
					errors.Details(errE)["handler"] = handlerName
					errors.Details(errE)["route"] = route.Name
					errors.Details(errE)["path"] = route.Path
					return errE
				}
			}
			h = logHandlerName(handlerName, h)
			// HEAD method is already handled by the router for non-API requests.
			errE := s.router.Handle(route.Name, http.MethodGet, route.Path, false, h)
			if errE != nil {
				errors.Details(errE)["handler"] = handlerName
				errors.Details(errE)["route"] = route.Name
				errors.Details(errE)["path"] = route.Path
				return errE
			}
		}
		if route.API { //nolint:nestif
			c := newCors(route.APICors)
			foundAnyAPIHandler := false
			foundOptionsHandler := false
			foundMethods := []string{}
			// MethodHead is handled by MethodGet handled.
			for _, method := range []string{
				http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch,
				http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace,
			} {
				handlerName := fmt.Sprintf("%s%s", route.Name, strings.Title(strings.ToLower(method))) //nolint:staticcheck
				m := v.MethodByName(handlerName)
				if !m.IsValid() {
					s.Logger.Debug().Str("handler", handlerName).Str("route", route.Name).Str("path", route.Path).Msg("route registration: API handler not found")
					continue
				}
				s.Logger.Debug().Str("handler", handlerName).Str("route", route.Name).Str("path", route.Path).Msg("route registration: API handler found")
				foundAnyAPIHandler = true
				// We cannot use Handler here because it is a named type.
				h, ok := m.Interface().(func(http.ResponseWriter, *http.Request, Params))
				if !ok {
					errE := errors.New("invalid API handler type")
					errors.Details(errE)["handler"] = handlerName
					errors.Details(errE)["route"] = route.Name
					errors.Details(errE)["path"] = route.Path
					errors.Details(errE)["type"] = fmt.Sprintf("%T", m.Interface())
					return errE
				}
				if c != nil {
					h = wrapCors(c, h)
					if method == http.MethodOptions {
						foundOptionsHandler = true
					}
				}
				h = logHandlerName(handlerName, h)
				errE := s.router.Handle(route.Name, method, route.Path, true, h)
				if errE != nil {
					errors.Details(errE)["handler"] = handlerName
					errors.Details(errE)["route"] = route.Name
					errors.Details(errE)["path"] = route.Path
					return errE
				}
				foundMethods = append(foundMethods, method)
				if method == http.MethodGet {
					errE := s.router.Handle(route.Name, http.MethodHead, route.Path, true, h)
					if errE != nil {
						errors.Details(errE)["handler"] = handlerName
						errors.Details(errE)["route"] = route.Name
						errors.Details(errE)["path"] = route.Path
						return errE
					}
					foundMethods = append(foundMethods, http.MethodHead)
				}
			}
			if !foundAnyAPIHandler {
				errE := errors.New("no API handler found")
				errors.Details(errE)["route"] = route.Name
				errors.Details(errE)["path"] = route.Path
				return errE
			}
			if c != nil {
				if !foundOptionsHandler {
					handlerName := fmt.Sprintf("%s%s", route.Name, strings.Title(strings.ToLower(http.MethodOptions))) //nolint:staticcheck
					optionsSuccessStatus := route.APICors.OptionsSuccessStatus
					if optionsSuccessStatus == 0 {
						optionsSuccessStatus = http.StatusNoContent
					}
					h := func(w http.ResponseWriter, r *http.Request, params Params) {
						c.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							// We do nothing after OPTIONS request has been handled,
							// even if it was not a CORS OPTIONS request.
							w.WriteHeader(optionsSuccessStatus)
						})).ServeHTTP(w, r)
					}
					h = logHandlerName(handlerName, h)
					errE := s.router.Handle(route.Name, http.MethodOptions, route.Path, true, h)
					if errE != nil {
						errors.Details(errE)["handler"] = handlerName
						errors.Details(errE)["route"] = route.Name
						errors.Details(errE)["path"] = route.Path
						return errE
					}
				}
				errE := methodsSubset(route.APICors, foundMethods)
				if errE != nil {
					errors.Details(errE)["route"] = route.Name
					errors.Details(errE)["path"] = route.Path
					return errE
				}
			}
		}
	}

	return nil
}

func (s *Service[SiteT]) renderAndCompressStaticFiles() errors.E {
	for _, siteT := range s.Sites {
		site := siteT.GetSite()

		if site.staticFiles != nil {
			return errors.New("renderAndCompressStaticFiles called more than once")
		}

		site.initializeStaticFiles()
	}

	if s.StaticFiles == nil {
		return nil
	}

	err := fs.WalkDir(s.StaticFiles, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return errors.WithStack(err)
		}
		if d.IsDir() {
			return nil
		}

		path = strings.TrimPrefix(path, ".")

		data, err := s.StaticFiles.ReadFile(path)
		if err != nil {
			errE := errors.WithStack(err)
			errors.Details(errE)["path"] = path
			return errE
		}

		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}

		mediaType := mime.TypeByExtension(filepath.Ext(path))
		if mediaType == "" {
			s.Logger.Debug().Str("path", path).Msg("unable to determine content type for static file")
			mediaType = "application/octet-stream"
		}

		// Each site might render HTML files differently.
		if strings.HasSuffix(path, ".html") {
			for _, siteT := range s.Sites {
				site := siteT.GetSite()

				htmlData, errE := s.render(path, data, siteT)
				if errE != nil {
					return errE
				}

				errE = site.addStaticFile(path, mediaType, htmlData)
				if errE != nil {
					return errE
				}
			}
		} else {
			// We do not use Site.addFile here so that we can reuse and deduplicate compressed
			// static files across all sites by inverting loops (here we first iterate over
			// compressions and then over sites).

			compressions := allCompressions
			if len(data) <= minCompressionSize {
				compressions = []string{compressionIdentity}
			}

			for _, compression := range compressions {
				d, errE := compress(compression, data)
				if errE != nil {
					errors.Details(errE)["path"] = path
					return errE
				}

				// len(data) cannot be 0 for compression != compressionIdentity because
				// 0 <= minCompressionSize and only compressionIdentity is tried then.
				if compression != compressionIdentity && float64(len(d))/float64(len(data)) >= minCompressionRatio {
					// No need to compress noncompressible files.
					continue
				}

				etag := computeEtag(d)

				for _, siteT := range s.Sites {
					site := siteT.GetSite()

					site.staticFiles[compression][path] = staticFile{
						Data:      d,
						Etag:      etag,
						MediaType: mediaType,
					}
				}
			}
		}

		s.Logger.Debug().Str("path", path).Msg("added file to static files")

		return nil
	})

	return errors.WithStack(err)
}

func (s *Service[SiteT]) renderAndCompressSiteContext() errors.E {
	if s.SiteContextPath == "" {
		return nil
	}

	for _, siteT := range s.Sites {
		site := siteT.GetSite()

		// In development, this method could be called first and static files are not yet
		// initialized (as requests for other static files are proxied), while in production
		// static files has already been initialized and populated.
		if site.staticFiles == nil {
			site.initializeStaticFiles()
		}

		data, errE := x.MarshalWithoutEscapeHTML(siteT)
		if errE != nil {
			return errE
		}

		errE = site.addStaticFile(s.SiteContextPath, "application/json", data)
		if errE != nil {
			return errE
		}
	}

	s.Logger.Debug().Str("path", s.SiteContextPath).Msg("added file to static files")

	return nil
}

func (s *Service[SiteT]) makeReverseProxy() errors.E {
	if s.reverseProxy != nil {
		return errors.New("makeReverseProxy called more than once")
	}

	target, err := url.Parse(s.Development)
	if err != nil {
		errE := errors.WithStack(err)
		errors.Details(errE)["url"] = s.Development
		return errE
	}

	singleHostDirector := httputil.NewSingleHostReverseProxy(target).Director
	director := func(req *http.Request) {
		singleHostDirector(req)

		// We pass request ID through.
		req.Header.Set("Request-Id", MustRequestID(req.Context()).String())

		// We potentially parse PostForm in parseForm middleware. In that case
		// the body is consumed and closed. We have to reconstruct it here.
		if postFormParsed(req) {
			encoded := req.PostForm.Encode()
			req.Body = io.NopCloser(strings.NewReader(encoded))
			if req.Header.Get("Content-Length") != "" {
				// Our reconstruction might have a different length.
				req.Header.Set("Content-Length", strconv.Itoa(len(encoded)))
			}
		}

		// TODO: Map origin and other headers.
	}

	// TODO: Map response cookies, other headers which include origin, and redirect locations.
	s.reverseProxy = &httputil.ReverseProxy{
		Rewrite:        nil,
		Director:       director,
		Transport:      cleanhttp.DefaultPooledTransport(),
		FlushInterval:  -1,
		ErrorLog:       log.New(s.Logger, "", 0),
		BufferPool:     nil,
		ModifyResponse: nil,
		ErrorHandler:   nil,
	}
	return nil
}

func (s *Service[SiteT]) serveStaticFiles() errors.E {
	staticH := logHandlerName("StaticFile", toHandler(s.staticFile))
	immutableH := logHandlerName("ImmutableFile", toHandler(s.immutableFile))

	for _, siteT := range s.Sites {
		site := siteT.GetSite()

		// We can use any compression to obtain all static paths, so we use compressionIdentity.
		for path := range site.staticFiles[compressionIdentity] {
			if s.SkipServingFile != nil && s.SkipServingFile(path) {
				continue
			}

			var n string
			var h Handler
			if s.IsImmutableFile != nil && s.IsImmutableFile(path) {
				n = fmt.Sprintf("ImmutableFile:%s", path)
				h = immutableH
			} else {
				n = fmt.Sprintf("StaticFile:%s", path)
				h = staticH
			}

			err := s.router.Handle(n, http.MethodGet, path, false, h)
			if err != nil {
				return errors.WithDetails(err, "path", path)
			}
		}

		// We can use any site to obtain all static paths,
		// so we break here after the first site.
		break
	}

	return nil
}

func (s *Service[SiteT]) render(path string, data []byte, siteT SiteT) ([]byte, errors.E) {
	t, err := template.New(path).Parse(string(data))
	if err != nil {
		return nil, errors.WithDetails(err, "path", path)
	}
	var out bytes.Buffer
	err = t.Execute(&out, siteT)
	if err != nil {
		return nil, errors.WithDetails(err, "path", path)
	}
	return out.Bytes(), nil
}

// AddMetadata adds header with metadata to the response.
//
// Metadata is encoded based on [RFC 8941]. Header name is "Metadata" with
// optional MetadataHeaderPrefix.
//
// [RFC 8941]: https://www.rfc-editor.org/rfc/rfc8941
func (s *Service[SiteT]) AddMetadata(w http.ResponseWriter, req *http.Request, metadata map[string]interface{}) ([]byte, errors.E) {
	if len(metadata) == 0 {
		return nil, nil
	}

	b := &bytes.Buffer{}
	err := encodeMetadata(metadata, b)
	if err != nil {
		return nil, err
	}
	w.Header().Add(s.MetadataHeaderPrefix+metadataHeader, b.String())

	logMetadata, ok := req.Context().Value(metadataContextKey).(map[string]interface{})
	// metadataContextKey might not exist if provided logger is disabled.
	if ok {
		for key, value := range metadata {
			// We overwrite any existing key. This is the same behavior RFC 8941 specifies
			// for duplicate keys in its dictionaries. The last one wins.
			logMetadata[key] = value
		}
	}

	return b.Bytes(), nil
}

// PrepareJSON prepares the JSON response to the request. It populates
// response headers and encodes data as JSON.
// Optional metadata is added as the response header.
//
// Besides other types, data can be of type []byte and [json.RawMessage] in which
// case it is expected that it already contains a well-formed JSON and is returned
// as-is.
//
// If there is an error, PrepareJSON responds to the request and returns nil.
func (s *Service[SiteT]) PrepareJSON(w http.ResponseWriter, req *http.Request, data interface{}, metadata map[string]interface{}) []byte {
	ctx := req.Context()
	timing := servertiming.FromContext(ctx)

	var encoded []byte
	switch d := data.(type) {
	case []byte:
		encoded = d
	case json.RawMessage:
		encoded = []byte(d)
	default:
		m := timing.NewMetric("j").Start()
		e, err := x.MarshalWithoutEscapeHTML(data)
		m.Stop()

		if err != nil {
			s.InternalServerErrorWithError(w, req, errors.WithStack(err))
			return nil
		}

		encoded = e
	}

	contentEncoding := negotiateContentEncoding(req, nil)
	if contentEncoding == "" {
		// If the client does not accept any compression we support (even no compression),
		// we ignore that and just do not compress.
		contentEncoding = compressionIdentity
	} else if len(encoded) <= minCompressionSize {
		contentEncoding = compressionIdentity
	}

	if contentEncoding != compressionIdentity {
		m := timing.NewMetric("c").Start()
		compressed, errE := compress(contentEncoding, encoded)
		m.Stop()

		if errE != nil {
			s.InternalServerErrorWithError(w, req, errE)
			return nil
		}

		// len(encoded) cannot be 0 because 0 <= minCompressionSize
		// and contentEncoding is set to compressionIdentity then.
		if float64(len(compressed))/float64(len(encoded)) >= minCompressionRatio {
			// No need to send noncompressible files. We already used time to compress
			// but we throw that away so that the client does not have to spend time decompressing.
			// We do not try if any other acceptable compression might have
			// a better ratio to not take too much time trying them. We assume
			// that the client prefers generally the best compression anyway.
			contentEncoding = compressionIdentity
		} else {
			encoded = compressed
		}
	}

	md, errE := s.AddMetadata(w, req, metadata)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return nil
	}

	etag := computeEtag(encoded, md)

	w.Header().Set("Content-Type", "application/json")
	if contentEncoding != compressionIdentity {
		w.Header().Set("Content-Encoding", contentEncoding)
	} else {
		// TODO: Always set Content-Length.
		//       See: https://github.com/golang/go/pull/50904
		w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	}
	if len(w.Header().Values("Cache-Control")) == 0 {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Add("Vary", "Accept-Encoding")
	w.Header().Set("Etag", etag)

	return encoded
}

// WriteJSON replies to the request by writing data as JSON.
//
// Optional metadata is added as the response header.
//
// Besides other types, data can be of type []byte and [json.RawMessage] in which
// case it is expected that it already contains a well-formed JSON and is written
// as-is.
//
// It does not otherwise end the request; the caller should ensure no further writes are done to w.
func (s *Service[SiteT]) WriteJSON(w http.ResponseWriter, req *http.Request, data interface{}, metadata map[string]interface{}) {
	encoded := s.PrepareJSON(w, req, data, metadata)
	if encoded == nil {
		return
	}

	// See: https://github.com/golang/go/issues/50905
	// See: https://github.com/golang/go/pull/50903
	http.ServeContent(w, req, "", time.Time{}, bytes.NewReader(encoded))
}

func (s *Service[SiteT]) site(req *http.Request) (SiteT, errors.E) { //nolint:ireturn
	host := getHost(req.Host)
	if host != "" {
		if site, ok := s.Sites[host]; ok {
			return site, nil
		}
	}
	err := errors.New("site not found for host")
	errors.Details(err)["host"] = host
	return *new(SiteT), err
}

// Reverse calls router's Reverse.
func (s *Service[SiteT]) Reverse(name string, params Params, qs url.Values) (string, errors.E) {
	return s.router.Reverse(name, params, qs)
}

// Reverse calls router's ReverseAPI.
func (s *Service[SiteT]) ReverseAPI(name string, params Params, qs url.Values) (string, errors.E) {
	return s.router.ReverseAPI(name, params, qs)
}

// TODO: Use Vite's manifest.json to send preload headers.

// ServeStaticFile replies to the request by serving the file at path from service's static files.
//
// It does not otherwise end the request; the caller should ensure no further writes are done to w.
func (s *Service[SiteT]) ServeStaticFile(w http.ResponseWriter, req *http.Request, path string) {
	immutable := false
	if s.IsImmutableFile != nil {
		immutable = s.IsImmutableFile(path)
	}
	s.serveStaticFile(w, req, path, immutable)
}

func (s *Service[SiteT]) serveStaticFile(w http.ResponseWriter, req *http.Request, path string, immutable bool) {
	site := MustGetSite[SiteT](req.Context()).GetSite()

	var contentEncoding string
	var ok bool
	var f staticFile

	// Always set Vary as our error responses also depend on Accept-Encoding.
	w.Header().Add("Vary", "Accept-Encoding")

	// TODO: When searching for a suitable compression, we should also search by etag from If-None-Match.
	//       If-None-Match might have an etag for a compression which is not picked here. This is probably rare though.
	compressions := slices.Clone(allCompressions)
	for {
		contentEncoding = negotiateContentEncoding(req, compressions)
		if contentEncoding == "" {
			// If the client does not accept any compression we support (even no compression),
			// we ignore that and just do not compress.
			contentEncoding = compressionIdentity
		}

		f, ok = site.staticFiles[contentEncoding][path]
		if ok {
			break
		}

		if contentEncoding == compressionIdentity {
			err := errors.New("no static file for path")
			errors.Details(err)["path"] = path
			// This should not really happen. ServeStaticFile should not be called for a file
			// which is not among service's static files.
			s.InternalServerErrorWithError(w, req, err)
			return
		}

		// There might be no file for compression because content is too short
		// or noncompressible. We try another compression.
		compressions = slices.DeleteFunc(compressions, func(c string) bool {
			return c == contentEncoding
		})
	}

	if f.Etag == "" {
		err := errors.New("no etag for static file")
		errors.Details(err)["compression"] = contentEncoding
		errors.Details(err)["path"] = path
		// This should not really happen. We should have computed etags for all static files.
		s.InternalServerErrorWithError(w, req, err)
		return
	}

	if f.MediaType == "" {
		err := errors.New("no content type for static file")
		errors.Details(err)["compression"] = contentEncoding
		errors.Details(err)["path"] = path
		// This should not really happen. We should have content types for all static files.
		s.InternalServerErrorWithError(w, req, err)
		return
	}

	w.Header().Set("Content-Type", f.MediaType)
	if contentEncoding != compressionIdentity {
		w.Header().Set("Content-Encoding", contentEncoding)
	} else {
		// TODO: Always set Content-Length.
		//       See: https://github.com/golang/go/pull/50904
		w.Header().Set("Content-Length", strconv.Itoa(len(f.Data)))
	}
	if immutable {
		w.Header().Set("Cache-Control", "max-age=31536000,immutable,stale-while-revalidate=86400")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Set("Etag", f.Etag)

	// See: https://github.com/golang/go/issues/50905
	// See: https://github.com/golang/go/pull/50903
	http.ServeContent(w, req, "", time.Time{}, bytes.NewReader(f.Data))
}

func (s *Service[SiteT]) staticFile(w http.ResponseWriter, req *http.Request) {
	s.serveStaticFile(w, req, req.URL.Path, false)
}

func (s *Service[SiteT]) immutableFile(w http.ResponseWriter, req *http.Request) {
	s.serveStaticFile(w, req, req.URL.Path, true)
}

func (s *Service[SiteT]) handlePanic(w http.ResponseWriter, req *http.Request, err interface{}) {
	logger := canonicalLogger(req.Context())
	var e error
	switch ee := err.(type) {
	case error:
		e = errors.WithStack(ee)
	case string:
		e = errors.New(ee)
	}
	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		if e != nil {
			return c.Bool("panic", true).Err(e)
		}
		return c.Interface("panic", err)
	})

	s.InternalServerError(w, req)
}
