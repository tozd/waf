package waf

import (
	"bytes"
	"context"
	"encoding/json"
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
	"strconv"
	"strings"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	z "gitlab.com/tozd/go/zerolog"
)

// CORSOptions is a subset of cors.Options.
//
// See description of fields in cors.Options.
//
// See: https://github.com/rs/cors/pull/164
type CORSOptions struct {
	AllowedOrigins       []string `json:"allowedOrigins,omitempty"`
	AllowedMethods       []string `json:"allowedMethods,omitempty"`
	AllowedHeaders       []string `json:"allowedHeaders,omitempty"`
	ExposedHeaders       []string `json:"exposedHeaders,omitempty"`
	MaxAge               int      `json:"maxAge,omitempty"`
	AllowCredentials     bool     `json:"allowCredentials,omitempty"`
	AllowPrivateNetwork  bool     `json:"allowPrivateNetwork,omitempty"`
	OptionsSuccessStatus int      `json:"optionsSuccessStatus,omitempty"`
}

// GetAllowedMethods returns the list of allowed methods.
func (c *CORSOptions) GetAllowedMethods() []string {
	if len(c.AllowedMethods) == 0 {
		// We allow only GET and HEAD by default.
		// This is different from the cors package which also has POST.
		return []string{http.MethodGet, http.MethodHead}
	}

	allowedMethods := []string{}
	hasGet := false
	hasHead := false
	for _, method := range c.AllowedMethods {
		method = strings.ToUpper(method)
		allowedMethods = append(allowedMethods, method)
		switch method {
		case http.MethodGet:
			hasGet = true
		case http.MethodHead:
			hasHead = true
		}
	}

	if hasGet && !hasHead {
		allowedMethods = append(allowedMethods, http.MethodHead)
	}

	return allowedMethods
}

// RouteOptions describe options for the route.
type RouteOptions struct {
	// Handlers for the route. A map between a HTTP method and a handler.
	Handlers map[string]Handler `exhaustruct:"optional" json:"handlers,omitempty"`

	// Enable CORS on handler(s)?
	CORS *CORSOptions `exhaustruct:"optional" json:"-"`
}

// Route is route definition which is used by a service to route to handlers
// with the router. It can also be used by Vue Router to register routes there.
type Route struct {
	// Does this route have a non-API handlers.
	RouteOptions `exhaustruct:"optional"`

	// Path for the route. It can contain parameters.
	Path string `json:"path"`

	// Does this route support API handlers.
	// API paths are automatically prefixed with /api.
	API RouteOptions `exhaustruct:"optional" json:"api,omitzero"`
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
	Domain string `json:"domain" required:"" yaml:"domain"`

	// Certificate file path for the site. It should be valid for the domain.
	// Used when Let's Encrypt is not configured.
	CertFile string `help:"Certificate for TLS, when not using Let's Encrypt." json:"-" name:"cert" placeholder:"PATH" type:"existingfile" yaml:"cert,omitempty"`

	// Key file path. Used when Let's Encrypt is not configured.
	KeyFile string `help:"Certificate's private key, when not using Let's Encrypt." json:"-" name:"key" placeholder:"PATH" type:"existingfile" yaml:"key,omitempty"`

	// Maps between content types, paths, and data/etag/media type.
	// They are per site because they can include rendered per-site data.
	// File contents are deduplicated between sites if they are the same.
	staticFiles map[string]map[string]staticFile
}

// Validate validates the site.
func (s *Site) Validate() error {
	if s.CertFile != "" || s.KeyFile != "" {
		if s.CertFile == "" {
			errE := errors.New("missing file certificate for provided private key")
			errors.Details(errE)["domain"] = s.Domain
			return errE
		}
		if s.KeyFile == "" {
			errE := errors.New("missing file certificate's matching private key")
			errors.Details(errE)["domain"] = s.Domain
			return errE
		}
	}

	return nil
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
		errE := errors.New("static file for path already exists")
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
	typ := reflect.TypeFor[SiteT]().Elem()
	st := reflect.New(typ).Interface().(SiteT) //nolint:forcetypeassert,errcheck
	site := st.GetSite()
	return st, site
}

func newCORS(options *CORSOptions) (*cors.Cors, func(http.ResponseWriter, *http.Request, Params)) {
	if options == nil {
		return nil, nil
	}

	c := cors.New(cors.Options{ //nolint:exhaustruct
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

	optionsSuccessStatus := options.OptionsSuccessStatus
	if optionsSuccessStatus == 0 {
		optionsSuccessStatus = http.StatusNoContent
	}

	return c, func(w http.ResponseWriter, r *http.Request, _ Params) {
		c.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// We do nothing after OPTIONS request has been handled,
			// even if it was not a CORS OPTIONS request.
			w.WriteHeader(optionsSuccessStatus)
		})).ServeHTTP(w, r)
	}
}

func wrapCORS(c *cors.Cors, h func(http.ResponseWriter, *http.Request, Params)) func(http.ResponseWriter, *http.Request, Params) {
	if c == nil {
		return h
	}

	return func(w http.ResponseWriter, r *http.Request, params Params) {
		c.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h(w, r, params)
		})).ServeHTTP(w, r)
	}
}

func methodsSubset(options *CORSOptions, methodsWithHandlers []string) errors.E {
	allowedMethods := mapset.NewThreadUnsafeSet[string]()
	allowedMethods.Append(options.GetAllowedMethods()...)

	methods := mapset.NewThreadUnsafeSet[string]()
	methods.Append(methodsWithHandlers...)

	extraMethods := allowedMethods.Difference(methods)
	if extraMethods.Cardinality() > 0 {
		errE := errors.New("CORS allowed methods contain methods without handlers")
		extra := extraMethods.ToSlice()
		slices.Sort(extra)
		errors.Details(errE)["extra"] = extra
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

	// Routes to be handled by the service. A map between route name and a route definition.
	Routes map[string]Route

	// Sites configured for the service. Key in the map must match site's domain.
	// This should generally be set to sites returned from Server.Init method.
	Sites map[string]SiteT

	// Middleware is a chain of additional middleware to append before the router.
	Middleware []func(http.Handler) http.Handler `exhaustruct:"optional"`

	// SiteContextPath is the path at which site context (JSON of site struct)
	// should be added to static files.
	SiteContextPath string `exhaustruct:"optional"`

	// RoutesPath is the path at which routes JSON should be added to static files.
	RoutesPath string `exhaustruct:"optional"`

	// MetadataHeaderPrefix is an optional prefix to the Metadata response header.
	MetadataHeaderPrefix string `exhaustruct:"optional"`

	// ProxyStaticTo is a base URL to proxy to during development, if set.
	// This should generally be set to result of Server.ProxyToInDevelopment method.
	// If set, StaticFiles are not served by the service so that they can be proxied instead.
	ProxyStaticTo string `exhaustruct:"optional"`

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
func (s *Service[SiteT]) RouteWith(router *Router) (http.Handler, errors.E) {
	if s.router != nil {
		return nil, errors.New("RouteWith called more than once")
	}
	s.router = router

	errE := s.configureRoutes()
	if errE != nil {
		return nil, errE
	}

	if s.ProxyStaticTo != "" {
		s.Logger.Debug().Str("proxy", s.ProxyStaticTo).Msg("proxying static files")
		errE := s.renderAndCompressSiteContext()
		if errE != nil {
			return nil, errE
		}
		errE = s.renderAndCompressRoutes()
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
		errE = s.renderAndCompressRoutes()
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
				*canonicalLoggerMessage(req.Context()) = "MethodNotAllowed" //nolint:goconst
				s.MethodNotAllowed(w, req, allow)
			}
		} else {
			m := s.router.MethodNotAllowed
			s.router.MethodNotAllowed = func(w http.ResponseWriter, req *http.Request, params Params, allow []string) {
				*canonicalLoggerMessage(req.Context()) = "MethodNotAllowed"
				m(w, req, params, allow)
			}
		}
	}
	if s.router.Panic == nil {
		s.router.Panic = s.handlePanic
	}

	c := newMiddlewareStack(s.CanonicalLogger, s.MetadataHeaderPrefix)

	c = c.Append(addResponseHeader("Strict-Transport-Security", "max-age=31536000"))

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

func (s *Service[SiteT]) registerRoutes(routeName, routePath string, api bool, options RouteOptions) errors.E {
	c, optionsHandler := newCORS(options.CORS)
	methods := []string{}

	for method, handler := range options.Handlers {
		handler = wrapCORS(c, handler)
		handler, handlerName := logHandlerName(routeName, method, api, handler) //nolint:govet

		errE := s.router.Handle(routeName, method, routePath, api, handler)
		if errE != nil {
			errors.Details(errE)["handler"] = handlerName
			errors.Details(errE)["route"] = routeName
			errors.Details(errE)["path"] = routePath
			return errE
		}
		methods = append(methods, method)

		// If no HEAD handler is defined, we reuse GET handler for it.
		if _, ok := options.Handlers[http.MethodHead]; method == http.MethodGet && !ok {
			errE := s.router.Handle(routeName, http.MethodHead, routePath, api, handler)
			if errE != nil {
				errors.Details(errE)["handler"] = handlerName
				errors.Details(errE)["route"] = routeName
				errors.Details(errE)["path"] = routePath
				return errE
			}
			methods = append(methods, http.MethodHead)
		}
	}

	if c != nil && len(methods) > 0 {
		// We have CORS enabled and at least one handler. If options handler is not defined, we add it.
		if _, ok := options.Handlers[http.MethodOptions]; !ok {
			optionsHandler, handlerName := logHandlerName(routeName, http.MethodOptions, api, optionsHandler)
			errE := s.router.Handle(routeName, http.MethodOptions, routePath, api, optionsHandler)
			if errE != nil {
				errors.Details(errE)["handler"] = handlerName
				errors.Details(errE)["route"] = routeName
				errors.Details(errE)["path"] = routePath
				return errE
			}
		}

		errE := methodsSubset(options.CORS, methods)
		if errE != nil {
			errors.Details(errE)["route"] = routeName
			errors.Details(errE)["path"] = routePath
			return errE
		}
	}

	return nil
}

func (s *Service[SiteT]) configureRoutes() errors.E {
	for routeName, route := range s.Routes {
		if len(route.Handlers) == 0 && len(route.API.Handlers) == 0 {
			errE := errors.New("at least one handler has to be set")
			errors.Details(errE)["route"] = routeName
			errors.Details(errE)["path"] = route.Path
			return errE
		}

		errE := s.registerRoutes(routeName, route.Path, false, route.RouteOptions)
		if errE != nil {
			return errE
		}

		errE = s.registerRoutes(routeName, route.Path, true, route.API)
		if errE != nil {
			return errE
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

		pathWithSlash := "/" + path

		data, err := s.StaticFiles.ReadFile(path)
		if err != nil {
			errE := errors.WithStack(err)
			errors.Details(errE)["path"] = pathWithSlash
			return errE
		}

		mediaType := mime.TypeByExtension(filepath.Ext(path))
		if mediaType == "" {
			s.Logger.Debug().Str("path", pathWithSlash).Msg("unable to determine content type for static file")
			mediaType = "application/octet-stream"
		}

		// Each site might render HTML files differently.
		if strings.HasSuffix(pathWithSlash, ".html") {
			for _, siteT := range s.Sites {
				site := siteT.GetSite()

				htmlData, errE := s.render(pathWithSlash, data, siteT)
				if errE != nil {
					return errE
				}

				errE = site.addStaticFile(pathWithSlash, mediaType, htmlData)
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
					errors.Details(errE)["path"] = pathWithSlash
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

					site.staticFiles[compression][pathWithSlash] = staticFile{
						Data:      d,
						Etag:      etag,
						MediaType: mediaType,
					}
				}
			}
		}

		s.Logger.Debug().Str("path", pathWithSlash).Msg("added file to static files")

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

func (s *Service[SiteT]) renderAndCompressRoutes() errors.E {
	if s.RoutesPath == "" {
		return nil
	}

	data, errE := x.MarshalWithoutEscapeHTML(s.Routes)
	if errE != nil {
		return errE
	}

	for _, siteT := range s.Sites {
		site := siteT.GetSite()

		// In development, this method could be called first and static files are not yet
		// initialized (as requests for other static files are proxied), while in production
		// static files has already been initialized and populated.
		if site.staticFiles == nil {
			site.initializeStaticFiles()
		}

		errE = site.addStaticFile(s.RoutesPath, "application/json", data)
		if errE != nil {
			return errE
		}
	}

	s.Logger.Debug().Str("path", s.RoutesPath).Msg("added file to static files")

	return nil
}

func (s *Service[SiteT]) makeReverseProxy() errors.E {
	if s.reverseProxy != nil {
		return errors.New("makeReverseProxy called more than once")
	}

	target, err := url.Parse(s.ProxyStaticTo)
	if err != nil {
		errE := errors.WithStack(err)
		errors.Details(errE)["url"] = s.ProxyStaticTo
		return errE
	}

	s.reverseProxy = &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = r.In.Host

			// We pass request ID through.
			r.Out.Header.Set("Request-Id", MustRequestID(r.In.Context()).String())

			// We potentially parse PostForm in parseForm middleware. In that case
			// the body is consumed and closed. We have to reconstruct it here.
			if postFormParsed(r.In) {
				encoded := r.In.PostForm.Encode()
				r.Out.Body = io.NopCloser(strings.NewReader(encoded))
				if r.Out.Header.Get("Content-Length") != "" {
					// Our reconstruction might have a different length.
					r.Out.Header.Set("Content-Length", strconv.Itoa(len(encoded)))
				}
			}

			// TODO: Map response cookies, other headers which include origin, and redirect locations.
		},
		Director:       nil,
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
	staticH, staticName := logHandlerName("StaticFile", http.MethodGet, false, toHandler(s.staticFile))
	immutableH, immutableName := logHandlerName("ImmutableFile", http.MethodGet, false, toHandler(s.immutableFile))

	for _, siteT := range s.Sites {
		site := siteT.GetSite()

		// We can use any compression to obtain all static paths, so we use compressionIdentity.
		for path := range site.staticFiles[compressionIdentity] {
			if s.SkipServingFile != nil && s.SkipServingFile(path) {
				continue
			}

			isImmutable := s.IsImmutableFile != nil && s.IsImmutableFile(path)

			var n string
			var h Handler
			if isImmutable {
				n = "ImmutableFile:" + path
				h = immutableH
			} else {
				n = "StaticFile:" + path
				h = staticH
			}

			for _, method := range []string{http.MethodGet, http.MethodHead} {
				errE := s.router.Handle(n, method, path, false, h)
				if errE != nil {
					if isImmutable {
						errors.Details(errE)["handler"] = immutableName
						errors.Details(errE)["route"] = "ImmutableFile"
					} else {
						errors.Details(errE)["handler"] = staticName
						errors.Details(errE)["route"] = "StaticFile"
					}
					errors.Details(errE)["path"] = path
					return errE
				}
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
	metrics := MustGetMetrics(ctx)

	var encoded []byte
	switch d := data.(type) {
	case []byte:
		encoded = d
	case json.RawMessage:
		encoded = []byte(d)
	default:
		m := metrics.Duration(MetricJSONMarshal).Start()
		e, err := x.MarshalWithoutEscapeHTML(data)
		m.Stop()

		if err != nil {
			s.InternalServerErrorWithError(w, req, errors.WithStack(err))
			return nil
		}

		encoded = e
	}

	contentEncoding := negotiateContentEncoding(w, req, nil)
	if contentEncoding == "" {
		// If the client does not accept any compression we support (even no compression),
		// we ignore that and just do not compress.
		contentEncoding = compressionIdentity
	} else if len(encoded) <= minCompressionSize {
		contentEncoding = compressionIdentity
	}

	if contentEncoding != compressionIdentity {
		m := metrics.Duration(MetricCompress).Start()
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
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	if len(w.Header().Values("Cache-Control")) == 0 {
		w.Header().Set("Cache-Control", "no-cache")
	}
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

	http.ServeContent(w, req, "", time.Time{}, bytes.NewReader(encoded))
}

func (s *Service[SiteT]) site(req *http.Request) (SiteT, errors.E) { //nolint:ireturn
	host, errE := getHost(req.Host)
	if errE != nil {
		return *new(SiteT), errE
	}
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

// ReverseAPI calls router's ReverseAPI.
func (s *Service[SiteT]) ReverseAPI(name string, params Params, qs url.Values) (string, errors.E) {
	return s.router.ReverseAPI(name, params, qs)
}

// GetRoute calls router's Get.
func (s *Service[SiteT]) GetRoute(path, method string) (ResolvedRoute, errors.E) {
	return s.router.Get(path, method)
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

	// TODO: When searching for a suitable compression, we should also search by etag from If-None-Match.
	//       If-None-Match might have an etag for a compression which is not picked here. This is probably rare though.
	compressions := slices.Clone(allCompressions)
	for {
		contentEncoding = negotiateContentEncoding(w, req, compressions)
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
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(f.Data)))
	if immutable {
		w.Header().Set("Cache-Control", "max-age=31536000,immutable,stale-while-revalidate=86400")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Set("Etag", f.Etag)

	http.ServeContent(w, req, "", time.Time{}, bytes.NewReader(f.Data))
}

func (s *Service[SiteT]) staticFile(w http.ResponseWriter, req *http.Request) {
	s.serveStaticFile(w, req, req.URL.Path, false)
}

func (s *Service[SiteT]) immutableFile(w http.ResponseWriter, req *http.Request) {
	s.serveStaticFile(w, req, req.URL.Path, true)
}

func (s *Service[SiteT]) handlePanic(w http.ResponseWriter, req *http.Request, err interface{}) {
	canonicalLoggerWithPanic(req.Context(), err)
	s.InternalServerError(w, req)
}
