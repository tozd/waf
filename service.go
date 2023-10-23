package waf

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	eddo "github.com/golang/gddo/httputil"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/justinas/alice"
	servertiming "github.com/mitchellh/go-server-timing"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
)

const contextPath = "/index.json"

type Route struct {
	Name string `json:"name"`
	Path string `json:"path"`
	API  bool   `json:"api,omitempty"`
	Get  bool   `json:"get,omitempty"`
}

type Site struct {
	Domain string `json:"domain" yaml:"domain"`
	Title  string `json:"title"  yaml:"title"`

	// We do not expose certificate and key file paths in JSON.
	CertFile string `json:"-" yaml:"cert,omitempty"`
	KeyFile  string `json:"-" yaml:"key,omitempty"`

	// Maps between content types, paths, and content/etags.
	// They are per site because they can include rendered per-site content.
	compressedFiles      map[string]map[string][]byte
	compressedFilesEtags map[string]map[string]string
}

func (s *Site) GetSite() *Site {
	return s
}

type hasSite interface {
	GetSite() *Site
}

type Service[SiteT hasSite] struct {
	Logger zerolog.Logger

	Files  fs.ReadFileFS
	Routes []Route
	Sites  map[string]SiteT

	// Build metadata.
	Version        string
	BuildTimestamp string
	Revision       string

	// It should be kept all lower case so that it is easier to
	// compare against in the case insensitive manner.
	MetadataHeaderPrefix string

	Development string

	IsImmutableFile func(path string) bool
	SkipStaticFile  func(path string) bool

	router       *Router
	reverseProxy *httputil.ReverseProxy
}

func (s *Service[SiteT]) RouteWith(service interface{}, router *Router) (http.Handler, errors.E) {
	if s.router != nil {
		panic(errors.New("RouteWith called more than once"))
	}
	s.router = router

	errE := s.configureRoutes(service)
	if errE != nil {
		return nil, errE
	}

	if s.Development != "" {
		errE := s.renderAndCompressContext()
		if errE != nil {
			return nil, errE
		}
		errE = s.computeEtags()
		if errE != nil {
			return nil, errE
		}
		errE = s.makeReverseProxy()
		if errE != nil {
			return nil, errE
		}
		s.router.NotFound = logHandlerName(autoName(s.Proxy), s.Proxy)
		s.router.MethodNotAllowed = logHandlerName(autoName(s.Proxy), s.Proxy)
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
		errE = s.serveStaticFiles()
		if errE != nil {
			return nil, errE
		}
		s.router.NotFound = logHandlerName(autoName(s.NotFound), s.NotFound)
		s.router.MethodNotAllowed = logHandlerName(autoName(s.MethodNotAllowed), s.MethodNotAllowed)
	}
	s.router.Panic = s.handlePanic

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
		l := zerolog.Ctx(req.Context()).WithLevel(level) //nolint:zerologlint
		if s.Revision != "" || s.BuildTimestamp != "" || s.Version != "" {
			build := zerolog.Dict()
			// In alphabetical order, so that it is the same as JSON marshal.
			if s.Revision != "" {
				build = build.Str("r", s.Revision)
			}
			if s.BuildTimestamp != "" {
				build = build.Str("t", s.BuildTimestamp)
			}
			if s.Version != "" {
				build = build.Str("v", s.Version)
			}
			l = l.Dict("build", build)
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
	c = c.Append(requestIDHandler("request", "Request-Id"))
	c = c.Append(httpVersionHandler("proto"))
	c = c.Append(hostHandler("host"))
	c = c.Append(etagHandler("etag"))
	c = c.Append(responseHeaderHandler("encoding", "Content-Encoding"))
	// parseForm should be as late as possible because it can fail
	// and we want other fields to be logged.
	c = c.Append(s.parseForm)
	// URLHandler should be after the parseForm middleware.
	c = c.Append(urlHandler("path", "query"))

	return c.Then(s.router), nil
}

func (s *Service[SiteT]) configureRoutes(service interface{}) errors.E {
	v := reflect.ValueOf(service)

	for _, route := range s.Routes {
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
				errE := errors.New("invalid route handler type")
				errors.Details(errE)["handler"] = handlerName
				errors.Details(errE)["name"] = route.Name
				errors.Details(errE)["path"] = route.Path
				errors.Details(errE)["type"] = fmt.Sprintf("%T", m.Interface())
				return errE
			}
			h = logHandlerName(handlerName, h)
			errE := s.router.Handle(route.Name, http.MethodGet, route.Path, false, h)
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
					errE := errors.New("invalid route handler type")
					errors.Details(errE)["handler"] = handlerName
					errors.Details(errE)["name"] = route.Name
					errors.Details(errE)["path"] = route.Path
					errors.Details(errE)["type"] = fmt.Sprintf("%T", m.Interface())
					return errE
				}
				h = logHandlerName(handlerName, h)
				errE := s.router.Handle(route.Name, method, route.Path, true, h)
				if errE != nil {
					errors.Details(errE)["handler"] = handlerName
					errors.Details(errE)["name"] = route.Name
					errors.Details(errE)["path"] = route.Path
					return errE
				}
				if method == http.MethodGet {
					errE := s.router.Handle(route.Name, http.MethodHead, route.Path, true, h)
					if errE != nil {
						errors.Details(errE)["handler"] = handlerName
						errors.Details(errE)["name"] = route.Name
						errors.Details(errE)["path"] = route.Path
						return errE
					}
				}
			}
			if !foundAnyAPIHandler {
				errE := errors.New("no route API handler found")
				errors.Details(errE)["name"] = route.Name
				errors.Details(errE)["path"] = route.Path
				return errE
			}
		}
	}

	return nil
}

func (s *Service[SiteT]) renderAndCompressFiles() errors.E {
	// Each site might render HTML files differently.
	for domain, siteT := range s.Sites {
		site := siteT.GetSite()

		if site.compressedFiles != nil {
			return errors.New("renderAndCompressFiles called more than once")
		}

		site.compressedFiles = make(map[string]map[string][]byte)

		for _, compression := range allCompressions {
			site.compressedFiles[compression] = make(map[string][]byte)

			err := fs.WalkDir(s.Files, ".", func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return errors.WithStack(err)
				}
				if d.IsDir() {
					return nil
				}

				data, err := s.Files.ReadFile(path)
				if err != nil {
					errE := errors.WithStack(err)
					errors.Details(errE)["path"] = path
					return errE
				}
				path = strings.TrimPrefix(path, ".")

				var errE errors.E
				if strings.HasSuffix(path, ".html") {
					data, errE = s.render(path, data, siteT)
					if errE != nil {
						errors.Details(errE)["path"] = path
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
		s.Sites[domain] = siteT
	}

	return nil
}

func (s *Service[SiteT]) renderAndCompressContext() errors.E {
	for domain, siteT := range s.Sites {
		site := siteT.GetSite()

		// In development, this method could be called first and compressedFiles are not yet
		// initialized (as requests for other files are proxied), while in production
		// compressedFiles has already been initialized and populated by built static files.
		if site.compressedFiles == nil {
			site.compressedFiles = make(map[string]map[string][]byte)
		}

		for _, compression := range allCompressions {
			if _, ok := site.compressedFiles[compression]; !ok {
				site.compressedFiles[compression] = make(map[string][]byte)
			}

			data, errE := x.MarshalWithoutEscapeHTML(s.getSiteContext(siteT))
			if errE != nil {
				return errE
			}

			data, errE = compress(compression, data)
			if errE != nil {
				return errE
			}

			site.compressedFiles[compression][contextPath] = data
		}

		// Map cannot be modified directly, so we modify the copy
		// and store it back into the map.
		s.Sites[domain] = siteT
	}

	return nil
}

func (s *Service[SiteT]) computeEtags() errors.E {
	for domain, siteT := range s.Sites {
		site := siteT.GetSite()

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
		s.Sites[domain] = siteT
	}

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
	staticName := autoName(s.staticFile)
	staticH := logHandlerName(staticName, s.staticFile)
	immutableName := autoName(s.immutableFile)
	immutableH := logHandlerName(staticName, s.immutableFile)

	for _, siteT := range s.Sites {
		site := siteT.GetSite()

		// We can use any compression to obtain all static paths, so we use compressionIdentity.
		for path := range site.compressedFiles[compressionIdentity] {
			if (s.SkipStaticFile != nil && s.SkipStaticFile(path)) || path == contextPath {
				continue
			}

			var n string
			var h Handler
			if s.IsImmutableFile != nil && s.IsImmutableFile(path) {
				n = fmt.Sprintf("%s:%s", immutableName, path)
				h = immutableH
			} else {
				n = fmt.Sprintf("%s:%s", staticName, path)
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

func (s *Service[SiteT]) render(path string, data []byte, site SiteT) ([]byte, errors.E) {
	t, err := template.New(path).Parse(string(data))
	if err != nil {
		return nil, errors.WithDetails(err, "path", path)
	}
	var out bytes.Buffer
	err = t.Execute(&out, s.getSiteContext(site))
	if err != nil {
		return nil, errors.WithDetails(err, "path", path)
	}
	return out.Bytes(), nil
}

func (s *Service[SiteT]) WriteJSON(w http.ResponseWriter, req *http.Request, contentEncoding string, data interface{}, metadata http.Header) {
	ctx := req.Context()
	timing := servertiming.FromContext(ctx)

	m := timing.NewMetric("j").Start()

	var encoded []byte
	switch d := data.(type) {
	case json.RawMessage:
		encoded = []byte(d)
	default:
		e, err := x.MarshalWithoutEscapeHTML(data)
		if err != nil {
			s.InternalServerErrorWithError(w, req, errors.WithStack(err))
			return
		}
		encoded = e
	}

	m.Stop()

	if len(encoded) <= minCompressionSize {
		contentEncoding = compressionIdentity
	}

	m = timing.NewMetric("c").Start()

	encoded, errE := compress(contentEncoding, encoded)
	if errE != nil {
		s.InternalServerErrorWithError(w, req, errE)
		return
	}

	m.Stop()

	hash := sha256.New()
	_, _ = hash.Write(encoded)

	for key, value := range metadata {
		w.Header()[textproto.CanonicalMIMEHeaderKey(s.MetadataHeaderPrefix+key)] = value
		_, _ = hash.Write([]byte(key))
		for _, v := range value {
			_, _ = hash.Write([]byte(v))
		}
	}

	etag := `"` + base64.RawURLEncoding.EncodeToString(hash.Sum(nil)) + `"`

	logger := hlog.FromRequest(req)
	if len(metadata) > 0 {
		logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return logValues(c, "metadata", metadata)
		})
	}

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
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// See: https://github.com/golang/go/issues/50905
	// See: https://github.com/golang/go/pull/50903
	http.ServeContent(w, req, "", time.Time{}, bytes.NewReader(encoded))
}

func (s *Service[SiteT]) Site(req *http.Request) (SiteT, errors.E) { //nolint:ireturn
	if site, ok := s.Sites[req.Host]; req.Host != "" && ok {
		return site, nil
	}
	err := errors.New("site not found for host")
	errors.Details(err)["host"] = req.Host
	return *new(SiteT), err
}

func (s *Service[SiteT]) Path(name string, params Params, qs url.Values) (string, errors.E) {
	return s.router.Path(name, params, qs)
}

func (s *Service[SiteT]) APIPath(name string, params Params, qs url.Values) (string, errors.E) {
	return s.router.APIPath(name, params, qs)
}

// TODO: Use Vite's manifest.json to send preload headers.
func (s *Service[SiteT]) serveStaticFile(w http.ResponseWriter, req *http.Request, path string, immutable bool) {
	contentEncoding := eddo.NegotiateContentEncoding(req, allCompressions)
	if contentEncoding == "" {
		s.NotAcceptable(w, req, nil)
		return
	}

	siteT, err := s.Site(req)
	if err != nil {
		s.NotFoundWithError(w, req, err)
		return
	}

	site := siteT.GetSite()

	data, ok := site.compressedFiles[contentEncoding][path]
	if !ok {
		err := errors.New("no data for compression and path")
		errors.Details(err)["compression"] = contentEncoding
		errors.Details(err)["path"] = path
		s.InternalServerErrorWithError(w, req, err)
		return
	}

	if len(data) <= minCompressionSize {
		contentEncoding = compressionIdentity
		data, ok = site.compressedFiles[contentEncoding][path]
		if !ok {
			err := errors.New("no data for compression and path")
			errors.Details(err)["compression"] = contentEncoding
			errors.Details(err)["path"] = path
			s.InternalServerErrorWithError(w, req, err)
			return
		}
	}

	etag, ok := site.compressedFilesEtags[contentEncoding][path]
	if !ok {
		err := errors.New("no etag for compression and path")
		errors.Details(err)["compression"] = contentEncoding
		errors.Details(err)["path"] = path
		s.InternalServerErrorWithError(w, req, err)
		return
	}

	contentType := mime.TypeByExtension(filepath.Ext(path))
	if contentType == "" {
		err := errors.New("unable to determine content type for file")
		errors.Details(err)["path"] = path
		s.InternalServerErrorWithError(w, req, err)
		return
	}

	w.Header().Set("Content-Type", contentType)
	if contentEncoding != compressionIdentity {
		w.Header().Set("Content-Encoding", contentEncoding)
	} else {
		// TODO: Always set Content-Length.
		//       See: https://github.com/golang/go/pull/50904
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	}
	if immutable {
		w.Header().Set("Cache-Control", "public,max-age=31536000,immutable,stale-while-revalidate=86400")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Add("Vary", "Accept-Encoding")
	w.Header().Set("Etag", etag)
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// See: https://github.com/golang/go/issues/50905
	// See: https://github.com/golang/go/pull/50903
	http.ServeContent(w, req, "", time.Time{}, bytes.NewReader(data))
}

func (s *Service[SiteT]) staticFile(w http.ResponseWriter, req *http.Request, _ Params) {
	s.serveStaticFile(w, req, req.URL.Path, false)
}

func (s *Service[SiteT]) immutableFile(w http.ResponseWriter, req *http.Request, _ Params) {
	s.serveStaticFile(w, req, req.URL.Path, true)
}

func (s *Service[SiteT]) handlePanic(w http.ResponseWriter, req *http.Request, err interface{}) {
	logger := hlog.FromRequest(req)
	var e error
	switch ee := err.(type) {
	case error:
		e = errors.WithStack(ee)
	case string:
		e = errors.New(ee)
	}
	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		if e != nil {
			return c.Err(e)
		}
		return c.Interface("panic", err)
	})

	s.InternalServerError(w, req, nil)
}
