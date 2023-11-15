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
	"strconv"
	"strings"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/justinas/alice"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	servertiming "github.com/tozd/go-server-timing"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	z "gitlab.com/tozd/go/zerolog"
)

const contextPath = "/index.json"

type Route struct {
	Name string `json:"name"`
	Path string `json:"path"`
	API  bool   `json:"api,omitempty"`
	Get  bool   `json:"get,omitempty"`
}

type file struct {
	Data      []byte
	Etag      string
	MediaType string
}

type Site struct {
	Domain string `json:"domain" yaml:"domain"`

	// We do not expose certificate and key file paths in JSON.
	CertFile string `json:"-" yaml:"cert,omitempty"`
	KeyFile  string `json:"-" yaml:"key,omitempty"`

	// Maps between content types, paths, and data/etag/media type.
	// They are per site because they can include rendered per-site content.
	files map[string]map[string]file
}

func (s *Site) GetSite() *Site {
	return s
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

type Service[SiteT hasSite] struct {
	Logger      zerolog.Logger
	WithContext func(context.Context) (context.Context, func(), func())

	Files  fs.ReadFileFS
	Routes []Route
	Sites  map[string]SiteT

	// Build metadata.
	Version        string
	BuildTimestamp string
	Revision       string

	MetadataHeaderPrefix string

	Development string

	IsImmutableFile func(path string) bool
	SkipStaticFile  func(path string) bool

	router       *Router
	reverseProxy *httputil.ReverseProxy
}

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
		p := logHandlerFuncName("Proxy", s.Proxy)
		s.router.NotFound = p
		s.router.MethodNotAllowed = func(w http.ResponseWriter, req *http.Request, _ Params, _ []string) {
			p(w, req)
		}
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
		s.router.NotFound = logHandlerFuncName("NotFound", s.NotFound)
		s.router.MethodNotAllowed = func(w http.ResponseWriter, req *http.Request, _ Params, allow []string) {
			logger := canonicalLogger(req.Context())
			logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
				return c.Str(zerolog.MessageFieldName, "MethodNotAllowed")
			})
			s.MethodNotAllowed(w, req, allow)
		}
	}
	s.router.Panic = s.handlePanic

	c := alice.New()

	// We first create a canonical log line logger as context logger.
	c = c.Append(hlog.NewHandler(s.Logger))
	// Then we set the canonical log line logger under its own context key as well.
	c = c.Append(setCanonicalLogger)
	// It has to be before accessHandler so that it can access the timing context.
	c = c.Append(func(next http.Handler) http.Handler {
		return servertiming.Middleware(next, nil)
	})
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
		l := hlog.FromRequest(req).WithLevel(level) //nolint:zerologlint
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
			h = logHandlerName(handlerName, h)
			errE := s.router.Handle(route.Name, http.MethodGet, route.Path, false, h)
			if errE != nil {
				errors.Details(errE)["handler"] = handlerName
				errors.Details(errE)["route"] = route.Name
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
				h = logHandlerName(handlerName, h)
				errE := s.router.Handle(route.Name, method, route.Path, true, h)
				if errE != nil {
					errors.Details(errE)["handler"] = handlerName
					errors.Details(errE)["route"] = route.Name
					errors.Details(errE)["path"] = route.Path
					return errE
				}
				if method == http.MethodGet {
					errE := s.router.Handle(route.Name, http.MethodHead, route.Path, true, h)
					if errE != nil {
						errors.Details(errE)["handler"] = handlerName
						errors.Details(errE)["route"] = route.Name
						errors.Details(errE)["path"] = route.Path
						return errE
					}
				}
			}
			if !foundAnyAPIHandler {
				errE := errors.New("no API handler found")
				errors.Details(errE)["route"] = route.Name
				errors.Details(errE)["path"] = route.Path
				return errE
			}
		}
	}

	return nil
}

// TODO: De-duplicate storing same file's content in memory multiple times (all non .html files are the same between sites).

func (s *Service[SiteT]) renderAndCompressFiles() errors.E {
	// Each site might render HTML files differently.
	for domain, siteT := range s.Sites {
		site := siteT.GetSite()

		if site.files != nil {
			return errors.New("renderAndCompressFiles called more than once")
		}

		site.files = make(map[string]map[string]file)

		for _, compression := range allCompressions {
			site.files[compression] = make(map[string]file)
		}

		err := fs.WalkDir(s.Files, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return errors.WithStack(err)
			}
			if d.IsDir() {
				return nil
			}

			path = strings.TrimPrefix(path, ".")

			data, err := s.Files.ReadFile(path)
			if err != nil {
				errE := errors.WithStack(err)
				errors.Details(errE)["path"] = path
				return errE
			}

			path = "/" + path

			var errE errors.E
			if strings.HasSuffix(path, ".html") {
				data, errE = s.render(path, data, siteT)
				if errE != nil {
					errors.Details(errE)["path"] = path
					return errE
				}
			}

			mediaType := mime.TypeByExtension(filepath.Ext(path))
			if mediaType == "" {
				s.Logger.Debug().Str("path", path).Msg("unable to determine content type for file")
				mediaType = "application/octet-stream"
			}

			compressions := allCompressions
			if len(data) <= minCompressionSize {
				compressions = []string{compressionIdentity}
			}

			for _, compression := range compressions {
				d, errE := compress(compression, data)
				if errE != nil {
					return errE
				}

				// len(data) cannot be 0 for compression != compressionIdentity because
				// 0 <= minCompressionSize and only compressionIdentity is tried then.
				if compression != compressionIdentity && float64(len(d))/float64(len(data)) >= minCompressionRatio {
					// No need to compress noncompressible files.
					continue
				}

				site.files[compression][path] = file{
					Data:      d,
					Etag:      "",
					MediaType: mediaType,
				}
			}

			return nil
		})
		if err != nil {
			return errors.WithStack(err)
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

		// In development, this method could be called first and files are not yet
		// initialized (as requests for other files are proxied), while in production
		// files has already been initialized and populated by built static files.
		if site.files == nil {
			site.files = make(map[string]map[string]file)
		}

		data, errE := x.MarshalWithoutEscapeHTML(s.getSiteContext(siteT))
		if errE != nil {
			return errE
		}

		compressions := allCompressions
		if len(data) <= minCompressionSize {
			compressions = []string{compressionIdentity}
		}

		for _, compression := range compressions {
			if _, ok := site.files[compression]; !ok {
				site.files[compression] = make(map[string]file)
			}

			d, errE := compress(compression, data)
			if errE != nil {
				return errE
			}

			// len(data) cannot be 0 for compression != compressionIdentity because
			// 0 <= minCompressionSize and only compressionIdentity is tried then.
			if compression != compressionIdentity && float64(len(d))/float64(len(data)) >= minCompressionRatio {
				// No need to compress noncompressible files.
				continue
			}

			site.files[compression][contextPath] = file{
				Data:      d,
				Etag:      "",
				MediaType: "application/json",
			}
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

		for compression, files := range site.files {
			for path, file := range files {
				if file.Etag != "" {
					errE := errors.New("etag already computed")
					errors.Details(errE)["compression"] = compression
					errors.Details(errE)["path"] = path
					return errE
				}

				file.Etag = computeEtag(file.Data)
				site.files[compression][path] = file
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
		for path := range site.files[compressionIdentity] {
			if s.SkipStaticFile != nil && s.SkipStaticFile(path) {
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

	logMetadata := req.Context().Value(metadataContextKey).(map[string]interface{}) //nolint:errcheck,forcetypeassert
	for key, value := range metadata {
		// We overwrite any existing key. This is the same behavior RFC 8941 specifies
		// for duplicate keys in its dictionaries. The last one wins.
		logMetadata[key] = value
	}

	return b.Bytes(), nil
}

func (s *Service[SiteT]) WriteJSON(w http.ResponseWriter, req *http.Request, data interface{}, metadata map[string]interface{}) {
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
			return
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
			return
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
		return
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

	// See: https://github.com/golang/go/issues/50905
	// See: https://github.com/golang/go/pull/50903
	http.ServeContent(w, req, "", time.Time{}, bytes.NewReader(encoded))
}

func (s *Service[SiteT]) site(req *http.Request) (SiteT, errors.E) { //nolint:ireturn
	if site, ok := s.Sites[req.Host]; req.Host != "" && ok {
		return site, nil
	}
	err := errors.New("site not found for host")
	errors.Details(err)["host"] = req.Host
	return *new(SiteT), err
}

func (s *Service[SiteT]) Reverse(name string, params Params, qs url.Values) (string, errors.E) {
	return s.router.Reverse(name, params, qs)
}

func (s *Service[SiteT]) ReverseAPI(name string, params Params, qs url.Values) (string, errors.E) {
	return s.router.ReverseAPI(name, params, qs)
}

// TODO: Use Vite's manifest.json to send preload headers.
func (s *Service[SiteT]) serveStaticFile(w http.ResponseWriter, req *http.Request, path string, immutable bool) {
	site := MustGetSite[SiteT](req.Context()).GetSite()

	var contentEncoding string
	var ok bool
	var f file

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

		f, ok = site.files[contentEncoding][path]
		if ok {
			break
		}

		if contentEncoding == compressionIdentity {
			err := errors.New("no file for path")
			errors.Details(err)["path"] = path
			// This should not really happen. We should not register
			// the static file handler for this path if the file does not exist.
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
		err := errors.New("no etag for file")
		errors.Details(err)["compression"] = contentEncoding
		errors.Details(err)["path"] = path
		// This should not really happen. We should have computed etags for all files.
		s.InternalServerErrorWithError(w, req, err)
		return
	}

	if f.MediaType == "" {
		err := errors.New("no content type for file")
		errors.Details(err)["compression"] = contentEncoding
		errors.Details(err)["path"] = path
		// This should not really happen. We should have content types for all files.
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
		w.Header().Set("Cache-Control", "public,max-age=31536000,immutable,stale-while-revalidate=86400")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Add("Vary", "Accept-Encoding")
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
