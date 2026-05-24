package waf

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
)

// Error replies to the request with the specified HTTP code.
// Error message is automatically generated based on the HTTP code
// using [http.StatusText].
//
// It does not otherwise end the request; the caller should ensure no further
// writes are done to w.
func Error(w http.ResponseWriter, _ *http.Request, code int) {
	body := http.StatusText(code)
	w.Header().Set("Cache-Control", "no-cache")
	// http.Error appends a newline so we have to add 1.
	w.Header().Set("Content-Length", strconv.Itoa(len(body)+1))
	http.Error(w, body, code)
}

// RequestID returns the request identifier from context ctx and true
// if the request identifier is stored in the context.
//
// Note, Waf service always stores the request identifier in the request context.
func RequestID(ctx context.Context) (identifier.Identifier, bool) {
	i, ok := ctx.Value(requestIDContextKey).(identifier.Identifier)
	return i, ok
}

// MustRequestID returns the request identifier from context ctx or panics
// if the request identifier is not stored in the context.
//
// Note, Waf service always stores the request identifier in the request context.
func MustRequestID(ctx context.Context) identifier.Identifier {
	i, ok := RequestID(ctx)
	if !ok {
		panic(errors.New("request ID not found in context"))
	}
	return i
}

// GetSite returns the site from context ctx and true
// if the site is stored in the context.
//
// Note, Waf service always stores the site (based on host header in the request)
// in the request context.
func GetSite[SiteT hasSite](ctx context.Context) (SiteT, bool) { //nolint:ireturn
	s, ok := ctx.Value(siteContextKey).(SiteT)
	return s, ok
}

// MustGetSite returns the site from context ctx or panics
// if the site is not stored in the context.
//
// Note, Waf service always stores the site (based on host header in the request)
// in the request context.
func MustGetSite[SiteT hasSite](ctx context.Context) SiteT { //nolint:ireturn
	s, ok := GetSite[SiteT](ctx)
	if !ok {
		panic(errors.New("site not found in context"))
	}
	return s
}

// GetMetrics returns metrics from context ctx and true if the metrics
// are stored in the context. If the metrics are not stored in the context,
// it returns a new dummy metrics instance and false.
//
// Note, Waf service always stores the metrics in the request context.
func GetMetrics(ctx context.Context) (*Metrics, bool) {
	m, ok := ctx.Value(metricsContextKey).(*Metrics)
	if !ok {
		return NewMetrics(), false
	}
	return m, true
}

// MustGetMetrics returns metrics from context ctx or panics
// if the metrics are not stored in the context.
//
// Note, Waf service always stores the metrics in the request context.
func MustGetMetrics(ctx context.Context) *Metrics {
	m, ok := GetMetrics(ctx)
	if !ok {
		panic(errors.New("metrics not found in context"))
	}
	return m
}

// NotFound replies to the request with the 404 (not found) HTTP code and the corresponding
// error message.
//
// It does not otherwise end the request; the caller should ensure no further
// writes are done to w.
func (s *Service[SiteT]) NotFound(w http.ResponseWriter, req *http.Request) {
	// We do not use http.NotFound because http.StatusText(http.StatusNotFound)
	// is different from what http.NotFound uses, and we want to use the same pattern.
	Error(w, req, http.StatusNotFound)
}

// NotFoundWithError replies to the request with the 404 (not found) HTTP code and the corresponding
// error message. Error err is logged to the canonical log line.
//
// As a special case, if err is [context.Canceled] or [context.DeadlineExceeded] it instead replies
// with the 408 (request timeout) HTTP code, the corresponding error message, and logs to the canonical log line
// that the context has been canceled or that deadline exceeded, respectively.
//
// It does not otherwise end the request; the caller should ensure no further
// writes are done to w.
func (s *Service[SiteT]) NotFoundWithError(w http.ResponseWriter, req *http.Request, err errors.E) {
	s.WithError(req.Context(), err)

	if errors.Is(err, context.Canceled) {
		// Rationale: the client canceled the request and stopped reading the response, so in
		// a way we are not prepared to wait indefinitely for the client to read the response.
		Error(w, req, http.StatusRequestTimeout)
		return
	} else if errors.Is(err, context.DeadlineExceeded) {
		// Rationale: the client was reading the response too slowly, and we were
		// not prepared to wait for so long.
		Error(w, req, http.StatusRequestTimeout)
		return
	}

	s.NotFound(w, req)
}

// MethodNotAllowed replies to the request with the 405 (method not allowed) HTTP code and the corresponding
// error message. It adds Allow response header based on the list of allowed methods
// in allow.
//
// It does not otherwise end the request; the caller should ensure no further
// writes are done to w.
func (s *Service[SiteT]) MethodNotAllowed(w http.ResponseWriter, req *http.Request, allow []string) {
	w.Header().Add("Allow", strings.Join(allow, ", "))
	Error(w, req, http.StatusMethodNotAllowed)
}

// BadRequest replies to the request with the 400 (bad request) HTTP code and the corresponding
// error message.
//
// It does not otherwise end the request; the caller should ensure no further
// writes are done to w.
func (s *Service[SiteT]) BadRequest(w http.ResponseWriter, req *http.Request) {
	Error(w, req, http.StatusBadRequest)
}

// BadRequestWithError replies to the request with the 400 (bad request) HTTP code and the corresponding
// error message. Error err is logged to the canonical log line.
//
// As a special case, if err is [context.Canceled] or [context.DeadlineExceeded] it instead replies
// with the 408 (request timeout) HTTP code, the corresponding error message, and logs to the canonical log line
// that the context has been canceled or that deadline exceeded, respectively.
//
// It does not otherwise end the request; the caller should ensure no further
// writes are done to w.
func (s *Service[SiteT]) BadRequestWithError(w http.ResponseWriter, req *http.Request, err errors.E) {
	s.WithError(req.Context(), err)

	if errors.Is(err, context.Canceled) {
		// Rationale: the client canceled the request and stopped reading the response, so in
		// a way we are not prepared to wait indefinitely for the client to read the response.
		Error(w, req, http.StatusRequestTimeout)
		return
	} else if errors.Is(err, context.DeadlineExceeded) {
		// Rationale: the client was reading the response too slowly, and we were
		// not prepared to wait for so long.
		Error(w, req, http.StatusRequestTimeout)
		return
	}

	s.BadRequest(w, req)
}

// InternalServerError replies to the request with the 500 (internal server error) HTTP code and the corresponding
// error message.
//
// It does not otherwise end the request; the caller should ensure no further
// writes are done to w.
func (s *Service[SiteT]) InternalServerError(w http.ResponseWriter, req *http.Request) {
	Error(w, req, http.StatusInternalServerError)
}

// InternalServerErrorWithError replies to the request with the 500 (internal server error) HTTP code and the corresponding
// error message. Error err is logged to the canonical log line.
//
// As a special case, if err is [context.Canceled] or [context.DeadlineExceeded] it instead replies
// with the 408 (request timeout) HTTP code, the corresponding error message, and logs to the canonical log line
// that the context has been canceled or that deadline exceeded, respectively.
//
// It does not otherwise end the request; the caller should ensure no further
// writes are done to w.
func (s *Service[SiteT]) InternalServerErrorWithError(w http.ResponseWriter, req *http.Request, err errors.E) {
	s.WithError(req.Context(), err)

	if errors.Is(err, context.Canceled) {
		// Rationale: the client canceled the request and stopped reading the response, so in
		// a way we are not prepared to wait indefinitely for the client to read the response.
		Error(w, req, http.StatusRequestTimeout)
		return
	} else if errors.Is(err, context.DeadlineExceeded) {
		// Rationale: the client was reading the response too slowly, and we were
		// not prepared to wait for so long.
		Error(w, req, http.StatusRequestTimeout)
		return
	}

	s.InternalServerError(w, req)
}

// Forbidden replies to the request with the 403 (forbidden) HTTP code and the corresponding
// error message.
//
// It does not otherwise end the request; the caller should ensure no further
// writes are done to w.
func (s *Service[SiteT]) Forbidden(w http.ResponseWriter, req *http.Request) {
	Error(w, req, http.StatusForbidden)
}

// ForbiddenWithError replies to the request with the 403 (forbidden) HTTP code and the corresponding
// error message. Error err is logged to the canonical log line.
//
// As a special case, if err is [context.Canceled] or [context.DeadlineExceeded] it instead replies
// with the 408 (request timeout) HTTP code, the corresponding error message, and logs to the canonical log line
// that the context has been canceled or that deadline exceeded, respectively.
//
// It does not otherwise end the request; the caller should ensure no further
// writes are done to w.
func (s *Service[SiteT]) ForbiddenWithError(w http.ResponseWriter, req *http.Request, err errors.E) {
	s.WithError(req.Context(), err)

	if errors.Is(err, context.Canceled) {
		// Rationale: the client canceled the request and stopped reading the response, so in
		// a way we are not prepared to wait indefinitely for the client to read the response.
		Error(w, req, http.StatusRequestTimeout)
		return
	} else if errors.Is(err, context.DeadlineExceeded) {
		// Rationale: the client was reading the response too slowly, and we were
		// not prepared to wait for so long.
		Error(w, req, http.StatusRequestTimeout)
		return
	}

	s.Forbidden(w, req)
}

// WithError logs err to the canonical log line.
//
// As a special case, if err is [context.Canceled] or [context.DeadlineExceeded] it logs to the
// canonical log line that the context has been canceled or that deadline exceeded, respectively.
func (s *Service[SiteT]) WithError(ctx context.Context, err errors.E) {
	canonicalLoggerWithError(ctx, err)
}

// Proxy proxies request to the development backend (e.g., Vite).
func (s *Service[SiteT]) Proxy(w http.ResponseWriter, req *http.Request) {
	if s.ProxyStaticTo == "" {
		s.InternalServerErrorWithError(w, req, errors.New("Proxy called without ProxyStaticTo config"))
		return
	}

	logger := canonicalLogger(req.Context())
	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("proxied", s.ProxyStaticTo)
	})
	s.reverseProxy.ServeHTTP(w, req)
}

// willProxy reports whether the request will fall through to the development
// proxy. It is true when ProxyStaticTo is configured and the request path does
// not resolve to a registered route. Middleware uses this to skip transforms
// (e.g. query-string canonicalization) that would corrupt opaque URLs handled
// by the proxied backend, like Vite's `?worker&inline` worker imports.
func (s *Service[SiteT]) willProxy(req *http.Request) bool {
	if s.ProxyStaticTo == "" {
		return false
	}
	_, errE := s.router.Get(req.URL.Path, req.Method)
	return errors.Is(errE, ErrNotFound)
}

// TemporaryRedirectSameMethod redirects the client to a new URL with the 307 (temporary redirect) HTTP code which makes
// the client redo the request to a new location with the same method and body.
func (s *Service[SiteT]) TemporaryRedirectSameMethod(w http.ResponseWriter, req *http.Request, location string) {
	http.Redirect(w, req, location, http.StatusTemporaryRedirect)
}

// TemporaryRedirectGetMethod redirects the client to a new URL with the 303 (see other) HTTP code which makes
// the client do the request to a new location with the GET method.
func (s *Service[SiteT]) TemporaryRedirectGetMethod(w http.ResponseWriter, req *http.Request, location string) {
	http.Redirect(w, req, location, http.StatusSeeOther)
}
