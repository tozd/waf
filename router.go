package waf

import (
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"gitlab.com/tozd/go/errors"
)

var errNotFound = errors.Base("not found")

type MethodNotAllowedError struct {
	Allow []string
}

func (*MethodNotAllowedError) Error() string {
	return "method not allowed"
}

type pathSegment struct {
	Value     string
	Parameter bool
}

func parsePath(path string) ([]pathSegment, errors.E) {
	if !strings.HasPrefix(path, "/") {
		errE := errors.New(`path does not start with "/"`)
		errors.Details(errE)["path"] = path
		return nil, errE
	}
	p := strings.TrimPrefix(path, "/")
	segments := []pathSegment{}
	// If path is "/".
	if p == "" {
		return segments, nil
	}
	parts := strings.Split(p, "/")
	for _, part := range parts {
		if part == "" {
			errE := errors.New("path has an empty part")
			errors.Details(errE)["path"] = path
			return nil, errE
		}
		// TODO: Support custom regex in params. For now we prevent them.
		//
		//	See: https://router.vuejs.org/guide/essentials/route-matching-syntax.html#Custom-regex-in-params
		if strings.ContainsAny(part, "=*+()?") {
			errE := errors.New("path contains unsupported characters")
			errors.Details(errE)["path"] = path
			return nil, errE
		}
		var segment pathSegment
		if strings.HasPrefix(part, ":") {
			segment.Value = strings.TrimPrefix(part, ":")
			segment.Parameter = true
		} else {
			segment.Value = part
		}
		segments = append(segments, segment)
	}
	return segments, nil
}

func compileRegexp(segments []pathSegment) (*regexp.Regexp, func([]string) Params, errors.E) {
	matchMap := make(map[int]string)
	expr := strings.Builder{}
	expr.WriteString("^")
	i := 0
	for _, segment := range segments {
		expr.WriteString("/")
		if segment.Parameter {
			expr.WriteString("([^/]+)")
			i++
			matchMap[i] = segment.Value
		} else {
			expr.WriteString(regexp.QuoteMeta(segment.Value))
		}
	}
	if len(segments) == 0 {
		expr.WriteString("/")
	}
	expr.WriteString("$")
	re, err := regexp.Compile(expr.String())
	if err != nil {
		return nil, nil, errors.WithDetails(err, "regexp", expr.String())
	}
	return re, func(match []string) Params {
		p := make(map[string]string, len(match)-1)
		for i, v := range match {
			if i == 0 {
				continue
			}
			p[matchMap[i]] = v
		}
		return p
	}, nil
}

type matcher struct {
	Regexp    *regexp.Regexp
	GetParams func([]string) Params
	Route     *route
}

type route struct {
	Name       string
	Path       string
	Segments   []pathSegment
	Parameters mapset.Set[string]
	GetHandler Handler
	// A map between methods and API handlers.
	APIHandlers map[string]Handler
}

// Params are parsed from the request URL path based on the
// matched route. Map keys are parameter names.
type Params map[string]string

// Handler type defines Waf router handler function signature.
//
// The function signature is similar to [http.HandlerFunc], but
// has additional parameter with Params parsed from the request URL path.
type Handler func(http.ResponseWriter, *http.Request, Params)

func toHandler(f func(http.ResponseWriter, *http.Request)) Handler {
	return func(w http.ResponseWriter, req *http.Request, _ Params) {
		f(w, req)
	}
}

// TODO: Implement RedirectTrailingSlash = true
// TODO: Implement RedirectFixedPath = true.

// Router calls handlers for HTTP requests based on URL path and HTTP method.
//
// The goal of the router is to match routes in the same way as [Vue Router].
// In addition, it supports also API handlers matched on HTTP method.
// API handlers share the same route name but have their path automatically
// prefixed with /api.
//
// [Vue Router]: https://router.vuejs.org/
type Router struct {
	// NotFound is called if no route matches URL path.
	// If not defined, the request is replied with the 404 (not found) HTTP code error.
	NotFound func(http.ResponseWriter, *http.Request)

	// MethodNotAllowed is called the route does not support used HTTP method.
	// If not defined, the request is replied with the 405 (method not allowed) HTTP code error.
	MethodNotAllowed func(http.ResponseWriter, *http.Request, Params, []string)

	// Panic is called if handler panics instead of returning.
	// If not defined, panics propagate.
	Panic func(w http.ResponseWriter, req *http.Request, err interface{})

	// EncodeQuery allows customization of how query strings are encoded
	// when reversing a route in Reverse and ReverseAPI methods.
	EncodeQuery func(qs url.Values) string

	// A map between route name and routes.
	routes   map[string]*route
	matchers []matcher
}

// Handle registers the route handler with route name at path and with HTTP method.
//
// Path can contain parameters which start with ":". E.g., "/post/:id" is a path with
// one parameter "id". Those parameters are parsed from the request URL and passed to
// handlers.
//
// Routes are matched in the order in which they are registered.
//
// Non-API handlers can use only GET HTTP method, which is used also for HEAD HTTP method
// automatically.
//
// Route is identified with the name and can have only one path associated with it, but
// it can have different handlers for different HTTP methods and can have both API and non-API handlers.
// Path for API handlers is automatically prefixed with /api, so you must not prefix it yourself.
func (r *Router) Handle(name, method, path string, api bool, handler Handler) errors.E {
	if name == "" {
		err := errors.New("name cannot be empty")
		errors.Details(err)["path"] = path
		errors.Details(err)["route"] = name
		return err
	}
	if handler == nil {
		err := errors.New("handler cannot be nil")
		errors.Details(err)["path"] = path
		errors.Details(err)["route"] = name
		return err
	}
	if strings.HasPrefix(path, "/api/") || path == "/api" {
		err := errors.New("path cannot start with /api")
		errors.Details(err)["path"] = path
		errors.Details(err)["route"] = name
		return err
	}
	ro, ok := r.routes[name]
	if !ok {
		segments, err := parsePath(path)
		if err != nil {
			err = errors.WithMessage(err, "parsing path failed")
			errors.Details(err)["path"] = path
			errors.Details(err)["route"] = name
			return err
		}
		re, get, err := compileRegexp(segments)
		if err != nil {
			err = errors.WithMessage(err, "compiling regexp failed")
			errors.Details(err)["path"] = path
			errors.Details(err)["route"] = name
			return err
		}
		parameters := mapset.NewThreadUnsafeSet[string]()
		for _, segment := range segments {
			if segment.Parameter {
				if !parameters.Add(segment.Value) {
					err := errors.New("duplicate parameter")
					errors.Details(err)["parameter"] = segment.Value
					errors.Details(err)["path"] = path
					errors.Details(err)["route"] = name
					return err
				}
			}
		}
		ro = &route{
			Name:        name,
			Path:        path,
			Segments:    segments,
			Parameters:  parameters,
			GetHandler:  nil,
			APIHandlers: make(map[string]Handler),
		}
		if r.routes == nil {
			r.routes = make(map[string]*route)
		}
		r.routes[name] = ro
		r.matchers = append(r.matchers, matcher{
			Regexp:    re,
			GetParams: get,
			Route:     ro,
		})
	}

	if ro.Path != path {
		err := errors.New("route with different paths")
		errors.Details(err)["route"] = name
		errors.Details(err)["path1"] = ro.Path
		errors.Details(err)["path1"] = path
		return err
	}

	for _, rr := range r.routes {
		if rr.Name == name {
			continue
		}

		if rr.Path == path {
			err := errors.New("path with different routes")
			errors.Details(err)["route1"] = name
			errors.Details(err)["route2"] = rr.Name
			errors.Details(err)["path"] = path
			return err
		}
	}

	if api {
		_, ok := ro.APIHandlers[method]
		if ok {
			err := errors.New("API handler already exists")
			errors.Details(err)["route"] = name
			errors.Details(err)["path"] = path
			errors.Details(err)["method"] = method
			return err
		}

		ro.APIHandlers[method] = handler
	} else {
		if method != http.MethodGet {
			err := errors.New("non-API handler must use GET HTTP method")
			errors.Details(err)["route"] = name
			errors.Details(err)["path"] = path
			return err
		}

		if ro.GetHandler != nil {
			err := errors.New("non-API handler already exists")
			errors.Details(err)["route"] = name
			errors.Details(err)["path"] = path
			return err
		}

		ro.GetHandler = handler
	}

	return nil
}

func (r *Router) recv(w http.ResponseWriter, req *http.Request) {
	if rcv := recover(); rcv != nil {
		r.Panic(w, req, rcv)
	}
}

// TODO: Compile all regexes into one large regex.

// ServeHTTP matches the route for the given request based on URL
// path, extracts Params from the path, and calls route's handler for
// the HTTP method.
//
// If no route matches URL path, NotFound is called, if defined, or
// the request is replied with the 404 (not found) HTTP code error.
//
// If the route does not support used HTTP method, MethodNotAllowed
// is called, if defined, or the request is replied with the
// 405 (method not allowed) HTTP code error.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if r.Panic != nil {
		defer r.recv(w, req)
	}

	_, handler, params, errE := r.get(req)
	var e *MethodNotAllowedError
	if errors.Is(errE, errNotFound) {
		if r.NotFound != nil {
			r.NotFound(w, req)
		} else {
			Error(w, req, http.StatusNotFound)
		}
		return
	} else if errors.As(errE, &e) {
		if r.MethodNotAllowed != nil {
			r.MethodNotAllowed(w, req, params, e.Allow)
		} else {
			w.Header().Add("Allow", strings.Join(e.Allow, ", "))
			Error(w, req, http.StatusMethodNotAllowed)
		}
		return
	} else if errE != nil {
		// This should not happen.
		panic(errE)
	}

	handler(w, req, params)
}

// TODO: Make Router.Get which returns a public struct with handler, params, and some (all?) information from route.
//       Also make sentinel errors public. Keep private Router.get to not have to allocate a new struct every time.

func (r *Router) get(req *http.Request) (*route, Handler, Params, errors.E) {
	path := req.URL.Path

	api := false
	if path == "/api" {
		api = true
		path = "/"
	} else if path == "/api/" {
		return nil, nil, nil, errors.WithStack(errNotFound)
	} else if strings.HasPrefix(path, "/api/") {
		api = true
		path = strings.TrimPrefix(path, "/api")
	}

	for _, matcher := range r.matchers {
		match := matcher.Regexp.FindStringSubmatch(path)
		if match == nil {
			continue
		}

		params := matcher.GetParams(match)

		var handler Handler
		if api {
			if len(matcher.Route.APIHandlers) == 0 {
				// We exit search early.
				break
			}
			var ok bool
			handler, ok = matcher.Route.APIHandlers[req.Method]
			if !ok {
				allow := []string{}
				for method := range matcher.Route.APIHandlers {
					allow = append(allow, method)
				}
				sort.Strings(allow)

				return matcher.Route, nil, params, errors.WithStack(&MethodNotAllowedError{
					Allow: allow,
				})
			}
		} else {
			if matcher.Route.GetHandler == nil {
				// We exit search early.
				break
			}
			if req.Method != http.MethodGet && req.Method != http.MethodHead {
				return matcher.Route, nil, params, errors.WithStack(&MethodNotAllowedError{
					Allow: []string{"GET", "HEAD"},
				})
			}
			handler = matcher.Route.GetHandler
		}

		return matcher.Route, handler, params, nil
	}

	return nil, nil, nil, errors.WithStack(errNotFound)
}

func (r *Router) reverse(name string, params Params, qs url.Values, api bool) (string, errors.E) {
	ro, ok := r.routes[name]
	if !ok {
		err := errors.New("route does not exist")
		errors.Details(err)["route"] = name
		return "", err
	}
	if api && len(ro.APIHandlers) == 0 {
		err := errors.New("route has no API handlers")
		errors.Details(err)["route"] = name
		return "", err
	}
	if !api && ro.GetHandler == nil {
		err := errors.New("route has no GET handler")
		errors.Details(err)["route"] = name
		return "", err
	}

	var res strings.Builder

	if api {
		res.WriteString("/api")
	}

	for _, segment := range ro.Segments {
		if !segment.Parameter {
			res.WriteString("/")
			res.WriteString(segment.Value)
			continue
		}

		val := params[segment.Value]
		if val == "" {
			err := errors.New("parameter is missing")
			errors.Details(err)["parameter"] = segment.Value
			errors.Details(err)["route"] = name
			return "", err
		}

		res.WriteString("/")
		res.WriteString(val)
	}

	if len(params) > ro.Parameters.Cardinality() {
		paramsSet := mapset.NewThreadUnsafeSet[string]()
		for key := range params {
			paramsSet.Add(key)
		}
		extraParameters := paramsSet.Difference(ro.Parameters)
		err := errors.New("extra parameters")
		errors.Details(err)["extra"] = extraParameters.ToSlice()
		errors.Details(err)["route"] = name
		return "", err
	}

	// For API routes we already wrote "/api" which is what we want when there are no segments.
	if res.Len() == 0 {
		res.WriteString("/")
	}

	if len(qs) > 0 {
		res.WriteString("?")
		if r.EncodeQuery != nil {
			res.WriteString(r.EncodeQuery(qs))
		} else {
			res.WriteString(qs.Encode())
		}
	}

	return res.String(), nil
}

// Reverse constructs the path and query string portion of an URL based on the route name,
// Params, and query string values.
func (r *Router) Reverse(name string, params Params, qs url.Values) (string, errors.E) {
	return r.reverse(name, params, qs, false)
}

// ReverseAPI constructs the path and query string portion of an URL for API calls
// based on the route name, Params, and query string values.
func (r *Router) ReverseAPI(name string, params Params, qs url.Values) (string, errors.E) {
	return r.reverse(name, params, qs, true)
}
