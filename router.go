package waf

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"gitlab.com/tozd/go/errors"
)

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

// TODO: Support custom regex in params.
//       See: https://router.vuejs.org/guide/essentials/route-matching-syntax.html#custom-regex-in-params

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

type Params map[string]string

type Handler func(http.ResponseWriter, *http.Request, Params)

// TODO: Implement RedirectTrailingSlash = true
// TODO: Implement RedirectFixedPath = true.

type Router struct {
	NotFound         Handler
	MethodNotAllowed Handler
	Panic            func(w http.ResponseWriter, req *http.Request, err interface{})
	EncodeQuery      func(qs url.Values) string

	// A map between route name and routes.
	routes   map[string]*route
	matchers []matcher
}

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
					errors.Details(err)["name"] = segment.Value
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
			err := errors.New("route with different paths")
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

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if r.Panic != nil {
		defer r.recv(w, req)
	}

	path := req.URL.Path

	api := false
	if strings.HasPrefix(path, "/api/") {
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
			var ok bool
			handler, ok = matcher.Route.APIHandlers[req.Method]
			if !ok {
				allow := []string{}
				for method := range matcher.Route.APIHandlers {
					allow = append(allow, method)
				}
				w.Header().Add("Allow", strings.Join(allow, ", "))

				if r.MethodNotAllowed != nil {
					r.MethodNotAllowed(w, req, params)
				} else {
					Error(w, req, http.StatusMethodNotAllowed)
				}
				return
			}
		} else {
			if matcher.Route.GetHandler == nil {
				// We exit search early.
				break
			}
			if req.Method != http.MethodGet && req.Method != http.MethodHead {
				w.Header().Add("Allow", "GET, HEAD")

				if r.MethodNotAllowed != nil {
					r.MethodNotAllowed(w, req, params)
				} else {
					Error(w, req, http.StatusMethodNotAllowed)
				}
				return
			}
			handler = matcher.Route.GetHandler
		}

		handler(w, req, params)
		return
	}

	if r.NotFound != nil {
		r.NotFound(w, req, nil)
	} else {
		Error(w, req, http.StatusNotFound)
	}
}

func (r *Router) path(name string, params Params, qs url.Values, api bool) (string, errors.E) {
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
			errors.Details(err)["name"] = segment.Value
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

	if api {
		if res.String() == "/api" {
			res.WriteString("/")
		}
	} else {
		if res.Len() == 0 {
			res.WriteString("/")
		}
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

func (r *Router) Path(name string, params Params, qs url.Values) (string, errors.E) {
	return r.path(name, params, qs, false)
}

func (r *Router) APIPath(name string, params Params, qs url.Values) (string, errors.E) {
	return r.path(name, params, qs, true)
}
