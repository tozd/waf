package waf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/errors"
)

func TestParsePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		inputPath      string
		expectedResult []pathSegment
		expectedError  string
	}{
		{
			inputPath: "/users/:id/posts",
			expectedResult: []pathSegment{
				{Value: "users", Parameter: false},
				{Value: "id", Parameter: true},
				{Value: "posts", Parameter: false},
			},
			expectedError: "",
		},
		{
			inputPath: "/profile",
			expectedResult: []pathSegment{
				{Value: "profile", Parameter: false},
			},
			expectedError: "",
		},
		{
			inputPath:      "users/posts",
			expectedResult: nil,
			expectedError:  `path does not start with "/"`,
		},
		{
			inputPath:      "/users//posts",
			expectedResult: nil,
			expectedError:  "path has an empty part",
		},
		{
			inputPath:      "/users/*filepath", // Not supported by Vue Router, but by httprouter.
			expectedResult: nil,
			expectedError:  "path contains unsupported characters",
		},
		{
			inputPath:      "/:orderId(\\d+)",
			expectedResult: nil,
			expectedError:  "path contains unsupported characters",
		},
		{
			inputPath:      "/:chapters+",
			expectedResult: nil,
			expectedError:  "path contains unsupported characters",
		},
		{
			inputPath:      "/:chapters*",
			expectedResult: nil,
			expectedError:  "path contains unsupported characters",
		},
		{
			inputPath:      "/:chapters(\\d+)+",
			expectedResult: nil,
			expectedError:  "path contains unsupported characters",
		},
		{
			inputPath:      "/:chapters(\\d+)*",
			expectedResult: nil,
			expectedError:  "path contains unsupported characters",
		},
		{
			inputPath:      "/users/:userId?",
			expectedResult: nil,
			expectedError:  "path contains unsupported characters",
		},
		{
			inputPath:      "/users/:userId(\\d+)?",
			expectedResult: nil,
			expectedError:  "path contains unsupported characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.inputPath, func(t *testing.T) {
			t.Parallel()

			segments, errE := parsePath(tt.inputPath)
			assert.Equal(t, tt.expectedResult, segments)
			if tt.expectedError != "" {
				assert.EqualError(t, errE, tt.expectedError)
			} else {
				require.NoError(t, errE, "% -+#.1v", errE)
			}
		})
	}
}

func TestCompileRegexp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		inputSegments  []pathSegment
		expectedRegexp string
		inputMatch     []string
		expectedParams Params
		expectedError  string
	}{
		{
			inputSegments: []pathSegment{
				{Value: "users", Parameter: false},
				{Value: "id", Parameter: true},
				{Value: "posts", Parameter: false},
			},
			expectedRegexp: `^/users/([^/]+)/posts$`,
			inputMatch:     []string{"", "123"},
			expectedParams: Params{
				"id": "123",
			},
			expectedError: "",
		},
		{
			inputSegments: []pathSegment{
				{Value: "profile", Parameter: false},
			},
			expectedRegexp: `^/profile$`,
			inputMatch:     []string{""},
			expectedParams: Params{},
			expectedError:  "",
		},
	}

	for k, tt := range tests {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			t.Parallel()

			re, paramMapFunc, errE := compileRegexp(tt.inputSegments)

			if tt.expectedError != "" {
				assert.Nil(t, re)
				assert.Nil(t, paramMapFunc)
				assert.EqualError(t, errE, tt.expectedError)
			} else {
				require.NoError(t, errE, "% -+#.1v", errE)
				if assert.NotNil(t, re) {
					assert.Equal(t, tt.expectedRegexp, re.String())
				}
				if assert.NotNil(t, paramMapFunc) {
					params := paramMapFunc(tt.inputMatch)
					assert.Equal(t, tt.expectedParams, params)
				}
			}
		})
	}
}

type testRoute struct {
	routeName string
	method    string
	path      string
	api       bool
}

func TestRouterHandle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		description        string
		routes             []testRoute
		expectedError      string
		expectedRoutes     map[string]*route
		expectedMatchCount int
	}{
		{
			description: "Adding one route with both API and non-API",
			routes: []testRoute{
				{
					routeName: "UsersPosts",
					method:    http.MethodGet,
					path:      "/users/:id/posts",
					api:       false,
				},
				{
					routeName: "UsersPosts",
					method:    http.MethodPost,
					path:      "/users/:id/posts",
					api:       true,
				},
			},
			expectedError: "",
		},
		{
			description: "Adding one API route, but different paths",
			routes: []testRoute{
				{
					routeName: "UsersPosts",
					method:    http.MethodGet,
					path:      "/users/:id/posts",
					api:       true,
				},
				{
					routeName: "UsersPosts",
					method:    http.MethodGet,
					path:      "/users/posts",
					api:       true,
				},
			},
			expectedError: "route with different paths",
		},
		{
			description: "Adding one non-API route, but different paths",
			routes: []testRoute{
				{
					routeName: "UsersPosts",
					method:    http.MethodGet,
					path:      "/users/:id/posts",
					api:       false,
				},
				{
					routeName: "UsersPosts",
					method:    http.MethodGet,
					path:      "/users/posts",
					api:       false,
				},
			},
			expectedError: "route with different paths",
		},
		{
			description: "Adding one route with both API and non-API, but different paths",
			routes: []testRoute{
				{
					routeName: "UsersPosts",
					method:    http.MethodGet,
					path:      "/users/:id/posts",
					api:       false,
				},
				{
					routeName: "UsersPosts",
					method:    http.MethodPost,
					path:      "/users/posts",
					api:       true,
				},
			},
			expectedError: "route with different paths",
		},
		{
			description: "Adding two routes with same path",
			routes: []testRoute{
				{
					routeName: "UsersPosts",
					method:    http.MethodGet,
					path:      "/users/:id/posts",
					api:       false,
				},
				{
					routeName: "UsersPostsExtra",
					method:    http.MethodGet,
					path:      "/users/:id/posts",
					api:       false,
				},
			},
			expectedError: "path with different routes",
		},
		{
			description: "Adding two routes with same path (API and non-API)",
			routes: []testRoute{
				{
					routeName: "UsersPosts",
					method:    http.MethodGet,
					path:      "/users/:id/posts",
					api:       false,
				},
				{
					routeName: "UsersPostsExtra",
					method:    http.MethodPost,
					path:      "/users/:id/posts",
					api:       true,
				},
			},
			expectedError: "path with different routes",
		},
		{
			description: "Adding duplicate non-API GET routes",
			routes: []testRoute{
				{
					routeName: "UsersPosts",
					method:    http.MethodGet,
					path:      "/users/:id/posts",
					api:       false,
				},
				{
					routeName: "UsersPosts",
					method:    http.MethodGet,
					path:      "/users/:id/posts",
					api:       false,
				},
			},
			expectedError: "non-API GET handler already exists",
		},
		{
			description: "Adding duplicate non-API OPTIONS routes",
			routes: []testRoute{
				{
					routeName: "UsersPosts",
					method:    http.MethodOptions,
					path:      "/users/:id/posts",
					api:       false,
				},
				{
					routeName: "UsersPosts",
					method:    http.MethodOptions,
					path:      "/users/:id/posts",
					api:       false,
				},
			},
			expectedError: "non-API OPTIONS handler already exists",
		},
		{
			description: "Allow non-API GET and OPTIONS routes",
			routes: []testRoute{
				{
					routeName: "UsersPosts",
					method:    http.MethodGet,
					path:      "/users/:id/posts",
					api:       false,
				},
				{
					routeName: "UsersPosts",
					method:    http.MethodOptions,
					path:      "/users/:id/posts",
					api:       false,
				},
			},
			expectedError: "",
		},
		{
			description: "Adding duplicate API routes",
			routes: []testRoute{
				{
					routeName: "UsersPosts",
					method:    http.MethodGet,
					path:      "/users/:id/posts",
					api:       true,
				},
				{
					routeName: "UsersPosts",
					method:    http.MethodGet,
					path:      "/users/:id/posts",
					api:       true,
				},
			},
			expectedError: "API handler already exists",
		},
		{
			description: "Adding non-API non-GET/OPTIONS handler",
			routes: []testRoute{
				{
					routeName: "UsersPosts",
					method:    http.MethodPost,
					path:      "/users/:id/posts",
					api:       false,
				},
			},
			expectedError: "non-API handler must use GET or OPTIONS HTTP method",
		},
		{
			description: "Adding a handler with an invalid path",
			routes: []testRoute{
				{
					routeName: "InvalidPath",
					method:    http.MethodGet,
					path:      "invalid-path",
					api:       false,
				},
			},
			expectedError: `parsing path failed: path does not start with "/"`,
		},
		{
			description: "Adding a handler with an invalid path (empty path)",
			routes: []testRoute{
				{
					routeName: "EmptyPath",
					method:    http.MethodGet,
					path:      "",
					api:       false,
				},
			},
			expectedError: `parsing path failed: path does not start with "/"`,
		},
		{
			description: "Adding a handler with duplicate params in path",
			routes: []testRoute{
				{
					routeName: "DuplicateParams",
					method:    http.MethodGet,
					path:      "/users/:id/posts/:id",
					api:       false,
				},
			},
			expectedError: "duplicate parameter",
		},
		{
			description: "Adding a handler with empty name",
			routes: []testRoute{
				{
					routeName: "",
					method:    http.MethodGet,
					path:      "/users/:id/posts",
					api:       false,
				},
			},
			expectedError: "name cannot be empty",
		},
		{
			description: "Adding API route with /api path",
			routes: []testRoute{
				{
					routeName: "UsersPosts",
					method:    http.MethodPost,
					path:      "/api/users/:id/posts",
					api:       true,
				},
			},
			expectedError: "path cannot start with /api",
		},
		{
			description: "Adding API /api route",
			routes: []testRoute{
				{
					routeName: "UsersPosts",
					method:    http.MethodPost,
					path:      "/api",
					api:       true,
				},
			},
			expectedError: "path cannot start with /api",
		},
		{
			description: "Adding non-API route with /api path",
			routes: []testRoute{
				{
					routeName: "UsersPosts",
					method:    http.MethodGet,
					path:      "/api/users/:id/posts",
					api:       false,
				},
			},
			expectedError: "path cannot start with /api",
		},
		{
			description: "Adding non-API /api route",
			routes: []testRoute{
				{
					routeName: "UsersPosts",
					method:    http.MethodGet,
					path:      "/api",
					api:       false,
				},
			},
			expectedError: "path cannot start with /api",
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			t.Parallel()

			r := &Router{}

			var errE errors.E
			for _, route := range tt.routes {
				errE = r.Handle(route.routeName, route.method, route.path, route.api, func(http.ResponseWriter, *http.Request, Params) {})
			}

			if tt.expectedError != "" {
				assert.EqualError(t, errE, tt.expectedError)
			} else {
				require.NoError(t, errE, "% -+#.1v", errE)
				for _, route := range tt.routes {
					assert.NotNil(t, r.routes[route.routeName])
				}
			}
		})
	}
}

func TestRouterReverse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		description   string
		path          string
		api           bool
		encodeQuery   func(qs url.Values) string
		params        Params
		qs            url.Values
		inputAPI      bool
		expectedPath  string
		expectedError string
	}{
		{
			description:   "Non-API path",
			path:          "/users/:id/posts",
			api:           false,
			params:        Params{"id": "123"},
			qs:            url.Values{},
			inputAPI:      false,
			encodeQuery:   nil,
			expectedPath:  "/users/123/posts",
			expectedError: "",
		},
		{
			description:   "API path",
			path:          "/users/:id/posts",
			api:           true,
			params:        Params{"id": "123"},
			qs:            url.Values{},
			inputAPI:      true,
			encodeQuery:   nil,
			expectedPath:  "/api/users/123/posts",
			expectedError: "",
		},
		{
			description:   "Non-API path with query string",
			path:          "/users/:id/posts",
			api:           false,
			params:        Params{"id": "123"},
			qs:            url.Values{"param1": {"value1"}, "param2": {"value2 % !@#"}},
			inputAPI:      false,
			encodeQuery:   nil,
			expectedPath:  "/users/123/posts?param1=value1&param2=value2+%25+%21%40%23",
			expectedError: "",
		},
		{
			description:   "API path with query string",
			path:          "/users/:id/posts",
			api:           true,
			params:        Params{"id": "123"},
			qs:            url.Values{"param1": {"value1"}, "param2": {"value2 % !@#"}},
			inputAPI:      true,
			encodeQuery:   nil,
			expectedPath:  "/api/users/123/posts?param1=value1&param2=value2+%25+%21%40%23",
			expectedError: "",
		},
		{
			description:   "Path with missing parameters",
			path:          "/users/:id/posts",
			api:           false,
			params:        Params{},
			qs:            url.Values{},
			inputAPI:      false,
			encodeQuery:   nil,
			expectedPath:  "",
			expectedError: "parameter is missing",
		},
		{
			description:   "Path with empty parameters",
			path:          "/users/:id/posts",
			api:           false,
			params:        Params{"id": ""},
			qs:            url.Values{},
			inputAPI:      false,
			encodeQuery:   nil,
			expectedPath:  "",
			expectedError: "parameter is missing",
		},
		{
			description:   "Path with extra parameters",
			path:          "/users/:id/posts",
			api:           false,
			params:        Params{"id": "123", "extra": "foobar"},
			qs:            url.Values{},
			inputAPI:      false,
			encodeQuery:   nil,
			expectedPath:  "",
			expectedError: "extra parameters",
		},
		{
			description:   "Root path",
			path:          "/",
			api:           false,
			params:        Params{},
			qs:            url.Values{},
			inputAPI:      false,
			encodeQuery:   nil,
			expectedPath:  "/",
			expectedError: "",
		},
		{
			description:   "Root path",
			path:          "/",
			api:           true,
			params:        Params{},
			qs:            url.Values{},
			inputAPI:      true,
			encodeQuery:   nil,
			expectedPath:  "/api",
			expectedError: "",
		},
		{
			description:   "Non-API path but API requested",
			path:          "/users/:id/posts",
			api:           false,
			params:        Params{},
			qs:            url.Values{},
			inputAPI:      true,
			encodeQuery:   nil,
			expectedPath:  "",
			expectedError: "route has no API handlers",
		},
		{
			description:   "API path but non-API requested",
			path:          "/users/:id/posts",
			api:           true,
			params:        Params{},
			qs:            url.Values{},
			inputAPI:      false,
			encodeQuery:   nil,
			expectedPath:  "",
			expectedError: "route has no GET or OPTIONS handler",
		},
		{
			description: "Path with custom query string",
			path:        "/users/:id/posts",
			api:         false,
			params:      Params{"id": "123"},
			qs:          url.Values{"param1": {"value1"}, "param2": {"value2"}},
			inputAPI:    false,
			encodeQuery: func(qs url.Values) string {
				var buf strings.Builder
				buf.WriteString(url.QueryEscape("param2"))
				buf.WriteByte('=')
				buf.WriteString(url.QueryEscape(qs.Get("param2")))
				buf.WriteByte('&')
				buf.WriteString(url.QueryEscape("param1"))
				buf.WriteByte('=')
				buf.WriteString(url.QueryEscape(qs.Get("param1")))
				return buf.String()
			},
			expectedPath:  "/users/123/posts?param2=value2&param1=value1",
			expectedError: "",
		},
		{
			description:   "Path with empty query string",
			path:          "/users/:id/posts",
			api:           false,
			params:        Params{"id": "123"},
			qs:            url.Values{"param1": {}},
			inputAPI:      false,
			encodeQuery:   nil,
			expectedPath:  "/users/123/posts",
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			t.Parallel()

			r := &Router{
				EncodeQuery: tt.encodeQuery,
			}

			errE := r.Handle("PathName", http.MethodGet, tt.path, tt.api, func(http.ResponseWriter, *http.Request, Params) {})
			require.NoError(t, errE, "% -+#.1v", errE)

			path, errE := r.reverse("PathName", tt.params, tt.qs, tt.inputAPI)

			if tt.expectedError != "" {
				assert.EqualError(t, errE, tt.expectedError)
			} else {
				require.NoError(t, errE, "% -+#.1v", errE)
				assert.Equal(t, tt.expectedPath, path)
			}
		})
	}
}

func TestRouterMissing(t *testing.T) {
	t.Parallel()

	r := &Router{}

	errE := r.Handle("PathName", http.MethodGet, "/", false, func(http.ResponseWriter, *http.Request, Params) {})
	require.NoError(t, errE, "% -+#.1v", errE)

	_, errE = r.reverse("PathNameMissing", nil, nil, false)
	assert.EqualError(t, errE, "route does not exist")

	errE = r.Handle("HandlerMissing", http.MethodGet, "/missing", false, nil)
	assert.EqualError(t, errE, "handler cannot be nil")
}

func TestRouterErrorHandlers(t *testing.T) {
	t.Parallel()

	r := &Router{
		NotFound: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(480)
		},
		MethodNotAllowed: func(w http.ResponseWriter, _ *http.Request, _ Params, _ []string) {
			w.WriteHeader(490)
		},
	}

	errE := r.Handle("PathName", http.MethodGet, "/", false, func(w http.ResponseWriter, _ *http.Request, _ Params) {
		w.WriteHeader(http.StatusOK)
	})
	require.NoError(t, errE, "% -+#.1v", errE)

	errE = r.Handle("PathName", http.MethodGet, "/", true, func(w http.ResponseWriter, _ *http.Request, _ Params) {
		w.WriteHeader(http.StatusOK)
	})
	require.NoError(t, errE, "% -+#.1v", errE)

	tests := []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/", http.StatusOK},
		{http.MethodGet, "/api", http.StatusOK},
		{http.MethodGet, "/api/", 480},
		{http.MethodGet, "/foobar", 480},
		{http.MethodGet, "/api/foobar", 480},
		{http.MethodPost, "/api/foobar", 480},
		{http.MethodPost, "/api", 490},
		{http.MethodPost, "/api/", 480},
		{http.MethodPost, "/", 490},
	}

	for k, tt := range tests {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(tt.method, tt.path, nil))
			assert.Equal(t, tt.status, w.Code)
		})
	}
}

func TestRouterServeHTTP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		description          string
		method               string
		path                 string
		api                  bool
		handler              Handler
		request              *http.Request
		expectedStatus       int
		expectedResponseBody string
		expectedAllowHeader  string
		expectPanic          string
	}{
		{
			description:          "NotFound handler test",
			method:               http.MethodGet,
			path:                 "/",
			api:                  false,
			handler:              func(_ http.ResponseWriter, _ *http.Request, _ Params) {},
			request:              httptest.NewRequest(http.MethodGet, "/notfound", nil),
			expectedStatus:       http.StatusNotFound,
			expectedResponseBody: "Not Found\n",
			expectedAllowHeader:  "",
			expectPanic:          "",
		},
		{
			description:          "NotFound non-API handler test",
			method:               http.MethodGet,
			path:                 "/",
			api:                  false,
			handler:              func(_ http.ResponseWriter, _ *http.Request, _ Params) {},
			request:              httptest.NewRequest(http.MethodGet, "/api", nil),
			expectedStatus:       http.StatusNotFound,
			expectedResponseBody: "Not Found\n",
			expectedAllowHeader:  "",
			expectPanic:          "",
		},
		{
			description:          "NotFound non-API handler test with /",
			method:               http.MethodGet,
			path:                 "/",
			api:                  false,
			handler:              func(_ http.ResponseWriter, _ *http.Request, _ Params) {},
			request:              httptest.NewRequest(http.MethodGet, "/api/", nil),
			expectedStatus:       http.StatusNotFound,
			expectedResponseBody: "Not Found\n",
			expectedAllowHeader:  "",
			expectPanic:          "",
		},
		{
			description:          "NotFound API handler test",
			method:               http.MethodGet,
			path:                 "/",
			api:                  true,
			handler:              func(_ http.ResponseWriter, _ *http.Request, _ Params) {},
			request:              httptest.NewRequest(http.MethodGet, "/", nil),
			expectedStatus:       http.StatusNotFound,
			expectedResponseBody: "Not Found\n",
			expectedAllowHeader:  "",
			expectPanic:          "",
		},
		{
			description:          "NotFound API handler test with /",
			method:               http.MethodGet,
			path:                 "/",
			api:                  true,
			handler:              func(_ http.ResponseWriter, _ *http.Request, _ Params) {},
			request:              httptest.NewRequest(http.MethodGet, "/api/", nil),
			expectedStatus:       http.StatusNotFound,
			expectedResponseBody: "Not Found\n",
			expectedAllowHeader:  "",
			expectPanic:          "",
		},
		{
			description:          "NotFound API handler test",
			method:               http.MethodGet,
			path:                 "/posts",
			api:                  true,
			handler:              func(_ http.ResponseWriter, _ *http.Request, _ Params) {},
			request:              httptest.NewRequest(http.MethodGet, "/api/posts/abcd", nil),
			expectedStatus:       http.StatusNotFound,
			expectedResponseBody: "Not Found\n",
			expectedAllowHeader:  "",
			expectPanic:          "",
		},
		{
			description:          "NotFound API handler test with /",
			method:               http.MethodGet,
			path:                 "/posts",
			api:                  true,
			handler:              func(_ http.ResponseWriter, _ *http.Request, _ Params) {},
			request:              httptest.NewRequest(http.MethodGet, "/api/posts/", nil),
			expectedStatus:       http.StatusNotFound,
			expectedResponseBody: "Not Found\n",
			expectedAllowHeader:  "",
			expectPanic:          "",
		},
		{
			description:          "MethodNotAllowed handler test",
			method:               http.MethodGet,
			path:                 "/users/:id/posts",
			api:                  false,
			handler:              func(_ http.ResponseWriter, _ *http.Request, _ Params) {},
			request:              httptest.NewRequest(http.MethodPost, "/users/123/posts", nil),
			expectedStatus:       http.StatusMethodNotAllowed,
			expectedResponseBody: "Method Not Allowed\n",
			expectedAllowHeader:  "GET, HEAD",
			expectPanic:          "",
		},
		{
			description:          "Invalid method API request",
			method:               http.MethodPost,
			path:                 "/users/:id/posts",
			api:                  true,
			handler:              func(_ http.ResponseWriter, _ *http.Request, _ Params) {},
			request:              httptest.NewRequest(http.MethodPatch, "/api/users/123/posts", nil),
			expectedStatus:       http.StatusMethodNotAllowed,
			expectedResponseBody: "Method Not Allowed\n",
			expectedAllowHeader:  "POST",
			expectPanic:          "",
		},
		{
			description:          "API does not mean non-API exists",
			method:               http.MethodPost,
			path:                 "/users/:id/posts",
			api:                  true,
			handler:              func(_ http.ResponseWriter, _ *http.Request, _ Params) {},
			request:              httptest.NewRequest(http.MethodGet, "/users/123/posts", nil),
			expectedStatus:       http.StatusNotFound,
			expectedResponseBody: "Not Found\n",
			expectedAllowHeader:  "",
			expectPanic:          "",
		},
		{
			description: "Valid non-API route with a GET request",
			method:      http.MethodGet,
			path:        "/users/:id/posts",
			api:         false,
			handler: func(w http.ResponseWriter, _ *http.Request, _ Params) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("Handler for route"))
			},
			request:              httptest.NewRequest(http.MethodGet, "/users/123/posts", nil),
			expectedStatus:       http.StatusOK,
			expectedResponseBody: "Handler for route",
			expectedAllowHeader:  "",
			expectPanic:          "",
		},
		{
			description:          "Valid non-API route with a POST non-API request",
			method:               http.MethodGet,
			path:                 "/users/:id/posts",
			api:                  false,
			handler:              func(_ http.ResponseWriter, _ *http.Request, _ Params) {},
			request:              httptest.NewRequest(http.MethodPost, "/users/123/posts", nil),
			expectedStatus:       http.StatusMethodNotAllowed,
			expectedResponseBody: "Method Not Allowed\n",
			expectedAllowHeader:  "GET, HEAD",
			expectPanic:          "",
		},
		{
			description:          "Valid non-API route with a POST API request",
			method:               http.MethodGet,
			path:                 "/users/:id/posts",
			api:                  false,
			handler:              func(_ http.ResponseWriter, _ *http.Request, _ Params) {},
			request:              httptest.NewRequest(http.MethodPost, "/api/users/123/posts", nil),
			expectedStatus:       http.StatusNotFound,
			expectedResponseBody: "Not Found\n",
			expectedAllowHeader:  "",
			expectPanic:          "",
		},
		{
			description: "Valid API route with a POST request",
			method:      http.MethodPost,
			path:        "/users/:id/posts",
			api:         true,
			handler: func(w http.ResponseWriter, _ *http.Request, _ Params) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte("Handler for route"))
			},
			request:              httptest.NewRequest(http.MethodPost, "/api/users/123/posts", nil),
			expectedStatus:       http.StatusCreated,
			expectedResponseBody: "Handler for route",
			expectedAllowHeader:  "",
			expectPanic:          "",
		},
		{
			description: "Handler panics",
			method:      http.MethodPost,
			path:        "/users/:id/posts",
			api:         true,
			handler: func(_ http.ResponseWriter, _ *http.Request, _ Params) {
				panic(errors.New("panic error"))
			},
			request:              httptest.NewRequest(http.MethodPost, "/api/users/123/posts", nil),
			expectedStatus:       http.StatusInternalServerError,
			expectedResponseBody: "",
			expectedAllowHeader:  "",
			expectPanic:          "panic error",
		},
		{
			description: "OPTIONS non-API handler",
			method:      http.MethodOptions,
			path:        "/",
			api:         false,
			handler: func(w http.ResponseWriter, _ *http.Request, _ Params) {
				w.WriteHeader(345)
			},
			request:              httptest.NewRequest(http.MethodOptions, "/", nil),
			expectedStatus:       345,
			expectedResponseBody: "",
			expectedAllowHeader:  "",
			expectPanic:          "",
		},
		{
			description:          "MethodNotAllowed OPTIONS handler test",
			method:               http.MethodOptions,
			path:                 "/users/:id/posts",
			api:                  false,
			handler:              func(_ http.ResponseWriter, _ *http.Request, _ Params) {},
			request:              httptest.NewRequest(http.MethodPost, "/users/123/posts", nil),
			expectedStatus:       http.StatusMethodNotAllowed,
			expectedResponseBody: "Method Not Allowed\n",
			expectedAllowHeader:  "OPTIONS",
			expectPanic:          "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			t.Parallel()

			var panicked interface{}

			r := &Router{
				Panic: func(w http.ResponseWriter, _ *http.Request, err interface{}) {
					panicked = err
					w.WriteHeader(http.StatusInternalServerError)
				},
			}
			errE := r.Handle("PathName", tt.method, tt.path, tt.api, tt.handler)
			require.NoError(t, errE, "% -+#.1v", errE)

			w := httptest.NewRecorder()
			r.ServeHTTP(w, tt.request)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Equal(t, tt.expectedResponseBody, w.Body.String())
			assert.Equal(t, tt.expectedAllowHeader, w.Header().Get("Allow"))
			if tt.expectPanic != "" {
				assert.Equal(t, tt.expectPanic, fmt.Sprintf("%s", panicked))
			}
		})
	}
}

func TestRouterGet(t *testing.T) {
	t.Parallel()

	hRan := false
	h := func(_ http.ResponseWriter, _ *http.Request, _ Params) {
		hRan = true
	}
	r := &Router{}
	errE := r.Handle("PathName", http.MethodGet, "/foobar/:x", false, h)
	require.NoError(t, errE, "% -+#.1v", errE)
	_, errE = r.Get("/foobar/123", http.MethodPost)
	var e *MethodNotAllowedError
	assert.ErrorAs(t, errE, &e)
	assert.Equal(t, []string{http.MethodGet, http.MethodHead}, e.Allow)
	_, errE = r.Get("/none", http.MethodGet)
	assert.ErrorIs(t, errE, ErrNotFound)
	route, errE := r.Get("/foobar/123", http.MethodGet)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, "PathName", route.Name)
	assert.Equal(t, Params{"x": "123"}, route.Params)
	require.NotNil(t, route.Handler)
	route.Handler(nil, nil, nil)
	assert.True(t, hRan)
}
