# Web application framework

[![pkg.go.dev](https://pkg.go.dev/badge/gitlab.com/tozd/waf)](https://pkg.go.dev/gitlab.com/tozd/waf)
[![Go Report Card](https://goreportcard.com/badge/gitlab.com/tozd/waf)](https://goreportcard.com/report/gitlab.com/tozd/waf)
[![pipeline status](https://gitlab.com/tozd/waf/badges/main/pipeline.svg?ignore_skipped=true)](https://gitlab.com/tozd/waf/-/pipelines)
[![coverage report](https://gitlab.com/tozd/waf/badges/main/coverage.svg)](https://gitlab.com/tozd/waf/-/graphs/main/charts)

A Go package providing a Vue-compatible web application framework.
It combines common patterns and best practices into a high-level API abstraction
so that you can focus on building apps.

Features:

- Routes are matched in the same way as [Vue Router](https://router.vuejs.org/) and supports
  having a single source of truth for both frontend and backend routes.
- Integrates well with [Vite](https://vitejs.dev/) development by proxying requests to Vite.
- Production ready and can be exposed directly on open Internet.
- Supports HTTP2 and TLS out of the box. TLS certificates can be automatically obtained
  (and updated) using [Let's Encrypt](https://letsencrypt.org/) (when running
  accessible from the Internet).
- Efficient serving of static files from memory with compression, caching, and HTTP range requests.
- Makes [canonical log lines](https://brandur.org/canonical-log-lines) for each request.
- Supports metrics in context and [server timing](https://www.w3.org/TR/server-timing/) measurements in response header.
- Supports structured metadata in a response header encoded based on
  [RFC 8941](https://www.rfc-editor.org/rfc/rfc8941).
- Supports [web sockets](https://en.wikipedia.org/wiki/WebSocket).
- Can serve multiple sites/configurations.
- Supports [CORS](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing) handling per route.

## Installation

This is a Go package. You can add it to your project using `go get`:

```sh
go get gitlab.com/tozd/waf
```

It requires Go 1.24 or newer.

Automatic media type detection uses file extensions and a file extension database has to be available
on the system.
On Alpine this can be `mailcap` package.
On Debina/Ubuntu `media-types` package.

## Usage

See full package documentation on [pkg.go.dev](https://pkg.go.dev/gitlab.com/tozd/waf#section-documentation).

See [examples](./_examples/) to see how can components combine together into an app.

### Local execution

To run apps locally, you need a HTTPS TLS certificate (as required by HTTP2). When running locally
you can use [mkcert](https://github.com/FiloSottile/mkcert), a tool to create a local CA
keypair which is then used to create a TLS certificate.

```sh
go install filippo.io/mkcert@latest
mkcert -install
mkcert localhost 127.0.0.1 ::1
```

This creates two files, `localhost+2.pem` and l`ocalhost+2-key.pem`, which you can then pass in
HTTPS configuration to Waf.

### Vite integration

During development you might want to use [Vite](https://vitejs.dev/).
Vite compiles frontend files and serves them. It also watches for changes in frontend files,
recompiles them, and hot-reloads the frontend as necessary.

After installing dependencies and running `vite serve`, Vite listens on `http://localhost:5173`.
Open [https://localhost:8080/](https://localhost:8080/) in your browser, which will connect
you to the backend which then proxies unknown requests (non-API requests) to Vite, the frontend.

If you want your handler to proxy to Vite during development, you can do something like:

```go
func (s *Service) HomeGet(w http.ResponseWriter, req *http.Request, _ waf.Params) {
  if s.ProxyStaticTo != "" {
    s.Proxy(w, req)
    return
  }

  // ... your handler ...
}
```

### Vue Router integration

You configure routes and their handlers through
[Service's Routes](https://pkg.go.dev/gitlab.com/tozd/waf#Service) field:

```go
import "gitlab.com/tozd/waf"

func newService() *Service {
  service := &Service{
    waf.Service[*waf.Site]{
      Routes: nil,
      RoutesPath: "/routes.json",
      // ... the rest ...
    },
  }

  service.Routes = map[string]waf.Route{
    "Home": {
      RouteOptions: waf.RouteOptions{
        Handlers: map[string]waf.Handler{
          http.MethodGet: service.HomeGet,
        },
      },
      Path: "/",
    },
  }

  return service
}
```

Because we configured `RoutesPath`, you can use then use same routes
in Vue Router as a single source of truth for routes.
On the frontend:

```ts
import { createRouter, createWebHistory } from "vue-router";

const routesMap = await fetch("/routes.json", {
  method: "GET",
  mode: "cors",
  credentials: "same-origin",
  referrer: document.location.href,
  referrerPolicy: "strict-origin-when-cross-origin",
}).then((response) => response.json());

const router = createRouter({
  history: createWebHistory(),
  routes: Object.entries(routesMap)
    .filter(([, route]) => route.handlers)
    .map(([name, route]) => ({
      path: route.path,
      name,
      component: () => import(`./views/${name}.vue`),
      props: true,
      strict: true,
    })),
});

const apiRouter = createRouter({
  history: createWebHistory(),
  routes: Object.entries(routesMap)
    .filter(([, route]) => route.api)
    .map(([name, route]) => ({
      path: route.path === "/" ? "/api" : `/api${route.path}`,
      name,
      component: () => null,
      props: true,
      strict: true,
    })),
});

router.apiResolve = apiRouter.resolve.bind(apiRouter);

// ... create the app, use router, and mount the app ...
```

You can then use `router.resolve` to resolve non-API routes and `router.apiResolve`
to resolve API routes.

## Why API paths have `/api` prefix and do not use content negotiation?

Content negotiated responses do not cache well.
[Browsers cache by path](https://bugs.chromium.org/p/chromium/issues/detail?id=1380505)
and ignore `Accept` header. This means that if your frontend requests both `text/html` and
`application/json` at same path only one of them will be cached and then if you then
repeat both requests, the request for non-cached content type might arrive first, invalidating
even the cached one. Browsers at least do not serve wrong content because Etag header
depends on the content itself so browsers detect cache mismatch.

## Related projects

There are many great projects doing similar things.
Waf's primarily goal is being compatible with [Vue Router](https://router.vuejs.org/)
and frontend development with [Vite](https://vitejs.dev/).

This package works well with [gitlab.com/tozd/go/zerolog](https://gitlab.com/tozd/go/zerolog)
(based on [zerolog](https://github.com/rs/zerolog)) and
[gitlab.com/tozd/go/cli](https://gitlab.com/tozd/go/cli) (based on
[Kong](https://github.com/alecthomas/kong)) packages.

## GitHub mirror

There is also a [read-only GitHub mirror available](https://github.com/tozd/waf),
if you need to fork the project there.
