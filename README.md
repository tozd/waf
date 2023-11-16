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
- Supports [server timing](https://www.w3.org/TR/server-timing/) measurements and response header.
- Supports structured metadata in a response header encoded based on
  [RFC 8941](https://www.rfc-editor.org/rfc/rfc8941).
- Supports web sockets.
- Can serve multiple sites/configurations.

## Installation

This is a Go package. You can add it to your project using `go get`:

```sh
go get gitlab.com/tozd/waf
```

It requires Go 1.21 or newer.

## Usage

See full package documentation on [pkg.go.dev](https://pkg.go.dev/gitlab.com/tozd/waf#section-documentation).

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
