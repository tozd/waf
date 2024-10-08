# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.19.0] - 2024-09-09

### Changed

- `DurationCounterMetric` logged rate is per second and not anymore per millisecond.
- Go 1.23 or newer is required.

## [0.18.1] - 2024-04-08

### Fixed

- Metrics API works when metrics are nil (e.g., not available in the context).
  All calls are noop.

## [0.18.0] - 2024-04-05

### Added

- `GetMetrics` and `MustGetMetrics` to access new metrics API through context.
- New metrics API supports durations, counters, counters with duration, and multiple durations.
  [#1](https://gitlab.com/tozd/waf/-/issues/1)

### Changed

- `Server-Timing` header is now always issued for all metrics as a trailer.

### Removed

- `github.com/tozd/go-server-timing` as a dependency. It cannot be used anymore to
  add metrics. Use `GetMetrics` and `MustGetMetrics` instead.

## [0.17.1] - 2024-04-01

### Fixed

- Do not reverse with just `?` for empty query strings.

## [0.17.0] - 2024-03-27

### Changed

- Change short CLI argument for development from `-d` to `-D`.

## [0.16.0] - 2024-03-19

### Changed

- Revert to use `url.Values` for query string values.

## [0.15.0] - 2024-03-19

### Changed

- Use encoder interface instead of `url.Values` for query string values.

## [0.14.0] - 2024-03-19

### Added

- `NotFoundWithError`.

### Fixed

- Add Kong tags on `Site`.

## [0.13.1] - 2024-03-19

### Fixed

- Add `Validate` on `Site`.

## [0.13.0] - 2024-03-10

### Changed

- Renamed `Service.Development` to `Service.ProxyStaticTo`.
- Renamed `Server.InDevelopment` to `Server.ProxyToInDevelopment`.

## [0.12.0] - 2024-03-10

### Added

- `developmentModeHelp` Kong variable to customize help message for development flag.

## [0.11.0] - 2024-03-06

### Changed

- Make routes definition easier to extend.

## [0.10.1] - 2024-03-04

### Fixed

- Simplify path traversal for static files.

## [0.10.0] - 2024-03-01

### Added

- Middleware logs its name as a canonical log line message if they fully handle the request.

## [0.9.2] - 2024-02-26

### Fixed

- Expose HTTP server for use in tests.

## [0.9.1] - 2024-02-20

### Fixed

- Set `Server.Addr` to the default value when not set.

## [0.9.0] - 2024-02-16

### Added

- `Service.GetRoute` calls `Router.Get`.

## [0.8.0] - 2024-02-16

### Added

- `Router.Get` resolves path and method to a route descriptor `ResolvedRoute`,
  or returns `MethodNotAllowedError` or `ErrNotFound` errors.

## [0.7.0] - 2024-01-28

### Added

- `APICors` and `GetCors` on `Route` struct enable CORS handling.

### Fixed

- Race condition with disabled logger.
  [#643](https://github.com/rs/zerolog/issues/643)
- Do not mark immutable responses as public.

## [0.6.0] - 2023-12-07

### Added

- `PrepareJSON` prepares JSON response.

## [0.5.0] - 2023-12-06

### Added

- `WithError` logs error to the canonical log line.

### Changed

- `BadRequestWithError` handles `context.Canceled` and `context.DeadlineExceeded`
  specially as well, like `InternalServerErrorWithError`.

### Removed

- `NotFoundWithError`: call `WithError` first and then `NotFound`.

## [0.4.0] - 2023-11-28

### Added

- Add `RedirectToMainSite` middleware.

## [0.3.0] - 2023-11-26

### Added

- Support additional middleware.

### Changed

- Remove `TLS.Domain` field and CLI argument.

## [0.2.0] - 2023-11-24

### Added

- Add helper `TemporaryRedirectGetMethod`.

### Changed

- Rename helper `TemporaryRedirect` to `TemporaryRedirectSameMethod`.

## [0.1.2] - 2023-11-22

### Fixed

- Change default port to (documented) 8080.

## [0.1.1] - 2023-11-22

### Fixed

- Skip installing middleware for canonical log line logger if the logger is disabled.
- Vite port changed from 3000 to 5173.

## [0.1.0] - 2023-11-20

### Added

- First public release.

[unreleased]: https://gitlab.com/tozd/waf/-/compare/v0.19.0...main
[0.19.0]: https://gitlab.com/tozd/waf/-/compare/v0.18.1...v0.19.0
[0.18.1]: https://gitlab.com/tozd/waf/-/compare/v0.18.0...v0.18.1
[0.18.0]: https://gitlab.com/tozd/waf/-/compare/v0.17.1...v0.18.0
[0.17.1]: https://gitlab.com/tozd/waf/-/compare/v0.17.0...v0.17.1
[0.17.0]: https://gitlab.com/tozd/waf/-/compare/v0.16.0...v0.17.0
[0.16.0]: https://gitlab.com/tozd/waf/-/compare/v0.15.0...v0.16.0
[0.15.0]: https://gitlab.com/tozd/waf/-/compare/v0.14.0...v0.15.0
[0.14.0]: https://gitlab.com/tozd/waf/-/compare/v0.13.1...v0.14.0
[0.13.1]: https://gitlab.com/tozd/waf/-/compare/v0.13.0...v0.13.1
[0.13.0]: https://gitlab.com/tozd/waf/-/compare/v0.12.0...v0.13.0
[0.12.0]: https://gitlab.com/tozd/waf/-/compare/v0.11.0...v0.12.0
[0.11.0]: https://gitlab.com/tozd/waf/-/compare/v0.10.1...v0.11.0
[0.10.1]: https://gitlab.com/tozd/waf/-/compare/v0.10.0...v0.10.1
[0.10.0]: https://gitlab.com/tozd/waf/-/compare/v0.9.2...v0.10.0
[0.9.2]: https://gitlab.com/tozd/waf/-/compare/v0.9.1...v0.9.2
[0.9.1]: https://gitlab.com/tozd/waf/-/compare/v0.9.0...v0.9.1
[0.9.0]: https://gitlab.com/tozd/waf/-/compare/v0.8.0...v0.9.0
[0.8.0]: https://gitlab.com/tozd/waf/-/compare/v0.7.0...v0.8.0
[0.7.0]: https://gitlab.com/tozd/waf/-/compare/v0.6.0...v0.7.0
[0.6.0]: https://gitlab.com/tozd/waf/-/compare/v0.5.0...v0.6.0
[0.5.0]: https://gitlab.com/tozd/waf/-/compare/v0.4.0...v0.5.0
[0.4.0]: https://gitlab.com/tozd/waf/-/compare/v0.3.0...v0.4.0
[0.3.0]: https://gitlab.com/tozd/waf/-/compare/v0.2.0...v0.3.0
[0.2.0]: https://gitlab.com/tozd/waf/-/compare/v0.1.2...v0.2.0
[0.1.2]: https://gitlab.com/tozd/waf/-/compare/v0.1.1...v0.1.2
[0.1.1]: https://gitlab.com/tozd/waf/-/compare/v0.1.0...v0.1.1
[0.1.0]: https://gitlab.com/tozd/waf/-/tags/v0.1.0

<!-- markdownlint-disable-file MD024 -->
