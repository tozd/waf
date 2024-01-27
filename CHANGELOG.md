# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `APICors` and `GetCors` on `Route` struct enable CORS handling.

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

[unreleased]: https://gitlab.com/tozd/waf/-/compare/v0.6.0...main
[0.6.0]: https://gitlab.com/tozd/waf/-/compare/v0.5.0...v0.6.0
[0.5.0]: https://gitlab.com/tozd/waf/-/compare/v0.4.0...v0.5.0
[0.4.0]: https://gitlab.com/tozd/waf/-/compare/v0.3.0...v0.4.0
[0.3.0]: https://gitlab.com/tozd/waf/-/compare/v0.2.0...v0.3.0
[0.2.0]: https://gitlab.com/tozd/waf/-/compare/v0.1.2...v0.2.0
[0.1.2]: https://gitlab.com/tozd/waf/-/compare/v0.1.1...v0.1.2
[0.1.1]: https://gitlab.com/tozd/waf/-/compare/v0.1.0...v0.1.1
[0.1.0]: https://gitlab.com/tozd/waf/-/tags/v0.1.0

<!-- markdownlint-disable-file MD024 -->
