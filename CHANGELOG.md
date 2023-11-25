# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Added

- Skip installing middleware for canonical log line logger if the logger is disabled.

### Fixed

- Vite port changed from 3000 to 5173.

## [0.1.0] - 2023-11-20

### Added

- First public release.

[unreleased]: https://gitlab.com/tozd/waf/-/compare/v0.2.0...main
[0.2.0]: https://gitlab.com/tozd/waf/-/compare/v0.1.2...v0.2.0
[0.1.2]: https://gitlab.com/tozd/waf/-/compare/v0.1.1...v0.1.2
[0.1.1]: https://gitlab.com/tozd/waf/-/compare/v0.1.0...v0.1.1
[0.1.0]: https://gitlab.com/tozd/waf/-/tags/v0.1.0

<!-- markdownlint-disable-file MD024 -->
