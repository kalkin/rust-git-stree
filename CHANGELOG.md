# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.2.4] - 2022-10-01

### Fixed

- fix: Search origin if upstream missing for a ref to pull
- fix: SubtreeConfig having origin url is also pullable

## [v0.2.3] - 2022-04-21

### Changed

- Fix `clippy::panic-in-result-fn`
- Remove most `unwrap()` calls
- Use `thiserror::Error`
- improvement(git-stree-list): Sort subtrees

### Fixed

- fix(git-stree-push): Use origin remote for push
- fix(git-stree-pull): Fallback to origin remote on pull

## [v0.2.2] - 2022-03-06

### Added

- `From<_>` for `PosixError`

### Changed

- `Subtrees.pull()` throws an error if no changes fetched

### Fixed

- Resolve `HEAD` before pushing

## [v0.2.1] - 2022-01-17

### Fixed

- repository url

## [v0.2.0] - 2022-01-17

### Added

- Document all Structs and enums
