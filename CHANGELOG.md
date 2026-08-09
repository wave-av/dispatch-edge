# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **BREAKING for Go SDK consumers: the minimum Go version is now 1.25** (`sdk/go/go.mod`,
  raised from `1.21`). Go 1.21 reached end-of-life on 2024-08-13; the supported releases are
  1.25 and 1.26. The `go` directive is the minimum Go this published module demands of
  everyone who installs it, so an EOL floor here is advertised to every consumer of
  `github.com/wave-av/dispatch-edge/sdk/go`.

  **If you build with an older or pinned toolchain, or with `GOTOOLCHAIN=off`, this is a hard
  build failure** — upgrade to Go 1.25 or later. With the default `GOTOOLCHAIN=auto`, Go
  fetches a suitable toolchain for you and no action is needed.

  **1.25 was chosen over 1.26 deliberately**: it is the oldest release still receiving security
  fixes, which keeps the supported consumer window as wide as it can be while no longer
  pointing at an end-of-life toolchain. No source changed — the SDK's code uses nothing newer
  than it did before, so this raises the floor for security-currency reasons rather than to
  adopt a new language feature.
