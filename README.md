# go-ctap/yubico

[![Go Reference](https://pkg.go.dev/badge/github.com/go-ctap/yubico.svg)](https://pkg.go.dev/github.com/go-ctap/yubico)
[![Go](https://github.com/go-ctap/yubico/actions/workflows/go.yml/badge.svg)](https://github.com/go-ctap/yubico/actions/workflows/go.yml)

Pure-Go support for Yubico-specific device information and identity.

> [!WARNING]
> This module is under active development. Its public API may change during
> `v0.x`.

## Packages

- `yubico` contains transport-independent device-information models, response
  parsing and canonical model naming.
- `yubico/transport/ctaphid` reads device information through Yubico's CTAPHID
  vendor command `0x42`, using
  [`github.com/go-ctap/ctap`](https://github.com/go-ctap/ctap).

The CTAPHID transport accepts an existing vendor-command channel and does not
take ownership of it. It sends logical command `0x42`; CTAPHID framing adds the
init-packet bit, so the on-wire command byte is `0xc2`.

## Installation

```sh
go get github.com/go-ctap/yubico@latest
```

See [`go.mod`](go.mod) for the required Go version.

## Testing

```sh
go test ./...
go vet ./...
```

The test suite does not require hardware.
