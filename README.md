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
- `yubico/transport/pcsc` reads device information through the Yubico
  management application on an exact PC/SC reader.
- `yubico/resolver` identifies a smart-card target and distinguishes a missing
  Yubico management application from transport or protocol failures.

The CTAPHID transport can open a FIDO HID collection by path and owns the
resulting connection until `Close`. `GetDeviceInfo` also accepts an existing
vendor-command channel without taking ownership of it. Both forms send logical
command `0x42`; CTAPHID framing adds the init-packet bit, so the on-wire command
byte is `0xc2`.

The PC/SC management AID, commands and status handling follow Yubico's
[Configuration Reference](https://developers.yubico.com/yubikey-manager/Config_Reference.html)
and the official
[`yubikey-manager`](https://github.com/Yubico/yubikey-manager)
implementation.

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
