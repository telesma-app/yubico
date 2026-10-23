# telesma-app/yubico

[![Go Reference](https://pkg.go.dev/badge/github.com/telesma-app/yubico.svg)](https://pkg.go.dev/github.com/telesma-app/yubico)
[![Go](https://github.com/telesma-app/yubico/actions/workflows/go.yml/badge.svg)](https://github.com/telesma-app/yubico/actions/workflows/go.yml)

Pure-Go support for reported Yubico management information.

> [!WARNING]
> This module is under active development. Its public API may change during
> `v0.x`.

## Installation

```sh
go get github.com/telesma-app/yubico@latest
```

See [`go.mod`](go.mod) for the required Go version.

## Packages

- `yubico` parses management responses and derives model names.
- `yubico/transport/ctaphid` reads device information through CTAPHID vendor command `0x42`.
- `yubico/transport/pcsc` reads device information through the management applet.

## Usage

`DeviceInfo` preserves reported values and raw TLVs; nil optional fields mean the
value was not reported. `SerialNumber` is the reported numeric serial.
`ModelName()` derives a model separately and returns false when it cannot
recognize the firmware or form factor.

Transport `Open` functions return caller-owned devices. Call `DeviceInfo(ctx)`
to read management information and `Close()` to release the connection.

`ctaphid.ReadDeviceInfo` and `pcsc.ReadDeviceInfo` borrow existing connections; for
PC/SC, the caller manages the transaction and subsequent applet selection.

`pcsc.Open(reader, opts...)` forwards native PC/SC options. By default, `Close`
leaves the card powered (`DispositionLeaveCard`). Pass
`nativepcsc.WithDisconnectDisposition(nativepcsc.DispositionResetCard)` when
a reset on close is required.

The protocol follows Yubico's
[Configuration Reference](https://developers.yubico.com/yubikey-manager/Config_Reference.html).
See the [Go reference](https://pkg.go.dev/github.com/telesma-app/yubico) for field
and error contracts.

## Testing

```sh
go test ./...
go vet ./...
```

The test suite does not require hardware.
