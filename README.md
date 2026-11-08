# telesma-app/yubico

[![Go Reference](https://pkg.go.dev/badge/github.com/telesma-app/yubico.svg)](https://pkg.go.dev/github.com/telesma-app/yubico)
[![Go](https://github.com/telesma-app/yubico/actions/workflows/go.yml/badge.svg)](https://github.com/telesma-app/yubico/actions/workflows/go.yml)

Go library for Yubico management information and PIV extensions.
Device information is available over PC/SC and CTAPHID.

> [!WARNING]
> This module is under active development. Its public API may change during `v0.x`.

## Features

- firmware, serial number, form factor, USB/NFC capabilities and FIPS information;
- model identification from reported device information;
- PIV slot metadata, attestation, key generation and import with PIN/touch policies;
- PIV management-key rotation, retry limits, reset and move/delete commands.

Available information and commands depend on the device and firmware.

## Installation

```sh
go get github.com/telesma-app/yubico@latest
```

See [`go.mod`](go.mod) for the required Go version.

## Quick start

Read device information through a named PC/SC reader:

```go
package main

import (
	"context"
	"fmt"
	"log"

	yubicopcsc "github.com/telesma-app/yubico/transport/pcsc"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	device, err := yubicopcsc.Open("exact PC/SC reader name")
	if err != nil {
		return err
	}
	defer device.Close()

	info, err := device.DeviceInfo(context.Background())
	if err != nil {
		return err
	}

	if model, ok := info.ModelName(); ok {
		fmt.Println("model:", model)
	}
	if info.SerialNumber != nil {
		fmt.Println("serial:", *info.SerialNumber)
	}
	fmt.Printf("firmware: %d.%d.%d\n",
		info.FirmwareVersion.Major, info.FirmwareVersion.Minor, info.FirmwareVersion.Build)
	return nil
}
```

`DeviceInfo` preserves reported values; optional fields are nil when absent.
`ModelName` derives a name separately and reports whether it recognized the model.

## Packages

| Package | Purpose |
| --- | --- |
| [`yubico`](https://pkg.go.dev/github.com/telesma-app/yubico) | Device-information parsing and model identification |
| [`transport/pcsc`](transport/pcsc) | Device information through the management applet |
| [`transport/ctaphid`](transport/ctaphid) | Device information through CTAPHID |
| [`piv`](piv) | Yubico PIV commands and policies |

PIV functions borrow an already selected [`piv/card.Device`](https://pkg.go.dev/github.com/telesma-app/piv/card).
Administrative operations take an explicit `card.AdministrationKey`.
Open the connection with the PIV library; the vendor package adds key policies,
metadata and administration commands to that session.

## Development

```sh
go test ./...
go vet ./...
golangci-lint run ./...
```

The test suite does not require hardware.

## License

[Apache License 2.0](LICENSE).

## References

- [YubiKey Configuration Reference](https://developers.yubico.com/yubikey-manager/Config_Reference.html)
- [Yubico PIV extensions](https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html)
- [PIV attestation](https://developers.yubico.com/PIV/Introduction/PIV_attestation.html)
