# telesma-app/yubico

[![Go Reference](https://pkg.go.dev/badge/github.com/telesma-app/yubico.svg)](https://pkg.go.dev/github.com/telesma-app/yubico)
[![Go](https://github.com/telesma-app/yubico/actions/workflows/go.yml/badge.svg)](https://github.com/telesma-app/yubico/actions/workflows/go.yml)

Pure-Go support for Yubico management information and PIV extensions.

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
- `yubico/piv` implements PIV vendor commands over a borrowed PIV connection.

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

## PIV extensions

The `piv` package borrows a selected
`github.com/telesma-app/piv/card.Device`. It reads the PIV applet version, numeric
serial, slot metadata and attestation certificates, and supports management-key
rotation, key import, generation with PIN/touch policies, retry-limit changes,
reset, and YubiKey 5.7 move/delete commands. It never owns or closes the connection.

Administrative operations take an explicit `card.AdministrationKey`. Management
authentication and the command share the device's operation gate. Retry-limit
changes and move/delete can also take an explicit `AuthenticationSource`; nil
omits VERIFY. No default credential, automatic retry or firmware fallback is used.
Reset submits only RESET and requires the PIN and PUK to be blocked already.
Changing retry limits also resets the PIN and PUK to their factory values.

```go
publicKey, err := yubicopiv.GenerateKey(ctx, device, yubicopiv.GenerateKeyRequest{
	Key:       protocol.DigitalSignature,
	Algorithm: protocol.ECCP256,
	Policy: yubicopiv.KeyPolicy{
		PIN:   yubicopiv.PINPolicyAlways,
		Touch: yubicopiv.TouchPolicyAlways,
	},
}, administrationKey)
```

Here `yubicopiv` imports `github.com/telesma-app/yubico/piv`; `protocol` imports
`github.com/telesma-app/piv/protocol`. Generation replaces the key and leaves the
certificate unchanged. The returned public key can be bound with
`device.PrivateKey` and used with the standard Go crypto interfaces.

> [!WARNING]
> Importing or generating a key in `AttestationKey` (slot `0xf9`), or deleting
> that key, permanently removes the ability to attest with the original Yubico
> factory key. PIV reset preserves this slot and cannot restore its factory key
> or certificate. See [Yubico's PIV attestation documentation](https://developers.yubico.com/PIV/Introduction/PIV_attestation.html).

Generation and import support RSA-1024/2048/3072 and P-256/P-384; RSA import needs
two primes and exponent 65537. RSA-4096, Ed25519 and X25519 are not implemented.
Metadata retains unknown algorithms and raw public-key bytes independently of
public-key parsing. Attestation parsing does not establish trust or verify
certificate chains. Device and firmware support is decided by the card's APDU
response; these commands have not been tested on hardware.

TOKEN2 reuses the confirmed compatible wire commands through this package.

## Testing

```sh
go test ./...
go vet ./...
```

The test suite does not require hardware.

Run golangci-lint v2 with the standard linters and `wsl_v5`:

```sh
golangci-lint run ./...
```
