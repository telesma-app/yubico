package piv

import (
	"context"
	"fmt"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/card"
	"github.com/telesma-app/piv/protocol"
)

// SetManagementKey authenticates with administrationKey and replaces the card's
// management key. Replacement is borrowed and is never retained or cleared.
// Touch must be Never, Always, or Cached; Default is not a SET MANAGEMENT KEY
// policy. Cached is available only on firmware that supports it. An interrupted
// exchange may have changed the key; this function never retries.
func SetManagementKey(
	ctx context.Context,
	transport AdministrationTransport,
	replacement card.AdministrationKey,
	touch TouchPolicy,
	administrationKey card.AdministrationKey,
) error {
	var size int

	switch replacement.Algorithm {
	case protocol.TripleDES:
		size = 24
	case protocol.AES128:
		size = 16
	case protocol.AES192:
		size = 24
	case protocol.AES256:
		size = 32
	default:
		return fmt.Errorf("yubico piv: unsupported management key algorithm %02x", byte(replacement.Algorithm))
	}

	if len(replacement.Key) != size {
		return fmt.Errorf("yubico piv: management key algorithm %02x requires %d bytes", byte(replacement.Algorithm), size)
	}

	var p2 byte

	switch touch {
	case TouchPolicyNever:
		p2 = 0xff
	case TouchPolicyAlways:
		p2 = 0xfe
	case TouchPolicyCached:
		p2 = 0xfd
	default:
		return fmt.Errorf("yubico piv: unsupported management key touch policy %02x", byte(touch))
	}

	data := make([]byte, 3, 3+len(replacement.Key))
	data[0], data[1], data[2] = byte(replacement.Algorithm), 0x9b, byte(len(replacement.Key))

	data = append(data, replacement.Key...)
	defer clear(data)

	response, err := administrationExchange(ctx, transport, iso7816.Command{
		INS: 0xff, P1: 0xff, P2: p2,
		Data: data, Encoding: iso7816.EncodingShort,
	}, administrationKey, nil)
	if err != nil {
		return err
	}

	return emptyResponse(response)
}

// SetPINRetries changes both retry limits and resets the PIN and PUK to their
// factory values. The operation requires management authentication and a
// verified application PIN. Authentication explicitly supplies that VERIFY;
// nil relies on already established PIN status. No value is tried or retried
// automatically. The card decides which retry limits it supports.
func SetPINRetries(
	ctx context.Context,
	transport AdministrationTransport,
	pinRetries, pukRetries byte,
	administrationKey card.AdministrationKey,
	authentication card.AuthenticationSource,
) error {
	response, err := administrationExchange(ctx, transport, iso7816.Command{
		INS: 0xfa, P1: pinRetries, P2: pukRetries, Encoding: iso7816.EncodingShort,
	}, administrationKey, authentication)
	if err != nil {
		return err
	}

	return emptyResponse(response)
}

// Reset erases PIV keys and certificates except the attestation key and
// certificate in slot F9. It restores the PIN, PUK, management key and retry
// limits to their factory defaults. Slot F9 remains unchanged; reset does not
// restore its original factory key or certificate if either was replaced or
// deleted.
//
// PIN and PUK must already be blocked. This function submits only RESET: it
// never consumes retries to arrange those conditions. It borrows transport and
// does not close or reselect the application.
func Reset(ctx context.Context, transport VendorTransport) error {
	response, err := exchange(ctx, transport, iso7816.Command{
		INS: 0xfb, Encoding: iso7816.EncodingShort,
	})
	if err != nil {
		return err
	}

	return emptyResponse(response)
}

// MoveKey moves source to an empty destination slot. Certificates are not moved.
// This command requires YubiKey 5.7 or later;
// firmware determines permitted slots and any additional authentication.
// Authentication may supply an explicit VERIFY, or be nil to omit it.
func MoveKey(
	ctx context.Context,
	transport AdministrationTransport,
	source, destination protocol.KeyReference,
	administrationKey card.AdministrationKey,
	authentication card.AuthenticationSource,
) error {
	if source == AttestationKey || destination == AttestationKey {
		return fmt.Errorf("yubico piv: attestation key cannot be moved")
	}

	response, err := administrationExchange(ctx, transport, iso7816.Command{
		INS: 0xf6, P1: byte(destination), P2: byte(source), Encoding: iso7816.EncodingShort,
	}, administrationKey, authentication)
	if err != nil {
		return err
	}

	return emptyResponse(response)
}

// DeleteKey deletes only the private key in reference, leaving its certificate
// untouched. This command requires YubiKey 5.7 or later. Authentication may
// supply an explicit VERIFY, or be nil to omit it. The operation never retries.
func DeleteKey(
	ctx context.Context,
	transport AdministrationTransport,
	reference protocol.KeyReference,
	administrationKey card.AdministrationKey,
	authentication card.AuthenticationSource,
) error {
	response, err := administrationExchange(ctx, transport, iso7816.Command{
		INS: 0xf6, P1: 0xff, P2: byte(reference), Encoding: iso7816.EncodingShort,
	}, administrationKey, authentication)
	if err != nil {
		return err
	}

	return emptyResponse(response)
}
