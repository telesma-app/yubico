// Package piv implements Yubico PIV extensions over a borrowed, selected PIV
// connection. A card.Device provides both ordinary and management-authenticated
// exchanges. These functions neither select an applet nor own the connection.
//
// Administrative functions authenticate explicitly supplied management keys and
// send the command in one card workflow. They do not retain credentials, choose
// default keys, retry commands, or infer firmware capabilities. Availability
// depends on the device and firmware; APDU rejections preserve their status.
//
// The wire protocol follows https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html.
// Attestation parsing does not verify a certificate chain or establish trust.
package piv

import (
	"context"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/card"
	"github.com/telesma-app/piv/protocol"
)

// VendorTransport exchanges complete APDU commands on a selected PIV connection.
// The caller retains ownership. A card.Device serializes each exchange with its
// other operations.
type VendorTransport interface {
	Exchange(context.Context, iso7816.Command) (iso7816.Response, error)
}

// AdministrationTransport keeps management authentication, optional reference
// verification, and a vendor command under the same operation gate.
type AdministrationTransport interface {
	ExchangeAdministration(context.Context, iso7816.Command, card.AdministrationKey, card.AuthenticationSource) (iso7816.Response, error)
}

var (
	_ VendorTransport         = (*card.Device)(nil)
	_ AdministrationTransport = (*card.Device)(nil)
)

const (
	// AttestationKey identifies the attestation key in slot F9. Replacing it by
	// import or generation, or deleting it, permanently removes the ability to
	// attest with the original Yubico factory key. Reset cannot restore that key.
	AttestationKey protocol.KeyReference = 0xf9
	// AttestationCertificate is the certificate object for AttestationKey.
	AttestationCertificate protocol.Object = 0x5fff01
)

// PINPolicy is the per-key Yubico PIN policy. Zero requests the device default.
type PINPolicy byte

const (
	PINPolicyDefault PINPolicy = 0
	PINPolicyNever   PINPolicy = 1
	PINPolicyOnce    PINPolicy = 2
	PINPolicyAlways  PINPolicy = 3
)

// TouchPolicy is the per-key Yubico touch policy. Zero requests the device default.
type TouchPolicy byte

const (
	TouchPolicyDefault TouchPolicy = 0
	TouchPolicyNever   TouchPolicy = 1
	TouchPolicyAlways  TouchPolicy = 2
	TouchPolicyCached  TouchPolicy = 3
)

// KeyPolicy selects the policies when generating or importing a key.
type KeyPolicy struct {
	PIN   PINPolicy
	Touch TouchPolicy
}

// GenerateKeyRequest selects a slot, algorithm and Yubico key policies.
// Parameter is the optional encoded RSA public exponent (tag 81), as in
// protocol.GenerateAsymmetricKeyPairRequest. Slices are borrowed for the call.
type GenerateKeyRequest struct {
	Key       protocol.KeyReference
	Algorithm protocol.Algorithm
	Parameter []byte
	Policy    KeyPolicy
}

// KeyOrigin is the key provenance reported by the card, without verification.
type KeyOrigin byte

const (
	KeyOriginGenerated KeyOrigin = 1
	KeyOriginImported  KeyOrigin = 2
)

// RetryCounts reports both the configured limit and the remaining attempts.
type RetryCounts struct {
	Total     byte
	Remaining byte
}

// Metadata preserves the fields reported for a PIN, PUK, management key or
// asymmetric slot. Nil optional fields mean that the card did not report them.
// Unknown algorithm, policy and origin identifiers are retained. Raw and
// PublicKeyData borrow the response bytes.
type Metadata struct {
	Raw           []byte
	Algorithm     *protocol.Algorithm
	Policy        *KeyPolicy
	Origin        *KeyOrigin
	PublicKeyData []byte
	Default       *bool
	Retries       *RetryCounts
}
