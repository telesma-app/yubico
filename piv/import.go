package piv

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/card"
	"github.com/telesma-app/piv/protocol"
)

// ImportKey replaces a slot's private key without replacing its certificate.
// Supported inputs are two-prime RSA-1024/2048/3072/4096 keys with exponent 65537,
// ECDSA P-256/P-384/P-521, Ed25519 and X25519 keys. PrivateKey is borrowed; its
// values and precomputed fields are not modified. Temporary wire data is cleared
// after the exchange.
//
// Importing into AttestationKey permanently replaces the factory attestation
// key. The original Yubico attestation capability cannot be restored by Reset.
//
// Policy is encoded explicitly when non-default. Firmware decides whether the
// requested algorithm, slot and policies are supported. An interrupted exchange
// may have replaced the key; this function never retries.
func ImportKey(
	ctx context.Context,
	transport AdministrationTransport,
	reference protocol.KeyReference,
	privateKey crypto.PrivateKey,
	policy KeyPolicy,
	administrationKey card.AdministrationKey,
) error {
	algorithm, data, err := encodePrivateKey(privateKey)
	if err != nil {
		return err
	}
	defer func() { clear(data) }()

	data = appendPolicy(data, policy)

	response, err := administrationExchange(ctx, transport, iso7816.Command{
		INS: 0xfe, P1: byte(algorithm), P2: byte(reference),
		Data: data, Encoding: iso7816.EncodingShort,
	}, administrationKey, nil)
	if err != nil {
		return err
	}

	return emptyResponse(response)
}

func encodePrivateKey(privateKey crypto.PrivateKey) (protocol.Algorithm, []byte, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		var algorithm protocol.Algorithm

		switch key.N.BitLen() {
		case 1024:
			algorithm = protocol.RSA1024
		case 2048:
			algorithm = protocol.RSA2048
		case 3072:
			algorithm = protocol.RSA3072
		case 4096:
			algorithm = protocol.RSA4096
		default:
			return 0, nil, fmt.Errorf("yubico piv: unsupported RSA key size %d", key.N.BitLen())
		}

		if len(key.Primes) != 2 || key.E != 65537 {
			return 0, nil, fmt.Errorf("yubico piv: RSA import requires two primes and exponent 65537")
		}

		// The on-card import reconstructs RSA from fixed-width CRT parameters,
		// rather than accepting a PKCS #1 or PKCS #8 private-key encoding.
		p, q := key.Primes[0], key.Primes[1]

		width := key.Size() / 2
		if p.BitLen() > width*8 || q.BitLen() > width*8 {
			return 0, nil, fmt.Errorf("yubico piv: RSA primes exceed the %d-byte import fields", width)
		}

		dp := new(big.Int).Mod(key.D, new(big.Int).Sub(p, big.NewInt(1)))
		dq := new(big.Int).Mod(key.D, new(big.Int).Sub(q, big.NewInt(1)))
		qinv := new(big.Int).ModInverse(q, p)

		encoded := make([]byte, width)
		defer clear(encoded)

		data := make([]byte, 0, 5*(width+4)+6)

		for i, parameter := range []*big.Int{p, q, dp, dq, qinv} {
			parameter.FillBytes(encoded)
			data = appendTLV(data, byte(i+1), encoded)
		}

		return algorithm, data, nil
	case *ecdsa.PrivateKey:
		var algorithm protocol.Algorithm

		switch key.Curve {
		case elliptic.P256():
			algorithm = protocol.ECCP256
		case elliptic.P384():
			algorithm = protocol.ECCP384
		case elliptic.P521():
			algorithm = protocol.ECCP521
		default:
			return 0, nil, fmt.Errorf("yubico piv: unsupported ECDSA curve %s", key.Curve.Params().Name)
		}

		encoded, err := key.Bytes()
		if err != nil {
			return 0, nil, err
		}

		defer clear(encoded)

		return algorithm, appendTLV(make([]byte, 0, len(encoded)+8), 0x06, encoded), nil
	case ed25519.PrivateKey:
		seed := key.Seed()
		defer clear(seed)

		return protocol.Ed25519, appendTLV(make([]byte, 0, len(seed)+8), 0x07, seed), nil
	case *ecdh.PrivateKey:
		if key.Curve() != ecdh.X25519() {
			return 0, nil, fmt.Errorf("yubico piv: unsupported ECDH curve %s", key.Curve())
		}

		encoded := key.Bytes()
		defer clear(encoded)

		return protocol.X25519, appendTLV(make([]byte, 0, len(encoded)+8), 0x08, encoded), nil
	default:
		return 0, nil, fmt.Errorf("yubico piv: unsupported private key type %T", privateKey)
	}
}

func appendPolicy(data []byte, policy KeyPolicy) []byte {
	if policy.PIN != PINPolicyDefault {
		data = appendTLV(data, 0xaa, []byte{byte(policy.PIN)})
	}

	if policy.Touch != TouchPolicyDefault {
		data = appendTLV(data, 0xab, []byte{byte(policy.Touch)})
	}

	return data
}
