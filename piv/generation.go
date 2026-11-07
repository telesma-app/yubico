package piv

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/card"
	"github.com/telesma-app/piv/client"
	"github.com/telesma-app/piv/protocol"
)

// GenerateKey replaces a slot's private key and returns its public key. Unlike
// the standard command, it includes Yubico PIN and touch policies. Supported
// algorithms are RSA-1024/2048/3072 and P-256/P-384. The certificate is unchanged.
//
// Generating in AttestationKey permanently replaces the factory attestation
// key. The original Yubico attestation capability cannot be restored by Reset.
//
// A client.KeyGenerationError means that key replacement was acknowledged but
// the public-key response was invalid or did not match Parameter. An interrupted
// exchange may also have replaced the key. The operation never retries.
func GenerateKey(
	ctx context.Context,
	transport AdministrationTransport,
	request GenerateKeyRequest,
	administrationKey card.AdministrationKey,
) (crypto.PublicKey, error) {
	switch request.Algorithm {
	case protocol.RSA1024, protocol.RSA2048, protocol.RSA3072, protocol.ECCP256, protocol.ECCP384:
	default:
		return nil, fmt.Errorf("yubico piv: unsupported public key algorithm %02x", byte(request.Algorithm))
	}

	template := appendTLV(nil, 0x80, []byte{byte(request.Algorithm)})
	if request.Parameter != nil {
		template = appendTLV(template, 0x81, request.Parameter)
	}

	template = appendPolicy(template, request.Policy)

	response, err := administrationExchange(ctx, transport, iso7816.Command{
		INS: 0x47, P2: byte(request.Key),
		Data: appendTLV(nil, 0xac, template),
		Le:   256, Encoding: iso7816.EncodingShort,
	}, administrationKey, nil)
	if err != nil {
		return nil, err
	}

	publicKey, err := protocol.ParsePublicKey(request.Algorithm, response.Data)
	if err != nil {
		return nil, &client.KeyGenerationError{Key: request.Key, Algorithm: request.Algorithm, Err: err}
	}

	if key, ok := publicKey.(*rsa.PublicKey); ok && request.Parameter != nil {
		if new(big.Int).SetBytes(request.Parameter).Cmp(big.NewInt(int64(key.E))) != 0 {
			return nil, &client.KeyGenerationError{
				Key: request.Key, Algorithm: request.Algorithm,
				Err: fmt.Errorf("%w: generated RSA public exponent does not match request", protocol.ErrInvalidResponse),
			}
		}
	}

	return publicKey, nil
}
