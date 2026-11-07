package piv

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/card"
	"github.com/telesma-app/piv/client"
	"github.com/telesma-app/piv/protocol"
)

// P-256's standard generator, returned in the PIV public-key template.
const generatedP256 = "7f49438641046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"

func TestGenerateKeyPoliciesWire(t *testing.T) {
	for _, test := range []struct {
		name    string
		request GenerateKeyRequest
		apdu    string
	}{
		{
			name: "explicit policies",
			request: GenerateKeyRequest{
				Key: protocol.DigitalSignature, Algorithm: protocol.ECCP256,
				Policy: KeyPolicy{PIN: PINPolicyAlways, Touch: TouchPolicyAlways},
			},
			apdu: "0047009c0bac09800111aa0103ab010200",
		},
		{
			name: "device defaults omitted",
			request: GenerateKeyRequest{
				Key: AttestationKey, Algorithm: protocol.ECCP256,
			},
			apdu: "004700f905ac0380011100",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &commandTransport{response: iso7816.Response{Status: 0x9000, Data: commandBytes(t, generatedP256)}}

			publicKey, err := GenerateKey(context.Background(), transport, test.request, card.AdministrationKey{})
			if err != nil {
				t.Fatal(err)
			}

			checkCommand(t, transport, test.apdu)

			key, ok := publicKey.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("public key = %T, want *ecdsa.PublicKey", publicKey)
			}

			encoded, err := key.Bytes()
			if err != nil {
				t.Fatal(err)
			}

			if key.Curve != elliptic.P256() || !bytes.Equal(encoded, commandBytes(t, generatedP256)[5:]) {
				t.Error("generated public key differs from P-256 generator")
			}
		})
	}
}

func TestGenerateKeyReportsAcknowledgedReplacement(t *testing.T) {
	transport := &commandTransport{response: iso7816.Response{Status: 0x9000, Data: []byte{0x7f, 0x49, 0}}}
	request := GenerateKeyRequest{Key: protocol.PIVAuthentication, Algorithm: protocol.ECCP384}

	publicKey, err := GenerateKey(context.Background(), transport, request, card.AdministrationKey{})

	var generated *client.KeyGenerationError
	if !errors.As(err, &generated) || !errors.Is(err, protocol.ErrInvalidResponse) {
		t.Fatalf("error = %v, want KeyGenerationError wrapping ErrInvalidResponse", err)
	}

	if publicKey != nil || generated.Key != request.Key || generated.Algorithm != request.Algorithm {
		t.Errorf("result = %#v, %#v", publicKey, generated)
	}

	if transport.calls != 1 {
		t.Errorf("commands = %d, want one attempt", transport.calls)
	}
}

func TestGenerateKeyUnsupportedAlgorithmHasNoEffect(t *testing.T) {
	transport := &commandTransport{}
	request := GenerateKeyRequest{Key: protocol.PIVAuthentication, Algorithm: 0xee}

	if _, err := GenerateKey(context.Background(), transport, request, card.AdministrationKey{}); err == nil {
		t.Fatal("unsupported algorithm succeeded")
	}

	if transport.calls != 0 {
		t.Errorf("commands = %d, want 0", transport.calls)
	}
}

func TestGenerateKeyMismatchedRSAExponentReportsReplacement(t *testing.T) {
	// Independently encoded RSA-1024 response: a 128-byte modulus and e=65537.
	data := append([]byte{0x7f, 0x49, 0x81, 0x88, 0x81, 0x81, 0x80}, bytes.Repeat([]byte{0xab}, 128)...)
	data = append(data, 0x82, 0x03, 0x01, 0x00, 0x01)
	transport := &commandTransport{response: iso7816.Response{Status: 0x9000, Data: data}}
	request := GenerateKeyRequest{Key: protocol.PIVAuthentication, Algorithm: protocol.RSA1024, Parameter: []byte{3}}

	publicKey, err := GenerateKey(context.Background(), transport, request, card.AdministrationKey{})

	var generated *client.KeyGenerationError
	if !errors.As(err, &generated) || !errors.Is(err, protocol.ErrInvalidResponse) || publicKey != nil {
		t.Fatalf("result = %v, %v; want acknowledged replacement with invalid response", publicKey, err)
	}

	checkCommand(t, transport, "0047009a08ac0680010681010300")
}
