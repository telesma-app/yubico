package piv

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/card"
	"github.com/telesma-app/piv/protocol"
)

type extendedPublicKey struct {
	name      string
	algorithm protocol.Algorithm
	wireID    byte
	response  []byte
	metadata  []byte
	public    []byte
}

func extendedPublicKeys(t testing.TB) []extendedPublicKey {
	t.Helper()

	// SEC 2 P-521 generator; RFC 8032 section 7.1 test 1; RFC 7748 section 6.1 Alice.
	p521 := commandBytes(t, "0400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650")
	ed := commandBytes(t, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	x := commandBytes(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	modulus := bytes.Repeat([]byte{0xab}, 512)
	rsaData := append([]byte{0x81, 0x82, 0x02, 0x00}, modulus...)
	rsaData = append(rsaData, 0x82, 0x03, 0x01, 0x00, 0x01)
	p521Data := append([]byte{0x86, 0x81, 0x85}, p521...)
	edData := append([]byte{0x86, 0x20}, ed...)
	xData := append([]byte{0x86, 0x20}, x...)

	return []extendedPublicKey{
		{
			name: "RSA4096", algorithm: protocol.RSA4096, wireID: 0x16, public: modulus,
			response: append([]byte{0x7f, 0x49, 0x82, 0x02, 0x09}, rsaData...),
			metadata: append([]byte{0x01, 0x01, 0x16, 0x04, 0x82, 0x02, 0x09}, rsaData...),
		},
		{
			name: "P521", algorithm: protocol.ECCP521, wireID: 0x15, public: p521,
			response: append([]byte{0x7f, 0x49, 0x81, 0x88}, p521Data...),
			metadata: append([]byte{0x01, 0x01, 0x15, 0x04, 0x81, 0x88}, p521Data...),
		},
		{
			name: "Ed25519", algorithm: protocol.Ed25519, wireID: 0xe0, public: ed,
			response: append([]byte{0x7f, 0x49, 0x22}, edData...),
			metadata: append([]byte{0x01, 0x01, 0xe0, 0x04, 0x22}, edData...),
		},
		{
			name: "X25519", algorithm: protocol.X25519, wireID: 0xe1, public: x,
			response: append([]byte{0x7f, 0x49, 0x22}, xData...),
			metadata: append([]byte{0x01, 0x01, 0xe1, 0x04, 0x22}, xData...),
		},
	}
}

func (fixture extendedPublicKey) check(t testing.TB, public crypto.PublicKey) {
	t.Helper()

	switch fixture.algorithm {
	case protocol.RSA4096:
		key, ok := public.(*rsa.PublicKey)
		if !ok || key.N.Cmp(new(big.Int).SetBytes(fixture.public)) != 0 || key.E != 65537 {
			t.Fatalf("RSA-4096 public key = %v", public)
		}
	case protocol.ECCP521:
		key, ok := public.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P521() {
			t.Fatalf("P-521 public key = %v", public)
		}

		encoded, err := key.Bytes()
		if err != nil || !bytes.Equal(encoded, fixture.public) {
			t.Fatalf("P-521 public key bytes = %x, %v", encoded, err)
		}
	case protocol.Ed25519:
		key, ok := public.(ed25519.PublicKey)
		if !ok || !bytes.Equal(key, fixture.public) {
			t.Fatalf("Ed25519 public key = %v", public)
		}
	case protocol.X25519:
		key, ok := public.(*ecdh.PublicKey)
		if !ok || key.Curve() != ecdh.X25519() || !bytes.Equal(key.Bytes(), fixture.public) {
			t.Fatalf("X25519 public key = %v", public)
		}
	}
}

func TestGenerateExtendedAlgorithmsWire(t *testing.T) {
	for _, fixture := range extendedPublicKeys(t) {
		t.Run(fixture.name, func(t *testing.T) {
			transport := &commandTransport{response: iso7816.Response{Status: 0x9000, Data: fixture.response}}
			request := GenerateKeyRequest{
				Key: protocol.DigitalSignature, Algorithm: fixture.algorithm,
				Policy: KeyPolicy{PIN: PINPolicyAlways, Touch: TouchPolicyAlways},
			}

			public, err := GenerateKey(t.Context(), transport, request, card.AdministrationKey{})
			if err != nil {
				t.Fatal(err)
			}

			checkCommand(t, transport, fmt.Sprintf("0047009c0bac098001%02xaa0103ab010200", fixture.wireID))
			fixture.check(t, public)
		})
	}
}

func TestMetadataExtendedPublicKeys(t *testing.T) {
	for _, fixture := range extendedPublicKeys(t) {
		t.Run(fixture.name, func(t *testing.T) {
			metadata, err := ParseMetadata(fixture.metadata)
			if err != nil {
				t.Fatal(err)
			}

			public, err := metadata.PublicKey()
			if err != nil {
				t.Fatal(err)
			}

			fixture.check(t, public)
		})
	}
}

func TestImportExtendedCurveKeysWire(t *testing.T) {
	p521Scalar := make([]byte, 66)
	p521Scalar[65] = 1

	p521, err := ecdsa.ParseRawPrivateKey(elliptic.P521(), p521Scalar)
	if err != nil {
		t.Fatal(err)
	}

	edSeed := commandBytes(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	ed := ed25519.NewKeyFromSeed(edSeed)
	xScalar := commandBytes(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")

	x, err := ecdh.X25519().NewPrivateKey(xScalar)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		key  crypto.PrivateKey
		apdu string
	}{
		{name: "P521", key: p521, apdu: "00fe159c4a0642" + fmt.Sprintf("%x", p521Scalar) + "aa0103ab0102"},
		{name: "Ed25519 seed", key: ed, apdu: "00fee09c2807209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60aa0103ab0102"},
		{name: "X25519 scalar", key: x, apdu: "00fee19c28082077076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2aaa0103ab0102"},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &commandTransport{response: iso7816.Response{Status: 0x9000}}
			policy := KeyPolicy{PIN: PINPolicyAlways, Touch: TouchPolicyAlways}

			if err := ImportKey(t.Context(), transport, protocol.DigitalSignature, test.key, policy, card.AdministrationKey{}); err != nil {
				t.Fatal(err)
			}

			checkCommand(t, transport, test.apdu)

			if !transport.admin || transport.authentication != nil {
				t.Error("import did not use administration without implicit PIN verification")
			}

			if !bytes.Equal(transport.borrowedData, make([]byte, len(transport.borrowedData))) {
				t.Error("temporary key import data was not cleared")
			}
		})
	}

	encoded, err := p521.Bytes()
	if err != nil || !bytes.Equal(encoded, p521Scalar) || !bytes.Equal(ed.Seed(), edSeed) || !bytes.Equal(x.Bytes(), xScalar) {
		t.Error("import modified a borrowed private key")
	}
}

func TestImportRSA4096CRTWire(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	parameters := []*big.Int{key.Primes[0], key.Primes[1], key.Precomputed.Dp, key.Precomputed.Dq, key.Precomputed.Qinv}
	key.Precomputed = rsa.PrecomputedValues{}
	transport := &commandTransport{response: iso7816.Response{Status: 0x9000}}

	if err := ImportKey(t.Context(), transport, protocol.KeyManagement, key, KeyPolicy{}, card.AdministrationKey{}); err != nil {
		t.Fatal(err)
	}

	if transport.calls != 1 || transport.command.INS != 0xfe || transport.command.P1 != 0x16 || transport.command.P2 != 0x9d {
		t.Fatalf("RSA-4096 import command = %#v, calls = %d", transport.command, transport.calls)
	}

	const fieldLength = 260
	if len(transport.command.Data) != 5*fieldLength {
		t.Fatalf("CRT payload length = %d, want %d", len(transport.command.Data), 5*fieldLength)
	}

	for i, want := range parameters {
		field := transport.command.Data[i*fieldLength : (i+1)*fieldLength]
		if !bytes.Equal(field[:4], []byte{byte(i + 1), 0x82, 0x01, 0x00}) || new(big.Int).SetBytes(field[4:]).Cmp(want) != 0 {
			t.Errorf("CRT field %d differs from its fixed-width standard-library oracle", i)
		}
	}

	if key.Precomputed.Dp != nil || key.Precomputed.Dq != nil || key.Precomputed.Qinv != nil {
		t.Error("import mutated the key's precomputed fields")
	}

	if !bytes.Equal(transport.borrowedData, make([]byte, len(transport.borrowedData))) {
		t.Error("temporary RSA key import data was not cleared")
	}
}

func TestImportRejectsUnsupportedECDHCurveBeforeAuthentication(t *testing.T) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	transport := &commandTransport{}

	if err := ImportKey(t.Context(), transport, protocol.KeyManagement, key, KeyPolicy{}, card.AdministrationKey{}); err == nil {
		t.Fatal("P-256 ECDH private key import succeeded")
	}

	if transport.calls != 0 {
		t.Errorf("commands = %d, want 0", transport.calls)
	}
}
