package piv

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/card"
	"github.com/telesma-app/piv/protocol"
)

func TestImportECDSAKeyWire(t *testing.T) {
	curve := elliptic.P256()
	scalar := commandBytes(t, "0000000000000000000000000000000000000000000000000000000000000001")

	key, err := ecdsa.ParseRawPrivateKey(curve, scalar)
	if err != nil {
		t.Fatal(err)
	}

	transport := &commandTransport{response: iso7816.Response{Status: 0x9000}}
	policy := KeyPolicy{PIN: PINPolicyAlways, Touch: TouchPolicyAlways}

	if err := ImportKey(context.Background(), transport, protocol.DigitalSignature, key, policy, card.AdministrationKey{}); err != nil {
		t.Fatal(err)
	}

	checkCommand(t, transport, "00fe119c2806200000000000000000000000000000000000000000000000000000000000000001aa0103ab0102")

	if !transport.admin || transport.authentication != nil {
		t.Error("import did not use administration without implicit PIN verification")
	}

	encoded, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(encoded, scalar) {
		t.Error("borrowed private key was modified")
	}

	if !bytes.Equal(transport.borrowedData, make([]byte, len(transport.borrowedData))) {
		t.Error("temporary key import data was not cleared")
	}
}

func TestImportRSAUsesFixedWidthCRTWithoutMutatingKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	// The standard library's independent precomputation supplies the CRT oracle.
	// Remove it from the valid key before import: importing must not populate it.
	parameters := []*big.Int{
		new(big.Int).Set(key.Primes[0]), new(big.Int).Set(key.Primes[1]),
		new(big.Int).Set(key.Precomputed.Dp), new(big.Int).Set(key.Precomputed.Dq),
		new(big.Int).Set(key.Precomputed.Qinv),
	}
	key.Precomputed = rsa.PrecomputedValues{}
	transport := &commandTransport{response: iso7816.Response{Status: 0x9000}}

	if err := ImportKey(context.Background(), transport, AttestationKey, key, KeyPolicy{}, card.AdministrationKey{}); err != nil {
		t.Fatal(err)
	}

	if !transport.admin || transport.command.INS != 0xfe || transport.command.P1 != 0x06 ||
		transport.command.P2 != 0xf9 || transport.command.Le != 0 {
		t.Errorf("import APDU header = %#v", transport.command)
	}

	const width = 64
	if len(transport.command.Data) != 5*(width+2) {
		t.Fatalf("CRT payload length = %d, want %d", len(transport.command.Data), 5*(width+2))
	}

	for i, want := range parameters {
		field := transport.command.Data[i*(width+2) : (i+1)*(width+2)]
		if field[0] != byte(i+1) || field[1] != 0x40 {
			t.Errorf("CRT field %d header = %x, want %02x40", i, field[:2], i+1)
		}

		if new(big.Int).SetBytes(field[2:]).Cmp(want) != 0 {
			t.Errorf("CRT field %d differs from standard library precomputation", i)
		}
	}

	if key.Precomputed.Dp != nil || key.Precomputed.Dq != nil || key.Precomputed.Qinv != nil {
		t.Error("import mutated the key's precomputed fields")
	}

	if !bytes.Equal(transport.borrowedData, make([]byte, len(transport.borrowedData))) {
		t.Error("temporary RSA key data was not cleared")
	}
}

func TestImportRejectsUnsupportedCurveBeforeAuthentication(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	transport := &commandTransport{}

	if err := ImportKey(context.Background(), transport, protocol.DigitalSignature, key, KeyPolicy{}, card.AdministrationKey{}); err == nil {
		t.Fatal("P-521 import succeeded")
	}

	if transport.calls != 0 {
		t.Errorf("commands = %d, want 0", transport.calls)
	}
}
