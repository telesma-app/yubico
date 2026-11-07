package piv

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"testing"

	"github.com/telesma-app/piv/protocol"
)

func TestParseMetadataPublicKey(t *testing.T) {
	// SEC 2 P-256 generator, used as the public key for private scalar 1.
	point := readBytes(t, "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
	data := readBytes(t, "0101110202020103010104438641")
	data = append(data, point...)

	metadata, err := ParseMetadata(data)
	if err != nil {
		t.Fatal(err)
	}

	if metadata.Algorithm != protocol.ECCP256 || metadata.Policy == nil || *metadata.Policy != (KeyPolicy{PIN: PINPolicyOnce, Touch: TouchPolicyNever}) || metadata.Origin == nil || *metadata.Origin != KeyOriginGenerated {
		t.Errorf("metadata = %+v", metadata)
	}

	public, err := metadata.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	key, ok := public.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		t.Fatalf("public key = %v", public)
	}

	encoded, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(encoded, point) {
		t.Errorf("public key bytes = %x", encoded)
	}

	if !bytes.Equal(metadata.Raw, data) || !bytes.Equal(metadata.PublicKeyData, data[12:]) {
		t.Error("metadata did not preserve its encoded data")
	}
}

func TestParseMetadataUnknownValues(t *testing.T) {
	data := readBytes(t, "0101f00202feff0301fe04010105010006020000ee02aabb")

	metadata, err := ParseMetadata(data)
	if err != nil {
		t.Fatal(err)
	}

	if metadata.Algorithm != 0xf0 || metadata.Policy == nil || metadata.Policy.PIN != 0xfe || metadata.Policy.Touch != 0xff || metadata.Origin == nil || *metadata.Origin != 0xfe {
		t.Errorf("unknown fields changed: %+v", metadata)
	}

	if metadata.Default == nil || *metadata.Default || metadata.Retries == nil || *metadata.Retries != (RetryCounts{}) {
		t.Errorf("reported zero fields lost: %+v", metadata)
	}

	if !bytes.Equal(metadata.Raw, data) {
		t.Error("unknown TLV lost")
	}

	if _, err := metadata.PublicKey(); err == nil {
		t.Error("unknown public-key algorithm was accepted")
	}
}

func TestParseMetadataAbsentOptionalFields(t *testing.T) {
	metadata, err := ParseMetadata([]byte{1, 1, 3})
	if err != nil {
		t.Fatal(err)
	}

	if metadata.Policy != nil || metadata.Origin != nil || metadata.PublicKeyData != nil || metadata.Default != nil || metadata.Retries != nil {
		t.Errorf("absent fields gained values: %+v", metadata)
	}
}

func TestParseMetadataMalformed(t *testing.T) {
	for _, encoded := range []string{
		"", "01", "0180", "018201", "0102ff", "0100", "01020000",
		"010103010103", "010103020100", "0101030300", "010103050102",
		"010103060103", "01010306020102", "010103ee82010000",
	} {
		t.Run(encoded, func(t *testing.T) {
			if _, err := ParseMetadata(readBytes(t, encoded)); !errors.Is(err, protocol.ErrInvalidResponse) {
				t.Errorf("error = %v, want invalid response", err)
			}
		})
	}
}
