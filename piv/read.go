package piv

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"fmt"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/card"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/yubico"
)

// ReadVersion reads the three-byte PIV application firmware version.
func ReadVersion(ctx context.Context, transport VendorTransport) (yubico.FirmwareVersion, error) {
	response, err := exchange(ctx, transport, iso7816.Command{INS: 0xfd, Encoding: iso7816.EncodingShort})
	if err != nil {
		return yubico.FirmwareVersion{}, err
	}

	if len(response.Data) != 3 {
		return yubico.FirmwareVersion{}, fmt.Errorf("%w: invalid Yubico PIV version", protocol.ErrInvalidResponse)
	}

	return yubico.FirmwareVersion{Major: response.Data[0], Minor: response.Data[1], Build: response.Data[2]}, nil
}

// ReadSerialNumber reads the Yubico four-byte, big-endian numeric serial.
func ReadSerialNumber(ctx context.Context, transport VendorTransport) (uint32, error) {
	response, err := exchange(ctx, transport, iso7816.Command{INS: 0xf8, Encoding: iso7816.EncodingShort})
	if err != nil {
		return 0, err
	}

	if len(response.Data) != 4 {
		return 0, fmt.Errorf("%w: invalid Yubico PIV serial number", protocol.ErrInvalidResponse)
	}

	return binary.BigEndian.Uint32(response.Data), nil
}

// ReadMetadata reads the current fields reported for a reference. It does not
// authenticate the slot or prove that a reported public key matches its key.
func ReadMetadata(ctx context.Context, transport VendorTransport, reference protocol.KeyReference) (Metadata, error) {
	response, err := exchange(ctx, transport, iso7816.Command{INS: 0xf7, P2: byte(reference), Encoding: iso7816.EncodingShort})
	if err != nil {
		return Metadata{}, err
	}

	return ParseMetadata(response.Data)
}

// AttestDER requests an attestation certificate for an on-device generated key.
// It returns the reported bytes without parsing or establishing trust. It does
// not install the certificate in the slot or modify the slot's key.
func AttestDER(ctx context.Context, transport VendorTransport, reference protocol.KeyReference) ([]byte, error) {
	response, err := exchange(ctx, transport, iso7816.Command{INS: 0xf9, P1: byte(reference), Encoding: iso7816.EncodingShort})
	if err != nil {
		return nil, err
	}

	return response.Data, nil
}

// Attest requests and parses an attestation certificate. Parsing does not verify
// its signature, chain, extension claims or a match with the slot's public key.
func Attest(ctx context.Context, transport VendorTransport, reference protocol.KeyReference) (*x509.Certificate, error) {
	der, err := AttestDER(ctx, transport, reference)
	if err != nil {
		return nil, err
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: Yubico attestation certificate: %v", protocol.ErrInvalidResponse, err)
	}

	return certificate, nil
}

// PublicKey parses the metadata's public key using its reported algorithm.
// PublicKeyData is a PIV public-key template value, not X.509 SubjectPublicKeyInfo.
// Supported algorithms match protocol.ParsePublicKey. Other algorithms remain
// available in Algorithm and PublicKeyData even when this method cannot parse them.
func (metadata Metadata) PublicKey() (crypto.PublicKey, error) {
	data := append([]byte{0x7f}, appendTLV(nil, 0x49, metadata.PublicKeyData)...)

	return protocol.ParsePublicKey(metadata.Algorithm, data)
}

func exchange(ctx context.Context, transport VendorTransport, command iso7816.Command) (iso7816.Response, error) {
	response, err := transport.Exchange(ctx, command)
	if err != nil {
		return iso7816.Response{}, err
	}

	if err := response.APDUError(); err != nil {
		return iso7816.Response{}, err
	}

	return response, nil
}

func administrationExchange(
	ctx context.Context,
	transport AdministrationTransport,
	command iso7816.Command,
	administrationKey card.AdministrationKey,
	authentication card.AuthenticationSource,
) (iso7816.Response, error) {
	response, err := transport.ExchangeAdministration(ctx, command, administrationKey, authentication)
	if err != nil {
		return iso7816.Response{}, err
	}

	if err := response.APDUError(); err != nil {
		return iso7816.Response{}, err
	}

	return response, nil
}

func emptyResponse(response iso7816.Response) error {
	if len(response.Data) != 0 {
		return fmt.Errorf("%w: unexpected Yubico response data", protocol.ErrInvalidResponse)
	}

	return nil
}
