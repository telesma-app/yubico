package piv

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
)

type readTransport struct {
	command  iso7816.Command
	response iso7816.Response
	err      error
}

func (transport *readTransport) Exchange(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
	transport.command = command

	return transport.response, transport.err
}

func readBytes(t testing.TB, data string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(data)
	if err != nil {
		t.Fatal(err)
	}

	return decoded
}

func TestReadVersion(t *testing.T) {
	transport := &readTransport{response: iso7816.Response{Status: 0x9000, Data: []byte{5, 7, 4}}}

	version, err := ReadVersion(context.Background(), transport)
	if err != nil {
		t.Fatal(err)
	}

	if version.String() != "5.7.4" {
		t.Errorf("version = %s", version)
	}

	wire, err := transport.command.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(wire, []byte{0, 0xfd, 0, 0}) {
		t.Errorf("command = %x", wire)
	}
}

func TestReadSerialNumber(t *testing.T) {
	transport := &readTransport{response: iso7816.Response{Status: 0x9000, Data: []byte{0, 1, 0xe2, 0x40}}}

	serial, err := ReadSerialNumber(context.Background(), transport)
	if err != nil {
		t.Fatal(err)
	}

	if serial != 123456 {
		t.Errorf("serial = %d, want 123456", serial)
	}

	wire, err := transport.command.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(wire, []byte{0, 0xf8, 0, 0}) {
		t.Errorf("command = %x", wire)
	}
}

func TestReadFailures(t *testing.T) {
	ioError := errors.New("card disconnected")
	tests := []struct {
		name     string
		response iso7816.Response
		err      error
		check    func(*testing.T, error)
	}{
		{
			name: "transport error", err: ioError,
			check: func(t *testing.T, err error) {
				if !errors.Is(err, ioError) {
					t.Errorf("error = %v, want I/O cause", err)
				}
			},
		},
		{
			name: "unsupported command", response: iso7816.Response{Status: 0x6d00, Data: []byte{5, 7, 4}},
			check: func(t *testing.T, err error) {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != 0x6d00 {
					t.Errorf("error = %v, want APDU 6D00", err)
				}
			},
		},
		{
			name: "short version", response: iso7816.Response{Status: 0x9000, Data: []byte{5, 7}},
			check: func(t *testing.T, err error) {
				if !errors.Is(err, protocol.ErrInvalidResponse) {
					t.Errorf("error = %v, want invalid response", err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := &readTransport{response: test.response, err: test.err}
			_, err := ReadVersion(context.Background(), transport)
			test.check(t, err)
		})
	}

	for _, data := range [][]byte{nil, {1, 2, 3}, {1, 2, 3, 4, 5}} {
		transport := &readTransport{response: iso7816.Response{Status: 0x9000, Data: data}}
		if _, err := ReadSerialNumber(context.Background(), transport); !errors.Is(err, protocol.ErrInvalidResponse) {
			t.Errorf("serial data %x: error = %v", data, err)
		}
	}
}

func TestReadMetadata(t *testing.T) {
	transport := &readTransport{response: iso7816.Response{Status: 0x9000, Data: readBytes(t, "0101ff05010006020302")}}

	metadata, err := ReadMetadata(context.Background(), transport, protocol.ApplicationPIN)
	if err != nil {
		t.Fatal(err)
	}

	if metadata.Algorithm != 0xff || metadata.Default == nil || *metadata.Default || metadata.Retries == nil || *metadata.Retries != (RetryCounts{Total: 3, Remaining: 2}) {
		t.Errorf("metadata = %+v", metadata)
	}

	wire, err := transport.command.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(wire, []byte{0, 0xf7, 0, 0x80}) {
		t.Errorf("command = %x", wire)
	}
}

func TestAttest(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "untrusted attestation"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(86400, 0),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	transport := &readTransport{response: iso7816.Response{Status: 0x9000, Data: der}}

	certificate, err := Attest(context.Background(), transport, protocol.DigitalSignature)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(certificate.Raw, der) {
		t.Error("attestation DER changed")
	}

	wire, err := transport.command.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(wire, []byte{0, 0xf9, 0x9c, 0}) {
		t.Errorf("command = %x", wire)
	}

	transport.response.Data = []byte{0x30, 0}

	got, err := AttestDER(context.Background(), transport, protocol.DigitalSignature)
	if err != nil || !bytes.Equal(got, transport.response.Data) {
		t.Errorf("raw DER = %x, %v", got, err)
	}

	if _, err := Attest(context.Background(), transport, protocol.DigitalSignature); !errors.Is(err, protocol.ErrInvalidResponse) {
		t.Errorf("malformed attestation: %v", err)
	}
}
