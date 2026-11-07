package piv

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/card"
	"github.com/telesma-app/piv/protocol"
)

type commandTransport struct {
	command        iso7816.Command
	borrowedData   []byte
	administration card.AdministrationKey
	authentication card.AuthenticationSource
	admin          bool
	calls          int
	response       iso7816.Response
	err            error
}

func (t *commandTransport) Exchange(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
	t.calls++
	t.command = command
	t.borrowedData = command.Data
	t.command.Data = bytes.Clone(command.Data)

	return t.response, t.err
}

func (t *commandTransport) ExchangeAdministration(
	ctx context.Context,
	command iso7816.Command,
	administration card.AdministrationKey,
	authentication card.AuthenticationSource,
) (iso7816.Response, error) {
	t.admin = true
	t.administration = administration
	t.authentication = authentication

	return t.Exchange(ctx, command)
}

func commandBytes(t testing.TB, encoded string) []byte {
	t.Helper()

	data, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func checkCommand(t testing.TB, transport *commandTransport, encoded string) {
	t.Helper()

	got, err := transport.command.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if want := commandBytes(t, encoded); !bytes.Equal(got, want) {
		t.Errorf("APDU = %x, want %x", got, want)
	}

	if transport.calls != 1 {
		t.Errorf("command calls = %d, want 1", transport.calls)
	}
}

func TestSetManagementKey(t *testing.T) {
	for _, test := range []struct {
		name      string
		algorithm protocol.Algorithm
		key       string
		touch     TouchPolicy
		apdu      string
	}{
		{
			name: "AES128 without touch", algorithm: protocol.AES128,
			key: "000102030405060708090a0b0c0d0e0f", touch: TouchPolicyNever,
			apdu: "00ffffff13089b10000102030405060708090a0b0c0d0e0f",
		},
		{
			name: "TripleDES with touch", algorithm: protocol.TripleDES,
			key: "000102030405060708090a0b0c0d0e0f1011121314151617", touch: TouchPolicyAlways,
			apdu: "00fffffe1b039b18000102030405060708090a0b0c0d0e0f1011121314151617",
		},
		{
			name: "AES256 cached touch", algorithm: protocol.AES256,
			key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", touch: TouchPolicyCached,
			apdu: "00fffffd230c9b20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &commandTransport{response: iso7816.Response{Status: 0x9000}}
			current := card.AdministrationKey{Algorithm: protocol.AES192, Key: make([]byte, 24)}
			replacement := card.AdministrationKey{Algorithm: test.algorithm, Key: commandBytes(t, test.key)}
			original := bytes.Clone(replacement.Key)

			if err := SetManagementKey(context.Background(), transport, replacement, test.touch, current); err != nil {
				t.Fatal(err)
			}

			checkCommand(t, transport, test.apdu)

			if !transport.admin || transport.administration.Algorithm != current.Algorithm ||
				!bytes.Equal(transport.administration.Key, current.Key) || transport.authentication != nil {
				t.Error("current administration key and authentication were not forwarded")
			}

			if !bytes.Equal(replacement.Key, original) {
				t.Error("replacement key was modified")
			}

			if !bytes.Equal(transport.borrowedData, make([]byte, len(transport.borrowedData))) {
				t.Error("temporary wire key was not cleared")
			}
		})
	}
}

func TestAdministrationCommands(t *testing.T) {
	authentication := card.AuthenticationSource(func(context.Context) (protocol.VerifyRequest, error) {
		return protocol.VerifyRequest{Reference: protocol.ApplicationPIN}, nil
	})
	key := card.AdministrationKey{Algorithm: protocol.TripleDES, Key: make([]byte, 24)}

	for _, test := range []struct {
		name string
		run  func(context.Context, *commandTransport) error
		apdu string
	}{
		{
			name: "retry limits",
			run: func(ctx context.Context, transport *commandTransport) error {
				return SetPINRetries(ctx, transport, 5, 7, key, authentication)
			},
			apdu: "00fa0507",
		},
		{
			name: "move key",
			run: func(ctx context.Context, transport *commandTransport) error {
				return MoveKey(ctx, transport, protocol.KeyManagement, protocol.RetiredKey1, key, authentication)
			},
			apdu: "00f6829d",
		},
		{
			name: "delete attestation key",
			run: func(ctx context.Context, transport *commandTransport) error {
				return DeleteKey(ctx, transport, AttestationKey, key, authentication)
			},
			apdu: "00f6fff9",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &commandTransport{response: iso7816.Response{Status: 0x9000}}

			if err := test.run(context.Background(), transport); err != nil {
				t.Fatal(err)
			}

			checkCommand(t, transport, test.apdu)

			if !transport.admin || transport.administration.Algorithm != key.Algorithm || transport.authentication == nil {
				t.Fatal("administration key or authentication was not forwarded")
			}

			request, err := transport.authentication(context.Background())
			if err != nil || request.Reference != protocol.ApplicationPIN {
				t.Errorf("forwarded authentication = %#v, %v", request, err)
			}
		})
	}
}

func TestResetSendsOnlyReset(t *testing.T) {
	transport := &commandTransport{response: iso7816.Response{Status: 0x9000}}

	if err := Reset(context.Background(), transport); err != nil {
		t.Fatal(err)
	}

	checkCommand(t, transport, "00fb0000")

	if transport.admin {
		t.Error("RESET attempted administration authentication")
	}
}

func TestCommandsPreserveFailures(t *testing.T) {
	cause := errors.New("transport unavailable")
	for _, test := range []struct {
		name     string
		response iso7816.Response
		err      error
		want     error
		status   iso7816.StatusWord
	}{
		{name: "transport", err: cause, want: cause},
		{name: "card rejection", response: iso7816.Response{Status: 0x6982}, status: 0x6982},
		{name: "unexpected successful payload", response: iso7816.Response{Status: 0x9000, Data: []byte{1}}, want: protocol.ErrInvalidResponse},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &commandTransport{response: test.response, err: test.err}

			err := SetPINRetries(context.Background(), transport, 3, 3, card.AdministrationKey{}, nil)
			if test.want != nil && !errors.Is(err, test.want) {
				t.Errorf("error = %v, want %v", err, test.want)
			}

			if test.status != 0 {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || iso7816.StatusWord(uint16(apdu.SW1)<<8|uint16(apdu.SW2)) != test.status {
					t.Errorf("error = %v, want APDU status %04x", err, test.status)
				}
			}
		})
	}
}
