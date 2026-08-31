package pcsc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/telesma-app/iso7816"
	nativepcsc "github.com/telesma-app/pcsc"
	"github.com/telesma-app/yubico"
)

var (
	selectManagementAPDU = []byte{
		0x00, 0xa4, 0x04, 0x00, 0x08,
		0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17,
	}
	deviceInfoPage0APDU = []byte{0x00, 0x1d, 0x00, 0x00, 0x00}
	deviceInfoPage1APDU = []byte{0x00, 0x1d, 0x01, 0x00, 0x00}
)

type cardStep struct {
	command  []byte
	response []byte
}

type scriptedCard struct {
	steps  []cardStep
	begins int
	ends   int
}

func (c *scriptedCard) BeginTransaction(context.Context) error {
	c.begins++
	return nil
}

func (c *scriptedCard) EndTransaction(nativepcsc.Disposition) error {
	c.ends++
	return nil
}

func (c *scriptedCard) Transmit(
	_ context.Context,
	command []byte,
) ([]byte, error) {
	if len(c.steps) == 0 {
		return nil, fmt.Errorf("unexpected APDU: %x", command)
	}
	step := c.steps[0]
	c.steps = c.steps[1:]
	if !bytes.Equal(command, step.command) {
		return nil, fmt.Errorf(
			"unexpected APDU: got %x, want %x",
			command,
			step.command,
		)
	}
	return bytes.Clone(step.response), nil
}

func (*scriptedCard) Close() error {
	return nil
}

func TestDeviceInfo(t *testing.T) {
	nfc := yubico.CapabilityU2F | yubico.CapabilityCTAP2
	firstPage := infoPage(
		0x01, 0x02, 0x02, 0x00,
		0x03, 0x02, 0x02, 0x00,
		0x04, 0x01, 0x01,
		0x05, 0x03, 0x05, 0x07, 0x01,
		0x0d, 0x02, byte(nfc>>8), byte(nfc),
		0x0e, 0x02, byte(nfc>>8), byte(nfc),
		0x10, 0x01, 0x01,
	)
	secondPage := infoPage(
		0x02, 0x04, 0x00, 0xbc, 0x61, 0x4e,
	)
	card := &scriptedCard{steps: []cardStep{
		{
			command:  selectManagementAPDU,
			response: apduResponse([]byte("5.7.1"), iso7816.StatusSuccess),
		},
		{
			command:  deviceInfoPage0APDU,
			response: apduResponse(firstPage, iso7816.StatusSuccess),
		},
		{
			command:  deviceInfoPage1APDU,
			response: apduResponse(secondPage, iso7816.StatusSuccess),
		},
	}}

	info, err := (&Device{card: card}).DeviceInfo(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := "YubiKey 5 NFC", info.ModelName("")
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if got := info.Serial; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}
	{
		want, got := uint32(12345678), *info.Serial
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if got := card.steps; len(got) != 0 {
		t.Errorf("got non-empty value %#v", got)
	}
	{
		want, got := 1, card.begins
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := 1, card.ends
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestDeviceInfoClassifiesMissingManagementApplication(t *testing.T) {
	for _, status := range []iso7816.StatusWord{
		0x6999,
		0x6a82,
		0x6b00,
		0x6d00,
	} {
		t.Run(status.String(), func(t *testing.T) {
			card := &scriptedCard{steps: []cardStep{{
				command:  selectManagementAPDU,
				response: apduResponse(nil, status),
			}}}

			_, err := (&Device{card: card}).DeviceInfo(t.Context())
			{
				err, target := err, ErrManagementApplicationNotAvailable
				if !errors.Is(err, target) {
					t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
				}
			}
		})
	}
}

func TestDeviceInfoDoesNotClassifyReadFailureAsMissingApplication(
	t *testing.T,
) {
	card := &scriptedCard{steps: []cardStep{
		{
			command:  selectManagementAPDU,
			response: apduResponse([]byte("5.7.1"), iso7816.StatusSuccess),
		},
		{
			command:  deviceInfoPage0APDU,
			response: apduResponse(nil, 0x6d00),
		},
	}}

	_, err := (&Device{card: card}).DeviceInfo(t.Context())
	if err == nil {
		t.Fatalf("expected an error")
	}
	{
		err, target := err, ErrManagementApplicationNotAvailable
		if errors.Is(err, target) {
			t.Fatalf("got error %v, unexpectedly matches %#v", err, target)
		}
	}
}

func apduResponse(data []byte, status iso7816.StatusWord) []byte {
	return append(bytes.Clone(data), status.SW1(), status.SW2())
}

func infoPage(fields ...byte) []byte {
	return append([]byte{byte(len(fields))}, fields...)
}
