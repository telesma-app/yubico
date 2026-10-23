package pcsc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

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
	err      error
}

type scriptedCard struct {
	steps    []cardStep
	begins   int
	ends     int
	beginErr error
	endErr   error
	closed   bool
}

func (c *scriptedCard) BeginTransaction(context.Context) error {
	c.begins++
	return c.beginErr
}

func (c *scriptedCard) EndTransaction(nativepcsc.Disposition) error {
	c.ends++
	return c.endErr
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

	return bytes.Clone(step.response), step.err
}

func (c *scriptedCard) Close() error {
	c.closed = true
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
		0x06, 2, 0, 0,
		0x07, 1, 15,
		0x08, 1, 0,
		0x0a, 1, 0,
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

	if got := info.SupportedNFCCapabilities; got == nil || *got != nfc {
		t.Errorf("reported NFC capabilities = %v, want %v", got, nfc)
	}

	if got := info.SerialNumber; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got, want := *info.SerialNumber, uint32(12345678); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got := card.steps; len(got) != 0 {
		t.Errorf("got non-empty value %#v", got)
	}

	if got, want := card.begins, 1; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := card.ends, 1; got != want {
		t.Errorf("got %#v, want %#v", got, want)
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
			if err, target := err, ErrManagementApplicationNotAvailable; !errors.Is(err, target) {
				t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
			}

			var apduErr *iso7816.APDUError
			if !errors.As(err, &apduErr) || apduErr.StatusWord() != status {
				t.Fatalf("underlying APDU error lost: %v", err)
			}

			if card.ends != 1 || card.closed {
				t.Fatalf("transaction ends = %d, card closed = %t", card.ends, card.closed)
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

	if err, target := err, ErrManagementApplicationNotAvailable; errors.Is(err, target) {
		t.Fatalf("got error %v, unexpectedly matches %#v", err, target)
	}

	if !errors.Is(err, yubico.ErrDeviceInfoNotSupported) {
		t.Fatalf("error = %v, want unsupported command", err)
	}

	var apduErr *iso7816.APDUError
	if !errors.As(err, &apduErr) || apduErr.StatusWord() != 0x6d00 {
		t.Fatalf("underlying APDU error lost: %v", err)
	}
}

func apduResponse(data []byte, status iso7816.StatusWord) []byte {
	return append(bytes.Clone(data), status.SW1(), status.SW2())
}

func infoPage(fields ...byte) []byte {
	return append([]byte{byte(len(fields))}, fields...)
}

func TestDeviceInfoPreservesFailures(t *testing.T) {
	ioErr := errors.New("card I/O failed")
	for _, test := range []struct {
		name       string
		selectStep cardStep
		readStep   cardStep
		beginErr   error
		endErr     error
		wantErr    error
		wantStatus iso7816.StatusWord
		wantEnds   int
	}{
		{name: "begin transaction", beginErr: ioErr, wantErr: ioErr},
		{name: "select I/O", selectStep: cardStep{err: ioErr}, wantErr: ioErr, wantEnds: 1},
		{name: "select status", selectStep: cardStep{response: apduResponse(nil, 0x6982)}, wantStatus: 0x6982, wantEnds: 1},
		{name: "select malformed APDU", selectStep: cardStep{response: []byte{0}}, wantErr: iso7816.ErrInvalidResponse, wantEnds: 1},
		{name: "read I/O", readStep: cardStep{err: ioErr}, wantErr: ioErr, wantEnds: 1},
		{name: "read status", readStep: cardStep{response: apduResponse(nil, 0x6a82)}, wantStatus: 0x6a82, wantEnds: 1},
		{name: "read malformed APDU", readStep: cardStep{response: []byte{0}}, wantErr: iso7816.ErrInvalidResponse, wantEnds: 1},
		{name: "read malformed TLV", readStep: cardStep{response: apduResponse([]byte{1}, iso7816.StatusSuccess)}, wantErr: yubico.ErrInvalidDeviceInfo, wantEnds: 1},
		{name: "end transaction", endErr: ioErr, wantErr: ioErr, wantEnds: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			selectStep := test.selectStep

			selectStep.command = selectManagementAPDU
			if selectStep.response == nil && selectStep.err == nil {
				selectStep.response = apduResponse(nil, iso7816.StatusSuccess)
			}

			readStep := test.readStep

			readStep.command = deviceInfoPage0APDU
			if readStep.response == nil && readStep.err == nil {
				readStep.response = apduResponse(completeInfoPage(), iso7816.StatusSuccess)
			}

			card := &scriptedCard{
				steps:    []cardStep{selectStep, readStep},
				beginErr: test.beginErr,
				endErr:   test.endErr,
			}

			_, err := (&Device{card: card}).DeviceInfo(t.Context())
			if test.wantStatus != 0 {
				var apduErr *iso7816.APDUError
				if !errors.As(err, &apduErr) || apduErr.StatusWord() != test.wantStatus {
					t.Fatalf("error = %v, want APDU status %s", err, test.wantStatus)
				}
			} else if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}

			if errors.Is(err, ErrManagementApplicationNotAvailable) || errors.Is(err, yubico.ErrDeviceInfoNotSupported) {
				t.Errorf("failure misclassified as unavailable: %v", err)
			}

			if card.ends != test.wantEnds || card.closed {
				t.Fatalf("transaction ends = %d, want %d; closed = %t", card.ends, test.wantEnds, card.closed)
			}
		})
	}
}

func TestDeviceInfoPagination(t *testing.T) {
	for _, test := range []struct {
		name    string
		pages   [][]byte
		invalid bool
	}{
		{"continuation flag", [][]byte{completeInfoPage(0x10, 1, 1), infoPage(0x10, 1, 1), infoPage()}, false},
		{"last repeated field", [][]byte{completeInfoPage(0x10, 1, 1, 0x10, 1, 0)}, false},
		{"invalid continuation flag", [][]byte{infoPage(0x10, 1, 1), infoPage(0x10, 1, 255)}, true},
		{"malformed trailing TLV", [][]byte{infoPage(0x10, 1, 1, 0xff)}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			card := &scriptedCard{steps: []cardStep{{
				command:  selectManagementAPDU,
				response: apduResponse([]byte("9.9.9"), iso7816.StatusSuccess),
			}}}
			for i, page := range test.pages {
				card.steps = append(card.steps, cardStep{
					command:  []byte{0, 0x1d, byte(i), 0, 0},
					response: apduResponse(page, iso7816.StatusSuccess),
				})
			}

			info, err := (&Device{card: card}).DeviceInfo(t.Context())
			if test.invalid {
				if !errors.Is(err, yubico.ErrInvalidDeviceInfo) {
					t.Fatalf("error = %v, want invalid device info", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}

			if err == nil && info.FirmwareVersion != (yubico.FirmwareVersion{Major: 5, Minor: 7, Build: 4}) {
				t.Fatal("SELECT response replaced reported firmware")
			}

			if len(card.steps) != 0 || card.ends != 1 || card.closed {
				t.Fatalf("unread steps = %d, transaction ends = %d, closed = %t", len(card.steps), card.ends, card.closed)
			}
		})
	}
}

func TestDeviceClose(t *testing.T) {
	card := &scriptedCard{}
	if err := (&Device{card: card}).Close(); err != nil {
		t.Fatal(err)
	}

	if !card.closed {
		t.Fatal("owned PC/SC connection was not closed")
	}
}

type blockingCard struct {
	started chan struct{}
	closed  chan struct{}
}

func (c *blockingCard) BeginTransaction(context.Context) error { return nil }

func (c *blockingCard) EndTransaction(nativepcsc.Disposition) error { return nil }

func (c *blockingCard) Transmit(ctx context.Context, _ []byte) ([]byte, error) {
	close(c.started)

	select {
	case <-c.closed:
		return nil, nativepcsc.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *blockingCard) Close() error {
	close(c.closed)
	return nil
}

func TestDeviceCloseInterruptsDeviceInfo(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	card := &blockingCard{started: make(chan struct{}), closed: make(chan struct{})}
	device := &Device{card: card}
	readResult := make(chan error, 1)

	go func() {
		_, err := device.DeviceInfo(ctx)
		readResult <- err
	}()

	select {
	case <-card.started:
	case <-time.After(5 * time.Second):
		t.Fatal("DeviceInfo did not start card I/O")
	}

	closeResult := make(chan error, 1)
	go func() { closeResult <- device.Close() }()

	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close waited for the blocked card I/O")
	}

	select {
	case err := <-readResult:
		if !errors.Is(err, nativepcsc.ErrClosed) {
			t.Fatalf("DeviceInfo error = %v, want ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not interrupt DeviceInfo")
	}
}

func TestReadDeviceInfoBorrowsCard(t *testing.T) {
	for _, test := range []struct {
		name    string
		status  iso7816.StatusWord
		wantErr error
	}{
		{"success", iso7816.StatusSuccess, nil},
		{"unsupported command", 0x6d00, yubico.ErrDeviceInfoNotSupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			card := &scriptedCard{steps: []cardStep{
				{command: selectManagementAPDU, response: apduResponse([]byte("9.9.9"), iso7816.StatusSuccess)},
				{command: deviceInfoPage0APDU, response: apduResponse(completeInfoPage(0x10, 1, 1), iso7816.StatusSuccess)},
				{command: deviceInfoPage1APDU, response: apduResponse(infoPage(0x02, 4, 0, 0, 0, 1), test.status)},
			}}

			info, err := ReadDeviceInfo(t.Context(), card)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}

			if err == nil && (info.SerialNumber == nil || *info.SerialNumber != 1 || info.FirmwareVersion != (yubico.FirmwareVersion{Major: 5, Minor: 7, Build: 4})) {
				t.Fatalf("reported data = %#v", info)
			}

			if card.begins != 0 || card.ends != 0 || card.closed || len(card.steps) != 0 {
				t.Fatalf("borrowed card: begin=%d end=%d closed=%t unread=%d", card.begins, card.ends, card.closed, len(card.steps))
			}
		})
	}
}

func completeInfoPage(fields ...byte) []byte {
	base := []byte{
		0x01, 2, 0x02, 0x3f,
		0x03, 2, 0x02, 0x3f,
		0x04, 1, 3,
		0x05, 3, 5, 7, 4,
		0x06, 2, 0, 0,
		0x07, 1, 15,
		0x08, 1, 0,
		0x0a, 1, 0,
	}

	return infoPage(append(base, fields...)...)
}
