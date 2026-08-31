package ctaphid

import (
	"bytes"
	"context"
	"errors"
	"testing"

	lowlevel "github.com/telesma-app/ctap/transport/ctaphid"
	"github.com/telesma-app/yubico"
)

const (
	reportSize    = 65
	initPacketBit = 0x80
)

type scriptedDevice struct {
	reads         *bytes.Reader
	writes        bytes.Buffer
	writeContexts []context.Context
	closed        bool
}

func (d *scriptedDevice) Read(_ context.Context, p []byte) (int, error) {
	return d.reads.Read(p)
}

func (d *scriptedDevice) Write(ctx context.Context, p []byte) (int, error) {
	d.writeContexts = append(d.writeContexts, ctx)
	return d.writes.Write(p)
}

func (d *scriptedDevice) Close() error {
	d.closed = true
	return nil
}

func TestDeviceInfo(t *testing.T) {
	type contextKey struct{}

	ctx := context.WithValue(t.Context(), contextKey{}, "device-info")
	cid := lowlevel.ChannelID{1, 2, 3, 4}
	payload := []byte{4, 0x01, 2, 0x02, 0x3f}
	rawDevice := newScriptedDevice(responseBytes(t, cid, CommandGetDeviceInfo, payload))
	device := &Device{transport: lowlevel.NewTransport(rawDevice, cid)}

	info, err := device.DeviceInfo(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := info.SupportedUSBCapabilities, yubico.Capability(0x023f); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	written := rawDevice.writes.Bytes()
	if got, want := len(written), reportSize; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}
	if got, want := written[5], byte(CommandGetDeviceInfo)|initPacketBit; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := written[1:5], cid[:]; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := len(rawDevice.writeContexts), 1; got != want {
		t.Fatalf("got length %d, want %d", got, want)
	}
	{
		want, got := "device-info", rawDevice.writeContexts[0].Value(contextKey{})
		gotValue, ok := got.(string)

		if !ok || gotValue != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestClose(t *testing.T) {
	rawDevice := newScriptedDevice()
	device := &Device{
		transport: lowlevel.NewTransport(rawDevice, lowlevel.ChannelID{}),
	}

	if err := device.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := rawDevice.closed; !got {
		t.Errorf("got false, want true")
	}
}

func TestOpenRejectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := Open(ctx, "unused")

	if err, target := err, context.Canceled; !errors.Is(err, target) {
		t.Errorf("got error %v, want errors.Is(error, %#v)", err, target)
	}
}

func newScriptedDevice(responses ...[]byte) *scriptedDevice {
	return &scriptedDevice{reads: bytes.NewReader(bytes.Join(responses, nil))}
}

func responseBytes(
	t testing.TB,
	cid lowlevel.ChannelID,
	command lowlevel.Command,
	data []byte,
) []byte {
	t.Helper()

	message, err := lowlevel.NewMessage(cid, command, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var reports bytes.Buffer
	_, err = message.WriteTo(&reports)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	encoded := reports.Bytes()
	var response []byte
	for len(encoded) > 0 {
		{
			got, limit := len(encoded), reportSize
			if got < limit {
				t.Fatalf("got %v, want greater than or equal to %v", got, limit)
			}
		}
		response = append(response, encoded[1:reportSize]...)
		encoded = encoded[reportSize:]
	}

	return response
}

var _ lowlevel.Device = (*scriptedDevice)(nil)
