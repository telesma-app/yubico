package ctaphid

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	lowlevel "github.com/telesma-app/ctap/transport/ctaphid"
	"github.com/telesma-app/yubico"
)

const (
	reportSize    = 65
	initPacketBit = 0x80
)

type scriptedDevice struct {
	t             testing.TB
	cid           lowlevel.ChannelID
	initReply     chan []byte
	ready         chan struct{}
	start         sync.Once
	reads         *bytes.Reader
	writes        bytes.Buffer
	writeContexts []context.Context
	closed        bool
}

func (d *scriptedDevice) Read(ctx context.Context, p []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case reply := <-d.initReply:
		return copy(p, reply), nil
	case <-d.ready:
		return d.reads.Read(p)
	}
}

func (d *scriptedDevice) Write(ctx context.Context, p []byte) (int, error) {
	if p[5] == byte(lowlevel.CTAPHID_INIT)|initPacketBit {
		data := append([]byte(nil), p[8:16]...)
		data = append(data, d.cid[:]...)

		data = append(data, 2, 1, 0, 0, 0x04)
		d.initReply <- responseBytes(d.t, lowlevel.BROADCAST_CID, lowlevel.CTAPHID_INIT, data)

		return len(p), nil
	}

	d.writeContexts = append(d.writeContexts, ctx)
	n, err := d.writes.Write(p)
	d.start.Do(func() { close(d.ready) })

	return n, err
}

func (d *scriptedDevice) Close() error {
	d.closed = true
	return nil
}

func TestDeviceInfo(t *testing.T) {
	type contextKey struct{}

	ctx := context.WithValue(t.Context(), contextKey{}, "device-info")
	cid := lowlevel.ChannelID{1, 2, 3, 4}
	payload := completeInfoPage()
	rawDevice := newScriptedDevice(responseBytes(t, cid, CommandGetDeviceInfo, payload))
	device := &Device{transport: openTestTransport(t, rawDevice, cid)}

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
		transport: openTestTransport(t, rawDevice, lowlevel.ChannelID{}),
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

func TestDeviceInfoPreservesWireProtocolError(t *testing.T) {
	cid := lowlevel.ChannelID{1, 2, 3, 4}
	raw := newScriptedDevice(responseBytes(t, cid, lowlevel.CTAPHID_ERROR, []byte{byte(lowlevel.ERR_INVALID_CMD)}))
	device := &Device{transport: openTestTransport(t, raw, cid)}

	_, err := device.DeviceInfo(t.Context())
	if !errors.Is(err, yubico.ErrDeviceInfoNotSupported) {
		t.Fatalf("error = %v, want unsupported command", err)
	}

	var protocolErr *lowlevel.ErrorResponse
	if !errors.As(err, &protocolErr) || protocolErr.ErrorCode != lowlevel.ERR_INVALID_CMD {
		t.Fatalf("underlying protocol error lost: %v", err)
	}

	if raw.closed {
		t.Fatal("read closed the caller-owned channel")
	}
}

func openTestTransport(t testing.TB, raw *scriptedDevice, cid lowlevel.ChannelID) *lowlevel.Transport {
	t.Helper()
	raw.t = t
	raw.cid = cid
	raw.initReply = make(chan []byte, 1)
	raw.ready = make(chan struct{})

	transport, err := lowlevel.Open(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = transport.Close() })

	return transport
}
