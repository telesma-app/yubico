package ctaphid

import (
	"bytes"
	"context"
	"testing"

	lowlevel "github.com/go-ctap/ctap/transport/ctaphid"
	"github.com/go-ctap/yubico"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)
	assert.Equal(t, yubico.Capability(0x023f), info.SupportedUSBCapabilities)

	written := rawDevice.writes.Bytes()
	require.Len(t, written, reportSize)
	assert.Equal(t, byte(CommandGetDeviceInfo)|initPacketBit, written[5])
	assert.Equal(t, cid[:], written[1:5])
	require.Len(t, rawDevice.writeContexts, 1)
	assert.Equal(t, "device-info", rawDevice.writeContexts[0].Value(contextKey{}))
}

func TestClose(t *testing.T) {
	rawDevice := newScriptedDevice()
	device := &Device{
		transport: lowlevel.NewTransport(rawDevice, lowlevel.ChannelID{}),
	}

	require.NoError(t, device.Close())
	assert.True(t, rawDevice.closed)
}

func TestOpenRejectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := Open(ctx, "unused")

	assert.ErrorIs(t, err, context.Canceled)
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
	require.NoError(t, err)

	var reports bytes.Buffer
	_, err = message.WriteTo(&reports)
	require.NoError(t, err)

	encoded := reports.Bytes()
	var response []byte
	for len(encoded) > 0 {
		require.GreaterOrEqual(t, len(encoded), reportSize)
		response = append(response, encoded[1:reportSize]...)
		encoded = encoded[reportSize:]
	}

	return response
}

var _ lowlevel.Device = (*scriptedDevice)(nil)
