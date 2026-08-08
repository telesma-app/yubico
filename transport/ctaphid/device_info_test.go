package ctaphid

import (
	"context"
	"errors"
	"slices"
	"testing"

	lowlevel "github.com/telesma-app/ctap/transport/ctaphid"
	"github.com/telesma-app/yubico"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type scriptedTransport struct {
	response  lowlevel.VendorResponse
	responses map[byte]lowlevel.VendorResponse
	err       error
	ctx       context.Context
	command   lowlevel.Command
	data      []byte
	allData   [][]byte
}

func (t *scriptedTransport) Vendor(
	ctx context.Context,
	command lowlevel.Command,
	data []byte,
) (lowlevel.VendorResponse, error) {
	t.ctx = ctx
	t.command = command
	t.data = slices.Clone(data)
	t.allData = append(t.allData, slices.Clone(data))

	if t.responses != nil {
		return t.responses[data[0]], t.err
	}
	return t.response, t.err
}

func TestGetDeviceInfo(t *testing.T) {
	type contextKey struct{}

	ctx := context.WithValue(t.Context(), contextKey{}, "device-info")
	payload := []byte{39,
		0x01, 2, 0x02, 0x3f,
		0x02, 4, 0x00, 0x12, 0x34, 0x56,
		0x03, 2, 0x02, 0x22,
		0x04, 1, 0x43,
		0x05, 3, 5, 7, 1,
		0x06, 2, 0x00, 0x0a,
		0x07, 1, 15,
		0x08, 1, 0x40,
		0x0a, 1, 1,
		0x30, 2, 0xaa, 0xbb,
	}
	transport := &scriptedTransport{
		response: lowlevel.VendorResponse{Data: payload},
	}

	info, err := GetDeviceInfo(ctx, transport)
	require.NoError(t, err)
	require.NotNil(t, info.Serial)
	assert.Equal(t, uint32(0x00123456), *info.Serial)
	assert.Equal(t, yubico.Capability(0x023f), info.SupportedUSBCapabilities)
	assert.Equal(t, yubico.FirmwareVersion{Major: 5, Minor: 7, Build: 1}, info.FirmwareVersion)
	assert.Equal(t, yubico.FormFactorUSBCKeychain, info.FormFactor)
	assert.True(t, info.IsSecurityKey)
	assert.False(t, info.IsFIPS)
	assert.True(t, info.Locked)
	assert.Equal(t, uint16(10), info.AutoEjectTimeout)
	assert.Equal(t, byte(15), info.ChallengeResponseTimeout)
	assert.Equal(t, []byte{0xaa, 0xbb}, info.UnknownFields[0x30])

	assert.Equal(t, CommandGetDeviceInfo, transport.command)
	assert.Equal(t, []byte{0}, transport.data)
	assert.Equal(t, "device-info", transport.ctx.Value(contextKey{}))
}

func TestGetDeviceInfoReadsAdditionalPages(t *testing.T) {
	transport := &scriptedTransport{
		responses: map[byte]lowlevel.VendorResponse{
			0: {Data: []byte{12,
				0x01, 2, 0x02, 0x3f,
				0x05, 3, 5, 7, 4,
				0x10, 1, 1,
			}},
			1: {Data: []byte{3,
				0x16, 1, 1,
			}},
		},
	}

	info, err := GetDeviceInfo(t.Context(), transport)
	require.NoError(t, err)
	assert.Equal(t, [][]byte{{0}, {1}}, transport.allData)
	assert.Equal(t, yubico.Capability(0x023f), info.SupportedUSBCapabilities)
	assert.True(t, info.PinComplexity)
}

func TestGetDeviceInfoPreservesTransportError(t *testing.T) {
	transportErr := errors.New("transport failed")
	transport := &scriptedTransport{err: transportErr}

	_, err := GetDeviceInfo(t.Context(), transport)

	assert.ErrorIs(t, err, transportErr)
}
