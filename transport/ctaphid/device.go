package ctaphid

import (
	"context"
	"errors"
	"fmt"

	lowlevel "github.com/go-ctap/ctap/transport/ctaphid"
	hidapi "github.com/go-ctap/hid"
	"github.com/go-ctap/yubico"
)

// Device is a Yubico device connected through the CTAPHID protocol.
type Device struct {
	transport *lowlevel.Transport
}

// Open opens the FIDO HID collection at path and allocates a CTAPHID channel.
func Open(ctx context.Context, path string) (*Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	device, err := hidapi.OpenPath(path)
	if err != nil {
		return nil, err
	}

	transport, err := lowlevel.Open(ctx, device)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("initialize CTAPHID channel: %w", err),
			device.Close(),
		)
	}

	return &Device{transport: transport}, nil
}

// DeviceInfo reads Yubico device information.
func (d *Device) DeviceInfo(ctx context.Context) (yubico.DeviceInfo, error) {
	return GetDeviceInfo(ctx, d.transport)
}

// Close closes the underlying HID device.
func (d *Device) Close() error {
	return d.transport.Close()
}
