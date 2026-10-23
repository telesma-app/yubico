// Package ctaphid accesses Yubico vendor commands over the CTAPHID protocol.
package ctaphid

import (
	"context"
	"errors"
	"fmt"

	lowlevel "github.com/telesma-app/ctap/transport/ctaphid"
	"github.com/telesma-app/yubico"
)

// CommandGetDeviceInfo is Yubico's GET DEVICE INFORMATION command. Its
// logical CTAPHID value is 0x42; CTAPHID framing adds the init-packet bit,
// resulting in the on-wire command byte 0xc2.
const CommandGetDeviceInfo = lowlevel.CTAPHID_VENDOR_FIRST + 2

// VendorTransport is the CTAPHID vendor-command capability required by
// Yubico's device-information command.
type VendorTransport interface {
	Vendor(
		context.Context,
		lowlevel.Command,
		[]byte,
	) (lowlevel.VendorResponse, error)
}

var _ VendorTransport = (*lowlevel.Transport)(nil)

// ReadDeviceInfo reads and parses Yubico device information through an existing
// CTAPHID vendor-command channel. The caller retains ownership of transport.
func ReadDeviceInfo(ctx context.Context, transport VendorTransport) (yubico.DeviceInfo, error) {
	var pages [][]byte

	for page := 0; ; page++ {
		response, err := transport.Vendor(ctx, CommandGetDeviceInfo, []byte{byte(page)})
		if err != nil {
			var responseError *lowlevel.ErrorResponse
			if errors.As(err, &responseError) && responseError.ErrorCode == lowlevel.ERR_INVALID_CMD {
				err = fmt.Errorf("%w: %w", yubico.ErrDeviceInfoNotSupported, err)
			}

			return yubico.DeviceInfo{}, fmt.Errorf("read Yubico device information over CTAPHID: %w", err)
		}

		pages = append(pages, response.Data)

		more, err := moreDeviceInfoPages(response.Data)
		if err != nil {
			return yubico.DeviceInfo{}, err
		}

		if !more {
			break
		}

		if page == 255 {
			return yubico.DeviceInfo{}, fmt.Errorf("%w: pagination exceeds page 255", yubico.ErrInvalidDeviceInfo)
		}
	}

	return yubico.ParseDeviceInfoPages(pages...)
}

func moreDeviceInfoPages(data []byte) (bool, error) {
	if len(data) == 0 || int(data[0]) != len(data)-1 {
		return false, fmt.Errorf("%w: total length does not match payload", yubico.ErrInvalidDeviceInfo)
	}

	var more bool

	for fields := data[1:]; len(fields) > 0; {
		if len(fields) < 2 || int(fields[1]) > len(fields)-2 {
			return false, fmt.Errorf("%w: truncated TLV", yubico.ErrInvalidDeviceInfo)
		}

		tag, length := fields[0], int(fields[1])
		value := fields[2 : 2+length]
		fields = fields[2+length:]

		if tag != 0x10 {
			continue
		}

		if len(value) != 1 || value[0] > 1 {
			return false, fmt.Errorf("%w: invalid pagination field", yubico.ErrInvalidDeviceInfo)
		}

		more = value[0] == 1
	}

	return more, nil
}
