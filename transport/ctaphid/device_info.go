// Package ctaphid accesses Yubico vendor commands over the CTAPHID protocol.
package ctaphid

import (
	"context"
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

// GetDeviceInfo reads and parses Yubico device information through an existing
// CTAPHID vendor-command channel. The caller retains ownership of transport.
func GetDeviceInfo(ctx context.Context, transport VendorTransport) (yubico.DeviceInfo, error) {
	remainingPages := byte(1)
	var pages [][]byte

	for page := byte(0); remainingPages > 0; page++ {
		remainingPages--
		response, err := transport.Vendor(ctx, CommandGetDeviceInfo, []byte{page})
		if err != nil {
			return yubico.DeviceInfo{}, fmt.Errorf("read Yubico device information over CTAPHID: %w", err)
		}

		pages = append(pages, response.Data)
		if more, ok, err := moreDeviceInfoPages(response.Data); err != nil {
			return yubico.DeviceInfo{}, err
		} else if ok {
			remainingPages = more
		}
	}

	return yubico.ParseDeviceInfoPages(pages...)
}

func moreDeviceInfoPages(data []byte) (byte, bool, error) {
	if len(data) == 0 || int(data[0]) != len(data)-1 {
		return 0, false, fmt.Errorf("%w: total length does not match payload", yubico.ErrInvalidDeviceInfo)
	}

	for fields := data[1:]; len(fields) > 0; {
		if len(fields) < 2 || int(fields[1]) > len(fields)-2 {
			return 0, false, fmt.Errorf("%w: truncated TLV", yubico.ErrInvalidDeviceInfo)
		}
		tag, length := fields[0], int(fields[1])
		value := fields[2 : 2+length]
		fields = fields[2+length:]
		if tag != 0x10 {
			continue
		}
		if len(value) != 1 {
			return 0, false, fmt.Errorf("%w: invalid pagination field", yubico.ErrInvalidDeviceInfo)
		}

		return value[0], true, nil
	}

	return 0, false, nil
}
