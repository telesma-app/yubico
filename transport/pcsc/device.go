// Package pcsc provides access to Yubico devices over PC/SC.
package pcsc

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/telesma-app/iso7816"
	nativepcsc "github.com/telesma-app/pcsc"
	"github.com/telesma-app/yubico"
)

// ErrManagementApplicationNotAvailable reports that the selected card does
// not expose Yubico's management application.
var ErrManagementApplicationNotAvailable = errors.New(
	"yubico pcsc: management application not available",
)

var managementAID = []byte{
	0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17,
}

type card interface {
	iso7816.Card
	BeginTransaction(context.Context) error
	EndTransaction(nativepcsc.Disposition) error
	Close() error
}

// Device is a Yubico device connected through a PC/SC reader.
type Device struct {
	mu   sync.Mutex
	card card
}

// Open connects to the Yubico device in reader and returns a caller-owned device.
// Options are passed to the native PC/SC connection; Close leaves the card
// powered by default. Use nativepcsc.WithDisconnectDisposition to request a reset.
func Open(reader string, opts ...nativepcsc.OpenOption) (*Device, error) {
	card, err := nativepcsc.Open(reader, opts...)
	if err != nil {
		return nil, err
	}

	return &Device{card: card}, nil
}

// Close closes the PC/SC connection, canceling an active card operation when
// supported by the native implementation.
func (d *Device) Close() error {
	return d.card.Close()
}

// DeviceInfo reads Yubico device information.
func (d *Device) DeviceInfo(
	ctx context.Context,
) (info yubico.DeviceInfo, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.card.BeginTransaction(ctx); err != nil {
		return yubico.DeviceInfo{}, err
	}
	defer func() {
		err = errors.Join(
			err,
			d.card.EndTransaction(nativepcsc.DispositionLeaveCard),
		)
	}()

	return ReadDeviceInfo(ctx, d.card)
}

// ReadDeviceInfo selects management on a borrowed card and leaves it selected.
// The caller serializes access, manages the transaction and subsequent applet
// selection, and retains ownership of the card.
func ReadDeviceInfo(ctx context.Context, card iso7816.Card) (yubico.DeviceInfo, error) {
	response, err := iso7816.Exchange(ctx, card, iso7816.Command{
		CLA:      0x00,
		INS:      0xa4,
		P1:       0x04,
		Data:     managementAID,
		Encoding: iso7816.EncodingShort,
	})
	if err != nil {
		return yubico.DeviceInfo{}, err
	}

	switch response.Status {
	case 0x6999, 0x6a82, 0x6b00, 0x6d00:
		return yubico.DeviceInfo{}, fmt.Errorf(
			"%w: %w",
			ErrManagementApplicationNotAvailable,
			response.APDUError(),
		)
	}

	if err := response.APDUError(); err != nil {
		return yubico.DeviceInfo{}, err
	}

	var pages [][]byte

	for page := 0; ; page++ {
		response, err := iso7816.Exchange(ctx, card, iso7816.Command{
			CLA:      0x00,
			INS:      0x1d,
			P1:       byte(page),
			Le:       256,
			Encoding: iso7816.EncodingShort,
		})
		if err != nil {
			return yubico.DeviceInfo{}, err
		}

		if err := response.APDUError(); err != nil {
			if response.Status == 0x6d00 {
				err = fmt.Errorf("%w: %w", yubico.ErrDeviceInfoNotSupported, err)
			}

			return yubico.DeviceInfo{}, err
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
		return false, yubico.ErrInvalidDeviceInfo
	}

	var more bool

	for fields := data[1:]; len(fields) > 0; {
		if len(fields) < 2 || int(fields[1]) > len(fields)-2 {
			return false, yubico.ErrInvalidDeviceInfo
		}

		tag, length := fields[0], int(fields[1])
		value := fields[2 : 2+length]
		fields = fields[2+length:]

		if tag == 0x10 {
			if len(value) != 1 || value[0] > 1 {
				return false, yubico.ErrInvalidDeviceInfo
			}

			more = value[0] == 1
		}
	}

	return more, nil
}
