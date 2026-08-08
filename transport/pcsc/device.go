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

// Open connects to the Yubico device in reader.
func Open(reader string) (*Device, error) {
	card, err := nativepcsc.Open(
		reader,
		nativepcsc.WithDisconnectDisposition(nativepcsc.DispositionResetCard),
	)
	if err != nil {
		return nil, err
	}

	return &Device{card: card}, nil
}

// Close closes the PC/SC connection.
func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

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

	if err := d.selectManagement(ctx); err != nil {
		return yubico.DeviceInfo{}, err
	}

	return d.readDeviceInfo(ctx)
}

func (d *Device) selectManagement(ctx context.Context) error {
	response, err := iso7816.Exchange(ctx, d.card, iso7816.Command{
		CLA:      0x00,
		INS:      0xa4,
		P1:       0x04,
		Data:     managementAID,
		Encoding: iso7816.EncodingShort,
	})
	if err != nil {
		return err
	}
	switch response.Status {
	case 0x6999, 0x6a82, 0x6b00, 0x6d00:
		return fmt.Errorf(
			"%w: %w",
			ErrManagementApplicationNotAvailable,
			response.APDUError(),
		)
	}

	return response.APDUError()
}

func (d *Device) readDeviceInfo(ctx context.Context) (yubico.DeviceInfo, error) {
	remainingPages := byte(1)
	var pages [][]byte

	for page := byte(0); remainingPages > 0; page++ {
		remainingPages--
		response, err := iso7816.Exchange(ctx, d.card, iso7816.Command{
			CLA:      0x00,
			INS:      0x1d,
			P1:       page,
			Le:       256,
			Encoding: iso7816.EncodingShort,
		})
		if err != nil {
			return yubico.DeviceInfo{}, err
		}
		if err := response.APDUError(); err != nil {
			return yubico.DeviceInfo{}, err
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
		return 0, false, yubico.ErrInvalidDeviceInfo
	}
	for fields := data[1:]; len(fields) > 0; {
		if len(fields) < 2 || int(fields[1]) > len(fields)-2 {
			return 0, false, yubico.ErrInvalidDeviceInfo
		}
		tag, length := fields[0], int(fields[1])
		value := fields[2 : 2+length]
		fields = fields[2+length:]
		if tag == 0x10 {
			if len(value) != 1 {
				return 0, false, yubico.ErrInvalidDeviceInfo
			}
			return value[0], true, nil
		}
	}

	return 0, false, nil
}
