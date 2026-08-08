// Package resolver identifies Yubico devices through local auxiliary
// transports.
package resolver

import (
	"context"
	"errors"

	"github.com/telesma-app/yubico"
	yubicopcsc "github.com/telesma-app/yubico/transport/pcsc"
)

// ErrNotApplicable reports that the exact smart-card target is not a Yubico
// device exposing the management application.
var ErrNotApplicable = errors.New("yubico resolver: target is not Yubico")

type device interface {
	Close() error
	DeviceInfo(context.Context) (yubico.DeviceInfo, error)
}

// Resolver resolves smart-card targets through PC/SC.
type Resolver struct {
	openPCSC func(string) (device, error)
}

// NewLocal creates a resolver backed by the host PC/SC service.
func NewLocal() *Resolver {
	return &Resolver{
		openPCSC: func(reader string) (device, error) {
			return yubicopcsc.Open(reader)
		},
	}
}

// ResolveSmartCard reads device information from the exact PC/SC reader.
func (r *Resolver) ResolveSmartCard(
	ctx context.Context,
	reader string,
) (yubico.DeviceInfo, error) {
	if err := ctx.Err(); err != nil {
		return yubico.DeviceInfo{}, err
	}

	opened, err := r.openPCSC(reader)
	if err != nil {
		return yubico.DeviceInfo{}, err
	}
	defer func() {
		_ = opened.Close()
	}()

	info, err := opened.DeviceInfo(ctx)
	if errors.Is(
		err,
		yubicopcsc.ErrManagementApplicationNotAvailable,
	) {
		return yubico.DeviceInfo{}, ErrNotApplicable
	}

	return info, err
}
