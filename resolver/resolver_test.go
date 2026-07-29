package resolver

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ctap/yubico"
	yubicopcsc "github.com/go-ctap/yubico/transport/pcsc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeDevice struct {
	info    yubico.DeviceInfo
	infoErr error
	closed  bool
}

func (d *fakeDevice) DeviceInfo(context.Context) (yubico.DeviceInfo, error) {
	return d.info, d.infoErr
}

func (d *fakeDevice) Close() error {
	d.closed = true
	return nil
}

func TestResolveSmartCard(t *testing.T) {
	want := yubico.DeviceInfo{
		FirmwareVersion: yubico.FirmwareVersion{
			Major: 5,
			Minor: 7,
			Build: 1,
		},
	}
	opened := &fakeDevice{info: want}
	resolver := NewLocal()
	resolver.openPCSC = func(reader string) (device, error) {
		assert.Equal(t, "reader-one", reader)
		return opened, nil
	}

	got, err := resolver.ResolveSmartCard(t.Context(), "reader-one")
	require.NoError(t, err)
	assert.Equal(t, want, got)
	assert.True(t, opened.closed)
}

func TestResolveSmartCardClassifiesMissingApplication(t *testing.T) {
	resolver := NewLocal()
	resolver.openPCSC = func(string) (device, error) {
		return &fakeDevice{
			infoErr: yubicopcsc.ErrManagementApplicationNotAvailable,
		}, nil
	}

	_, err := resolver.ResolveSmartCard(t.Context(), "reader-one")
	require.ErrorIs(t, err, ErrNotApplicable)
	require.False(t, errors.Is(
		err,
		yubicopcsc.ErrManagementApplicationNotAvailable,
	))
}
