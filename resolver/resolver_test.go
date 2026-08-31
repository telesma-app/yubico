package resolver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/telesma-app/yubico"
	yubicopcsc "github.com/telesma-app/yubico/transport/pcsc"
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
		if got, want := reader, "reader-one"; got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
		return opened, nil
	}

	got, err := resolver.ResolveSmartCard(t.Context(), "reader-one")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := want, got
		gotJSON, gotErr := json.Marshal(got)
		wantJSON, wantErr := json.Marshal(want)
		if gotErr != nil || wantErr != nil {
			t.Fatalf("marshal device info: got error %v, want error %v", gotErr, wantErr)
		}
		if string(gotJSON) != string(wantJSON) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if got := opened.closed; !got {
		t.Errorf("got false, want true")
	}
}

func TestResolveSmartCardClassifiesMissingApplication(t *testing.T) {
	resolver := NewLocal()
	resolver.openPCSC = func(string) (device, error) {
		return &fakeDevice{
			infoErr: yubicopcsc.ErrManagementApplicationNotAvailable,
		}, nil
	}

	_, err := resolver.ResolveSmartCard(t.Context(), "reader-one")
	if err, target := err, ErrNotApplicable; !errors.Is(err, target) {
		t.Fatalf("got error %v, want errors.Is(error, %#v)", err, target)
	}
	if got := errors.Is(
		err,
		yubicopcsc.ErrManagementApplicationNotAvailable,
	); got {
		t.Fatalf("got true, want false")
	}
}
