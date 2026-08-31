package ctaphid

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	lowlevel "github.com/telesma-app/ctap/transport/ctaphid"
	"github.com/telesma-app/yubico"
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := info.Serial; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}
	if got, want := *info.Serial, uint32(0x00123456); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := info.SupportedUSBCapabilities, yubico.Capability(0x023f); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	{
		want, got := yubico.FirmwareVersion{Major: 5, Minor: 7, Build: 1}, info.FirmwareVersion
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if got, want := info.FormFactor, yubico.FormFactorUSBCKeychain; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got := info.IsSecurityKey; !got {
		t.Errorf("got false, want true")
	}
	if got := info.IsFIPS; got {
		t.Errorf("got true, want false")
	}
	if got := info.Locked; !got {
		t.Errorf("got false, want true")
	}
	if got, want := info.AutoEjectTimeout, uint16(10); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := info.ChallengeResponseTimeout, byte(15); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	{
		want, got := []byte{0xaa, 0xbb}, info.UnknownFields[0x30]
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	if got, want := transport.command, CommandGetDeviceInfo; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	{
		want, got := []byte{0}, transport.data
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := "device-info", transport.ctx.Value(contextKey{})
		gotValue, ok := got.(string)

		if !ok || gotValue != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		want, got := [][]byte{{0}, {1}}, transport.allData
		if (got == nil) != (want == nil) || !slices.EqualFunc(got, want, func(got, want []byte) bool {
			return (got == nil) == (want == nil) && bytes.Equal(got, want)
		}) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if got, want := info.SupportedUSBCapabilities, yubico.Capability(0x023f); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got := info.PinComplexity; !got {
		t.Errorf("got false, want true")
	}
}

func TestGetDeviceInfoPreservesTransportError(t *testing.T) {
	transportErr := errors.New("transport failed")
	transport := &scriptedTransport{err: transportErr}

	_, err := GetDeviceInfo(t.Context(), transport)

	if err, target := err, transportErr; !errors.Is(err, target) {
		t.Errorf("got error %v, want errors.Is(error, %#v)", err, target)
	}
}
