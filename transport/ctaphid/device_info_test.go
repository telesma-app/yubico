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
	allData   [][]byte
}

func (t *scriptedTransport) Vendor(
	ctx context.Context,
	command lowlevel.Command,
	data []byte,
) (lowlevel.VendorResponse, error) {
	t.ctx = ctx
	t.command = command
	t.allData = append(t.allData, slices.Clone(data))

	if t.responses != nil {
		return t.responses[data[0]], t.err
	}

	return t.response, t.err
}

func TestReadDeviceInfo(t *testing.T) {
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

	info, err := ReadDeviceInfo(ctx, transport)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := info.SerialNumber; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}

	if got, want := *info.SerialNumber, uint32(0x00123456); got != want {
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
		want, got := []byte{0xaa, 0xbb}, info.RawFields[0x30]
		if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}

	if got, want := transport.command, CommandGetDeviceInfo; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}

	if got, want := transport.allData, [][]byte{{0}}; !slices.EqualFunc(got, want, bytes.Equal) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	{
		want, got := "device-info", transport.ctx.Value(contextKey{})
		gotValue, ok := got.(string)

		if !ok || gotValue != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestReadDeviceInfoReadsAdditionalPages(t *testing.T) {
	transport := &scriptedTransport{
		responses: map[byte]lowlevel.VendorResponse{
			0: {Data: []byte{12,
				0x01, 2, 0x02, 0x3f,
				0x05, 3, 5, 7, 4,
				0x10, 1, 1,
			}},
			1: {Data: infoPage(
				0x03, 2, 0x02, 0x3f,
				0x04, 1, 3,
				0x06, 2, 0, 0,
				0x07, 1, 15,
				0x08, 1, 0,
				0x0a, 1, 0,
				0x16, 1, 1,
			)},
		},
	}

	info, err := ReadDeviceInfo(t.Context(), transport)
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

	if got := *info.PinComplexity; !got {
		t.Errorf("got false, want true")
	}
}

func TestReadDeviceInfoPreservesTransportError(t *testing.T) {
	transportErr := errors.New("transport failed")
	transport := &scriptedTransport{err: transportErr}

	_, err := ReadDeviceInfo(t.Context(), transport)

	if err, target := err, transportErr; !errors.Is(err, target) {
		t.Errorf("got error %v, want errors.Is(error, %#v)", err, target)
	}
}

func TestReadDeviceInfoClassifiesProtocolErrors(t *testing.T) {
	for _, code := range []lowlevel.Error{lowlevel.ERR_INVALID_CMD, lowlevel.ERR_CHANNEL_BUSY, 0xfe} {
		protocolErr := &lowlevel.ErrorResponse{ErrorCode: code}
		transport := &scriptedTransport{err: protocolErr}

		_, err := ReadDeviceInfo(t.Context(), transport)
		if got, want := errors.Is(err, yubico.ErrDeviceInfoNotSupported), code == lowlevel.ERR_INVALID_CMD; got != want {
			t.Errorf("code %v: unsupported = %t, want %t", code, got, want)
		}

		var got *lowlevel.ErrorResponse
		if !errors.As(err, &got) || got != protocolErr {
			t.Errorf("code %v: underlying error lost: %v", code, err)
		}
	}
}

func TestReadDeviceInfoPagination(t *testing.T) {
	for _, test := range []struct {
		name      string
		responses map[byte]lowlevel.VendorResponse
		wantPages int
		invalid   bool
	}{
		{
			name: "continuation flag on every nonfinal page",
			responses: map[byte]lowlevel.VendorResponse{
				0: {Data: completeInfoPage(0x10, 1, 1)},
				1: {Data: []byte{3, 0x10, 1, 1}},
				2: {Data: []byte{0}},
			},
			wantPages: 3,
		},
		{
			name: "last repeated pagination field wins",
			responses: map[byte]lowlevel.VendorResponse{
				0: {Data: completeInfoPage(0x10, 1, 1, 0x10, 1, 0)},
			},
			wantPages: 1,
		},
		{
			name: "reject invalid continuation flag",
			responses: map[byte]lowlevel.VendorResponse{
				0: {Data: []byte{3, 0x10, 1, 1}},
				1: {Data: []byte{3, 0x10, 1, 255}},
			},
			wantPages: 2,
			invalid:   true,
		},
		{
			name: "malformed page",
			responses: map[byte]lowlevel.VendorResponse{
				0: {Data: []byte{3, 0x10, 1, 1}},
				1: {Data: []byte{3, 0x01, 2, 0}},
			},
			wantPages: 2,
			invalid:   true,
		},
		{
			name: "validate TLV after pagination field",
			responses: map[byte]lowlevel.VendorResponse{
				0: {Data: []byte{4, 0x10, 1, 1, 0xff}},
			},
			wantPages: 1,
			invalid:   true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &scriptedTransport{responses: test.responses}

			_, err := ReadDeviceInfo(t.Context(), transport)
			if test.invalid {
				if !errors.Is(err, yubico.ErrInvalidDeviceInfo) {
					t.Fatalf("error = %v, want invalid device info", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}

			if len(transport.allData) != test.wantPages {
				t.Fatalf("pages = %v, want %d", transport.allData, test.wantPages)
			}
		})
	}
}

func TestReadDeviceInfoReadsLastAddressablePage(t *testing.T) {
	responses := map[byte]lowlevel.VendorResponse{
		0: {Data: completeInfoPage(0x10, 1, 1)},
	}
	for i := 1; i < 255; i++ {
		responses[byte(i)] = lowlevel.VendorResponse{Data: []byte{3, 0x10, 1, 1}}
	}

	responses[255] = lowlevel.VendorResponse{Data: []byte{0}}

	transport := &scriptedTransport{responses: responses}
	if _, err := ReadDeviceInfo(t.Context(), transport); err != nil {
		t.Fatal(err)
	}

	if len(transport.allData) != 256 || transport.allData[255][0] != 255 {
		t.Fatalf("did not read pages 0..255: %v", transport.allData)
	}
}

func infoPage(fields ...byte) []byte {
	return append([]byte{byte(len(fields))}, fields...)
}

func completeInfoPage(fields ...byte) []byte {
	base := []byte{
		0x01, 2, 0x02, 0x3f,
		0x03, 2, 0x02, 0x3f,
		0x04, 1, 3,
		0x05, 3, 5, 7, 4,
		0x06, 2, 0, 0,
		0x07, 1, 15,
		0x08, 1, 0,
		0x0a, 1, 0,
	}

	return infoPage(append(base, fields...)...)
}

func TestReadDeviceInfoRejectsContinuationAfterLastPage(t *testing.T) {
	responses := make(map[byte]lowlevel.VendorResponse)
	for page := 0; page <= 255; page++ {
		responses[byte(page)] = lowlevel.VendorResponse{Data: []byte{3, 0x10, 1, 1}}
	}

	transport := &scriptedTransport{responses: responses}

	_, err := ReadDeviceInfo(t.Context(), transport)
	if !errors.Is(err, yubico.ErrInvalidDeviceInfo) || len(transport.allData) != 256 {
		t.Fatalf("overflow: pages=%d, error=%v", len(transport.allData), err)
	}
}
