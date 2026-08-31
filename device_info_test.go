package yubico

import (
	"encoding/hex"
	"errors"
	"testing"
)

func TestParseDeviceInfoRejectsMalformedData(t *testing.T) {
	tests := [][]byte{
		nil,
		{0},
		{2, 0x01},
		{3, 0x01, 2, 0xff},
		{4, 0x02, 1, 0xff},
		{3, 0x0a, 1, 2},
		{8, 0x01, 2, 0, 1, 0x0d, 2, 0, 1},
		{8, 0x01, 2, 0, 1, 0x0e, 2, 0, 1},
		{6, 0x01, 2, 0, 1, 0x10, 0},
	}
	for _, data := range tests {
		_, err := ParseDeviceInfo(data)
		if err == nil {
			t.Fatalf("expected an error")
		}
		if got := errors.Is(err, ErrInvalidDeviceInfo); !got {
			t.Errorf("got false, want true")
		}
	}
}

func TestParseDeviceInfoAllowsOmittedAndRepeatedFields(t *testing.T) {
	info, err := ParseDeviceInfo([]byte{12,
		0x01, 2, 0x02, 0x3f,
		0x04, 1, 0x01,
		0x04, 1, 0x03,
		0x30, 0,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := info.FormFactor, FormFactorUSBCKeychain; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got := info.FirmwareVersion; !(got == FirmwareVersion{}) {
		t.Errorf("got %#v, want zero value", got)
	}
}

func TestParseDeviceInfoCurrentYubicoFields(t *testing.T) {
	fields, err := hex.DecodeString(
		"01021206030212060204023251e904010705030000010602000007010f080100" +
			"0a010020030100002103030001100101110400000000120100130c3738434c" +
			"5546583530303050140200001502000016010017010018020000190e010305" +
			"0800020101030400000003",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	{
		got, limit := len(fields), 255
		if got > limit {
			t.Fatalf("got %v, want less than or equal to %v", got, limit)
		}
	}

	info, err := ParseDeviceInfo(append([]byte{byte(len(fields))}, fields...))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := info.VersionQualifier; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}
	{
		want, got := FirmwareVersion{Major: 0, Minor: 0, Build: 1}, info.FirmwareVersion
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := FirmwareVersion{Major: 5, Minor: 8, Build: 0}, info.VersionQualifier.Version
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if got, want := info.VersionQualifier.ReleaseType, ReleaseTypeBeta; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := info.VersionQualifier.Iteration, uint32(3); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	{
		want, got := FirmwareVersion{Major: 5, Minor: 8, Build: 0}, info.EffectiveFirmwareVersion()
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if got := info.PinComplexity; got {
		t.Errorf("got true, want false")
	}
	if got := info.PartNumber; got == nil {
		t.Fatalf("got nil, want a non-nil value")
	}
	if got, want := *info.PartNumber, "78CLUFX5000P"; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	{
		want, got := &FirmwareVersion{Major: 1}, info.FPSVersion
		if got != want && (got == nil || want == nil || *got != *want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	{
		want, got := &FirmwareVersion{Major: 3, Build: 1}, info.STMVersion
		if got != want && (got == nil || want == nil || *got != *want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if _, ok := info.UnknownFields[byte(0x20)]; ok {
		t.Errorf("value unexpectedly contains %#v", byte(0x20))
	}
	if _, ok := info.UnknownFields[byte(0x21)]; ok {
		t.Errorf("value unexpectedly contains %#v", byte(0x21))
	}
	if got, want := info.ModelName("fallback"), "YubiKey C Bio - FIDO Edition"; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestParseDeviceInfoPages(t *testing.T) {
	info, err := ParseDeviceInfoPages(
		[]byte{12,
			0x01, 2, 0x02, 0x3f,
			0x05, 3, 5, 7, 4,
			0x10, 1, 1,
		},
		[]byte{3,
			0x16, 1, 1,
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := info.SupportedUSBCapabilities, Capability(0x023f); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	{
		want, got := FirmwareVersion{Major: 5, Minor: 7, Build: 4}, info.FirmwareVersion
		if got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
	if got := info.PinComplexity; !got {
		t.Errorf("got false, want true")
	}
	if _, ok := info.UnknownFields[byte(0x10)]; ok {
		t.Errorf("value unexpectedly contains %#v", byte(0x10))
	}
}

func TestParseDeviceInfoCurrentCapabilityFields(t *testing.T) {
	info, err := ParseDeviceInfo([]byte{19,
		0x01, 2, 0x02, 0x02,
		0x14, 2, 0x00, 0x1f,
		0x15, 2, 0x00, 0x03,
		0x17, 1, 1,
		0x18, 2, 0x02, 0x10,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := info.FIPSCapable, CapabilityCTAP2|CapabilityPIV|CapabilityOpenPGP|CapabilityOATH|CapabilityHSMAuth; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := info.FIPSApproved, CapabilityCTAP2|CapabilityPIV; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got := info.NFCRestricted; !got {
		t.Errorf("got false, want true")
	}
	if got, want := info.ResetBlocked, CapabilityCTAP2|CapabilityPIV; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestParseDeviceInfoNormalizesYubiKey4Fields(t *testing.T) {
	info, err := ParseDeviceInfo([]byte{13,
		0x01, 2, 0x00, 0x01,
		0x03, 2, 0x00, 0x20,
		0x05, 3, 4, 2, 4,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := info.SupportedUSBCapabilities, Capability(0x003f); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got := info.EnabledUSBCapabilities; !(got == 0) {
		t.Errorf("got %#v, want zero value", got)
	}

	info, err = ParseDeviceInfo([]byte{9,
		0x01, 2, 0x00, 0x3f,
		0x05, 3, 4, 4, 5,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := info.IsFIPS; !got {
		t.Errorf("got false, want true")
	}
}

func TestParseDeviceInfoNormalizesUnknownFormFactor(t *testing.T) {
	info, err := ParseDeviceInfo([]byte{7,
		0x01, 2, 0x02, 0x02,
		0x04, 1, 0x4f,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := info.FormFactor, FormFactorUnknown; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got := info.IsSecurityKey; !got {
		t.Errorf("got false, want true")
	}
}

func TestFormFactorString(t *testing.T) {
	tests := []struct {
		name string
		form FormFactor
		want string
	}{
		{"unknown", FormFactorUnknown, "FormFactorUnknown"},
		{"USB-C nano", FormFactorUSBCNano, "FormFactorUSBCNano"},
		{"USB-C biometric keychain", FormFactorUSBCBiometricKeychain, "FormFactorUSBCBiometricKeychain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, want := tt.form.String(), tt.want; got != want {
				t.Errorf("got %#v, want %#v", got, want)
			}
		})
	}
}
