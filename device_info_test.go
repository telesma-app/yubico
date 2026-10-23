package yubico

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestParseDeviceInfoRejectsMalformedData(t *testing.T) {
	for _, data := range [][]byte{
		nil,
		{2, 0x01},
		{3, 0x01, 2, 0xff},
		{1, 0x01},
		completeInfoPage(0x0a, 1, 2),
		completeInfoPage(0x16, 1, 2),
		completeInfoPage(0x17, 1, 2),
		completeInfoPage(0x13, 1, 0xff),
		completeInfoPage(0x19, 1, 0x01),
		completeInfoPage(0x19, 3, 0x01, 3, 5),
		completeInfoPage(0x19, 3, 0x01, 1, 5),
		completeInfoPage(0x19, 2, 0x02, 0),
		completeInfoPage(0x19, 2, 0x03, 0),
	} {
		if _, err := ParseDeviceInfo(data); !errors.Is(err, ErrInvalidDeviceInfo) {
			t.Errorf("ParseDeviceInfo(%x) error = %v, want ErrInvalidDeviceInfo", data, err)
		}
	}

	for _, tag := range []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a,
		0x0d, 0x0e, 0x10, 0x14, 0x15, 0x16, 0x17, 0x18, 0x20, 0x21,
	} {
		if _, err := ParseDeviceInfo(completeInfoPage(tag, 0)); !errors.Is(err, ErrInvalidDeviceInfo) {
			t.Errorf("empty tag 0x%02x error = %v, want ErrInvalidDeviceInfo", tag, err)
		}
	}
}

func TestParseDeviceInfoPreservesPresence(t *testing.T) {
	absent := parseInfo(t)
	if absent.SerialNumber != nil || absent.VersionQualifier != nil || absent.PartNumber != nil ||
		absent.SupportedNFCCapabilities != nil || absent.EnabledNFCCapabilities != nil ||
		absent.FIPSCapable != nil || absent.FIPSApproved != nil || absent.PinComplexity != nil ||
		absent.NFCRestricted != nil || absent.ResetBlocked != nil || absent.FPSVersion != nil || absent.STMVersion != nil {
		t.Fatalf("absent optional fields acquired values: %#v", absent)
	}

	info := parseInfo(t,
		0x01, 2, 0, 0,
		0x02, 4, 0, 0, 0, 0,
		0x03, 2, 0, 0,
		0x04, 1, 0,
		0x05, 3, 0, 0, 0,
		0x06, 2, 0, 0,
		0x07, 1, 0,
		0x08, 1, 0,
		0x0a, 1, 0,
		0x0d, 2, 0, 0,
		0x0e, 2, 0, 0,
		0x13, 0,
		0x14, 2, 0, 0,
		0x15, 2, 0, 0,
		0x16, 1, 0,
		0x17, 1, 0,
		0x18, 2, 0, 0,
		0x19, 14, 1, 3, 0, 0, 0, 2, 1, 0, 3, 4, 0, 0, 0, 0,
		0x20, 3, 0, 0, 0,
		0x21, 3, 0, 0, 0,
	)
	requireEqual(t, info.SupportedUSBCapabilities, Capability(0))
	requireValue(t, info.SerialNumber, uint32(0))
	requireValue(t, info.EnabledUSBCapabilities, Capability(0))
	requireEqual(t, info.FormFactor, FormFactorUnknown)
	requireEqual(t, info.IsFIPS, false)
	requireEqual(t, info.IsSecurityKey, false)
	requireEqual(t, info.FirmwareVersion, FirmwareVersion{})
	requireEqual(t, info.AutoEjectTimeout, uint16(0))
	requireEqual(t, info.ChallengeResponseTimeout, byte(0))
	requireEqual(t, info.DeviceFlags, byte(0))
	requireEqual(t, info.Locked, false)
	requireValue(t, info.SupportedNFCCapabilities, Capability(0))
	requireValue(t, info.EnabledNFCCapabilities, Capability(0))
	requireValue(t, info.PartNumber, "")
	requireValue(t, info.FIPSCapable, FIPSCapability(0))
	requireValue(t, info.FIPSApproved, FIPSCapability(0))
	requireValue(t, info.PinComplexity, false)
	requireValue(t, info.NFCRestricted, false)
	requireValue(t, info.ResetBlocked, Capability(0))
	requireValue(t, info.FPSVersion, FirmwareVersion{})
	requireValue(t, info.STMVersion, FirmwareVersion{})
	requireEqual(t, info.VersionQualifier.Version, FirmwareVersion{})
	requireEqual(t, info.VersionQualifier.ReleaseType, ReleaseTypeAlpha)
	requireEqual(t, info.VersionQualifier.Iteration, uint32(0))

	// Optional zero values must remain distinguishable in the report's JSON.
	for _, test := range []struct {
		info    DeviceInfo
		present bool
	}{
		{absent, false},
		{info, true},
	} {
		encoded, err := json.Marshal(test.info)
		if err != nil {
			t.Fatal(err)
		}

		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}

		for _, name := range []string{"serialNumber", "partNumber", "pinComplexity", "versionQualifier"} {
			if _, present := fields[name]; present != test.present {
				t.Errorf("JSON field %s presence = %t, want %t", name, present, test.present)
			}
		}

		for _, name := range []string{"supportedUSBCapabilities", "formFactor", "firmwareVersion", "autoEjectTimeout", "challengeResponseTimeout", "deviceFlags", "locked", "isFIPS", "isSecurityKey"} {
			if _, present := fields[name]; !present {
				t.Errorf("required JSON field %s missing", name)
			}
		}
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
		t.Fatal(err)
	}

	info, err := ParseDeviceInfo(infoPage(fields...))
	if err != nil {
		t.Fatal(err)
	}

	requireValue(t, info.SerialNumber, uint32(36852201))
	requireEqual(t, info.SupportedUSBCapabilities, Capability(0x1206))
	requireValue(t, info.EnabledUSBCapabilities, Capability(0x1206))
	requireEqual(t, info.FormFactor, FormFactorUSBCBiometricKeychain)
	requireEqual(t, info.FirmwareVersion, FirmwareVersion{Build: 1})

	if info.VersionQualifier == nil {
		t.Fatal("missing qualifier")
	}

	requireEqual(t, info.VersionQualifier.Version, FirmwareVersion{Major: 5, Minor: 8})
	requireEqual(t, info.VersionQualifier.ReleaseType, ReleaseTypeBeta)
	requireEqual(t, info.VersionQualifier.Iteration, uint32(3))
	requireValue(t, info.PinComplexity, false)
	requireValue(t, info.PartNumber, "78CLUFX5000P")
	requireValue(t, info.FPSVersion, FirmwareVersion{Major: 1})
	requireValue(t, info.STMVersion, FirmwareVersion{Major: 3, Build: 1})

	if got := info.RawFields[0x11]; !bytes.Equal(got, []byte{0, 0, 0, 0}) {
		t.Errorf("unknown field = %x", got)
	}
}

func TestParseDeviceInfoPreservesUnknownValues(t *testing.T) {
	info := parseInfo(t,
		0x01, 2, 0x80, 0x01,
		0x04, 1, 0xff,
		0x08, 1, 0xff,
		0x14, 2, 0x80, 0x1f,
		0x15, 2, 0x40, 0x03,
		0x19, 18, 0x01, 3, 5, 8, 0, 0x02, 1, 0xff, 0x03, 4, 0, 0, 0, 1, 0x80, 2, 0xaa, 0xbb,
		0xfe, 2, 0xff, 0x01,
		0xff, 0,
	)
	requireEqual(t, info.SupportedUSBCapabilities, Capability(0x8001))
	requireEqual(t, info.FormFactor, FormFactor(15))
	requireEqual(t, info.IsFIPS, true)
	requireEqual(t, info.IsSecurityKey, true)
	requireEqual(t, info.DeviceFlags, byte(0xff))
	requireValue(t, info.FIPSCapable, FIPSCapability(0x8000)|FIPSCapabilityCTAP2|FIPSCapabilityPIV|FIPSCapabilityOpenPGP|FIPSCapabilityOATH|FIPSCapabilityHSMAuth)
	requireValue(t, info.FIPSApproved, FIPSCapability(0x4000)|FIPSCapabilityCTAP2|FIPSCapabilityPIV)
	requireEqual(t, info.VersionQualifier.ReleaseType, ReleaseType(0xff))

	if got := info.VersionQualifier.RawFields[0x80]; !bytes.Equal(got, []byte{0xaa, 0xbb}) {
		t.Errorf("unknown qualifier TLV = %x", got)
	}

	if got := info.RawFields[0x04]; !bytes.Equal(got, []byte{0xff}) {
		t.Errorf("raw form factor = %x", got)
	}

	if got := info.RawFields[0xfe]; !bytes.Equal(got, []byte{0xff, 0x01}) {
		t.Errorf("unknown TLV = %x", got)
	}

	if got, ok := info.RawFields[0xff]; !ok || len(got) != 0 {
		t.Errorf("empty unknown TLV = %x, present %t", got, ok)
	}
}

func TestParseDeviceInfoDoesNotCorrectFirmware(t *testing.T) {
	for _, version := range []FirmwareVersion{
		{Major: 4, Minor: 2, Build: 4},
		{Major: 4, Minor: 4, Build: 5},
		{Major: 5, Minor: 2, Build: 3},
	} {
		t.Run(version.String(), func(t *testing.T) {
			info := parseInfo(t,
				0x01, 2, 0, 1,
				0x03, 2, 0, 0x20,
				0x04, 1, 0x03,
				0x05, 3, version.Major, version.Minor, version.Build,
				0x0d, 2, 0, 2,
				0x0e, 2, 0, 0,
			)
			requireEqual(t, info.SupportedUSBCapabilities, CapabilityOTP)
			requireValue(t, info.EnabledUSBCapabilities, CapabilityOATH)
			requireEqual(t, info.IsFIPS, false)
			requireEqual(t, info.FirmwareVersion, version)
			requireValue(t, info.SupportedNFCCapabilities, CapabilityU2F)
			requireValue(t, info.EnabledNFCCapabilities, Capability(0))
		})
	}
}

func TestParseDeviceInfoPages(t *testing.T) {
	first := infoPage(
		0x01, 2, 0x02, 0x3f,
		0x04, 1, 0xc1,
		0x04, 1, 0x03,
		0x05, 3, 5, 7, 4,
		0x10, 1, 1,
		0xfe, 1, 1,
	)
	last := infoPage(
		0x03, 2, 0, 0, 0x06, 2, 0, 0, 0x07, 1, 0, 0x08, 1, 0, 0x0a, 1, 0,
		0x01, 2, 0, 0, 0x16, 1, 1, 0xfe, 1, 2,
	)

	info, err := ParseDeviceInfoPages(first, last)
	if err != nil {
		t.Fatal(err)
	}

	requireEqual(t, info.SupportedUSBCapabilities, Capability(0))
	requireEqual(t, info.FormFactor, FormFactorUSBCKeychain)
	requireEqual(t, info.IsFIPS, false)
	requireEqual(t, info.IsSecurityKey, false)
	requireEqual(t, info.FirmwareVersion, FirmwareVersion{Major: 5, Minor: 7, Build: 4})
	requireValue(t, info.PinComplexity, true)

	if got := info.RawFields[0xfe]; !bytes.Equal(got, []byte{2}) {
		t.Errorf("raw repeated TLV = %x", got)
	}

	clear(first)
	clear(last)

	if got := info.RawFields[0xfe]; !bytes.Equal(got, []byte{2}) {
		t.Errorf("raw TLV changed with input: %x", got)
	}
}

func TestParseDeviceInfoQualifierPresenceAndOwnership(t *testing.T) {
	data := completeInfoPage(0x19, 14,
		1, 3, 0, 0, 0,
		2, 1, 0,
		3, 4, 0, 0, 0, 0,
	)

	info, err := ParseDeviceInfo(data)
	if err != nil {
		t.Fatal(err)
	}

	requireEqual(t, info.VersionQualifier.Version, FirmwareVersion{})
	requireEqual(t, info.VersionQualifier.ReleaseType, ReleaseTypeAlpha)
	requireEqual(t, info.VersionQualifier.Iteration, uint32(0))
	requireEqual(t, info.FirmwareVersion, FirmwareVersion{Major: 5, Minor: 7, Build: 4})

	for i := range data {
		data[i] = 0xff
	}

	if got := info.VersionQualifier.RawFields[1]; !bytes.Equal(got, []byte{0, 0, 0}) {
		t.Errorf("qualifier raw data changed with input: %x", got)
	}
}

func TestFirmwareVersionString(t *testing.T) {
	for _, test := range []struct {
		version FirmwareVersion
		want    string
	}{
		{FirmwareVersion{Major: 5, Minor: 7, Build: 1}, "5.7.1"},
		{FirmwareVersion{}, "0.0.0"},
	} {
		if got := test.version.String(); got != test.want {
			t.Errorf("String() = %q, want %q", got, test.want)
		}
	}
}

func TestFormFactorString(t *testing.T) {
	if got := FormFactor(15).String(); got != "FormFactor(15)" {
		t.Fatalf("unknown form factor string = %q", got)
	}
}

func infoPage(fields ...byte) []byte {
	return append([]byte{byte(len(fields))}, fields...)
}

func parseInfo(t *testing.T, fields ...byte) DeviceInfo {
	t.Helper()

	info, err := ParseDeviceInfo(completeInfoPage(fields...))
	if err != nil {
		t.Fatal(err)
	}

	return info
}

func requireValue[T comparable](t *testing.T, got *T, want T) {
	t.Helper()

	if got == nil {
		t.Fatalf("absent value, want %#v", want)
	}

	if *got != want {
		t.Errorf("got %#v, want %#v", *got, want)
	}
}

// baseFields is a complete response in the documented YubiKey 5 format.
func baseFields() []byte {
	return []byte{
		0x01, 2, 0x02, 0x3f,
		0x03, 2, 0x02, 0x3f,
		0x04, 1, 3,
		0x05, 3, 5, 7, 4,
		0x06, 2, 0, 0,
		0x07, 1, 15,
		0x08, 1, 0,
		0x0a, 1, 0,
	}
}

func completeInfoPage(fields ...byte) []byte {
	return infoPage(append(baseFields(), fields...)...)
}

func withoutTag(fields []byte, tag byte) []byte {
	var result []byte

	for len(fields) > 0 {
		length := 2 + int(fields[1])
		if fields[0] != tag {
			result = append(result, fields[:length]...)
		}

		fields = fields[length:]
	}

	return result
}

func requireEqual[T comparable](t *testing.T, got, want T) {
	t.Helper()

	if got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestParseDeviceInfoRequiresBaseFields(t *testing.T) {
	for _, tag := range []byte{0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a} {
		t.Run(fmt.Sprintf("tag_%02x", tag), func(t *testing.T) {
			page := infoPage(withoutTag(baseFields(), tag)...)

			_, err := ParseDeviceInfo(page)
			if !errors.Is(err, ErrInvalidDeviceInfo) || !strings.Contains(err.Error(), fmt.Sprintf("0x%02x", tag)) {
				t.Fatalf("missing tag 0x%02x: error = %v", tag, err)
			}
		})
	}

	if _, err := ParseDeviceInfo([]byte{0}); !errors.Is(err, ErrInvalidDeviceInfo) {
		t.Fatalf("empty response error = %v", err)
	}
}

func TestParseDeviceInfoYubiKey4MayOmitEnabledUSB(t *testing.T) {
	fields := withoutTag(baseFields(), 0x03)
	for _, version := range []FirmwareVersion{
		{Major: 4, Minor: 2, Build: 4},
		{Major: 4, Minor: 4, Build: 5},
	} {
		page := infoPage(append(fields, 0x05, 3, version.Major, version.Minor, version.Build)...)

		info, err := ParseDeviceInfo(page)
		if err != nil {
			t.Fatal(err)
		}

		if info.EnabledUSBCapabilities != nil {
			t.Fatal("omitted enabled USB capabilities acquired a value")
		}

		requireEqual(t, info.SupportedUSBCapabilities, Capability(0x023f))
		requireEqual(t, info.IsFIPS, false)
	}
	// A later page can supply the version which makes the omission valid.
	_, err := ParseDeviceInfoPages(
		infoPage(withoutTag(fields, 0x05)...),
		infoPage(0x05, 3, 4, 4, 5),
	)
	if err != nil {
		t.Fatal(err)
	}
	// The last version wins; an earlier YubiKey 4 version must not waive the
	// requirement for a final YubiKey 5 response.
	_, err = ParseDeviceInfoPages(
		infoPage(append(fields, 0x05, 3, 4, 4, 5)...),
		infoPage(0x05, 3, 5, 7, 4),
	)
	if !errors.Is(err, ErrInvalidDeviceInfo) {
		t.Fatalf("final YubiKey 5 version without USB enabled: %v", err)
	}
}

func TestParseDeviceInfoRequiresPairedNFCFields(t *testing.T) {
	for _, tag := range []byte{0x0d, 0x0e} {
		if _, err := ParseDeviceInfo(completeInfoPage(tag, 2, 0, 0)); !errors.Is(err, ErrInvalidDeviceInfo) {
			t.Fatalf("unpaired NFC tag 0x%02x: %v", tag, err)
		}
	}

	info, err := ParseDeviceInfoPages(
		completeInfoPage(0x0d, 2, 0, 0),
		infoPage(0x0e, 2, 0, 0),
	)
	if err != nil {
		t.Fatal(err)
	}

	requireValue(t, info.SupportedNFCCapabilities, Capability(0))
	requireValue(t, info.EnabledNFCCapabilities, Capability(0))
}

func TestParseDeviceInfoRequiresCompleteQualifier(t *testing.T) {
	qualifier := []byte{1, 3, 5, 8, 0, 2, 1, 0, 3, 4, 0, 0, 0, 0}
	for _, tag := range []byte{1, 2, 3} {
		fields := withoutTag(qualifier, tag)

		_, err := ParseDeviceInfo(completeInfoPage(append([]byte{0x19, byte(len(fields))}, fields...)...))
		if !errors.Is(err, ErrInvalidDeviceInfo) || !strings.Contains(err.Error(), "version qualifier") {
			t.Fatalf("qualifier without tag %d: %v", tag, err)
		}
	}

	if _, err := ParseDeviceInfo(completeInfoPage(0x19, 0)); !errors.Is(err, ErrInvalidDeviceInfo) {
		t.Fatalf("empty qualifier: %v", err)
	}
	// Presence requirements apply to the final merged value, not a replaced TLV.
	info, err := ParseDeviceInfoPages(
		completeInfoPage(0x19, 0),
		infoPage(append([]byte{0x19, byte(len(qualifier))}, qualifier...)...),
	)
	if err != nil {
		t.Fatal(err)
	}

	requireEqual(t, info.VersionQualifier.Version, FirmwareVersion{Major: 5, Minor: 8})
	requireEqual(t, info.VersionQualifier.ReleaseType, ReleaseTypeAlpha)
	requireEqual(t, info.VersionQualifier.Iteration, uint32(0))
}
