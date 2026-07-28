package yubico

import "testing"

func TestDeviceInfoModelName(t *testing.T) {
	nfc := CapabilityU2F | CapabilityCTAP2
	serial := uint32(12345678)
	version := FirmwareVersion{Major: 5, Minor: 7, Build: 1}
	tests := []struct {
		name string
		info DeviceInfo
		want string
	}{
		{"USB-C nano", DeviceInfo{FirmwareVersion: version, FormFactor: FormFactorUSBCNano}, "YubiKey 5C Nano"},
		{"USB-C NFC", DeviceInfo{FirmwareVersion: version, FormFactor: FormFactorUSBCKeychain, SupportedNFCCapabilities: &nfc}, "YubiKey 5C NFC"},
		{"USB-A NFC", DeviceInfo{FirmwareVersion: version, FormFactor: FormFactorUSBAKeychain, SupportedNFCCapabilities: &nfc}, "YubiKey 5 NFC"},
		{"USB-A", DeviceInfo{FirmwareVersion: version, FormFactor: FormFactorUSBAKeychain}, "YubiKey 5A"},
		{"USB-C Lightning", DeviceInfo{FirmwareVersion: version, FormFactor: FormFactorUSBCLightning, SupportedNFCCapabilities: &nfc}, "YubiKey 5Ci"},
		{"invalid early NFC", DeviceInfo{FirmwareVersion: FirmwareVersion{Major: 5, Minor: 2, Build: 3}, FormFactor: FormFactorUSBCKeychain, SupportedNFCCapabilities: &nfc}, "YubiKey 5C"},
		{"valid NFC", DeviceInfo{FirmwareVersion: FirmwareVersion{Major: 5, Minor: 2, Build: 4}, FormFactor: FormFactorUSBCKeychain, SupportedNFCCapabilities: &nfc}, "YubiKey 5C NFC"},
		{"security key", DeviceInfo{FirmwareVersion: version, FormFactor: FormFactorUSBCKeychain, IsSecurityKey: true, SupportedNFCCapabilities: &nfc}, "Security Key C NFC"},
		{"enterprise", DeviceInfo{FirmwareVersion: version, FormFactor: FormFactorUSBCKeychain, IsSecurityKey: true, Serial: &serial, SupportedNFCCapabilities: &nfc}, "Security Key C NFC - Enterprise Edition"},
		{"FIPS", DeviceInfo{FirmwareVersion: version, FormFactor: FormFactorUSBCNano, IsFIPS: true}, "YubiKey 5C Nano FIPS"},
		{"bio FIDO", DeviceInfo{FirmwareVersion: version, FormFactor: FormFactorUSBABiometricKeychain, SupportedUSBCapabilities: CapabilityU2F | CapabilityCTAP2}, "YubiKey Bio - FIDO Edition"},
		{"bio multi", DeviceInfo{FirmwareVersion: version, FormFactor: FormFactorUSBCBiometricKeychain, SupportedUSBCapabilities: CapabilityU2F | CapabilityCTAP2 | CapabilityPIV}, "YubiKey C Bio - Multi-protocol Edition"},
		{"unknown", DeviceInfo{FirmwareVersion: version}, "YubiKey 5"},
		{"unknown NFC", DeviceInfo{FirmwareVersion: version, SupportedNFCCapabilities: &nfc}, "YubiKey 5 NFC"},
		{"enhanced PIN", DeviceInfo{FirmwareVersion: version, FormFactor: FormFactorUSBCKeychain, PinComplexity: true, SupportedNFCCapabilities: &nfc}, "YubiKey 5C NFC - Enhanced PIN"},
		{
			"qualified beta firmware",
			DeviceInfo{
				FirmwareVersion: FirmwareVersion{Major: 0, Minor: 0, Build: 1},
				VersionQualifier: &VersionQualifier{
					Version:     FirmwareVersion{Major: 5, Minor: 8, Build: 0},
					ReleaseType: ReleaseTypeBeta,
					Iteration:   3,
				},
				FormFactor:               FormFactorUSBCBiometricKeychain,
				SupportedUSBCapabilities: CapabilityU2F | CapabilityCTAP2,
			},
			"YubiKey C Bio - FIDO Edition",
		},
		{"preview 5.0", DeviceInfo{FirmwareVersion: FirmwareVersion{Major: 5}, FormFactor: FormFactorUSBCNano}, "YubiKey Preview"},
		{"preview 5.2.2", DeviceInfo{FirmwareVersion: FirmwareVersion{Major: 5, Minor: 2, Build: 2}, FormFactor: FormFactorUSBCNano}, "YubiKey Preview"},
		{"preview 5.5.1", DeviceInfo{FirmwareVersion: FirmwareVersion{Major: 5, Minor: 5, Build: 1}, FormFactor: FormFactorUSBCNano}, "YubiKey Preview"},
		{"production 5.5.2", DeviceInfo{FirmwareVersion: FirmwareVersion{Major: 5, Minor: 5, Build: 2}, FormFactor: FormFactorUSBCNano}, "YubiKey 5C Nano"},
		{"unsupported", DeviceInfo{FirmwareVersion: FirmwareVersion{Major: 4, Minor: 4, Build: 5}, FormFactor: FormFactorUSBCNano}, "fallback"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.info.ModelName("fallback"); got != test.want {
				t.Fatalf("ModelName() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestFirmwareVersionString(t *testing.T) {
	if got := (FirmwareVersion{Major: 5, Minor: 7, Build: 1}).String(); got != "5.7.1" {
		t.Fatalf("String() = %q", got)
	}
	if got := (FirmwareVersion{}).String(); got != "" {
		t.Fatalf("zero String() = %q", got)
	}
}
