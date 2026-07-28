package yubico

import (
	"strconv"
	"strings"
)

// String formats a non-zero firmware version as major.minor.build.
func (v FirmwareVersion) String() string {
	if v == (FirmwareVersion{}) {
		return ""
	}

	return strconv.Itoa(int(v.Major)) + "." +
		strconv.Itoa(int(v.Minor)) + "." +
		strconv.Itoa(int(v.Build))
}

// ModelName returns the canonical marketing name derived from Yubico device
// information. fallback is returned for firmware generations whose naming
// rules are not known.
func (info DeviceInfo) ModelName(fallback string) string {
	version := info.EffectiveFirmwareVersion()
	if isPreviewFirmware(version) {
		return "YubiKey Preview"
	}

	if version.Major != 5 || version.Minor < 1 {
		return fallback
	}

	isNano := info.FormFactor == FormFactorUSBANano ||
		info.FormFactor == FormFactorUSBCNano
	isBio := info.FormFactor == FormFactorUSBABiometricKeychain ||
		info.FormFactor == FormFactorUSBCBiometricKeychain
	isUSBTypeC := info.FormFactor == FormFactorUSBCKeychain ||
		info.FormFactor == FormFactorUSBCNano ||
		info.FormFactor == FormFactorUSBCBiometricKeychain

	var parts []string
	if info.IsSecurityKey {
		parts = []string{"Security Key"}
	} else {
		parts = []string{"YubiKey"}
		if !isBio {
			parts = append(parts, "5")
		}
	}

	if isUSBTypeC {
		parts = append(parts, "C")
	} else if info.FormFactor == FormFactorUSBCLightning {
		parts = append(parts, "Ci")
	}

	if isNano {
		parts = append(parts, "Nano")
	} else if info.HasNFC() {
		parts = append(parts, "NFC")
	} else if info.FormFactor == FormFactorUSBAKeychain {
		parts = append(parts, "A")
	} else if isBio {
		parts = append(parts, "Bio")
	}

	if info.IsFIPS {
		parts = append(parts, "FIPS")
	} else if isBio {
		switch {
		case isFIDOOnly(info.SupportedUSBCapabilities):
			parts = append(parts, "- FIDO Edition")
		case info.SupportedUSBCapabilities&CapabilityPIV != 0:
			parts = append(parts, "- Multi-protocol Edition")
		}
	} else if info.IsSecurityKey && info.Serial != nil {
		parts = append(parts, "- Enterprise Edition")
	} else if info.PinComplexity && !info.IsSecurityKey {
		parts = append(parts, "- Enhanced PIN")
	}

	name := strings.Join(parts, " ")
	name = strings.Replace(name, "5 C", "5C", 1)
	return strings.Replace(name, "5 A", "5A", 1)
}

// HasNFC reports whether NFC capability data is valid for this form factor and
// firmware generation.
func (info DeviceInfo) HasNFC() bool {
	if info.SupportedNFCCapabilities == nil && info.EnabledNFCCapabilities == nil {
		return false
	}

	switch info.FormFactor {
	case FormFactorUSBANano,
		FormFactorUSBCNano,
		FormFactorUSBCLightning:
		return false
	case FormFactorUSBCKeychain:
		return firmwareAtLeast(info.EffectiveFirmwareVersion(), FirmwareVersion{Major: 5, Minor: 2, Build: 4})
	default:
		return true
	}
}

func isPreviewFirmware(version FirmwareVersion) bool {
	ranges := [][2]FirmwareVersion{
		{{Major: 5}, {Major: 5, Minor: 1}},
		{{Major: 5, Minor: 2}, {Major: 5, Minor: 2, Build: 3}},
		{{Major: 5, Minor: 5}, {Major: 5, Minor: 5, Build: 2}},
	}

	for _, firmwareRange := range ranges {
		if firmwareAtLeast(version, firmwareRange[0]) &&
			!firmwareAtLeast(version, firmwareRange[1]) {
			return true
		}
	}

	return false
}

func firmwareAtLeast(got, want FirmwareVersion) bool {
	if got.Major != want.Major {
		return got.Major > want.Major
	}
	if got.Minor != want.Minor {
		return got.Minor > want.Minor
	}

	return got.Build >= want.Build
}

func isFIDOOnly(value Capability) bool {
	nonFIDO := CapabilityOTP |
		CapabilityOATH |
		CapabilityPIV |
		CapabilityOpenPGP |
		CapabilityHSMAuth
	fido := CapabilityU2F | CapabilityCTAP2

	return value&nonFIDO == 0 && value&fido != 0
}
