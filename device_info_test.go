package yubico

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidDeviceInfo))
	}
}

func TestParseDeviceInfoAllowsOmittedAndRepeatedFields(t *testing.T) {
	info, err := ParseDeviceInfo([]byte{12,
		0x01, 2, 0x02, 0x3f,
		0x04, 1, 0x01,
		0x04, 1, 0x03,
		0x30, 0,
	})
	require.NoError(t, err)
	assert.Equal(t, FormFactorUSBCKeychain, info.FormFactor)
	assert.Zero(t, info.FirmwareVersion)
}

func TestParseDeviceInfoCurrentYubicoFields(t *testing.T) {
	fields, err := hex.DecodeString(
		"01021206030212060204023251e904010705030000010602000007010f080100" +
			"0a010020030100002103030001100101110400000000120100130c3738434c" +
			"5546583530303050140200001502000016010017010018020000190e010305" +
			"0800020101030400000003",
	)
	require.NoError(t, err)
	require.LessOrEqual(t, len(fields), 255)

	info, err := ParseDeviceInfo(append([]byte{byte(len(fields))}, fields...))
	require.NoError(t, err)
	require.NotNil(t, info.VersionQualifier)
	assert.Equal(t, FirmwareVersion{Major: 0, Minor: 0, Build: 1}, info.FirmwareVersion)
	assert.Equal(t, FirmwareVersion{Major: 5, Minor: 8, Build: 0}, info.VersionQualifier.Version)
	assert.Equal(t, ReleaseTypeBeta, info.VersionQualifier.ReleaseType)
	assert.Equal(t, uint32(3), info.VersionQualifier.Iteration)
	assert.Equal(t, FirmwareVersion{Major: 5, Minor: 8, Build: 0}, info.EffectiveFirmwareVersion())
	assert.False(t, info.PinComplexity)
	require.NotNil(t, info.PartNumber)
	assert.Equal(t, "78CLUFX5000P", *info.PartNumber)
	assert.Equal(t, &FirmwareVersion{Major: 1}, info.FPSVersion)
	assert.Equal(t, &FirmwareVersion{Major: 3, Build: 1}, info.STMVersion)
	assert.NotContains(t, info.UnknownFields, byte(0x20))
	assert.NotContains(t, info.UnknownFields, byte(0x21))
	assert.Equal(t, "YubiKey C Bio - FIDO Edition", info.ModelName("fallback"))
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
	require.NoError(t, err)
	assert.Equal(t, Capability(0x023f), info.SupportedUSBCapabilities)
	assert.Equal(t, FirmwareVersion{Major: 5, Minor: 7, Build: 4}, info.FirmwareVersion)
	assert.True(t, info.PinComplexity)
	assert.NotContains(t, info.UnknownFields, byte(0x10))
}

func TestParseDeviceInfoCurrentCapabilityFields(t *testing.T) {
	info, err := ParseDeviceInfo([]byte{19,
		0x01, 2, 0x02, 0x02,
		0x14, 2, 0x00, 0x1f,
		0x15, 2, 0x00, 0x03,
		0x17, 1, 1,
		0x18, 2, 0x02, 0x10,
	})
	require.NoError(t, err)

	assert.Equal(t,
		CapabilityCTAP2|CapabilityPIV|CapabilityOpenPGP|CapabilityOATH|CapabilityHSMAuth,
		info.FIPSCapable,
	)
	assert.Equal(t, CapabilityCTAP2|CapabilityPIV, info.FIPSApproved)
	assert.True(t, info.NFCRestricted)
	assert.Equal(t, CapabilityCTAP2|CapabilityPIV, info.ResetBlocked)
}

func TestParseDeviceInfoNormalizesYubiKey4Fields(t *testing.T) {
	info, err := ParseDeviceInfo([]byte{13,
		0x01, 2, 0x00, 0x01,
		0x03, 2, 0x00, 0x20,
		0x05, 3, 4, 2, 4,
	})
	require.NoError(t, err)
	assert.Equal(t, Capability(0x003f), info.SupportedUSBCapabilities)
	assert.Zero(t, info.EnabledUSBCapabilities)

	info, err = ParseDeviceInfo([]byte{9,
		0x01, 2, 0x00, 0x3f,
		0x05, 3, 4, 4, 5,
	})
	require.NoError(t, err)
	assert.True(t, info.IsFIPS)
}

func TestParseDeviceInfoNormalizesUnknownFormFactor(t *testing.T) {
	info, err := ParseDeviceInfo([]byte{7,
		0x01, 2, 0x02, 0x02,
		0x04, 1, 0x4f,
	})
	require.NoError(t, err)
	assert.Equal(t, FormFactorUnknown, info.FormFactor)
	assert.True(t, info.IsSecurityKey)
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
			assert.Equal(t, tt.want, tt.form.String())
		})
	}
}
