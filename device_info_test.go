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
		{2, 0x01},
		{3, 0x01, 2, 0xff},
		{4, 0x02, 1, 0xff},
		{3, 0x0a, 1, 2},
	}
	for _, data := range tests {
		_, err := ParseDeviceInfo(data)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidDeviceInfo))
	}
}

func TestParseDeviceInfoAllowsOmittedAndRepeatedFields(t *testing.T) {
	info, err := ParseDeviceInfo([]byte{8,
		0x04, 1, 0x01,
		0x04, 1, 0x03,
		0x20, 0,
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
