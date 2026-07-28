package yubico

import (
	"encoding/binary"
	"errors"
	"fmt"
)

//go:generate go tool stringer -type=Capability,FormFactor -output=device_info_string.go

// Capability is a bitmap of applications exposed by a YubiKey interface.
type Capability uint16

const (
	CapabilityOTP     Capability = 0x0001
	CapabilityU2F     Capability = 0x0002
	CapabilityCCID    Capability = 0x0004
	CapabilityOpenPGP Capability = 0x0008
	CapabilityPIV     Capability = 0x0010
	CapabilityOATH    Capability = 0x0020
	CapabilityHSMAuth Capability = 0x0100
	CapabilityCTAP2   Capability = 0x0200
)

// FirmwareVersion is the major.minor.build version reported by the device.
type FirmwareVersion struct {
	Major byte
	Minor byte
	Build byte
}

// ReleaseType identifies the release stage of qualified firmware.
type ReleaseType byte

const (
	ReleaseTypeAlpha ReleaseType = iota
	ReleaseTypeBeta
	ReleaseTypeFinal
)

// VersionQualifier contains the behavioral firmware version reported by
// development firmware.
type VersionQualifier struct {
	Version     FirmwareVersion
	ReleaseType ReleaseType
	Iteration   uint32
}

// FormFactor describes the physical shape and connector type of a YubiKey.
type FormFactor byte

const (
	FormFactorUnknown               FormFactor = 0
	FormFactorUSBAKeychain          FormFactor = 1
	FormFactorUSBANano              FormFactor = 2
	FormFactorUSBCKeychain          FormFactor = 3
	FormFactorUSBCNano              FormFactor = 4
	FormFactorUSBCLightning         FormFactor = 5
	FormFactorUSBABiometricKeychain FormFactor = 6
	FormFactorUSBCBiometricKeychain FormFactor = 7
)

// DeviceInfo is returned by Yubico's GET DEVICE INFORMATION command.
// UnknownFields preserves tags introduced by newer firmware.
type DeviceInfo struct {
	SupportedUSBCapabilities Capability
	Serial                   *uint32
	EnabledUSBCapabilities   Capability
	FormFactor               FormFactor
	IsFIPS                   bool
	IsSecurityKey            bool
	FirmwareVersion          FirmwareVersion
	VersionQualifier         *VersionQualifier
	AutoEjectTimeout         uint16
	ChallengeResponseTimeout byte
	DeviceFlags              byte
	Locked                   bool
	PinComplexity            bool
	SupportedNFCCapabilities *Capability
	EnabledNFCCapabilities   *Capability
	UnknownFields            map[byte][]byte
}

var ErrInvalidDeviceInfo = errors.New("yubico: invalid device information")

// ParseDeviceInfo parses TOTAL-LENGTH followed by TAG-LENGTH-VALUE fields.
func ParseDeviceInfo(data []byte) (DeviceInfo, error) {
	return ParseDeviceInfoPages(data)
}

// ParseDeviceInfoPages parses and merges one or more paginated device-info
// responses. Fields from later pages replace fields with the same tag from
// earlier pages.
func ParseDeviceInfoPages(pages ...[]byte) (DeviceInfo, error) {
	if len(pages) == 0 {
		return DeviceInfo{}, fmt.Errorf("%w: missing response page", ErrInvalidDeviceInfo)
	}

	info := DeviceInfo{UnknownFields: make(map[byte][]byte)}
	for _, data := range pages {
		if len(data) == 0 || int(data[0]) != len(data)-1 {
			return DeviceInfo{}, fmt.Errorf("%w: total length does not match payload", ErrInvalidDeviceInfo)
		}
		if err := parseDeviceInfoFields(&info, data[1:]); err != nil {
			return DeviceInfo{}, err
		}
	}

	return info, nil
}

func parseDeviceInfoFields(info *DeviceInfo, fields []byte) error {
	for len(fields) > 0 {
		if len(fields) < 2 || int(fields[1]) > len(fields)-2 {
			return fmt.Errorf("%w: truncated TLV", ErrInvalidDeviceInfo)
		}
		tag, length := fields[0], int(fields[1])
		value := fields[2 : 2+length]
		fields = fields[2+length:]

		switch tag {
		case 0x01:
			v, err := capability(tag, value)
			if err != nil {
				return err
			}
			info.SupportedUSBCapabilities = v
		case 0x02:
			if len(value) != 4 {
				return fieldLengthError(tag, 4, len(value))
			}
			v := binary.BigEndian.Uint32(value)
			info.Serial = &v
		case 0x03:
			v, err := capability(tag, value)
			if err != nil {
				return err
			}
			info.EnabledUSBCapabilities = v
		case 0x04:
			if len(value) != 1 {
				return fieldLengthError(tag, 1, len(value))
			}
			info.FormFactor = FormFactor(value[0] & 0x0f)
			info.IsFIPS = value[0]&0x80 != 0
			info.IsSecurityKey = value[0]&0x40 != 0
		case 0x05:
			if len(value) != 3 {
				return fieldLengthError(tag, 3, len(value))
			}
			v := FirmwareVersion{value[0], value[1], value[2]}
			info.FirmwareVersion = v
		case 0x06:
			if len(value) != 2 {
				return fieldLengthError(tag, 2, len(value))
			}
			v := binary.BigEndian.Uint16(value)
			info.AutoEjectTimeout = v
		case 0x07:
			if len(value) != 1 {
				return fieldLengthError(tag, 1, len(value))
			}
			v := value[0]
			info.ChallengeResponseTimeout = v
		case 0x08:
			if len(value) != 1 {
				return fieldLengthError(tag, 1, len(value))
			}
			v := value[0]
			info.DeviceFlags = v
		case 0x0a:
			if len(value) != 1 || value[0] > 1 {
				return fmt.Errorf("%w: invalid locked field", ErrInvalidDeviceInfo)
			}
			v := value[0] == 1
			info.Locked = v
		case 0x0d:
			v, err := capability(tag, value)
			if err != nil {
				return err
			}
			info.SupportedNFCCapabilities = &v
		case 0x0e:
			v, err := capability(tag, value)
			if err != nil {
				return err
			}
			info.EnabledNFCCapabilities = &v
		case 0x10:
			// Pagination metadata is consumed by the transport.
		case 0x16:
			v, err := booleanField(tag, value)
			if err != nil {
				return err
			}
			info.PinComplexity = v
		case 0x19:
			v, err := parseVersionQualifier(tag, value)
			if err != nil {
				return err
			}
			info.VersionQualifier = &v
		default:
			info.UnknownFields[tag] = append([]byte(nil), value...)
		}
	}

	return nil
}

// EffectiveFirmwareVersion returns the version used for behavioral checks.
// Alpha and beta firmware report this version through VersionQualifier.
func (info DeviceInfo) EffectiveFirmwareVersion() FirmwareVersion {
	if info.VersionQualifier != nil &&
		info.VersionQualifier.ReleaseType != ReleaseTypeFinal {
		return info.VersionQualifier.Version
	}

	return info.FirmwareVersion
}

func capability(tag byte, value []byte) (Capability, error) {
	if len(value) != 2 {
		return 0, fieldLengthError(tag, 2, len(value))
	}
	return Capability(binary.BigEndian.Uint16(value)), nil
}

func booleanField(tag byte, value []byte) (bool, error) {
	if len(value) != 1 {
		return false, fieldLengthError(tag, 1, len(value))
	}
	if value[0] > 1 {
		return false, fmt.Errorf("%w: tag 0x%02x has invalid boolean value %d", ErrInvalidDeviceInfo, tag, value[0])
	}

	return value[0] == 1, nil
}

func parseVersionQualifier(tag byte, value []byte) (VersionQualifier, error) {
	var qualifier VersionQualifier
	var hasVersion, hasReleaseType, hasIteration bool

	for fields := value; len(fields) > 0; {
		if len(fields) < 2 || int(fields[1]) > len(fields)-2 {
			return VersionQualifier{}, fmt.Errorf("%w: tag 0x%02x contains truncated TLV", ErrInvalidDeviceInfo, tag)
		}
		fieldTag, length := fields[0], int(fields[1])
		fieldValue := fields[2 : 2+length]
		fields = fields[2+length:]

		switch fieldTag {
		case 0x01:
			if len(fieldValue) != 3 {
				return VersionQualifier{}, fieldLengthError(fieldTag, 3, len(fieldValue))
			}
			qualifier.Version = FirmwareVersion{fieldValue[0], fieldValue[1], fieldValue[2]}
			hasVersion = true
		case 0x02:
			if len(fieldValue) != 1 {
				return VersionQualifier{}, fieldLengthError(fieldTag, 1, len(fieldValue))
			}
			qualifier.ReleaseType = ReleaseType(fieldValue[0])
			if qualifier.ReleaseType > ReleaseTypeFinal {
				return VersionQualifier{}, fmt.Errorf(
					"%w: tag 0x%02x has invalid release type %d",
					ErrInvalidDeviceInfo,
					tag,
					fieldValue[0],
				)
			}
			hasReleaseType = true
		case 0x03:
			if len(fieldValue) != 4 {
				return VersionQualifier{}, fieldLengthError(fieldTag, 4, len(fieldValue))
			}
			qualifier.Iteration = binary.BigEndian.Uint32(fieldValue)
			hasIteration = true
		}
	}

	if !hasVersion || !hasReleaseType || !hasIteration {
		return VersionQualifier{}, fmt.Errorf("%w: tag 0x%02x is incomplete", ErrInvalidDeviceInfo, tag)
	}

	return qualifier, nil
}

func fieldLengthError(tag byte, want, got int) error {
	return fmt.Errorf("%w: tag 0x%02x length is %d, want %d", ErrInvalidDeviceInfo, tag, got, want)
}
