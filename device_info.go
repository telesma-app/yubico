package yubico

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
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

const (
	tagUSBSupported     byte = 0x01
	tagSerial           byte = 0x02
	tagUSBEnabled       byte = 0x03
	tagFormFactor       byte = 0x04
	tagFirmwareVersion  byte = 0x05
	tagAutoEjectTimeout byte = 0x06
	tagChallengeTimeout byte = 0x07
	tagDeviceFlags      byte = 0x08
	tagLocked           byte = 0x0a
	tagNFCSupported     byte = 0x0d
	tagNFCEnabled       byte = 0x0e
	tagMoreData         byte = 0x10
	tagPartNumber       byte = 0x13
	tagFIPSCapable      byte = 0x14
	tagFIPSApproved     byte = 0x15
	tagPinComplexity    byte = 0x16
	tagNFCRestricted    byte = 0x17
	tagResetBlocked     byte = 0x18
	tagVersionQualifier byte = 0x19
	tagFPSVersion       byte = 0x20
	tagSTMVersion       byte = 0x21
)

// FirmwareVersion is the major.minor.build version reported by the device.
type FirmwareVersion struct {
	Major byte `json:"major"`
	Minor byte `json:"minor"`
	Build byte `json:"build"`
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
	Version     FirmwareVersion `json:"version"`
	ReleaseType ReleaseType     `json:"releaseType"`
	Iteration   uint32          `json:"iteration"`
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
	SupportedUSBCapabilities Capability        `json:"supportedUSBCapabilities"`
	Serial                   *uint32           `json:"serial,omitempty"`
	EnabledUSBCapabilities   Capability        `json:"enabledUSBCapabilities"`
	FormFactor               FormFactor        `json:"formFactor"`
	IsFIPS                   bool              `json:"isFIPS"`
	IsSecurityKey            bool              `json:"isSecurityKey"`
	FirmwareVersion          FirmwareVersion   `json:"firmwareVersion"`
	VersionQualifier         *VersionQualifier `json:"versionQualifier,omitempty"`
	AutoEjectTimeout         uint16            `json:"autoEjectTimeout"`
	ChallengeResponseTimeout byte              `json:"challengeResponseTimeout"`
	DeviceFlags              byte              `json:"deviceFlags"`
	Locked                   bool              `json:"locked"`
	PartNumber               *string           `json:"partNumber,omitempty"`
	FIPSCapable              Capability        `json:"fipsCapable"`
	FIPSApproved             Capability        `json:"fipsApproved"`
	PinComplexity            bool              `json:"pinComplexity"`
	NFCRestricted            bool              `json:"nfcRestricted"`
	ResetBlocked             Capability        `json:"resetBlocked"`
	FPSVersion               *FirmwareVersion  `json:"fpsVersion,omitempty"`
	STMVersion               *FirmwareVersion  `json:"stmVersion,omitempty"`
	SupportedNFCCapabilities *Capability       `json:"supportedNFCCapabilities,omitempty"`
	EnabledNFCCapabilities   *Capability       `json:"enabledNFCCapabilities,omitempty"`
	UnknownFields            map[byte][]byte   `json:"unknownFields"`
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
	seen := make(map[byte]bool)
	for _, data := range pages {
		if len(data) == 0 || int(data[0]) != len(data)-1 {
			return DeviceInfo{}, fmt.Errorf("%w: total length does not match payload", ErrInvalidDeviceInfo)
		}
		if err := parseDeviceInfoFields(&info, seen, data[1:]); err != nil {
			return DeviceInfo{}, err
		}
	}
	if !seen[tagUSBSupported] {
		return DeviceInfo{}, fmt.Errorf("%w: missing supported USB capabilities", ErrInvalidDeviceInfo)
	}
	if seen[tagNFCSupported] != seen[tagNFCEnabled] {
		return DeviceInfo{}, fmt.Errorf("%w: NFC capability fields must be present together", ErrInvalidDeviceInfo)
	}
	normalizeDeviceInfo(&info)

	return info, nil
}

func parseDeviceInfoFields(info *DeviceInfo, seen map[byte]bool, fields []byte) error {
	for len(fields) > 0 {
		if len(fields) < 2 || int(fields[1]) > len(fields)-2 {
			return fmt.Errorf("%w: truncated TLV", ErrInvalidDeviceInfo)
		}
		tag, length := fields[0], int(fields[1])
		value := fields[2 : 2+length]
		fields = fields[2+length:]
		seen[tag] = true

		switch tag {
		case tagUSBSupported:
			v, err := capability(tag, value)
			if err != nil {
				return err
			}
			info.SupportedUSBCapabilities = v
		case tagSerial:
			if len(value) != 4 {
				return fieldLengthError(tag, 4, len(value))
			}
			v := binary.BigEndian.Uint32(value)
			info.Serial = &v
		case tagUSBEnabled:
			v, err := capability(tag, value)
			if err != nil {
				return err
			}
			info.EnabledUSBCapabilities = v
		case tagFormFactor:
			if len(value) != 1 {
				return fieldLengthError(tag, 1, len(value))
			}
			info.FormFactor = FormFactor(value[0] & 0x0f)
			if info.FormFactor > FormFactorUSBCBiometricKeychain {
				info.FormFactor = FormFactorUnknown
			}
			info.IsFIPS = value[0]&0x80 != 0
			info.IsSecurityKey = value[0]&0x40 != 0
		case tagFirmwareVersion:
			if len(value) != 3 {
				return fieldLengthError(tag, 3, len(value))
			}
			info.FirmwareVersion = FirmwareVersion{value[0], value[1], value[2]}
		case tagAutoEjectTimeout:
			if len(value) != 2 {
				return fieldLengthError(tag, 2, len(value))
			}
			v := binary.BigEndian.Uint16(value)
			info.AutoEjectTimeout = v
		case tagChallengeTimeout:
			if len(value) != 1 {
				return fieldLengthError(tag, 1, len(value))
			}
			v := value[0]
			info.ChallengeResponseTimeout = v
		case tagDeviceFlags:
			if len(value) != 1 {
				return fieldLengthError(tag, 1, len(value))
			}
			v := value[0]
			info.DeviceFlags = v
		case tagLocked:
			if len(value) != 1 || value[0] > 1 {
				return fmt.Errorf("%w: invalid locked field", ErrInvalidDeviceInfo)
			}
			v := value[0] == 1
			info.Locked = v
		case tagNFCSupported:
			v, err := capability(tag, value)
			if err != nil {
				return err
			}
			info.SupportedNFCCapabilities = &v
		case tagNFCEnabled:
			v, err := capability(tag, value)
			if err != nil {
				return err
			}
			info.EnabledNFCCapabilities = &v
		case tagMoreData:
			// Pagination metadata is consumed by the transport.
			if len(value) != 1 {
				return fieldLengthError(tag, 1, len(value))
			}
		case tagPartNumber:
			info.PartNumber = nil
			if len(value) > 0 && utf8.Valid(value) {
				v := string(value)
				info.PartNumber = &v
			}
		case tagFIPSCapable:
			v, err := fipsCapabilities(tag, value)
			if err != nil {
				return err
			}
			info.FIPSCapable = v
		case tagFIPSApproved:
			v, err := fipsCapabilities(tag, value)
			if err != nil {
				return err
			}
			info.FIPSApproved = v
		case tagPinComplexity:
			v, err := booleanField(tag, value)
			if err != nil {
				return err
			}
			info.PinComplexity = v
		case tagNFCRestricted:
			v, err := booleanField(tag, value)
			if err != nil {
				return err
			}
			info.NFCRestricted = v
		case tagResetBlocked:
			v, err := capability(tag, value)
			if err != nil {
				return err
			}
			info.ResetBlocked = v
		case tagVersionQualifier:
			v, err := parseVersionQualifier(tag, value)
			if err != nil {
				return err
			}
			info.VersionQualifier = &v
		case tagFPSVersion:
			if len(value) != 3 {
				return fieldLengthError(tag, 3, len(value))
			}
			info.FPSVersion = nil
			v := FirmwareVersion{value[0], value[1], value[2]}
			if v != (FirmwareVersion{}) {
				info.FPSVersion = &v
			}
		case tagSTMVersion:
			if len(value) != 3 {
				return fieldLengthError(tag, 3, len(value))
			}
			info.STMVersion = nil
			v := FirmwareVersion{value[0], value[1], value[2]}
			if v != (FirmwareVersion{}) {
				info.STMVersion = &v
			}
		default:
			info.UnknownFields[tag] = append([]byte(nil), value...)
		}
	}

	return nil
}

func normalizeDeviceInfo(info *DeviceInfo) {
	version := info.EffectiveFirmwareVersion()

	// YubiKey 4.2.4 reports its supported applications incorrectly.
	if version == (FirmwareVersion{Major: 4, Minor: 2, Build: 4}) {
		info.SupportedUSBCapabilities = Capability(0x003f)
	}
	// Enabled USB capabilities are not reliable on YubiKey 4 firmware.
	if version.Major == 4 {
		info.EnabledUSBCapabilities = 0
	}
	// YubiKey 4 FIPS devices identify themselves through their firmware range.
	if version.Major == 4 && version.Minor == 4 {
		info.IsFIPS = true
	}
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

func fipsCapabilities(tag byte, value []byte) (Capability, error) {
	if len(value) != 2 {
		return 0, fieldLengthError(tag, 2, len(value))
	}

	raw := binary.BigEndian.Uint16(value)
	var capabilities Capability
	if raw&(1<<0) != 0 {
		capabilities |= CapabilityCTAP2
	}
	if raw&(1<<1) != 0 {
		capabilities |= CapabilityPIV
	}
	if raw&(1<<2) != 0 {
		capabilities |= CapabilityOpenPGP
	}
	if raw&(1<<3) != 0 {
		capabilities |= CapabilityOATH
	}
	if raw&(1<<4) != 0 {
		capabilities |= CapabilityHSMAuth
	}

	return capabilities, nil
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
