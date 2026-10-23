package yubico

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
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

// FIPSCapability is the bitmap used by the FIPS capable and approved TLVs.
// Its bit positions differ from Capability. Unknown bits are preserved.
type FIPSCapability uint16

const (
	FIPSCapabilityCTAP2   FIPSCapability = 1 << 0
	FIPSCapabilityPIV     FIPSCapability = 1 << 1
	FIPSCapabilityOpenPGP FIPSCapability = 1 << 2
	FIPSCapabilityOATH    FIPSCapability = 1 << 3
	FIPSCapabilityHSMAuth FIPSCapability = 1 << 4
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

// VersionQualifier contains the required version, release type and iteration TLVs.
type VersionQualifier struct {
	Version     FirmwareVersion `json:"version"`
	ReleaseType ReleaseType     `json:"releaseType"`
	Iteration   uint32          `json:"iteration"`
	RawFields   map[byte][]byte `json:"rawFields"`
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

// DeviceInfo contains reported management values; nil pointers mark absent TLVs.
// RawFields owns a copy of every tag's last value. Parsing applies no firmware
// corrections or model inference.
type DeviceInfo struct {
	SupportedUSBCapabilities Capability        `json:"supportedUSBCapabilities"`
	SerialNumber             *uint32           `json:"serialNumber,omitempty"`
	EnabledUSBCapabilities   *Capability       `json:"enabledUSBCapabilities,omitempty"`
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
	FIPSCapable              *FIPSCapability   `json:"fipsCapable,omitempty"`
	FIPSApproved             *FIPSCapability   `json:"fipsApproved,omitempty"`
	PinComplexity            *bool             `json:"pinComplexity,omitempty"`
	NFCRestricted            *bool             `json:"nfcRestricted,omitempty"`
	ResetBlocked             *Capability       `json:"resetBlocked,omitempty"`
	FPSVersion               *FirmwareVersion  `json:"fpsVersion,omitempty"`
	STMVersion               *FirmwareVersion  `json:"stmVersion,omitempty"`
	SupportedNFCCapabilities *Capability       `json:"supportedNFCCapabilities,omitempty"`
	EnabledNFCCapabilities   *Capability       `json:"enabledNFCCapabilities,omitempty"`
	RawFields                map[byte][]byte   `json:"rawFields"`
}

var (
	// ErrInvalidDeviceInfo reports malformed device-information response data.
	ErrInvalidDeviceInfo = errors.New("yubico: invalid device information")
	// ErrDeviceInfoNotSupported reports an explicit protocol rejection of the
	// GET DEVICE INFORMATION command. The underlying protocol error is retained.
	ErrDeviceInfoNotSupported = errors.New("yubico: device information command not supported")
)

// ParseDeviceInfo parses TOTAL-LENGTH followed by TAG-LENGTH-VALUE fields.
func ParseDeviceInfo(data []byte) (DeviceInfo, error) {
	return ParseDeviceInfoPages(data)
}

// ParseDeviceInfoPages merges pages, then checks required fields.
// Later values replace earlier values of the same tag.
func ParseDeviceInfoPages(pages ...[]byte) (DeviceInfo, error) {
	if len(pages) == 0 {
		return DeviceInfo{}, fmt.Errorf("%w: missing response page", ErrInvalidDeviceInfo)
	}

	info := DeviceInfo{RawFields: make(map[byte][]byte)}
	for _, data := range pages {
		if len(data) == 0 || int(data[0]) != len(data)-1 {
			return DeviceInfo{}, fmt.Errorf("%w: total length does not match payload", ErrInvalidDeviceInfo)
		}
		if err := parseDeviceInfoFields(&info, data[1:]); err != nil {
			return DeviceInfo{}, err
		}
	}

	// YubiKey 4 may omit enabled USB capabilities.
	for _, tag := range [...]byte{
		tagUSBSupported, tagFormFactor, tagFirmwareVersion,
		tagAutoEjectTimeout, tagChallengeTimeout, tagDeviceFlags, tagLocked,
	} {
		if _, ok := info.RawFields[tag]; !ok {
			return DeviceInfo{}, fmt.Errorf("%w: missing required tag 0x%02x", ErrInvalidDeviceInfo, tag)
		}
	}
	if info.EnabledUSBCapabilities == nil && info.FirmwareVersion.Major != 4 {
		return DeviceInfo{}, fmt.Errorf("%w: missing required tag 0x%02x", ErrInvalidDeviceInfo, tagUSBEnabled)
	}
	if (info.SupportedNFCCapabilities == nil) != (info.EnabledNFCCapabilities == nil) {
		return DeviceInfo{}, fmt.Errorf("%w: NFC capability fields must be present together", ErrInvalidDeviceInfo)
	}
	if info.VersionQualifier != nil {
		for _, tag := range [...]byte{0x01, 0x02, 0x03} {
			if _, ok := info.VersionQualifier.RawFields[tag]; !ok {
				return DeviceInfo{}, fmt.Errorf("%w: version qualifier missing required tag 0x%02x", ErrInvalidDeviceInfo, tag)
			}
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
		info.RawFields[tag] = slices.Clone(value)

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
			info.SerialNumber = &v
		case tagUSBEnabled:
			v, err := capability(tag, value)
			if err != nil {
				return err
			}
			info.EnabledUSBCapabilities = &v
		case tagFormFactor:
			if len(value) != 1 {
				return fieldLengthError(tag, 1, len(value))
			}
			info.FormFactor = FormFactor(value[0] & 0x0f)
			info.IsFIPS = value[0]&0x80 != 0
			info.IsSecurityKey = value[0]&0x40 != 0
		case tagFirmwareVersion:
			if len(value) != 3 {
				return fieldLengthError(tag, 3, len(value))
			}
			info.FirmwareVersion = FirmwareVersion{Major: value[0], Minor: value[1], Build: value[2]}
		case tagAutoEjectTimeout:
			if len(value) != 2 {
				return fieldLengthError(tag, 2, len(value))
			}
			info.AutoEjectTimeout = binary.BigEndian.Uint16(value)
		case tagChallengeTimeout:
			if len(value) != 1 {
				return fieldLengthError(tag, 1, len(value))
			}
			info.ChallengeResponseTimeout = value[0]
		case tagDeviceFlags:
			if len(value) != 1 {
				return fieldLengthError(tag, 1, len(value))
			}
			info.DeviceFlags = value[0]
		case tagLocked:
			if len(value) != 1 || value[0] > 1 {
				return fmt.Errorf("%w: invalid locked field", ErrInvalidDeviceInfo)
			}
			info.Locked = value[0] == 1
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
			if !utf8.Valid(value) {
				return fmt.Errorf("%w: part number is not UTF-8", ErrInvalidDeviceInfo)
			}
			v := string(value)
			info.PartNumber = &v
		case tagFIPSCapable:
			v, err := fipsCapabilities(tag, value)
			if err != nil {
				return err
			}
			info.FIPSCapable = &v
		case tagFIPSApproved:
			v, err := fipsCapabilities(tag, value)
			if err != nil {
				return err
			}
			info.FIPSApproved = &v
		case tagPinComplexity:
			v, err := booleanField(tag, value)
			if err != nil {
				return err
			}
			info.PinComplexity = &v
		case tagNFCRestricted:
			v, err := booleanField(tag, value)
			if err != nil {
				return err
			}
			info.NFCRestricted = &v
		case tagResetBlocked:
			v, err := capability(tag, value)
			if err != nil {
				return err
			}
			info.ResetBlocked = &v
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
			info.FPSVersion = &FirmwareVersion{Major: value[0], Minor: value[1], Build: value[2]}
		case tagSTMVersion:
			if len(value) != 3 {
				return fieldLengthError(tag, 3, len(value))
			}
			info.STMVersion = &FirmwareVersion{Major: value[0], Minor: value[1], Build: value[2]}
		}
	}

	return nil
}

func capability(tag byte, value []byte) (Capability, error) {
	if len(value) != 2 {
		return 0, fieldLengthError(tag, 2, len(value))
	}
	return Capability(binary.BigEndian.Uint16(value)), nil
}

func fipsCapabilities(tag byte, value []byte) (FIPSCapability, error) {
	if len(value) != 2 {
		return 0, fieldLengthError(tag, 2, len(value))
	}
	return FIPSCapability(binary.BigEndian.Uint16(value)), nil
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
	qualifier := VersionQualifier{RawFields: make(map[byte][]byte)}

	for fields := value; len(fields) > 0; {
		if len(fields) < 2 || int(fields[1]) > len(fields)-2 {
			return VersionQualifier{}, fmt.Errorf("%w: tag 0x%02x contains truncated TLV", ErrInvalidDeviceInfo, tag)
		}
		fieldTag, length := fields[0], int(fields[1])
		fieldValue := fields[2 : 2+length]
		fields = fields[2+length:]
		qualifier.RawFields[fieldTag] = slices.Clone(fieldValue)

		switch fieldTag {
		case 0x01:
			if len(fieldValue) != 3 {
				return VersionQualifier{}, fieldLengthError(fieldTag, 3, len(fieldValue))
			}
			qualifier.Version = FirmwareVersion{Major: fieldValue[0], Minor: fieldValue[1], Build: fieldValue[2]}
		case 0x02:
			if len(fieldValue) != 1 {
				return VersionQualifier{}, fieldLengthError(fieldTag, 1, len(fieldValue))
			}
			qualifier.ReleaseType = ReleaseType(fieldValue[0])
		case 0x03:
			if len(fieldValue) != 4 {
				return VersionQualifier{}, fieldLengthError(fieldTag, 4, len(fieldValue))
			}
			qualifier.Iteration = binary.BigEndian.Uint32(fieldValue)
		}
	}

	return qualifier, nil
}

func fieldLengthError(tag byte, want, got int) error {
	return fmt.Errorf("%w: tag 0x%02x length is %d, want %d", ErrInvalidDeviceInfo, tag, got, want)
}
