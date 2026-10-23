package yubico

import "strconv"

// String formats the reported version as major.minor.build, including 0.0.0.
func (v FirmwareVersion) String() string {
	return strconv.Itoa(int(v.Major)) + "." +
		strconv.Itoa(int(v.Minor)) + "." +
		strconv.Itoa(int(v.Build))
}
