package piv

import (
	"fmt"

	"github.com/telesma-app/piv/protocol"
)

// ParseMetadata parses the GET METADATA TLV response. The algorithm is required;
// other known fields are optional. Unknown fields are retained in Raw. Public-key
// parsing is separate so a new algorithm does not prevent metadata inspection.
func ParseMetadata(data []byte) (Metadata, error) {
	metadata := Metadata{Raw: data}

	var seen byte

	for len(data) != 0 {
		tag, value, rest, err := parseTLV(data)
		if err != nil {
			return Metadata{}, err
		}

		data = rest

		if tag < 1 || tag > 6 {
			continue
		}

		bit := byte(1 << tag)
		if seen&bit != 0 {
			return Metadata{}, fmt.Errorf("%w: duplicate metadata tag %02x", protocol.ErrInvalidResponse, tag)
		}

		seen |= bit

		switch tag {
		case 1:
			if len(value) != 1 {
				return Metadata{}, fmt.Errorf("%w: invalid metadata algorithm", protocol.ErrInvalidResponse)
			}

			metadata.Algorithm = protocol.Algorithm(value[0])
		case 2:
			if len(value) != 2 {
				return Metadata{}, fmt.Errorf("%w: invalid metadata policy", protocol.ErrInvalidResponse)
			}

			metadata.Policy = &KeyPolicy{PIN: PINPolicy(value[0]), Touch: TouchPolicy(value[1])}
		case 3:
			if len(value) != 1 {
				return Metadata{}, fmt.Errorf("%w: invalid metadata origin", protocol.ErrInvalidResponse)
			}

			origin := KeyOrigin(value[0])
			metadata.Origin = &origin
		case 4:
			metadata.PublicKeyData = value
		case 5:
			if len(value) != 1 || value[0] > 1 {
				return Metadata{}, fmt.Errorf("%w: invalid metadata default flag", protocol.ErrInvalidResponse)
			}

			isDefault := value[0] == 1
			metadata.Default = &isDefault
		case 6:
			if len(value) != 2 || value[1] > value[0] {
				return Metadata{}, fmt.Errorf("%w: invalid metadata retry counts", protocol.ErrInvalidResponse)
			}

			metadata.Retries = &RetryCounts{Total: value[0], Remaining: value[1]}
		}
	}

	if seen&(1<<1) == 0 {
		return Metadata{}, fmt.Errorf("%w: missing metadata algorithm", protocol.ErrInvalidResponse)
	}

	return metadata, nil
}
