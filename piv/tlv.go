package piv

import (
	"encoding/binary"
	"fmt"
	"math/bits"

	"github.com/telesma-app/piv/protocol"
)

// Yubico's extension fields have one-byte tags and definite BER lengths.
func appendTLV(dst []byte, tag byte, value []byte) []byte {
	dst = append(dst, tag)
	if len(value) < 0x80 {
		dst = append(dst, byte(len(value)))
	} else {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		n := (bits.Len(uint(len(value))) + 7) / 8
		dst = append(dst, 0x80|byte(n))
		dst = append(dst, length[len(length)-n:]...)
	}

	return append(dst, value...)
}

func parseTLV(data []byte) (tag byte, value, rest []byte, err error) {
	if len(data) < 2 {
		return 0, nil, nil, fmt.Errorf("%w: truncated Yubico TLV", protocol.ErrInvalidResponse)
	}

	tag = data[0]
	position := 2

	length := uint64(data[1])
	if length&0x80 != 0 {
		n := int(length & 0x7f)
		if n == 0 || n > 8 || n > len(data)-position {
			return 0, nil, nil, fmt.Errorf("%w: invalid Yubico TLV length", protocol.ErrInvalidResponse)
		}

		length = 0
		for _, b := range data[position : position+n] {
			length = length<<8 | uint64(b)
		}

		position += n
	}

	if length > uint64(len(data)-position) {
		return 0, nil, nil, fmt.Errorf("%w: truncated Yubico TLV value", protocol.ErrInvalidResponse)
	}

	end := position + int(length)

	return tag, data[position:end:end], data[end:], nil
}
