package netbios

import (
	"encoding/binary"
	"errors"
	"strings"
)

// Sentinel errors returned by parseResponse.
var (
	ErrTooShortNetBIOSResponse          = errors.New("netbios: response too short")
	ErrNoHostnameFoundInNetBIOSResponse = errors.New("netbios: no valid hostname found in response")
)

// parseResponse extracts the first non-group workstation or file-server name
// from a NetBIOS Node Status Response (RFC 1002 §4.2.18).
//
// The response layout (offsets relevant to parsing):
//
//	Bytes 0-53  : standard NBNS header + resource record header
//	Bytes 54-55 : RDLENGTH (number of bytes in RDATA)
//	Byte  56    : NUMBER of NAMES in the name table
//	Bytes 57+   : name table — 18 bytes per entry (15-byte name, 1-byte suffix, 2-byte flags)
//
// We prefer suffix 0x20 (workstation) over 0x00 (generic) when both are present.
func parseResponse(response []byte) (string, error) {
	if len(response) < 57 {
		return "", ErrTooShortNetBIOSResponse
	}

	rdLength := int(binary.BigEndian.Uint16(response[54:56]))
	numNames := int(response[56])
	expectedMinRD := 1 + numNames*18 + 6 // numNames field (1) + entries + stats (6)

	if len(response) < 57+numNames*18 || rdLength < expectedMinRD {
		return "", ErrTooShortNetBIOSResponse
	}

	// First pass: prefer suffix 0x20 (workstation service),
	// second pass: accept suffix 0x00 (domain/machine name).
	for _, targetSuffix := range []byte{0x20, 0x00} {
		offset := 57
		for i := 0; i < numNames; i++ {
			nameBytes := response[offset : offset+15]
			suffix := response[offset+15]
			nameFlags := binary.BigEndian.Uint16(response[offset+16 : offset+18])
			isGroup := (nameFlags & 0x8000) != 0

			if !isGroup && suffix == targetSuffix {
				hostname := strings.TrimRight(string(nameBytes), " \x00")
				if hostname != "" {
					return hostname, nil
				}
			}
			offset += 18
		}
	}

	return "", ErrNoHostnameFoundInNetBIOSResponse
}
