package netbios

import "encoding/binary"

// buildNBSTATQueryWithTxID constructs a NetBIOS Node Status Request
// (RFC 1002 §4.2.18) with the supplied transaction ID, which is echoed back in
// the response and used to correlate replies on a shared socket.
func buildNBSTATQueryWithTxID(txID uint16) []byte {
	query := make([]byte, 50)
	binary.BigEndian.PutUint16(query[0:2], txID)
	// Flags: 0x0000 → standard query, no recursion
	binary.BigEndian.PutUint16(query[2:4], 0x0000)
	// QDCOUNT = 1 question
	binary.BigEndian.PutUint16(query[4:6], 0x0001)
	// ANCOUNT / NSCOUNT / ARCOUNT = 0
	binary.BigEndian.PutUint16(query[6:8], 0x0000)
	binary.BigEndian.PutUint16(query[8:10], 0x0000)
	binary.BigEndian.PutUint16(query[10:12], 0x0000)
	// QNAME: encoded wildcard "*" padded to 16 bytes (produces 34 bytes)
	copy(query[12:46], encodeNetBIOSName("*"))
	// QTYPE  = NBSTAT (0x0021)
	binary.BigEndian.PutUint16(query[46:48], 0x0021)
	// QCLASS = IN (0x0001)
	binary.BigEndian.PutUint16(query[48:50], 0x0001)

	return query
}

// encodeNetBIOSName applies the first-level NetBIOS name encoding (RFC 1001 §14.1).
// The name is padded/truncated to 15 bytes, the 16th byte is the "suffix" (0x00
// for workstations).  Each nibble is offset by 'A' to produce printable ASCII.
func encodeNetBIOSName(name string) []byte {
	var raw [16]byte
	copy(raw[:15], name)

	// Length byte (32 = 0x20) + 32 encoded bytes + trailing null label
	encoded := make([]byte, 34)
	encoded[0] = 32
	for i := 0; i < 16; i++ {
		encoded[1+2*i] = ((raw[i] >> 4) & 0x0F) + 'A'
		encoded[2+2*i] = (raw[i] & 0x0F) + 'A'
	}
	encoded[33] = 0x00
	return encoded
}
