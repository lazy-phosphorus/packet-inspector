package utils

// 提取 8 位，大端
func ExtractUint8BE(packet []byte, offset int) uint8 {
	return packet[offset]
}

// 提取 16 位，大端
func ExtractUint16BE(packet []byte, offset int) uint16 {
	return uint16(packet[offset])<<8 | uint16(packet[offset+1])
}

// 提取 32 位，大端
func ExtractUint32BE(packet []byte, offset int) uint32 {
	return uint32(packet[offset])<<24 | uint32(packet[offset+1])<<16 | uint32(packet[offset+2])<<8 | uint32(packet[offset+3])
}

// 提取 64 位，大端
func ExtractUint64BE(packet []byte, offset int) uint64 {
	return uint64(packet[offset])<<56 | uint64(packet[offset+1])<<48 | uint64(packet[offset+2])<<40 | uint64(packet[offset+3])<<32 | uint64(packet[offset+4])<<24 | uint64(packet[offset+5])<<16 | uint64(packet[offset+6])<<8 | uint64(packet[offset+7])
}
