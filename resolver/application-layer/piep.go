package applicationlayer

import (
	"encoding/hex"
	"fmt"
	"packet-inspector/resolver"
	"packet-inspector/utils"
	"strconv"
	"strings"
)

type PIEP struct {
	resolver.IPacket
	raw        []byte // 原始数据
	startBit   uint8  // 起始位
	address    uint32 // 设备地址
	frameType  uint8  // 帧类型
	dataLength uint8  // 载荷长度，以字节为单位
	payload    []byte // 载荷
}

func (piep *PIEP) Raw() []byte {
	return piep.raw
}

func (piep *PIEP) Hex() string {
	return strings.ToUpper(hex.EncodeToString(piep.raw))
}

func (piep *PIEP) ToReadableString(indent int) string {
	builder := new(strings.Builder)
	tabs := make([]byte, indent)
	for i := range indent {
		tabs[i] = '\t'
	}

	builder.Write(tabs)
	builder.WriteString("Protocol: PIEP (Application)\n")

	builder.Write(tabs)
	builder.WriteString("Start bit: ")
	builder.WriteString(fmt.Sprintf("0x%02X", piep.startBit))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Address: ")
	builder.WriteString(fmt.Sprintf("0x%08X", piep.address))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Frame type: ")
	builder.WriteString(fmt.Sprintf("0x%02X", piep.frameType))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Data length: ")
	builder.WriteString(strconv.Itoa(int(piep.dataLength)))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Data: ")
	builder.WriteString(strings.ToUpper(hex.EncodeToString(piep.payload)))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Raw: ")
	builder.WriteString(piep.Hex())
	builder.WriteByte('\n')

	return builder.String()
}

func PIEPResolve(packet []byte) resolver.IPacket {
	piep := new(PIEP)
	length := len(packet)

	if length < 7 {
		return nil
	}

	piep.startBit = utils.ExtractUint8BE(packet, 0)
	piep.address = utils.ExtractUint32BE(packet, 1)
	piep.frameType = utils.ExtractUint8BE(packet, 5)
	piep.dataLength = utils.ExtractUint8BE(packet, 6)

	if int(piep.dataLength)+7 != length {
		return nil
	}
	if piep.dataLength > 0 {
		piep.payload = make([]byte, piep.dataLength)
		copy(piep.payload, packet[7:length])
	} else {
		piep.payload = nil
	}
	piep.raw = make([]byte, length)
	copy(piep.raw, packet)

	return piep
}
