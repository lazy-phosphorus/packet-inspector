package applicationlayer

import (
	"encoding/hex"
	"fmt"
	"packet-inspector/resolver"
	"strconv"
	"strings"
)

type FlexRay struct {
	resolver.IPacket
	raw              []byte
	reserved         bool   // 缺省位（1 bit）
	payloadIndicator bool   // 有效负载指示（1 bit）
	nullIndicator    bool   // 空帧指示位（1bit）
	syncIndicator    bool   // 同步帧指示位（1 bit）
	startupIndicator bool   // 启动帧指示位（1 bit）
	id               uint16 // id 标识报文（11 bit）
	payloadLength    uint8  // 载荷字节数（7bit），单位 2 字节
	checksum         uint16 // CRC 校验码（11 bit）
	cycleCount       uint8  // 周期计数器（6 bit）
	payload          []byte // 载荷
	trailer          uint32 // 帧尾（24 bit）
}

func (flexray *FlexRay) Raw() []byte {
	return flexray.raw
}

func (flexray *FlexRay) Hex() string {
	return strings.ToUpper(hex.EncodeToString(flexray.raw))
}

func (flexray *FlexRay) ToReadableString(indent int) string {
	builder := new(strings.Builder)
	tabs := make([]byte, indent)
	for i := range indent {
		tabs[i] = '\t'
	}

	builder.Write(tabs)
	builder.WriteString("Protocol: FlexRay (Application)\n")

	builder.Write(tabs)
	builder.WriteString("Reserved bit: ")
	if flexray.reserved {
		builder.WriteString("0")
	} else {
		builder.WriteString("1")
	}
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Payload valid indicator: ")
	if flexray.payloadIndicator {
		builder.WriteString("0")
	} else {
		builder.WriteString("1")
	}
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Null frame indicator: ")
	if flexray.nullIndicator {
		builder.WriteString("0")
	} else {
		builder.WriteString("1")
	}
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Sync indicator: ")
	if flexray.syncIndicator {
		builder.WriteString("0")
	} else {
		builder.WriteString("1")
	}
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Startup indicator: ")
	if flexray.startupIndicator {
		builder.WriteString("0")
	} else {
		builder.WriteString("1")
	}
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("ID: ")
	builder.WriteString(fmt.Sprintf("%03X", flexray.id))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Payload length: ")
	builder.WriteString(strconv.Itoa(int(flexray.payloadLength)))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("ID : ")
	builder.WriteString(fmt.Sprintf("%04X", flexray.checksum))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Cycle count: ")
	builder.WriteString(strconv.Itoa(int(flexray.cycleCount)))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Payload: ")
	builder.WriteString(strings.ToUpper(hex.EncodeToString(flexray.payload)))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Frame tail : ")
	builder.WriteString(fmt.Sprintf("%06X", flexray.trailer))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Raw : ")
	builder.WriteString(flexray.Hex())
	builder.WriteByte('\n')

	return builder.String()
}

func FlexRayResolve(packet []byte) resolver.IPacket {
	flexray := new(FlexRay)
	length := len(packet)

	if length < 8 {
		return nil
	}

	flexray.reserved = (packet[0] & 0x80) == 0x80
	flexray.payloadIndicator = (packet[0] & 0x40) == 0x40
	flexray.nullIndicator = (packet[0] & 0x20) == 0x20
	flexray.syncIndicator = (packet[0] & 0x10) == 0x10
	flexray.startupIndicator = (packet[0] & 0x8) == 0x8
	flexray.id = (uint16(packet[0]&0x7) << 8) | uint16(packet[1])
	flexray.payloadLength = packet[2] >> 1
	flexray.checksum = ((uint16(packet[3]) & 0x1) << 10) | (uint16(packet[4]) << 2) | (uint16(packet[5]>>6) & 0x3)
	flexray.cycleCount = packet[5] & 0x3F

	if length != int(flexray.payloadLength)*2+8 {
		return nil
	} else if !flexray.payloadIndicator && flexray.payloadLength != 0 {
		return nil
	}
	if flexray.payloadLength != 0 {
		flexray.payload = make([]byte, flexray.payloadLength*2)
		copy(flexray.payload, packet[5:length-3])
	} else {
		flexray.payload = nil
	}

	flexray.trailer = (uint32(packet[length-3]) << 16) | (uint32(packet[length-2]) << 8) | uint32(packet[length-1])
	flexray.raw = make([]byte, length)
	copy(flexray.raw, packet)

	return flexray
}
