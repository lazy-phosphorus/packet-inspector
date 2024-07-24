package transportlayer

import (
	"encoding/hex"
	"fmt"
	"packet-inspector/resolver"
	applicationlayer "packet-inspector/resolver/application-layer"
	"packet-inspector/utils"
	"strconv"
	"strings"
)

type TCP struct {
	resolver.IPacket
	raw            []byte // 原始报文
	source         uint16 // 源端口
	destination    uint16 // 目的端口
	sequence       uint32 // 序号字段
	acknowledgment uint32 // 确认序号
	dataOffset     uint8  // 数据偏移（首部长度），单位为 4 字节（4 bit）
	reserved       uint8  // 保留位，全 0（4 bit）
	cwr            bool   // 拥塞窗口减少标识
	ece            bool   // ECN 回声标识
	urg            bool   // 紧急指针有效标识
	ack            bool   // 确认序号有效标识
	psh            bool   // 尽快交付标识
	rst            bool   // 重连标识
	syn            bool   // 同步序号标识
	fin            bool   // 结束标识
	window         uint16 // 窗口
	checksum       uint16 // 校验和
	urgentPointer  uint16 // 紧急数据长度，仅在 urg 置 1 时有效
	options        []byte // 选项字段
	data           resolver.IPacket
}

func (tcp *TCP) Raw() []byte {
	return tcp.raw
}

func (tcp *TCP) Hex() string {
	return strings.ToUpper(hex.EncodeToString(tcp.raw))
}

func (tcp *TCP) ToReadableString(indent int) string {
	builder := new(strings.Builder)
	tabs := make([]byte, indent)
	for i := range indent {
		tabs[i] = '\t'
	}

	builder.Write(tabs)
	builder.WriteString("Protocol: TCP (Transport)\n")

	builder.Write(tabs)
	builder.WriteString("Source port: ")
	builder.WriteString(strconv.Itoa(int(tcp.source)))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Destination port: ")
	builder.WriteString(strconv.Itoa(int(tcp.destination)))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Sequence number: ")
	builder.WriteString(fmt.Sprintf("0x%08X", tcp.sequence))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Acknowledgment number: ")
	builder.WriteString(fmt.Sprintf("0x%08X", tcp.acknowledgment))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Data offset: ")
	builder.WriteString(strconv.Itoa(int(tcp.dataOffset)))
	builder.WriteString(" (* 4 byte)\n")

	builder.Write(tabs)
	builder.WriteString("Reserved: ")
	builder.WriteString(fmt.Sprintf("0x%02X", tcp.reserved))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("CWR: ")
	if tcp.cwr {
		builder.WriteString("0")
	} else {
		builder.WriteString("1")
	}
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("ECE: ")
	if tcp.ece {
		builder.WriteString("0")
	} else {
		builder.WriteString("1")
	}
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("URG: ")
	if tcp.urg {
		builder.WriteString("0")
	} else {
		builder.WriteString("1")
	}
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("ACK: ")
	if tcp.ack {
		builder.WriteString("0")
	} else {
		builder.WriteString("1")
	}
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("PSH: ")
	if tcp.psh {
		builder.WriteString("0")
	} else {
		builder.WriteString("1")
	}
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("RST: ")
	if tcp.rst {
		builder.WriteString("0")
	} else {
		builder.WriteString("1")
	}
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("SYN: ")
	if tcp.syn {
		builder.WriteString("0")
	} else {
		builder.WriteString("1")
	}
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("FIN: ")
	if tcp.fin {
		builder.WriteString("0")
	} else {
		builder.WriteString("1")
	}
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Window: ")
	builder.WriteString(fmt.Sprintf("0x%04X", tcp.window))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Checksum: ")
	builder.WriteString(fmt.Sprintf("0x%04X", tcp.checksum))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Urgent pointer: ")
	builder.WriteString(strconv.Itoa(int(tcp.urgentPointer)))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Options(HEX): ")
	if tcp.options != nil {
		builder.WriteString(strings.ToUpper(hex.EncodeToString(tcp.options)))
	} else {
		builder.WriteString("(No options)")
	}
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Data: {\n")
	if tcp.data != nil {
		builder.WriteString(tcp.data.ToReadableString(indent + 1))
	} else {
		builder.Write(tabs)
		builder.WriteByte('\t')
		builder.WriteString("(NOT RESOLVED)\n")
	}
	builder.Write(tabs)
	builder.WriteString("}\n")

	builder.Write(tabs)
	builder.WriteString("Raw: ")
	builder.WriteString(tcp.Hex())
	builder.WriteByte('\n')

	return builder.String()
}

func TCPResolve(packet []byte) resolver.IPacket {
	tcp := new(TCP)
	length := len(packet)
	if length < 20 {
		return nil
	}

	tcp.source = utils.ExtractUint16BE(packet, 0)
	tcp.destination = utils.ExtractUint16BE(packet, 2)
	tcp.sequence = utils.ExtractUint32BE(packet, 4)
	tcp.acknowledgment = utils.ExtractUint32BE(packet, 8)
	tcp.dataOffset = packet[12] >> 4
	tcp.reserved = packet[12] & 0xF
	tcp.cwr = (packet[13] & 0x80) == 0x80
	tcp.ece = (packet[13] & 0x40) == 0x40
	tcp.urg = (packet[13] & 0x20) == 0x20
	tcp.ack = (packet[13] & 0x10) == 0x10
	tcp.psh = (packet[13] & 0x8) == 0x8
	tcp.rst = (packet[13] & 0x4) == 0x4
	tcp.syn = (packet[13] & 0x2) == 0x2
	tcp.fin = (packet[13] & 0x1) == 0x1
	tcp.window = utils.ExtractUint16BE(packet, 14)
	tcp.checksum = utils.ExtractUint16BE(packet, 16)
	tcp.urgentPointer = utils.ExtractUint16BE(packet, 18)
	if tcp.dataOffset > 5 {
		tcp.options = make([]byte, tcp.dataOffset*4-20)
		copy(tcp.options, packet[20:tcp.dataOffset*4])
	} else {
		tcp.options = nil
	}

	for _, resolver := range applicationlayer.Resolvers {
		tcp.data = resolver(packet[tcp.dataOffset*4 : length])
		if tcp.data != nil {
			break
		}
	}
	tcp.raw = make([]byte, length)
	copy(tcp.raw, packet)

	return tcp
}
