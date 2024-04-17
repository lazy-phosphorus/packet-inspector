package transportlayer

import (
	"encoding/hex"
	"fmt"
	"packet-inspector/resolver"
	applicationlayer "packet-inspector/resolver/application-layer"
	"strconv"
	"strings"
)

type TCP struct {
	resolver.IPacket
	raw            []byte           // 原始报文
	source         uint16           // 源端口
	destination    uint16           // 目的端口
	sequence       uint32           // 序号字段
	acknowledgment uint32           // 确认号
	dataOffset     uint8            // 首部长度，单位为 4 字节（4 bit）
	reserved       uint8            // 保留位，全 0（6 bit）
	urg            bool             // 紧急标识
	ack            bool             // 确认标识
	psh            bool             // 尽快交付标识
	rst            bool             // 重连标识
	syn            bool             // 同步序号标识
	fin            bool             // 结束标识
	window         uint16           // 窗口
	checksum       uint16           // 校验和
	urgentLength   uint16           // 紧急数据长度，仅在 urg 置 1 时有效
	options        []byte           // 选项字段
	data           resolver.IPacket // 上层协议的数据
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
	builder.WriteString(strconv.Itoa(int(tcp.urgentLength)))
	builder.WriteByte('\n')
	builder.Write(tabs)
	builder.WriteString("Options: ")
	if tcp.options != nil {
		builder.WriteString(hex.EncodeToString(tcp.options))
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
	tcp.source = uint16(packet[0])<<8 | uint16(packet[1])
	tcp.destination = uint16(packet[2])<<8 | uint16(packet[3])
	tcp.sequence = uint32(packet[4])<<24 | uint32(packet[5])<<16 | uint32(packet[6])<<8 | uint32(packet[7])
	tcp.acknowledgment = uint32(packet[8])<<24 | uint32(packet[9])<<16 | uint32(packet[10])<<8 | uint32(packet[11])
	tcp.dataOffset = (packet[12] & 0xF0) >> 4
	if int(tcp.dataOffset)*4 > length {
		return nil
	}
	tcp.reserved = (packet[12]&0x0F)<<2 | (packet[13]&0xC0)>>6
	tcp.urg = (packet[13] & 0x20) == 0x20
	tcp.ack = (packet[13] & 0x10) == 0x10
	tcp.psh = (packet[13] & 0x08) == 0x08
	tcp.rst = (packet[13] & 0x04) == 0x04
	tcp.syn = (packet[13] & 0x02) == 0x02
	tcp.fin = (packet[13] & 0x01) == 0x01
	tcp.window = uint16(packet[14])<<8 | uint16(packet[15])
	tcp.checksum = uint16(packet[16])<<8 | uint16(packet[17])
	tcp.urgentLength = uint16(packet[18])<<8 | uint16(packet[19])
	if tcp.dataOffset > 5 {
		tcp.options = make([]byte, tcp.dataOffset*4-20)
		copy(tcp.options, packet[20:tcp.dataOffset*4])
	}
	if tcp.dataOffset != 0 && int(tcp.dataOffset)*4 < length {
		for _, resolve := range applicationlayer.Resolvers {
			tcp.data = resolve(packet[tcp.dataOffset*4 : length])
			if tcp.data != nil {
				break
			}
		}
	}
	tcp.raw = packet
	return tcp
}
