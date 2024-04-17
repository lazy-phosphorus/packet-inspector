package networklayer

import (
	"encoding/hex"
	"fmt"
	"packet-inspector/resolver"
	transportlayer "packet-inspector/resolver/transport-layer"
	"strconv"
	"strings"
)

const (
	IPV4_PROTOCOL_TCP uint8 = 0x6
	IPV4_PROTOCOL_UDP uint8 = 0x11
)

var IPV4_PROTOCOL_NAME = map[uint8]string{
	IPV4_PROTOCOL_TCP: "TCP",
	IPV4_PROTOCOL_UDP: "UDP",
}

type IPV4 struct {
	resolver.IPacket
	raw            []byte           // 原始数据
	version        uint8            // 版本，应当为 0b0100（4 bit）
	headerLength   uint8            // 报文头长度，单位为 4 字节（4 bit）
	serviceType    uint8            // 服务类型
	length         uint16           // 总长度
	identification uint16           // 标识符
	flags          uint8            // 3bit
	fragment       uint16           // 片偏移
	liveTime       uint8            // 可经过的路由数
	protocol       uint8            // 上层协议类型
	checksum       uint16           // 报文头校验和
	source         [4]byte          // 源 IP地址
	destination    [4]byte          // 目的 IP 地址
	options        []byte           // 选项字段
	data           resolver.IPacket // 上层协议数据
}

func (ipv4 *IPV4) Raw() []byte {
	return ipv4.raw
}

func (ipv4 *IPV4) Hex() string {
	return strings.ToUpper(hex.EncodeToString(ipv4.raw))
}

func (ipv4 *IPV4) ToReadableString(indent int) string {
	builder := new(strings.Builder)
	tabs := make([]byte, indent)
	for i := range indent {
		tabs[i] = '\t'
	}
	builder.Write(tabs)
	builder.WriteString("Version: ")
	builder.WriteString(strconv.Itoa(int(ipv4.version)))
	builder.WriteByte('\n')
	builder.Write(tabs)
	builder.WriteString("Header length: ")
	builder.WriteString(strconv.Itoa(int(ipv4.headerLength)))
	builder.WriteString(" (* 4 byte)\n")
	builder.Write(tabs)
	builder.WriteString("Service type: ")
	builder.WriteString(fmt.Sprintf("0x%02X", ipv4.serviceType))
	builder.Write(tabs)
	builder.WriteByte('\n')
	builder.Write(tabs)
	builder.WriteString("Total length: ")
	builder.WriteString(strconv.Itoa(int(ipv4.length)))
	builder.WriteByte('\n')
	builder.Write(tabs)
	builder.WriteString("Identification: ")
	builder.WriteString(fmt.Sprintf("0x%04X", ipv4.identification))
	builder.WriteByte('\n')
	builder.Write(tabs)
	builder.WriteString("Flags: ")
	builder.WriteString(fmt.Sprintf("0b%03b", ipv4.flags))
	builder.WriteByte('\n')
	builder.Write(tabs)
	builder.WriteString("Fragment offset: ")
	builder.WriteString(fmt.Sprintf("0x%04X", ipv4.fragment))
	builder.WriteByte('\n')
	builder.Write(tabs)
	builder.WriteString("Live time: ")
	builder.WriteString(strconv.Itoa(int(ipv4.liveTime)))
	builder.WriteByte('\n')
	builder.Write(tabs)
	builder.WriteString("Protocol: ")
	builder.WriteString(strconv.Itoa(int(ipv4.protocol)))
	builder.WriteString(" (")
	temp := IPV4_PROTOCOL_NAME[ipv4.protocol]
	if temp != "" {
		builder.WriteString(temp)
	} else {
		builder.WriteString("Unknown")
	}
	builder.WriteString(")\n")
	builder.Write(tabs)
	builder.WriteString("Header check sum: ")
	builder.WriteString(fmt.Sprintf("0x%04X", ipv4.checksum))
	builder.WriteString("\n")
	builder.Write(tabs)
	builder.WriteString("Source address: ")
	builder.WriteString(strconv.Itoa(int(ipv4.source[0])))
	builder.WriteByte(':')
	builder.WriteString(strconv.Itoa(int(ipv4.source[1])))
	builder.WriteByte(':')
	builder.WriteString(strconv.Itoa(int(ipv4.source[2])))
	builder.WriteByte(':')
	builder.WriteString(strconv.Itoa(int(ipv4.source[3])))
	builder.WriteByte('\n')
	builder.Write(tabs)
	builder.WriteString("Destination address: ")
	builder.WriteString(strconv.Itoa(int(ipv4.source[0])))
	builder.WriteByte(':')
	builder.WriteString(strconv.Itoa(int(ipv4.source[1])))
	builder.WriteByte(':')
	builder.WriteString(strconv.Itoa(int(ipv4.source[2])))
	builder.WriteByte(':')
	builder.WriteString(strconv.Itoa(int(ipv4.source[3])))
	builder.WriteByte('\n')
	builder.Write(tabs)
	builder.WriteString("Options: ")
	if ipv4.options == nil {
		builder.WriteString("(No options)")
	} else {
		builder.WriteString(strings.ToUpper(hex.EncodeToString(ipv4.options)))
	}
	builder.WriteByte('\n')
	builder.Write(tabs)
	builder.WriteString("Data: {\n")
	if ipv4.data != nil {
		builder.WriteString(ipv4.data.ToReadableString(indent + 1))
	} else {
		builder.Write(tabs)
		builder.WriteByte('\t')
		builder.WriteString("(NOT RESOLVED)\n")
	}
	builder.Write(tabs)
	builder.WriteString("}\n")
	builder.Write(tabs)
	builder.WriteString("Raw: ")
	builder.WriteString(ipv4.Hex())
	builder.WriteByte('\n')
	return builder.String()
}

func IPV4Resolve(packet []byte) resolver.IPacket {
	ipv4 := new(IPV4)
	length := len(packet)
	if length < 20 || length > 65535 {
		return nil
	}
	if (0x40 & packet[0]) != 0x40 {
		return nil
	}
	ipv4.version = 4
	ipv4.headerLength = 0x0F & packet[0]
	if ipv4.headerLength*4 < 20 {
		return nil
	}
	ipv4.serviceType = packet[1]
	ipv4.length = uint16(packet[2])<<8 | uint16(packet[3])
	if uint16(length) != ipv4.length {
		println(length, ipv4.length)
		return nil
	}
	ipv4.identification = uint16(packet[4])<<8 | uint16(packet[5])
	ipv4.flags = (packet[6] & 0xE0) >> 5
	ipv4.fragment = (uint16(packet[6])&0x1F)<<8 | uint16(packet[7])
	ipv4.liveTime = packet[8]
	ipv4.protocol = packet[9]
	ipv4.checksum = uint16(packet[10])<<8 | uint16(packet[11])
	copy(ipv4.source[:], packet[12:16])
	copy(ipv4.destination[:], packet[16:20])
	if ipv4.headerLength > 5 {
		ipv4.options = make([]byte, ipv4.headerLength*4-20)
		copy(ipv4.options, packet[20:length])
	}
	resolve := transportlayer.Resolvers[IPV4_PROTOCOL_NAME[ipv4.protocol]]
	if resolve != nil {
		ipv4.data = resolve(packet[uint16(ipv4.headerLength)*4 : ipv4.length])
	}
	ipv4.raw = packet
	return ipv4
}
