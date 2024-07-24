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
	IPv6_NEXT_HEADER_HBH      uint8 = 0x0 // 逐跳扩展头
	IPv6_NEXT_HEADER_TCP      uint8 = 0x6
	IPv6_NEXT_HEADER_UDP      uint8 = 0x11
	IPv6_NEXT_HEADER_ROUTING  uint8 = 0x2b // 路由扩展头
	IPv6_NEXT_HEADER_FRAGMENT uint8 = 0x2c
	IPv6_NEXT_HEADER_DO       uint8 = 0x3c // 目的选项扩展头
)

type IPv6 struct {
	resolver.IPacket
	raw           []byte           // 原始报文
	version       uint8            // 版本（4 bit）
	trafficType   uint8            // 流量类别
	flowLabel     uint32           // 流标签（20 bit）
	payloadLength uint16           // 数据部分的长度，包含扩展报文头
	nextHeader    uint8            // 扩展报文头的类型
	hopLimit      uint8            // 跳数限制
	source        [16]byte         // 源 IP 地址
	destination   [16]byte         // 目的 IP 地址
	data          resolver.IPacket // 上层协议的数据
}

func (ipv6 *IPv6) Hex() string {
	return hex.EncodeToString(ipv6.raw)
}

func (ipv6 *IPv6) Raw() []byte {
	return ipv6.raw
}

func (ipv6 *IPv6) ToReadableString(indent int) string {
	builder := new(strings.Builder)
	tabs := make([]byte, indent)
	for i := range indent {
		tabs[i] = '\t'
	}

	builder.Write(tabs)
	builder.WriteString("Protocol: IPv6 (Network)\n")

	builder.Write(tabs)
	builder.WriteString("Version: ")
	builder.WriteString(strconv.Itoa(int(ipv6.version)))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Traffic type: ")
	builder.WriteString(fmt.Sprintf("0x%2X", ipv6.trafficType))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Flow label: ")
	builder.WriteString(fmt.Sprintf("0x%05X", ipv6.flowLabel))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Payload length: ")
	builder.WriteString(strconv.Itoa(int(ipv6.payloadLength)))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Next header: ")
	builder.WriteString(fmt.Sprintf("0x%02X", ipv6.nextHeader))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Hop limit: ")
	builder.WriteString(strconv.Itoa(int(ipv6.hopLimit)))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Source address: ")
	for i := range ipv6.source {
		if i == 0 {
			builder.WriteString(fmt.Sprintf("%02X", ipv6.source[i]))
		}
		builder.WriteString(fmt.Sprintf(":%02X", ipv6.source[i]))
	}
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Destination address: ")
	for i := range ipv6.destination {
		if i == 0 {
			builder.WriteString(fmt.Sprintf("%02X", ipv6.destination[i]))
		}
		builder.WriteString(fmt.Sprintf(":%02X", ipv6.destination[i]))
	}
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Data: {\n")
	if ipv6.data != nil {
		builder.WriteString(ipv6.data.ToReadableString(indent + 1))
	} else {
		builder.Write(tabs)
		builder.WriteByte('\t')
		builder.WriteString("(NOT RESOLVED)\n")
	}
	builder.Write(tabs)
	builder.WriteString("}\n")

	builder.Write(tabs)
	builder.WriteString("Raw: ")
	builder.Write(ipv6.raw)
	builder.WriteByte('\n')

	return builder.String()
}

func IPv6Resolve(packet []byte) resolver.IPacket {
	ipv6 := new(IPv6)
	length := len(packet)
	if length < 40 || length > 65575 {
		return nil
	}
	if (packet[0] & 0x60) != 0x60 {
		return nil
	}
	ipv6.version = 6
	ipv6.trafficType = (packet[0]&0x0F)<<4 | (packet[1]&0xF0)>>4
	ipv6.flowLabel = (uint32(packet[1]&0x0F) << 16) | (uint32(packet[2]) << 8) | uint32(packet[3])
	ipv6.payloadLength = uint16(packet[4])<<8 | uint16(packet[5])
	if 40+ipv6.payloadLength != uint16(length) {
		return nil
	}
	ipv6.nextHeader = packet[6]
	ipv6.hopLimit = packet[7]
	copy(ipv6.source[:], packet[8:24])
	copy(ipv6.destination[:], packet[24:40])
	switch ipv6.nextHeader {
	case IPv6_NEXT_HEADER_TCP:
		resolve := transportlayer.Resolvers["TCP"]
		if resolve != nil {
			ipv6.data = resolve(packet[40 : 40+ipv6.payloadLength])
		}
	case IPv4_PROTOCOL_UDP:
		resolve := transportlayer.Resolvers["UDP"]
		if resolve != nil {
			ipv6.data = resolve(packet[40 : 40+ipv6.payloadLength])
		}
	}
	return ipv6
}
