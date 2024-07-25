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

type UDP struct {
	resolver.IPacket
	raw         []byte           // 原始报文
	source      uint16           // 源端口
	destination uint16           // 目的端口
	length      uint16           // 报文总长度
	checksum    uint16           // 校验和
	data        resolver.IPacket // 上层协议数据
}

func (udp *UDP) Raw() []byte {
	return udp.raw
}

func (udp *UDP) Hex() string {
	return strings.ToUpper(hex.EncodeToString(udp.raw))
}

func (udp *UDP) ToReadableString(indent int) string {
	builder := new(strings.Builder)
	tabs := make([]byte, indent)
	for i := range indent {
		tabs[i] = '\t'
	}

	builder.Write(tabs)
	builder.WriteString("Protocol: UDP (Transport)\n")

	builder.Write(tabs)
	builder.WriteString("Source port: ")
	builder.WriteString(strconv.Itoa(int(udp.source)))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Destination port: ")
	builder.WriteString(strconv.Itoa(int(udp.destination)))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Total length: ")
	builder.WriteString(strconv.Itoa(int(udp.length)))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Checksum: ")
	builder.WriteString(fmt.Sprintf("0x%04X", udp.checksum))
	builder.WriteByte('\n')

	builder.Write(tabs)
	builder.WriteString("Data: {\n")
	if udp.data != nil {
		builder.WriteString(udp.data.ToReadableString(indent + 1))
	} else {
		builder.Write(tabs)
		builder.WriteString("\t(NOT RESOLVED)\n")
	}
	builder.Write(tabs)
	builder.WriteString("}\n")

	return builder.String()
}

func UDPResolve(packet []byte) resolver.IPacket {
	udp := new(UDP)
	length := len(packet)
	if length < 8 {
		return nil
	}

	udp.source = utils.ExtractUint16BE(packet, 0)
	udp.destination = utils.ExtractUint16BE(packet, 2)
	udp.length = utils.ExtractUint16BE(packet, 4)
	println("length = ", length, "udp length = ", udp.length)
	if length != int(udp.length) {
		return nil
	}
	udp.checksum = utils.ExtractUint16BE(packet, 6)
	if length > 8 {
		for _, resolver := range applicationlayer.Resolvers {
			udp.data = resolver(packet[8:length])
			if udp.data != nil {
				break
			}
		}
	}
	udp.raw = make([]byte, length)
	copy(udp.raw, packet)

	return udp
}
