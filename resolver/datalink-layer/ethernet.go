package datalinklayer

import (
	"encoding/hex"
	"fmt"
	"packet-inspector/resolver"
	networklayer "packet-inspector/resolver/network-layer"
	"packet-inspector/types"
	"strings"
)

const (
	ETHERNET_PROTOCOL_IPV4 uint16 = 0x0800
	ETHERNET_PROTOCOL_ARP  uint16 = 0x0806
	ETHERNET_PROTOCOL_IPV6 uint16 = 0x86DD
)

var ETHERNET_PROTOCOL_NAME = map[uint16]string{
	ETHERNET_PROTOCOL_IPV4: "IPv4",
	ETHERNET_PROTOCOL_ARP:  "ARP",
	ETHERNET_PROTOCOL_IPV6: "IPv6",
}

type IEthernet interface {
	resolver.IPacket
	Source() types.Mac
	Destination() types.Mac
}

type BaseEthernet struct {
	IEthernet
	raw         []byte    // 原始报文
	destination types.Mac // 目的 MAC 地址
	source      types.Mac // 源 MAC 地址
	etype       uint16    // 以太网帧类型，大于 0x600 为 Ethernet II，小于 1500 为 IEEE 802.3 SNAP
}

func (ethernet *BaseEthernet) Hex() string {
	return strings.ToUpper(hex.EncodeToString(ethernet.raw))
}

func (ethernet *BaseEthernet) Raw() []byte {
	return ethernet.raw
}

func (ethernet *BaseEthernet) Source() types.Mac {
	return ethernet.source
}

func (ethernet *BaseEthernet) Destination() types.Mac {
	return ethernet.destination
}

type EthernetII struct {
	BaseEthernet
	data resolver.IPacket // 上层协议的数据
}

func (ethernet *EthernetII) ToReadableString(indent int) string {
	builder := new(strings.Builder)
	tabs := make([]byte, indent)
	for i := range indent {
		tabs[i] = '\t'
	}

	builder.Write(tabs)
	builder.WriteString("Source MAC address: ")
	builder.WriteString(ethernet.source.ToString())
	builder.WriteByte('\n')
	builder.Write(tabs)
	builder.WriteString("Destination MAC address: ")
	builder.WriteString(ethernet.destination.ToString())
	builder.WriteByte('\n')
	builder.Write(tabs)
	builder.WriteString("Protocol type: ")
	builder.WriteString(fmt.Sprintf("0x%04X (", ethernet.etype))
	temp := ETHERNET_PROTOCOL_NAME[ethernet.etype]
	if temp != "" {
		builder.WriteString(temp)
	} else {
		builder.WriteString("Unknown")
	}
	builder.WriteString(")\n")
	builder.Write(tabs)
	builder.WriteString("Data: {\n")
	if ethernet.data != nil {
		builder.WriteString(ethernet.data.ToReadableString(indent + 1))
	} else {
		builder.Write(tabs)
		builder.WriteByte('\t')
		builder.WriteString("(NOT RESOLVED)\n")
	}
	builder.Write(tabs)
	builder.WriteString("}\n")
	builder.Write(tabs)
	builder.WriteString("Raw: ")
	builder.WriteString(ethernet.Hex())
	builder.WriteByte('\n')
	return builder.String()
}

// ! 以下协议格式似乎已经废弃
// type NovellNetware8023Raw struct {
// 	destination types.Mac     // 目的 MAC 地址
// 	source      types.Mac     // 源 MAC 地址
// 	length      uint16        // 报文长度（不含校验码）
// 	data        types.IPacket // 上层协议的数据
// 	fcs         uint32        // 校验码

// 	raw []byte // 原始报文
// 	crc uint32 // 真实 CRC 校验码
// }

// type IEEE8023LLC struct {
// 	destination types.Mac // 目的 MAC 地址
// 	source      types.Mac // 源 MAC 地址
// 	length      uint16    // 报文长度（不含校验码）
// 	dsap        byte      // 目的服务访问点
// 	ssap        byte      // 源服务访问点
// 	control     byte
// 	data        types.IPacket // 上层协议的数据
// 	fcs         uint32        // 校验码

// 	raw []byte // 原始报文
// 	crc uint32 // 真实 CRC 校验码
// }

type IEEE8023SNAP struct {
	BaseEthernet
	dsap    byte             // 目的服务访问点，固定为 0xAA
	ssap    byte             // 源服务访问点，固定为 0xAA
	control byte             // 固定为 0x03
	oui     [3]byte          // 组织唯一标识符
	utype   uint16           // 上层协议类型（仅当 oui 字段为 0x000000 时）
	data    resolver.IPacket // 上层协议
}

func EthernetIIResolve(packet []byte) *EthernetII {
	ethernet := new(EthernetII)
	ethernet.destination.Parse([6]byte(packet[0:6]))
	ethernet.source.Parse([6]byte(packet[6:12]))

	length := len(packet)

	ethernet.etype |= uint16(packet[12]) << 8
	ethernet.etype |= uint16(packet[13])
	resolve := networklayer.Resolvers[ETHERNET_PROTOCOL_NAME[ethernet.etype]]
	if resolve != nil {
		ethernet.data = resolve(packet[14:length])
	}
	ethernet.raw = packet
	return ethernet
}

func IEEE8023SNAPResolve(packet []byte) *IEEE8023SNAP {
	ethernet := new(IEEE8023SNAP)
	ethernet.destination.Parse([6]byte(packet[0:6]))
	ethernet.source.Parse([6]byte(packet[6:12]))

	length := len(packet)

	ethernet.etype |= uint16(packet[12]) << 8
	ethernet.etype |= uint16(packet[13])
	dsap := packet[14]
	ssap := packet[15]
	control := packet[16]
	if dsap != 0xAA || ssap != 0xAA || control != 0x03 {
		return nil
	}
	ethernet.dsap = dsap
	ethernet.ssap = ssap
	ethernet.control = control
	copy(ethernet.oui[:], packet[17:20])
	ethernet.utype |= uint16(packet[12]) << 8
	ethernet.utype |= uint16(packet[13])
	resolve := networklayer.Resolvers[ETHERNET_PROTOCOL_NAME[ethernet.etype]]
	if (ethernet.oui[0]|ethernet.oui[1]|ethernet.oui[2]) == 0 && resolve != nil {
		ethernet.data = resolve(packet[14:length])
	}
	ethernet.raw = packet
	return ethernet
}

func EthernetResolve(packet []byte) resolver.IPacket {
	length := len(packet)
	if length < 64 || length > 1500 {
		return nil
	}

	temp := uint16(0)
	temp |= uint16(packet[12]) << 8
	temp |= uint16(packet[13])

	if 0x600 <= temp {
		return EthernetIIResolve(packet)
	} else if temp <= 1500 {
		return IEEE8023SNAPResolve(packet)
	} else {
		return nil
	}
}
