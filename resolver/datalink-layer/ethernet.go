package datalinklayer

import (
	"encoding/hex"
	"fmt"
	"packet-inspector/resolver"
	networklayer "packet-inspector/resolver/network-layer"
	"packet-inspector/types"
	"packet-inspector/utils"
	"strings"
)

type EthernetInnerProtocol uint16

const (
	ETHERNET_PROTOCOL_IPv4 uint16 = 0x0800
	ETHERNET_PROTOCOL_ARP  uint16 = 0x0806
	ETHERNET_PROTOCOL_IPv6 uint16 = 0x86DD
)

var ETHERNET_PROTOCOL_NAME = map[uint16]string{
	ETHERNET_PROTOCOL_IPv4: "IPv4",
	ETHERNET_PROTOCOL_ARP:  "ARP",
	ETHERNET_PROTOCOL_IPv6: "IPv6",
}

// 尝试用以太网帧格式解析报文
func EthernetResolve(packet []byte) resolver.IPacket {
	length := len(packet)
	if length < 14 || length > 1500 {
		return nil
	}

	temp := utils.ExtractUint16BE(packet, 12)

	/**
	 * 第 12 字节
	 * > 0x600 为 EthernetII
	 * < 1500 为 IEEE 802.3 SNAP
	 */
	if 0x600 <= temp {
		return EthernetIIResolve(packet)
	} else if temp <= 1500 {
		return IEEE8023SNAPResolve(packet)
	} else {
		return nil
	}
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

// 16 进制化的原始报文
func (ethernet *BaseEthernet) Hex() string {
	return strings.ToUpper(hex.EncodeToString(ethernet.raw))
}

// 原始报文
func (ethernet *BaseEthernet) Raw() []byte {
	return ethernet.raw
}

// 源 MAC 地址
func (ethernet *BaseEthernet) Source() types.Mac {
	return ethernet.source
}

// 目的 MAC 地址
func (ethernet *BaseEthernet) Destination() types.Mac {
	return ethernet.destination
}

// EthernetII 协议
type EthernetII struct {
	BaseEthernet
	data resolver.IPacket // 载荷的数据
}

// 转换为可读字符串
func (ethernet *EthernetII) ToReadableString(indent int) string {
	builder := new(strings.Builder)
	tabs := make([]byte, indent)
	for i := range indent {
		tabs[i] = '\t'
	}

	builder.Write(tabs)
	builder.WriteString("Protocol: Ethernet (Datalink)\n")

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
		builder.WriteString("\t(NOT RESOLVED)\n")
	}
	builder.Write(tabs)
	builder.WriteString("}\n")

	builder.Write(tabs)
	builder.WriteString("Raw: ")
	builder.WriteString(ethernet.Hex())
	builder.WriteByte('\n')

	return builder.String()
}

// 以 EthernetII 协议格式解析报文
func EthernetIIResolve(packet []byte) *EthernetII {
	ethernet := new(EthernetII)
	ethernet.destination.Parse([6]byte(packet[0:6]))
	ethernet.source.Parse([6]byte(packet[6:12]))

	length := len(packet)

	ethernet.etype = utils.ExtractUint16BE(packet, 12)
	if resolve := networklayer.Resolvers[ETHERNET_PROTOCOL_NAME[ethernet.etype]]; resolve != nil {
		ethernet.data = resolve(packet[14:length])
	} else {
		ethernet.data = nil
	}
	ethernet.raw = make([]byte, length)
	copy(ethernet.raw, packet)

	return ethernet
}

// IEEE 802.3 SNAP 协议
type IEEE8023SNAP struct {
	BaseEthernet
	dsap    byte             // 目的服务访问点，固定为 0xAA
	ssap    byte             // 源服务访问点，固定为 0xAA
	control byte             // 固定为 0x03
	oui     [3]byte          // 组织唯一标识符
	utype   uint16           // 上层协议类型（仅当 oui 字段为 0x000000 时）
	data    resolver.IPacket // 上层协议数据
}

// 以 IEEE 802.3 SNAP 协议格式解析报文
func IEEE8023SNAPResolve(packet []byte) *IEEE8023SNAP {
	ethernet := new(IEEE8023SNAP)
	ethernet.destination.Parse([6]byte(packet[0:6]))
	ethernet.source.Parse([6]byte(packet[6:12]))

	length := len(packet)

	ethernet.etype = utils.ExtractUint16BE(packet, 12)
	ethernet.dsap = utils.ExtractUint8BE(packet, 14)
	ethernet.ssap = utils.ExtractUint8BE(packet, 14)
	ethernet.control = utils.ExtractUint8BE(packet, 14)
	if ethernet.dsap != 0xAA || ethernet.ssap != 0xAA || ethernet.control != 0x03 {
		return nil
	}
	copy(ethernet.oui[:], packet[17:20])
	ethernet.utype = utils.ExtractUint16BE(packet, 20)
	resolve := networklayer.Resolvers[ETHERNET_PROTOCOL_NAME[ethernet.utype]]
	if (ethernet.oui[0]|ethernet.oui[1]|ethernet.oui[2]) == 0 && resolve != nil {
		ethernet.data = resolve(packet[14:length])
	} else {
		ethernet.data = nil
	}
	ethernet.raw = make([]byte, length)
	copy(ethernet.raw, packet)

	return ethernet
}
