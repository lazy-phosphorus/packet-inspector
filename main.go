package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"packet-inspector/resolver"
	datalinklayer "packet-inspector/resolver/datalink-layer"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

func worker(cache []byte) {
	var packet resolver.IPacket = nil
	for _, resolve := range datalinklayer.Resolvers {
		packet = resolve(cache)
		if packet != nil {
			break
		}
	}
	if packet == nil {
		fmt.Printf("Can not resolve %s", hex.EncodeToString(cache))
	} else {
		println(packet.ToReadableString(0))
	}
}

func main() {
	if len(os.Args) < 2 {
		panic("no device specified")
	}
	handle, err := pcap.OpenLive(os.Args[1], 4096, false, 30*time.Second)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		go worker(packet.Data())
	}
}
