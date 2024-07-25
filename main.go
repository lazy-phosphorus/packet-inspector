package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"packet-inspector/resolver"
	applicationlayer "packet-inspector/resolver/application-layer"
	datalinklayer "packet-inspector/resolver/datalink-layer"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/tcpassembly"
)

type reassembler struct{}

type stream struct {
	tcpassembly.Stream
	net       gopacket.Flow
	transport gopacket.Flow
	data      []byte
	start     time.Time
	end       time.Time
}

func (factory *reassembler) New(net gopacket.Flow, transport gopacket.Flow) tcpassembly.Stream {
	log.Printf("new stream %v:%v started", net, transport)
	s := &stream{
		net:       net,
		transport: transport,
		start:     time.Now(),
	}
	s.end = s.start
	return s
}

func (s *stream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	for _, reassembly := range reassemblies {
		if !reassembly.Seen.Before(s.end) {
			s.end = reassembly.Seen
		}
		s.data = append(s.data, reassembly.Bytes...)
	}
}

func (s *stream) ReassemblyComplete() {
	for _, resolver := range applicationlayer.Resolvers {
		packet := resolver(s.data)
		if packet != nil {
			println(packet.ToReadableString(0))
			return
		}
	}
	fmt.Printf("[Application Layer] Can not resolve %s\n", hex.EncodeToString(s.data))
}

func worker(packet gopacket.Packet) {
	var resolvedPacket resolver.IPacket = nil
	for _, resolve := range datalinklayer.Resolvers {
		resolvedPacket = resolve(packet.Data())
		if packet != nil {
			break
		}
	}
	if resolvedPacket == nil {
		fmt.Printf("[Datalink Layer] Can not resolve %s\n", hex.EncodeToString(packet.Data()))
	} else {
		println(resolvedPacket.ToReadableString(0))
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

	streamFactory := &reassembler{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	nextFlush := time.Now().Add(time.Minute / 2)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		go worker(packet)

		if time.Now().After(nextFlush) {
			assembler.FlushOlderThan(time.Now().Add(time.Minute / 2))
			nextFlush = time.Now().Add(time.Minute / 2)
		}

		tcp, ok := packet.TransportLayer().(*layers.TCP)
		if ok {
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
		}

	}
}
