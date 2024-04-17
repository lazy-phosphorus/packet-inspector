package main

import (
	"encoding/hex"
	"fmt"
	"packet-inspector/inspector"
	"packet-inspector/resolver"
	datalinklayer "packet-inspector/resolver/datalink-layer"
)

func work(cache []byte) {
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
	inspktr := inspector.NewInspector(4096)
	err := inspktr.Open()
	if err != nil {
		println(err.Error())
		return
	}
	defer inspktr.Close()

	for {
		cache, _ := inspktr.Read()
		go work(cache)
	}
}
