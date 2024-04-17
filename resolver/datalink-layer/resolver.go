package datalinklayer

import "packet-inspector/resolver"

var Resolvers = map[string]resolver.PacketResolver{}

func init() {
	Resolvers["ethernet"] = EthernetResolve
}
