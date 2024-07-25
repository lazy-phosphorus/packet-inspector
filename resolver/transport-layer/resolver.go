package transportlayer

import "packet-inspector/resolver"

var Resolvers = map[string]resolver.PacketResolver{}

func init() {
	Resolvers["TCP"] = TCPResolve
	Resolvers["UDP"] = UDPResolve
}
