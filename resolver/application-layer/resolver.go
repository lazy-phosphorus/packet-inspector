package applicationlayer

import "packet-inspector/resolver"

var Resolvers = map[string]resolver.PacketResolver{}

func init() {
	Resolvers["PIEP"] = PIEPResolve
}
