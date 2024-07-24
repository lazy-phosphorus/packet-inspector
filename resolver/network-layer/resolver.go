package networklayer

import "packet-inspector/resolver"

var Resolvers = map[string]resolver.PacketResolver{}

func init() {
	Resolvers["IPv4"] = IPv4Resolve
}
