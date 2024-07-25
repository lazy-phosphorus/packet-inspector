package applicationlayer

import "packet-inspector/resolver"

var Resolvers = map[string]resolver.PacketResolver{}

func init() {
	Resolvers["PieP"] = PiePResolve
	Resolvers["FlexRay"] = FlexRayResolve
	Resolvers["HTTP"] = HTTPResolve
}
