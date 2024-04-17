package resolver

type IPacket interface {
	Hex() string
	Raw() []byte
	ToReadableString(indent int) string
}

type PacketResolver func(packet []byte) IPacket
