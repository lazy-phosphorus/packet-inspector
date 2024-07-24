package resolver

type IPacket interface {
	Hex() string
	Raw() []byte
	ToReadableString(indent int) string
	Payload() []byte
}

type PacketResolver func(packet []byte) IPacket
