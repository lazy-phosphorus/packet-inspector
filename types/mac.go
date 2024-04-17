package types

import "fmt"

type Mac struct {
	maker [3]byte
	id    [3]byte
}

func (mac *Mac) Parse(addr [6]byte) {
	copy(mac.maker[:], addr[0:3])
	copy(mac.id[:], addr[3:6])
}

func (mac *Mac) ToString() string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", mac.maker[0], mac.maker[1], mac.maker[2], mac.id[0], mac.id[1], mac.id[2])
}

func (mac *Mac) IsGlobal() bool {
	return (mac.maker[0] & 0b10) == 0
}

func (mac *Mac) IsLocal() bool {
	return (mac.maker[0] & 0b10) == 0b10
}

func (mac *Mac) IsUnicast() bool {
	return (mac.maker[0] & 0b1) == 0
}

func (mac *Mac) IsMulticast() bool {
	return (mac.maker[0] & 0b1) == 0b1
}

func (mac *Mac) IsBroadcast() bool {
	return (mac.maker[0] & mac.maker[1] & mac.maker[2] & mac.id[0] & mac.id[1] & mac.id[2]) == 0xFF
}

func (mac *Mac) IsFullZero() bool {
	return (mac.maker[0] | mac.maker[1] | mac.maker[2] | mac.id[0] | mac.id[1] | mac.id[2]) == 0
}
