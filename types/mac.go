package types

import "fmt"

type Mac struct {
	maker [3]byte
	id    [3]byte
}

// 解析 MAC 地址
func (mac *Mac) Parse(addr [6]byte) {
	copy(mac.maker[:], addr[0:3])
	copy(mac.id[:], addr[3:6])
}

// 格式化为字符串
func (mac *Mac) ToString() string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", mac.maker[0], mac.maker[1], mac.maker[2], mac.id[0], mac.id[1], mac.id[2])
}
