package agent

import (
	"errors"
	"net"
	"strings"
	"time"
)

type wolPacketConn interface {
	Write([]byte) (int, error)
	Close() error
}

func wakeOnLAN(mac string, dial func(network, address string) (wolPacketConn, error)) error {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil || len(hw) != 6 {
		return errors.New("invalid mac address")
	}
	packet := make([]byte, 6+16*len(hw))
	for i := 0; i < 6; i++ {
		packet[i] = 0xff
	}
	for i := 0; i < 16; i++ {
		copy(packet[6+i*len(hw):], hw)
	}
	conn, err := dial("udp4", "255.255.255.255:9")
	if err != nil {
		return err
	}
	defer conn.Close()
	n, err := conn.Write(packet)
	if err != nil {
		return err
	}
	if n != len(packet) {
		return errors.New("short wol packet write")
	}
	return nil
}

func sendWakeOnLAN(mac string) error {
	return wakeOnLAN(mac, func(network, address string) (wolPacketConn, error) {
		conn, err := net.DialTimeout(network, address, 5*time.Second)
		if err != nil {
			return nil, err
		}
		return conn, nil
	})
}
