package agent

import (
	"bytes"
	"errors"
	"testing"
)

type fakeWOLConn struct {
	data []byte
	err  error
}

func (c *fakeWOLConn) Write(data []byte) (int, error) {
	c.data = append([]byte(nil), data...)
	if c.err != nil {
		return 0, c.err
	}
	return len(data), nil
}

func (c *fakeWOLConn) Close() error { return nil }

func TestWakeOnLAN(t *testing.T) {
	var network, address string
	conn := &fakeWOLConn{}
	err := wakeOnLAN("aa:bb:cc:dd:ee:ff", func(n, a string) (wolPacketConn, error) {
		network, address = n, a
		return conn, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if network != "udp4" || address != "255.255.255.255:9" || len(conn.data) != 102 {
		t.Fatalf("target/size: %s %s %d", network, address, len(conn.data))
	}
	if !bytes.Equal(conn.data[:6], []byte{255, 255, 255, 255, 255, 255}) {
		t.Fatalf("prefix: %v", conn.data[:6])
	}
	want := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	for i := 0; i < 16; i++ {
		if !bytes.Equal(conn.data[6+i*6:12+i*6], want) {
			t.Fatalf("mac copy %d: %x", i, conn.data[6+i*6:12+i*6])
		}
	}
}

func TestWakeOnLANRejectsBadInput(t *testing.T) {
	if err := wakeOnLAN("not-a-mac", nil); err == nil {
		t.Fatal("invalid mac accepted")
	}
	if err := wakeOnLAN("aa:bb:cc:dd:ee:ff", func(string, string) (wolPacketConn, error) {
		return nil, errors.New("dial")
	}); err == nil {
		t.Fatal("dial failure ignored")
	}
}
