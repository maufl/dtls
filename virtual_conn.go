package dtls

import (
	"errors"
	"net"
	"time"
)

type VirtualConn struct {
	in            chan []byte
	out           net.PacketConn
	localAddress  net.Addr
	remoteAddress net.Addr
	readDeadline  time.Time
}

func NewVirtualConn(conn net.PacketConn, local, remote net.Addr) *VirtualConn {
	return &VirtualConn{
		in:            make(chan []byte),
		out:           conn,
		localAddress:  local,
		remoteAddress: remote,
	}
}

func (c *VirtualConn) Receive(b []byte) {
	c.in <- b
}

func (c *VirtualConn) Read(b []byte) (n int, err error) {
	select {
	case record := <-c.in:
		return copy(b, record), nil
	case <-time.After(time.Until(c.readDeadline)):
		return 0, errors.New("Timeout")
	}
}

func (c *VirtualConn) Write(b []byte) (n int, err error) {
	return c.out.WriteTo(b, c.remoteAddress)
}

func (c *VirtualConn) Close() error {
	close(c.in)
	return nil
}

func (c *VirtualConn) LocalAddr() net.Addr {
	return c.localAddress
}

func (c *VirtualConn) RemoteAddr() net.Addr {
	return c.remoteAddress
}

func (c *VirtualConn) SetDeadline(t time.Time) (err error) {
	return c.SetReadDeadline(t)
}

func (c *VirtualConn) SetReadDeadline(t time.Time) (err error) {
	c.readDeadline = t
	return
}

func (c *VirtualConn) SetWriteDeadline(t time.Time) (err error) {
	return
}
