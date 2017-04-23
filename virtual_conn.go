package dtls

import (
	"net"
	"time"
)

type virtualConn struct {
	in            chan []byte
	out           net.PacketConn
	localAddress  net.Addr
	remoteAddress net.Addr
	readDeadline  time.Time
}

func newVirtualConn(conn net.PacketConn, local, remote net.Addr) *virtualConn {
	return &virtualConn{
		in:            make(chan []byte),
		out:           conn,
		localAddress:  local,
		remoteAddress: remote,
	}
}

func (c *virtualConn) Receive(b []byte) {
	c.in <- b
}

func (c *virtualConn) Read(b []byte) (n int, err error) {
	record := <-c.in
	return copy(b, record), nil
}

func (c *virtualConn) Write(b []byte) (n int, err error) {
	return c.out.WriteTo(b, c.remoteAddress)
}

func (c *virtualConn) Close() error {
	close(c.in)
	return nil
}

func (c *virtualConn) LocalAddr() net.Addr {
	return c.localAddress
}

func (c *virtualConn) RemoteAddr() net.Addr {
	return c.remoteAddress
}

func (c *virtualConn) SetDeadline(t time.Time) (err error) {
	return c.SetReadDeadline(t)
}

func (c *virtualConn) SetReadDeadline(t time.Time) (err error) {
	c.readDeadline = t
	return
}

func (c *virtualConn) SetWriteDeadline(t time.Time) (err error) {
	return
}
