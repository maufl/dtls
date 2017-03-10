package dtls

import (
	"net"
)

type Listener struct {
	net.PacketConn

	connections map[net.Addr]*VirtualConn
}

func NewListener(c net.PacketConn) *Listener {
	return &Listener{
		PacketConn:  c,
		connections: make(map[net.Addr]*VirtualConn),
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	for {
		buffer := make([]byte, UDP_MAX_SIZE)
		n, addr, err := l.ReadFrom(buffer)
		if err != nil {
			return nil, err
		}
		if conn, ok := l.connections[addr]; ok {
			go conn.Receive(buffer[:n])
			continue
		}
		virtualConn := NewVirtualConn(l, l.LocalAddr(), addr)
		go virtualConn.Receive(buffer[:n])
		return NewConn(virtualConn, true)
	}
}

func (l *Listener) Close() error {
	for _, conn := range l.connections {
		conn.Close()
	}
	return l.PacketConn.Close()
}

func (l *Listener) Addr() net.Addr {
	return l.PacketConn.LocalAddr()
}
