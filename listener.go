package dtls

import (
	"log"
	"net"
)

type Listener struct {
	net.PacketConn

	connections map[string]*virtualConn
}

func NewListener(c net.PacketConn) *Listener {
	return &Listener{
		PacketConn:  c,
		connections: make(map[string]*virtualConn),
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	for {
		buffer := make([]byte, UDP_MAX_SIZE)
		n, addr, err := l.ReadFrom(buffer)
		log.Printf("Read new packet in listener")
		if err != nil {
			log.Printf("Error while reading from socekt: %s", err)
			return nil, err
		}
		if conn, ok := l.connections[addr.String()]; ok {
			log.Printf("Forwarding packet to virtual connection")
			go conn.Receive(buffer[:n])
			continue
		}
		log.Printf("Creating new connection for packet from %s", addr)
		virtualConn := newVirtualConn(l, l.LocalAddr(), addr)
		go virtualConn.Receive(buffer[:n])
		l.connections[addr.String()] = virtualConn
		return NewConn(virtualConn, true), nil
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
