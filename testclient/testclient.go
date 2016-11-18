package main

import (
	"github.com/maufl/dtls"
	"log"
	"net"
)

func main() {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5556")
	if err != nil {
		log.Fatalf("Unable to resolve remote address: %v\n", err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Fatalf("Unable to connect to remote addr: %v\n", err)
	}
	dtlsConn := dtls.NewConn(conn)
	_, _ = dtlsConn.Read()
}
