package main

import (
	"github.com/maufl/dtls"
	"log"
	"net"
	"time"
)

func main() {
	laddr, err := net.ResolveUDPAddr("udp", "[fe80::1cce:99ff:fe67:3645%client0]:5556")
	if err != nil {
		log.Fatalf("Unable to resolve local address: %s\n", err)
	}
	raddr, err := net.ResolveUDPAddr("udp", "[fe80::8471:57ff:fe48:9ee2%client0]:5556")
	if err != nil {
		log.Fatalf("Unable to resolve remote address: %v\n", err)
	}
	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		log.Fatalf("Unable to connect to remote addr: %v\n", err)
	}
	dtlsConn := dtls.NewConn(conn, false)
	for {
		dtlsConn.Write([]byte("Hello World"))
		buffer := make([]byte, dtls.UDP_MAX_SIZE)
		n, err := dtlsConn.Read(buffer)
		if err != nil {
			log.Fatalf("Error while reading: %s", err)
		}
		log.Printf("Read data: %s", string(buffer[:n]))
		time.Sleep(1 * time.Second)
	}
}
