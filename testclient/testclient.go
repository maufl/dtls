package main

import (
	"github.com/maufl/dtls"
	"log"
	"net"
	"time"
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
