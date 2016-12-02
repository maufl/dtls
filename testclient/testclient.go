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
	dtlsConn, err := dtls.NewConn(conn)
	if err != nil {
		log.Fatalf("Error while opening connection: %s", err)
	}
	for {
		dtlsConn.Write([]byte("Hello World"))
		bytes, err := dtlsConn.Read()
		if err != nil {
			log.Fatalf("Error while reading: %s", err)
		}
		log.Printf("Read data: %s", string(bytes))
		time.Sleep(1 * time.Second)
	}
}
