package main

import (
	"github.com/maufl/dtls"
	"log"
	"net"
)

func main() {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:10000")
	if err != nil {
		log.Fatalf("Unable to resolve address: %v\n", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("Unable to listen on adress: %v\n", err)
	}
	listener := dtls.NewListener(conn)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go (func() {
			for {
				buffer := make([]byte, 64*1024)
				n, err := conn.Read(buffer)
				if err != nil {
					return
				}
				_, err = conn.Write(buffer[:n])
				if err != nil {
					return
				}
			}
		})()
	}
}
