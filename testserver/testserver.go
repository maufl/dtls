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
		log.Printf("Listening for new connection")
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error while accepting new connection: %s", err)
			return
		}
		go (func() {
			for {
				buffer := make([]byte, 64*1024)
				n, err := conn.Read(buffer)
				if err != nil {
					log.Printf("Error while reading data: %s", err)
					return
				}
				_, err = conn.Write(buffer[:n])
				if err != nil {
					log.Printf("Error while writing data: %s", err)
					return
				}
			}
		})()
	}
	log.Printf("Server shutting down")
}
