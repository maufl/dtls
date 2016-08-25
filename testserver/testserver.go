package main

import (
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
	for {
		buffer := make([]byte, 65000)
		bytes, raddr, err := conn.ReadFrom(buffer)
		if err != nil {
			log.Fatalf("Unable to read message: %v\n", err)
		}
		log.Printf("Read message from %v\n", raddr)
		log.Printf("%v\n", string(buffer[:bytes]))
		_, err = conn.WriteTo(buffer[:bytes], raddr)
		if err != nil {
			log.Fatalf("Unable to write hello message: %v\n", err)
		}
	}
}
