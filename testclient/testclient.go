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
	err = dtlsConn.SendClientHello([]byte{})
	if err != nil {
		log.Fatalf("Unable to send hello message: %v\n", err)
	}
	record, err := dtlsConn.ReadRecord()
	if err != nil {
		log.Fatalf("Unable to read record: %v\n", err)
	}
	log.Printf("%s\n", record)
	handshake := record.Payload.(dtls.Handshake)
	helloVerifyRequest := handshake.Payload.(dtls.HandshakeHelloVerifyRequest)
	err = dtlsConn.SendClientHello(helloVerifyRequest.Cookie)
	if err != nil {
		log.Fatalf("Unable to send hello message: %v\n", err)
	}
	record, err = dtlsConn.ReadRecord()
	if err != nil {
		log.Fatalf("Unable to read record: %v\n", err)
	}
	log.Printf("%s\n", record)
	record, err = dtlsConn.ReadRecord()
	if err != nil {
		log.Fatalf("Unable to read record: %v\n", err)
	}
	log.Printf("%s\n", record)
	handshake = record.Payload.(dtls.Handshake)
	_ = handshake.Payload.(dtls.HandshakeServerKeyExchange)
	record, err = dtlsConn.ReadRecord()
	if err != nil {
		log.Fatalf("Unable to read record: %v\n", err)
	}
	log.Printf("%s\n", record)

}
