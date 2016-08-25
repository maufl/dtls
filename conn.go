package dtls

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net"
	"time"
)

const UDP_MAX_SIZE = 64 * 1024

type Conn struct {
	*net.UDPConn
	sequenceNumber uint64
	random         Random
	sessionID      []byte
}

func NewConn(c *net.UDPConn) *Conn {
	var randomBytes = [28]byte{}
	if _, err := rand.Read(randomBytes[:]); err != nil {
		panic(err)
	}
	return &Conn{
		UDPConn: c,
		random:  Random{GMTUnixTime: uint32(time.Now().Unix()), Opaque: randomBytes},
	}
}

func (c *Conn) ReadRecord() (Record, error) {
	buffer := make([]byte, UDP_MAX_SIZE)
	bytes, _, err := c.UDPConn.ReadFrom(buffer)
	if err != nil {
		return Record{}, err
	}
	record, err := ReadRecord(buffer[:bytes])
	if err != nil {
		return Record{}, err
	}
	if record.Type == TypeHandshake {
		handshake, err := ReadHandshake(record.Fragment[:12])
		if err != nil {
			return Record{}, err
		}
		if handshake.MsgType == HelloVerifyRequest {
			helloVerifyRequest, err := ReadHandshakeHelloVerifyRequest(record.Fragment[12:])
			if err != nil {
				return Record{}, err
			}
			handshake.AssembledFragment = helloVerifyRequest
		}
		record.ParsedFragment = handshake
	}
	return record, nil
}

func (c *Conn) SendRecord(r Record) error {
	log.Printf("Sending record: %s\n", r)
	recordBytes := r.Bytes()
	log.Println("Record is")
	log.Println("\n" + hex.Dump(recordBytes))
	_, err := c.UDPConn.Write(recordBytes)
	return err
}

func (c *Conn) SendClientHello(Cookie []byte) error {
	clientHello := HandshakeClientHello{
		ClientVersion: DTLS_10,
		Random:        c.random,
		SessionID:     c.sessionID,
		Cookie:        Cookie,
		CipherSuites: []CipherSuite{
			TLS_NULL_WITH_NULL_NULL,
			TLS_DH_ANON_WITH_AES_128_CBC_SHA,
			TLS_DH_ANON_AES_256_CBC_SHA256,
		},
		CompressionMethods: []CompressionMethod{
			CompressionNone,
		},
	}
	clientHelloBytes := clientHello.Bytes()
	handshake := Handshake{
		MsgType:           ClientHello,
		Length:            uint32(len(clientHelloBytes)),
		MessageSeq:        0,
		FragmentOffset:    0,
		FragmentLength:    uint32(len(clientHelloBytes)),
		AssembledFragment: clientHello,
	}
	handshakeBytes := handshake.Bytes()
	record := Record{
		Type:           TypeHandshake,
		Version:        DTLS_10,
		Epoch:          0,
		SequenceNumber: c.sequenceNumber,
		Length:         uint16(len(handshakeBytes) + len(clientHelloBytes)),
		Fragment:       append(handshakeBytes, clientHelloBytes...),
		ParsedFragment: handshake,
	}
	c.sequenceNumber += 1
	return c.SendRecord(record)
}
