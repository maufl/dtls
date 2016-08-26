package dtls

import (
	"encoding/hex"
	"log"
	"net"
)

const UDP_MAX_SIZE = 64 * 1024

type Conn struct {
	*net.UDPConn
	sequenceNumber uint64
	random         Random
	sessionID      []byte
}

func NewConn(c *net.UDPConn) *Conn {
	return &Conn{
		UDPConn: c,
		random:  NewRandom(),
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
		} else if handshake.MsgType == ServerHello {
			serverHello, err := ReadHandshakeServerHello(record.Fragment[12:])
			if err != nil {
				return Record{}, err
			}
			handshake.AssembledFragment = serverHello
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
			TLS_DH_anon_WITH_AES_128_CBC_SHA,
			TLS_DH_anon_WITH_AES_256_CBC_SHA256,
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
