package dtls

import (
	"bytes"
	_ "encoding/hex"
	_ "log"
	"net"
)

const UDP_MAX_SIZE = 64 * 1024

type SecurityParameters struct {
	CipherSuite
	CompressionMethod
	MasterSecret [48]byte
	ClientRandom Random
	ServerRandom Random
}

type Conn struct {
	*net.UDPConn
	sequenceNumber    uint64
	random            Random
	sessionID         []byte
	currentReadState  SecurityParameters
	currentWriteState SecurityParameters
	pendingReadState  SecurityParameters
	pendingWriteState SecurityParameters
}

func NewConn(c *net.UDPConn) *Conn {
	return &Conn{
		UDPConn: c,
		random:  NewRandom(),
	}
}

func (c *Conn) ReadRecord() (Record, error) {
	slice := make([]byte, UDP_MAX_SIZE)
	n, _, err := c.UDPConn.ReadFrom(slice)
	if err != nil {
		return Record{}, err
	}
	buffer := bytes.NewBuffer(slice[:n])
	record, err := ReadRecord(buffer)
	if err != nil {
		return Record{}, err
	}
	if handshake, ok := record.Payload.(Handshake); ok {
		handshakeBuffer := bytes.NewBuffer(handshake.Fragment)
		if handshake.MsgType == HelloVerifyRequest {
			helloVerifyRequest, err := ReadHandshakeHelloVerifyRequest(handshakeBuffer)
			if err != nil {
				return Record{}, err
			}
			handshake.Payload = helloVerifyRequest
		} else if handshake.MsgType == ServerHello {
			serverHello, err := ReadHandshakeServerHello(handshakeBuffer)
			if err != nil {
				return Record{}, err
			}
			handshake.Payload = serverHello
		}
	}
	return record, nil
}

func (c *Conn) SendRecord(r Record) error {
	//log.Printf("Sending record: %s\n", r)
	recordBytes := r.Bytes()
	//log.Println("Record is")
	//log.Println("\n" + hex.Dump(recordBytes))
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
		MsgType:        ClientHello,
		Length:         uint32(len(clientHelloBytes)),
		MessageSeq:     0,
		FragmentOffset: 0,
		FragmentLength: uint32(len(clientHelloBytes)),
		Payload:        clientHello,
	}
	handshakeBytes := handshake.Bytes()
	record := Record{
		Type:           TypeHandshake,
		Version:        DTLS_10,
		Epoch:          0,
		SequenceNumber: c.sequenceNumber,
		Length:         uint16(len(handshakeBytes)),
		Payload:        handshake,
	}
	c.sequenceNumber += 1
	return c.SendRecord(record)
}
