package dtls

import (
	"bytes"
	_ "encoding/hex"
	"log"
	"net"
)

const UDP_MAX_SIZE = 64 * 1024

type SecurityParameters struct {
	*CipherSuite
	CompressionMethod
	KeyAgreement
	MasterSecret [48]byte
	ClientRandom Random
	ServerRandom Random
	Cipher       interface{}
	Mac          macFunction
}

type Conn struct {
	*net.UDPConn
	cookie            []byte
	sequenceNumber    uint64
	sessionID         []byte
	finishedHash      finishedHash
	currentReadState  SecurityParameters
	currentWriteState SecurityParameters
	pendingReadState  SecurityParameters
	pendingWriteState SecurityParameters
}

func NewConn(c *net.UDPConn) *Conn {
	dtlsConn := &Conn{
		UDPConn:      c,
		finishedHash: newFinishedHash(),
		pendingReadState: SecurityParameters{
			ClientRandom: NewRandom(),
		},
		pendingWriteState: SecurityParameters{
			ServerRandom: NewRandom(),
		},
	}
	dtlsConn.sendClientHello()
	return dtlsConn
}

func (c *Conn) Listen() {
	for {
		c.ReadRecord()
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
	log.Printf("Received new record: %s\n", record)
	if handshake, ok := record.Payload.(Handshake); ok {
		c.handleHandshakeRecord(handshake)
	}
	return record, nil
}

func (c *Conn) SendRecord(r Record) error {
	log.Printf("Sending record: %s\n", r)
	recordBytes := r.Bytes()
	//log.Println("Record is")
	//log.Println("\n" + hex.Dump(recordBytes))
	_, err := c.UDPConn.Write(recordBytes)
	return err
}
