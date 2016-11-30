package dtls

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
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
	Cipher       cipher.Block
	Mac          macFunction
}

type Conn struct {
	*net.UDPConn
	cookie                  []byte
	sequenceNumber          uint64
	handshakeSequenceNumber uint16
	sessionID               []byte
	finishedHash            finishedHash
	epoch                   uint16
	version                 ProtocolVersion
	currentReadState        SecurityParameters
	currentWriteState       SecurityParameters
	pendingReadState        SecurityParameters
	pendingWriteState       SecurityParameters
}

func NewConn(c *net.UDPConn) *Conn {
	random := NewRandom()
	dtlsConn := &Conn{
		UDPConn:      c,
		version:      DTLS_10,
		finishedHash: newFinishedHash(),
		pendingReadState: SecurityParameters{
			ClientRandom: random,
		},
		pendingWriteState: SecurityParameters{
			ClientRandom: random,
		},
	}
	dtlsConn.sendClientHello()
	return dtlsConn
}

func (c *Conn) Read() (data []byte, err error) {
	for {
		record, err := c.ReadRecord()
		if err != nil {
			return nil, err
		}
		if handshake, ok := record.Payload.(Handshake); ok {
			c.handleHandshakeRecord(handshake)
			continue
		}
		if record.Type == TypeApplicationData {
			return record.PayloadRaw, nil
		}
		panic("Not implemented")
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
	//log.Printf("Received new record: %s\n", record)
	return record, nil
}

func (c *Conn) Write(data []byte) error {
	return nil
}

func (c *Conn) SendRecord(typ ContentType, payload []byte) error {
	sequenceNumber := c.sequenceNumber
	epoch := c.epoch
	c.sequenceNumber += 1
	log.Printf("Record before authenticating %x", payload)
	authenticated := c.MACRecord(typ, epoch, sequenceNumber, payload)
	log.Printf("Record after authenticationg %x", authenticated)
	encrypted, err := c.EncryptRecord(authenticated)
	if err != nil {
		log.Printf("Error while Encrypting record: %s\n", err)
		return err
	}
	header := BuildRecordHeader(typ, c.version, epoch, sequenceNumber, uint16(len(encrypted)))
	recordBytes := append(header, encrypted...)
	_, err = c.UDPConn.Write(recordBytes)
	return err
}

func (c *Conn) MACRecord(typ ContentType, epoch uint16, sequenceNumber uint64, payload []byte) []byte {
	if c.currentWriteState.Mac == nil {
		return payload
	}
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, sequenceNumber)
	binary.BigEndian.PutUint16(seq, epoch)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(payload)))
	mac := c.currentWriteState.Mac.MAC(seq, typ.Bytes(), c.version.Bytes(), length, payload)
	return append(payload, mac...)
}

func (c *Conn) EncryptRecord(payload []byte) ([]byte, error) {
	ciph := c.currentWriteState.Cipher
	if ciph == nil {
		return payload, nil
	}
	blockSize := ciph.BlockSize()
	padded := padToBlockSize(payload, blockSize)
	encrypted := make([]byte, blockSize+len(padded))
	iv := encrypted[:blockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(ciph, iv)
	mode.CryptBlocks(encrypted[blockSize:], padded)
	return encrypted, nil
}

// padToBlockSize calculates the needed padding block, if any, for a payload.
// On exit, prefix aliases payload and extends to the end of the last full
// block of payload. finalBlock is a fresh slice which contains the contents of
// any suffix of payload as well as the needed padding to make finalBlock a
// full block.
func padToBlockSize(payload []byte, blockSize int) (padded []byte) {
	overrun := len(payload) % blockSize
	paddingLen := blockSize - overrun
	padded = make([]byte, len(payload)+paddingLen)
	copy(padded, payload)
	for i := len(payload); i < len(payload)+paddingLen; i++ {
		padded[i] = byte(paddingLen - 1)
	}
	log.Printf("Record after padding %x", padded)
	return
}
