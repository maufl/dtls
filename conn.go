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
	currentReadState        SecurityParameters
	currentWriteState       SecurityParameters
	pendingReadState        SecurityParameters
	pendingWriteState       SecurityParameters
}

func NewConn(c *net.UDPConn) *Conn {
	random := NewRandom()
	dtlsConn := &Conn{
		UDPConn:      c,
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
	//log.Printf("Received new record: %s\n", record)
	if handshake, ok := record.Payload.(Handshake); ok {
		c.handleHandshakeRecord(handshake)
	}
	return record, nil
}

func (c *Conn) SendRecord(r Record) error {
	//log.Printf("Sending record: %s\n", r)
	if err := c.MACRecord(&r); err != nil {
		log.Printf("Error while MACing record: %s\n", err)
		return err
	}
	if err := c.EncryptRecord(&r); err != nil {
		log.Printf("Error while Encrypting record: %s\n", err)
		return err
	}
	recordBytes := r.Bytes()
	//log.Println("Record is")
	//log.Println("\n" + hex.Dump(recordBytes))
	_, err := c.UDPConn.Write(recordBytes)
	return err
}

func (c *Conn) MACRecord(r *Record) error {
	if c.currentWriteState.Mac != nil {
		//log.Println("MACing record")
		if r.PayloadRaw == nil {
			r.PayloadRaw = r.Payload.Bytes()
		}
		seq := make([]byte, 8)
		binary.BigEndian.PutUint64(seq, r.SequenceNumber)
		binary.BigEndian.PutUint16(seq, r.Epoch)
		len := make([]byte, 2)
		binary.BigEndian.PutUint16(len, r.Length)
		mac := c.currentWriteState.Mac.MAC(seq, r.Type.Bytes(), r.Version.Bytes(), len, r.PayloadRaw)
		r.PayloadRaw = append(r.PayloadRaw, mac...)
	}
	return nil
}

func (c *Conn) EncryptRecord(r *Record) error {
	ciph := c.currentWriteState.Cipher
	if ciph != nil {
		blockSize := ciph.BlockSize()
		//log.Println("Encrypting record")
		if r.PayloadRaw == nil {
			r.PayloadRaw = r.Payload.Bytes()
		}
		padded := padToBlockSize(r.PayloadRaw, blockSize)
		encrypted := make([]byte, blockSize+len(padded))
		iv := encrypted[:blockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return err
		}
		mode := cipher.NewCBCEncrypter(ciph, iv)
		mode.CryptBlocks(encrypted[blockSize:], padded)
		r.PayloadRaw = encrypted
		r.Length = uint16(len(encrypted))
	}
	return nil
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
	return
}
