package dtls

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
)

const UDP_MAX_SIZE = 64 * 1024

type securityParameters struct {
	compressionMethod
	Cipher cipher.Block
	Mac    macFunction
}

type Conn struct {
	net.Conn
	sequenceNumber    uint64
	epoch             uint16
	version           protocolVersion
	handshakeComplete bool

	currentReadState  securityParameters
	currentWriteState securityParameters
	pendingReadState  securityParameters
	pendingWriteState securityParameters

	handshakeContext handshakeContext

	recordQueue []*record
}

func NewConn(c net.Conn, server bool) net.Conn {
	log.Printf("Opening new DTLS conenction")
	dtlsConn := &Conn{
		Conn:    c,
		version: DTLS_12,
	}
	if server {
		dtlsConn.handshakeContext = &serverHandshake{baseHandshakeContext{Conn: dtlsConn, isServer: true, handshakeMessageBuffer: make(map[uint16]*handshakeFragmentList)}}
	} else {
		random := newRandom()
		dtlsConn.handshakeContext = &clientHandshake{baseHandshakeContext{Conn: dtlsConn, isServer: false, clientRandom: random, handshakeMessageBuffer: make(map[uint16]*handshakeFragmentList)}}
	}
	return dtlsConn
}

func (c *Conn) handshake() (err error) {
	log.Printf("Begin handshake")
	c.handshakeContext.beginHandshake()
	for {
		log.Printf("Wait to read record")
		typ, payload, err := c.readRecord()
		if err != nil {
			return err
		}
		if typ != typeHandshake {
			continue
		}
		log.Printf("Process next handshake packet")
		log.Printf("Handshake record is %x", payload)
		handshake, err := readHandshake(bytes.NewBuffer(payload))
		if err != nil {
			return err
		}
		if complete, err := c.handshakeContext.continueHandshake(&handshake); err != nil {
			return err
		} else if complete {
			c.handshakeComplete = true
			return nil
		}
	}
	return nil
}

func (c *Conn) Read(buffer []byte) (len int, err error) {
	if !c.handshakeComplete {
		err := c.handshake()
		if err != nil {
			return 0, err
		}
	}
	for {
		typ, payload, err := c.readRecord()
		if err != nil {
			return 0, err
		}
		if typ == typeApplicationData {
			len = copy(buffer, payload)
			return len, nil
		}
	}
}

func (c *Conn) readRecord() (typ contentType, payload []byte, err error) {
	var rec *record
	if len(c.recordQueue) > 0 {
		log.Printf("Poping record from queue")
		rec = c.recordQueue[0]
		c.recordQueue = c.recordQueue[1:]
	} else {
		slice := make([]byte, UDP_MAX_SIZE)
		n, err := c.Conn.Read(slice)
		if err != nil {
			return typ, payload, err
		}
		buffer := bytes.NewBuffer(slice[:n])
		rec, err = readRecord(buffer)
		if err != nil {
			return typ, payload, err
		}
		for buffer.Len() > 0 {
			log.Printf("Read additional record from packet")
			r, err := readRecord(buffer)
			if err != nil {
				return typ, nil, err
			}
			c.recordQueue = append(c.recordQueue, r)
		}
	}
	if rec.Type == typeChangeCipherSpec {
		log.Printf("Received change cipher spec record")
		c.currentReadState = c.pendingReadState
		c.pendingReadState = securityParameters{}
		return rec.Type, nil, nil
	}
	authenticated, err := c.decryptRecord(rec.Payload)
	if err != nil {
		return typ, payload, err
	}
	payload, err = c.removeMAC(rec.Type, rec.Epoch, rec.SequenceNumber, authenticated)
	return rec.Type, payload, err
}

func (c *Conn) Write(data []byte) (int, error) {
	if !c.handshakeComplete {
		err := c.handshake()
		if err != nil {
			return 0, err
		}
	}
	return c.sendRecord(typeApplicationData, data)
}

func (c *Conn) sendRecord(typ contentType, payload []byte) (int, error) {
	sequenceNumber := c.sequenceNumber
	epoch := c.epoch
	c.sequenceNumber += 1
	authenticated := c.macRecord(typ, epoch, sequenceNumber, payload)
	encrypted, err := c.encryptRecord(authenticated)
	if err != nil {
		log.Printf("Error while Encrypting record: %s\n", err)
		return 0, err
	}
	header := buildRecordHeader(typ, c.version, epoch, sequenceNumber, uint16(len(encrypted)))
	recordBytes := append(header, encrypted...)
	n, err := c.Conn.Write(recordBytes)
	if err == nil && typ == typeChangeCipherSpec {
		c.currentWriteState = c.pendingWriteState
		c.pendingWriteState = securityParameters{}
	}
	return n, err
}

func (c *Conn) sendChangeCipherSpec() error {
	_, err := c.sendRecord(typeChangeCipherSpec, []byte{1})
	if err == nil {
		c.epoch += 1
	}
	return err
}

func (c *Conn) macRecord(typ contentType, epoch uint16, sequenceNumber uint64, payload []byte) []byte {
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

func (c *Conn) removeMAC(typ contentType, epoch uint16, sequenceNumber uint64, payload []byte) ([]byte, error) {
	if c.currentReadState.Mac == nil {
		return payload, nil
	}
	macSize := c.currentReadState.Mac.Size()
	suppliedMac := payload[len(payload)-macSize:]
	payload = payload[:len(payload)-macSize]
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, sequenceNumber)
	binary.BigEndian.PutUint16(seq, epoch)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(payload)))
	mac := c.currentReadState.Mac.MAC(seq, typ.Bytes(), c.version.Bytes(), length, payload)
	if !bytes.Equal(suppliedMac, mac) {
		return []byte{}, errors.New("Invalid record MAC")
	}
	return payload, nil
}

func (c *Conn) encryptRecord(payload []byte) ([]byte, error) {
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

func (c *Conn) decryptRecord(payload []byte) ([]byte, error) {
	ciph := c.currentReadState.Cipher
	if ciph == nil {
		return payload, nil
	}
	blockSize := ciph.BlockSize()
	if len(payload)%blockSize != 0 {
		return payload, errors.New("Encrypted payload is not multiple of block size")
	}
	mode := cipher.NewCBCDecrypter(ciph, payload[:blockSize])
	mode.CryptBlocks(payload[blockSize:], payload[blockSize:])
	return checkAndRemovePadding(payload[blockSize:])
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

func checkAndRemovePadding(padded []byte) (payload []byte, err error) {
	paddingLength := int(padded[len(padded)-1])
	if paddingLength > len(padded)-1 {
		return []byte{}, errors.New("Invalid decrypted record")
	}
	for i := len(padded) - paddingLength - 1; i < len(padded); i++ {
		if int(padded[i]) != paddingLength {
			return []byte{}, errors.New("Invalid padding")
		}
	}
	return padded[:len(padded)-paddingLength-1], nil
}
