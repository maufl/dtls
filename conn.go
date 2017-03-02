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

type SecurityParameters struct {
	CompressionMethod
	Cipher cipher.Block
	Mac    macFunction
}

type Conn struct {
	*net.UDPConn
	sequenceNumber uint64
	epoch          uint16
	version        ProtocolVersion

	currentReadState  SecurityParameters
	currentWriteState SecurityParameters
	pendingReadState  SecurityParameters
	pendingWriteState SecurityParameters

	handshakeContext handshakeContext
}

func NewConn(c *net.UDPConn) (*Conn, error) {
	random := NewRandom()
	dtlsConn := &Conn{
		UDPConn:          c,
		version:          DTLS_10,
		handshakeContext: &clientHandshake{baseHandshakeContext{isServer: false, clientRandom: random}},
	}
	err := dtlsConn.handshake()
	return dtlsConn, err
}

func (c *Conn) handshake() (err error) {
	c.handshakeContext.continueHandshake()
	for {
		typ, payload, err := c.ReadRecord()
		if err != nil {
			return err
		}
		if typ == TypeHandshake {
			handshake, err := ReadHandshake(bytes.NewBuffer(payload))
			if err != nil {
				return err
			}
			c.handshakeContext.receiveMessage(&handshake)
			c.handshakeContext.continueHandshake()
			if c.handshakeContext.isHandshakeComplete() {
				break
			}
		}
	}
	return nil
}

func (c *Conn) Read() (data []byte, err error) {
	for {
		typ, payload, err := c.ReadRecord()
		if err != nil {
			return nil, err
		}
		if typ == TypeApplicationData {
			return payload, nil
		}
	}
}

func (c *Conn) ReadRecord() (typ ContentType, payload []byte, err error) {
	for {
		slice := make([]byte, UDP_MAX_SIZE)
		n, _, err := c.UDPConn.ReadFrom(slice)
		if err != nil {
			return typ, payload, err
		}
		if n < 13 {
			err = InvalidRecordError
			return typ, payload, err
		}
		record, err := ReadRecord(bytes.NewBuffer(slice[:n]))
		if err != nil {
			return typ, payload, err
		}
		if record.Type == TypeChangeCipherSpec {
			c.currentReadState = c.pendingReadState
			c.pendingReadState = SecurityParameters{}
			continue
		}
		authenticated, err := c.DecryptRecord(record.Payload)
		if err != nil {
			return typ, payload, err
		}
		payload, err = c.RemoveMAC(record.Type, record.Epoch, record.SequenceNumber, authenticated)
		return record.Type, payload, err
	}
}

func (c *Conn) Write(data []byte) error {
	return c.SendRecord(TypeApplicationData, data)
}

func (c *Conn) SendRecord(typ ContentType, payload []byte) error {
	sequenceNumber := c.sequenceNumber
	epoch := c.epoch
	c.sequenceNumber += 1
	authenticated := c.MACRecord(typ, epoch, sequenceNumber, payload)
	encrypted, err := c.EncryptRecord(authenticated)
	if err != nil {
		log.Printf("Error while Encrypting record: %s\n", err)
		return err
	}
	header := BuildRecordHeader(typ, c.version, epoch, sequenceNumber, uint16(len(encrypted)))
	recordBytes := append(header, encrypted...)
	_, err = c.UDPConn.Write(recordBytes)
	if err == nil && typ == TypeChangeCipherSpec {
		c.currentWriteState = c.pendingWriteState
		c.pendingWriteState = SecurityParameters{}
	}
	return err
}

func (c *Conn) sendChangeCipherSpec() error {
	c.epoch += 1
	return c.SendRecord(TypeChangeCipherSpec, []byte{1})
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

func (c *Conn) RemoveMAC(typ ContentType, epoch uint16, sequenceNumber uint64, payload []byte) ([]byte, error) {
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

func (c *Conn) DecryptRecord(payload []byte) ([]byte, error) {
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
	for i := len(padded) - paddingLength - 1; i < len(padded); i++ {
		if int(padded[i]) != paddingLength {
			return []byte{}, errors.New("Invalid padding")
		}
	}
	return padded[:len(padded)-paddingLength-1], nil
}
