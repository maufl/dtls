package dtls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type handshakeType byte

const (
	helloRequest       handshakeType = 0
	clientHello                      = 1
	serverHello                      = 2
	helloVerifyRequest               = 3
	certificate                      = 11
	serverKeyExchange                = 12
	certificateRequest               = 13
	serverHelloDone                  = 14
	certificateVerify                = 15
	clientKeyExchange                = 16
	finished                         = 20
)

func (ht handshakeType) Bytes() []byte {
	return []byte{byte(ht)}
}

func (ht handshakeType) String() string {
	switch ht {
	case helloRequest:
		return "HelloRequest"
	case clientHello:
		return "ClientHello"
	case serverHello:
		return "ServerHello"
	case helloVerifyRequest:
		return "HelloVerifyRequest"
	case certificate:
		return "Certificate"
	case serverKeyExchange:
		return "ServerKeyExchange"
	case certificateRequest:
		return "CertificateRequest"
	case serverHelloDone:
		return "ServerHelloDone"
	case certificateVerify:
		return "CertificateVerify"
	case clientKeyExchange:
		return "ClientKeyExchange"
	case finished:
		return "Finished"
	default:
		return "xxx"
	}
}

var InvalidHandshakeType = errors.New("Invalid handshake type")

func readHandshakeType(buffer *bytes.Buffer) (handshakeType, error) {
	b, err := buffer.ReadByte()
	if err != nil {
		return 255, err
	}
	switch b {
	case 0:
		return helloRequest, nil
	case 1:
		return clientHello, nil
	case 2:
		return serverHello, nil
	case 3:
		return helloVerifyRequest, nil
	case 11:
		return certificate, nil
	case 12:
		return serverKeyExchange, nil
	case 13:
		return certificateRequest, nil
	case 14:
		return serverHelloDone, nil
	case 15:
		return certificateVerify, nil
	case 16:
		return clientKeyExchange, nil
	case 20:
		return finished, nil
	default:
		return 0, InvalidHandshakeType
	}
}

type handshake struct {
	MsgType        handshakeType
	Length         uint32
	MessageSeq     uint16
	FragmentOffset uint32
	FragmentLength uint32
	Fragment       []byte
}

var InvalidHandshakeError = errors.New("Invalid handshake")

func ReadHandshake(buffer *bytes.Buffer) (h handshake, err error) {
	if buffer.Len() < 12 {
		return h, errors.New("Buffer does not contain enough bytes to read handshake header")
	}
	if h.MsgType, err = readHandshakeType(buffer); err != nil {
		return
	}
	h.Length = readUint24(buffer)
	h.MessageSeq = readUint16(buffer)
	h.FragmentOffset = readUint24(buffer)
	h.FragmentLength = readUint24(buffer)
	if buffer.Len() < int(h.FragmentLength) {
		return h, errors.New("Buffer does not contain all bytes of fragment")
	}
	h.Fragment = buffer.Next(int(h.FragmentLength))
	return
}

func (h handshake) Bytes() []byte {
	buffer := bytes.Buffer{}
	buffer.Write(h.MsgType.Bytes())
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, h.Length)
	buffer.Write(b[1:])
	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, h.MessageSeq)
	buffer.Write(b)
	b = make([]byte, 4)
	binary.BigEndian.PutUint32(b, h.FragmentOffset)
	buffer.Write(b[1:])
	b = make([]byte, 4)
	binary.BigEndian.PutUint32(b, h.FragmentLength)
	buffer.Write(b[1:])
	buffer.Write(h.Fragment)
	return buffer.Bytes()
}

func (h handshake) String() string {
	return fmt.Sprintf("Handshake{ Type: %s, Length: %d, MessageSeq: %d, FragmentOffset: %d, FragmentLength: %d, Fragment: %x }", h.MsgType, h.Length, h.MessageSeq, h.FragmentOffset, h.FragmentLength, h.Fragment)
}
