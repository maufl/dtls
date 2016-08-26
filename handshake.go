package dtls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type HandshakeType byte

const (
	HelloRequest       HandshakeType = 0
	ClientHello                      = 1
	ServerHello                      = 2
	HelloVerifyRequest               = 3
	Certificate                      = 11
	ServerKeyExchange                = 12
	CertificateRequest               = 13
	ServerHelloDone                  = 14
	CertificateVerify                = 15
	ClientKeyExchange                = 16
	Finished                         = 20
)

func (ht HandshakeType) Bytes() []byte {
	return []byte{byte(ht)}
}

func (ht HandshakeType) String() string {
	switch ht {
	case HelloRequest:
		return "HelloRequest"
	case ClientHello:
		return "ClientHello"
	case ServerHello:
		return "ServerHello"
	case HelloVerifyRequest:
		return "HelloVerifyRequest"
	case Certificate:
		return "Certificate"
	case ServerKeyExchange:
		return "ServerKeyExchange"
	case CertificateRequest:
		return "CertificateRequest"
	case ServerHelloDone:
		return "ServerHelloDone"
	case CertificateVerify:
		return "CertificateVerify"
	case ClientKeyExchange:
		return "ClientKeyExchange"
	case Finished:
		return "Finished"
	default:
		return "xxx"
	}
}

var InvalidHandshakeType = errors.New("Invalid handshake type")

func ReadHandshakeType(b byte) (HandshakeType, error) {
	switch b {
	case 0:
		return HelloRequest, nil
	case 1:
		return ClientHello, nil
	case 2:
		return ServerHello, nil
	case 3:
		return HelloVerifyRequest, nil
	case 11:
		return Certificate, nil
	case 12:
		return ServerKeyExchange, nil
	case 13:
		return CertificateRequest, nil
	case 14:
		return ServerHelloDone, nil
	case 15:
		return CertificateVerify, nil
	case 16:
		return ClientKeyExchange, nil
	case 20:
		return Finished, nil
	default:
		return 0, InvalidHandshakeType
	}
}

type Handshake struct {
	MsgType           HandshakeType
	Length            uint32
	MessageSeq        uint16
	FragmentOffset    uint32
	FragmentLength    uint32
	AssembledFragment interface{}
}

var InvalidHandshakeError = errors.New("Invalid handshake")

func ReadHandshake(buffer []byte) (h Handshake, err error) {
	if len(buffer) < 12 {
		return h, InvalidHandshakeError
	}
	if h.MsgType, err = ReadHandshakeType(buffer[0]); err != nil {
		return
	}
	h.Length = binary.BigEndian.Uint32(append([]byte{0}, buffer[1:4]...))
	h.MessageSeq = binary.BigEndian.Uint16(buffer[4:6])
	h.FragmentOffset = binary.BigEndian.Uint32(append([]byte{0}, buffer[6:9]...))
	h.FragmentLength = binary.BigEndian.Uint32(append([]byte{0}, buffer[9:12]...))
	return
}

func (h Handshake) Bytes() []byte {
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
	return buffer.Bytes()
}

func (h Handshake) String() string {
	return fmt.Sprintf("Handshake{ Type: %s, Length: %d, MessageSeq: %d, FragmentOffset: %d, FragmentLength: %d, \n\t%s\n }", h.MsgType, h.Length, h.MessageSeq, h.FragmentOffset, h.FragmentLength, h.AssembledFragment)
}
