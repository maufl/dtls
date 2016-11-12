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

func ReadHandshakeType(buffer *bytes.Buffer) (HandshakeType, error) {
	b, err := buffer.ReadByte()
	if err != nil {
		return 255, err
	}
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
	MsgType        HandshakeType
	Length         uint32
	MessageSeq     uint16
	FragmentOffset uint32
	FragmentLength uint32
	Fragment       []byte
	Payload        ToBytes
}

var InvalidHandshakeError = errors.New("Invalid handshake")

func ReadHandshake(buffer *bytes.Buffer) (h Handshake, err error) {
	if buffer.Len() < 12 {
		return h, errors.New("Buffer does not contain enough bytes to read handshake header")
	}
	if h.MsgType, err = ReadHandshakeType(buffer); err != nil {
		return
	}
	h.Length = ReadUint24(buffer)
	h.MessageSeq = ReadUint16(buffer)
	h.FragmentOffset = ReadUint24(buffer)
	h.FragmentLength = ReadUint24(buffer)
	if buffer.Len() < int(h.FragmentLength) {
		return h, errors.New("Buffer does not contain all bytes of fragment")
	}
	h.Fragment = buffer.Next(int(h.FragmentLength))
	if h.Length == h.FragmentLength {
		handshakeMessageBuffer := bytes.NewBuffer(h.Fragment)
		var err error = nil
		switch h.MsgType {
		case HelloVerifyRequest:
			h.Payload, err = ReadHandshakeHelloVerifyRequest(handshakeMessageBuffer)
		case ServerHello:
			h.Payload, err = ReadHandshakeServerHello(handshakeMessageBuffer)
		case ServerKeyExchange:
			h.Payload, err = ReadHandshakeServerKeyExchange(handshakeMessageBuffer)
		case ServerHelloDone:
			h.Payload, err = ReadHandshakeServerHelloDone(handshakeMessageBuffer)
		}
		if err != nil {
			return h, err
		}
	}
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
	buffer.Write(h.Payload.Bytes())
	return buffer.Bytes()
}

func (h Handshake) VerifyBytes() []byte {
	buffer := bytes.Buffer{}
	buffer.Write(h.MsgType.Bytes())
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, h.Length)
	buffer.Write(b[1:])
	buffer.Write(h.Payload.Bytes())
	return buffer.Bytes()
}

func (h Handshake) String() string {
	return fmt.Sprintf("Handshake{ Type: %s, Length: %d, MessageSeq: %d, FragmentOffset: %d, FragmentLength: %d, \n\t%s\n }", h.MsgType, h.Length, h.MessageSeq, h.FragmentOffset, h.FragmentLength, h.Payload)
}
