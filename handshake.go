package dtls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
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

type HandshakeHelloRequest struct {
}

type Random struct {
	GMTUnixTime uint32
	Opaque      [28]byte
}

func (r Random) String() string {
	return fmt.Sprintf("Random{ UnixTime: %s, Opaque: %x }", time.Unix(int64(r.GMTUnixTime), 0), r.Opaque)
}

func (r Random) Bytes() []byte {
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, r.GMTUnixTime)
	return append(buffer, r.Opaque[:]...)
}

type CipherSuite [2]byte

var (
	TLS_NULL_WITH_NULL_NULL          CipherSuite = CipherSuite{0x0, 0x0}
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA             = CipherSuite{0x0, 0x33}
	TLS_DH_ANON_WITH_AES_128_CBC_SHA             = CipherSuite{0x0, 0x34}
	TLS_DH_ANON_AES_256_CBC_SHA256               = CipherSuite{0x0, 0x6d}
)

func (cs CipherSuite) Bytes() []byte {
	return cs[:]
}

type CompressionMethod byte

func (cm CompressionMethod) Bytes() []byte {
	return []byte{byte(cm)}
}

const (
	CompressionNone CompressionMethod = 0
)

type ExtensionType uint16

func (et ExtensionType) Bytes() []byte {
	buffer := make([]byte, 2)
	binary.BigEndian.PutUint16(buffer, uint16(et))
	return buffer
}

const (
	ExtensionSignatureAlgorithms ExtensionType = 13
)

type Extension struct {
	Type ExtensionType
	Data []byte
}

func (e Extension) Bytes() []byte {
	buffer := bytes.Buffer{}
	buffer.Write(e.Type.Bytes())
	buffer.Write(e.Data)
	return buffer.Bytes()
}

type HandshakeClientHello struct {
	ClientVersion      ProtocolVersion
	Random             Random
	SessionID          []byte
	Cookie             []byte
	CipherSuites       []CipherSuite
	CompressionMethods []CompressionMethod
	Extensions         []Extension
}

func (ch HandshakeClientHello) String() string {
	return fmt.Sprintf("ClientHello{ ClientVersion: %s, Random: %s, SessionID: %x, Cookie: %x }", ch.ClientVersion, ch.Random, ch.SessionID, ch.Cookie)
}

func (ch HandshakeClientHello) Bytes() []byte {
	buffer := bytes.Buffer{}
	buffer.Write(ch.ClientVersion.Bytes())
	buffer.Write(ch.Random.Bytes())
	buffer.Write([]byte{byte(len(ch.SessionID))})
	buffer.Write(ch.SessionID)
	buffer.Write([]byte{byte(len(ch.Cookie))})
	buffer.Write(ch.Cookie)
	cipherSuiteLength := len(ch.CipherSuites) * 2
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(cipherSuiteLength))
	buffer.Write(b)
	for _, cipherSuite := range ch.CipherSuites {
		buffer.Write(cipherSuite.Bytes())
	}
	buffer.Write([]byte{byte(len(ch.CompressionMethods))})
	for _, compressionMethods := range ch.CompressionMethods {
		buffer.Write(compressionMethods.Bytes())
	}
	for _, extension := range ch.Extensions {
		buffer.Write(extension.Bytes())
	}
	return buffer.Bytes()
}

type HandshakeServerHello struct {
	ServerVersion     ProtocolVersion
	Random            Random
	SessionID         []byte
	CipherSuite       CipherSuite
	CompressionMethod CompressionMethod
	Extensions        []Extension
}

type HandshakeHelloVerifyRequest struct {
	ServerVersion ProtocolVersion
	Cookie        []byte
}

func (hvr HandshakeHelloVerifyRequest) String() string {
	return fmt.Sprintf("HelloVerifyRequest{ ServerVersion: %s, Cookie: %x }", hvr.ServerVersion, hvr.Cookie)
}

func ReadHandshakeHelloVerifyRequest(buffer []byte) (hvr HandshakeHelloVerifyRequest, err error) {
	if len(buffer) < 2 {
		return hvr, InvalidHandshakeError
	}
	if hvr.ServerVersion, err = ReadProtocolVersion(buffer[0], buffer[1]); err != nil {
		return
	}
	cookieLength := int(buffer[2])
	if len(buffer) != cookieLength+3 {
		return hvr, InvalidHandshakeError
	}
	hvr.Cookie = buffer[3:]
	return
}
