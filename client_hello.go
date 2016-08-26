package dtls

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

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
