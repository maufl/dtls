package dtls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type handshakeClientHello struct {
	ClientVersion      protocolVersion
	Random             random
	SessionID          []byte
	Cookie             []byte
	CipherSuites       []*cipherSuite
	CompressionMethods []compressionMethod
	Extensions         []extension
}

func readHandshakeClientHello(data []byte) (clientHello handshakeClientHello, err error) {
	buffer := bytes.NewBuffer(data)
	if clientHello.ClientVersion, err = readProtocolVersion(buffer); err != nil {
		return
	}
	if clientHello.Random, err = readRandom(buffer); err != nil {
		return
	}

	sessionIDLength, err := buffer.ReadByte()
	if err != nil {
		return
	}
	if int(sessionIDLength) > buffer.Len() {
		err = errors.New("Insufficient data to read session ID")
		return
	}
	clientHello.SessionID = buffer.Next(int(sessionIDLength))

	cookieLength, err := buffer.ReadByte()
	if err != nil {
		return
	}
	if int(cookieLength) > buffer.Len() {
		err = errors.New("Insufficient data to read cookie")
		return
	}
	clientHello.Cookie = buffer.Next(int(cookieLength))

	numCipherSuites := int(readUint16(buffer)) / 2
	for i := 0; i < numCipherSuites; i++ {
		cipherSuite, err := readCipherSuite(buffer)
		if err != nil {
			return clientHello, err
		}
		clientHello.CipherSuites = append(clientHello.CipherSuites, cipherSuite)
	}

	numCompressionMethods, err := buffer.ReadByte()
	if err != nil {
		return
	}
	for i := 0; i < int(numCompressionMethods); i++ {
		compressionMethod, err := readCompressionMethod(buffer)
		if err != nil {
			return clientHello, err
		}
		clientHello.CompressionMethods = append(clientHello.CompressionMethods, compressionMethod)
	}
	//TODO: Extensions
	return
}

func (ch handshakeClientHello) String() string {
	return fmt.Sprintf("ClientHello{ ClientVersion: %s, Random: %s, SessionID: %x, Cookie: %x }", ch.ClientVersion, ch.Random, ch.SessionID, ch.Cookie)
}

func (ch handshakeClientHello) Bytes() []byte {
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
