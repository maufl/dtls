package dtls

import (
	"encoding/binary"
	"fmt"
)

type HandshakeServerHello struct {
	ServerVersion     ProtocolVersion
	Random            Random
	SessionID         []byte
	CipherSuite       CipherSuite
	CompressionMethod CompressionMethod
	Extensions        []Extension
}

func (sh HandshakeServerHello) String() string {
	return fmt.Sprintf("ServerHello{ ServerVersion: %s, Random: %s, SessionID: %x, CipherSuite: %s, CompressionMethod: %s }", sh.ServerVersion, sh.Random, sh.SessionID, sh.CipherSuite, sh.CompressionMethod)
}

func ReadHandshakeServerHello(buffer []byte) (hsh HandshakeServerHello, err error) {
	if len(buffer) < 35 {
		return hsh, InvalidHandshakeError
	}
	if hsh.ServerVersion, err = ReadProtocolVersion(buffer[0], buffer[1]); err != nil {
		return
	}
	if hsh.Random, err = ReadRandom(buffer[2:34]); err != nil {
		return
	}
	sessionIdLength := uint(buffer[34])
	hsh.SessionID = buffer[35 : sessionIdLength+35]
	currentByte := sessionIdLength + 35
	if hsh.CipherSuite, err = ReadCipherSuite(buffer[currentByte], buffer[currentByte+1]); err != nil {
		return
	}
	currentByte += 2
	if hsh.CompressionMethod, err = ReadCompressionMethod(buffer[currentByte]); err != nil {
		return
	}
	currentByte += 1
	// TODO: does this field exist if there are no extensions?
	numExtensions := int(binary.BigEndian.Uint16(buffer[currentByte : currentByte+2]))
	hsh.Extensions = make([]Extension, numExtensions)
	currentByte += 2
	for i := 0; i < numExtensions; i++ {
		if hsh.Extensions[i], err = ReadExtension(buffer[currentByte:]); err != nil {
			return
		}
		currentByte += hsh.Extensions[i].Consumes()
	}
	return
}
