package dtls

import (
	"bytes"
	"errors"
	"fmt"
)

type HandshakeServerHello struct {
	ServerVersion     ProtocolVersion
	Random            Random
	SessionID         []byte
	CipherSuite       *CipherSuite
	CompressionMethod CompressionMethod
	Extensions        []Extension
}

func (sh HandshakeServerHello) String() string {
	return fmt.Sprintf("ServerHello{ ServerVersion: %s, Random: %s, SessionID: %x, CipherSuite: %s, CompressionMethod: %s }", sh.ServerVersion, sh.Random, sh.SessionID, sh.CipherSuite, sh.CompressionMethod)
}

func (sh HandshakeServerHello) Bytes() []byte {
	buffer := &bytes.Buffer{}
	buffer.Write(sh.ServerVersion.Bytes())
	buffer.Write(sh.Random.Bytes())
	buffer.WriteByte(byte(len(sh.SessionID)))
	buffer.Write(sh.SessionID)
	buffer.Write(sh.CipherSuite.Bytes())
	buffer.Write(sh.CompressionMethod.Bytes())
	for _, extension := range sh.Extensions {
		buffer.Write(extension.Bytes())
	}
	return buffer.Bytes()
}

func ReadHandshakeServerHello(byts []byte) (hsh HandshakeServerHello, err error) {
	buffer := bytes.NewBuffer(byts)
	if buffer.Len() < 35 {
		return hsh, errors.New("Buffer does not contain all bytes of server hello")
	}
	if hsh.ServerVersion, err = ReadProtocolVersion(buffer); err != nil {
		return
	}
	if hsh.Random, err = ReadRandom(buffer); err != nil {
		return
	}
	sessionIdLength, err := buffer.ReadByte()
	if err != nil {
		return
	}
	if buffer.Len() < int(sessionIdLength) {
		return hsh, InvalidHandshakeError
	}
	hsh.SessionID = buffer.Next(int(sessionIdLength))
	if hsh.CipherSuite, err = ReadCipherSuite(buffer); err != nil {
		return
	}
	if hsh.CompressionMethod, err = ReadCompressionMethod(buffer); err != nil {
		return
	}
	if buffer.Len() > 2 {
		// TODO: does this field exist if there are no extensions?
		numExtensions := ReadUint16(buffer)
		hsh.Extensions = make([]Extension, int(numExtensions))
		for i := 0; i < int(numExtensions); i++ {
			if hsh.Extensions[i], err = ReadExtension(buffer); err != nil {
				return
			}
		}
	}
	return
}
