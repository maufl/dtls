package dtls

import (
	"bytes"
	"errors"
	"fmt"
)

type handshakeServerHello struct {
	ServerVersion     protocolVersion
	Random            random
	SessionID         []byte
	CipherSuite       *cipherSuite
	CompressionMethod compressionMethod
	Extensions        []*extension
}

func (sh handshakeServerHello) String() string {
	return fmt.Sprintf("ServerHello{ ServerVersion: %s, Random: %s, SessionID: %x, CipherSuite: %s, CompressionMethod: %s }", sh.ServerVersion, sh.Random, sh.SessionID, sh.CipherSuite, sh.CompressionMethod)
}

func (sh handshakeServerHello) Bytes() []byte {
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

func readHandshakeServerHello(byts []byte) (hsh handshakeServerHello, err error) {
	buffer := bytes.NewBuffer(byts)
	if buffer.Len() < 35 {
		return hsh, errors.New("Buffer does not contain all bytes of server hello")
	}
	if hsh.ServerVersion, err = readProtocolVersion(buffer); err != nil {
		return
	}
	if hsh.Random, err = readRandom(buffer); err != nil {
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
	if hsh.CipherSuite, err = readCipherSuite(buffer); err != nil {
		return
	}
	if hsh.CompressionMethod, err = readCompressionMethod(buffer); err != nil {
		return
	}
	if buffer.Len() > 2 {
		// TODO: does this field exist if there are no extensions?
		sizeExtensions := int(readUint16(buffer))
		if buffer.Len() != sizeExtensions {
			// TODO alert decode error
		}
		hsh.Extensions = make([]*extension, 0)
		for buffer.Len() > 0 {
			extension, err := readExtension(buffer)
			if err != nil {
				//TODO alert decode error
			}
			hsh.Extensions = append(hsh.Extensions, extension)
		}
	}
	return
}
