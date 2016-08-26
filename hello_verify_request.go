package dtls

import (
	"fmt"
)

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
