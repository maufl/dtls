package dtls

import (
	"bytes"
	"fmt"
)

type HandshakeServerHelloDone struct{}

func ReadHandshakeServerHelloDone(buffer *bytes.Buffer) (HandshakeServerHelloDone, error) {
	return HandshakeServerHelloDone{}, nil
}

func (shd HandshakeServerHelloDone) String() string {
	return fmt.Sprintf("ServerHelloDone{}")
}

func (shd HandshakeServerHelloDone) Bytes() []byte {
	return []byte{}
}
