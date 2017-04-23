package dtls

import (
	"bytes"
	"fmt"
)

type handshakeServerHelloDone struct{}

func readHandshakeServerHelloDone(buffer *bytes.Buffer) (handshakeServerHelloDone, error) {
	return handshakeServerHelloDone{}, nil
}

func (shd handshakeServerHelloDone) String() string {
	return fmt.Sprintf("ServerHelloDone{}")
}

func (shd handshakeServerHelloDone) Bytes() []byte {
	return []byte{}
}
