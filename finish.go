package dtls

import (
	"bytes"
	"fmt"
)

type HandshakeFinished struct {
	VerifyData []byte
}

func ReadHandshakeFinished(buffer *bytes.Buffer) (f HandshakeFinished, err error) {
	copy(f.VerifyData, buffer.Bytes())
	return
}

func (f HandshakeFinished) Bytes() []byte {
	return f.VerifyData
}

func (f HandshakeFinished) String() string {
	return fmt.Sprintf("Finished{ VerifyData: %x }", f.VerifyData)
}
