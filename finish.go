package dtls

import (
	"fmt"
)

type HandshakeFinished struct {
	VerifyData []byte
}

func ReadHandshakeFinished(byts []byte) (f HandshakeFinished, err error) {
	f.VerifyData = byts
	return
}

func (f HandshakeFinished) Bytes() []byte {
	return f.VerifyData
}

func (f HandshakeFinished) String() string {
	return fmt.Sprintf("Finished{ VerifyData: %x }", f.VerifyData)
}
