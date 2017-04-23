package dtls

import (
	"fmt"
)

type handshakeFinished struct {
	VerifyData []byte
}

func readHandshakeFinished(byts []byte) (f handshakeFinished, err error) {
	f.VerifyData = byts
	return
}

func (f handshakeFinished) Bytes() []byte {
	return f.VerifyData
}

func (f handshakeFinished) String() string {
	return fmt.Sprintf("Finished{ VerifyData: %x }", f.VerifyData)
}
