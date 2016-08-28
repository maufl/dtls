package dtls

import (
	"bytes"
	"fmt"
)

type ClientDiffieHellmanPublic struct {
	PublicKey []byte
}

func ReadClientDiffieHellmanPublic(buffer *bytes.Buffer) (cdhp ClientDiffieHellmanPublic, err error) {
	size := ReadUint16(buffer)
	cdhp.PublicKey = buffer.Next(int(size))
	return
}

func (cdhp ClientDiffieHellmanPublic) String() string {
	return fmt.Sprintf("ClientDiffieHellmanPublic{ PublicKey: %x }", cdhp.PublicKey)
}

func (cdhp ClientDiffieHellmanPublic) Bytes() []byte {
	buffer := &bytes.Buffer{}
	return buffer.Bytes()
}

type HandshakeClientKeyExchange struct {
	ClientDiffieHellmanPublic
}
