package dtls

import (
	"bytes"
	"encoding/binary"
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
	buffer := make([]byte, 2+len(cdhp.PublicKey))
	binary.BigEndian.PutUint16(buffer, uint16(len(cdhp.PublicKey)))
	copy(buffer[2:], cdhp.PublicKey)
	return buffer
}

type HandshakeClientKeyExchange struct {
	ClientDiffieHellmanPublic
}

func (ckx HandshakeClientKeyExchange) String() string {
	return fmt.Sprintf("ClientKeyExchange{ PublicKey: %v }", ckx.PublicKey)
}
