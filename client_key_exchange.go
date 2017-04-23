package dtls

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type clientDiffieHellmanPublic struct {
	PublicKey []byte
}

func readClientDiffieHellmanPublic(buffer *bytes.Buffer) (cdhp clientDiffieHellmanPublic, err error) {
	size := readUint16(buffer)
	cdhp.PublicKey = buffer.Next(int(size))
	return
}

func (cdhp clientDiffieHellmanPublic) String() string {
	return fmt.Sprintf("ClientDiffieHellmanPublic{ PublicKey: %x }", cdhp.PublicKey)
}

func (cdhp clientDiffieHellmanPublic) Bytes() []byte {
	buffer := make([]byte, 2+len(cdhp.PublicKey))
	binary.BigEndian.PutUint16(buffer, uint16(len(cdhp.PublicKey)))
	copy(buffer[2:], cdhp.PublicKey)
	return buffer
}

type handshakeClientKeyExchange struct {
	clientDiffieHellmanPublic
}

func readClientKeyExchange(data []byte) (ckx handshakeClientKeyExchange, err error) {
	buf := bytes.NewBuffer(data)
	params, err := readClientDiffieHellmanPublic(buf)
	if err != nil {
		return
	}
	return handshakeClientKeyExchange{
		clientDiffieHellmanPublic: params,
	}, nil
}

func (ckx handshakeClientKeyExchange) String() string {
	return fmt.Sprintf("ClientKeyExchange{ PublicKey: %v }", ckx.PublicKey)
}
