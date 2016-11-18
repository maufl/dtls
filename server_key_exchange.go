package dtls

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type ServerDHParams struct {
	G         []byte
	P         []byte
	PublicKey []byte
}

func ReadServerDHParams(buffer *bytes.Buffer) (sdhp ServerDHParams, err error) {
	pLength := ReadUint16(buffer)
	sdhp.P = buffer.Next(int(pLength))
	gLength := ReadUint16(buffer)
	sdhp.G = buffer.Next(int(gLength))
	pubKeyLength := ReadUint16(buffer)
	sdhp.PublicKey = buffer.Next(int(pubKeyLength))
	return
}

func (sdhp ServerDHParams) String() string {
	return fmt.Sprintf("ServerDHParams{ G: %x, P: %x, PublicKey: %x }", sdhp.G, sdhp.P, sdhp.PublicKey)
}

func (sdhp ServerDHParams) Bytes() []byte {
	buffer := &bytes.Buffer{}
	t := make([]byte, 2)
	binary.BigEndian.PutUint16(t, uint16(len(sdhp.P)))
	buffer.Write(t)
	buffer.Write(sdhp.P)
	t = make([]byte, 2)
	binary.BigEndian.PutUint16(t, uint16(len(sdhp.G)))
	buffer.Write(t)
	buffer.Write(sdhp.G)
	t = make([]byte, 2)
	binary.BigEndian.PutUint16(t, uint16(len(sdhp.PublicKey)))
	buffer.Write(t)
	buffer.Write(sdhp.PublicKey)
	return buffer.Bytes()
}

type HandshakeServerKeyExchange struct {
	Params ServerDHParams
}

func ReadHandshakeServerKeyExchange(buffer *bytes.Buffer) (ske HandshakeServerKeyExchange, err error) {
	ske.Params, err = ReadServerDHParams(buffer)
	if err != nil {
		panic("Unparsable server key exchange message")
	}
	return
}

func (ske HandshakeServerKeyExchange) String() string {
	return fmt.Sprintf("ServerKeyExchange{ Params: %s }", ske.Params)
}

func (ske HandshakeServerKeyExchange) Bytes() []byte {
	return ske.Params.Bytes()
}
