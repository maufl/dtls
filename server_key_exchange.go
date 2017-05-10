package dtls

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type serverDHParams struct {
	G         []byte
	P         []byte
	PublicKey []byte
}

func readServerDHParams(buffer *bytes.Buffer) (sdhp serverDHParams, err error) {
	pLength := readUint16(buffer)
	sdhp.P = buffer.Next(int(pLength))
	gLength := readUint16(buffer)
	sdhp.G = buffer.Next(int(gLength))
	pubKeyLength := readUint16(buffer)
	sdhp.PublicKey = buffer.Next(int(pubKeyLength))
	return
}

func (sdhp serverDHParams) String() string {
	return fmt.Sprintf("ServerDHParams{ G: %x, P: %x, PublicKey: %x }", sdhp.G, sdhp.P, sdhp.PublicKey)
}

func (sdhp serverDHParams) Bytes() []byte {
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

type handshakeServerKeyExchange struct {
	Params       serverDHParams
	SignedParams digitallySigned
}

func readHandshakeServerKeyExchange(byts []byte) (ske handshakeServerKeyExchange, err error) {
	buffer := bytes.NewBuffer(byts)
	if buffer.Len() == 0 {
		return
	}
	ske.Params, err = readServerDHParams(buffer)
	if err != nil {
		panic("Unparsable server key exchange message")
	}
	if buffer.Len() > 0 {
		ske.SignedParams, err = readDigitallySigned(buffer)
	}
	return
}

func (ske handshakeServerKeyExchange) String() string {
	return fmt.Sprintf("ServerKeyExchange{ Params: %s }", ske.Params)
}

func (ske handshakeServerKeyExchange) Bytes() []byte {
	return ske.Params.Bytes()
}
