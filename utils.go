package dtls

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type toBytes interface {
	Bytes() []byte
}

var InsufficentBytesError = errors.New("Insufficent bytes in buffer")

func readUint16(buffer *bytes.Buffer) uint16 {
	t := buffer.Next(2)
	return binary.BigEndian.Uint16(t)
}

func readUint24(buffer *bytes.Buffer) uint32 {
	t := buffer.Next(3)
	return binary.BigEndian.Uint32(append([]byte{0}, t...))
}

func readUint32(buffer *bytes.Buffer) uint32 {
	t := buffer.Next(4)
	return binary.BigEndian.Uint32(t)
}

func readUint48(buffer *bytes.Buffer) uint64 {
	t := buffer.Next(6)
	return binary.BigEndian.Uint64(append([]byte{0, 0}, t...))
}
