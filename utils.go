package dtls

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type ToBytes interface {
	Bytes() []byte
}

var InsufficentBytesError = errors.New("Insufficent bytes in buffer")

func ReadUint16(buffer *bytes.Buffer) uint16 {
	t := buffer.Next(2)
	return binary.BigEndian.Uint16(t)
}

func ReadUint24(buffer *bytes.Buffer) uint32 {
	t := buffer.Next(3)
	return binary.BigEndian.Uint32(append([]byte{0}, t...))
}

func ReadUint32(buffer *bytes.Buffer) uint32 {
	t := buffer.Next(4)
	return binary.BigEndian.Uint32(t)
}

func ReadUint48(buffer *bytes.Buffer) uint64 {
	t := buffer.Next(6)
	return binary.BigEndian.Uint64(append([]byte{0, 0}, t...))
}
