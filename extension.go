package dtls

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type ExtensionType uint16

func (et ExtensionType) Bytes() []byte {
	buffer := make([]byte, 2)
	binary.BigEndian.PutUint16(buffer, uint16(et))
	return buffer
}

func ReadExtensionType(buffer *bytes.Buffer) (ExtensionType, error) {
	n := ReadUint16(buffer)
	switch n {
	case 13:
		return ExtensionSignatureAlgorithms, nil
	default:
		return 0, InvalidExtensionTypeError
	}
}

var InvalidExtensionTypeError = errors.New("Invalid extension type")

const (
	ExtensionSignatureAlgorithms ExtensionType = 13
)

type Extension struct {
	Type ExtensionType
	Data []byte
}

var InvalidExtensionError = errors.New("Invalid extension")

func ReadExtension(buffer *bytes.Buffer) (e Extension, err error) {
	if buffer.Len() < 4 {
		return e, InvalidExtensionError
	}
	if e.Type, err = ReadExtensionType(buffer); err != nil {
		return
	}
	dataSize := int(ReadUint16(buffer))
	if buffer.Len() < dataSize {
		return e, InvalidExtensionError
	}
	e.Data = buffer.Next(dataSize)
	return
}

func (e Extension) Bytes() []byte {
	buffer := bytes.Buffer{}
	buffer.Write(e.Type.Bytes())
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(len(e.Data)))
	buffer.Write(b)
	buffer.Write(e.Data)
	return buffer.Bytes()
}

func (e Extension) Consumes() uint {
	return uint(4 + len(e.Data))
}
