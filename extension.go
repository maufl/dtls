package dtls

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type extensionType uint16

func (et extensionType) Bytes() []byte {
	buffer := make([]byte, 2)
	binary.BigEndian.PutUint16(buffer, uint16(et))
	return buffer
}

func readExtensionType(buffer *bytes.Buffer) (extensionType, error) {
	n := readUint16(buffer)
	switch n {
	case 13:
		return ExtensionSignatureAlgorithms, nil
	default:
		return 0, InvalidExtensionTypeError
	}
}

var InvalidExtensionTypeError = errors.New("Invalid extension type")

const (
	ExtensionSignatureAlgorithms extensionType = 13
)

type extension struct {
	Type extensionType
	Data []byte
}

var InvalidExtensionError = errors.New("Invalid extension")

func readExtension(buffer *bytes.Buffer) (e extension, err error) {
	if buffer.Len() < 4 {
		return e, InvalidExtensionError
	}
	if e.Type, err = readExtensionType(buffer); err != nil {
		return
	}
	dataSize := int(readUint16(buffer))
	if buffer.Len() < dataSize {
		return e, InvalidExtensionError
	}
	e.Data = buffer.Next(dataSize)
	return
}

func (e extension) Bytes() []byte {
	buffer := bytes.Buffer{}
	buffer.Write(e.Type.Bytes())
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(len(e.Data)))
	buffer.Write(b)
	buffer.Write(e.Data)
	return buffer.Bytes()
}

func (e extension) Consumes() uint {
	return uint(4 + len(e.Data))
}
