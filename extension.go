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

func ReadExtensionType(buffer []byte) (ExtensionType, error) {
	if len(buffer) != 2 {
		panic("Called ReadExtensionType with wrongly sized buffer")
	}
	n := binary.BigEndian.Uint16(buffer)
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

func ReadExtension(buffer []byte) (e Extension, err error) {
	if len(buffer) < 4 {
		return e, InvalidExtensionError
	}
	if e.Type, err = ReadExtensionType(buffer[:2]); err != nil {
		return
	}
	dataSize := int(binary.BigEndian.Uint16(buffer[2:4]))
	if len(buffer) < 4+dataSize {
		return e, InvalidExtensionError
	}
	e.Data = buffer[4:dataSize]
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
