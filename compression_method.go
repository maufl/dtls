package dtls

import (
	"bytes"
	"errors"
)

type CompressionMethod byte

func (cm CompressionMethod) Bytes() []byte {
	return []byte{byte(cm)}
}

const (
	CompressionNone CompressionMethod = 0
)

func ReadCompressionMethod(buffer *bytes.Buffer) (CompressionMethod, error) {
	if b, err := buffer.ReadByte(); err == nil && b == 0 {
		return CompressionNone, nil
	} else if err != nil {
		return 0, err
	}
	return 0, InvalidCompressionError
}

func (cm CompressionMethod) String() string {
	if cm == CompressionNone {
		return "None"
	}
	return "xxx"
}

var InvalidCompressionError = errors.New("Invalid compression")
