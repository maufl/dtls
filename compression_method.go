package dtls

import (
	"errors"
)

type CompressionMethod byte

func (cm CompressionMethod) Bytes() []byte {
	return []byte{byte(cm)}
}

const (
	CompressionNone CompressionMethod = 0
)

func ReadCompressionMethod(b byte) (CompressionMethod, error) {
	if b == 0 {
		return CompressionNone, nil
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
