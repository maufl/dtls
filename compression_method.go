package dtls

import (
	"bytes"
	"errors"
)

type compressionMethod byte

func (cm compressionMethod) Bytes() []byte {
	return []byte{byte(cm)}
}

const (
	compressionNone compressionMethod = 0
)

func readCompressionMethod(buffer *bytes.Buffer) (compressionMethod, error) {
	if b, err := buffer.ReadByte(); err == nil && b == 0 {
		return compressionNone, nil
	} else if err != nil {
		return 0, err
	}
	return 0, InvalidCompressionError
}

func (cm compressionMethod) String() string {
	if cm == compressionNone {
		return "None"
	}
	return "xxx"
}

var InvalidCompressionError = errors.New("Invalid compression")
