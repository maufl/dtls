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
	return extensionType(readUint16(buffer)), nil
}

var InvalidExtensionTypeError = errors.New("Invalid extension type")

// Copied from https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
const (
	extensionServerName           extensionType = 0
	extensionMaxFragmentLength                  = 1
	extensionClientCertificateUrl               = 2
	extensionTrustedCAKeys                      = 3
	extensionTruncatedHMAC                      = 4
	extensionStatusRequest                      = 5
	extensionUserMapping                        = 6
	extensionClientAuthz                        = 7
	extensionServerAuthz                        = 8
	extensionCertType                           = 9
	extensionSupportedGroups                    = 10
	extensionECPointFormats                     = 11
	extensionSRP                                = 12
	extensionSignatureAlgorithms                = 13
	extensionUseSRTP                            = 14
	extensionHeartbeat                          = 15
	//TODO copy remaining extension types
)

type extension struct {
	Type extensionType
	Data []byte
}

var InvalidExtensionError = errors.New("Invalid extension")

func readExtension(buffer *bytes.Buffer) (e *extension, err error) {
	e = &extension{}
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
	buffer := make([]byte, 4+len(e.Data))
	binary.BigEndian.PutUint16(buffer[:2], uint16(e.Type))
	binary.BigEndian.PutUint16(buffer[2:4], uint16(len(e.Data)))
	copy(buffer[4:], e.Data)
	return buffer
}

var clientExtensionCertificateTypeOpenPGP = &extension{Type: extensionCertType, Data: []byte{1, 1}}
var clientExtensionCertificateTypeX509 = &extension{Type: extensionCertType, Data: []byte{1, 0}}
var clientExtensionCertificateTypeOpenPGPX509 = &extension{Type: extensionCertType, Data: []byte{2, 1, 0}}
var clientExtensionCertificateTypeX509OpenPGP = &extension{Type: extensionCertType, Data: []byte{2, 0, 1}}
var serverExtensionCertificateTypeOpenPGP = &extension{Type: extensionCertType, Data: []byte{1}}
var serverExtensionCertificateTypeX509 = &extension{Type: extensionCertType, Data: []byte{0}}
