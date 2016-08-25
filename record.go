package dtls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type ContentType byte

const (
	TypeChangeChiperSpec ContentType = 20
	TypeAlert                        = 21
	TypeHandshake                    = 22
	TypeApplicationData              = 23
)

func (ct ContentType) Bytes() []byte {
	return []byte{byte(ct)}
}

func (t ContentType) String() string {
	switch t {
	case TypeChangeChiperSpec:
		return "ChangeChiperSpec"
	case TypeAlert:
		return "Alert"
	case TypeHandshake:
		return "Handshake"
	case TypeApplicationData:
		return "ApplicationData"
	default:
		return "xxx"
	}
}

var ContentTypeError error = errors.New("Unknown content type")

func ReadContentType(b byte) (ContentType, error) {
	switch b {
	case 20:
		return TypeChangeChiperSpec, nil
	case 21:
		return TypeAlert, nil
	case 22:
		return TypeHandshake, nil
	case 23:
		return TypeApplicationData, nil
	default:
		return 255, ContentTypeError
	}
}

type ProtocolVersion struct {
	Major uint8
	Minor uint8
}

var DTLS_10 = ProtocolVersion{Major: 254, Minor: 255}
var DTLS_12 = ProtocolVersion{Major: 254, Minor: 253}

func (v ProtocolVersion) String() string {
	switch v {
	case DTLS_10:
		return "1.0"
	case DTLS_12:
		return "1.2"
	default:
		return "x.x"
	}
}

func (v ProtocolVersion) Bytes() []byte {
	return []byte{v.Major, v.Minor}
}

var ProtocolVersionError error = errors.New("Unknown protocol version")

func ReadProtocolVersion(maj, min byte) (ProtocolVersion, error) {
	if maj == 254 && min == 253 {
		return DTLS_12, nil
	} else if maj == 254 && min == 255 {
		return DTLS_10, nil
	}
	return ProtocolVersion{}, ProtocolVersionError
}

type Record struct {
	Type           ContentType
	Version        ProtocolVersion
	Epoch          uint16
	SequenceNumber uint64
	Length         uint16
	Fragment       []byte
	ParsedFragment interface{}
}

func (r Record) Bytes() []byte {
	buffer := bytes.Buffer{}
	buffer.Write(r.Type.Bytes())
	buffer.Write(r.Version.Bytes())
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, r.Epoch)
	buffer.Write(b)
	b = make([]byte, 8)
	binary.BigEndian.PutUint64(b, r.SequenceNumber)
	buffer.Write(b[2:])
	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, r.Length)
	buffer.Write(b)
	return append(buffer.Bytes(), r.Fragment...)
}

var InvalidRecord error = errors.New("InvalidRecord")

func ReadRecord(buffer []byte) (r Record, e error) {
	if len(buffer) < 13 {
		return r, InvalidRecord
	}
	t, err := ReadContentType(buffer[0])
	if err != nil {
		return r, err
	}
	r.Type = t
	v, err := ReadProtocolVersion(buffer[1], buffer[2])
	if err != nil {
		return r, err
	}
	r.Version = v
	r.Epoch = binary.BigEndian.Uint16(buffer[3:5])
	r.SequenceNumber = binary.BigEndian.Uint64(append([]byte{0, 0}, buffer[5:11]...))
	r.Length = binary.BigEndian.Uint16(buffer[11:13])
	if len(buffer) < int(r.Length)+13 {
		return r, InvalidRecord
	}
	r.Fragment = buffer[13:]
	return r, nil
}

func (r Record) String() string {
	return fmt.Sprintf("Record{ Type: %s, ProtocolVersion: %s, Epoch: %d, SequenceNumber: %d, Length: %d, \n\t%s\n }", r.Type, r.Version, r.Epoch, r.SequenceNumber, r.Length, r.ParsedFragment)
}
