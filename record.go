package dtls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type ContentType byte

const (
	TypeChangeCipherSpec ContentType = 20
	TypeAlert                        = 21
	TypeHandshake                    = 22
	TypeApplicationData              = 23
)

func (ct ContentType) Bytes() []byte {
	return []byte{byte(ct)}
}

func (t ContentType) String() string {
	switch t {
	case TypeChangeCipherSpec:
		return "ChangeCipherSpec"
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

func ReadContentType(buffer *bytes.Buffer) (ct ContentType, err error) {
	b, err := buffer.ReadByte()
	if err != nil {
		return
	}
	switch b {
	case 20:
		return TypeChangeCipherSpec, nil
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

func ReadProtocolVersion(buffer *bytes.Buffer) (pv ProtocolVersion, err error) {
	if pv.Major, err = buffer.ReadByte(); err != nil {
		return
	}
	if pv.Minor, err = buffer.ReadByte(); err != nil {
		return
	}
	switch pv {
	case DTLS_12:
		return DTLS_12, nil
	case DTLS_10:
		return DTLS_10, nil
	default:
		return pv, ProtocolVersionError
	}
}

type Record struct {
	Type           ContentType
	Version        ProtocolVersion
	Epoch          uint16
	SequenceNumber uint64
	Length         uint16
	Payload        ToBytes
	PayloadRaw     []byte
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
	if r.PayloadRaw == nil {
		r.PayloadRaw = r.Payload.Bytes()
	}
	return append(buffer.Bytes(), r.PayloadRaw...)
}

var InvalidRecordError = errors.New("InvalidRecord")

func ReadRecord(buffer *bytes.Buffer) (r Record, err error) {
	if buffer.Len() < 13 {
		return r, errors.New("Not enough bytes to read header")
	}
	if r.Type, err = ReadContentType(buffer); err != nil {
		return
	}
	if r.Version, err = ReadProtocolVersion(buffer); err != nil {
		return
	}
	r.Epoch = ReadUint16(buffer)
	r.SequenceNumber = ReadUint48(buffer)
	r.Length = ReadUint16(buffer)
	if buffer.Len() < int(r.Length) {
		return r, InvalidRecordError
	}
	switch r.Type {
	case TypeHandshake:
		r.Payload, err = ReadHandshake(buffer)
	case TypeApplicationData:
		r.PayloadRaw = buffer.Bytes()
	default:
		return r, InvalidRecordError
	}
	return
}

func (r Record) String() string {
	return fmt.Sprintf("Record{ Type: %s, ProtocolVersion: %s, Epoch: %d, SequenceNumber: %d, Length: %d, \n\t%s\n }", r.Type, r.Version, r.Epoch, r.SequenceNumber, r.Length, r.Payload)
}
