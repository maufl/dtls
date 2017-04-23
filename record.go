package dtls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type contentType byte

const (
	typeChangeCipherSpec contentType = 20
	typeAlert                        = 21
	typeHandshake                    = 22
	typeApplicationData              = 23
)

func (ct contentType) Bytes() []byte {
	return []byte{byte(ct)}
}

func (t contentType) String() string {
	switch t {
	case typeChangeCipherSpec:
		return "ChangeCipherSpec"
	case typeAlert:
		return "Alert"
	case typeHandshake:
		return "Handshake"
	case typeApplicationData:
		return "ApplicationData"
	default:
		return "xxx"
	}
}

var ContentTypeError error = errors.New("Unknown content type")

func readContentType(buffer *bytes.Buffer) (ct contentType, err error) {
	b, err := buffer.ReadByte()
	if err != nil {
		return
	}
	switch b {
	case 20:
		return typeChangeCipherSpec, nil
	case 21:
		return typeAlert, nil
	case 22:
		return typeHandshake, nil
	case 23:
		return typeApplicationData, nil
	default:
		return 255, ContentTypeError
	}
}

type protocolVersion struct {
	major uint8
	minor uint8
}

var DTLS_10 = protocolVersion{major: 254, minor: 255}
var DTLS_12 = protocolVersion{major: 254, minor: 253}

func (v protocolVersion) String() string {
	switch v {
	case DTLS_10:
		return "1.0"
	case DTLS_12:
		return "1.2"
	default:
		return "x.x"
	}
}

func (v protocolVersion) Bytes() []byte {
	return []byte{v.major, v.minor}
}

var ProtocolVersionError error = errors.New("Unknown protocol version")

func readProtocolVersion(buffer *bytes.Buffer) (pv protocolVersion, err error) {
	if pv.major, err = buffer.ReadByte(); err != nil {
		return
	}
	if pv.minor, err = buffer.ReadByte(); err != nil {
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

type record struct {
	Type           contentType
	Version        protocolVersion
	Epoch          uint16
	SequenceNumber uint64
	Length         uint16
	Payload        []byte
}

func buildRecordHeader(typ contentType, version protocolVersion, epoch uint16, sequenceNumber uint64, length uint16) (header []byte) {
	header = make([]byte, 13)
	header[0] = byte(typ)
	copy(header[1:], version.Bytes())
	binary.BigEndian.PutUint64(header[3:], sequenceNumber)
	binary.BigEndian.PutUint16(header[3:], epoch)
	binary.BigEndian.PutUint16(header[11:], length)
	return
}

func (r record) Bytes() []byte {
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
	return append(buffer.Bytes(), r.Payload...)
}

var InvalidRecordError = errors.New("InvalidRecord")

func readRecord(buffer *bytes.Buffer) (r *record, err error) {
	r = &record{}
	if buffer.Len() < 13 {
		return r, InvalidRecordError
	}
	if r.Type, err = readContentType(buffer); err != nil {
		return
	}
	if r.Version, err = readProtocolVersion(buffer); err != nil {
		return
	}
	r.Epoch = readUint16(buffer)
	r.SequenceNumber = readUint48(buffer)
	r.Length = readUint16(buffer)
	if buffer.Len() < int(r.Length) {
		return r, InvalidRecordError
	}
	r.Payload = buffer.Next(int(r.Length))
	return
}

func (r record) String() string {
	return fmt.Sprintf("Record{ Type: %s, ProtocolVersion: %s, Epoch: %d, SequenceNumber: %d, Length: %d, \n\t%s\n }", r.Type, r.Version, r.Epoch, r.SequenceNumber, r.Length, r.Payload)
}
