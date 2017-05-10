package dtls

import (
	"bytes"
)

const (
	openpgpCertDescriptorTypeEmpty             uint8 = 1
	openpgpCertDescriptorTypeSubkey                  = 2
	openpgpCertDescriptorTypeSubkeyFingerprint       = 3
)

type openpgpSubkeyCert struct {
	keyId []byte
	cert  []byte
}

type openpgpSubkeyFingerprint struct {
	keyId       []byte
	fingerprint []byte
}

type openpgpCertificate struct {
	descriptorType    uint8
	subkeyCert        openpgpSubkeyCert
	subkeyFingerprint openpgpSubkeyFingerprint
}

func readOpenpgpCertificate(buffer *bytes.Buffer) (cert openpgpCertificate, err error) {
	cert.descriptorType, err = buffer.ReadByte()
	if err != nil {
		return
	}
	if cert.descriptorType == openpgpCertDescriptorTypeSubkey {
		keyIdSize, err := buffer.ReadByte()
		if err != nil {
			return cert, err
		}
		cert.subkeyCert.keyId = buffer.Next(int(keyIdSize))
		certSize, err := buffer.ReadByte()
		if err != nil {
			return cert, err
		}
		cert.subkeyCert.cert = buffer.Next(int(certSize))
	} else if cert.descriptorType == openpgpCertDescriptorTypeSubkeyFingerprint {
		keyIdSize, err := buffer.ReadByte()
		if err != nil {
			return cert, err
		}
		cert.subkeyFingerprint.keyId = buffer.Next(int(keyIdSize))
		fingerprintSize, err := buffer.ReadByte()
		if err != nil {
			return cert, err
		}
		cert.subkeyFingerprint.fingerprint = buffer.Next(int(fingerprintSize))
	}
	//TODO handle errors
	return
}
