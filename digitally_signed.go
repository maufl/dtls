package dtls

import (
	"bytes"
)

const (
	hashAlgorithmNone   uint8 = 0
	hashAlgorithmMd5          = 1
	hashAlgorithmSha1         = 2
	hashAlgorithmSha224       = 3
	hashAlgorihtmSha256       = 4
	hashAlgorithmSha384       = 5
	hashAlgorithmSha512       = 6
)

const (
	signatureAlgorithmAnonymous uint8 = 0
	signatureAlgorithmRsa             = 1
	signatureAlgorithmDsa             = 2
	signatureAlgorithmEcdsa           = 3
)

type signatureAndHashAlgorithm struct {
	hash      uint8
	signature uint8
}

func readSignatureAndHashAlgorithm(buffer *bytes.Buffer) (sigAndHash signatureAndHashAlgorithm, err error) {
	sigAndHash.hash, err = buffer.ReadByte()
	if err != nil {
		return
	}
	sigAndHash.signature, err = buffer.ReadByte()
	return
}

type digitallySigned struct {
	algorithm signatureAndHashAlgorithm
	signature []byte
}

func readDigitallySigned(buffer *bytes.Buffer) (digisig digitallySigned, err error) {
	digisig.algorithm, err = readSignatureAndHashAlgorithm(buffer)
	if err != nil {
		return
	}
	signatureSize := int(readUint16(buffer))
	digisig.signature = buffer.Next(signatureSize)
	return
}
