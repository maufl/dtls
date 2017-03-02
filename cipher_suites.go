// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dtls

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
)

// A cipherSuite is a specific combination of key agreement, cipher and MAC
// function. All cipher suites currently assume RSA key agreement.
type CipherSuite struct {
	id uint16
	// the lengths, in bytes, of the key material needed for each component.
	keyLen       int
	macLen       int
	ivLen        int
	KeyAgreement func() KeyAgreement
	// If elliptic is set, a server will only consider this ciphersuite if
	// the ClientHello indicated that the client supports an elliptic curve
	// and point format that we can handle.
	elliptic bool
	cipher   func(key []byte) cipher.Block
	mac      func(macKey []byte) macFunction
}

var CipherSuites = []*CipherSuite{
	{TLS_DH_anon_WITH_AES_128_CBC_SHA, 16, 20, 16, dheKA, false, cipherAES, macSHA1},
	{TLS_DH_anon_WITH_AES_256_CBC_SHA256, 32, 32, 16, dheKA, false, cipherAES, macSHA256},
}

func (cs CipherSuite) Bytes() []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, cs.id)
	return b
}

func (cs CipherSuite) String() string {
	switch cs.id {
	case TLS_NULL_WITH_NULL_NULL:
		return "TLS_NULL_WITH_NULL_NULL"
	case TLS_DH_anon_WITH_AES_128_CBC_SHA:
		return "TLS_DH_anon_WITH_AES_128_CBC_SHA"
	case TLS_DH_anon_WITH_AES_256_CBC_SHA256:
		return "TLS_DH_anon_WITH_AES_256_CBC_SHA256"
	default:
		return "UNKNOWN_CIPHER_SUITE"
	}
}

func ReadCipherSuite(buffer *bytes.Buffer) (*CipherSuite, error) {
	id := binary.BigEndian.Uint16(buffer.Next(2))
	for _, cs := range CipherSuites {
		if cs.id == id {
			return cs, nil
		}
	}
	return &CipherSuite{}, InvalidCipherSuite
}

var InvalidCipherSuite = errors.New("Invalid cipher suite")

func dheKA() KeyAgreement {
	return new(DHEKeyAgreement)
}

func cipherAES(key []byte) cipher.Block {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return block
}

func macSHA1(key []byte) macFunction {
	return tls10MAC{hmac.New(sha1.New, key)}
}

func macSHA256(key []byte) macFunction {
	return tls10MAC{hmac.New(sha256.New, key)}
}

type macFunction interface {
	Size() int
	MAC(seq, typ, version, length, data []byte) []byte
}

// tls10MAC implements the TLS 1.0 MAC function. RFC 2246, section 6.2.3.
type tls10MAC struct {
	h hash.Hash
}

func (s tls10MAC) Size() int {
	return s.h.Size()
}

func (s tls10MAC) MAC(seq, typ, version, length, record []byte) []byte {
	s.h.Reset()
	s.h.Write(seq)
	s.h.Write(typ)
	s.h.Write(version)
	s.h.Write(length)
	s.h.Write(record)
	return s.h.Sum(nil)
}

// A list of the possible cipher suite ids. Taken from
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml
const (
	TLS_NULL_WITH_NULL_NULL             uint16 = 0x0
	TLS_DH_anon_WITH_AES_128_CBC_SHA           = 0x0034
	TLS_DH_anon_WITH_AES_256_CBC_SHA256        = 0x006d
)
