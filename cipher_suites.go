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
type cipherSuite struct {
	id cipherSuiteId
	// the lengths, in bytes, of the key material needed for each component.
	keyLen       int
	macLen       int
	ivLen        int
	KeyAgreement func() keyAgreement
	// If elliptic is set, a server will only consider this ciphersuite if
	// the ClientHello indicated that the client supports an elliptic curve
	// and point format that we can handle.
	signedKeyExchange bool
	elliptic          bool
	cipher            func(key []byte) cipher.Block
	mac               func(macKey []byte) macFunction
}

var cipherSuites = []*cipherSuite{
	{TLS_DH_anon_WITH_AES_128_CBC_SHA, 16, 20, 16, dheKA, false, false, cipherAES, macSHA1},
	{TLS_DH_anon_WITH_AES_256_CBC_SHA256, 32, 32, 16, dheKA, false, false, cipherAES, macSHA256},
	{TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, 32, 32, 16, dheKA, true, false, cipherAES, macSHA256},
	{TLS_DHE_RSA_WITH_AES_256_CBC_SHA, 32, 32, 16, dheKA, true, false, cipherAES, macSHA1},
}

func (cs cipherSuite) Bytes() []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(cs.id))
	return b
}

func (cs cipherSuite) String() string {
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

func readCipherSuite(buffer *bytes.Buffer) (*cipherSuite, error) {
	id := binary.BigEndian.Uint16(buffer.Next(2))
	for _, cs := range cipherSuites {
		if uint16(cs.id) == id {
			return cs, nil
		}
	}
	return &cipherSuite{}, InvalidCipherSuite
}

var InvalidCipherSuite = errors.New("Invalid cipher suite")

func dheKA() keyAgreement {
	return new(dheKeyAgreement)
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
