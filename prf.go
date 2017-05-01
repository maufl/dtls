// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dtls

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"hash"
)

// Split a premaster secret in two as specified in RFC 4346, section 5.
func splitPreMasterSecret(secret []byte) (s1, s2 []byte) {
	s1 = secret[0 : (len(secret)+1)/2]
	s2 = secret[len(secret)/2:]
	return
}

// pHash implements the P_hash function, as defined in RFC 4346, section 5.
func pHash(result, secret, seed []byte, hash func() hash.Hash) {
	h := hmac.New(hash, secret)
	h.Write(seed)
	a := h.Sum(nil)

	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		todo := len(b)
		if j+todo > len(result) {
			todo = len(result) - j
		}
		copy(result[j:j+todo], b)
		j += todo

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}

// pRF10 implements the TLS 1.0 pseudo-random function, as defined in RFC 2246, section 5.
func pRF10(result, secret, label, seed []byte) {
	hashSHA1 := sha1.New
	hashMD5 := md5.New

	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)

	s1, s2 := splitPreMasterSecret(secret)
	pHash(result, s1, labelAndSeed, hashMD5)
	result2 := make([]byte, len(result))
	pHash(result2, s2, labelAndSeed, hashSHA1)

	for i, b := range result2 {
		result[i] ^= b
	}
}

func pRF12(result, secret, label, seed []byte) {
	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)
	pHash(result, secret, labelAndSeed, sha256.New)
}

const (
	tlsRandomLength      = 32 // Length of a random nonce in TLS 1.1.
	masterSecretLength   = 48 // Length of a master secret in TLS 1.1.
	finishedVerifyLength = 12 // Length of verify_data in a Finished message.
)

var masterSecretLabel = []byte("master secret")
var keyExpansionLabel = []byte("key expansion")
var clientFinishedLabel = []byte("client finished")
var serverFinishedLabel = []byte("server finished")

// keysFromPreMasterSecret generates the connection keys from the pre master
// secret, given the lengths of the MAC key, cipher key and IV, as defined in
// RFC 2246, section 6.3.
func keysFromPreMasterSecret(version protocolVersion, preMasterSecret, clientRandom, serverRandom []byte, macLen, keyLen int) (masterSecret, clientMAC, serverMAC, clientKey, serverKey []byte) {
	prf := pRF10
	if version == DTLS_12 {
		prf = pRF12
	}

	var seed [tlsRandomLength * 2]byte
	copy(seed[0:len(clientRandom)], clientRandom)
	copy(seed[len(clientRandom):], serverRandom)
	masterSecret = make([]byte, masterSecretLength)
	prf(masterSecret, preMasterSecret, masterSecretLabel, seed[0:])

	copy(seed[0:len(clientRandom)], serverRandom)
	copy(seed[len(serverRandom):], clientRandom)

	n := 2*macLen + 2*keyLen
	keyMaterial := make([]byte, n)
	prf(keyMaterial, masterSecret, keyExpansionLabel, seed[0:])
	clientMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	serverMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	clientKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	serverKey = keyMaterial[:keyLen]
	return
}

func newFinishedHash() finishedHash {
	return finishedHash{Buffer: bytes.Buffer{}}
}

// A finishedHash calculates the hash of a set of handshake messages suitable
// for including in a Finished message.
type finishedHash struct {
	bytes.Buffer
}

// finishedSum10 calculates the contents of the verify_data member of a TLSv1
// Finished message given the MD5 and SHA1 hashes of a set of handshake
// messages.
func finishedSum10(md5, sha1, label, masterSecret []byte) []byte {
	seed := make([]byte, len(md5)+len(sha1))
	copy(seed, md5)
	copy(seed[len(md5):], sha1)
	out := make([]byte, finishedVerifyLength)
	pRF10(out, masterSecret, label, seed)
	return out
}

func finishedSum12(hash, label, masterSecret []byte) []byte {
	out := make([]byte, finishedVerifyLength)
	pRF12(out, masterSecret, label, hash)
	return out
}

// clientSum10 returns the contents of the verify_data member of a client's
// Finished message.
func (h finishedHash) clientSum10(masterSecret []byte) []byte {
	md5 := md5.New()
	md5.Write(h.Bytes())
	md5Digest := md5.Sum(nil)
	sha1 := sha1.New()
	sha1.Write(h.Bytes())
	sha1Digest := sha1.Sum(nil)
	return finishedSum10(md5Digest, sha1Digest, clientFinishedLabel, masterSecret)
}

// serverSum10 returns the contents of the verify_data member of a server's
// Finished message.
func (h finishedHash) serverSum10(masterSecret []byte) []byte {
	md5 := md5.New()
	md5.Write(h.Bytes())
	md5Digest := md5.Sum(nil)
	sha1 := sha1.New()
	sha1.Write(h.Bytes())
	sha1Digest := sha1.Sum(nil)
	return finishedSum10(md5Digest, sha1Digest, serverFinishedLabel, masterSecret)
}

func (h finishedHash) clientSum12(masterSecret []byte) []byte {
	sha256 := sha256.New()
	sha256.Write(h.Bytes())
	sha256Digest := sha256.Sum(nil)
	return finishedSum12(sha256Digest, clientFinishedLabel, masterSecret)
}

func (h finishedHash) serverSum12(masterSecret []byte) []byte {
	sha256 := sha256.New()
	sha256.Write(h.Bytes())
	sha256Digest := sha256.Sum(nil)
	return finishedSum12(sha256Digest, serverFinishedLabel, masterSecret)
}
