// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dtls

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
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
func keysFromPreMasterSecret(preMasterSecret, clientRandom, serverRandom []byte, macLen, keyLen int) (masterSecret, clientMAC, serverMAC, clientKey, serverKey []byte) {
	prf := pRF10

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
	return finishedHash{md5.New(), sha1.New(), md5.New(), sha1.New()}
}

// A finishedHash calculates the hash of a set of handshake messages suitable
// for including in a Finished message.
type finishedHash struct {
	clientMD5  hash.Hash
	clientSHA1 hash.Hash
	serverMD5  hash.Hash
	serverSHA1 hash.Hash
}

func (h finishedHash) Write(msg []byte) (n int, err error) {
	h.clientMD5.Write(msg)
	h.clientSHA1.Write(msg)
	h.serverMD5.Write(msg)
	h.serverSHA1.Write(msg)
	return len(msg), nil
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

// clientSum returns the contents of the verify_data member of a client's
// Finished message.
func (h finishedHash) clientSum(masterSecret []byte) []byte {
	md5 := h.clientMD5.Sum(nil)
	sha1 := h.clientSHA1.Sum(nil)
	return finishedSum10(md5, sha1, clientFinishedLabel, masterSecret)
}

// serverSum returns the contents of the verify_data member of a server's
// Finished message.
func (h finishedHash) serverSum(masterSecret []byte) []byte {
	md5 := h.serverMD5.Sum(nil)
	sha1 := h.serverSHA1.Sum(nil)
	return finishedSum10(md5, sha1, serverFinishedLabel, masterSecret)
}
