package dtls

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	_ "fmt"
	_ "log"
	"testing"
)

var clientKey []byte = hexToBytes("4429aea63f088bdfbcc832a21d0520dd")
var iv []byte = hexToBytes("156456914959a31c6cc84b25842d8a1c")

var payload []byte = hexToBytes("1400000c000300000000000c34f515344a87344e69bc3275b3faa0f20791e46dfeb410edefb283add5aa2867")
var padded []byte = hexToBytes("1400000c000300000000000c34f515344a87344e69bc3275b3faa0f20791e46dfeb410edefb283add5aa286703030303")
var encrypted []byte = hexToBytes("156456914959a31c6cc84b25842d8a1c10535e811aeb930fb7975847bb3ec015dd10e7af381f78d12f4d9fccd7ff025cd19000530d2808c8cc8e3657215ce605")

func TestEncryptRecord(t *testing.T) {
	ciph, err := aes.NewCipher(clientKey)
	if err != nil {
		panic(err)
	}
	blockSize := ciph.BlockSize()
	if !bytes.Equal(padToBlockSize(payload, blockSize), padded) {
		t.Errorf("padToBlockSize not working as expected")
	}
	result := make([]byte, len(padded)+len(iv))
	copy(result, iv)
	mode := cipher.NewCBCEncrypter(ciph, iv)
	mode.CryptBlocks(result[len(iv):], padded)
	if !bytes.Equal(result, encrypted) {
		t.Errorf("encryption not working as expected")
	}

}

func hexToBytes(h string) (b []byte) {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err.Error())
	}
	return
}
