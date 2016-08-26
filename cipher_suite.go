package dtls

import (
	"errors"
)

type CipherSuite [2]byte

func ReadCipherSuite(high, low byte) (CipherSuite, error) {
	switch (CipherSuite{high, low}) {
	case TLS_NULL_WITH_NULL_NULL:
		return TLS_NULL_WITH_NULL_NULL, nil
	case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
		return TLS_DHE_RSA_WITH_AES_128_CBC_SHA, nil
	case TLS_DH_anon_WITH_AES_128_CBC_SHA:
		return TLS_DH_anon_WITH_AES_128_CBC_SHA, nil
	case TLS_DH_anon_WITH_AES_256_CBC_SHA256:
		return TLS_DH_anon_WITH_AES_256_CBC_SHA256, nil
	default:
		return TLS_NULL_WITH_NULL_NULL, InvalidCipherSuite
	}
}

var (
	TLS_NULL_WITH_NULL_NULL             CipherSuite = CipherSuite{0x0, 0x0}
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA                = CipherSuite{0x0, 0x33}
	TLS_DH_anon_WITH_AES_128_CBC_SHA                = CipherSuite{0x0, 0x34}
	TLS_DH_anon_WITH_AES_256_CBC_SHA256             = CipherSuite{0x0, 0x6d}
)

func (cs CipherSuite) Bytes() []byte {
	return cs[:]
}

func (cs CipherSuite) String() string {
	switch cs {
	case TLS_NULL_WITH_NULL_NULL:
		return "TLS_NULL_WITH_NULL_NULL"
	case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
	case TLS_DH_anon_WITH_AES_128_CBC_SHA:
		return "TLS_DH_anon_WITH_AES_128_CBC_SHA"
	case TLS_DH_anon_WITH_AES_256_CBC_SHA256:
		return "TLS_DH_anon_WITH_AES_256_CBC_SHA256"
	default:
		return "xxx"
	}
}

var InvalidCipherSuite = errors.New("Invalid cipher suite")
