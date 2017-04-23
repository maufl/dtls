package dtls

type changeCipherSpec [1]byte

func (ccs changeCipherSpec) Bytes() []byte {
	return ccs[:]
}
