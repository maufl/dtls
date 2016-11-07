package dtls

type ChangeCipherSpec [1]byte

func (ccs ChangeCipherSpec) Bytes() []byte {
	return ccs[:]
}
