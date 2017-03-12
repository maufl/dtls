package dtls

import (
	"bytes"
	"testing"
)

func TestHandshakeFragmentList(t *testing.T) {
	h1 := &Handshake{ServerKeyExchange, 30, 2, 0, 15, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}}
	h2 := &Handshake{ServerKeyExchange, 30, 2, 20, 5, []byte{20, 21, 22, 23, 24}}
	h3 := &Handshake{ServerKeyExchange, 30, 2, 10, 10, []byte{10, 11, 12, 13, 14, 15, 16, 17, 18, 19}}
	h4 := &Handshake{ServerKeyExchange, 30, 2, 25, 5, []byte{25, 26, 27, 28, 29}}

	hfl := NewHandshakeFragmentList(h1)
	err := hfl.InsertFragment(h2)
	if err != nil {
		t.Errorf("Insert handshake %+v failed: %s", h2, err)
	}
	if hfl.IsComplete() {
		t.Errorf("Handshake fragment list reports completion, but thats not possible")
	}
	err = hfl.InsertFragment(h3)
	if err != nil {
		t.Errorf("Insert handshake %+v failed: %s", h3, err)
	}
	if hfl.IsComplete() {
		t.Errorf("Handshake fragment list reports completion, but thats not possible")
	}
	err = hfl.InsertFragment(h4)
	if err != nil {
		t.Errorf("Insert handshake %+v failed: %s", h4, err)
	}
	if !hfl.IsComplete() {
		t.Errorf("Handshake fragment list reports not complete, but should be complete")
	}
	h := hfl.GetCompleteHandshake()
	if h.MsgType != ServerKeyExchange {
		t.Errorf("Completed handshake has unexpected msg type %+v, expected is", h.MsgType, ServerKeyExchange)
	}
	if h.Length != 30 {
		t.Errorf("Completed handshake has unexpected length %d, expected is 30", h.Length, 30)
	}
	if h.MessageSeq != 2 {
		t.Errorf("Completed handshake has unexpected message seq %d, expected is %d", h.MessageSeq, 2)
	}
	if h.FragmentOffset != 0 {
		t.Errorf("Completed handshake has unexpected fragment offset %d, expected is %d", h.FragmentOffset, 0)
	}
	if h.FragmentLength != 30 {
		t.Errorf("Completed handshake has unexpected fragment length %d, expected is %d", h.FragmentLength, 30)
	}
	expected := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29}
	if !bytes.Equal(h.Fragment, expected) {
		t.Errorf("Completed handshake has unexpected fragment content %x,\nexpected is %x", h.Fragment, expected)
	}
}
