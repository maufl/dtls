package dtls

import (
	"errors"
)

type HandshakeFragmentList struct {
	MsgType    HandshakeType
	Length     uint32
	MessageSeq uint16
	Fragments  []*Handshake
}

func NewHandshakeFragmentList(h *Handshake) *HandshakeFragmentList {
	return &HandshakeFragmentList{
		MsgType:    h.MsgType,
		Length:     h.Length,
		MessageSeq: h.MessageSeq,
		Fragments:  []*Handshake{h},
	}
}

func (hfl *HandshakeFragmentList) InsertFragment(newHandshake *Handshake) error {
	if newHandshake.MsgType != hfl.MsgType ||
		newHandshake.Length != hfl.Length ||
		newHandshake.MessageSeq != hfl.MessageSeq {
		return errors.New("Received a handshake fragment which is incompatible with previous fragments")
	}
	for i, handshake := range hfl.Fragments {
		if handshake.FragmentOffset > newHandshake.FragmentOffset {
			hfl.InsertFragmentAt(newHandshake, i)
			return nil
		}
	}
	hfl.InsertFragmentAt(newHandshake, len(hfl.Fragments))
	return nil
}

func (hfl *HandshakeFragmentList) InsertFragmentAt(f *Handshake, i int) {
	hfl.Fragments = append(hfl.Fragments, nil)
	copy(hfl.Fragments[i+1:], hfl.Fragments[i:])
	hfl.Fragments[i] = f
}

func (hfl *HandshakeFragmentList) IsComplete() bool {
	offset := uint32(0)
	for _, handshake := range hfl.Fragments {
		if handshake.FragmentOffset <= offset {
			offset = handshake.FragmentOffset + handshake.FragmentLength
		} else {
			return false
		}
	}
	if offset == hfl.Length {
		return true
	}
	return false
}

func (hfl *HandshakeFragmentList) GetCompleteHandshake() *Handshake {
	h := &Handshake{
		MsgType:        hfl.MsgType,
		Length:         hfl.Length,
		MessageSeq:     hfl.MessageSeq,
		FragmentOffset: 0,
		FragmentLength: hfl.Length,
		Fragment:       make([]byte, hfl.Length),
	}
	for _, handshake := range hfl.Fragments {
		copy(h.Fragment[handshake.FragmentOffset:], handshake.Fragment)
	}
	return h
}
