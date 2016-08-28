package dtls

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
)

type Random struct {
	GMTUnixTime time.Time
	Opaque      [28]byte
}

func NewRandom() (r Random) {
	r.GMTUnixTime = time.Now().UTC()
	if _, err := rand.Read(r.Opaque[:]); err != nil {
		panic(err)
	}
	return
}

func ReadRandom(buffer *bytes.Buffer) (r Random, err error) {
	if buffer.Len() < 32 {
		return r, InvalidHandshakeError
	}
	t := ReadUint32(buffer)
	r.GMTUnixTime = time.Unix(int64(t), 0)
	copy(r.Opaque[:], buffer.Next(28))
	return
}

func (r Random) String() string {
	return fmt.Sprintf("Random{ UnixTime: %s, Opaque: %x }", r.GMTUnixTime, r.Opaque)
}

func (r Random) Bytes() []byte {
	buffer := make([]byte, 4)
	binary.BigEndian.PutUint32(buffer, uint32(r.GMTUnixTime.Unix()))
	return append(buffer, r.Opaque[:]...)
}
