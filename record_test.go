package dtls

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestBuildRecordHeader(t *testing.T) {
	header := buildRecordHeader(typeHandshake, DTLS_10, 1, 4, 82)
	reference, err := hex.DecodeString("16feff00010000000000040052")
	if err != nil {
		t.Fatalf("Could not decode reference header: %s", err)
	}
	if !bytes.Equal(header, reference) {
		t.Errorf("BuildRecordHeader expexted to return %x but returned %x", reference, header)
	}
}
