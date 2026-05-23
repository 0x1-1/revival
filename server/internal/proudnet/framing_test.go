package proudnet

import (
	"bytes"
	"testing"
)

func TestReadFrameGoleyPN32(t *testing.T) {
	raw := []byte{
		0x32, 0x18, 0x00, 0x00,
		0xad, 0x9a, 0x9e, 0x93, 0x45, 0x98, 0xb1, 0x9e,
		0x9b, 0x8d, 0xa6, 0x00, 0x24, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77, 0x88, 0x1d, 0x4c, 0x60,
		0xaa, 0xbb, 0xcc, 0xdd,
	}

	f, err := ReadFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadFrame returned error: %v", err)
	}
	if f.MsgType != 0x00 {
		t.Fatalf("MsgType = 0x%02x, want 0x00", f.MsgType)
	}
	if got, want := len(f.Body), 24; got != want {
		t.Fatalf("len(Body) = %d, want %d", got, want)
	}
	if f.Body[0] != 0xad || f.Body[23] != 0x60 {
		t.Fatalf("unexpected body boundaries: first=0x%02x last=0x%02x", f.Body[0], f.Body[23])
	}
}

func TestWriteFrameGoleyPN32(t *testing.T) {
	var buf bytes.Buffer
	body := []byte{0xde, 0xad, 0xbe, 0xef}
	if err := WriteFrame(&buf, MessageTypeRMI, body); err != nil {
		t.Fatalf("WriteFrame returned error: %v", err)
	}
	want := []byte{0x32, 0x04, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("frame bytes = % x, want % x", buf.Bytes(), want)
	}
}

func TestReadFrameRejectsBadMarker(t *testing.T) {
	raw := []byte{0x31, 0x00, 0x00, 0x00}
	if _, err := ReadFrame(bytes.NewReader(raw)); err == nil {
		t.Fatal("ReadFrame succeeded with a bad marker")
	}
}
