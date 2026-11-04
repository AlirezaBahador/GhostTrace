package decoder

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func validWire() []byte {
	b := make([]byte, WireSize)
	binary.LittleEndian.PutUint64(b[0:8], 123456789)
	binary.LittleEndian.PutUint32(b[8:12], 2345)
	binary.LittleEndian.PutUint32(b[12:16], 2345)
	binary.LittleEndian.PutUint32(b[16:20], 1000)
	binary.LittleEndian.PutUint32(b[20:24], 1001)
	binary.LittleEndian.PutUint32(b[24:28], KindExec)
	copy(b[32:48], "example")
	return b
}

func TestDecode(t *testing.T) {
	b := validWire()
	got, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.PID != 2345 || got.TID != 2345 || got.UID != 1000 || got.GID != 1001 || got.Comm != "example" || got.Kind != KindExec || got.MonotonicNS != 123456789 {
		t.Fatalf("unexpected decoded event: %+v", got)
	}
	b = validWire()
	binary.LittleEndian.PutUint32(b[24:28], KindExit)
	if got, err := Decode(b); err != nil || got.Kind != KindExit {
		t.Fatalf("exit: %+v %v", got, err)
	}
}

func TestDecodeRejectsMalformedRecords(t *testing.T) {
	tests := []struct {
		name  string
		alter func([]byte) []byte
	}{
		{"short", func(b []byte) []byte { return b[:WireSize-1] }},
		{"long", func(b []byte) []byte { return append(b, 0) }},
		{"pid zero", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[8:12], 0); return b }},
		{"tid zero", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[12:16], 0); return b }},
		{"bad type", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[24:28], 99); return b }},
		{"reserved", func(b []byte) []byte { b[31] = 1; return b }},
		{"non-leader exit", func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[24:28], KindExit)
			binary.LittleEndian.PutUint32(b[12:16], 567)
			return b
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Decode(tt.alter(validWire())); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("wanted ErrInvalidRecord; got %v", err)
			}
		})
	}
}

func TestCommTruncation(t *testing.T) {
	b := validWire()
	copy(b[32:48], strings.Repeat("A", 16))
	got, err := Decode(b)
	if err != nil || len(got.Comm) != 16 {
		t.Fatalf("got %q: %v", got.Comm, err)
	}
}
