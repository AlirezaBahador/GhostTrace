// Package decoder defines the version-one binary protocol emitted by eBPF.
package decoder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const WireSize = 48

const (
	KindExec uint32 = 1
	KindExit uint32 = 2
)

var ErrInvalidRecord = errors.New("invalid kernel process record")

// ProcessRecord contains only kernel-collected fields, not userspace enrichment.
type ProcessRecord struct {
	MonotonicNS uint64
	PID         uint32
	TID         uint32
	UID         uint32
	GID         uint32
	Kind        uint32
	Comm        string
}

// Decode accepts only the exact v1 little-endian 48-byte wire layout.
// Supported target architectures are linux/amd64 and linux/arm64.
func Decode(data []byte) (ProcessRecord, error) {
	if len(data) != WireSize {
		return ProcessRecord{}, fmt.Errorf("%w: size %d, want %d", ErrInvalidRecord, len(data), WireSize)
	}
	r := ProcessRecord{
		MonotonicNS: binary.LittleEndian.Uint64(data[0:8]),
		PID:         binary.LittleEndian.Uint32(data[8:12]),
		TID:         binary.LittleEndian.Uint32(data[12:16]),
		UID:         binary.LittleEndian.Uint32(data[16:20]),
		GID:         binary.LittleEndian.Uint32(data[20:24]),
		Kind:        binary.LittleEndian.Uint32(data[24:28]),
		Comm:        string(bytes.TrimRight(data[32:48], "\x00")),
	}
	if binary.LittleEndian.Uint32(data[28:32]) != 0 {
		return ProcessRecord{}, fmt.Errorf("%w: nonzero reserved bits", ErrInvalidRecord)
	}
	if r.PID == 0 || r.TID == 0 || (r.Kind != KindExec && r.Kind != KindExit) {
		return ProcessRecord{}, fmt.Errorf("%w: pid=%d tid=%d type=%d", ErrInvalidRecord, r.PID, r.TID, r.Kind)
	}
	if r.Kind == KindExit && r.PID != r.TID {
		return ProcessRecord{}, fmt.Errorf("%w: exit is not from leader", ErrInvalidRecord)
	}
	return r, nil
}
