//go:build linux && (amd64 || arm64)

package collector

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/AlirezaBahador/GhostTrace/internal/decoder"
)

// Collector owns the kernel links, collection, and bounded ring reader.
type Collector struct {
	collection *ebpf.Collection
	execLink   link.Link
	exitLink   link.Link
	reader     *ringbuf.Reader
	stopOnce   sync.Once
	closeOnce  sync.Once
}

func Open(objectPath string) (_ *Collector, err error) {
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return nil, fmt.Errorf("read BPF object %q: %w", objectPath, err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load BPF collection (need kernel >=5.8 and tracepoint/BPF privileges): %w", err)
	}
	c := &Collector{collection: collection}
	defer func() {
		if err != nil {
			_ = c.Close()
		}
	}()

	eventsMap := collection.Maps["events"]
	if eventsMap == nil || collection.Maps["ringbuf_drops"] == nil {
		return nil, fmt.Errorf("BPF object missing required maps")
	}
	execProgram, exitProgram := collection.Programs["trace_exec"], collection.Programs["trace_exit"]
	if execProgram == nil || exitProgram == nil {
		return nil, fmt.Errorf("BPF object missing required programs")
	}
	c.reader, err = ringbuf.NewReader(eventsMap)
	if err != nil {
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}
	c.execLink, err = link.Tracepoint("sched", "sched_process_exec", execProgram, nil)
	if err != nil {
		return nil, fmt.Errorf("attach exec tracepoint: %w", err)
	}
	c.exitLink, err = link.Tracepoint("sched", "sched_process_exit", exitProgram, nil)
	if err != nil {
		return nil, fmt.Errorf("attach exit tracepoint: %w", err)
	}
	return c, nil
}

func (c *Collector) Read() (decoder.ProcessRecord, error) {
	rec, err := c.reader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return decoder.ProcessRecord{}, io.EOF
		}
		return decoder.ProcessRecord{}, err
	}
	return decoder.Decode(rec.RawSample)
}

func (c *Collector) Stop() error {
	var err error
	c.stopOnce.Do(func() {
		if c.reader != nil {
			err = c.reader.Close()
		}
	})
	return err
}

func (c *Collector) Drops() (uint64, error) {
	m := c.collection.Maps["ringbuf_drops"]
	var key uint32
	var value uint64
	if err := m.Lookup(&key, &value); err != nil {
		return 0, fmt.Errorf("read ringbuf drops counter: %w", err)
	}
	return value, nil
}

func (c *Collector) Close() error {
	var firstErr error
	c.closeOnce.Do(func() {
		if err := c.Stop(); err != nil {
			firstErr = err
		}
		if c.exitLink != nil {
			if err := c.exitLink.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if c.execLink != nil {
			if err := c.execLink.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if c.collection != nil {
			c.collection.Close()
		}
	})
	return firstErr
}
