package ebpf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type Loader struct {
	objs         *xdpObjects
	link         link.Link
	reader       *ringbuf.Reader
	readerClose  sync.Once
	closeErr     error
	linkClose    sync.Once
	linkCloseErr error
}

type XDPStats struct {
	PacketsSeen          uint64
	PacketsParsed        uint64
	RingbufReserveFailed uint64
	EventsSubmitted      uint64
}

func NewLoader(iface string) (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}

	objs := &xdpObjects{}
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelBranch | ebpf.LogLevelInstruction,
			LogSizeStart: 1 << 20,
		},
	}

	if err := loadXdpObjects(objs, opts); err != nil {
		var verifierErr *ebpf.VerifierError
		if errors.As(err, &verifierErr) {
			return nil, fmt.Errorf("Load eBPF objects:\n%+v", verifierErr)
		}
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	networkInterface, err := net.InterfaceByName(iface)
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("get interface index for %s: %w", iface, err)
	}

	attached, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpCollector,
		Interface: networkInterface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("attach XDP program: %w", err)
	}

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		_ = attached.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("create ring buffer reader: %w", err)
	}

	return &Loader{
		objs:   objs,
		link:   attached,
		reader: reader,
	}, nil
}

func (l *Loader) Start(ctx context.Context, handler func([]byte)) error {
	watchDone := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
			l.closeReader()
		case <-watchDone:
		}
	}()

	defer close(watchDone)

	for {
		record, err := l.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read from ring buffer: %w", err)
		}

		handler(record.RawSample)
	}
}

func (l *Loader) Stats() (XDPStats, error) {
	var result XDPStats

	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return result, fmt.Errorf("get possible CPU count: %w", err)
	}

	values := make([]xdpXdpStats, possibleCPUs)

	key := uint32(0)

	if err := l.objs.Stats.Lookup(&key, &values); err != nil {
		return result, fmt.Errorf("read XDP stats map: %w", err)
	}

	for _, value := range values {
		result.PacketsSeen += value.PacketsSeen
		result.PacketsParsed += value.PacketsParsed
		result.RingbufReserveFailed += value.RingbufReserveFailed
		result.EventsSubmitted += value.EventsSubmitted
	}

	return result, nil
}

func (l *Loader) closeReader() {
	l.readerClose.Do(func() {
		l.closeErr = l.reader.Close()
	})
}

// Stop stops userspace ring-buffer reading and detaches the XDP program.
// The eBPF maps remain open so final statistics can still be read.
func (l *Loader) Stop() error {
	l.closeReader()

	l.linkClose.Do(func() {
		if l.link != nil {
			l.linkCloseErr = l.link.Close()
		}
	})

	var errs []error

	if l.closeErr != nil {
		errs = append(errs, fmt.Errorf("close ring buffer reader: %w", l.closeErr))
	}

	if l.linkCloseErr != nil {
		errs = append(errs, fmt.Errorf("detach XDP link: %w", l.linkCloseErr))
	}

	if len(errs) > 0 {
		return fmt.Errorf("stop eBPF loader: %v", errs)
	}

	return nil
}

// Close releases the eBPF maps and programs.
// Call Stop first if you need to read final statistics.
func (l *Loader) Close() error {
	stopErr := l.Stop()

	var objectErr error
	if l.objs != nil {
		objectErr = l.objs.Close()
	}

	if stopErr != nil && objectErr != nil {
		return fmt.Errorf("%v; close eBPF objects: %w", stopErr, objectErr)
	}
	if stopErr != nil {
		return stopErr
	}
	if objectErr != nil {
		return fmt.Errorf("close eBPF objects: %w", objectErr)
	}

	return nil
}
