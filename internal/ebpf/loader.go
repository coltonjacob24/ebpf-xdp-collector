package ebpf

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type Loader struct {
	objs   *xdpObjects
	link   link.Link
	reader *ringbuf.Reader
}

func NewLoader(iface string) (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}
	objs := &xdpObjects{}
	if err := loadXdpObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}
	ifindex, err := net.InterfaceByName(iface)
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("get interface index for %s: %w", iface, err)
	}
	l, err := link.AttachXDP(link.XDPOptions{Program: objs.XdpCollector, Interface: ifindex.Index})
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("attach XDP program: %w", err)
	}
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		_ = l.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("create ring buffer reader: %w", err)
	}
	return &Loader{objs: objs, link: l, reader: reader}, nil
}

func (l *Loader) Start(ctx context.Context, handler func([]byte)) error {
	if l.reader == nil {
		return fmt.Errorf("ring buffer reader is not initialized")
	}
	// Read blocks; closing the reader is what unblocks it on cancellation.
	go func() {
		<-ctx.Done()
		_ = l.reader.Close()
	}()
	for {
		record, err := l.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) && ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read from ring buffer: %w", err)
		}
		handler(record.RawSample)
	}
}

func (l *Loader) Close() error {
	var errs []error
	if l.reader != nil {
		if err := l.reader.Close(); err != nil && !errors.Is(err, ringbuf.ErrClosed) {
			errs = append(errs, fmt.Errorf("close ring buffer reader: %w", err))
		}
	}
	if l.link != nil {
		if err := l.link.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close XDP link: %w", err))
		}
	}
	if l.objs != nil {
		if err := l.objs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close eBPF objects: %w", err))
		}
	}
	if len(errs) != 0 {
		return fmt.Errorf("loader close errors: %v", errs)
	}
	return nil
}
