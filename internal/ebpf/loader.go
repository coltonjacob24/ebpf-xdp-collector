package ebpf

import (
	"context"
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
	// Remove the resource limit for loading eBPF programs
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	// Load the eBPF objects
	objs := &xdpObjects{}
	if err := loadXdpObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load eBPF objects: %w", err)
	}

	// Attach the XDP program to the specified interface
	ifindex, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface index for %s: %w", iface, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpCollector,
		Interface: ifindex.Index,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach XDP program: %w", err)
	}

	// Create a ring buffer reader
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		l.Close()
		objs.Close()
		return nil, fmt.Errorf("failed to create ring buffer reader: %w", err)
	}

	return &Loader{
		objs:   objs,
		link:   l,
		reader: reader,
	}, nil
}

func (l *Loader) Start(ctx context.Context, handler func([]byte)) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			record, err := l.reader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return nil
				}
				return fmt.Errorf("failed to read from ring buffer: %w", err)
			}
			handler(record.RawSample)
		}
	}
}

func (l *Loader) Close() error {
	var errs []error
	if l.reader != nil {
		if err := l.reader.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close ring buffer reader: %w", err))
		}
	}
	if l.link != nil {
		if err := l.link.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close link: %w", err))
		}
	}
	if l.objs != nil {
		if err := l.objs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close eBPF objects: %w", err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors occurred while closing loader: %v", errs)
	}
	return nil
}
