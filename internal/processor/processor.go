package processor

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/coltonjacob24/ebpf-xdp-collector/internal/influx"
)

const rawEventSize = 32

type rawPacket struct {
	Timestamp  uint64
	SourceIP   uint32
	DestIP     uint32
	SourcePort uint16
	DestPort   uint16
	Protocol   uint8
	PktLen     uint16
}

type Processor struct {
	writer       *influx.Writer
	events       atomic.Uint64
	parseErrors  atomic.Uint64
	writeErrors  atomic.Uint64
}

func New(writer *influx.Writer) *Processor { return &Processor{writer: writer} }

// HandleEvent is called for every event read from the kernel ring buffer.
// It intentionally avoids per-packet logging; counters can be sampled by metrics.
func (p *Processor) HandleEvent(raw []byte) {
	p.events.Add(1)
	event, err := parseRawEvent(raw)
	if err != nil {
		p.parseErrors.Add(1)
		return
	}

	packet := influx.PacketEvent{
		Timestamp:  time.Unix(0, int64(event.Timestamp)).UTC(),
		SourceIP:   intToIP(event.SourceIP).String(),
		DestIP:     intToIP(event.DestIP).String(),
		SourcePort: event.SourcePort,
		DestPort:   event.DestPort,
		Protocol:   protocolToString(event.Protocol),
		PktLen:     event.PktLen,
	}
	if err := p.writer.Write(packet); err != nil {
		p.writeErrors.Add(1)
	}
}

func (p *Processor) Counts() (events, parseErrors, writeErrors uint64) {
	return p.events.Load(), p.parseErrors.Load(), p.writeErrors.Load()
}

func parseRawEvent(data []byte) (*rawPacket, error) {
	if len(data) < rawEventSize {
		return nil, fmt.Errorf("event size %d is smaller than %d", len(data), rawEventSize)
	}
	return &rawPacket{
		Timestamp:  binary.LittleEndian.Uint64(data[0:8]),
		SourceIP:   binary.LittleEndian.Uint32(data[8:12]),
		DestIP:     binary.LittleEndian.Uint32(data[12:16]),
		SourcePort: binary.LittleEndian.Uint16(data[16:18]),
		DestPort:   binary.LittleEndian.Uint16(data[18:20]),
		Protocol:   data[20],
		PktLen:     binary.LittleEndian.Uint16(data[22:24]),
	}, nil
}

func intToIP(ip uint32) net.IP {
	result := make(net.IP, net.IPv4len)
	binary.LittleEndian.PutUint32(result, ip)
	return result
}

func protocolToString(protocol uint8) string {
	switch protocol {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", protocol)
	}
}
