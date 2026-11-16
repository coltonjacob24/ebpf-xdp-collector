package processor

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"github.com/coltonjacob24/ebpf-xdp-collector/internal/influx"
)

const packetEventSize = 32

// rawPacket mirrors packet_event in bpf/xdp_collector.h.
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
	writer      *influx.Writer
	events      atomic.Uint64
	parseErrors atomic.Uint64
	writeErrors atomic.Uint64
	wallClockOffsetNS int64
	hasClockOffset bool
}
type Stats struct {
	Events      uint64
	ParseErrors uint64
	WriteErrors uint64
}

func New(writer *influx.Writer) *Processor { 
	p := &Processor{writer: writer}

	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		monoNS := st.Sec*int64(time.Second) + ts.Nsec
		p.wallClockOffsetNS = time.Now().UnixNano() - monoNS
		p.hasClockOffset = true
	}

	return p
}

// HandleEvent intentionally avoids per-packet logging; use Stats for counters.
func (p *Processor) HandleEvent(raw []byte) {
	p.events.Add(1)
	event, err := parseRawEvent(raw)
	if err != nil {
		p.parseErrors.Add(1)
		return
	}
	packet := influx.PacketEvent{
		Timestamp:  func() time.Time() {
			if p.hasClockOffset {
				return time.Unix(0, int64(event.Timestamp)+p.wallClockOffsetNS).UTC()	
			}
			return time.Now().UTC()
		}(),
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
func (p *Processor) Stats() Stats {
	return Stats{Events: p.events.Load(), ParseErrors: p.parseErrors.Load(), WriteErrors: p.writeErrors.Load()}
}
func parseRawEvent(data []byte) (*rawPacket, error) {
	if len(data) != packetEventSize {
		return nil, fmt.Errorf("invalid event size: got %d, want %d", len(data), packetEventSize)
	}
	return &rawPacket{
		Timestamp:  binary.LittleEndian.Uint64(data[0:8]),
		SourceIP:   binary.LittleEndian.Uint32(data[8:12]),
		DestIP:     binary.LittleEndian.Uint32(data[12:16]),
		SourcePort: binary.LittleEndian.Uint16(data[16:18]),
		DestPort:   binary.LittleEndian.Uint16(data[18:20]),
		Protocol:   data[20],
		// Byte 21 is explicit alignment padding in the C event structure.
		PktLen: binary.LittleEndian.Uint16(data[22:24]),
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
