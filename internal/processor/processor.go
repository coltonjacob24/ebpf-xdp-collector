package processor

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/coltonjacob24/ebpf-xdp-collector/internal/influx"
)

// rawPacketEvent represents the raw packet data as received from the network.
// This must match the structure of the C struct in bpf/xdp_collector.h
type rawPacket struct {
	Timestamp  uint64
	SourceIP   uint32
	DestIP     uint32
	SourcePort uint16
	DestPort   uint16
	Protocol   uint8
	PktLen     uint16
	_          [3]uint8 // Padding to align the struct to 8 bytes
}

type Processor struct {
	writer *influx.Writer
}

func New(writer *influx.Writer) *Processor {
	return &Processor{
		writer: writer,
	}
}

// HandleEvent is called for every event from ring buffer.
func (p *Processor) HandleEvent(raw []byte) {
	if len(raw) < 32 { // minimum size of the struct
		log.Printf("Received undersized event: %d bytes", len(raw))
		return
	}

	event, err := parseRawEvent(raw)
	if err != nil {
		log.Printf("Failed to parse raw event: %v", err)
		return
	}
	// At this point, 'event' contains the parsed raw packet event.

	// Convert to the format expected by Influx writer.
	packet := influx.PacketEvent{
		Timestamp:  time.Unix(0, int64(event.Timestamp)),
		SourceIP:   intToIP(event.SourceIP).String(),
		DestIP:     intToIP(event.DestIP).String(),
		SourcePort: event.SourcePort,
		DestPort:   event.DestPort,
		Protocol:   protocolToString(event.Protocol),
		PktLen:     event.PktLen,
	}

	if err := p.writer.Write(packet); err != nil {
		log.Printf("Failed to write packet to Influx writer: %v", err)
	}
}

func parseRawEvent(data []byte) (*rawPacket, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("insufficient data length: %d", len(data))
	}

	event := &rawPacket{
		Timestamp:  binary.LittleEndian.Uint64(data[0:8]),
		SourceIP:   binary.LittleEndian.Uint32(data[8:12]),
		DestIP:     binary.LittleEndian.Uint32(data[12:16]),
		SourcePort: binary.LittleEndian.Uint16(data[16:18]),
		DestPort:   binary.LittleEndian.Uint16(data[18:20]),
		Protocol:   data[20],
		PktLen:     binary.LittleEndian.Uint16(data[21:23]),
	}

	return event, nil
}

func intToIP(ip uint32) net.IP {
	result := make(net.IP, 4)
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
