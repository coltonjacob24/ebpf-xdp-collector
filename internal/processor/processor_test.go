package processor

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/coltonjacob24/ebpf-xdp-collector/internal/influx"
)

type mockWriter struct {
	events []influx.PacketEvent
	err    error
}

func (m *mockWriter) Write(event influx.PacketEvent) error {
	m.events = append(m.events, event)
	return m.err
}

func makeRawEvent() []byte {
	raw := make([]byte, packetEventSize)
	binary.LittleEndian.PutUint64(raw[0:8], 1_000_000_000) // timestamp
	binary.LittleEndian.PutUint32(raw[8:12], 0x0A01A8C0)   // source IP
	binary.LittleEndian.PutUint32(raw[12:16], 0x0500000A)  // dest IP
	binary.LittleEndian.PutUint16(raw[16:18], 54321)       // source port
	binary.LittleEndian.PutUint16(raw[18:20], 443)         // dest port

	raw[20] = 6 // protocol (TCP)
	raw[21] = 0
	binary.LittleEndian.PutUint16(raw[22:24], 60) // packet length

	return raw
}

func TestParseRawEvent(t *testing.T) {
	raw := makeRawEvent()

	event, err := parseRawEvent(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Timestamp != 1_000_000_000 {
		t.Errorf("unexpected timestamp: got %d, want %d", event.Timestamp, 1_000_000_000)
	}

	if event.SourceIP != 0x0A01A8C0 {
		t.Errorf("unexpected source IP: got %x, want %x", event.SourceIP, 0x0A01A8C0)
	}

	if event.DestIP != 0x0500000A {
		t.Errorf("unexpected dest IP: got %x, want %x", event.DestIP, 0x0500000A)
	}

	if event.SourcePort != 54321 {
		t.Errorf("unexpected source port: got %d, want %d", event.SourcePort, 54321)
	}

	if event.DestPort != 443 {
		t.Errorf("unexpected dest port: got %d, want %d", event.DestPort, 443)
	}

	if event.Protocol != 6 {
		t.Errorf("unexpected protocol: got %d, want %d", event.Protocol, 6)
	}

	if event.PktLen != 60 {
		t.Errorf("unexpected packet length: got %d, want %d", event.PktLen, 60)
	}
}

func TestParseRawEventRejectsInvalidSize(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"too short", 31},
		{"oversized", 33},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseRawEvent(make([]byte, tt.size)); err == nil {
				t.Fatalf("expected size error for %d", tt.size)
			}
		})
	}
}

func TestHandleEventProducesCorrectInfluxMetadata(t *testing.T) {
	writer := &mockWriter{}

	p := &Processor{
		writer: writer,
	}

	p.HandleEvent(makeRawEvent())

	if len(writer.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(writer.events))
	}

	got := writer.events[0]

	checks := []struct {
		name string
		got  string
		want string
	}{
		{"source IP", got.SourceIP, "192.168.1.10"},
		{"destination IP", got.DestIP, "10.0.0.5"},
		{"protocol", got.Protocol, "TCP"},
	}

	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s: got %q, want %q", check.name, check.got, check.want)
		}
	}

	if got.SourcePort != 54321 {
		t.Errorf("source port = %d", got.SourcePort)
	}

	if got.DestPort != 443 {
		t.Errorf("destination port = %d", got.DestPort)
	}

	if got.PktLen != 60 {
		t.Errorf("packet length = %d", got.PktLen)
	}

	if got.Timestamp.IsZero() {
		t.Error("timestamp should not be zero")
	}
}

func TestHandleEventProtocolMapping(t *testing.T) {
	tests := []struct {
		protocol uint8
		want     string
	}{
		{1, "ICMP"},
		{6, "TCP"},
		{17, "UDP"},
		{99, "UNKNOWN(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			writer := &mockWriter{}
			p := &Processor{writer: writer}

			raw := makeRawEvent()
			raw[20] = tt.protocol

			p.HandleEvent(raw)

			if len(writer.events) != 1 {
				t.Fatal("expected one event")
			}

			if got := writer.events[0].Protocol; got != tt.want {
				t.Errorf("protocol = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHandleEventDoesNotWriteMalformedEvent(t *testing.T) {
	writer := &mockWriter{}
	p := &Processor{writer: writer}

	p.HandleEvent(make([]byte, 10))

	if len(writer.events) != 0 {
		t.Fatal("malformed event reached writer")
	}

	stats := p.Stats()

	if stats.ParseErrors != 1 {
		t.Errorf("parse errors = %d, want 1", stats.ParseErrors)
	}
}

func TestHandleEventCountsWriteErrors(t *testing.T) {
	writer := &mockWriter{
		err: errors.New("simulated InfluxDB failure"),
	}

	p := &Processor{writer: writer}
	p.HandleEvent(makeRawEvent())

	if p.Stats().WriteErrors != 1 {
		t.Error("expected one write error")
	}
}

func TestMonotonicTimestampConversion(t *testing.T) {
	offset := int64(1_700_000_000_000_000_000)
	monotonic := uint64(5_000_000_000)

	got := time.Unix(0, int64(monotonic)+offset).UTC()
	want := time.Unix(0, offset+int64(monotonic)).UTC()

	if !got.Equal(want) {
		t.Errorf("timestamp = %v, want %v", got, want)
	}
}

func TestParseRawEventUsesAlignedPacketLengthOffset(t *testing.T) {
	raw := make([]byte, packetEventSize)
	binary.LittleEndian.PutUint64(raw[0:8], 1_700_000_000_000_000_000)
	binary.LittleEndian.PutUint32(raw[8:12], 0x0100007f)
	binary.LittleEndian.PutUint32(raw[12:16], 0x0200007f)
	binary.LittleEndian.PutUint16(raw[16:18], 8080)
	binary.LittleEndian.PutUint16(raw[18:20], 443)
	raw[20] = 6
	raw[21] = 0xff
	binary.LittleEndian.PutUint16(raw[22:24], 1500)
	got, err := parseRawEvent(raw)
	if err != nil {
		t.Fatal(err)
	}

	if got.SourcePort != 8080 || got.DestPort != 443 || got.PktLen != 1500 {
		t.Fatalf("decoded fields: %+v", got)
	}
}

func TestParseRawEventRejectsWrongSize(t *testing.T) {
	for _, n := range []int{packetEventSize - 1, packetEventSize + 1} {
		if _, err := parseRawEvent(make([]byte, n)); err == nil {
			t.Fatalf("expected size error for %d", n)
		}
	}
}
