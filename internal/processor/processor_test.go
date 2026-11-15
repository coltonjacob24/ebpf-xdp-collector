package processor

import(
  "encoding/binary"
  "testing"
)

func TestParseRawEventUsesAlignedPacketLengthOffset(t *testing.T) {
  raw := make([]byte,packetEventSize)
  binary.LittleEndian.PutUint64(raw[0:8], 1_700_000_000_000_000_000)
  binary.LittleEndian.PutUint32(raw[8:12], 0x0100007f)
  binary.LittleEndian.PutUint32(raw[12:16], 0x0200007f)
  binary.LittleEndian.PutUint16(raw[16:18], 8080)
  binary.LittleEndian.PutUint16(raw[18:20], 443)
  raw[20]=6;raw[21]=0xff
  binary.LittleEndian.PutUint16(raw[22:24], 1500)
  got,err:=parseRawEvent(raw)
  if err != nil {
    t.Fatal(err)
  }
  
  if got.SourcePort != 8080 || got.DestPort != 443 || got.PktLen != 1500 {
    t.Fatalf("decoded fields: %+v", got)
  }
}

func TestParseRawEventRejectsWrongSize(t *testing.T) {
  for _, n := range []int{packetEventSize-1, packetEventSize+1} {
    if _, err := parseRawEvent(make([]byte, n)); err == nil {
      t.Fatalf("expected size error for %d",n)
    }
  }
}
