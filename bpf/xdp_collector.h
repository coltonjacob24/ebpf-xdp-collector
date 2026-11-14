#ifndef __XDP_COLLECTOR_H
#define XDP_COLLECTOR_H

struct packet_event {
  __u64 timestamp;      // nanoseconds
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u8 protocol;        // IPPROTO_TCP /UDP /ICMP
  __u16 pkt_len;
  __u8 pad[3];          // padding to align the structure to 8 bytes
};

#endif // __XDP_COLLECTOR_H