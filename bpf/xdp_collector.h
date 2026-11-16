#ifndef __XDP_COLLECTOR_H
#define __XDP_COLLECTOR_H

#include <linux/types.h>

/* Fixed 32-byte event shared with internal/processor. */
struct packet_event {
  __u64 timestamp_ns; /* Monotonic nanoseconds since boot */
  __u32 src_ip;       /* IPv4 network-order address */
  __u32 dst_ip;
  __u16 src_port;     /* host byte order */
  __u16 dst_port;
  __u8 protocol;
  __u8 pad0;
  __u16 pkt_len;      /* IPv4 total length, host byte order */
  __u8 pad[8];
};
#endif
