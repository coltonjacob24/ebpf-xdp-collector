#ifndef __XDP_COLLECTOR_H
#define __XDP_COLLECTOR_H

struct packet_event {
    __u64 timestamp;  /* Unix epoch nanoseconds */
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 pad0;        /* explicit alignment before pkt_len */
    __u16 pkt_len;
    __u8 pad[3];
};

#endif
