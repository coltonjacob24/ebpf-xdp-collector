
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "xdp_collector.h"
#include "packet_parser.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("xdp")
int xdp_collector(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct parsed_packet packet = {};

    if (!parse_ipv4_packet(data, data_end, &packet))
        return XDP_PASS;

    struct packet_event *e;

    e = bpf_ringbuf_reserve(
        &events,
        sizeof(*e),
        0
    );

    if (!e)
        return XDP_PASS;

    e->timestamp_ns = bpf_ktime_get_ns();

    e->src_ip = packet.src_ip;
    e->dst_ip = packet.dst_ip;

    e->src_port = packet.src_port;
    e->dst_port = packet.dst_port;

    e->protocol = packet.protocol;

    e->pad0 = 0;

    e->pkt_len = packet.pkt_len;

    __builtin_memset(
        e->pad,
        0,
        sizeof(e->pad)
    );

    bpf_ringbuf_submit(e, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
