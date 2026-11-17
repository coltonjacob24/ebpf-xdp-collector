#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "xdp_collector.h"
#include "packet_parser.h"

struct xdp_stats {
    __u64 packets_seen;
    __u64 packets_parsed;
    __u64 ringbuf_reserve_failed;
    __u64 events_submitted;
};

/*
 * Per-CPU counters avoid cross-CPU contention.
 * There is one stats entry, at key 0, for each possible CPU.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_stats);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("xdp")
int xdp_collector(struct xdp_md *ctx)
{
    __u32 key = 0;
    struct xdp_stats *counter;

    counter = bpf_map_lookup_elem(&stats, &key);
    if (counter)
        counter->packets_seen++;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct parsed_packet packet = {};

    if (!parse_ipv4_packet(data, data_end, &packet))
        return XDP_PASS;

    if (counter)
        counter->packets_parsed++;

    struct packet_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

    if (!e) {
        if (counter)
            counter->ringbuf_reserve_failed++;
        return XDP_PASS;
    }

    e->timestamp_ns = bpf_ktime_get_ns();
    e->src_ip = packet.src_ip;
    e->dst_ip = packet.dst_ip;
    e->src_port = packet.src_port;
    e->dst_port = packet.dst_port;
    e->protocol = packet.protocol;
    e->pad0 = 0;
    e->pkt_len = packet.pkt_len;

    __builtin_memset(e->pad, 0, sizeof(e->pad));

    bpf_ringbuf_submit(e, 0);

    if (counter)
        counter->events_submitted++;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
