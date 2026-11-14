#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_collector.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);           // 16MB ring buffer
} events SEC(".maps");

SEC("xdp")
int xdp_collector(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct packet_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

    if (!e)
        return XDP_PASS;

    e->timestamp = bpf_ktime_get_ns();
    e->src_ip = ip->saddr;
    e->dst_ip = ip->daddr;
    e->protocol = ip->protocol;
    e->pkt_len = bpf_ntohs(ip->tot_len);
    e->src_port = 0;
    e->dst_port = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) {
            e->src_port = bpf_ntohs(tcp->source);
            e->dst_port = bpf_ntohs(tcp->dest);
        }      
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) {
            e->src_port = bpf_ntohs(udp->source);
            e->dst_port = bpf_ntohs(udp->dest);
        }
    }

    bpf_ringbuf_submit(e, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";