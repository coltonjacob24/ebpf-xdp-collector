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
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("xdp")
int xdp_collector(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end || ip->version != 4 || ip->ihl < 5)
        return XDP_PASS;

    __u32 ip_header_len = (__u32)ip->ihl * 4;
    if ((void *)ip + ip_header_len > data_end)
        return XDP_PASS;

    __u16 ip_total_len = bpf_ntohs(ip->tot_len);
    if (ip_total_len < ip_header_len || (void *)ip + ip_total_len > data_end)
        return XDP_PASS;

    __u16 src_port = 0, dst_port = 0;
    __u16 frag = bpf_ntohs(ip->frag_off);
    if (!(frag & (IP_MF | IP_OFFSET))) {
        void *l4 = (void *)ip + ip_header_len;
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = l4;
            if ((void *)(tcp + 1) <= data_end) {
                src_port = bpf_ntohs(tcp->source);
                dst_port = bpf_ntohs(tcp->dest);
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = l4;
            if ((void *)(udp + 1) <= data_end) {
                src_port = bpf_ntohs(udp->source);
                dst_port = bpf_ntohs(udp->dest);
            }
        }
    }

    struct packet_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return XDP_PASS;

    e->timestamp = bpf_ktime_get_real_ns();
    e->src_ip = ip->saddr;
    e->dst_ip = ip->daddr;
    e->src_port = src_port;
    e->dst_port = dst_port;
    e->protocol = ip->protocol;
    e->pad0 = 0;
    e->pkt_len = ip_total_len;
    e->pad[0] = e->pad[1] = e->pad[2] = 0;

    bpf_ringbuf_submit(e, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
