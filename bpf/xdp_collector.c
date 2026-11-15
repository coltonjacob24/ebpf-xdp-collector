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

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    /* Initial version intentionally supports Ethernet + IPv4 only. */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end || ip->version != 4 || ip->ihl < 5)
        return XDP_PASS;

    __u32 ip_header_len = (__u32)ip->ihl * 4;
    void *ip_header_end = (void *)ip + ip_header_len;
    if (ip_header_end > data_end)
        return XDP_PASS;

    __u16 ip_len = bpf_ntohs(ip->tot_len);
    if (ip_len < ip_header_len)
        return XDP_PASS;
    void *ip_end = (void *)ip + ip_len;
    if (ip_end > data_end)
        return XDP_PASS;

    __u16 src_port = 0, dst_port = 0;
    /* Later IPv4 fragments do not contain transport headers. */
    if ((ip->frag_off & bpf_htons(IP_OFFSET)) == 0) {
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = ip_header_end;
            if ((void *)(tcp + 1) <= ip_end && tcp->doff >= 5) {
                __u32 tcp_len = (__u32)tcp->doff * 4;
                if ((void *)tcp + tcp_len <= ip_end) {
                    src_port = bpf_ntohs(tcp->source);
                    dst_port = bpf_ntohs(tcp->dest);
                }
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = ip_header_end;
            if ((void *)(udp + 1) <= ip_end) {
                src_port = bpf_ntohs(udp->source);
                dst_port = bpf_ntohs(udp->dest);
            }
        }
    }

    struct packet_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return XDP_PASS;

    e->timestamp_ns = bpf_ktime_get_real_ns();
    e->src_ip = ip->saddr;
    e->dst_ip = ip->daddr;
    e->src_port = src_port;
    e->dst_port = dst_port;
    e->protocol = ip->protocol;
    e->pad0 = 0;
    e->pkt_len = ip_len;
    __builtin_memset(e->pad, 0, sizeof(e->pad));
    bpf_ringbuf_submit(e, 0);
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
