
#ifndef __PACKET_PARSER_H
#define __PACKET_PARSER_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define packet_be16_to_cpu(v) __builtin_bswap16(v)
#else
#define packet_be16_to_cpu(v) (v)
#endif

struct parsed_packet {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u16 pkt_len;
};

/* Shared by the XDP program and host-side C tests. */
static __inline__ __attribute__((always_inline))
int parse_ipv4_packet(void *data, void *data_end, struct parsed_packet *out)
{
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end ||
        eth->h_proto != packet_be16_to_cpu(ETH_P_IP))
        return 0;

    struct iphdr *ip = (void *)(eth + 1);

    if ((void *)(ip + 1) > data_end ||
        ip->version != 4 ||
        ip->ihl < 5)
        return 0;

    __u32 ihl_bytes = (__u32)ip->ihl * 4;
    void *l4 = (void *)ip + ihl_bytes;

    if (l4 > data_end)
        return 0;

    __u16 ip_len = packet_be16_to_cpu(ip->tot_len);

    if (ip_len < ihl_bytes)
        return 0;

    void *ip_end = (void *)ip + ip_len;

    if (ip_end > data_end)
        return 0;

    __u16 src_port = 0;
    __u16 dst_port = 0;

    __u16 frag = packet_be16_to_cpu(ip->frag_off);

    /* Skip L4 parsing for first and later fragments. */
    if ((frag & 0x3fff) == 0) {

        if (ip->protocol == IPPROTO_TCP) {

            struct tcphdr *tcp = l4;

            if ((void *)(tcp + 1) <= ip_end &&
                tcp->doff >= 5) {

                __u32 tcp_len = (__u32)tcp->doff * 4;

                if ((void *)tcp + tcp_len <= ip_end) {
                    src_port = packet_be16_to_cpu(tcp->source);
                    dst_port = packet_be16_to_cpu(tcp->dest);
                }
            }

        } else if (ip->protocol == IPPROTO_UDP) {

            struct udphdr *udp = l4;

            if ((void *)(udp + 1) <= ip_end) {
                src_port = packet_be16_to_cpu(udp->source);
                dst_port = packet_be16_to_cpu(udp->dest);
            }
        }
    }

    out->src_ip = ip->saddr;
    out->dst_ip = ip->daddr;
    out->src_port = src_port;
    out->dst_port = dst_port;
    out->protocol = ip->protocol;
    out->pkt_len = ip_len;

    return 1;
}

#endif
