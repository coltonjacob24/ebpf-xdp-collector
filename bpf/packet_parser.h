
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

static __inline__ __attribute__((always_inline))
int parse_ipv4_packet(void *data, void *data_end,
                      struct parsed_packet *out)
{
    struct ethhdr *eth = data;

    /* Prove the Ethernet header is accessible before reading it. */
    if ((void *)(eth + 1) > data_end)
        return 0;

    if (eth->h_proto != packet_be16_to_cpu(ETH_P_IP))
        return 0;

    struct iphdr *ip = (void *)(eth + 1);

    /* Prove the fixed IPv4 header is accessible. */
    if ((void *)(ip + 1) > data_end)
        return 0;

    if (ip->version != 4)
        return 0;

    /* IPv4 IHL is 5–15 words, or 20–60 bytes. */
    if (ip->ihl < 5 || ip->ihl > 15)
        return 0;

    __u32 ihl_bytes = (__u32)ip->ihl * 4;

    void *l4 = (void *)ip + ihl_bytes;

    /* Validate the complete IPv4 header, including options. */
    if (l4 > data_end)
        return 0;

    /*
	* Read IPv4 total length byte-by-byte.
	* This avoids the BPF endian conversion instruction causing verifier to lose
		the scalar's bounds
    */
    const volatile  __u8 *ip_len_bytes = (const volatile __u8 *)&ip->tot_len;
    __u32 ip_len = ((__u32)ip_len_bytes[0] << 8) | (__u32)ip_len_bytes[1];

    if (ip_len < ihl_bytes)
        return 0;

    /*
     * ip_len is a 16-bit value. Check the resulting packet pointer
     * against data_end before using it as a transport-header boundary.
     */
    void *ip_end = (void *)ip + ip_len;

    __u16 src_port = 0;
    __u16 dst_port = 0;

    __u16 frag = packet_be16_to_cpu(ip->frag_off);

    /* Do not parse transport headers in fragmented packets. */
    if ((frag & 0x3fff) == 0) {

        if (ip->protocol == IPPROTO_TCP) {

            /*
             * Check the minimum TCP header against the actual
             * packet boundary before reading any TCP fields.
             */
            struct tcphdr *tcp = l4;

            if ((void *)tcp + sizeof(struct tcphdr) > data_end)
                goto transport_done;

            if ((void *)tcp + sizeof(struct tcphdr) > ip_end)
                goto transport_done;

            /*
             * The fixed TCP header is now bounded.
             * Validate the TCP data offset.
             */
            __u8 doff = tcp->doff;

            if (doff < 5 || doff > 15)
                goto transport_done;

            __u32 tcp_len = (__u32)doff * 4;

            if ((void *)tcp + tcp_len > data_end)
                goto transport_done;

            if ((void *)tcp + tcp_len > ip_end)
                goto transport_done;

            src_port = packet_be16_to_cpu(tcp->source);
            dst_port = packet_be16_to_cpu(tcp->dest);

        } else if (ip->protocol == IPPROTO_UDP) {

            struct udphdr *udp = l4;

            if ((void *)udp + sizeof(struct udphdr) > data_end)
                goto transport_done;

            if ((void *)udp + sizeof(struct udphdr) > ip_end)
                goto transport_done;

            src_port = packet_be16_to_cpu(udp->source);
            dst_port = packet_be16_to_cpu(udp->dest);
        }
    }

transport_done:
    /*
	* Validate complete IPv4 packet against frame boundry
    */
    if (ip_end > data_end) {
	return 0;
    }

    out->src_ip = ip->saddr;
    out->dst_ip = ip->daddr;
    out->src_port = src_port;
    out->dst_port = dst_port;
    out->protocol = ip->protocol;
    out->pkt_len = (__u16)ip_len;

    return 1;
}

#endif
