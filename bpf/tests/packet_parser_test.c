
#include <arpa/inet.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "xdp_collector.h"
#include "packet_parser.h"

#define CAP 128

static int failures;

#define CHECK(c, msg) do { \
    if (!(c)) { \
        fprintf(stderr, "FAIL: %s\n", msg); \
        failures++; \
    } \
} while (0)

/* Verify the exact C-to-Go event layout. */

_Static_assert(
    sizeof(struct packet_event) == 32,
    "packet_event size must be 32"
);

_Static_assert(
    offsetof(struct packet_event, timestamp_ns) == 0,
    "timestamp offset"
);

_Static_assert(
    offsetof(struct packet_event, src_ip) == 8,
    "src_ip offset"
);

_Static_assert(
    offsetof(struct packet_event, dst_ip) == 12,
    "dst_ip offset"
);

_Static_assert(
    offsetof(struct packet_event, src_port) == 16,
    "src_port offset"
);

_Static_assert(
    offsetof(struct packet_event, dst_port) == 18,
    "dst_port offset"
);

_Static_assert(
    offsetof(struct packet_event, protocol) == 20,
    "protocol offset"
);

_Static_assert(
    offsetof(struct packet_event, pad0) == 21,
    "pad0 offset"
);

_Static_assert(
    offsetof(struct packet_event, pkt_len) == 22,
    "pkt_len offset"
);

_Static_assert(
    offsetof(struct packet_event, pad) == 24,
    "pad offset"
);

struct frame {
    unsigned char data[CAP];
    size_t len;
};

static void init_frame(
    struct frame *f,
    unsigned char proto,
    unsigned short l4len
)
{
    memset(f, 0, sizeof(*f));

    struct ethhdr *eth =
        (struct ethhdr *)f->data;

    eth->h_proto = htons(ETH_P_IP);

    struct iphdr *ip =
        (struct iphdr *)(f->data + sizeof(*eth));

    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 64;
    ip->protocol = proto;

    ip->tot_len = htons(
        (unsigned short)(20 + l4len)
    );

    ip->saddr = inet_addr("192.168.1.10");
    ip->daddr = inet_addr("10.0.0.5");

    f->len = sizeof(*eth) + 20 + l4len;
}

static int parse(
    struct frame *f,
    struct parsed_packet *p
)
{
    return parse_ipv4_packet(
        f->data,
        f->data + f->len,
        p
    );
}

/* Test 1: TCP */

static void test_tcp(void)
{
    struct frame f;

    init_frame(
        &f,
        IPPROTO_TCP,
        sizeof(struct tcphdr)
    );

    struct tcphdr *t =
        (struct tcphdr *)(
            f.data +
            sizeof(struct ethhdr) +
            20
        );

    t->source = htons(54321);
    t->dest = htons(443);
    t->doff = 5;

    struct parsed_packet p = {0};

    CHECK(parse(&f, &p), "TCP packet should parse");

    CHECK(
        p.src_ip == inet_addr("192.168.1.10"),
        "TCP source IP"
    );

    CHECK(
        p.dst_ip == inet_addr("10.0.0.5"),
        "TCP destination IP"
    );

    CHECK(
        p.src_port == 54321 &&
        p.dst_port == 443,
        "TCP ports"
    );

    CHECK(
        p.protocol == IPPROTO_TCP &&
        p.pkt_len == 40,
        "TCP protocol/length"
    );
}

/* Test 2: UDP */

static void test_udp(void)
{
    struct frame f;

    init_frame(
        &f,
        IPPROTO_UDP,
        sizeof(struct udphdr)
    );

    struct udphdr *u =
        (struct udphdr *)(
            f.data +
            sizeof(struct ethhdr) +
            20
        );

    u->source = htons(5353);
    u->dest = htons(53);
    u->len = htons(8);

    struct parsed_packet p = {0};

    CHECK(parse(&f, &p), "UDP packet should parse");

    CHECK(
        p.src_port == 5353 &&
        p.dst_port == 53,
        "UDP ports"
    );

    CHECK(
        p.protocol == IPPROTO_UDP &&
        p.pkt_len == 28,
        "UDP protocol/length"
    );
}

/* Test 3: ICMP */

static void test_icmp_zero_ports(void)
{
    struct frame f;

    init_frame(&f, IPPROTO_ICMP, 8);

    struct parsed_packet p = {0};

    CHECK(parse(&f, &p), "ICMP packet should parse");

    CHECK(
        p.src_port == 0 &&
        p.dst_port == 0,
        "ICMP ports must be zero"
    );
}

/* Test 4: Non-IPv4 */

static void test_non_ipv4_ignored(void)
{
    struct frame f = {0};

    f.len = sizeof(struct ethhdr);

    ((struct ethhdr *)f.data)->h_proto =
        htons(ETH_P_ARP);

    struct parsed_packet p = {0};

    CHECK(
        !parse(&f, &p),
        "ARP must be ignored"
    );
}

/* Test 5: Truncated Ethernet header */

static void test_truncated_ethernet_ignored(void)
{
    struct frame f = {0};

    f.len = sizeof(struct ethhdr) - 1;

    struct parsed_packet p = {0};

    CHECK(
        !parse(&f, &p),
        "truncated Ethernet header must be ignored"
    );
}

/* Test 6: Invalid IPv4 header length */

static void test_bad_ihl_ignored(void)
{
    struct frame f;

    init_frame(&f, IPPROTO_ICMP, 8);

    ((struct iphdr *)(
        f.data + sizeof(struct ethhdr)
    ))->ihl = 4;

    struct parsed_packet p = {0};

    CHECK(
        !parse(&f, &p),
        "IHL below 5 must be ignored"
    );
}

/* Test 7: Invalid IPv4 total length */

static void test_bad_total_length_ignored(void)
{
    struct frame f;

    init_frame(&f, IPPROTO_ICMP, 8);

    ((struct iphdr *)(
        f.data + sizeof(struct ethhdr)
    ))->tot_len = htons(19);

    struct parsed_packet p = {0};

    CHECK(
        !parse(&f, &p),
        "IP total length below header size must be ignored"
    );
}

/* Test 8: Truncated IP packet */

static void test_truncated_ip_ignored(void)
{
    struct frame f;

    init_frame(
        &f,
        IPPROTO_TCP,
        sizeof(struct tcphdr)
    );

    f.len--;

    struct parsed_packet p = {0};

    CHECK(
        !parse(&f, &p),
        "truncated IP packet must be ignored"
    );
}

/* Test 9: IPv4 fragments */

static void test_fragments_have_zero_ports(void)
{
    struct frame f;

    init_frame(
        &f,
        IPPROTO_TCP,
        sizeof(struct tcphdr)
    );

    ((struct iphdr *)(
        f.data + sizeof(struct ethhdr)
    ))->frag_off = htons(0x2000);

    struct tcphdr *t =
        (struct tcphdr *)(
            f.data +
            sizeof(struct ethhdr) +
            20
        );

    t->source = htons(1000);
    t->dest = htons(2000);
    t->doff = 5;

    struct parsed_packet p = {0};

    CHECK(
        parse(&f, &p),
        "fragment should still produce IPv4 metadata"
    );

    CHECK(
        p.src_port == 0 &&
        p.dst_port == 0,
        "fragment ports must be zero"
    );
}

/* Test 10: Invalid TCP data offset */

static void test_bad_tcp_data_offset_zero_ports(void)
{
    struct frame f;

    init_frame(
        &f,
        IPPROTO_TCP,
        sizeof(struct tcphdr)
    );

    struct tcphdr *t =
        (struct tcphdr *)(
            f.data +
            sizeof(struct ethhdr) +
            20
        );

    t->source = htons(1000);
    t->dest = htons(2000);
    t->doff = 4;

    struct parsed_packet p = {0};

    CHECK(
        parse(&f, &p),
        "bad TCP offset should not discard IPv4 metadata"
    );

    CHECK(
        p.src_port == 0 &&
        p.dst_port == 0,
        "invalid TCP offset ports must be zero"
    );
}

int main(void)
{
    test_tcp();
    test_udp();
    test_icmp_zero_ports();
    test_non_ipv4_ignored();
    test_truncated_ethernet_ignored();
    test_bad_ihl_ignored();
    test_bad_total_length_ignored();
    test_truncated_ip_ignored();
    test_fragments_have_zero_ports();
    test_bad_tcp_data_offset_zero_ports();

    if (failures) {
        fprintf(
            stderr,
            "%d C test(s) failed\n",
            failures
        );

        return EXIT_FAILURE;
    }

    puts(
        "PASS: 10 C packet-parser cases; "
        "packet_event layout is 32 bytes."
    );

    return EXIT_SUCCESS;
}
