#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "../xdp_collector.h"

int main(void) {
    struct packet_event event;
    memset(&event, 0, sizeof(event));

    /*
     * Values are deliberately distinctive so Go can verify
     * every field and byte offset.
     */
    event.timestamp_ns = 1234567890123ULL;
    event.src_ip = inet_addr("192.168.1.10");
    event.dst_ip = inet_addr("10.0.0.25");
    event.src_port = 54321;
    event.dst_port = 443;
    event.protocol = 6;       /* TCP */
    event.pkt_len = 1500;

    if (fwrite(&event, sizeof(event), 1, stdout) != 1) {
        perror("fwrite");
        return 1;
    }

    return 0;
}
