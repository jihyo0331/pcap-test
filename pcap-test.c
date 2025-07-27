#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define MAX_PAYLOAD_PRINT 20

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char *dev_;
} Param;

Param param = { .dev_ = NULL };

bool parse(Param *param, int argc, char *argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char *argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null – %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex return %d (%s)\n", res, pcap_geterr(pcap));
            break;
        }

        size_t caplen = header->caplen;
        const u_char *ptr = packet;

        if (caplen < 14) continue;
        const u_char *eth_dst = ptr;
        const u_char *eth_src = ptr + 6;
        uint16_t ether_type = ntohs(*(uint16_t *)(ptr + 12));
        ptr += 14; caplen -= 14;
        if (ether_type != 0x0800) continue;

        if (caplen < 20) continue;
        uint8_t ihl = ptr[0] & 0x0F;
        size_t ip_hdr_len = ihl * 4;
        if (caplen < ip_hdr_len) continue;
        struct in_addr ip_src, ip_dst;
        memcpy(&ip_src, ptr + 12, 4);
        memcpy(&ip_dst, ptr + 16, 4);
        uint8_t protocol = ptr[9];
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_src, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ip_dst, dst_ip, sizeof(dst_ip));
        ptr += ip_hdr_len; caplen -= ip_hdr_len;
        if (protocol != IPPROTO_TCP) continue;

        if (caplen < 20) continue;
        uint16_t src_port = ntohs(*(uint16_t *)ptr);
        uint16_t dst_port = ntohs(*(uint16_t *)(ptr + 2));
        uint8_t data_offset = ptr[12] >> 4;
        size_t tcp_hdr_len = data_offset * 4;
        if (caplen < tcp_hdr_len) continue;
        ptr += tcp_hdr_len; caplen -= tcp_hdr_len;

        printf("Ethernet Header: src mac=%02x:%02x:%02x:%02x:%02x:%02x, "
               "dst mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_src[0], eth_src[1], eth_src[2], eth_src[3], eth_src[4], eth_src[5],
               eth_dst[0], eth_dst[1], eth_dst[2], eth_dst[3], eth_dst[4], eth_dst[5]);

        printf("IP Header: src ip=%s, dst ip=%s\n", src_ip, dst_ip);

        printf("TCP Header: src port=%u, dst port=%u\n", src_port, dst_port);

        printf("Payload: ");
        int to_print = caplen > MAX_PAYLOAD_PRINT ? MAX_PAYLOAD_PRINT : (int)caplen;
        for (int i = 0; i < to_print; i++) {
            printf("%02x ", ptr[i]);
        }
        printf("\n\n");
    }

    pcap_close(pcap);
    return 0;
}
