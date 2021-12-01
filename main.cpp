#include <stdio.h>
#include <string.h>
#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"

#pragma pack(push, 1)
struct Pkt_FIN final
{
    EthHdr eth_;
    IpHdr ip_;
    TcpHdr tcp_;
    char tcpData[56];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Pkt final
{
    EthHdr eth_;
    IpHdr ip_;
    TcpHdr tcp_;
};
#pragma pack(pop)

void usage();
char *strnstr(const char *s, const char *find, size_t slen);
Mac getMyMac(char *dev);
void createForwardBlockPkt(pcap_t *handle, Pkt *orgPkt, pcap_pkthdr *header, Mac myMac);
void createBackwardBlockPkt(pcap_t *handle, Pkt *orgPkt, pcap_pkthdr *header, Mac myMac);

int main(int argc, char *argv[])
{
    if(argc != 3)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    char *pattern = argv[2];
    printf("%s\n", pattern);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    Mac my_mac = getMyMac(dev);
    printf("My Mac : %s\n", std::string(my_mac).data());

    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        Pkt *pkt = (struct Pkt *)packet;
        uint16_t dport = ntohs(pkt->tcp_.th_dport);

        if ((pkt->ip_.ip_p) == 0x06)
        {
            if (dport == 80 || dport == 443)
            {
                int len = pkt->ip_.len() - (pkt->ip_.ip_hl) * 4 - (pkt->tcp_.th_off) * 4;
                int location = (header->caplen) - len;
                char *ptr = (char *)malloc(sizeof(char) * len);
                memcpy(ptr, packet + location, len);

                if ((ptr = strnstr(ptr, pattern, len)) != NULL)
                {
                    createForwardBlockPkt(handle, pkt, header, my_mac);
                    createBackwardBlockPkt(handle, pkt, header, my_mac);
                    printf("block!!!\n");
                }
            }
        }
    }

    pcap_close(handle);
    return 0;
}

void usage()
{
    printf("syntax: tcp-block <interface> <pattern>\n");
    printf("sample: tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

char *strnstr(const char *s, const char *find, size_t slen)
{
    char c, sc;
    size_t len;

    if ((c = *find++) != '\0')
    {
        len = strlen(find);
        do
        {
            do
            {
                if (slen-- < 1 || (sc = *s++) == '\0')
                    return (NULL);
            } while (sc != c);
            if (len > slen)
                return (NULL);
        } while (strncmp(s, find, len) != 0);
        s--;
    }
    return ((char *)s);
}

Mac getMyMac(char *dev)
{
    struct ifreq ifr;
    int s;
    char mac_[12] = {
        0,
    };
    Mac mac;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
    {
        printf("Error");
        return 0;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
    {
        printf("Error");
        return 0;
    }

    sprintf(mac_, "%02x:%02x:%02x:%02x:%02x:%02x",
            (unsigned char)ifr.ifr_hwaddr.sa_data[0],
            (unsigned char)ifr.ifr_hwaddr.sa_data[1],
            (unsigned char)ifr.ifr_hwaddr.sa_data[2],
            (unsigned char)ifr.ifr_hwaddr.sa_data[3],
            (unsigned char)ifr.ifr_hwaddr.sa_data[4],
            (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    mac = Mac(mac_);
    close(s);

    return mac;
}

void createForwardBlockPkt(pcap_t *handle, Pkt *orgPkt, pcap_pkthdr *header, Mac myMac)
{
    Pkt *pkt = (Pkt*)malloc(header->caplen);
    uint32_t org_tcpDataSize;

    org_tcpDataSize = orgPkt->ip_.len() - orgPkt->ip_.iphl()*4 - orgPkt->tcp_.th_off*4;

    memcpy(pkt, orgPkt, header->caplen);

    pkt->eth_.smac_ = myMac;

    pkt->ip_.ip_len = htons(orgPkt->ip_.ip_hl * 4 + orgPkt->tcp_.th_off * 4);
    pkt->ip_.ip_sum = htons(IpHdr::calcChecksum(&(pkt->ip_)));

    pkt->tcp_.th_seq = htonl(ntohl(orgPkt->tcp_.th_seq) + org_tcpDataSize);
    pkt->tcp_.th_flags = 0x14; //RST & ACK
    pkt->tcp_.th_off = sizeof(TcpHdr) >> 2;
    pkt->tcp_.th_sum = htons(TcpHdr::calcChecksum(&(pkt->ip_), &(pkt->tcp_)));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(pkt), header->caplen);
    free(pkt);
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    else printf("Forward success!!\n");
}

void createBackwardBlockPkt(pcap_t *handle, Pkt *orgPkt, pcap_pkthdr *header, Mac myMac)
{
    char msg[56] = "HTTP/1.1 302 Redirect\r\nLocation: http://warning.or.kr\r\n";
    Pkt_FIN *pkt = (Pkt_FIN*)malloc(header->caplen + strlen(msg));
    uint32_t org_tcpDataSize;
    org_tcpDataSize = orgPkt->ip_.len() - orgPkt->ip_.iphl()*4 - orgPkt->tcp_.th_off*4;
    
    memcpy(pkt, orgPkt, header->caplen);

    pkt->eth_.smac_ = myMac;
    pkt->eth_.dmac_ = orgPkt->eth_.smac_;

    pkt->ip_.ip_ttl = 128;
    pkt->ip_.ip_src = orgPkt->ip_.ip_dst;
    pkt->ip_.ip_dst = orgPkt->ip_.ip_src;

    pkt->tcp_.th_sport = orgPkt->tcp_.th_dport;
    pkt->tcp_.th_dport = orgPkt->tcp_.th_sport;
    pkt->tcp_.th_seq = orgPkt->tcp_.th_ack;
    pkt->tcp_.th_ack = htonl(ntohl(orgPkt->tcp_.th_seq) + org_tcpDataSize);
    pkt->tcp_.th_off = sizeof(TcpHdr) >> 2;

    uint16_t dport = ntohs(orgPkt->tcp_.th_dport);

    if (dport == 80)
    {
        pkt->ip_.ip_len = htons(orgPkt->ip_.ip_hl * 4 + orgPkt->tcp_.th_off * 4 + strlen(msg));
        pkt->tcp_.th_flags = 0x11; //FIN & ACK
        memcpy(pkt->tcpData, msg, strlen(msg));
        pkt->ip_.ip_sum = htons(IpHdr::calcChecksum(&(pkt->ip_)));
        pkt->tcp_.th_sum = htons(TcpHdr::calcChecksum(&(pkt->ip_), &(pkt->tcp_)));


        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(pkt), header->caplen + strlen(msg));
        if (res != 0)
        {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        else printf("Backward Success!!\n");
    }
    else if (dport == 443)
    {
        pkt->ip_.ip_len = htons(orgPkt->ip_.ip_hl * 4 + orgPkt->tcp_.th_off * 4);
        pkt->tcp_.th_flags = 0x14; //RST & ACK
        pkt->ip_.ip_sum = htons(IpHdr::calcChecksum(&(pkt->ip_)));
        pkt->tcp_.th_sum = htons(TcpHdr::calcChecksum(&(pkt->ip_), &(pkt->tcp_)));

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(pkt), header->caplen);
        if (res != 0)
        {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        else printf("Backward Success!!\n");

    }
    free(pkt);
}