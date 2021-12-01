#pragma once
#include <stdint.h>
#include "iphdr.h"

#pragma pack(push, 1)
struct TcpHdr final {
    uint16_t th_sport;       /* source port */
    uint16_t th_dport;       /* destination port */
    uint32_t th_seq;          /* sequence number */
    uint32_t th_ack;          /* acknowledgement number */

    uint8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */

    uint8_t  th_flags;       /* control flags */

    uint16_t th_win;         /* window */
    uint16_t th_sum;         /* checksum */
    uint16_t th_urp;         /* urgent pointer */

    uint16_t sum() { return ntohs(th_sum); }
    
    static uint16_t calcChecksum(IpHdr* ipHdr, TcpHdr* tcpHdr);
};

typedef TcpHdr *PTcpHdr;
#pragma pack(pop)