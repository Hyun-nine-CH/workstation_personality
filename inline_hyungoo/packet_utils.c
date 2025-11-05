#define _DEFAULT_SOURCE
#include "packet_utils.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>

int parse_ipv4_tuple(const unsigned char* buf, uint32_t len, ip4_tuple_t* o) {
    if (!buf || !o || len < sizeof(struct iphdr)) return -1;
    const struct iphdr* ip = (const struct iphdr*)buf;
    if (ip->version != 4) return -1;

    uint32_t ihl = ip->ihl * 4u;
    if (ihl < sizeof(struct iphdr) || ihl > len) return -1;

    struct in_addr s = { .s_addr = ip->saddr };
    struct in_addr d = { .s_addr = ip->daddr };

    if (!inet_ntop(AF_INET, &s, o->src, sizeof(o->src))) return -1;
    if (!inet_ntop(AF_INET, &d, o->dst, sizeof(o->dst))) return -1;

    o->proto = (uint8_t)ip->protocol;
    o->sport = 0;
    o->dport = 0;

    if (ip->protocol == IPPROTO_TCP) {
        if (len < ihl + sizeof(struct tcphdr)) return 0; // not enough
        const struct tcphdr* th = (const struct tcphdr*)(buf + ihl);
        o->sport = (uint16_t)ntohs(th->source);
        o->dport = (uint16_t)ntohs(th->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        if (len < ihl + sizeof(struct udphdr)) return 0; // not enough
        const struct udphdr* uh = (const struct udphdr*)(buf + ihl);
// glibc [netinet/udp.h]-> uh_sport/uh_dport, one of the header-> source/dst
// #ifdef uh_sport
        o->sport = (uint16_t)ntohs(uh->uh_sport);
        o->dport = (uint16_t)ntohs(uh->uh_dport);
// #else
//        o->sport = (uint16_t)ntohs(*(uint16_t*)((char*)uh + 0));
//        o->dport = (uint16_t)ntohs(*(uint16_t*)((char*)uh + 2));
// #endif
    }
    return 0;
}

// 문자열 기반 ip4_tuple_t -> 숫자형 five_tuple 변환
int ip4_tuple_to_five_tuple(const ip4_tuple_t* in, five_tuple* out){
    if (!in || !out) return -1;
    struct in_addr sa = {0}, da = {0};
    if (inet_pton(AF_INET, in->src, &sa) != 1) return -1;
    if (inet_pton(AF_INET, in->dst, &da) != 1) return -1;
    out->saddr = sa.s_addr; // network-byte-order
    out->daddr = da.s_addr; // network-byte-order
    out->sport = in->sport;
    out->dport = in->dport;
    out->proto = in->proto;
    return 0;
}

// 간단한 32비트 해시 (회전+섞기)
static inline uint32_t rotl32(uint32_t x, int r){ return (x<<r) | (x>>(32-r)); }
uint32_t flow_hash_v4(const five_tuple* f){
    if (!f) return 0;
    uint32_t h = 0x9e3779b9u;                         // golden ratio
    h ^= f->saddr + rotl32(f->daddr, 16);
    h ^= ((uint32_t)f->sport << 16) | f->dport;
    h ^= ((uint32_t)f->proto << 24);
    h ^= rotl32(h,13) * 0x85ebca6bU;                  // mix
    h ^= h >> 16;
    if (h == 0) h = 1;                                // 0 회피
    return h;
}
