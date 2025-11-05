#pragma once
#include <stdint.h>

// event snapshot bytes n (dash board/log)
#ifndef IPS_EVENT_SNAPLEN
#define IPS_EVENT_SNAPLEN 160
#endif

// NFQueue -> Kernel<->User copy bytes (in-line analysis)
#ifndef IPS_NFQ_COPY_BYTES
#define IPS_NFQ_COPY_BYTES 1600
#endif

typedef struct {
    uint64_t ts_ns; // realtime ns unit
    uint8_t verdict; // 0=ACCEPT, 1=DROP
    uint16_t rule_id; // engine inner rules ID
    uint16_t risk_score; // weighting score

    uint8_t proto; // IPPROTO_*: TCP/UDP/...

    uint32_t saddr; // IPv4 network byte order
    uint32_t daddr; // IPv4 network byte order
    uint16_t sport; // host byte order
    uint16_t dport; // host byte order

    uint32_t flow_hash; // 5tuple hash(IDS 매칭 키)
    uint16_t tot_len; // raw packet tot len
    uint16_t caplen; // snapshot length (<= event len)
    uint8_t data[IPS_EVENT_SNAPLEN]; // payload snapshot(H+|a|)
} ips_event_t;
