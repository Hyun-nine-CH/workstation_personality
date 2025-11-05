#pragma once
#include <stdint.h>

typedef struct {
    char     src[16];
    char     dst[16];
    uint16_t sport;
    uint16_t dport;
    uint8_t  proto;
} ip4_tuple_t;

int parse_ipv4_tuple(const unsigned char* buf, uint32_t len, ip4_tuple_t* out);

// 숫자형 5-튜플(IPv4). 주소는 network-byte-order(inet_pton 그대로)로 저장.
typedef struct {
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    uint8_t  proto;
} five_tuple;

// ip4_tuple_t(문자열 주소) -> five_tuple(숫자 주소) 변환
int ip4_tuple_to_five_tuple(const ip4_tuple_t* in, five_tuple* out);

// 흐름 해시(간단/충돌저항 보강 믹스)
uint32_t flow_hash_v4(const five_tuple* f);
