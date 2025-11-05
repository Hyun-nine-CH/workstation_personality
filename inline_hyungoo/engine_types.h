#pragma once
#include <stdint.h>
#include <sys/time.h>

typedef enum { VERDICT_ACCEPT=0, VERDICT_DROP=1 } verdict_t;

typedef struct {
  uint32_t saddr, daddr;  // IPv4 (network byte order)
  uint16_t sport, dport;  // host order
  uint8_t  l4proto;       // TCP=6, UDP=17, ICMP=1 ...
} five_tuple_t;

typedef struct {
  uint32_t pkt_id;        // NFQ packet id (host order)
  uint16_t hwproto;       // ETH_P_IP 등 (옵션)
  struct timeval ts;      // **NFQ 콜백 수신 시각**
  five_tuple_t ft;
  uint32_t snaplen;       // 스냅샷 길이(보통 0 또는 ≤1600)
  uint8_t*  snap;         // 스냅 포인터(옵션)
  void*     nfq_handle;   // qh (opaque)
} job_t;

typedef struct {
  verdict_t verdict;
  uint32_t  mark;         // fwmark/classid (옵션)
  char      reason[64];   // DROP 사유 (예: "BLOCKME")
} decision_t;

