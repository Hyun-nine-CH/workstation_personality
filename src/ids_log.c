// (hyungoo)
// ids_log.c (임시 구현: STDOUT 또는 파일/ELK로 변경 가능)
#include <stdio.h>
#include <inttypes.h>
#include "ids_log.h"

void ids_log_event(const ips_event_t* ev){
  
  fprintf(stdout,
    "[IPS-EVENT] ts=%" PRIu64 "verdict=%s rule=%u score=%u "
    "flow=%u %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u cap=%u tot=%u proto=%u\n",
    ev->ts_ns,
    ev->verdict ? "DROP" : "ACCEPT",
    ev->rule_id, ev->risk_score,
    ev->flow_hash,
    (ev->saddr)&255, (ev->saddr>>8)&255, (ev->saddr>>16)&255, (ev->saddr>>24)&255, ev->sport,
    (ev->daddr)&255, (ev->daddr>>8)&255, (ev->daddr>>16)&255, (ev->daddr>>24)&255, ev->dport,
    ev->caplen, ev->tot_len, ev->proto
  );
  // TODO: 세션 UI 탭/대시보드 전송, NFLOG 패킷과 5tuple+ts로 상관관계 매칭

  }
