#include "decider.h"
#include "ui_tap.h"

#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

static inline uint16_t ms_since(const struct timeval* t0){
    struct timeval now; gettimeofday(&now, NULL);
    long ms = (now.tv_sec - t0->tv_sec)*1000 + (now.tv_usec - t0->tv_usec)/1000;
    if (ms < 0) {
        ms = 0;
    } else if (ms > 65535) {
        ms = 65535;
    }
    return (uint16_t)ms;
}
static inline const char* proto_str(uint8_t p){
    return p==6?"TCP":(p==17?"UDP":(p==1?"ICMP":"UNK"));
}
static inline const char* verdict_str(verdict_t v){
    return v==VERDICT_DROP?"DROP":"ACCEPT";
}

void decider_apply(struct nfq_q_handle* qh,
                   const job_t* job,
                   const decision_t* dec,
                   const char* dir_hint)
{
    // 1) VERDICT 텔레메트리 전송
    ui_tap_msg_t u = {0};
    gettimeofday(&u.ts, NULL);
    u.stage   = UI_STAGE_VERDICT;
    u.pkt_id  = job->pkt_id;
    u.saddr   = job->ft.saddr; u.daddr = job->ft.daddr;
    u.sport   = job->ft.sport; u.dport = job->ft.dport;
    u.len     = job->snaplen;
    snprintf(u.proto, sizeof(u.proto), "%s", proto_str(job->ft.l4proto));
    snprintf(u.dir,   sizeof(u.dir),   "%s", dir_hint?dir_hint:"FWD");
    snprintf(u.verdict, sizeof(u.verdict), "%s", verdict_str(dec->verdict));
    u.latency_ms = ms_since(&job->ts);
//    snprintf(u.reason, sizeof(u.reason), "%s", dec->reason[0]?dec->reason:"");

    // dec->reason이 길어도 u.reason(32B)에 안전하게 잘라 넣기
    snprintf(u.reason, sizeof(u.reason), "%.*s", (int)sizeof(u.reason) - 1, dec->reason[0] ? dec->reason : "");
    ui_tap_emit(&u);

    // 2) 커널로 최종 verdict
    uint32_t v = (dec->verdict==VERDICT_DROP) ? NF_DROP : NF_ACCEPT;
//    nfq_set_verdict(qh, job->pkt_id, v, 0, NULL);
    nfq_set_verdict2(qh, job->pkt_id, v, dec->mark /*fwmark*/, 0, NULL);
}

