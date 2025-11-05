#include "nfq_iface.h"
#include "packet_utils.h"
#include "ruleset.h"
#include "../common_hyungoo/shm_ipc.h"
#include "../common_hyungoo/ips_event.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <signal.h> // g_run extern type
#include <sys/socket.h> // recv()
#include <arpa/inet.h>
#include <linux/netfilter.h> // NF_ACCEPT/NF_DROP

#include <semaphore.h> // sem_post
#include <linux/netlink.h>

// Pre/Vedict telemetry & decider header
#include "engine_types.h"
#include "ui_tap.h"
#include "decider.h"
#include <net/if.h> // if_nametoindex

// post-accept 이중 미러를 사용할 때 1로 설정하면,
// ACCEPT verdict에 skb mark 0x1을 세팅
#ifndef USE_POST_ACCEPT_MARK
#define USE_POST_ACCEPT_MARK 0
#endif

extern shm_ipc_t g_ipc; // main_nfq.c에서 생성된 SHM 핸들 사용
extern volatile sig_atomic_t g_run;

// === runtime tuning knobs defaults ===
static uint16_t g_queue_num = 0; // default Q 0
static unsigned g_copy_bytes = 1600; // NFQNL_COPY_PACKET range
static unsigned g_queue_maxlen = 4096; // 4096 ~ 65535
static unsigned g_rcvbuf_mb = 8; // netlink socket RCVBUF[MiB]

// utility_dir/protocol
static unsigned if_wan = 0, if_lan = 0, if_br = 0;
static void init_ifindex(void){
    if_wan=if_nametoindex("enp0s1"); // WAN NIC
    if_lan=if_nametoindex("enp0s2"); // LAN NIC
    if_br=if_nametoindex("br-demo"); // not exist = 0
}

static inline int is_lan_if(int ifi){ // ADD
    return (ifi==(int)if_lan) || (if_br && ifi==(int)if_br);
}
static inline const char* dir_from(int indev, int outdev){
    if (indev==(int)if_wan && is_lan_if(outdev)) return "WAN->LAN"; // MOD
    if (is_lan_if(indev)   && outdev==(int)if_wan) return "LAN->WAN"; // MOD
    return "FWD";
}

static inline const char* proto_str_num(uint8_t p){
    switch(p){ case 6: return "TCP"; case 17: return "UDP"; case 1: return "ICMP"; default: return "UNK"; }
}

// setting
void nfq_cfg_set_qnum(uint16_t qnum){ g_queue_num = qnum; }
void nfq_cfg_set_copy(unsigned bytes){ if(bytes) g_copy_bytes = bytes; }
void nfq_cfg_set_qlen(unsigned qlen){ if(qlen) g_queue_maxlen = qlen; }
void nfq_cfg_set_rcvbuf_mb(unsigned mb){ if(mb) g_rcvbuf_mb = mb; }

static inline uint64_t now_ns(){
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec*1000000000ull + ts.tv_nsec;
}

static int cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
              struct nfq_data* nfa, void* data) {
    (void)nfmsg; (void)data;

    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) return 0;
    uint32_t id = ntohl(ph->packet_id);

    unsigned char* payload = NULL;
    int plen = nfq_get_payload(nfa, &payload);
    if (plen < 0) plen = 0;

    ip4_tuple_t t = (ip4_tuple_t){0};
    (void)parse_ipv4_tuple(payload, (uint32_t)plen, &t); // t.src,t.dst(char*), t.sport,t.dport, t.proto 채움

    // job_t + Pre telemetry str
    job_t job=(job_t){0};
    job.pkt_id=id;
    gettimeofday(&job.ts, NULL);
    five_tuple_t ft=(five_tuple_t){0};
    ft.l4proto=t.proto;
    {
        struct in_addr sa={0}, da={0};
        if (inet_pton(AF_INET, t.src, &sa)==1) ft.saddr=sa.s_addr;
        if (inet_pton(AF_INET, t.dst, &da)==1) ft.daddr=da.s_addr;
        ft.sport=t.sport;
        ft.dport=t.dport;
    }
    job.ft=ft;
    job.snaplen=(uint32_t)plen;
    job.nfq_handle=qh;

    int indev=nfq_get_indev(nfa);
    int outdev=nfq_get_outdev(nfa);
    const char* dir=dir_from(indev, outdev);

    ui_tap_msg_t um={0};
    um.stage=UI_STAGE_PRE;
    um.ts=job.ts;
    um.pkt_id=id;
    um.saddr=job.ft.saddr; um.daddr=job.ft.daddr;
    um.sport=job.ft.sport; um.dport=job.ft.dport;
    um.len=(uint16_t)((plen<=0) ? 0 : (plen>65535 ? 65535 : plen));
    snprintf(um.proto, sizeof(um.proto), "%s", proto_str_num(job.ft.l4proto));
    snprintf(um.dir, sizeof(um.dir), "%s", dir);
    ui_tap_emit(&um);
    // === END telemetry Pre ===

    int rid = -1;
    const int matched = ruleset_match(payload, (uint32_t)plen, &rid);
    const int drop = matched ? 1 : 0;

    if (drop) {
        printf("[NFQ] id=%u %s:%u -> %s:%u  verdict=DROP rule=%d\n", id, t.src, t.sport, t.dst, t.dport, rid);
        // nfq_set_verdict2(qh, id, NF_DROP, 0x0, 0, NULL);
    } else {
        printf("[NFQ] id=%u %s:%u -> %s:%u  verdict=ACCEPT\n", id, t.src, t.sport, t.dst, t.dport);
        // uint32_t mark = USE_POST_ACCEPT_MARK ? 0x1 : 0x0;
        // nfq_set_verdict2(qh, id, NF_ACCEPT, mark, 0, NULL);
    }

    // === decider -> verdict ===
    decision_t dec=(decision_t){0};
    dec.verdict=drop ? VERDICT_DROP : VERDICT_ACCEPT;
    dec.mark=(!drop && USE_POST_ACCEPT_MARK) ? 0x1 : 0x0;
    if(drop && rid>=0) snprintf(dec.reason,sizeof(dec.reason),"RULE_%d", rid);
    decider_apply(qh, &job, &dec, dir);
    // === END ===

    // === ★ 추가: VERDICT 텔레메트리(POST) ===
    {
        ui_tap_msg_t um2 = (ui_tap_msg_t){0};
        um2.stage  = UI_STAGE_VERDICT;        // 1
        um2.ts     = job.ts;                  // verdict 시각(간단히 pre와 동일하게)
        um2.pkt_id = id;

        um2.saddr = job.ft.saddr;  um2.daddr = job.ft.daddr;
        um2.sport = job.ft.sport;  um2.dport = job.ft.dport;
        um2.len   = (uint16_t)((plen<=0) ? 0 : (plen>65535 ? 65535 : plen));

        snprintf(um2.proto, sizeof(um2.proto), "%s", proto_str_num(job.ft.l4proto));
        snprintf(um2.dir,   sizeof(um2.dir),   "%s", dir);

        // "ACCEPT"/"DROP" 문자열 채우기
        snprintf(um2.verdict, sizeof(um2.verdict), "%s", drop ? "DROP" : "ACCEPT");

        // 간단한 latency 계산(옵션): 지금-Pre 시각
        struct timeval now; gettimeofday(&now, NULL);
        long dms = (now.tv_sec - job.ts.tv_sec) * 1000L + (now.tv_usec - job.ts.tv_usec)/1000L;
        if (dms < 0) dms = 0;
        um2.latency_ms = (uint16_t)((dms > 65535) ? 65535 : dms);

        // DROP 사유
        if (drop && rid >= 0)
            snprintf(um2.reason, sizeof(um2.reason), "RULE_%d", rid);
        else
            um2.reason[0] = '\0';

        ui_tap_emit(&um2);
    }
    // === ★ 추가 끝 ===

    // ---- SHM 이벤트 (단방향 텔레메트리) ----
    // IDS에 ACCEPT된 Packets만 Shared Memory로 Push하려면,
    if (!drop) {
        ips_event_t ev; memset(&ev, 0, sizeof(ev));
        ev.ts_ns      = now_ns();
//        ev.verdict    = (uint8_t)(drop ? 1 : 0);
        ev.verdict    = (uint8_t)dec.verdict;      // ACCEPT(=0/1 정의에 맞춤)
        ev.rule_id    = (uint16_t)(rid >= 0 ? rid : 0);
        ev.risk_score = 0;               // 필요 시 ruleset 확장
        ev.proto      = t.proto;

        struct in_addr sa = {0}, da = {0};
        if (inet_pton(AF_INET, t.src, &sa) == 1) ev.saddr = sa.s_addr;
        if (inet_pton(AF_INET, t.dst, &da) == 1) ev.daddr = da.s_addr;
        ev.sport = t.sport;
        ev.dport = t.dport;

        // flow hash (packet_utils에 구현)
        five_tuple ft_ev;
        if (ip4_tuple_to_five_tuple(&t, &ft_ev) == 0) {
            ev.flow_hash = flow_hash_v4(&ft_ev); // Or, flow_hash64_v4(&ft_ev)
        } else {
            ev.flow_hash = 1;
        }

        if (plen > 0) {
            ev.tot_len=(uint16_t)plen;
            ev.caplen = (uint16_t)((plen < IPS_EVENT_SNAPLEN) ? plen : IPS_EVENT_SNAPLEN);
            memcpy(ev.data, payload, ev.caplen);
        }
        if (g_ipc.ring) {
            if (ips_ring_push(g_ipc.ring, &ev) && g_ipc.sem) {
                sem_post(g_ipc.sem);
            }
        }
    } // ACCEPT only traffic_>ids
    return 0;
}

struct nfq_handle* nfq_setup(struct nfq_q_handle** out_qh, uint16_t qnum) {
    struct nfq_handle* h = nfq_open();
    if (!h) { perror("nfq_open"); return NULL; }

    nfq_unbind_pf(h, AF_INET);
    if (nfq_bind_pf(h, AF_INET) < 0) {
        perror("nfq_bind_pf"); goto fail_h;
    }

    struct nfq_q_handle* qh = nfq_create_queue(h, qnum, &cb, NULL);
    if (!qh) { perror("nfq_create_queue"); goto fail_h; }

    // 헤더+조금만 복사 (성능/부하 균형)
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, g_copy_bytes) < 0) {
        perror("nfq_set_mode");
        nfq_destroy_queue(qh); goto fail_h;
    }

    // Queue len increase
    if(nfq_set_queue_maxlen(qh, g_queue_maxlen)<0) {
        perror("nfq_set_queue_maxlen");
    }

    // netlink socket tuning
    int fd=nfq_fd(h);
    int one=1;
    if (setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &one, sizeof(one)) < 0) {
        perror("setsockopt(NETLINK_NO_ENOBUFS)");
    }
    int rcv = (int)g_rcvbuf_mb * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv)) < 0) {
        perror("setsockopt(SO_RCVBUF)");
    }

    // ifindex init
    init_ifindex();

    *out_qh = qh;
    return h;

fail_h:
    nfq_close(h);
    return NULL;
}

void nfq_teardown(struct nfq_handle* h, struct nfq_q_handle* qh) {
    if (qh) nfq_destroy_queue(qh);
    if (h) nfq_close(h);
}
// NFQueue main loop
int run_nfq(uint16_t qnum) {
    struct nfq_q_handle* qh=NULL;
    struct nfq_handle* h=nfq_setup(&qh, qnum); // queue 0 <= ;
    if (!h) return 1;

    const int fd = nfq_fd(h);
    int rv;
    char buf[65536];

    printf("[NFQ] listening on queue %u (Ctrl+C to stop)\n", (unsigned)qnum);

    while (g_run) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        
        struct timeval tv = {1, 0}; // 1초 timeout
        int ret = select(fd+1, &fds, NULL, NULL, &tv);
        
        if (ret > 0 && FD_ISSET(fd, &fds)) {
            rv = recv(fd, buf, sizeof(buf), 0);
            if (rv >= 0) nfq_handle_packet(h, buf, rv);
        } else if (ret < 0 && errno != EINTR) {
            perror("select");
            break;
        }
        // ret == 0 (timeout): 그냥 루프 돌면서 g_run 체크
    }

    nfq_teardown(h,qh);
    printf("[NFQ] bye\n");
    return 0;
}
