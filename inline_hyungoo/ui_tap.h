#pragma once
#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef UI_TAP_ENABLE
#define UI_TAP_ENABLE 1   // 0으로 빌드하면 전부 no-op
#endif

typedef enum { UI_STAGE_PRE=0, UI_STAGE_VERDICT=1 } ui_stage_t;

typedef struct {
    ui_stage_t stage;      // 0=PRE, 1=VERDICT
    struct timeval ts;     // 이 stage의 시각

    // 식별/튜플
    uint32_t pkt_id;       // NFQ packet id
    uint32_t saddr;        // IPv4 network byte order (use inet_ntop on emit)
    uint32_t daddr;        // IPv4 network byte order
    uint16_t sport;        // host byte order
    uint16_t dport;        // host byte order
    uint16_t len;          // 0 ~ 65535
    char     proto[8];     // "TCP"/"UDP"/"ICMP"/"UNK"
    char     dir[16];      // "WAN->LAN"/"LAN->WAN"/"FWD" 등

    // VERDICT 부가정보
    char     verdict[8];   // PRE: "" , VERDICT: "ACCEPT"/"DROP"
    uint16_t latency_ms;   // VERDICT면 (now - pre.ts), PRE면 0
    char     reason[32];   // DROP 사유(옵션)
} ui_tap_msg_t;

int  ui_tap_start(const char* host, uint16_t port, size_t queue_cap);
void ui_tap_stop(void);
void ui_tap_emit(const ui_tap_msg_t* m);  // 콜백에서 호출(논블로킹)
uint64_t ui_tap_dropped(void);

#ifdef __cplusplus
}
#endif

