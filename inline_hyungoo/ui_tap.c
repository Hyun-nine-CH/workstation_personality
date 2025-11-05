#define _GNU_SOURCE
#include "ui_tap.h"
#if UI_TAP_ENABLE

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <stdatomic.h>

typedef struct {
    ui_tap_msg_t* buf; size_t cap, head, tail;
    pthread_mutex_t m; pthread_cond_t  cv;
} ring_t;

static int sockfd=-1;
static struct sockaddr_in dst;
static pthread_t th;
static ring_t rq;
static volatile int running=0;
static _Atomic uint64_t dropped=0;

static int ring_init(ring_t* q, size_t cap){
    q->buf = (ui_tap_msg_t*)calloc(cap, sizeof(ui_tap_msg_t));
    if(!q->buf) return -1;
    q->cap=cap; q->head=q->tail=0;
    pthread_mutex_init(&q->m, NULL);
    pthread_cond_init(&q->cv, NULL);
    return 0;
}
static void ring_fini(ring_t* q){
    if(q->buf) free(q->buf);
    pthread_mutex_destroy(&q->m);
    pthread_cond_destroy(&q->cv);
}
static int ring_push_nb(ring_t* q, const ui_tap_msg_t* m){
    if(pthread_mutex_trylock(&q->m)!=0){ dropped++; return -1; }
    size_t next=(q->head+1)%q->cap;
    if(next==q->tail){ pthread_mutex_unlock(&q->m); dropped++; return -1; }
    q->buf[q->head]=*m; q->head=next;
    pthread_cond_signal(&q->cv);
    pthread_mutex_unlock(&q->m);
    return 0;
}
static int ring_pop(ring_t* q, ui_tap_msg_t* out, int to_ms){
    struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts);
    ts.tv_sec+=to_ms/1000; ts.tv_nsec+=(to_ms%1000)*1000000L;
    if(ts.tv_nsec>=1000000000L){ ts.tv_sec++; ts.tv_nsec-=1000000000L; }
    pthread_mutex_lock(&q->m);
    while(q->head==q->tail && running){
        if(pthread_cond_timedwait(&q->cv,&q->m,&ts)==ETIMEDOUT){
            pthread_mutex_unlock(&q->m); return 0;
        }
    }
    if(!running){ pthread_mutex_unlock(&q->m); return 0; }
    *out=q->buf[q->tail]; q->tail=(q->tail+1)%q->cap;
    pthread_mutex_unlock(&q->m);
    return 1;
}
static void ip4str(uint32_t be, char* out, size_t n){
    struct in_addr a={.s_addr=be}; const char* s=inet_ntoa(a);
    snprintf(out,n,"%s", s?:"0.0.0.0");
}

static void* sender(void* _){
    (void)_; ui_tap_msg_t m; char js[512];
    while(running){
        int got=ring_pop(&rq,&m,100); if(!running) break; if(got!=1) continue;
        char sa[32],da[32]; ip4str(m.saddr,sa,sizeof(sa)); ip4str(m.daddr,da,sizeof(da));
        double ts=(double)m.ts.tv_sec + (double)m.ts.tv_usec/1e6;

        int len = snprintf(js, sizeof(js),
            "{\"stage\":%d,\"ts\":%.6f,\"pkt_id\":%u,"
            "\"dir\":\"%s\",\"len\":%u,"
            "\"ft\":{"
                "\"proto\":\"%s\","
                "\"saddr\":\"%s\",\"sport\":%u,"
                "\"daddr\":\"%s\",\"dport\":%u"
            "},"
            "\"verdict\":\"%s\",\"lat_ms\":%u,\"reason\":\"%s\"}\n",
            (int)m.stage, ts, m.pkt_id,
            m.dir, m.len,
            m.proto,
            sa, (unsigned)m.sport,
            da, (unsigned)m.dport,
            m.verdict, (unsigned)m.latency_ms, m.reason);

        if(len>0){
            (void)sendto(sockfd, js, (size_t)len, MSG_DONTWAIT,
                         (struct sockaddr*)&dst, sizeof(dst));
        }
    }
    return NULL;
}

int ui_tap_start(const char* host, uint16_t port, size_t cap){
    if(running) return 0;
    sockfd=socket(AF_INET,SOCK_DGRAM,0); if(sockfd<0) return -1;

    // ★ 추가: 송신버퍼/재사용 옵션 (드랍 감소)
    int snd = 1<<20;  // 1MB
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
    int reuse = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    memset(&dst,0,sizeof(dst));
    dst.sin_family=AF_INET; dst.sin_port=htons(port);
    if(inet_pton(AF_INET, host?host:"127.0.0.1", &dst.sin_addr)!=1){
        close(sockfd); sockfd=-1; return -1;
    }
    if(cap<4096) cap=4096;
    if(ring_init(&rq,cap)!=0){ close(sockfd); sockfd=-1; return -1; }
    dropped=0; running=1;
    if(pthread_create(&th,NULL,sender,NULL)!=0){
        running=0; ring_fini(&rq); close(sockfd); sockfd=-1; return -1;
    }
    return 0;
}
void ui_tap_stop(void){
    if(!running) return;
    running=0;
    pthread_mutex_lock(&rq.m);
    pthread_cond_broadcast(&rq.cv);
    pthread_mutex_unlock(&rq.m);
    pthread_join(th,NULL);
    ring_fini(&rq);
    if(sockfd>=0){ close(sockfd); sockfd=-1; }
}
void ui_tap_emit(const ui_tap_msg_t* m){
    if(!running||!m) return;
    (void)ring_push_nb(&rq,m);
}
uint64_t ui_tap_dropped(void){ return dropped; }

#else
int  ui_tap_start(const char* h,uint16_t p,size_t c){ (void)h;(void)p;(void)c; return 0; }
void ui_tap_stop(void){}
void ui_tap_emit(const ui_tap_msg_t* m){ (void)m; }
uint64_t ui_tap_dropped(void){ return 0; }
#endif

