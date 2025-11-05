// (hyungoo)
#define _POSIX_C_SOURCE 200809L
#include <semaphore.h>
#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include "../common_hyungoo/shm_ipc.h"
#include "../common_hyungoo/ips_event.h"
#include "ts_packet_queue.h"
#include "common.h" // ThreadArgs 사용
#include "ids_log.h"
#include <stdlib.h>

static shm_ipc_t g_ipc;
static volatile sig_atomic_t* g_is_running;

static void* shm_consumer_loop(void* arg){
  ThreadArgs* thread_args = (ThreadArgs*)arg;
    PacketQueue* packetQueue = thread_args->packetQueue;

    printf(" -> [OK] SHM 이벤트 소비자 스레드가 동작을 시작합니다.\n");

    while (*g_is_running) {
        struct timespec ts;
        // 200ms 타임아웃으로 세마포어 대기
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 200 * 1000 * 1000L; // 200 milliseconds
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000L;
        }

        // IPS가 sem_post()를 호출할 때까지 여기서 대기 (타임아웃 포함)
        int ret = sem_timedwait(g_ipc.sem, &ts);
        if (ret == -1) {
            // 타임아웃이거나 인터럽트된 경우, is_running 플래그 확인 후 계속
            if (!(*g_is_running)) break;
            continue;
        }

        // 링 버퍼에 있는 모든 이벤트를 꺼내서 처리
        ips_event_t ev;
        while (ips_ring_pop(g_ipc.ring, &ev)) {
            // [핵심 로직]
            // 1. 수신된 이벤트를 로그로 출력 (기존 ids_log_event 활용)
            printf("[IDS-Consumer] Received event from SHM. Rule ID: %u, Verdict: %s\n",
                   ev.rule_id, ev.verdict ? "DROP" : "ACCEPT");
            ids_log_event(&ev);

            // 2. 이벤트의 Raw Packet 부분을 IDS 내부의 PacketQueue에 넣는다.
            if (ev.caplen > 0) {
                RawPacket* new_packet = (RawPacket*)malloc(sizeof(RawPacket));
                if (new_packet) {
                    // caplen이 MAX_PACKET_SIZE를 넘지 않도록 보장
                    unsigned int copy_len = ev.caplen > MAX_PACKET_SIZE ? MAX_PACKET_SIZE : ev.caplen;
                    memcpy(new_packet->data, ev.data, copy_len);
                    new_packet->len = copy_len;
                    
                    tsPacketqPush(packetQueue, new_packet);
                }
            }
        }
    }
    
    printf("SHM 이벤트 소비자 스레드가 종료됩니다.\n");
    return NULL;
  /*
    (void)arg;
    for(;;){
        struct timespec ts;
        // 200ms 타임아웃 대기
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 200*1000*1000L;
        if (ts.tv_nsec >= 1000000000L){ ts.tv_sec+=1; ts.tv_nsec-=1000000000L; }
        // 타임아웃 대기
        (void)sem_timedwait(g_ipc.sem, &ts);
        
        // drain
        ips_event_t ev;
        while (ips_ring_pop(g_ipc.ring, &ev)){
            ids_log_event(&ev); // 대시보드/세션탭으로 올릴 핵심 근거
        }
    }
    return NULL;
  */
}

int shm_consumer_start(ThreadArgs* args){
  if (shm_ipc_open(&g_ipc, /*create=*/0) != 0) {
    perror("SHM attach failed. Is the IPS process running first?");
    return -1;
  }

  g_is_running = args->isRunning;

  pthread_t th;
  if (pthread_create(&th, NULL, shm_consumer_loop, args) != 0) {
      perror("SHM consumer thread create failed");
      shm_ipc_close(&g_ipc);
      return -1;
  }

  pthread_detach(th);
  return 0;
}

void shm_consumer_stop(void) {
    shm_ipc_close(&g_ipc);
}