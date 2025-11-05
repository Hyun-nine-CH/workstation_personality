#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include "ts_packet_queue.h"
#include "../common_hyungoo/shm_ipc.h" // 공유 메모리 구조체 정의 포함
#include "thread_shm_receiver.h"

// 공유 메모리 수신 스레드 메인 함수
void* shm_receiver_thread_main(void* args){
    ThreadArgs* thread_args = (ThreadArgs*)args;
    PacketQueue* packetQueue = thread_args->packetQueue;
    // 메인에서 넘겨받은 공유 메모리 포인터
    SharedPacketBuffer* sharedBuffer = thread_args->sharedBuffer;
    volatile sig_atomic_t* isRunning = thread_args->isRunning;

    printf(" -> [OK] 공유 메모리 수신 스레드가 동작을 시작합니다.\n");

    while(*isRunning){
        // 1. 공유 메모리에서 패킷 데이터 읽기 (소비자)
        pthread_mutex_lock(&sharedBuffer->lock);
        // 버퍼가 비어있고 프로그램이 실행 중이면 대기
        while(sharedBuffer->count == 0 && *isRunning){
            pthread_cond_wait(&sharedBuffer->cond_read, &sharedBuffer->lock);
        }
        // * while 내부에서 *isRunning 추가 체크
        if (!*isRunning) {  
            pthread_mutex_unlock(&sharedBuffer->lock);
            break; // 즉시 종료
        }

        // 공유 메모리에서 읽어올 패킷의 메타데이터
        unsigned int packet_len_from_shm = sharedBuffer->packets[sharedBuffer->read_idx].len;

        // 공유 메모리의 길이 값이 유효한지 검사
        if (packet_len_from_shm == 0 || packet_len_from_shm > MAX_PACKET_SIZE) {
            fprintf(stderr, "[SHM Receiver] Error: Invalid packet length %u in shared memory. Skipping.\n", packet_len_from_shm);
            // 이 데이터는 오염되었을 가능성이 높으므로 그냥 버리고 인덱스만 증가
            sharedBuffer->read_idx = (sharedBuffer->read_idx + 1) % PKT_MAX;
            sharedBuffer->count--;
            pthread_mutex_unlock(&sharedBuffer->lock);
            continue;
        }

        // 공유 메모리 버퍼에서 데이터 꺼내기
        RawPacket* received_packet = (RawPacket*)malloc(sizeof(RawPacket));
        if(received_packet == NULL){
            pthread_mutex_unlock(&sharedBuffer->lock);
            // 메모리 할당 실패
            continue; 
        }
        // 공유 메모리 내용을 새 메모리 공간으로 복사
        // rawpacket 구조 변경으로 필요없음.
        /*
        received_packet->len = sharedBuffer->packets[sharedBuffer->read_idx].len;
        received_packet->data = (unsigned char*)malloc(received_packet->len);
        if(received_packet->data == NULL){
            free(received_packet);
            pthread_mutex_unlock(&sharedBuffer->lock);
            continue;
        }
        */
        // memcpy(received_packet->data, sharedBuffer->packets[sharedBuffer->read_idx].data, received_packet->len);
        memcpy(received_packet, &sharedBuffer->packets[sharedBuffer->read_idx], sizeof(RawPacket));
        // 공유 메모리 버퍼 인덱스 및 카운트 업데이트
        sharedBuffer->read_idx = (sharedBuffer->read_idx + 1) % PKT_MAX;
        sharedBuffer->count--;
        // 버퍼에 공간이 생김을 alert
        pthread_cond_signal(&sharedBuffer->cond_write);
        pthread_mutex_unlock(&sharedBuffer->lock);

        // 2. IDS 내부의 PacketQueue 에 패킷 넣기
        // if(received_packet){
            printf("[SHM Receiver] 공유 메모리로부터 패킷을 받음, len : %u\n", received_packet->len);
            tsPacketqPush(packetQueue, received_packet);
        // }
    }

    printf("공유 메모리 수신 스레드가 종료됩니다.\n");
    return NULL;
}