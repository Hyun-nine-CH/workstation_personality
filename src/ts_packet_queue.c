// ts_packet_queue.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "ts_packet_queue.h"

// 큐를 초기화하는 함수
void tsPacketqInit(PacketQueue* q, volatile sig_atomic_t* isRunningFlag) {
    if (q == NULL) return;

    q->head = NULL;
    q->tail = NULL;
    q->count = 0;
    q->isRunning = isRunningFlag;

    // 뮤텍스와 조건 변수 초기화
    if (pthread_mutex_init(&q->lock, NULL) != 0) {
        perror("PacketQueue 뮤텍스 초기화 실패");
        exit(EXIT_FAILURE);
    }
    if (pthread_cond_init(&q->cond, NULL) != 0) {
        perror("PacketQueue 조건 변수 초기화 실패");
        exit(EXIT_FAILURE);
    }
}

// 큐에 새로운 패킷을 추가하는 함수 (생산자 => 캡처 스레드)
void tsPacketqPush(PacketQueue* q, RawPacket* packet) {
    if (q == NULL || packet == NULL) return;

    // 새 노드 생성
    PacketNode* newNode = (PacketNode*)malloc(sizeof(PacketNode));
    if (newNode == NULL) {
        perror("PacketNode 메모리 할당 실패");
        return;
    }
    newNode->packet = packet;
    newNode->next = NULL;

    // 임계 구역(CS) 시작
    pthread_mutex_lock(&q->lock);

    if (q->tail == NULL) { // 큐가 비어있는 경우
        q->head = newNode;
        q->tail = newNode;
    } else { // 큐에 아이템이 있는 경우
        q->tail->next = newNode;
        q->tail = newNode;
    }
    q->count++;

    // printf("[Queue] PUSHED! count = %d. Signaling consumer.\n", q->count);
    // 큐가 비어있어서 잠들어 있을 수 있는 소비(ex. 파싱 스레드) 스레드를 깨움
    pthread_cond_signal(&q->cond);

    pthread_mutex_unlock(&q->lock);
    // 임계 구역 끝
}

// 큐에서 패킷을 꺼내는 함수 (소비자 => 파싱 스레드)
RawPacket* tsPacketqPop(PacketQueue* q) {
    if (q == NULL) return NULL;

    // printf("[Queue] POP trying to lock. count = %d\n", q->count);

    // 임계 구역 시작
    pthread_mutex_lock(&q->lock);

    // printf("[Queue] POP waiting on condition...\n");
    // 큐가 비어있고, 프로그램이 계속 실행 중이면, 데이터가 들어올 때까지 대기
    while (q->head == NULL && *(q->isRunning)) {
        // pthread_cond_wait은 뮤텍스를 잠시 풀고 대기 상태에 들어감.
        // 다른 스레드가 pthread_cond_signal/broadcast를 호출하면 깨어나면서 다시 뮤텍스를 잡음.
        pthread_cond_wait(&q->cond, &q->lock);
    }

    printf("[Queue] POP woke up! is_running=%d, head is %s\n", 
           *(q->isRunning), (q->head == NULL ? "NULL" : "NOT NULL"));

    // 루프를 빠져나온 이유가 프로그램 종료 신호 때문인지 확인
    if (*(q->isRunning) == 0 && q->head == NULL) {
        pthread_mutex_unlock(&q->lock);
        return NULL; // 큐가 비었고 종료 신호를 받았으므로 NULL 반환
    }

    // 큐에서 첫 번째 노드를 꺼냄
    PacketNode* nodeToPop = q->head;
    RawPacket* packet = nodeToPop->packet;
    q->head = nodeToPop->next;

    if (q->head == NULL) { // 큐가 비게 되면 tail도 NULL로 설정
        q->tail = NULL;
    }
    q->count--;

    // 노드 자체는 해제 (내부의 packet 데이터 X)
    free(nodeToPop);

    pthread_mutex_unlock(&q->lock);
    // 임계 구역 끝

    return packet; // 꺼낸 패킷 데이터 반환
}

// 큐의 모든 자원을 해제하는 함수
void tsPacketqDestroy(PacketQueue* q) {
    if (q == NULL) return;

    // 먼저 큐를 잠그고, 다른 스레드가 접근하지 못하도록 함
    pthread_mutex_lock(&q->lock);

    PacketNode* current = q->head;
    while (current != NULL) {
        PacketNode* to_free_node = current;
        // RawPacket* to_free_packet = current->packet;
        current = current->next;

        // if (to_free_packet) {
            // free(to_free_packet->data); // RawPacket 구조가 배열이므로 이 줄은 필요 없음
            // free(to_free_packet);
        // }
        if (to_free_node->packet) {
            fprintf(stderr, "Warning: A packet was left in the queue and will leak memory.\n");
        }
        free(to_free_node);
    }
    
    q->head = NULL;
    q->tail = NULL;
    q->count = 0;

    pthread_mutex_unlock(&q->lock);

    // 뮤텍스와 조건 변수 파괴
    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->cond);
}

// 프로그램 종료 시, 큐에서 대기 중인 스레드를 깨우는 함수
void tsPacketqSignalExit(PacketQueue* q) {
    if (q == NULL) return;
    
    // 대기 중인 소비자 스레드(tsPacketqPop)를 모두 깨우기 위해
    pthread_mutex_lock(&q->lock);
    // 뮤텍스를 잠시 잡고 조건 변수에 브로드캐스트 신호를 보냄
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->lock);
}