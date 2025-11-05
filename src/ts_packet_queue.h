// ts_packet_queue.h
#ifndef TS_PACKET_QUEUE_H
#define TS_PACKET_QUEUE_H

#include <pthread.h>
#include <signal.h>
#include "common.h" // RawPacket 구조체를 사용하기 위해 포함

// 큐를 초기화하는 함수
// isRunning 포인터를 받아야 Graceful Shutdown 시 대기중인 스레드를 깨울 수 있음
void tsPacketqInit(PacketQueue* q, volatile sig_atomic_t* isRunningFlag);

// 큐에 새로운 패킷을 추가하는 함수
void tsPacketqPush(PacketQueue* q, RawPacket* packet);

// 큐에서 패킷을 꺼내는 함수
// 큐가 비어있으면 데이터가 들어오거나 종료 신호가 올 때까지 대기
RawPacket* tsPacketqPop(PacketQueue* q);

// 큐의 모든 자원을 해제하는 함수
void tsPacketqDestroy(PacketQueue* q);

// 프로그램 종료 시, 큐에서 대기 중인 스레드를 깨우는 함수
void tsPacketqSignalExit(PacketQueue* q);

#endif // TS_PACKET_QUEUE_H