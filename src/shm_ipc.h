// shm_ipc.h
#ifndef SHM_IPC_H
#define SHM_IPC_H

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <semaphore.h>
#include "rawPacket.h"

#define SHM_NAME "/argus_ips_ids_ring"
#define PKT_MAX 512 // 공유 버퍼에 저장할 수 있는 최대 패킷 수

// 공유 메모리 버퍼 구조체
typedef struct {
    pthread_mutex_t lock; // 공유 버퍼 접근을 위한 뮤텍스
    pthread_cond_t cond_read; // 데이터가 있음을 알리는 조건 변수
    pthread_cond_t cond_write; // 공간이 있음을 알리는 조건 변수
    int write_idx; // 다음 데이터를 쓸 위치
    int read_idx; // 다음 데이터를 읽을 위치
    int count; // 버퍼에 있는 데이터 개수
    RawPacket packets[PKT_MAX]; // 실제 데이터 저장 공간 (순환 버퍼)
} SharedPacketBuffer;

#endif // SHM_IPC_H