#pragma once
#include <semaphore.h>
#include "ips_ring.h"

// process간 공유, 한번 만 정의
#define ARGUS_SHM_NAME "/argus_ips_ids_ring"
#define ARGUS_SEM_NAME "/argus_ips_ids_sem"

typedef struct {
    int shm_fd;
    ips_ring_t* ring; // mmapped ring(memory에 mapping)
    sem_t* sem; // IPS: post, IDS: timed wait(생산->소비 시그널)
} shm_ipc_t;

// create=1: shm/sem 생성은 IPS, create=0: 소비는 IDS인 체계
int shm_ipc_open (shm_ipc_t* ipc, int create); // IPS=1, IDS=0
void shm_ipc_close(shm_ipc_t* ipc);
int shm_ipc_unlink_all(void);
