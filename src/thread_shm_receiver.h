#ifndef THREAD_SHM_RECEIVER_H
#define THREAD_SHM_RECEIVER_H
#include "common.h"

// 공유 메모리 수신 스레드의 메인 함수
void* shm_receiver_thread_main(void* args);

#endif // THREAD_SHM_RECEIVER_H
