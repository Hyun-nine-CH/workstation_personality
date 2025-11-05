// (hyungoo)
#ifndef THREAD_CAPTURE_H
#define THREAD_CAPTURE_H
#include "common.h"

// main.c에서 pthread_create로 호출할 스레드 진입점(entry point) 함수
void* pcap_thread_main(void* args);
void capture_request_stop(void);

#endif // THREAD_CAPTURE_H
