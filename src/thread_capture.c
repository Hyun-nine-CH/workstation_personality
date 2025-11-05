// (hyungoo)
#define _DEFAULT_SOURCE
#include <sys/types.h>
#include <stdint.h>
#include <pcap.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// #include <time.h>
#include "common.h"
#include "ts_packet_queue.h"
#include "thread_capture.h"

// pcap handle 저장 전역 변수
static pcap_t* g_pcap_handle = NULL;

void capture_request_stop(void){
    if(g_pcap_handle){
        pcap_breakloop(g_pcap_handle);
    }
}

/*
void packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    // u_char* 를 PacketQueue*로 변환
    PacketQueue* queue = (PacketQueue*)args;

    // 캡처된 패킷 길이가 RawPacket의 최대 크기를 넘지 않는지 확인
    if (header->caplen == 0 || header->caplen > MAX_PACKET_SIZE) {
        fprintf(stderr, "Packet 0 or too large (%u bytes), dropping.\n", header->caplen);
        return;
    }

    // 캡처된 패킷 데이터를 PacketQueue에 넣음
    // pkt_data는 pcap 내부 버퍼 이므로
    // 다른 스레드에서 안전하게 사용하기 위해 데이터를 복사해서 넣음
    RawPacket* new_packet = (RawPacket*)malloc(sizeof(RawPacket));
    if (new_packet) {
        // 이미 구조체 내부에 byte 배열로 존재하므로 malloc 필요없음.
        // new_packet->data = (unsigned char*)malloc(header->caplen);
        // if (new_packet->data) {
            memcpy(new_packet->data, pkt_data, header->caplen);
            new_packet->len = header->caplen;
            
            // 큐에 푸시
            tsPacketqPush(queue, new_packet);
        // } else {
        //    free(new_packet);
        // }
    }

    // queue input 개수 체크
    // printf("[PacketQueue_개수] : %d\n", queue->count);

    // (2주차 목표) 일단 수신된 패킷을 간단한 출력

    printf("[캡처 스레드] Packet captured, length: %d\n", header->len);
*/

// PacketQueue(u_char*) 를 인자로 받는 콜백 함수
static void packet_handler(unsigned char* args, const struct pcap_pkthdr* header, const unsigned char* pkt_data) {
    // u_char* 를 PacketQueue*로 변환
    PacketQueue* queue = (PacketQueue*)args;

    // 캡처된 패킷 데이터를 PacketQueue에 넣음
    // pkt_data는 pcap 내부 버퍼 이므로
    // 다른 스레드에서 안전하게 사용하기 위해 데이터를 복사해서 넣음
    // caplen 0 defence
    if (!header || header->caplen==0) return;

    RawPacket* new_packet = (RawPacket*)malloc(sizeof(RawPacket));
    if (!new_packet) return;

    // new_packet->data = (unsigned char*)malloc(header->caplen);
    if (!new_packet->data) { free(new_packet); return; }

    memcpy(new_packet->data, pkt_data, header->caplen);
    new_packet->len = header->caplen;
    
    // 큐에 푸시
    tsPacketqPush(queue, new_packet);

    // queue size logging
    printf("[IDS nflog:5] enqueue: caplen=%u, qsize=%d\n", header->caplen, queue->count);
}
/*
    // (2주차 목표) 일단 수신된 패킷을 간단한 출력
    printf("[캡처 스레드] Packet captured, length: %d\n", header->len);
=======
    // printf("[캡처 스레드] Packet captured, length: %d\n", header->len);
}
*/

// pcap_thread_main 스레드 함수 (nflog:5 fixed)
void* pcap_thread_main(void* args) {
    ThreadArgs* thread_args = (ThreadArgs*)args;
    PacketQueue* queue = thread_args->packetQueue;
    volatile sig_atomic_t* isRunning = thread_args->isRunning;

//    pcap_if_t* alldevs;
//    pcap_if_t* d;
//    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
//    int i = 0;
//    int inum;
//    struct bpf_program fp; // BPF 필터 구조체
//    char filter_exp[] = "ip"; // 필터 표현식 (일단 IP 패킷만 필터)
//    bpf_u_int32 mask;
//    bpf_u_int32 net;

    // nflog:5 device create
    pcap_t* adhandle = pcap_create("nflog:5", errbuf);
    if (!adhandle) {
        fprintf(stderr, "pcap_create(nflog:5) 실패: %s\n", errbuf);
        return NULL;
    }
    g_pcap_handle = adhandle;

    pcap_set_snaplen(adhandle, 1600);
    pcap_set_promisc(adhandle, 0);
    pcap_set_timeout(adhandle, 100);

#ifdef PCAP_ERROR
#endif
#ifdef HAVE_PCAP_SET_IMMEDIATE_MODE
    pcap_set_immediate_mode(adhandle,1); // latency decrease
#endif
    pcap_set_buffer_size(adhandle, 4<<20);

    if (pcap_activate(adhandle) < 0) {
        fprintf(stderr, "pcap_activate: %s\n", pcap_geterr(adhandle));
        pcap_close(adhandle);
        g_pcap_handle = NULL;
        return NULL;
    }

    // DLT nflog checking
    int dlt = pcap_datalink(adhandle);
    if (dlt != DLT_NFLOG) {
        fprintf(stderr, "warning: DLT=%d (expected DLT_nflog)\n", dlt);
    }
    printf("[nflog:5]에서 캠처를 시작합니다...\n");

    // capture loop
    while(*isRunning) {
        int rc = pcap_dispatch(adhandle, -1, packet_handler, (unsigned char*)queue);
        if (rc == -2) break; // break loop
        if (rc < 0) {
            const char* perr=pcap_geterr(adhandle);
            fprintf(stderr, "pcap_dispatch rc=%d err=%s\n", rc, perr ? perr : "(null)");
            if(perr&&strstr(perr,"Message truncated")) {
                continue;
            }
            break;
        }
        // rc == 0; timeout -> continue
    }
/*
    // 1. NIC 디바이스 목록 찾기
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs 오류: %s\n", errbuf);
        return NULL;
    }

    for (d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description) printf(" (%s)\n", d->description);
        else printf(" (설명 없음)\n");
    }

    if (i == 0) {
        printf("\n네트워크 인터페이스를 찾을 수 없습니다.\n");
        pcap_freealldevs(alldevs);
        return NULL;
    }

    // 2. 사용자로부터 NIC 디바이스 선택 받기
    printf("캡처할 인터페이스 번호를 입력하세요 (1-%d): ", i);
    scanf("%d", &inum);

    if (inum < 1 || inum > i) {
        printf("\n잘못된 번호입니다.\n");
        pcap_freealldevs(alldevs);
        return NULL;
    }

    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
    
    // 선택한 디바이스의 IP와 서브넷 마스크 정보 얻기
    if (pcap_lookupnet(d->name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "%s의 IP 주소를 찾을 수 없습니다: %s\n", d->name, errbuf);
        net = 0;
        mask = 0;
    }

    // 3. 선택한 디바이스 열기
    // 65536: 캡처할 패킷의 최대 크기 (snaplen)
    // 1: promiscuous mode (무차별 모드) 활성화
    // 1000: 타임아웃 (ms)
    adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
    if (adhandle == NULL) {
        fprintf(stderr, "\n어댑터를 열 수 없습니다: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return NULL;
    }
    
    g_pcap_handle = adhandle;

    // 4. 필터 컴파일 및 적용 (성능 최적화)
    if (pcap_compile(adhandle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "필터 컴파일 오류: %s\n", pcap_geterr(adhandle));
        pcap_freealldevs(alldevs);
        pcap_close(adhandle);
        return NULL;
    }
    if (pcap_setfilter(adhandle, &fp) == -1) {
        fprintf(stderr, "필터 적용 오류: %s\n", pcap_geterr(adhandle));
        pcap_freealldevs(alldevs);
        pcap_close(adhandle);
        return NULL;
    }

    printf("\n[%s]에서 캡처를 시작합니다...\n", d->name);
    pcap_freealldevs(alldevs);

    // 5. 패킷 캡처 루프 시작
    while (*isRunning) {
        // pcap_loop 대신 pcap_dispatch를 사용하여 비동기 종료에 더 유리하도록 함
        // pcap_dispatch -> 버퍼에 쌓인 패킷만 처리하고 즉시 반환
        int rc = pcap_dispatch(adhandle, -1, packet_handler, (u_char*)queue);
        if(rc == -2){
            break;
        }
    }
*/    
    // 6. 종료 처리
    pcap_close(adhandle);
    g_pcap_handle = NULL;
    printf("캡처 스레드가 종료됩니다.\n");
    return NULL;
}
