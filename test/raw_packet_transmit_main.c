// raw_packet_transmit_main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include "../src/rawPacket.h"  // RawPacket 정의
#include "../src/shm_ipc.h" // SharedPacketBuffer 정의

// 공유 메모리 버퍼 포인터 (전역)
SharedPacketBuffer* g_shared_buffer = NULL;
// pcap 핸들 (종료 시 사용)
pcap_t* g_pcap_handle = NULL;
volatile sig_atomic_t is_running = 1;

// pcap 콜백 함수: 캡처된 패킷을 공유 메모리에 쓴다.
void shm_packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    if (g_shared_buffer == NULL) return;
    // 길이가 0인 패킷 무시
    if (header->caplen == 0) return;

    unsigned int copy_len = header->caplen;
    if (copy_len > MAX_PACKET_SIZE) {
        // 실제 길이보다 작게 복사되지만, 메모리 오염은 막을 수 있음
        fprintf(stderr, "[IPS-Producer] Warning: Large packet truncated from %u to %d bytes.\n", header->caplen, MAX_PACKET_SIZE);
        copy_len = MAX_PACKET_SIZE;
    }

    // --- 생산자 로직 시작 ---
    pthread_mutex_lock(&g_shared_buffer->lock);

    // 헤더 길이가 0 이거나 너무 큰 패킷은 무시
    if(header->caplen == 0 || header->caplen > MAX_PACKET_SIZE){
        printf("헤더 길이가 0 이거나 MAX_PACKET_SIZE 보다 큼, caplen : %d\n", header->caplen);
        return;
    }

    // 버퍼가 꽉 찼는지 확인
    // 실제로는 cond_wait으로 대기해야 하지만, 간단한 테스트를 위해 꽉 차면 그냥 버린다.
    if (g_shared_buffer->count >= PKT_MAX) {
        printf("[IPS-Producer] sharedBuffer full -> 해당 패킷 버림\n");
        pthread_mutex_unlock(&g_shared_buffer->lock);
        return;
    }

    // 공유 메모리의 다음 쓸 위치에 데이터 복사
    int write_index = g_shared_buffer->write_idx;
    g_shared_buffer->packets[write_index].len = header->caplen;
    // 실제 데이터 복사
    memcpy(g_shared_buffer->packets[write_index].data, pkt_data, copy_len);

    // 인덱스와 카운트 업데이트
    g_shared_buffer->write_idx = (g_shared_buffer->write_idx + 1) % PKT_MAX;
    g_shared_buffer->count++;

    printf("[IPS-Producer] 공유 메모리에 rawpacket write, len: %d\n", header->caplen);

    // 데이터가 추가되었음을 소비자(IDS)에게 알림
    pthread_cond_signal(&g_shared_buffer->cond_read);
    
    pthread_mutex_unlock(&g_shared_buffer->lock);
    // --- 생산자 로직 끝 ---
}

// 프로그램 종료를 위한 시그널 핸들러
void handle_shutdown(int signal) {
    printf("\n[IPS-Producer] Shutdown signal 발생 테스트 캡처 스레드 종료...\n");
    is_running = 0;
    if (g_pcap_handle) {
        pcap_breakloop(g_pcap_handle);
    }
}

int main() {
    signal(SIGINT, handle_shutdown);
    signal(SIGTERM, handle_shutdown);

    // --- 1. 공유 메모리 연결 ---
    printf("[IPS-Producer] Connecting to shared memory...\n");
    int shm_fd = shm_open(SHM_NAME, O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("shm_open 실패. Argus process 먼저 실행 필요");
        exit(EXIT_FAILURE);
    }
    
    g_shared_buffer = (SharedPacketBuffer*)mmap(0, sizeof(SharedPacketBuffer), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (g_shared_buffer == MAP_FAILED) {
        perror("mmap failed");
        close(shm_fd);
        exit(EXIT_FAILURE);
    }
    printf("[IPS-Producer] 공유 메모리 연결 완료.\n");
    
    // START : libpcap 에서 받아서 argus 로 rawpacket 넘기는 테스트용 코드들
    // --- 2. libpcap 설정
    pcap_if_t* alldevs;
    pcap_if_t* d;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;
    int inum;
    struct bpf_program fp; // BPF 필터 구조체
    char filter_exp[] = "ip"; // 필터 표현식 (일단 IP 패킷만 필터)
    bpf_u_int32 mask;
    bpf_u_int32 net;
    // 1. NIC 디바이스 목록 찾기
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs 오류: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    for (d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description) printf(" (%s)\n", d->description);
        else printf(" (설명 없음)\n");
    }
    if (i == 0) {
        printf("\n네트워크 인터페이스를 찾을 수 없습니다.\n");
        pcap_freealldevs(alldevs);
        exit(EXIT_FAILURE);
    }
    // 2. 사용자로부터 NIC 디바이스 선택 받기
    printf("캡처할 인터페이스 번호를 입력하세요 (1-%d): ", i);
    scanf("%d", &inum);
    if (inum < 1 || inum > i) {
        printf("\n잘못된 번호입니다.\n");
        pcap_freealldevs(alldevs);
        exit(EXIT_FAILURE);
    }
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    // 선택한 디바이스의 IP와 서브넷 마스크 정보 얻기
    if (pcap_lookupnet(d->name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "%s의 IP 주소를 찾을 수 없습니다: %s\n", d->name, errbuf);
        net = 0;
        mask = 0;
    }
    
    g_pcap_handle = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
    if (g_pcap_handle == NULL) { /* ... 오류 처리 ... */ }
    
    printf("[IPS-Producer] Starting packet capture on %s...\n", d->name);
    pcap_freealldevs(alldevs);

    // --- 3. 캡처 루프 시작 ---
    while(is_running){
        pcap_dispatch(g_pcap_handle, -1, shm_packet_handler, NULL);
    }
    
    // --- 4. 종료 처리 ---
    printf("[IPS-Producer] 캡처 종료. 정리 중...\n");
    pcap_close(g_pcap_handle);
    // END : libpcap 에서 받아서 argus 로 rawpacket 넘기는 테스트용 코드들

    munmap(g_shared_buffer, sizeof(SharedPacketBuffer));
    close(shm_fd);
    
    printf("[IPS-Producer] 테스트 캡처 프로세스 종료 완료.\n");
    return 0;
}