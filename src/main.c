#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <string.h> // memset
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
// hyungoo start
#include <errno.h> // plus
#include "shm_consumer.h" // shared memory consumer (최현구)
// hyungoo end

#include "common.h"           // 공용 구조체
#include "ts_packet_queue.h"    // Packet Queue
// #include "ts_alert_queue.h"     // Alert Queue
#include "thread_capture.h"     // libpcap 캡처 스레드 (IPS 로부터 공유 메모리를 통해 패킷을 수신하므로 이제 단순 테스트/분석 디버깅 용임)
#include "thread_shm_receiver.h" // 캡처 스레드 대신에 shm(공유 메모리) 수신 스레드 헤더를 포함
#include "thread_parser.h"   // 파싱/분류 스레드
#include "sessionManager.h"
// #include "thread_analyzer.h" // 융합/위협 분석 스레드
// #include "thread_response.h"  // 후처리/로깅 스레드
#include "../common_hyungoo/shm_ipc.h" // IPS -> IDS rawpacket 전송을 위한 공유 메모리 구조체 정의 헤더 include

// hyungoo start
// warning message, helper func.
static ssize_t write_all(int fd, const void* buf, size_t len) {
    const char* p = (const char*)buf;
    size_t left = len;
    while (left > 0) {
        ssize_t n = write(fd, p, left);
        if (n < 0) {
            if (errno == EINTR) continue; // 시그널이면 재시도
            return -1;                    // 진짜 오류
        }
        if (n == 0) break;                // 더 이상 못 씀
        p += n;
        left -= n;
    }
    return (ssize_t)(len - left);         // 실제 쓴 바이트
}
// hyungoo end

// 전역 서버 소켓(== server_sock) -> 클라이언트 연결 관리/종료 시
int server_sock_global = -1; // +init


// 클라이언트 연결 관리를 위한 전역 변수
#define MAX_CLIENTS 10
int client_sockets[MAX_CLIENTS];
pthread_mutex_t client_sockets_mutex = PTHREAD_MUTEX_INITIALIZER;

// 스레드 간 데이터 통로인 큐
PacketQueue packetQueue;
SessionManager sessionManager;
// AlertQueue alertQueue;

// 프로그램의 종료를 제어하기 위한 플래그
// volatile sig_atomic_t : 시그널 핸들러에서 사용하는 공유 변수를 안전하게 조작
volatile sig_atomic_t is_running = 1;

// 공유 메모리 포인터
SharedPacketBuffer* sharedBuffer_global = NULL;
shm_ipc_t* g_ipc = NULL; // 전역 SHM Handle
// 공유 메모리 파일 디스크립터
int shm_fd_global = -1;

// 함수 프로토타입들 (하단 정의 확인)
void handle_shutdown_signal(int signal);
// ... 클라이언트 연결을 수락하는 스레드 함수
void* client_connection_thread(void* arg);
// ... 각 클라이언트와의 통신을 전담하는 스레드 함수
void* handle_client_comm(void* arg);


// main 함수
int main(int argc, char *argv[]) {
    printf("Argus IPS 초기화 진행 중...\n");

    // Ctrl+C, 프로세스 종료 시그널 수신 시ㄴ 핸들 함수 호출
    signal(SIGINT, handle_shutdown_signal);
    signal(SIGTERM, handle_shutdown_signal);

    // start -- 공유 메모리 초기화
    /*
    printf("공유 메모리 설정 중...\n");
    // 0. 기존 공유 메모리 객체를 먼저 제거함 (잔여 파일 에러 방지)
    shm_unlink(SHM_NAME);

    // 1. 공유 메모리 객체 생성/열기
    shm_fd_global = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if(shm_fd_global == -1){
        perror("shm_open 실패");
        exit(EXIT_FAILURE);
    }
    // 2. 공유 메모리 크기 설정
    if(ftruncate(shm_fd_global, sizeof(ips_ring_t)) == -1) {
        perror("ftruncate 실패");
        exit(EXIT_FAILURE);
    }
    // 3. 메모리 매핑
    sharedBuffer_global = mmap(0, sizeof(ips_ring_t), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd_global, 0);
    if(sharedBuffer_global == MAP_FAILED){
        perror("mmap 실패");
        exit(EXIT_FAILURE);
    }
    // 4. 공유 동기화 객체 ini
    // 뮤텍스와 조건 변수의 속성을 담을 객체
    pthread_mutexattr_t mattr;
    pthread_condattr_t cattr;
    // 속성 구조체를 초기화
    pthread_mutexattr_init(&mattr);
    pthread_condattr_init(&cattr);
    // 다른 스포레스 간 공유가 가능하도록 PTHREAD_PROCESS_SHARED 설정
    pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
    pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
    // 실제 공유 메모리에 올라가 있는 구조체 sharedBuffer_global 내부 동기화 객체들을 초기화
    pthread_mutex_init(&sharedBuffer_global->lock, &mattr);
    pthread_cond_init(&sharedBuffer_global->cond_read, &cattr);
    pthread_cond_init(&sharedBuffer_global->cond_write, &cattr);
    // 더 이상 필요 없는 attribute 객체 정리
    pthread_mutexattr_destroy(&mattr);
    pthread_condattr_destroy(&cattr);
    // 버퍼 상태 초기화
    sharedBuffer_global->count = 0;
    sharedBuffer_global->read_idx = 0;
    sharedBuffer_global->write_idx = 0;
    printf("공유 메모리 초기화 완료\n");
    */
    // -- end 공유 메모리 초기화

    // 공유 자원 초기화
    tsPacketqInit(&packetQueue, &is_running);
    // smInit 은 thread_parser.c 에서 수행함 !
    // tsAlertqInit(&alertQueue, &is_running);
    memset(client_sockets, 0, sizeof(client_sockets));
    printf("공유 자원 초기화 완료.\n");

    // 스레드에 전달할 인자 준비
    // 각 스레드에서 common_args 를 받고 ex. args->packetqueue 와 같은 방식으로 사용
    ThreadArgs common_args = { 
        .packetQueue = &packetQueue,
        .sessionManager = &sessionManager,
        .sharedBuffer = sharedBuffer_global, // 공유 메모리 포인터 전달
        // .alertQueue = &alertQueue,
        .isRunning = &is_running
    };

    // hyungoo start
    // SHM event consumer thread start! (IPS->IDS 텔레메트리 수
    printf("SHM 소비자 모듈 시작 중...\n");
    if (shm_consumer_start(&common_args) != 0) {
        perror("SHM 소비 스레드 시작 실패");
        exit(EXIT_FAILURE);
    }
    printf("SHM 소비자 모듈 시작 완료.\n");
    // hyungoo end

    // 워커 스레드 선언
    pthread_t /*nfqueue_tid, */capture_tid , parser_tid, shm_receiver_tid
    /*, analyzer_tid, response_tid*/;
    pthread_t connection_tid; // 클라이언트 연결 수락용 스레드

    printf("IDS 워커 스레드 생성 중...\n");

    // libpcap 캡처 스레드 생성 코드 부분 (테스트용)
    /*
        if (pthread_create(&capture_tid, NULL,  pcap_thread_main, &common_args) != 0) {
            perror("libpcap 캡처 스레드 생성 실패"); exit(EXIT_FAILURE);
        }
        printf(" -> [OK] 2-1. libpcap 캡처 스레드가 생성되었습니다.\n");
    */

    // 캡처 스레드 대신 공유 메모리 수신 스레드 생성
    /*
    if(pthread_create(&shm_receiver_tid, NULL, shm_receiver_thread_main, &common_args) != 0){
        perror("공유 메모리 수신 스레드 생성 실패");
        exit(EXIT_FAILURE);
    }
    printf(" -> [OK] 2-1. 공유 메모리 수신 스레드가 생성되었습니다.\n");
    */

    if (pthread_create(&parser_tid, NULL, parser_thread_main, &common_args) != 0) {
        perror("파싱/분류 스레드 생성 실패"); exit(EXIT_FAILURE);
    }
    printf(" -> [OK] 2-2. 파싱/분류 스레드가 생성되었습니다.\n");
    
    /*
    if (pthread_create(&analyzer_tid, NULL, analyzer_thread_main, &common_args) != 0) {
        perror("융합/위협 분석 스레드 생성 실패"); exit(EXIT_FAILURE);
    }
    printf(" -> [OK] 2-3. 융합/위협 분석 스레드가 생성되었습니다.\n");
    */

    /*
    if (pthread_create(&response_tid, NULL, response_thread_main, &common_args) != 0) {
        perror("후처리/로깅 스레드 생성 실패"); exit(EXIT_FAILURE);
    }
    printf(" -> [OK] 2-4. 후처리/로깅 스레드가 생성되었습니다.\n");
    */

    // 클라이언트 연결 수락 스레드 생성
    if (pthread_create(&connection_tid, NULL, client_connection_thread, (void*)&is_running) != 0) {
        perror("클라이언트 연결 관리 스레드 생성 실패"); exit(EXIT_FAILURE);
    }
    printf(" -> [OK] 클라이언트 연결 관리 스레드가 생성되었습니다.\n");

    printf("\n모든 스레드가 정상적으로 생성되었습니다. Argus가 활성화되었습니다.\n");
    printf("Ctrl+C를 입력하면 종료됩니다.\n");
    
    // pthread_join(shm_receiver_tid, NULL);
    // (test용 캡처 스레드)
    /*
    pthread_join(capture_tid, NULL);
    */
    pthread_join(parser_tid, NULL);
    // pthread_join(analyzer_tid, NULL);
    // pthread_join(response_tid, NULL);
    pthread_join(connection_tid, NULL);

    // 공유 자원 해제
    printf("\n모든 스레드가 종료되었습니다. 할당한 자원을 해제합니다...\n");
    tsPacketqDestroy(&packetQueue);
    // smDestroy 는 thread_parser.c 에서 수행함 !
    // tsAlertqDestroy(&alertQueue);
    pthread_mutex_destroy(&client_sockets_mutex);
    
    // 공유 메모리 해제
    // munmap(sharedBuffer_global, sizeof(SharedPacketBuffer));
    // close(shm_fd_global);
    // 시스템에서 공유 메모리 객체 제거
    // shm_unlink(SHM_NAME);
    shm_consumer_stop();

    printf("종료 완료.\n");

    return 0;
}


// 시그널 핸들러 함수
void handle_shutdown_signal(int signal) {
    (void)signal;
    printf("\n종료 시그널을 수신했습니다. 모든 스레드를 안전하게 종료합니다...\n");
    is_running = 0;
    
    // 캡처 스레드 있을 때 테스트용
    /*
    // 캡처 스레드 캡처 루프(dispatcher) 중단
    capture_request_stop();
    */

    // 큐에서 대기 중인 스레드를 깨우기 위한 추가 조치
    tsPacketqSignalExit(&packetQueue);
    // tsAlertqSignalExit(&alertQueue);

    // 공유 메모리 수신 스레드 깨우기
    if (sharedBuffer_global != NULL) {
        pthread_mutex_lock(&sharedBuffer_global->lock);
        pthread_cond_broadcast(&sharedBuffer_global->cond_read);
        pthread_cond_broadcast(&sharedBuffer_global->cond_write);
        pthread_mutex_unlock(&sharedBuffer_global->lock);
    }

    // 클라이언트 수신 스레드 깨우기
    /*
    if(server_sock_global != -1){
        close(server_sock_global);
        server_sock_global = -1;
    }
    */
    if(server_sock_global != -1){
        int dummy_sock = socket(PF_INET, SOCK_STREAM, 0);
        if (dummy_sock != -1) {
            struct sockaddr_in server_addr;
            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
            server_addr.sin_port = htons(8085); // 서버가 리슨하는 포트와 동일
            
            // 접속 시도 (성공하든 실패하든 상관없음, accept()를 깨우는 것이 목적)
            connect(dummy_sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
            
            // 임시 소켓은 바로 닫음
            close(dummy_sock);
        }
        // 그 후에 서버 소켓을 닫아도 늦지 않음.
        shutdown(server_sock_global, SHUT_RDWR); // 더 우아한 종료
        close(server_sock_global);
        server_sock_global = -1;
    }
}

// 각 클라이언트와의 통신을 전담하는 스레드 함수
void* handle_client_comm(void* arg) {
    int client_sock = *(int*)arg;
    // 동적 할당된 메모리 해제
    free(arg);
    char buffer[BUFSIZ];
    int read_len;

    // 서버의 각 통신 스레드는 자신만의 클라이언트와 계속 통신
    while ((read_len = read(client_sock, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[read_len] = '\0';
        printf("[Client %d] 메시지 수신: %s", client_sock, buffer);

        // Todo list 3~4주차? (직접 명령 받을 때 추가 json 받고 파싱) : 여기서 수신된 JSON 명령을 파싱하고,
        // AlertQueue나 다른 메커니즘을 통해 다른 스레드에 작업을 요청해야 함.
        // (예: "스트리밍 시작" 명령을 받으면, 홈캠 서버로 전달)

        // 명령 처리 후 응답처리 (간단하게 일단.. 첫 싲ㅏㄱ이므로 !)

        // hyungoo : write_all 로 변경
        const char* msg = "명령 수신 완료\n";
        if (write_all(client_sock, msg, strlen(msg)) < 0) {
            perror("write_all");
        }

//        (void)write(client_sock, "명령 수신 완료\n", strlen("명령 수신 완료\n"));
    }

    // read()가 0 이하를 반환하면 클라이언트 연결이 끊긴 것
    printf("관제 클라이언트(%d) 연결 종료.\n", client_sock);
    
    // 전역 소켓 배열에서 자신을 제거 (뮤텍스로 보호)
    pthread_mutex_lock(&client_sockets_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (client_sockets[i] == client_sock) {
            client_sockets[i] = 0; // 슬롯 비우기
            break;
        }
    }
    pthread_mutex_unlock(&client_sockets_mutex);

    close(client_sock);
    return NULL;
}

// 클라이언트 연결을 수락하고 관리하는 스레드 함수
void* client_connection_thread(void* arg) {
    volatile sig_atomic_t* isRunning = (volatile sig_atomic_t*)arg;
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_size;
    // 아직 라즈베리파이 x -> gw ip : 192.168.2.29
    const int PORT = 8085;

    // Argus Listen 소켓
    server_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (server_sock == -1) {
        perror("서버 소켓 생성 실패");
        return NULL;
    }
    server_sock_global = server_sock;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("서버 소켓 바인드 실패");
        close(server_sock);
        return NULL;
    }

    if (listen(server_sock, 5) == -1) {
        perror("서버 소켓 리슨 실패");
        close(server_sock);
        server_sock_global=-1;
        return NULL;
    }

    printf("관제 클라이언트 연결 대기 중... (Port: %d)\n", PORT);

    while (*isRunning) {
        client_addr_size = sizeof(client_addr);
        // Argus 와 각 클라이언트 "통신" 소켓 accept 처리
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_addr_size);
        
        if (client_sock == -1) {
            if (*isRunning == 0) break;
            perror("클라이언트 연결 수락 실패");
            continue;
        }

        printf("관제 클라이언트 연결됨: %s\n", inet_ntoa(client_addr.sin_addr));

        // 새 클라이언트를 배열에 추가 (뮤텍스로 보호)
        pthread_mutex_lock(&client_sockets_mutex);
        int client_added = 0;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (client_sockets[i] == 0) {
                client_sockets[i] = client_sock;
                client_added = 1;
                break;
            }
        }
        pthread_mutex_unlock(&client_sockets_mutex);

        if (client_added) {
            // 통신을 전담할 새로운 스레드를 생성
            pthread_t tid;
            int* client_sock_ptr = (int*)malloc(sizeof(int));
            // hyungoo : !client_sock_ptr || 추가
            if (!client_sock_ptr || client_sock_ptr == NULL) {
                perror("메모리 할당 실패");
                close(client_sock);
                continue;
            }
            *client_sock_ptr = client_sock;

            if (pthread_create(&tid, NULL, handle_client_comm, client_sock_ptr) != 0) {
                perror("클라이언트 통신 스레드 생성 실패");
                free(client_sock_ptr);
                close(client_sock);
            }
            // 생성된 스레드는 알아서 동작하므로, main에서 join할 필요 없음 (분리)
            pthread_detach(tid); 
        } else {
            printf("클라이언트 수용량 초과. 연결을 거부합니다.\n");

            // hyungoo : write_all 로 변경
            const char* full = "서버가 가득 찼습니다.\n";
            (void)write_all(client_sock, full, strlen(full));

//            (void)write(client_sock, "서버가 가득 찼습니다.\n", strlen("서버가 가득 찼습니다.\n"));
            close(client_sock);
        }
    }

    close(server_sock);
  
    // hyungoo 
    server_sock_global=-1;

    printf("클라이언트 연결 관리 스레드가 종료됩니다.\n");
    return NULL;
}
