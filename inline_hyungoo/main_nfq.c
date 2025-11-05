//cat > main_nfq.c <<'EOF'
#include "ui_tap.h" // ui telemetry str/qit
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <semaphore.h> // sem_unlink
#include <sys/mman.h> // shm_unlink
#include "../common_hyungoo/shm_ipc.h"

#include "nfq_iface.h"
#include "ruleset.h"

volatile sig_atomic_t g_run = 1;
static void on_sigint(int s){ (void)s; g_run = 0; }
shm_ipc_t g_ipc; // 전역 SHM Handle

static unsigned get_uenv(const char* name, unsigned defv) {
    const char* s=getenv(name);
    if (!s || !*s) return defv;
    char* end=NULL;
    unsigned long v=strtoul(s,&end,10);
    return (end && *end=='\0') ? (unsigned)v : defv;
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    // output line buffer + SIGINT Handler
    setvbuf(stdout, NULL, _IOLBF, 0); // line_buffered
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);
    signal(SIGPIPE, SIG_IGN);

    // rule engine init
    if(ruleset_init(NULL) != 0) {
        fprintf(stderr, "ruleset_init failed\n");
        return 1;
    }

    // SHM creation (IPS: CREAT) default: flush
    const char* persist=getenv("ARGUS_SHM_PERSIST");
    const int persist_on=(persist && strcmp(persist,"1")==0);

    if(!persist_on) {
        // default: 시작 시, 이전 SHM/SEM 삭제
        shm_unlink(ARGUS_SHM_NAME);
        sem_unlink(ARGUS_SEM_NAME);
        printf("[SHM] flushed (ARGUS_SHM_PERSIST != 1)\n");
    }else{
        // 포렌식/디버깅: 이전 SHM/SEM 유지
        printf("[SHM] persist mode ON; skip unlink\n");
    }

    if(shm_ipc_open(&g_ipc, /*create=*/1) !=0) {
        fprintf(stderr, "SHM init failed\n");
        return 1;
    }

    // === runtime NFQ tuning env ===
    unsigned qnum=get_uenv("ARGUS_NFQ_NUM", 0);
    unsigned copy_b=get_uenv("ARGUS_NFQ_COPY", 1600);
    unsigned qlen=get_uenv("ARGUS_NFQ_QLEN", 4096);
    unsigned rcvbuf_mb=get_uenv("ARGUS_NFQ_RCVBUF_MB", 8);

    nfq_cfg_set_qnum((uint16_t)qnum);
    nfq_cfg_set_copy(copy_b);
    nfq_cfg_set_qlen(qlen);
    nfq_cfg_set_rcvbuf_mb(rcvbuf_mb);

    printf("[NFQ] qnum=%u copy=%u qlen=%u rcvbuf=%uMB\n", qnum, copy_b, qlen, rcvbuf_mb);

    // === UI telemetry(UDP 127.0.0.1:9090) init ===
    const char* ui_host=getenv("ARGUS_UI_HOST");
    if (!ui_host || !*ui_host) ui_host="127.0.0.1";
    unsigned ui_port=get_uenv("ARGUS_UI_PORT",9090);
    unsigned ui_qcap=get_uenv("ARGUS_UI_QCAP",8192);

    if (ui_tap_start(ui_host, (uint16_t)ui_port, ui_qcap) != 0) {
        fprintf(stderr, "[UI] telemetry start FAILED -> %s:%u (qcap=%u)\n", ui_host, ui_port, ui_qcap);
    } else {
        printf("[UI] telemetry -> %s:%u (qcap=%u)\n", ui_host, ui_port, ui_qcap);
    }

    // based NFQueue init/loop en)
    int rc = run_nfq((uint16_t)qnum);
    
    // UI telemetry quit
    ui_tap_stop();

    shm_ipc_close(&g_ipc);
    if(!persist_on) {
        shm_ipc_unlink_all();
    }
    // ruleset_fini();
    return rc; 
}
