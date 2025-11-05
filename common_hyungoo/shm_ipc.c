#include "shm_ipc.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int shm_ipc_open(shm_ipc_t* ipc, int create){
    if(!ipc) { errno=EINVAL; return -1; }
    // 구조체 정리 (shm_fd, ring, semaphore 등 기본값 0/NULL)
    memset(ipc, 0, sizeof(*ipc));

    // SHM open
    int oflag=O_RDWR | (create ? O_CREAT : 0);
    int fd=shm_open(ARGUS_SHM_NAME, oflag, 0666);
    if(fd<0) return -1;

    // 크기 지정, 생성 시 ftruncate
    size_t sz = sizeof(ips_ring_t);
    if (create) {
        if (ftruncate(fd, sz)<0){
            int e=errno;
            close(fd);
            errno=e;
            return -1;
        }
    }

    // mmap
    void* p=mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    int saved_errno=errno;
    close(fd);
    if (p==MAP_FAILED) {
        errno=saved_errno;
        return -1;
    }

    ipc->ring=(ips_ring_t*)p;

    // ring buffer init (create할 때), ips_ring_init()이 있으면 그대로, 없으면 0으로 초기화
// #ifdef IPS_RING_HAVE_INIT
//    if (create) ips_ring_init(ipc->ring);
// #else
    if (create) memset(ipc->ring,0,sz);
// #endif

    // semaphore open (create할 때, O_CREAT, 초기값은 0)
    ipc->sem=sem_open(ARGUS_SEM_NAME, create ? O_CREAT: 0, 0600, 0);
    if (ipc->sem==SEM_FAILED) {
        saved_errno=errno;
        munmap(ipc->ring,sz);
        ipc->ring=NULL;
        errno=saved_errno;
        return -1;
    }
    return 0;
}
void shm_ipc_close(shm_ipc_t* ipc) {
    if(!ipc) return;
    if(ipc->ring) {
        munmap(ipc->ring, sizeof(ips_ring_t));
        ipc->ring=NULL;
    }
    if(ipc->sem && ipc->sem != SEM_FAILED) {
        sem_close(ipc->sem);
        ipc->sem=NULL;
    }
}
int shm_ipc_unlink_all(void) {
    shm_unlink(ARGUS_SHM_NAME);
    sem_unlink(ARGUS_SEM_NAME);
    return 0;
}
