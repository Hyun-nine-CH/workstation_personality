#include "apue.h"
#include <fcntl.h>

int main(int argc, char *argv[]){
    int val;
    if (argc!=2)
        err_quit("usage: a.out <descriptor#>");
    if ((val=fcntl(atoi(argv[1]),F_GETFL,0))<0) /* the first factor is a outer input case so u have to use a atoi() function are u ok? yeah~~@@@ I'll recommand that you utilize a strtol() function */
        err_sys("fcntl error for fd %d",atoi(argv[1]));
    
    /* if the pipe number n is open */
    switch(val&O_ACCMODE){
    case O_RDONLY: /* ./executeName n < file */
        printf("read only");
        break;
    
    case O_WRONLY: /* ./executeName n > file */
        printf("write only");
        break;
    
    case O_RDWR: /* ./executeName n <> file */
        printf("read write");
        break;

    default:
        err_dump("unknown access mode");
    }
    if(val&O_APPEND)
        printf(",append"); /* ./executeName n n>>file */
    if(val&O_NONBLOCK)
        printf(",nonblocking");
    if(val&O_SYNC)
        printf(",synchronous writes");

#if !defined(_POSIX_C_SOURCE)&&defined(O_FSYNC)&&(O_FSYNC!=O_SYNC) /* legacy code O_FSYNC */
    if(val&O_FSYNC)
        printf(",synchronous writes");
#endif
    putchar('\n');
    exit(0);
}