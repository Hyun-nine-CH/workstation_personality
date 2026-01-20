#include "apue.h"
#define BUFSIZE     4096

/*
    if add the line:
        set_fl(STDOUT_FILENO,O_SYNC);
    to the beginning section of this IOProgram source codes,
    I'll turn on the synchronous-write flag. this causes each write to wait for the data to be written to disk before returning.
    Normally in the UNIX System, a write only queues the data for writing; the actual disk write operation can take place sometime later.
*/
int main(void){
    int     n;
    char    buf[BUFSIZE];

    while((n=read(STDIN_FILENO,buf,BUFSIZE))>0)
        if(write(STDOUT_FILENO,buf,n)!=n)
            err_sys("write error");
    if(n<0)
        err_sys("read error");
    exit(0);
}