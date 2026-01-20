#include "apue.h"
#include <fcntl.h>

/* flags are file status flags to turn on */
void set_fl(int fd,int flags){
    int     val;
    if ((val=fcntl(fd,F_GETFL,0))<0)
        err_sys("fcntl F_GETFL error");
    val|=flags; /* turn on flags */
    // val&=~flags;
    /* turn flags off
        a function named clr_fl, which we'll use in some later examples.
        this statement logically ANDs the one's complement of flags with the current val.
    */
    /*
    if add the line:
        set_fl(STDOUT_FILENO,O_SYNC);
    to the beginning section of the IOProgram.c file for this directory,
    I'll turn on the synchronous-write flag. this causes each write to wait for the data to be written to disk before returning.
    Normally in the UNIX System, a write only queues the data for writing; the actual disk write operation can take place sometime later.
    */
    if(fcntl(fd,F_SETFL,val)<0)
        err_sys("fcntl F_SETFL error");
}