/* start self code review */
#include "apue.h"

static void sig_alrm(int);

int main(void){
    int                     n;
    char        line[MAXLINE];

    if(signal(SIGALRM,sig_alrm)==SIG_ERR)
        err_sys("signal(SIGALRM) error");

    alarm(10);

    /* start a blocking function */
    if((n=read(STDIN_FILENO,line,MAXLINE))<0)
        err_sys("read error");      /* after 10.0 seconds, the read function returns -1 */
    
    /* jump up this below and move a handler sig_alrm(int signo) */
    alarm(0);

    write(STDOUT_FILENO,line,n);
    exit(0);
}

static void sig_alrm(int signo){
    /* nothing to do, just return to interrupt the read */
}
