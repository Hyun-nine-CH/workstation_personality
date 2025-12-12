#include "apue.h"
#include <sys/wait.h>

/* signal capture start */
static void sig_int(int);

int main(void){
    typedef struct S{
        char         buf[MAXLINE];
    } S;
    
    pid_t            pid;
    int           status;
    S s;
    S *st=&s;
    
    /* signal error detection */
    if(signal(SIGINT,sig_int)==SIG_ERR)
        err_sys("signal error");

    /* replay */
    printf("%% ");
    while((fgets(st->buf,MAXLINE,stdin))){
        if(st->buf[strlen(st->buf)-1]=='\n')
            st->buf[strlen(st->buf)-1]=0;

        /* process embranchments */
        if((pid=fork())<0){
            err_sys("fork error emerges!!!!"); // error detection
        }else if(pid==0){
            /* implements */
            execlp(st->buf,st->buf,(char*)0);
            err_ret("can't execute: %s",st->buf);
            _exit(127);
        }
        if((pid=waitpid(pid,&status,0))<0)
            err_sys("waitpid error emerges!");
        
        printf("%% "); // loop bash print out
    }
    exit(0);
}
void sig_int(int signo){
    printf("\ninterrupt\n%% ");
}