#include <stdio.h>
#include <unistd.h>
#include <sched.h>
// #include <sys/types.h>

static int g_var=1;
char str[]="PID";

int main(int argc, char **argv){
    int var;
    pid_t pid; // system scheduler header added
    var=92;

    if((pid=fork())<0){
        perror("[ERROR]: fork()");
    }else if(pid==0){ // pid==0인 경우를 보통 자식 프로세스라고 지칭
        g_var++;
        var++;
        printf("Parent %s from Child Process(%d): %d\n",str,getpid(),getppid());
    }else{ // 그 외에는 부모 프로세스
        printf("Child %s from Parent Process(%d): %d\n",str,getpid(),pid);
        sleep(1);
    }
    printf("pid=%d, Global var=%d,var=%d\n",getpid(),g_var,var);
    return 0;
}