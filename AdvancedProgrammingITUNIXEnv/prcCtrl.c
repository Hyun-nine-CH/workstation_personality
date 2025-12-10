#include "apue.h" // MAXLINE DEF
#include <sys/wait.h>

/*
int main(void){
    char                buf[MAXLINE];
    pid_t               pid;
    int                 status;

    printf("%% ");
    while(fgets(buf,MAXLINE,stdin)!=NULL){
        if(buf[strlen(buf)-1]=='\n')
            buf[strlen(buf)-1]=0;

        if((pid=fork())<0){
            err_sys("fork error");
        }else if(pid==0){
            execlp(buf,buf,(char*)0);
            err_ret("couldn't execute: %s",buf);
            exit(127);
        }

        if((pid=waitpid(pid,&status,0))<0)
            err_sys("waitpid error");
        printf("%% ");
    }
    exit(0);
}
*/
int main(void){
	/* type definitions */
	int                 status;
	pid_t                  pid;
	char          buf[MAXLINE];
	
	/* ~% bash */
	printf("%% ");
	
	/* launcher of input words */
	while(fgets(buf,MAXLINE,stdin)){ // return: pointer; if failure, NULL
		char *p=strchr(buf,'\n');
		if(p)
			*p='\0';
	
		/* process embranchments */
		/* failure/error */
		if((pid=fork())<0){
			err_sys("fork error");
		
		}else if(pid==0){
			execlp(buf,buf,(char*)0);
			err_ret("~%: %s",buf);
			_exit(127);
		}
		
		if((pid=waitpid(pid,&status,0))<0)
			err_sys("waitpid error");
		
		printf("%% ");
	}
	exit(0);
	

}