#include <signal.h>
#include <errno.h>

/*
<signal.h> usually defines NSIG to include signal number 0.
*/

// #define NSIG        32
#define SIGBAD(signo)       ((signo)<=0||(signo)>=NSIG)         /* verdict invalid value */
#define IDX(s)              ((s-1)/(8*sizeof(unsigned long)))
#define BIT(s)              ((s-1)%(8*sizeof(unsigned long)))

// typedef unsigned long sigset_t;
int sigaddset(sigset_t* set,int signo){
    if(SIGBAD(signo)){
        errno=EINVAL;
        return -1;
    }

//    int idx=(signo-1)/(8*sizeof(unsigned long));
//    int bit=(signo-1)%(8*sizeof(unsigned long));

    // *set|=1<<(signo-1);   /* turn bit on */
    set->__val[IDX(signo)]|=(1UL<<BIT(signo));    /* the new formation */
    
    return 0;      /* bit mask 1<<(N-1) means that 2^(0), 2^(1), 2^(2), ..., 2^(N-2), 2^(N-1) for 1<=N<M */
}

int sigdelset(sigset_t* set,int signo){
    if(SIGBAD(signo)){
        errno=EINVAL;
        return -1;
    }

//    *set&=~(1<<(signo-1));      /* turn bit off */
    set->__val[IDX(signo)]&=~(1UL<<BIT(signo));    /* the new formation */

    return 0;
}

int sigismember(const sigset_t* set,int signo){
    if(SIGBAD(signo)){
        errno=EINVAL;
        return -1;
    }

//    return((*set&(1<<(signo-1)))!=0);       /* if 1, true or what if the number is 0, this is false */
    return (set->__val[IDX(signo)]&(1UL<<BIT(signo)))!=0;  
}