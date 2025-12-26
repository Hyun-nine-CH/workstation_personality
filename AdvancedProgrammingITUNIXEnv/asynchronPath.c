#include "apue.h"
#include <errno.h>
#include <limits.h>

#ifdef      PATH_MAX
static      long pathmax=PATH_MAX;
#else
static long pathmax=0;
#endif

static long posix_version=0;
static long xsi_version=0;

/* if PATH_MAX is unstable limits, it's no guarantee for a fitness */
#define PATH_MAX_GUESS      1024

char* path_alloc(size_t* sizep) /* what if not NULL, give back the allocated sizes*/{
    char    *ptr;
    size_t  size;

    if(posix_version==0)
        posix_version=sysconf(_SC_VERSION);
    if(xsi_version==0)
        xsi_version=sysconf(_SC_XOPEN_VERSION);

    if(pathmax==0){
        errno=0;
        if((pathmax=pathconf("/",_PC_PATH_MAX))<0){
            if(errno==0)
                pathmax=PATH_MAX_GUESS;
            else
                err_sys("pathconf error for _PC_PATH_MAX");
        }else{
            pathmax++;  /* for route, add to plus one relatively*/
        }
    }
    /*
    before POSIX.1-2001, there is a no guarantee which doesn't include termination NULL byte at the PATH_MAX. XPG3 is the same.    
    */
    if((posix_version<200112L) && (xsi_version<4))
        size=pathmax+1;
    else
        size=pathmax;

    if((ptr=malloc(size))==NULL)
        err_sys("malloc error for pathname");
    if(sizep!=NULL)
        *sizep=size;
    return(ptr);
}