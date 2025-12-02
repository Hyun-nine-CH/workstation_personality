#include "apue.h"
#include <dirent.h>

int main(int argc, char *argv[]){
    DIR                 *dp; // directory path
    struct dirent       *dirp; // maybe directory entry
    if(argc!=2)
        err_quit("usage: ls directory_name"); // printf(stderr) + exit(1)
    if((dp=opendir(argv[1]))==NULL)
        err_sys("can't open%s",argv[1]); // err_sys("arg%s",errno), errno=argv[1]
        // commonly, err_*() does include exit(1)
    while((dirp=readdir(dp))!=NULL)
        printf("%s\n",dirp->d_name);

    closedir(dp);
    exit(0);
}