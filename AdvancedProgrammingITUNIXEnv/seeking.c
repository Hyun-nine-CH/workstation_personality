#include "apue.h"

int main(void){
    if(lseek(STDIN_FILENO,0,SEEK_CUR)==-1) // doesn't compare lseek and a number less than 0 because of error treatments
        printf("cannot seek\n");
    else
        printf("seek OK\n");
    exit(0);
}