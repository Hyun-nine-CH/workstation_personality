#include "apue.h"

int main(void){
    int c;
    while ((c=getc(stdin))!=EOF) // This is, doesn't empty!!
        if(putc(c,stdout)==EOF) // No output, nothing is outcome
            err_sys("output error");

    if(ferror(stdin)) // commonly, type error
        err_sys("input error");
    
    exit(0);
}