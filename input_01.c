#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

int main(void){
    char tmp1[BUFSIZ], tmp2[BUFSIZ];
    char name1[BUFSIZ], name2[BUFSIZ];
    int age1, age2;

    fgets(tmp1, sizeof(tmp1),stdin);
    tmp1[strcspn(tmp1,"\n")]=0; // 개행 제거
    sscanf(tmp1,"%s %d", name1, &age1);

    fgets(tmp2,sizeof(tmp2),stdin);
    tmp2[strcspn(tmp2,"\n")]=0;
    sscanf(tmp2,"%s %d", name2, &age2);

    // cmp
    if(strcmp(name1,name2)==0&&age1==age2){
        printf("같다\n");
    }else{
        printf("다르다\n");
    }
    return 0;
}