#include <stdio.h>

int main(void){
    char perID[7];
    char name[10];

    fputs("Enter your ID: ", stdout);
    fgets(perID, sizeof(perID),stdin);
    // scanf("%*c"); // Clear the input buffer

    fflush(stdin);
    fputs("Enter your name: ",stdout);
    fgets(name,sizeof(name),stdin);

    printf("ID: %s\n",perID);
    printf("Name: %s\n",name);
    return 0;
}