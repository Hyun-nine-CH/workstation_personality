#include <stdio.h>
#include <stdbool.h>

#define CIR_BUF 10

typedef struct{
    unsigned int st;
    unsigned int dst;
    char data[CIR_BUF];
} t_type; // pointer로 사용

bool is(t_type* x){
    bool res = false;
    res=(CIR_BUF+x)->st-x->dst%CIR_BUF;
    return res;
};

// data 입력
void EQ(t_type* x,char c){
    unsigned int i=(unsigned int)(x->st+1)%CIR_BUF;
    if(i!=x->dst){
        x->data[x->st]=c;
        x->st=i;
    }
    else{
        printf("the ring is full\n");
    }
}

// data 출력 동시에 출력된 정보 제거
char DQ(t_type* x){
    char c='\0';
    if(x->st==x->dst){
        printf("the ring is empty\n");
    }else{
        c=x->data[x->dst];
        x->dst=(unsigned int)(x->dst+1)%CIR_BUF;
    }
    return c;
}

void P(t_type* x){
    int i=x->dst;
    if(x->st==x->dst){
        printf("the ring buffer is empty\n");
    }else{
        while(i!=x->st){
            printf("%c ",x->data[i]);
            i=(i+1)%CIR_BUF;
        } // 버퍼가 비어있는 것인지, 채워져 있는 것인지 구분하기 위한 조치
        printf("\n");
    }
}

int main(){
    t_type buf={0,0,{0}};
    t_type* x_handler=&buf;

    bool exit=false;

    while(!exit){
        int num;
        char c;
        // printf("1. input, 2. delete, 3. output 4. exit\n");
        fputs("1. input, 2. delete, 3. output 4. exit\n",stdout);
        fgets(num,sizeof(num),stdin);
        // scanf("%d",&num);
        // rewind(stdin);

        switch(num){
            case 1:
                // printf("character: ");
                fputs("문자 입력: ",stdout);
                fgets(c,sizeof(c),stdin);
                // scanf("%c",&c);
                EQ(x_handler,c);
                // rewind(stdin);
                break;
            case 2:
                DQ(x_handler);
                break;
            case 3:
                P(x_handler);
                break;
            case 4:
                exit=true;
                break;
        }
    }
    return 0;
}