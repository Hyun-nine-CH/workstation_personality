/*
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
*/

#include <stdio.h>
#include <stdbool.h>

#define BUF_SIZ 5

typedef struct {
    int head;
    int tail;
    int cnt;
    int buf[BUF_SIZ];
} cirb;

void initBuf(cirb* v){
    v->head=v->tail=v->cnt=0;
}

bool enQ(cirb* v, int s){
    if(v->cnt==BUF_SIZ){
        printf("the buf ring is occupy %d\n",s);
        return false;
    }
    v->buf[v->head]=s;
    v->head=(v->head+1)%BUF_SIZ;
    v->cnt++;
    printf("head<-%d, add %d\n",v->head,s);
    return true;
}

bool deQ(cirb* v, int *s){
    if(v->cnt==0){
        printf("the buf ring is unoccupy\n");
        return false;
    }
    *s=v->buf[v->tail];
    v->tail=(v->tail+1)%BUF_SIZ;
    v->cnt--;
    printf("tail->%d, del %d\n",v->tail,*s);
    return true;
}

void printb(cirb* v){
    printf("\n[current buf] cnt=%d\n",v->cnt);
    for(int i=0;i<BUF_SIZ;i++){
        if(i==v->head&&i==v->tail)
            printf("[%d]*head & tail ",v->buf[i]);
        else if(i==v->head)
            printf("[%d]*head ",v->buf[i]);
        else if(i==v->tail)
            printf("[%d]*tail ",v->buf[i]);
        else
            printf("[%d] ",v->buf[i]);
    }
    printf("\n\n");
}

int main(){
    cirb v;
    initBuf(&v);
    char cmd;
    int s;

    printf("===self test_ring buf===\n");
    printf("add: (a), del: (d), prt: (p), qut: (q)\n");

    while(1){
        printf(">> ");
        scanf(" %c",&cmd);
        if(cmd=='a'){
            printf("add num: ");
            scanf("%d", &s);
            enQ(&v,s);
        }
        else if(cmd=='d'){
            if(deQ(&v,&s))
                printf("deleted val: %d\n",s);
        }
        else if(cmd=='p'){
            printb(&v);
        }
        else if(cmd=='q'){
            printf("program quit\n");
            break;
        }
        else
            printf("please choose the action icon: (a), (d), (p), (q)\n");
    }
    return 0;
}
