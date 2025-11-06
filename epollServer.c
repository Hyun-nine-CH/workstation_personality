#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#define SERVER_PORT 5100
#define MAX_EVENT 32

void setnonblocking(int fd){
    int opts=fcntl(fd,F_GETFL);
    opts |= O_NONBLOCK;
    fcntl(fd,F_SETFL,opts);
}

int main(int argc, char **argv){
    int ssock,csock;
    socklen_t clen;
    int n,epfd,nfds=1;
    struct sockaddr_in servaddr,cliaddr;
    struct epoll_event ev;
    struct epoll_event events[MAX_EVENT];
    char mesg[BUFSIZ];

    if((ssock=socket(AF_INET, SOCK_STREAM,0))<0){
        perror("socket()");
        return -1;
    }

    setnonblocking(ssock);
    memset(&servaddr,0,sizeof(servaddr));
    servaddr.sin_family=AF_INET;
}