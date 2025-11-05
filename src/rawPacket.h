// rawpacket 구조체 정의
#ifndef RAWPACKET_H
#define RAWPACKET_H

#define MAX_PACKET_SIZE 1600

typedef struct {
    unsigned char data[MAX_PACKET_SIZE];
    unsigned int len;
} RawPacket;

#endif // RAWPACKET_H