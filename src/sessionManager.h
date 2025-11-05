#ifndef SESSION_MANAGER_H
#define SESSION_MANAGER_H

#include <time.h>
#include <pthread.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>
#include "common.h"

void smInit(SessionManager* sm);
unsigned char* smHandlePacket(SessionManager* sm, const IPHeader* ipHeader, const TCPHeader* tcpHeader, const unsigned char* payload, int* outLen);
SessionInfo* smFind(SessionManager* sm, uint32_t srcIp, uint16_t srcPort, uint32_t dstIp, uint16_t dstPort);
void smDelete(SessionManager* sm, SessionInfo* sessionToDelete);
void smCleanupTimeout(SessionManager* sm);
void smDestroy(SessionManager* sm);

#endif // SESSION_MANAGER_H