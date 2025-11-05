#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <signal.h>
#include "sessionManager.h"

static unsigned int hashFunction(uint32_t srcIp, uint16_t srcPort, uint32_t dstIp, uint16_t dstPort);
static SessionInfo* findOrCreateSession(SessionManager* sm, uint32_t srcIp, uint16_t srcPort, uint32_t dstIp, uint16_t dstPort);

static unsigned int hashFunction(uint32_t srcIp, uint16_t srcPort, uint32_t dstIp, uint16_t dstPort) {
    unsigned int hash = srcIp ^ dstIp ^ srcPort ^ dstPort;
    return hash % HASH_TABLE_SIZE;
}

void smInit(SessionManager* sm) {
    if (sm == NULL) return;
    memset(sm->buckets, 0, sizeof(SessionInfo*) * HASH_TABLE_SIZE);
    if (pthread_mutex_init(&sm->lock, NULL) != 0) {
        perror("뮤텍스 초기화 실패");
        exit(EXIT_FAILURE);
    }
    sm->activeSessions = 0;
}

void smDestroy(SessionManager* sm) {
    if (sm == NULL) return;
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        SessionInfo* current = sm->buckets[i];
        while (current != NULL) {
            SessionInfo* toDelete = current;
            current = current->next;
            smDelete(sm, toDelete);
        }
    }
    pthread_mutex_destroy(&sm->lock);
}

void smDelete(SessionManager* sm, SessionInfo* sessionToDelete) {
    if (sessionToDelete == NULL) return;

    TCPFragment* currentFrag = sessionToDelete->fwdFragments;
    while (currentFrag != NULL) {
        TCPFragment* toFree = currentFrag;
        currentFrag = currentFrag->next;
        free(toFree->data);
        free(toFree);
    }

    currentFrag = sessionToDelete->bwdFragments;
    while (currentFrag != NULL) {
        TCPFragment* toFree = currentFrag;
        currentFrag = currentFrag->next;
        free(toFree->data);
        free(toFree);
    }

    free(sessionToDelete);
}

static SessionInfo* findOrCreateSession(SessionManager* sm, uint32_t srcIp, uint16_t srcPort, uint32_t dstIp, uint16_t dstPort) {
    unsigned int index = hashFunction(srcIp, srcPort, dstIp, dstPort);

    SessionInfo* current = sm->buckets[index];
    while (current != NULL) {
        if (current->srcIp == srcIp && current->srcPort == srcPort &&
            current->dstIp == dstIp && current->dstPort == dstPort) {
            return current;
        }
        if (current->srcIp == dstIp && current->srcPort == dstPort &&
            current->dstIp == srcIp && current->dstPort == srcPort) {
            return current;
        }
        current = current->next;
    }

    SessionInfo* newSession = (SessionInfo*)malloc(sizeof(SessionInfo));
    if (newSession == NULL) {
        perror("세션 생성 실패");
        return NULL;
    }
    
    memset(newSession, 0, sizeof(SessionInfo));
    newSession->srcIp = srcIp;
    newSession->srcPort = srcPort;
    newSession->dstIp = dstIp;
    newSession->dstPort = dstPort;
    newSession->state = TCP_STATE_NONE;
    newSession->startTime = time(NULL);
    newSession->lastActiveTime = time(NULL);

    newSession->next = sm->buckets[index];
    sm->buckets[index] = newSession;
    sm->activeSessions++;

    return newSession;
}

SessionInfo* smFind(SessionManager* sm, uint32_t srcIp, uint16_t srcPort, uint32_t dstIp, uint16_t dstPort) {
    if (sm == NULL) return NULL;
    unsigned int index = hashFunction(srcIp, srcPort, dstIp, dstPort);
    SessionInfo* foundSession = NULL;
    pthread_mutex_lock(&sm->lock);
    SessionInfo* current = sm->buckets[index];
    while (current != NULL) {
        if ((current->srcIp == srcIp && current->srcPort == srcPort && current->dstIp == dstIp && current->dstPort == dstPort) ||
            (current->srcIp == dstIp && current->srcPort == dstPort && current->dstIp == srcIp && current->dstPort == srcPort)) {
            foundSession = current;
            break;
        }
        current = current->next;
    }
    pthread_mutex_unlock(&sm->lock);
    return foundSession;
}

unsigned char* smHandlePacket(SessionManager* sm, const IPHeader* ipHeader, const TCPHeader* tcpHeader, const unsigned char* payload, int* outLen) {
    if (sm == NULL || ipHeader == NULL || tcpHeader == NULL || outLen == NULL) {
        return NULL;
    }
    
    *outLen = 0;
    unsigned char* reassembledStream = NULL;

    pthread_mutex_lock(&sm->lock);

    // --- 1. 기본 정보 추출 (한 번만 수행) ---
    uint32_t srcIpInt = *(uint32_t*)ipHeader->srcIP;
    uint32_t dstIpInt = *(uint32_t*)ipHeader->dstIP;
    uint8_t flags = tcpHeader->flags;
    uint32_t seqNum = ntohl(tcpHeader->seq);
    uint32_t ackNum = ntohl(tcpHeader->ack);
    unsigned int ip_header_len_bytes = (ipHeader->verIHL & 0x0F) * 4;
    unsigned int tcp_header_len_bytes = (tcpHeader->data >> 4) * 4;
    unsigned int payloadLen = ntohs(ipHeader->length) - ip_header_len_bytes - tcp_header_len_bytes;

    // --- 2. 세션 찾기 또는 생성 ---
    SessionInfo* session = findOrCreateSession(sm, srcIpInt, tcpHeader->srcPort, dstIpInt, tcpHeader->dstPort);
    if (session == NULL) {
        pthread_mutex_unlock(&sm->lock);
        return NULL;
    }
    
    session->lastActiveTime = time(NULL);

    // --- 3. [핵심 수정] TCP 상태 머신 로직 (Stateful Analysis) ---
    bool is_forward = (session->srcIp == srcIpInt);

    if (flags & 0x04) { // RST
        session->state = TCP_CLOSED;
    } else if (flags & 0x01) { // FIN
        if (session->state == TCP_ESTABLISHED) session->state = TCP_FIN_WAIT;
    } else if (flags & 0x02) { // SYN
        if (is_forward && !(flags & 0x10)) { // Pure SYN
            if (session->state == TCP_STATE_NONE || session->state == TCP_CLOSED) {
                session->state = TCP_SYN_SENT;
                session->nextFwdSeq = seqNum + 1;
            }
        } else if (!is_forward && (flags & 0x10)) { // SYN/ACK
            if (session->state == TCP_SYN_SENT) {
                session->nextBwdSeq = seqNum + 1;
            }
        }
    } else if (flags & 0x10) { // Pure ACK
        if (session->state == TCP_SYN_SENT && session->nextBwdSeq != 0) {
            if (ackNum == session->nextBwdSeq) {
                session->state = TCP_ESTABLISHED;
                session->nextFwdSeq = ackNum;
            }
        }
    }

    // --- 통계 정보 갱신 (페이로드 길이 기반) ---
    if (is_forward) {
        session->fwdPacketCount++;
        if (payloadLen > 0) session->fwdTotalBytes += payloadLen;
    } else {
        session->bwdPacketCount++;
        if (payloadLen > 0) session->bwdTotalBytes += payloadLen;
    }

    // --- TCP 스트림 재조합 (ESTABLISHED 상태에서만 수행) ---
    if (payloadLen > 0 && session->state >= TCP_ESTABLISHED) {
        TCPFragment** fragmentList;
        uint32_t* nextSeq;

        if (is_forward) {
            fragmentList = &session->fwdFragments;
            nextSeq = &session->nextFwdSeq;
        } else {
            fragmentList = &session->bwdFragments;
            nextSeq = &session->nextBwdSeq;
        }

        unsigned char* reassembledBuffer = NULL;
        int reassembledLen = 0;

        #define APPEND_TO_BUFFER(data_ptr, data_len) do { \
            unsigned char* new_buf = realloc(reassembledBuffer, reassembledLen + data_len); \
            if (new_buf) { \
                reassembledBuffer = new_buf; \
                memcpy(reassembledBuffer + reassembledLen, data_ptr, data_len); \
                reassembledLen += data_len; \
            } else { \
                free(reassembledBuffer); reassembledBuffer = NULL; reassembledLen = 0; \
            } \
        } while(0)

        if (seqNum == *nextSeq) {
            APPEND_TO_BUFFER(payload, payloadLen);
            if (reassembledBuffer == NULL) {
                pthread_mutex_unlock(&sm->lock);
                return NULL;
            }
            *nextSeq += payloadLen;

            TCPFragment* frag = *fragmentList;
            while (frag != NULL && frag->seq == *nextSeq) {
                APPEND_TO_BUFFER(frag->data, frag->len);
                if (reassembledBuffer == NULL) break;
                *nextSeq += frag->len;

                TCPFragment* to_free = frag;
                *fragmentList = frag->next;
                frag = *fragmentList;
                free(to_free->data);
                free(to_free);
            }
        } else if (seqNum > *nextSeq) { // 비순차적 패킷 보류 로직
            TCPFragment* newFrag = (TCPFragment*)malloc(sizeof(TCPFragment));
            if (newFrag) {
                newFrag->seq = seqNum;
                newFrag->len = payloadLen;
                newFrag->data = (unsigned char*)malloc(payloadLen);
                if (newFrag->data) {
                    memcpy(newFrag->data, payload, payloadLen);

                    TCPFragment* prev = NULL;
                    TCPFragment* curr = *fragmentList;
                    while (curr != NULL && curr->seq < newFrag->seq) {
                        prev = curr;
                        curr = curr->next;
                    }
                    if (prev == NULL) {
                        newFrag->next = *fragmentList;
                        *fragmentList = newFrag;
                    } else {
                        newFrag->next = curr;
                        prev->next = newFrag;
                    }
                } else {
                    free(newFrag);
                }
            }
        }

        if (reassembledLen > 0) {
            *outLen = reassembledLen;
            reassembledStream = reassembledBuffer;
        }
    }
    #undef APPEND_TO_BUFFER
    pthread_mutex_unlock(&sm->lock);

    return reassembledStream;
}

void smCleanupTimeout(SessionManager* sm) {
    if (sm == NULL) return;
    
    time_t now = time(NULL);
    const int sessionTimeout = 300;

    pthread_mutex_lock(&sm->lock);

    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        SessionInfo* current = sm->buckets[i];
        SessionInfo* prev = NULL;
        
        while (current != NULL) {
            if (difftime(now, current->lastActiveTime) > sessionTimeout) {
                SessionInfo* toDelete = current;
                
                if (prev == NULL) {
                    sm->buckets[i] = current->next;
                } else {
                    prev->next = current->next;
                }
                current = current->next;
                
                smDelete(sm, toDelete);
                sm->activeSessions--;
            } else {
                prev = current;
                current = current->next;
            }
        }
    }

    pthread_mutex_unlock(&sm->lock);
}