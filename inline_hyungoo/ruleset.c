// #include <stddef.h> // size_t
#define _GNU_SOURCE // for memmem on glibc

// #define _DEFAULT_SOURCE
#include "ruleset.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

static uint16_t g_drop_tcp_port=0; // ARGUS_DROP_TCP_PORT -> Control
static int g_rule_blockme = 1; // default ON
static int g_blockme_ci = 0; // default OFF

int ruleset_init(const char* path) {
    (void)path;
    const char* p;

    p = getenv("ARGUS_DROP_TCP_PORT");
    if (p && *p) {
        long v=strtol(p,NULL,10);
        if(v>0 && v <= 65535) g_drop_tcp_port=(uint16_t)v;
    }
    p=getenv("ARGUS_RULE_BLOCKME");
    if(p && *p) g_rule_blockme=(atoi(p) != 0) ? 1 : 0;

    p=getenv("ARGUS_RULE_BLOCKME_CI");
    if(p && *p) g_blockme_ci = (atoi(p) != 0) ? 1 : 0;
    
    return 0;
}

void ruleset_fini(void) { }

// if ARGUS_DROP_TCP_PORT setting and forward,
// in payload, "BLOCKME" then, DROP
int ruleset_match(const unsigned char* buf, uint32_t len, int* out_rule_id) {
    if(!buf || len<sizeof(struct iphdr)) return 0;
    const struct iphdr* ip=(const struct iphdr*)buf;
    if(ip->version !=4) return 0;

    uint32_t ihl=(uint32_t)ip->ihl*4u;
    if(ihl<sizeof(struct iphdr) || ihl>len) return 0;

    if(ip->protocol==IPPROTO_TCP && len>=ihl + sizeof(struct tcphdr)) {
        const struct tcphdr* th=(const struct tcphdr*)(buf + ihl);
        uint16_t dport=(uint16_t)ntohs(th->dest);

        if(g_drop_tcp_port && dport == g_drop_tcp_port) {
            if(out_rule_id) *out_rule_id=1000+dport; // ex: 1443->rule 2443
            return 1; // DROP
        }
    }

    if(g_rule_blockme && len>=7){
        const void* p = NULL;

        if(!g_blockme_ci) {
            p=memmem(buf, len, "BLOCKME", 7);
        }else{
            unsigned char tmp[2048];
            uint32_t n=len < sizeof(tmp) ? len : (uint32_t)sizeof(tmp);
            for (uint32_t i=0; i<n; ++i) {
                unsigned char c=buf[i];
                if (c>='A' && c<= 'Z') c=(unsigned char)(c - 'A' + 'a');
                tmp[i]=c;
            }
            p=memmem(tmp, n, "blockme", 7);
        }
        if(p) {
            if (out_rule_id) *out_rule_id=2001;
            return 1; // DROP
        }
    }
    return 0;
}
