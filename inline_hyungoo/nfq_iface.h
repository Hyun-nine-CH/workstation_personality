#pragma once
#include <stdint.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

// runtime tuning set: lib func. name
void nfq_cfg_set_qnum(uint16_t qnum);
void nfq_cfg_set_copy(unsigned bytes);
void nfq_cfg_set_qlen(unsigned qlen);
void nfq_cfg_set_rcvbuf_mb(unsigned mb);

struct nfq_handle* nfq_setup(struct nfq_q_handle** out_qh, uint16_t qnum);
void nfq_teardown(struct nfq_handle* h, struct nfq_q_handle* qh);
int run_nfq(uint16_t qnum);
