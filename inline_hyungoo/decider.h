#pragma once
#include "engine_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// forward-declare
struct nfq_q_handle; // libnetfilter_q header (X)

// finally verdict apply(VERDICT telemetry emit + nfq_set verdict
// dir: WAN->LAN/LAN->WAN/FWD or NULL
void decider_apply(struct nfq_q_handle* qh, const job_t* job, const decision_t* dec, const char* dir_hint);

#ifdef __cplusplus
}
#endif
