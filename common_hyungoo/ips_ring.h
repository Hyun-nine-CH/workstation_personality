#pragma once
#include <stdatomic.h>
#include "ips_event.h"

#define IPS_RING_CAP (1u<<14) // 16384 slot
#define IPS_RING_MASK (IPS_RING_CAP-1)

typedef struct {
    _Atomic uint64_t w, r, drops_overrun;
    ips_event_t slot[IPS_RING_CAP];
} ips_ring_t;

int ips_ring_push(ips_ring_t* q, const ips_event_t* ev);
int ips_ring_pop(ips_ring_t* q, ips_event_t* out);
