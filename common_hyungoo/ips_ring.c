#include "ips_ring.h"

int ips_ring_push(ips_ring_t* q, const ips_event_t* ev){
    uint64_t w=atomic_load_explicit(&q->w, memory_order_relaxed);
    uint64_t r=atomic_load_explicit(&q->r, memory_order_acquire);
    if (w-r>=IPS_RING_CAP) { atomic_fetch_add(&q->drops_overrun,1); return 0; }
    q->slot[w & IPS_RING_MASK] = *ev;
    atomic_store_explicit(&q->w, w+1, memory_order_release);
    return 1;
}
int ips_ring_pop(ips_ring_t* q, ips_event_t* out){
    uint64_t r=atomic_load_explicit(&q->r, memory_order_relaxed);
    uint64_t w=atomic_load_explicit(&q->w, memory_order_acquire);
    if (r==w) return 0;
    *out=q->slot[r & IPS_RING_MASK];
    atomic_store_explicit(&q->r, r+1, memory_order_release);
    return 1;
}
