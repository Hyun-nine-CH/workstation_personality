#pragma once
#include <stdint.h>

int ruleset_init(const char* path);
void ruleset_fini(void);

// matching: *out_rule_id>=0, if not, *out_rule_id: -1
int ruleset_match(const unsigned char* buf, uint32_t len, int* out_rule_id);
