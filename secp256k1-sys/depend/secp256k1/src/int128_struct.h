#ifndef SECP256K1_INT128_STRUCT_H
#define SECP256K1_INT128_STRUCT_H

#include <stdint.h>
#include "util.h"

typedef struct {
  uint64_t lo;
  uint64_t hi;
} batchverify_rustsecp256k1_v0_10_0_uint128;

typedef batchverify_rustsecp256k1_v0_10_0_uint128 batchverify_rustsecp256k1_v0_10_0_int128;

#endif
