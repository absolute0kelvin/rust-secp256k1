/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECKEY_H
#define SECP256K1_ECKEY_H

#include <stddef.h>

#include "group.h"
#include "scalar.h"
#include "ecmult.h"
#include "ecmult_gen.h"

static int batchverify_rustsecp256k1_v0_10_0_eckey_pubkey_parse(batchverify_rustsecp256k1_v0_10_0_ge *elem, const unsigned char *pub, size_t size);
static int batchverify_rustsecp256k1_v0_10_0_eckey_pubkey_serialize(batchverify_rustsecp256k1_v0_10_0_ge *elem, unsigned char *pub, size_t *size, int compressed);

static int batchverify_rustsecp256k1_v0_10_0_eckey_privkey_tweak_add(batchverify_rustsecp256k1_v0_10_0_scalar *key, const batchverify_rustsecp256k1_v0_10_0_scalar *tweak);
static int batchverify_rustsecp256k1_v0_10_0_eckey_pubkey_tweak_add(batchverify_rustsecp256k1_v0_10_0_ge *key, const batchverify_rustsecp256k1_v0_10_0_scalar *tweak);
static int batchverify_rustsecp256k1_v0_10_0_eckey_privkey_tweak_mul(batchverify_rustsecp256k1_v0_10_0_scalar *key, const batchverify_rustsecp256k1_v0_10_0_scalar *tweak);
static int batchverify_rustsecp256k1_v0_10_0_eckey_pubkey_tweak_mul(batchverify_rustsecp256k1_v0_10_0_ge *key, const batchverify_rustsecp256k1_v0_10_0_scalar *tweak);

#endif /* SECP256K1_ECKEY_H */
