//
//  BRKey.c
//
//  Created by Aaron Voisine on 8/19/15.
//  Copyright (c) 2015 breadwallet LLC
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

#include "BRKey.h"
#include "BRAddress.h"
#include "BRBase58.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#if __BIG_ENDIAN__ || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) ||\
    __ARMEB__ || __THUMBEB__ || __AARCH64EB__ || __MIPSEB__
#define WORDS_BIGENDIAN        1
#endif
#define DETERMINISTIC          1
#define USE_BASIC_CONFIG       1
#define ENABLE_MODULE_RECOVERY 1

#pragma clang diagnostic push
#pragma GCC diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wconditional-uninitialized"
//#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#include "secp256k1/src/basic-config.h"
#include "secp256k1/src/secp256k1.c"
#pragma clang diagnostic pop
#pragma GCC diagnostic pop

static pthread_once_t _ctx_once = PTHREAD_ONCE_INIT;
static secp256k1_context *_ctx = NULL;

static void _ctx_init()
{
    //pthread_detach(pthread_self());
    _ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

// assigns secret to key and returns true on success
int BRKeySetSecret(BRKey *key, const UInt256 *secret, int compressed)
{
    assert(key != NULL);
    assert(secret != NULL);

    pthread_once(&_ctx_once, _ctx_init);
    BRKeyClean(key);
    UInt256Get(&key->secret, secret);
    key->compressed = compressed;
    return secp256k1_ec_seckey_verify(_ctx, key->secret.u8);
}

// wipes key material from key
void BRKeyClean(BRKey *key)
{
    assert(key != NULL);
    var_clean(key);
}

// assigns DER encoded pubKey to key and returns true on success
int BRKeySetPubKey(BRKey *key, const uint8_t *pubKey, size_t pkLen)
{
    secp256k1_pubkey pk;

    assert(key != NULL);
    assert(pubKey != NULL);
    assert(pkLen == 33 || pkLen == 65);

    pthread_once(&_ctx_once, _ctx_init);
    BRKeyClean(key);
    memcpy(key->pubKey, pubKey, pkLen);
    key->compressed = (pkLen <= 33);
    return secp256k1_ec_pubkey_parse(_ctx, &pk, key->pubKey, pkLen);
}

// writes the DER encoded public key to pubKey and returns number of bytes written, or pkLen needed if pubKey is NULL
size_t BRKeyPubKey(BRKey *key, void *pubKey, size_t pkLen)
{
    static uint8_t empty[65]; // static vars initialize to zero
    size_t size = (key->compressed) ? 33 : 65;
    secp256k1_pubkey pk;

    assert(key != NULL);

    if (memcmp(key->pubKey, empty, size) == 0) {
        if (secp256k1_ec_pubkey_create(_ctx, &pk, key->secret.u8)) {
            secp256k1_ec_pubkey_serialize(_ctx, key->pubKey, &size, &pk,
                                          (key->compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED));
        }
        else size = 0;
    }

    if (pubKey && size <= pkLen) memcpy(pubKey, key->pubKey, size);
    return (! pubKey || size <= pkLen) ? size : 0;
}

// returns the ripemd160 hash of the sha256 hash of the public key
UInt160 BRKeyHash160(BRKey *key)
{
    UInt160 hash = UINT160_ZERO;
    size_t len;
    secp256k1_pubkey pk;

    assert(key != NULL);
    len = BRKeyPubKey(key, NULL, 0);
    if (len > 0 && secp256k1_ec_pubkey_parse(_ctx, &pk, key->pubKey, len)) BRHash160(&hash, key->pubKey, len);
    return hash;
}

// simple version of secp256k1_ec_pubkey_parse(_ctx, &pk, key->pubKey, pkLen)
// assigns DER encoded pubKey to key and returns true on success
int BRKeyPubKeyDecode(secp256k1_pubkey *pk, const uint8_t *input, size_t inputlen)
{
    if (!(inputlen == 33 || inputlen == 65))
        return 0;

    pthread_once(&_ctx_once, _ctx_init);

    secp256k1_ge Q;

    memset(pk, 0, sizeof(*pk));
    secp256k1_eckey_pubkey_parse(&Q, input, inputlen);
    secp256k1_pubkey_save(pk, &Q);
    secp256k1_ge_clear(&Q);

    return 1;
}

