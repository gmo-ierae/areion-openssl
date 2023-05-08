/*
 * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for areion_opp cipher */

//#include "include/crypto/poly1305.h"
#include "cipher_chacha20.h"

#define NO_TLS_PAYLOAD_LENGTH ((size_t)-1)
#define AREION_OPP_IVLEN 12

typedef struct {
    uint64_t a;
    uint64_t b;
    uint64_t c;
    uint64_t d;
} opp_state_t;

typedef struct {
    PROV_CIPHER_CTX base;       /* must be first */
    opp_state_t Sa;
    opp_state_t Se;
    opp_state_t La;
    opp_state_t Le;
    unsigned char ad_buf[32];
    unsigned char buf[32];
    int ad_partial_len;
    int partial_len;
    unsigned char key[16];
    unsigned char tag[16];
} PROV_AREION_OPP_CTX;

typedef struct prov_cipher_hw_areion_opp_st {
    PROV_CIPHER_HW base; /* must be first */
    int (*aead_cipher)(PROV_CIPHER_CTX *dat, unsigned char *out, size_t *outl,
                       size_t outsize, const unsigned char *in, size_t len);
    int (*initiv)(PROV_CIPHER_CTX *ctx);
} PROV_CIPHER_HW_AREION_OPP;

const PROV_CIPHER_HW *ossl_prov_cipher_hw_areion_opp(size_t keybits);
