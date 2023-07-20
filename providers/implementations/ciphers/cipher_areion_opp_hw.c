/*
 * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2023 GMO Cybersecurity by Ierae, Inc. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* areion_opp cipher implementation */

#include "internal/endian.h"
#include "cipher_areion_opp.h"

#include <stdbool.h>
#include <immintrin.h>

/* Round Constant */
static const uint32_t RC[24*4] = {
	0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
	0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
	0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
	0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
	0x9216d5d9, 0x8979fb1b, 0xd1310ba6, 0x98dfb5ac,
	0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
	0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7,
	0x801f2e28, 0x58efc166, 0x36920d87, 0x1574e690,
	0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658,
	0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5,
	0x9c30d539, 0x2af26013, 0xc5d1b023, 0x286085f0,
	0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e,
	0x6c9e0e8b, 0xb01e8a3e, 0xd71577c1, 0xbd314b27,
	0x78af2fda, 0x55605c60, 0xe65525f3, 0xaa55ab94,
	0x57489862, 0x63e81440, 0x55ca396a, 0x2aab10b6,
	0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993,
	0xb3ee1411, 0x636fbc2a, 0x2ba9c55d, 0x741831f6,
	0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c,
	0x7a325381, 0x28958677, 0x3b8f4898, 0x6b4bb9af,
	0xc4bfe81b, 0x66282193, 0x61d809cc, 0xfb21a991,
	0x487cac60, 0x5dec8032, 0xef845d5d, 0xe98575b1,
	0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5,
	0xf6d6ff38, 0x3f442392, 0xe0b4482a, 0x48420040,
	0x69c8f04a, 0x9e1f9b5e, 0x21c66842, 0xf6e96c9a
};

#define RC0(i) _mm_setr_epi32(RC[(i)*4+0], RC[(i)*4+1], RC[(i)*4+2], RC[(i)*4+3])
#define RC1(i) _mm_setr_epi32(0, 0, 0, 0)

/* Round Function for the 256-bit permutation */
#define Round_Function_256(x0, x1, i) do{ \
	x1 = _mm_aesenc_si128(_mm_aesenc_si128(x0, RC0(i)), x1); \
	x0 = _mm_aesenclast_si128(x0, RC1(i)); \
} while(0)

/* 256-bit permutation */
#define perm256(x0, x1) do { \
	Round_Function_256(x0, x1, 0); \
	Round_Function_256(x1, x0, 1); \
	Round_Function_256(x0, x1, 2); \
	Round_Function_256(x1, x0, 3); \
	Round_Function_256(x0, x1, 4); \
	Round_Function_256(x1, x0, 5); \
	Round_Function_256(x0, x1, 6); \
	Round_Function_256(x1, x0, 7); \
	Round_Function_256(x0, x1, 8); \
	Round_Function_256(x1, x0, 9); \
} while(0)

/* Inversed Round Function for the 256-bit permutation */
#define Inv_Round_Function_256(x0, x1, i) do { \
	x0 = _mm_aesdeclast_si128(x0, RC1(i)); \
	x1 = _mm_aesenc_si128(_mm_aesenc_si128(x0, RC0(i)), x1); \
} while(0)

/* Inversed 256-bit permutation */
#define Inv_perm256(x0, x1) do { \
	Inv_Round_Function_256(x1, x0, 9); \
	Inv_Round_Function_256(x0, x1, 8); \
	Inv_Round_Function_256(x1, x0, 7); \
	Inv_Round_Function_256(x0, x1, 6); \
	Inv_Round_Function_256(x1, x0, 5); \
	Inv_Round_Function_256(x0, x1, 4); \
	Inv_Round_Function_256(x1, x0, 3); \
	Inv_Round_Function_256(x0, x1, 2); \
	Inv_Round_Function_256(x1, x0, 1); \
	Inv_Round_Function_256(x0, x1, 0); \
} while(0)

void permute_areion_256_ref(__m128i dst[2], const __m128i src[2])
{
    __m128i x0 = src[0];
    __m128i x1 = src[1];
    perm256(x0, x1);
    dst[0] = x0;
    dst[1] = x1;
}

void inverse_areion_256_ref(__m128i dst[2], const __m128i src[2])
{
    __m128i x0 = src[0];
    __m128i x1 = src[1];
    Inv_perm256(x0, x1);
    dst[0] = x0;
    dst[1] = x1;
}

void permute_areion_256u8_ref(uint8_t dst[32], const uint8_t src[32])
{
    const __m128i_u *src_p = (const __m128i_u *)src;
    __m128i_u *dst_p = (__m128i_u *)dst;

    __m128i x[2] = {
        _mm_loadu_si128(&src_p[0]),
        _mm_loadu_si128(&src_p[1])
    };
    __m128i y[2];
    permute_areion_256_ref(y, x);
    _mm_storeu_si128(&dst_p[0], y[0]);
    _mm_storeu_si128(&dst_p[1], y[1]);
}

void inverse_areion_256u8_ref(uint8_t dst[32], const uint8_t src[32])
{
    const __m128i_u *src_p = (const __m128i_u *)src;
    __m128i_u *dst_p = (__m128i_u *)dst;

    __m128i x[2] = {
        _mm_loadu_si128(&src_p[0]),
        _mm_loadu_si128(&src_p[1])
    };
    __m128i y[2];
    inverse_areion_256_ref(y, x);
    _mm_storeu_si128(&dst_p[0], y[0]);
    _mm_storeu_si128(&dst_p[1], y[1]);
}

/*
    OPP - MEM AEAD source code package

    :copyright: (c) 2015 by Philipp Jovanovic and Samuel Neves
    :license: Creative Commons CC0 1.0
*/
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uint64_t opp_word_t;

#define OPP_W 64           /* word size */
#define OPP_T (OPP_W *  2) /* tag size */
#define OPP_N (OPP_W *  2) /* nonce size */
#define OPP_K (OPP_W *  2) /* key size */
#define OPP_B (OPP_W *  4) /* permutation width */

#define BITS(x) (sizeof(x) * CHAR_BIT)
#define BYTES(x) (((x) + 7) / 8)
#define WORDS(x) (((x) + (OPP_W-1)) / OPP_W)

static inline opp_state_t load_state(const void *in)
{
    return *(opp_state_t *)in;
}

static inline void store_state(void *out, const opp_state_t *s)
{
    *(opp_state_t *)out = *s;
}

static inline opp_state_t zero_state()
{
    return (opp_state_t) { 0, 0, 0, 0 };
}

static inline opp_state_t xor_state(opp_state_t x, opp_state_t y)
{
    opp_state_t v;
    v.a = x.a ^ y.a;
    v.b = x.b ^ y.b;
    v.c = x.c ^ y.c;
    v.d = x.d ^ y.d;
    return v;
}

static inline opp_word_t rotl(opp_word_t x, int c)
{
    return (x << c) | (x >> (BITS(x) - c));
}

static inline void opp_permute(opp_state_t *state)
{
    permute_areion_256u8_ref((uint8_t *)state, (const uint8_t *)state);
}

static inline void opp_permute_inverse(opp_state_t *state)
{
    inverse_areion_256u8_ref((uint8_t *)state, (const uint8_t *)state);
}

static inline opp_state_t opp_pad(const uint8_t *in, const size_t inlen)
{
    uint8_t block[BYTES(OPP_B)];
    for (size_t i = 0; i < BYTES(OPP_B); i++) {
        if (i < inlen) {
            block[i] = in[i];
        } else if (i == inlen) {
            block[i] = 0x01;
        } else {
            block[i] = 0;
        }
    }
    return load_state(block);
}

static inline void store_state_trunc(uint8_t *out, size_t outlen, const opp_state_t *s)
{
    uint8_t block[BYTES(OPP_B)];
    store_state(block, s);
    memcpy(out, block, outlen);
}

static inline opp_state_t opp_init_mask(const unsigned char *k, const unsigned char *n)
{
    uint8_t block[BYTES(OPP_B)];
    memcpy(&block[0], n, 16);
    memcpy(&block[16], k, 16);
    opp_state_t mask = load_state(block);
    /* apply permutation */
    opp_permute(&mask);
    return mask;
}

/* 
  b = 256, w = 64, n = 4 
  Ref. Table 1 in [Granger et al., EUROCRYPT'16]
*/
static inline opp_state_t opp_phi(opp_state_t x)
{
    opp_state_t s;

    s.a = x.b;
    s.b = x.c;
    s.c = x.d;
    s.d = rotl(x.a, 3) ^ (x.d >> 5);

    return s;
}

/* alpha(x) = phi(x) */
static inline opp_state_t opp_alpha(opp_state_t x)
{
   return opp_phi(x);
}

/* beta(x) = phi(x) ^ x */
static inline opp_state_t opp_beta(opp_state_t x)
{
    opp_state_t y = opp_phi(x);
    return xor_state(y, x);
}

/* gamma(x) = phi^2(x) ^ phi(x) ^ x */
static inline opp_state_t opp_gamma(opp_state_t x)
{
    opp_state_t y = opp_phi(x);
    opp_state_t z = opp_phi(y);
    return xor_state(z, xor_state(y, x));
}

static inline opp_state_t opp_mem(opp_state_t x, opp_state_t m)
{
    opp_state_t block = xor_state(x, m);
    opp_permute(&block);
    return xor_state(block, m);
}

static inline opp_state_t opp_mem_inverse(opp_state_t x, opp_state_t m)
{
    opp_state_t block = xor_state(x, m);
    opp_permute_inverse(&block);
    return xor_state(block, m);
}

static inline void opp_absorb_block(opp_state_t *state, opp_state_t *mask, const uint8_t * in)
{
    opp_state_t inb = load_state(in);
    opp_state_t outb = opp_mem(inb, *mask);
    *state = xor_state(*state, outb);
    *mask = opp_alpha(*mask);
}

static inline void opp_absorb_lastblock(opp_state_t *state, opp_state_t *mask, const uint8_t *in, size_t inlen)
{
    *mask = opp_beta(*mask);
    opp_state_t inb = opp_pad(in, inlen);
    opp_state_t outb = opp_mem(inb, *mask);
    *state = xor_state(*state, outb);
    *mask = opp_alpha(*mask);
}

static inline void opp_encrypt_block(opp_state_t *state, opp_state_t *mask, uint8_t *out, const uint8_t *in)
{
    opp_state_t inb = load_state(in);
    opp_state_t outb = opp_mem(inb, *mask);
    store_state(out, &outb);
    *state = xor_state(*state, inb);
    *mask = opp_alpha(*mask);
}

static inline void opp_encrypt_lastblock(opp_state_t *state, opp_state_t *mask, uint8_t *out, const uint8_t *in, size_t inlen)
{
    *mask = opp_beta(*mask);
    opp_state_t inb = opp_pad(in, inlen);
    opp_state_t block = opp_mem(zero_state(), *mask);
    opp_state_t outb = xor_state(block, inb);
    store_state_trunc(out, inlen, &outb);
    *state = xor_state(*state, inb);
}

static inline void opp_decrypt_block(opp_state_t *state, opp_state_t *mask, uint8_t *out, const uint8_t *in)
{
    opp_state_t inb = load_state(in);
    opp_state_t outb = opp_mem_inverse(inb, *mask);
    store_state(out, &outb);
    *state = xor_state(*state, outb);
    *mask = opp_alpha(*mask);
}

static inline void opp_decrypt_lastblock(opp_state_t *state, opp_state_t *mask, uint8_t *out, const uint8_t *in, size_t inlen)
{
    *mask = opp_beta(*mask);
    opp_state_t inb = opp_pad(in, inlen);
    opp_state_t block = opp_mem(zero_state(), *mask);
    opp_state_t outb = xor_state(block, inb);
    store_state_trunc(out, inlen, &outb);
    opp_state_t plainb = opp_pad(out, inlen);
    *state = xor_state(*state, plainb);
}

static void opp_finalise(opp_state_t sa, opp_state_t se, opp_state_t mask, unsigned char *tag)
{
    opp_state_t m = opp_beta(opp_beta(mask));
    opp_state_t block = opp_mem(se, m);
    opp_state_t outb = xor_state(sa, block);
    store_state_trunc(tag, BYTES(OPP_T), &outb);
}

static int opp_verify_tag(const unsigned char *tag1, const unsigned char *tag2)
{
    unsigned acc = 0;
    size_t i;

    for(i = 0; i < BYTES(OPP_T); ++i)
    {
        acc |= tag1[i] ^ tag2[i];
    }
    return (((acc - 1) >> 8) & 1) - 1;
}

static bool initialize_areion_256_opp(bool enc, const uint8_t *n, const uint8_t *k, PROV_AREION_OPP_CTX *state)
{
    state->ad_partial_len = 0;
    state->partial_len = 0;
    state->Sa = zero_state();
    state->Se = zero_state();
    state->La = opp_init_mask(k, n);
    state->Le = opp_gamma(state->La);

    return true;
}

static bool update_areion_256_opp(uint8_t *out, size_t *olen, size_t olimit, uint8_t *in, size_t ilen, PROV_AREION_OPP_CTX *state, int enc)
{
    uint8_t *out_orig = out;
    if (!out) {
        if (olen) {
            *olen = 0;
        }
        // AD
        if (state->ad_partial_len > 0) {
            while (ilen > 0 && state->ad_partial_len < BYTES(OPP_B)) {
                state->ad_buf[state->ad_partial_len] = *in;
                state->ad_partial_len++;
                in++;
                ilen--;
            }
            if (state->ad_partial_len == BYTES(OPP_B)) {
                opp_absorb_block(&state->Sa, &state->La, state->ad_buf);
                state->ad_partial_len = 0;
                opp_alpha(state->La);
            }
        }
        while (ilen >= BYTES(OPP_B)) {
            opp_absorb_block(&state->Sa, &state->La, in);
            in += BYTES(OPP_B);
            ilen -= BYTES(OPP_B);
            opp_alpha(state->La);
        }
        while (ilen > 0) {
            state->ad_buf[state->ad_partial_len] = *in;
            state->ad_partial_len++;
            in++;
            ilen--;
        }
    } else {
        // plain/cipher text
        if (olimit < (state->partial_len + ilen) / BYTES(OPP_B) * BYTES(OPP_B)) {
            return false;
        }
        *olen = 0;
        if (state->partial_len > 0) {
            while (ilen > 0 && state->partial_len < BYTES(OPP_B)) {
                state->buf[state->partial_len] = *in;
                state->partial_len++;
                in++;
                ilen--;
            }
            if (state->partial_len == BYTES(OPP_B)) {
                if (enc) {
                    opp_encrypt_block(&state->Se, &state->Le, out, state->buf);
                } else {
                    opp_decrypt_block(&state->Se, &state->Le, out, state->buf);
                }
                state->partial_len = 0;
                out += BYTES(OPP_B);
                *olen += BYTES(OPP_B);
                opp_alpha(state->Le);
            }
        }
        while (ilen >= BYTES(OPP_B)) {
            if (enc) {
                opp_encrypt_block(&state->Se, &state->Le, out, in);
            } else {
                opp_decrypt_block(&state->Se, &state->Le, out, in);
            }
            in += BYTES(OPP_B);
            ilen -= BYTES(OPP_B);
            out += BYTES(OPP_B);
            *olen += BYTES(OPP_B);
            opp_alpha(state->Le);
        }
        while (ilen > 0) {
            state->buf[state->partial_len] = *in;
            state->partial_len++;
            in++;
            ilen--;
        }
    }
    return true;
}

static bool finalize_areion_256_opp(uint8_t *out, size_t *olen, size_t olimit, uint8_t *tag, PROV_AREION_OPP_CTX *state, int enc)
{
    uint8_t *out_orig = out;
    if (olimit < state->partial_len) {
        return false;
    }
    *olen = 0;
    if (state->ad_partial_len > 0) {
        opp_beta(state->La);
        opp_absorb_lastblock(&state->Sa, &state->La, state->ad_buf, state->ad_partial_len);
        state->ad_partial_len = 0;
    }

    if (state->partial_len > 0) {
        opp_beta(state->Le);
        if (enc) {
            opp_encrypt_lastblock(&state->Se, &state->Le, out, state->buf, state->partial_len);
        } else {
            opp_decrypt_lastblock(&state->Se, &state->Le, out, state->buf, state->partial_len);
        }
        out += state->partial_len;
        *olen += state->partial_len;
        state->partial_len = 0;
    }

    if (enc) {
        opp_finalise(state->Sa, state->Se, state->Le, tag);
    } else {
        unsigned char tag_computed[BYTES(OPP_T)];
        opp_finalise(state->Sa, state->Se, state->Le, tag_computed);
        if (opp_verify_tag(tag_computed, tag) != 0) {
            return false;
        }
    }

    return true;
}

static int areion_opp_initkey(PROV_CIPHER_CTX *bctx,
                                     const unsigned char *key, size_t keylen)
{
    PROV_AREION_OPP_CTX *ctx = (PROV_AREION_OPP_CTX *)bctx;
    if (keylen != sizeof ctx->key) {
        return 0;
    }
    memcpy(ctx->key, key, keylen);
    return 1;
}

static int areion_opp_initiv(PROV_CIPHER_CTX *bctx)
{
    PROV_AREION_OPP_CTX *ctx = (PROV_AREION_OPP_CTX *)bctx;
    initialize_areion_256_opp(bctx->enc, bctx->iv, ctx->key, ctx);
    return 1;
}

static int areion_opp_aead_cipher(PROV_CIPHER_CTX *bctx,
                                         unsigned char *out, size_t *outl, size_t outsize,
                                         const unsigned char *in, size_t inl)
{
    PROV_AREION_OPP_CTX *ctx = (PROV_AREION_OPP_CTX *)bctx;

    if (in != NULL) {
        return update_areion_256_opp(out, outl, outsize, in, inl, ctx, bctx->enc);
    } else {
        return finalize_areion_256_opp(out, outl, outsize, ctx->tag, ctx, bctx->enc);
    }
}

static const PROV_CIPHER_HW_AREION_OPP areion_opp_hw =
{
    { areion_opp_initkey, NULL },
    areion_opp_aead_cipher,
    areion_opp_initiv,
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_areion_opp(size_t keybits)
{
    return (PROV_CIPHER_HW *)&areion_opp_hw;
}
