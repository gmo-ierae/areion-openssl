/*
 * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2023 GMO Cybersecurity by Ierae, Inc. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for areion_opp cipher */

#include <openssl/proverr.h>
#include "cipher_areion_opp.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"

#define AREION_OPP_KEYLEN 16
#define AREION_OPP_BLKLEN 32
#define AREION_OPP_TAGLEN 16
#define AREION_OPP_MAX_IVLEN 12
#define AREION_OPP_MODE 0
#define AREION_OPP_FLAGS (PROV_CIPHER_FLAG_AEAD                         \
                                 | PROV_CIPHER_FLAG_CUSTOM_IV)

static OSSL_FUNC_cipher_newctx_fn areion_opp_newctx;
static OSSL_FUNC_cipher_freectx_fn areion_opp_freectx;
static OSSL_FUNC_cipher_encrypt_init_fn areion_opp_einit;
static OSSL_FUNC_cipher_decrypt_init_fn areion_opp_dinit;
static OSSL_FUNC_cipher_get_params_fn areion_opp_get_params;
static OSSL_FUNC_cipher_get_ctx_params_fn areion_opp_get_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn areion_opp_set_ctx_params;
static OSSL_FUNC_cipher_cipher_fn areion_opp_cipher;
static OSSL_FUNC_cipher_final_fn areion_opp_final;
static OSSL_FUNC_cipher_gettable_ctx_params_fn areion_opp_gettable_ctx_params;
#define areion_opp_settable_ctx_params ossl_cipher_aead_settable_ctx_params
#define areion_opp_gettable_params ossl_cipher_generic_gettable_params
#define areion_opp_update areion_opp_cipher

static void *areion_opp_newctx(void *provctx)
{
    PROV_AREION_OPP_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL) {
        ossl_cipher_generic_initkey(&ctx->base, AREION_OPP_KEYLEN * 8,
                                    AREION_OPP_BLKLEN * 8,
                                    AREION_OPP_IVLEN * 8,
                                    AREION_OPP_MODE,
                                    AREION_OPP_FLAGS,
                                    ossl_prov_cipher_hw_areion_opp(
                                        AREION_OPP_KEYLEN * 8),
                                    NULL);
    }
    return ctx;
}

static void areion_opp_freectx(void *vctx)
{
    PROV_AREION_OPP_CTX *ctx = (PROV_AREION_OPP_CTX *)vctx;

    if (ctx != NULL) {
        ossl_cipher_generic_reset_ctx((PROV_CIPHER_CTX *)vctx);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

static int areion_opp_get_params(OSSL_PARAM params[])
{
    return ossl_cipher_generic_get_params(params, 0, AREION_OPP_FLAGS,
                                          AREION_OPP_KEYLEN * 8,
                                          AREION_OPP_BLKLEN * 8,
                                          AREION_OPP_IVLEN * 8);
}

static int areion_opp_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_AREION_OPP_CTX *ctx = (PROV_AREION_OPP_CTX *)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_set_size_t(p, AREION_OPP_IVLEN)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, AREION_OPP_KEYLEN)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, AREION_OPP_TAGLEN)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
        if (!ctx->base.enc) {
            ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_SET);
            return 0;
        }
        if (p->data_size != AREION_OPP_TAGLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG_LENGTH);
            return 0;
        }
        memcpy(p->data, ctx->tag, p->data_size);
    }

    return 1;
}

static const OSSL_PARAM areion_opp_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *areion_opp_gettable_ctx_params
    (ossl_unused void *cctx, ossl_unused void *provctx)
{
    return areion_opp_known_gettable_ctx_params;
}

static int areion_opp_set_ctx_params(void *vctx,
                                            const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    size_t len;
    PROV_AREION_OPP_CTX *ctx = (PROV_AREION_OPP_CTX *)vctx;
    PROV_CIPHER_HW_AREION_OPP *hw =
        (PROV_CIPHER_HW_AREION_OPP *)ctx->base.hw;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len != AREION_OPP_KEYLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len != AREION_OPP_MAX_IVLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (p->data_size != AREION_OPP_TAGLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG_LENGTH);
            return 0;
        }
        if (p->data != NULL) {
            if (ctx->base.enc) {
                ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_NEEDED);
                return 0;
            }
            memcpy(ctx->tag, p->data, p->data_size);
        }
    }

    /* ignore OSSL_CIPHER_PARAM_AEAD_MAC_KEY */
    return 1;
}

static int areion_opp_einit(void *vctx, const unsigned char *key,
                                  size_t keylen, const unsigned char *iv,
                                  size_t ivlen, const OSSL_PARAM params[])
{
    int ret;

    /* The generic function checks for ossl_prov_is_running() */
    ret = ossl_cipher_generic_einit(vctx, key, keylen, iv, ivlen, NULL);
    if (ret && iv != NULL) {
        PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
        PROV_CIPHER_HW_AREION_OPP *hw =
            (PROV_CIPHER_HW_AREION_OPP *)ctx->hw;

        hw->initiv(ctx);
    }
    if (ret && !areion_opp_set_ctx_params(vctx, params))
        ret = 0;
    return ret;
}

static int areion_opp_dinit(void *vctx, const unsigned char *key,
                                  size_t keylen, const unsigned char *iv,
                                  size_t ivlen, const OSSL_PARAM params[])
{
    int ret;

    /* The generic function checks for ossl_prov_is_running() */
    ret = ossl_cipher_generic_dinit(vctx, key, keylen, iv, ivlen, NULL);
    if (ret && iv != NULL) {
        PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
        PROV_CIPHER_HW_AREION_OPP *hw =
            (PROV_CIPHER_HW_AREION_OPP *)ctx->hw;

        hw->initiv(ctx);
    }
    if (ret && !areion_opp_set_ctx_params(vctx, params))
        ret = 0;
    return ret;
}

static int areion_opp_cipher(void *vctx, unsigned char *out,
                                    size_t *outl, size_t outsize,
                                    const unsigned char *in, size_t inl)
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
    PROV_CIPHER_HW_AREION_OPP *hw =
        (PROV_CIPHER_HW_AREION_OPP *)ctx->hw;

    if (!ossl_prov_is_running())
        return 0;

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (!hw->aead_cipher(ctx, out, outl, outsize, in, inl))
        return 0;

    return 1;
}

static int areion_opp_final(void *vctx, unsigned char *out, size_t *outl,
                                   size_t outsize)
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
    PROV_CIPHER_HW_AREION_OPP *hw =
        (PROV_CIPHER_HW_AREION_OPP *)ctx->hw;

    if (!ossl_prov_is_running())
        return 0;

    if (hw->aead_cipher(ctx, out, outl, outsize, NULL, 0) <= 0)
        return 0;

    return 1;
}

/* ossl_areion_opp_functions */
const OSSL_DISPATCH ossl_areion_opp_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))areion_opp_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))areion_opp_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))areion_opp_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))areion_opp_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))areion_opp_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))areion_opp_final },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))areion_opp_cipher },
    { OSSL_FUNC_CIPHER_GET_PARAMS,
        (void (*)(void))areion_opp_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
        (void (*)(void))areion_opp_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
         (void (*)(void))areion_opp_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
        (void (*)(void))areion_opp_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
        (void (*)(void))areion_opp_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
        (void (*)(void))areion_opp_settable_ctx_params },
    { 0, NULL }
};

