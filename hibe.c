#include <relic/relic.h>
#include <stddef.h>
#include <FIPS202-opt64/SimpleFIPS202.h>
#include "include/hibe.h"
#include "logger.h"
#include "util.h"
#include "include/err_codes.h"

int hibe_setup(hibe_setup_pair_t *setupPair) {
    int status = BFE_SUCCESS;
    if (setupPair->systemParams->hLen < 1) {
        logger_log(LOGGER_ERROR, "Provided tree depth has to be positive!");
        return BFE_ERR_INVALID_PARAM;
    }

    bn_t order, alpha, delta;
    ep_t masterKey;
    bn_null(order);
    bn_null(alpha);
    bn_null(delta);
    ep_null(masterKey);
    ep_null(returnPair.masterKey);

    TRY {
        bn_new(order);
        bn_new(alpha);
        bn_new(delta);
        ep_new(masterKey);
        ep_new(returnPair.masterKey);
        ep_curve_get_ord(order);
        bn_rand_mod(alpha, order);
        bn_copy(delta, alpha);

        for (int i = 0; i < 3; i++) {
            ep_null(systemParams->g[i].g1_g);
            ep2_null(systemParams->g[i].g2_g);
            ep_new(systemParams->g[i].g1_g);
            ep2_new(systemParams->g[i].g2_g);
            ep_mul_gen(setupPair->systemParams->g[i].g1_g, delta);
            ep2_mul_gen(setupPair->systemParams->g[i].g2_g, delta);
            bn_rand_mod(delta, order);
        }

        for (int i = 0; i < setupPair->systemParams->hLen; i++) {
            ep_null(systemParams->h[i].g1_h);
            ep2_null(systemParams->h[i].g2_h);
            ep_new(systemParams->h[i].g1_h);
            ep2_new(systemParams->h[i].g2_h);
            bn_rand_mod(delta, order);
            ep_mul_gen(setupPair->systemParams->h[i].g1_h, delta);
            ep2_mul_gen(setupPair->systemParams->h[i].g2_h, delta);
        }

        ep_mul(masterKey, setupPair->systemParams->g[1].g1_g, alpha);
        ep_copy(setupPair->masterKey, masterKey);
    } CATCH_ANY {
        logger_log(LOGGER_ERROR, "Error occurred in HIBE setup function.");
        status = BFE_ERR_GENERAL;
    } FINALLY {
        bn_free(order);
        bn_free(alpha);
        bn_free(delta);
        ep_free(masterKey);
    }

    return status;
}

int hibe_extract(hibe_private_key_t *privateKey, hibe_system_params_t *systemParams, ep_t masterKey, const char *id) {
    int status = BFE_SUCCESS;
    bn_t order, r, two;
    ep_t a0, hTemp;

    bn_null(order);
    bn_null(r);
    bn_null(two);
    ep_null(a0);
    ep_null(hTemp);
    ep_null(privateKey->a0);
    ep_null(privateKey->a1);

    TRY {
        bn_new(order);
        bn_new(r);
        bn_new(two);
        bn_set_dig(two, 2);
        ep_new(a0);
        ep_set_infty(a0);
        ep_new(hTemp);
        ep_new(privateKey->a0);
        ep_new(privateKey->a1);

        ep_curve_get_ord(order);
        bn_rand_mod(r, order);

        for (int i = 0; i < strlen(id); i++) {
            if (id[i] == '0') {
                ep_add_basic(a0, a0, systemParams->h[i].g1_h);
            } else {
                ep_mul(hTemp, systemParams->h[i].g1_h, two);
                ep_add_basic(a0, a0, hTemp);
            }
        }

        ep_add_basic(a0, a0, systemParams->g[2].g1_g);
        ep_mul(a0, a0, r);
        ep_add_basic(a0, a0, masterKey);

        for (size_t i = 0; i < privateKey->bLen; i++) {
            ep_null(privateKey->b[i]);
            ep_new(privateKey->b[i]);
            ep_mul(privateKey->b[i], systemParams->h[i + strlen(id)].g1_h, r);
        }

        ep_copy(privateKey->a0, a0);
        ep_mul_gen(privateKey->a1, r);
    } CATCH_ANY {
        logger_log(LOGGER_ERROR, "Error occurred in HIBE extract function.");
        status = BFE_ERR_GENERAL;
    } FINALLY {
        bn_free(order);
        bn_free(r);
        bn_free(two);
        ep_free(a0);
        ep_free(hTemp);
    }

    return status;
}

int hibe_derive(hibe_private_key_t *privateKey, hibe_system_params_t *systemParams, hibe_private_key_t *parentPrivateKey, const char *id) {
    int status = BFE_SUCCESS;
    bn_t order, t, two;
    ep_t a0, hTemp;

    bn_null(order);
    bn_null(t);
    bn_null(two);
    ep_null(a0);
    ep_null(hTemp);
    ep_null(privateKey->a0);
    ep_null(privateKey->a1);

    TRY {
        bn_new(order);
        bn_new(t);
        bn_new(two);
        bn_set_dig(two, 2);
        ep_new(a0);
        ep_new(hTemp);
        ep_set_infty(a0);
        ep_new(privateKey->a0);
        ep_new(privateKey->a1);

        ep_curve_get_ord(order);
        bn_rand_mod(t, order);

        for (int i = 0; i < strlen(id); i++) {
            if (id[i] == '0') {
                ep_add_basic(a0, a0, systemParams->h[i].g1_h);
            } else {
                ep_mul(hTemp, systemParams->h[i].g1_h, two);
                ep_add_basic(a0, a0, hTemp);
            }
        }

        ep_add_basic(a0, a0, systemParams->g[2].g1_g);
        ep_mul(a0, a0, t);
        ep_add_basic(a0, a0, parentPrivateKey->a0);

        if (id[strlen(id) - 1] == '0') {
            ep_add_basic(a0, a0, parentPrivateKey->b[0]);
        } else {
            ep_mul(hTemp, parentPrivateKey->b[0], two);
            ep_add_basic(a0, a0, hTemp);
        }

        for (size_t i = 0; i < privateKey->bLen; i++) {
            ep_null(privateKey->b[i]);
            ep_new(privateKey->b[i]);
            ep_mul(privateKey->b[i], systemParams->h[i + strlen(id)].g1_h, t);
            ep_add_basic(privateKey->b[i], privateKey->b[i], parentPrivateKey->b[i + 1]);
        }

        ep_copy(privateKey->a0, a0);
        ep_mul_gen(privateKey->a1, t);
        ep_add_basic(privateKey->a1, privateKey->a1, parentPrivateKey->a1);
    } CATCH_ANY {
        logger_log(LOGGER_ERROR, "Error occurred in HIBE derive function.");
        status = BFE_ERR_GENERAL;
    } FINALLY {
        bn_free(order);
        bn_free(t);
        bn_free(two);
        ep_free(a0);
        ep_free(hTemp);
    }

    return status;
}

int hibe_encrypt(hibe_ciphertext_t *ciphertext, hibe_system_params_t *systemParams, const char *id, uint8_t *message) {
    int status = BFE_SUCCESS;

    uint8_t digest[ciphertext->aLen];
    bn_t order, s;
    fp12_t a;
    ep_t gTemp;
    ep2_t b, c, hTemp;

    bn_null(order);
    bn_null(s);
    fp12_null(a);
    ep_null(gTemp);
    ep2_null(b);
    ep2_null(c);
    ep2_null(hTemp);
    ep2_null(ciphertext->b);
    ep2_null(ciphertext->c);

    TRY {
        bn_new(order);
        bn_new(s);
        fp12_new(a);
        ep_new(gTemp);
        ep2_new(b);
        ep2_new(c);
        ep2_new(hTemp);
        ep2_set_infty(c);
        ep2_new(ciphertext->b);
        ep2_new(ciphertext->c);

        ep_curve_get_ord(order);
        bn_rand_mod(s, order);

        ep_mul(gTemp, systemParams->g[0].g1_g, s);
        pp_map_k12(a, gTemp, systemParams->g[1].g2_g);

        int binSize = fp12_size_bin(a, 0);
        uint8_t bin[binSize];
        fp12_write_bin(bin, binSize, a, 0);
        SHAKE256(digest, ciphertext->aLen, bin, binSize);
        byteArraysXOR(ciphertext->a, digest, message, ciphertext->aLen, ciphertext->aLen);

        ep2_mul_gen(b, s);

        for (int i = 0; i < strlen(id); i++) {
          if (id[i] == '0') {
            ep2_add_basic(c, c, systemParams->h[i].g2_h);
          } else {
            ep2_dbl_basic(hTemp, systemParams->h[i].g2_h);
            ep2_add_basic(c, c, hTemp);
          }
        }

        ep2_add_basic(c, c, systemParams->g[2].g2_g);
        ep2_mul(c, c, s);

        ep2_copy(ciphertext->b, b);
        ep2_copy(ciphertext->c, c);

    } CATCH_ANY {
        logger_log(LOGGER_ERROR, "Error occurred in HIBE encrypt function.");
        status = BFE_ERR_GENERAL;
    } FINALLY {
        bn_free(order);
        bn_free(s);
        fp12_free(a);
        ep2_free(b);
        ep2_free(c);
        ep2_free(hTemp);
        ep_free(gTemp);
    }

    return status;
}

int hibe_decrypt(uint8_t *message, hibe_ciphertext_t *ciphertext, hibe_private_key_t *privateKey) {
    int status = BFE_SUCCESS;
    fp12_t numerator, denominator, pairingResult;
    ep_t temp;
    uint8_t digest[ciphertext->aLen];

    ep_null(temp);
    fp12_null(numerator);
    fp12_null(denominator);
    fp12_null(pairingResult);

    TRY {
        ep_new(temp);
        fp12_new(numerator);
        fp12_new(denominator);
        fp12_new(pairingResult);

        ep_neg(temp, privateKey->a1);
        pp_map_k12(numerator, privateKey->a0, ciphertext->b);
        pp_map_k12(denominator, temp, ciphertext->c);

        fp12_mul(pairingResult, numerator, denominator);

        int binSize = fp12_size_bin(pairingResult, 0);
        uint8_t bin[binSize];
        fp12_write_bin(bin, binSize, pairingResult, 0);
        SHAKE256(digest, ciphertext->aLen, bin, binSize);
        byteArraysXOR(message, digest, ciphertext->a, ciphertext->aLen, ciphertext->aLen);

    } CATCH_ANY {
        logger_log(LOGGER_ERROR, "Error occurred in HIBE decrypt function.");
        status = BFE_ERR_GENERAL;
    } FINALLY {
        fp12_free(numerator);
        fp12_free(denominator);
        fp12_free(pairingResult);
        ep_free(temp);
    }

    return status;
}

void hibe_free_system_params(hibe_system_params_t *systemParams) {
    for (int i = 0; i < 3; i++) {
        ep_free(systemParams->g[i].g1_g);
        ep2_free(systemParams->g[i].g2_g);
    }
    for (int i = 0; i < systemParams->hLen; i++) {
        ep_free(systemParams->h[i].g1_h);
        ep2_free(systemParams->h[i].g2_h);
    }
}

hibe_setup_pair_t *hibe_init_setup_pair(int depth) {
    hibe_setup_pair_t *setupPair = malloc(sizeof(hibe_setup_pair_t));
    setupPair->systemParams = malloc(offsetof(hibe_system_params_t, h) + depth * sizeof(setupPair->systemParams->h[0]));
    setupPair->systemParams->hLen = depth;
    return setupPair;
}

void hibe_free_setup_pair(hibe_setup_pair_t *setupPair) {
    hibe_free_system_params(setupPair->systemParams);
    ep_free(setupPair->masterKey);
    free(setupPair);
}

hibe_private_key_t *hibe_init_private_key(hibe_system_params_t *systemParams, const char *id) {
    size_t bLen = systemParams->hLen - strlen(id);
    hibe_private_key_t *privateKey = malloc(offsetof(hibe_private_key_t, b) + bLen * sizeof(privateKey->b[0]));
    privateKey->bLen = bLen;
    return privateKey;
}

void hibe_free_private_key(hibe_private_key_t *privateKey) {
    ep_free(privateKey->a0);
    ep_free(privateKey->a1);
    for (int i = 0; i < privateKey->bLen; i++) {
        ep_free(privateKey->b[i]);
    }
}

hibe_ciphertext_t *hibe_init_ciphertext(int messageLen) {
    hibe_ciphertext_t *ciphertext = malloc(offsetof(hibe_ciphertext_t, a) + messageLen * sizeof(ciphertext->a[0]));
    ciphertext->aLen = messageLen;
    return ciphertext;
}

void hibe_free_ciphertext(hibe_ciphertext_t *ciphertext) {
    ep2_free(ciphertext->b);
    ep2_free(ciphertext->c);
    free(ciphertext);
}