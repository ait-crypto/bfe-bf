#include "include/bfibe.h"

#include <stdio.h>
#include <stddef.h>
#include <FIPS202-opt64/SimpleFIPS202.h>
#include "relic/relic.h"
#include "util.h"
#include "logger.h"
#include "include/err_codes.h"

int bf_ibe_setup(bf_ibe_keys_t *keys) {
    int status = BFE_SUCCESS;

    bn_t group1Order;
    ep_t publicKey;
    bn_t masterKey;

    bn_null(group1Order);
    ep_null(publicKey);
    bn_null(masterKey);
    ep_null(keys->publicKey);
    bn_null(keys->masterKey);

    TRY {
        bn_new(group1Order);
        ep_new(publicKey);
        bn_new(masterKey);
        ep_new(keys->publicKey);
        bn_new(keys->masterKey);

        ep_curve_get_ord(group1Order);
        bn_rand_mod(masterKey, group1Order);
        ep_mul_gen(publicKey, masterKey);

        ep_copy(keys->publicKey, publicKey);
        bn_copy(keys->masterKey, masterKey);

    } CATCH_ANY {
        logger_log(LOGGER_ERROR, "Error occurred in IBE setup function.");
        status = BFE_ERR_GENERAL;
    } FINALLY {
        bn_free(group1Order);
        ep_free(publicKey);
        bn_free(masterKey);
    }

    return status;
}

void bf_ibe_free_keys(bf_ibe_keys_t* keys)
{
    ep_free(keys->publicKey);
    bn_free(keys->masterKey);
}

int bf_ibe_extract(ep2_t privateKey, bn_t masterKey, uint8_t *id, int idLen) {
    int status = BFE_SUCCESS;
    ep2_t qid;

    ep2_null(privateKey);
    ep2_null(qid);

    TRY {
        ep2_new(privateKey);
        ep2_new(qid);

        ep2_map(qid, id, idLen);
        ep2_mul(privateKey, qid, masterKey);
    } CATCH_ANY {
        logger_log(LOGGER_ERROR, "Error occurred in IBE extract function.");
        status = BFE_ERR_GENERAL;
    } FINALLY {
        ep2_free(qid);
    };

    return status;
}

int bf_ibe_encrypt(bf_ibe_ciphertext_t *ciphertext, ep_t publicKey, uint8_t *id, int idLen, uint8_t *message, bn_t r) {
    int status = BFE_SUCCESS;
    uint8_t digest[ciphertext->vLen];
    ep_t publicKeyR;
    ep2_t qid;
    fp12_t gIDR;
    bn_t group1Order;
    ep_t ciphertextLeft;

    ep_null(publicKeyR);
    ep2_null(qid);
    fp12_null(gIDR);
    ep_null(ciphertextLeft);
    ep_null(ciphertext->u);

    TRY {
        ep_new(publicKeyR);
        ep2_new(qid);
        fp12_new(gIDR);
        bn_new(group1Order);
        ep_new(ciphertextLeft);
        ep_new(ciphertext->u);

        ep_mul_gen(ciphertextLeft, r);
        ep_mul(publicKeyR, publicKey, r);

        ep2_map(qid, id, idLen);
        pp_map_k12(gIDR, publicKeyR, qid);

        int binSize = fp12_size_bin(gIDR, 0);
        uint8_t bin[binSize];
        fp12_write_bin(bin, binSize, gIDR, 0);
        SHAKE256(digest, ciphertext->vLen, bin, binSize);
        byteArraysXOR(ciphertext->v, digest, message, ciphertext->vLen, ciphertext->vLen);
        ep_copy(ciphertext->u, ciphertextLeft);
    } CATCH_ANY {
        logger_log(LOGGER_ERROR, "Error occurred in IBE encrypt function.");
        status = BFE_ERR_GENERAL;
    } FINALLY {
        ep2_free(qid);
        fp12_free(gIDR);
        bn_free(group1Order);
        ep_free(ciphertextLeft);
        ep_free(publicKeyR);
    };

    return status;
}

int bf_ibe_decrypt(uint8_t *message, bf_ibe_ciphertext_t *ciphertext, ep2_t privateKey) {
    int status = BFE_SUCCESS;
    uint8_t digest[ciphertext->vLen];
    fp12_t dU;

    fp12_null(dU);

    TRY {
        fp12_new(dU);

        pp_map_k12(dU, ciphertext->u, privateKey);
        int binSize = fp12_size_bin(dU, 0);
        uint8_t bin[binSize];
        fp12_write_bin(bin, binSize, dU, 0);
        md_map(digest, bin, binSize);
        SHAKE256(digest, ciphertext->vLen, bin, binSize);
        byteArraysXOR(message, digest, ciphertext->v, ciphertext->vLen, ciphertext->vLen);
    } CATCH_ANY {
        logger_log(LOGGER_ERROR, "Error occurred in IBE decrypt function.");
        status = BFE_ERR_GENERAL;
    } FINALLY {
        fp12_free(dU);
    };

    return status;
}

bf_ibe_ciphertext_t *bf_ibe_init_ciphertext(int messageLen) {
    bf_ibe_ciphertext_t *ciphertext = malloc(offsetof(bf_ibe_ciphertext_t, v) + messageLen * sizeof(ciphertext->v[0]));
    ciphertext->vLen = messageLen;
    return ciphertext;
}

void bf_ibe_free_ciphertext(bf_ibe_ciphertext_t *ciphertext) {
    ep_free(ciphertext->u);
    free(ciphertext);
}

__attribute__((constructor)) void coreInit (void)
{
    if (core_init() != RLC_OK) {
        core_clean();
    }
    ep_param_set_any_pairf();

}
__attribute__((destructor)) void coreClean (void)
{
    core_clean();
}