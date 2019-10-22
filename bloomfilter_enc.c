#include <stddef.h>
#include <math.h>
#include <FIPS202-opt64/SimpleFIPS202.h>
#include "include/bloomfilter_enc.h"
#include "include/bloomfilter.h"
#include "include/bfibe.h"
#include "logger.h"
#include "util.h"
#include "include/err_codes.h"

bloomfilter_enc_ciphertext_pair_t *bloomfilter_enc_init_ciphertext_pair(bloomfilter_enc_system_params_t systemParams);

int bloomfilter_enc_setup(bloomfilter_enc_setup_pair_t *setupPair) {
    int status = BFE_SUCCESS;
    bf_ibe_keys_t ibeKeys;
    bf_ibe_setup(&ibeKeys);

    ep_null(setupPair->systemParams.publicKey);
    TRY {
        ep_new(setupPair->systemParams.publicKey);
        ep_copy(setupPair->systemParams.publicKey, ibeKeys.publicKey);
        for (int i = 0; i < setupPair->systemParams.filterSize; i++) {
            status = bf_ibe_extract(setupPair->secretKey->secretKey[i], ibeKeys.masterKey, (uint8_t *) &i, sizeof(i));
            if (status) {
                break;
            }
        }
    } CATCH_ANY {
        logger_log(LOGGER_ERROR, "Error occurred in Bloom Filter Encryption setup function.");
        status = BFE_ERR_GENERAL;
    } FINALLY {

    }

    bf_ibe_free_keys(&ibeKeys);

    return status;
}

int _bloomfilter_enc_encrypt(bloomfilter_enc_ciphertext_pair_t *ciphertextPair, bloomfilter_enc_system_params_t systemParams, bn_t r, uint8_t *K) {
    int status = BFE_SUCCESS;
    int bitPositions[systemParams.filterHashCount];
    memcpy(ciphertextPair->K, K, ciphertextPair->KLen);

    int i;
    ep_t gR;

    ep_null(gR);
    ep_null(ciphertext->u);

    TRY {
        ep_new(gR);
        ep_new(ciphertext->u);

        ep_mul_gen(gR, r);

        int binLen = ep_size_bin(gR, 0);
        uint8_t bin[binLen];
        ep_write_bin(bin, binLen, gR, 0);
        bloomfilter_get_bit_positions(bitPositions, bin, binLen, systemParams.filterHashCount, systemParams.filterSize);

        bf_ibe_ciphertext_t *tempCiphertext;
        for (i = 0; i < systemParams.filterHashCount; i++) {
            tempCiphertext = bf_ibe_init_ciphertext(ciphertextPair->KLen);
            status = bf_ibe_encrypt(tempCiphertext, systemParams.publicKey, (uint8_t *) &bitPositions[i], sizeof(i), ciphertextPair->K, r);
            if (status) {
                bf_ibe_free_ciphertext(tempCiphertext);
                break;
            }
            memcpy(&ciphertextPair->ciphertext->v[i * systemParams.keyLength], tempCiphertext->v, tempCiphertext->vLen);
            if (i == 0) {
                ep_copy(ciphertextPair->ciphertext->u, tempCiphertext->u);
            }
            bf_ibe_free_ciphertext(tempCiphertext);
        }
    } CATCH_ANY {
        logger_log(LOGGER_ERROR, "Error occurred in Bloom Filter Encryption encrypt function.");
        status = BFE_ERR_GENERAL;
    } FINALLY {
        ep_free(gR);
    }

    return status;
}

int bloomfilter_enc_encrypt_key(bloomfilter_enc_ciphertext_pair_t *ciphertextPair, bloomfilter_enc_system_params_t systemParams, uint8_t *K) {
    int status = BFE_SUCCESS;
    bn_t group1Order;
    bn_t r;

    bn_null(group1Order);
    bn_null(r);

    TRY {
        bn_new(group1Order);
        bn_new(r);

        ep_curve_get_ord(group1Order);

        int exponentLength = bn_size_bin(group1Order);
        int totalRandLength = systemParams.keyLength + exponentLength;
        uint8_t randDigest[totalRandLength];
        SHAKE256(randDigest, totalRandLength, K, systemParams.keyLength);
        bn_read_bin(r, randDigest, exponentLength);

        status = _bloomfilter_enc_encrypt(ciphertextPair, systemParams, r, K);
        if (!status) {
            memcpy(ciphertextPair->K, &K[exponentLength], ciphertextPair->KLen);
        }
    } CATCH_ANY {
        logger_log(LOGGER_ERROR, "Error occurred in Bloom Filter Encryption encrypt function.");
        status = BFE_ERR_GENERAL;
    } FINALLY {
        bn_free(group1Order);
        bn_free(r);
    }

    return status;
}

int bloomfilter_enc_encrypt(bloomfilter_enc_ciphertext_pair_t *ciphertextPair, bloomfilter_enc_system_params_t systemParams) {
    uint8_t K[systemParams.keyLength];
    generateRandomBytes(K, systemParams.keyLength);

    return bloomfilter_enc_encrypt_key(ciphertextPair, systemParams, K);
}

void bloomfilter_enc_puncture(bloomfilter_enc_secret_key_t *secretKey, bloomfilter_enc_ciphertext_t *ciphertext) {
    int affectedIndexes[secretKey->filter.hashCount];
    bloomfilter_add(&secretKey->filter, ciphertext->u, sizeof(ciphertext->u));
    bloomfilter_get_bit_positions(affectedIndexes, ciphertext->u, sizeof(ciphertext->u), secretKey->filter.hashCount, bloomfilter_get_size(secretKey->filter));
    for (int i = 0; i < secretKey->filter.hashCount; i++) {
        ep2_free(secretKey->secretKey[affectedIndexes[i]]);
    }
    logger_log(LOGGER_INFO, "The key has been punctured");
}

int bloomfilter_enc_ciphertext_cmp(bloomfilter_enc_ciphertext_t *ciphertext1, bloomfilter_enc_ciphertext_t *ciphertext2) {
    return ep_cmp(ciphertext1->u, ciphertext2->u) == RLC_NE
           || ciphertext1->vLen != ciphertext2->vLen
           || memcmp(ciphertext1->v, ciphertext2->v, ciphertext1->vLen) != 0;
}

int bloomfilter_enc_decrypt(uint8_t *key, bloomfilter_enc_system_params_t systemParams, bloomfilter_enc_secret_key_t *secretKey, bloomfilter_enc_ciphertext_t *ciphertext) {
    int status = BFE_SUCCESS;
    logger_log(LOGGER_INFO, "Decrypting the secret key.");
    if (bloomfilter_maybe_contains(secretKey->filter, ciphertext->u, sizeof(ciphertext->u))) {
        logger_log(LOGGER_WARNING, "Secret key already punctured with the given ciphertext!");
        return BFE_ERR_KEY_PUNCTURED;
    }
    uint8_t tempKey[systemParams.keyLength];
    int affectedIndexes[secretKey->filter.hashCount];
    bf_ibe_ciphertext_t *ibeCiphertext = malloc(offsetof(bf_ibe_ciphertext_t, v) + systemParams.keyLength * sizeof(ibeCiphertext->v[0]));
    ibeCiphertext->vLen = systemParams.keyLength;

    bn_t r, group1Order;
    bloomfilter_enc_ciphertext_pair_t *genCiphertextPair;

    ep_null(ibeCiphertext->u);
    bn_null(r);
    bn_null(group1Order);

    TRY {
        ep_new(ibeCiphertext->u);
        bn_new(r);
        bn_new(group1Order);

        int binLen = ep_size_bin(ciphertext->u, 0);
        uint8_t bin[binLen];
        ep_write_bin(bin, binLen, ciphertext->u, 0);
        bloomfilter_get_bit_positions(affectedIndexes, bin, binLen, secretKey->filter.hashCount, bloomfilter_get_size(secretKey->filter));

        for (int i = 0; i < secretKey->filter.hashCount; i++) {
            if (secretKey->secretKey[affectedIndexes[i]] != NULL) {
                  ep_copy(ibeCiphertext->u, ciphertext->u);
                  memcpy(ibeCiphertext->v, &ciphertext->v[i * ibeCiphertext->vLen], ibeCiphertext->vLen);
                  status = bf_ibe_decrypt(tempKey, ibeCiphertext, secretKey->secretKey[affectedIndexes[i]]);
                  if (!status) {
                      break;
                  }
            }
        }

        ep_curve_get_ord(group1Order);
        int exponentLength = bn_size_bin(group1Order);
        int totalRandLength = systemParams.keyLength + exponentLength;
        uint8_t randDigest[totalRandLength];
        SHAKE256(randDigest, totalRandLength, tempKey, systemParams.keyLength);
        bn_read_bin(r, randDigest, exponentLength);

        genCiphertextPair = bloomfilter_enc_init_ciphertext_pair(systemParams);
        status = _bloomfilter_enc_encrypt(genCiphertextPair, systemParams, r, tempKey);

        if (!status && bloomfilter_enc_ciphertext_cmp(genCiphertextPair->ciphertext, ciphertext) == 0) {
            memcpy(key, tempKey, systemParams.keyLength);
            logger_log(LOGGER_INFO, "Secret key successfully decrypted.");
        }

    } CATCH_ANY {
        logger_log(LOGGER_ERROR, "Error occurred in Bloom Filter Encryption decrypt function.");
        status = BFE_ERR_GENERAL;
    } FINALLY {
        bn_free(r);
        bn_free(group1Order);
        bf_ibe_free_ciphertext(ibeCiphertext);
        bloomfilter_enc_free_ciphertext_pair(genCiphertextPair);
    }

    return status;
}

void bloomfilter_enc_free_secret_key(bloomfilter_enc_secret_key_t *secretKey) {
    for (int i = 0; i < secretKey->secretKeyLen; i++) {
        ep2_free(secretKey->secretKey[i]);
    }
    bloomfilter_clean(&secretKey->filter);
    free(secretKey);
}

void bloomfilter_enc_free_system_params(bloomfilter_enc_system_params_t *systemParams) {
    ep_free(systemParams->publicKey);
}

bloomfilter_enc_setup_pair_t *bloomfilter_enc_init_setup_pair(int keyLength, int filterElementNumber, double falsePositiveProbability) {
    bloomfilter_enc_setup_pair_t *returnPair = malloc(sizeof(bloomfilter_enc_setup_pair_t));
    returnPair->systemParams.keyLength = keyLength;
    bloomfilter_t filter = bloomfilter_init(filterElementNumber, falsePositiveProbability);
    int bloomSize = bloomfilter_get_size(filter);

    returnPair->secretKey = malloc(offsetof(bloomfilter_enc_secret_key_t, secretKey) + bloomSize * sizeof(returnPair->secretKey->secretKey[0]));
    returnPair->secretKey->secretKeyLen = bloomSize;
    returnPair->systemParams.filterSize = bloomSize;
    returnPair->systemParams.filterHashCount = filter.hashCount;
    returnPair->secretKey->filter = filter;
    return returnPair;
}

void bloomfilter_enc_free_setup_pair(bloomfilter_enc_setup_pair_t *setupPair) {
//    bloomfilter_enc_free_secret_key(setupPair->secretKey);
//    bloomfilter_enc_free_system_params(&setupPair->systemParams);
    free(setupPair);
}

void bloomfilter_enc_free_ciphertext(bloomfilter_enc_ciphertext_t *ciphertext) {
    ep_free(ciphertext->u);
    free(ciphertext);
}

bloomfilter_enc_ciphertext_pair_t *bloomfilter_enc_init_ciphertext_pair(bloomfilter_enc_system_params_t systemParams) {
    bloomfilter_enc_ciphertext_t *ciphertext = malloc(offsetof(bloomfilter_enc_ciphertext_t, v) + systemParams.filterHashCount * systemParams.keyLength * sizeof(ciphertext->v[0]));
    bloomfilter_enc_ciphertext_pair_t *returnPair = malloc(offsetof(bloomfilter_enc_ciphertext_pair_t, K) + systemParams.keyLength * sizeof(returnPair->K[0]));
    ciphertext->vLen = systemParams.filterHashCount * systemParams.keyLength;
    returnPair->KLen = systemParams.keyLength;
    returnPair->ciphertext = ciphertext;
    return returnPair;
}

void bloomfilter_enc_free_ciphertext_pair(bloomfilter_enc_ciphertext_pair_t *ciphertextPair) {
    bloomfilter_enc_free_ciphertext(ciphertextPair->ciphertext);
    free(ciphertextPair);
}

int bloomfilter_enc_ciphertext_size_bin(bloomfilter_enc_ciphertext_t *ciphertext) {
    return 2 * sizeof(int) + ep_size_bin(ciphertext->u, 0) + ciphertext->vLen;
}

void bloomfilter_enc_ciphertext_write_bin(uint8_t *bin, bloomfilter_enc_ciphertext_t *ciphertext) {
    int uLen = ep_size_bin(ciphertext->u, 0);
    int totalLen = bloomfilter_enc_ciphertext_size_bin(ciphertext);
    memcpy(bin, &uLen, sizeof(int));
    memcpy(&bin[sizeof(int)], &totalLen, sizeof(int));
    ep_write_bin(&bin[2 * sizeof(int)], ep_size_bin(ciphertext->u, 0), ciphertext->u, 0);
    memcpy(&bin[totalLen - ciphertext->vLen], ciphertext->v, ciphertext->vLen);
}
// TODO this should be refactored to return error code
bloomfilter_enc_ciphertext_t *bloomfilter_enc_ciphertext_read_bin(const uint8_t *bin) {
    int uLen, totalLen, vLen;
    memcpy(&uLen, bin, sizeof(int));
    memcpy(&totalLen, &bin[sizeof(int)], sizeof(int));
    vLen = totalLen - uLen - 2 * sizeof(int);
    bloomfilter_enc_ciphertext_t *ciphertext = malloc(offsetof(bloomfilter_enc_ciphertext_t, v) + vLen * sizeof(ciphertext->v[0]));

    ep_null(ciphertext->u);
    TRY {
        ep_new(ciphertext->u);
        ep_read_bin(ciphertext->u, &bin[2 * sizeof(int)], uLen);
    } CATCH_ANY {
        logger_log(LOGGER_ERROR, "Error occurred in bloomfilter_enc_ciphertext_read_bin function.");
        THROW(ERR_CAUGHT);
    } FINALLY {
    }
    ciphertext->vLen = vLen;
    memcpy(ciphertext->v, &bin[totalLen - vLen], vLen);
    return ciphertext;
}

void bloomfilter_enc_write_setup_pair_to_file(bloomfilter_enc_setup_pair_t *setupPair) {
    int publicKeyBinLen = ep_size_bin(setupPair->systemParams.publicKey, 0);
    uint8_t publicKeyBin[publicKeyBinLen];
    ep_write_bin(publicKeyBin, publicKeyBinLen, setupPair->systemParams.publicKey, 0);

    int secretKeybinLen = ep2_size_bin(setupPair->secretKey->secretKey[0], 0);
    uint8_t secretKeyUnitBin[secretKeybinLen];

    FILE *fp_params, *fp_public_key, *fp_secret_key;
    fp_params = fopen("params.txt", "w+");
    fp_public_key = fopen("public_key.txt", "w+");
    fp_secret_key = fopen("secret_key.txt", "w+");
    fprintf(fp_params, "%d %d %d", setupPair->systemParams.filterHashCount, setupPair->systemParams.filterSize,
            setupPair->systemParams.keyLength);
    fprintf(fp_public_key, "%d ", publicKeyBinLen);
    for(int i = 0; i < secretKeybinLen; i++) {
        fprintf(fp_public_key, "%c", publicKeyBin[i]);
    }
    fprintf(fp_secret_key, "%d %d %d\n", setupPair->secretKey->filter.bitSet.size, setupPair->secretKey->filter.hashCount,
            ep2_size_bin(setupPair->secretKey->secretKey[0], 0));
    for (int i = 0; i < ceil(setupPair->secretKey->filter.bitSet.size * 1.0 / BITSET_WORD_BITS); i++) {
        fprintf(fp_secret_key, "%u ", setupPair->secretKey->filter.bitSet.bitArray[i]);
    }
    fprintf(fp_secret_key, "\n");
    for (int i = 0; i < setupPair->secretKey->filter.bitSet.size; i++) {
        if (bitset_get(setupPair->secretKey->filter.bitSet, i) == 0) {
            ep2_write_bin(secretKeyUnitBin, secretKeybinLen, setupPair->secretKey->secretKey[i], 0);
            for(int j = 0; j < secretKeybinLen; j++) {
                fprintf(fp_secret_key, "%c", secretKeyUnitBin[j]);
            }
        }
    }
    fclose(fp_params);
    fclose(fp_public_key);
    fclose(fp_secret_key);
}

bloomfilter_enc_system_params_t bloomfilter_enc_read_system_params_from_file() {
    bloomfilter_enc_system_params_t systemParams;
    int publicKeyBinLen;

    FILE *fp_params, *fp_public_key;
    fp_params = fopen("params.txt", "r");
    fp_public_key = fopen("public_key.txt", "r");
    if (fscanf(fp_params, "%d %d %d", &systemParams.filterHashCount, &systemParams.filterSize, &systemParams.keyLength) != 3) {
        logger_log(LOGGER_ERROR, "Error occurred while reading system params from a file.");
    }

    if (fscanf(fp_public_key, "%d ", &publicKeyBinLen) != 1) {
        logger_log(LOGGER_ERROR, "Error occurred while reading public key length from a file.");
    }
    uint8_t publicKeyBin[publicKeyBinLen];
    if (fread(publicKeyBin, sizeof(uint8_t), publicKeyBinLen, fp_public_key) != publicKeyBinLen) {
        logger_log(LOGGER_ERROR, "Error occurred while reading public key from a file.");
    }

    ep_null(systemParams.publicKey);
    TRY {
        ep_new(systemParams.publicKey);
        ep_read_bin(systemParams.publicKey, publicKeyBin, publicKeyBinLen);
    } CATCH_ANY {
        logger_log(LOGGER_ERROR, "Error occurred while setting public key.");
        THROW(ERR_CAUGHT);
    } FINALLY {

    }

    fclose(fp_params);
    fclose(fp_public_key);

    return systemParams;
}

bloomfilter_enc_secret_key_t *bloomfilter_enc_read_secret_key_from_file() {
    int filterSize, filterHashCount, secretKeyUnitBinLen;

    FILE *fp_secret_key;
    fp_secret_key = fopen("secret_key.txt", "r");

    if (fscanf(fp_secret_key, "%d %d %d\n", &filterSize, &filterHashCount, &secretKeyUnitBinLen) != 3) {
        logger_log(LOGGER_ERROR, "Error occurred while reading secret key attributes from a file.");
    }
    bloomfilter_enc_secret_key_t *secretKey = malloc(offsetof(bloomfilter_enc_secret_key_t, secretKey) + filterSize * sizeof(secretKey->secretKey[0]));
    bloomfilter_t filter = bloomfilter_init_fixed(filterSize, filterHashCount);
    secretKey->secretKeyLen = filterSize;

    uint8_t secretKeyUnitBin[secretKeyUnitBinLen];

    for (int i = 0; i < ceil(filterSize * 1.0 / BITSET_WORD_BITS); i++) {
        if (fscanf(fp_secret_key, "%u ", &filter.bitSet.bitArray[i]) != 1) {
            logger_log(LOGGER_ERROR, "Error occurred while reading bloom filter bits from a file.");
        }
    }

    TRY {
        for (int i = 0; i < filterSize; i++) {
            if (bitset_get(filter.bitSet, i) == 0) {
                if (fread(secretKeyUnitBin, sizeof(uint8_t), secretKeyUnitBinLen, fp_secret_key) != secretKeyUnitBinLen) {
                    logger_log(LOGGER_ERROR, "Error occurred while reading secret key from a file.");
                }
                ep2_null(secretKey->secretKey[i]);
                ep2_new(secretKey->secretKey[i]);
                ep2_read_bin(secretKey->secretKey[i], secretKeyUnitBin, secretKeyUnitBinLen);
            }
        }
    } CATCH_ANY {
        logger_log(LOGGER_ERROR, "Error occurred in Bloom Filter Encryption setup function.");
        THROW(ERR_CAUGHT);
    } FINALLY {

    }

    fclose(fp_secret_key);

    secretKey->filter = filter;
    return secretKey;
}