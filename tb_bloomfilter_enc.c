#include <math.h>
#include <stddef.h>

#include "FIPS202-opt64/SimpleFIPS202.h"
#include "include/tb_bloomfilter_enc.h"
#include "include/bloomfilter.h"
#include "include/hibe.h"
#include "include/err_codes.h"
#include "logger.h"
#include "util.h"

int _calculate_target_bloom_filter_tree_depth(int filterSize);
void _get_child_node_id(char *childNodeId, const char *nodeId, int childIndex);
void _free_secret_key_unit(hibe_private_key_t **secretKeyUnit);
int _generate_time_keys(const char *currentNodeId, const char *targetNodeId, hibe_private_key_t *currentNodeKey,
                         tb_bloomfilter_enc_secret_key_t *secretKey, tb_bloomfilter_enc_system_params_t systemParams);
int _generate_bf_keys(const char *nodeId, hibe_private_key_t *nodeKey, tb_bloomfilter_enc_secret_key_t *secretKey,
                       tb_bloomfilter_enc_system_params_t systemParams);

int tb_bloomfilter_enc_setup(tb_bloomfilter_enc_setup_pair_t *setupPair, int keyLength) {
    int status = BFE_SUCCESS;
    hibe_setup_pair_t *hibeSetupPair;

    TRY {

        hibeSetupPair = hibe_init_setup_pair(setupPair->systemParams.timeSlotsExponent + _calculate_target_bloom_filter_tree_depth(bloomfilter_get_size(setupPair->secretKey->filter)));
        status = hibe_setup(hibeSetupPair);
        if (!status) {
            setupPair->systemParams.hibeSystemParams = hibeSetupPair->systemParams;
            setupPair->systemParams.keyLength = keyLength;

            setupPair->secretKey->key[0] = hibe_init_private_key(hibeSetupPair->systemParams, "0");
            hibe_extract(setupPair->secretKey->key[0], hibeSetupPair->systemParams, hibeSetupPair->masterKey, "0");
            setupPair->secretKey->key[setupPair->systemParams.timeSlotsExponent] = hibe_init_private_key(hibeSetupPair->systemParams, "1");
            hibe_extract(setupPair->secretKey->key[setupPair->systemParams.timeSlotsExponent], hibeSetupPair->systemParams, hibeSetupPair->masterKey, "1");

            setupPair->secretKey->intervalIndex = -1; // the epsilon key

            status = tb_bloomfilter_enc_puncture_int(setupPair->secretKey, setupPair->systemParams);
        }
    } CATCH_ANY {
        logger_log(LOGGER_ERROR, "Error occurred in Time-Based Bloom Filter Encryption setup function.");
        status = BFE_ERR_GENERAL;
    } FINALLY {
        ep_free(hibeSetupPair.masterKey);
    }

    return status;
}

int tb_bloomfilter_enc_encrypt(tb_bloomfilter_enc_ciphertext_t *ciphertext, tb_bloomfilter_enc_system_params_t systemParams, const char *intervalId) {
    int status = BFE_SUCCESS;
    tb_bloomfilter_enc_encapsulated_keys_t *encapsulatedKeys = malloc(offsetof(tb_bloomfilter_enc_encapsulated_keys_t, keys) + systemParams.filterHashCount * sizeof(encapsulatedKeys->keys[0]));
    encapsulatedKeys->keysLen = systemParams.filterHashCount;

    int bfTreeDepth = _calculate_target_bloom_filter_tree_depth(systemParams.filterSize);
    uint8_t K[systemParams.keyLength];

    bn_t order, cRand, kRand;
    bn_null(order);
    bn_null(cRand);
    bn_null(kRand);

    TRY {
        bn_new(order);
        bn_new(cRand);
        bn_new(kRand);

        ep_curve_get_ord(order);
        bn_rand_mod(cRand, order);
        int cBinSize = bn_size_bin(cRand);
        uint8_t cBin[cBinSize];
        bn_write_bin(cBin, cBinSize, cRand);
        SHAKE256(ciphertext->c, systemParams.keyLength, cBin, cBinSize);

        bn_rand_mod(kRand, order);
        int kBinSize = bn_size_bin(kRand);
        uint8_t kBin[kBinSize];
        bn_write_bin(kBin, kBinSize, kRand);
        SHAKE256(K, systemParams.keyLength, kBin, kBinSize);

        printf("\nOriginal key:\n");
        for (int i = 0; i < systemParams.keyLength; i++) {
            printf("%c", K[i]);
        }


        int bitPositions[systemParams.filterHashCount];
        bloomfilter_get_bit_positions(bitPositions, ciphertext->c, systemParams.keyLength, systemParams.filterHashCount, systemParams.filterSize);

        char keyIdentity[strlen(intervalId) + bfTreeDepth + 1];
        keyIdentity[strlen(intervalId) + bfTreeDepth] = '\0';
        for (int i = 0; i < systemParams.filterHashCount; i++) {
            memset(keyIdentity, '0', strlen(intervalId) + bfTreeDepth);
            strncpy(keyIdentity, intervalId, strlen(intervalId)); // instead of strlen we can also use time tree depth from system params
            if (bitPositions[i] > 0) { // because log2 is -infinity for 0
                itoa(bitPositions[i], &keyIdentity[strlen(intervalId) + bfTreeDepth - ((int) floor(log2(bitPositions[i])) + 1)], 2); // padding bit position binary representation and adding it to full key identity
            }
            encapsulatedKeys->keys[i] = hibe_init_ciphertext(systemParams.keyLength);
            status = hibe_encrypt(encapsulatedKeys->keys[i], systemParams.hibeSystemParams, keyIdentity, K);
        }

        ciphertext->encapsulatedKeys = encapsulatedKeys;

    } CATCH_ANY {
        logger_log(LOGGER_ERROR, "Error occurred in Time-Based Bloom Filter Encryption encrypt function.");
        status = BFE_ERR_GENERAL;
    } FINALLY {
        bn_free(order);
        bn_free(cRand);
        bn_free(kRand);
    }

    return status;
}

int tb_bloomfilter_enc_decrypt(uint8_t *key, tb_bloomfilter_enc_system_params_t systemParams, tb_bloomfilter_enc_secret_key_t *secretKey,
                        tb_bloomfilter_enc_ciphertext_t *ciphertext) {
    int status = BFE_SUCCESS;
    if (bloomfilter_maybe_contains(secretKey->filter, ciphertext->c, ciphertext->cLen)) {
        logger_log(LOGGER_ERROR, "Secret key already punctured with the given ciphertext!");
        return BFE_ERR_KEY_PUNCTURED;
    };

    int bitPositions[systemParams.filterHashCount];
    bloomfilter_get_bit_positions(bitPositions, ciphertext->c, ciphertext->cLen, systemParams.filterHashCount, systemParams.filterSize);

    for (int i = 0; i < systemParams.filterHashCount; i++) {
        if (secretKey->key[bitPositions[i] + systemParams.timeSlotsExponent + 1] != NULL) {
            status = hibe_decrypt(key, ciphertext->encapsulatedKeys->keys[i], secretKey->key[bitPositions[i] + systemParams.timeSlotsExponent + 1]);
            if (!status) {
                logger_log(LOGGER_INFO, "Secret key successfully decrypted.");
                break;
            }
        }
    }

    return status;
}

void tb_bloomfilter_enc_puncture_key(tb_bloomfilter_enc_secret_key_t *secretKey, tb_bloomfilter_enc_system_params_t systemParams,
                                     tb_bloomfilter_enc_ciphertext_t *ciphertext) {
    int affectedIndexes[secretKey->filter.hashCount];
    bloomfilter_add(&secretKey->filter, ciphertext->c, ciphertext->cLen);
    bloomfilter_get_bit_positions(affectedIndexes, ciphertext->c, ciphertext->cLen, secretKey->filter.hashCount, bloomfilter_get_size(secretKey->filter));
    for (int i = 0; i < secretKey->filter.hashCount; i++) {
        _free_secret_key_unit(&secretKey->key[affectedIndexes[i]  + systemParams.timeSlotsExponent + 1]);
    }
    logger_log(LOGGER_INFO, "The key has been punctured");
}

int tb_bloomfilter_enc_puncture_int(tb_bloomfilter_enc_secret_key_t *secretKey,
                                     tb_bloomfilter_enc_system_params_t systemParams) {
    int status = BFE_SUCCESS;
    int newIntervalIndex = secretKey->intervalIndex + 1;
    if (newIntervalIndex >= pow(2, systemParams.timeSlotsExponent)) {
        logger_log(LOGGER_ERROR, "No more time intervals left. Puncturing not possible.");
        return BFE_ERR_NO_MORE_TIME_INTERVALS;
    }
    int timeTreeDepth = systemParams.timeSlotsExponent;

    char newIntervalBinaryIndex[systemParams.timeSlotsExponent + 1];
    memset(newIntervalBinaryIndex, '0', (size_t ) systemParams.timeSlotsExponent); // todo not cool
    newIntervalBinaryIndex[systemParams.timeSlotsExponent] = '\0';
    if (newIntervalIndex > 0) {
        itoa(newIntervalIndex, &newIntervalBinaryIndex[systemParams.timeSlotsExponent - ((int) floor(log2(newIntervalIndex)) + 1)], 2);
    }

    int timeKeyIndex;
    if (newIntervalBinaryIndex[strlen(newIntervalBinaryIndex) - 1] == '1') {
        timeKeyIndex = 1;
    } else {
        int i = strlen(newIntervalBinaryIndex) - 1;
        for (; newIntervalBinaryIndex[i] == '0' && i >= 0; --i);
        int closestTimeKeyIndex = 0;
        char closestTimeKeyId[i >= 0 ? i + 2 : 2];
        if (i >= 0) {
            closestTimeKeyId[i + 1] = '\0';
            strncpy(closestTimeKeyId, newIntervalBinaryIndex, i + 1);
            closestTimeKeyIndex = timeTreeDepth - i;
        } else {
            closestTimeKeyId[0] = '0';
            closestTimeKeyId[1] = '\0';
        }

        _generate_time_keys(closestTimeKeyId, newIntervalBinaryIndex, secretKey->key[closestTimeKeyIndex],
                            secretKey, systemParams);
        timeKeyIndex = 0;
    }

    bloomfilter_reset(&secretKey->filter);
    for (int i = timeTreeDepth + 1; i < secretKey->keyLen; i++) {
        // destroy all the remaining keys
        _free_secret_key_unit(&secretKey->key[i]);
    }
    // TODO ignoring here the error code
    _generate_bf_keys(newIntervalBinaryIndex, secretKey->key[timeKeyIndex], secretKey, systemParams);
    secretKey->intervalIndex = (int) strtol(newIntervalBinaryIndex, NULL, 2);
    _free_secret_key_unit(&secretKey->key[timeKeyIndex]);

    return status;
}

int _calculate_target_bloom_filter_tree_depth(int filterSize) {
    return (int) ceil(log2(filterSize));
}

int _generate_time_keys(const char *currentNodeId, const char *targetNodeId, hibe_private_key_t *currentNodeKey,
                         tb_bloomfilter_enc_secret_key_t *secretKey, tb_bloomfilter_enc_system_params_t systemParams) {
    int status = BFE_SUCCESS;
    if (strncmp(currentNodeId, targetNodeId, strlen(currentNodeId)) != 0) {
        size_t targetKeyIndex = systemParams.timeSlotsExponent + 1 - strlen(currentNodeId);
        secretKey->key[targetKeyIndex] = currentNodeKey;
        return BFE_SUCCESS;
    }

    if (strcmp(currentNodeId, targetNodeId) == 0) {
        secretKey->key[0] = currentNodeKey;
        return BFE_SUCCESS;
    }

    char leftNodeId[strlen(currentNodeId) + 2];
    char rightNodeId[strlen(currentNodeId) + 2];
    _get_child_node_id(leftNodeId, currentNodeId, 0);
    _get_child_node_id(rightNodeId, currentNodeId, 1);

    TRY {
        hibe_private_key_t *leftNodeKey = hibe_init_private_key(systemParams.hibeSystemParams, leftNodeId);
        hibe_derive(leftNodeKey, systemParams.hibeSystemParams, currentNodeKey, leftNodeId);
        hibe_private_key_t *rightNodeKey = hibe_init_private_key(systemParams.hibeSystemParams, rightNodeId);
        hibe_derive(rightNodeKey, systemParams.hibeSystemParams, currentNodeKey, rightNodeId);

        hibe_free_private_key(currentNodeKey);

                        _generate_time_keys(leftNodeId, targetNodeId, leftNodeKey, secretKey, systemParams);
                        _generate_time_keys(rightNodeId, targetNodeId, rightNodeKey, secretKey, systemParams);

    } CATCH_ANY {
        logger_log(LOGGER_ERROR, "Error occurred in Time-Based Bloom Filter Encryption time keys generation function.");
        status = BFE_ERR_GENERAL;
    } FINALLY {

    }

    return status;
}

int _generate_bf_keys(const char *nodeId, hibe_private_key_t *nodeKey, tb_bloomfilter_enc_secret_key_t *secretKey,
                       tb_bloomfilter_enc_system_params_t systemParams) {
    int status = BFE_SUCCESS;
    char lastBfIndexId[(int) ceil(log2(bloomfilter_get_size(secretKey->filter))) + 1];
    lastBfIndexId[(int) ceil(log2(bloomfilter_get_size(secretKey->filter)))] = '\0';
    char nodeIdPrefix[systemParams.timeSlotsExponent + 1];
    nodeIdPrefix[systemParams.timeSlotsExponent] = '\0';
    itoa(bloomfilter_get_size(secretKey->filter), lastBfIndexId, 2);

    strncpy(lastBfIndexId, lastBfIndexId, strlen(nodeId) - systemParams.timeSlotsExponent);
    strncpy(nodeIdPrefix, nodeId, systemParams.timeSlotsExponent);
    if (compareBinaryStrings(nodeIdPrefix, lastBfIndexId) > 0) {
        hibe_free_private_key(nodeKey);
        return BFE_SUCCESS;
    }

    int bfTreeDepth = _calculate_target_bloom_filter_tree_depth(bloomfilter_get_size(secretKey->filter));
    int fullTreeDepth = systemParams.timeSlotsExponent + bfTreeDepth;
    if (strlen(nodeId) == fullTreeDepth) {
        int secretKeyIndex = (int) strtol(&nodeId[systemParams.timeSlotsExponent], NULL, 2) + systemParams.timeSlotsExponent + 1; // adding offset since the first part of the key is reserved for time keys
        secretKey->key[secretKeyIndex] = nodeKey;
        return BFE_SUCCESS;
    }

    char leftNodeId[strlen(nodeId) + 2];
    char rightNodeId[strlen(nodeId) + 2];
    _get_child_node_id(leftNodeId, nodeId, 0);
    _get_child_node_id(rightNodeId, nodeId, 1);

    TRY {
        hibe_private_key_t *leftNodeKey = hibe_init_private_key(systemParams.hibeSystemParams, leftNodeId);
        hibe_derive(leftNodeKey, systemParams.hibeSystemParams, nodeKey, leftNodeId);
        hibe_private_key_t *rightNodeKey = hibe_init_private_key(systemParams.hibeSystemParams, rightNodeId);
        hibe_derive(rightNodeKey, systemParams.hibeSystemParams, nodeKey, rightNodeId);

                        _generate_bf_keys(leftNodeId, leftNodeKey, secretKey, systemParams);
                        _generate_bf_keys(rightNodeId, rightNodeKey, secretKey, systemParams);
    } CATCH_ANY {
        logger_log(LOGGER_ERROR, "Error occurred in Time-Based Bloom Filter Encryption BF keys generation function.");
        status = BFE_ERR_GENERAL;
    } FINALLY {
        hibe_free_private_key(nodeKey);
    }

    return status;
}

void _get_child_node_id(char *childNodeId, const char *nodeId, int childIndex) {
    strncpy(childNodeId, nodeId, strlen(nodeId));
    if (childIndex == 0) {
        childNodeId[strlen(nodeId)] = '0';
    } else {
        childNodeId[strlen(nodeId)] = '1';
    }
    childNodeId[strlen(nodeId) + 1] = '\0';
}

void _free_secret_key_unit(hibe_private_key_t **secretKeyUnit) {
    if (*secretKeyUnit == NULL) {
        return;
    }
    hibe_free_private_key(*secretKeyUnit);
    *secretKeyUnit = NULL;
}

tb_bloomfilter_enc_ciphertext_t *tb_bloomfilter_enc_init_ciphertext(tb_bloomfilter_enc_system_params_t systemParams) {
    tb_bloomfilter_enc_ciphertext_t *ciphertext = malloc(offsetof(tb_bloomfilter_enc_ciphertext_t, c) + systemParams.keyLength * sizeof(ciphertext->c[0]));
    ciphertext->cLen = systemParams.keyLength;
    return ciphertext;
}

void tb_bloomfilter_enc_free_ciphertext(tb_bloomfilter_enc_ciphertext_t *ciphertext) {
    for (int i = 0; i < ciphertext->encapsulatedKeys->keysLen; i++) {
        hibe_free_ciphertext(ciphertext->encapsulatedKeys->keys[i]);
    }
    free(ciphertext->encapsulatedKeys);
    free(ciphertext);
}

void tb_bloomfilter_enc_free_system_params(tb_bloomfilter_enc_system_params_t *systemParams) {
    hibe_free_system_params(systemParams->hibeSystemParams);
}

void tb_bloomfilter_enc_free_secret_key(tb_bloomfilter_enc_secret_key_t *secretkey) {
    for (int i = 0; i < secretkey->keyLen; i++) {
        _free_secret_key_unit(&secretkey->key[i]);
    }
    bloomfilter_clean(&secretkey->filter);
}

tb_bloomfilter_enc_setup_pair_t *tb_bloomfilter_enc_init_setup_pair(int filterElementNumber, double falsePositiveProbability, int timeSlotsExponent) {
    tb_bloomfilter_enc_setup_pair_t *returnPair = malloc(sizeof(tb_bloomfilter_enc_setup_pair_t));
    bloomfilter_t filter = bloomfilter_init(filterElementNumber, falsePositiveProbability);
    int bloomSize = bloomfilter_get_size(filter);
    int timeTreeDepth = timeSlotsExponent;
    int bfTreeDepth = _calculate_target_bloom_filter_tree_depth(bloomSize);

    returnPair->secretKey = malloc(offsetof(tb_bloomfilter_enc_secret_key_t, key) + (timeTreeDepth + 1 + (int) pow(2, bfTreeDepth)) * sizeof(returnPair->secretKey->key[0]));
    memset(returnPair->secretKey, 0, offsetof(tb_bloomfilter_enc_secret_key_t, key) + (timeTreeDepth + 1 + (int) pow(2, bfTreeDepth)) * sizeof(returnPair->secretKey->key[0]));
    returnPair->secretKey->keyLen = timeTreeDepth + 1 + (int) pow(2, bfTreeDepth); // todo this casting is not really perfect way of dealing with this
    returnPair->secretKey->filter = filter;
    returnPair->systemParams.filterSize = bloomSize;
    returnPair->systemParams.timeSlotsExponent = timeSlotsExponent;
    returnPair->systemParams.filterHashCount = filter.hashCount;
    return returnPair;
}

void tb_bloomfilter_enc_free_setup_pair(tb_bloomfilter_enc_setup_pair_t *setupPair) {
    tb_bloomfilter_enc_free_system_params(&setupPair->systemParams);
    tb_bloomfilter_enc_free_secret_key(setupPair->secretKey);
    free(setupPair);
}