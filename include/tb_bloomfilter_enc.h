#ifndef MASTER_PROJECT_TB_BLOOMFILTER_ENC_H
#define MASTER_PROJECT_TB_BLOOMFILTER_ENC_H

#include "bloomfilter.h"
#include "hibe.h"

typedef struct _tb_bloomfilter_enc_system_params_t {
  int filterHashCount;
  int filterSize;
  int timeSlotsExponent;
  int keyLength;
  hibe_system_params_t* hibeSystemParams;
} tb_bloomfilter_enc_system_params_t;

typedef struct _tb_bloomfilter_enc_secret_key_t {
  int intervalIndex;
  bloomfilter_t filter;
  int keyLen;
  hibe_private_key_t* key[];
} tb_bloomfilter_enc_secret_key_t;

typedef struct _tb_bloomfilter_enc_setup_pair_t {
  tb_bloomfilter_enc_system_params_t systemParams;
  tb_bloomfilter_enc_secret_key_t* secretKey;
} tb_bloomfilter_enc_setup_pair_t;

typedef struct _tb_bloomfilter_enc_encapsulated_keys_t {
  int keysLen;
  hibe_ciphertext_t* keys[];
} tb_bloomfilter_enc_encapsulated_keys_t;

typedef struct _tb_bloomfilter_enc_ciphertext_t {
  tb_bloomfilter_enc_encapsulated_keys_t* encapsulatedKeys;
  int cLen;
  uint8_t c[];
} tb_bloomfilter_enc_ciphertext_t;

/**
 * Punctures a secret key for the given ciphertext. After this action the secret key will not be
 * usable for decrypting the same ciphertext again in the same time interval. This function runs in
 * place which means a passed secret key will be modified.
 *
 * @param secretKey[out]            - secret key to be punctured.
 * @param systemParams[in]          - system parameters.
 * @param ciphertext[in]            - ciphertext for which the secret key is being punctured.
 */
void tb_bloomfilter_enc_puncture_key(tb_bloomfilter_enc_secret_key_t* secretKey,
                                     tb_bloomfilter_enc_system_params_t systemParams,
                                     tb_bloomfilter_enc_ciphertext_t* ciphertext);

/**
 * Punctures a time interval by modifying a secret key so it becomes useless for encrypting the
 * ciphertexts of previous intervals, resetting the underlying Bloom fiter and generating new secret
 * key units for decrypting future encapsulated keys. This function runs in place which means a
 * passed secret key will be modified.
 *
 * @param secretKey[out]            - secret key to be punctured.
 * @param systemParams[in]          - system parameters.
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
int tb_bloomfilter_enc_puncture_int(tb_bloomfilter_enc_secret_key_t* secretKey,
                                    tb_bloomfilter_enc_system_params_t systemParams);

/**
 * Sets up the Time-Based Bloom Filter Encryption (tb-bfe) scheme.
 *
 * @param setupPair[out]            - the tb-bfe setup pair containing system parameters and secret
 * key.
 * @param keyLength[in]             - size of the random generated keys when calling the
 * tb_bloomfilter_enc_encrypt() function, in bytes.
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
int tb_bloomfilter_enc_setup(tb_bloomfilter_enc_setup_pair_t* setupPair, int keyLength);

/**
 * Generates a random key K and encrypts it.
 *
 * @param ciphertext[out]           - ciphertext in form of (c, Kenc), c being the random identifier
 * of the ciphertext and Kenc being the collection of encapsulated keys.
 * @param systemParams[in]          - system parameters.
 * @param intervalId[in]            - id of the time interval for which the key is being encrypted
 * (e.g. if there are 2^3 time intervals in total, their ids in binary form are of length 3, from
 * "000" to "111").
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
int tb_bloomfilter_enc_encrypt(tb_bloomfilter_enc_ciphertext_t* ciphertext,
                               tb_bloomfilter_enc_system_params_t systemParams,
                               const char* intervalId);

/**
 * Decrypts a given ciphertext. The secret key should not be already punctured with the same
 * ciphertext in the same time interval.
 *
 * @param key[out]                  - the returned decrypted key.
 * @param systemParams[in]          - system parameters.
 * @param secretKey[in]             - secret key to be used for decrypting.
 * @param ciphertext[in]            - ciphertext.
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
int tb_bloomfilter_enc_decrypt(uint8_t* key, tb_bloomfilter_enc_system_params_t systemParams,
                               tb_bloomfilter_enc_secret_key_t* secretKey,
                               tb_bloomfilter_enc_ciphertext_t* ciphertext);

/**
 * Allocates the memory for the tb-bfe ciphertext.
 *
 * @param systemParams              - system parameters.
 * @return The ciphertext struct.
 */
tb_bloomfilter_enc_ciphertext_t*
tb_bloomfilter_enc_init_ciphertext(tb_bloomfilter_enc_system_params_t systemParams);

/**
 * Frees the memory allocated by the tb-bfe ciphertext. This method has to be called after the
 * ciphertext is no longer needed to avoid memory leaks.
 *
 * @param ciphertext                - the corresponding ciphertext.
 */
void tb_bloomfilter_enc_free_ciphertext(tb_bloomfilter_enc_ciphertext_t* ciphertext);

/**
 * Frees the memory allocated by the tb-bfe system parameters. This method has to be called after
 * the system parameters are no longer needed to avoid memory leaks.
 *
 * @param systemParams              - the corresponding system parameters.
 */
void tb_bloomfilter_enc_free_system_params(tb_bloomfilter_enc_system_params_t* systemParams);

/**
 * Frees the memory allocated by the tb-bfe secret key. This method has to be called after the
 * secret key is no longer needed to avoid memory leaks.
 *
 * @param secretkey                 - the corresponding secret key.
 */
void tb_bloomfilter_enc_free_secret_key(tb_bloomfilter_enc_secret_key_t* secretkey);

/**
 * Allocates the memory for the tb-bfe setup pair.
 *
 * @param filterElementNumber       - expected number of keys per single interval to be encrypted
 * before the secret key of an interval is fully punctured.
 * @param falsePositiveProbability  - target false positive probability of the scheme. Smaller
 * probability means larger secret key.
 * @param timeSlotsExponent         - number defining the total amount of time slots, in power of
 * two format
 * @return The setup pair struct.
 */
tb_bloomfilter_enc_setup_pair_t* tb_bloomfilter_enc_init_setup_pair(int filterElementNumber,
                                                                    double falsePositiveProbability,
                                                                    int timeSlotsExponent);

/**
 * Frees the memory allocated by the tb-bfe setup pair. This method has to be called after the setup
 * pair is no longer needed to avoid memory leaks.
 *
 * @param setupPair                 - the corresponding setup pair.
 */
void tb_bloomfilter_enc_free_setup_pair(tb_bloomfilter_enc_setup_pair_t* setupPair);

#endif // MASTER_PROJECT_TB_BLOOMFILTER_ENC_H
