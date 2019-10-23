#ifndef MASTER_PROJECT_BLOOMFILTER_ENC_H
#define MASTER_PROJECT_BLOOMFILTER_ENC_H

#include <relic/relic_epx.h>
#include "bloomfilter.h"
#include "bfibe.h"

typedef struct _bloomfilter_enc_system_params_t {
    unsigned int filterHashCount;
    unsigned int filterSize;
    unsigned int keyLength;
    double falsePositiveProbability;
    bf_ibe_public_key_t publicKey;
} bloomfilter_enc_system_params_t;
typedef bloomfilter_enc_system_params_t bloomfilter_enc_public_key_t;

typedef struct _bloomfilter_enc_secret_key_t {
    bloomfilter_t filter;
    unsigned int secretKeyLen;
    bf_ibe_extracted_key_t* secretKey;
} bloomfilter_enc_secret_key_t;

typedef struct _bloomfilter_enc_setup_pair_t {
    bloomfilter_enc_system_params_t systemParams;
    bloomfilter_enc_secret_key_t *secretKey;
} bloomfilter_enc_setup_pair_t;

typedef struct _bloomfilter_enc_ciphertext_t {
    ep_t u;
    unsigned int vLen;
    uint8_t v[];
} bloomfilter_enc_ciphertext_t;

typedef struct _bloomfilter_enc_ciphertext_pair_t {
    bloomfilter_enc_ciphertext_t *ciphertext;
    unsigned int KLen;
    uint8_t K[];
} bloomfilter_enc_ciphertext_pair_t;

int bloomfilter_enc_init_secret_key(bloomfilter_enc_secret_key_t* secret_key);
void bloomfilter_enc_clear_secret_key(bloomfilter_enc_secret_key_t* secret_key);

int bloomfilter_enc_init_public_key(bloomfilter_enc_public_key_t* public_key);
void bloomfilter_enc_clear_public_key(bloomfilter_enc_public_key_t* public_key);

/**
 * Sets up the Bloom Filter Encryption (bfe) scheme.
 *
 * @param setupPair[out]                - the bfe setup pair containing system parameters (with public key) and secret key.
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
int bloomfilter_enc_setup(bloomfilter_enc_system_params_t* systemParams,
                          bloomfilter_enc_secret_key_t* secret_key, unsigned int keyLength,
                          unsigned int filterElementNumber, double falsePositiveProbability);

/**
 * Encrypts the key passed as a parameter.
 *
 * @param ciphertextPair[out]           - pair in form of (C, K), C being the ciphertext and K being the given key.
 * @param systemParams[in]              - system parameters.
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
int bloomfilter_enc_encrypt_key(bloomfilter_enc_ciphertext_pair_t *ciphertextPair, bloomfilter_enc_system_params_t* systemParams, uint8_t *K);

/**
 * Generates a random key K and encrypts it.
 *
 * @param ciphertextPair[out]           - pair in form of (C, K), C being the ciphertext and K being the random generated key.
 * @param systemParams[in]              - system parameters.
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
int bloomfilter_enc_encrypt(bloomfilter_enc_ciphertext_pair_t *ciphertextPair, bloomfilter_enc_system_params_t* systemParams);

/**
 * Punctures a secret key for the given ciphertext. After this action the secret key will not be usable for decrypting
 * the same ciphertext again. This function runs in place which means a passed secret key will be modified.
 *
 * @param secretKey[out]            - secret key to be punctured.
 * @param ciphertext[in]            - ciphertext for which the secret key is being punctured.
 */
void bloomfilter_enc_puncture(bloomfilter_enc_secret_key_t *secretKey, bloomfilter_enc_ciphertext_t *ciphertext);

/**
 * Compares two bfe ciphertexts.
 *
 * @param ciphertext1               - First ciphertext.
 * @param ciphertext2               - Second ciphertext.
 * @return 0 if equal, 1 if not equal.
 */
int bloomfilter_enc_ciphertext_cmp(bloomfilter_enc_ciphertext_t *ciphertext1, bloomfilter_enc_ciphertext_t *ciphertext2);

/**
 * Decrypts a given ciphertext. The secret key should not be already punctured with the same ciphertext.
 *
 * @param key[out]                  - the returned decrypted key.
 * @param systemParams[in]          - system parameters.
 * @param secretKey[in]             - secret key to be used for decrypting.
 * @param ciphertext[in]            - ciphertext.
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
int bloomfilter_enc_decrypt(uint8_t *key, bloomfilter_enc_system_params_t* systemParams, bloomfilter_enc_secret_key_t *secretKey, bloomfilter_enc_ciphertext_t *ciphertext);

/**
 * Frees the memory allocated by the bfe secret key. This method has to be called after the secret key is no longer
 * needed to avoid memory leaks.
 *
 * @param secretKey                 - the corresponding secret key.
 */
void bloomfilter_enc_free_secret_key(bloomfilter_enc_secret_key_t *secretKey);

/**
 * Frees the memory allocated by the bfe system parameters. This method has to be called after the system parameters are
 * no longer needed to avoid memory leaks.
 *
 * @param systemParams              - the corresponding system parameters.
 */
void bloomfilter_enc_free_system_params(bloomfilter_enc_system_params_t *systemParams);

/**
 * Allocates the memory for the bfe setup pair.
 *
 * @param keyLength[in]                 - size of the random generated keys when calling the bloomfilter_enc_encrypt() function, in bytes.
 * @param filterElementNumber[in]       - expected number of keys to be encrypted before the secret key is fully punctured.
 * @param falsePositiveProbability[in]  - target false positive probability of the scheme. Smaller probability means larger secret key.
 * @return The setup pair struct.
 */
bloomfilter_enc_setup_pair_t *bloomfilter_enc_init_setup_pair(unsigned int keyLength, unsigned int filterElementNumber, double falsePositiveProbability);

/**
 * Frees the memory allocated by the bfe setup pair. This method has to be called after the setup pair is no longer
 * needed to avoid memory leaks.
 *
 * @param setupPair                 - the corresponding setup pair.
 */
void bloomfilter_enc_free_setup_pair(bloomfilter_enc_setup_pair_t *setupPair);

/**
 * Frees the memory allocated by the bfe ciphertext. This method has to be called after the ciphertext is no longer
 * needed to avoid memory leaks.
 *
 * @param ciphertext                - the corresponding ciphertext.
 */
void bloomfilter_enc_free_ciphertext(bloomfilter_enc_ciphertext_t *ciphertext);

/**
 * Allocates the memory allocated for the bfe ciphertext pair.
 *
 * @param systemParams              - system parameters.
 * @return The ciphertext pair struct.
 */
bloomfilter_enc_ciphertext_pair_t *bloomfilter_enc_init_ciphertext_pair(bloomfilter_enc_system_params_t* systemParams);

/**
 * Frees the memory allocated by the bfe ciphertext pair. This method has to be called after the ciphertext pair is no
 * longer needed to avoid memory leaks.
 *
 * @param ciphertextPair            - the corresponding ciphertext pair.
 */
void bloomfilter_enc_free_ciphertext_pair(bloomfilter_enc_ciphertext_pair_t *ciphertextPair);

/**
 * Calculates number of bytes needed to store a given ciphertext.
 *
 * @param ciphertext                - the ciphertext.
 * @return Number of bytes needed to store the ciphertext.
 */
int bloomfilter_enc_ciphertext_size_bin(bloomfilter_enc_ciphertext_t *ciphertext);

/**
 * Writes a given ciphertext to a byte array.
 *
 * @param bin[out]                  - the ciphertext byte array.
 * @param ciphertext[in]            - the ciphertext.
 */
void bloomfilter_enc_ciphertext_write_bin(uint8_t *bin, bloomfilter_enc_ciphertext_t *ciphertext);

/**
 * Reads a given ciphertext stored as a byte array.
 *
 * @param bin                       - the ciphertext byte array.
 * @return Ciphertext.
 */
bloomfilter_enc_ciphertext_t *bloomfilter_enc_ciphertext_read_bin(const uint8_t *bin);

/**
 * Writes a given setup pair to files params.txt, public_key.txt, and secret_key.txt.
 *
 * @param setupPair                 - the setup pair.
 */
void bloomfilter_enc_write_setup_pair_to_file(bloomfilter_enc_setup_pair_t *setupPair);

/**
 * Reads system parameters from params.txt and public_key.txt files.
 *
 * @return System parameters.
 */
bloomfilter_enc_system_params_t bloomfilter_enc_read_system_params_from_file();

/**
 * Reads secret key from secret_key.txt file.
 *
 * @return Secret key.
 */
bloomfilter_enc_secret_key_t *bloomfilter_enc_read_secret_key_from_file();

#endif //MASTER_PROJECT_BLOOMFILTER_ENC_H
