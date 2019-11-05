#ifndef BFE_BLOOMFILTER_ENC_H
#define BFE_BLOOMFILTER_ENC_H

#include "bfibe.h"
#include "bloomfilter.h"
#include "macros.h"

#include <relic/relic_epx.h>

typedef struct {
  unsigned int filterHashCount;
  unsigned int filterSize;
  unsigned int keyLength;
  bf_ibe_public_key_t publicKey;
} bloomfilter_enc_public_key_t;

typedef struct {
  bloomfilter_t filter;
  unsigned int secretKeyLen;
  bf_ibe_extracted_key_t* secretKey;
} bloomfilter_enc_secret_key_t;

typedef struct {
  ep_t u;
  unsigned int vLen;
  uint8_t* v;
} bloomfilter_enc_ciphertext_t;

typedef struct {
  bloomfilter_enc_ciphertext_t ciphertext;
  unsigned int KLen;
  uint8_t* K;
} bloomfilter_enc_ciphertext_pair_t;

/**
 * Initialize secret key.
 *
 * @param secret_key[out] the secret key
 * @return BFE_SUCCESS or BFE_ERR_*
 */
BFE_VISIBLE int bloomfilter_enc_init_secret_key(bloomfilter_enc_secret_key_t* secret_key);
/**
 * Clear secret key.
 *
 * @param secret_key[out] the secret key
 */
BFE_VISIBLE void bloomfilter_enc_clear_secret_key(bloomfilter_enc_secret_key_t* secret_key);

/**
 * Initialize public key.
 *
 * @param public_key[out] the public key
 * @return BFE_SUCCESS or BFE_ERR_*
 */
BFE_VISIBLE int bloomfilter_enc_init_public_key(bloomfilter_enc_public_key_t* public_key);
/**
 * Clear public key.
 *
 * @param public_key[out] the public key
 */
BFE_VISIBLE void bloomfilter_enc_clear_public_key(bloomfilter_enc_public_key_t* public_key);

/**
 * Sets up the Bloom Filter Encryption (bfe) scheme and create public and secret keys.
 *
 * @param public_key[out] the public key
 * @param secret_key[out] the secret key
 * @param key_length[in] length of the encapsulated keys
 * @param filter_element_number[in] desired number of elements in the bloom filter
 * @param false_positive_probability[in] desired false positive probability of the bloom filter
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
BFE_VISIBLE int bloomfilter_enc_setup(bloomfilter_enc_public_key_t* public_key,
                                      bloomfilter_enc_secret_key_t* secret_key,
                                      unsigned int key_length, unsigned int filter_element_number,
                                      double false_positive_probability);

/**
 * Encrypts the key passed as a parameter.
 *
 * @param ciphertextPair[out] pair in form of (C, K), C being the ciphertext and K being the given
 * key
 * @param public_key[in] the public key
 * @param K[in] key to encapsulate
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
BFE_VISIBLE int bloomfilter_enc_encrypt_key(bloomfilter_enc_ciphertext_pair_t* ciphertextPair,
                                            bloomfilter_enc_public_key_t* public_key,
                                            const uint8_t* K);

/**
 * Generates a random key K and encapsulates it.
 *
 * @param ciphertext_pair[out]  pair in form of (C, K), C being the ciphertext and K being the
 * randomly generated key
 * @param public_key[in] the public key
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
BFE_VISIBLE int bloomfilter_enc_encrypt(bloomfilter_enc_ciphertext_pair_t* ciphertext_pair,
                                        bloomfilter_enc_public_key_t* public_key);

/**
 * Punctures a secret key for the given ciphertext. After this action the secret key will not be
 * usable for decrypting the same ciphertext again. This function runs in place which means a passed
 * secret key will be modified.
 *
 * @param secret_key[out] the secret key to be punctured
 * @param ciphertext[in] ciphertext for which the secret key is being punctured
 */
BFE_VISIBLE void bloomfilter_enc_puncture(bloomfilter_enc_secret_key_t* secret_key,
                                          bloomfilter_enc_ciphertext_t* ciphertext);

/**
 * Compares two BFE ciphertexts.
 *
 * @param ciphertext1[in] First ciphertext
 * @param ciphertext2[in] Second ciphertext
 * @return 0 if equal, 1 if not equal.
 */
BFE_VISIBLE int bloomfilter_enc_ciphertext_cmp(const bloomfilter_enc_ciphertext_t* ciphertext1,
                                               const bloomfilter_enc_ciphertext_t* ciphertext2);

/**
 * Decapsulates a given ciphertext. The secret key should not be already punctured with the same
 * ciphertext.
 *
 * @param key[out] the returned decrypted key
 * @param public_key[in] the public key
 * @param secret_Key[in] the secret key to be used for decrypting
 * @param ciphertext[in] the ciphertext
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
BFE_VISIBLE int bloomfilter_enc_decrypt(uint8_t* key, bloomfilter_enc_public_key_t* public_key,
                                        bloomfilter_enc_secret_key_t* secret_key,
                                        bloomfilter_enc_ciphertext_t* ciphertext);

/**
 * Init the ciphertext.
 *
 * @param ciphertext[out] the ciphertext
 * @param public_key[in] the pulic key
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
BFE_VISIBLE int bloomfilter_enc_init_ciphertext(bloomfilter_enc_ciphertext_t* ciphertext,
                                                const bloomfilter_enc_public_key_t* public_key);
/**
 * Clear the ciphertext.
 *
 * @param ciphertext[out] the ciphertext
 */
BFE_VISIBLE void bloomfilter_enc_clear_ciphertext(bloomfilter_enc_ciphertext_t* ciphertext);

/**
 * Initialize a ciphertext pair.
 *
 * @param pair[out] ciphertext pair to initialize
 * @param public_key[in] the public key
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
BFE_VISIBLE int
bloomfilter_enc_init_ciphertext_pair(bloomfilter_enc_ciphertext_pair_t* pair,
                                     const bloomfilter_enc_public_key_t* public_key);

/**
 * Clear ciphertext pair.
 *
 * @param ciphertextPair[out] the corresponding ciphertext pair.
 */
BFE_VISIBLE void
bloomfilter_enc_clear_ciphertext_pair(bloomfilter_enc_ciphertext_pair_t* ciphertextPair);

/**
 * Calculates number of bytes needed to store a given ciphertext.
 *
 * @param ciphertext[in] the ciphertext.
 * @return Number of bytes needed to store the ciphertext.
 */
BFE_VISIBLE unsigned int
bloomfilter_enc_ciphertext_size_bin(const bloomfilter_enc_ciphertext_t* ciphertext);

/**
 * Writes a given ciphertext to a byte array.
 *
 * @param bin[out]                  - the ciphertext byte array.
 * @param ciphertext[in]            - the ciphertext.
 */
BFE_VISIBLE void bloomfilter_enc_ciphertext_write_bin(uint8_t* bin,
                                                      bloomfilter_enc_ciphertext_t* ciphertext);

/**
 * Reads a given ciphertext stored as a byte array.
 *
 * @param ciphertext                - the ciphertext
 * @param bin                       - the destination byte array.
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
BFE_VISIBLE int bloomfilter_enc_ciphertext_read_bin(bloomfilter_enc_ciphertext_t* ciphertext,
                                                    const uint8_t* bin);

/**
 * Calculates number of bytes needed to store a given secret key.
 *
 * @param secret_key[in] the secret key.
 * @return Number of bytes needed to store the secret key.
 */
BFE_VISIBLE unsigned int
bloomfilter_enc_secret_key_size_bin(const bloomfilter_enc_secret_key_t* secret_key);

/**
 * Writes a given secret key to a byte array.
 *
 * @param bin[out]                  - the secret key byte array.
 * @param secret_key[in]            - the secret key.
 */
BFE_VISIBLE void bloomfilter_enc_secret_key_write_bin(uint8_t* bin,
                                                      bloomfilter_enc_secret_key_t* secret_key);

/**
 * Reads a given secret key stored as a byte array.
 *
 * @param secret_key                - the secret key
 * @param bin                       - the destination byte array.
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
BFE_VISIBLE int bloomfilter_enc_secret_key_read_bin(bloomfilter_enc_secret_key_t* secret_key,
                                                    const uint8_t* bin);

/**
 * Calculates number of bytes needed to store a given public key.
 *
 * @param public_key[in] the public key.
 * @return Number of bytes needed to store the public key.
 */
BFE_VISIBLE unsigned int
bloomfilter_enc_public_key_size_bin(const bloomfilter_enc_public_key_t* public_key);

/**
 * Writes a given public key to a byte array.
 *
 * @param bin[out]                  - the public key byte array.
 * @param public_key[in]            - the public key.
 */
BFE_VISIBLE void bloomfilter_enc_public_key_write_bin(uint8_t* bin,
                                                      bloomfilter_enc_public_key_t* public_key);

/**
 * Reads a given public key stored as a byte array.
 *
 * @param public_key                - the public key
 * @param bin                       - the destination byte array.
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
BFE_VISIBLE int bloomfilter_enc_public_key_read_bin(bloomfilter_enc_public_key_t* public_key,
                                                    const uint8_t* bin);



#endif // MASTER_PROJECT_BLOOMFILTER_ENC_H
