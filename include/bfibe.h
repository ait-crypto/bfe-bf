#ifndef BFE_BFIBE_H
#define BFE_BFIBE_H

#include "macros.h"

#include <relic/relic.h>

typedef struct {
  ep_t u;
  size_t vLen;
  uint8_t v[];
} bf_ibe_ciphertext_t;

typedef struct {
  bn_t key;
} bf_ibe_secret_key_t;

typedef struct {
  ep2_t key;
  unsigned int set;
} bf_ibe_extracted_key_t;

typedef struct {
  ep_t key;
} bf_ibe_public_key_t;

typedef struct {
  bf_ibe_public_key_t public_key;
  bf_ibe_secret_key_t secret_key;
} bf_ibe_keys_t;

/**
 * Sets up the Boneh-Franklin Identity Based Encryption (ibe) scheme.
 *
 * @param secret_key[out]                 - the ibe secret key
 * @param public_key[out]                 - the ibe public key
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
BFE_VISIBLE int bf_ibe_setup(bf_ibe_secret_key_t* secret_key, bf_ibe_public_key_t* public_key);

/**
 * Extracts a private key for the given id.
 *
 * @param privateKey[out]           - the ibe private key.
 * @param masterKey[in]             - the ibe master key.
 * @param id[in]                    - id for which the private key is being retrieved.
 * @param idLen[in]                 - length of id in bytes.
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
BFE_VISIBLE int bf_ibe_extract(bf_ibe_extracted_key_t* privateKey,
                               const bf_ibe_secret_key_t* masterKey, const uint8_t* id,
                               size_t idLen);

/**
 * Encrypts a given message under the specific id.
 *
 * @param ciphertext[out]           - the ciphertext in form of C = (U, V).
 * @param publicKey[in]             - the ibe public key.
 * @param id[in]                    - id under which the message is being encrypted.
 * @param idLen[in]                 - length of id in bytes.
 * @param message[in]               - message to be encrypted.
 * @param r[in]                     - random value.
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
BFE_VISIBLE int bf_ibe_encrypt(bf_ibe_ciphertext_t* ciphertext,
                               const bf_ibe_public_key_t* publicKey, const uint8_t* id,
                               size_t idLen, const uint8_t* message, bn_t r);

/**
 * Decrypts a given ciphertext.
 *
 * @param message[out]              - the returned decrypted message.
 * @param ciphertext[in]            - ciphertext.
 * @param privateKey[in]            - private key for the id under which the message was encrypted.
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
BFE_VISIBLE int bf_ibe_decrypt(uint8_t* message, const bf_ibe_ciphertext_t* ciphertext,
                               const bf_ibe_extracted_key_t* privateKey);

/**
 * Allocates the memory for the ibe ciphertext.
 *
 * @param messageLen                - length of message in bytes.
 * @return The ciphertext struct.
 */
BFE_VISIBLE bf_ibe_ciphertext_t* bf_ibe_init_ciphertext(size_t messageLen);

/**
 * Frees the memory allocated by the ibe ciphertext. This method has to be called after the
 * ciphertext is no longer needed to avoid memory leaks.
 *
 * @param ciphertext                - the corresponding ciphertext.
 */
BFE_VISIBLE void bf_ibe_free_ciphertext(bf_ibe_ciphertext_t* ciphertext);

/**
 * Initializes secret key.
 *
 * @param key the key to initialize
 */
BFE_VISIBLE int bf_ibe_init_secret_key(bf_ibe_secret_key_t* key);

/**
 * Clear secret key.
 *
 * @param key the key to clear
 */
BFE_VISIBLE void bf_ibe_clear_secret_key(bf_ibe_secret_key_t* key);

/**
 * Initializes public key.
 *
 * @param key the key to initialize
 */
BFE_VISIBLE int bf_ibe_init_public_key(bf_ibe_public_key_t* key);

/**
 * Clear public key.
 *
 * @param key the key to clear
 */
BFE_VISIBLE void bf_ibe_clear_public_key(bf_ibe_public_key_t* key);

/**
 * Initializes extracted key.
 *
 * @param key the key to initialize
 */
BFE_VISIBLE int bf_ibe_init_extracted_key(bf_ibe_extracted_key_t* key);

/**
 * Clear extracted key.
 *
 * @param key the key to clear
 */
BFE_VISIBLE void bf_ibe_clear_extracted_key(bf_ibe_extracted_key_t* key);

#endif
