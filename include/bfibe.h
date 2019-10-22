#ifndef MASTER_PROJECT_LIBRARY_H
#define MASTER_PROJECT_LIBRARY_H

#include <relic/relic.h>

typedef struct _bf_ibe_ciphertext_t {
    ep_t u;
    int vLen;
    uint8_t v[];
} bf_ibe_ciphertext_t;

typedef struct _bf_ibe_keys_t {
    ep_t publicKey;
    bn_t masterKey;
} bf_ibe_keys_t;

/**
 * Sets up the Boneh-Franklin Identity Based Encryption (ibe) scheme.
 *
 * @param keys[out]                 - the ibe key pair containing both public and master key.
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
int bf_ibe_setup(bf_ibe_keys_t *keys);

/**
 * Frees keys of the IBE.
 *
 * @param keys                      - keys of the IBE
 */
void bf_ibe_free_keys(bf_ibe_keys_t* keys);

/**
 * Extracts a private key for the given id.
 *
 * @param privateKey[out]           - the ibe private key.
 * @param masterKey[in]             - the ibe master key.
 * @param id[in]                    - id for which the private key is being retrieved.
 * @param idLen[in]                 - length of id in bytes.
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
int bf_ibe_extract(ep2_t privateKey, bn_t masterKey, uint8_t *id, int idLen);

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
int bf_ibe_encrypt(bf_ibe_ciphertext_t *ciphertext, ep_t publicKey, uint8_t *id, int idLen, uint8_t *message, bn_t r);

/**
 * Decrypts a given ciphertext.
 *
 * @param message[out]              - the returned decrypted message.
 * @param ciphertext[in]            - ciphertext.
 * @param privateKey[in]            - private key for the id under which the message was encrypted.
 * @return BFE_SUCCESS or BFE_ERR_*.
 */
int bf_ibe_decrypt(uint8_t *message, bf_ibe_ciphertext_t *ciphertext, ep2_t privateKey);

/**
 * Allocates the memory for the ibe ciphertext.
 *
 * @param messageLen                - length of message in bytes.
 * @return The ciphertext struct.
 */
bf_ibe_ciphertext_t *bf_ibe_init_ciphertext(int messageLen);

/**
 * Frees the memory allocated by the ibe ciphertext. This method has to be called after the ciphertext is no longer
 * needed to avoid memory leaks.
 *
 * @param ciphertext                - the corresponding ciphertext.
 */
void bf_ibe_free_ciphertext(bf_ibe_ciphertext_t *ciphertext);

#endif