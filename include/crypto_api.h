#ifndef BFE_CRYPTO_API_H
#define BFE_CRYPTO_API_H

#include "macros.h"

/** Size of the public key */
#define CRYPTO_PUBLICKEYBYTES ((3 * 4) + (1 + 2 * 48))
/** Size of the secret key */
#define CRYPTO_SECRETKEYBYTES ((2 * 4) + 65536 + 524288 * (1 + 4 * 48))
/** Size of the ciphertext */
#define CRYPTO_CIPHERTEXTBYTES ((1 * 4) + (1 + 2 * 48) + (32 * 11))
/** Size of the encapsulated key */
#define CRYPTO_BYTES 32

/**
 * Generate a new key pair.
 *
 * @param pk buffer of size \ref CRYPTO_PUBLICKEYBYTES to store public key
 * @param sk buffer of size \ref CRYPTO_SECRETKEYBYTES to store the secret key
 * @return 0 on success, non-0 otherwise
 */
BFE_VISIBLE int crypto_kem_keypair(unsigned char* pk, unsigned char* sk);
/**
 * Encapsulate a new key.
 *
 * @param c buffer of size \ref CRYPTO_CIPHERTEXTBYTES to store the ciphertext
 * @param k buffer of size \ref CRYPTO_BYTES to store the encapsulated key
 * @param pk the public key
 * @return 0 on success, non-0 otherwise
 */
BFE_VISIBLE int crypto_kem_enc(unsigned char* c, unsigned char* k, const unsigned char* pk);
/**
 * Decapsulate a ciphertext.
 *
 * @param c the ciphertext
 * @param k buffer of size \ref CRYPTO_BYTES to store the encapsulated key
 * @param sk the secret key
 * @return 0 on success, non-0 otherwise
 */
BFE_VISIBLE int crypto_kem_dec(unsigned char* k, const unsigned char* c, const unsigned char* sk);
/**
 * Puncture the secret key with a ciphertext.
 *
 * @param c the ciphertext
 * @param sk the secret key
 * @return 0 on success, non-0 otherwise
 */
BFE_VISIBLE int crypto_kem_punc(unsigned char* sk, const unsigned char* c);

#endif
