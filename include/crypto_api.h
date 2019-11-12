#ifndef BFE_CRYPTO_API_H
#define BFE_CRYPTO_API_H

#include "macros.h"

#define CRYPTO_PUBLICKEYBYTES ((3 * 4) + (1 + 2 * 48))
#define CRYPTO_SECRETKEYBYTES ((2 * 4) + 65536 + 524288 * (1 + 4 * 48))
#define CRYPTO_CIPHERTEXTBYTES ((1 * 4) + (1 + 2 * 48) + (32 * 11))
#define CRYPTO_BYTES 32

BFE_VISIBLE int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
BFE_VISIBLE int crypto_kem_enc(unsigned char *c, unsigned char *k, const unsigned char *pk);
BFE_VISIBLE int crypto_kem_dec(unsigned char *k, const unsigned char *c, const unsigned char *sk);
BFE_VISIBLE int crypto_kem_punc(unsigned char *sk, const unsigned char *c);

#endif
