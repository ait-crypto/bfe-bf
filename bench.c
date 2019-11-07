#include <relic/relic_conf.h>
/* Because relic hardcodes too much stuff ... */
#undef BENCH
#define BENCH 50
#include <relic/relic_bench.h>

#include <string.h>

#include "include/bloomfilter_enc.h"

static void bench_bfe(void) {
  bloomfilter_enc_secret_key_t sk;
  bloomfilter_enc_public_key_t pk;

  bloomfilter_enc_init_secret_key(&sk);
  bloomfilter_enc_init_public_key(&pk);
  /* n=2^19 >= 2^12 per day for 3 months, correctness error ~ 2^-10 */
  BENCH_ONCE("keygen", bloomfilter_enc_setup(&pk, &sk, 32, 1 << 19, 0.0009765625));

  bloomfilter_enc_ciphertext_t ciphertext;
  bloomfilter_enc_init_ciphertext(&ciphertext, &pk);

  uint8_t K[pk.keyLength], decrypted[pk.keyLength];
  BENCH_BEGIN("encrypt") {
    BENCH_ADD(bloomfilter_enc_encrypt(&ciphertext, K, &pk));
  }
  BENCH_END;
  BENCH_BEGIN("decrypt") {
    bloomfilter_enc_encrypt(&ciphertext, K, &pk);
    memset(decrypted, 0, pk.keyLength);
    BENCH_ADD(bloomfilter_enc_decrypt(decrypted, &pk, &sk, &ciphertext));
  }
  BENCH_END;
  BENCH_BEGIN("puncture") {
    bloomfilter_enc_encrypt(&ciphertext, K, &pk);
    BENCH_ADD(bloomfilter_enc_puncture(&sk, &ciphertext));
  }
  BENCH_END;

  bloomfilter_enc_clear_secret_key(&sk);
  bloomfilter_enc_clear_public_key(&pk);
  bloomfilter_enc_clear_ciphertext(&ciphertext);
}

int main() {
  bench_bfe();
  return 0;
}
