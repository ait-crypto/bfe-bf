#include "../include/bloomfilter_enc.h"
#undef DOUBLE
#undef CALL

#include <cgreen/cgreen.h>

Describe(BFE);
BeforeEach(BFE) {}
AfterEach(BFE) {}

Ensure(BFE, encrypt_decrypt) {
  bloomfilter_enc_secret_key_t sk;
  bloomfilter_enc_public_key_t pk;

  assert_true(!bloomfilter_enc_init_secret_key(&sk));
  assert_true(!bloomfilter_enc_init_public_key(&pk));
  assert_true(!bloomfilter_enc_setup(&pk, &sk, 57, 50, 0.001));

  bloomfilter_enc_ciphertext_pair_t ciphertextPair;

  uint8_t decrypted[pk.keyLength];
  memset(decrypted, 0, pk.keyLength);
  assert_true(!bloomfilter_enc_init_ciphertext_pair(&ciphertextPair, &pk));
  assert_true(!bloomfilter_enc_encrypt(&ciphertextPair, &pk));
  assert_true(!bloomfilter_enc_decrypt(decrypted, &pk, &sk, &ciphertextPair.ciphertext));
  assert_true(!memcmp(ciphertextPair.K, decrypted, ciphertextPair.KLen));

  bloomfilter_enc_clear_secret_key(&sk);
  bloomfilter_enc_clear_public_key(&pk);
  bloomfilter_enc_clear_ciphertext_pair(&ciphertextPair);
}

Ensure(BFE, encrypt_decrypt_serialized) {
  bloomfilter_enc_secret_key_t sk;
  bloomfilter_enc_public_key_t pk;

  assert_true(!bloomfilter_enc_init_secret_key(&sk));
  assert_true(!bloomfilter_enc_init_public_key(&pk));
  assert_true(!bloomfilter_enc_setup(&pk, &sk, 57, 50, 0.001));

  bloomfilter_enc_ciphertext_pair_t ciphertextPair;
  bloomfilter_enc_ciphertext_t ciphertext;

  uint8_t decrypted[pk.keyLength];
  memset(decrypted, 0, pk.keyLength);

  assert_true(!bloomfilter_enc_init_ciphertext_pair(&ciphertextPair, &pk));
  assert_true(!bloomfilter_enc_encrypt(&ciphertextPair, &pk));

  const size_t csize = bloomfilter_enc_ciphertext_size_bin(&ciphertextPair.ciphertext);
  uint8_t bin[csize];

  bloomfilter_enc_ciphertext_write_bin(bin, &ciphertextPair.ciphertext);
  assert_true(!bloomfilter_enc_ciphertext_read_bin(&ciphertext, bin));

  assert_true(!bloomfilter_enc_decrypt(decrypted, &pk, &sk, &ciphertext));
  assert_true(!memcmp(ciphertextPair.K, decrypted, ciphertextPair.KLen));

  bloomfilter_enc_clear_secret_key(&sk);
  bloomfilter_enc_clear_public_key(&pk);
  bloomfilter_enc_clear_ciphertext_pair(&ciphertextPair);
  bloomfilter_enc_clear_ciphertext(&ciphertext);
}

Ensure(BFE, decrypt_punctured) {
  bloomfilter_enc_secret_key_t sk;
  bloomfilter_enc_public_key_t pk;

  assert_true(!bloomfilter_enc_init_secret_key(&sk));
  assert_true(!bloomfilter_enc_init_public_key(&pk));
  assert_true(!bloomfilter_enc_setup(&pk, &sk, 57, 50, 0.001));

  bloomfilter_enc_ciphertext_pair_t ciphertextPair;

  uint8_t decrypted[pk.keyLength];
  memset(decrypted, 0, pk.keyLength);

  assert_true(!bloomfilter_enc_init_ciphertext_pair(&ciphertextPair, &pk));
  assert_true(!bloomfilter_enc_encrypt(&ciphertextPair, &pk));
  bloomfilter_enc_puncture(&sk, &ciphertextPair.ciphertext);

  assert_false(!bloomfilter_enc_decrypt(decrypted, &pk, &sk, &ciphertextPair.ciphertext));

  bloomfilter_enc_clear_secret_key(&sk);
  bloomfilter_enc_clear_public_key(&pk);
  bloomfilter_enc_clear_ciphertext_pair(&ciphertextPair);
}

Ensure(BFE, keys_serialized) {
  bloomfilter_enc_secret_key_t sk;
  bloomfilter_enc_public_key_t pk;

  bloomfilter_enc_secret_key_t deserialized_sk;
  bloomfilter_enc_public_key_t deserialized_pk;

  assert_true(!bloomfilter_enc_init_secret_key(&sk));
  assert_true(!bloomfilter_enc_init_public_key(&pk));
  assert_true(!bloomfilter_enc_setup(&pk, &sk, 57, 50, 0.001));
  assert_true(!bloomfilter_enc_init_public_key(&deserialized_pk));

  bloomfilter_enc_ciphertext_pair_t ciphertextPair;
  assert_true(!bloomfilter_enc_init_ciphertext_pair(&ciphertextPair, &pk));

  uint8_t pk_bin[bloomfilter_enc_public_key_size_bin(&pk)];
  bloomfilter_enc_public_key_write_bin(pk_bin, &pk);
  assert_true(!bloomfilter_enc_public_key_read_bin(&deserialized_pk, pk_bin));

  uint8_t* sk_bin = malloc(bloomfilter_enc_secret_key_size_bin(&sk));
  bloomfilter_enc_secret_key_write_bin(sk_bin, &sk);
  assert_true(!bloomfilter_enc_secret_key_read_bin(&deserialized_sk, sk_bin));
  free(sk_bin);

  uint8_t decrypted[pk.keyLength];
  memset(decrypted, 0, pk.keyLength);

  assert_true(!bloomfilter_enc_encrypt(&ciphertextPair, &deserialized_pk));
  assert_true(!bloomfilter_enc_decrypt(decrypted, &pk, &sk, &ciphertextPair.ciphertext));
  assert_true(!memcmp(ciphertextPair.K, decrypted, ciphertextPair.KLen));

  assert_true(!bloomfilter_enc_encrypt(&ciphertextPair, &pk));
  assert_true(!bloomfilter_enc_decrypt(decrypted, &pk, &deserialized_sk, &ciphertextPair.ciphertext));
  assert_true(!memcmp(ciphertextPair.K, decrypted, ciphertextPair.KLen));

  bloomfilter_enc_clear_ciphertext_pair(&ciphertextPair);
  bloomfilter_enc_clear_secret_key(&deserialized_sk);
  bloomfilter_enc_clear_public_key(&deserialized_pk);
  bloomfilter_enc_clear_secret_key(&sk);
  bloomfilter_enc_clear_public_key(&pk);
}

int main() {
  TestSuite* suite = create_test_suite();
  add_test_with_context(suite, BFE, encrypt_decrypt);
  add_test_with_context(suite, BFE, encrypt_decrypt_serialized);
  add_test_with_context(suite, BFE, decrypt_punctured);
  add_test_with_context(suite, BFE, keys_serialized);
  return run_test_suite(suite, create_text_reporter());
}
