#include "../include/bfe.h"
#undef DOUBLE
#undef CALL

#include <cgreen/cgreen.h>

Describe(BFE);
BeforeEach(BFE) {}
AfterEach(BFE) {}

#define KEY_SIZE 32

Ensure(BFE, encrypt_decrypt) {
  bfe_secret_key_t sk;
  bfe_public_key_t pk;

  assert_true(!bfe_init_secret_key(&sk));
  assert_true(!bfe_init_public_key(&pk));
  assert_true(!bfe_keygen(&pk, &sk, KEY_SIZE, 50, 0.001));

  bfe_ciphertext_t ciphertext;

  uint8_t K[KEY_SIZE], decrypted[KEY_SIZE];
  memset(decrypted, 0, KEY_SIZE);
  assert_true(!bfe_init_ciphertext(&ciphertext, &pk));
  assert_true(!bfe_encaps(&ciphertext, K, &pk));
  assert_true(!bfe_decaps(decrypted, &pk, &sk, &ciphertext));
  assert_true(!memcmp(K, decrypted, KEY_SIZE));

  bfe_clear_secret_key(&sk);
  bfe_clear_public_key(&pk);
  bfe_clear_ciphertext(&ciphertext);
}

Ensure(BFE, encrypt_decrypt_serialized) {
  bfe_secret_key_t sk;
  bfe_public_key_t pk;

  assert_true(!bfe_init_secret_key(&sk));
  assert_true(!bfe_init_public_key(&pk));
  assert_true(!bfe_keygen(&pk, &sk, KEY_SIZE, 50, 0.001));

  bfe_ciphertext_t ciphertext;
  bfe_ciphertext_t deserialized_ciphertext;

  uint8_t K[KEY_SIZE], decrypted[KEY_SIZE];
  memset(decrypted, 0, KEY_SIZE);

  assert_true(!bfe_init_ciphertext(&ciphertext, &pk));
  assert_true(!bfe_encaps(&ciphertext, K, &pk));

  const size_t csize = bfe_ciphertext_size_bin(&ciphertext);
  uint8_t* bin = malloc(csize);
  assert_true(bin != NULL);

  bfe_ciphertext_write_bin(bin, &ciphertext);
  assert_true(!bfe_ciphertext_read_bin(&deserialized_ciphertext, bin));

  assert_true(!bfe_decaps(decrypted, &pk, &sk, &deserialized_ciphertext));
  assert_true(!memcmp(K, decrypted, KEY_SIZE));

  free(bin);
  bfe_clear_secret_key(&sk);
  bfe_clear_public_key(&pk);
  bfe_clear_ciphertext(&deserialized_ciphertext);
  bfe_clear_ciphertext(&ciphertext);
}

Ensure(BFE, decrypt_punctured) {
  bfe_secret_key_t sk;
  bfe_public_key_t pk;

  assert_true(!bfe_init_secret_key(&sk));
  assert_true(!bfe_init_public_key(&pk));
  assert_true(!bfe_keygen(&pk, &sk, KEY_SIZE, 50, 0.001));

  bfe_ciphertext_t ciphertext;

  uint8_t K[KEY_SIZE], decrypted[KEY_SIZE];
  memset(decrypted, 0, KEY_SIZE);

  assert_true(!bfe_init_ciphertext(&ciphertext, &pk));
  assert_true(!bfe_encaps(&ciphertext, K, &pk));
  bfe_puncture(&sk, &ciphertext);

  assert_false(!bfe_decaps(decrypted, &pk, &sk, &ciphertext));

  bfe_clear_secret_key(&sk);
  bfe_clear_public_key(&pk);
  bfe_clear_ciphertext(&ciphertext);
}

Ensure(BFE, keys_serialized) {
  bfe_secret_key_t sk;
  bfe_public_key_t pk;

  bfe_secret_key_t deserialized_sk;
  bfe_public_key_t deserialized_pk;

  assert_true(!bfe_init_secret_key(&sk));
  assert_true(!bfe_init_public_key(&pk));
  assert_true(!bfe_keygen(&pk, &sk, KEY_SIZE, 50, 0.001));
  assert_true(!bfe_init_public_key(&deserialized_pk));

  bfe_ciphertext_t ciphertext;
  assert_true(!bfe_init_ciphertext(&ciphertext, &pk));

  uint8_t* pk_bin = malloc(bfe_public_key_size_bin());
  bfe_public_key_write_bin(pk_bin, &pk);
  assert_true(!bfe_public_key_read_bin(&deserialized_pk, pk_bin));
  free(pk_bin);

  uint8_t* sk_bin = malloc(bfe_secret_key_size_bin(&sk));
  bfe_secret_key_write_bin(sk_bin, &sk);
  assert_true(!bfe_secret_key_read_bin(&deserialized_sk, sk_bin));
  free(sk_bin);

  uint8_t K[KEY_SIZE], decrypted[KEY_SIZE];
  memset(decrypted, 0, KEY_SIZE);

  assert_true(!bfe_encaps(&ciphertext, K, &deserialized_pk));
  assert_true(!bfe_decaps(decrypted, &pk, &sk, &ciphertext));
  assert_true(!memcmp(K, decrypted, KEY_SIZE));

  assert_true(!bfe_encaps(&ciphertext, K, &pk));
  assert_true(!bfe_decaps(decrypted, &pk, &deserialized_sk, &ciphertext));
  assert_true(!memcmp(K, decrypted, KEY_SIZE));

  bfe_clear_ciphertext(&ciphertext);
  bfe_clear_secret_key(&deserialized_sk);
  bfe_clear_public_key(&deserialized_pk);
  bfe_clear_secret_key(&sk);
  bfe_clear_public_key(&pk);
}

int main() {
  TestSuite* suite = create_test_suite();
  add_test_with_context(suite, BFE, encrypt_decrypt);
  add_test_with_context(suite, BFE, encrypt_decrypt_serialized);
  add_test_with_context(suite, BFE, decrypt_punctured);
  add_test_with_context(suite, BFE, keys_serialized);
  return run_test_suite(suite, create_text_reporter());
}
