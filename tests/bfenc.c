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

  bloomfilter_enc_init_secret_key(&sk);
  bloomfilter_enc_init_public_key(&pk);
  bloomfilter_enc_setup(&pk, &sk, 57, 50, 0.001);

  bloomfilter_enc_ciphertext_pair_t ciphertextPair;

  uint8_t decrypted[pk.keyLength];
  memset(decrypted, 0, pk.keyLength);
  TRY {
    assert_true(!bloomfilter_enc_init_ciphertext_pair(&ciphertextPair, &pk));
    assert_true(!bloomfilter_enc_encrypt(&ciphertextPair, &pk));
    assert_true(!bloomfilter_enc_decrypt(decrypted, &pk, &sk, &ciphertextPair.ciphertext));
    assert_true(!memcmp(ciphertextPair.K, decrypted, ciphertextPair.KLen));
  }
  CATCH_ANY {
    assert_true(false);
  }
  FINALLY {
    bloomfilter_enc_clear_secret_key(&sk);
    bloomfilter_enc_clear_public_key(&pk);
    bloomfilter_enc_clear_ciphertext_pair(&ciphertextPair);
  }
}

Ensure(BFE, encrypt_decrypt_serialized) {
  bloomfilter_enc_secret_key_t sk;
  bloomfilter_enc_public_key_t pk;

  bloomfilter_enc_init_secret_key(&sk);
  bloomfilter_enc_init_public_key(&pk);
  bloomfilter_enc_setup(&pk, &sk, 57, 50, 0.001);

  bloomfilter_enc_ciphertext_pair_t ciphertextPair;
  bloomfilter_enc_ciphertext_t ciphertext;

  uint8_t decrypted[pk.keyLength];
  memset(decrypted, 0, pk.keyLength);
  TRY {
    assert_true(!bloomfilter_enc_init_ciphertext_pair(&ciphertextPair, &pk));
    assert_true(!bloomfilter_enc_encrypt(&ciphertextPair, &pk));

    const size_t csize = bloomfilter_enc_ciphertext_size_bin(&ciphertextPair.ciphertext);
    uint8_t bin[csize];

    bloomfilter_enc_ciphertext_write_bin(bin, &ciphertextPair.ciphertext);
    assert_true(!bloomfilter_enc_ciphertext_read_bin(&ciphertext, bin));

    assert_true(!bloomfilter_enc_decrypt(decrypted, &pk, &sk, &ciphertext));
    assert_true(!memcmp(ciphertextPair.K, decrypted, ciphertextPair.KLen));
  }
  CATCH_ANY {
    assert_true(false);
  }
  FINALLY {
    bloomfilter_enc_clear_secret_key(&sk);
    bloomfilter_enc_clear_public_key(&pk);
    bloomfilter_enc_clear_ciphertext_pair(&ciphertextPair);
    bloomfilter_enc_clear_ciphertext(&ciphertext);
  }
}

Ensure(BFE, decrypt_punctured) {
  bloomfilter_enc_secret_key_t sk;
  bloomfilter_enc_public_key_t pk;

  bloomfilter_enc_init_secret_key(&sk);
  bloomfilter_enc_init_public_key(&pk);
  bloomfilter_enc_setup(&pk, &sk, 57, 50, 0.001);

  bloomfilter_enc_ciphertext_pair_t ciphertextPair;

  uint8_t decrypted[pk.keyLength];
  memset(decrypted, 0, pk.keyLength);
  TRY {
    assert_true(!bloomfilter_enc_init_ciphertext_pair(&ciphertextPair, &pk));
    assert_true(!bloomfilter_enc_encrypt(&ciphertextPair, &pk));
    bloomfilter_enc_puncture(&sk, &ciphertextPair.ciphertext);

    assert_false(!bloomfilter_enc_decrypt(decrypted, &pk, &sk, &ciphertextPair.ciphertext));
  }
  CATCH_ANY {
    assert_true(false);
  }
  FINALLY {
    bloomfilter_enc_clear_secret_key(&sk);
    bloomfilter_enc_clear_public_key(&pk);
    bloomfilter_enc_clear_ciphertext_pair(&ciphertextPair);
  }
}

int main() {
  TestSuite* suite = create_test_suite();
  add_test_with_context(suite, BFE, encrypt_decrypt);
  add_test_with_context(suite, BFE, encrypt_decrypt_serialized);
  add_test_with_context(suite, BFE, decrypt_punctured);
  return run_test_suite(suite, create_text_reporter());
}
