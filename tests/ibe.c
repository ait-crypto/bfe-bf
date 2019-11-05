#include "../include/bfibe.h"
#undef DOUBLE
#undef CALL

#include <cgreen/cgreen.h>

Describe(IBE);
BeforeEach(IBE) {}
AfterEach(IBE) {}

Ensure(IBE, encrypt_decrypt) {
  uint8_t id[5];
  rand_bytes(id, sizeof(id));

  uint8_t message[64];
  rand_bytes(message, sizeof(message));

  uint8_t decrypted[sizeof(message)] = { 0 };

  bf_ibe_secret_key_t master_key;
  bf_ibe_public_key_t public_key;
  bf_ibe_extracted_key_t private_key;

  bf_ibe_init_secret_key(&master_key);
  bf_ibe_init_public_key(&public_key);
  bf_ibe_init_extracted_key(&private_key);

  assert_true(!bf_ibe_setup(&master_key, &public_key));
  assert_true(!bf_ibe_extract(&private_key, &master_key, id, sizeof(id)));

  bn_t r, order;
  bn_null(r);
  bn_null(order);

  TRY {
    bn_new(r);
    bn_new(order);
    ep_curve_get_ord(order);
    bn_rand_mod(r, order);

    bf_ibe_ciphertext_t* cipherText = bf_ibe_init_ciphertext(sizeof(message));
    assert_true(!bf_ibe_encrypt(cipherText, &public_key, id, sizeof(id), message, r));
    assert_true(!bf_ibe_decrypt(decrypted, cipherText, &private_key));
    assert_true(!memcmp(message, decrypted, sizeof(message) == 0));
    bf_ibe_free_ciphertext(cipherText);
  } CATCH_ANY {
    assert_true(false);
  } FINALLY {
    bn_free(r);
    bn_free(order);
  }

  bf_ibe_clear_extracted_key(&private_key);
  bf_ibe_clear_public_key(&public_key);
  bf_ibe_clear_secret_key(&master_key);
}

int main() {
  TestSuite* suite = create_test_suite();
  add_test_with_context(suite, IBE, encrypt_decrypt);
  return run_test_suite(suite, create_text_reporter());
}
