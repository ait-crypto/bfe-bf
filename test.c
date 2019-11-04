#include <stdio.h>

#include "include/bfibe.h"
#include "include/bloomfilter.h"
#include "include/bloomfilter_enc.h"

static void test_ibe() {
  uint8_t id[5];
  rand_bytes(id, sizeof(id));
  uint8_t message[] = {0x41, 0x61, 0x22, 0x62, 0x63, 0x64, 0x41, 0x61, 0x62, 0x63, 0x64,
                       0x41, 0x61, 0x62, 0x63, 0x64, 0x41, 0x61, 0x62, 0x63, 0x64, 0x41,
                       0x61, 0x62, 0x63, 0x64, 0x41, 0x61, 0x62, 0x63, 0x64, 0x64, 0x64};
  uint8_t decrypted[33];

  bf_ibe_secret_key_t master_key;
  bf_ibe_public_key_t public_key;
  bf_ibe_extracted_key_t private_key;

  bf_ibe_init_secret_key(&master_key);
  bf_ibe_init_public_key(&public_key);
  bf_ibe_init_extracted_key(&private_key);

  bf_ibe_setup(&master_key, &public_key);

  bf_ibe_extract(&private_key, &master_key, id, sizeof(id));

  bn_t r, order;
  bn_null(r) bn_null(order) bn_new(r) bn_new(order) ep_curve_get_ord(order);
  bn_rand_mod(r, order);

  bf_ibe_ciphertext_t* cipherText = bf_ibe_init_ciphertext(sizeof(message));
  bf_ibe_encrypt(cipherText, &public_key, id, sizeof(id), message, r);
  bf_ibe_decrypt(decrypted, cipherText, &private_key);
  printf("RESULTS:\n");
  printf("Original msg:\n");
  for (int i = 0; i < 33; i++) {
    printf("%02x", message[i]);
  }
  printf("\nDecrypted msg:\n");
  for (int i = 0; i < 33; i++) {
    printf("%02x", decrypted[i]);
  }

  bn_free(r);
  bn_free(order);
  bf_ibe_free_ciphertext(cipherText);

  bf_ibe_clear_extracted_key(&private_key);
  bf_ibe_clear_public_key(&public_key);
  bf_ibe_clear_secret_key(&master_key);
}

static void test_bloomfilter_enc() {
  err_t e;

  bloomfilter_enc_secret_key_t sk;
  bloomfilter_enc_public_key_t pk;

  bloomfilter_enc_init_secret_key(&sk);
  bloomfilter_enc_init_public_key(&pk);
  bloomfilter_enc_setup(&pk, &sk, 57, 50, 0.001);

  bloomfilter_enc_ciphertext_pair_t ciphertextPair;

  TRY {
    uint8_t decrypted[pk.keyLength];
    memset(decrypted, 0, pk.keyLength);

    bloomfilter_enc_init_ciphertext_pair(&ciphertextPair, &pk);
    bloomfilter_enc_encrypt(&ciphertextPair, &pk);
    printf("Original key %u %u:\n", pk.keyLength, ciphertextPair.KLen);
    for (unsigned int i = 0; i < ciphertextPair.KLen; i++) {
      printf("%02x", ciphertextPair.K[i]);
    }
    printf("\n");
    bloomfilter_enc_decrypt(decrypted, &pk, &sk, &ciphertextPair.ciphertext);
    printf("Decrypted key:\n");
    for (unsigned int i = 0; i < ciphertextPair.KLen; i++) {
      printf("%02x", decrypted[i]);
    }
    printf("\n");
    memset(decrypted, 0, pk.keyLength);

    bloomfilter_enc_puncture(&sk, &ciphertextPair.ciphertext);
    // bloomfilter_enc_write_setup_pair_to_file(setupPair);
    // bloomfilter_enc_system_params_t systemParamsFromFile =
    // bloomfilter_enc_read_system_params_from_file(); bloomfilter_enc_secret_key_t
    // *secretKeyFromFile = bloomfilter_enc_read_secret_key_from_file();
    bloomfilter_enc_decrypt(decrypted, &pk, &sk, &ciphertextPair.ciphertext);
    printf("Decrypted key:\n");
    for (unsigned int i = 0; i < ciphertextPair.KLen; i++) {
      printf("%02x", decrypted[i]);
    }
    printf("\n");
  }
  CATCH(e) {
    switch (e) {
    case ERR_NO_VALID:
      util_print("Key already punctured!\n");
    }
  }
  FINALLY {
    bloomfilter_enc_clear_secret_key(&sk);
    bloomfilter_enc_clear_public_key(&pk);
    bloomfilter_enc_clear_ciphertext_pair(&ciphertextPair);
  }
}

static void test_bloom_filter() {
  uint8_t input1[2] = {'P', 'a'};
  uint8_t input2[2] = {'P', 'b'};
  uint8_t input3[2] = {'P', 'c'};

  printf("\nSTART BLOOM FILTER TEST\n\n");
  bloomfilter_t bloom = bloomfilter_init(300, 0.001);
  printf("--- Filter size: %d\n", bloomfilter_get_size(bloom));
  printf("--- Filter hash count: %d\n", bloom.hashCount);
  bloomfilter_add(&bloom, input1, sizeof(input1));
  bloomfilter_add(&bloom, input2, sizeof(input2));
  printf("--- Filter has input1: %s\n",
         bloomfilter_maybe_contains(bloom, input1, sizeof(input1)) == 1 ? "TRUE" : "FALSE");
  printf("--- Filter has input2: %s\n",
         bloomfilter_maybe_contains(bloom, input2, sizeof(input2)) == 1 ? "TRUE" : "FALSE");
  printf("--- Filter has input3: %s\n",
         bloomfilter_maybe_contains(bloom, input3, sizeof(input3)) == 1 ? "TRUE" : "FALSE");
  bloomfilter_clean(&bloom);
  printf("\nEND BLOOM FILTER TEST\n");
}

int main() {
  test_ibe();
  test_bloom_filter();
  test_bloomfilter_enc();
}
