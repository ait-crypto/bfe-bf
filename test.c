#include <stdio.h>

#include "include/bfibe.h"
#include "include/bloomfilter.h"
#include "include/bloomfilter_enc.h"
#include "include/hibe.h"
#include "include/tb_bloomfilter_enc.h"

static void test_tb_bloomfilter_enc() {
    tb_bloomfilter_enc_setup_pair_t *setupPair;
    tb_bloomfilter_enc_ciphertext_t *ciphertext;
    tb_bloomfilter_enc_ciphertext_t *ciphertext2;
    tb_bloomfilter_enc_ciphertext_t *ciphertext3;
    tb_bloomfilter_enc_ciphertext_t *ciphertext4;
    tb_bloomfilter_enc_ciphertext_t *ciphertext5;
    tb_bloomfilter_enc_ciphertext_t *ciphertext6;
    tb_bloomfilter_enc_ciphertext_t *ciphertext7;
    tb_bloomfilter_enc_ciphertext_t *ciphertext8;
    uint8_t K[57]; // todo this should be dynamic
    uint8_t K2[57]; // todo this should be dynamic
    uint8_t K3[57]; // todo this should be dynamic
    uint8_t K4[57]; // todo this should be dynamic
    uint8_t K5[57]; // todo this should be dynamic
    uint8_t K6[57]; // todo this should be dynamic
    uint8_t K7[57]; // todo this should be dynamic
    uint8_t K8[57]; // todo this should be dynamic

    TRY {
        setupPair = tb_bloomfilter_enc_init_setup_pair(100, 0.001, 3);
        tb_bloomfilter_enc_setup(setupPair, 57);
        ciphertext = tb_bloomfilter_enc_init_ciphertext(setupPair->systemParams);
        tb_bloomfilter_enc_encrypt(ciphertext, setupPair->systemParams, "000");
        tb_bloomfilter_enc_decrypt(K, setupPair->systemParams, setupPair->secretKey, ciphertext);
        tb_bloomfilter_enc_puncture_key(setupPair->secretKey, setupPair->systemParams, ciphertext);
        tb_bloomfilter_enc_decrypt(K2, setupPair->systemParams, setupPair->secretKey, ciphertext);


        printf("\nDecrypted key:\n");
        for (int i = 0; i < 57; i++) {
            printf("%02x", K[i]);
        }

        printf("\nDecrypted key:\n");
        for (int i = 0; i < 57; i++) {
            printf("%02x", K2[i]);
        }
        printf("\n");

//        tb_bloomfilter_enc_puncture_int(setupPair.secretKey, setupPair.systemParams);
//        ciphertext2 = tb_bloomfilter_enc_encrypt(setupPair.systemParams, "001");
//        tb_bloomfilter_enc_decrypt(K2, setupPair.systemParams, setupPair.secretKey, ciphertext2);
//
//        printf("\nDecrypted key:\n");
//        for (int i = 0; i < 57; i++) {
//            printf("%c", K2[i]);
//        }
//
//        tb_bloomfilter_enc_puncture_int(setupPair.secretKey, setupPair.systemParams);
//        ciphertext3 = tb_bloomfilter_enc_encrypt(setupPair.systemParams, "010");
//        tb_bloomfilter_enc_decrypt(K3, setupPair.systemParams, setupPair.secretKey, ciphertext3);
//
//        printf("\nDecrypted key:\n");
//        for (int i = 0; i < 57; i++) {
//            printf("%c", K3[i]);
//        }
//
//        tb_bloomfilter_enc_puncture_int(setupPair.secretKey, setupPair.systemParams);
//        ciphertext4 = tb_bloomfilter_enc_encrypt(setupPair.systemParams, "011");
//        tb_bloomfilter_enc_decrypt(K4, setupPair.systemParams, setupPair.secretKey, ciphertext4);
//
//        printf("\nDecrypted key:\n");
//        for (int i = 0; i < 57; i++) {
//            printf("%c", K4[i]);
//        }
//
//        tb_bloomfilter_enc_puncture_int(setupPair.secretKey, setupPair.systemParams);
//        ciphertext5 = tb_bloomfilter_enc_encrypt(setupPair.systemParams, "100");
//        tb_bloomfilter_enc_decrypt(K5, setupPair.systemParams, setupPair.secretKey, ciphertext5);
//
//        printf("\nDecrypted key:\n");
//        for (int i = 0; i < 57; i++) {
//            printf("%c", K5[i]);
//        }
//
//        tb_bloomfilter_enc_puncture_int(setupPair.secretKey, setupPair.systemParams);
//        ciphertext6 = tb_bloomfilter_enc_encrypt(setupPair.systemParams, "101");
//        tb_bloomfilter_enc_decrypt(K6, setupPair.systemParams, setupPair.secretKey, ciphertext6);
//
//        printf("\nDecrypted key:\n");
//        for (int i = 0; i < 57; i++) {
//            printf("%c", K6[i]);
//        }
//
//        tb_bloomfilter_enc_puncture_int(setupPair.secretKey, setupPair.systemParams);
//        ciphertext7 = tb_bloomfilter_enc_encrypt(setupPair.systemParams, "110");
//        tb_bloomfilter_enc_decrypt(K7, setupPair.systemParams, setupPair.secretKey, ciphertext7);
//
//        printf("\nDecrypted key:\n");
//        for (int i = 0; i < 57; i++) {
//            printf("%c", K7[i]);
//        }
//
//        tb_bloomfilter_enc_puncture_int(setupPair.secretKey, setupPair.systemParams);
//        ciphertext8 = tb_bloomfilter_enc_encrypt(setupPair.systemParams, "111");
//        tb_bloomfilter_enc_decrypt(K8, setupPair.systemParams, setupPair.secretKey, ciphertext8);
//
//        printf("\nDecrypted key:\n");
//        for (int i = 0; i < 57; i++) {
//            printf("%c", K8[i]);
//        }
//
//        tb_bloomfilter_enc_puncture_int(setupPair.secretKey, setupPair.systemParams);

    } CATCH_ANY {

    } FINALLY {
        tb_bloomfilter_enc_free_ciphertext(ciphertext);
//        tb_bloomfilter_enc_free_ciphertext(ciphertext2);
//        tb_bloomfilter_enc_free_ciphertext(ciphertext3);
//        tb_bloomfilter_enc_free_ciphertext(ciphertext4);
//        tb_bloomfilter_enc_free_ciphertext(ciphertext5);
//        tb_bloomfilter_enc_free_ciphertext(ciphertext6);
//        tb_bloomfilter_enc_free_ciphertext(ciphertext7);
//        tb_bloomfilter_enc_free_ciphertext(ciphertext8);
        tb_bloomfilter_enc_free_setup_pair(setupPair);
    }

}

static void test_hibe() {
    uint8_t message[] = { 0x41, 0x61, 0x62, 0x63, 0x64, 0x41, 0x61, 0x62, 0x63, 0x64, 0x41, 0x61, 0x62, 0x63, 0x64, 0x41, 0x61, 0x62, 0x63, 0x64, 0x41, 0x61, 0x62, 0x63, 0x64, 0x41, 0x61, 0x62, 0x63, 0x64, 0x64, 0x64 };
    uint8_t decrypted[32];
    hibe_setup_pair_t *setupPair;
    hibe_private_key_t *privateKey;
    hibe_private_key_t *newPrivateKey;
    hibe_private_key_t *newPrivateKey2;
    hibe_private_key_t *newPrivateKey3;
    hibe_ciphertext_t *ciphertext;

    setupPair = hibe_init_setup_pair(6);

    TRY {
        hibe_setup(setupPair);
        privateKey = hibe_init_private_key(setupPair->systemParams, "11");
        hibe_extract(privateKey, setupPair->systemParams, setupPair->masterKey, "11");
        newPrivateKey = hibe_init_private_key(setupPair->systemParams, "11");
        hibe_derive(newPrivateKey, setupPair->systemParams, privateKey, "110");
        newPrivateKey2 = hibe_init_private_key(setupPair->systemParams, "11");
        hibe_derive(newPrivateKey2, setupPair->systemParams, newPrivateKey, "1100");
        newPrivateKey3 = hibe_init_private_key(setupPair->systemParams, "11");
        hibe_derive(newPrivateKey3, setupPair->systemParams, newPrivateKey, "1101");
        ciphertext = hibe_init_ciphertext(sizeof(message));
        hibe_encrypt(ciphertext, setupPair->systemParams, "1101", message);
        hibe_decrypt(decrypted, ciphertext, newPrivateKey3);
    } CATCH_ANY {

    } FINALLY {
        hibe_free_setup_pair(setupPair);
        hibe_free_private_key(privateKey);
        hibe_free_private_key(newPrivateKey);
        hibe_free_private_key(newPrivateKey2);
        hibe_free_private_key(newPrivateKey3);
        hibe_free_ciphertext(ciphertext);
    }


    printf("Original msg:\n");
    for (int i = 0; i < 32; i++) {
        printf("%02x", message[i]);
    }
    printf("\nDecrypted msg:\n");
    for (int i = 0; i < 32; i++) {
        printf("%02x", decrypted[i]);
    }
    printf("\n");
}

static void test_ibe() {
    uint8_t id[5];
    rand_bytes(id, sizeof(id));
    uint8_t message[] = { 0x41, 0x61, 0x22, 0x62, 0x63, 0x64, 0x41, 0x61, 0x62, 0x63, 0x64, 0x41, 0x61, 0x62, 0x63, 0x64, 0x41, 0x61, 0x62, 0x63, 0x64, 0x41, 0x61, 0x62, 0x63, 0x64, 0x41, 0x61, 0x62, 0x63, 0x64, 0x64, 0x64 };
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
    bn_null(r)
    bn_null(order)
    bn_new(r)
    bn_new(order)
    ep_curve_get_ord(order);
    bn_rand_mod(r, order);

    bf_ibe_ciphertext_t *cipherText = bf_ibe_init_ciphertext(sizeof(message));
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
    for (int i = 0; i < ciphertextPair.KLen; i++) {
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
    uint8_t input1[2] = { 'P', 'a' };
    uint8_t input2[2] = { 'P', 'b' };
    uint8_t input3[2] = { 'P', 'c' };

    printf("\nSTART BLOOM FILTER TEST\n\n");
    bloomfilter_t bloom = bloomfilter_init(300, 0.001);
    printf("--- Filter size: %d\n", bloomfilter_get_size(bloom));
    printf("--- Filter hash count: %d\n", bloom.hashCount);
    bloomfilter_add(&bloom, input1, sizeof(input1));
    bloomfilter_add(&bloom, input2, sizeof(input2));
    printf("--- Filter has input1: %s\n", bloomfilter_maybe_contains(bloom, input1, sizeof(input1)) == 1 ? "TRUE" : "FALSE");
    printf("--- Filter has input2: %s\n", bloomfilter_maybe_contains(bloom, input2, sizeof(input2)) == 1 ? "TRUE" : "FALSE");
    printf("--- Filter has input3: %s\n", bloomfilter_maybe_contains(bloom, input3, sizeof(input3)) == 1 ? "TRUE" : "FALSE");
    bloomfilter_clean(&bloom);
    printf("\nEND BLOOM FILTER TEST\n");
}

int main () {
    test_ibe();
    test_bloom_filter();
    test_bloomfilter_enc();
    // test_hibe();
    // test_tb_bloomfilter_enc();
}

