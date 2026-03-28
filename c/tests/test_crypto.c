#include "../include/crypto/crypto.h"
#include "test_utils.h"

#include <string.h>

static int test_crypto_basic(void) {
    unsigned char msg[] = "hello";
    unsigned char nonce[P2P_NONCE_BYTES];
    unsigned char ct[256];
    unsigned char pt[256];
    size_t ct_len = 0;
    size_t pt_len = 0;
    unsigned char key[32] = {0};
    IdentityKeyPair id;

    ASSERT_EQ(generate_identity_keypair(&id), P2P_OK);
    ASSERT_EQ(encrypt_bytes(key, msg, strlen((char *)msg), nonce, ct, &ct_len), P2P_OK);
    ASSERT_EQ(decrypt_bytes(key, nonce, ct, ct_len, pt, &pt_len), P2P_OK);

    pt[pt_len] = '\0';
    ASSERT_STR_EQ((char *)pt, "hello");

    TEST_PASS();
}

static int test_crypto_failure(void) {
    unsigned char msg[] = "hello";
    unsigned char nonce[P2P_NONCE_BYTES];
    unsigned char ct[256];
    unsigned char pt[256];
    size_t ct_len = 0;
    size_t pt_len = 0;
    unsigned char key1[32] = {0};
    unsigned char key2[32] = {0};

    key2[0] = 1;

    ASSERT_EQ(encrypt_bytes(key1, msg, strlen((char *)msg), nonce, ct, &ct_len), P2P_OK);
    ASSERT_TRUE(decrypt_bytes(key2, nonce, ct, ct_len, pt, &pt_len) != P2P_OK);

    TEST_PASS();
}

static int test_tamper_detected(void) {
    unsigned char msg[] = "hello";
    unsigned char nonce[P2P_NONCE_BYTES];
    unsigned char ct[256];
    unsigned char pt[256];
    size_t ct_len = 0;
    size_t pt_len = 0;
    unsigned char key[32] = {0};

    ASSERT_EQ(encrypt_bytes(key, msg, strlen((char *)msg), nonce, ct, &ct_len), P2P_OK);

    ct[0] ^= 0x01;

    ASSERT_TRUE(decrypt_bytes(key, nonce, ct, ct_len, pt, &pt_len) != P2P_OK);

    TEST_PASS();
}

int test_crypto(void) {
    test_print_start("test_crypto_basic");
    ASSERT_EQ(test_crypto_basic(), 0);
    test_print_pass("test_crypto_basic");

    test_print_start("test_crypto_failure");
    ASSERT_EQ(test_crypto_failure(), 0);
    test_print_pass("test_crypto_failure");

    test_print_start("test_tamper_detected");
    ASSERT_EQ(test_tamper_detected(), 0);
    test_print_pass("test_tamper_detected");

    TEST_PASS();
}