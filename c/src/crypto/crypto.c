#include "../../include/crypto/crypto.h"

#include <openssl/evp.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

static int ensure_sodium_init(void) {
    static int initialized = 0;

    if (!initialized) {
        if (sodium_init() < 0) {
            return P2P_ERR;
        }
        initialized = 1;
    }

    return P2P_OK;
}

static int write_bytes_to_file(const char *path, const unsigned char *data, size_t len) {
    FILE *fp;

    if (path == NULL || data == NULL) {
        return P2P_ERR;
    }

    fp = fopen(path, "wb");
    if (fp == NULL) {
        return P2P_ERR;
    }

    if (fwrite(data, 1, len, fp) != len) {
        fclose(fp);
        return P2P_ERR;
    }

    fclose(fp);
    return P2P_OK;
}

static int read_bytes_from_file(const char *path, unsigned char *data, size_t len) {
    FILE *fp;

    if (path == NULL || data == NULL) {
        return P2P_ERR;
    }

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return P2P_ERR;
    }

    if (fread(data, 1, len, fp) != len) {
        fclose(fp);
        return P2P_ERR;
    }

    fclose(fp);
    return P2P_OK;
}

// hkdf-extract
static int hkdf_extract(const unsigned char *salt, size_t salt_len,
                        const unsigned char *ikm, size_t ikm_len,
                        unsigned char prk[crypto_auth_hmacsha256_BYTES]) {
    crypto_auth_hmacsha256_state state;
    unsigned char zero_salt[crypto_auth_hmacsha256_KEYBYTES];

    if (ikm == NULL || prk == NULL) {
        return P2P_ERR;
    }

    if (salt == NULL || salt_len == 0) {
        memset(zero_salt, 0, sizeof(zero_salt));
        salt = zero_salt;
        salt_len = sizeof(zero_salt);
    }

    crypto_auth_hmacsha256_init(&state, salt, salt_len);
    crypto_auth_hmacsha256_update(&state, ikm, ikm_len);
    crypto_auth_hmacsha256_final(&state, prk);

    sodium_memzero(&state, sizeof(state));
    sodium_memzero(zero_salt, sizeof(zero_salt));

    return P2P_OK;
}

// hkdf-expand
static int hkdf_expand(const unsigned char prk[crypto_auth_hmacsha256_BYTES],
                       const unsigned char *info, size_t info_len,
                       unsigned char *okm, size_t okm_len) {
    crypto_auth_hmacsha256_state state;
    unsigned char block[crypto_auth_hmacsha256_BYTES];
    unsigned char counter = 0x01;

    if (prk == NULL || okm == NULL) {
        return P2P_ERR;
    }

    if (okm_len > crypto_auth_hmacsha256_BYTES) {
        return P2P_ERR;
    }

    crypto_auth_hmacsha256_init(&state, prk, crypto_auth_hmacsha256_BYTES);

    if (info != NULL && info_len > 0) {
        crypto_auth_hmacsha256_update(&state, info, info_len);
    }

    crypto_auth_hmacsha256_update(&state, &counter, 1);
    crypto_auth_hmacsha256_final(&state, block);

    memcpy(okm, block, okm_len);

    sodium_memzero(&state, sizeof(state));
    sodium_memzero(block, sizeof(block));

    return P2P_OK;
}

int base64_encode(const unsigned char *input, size_t input_len, char *output, size_t output_size) {
    size_t needed;

    if (ensure_sodium_init() != P2P_OK) {
        return P2P_ERR;
    }

    needed = sodium_base64_encoded_len(input_len, sodium_base64_VARIANT_ORIGINAL);
    if (output_size < needed) {
        return P2P_ERR;
    }

    sodium_bin2base64(output, output_size, input, input_len, sodium_base64_VARIANT_ORIGINAL);
    return P2P_OK;
}

int base64_decode(const char *input, unsigned char *output, size_t output_size, size_t *output_len) {
    if (ensure_sodium_init() != P2P_OK) {
        return P2P_ERR;
    }

    if (sodium_base642bin(output, output_size, input, strlen(input),
                          NULL, output_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0) {
        return P2P_ERR;
    }

    return P2P_OK;
}

int generate_identity_keypair(IdentityKeyPair *kp) {
    if (ensure_sodium_init() != P2P_OK || kp == NULL) {
        return P2P_ERR;
    }

    crypto_sign_keypair(kp->pub, kp->priv);
    return P2P_OK;
}

int load_identity_keypair(const char *pub_path, const char *priv_path, IdentityKeyPair *kp) {
    if (kp == NULL) {
        return P2P_ERR;
    }

    if (read_bytes_from_file(pub_path, kp->pub, sizeof(kp->pub)) != P2P_OK) {
        return P2P_ERR;
    }

    if (read_bytes_from_file(priv_path, kp->priv, sizeof(kp->priv)) != P2P_OK) {
        return P2P_ERR;
    }

    return P2P_OK;
}

int save_identity_keypair(const char *pub_path, const char *priv_path, const IdentityKeyPair *kp) {
    if (kp == NULL) {
        return P2P_ERR;
    }

    if (write_bytes_to_file(pub_path, kp->pub, sizeof(kp->pub)) != P2P_OK) {
        return P2P_ERR;
    }

    if (write_bytes_to_file(priv_path, kp->priv, sizeof(kp->priv)) != P2P_OK) {
        return P2P_ERR;
    }

    return P2P_OK;
}

int identity_pubkey_to_base64(const IdentityKeyPair *kp, char *output, size_t output_size) {
    return base64_encode(kp->pub, sizeof(kp->pub), output, output_size);
}

int generate_ephemeral_keypair(EphemeralKeyPair *kp) {
    if (ensure_sodium_init() != P2P_OK || kp == NULL) {
        return P2P_ERR;
    }

    crypto_kx_keypair(kp->pub, kp->priv);
    return P2P_OK;
}

int ephemeral_pubkey_to_base64(const EphemeralKeyPair *kp, char *output, size_t output_size) {
    return base64_encode(kp->pub, sizeof(kp->pub), output, output_size);
}

int ephemeral_pubkey_from_base64(const char *input, unsigned char pub[P2P_X25519_PUBKEY_BYTES]) {
    size_t decoded_len = 0;

    if (base64_decode(input, pub, P2P_X25519_PUBKEY_BYTES, &decoded_len) != P2P_OK) {
        return P2P_ERR;
    }

    return decoded_len == P2P_X25519_PUBKEY_BYTES ? P2P_OK : P2P_ERR;
}

int compute_shared_secret(const EphemeralKeyPair *local_kp,
                          const unsigned char remote_pub[P2P_X25519_PUBKEY_BYTES],
                          unsigned char shared_secret[P2P_SESSION_KEY_BYTES]) {
    if (ensure_sodium_init() != P2P_OK || local_kp == NULL || remote_pub == NULL || shared_secret == NULL) {
        return P2P_ERR;
    }

    return crypto_scalarmult(shared_secret, local_kp->priv, remote_pub) == 0 ? P2P_OK : P2P_ERR;
}

int derive_session_key(const unsigned char *shared_secret,
                       const char *info,
                       unsigned char out_key[P2P_SESSION_KEY_BYTES]) {
    unsigned char prk[crypto_auth_hmacsha256_BYTES];

    if (shared_secret == NULL || info == NULL || out_key == NULL) {
        return P2P_ERR;
    }

    if (hkdf_extract(NULL, 0,
                     shared_secret, P2P_SESSION_KEY_BYTES,
                     prk) != P2P_OK) {
        return P2P_ERR;
    }

    if (hkdf_expand(prk,
                    (const unsigned char *)info, strlen(info),
                    out_key, P2P_SESSION_KEY_BYTES) != P2P_OK) {
        sodium_memzero(prk, sizeof(prk));
        return P2P_ERR;
    }

    sodium_memzero(prk, sizeof(prk));
    return P2P_OK;
}

// encrypt using aes-gcm
int encrypt_bytes(const unsigned char key[P2P_SESSION_KEY_BYTES],
                  const unsigned char *plaintext,
                  size_t plaintext_len,
                  unsigned char nonce[P2P_NONCE_BYTES],
                  unsigned char *ciphertext,
                  size_t *ciphertext_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int total_len = 0;
    unsigned char tag[16];

    if (ensure_sodium_init() != P2P_OK) {
        return P2P_ERR;
    }

    if (key == NULL || plaintext == NULL || nonce == NULL || ciphertext == NULL || ciphertext_len == NULL) {
        return P2P_ERR;
    }

    randombytes_buf(nonce, P2P_NONCE_BYTES);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return P2P_ERR;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return P2P_ERR;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, P2P_NONCE_BYTES, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return P2P_ERR;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return P2P_ERR;
    }

    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return P2P_ERR;
        }
        total_len += len;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext + total_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return P2P_ERR;
    }
    total_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return P2P_ERR;
    }

    memcpy(ciphertext + total_len, tag, sizeof(tag));
    total_len += (int)sizeof(tag);

    *ciphertext_len = (size_t)total_len;

    EVP_CIPHER_CTX_free(ctx);
    return P2P_OK;
}

// decrypt aes-gcm
int decrypt_bytes(const unsigned char key[P2P_SESSION_KEY_BYTES],
                  const unsigned char nonce[P2P_NONCE_BYTES],
                  const unsigned char *ciphertext,
                  size_t ciphertext_len,
                  unsigned char *plaintext,
                  size_t *plaintext_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int total_len = 0;
    size_t data_len;
    const unsigned char *tag;

    if (key == NULL || nonce == NULL || ciphertext == NULL || plaintext == NULL || plaintext_len == NULL) {
        return P2P_ERR;
    }

    if (ciphertext_len < 16) {
        return P2P_ERR;
    }

    data_len = ciphertext_len - 16;
    tag = ciphertext + data_len;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return P2P_ERR;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return P2P_ERR;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, P2P_NONCE_BYTES, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return P2P_ERR;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return P2P_ERR;
    }

    if (data_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)data_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return P2P_ERR;
        }
        total_len += len;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return P2P_ERR;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + total_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return P2P_ERR;
    }
    total_len += len;

    *plaintext_len = (size_t)total_len;

    EVP_CIPHER_CTX_free(ctx);
    return P2P_OK;
}