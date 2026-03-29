#ifndef CRYPTO_H
#define CRYPTO_H

#include "../common.h"
#include <stddef.h>
#include <stdint.h>

#define P2P_PASSPHRASE_SALT_BYTES 16
#define P2P_GCM_TAG_BYTES 16

typedef struct {
    unsigned char pub[P2P_ED25519_PUBKEY_BYTES];
    unsigned char priv[P2P_ED25519_PRIVKEY_BYTES];
} IdentityKeyPair;

typedef struct {
    unsigned char pub[P2P_X25519_PUBKEY_BYTES];
    unsigned char priv[P2P_X25519_PRIVKEY_BYTES];
} EphemeralKeyPair;

typedef struct {
    unsigned char shared_secret[P2P_SESSION_KEY_BYTES];
    unsigned char send_key[P2P_SESSION_KEY_BYTES];
    unsigned char recv_key[P2P_SESSION_KEY_BYTES];
} SessionKeys;

int base64_encode(const unsigned char *input, size_t input_len, char *output, size_t output_size);
int base64_decode(const char *input, unsigned char *output, size_t output_size, size_t *output_len);

int generate_identity_keypair(IdentityKeyPair *kp);
int load_identity_keypair(const char *pub_path,
                          const char *priv_path,
                          const char *passphrase,
                          IdentityKeyPair *kp);
int save_identity_keypair(const char *pub_path,
                          const char *priv_path,
                          const IdentityKeyPair *kp,
                          const char *passphrase);

int derive_key_from_passphrase(const char *passphrase,
                               unsigned char salt[P2P_PASSPHRASE_SALT_BYTES],
                               unsigned char key[P2P_SESSION_KEY_BYTES],
                               int generate_salt);

int identity_pubkey_to_base64(const IdentityKeyPair *kp, char *output, size_t output_size);

int generate_ephemeral_keypair(EphemeralKeyPair *kp);
int ephemeral_pubkey_to_base64(const EphemeralKeyPair *kp, char *output, size_t output_size);
int ephemeral_pubkey_from_base64(const char *input, unsigned char pub[P2P_X25519_PUBKEY_BYTES]);

int compute_shared_secret(const EphemeralKeyPair *local_kp,
                          const unsigned char remote_pub[P2P_X25519_PUBKEY_BYTES],
                          unsigned char shared_secret[P2P_SESSION_KEY_BYTES]);

int derive_session_key(const unsigned char shared_secret[P2P_SESSION_KEY_BYTES],
                       const char *info_str,
                       unsigned char session_key[P2P_SESSION_KEY_BYTES]);

int encrypt_bytes(const unsigned char key[P2P_SESSION_KEY_BYTES],
                  const unsigned char *plaintext,
                  size_t plaintext_len,
                  unsigned char nonce[P2P_NONCE_BYTES],
                  unsigned char *ciphertext,
                  size_t *ciphertext_len);

int decrypt_bytes(const unsigned char key[P2P_SESSION_KEY_BYTES],
                  const unsigned char nonce[P2P_NONCE_BYTES],
                  const unsigned char *ciphertext,
                  size_t ciphertext_len,
                  unsigned char *plaintext,
                  size_t *plaintext_len);

#endif