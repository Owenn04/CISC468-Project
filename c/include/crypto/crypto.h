#ifndef CRYPTO_H
#define CRYPTO_H

#include "../common.h"
#include <stddef.h>
#include <stdint.h>

// long-term identity keypair
typedef struct {
    unsigned char pub[P2P_ED25519_PUBKEY_BYTES];
    unsigned char priv[P2P_ED25519_PRIVKEY_BYTES];
} IdentityKeyPair;

// ephemeral x25519 keypair
typedef struct {
    unsigned char pub[P2P_X25519_PUBKEY_BYTES];
    unsigned char priv[P2P_X25519_PRIVKEY_BYTES];
} EphemeralKeyPair;

// UPDATED: session keys (directional)
typedef struct {
    unsigned char shared_secret[P2P_SESSION_KEY_BYTES];

    // NEW: directional keys (required for Python compatibility)
    unsigned char send_key[P2P_SESSION_KEY_BYTES];
    unsigned char recv_key[P2P_SESSION_KEY_BYTES];
} SessionKeys;

// base64 helpers
int base64_encode(const unsigned char *input, size_t input_len, char *output, size_t output_size);
int base64_decode(const char *input, unsigned char *output, size_t output_size, size_t *output_len);

// identity key helpers
int generate_identity_keypair(IdentityKeyPair *kp);
int load_identity_keypair(const char *pub_path, const char *priv_path, IdentityKeyPair *kp);
int save_identity_keypair(const char *pub_path, const char *priv_path, const IdentityKeyPair *kp);

// convert ed25519 public key to base64
int identity_pubkey_to_base64(const IdentityKeyPair *kp, char *output, size_t output_size);

// ephemeral key helpers
int generate_ephemeral_keypair(EphemeralKeyPair *kp);
int ephemeral_pubkey_to_base64(const EphemeralKeyPair *kp, char *output, size_t output_size);
int ephemeral_pubkey_from_base64(const char *input, unsigned char pub[P2P_X25519_PUBKEY_BYTES]);

// derive shared secret and session key
int compute_shared_secret(const EphemeralKeyPair *local_kp,
                          const unsigned char remote_pub[P2P_X25519_PUBKEY_BYTES],
                          unsigned char shared_secret[P2P_SESSION_KEY_BYTES]);

int derive_session_key(const unsigned char shared_secret[P2P_SESSION_KEY_BYTES],
                       const char *info_str,
                       unsigned char session_key[P2P_SESSION_KEY_BYTES]);

// encrypt plaintext with aes-256-gcm
int encrypt_bytes(const unsigned char key[P2P_SESSION_KEY_BYTES],
                  const unsigned char *plaintext,
                  size_t plaintext_len,
                  unsigned char nonce[P2P_NONCE_BYTES],
                  unsigned char *ciphertext,
                  size_t *ciphertext_len);

// decrypt aes-256-gcm ciphertext
int decrypt_bytes(const unsigned char key[P2P_SESSION_KEY_BYTES],
                  const unsigned char nonce[P2P_NONCE_BYTES],
                  const unsigned char *ciphertext,
                  size_t ciphertext_len,
                  unsigned char *plaintext,
                  size_t *plaintext_len);

#endif