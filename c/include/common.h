#ifndef COMMON_H
#define COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// mdns service type used for peer discovery
#define P2P_SERVICE_TYPE "_p2pshare._tcp"

// framing constants
#define P2P_HEADER_SIZE 4
#define P2P_MAX_MSG_SIZE (256U * 1024U)

// basic size limits
#define P2P_MAX_USERNAME_LEN 64
#define P2P_MAX_HOST_LEN 256
#define P2P_MAX_PATH_LEN 512
#define P2P_MAX_FILENAME_LEN 256

// key and crypto sizes
#define P2P_ED25519_PUBKEY_BYTES 32
#define P2P_ED25519_PRIVKEY_BYTES 64
#define P2P_X25519_PUBKEY_BYTES 32
#define P2P_X25519_PRIVKEY_BYTES 32
#define P2P_SESSION_KEY_BYTES 32
#define P2P_NONCE_BYTES 12
#define P2P_SHA256_HEX_LEN 64

// message types
#define MSG_HELLO             "HELLO"
#define MSG_HELLO_ACK         "HELLO_ACK"
#define MSG_KEY_EXCHANGE      "KEY_EXCHANGE"
#define MSG_KEY_EXCHANGE_ACK  "KEY_EXCHANGE_ACK"
#define MSG_LIST_REQUEST      "LIST_REQUEST"
#define MSG_LIST_RESPONSE     "LIST_RESPONSE"
#define MSG_FILE_REQUEST      "FILE_REQUEST"
#define MSG_FILE_TRANSFER     "FILE_TRANSFER"
#define MSG_CONSENT_REQUEST   "CONSENT_REQUEST"
#define MSG_CONSENT_RESPONSE  "CONSENT_RESPONSE"
#define MSG_KEY_ROTATION      "KEY_ROTATION"
#define MSG_ERROR             "ERROR"

// common status codes
#define P2P_OK 0
#define P2P_ERR -1

// discovered peer info
typedef struct {
    char username[P2P_MAX_USERNAME_LEN];
    char host[P2P_MAX_HOST_LEN];
    uint16_t port;
} PeerInfo;

// pinned contact info
typedef struct {
    char username[P2P_MAX_USERNAME_LEN];
    char identity_pub_b64[128];
    bool verified;
} ContactEntry;

#endif