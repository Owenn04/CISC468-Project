#ifndef CONNECTION_H
#define CONNECTION_H

#include "../common.h"
#include "../crypto/crypto.h"
#include <cjson/cJSON.h>

// state for one peer connection
typedef struct {
    int sockfd;

    char local_username[P2P_MAX_USERNAME_LEN];
    char remote_username[P2P_MAX_USERNAME_LEN];

    IdentityKeyPair local_identity;
    EphemeralKeyPair local_ephemeral;

    unsigned char remote_identity_pub[P2P_ED25519_PUBKEY_BYTES];
    unsigned char remote_ephemeral_pub[P2P_X25519_PUBKEY_BYTES];

    // trust + identity tracking
    bool remote_identity_known;
    bool remote_identity_verified;

    SessionKeys session_keys;

    bool handshake_complete;
    bool is_initiator;
} PeerConnection;

/* =========================
   lifecycle
   ========================= */

// initialize connection state
void connection_init(PeerConnection *conn, int sockfd, const char *local_username, bool is_initiator);

// close socket and clear sensitive data
void connection_cleanup(PeerConnection *conn);

// set local identity keypair
int connection_set_identity(PeerConnection *conn, const IdentityKeyPair *identity);

// connect to remote peer
int connection_connect_to_host(const char *host, uint16_t port);

/* =========================
   handshake
   ========================= */

// perform initiator side of handshake
int connection_handshake_initiator(PeerConnection *conn);

// perform responder side of handshake
int connection_handshake_responder(PeerConnection *conn);

// send hello / hello_ack
int connection_send_hello(PeerConnection *conn);
int connection_send_hello_ack(PeerConnection *conn);

// send key exchange / key_exchange_ack
int connection_send_key_exchange(PeerConnection *conn);
int connection_send_key_exchange_ack(PeerConnection *conn);

// receive and process handshake messages
int connection_handle_hello(PeerConnection *conn, cJSON *msg);
int connection_handle_hello_ack(PeerConnection *conn, cJSON *msg);
int connection_handle_key_exchange(PeerConnection *conn, cJSON *msg);
int connection_handle_key_exchange_ack(PeerConnection *conn, cJSON *msg);

// derive final session key after key exchange
int connection_derive_session(PeerConnection *conn);

/* =========================
   encrypted messaging
   ========================= */

// send encrypted payload inside standard message envelope
int connection_send_encrypted(
    PeerConnection *conn,
    const char *msg_type,
    cJSON *plain_payload
);

// receive one message and decrypt payload if needed
cJSON *connection_recv_encrypted(
    PeerConnection *conn,
    char *msg_type_buf,
    size_t msg_type_buf_size
);

// wrap payload into { "enc": { "nonce": "...", "ct": "..." } }
cJSON *connection_build_encrypted_payload(
    PeerConnection *conn,
    cJSON *plain_payload
);

// extract and decrypt payload from encrypted message
cJSON *connection_decrypt_payload(
    PeerConnection *conn,
    cJSON *msg
);

/* =========================
   server-side dispatch helper
   ========================= */

// receive + decrypt + return message type + payload
int connection_recv_and_parse(
    PeerConnection *conn,
    char *msg_type_buf,
    size_t msg_type_buf_size,
    cJSON **out_payload
);

#endif