#include "../include/network/connection.h"
#include "../include/network/protocol.h"

#include <arpa/inet.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* =========================
   helpers
   ========================= */

static int decode_identity_pubkey(const char *input,
                                  unsigned char pub[P2P_ED25519_PUBKEY_BYTES]) {
    size_t decoded_len = 0;

    if (!input || !pub) return P2P_ERR;

    if (base64_decode(input, pub, P2P_ED25519_PUBKEY_BYTES, &decoded_len) != P2P_OK)
        return P2P_ERR;

    return (decoded_len == P2P_ED25519_PUBKEY_BYTES) ? P2P_OK : P2P_ERR;
}

/* =========================
   lifecycle
   ========================= */

void connection_init(PeerConnection *conn, int sockfd, const char *local_username, bool is_initiator) {
    memset(conn, 0, sizeof(*conn));

    conn->sockfd = sockfd;
    conn->is_initiator = is_initiator;

    if (local_username) {
        strncpy(conn->local_username, local_username, P2P_MAX_USERNAME_LEN - 1);
    }
}

void connection_cleanup(PeerConnection *conn) {
    if (!conn) return;

    if (conn->sockfd >= 0) {
        close(conn->sockfd);
        conn->sockfd = -1;
    }

    sodium_memzero(&conn->session_keys, sizeof(conn->session_keys));
}

/* =========================
   identity
   ========================= */

int connection_set_identity(PeerConnection *conn, const IdentityKeyPair *identity) {
    memcpy(&conn->local_identity, identity, sizeof(IdentityKeyPair));
    return P2P_OK;
}

int connection_connect_to_host(const char *host, uint16_t port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return P2P_ERR;

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        close(sockfd);
        return P2P_ERR;
    }

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        return P2P_ERR;
    }

    return sockfd;
}

/* =========================
   handshake send
   ========================= */

int connection_send_hello(PeerConnection *conn) {
    char b64[128];
    identity_pubkey_to_base64(&conn->local_identity, b64, sizeof(b64));

    cJSON *p = build_hello_payload(b64);
    int r = send_json_message(conn->sockfd, MSG_HELLO, conn->local_username, p);
    cJSON_Delete(p);

    return r;
}

int connection_send_hello_ack(PeerConnection *conn) {
    char b64[128];
    identity_pubkey_to_base64(&conn->local_identity, b64, sizeof(b64));

    cJSON *p = build_hello_ack_payload(b64);
    int r = send_json_message(conn->sockfd, MSG_HELLO_ACK, conn->local_username, p);
    cJSON_Delete(p);

    return r;
}

int connection_send_key_exchange(PeerConnection *conn) {
    generate_ephemeral_keypair(&conn->local_ephemeral);

    char b64[128];
    ephemeral_pubkey_to_base64(&conn->local_ephemeral, b64, sizeof(b64));

    cJSON *p = build_key_exchange_payload(b64);
    int r = send_json_message(conn->sockfd, MSG_KEY_EXCHANGE, conn->local_username, p);
    cJSON_Delete(p);

    return r;
}

int connection_send_key_exchange_ack(PeerConnection *conn) {
    generate_ephemeral_keypair(&conn->local_ephemeral);

    char b64[128];
    ephemeral_pubkey_to_base64(&conn->local_ephemeral, b64, sizeof(b64));

    cJSON *p = build_key_exchange_ack_payload(b64);
    int r = send_json_message(conn->sockfd, MSG_KEY_EXCHANGE_ACK, conn->local_username, p);
    cJSON_Delete(p);

    return r;
}

/* =========================
   handshake receive
   ========================= */

int connection_handle_hello(PeerConnection *conn, cJSON *msg) {
    const char *sender = msg_get_sender(msg);
    cJSON *payload = msg_get_payload(msg);
    const char *pub;

    if (sender == NULL || payload == NULL) {
        return P2P_ERR;
    }

    strncpy(conn->remote_username, sender, P2P_MAX_USERNAME_LEN - 1);
    conn->remote_username[P2P_MAX_USERNAME_LEN - 1] = '\0';

    pub = payload_get_string(payload, "identity_pub");
    if (pub == NULL) {
        return P2P_ERR;
    }

    return decode_identity_pubkey(pub, conn->remote_identity_pub);
}

int connection_handle_hello_ack(PeerConnection *conn, cJSON *msg) {
    return connection_handle_hello(conn, msg);
}

int connection_handle_key_exchange(PeerConnection *conn, cJSON *msg) {
    const char *pub;
    cJSON *payload = msg_get_payload(msg);

    if (payload == NULL) {
        return P2P_ERR;
    }

    pub = payload_get_string(payload, "ephemeral_pub");
    if (pub == NULL) {
        return P2P_ERR;
    }

    return ephemeral_pubkey_from_base64(pub, conn->remote_ephemeral_pub);
}

int connection_handle_key_exchange_ack(PeerConnection *conn, cJSON *msg) {
    return connection_handle_key_exchange(conn, msg);
}

/* =========================
   session derivation
   ========================= */

int connection_derive_session(PeerConnection *conn) {
    if (compute_shared_secret(&conn->local_ephemeral,
                              conn->remote_ephemeral_pub,
                              conn->session_keys.shared_secret) != P2P_OK) {
        return P2P_ERR;
    }

    if (conn->is_initiator) {
        if (derive_session_key(conn->session_keys.shared_secret,
                               "initiator-to-responder",
                               conn->session_keys.send_key) != P2P_OK) {
            return P2P_ERR;
        }

        if (derive_session_key(conn->session_keys.shared_secret,
                               "responder-to-initiator",
                               conn->session_keys.recv_key) != P2P_OK) {
            return P2P_ERR;
        }
    } else {
        if (derive_session_key(conn->session_keys.shared_secret,
                               "responder-to-initiator",
                               conn->session_keys.send_key) != P2P_OK) {
            return P2P_ERR;
        }

        if (derive_session_key(conn->session_keys.shared_secret,
                               "initiator-to-responder",
                               conn->session_keys.recv_key) != P2P_OK) {
            return P2P_ERR;
        }
    }

    conn->handshake_complete = true;
    return P2P_OK;
}

/* =========================
   handshake flow
   ========================= */

int connection_handshake_initiator(PeerConnection *conn) {
    cJSON *msg = NULL;
    const char *type = NULL;
    int result = P2P_ERR;

    if (connection_send_hello(conn) != P2P_OK) {
        return P2P_ERR;
    }

    msg = recv_json_message(conn->sockfd);
    if (msg == NULL) {
        return P2P_ERR;
    }

    type = msg_get_type(msg);
    if (type == NULL || strcmp(type, MSG_HELLO_ACK) != 0) {
        cJSON_Delete(msg);
        return P2P_ERR;
    }

    if (connection_handle_hello_ack(conn, msg) != P2P_OK) {
        cJSON_Delete(msg);
        return P2P_ERR;
    }
    cJSON_Delete(msg);
    msg = NULL;

    if (connection_send_key_exchange(conn) != P2P_OK) {
        return P2P_ERR;
    }

    msg = recv_json_message(conn->sockfd);
    if (msg == NULL) {
        return P2P_ERR;
    }

    type = msg_get_type(msg);
    if (type == NULL || strcmp(type, MSG_KEY_EXCHANGE_ACK) != 0) {
        cJSON_Delete(msg);
        return P2P_ERR;
    }

    if (connection_handle_key_exchange_ack(conn, msg) != P2P_OK) {
        cJSON_Delete(msg);
        return P2P_ERR;
    }
    cJSON_Delete(msg);

    result = connection_derive_session(conn);
    return result;
}

int connection_handshake_responder(PeerConnection *conn) {
    cJSON *msg = NULL;
    const char *type = NULL;
    int result = P2P_ERR;

    msg = recv_json_message(conn->sockfd);
    if (msg == NULL) {
        return P2P_ERR;
    }

    type = msg_get_type(msg);
    if (type == NULL || strcmp(type, MSG_HELLO) != 0) {
        cJSON_Delete(msg);
        return P2P_ERR;
    }

    if (connection_handle_hello(conn, msg) != P2P_OK) {
        cJSON_Delete(msg);
        return P2P_ERR;
    }
    cJSON_Delete(msg);
    msg = NULL;

    if (connection_send_hello_ack(conn) != P2P_OK) {
        return P2P_ERR;
    }

    msg = recv_json_message(conn->sockfd);
    if (msg == NULL) {
        return P2P_ERR;
    }

    type = msg_get_type(msg);
    if (type == NULL || strcmp(type, MSG_KEY_EXCHANGE) != 0) {
        cJSON_Delete(msg);
        return P2P_ERR;
    }

    if (connection_handle_key_exchange(conn, msg) != P2P_OK) {
        cJSON_Delete(msg);
        return P2P_ERR;
    }
    cJSON_Delete(msg);

    if (connection_send_key_exchange_ack(conn) != P2P_OK) {
        return P2P_ERR;
    }

    result = connection_derive_session(conn);
    return result;
}

/* =========================
   encryption
   ========================= */

cJSON *connection_build_encrypted_payload(PeerConnection *conn, cJSON *plain) {
    char *text = NULL;
    unsigned char nonce[P2P_NONCE_BYTES];
    unsigned char ct[4096];
    size_t ct_len = 0;
    char nonce_b64[64];
    char ct_b64[8192];
    cJSON *enc = NULL;

    if (conn == NULL || plain == NULL || !conn->handshake_complete) {
        return NULL;
    }

    text = cJSON_PrintUnformatted(plain);
    if (text == NULL) {
        return NULL;
    }

    if (encrypt_bytes(conn->session_keys.send_key,
                      (unsigned char *)text,
                      strlen(text),
                      nonce,
                      ct,
                      &ct_len) != P2P_OK) {
        cJSON_free(text);
        return NULL;
    }

    if (base64_encode(nonce, sizeof(nonce), nonce_b64, sizeof(nonce_b64)) != P2P_OK) {
        cJSON_free(text);
        return NULL;
    }

    if (base64_encode(ct, ct_len, ct_b64, sizeof(ct_b64)) != P2P_OK) {
        cJSON_free(text);
        return NULL;
    }

    enc = build_encrypted_payload(nonce_b64, ct_b64);

    cJSON_free(text);
    return enc;
}

cJSON *connection_decrypt_payload(PeerConnection *conn, cJSON *msg) {
    const char *nonce_b64;
    const char *ct_b64;
    unsigned char nonce[P2P_NONCE_BYTES];
    unsigned char ct[8192];
    unsigned char pt[8192];
    size_t nonce_len = 0;
    size_t ct_len = 0;
    size_t pt_len = 0;

    if (conn == NULL || msg == NULL || !conn->handshake_complete) {
        return NULL;
    }

    nonce_b64 = msg_get_enc_nonce(msg);
    ct_b64 = msg_get_enc_ct(msg);

    if (nonce_b64 == NULL || ct_b64 == NULL) {
        return NULL;
    }

    if (base64_decode(nonce_b64, nonce, sizeof(nonce), &nonce_len) != P2P_OK) {
        return NULL;
    }

    if (nonce_len != P2P_NONCE_BYTES) {
        return NULL;
    }

    if (base64_decode(ct_b64, ct, sizeof(ct), &ct_len) != P2P_OK) {
        return NULL;
    }

    if (decrypt_bytes(conn->session_keys.recv_key,
                      nonce,
                      ct,
                      ct_len,
                      pt,
                      &pt_len) != P2P_OK) {
        return NULL;
    }

    if (pt_len >= sizeof(pt)) {
        return NULL;
    }

    pt[pt_len] = '\0';

    return cJSON_Parse((char *)pt);
}

/* =========================
   encrypted messaging
   ========================= */

int connection_send_encrypted(PeerConnection *conn, const char *type, cJSON *payload) {
    cJSON *enc;
    int r;

    if (conn == NULL || type == NULL || payload == NULL || !conn->handshake_complete) {
        return P2P_ERR;
    }

    enc = connection_build_encrypted_payload(conn, payload);
    if (enc == NULL) {
        return P2P_ERR;
    }

    r = send_json_message(conn->sockfd, type, conn->local_username, enc);
    cJSON_Delete(enc);

    return r;
}

cJSON *connection_recv_encrypted(PeerConnection *conn, char *type_buf, size_t size) {
    cJSON *msg;
    cJSON *payload;
    const char *type;

    if (conn == NULL || type_buf == NULL || size == 0 || !conn->handshake_complete) {
        return NULL;
    }

    msg = recv_json_message(conn->sockfd);
    if (msg == NULL) {
        return NULL;
    }

    type = msg_get_type(msg);
    if (type == NULL) {
        cJSON_Delete(msg);
        return NULL;
    }

    strncpy(type_buf, type, size - 1);
    type_buf[size - 1] = '\0';

    payload = connection_decrypt_payload(conn, msg);
    cJSON_Delete(msg);

    if (payload == NULL) {
        return NULL;
    }

    return payload;
}