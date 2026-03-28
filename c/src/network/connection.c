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
        fprintf(stderr, "[debug] connection_handle_hello: missing sender or payload\n");
        return P2P_ERR;
    }

    strncpy(conn->remote_username, sender, P2P_MAX_USERNAME_LEN - 1);
    conn->remote_username[P2P_MAX_USERNAME_LEN - 1] = '\0';

    pub = payload_get_string(payload, "identity_pub");
    if (pub == NULL) {
        fprintf(stderr, "[debug] connection_handle_hello: missing identity_pub\n");
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
        fprintf(stderr, "[debug] connection_handle_key_exchange: missing payload\n");
        return P2P_ERR;
    }

    pub = payload_get_string(payload, "ephemeral_pub");
    if (pub == NULL) {
        fprintf(stderr, "[debug] connection_handle_key_exchange: missing ephemeral_pub\n");
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
        fprintf(stderr, "[debug] connection_derive_session: compute_shared_secret failed\n");
        return P2P_ERR;
    }

    if (conn->is_initiator) {
        if (derive_session_key(conn->session_keys.shared_secret,
                               "initiator-to-responder",
                               conn->session_keys.send_key) != P2P_OK) {
            fprintf(stderr, "[debug] connection_derive_session: initiator send derive failed\n");
            return P2P_ERR;
        }

        if (derive_session_key(conn->session_keys.shared_secret,
                               "responder-to-initiator",
                               conn->session_keys.recv_key) != P2P_OK) {
            fprintf(stderr, "[debug] connection_derive_session: initiator recv derive failed\n");
            return P2P_ERR;
        }

        fprintf(stderr, "[debug] derived initiator send/recv session keys for %s\n",
                conn->remote_username[0] ? conn->remote_username : "(unknown)");
    } else {
        if (derive_session_key(conn->session_keys.shared_secret,
                               "responder-to-initiator",
                               conn->session_keys.send_key) != P2P_OK) {
            fprintf(stderr, "[debug] connection_derive_session: responder send derive failed\n");
            return P2P_ERR;
        }

        if (derive_session_key(conn->session_keys.shared_secret,
                               "initiator-to-responder",
                               conn->session_keys.recv_key) != P2P_OK) {
            fprintf(stderr, "[debug] connection_derive_session: responder recv derive failed\n");
            return P2P_ERR;
        }

        fprintf(stderr, "[debug] derived responder send/recv session keys for %s\n",
                conn->remote_username[0] ? conn->remote_username : "(unknown)");
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
        fprintf(stderr, "[debug] handshake initiator: send hello failed\n");
        return P2P_ERR;
    }

    msg = recv_json_message(conn->sockfd);
    if (msg == NULL) {
        fprintf(stderr, "[debug] handshake initiator: recv hello_ack failed\n");
        return P2P_ERR;
    }

    type = msg_get_type(msg);
    if (type == NULL || strcmp(type, MSG_HELLO_ACK) != 0) {
        fprintf(stderr, "[debug] handshake initiator: expected HELLO_ACK, got %s\n",
                type ? type : "(null)");
        cJSON_Delete(msg);
        return P2P_ERR;
    }

    if (connection_handle_hello_ack(conn, msg) != P2P_OK) {
        fprintf(stderr, "[debug] handshake initiator: handle hello_ack failed\n");
        cJSON_Delete(msg);
        return P2P_ERR;
    }
    cJSON_Delete(msg);
    msg = NULL;

    if (connection_send_key_exchange(conn) != P2P_OK) {
        fprintf(stderr, "[debug] handshake initiator: send key_exchange failed\n");
        return P2P_ERR;
    }

    msg = recv_json_message(conn->sockfd);
    if (msg == NULL) {
        fprintf(stderr, "[debug] handshake initiator: recv key_exchange_ack failed\n");
        return P2P_ERR;
    }

    type = msg_get_type(msg);
    if (type == NULL || strcmp(type, MSG_KEY_EXCHANGE_ACK) != 0) {
        fprintf(stderr, "[debug] handshake initiator: expected KEY_EXCHANGE_ACK, got %s\n",
                type ? type : "(null)");
        cJSON_Delete(msg);
        return P2P_ERR;
    }

    if (connection_handle_key_exchange_ack(conn, msg) != P2P_OK) {
        fprintf(stderr, "[debug] handshake initiator: handle key_exchange_ack failed\n");
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
        fprintf(stderr, "[debug] handshake responder: recv hello failed\n");
        return P2P_ERR;
    }

    type = msg_get_type(msg);
    if (type == NULL || strcmp(type, MSG_HELLO) != 0) {
        fprintf(stderr, "[debug] handshake responder: expected HELLO, got %s\n",
                type ? type : "(null)");
        cJSON_Delete(msg);
        return P2P_ERR;
    }

    if (connection_handle_hello(conn, msg) != P2P_OK) {
        fprintf(stderr, "[debug] handshake responder: handle hello failed\n");
        cJSON_Delete(msg);
        return P2P_ERR;
    }
    cJSON_Delete(msg);
    msg = NULL;

    if (connection_send_hello_ack(conn) != P2P_OK) {
        fprintf(stderr, "[debug] handshake responder: send hello_ack failed\n");
        return P2P_ERR;
    }

    msg = recv_json_message(conn->sockfd);
    if (msg == NULL) {
        fprintf(stderr, "[debug] handshake responder: recv key_exchange failed\n");
        return P2P_ERR;
    }

    type = msg_get_type(msg);
    if (type == NULL || strcmp(type, MSG_KEY_EXCHANGE) != 0) {
        fprintf(stderr, "[debug] handshake responder: expected KEY_EXCHANGE, got %s\n",
                type ? type : "(null)");
        cJSON_Delete(msg);
        return P2P_ERR;
    }

    if (connection_handle_key_exchange(conn, msg) != P2P_OK) {
        fprintf(stderr, "[debug] handshake responder: handle key_exchange failed\n");
        cJSON_Delete(msg);
        return P2P_ERR;
    }
    cJSON_Delete(msg);

    if (connection_send_key_exchange_ack(conn) != P2P_OK) {
        fprintf(stderr, "[debug] handshake responder: send key_exchange_ack failed\n");
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
        fprintf(stderr, "[debug] connection_build_encrypted_payload: invalid state\n");
        return NULL;
    }

    text = cJSON_PrintUnformatted(plain);
    if (text == NULL) {
        fprintf(stderr, "[debug] connection_build_encrypted_payload: json print failed\n");
        return NULL;
    }

    if (encrypt_bytes(conn->session_keys.send_key,
                      (unsigned char *)text,
                      strlen(text),
                      nonce,
                      ct,
                      &ct_len) != P2P_OK) {
        fprintf(stderr, "[debug] connection_build_encrypted_payload: encrypt_bytes failed\n");
        cJSON_free(text);
        return NULL;
    }

    if (base64_encode(nonce, sizeof(nonce), nonce_b64, sizeof(nonce_b64)) != P2P_OK) {
        fprintf(stderr, "[debug] connection_build_encrypted_payload: nonce base64 failed\n");
        cJSON_free(text);
        return NULL;
    }

    if (base64_encode(ct, ct_len, ct_b64, sizeof(ct_b64)) != P2P_OK) {
        fprintf(stderr, "[debug] connection_build_encrypted_payload: ct base64 failed\n");
        cJSON_free(text);
        return NULL;
    }

    enc = build_encrypted_payload(nonce_b64, ct_b64);
    if (enc == NULL) {
        fprintf(stderr, "[debug] connection_build_encrypted_payload: build_encrypted_payload failed\n");
    } else {
        fprintf(stderr, "[debug] encrypted outgoing payload for type send on socket %d\n", conn->sockfd);
    }

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
        fprintf(stderr, "[debug] connection_decrypt_payload: invalid state\n");
        return NULL;
    }

    nonce_b64 = msg_get_enc_nonce(msg);
    ct_b64 = msg_get_enc_ct(msg);

    if (nonce_b64 == NULL || ct_b64 == NULL) {
        fprintf(stderr, "[debug] connection_decrypt_payload: missing nonce or ct\n");
        return NULL;
    }

    if (base64_decode(nonce_b64, nonce, sizeof(nonce), &nonce_len) != P2P_OK) {
        fprintf(stderr, "[debug] connection_decrypt_payload: nonce base64 decode failed\n");
        return NULL;
    }

    if (nonce_len != P2P_NONCE_BYTES) {
        fprintf(stderr, "[debug] connection_decrypt_payload: bad nonce length %zu\n", nonce_len);
        return NULL;
    }

    if (base64_decode(ct_b64, ct, sizeof(ct), &ct_len) != P2P_OK) {
        fprintf(stderr, "[debug] connection_decrypt_payload: ct base64 decode failed\n");
        return NULL;
    }

    if (decrypt_bytes(conn->session_keys.recv_key,
                      nonce,
                      ct,
                      ct_len,
                      pt,
                      &pt_len) != P2P_OK) {
        fprintf(stderr, "[debug] connection_decrypt_payload: decrypt_bytes failed for %s\n",
                conn->remote_username[0] ? conn->remote_username : "(unknown)");
        return NULL;
    }

    if (pt_len >= sizeof(pt)) {
        fprintf(stderr, "[debug] connection_decrypt_payload: plaintext too large %zu\n", pt_len);
        return NULL;
    }

    pt[pt_len] = '\0';

    fprintf(stderr, "[debug] decrypted incoming payload from %s\n",
            conn->remote_username[0] ? conn->remote_username : "(unknown)");

    return cJSON_Parse((char *)pt);
}

/* =========================
   encrypted messaging
   ========================= */

int connection_send_encrypted(PeerConnection *conn, const char *type, cJSON *payload) {
    cJSON *enc;
    int r;

    if (conn == NULL || type == NULL || payload == NULL || !conn->handshake_complete) {
        fprintf(stderr, "[debug] connection_send_encrypted: invalid state\n");
        return P2P_ERR;
    }

    enc = connection_build_encrypted_payload(conn, payload);
    if (enc == NULL) {
        fprintf(stderr, "[debug] connection_send_encrypted: failed to build encrypted payload for %s\n", type);
        return P2P_ERR;
    }

    r = send_json_message(conn->sockfd, type, conn->local_username, enc);
    cJSON_Delete(enc);

    if (r != P2P_OK) {
        fprintf(stderr, "[debug] connection_send_encrypted: send_json_message failed for %s\n", type);
    } else {
        fprintf(stderr, "[debug] sent encrypted message type %s\n", type);
    }

    return r;
}

cJSON *connection_recv_encrypted(PeerConnection *conn, char *type_buf, size_t size) {
    cJSON *msg;
    cJSON *payload;
    const char *type;

    if (conn == NULL || type_buf == NULL || size == 0 || !conn->handshake_complete) {
        fprintf(stderr, "[debug] connection_recv_encrypted: invalid state\n");
        return NULL;
    }

    msg = recv_json_message(conn->sockfd);
    if (msg == NULL) {
        fprintf(stderr, "[debug] connection_recv_encrypted: recv_json_message failed or socket closed\n");
        return NULL;
    }

    type = msg_get_type(msg);
    if (type == NULL) {
        fprintf(stderr, "[debug] connection_recv_encrypted: missing type\n");
        cJSON_Delete(msg);
        return NULL;
    }

    strncpy(type_buf, type, size - 1);
    type_buf[size - 1] = '\0';

    fprintf(stderr, "[debug] received encrypted message envelope type %s\n", type_buf);

    payload = connection_decrypt_payload(conn, msg);
    cJSON_Delete(msg);

    if (payload == NULL) {
        fprintf(stderr, "[debug] connection_recv_encrypted: decrypt failed for type %s\n", type_buf);
        return NULL;
    }

    return payload;
}