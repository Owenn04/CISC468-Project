#include "../../include/network/protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* =========================
   low-level io
   ========================= */

int send_all(int sockfd, const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char *)buf;
    size_t total_sent = 0;

    while (total_sent < len) {
        ssize_t sent = send(sockfd, p + total_sent, len - total_sent, 0);
        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }
            return P2P_ERR;
        }
        if (sent == 0) {
            return P2P_ERR;
        }
        total_sent += (size_t)sent;
    }

    return P2P_OK;
}

int recv_all(int sockfd, void *buf, size_t len) {
    unsigned char *p = (unsigned char *)buf;
    size_t total_read = 0;

    while (total_read < len) {
        ssize_t received = recv(sockfd, p + total_read, len - total_read, 0);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            return P2P_ERR;
        }
        if (received == 0) {
            return P2P_ERR;
        }
        total_read += (size_t)received;
    }

    return P2P_OK;
}

/* =========================
   framed json
   ========================= */

int send_json_message(int sockfd, const char *msg_type, const char *sender, cJSON *payload) {
    if (msg_type == NULL || sender == NULL || payload == NULL) {
        return P2P_ERR;
    }

    int result = P2P_ERR;
    cJSON *root = NULL;
    cJSON *payload_copy = NULL;
    char *json_str = NULL;
    uint32_t body_len;
    uint32_t net_len;

    root = cJSON_CreateObject();
    if (root == NULL) {
        goto cleanup;
    }

    if (cJSON_AddStringToObject(root, "type", msg_type) == NULL) {
        goto cleanup;
    }
    if (cJSON_AddStringToObject(root, "sender", sender) == NULL) {
        goto cleanup;
    }

    payload_copy = cJSON_Duplicate(payload, 1);
    if (payload_copy == NULL) {
        goto cleanup;
    }
    if (!cJSON_AddItemToObject(root, "payload", payload_copy)) {
        cJSON_Delete(payload_copy);
        payload_copy = NULL;
        goto cleanup;
    }

    json_str = cJSON_PrintUnformatted(root);
    if (json_str == NULL) {
        goto cleanup;
    }

    body_len = (uint32_t)strlen(json_str);
    if (body_len == 0 || body_len > PROTOCOL_MAX_MESSAGE_SIZE) {
        goto cleanup;
    }

    net_len = htonl(body_len);
    if (send_all(sockfd, &net_len, sizeof(net_len)) != P2P_OK) {
        goto cleanup;
    }
    if (send_all(sockfd, json_str, body_len) != P2P_OK) {
        goto cleanup;
    }

    result = P2P_OK;

cleanup:
    if (json_str != NULL) {
        cJSON_free(json_str);
    }
    if (root != NULL) {
        cJSON_Delete(root);
    }
    return result;
}

cJSON *recv_json_message(int sockfd) {
    uint32_t net_len = 0;
    uint32_t body_len;
    char *body;
    cJSON *msg;

    if (recv_all(sockfd, &net_len, sizeof(net_len)) != P2P_OK) {
        return NULL;
    }

    body_len = ntohl(net_len);
    if (body_len == 0 || body_len > PROTOCOL_MAX_MESSAGE_SIZE) {
        return NULL;
    }

    body = (char *)malloc(body_len + 1);
    if (body == NULL) {
        return NULL;
    }

    if (recv_all(sockfd, body, body_len) != P2P_OK) {
        free(body);
        return NULL;
    }

    body[body_len] = '\0';
    msg = cJSON_Parse(body);
    free(body);
    return msg;
}

/* =========================
   message accessors
   ========================= */

const char *msg_get_type(cJSON *msg) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(msg, "type");
    if (!cJSON_IsString(item) || item->valuestring == NULL) {
        return NULL;
    }
    return item->valuestring;
}

const char *msg_get_sender(cJSON *msg) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(msg, "sender");
    if (!cJSON_IsString(item) || item->valuestring == NULL) {
        return NULL;
    }
    return item->valuestring;
}

cJSON *msg_get_payload(cJSON *msg) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(msg, "payload");
    if (!cJSON_IsObject(item)) {
        return NULL;
    }
    return item;
}

/* =========================
   encrypted wrapper
   ========================= */

cJSON *build_encrypted_payload(const char *nonce_b64, const char *ct_b64) {
    cJSON *payload = NULL;
    cJSON *enc = NULL;

    if (nonce_b64 == NULL || ct_b64 == NULL) {
        return NULL;
    }

    payload = cJSON_CreateObject();
    enc = cJSON_CreateObject();
    if (payload == NULL || enc == NULL) {
        goto fail;
    }

    if (cJSON_AddStringToObject(enc, "nonce", nonce_b64) == NULL) {
        goto fail;
    }
    if (cJSON_AddStringToObject(enc, "ct", ct_b64) == NULL) {
        goto fail;
    }
    if (!cJSON_AddItemToObject(payload, "enc", enc)) {
        goto fail;
    }

    return payload;

fail:
    if (enc != NULL && enc->string == NULL) {
        cJSON_Delete(enc);
    }
    if (payload != NULL) {
        cJSON_Delete(payload);
    }
    return NULL;
}

cJSON *msg_get_enc(cJSON *msg) {
    cJSON *payload = msg_get_payload(msg);
    cJSON *enc;

    if (payload == NULL) {
        return NULL;
    }

    enc = cJSON_GetObjectItemCaseSensitive(payload, "enc");
    if (!cJSON_IsObject(enc)) {
        return NULL;
    }
    return enc;
}

const char *msg_get_enc_nonce(cJSON *msg) {
    cJSON *enc = msg_get_enc(msg);
    cJSON *item;

    if (enc == NULL) {
        return NULL;
    }

    item = cJSON_GetObjectItemCaseSensitive(enc, "nonce");
    if (!cJSON_IsString(item) || item->valuestring == NULL) {
        return NULL;
    }
    return item->valuestring;
}

const char *msg_get_enc_ct(cJSON *msg) {
    cJSON *enc = msg_get_enc(msg);
    cJSON *item;

    if (enc == NULL) {
        return NULL;
    }

    item = cJSON_GetObjectItemCaseSensitive(enc, "ct");
    if (!cJSON_IsString(item) || item->valuestring == NULL) {
        return NULL;
    }
    return item->valuestring;
}

/* =========================
   payload builders
   ========================= */

static cJSON *build_single_string_payload(const char *key, const char *value) {
    cJSON *p;

    if (key == NULL || value == NULL) {
        return NULL;
    }

    p = cJSON_CreateObject();
    if (p == NULL) {
        return NULL;
    }

    if (cJSON_AddStringToObject(p, key, value) == NULL) {
        cJSON_Delete(p);
        return NULL;
    }

    return p;
}

cJSON *build_hello_payload(const char *identity_pub_b64) {
    return build_single_string_payload("identity_pub", identity_pub_b64);
}

cJSON *build_hello_ack_payload(const char *identity_pub_b64) {
    return build_single_string_payload("identity_pub", identity_pub_b64);
}

cJSON *build_key_exchange_payload(const char *ephemeral_pub_b64) {
    return build_single_string_payload("ephemeral_pub", ephemeral_pub_b64);
}

cJSON *build_key_exchange_ack_payload(const char *ephemeral_pub_b64) {
    return build_single_string_payload("ephemeral_pub", ephemeral_pub_b64);
}

cJSON *build_list_request_payload(void) {
    return cJSON_CreateObject();
}

cJSON *build_list_response_payload(cJSON *files_array) {
    cJSON *p;
    cJSON *copy;

    if (files_array == NULL || !cJSON_IsArray(files_array)) {
        return NULL;
    }

    p = cJSON_CreateObject();
    if (p == NULL) {
        return NULL;
    }

    copy = cJSON_Duplicate(files_array, 1);
    if (copy == NULL) {
        cJSON_Delete(p);
        return NULL;
    }

    if (!cJSON_AddItemToObject(p, "files", copy)) {
        cJSON_Delete(copy);
        cJSON_Delete(p);
        return NULL;
    }

    return p;
}

cJSON *build_file_request_payload(const char *filename) {
    return build_single_string_payload("filename", filename);
}

cJSON *build_file_transfer_payload(const char *filename,
                                   const char *nonce_b64,
                                   const char *ct_b64,
                                   const char *sha256_hex,
                                   const char *sig_b64) {
    cJSON *p;

    if (filename == NULL || nonce_b64 == NULL || ct_b64 == NULL ||
        sha256_hex == NULL || sig_b64 == NULL) {
        return NULL;
    }

    p = cJSON_CreateObject();
    if (p == NULL) {
        return NULL;
    }

    if (cJSON_AddStringToObject(p, "filename", filename) == NULL ||
        cJSON_AddStringToObject(p, "nonce", nonce_b64) == NULL ||
        cJSON_AddStringToObject(p, "ct", ct_b64) == NULL ||
        cJSON_AddStringToObject(p, "sha256", sha256_hex) == NULL ||
        cJSON_AddStringToObject(p, "sig", sig_b64) == NULL) {
        cJSON_Delete(p);
        return NULL;
    }

    return p;
}

cJSON *build_consent_request_payload(const char *filename,
                                     const char *sha256_hex,
                                     const char *sig_b64) {
    cJSON *p;

    if (filename == NULL || sha256_hex == NULL || sig_b64 == NULL) {
        return NULL;
    }

    p = cJSON_CreateObject();
    if (p == NULL) {
        return NULL;
    }

    if (cJSON_AddStringToObject(p, "filename", filename) == NULL ||
        cJSON_AddStringToObject(p, "sha256", sha256_hex) == NULL ||
        cJSON_AddStringToObject(p, "sig", sig_b64) == NULL) {
        cJSON_Delete(p);
        return NULL;
    }

    return p;
}

cJSON *build_consent_response_payload(int accepted, const char *message) {
    cJSON *p = cJSON_CreateObject();

    if (p == NULL) {
        return NULL;
    }

    if (cJSON_AddBoolToObject(p, "accepted", accepted ? 1 : 0) == NULL) {
        cJSON_Delete(p);
        return NULL;
    }

    if (message != NULL && cJSON_AddStringToObject(p, "message", message) == NULL) {
        cJSON_Delete(p);
        return NULL;
    }

    return p;
}

cJSON *build_key_rotation_payload(const char *new_identity_pub_b64, const char *rotation_sig_b64) {
    cJSON *p;

    if (new_identity_pub_b64 == NULL || rotation_sig_b64 == NULL) {
        return NULL;
    }

    p = cJSON_CreateObject();
    if (p == NULL) {
        return NULL;
    }

    if (cJSON_AddStringToObject(p, "new_pub", new_identity_pub_b64) == NULL ||
        cJSON_AddStringToObject(p, "sig", rotation_sig_b64) == NULL) {
        cJSON_Delete(p);
        return NULL;
    }

    return p;
}

cJSON *build_verify_request_payload(void) {
    return cJSON_CreateObject();
}

cJSON *build_verify_response_payload(const char *identity_pub_b64) {
    return build_single_string_payload("identity_pub", identity_pub_b64);
}

cJSON *build_error_payload(const char *message) {
    return build_single_string_payload("message", message);
}

/* =========================
   payload extractors
   ========================= */

const char *payload_get_string(cJSON *payload, const char *key) {
    cJSON *item;

    if (payload == NULL || key == NULL) {
        return NULL;
    }

    item = cJSON_GetObjectItemCaseSensitive(payload, key);
    if (!cJSON_IsString(item) || item->valuestring == NULL) {
        return NULL;
    }

    return item->valuestring;
}

cJSON *payload_get_array(cJSON *payload, const char *key) {
    cJSON *item;

    if (payload == NULL || key == NULL) {
        return NULL;
    }

    item = cJSON_GetObjectItemCaseSensitive(payload, key);
    if (!cJSON_IsArray(item)) {
        return NULL;
    }

    return item;
}

int payload_get_bool(cJSON *payload, const char *key, int default_value) {
    cJSON *item;

    if (payload == NULL || key == NULL) {
        return default_value;
    }

    item = cJSON_GetObjectItemCaseSensitive(payload, key);
    if (cJSON_IsBool(item)) {
        return cJSON_IsTrue(item) ? 1 : 0;
    }

    return default_value;
}