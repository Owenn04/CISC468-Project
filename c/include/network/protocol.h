#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "../common.h"
#include <cjson/cJSON.h>

#define PROTOCOL_MAX_MESSAGE_SIZE (256U * 1024U * 1024U)

// app message types
#define MSG_VERIFY_REQUEST   "VERIFY_REQUEST"
#define MSG_VERIFY_RESPONSE  "VERIFY_RESPONSE"
#define MSG_LIST_REQUEST     "LIST_REQUEST"
#define MSG_LIST_RESPONSE    "LIST_RESPONSE"
#define MSG_FILE_REQUEST     "FILE_REQUEST"
#define MSG_FILE_TRANSFER    "FILE_TRANSFER"
#define MSG_ERROR            "ERROR"
#define MSG_KEY_ROTATION     "KEY_ROTATION"

// send full buffer over socket
int send_all(int sockfd, const void *buf, size_t len);

// receive exact number of bytes
int recv_all(int sockfd, void *buf, size_t len);

// build and send framed json message
int send_json_message(int sockfd, const char *msg_type, const char *sender, cJSON *payload);

// receive framed json message
cJSON *recv_json_message(int sockfd);

// extract fields from message
const char *msg_get_type(cJSON *msg);
const char *msg_get_sender(cJSON *msg);
cJSON *msg_get_payload(cJSON *msg);

// generic encrypted wrapper helpers
cJSON *build_encrypted_payload(const char *nonce_b64, const char *ct_b64);
cJSON *msg_get_enc(cJSON *msg);
const char *msg_get_enc_nonce(cJSON *msg);
const char *msg_get_enc_ct(cJSON *msg);

// payload builders for handshake
cJSON *build_hello_payload(const char *identity_pub_b64);
cJSON *build_hello_ack_payload(const char *identity_pub_b64);
cJSON *build_key_exchange_payload(const char *ephemeral_pub_b64);
cJSON *build_key_exchange_ack_payload(const char *ephemeral_pub_b64);

// payload builders for app messages
cJSON *build_list_request_payload(void);
cJSON *build_list_response_payload(cJSON *files_array);
cJSON *build_file_request_payload(const char *filename);
cJSON *build_file_transfer_payload(const char *filename,
                                   const char *nonce_b64,
                                   const char *ct_b64,
                                   const char *sha256_hex,
                                   const char *sig_b64);
cJSON *build_consent_request_payload(
    const char *filename,
    const char *sha256_hex,
    const char *sig_b64
);
cJSON *build_consent_response_payload(int accepted, const char *message);
cJSON *build_key_rotation_payload(const char *new_identity_pub_b64, const char *rotation_sig_b64);

// verify
cJSON *build_verify_request_payload(void);
cJSON *build_verify_response_payload(const char *identity_pub_b64);

cJSON *build_error_payload(const char *message);

// common payload extractors
const char *payload_get_string(cJSON *payload, const char *key);
cJSON *payload_get_array(cJSON *payload, const char *key);
int payload_get_bool(cJSON *payload, const char *key, int default_value);

#endif