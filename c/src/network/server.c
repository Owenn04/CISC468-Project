#include "../include/network/server.h"
#include "../include/network/connection.h"
#include "../include/network/protocol.h"
#include "../include/storage/storage.h"

#include <arpa/inet.h>
#include <errno.h>
#include <sodium.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int mkdir_if_missing(const char *path) {
    struct stat st;

    if (path == NULL) {
        return P2P_ERR;
    }

    if (stat(path, &st) == 0) {
        return S_ISDIR(st.st_mode) ? P2P_OK : P2P_ERR;
    }

    if (mkdir(path, 0700) == 0) {
        return P2P_OK;
    }

    return (errno == EEXIST) ? P2P_OK : P2P_ERR;
}

static int read_file_bytes(const char *path, unsigned char **out_data, size_t *out_len) {
    FILE *fp = NULL;
    unsigned char *buf = NULL;
    long file_size;

    if (path == NULL || out_data == NULL || out_len == NULL) {
        return P2P_ERR;
    }

    *out_data = NULL;
    *out_len = 0;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return P2P_ERR;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return P2P_ERR;
    }

    file_size = ftell(fp);
    if (file_size < 0) {
        fclose(fp);
        return P2P_ERR;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return P2P_ERR;
    }

    buf = (unsigned char *)malloc((size_t)file_size);
    if (buf == NULL && file_size > 0) {
        fclose(fp);
        return P2P_ERR;
    }

    if (file_size > 0) {
        if (fread(buf, 1, (size_t)file_size, fp) != (size_t)file_size) {
            fclose(fp);
            free(buf);
            return P2P_ERR;
        }
    }

    fclose(fp);

    *out_data = buf;
    *out_len = (size_t)file_size;
    return P2P_OK;
}

static int sha256_hex(const unsigned char *data, size_t len, char out_hex[P2P_SHA256_HEX_LEN + 1]) {
    unsigned char digest[crypto_hash_sha256_BYTES];
    size_t i;

    if (out_hex == NULL) {
        return P2P_ERR;
    }

    crypto_hash_sha256(digest, data, (unsigned long long)len);

    for (i = 0; i < crypto_hash_sha256_BYTES; i++) {
        snprintf(out_hex + (i * 2), 3, "%02x", digest[i]);
    }

    out_hex[P2P_SHA256_HEX_LEN] = '\0';
    return P2P_OK;
}

static int sign_file_metadata(const IdentityKeyPair *identity,
                              const char *filename,
                              const char *sha256_str,
                              char *sig_b64,
                              size_t sig_b64_size) {
    unsigned char sig[crypto_sign_BYTES];
    unsigned long long sig_len = 0;
    char meta[1024];
    int written;

    if (identity == NULL || filename == NULL || sha256_str == NULL || sig_b64 == NULL) {
        return P2P_ERR;
    }

    written = snprintf(meta, sizeof(meta), "%s|%s", filename, sha256_str);
    if (written < 0 || (size_t)written >= sizeof(meta)) {
        return P2P_ERR;
    }

    if (crypto_sign_detached(sig,
                             &sig_len,
                             (const unsigned char *)meta,
                             (unsigned long long)strlen(meta),
                             identity->priv) != 0) {
        return P2P_ERR;
    }

    if (base64_encode(sig, (size_t)sig_len, sig_b64, sig_b64_size) != P2P_OK) {
        return P2P_ERR;
    }

    return P2P_OK;
}

static int handle_key_rotation(PeerConnection *conn, cJSON *payload) {
    const char *new_pub;
    const char *sig_b64;
    char path[P2P_MAX_PATH_LEN];
    char old_pub_b64[128];
    char message[512];
    FILE *fp = NULL;
    unsigned char old_pub[crypto_sign_PUBLICKEYBYTES];
    unsigned char sig[crypto_sign_BYTES];
    size_t old_pub_len = 0;
    size_t sig_len = 0;

    new_pub = payload_get_string(payload, "new_pub");
    sig_b64 = payload_get_string(payload, "sig");

    if (new_pub == NULL || sig_b64 == NULL) {
        return P2P_ERR;
    }

    snprintf(path, sizeof(path), "data/contacts/%s.pub", conn->remote_username);

    fp = fopen(path, "r");
    if (fp == NULL) {
        return P2P_ERR;
    }

    if (fgets(old_pub_b64, sizeof(old_pub_b64), fp) == NULL) {
        fclose(fp);
        return P2P_ERR;
    }
    fclose(fp);

    old_pub_b64[strcspn(old_pub_b64, "\r\n")] = '\0';

    if (base64_decode(old_pub_b64, old_pub, sizeof(old_pub), &old_pub_len) != P2P_OK ||
        old_pub_len != sizeof(old_pub)) {
        return P2P_ERR;
    }

    if (base64_decode(sig_b64, sig, sizeof(sig), &sig_len) != P2P_OK ||
        sig_len != sizeof(sig)) {
        return P2P_ERR;
    }

    snprintf(message, sizeof(message), "KEY_ROTATION|%s|%s", conn->remote_username, new_pub);

    if (crypto_sign_verify_detached(sig,
                                    (const unsigned char *)message,
                                    (unsigned long long)strlen(message),
                                    old_pub) != 0) {
        printf("ignored key update from %s\n", conn->remote_username);
        return P2P_ERR;
    }

    fp = fopen(path, "w");
    if (fp == NULL) {
        return P2P_ERR;
    }

    fprintf(fp, "%s\n", new_pub);
    fclose(fp);

    printf("updated saved key for %s\n", conn->remote_username);
    return P2P_OK;
}

static int create_listener_socket(uint16_t port) {
    int sockfd;
    int opt = 1;
    struct sockaddr_in addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return P2P_ERR;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(sockfd);
        return P2P_ERR;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        return P2P_ERR;
    }

    if (listen(sockfd, 10) < 0) {
        close(sockfd);
        return P2P_ERR;
    }

    return sockfd;
}

static int handle_list_request(PeerServer *server, PeerConnection *conn) {
    cJSON *files_obj = NULL;
    cJSON *files_array = NULL;
    cJSON *payload = NULL;
    int result = P2P_ERR;

    files_obj = storage_build_shared_files_json(&server->local_identity);
    if (files_obj == NULL) {
        return P2P_ERR;
    }

    files_array = cJSON_DetachItemFromObjectCaseSensitive(files_obj, "files");
    if (!cJSON_IsArray(files_array)) {
        goto cleanup;
    }

    payload = build_list_response_payload(files_array);
    files_array = NULL;
    if (payload == NULL) {
        goto cleanup;
    }

    result = connection_send_encrypted(conn, MSG_LIST_RESPONSE, payload);

cleanup:
    if (files_array != NULL) {
        cJSON_Delete(files_array);
    }
    if (payload != NULL) {
        cJSON_Delete(payload);
    }
    if (files_obj != NULL) {
        cJSON_Delete(files_obj);
    }

    return result;
}

static int handle_file_request(PeerConnection *conn, cJSON *payload) {
    const char *filename;
    char full_path[P2P_MAX_PATH_LEN];
    unsigned char *data = NULL;
    size_t len = 0;
    size_t b64_size;
    char *content_b64 = NULL;
    char sha256_str[P2P_SHA256_HEX_LEN + 1];
    char sig_b64[128];
    cJSON *resp = NULL;
    cJSON *err = NULL;
    int result = P2P_ERR;

    filename = payload_get_string(payload, "filename");
    if (filename == NULL) {
        err = build_error_payload("missing filename");
        if (err != NULL) {
            connection_send_encrypted(conn, MSG_ERROR, err);
            cJSON_Delete(err);
        }
        return P2P_ERR;
    }

    if (storage_find_shared_file(filename, full_path, sizeof(full_path)) != P2P_OK) {
        err = build_error_payload("file not found");
        if (err != NULL) {
            connection_send_encrypted(conn, MSG_ERROR, err);
            cJSON_Delete(err);
        }
        return P2P_ERR;
    }

    if (read_file_bytes(full_path, &data, &len) != P2P_OK) {
        err = build_error_payload("failed to read file");
        if (err != NULL) {
            connection_send_encrypted(conn, MSG_ERROR, err);
            cJSON_Delete(err);
        }
        return P2P_ERR;
    }

    unsigned char nonce[P2P_NONCE_BYTES];
    unsigned char ct[8192];
    size_t ct_len = 0;

    char nonce_b64[64];
    char ct_b64[8192];

    if (encrypt_bytes(conn->session_keys.send_key,
                  data,
                  len,
                  nonce,
                  ct,
                  &ct_len) != P2P_OK) {
        goto cleanup;
    }

if (base64_encode(nonce, sizeof(nonce), nonce_b64, sizeof(nonce_b64)) != P2P_OK) {
    goto cleanup;
}

if (base64_encode(ct, ct_len, ct_b64, sizeof(ct_b64)) != P2P_OK) {
    goto cleanup;
}

    if (sha256_hex(data, len, sha256_str) != P2P_OK) {
        goto cleanup;
    }

    if (sign_file_metadata(&conn->local_identity, filename, sha256_str, sig_b64, sizeof(sig_b64)) != P2P_OK) {
        goto cleanup;
    }

    resp = build_file_transfer_payload(filename, nonce_b64, ct_b64, sha256_str, sig_b64);
    if (resp == NULL) {
        goto cleanup;
    }

    result = connection_send_encrypted(conn, MSG_FILE_TRANSFER, resp);

cleanup:
    if (result != P2P_OK) {
        err = build_error_payload("failed to prepare file transfer");
        if (err != NULL) {
            connection_send_encrypted(conn, MSG_ERROR, err);
            cJSON_Delete(err);
        }
    }

    if (resp != NULL) {
        cJSON_Delete(resp);
    }
    if (content_b64 != NULL) {
        free(content_b64);
    }
    if (data != NULL) {
        sodium_memzero(data, len);
        free(data);
    }

    return result;
}

static int handle_verify_request(PeerConnection *conn) {
    char identity_pub_b64[128];
    cJSON *resp = NULL;
    int result = P2P_ERR;

    if (identity_pubkey_to_base64(&conn->local_identity,
                                  identity_pub_b64,
                                  sizeof(identity_pub_b64)) != P2P_OK) {
        return P2P_ERR;
    }

    resp = build_verify_response_payload(identity_pub_b64);
    if (resp == NULL) {
        return P2P_ERR;
    }

    result = connection_send_encrypted(conn, MSG_VERIFY_RESPONSE, resp);
    cJSON_Delete(resp);

    return result;
}

static void connection_loop(PeerServer *server, PeerConnection *conn) {
    char type[64];

    while (1) {
        cJSON *payload = connection_recv_encrypted(conn, type, sizeof(type));
        if (payload == NULL) {
            break;
        }

        if (strcmp(type, MSG_LIST_REQUEST) == 0) {
            handle_list_request(server, conn);
        } else if (strcmp(type, MSG_FILE_REQUEST) == 0) {
            handle_file_request(conn, payload);
        } else if (strcmp(type, MSG_VERIFY_REQUEST) == 0) {
            handle_verify_request(conn);
        } else if (strcmp(type, MSG_KEY_ROTATION) == 0) {
            handle_key_rotation(conn, payload);
        } else {
            cJSON *err = build_error_payload("unknown request");
            if (err != NULL) {
                connection_send_encrypted(conn, MSG_ERROR, err);
                cJSON_Delete(err);
            }
        }

        cJSON_Delete(payload);
    }
}

static void handle_incoming_connection(PeerServer *server, int peer_fd) {
    PeerConnection conn;

    connection_init(&conn, peer_fd, server->local_username, false);
    connection_set_identity(&conn, &server->local_identity);

    if (connection_handshake_responder(&conn) != P2P_OK) {
        fprintf(stderr, "handshake failed\n");
        connection_cleanup(&conn);
        return;
    }

    printf("accepted connection from %s\n", conn.remote_username);

    connection_loop(server, &conn);

    connection_cleanup(&conn);
}

static void *server_thread_main(void *arg) {
    PeerServer *server = (PeerServer *)arg;

    while (server->running) {
        struct sockaddr_in peer_addr;
        socklen_t len = sizeof(peer_addr);
        int fd;

        fd = accept(server->listen_fd, (struct sockaddr *)&peer_addr, &len);
        if (fd < 0) {
            if (server->running) {
                perror("accept");
            }
            continue;
        }

        handle_incoming_connection(server, fd);
    }

    return NULL;
}

void server_init(PeerServer *server, const char *local_username, uint16_t port) {
    if (server == NULL) {
        return;
    }

    memset(server, 0, sizeof(*server));
    server->listen_fd = -1;
    server->port = port;
    server->running = false;

    if (local_username != NULL) {
        strncpy(server->local_username, local_username, P2P_MAX_USERNAME_LEN - 1);
        server->local_username[P2P_MAX_USERNAME_LEN - 1] = '\0';
    }
}

int server_set_identity(PeerServer *server, const IdentityKeyPair *identity) {
    if (server == NULL || identity == NULL) {
        return P2P_ERR;
    }

    memcpy(&server->local_identity, identity, sizeof(IdentityKeyPair));
    return P2P_OK;
}

int server_init_storage(PeerServer *server) {
    (void)server;

    if (mkdir_if_missing("data") != P2P_OK) {
        return P2P_ERR;
    }

    if (mkdir_if_missing(P2P_SHARED_DIR) != P2P_OK) {
        return P2P_ERR;
    }

    if (mkdir_if_missing(P2P_RECEIVED_DIR) != P2P_OK) {
        return P2P_ERR;
    }

    return P2P_OK;
}

int server_start(PeerServer *server) {
    if (server == NULL) {
        return P2P_ERR;
    }

    if (server_init_storage(server) != P2P_OK) {
        return P2P_ERR;
    }

    server->listen_fd = create_listener_socket(server->port);
    if (server->listen_fd < 0) {
        return P2P_ERR;
    }

    server->running = true;

    if (pthread_create(&server->thread, NULL, server_thread_main, server) != 0) {
        close(server->listen_fd);
        server->listen_fd = -1;
        server->running = false;
        return P2P_ERR;
    }

    return P2P_OK;
}

void server_stop(PeerServer *server) {
    if (server == NULL) {
        return;
    }

    if (!server->running) {
        if (server->listen_fd >= 0) {
            close(server->listen_fd);
            server->listen_fd = -1;
        }
        return;
    }

    server->running = false;

    if (server->listen_fd >= 0) {
        close(server->listen_fd);
        server->listen_fd = -1;
    }

    pthread_join(server->thread, NULL);
}