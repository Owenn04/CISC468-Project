#include "../include/common.h"
#include "../include/crypto/crypto.h"
#include "../include/network/connection.h"
#include "../include/network/discovery.h"
#include "../include/network/protocol.h"
#include "../include/network/server.h"
#include "../include/storage/storage.h"

#include <pthread.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void print_help(void) {
    printf("available commands:\n");
    printf("  /help                     show this help message\n");
    printf("  /peers                    list discovered peers\n");
    printf("  /list <peer>              list files shared by a peer\n");
    printf("  /get <peer> <file>        download a file from a peer\n");
    printf("  /send <peer> <file>       send a file to a peer\n");
    printf("  /shared                   list local shared files\n");
    printf("  /received                 list received files\n");
    printf("  /export <file> <path>     export a received file\n");
    printf("  /share <path>             add a file to shared files\n");
    printf("  /verify <peer>            verify a peer identity key\n");
    printf("  /rotate                   rotate identity key\n");
    printf("  /quit                     exit the client\n");
}

static int ensure_dir(const char *path) {
    struct stat st;

    if (path == NULL) {
        return P2P_ERR;
    }

    if (stat(path, &st) == 0) {
        return S_ISDIR(st.st_mode) ? P2P_OK : P2P_ERR;
    }

    if (mkdir(path, 0700) != 0) {
        return P2P_ERR;
    }

    return P2P_OK;
}

static int ensure_data_dirs(void) {
    if (ensure_dir("data") != P2P_OK) {
        return P2P_ERR;
    }

    if (ensure_dir("data/keys") != P2P_OK) {
        return P2P_ERR;
    }

    if (ensure_dir("data/contacts") != P2P_OK) {
        return P2P_ERR;
    }

    if (ensure_dir(P2P_SHARED_DIR) != P2P_OK) {
        return P2P_ERR;
    }

    if (ensure_dir(P2P_RECEIVED_DIR) != P2P_OK) {
        return P2P_ERR;
    }

    return P2P_OK;
}

static void format_fingerprint_from_b64(const char *pub_b64, char *out, size_t out_size) {
    unsigned char pub[P2P_ED25519_PUBKEY_BYTES];
    unsigned char hash[crypto_hash_sha256_BYTES];
    size_t pub_len = 0;
    size_t i;
    size_t pos = 0;

    if (out == NULL || out_size == 0) {
        return;
    }

    out[0] = '\0';

    if (pub_b64 == NULL) {
        snprintf(out, out_size, "invalid");
        return;
    }

    if (base64_decode(pub_b64, pub, sizeof(pub), &pub_len) != P2P_OK || pub_len != sizeof(pub)) {
        snprintf(out, out_size, "invalid");
        return;
    }

    crypto_hash_sha256(hash, pub, sizeof(pub));

    for (i = 0; i < 16 && pos + 3 < out_size; i++) {
        if (i > 0 && (i % 2) == 0) {
            out[pos++] = ':';
        }

        snprintf(out + pos, out_size - pos, "%02x", hash[i]);
        pos += 2;
    }

    if (pos < out_size) {
        out[pos] = '\0';
    } else {
        out[out_size - 1] = '\0';
    }
}

static int load_or_create_identity(const char *username, IdentityKeyPair *identity) {
    char pub_path[P2P_MAX_PATH_LEN];
    char priv_path[P2P_MAX_PATH_LEN];
    char pub_b64[128];
    char fingerprint[128];

    if (username == NULL || identity == NULL) {
        return P2P_ERR;
    }

    snprintf(pub_path, sizeof(pub_path), "data/keys/%s.pub", username);
    snprintf(priv_path, sizeof(priv_path), "data/keys/%s.key", username);

    if (load_identity_keypair(pub_path, priv_path, identity) == P2P_OK) {
        if (identity_pubkey_to_base64(identity, pub_b64, sizeof(pub_b64)) == P2P_OK) {
            format_fingerprint_from_b64(pub_b64, fingerprint, sizeof(fingerprint));
            printf("loaded identity for %s\n", username);
            printf("fingerprint: %s\n", fingerprint);
        }
        return P2P_OK;
    }

    if (generate_identity_keypair(identity) != P2P_OK) {
        return P2P_ERR;
    }

    if (save_identity_keypair(pub_path, priv_path, identity) != P2P_OK) {
        return P2P_ERR;
    }

    if (identity_pubkey_to_base64(identity, pub_b64, sizeof(pub_b64)) == P2P_OK) {
        format_fingerprint_from_b64(pub_b64, fingerprint, sizeof(fingerprint));
        printf("generated new identity for %s\n", username);
        printf("fingerprint: %s\n", fingerprint);
    }

    return P2P_OK;
}

static int is_blank_line(const char *line) {
    size_t i;

    if (line == NULL) {
        return 1;
    }

    for (i = 0; line[i] != '\0'; i++) {
        if (line[i] != ' ' && line[i] != '\t' && line[i] != '\n' && line[i] != '\r') {
            return 0;
        }
    }

    return 1;
}

static void trim_newline(char *line) {
    size_t len;

    if (line == NULL) {
        return;
    }

    len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[len - 1] = '\0';
        len--;
    }
}

static int split_command(char *line, char **parts, int max_parts) {
    int count = 0;
    char *token = NULL;

    if (line == NULL || parts == NULL || max_parts <= 0) {
        return 0;
    }

    token = strtok(line, " \t");
    while (token != NULL && count < max_parts) {
        parts[count++] = token;
        token = strtok(NULL, " \t");
    }

    return count;
}

static int contact_exists(const char *peer_name) {
    char path[P2P_MAX_PATH_LEN];

    if (peer_name == NULL) {
        return 0;
    }

    snprintf(path, sizeof(path), "data/contacts/%s.pub", peer_name);
    return access(path, F_OK) == 0;
}

static int save_contact_key(const char *peer_name, const char *identity_pub_b64) {
    char path[P2P_MAX_PATH_LEN];
    FILE *fp = NULL;

    if (peer_name == NULL || identity_pub_b64 == NULL) {
        return P2P_ERR;
    }

    snprintf(path, sizeof(path), "data/contacts/%s.pub", peer_name);

    fp = fopen(path, "w");
    if (fp == NULL) {
        return P2P_ERR;
    }

    fprintf(fp, "%s\n", identity_pub_b64);
    fclose(fp);

    return P2P_OK;
}

static int connect_to_peer(PeerDiscovery *discovery,
                           const char *peer_name,
                           PeerConnection *conn,
                           const char *username,
                           IdentityKeyPair *identity) {
    PeerInfo peer_info;
    int fd;
    char remote_pub_b64[128];
    char fingerprint[128];

    if (discovery == NULL || peer_name == NULL || conn == NULL || username == NULL || identity == NULL) {
        return P2P_ERR;
    }

    memset(&peer_info, 0, sizeof(peer_info));

    if (discovery_get_peer(discovery, peer_name, &peer_info) != P2P_OK) {
        printf("peer not found: %s\n", peer_name);
        return P2P_ERR;
    }

    fd = connection_connect_to_host(peer_info.host, peer_info.port);
    if (fd < 0) {
        printf("failed to connect to %s\n", peer_name);
        return P2P_ERR;
    }

    connection_init(conn, fd, username, true);

    if (connection_set_identity(conn, identity) != P2P_OK) {
        connection_cleanup(conn);
        return P2P_ERR;
    }

    if (connection_handshake_initiator(conn) != P2P_OK) {
        printf("handshake failed with %s\n", peer_name);
        connection_cleanup(conn);
        return P2P_ERR;
    }

    if (base64_encode(conn->remote_identity_pub,
                      P2P_ED25519_PUBKEY_BYTES,
                      remote_pub_b64,
                      sizeof(remote_pub_b64)) == P2P_OK &&
        !contact_exists(peer_name)) {
        format_fingerprint_from_b64(remote_pub_b64, fingerprint, sizeof(fingerprint));
        printf("new peer: %s\n", peer_name);
        printf("fingerprint: %s\n", fingerprint);
        printf("verify it out of band with /verify %s\n", peer_name);
    }

    printf("secure session with %s\n", peer_name);

    return P2P_OK;
}

static void cmd_list(PeerDiscovery *discovery,
                     const char *peer_name,
                     const char *username,
                     IdentityKeyPair *identity) {
    PeerConnection conn;
    cJSON *req = NULL;
    cJSON *resp = NULL;
    cJSON *files = NULL;
    cJSON *item = NULL;
    char msg_type[64];

    if (connect_to_peer(discovery, peer_name, &conn, username, identity) != P2P_OK) {
        return;
    }

    req = build_list_request_payload();
    if (req == NULL) {
        printf("failed to build request\n");
        connection_cleanup(&conn);
        return;
    }

    if (connection_send_encrypted(&conn, MSG_LIST_REQUEST, req) != P2P_OK) {
        printf("failed to send list request\n");
        cJSON_Delete(req);
        connection_cleanup(&conn);
        return;
    }

    cJSON_Delete(req);

    resp = connection_recv_encrypted(&conn, msg_type, sizeof(msg_type));
    if (resp == NULL) {
        printf("failed to receive response\n");
        connection_cleanup(&conn);
        return;
    }

    if (strcmp(msg_type, MSG_LIST_RESPONSE) != 0) {
        printf("unexpected response: %s\n", msg_type);
        cJSON_Delete(resp);
        connection_cleanup(&conn);
        return;
    }

    files = payload_get_array(resp, "files");
    if (files == NULL) {
        printf("invalid list response\n");
        cJSON_Delete(resp);
        connection_cleanup(&conn);
        return;
    }

    if (cJSON_GetArraySize(files) == 0) {
        printf("shared files: none\n");
        cJSON_Delete(resp);
        connection_cleanup(&conn);
        return;
    }

    printf("shared files:\n");
    cJSON_ArrayForEach(item, files) {
        const char *filename = payload_get_string(item, "filename");
        cJSON *size_item = cJSON_GetObjectItemCaseSensitive(item, "size");

        if (filename != NULL) {
            if (cJSON_IsNumber(size_item)) {
                printf("  %s (%lld bytes)\n", filename, (long long)size_item->valuedouble);
            } else {
                printf("  %s\n", filename);
            }
        }
    }

    cJSON_Delete(resp);
    connection_cleanup(&conn);
}

static void cmd_get(PeerDiscovery *discovery,
                    const char *peer_name,
                    const char *filename,
                    const char *username,
                    IdentityKeyPair *identity) {
    PeerConnection conn;
    cJSON *req = NULL;
    cJSON *resp = NULL;
    char msg_type[64];
    const char *recv_filename;
    const char *content_b64;
    unsigned char *data = NULL;
    size_t data_len = 0;

    if (connect_to_peer(discovery, peer_name, &conn, username, identity) != P2P_OK) {
        return;
    }

    req = build_file_request_payload(filename);
    if (req == NULL) {
        printf("failed to build request\n");
        connection_cleanup(&conn);
        return;
    }

    if (connection_send_encrypted(&conn, MSG_FILE_REQUEST, req) != P2P_OK) {
        printf("failed to send file request\n");
        cJSON_Delete(req);
        connection_cleanup(&conn);
        return;
    }

    cJSON_Delete(req);

    resp = connection_recv_encrypted(&conn, msg_type, sizeof(msg_type));
    if (resp == NULL) {
        printf("failed to receive response\n");
        connection_cleanup(&conn);
        return;
    }

    if (strcmp(msg_type, MSG_FILE_TRANSFER) != 0) {
        if (strcmp(msg_type, MSG_ERROR) == 0) {
            const char *message = payload_get_string(resp, "message");
            if (message != NULL) {
                printf("error: %s\n", message);
            } else {
                printf("file request failed\n");
            }
        } else {
            printf("unexpected response: %s\n", msg_type);
        }

        cJSON_Delete(resp);
        connection_cleanup(&conn);
        return;
    }

    recv_filename = payload_get_string(resp, "filename");
    content_b64 = payload_get_string(resp, "content");

    if (recv_filename == NULL || content_b64 == NULL) {
        printf("invalid file transfer response\n");
        cJSON_Delete(resp);
        connection_cleanup(&conn);
        return;
    }

    data = (unsigned char *)malloc(strlen(content_b64));
    if (data == NULL) {
        printf("out of memory\n");
        cJSON_Delete(resp);
        connection_cleanup(&conn);
        return;
    }

    if (base64_decode(content_b64, data, strlen(content_b64), &data_len) != P2P_OK) {
        printf("failed to decode file\n");
        free(data);
        cJSON_Delete(resp);
        connection_cleanup(&conn);
        return;
    }

    if (storage_save_received_file(recv_filename, data, data_len) != P2P_OK) {
        printf("failed to save received file\n");
        free(data);
        cJSON_Delete(resp);
        connection_cleanup(&conn);
        return;
    }

    printf("saved file: %s\n", recv_filename);

    free(data);
    cJSON_Delete(resp);
    connection_cleanup(&conn);
}

static void cmd_verify(PeerDiscovery *discovery,
                       const char *peer_name,
                       const char *username,
                       IdentityKeyPair *identity) {
    PeerConnection conn;
    cJSON *req = NULL;
    cJSON *resp = NULL;
    char msg_type[64];
    const char *identity_pub = NULL;
    char fingerprint[128];
    char confirm[32];

    if (connect_to_peer(discovery, peer_name, &conn, username, identity) != P2P_OK) {
        return;
    }

    req = build_verify_request_payload();
    if (req == NULL) {
        printf("failed to build verify request\n");
        connection_cleanup(&conn);
        return;
    }

    if (connection_send_encrypted(&conn, MSG_VERIFY_REQUEST, req) != P2P_OK) {
        printf("failed to send verify request\n");
        cJSON_Delete(req);
        connection_cleanup(&conn);
        return;
    }

    cJSON_Delete(req);

    resp = connection_recv_encrypted(&conn, msg_type, sizeof(msg_type));
    if (resp == NULL) {
        printf("failed to receive verify response\n");
        connection_cleanup(&conn);
        return;
    }

    if (strcmp(msg_type, MSG_VERIFY_RESPONSE) != 0) {
        if (strcmp(msg_type, MSG_ERROR) == 0) {
            const char *message = payload_get_string(resp, "message");
            if (message != NULL) {
                printf("error: %s\n", message);
            } else {
                printf("verify failed\n");
            }
        } else {
            printf("unexpected response: %s\n", msg_type);
        }

        cJSON_Delete(resp);
        connection_cleanup(&conn);
        return;
    }

    identity_pub = payload_get_string(resp, "identity_pub");
    if (identity_pub == NULL) {
        printf("invalid verify response\n");
        cJSON_Delete(resp);
        connection_cleanup(&conn);
        return;
    }

    format_fingerprint_from_b64(identity_pub, fingerprint, sizeof(fingerprint));
    printf("fingerprint for %s: %s\n", peer_name, fingerprint);
    printf("does this match? [y/N] ");

    if (fgets(confirm, sizeof(confirm), stdin) == NULL) {
        printf("verification cancelled\n");
        cJSON_Delete(resp);
        connection_cleanup(&conn);
        return;
    }

    if (confirm[0] != 'y' && confirm[0] != 'Y') {
        printf("verification cancelled\n");
        cJSON_Delete(resp);
        connection_cleanup(&conn);
        return;
    }

    if (save_contact_key(peer_name, identity_pub) != P2P_OK) {
        printf("failed to save identity\n");
        cJSON_Delete(resp);
        connection_cleanup(&conn);
        return;
    }

    printf("saved verified key for %s\n", peer_name);

    cJSON_Delete(resp);
    connection_cleanup(&conn);
}

static int sign_key_rotation(const IdentityKeyPair *old_identity,
                             const char *username,
                             const char *new_pub_b64,
                             char *sig_b64,
                             size_t sig_b64_size) {
    unsigned char sig[crypto_sign_BYTES];
    unsigned long long sig_len = 0;
    char payload[512];
    int written;

    if (old_identity == NULL || username == NULL || new_pub_b64 == NULL || sig_b64 == NULL) {
        return P2P_ERR;
    }

    written = snprintf(payload, sizeof(payload), "KEY_ROTATION|%s|%s", username, new_pub_b64);
    if (written < 0 || (size_t)written >= sizeof(payload)) {
        return P2P_ERR;
    }

    if (crypto_sign_detached(sig,
                             &sig_len,
                             (const unsigned char *)payload,
                             (unsigned long long)strlen(payload),
                             old_identity->priv) != 0) {
        return P2P_ERR;
    }

    if (base64_encode(sig, (size_t)sig_len, sig_b64, sig_b64_size) != P2P_OK) {
        return P2P_ERR;
    }

    return P2P_OK;
}

static int copy_discovered_peers(PeerDiscovery *discovery, PeerInfo *out_peers, size_t max_peers) {
    size_t i;
    int count = 0;

    if (discovery == NULL || out_peers == NULL || max_peers == 0) {
        return 0;
    }

    pthread_mutex_lock(&discovery->lock);

    for (i = 0; i < P2P_MAX_PEERS && (size_t)count < max_peers; i++) {
        if (!discovery->peers[i].in_use) {
            continue;
        }

        memset(&out_peers[count], 0, sizeof(PeerInfo));
        strncpy(out_peers[count].username, discovery->peers[i].username, P2P_MAX_USERNAME_LEN - 1);
        strncpy(out_peers[count].host, discovery->peers[i].host, P2P_MAX_HOST_LEN - 1);
        out_peers[count].port = discovery->peers[i].port;
        count++;
    }

    pthread_mutex_unlock(&discovery->lock);
    return count;
}

static void cmd_rotate(PeerDiscovery *discovery,
                       PeerServer *server,
                       const char *username,
                       IdentityKeyPair *identity) {
    IdentityKeyPair new_identity;
    PeerInfo peers[P2P_MAX_PEERS];
    char new_pub_b64[128];
    char sig_b64[256];
    char pub_path[P2P_MAX_PATH_LEN];
    char priv_path[P2P_MAX_PATH_LEN];
    char fingerprint[128];
    int peer_count;
    int notified = 0;
    int i;

    if (discovery == NULL || server == NULL || username == NULL || identity == NULL) {
        printf("rotate failed\n");
        return;
    }

    if (generate_identity_keypair(&new_identity) != P2P_OK) {
        printf("failed to generate new identity\n");
        return;
    }

    if (identity_pubkey_to_base64(&new_identity, new_pub_b64, sizeof(new_pub_b64)) != P2P_OK) {
        printf("failed to encode new public key\n");
        sodium_memzero(&new_identity, sizeof(new_identity));
        return;
    }

    if (sign_key_rotation(identity, username, new_pub_b64, sig_b64, sizeof(sig_b64)) != P2P_OK) {
        printf("failed to sign key rotation\n");
        sodium_memzero(&new_identity, sizeof(new_identity));
        return;
    }

    peer_count = copy_discovered_peers(discovery, peers, P2P_MAX_PEERS);

    for (i = 0; i < peer_count; i++) {
        PeerConnection conn;
        cJSON *payload = NULL;

        if (strcmp(peers[i].username, username) == 0) {
            continue;
        }

        if (connect_to_peer(discovery, peers[i].username, &conn, username, identity) != P2P_OK) {
            continue;
        }

        payload = build_key_rotation_payload(new_pub_b64, sig_b64);
        if (payload != NULL) {
            if (connection_send_encrypted(&conn, MSG_KEY_ROTATION, payload) == P2P_OK) {
                notified++;
            }
            cJSON_Delete(payload);
        }

        connection_cleanup(&conn);
    }

    snprintf(pub_path, sizeof(pub_path), "data/keys/%s.pub", username);
    snprintf(priv_path, sizeof(priv_path), "data/keys/%s.key", username);

    if (save_identity_keypair(pub_path, priv_path, &new_identity) != P2P_OK) {
        printf("failed to save new identity\n");
        sodium_memzero(&new_identity, sizeof(new_identity));
        return;
    }

    memcpy(identity, &new_identity, sizeof(IdentityKeyPair));
    server_set_identity(server, identity);

    format_fingerprint_from_b64(new_pub_b64, fingerprint, sizeof(fingerprint));

    printf("rotated identity key\n");
    printf("notified %d peer(s)\n", notified);
    printf("new fingerprint: %s\n", fingerprint);

    sodium_memzero(&new_identity, sizeof(new_identity));
}

int main(int argc, char *argv[]) {
    char input[1024];
    char *parts[4];
    int part_count;

    const char *username;
    uint16_t port;

    IdentityKeyPair identity;
    PeerServer server;
    PeerDiscovery discovery;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <username> <port>\n", argv[0]);
        return 1;
    }

    username = argv[1];
    port = (uint16_t)atoi(argv[2]);

    if (port == 0) {
        fprintf(stderr, "invalid port\n");
        return 1;
    }

    if (ensure_data_dirs() != P2P_OK) {
        fprintf(stderr, "failed to create data directories\n");
        return 1;
    }

    if (load_or_create_identity(username, &identity) != P2P_OK) {
        fprintf(stderr, "failed to load or create identity\n");
        return 1;
    }

    server_init(&server, username, port);
    if (server_set_identity(&server, &identity) != P2P_OK) {
        fprintf(stderr, "failed to set server identity\n");
        return 1;
    }

    if (server_start(&server) != P2P_OK) {
        fprintf(stderr, "failed to start server\n");
        return 1;
    }

    discovery_init(&discovery, username, port);
    if (discovery_start(&discovery) != P2P_OK) {
        fprintf(stderr, "failed to start discovery\n");
        server_stop(&server);
        return 1;
    }

    printf("listening on port %u\n", port);
    printf("ready. type /help for commands.\n");

    while (1) {
        printf("> ");
        fflush(stdout);

        if (fgets(input, sizeof(input), stdin) == NULL) {
            printf("\n");
            break;
        }

        if (is_blank_line(input)) {
            continue;
        }

        trim_newline(input);
        part_count = split_command(input, parts, 4);

        if (part_count == 0) {
            continue;
        }

        if (strcmp(parts[0], "/help") == 0) {
            print_help();
        } else if (strcmp(parts[0], "/peers") == 0) {
            discovery_print_peers(&discovery);
        } else if (strcmp(parts[0], "/list") == 0) {
            if (part_count != 2) {
                printf("usage: /list <peer>\n");
                continue;
            }

            cmd_list(&discovery, parts[1], username, &identity);
        } else if (strcmp(parts[0], "/get") == 0) {
            if (part_count != 3) {
                printf("usage: /get <peer> <file>\n");
                continue;
            }

            cmd_get(&discovery, parts[1], parts[2], username, &identity);
        } else if (strcmp(parts[0], "/send") == 0) {
            if (part_count != 3) {
                printf("usage: /send <peer> <file>\n");
                continue;
            }

            printf("/send not implemented yet for peer %s file %s\n", parts[1], parts[2]);
        } else if (strcmp(parts[0], "/shared") == 0) {
            storage_print_shared_files();
        } else if (strcmp(parts[0], "/received") == 0) {
            storage_print_received_files();
        } else if (strcmp(parts[0], "/export") == 0) {
            if (part_count != 3) {
                printf("usage: /export <file> <path>\n");
                continue;
            }

            if (storage_export_received_file(parts[1], parts[2]) == P2P_OK) {
                printf("exported: %s\n", parts[1]);
            } else {
                printf("failed to export file\n");
            }
        } else if (strcmp(parts[0], "/share") == 0) {
            char out_name[P2P_MAX_FILENAME_LEN];

            if (part_count != 2) {
                printf("usage: /share <path>\n");
                continue;
            }

            if (storage_add_shared_file(parts[1], out_name, sizeof(out_name)) == P2P_OK) {
                printf("shared: %s\n", out_name);
            } else {
                printf("failed to share file\n");
            }
        } else if (strcmp(parts[0], "/verify") == 0) {
            if (part_count != 2) {
                printf("usage: /verify <peer>\n");
                continue;
            }

            cmd_verify(&discovery, parts[1], username, &identity);
        } else if (strcmp(parts[0], "/rotate") == 0) {
            cmd_rotate(&discovery, &server, username, &identity);
        } else if (strcmp(parts[0], "/quit") == 0) {
            break;
        } else {
            printf("unknown command: %s\n", parts[0]);
            printf("type /help for available commands\n");
        }
    }

    discovery_stop(&discovery);
    server_stop(&server);

    return 0;
}