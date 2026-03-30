#ifndef SERVER_H
#define SERVER_H

#include "../common.h"
#include "../crypto/crypto.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

// server state for incoming peer connections
typedef struct {
    int listen_fd;
    uint16_t port;
    bool running;

    char local_username[P2P_MAX_USERNAME_LEN];
    IdentityKeyPair local_identity;
    char storage_passphrase[256];

    pthread_t thread;
} PeerServer;

// initialize server state
void server_init(PeerServer *server, const char *local_username, uint16_t port);

// set local identity used for handshakes
int server_set_identity(PeerServer *server, const IdentityKeyPair *identity);

// set passphrase used to encrypt received files at rest
int server_set_passphrase(PeerServer *server, const char *passphrase);

// ensure storage directories exist
int server_init_storage(PeerServer *server);

// start background listener thread
int server_start(PeerServer *server);

// stop listener and clean up
void server_stop(PeerServer *server);

#endif