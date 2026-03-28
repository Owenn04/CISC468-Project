#ifndef DISCOVERY_H
#define DISCOVERY_H

#include "../common.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#define P2P_MAX_PEERS 64

typedef struct {
    char username[P2P_MAX_USERNAME_LEN];
    char host[P2P_MAX_HOST_LEN];
    uint16_t port;
    bool in_use;
} DiscoveredPeer;

typedef struct {
    char local_username[P2P_MAX_USERNAME_LEN];
    uint16_t local_port;
    bool running;

    pthread_t thread;
    pthread_mutex_t lock;

    DiscoveredPeer peers[P2P_MAX_PEERS];

    // avahi runtime objects
    void *simple_poll;
    void *client;
    void *group;
    void *browser;
} PeerDiscovery;

void discovery_init(PeerDiscovery *discovery, const char *local_username, uint16_t local_port);
int discovery_start(PeerDiscovery *discovery);
void discovery_stop(PeerDiscovery *discovery);

int discovery_add_peer(PeerDiscovery *discovery, const char *username, const char *host, uint16_t port);
void discovery_remove_peer(PeerDiscovery *discovery, const char *username);
int discovery_get_peer(PeerDiscovery *discovery, const char *username, PeerInfo *out_peer);
void discovery_print_peers(PeerDiscovery *discovery);

#endif