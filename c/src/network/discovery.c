#include "../../include/network/discovery.h"

#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-client/publish.h>
#include <avahi-common/address.h>
#include <avahi-common/error.h>
#include <avahi-common/malloc.h>
#include <avahi-common/simple-watch.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void create_services(PeerDiscovery *discovery);

static int find_peer_index(PeerDiscovery *discovery, const char *username) {
    int i;

    for (i = 0; i < P2P_MAX_PEERS; i++) {
        if (discovery->peers[i].in_use &&
            strcmp(discovery->peers[i].username, username) == 0) {
            return i;
        }
    }

    return -1;
}

static int find_free_peer_slot(PeerDiscovery *discovery) {
    int i;

    for (i = 0; i < P2P_MAX_PEERS; i++) {
        if (!discovery->peers[i].in_use) {
            return i;
        }
    }

    return -1;
}

static void get_local_ip_string(char *out, size_t out_size) {
    int sockfd;
    struct sockaddr_in remote_addr;
    struct sockaddr_in local_addr;
    socklen_t local_len = sizeof(local_addr);

    if (out == NULL || out_size == 0) {
        return;
    }

    snprintf(out, out_size, "127.0.0.1");

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return;
    }

    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(53);

    if (inet_pton(AF_INET, "8.8.8.8", &remote_addr.sin_addr) != 1) {
        close(sockfd);
        return;
    }

    if (connect(sockfd, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) != 0) {
        close(sockfd);
        return;
    }

    if (getsockname(sockfd, (struct sockaddr *)&local_addr, &local_len) == 0) {
        const char *ip = inet_ntop(AF_INET, &local_addr.sin_addr, out, (socklen_t)out_size);
        if (ip == NULL) {
            snprintf(out, out_size, "127.0.0.1");
        }
    }

    close(sockfd);
}

int discovery_add_peer(PeerDiscovery *discovery, const char *username, const char *host, uint16_t port) {
    int index;
    int was_new = 0;

    if (discovery == NULL || username == NULL || host == NULL) {
        return P2P_ERR;
    }

    pthread_mutex_lock(&discovery->lock);

    index = find_peer_index(discovery, username);
    if (index < 0) {
        index = find_free_peer_slot(discovery);
        was_new = 1;
    }

    if (index < 0) {
        pthread_mutex_unlock(&discovery->lock);
        return P2P_ERR;
    }

    strncpy(discovery->peers[index].username, username, P2P_MAX_USERNAME_LEN - 1);
    discovery->peers[index].username[P2P_MAX_USERNAME_LEN - 1] = '\0';

    strncpy(discovery->peers[index].host, host, P2P_MAX_HOST_LEN - 1);
    discovery->peers[index].host[P2P_MAX_HOST_LEN - 1] = '\0';

    discovery->peers[index].port = port;
    discovery->peers[index].in_use = true;

    pthread_mutex_unlock(&discovery->lock);

    if (was_new) {
        printf("found peer: %s at %s:%u\n", username, host, port);
    }

    return P2P_OK;
}

void discovery_remove_peer(PeerDiscovery *discovery, const char *username) {
    int index;

    if (discovery == NULL || username == NULL) {
        return;
    }

    pthread_mutex_lock(&discovery->lock);

    index = find_peer_index(discovery, username);
    if (index >= 0) {
        memset(&discovery->peers[index], 0, sizeof(discovery->peers[index]));
    }

    pthread_mutex_unlock(&discovery->lock);

    if (index >= 0) {
        printf("peer left: %s\n", username);
    }
}

int discovery_get_peer(PeerDiscovery *discovery, const char *username, PeerInfo *out_peer) {
    int index;

    if (discovery == NULL || username == NULL || out_peer == NULL) {
        return P2P_ERR;
    }

    pthread_mutex_lock(&discovery->lock);

    index = find_peer_index(discovery, username);
    if (index < 0) {
        pthread_mutex_unlock(&discovery->lock);
        return P2P_ERR;
    }

    strncpy(out_peer->username, discovery->peers[index].username, P2P_MAX_USERNAME_LEN - 1);
    out_peer->username[P2P_MAX_USERNAME_LEN - 1] = '\0';

    strncpy(out_peer->host, discovery->peers[index].host, P2P_MAX_HOST_LEN - 1);
    out_peer->host[P2P_MAX_HOST_LEN - 1] = '\0';

    out_peer->port = discovery->peers[index].port;

    pthread_mutex_unlock(&discovery->lock);
    return P2P_OK;
}

void discovery_print_peers(PeerDiscovery *discovery) {
    int i;
    int found = 0;

    if (discovery == NULL) {
        return;
    }

    pthread_mutex_lock(&discovery->lock);

    for (i = 0; i < P2P_MAX_PEERS; i++) {
        if (!discovery->peers[i].in_use) {
            continue;
        }

        printf("%s - %s:%u\n",
               discovery->peers[i].username,
               discovery->peers[i].host,
               discovery->peers[i].port);
        found = 1;
    }

    pthread_mutex_unlock(&discovery->lock);

    if (!found) {
        printf("no peers found\n");
    }
}

static void entry_group_callback(AvahiEntryGroup *group,
                                 AvahiEntryGroupState state,
                                 void *userdata) {
    PeerDiscovery *discovery = (PeerDiscovery *)userdata;

    if (group == NULL || discovery == NULL) {
        return;
    }

    if (state == AVAHI_ENTRY_GROUP_COLLISION) {
        fprintf(stderr, "service name collision\n");
        if (discovery->simple_poll != NULL) {
            avahi_simple_poll_quit((AvahiSimplePoll *)discovery->simple_poll);
        }
    } else if (state == AVAHI_ENTRY_GROUP_FAILURE) {
        fprintf(stderr, "entry group failure: %s\n",
                avahi_strerror(avahi_client_errno((AvahiClient *)discovery->client)));
        if (discovery->simple_poll != NULL) {
            avahi_simple_poll_quit((AvahiSimplePoll *)discovery->simple_poll);
        }
    }
}

static void create_services(PeerDiscovery *discovery) {
    AvahiStringList *txt = NULL;
    int ret;

    if (discovery == NULL || discovery->client == NULL) {
        return;
    }

    if (discovery->group == NULL) {
        discovery->group = avahi_entry_group_new(
            (AvahiClient *)discovery->client,
            entry_group_callback,
            discovery
        );

        if (discovery->group == NULL) {
            fprintf(stderr, "failed to create entry group\n");
            avahi_simple_poll_quit((AvahiSimplePoll *)discovery->simple_poll);
            return;
        }
    }

    if (avahi_entry_group_is_empty((AvahiEntryGroup *)discovery->group)) {
        char txt_record[128];

        snprintf(txt_record, sizeof(txt_record), "username=%s", discovery->local_username);
        txt = avahi_string_list_new(txt_record, NULL);

        ret = avahi_entry_group_add_service_strlst(
            (AvahiEntryGroup *)discovery->group,
            AVAHI_IF_UNSPEC,
            AVAHI_PROTO_UNSPEC,
            0,
            discovery->local_username,
            P2P_SERVICE_TYPE,
            NULL,
            NULL,
            discovery->local_port,
            txt
        );

        if (txt != NULL) {
            avahi_string_list_free(txt);
        }

        if (ret < 0) {
            fprintf(stderr, "failed to add service: %s\n", avahi_strerror(ret));
            avahi_simple_poll_quit((AvahiSimplePoll *)discovery->simple_poll);
            return;
        }

        ret = avahi_entry_group_commit((AvahiEntryGroup *)discovery->group);
        if (ret < 0) {
            fprintf(stderr, "failed to commit service: %s\n", avahi_strerror(ret));
            avahi_simple_poll_quit((AvahiSimplePoll *)discovery->simple_poll);
            return;
        }

        {
            char ip[64];
            get_local_ip_string(ip, sizeof(ip));
            printf("advertising as %s on %s:%u\n",
                   discovery->local_username,
                   ip,
                   discovery->local_port);
        }
    }
}

static void resolve_callback(AvahiServiceResolver *resolver,
                             AvahiIfIndex interface,
                             AvahiProtocol protocol,
                             AvahiResolverEvent event,
                             const char *name,
                             const char *type,
                             const char *domain,
                             const char *host_name,
                             const AvahiAddress *address,
                             uint16_t port,
                             AvahiStringList *txt,
                             AvahiLookupResultFlags flags,
                             void *userdata) {
    PeerDiscovery *discovery = (PeerDiscovery *)userdata;
    char addr_buf[AVAHI_ADDRESS_STR_MAX];
    const char *username = name;
    AvahiStringList *item;

    (void)interface;
    (void)protocol;
    (void)type;
    (void)domain;
    (void)host_name;
    (void)flags;

    if (discovery == NULL || resolver == NULL) {
        return;
    }

    if (event == AVAHI_RESOLVER_FAILURE) {
        avahi_service_resolver_free(resolver);
        return;
    }

    avahi_address_snprint(addr_buf, sizeof(addr_buf), address);

    item = avahi_string_list_find(txt, "username");
    if (item != NULL) {
        char *key = NULL;
        char *value = NULL;

        if (avahi_string_list_get_pair(item, &key, &value, NULL) == 0 && value != NULL) {
            username = value;
            discovery_add_peer(discovery, username, addr_buf, port);
        } else {
            discovery_add_peer(discovery, username, addr_buf, port);
        }

        if (key != NULL) {
            avahi_free(key);
        }
        if (value != NULL) {
            avahi_free(value);
        }
    } else {
        discovery_add_peer(discovery, username, addr_buf, port);
    }

    avahi_service_resolver_free(resolver);
}

static void browse_callback(AvahiServiceBrowser *browser,
                            AvahiIfIndex interface,
                            AvahiProtocol protocol,
                            AvahiBrowserEvent event,
                            const char *name,
                            const char *type,
                            const char *domain,
                            AvahiLookupResultFlags flags,
                            void *userdata) {
    PeerDiscovery *discovery = (PeerDiscovery *)userdata;

    (void)browser;
    (void)flags;

    if (discovery == NULL || discovery->client == NULL) {
        return;
    }

    switch (event) {
        case AVAHI_BROWSER_NEW:
            if (strcmp(name, discovery->local_username) != 0) {
                if (avahi_service_resolver_new(
                        (AvahiClient *)discovery->client,
                        interface,
                        protocol,
                        name,
                        type,
                        domain,
                        AVAHI_PROTO_UNSPEC,
                        0,
                        resolve_callback,
                        discovery
                    ) == NULL) {
                    fprintf(stderr, "failed to resolve service: %s\n",
                            avahi_strerror(avahi_client_errno((AvahiClient *)discovery->client)));
                }
            }
            break;

        case AVAHI_BROWSER_REMOVE:
            discovery_remove_peer(discovery, name);
            break;

        case AVAHI_BROWSER_FAILURE:
            fprintf(stderr, "browser failure: %s\n",
                    avahi_strerror(avahi_client_errno((AvahiClient *)discovery->client)));
            if (discovery->simple_poll != NULL) {
                avahi_simple_poll_quit((AvahiSimplePoll *)discovery->simple_poll);
            }
            break;

        default:
            break;
    }
}

static void client_callback(AvahiClient *client,
                            AvahiClientState state,
                            void *userdata) {
    PeerDiscovery *discovery = (PeerDiscovery *)userdata;

    if (discovery == NULL) {
        return;
    }

    discovery->client = client;

    switch (state) {
        case AVAHI_CLIENT_S_RUNNING:
            create_services(discovery);

            if (discovery->browser == NULL) {
                discovery->browser = avahi_service_browser_new(
                    client,
                    AVAHI_IF_UNSPEC,
                    AVAHI_PROTO_UNSPEC,
                    P2P_SERVICE_TYPE,
                    NULL,
                    0,
                    browse_callback,
                    discovery
                );

                if (discovery->browser == NULL) {
                    fprintf(stderr, "failed to create service browser: %s\n",
                            avahi_strerror(avahi_client_errno(client)));
                    avahi_simple_poll_quit((AvahiSimplePoll *)discovery->simple_poll);
                }
            }
            break;

        case AVAHI_CLIENT_FAILURE:
            fprintf(stderr, "client failure: %s\n",
                    avahi_strerror(avahi_client_errno(client)));
            if (discovery->simple_poll != NULL) {
                avahi_simple_poll_quit((AvahiSimplePoll *)discovery->simple_poll);
            }
            break;

        case AVAHI_CLIENT_S_COLLISION:
        case AVAHI_CLIENT_S_REGISTERING:
            if (discovery->group != NULL) {
                avahi_entry_group_reset((AvahiEntryGroup *)discovery->group);
            }
            break;

        default:
            break;
    }
}

static void *discovery_thread_main(void *arg) {
    PeerDiscovery *discovery = (PeerDiscovery *)arg;
    int error;

    discovery->simple_poll = avahi_simple_poll_new();
    if (discovery->simple_poll == NULL) {
        fprintf(stderr, "failed to create avahi poll object\n");
        discovery->running = false;
        return NULL;
    }

    discovery->client = avahi_client_new(
        avahi_simple_poll_get((AvahiSimplePoll *)discovery->simple_poll),
        0,
        client_callback,
        discovery,
        &error
    );

    if (discovery->client == NULL) {
        fprintf(stderr, "failed to create avahi client: %s\n", avahi_strerror(error));
        avahi_simple_poll_free((AvahiSimplePoll *)discovery->simple_poll);
        discovery->simple_poll = NULL;
        discovery->running = false;
        return NULL;
    }

    avahi_simple_poll_loop((AvahiSimplePoll *)discovery->simple_poll);

    if (discovery->browser != NULL) {
        avahi_service_browser_free((AvahiServiceBrowser *)discovery->browser);
        discovery->browser = NULL;
    }

    if (discovery->group != NULL) {
        avahi_entry_group_free((AvahiEntryGroup *)discovery->group);
        discovery->group = NULL;
    }

    if (discovery->client != NULL) {
        avahi_client_free((AvahiClient *)discovery->client);
        discovery->client = NULL;
    }

    if (discovery->simple_poll != NULL) {
        avahi_simple_poll_free((AvahiSimplePoll *)discovery->simple_poll);
        discovery->simple_poll = NULL;
    }

    discovery->running = false;
    return NULL;
}

void discovery_init(PeerDiscovery *discovery, const char *local_username, uint16_t local_port) {
    if (discovery == NULL) {
        return;
    }

    memset(discovery, 0, sizeof(*discovery));
    discovery->local_port = local_port;
    discovery->running = false;

    pthread_mutex_init(&discovery->lock, NULL);

    if (local_username != NULL) {
        strncpy(discovery->local_username, local_username, P2P_MAX_USERNAME_LEN - 1);
        discovery->local_username[P2P_MAX_USERNAME_LEN - 1] = '\0';
    }
}

int discovery_start(PeerDiscovery *discovery) {
    if (discovery == NULL) {
        return P2P_ERR;
    }

    if (discovery->running) {
        return P2P_OK;
    }

    discovery->running = true;

    if (pthread_create(&discovery->thread, NULL, discovery_thread_main, discovery) != 0) {
        discovery->running = false;
        return P2P_ERR;
    }

    return P2P_OK;
}

void discovery_stop(PeerDiscovery *discovery) {
    if (discovery == NULL) {
        return;
    }

    if (discovery->running && discovery->simple_poll != NULL) {
        avahi_simple_poll_quit((AvahiSimplePoll *)discovery->simple_poll);
        pthread_join(discovery->thread, NULL);
    }

    discovery->running = false;
    pthread_mutex_destroy(&discovery->lock);
}