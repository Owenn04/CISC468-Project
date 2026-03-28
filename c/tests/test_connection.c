#include "../include/network/connection.h"
#include "../include/crypto/crypto.h"
#include "../include/network/protocol.h"
#include "test_utils.h"

#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

static void *responder_thread(void *arg) {
    PeerConnection *conn = (PeerConnection *)arg;
    connection_handshake_responder(conn);
    return NULL;
}

static int setup_handshaked_pair(PeerConnection *a, PeerConnection *b) {
    int fds[2];
    IdentityKeyPair id_a, id_b;
    pthread_t t;

    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    ASSERT_EQ(generate_identity_keypair(&id_a), P2P_OK);
    ASSERT_EQ(generate_identity_keypair(&id_b), P2P_OK);

    connection_init(a, fds[0], "alice", true);
    connection_init(b, fds[1], "bob", false);

    ASSERT_EQ(connection_set_identity(a, &id_a), P2P_OK);
    ASSERT_EQ(connection_set_identity(b, &id_b), P2P_OK);

    ASSERT_EQ(pthread_create(&t, NULL, responder_thread, b), 0);
    ASSERT_EQ(connection_handshake_initiator(a), P2P_OK);
    ASSERT_EQ(pthread_join(t, NULL), 0);

    ASSERT_TRUE(a->handshake_complete);
    ASSERT_TRUE(b->handshake_complete);

    TEST_PASS();
}

static int test_handshake_basic(void) {
    PeerConnection a, b;

    ASSERT_EQ(setup_handshaked_pair(&a, &b), 0);

    connection_cleanup(&a);
    connection_cleanup(&b);

    TEST_PASS();
}

static int test_handshake_key_agreement(void) {
    PeerConnection a, b;

    ASSERT_EQ(setup_handshaked_pair(&a, &b), 0);

    ASSERT_TRUE(memcmp(a.session_keys.send_key,
                       b.session_keys.recv_key,
                       sizeof(a.session_keys.send_key)) == 0);

    ASSERT_TRUE(memcmp(a.session_keys.recv_key,
                       b.session_keys.send_key,
                       sizeof(a.session_keys.recv_key)) == 0);

    connection_cleanup(&a);
    connection_cleanup(&b);

    TEST_PASS();
}

static int test_encrypted_round_trip(void) {
    PeerConnection a, b;
    cJSON *payload = NULL;
    cJSON *recv_payload = NULL;
    char type[64];

    ASSERT_EQ(setup_handshaked_pair(&a, &b), 0);

    payload = cJSON_CreateObject();
    ASSERT_TRUE(payload != NULL);
    ASSERT_TRUE(cJSON_AddStringToObject(payload, "filename", "notes.txt") != NULL);
    ASSERT_TRUE(cJSON_AddStringToObject(payload, "sha256", "abc123") != NULL);

    ASSERT_EQ(connection_send_encrypted(&a, MSG_FILE_REQUEST, payload), P2P_OK);
    cJSON_Delete(payload);

    recv_payload = connection_recv_encrypted(&b, type, sizeof(type));
    ASSERT_TRUE(recv_payload != NULL);

    ASSERT_STR_EQ(type, MSG_FILE_REQUEST);
    ASSERT_STR_EQ(payload_get_string(recv_payload, "filename"), "notes.txt");
    ASSERT_STR_EQ(payload_get_string(recv_payload, "sha256"), "abc123");

    cJSON_Delete(recv_payload);
    connection_cleanup(&a);
    connection_cleanup(&b);

    TEST_PASS();
}

int test_connection(void) {
    test_print_start("test_handshake_basic");
    ASSERT_EQ(test_handshake_basic(), 0);
    test_print_pass("test_handshake_basic");

    test_print_start("test_handshake_key_agreement");
    ASSERT_EQ(test_handshake_key_agreement(), 0);
    test_print_pass("test_handshake_key_agreement");

    test_print_start("test_encrypted_round_trip");
    ASSERT_EQ(test_encrypted_round_trip(), 0);
    test_print_pass("test_encrypted_round_trip");

    TEST_PASS();
}