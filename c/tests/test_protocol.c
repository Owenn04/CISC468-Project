#include "../include/network/protocol.h"
#include "test_utils.h"

#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

static int test_protocol_builders(void) {
    cJSON *payload = build_list_request_payload();
    ASSERT_TRUE(payload != NULL);
    cJSON_Delete(payload);

    payload = build_file_request_payload("notes.txt");
    ASSERT_TRUE(payload != NULL);
    ASSERT_STR_EQ(payload_get_string(payload, "filename"), "notes.txt");
    cJSON_Delete(payload);

    TEST_PASS();
}

static int test_protocol_framing(void) {
    int fds[2];
    cJSON *payload = NULL;
    cJSON *msg = NULL;
    cJSON *recv_payload = NULL;

    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    payload = cJSON_CreateObject();
    ASSERT_TRUE(payload != NULL);
    ASSERT_TRUE(cJSON_AddStringToObject(payload, "filename", "notes.txt") != NULL);

    ASSERT_EQ(send_json_message(fds[0], MSG_FILE_REQUEST, "alice", payload), P2P_OK);
    cJSON_Delete(payload);

    msg = recv_json_message(fds[1]);
    ASSERT_TRUE(msg != NULL);

    ASSERT_STR_EQ(msg_get_type(msg), MSG_FILE_REQUEST);
    ASSERT_STR_EQ(msg_get_sender(msg), "alice");

    recv_payload = msg_get_payload(msg);
    ASSERT_TRUE(recv_payload != NULL);
    ASSERT_STR_EQ(payload_get_string(recv_payload, "filename"), "notes.txt");

    cJSON_Delete(msg);
    close(fds[0]);
    close(fds[1]);

    TEST_PASS();
}

int test_protocol(void) {
    test_print_start("test_protocol_builders");
    ASSERT_EQ(test_protocol_builders(), 0);
    test_print_pass("test_protocol_builders");

    test_print_start("test_protocol_framing");
    ASSERT_EQ(test_protocol_framing(), 0);
    test_print_pass("test_protocol_framing");

    TEST_PASS();
}