#include "test_utils.h"

#include <string.h>

void test_print_start(const char *name) {
    if (name != NULL) {
        printf("%s...\n", name);
    }
}

void test_print_pass(const char *name) {
    if (name != NULL) {
        printf("[PASS] %s\n", name);
    }
}

int test_str_eq(const char *a, const char *b) {
    if (a == NULL || b == NULL) {
        return 0;
    }

    return strcmp(a, b) == 0;
}