#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stdio.h>

#define ASSERT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            printf("[FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            return 1; \
        } \
    } while (0)

#define ASSERT_EQ(a, b) \
    do { \
        if ((a) != (b)) { \
            printf("[FAIL] %s:%d: %s != %s\n", __FILE__, __LINE__, #a, #b); \
            return 1; \
        } \
    } while (0)

#define ASSERT_STR_EQ(a, b) \
    do { \
        if (test_str_eq((a), (b)) == 0) { \
            printf("[FAIL] %s:%d: strings differ: \"%s\" != \"%s\"\n", __FILE__, __LINE__, (a), (b)); \
            return 1; \
        } \
    } while (0)

#define TEST_PASS() \
    do { \
        return 0; \
    } while (0)

void test_print_start(const char *name);
void test_print_pass(const char *name);
int test_str_eq(const char *a, const char *b);

#endif