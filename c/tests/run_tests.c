#include <stdio.h>

int test_crypto(void);
int test_protocol(void);
int test_connection(void);

int main(void) {
    int fails = 0;

    printf("Running tests...\n");

    if (test_crypto()) fails++;
    if (test_protocol()) fails++;
    if (test_connection()) fails++;

    if (fails == 0) {
        printf("ALL TESTS PASSED\n");
    } else {
        printf("%d TEST SUITE(S) FAILED\n", fails);
    }

    return fails;
}