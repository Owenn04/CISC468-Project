#ifndef STORAGE_H
#define STORAGE_H

#include "../common.h"
#include "../crypto/crypto.h"
#include <cjson/cJSON.h>
#include <stddef.h>

#define P2P_SHARED_DIR   "data/shared"
#define P2P_RECEIVED_DIR "data/received"

typedef struct {
    char name[P2P_MAX_FILENAME_LEN];
    char path[P2P_MAX_PATH_LEN];
    size_t size;
} StoredFile;

// list files
int storage_list_shared_files(StoredFile *files, size_t max_files, size_t *out_count);

// print helpers
void storage_print_shared_files(void);
void storage_print_received_files(void);

// python-compatible json (CRITICAL)
cJSON *storage_build_shared_files_json(const IdentityKeyPair *identity);

// file lookup + copy
int storage_find_shared_file(const char *filename, char *out_path, size_t out_path_size);
int storage_add_shared_file(const char *src_path, char *out_name, size_t out_name_size);

// received files
int storage_save_received_file(const char *filename, const unsigned char *data, size_t data_len);
int storage_export_received_file(const char *filename, const char *dest_path);

// hashing + signing
int storage_compute_sha256_hex(const unsigned char *data, size_t len, char out_hex[P2P_SHA256_HEX_LEN + 1]);

int storage_sign_file_metadata(
    const IdentityKeyPair *identity,
    const char *filename,
    const char *sha256_hex,
    char *sig_b64,
    size_t sig_b64_size
);

#endif