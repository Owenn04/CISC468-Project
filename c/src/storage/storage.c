#include "../../include/storage/storage.h"

#include <dirent.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* =========================
   helpers
   ========================= */

static int is_dot_entry(const char *name) {
    return (!name || strcmp(name, ".") == 0 || strcmp(name, "..") == 0);
}

static int join_path(const char *dir, const char *name, char *out, size_t out_size) {
    int written = snprintf(out, out_size, "%s/%s", dir, name);
    return (written < 0 || (size_t)written >= out_size) ? P2P_ERR : P2P_OK;
}

static int read_file_bytes(const char *path, unsigned char **out, size_t *len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return P2P_ERR;

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char *buf = malloc(size);
    if (!buf) {
        fclose(fp);
        return P2P_ERR;
    }

    fread(buf, 1, size, fp);
    fclose(fp);

    *out = buf;
    *len = size;
    return P2P_OK;
}

/* =========================
   hashing + signing
   ========================= */

int storage_compute_sha256_hex(const unsigned char *data, size_t len, char out_hex[P2P_SHA256_HEX_LEN + 1]) {
    unsigned char hash[crypto_hash_sha256_BYTES];

    crypto_hash_sha256(hash, data, len);

    for (int i = 0; i < 32; i++) {
        sprintf(out_hex + (i * 2), "%02x", hash[i]);
    }

    out_hex[64] = '\0';
    return P2P_OK;
}

int storage_sign_file_metadata(
    const IdentityKeyPair *identity,
    const char *filename,
    const char *sha256_hex,
    char *sig_b64,
    size_t sig_b64_size
) {
    unsigned char sig[crypto_sign_BYTES];
    unsigned long long sig_len;

    char meta[512];
    snprintf(meta, sizeof(meta), "%s|%s", filename, sha256_hex);

    crypto_sign_detached(sig, &sig_len,
        (unsigned char *)meta,
        strlen(meta),
        identity->priv
    );

    return base64_encode(sig, sig_len, sig_b64, sig_b64_size);
}

/* =========================
   listing
   ========================= */

int storage_list_shared_files(StoredFile *files, size_t max_files, size_t *out_count) {
    DIR *dir = opendir(P2P_SHARED_DIR);
    if (!dir) return P2P_ERR;

    struct dirent *entry;
    size_t count = 0;

    while ((entry = readdir(dir))) {
        if (is_dot_entry(entry->d_name)) continue;
        if (count >= max_files) break;

        strncpy(files[count].name, entry->d_name, P2P_MAX_FILENAME_LEN - 1);

        join_path(P2P_SHARED_DIR, entry->d_name, files[count].path, sizeof(files[count].path));

        FILE *fp = fopen(files[count].path, "rb");
        if (fp) {
            fseek(fp, 0, SEEK_END);
            files[count].size = ftell(fp);
            fclose(fp);
        }

        count++;
    }

    closedir(dir);
    *out_count = count;
    return P2P_OK;
}

/* =========================
   JSON builder (CRITICAL)
   ========================= */

cJSON *storage_build_shared_files_json(const IdentityKeyPair *identity) {
    StoredFile files[256];
    size_t count = 0;

    if (storage_list_shared_files(files, 256, &count) != P2P_OK) {
        return NULL;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON *arr = cJSON_CreateArray();

    for (size_t i = 0; i < count; i++) {
        unsigned char *data;
        size_t len;

        if (read_file_bytes(files[i].path, &data, &len) != P2P_OK) {
            continue;
        }

        char sha256[65];
        storage_compute_sha256_hex(data, len, sha256);

        char sig_b64[128];
        storage_sign_file_metadata(identity, files[i].name, sha256, sig_b64, sizeof(sig_b64));

        cJSON *obj = cJSON_CreateObject();

        cJSON_AddStringToObject(obj, "filename", files[i].name);
        cJSON_AddNumberToObject(obj, "size", (double)len);
        cJSON_AddStringToObject(obj, "sha256", sha256);
        cJSON_AddStringToObject(obj, "sig", sig_b64);

        cJSON_AddItemToArray(arr, obj);

        free(data);
    }

    cJSON_AddItemToObject(root, "files", arr);
    return root;
}

void storage_print_shared_files(void) {
    StoredFile files[256];
    size_t count = 0;

    if (storage_list_shared_files(files, 256, &count) != P2P_OK) {
        printf("failed to read shared files\n");
        return;
    }

    if (count == 0) {
        printf("no shared files\n");
        return;
    }

    for (size_t i = 0; i < count; i++) {
        printf("%s\n", files[i].name);
    }
}

void storage_print_received_files(void) {
    DIR *dir = opendir(P2P_RECEIVED_DIR);
    struct dirent *entry;
    int found = 0;

    if (!dir) {
        printf("failed to read received files\n");
        return;
    }

    while ((entry = readdir(dir))) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        printf("%s\n", entry->d_name);
        found = 1;
    }

    closedir(dir);

    if (!found) {
        printf("no received files\n");
    }
}

int storage_export_received_file(const char *filename, const char *dest_path) {
    char src[P2P_MAX_PATH_LEN];

    snprintf(src, sizeof(src), "%s/%s", P2P_RECEIVED_DIR, filename);

    FILE *in = fopen(src, "rb");
    FILE *out = fopen(dest_path, "wb");

    if (!in || !out) return P2P_ERR;

    char buf[4096];
    size_t n;

    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        fwrite(buf, 1, n, out);
    }

    fclose(in);
    fclose(out);

    return P2P_OK;
}

int storage_add_shared_file(const char *src_path, char *out_name, size_t out_size) {
    const char *base = strrchr(src_path, '/');
    base = base ? base + 1 : src_path;

    strncpy(out_name, base, out_size - 1);

    char dest[P2P_MAX_PATH_LEN];
    snprintf(dest, sizeof(dest), "%s/%s", P2P_SHARED_DIR, out_name);

    FILE *in = fopen(src_path, "rb");
    FILE *out = fopen(dest, "wb");

    if (!in || !out) return P2P_ERR;

    char buf[4096];
    size_t n;

    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        fwrite(buf, 1, n, out);
    }

    fclose(in);
    fclose(out);

    return P2P_OK;
}

int storage_save_received_file(const char *filename, const unsigned char *data, size_t len) {
    char path[P2P_MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s", P2P_RECEIVED_DIR, filename);

    FILE *fp = fopen(path, "wb");
    if (!fp) return P2P_ERR;

    fwrite(data, 1, len, fp);
    fclose(fp);

    return P2P_OK;
}

int storage_find_shared_file(const char *filename, char *out_path, size_t out_size) {
    snprintf(out_path, out_size, "%s/%s", P2P_SHARED_DIR, filename);

    FILE *fp = fopen(out_path, "rb");
    if (!fp) return P2P_ERR;

    fclose(fp);
    return P2P_OK;
}