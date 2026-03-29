#include "../../include/storage/storage.h"

#include <dirent.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int is_dot_entry(const char *name) {
    return (!name || strcmp(name, ".") == 0 || strcmp(name, "..") == 0);
}

static int join_path(const char *dir, const char *name, char *out, size_t out_size) {
    int written = snprintf(out, out_size, "%s/%s", dir, name);
    return (written < 0 || (size_t)written >= out_size) ? P2P_ERR : P2P_OK;
}

static int read_file_bytes(const char *path, unsigned char **out, size_t *len) {
    FILE *fp = fopen(path, "rb");
    unsigned char *buf;
    long size;

    if (!fp) return P2P_ERR;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return P2P_ERR;
    }

    size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        return P2P_ERR;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return P2P_ERR;
    }

    buf = (unsigned char *)malloc((size_t)size);
    if (!buf && size > 0) {
        fclose(fp);
        return P2P_ERR;
    }

    if (size > 0 && fread(buf, 1, (size_t)size, fp) != (size_t)size) {
        fclose(fp);
        free(buf);
        return P2P_ERR;
    }

    fclose(fp);

    *out = buf;
    *len = (size_t)size;
    return P2P_OK;
}

int storage_compute_sha256_hex(const unsigned char *data, size_t len, char out_hex[P2P_SHA256_HEX_LEN + 1]) {
    unsigned char hash[crypto_hash_sha256_BYTES];
    int i;

    crypto_hash_sha256(hash, data, len);

    for (i = 0; i < 32; i++) {
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

int storage_list_shared_files(StoredFile *files, size_t max_files, size_t *out_count) {
    DIR *dir = opendir(P2P_SHARED_DIR);
    struct dirent *entry;
    size_t count = 0;

    if (!dir) return P2P_ERR;

    while ((entry = readdir(dir))) {
        FILE *fp;

        if (is_dot_entry(entry->d_name)) continue;
        if (count >= max_files) break;

        strncpy(files[count].name, entry->d_name, P2P_MAX_FILENAME_LEN - 1);
        files[count].name[P2P_MAX_FILENAME_LEN - 1] = '\0';

        if (join_path(P2P_SHARED_DIR, entry->d_name, files[count].path, sizeof(files[count].path)) != P2P_OK) {
            continue;
        }

        fp = fopen(files[count].path, "rb");
        if (fp) {
            if (fseek(fp, 0, SEEK_END) == 0) {
                files[count].size = (size_t)ftell(fp);
            } else {
                files[count].size = 0;
            }
            fclose(fp);
        } else {
            files[count].size = 0;
        }

        count++;
    }

    closedir(dir);
    *out_count = count;
    return P2P_OK;
}

cJSON *storage_build_shared_files_json(const IdentityKeyPair *identity) {
    StoredFile files[256];
    size_t count = 0;
    cJSON *root;
    cJSON *arr;
    size_t i;

    if (storage_list_shared_files(files, 256, &count) != P2P_OK) {
        return NULL;
    }

    root = cJSON_CreateObject();
    arr = cJSON_CreateArray();

    if (root == NULL || arr == NULL) {
        cJSON_Delete(root);
        cJSON_Delete(arr);
        return NULL;
    }

    for (i = 0; i < count; i++) {
        unsigned char *data;
        size_t len;
        char sha256[65];
        char sig_b64[128];
        cJSON *obj;

        if (read_file_bytes(files[i].path, &data, &len) != P2P_OK) {
            continue;
        }

        storage_compute_sha256_hex(data, len, sha256);
        storage_sign_file_metadata(identity, files[i].name, sha256, sig_b64, sizeof(sig_b64));

        obj = cJSON_CreateObject();
        if (obj != NULL) {
            cJSON_AddStringToObject(obj, "filename", files[i].name);
            cJSON_AddNumberToObject(obj, "size", (double)len);
            cJSON_AddStringToObject(obj, "sha256", sha256);
            cJSON_AddStringToObject(obj, "sig", sig_b64);
            cJSON_AddItemToArray(arr, obj);
        }

        free(data);
    }

    cJSON_AddItemToObject(root, "files", arr);
    return root;
}

void storage_print_shared_files(void) {
    StoredFile files[256];
    size_t count = 0;
    size_t i;

    if (storage_list_shared_files(files, 256, &count) != P2P_OK) {
        printf("failed to read shared files\n");
        return;
    }

    if (count == 0) {
        printf("no shared files\n");
        return;
    }

    for (i = 0; i < count; i++) {
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

int storage_export_received_file(const char *filename,
                                 const char *dest_path,
                                 const char *passphrase) {
    char src[P2P_MAX_PATH_LEN];
    unsigned char *enc = NULL;
    size_t enc_len = 0;
    unsigned char salt[P2P_PASSPHRASE_SALT_BYTES];
    unsigned char nonce[P2P_NONCE_BYTES];
    unsigned char key[P2P_SESSION_KEY_BYTES];
    unsigned char *plaintext = NULL;
    size_t ct_len;
    size_t pt_len = 0;
    FILE *out;

    if (filename == NULL || dest_path == NULL || passphrase == NULL) {
        return P2P_ERR;
    }

    snprintf(src, sizeof(src), "%s/%s", P2P_RECEIVED_DIR, filename);

    if (read_file_bytes(src, &enc, &enc_len) != P2P_OK) {
        return P2P_ERR;
    }

    if (enc_len < P2P_PASSPHRASE_SALT_BYTES + P2P_NONCE_BYTES + P2P_GCM_TAG_BYTES) {
        free(enc);
        return P2P_ERR;
    }

    memcpy(salt, enc, P2P_PASSPHRASE_SALT_BYTES);
    memcpy(nonce, enc + P2P_PASSPHRASE_SALT_BYTES, P2P_NONCE_BYTES);
    ct_len = enc_len - P2P_PASSPHRASE_SALT_BYTES - P2P_NONCE_BYTES;

    if (derive_key_from_passphrase(passphrase, salt, key, 0) != P2P_OK) {
        free(enc);
        return P2P_ERR;
    }

    plaintext = (unsigned char *)malloc(ct_len);
    if (plaintext == NULL && ct_len > 0) {
        sodium_memzero(key, sizeof(key));
        free(enc);
        return P2P_ERR;
    }

    if (decrypt_bytes(key,
                      nonce,
                      enc + P2P_PASSPHRASE_SALT_BYTES + P2P_NONCE_BYTES,
                      ct_len,
                      plaintext,
                      &pt_len) != P2P_OK) {
        sodium_memzero(key, sizeof(key));
        free(enc);
        free(plaintext);
        return P2P_ERR;
    }

    out = fopen(dest_path, "wb");
    if (!out) {
        sodium_memzero(key, sizeof(key));
        free(enc);
        free(plaintext);
        return P2P_ERR;
    }

    if (pt_len > 0 && fwrite(plaintext, 1, pt_len, out) != pt_len) {
        fclose(out);
        sodium_memzero(key, sizeof(key));
        free(enc);
        free(plaintext);
        return P2P_ERR;
    }

    fclose(out);

    sodium_memzero(key, sizeof(key));
    free(enc);
    free(plaintext);

    return P2P_OK;
}

int storage_add_shared_file(const char *src_path, char *out_name, size_t out_size) {
    const char *base = strrchr(src_path, '/');
    char dest[P2P_MAX_PATH_LEN];
    FILE *in;
    FILE *out;
    char buf[4096];
    size_t n;

    base = base ? base + 1 : src_path;

    strncpy(out_name, base, out_size - 1);
    out_name[out_size - 1] = '\0';

    snprintf(dest, sizeof(dest), "%s/%s", P2P_SHARED_DIR, out_name);

    in = fopen(src_path, "rb");
    out = fopen(dest, "wb");

    if (!in || !out) {
        if (in) fclose(in);
        if (out) fclose(out);
        return P2P_ERR;
    }

    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            fclose(in);
            fclose(out);
            return P2P_ERR;
        }
    }

    fclose(in);
    fclose(out);

    return P2P_OK;
}

int storage_save_received_file(const char *filename,
                               const unsigned char *data,
                               size_t len,
                               const char *passphrase) {
    char path[P2P_MAX_PATH_LEN];
    unsigned char salt[P2P_PASSPHRASE_SALT_BYTES];
    unsigned char key[P2P_SESSION_KEY_BYTES];
    unsigned char nonce[P2P_NONCE_BYTES];
    unsigned char *ciphertext = NULL;
    size_t ct_len = 0;
    FILE *fp;

    if (!filename || !data || !passphrase) return P2P_ERR;

    snprintf(path, sizeof(path), "%s/%s", P2P_RECEIVED_DIR, filename);

    if (derive_key_from_passphrase(passphrase, salt, key, 1) != P2P_OK) {
        return P2P_ERR;
    }

    ciphertext = (unsigned char *)malloc(len + P2P_GCM_TAG_BYTES);
    if (ciphertext == NULL && len > 0) {
        sodium_memzero(key, sizeof(key));
        return P2P_ERR;
    }

    if (encrypt_bytes(key, data, len, nonce, ciphertext, &ct_len) != P2P_OK) {
        sodium_memzero(key, sizeof(key));
        free(ciphertext);
        return P2P_ERR;
    }

    fp = fopen(path, "wb");
    if (!fp) {
        sodium_memzero(key, sizeof(key));
        free(ciphertext);
        return P2P_ERR;
    }

    if (fwrite(salt, 1, P2P_PASSPHRASE_SALT_BYTES, fp) != P2P_PASSPHRASE_SALT_BYTES ||
        fwrite(nonce, 1, P2P_NONCE_BYTES, fp) != P2P_NONCE_BYTES ||
        fwrite(ciphertext, 1, ct_len, fp) != ct_len) {
        fclose(fp);
        sodium_memzero(key, sizeof(key));
        free(ciphertext);
        return P2P_ERR;
    }

    fclose(fp);
    sodium_memzero(key, sizeof(key));
    free(ciphertext);

    return P2P_OK;
}

int storage_find_shared_file(const char *filename, char *out_path, size_t out_size) {
    FILE *fp;

    snprintf(out_path, out_size, "%s/%s", P2P_SHARED_DIR, filename);

    fp = fopen(out_path, "rb");
    if (!fp) return P2P_ERR;

    fclose(fp);
    return P2P_OK;
}