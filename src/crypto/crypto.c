#include <gcrypt.h>

#include "crypto.h"
#include "memory_utils.h"

/* Based on: https://github.com/vedantk/gcrypt-example/blob/master/gcry.cc */

#define GCRY_CIPHER GCRY_CIPHER_AES128   /* Pick the cipher here */
#define GCRY_C_MODE GCRY_CIPHER_MODE_ECB /* Pick the cipher mode here */

static gcry_cipher_hd_t gcry_cipher_hd;

void gcrypt_init(void)
{
    gcry_error_t err;

    if (gcry_check_version(GCRYPT_VERSION) == NULL) {
        fprintf(stderr, "gcrypt: library version mismatch");
    }

    err = gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
    err |= gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    err |= gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
    err |= gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "gcrypt: failed initialization");
    }
}

void gcrypt_set_key_and_iv(const char *key, const char *iv)
{
    size_t keylen = gcry_cipher_get_algo_keylen(GCRY_CIPHER),
           blklen = gcry_cipher_get_algo_blklen(GCRY_CIPHER);
    gcry_error_t err;

    err = gcry_cipher_open(&gcry_cipher_hd, GCRY_CIPHER, GCRY_C_MODE, 0);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "gcry_cipher_open failed: %s/%s\n",
                gcry_strsource(err),
                gcry_strerror(err));
        return;
    }

    err = gcry_cipher_setkey(gcry_cipher_hd, key, keylen);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "gcry_cipher_setkey failed: %s/%s\n",
                gcry_strsource(err),
                gcry_strerror(err));
        return;
    }

    err = gcry_cipher_setiv(gcry_cipher_hd, iv, blklen);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "gcry_cipher_setiv failed: %s/%s\n",
                gcry_strsource(err),
                gcry_strerror(err));
    }
}

/* Free out buffer after using! */
char *gcrypt_encrypt_msg(const char *msg, size_t msg_length, int *out_length)
{
    size_t blklen = gcry_cipher_get_algo_blklen(GCRY_CIPHER);
    gcry_error_t err;
    char *out = NULL;

    if ((msg_length & (blklen - 1u)) != 0u) {
        msg_length += blklen - (msg_length & (blklen - 1u));
    }

    out = dawn_malloc(msg_length);
    if (out == NULL) {
        fprintf(stderr, "Failed to allocate memory!\n");
        goto exit;
    }

    err = gcry_cipher_encrypt(gcry_cipher_hd, out, msg_length, msg, msg_length);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "gcry_cipher_encrypt failed: %s/%s\n",
                gcry_strsource(err),
                gcry_strerror(err));
        dawn_free(out);
        out = NULL;
        goto exit;
    }

    *out_length = msg_length;

exit:
    return out;
}

/* Free out buffer after using! */
char *gcrypt_decrypt_msg(const char *msg, size_t msg_length)
{
    size_t blklen = gcry_cipher_get_algo_blklen(GCRY_CIPHER);
    gcry_error_t err;
    char *out = NULL;

    if ((msg_length & (blklen - 1u)) != 0u) {
        fprintf(stderr, "Message length does not fit alignment requirements. Won't decrypt!\n");
        goto exit;
    }

    out = dawn_malloc(msg_length);
    if (out == NULL) {
        fprintf(stderr, "Failed to allocate memory!\n");
        goto exit;
    }

    err = gcry_cipher_decrypt(gcry_cipher_hd, out, msg_length, msg, msg_length);
    if (err != GPG_ERR_NO_ERROR) {
        fprintf(stderr, "gcry_cipher_decrypt failed: %s/%s\n",
                gcry_strsource(err),
                gcry_strerror(err));
        dawn_free(out);
        out = NULL;
    }

exit:
    return out;
}
