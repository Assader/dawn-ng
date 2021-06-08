#include <gcrypt.h>

#include "crypto.h"
#include "dawn_log.h"
#include "memory_utils.h"

/* Based on: https://github.com/vedantk/gcrypt-example/blob/master/gcry.cc */

enum {
    GCRY_CIPHER      = GCRY_CIPHER_AES,      /* Pick the cipher here */
    GCRY_CIPHER_MODE = GCRY_CIPHER_MODE_ECB, /* Pick the cipher mode here */
};

static gcry_cipher_hd_t gcry_cipher_hd;

bool gcrypt_init(char *key, char *init_vector)
{
    size_t keylen = gcry_cipher_get_algo_keylen(GCRY_CIPHER),
           blklen = gcry_cipher_get_algo_blklen(GCRY_CIPHER);
    gcry_error_t err;

    if (gcry_check_version(GCRYPT_VERSION) == NULL) {
        err = gpg_err_make(GPG_ERR_SOURCE_USER_1, GPG_ERR_UNKNOWN_VERSION);
        goto error;
    }

    if (strnlen(key, MAX_KEY_LENGTH) < keylen || strnlen(init_vector, MAX_KEY_LENGTH) < blklen) {
        err = gpg_err_make(GPG_ERR_SOURCE_USER_1, GPG_ERR_BAD_KEY);
        goto error;
    }

    err = gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
    err |= gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    err |= gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
    err |= gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    if (err != GPG_ERR_NO_ERROR) {
        err = gpg_err_make(GPG_ERR_SOURCE_USER_1, GPG_ERR_INTERNAL);
        goto error;
    }

    err = gcry_cipher_open(&gcry_cipher_hd, GCRY_CIPHER, GCRY_CIPHER_MODE, 0);
    if (err != GPG_ERR_NO_ERROR) {
        goto error;
    }

    err = gcry_cipher_setkey(gcry_cipher_hd, key, keylen);
    if (err != GPG_ERR_NO_ERROR) {
        goto error;
    }

    err = gcry_cipher_setiv(gcry_cipher_hd, init_vector, blklen);
    if (err != GPG_ERR_NO_ERROR) {
        goto error;
    }

    secure_zero(key, keylen);
    secure_zero(init_vector, blklen);

    return true;
error:
    DAWN_LOG_ERROR("Failed to initialize gcrypt: %s/%s", gcry_strsource(err), gcry_strerror(err));

    return false;
}

char *gcrypt_encrypt_msg(const char *msg, size_t msg_length, int *out_length)
{
    size_t blklen = gcry_cipher_get_algo_blklen(GCRY_CIPHER);
    gcry_error_t err;
    char *out = NULL;

    /* Check if message fits cipher alignment requirements... */
    if ((msg_length & (blklen - 1u)) != 0u) {
        /* ... and append some trash if it does not. */
        msg_length += blklen - (msg_length & (blklen - 1u));
    }

    out = dawn_malloc(msg_length);
    if (out == NULL) {
        DAWN_LOG_ERROR("Failed to allocate memory");
        goto exit;
    }

    err = gcry_cipher_encrypt(gcry_cipher_hd, out, msg_length, msg, msg_length);
    if (err != GPG_ERR_NO_ERROR) {
        DAWN_LOG_ERROR("Failed to encrypt message: %s/%s", gcry_strsource(err), gcry_strerror(err));
        dawn_free(out);
        out = NULL;
        goto exit;
    }

    *out_length = msg_length;

exit:
    return out;
}

bool gcrypt_decrypt_msg(char *msg, size_t msg_length)
{
    size_t blklen = gcry_cipher_get_algo_blklen(GCRY_CIPHER);
    gcry_error_t err;

    if ((msg_length & (blklen - 1u)) != 0u) {
        DAWN_LOG_ERROR("Message length does not fit alignment requirements! Won't decrypt");
        return false;
    }

    err = gcry_cipher_decrypt(gcry_cipher_hd, msg, msg_length, NULL, 0);
    if (err != GPG_ERR_NO_ERROR) {
        DAWN_LOG_ERROR("Failed to decrypt message: %s/%s", gcry_strsource(err), gcry_strerror(err));
        return false;
    }

    return true;
}

/* I'd like to use memset_s, but for compatibility reasons... */
void secure_zero(void *s, size_t n)
{
    volatile char *p = s;

    while (n--) {
        *p++ = 0;
    }
}
