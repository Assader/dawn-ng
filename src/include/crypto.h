#ifndef DAWN_CRYPTO_H
#define DAWN_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>

enum {
    MAX_KEY_LENGTH = 64
};

/**
 * Initialize gcrypt.
 * Has to be called before using the other functions!
 * Key and iv will be destroyed in case of successfull initializtion.
 * @param key
 * @param iv
 * @return true if init was successfull, false otherwise.
 */
bool gcrypt_init(char *key, char *iv);

/**
 * Function that encrypts the message.
 * Free the string after using it!
 * @param msg
 * @param msg_length
 * @param out_length
 * @return the encrypted string.
 */
char *gcrypt_encrypt_msg(const char *msg, size_t msg_length, int *out_length);

/**
 * Function that decrypts a message.
 * Free the string after using it!
 * @param msg
 * @param msg_length
 * @return the decrypted string.
 */
char *gcrypt_decrypt_msg(const char *msg, size_t msg_length);

void secure_zero(void *s, size_t n);

#endif /* DAWN_CRYPTO_H */
