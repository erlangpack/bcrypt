/* Copyright (c) 2026 Marc Worrell <marc@worrell.nl>
 * See LICENSE for license terms.
 */

/* Run under ASan/UBSan with `make security-test`. */
#include <assert.h>
#include <string.h>
#include "bcrypt.h"

int main(void)
{
    unsigned char password[1025];
    unsigned char salt[1024];
    const unsigned char valid[] = "$2b$04$......................";
    const unsigned char php_salt[] = "$2y$04$......................";
    char output[BCRYPT_HASHSIZE];
    memset(password, 'A', sizeof(password));
    memset(salt, '.', sizeof(salt));
    memcpy(salt, "$2b$04$", 7);

    /* Inputs are deliberately not NUL terminated. */
    assert(bcrypt_hash(output, sizeof(output), password, 1024,
        valid, 29) == BCRYPT_OK);
    assert(strlen(output) == 60);
    assert(bcrypt_hash(output, 60, password, 72,
        valid, 29) == BCRYPT_INVALID_SALT);
    assert(bcrypt_hash(output, sizeof(output), password, 1025,
        valid, 29) == BCRYPT_INVALID_PASSWORD_LENGTH);
    assert(bcrypt_hash(output, sizeof(output), password, 72,
        salt, sizeof(salt)) == BCRYPT_INVALID_SALT);
    assert(bcrypt_hash(output, sizeof(output), password, 72,
        NULL, 0) == BCRYPT_INVALID_SALT);
    for (size_t i = 7; i < 29; i++) {
        memcpy(salt, valid, 29);
        salt[i] = '!';
        assert(bcrypt_hash(output, sizeof(output), password, 72,
            salt, 29) == BCRYPT_INVALID_SALT);
    }
    assert(bcrypt_hash(output, sizeof(output), password, 1024,
        php_salt, 29) == BCRYPT_OK);
    assert(strlen(output) == 60 && strncmp(output, "$2y$", 4) == 0);
    password[0] = 0;
    assert(bcrypt_hash(output, sizeof(output), password, 72,
        valid, 29) == BCRYPT_INVALID_PASSWORD);
    assert(bcrypt_hash(output, sizeof(output), password, 72,
        php_salt, 29) == BCRYPT_INVALID_PASSWORD);
    bcrypt_clear(password, sizeof(password));
    for (size_t i = 0; i < sizeof(password); i++)
        assert(password[i] == 0);
    return 0;
}
