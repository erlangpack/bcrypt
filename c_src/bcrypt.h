#ifndef ERLANG_BCRYPT_H
#define ERLANG_BCRYPT_H

#include <stddef.h>
#include <sys/types.h>

#define BCRYPT_MAXPASSWORD 1024
#define BCRYPT_SALTSIZE 30
#define BCRYPT_HASHSIZE 61

enum bcrypt_result {
    BCRYPT_OK,
    BCRYPT_INVALID_SALT,
    BCRYPT_INVALID_PASSWORD,
    BCRYPT_INVALID_PASSWORD_LENGTH
};

int bcrypt_hash(char *, size_t, const unsigned char *, size_t,
    const unsigned char *, size_t);
void encode_salt(char *, u_int8_t *, u_int16_t, u_int8_t);
void bcrypt_clear(void *, size_t);

#endif
