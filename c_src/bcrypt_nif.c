/*
 * Copyright (c) 2026 Marc Worrell <marc@worrell.nl>
 * Copyright (c) 2011-2012 Hunter Morris <hunter.morris@smarkets.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <string.h>
#include "erl_nif.h"
#include "bcrypt.h"

static ERL_NIF_TERM error(ErlNifEnv *env, const char *reason)
{
    return enif_make_tuple2(env, enif_make_atom(env, "error"),
        enif_make_atom(env, reason));
}

static ERL_NIF_TERM bcrypt_encode_salt(ErlNifEnv *env, int argc,
    const ERL_NIF_TERM argv[])
{
    ErlNifBinary raw;
    unsigned int rounds;
    char salt[BCRYPT_SALTSIZE];

    if (argc != 2 || !enif_inspect_binary(env, argv[0], &raw) ||
        raw.size != 16 || !enif_get_uint(env, argv[1], &rounds) ||
        rounds < 4 || rounds > 31)
        return enif_make_badarg(env);
    /* Inspected binaries belong to the VM; never release them here. */
    encode_salt(salt, raw.data, raw.size, rounds);
    return enif_make_string(env, salt, ERL_NIF_LATIN1);
}

/* OTP owns scheduling and lifetime. There are no native queues, worker
 * threads, allocated task environments or blocking resource destructors. */
static ERL_NIF_TERM bcrypt_hashpw(ErlNifEnv *env, int argc,
    const ERL_NIF_TERM argv[])
{
    ErlNifBinary password, salt;
    char encrypted[BCRYPT_HASHSIZE];
    ERL_NIF_TERM result;
    int status;

    if (argc != 2 || !enif_inspect_binary(env, argv[0], &password) ||
        !enif_inspect_binary(env, argv[1], &salt))
        return enif_make_badarg(env);
    status = bcrypt_hash(encrypted, sizeof(encrypted), password.data,
        password.size, salt.data, salt.size);
    switch (status) {
    case BCRYPT_OK:
        result = enif_make_tuple2(env, enif_make_atom(env, "ok"),
            enif_make_string(env, encrypted, ERL_NIF_LATIN1));
        bcrypt_clear(encrypted, sizeof(encrypted));
        return result;
    case BCRYPT_INVALID_PASSWORD:
        return error(env, "invalid_password");
    case BCRYPT_INVALID_PASSWORD_LENGTH:
        return error(env, "invalid_password_length");
    default:
        return error(env, "invalid_salt");
    }
}

static ErlNifFunc bcrypt_nif_funcs[] = {
    {"encode_salt", 2, bcrypt_encode_salt, 0},
    {"hashpw_dirty", 2, bcrypt_hashpw, ERL_NIF_DIRTY_JOB_CPU_BOUND}
};

ERL_NIF_INIT(bcrypt_nif, bcrypt_nif_funcs, NULL, NULL, NULL, NULL)
