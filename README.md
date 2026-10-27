bcrypt
======

![Test](https://github.com/erlangpack/bcrypt/workflows/Test/badge.svg)
[![Hex pm](http://img.shields.io/hexpm/v/bcrypt.svg?style=flat)](https://hex.pm/packages/bcrypt)

erlang-bcrypt is a wrapper around the OpenBSD Blowfish password hashing
algorithm, as described in 
[A Future-Adaptable Password Scheme](http://www.openbsd.org/papers/bcrypt-paper.ps) 
by Niels Provos and David Mazieres.

This bcrypt repository at erlangpack is in active maintainance and used
as the basis of the Hex package.


OTP Compatibility
-----------------

erlang-bcrypt is compatible with OTP 21.3 to 29.

Use version 1.0.3 on OTP versions before 21.3

In version 1.1.0 support for OTP 21.2 and earlier is removed
due to the removal of erl_interface in OTP 23.


Rebar.config
------------

erlang-bcrypt is on Hex:

  ```erlang
  {deps, [
      {bcrypt, "~> 2.0"}
  ]}.
  ```

To use the master branch:

  ```erlang
  {deps, [
      {bcrypt, {git, ".*", {git, "https://github.com/erlangpack/bcrypt.git", {branch, "master"}}}
  ]}.
  ```


Basic build instructions
------------------------

1. Build it (project uses rebar3, a Makefile is included):

    ```shell
    make
    ```

2. Run it (simple way, starting sasl, crypto, poolboy and bcrypt):

    ```shell
    $ ./rebar3 shell
    ===> Verifying dependencies...
    ===> Compiling bcrypt
    make: Nothing to be done for `all'.
    Erlang/OTP 28 [erts-16.4] [source] [64-bit] [smp:10:10] [ds:10:10:10] [async-threads:1] [jit]

    Eshell V16.4 (press Ctrl+G to abort, type help(). for help)
    1> application:ensure_all_started(bcrypt).
    {ok,[poolboy,bcrypt]
    2>     
    ```


Basic usage instructions
------------------------

Hash a password using a salt with the default number of rounds:

```erlang
1> {ok, Salt} = bcrypt:gen_salt().
{ok,"$2b$12$JrJ8HaRoDZaCALBL08XAie"}
2> {ok, Hash} = bcrypt:hashpw("foo", Salt).
{ok,"$2b$12$JrJ8HaRoDZaCALBL08XAie1PQi.8QII9K0f05qhVSaHGOW56jnYW2"}
```

Verify the password:

```erlang
3> {ok, Hash} =:= bcrypt:hashpw("foo", Hash).
true
4> {ok, Hash} =:= bcrypt:hashpw("bar", Hash).
false
```

Generate a PHP-compatible `$2y$` hash using `gen_salt/2`:

```erlang
{ok, PhpSalt} = bcrypt:gen_salt(12, '2y'),
{ok, PhpHash} = bcrypt:hashpw(<<"password">>, PhpSalt).
```

Store `PhpHash` as the password hash; PHP can verify it with
`password_verify()`.


Configuration
-------------

The bcrypt application is configured by changing values in the
application's environment:

`default_log_rounds`
  Sets the default number of rounds which define the complexity of the
  hash function. Defaults to `12`.

`mechanism`
  Selects `nif` (the default) or `port`. The NIF hashes inside the Erlang VM
  on OTP dirty CPU schedulers. The port backend hashes in a pool of external
  OS processes. Set this option before starting bcrypt; restart the bcrypt
  application after changing it.

`pool_size`
  Sets the maximum number of port workers when using `port`. Defaults to `4`.

`nif_pool_size`
  Sets the number of Erlang workers in the NIF pool when using `nif`.
  Defaults to `4`. This does not set the number of OTP dirty CPU schedulers.

`nif_pool_max_overflow`
  Sets the maximum number of additional temporary NIF pool workers when
  the regular workers are busy. Defaults to `10`.


Password compatibility and native safety
----------------------------------------

New salts use `$2b$`. Hashing uses at most the first 72 password bytes,
following OpenBSD bcrypt. Passwords up to 1,024 bytes are accepted; longer
inputs return `{error, invalid_password_length}`. Malformed salts return
`{error, invalid_salt}`. These rules apply to both the NIF and port backends.

`$2b$` and `$2y$` reject embedded NUL bytes with `{error, invalid_password}`. Pass text
passwords as encoded bytes; do not pass raw binary prehashes containing NULs.
Existing `$2a$` hashes retain historical password-length wraparound and NUL
termination semantics for verification. After a successful legacy verification,
generate a fresh salt and rehash with `$2b$`; do not just change the prefix.
Legacy hashes affected by those behaviors may warrant a password reset.

PHP `$2y$` hashes are supported by both backends with the same hashing
semantics as `$2b$`. Pass the stored hash directly to `bcrypt:hashpw/2`;
the returned hash retains `$2y$`, so the usual verification pattern works
without rewriting stored prefixes:

```erlang
%% StoredHash is the PHP hash as a byte list; Password contains the same
%% encoded bytes used in PHP (for example, a UTF-8 binary).
{ok, StoredHash} =:= bcrypt:hashpw(Password, StoredHash).
```

`gen_salt/0` and `gen_salt/1` generate `$2b$` salts. To generate a PHP
`$2y$` hash directly, select the version with `gen_salt(Rounds, Version)`:

```erlang
{ok, Salt} = bcrypt:gen_salt(12, '2y'),
{ok, PhpHash} = bcrypt:hashpw(<<"password">>, Salt).
```

The version must be the atom `'2b'` or `'2y'`, and the cost must be an integer
from 4 to 31. Invalid options raise `function_clause`, as with `gen_salt/1`.
The option works with both backends. `PhpHash` retains `$2y$` and can be
verified using PHP's `password_verify()`.

The same 1,024-byte input limit and NUL-byte rejection apply to `$2y$`;
`$2x$` remains unsupported.

The NIF uses OTP dirty CPU schedulers. Its asynchronous `hashpw/5` interface
uses an Erlang helper process and an opaque reference from `create_ctx/0`;
there are no custom native threads, task queues, or blocking destructors.
The public pool still limits concurrent requests. Killing a caller does not
cancel an already running hash; applications should restrict accepted costs
and rate-limit authentication requests. Contexts created before this change
must be recreated when upgrading the application.

The C core incorporates OpenBSD `bcrypt.c` revision 1.58, including `$2b$`,
strict salt parsing, decoder error checking, output bounds, and secure clearing,
with a bounded input adapter shared by both backends. Upstream source:
[OpenBSD bcrypt.c](https://github.com/openbsd/src/blob/master/lib/libc/crypt/bcrypt.c).

Run `make security-test` for native boundary checks under ASan/UBSan. Run
`rebar3 as test eunit` for compatibility, malformed-input, and lifecycle tests.
The lifecycle regression can also be run with `ERL_FLAGS="+S 1"` to verify
that owner exit does not block the sole normal scheduler.


Run tests
---------

To run the eunit and proper tests use:

```shell
make test
```

To test all exported function of a module use:

```shell
$ ./rebar3 as test shell
===> Verifying dependencies...
===> Analyzing applications...
===> Compiling bcrypt
make: Nothing to be done for all.
Erlang/OTP 28 [erts-16.4] [source] [64-bit] [smp:10:10] [ds:10:10:10] [async-threads:1] [jit]

Eshell V16.4 (press Ctrl+G to abort, type help(). for help)
1> application:ensure_all_started(bcrypt).
{ok,[poolboy,bcrypt]}
2> proper:check_specs(bcrypt).            
Testing bcrypt:gen_salt/0
....................................................................................................
OK: Passed 100 test(s).

Testing bcrypt:is_worker_available/0
....................................................................................................
OK: Passed 100 test(s).

Testing bcrypt:gen_salt/2
....................................................................................................
OK: Passed 100 test(s).

Testing bcrypt:hashpw/2
....................................................................................................
OK: Passed 100 test(s).

Testing bcrypt:gen_salt/1
....................................................................................................
OK: Passed 100 test(s).

Testing bcrypt:mechanism/0
....................................................................................................
OK: Passed 100 test(s).

[]
4> 
```

## Documentation generation

### Edoc for public API
```
rebar3 edoc
```

### Edoc for private API
```
rebar3 as edoc_private edoc
```

### ExDoc

```
rebar3 ex_doc --output edoc
```

Original authors
----------------

Hunter Morris & [Mrinal Wadhwa](https://github.com/mrinalwadhwa).
