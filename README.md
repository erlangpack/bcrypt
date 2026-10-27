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
      {bcrypt, "1.1.3"}
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

2. Run it (simple way, starting sasl, crypto and bcrypt):

    ```shell
    $ ./rebar3 shell
    ===> Verifying dependencies...
    ===> Compiling bcrypt
    make: Nothing to be done for `all'.
    Erlang/OTP 23 [erts-11.0] [source] [64-bit] [smp:12:12] [ds:12:12:10] [async-threads:1] [hipe]

    Eshell V11.0  (abort with ^G)
    1> application:ensure_all_started(bcrypt).
    {ok,[bcrypt]}
    2>     
    ```

Basic usage instructions
------------------------

Hash a password using a salt with the default number of rounds:

```erlang
1> {ok, Salt} = bcrypt:gen_salt().
{ok,"$2b$12$sSS8Eg.ovVzaHzi1nUHYK."}
2> {ok, Hash} = bcrypt:hashpw("foo", Salt).
{ok,"$2b$12$sSS8Eg.ovVzaHzi1nUHYK.HbUIOdlQI0iS22Q5rd5z.JVVYH6sfm6"}
```

Verify the password:

```erlang
3> {ok, Hash} =:= bcrypt:hashpw("foo", Hash).
true
4> {ok, Hash} =:= bcrypt:hashpw("bar", Hash).
false
```

Configuration
-------------

The bcrypt application is configured by changing values in the
application's environment:

`default_log_rounds`
  Sets the default number of rounds which define the complexity of the
  hash function. Defaults to `12`.

`mechanism`
  Specifies whether to use the NIF implementation (`'nif'`) or a
  pool of port programs (`'port'`). Defaults to `'nif'`.

  `Note: hashing runs on OTP dirty CPU schedulers, not normal scheduler threads.`

`pool_size`
  Specifies the size of the port program pool. Defaults to `4`.

`nif_pool_size`
  Specifies the size of the nif program pool. Defaults to `4`.

`nif_pool_max_overflow`
  Specifies the max workers to overflow of the nif program pool. Defaults to `10`.

Run tests
---------

To run the eunit and proper tests use:

```shell
make tests
```

To test all exported function of a module use:

```shell
$ ./rebar3 as test shell
===> Verifying dependencies...
===> Compiling bcrypt
make: Nothing to be done for all.
Erlang/OTP 23 [erts-11.0] [source] [64-bit] [smp:12:12] [ds:12:12:10] [async-threads:1] [hipe]

Eshell V11.0  (abort with ^G)
1> application:ensure_all_started(bcrypt).
{ok,[bcrypt]}
2>proper:check_specs(bcrypt).            
Testing bcrypt:gen_salt/0
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

### Edoc

#### Generate public API
```
rebar3 edoc
```

#### Generate private API
```
rebar3 as edoc_private edoc
```

### ExDoc

```
rebar3 ex_doc --output edoc
```


Both the _port_ and the _NIF_ version of bcrypt are tested.
All tests should pass.

Original authors
----------------

Hunter Morris & [Mrinal Wadhwa](https://github.com/mrinalwadhwa).

## Password compatibility and native safety

New salts use `$2b$`. Hashing uses at most the first 72 password bytes,
following OpenBSD bcrypt. Passwords up to 1,024 bytes are accepted; longer
inputs return `{error, invalid_password_length}`. Malformed salts return
`{error, invalid_salt}`. These rules apply to both the NIF and port backends.

`$2b$` rejects embedded NUL bytes with `{error, invalid_password}`. Pass text
passwords as encoded bytes; do not pass raw binary prehashes containing NULs.
Existing `$2a$` hashes retain historical password-length wraparound and NUL
termination semantics for verification. After a successful legacy verification,
generate a fresh salt and rehash with `$2b$`; do not just change the prefix.
Legacy hashes affected by those behaviors may warrant a password reset.

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
