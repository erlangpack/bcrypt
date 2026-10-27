%% Copyright (c) 2011 Hunter Morris
%% Distributed under the MIT license; see LICENSE for details.
%% @doc The OpenBSD Blowfish password hashing algorithm wrapper module.
-module(bcrypt).
-author('Hunter Morris <hunter.morris@smarkets.com>').

%% API
-export([start/0, stop/0]).
-export([mechanism/0]).
-export([gen_salt/0, gen_salt/1, hashpw/2, is_worker_available/0]).

-type mechanism() :: nif | port.
-type rounds() :: 4..31.
-type pwerr() :: invalid_salt | invalid_salt_length | invalid_rounds
    | invalid_password | invalid_password_length.

-export_type([ mechanism/0, rounds/0, pwerr/0 ]).

%% @doc Starts `Application' `bcrypt'. 
%% <b>See also:</b> 
%% [http://erlang.org/doc/man/application.html#start-1 application:start/1].

start() -> application:start(bcrypt).

%% @doc Stops `Application' `bcrypt'.  
%% <b>See also:</b> 
%% [http://erlang.org/doc/man/application.html#stop-1 application:stop/1].

stop()  -> application:stop(bcrypt).

%% @doc Get environment setting of hash generation.

-spec mechanism() -> mechanism().
mechanism() ->
    {ok, M} = application:get_env(bcrypt, mechanism),
    M.

%% @doc Returns a random string data.

-spec gen_salt() -> Result when
	Result :: {ok, Salt},
	Salt :: [byte()].
gen_salt() ->
    do_gen_salt(mechanism()).

%% @doc Generate a random string data.

-spec gen_salt( Rounds ) -> Result when
	Rounds :: rounds(),
	Result :: {ok, Salt},
	Salt :: [byte()].
gen_salt(Rounds) when is_integer(Rounds), Rounds < 32, Rounds > 3 ->
    do_gen_salt(mechanism(), Rounds).

%% @doc Make hash string based on `Password' and `Salt'.

-spec hashpw( Password, Salt ) -> Result when
	Password :: [byte()] | binary(), 
	Salt :: [byte()] | binary(),
	Result :: {ok, Hash} | {error, ErrorDescription},
	Hash :: [byte()],
	ErrorDescription :: pwerr().
hashpw(Password, Salt) ->
    case {iolist_size(Password), iolist_size(Salt)} of
        {N, _} when N > 1024 -> {error, invalid_password_length};
        {_, N} when N =/= 29, N =/= 60 -> {error, invalid_salt};
        _ -> do_hashpw(mechanism(), Password, Salt)
    end.

%% @doc Is at least one bcrypt worker currently available for work?

-spec is_worker_available() -> Result when
	Result :: boolean().
is_worker_available() ->
    do_is_worker_available(mechanism()).

%% @private

-spec do_gen_salt(nif | port) -> Result when
	Result :: {ok, Salt},
	Salt :: [byte()].
do_gen_salt(nif)  -> bcrypt_nif_worker:gen_salt();
do_gen_salt(port) -> bcrypt_pool:gen_salt().

%% @private

-spec do_gen_salt(nif | port, Rounds) -> Result when
	Rounds :: rounds(),
	Result :: {ok, Salt},
	Salt :: [byte()].
do_gen_salt(nif, Rounds)  -> bcrypt_nif_worker:gen_salt(Rounds);
do_gen_salt(port, Rounds) -> bcrypt_pool:gen_salt(Rounds).

%% @private

-spec do_hashpw(nif | port, Password, Salt) -> Result when
	Password :: [byte()] | binary(), 
	Salt :: [byte()],
	Result :: {ok, Hash} | {error, ErrorDescription},
	Hash :: [byte()],
	ErrorDescription :: pwerr().
do_hashpw(nif, Password, Salt)  -> bcrypt_nif_worker:hashpw(Password, Salt);
do_hashpw(port, Password, Salt) -> bcrypt_pool:hashpw(Password, Salt).

-spec do_is_worker_available(nif | port) -> Result when
	Result :: boolean().
do_is_worker_available(nif)  -> bcrypt_nif_worker:is_worker_available();
do_is_worker_available(port) -> bcrypt_pool:is_worker_available().
