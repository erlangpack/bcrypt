-module(bcrypt_security_tests).
-include_lib("eunit/include/eunit.hrl").

-define(SALT, <<"$2b$04$......................">>).
-define(LEGACY_SALT, <<"$2a$04$......................">>).

security_test_() ->
    [{atom_to_list(Mechanism),
      {setup, fun() -> start(Mechanism) end,
       fun(_) -> application:stop(bcrypt) end,
       fun(_) -> [
           ?_test(default_version()),
           ?_test(known_vectors()),
           ?_test(length_boundaries()),
           ?_test(legacy_verification()),
           ?_test(nul_passwords()),
           ?_test(invalid_salts()),
           ?_test(reject_oversized_inputs())
       ] end}}
     || Mechanism <- [nif, port]].

start(Mechanism) ->
    application:stop(bcrypt),
    application:load(bcrypt),
    application:set_env(bcrypt, mechanism, Mechanism),
    application:set_env(bcrypt, nif_pool_size, 1),
    application:set_env(bcrypt, nif_pool_max_overflow, 0),
    application:set_env(bcrypt, pool_size, 1),
    {ok, _} = application:ensure_all_started(bcrypt).

default_version() ->
    ?assertMatch({ok, "$2b$12$" ++ _}, bcrypt:gen_salt()),
    {ok, "$2b$04$" ++ Encoded} = bcrypt:gen_salt(4),
    ?assertEqual(22, length(Encoded)).

known_vectors() ->
    %% Published Openwall vectors; $2b$ agrees with $2a$ for these inputs.
    Salt = "$2b$05$CCCCCCCCCCCCCCCCCCCCC.",
    lists:foreach(fun({Password, Suffix}) ->
        ?assertEqual({ok, Salt ++ Suffix}, bcrypt:hashpw(Password, Salt))
    end, [{"", "7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy"},
          {"U*U", "E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"},
          {"U*U*", "VGOzA784oUp/Z0DY336zx7pLYAy0lwK"}]).

length_boundaries() ->
    %% $2b$ consumes the first 72 bytes, without an 8-bit length wrap.
    Password = <<"A", (binary:copy(<<"B">>, 1023))/binary>>,
    {ok, Expected} = bcrypt:hashpw(binary:part(Password, 0, 72), ?SALT),
    lists:foreach(fun(N) ->
        ?assertEqual({ok, Expected},
            bcrypt:hashpw(binary:part(Password, 0, N), ?SALT))
    end, [72, 73, 254, 255, 256, 257, 511, 512, 1023, 1024]),
    ?assertNotEqual({ok, Expected},
        bcrypt:hashpw(binary:part(Password, 0, 71), ?SALT)),
    ?assertNotEqual({ok, Expected},
        bcrypt:hashpw(binary:copy(<<"A">>, 72), ?SALT)),
    ?assertEqual({ok, Expected}, bcrypt:hashpw(Password, Expected)).

legacy_verification() ->
    %% Captured from the pre-fix implementation, including its wraparound.
    Password = <<"A", (binary:copy(<<"B">>, 255))/binary>>,
    Hash = "$2a$04$.......................KyxKLMd5vyP1icw21wqSvz/XeB9gba",
    ?assertEqual({ok, Hash}, bcrypt:hashpw(Password, ?LEGACY_SALT)),
    ?assertEqual({ok, Hash}, bcrypt:hashpw(Password, Hash)).

nul_passwords() ->
    lists:foreach(fun(P) ->
        ?assertEqual({error, invalid_password}, bcrypt:hashpw(P, ?SALT))
    end, [<<0>>, <<"abc", 0, "def">>, <<"abc", 0>>]),
    %% Existing $2a$ hashes remain verifiable, even for historical NUL inputs.
    Legacy = "$2a$04$......................ini1L2hXWkegMV822DC6vks..mWmZHK",
    ?assertEqual({ok, Legacy}, bcrypt:hashpw(<<"abc", 0, "def">>, Legacy)).

invalid_salts() ->
    Invalid = [<<>>, <<"$">>, <<"$2b$04$">>,
        <<"X2b$04$......................">>,
        <<"$1b$04$......................">>,
        <<"$2x$04$......................">>,
        <<"$2bX04$......................">>,
        <<"$2b$4x$......................">>,
        <<"$2b$+4$......................">>,
        <<"$2b$03$......................">>,
        <<"$2b$32$......................">>,
        binary:copy(<<"A">>, 1024)],
    lists:foreach(fun(S) ->
        ?assertEqual({error, invalid_salt}, bcrypt:hashpw(<<"test">>, S))
    end, Invalid),
    %% Exercise every decoder position, including NUL and non-ASCII input.
    lists:foreach(fun({Pos, Byte}) ->
        <<Prefix:Pos/binary, _, Suffix/binary>> = ?SALT,
        Salt = <<Prefix/binary, Byte, Suffix/binary>>,
        ?assertEqual({error, invalid_salt}, bcrypt:hashpw(<<"test">>, Salt))
    end, [{Pos, Byte} || Pos <- lists:seq(7, 28), Byte <- [0, $!, 255]]).

reject_oversized_inputs() ->
    ?assertEqual({error, invalid_password_length},
        bcrypt:hashpw(binary:copy(<<"A">>, 1025), ?SALT)),
    ?assertEqual({error, invalid_salt},
        bcrypt:hashpw(<<"test">>, binary:copy(<<"A">>, 1025))),
    %% Exercise backend entry points too, bypassing public size checks.
    Hash = case bcrypt:mechanism() of
        nif -> fun bcrypt_nif_worker:hashpw/2;
        port -> fun bcrypt_pool:hashpw/2
    end,
    ?assertEqual({error, invalid_password_length},
        Hash(binary:copy(<<"A">>, 1025), ?SALT)),
    ?assertEqual({error, invalid_salt},
        Hash(<<"test">>, binary:copy(<<"A">>, 1025))),
    %% A rejected request must not break or consume a pool worker.
    ?assertMatch({ok, _}, bcrypt:hashpw(<<"test">>, ?SALT)).

async_owner_exit_test() ->
    %% Run with +S 1 as well: owner exit must not join a hashing C thread.
    Parent = self(),
    Pid = spawn(fun() ->
        Ctx = bcrypt_nif:create_ctx(),
        ok = bcrypt_nif:hashpw(Ctx, make_ref(), self(), <<"test">>,
            <<"$2b$14$......................">>),
        Parent ! ready,
        receive stop -> Ctx end
    end),
    receive ready -> ok after 5000 -> error(owner_not_ready) end,
    Monitor = monitor(process, Pid),
    Started = erlang:monotonic_time(millisecond),
    exit(Pid, kill),
    receive {'DOWN', Monitor, process, Pid, killed} -> ok
    after 200 -> error(owner_exit_blocked)
    end,
    ?assert(erlang:monotonic_time(millisecond) - Started < 200),
    %% Independently prove the asynchronous API still delivers its response.
    Ref = make_ref(),
    ok = bcrypt_nif:hashpw(bcrypt_nif:create_ctx(), Ref, self(), <<"test">>, ?SALT),
    receive {ok, Ref, "$2b$04$" ++ _} -> ok
    after 5000 -> error(no_hash_reply)
    end.
