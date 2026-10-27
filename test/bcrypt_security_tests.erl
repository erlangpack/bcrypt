-module(bcrypt_security_tests).
-include_lib("eunit/include/eunit.hrl").

-define(SALT, <<"$2b$04$......................">>).
-define(PHP_SALT, <<"$2y$04$......................">>).
-define(LEGACY_SALT, <<"$2a$04$......................">>).

security_test_() ->
    [{atom_to_list(Mechanism),
      {setup, fun() -> start(Mechanism) end,
       fun(_) -> application:stop(bcrypt) end,
       fun(_) -> [
           ?_test(default_version()),
           ?_test(explicit_salt_version()),
           ?_test(invalid_salt_options()),
           ?_test(known_vectors()),
           ?_test(php_vectors()),
           ?_test(php_length_boundaries()),
           ?_test(php_invalid_inputs()),
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

explicit_salt_version() ->
    lists:foreach(fun({Version, Prefix}) ->
        %% Check cost boundaries without attempting an expensive cost-31 hash.
        lists:foreach(fun(Rounds) ->
            {ok, Salt} = bcrypt:gen_salt(Rounds, Version),
            ExpectedPrefix = lists:flatten(io_lib:format("~s~2..0B$", [Prefix, Rounds])),
            ?assert(lists:prefix(ExpectedPrefix, Salt)),
            ?assertEqual(29, length(Salt))
        end, [4, 12, 31]),
        {ok, Salt} = bcrypt:gen_salt(4, Version),
        {ok, Hash} = bcrypt:hashpw(<<"password">>, Salt),
        ?assert(lists:prefix(Prefix, Hash)),
        ?assertEqual({ok, Hash}, bcrypt:hashpw(<<"password">>, Hash)),
        ?assertNotEqual({ok, Hash}, bcrypt:hashpw(<<"wrong">>, Hash))
    end, [{'2b', "$2b$"}, {'2y', "$2y$"}]).

invalid_salt_options() ->
    %% Invalid options follow gen_salt/1's existing function_clause behavior.
    lists:foreach(fun(Args) ->
        ?assertError(function_clause, apply(bcrypt, gen_salt, Args))
    end, [[4, '2a'], [4, '2x'], [4, "2y"], [4, <<"2y">>],
          [3, '2b'], [32, '2b'], [3, '2y'], [32, '2y'], [4.0, '2y']]),
    ?assertMatch({ok, "$2b$04$" ++ _}, bcrypt:gen_salt(4)).

known_vectors() ->
    %% Published Openwall vectors; $2b$ agrees with $2a$ for these inputs.
    Salt = "$2b$05$CCCCCCCCCCCCCCCCCCCCC.",
    lists:foreach(fun({Password, Suffix}) ->
        ?assertEqual({ok, Salt ++ Suffix}, bcrypt:hashpw(Password, Salt))
    end, [{"", "7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy"},
          {"U*U", "E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"},
          {"U*U*", "VGOzA784oUp/Z0DY336zx7pLYAy0lwK"}]).

php_vectors() ->
    %% Generated with PHP 8.5.9 crypt($password, '$2y$04$......................').
    %% Fixed fixtures keep PHP out of the test/runtime dependencies.
    Vectors = [
        {<<>>, "w74bL5gU7LSJClZClCa.Pkz14aTv/XO"},
        {<<"password">>, "LAtw7/ohmmBAhnXqmkuIz83Rl5Qdjhm"},
        {<<"pässwörd"/utf8>>, "qnB8eqNMuizEQ3mLqW93JYyN8aQz3iO"},
        {<<255, 128, 163>>, "Ob6ydY8/tzRw2F.YD8ZfQe6VkpynLsi"}
    ],
    lists:foreach(fun({Password, Suffix}) ->
        Expected = binary_to_list(?PHP_SALT) ++ Suffix,
        %% Both a salt and a stored hash must preserve the $2y$ prefix.
        ?assertEqual({ok, Expected}, bcrypt:hashpw(Password, ?PHP_SALT)),
        ?assertEqual({ok, Expected}, bcrypt:hashpw(Password, Expected)),
        ?assertEqual({ok, Expected},
            bcrypt:hashpw(binary_to_list(Password), list_to_binary(Expected))),
        ?assertNotEqual({ok, Expected}, bcrypt:hashpw(<<"wrong">>, Expected)),
        ?assertEqual({ok, binary_to_list(?SALT) ++ Suffix},
            bcrypt:hashpw(Password, ?SALT))
    end, Vectors).

php_length_boundaries() ->
    Password = <<"A", (binary:copy(<<"B">>, 1023))/binary>>,
    %% PHP reference outputs for 71 bytes and for 72 or more bytes.
    Short = binary_to_list(?PHP_SALT) ++ "HngKtCj1MUdG5WavwdNXo.lTVlWjsba",
    Long = binary_to_list(?PHP_SALT) ++ "G0G3HvI30KYH1y5QpphZX4Y4p0vztu6",
    ?assertEqual({ok, Short},
        bcrypt:hashpw(binary:part(Password, 0, 71), ?PHP_SALT)),
    lists:foreach(fun(N) ->
        P = binary:part(Password, 0, N),
        ?assertEqual({ok, Long}, bcrypt:hashpw(P, ?PHP_SALT)),
        ?assertEqual({ok, Long}, bcrypt:hashpw(P, Long))
    end, [72, 73, 254, 255, 256, 257, 511, 512, 1023, 1024]).

php_invalid_inputs() ->
    lists:foreach(fun(Password) ->
        ?assertEqual({error, invalid_password},
            bcrypt:hashpw(Password, ?PHP_SALT))
    end, [<<0>>, <<"abc", 0, "def">>, <<"abc", 0>>,
          <<(binary:copy(<<"A">>, 72))/binary, 0>>]),
    ?assertEqual({error, invalid_password_length},
        bcrypt:hashpw(binary:copy(<<"A">>, 1025), ?PHP_SALT)),
    lists:foreach(fun(Salt) ->
        ?assertEqual({error, invalid_salt}, bcrypt:hashpw(<<"test">>, Salt))
    end, [<<"$2y$04$">>, <<"$2y$03$......................">>,
          <<"$2y$32$......................">>,
          <<"$2y$4x$......................">>,
          <<"$2y$04$!!!!!!!!!!!!!!!!!!!!!!">>]).

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
