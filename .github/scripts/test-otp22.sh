#!/bin/sh
# Run inside the official erlang:22.3 image, in a fresh checkout.
set -eu

erl -noshell -eval '"22" = erlang:system_info(otp_release), halt().'

# Current publishing/test plugins may require newer OTP. Keep the project's
# dependencies and test settings, and invoke PropEr directly without a plugin.
config_backup=$(mktemp)
cp rebar.config "$config_backup"
trap 'cp "$config_backup" rebar.config; rm -f "$config_backup"' EXIT

erl -noshell -eval '
    {ok, Config} = file:consult("rebar.config"),
    WithoutPlugins = fun(Options) ->
        proplists:delete(project_plugins, proplists:delete(plugins, Options))
    end,
    Profiles = [{Name, WithoutPlugins(Options)} ||
        {Name, Options} <- proplists:get_value(profiles, Config, [])],
    Updated = lists:keystore(profiles, 1, WithoutPlugins(Config),
        {profiles, Profiles}),
    ok = file:write_file("rebar.config",
        [io_lib:format("~p.~n", [Term]) || Term <- Updated]),
    halt().'

rebar3 version
make
rebar3 as test eunit
make security-test
ERL_FLAGS="+S 1" rebar3 as test eunit --module=bcrypt_security_tests

erl -noshell -pa _build/test/lib/*/ebin _build/test/lib/bcrypt/test -eval '
    case proper:module(prop_bcrypt, [{numtests, 100}]) of
        [] -> halt(0);
        _ -> halt(1)
    end.'

make xref
make dialyzer
