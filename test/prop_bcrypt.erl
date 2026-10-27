-module(prop_bcrypt).

-include_lib("proper/include/proper.hrl").
-import(base,[bigger/1]).

%%%%%%%%%%%%%%%%%%
%%% Properties %%%
%%%%%%%%%%%%%%%%%%


prop_mechanism_nif() ->
    ?SETUP(setup(nif),
    ?FORALL(_Ok, exactly(ok),
    begin
        Mechanism = bcrypt:mechanism(),
        nif =:= Mechanism
    end)        
    ).

prop_mechanism_port() ->
    ?SETUP(setup(port),
    ?FORALL(_Ok, exactly(ok),
    begin
        Mechanism = bcrypt:mechanism(),
        port =:= Mechanism
    end)        
    ).

prop_salt_rounds_nif() ->
    ?SETUP(setup(nif),
    check_salt_rounds()        
    ).

prop_salt_rounds_port() ->
    ?SETUP(setup(port),
    check_salt_rounds()        
    ).


prop_salt_port() ->
    ?SETUP(setup(port),
    check_salt()        
    ).

prop_simple_nif() ->
    ?SETUP(setup(nif),
    check_simple()        
    ).

prop_simple_port() ->
    ?SETUP(setup(port),
    check_simple()        
    ).

%%%%%%%%%%%%%%%%%%
%%%  Helpers   %%%
%%%%%%%%%%%%%%%%%%

setup(Mechanism) ->
    fun() ->
        application:start(crypto),
        application:start(poolboy),
        case application:load(bcrypt) of
            {error, {already_loaded, bcrypt}} -> ok;
            ok -> ok
        end,
        ok = application:set_env(bcrypt, mechanism, Mechanism),
        case application:start(bcrypt) of
            {error, {already_started, bcrypt}} ->
                ok = application:stop(bcrypt),
                ok = application:start(bcrypt);
            ok -> ok
        end,
        fun() -> ok end
    end.

check_salt() ->
    ?FORALL(_Ok, exactly(ok),
    begin
        {ok, Salt} = bcrypt:gen_salt(),
        % io:format("Salt = ~s~n", [Salt]),
        is_list(Salt)
    end).

check_salt_rounds() ->
    ?FORALL(Rounds, range(4, 31),
    begin
        {ok, Salt} = bcrypt:gen_salt(Rounds),
        %io:format("Salt = ~s~n", [Salt]),
        is_list(Salt)
    end).

check_simple() ->
    ?FORALL(Password, password(),
    begin
        {ok, Salt} = bcrypt:gen_salt(),  
        {ok, Hash} = bcrypt:hashpw(Password, Salt),
        {ok, Hash} =:= bcrypt:hashpw(Password, Hash)
    end).



%%%%%%%%%%%%%%%%%%
%%% Generators %%%
%%%%%%%%%%%%%%%%%%

%% $2b$ rejects embedded NUL bytes; explicit rejection is covered by EUnit.
password() -> oneof([?LET(Bytes, ascii_string(), list_to_binary(Bytes)), ascii_string()]).
ascii_string() -> list(range(1,255)).
