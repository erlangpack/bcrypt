%% @copyright 2011 Hunter Morris, 2026 Marc Worrell
%% @doc Implementation of `gen_server' behaviour.
%% @end
%% Distributed under the MIT license; see LICENSE for details.
-module(bcrypt_nif_worker).
-author('Hunter Morris <huntermorris@gmail.com>').

-behaviour(gen_server).

-export([start_link/1]).
-export([gen_salt/0, gen_salt/1]).
-export([hashpw/2]).
-export([is_worker_available/0]).

%% gen_server
-export([init/1, code_change/3, terminate/2,
         handle_call/3, handle_cast/2, handle_info/2]).

-record(state, {
          default_log_rounds :: integer(), 
		  context :: term()
         }).

-type state() :: #state{default_log_rounds :: integer(), context :: term()}.

%% @doc Creates a `gen_server' process as part of a supervision tree.

-spec start_link(Args) -> Result when
	Args :: term(),
	Result :: {ok,Pid} | ignore | {error,Error},
	Pid :: pid(),
	Error :: {already_started,Pid} | term().
start_link(Args) -> gen_server:start_link(?MODULE, Args, []).

%% @doc Returns bcrypt salt.

-spec gen_salt() -> Result when
	Result :: [byte()].
gen_salt() ->
    poolboy:transaction(bcrypt_nif_pool, fun(Worker) ->
        gen_server:call(Worker, gen_salt, infinity)
    end).

%% @doc Returns bcrypt salt.

-spec gen_salt(Rounds) -> Result when
	Rounds :: bcrypt:rounds(),
	Result :: [byte()].
gen_salt(Rounds) ->
    poolboy:transaction(bcrypt_nif_pool, fun(Worker) ->
        gen_server:call(Worker, {gen_salt, Rounds}, infinity)
    end).

%% @doc Make hash string based on `Password' and `Salt'.

-spec hashpw( Password, Salt ) -> Result when
	Password :: [byte()] | binary(), 
	Salt :: [byte()] | binary(),
	Result :: {ok, Hash} | {error, ErrorDescription},
	Hash :: [byte()],
	ErrorDescription :: bcrypt:pwerr().
hashpw(Password, Salt) ->
    poolboy:transaction(bcrypt_nif_pool, fun(Worker) ->
         gen_server:call(Worker, {hashpw, Password, Salt}, infinity)
    end).

%% @doc Is at least one bcrypt worker currently available for work?

-spec is_worker_available() -> Result when
	Result :: boolean().
is_worker_available() ->
	{StateName, _Workers, _Overflow, _Size} = poolboy:status(bcrypt_nif_pool),
	StateName =/= full.
	
%% @private

-spec init(Args) -> Result when 
	Args :: list(),
	Result :: {ok, state()}.
init([]) ->
    process_flag(trap_exit, true),
    {ok, Default} = application:get_env(bcrypt, default_log_rounds),
    Ctx = bcrypt_nif:create_ctx(),
    {ok, #state{default_log_rounds = Default, context = Ctx}}.

%% @private

terminate(shutdown, _) -> ok.

%% @private

-spec handle_call(term(), gen_server:from(), state()) ->
    {reply, term(), state()}.

handle_call(gen_salt, _From, #state{default_log_rounds = R} = State) ->
    Salt = bcrypt_nif:gen_salt(R),
    {reply, {ok, Salt}, State};
handle_call({gen_salt, R}, _From, State) ->
    Salt = bcrypt_nif:gen_salt(R),
    {reply, {ok, Salt}, State};
handle_call({hashpw, Password, Salt}, _From, #state{context=Ctx}=State) ->
    Ref = make_ref(),
    ok = bcrypt_nif:hashpw(Ctx, Ref, self(), Password, Salt),
    receive
        {ok, Ref, Result} ->
            {reply, {ok, Result}, State};
        {error, Ref, Result} ->
            {reply, {error, Result}, State}
    end;
handle_call(Msg, _, _) -> exit({unknown_call, Msg}).

%% @private

handle_cast(Msg, _) -> exit({unknown_cast, Msg}).

%% @private

handle_info(Msg, _) -> exit({unknown_info, Msg}).

%% @private

code_change(_OldVsn, State, _Extra) -> {ok, State}.
