%% @copyright 2011 Hunter Morris
%% @doc Implementation of `gen_server' behaviour.
%% @end
%% Distributed under the MIT license; see LICENSE for details.
-module(bcrypt_pool).
-author('Hunter Morris <huntermorris@gmail.com>').

-behaviour(gen_server).

-export([start_link/0, available/1]).
-export([gen_salt/0, gen_salt/1]).
-export([hashpw/2]).
-export([is_worker_available/0]).

%% gen_server
-export([init/1, code_change/3, terminate/2,
         handle_call/3, handle_cast/2, handle_info/2]).

-record(state, {
          size = 0,
          busy = 0,
          requests = queue:new(),
          ports = queue:new()
         }).

-record(req, {mon :: reference(), from :: gen_server:from()}).

-type state() :: #state{size :: 0, busy :: 0, requests :: queue:queue(), ports :: queue:queue()}.

%% @doc Creates a `gen_server' process as part of a supervision tree.

-spec start_link() -> Result when
	Result :: {ok,Pid} | ignore | {error,Error},
	Pid :: pid(),
	Error :: {already_started,Pid} | term().
start_link() -> gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Asynchronously check if `Pid' in `#state:requests' queue or not.

-spec available(Pid) -> Result when
	Pid :: pid(),
	Result :: ok.
available(Pid) -> gen_server:cast(?MODULE, {available, Pid}).

%% @doc Is at least one bcrypt worker currently available for work?

-spec is_worker_available() -> Result when
	Result :: boolean().
is_worker_available() ->
    gen_server:call(?MODULE, is_worker_available, infinity).

%% @doc Generate a random text salt.

-spec gen_salt() -> Result when
	Result :: {ok, Salt},
	Salt :: [byte()].
gen_salt()             -> do_call(fun bcrypt_port:gen_salt/1, []).

%% @doc Generate a random text salt. Rounds defines the complexity of 
%% the hashing, increasing the cost as 2^log_rounds.

-spec gen_salt(Rounds) -> Result when
	Rounds :: bcrypt:rounds(),
	Result :: {ok, Salt},
	Salt :: [byte()].
gen_salt(Rounds)       -> do_call(fun bcrypt_port:gen_salt/2, [Rounds]).

%% @doc Hash the specified password and the salt.

hashpw(Password, Salt) -> do_call(fun bcrypt_port:hashpw/3, [Password, Salt]).

%% @private

-spec init([]) -> Result when
	Result :: {ok, state()}.
init([]) ->
    {ok, Size} = application:get_env(bcrypt, pool_size),
    {ok, #state{size = Size}}.

%% @private

terminate(shutdown, _) -> ok.

%% @private

-spec handle_call(Request, From, State) -> Result when 
	Request :: request,
    From :: gen_server:from(),
	State :: state(),
	Result :: {noreply, state()} | {reply, {ok, pid()}, state()}.
handle_call(request, {RPid, _} = From, #state{ports = P} = State) ->
    case queue:out(P) of
        {empty, P} ->
            #state{size = Size, busy = B, requests = R} = State,
            B1 =
                if Size > B ->
                        {ok, _} = bcrypt_port_sup:start_child(),
                        B + 1;
                   true ->
                        B
                end,
            RRef = erlang:monitor(process, RPid),
            R1 = queue:in(#req{mon = RRef, from = From}, R),
            {noreply, State#state{requests = R1,
                                  busy = B1}};
        {{value, PPid}, P1} ->
            #state{busy = B} = State,
            {reply, {ok, PPid}, State#state{busy = B + 1, ports = P1}}
    end;
handle_call(is_worker_available, _From, #state{size = Size, busy = Busy} = State) ->
    {reply, Size > Busy, State};
handle_call(Msg, _, _) -> exit({unknown_call, Msg}).

%% @private

-spec handle_cast({available, Pid}, state()) -> Result when
	Pid :: pid(),
	Result :: {noreply, state()}.
handle_cast(
  {available, Pid},
  #state{requests = R, ports = P, busy = B} = S) ->
    case queue:out(R) of
        {empty, R} ->
            {noreply, S#state{ports = queue:in(Pid, P), busy = B - 1}};
        {{value, #req{mon = Mon, from = F}}, R1} ->
            true = erlang:demonitor(Mon, [flush]),
            gen_server:reply(F, {ok, Pid}),
            {noreply, S#state{requests = R1}}
    end;
handle_cast(Msg, _) -> exit({unknown_cast, Msg}).

%% @private

handle_info({'DOWN', Ref, process, _Pid, _Reason}, #state{requests = R} = State) ->
    R1 = queue:from_list(lists:keydelete(Ref, #req.mon, queue:to_list(R))),
    {noreply, State#state{requests = R1}};

%% @private

handle_info(Msg, _) -> exit({unknown_info, Msg}).

%% @private

code_change(_OldVsn, State, _Extra) -> {ok, State}.

do_call(F, Args0) ->
    {ok, Pid} = gen_server:call(?MODULE, request, infinity),
    Args = [Pid|Args0],
    apply(F, Args).
