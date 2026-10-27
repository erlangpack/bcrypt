%% @author Hunter Morris <hunter.morris@smarkets.com>
%% @copyright 2011 Hunter Morris, 2026 Marc Worrell
%%
%% @doc Bcrypt Erlang wrapper. <div>The wrapper around the OpenBSD Blowfish password hashing algorithm, as
%% described in: [http://www.openbsd.org/papers/bcrypt-paper.ps "A Future-Adaptable Password Scheme"]
%% by Niels Provos and David Mazieres.</div>
%% @end
%%
%% Permission to use, copy, modify, and distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.

%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
-module(bcrypt_nif).
-author('Hunter Morris <hunter.morris@smarkets.com>').

%% API
-export([init/0]).
-export([gen_salt/1, hashpw/5, create_ctx/0]).

-on_load(init/0).

%%--------------------------------------------------------------------
%% @doc Load the bcrypt NIFs
%% @private
%% @end
%%--------------------------------------------------------------------

-spec init() -> Result when
	Result :: ok | Error,
	Error :: {error, {Reason, ErrorText}},
	Reason :: load_failed | bad_lib | load | reload | upgrade | old_code,
	ErrorText :: string().
init() ->
    Dir = case code:priv_dir(bcrypt) of
              {error, bad_name} ->
                  case code:which(bcrypt) of
                      Filename when is_list(Filename) ->
                          filename:join(
                            [filename:dirname(Filename), "../priv"]);
                      _ ->
                          "../priv"
                  end;
              Priv -> Priv
          end,
    erlang:load_nif(filename:join(Dir, "bcrypt_nif"), 0).

%%--------------------------------------------------------------------
%% @doc Generate a random text salt for use with hashpw/3. LogRounds
%% defines the complexity of the hashing, increasing the cost as
%% 2^log_rounds.
%% @end
%%--------------------------------------------------------------------

-spec gen_salt(LogRounds) -> Result when  
	LogRounds :: integer(),
	Result :: [byte()].
gen_salt(LogRounds)
  when is_integer(LogRounds), LogRounds < 32, LogRounds > 3 ->
    R = crypto:strong_rand_bytes(16),
    encode_salt(R, LogRounds).

encode_salt(_R, _LogRounds) ->
    nif_stub_error(?LINE).

%%--------------------------------------------------------------------
%% @doc Create an opaque token for the asynchronous hashing interface.
%% @end
%%--------------------------------------------------------------------

-spec create_ctx() -> Context when
	Context :: term().
create_ctx() ->
    make_ref().

%%--------------------------------------------------------------------
%% @doc Hash the specified password and the salt using the OpenBSD
%% Blowfish password hashing algorithm. Returns the hashed password.
%% @end
%%--------------------------------------------------------------------

-spec hashpw(Ctx, Ref, Pid, Password, Salt) -> Result when 
	Ctx :: term(), 
	Ref :: reference(), 
	Pid :: pid(), 
	Password :: iodata(),
	Salt :: iodata(),
	Result :: ok.
hashpw(Ctx, Ref, Pid, Password, Salt)
  when is_reference(Ctx), is_reference(Ref), is_pid(Pid), node(Pid) =:= node() ->
    %% Bound inputs before converting iolists or copying them into a helper.
    case {iolist_size(Password), iolist_size(Salt)} of
        {N, _} when N > 1024 ->
            Pid ! {error, Ref, invalid_password_length};
        {_, N} when N =/= 29, N =/= 60 ->
            Pid ! {error, Ref, invalid_salt};
        _ ->
            Pass = iolist_to_binary(Password),
            Setting = iolist_to_binary(Salt),
            spawn(fun() ->
                {Status, Result} = hashpw_dirty(Pass, Setting),
                Pid ! {Status, Ref, Result}
            end)
    end,
    ok.

%% This NIF runs exclusively on OTP dirty CPU schedulers.
hashpw_dirty(_Password, _Salt) ->
    nif_stub_error(?LINE).

nif_stub_error(Line) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, Line}).
