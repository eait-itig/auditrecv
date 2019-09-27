%%
%% auditrecv
%% receiver for illumos/solaris audit_remote.so stream
%%
%% Copyright 2019 Alex Wilson <alex@uq.edu.au>
%% The University of Queensland
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%

-module(auditrecv_fsm_sup).

-behaviour(supervisor).

%% API
-export([start_link/0, start_fsm/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

start_fsm() ->
    supervisor:start_child(?SERVER, []).

init([]) ->
    EsConfig = application:get_env(auditrecv, elasticsearch, []),
    EsHost = proplists:get_value(host, EsConfig, "127.0.0.1"),
    EsPort = proplists:get_value(port, EsConfig, 9200),
    {ok, LSock} = gen_tcp:listen(1234, [binary, {active, false}, {packet, 4},
        {reuseaddr, true}]),
    lager:debug("listening for audit clients on port 1234"),
    [spawn(fun start_fsm/0) || _N <- lists:seq(1,3)],
    Flags = #{
        strategy => simple_one_for_one,
        intensity => 30,
        period => 60
    },
    Kids = [#{
        id => fsm,
        start => {auditrecv_fsm, start_link, [LSock, EsHost, EsPort]},
        restart => transient
    }],
    {ok, {Flags, Kids}}.
