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

-module(vmlookup).
-behaviour(gen_server).

-export([start_link/2, lookup/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

start_link(VmApi, Mahi) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [VmApi, Mahi], []).

lookup(Uuid) ->
    gen_server:call(?MODULE, {lookup, Uuid}).

-record(state, {vmgun, mhgun, vms = #{}, users = #{}}).

init([VmApi, Mahi]) ->
    {ok, VmGun} = gun:open(VmApi, 80),
    {ok, MhGun} = gun:open(Mahi, 80),
    {ok, #state{vmgun = VmGun, mhgun = MhGun}}.

handle_call({lookup, Uuid}, _From, S = #state{vms = Vms0}) ->
    case Vms0 of
        #{Uuid := Name} ->
            {reply, {ok, Name}, S};
        _ ->
            handle_lookup(Uuid, S)
    end.

handle_lookup(Uuid, S = #state{vmgun = VmGun, mhgun = MhGun}) ->
    Stream = gun:get(VmGun, <<"/vms/", Uuid/binary>>),
    case gun:await(VmGun, Stream) of
        {response, fin, Status, _} ->
            {reply, {error, Status}, S};
        {response, nofin, Status, _} when (Status < 300) ->
            {ok, Body} = gun:await_body(VmGun, Stream),
            Vm = jsx:decode(Body, [return_maps]),
            #{<<"alias">> := Alias, <<"owner_uuid">> := UserUuid} = Vm,
            #state{vms = Vms0, users = Users0} = S,
            {OwnerName, Users1} = case Users0 of
                #{UserUuid := Username} ->
                    {Username, Users0};
                _ ->
                    UStream = gun:get(MhGun, <<"/accounts/", UserUuid/binary>>),
                    case gun:await(MhGun, UStream) of
                        {response, fin, _} ->
                            {<<"unknown">>, Users0};
                        {response, nofin, UStatus, _} when (UStatus < 300) ->
                            {ok, UBody} = gun:await_body(MhGun, UStream),
                            UObj = jsx:decode(UBody, [return_maps]),
                            #{<<"account">> := #{<<"login">> := Username}} = UObj,
                            U1 = Users0#{UserUuid => Username},
                            {Username, U1};
                        {response, nofin, _, _} ->
                            {ok, _} = gun:await_body(MhGun, UStream),
                            {<<"unknown">>, Users0}
                    end
            end,
            Name = <<OwnerName/binary, "-", Alias/binary>>,
            Vms1 = Vms0#{Uuid => Name},
            S2 = S#state{vms = Vms1, users = Users1},
            {reply, {ok, Name}, S2};
        {response, nofin, _, _} ->
            {ok, Body} = gun:await_body(VmGun, Stream),
            Err = jsx:decode(Body, [return_maps]),
            {reply, {error, Err}, S}
    end.

handle_cast(Msg, S) ->
    {stop, {unexpected_cast, Msg}, S}.

handle_info(_Msg, S) ->
    {noreply, S}.
