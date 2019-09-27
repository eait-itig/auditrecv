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

-module(auditrecv_fsm).
-behaviour(gen_statem).

-vsn(2).

-export([start_link/3]).

-export([init/1, callback_mode/0, terminate/3, code_change/4]).
-export([accept/3, version_neg/3, gss_neg/3, recv_audit/3]).

start_link(LSock, EsHost, EsPort) ->
    gen_statem:start_link(?MODULE, [LSock, EsHost, EsPort], []).

-define(BUF_WINDOW, 5).
-record(state, {sock, lsock, peer, gun, eshost, esport, buf = [], lastseq=0, mech}).

callback_mode() -> [state_functions, state_enter].

init([LSock, EsHost, EsPort]) ->
    {ok, accept, #state{eshost = EsHost, esport = EsPort, lsock = LSock}}.

accept(enter, _, S = #state{lsock = LSock, eshost = EsHost, esport = EsPort}) ->
    {ok, Sock} = gen_tcp:accept(LSock),
    {ok, _} = auditrecv_fsm_sup:start_fsm(),
    {ok, {PeerIp, _Port}} = inet:peername(Sock),
    lager:md([{peer, inet:ntoa(PeerIp)}]),
    lager:info("accepted audit connection from ~p", [PeerIp]),
    {ok, Gun} = gun:open(EsHost, EsPort),
    self() ! accepted,
    {keep_state, S#state{sock = Sock, peer = PeerIp, gun = Gun}};
accept(info, {tcp_closed, Sock}, S = #state{sock = Sock}) ->
    {stop, normal, S};
accept(info, {gun_up, Gun, _}, #state{gun = Gun}) ->
    keep_state_and_data;
accept(info, accepted, S) ->
    {next_state, version_neg, S}.

terminate(_R, _St, #state{sock = undefined}) ->
    ok;
terminate(_R, _St, #state{sock = Sock, gun = Gun}) ->
    gen_tcp:close(Sock),
    gun:close(Gun),
    ok.

version_neg(enter, _, #state{sock = S}) ->
    inet:setopts(S, [{active, once}]),
    keep_state_and_data;
version_neg(info, {tcp, Sock, Data}, S = #state{sock = Sock}) ->
    Versions = binary:split(Data, [<<",">>], [global]),
    case Versions of
        [<<"01">>] ->
            lager:debug("negotiated version 1"),
            ok = gen_tcp:send(Sock, <<"01">>),
            {next_state, gss_neg, S};
        _ ->
            {stop, {unknown_versions, Versions}, S}
    end;
version_neg(info, {gun_up, Gun, _}, #state{gun = Gun}) ->
    keep_state_and_data;
version_neg(info, {tcp_closed, Sock}, S = #state{sock = Sock}) ->
    {stop, normal, S}.

gss_decode(Tag) ->
    {application, constructed, 0, Contents, <<>>} = Tag,
    {universal, primitive, 6, Oid, Rem} = Contents,
    {Oid, Rem}.

-define(DUMMY_OID, <<43,6,1,4,1,42,2,26,1,2>>).
dummy_decode(Rem) ->
    <<DummyType:16/big,DummyData/binary>> = Rem,
    {DummyType, DummyData}.
dummy_encode(Type, Data) ->
    Rem = <<Type:16/big, Data/binary>>,
    der:write_tag({application, constructed, 0,
        {universal, primitive, 6, ?DUMMY_OID, Rem}, <<>>}).

-define(DH1024_OID, <<8#53,6,4,1,8#52,2,8#32,2,5>>).
-define(DH_INIT_CNTX, 1).
-define(DH_ACCEPT_CNTX, 2).
-define(DH_MIC, 3).
-define(DH_WRAP, 4).
-define(DH_DESTROY_CNTX, 5).

xdr_get_padblob(<<Len:32/big, Data:Len/binary, Rem0/binary>>) ->
    Padding = 4 - (Len rem 4),
    <<_:Padding/binary, Rem1/binary>> = Rem0,
    {Data, Rem1}.

dh_decode(Data) ->
    <<Version:32/big, Rem0/binary>> = Data,
    1 = Version,
    <<TokenType:32/big-signed, Rem1/binary>> = Rem0,
    {Ret, Rem2} = dh_decode(TokenType, Rem1),
    <<SigLen:32/big, Sig:SigLen/binary, _/binary>> = Rem2,
    Ret#{verifier => Sig}.

dh_decode(?DH_INIT_CNTX, Rem0) ->
    {Ctx, Rem1} = dh_decode_ctx_desc(Rem0),
    <<Count:32/big, Rem2>> = Rem1,
    {Keys, Rem3} = lists:foldl(fun (_N, {KeysAcc, BinAcc}) ->
        <<Key:8/binary, Rest/binary>> = BinAcc,
        {KeysAcc ++ [Key], Rest}
    end, {[], Rem2}, lists:seq(1, Count)),
    {Ctx#{keys => Keys}, Rem3}.

dh_decode_ctx_desc(Rem0) ->
    {Remote, Rem1} = xdr_get_padblob(Rem0),
    {Local, Rem2} = xdr_get_padblob(Rem1),
    <<Flags:32/big, Expire:32/big, Rem3/binary>> = Rem2,
    <<InitiatorType:32/big, Rem4/binary>> = Rem3,
    {InitiatorAddr, Rem5} = xdr_get_padblob(Rem4),
    <<AcceptorType:32/big, Rem6/binary>> = Rem5,
    {AcceptorAddr, Rem7} = xdr_get_padblob(Rem6),
    {AppData, Rem8} = xdr_get_padblob(Rem7),
    {#{
        remote => Remote, local => Local, flags => Flags, expire => Expire,
        appdata => AppData, initiator => {InitiatorType, InitiatorAddr},
        acceptor => {AcceptorType, AcceptorAddr}
    }, Rem8}.

gss_neg(enter, _, #state{sock = S}) ->
    inet:setopts(S, [{active, once}]),
    keep_state_and_data;
gss_neg(info, {tcp, Sock, Data}, S = #state{sock = Sock}) ->
    Pkt = der:read_tag(Data),
    case gss_decode(Pkt) of
        {?DUMMY_OID, Inner} ->
            case dummy_decode(Inner) of
                {0, <<"0",0>>} ->
                    {next_state, recv_audit, S#state{mech = dummy}};
                {0, <<"1",0>>} ->
                    RespPkt = dummy_encode(0, <<"0", 0>>),
                    ok = gen_tcp:send(Sock, RespPkt),
                    {next_state, recv_audit, S#state{mech = dummy}};
                Pkt ->
                    lager:debug("unknown message: ~p", [Pkt]),
                    {repeat_state, S}
            end;
        {?DH1024_OID, Inner} ->
            DhPkt = dh_decode(Inner),
            lager:debug("gss-dh message: ~p", [DhPkt]),
            {repeat_state, S#state{mech = dh1024}};
        {Oid, _} ->
            lager:debug("unknown gss oid: ~p", [Oid]),
            {repeat_state, S}
    end;
gss_neg(info, {gun_up, Gun, _}, #state{gun = Gun}) ->
    keep_state_and_data;
gss_neg(info, {tcp_closed, Sock}, S = #state{sock = Sock}) ->
    {stop, normal, S}.

bulk_and_ack(S0 = #state{gun = Gun, buf = B0}) ->
    Body = make_bulk_body(B0),
    Hdrs = [{<<"content-type">>, <<"application/x-ndjson">>}],
    Stream = gun:post(Gun, "/_bulk", Hdrs, Body),
    case gun:await(Gun, Stream) of
        {response, fin, Status, _} ->
            lager:error("bulk returned http ~p", [Status]);
        {response, nofin, _Status, _} ->
            {ok, RetBody} = gun:await_body(Gun, Stream),
            Ret = jsx:decode(RetBody, [return_maps]),
            case Ret of
                #{<<"errors">> := false} -> ok;
                _ ->
                    lager:error("bulk returned errors: ~p", [Ret])
            end
    end,
    S1 = lists:foldl(fun send_ack/2, S0, B0),
    lager:trace("ack'd records ~p", [[SN || {SN,_} <- B0]]),
    S1#state{buf = []}.

recv_audit(enter, _, #state{sock = S}) ->
    inet:setopts(S, [{active, once}]),
    {keep_state_and_data, [{state_timeout, 1000, idle}]};
recv_audit(info, {tcp, Sock, Data}, S0 = #state{sock = Sock, buf = B0}) ->
    Pkt = der:read_tag(Data),
    case gss_decode(Pkt) of
        {?DUMMY_OID, Inner} ->
            {0, InnerData} = dummy_decode(Inner)
    end,
    case InnerData of
        <<SeqNr:64/big, AuditRec/binary>> ->
            lager:trace("got audit rec ~p (~p bytes)", [SeqNr, size(AuditRec)]),
            S1 = S0#state{lastseq = SeqNr},
            Rec0 = autoken:parse_token(AuditRec),
            Rec1 = Rec0#{from => list_to_binary(inet:ntoa(S0#state.peer))},
            Rec2 = case Rec1 of
                #{zonename := Z} ->
                    case vmlookup:lookup(Z) of
                        {ok, Z2} -> Rec1#{zonealias => Z2};
                        _ -> Rec1
                    end;
                _ -> Rec1
            end,
            B1 = [{SeqNr, Rec2} | B0],
            if
                (length(B1) > ?BUF_WINDOW) ->
                    S2 = bulk_and_ack(S1#state{buf = B1}),
                    {repeat_state, S2};
                true ->
                    S2 = S1#state{buf = B1},
                    {repeat_state, S2}
            end;
        Pkt ->
            lager:error("unknown message: ~p", [Pkt]),
            {repeat_state, S0}
    end;
recv_audit(state_timeout, idle, S = #state{buf = B0}) when (length(B0) > 0) ->
    S1 = bulk_and_ack(S),
    {keep_state, S1};
recv_audit(state_timeout, _, #state{}) ->
    keep_state_and_data;
recv_audit(info, {gun_up, Gun, _}, #state{gun = Gun}) ->
    keep_state_and_data;
recv_audit(info, {tcp_closed, Sock}, S = #state{sock = Sock}) ->
    lager:info("stream from ~p closed", [S#state.peer]),
    {stop, normal, S}.

send_ack({SeqNr, _}, S = #state{sock = Sock}) ->
    Token = dummy_encode(0, <<"dummy_gss_sign">>),
    AckPkt = <<SeqNr:64/big, Token/binary>>,
    ok = gen_tcp:send(Sock, AckPkt),
    S.

make_bulk_body([]) -> <<>>;
make_bulk_body([{_, Obj} | Rem]) ->
    #{time := TS} = Obj,
    <<Year:4/binary, "-", Month:2/binary, "-", Day:2/binary, "T", _/binary>> = TS,
    Index = <<"audit-", Year/binary, "-", Month/binary, "-", Day/binary>>,
    Action = #{index => #{'_index' => Index, '_type' => <<"audit">>}},
    ActionJson = jsx:encode(Action),
    ObjJson = jsx:encode(Obj),
    Rest = make_bulk_body(Rem),
    <<ActionJson/binary, "\n", ObjJson/binary, "\n", Rest/binary>>.

code_change(_, State, {state, Sock, LSock, Peer, Gun, Buf}, _) ->
    {ok, State,
        #state{sock = Sock, lsock = LSock, peer = Peer, gun = Gun, buf = Buf}}.
