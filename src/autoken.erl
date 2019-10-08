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

-module(autoken).

-export([parse_token/1]).

-include("auditrecs.hrl").

take_cstrings(0, Data) ->
    {[], Data};
take_cstrings(N, Data) ->
    [Next, Rest] = binary:split(Data, [<<0>>]),
    {Others, Rem} = take_cstrings(N - 1, Rest),
    {[Next | Others], Rem}.

ip4_stringify(<<A1, A2, A3, A4>>) ->
    AB1 = integer_to_binary(A1),
    AB2 = integer_to_binary(A2),
    AB3 = integer_to_binary(A3),
    AB4 = integer_to_binary(A4),
    <<AB1/binary, ".", AB2/binary, ".", AB3/binary, ".", AB4/binary>>.

ip6_stringify(Addr) ->
    iolist_to_binary(
        lists:join(":", [integer_to_list(A, 16) || <<A:16/big>> <= Addr])).

hex_stringify(V) ->
    << <<Y>> || <<X:4>> <= V, Y <- integer_to_list(X, 16) >>.
octal_stringify(V) ->
    integer_to_binary(V, 8).

parse_net_port_id(Base, TermPortId) ->
    case TermPortId of
        <<RemotePort:16/little, LocalPort:16/little>> ->
            Base#{ local_port => LocalPort, remote_port => RemotePort };
        <<_:30, RemotePortHigh:2/bitstring,
          _:2, RemotePortLow:14/bitstring, LocalPort:16/little>> ->
            <<RemotePort:16/little>> = <<RemotePortHigh/bitstring,
                RemotePortLow/bitstring>>,
            Base#{ local_port => LocalPort, remote_port => RemotePort };
        _ ->
            PortIdHex = << <<Y>> || <<X:4>> <= TermPortId,
                Y <- integer_to_list(X,16) >>,
            Base#{ port_id => PortIdHex }
    end.

parse_terminal(TermMachAddr, TermPortId) ->
    case TermMachAddr of
        <<0,0,0,0>> ->
            Bits = bit_size(TermPortId),
            <<DevId:Bits/big>> = TermPortId,
            #{ dev => DevId };
        _ ->
            Base = #{ ip => ip4_stringify(TermMachAddr) },
            parse_net_port_id(Base, TermPortId)
    end.

parse_token(Binary) ->
    postproc(parse_token(#{}, Binary)).

parse_token(_, <<AutHeader, Len:32/big, Rem/binary>>)
        when (AutHeader =:= ?AUT_HEADER32) or (AutHeader =:= ?AUT_HEADER64) ->
    InnerLen = Len - 5,
    <<Rem2:InnerLen/binary, _Rest/binary>> = Rem,
    <<Version:8, Rem3/binary>> = Rem2,
    2 = Version,
    <<EvtType:16/big, _EvtMod:16/big, Rem4/binary>> = Rem3,
    case AutHeader of
        ?AUT_HEADER32 ->
            <<Secs:32/big, NSecs:32/big, Rem5/binary>> = Rem4;
        ?AUT_HEADER64 ->
            <<Secs:64/big, NSecs:64/big, Rem5/binary>> = Rem4
    end,
    MSecs = Secs * 1000 + round(NSecs / 1.0e6),
    TS = unicode:characters_to_binary(calendar:system_time_to_rfc3339(MSecs,
        [{unit, millisecond}, {offset, "Z"}]), utf8),
    Z = #{
        version => Version,
        event => audefs:event_to_name(EvtType),
        time => TS
    },
    parse_token(Z, Rem5);

parse_token(_, <<AutHeaderEx, Len:32/big, Rem/binary>>)
        when (AutHeaderEx =:= ?AUT_HEADER32_EX) or (AutHeaderEx =:= ?AUT_HEADER64_EX) ->
    InnerLen = Len - 5,
    <<Rem2:InnerLen/binary, _Rest/binary>> = Rem,
    <<Version:8, Rem3/binary>> = Rem2,
    2 = Version,
    <<EvtType:16/big, _EvtMod:16/big, Rem4/binary>> = Rem3,
    <<AddrLen:32/big, _Addr:AddrLen/binary, Rem5/binary>> = Rem4,
    case AutHeaderEx of
        ?AUT_HEADER32_EX ->
            <<Secs:32/big, NSecs:32/big, Rem6/binary>> = Rem5;
        ?AUT_HEADER64_EX ->
            <<Secs:64/big, NSecs:64/big, Rem6/binary>> = Rem5
    end,
    MSecs = Secs * 1000 + round(NSecs / 1.0e6),
    TS = unicode:characters_to_binary(calendar:system_time_to_rfc3339(MSecs,
        [{unit, millisecond}, {offset, "Z"}]), utf8),
    Z = #{
        version => Version,
        event => audefs:event_to_name(EvtType),
        time => TS
    },
    parse_token(Z, Rem6);

parse_token(Z0, <<?AUT_PATH, Len:16/big, Path:Len/binary, Rem/binary>>) ->
    [RealPath,_] = binary:split(Path, [<<0>>]),
    Z1 = Z0#{path => RealPath},
    parse_token(Z1, Rem);

parse_token(Z0, <<?AUT_EXEC_ARGS, Count:32/big, Rem/binary>>) ->
    {Args, Rem2} = take_cstrings(Count, Rem),
    Z1 = Z0#{exec_args => Args},
    parse_token(Z1, Rem2);

parse_token(Z0, <<?AUT_EXEC_ENV, Count:32/big, Rem/binary>>) ->
    {Args, Rem2} = take_cstrings(Count, Rem),
    Env = lists:foldl(fun (E, Acc) ->
        [N, V] = binary:split(E, [<<"=">>]),
        Acc#{N => V}
    end, #{}, Args),
    Z1 = Z0#{exec_env => Env},
    parse_token(Z1, Rem2);

parse_token(Z0, <<?AUT_ARG, _ArgN, ArgV:32/big-signed, StrLen:16/big,
        Str:StrLen/binary, Rem/binary>>) ->
    [RealStr,_] = binary:split(Str, [<<0>>]),
    Args0 = case Z0 of
        #{args := A} -> A;
        _ -> #{}
    end,
    Args1 = Args0#{RealStr => ArgV},
    Z1 = Z0#{args => Args1},
    parse_token(Z1, Rem);

parse_token(Z0, <<?AUT_ARG64, _ArgN, ArgV:64/big-signed, StrLen:16/big,
        Str:StrLen/binary, Rem/binary>>) ->
    [RealStr,_] = binary:split(Str, [<<0>>]),
    Args0 = case Z0 of
        #{args := A} -> A;
        _ -> #{}
    end,
    Args1 = Args0#{RealStr => ArgV},
    Z1 = Z0#{args => Args1},
    parse_token(Z1, Rem);

parse_token(Z0, <<?AUT_RETURN32, ErrNo, RetVal:32/big-signed, Rem/binary>>) ->
    Z1 = Z0#{return => RetVal, errno => ErrNo},
    parse_token(Z1, Rem);

parse_token(Z0, <<?AUT_RETURN64, ErrNo, RetVal:64/big-signed, Rem/binary>>) ->
    Z1 = Z0#{return => RetVal, errno => ErrNo},
    parse_token(Z1, Rem);

parse_token(Z0, <<?AUT_ATTR32, Mode:32/big, UID:32/big-signed,
        GID:32/big-signed, FsId:32/big, NodeId:32/big,
        Dev:32/big-signed, Rem/binary>>) ->
    Attrs = #{
        mode_octal => octal_stringify(Mode), uid => UID, gid => GID,
        fsid => FsId, inode_hex => hex_stringify(<<NodeId:32/big>>),
        devid => integer_to_binary(Dev)
    },
    Z1 = Z0#{attributes => Attrs},
    parse_token(Z1, Rem);

parse_token(Z0, <<?AUT_ATTR64, Mode:32/big, UID:32/big-signed,
        GID:32/big-signed, FsId:32/big, NodeId:64/big,
        Dev:64/big-signed, Rem/binary>>) ->
    Attrs = #{
        mode_octal => octal_stringify(Mode), uid => UID, gid => GID,
        fsid => FsId, inode_hex => hex_stringify(<<NodeId:64/big>>),
        devid => integer_to_binary(Dev)
    },
    Z1 = Z0#{attributes => Attrs},
    parse_token(Z1, Rem);

parse_token(Z0, <<AutSubject, AuditId:32/big-signed, EUID:32/big-signed,
        EGID:32/big-signed, RUID:32/big-signed, RGID:32/big-signed,
        Pid:32/big, SessId:32/big, Rem0/binary>>)
        when (AutSubject =:= ?AUT_SUBJECT) or (AutSubject =:= ?AUT_SUBJECT64) ->
    case AutSubject of
        ?AUT_SUBJECT ->
            <<TermPortId:4/binary, TermMachAddr:4/binary, Rem/binary>> = Rem0;
        ?AUT_SUBJECT64 ->
            <<TermPortId:8/binary, TermMachAddr:4/binary, Rem/binary>> = Rem0
    end,
    Term = parse_terminal(TermMachAddr, TermPortId),
    Subj = #{
        audit_id => AuditId, uid => EUID, gid => EGID, ruid => RUID,
        rgid => RGID, pid => Pid, session_id => SessId, terminal => Term
    },
    Z1 = Z0#{subject => Subj},
    parse_token(Z1, Rem);

parse_token(Z0, <<AutProcess, AuditId:32/big-signed, EUID:32/big-signed,
        EGID:32/big-signed, RUID:32/big-signed, RGID:32/big-signed, Pid:32/big,
        SessId:32/big, Rem0/binary>>)
        when (AutProcess =:= ?AUT_PROCESS) or (AutProcess =:= ?AUT_PROCESS64) ->
    case AutProcess of
        ?AUT_PROCESS ->
            <<TermPortId:4/binary, TermMachAddr:4/binary, Rem/binary>> = Rem0;
        ?AUT_PROCESS64 ->
            <<TermPortId:8/binary, TermMachAddr:4/binary, Rem/binary>> = Rem0
    end,
    Term = parse_terminal(TermMachAddr, TermPortId),
    Proc = #{
        audit_id => AuditId, uid => EUID, gid => EGID, ruid => RUID,
        rgid => RGID, pid => Pid, session_id => SessId, terminal => Term
    },
    Z1 = Z0#{process => Proc},
    parse_token(Z1, Rem);

parse_token(Z0, <<?AUT_UPRIV, Status, Len:16/big, StrNull:Len/binary,
        Rem/binary>>) ->
    [Str, _] = binary:split(StrNull, [<<0>>]),
    Z1 = Z0#{used_privs => #{privs => Str, success => Status}},
    parse_token(Z1, Rem);

parse_token(Z0, <<?AUT_UAUTH, Len:16/big, StrNull:Len/binary, Rem/binary>>) ->
    [Str, _] = binary:split(StrNull, [<<0>>]),
    Z1 = Z0#{used_auth => Str},
    parse_token(Z1, Rem);

parse_token(Z0, <<?AUT_FMRI, Len:16/big, StrNull:Len/binary, Rem/binary>>) ->
    [Str, _] = binary:split(StrNull, [<<0>>]),
    Z1 = Z0#{fmri => Str},
    parse_token(Z1, Rem);

parse_token(Z0, <<?AUT_TEXT, Len:16/big, StrNull:Len/binary, Rem/binary>>) ->
    [Str, _] = binary:split(StrNull, [<<0>>]),
    Z1 = Z0#{text => Str},
    parse_token(Z1, Rem);

parse_token(Z0, <<?AUT_IN_ADDR, Addr:4/binary, Rem/binary>>) ->
    Z1 = Z0#{addr => ip4_stringify(Addr)},
    parse_token(Z1, Rem);

parse_token(Z0, <<?AUT_IN_ADDR_EX, ?AU_IPV6:32/big, Addr:16/binary, Rem/binary>>) ->
    Z1 = Z0#{addr => ip6_stringify(Addr)},
    parse_token(Z1, Rem);

parse_token(Z0, <<?AUT_PRIV, SetLen:16/big, SetNull:SetLen/binary,
        PrivsLen:16/big, PrivsNull:PrivsLen/binary, Rem/binary>>) ->
    [Set, _] = binary:split(SetNull, [<<0>>]),
    [Privs, _] = binary:split(PrivsNull, [<<0>>]),
    Privs0 = case Z0 of
        #{privs := P} -> P;
        _ -> #{}
    end,
    Privs1 = Privs0#{Set => Privs},
    Z1 = Z0#{privs => Privs1},
    parse_token(Z1, Rem);

parse_token(Z0, <<?AUT_ZONENAME, Len:16/big, StrNull:Len/binary, Rem/binary>>) ->
    [Str, _] = binary:split(StrNull, [<<0>>]),
    Z1 = Z0#{zonename => Str},
    parse_token(Z1, Rem);

parse_token(Z0, <<?AUT_TRAILER, ?AUT_TRAILER_MAGIC:16/big, _Len:32/big>>) ->
    Z0;
parse_token(Z0, <<TokenId, _/binary>>) ->
    Z0#{unknown_token => TokenId};
parse_token(Z, <<>>) -> Z.

postproc(Rec0 = #{event := kill, args := Args0 = #{<<"signal">> := SigId}}) when is_integer(SigId) ->
    Args1 = Args0#{<<"signal">> => audefs:sig_to_name(SigId)},
    Rec1 = Rec0#{args => Args1},
    postproc(Rec1);
postproc(Rec0 = #{event := setppriv, args := Args0 = #{<<"op">> := OpId}}) when is_integer(OpId) ->
    Args1 = Args0#{<<"op">> => audefs:priv_op_to_name(OpId)},
    Rec1 = Rec0#{args => Args1},
    postproc(Rec1);
postproc(Rec0 = #{args := Args0 = #{<<"as_success">> := Mask}}) when is_integer(Mask) ->
    Args1 = Args0#{<<"as_success">> => audefs:pmask_to_names(Mask)},
    Rec1 = Rec0#{args => Args1},
    postproc(Rec1);
postproc(Rec0 = #{args := Args0 = #{<<"as_failure">> := Mask}}) when is_integer(Mask) ->
    Args1 = Args0#{<<"as_failure">> => audefs:pmask_to_names(Mask)},
    Rec1 = Rec0#{args => Args1},
    postproc(Rec1);
postproc(Rec0 = #{event := setaudit_addr, args := Args0 = #{<<"port">> := PortId}}) when is_integer(PortId) ->
    Args1 = Args0#{<<"port">> => parse_net_port_id(#{}, <<PortId:64/big>>)},
    Rec1 = Rec0#{args => Args1},
    postproc(Rec1);
postproc(Rec0 = #{event := auditon_setpmask, args := Args0 = #{<<"setpmask:as_success">> := Mask}}) when is_integer(Mask) ->
    Args1 = Args0#{<<"setpmask:as_success">> => audefs:pmask_to_names(Mask)},
    Rec1 = Rec0#{args => Args1},
    postproc(Rec1);
postproc(Rec0 = #{event := auditon_setpmask, args := Args0 = #{<<"setpmask:as_failure">> := Mask}}) when is_integer(Mask) ->
    Args1 = Args0#{<<"setpmask:as_failure">> => audefs:pmask_to_names(Mask)},
    Rec1 = Rec0#{args => Args1},
    postproc(Rec1);
postproc(Rec0 = #{event := auditon_setkmask, args := Args0 = #{<<"setkmask:as_success">> := Mask}}) when is_integer(Mask) ->
    Args1 = Args0#{<<"setkmask:as_success">> => audefs:pmask_to_names(Mask)},
    Rec1 = Rec0#{args => Args1},
    postproc(Rec1);
postproc(Rec0 = #{event := auditon_setkmask, args := Args0 = #{<<"setkmask:as_failure">> := Mask}}) when is_integer(Mask) ->
    Args1 = Args0#{<<"setkmask:as_failure">> => audefs:pmask_to_names(Mask)},
    Rec1 = Rec0#{args => Args1},
    postproc(Rec1);
postproc(Rec0 = #{errno := ErrNo}) when is_integer(ErrNo) ->
    Rec1 = Rec0#{errno => audefs:errno_to_name(ErrNo)},
    postproc(Rec1);
postproc(Rec) -> Rec.
