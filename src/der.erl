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

-module(der).

-export([read_tag/1, write_tag/1]).

read_len(<<0:1, L:7, Data:L/binary, Rem/binary>>) when (L < (1 bsl 7)) ->
  {Data, Rem};
read_len(<<1:1, LL:7, L:LL/big-unit:8, Data:L/binary, Rem/binary>>) ->
  {Data, Rem}.

write_len(Data) ->
  L = byte_size(Data),
  if
    (L < (1 bsl 7)) ->
      <<0:1, L:7, Data/binary>>;
    true ->
      Len = binary:encode_unsigned(L),
      LL = byte_size(Len),
      <<1:1, LL:7, Len/binary, Data/binary>>
  end.

read_tag_next(<<1:1, Bits:7, Rem/binary>>) ->
  {Cont, Rest} = read_tag_next(Rem),
  {<<Bits:7, Cont/bitstring>>, Rest};
read_tag_next(<<0:1, Bits:7, Rem/binary>>) ->
  {<<Bits:7>>, Rem}.

type_to_atom(Type) ->
  case Type of
    2#00 -> universal;
    2#01 -> application;
    2#10 -> context;
    2#11 -> private
  end.
atom_to_type(universal) -> 2#00;
atom_to_type(application) -> 2#01;
atom_to_type(context) -> 2#10;
atom_to_type(private) -> 2#11.

cons_to_atom(1) -> constructed;
cons_to_atom(0) -> primitive.
atom_to_cons(constructed) -> 1;
atom_to_cons(primitive) -> 0.

read_tag(<<Type:2, Cons:1, 2#11111:5, Rem/binary>>) ->
  {Tag, Rem2} = read_tag_next(Rem),
  {Data, Rem3} = read_len(Rem2),
  Data2 = case cons_to_atom(Cons) of
    constructed -> read_tag(Data);
    primitive -> Data
  end,
  {type_to_atom(Type), cons_to_atom(Cons), Tag, Data2, Rem3};
read_tag(<<Type:2, Cons:1, Tag:5, Rem/binary>>) ->
  {Data, Rem2} = read_len(Rem),
  Data2 = case cons_to_atom(Cons) of
    constructed -> read_tag(Data);
    primitive -> Data
  end,
  {type_to_atom(Type), cons_to_atom(Cons), Tag, Data2, Rem2}.

write_tag({TypeAtom, ConsAtom, Tag, Data, Extra}) when (Tag < 2#11111) ->
  Data2 = case ConsAtom of
    constructed -> write_tag(Data);
    primitive -> Data
  end,
  Data3 = write_len(Data2),
  Type = atom_to_type(TypeAtom),
  Cons = atom_to_cons(ConsAtom),
  <<Type:2, Cons:1, Tag:5, Data3/binary, Extra/binary>>.
