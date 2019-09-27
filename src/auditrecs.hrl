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

-define(AUP_BINARY, 0).
-define(AUP_DECIMAL, 2).
-define(AUP_HEX, 3).
-define(AUP_OCTAL, 1).
-define(AUP_STRING, 4).
-define(AUR_BYTE, 0).
-define(AUR_CHAR, 0).
-define(AUR_INT, 2).
-define(AUR_INT32, 2).
-define(AUR_INT64, 3).
-define(AUR_SHORT, 1).
-define(AUT_ACE, 16#35).
-define(AUT_ACL, 16#30).
-define(AUT_ARG, 16#2D).
-define(AUT_ARG32, 16#2D).
-define(AUT_ARG64, 16#71).
-define(AUT_ATTR, 16#31).
-define(AUT_ATTR32, 16#3E).
-define(AUT_ATTR64, 16#73).
-define(AUT_CMD, 16#51).
-define(AUT_DATA, 16#21).
-define(AUT_EXEC_ARGS, 16#3C).
-define(AUT_EXEC_ENV, 16#3D).
-define(AUT_EXIT, 16#52).
-define(AUT_FMRI, 16#20).
-define(AUT_GROUPS, 16#34).
-define(AUT_HEADER, 16#14).
-define(AUT_HEADER32, 16#14).
-define(AUT_HEADER32_EX, 16#15).
-define(AUT_HEADER64, 16#74).
-define(AUT_HEADER64_EX, 16#79).
-define(AUT_HOST, 16#70).
-define(AUT_IN_ADDR, 16#2A).
-define(AUT_IN_ADDR_EX, 16#7e).
-define(AUT_INVALID, 16#00).
-define(AUT_IP, 16#2B).
-define(AUT_IPC, 16#22).
-define(AUT_IPC_PERM, 16#32).
-define(AUT_IPORT, 16#2C).
-define(AUT_LABEL, 16#33).
-define(AUT_LIAISON, 16#3A).
-define(AUT_NEWGROUPS, 16#3B).
-define(AUT_OHEADER, 16#12).
-define(AUT_OPAQUE, 16#29).
-define(AUT_OTHER_FILE, 16#11).
-define(AUT_OTHER_FILE32, 16#11).
-define(AUT_OTHER_FILE64, 16#78).
-define(AUT_PATH, 16#23).
-define(AUT_PRIV, 16#38).
-define(AUT_PROCESS, 16#26).
-define(AUT_PROCESS32, 16#26).
-define(AUT_PROCESS32_EX, 16#7b).
-define(AUT_PROCESS64, 16#77).
-define(AUT_PROCESS64_EX, 16#7d).
-define(AUT_RETURN, 16#27).
-define(AUT_RETURN32, 16#27).
-define(AUT_RETURN64, 16#72).
-define(AUT_SECFLAGS, 16#62).
-define(AUT_SEQ, 16#2F).
-define(AUT_SOCKET, 16#2E).
-define(AUT_SOCKET_EX, 16#7f).
-define(AUT_SUBJECT, 16#24).
-define(AUT_SUBJECT32, 16#24).
-define(AUT_SUBJECT32_EX, 16#7a).
-define(AUT_SUBJECT64, 16#75).
-define(AUT_SUBJECT64_EX, 16#7c).
-define(AUT_TEXT, 16#28).
-define(AUT_TID, 16#61).
-define(AUT_TRAILER, 16#13).
-define(AUT_UAUTH, 16#3F).
-define(AUT_UPRIV, 16#39).
-define(AUT_USER, 16#36).
-define(AUT_XATOM, 16#40).
-define(AUT_XATPATH, 16#25).
-define(AUT_XCLIENT, 16#4B).
-define(AUT_XCOLORMAP, 16#44).
-define(AUT_XCURSOR, 16#45).
-define(AUT_XFONT, 16#46).
-define(AUT_XGC, 16#47).
-define(AUT_XOBJ, 16#41).
-define(AUT_XPIXMAP, 16#48).
-define(AUT_XPROPERTY, 16#49).
-define(AUT_XPROTO, 16#42).
-define(AUT_XSELECT, 16#43).
-define(AUT_XWINDOW, 16#4A).
-define(AUT_ZONENAME, 16#60).

-define(AU_IPV4, 4).
-define(AU_IPV6, 16).

-define(AUT_TRAILER_MAGIC, 16#B105).
