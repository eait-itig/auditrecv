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

-module(audefs).

-export([event_to_name/1, sig_to_name/1, priv_op_to_name/1, errno_to_name/1,
    pmask_to_names/1]).

event_to_name(0) -> null;
event_to_name(1) -> exit;
event_to_name(2) -> forkall;
event_to_name(3) -> open;
event_to_name(4) -> creat;
event_to_name(5) -> link;
event_to_name(6) -> unlink;
event_to_name(7) -> exec;
event_to_name(8) -> chdir;
event_to_name(9) -> mknod;
event_to_name(10) -> chmod;
event_to_name(11) -> chown;
event_to_name(12) -> umount;
event_to_name(13) -> junk;
event_to_name(14) -> access;
event_to_name(15) -> kill;
event_to_name(16) -> stat;
event_to_name(17) -> lstat;
event_to_name(18) -> acct;
event_to_name(19) -> mctl;
event_to_name(20) -> reboot;
event_to_name(21) -> symlink;
event_to_name(22) -> readlink;
event_to_name(23) -> execve;
event_to_name(24) -> chroot;
event_to_name(25) -> vfork;
event_to_name(26) -> setgroups;
event_to_name(27) -> setpgrp;
event_to_name(28) -> swapon;
event_to_name(29) -> sethostname;
event_to_name(30) -> fcntl;
event_to_name(31) -> setpriority;
event_to_name(32) -> connect;
event_to_name(33) -> accept;
event_to_name(34) -> bind;
event_to_name(35) -> setsockopt;
event_to_name(36) -> vtrace;
event_to_name(37) -> settimeofday;
event_to_name(38) -> fchown;
event_to_name(39) -> fchmod;
event_to_name(40) -> setreuid;
event_to_name(41) -> setregid;
event_to_name(42) -> rename;
event_to_name(43) -> truncate;
event_to_name(44) -> ftruncate;
event_to_name(45) -> flock;
event_to_name(46) -> shutdown;
event_to_name(47) -> mkdir;
event_to_name(48) -> rmdir;
event_to_name(49) -> utimes;
event_to_name(50) -> adjtime;
event_to_name(51) -> setrlimit;
event_to_name(52) -> killpg;
event_to_name(53) -> nfs_svc;
event_to_name(54) -> statfs;
event_to_name(55) -> fstatfs;
event_to_name(56) -> unmount;
event_to_name(57) -> async_daemon;
event_to_name(58) -> nfs_getfh;
event_to_name(59) -> setdomainname;
event_to_name(60) -> quotactl;
event_to_name(61) -> exportfs;
event_to_name(62) -> mount;
event_to_name(63) -> semsys;
event_to_name(64) -> msgsys;
event_to_name(65) -> shmsys;
event_to_name(66) -> bsmsys;
event_to_name(67) -> rfssys;
event_to_name(68) -> fchdir;
event_to_name(69) -> fchroot;
event_to_name(70) -> vpixsys;
event_to_name(71) -> pathconf;
event_to_name(72) -> open_r;
event_to_name(73) -> open_rc;
event_to_name(74) -> open_rt;
event_to_name(75) -> open_rtc;
event_to_name(76) -> open_w;
event_to_name(77) -> open_wc;
event_to_name(78) -> open_wt;
event_to_name(79) -> open_wtc;
event_to_name(80) -> open_rw;
event_to_name(81) -> open_rwc;
event_to_name(82) -> open_rwt;
event_to_name(83) -> open_rwtc;
event_to_name(84) -> msgctl;
event_to_name(85) -> msgctl_rmid;
event_to_name(86) -> msgctl_set;
event_to_name(87) -> msgctl_stat;
event_to_name(88) -> msgget;
event_to_name(89) -> msgrcv;
event_to_name(90) -> msgsnd;
event_to_name(91) -> shmctl;
event_to_name(92) -> shmctl_rmid;
event_to_name(93) -> shmctl_set;
event_to_name(94) -> shmctl_stat;
event_to_name(95) -> shmget;
event_to_name(96) -> shmat;
event_to_name(97) -> shmdt;
event_to_name(98) -> semctl;
event_to_name(99) -> semctl_rmid;
event_to_name(100) -> semctl_set;
event_to_name(101) -> semctl_stat;
event_to_name(102) -> semctl_getncnt;
event_to_name(103) -> semctl_getpid;
event_to_name(104) -> semctl_getval;
event_to_name(105) -> semctl_getall;
event_to_name(106) -> semctl_getzcnt;
event_to_name(107) -> semctl_setval;
event_to_name(108) -> semctl_setall;
event_to_name(109) -> semget;
event_to_name(110) -> semop;
event_to_name(111) -> core;
event_to_name(112) -> close;
event_to_name(113) -> systemboot;
event_to_name(114) -> async_daemon_exit;
event_to_name(115) -> nfssvc_exit;
event_to_name(116) -> pfexec;
event_to_name(117) -> open_s;
event_to_name(118) -> open_e;
event_to_name(130) -> getauid;
event_to_name(131) -> setauid;
event_to_name(132) -> getaudit;
event_to_name(133) -> setaudit;
event_to_name(134) -> getuseraudit;
event_to_name(135) -> setuseraudit;
event_to_name(136) -> auditsvc;
event_to_name(138) -> auditon;
event_to_name(139) -> auditon_gtermid;
event_to_name(140) -> auditon_stermid;
event_to_name(141) -> auditon_gpolicy;
event_to_name(142) -> auditon_spolicy;
event_to_name(143) -> auditon_gestate;
event_to_name(144) -> auditon_sestate;
event_to_name(145) -> auditon_gqctrl;
event_to_name(146) -> auditon_sqctrl;
event_to_name(147) -> getkernstate;
event_to_name(148) -> setkernstate;
event_to_name(149) -> getportaudit;
event_to_name(150) -> auditstat;
event_to_name(153) -> enterprom;
event_to_name(154) -> exitprom;
event_to_name(158) -> ioctl;
event_to_name(173) -> oneside;
event_to_name(174) -> msggetl;
event_to_name(175) -> msgrcvl;
event_to_name(176) -> msgsndl;
event_to_name(177) -> semgetl;
event_to_name(178) -> shmgetl;
event_to_name(183) -> socket;
event_to_name(184) -> sendto;
event_to_name(185) -> pipe;
event_to_name(186) -> socketpair;
event_to_name(187) -> send;
event_to_name(188) -> sendmsg;
event_to_name(189) -> recv;
event_to_name(190) -> recvmsg;
event_to_name(191) -> recvfrom;
event_to_name(192) -> read;
event_to_name(193) -> getdents;
event_to_name(194) -> lseek;
event_to_name(195) -> write;
event_to_name(196) -> writev;
event_to_name(197) -> nfs;
event_to_name(198) -> readv;
event_to_name(199) -> ostat;
event_to_name(200) -> setuid;
event_to_name(201) -> stime;
event_to_name(202) -> utime;
event_to_name(203) -> nice;
event_to_name(204) -> osetpgrp;
event_to_name(205) -> setgid;
event_to_name(206) -> readl;
event_to_name(207) -> readvl;
event_to_name(208) -> fstat;
event_to_name(209) -> dup2;
event_to_name(210) -> mmap;
event_to_name(211) -> audit;
event_to_name(212) -> priocntlsys;
event_to_name(213) -> munmap;
event_to_name(214) -> setegid;
event_to_name(215) -> seteuid;
event_to_name(216) -> putmsg;
event_to_name(217) -> getmsg;
event_to_name(218) -> putpmsg;
event_to_name(219) -> getpmsg;
event_to_name(220) -> auditsys;
event_to_name(221) -> auditon_getkmask;
event_to_name(222) -> auditon_setkmask;
event_to_name(223) -> auditon_getcwd;
event_to_name(224) -> auditon_getcar;
event_to_name(225) -> auditon_getstat;
event_to_name(226) -> auditon_setstat;
event_to_name(227) -> auditon_setumask;
event_to_name(228) -> auditon_setsmask;
event_to_name(229) -> auditon_getcond;
event_to_name(230) -> auditon_setcond;
event_to_name(231) -> auditon_getclass;
event_to_name(232) -> auditon_setclass;
event_to_name(233) -> fusers;
event_to_name(234) -> statvfs;
event_to_name(235) -> xstat;
event_to_name(236) -> lxstat;
event_to_name(237) -> lchown;
event_to_name(238) -> memcntl;
event_to_name(239) -> sysinfo;
event_to_name(240) -> xmknod;
event_to_name(241) -> fork1;
event_to_name(242) -> modctl;
event_to_name(243) -> modload;
event_to_name(244) -> modunload;
event_to_name(245) -> modconfig;
event_to_name(246) -> modaddmaj;
event_to_name(247) -> sockaccept;
event_to_name(248) -> sockconnect;
event_to_name(249) -> socksend;
event_to_name(250) -> sockreceive;
event_to_name(251) -> aclset;
event_to_name(252) -> faclset;
event_to_name(253) -> doorfs;
event_to_name(254) -> doorfs_door_call;
event_to_name(255) -> doorfs_door_return;
event_to_name(256) -> doorfs_door_create;
event_to_name(257) -> doorfs_door_revoke;
event_to_name(258) -> doorfs_door_info;
event_to_name(259) -> doorfs_door_cred;
event_to_name(260) -> doorfs_door_bind;
event_to_name(261) -> doorfs_door_unbind;
event_to_name(262) -> p_online;
event_to_name(263) -> processor_bind;
event_to_name(264) -> inst_sync;
event_to_name(265) -> sockconfig;
event_to_name(266) -> setaudit_addr;
event_to_name(267) -> getaudit_addr;
event_to_name(268) -> umount2;
event_to_name(269) -> fsat;
event_to_name(270) -> openat_r;
event_to_name(271) -> openat_rc;
event_to_name(272) -> openat_rt;
event_to_name(273) -> openat_rtc;
event_to_name(274) -> openat_w;
event_to_name(275) -> openat_wc;
event_to_name(276) -> openat_wt;
event_to_name(277) -> openat_wtc;
event_to_name(278) -> openat_rw;
event_to_name(279) -> openat_rwc;
event_to_name(280) -> openat_rwt;
event_to_name(281) -> openat_rwtc;
event_to_name(282) -> renameat;
event_to_name(283) -> fstatat;
event_to_name(284) -> fchownat;
event_to_name(285) -> futimesat;
event_to_name(286) -> unlinkat;
event_to_name(287) -> clock_settime;
event_to_name(288) -> ntp_adjtime;
event_to_name(289) -> setppriv;
event_to_name(290) -> moddevplcy;
event_to_name(291) -> modaddpriv;
event_to_name(292) -> cryptoadm;
event_to_name(293) -> configkssl;
event_to_name(294) -> brandsys;
event_to_name(295) -> pf_policy_addrule;
event_to_name(296) -> pf_policy_delrule;
event_to_name(297) -> pf_policy_clone;
event_to_name(298) -> pf_policy_flip;
event_to_name(299) -> pf_policy_flush;
event_to_name(300) -> pf_policy_algs;
event_to_name(301) -> portfs;
event_to_name(302) -> labelsys_tnrh;
event_to_name(303) -> labelsys_tnrhtp;
event_to_name(304) -> labelsys_tnmlp;
event_to_name(305) -> portfs_associate;
event_to_name(306) -> portfs_dissociate;
event_to_name(307) -> setsid;
event_to_name(308) -> setpgid;
event_to_name(309) -> faccessat;
event_to_name(310) -> auditon_getamask;
event_to_name(311) -> auditon_setamask;
event_to_name(312) -> psecflags;
event_to_name(313) -> auditon_getpinfo;
event_to_name(314) -> auditon_setpmask;
event_to_name(315) -> auditon_getkaudit;
event_to_name(316) -> auditon_setkaudit;
event_to_name(317) -> auditon_other;
event_to_name(6144) -> at_create;
event_to_name(6145) -> at_delete;
event_to_name(6146) -> at_perm;
event_to_name(6147) -> cron_invoke;
event_to_name(6148) -> crontab_create;
event_to_name(6149) -> crontab_delete;
event_to_name(6150) -> crontab_perm;
event_to_name(6151) -> inetd_connect;
event_to_name(6152) -> login;
event_to_name(6153) -> logout;
event_to_name(6154) -> telnet;
event_to_name(6155) -> rlogin;
event_to_name(6156) -> mountd_mount;
event_to_name(6157) -> mountd_umount;
event_to_name(6158) -> rshd;
event_to_name(6159) -> su;
event_to_name(6160) -> halt_solaris;
event_to_name(6161) -> reboot_solaris;
event_to_name(6162) -> rexecd;
event_to_name(6163) -> passwd;
event_to_name(6164) -> rexd;
event_to_name(6165) -> ftpd;
event_to_name(6166) -> init_solaris;
event_to_name(6167) -> uadmin_solaris;
event_to_name(6168) -> shutdown_solaris;
event_to_name(6169) -> poweroff_solaris;
event_to_name(6170) -> crontab_mod;
event_to_name(6171) -> ftpd_logout;
event_to_name(6172) -> ssh;
event_to_name(6173) -> role_login;
event_to_name(6180) -> prof_cmd;
event_to_name(6181) -> filesystem_add;
event_to_name(6182) -> filesystem_delete;
event_to_name(6183) -> filesystem_modify;
event_to_name(6184) -> network_add;
event_to_name(6185) -> network_delete;
event_to_name(6186) -> network_modify;
event_to_name(6187) -> printer_add;
event_to_name(6188) -> printer_delete;
event_to_name(6189) -> printer_modify;
event_to_name(6190) -> scheduledjob_add;
event_to_name(6191) -> scheduledjob_delete;
event_to_name(6192) -> scheduledjob_modify;
event_to_name(6193) -> serialport_add;
event_to_name(6194) -> serialport_delete;
event_to_name(6195) -> serialport_modify;
event_to_name(6196) -> usermgr_add;
event_to_name(6197) -> usermgr_delete;
event_to_name(6198) -> usermgr_modify;
event_to_name(6199) -> uauth;
event_to_name(6200) -> allocate_succ;
event_to_name(6201) -> allocate_fail;
event_to_name(6202) -> deallocate_succ;
event_to_name(6203) -> deallocate_fail;
event_to_name(6205) -> listdevice_succ;
event_to_name(6206) -> listdevice_fail;
event_to_name(6207) -> create_user;
event_to_name(6208) -> modify_user;
event_to_name(6209) -> delete_user;
event_to_name(6210) -> disable_user;
event_to_name(6211) -> enable_user;
event_to_name(6212) -> newgrp_login;
event_to_name(6213) -> admin_authenticate;
event_to_name(6214) -> kadmind_auth;
event_to_name(6215) -> kadmind_unauth;
event_to_name(6216) -> krb5kdc_as_req;
event_to_name(6217) -> krb5kdc_tgs_req;
event_to_name(6218) -> krb5kdc_tgs_req_2ndtktmm;
event_to_name(6219) -> krb5kdc_tgs_req_alt_tgt;
event_to_name(6220) -> smserverd;
event_to_name(6221) -> screenlock;
event_to_name(6222) -> screenunlock;
event_to_name(6223) -> zone_state;
event_to_name(6224) -> inetd_copylimit;
event_to_name(6225) -> inetd_failrate;
event_to_name(6226) -> inetd_ratelimit;
event_to_name(6227) -> zlogin;
event_to_name(6228) -> su_logout;
event_to_name(6229) -> role_logout;
event_to_name(6230) -> attach;
event_to_name(6231) -> detach;
event_to_name(6232) -> remove;
event_to_name(6233) -> pool_import;
event_to_name(6234) -> pool_export;
event_to_name(6235) -> dladm_create_secobj;
event_to_name(6236) -> dladm_delete_secobj;
event_to_name(6237) -> uadmin_shutdown;
event_to_name(6238) -> uadmin_reboot;
event_to_name(6239) -> uadmin_dump;
event_to_name(6240) -> uadmin_freeze;
event_to_name(6241) -> uadmin_remount;
event_to_name(6242) -> uadmin_ftrace;
event_to_name(6243) -> uadmin_swapctl;
event_to_name(6244) -> smbd_session;
event_to_name(6245) -> smbd_logoff;
event_to_name(6246) -> vscan_quarantine;
event_to_name(6247) -> ndmp_connect;
event_to_name(6248) -> ndmp_disconnect;
event_to_name(6249) -> ndmp_backup;
event_to_name(6250) -> ndmp_restore;
event_to_name(6251) -> cpu_ondemand;
event_to_name(6252) -> cpu_performance;
event_to_name(6253) -> cpu_threshold;
event_to_name(6254) -> uadmin_thaw;
event_to_name(6255) -> uadmin_config;
event_to_name(6260) -> smf_enable;
event_to_name(6261) -> smf_tmp_enable;
event_to_name(6262) -> smf_disable;
event_to_name(6263) -> smf_tmp_disable;
event_to_name(6264) -> smf_restart;
event_to_name(6265) -> smf_refresh;
event_to_name(6266) -> smf_clear;
event_to_name(6267) -> smf_degrade;
event_to_name(6268) -> smf_immediate_degrade;
event_to_name(6269) -> smf_maintenance;
event_to_name(6270) -> smf_immediate_maintenance;
event_to_name(6271) -> smf_immtmp_maintenance;
event_to_name(6272) -> smf_tmp_maintenance;
event_to_name(6273) -> smf_milestone;
event_to_name(6275) -> smf_read_prop;
event_to_name(6280) -> smf_create;
event_to_name(6281) -> smf_delete;
event_to_name(6282) -> smf_create_pg;
event_to_name(6283) -> smf_create_npg;
event_to_name(6284) -> smf_delete_pg;
event_to_name(6285) -> smf_delete_npg;
event_to_name(6286) -> smf_create_snap;
event_to_name(6287) -> smf_delete_snap;
event_to_name(6288) -> smf_attach_snap;
event_to_name(6289) -> smf_annotation;
event_to_name(6290) -> smf_create_prop;
event_to_name(6291) -> smf_change_prop;
event_to_name(6292) -> smf_delete_prop;
event_to_name(6300) -> nwam_enable;
event_to_name(6301) -> nwam_disable;
event_to_name(6310) -> ilb_create_healthcheck;
event_to_name(6311) -> ilb_delete_healthcheck;
event_to_name(6312) -> ilb_create_rule;
event_to_name(6313) -> ilb_delete_rule;
event_to_name(6314) -> ilb_disable_rule;
event_to_name(6315) -> ilb_enable_rule;
event_to_name(6316) -> ilb_add_server;
event_to_name(6317) -> ilb_disable_server;
event_to_name(6318) -> ilb_enable_server;
event_to_name(6319) -> ilb_remove_server;
event_to_name(6320) -> ilb_create_servergroup;
event_to_name(6321) -> ilb_delete_servergroup;
event_to_name(6330) -> netcfg_update;
event_to_name(6331) -> netcfg_remove;
event_to_name(6400) -> tpm_takeownership;
event_to_name(6401) -> tpm_clearowner;
event_to_name(6402) -> tpm_setoperatorauth;
event_to_name(6403) -> tpm_setownerinstall;
event_to_name(6404) -> tpm_selftestfull;
event_to_name(6405) -> tpm_certifyselftest;
event_to_name(6406) -> tpm_continueselftest;
event_to_name(6407) -> tpm_ownersetdisable;
event_to_name(6408) -> tpm_ownerclear;
event_to_name(6409) -> tpm_disableownerclear;
event_to_name(6410) -> tpm_forceclear;
event_to_name(6411) -> tpm_disableforceclear;
event_to_name(6412) -> tpm_physicaldisable;
event_to_name(6413) -> tpm_physicalenable;
event_to_name(6414) -> tpm_physicaldeactivate;
event_to_name(6415) -> tpm_settempdeactivated;
event_to_name(6416) -> tpm_settempdeactivated2;
event_to_name(6417) -> tpm_physicalpresence;
event_to_name(6418) -> tpm_fieldupgrade;
event_to_name(6419) -> tpm_resetlockvalue;
event_to_name(6500) -> hotplug_state;
event_to_name(6501) -> hotplug_set;
event_to_name(Id) -> integer_to_binary(Id).

sig_to_name(1) -> sighup;
sig_to_name(2) -> sigint;
sig_to_name(3) -> sigquit;
sig_to_name(4) -> sigill;
sig_to_name(5) -> sigtrap;
sig_to_name(6) -> sigabrt;
sig_to_name(7) -> sigemt;
sig_to_name(8) -> sigfpe;
sig_to_name(9) -> sigkill;
sig_to_name(10) -> sigbus;
sig_to_name(11) -> sigsegv;
sig_to_name(12) -> sigsys;
sig_to_name(13) -> sigpipe;
sig_to_name(14) -> sigalrm;
sig_to_name(15) -> sigterm;
sig_to_name(16) -> sigusr1;
sig_to_name(17) -> sigusr2;
sig_to_name(18) -> sigchld;
sig_to_name(19) -> sigpwr;
sig_to_name(20) -> sigwinch;
sig_to_name(21) -> sigurg;
sig_to_name(22) -> sigpoll;
sig_to_name(23) -> sigstop;
sig_to_name(24) -> sigtstp;
sig_to_name(25) -> sigcont;
sig_to_name(26) -> sigttin;
sig_to_name(27) -> sigttou;
sig_to_name(28) -> sigvtalrm;
sig_to_name(29) -> sigprof;
sig_to_name(30) -> sigxcpu;
sig_to_name(31) -> sigxfsz;
sig_to_name(32) -> sigwaiting;
sig_to_name(33) -> siglwp;
sig_to_name(34) -> sigfreeze;
sig_to_name(35) -> sigthaw;
sig_to_name(36) -> sigcancel;
sig_to_name(37) -> siglost;
sig_to_name(38) -> sigxres;
sig_to_name(39) -> sigjvm1;
sig_to_name(40) -> sigjvm2;
sig_to_name(41) -> siginfo;
sig_to_name(N) -> integer_to_binary(N).

priv_op_to_name(0) -> priv_on;
priv_op_to_name(1) -> priv_off;
priv_op_to_name(2) -> priv_set;
priv_op_to_name(N) -> integer_to_binary(N).

errno_to_name(1) -> eperm;
errno_to_name(2) -> enoent;
errno_to_name(3) -> esrch;
errno_to_name(4) -> eintr;
errno_to_name(5) -> eio;
errno_to_name(6) -> enxio;
errno_to_name(7) -> e2big;
errno_to_name(8) -> enoexec;
errno_to_name(9) -> ebadf;
errno_to_name(10) -> echild;
errno_to_name(11) -> eagain;
errno_to_name(12) -> enomem;
errno_to_name(13) -> eacces;
errno_to_name(14) -> efault;
errno_to_name(15) -> enotblk;
errno_to_name(16) -> ebusy;
errno_to_name(17) -> eexist;
errno_to_name(18) -> exdev;
errno_to_name(19) -> enodev;
errno_to_name(20) -> enotdir;
errno_to_name(21) -> eisdir;
errno_to_name(22) -> einval;
errno_to_name(23) -> enfile;
errno_to_name(24) -> emfile;
errno_to_name(25) -> enotty;
errno_to_name(26) -> etxtbsy;
errno_to_name(27) -> efbig;
errno_to_name(28) -> enospc;
errno_to_name(29) -> espipe;
errno_to_name(30) -> erofs;
errno_to_name(31) -> emlink;
errno_to_name(32) -> epipe;
errno_to_name(33) -> edom;
errno_to_name(34) -> erange;
errno_to_name(35) -> enomsg;
errno_to_name(36) -> eidrm;
errno_to_name(37) -> echrng;
errno_to_name(38) -> el2nsync;
errno_to_name(39) -> el3hlt;
errno_to_name(40) -> el3rst;
errno_to_name(41) -> elnrng;
errno_to_name(42) -> eunatch;
errno_to_name(43) -> enocsi;
errno_to_name(44) -> el2hlt;
errno_to_name(45) -> edeadlk;
errno_to_name(46) -> enolck;
errno_to_name(47) -> ecanceled;
errno_to_name(48) -> enotsup;
errno_to_name(49) -> edquot;
errno_to_name(50) -> ebade;
errno_to_name(51) -> ebadr;
errno_to_name(52) -> exfull;
errno_to_name(53) -> enoano;
errno_to_name(54) -> ebadrqc;
errno_to_name(55) -> ebadslt;
errno_to_name(56) -> edeadlock;
errno_to_name(57) -> ebfont;
errno_to_name(58) -> eownerdead;
errno_to_name(59) -> enotrecoverable;
errno_to_name(60) -> enostr;
errno_to_name(61) -> enodata;
errno_to_name(62) -> etime;
errno_to_name(63) -> enosr;
errno_to_name(64) -> enonet;
errno_to_name(65) -> enopkg;
errno_to_name(66) -> eremote;
errno_to_name(67) -> enolink;
errno_to_name(68) -> eadv;
errno_to_name(69) -> esrmnt;
errno_to_name(70) -> ecomm;
errno_to_name(71) -> eproto;
errno_to_name(72) -> elockunmapped;
errno_to_name(73) -> enotactive;
errno_to_name(74) -> emultihop;
errno_to_name(77) -> ebadmsg;
errno_to_name(78) -> enametoolong;
errno_to_name(79) -> eoverflow;
errno_to_name(80) -> enotuniq;
errno_to_name(81) -> ebadfd;
errno_to_name(82) -> eremchg;
errno_to_name(83) -> elibacc;
errno_to_name(84) -> elibbad;
errno_to_name(85) -> elibscn;
errno_to_name(86) -> elibmax;
errno_to_name(87) -> elibexec;
errno_to_name(88) -> eilseq;
errno_to_name(89) -> enosys;
errno_to_name(90) -> eloop;
errno_to_name(91) -> erestart;
errno_to_name(92) -> estrpipe;
errno_to_name(93) -> enotempty;
errno_to_name(94) -> eusers;
errno_to_name(95) -> enotsock;
errno_to_name(96) -> edestaddrreq;
errno_to_name(97) -> emsgsize;
errno_to_name(98) -> eprototype;
errno_to_name(99) -> enoprotoopt;
errno_to_name(120) -> eprotonosupport;
errno_to_name(121) -> esocktnosupport;
errno_to_name(122) -> eopnotsupp;
errno_to_name(123) -> epfnosupport;
errno_to_name(124) -> eafnosupport;
errno_to_name(125) -> eaddrinuse;
errno_to_name(126) -> eaddrnotavail;
errno_to_name(127) -> enetdown;
errno_to_name(128) -> enetunreach;
errno_to_name(129) -> enetreset;
errno_to_name(130) -> econnaborted;
errno_to_name(131) -> econnreset;
errno_to_name(132) -> enobufs;
errno_to_name(133) -> eisconn;
errno_to_name(134) -> enotconn;
errno_to_name(143) -> eshutdown;
errno_to_name(144) -> etoomanyrefs;
errno_to_name(145) -> etimedout;
errno_to_name(146) -> econnrefused;
errno_to_name(147) -> ehostdown;
errno_to_name(148) -> ehostunreach;
errno_to_name(149) -> ealready;
errno_to_name(150) -> einprogress;
errno_to_name(151) -> estale;
errno_to_name(N) -> integer_to_binary(N).

pmask_to_names(V) ->
    Classes = [
        {16#ffffffff, <<"all">>},
        {16#80000000, <<"ot">>},
        {16#40000000, <<"ex">>},
        {16#20000000, <<"io">>},
        {16#01c00000, <<"xx">>},
        {16#01000000, <<"xs">>},
        {16#00800000, <<"xc">>},
        {16#00400000, <<"xp">>},
        {16#00300000, <<"pc">>},
        {16#00200000, <<"pm">>},
        {16#00100000, <<"ps">>},
        {16#000f0000, <<"ad">>},
        {16#00080000, <<"aa">>},
        {16#00070000, <<"am">>},
        {16#00040000, <<"ua">>},
        {16#00020000, <<"as">>},
        {16#00010000, <<"ss">>},
        {16#00008000, <<"cy">>},
        {16#00004000, <<"ap">>},
        {16#00001000, <<"lo">>},
        {16#00000400, <<"na">>},
        {16#00000200, <<"ip">>},
        {16#00000100, <<"nt">>},
        {16#00000040, <<"cl">>},
        {16#00000020, <<"fd">>},
        {16#00000010, <<"fc">>},
        {16#00000008, <<"fm">>},
        {16#00000004, <<"fa">>},
        {16#00000002, <<"fw">>},
        {16#00000001, <<"fr">>}
    ],
    {_Rem, OutFlags} = lists:foldl(fun ({Mask, Name}, {Rem, Flags}) ->
        case (Rem band Mask) of
            Mask -> {Rem band (bnot Mask), [Name | Flags]};
            _ -> {Rem, Flags}
        end
    end, {V, []}, Classes),
    OutFlags.
