// YARA rules, version 0.1.1_2020_04_26

rule exp2_12f5c7a9c7e46d53dc389ff1663c0565 {
	meta:
		aliases = "__GI_exp2, exp2"
		size = "16"
		objfiles = "w_exp2@libm.a"
	strings:
		$pattern = { ( CC | 0F ) 28 C8 66 0F 12 05 ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __mulsc3_b9f78c71355896c406d7771f5e5bc67f {
	meta:
		aliases = "__mulsc3"
		size = "738"
		objfiles = "_mulsc3@libgcc.a"
	strings:
		$pattern = { ( CC | 0F ) 28 F8 44 0F 28 C1 44 0F 28 C8 F3 0F 59 FA 44 0F 28 D2 F3 44 0F 59 C3 0F 28 E8 F3 44 0F 59 CB F3 44 0F 59 D1 0F 28 E7 F3 41 0F 5C E0 41 0F 28 F1 F3 41 0F 58 F2 0F 2E E4 7A 15 75 13 F3 0F 11 64 24 F8 F3 0F 11 74 24 FC F3 0F 7E 44 24 F8 C3 0F 2E F6 7A 02 74 E6 0F 28 C5 0F 2E ED 0F 9B C2 F3 0F 5C C5 0F 2E C0 0F 9A C0 84 D0 0F 85 A3 00 00 00 0F 28 C1 0F 2E C9 0F 9B C2 F3 0F 5C C1 0F 2E C0 0F 9A C0 84 D0 0F 85 0E 01 00 00 31 C9 0F 2E DB 0F 9A C1 31 F6 0F 2E D2 40 0F 9A C6 31 FF 0F 28 C2 48 85 F6 0F 94 C2 F3 0F 5C C2 0F 2E C0 0F 9A C0 84 D0 0F 85 E4 01 00 00 0F 28 C3 48 85 C9 0F 94 C2 F3 0F 5C C3 }
	condition:
		$pattern
}

rule __fixunssfdi_0f7f77f817f617047974b82a3a08caf4 {
	meta:
		aliases = "__fixunssfdi"
		size = "43"
		objfiles = "_fixunssfsi@libgcc.a"
	strings:
		$pattern = { ( CC | 0F ) 2E 05 ?? ?? ?? ?? 72 1C F3 0F 5C 05 ?? ?? ?? ?? 48 B8 00 00 00 00 00 00 00 80 F3 48 0F 2C D0 48 8D 04 02 C3 F3 48 0F 2C C0 C3 }
	condition:
		$pattern
}

rule set_fast_math_0ec28eb99b58f4adbda3209752cbd2c6 {
	meta:
		aliases = "set_fast_math"
		size = "19"
		objfiles = "crtfastmath"
	strings:
		$pattern = { ( CC | 0F ) AE 5C 24 FC 81 4C 24 FC 40 80 00 00 0F AE 54 24 FC C3 }
	condition:
		$pattern
}

rule __decode_header_c35093e23579a2b4afcef973aca424d3 {
	meta:
		aliases = "__decode_header"
		size = "161"
		objfiles = "decodeh@libc.a"
	strings:
		$pattern = { ( CC | 0F ) B6 07 0F B6 57 01 C1 E0 08 09 D0 89 06 0F BE 47 02 C1 E8 1F 89 46 04 8A 47 02 C0 E8 03 83 E0 0F 89 46 08 0F B6 47 02 C1 E8 02 83 E0 01 89 46 0C 0F B6 47 02 D1 E8 83 E0 01 89 46 10 0F B6 47 02 83 E0 01 89 46 14 0F BE 47 03 C1 E8 1F 89 46 18 0F B6 47 03 83 E0 0F 89 46 1C 0F B6 47 04 0F B6 57 05 C1 E0 08 09 D0 89 46 20 0F B6 47 06 0F B6 57 07 C1 E0 08 09 D0 89 46 24 0F B6 47 08 0F B6 57 09 C1 E0 08 09 D0 89 46 28 0F B6 47 0A 0F B6 57 0B C1 E0 08 09 D0 89 46 2C B8 0C 00 00 00 C3 }
	condition:
		$pattern
}

rule __flbf_f5ba2419795d2f795740a1cdd5576742 {
	meta:
		aliases = "__flbf"
		size = "9"
		objfiles = "__flbf@libc.a"
	strings:
		$pattern = { ( CC | 0F ) B7 07 25 00 01 00 00 C3 }
	condition:
		$pattern
}

rule feof_unlocked_702176e8f2e625e79381705fe9276f56 {
	meta:
		aliases = "feof_unlocked"
		size = "7"
		objfiles = "feof_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 0F ) B7 07 83 E0 04 C3 }
	condition:
		$pattern
}

rule ferror_unlocked_7ebc92747437a437aaea3b4bf74e2363 {
	meta:
		aliases = "ferror_unlocked"
		size = "7"
		objfiles = "ferror_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 0F ) B7 07 83 E0 08 C3 }
	condition:
		$pattern
}

rule __freading_999969432a7bdf5f8aef25ddf7cd4818 {
	meta:
		aliases = "__freading"
		size = "7"
		objfiles = "__freading@libc.a"
	strings:
		$pattern = { ( CC | 0F ) B7 07 83 E0 23 C3 }
	condition:
		$pattern
}

rule __fwriting_7abd4997f4c9d077a49d6bd52b05e2b4 {
	meta:
		aliases = "__fwriting"
		size = "7"
		objfiles = "__fwriting@libc.a"
	strings:
		$pattern = { ( CC | 0F ) B7 07 83 E0 50 C3 }
	condition:
		$pattern
}

rule __freadable_0c550560967049fe748943698dfc12f4 {
	meta:
		aliases = "__freadable"
		size = "13"
		objfiles = "__freadable@libc.a"
	strings:
		$pattern = { ( CC | 0F ) B7 07 C1 E8 04 83 F0 01 83 E0 01 C3 }
	condition:
		$pattern
}

rule __fwritable_84670765959e55d6a665f4d12e6cf5b5 {
	meta:
		aliases = "__fwritable"
		size = "13"
		objfiles = "__fwritable@libc.a"
	strings:
		$pattern = { ( CC | 0F ) B7 07 C1 E8 05 83 F0 01 83 E0 01 C3 }
	condition:
		$pattern
}

rule __libc_sa_len_24d7cad772e1b80ec5519fabdcf0a56c {
	meta:
		aliases = "__libc_sa_len"
		size = "49"
		objfiles = "sa_len@libc.a"
	strings:
		$pattern = { ( CC | 0F ) B7 C7 83 F8 02 74 23 7F 06 FF C8 75 14 EB 0C 83 F8 04 74 16 83 F8 0A 75 08 EB 09 B8 6E 00 00 00 C3 31 C0 C3 B8 1C 00 00 00 C3 B8 10 00 00 00 C3 }
	condition:
		$pattern
}

rule __GI_inet_netof_80c4b1fc4828b7c517e0c4381492c95e {
	meta:
		aliases = "inet_netof, __GI_inet_netof"
		size = "38"
		objfiles = "inet_netof@libc.a"
	strings:
		$pattern = { ( CC | 0F ) CF 85 FF 78 06 89 F8 C1 E8 18 C3 89 F8 25 00 00 00 C0 3D 00 00 00 80 75 06 89 F8 C1 E8 10 C3 89 F8 C1 E8 08 C3 }
	condition:
		$pattern
}

rule inet_lnaof_7cd7502dd9df223b49cdeec12943c67a {
	meta:
		aliases = "inet_lnaof"
		size = "43"
		objfiles = "inet_lnaof@libc.a"
	strings:
		$pattern = { ( CC | 0F ) CF 85 FF 78 0A 89 F9 81 E1 FF FF FF 00 EB 18 89 FA 0F B7 CF 40 0F B6 C7 81 E2 00 00 00 C0 81 FA 00 00 00 80 0F 45 C8 89 C8 C3 }
	condition:
		$pattern
}

rule htonl_f24c2e84d472595e4e4e43a68927b1b2 {
	meta:
		aliases = "ntohl, htonl"
		size = "5"
		objfiles = "ntohl@libc.a"
	strings:
		$pattern = { ( CC | 0F ) CF 89 F8 C3 }
	condition:
		$pattern
}

rule pthread_equal_c11f863d6be2c66fb42fa0367477969e {
	meta:
		aliases = "__GI_pthread_equal, pthread_equal"
		size = "9"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) C0 48 39 F7 0F 94 C0 C3 }
	condition:
		$pattern
}

rule rwlock_can_rdlock_b497feaa1ecde8220ed3e9661004e516 {
	meta:
		aliases = "rwlock_can_rdlock"
		size = "36"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) C0 48 83 7F 18 00 75 1A 83 7F 30 00 74 0F 48 83 7F 28 00 74 08 31 C0 85 F6 0F 95 C0 C3 B8 01 00 00 00 C3 }
	condition:
		$pattern
}

rule __GI_strnlen_6e1eba747d863bec01a1267f490b134b {
	meta:
		aliases = "strnlen, __GI_strnlen"
		size = "206"
		objfiles = "strnlen@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C0 48 85 F6 0F 84 C2 00 00 00 EB 13 48 39 C6 48 0F 46 C6 48 29 F8 C3 48 89 D0 E9 A3 00 00 00 48 8D 34 37 48 C7 C0 FF FF FF FF 48 39 FE 48 0F 42 F0 48 89 F8 EB 08 80 38 00 74 D1 48 FF C0 A8 07 75 F4 48 89 C1 EB 76 48 8B 01 48 BA FF FE FE FE FE FE FE FE 48 83 C1 08 48 01 D0 48 BA 80 80 80 80 80 80 80 80 48 85 C2 74 50 80 79 F8 00 48 8D 51 F8 74 A3 80 79 F9 00 48 8D 42 01 74 44 80 79 FA 00 48 8D 42 02 74 3A 80 79 FB 00 48 8D 42 03 74 30 80 79 FC 00 48 8D 42 04 74 26 80 79 FD 00 48 8D 42 05 74 1C 80 79 FE 00 48 8D 42 06 74 12 80 79 FF 00 48 8D 42 07 74 08 48 89 F0 48 39 F1 72 85 48 39 C6 48 0F }
	condition:
		$pattern
}

rule __ffsdi2_8a78910301e43abbf21c9564d1583c7b {
	meta:
		aliases = "__ffsdi2"
		size = "55"
		objfiles = "_ffssi2@libgcc.a"
	strings:
		$pattern = { ( CC | 31 ) C0 48 85 FF 74 2E 48 89 F8 B9 38 00 00 00 48 F7 D8 48 21 F8 48 89 C2 48 D3 EA 84 D2 75 09 48 83 E9 08 75 F0 48 89 C2 48 8B 05 ?? ?? ?? ?? 0F B6 04 10 01 C8 F3 C3 }
	condition:
		$pattern
}

rule pthread_attr_setstackaddr_841fb402784fbb2ab10dc7f3cd5ffd14 {
	meta:
		aliases = "__pthread_attr_setstackaddr, pthread_attr_setstackaddr"
		size = "14"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) C0 48 89 77 28 C7 47 20 01 00 00 00 C3 }
	condition:
		$pattern
}

rule pthread_cond_init_686255982696a267826477ec24e8d342 {
	meta:
		aliases = "__GI_pthread_cond_init, pthread_cond_init"
		size = "25"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) C0 48 C7 07 00 00 00 00 C7 47 08 00 00 00 00 48 C7 47 10 00 00 00 00 C3 }
	condition:
		$pattern
}

rule check_match_f2ded00236f29210e5ed5f382f828fec {
	meta:
		aliases = "check_match"
		size = "101"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 31 ) C0 66 83 7F 06 00 49 89 D0 0F 94 C0 85 C8 75 4E 48 83 7F 08 00 74 47 0F B6 47 04 83 E0 0F 83 F8 02 0F 9F C2 83 F8 05 0F 95 C0 84 D0 75 30 8B 07 49 8D 50 FF 48 8D 74 06 FF 48 FF C6 48 FF C2 8A 0E 8A 02 84 C9 75 07 0F B6 D0 F7 DA EB 0C 38 C1 74 E7 0F B6 D1 0F B6 C0 29 C2 85 D2 74 02 31 FF 48 89 F8 C3 }
	condition:
		$pattern
}

rule cfgetispeed_60c33ceb298080a4794337b3e0a77ca7 {
	meta:
		aliases = "cfgetispeed"
		size = "16"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C0 83 3F 00 78 08 8B 47 08 25 0F 10 00 00 C3 }
	condition:
		$pattern
}

rule __pthread_setconcurrency_539feb83c6425c7690ee677a08834eb5 {
	meta:
		aliases = "pthread_setconcurrency, __pthread_setconcurrency"
		size = "9"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) C0 89 3D ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule pthread_rwlockattr_destroy_95da5d637ce2b37c162272462d63ab78 {
	meta:
		aliases = "pthread_condattr_init, _Unwind_GetRegionStart, pthread_mutexattr_destroy, __pthread_mutex_lock, __gthread_active_p, __pthread_mutex_init, __pthread_mutex_unlock, __GI_wcsftime, __pthread_mutex_trylock, __GI_pthread_attr_destroy, pthread_attr_destroy, authnone_refresh, pthread_condattr_destroy, __GI_pthread_condattr_init, wcsftime, _Unwind_GetTextRelBase, __pthread_return_0, grantpt, _svcauth_null, __udiv_w_sdiv, _Unwind_FindEnclosingFunction, __GI_pthread_condattr_destroy, __pthread_mutexattr_destroy, xdrstdio_inline, clntraw_control, _Unwind_GetDataRelBase, pthread_rwlockattr_destroy"
		size = "3"
		objfiles = "condvar@libpthread.a, grantpt@libc.a, clnt_raw@libc.a, gthr_gnat@libgcc.a, wcsftime@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C0 C3 }
	condition:
		$pattern
}

rule __pthread_mutexattr_getpshared_31c376d22c9d3e92413779e1c247ac31 {
	meta:
		aliases = "pthread_mutexattr_getpshared, pthread_condattr_getpshared, __pthread_mutexattr_getpshared"
		size = "9"
		objfiles = "condvar@libpthread.a, mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) C0 C7 06 00 00 00 00 C3 }
	condition:
		$pattern
}

rule pthread_rwlockattr_init_aa67116420e5462cc3551098e4e7fb72 {
	meta:
		aliases = "pthread_rwlockattr_init"
		size = "16"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) C0 C7 07 00 00 00 00 C7 47 04 00 00 00 00 C3 }
	condition:
		$pattern
}

rule __pthread_mutexattr_init_a0139c0de72b46dc02cbec50858dabe6 {
	meta:
		aliases = "pthread_mutexattr_init, __pthread_mutexattr_init"
		size = "9"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) C0 C7 07 03 00 00 00 C3 }
	condition:
		$pattern
}

rule clnt_sperrno_96ad1e01d1523f7e8ccc03818cff8578 {
	meta:
		aliases = "__GI_clnt_sperrno, clnt_sperrno"
		size = "42"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C0 EB 1A 39 3C C5 ?? ?? ?? ?? 75 0E 8B 04 C5 ?? ?? ?? ?? 48 05 ?? ?? ?? ?? C3 48 FF C0 48 83 F8 11 76 E0 B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __fpending_69496ed76f6f3a651a811ad39d8ca403 {
	meta:
		aliases = "__fpending"
		size = "16"
		objfiles = "__fpending@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C0 F6 07 40 74 08 48 8B 47 18 48 2B 47 08 C3 }
	condition:
		$pattern
}

rule isascii_104d1f6339c601ecab6ff08a37700f2f {
	meta:
		aliases = "isascii"
		size = "12"
		objfiles = "isascii@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C0 F7 C7 80 FF FF FF 0F 94 C0 C3 }
	condition:
		$pattern
}

rule __register_frame_info_9a45c5194586f47a7935b5e313ed5c07 {
	meta:
		aliases = "__register_frame_info_table, __register_frame_info"
		size = "9"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 31 ) C9 31 D2 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule read_uleb128_310b37baa011d661109821584da13a42 {
	meta:
		aliases = "read_uleb128"
		size = "37"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a, unwind_c@libgcc.a"
	strings:
		$pattern = { ( CC | 31 ) C9 45 31 C0 0F B6 17 48 FF C7 48 89 D0 83 E0 7F 48 D3 E0 83 C1 07 49 09 C0 84 D2 78 E7 48 89 F8 4C 89 06 C3 }
	condition:
		$pattern
}

rule read_sleb128_573311180f9ecb16c35da25ab423d5dd {
	meta:
		aliases = "read_sleb128"
		size = "60"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 31 ) C9 45 31 C0 0F B6 17 48 FF C7 48 89 D0 83 E0 7F 48 D3 E0 83 C1 07 49 09 C0 84 D2 78 E7 83 F9 3F 77 12 83 E2 40 74 0D 48 C7 C0 FF FF FF FF 48 D3 E0 49 09 C0 48 89 F8 4C 89 06 C3 }
	condition:
		$pattern
}

rule __GI_strncmp_cde295d64e9c9c761593e29f2406a899 {
	meta:
		aliases = "strncmp, __GI_strncmp"
		size = "176"
		objfiles = "strncmp@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C9 45 31 C9 48 83 FA 03 49 89 D0 0F 86 8D 00 00 00 49 89 D2 49 C1 EA 02 8A 0F 44 8A 0E 84 C9 0F 94 C2 44 38 C9 0F 95 C0 08 C2 75 77 8A 4F 01 44 8A 4E 01 84 C9 0F 94 C2 44 38 C9 0F 95 C0 08 C2 75 61 8A 4F 02 44 8A 4E 02 84 C9 0F 94 C2 44 38 C9 0F 95 C0 08 C2 75 4B 8A 4F 03 44 8A 4E 03 84 C9 0F 94 C2 44 38 C9 0F 95 C0 08 C2 75 35 48 83 C7 04 48 83 C6 04 49 FF CA 75 9D 41 83 E0 03 EB 1D 8A 0F 44 8A 0E 84 C9 0F 94 C2 44 38 C9 0F 95 C0 08 C2 75 0E 48 FF C7 48 FF C6 49 FF C8 4D 85 C0 75 DE 41 0F B6 C1 0F B6 D1 29 C2 89 D0 C3 }
	condition:
		$pattern
}

rule strlcat_85a059759eb9710802b4e7bc83f1d377 {
	meta:
		aliases = "__GI_strlcat, strlcat"
		size = "52"
		objfiles = "strlcat@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C9 48 39 D1 72 07 48 8D 7C 24 FF EB 1A 80 3F 00 74 15 48 FF C7 48 FF C1 EB E7 48 FF C1 48 39 D1 48 83 D7 00 48 FF C6 8A 06 84 C0 88 07 75 EB 48 89 C8 C3 }
	condition:
		$pattern
}

rule setlinebuf_39e6249301b7316c441c9b1be99fbdce {
	meta:
		aliases = "setlinebuf"
		size = "14"
		objfiles = "setlinebuf@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C9 BA 01 00 00 00 31 F6 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_wcstoul_0b8614121f4839ecf9cde74d5b6b8c69 {
	meta:
		aliases = "__libc_waitpid, strtoul, __GI_strtoul, __GI_strtoull, strtoull, __GI_waitpid, waitpid, wcstoumax, wcstoull, wcstoul, __GI_wcstoull, strtoumax, __GI_wcstoul"
		size = "7"
		objfiles = "wcstoul@libc.a, strtoul@libc.a, waitpid@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C9 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_wcswidth_519caf6aaaa3a66af2973adae5223eb5 {
	meta:
		aliases = "wcswidth, __GI_wcswidth"
		size = "87"
		objfiles = "wcswidth@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C9 EB 0C 89 D0 83 E0 7F 39 C2 75 44 48 FF C1 48 39 F1 73 07 8B 14 8F 85 D2 75 E8 31 C9 EB 24 81 FA FF 00 00 00 7F 29 83 FA 1F 0F 9E C0 83 EA 7F 83 FA 20 0F 96 C2 08 D0 75 16 48 83 C7 04 FF C1 48 FF CE 48 85 F6 74 0B 8B 17 85 D2 75 D1 EB 03 83 C9 FF 89 C8 C3 }
	condition:
		$pattern
}

rule __GI_wcstof_3cb1ef1313d9618f38d69ea4ff44828f {
	meta:
		aliases = "__GI_strtof, wcstof, strtof, __GI_wcstof"
		size = "42"
		objfiles = "wcstof@libc.a, strtof@libc.a"
	strings:
		$pattern = { ( CC | 31 ) D2 48 83 EC 38 E8 ?? ?? ?? ?? D9 54 24 28 DB 7C 24 10 D9 44 24 28 DB 3C 24 E8 ?? ?? ?? ?? F3 0F 10 44 24 28 48 83 C4 38 C3 }
	condition:
		$pattern
}

rule wcstod_af84d5639ed8c17e7ee2dc6cb47c24b3 {
	meta:
		aliases = "__GI_strtod, __GI_wcstod, strtod, wcstod"
		size = "42"
		objfiles = "strtod@libc.a, wcstod@libc.a"
	strings:
		$pattern = { ( CC | 31 ) D2 48 83 EC 38 E8 ?? ?? ?? ?? DD 54 24 20 DB 7C 24 10 DD 44 24 20 DB 3C 24 E8 ?? ?? ?? ?? 66 0F 12 44 24 20 48 83 C4 38 C3 }
	condition:
		$pattern
}

rule wcsrchr_5af5afbca6ccfb5048da5f9a2c292626 {
	meta:
		aliases = "wcsrchr"
		size = "24"
		objfiles = "wcsrchr@libc.a"
	strings:
		$pattern = { ( CC | 31 ) D2 8B 07 39 F0 48 0F 44 D7 85 C0 74 06 48 83 C7 04 EB EE 48 89 D0 C3 }
	condition:
		$pattern
}

rule __GI_vwarnx_ddc6f3bfdf32a5fedb3333060daaf400 {
	meta:
		aliases = "vwarnx, __GI_vwarnx"
		size = "7"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 31 ) D2 E9 2F FF FF FF }
	condition:
		$pattern
}

rule __GI_wcstold_b4e14f698767da14cd59fb60f58a9700 {
	meta:
		aliases = "wcstold, __GI_strtold, strtold, __GI_wcstold"
		size = "7"
		objfiles = "wcstold@libc.a, strtold@libc.a"
	strings:
		$pattern = { ( CC | 31 ) D2 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule gai_strerror_e2edf0b21525cdcb4cd4262cf3cd9647 {
	meta:
		aliases = "gai_strerror"
		size = "42"
		objfiles = "gai_strerror@libc.a"
	strings:
		$pattern = { ( CC | 31 ) D2 EB 1A 48 89 D0 48 C1 E0 04 39 B8 ?? ?? ?? ?? 75 08 48 8B 80 ?? ?? ?? ?? C3 48 FF C2 48 83 FA 0F 76 E0 B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule glob_pattern_p_6c93c91b2ef0624c863aa0005e87d066 {
	meta:
		aliases = "__GI_glob_pattern_p, glob_pattern_p"
		size = "86"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 31 ) D2 EB 43 0F BE C0 83 F8 5B 74 1A 7F 0C 83 F8 2A 74 3D 83 F8 3F 75 2C EB 36 83 F8 5C 74 0E 83 F8 5D 75 20 EB 1A BA 01 00 00 00 EB 17 85 F6 74 13 80 7F 01 00 48 8D 47 01 74 09 48 89 C7 EB 04 85 D2 75 0C 48 FF C7 8A 07 84 C0 75 B7 31 C0 C3 B8 01 00 00 00 C3 }
	condition:
		$pattern
}

rule _start_7ba89daedb79fd291e18f5fa204e7fcc {
	meta:
		aliases = "_start"
		size = "42"
		objfiles = "Scrt1"
	strings:
		$pattern = { ( CC | 31 ) ED 49 89 D1 5E 48 89 E2 48 83 E4 F0 50 54 48 8B 3D ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 4C 8B 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? F4 }
	condition:
		$pattern
}

rule _start_6be03ca145641244d01fe9237c98de4f {
	meta:
		aliases = "_start"
		size = "42"
		objfiles = "crt1"
	strings:
		$pattern = { ( CC | 31 ) ED 49 89 D1 5E 48 89 E2 48 83 E4 F0 50 54 48 C7 C7 ?? ?? ?? ?? 48 C7 C1 ?? ?? ?? ?? 49 C7 C0 ?? ?? ?? ?? E8 ?? ?? ?? ?? F4 }
	condition:
		$pattern
}

rule setpgrp_63f7d29c07d3387c7aa25ec2c46d2240 {
	meta:
		aliases = "setpgrp"
		size = "9"
		objfiles = "setpgrp@libc.a"
	strings:
		$pattern = { ( CC | 31 ) F6 31 FF E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_once_fork_child_f1eecc8d850050768ed57259f8a01f55 {
	meta:
		aliases = "__pthread_once_fork_child"
		size = "64"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) F6 48 83 EC 08 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 F6 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 3D FB FF FF 7F 7F 0B 83 C0 04 89 05 ?? ?? ?? ?? EB 0A C7 05 ?? ?? ?? ?? 00 00 00 00 58 C3 }
	condition:
		$pattern
}

rule sigpause_d3010fe72d6379f6b7707fbcdd11fb6d {
	meta:
		aliases = "__GI_sigpause, mkstemp, atof, sigpause"
		size = "7"
		objfiles = "atof@libc.a, mkstemp@libc.a, sigpause@libc.a"
	strings:
		$pattern = { ( CC | 31 ) F6 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tzset_c73e1ce28b479111226384d7151d565c {
	meta:
		aliases = "__GI_tzset, tzset"
		size = "29"
		objfiles = "tzset@libc.a"
	strings:
		$pattern = { ( CC | 31 ) FF 48 83 EC 08 E8 ?? ?? ?? ?? 31 FF 48 3D FF 4E 98 45 58 40 0F 9E C7 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule siggetmask_644d21c7c18a50049422bd426f8ae255 {
	meta:
		aliases = "siggetmask"
		size = "7"
		objfiles = "siggetmask@libc.a"
	strings:
		$pattern = { ( CC | 31 ) FF E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule setup_salt_c9106b61a2f67a740a550589397a879d {
	meta:
		aliases = "setup_salt"
		size = "70"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 3B ) 3D ?? ?? ?? ?? 74 3D 41 B8 00 00 80 00 BE 01 00 00 00 31 C9 31 D2 89 3D ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 EB 11 89 D0 44 09 C0 85 FE 0F 45 D0 01 F6 41 D1 E8 FF C1 83 F9 17 7E EA 89 15 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule fibheap_rem_root_a82a604bed1d8d6b29ee6fdcf4af70ed {
	meta:
		aliases = "fibheap_rem_root"
		size = "34"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 3B ) 52 08 55 89 E5 53 89 C3 74 0D 89 D0 E8 1E FE FF FF 89 43 08 5B 5D C3 C7 40 08 00 00 00 00 5B 5D C3 }
	condition:
		$pattern
}

rule ascii_to_bin_88edc3a0571de95249cd32376343bb7e {
	meta:
		aliases = "ascii_to_bin"
		size = "63"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 40 ) 80 FF 7A 7F 36 40 80 FF 60 7E 08 40 0F BE C7 83 E8 3B C3 40 80 FF 5A 7F 22 40 80 FF 40 7E 08 40 0F BE C7 83 E8 35 C3 40 80 FF 39 7F 0E 40 80 FF 2D 7E 08 40 0F BE C7 83 E8 2E C3 31 C0 C3 }
	condition:
		$pattern
}

rule dysize_c32113a9faa0ce4acb6619d31bd1b4d8 {
	meta:
		aliases = "dysize"
		size = "52"
		objfiles = "dysize@libc.a"
	strings:
		$pattern = { ( CC | 40 ) F6 C7 03 53 75 26 BA 64 00 00 00 89 F8 89 D3 99 F7 FB 85 D2 75 0F 66 BA 90 01 89 F8 89 D3 99 F7 FB 85 D2 75 07 B8 6E 01 00 00 EB 05 B8 6D 01 00 00 5B C3 }
	condition:
		$pattern
}

rule __GI_tsearch_0662a6a5ecaef09fd28835969ec7c252 {
	meta:
		aliases = "tsearch, __GI_tsearch"
		size = "109"
		objfiles = "tsearch@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 31 C0 48 85 F6 49 89 D4 55 48 89 FD 53 48 89 F3 74 54 EB 25 48 8B 03 EB 4D 48 8B 30 48 89 EF 41 FF D4 83 F8 00 74 ED 7D 09 48 8B 1B 48 83 C3 08 EB 07 48 8B 1B 48 83 C3 10 48 8B 03 48 85 C0 75 D8 BF 18 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 74 16 48 89 03 48 89 28 48 C7 40 10 00 00 00 00 48 C7 40 08 00 00 00 00 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __GI___dl_iterate_phdr_9bbfd535ed158bde63667297cc33e144 {
	meta:
		aliases = "__dl_iterate_phdr, __GI___dl_iterate_phdr"
		size = "101"
		objfiles = "dl_iterate_phdr@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 31 C0 49 89 FC 55 48 89 F5 53 48 83 EC 20 48 8B 1D ?? ?? ?? ?? EB 3E 48 8B 03 48 89 E7 48 89 EA BE 20 00 00 00 48 89 04 24 48 8B 43 08 48 89 44 24 08 48 8B 83 A0 01 00 00 48 89 44 24 10 48 8B 83 98 01 00 00 66 89 44 24 18 41 FF D4 85 C0 75 09 48 8B 5B 18 48 85 DB 75 BD 48 83 C4 20 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule cfsetspeed_0c697faf8ca558f32e047035756e9b58 {
	meta:
		aliases = "cfsetspeed"
		size = "99"
		objfiles = "cfsetspeed@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 31 C0 49 89 FC 55 89 F5 53 EB 3D 8B 1C C5 ?? ?? ?? ?? 39 DD 75 0E 89 EE 4C 89 E7 E8 ?? ?? ?? ?? 89 EE EB 15 3B 2C C5 ?? ?? ?? ?? 75 18 89 DE 4C 89 E7 E8 ?? ?? ?? ?? 89 DE 4C 89 E7 E8 ?? ?? ?? ?? 31 C0 EB 17 48 FF C0 48 83 F8 1F 76 BD E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __GI_tcgetattr_ede7290c4daeaac138976d0e19aafbac {
	meta:
		aliases = "tcgetattr, __GI_tcgetattr"
		size = "110"
		objfiles = "tcgetattr@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 31 C0 55 53 48 89 F3 BE 01 54 00 00 48 83 EC 30 48 89 E2 E8 ?? ?? ?? ?? 85 C0 89 C5 75 43 8B 04 24 48 8D 74 24 11 48 8D 7B 11 BA 13 00 00 00 89 03 8B 44 24 04 89 43 04 8B 44 24 08 89 43 08 8B 44 24 0C 89 43 0C 8A 44 24 10 88 43 10 E8 ?? ?? ?? ?? BA 0D 00 00 00 48 89 C7 31 F6 E8 ?? ?? ?? ?? 48 83 C4 30 89 E8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule opendir_3a182bc9068eee2b3544a5669acfa284 {
	meta:
		aliases = "__GI_opendir, opendir"
		size = "243"
		objfiles = "opendir@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 31 C0 BE 00 08 01 00 55 53 31 DB 48 81 EC 90 00 00 00 E8 ?? ?? ?? ?? 85 C0 89 C5 0F 88 C1 00 00 00 48 89 E6 89 C7 E8 ?? ?? ?? ?? 85 C0 78 17 31 C0 BA 01 00 00 00 BE 02 00 00 00 89 EF E8 ?? ?? ?? ?? 85 C0 79 17 E8 ?? ?? ?? ?? 44 8B 20 48 89 C3 89 EF E8 ?? ?? ?? ?? 44 89 23 EB 76 BF 58 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 52 89 28 48 C7 40 20 00 00 00 00 48 C7 40 10 00 00 00 00 48 C7 40 08 00 00 00 00 48 8B 44 24 38 48 3D FF 01 00 00 48 89 43 28 77 08 48 C7 43 28 00 02 00 00 48 8B 73 28 BF 01 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 43 18 75 1E 48 89 DF E8 ?? ?? ?? ?? 89 EF E8 ?? ?? }
	condition:
		$pattern
}

rule marshal_new_auth_d8fd9aeead2e12f8fa0897febe965b2c {
	meta:
		aliases = "marshal_new_auth"
		size = "130"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 31 C9 BA 90 01 00 00 55 53 48 89 FB 48 83 EC 30 4C 8B 67 40 48 89 E7 49 8D 74 24 38 E8 ?? ?? ?? ?? 48 89 DE 48 89 E7 E8 ?? ?? ?? ?? 85 C0 74 10 48 8D 73 18 48 89 E7 E8 ?? ?? ?? ?? 85 C0 75 0C BF ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 13 48 8B 44 24 08 48 89 E7 FF 50 20 41 89 84 24 C8 01 00 00 48 8B 44 24 08 48 8B 40 38 48 85 C0 74 05 48 89 E7 FF D0 48 83 C4 30 B8 01 00 00 00 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule rresvport_1a16e1208a810c2a29eaad1d8c3e89f9 {
	meta:
		aliases = "__GI_rresvport, rresvport"
		size = "142"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 31 D2 BE 01 00 00 00 55 48 89 FD BF 02 00 00 00 53 48 83 EC 10 66 C7 04 24 02 00 C7 44 24 04 00 00 00 00 E8 ?? ?? ?? ?? 85 C0 89 C3 79 0B EB 50 89 DF E8 ?? ?? ?? ?? EB 47 48 89 E6 BA 10 00 00 00 89 DF 8B 45 00 66 C1 C8 08 66 89 44 24 02 E8 ?? ?? ?? ?? 85 C0 79 2B E8 ?? ?? ?? ?? 83 38 62 49 89 C4 75 CB FF 4D 00 81 7D 00 00 02 00 00 75 C8 89 DF E8 ?? ?? ?? ?? 41 C7 04 24 0B 00 00 00 83 CB FF 5A 59 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule xdrrec_setpos_d29cff40f908ee319df3c82956185d7a {
	meta:
		aliases = "xdrrec_setpos"
		size = "115"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 41 89 F4 55 48 89 FD 53 48 8B 5F 18 E8 96 FF FF FF 83 F8 FF 74 54 8B 55 00 44 29 E0 85 D2 74 06 FF CA 75 46 EB 1B 48 8B 53 20 48 98 48 29 C2 48 3B 53 30 76 35 48 3B 53 28 73 2F 48 89 53 20 EB 22 3B 43 68 48 8B 53 58 7D 20 48 98 48 29 C2 48 3B 53 60 77 15 48 3B 53 50 72 0F 48 29 43 68 48 89 53 58 B8 01 00 00 00 EB 02 31 C0 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule getservbyport_5fdedfcefee5bdf29aff5f55f15cd320 {
	meta:
		aliases = "__GI_getservbyport, getservbyport"
		size = "65"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 41 89 FC 53 48 89 F3 48 83 EC 18 E8 27 FC FF FF 48 8B 0D ?? ?? ?? ?? 4C 8D 4C 24 10 48 89 DE 44 89 E7 41 B8 19 11 00 00 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 44 24 10 48 83 C4 18 5B 41 5C C3 }
	condition:
		$pattern
}

rule putc_64b5ad6c57df1b91e0dabef124e5b57e {
	meta:
		aliases = "__GI_fputc, fputc, __GI_putc, putc"
		size = "146"
		objfiles = "fputc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 41 89 FC 55 48 89 F5 53 48 83 EC 20 83 7E 50 00 74 23 48 8B 46 18 48 3B 46 30 73 10 40 88 38 40 0F B6 DF 48 FF C0 48 89 46 18 EB 59 E8 ?? ?? ?? ?? 89 C3 EB 50 48 8D 5E 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8B 45 18 48 3B 45 30 73 10 44 88 20 41 0F B6 DC 48 FF C0 48 89 45 18 EB 0D 48 89 EE 44 89 E7 E8 ?? ?? ?? ?? 89 C3 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule tcgetsid_578e2aef91cadddbec25f6da48384ad3 {
	meta:
		aliases = "tcgetsid"
		size = "131"
		objfiles = "tcgetsid@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 41 89 FC 55 53 48 83 EC 10 83 3D ?? ?? ?? ?? 00 75 33 E8 ?? ?? ?? ?? 48 8D 54 24 0C 8B 28 48 89 C3 BE 29 54 00 00 31 C0 44 89 E7 E8 ?? ?? ?? ?? 85 C0 79 3D 83 3B 16 75 3E C7 05 ?? ?? ?? ?? 01 00 00 00 89 2B 44 89 E7 E8 ?? ?? ?? ?? 83 F8 FF 89 C7 74 23 E8 ?? ?? ?? ?? 89 44 24 0C FF C0 75 10 E8 ?? ?? ?? ?? 83 38 03 75 06 C7 00 19 00 00 00 8B 44 24 0C EB 03 83 C8 FF 5A 59 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule putchar_2a8d968bb3d406bade4a06799248b243 {
	meta:
		aliases = "putchar"
		size = "153"
		objfiles = "putchar@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 41 89 FC 55 53 48 83 EC 20 48 8B 2D ?? ?? ?? ?? 83 7D 50 00 74 26 48 8B 45 18 48 3B 45 30 73 10 40 88 38 40 0F B6 DF 48 FF C0 48 89 45 18 EB 5C 48 89 EE E8 ?? ?? ?? ?? 89 C3 EB 50 48 8D 5D 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8B 45 18 48 3B 45 30 73 10 44 88 20 41 0F B6 DC 48 FF C0 48 89 45 18 EB 0D 48 89 EE 44 89 E7 E8 ?? ?? ?? ?? 89 C3 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule error_62f92f78853643241b4ca4518889c0b3 {
	meta:
		aliases = "__error, error"
		size = "326"
		objfiles = "error@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 41 89 FC 55 89 F5 53 48 89 D3 48 81 EC D0 00 00 00 48 89 4C 24 38 0F B6 C8 4C 89 44 24 40 48 8D 04 8D 00 00 00 00 B9 ?? ?? ?? ?? 4C 89 4C 24 48 48 29 C1 48 8D 84 24 CF 00 00 00 FF E1 0F 29 78 F1 0F 29 70 E1 0F 29 68 D1 0F 29 60 C1 0F 29 58 B1 0F 29 50 A1 0F 29 48 91 0F 29 40 81 48 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 04 FF D0 EB 1A 48 8B 15 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? BE ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? 48 8D 84 24 F0 00 00 00 48 8B 3D ?? ?? ?? ?? 48 89 E2 48 89 DE C7 04 24 18 00 00 00 C7 44 24 04 30 00 00 00 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 }
	condition:
		$pattern
}

rule getnetbyaddr_bce6d60d426ccf7450f098c4bdb243d8 {
	meta:
		aliases = "getnetbyaddr"
		size = "68"
		objfiles = "getnetbyad@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 41 89 FC 8B 3D ?? ?? ?? ?? 55 89 F5 53 E8 ?? ?? ?? ?? EB 0B 39 6B 10 75 06 44 39 63 14 74 0D E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 75 E8 83 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 48 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule fcntl_01bef381c77e80c0aeec63f7d1e2fb7f {
	meta:
		aliases = "fcntl"
		size = "110"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 41 89 FC BF 01 00 00 00 53 89 F3 48 81 EC D8 00 00 00 48 8D 74 24 1C 48 89 54 24 30 E8 ?? ?? ?? ?? 48 8D 84 24 F0 00 00 00 C7 04 24 18 00 00 00 89 DE 44 89 E7 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 48 83 C0 10 48 8B 10 31 C0 E8 ?? ?? ?? ?? 8B 7C 24 1C 89 C3 31 F6 E8 ?? ?? ?? ?? 89 D8 48 81 C4 D8 00 00 00 5B 41 5C C3 }
	condition:
		$pattern
}

rule inet_ntop4_412def45ef03152bd130031957174296 {
	meta:
		aliases = "inet_ntop4"
		size = "280"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 45 31 D2 49 89 F4 FC 55 45 31 C9 48 89 D5 53 48 89 FB 48 83 EC 20 66 8B 05 ?? ?? ?? ?? 48 8D 7C 24 02 66 89 04 24 31 C0 AB AB AB 66 AB AA E9 9F 00 00 00 49 63 C2 B9 64 00 00 00 49 63 F9 4C 8D 1C 03 41 8D 71 01 45 89 C8 66 41 0F B6 13 89 D0 F6 F1 89 C1 8D 41 30 3C 30 88 04 3C 75 27 B9 0A 00 00 00 89 D0 31 D2 F6 F1 B9 0A 00 00 00 66 0F B6 C0 66 F7 F1 83 C2 30 80 FA 30 88 14 3C 74 29 41 89 F0 EB 24 B9 0A 00 00 00 89 D0 31 D2 F6 F1 B9 0A 00 00 00 48 63 F6 45 8D 41 02 66 0F B6 C0 66 F7 F1 83 C2 30 88 14 34 66 41 0F B6 03 B9 0A 00 00 00 31 D2 49 63 F0 45 8D 48 02 41 FF C2 66 F7 F1 41 8D 40 01 }
	condition:
		$pattern
}

rule sched_getaffinity_c514d96bdef5d4a8ade980c17bbd11fc {
	meta:
		aliases = "sched_getaffinity"
		size = "96"
		objfiles = "sched_getaffinity@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 63 FF 49 89 D4 B8 CC 00 00 00 55 48 89 F5 BE FF FF FF 7F 48 81 FD FF FF FF 7F 53 48 0F 46 F5 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 83 FB FF 89 D8 74 16 48 63 FB 31 F6 48 29 FD 49 8D 3C 3C 48 89 EA E8 ?? ?? ?? ?? 31 C0 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __GI_fstat_cc894928f3bf2ad2cc69366014fc1338 {
	meta:
		aliases = "fstat64, __GI_fstat64, fstat, __GI_fstat"
		size = "82"
		objfiles = "fstat@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 63 FF B8 05 00 00 00 55 48 89 F5 53 48 81 EC 90 00 00 00 48 89 E6 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 85 DB 75 0B 48 89 EE 48 89 E7 E8 ?? ?? ?? ?? 48 81 C4 90 00 00 00 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __GI_tfind_cd4902c967cb84d316afa141fe9dd188 {
	meta:
		aliases = "tfind, __GI_tfind"
		size = "71"
		objfiles = "tfind@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 85 F6 49 89 FC 55 48 89 D5 53 48 89 F3 74 2E EB 24 48 8B 30 4C 89 E7 FF D5 83 F8 00 75 05 48 8B 03 EB 1C 7D 09 48 8B 1B 48 83 C3 08 EB 07 48 8B 1B 48 83 C3 10 48 8B 03 48 85 C0 75 D4 31 C0 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule wcstok_871debd9b20d4bdf076e3fc156fd3871 {
	meta:
		aliases = "wcstok"
		size = "90"
		objfiles = "wcstok@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 85 FF 49 89 D4 55 48 89 F5 53 48 89 FB 75 08 48 8B 1A 48 85 DB 74 38 48 89 DF 48 89 EE E8 ?? ?? ?? ?? 48 8D 1C 83 83 3B 00 75 06 31 DB 31 C0 EB 1A 48 89 EE 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 74 0A C7 00 00 00 00 00 48 83 C0 04 49 89 04 24 48 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __GI_strtok_r_95e1fe7d95cceb17df56a3731420047e {
	meta:
		aliases = "strtok_r, __GI_strtok_r"
		size = "94"
		objfiles = "strtok_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 85 FF 49 89 F4 55 48 89 D5 53 48 89 FB 75 03 48 8B 1A 48 89 DF 4C 89 E6 E8 ?? ?? ?? ?? 48 01 C3 80 3B 00 75 08 31 C0 48 89 5D 00 EB 29 4C 89 E6 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 75 0C 31 F6 48 89 DF E8 ?? ?? ?? ?? EB 06 C6 00 00 48 FF C0 48 89 45 00 48 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule pthread_detach_ab317b1031170fe19941bd0864695f11 {
	meta:
		aliases = "pthread_detach"
		size = "210"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 89 F8 31 F6 25 FF 03 00 00 49 89 FC 55 48 C1 E0 05 48 8D A8 ?? ?? ?? ?? 53 48 89 EF 48 81 EC B0 00 00 00 E8 ?? ?? ?? ?? 48 8B 45 10 48 85 C0 74 06 4C 39 60 20 74 0F 48 89 EF E8 ?? ?? ?? ?? B8 03 00 00 00 EB 7D 80 78 51 00 74 0F 48 89 EF E8 ?? ?? ?? ?? B8 16 00 00 00 EB 68 48 83 78 68 00 74 0A 48 89 EF E8 ?? ?? ?? ?? EB 55 0F BE 58 50 C6 40 51 01 48 89 EF E8 ?? ?? ?? ?? 85 DB 74 41 83 3D ?? ?? ?? ?? 00 78 38 E8 EF FB FF FF 48 89 04 24 C7 44 24 08 01 00 00 00 4C 89 64 24 10 8B 3D ?? ?? ?? ?? 48 89 E6 BA A8 00 00 00 E8 ?? ?? ?? ?? 48 FF C0 75 0A E8 ?? ?? ?? ?? 83 38 04 74 DE 31 C0 48 81 }
	condition:
		$pattern
}

rule pthread_kill_80bdc3d2f09465278f100642c41cd0e4 {
	meta:
		aliases = "pthread_kill"
		size = "110"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 89 F8 41 89 F4 25 FF 03 00 00 31 F6 48 C1 E0 05 55 48 8D A8 ?? ?? ?? ?? 53 48 89 FB 48 89 EF E8 ?? ?? ?? ?? 48 8B 45 10 48 85 C0 74 06 48 39 58 20 74 0F 48 89 EF E8 ?? ?? ?? ?? BA 03 00 00 00 EB 22 8B 58 28 48 89 EF E8 ?? ?? ?? ?? 44 89 E6 89 DF E8 ?? ?? ?? ?? 31 D2 FF C0 75 07 E8 ?? ?? ?? ?? 8B 10 5B 5D 41 5C 89 D0 C3 }
	condition:
		$pattern
}

rule pthread_kill_all_threads_588c23c61a9a224ad89b1d65b5e729c0 {
	meta:
		aliases = "pthread_kill_all_threads"
		size = "67"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 8B 05 ?? ?? ?? ?? 41 89 F4 55 89 FD 53 48 8B 18 EB 0D 8B 7B 28 89 EE E8 ?? ?? ?? ?? 48 8B 1B 48 3B 1D ?? ?? ?? ?? 75 EA 45 85 E4 74 0E 8B 7B 28 89 EE 5B 5D 41 5C E9 ?? ?? ?? ?? 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule _dl_run_init_array_444c635cf44fbc216311a8ed567a6ad3 {
	meta:
		aliases = "_dl_run_init_array"
		size = "59"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 8B 87 48 01 00 00 48 8B 0F 48 8B 97 58 01 00 00 55 48 85 C0 53 74 1C 49 89 D4 48 8D 2C 01 31 DB 49 C1 EC 03 EB 08 89 D8 FF C3 FF 54 C5 00 44 39 E3 72 F3 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __GI_inet_ntoa_r_abbc8d5e30456a48a4a04202e04d23aa {
	meta:
		aliases = "inet_ntoa_r, __GI_inet_ntoa_r"
		size = "77"
		objfiles = "inet_ntoa@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 8D 46 0F 45 31 E4 0F CF 55 31 ED 53 89 FB EB 2C 89 DE 31 C9 BA F6 FF FF FF 81 E6 FF 00 00 00 48 89 C7 E8 ?? ?? ?? ?? 48 FF C8 48 85 ED 74 04 C6 45 00 2E C1 EB 08 41 FF C4 48 89 C5 41 83 FC 03 7E CE 5B 5D 41 5C 48 FF C0 C3 }
	condition:
		$pattern
}

rule __GI___cxa_atexit_74a4667f311466b0ed569a94f7e919f2 {
	meta:
		aliases = "__cxa_atexit, __GI___cxa_atexit"
		size = "61"
		objfiles = "__cxa_atexit@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 D4 31 D2 48 85 FF 55 48 89 F5 53 48 89 FB 74 22 E8 ?? ?? ?? ?? 83 CA FF 48 85 C0 74 15 48 89 58 08 48 89 68 10 31 D2 4C 89 60 18 48 C7 00 03 00 00 00 5B 5D 41 5C 89 D0 C3 }
	condition:
		$pattern
}

rule _pthread_cleanup_push_67f513242058e016d346083fa83d91bd {
	meta:
		aliases = "_pthread_cleanup_push"
		size = "61"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 D4 55 48 89 FD 53 48 89 F3 E8 00 FF FF FF 48 89 5D 00 4C 89 65 08 48 8B 50 70 48 85 D2 48 89 55 18 74 0D 48 39 D5 72 08 48 C7 45 18 00 00 00 00 48 89 68 70 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule _pthread_cleanup_push_defer_7f1f0188e1b5dea9aed2ccadc7a9a73d {
	meta:
		aliases = "__pthread_cleanup_push_defer, _pthread_cleanup_push_defer"
		size = "75"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 D4 55 48 89 FD 53 48 89 F3 E8 68 FF FF FF 48 89 5D 00 48 89 C2 4C 89 65 08 0F BE 40 79 89 45 10 48 8B 42 70 48 85 C0 48 89 45 18 74 0D 48 39 C5 72 08 48 C7 45 18 00 00 00 00 C6 42 79 00 48 89 6A 70 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule pthread_sigmask_32dc588768addd40486aa509ac58b4fd {
	meta:
		aliases = "pthread_sigmask"
		size = "138"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 D4 55 89 FD 53 48 83 C4 80 48 85 F6 74 56 BA 80 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 83 FD 01 74 33 83 FD 02 74 06 85 ED 74 10 EB 36 8B 35 ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 85 F6 7E 10 EB 06 8B 35 ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? 48 89 E6 4C 89 E2 89 EF E8 ?? ?? ?? ?? 31 D2 FF C0 75 07 E8 ?? ?? ?? ?? 8B 10 48 83 EC 80 89 D0 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __pthread_internal_tsd_set_39c2b56d9a235ad2e87e0f5409c746e8 {
	meta:
		aliases = "__pthread_internal_tsd_set"
		size = "35"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 53 89 FB 48 63 DB 48 83 EC 08 E8 7D FF FF FF 4C 89 A4 D8 48 02 00 00 31 C0 5A 5B 41 5C C3 }
	condition:
		$pattern
}

rule pthread_mutex_timedlock_323dbe7ba6f4dc234d03429f1cb6dffe {
	meta:
		aliases = "pthread_mutex_timedlock"
		size = "199"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 48 89 FD 53 48 81 7E 08 FF C9 9A 3B 0F 87 9C 00 00 00 8B 47 10 83 F8 01 74 24 7F 09 85 C0 74 11 E9 89 00 00 00 83 F8 02 74 42 83 F8 03 75 7F EB 67 48 8D 7F 18 31 F6 E8 ?? ?? ?? ?? EB 11 E8 55 FE FF FF 48 39 45 08 48 89 C3 75 07 FF 45 04 31 D2 EB 67 48 8D 7D 18 48 89 C6 E8 ?? ?? ?? ?? 48 89 5D 08 C7 45 04 00 00 00 00 EB E3 E8 27 FE FF FF 48 39 45 08 48 89 C3 BA 23 00 00 00 74 3B 48 8D 7D 18 4C 89 E2 48 89 C6 E8 ?? ?? ?? ?? 85 C0 74 23 48 89 5D 08 EB B7 48 8D 7F 18 48 89 F2 31 F6 E8 ?? ?? ?? ?? 31 D2 85 C0 75 0E EB 07 BA 16 00 00 00 EB 05 BA 6E 00 00 00 5B 5D 41 5C 89 D0 C3 }
	condition:
		$pattern
}

rule pthread_once_f7a9de83ac2106807ae73db55c0445fe {
	meta:
		aliases = "__pthread_once, pthread_once"
		size = "207"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 48 89 FD 53 48 83 EC 20 83 3F 02 75 05 E9 AC 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 00 89 D0 83 E0 03 FF C8 75 23 83 E2 FC 3B 15 ?? ?? ?? ?? 74 18 C7 45 00 00 00 00 00 EB 0F BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 00 89 D0 83 E0 03 FF C8 74 E5 31 DB 85 D2 75 49 8B 05 ?? ?? ?? ?? BF ?? ?? ?? ?? 83 C8 01 89 45 00 E8 ?? ?? ?? ?? 48 89 EA BE ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? 41 FF D4 31 F6 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BB 01 00 00 00 C7 45 00 02 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 DB 74 0A BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 C4 20 }
	condition:
		$pattern
}

rule pmap_unset_2405b45d7e4150bfec0fdacaae70d518 {
	meta:
		aliases = "__GI_pmap_unset, pmap_unset"
		size = "217"
		objfiles = "pmap_clnt@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 48 89 FD 53 48 83 EC 50 48 8D 5C 24 30 C7 44 24 4C FF FF FF FF 48 89 DF E8 9B FE FF FF 85 C0 0F 84 A3 00 00 00 48 8B 0D ?? ?? ?? ?? 4C 8B 05 ?? ?? ?? ?? 4C 8D 4C 24 4C 48 89 DF BA 02 00 00 00 BE A0 86 01 00 C7 44 24 08 90 01 00 00 C7 04 24 90 01 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 67 48 89 6C 24 10 4C 89 64 24 18 48 8D 4C 24 10 48 C7 44 24 20 00 00 00 00 48 C7 44 24 28 00 00 00 00 4C 8D 4C 24 48 4C 8B 50 08 48 8B 05 ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? BA ?? ?? ?? ?? BE 02 00 00 00 48 89 DF 48 89 04 24 48 8B 05 ?? ?? ?? ?? 48 89 44 24 08 41 FF 12 48 8B 43 08 48 89 DF FF 50 20 }
	condition:
		$pattern
}

rule __encode_question_222b9cfed52f5d88af83d97130a32b28 {
	meta:
		aliases = "__encode_question"
		size = "80"
		objfiles = "encodeq@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 48 89 FD 53 48 8B 3F 89 D3 E8 ?? ?? ?? ?? 85 C0 89 C1 78 2F 29 C3 83 FB 03 7F 05 83 C9 FF EB 23 48 63 D0 0F B6 45 09 83 C1 04 49 8D 14 14 88 02 8B 45 08 88 42 01 0F B6 45 0D 88 42 02 8B 45 0C 88 42 03 5B 5D 41 5C 89 C8 C3 }
	condition:
		$pattern
}

rule __GI_wcscasecmp_927e133d075718c3177d3be609cda204 {
	meta:
		aliases = "wcscasecmp, __GI_wcscasecmp"
		size = "99"
		objfiles = "wcscasecmp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 48 89 FD 53 EB 0E 83 7D 00 00 74 41 48 83 C5 04 49 83 C4 04 8B 7D 00 41 3B 3C 24 74 E9 E8 ?? ?? ?? ?? 41 8B 3C 24 89 C3 E8 ?? ?? ?? ?? 39 C3 74 D5 8B 7D 00 E8 ?? ?? ?? ?? 41 8B 3C 24 89 C3 E8 ?? ?? ?? ?? 83 CA FF 39 C3 72 0B EB 04 31 D2 EB 05 BA 01 00 00 00 5B 5D 41 5C 89 D0 C3 }
	condition:
		$pattern
}

rule vdprintf_3e276dae4a6d1b9c31585e063ceac8b6 {
	meta:
		aliases = "__GI_vdprintf, vdprintf"
		size = "165"
		objfiles = "vdprintf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 53 48 89 D3 48 81 EC C0 00 00 00 48 8D 84 24 80 00 00 00 48 8D 94 24 C0 00 00 00 89 7C 24 04 48 8D 7C 24 58 66 C7 04 24 D0 00 C6 44 24 02 00 48 89 54 24 10 48 89 44 24 08 48 89 44 24 28 48 89 44 24 30 48 89 44 24 18 48 89 44 24 20 C7 44 24 48 00 00 00 00 C7 44 24 50 01 00 00 00 E8 ?? ?? ?? ?? 48 89 DA 4C 89 E6 48 89 E7 48 C7 44 24 38 00 00 00 00 E8 ?? ?? ?? ?? 85 C0 89 C3 7E 12 48 89 E7 E8 ?? ?? ?? ?? 85 C0 B8 FF FF FF FF 0F 45 D8 48 81 C4 C0 00 00 00 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __GI_pthread_cond_wait_191d66e58e91d39d83ef5ecc762561d1 {
	meta:
		aliases = "pthread_cond_wait, __GI_pthread_cond_wait"
		size = "355"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 53 48 89 FB 48 83 EC 20 E8 94 FD FF FF 48 89 44 24 18 41 8B 44 24 10 83 F8 03 0F 95 C2 85 C0 0F 95 C0 84 D0 74 15 48 8B 44 24 18 49 39 44 24 08 BA 16 00 00 00 0F 85 17 01 00 00 48 8B 44 24 18 48 89 1C 24 48 89 E6 48 C7 44 24 08 ?? ?? ?? ?? C6 80 D1 02 00 00 00 48 8B 7C 24 18 E8 AB FC FF FF 48 8B 74 24 18 48 89 DF E8 ?? ?? ?? ?? 48 8B 44 24 18 80 78 7A 00 74 10 48 8B 44 24 18 BD 01 00 00 00 80 78 78 00 74 10 48 8B 74 24 18 48 8D 7B 10 31 ED E8 E1 FB FF FF 48 89 DF E8 ?? ?? ?? ?? 85 ED 74 0E 48 8B 7C 24 18 31 F6 E8 5B FC FF FF EB 78 4C 89 E7 31 DB E8 ?? ?? ?? ?? 48 8B 7C 24 18 }
	condition:
		$pattern
}

rule __GI_pthread_attr_setschedpara_55484993d329653135ed4fc2f8eb5042 {
	meta:
		aliases = "pthread_attr_setschedparam, __GI_pthread_attr_setschedparam"
		size = "71"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 53 48 89 FB 8B 7F 04 E8 ?? ?? ?? ?? 8B 7B 04 89 C5 E8 ?? ?? ?? ?? 41 8B 14 24 39 C2 7C 19 39 EA 7F 15 48 8D 7B 08 BA 04 00 00 00 4C 89 E6 E8 ?? ?? ?? ?? 31 C0 EB 05 B8 16 00 00 00 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule svctcp_recv_19781b6bf0dbbd7e44ca9bfa3e5236e6 {
	meta:
		aliases = "svctcp_recv"
		size = "74"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 53 48 8B 6F 40 48 8D 5D 10 C7 45 10 01 00 00 00 48 89 DF E8 ?? ?? ?? ?? 4C 89 E6 48 89 DF E8 ?? ?? ?? ?? 85 C0 74 0F 49 8B 04 24 48 89 45 08 B8 01 00 00 00 EB 09 C7 45 00 00 00 00 00 31 C0 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule svcunix_recv_79312075c377da1ebc11575a33366ff9 {
	meta:
		aliases = "svcunix_recv"
		size = "101"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 53 48 8B 6F 40 48 8D 5D 10 C7 45 10 01 00 00 00 48 89 DF E8 ?? ?? ?? ?? 4C 89 E6 48 89 DF E8 ?? ?? ?? ?? 85 C0 74 2A 49 8B 04 24 48 89 45 08 B8 01 00 00 00 41 C7 44 24 48 01 00 00 00 49 C7 44 24 50 ?? ?? ?? ?? 41 C7 44 24 58 28 00 00 00 EB 09 C7 45 00 00 00 00 00 31 C0 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule if_indextoname_6bc0f04542869dafebd7735222b1fc55 {
	meta:
		aliases = "if_indextoname"
		size = "117"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 53 89 FB 48 83 EC 30 E8 ?? ?? ?? ?? 89 C5 31 C0 85 ED 78 52 48 89 E2 BE 10 89 00 00 89 EF 89 5C 24 10 E8 ?? ?? ?? ?? 85 C0 79 24 E8 ?? ?? ?? ?? 8B 18 89 EF 49 89 C4 E8 ?? ?? ?? ?? B8 06 00 00 00 83 FB 13 0F 44 D8 31 C0 41 89 1C 24 EB 17 89 EF E8 ?? ?? ?? ?? BA 10 00 00 00 48 89 E6 4C 89 E7 E8 ?? ?? ?? ?? 48 83 C4 30 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule trecurse_02a1778a5f6ec71ad778a22c57d39152 {
	meta:
		aliases = "trecurse"
		size = "114"
		objfiles = "twalk@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 89 D5 53 48 83 7F 08 00 48 89 FB 75 0C 48 83 7F 10 00 BE 03 00 00 00 74 46 31 F6 48 89 DF 89 EA 41 FF D4 48 8B 7B 08 48 85 FF 74 0B 8D 55 01 4C 89 E6 E8 C3 FF FF FF 48 89 DF 89 EA BE 01 00 00 00 41 FF D4 48 8B 7B 10 48 85 FF 74 0B 8D 55 01 4C 89 E6 E8 A2 FF FF FF 89 EA BE 02 00 00 00 48 89 DF 4D 89 E3 5B 5D 41 5C 41 FF E3 }
	condition:
		$pattern
}

rule __GI_getrpcbyname_9ee0c7b3a151107dc49dd59986903a89 {
	meta:
		aliases = "getrpcbyname, __GI_getrpcbyname"
		size = "88"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 31 FF 55 53 E8 ?? ?? ?? ?? EB 2E 48 8B 7D 00 4C 89 E6 E8 ?? ?? ?? ?? 85 C0 74 30 48 8B 5D 08 EB 10 4C 89 E6 E8 ?? ?? ?? ?? 85 C0 74 1E 48 83 C3 08 48 8B 3B 48 85 FF 75 E8 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 75 C5 E8 ?? ?? ?? ?? 5B 48 89 E8 5D 41 5C C3 }
	condition:
		$pattern
}

rule __GI_seed48_r_bb7285ed8a06f650a20d1dea092e2510 {
	meta:
		aliases = "seed48_r, __GI_seed48_r"
		size = "88"
		objfiles = "seed48_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 48 8D 7E 06 BA 06 00 00 00 53 48 89 F3 48 83 EC 08 E8 ?? ?? ?? ?? 66 41 8B 44 24 04 48 B9 6D E6 EC DE 05 00 00 00 66 89 43 04 66 41 8B 44 24 02 66 89 43 02 66 41 8B 04 24 48 89 4B 10 66 C7 43 0C 0B 00 66 C7 43 0E 01 00 66 89 03 31 C0 5A 5B 41 5C C3 }
	condition:
		$pattern
}

rule cond_extricate_func_5f37f31f0cdf162e5aa25c8e8f0e3ad7 {
	meta:
		aliases = "cond_extricate_func"
		size = "69"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 53 48 89 F3 48 83 EC 18 E8 A9 FF FF FF 48 89 44 24 10 48 8B 74 24 10 4C 89 E7 E8 ?? ?? ?? ?? 49 8D 7C 24 10 48 89 DE E8 83 FE FF FF 4C 89 E7 89 C3 E8 ?? ?? ?? ?? 89 D8 48 83 C4 18 5B 41 5C C3 }
	condition:
		$pattern
}

rule new_sem_extricate_func_3d322cbce827a8271668d97de96579d8 {
	meta:
		aliases = "new_sem_extricate_func"
		size = "69"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 53 48 89 F3 48 83 EC 18 E8 A9 FF FF FF 48 89 44 24 10 48 8B 74 24 10 4C 89 E7 E8 ?? ?? ?? ?? 49 8D 7C 24 18 48 89 DE E8 39 FE FF FF 4C 89 E7 89 C3 E8 ?? ?? ?? ?? 89 D8 48 83 C4 18 5B 41 5C C3 }
	condition:
		$pattern
}

rule getservbyname_60e45e9096203fa89306855a6472647e {
	meta:
		aliases = "getservbyname"
		size = "65"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 53 48 89 F3 48 83 EC 18 E8 FD FA FF FF 48 8B 0D ?? ?? ?? ?? 4C 8D 4C 24 10 48 89 DE 4C 89 E7 41 B8 19 11 00 00 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 44 24 10 48 83 C4 18 5B 41 5C C3 }
	condition:
		$pattern
}

rule siglongjmp_0ce50aa11f2db21434f5f07bf90c1ab3 {
	meta:
		aliases = "siglongjmp"
		size = "27"
		objfiles = "ptlongjmp@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 53 89 F3 48 83 EC 08 E8 29 FF FF FF 89 DE 4C 89 E7 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule longjmp_7b693769a2bb942cb5e3c47c6197ce7a {
	meta:
		aliases = "longjmp"
		size = "27"
		objfiles = "ptlongjmp@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 53 89 F3 48 83 EC 08 E8 44 FF FF FF 89 DE 4C 89 E7 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule gethostbyname2_4622dae09b8fb7a6ee67f09f103973ad {
	meta:
		aliases = "gethostbyname2"
		size = "65"
		objfiles = "gethostbyname2@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 53 89 F3 48 83 EC 18 E8 ?? ?? ?? ?? 4C 8D 4C 24 10 89 DE 4C 89 E7 41 B8 00 02 00 00 B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 04 24 E8 ?? ?? ?? ?? 48 8B 44 24 10 48 83 C4 18 5B 41 5C C3 }
	condition:
		$pattern
}

rule byte_common_op_match_null_stri_68160cd05574dac70d4c0103582b28e5 {
	meta:
		aliases = "byte_common_op_match_null_string_p"
		size = "276"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 48 89 D5 53 48 83 EC 10 48 8B 0F 48 89 4C 24 08 0F B6 01 48 8D 79 01 48 89 7C 24 08 83 F8 0C 77 24 83 F8 09 0F 83 CB 00 00 00 83 F8 06 74 39 83 F8 08 0F 84 B3 00 00 00 85 C0 0F 84 B5 00 00 00 E9 C0 00 00 00 83 F8 15 74 6A 77 0B 83 F8 0D 0F 85 B0 00 00 00 EB 45 83 E8 1A 83 F8 03 0F 87 A2 00 00 00 E9 8D 00 00 00 0F B6 59 01 48 8D 7C 24 08 E8 03 01 00 00 89 C6 48 63 DB 48 8D 4C DD 00 8A 01 83 E0 03 3C 03 75 0E 8A 01 89 F2 83 E2 03 83 E0 FC 09 D0 88 01 40 84 F6 EB 57 0F BE 47 01 0F B6 51 01 C1 E0 08 01 D0 78 5A 48 98 48 8D 44 01 03 EB 30 48 8D 71 03 48 89 74 24 08 0F BE 46 01 0F }
	condition:
		$pattern
}

rule _charpad_fc11b21d36190dd9990a91816b84fffb {
	meta:
		aliases = "_charpad"
		size = "68"
		objfiles = "_vfprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 48 89 D5 53 48 89 D3 48 83 EC 10 40 88 74 24 0F EB 03 48 FF CB 48 85 DB 74 17 48 8D 7C 24 0F 4C 89 E2 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 FF C8 74 E1 5A 59 48 29 DD 5B 48 89 E8 5D 41 5C C3 }
	condition:
		$pattern
}

rule _charpad_95c4516572a62c91ef61c77c1fbc00be {
	meta:
		aliases = "_charpad"
		size = "64"
		objfiles = "_vfwprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 48 89 D5 53 48 89 D3 48 83 EC 10 89 34 24 EB 03 48 FF CB 48 85 DB 74 15 48 89 E7 4C 89 E2 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 FF C8 74 E3 5A 59 48 29 DD 5B 48 89 E8 5D 41 5C C3 }
	condition:
		$pattern
}

rule svc_find_9dc4ccb88bc3a285bd6c6655aa70f163 {
	meta:
		aliases = "svc_find"
		size = "61"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 48 89 D5 53 48 89 F3 E8 ?? ?? ?? ?? 48 8B 80 F0 00 00 00 31 D2 EB 12 4C 39 60 08 75 06 48 39 58 10 74 0B 48 89 C2 48 8B 00 48 85 C0 75 E9 48 89 55 00 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __GI_gethostname_464545322024336dae2a43d1e6029732 {
	meta:
		aliases = "gethostname, __GI_gethostname"
		size = "94"
		objfiles = "gethostname@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 48 89 F5 53 48 81 EC 90 01 00 00 48 89 E7 48 89 E3 E8 ?? ?? ?? ?? 83 F8 FF 74 31 48 83 C3 41 48 89 DF E8 ?? ?? ?? ?? 48 FF C0 48 39 E8 76 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 0D 48 89 DE 4C 89 E7 E8 ?? ?? ?? ?? 31 C0 48 81 C4 90 01 00 00 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __libc_getdomainname_abc0f90b16749a5b018acbca3906957b {
	meta:
		aliases = "__GI___libc_getdomainname, __GI_getdomainname, getdomainname, __libc_getdomainname"
		size = "97"
		objfiles = "getdomainname@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 48 89 F5 53 48 81 EC 90 01 00 00 48 89 E7 48 89 E3 E8 ?? ?? ?? ?? 83 F8 FF 74 34 48 81 C3 45 01 00 00 48 89 DF E8 ?? ?? ?? ?? 48 FF C0 48 39 E8 76 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 0D 48 89 DE 4C 89 E7 E8 ?? ?? ?? ?? 31 C0 48 81 C4 90 01 00 00 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule _Unwind_RaiseException_Phase2_a4a333df2e594c69894ee8f52df8ea01 {
	meta:
		aliases = "_Unwind_RaiseException_Phase2"
		size = "120"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 48 89 F5 53 48 8B 06 EB 36 90 4D 85 C9 74 21 89 DE 49 89 E8 4C 89 E1 83 CE 02 49 8B 14 24 BF 01 00 00 00 41 FF D1 83 F8 07 74 3D 83 F8 08 75 33 85 DB 75 39 48 8B 45 00 48 8B 00 48 89 45 00 45 31 C9 48 85 C0 BA 05 00 00 00 74 06 4C 8B 48 30 30 D2 31 DB 49 3B 44 24 18 0F 94 C3 C1 E3 02 85 D2 74 A7 B8 02 00 00 00 5B 5D 41 5C C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule rendezvous_request_363359a27f0b8834a47dd68ff2ed895b {
	meta:
		aliases = "rendezvous_request"
		size = "151"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 53 48 81 EC 90 00 00 00 48 8B 6F 40 C7 84 24 8C 00 00 00 6E 00 00 00 41 8B 3C 24 48 8D 94 24 8C 00 00 00 48 89 E6 E8 ?? ?? ?? ?? 85 C0 89 C3 79 0C E8 ?? ?? ?? ?? 83 38 04 75 48 EB CF 4C 8D 64 24 70 BA 10 00 00 00 31 F6 4C 89 E7 E8 ?? ?? ?? ?? 66 C7 44 24 70 01 00 8B 55 04 89 DF 8B 75 00 E8 FC F9 FF FF 48 8D 78 14 BA 10 00 00 00 4C 89 E6 48 89 C3 E8 ?? ?? ?? ?? 8B 84 24 8C 00 00 00 89 43 10 48 81 C4 90 00 00 00 31 C0 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __GI_if_nametoindex_f972dad1fdb56a40c7ae4557b7e3564d {
	meta:
		aliases = "if_nametoindex, __GI_if_nametoindex"
		size = "115"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 53 48 83 EC 30 E8 ?? ?? ?? ?? 85 C0 89 C5 78 52 BA 10 00 00 00 4C 89 E6 48 89 E7 E8 ?? ?? ?? ?? 31 C0 48 89 E2 BE 33 89 00 00 89 EF E8 ?? ?? ?? ?? 85 C0 79 20 E8 ?? ?? ?? ?? 8B 18 89 EF 49 89 C4 E8 ?? ?? ?? ?? 83 FB 16 75 17 41 C7 04 24 26 00 00 00 EB 0D 89 EF E8 ?? ?? ?? ?? 8B 44 24 10 EB 02 31 C0 48 83 C4 30 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __pthread_do_exit_60519f3c86345d11ad2c1b9e05d3f572 {
	meta:
		aliases = "__pthread_do_exit"
		size = "236"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 53 48 89 F3 48 81 EC B0 00 00 00 E8 58 FF FF FF 48 89 DF 48 89 C5 C6 40 78 01 C6 40 79 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 7D 30 48 89 EE E8 ?? ?? ?? ?? 83 BD A4 02 00 00 00 4C 89 65 58 74 2E 8B 05 ?? ?? ?? ?? 0B 85 A8 02 00 00 F6 C4 01 74 1D C7 85 B0 02 00 00 09 00 00 00 48 89 AD B8 02 00 00 48 89 2D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 5D 68 48 8B 7D 30 C6 45 50 01 E8 ?? ?? ?? ?? 48 85 DB 74 08 48 89 DF E8 ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? 48 39 DD 75 46 83 3D ?? ?? ?? ?? 00 78 3D 48 89 1C 24 C7 44 24 08 03 00 00 00 8B 3D ?? ?? ?? ?? 48 89 E6 BA A8 00 00 00 E8 ?? ?? ?? ?? 48 }
	condition:
		$pattern
}

rule xdr_callmsg_89cfa7ca0cc3e1df71901f5e32e1c4f4 {
	meta:
		aliases = "__GI_xdr_callmsg, xdr_callmsg"
		size = "856"
		objfiles = "rpc_cmsg@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 53 83 3F 00 48 89 F3 0F 85 F6 00 00 00 8B 4E 40 81 F9 90 01 00 00 0F 87 28 03 00 00 8B 46 58 3D 90 01 00 00 0F 87 1A 03 00 00 48 8B 57 08 8D 71 03 83 C0 03 83 E0 FC 83 E6 FC 8D 74 06 28 FF 52 30 48 85 C0 48 89 C2 0F 84 B6 00 00 00 8B 03 48 8D 72 04 0F C8 89 02 8B 43 08 0F C8 89 42 04 83 7B 08 00 0F 85 DB 02 00 00 8B 43 10 48 8D 4A 08 0F C8 89 46 04 48 83 7B 10 02 0F 85 C4 02 00 00 48 8D 6B 30 8B 43 18 4C 8D 62 20 0F C8 89 41 04 8B 43 20 0F C8 89 42 10 8B 43 28 0F C8 89 42 14 8B 43 30 0F C8 89 42 18 8B 45 10 0F C8 89 42 1C 8B 45 10 85 C0 74 1A 48 8B 75 08 4C 89 E7 89 C2 E8 ?? }
	condition:
		$pattern
}

rule wcsdup_2ddfb0542661823addfbfdcc0fe4a3ad {
	meta:
		aliases = "wcsdup"
		size = "58"
		objfiles = "wcsdup@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 53 E8 ?? ?? ?? ?? 48 8D 2C 85 04 00 00 00 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 0E 48 89 EA 4C 89 E6 48 89 C7 E8 ?? ?? ?? ?? 48 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __GI_strdup_928dc0fe883cbf38536f3a6987ccba7a {
	meta:
		aliases = "strdup, __GI_strdup"
		size = "54"
		objfiles = "strdup@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 53 E8 ?? ?? ?? ?? 48 8D 68 01 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 0E 48 89 EA 4C 89 E6 48 89 C7 E8 ?? ?? ?? ?? 48 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __GI_strndup_10814bf1eca227bcec5f68c16fc201d4 {
	meta:
		aliases = "strndup, __GI_strndup"
		size = "58"
		objfiles = "strndup@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 53 E8 ?? ?? ?? ?? 48 8D 78 01 48 89 C5 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 12 48 89 EA 4C 89 E6 48 89 C7 E8 ?? ?? ?? ?? C6 04 2B 00 48 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __pthread_perform_cleanup_d57c6afaebe1c336cf0f1aaa63705f0c {
	meta:
		aliases = "__pthread_perform_cleanup"
		size = "65"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 53 E8 AF FF FF FF 48 8B 58 70 48 89 C5 EB 0F 4C 39 E3 76 0F 48 8B 7B 08 FF 13 48 8B 5B 18 48 85 DB 75 EC 48 83 BD 58 02 00 00 00 74 09 5B 5D 41 5C E9 ?? ?? ?? ?? 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule openlog_57cf106c60ddf9b508f2a3595b886c1d {
	meta:
		aliases = "__GI_openlog, openlog"
		size = "318"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 89 D5 BA ?? ?? ?? ?? 53 89 F3 BE ?? ?? ?? ?? 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 4D 85 E4 89 1D ?? ?? ?? ?? 49 0F 45 C4 85 ED 48 89 05 ?? ?? ?? ?? 74 15 8B 05 ?? ?? ?? ?? F7 C5 07 FC FF FF 0F 44 C5 89 05 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? FF BD 02 00 00 00 75 62 F6 05 ?? ?? ?? ?? 08 74 59 31 D2 BF 01 00 00 00 89 EE E8 ?? ?? ?? ?? 83 F8 FF 89 C7 89 05 ?? ?? ?? ?? 0F 84 93 00 00 00 BA 01 00 00 00 BE 02 00 00 00 31 C0 E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? BE 03 00 00 00 31 C0 E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 80 CC 08 BE 04 00 00 00 89 C2 }
	condition:
		$pattern
}

rule xprt_unregister_0dfde0e7fc3c959867216c6ebcfbf2bd {
	meta:
		aliases = "__GI_xprt_unregister, xprt_unregister"
		size = "136"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 8B 2F 53 E8 ?? ?? ?? ?? 39 C5 7D 71 E8 ?? ?? ?? ?? 48 63 DD 48 8B 80 E8 00 00 00 48 8D 14 DD 00 00 00 00 4C 39 24 10 75 54 81 FD FF 03 00 00 48 C7 04 10 00 00 00 00 7F 1C E8 ?? ?? ?? ?? 89 E9 48 C1 EB 06 48 C7 C2 FE FF FF FF 83 E1 3F 48 D3 C2 48 21 14 D8 31 DB EB 1B E8 ?? ?? ?? ?? 48 63 D3 48 C1 E2 03 48 03 10 39 2A 75 06 C7 02 FF FF FF FF FF C3 E8 ?? ?? ?? ?? 3B 18 7C DC 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule sigwait_6a8e4e529cadd57e2f9cfcac1175ef1c {
	meta:
		aliases = "sigwait"
		size = "355"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 BD 01 00 00 00 53 48 81 EC 10 02 00 00 48 89 74 24 08 E8 E8 FD FF FF 48 8D 9C 24 80 01 00 00 48 89 84 24 08 02 00 00 48 89 DF E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? EB 79 89 EE 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 74 69 3B 2D ?? ?? ?? ?? 74 61 3B 2D ?? ?? ?? ?? 74 59 3B 2D ?? ?? ?? ?? 74 51 48 8D BC 24 80 01 00 00 89 EE E8 ?? ?? ?? ?? 48 63 C5 48 83 3C C5 ?? ?? ?? ?? 01 77 34 48 8D 9C 24 E0 00 00 00 48 C7 84 24 E0 00 00 00 ?? ?? ?? ?? 48 8D 7B 08 E8 ?? ?? ?? ?? 31 D2 48 89 DE 89 EF C7 84 24 68 01 00 00 00 00 00 00 E8 ?? ?? ?? ?? FF C5 83 FD 41 7E 82 48 8D 7C 24 10 }
	condition:
		$pattern
}

rule getnetbyname_be87f83c476990b4a02e4989d3192038 {
	meta:
		aliases = "getnetbyname"
		size = "101"
		objfiles = "getnetbynm@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 8B 3D ?? ?? ?? ?? 55 53 E8 ?? ?? ?? ?? EB 2E 48 8B 7D 00 4C 89 E6 E8 ?? ?? ?? ?? 85 C0 74 2B 48 8B 5D 08 EB 10 4C 89 E6 E8 ?? ?? ?? ?? 85 C0 74 19 48 83 C3 08 48 8B 3B 48 85 FF 75 E8 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 75 C5 83 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 5B 48 89 E8 5D 41 5C C3 }
	condition:
		$pattern
}

rule __GI_nanosleep_63f587e4af7130c1b60d9c182931d535 {
	meta:
		aliases = "nanosleep, __GI_nanosleep"
		size = "62"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC BF 01 00 00 00 53 48 89 F3 48 83 EC 18 48 8D 74 24 14 E8 ?? ?? ?? ?? 48 89 DE 4C 89 E7 E8 ?? ?? ?? ?? 8B 7C 24 14 89 C3 31 F6 E8 ?? ?? ?? ?? 89 D8 48 83 C4 18 5B 41 5C C3 }
	condition:
		$pattern
}

rule open64_626ee9a2af22e5a8ad132244b496ecc2 {
	meta:
		aliases = "open, open64"
		size = "109"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC BF 01 00 00 00 53 89 F3 48 81 EC D8 00 00 00 48 8D 74 24 1C 48 89 54 24 30 E8 ?? ?? ?? ?? 48 8D 84 24 F0 00 00 00 C7 04 24 18 00 00 00 89 DE 4C 89 E7 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 48 83 C0 10 8B 10 31 C0 E8 ?? ?? ?? ?? 8B 7C 24 1C 89 C3 31 F6 E8 ?? ?? ?? ?? 89 D8 48 81 C4 D8 00 00 00 5B 41 5C C3 }
	condition:
		$pattern
}

rule pthread_key_create_3c14d3648f88941cd750d50d11f29dd7 {
	meta:
		aliases = "pthread_key_create"
		size = "105"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC BF ?? ?? ?? ?? 55 48 89 F5 53 31 DB E8 ?? ?? ?? ?? EB 35 48 63 C3 48 C1 E0 04 83 B8 ?? ?? ?? ?? 00 75 23 BF ?? ?? ?? ?? C7 80 ?? ?? ?? ?? 01 00 00 00 48 89 A8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 41 89 1C 24 EB 19 FF C3 81 FB FF 03 00 00 7E C3 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 0B 00 00 00 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule svcunix_reply_aee213947b63da36c090a870ec1f50d4 {
	meta:
		aliases = "svctcp_reply, svcunix_reply"
		size = "59"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 53 48 83 EC 08 48 8B 47 40 4C 8D 60 10 C7 40 10 00 00 00 00 48 8B 40 08 4C 89 E7 48 89 06 E8 ?? ?? ?? ?? 4C 89 E7 BE 01 00 00 00 89 C3 E8 ?? ?? ?? ?? 5A 89 D8 5B 41 5C C3 }
	condition:
		$pattern
}

rule xdr_double_34ce6ce8729bb534299c0cff895d562a {
	meta:
		aliases = "xdr_double"
		size = "155"
		objfiles = "xdr_float@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 F5 53 48 89 FB 48 83 EC 10 8B 07 83 F8 01 74 46 72 0C 83 F8 02 BA 01 00 00 00 74 71 EB 6D 48 63 46 04 48 89 04 24 48 63 06 48 89 E6 48 89 44 24 08 48 8B 47 08 FF 50 08 31 D2 85 C0 74 4F 48 8B 43 08 48 8D 74 24 08 48 89 DF FF 50 08 31 D2 85 C0 0F 95 C2 EB 37 48 8B 47 08 48 8D 74 24 08 FF 10 85 C0 74 26 48 8B 43 08 48 89 E6 48 89 DF FF 10 85 C0 74 16 48 8B 04 24 BA 01 00 00 00 89 45 00 48 8B 44 24 08 89 45 04 EB 02 31 D2 5E 5F 5B 5D 41 5C 89 D0 C3 }
	condition:
		$pattern
}

rule __des_crypt_e7554d313dd97eb6e4e227dac84f8509 {
	meta:
		aliases = "__des_crypt"
		size = "407"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 F5 53 48 89 FB 48 83 EC 10 E8 A5 F5 FF FF 48 89 E2 EB 11 8A 03 01 C0 88 02 48 FF C2 80 7A FF 01 48 83 DB FF 48 89 D0 48 89 E7 48 29 E0 48 83 F8 08 75 E0 E8 65 FD FF FF 44 0F BE 65 00 0F BE 7D 01 44 88 25 ?? ?? ?? ?? 8A 45 01 84 C0 41 0F 44 C4 88 05 ?? ?? ?? ?? E8 18 F5 FF FF 89 C3 44 89 E7 C1 E3 06 E8 0B F5 FF FF 09 C3 89 DF E8 46 F9 FF FF 48 8D 54 24 0C 48 8D 4C 24 08 31 F6 31 FF 41 B8 19 00 00 00 E8 73 F9 FF FF 31 D2 85 C0 0F 85 F3 00 00 00 8B 54 24 0C C6 05 ?? ?? ?? ?? 00 89 D0 89 D1 C1 E8 1A C1 E9 08 83 E0 3F 83 E1 3F 8A 80 ?? ?? ?? ?? 88 05 ?? ?? ?? ?? 89 D0 C1 E8 14 83 E0 }
	condition:
		$pattern
}

rule obstack_free_182f001303ea6dd3fdad291902ee1670 {
	meta:
		aliases = "obstack_free"
		size = "109"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 F5 53 48 8B 57 08 48 89 FB EB 25 F6 43 50 01 4C 8B 62 08 48 8B 43 40 74 0B 48 8B 7B 48 48 89 D6 FF D0 EB 05 48 89 D7 FF D0 80 4B 50 02 4C 89 E2 48 85 D2 74 24 48 39 EA 73 D1 48 39 2A 72 CC 48 85 D2 74 15 48 89 6B 18 48 89 6B 10 48 8B 02 48 89 53 08 48 89 43 20 EB 0A 48 85 ED 74 05 E8 ?? ?? ?? ?? 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule pathconf_bb532de259921c348f9e365e7bd94beb {
	meta:
		aliases = "pathconf"
		size = "201"
		objfiles = "pathconf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 81 EC 90 00 00 00 80 3F 00 75 0D E8 ?? ?? ?? ?? C7 00 02 00 00 00 EB 23 83 FE 13 77 13 89 F0 FF 24 C5 ?? ?? ?? ?? B8 20 00 00 00 E9 85 00 00 00 E8 ?? ?? ?? ?? C7 00 16 00 00 00 48 83 C8 FF EB 74 B8 7F 00 00 00 EB 6D E8 ?? ?? ?? ?? 48 89 EF 48 89 E6 48 89 C3 44 8B 20 E8 ?? ?? ?? ?? 85 C0 79 0A 83 3B 26 75 D4 44 89 23 EB 36 48 8B 44 24 40 EB 42 31 C0 EB 3E 48 89 E6 E8 ?? ?? ?? ?? 85 C0 78 B8 8B 44 24 18 25 00 F0 00 00 3D 00 80 00 00 0F 95 C2 3D 00 60 00 00 0F 95 C0 84 D0 75 9B EB 0E B8 FF 00 00 00 EB 0C B8 00 10 00 00 EB 05 B8 01 00 00 00 48 81 C4 90 00 00 00 5B 5D 41 5C }
	condition:
		$pattern
}

rule feof_2de71bea0159b21a0b0be9fd204250a3 {
	meta:
		aliases = "feof"
		size = "83"
		objfiles = "feof@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 83 EC 20 44 8B 67 50 45 85 E4 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 45 85 E4 8B 5D 00 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 89 D8 5B 5D 41 5C 83 E0 04 C3 }
	condition:
		$pattern
}

rule ferror_3a04ed3445111157b5634172ca4daded {
	meta:
		aliases = "ferror"
		size = "83"
		objfiles = "ferror@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 83 EC 20 44 8B 67 50 45 85 E4 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 45 85 E4 8B 5D 00 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 89 D8 5B 5D 41 5C 83 E0 08 C3 }
	condition:
		$pattern
}

rule fgetwc_5cbe594d01d37de7b04e47bc8cfb7e00 {
	meta:
		aliases = "__GI_fgetwc, fileno, __GI_fileno, getwc, fgetwc"
		size = "87"
		objfiles = "fileno@libc.a, fgetwc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 83 EC 20 44 8B 67 50 45 85 E4 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 45 85 E4 89 C3 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule clearerr_91b9da6e4876f7bbcc34aa7537df286c {
	meta:
		aliases = "clearerr"
		size = "80"
		objfiles = "clearerr@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 83 EC 20 44 8B 67 50 45 85 E4 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 66 83 65 00 F3 45 85 E4 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __GI_rewind_eac8a33955e34a1f36e5f64ba9423574 {
	meta:
		aliases = "rewind, __GI_rewind"
		size = "92"
		objfiles = "rewind@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 83 EC 20 44 8B 67 50 45 85 E4 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 66 83 65 00 F7 31 D2 31 F6 48 89 EF E8 ?? ?? ?? ?? 45 85 E4 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __GI_fflush_02d0d0f56e9ea1ecfe73c3ba80ad1a74 {
	meta:
		aliases = "fflush, __GI_fflush"
		size = "113"
		objfiles = "fflush@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 83 EC 20 48 85 FF 74 4C 48 81 FF ?? ?? ?? ?? 74 43 44 8B 67 50 45 85 E4 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 45 85 E4 89 C3 75 19 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? EB 0A 48 89 EF E8 ?? ?? ?? ?? 89 C3 48 83 C4 20 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule gets_ae9c0b16582eb0aa3b639758b4919f74 {
	meta:
		aliases = "gets"
		size = "138"
		objfiles = "gets@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 83 EC 20 48 8B 05 ?? ?? ?? ?? 44 8B 60 50 45 85 E4 74 05 48 89 EB EB 26 48 8D 50 58 48 89 E7 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 83 C7 58 E8 ?? ?? ?? ?? EB D8 48 FF C3 E8 ?? ?? ?? ?? 83 F8 FF 74 06 3C 0A 88 03 75 ED FF C0 0F 94 C2 48 39 DD 0F 94 C0 08 C2 74 04 31 ED EB 03 C6 03 00 45 85 E4 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 48 89 E8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule closedir_2607f0ede770a0c5326c44350fcb6af3 {
	meta:
		aliases = "__GI_closedir, closedir"
		size = "116"
		objfiles = "closedir@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 83 EC 20 83 3F FF 75 10 E8 ?? ?? ?? ?? C7 00 09 00 00 00 83 C8 FF EB 4B 48 8D 5F 30 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 8B 5D 00 BE 01 00 00 00 48 89 E7 C7 45 00 FF FF FF FF E8 ?? ?? ?? ?? 48 8B 7D 18 E8 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 89 DF E8 ?? ?? ?? ?? 48 83 C4 20 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule ftello64_84ddae23c3618c4855e4b5e151b68507 {
	meta:
		aliases = "__GI_ftello64, ftello64"
		size = "154"
		objfiles = "ftello64@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 83 EC 30 48 C7 44 24 28 00 00 00 00 44 8B 67 50 45 85 E4 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 0F B7 45 00 31 D2 48 8D 5C 24 28 48 89 EF 48 89 DE 25 40 04 00 00 3D 40 04 00 00 0F 94 C2 FF C2 E8 ?? ?? ?? ?? 85 C0 78 0F 48 89 DE 48 89 EF E8 ?? ?? ?? ?? 85 C0 79 09 48 C7 44 24 28 FF FF FF FF 45 85 E4 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 8B 44 24 28 48 83 C4 30 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __pthread_cleanup_pop_restore_850ad896f69f48477984448c2cb66f5d {
	meta:
		aliases = "_pthread_cleanup_pop_restore, __pthread_cleanup_pop_restore"
		size = "80"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 89 F3 E8 C7 FE FF FF 85 DB 49 89 C4 74 07 48 8B 7D 08 FF 55 00 48 8B 45 18 41 80 7C 24 7A 00 49 89 44 24 70 8B 45 10 41 88 44 24 79 74 16 66 41 81 7C 24 78 00 01 75 0C 48 89 E6 48 83 CF FF E8 ?? ?? ?? ?? 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __GI_remove_05adc48a0046fce37e76e6d3668b5f82 {
	meta:
		aliases = "remove, __GI_remove"
		size = "55"
		objfiles = "remove@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 E8 ?? ?? ?? ?? 48 89 EF 48 89 C3 44 8B 20 E8 ?? ?? ?? ?? 85 C0 79 14 83 3B 14 75 0F 44 89 23 48 89 EF 5B 5D 41 5C E9 ?? ?? ?? ?? 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule get_cie_encoding_0f335b2a65154deafad2bb0e105437c2 {
	meta:
		aliases = "get_cie_encoding"
		size = "197"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 8D 6F 09 53 48 89 FB 48 83 EC 20 80 7F 09 7A 74 0B 48 83 C4 20 31 C0 5B 5D 41 5C C3 48 89 EF 4C 8D 64 24 10 E8 ?? ?? ?? ?? 48 8D 7C 05 01 4C 89 E6 E8 D6 FB FF FF 48 8D 74 24 08 48 89 C7 E8 F9 FB FF FF 80 7B 08 01 48 8D 78 01 74 0E 48 89 C7 4C 89 E6 E8 B4 FB FF FF 48 89 C7 4C 89 E6 48 89 EB E8 A6 FB FF FF 0F B6 55 01 48 8D 6C 24 18 80 FA 52 75 1C EB 3F 66 66 90 66 66 90 80 FA 4C 75 90 0F B6 53 02 48 FF C0 48 FF C3 80 FA 52 74 25 80 FA 50 75 E7 0F B6 38 48 8D 50 01 31 F6 48 89 E9 83 E7 7F E8 A3 FD FF FF 0F B6 53 02 48 FF C3 80 FA 52 75 DB 0F B6 00 48 83 C4 20 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __GI_fgetwc_unlocked_54da1f507f3e8937212c8a6de3c67ff0 {
	meta:
		aliases = "fgetwc_unlocked, getwc_unlocked, __GI_fgetwc_unlocked"
		size = "292"
		objfiles = "fgetwc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 48 89 FB 48 83 EC 10 0F B7 07 25 03 08 00 00 3D 00 08 00 00 77 15 BE 00 08 00 00 83 CD FF E8 ?? ?? ?? ?? 85 C0 0F 85 EC 00 00 00 0F B7 03 A8 02 74 33 A8 01 75 06 83 7B 44 00 74 06 C6 43 02 00 EB 06 8A 43 03 88 43 02 8B 03 48 89 C2 FF C8 83 E2 01 66 89 03 8B 6C 93 40 C7 43 44 00 00 00 00 E9 9D 00 00 00 48 83 7B 08 00 75 11 48 8D 74 24 0F 48 89 DF E8 6A FF FF FF 48 FF 43 10 83 7B 48 00 75 04 C6 43 02 00 48 8B 43 20 48 8B 73 18 89 C5 29 F5 85 ED 74 3E 4C 63 E5 48 8D 4B 48 48 89 E7 4C 89 E2 E8 ?? ?? ?? ?? 48 83 F8 00 48 89 C2 7C 15 B8 01 00 00 00 8B 2C 24 48 0F 44 D0 48 01 53 18 00 53 }
	condition:
		$pattern
}

rule scan_getwc_e06e334ebc05caeab9cf0d81fc6ac07d {
	meta:
		aliases = "scan_getwc"
		size = "157"
		objfiles = "vfscanf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 48 89 FB 48 83 EC 10 FF 4F 14 44 8B 67 14 45 85 E4 79 09 80 4F 1D 02 83 C8 FF EB 76 48 C7 C5 FD FF FF FF C7 47 14 FF FF FF 7F EB 2A 8B 03 48 8D 4B 20 48 8D 74 24 0F 48 89 E7 BA 01 00 00 00 88 44 24 0F E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 79 25 48 83 F8 FE 75 0C 48 89 DF E8 ?? ?? ?? ?? 85 C0 79 CA 48 83 FD FD 75 15 48 83 C5 02 C7 43 28 FF FF FF FF EB 17 8B 04 24 89 43 28 EB 0F E8 ?? ?? ?? ?? C7 00 54 00 00 00 C6 43 1F 01 44 89 63 14 89 E8 5A 59 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule rendezvous_request_054ace6217a3c71f5301ac7abdf2801d {
	meta:
		aliases = "rendezvous_request"
		size = "105"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 48 89 FB 48 83 EC 20 48 8B 6F 40 C7 44 24 1C 10 00 00 00 8B 3B 48 8D 54 24 1C 48 89 E6 E8 ?? ?? ?? ?? 85 C0 89 C7 79 0C E8 ?? ?? ?? ?? 83 38 04 75 28 EB D7 8B 55 04 8B 75 00 E8 A6 FB FF FF 48 8D 78 14 BA 10 00 00 00 48 89 E6 48 89 C3 E8 ?? ?? ?? ?? 8B 44 24 1C 89 43 10 48 83 C4 20 31 C0 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __ieee754_rem_pio2_74b1ff0bf6828ae73a3d92d27acf06b2 {
	meta:
		aliases = "__ieee754_rem_pio2"
		size = "814"
		objfiles = "e_rem_pio2@libm.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 48 89 FB 48 83 EC 30 F2 0F 11 44 24 08 48 8B 54 24 08 49 89 D4 49 C1 EC 20 44 89 E5 81 E5 FF FF FF 7F 81 FD FB 21 E9 3F 7F 11 F2 0F 11 07 48 C7 47 08 00 00 00 00 E9 27 02 00 00 81 FD 7B D9 02 40 0F 8F D3 00 00 00 45 85 E4 66 0F 12 0D ?? ?? ?? ?? 7E 64 0F 28 D0 81 FD FB 21 F9 3F F2 0F 5C D1 74 20 66 0F 12 0D ?? ?? ?? ?? 0F 28 C2 F2 0F 5C C1 F2 0F 11 07 0F 28 C2 F2 0F 5C 07 F2 0F 5C C1 EB 26 0F 28 C2 66 0F 12 15 ?? ?? ?? ?? F2 0F 5C 05 ?? ?? ?? ?? 0F 28 C8 F2 0F 5C CA F2 0F 5C C1 F2 0F 11 0F F2 0F 5C C2 B9 01 00 00 00 F2 0F 11 43 08 E9 67 02 00 00 0F 28 D1 81 FD FB 21 F9 3F F2 0F 58 }
	condition:
		$pattern
}

rule svc_getreq_common_30bba3b37d68ceb8b1b748ad571aa7fc {
	meta:
		aliases = "__GI_svc_getreq_common, svc_getreq_common"
		size = "422"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 89 FB 48 63 DB 48 81 EC 50 05 00 00 48 89 E0 48 89 A4 24 E8 04 00 00 48 05 90 01 00 00 48 89 84 24 00 05 00 00 E8 ?? ?? ?? ?? 49 89 C4 48 8B 80 E8 00 00 00 48 8B 1C D8 48 85 DB 0F 84 55 01 00 00 48 8B 43 08 48 8D AC 24 B0 04 00 00 48 89 DF 48 89 EE FF 10 85 C0 0F 84 17 01 00 00 48 8D 84 24 20 03 00 00 83 BC 24 E0 04 00 00 00 48 8D BC 24 28 05 00 00 48 8D B4 24 E0 04 00 00 B9 06 00 00 00 48 89 9C 24 48 05 00 00 48 89 84 24 40 05 00 00 48 8B 84 24 C8 04 00 00 FC F3 A5 48 89 84 24 10 05 00 00 48 8B 84 24 D0 04 00 00 48 89 84 24 18 05 00 00 48 8B 84 24 D8 04 00 00 48 89 84 24 20 05 00 }
	condition:
		$pattern
}

rule unlockpt_186971b2046302a582ce89b91a352270 {
	meta:
		aliases = "unlockpt"
		size = "78"
		objfiles = "unlockpt@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 89 FB 48 83 EC 10 E8 ?? ?? ?? ?? 48 8D 54 24 0C 44 8B 20 48 89 C5 BE 31 54 04 40 31 C0 89 DF C7 44 24 0C 00 00 00 00 E8 ?? ?? ?? ?? 31 D2 85 C0 74 0F 83 CA FF 83 7D 00 16 75 06 44 89 65 00 31 D2 89 D0 5A 59 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule pthread_mutex_trylock_e885e0c017597b574fbf1e6fa5ae9b93 {
	meta:
		aliases = "__pthread_mutex_trylock, pthread_mutex_trylock"
		size = "148"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 8B 47 10 48 89 FB 83 F8 01 74 26 7F 06 85 C0 74 13 EB 0A 83 F8 02 74 4A 83 F8 03 74 5F BD 16 00 00 00 EB 65 5B 5D 41 5C 48 8D 7F 18 E9 D9 FD FF FF E8 F8 FE FF FF 48 39 43 08 49 89 C4 75 07 FF 43 04 31 ED EB 43 48 8D 7B 18 E8 BB FD FF FF 85 C0 89 C5 75 34 4C 89 63 08 C7 43 04 00 00 00 00 EB 27 48 8D 7F 18 E8 C4 FD FF FF 85 C0 89 C5 75 18 E8 B8 FE FF FF 48 89 43 08 EB 0D 5B 5D 41 5C 48 8D 7F 18 E9 A6 FD FF FF 5B 89 E8 5D 41 5C C3 }
	condition:
		$pattern
}

rule fpathconf_f0159e76e9bee59fb866cc9996c8e564 {
	meta:
		aliases = "fpathconf"
		size = "204"
		objfiles = "fpathconf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 89 FD 53 48 81 EC 90 00 00 00 85 FF 79 0D E8 ?? ?? ?? ?? C7 00 09 00 00 00 EB 30 85 F6 B8 7F 00 00 00 0F 84 95 00 00 00 8D 46 FF 83 F8 12 77 10 89 C0 FF 24 C5 ?? ?? ?? ?? B8 20 00 00 00 EB 7D E8 ?? ?? ?? ?? C7 00 16 00 00 00 48 83 C8 FF EB 6C E8 ?? ?? ?? ?? 89 EF 48 89 E6 48 89 C3 44 8B 20 E8 ?? ?? ?? ?? 85 C0 79 0A 83 3B 26 75 DC 44 89 23 EB 36 48 8B 44 24 40 EB 42 31 C0 EB 3E 48 89 E6 E8 ?? ?? ?? ?? 85 C0 78 C0 8B 44 24 18 25 00 F0 00 00 3D 00 80 00 00 0F 95 C2 3D 00 60 00 00 0F 95 C0 84 D0 75 A3 EB 0E B8 FF 00 00 00 EB 0C B8 00 10 00 00 EB 05 B8 01 00 00 00 48 81 C4 90 00 00 00 5B }
	condition:
		$pattern
}

rule setlogmask_d133f4aa2d050d3e5455ac045a34194f {
	meta:
		aliases = "setlogmask"
		size = "80"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 89 FD 53 48 83 EC 20 85 FF 44 8B 25 ?? ?? ?? ?? 74 2F BE ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 89 2D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 C4 20 44 89 E0 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __ieee754_yn_95d05340ef784c84a167d3a75259aed0 {
	meta:
		aliases = "__ieee754_yn"
		size = "676"
		objfiles = "e_jn@libm.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 89 FD 53 48 83 EC 20 F2 0F 11 44 24 08 48 8B 5C 24 08 48 89 DE 89 D8 89 DA 48 C1 EE 20 F7 D8 09 D8 89 F1 81 E1 FF FF FF 7F C1 E8 1F 09 C8 3D 00 00 F0 7F 76 0C 0F 28 C8 F2 0F 58 C8 E9 54 02 00 00 09 CA 75 15 66 0F 12 0D ?? ?? ?? ?? F2 0F 5E 0D ?? ?? ?? ?? E9 3B 02 00 00 85 F6 79 0C 0F 57 C9 F2 0F 5E C9 E9 2B 02 00 00 85 FF 41 BC 01 00 00 00 79 0C F7 DD 89 E8 83 E0 01 01 C0 41 29 C4 85 ED 75 18 48 89 5C 24 08 66 0F 12 44 24 08 48 83 C4 20 5B 5D 41 5C E9 ?? ?? ?? ?? 83 FD 01 75 1E 48 89 5C 24 08 66 0F 12 44 24 08 E8 ?? ?? ?? ?? F2 41 0F 2A CC F2 0F 59 C8 E9 D6 01 00 00 81 F9 00 00 F0 7F }
	condition:
		$pattern
}

rule __ieee754_jn_2b4da4b089dd293a475f3328d560da27 {
	meta:
		aliases = "__ieee754_jn"
		size = "1052"
		objfiles = "e_jn@libm.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 89 FD 53 48 83 EC 50 F2 0F 11 44 24 08 48 8B 54 24 08 49 89 D4 89 D0 49 C1 EC 20 F7 D8 09 D0 44 89 E3 81 E3 FF FF FF 7F C1 E8 1F 09 D8 3D 00 00 F0 7F 76 0C 0F 28 C8 F2 0F 58 C8 E9 CD 03 00 00 85 FF 79 11 66 0F 57 05 ?? ?? ?? ?? F7 DD 41 81 EC 00 00 00 80 85 ED 75 0D 48 83 C4 50 5B 5D 41 5C E9 ?? ?? ?? ?? 83 FD 01 75 0D 48 83 C4 50 5B 5D 41 5C E9 ?? ?? ?? ?? 09 DA 0F 94 C2 81 FB FF FF EF 7F 0F 9F C0 08 C2 0F 85 6B 03 00 00 E8 ?? ?? ?? ?? F2 0F 11 44 24 48 F2 0F 2A C5 66 0F 12 4C 24 48 F2 0F 11 44 24 28 66 0F 2E C8 0F 82 4B 01 00 00 81 FB FF FF CF 52 0F 8E EE 00 00 00 89 E8 83 E0 03 83 }
	condition:
		$pattern
}

rule pthread_rwlock_tryrdlock_5eb902ddb83f733f109e337fd169a710 {
	meta:
		aliases = "pthread_rwlock_tryrdlock"
		size = "146"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 BD 10 00 00 00 53 48 89 FB 48 83 EC 20 E8 42 FE FF FF 48 8D 4C 24 1C 48 8D 54 24 08 48 8D 7C 24 10 48 89 DE 48 89 44 24 10 E8 06 FF FF FF 48 8B 74 24 10 48 89 DF 41 89 C4 E8 ?? ?? ?? ?? 31 F6 48 89 DF E8 16 FD FF FF 85 C0 74 06 FF 43 10 40 30 ED 48 89 DF E8 ?? ?? ?? ?? 85 ED 75 26 45 85 E4 75 07 83 7C 24 1C 00 74 1A 48 8B 44 24 08 48 85 C0 74 05 FF 40 10 EB 0B 48 8B 44 24 10 FF 80 F0 02 00 00 48 83 C4 20 89 E8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule lckpwdf_3c149ad0fc8ea6b9091fb7c83440186b {
	meta:
		aliases = "lckpwdf"
		size = "487"
		objfiles = "lckpwdf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 83 C8 FF 55 53 48 81 EC 80 02 00 00 39 05 ?? ?? ?? ?? 0F 85 C1 01 00 00 48 8D BC 24 40 02 00 00 BA ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 31 C0 BE 01 00 00 00 E8 ?? ?? ?? ?? 83 F8 FF 89 C7 89 05 ?? ?? ?? ?? 0F 84 6A 01 00 00 31 D2 31 C0 BE 01 00 00 00 E8 ?? ?? ?? ?? 83 F8 FF 89 C3 75 16 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 1D ?? ?? ?? ?? E9 3F 01 00 00 8B 3D ?? ?? ?? ?? 83 CB 01 31 C0 89 DA BE 02 00 00 00 E8 ?? ?? ?? ?? 85 C0 0F 88 0B 01 00 00 31 F6 BA 98 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 8D AC 24 A0 00 00 00 48 8D 7C 24 08 48 C7 04 24 ?? }
	condition:
		$pattern
}

rule _uintmaxtostr_26bea1ab229cdbaa2a8e7f12544915da {
	meta:
		aliases = "_uintmaxtostr"
		size = "187"
		objfiles = "_uintmaxtostr@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 85 D2 41 89 D1 55 53 89 CB 79 12 41 F7 D9 48 85 F6 79 0A 48 F7 DE BD 01 00 00 00 EB 02 31 ED 83 C8 FF 31 D2 C6 07 00 41 F7 F1 44 8D 52 01 41 89 C3 45 39 CA 75 06 41 FF C3 45 31 D2 41 89 F0 48 C1 EE 20 85 F6 74 3B 89 F0 31 D2 41 F7 F1 41 89 D4 89 C6 31 D2 44 89 C0 41 F7 F1 41 89 C0 44 89 D0 89 D1 41 0F AF C4 44 89 E2 41 0F AF D3 8D 04 01 41 8D 0C 10 31 D2 41 F7 F1 44 8D 04 01 89 D1 EB 0D 44 89 C0 31 D2 41 F7 F1 89 D1 41 89 C0 8D 41 30 8D 14 19 48 FF CF 83 F9 09 0F 47 C2 88 07 44 89 C0 09 F0 75 9C 85 ED 74 06 48 FF CF C6 07 2D 5B 5D 41 5C 48 89 F8 C3 }
	condition:
		$pattern
}

rule _obstack_begin_c45a57268b9c03000760c2359595497d {
	meta:
		aliases = "_obstack_begin"
		size = "149"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 85 D2 B8 10 00 00 00 55 89 D5 0F 44 E8 85 F6 66 B8 E0 0F 53 0F 44 F0 80 67 50 FE F6 47 50 01 44 8D 65 FF 48 63 F6 48 89 FB 48 89 4F 38 4C 89 47 40 48 89 37 44 89 67 30 74 08 48 8B 7F 48 FF D1 EB 05 48 8B 3F FF D1 48 85 C0 48 89 C1 48 89 43 08 75 05 E8 3C 02 00 00 49 63 C4 F7 DD 48 8D 44 01 10 48 63 D5 48 21 D0 48 89 43 10 48 89 43 18 48 89 C8 48 03 03 48 89 01 48 89 43 20 B8 01 00 00 00 48 C7 41 08 00 00 00 00 80 63 50 F9 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule _obstack_begin_1_16e93612186b0086c4642d9c24783d89 {
	meta:
		aliases = "_obstack_begin_1"
		size = "152"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 85 D2 B8 10 00 00 00 55 89 D5 0F 44 E8 85 F6 66 B8 E0 0F 53 48 89 FB 0F 44 F0 80 4B 50 01 44 8D 65 FF 48 63 F6 F6 43 50 01 4C 89 CF 48 89 4B 38 4C 89 43 40 48 89 33 44 89 63 30 4C 89 4B 48 74 04 FF D1 EB 05 48 8B 3B FF D1 48 85 C0 48 89 C1 48 89 43 08 75 05 E8 A4 01 00 00 49 63 C4 F7 DD 48 8D 44 01 10 48 63 D5 48 21 D0 48 89 43 10 48 89 43 18 48 89 C8 48 03 03 48 89 01 48 89 43 20 B8 01 00 00 00 48 C7 41 08 00 00 00 00 80 63 50 F9 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __GI_stat64_bbdbc81d4a102245f5e99ec634ac9a5e {
	meta:
		aliases = "__GI_stat, stat64, stat, __GI_stat64"
		size = "79"
		objfiles = "stat@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 B8 04 00 00 00 55 48 89 F5 53 48 81 EC 90 00 00 00 48 89 E6 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 85 DB 75 0B 48 89 EE 48 89 E7 E8 ?? ?? ?? ?? 48 81 C4 90 00 00 00 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __GI_lstat_826d9ac11ad0acf1713647c7ac3276bd {
	meta:
		aliases = "__GI_lstat64, lstat, lstat64, __GI_lstat"
		size = "79"
		objfiles = "lstat@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 B8 06 00 00 00 55 48 89 F5 53 48 81 EC 90 00 00 00 48 89 E6 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 85 DB 75 0B 48 89 EE 48 89 E7 E8 ?? ?? ?? ?? 48 81 C4 90 00 00 00 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __GI_wctype_e15094d8178f22e9c115513efe4486e7 {
	meta:
		aliases = "wctype, wctrans, __GI_wctrans, __GI_wctype"
		size = "64"
		objfiles = "wctype@libc.a, wctrans@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 B8 ?? ?? ?? ?? 49 89 FC 55 BD 01 00 00 00 53 48 8D 58 01 4C 89 E7 48 89 DE E8 ?? ?? ?? ?? 85 C0 75 04 89 E8 EB 13 0F B6 43 FF 48 8D 04 03 80 38 00 74 04 FF C5 EB D8 31 C0 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule timegm_3240a1c925d1436d2ef07c0e6a02cc97 {
	meta:
		aliases = "timegm"
		size = "64"
		objfiles = "timegm@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 BA 40 00 00 00 49 89 FC 31 F6 53 48 83 EC 48 48 89 E7 E8 ?? ?? ?? ?? 48 8D 7C 24 18 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 89 E7 48 89 E2 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 48 5B 41 5C C3 }
	condition:
		$pattern
}

rule __xstat64_conv_9432164620a3e77f26981d630ed781b3 {
	meta:
		aliases = "__xstat64_conv"
		size = "172"
		objfiles = "xstatconv@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 BA 90 00 00 00 49 89 FC 53 48 89 F3 31 F6 48 89 DF 48 83 EC 08 E8 ?? ?? ?? ?? 49 8B 04 24 48 89 03 49 8B 44 24 08 48 89 43 08 41 8B 44 24 18 89 43 18 49 8B 44 24 10 48 89 43 10 41 8B 44 24 1C 89 43 1C 41 8B 44 24 20 89 43 20 49 8B 44 24 28 48 89 43 28 49 8B 44 24 30 48 89 43 30 49 8B 44 24 38 48 89 43 38 49 8B 44 24 40 48 89 43 40 49 8B 44 24 48 48 89 43 48 49 8B 44 24 58 48 89 43 58 49 8B 44 24 68 48 89 43 68 49 8B 44 24 50 48 89 43 50 49 8B 44 24 60 48 89 43 60 49 8B 44 24 70 48 89 43 70 58 5B 41 5C C3 }
	condition:
		$pattern
}

rule __xstat_conv_91c632858e2441ba8fbf0a13eccd2a23 {
	meta:
		aliases = "__xstat_conv"
		size = "172"
		objfiles = "xstatconv@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 BA 90 00 00 00 49 89 FC 53 48 89 F3 31 F6 48 89 DF 48 83 EC 08 E8 ?? ?? ?? ?? 49 8B 04 24 48 89 03 49 8B 44 24 08 48 89 43 08 41 8B 44 24 18 89 43 18 49 8B 44 24 10 48 89 43 10 41 8B 44 24 1C 89 43 1C 41 8B 44 24 20 89 43 20 49 8B 44 24 28 48 89 43 28 49 8B 44 24 30 48 89 43 30 49 8B 44 24 38 48 89 43 38 49 8B 44 24 40 48 89 43 40 49 8B 44 24 48 48 89 43 48 49 8B 44 24 58 48 89 43 58 49 8B 44 24 68 48 89 43 68 49 8B 44 24 50 48 89 43 50 49 8B 44 24 60 48 89 43 60 49 8B 44 24 70 48 89 43 70 5A 5B 41 5C C3 }
	condition:
		$pattern
}

rule srand_760055d0b3360962c922cb2ccffe3fc8 {
	meta:
		aliases = "srandom, srand"
		size = "72"
		objfiles = "random@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 BA ?? ?? ?? ?? 41 89 FC BE ?? ?? ?? ?? 53 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 44 89 E7 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 5B 41 5C C3 }
	condition:
		$pattern
}

rule svcudp_enablecache_00d08609881b3029feefcfa134a039b2 {
	meta:
		aliases = "svcudp_enablecache"
		size = "201"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 BA ?? ?? ?? ?? 55 48 89 F5 53 4C 8B 67 48 49 83 BC 24 D0 01 00 00 00 75 17 BF 48 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 75 1C BA ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? BE ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? 31 C0 EB 7B 48 89 EF 48 89 28 48 C7 40 18 00 00 00 00 48 C1 E7 05 89 FF E8 ?? ?? ?? ?? 48 85 C0 48 89 C7 48 89 43 08 BA ?? ?? ?? ?? 74 BF 48 8D 14 AD 00 00 00 00 31 F6 48 63 D2 48 C1 E2 03 E8 ?? ?? ?? ?? 48 8D 3C ED 00 00 00 00 89 FF E8 ?? ?? ?? ?? 48 85 C0 48 89 C7 48 89 43 10 BA ?? ?? ?? ?? 74 89 48 63 D5 31 F6 48 C1 E2 03 E8 ?? ?? ?? ?? 49 89 9C 24 D0 01 00 00 B8 01 00 00 00 5B 5D 41 5C }
	condition:
		$pattern
}

rule getutent_df31cc6bf68b196c8de098c1c9b71c6f {
	meta:
		aliases = "getutent"
		size = "73"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 53 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? E8 4E FE FF FF BE 01 00 00 00 48 89 C3 48 89 E7 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 28 5B 41 5C C3 }
	condition:
		$pattern
}

rule __GI_getutid_0dccabcc0b6bab0806ff799f70aa9233 {
	meta:
		aliases = "getutid, __GI_getutid"
		size = "73"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 53 48 89 FB 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 DF E8 CA FE FF FF BE 01 00 00 00 48 89 C3 48 89 E7 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 28 5B 41 5C C3 }
	condition:
		$pattern
}

rule sethostent_1b82fb4773dd243d9c0dc8989ae00637 {
	meta:
		aliases = "sethostent"
		size = "71"
		objfiles = "gethostent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 53 89 FB 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 85 DB BE 01 00 00 00 0F 95 C0 48 89 E7 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 C4 28 5B 41 5C C3 }
	condition:
		$pattern
}

rule pclose_0ad032cc6e2d5b6881a7922fbd52a7d0 {
	meta:
		aliases = "pclose"
		size = "190"
		objfiles = "popen@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 55 48 89 FD 53 48 83 EC 30 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? 48 85 DB 74 3C 48 39 6B 08 75 1F 48 8B 03 48 89 05 ?? ?? ?? ?? EB 2A E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 1D 8B 44 24 2C EB 5D 48 89 DA 48 8B 1B 48 85 DB 74 E2 48 39 6B 08 75 EF 48 8B 03 48 89 02 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 85 DB 74 31 48 89 DF 44 8B 63 10 E8 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 48 8D 74 24 2C 31 D2 44 89 E7 E8 ?? ?? ?? ?? 85 C0 79 AA E8 ?? ?? ?? ?? 83 38 04 74 E3 83 C8 FF 48 83 C4 30 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule xdr_pointer_02e843fa1f18f52780446d28259a7b04 {
	meta:
		aliases = "xdr_pointer"
		size = "101"
		objfiles = "xdr_reference@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 31 C0 41 89 D5 41 54 49 89 CC 55 48 89 FD 53 48 89 F3 48 83 EC 18 48 83 3E 00 48 8D 74 24 14 0F 95 C0 89 44 24 14 E8 ?? ?? ?? ?? 31 D2 85 C0 74 25 83 7C 24 14 00 75 0B B2 01 48 C7 03 00 00 00 00 EB 13 44 89 EA 4C 89 E1 48 89 DE 48 89 EF E8 ?? ?? ?? ?? 89 C2 48 83 C4 18 89 D0 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule __malloc_trim_3f4fbb7621d4302da7a885f221f45596 {
	meta:
		aliases = "__malloc_trim"
		size = "153"
		objfiles = "free@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 31 D2 49 89 F5 41 54 55 53 48 83 EC 08 48 8B 46 60 8B 8E A4 06 00 00 48 8B 68 08 48 83 E5 FC 48 89 E8 48 29 F8 48 8D 44 08 DF 48 F7 F1 48 8D 58 FF 48 0F AF D9 48 85 DB 7E 53 31 FF E8 ?? ?? ?? ?? 49 89 C4 48 89 E8 49 03 45 60 49 39 C4 75 3D 48 F7 DB 48 89 DF E8 ?? ?? ?? ?? 31 FF E8 ?? ?? ?? ?? 48 83 F8 FF 74 25 4C 89 E2 48 29 C2 74 1D 49 8B 45 60 49 29 95 B8 06 00 00 48 29 D5 48 83 CD 01 48 89 68 08 B8 01 00 00 00 EB 02 31 C0 5A 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule pthread_rwlock_destroy_54972c051c8d0eefa6421193f445cbdc {
	meta:
		aliases = "pthread_rwlock_destroy"
		size = "60"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 31 F6 41 54 53 48 89 FB E8 ?? ?? ?? ?? 44 8B 63 10 4C 8B 6B 18 48 89 DF E8 ?? ?? ?? ?? 5B 45 85 E4 0F 9F C0 4D 85 ED 0F 95 C2 09 D0 41 5C 3C 01 41 5D 19 C0 F7 D0 83 E0 10 C3 }
	condition:
		$pattern
}

rule fseeko64_f29b4aff1d2a2a213c8992869bac2164 {
	meta:
		aliases = "__GI_fseeko64, fseeko64"
		size = "218"
		objfiles = "fseeko64@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 41 89 D4 55 48 89 FD 53 48 83 EC 38 83 FA 02 48 89 74 24 28 76 13 83 CB FF E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 A0 00 00 00 44 8B 6F 50 45 85 ED 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? F6 45 00 40 74 0D 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 75 53 41 83 FC 01 75 11 48 8D 74 24 28 48 89 EF E8 ?? ?? ?? ?? 85 C0 78 3C 48 8D 74 24 28 44 89 E2 48 89 EF E8 ?? ?? ?? ?? 85 C0 78 28 66 83 65 00 B8 48 8B 45 08 31 DB C7 45 48 00 00 00 00 C6 45 02 00 48 89 45 18 48 89 45 20 48 89 45 28 48 89 45 30 EB 03 83 CB FF 45 85 ED 75 0D 48 89 E7 BE 01 00 00 00 }
	condition:
		$pattern
}

rule fwide_fb50f822e12f3bf603da69d2dd2c294d {
	meta:
		aliases = "fwide"
		size = "139"
		objfiles = "fwide@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 41 89 F4 55 48 89 FD 53 48 83 EC 28 44 8B 6F 50 45 85 ED 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 45 85 E4 74 21 8B 4D 00 F7 C1 80 08 00 00 75 16 45 85 E4 B8 00 08 00 00 BA 80 00 00 00 0F 4E C2 09 C1 66 89 4D 00 45 85 ED 0F B7 5D 00 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 89 D8 81 E3 80 00 00 00 48 83 C4 28 25 00 08 00 00 29 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule __GI_sigaction_0ffa411cd4ec61b531cfc9b7465f4ebc {
	meta:
		aliases = "sigaction, __libc_sigaction, __GI_sigaction"
		size = "247"
		objfiles = "sigaction@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 41 89 FC 55 48 89 D5 53 48 89 F3 48 81 EC 48 01 00 00 48 85 F6 74 42 48 8B 06 48 8D BC 24 B8 00 00 00 48 8D 76 08 BA 80 00 00 00 48 89 84 24 A0 00 00 00 E8 ?? ?? ?? ?? 8B 83 88 00 00 00 48 C7 84 24 B0 00 00 00 ?? ?? ?? ?? 0D 00 00 00 04 48 98 48 89 84 24 A8 00 00 00 31 F6 48 8D 84 24 A0 00 00 00 48 85 ED 48 89 F2 49 89 E5 41 BA 08 00 00 00 48 0F 45 D4 48 85 DB 49 63 FC 48 0F 45 F0 B8 0D 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 48 85 ED F7 D0 0F 95 C2 C1 E8 1F 84 D0 74 31 48 8B 04 24 49 8D 75 18 48 8D 7D 08 BA 80 00 00 00 48 }
	condition:
		$pattern
}

rule ungetwc_201bf0c809eccebb47d9f7f30222f920 {
	meta:
		aliases = "__GI_ungetwc, ungetwc"
		size = "176"
		objfiles = "ungetwc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 41 89 FC 55 48 89 F5 53 48 83 EC 28 44 8B 6E 50 45 85 ED 75 1C 48 8D 5E 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 0F B7 45 00 25 03 08 00 00 3D 00 08 00 00 77 11 BE 00 08 00 00 48 89 EF E8 ?? ?? ?? ?? 85 C0 75 36 0F B7 45 00 A8 02 74 0A A8 01 75 2A 83 7D 44 00 75 24 41 83 FC FF 74 1E 66 FF 45 00 C7 45 44 01 00 00 00 0F B7 45 00 66 83 65 00 FB 83 E0 01 44 89 64 85 40 EB 04 41 83 CC FF 45 85 ED 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 44 89 E0 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule ungetc_e49d61bc869cee2c724ff1d23ba9b2a8 {
	meta:
		aliases = "__GI_ungetc, ungetc"
		size = "228"
		objfiles = "ungetc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 41 89 FC 55 48 89 F5 53 48 83 EC 28 44 8B 6E 50 45 85 ED 75 1C 48 8D 5E 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8B 4D 18 48 3B 4D 28 0F 92 C2 41 83 FC FF 0F 95 C0 84 D0 74 16 48 3B 4D 08 76 10 44 38 61 FF 75 0A 48 8D 41 FF 48 89 45 18 EB 58 0F B7 45 00 25 83 00 00 00 3D 80 00 00 00 77 11 BE 80 00 00 00 48 89 EF E8 ?? ?? ?? ?? 85 C0 75 3E 0F B7 45 00 A8 02 74 0A A8 01 75 32 83 7D 44 00 75 2C 41 83 FC FF 74 26 48 8B 45 08 66 FF 45 00 C7 45 44 01 00 00 00 48 89 45 28 0F B7 45 00 83 E0 01 44 89 64 85 40 66 83 65 00 FB EB 04 41 83 CC FF 45 85 ED 75 }
	condition:
		$pattern
}

rule __GI_xdr_pmaplist_c007d1b36b6c47788673e6d0341ac6b9 {
	meta:
		aliases = "xdr_pmaplist, __GI_xdr_pmaplist"
		size = "142"
		objfiles = "pmap_prot2@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 45 31 E4 55 48 89 FD 53 48 89 F3 48 83 EC 18 83 3F 02 41 0F 94 C4 45 31 ED EB 03 4C 89 EB 31 C0 48 83 3B 00 48 8D 74 24 14 48 89 EF 0F 95 C0 89 44 24 14 E8 ?? ?? ?? ?? 85 C0 74 41 83 7C 24 14 00 75 07 B8 01 00 00 00 EB 35 45 85 E4 74 07 4C 8B 2B 49 83 C5 20 B9 ?? ?? ?? ?? BA 28 00 00 00 48 89 DE 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 0E 45 85 E4 75 A7 48 8B 1B 48 83 C3 20 EB A1 31 C0 48 83 C4 18 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule __GI___ns_name_uncompress_2c1a10040e5866f4b2cdc4d3ee489a8f {
	meta:
		aliases = "__ns_name_uncompress, __GI___ns_name_uncompress"
		size = "77"
		objfiles = "ns_name@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 CC 55 4C 89 C5 41 B8 FF 00 00 00 53 48 81 EC 08 01 00 00 48 89 E1 E8 ?? ?? ?? ?? 83 F8 FF 89 C3 74 12 48 89 EA 4C 89 E6 48 89 E7 E8 ?? ?? ?? ?? FF C0 75 03 83 CB FF 48 81 C4 08 01 00 00 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule fgetpos_2f9eb78aaa151e8f1c76ca032b849bcf {
	meta:
		aliases = "fgetpos64, fgetpos"
		size = "131"
		objfiles = "fgetpos64@libc.a, fgetpos@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 F4 55 48 89 FD 53 48 83 EC 28 44 8B 6F 50 45 85 ED 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 EF 83 CB FF E8 ?? ?? ?? ?? 48 85 C0 49 89 04 24 78 1B 8B 45 48 31 DB 41 89 44 24 08 8B 45 4C 41 89 44 24 0C 0F B6 45 02 41 89 44 24 10 45 85 ED 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule fsetpos_66d716988b848d65c754263c654c95f8 {
	meta:
		aliases = "fsetpos64, fsetpos"
		size = "128"
		objfiles = "fsetpos@libc.a, fsetpos64@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 F4 55 48 89 FD 53 48 83 EC 28 44 8B 6F 50 45 85 ED 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 49 8B 34 24 31 D2 48 89 EF E8 ?? ?? ?? ?? 85 C0 89 C3 75 18 41 8B 44 24 08 89 45 48 41 8B 44 24 0C 89 45 4C 41 8B 44 24 10 88 45 02 45 85 ED 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule putgrent_2ba816865cbc89975e0512b66e51e03a {
	meta:
		aliases = "putgrent"
		size = "216"
		objfiles = "putgrent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 F4 55 48 89 FD 53 48 83 EC 28 48 85 FF 0F 94 C2 48 85 F6 0F 94 C0 08 C2 74 13 83 CB FF E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 98 00 00 00 44 8B 6E 50 45 85 ED 75 1C 48 8D 5E 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 44 8B 45 10 48 8B 4D 08 31 C0 48 8B 55 00 BE ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 78 3F 48 8B 5D 18 BE ?? ?? ?? ?? 48 8B 13 48 85 D2 75 15 4C 89 E6 BF 0A 00 00 00 31 DB E8 ?? ?? ?? ?? 85 C0 79 1E EB 19 31 C0 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 78 0B 48 83 C3 08 BE ?? ?? ?? ?? EB CA 83 CB FF 45 85 ED 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? }
	condition:
		$pattern
}

rule __pthread_lock_0d66a3782b7c5971588aee2faa84d515 {
	meta:
		aliases = "__pthread_lock"
		size = "170"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 F4 55 53 48 89 FB 48 83 EC 18 48 83 3F 00 75 16 31 D2 B9 01 00 00 00 48 89 D0 F0 48 0F B1 0F 0F 94 C2 84 D2 75 73 45 31 ED 48 8B 2B 40 F6 C5 01 75 0E 48 89 E9 BA 01 00 00 00 48 83 C9 01 EB 16 4D 85 E4 75 08 E8 07 FF FF FF 49 89 C4 4C 89 E1 31 D2 48 83 C9 01 4D 85 E4 74 05 49 89 6C 24 18 48 89 E8 F0 48 0F B1 0B 0F 94 C1 84 C9 74 BA 85 D2 75 1D 4C 89 E7 E8 1B FF FF FF 49 83 7C 24 18 00 74 A6 41 FF C5 EB EB 4C 89 E7 E8 DF FD FF FF 41 FF CD 41 83 FD FF 75 EF 48 83 C4 18 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule __GI_fputs_unlocked_24f1219a2acde5641c27a3c7f3e02faf {
	meta:
		aliases = "fputs_unlocked, __GI_fputs_unlocked"
		size = "56"
		objfiles = "fputs_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 53 48 89 F3 E8 ?? ?? ?? ?? 48 89 D9 48 89 C2 4C 89 E7 BE 01 00 00 00 49 89 C5 E8 ?? ?? ?? ?? 5B 48 89 C2 83 C8 FF 41 5C 4C 39 EA 41 5D 0F 44 C2 C3 }
	condition:
		$pattern
}

rule _Unwind_Backtrace_73c042674c84e7b782efdfef542aabf5 {
	meta:
		aliases = "_Unwind_Backtrace"
		size = "89"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 55 48 89 F5 53 48 83 EC 18 48 8B 05 ?? ?? ?? ?? 48 89 04 24 EB 13 66 66 90 83 FB 05 74 27 48 8B 04 24 48 8B 00 48 89 04 24 48 83 3C 24 01 48 89 EE 48 89 E7 19 DB 83 E3 05 41 FF D4 85 C0 74 D9 BB 03 00 00 00 48 83 C4 18 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule putspent_a2d454dad9e6bea9e382f12986c3a63a {
	meta:
		aliases = "putspent"
		size = "232"
		objfiles = "putspent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 55 48 89 F5 53 48 83 EC 28 44 8B 6E 50 45 85 ED 75 1C 48 8D 5E 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 49 8B 4C 24 08 49 8B 14 24 B8 ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 EF 48 85 C9 48 0F 44 C8 31 C0 31 DB E8 ?? ?? ?? ?? 85 C0 79 30 EB 65 0F B6 83 ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 EF 49 8B 14 04 B8 ?? ?? ?? ?? 48 83 FA FF 48 0F 45 F0 31 C0 E8 ?? ?? ?? ?? 85 C0 78 3A 48 FF C3 48 83 FB 05 76 CC 49 8B 54 24 40 48 83 FA FF 74 13 31 C0 BE ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 85 C0 78 13 48 89 EE BF 0A 00 00 00 31 DB E8 ?? ?? ?? ?? 85 C0 7F 03 83 CB }
	condition:
		$pattern
}

rule __get_next_rpcent_640a5af9c7cfefb8efc56088ea7acb86 {
	meta:
		aliases = "__get_next_rpcent"
		size = "313"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 55 53 48 83 EC 08 49 8D AC 24 48 01 00 00 49 8B 14 24 BE 00 10 00 00 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 0F 84 A5 00 00 00 48 89 EF E8 ?? ?? ?? ?? 42 C6 84 20 47 01 00 00 0A 41 80 BC 24 48 01 00 00 23 74 C2 BE 23 00 00 00 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 75 12 BE 0A 00 00 00 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 74 9E C6 00 00 48 89 EF E8 46 FF FF FF 48 85 C0 74 8E 48 8D 58 01 C6 00 00 49 89 AC 24 30 01 00 00 EB 03 48 FF C3 8A 03 3C 20 0F 94 C2 3C 09 0F 94 C0 08 C2 75 ED 4D 8D 6C 24 18 48 89 DF E8 ?? ?? ?? ?? 48 89 DF 41 89 84 24 40 01 00 00 4D 89 AC 24 38 01 00 00 E8 F8 FE FF FF }
	condition:
		$pattern
}

rule __GI_unsetenv_8529209b038c9705d846967a2b5f56d3 {
	meta:
		aliases = "unsetenv, __GI_unsetenv"
		size = "190"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 55 53 48 83 EC 28 48 85 FF 74 14 80 3F 00 74 0F BE 3D 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 74 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 7D 4C 89 E7 E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 E7 BE ?? ?? ?? ?? 49 89 C5 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 2D ?? ?? ?? ?? EB 35 4C 89 EA 4C 89 E6 48 89 DF E8 ?? ?? ?? ?? 85 C0 75 1F 42 80 3C 2B 3D 75 18 48 89 EA 48 8B 42 08 48 8D 4A 08 48 85 C0 48 89 02 74 09 48 89 CA EB EB 48 83 C5 08 48 8B 5D 00 48 85 DB 75 C2 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 31 C0 48 83 C4 28 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule puts_a8e0e91a3dc6c0775e943b42a02a9436 {
	meta:
		aliases = "puts"
		size = "130"
		objfiles = "puts@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 55 53 48 83 EC 28 48 8B 2D ?? ?? ?? ?? 44 8B 6D 50 45 85 ED 75 1C 48 8D 5D 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 EE 4C 89 E7 E8 ?? ?? ?? ?? 83 F8 FF 89 C3 74 18 48 89 EE BF 0A 00 00 00 E8 ?? ?? ?? ?? 8D 53 01 83 F8 FF 89 C3 0F 45 DA 45 85 ED 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule authunix_validate_e01e30b01c3cc7c7e6b2b5c020284caf {
	meta:
		aliases = "authunix_validate"
		size = "159"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 55 53 48 83 EC 38 83 3E 02 75 7D 48 8B 6F 40 8B 56 10 48 89 E7 48 8B 76 08 B9 01 00 00 00 E8 ?? ?? ?? ?? 48 8B 7D 20 48 85 FF 74 0D E8 ?? ?? ?? ?? 48 C7 45 20 00 00 00 00 48 8D 5D 18 48 89 E7 48 89 DE E8 ?? ?? ?? ?? 85 C0 B9 06 00 00 00 4C 89 E7 FC 48 89 DE 75 26 48 89 DE 48 89 E7 C7 04 24 02 00 00 00 E8 ?? ?? ?? ?? FC 48 C7 45 20 00 00 00 00 B9 06 00 00 00 4C 89 E7 48 89 EE F3 A5 4C 89 E7 E8 04 FE FF FF 48 83 C4 38 B8 01 00 00 00 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule do_close_96f6224e67b3bfa99628f34e168951c2 {
	meta:
		aliases = "do_close"
		size = "35"
		objfiles = "rtime@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 53 89 FB E8 ?? ?? ?? ?? 44 8B 28 49 89 C4 89 DF E8 ?? ?? ?? ?? 45 89 2C 24 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule _dl_linux_resolver_62a59213ae6fe5e9ff84a40dabf87a7f {
	meta:
		aliases = "_dl_linux_resolver"
		size = "220"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 48 63 EE 53 48 89 FB 48 83 EC 08 48 03 AF 38 01 00 00 48 8B 97 B0 00 00 00 48 8B 4D 08 48 89 C8 48 C1 F8 20 48 6B C0 18 44 8B 24 10 4C 03 A7 A8 00 00 00 83 F9 07 74 34 48 8B 15 ?? ?? ?? ?? 31 C0 BE ?? ?? ?? ?? BF 02 00 00 00 E8 ?? ?? ?? ?? BF 01 00 00 00 B8 3C 00 00 00 0F 05 48 3D 00 F0 FF FF 76 08 F7 D8 89 05 ?? ?? ?? ?? 48 8B 73 38 48 89 DA B9 01 00 00 00 4C 89 E7 4C 8B 6D 00 48 8B 2B E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 75 37 48 8B 15 ?? ?? ?? ?? 31 C0 4C 89 E1 BE ?? ?? ?? ?? BF 02 00 00 00 E8 ?? ?? ?? ?? BF 01 00 00 00 B8 3C 00 00 00 0F 05 48 3D 00 F0 FF FF 76 08 F7 D8 89 05 ?? }
	condition:
		$pattern
}

rule universal_67e0bcb941aeacce11bdef7151c3ece7 {
	meta:
		aliases = "universal"
		size = "354"
		objfiles = "svc_simple@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 48 89 F5 53 48 81 EC 78 22 00 00 48 8B 47 10 48 C7 84 24 68 22 00 00 00 00 00 00 48 85 C0 75 30 31 D2 BE ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 85 C0 0F 85 18 01 00 00 BA 04 00 00 00 BE ?? ?? ?? ?? BF 02 00 00 00 E8 ?? ?? ?? ?? E9 93 00 00 00 44 8B 27 41 89 C5 E8 ?? ?? ?? ?? 48 8B 98 00 01 00 00 E9 9D 00 00 00 44 39 63 08 0F 85 8F 00 00 00 44 39 6B 0C 0F 85 85 00 00 00 31 F6 BA 60 22 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 8B 45 08 48 8B 73 10 48 89 E2 48 89 EF FF 50 10 85 C0 0F 84 A4 00 00 00 48 89 E7 FF 13 48 85 C0 75 0E 48 81 7B 18 ?? ?? ?? ?? 0F 85 94 00 00 00 48 8B 73 18 48 89 C2 48 }
	condition:
		$pattern
}

rule __GI_clnt_sperror_09ca0ce47c89611b181406b4ba9f5a06 {
	meta:
		aliases = "clnt_sperror, __GI_clnt_sperror"
		size = "401"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 48 89 F5 53 48 89 FB 48 81 EC 28 04 00 00 E8 9E FE FF FF 49 89 C5 31 C0 4D 85 ED 0F 84 5D 01 00 00 48 8B 43 08 48 89 DF 48 8D B4 24 00 04 00 00 FF 50 10 48 89 EA BE ?? ?? ?? ?? 4C 89 EF 31 C0 E8 ?? ?? ?? ?? 8B BC 24 00 04 00 00 48 98 49 8D 5C 05 00 E8 ?? ?? ?? ?? 48 89 DF 48 89 C6 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 83 BC 24 00 04 00 00 11 48 8D 2C 03 0F 87 D2 00 00 00 8B 84 24 00 04 00 00 FF 24 C5 ?? ?? ?? ?? 8B BC 24 08 04 00 00 48 89 E6 BA 00 04 00 00 E8 ?? ?? ?? ?? 48 89 E2 BE ?? ?? ?? ?? 48 89 EF 31 C0 E8 ?? ?? ?? ?? E9 B8 00 00 00 8B 04 C5 ?? ?? ?? ?? 4C 8D A0 ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_fclose_e54d49b903ccf3012288f405459f36f0 {
	meta:
		aliases = "fclose, __GI_fclose"
		size = "259"
		objfiles = "fclose@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 48 89 FD 53 48 83 EC 48 44 8B 6F 50 45 85 ED 75 1E 48 8D 5F 58 48 8D 7C 24 20 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 45 31 E4 F6 45 00 40 74 0B 48 89 EF E8 ?? ?? ?? ?? 41 89 C4 8B 7D 04 E8 ?? ?? ?? ?? 83 CA FF 85 C0 BE ?? ?? ?? ?? 44 0F 48 E2 89 55 04 48 89 E7 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 FF C0 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 81 65 00 00 60 66 83 4D 00 30 45 85 ED 75 0F 48 8D 7C 24 20 BE 01 00 00 00 E8 ?? ?? ?? ?? F6 45 01 40 74 09 48 8B 7D 08 E8 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? }
	condition:
		$pattern
}

rule memalign_0f00e9361dcdaef7f9b52b3afc820a97 {
	meta:
		aliases = "memalign"
		size = "413"
		objfiles = "memalign@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 48 89 FD 53 48 89 F3 48 83 EC 28 48 83 FF 10 77 10 48 89 F7 E8 ?? ?? ?? ?? 48 89 C3 E9 69 01 00 00 48 83 FF 1F B8 20 00 00 00 BF 20 00 00 00 48 0F 46 E8 48 8D 45 FF 48 85 E8 75 05 EB 0B 48 01 FF 48 39 EF 72 F8 48 89 FD 48 89 E7 BA ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 FB BF 76 12 31 DB E8 ?? ?? ?? ?? C7 00 0C 00 00 00 E9 0D 01 00 00 48 8D 43 17 41 BD 20 00 00 00 48 89 C2 48 83 E2 F0 48 83 F8 1F 4C 0F 47 EA 31 DB 49 8D 7C 2D 20 E8 ?? ?? ?? ?? 48 85 C0 48 89 C1 0F 84 CF 00 00 00 31 D2 4C 8D 60 F0 48 F7 F5 48 85 D2 74 7B 48 8D 44 29 FF 48 89 }
	condition:
		$pattern
}

rule initshells_9a762d18ddb1f711d22bb8cb9767360c {
	meta:
		aliases = "initshells"
		size = "353"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 53 48 81 EC 98 00 00 00 E8 BA FF FF FF BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 49 89 C4 B8 ?? ?? ?? ?? 4D 85 E4 0F 84 21 01 00 00 4C 89 E7 E8 ?? ?? ?? ?? 48 89 E6 89 C7 E8 ?? ?? ?? ?? FF C0 0F 84 F5 00 00 00 8B 7C 24 30 FF C7 E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 0F 84 DA 00 00 00 8B 44 24 30 BA 03 00 00 00 BE 08 00 00 00 89 D1 31 D2 F7 F1 89 C7 E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 0F 84 AF 00 00 00 BE 02 00 00 00 4C 89 E7 E8 ?? ?? ?? ?? 48 8B 2D ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? 44 8B 6C 24 30 EB 57 48 FF C3 8A 0B 80 F9 23 0F 95 C2 80 F9 2F 0F 95 C0 84 D0 74 }
	condition:
		$pattern
}

rule clnt_spcreateerror_5283ca5d700f539c64dbe267f257687d {
	meta:
		aliases = "__GI_clnt_spcreateerror, clnt_spcreateerror"
		size = "260"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 53 48 89 FB 48 81 EC 08 04 00 00 E8 BE FF FF FF 48 85 C0 49 89 C5 0F 84 D2 00 00 00 E8 ?? ?? ?? ?? 48 89 DA 49 89 C4 BE ?? ?? ?? ?? 4C 89 EF 31 C0 E8 ?? ?? ?? ?? 41 8B 3C 24 48 98 49 8D 5C 05 00 E8 ?? ?? ?? ?? 48 89 DF 48 89 C6 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 01 C3 41 8B 04 24 83 F8 0C 74 3F 83 F8 0E 75 7D BE ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 41 8B 7C 24 08 48 01 C3 E8 ?? ?? ?? ?? 48 89 DF 48 89 C6 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 01 C3 EB 43 BE ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 41 8B 7C 24 10 48 8D 2C 03 BA }
	condition:
		$pattern
}

rule _stdio_fopen_448358f63ad993e066d3d798fecde809 {
	meta:
		aliases = "_stdio_fopen"
		size = "551"
		objfiles = "_fopen@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 CD 41 54 49 89 FC 55 48 89 D5 53 48 83 EC 48 8A 06 3C 72 74 3C 3C 77 BB 41 02 00 00 74 35 3C 61 66 BB 41 04 74 2D E8 ?? ?? ?? ?? 48 85 ED C7 00 16 00 00 00 0F 84 D9 01 00 00 F6 45 01 20 0F 84 CF 01 00 00 48 89 EF E8 ?? ?? ?? ?? E9 C2 01 00 00 31 DB 80 7E 01 62 48 8D 46 01 48 0F 45 C6 80 78 01 2B 75 08 89 D8 83 C8 01 8D 58 01 48 85 ED 75 2C BF 80 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 0F 84 8D 01 00 00 48 8D 78 58 66 C7 00 00 20 48 C7 40 08 00 00 00 00 E8 ?? ?? ?? ?? 45 85 ED 78 46 89 DA 41 8D 44 24 01 44 89 6D 04 83 E2 03 FF C2 21 D0 39 D0 0F 85 69 FF FF FF 44 89 E0 F7 D0 25 00 }
	condition:
		$pattern
}

rule getmntent_r_1bc18f573939a778b74e9af73e0231a4 {
	meta:
		aliases = "__GI_getmntent_r, getmntent_r"
		size = "302"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 CD 41 54 49 89 FC 55 48 89 D5 53 48 89 F3 48 83 EC 18 48 85 FF 0F 94 C2 48 85 F6 0F 94 C0 08 C2 0F 85 F4 00 00 00 48 85 ED 0F 84 EB 00 00 00 EB 11 8A 45 00 3C 23 0F 94 C2 3C 0A 0F 94 C0 08 C2 74 18 4C 89 E2 44 89 EE 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 75 DC E9 C0 00 00 00 4C 8D 64 24 10 BE ?? ?? ?? ?? 48 89 EF 48 C7 44 24 10 00 00 00 00 4C 89 E2 E8 ?? ?? ?? ?? 48 85 C0 48 89 03 0F 84 96 00 00 00 31 FF 4C 89 E2 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 43 08 74 7E 31 FF 4C 89 E2 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 43 10 74 66 31 FF 4C 89 E2 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 }
	condition:
		$pattern
}

rule __GI_xdr_string_4f90182a82c6ab4cc172b920e93e23e2 {
	meta:
		aliases = "xdr_string, __GI_xdr_string"
		size = "215"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 D5 41 54 49 89 F4 55 48 89 FD 53 48 83 EC 18 8B 07 48 8B 1E 85 C0 74 0F 83 F8 02 75 1F 48 85 DB 75 0E E9 98 00 00 00 48 85 DB 0F 84 96 00 00 00 48 89 DF E8 ?? ?? ?? ?? 89 44 24 14 48 8D 74 24 14 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 79 8B 44 24 14 44 39 E8 77 70 8B 55 00 83 FA 01 74 09 72 3E 83 FA 02 75 61 EB 48 FF C0 74 54 48 85 DB 75 26 89 C7 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 49 89 04 24 75 13 48 8B 35 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 30 8B 44 24 14 C6 04 03 00 8B 54 24 14 48 89 DE 48 89 EF E8 ?? ?? ?? ?? EB 19 48 89 DF E8 ?? ?? ?? ?? 49 C7 04 24 00 00 00 00 B8 01 00 00 00 }
	condition:
		$pattern
}

rule iruserfopen_c01393b4f506d398becb8aeb2c9bd308 {
	meta:
		aliases = "iruserfopen"
		size = "152"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 F5 41 54 55 48 89 FD 53 31 DB 48 81 EC 98 00 00 00 48 89 E6 E8 ?? ?? ?? ?? 85 C0 75 66 8B 44 24 18 25 00 F0 00 00 3D 00 80 00 00 75 56 BE ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 41 48 89 C7 E8 ?? ?? ?? ?? 89 C7 48 89 E6 E8 ?? ?? ?? ?? 85 C0 78 1C 8B 44 24 1C 85 C0 74 05 44 39 E8 75 0F F6 44 24 18 12 75 08 48 83 7C 24 10 01 76 0F 48 85 DB 74 0A 48 89 DF 31 DB E8 ?? ?? ?? ?? 48 81 C4 98 00 00 00 48 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule fputwc_302df8488cc5c5ce4a59d3669a36430d {
	meta:
		aliases = "putwc, fputwc"
		size = "97"
		objfiles = "fputwc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 FD 41 54 55 48 89 F5 53 48 83 EC 28 44 8B 66 50 45 85 E4 75 1C 48 8D 5E 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 EE 44 89 EF E8 ?? ?? ?? ?? 45 85 E4 89 C3 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule bindresvport_013d4b29642b5e99a752c33acdd050b2 {
	meta:
		aliases = "__GI_bindresvport, bindresvport"
		size = "226"
		objfiles = "bindresvport@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 FD 41 54 55 53 48 89 F3 48 83 EC 18 48 85 F6 75 1A BA 10 00 00 00 31 F6 48 89 E7 E8 ?? ?? ?? ?? 48 89 E3 66 C7 04 24 02 00 EB 19 66 83 3E 02 74 13 E8 ?? ?? ?? ?? 83 C9 FF C7 00 60 00 00 00 E9 8D 00 00 00 66 83 3D ?? ?? ?? ?? 00 75 1B E8 ?? ?? ?? ?? BA A8 01 00 00 89 D1 99 F7 F9 66 81 C2 58 02 66 89 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 ED 49 89 C4 83 C9 FF C7 00 62 00 00 00 EB 3A 66 8B 05 ?? ?? ?? ?? 48 89 DE 44 89 EF 89 C2 FF C0 66 C1 CA 08 66 3D 00 04 66 89 53 02 BA 58 02 00 00 0F 4C D0 FF C5 66 89 15 ?? ?? ?? ?? BA 10 00 00 00 E8 ?? ?? ?? ?? 89 C1 81 FD A7 01 00 00 89 C8 0F 9E C2 C1 }
	condition:
		$pattern
}

rule lockf_2069361860def5c5f9a2a3288823ab2e {
	meta:
		aliases = "lockf64, __GI_lockf, __GI_lockf64, lockf"
		size = "223"
		objfiles = "lockf64@libc.a, lockf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 FD 41 54 55 89 F5 31 F6 53 48 89 D3 BA 20 00 00 00 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? 83 FD 01 66 C7 44 24 02 01 00 48 C7 44 24 08 00 00 00 00 48 89 5C 24 10 74 5A 7F 06 85 ED 74 4C EB 6C 83 FD 02 74 5A 83 FD 03 75 62 48 89 E2 31 C0 BE 05 00 00 00 44 89 EF 66 C7 04 24 00 00 E8 ?? ?? ?? ?? 83 CA FF 85 C0 78 66 66 83 3C 24 02 74 5D 8B 5C 24 18 E8 ?? ?? ?? ?? 39 C3 74 50 E8 ?? ?? ?? ?? C7 00 0D 00 00 00 EB 2D 66 C7 04 24 02 00 EB 13 BE 07 00 00 00 66 C7 04 24 01 00 EB 1D 66 C7 04 24 01 00 BE 06 00 00 00 EB 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CA FF EB 13 48 89 E2 44 89 EF 31 C0 E8 }
	condition:
		$pattern
}

rule _time_tzset_857d57613266532263f0dbbde52f6d07 {
	meta:
		aliases = "_time_tzset"
		size = "991"
		objfiles = "tzset@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 FD BA ?? ?? ?? ?? BE ?? ?? ?? ?? 41 54 55 53 48 81 EC C8 00 00 00 48 8D BC 24 90 00 00 00 48 C7 84 24 B8 00 00 00 00 00 00 00 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 75 5E 31 F6 31 C0 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 41 89 C4 78 44 BD 44 00 00 00 48 89 E3 48 89 EA 48 89 DE 44 89 E7 E8 ?? ?? ?? ?? 48 83 F8 00 7C 1E 74 08 48 01 C3 48 29 C5 75 E2 48 39 E3 76 0F 80 7B FF 0A 75 09 C6 43 FF 00 48 89 E3 EB 02 31 DB 44 89 E7 E8 ?? ?? ?? ?? 48 85 DB 74 06 8A 03 84 C0 75 2C 31 F6 BA 40 00 00 00 BF ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 00 E8 ?? }
	condition:
		$pattern
}

rule read_491c3cad1fea36f1a10c020855681855 {
	meta:
		aliases = "read"
		size = "73"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 FD BF 01 00 00 00 41 54 49 89 F4 53 48 89 D3 48 83 EC 10 48 8D 74 24 0C E8 ?? ?? ?? ?? 48 89 DA 4C 89 E6 44 89 EF E8 ?? ?? ?? ?? 8B 7C 24 0C 31 F6 48 89 C3 E8 ?? ?? ?? ?? 41 5B 48 89 D8 5B 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule accept_cd5c987f9922375a6603a4187b97190a {
	meta:
		aliases = "accept"
		size = "72"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 FD BF 01 00 00 00 41 54 49 89 F4 53 48 89 D3 48 83 EC 10 48 8D 74 24 0C E8 ?? ?? ?? ?? 48 89 DA 4C 89 E6 44 89 EF E8 ?? ?? ?? ?? 8B 7C 24 0C 31 F6 89 C3 E8 ?? ?? ?? ?? 41 5A 41 5B 89 D8 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule write_00df45f634a800ddde6c830304dc4685 {
	meta:
		aliases = "write"
		size = "73"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 FD BF 01 00 00 00 41 54 49 89 F4 53 48 89 D3 48 83 EC 10 48 8D 74 24 0C E8 ?? ?? ?? ?? 48 89 DA 4C 89 E6 44 89 EF E8 ?? ?? ?? ?? 8B 7C 24 0C 48 89 C3 31 F6 E8 ?? ?? ?? ?? 48 89 D8 5B 41 5C 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule lseek64_7645758ee9a0c8f9d702e77db797a17c {
	meta:
		aliases = "lseek64"
		size = "72"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 FD BF 01 00 00 00 41 54 49 89 F4 53 89 D3 48 83 EC 10 48 8D 74 24 0C E8 ?? ?? ?? ?? 89 DA 4C 89 E6 44 89 EF E8 ?? ?? ?? ?? 8B 7C 24 0C 31 F6 48 89 C3 E8 ?? ?? ?? ?? 41 58 41 59 48 89 D8 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule lseek_23e099d154cc276a014024ecf634d7a4 {
	meta:
		aliases = "lseek"
		size = "72"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 FD BF 01 00 00 00 41 54 49 89 F4 53 89 D3 48 83 EC 10 48 8D 74 24 0C E8 ?? ?? ?? ?? 89 DA 4C 89 E6 44 89 EF E8 ?? ?? ?? ?? 8B 7C 24 0C 31 F6 48 89 C3 E8 ?? ?? ?? ?? 41 5A 41 5B 48 89 D8 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule sendmsg_2dc8b5a81df417ffdd7839451fd90e68 {
	meta:
		aliases = "sendmsg"
		size = "70"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 FD BF 01 00 00 00 41 54 49 89 F4 53 89 D3 48 83 EC 10 48 8D 74 24 0C E8 ?? ?? ?? ?? 89 DA 4C 89 E6 44 89 EF E8 ?? ?? ?? ?? 8B 7C 24 0C 31 F6 48 89 C3 E8 ?? ?? ?? ?? 5A 59 48 89 D8 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule recvmsg_16c31f13ac3112e60b975fec63caf2bf {
	meta:
		aliases = "recvmsg"
		size = "70"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 FD BF 01 00 00 00 41 54 49 89 F4 53 89 D3 48 83 EC 10 48 8D 74 24 0C E8 ?? ?? ?? ?? 89 DA 4C 89 E6 44 89 EF E8 ?? ?? ?? ?? 8B 7C 24 0C 31 F6 48 89 C3 E8 ?? ?? ?? ?? 5E 5F 48 89 D8 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule connect_8f0918523004c7ba4d88307de3b91f94 {
	meta:
		aliases = "connect"
		size = "70"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 FD BF 01 00 00 00 41 54 49 89 F4 53 89 D3 48 83 EC 10 48 8D 74 24 0C E8 ?? ?? ?? ?? 89 DA 4C 89 E6 44 89 EF E8 ?? ?? ?? ?? 8B 7C 24 0C 31 F6 89 C3 E8 ?? ?? ?? ?? 41 58 41 59 89 D8 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule waitpid_bc9c560ee7d0bfd58e0be24789dc9c20 {
	meta:
		aliases = "__GI_waitpid, waitpid"
		size = "69"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 FD BF 01 00 00 00 41 54 49 89 F4 53 89 D3 48 83 EC 10 48 8D 74 24 0C E8 ?? ?? ?? ?? 89 DA 4C 89 E6 44 89 EF E8 ?? ?? ?? ?? 8B 7C 24 0C 31 F6 89 C3 E8 ?? ?? ?? ?? 41 5D 5A 89 D8 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule parse_printf_format_456603a8dd89eaef6cc81a665334c57d {
	meta:
		aliases = "parse_printf_format"
		size = "279"
		objfiles = "parse_printf_format@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 45 31 ED 41 54 49 89 FC 55 48 89 D5 53 48 89 F3 4C 89 E6 48 81 EC 08 01 00 00 48 89 E7 E8 ?? ?? ?? ?? 85 C0 0F 88 DA 00 00 00 8B 44 24 1C 85 C0 0F 8E C2 00 00 00 4C 63 E8 48 89 D9 49 39 DD 49 0F 46 CD 31 D2 EB 0E 8B 44 94 2C 48 FF C2 89 45 00 48 83 C5 04 48 39 CA 72 ED E9 A5 00 00 00 3C 25 0F 85 8E 00 00 00 49 FF C4 41 80 3C 24 25 0F 84 80 00 00 00 48 89 E7 4C 89 24 24 E8 ?? ?? ?? ?? 81 7C 24 0C 00 00 00 80 4C 8B 24 24 75 16 49 FF C5 48 85 DB 74 0E C7 45 00 00 00 00 00 48 FF CB 48 83 C5 04 81 7C 24 08 00 00 00 80 75 16 49 FF C5 48 85 DB 74 0E C7 45 00 00 00 00 00 48 FF CB 48 83 C5 04 8B }
	condition:
		$pattern
}

rule __pthread_destroy_specifics_f6f5c542fce003b58c1fafcb6ff1a31e {
	meta:
		aliases = "__pthread_destroy_specifics"
		size = "238"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 45 31 ED 41 54 55 53 48 83 EC 08 E8 19 FF FF FF 41 B8 01 00 00 00 48 89 C5 EB 73 48 63 C3 45 31 E4 48 83 BC C5 48 01 00 00 00 75 52 EB 56 89 D8 48 63 D3 C1 E0 05 44 01 E0 48 98 48 C1 E0 04 48 8B B0 ?? ?? ?? ?? 49 63 C4 48 8D 0C C5 00 00 00 00 48 03 8C D5 48 01 00 00 48 85 F6 0F 95 C2 48 8B 39 48 85 FF 0F 95 C0 84 D0 74 0F 48 C7 01 00 00 00 00 FF D6 41 B8 01 00 00 00 41 FF C4 41 83 FC 1F 7E AA FF C3 83 FB 1F 7E 90 41 FF C5 41 83 FD 03 0F 9E C0 41 84 C0 74 07 31 DB 45 31 C0 EB E5 48 8B 7D 30 48 89 EE 45 31 E4 E8 ?? ?? ?? ?? EB 24 49 63 DC 48 8B BC DD 48 01 00 00 48 85 FF 74 11 E8 ?? ?? ?? }
	condition:
		$pattern
}

rule fflush_unlocked_cd7b78176d67e6c1d06f2a22d7aadd64 {
	meta:
		aliases = "__GI_fflush_unlocked, fflush_unlocked"
		size = "329"
		objfiles = "fflush_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 45 31 ED 41 54 55 53 48 89 FB 48 83 EC 28 48 81 FF ?? ?? ?? ?? 74 0F 48 85 FF 41 BD 00 01 00 00 0F 85 EE 00 00 00 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 45 31 E4 E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 FF C0 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 2D ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? EB 76 F6 45 00 40 74 6C 83 3D ?? ?? ?? ?? 02 74 1C 48 8D 5D 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 44 89 E8 0B 45 00 66 35 40 }
	condition:
		$pattern
}

rule _obstack_newchunk_79c98f43d65a566f8f4cae32624ab636 {
	meta:
		aliases = "_obstack_newchunk"
		size = "304"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 48 63 F6 41 54 55 53 48 89 FB 48 83 EC 08 48 63 47 30 4C 8B 67 18 4C 2B 67 10 4C 8B 6F 08 48 01 C6 4C 89 E0 48 C1 F8 03 49 8D 44 04 64 48 01 C6 48 39 37 48 8B 47 38 48 89 F5 48 0F 4D 2F F6 47 50 01 74 0B 48 8B 7F 48 48 89 EE FF D0 EB 05 48 89 EF FF D0 48 85 C0 48 89 C6 75 05 E8 06 01 00 00 48 89 43 08 4C 89 68 08 48 8D 04 28 48 89 43 20 48 89 06 8B 53 30 48 63 C2 48 8D 6C 06 10 89 D0 F7 D0 48 98 48 21 C5 31 C0 83 FA 0E 7E 30 4C 89 E7 48 C1 EF 02 48 8D 4F FF EB 16 48 8B 53 10 48 8D 04 8D 00 00 00 00 48 FF C9 8B 14 02 89 54 05 00 48 85 C9 79 E5 48 8D 04 BD 00 00 00 00 48 89 C2 EB 0E 48 8B }
	condition:
		$pattern
}

rule pthread_cancel_5329262980f29808a05a13577e9dd678 {
	meta:
		aliases = "pthread_cancel"
		size = "188"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 48 89 F8 31 F6 25 FF 03 00 00 41 54 48 C1 E0 05 4C 8D A0 ?? ?? ?? ?? 55 48 89 FD 4C 89 E7 53 48 83 EC 08 E8 ?? ?? ?? ?? 49 8B 5C 24 10 48 85 DB 74 06 48 39 6B 20 74 0F 4C 89 E7 E8 ?? ?? ?? ?? B8 03 00 00 00 EB 6B 0F BE 43 7A 80 7B 78 01 C6 43 7A 01 0F 94 C2 85 C0 0F 95 C0 08 C2 74 0A 4C 89 E7 E8 ?? ?? ?? ?? EB 47 48 8B 83 D8 02 00 00 31 ED 44 8B 6B 28 48 85 C0 74 11 48 89 DE 48 8B 38 FF 50 08 89 C5 88 83 D0 02 00 00 4C 89 E7 E8 ?? ?? ?? ?? 85 ED 74 0A 48 89 DF E8 ?? ?? ?? ?? EB 0E 8B 35 ?? ?? ?? ?? 44 89 EF E8 ?? ?? ?? ?? 31 C0 5E 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule memmem_75ba5eaae0438ab3f9c8c270e70fad6c {
	meta:
		aliases = "__GI_memmem, memmem"
		size = "95"
		objfiles = "memmem@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 48 89 F8 49 89 D5 41 54 4C 8D 24 37 55 49 29 CC 48 89 CD 53 48 89 FB 48 83 EC 08 48 85 C9 74 35 EB 05 48 89 D8 EB 2E 48 39 CE 73 22 EB 25 8A 03 41 3A 45 00 75 15 48 8D 55 FF 49 8D 75 01 48 8D 7B 01 E8 ?? ?? ?? ?? 85 C0 74 D7 48 FF C3 4C 39 E3 76 DB 31 C0 5A 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule __GI_pthread_getschedparam_66986966d8f1f7b86ccb8fbe4e939ceb {
	meta:
		aliases = "pthread_getschedparam, __GI_pthread_getschedparam"
		size = "140"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 48 89 F8 49 89 F5 25 FF 03 00 00 31 F6 41 54 48 C1 E0 05 49 89 D4 55 48 89 FD 53 48 8D 98 ?? ?? ?? ?? 48 83 EC 08 48 89 DF E8 ?? ?? ?? ?? 48 8B 43 10 48 85 C0 74 06 48 39 68 20 74 0F 48 89 DF E8 ?? ?? ?? ?? B8 03 00 00 00 EB 36 8B 68 28 48 89 DF E8 ?? ?? ?? ?? 89 EF E8 ?? ?? ?? ?? 83 F8 FF 89 C3 74 0E 4C 89 E6 89 EF E8 ?? ?? ?? ?? FF C0 75 09 E8 ?? ?? ?? ?? 8B 00 EB 06 41 89 5D 00 31 C0 5A 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule __GI_wcsncasecmp_163ff42c9d1f3d01b619c5f5678eecea {
	meta:
		aliases = "wcsncasecmp, __GI_wcsncasecmp"
		size = "110"
		objfiles = "wcsncasecmp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 D5 41 54 49 89 F4 55 48 89 FD 53 48 83 EC 08 EB 11 83 7D 00 00 74 49 48 83 C5 04 49 83 C4 04 49 FF CD 4D 85 ED 74 39 8B 7D 00 41 3B 3C 24 74 E1 E8 ?? ?? ?? ?? 41 8B 3C 24 89 C3 E8 ?? ?? ?? ?? 39 C3 74 CD 8B 7D 00 E8 ?? ?? ?? ?? 41 8B 3C 24 89 C3 E8 ?? ?? ?? ?? 39 C3 19 C0 83 C8 01 EB 02 31 C0 5A 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule pthread_atfork_46813445732f51e0f891a426eabf2f11 {
	meta:
		aliases = "pthread_atfork"
		size = "134"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 D5 41 54 49 89 F4 55 48 89 FD BF 30 00 00 00 53 48 83 EC 08 E8 ?? ?? ?? ?? 48 89 C3 B8 0C 00 00 00 48 85 DB 74 54 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C9 48 89 DA 48 89 EE BF ?? ?? ?? ?? E8 91 FE FF FF 48 8D 53 10 B9 01 00 00 00 4C 89 E6 BF ?? ?? ?? ?? E8 7B FE FF FF 48 8D 53 20 B9 01 00 00 00 4C 89 EE BF ?? ?? ?? ?? E8 65 FE FF FF BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 5A 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule timer_create_986950da4b3fe5a1a820930d962aaba9 {
	meta:
		aliases = "timer_create"
		size = "168"
		objfiles = "timer_create@librt.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 D5 41 54 49 89 F4 55 53 89 FB 48 83 EC 58 48 85 F6 75 13 C7 44 24 0C 00 00 00 00 C7 44 24 08 0E 00 00 00 49 89 E4 41 83 7C 24 0C 02 74 66 BF 08 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 74 54 48 89 04 24 48 8D 54 24 4C 4C 89 E6 48 63 FB B8 DE 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 83 FB FF 74 15 41 8B 44 24 0C 49 89 6D 00 89 45 00 8B 44 24 4C 89 45 04 EB 0D 48 89 EF E8 ?? ?? ?? ?? EB 03 83 CB FF 48 83 C4 58 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule fgetws_unlocked_c781fe478dcce998a680c68059be4d5c {
	meta:
		aliases = "__GI_fgetws_unlocked, fgetws_unlocked"
		size = "81"
		objfiles = "fgetws_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 D5 41 54 49 89 FC 55 89 F5 53 48 89 FB 48 83 EC 08 EB 02 FF CD 83 FD 01 7E 18 4C 89 EF E8 ?? ?? ?? ?? 83 F8 FF 74 0B 89 03 48 83 C3 04 83 F8 0A 75 E1 4C 39 E3 75 05 45 31 E4 EB 06 C7 03 00 00 00 00 5A 5B 5D 4C 89 E0 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule __regerror_1dc5e848725cc42ad75eee07eb928399 {
	meta:
		aliases = "regerror, __regerror"
		size = "111"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 D5 41 54 55 48 89 CD 53 48 83 EC 08 83 FF 10 76 05 E8 ?? ?? ?? ?? 48 63 C7 48 8B 1C C5 ?? ?? ?? ?? 48 81 C3 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 85 ED 4C 8D 60 01 74 27 49 39 EC 76 14 48 8D 55 FF 48 89 DE 4C 89 EF E8 ?? ?? ?? ?? C6 00 00 EB 0E 4C 89 E2 48 89 DE 4C 89 EF E8 ?? ?? ?? ?? 5E 5B 5D 4C 89 E0 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule __GI_sigaction_550eb7662730f2bda91a5c3acce2faf3 {
	meta:
		aliases = "sigaction, __GI_sigaction"
		size = "224"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 D5 41 54 55 48 89 F5 53 89 FB 48 81 EC A8 00 00 00 3B 3D ?? ?? ?? ?? 0F 84 A8 00 00 00 3B 3D ?? ?? ?? ?? 0F 84 9C 00 00 00 3B 3D ?? ?? ?? ?? 75 08 85 FF 0F 8F 8C 00 00 00 31 F6 48 85 ED 74 44 BA 98 00 00 00 48 89 EE 48 89 E7 E8 ?? ?? ?? ?? 48 83 7D 00 01 0F 97 C2 85 DB 0F 9F C0 84 D0 74 20 83 FB 40 7F 1B F6 85 88 00 00 00 04 74 0A 48 C7 04 24 ?? ?? ?? ?? EB 08 48 C7 04 24 ?? ?? ?? ?? 48 89 E6 4C 89 EA 89 DF E8 ?? ?? ?? ?? 83 F8 FF 74 3B 8D 43 FF 83 F8 3F 77 31 4D 85 ED 74 0F 48 63 C3 48 8B 04 C5 ?? ?? ?? ?? 49 89 45 00 48 85 ED 74 18 48 8B 45 00 48 63 D3 48 89 04 D5 ?? ?? ?? ?? EB }
	condition:
		$pattern
}

rule logwtmp_201af1682d9272c85058895a6eddf41a {
	meta:
		aliases = "logwtmp"
		size = "167"
		objfiles = "logwtmp@libutil.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 D5 BA 90 01 00 00 41 54 49 89 FC 55 48 89 F5 31 F6 53 48 81 EC 98 01 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 85 ED 74 0B 80 7D 00 00 B8 07 00 00 00 75 05 B8 08 00 00 00 66 89 04 24 E8 ?? ?? ?? ?? 48 8D 7C 24 08 4C 89 E6 BA 1F 00 00 00 89 44 24 04 E8 ?? ?? ?? ?? 48 8D 7C 24 2C 48 89 EE BA 1F 00 00 00 E8 ?? ?? ?? ?? 48 8D 7C 24 4C BA FF 00 00 00 4C 89 EE E8 ?? ?? ?? ?? 48 8D BC 24 58 01 00 00 31 F6 E8 ?? ?? ?? ?? 48 89 E6 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 81 C4 98 01 00 00 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule exchange_f1ec59eef2bb80820d2abb05816c31cf {
	meta:
		aliases = "exchange"
		size = "187"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F0 49 89 FD 41 54 55 53 8B 5E 28 44 8B 66 2C 8B 2E EB 78 41 89 EA 45 89 E1 31 FF 45 29 E2 41 29 D9 45 31 DB 45 39 CA 7F 2C EB 58 89 E8 42 8D 0C 1B 44 29 C8 44 01 D8 48 63 C9 41 FF C3 48 98 49 8D 4C CD 00 49 8D 44 C5 00 48 8B 31 48 8B 10 48 89 11 48 89 30 45 39 CB 7C D1 44 29 CD EB 2C 8D 0C 3B 41 8D 04 3C FF C7 48 63 C9 48 98 49 8D 4C CD 00 49 8D 44 C5 00 48 8B 31 48 8B 10 48 89 11 48 89 30 44 39 D7 7C D7 44 01 D3 44 39 E5 0F 9F C2 41 39 DC 0F 9F C0 84 D0 0F 85 74 FF FF FF 41 8B 10 89 D0 41 2B 40 2C 41 89 50 2C 41 01 40 28 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule readtcp_4a264c5b3535e8f8dc7b41c911935224 {
	meta:
		aliases = "readtcp"
		size = "131"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 41 89 D4 55 48 89 FD 53 48 83 EC 18 8B 1F 48 89 E7 BA B8 88 00 00 BE 01 00 00 00 89 1C 24 66 C7 44 24 04 01 00 E8 ?? ?? ?? ?? 83 F8 FF 74 06 85 C0 74 31 EB 0A E8 ?? ?? ?? ?? 83 38 04 EB 0B 0F BF 44 24 06 A8 18 75 1C A8 20 75 18 F6 44 24 06 01 74 BB 49 63 D4 4C 89 EE 89 DF E8 ?? ?? ?? ?? 85 C0 7F 0D 48 8B 45 40 C7 00 00 00 00 00 83 C8 FF 48 83 C4 18 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule xdrrec_getbytes_b253483967c01953be6bc109d37c37c9 {
	meta:
		aliases = "xdrrec_getbytes"
		size = "110"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 41 89 D4 55 53 48 83 EC 08 48 8B 6F 18 EB 41 8B 45 68 85 C0 75 14 83 7D 70 00 75 40 48 89 EF E8 E8 FE FF FF 85 C0 75 28 EB 32 44 39 E0 44 89 E3 4C 89 EE 0F 46 D8 48 89 EF 89 DA E8 6B FE FF FF 85 C0 74 18 89 D8 48 29 45 68 41 29 DC 49 01 C5 45 85 E4 75 BA B8 01 00 00 00 EB 02 31 C0 41 5B 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule __GI_vswscanf_889bff707294fe44daffe2d1ce48272d {
	meta:
		aliases = "vswscanf, __GI_vswscanf"
		size = "135"
		objfiles = "vswscanf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 49 89 D4 53 48 89 FB 48 83 C4 80 48 89 7C 24 18 48 89 7C 24 08 E8 ?? ?? ?? ?? 48 8D 04 83 48 8D 7C 24 58 48 89 5C 24 28 48 89 5C 24 30 C7 44 24 04 FD FF FF FF 48 89 44 24 10 48 89 44 24 20 66 C7 04 24 21 08 C6 44 24 02 00 C7 44 24 48 00 00 00 00 C7 44 24 50 01 00 00 00 E8 ?? ?? ?? ?? 4C 89 E2 4C 89 EE 48 89 E7 48 C7 44 24 38 00 00 00 00 E8 ?? ?? ?? ?? 48 83 EC 80 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule sem_timedwait_ddc34bf93063b4f82133e1651167e84d {
	meta:
		aliases = "sem_timedwait"
		size = "353"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 49 89 FC 55 53 48 83 EC 18 E8 5C FF FF FF 4C 89 E7 48 89 C6 48 89 C5 E8 ?? ?? ?? ?? 41 8B 44 24 10 85 C0 7E 14 FF C8 4C 89 E7 41 89 44 24 10 E8 ?? ?? ?? ?? E9 14 01 00 00 49 81 7D 08 FF C9 9A 3B 76 18 4C 89 E7 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 ED 00 00 00 4C 89 24 24 48 C7 44 24 08 ?? ?? ?? ?? 48 89 E6 C6 85 D2 02 00 00 00 48 89 EF E8 D2 FD FF FF 80 7D 7A 00 74 0B 80 7D 78 00 BB 01 00 00 00 74 0F 49 8D 7C 24 18 48 89 EE 31 DB E8 5F FD FF FF 4C 89 E7 E8 ?? ?? ?? ?? 85 DB 74 0C 31 F6 48 89 EF E8 9C FD FF FF EB 75 4C 89 EE 48 89 EF E8 ?? ?? ?? ?? 85 C0 75 2E }
	condition:
		$pattern
}

rule vwarn_work_a3d7a617488c5c85ce458bfd8ad4133a {
	meta:
		aliases = "vwarn_work"
		size = "202"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 49 89 FC 55 53 BB ?? ?? ?? ?? 48 83 EC 68 85 D2 74 19 E8 ?? ?? ?? ?? 8B 38 48 89 E6 BA 40 00 00 00 BB ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 8B 68 50 85 ED 75 23 48 8D 7C 24 40 48 8D 50 58 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 83 C7 58 E8 ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 31 C0 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 4D 85 E4 74 16 48 8B 3D ?? ?? ?? ?? 4C 89 EA 4C 89 E6 48 83 EB 02 E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 31 C0 48 89 E2 48 89 DE E8 ?? ?? ?? ?? 85 ED 75 0F 48 8D 7C 24 40 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 68 5B 5D 41 5C 41 }
	condition:
		$pattern
}

rule __wcstofpmax_1ff8e452c2a4cac19d7c3bf01eb330ed {
	meta:
		aliases = "__wcstofpmax"
		size = "585"
		objfiles = "__wcstofpmax@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 49 89 FC 55 89 D5 53 48 89 FB 48 83 EC 28 EB 04 48 83 C3 04 8B 3B E8 ?? ?? ?? ?? 85 C0 75 F1 8B 03 83 F8 2B 74 0D 45 31 C0 83 F8 2D 75 0C 41 B0 01 EB 03 45 31 C0 48 83 C3 04 D9 EE 4C 8B 0D ?? ?? ?? ?? 31 FF 83 CE FF D9 05 ?? ?? ?? ?? EB 2C 81 FE 00 00 00 80 83 DE FF 85 F6 75 05 83 F9 30 74 16 FF C6 83 FE 15 7F 0F DC C9 8D 41 D0 89 44 24 80 DB 44 24 80 DE C2 48 83 C3 04 8B 0B 48 63 C1 41 F6 04 41 08 75 C8 83 F9 2E 0F 94 C2 48 85 FF 0F 94 C0 84 D0 74 09 48 83 C3 04 48 89 DF EB DB DF C0 85 F6 0F 89 A0 00 00 00 48 85 FF 0F 85 8F 00 00 00 31 F6 31 D2 EB 49 89 FA 8D 44 32 01 48 }
	condition:
		$pattern
}

rule initstate_r_020337a058783133062e5378c36ae8c2 {
	meta:
		aliases = "__GI_initstate_r, initstate_r"
		size = "185"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 55 48 89 CD 53 48 83 EC 08 48 83 FA 7F 76 0E 48 81 FA 00 01 00 00 19 DB 83 C3 04 EB 19 48 83 FA 1F 77 0A 31 DB 48 83 FA 07 77 0B EB 64 48 83 FA 40 19 DB 83 C3 02 48 63 C3 4D 8D 65 04 89 5D 18 48 63 14 85 ?? ?? ?? ?? 8B 04 85 ?? ?? ?? ?? 48 89 EE 4C 89 65 10 89 45 20 89 55 1C 49 8D 14 94 48 89 55 28 E8 ?? ?? ?? ?? 31 C0 85 DB 41 C7 45 00 00 00 00 00 74 33 48 8B 45 08 4C 29 E0 48 C1 F8 02 48 8D 04 80 8D 04 03 41 89 45 00 31 C0 EB 19 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 5F 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule getcwd_99f5bde551f24d0e72f142422c9a6d53 {
	meta:
		aliases = "__GI_getcwd, getcwd"
		size = "203"
		objfiles = "getcwd@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 55 48 89 FD 53 48 83 EC 08 48 85 F6 75 2C 48 85 FF 74 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 94 00 00 00 E8 ?? ?? ?? ?? BA 00 10 00 00 3D 00 10 00 00 0F 4D D0 48 63 DA EB 0B 48 85 FF 48 89 F3 49 89 FC 75 10 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 49 89 C4 74 62 48 89 DE 4C 89 E7 B8 4F 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 85 DB 78 28 48 85 ED 0F 94 C2 4D 85 ED 0F 94 C0 84 D0 74 0E 48 63 F3 4C 89 E7 E8 ?? ?? ?? ?? 48 89 C5 48 85 ED 75 16 4C 89 E5 EB 11 48 85 ED 75 0A 4C 89 E7 E8 ?? ?? ?? ?? EB 02 31 ED 5A 5B 48 89 E8 5D 41 5C }
	condition:
		$pattern
}

rule _Unwind_Find_FDE_61db2a6f097abd0e120744638493a695 {
	meta:
		aliases = "_Unwind_Find_FDE"
		size = "289"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 55 53 48 89 FB 48 83 EC 18 48 8B 2D ?? ?? ?? ?? 48 85 ED 75 0E E9 80 00 00 00 48 8B 6D 28 48 85 ED 74 77 48 3B 5D 00 66 90 72 EF 48 89 DE 48 89 EF E8 63 F9 FF FF 48 85 C0 49 89 C4 74 5C 48 8B 45 08 49 89 45 00 48 8B 45 10 49 89 45 08 8B 45 20 66 C1 E8 03 F6 45 20 04 0F B6 C0 0F 85 A1 00 00 00 0F B6 D8 48 89 EE 89 DF E8 4A EF FF FF 48 8D 4C 24 10 49 8D 54 24 08 48 89 C6 89 DF E8 96 EF FF FF 48 8B 44 24 10 49 89 45 10 48 83 C4 18 4C 89 E0 5B 5D 41 5C 41 5D C3 45 31 E4 48 8B 2D ?? ?? ?? ?? 48 85 ED 74 E3 48 8B 45 28 48 89 DE 48 89 EF 48 89 05 ?? ?? ?? ?? E8 DA F8 FF FF 49 89 }
	condition:
		$pattern
}

rule __encode_answer_dd2b90513cc210870f5ee3184e6be38d {
	meta:
		aliases = "__encode_answer"
		size = "161"
		objfiles = "encodea@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 55 89 D5 53 48 89 FB 48 83 EC 08 48 8B 3F E8 ?? ?? ?? ?? 85 C0 41 89 C4 78 75 29 C5 8B 43 14 83 C0 0A 39 C5 7D 06 41 83 CC FF EB 63 0F B6 43 09 49 63 FC 49 8D 7C 3D 00 88 07 8B 43 08 88 47 01 0F B6 43 0D 88 47 02 8B 43 0C 88 47 03 0F B6 43 13 88 47 04 0F B6 43 12 88 47 05 0F B6 43 11 88 47 06 8B 43 10 88 47 07 0F B6 43 15 88 47 08 8B 43 14 88 47 09 48 63 53 14 48 83 C7 0A 48 8B 73 18 E8 ?? ?? ?? ?? 8B 43 14 83 C0 0A 41 01 C4 5A 5B 5D 44 89 E0 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule getspent_r_682c74159ccc7457f3e7bc40c12c8a6d {
	meta:
		aliases = "getpwent_r, __GI_getspent_r, __GI_getgrent_r, __GI_getpwent_r, getgrent_r, getspent_r"
		size = "173"
		objfiles = "getpwent_r@libc.a, getgrent_r@libc.a, getspent_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 BE ?? ?? ?? ?? 41 54 49 89 FC 55 48 89 CD 53 48 89 D3 BA ?? ?? ?? ?? 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 C7 45 00 00 00 00 00 48 83 3D ?? ?? ?? ?? 00 75 2B BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 75 09 E8 ?? ?? ?? ?? 8B 18 EB 2B C7 40 50 01 00 00 00 4C 8B 05 ?? ?? ?? ?? 48 89 D9 4C 89 EA 4C 89 E6 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 89 C3 75 04 4C 89 65 00 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 89 D8 48 83 C4 28 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule readunix_79effc3e6c6a4c66d1d86337ea49b0ca {
	meta:
		aliases = "readunix"
		size = "298"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 41 89 D4 55 48 89 F5 53 48 83 EC 68 8B 1F 48 8D 7C 24 50 BA B8 88 00 00 BE 01 00 00 00 89 5C 24 50 66 C7 44 24 54 01 00 E8 ?? ?? ?? ?? 83 F8 FF 74 0A 85 C0 0F 84 CF 00 00 00 EB 0A E8 ?? ?? ?? ?? 83 38 04 EB 0F 0F BF 44 24 56 A8 18 0F 85 B6 00 00 00 A8 20 0F 85 AE 00 00 00 F6 44 24 56 01 74 AC 49 63 C4 48 8D 4C 24 5C 41 B8 04 00 00 00 48 89 44 24 48 48 8D 44 24 40 BA 10 00 00 00 BE 01 00 00 00 89 DF 48 89 6C 24 40 48 89 44 24 10 48 C7 44 24 18 01 00 00 00 48 C7 04 24 00 00 00 00 C7 44 24 08 00 00 00 00 48 C7 44 24 20 ?? ?? ?? ?? 48 C7 44 24 28 28 00 00 00 C7 44 24 30 00 00 }
	condition:
		$pattern
}

rule writetcp_62716c6eb7945641e80949ebebb33279 {
	meta:
		aliases = "writetcp"
		size = "80"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 41 89 D4 55 48 89 F5 53 89 D3 48 83 EC 08 EB 2A 41 8B 7D 00 48 63 D3 48 89 EE E8 ?? ?? ?? ?? 85 C0 79 10 49 8B 45 40 41 83 CC FF C7 00 00 00 00 00 EB 0B 29 C3 48 98 48 01 C5 85 DB 7F D2 5E 5B 5D 44 89 E0 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule gethostbyaddr_05a060a57be7981e01dccd002692de98 {
	meta:
		aliases = "__GI_gethostbyaddr, gethostbyaddr"
		size = "81"
		objfiles = "gethostbyaddr@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 41 89 F4 53 89 D3 48 83 EC 20 E8 ?? ?? ?? ?? 48 89 44 24 08 48 8D 44 24 18 89 DA 44 89 E6 4C 89 EF 41 B9 00 02 00 00 41 B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 48 89 04 24 E8 ?? ?? ?? ?? 48 8B 44 24 18 48 83 C4 20 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule fgets_unlocked_a4e9ed5d00fce2849a183e19fe90594a {
	meta:
		aliases = "__GI_fgets_unlocked, fgets_unlocked"
		size = "116"
		objfiles = "fgets_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 41 89 F4 55 48 89 D5 53 48 89 FB 48 83 EC 08 85 F6 7F 3D EB 4A 48 8B 45 18 48 3B 45 28 73 13 8A 10 48 FF C0 88 13 48 FF C3 80 FA 0A 48 89 45 18 EB 1C 48 89 EF E8 ?? ?? ?? ?? 83 F8 FF 75 08 F6 45 00 08 74 10 EB 18 88 03 48 FF C3 3C 0A 74 05 41 FF CC 75 C0 4C 39 EB 76 05 C6 03 00 EB 03 45 31 ED 5A 5B 5D 41 5C 4C 89 E8 41 5D C3 }
	condition:
		$pattern
}

rule _dl_fixup_ecbf4b9080cade822eaa5c3d569d99e4 {
	meta:
		aliases = "_dl_fixup"
		size = "277"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 41 89 F4 55 53 48 83 EC 08 48 8B 7F 20 48 85 FF 74 0F E8 ?? ?? ?? ?? 85 C0 89 C5 0F 85 E2 00 00 00 49 8B 5D 00 BD 01 00 00 00 48 83 BB 08 01 00 00 00 66 8B 53 42 0F 85 C7 00 00 00 48 8B B3 B8 00 00 00 48 8B 83 C0 00 00 00 48 85 F6 74 4F 80 E2 01 75 4A 8B BB 90 01 00 00 41 89 C0 85 FF 74 29 89 F8 4C 8B 0B 48 8D 4E E8 4C 6B D0 18 48 83 C1 18 4C 89 C8 48 03 41 10 48 8B 11 FF CF 49 89 04 11 75 EA 45 29 D0 4C 01 D6 44 89 C2 4C 89 EF E8 ?? ?? ?? ?? 66 83 4B 42 01 89 C5 EB 02 31 ED 48 83 BB 40 01 00 00 00 B8 02 00 00 00 44 0F 45 E0 48 83 BB 38 01 00 00 00 74 48 F6 43 42 02 74 0E }
	condition:
		$pattern
}

rule pthread_cleanup_upto_21013a1a61b7416465c72be89cba35b2 {
	meta:
		aliases = "pthread_cleanup_upto"
		size = "171"
		objfiles = "ptlongjmp@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 41 BC ?? ?? ?? ?? 55 53 48 83 EC 08 48 3B 25 ?? ?? ?? ?? 48 89 E5 73 3F 48 3B 25 ?? ?? ?? ?? 72 0F 48 3B 25 ?? ?? ?? ?? 41 BC ?? ?? ?? ?? 72 27 83 3D ?? ?? ?? ?? 00 74 0E E8 ?? ?? ?? ?? 49 89 C4 EB 14 31 DB EB 31 48 89 E8 48 0D FF FF 1F 00 4C 8D A0 01 FD FF FF 49 8B 5C 24 70 EB 0F 48 39 EB 76 E0 48 8B 7B 08 FF 13 48 8B 5B 18 48 85 DB 74 06 49 3B 5D 30 72 E6 49 8B 84 24 A0 00 00 00 49 89 5C 24 70 48 85 C0 74 12 49 3B 45 30 73 0C 49 C7 84 24 A0 00 00 00 00 00 00 00 58 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule __parsespent_a1c5433ca5b997a72fb736b987fd1913 {
	meta:
		aliases = "__parsespent"
		size = "153"
		objfiles = "__parsespent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 45 31 E4 55 48 89 F5 53 48 83 EC 18 49 63 C4 41 83 FC 01 0F B6 80 ?? ?? ?? ?? 49 8D 5C 05 00 7F 17 48 89 2B BE 3A 00 00 00 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 75 3E EB 48 48 8D 74 24 10 BA 0A 00 00 00 48 89 EF E8 ?? ?? ?? ?? 48 89 03 48 39 6C 24 10 75 07 48 C7 03 FF FF FF FF 41 83 FC 08 48 8B 44 24 10 75 09 31 D2 80 38 00 74 18 EB 11 80 38 3A 75 0C 48 8D 68 01 41 FF C4 C6 00 00 EB 8C BA 16 00 00 00 48 83 C4 18 89 D0 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule fwrite_unlocked_1fe3016b1275a5cc03f1320d25ebd2bf {
	meta:
		aliases = "__GI_fwrite_unlocked, fwrite_unlocked"
		size = "134"
		objfiles = "fwrite_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 49 89 D4 55 48 89 F5 53 48 89 CB 48 83 EC 08 0F B7 01 25 C0 00 00 00 3D C0 00 00 00 74 11 BE 80 00 00 00 48 89 CF E8 ?? ?? ?? ?? 85 C0 75 46 48 85 ED 0F 95 C2 4D 85 E4 0F 95 C0 84 D0 74 36 48 83 C8 FF 31 D2 48 F7 F5 49 39 C4 77 19 48 89 EE 48 89 DA 4C 89 EF 49 0F AF F4 E8 ?? ?? ?? ?? 31 D2 48 F7 F5 EB 11 66 83 0B 08 E8 ?? ?? ?? ?? C7 00 16 00 00 00 31 C0 5A 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule __stdio_fwrite_036a36672f51865a02a33d876a41b213 {
	meta:
		aliases = "__stdio_fwrite"
		size = "259"
		objfiles = "_fwrite@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 49 89 F4 55 48 89 D5 53 48 83 EC 08 F6 42 01 02 0F 85 C6 00 00 00 83 7A 04 FE 48 8B 7A 18 48 8B 42 10 75 21 48 89 C3 48 29 FB 48 39 DE 48 0F 46 DE 4C 89 EE 48 89 DA E8 ?? ?? ?? ?? 48 01 5D 18 E9 AC 00 00 00 48 29 F8 48 39 C6 77 77 48 89 F2 4C 89 EE E8 ?? ?? ?? ?? 4C 01 65 18 F6 45 01 01 0F 84 8B 00 00 00 4C 89 E2 BE 0A 00 00 00 4C 89 EF E8 ?? ?? ?? ?? 48 85 C0 74 76 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 74 69 49 39 C4 48 89 C3 4C 89 E0 49 0F 46 DC BE 0A 00 00 00 48 29 D8 48 89 DA 49 01 C5 4C 89 EF E8 ?? ?? ?? ?? 48 85 C0 48 89 C2 74 3E 49 8D 44 1D 00 48 29 D0 48 29 45 18 49 29 }
	condition:
		$pattern
}

rule byte_group_match_null_string_p_5f7455216f701cc36e0f553c3f9462f1 {
	meta:
		aliases = "byte_group_match_null_string_p"
		size = "304"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 49 89 F4 55 48 89 D5 53 48 83 EC 18 48 8B 07 48 83 C0 02 48 89 44 24 10 E9 F1 00 00 00 0F B6 02 83 F8 07 0F 84 C2 00 00 00 83 F8 0F 0F 85 C8 00 00 00 48 8D 42 01 48 89 44 24 10 0F BE 40 01 0F B6 4A 01 48 83 C2 03 48 89 54 24 10 C1 E0 08 01 C1 79 5D E9 B6 00 00 00 48 89 74 24 10 EB 60 48 8D 74 1F FD 48 89 EA E8 22 FF FF FF 84 C0 0F 84 A8 00 00 00 48 89 DE 48 03 74 24 10 48 89 74 24 10 80 3E 0F 75 39 48 8D 46 01 48 89 44 24 10 0F BE 40 01 0F B6 56 01 C1 E0 08 8D 0C 02 48 8D 56 03 48 63 C1 48 89 54 24 10 80 7C 02 FD 0E 75 A8 48 8B 7C 24 10 48 63 D9 80 7C 1F FD 0E 74 A0 48 8B }
	condition:
		$pattern
}

rule lsearch_fd3c6b71d08545fa9e79ca0899fac8b5 {
	meta:
		aliases = "lsearch"
		size = "67"
		objfiles = "lsearch@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 49 89 F4 55 48 89 D5 53 48 89 CB 48 83 EC 08 E8 ?? ?? ?? ?? 48 85 C0 75 1B 48 89 DF 48 89 DA 4C 89 EE 48 0F AF 7D 00 49 8D 3C 3C E8 ?? ?? ?? ?? 48 FF 45 00 5A 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule __GI_svc_unregister_5cb24ce3f426a5440b21827b4a149db4 {
	meta:
		aliases = "svc_unregister, __GI_svc_unregister"
		size = "101"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 49 89 F4 55 53 48 83 EC 18 48 8D 54 24 10 E8 76 FD FF FF 48 85 C0 48 89 C3 74 38 48 8B 44 24 10 48 8B 2B 48 85 C0 75 0E E8 ?? ?? ?? ?? 48 89 A8 F0 00 00 00 EB 03 48 89 28 48 89 DF 48 C7 03 00 00 00 00 E8 ?? ?? ?? ?? 4C 89 E6 4C 89 EF E8 ?? ?? ?? ?? 48 83 C4 18 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule remquo_bcda67ff6dc8df55b3e0615fe7de40f1 {
	meta:
		aliases = "__GI_remquo, remquo"
		size = "115"
		objfiles = "s_remquo@libm.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 53 31 DB 48 83 EC 10 F2 0F 11 04 24 4C 8B 24 24 F2 0F 5E C1 F2 0F 11 4C 24 08 48 8B 44 24 08 4C 89 E2 48 C1 EA 20 48 C1 E8 20 C1 EA 1F C1 E8 1F 39 C2 0F 94 C3 8D 5C 1B FF E8 ?? ?? ?? ?? 48 63 DB E8 ?? ?? ?? ?? 83 E0 7F 48 0F AF D8 41 89 5D 00 4C 89 24 24 66 0F 12 4C 24 08 66 0F 12 04 24 58 5A 5B 41 5C 41 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_fputws_unlocked_3c748e7412d1112442eb46642c4483cb {
	meta:
		aliases = "fputws_unlocked, __GI_fputws_unlocked"
		size = "50"
		objfiles = "fputws_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 53 48 89 F3 E8 ?? ?? ?? ?? 48 89 DA 4C 89 EF 48 89 C6 49 89 C4 E8 ?? ?? ?? ?? 5B 4C 39 E0 41 5C 41 5D 0F 94 C0 0F B6 C0 FF C8 C3 }
	condition:
		$pattern
}

rule __parsepwent_80867b2e5c523e06394a78bd6f15c852 {
	meta:
		aliases = "__parsepwent"
		size = "141"
		objfiles = "__parsepwent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 55 31 ED 53 48 89 F3 48 83 EC 18 48 63 C5 0F B6 80 ?? ?? ?? ?? 4D 8D 64 05 00 89 E8 83 E0 06 83 F8 02 74 1D 83 FD 06 49 89 1C 24 74 47 BE 3A 00 00 00 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 75 2A EB 37 48 8D 74 24 10 BA 0A 00 00 00 48 89 DF E8 ?? ?? ?? ?? 48 89 C2 48 8B 44 24 10 48 39 D8 74 18 80 38 3A 75 13 41 89 14 24 48 8D 58 01 FF C5 C6 00 00 EB 97 31 C0 EB 03 83 C8 FF 48 83 C4 18 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule __GI_fputws_99a800bf3357b96d85730affeec177c2 {
	meta:
		aliases = "__GI_fputs, fputws, fputs, __GI_fputws"
		size = "97"
		objfiles = "fputws@libc.a, fputs@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 55 48 89 F5 53 48 83 EC 28 44 8B 66 50 45 85 E4 75 1C 48 8D 5E 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 EE 4C 89 EF E8 ?? ?? ?? ?? 45 85 E4 89 C3 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule tdelete_17e11255d4c863baa00b945c9ae7e386 {
	meta:
		aliases = "tdelete"
		size = "204"
		objfiles = "tdelete@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 55 48 89 F5 53 48 89 D3 48 83 EC 08 48 85 F6 0F 84 A6 00 00 00 4C 8B 26 4D 85 E4 EB 16 48 8D 68 08 49 89 C4 48 8D 40 10 85 D2 48 0F 49 E8 48 83 7D 00 00 0F 84 82 00 00 00 48 8B 45 00 4C 89 EF 48 8B 30 FF D3 83 F8 00 89 C2 48 8B 45 00 75 CD 48 8B 58 08 48 8B 48 10 48 85 DB 74 12 48 85 C9 74 47 48 8B 51 08 48 85 D2 75 0F 48 89 59 08 48 89 CB EB 35 48 89 C2 48 89 F1 48 8B 42 08 48 89 D6 48 85 C0 75 EE 48 8B 42 10 48 89 D3 48 89 41 08 48 8B 45 00 48 8B 40 08 48 89 42 08 48 8B 45 00 48 8B 40 10 48 89 42 10 48 8B 7D 00 E8 ?? ?? ?? ?? 4C 89 E0 48 89 5D 00 EB 02 31 C0 5A 5B 5D 41 }
	condition:
		$pattern
}

rule __GI_xprt_register_044fd21ff280e45bafb9fe5b3208fb04 {
	meta:
		aliases = "xprt_register, __GI_xprt_register"
		size = "270"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 55 53 48 83 EC 08 44 8B 27 E8 ?? ?? ?? ?? 48 83 B8 E8 00 00 00 00 48 89 C5 75 24 E8 ?? ?? ?? ?? 48 98 48 8D 3C C5 00 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 85 E8 00 00 00 0F 84 C0 00 00 00 E8 ?? ?? ?? ?? 41 39 C4 0F 8D B2 00 00 00 48 8B 85 E8 00 00 00 49 63 DC 41 81 FC FF 03 00 00 4C 89 2C D8 7F 1B E8 ?? ?? ?? ?? 44 89 E1 48 C1 EB 06 BA 01 00 00 00 83 E1 3F 48 D3 E2 48 09 14 D8 31 DB EB 2F E8 ?? ?? ?? ?? 48 89 C1 48 63 C3 48 8D 14 C5 00 00 00 00 48 89 D0 48 03 01 83 38 FF 75 0F 44 89 20 48 8B 01 66 C7 44 10 04 C3 00 EB 4F FF C3 E8 ?? ?? ?? ?? 48 89 C5 8B 00 39 C3 7C C3 FF }
	condition:
		$pattern
}

rule msync_0ce154178588923eeef54445e970974d {
	meta:
		aliases = "msync"
		size = "68"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD BF 01 00 00 00 41 54 49 89 F4 53 89 D3 48 83 EC 10 48 8D 74 24 0C E8 ?? ?? ?? ?? 89 DA 4C 89 E6 4C 89 EF E8 ?? ?? ?? ?? 8B 7C 24 0C 31 F6 89 C3 E8 ?? ?? ?? ?? 5E 5F 89 D8 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule ether_hostton_2035ada10bd5ade3be5613f3e7e30afa {
	meta:
		aliases = "ether_hostton"
		size = "130"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD BF ?? ?? ?? ?? 41 54 49 89 F4 BE ?? ?? ?? ?? 55 53 83 CB FF 48 81 EC 08 01 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 74 45 EB 23 31 DB EB 37 4C 89 E6 48 89 E7 E8 84 FF FF FF 48 85 C0 48 89 C6 74 0C 4C 89 EF E8 ?? ?? ?? ?? 85 C0 74 DD 48 89 EA BE 00 01 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 85 C0 75 CC 83 CB FF 48 89 EF E8 ?? ?? ?? ?? 48 81 C4 08 01 00 00 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule __xpg_strerror_r_508625972a4ce8019344f4e8571a4864 {
	meta:
		aliases = "__GI___xpg_strerror_r, strerror_r, __xpg_strerror_r"
		size = "194"
		objfiles = "__xpg_strerror_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 89 F8 49 89 F5 41 54 55 BD ?? ?? ?? ?? 53 48 89 D3 48 83 EC 48 83 FF 7C 76 0C EB 17 80 7D 00 01 83 D8 00 48 FF C5 85 C0 75 F2 45 31 E4 80 7D 00 00 75 30 48 63 F7 48 8D 7C 24 31 31 C9 BA F6 FF FF FF 41 BC 16 00 00 00 E8 ?? ?? ?? ?? 48 8D 68 F2 BA 0E 00 00 00 BE ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 4D 85 ED B8 00 00 00 00 48 89 EF 48 0F 44 D8 E8 ?? ?? ?? ?? 8D 50 01 48 63 C2 48 39 D8 76 08 89 DA 41 BC 22 00 00 00 85 D2 74 17 48 63 DA 48 89 EE 4C 89 EF 48 89 DA E8 ?? ?? ?? ?? 41 C6 44 1D FF 00 45 85 E4 74 08 E8 ?? ?? ?? ?? 44 89 20 48 83 C4 48 44 89 E0 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule getresuid_3ae8953890bf70ef5acfc50131099116 {
	meta:
		aliases = "getresuid"
		size = "107"
		objfiles = "getresuid@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 B8 76 00 00 00 49 89 D5 41 54 49 89 F4 55 48 89 FD 53 48 83 EC 18 48 8D 54 24 0C 48 8D 74 24 10 48 8D 7C 24 14 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 85 DB 75 17 8B 44 24 14 89 45 00 8B 44 24 10 41 89 04 24 8B 44 24 0C 41 89 45 00 48 83 C4 18 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule getresgid_d9455d2dd20c150d44426d609c12dda9 {
	meta:
		aliases = "getresgid"
		size = "107"
		objfiles = "getresgid@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 B8 78 00 00 00 49 89 D5 41 54 49 89 F4 55 48 89 FD 53 48 83 EC 18 48 8D 54 24 0C 48 8D 74 24 10 48 8D 7C 24 14 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 85 DB 75 17 8B 44 24 14 89 45 00 8B 44 24 10 41 89 04 24 8B 44 24 0C 41 89 45 00 48 83 C4 18 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule __malloc_consolidate_c7717ce81fd4b44bd3dee8fbd465370e {
	meta:
		aliases = "__malloc_consolidate"
		size = "410"
		objfiles = "free@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 BA 01 00 00 00 41 54 55 53 48 89 FB 48 83 EC 08 48 8B 07 48 85 C0 0F 84 18 01 00 00 83 E0 FD 4C 8D 57 08 48 8D 6F 70 48 89 07 C1 E8 03 83 E8 02 4D 8D 2C C2 49 8B 0A 48 85 C9 0F 84 D2 00 00 00 49 C7 02 00 00 00 00 48 8B 41 08 4C 8B 61 10 49 89 C0 49 83 E0 FE A8 01 4A 8D 34 01 4C 8B 5E 08 75 2B 4C 8B 09 48 89 C8 4C 29 C8 48 8B 78 10 48 8B 50 18 48 8B 4F 18 48 39 C1 75 45 48 39 4A 10 75 3F 4D 01 C8 48 89 57 18 48 89 7A 10 4D 89 D9 49 83 E1 FC 48 3B 73 60 74 5C 42 8B 44 0E 08 4C 89 4E 08 83 E0 01 85 C0 75 27 48 8B 56 10 48 8B 46 18 48 8B 7A 18 48 39 F7 75 06 48 39 78 10 74 05 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_sleep_35c91511c460fe79800ebcb08cb962ae {
	meta:
		aliases = "sleep, __GI_sleep"
		size = "415"
		objfiles = "sleep@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 BA 10 00 00 00 41 54 55 53 48 81 EC B8 01 00 00 85 FF 75 14 E9 6F 01 00 00 48 63 C2 48 C7 84 C4 20 01 00 00 00 00 00 00 FF CA 79 ED 48 8D 9C 24 20 01 00 00 89 FF BE 11 00 00 00 48 89 BC 24 A0 01 00 00 48 C7 84 24 A8 01 00 00 00 00 00 00 48 89 DF E8 ?? ?? ?? ?? 85 C0 0F 88 2D 01 00 00 48 8D AC 24 A0 00 00 00 31 FF 48 89 DE 48 89 EA E8 ?? ?? ?? ?? 85 C0 0F 85 10 01 00 00 BE 11 00 00 00 48 89 EF E8 ?? ?? ?? ?? 85 C0 BA 10 00 00 00 74 14 E9 C1 00 00 00 48 63 C2 48 C7 84 C4 20 01 00 00 00 00 00 00 FF CA 79 ED 48 8D BC 24 20 01 00 00 BE 11 00 00 00 E8 ?? ?? ?? ?? 85 C0 0F 88 C8 00 00 00 31 F6 }
	condition:
		$pattern
}

rule localtime_r_2ac701d4eaad5dd18386d8e83c136901 {
	meta:
		aliases = "__GI_localtime_r, localtime_r"
		size = "103"
		objfiles = "localtime_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 BA ?? ?? ?? ?? 49 89 F5 BE ?? ?? ?? ?? 41 54 53 48 89 FB 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 FF 48 81 3B FF 4E 98 45 40 0F 9E C7 E8 ?? ?? ?? ?? 4C 89 EE 48 89 DF BA ?? ?? ?? ?? E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 83 C4 20 4C 89 E8 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule _time_mktime_691f8175c54a2e3c65e533858d259e52 {
	meta:
		aliases = "_time_mktime"
		size = "91"
		objfiles = "_time_mktime@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 BA ?? ?? ?? ?? 49 89 FD 41 54 53 89 F3 BE ?? ?? ?? ?? 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 DE 4C 89 EF BA ?? ?? ?? ?? E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 C3 48 89 E7 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 20 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule setstate_6b2535037577209b6aef2552c6f3a3ef {
	meta:
		aliases = "setstate"
		size = "98"
		objfiles = "random@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 41 54 53 48 89 FB 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 8B 25 ?? ?? ?? ?? 48 89 DF BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 DB 48 89 E7 BE 01 00 00 00 49 83 EC 04 85 C0 49 0F 49 DC E8 ?? ?? ?? ?? 48 83 C4 20 48 89 D8 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule rewinddir_bca9c52ed9cb75b7433d9b15cecb197c {
	meta:
		aliases = "rewinddir"
		size = "98"
		objfiles = "rewinddir@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 BE ?? ?? ?? ?? 41 54 4C 8D 67 30 53 4C 89 E2 48 89 FB 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? 8B 3B 31 D2 31 F6 E8 ?? ?? ?? ?? 48 C7 43 10 00 00 00 00 48 C7 43 08 00 00 00 00 BE 01 00 00 00 48 C7 43 20 00 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 83 C4 20 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule __fork_78c7efa20475e9f57db4645210a3d8b1 {
	meta:
		aliases = "fork, __fork"
		size = "236"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 BF ?? ?? ?? ?? 41 54 55 53 48 83 EC 18 E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 4C 8B 2D ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? E8 BF FF FF FF E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 41 89 C4 75 74 BD ?? ?? ?? ?? 48 85 ED 74 56 48 89 E7 E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 48 89 E6 E8 ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? 48 85 ED 74 27 48 89 E7 E8 ?? ?? ?? ?? 31 F6 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 48 89 E6 E8 ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 89 EF EB 1C BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF }
	condition:
		$pattern
}

rule __fixunsxfti_3611deb55d9845df4c1263371db49855 {
	meta:
		aliases = "__fixunsxfti"
		size = "534"
		objfiles = "_fixunsxfdi@libgcc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 D9 EE 31 C0 31 D2 41 54 53 48 83 EC 10 DB 6C 24 30 D9 C9 DF E9 0F 87 B3 01 00 00 DB 2D ?? ?? ?? ?? DE C9 DB 2D ?? ?? ?? ?? D9 C9 DB E9 DD D9 0F 83 91 00 00 00 D9 7C 24 0E 0F B7 44 24 0E 45 31 E4 80 CC 0C 66 89 44 24 0C D9 6C 24 0C DF 3C 24 D9 6C 24 0E 48 8B 0C 24 48 85 C9 49 89 CD 0F 88 A6 00 00 00 4C 89 E7 48 89 CE E8 ?? ?? ?? ?? DB 6C 24 30 DE E1 D9 EE DF E9 0F 87 C4 00 00 00 DB 2D ?? ?? ?? ?? D9 C9 DB E9 DD D9 0F 83 FE 00 00 00 D9 7C 24 0E 0F B7 44 24 0E 80 CC 0C 66 89 44 24 0C D9 6C 24 0C DF 3C 24 D9 6C 24 0E 48 8B 0C 24 48 89 C8 31 D2 4C 01 E0 4C 11 EA 48 83 C4 10 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule rwlock_have_already_e699021eeb978f5100d9573877a3a041 {
	meta:
		aliases = "rwlock_have_already"
		size = "201"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 56 31 C0 49 89 D6 31 D2 41 55 49 89 CD 31 C9 41 54 49 89 FC 55 48 89 F5 53 83 7E 30 01 48 8B 1F 0F 85 8E 00 00 00 48 85 DB 75 08 E8 EF FE FF FF 48 89 C3 48 8B 93 E0 02 00 00 EB 09 48 39 6A 08 74 0A 48 8B 12 48 85 D2 75 F2 EB 05 48 85 D2 75 5C 83 BB F0 02 00 00 00 7F 53 48 8B 93 E8 02 00 00 48 85 D2 74 0C 48 8B 02 48 89 83 E8 02 00 00 EB 0D BF 18 00 00 00 E8 ?? ?? ?? ?? 48 89 C2 31 C0 48 85 D2 B9 01 00 00 00 74 29 C7 42 10 01 00 00 00 48 89 6A 08 30 C9 48 8B 83 E0 02 00 00 48 89 02 31 C0 48 89 93 E0 02 00 00 EB 07 31 C9 B8 01 00 00 00 41 89 4D 00 49 89 16 49 89 1C 24 5B 5D 41 5C 41 5D 41 5E }
	condition:
		$pattern
}

rule get_myaddress_1b901adfe97b3414421fcc0b3e23e3cc {
	meta:
		aliases = "get_myaddress"
		size = "288"
		objfiles = "get_myaddress@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 31 D2 BE 02 00 00 00 41 55 49 89 FD BF 02 00 00 00 41 54 55 53 48 81 EC 40 10 00 00 E8 ?? ?? ?? ?? 85 C0 41 89 C4 BF ?? ?? ?? ?? 78 36 48 8D 94 24 30 10 00 00 31 C0 BE 12 89 00 00 44 89 E7 C7 84 24 30 10 00 00 00 10 00 00 48 89 A4 24 38 10 00 00 45 31 F6 E8 ?? ?? ?? ?? 85 C0 79 14 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF 01 00 00 00 E8 ?? ?? ?? ?? 48 8B 9C 24 38 10 00 00 8B AC 24 30 10 00 00 EB 72 FC 48 8D BC 24 00 10 00 00 B9 0A 00 00 00 48 89 DE F3 A5 48 8D 94 24 00 10 00 00 31 C0 BE 13 89 00 00 44 89 E7 E8 ?? ?? ?? ?? 85 C0 79 07 BF ?? ?? ?? ?? EB AB 0F BF 84 24 10 10 00 00 A8 01 74 2A 66 83 }
	condition:
		$pattern
}

rule __get_myaddress_59eff163d85fbd720411484ad4639fd2 {
	meta:
		aliases = "__get_myaddress"
		size = "322"
		objfiles = "pmap_clnt@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 31 D2 BE 02 00 00 00 41 55 49 89 FD BF 02 00 00 00 41 54 55 53 48 81 EC 40 10 00 00 E8 ?? ?? ?? ?? 85 C0 41 89 C4 BF ?? ?? ?? ?? 78 39 48 8D 94 24 30 10 00 00 31 C0 BE 12 89 00 00 44 89 E7 C7 84 24 30 10 00 00 00 10 00 00 48 89 A4 24 38 10 00 00 E8 ?? ?? ?? ?? 85 C0 41 BE 01 00 00 00 79 3D BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF 01 00 00 00 E8 ?? ?? ?? ?? 48 8B 43 10 44 89 E7 49 89 45 00 48 8B 43 18 66 41 C7 45 02 00 6F 49 89 45 08 E8 ?? ?? ?? ?? B8 01 00 00 00 E9 92 00 00 00 48 8B 9C 24 38 10 00 00 8B AC 24 30 10 00 00 EB 65 FC 48 8D BC 24 00 10 00 00 B9 0A 00 00 00 48 89 DE F3 A5 48 8D 94 24 }
	condition:
		$pattern
}

rule svcudp_reply_1e83f15ffe9a6f250c2623189c7dd5da {
	meta:
		aliases = "svcudp_reply"
		size = "553"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 49 89 FC 55 53 48 89 F3 31 F6 48 83 EC 10 4C 8B 6F 48 49 8D 6D 10 41 C7 45 10 00 00 00 00 48 8B 45 08 48 89 EF FF 50 28 49 8B 45 08 48 89 DE 48 89 EF 48 89 03 E8 ?? ?? ?? ?? 85 C0 0F 84 D2 01 00 00 48 8B 45 08 48 89 EF FF 50 20 49 8D 74 24 60 89 C3 49 8B 44 24 40 48 63 D3 48 83 7E 18 00 74 17 41 8B 3C 24 49 89 54 24 58 31 D2 49 89 44 24 50 E8 ?? ?? ?? ?? EB 18 45 8B 4C 24 10 41 8B 3C 24 4D 8D 44 24 14 31 C9 48 89 C6 E8 ?? ?? ?? ?? 39 D8 41 89 C6 0F 85 78 01 00 00 49 83 BD D0 01 00 00 00 F7 D0 B9 01 00 00 00 0F 95 C2 C1 E8 1F 84 D0 0F 84 5D 01 00 00 4D 8B 6C 24 48 49 8B AD D0 }
	condition:
		$pattern
}

rule _stdio_init_330c8b492ddc0dfe154cbbedb6304f7d {
	meta:
		aliases = "_stdio_init"
		size = "107"
		objfiles = "_stdio@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 53 BB 01 00 00 00 48 83 EC 08 E8 ?? ?? ?? ?? 31 FF 49 89 C5 44 8B 30 44 8B 25 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 DA BF 01 00 00 00 29 C2 89 D0 C1 E0 08 41 31 C4 66 44 89 25 ?? ?? ?? ?? 44 8B 25 ?? ?? ?? ?? E8 ?? ?? ?? ?? 29 C3 C1 E3 08 41 31 DC 66 44 89 25 ?? ?? ?? ?? 45 89 75 00 58 5B 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule xdr_rmtcall_args_b4f04f0ad6ebbbc0641dfc934b875f16 {
	meta:
		aliases = "__GI_xdr_rmtcall_args, xdr_rmtcall_args"
		size = "226"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 55 48 89 F5 53 48 89 FB 48 83 EC 10 E8 ?? ?? ?? ?? 85 C0 0F 84 B6 00 00 00 48 8D 75 08 48 89 DF E8 ?? ?? ?? ?? 85 C0 0F 84 A2 00 00 00 48 8D 75 10 48 89 DF E8 ?? ?? ?? ?? 85 C0 0F 84 8E 00 00 00 48 8B 43 08 48 89 DF 48 C7 44 24 08 00 00 00 00 FF 50 20 48 8D 74 24 08 48 89 DF 41 89 C6 E8 ?? ?? ?? ?? 85 C0 74 67 48 8B 43 08 48 89 DF FF 50 20 48 8B 75 20 41 89 C5 48 89 DF 31 C0 FF 55 28 85 C0 74 4A 48 8B 43 08 48 89 DF FF 50 20 44 89 EA 41 89 C4 89 C0 48 29 D0 44 89 F6 48 89 DF 48 89 45 18 48 8B 43 08 FF 50 28 48 8D 75 18 48 89 DF E8 ?? ?? ?? ?? 85 C0 74 14 48 8B 43 08 44 89 E6 }
	condition:
		$pattern
}

rule __GI_statvfs_7b3c47063842b7177a64ae9fedf9f737 {
	meta:
		aliases = "statvfs64, statvfs, __GI_statvfs"
		size = "658"
		objfiles = "statvfs64@libc.a, statvfs@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 55 48 89 FD 53 48 89 F3 48 81 EC D0 05 00 00 48 8D B4 24 20 05 00 00 E8 ?? ?? ?? ?? 83 CA FF 85 C0 0F 88 53 02 00 00 48 8B 84 24 28 05 00 00 48 63 94 24 58 05 00 00 48 8D 7B 58 31 F6 48 89 03 48 89 43 08 48 8B 84 24 30 05 00 00 48 89 43 10 48 8B 84 24 38 05 00 00 48 89 43 18 48 8B 84 24 40 05 00 00 48 89 43 20 48 8B 84 24 48 05 00 00 48 89 43 28 48 8B 84 24 50 05 00 00 48 89 43 30 48 63 84 24 5C 05 00 00 48 C1 E0 20 48 09 C2 48 8B 84 24 60 05 00 00 48 89 53 40 BA 18 00 00 00 48 89 43 50 E8 ?? ?? ?? ?? 48 8B 43 30 48 8D B4 24 90 04 00 00 48 C7 43 48 00 00 00 00 48 89 EF 48 89 }
	condition:
		$pattern
}

rule __ieee754_remainder_f18a831d8ccebf0538859d6ab0b78f6f {
	meta:
		aliases = "__ieee754_remainder"
		size = "339"
		objfiles = "e_remainder@libm.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 55 53 48 83 EC 30 F2 0F 11 4C 24 28 48 8B 44 24 28 F2 0F 11 44 24 08 48 8B 54 24 08 41 89 C4 48 89 D1 41 89 D5 48 89 C2 48 C1 EA 20 48 C1 E9 20 89 D5 81 E5 FF FF FF 7F 89 E8 44 09 E0 75 06 F2 0F 59 C1 EB 2C 89 CB 41 89 CE 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7F 13 81 FD FF FF EF 7F 7E 1A 8D 85 00 00 10 80 44 09 E0 74 0F F2 0F 59 44 24 28 F2 0F 5E C0 E9 C6 00 00 00 81 FD FF FF DF 7F 7F 0F 66 0F 12 4C 24 28 F2 0F 58 C9 E8 ?? ?? ?? ?? 29 EB 45 29 E5 44 09 EB 75 0D F2 0F 59 05 ?? ?? ?? ?? E9 98 00 00 00 E8 ?? ?? ?? ?? 0F 28 C8 66 0F 12 44 24 28 F2 0F 11 4C 24 10 E8 ?? ?? ?? ?? 81 }
	condition:
		$pattern
}

rule __udivti3_5b02f88e4e8d05f75f6136904892a64f {
	meta:
		aliases = "__udivti3"
		size = "1378"
		objfiles = "_udivdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 55 53 48 89 74 24 F8 48 89 4C 24 E8 48 8B 74 24 E8 48 89 7C 24 F0 48 89 54 24 E0 4C 8B 5C 24 F0 48 8B 7C 24 E0 4C 8B 44 24 F8 48 85 F6 0F 85 EB 00 00 00 4C 39 C7 0F 86 8F 02 00 00 B9 38 00 00 00 48 89 FA 48 D3 EA 84 D2 75 09 48 83 E9 08 75 F0 48 89 FA 48 8B 05 ?? ?? ?? ?? 0F B6 04 10 BA 40 00 00 00 48 8D 04 01 48 29 C2 48 89 D0 0F 85 6E 04 00 00 48 89 FE 31 D2 4C 89 C0 48 C1 EE 20 48 89 FB 48 F7 F6 83 E3 FF 31 D2 49 89 D9 4C 0F AF C8 49 89 C2 4C 89 C0 48 F7 F6 4C 89 D8 48 C1 E8 20 48 C1 E2 20 48 09 D0 49 39 C1 76 14 48 01 F8 49 FF CA 48 39 C7 77 09 49 39 C1 0F 87 70 04 00 00 }
	condition:
		$pattern
}

rule svc_run_5c7f423553bbe7c59bad945c8607e614 {
	meta:
		aliases = "svc_run"
		size = "213"
		objfiles = "svc_run@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 55 53 E8 ?? ?? ?? ?? 8B 18 49 89 C6 85 DB 75 0F E8 ?? ?? ?? ?? 48 83 38 00 0F 84 A7 00 00 00 48 63 FB 45 31 ED 48 C1 E7 03 E8 ?? ?? ?? ?? 48 89 C5 EB 33 E8 ?? ?? ?? ?? 48 8B 10 49 63 DD 41 FF C5 48 C1 E3 03 4C 8D 64 1D 00 8B 14 1A 41 89 14 24 48 8B 00 66 41 C7 44 24 06 00 00 8B 44 18 04 66 41 89 44 24 04 41 8B 06 41 39 C5 7C C5 48 63 F0 83 CA FF 48 89 EF E8 ?? ?? ?? ?? 83 F8 FF 89 C6 74 06 85 C0 74 32 EB 28 48 89 EF E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 38 04 0F 84 63 FF FF FF 5B 5D 41 5C 41 5D 41 5E BF ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? E9 }
	condition:
		$pattern
}

rule fstatvfs_829b77d2dde211c47259bd19112ec049 {
	meta:
		aliases = "fstatvfs64, fstatvfs"
		size = "656"
		objfiles = "fstatvfs64@libc.a, fstatvfs@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 55 89 FD 53 48 89 F3 48 81 EC D0 05 00 00 48 8D B4 24 20 05 00 00 E8 ?? ?? ?? ?? 83 CA FF 85 C0 0F 88 52 02 00 00 48 8B 84 24 28 05 00 00 48 63 94 24 58 05 00 00 48 8D 7B 58 31 F6 48 89 03 48 89 43 08 48 8B 84 24 30 05 00 00 48 89 43 10 48 8B 84 24 38 05 00 00 48 89 43 18 48 8B 84 24 40 05 00 00 48 89 43 20 48 8B 84 24 48 05 00 00 48 89 43 28 48 8B 84 24 50 05 00 00 48 89 43 30 48 63 84 24 5C 05 00 00 48 C1 E0 20 48 09 C2 48 8B 84 24 60 05 00 00 48 89 53 40 BA 18 00 00 00 48 89 43 50 E8 ?? ?? ?? ?? 48 8B 43 30 48 8D B4 24 90 04 00 00 48 C7 43 48 00 00 00 00 89 EF 48 89 43 38 }
	condition:
		$pattern
}

rule authunix_refresh_f46d1363507c182061fda52a9c05748c {
	meta:
		aliases = "authunix_refresh"
		size = "235"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 45 31 ED 41 54 55 48 89 FD 53 48 83 EC 70 48 8B 5F 40 48 8B 43 08 48 39 47 08 0F 84 B7 00 00 00 48 FF 43 30 48 C7 44 24 38 00 00 00 00 4C 8D 74 24 30 48 C7 44 24 50 00 00 00 00 8B 53 10 B9 01 00 00 00 48 8B 73 08 48 89 E7 E8 ?? ?? ?? ?? 4C 89 F6 48 89 E7 E8 ?? ?? ?? ?? 85 C0 74 52 48 8D 7C 24 60 31 F6 E8 ?? ?? ?? ?? 48 8B 44 24 60 31 F6 48 89 E7 C7 04 24 00 00 00 00 48 89 44 24 30 48 8B 44 24 08 FF 50 28 4C 89 F6 48 89 E7 E8 ?? ?? ?? ?? 85 C0 41 89 C5 74 16 FC B9 06 00 00 00 48 89 EF 48 89 DE F3 A5 48 89 EF E8 CA FE FF FF 48 8D 74 24 30 48 89 E7 C7 04 24 02 00 00 00 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_svc_getreqset_dbec560535f503f0a6d6e646ad618543 {
	meta:
		aliases = "svc_getreqset, __GI_svc_getreqset"
		size = "90"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 45 31 ED 41 54 55 53 48 89 FB 49 89 DC E8 ?? ?? ?? ?? 41 89 C6 EB 31 41 8B 2C 24 EB 16 41 8D 7C 1D FF E8 ?? ?? ?? ?? 8D 4B FF B8 01 00 00 00 D3 E0 31 C5 89 EF E8 ?? ?? ?? ?? 85 C0 89 C3 75 DD 49 83 C4 04 41 83 C5 20 45 39 F5 7C CA 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule seekdir_9ace79e43e0cd385341ebdf68a71f1ae {
	meta:
		aliases = "seekdir"
		size = "102"
		objfiles = "seekdir@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 49 89 F5 BE ?? ?? ?? ?? 41 54 4C 8D 67 30 53 4C 89 E2 48 89 FB 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? 8B 3B 4C 89 EE 31 D2 E8 ?? ?? ?? ?? 48 C7 43 08 00 00 00 00 48 89 43 20 BE 01 00 00 00 48 C7 43 10 00 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 83 C4 28 5B 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule writeunix_40e8701bfdbd9e28cf32c07eb60cc0d2 {
	meta:
		aliases = "writeunix"
		size = "258"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 49 89 FD 41 54 41 89 D4 55 48 89 F5 53 89 D3 48 83 EC 60 E9 CE 00 00 00 45 8B 75 00 E8 ?? ?? ?? ?? 89 44 24 50 E8 ?? ?? ?? ?? 89 44 24 54 E8 ?? ?? ?? ?? 48 8D 74 24 50 BA 0C 00 00 00 BF ?? ?? ?? ?? 89 44 24 58 E8 ?? ?? ?? ?? 48 63 C3 C7 05 ?? ?? ?? ?? 01 00 00 00 C7 05 ?? ?? ?? ?? 02 00 00 00 48 89 44 24 48 48 8D 44 24 40 48 C7 05 ?? ?? ?? ?? 1C 00 00 00 48 89 6C 24 40 48 C7 44 24 18 01 00 00 00 48 89 44 24 10 48 C7 04 24 00 00 00 00 C7 44 24 08 00 00 00 00 48 C7 44 24 20 ?? ?? ?? ?? 48 C7 44 24 28 20 00 00 00 C7 44 24 30 00 00 00 00 31 D2 48 89 E6 44 89 F7 E8 ?? ?? ?? ?? 85 C0 79 }
	condition:
		$pattern
}

rule writetcp_62fbc3b2dcb51a7eda8078c00264b270 {
	meta:
		aliases = "writetcp"
		size = "91"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 49 89 FD 41 54 41 89 D4 55 48 89 F5 53 89 D3 EB 36 41 8B 7D 00 48 63 D3 48 89 EE E8 ?? ?? ?? ?? 83 F8 FF 49 89 C6 75 18 E8 ?? ?? ?? ?? 8B 00 45 89 F4 41 C7 45 30 03 00 00 00 41 89 45 38 EB 0B 29 C3 48 98 48 01 C5 85 DB 7F C6 5B 5D 44 89 E0 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule __parsegrent_60f397b5bd983fc1306f1f3f3de44944 {
	meta:
		aliases = "__parsegrent"
		size = "271"
		objfiles = "__parsegrent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 49 89 FD 41 54 55 31 ED 53 48 89 F3 48 83 EC 10 4C 8B 37 48 63 C5 83 FD 01 0F B6 80 ?? ?? ?? ?? 4D 8D 64 05 00 7F 25 49 89 1C 24 BE 3A 00 00 00 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 0F 84 BC 00 00 00 48 8D 58 01 FF C5 C6 00 00 EB C7 48 8D 74 24 08 BA 0A 00 00 00 48 89 DF E8 ?? ?? ?? ?? 41 89 04 24 48 8B 4C 24 08 48 39 D9 0F 84 8D 00 00 00 80 39 3A 0F 85 84 00 00 00 80 79 01 00 BE 01 00 00 00 74 33 C6 01 2C 80 39 2C 75 23 C6 01 00 48 FF C1 8A 01 84 C0 74 65 3C 2C 74 61 48 0F BE D0 48 8B 05 ?? ?? ?? ?? F6 04 50 20 75 50 FF C6 48 FF C1 80 39 00 75 D0 48 8D 51 08 48 63 C6 48 83 E2 F8 48 8D }
	condition:
		$pattern
}

rule __GI_getenv_87a0e84363f03f18e389588d53c1f6be {
	meta:
		aliases = "getenv, __GI_getenv"
		size = "92"
		objfiles = "getenv@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 49 89 FD 41 54 55 48 8B 2D ?? ?? ?? ?? 53 48 85 ED 74 3A E8 ?? ?? ?? ?? 41 89 C6 EB 27 4D 63 E6 48 89 DE 4C 89 EF 4C 89 E2 E8 ?? ?? ?? ?? 85 C0 75 0E 4A 8D 04 23 80 38 3D 75 05 48 FF C0 EB 0F 48 83 C5 08 48 8B 5D 00 48 85 DB 75 D0 31 C0 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule __ieee754_lgamma_r_101a169283668344e7d69293b4ad9407 {
	meta:
		aliases = "__ieee754_lgamma_r"
		size = "2047"
		objfiles = "e_lgamma_r@libm.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 49 89 FD 41 54 55 53 48 83 EC 50 F2 0F 11 44 24 38 48 8B 44 24 38 C7 07 01 00 00 00 49 89 C6 49 C1 EE 20 44 89 F5 81 E5 FF FF FF 7F 81 FD FF FF EF 7F 7E 0C 0F 28 E8 F2 0F 59 E8 E9 AB 07 00 00 41 89 C4 89 E8 44 09 E0 74 52 81 FD FF FF 8F 3B 7F 36 45 85 F6 79 16 C7 07 FF FF FF FF 66 0F 12 44 24 38 66 0F 57 05 ?? ?? ?? ?? EB 06 66 0F 12 44 24 38 E8 ?? ?? ?? ?? 0F 28 E8 66 0F 57 2D ?? ?? ?? ?? E9 63 07 00 00 45 85 F6 78 07 31 DB E9 FA 01 00 00 81 FD FF FF 2F 43 7E 15 66 0F 12 2D ?? ?? ?? ?? F2 0F 5E 2D ?? ?? ?? ?? E9 3A 07 00 00 48 8B 44 24 38 48 C1 E8 20 89 C3 81 E3 FF FF FF 7F 81 FB }
	condition:
		$pattern
}

rule dladdr_648961442adab6dca736310531f0eeb4 {
	meta:
		aliases = "dladdr"
		size = "254"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 49 89 FD 41 54 55 53 48 89 F3 E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 31 FF EB 1B 48 8B 50 28 4C 39 EA 73 0E 48 85 FF 74 06 48 39 57 28 73 03 48 89 C7 48 8B 40 18 48 85 C0 75 E0 48 85 FF 0F 84 AE 00 00 00 48 8B 47 08 45 31 C9 45 31 F6 45 31 D2 45 31 DB 48 89 03 48 8B 47 28 48 89 43 08 48 8B AF B0 00 00 00 4C 8B A7 A8 00 00 00 EB 4B 48 8B 47 58 44 89 CA 8B 34 90 EB 38 41 89 F0 49 6B C0 18 48 8B 4C 28 08 48 03 0F 4C 39 E9 77 1C 45 85 D2 0F 94 C2 49 39 CB 0F 92 C0 08 C2 74 0C 41 89 F6 49 89 CB 41 BA 01 00 00 00 48 8B 47 78 42 8B 34 80 85 F6 75 C4 41 FF C1 44 3B 4F 50 72 AF 45 85 D2 74 18 }
	condition:
		$pattern
}

rule pmap_set_ecce4ea81149f9ac94f0773e27fa3e62 {
	meta:
		aliases = "__GI_pmap_set, pmap_set"
		size = "255"
		objfiles = "pmap_clnt@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 89 CE 41 55 41 89 D5 41 54 49 89 F4 55 48 89 FD 53 48 83 EC 50 48 8D 5C 24 30 C7 44 24 4C FF FF FF FF 48 89 DF E8 B8 FD FF FF 85 C0 0F 84 BB 00 00 00 48 8B 0D ?? ?? ?? ?? 4C 8B 05 ?? ?? ?? ?? 4C 8D 4C 24 4C 48 89 DF BA 02 00 00 00 BE A0 86 01 00 C7 44 24 08 90 01 00 00 C7 04 24 90 01 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 7F 49 63 C5 48 89 6C 24 10 4C 89 64 24 18 48 89 44 24 20 41 0F B7 C6 48 8D 4C 24 10 48 89 44 24 28 48 8B 05 ?? ?? ?? ?? 4C 8D 4C 24 48 4C 8B 53 08 41 B8 ?? ?? ?? ?? BA ?? ?? ?? ?? BE 01 00 00 00 48 89 DF 48 89 04 24 48 8B 05 ?? ?? ?? ?? 48 89 44 24 08 41 FF 12 85 }
	condition:
		$pattern
}

rule xdr_bytes_c13722e36fe9563f1cc5902c5d747de1 {
	meta:
		aliases = "__GI_xdr_bytes, xdr_bytes"
		size = "177"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 89 CE 41 55 49 89 F5 41 54 49 89 FC 55 48 89 D5 53 48 8B 1E 48 89 D6 E8 ?? ?? ?? ?? 85 C0 74 7C 8B 6D 00 44 39 F5 76 07 41 83 3C 24 02 75 6D 41 8B 04 24 83 F8 01 74 09 72 36 83 F8 02 75 5D EB 44 85 ED 74 5B 48 85 DB 75 26 89 EF E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 49 89 45 00 75 13 48 8B 35 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 2C 48 89 DE 89 EA 4C 89 E7 5B 5D 41 5C 41 5D 41 5E E9 ?? ?? ?? ?? 48 85 DB 74 16 48 89 DF E8 ?? ?? ?? ?? 49 C7 45 00 00 00 00 00 EB 04 31 C0 EB 05 B8 01 00 00 00 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule tcsetattr_b1c7619de8e687283692a3ad4239a01f {
	meta:
		aliases = "__GI_tcsetattr, tcsetattr"
		size = "269"
		objfiles = "tcsetattr@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 89 FE 41 55 41 54 55 53 48 89 D3 48 83 EC 30 83 FE 01 74 10 83 FE 02 74 22 85 F6 BD 02 54 00 00 74 1E EB 07 BD 03 54 00 00 EB 15 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 B9 00 00 00 BD 04 54 00 00 8B 03 48 8D 73 11 48 8D 7C 24 11 BA 13 00 00 00 25 FF FF FF 7F 89 04 24 8B 43 04 89 44 24 04 8B 43 08 89 44 24 08 8B 43 0C 89 44 24 0C 8A 43 10 88 44 24 10 E8 ?? ?? ?? ?? 31 C0 48 89 E2 48 89 EE 44 89 F7 E8 ?? ?? ?? ?? 85 C0 89 C1 0F 94 C2 48 81 FD 02 54 00 00 0F 94 C0 84 D0 74 5D E8 ?? ?? ?? ?? BE 01 54 00 00 44 8B 20 48 89 C5 48 89 E2 31 C0 44 89 F7 E8 ?? ?? ?? ?? 85 C0 74 06 44 89 65 00 EB 34 }
	condition:
		$pattern
}

rule sigqueue_e6c2d6292e87478751f61762a024ef4a {
	meta:
		aliases = "sigqueue"
		size = "132"
		objfiles = "sigqueue@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 89 FE 41 55 49 89 D5 BA 80 00 00 00 41 54 41 89 F4 31 F6 53 48 81 EC 88 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 44 89 24 24 C7 44 24 08 FF FF FF FF E8 ?? ?? ?? ?? 89 44 24 10 E8 ?? ?? ?? ?? 49 63 F4 89 44 24 14 4C 89 6C 24 18 48 89 E2 49 63 FE B8 81 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 81 C4 88 00 00 00 89 D8 5B 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule error_at_line_6e66dbf141a49916dcacda74af88b79e {
	meta:
		aliases = "__error_at_line, error_at_line"
		size = "423"
		objfiles = "error@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 89 FE 41 55 4D 89 C5 41 54 41 89 F4 55 89 CD 53 48 89 D3 0F B6 D0 48 8D 04 95 00 00 00 00 BA ?? ?? ?? ?? 48 81 EC D0 00 00 00 48 29 C2 48 8D 84 24 CF 00 00 00 4C 89 4C 24 48 FF E2 0F 29 78 F1 0F 29 70 E1 0F 29 68 D1 0F 29 60 C1 0F 29 58 B1 0F 29 50 A1 0F 29 48 91 0F 29 40 81 83 3D ?? ?? ?? ?? 00 74 35 39 0D ?? ?? ?? ?? 75 20 48 8B 3D ?? ?? ?? ?? 48 39 FB 0F 84 17 01 00 00 48 89 DE E8 ?? ?? ?? ?? 85 C0 0F 84 07 01 00 00 48 89 1D ?? ?? ?? ?? 89 2D ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 04 FF D0 EB 1A 48 8B 15 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? BE }
	condition:
		$pattern
}

rule pread_3a6bb03e40ba3b9614bb4ea107551310 {
	meta:
		aliases = "pwrite, pread64, pread"
		size = "84"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 89 FE BF 01 00 00 00 41 55 49 89 F5 41 54 49 89 D4 53 48 89 CB 48 83 EC 18 48 8D 74 24 14 E8 ?? ?? ?? ?? 48 89 D9 4C 89 E2 4C 89 EE 44 89 F7 E8 ?? ?? ?? ?? 8B 7C 24 14 48 89 C3 31 F6 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 18 5B 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule send_1e8120eeef72e7c40dddea4a05683146 {
	meta:
		aliases = "recv, send"
		size = "82"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 89 FE BF 01 00 00 00 41 55 49 89 F5 41 54 49 89 D4 53 89 CB 48 83 EC 18 48 8D 74 24 14 E8 ?? ?? ?? ?? 89 D9 4C 89 E2 4C 89 EE 44 89 F7 E8 ?? ?? ?? ?? 8B 7C 24 14 48 89 C3 31 F6 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 18 5B 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule makefd_xprt_45f5f2a9357a3d9358c72c3366cb366e {
	meta:
		aliases = "makefd_xprt"
		size = "197"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 89 FE BF 50 01 00 00 41 55 41 89 F5 41 54 41 89 D4 55 53 E8 ?? ?? ?? ?? BF D0 01 00 00 48 89 C3 E8 ?? ?? ?? ?? 48 85 DB 48 89 C5 0F 94 C2 48 85 C0 0F 94 C0 08 C2 74 25 48 8B 35 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 DF 31 DB E8 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? EB 59 48 8D 7D 10 41 B9 ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? 48 89 D9 44 89 E2 44 89 EE C7 45 00 02 00 00 00 E8 ?? ?? ?? ?? 48 8D 45 40 48 C7 43 48 00 00 00 00 48 89 6B 40 C7 43 10 00 00 00 00 48 C7 43 08 ?? ?? ?? ?? 48 89 DF 48 89 43 30 66 C7 43 04 00 00 44 89 33 E8 ?? ?? ?? ?? 48 89 D8 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule __GI_sgetspent_r_a0c2f17ef8f95076a07c053c3370a3ea {
	meta:
		aliases = "sgetspent_r, __GI_sgetspent_r"
		size = "111"
		objfiles = "sgetspent_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 48 81 F9 FF 00 00 00 49 89 F6 49 C7 00 00 00 00 00 41 55 4D 89 C5 41 54 49 89 CC 55 48 89 D5 53 48 89 FB 77 12 E8 ?? ?? ?? ?? C7 00 22 00 00 00 B8 22 00 00 00 EB 2D 48 39 D7 74 15 E8 ?? ?? ?? ?? 4C 39 E0 73 DF 48 89 DE 48 89 EF E8 ?? ?? ?? ?? 48 89 EE 4C 89 F7 E8 ?? ?? ?? ?? 85 C0 75 04 4D 89 75 00 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule ___path_search_ee23b29016b4a021ba26eaad59f78c68 {
	meta:
		aliases = "___path_search"
		size = "219"
		objfiles = "tempname@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 48 85 C9 49 89 FE 41 55 49 89 F5 41 54 49 89 CC 55 53 48 89 D3 74 1D 80 39 00 74 18 48 89 CF E8 ?? ?? ?? ?? 48 83 F8 05 48 89 C5 76 12 BD 05 00 00 00 EB 0B BD 04 00 00 00 41 BC ?? ?? ?? ?? 48 85 DB 75 3B BF ?? ?? ?? ?? BB ?? ?? ?? ?? E8 51 FD FF FF 85 C0 75 28 48 89 DE 48 89 DF E8 ?? ?? ?? ?? 85 C0 74 0C 48 89 DF E8 36 FD FF FF 85 C0 75 0D E8 ?? ?? ?? ?? C7 00 02 00 00 00 EB 32 48 89 DF E8 ?? ?? ?? ?? 48 89 C2 EB 03 48 FF CA 48 83 FA 01 76 07 80 7C 13 FF 2F 74 F0 48 8D 44 2A 08 49 39 C5 73 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 1A 4D 89 E1 49 89 E8 48 89 D9 BE ?? ?? ?? ?? 4C 89 }
	condition:
		$pattern
}

rule __GI_pthread_setschedparam_51d21eae837b982e1a429fe9d8c79320 {
	meta:
		aliases = "pthread_setschedparam, __GI_pthread_setschedparam"
		size = "162"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 56 48 89 F8 49 89 D6 25 FF 03 00 00 41 55 48 C1 E0 05 41 89 F5 31 F6 41 54 49 89 FC 55 48 8D A8 ?? ?? ?? ?? 53 48 89 EF E8 ?? ?? ?? ?? 48 8B 5D 10 48 85 DB 74 06 4C 39 63 20 74 0F 48 89 EF E8 ?? ?? ?? ?? B8 03 00 00 00 EB 4D 8B 7B 28 4C 89 F2 44 89 EE E8 ?? ?? ?? ?? FF C0 75 11 48 89 EF E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 00 EB 2A 31 C0 45 85 ED 74 03 41 8B 06 89 43 2C 48 89 EF E8 ?? ?? ?? ?? 31 C0 83 3D ?? ?? ?? ?? 00 78 0A 8B 7B 2C E8 ?? ?? ?? ?? 31 C0 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule xdr_reference_e389ec92d003100ccc5d4c167585a0d0 {
	meta:
		aliases = "__GI_xdr_reference, xdr_reference"
		size = "149"
		objfiles = "xdr_reference@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 CE 41 55 49 89 F5 41 54 49 89 FC 55 89 D5 53 48 8B 1E 48 85 DB 75 48 8B 07 83 F8 01 74 0C 83 F8 02 BD 01 00 00 00 74 5E EB 35 89 D7 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 49 89 45 00 75 15 48 8B 35 ?? ?? ?? ?? BF ?? ?? ?? ?? 31 ED E8 ?? ?? ?? ?? EB 34 48 63 D5 31 F6 48 89 C7 E8 ?? ?? ?? ?? 83 CA FF 31 C0 48 89 DE 4C 89 E7 41 FF D6 41 83 3C 24 02 89 C5 75 10 48 89 DF E8 ?? ?? ?? ?? 49 C7 45 00 00 00 00 00 5B 89 E8 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule getprotoent_r_eaa461dd2cee8c6aac93bb96705f1ee7 {
	meta:
		aliases = "__GI_getprotoent_r, getprotoent_r"
		size = "467"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 CE 41 55 49 89 FD 41 54 49 89 F4 55 53 48 89 D3 48 83 EC 20 48 81 FA 17 01 00 00 48 C7 01 00 00 00 00 77 15 BB 22 00 00 00 E8 ?? ?? ?? ?? C7 00 22 00 00 00 E9 87 01 00 00 48 89 E7 BA ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 49 8D AC 24 18 01 00 00 E8 ?? ?? ?? ?? 48 8D 83 E8 FE FF FF 48 3D 00 10 00 00 77 15 BB 22 00 00 00 E8 ?? ?? ?? ?? C7 00 22 00 00 00 E9 32 01 00 00 48 83 3D ?? ?? ?? ?? 00 75 31 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 75 16 E8 ?? ?? ?? ?? 8B 18 E9 01 01 00 00 BB 02 00 00 00 E9 F7 00 00 00 48 8B 15 ?? ?? ?? ?? BE }
	condition:
		$pattern
}

rule __get_hosts_byaddr_r_843765afbfd4bbd6f3bfe8480a75db7d {
	meta:
		aliases = "__get_hosts_byaddr_r"
		size = "138"
		objfiles = "get_hosts_byaddr_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 CE 41 55 4D 89 C5 41 54 4D 89 CC 55 89 D5 53 48 83 EC 50 83 FA 02 74 07 83 FA 0A 75 5A EB 05 83 FE 04 EB 03 83 FE 10 75 4E 48 8D 5C 24 20 48 89 FE B9 2E 00 00 00 89 EF 48 89 DA E8 ?? ?? ?? ?? 48 8B 84 24 88 00 00 00 4D 89 E9 4D 89 F0 B9 02 00 00 00 89 EA 48 89 DE 31 FF 4C 89 24 24 48 89 44 24 10 48 8B 84 24 80 00 00 00 48 89 44 24 08 E8 ?? ?? ?? ?? EB 02 31 C0 48 83 C4 50 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule pthread_cond_timedwait_71d765c4204d750a2186b8b8462f471c {
	meta:
		aliases = "__GI_pthread_cond_timedwait, pthread_cond_timedwait"
		size = "458"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 D6 41 55 41 54 49 89 F4 55 48 89 FD 53 48 83 EC 20 E8 57 FF FF FF 48 89 44 24 18 41 8B 44 24 10 83 F8 03 0F 95 C2 85 C0 0F 95 C0 84 D0 74 15 48 8B 44 24 18 49 39 44 24 08 BA 16 00 00 00 0F 85 73 01 00 00 48 8B 44 24 18 48 89 2C 24 48 89 E6 48 C7 44 24 08 ?? ?? ?? ?? C6 80 D1 02 00 00 00 48 8B 7C 24 18 E8 6E FE FF FF 48 8B 74 24 18 48 89 EF E8 ?? ?? ?? ?? 48 8B 44 24 18 80 78 7A 00 74 10 48 8B 44 24 18 BB 01 00 00 00 80 78 78 00 74 10 48 8B 74 24 18 48 8D 7D 10 31 DB E8 A4 FD FF FF 48 89 EF E8 ?? ?? ?? ?? 85 DB 74 11 48 8B 7C 24 18 31 F6 E8 1E FE FF FF E9 B4 00 00 00 4C 89 E7 45 31 }
	condition:
		$pattern
}

rule _dl_add_elf_hash_table_506293f6c99d164ed1e5128a9f169750 {
	meta:
		aliases = "_dl_add_elf_hash_table"
		size = "256"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 D6 41 55 49 89 CD 41 54 49 89 FC 55 48 89 F5 53 48 8B 1D ?? ?? ?? ?? 48 85 DB 75 2F BF C8 01 00 00 E8 ?? ?? ?? ?? BA C8 01 00 00 48 89 C3 48 89 05 ?? ?? ?? ?? EB 06 C6 00 00 48 FF C0 48 FF CA 48 83 FA FF 75 F1 EB 3B 48 89 C3 48 8B 43 18 48 85 C0 75 F4 BF C8 01 00 00 E8 ?? ?? ?? ?? BA C8 01 00 00 48 89 43 18 EB 06 C6 00 00 48 FF C0 48 FF CA 48 83 FA FF 75 F1 48 8B 43 18 48 89 58 20 48 89 C3 48 C7 43 18 00 00 00 00 66 C7 43 42 00 00 4C 89 E7 E8 ?? ?? ?? ?? 4C 89 6B 10 48 89 43 08 C7 43 30 03 00 00 00 49 8B 56 20 48 85 D2 74 1E 8B 02 89 43 50 8B 42 04 48 83 C2 08 48 89 53 58 89 43 70 }
	condition:
		$pattern
}

rule __pthread_alt_timedlock_bd066e6ee98ed01b43b4021855340e77 {
	meta:
		aliases = "__pthread_alt_timedlock"
		size = "237"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 D6 41 55 49 89 F5 41 54 45 31 E4 55 48 89 FD BF ?? ?? ?? ?? 53 48 83 EC 10 E8 84 FC FF FF 48 8B 3D ?? ?? ?? ?? 48 85 FF 74 0D 48 8B 07 49 89 FC 48 89 05 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 4D 85 E4 75 1F BF 18 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 49 89 C4 75 0D 4C 89 EE 48 89 EF E8 ?? ?? ?? ?? EB 72 48 8B 5D 00 BA 01 00 00 00 48 85 DB 74 15 4D 85 ED 75 08 E8 7B FD FF FF 49 89 C5 4D 89 6C 24 08 4C 89 E2 41 C7 44 24 10 00 00 00 00 49 89 1C 24 48 89 D8 F0 48 0F B1 55 00 0F 94 C2 84 D2 74 C0 48 85 DB 74 25 4C 89 F6 4C 89 EF E8 ?? ?? ?? ?? 85 C0 75 16 B0 01 41 87 44 24 10 31 D2 48 85 }
	condition:
		$pattern
}

rule __stdio_WRITE_108589266ba290b869d9083fd75d13a1 {
	meta:
		aliases = "__stdio_WRITE"
		size = "147"
		objfiles = "_WRITE@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 D6 41 55 49 89 F5 41 54 55 48 89 FD 53 48 89 D3 48 83 FB 00 74 6D 8B 7D 04 48 BA FF FF FF FF FF FF FF 7F 4C 89 EE 48 0F 4D D3 49 89 DC E8 ?? ?? ?? ?? 48 85 C0 78 08 48 29 C3 49 01 C5 EB D1 48 8B 55 08 48 8B 45 10 66 83 4D 00 08 48 29 D0 74 2F 48 39 D8 4C 0F 46 E0 41 8A 45 00 3C 0A 88 02 75 06 F6 45 01 01 75 0D 48 FF C2 49 FF CC 74 05 49 FF C5 EB E3 48 89 55 18 48 2B 55 08 48 29 D3 49 29 DE 5B 5D 41 5C 41 5D 4C 89 F0 41 5E C3 }
	condition:
		$pattern
}

rule __GI_xdr_union_303f71a56feda0238f6d3bb24a25b9fd {
	meta:
		aliases = "xdr_union, __GI_xdr_union"
		size = "112"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 D6 41 55 4D 89 C5 41 54 49 89 F4 55 48 89 FD 53 48 89 CB E8 ?? ?? ?? ?? 85 C0 74 45 41 8B 04 24 EB 18 39 03 75 10 83 CA FF 4C 89 F6 48 89 EF 31 C0 49 89 CB EB 20 48 83 C3 10 48 8B 4B 08 48 85 C9 75 DF 4D 85 ED 74 19 83 CA FF 4C 89 F6 48 89 EF 31 C0 4D 89 EB 5B 5D 41 5C 41 5D 41 5E 41 FF E3 5B 5D 41 5C 41 5D 41 5E 31 C0 C3 }
	condition:
		$pattern
}

rule getgrouplist_4464b00c28f3d286972425778b96b1e9 {
	meta:
		aliases = "getgrouplist"
		size = "108"
		objfiles = "getgrouplist@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 D6 48 89 CA 41 55 41 89 F5 41 54 49 89 CC 55 53 8B 19 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 75 0E 85 DB 74 37 BB 01 00 00 00 45 89 2E EB 30 41 39 1C 24 41 0F 4E 1C 24 85 DB 74 12 48 63 D3 48 89 C6 4C 89 F7 48 C1 E2 02 E8 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 41 3B 1C 24 7D 03 83 CB FF 89 D8 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule xdrrec_putbytes_049e4778212f202da9ed86c6deb8595c {
	meta:
		aliases = "xdrrec_putbytes"
		size = "119"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 41 54 41 89 D4 55 53 48 8B 6F 18 EB 50 48 8B 7D 20 48 8B 5D 28 4C 89 F6 29 FB 44 39 E3 41 0F 47 DC 41 89 DD 4C 89 EA E8 ?? ?? ?? ?? 4C 01 6D 20 48 8B 45 28 48 39 45 20 0F 94 C2 41 29 DC 0F 95 C0 84 D0 74 15 31 F6 C7 45 38 01 00 00 00 48 89 EF E8 B6 FB FF FF 85 C0 74 0D 4D 01 EE 45 85 E4 75 AB B8 01 00 00 00 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule readtcp_b66e9938f8288fc2baabccf76d790195 {
	meta:
		aliases = "readtcp"
		size = "206"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 41 54 41 89 D4 BA E8 03 00 00 48 89 D6 55 31 ED 53 48 89 FB 48 83 EC 10 48 8B 47 10 48 69 4F 08 E8 03 00 00 48 99 48 F7 FE 45 85 E4 44 8D 2C 01 0F 84 84 00 00 00 8B 07 66 C7 44 24 04 01 00 89 04 24 48 89 E7 44 89 EA BE 01 00 00 00 E8 ?? ?? ?? ?? 83 F8 FF 89 C5 74 0D 85 C0 75 21 C7 43 30 05 00 00 00 EB 3E E8 ?? ?? ?? ?? 83 38 04 74 D2 C7 43 30 04 00 00 00 8B 00 89 43 38 EB 3C 8B 3B 49 63 D4 4C 89 F6 E8 ?? ?? ?? ?? 83 F8 FF 89 C5 74 17 85 C0 75 24 C7 43 38 68 00 00 00 C7 43 30 04 00 00 00 83 CD FF EB 11 E8 ?? ?? ?? ?? 8B 00 C7 43 30 04 00 00 00 89 43 38 5A 59 5B 89 E8 5D 41 }
	condition:
		$pattern
}

rule __md5_Update_e98534d7dc56b11071e14ea2ab72274f {
	meta:
		aliases = "__md5_Update"
		size = "168"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 41 89 D5 42 8D 14 ED 00 00 00 00 41 54 55 48 89 FD 53 8B 47 10 89 C1 01 D0 C1 E9 03 89 47 10 83 E1 3F 39 D0 73 03 FF 47 14 41 BC 40 00 00 00 44 89 E8 31 DB 41 29 CC C1 E8 1D 01 45 14 45 39 E5 72 40 48 8D 5D 18 89 CF 44 89 E2 4C 89 F6 48 8D 3C 3B E8 ?? ?? ?? ?? 48 89 DE 48 89 EF 44 89 E3 E8 33 FE FF FF EB 11 89 DE 48 89 EF 83 C3 40 49 8D 34 36 E8 20 FE FF FF 8D 43 3F 44 39 E8 72 E7 31 C9 44 89 EA 89 DE 89 C8 29 DA 48 8D 7C 05 18 49 8D 34 36 5B 5D 41 5C 41 5D 41 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule readunix_5a215b2a835a93bdbfbca2d3e1f7f054 {
	meta:
		aliases = "readunix"
		size = "398"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 41 89 D5 BA E8 03 00 00 41 54 55 48 89 FD 53 48 89 D3 48 83 EC 60 48 8B 47 10 48 69 4F 08 E8 03 00 00 48 99 48 F7 FB 66 31 DB 45 85 ED 44 8D 24 01 0F 84 41 01 00 00 8B 07 66 C7 44 24 54 01 00 89 44 24 50 48 8D 7C 24 50 44 89 E2 BE 01 00 00 00 E8 ?? ?? ?? ?? 83 F8 FF 89 C3 74 13 85 C0 75 30 C7 85 90 00 00 00 05 00 00 00 E9 EC 00 00 00 E8 ?? ?? ?? ?? 83 38 04 74 CA C7 85 90 00 00 00 04 00 00 00 8B 00 89 85 98 00 00 00 E9 E7 00 00 00 44 8B 65 00 49 63 C5 48 8D 4C 24 5C 48 89 44 24 48 48 8D 44 24 40 41 B8 04 00 00 00 BA 10 00 00 00 BE 01 00 00 00 4C 89 74 24 40 44 89 E7 48 89 }
	condition:
		$pattern
}

rule __GI_vsscanf_17a24295c755c845701a15690ff11a72 {
	meta:
		aliases = "vsscanf, __GI_vsscanf"
		size = "149"
		objfiles = "vsscanf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 49 89 D5 41 54 53 48 89 FB 48 81 EC 88 00 00 00 48 8D 7C 24 58 C7 44 24 04 FE FF FF FF 66 C7 04 24 A1 00 C6 44 24 02 00 C7 44 24 48 00 00 00 00 C7 44 24 50 01 00 00 00 E8 ?? ?? ?? ?? 48 89 DF 48 89 5C 24 18 48 89 5C 24 08 48 C7 44 24 38 00 00 00 00 E8 ?? ?? ?? ?? 48 03 44 24 08 4C 89 EA 4C 89 F6 48 89 E7 48 89 5C 24 30 48 89 44 24 10 48 89 44 24 20 48 89 44 24 28 E8 ?? ?? ?? ?? 48 81 C4 88 00 00 00 5B 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule vfwprintf_1b4a0da9ac32c6f2ec2007e197f5ab98 {
	meta:
		aliases = "__GI_vfwprintf, vfwprintf"
		size = "143"
		objfiles = "vfwprintf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 49 89 D5 41 54 55 48 89 FD 53 48 83 EC 20 44 8B 67 50 45 85 E4 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 0F B7 45 00 25 40 08 00 00 3D 40 08 00 00 74 14 BE 00 08 00 00 48 89 EF 83 CB FF E8 ?? ?? ?? ?? 85 C0 75 10 4C 89 EA 4C 89 F6 48 89 EF E8 ?? ?? ?? ?? 89 C3 45 85 E4 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 89 D8 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule vfprintf_d74aac8cb36809fa0560bd57df21c0c9 {
	meta:
		aliases = "__GI_vfprintf, vfprintf"
		size = "143"
		objfiles = "vfprintf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 49 89 D5 41 54 55 48 89 FD 53 48 83 EC 20 44 8B 67 50 45 85 E4 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 0F B7 45 00 25 C0 00 00 00 3D C0 00 00 00 74 14 BE 80 00 00 00 48 89 EF 83 CB FF E8 ?? ?? ?? ?? 85 C0 75 10 4C 89 EA 4C 89 F6 48 89 EF E8 ?? ?? ?? ?? 89 C3 45 85 E4 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 89 D8 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule pthread_sighandler_ae1c88302ec94e8014f739482a4c71ba {
	meta:
		aliases = "pthread_sighandler"
		size = "107"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 49 89 D5 41 54 55 89 FD 53 E8 3B FF FF FF 80 B8 A8 00 00 00 00 48 89 C3 74 0C C6 80 A8 00 00 00 00 89 68 38 EB 35 4C 8B A0 A0 00 00 00 4D 85 E4 75 07 48 89 A0 A0 00 00 00 48 63 C5 4C 89 EA 4C 89 F6 89 EF FF 14 C5 ?? ?? ?? ?? 4D 85 E4 75 0B 48 C7 83 A0 00 00 00 00 00 00 00 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule pthread_sighandler_rt_fef6cd3116de0bcceb57d7353cf44210 {
	meta:
		aliases = "pthread_sighandler_rt"
		size = "107"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 49 89 D5 41 54 55 89 FD 53 E8 A6 FF FF FF 80 B8 A8 00 00 00 00 48 89 C3 74 0C C6 80 A8 00 00 00 00 89 68 38 EB 35 4C 8B A0 A0 00 00 00 4D 85 E4 75 07 48 89 A0 A0 00 00 00 48 63 C5 4C 89 EA 4C 89 F6 89 EF FF 14 C5 ?? ?? ?? ?? 4D 85 E4 75 0B 48 C7 83 A0 00 00 00 00 00 00 00 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule pthread_join_a9219f0257f58e608578817afd60629f {
	meta:
		aliases = "pthread_join"
		size = "502"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 49 89 FD 41 54 55 53 48 81 EC D0 00 00 00 E8 5C FE FF FF 48 89 84 24 C8 00 00 00 4C 89 E8 48 8B B4 24 C8 00 00 00 25 FF 03 00 00 48 C7 84 24 B8 00 00 00 ?? ?? ?? ?? 48 C1 E0 05 48 8D A8 ?? ?? ?? ?? 48 89 EF 48 89 AC 24 B0 00 00 00 E8 ?? ?? ?? ?? 48 8B 5D 10 48 85 DB 74 06 4C 39 6B 20 74 12 48 89 EF E8 ?? ?? ?? ?? B8 03 00 00 00 E9 6C 01 00 00 48 8B 84 24 C8 00 00 00 48 39 C3 75 12 48 89 EF E8 ?? ?? ?? ?? B8 23 00 00 00 E9 4D 01 00 00 80 7B 51 00 75 07 48 83 7B 68 00 74 12 48 89 EF E8 ?? ?? ?? ?? B8 16 00 00 00 E9 2E 01 00 00 80 7B 50 00 0F 85 CA 00 00 00 48 8B BC 24 C8 00 }
	condition:
		$pattern
}

rule get_input_bytes_bdb8af6e66268725ab7564f452f560f7 {
	meta:
		aliases = "get_input_bytes"
		size = "97"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 49 89 FD 41 54 55 89 D5 53 EB 3D 49 8B 75 58 49 8B 45 60 29 F0 85 C0 75 0E 4C 89 EF E8 DC FD FF FF 85 C0 75 23 EB 2A 39 E8 41 89 EC 4C 89 F7 44 0F 4E E0 49 63 DC 44 29 E5 48 89 DA 49 01 DE E8 ?? ?? ?? ?? 49 01 5D 58 85 ED 7F BF B8 01 00 00 00 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule readdir64_r_1b15cbe64007e0e7a6e6aa375c1d4ddb {
	meta:
		aliases = "readdir_r, __GI_readdir_r, __GI_readdir64_r, readdir64_r"
		size = "217"
		objfiles = "readdir_r@libc.a, readdir64_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 BE ?? ?? ?? ?? 41 55 49 89 D5 41 54 45 31 E4 55 48 89 FD 53 48 8D 5F 30 48 83 EC 20 48 89 DA 48 89 E7 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8B 45 08 48 39 45 10 77 35 48 8B 55 28 48 8B 75 18 8B 7D 00 E8 ?? ?? ?? ?? 48 83 F8 00 7F 13 49 C7 45 00 00 00 00 00 74 52 E8 ?? ?? ?? ?? 8B 18 EB 4B 48 89 45 10 48 C7 45 08 00 00 00 00 48 8B 45 08 49 89 C4 4C 03 65 18 41 0F B7 54 24 10 48 01 D0 48 89 45 08 49 8B 44 24 08 48 89 45 20 49 83 3C 24 00 74 99 41 0F B7 54 24 10 4C 89 E6 4C 89 F7 E8 ?? ?? ?? ?? 49 89 45 00 31 DB 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 4D 85 E4 B8 00 00 00 00 0F }
	condition:
		$pattern
}

rule writeunix_ef476d6994a8c4bcb53874a81dcfb38b {
	meta:
		aliases = "writeunix"
		size = "95"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 FE 41 55 41 89 D5 41 54 49 89 F4 55 89 D5 53 EB 3A 41 8B 3E 48 63 D5 4C 89 E6 E8 14 FF FF FF 83 F8 FF 89 C3 75 1E E8 ?? ?? ?? ?? 8B 00 41 89 DD 41 C7 86 90 00 00 00 03 00 00 00 41 89 86 98 00 00 00 EB 0B 29 C5 48 98 49 01 C4 85 ED 7F C2 5B 5D 41 5C 44 89 E8 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule svc_getreq_poll_fbb42766a832d1c0e9255dc0b0ebf959 {
	meta:
		aliases = "__GI_svc_getreq_poll, svc_getreq_poll"
		size = "115"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 FE 41 55 41 89 F5 41 54 45 31 E4 55 31 ED 53 EB 41 48 63 C5 49 8D 04 C6 8B 18 83 FB FF 74 31 66 8B 40 06 66 85 C0 74 28 41 FF C4 A8 20 74 1A E8 ?? ?? ?? ?? 48 8B 80 E8 00 00 00 48 63 D3 48 8B 3C D0 E8 ?? ?? ?? ?? EB 07 89 DF E8 ?? ?? ?? ?? FF C5 E8 ?? ?? ?? ?? 3B 28 0F 9C C2 45 39 EC 0F 9C C0 84 D0 75 AB 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule fgets_e4126582bb8394683ceec76b3d52a7ff {
	meta:
		aliases = "fgetws, __GI_fgets, fgets"
		size = "109"
		objfiles = "fgets@libc.a, fgetws@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 FE 41 55 41 89 F5 41 54 55 48 89 D5 53 48 83 EC 20 44 8B 62 50 45 85 E4 75 1C 48 8D 5A 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 EA 44 89 EE 4C 89 F7 E8 ?? ?? ?? ?? 45 85 E4 48 89 C3 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 48 89 D8 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule pthread_create_4cb5e9c697087d6e8d96e26ffab4894c {
	meta:
		aliases = "pthread_create"
		size = "178"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 FE 41 55 49 89 CD 41 54 49 89 D4 55 48 89 F5 53 48 81 EC B0 00 00 00 83 3D ?? ?? ?? ?? 00 79 0E E8 ?? ?? ?? ?? 85 C0 BA 0B 00 00 00 78 6E E8 B5 F8 FF FF 48 8D 54 24 28 31 F6 BF 02 00 00 00 48 89 C3 48 89 04 24 C7 44 24 08 00 00 00 00 48 89 6C 24 10 4C 89 64 24 18 4C 89 6C 24 20 E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 48 89 E6 BA A8 00 00 00 E8 ?? ?? ?? ?? 48 FF C0 75 0A E8 ?? ?? ?? ?? 83 38 04 74 DE 48 89 DF E8 39 FA FF FF 83 7B 60 00 75 07 48 8B 43 58 49 89 06 8B 53 60 48 81 C4 B0 00 00 00 89 D0 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule lfind_d2840f5b0fbdbcb1191f05edd54aeced {
	meta:
		aliases = "__GI_lfind, lfind"
		size = "66"
		objfiles = "lfind@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 FE 41 55 49 89 CD 41 54 4D 89 C4 55 48 89 F5 53 8B 1A EB 15 48 89 EE 4C 89 F7 41 FF D4 85 C0 75 05 48 89 EE EB 0C 4C 01 ED FF CB 83 FB FF 75 E4 31 F6 5B 5D 41 5C 41 5D 41 5E 48 89 F0 C3 }
	condition:
		$pattern
}

rule __GI_gethostent_r_40cf1c70c26b8a04ffeb403c8310afb5 {
	meta:
		aliases = "gethostent_r, __GI_gethostent_r"
		size = "206"
		objfiles = "gethostent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 FE 41 55 49 89 F5 BE ?? ?? ?? ?? 41 54 49 89 D4 BA ?? ?? ?? ?? 55 4C 89 C5 53 48 89 CB 48 83 EC 40 48 8D 7C 24 20 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 3D ?? ?? ?? ?? 00 75 1F E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 75 0E 48 C7 03 00 00 00 00 BB 02 00 00 00 EB 4E 48 8B 3D ?? ?? ?? ?? 31 F6 4D 89 E9 4D 89 F0 B9 01 00 00 00 BA 02 00 00 00 48 89 5C 24 08 48 89 6C 24 10 4C 89 24 24 E8 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 89 C3 75 17 48 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 48 8D 7C 24 20 BE 01 00 00 00 E8 ?? ?? ?? ?? 89 D8 48 83 C4 40 5B 5D 41 }
	condition:
		$pattern
}

rule ether_ntohost_a7e0d554cfbf9ed949f4ebefce818b17 {
	meta:
		aliases = "ether_ntohost"
		size = "161"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 FE BF ?? ?? ?? ?? 41 55 49 89 F5 BE ?? ?? ?? ?? 41 54 55 53 83 CB FF 48 81 EC 10 01 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 74 60 EB 3E 48 89 DE 4C 89 F7 31 DB E8 ?? ?? ?? ?? EB 47 4C 8D A4 24 00 01 00 00 48 89 E7 4C 89 E6 E8 ED FE FF FF 48 85 C0 48 89 C3 74 14 BA 06 00 00 00 4C 89 E6 4C 89 EF E8 ?? ?? ?? ?? 85 C0 74 C2 48 89 EA BE 00 01 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 85 C0 75 BC 83 CB FF 48 89 EF E8 ?? ?? ?? ?? 48 81 C4 10 01 00 00 89 D8 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule pthread_setspecific_83ea1ff46804d3a5c192e5a2659c6dff {
	meta:
		aliases = "pthread_setspecific"
		size = "139"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 56 81 FF FF 03 00 00 49 89 F6 41 55 41 54 55 89 FD 53 77 66 89 F8 48 C1 E0 04 83 B8 ?? ?? ?? ?? 00 74 57 41 89 ED 41 C1 ED 05 45 89 EC E8 0A FE FF FF 4A 83 BC E0 48 01 00 00 00 48 89 C3 75 21 BE 08 00 00 00 BF 20 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 BA 0C 00 00 00 74 26 4A 89 84 E3 48 01 00 00 44 89 E8 48 89 EA 48 8B 84 C3 48 01 00 00 83 E2 1F 4C 89 34 D0 31 D2 EB 05 BA 16 00 00 00 5B 5D 41 5C 41 5D 41 5E 89 D0 C3 }
	condition:
		$pattern
}

rule regcomp_412f98b69b78589b49f1efe8294e629a {
	meta:
		aliases = "__regcomp, regcomp"
		size = "323"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 89 D0 49 89 F6 83 E0 01 41 55 83 F8 01 41 54 41 89 D4 55 48 19 ED 81 E5 CA 4F FD 00 53 48 89 FB 48 C7 07 00 00 00 00 48 C7 47 08 00 00 00 00 48 C7 47 10 00 00 00 00 BF 00 01 00 00 E8 ?? ?? ?? ?? 48 81 C5 FC B2 03 00 41 F6 C4 02 48 89 43 20 74 55 BF 00 01 00 00 41 BD 0C 00 00 00 E8 ?? ?? ?? ?? 31 F6 48 85 C0 48 89 43 28 75 30 E9 C3 00 00 00 48 63 C6 48 8B 7B 28 89 F2 48 8D 0C 00 48 8B 05 ?? ?? ?? ?? F6 04 08 01 74 0A 48 8B 05 ?? ?? ?? ?? 8A 14 08 89 F0 FF C6 88 14 07 81 FE FF 00 00 00 76 CD EB 08 48 C7 43 28 00 00 00 00 41 F6 C4 04 8A 43 38 74 10 48 83 E5 BF 83 C8 80 48 81 CD 00 01 00 00 }
	condition:
		$pattern
}

rule __decode_question_310312cd9acfeb7f871d809e1ef23715 {
	meta:
		aliases = "__decode_question"
		size = "119"
		objfiles = "decodeq@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 B9 00 01 00 00 41 55 49 89 FD 41 54 41 89 F4 55 48 89 D5 53 48 81 EC 00 01 00 00 48 89 E2 E8 ?? ?? ?? ?? 85 C0 89 C3 78 3A 48 89 E7 E8 ?? ?? ?? ?? 41 8D 14 1C 48 89 45 00 83 C3 04 48 63 D2 49 8D 54 15 00 0F B6 02 0F B6 4A 01 C1 E0 08 09 C8 89 45 08 0F B6 42 02 0F B6 52 03 C1 E0 08 09 D0 89 45 0C 48 81 C4 00 01 00 00 89 D8 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule vasprintf_df0db35718ece34fb16f524a1418a9f1 {
	meta:
		aliases = "__GI_vasprintf, vasprintf"
		size = "146"
		objfiles = "vasprintf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 B9 06 00 00 00 49 89 F6 FC 41 55 48 89 D6 49 89 FD 41 54 55 48 89 D5 4C 89 F2 53 48 83 EC 30 48 8D 44 24 10 48 89 C7 F3 A5 31 F6 31 FF 48 89 C1 E8 ?? ?? ?? ?? 85 C0 89 C3 49 C7 45 00 00 00 00 00 78 3E FF C3 4C 63 E3 4C 89 E7 E8 ?? ?? ?? ?? 48 85 C0 48 89 C7 49 89 45 00 74 25 48 89 E9 4C 89 F2 4C 89 E6 E8 ?? ?? ?? ?? 85 C0 89 C3 79 11 49 8B 7D 00 E8 ?? ?? ?? ?? 49 C7 45 00 00 00 00 00 48 83 C4 30 89 D8 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule __open_nameservers_034c1ee7f91a9ca166683c8ae166f67e {
	meta:
		aliases = "__open_nameservers"
		size = "597"
		objfiles = "opennameservers@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 41 55 41 54 55 53 48 81 EC D0 00 00 00 48 8D BC 24 B0 00 00 00 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 0F 8F F6 01 00 00 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 49 89 C5 0F 85 A9 01 00 00 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 49 89 C5 0F 85 8E 01 00 00 E9 B0 01 00 00 48 FF C6 8A 0E 84 C9 74 11 48 8B 05 ?? ?? ?? ?? 48 0F BE D1 F6 04 50 20 75 E6 84 C9 0F 94 C2 80 F9 0A 0F 94 C0 08 C2 0F 85 5C 01 00 00 45 31 F6 80 F9 23 75 58 E9 4F 01 00 00 49 63 C6 48 89 B4 C4 80 00 00 00 EB 03 48 FF C6 8A 0E 84 C9 74 1E }
	condition:
		$pattern
}

rule fcloseall_d2138916f730cd6541b16c7ad9262622 {
	meta:
		aliases = "fcloseall"
		size = "239"
		objfiles = "fcloseall@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 41 55 45 31 ED 41 54 55 53 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 FF C0 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 2D ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? EB 5D 44 8B 65 50 4C 8B 75 38 45 85 E4 75 1C 48 8D 5D 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 0F B7 45 00 83 E0 30 83 F8 30 74 13 48 89 EF E8 ?? ?? ?? ?? 85 C0 B8 FF FF FF FF 44 0F 45 E8 45 85 E4 75 0D 48 89 E7 }
	condition:
		$pattern
}

rule getpass_f2400cee35f887f1bd65a826dcd21f0b {
	meta:
		aliases = "getpass"
		size = "365"
		objfiles = "getpass@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 BE ?? ?? ?? ?? 49 89 FE BF ?? ?? ?? ?? 41 55 41 54 55 53 48 83 C4 80 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 48 89 C3 75 0E 48 8B 2D ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? 48 89 EF 45 31 ED E8 ?? ?? ?? ?? 48 89 E6 89 C7 E8 ?? ?? ?? ?? 85 C0 75 4F FC 48 8D 7C 24 40 B9 0F 00 00 00 48 89 E6 F3 A5 48 89 EF 83 64 24 0C F6 45 31 ED E8 ?? ?? ?? ?? 48 89 E2 89 C7 BE 02 00 00 00 E8 ?? ?? ?? ?? 85 C0 41 0F 94 C5 48 3B 2D ?? ?? ?? ?? 74 11 31 C9 BA 02 00 00 00 31 F6 48 89 EF E8 ?? ?? ?? ?? 48 89 DE 4C 89 F7 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 EA BE FF 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? }
	condition:
		$pattern
}

rule authunix_create_default_ef4d4e95f9d6e5b713927e14216ae196 {
	meta:
		aliases = "__GI_authunix_create_default, authunix_create_default"
		size = "171"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 BF 03 00 00 00 41 55 41 54 55 31 ED 53 48 81 EC 00 01 00 00 E8 ?? ?? ?? ?? 85 C0 89 C3 74 14 48 63 F8 48 C1 E7 02 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 74 37 BE FF 00 00 00 48 89 E7 E8 ?? ?? ?? ?? FF C0 74 26 C6 84 24 FF 00 00 00 00 E8 ?? ?? ?? ?? 41 89 C5 E8 ?? ?? ?? ?? 48 89 EE 89 DF 41 89 C4 E8 ?? ?? ?? ?? 85 C0 79 05 E8 ?? ?? ?? ?? 83 F8 10 B9 10 00 00 00 49 89 E8 0F 4E C8 44 89 E2 44 89 EE 48 89 E7 E8 ?? ?? ?? ?? 48 89 EF 48 89 C3 E8 ?? ?? ?? ?? 48 81 C4 00 01 00 00 48 89 D8 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule __ieee754_pow_824a0b849f93a0b27362be3c78a7efad {
	meta:
		aliases = "__ieee754_pow"
		size = "2154"
		objfiles = "e_pow@libm.a"
	strings:
		$pattern = { ( CC | 41 ) 57 0F 28 D0 44 0F 28 C1 41 56 41 55 41 54 55 53 48 83 EC 68 F2 0F 11 44 24 08 48 8B 54 24 08 F2 0F 11 4C 24 08 48 8B 4C 24 08 48 89 D0 48 C1 EA 20 49 89 CC 41 89 C6 89 CE 49 C1 EC 20 44 89 E3 81 E3 FF FF FF 7F 89 D8 09 C8 75 0E 66 44 0F 12 05 ?? ?? ?? ?? E9 FC 07 00 00 89 D5 41 89 D5 81 E5 FF FF FF 7F 81 FD 00 00 F0 7F 7F 25 0F 94 44 24 57 45 85 F6 0F 95 C0 84 44 24 57 75 14 81 FB 00 00 F0 7F 7F 0C 0F 94 C2 85 C9 0F 95 C0 84 D0 74 0A F2 44 0F 58 C2 E9 BA 07 00 00 45 85 ED 79 77 81 FB FF FF 3F 43 41 BF 02 00 00 00 7F 6C 81 FB FF FF EF 3F 7E 61 89 D8 C1 F8 14 2D FF 03 00 00 83 F8 14 7E 24 C7 }
	condition:
		$pattern
}

rule __GI_rexec_af_83c0b5fc2b0f5734889b41a075d20e02 {
	meta:
		aliases = "rexec_af, __GI_rexec_af"
		size = "1084"
		objfiles = "rexec@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 31 C0 4D 89 CF 66 C1 CE 08 41 56 49 89 FE 41 55 41 54 55 83 CD FF 53 48 81 EC D8 01 00 00 4C 8D AC 24 90 01 00 00 48 89 54 24 38 48 89 4C 24 30 48 89 54 24 18 48 89 4C 24 20 BA ?? ?? ?? ?? 0F B7 CE 4C 89 EF BE 20 00 00 00 4C 89 44 24 10 0F B7 9C 24 10 02 00 00 E8 ?? ?? ?? ?? 4C 8D A4 24 40 01 00 00 31 F6 BA 30 00 00 00 C6 84 24 AF 01 00 00 00 4C 89 E7 E8 ?? ?? ?? ?? 49 8B 3E 48 8D 8C 24 B8 01 00 00 4C 89 E2 4C 89 EE 89 9C 24 44 01 00 00 C7 84 24 48 01 00 00 01 00 00 00 C7 84 24 40 01 00 00 02 00 00 00 E8 ?? ?? ?? ?? 85 C0 0F 85 70 03 00 00 48 8B 84 24 B8 01 00 00 48 8B 70 20 48 85 F6 74 }
	condition:
		$pattern
}

rule _vfwprintf_internal_0b0d9d154791cee281d829293d53c480 {
	meta:
		aliases = "_vfwprintf_internal"
		size = "1863"
		objfiles = "_vfwprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 49 89 F4 31 F6 55 48 89 D5 BA 00 01 00 00 53 48 81 EC 08 03 00 00 48 8D 9C 24 40 01 00 00 48 89 7C 24 10 48 89 DF E8 ?? ?? ?? ?? 48 8D 8C 24 F0 02 00 00 48 8D B4 24 C8 02 00 00 48 83 CA FF 31 FF FF 8C 24 5C 01 00 00 4C 89 A4 24 40 01 00 00 C7 84 24 54 01 00 00 80 00 00 00 C7 84 24 F0 02 00 00 00 00 00 00 4C 89 A4 24 C8 02 00 00 E8 ?? ?? ?? ?? 48 FF C0 75 11 48 C7 84 24 40 01 00 00 ?? ?? ?? ?? E9 9A 00 00 00 48 8D 43 2C BA 09 00 00 00 C7 00 08 00 00 00 48 83 C0 04 FF CA 75 F2 4C 89 E0 EB 35 83 FA 25 75 2C 48 83 C0 04 83 38 25 74 23 48 8D BC 24 40 01 00 00 48 89 84 24 40 }
	condition:
		$pattern
}

rule realpath_782d62ecf679fd530d2f1cc6bd9104df {
	meta:
		aliases = "realpath"
		size = "604"
		objfiles = "realpath@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 49 89 F4 55 48 89 FD 53 48 81 EC 18 10 00 00 48 85 FF 75 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 18 02 00 00 80 3F 00 75 10 E8 ?? ?? ?? ?? C7 00 02 00 00 00 E9 03 02 00 00 E8 ?? ?? ?? ?? 48 3D FD 0F 00 00 0F 87 D1 01 00 00 4C 8D 6C 24 10 48 89 EE 49 29 C5 49 8D 9D FF 0F 00 00 48 89 DF E8 ?? ?? ?? ?? 49 8D 84 24 FE 0F 00 00 48 89 04 24 41 80 BD FF 0F 00 00 2F 74 3C BE FF 0F 00 00 4C 89 E7 E8 ?? ?? ?? ?? 48 85 C0 0F 84 AC 01 00 00 4C 89 E7 E8 ?? ?? ?? ?? 49 8D 2C 04 80 7D FF 2F 74 07 C6 45 00 2F 48 FF C5 C7 44 24 08 00 00 00 00 E9 3F 01 00 00 49 8D 6C 24 01 49 8D 9D 00 10 }
	condition:
		$pattern
}

rule __GI_inet_pton_e6d590a3c6adf1e5fa8d3ebd621edd98 {
	meta:
		aliases = "inet_pton, __GI_inet_pton"
		size = "493"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 49 89 F4 55 53 48 83 EC 38 83 FF 02 48 89 54 24 08 74 0B 83 FF 0A 0F 85 A8 01 00 00 EB 12 48 8B 74 24 08 4C 89 E7 E8 46 FF FF FF E9 A6 01 00 00 48 8D 7C 24 20 31 F6 BA 10 00 00 00 E8 ?? ?? ?? ?? 41 80 3C 24 3A 48 89 C3 4C 8D 70 10 75 0E 49 FF C4 41 80 3C 24 3A 0F 85 77 01 00 00 4D 89 E7 48 C7 44 24 18 00 00 00 00 E9 83 00 00 00 89 EE BF ?? ?? ?? ?? 49 FF C4 E8 ?? ?? ?? ?? 48 85 C0 48 89 C2 74 20 B8 ?? ?? ?? ?? 41 C1 E5 04 29 C2 41 09 D5 41 81 FD FF FF 00 00 0F 86 8B 00 00 00 E9 2F 01 00 00 83 FD 3A 75 54 83 7C 24 14 00 75 16 48 83 7C 24 18 00 0F 85 17 01 00 00 4D 89 E7 }
	condition:
		$pattern
}

rule _Unwind_ForcedUnwind_Phase2_1076a02fc29c32f268f035aaf6760838 {
	meta:
		aliases = "_Unwind_ForcedUnwind_Phase2"
		size = "172"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 49 89 FC 55 48 89 F5 53 48 83 EC 08 4C 8B 7F 10 4C 8B 77 18 48 8B 06 EB 41 83 FB 05 74 75 4D 85 ED 74 23 49 89 E8 4C 89 E1 49 8B 14 24 BE 0A 00 00 00 BF 01 00 00 00 41 FF D5 83 F8 07 89 C3 74 52 83 F8 08 75 48 48 8B 7D 00 E8 ?? ?? ?? ?? 48 8B 45 00 48 8B 00 48 89 45 00 45 31 ED 48 85 C0 BE 1A 00 00 00 BB 05 00 00 00 74 09 4C 8B 68 30 40 B6 0A 30 DB 4D 89 F1 49 89 E8 4C 89 E1 49 8B 14 24 BF 01 00 00 00 41 FF D7 85 C0 74 8B BB 02 00 00 00 48 83 C4 08 89 D8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule _stdlib_wcsto_l_ed444ffd24b97d2ac89650a80be9b26f {
	meta:
		aliases = "_stdlib_wcsto_l"
		size = "369"
		objfiles = "_stdlib_wcsto_l@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 49 89 FC 55 89 D5 53 48 89 FB 48 83 EC 18 48 89 74 24 10 89 4C 24 0C EB 04 48 83 C3 04 8B 3B E8 ?? ?? ?? ?? 85 C0 75 F1 8B 03 83 F8 2B 74 10 45 31 ED 83 F8 2D 75 0F 41 BD 01 00 00 00 EB 03 45 31 ED 48 83 C3 04 F7 C5 EF FF FF FF 4C 89 E7 75 2D 83 C5 0A 83 3B 30 75 1A 48 83 C3 04 83 ED 02 8B 03 48 89 DF 83 C8 20 83 F8 78 75 06 01 ED 48 83 C3 04 83 FD 11 B8 10 00 00 00 0F 4D E8 8D 45 FE 31 F6 83 F8 22 77 7E 4C 63 E5 48 83 C8 FF 31 D2 49 F7 F4 49 89 C7 41 89 D6 EB 03 48 89 DF 8B 13 8D 42 D0 8D 4A D0 83 F8 09 76 17 89 D0 B9 28 00 00 00 83 C8 20 83 F8 60 76 08 89 D0 83 C8 20 }
	condition:
		$pattern
}

rule _dl_do_reloc_d38684faa9dfdcbf64653138499c36a7 {
	meta:
		aliases = "_dl_do_reloc"
		size = "328"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 48 89 D5 53 31 DB 48 83 EC 08 4C 8B 22 48 8B 52 08 4C 03 27 41 89 D6 48 C1 EA 20 48 63 C2 48 6B C0 18 85 D2 4C 8D 2C 01 41 8B 45 00 74 71 31 D2 41 83 FE 05 89 C0 0F 94 C2 4D 8D 3C 00 31 C9 01 D2 41 83 FE 07 0F 94 C1 09 D1 48 89 FA 4C 89 FF E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 75 42 41 8A 45 04 C0 E8 04 3C 02 74 37 48 8B 15 ?? ?? ?? ?? 31 C0 4C 89 F9 BE ?? ?? ?? ?? BF 02 00 00 00 E8 ?? ?? ?? ?? BF 01 00 00 00 B8 3C 00 00 00 0F 05 48 3D 00 F0 FF FF 76 08 F7 D8 89 05 ?? ?? ?? ?? 41 83 FE 12 77 0A 44 89 F0 FF 24 C5 ?? ?? ?? ?? 83 C8 FF EB 7F 48 03 5D 10 48 2B 5D 00 EB 04 48 }
	condition:
		$pattern
}

rule _vfprintf_internal_d34f4e0686d6c06c971c8294d2e3d588 {
	meta:
		aliases = "_vfprintf_internal"
		size = "1595"
		objfiles = "_vfprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 48 89 D5 53 48 89 F3 48 81 EC D8 01 00 00 4C 8D 64 24 30 48 89 7C 24 20 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 79 33 48 8B 5C 24 30 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 48 89 C6 C7 44 24 2C FF FF FF FF 0F 84 D7 05 00 00 48 8B 54 24 20 48 89 DF E8 ?? ?? ?? ?? E9 BD 05 00 00 4C 89 E7 48 89 EE E8 ?? ?? ?? ?? 48 89 DF C7 44 24 2C 00 00 00 00 EB 03 48 FF C3 8A 03 84 C0 0F 95 C2 3C 25 0F 95 C0 84 D0 75 ED 48 39 FB 74 2C 48 89 DD 31 D2 48 29 FD 48 85 ED 7E 0F 48 8B 54 24 20 48 89 EE E8 ?? ?? ?? ?? 89 C2 48 63 C2 48 39 E8 0F 85 65 05 00 00 01 54 24 2C 80 3B 00 0F 84 60 05 00 00 80 7B 01 }
	condition:
		$pattern
}

rule __pthread_alt_unlock_fa9209515c6f802697f49c3c1282e2e2 {
	meta:
		aliases = "__pthread_alt_unlock"
		size = "221"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 48 89 FD 53 48 83 EC 08 48 8B 4D 00 48 83 F9 01 77 17 31 D2 48 89 C8 F0 48 0F B1 55 00 0F 94 C2 84 D2 74 E4 E9 9F 00 00 00 48 89 CB 41 BE 00 00 00 80 49 89 CC 49 89 EF 49 89 ED EB 42 83 7B 10 00 74 21 48 89 DA 4C 89 EE 48 89 EF E8 03 FF FF FF 48 89 DF E8 6E FF FF FF 49 39 ED 49 8B 5D 00 75 1D EB 1B 48 8B 53 08 8B 42 2C 44 39 F0 7C 09 49 89 DC 4D 89 EF 41 89 C6 49 89 DD 48 8B 1B 48 83 FB 01 75 B8 41 81 FE 00 00 00 80 0F 84 76 FF FF FF BA 01 00 00 00 41 87 54 24 10 48 85 D2 0F 85 63 FF FF FF 4C 89 E2 48 89 EF 4C 89 FE E8 A1 FE FF FF 49 8B 7C 24 08 5A 5B 5D 41 5C 41 5D }
	condition:
		$pattern
}

rule realloc_c958699714afa0331c42ded695e987cf {
	meta:
		aliases = "realloc"
		size = "857"
		objfiles = "realloc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 48 89 FD 53 48 89 F3 48 83 EC 48 48 85 FF 75 10 48 89 F7 E8 ?? ?? ?? ?? 48 89 C3 E9 1E 03 00 00 48 85 F6 75 0A E8 ?? ?? ?? ?? E9 0F 03 00 00 48 8D 7C 24 20 BA ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 FB BF 76 12 31 DB E8 ?? ?? ?? ?? C7 00 0C 00 00 00 E9 D9 02 00 00 48 8D 43 17 41 B8 20 00 00 00 4C 8D 7D F0 48 89 C2 48 83 E2 F0 48 83 F8 1F 4C 0F 47 C2 48 8B 55 F8 49 89 D4 49 83 E4 FC F6 C2 02 0F 85 AA 01 00 00 4D 39 C4 4C 89 E1 0F 83 47 01 00 00 4B 8D 1C 27 48 3B 1D ?? ?? ?? ?? 75 3A 48 8B 43 08 48 83 E0 FC 49 8D 0C 04 49 8D 40 20 }
	condition:
		$pattern
}

rule __dns_lookup_ee9cd15067847a5b8e86113785724ffe {
	meta:
		aliases = "__dns_lookup"
		size = "1862"
		objfiles = "dnslookup@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 4C 89 CD 53 48 81 EC 28 01 00 00 48 89 7C 24 20 BF 00 02 00 00 89 54 24 18 89 74 24 1C 48 89 4C 24 10 4C 89 44 24 08 E8 ?? ?? ?? ?? BF 01 04 00 00 49 89 C6 E8 ?? ?? ?? ?? 4D 85 F6 48 89 04 24 0F 94 C2 48 85 C0 0F 94 C0 08 C2 0F 85 45 06 00 00 83 7C 24 18 00 0F 84 3A 06 00 00 48 8B 44 24 20 80 38 00 0F 84 2C 06 00 00 48 89 C7 E8 ?? ?? ?? ?? 48 8B 54 24 20 48 8D 9C 24 C0 00 00 00 BE ?? ?? ?? ?? 48 89 DF 80 7C 02 FF 2E BA ?? ?? ?? ?? 0F 94 44 24 43 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? BE 01 00 00 00 48 89 DF 99 F7 7C 24 18 0F B7 05 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_manager_791c8961c036c3d9dc072650823147b0 {
	meta:
		aliases = "__pthread_manager"
		size = "1770"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 53 48 81 EC 88 01 00 00 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 48 8D 9C 24 F0 00 00 00 89 7C 24 10 48 89 DF E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? BE 05 00 00 00 48 89 DF E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 85 C0 74 12 8B 35 ?? ?? ?? ?? 85 F6 7E 08 48 89 DF E8 ?? ?? ?? ?? 48 8D B4 24 F0 00 00 00 BF 02 00 00 00 31 D2 E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 8B 78 2C E8 ?? ?? ?? ?? 8B 7C 24 10 48 8D 74 24 40 BA A8 00 00 00 E8 ?? ?? ?? ?? 48 FF C0 75 0A E8 ?? ?? ?? ?? 83 38 04 74 DE 8B 44 24 10 66 C7 84 24 74 01 00 00 01 00 89 84 24 }
	condition:
		$pattern
}

rule clnt_broadcast_a15877e451977cfdaabe9b98fe5d159d {
	meta:
		aliases = "clnt_broadcast"
		size = "1470"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 53 48 81 EC E8 29 00 00 48 89 7C 24 30 48 89 74 24 28 48 89 54 24 20 48 89 4C 24 18 4C 89 44 24 10 4C 89 4C 24 08 E8 ?? ?? ?? ?? BF 02 00 00 00 BA 11 00 00 00 BE 02 00 00 00 48 89 44 24 38 C7 84 24 D8 29 00 00 01 00 00 00 E8 ?? ?? ?? ?? 85 C0 41 89 C7 BF ?? ?? ?? ?? 78 28 48 8D 8C 24 D8 29 00 00 41 B8 04 00 00 00 BA 06 00 00 00 BE 01 00 00 00 89 C7 E8 ?? ?? ?? ?? 85 C0 79 14 BF ?? ?? ?? ?? BB 03 00 00 00 E8 ?? ?? ?? ?? E9 F8 04 00 00 48 8D 44 24 50 48 8D 94 24 B0 29 00 00 BE 12 89 00 00 44 89 FF 44 89 BC 24 C0 29 00 00 66 C7 84 24 C4 29 00 00 01 00 48 89 84 24 B8 29 }
	condition:
		$pattern
}

rule scandir_ed1b9fb8823bbd8aa1d7b4920a5a797b {
	meta:
		aliases = "scandir64, scandir"
		size = "360"
		objfiles = "scandir@libc.a, scandir64@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 53 48 83 EC 28 48 89 74 24 10 48 89 54 24 08 48 89 0C 24 E8 ?? ?? ?? ?? 49 89 C7 83 C8 FF 4D 85 FF 0F 84 29 01 00 00 E8 ?? ?? ?? ?? 48 89 C5 8B 00 45 31 F6 45 31 ED 89 44 24 24 C7 45 00 00 00 00 00 48 C7 44 24 18 00 00 00 00 E9 85 00 00 00 48 83 7C 24 08 00 74 14 4C 89 E7 FF 54 24 08 85 C0 75 09 C7 45 00 00 00 00 00 EB 69 C7 45 00 00 00 00 00 4C 3B 6C 24 18 75 33 4D 85 ED 48 C7 44 24 18 0A 00 00 00 4B 8D 44 2D 00 48 0F 44 44 24 18 4C 89 F7 48 89 C6 48 89 44 24 18 48 C1 E6 03 E8 ?? ?? ?? ?? 48 85 C0 74 3F 49 89 C6 41 0F B7 5C 24 10 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 48 }
	condition:
		$pattern
}

rule __GI_strftime_e624072cd0adf39f97549aa5856d903f {
	meta:
		aliases = "strftime, __GI_strftime"
		size = "1430"
		objfiles = "strftime@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 53 48 89 D3 48 81 EC 98 00 00 00 48 89 7C 24 20 48 89 74 24 18 48 89 CF 31 F6 48 89 4C 24 10 E8 ?? ?? ?? ?? 31 FF 48 3D FF 4E 98 45 40 0F 9E C7 E8 ?? ?? ?? ?? 48 8B 44 24 18 48 89 DF C7 44 24 3C 00 00 00 00 48 89 44 24 30 48 83 7C 24 30 00 0F 84 23 05 00 00 8A 07 84 C0 75 2E 83 7C 24 3C 00 75 17 48 8B 54 24 20 C6 02 00 48 8B 44 24 18 48 2B 44 24 30 E9 01 05 00 00 FF 4C 24 3C 48 63 44 24 3C 48 8B 7C C4 40 EB C0 3C 25 48 89 7C 24 28 48 89 FD 41 BF 01 00 00 00 0F 85 92 04 00 00 48 8D 4F 01 48 89 4C 24 28 8A 4F 01 80 F9 25 0F 84 7D 04 00 00 80 F9 4F 41 B7 02 BE 3F 00 00 }
	condition:
		$pattern
}

rule des_setkey_b028930b65233787cc5ed96b54e81661 {
	meta:
		aliases = "des_setkey"
		size = "606"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 53 48 89 FB 48 83 EC 08 E8 00 F8 FF FF 8B 03 44 8B 53 04 0F C8 89 C2 41 0F CA 44 09 D2 74 15 3B 05 ?? ?? ?? ?? 75 0D 44 3B 15 ?? ?? ?? ?? 0F 84 15 02 00 00 89 C7 89 C6 41 89 C1 89 05 ?? ?? ?? ?? D1 E8 44 89 D1 45 89 D0 49 89 C3 C1 EF 19 C1 EE 11 41 C1 E9 09 44 89 D2 89 FF 83 E6 7F 41 83 E3 7F 41 83 E1 7F C1 E9 19 41 C1 E8 11 89 C9 41 83 E0 7F 44 89 15 ?? ?? ?? ?? C1 EA 09 41 D1 EA 44 8B 34 B5 ?? ?? ?? ?? 42 8B 04 8D ?? ?? ?? ?? 44 0B 34 BD ?? ?? ?? ?? 83 E2 7F 42 0B 04 9D ?? ?? ?? ?? 41 83 E2 7F 44 0B 34 8D ?? ?? ?? ?? 42 0B 04 85 ?? ?? ?? ?? 44 0B 34 95 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clntudp_bufcreate_8e6379def96776991331c9016ba371fe {
	meta:
		aliases = "__GI_clntudp_bufcreate, clntudp_bufcreate"
		size = "681"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 53 48 89 FB BF 18 00 00 00 48 81 EC B8 00 00 00 48 89 54 24 20 48 89 74 24 28 48 89 4C 24 18 4C 89 44 24 10 4C 89 4C 24 08 48 89 4C 24 30 4C 89 44 24 38 E8 ?? ?? ?? ?? 44 8B B4 24 F0 00 00 00 44 8B A4 24 F8 00 00 00 49 89 C7 41 83 C6 03 41 83 C4 03 41 83 E6 FC 41 83 E4 FC 45 89 E5 44 89 F7 4A 8D BC 2F A0 00 00 00 E8 ?? ?? ?? ?? 4D 85 FF 48 89 C5 0F 94 C2 48 85 C0 0F 94 C0 08 C2 74 2B E8 ?? ?? ?? ?? 48 8B 35 ?? ?? ?? ?? 48 89 C3 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 03 0C 00 00 00 C7 43 10 0C 00 00 00 E9 C2 01 00 00 4A 8D 84 2D 9C 00 00 00 48 89 85 90 00 00 00 66 83 7B 02 }
	condition:
		$pattern
}

rule vsyslog_681303e2ee6387c3d54650d1cc6e7421 {
	meta:
		aliases = "__GI_vsyslog, vsyslog"
		size = "810"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 89 FD 53 48 81 EC 88 05 00 00 48 8D 9C 24 B0 04 00 00 48 89 74 24 08 48 89 14 24 31 F6 BA 98 00 00 00 48 89 DF E8 ?? ?? ?? ?? 48 8D 7B 08 48 C7 84 24 B0 04 00 00 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 94 24 10 04 00 00 48 89 DE BF 0D 00 00 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D BC 24 50 05 00 00 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 49 89 C7 44 8B 20 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 E9 B8 01 00 00 00 83 E1 07 D3 E0 85 05 ?? ?? ?? ?? 0F 84 51 02 00 00 F7 C5 00 FC FF FF 0F 85 45 02 00 00 83 3D ?? ?? ?? ?? 00 78 09 83 3D ?? ?? ?? ?? 00 75 17 8B 35 ?? ?? ?? ?? 48 8B 3D }
	condition:
		$pattern
}

rule fnmatch_656ae4c7f91aef100b1a93477c27b4d0 {
	meta:
		aliases = "__GI_fnmatch, fnmatch"
		size = "1193"
		objfiles = "fnmatch_old@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 89 D5 41 54 55 48 89 F5 53 E9 5F 04 00 00 45 89 EE 41 83 E6 10 74 23 84 D2 78 1F 48 0F BE C2 48 8D 0C 00 48 8B 05 ?? ?? ?? ?? F6 04 08 01 74 0A 48 8B 05 ?? ?? ?? ?? 8A 14 08 0F BE CA 48 FF C7 83 F9 3F 74 24 7F 0E 83 F9 2A 0F 85 E4 03 00 00 E9 D0 00 00 00 83 F9 5B 0F 84 DE 01 00 00 83 F9 5C 0F 85 CD 03 00 00 EB 47 8A 45 00 84 C0 0F 84 1A 04 00 00 44 89 EA 80 E2 01 74 08 3C 2F 0F 84 0A 04 00 00 41 F6 C5 04 0F 84 DC 03 00 00 3C 2E 0F 85 D4 03 00 00 48 39 F5 0F 84 EF 03 00 00 84 D2 0F 84 C3 03 00 00 80 7D FF 2F E9 5B 03 00 00 41 F6 C5 02 75 35 8A 17 48 FF C7 84 D2 0F 84 CB 03 }
	condition:
		$pattern
}

rule _time_mktime_tzi_8eaf5fd143a71e13d8f65efe8d3dc18a {
	meta:
		aliases = "_time_mktime_tzi"
		size = "560"
		objfiles = "_time_mktime_tzi@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 49 89 D5 BA 38 00 00 00 41 54 55 53 48 83 EC 78 48 8D 5C 24 30 48 89 7C 24 20 89 74 24 1C 48 89 FE 48 89 DF E8 ?? ?? ?? ?? 31 C0 41 80 7D 38 00 0F 45 44 24 50 45 31 FF 85 C0 89 44 24 50 74 12 85 C0 41 B7 01 0F 9F C0 0F B6 C0 8D 44 00 FF 89 43 20 8B 4B 14 48 8D 43 18 41 B8 90 01 00 00 48 8D 7B 10 48 8D 6B 14 4C 8D 63 1C 48 89 44 24 28 89 C8 99 41 F7 F8 BA 0C 00 00 00 89 D6 89 43 18 69 C0 90 01 00 00 29 C1 8B 43 10 99 F7 FE 01 C1 89 43 1C 89 4B 14 6B C0 0C 29 07 8B 43 10 85 C0 79 09 83 C0 0C 89 43 10 FF 4D 00 81 45 00 6C 07 00 00 BE ?? ?? ?? ?? 8B 4B 14 F6 C1 03 75 24 BA 64 00 }
	condition:
		$pattern
}

rule __GI_vfwscanf_35ae2252e022b2f85e3feddc3c2270a6 {
	meta:
		aliases = "vfwscanf, __GI_vfwscanf"
		size = "1861"
		objfiles = "vfwscanf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 49 89 D5 BA 48 00 00 00 41 54 55 48 89 F5 31 F6 53 48 81 EC 88 01 00 00 48 89 7C 24 08 48 8D 7C 24 20 C7 44 24 68 FF FF FF FF E8 ?? ?? ?? ?? 48 8B 44 24 08 8B 40 50 85 C0 89 44 24 18 75 26 48 8B 5C 24 08 48 8D BC 24 40 01 00 00 BE ?? ?? ?? ?? 48 83 C3 58 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8B 74 24 08 48 8D BC 24 A0 00 00 00 48 89 EB 41 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 8B 84 24 A8 00 00 00 48 C7 84 24 D0 00 00 00 ?? ?? ?? ?? 8A 40 03 48 C7 84 24 E8 00 00 00 ?? ?? ?? ?? C7 84 24 80 00 00 00 00 00 00 00 88 84 24 BC 00 00 00 E9 B2 05 00 00 80 A4 24 BD 00 00 00 01 }
	condition:
		$pattern
}

rule re_search_2_6d6c2b59f6ad36319fcc079aa7c9628c {
	meta:
		aliases = "__re_search_2, re_search_2"
		size = "553"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 49 89 FD 41 54 41 89 D4 44 89 CA 47 8D 3C 04 C1 EA 1F 55 53 44 89 CB 48 83 EC 38 45 39 F9 48 89 74 24 28 48 89 4C 24 20 44 89 44 24 1C 48 8B 47 28 4C 8B 77 20 8B 6C 24 70 48 89 44 24 30 0F 9F C0 08 D0 0F 85 BF 01 00 00 44 89 CA 01 EA 79 07 44 89 CD F7 DD EB 0C 44 89 F8 44 29 C8 44 39 FA 0F 4F E8 49 83 7D 10 00 0F 95 C2 85 ED 0F 9F C0 84 D0 74 22 49 8B 45 00 8A 00 3C 0B 74 0B 3C 09 75 14 41 80 7D 38 00 78 0D 85 DB 0F 8F 77 01 00 00 BD 01 00 00 00 4D 85 F6 74 18 41 F6 45 38 08 75 11 4C 89 EF E8 ?? ?? ?? ?? 83 F8 FE 0F 84 5A 01 00 00 4D 85 F6 0F 95 C2 44 39 FB 0F 9C C0 84 D0 0F }
	condition:
		$pattern
}

rule add_fdes_2da6ee494240d61d71df00dafc39a3d9 {
	meta:
		aliases = "add_fdes"
		size = "293"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 49 89 FD 41 54 55 48 89 D5 53 48 83 EC 28 48 89 74 24 10 8B 47 20 48 89 FE 66 C1 E8 03 44 0F B6 E0 44 89 E7 E8 21 FB FF FF 8B 75 00 49 89 C7 85 F6 0F 84 D9 00 00 00 48 8D 44 24 20 45 31 F6 48 89 44 24 08 EB 3D 66 66 66 90 48 83 7D 08 00 74 1D 48 8B 44 24 10 48 8B 10 48 85 D2 74 10 48 8B 42 08 48 89 6C C2 10 48 FF C0 48 89 42 08 8B 45 00 48 01 E8 8B 48 04 48 8D 68 04 85 C9 0F 84 8D 00 00 00 8B 45 04 85 C0 74 E4 41 F6 45 20 04 74 2A 48 8D 5D 04 48 98 48 29 C3 4C 39 F3 74 19 48 89 DF E8 B3 FC FF FF 4C 89 EE 0F B6 F8 41 89 C4 E8 95 FA FF FF 49 89 C7 49 89 DE 45 85 E4 74 8A 48 8B }
	condition:
		$pattern
}

rule clnttcp_call_d2e5cad3bf92efb49589ab6c979e69a5 {
	meta:
		aliases = "clnttcp_call"
		size = "623"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 49 89 FD 41 54 55 53 48 81 EC A8 00 00 00 48 89 54 24 20 48 89 74 24 38 48 89 4C 24 18 4C 89 44 24 10 4C 89 4C 24 08 48 8B 5F 10 48 8B 84 24 E8 00 00 00 48 8B 94 24 E0 00 00 00 83 7B 18 00 48 8D 6B 68 4C 8D 7B 48 75 08 48 89 43 10 48 89 53 08 48 83 7C 24 10 00 75 3E 48 83 7B 08 00 75 37 45 31 F6 48 83 7B 10 00 41 0F 95 C6 EB 2F B8 03 00 00 00 C7 43 30 03 00 00 00 E9 D8 01 00 00 31 C0 E9 D1 01 00 00 B8 05 00 00 00 C7 43 30 05 00 00 00 E9 C0 01 00 00 41 BE 01 00 00 00 C7 44 24 34 02 00 00 00 C7 45 00 00 00 00 00 C7 43 30 00 00 00 00 48 8D 73 48 41 FF 0F 48 89 EF 41 8B 07 0F C8 }
	condition:
		$pattern
}

rule clntunix_call_1484976fb36cc45cc794dd246fc87427 {
	meta:
		aliases = "clntunix_call"
		size = "676"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 49 89 FD 41 54 55 53 48 81 EC A8 00 00 00 48 89 54 24 20 48 89 74 24 38 48 89 4C 24 18 4C 89 44 24 10 4C 89 4C 24 08 48 8B 5F 10 48 8B 84 24 E8 00 00 00 48 8B 94 24 E0 00 00 00 83 7B 18 00 48 8D AB C8 00 00 00 4C 8D BB A8 00 00 00 75 08 48 89 43 10 48 89 53 08 48 83 7C 24 10 00 75 44 48 83 7B 08 00 75 3D 45 31 F6 48 83 7B 10 00 41 0F 95 C6 EB 35 B8 03 00 00 00 C7 83 90 00 00 00 03 00 00 00 E9 04 02 00 00 31 C0 E9 FD 01 00 00 B8 05 00 00 00 C7 83 90 00 00 00 05 00 00 00 E9 E9 01 00 00 41 BE 01 00 00 00 C7 44 24 34 02 00 00 00 C7 45 00 00 00 00 00 C7 83 90 00 00 00 00 00 00 00 }
	condition:
		$pattern
}

rule _ppfs_parsespec_e99d95070e80cc87d61f8c841a35da85 {
	meta:
		aliases = "_ppfs_parsespec"
		size = "1022"
		objfiles = "_ppfs_parsespec@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 49 89 FD 41 54 55 53 48 83 EC 58 C7 44 24 30 00 00 00 00 C7 44 24 34 00 00 00 00 C7 44 24 40 08 00 00 00 C7 44 24 44 08 00 00 00 44 8B 47 14 44 8B 7F 1C 41 81 E0 80 00 00 00 75 14 48 8B 0F EB 4C 89 FA E9 9E 01 00 00 48 FF C5 E9 AE 01 00 00 31 FF 48 63 D7 49 8B 4D 00 48 8D 34 95 00 00 00 00 8B 44 31 FC 88 44 14 10 89 C2 0F BE C0 3B 44 31 FC 0F 85 6E 03 00 00 84 D2 74 07 FF C7 83 FF 1F 76 CF 48 8D 4C 24 11 C6 44 24 2F 00 45 31 DB 45 31 D2 EB 03 48 89 E9 80 39 2A 48 89 CD 75 13 44 89 D0 48 8D 69 01 F7 D8 48 98 C7 44 84 40 00 00 00 00 4C 8B 0D ?? ?? ?? ?? 31 FF EB 16 81 FF FE 0F }
	condition:
		$pattern
}

rule __psfs_do_numeric_d17765fba0d914122a17da1056a2c7b0 {
	meta:
		aliases = "__psfs_do_numeric"
		size = "1103"
		objfiles = "__psfs_do_numeric@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 49 89 FD 41 54 55 53 48 89 F3 48 81 EC D8 00 00 00 8B 47 68 89 44 24 08 FF C8 83 7C 24 08 01 48 98 44 8A B0 ?? ?? ?? ?? 75 56 BD ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 85 C0 78 08 0F B6 45 00 3B 03 74 16 48 89 DF E8 ?? ?? ?? ?? 48 81 FD ?? ?? ?? ?? 76 2C E9 D5 03 00 00 48 FF C5 80 7D 00 00 75 CD 41 80 7D 70 00 0F 84 C8 03 00 00 41 FF 45 60 41 8B 75 64 31 D2 49 8B 7D 50 E9 86 01 00 00 48 89 DF E8 ?? ?? ?? ?? 8B 0B 83 C8 FF 85 C9 0F 88 A2 03 00 00 83 F9 2B 48 8D 6C 24 20 0F 94 C2 83 F9 2D 0F 94 C0 08 C2 75 05 49 89 EC EB 10 4C 8D 65 01 48 89 DF 88 4C 24 20 E8 ?? ?? ?? ?? 41 F6 C6 }
	condition:
		$pattern
}

rule __gen_tempname_24c2795eb66d9426fdfa2f6e219046f0 {
	meta:
		aliases = "__gen_tempname"
		size = "552"
		objfiles = "tempname@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 89 F6 41 55 41 54 55 48 89 FD 53 48 81 EC B8 00 00 00 E8 ?? ?? ?? ?? 49 89 C5 8B 00 48 89 EF 89 44 24 0C E8 ?? ?? ?? ?? 48 83 F8 05 76 21 48 8D 44 05 FA BE ?? ?? ?? ?? 45 31 FF 48 89 04 24 48 89 C7 E8 ?? ?? ?? ?? 85 C0 0F 84 AA 01 00 00 41 C7 45 00 16 00 00 00 E9 B2 01 00 00 31 F6 31 C0 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 89 C3 79 17 31 C0 BE 00 08 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 89 C3 78 28 48 8D B4 24 A0 00 00 00 BA 06 00 00 00 89 DF E8 ?? ?? ?? ?? 89 DF 41 89 C4 E8 ?? ?? ?? ?? 41 83 FC 06 0F 84 91 00 00 00 48 8D 7C 24 10 31 F6 E8 ?? ?? ?? ?? 48 8B 5C 24 18 4C 8B 25 }
	condition:
		$pattern
}

rule frame_downheap_262421aac92e2ae1f33cefa7588fb8dc {
	meta:
		aliases = "frame_downheap"
		size = "178"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 45 89 C6 41 55 49 89 D5 41 54 55 8D 6C 09 01 53 48 83 EC 18 44 39 C5 48 89 7C 24 10 48 89 74 24 08 7D 7C 41 89 CF EB 3C 66 66 66 90 49 63 C7 49 8B 14 24 48 8B 7C 24 10 49 8D 5C C5 00 48 8B 33 FF 54 24 08 85 C0 79 57 49 8B 04 24 48 8B 13 41 89 EF 48 89 03 8D 44 2D 01 49 89 14 24 41 39 C6 7E 3D 89 C5 8D 5D 01 48 63 C5 4D 8D 64 C5 00 41 39 DE 7E B8 48 C1 E0 03 48 8B 7C 24 10 4D 8D 64 05 00 49 8B 54 05 08 49 8B 34 24 FF 54 24 08 85 C0 79 99 48 63 C3 89 DD 4D 8D 64 C5 00 EB 8D 48 83 C4 18 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule __fake_pread_write_782cc1a0fe853f98e6fa6d52d8e225e4 {
	meta:
		aliases = "__fake_pread_write"
		size = "165"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 45 89 C6 41 55 49 89 F5 31 F6 41 54 41 89 FC 55 48 89 D5 BA 01 00 00 00 53 48 89 CB 48 83 EC 08 E8 ?? ?? ?? ?? 48 83 F8 FF 49 89 C7 74 60 31 D2 48 89 DE 44 89 E7 E8 ?? ?? ?? ?? 48 FF C0 74 4E 41 FF CE 75 10 48 89 EA 4C 89 EE 44 89 E7 E8 ?? ?? ?? ?? EB 0E 48 89 EA 4C 89 EE 44 89 E7 E8 ?? ?? ?? ?? 48 89 C5 E8 ?? ?? ?? ?? 31 D2 4C 89 FE 44 89 E7 48 89 C3 44 8B 28 E8 ?? ?? ?? ?? 48 FF C0 75 06 48 83 FD FF 75 05 44 89 2B EB 04 48 83 CD FF 59 5B 48 89 E8 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule __fake_pread_write64_71ea050877978e644d96e2df86cc0581 {
	meta:
		aliases = "__fake_pread_write64"
		size = "165"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 45 89 C6 41 55 49 89 F5 31 F6 41 54 41 89 FC 55 48 89 D5 BA 01 00 00 00 53 48 89 CB 48 83 EC 08 E8 ?? ?? ?? ?? 48 83 F8 FF 49 89 C7 74 60 31 D2 48 89 DE 44 89 E7 E8 ?? ?? ?? ?? 48 FF C0 74 4E 41 FF CE 75 10 48 89 EA 4C 89 EE 44 89 E7 E8 ?? ?? ?? ?? EB 0E 48 89 EA 4C 89 EE 44 89 E7 E8 ?? ?? ?? ?? 48 89 C5 E8 ?? ?? ?? ?? 31 D2 4C 89 FE 44 89 E7 48 89 C3 44 8B 28 E8 ?? ?? ?? ?? 48 FF C0 75 06 48 83 FD FF 75 05 44 89 2B EB 04 48 83 CD FF 5A 5B 48 89 E8 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule __GI_setvbuf_98a18e8a04b6e35eea7e18a576b220a5 {
	meta:
		aliases = "setvbuf, __GI_setvbuf"
		size = "282"
		objfiles = "setvbuf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 CE 41 55 41 89 D5 41 54 49 89 F4 55 48 89 FD 53 48 83 EC 28 44 8B 7F 50 45 85 FF 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 41 83 FD 02 76 13 83 CB FF E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 9F 00 00 00 8B 45 00 83 CB FF A9 CF 08 00 00 0F 85 8E 00 00 00 80 E4 FC 66 89 45 00 44 89 E8 C1 E0 08 66 09 45 00 41 83 FD 02 0F 94 C2 4D 85 F6 0F 94 C0 08 C2 74 0A 31 DB 45 31 E4 45 31 F6 EB 28 31 DB 4D 85 E4 75 21 48 8B 45 10 48 2B 45 08 4C 39 F0 74 4C 4C 89 F7 E8 ?? ?? ?? ?? 48 85 C0 49 89 C4 74 3C 66 BB 00 40 8B 45 00 F6 C4 40 74 10 48 8B 7D }
	condition:
		$pattern
}

rule __GI_memcmp_4e92cf00daf415d15793163566a7f321 {
	meta:
		aliases = "bcmp, memcmp, __GI_memcmp"
		size = "755"
		objfiles = "memcmp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 D6 41 55 41 54 55 53 48 83 EC 10 48 83 FA 0F 77 20 E9 C1 02 00 00 0F B6 06 0F B6 17 48 29 C2 48 89 D0 0F 85 7B 02 00 00 48 FF C7 48 FF C6 49 FF CE 40 F6 C6 07 48 89 74 24 08 75 DA 48 89 F8 49 89 FF 83 E0 07 0F 85 D8 00 00 00 4C 89 F2 48 C1 EA 03 48 89 D0 83 E0 03 48 83 F8 01 74 46 72 33 48 83 F8 03 48 8B 0E 48 8B 07 74 14 49 89 C1 48 83 EF 10 48 89 C8 48 83 EE 10 48 83 C2 02 EB 67 49 89 C2 49 89 C8 48 83 EF 08 48 83 EE 08 48 FF C2 EB 47 48 85 D2 0F 84 FA 01 00 00 48 8B 0F 48 8B 06 EB 1E 48 FF CA 4C 8B 17 4C 8B 06 74 60 48 83 C7 08 48 83 C6 08 4D 39 C2 48 8B 0F 48 8B 06 75 56 }
	condition:
		$pattern
}

rule ptsname_r_f0e7c3911ea2f2efc64b797fa7329437 {
	meta:
		aliases = "__GI_ptsname_r, ptsname_r"
		size = "171"
		objfiles = "ptsname@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 D6 41 55 49 89 F5 41 54 55 53 89 FB 48 83 EC 18 E8 ?? ?? ?? ?? 48 8D 54 24 0C 44 8B 38 49 89 C4 BE 30 54 04 80 31 C0 89 DF E8 ?? ?? ?? ?? 85 C0 75 57 48 63 74 24 0C 48 8D 7C 24 0B 48 89 E3 31 C9 BA F6 FF FF FF E8 ?? ?? ?? ?? 48 29 C3 48 89 C5 48 83 C3 15 49 39 DE 73 0F B8 22 00 00 00 41 C7 04 24 22 00 00 00 EB 2D BE ?? ?? ?? ?? 4C 89 EF E8 ?? ?? ?? ?? 48 89 EE 4C 89 EF E8 ?? ?? ?? ?? 31 C0 45 89 3C 24 EB 0D 41 C7 04 24 19 00 00 00 B8 19 00 00 00 48 83 C4 18 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule getaddrinfo_9828334668fdbbad22ec43e1801c3408 {
	meta:
		aliases = "__GI_getaddrinfo, getaddrinfo"
		size = "697"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 FE 41 55 41 54 49 89 D4 55 48 89 F5 53 48 81 EC 88 00 00 00 48 85 FF 48 89 4C 24 08 48 C7 44 24 78 00 00 00 00 74 12 80 3F 2A 75 0D 80 7F 01 00 B8 00 00 00 00 4C 0F 44 F0 48 85 ED 74 13 80 7D 00 2A 75 0D 80 7D 01 00 B8 00 00 00 00 48 0F 44 E8 4C 89 F0 48 09 E8 0F 84 38 02 00 00 4D 85 E4 75 17 48 8D 5C 24 30 BA 30 00 00 00 31 F6 48 89 DF 49 89 DC E8 ?? ?? ?? ?? 41 8B 14 24 F7 C2 C0 FB FF FF 0F 85 13 02 00 00 D1 EA 4D 85 F6 0F 94 C0 84 C2 0F 85 03 02 00 00 48 85 ED 74 6D 80 7D 00 00 74 67 48 8D 74 24 70 BA 0A 00 00 00 48 89 EF 48 89 6C 24 60 E8 ?? ?? ?? ?? 89 44 24 68 48 8B 44 }
	condition:
		$pattern
}

rule __GI_strptime_51021606085b301736f2225ef9a82633 {
	meta:
		aliases = "strptime, __GI_strptime"
		size = "1065"
		objfiles = "strptime@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 FE 41 55 41 54 55 53 48 81 EC 98 00 00 00 48 89 54 24 08 31 D2 48 63 C2 FF C2 83 FA 0C C7 44 84 20 00 00 00 80 7E EE 49 89 F5 C7 44 24 14 00 00 00 00 41 8A 45 00 84 C0 75 50 83 7C 24 14 00 75 39 83 7C 24 38 07 8B 44 24 14 0F 45 44 24 38 31 C9 89 44 24 38 48 63 D1 8B 44 94 20 3D 00 00 00 80 74 08 48 8B 5C 24 08 89 04 93 FF C1 83 F9 07 7E E3 4C 89 F7 E9 94 03 00 00 FF 4C 24 14 48 63 44 24 14 4C 8B 6C C4 60 EB A8 3C 25 0F 85 44 03 00 00 49 FF C5 41 8A 4D 00 80 F9 25 0F 84 34 03 00 00 80 F9 4F BE 3F 00 00 00 0F 94 C2 80 F9 45 0F 94 C0 08 C2 74 16 80 F9 4F BE 40 00 00 00 B8 80 FF }
	condition:
		$pattern
}

rule __prefix_array_124160f11ad61a9b0f5aa8a20eed3cfd {
	meta:
		aliases = "__prefix_array"
		size = "201"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 FE 41 55 41 54 55 53 48 83 EC 18 48 89 74 24 10 48 89 54 24 08 E8 ?? ?? ?? ?? 48 83 F8 01 49 89 C5 75 0B 45 31 ED 41 80 3E 2F 41 0F 95 C5 45 31 E4 EB 78 48 8B 44 24 10 4A 8D 2C E0 48 8B 7D 00 E8 ?? ?? ?? ?? 4A 8D 7C 28 02 4C 8D 78 01 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 75 1F EB 11 48 8B 44 24 10 49 FF CC 4A 8B 3C E0 E8 ?? ?? ?? ?? 4D 85 E4 75 EA B8 01 00 00 00 EB 3A 4C 89 EA 4C 89 F6 48 89 C7 E8 ?? ?? ?? ?? C6 00 2F 48 8B 75 00 48 8D 78 01 4C 89 FA 49 FF C4 E8 ?? ?? ?? ?? 48 8B 7D 00 E8 ?? ?? ?? ?? 48 89 5D 00 4C 3B 64 24 08 72 81 31 C0 48 83 C4 18 5B 5D 41 5C 41 5D 41 5E 41 5F }
	condition:
		$pattern
}

rule __ivaliduser2_42f7253fdb18cb41b0d6b558940da3fd {
	meta:
		aliases = "__ivaliduser2"
		size = "773"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 FE 41 55 41 54 55 53 48 83 EC 68 89 74 24 18 48 89 54 24 10 48 89 4C 24 08 48 C7 44 24 50 00 00 00 00 48 C7 44 24 48 00 00 00 00 E9 96 02 00 00 48 8B 54 24 50 48 8B 44 24 48 C6 44 02 FF 00 48 8B 5C 24 50 48 8B 35 ?? ?? ?? ?? 48 89 DA EB 03 48 FF C2 8A 0A 84 C9 74 0A 48 0F BE C1 F6 04 46 20 75 ED 84 C9 0F 94 C2 80 F9 23 0F 94 C0 09 D0 A8 01 0F 85 4E 02 00 00 BE 0A 00 00 00 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 75 44 49 8B 46 18 49 3B 46 28 73 0C 0F B6 08 48 FF C0 49 89 46 18 EB 0A 4C 89 F7 E8 ?? ?? ?? ?? 89 C1 83 F9 0A 0F 95 C2 FF C1 0F 95 C0 84 D0 75 D1 E9 08 02 00 00 48 8B 05 ?? }
	condition:
		$pattern
}

rule classify_object_over_fdes_1826a6adfc559fd0e514634d3b53e34d {
	meta:
		aliases = "classify_object_over_fdes"
		size = "336"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 FE 41 55 41 54 55 53 48 89 F3 48 83 EC 28 44 8B 06 48 C7 44 24 08 00 00 00 00 45 85 C0 0F 84 F7 00 00 00 48 8D 44 24 20 31 D2 45 31 FF 48 C7 44 24 10 00 00 00 00 48 89 04 24 EB 28 48 FF 44 24 08 49 39 16 0F 86 C2 00 00 00 49 89 16 4C 89 E2 8B 03 48 01 D8 8B 78 04 48 8D 58 04 85 FF 0F 84 B6 00 00 00 8B 43 04 85 C0 74 E5 4C 8D 63 04 48 98 41 0F B6 EF 49 29 C4 49 39 D4 74 44 4C 89 E7 E8 A5 FB FF FF 0F B6 E8 4C 89 F6 41 89 C7 89 EF E8 85 F9 FF FF 48 89 44 24 10 41 8B 46 20 66 25 F8 07 66 3D F8 07 0F 84 82 00 00 00 41 8B 46 20 66 C1 E8 03 0F B6 C0 41 39 C7 74 05 41 80 4E 20 04 48 }
	condition:
		$pattern
}

rule __decode_answer_5caf42eb1bd16c18b8a50ed304e0f661 {
	meta:
		aliases = "__decode_answer"
		size = "242"
		objfiles = "decodea@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 FE 41 55 41 89 F5 41 54 49 89 CC B9 00 01 00 00 55 53 89 D3 48 81 EC 18 01 00 00 4C 8D 7C 24 10 4C 89 FA E8 ?? ?? ?? ?? 85 C0 89 C5 0F 88 A6 00 00 00 41 01 C5 44 29 EB 83 EB 0A 89 5C 24 0C 79 07 89 DD E9 90 00 00 00 49 63 DD 4C 89 FF 49 8D 1C 1E E8 ?? ?? ?? ?? 49 89 04 24 0F B6 03 48 8D 73 04 0F B6 53 01 C1 E0 08 09 D0 41 89 44 24 08 0F B6 43 02 0F B6 53 03 C1 E0 08 09 D0 41 89 44 24 0C 0F B6 53 04 0F B6 46 01 0F B6 4E 02 C1 E2 18 C1 E0 10 C1 E1 08 09 C2 0F B6 46 03 09 C2 09 D1 41 89 4C 24 10 0F B6 43 08 0F B6 53 09 48 83 C3 0A 49 89 5C 24 18 C1 E0 08 09 D0 41 8D 55 0A 41 89 }
	condition:
		$pattern
}

rule getdelim_baa89f927cffc9324e328d86b4df8ff8 {
	meta:
		aliases = "__GI_getdelim, getdelim"
		size = "280"
		objfiles = "getdelim@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 FE 41 55 49 89 F5 41 54 55 48 89 CD 53 48 83 EC 38 48 85 FF 89 54 24 0C 0F 94 C2 48 85 F6 0F 94 C0 08 C2 75 05 48 85 C9 75 1D 48 83 CD FF E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 C2 00 00 00 48 83 CD FF E9 A5 00 00 00 44 8B 79 50 45 85 FF 75 1E 48 8D 59 58 48 8D 7C 24 10 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 49 8B 1E 48 85 DB 75 08 49 C7 45 00 00 00 00 00 41 BC 01 00 00 00 49 8B 45 00 49 39 C4 72 1C 48 8D 70 40 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 9D 49 83 45 00 40 49 89 06 48 8B 45 18 48 3B 45 28 73 0C 0F B6 10 48 FF C0 48 89 45 18 EB 0A 48 89 EF }
	condition:
		$pattern
}

rule _wstdio_fwrite_e19293d1b38bd918a8a451d5365beb70 {
	meta:
		aliases = "_wstdio_fwrite"
		size = "249"
		objfiles = "_wfwrite@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 FE 41 55 49 89 F5 41 54 55 48 89 D5 53 48 83 EC 58 83 7A 04 FD 75 3E 48 8B 7A 18 48 8B 42 10 48 29 F8 48 C1 F8 02 48 39 C6 48 89 C3 48 0F 46 DE 48 85 DB 0F 84 A8 00 00 00 48 89 DA 4C 89 F6 E8 ?? ?? ?? ?? 48 8D 04 9D 00 00 00 00 48 01 45 18 E9 8C 00 00 00 0F B7 02 25 40 08 00 00 3D 40 08 00 00 74 16 BE 00 08 00 00 48 89 D7 E8 ?? ?? ?? ?? 85 C0 74 05 45 31 ED EB 67 45 31 E4 4C 89 74 24 48 EB 55 4C 89 EA 48 8D 74 24 48 4C 8D 45 48 4C 29 E2 B9 40 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 83 F8 FF 48 89 C3 74 35 48 85 C0 75 0C 4B 8D 44 A6 04 B3 01 48 89 44 24 48 48 89 EA 48 89 DE 48 89 }
	condition:
		$pattern
}

rule hsearch_r_1ed8c117b7ce9b63d4f3427a77651e89 {
	meta:
		aliases = "__GI_hsearch_r, hsearch_r"
		size = "417"
		objfiles = "hsearch_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 4D 89 C6 41 55 41 54 55 53 48 83 EC 48 48 89 74 24 18 48 89 4C 24 08 48 89 74 24 40 48 89 7C 24 20 89 54 24 14 48 89 7C 24 38 E8 ?? ?? ?? ?? 89 C6 89 C1 EB 13 48 8B 5C 24 20 89 CA 89 F0 C1 E0 04 0F BE 14 13 8D 34 10 FF C9 83 F9 FF 75 E6 41 8B 46 08 31 D2 49 8B 0E 89 44 24 2C 89 F0 48 89 CB F7 74 24 2C B8 01 00 00 00 48 89 4C 24 30 85 D2 89 D5 0F 44 E8 89 E8 48 6B C0 18 48 01 C3 8B 03 85 C0 74 75 39 E8 75 1B 48 8B 73 08 48 8B 7C 24 20 E8 ?? ?? ?? ?? 85 C0 75 09 48 8D 43 08 E9 B3 00 00 00 8B 54 24 2C 89 E8 89 EB 83 EA 02 89 D1 31 D2 F7 F1 44 8D 6A 01 44 39 EB 77 04 03 5C 24 2C 44 29 }
	condition:
		$pattern
}

rule getsubopt_97576bfdfb65de437b8f5f20aee4e09a {
	meta:
		aliases = "getsubopt"
		size = "235"
		objfiles = "getsubopt@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 83 CF FF 41 56 41 55 41 54 55 53 48 83 EC 18 48 89 7C 24 10 48 89 74 24 08 48 89 14 24 48 8B 2F 80 7D 00 00 0F 84 AC 00 00 00 BE 2C 00 00 00 48 89 EF E8 ?? ?? ?? ?? 48 89 C2 BE 3D 00 00 00 48 89 EF 48 29 EA 48 89 C3 E8 ?? ?? ?? ?? 48 85 C0 49 89 C5 4C 0F 44 EB 45 31 FF EB 4B 4D 89 EE 4C 89 E6 48 89 EF 49 29 EE 4C 89 F2 E8 ?? ?? ?? ?? 85 C0 75 30 43 80 3C 34 00 75 29 49 8D 55 01 31 C0 49 39 DD 48 0F 45 C2 48 8B 14 24 48 89 02 80 3B 00 74 06 C6 03 00 48 FF C3 48 8B 44 24 10 48 89 18 EB 32 41 FF C7 48 8B 54 24 08 49 63 C7 4C 8B 24 C2 4D 85 E4 75 A4 48 8B 04 24 48 89 28 80 3B 00 74 06 C6 }
	condition:
		$pattern
}

rule do_des_4e3695d1d83ed7bea14268790166cd2d {
	meta:
		aliases = "do_des"
		size = "752"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 83 F8 00 89 F8 41 56 49 89 D6 BA 01 00 00 00 41 55 41 54 45 89 C4 55 53 89 F3 48 89 4C 24 F8 0F 84 BB 02 00 00 7E 0E 41 BF ?? ?? ?? ?? 41 BD ?? ?? ?? ?? EB 0F 41 F7 DC 41 BF ?? ?? ?? ?? 41 BD ?? ?? ?? ?? 41 89 C1 48 89 C1 89 DA 41 C1 E9 18 48 C1 E9 10 C1 EA 18 44 0F B6 C0 48 89 DE 0F B6 C4 89 D2 45 89 C9 81 E1 FF 00 00 00 49 89 C2 45 89 C0 48 C1 EE 10 44 8B 1C 95 ?? ?? ?? ?? 44 0B 1C 85 ?? ?? ?? ?? 0F B6 FB 8B 04 8D ?? ?? ?? ?? 42 0B 04 8D ?? ?? ?? ?? 81 E6 FF 00 00 00 42 0B 04 85 ?? ?? ?? ?? 0F B6 EF 89 FF 0B 04 B5 ?? ?? ?? ?? 44 0B 1C AD ?? ?? ?? ?? 0B 04 BD ?? ?? ?? ?? 8B 1C 95 ?? }
	condition:
		$pattern
}

rule __GI_authunix_create_f0c0fb94002dbfb829ebf07bc5954fad {
	meta:
		aliases = "authunix_create, __GI_authunix_create"
		size = "401"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 CF 41 56 41 89 D6 41 55 41 89 F5 41 54 49 89 FC BF 48 00 00 00 55 53 48 81 EC 18 02 00 00 4C 89 44 24 08 E8 ?? ?? ?? ?? BF D0 01 00 00 48 89 C5 E8 ?? ?? ?? ?? 48 85 ED 48 89 C3 0F 94 C2 48 85 C0 0F 94 C0 08 C2 74 28 48 8B 35 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 EF 31 ED E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? E9 08 01 00 00 FC 48 C7 45 38 ?? ?? ?? ?? 48 89 5D 40 48 8D 7B 18 BE ?? ?? ?? ?? B9 06 00 00 00 F3 A5 48 8D 7D 18 48 8D 73 18 B1 06 F3 A5 48 8D BC 24 00 02 00 00 31 F6 48 C7 43 30 00 00 00 00 E8 ?? ?? ?? ?? 48 8B 84 24 00 02 00 00 4C 89 A4 24 D8 01 00 00 4C 8D A4 24 }
	condition:
		$pattern
}

rule __GI_pmap_getport_70eb86aa1904177286428dc5d1b44dc1 {
	meta:
		aliases = "pmap_getport, __GI_pmap_getport"
		size = "282"
		objfiles = "pm_getport@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 CF 41 56 49 89 D6 BA 02 00 00 00 41 55 49 89 F5 BE A0 86 01 00 41 54 49 89 FC 55 53 48 83 EC 48 48 8B 0D ?? ?? ?? ?? 4C 8B 05 ?? ?? ?? ?? 4C 8D 4C 24 38 66 C7 44 24 3E 00 00 C7 44 24 38 FF FF FF FF 66 C7 47 02 00 6F C7 44 24 08 90 01 00 00 C7 04 24 90 01 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 0F 84 92 00 00 00 E8 ?? ?? ?? ?? 48 89 C5 48 8B 05 ?? ?? ?? ?? 45 89 FF 4C 89 6C 24 10 4C 89 74 24 18 48 8D 4C 24 10 4C 89 7C 24 20 48 C7 44 24 28 00 00 00 00 4C 8D 4C 24 3E 4C 8B 53 08 48 89 04 24 41 B8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? BA ?? ?? ?? ?? BE 03 00 00 00 48 89 DF 48 89 44 24 08 41 }
	condition:
		$pattern
}

rule inet_ntop_8b2266c712b12e7be9392cb19ae37df3 {
	meta:
		aliases = "__GI_inet_ntop, inet_ntop"
		size = "527"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 CF 41 56 49 89 F6 41 55 41 54 55 53 48 83 EC 68 83 FF 02 48 89 54 24 08 74 0B 83 FF 0A 0F 85 C9 01 00 00 EB 14 48 8B 74 24 08 89 CA 4C 89 F7 E8 B0 FE FF FF E9 AE 01 00 00 48 8D 7C 24 40 BA 20 00 00 00 31 F6 E8 ?? ?? ?? ?? 31 C9 EB 27 89 C8 BE 02 00 00 00 48 63 F9 99 83 C1 02 F7 FE 41 0F B6 54 3E 01 48 63 F0 41 0F B6 04 3E C1 E0 08 09 D0 89 44 B4 40 83 F9 0F 7E D4 41 83 CC FF 31 C9 44 89 E2 EB 37 48 63 C1 83 7C 84 40 00 75 12 83 FA FF 75 09 89 CA BB 01 00 00 00 EB 1D FF C3 EB 19 83 FA FF 74 14 41 83 FC FF 74 05 44 39 EB 7E 06 41 89 DD 41 89 D4 83 CA FF FF C1 83 F9 07 7E C4 83 FA FF }
	condition:
		$pattern
}

rule svcunix_create_d629c54aca11b0a65e24d133bfe6197d {
	meta:
		aliases = "svcunix_create"
		size = "394"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 D7 41 56 41 89 F6 41 55 45 31 ED 41 54 49 89 CC 55 89 FD 53 48 81 EC 88 00 00 00 83 FF FF C7 44 24 7C 10 00 00 00 75 29 31 D2 BE 01 00 00 00 BF 01 00 00 00 E8 ?? ?? ?? ?? 85 C0 89 C5 41 B5 01 79 0F BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 D7 00 00 00 31 F6 BA 6E 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 4C 89 E7 66 C7 04 24 01 00 E8 ?? ?? ?? ?? FF C0 48 8D 7C 24 02 4C 89 E6 89 C2 89 44 24 7C E8 ?? ?? ?? ?? 8B 54 24 7C 48 89 E6 89 EF 83 C2 02 89 54 24 7C E8 ?? ?? ?? ?? 48 8D 54 24 7C 48 89 E6 89 EF E8 ?? ?? ?? ?? 85 C0 75 10 BE 02 00 00 00 89 EF E8 ?? ?? ?? ?? 85 C0 74 22 BF ?? ?? ?? ?? 45 31 E4 E8 }
	condition:
		$pattern
}

rule svctcp_create_8a19d24e40e3c1d79e7f0099afd4cf3f {
	meta:
		aliases = "svctcp_create"
		size = "380"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 D7 41 56 41 89 F6 41 55 45 31 ED 41 54 55 89 FD 53 48 83 EC 28 83 FF FF C7 44 24 1C 10 00 00 00 75 2C BA 06 00 00 00 BE 01 00 00 00 BF 02 00 00 00 E8 ?? ?? ?? ?? 85 C0 89 C5 41 B5 01 79 0F BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 C8 00 00 00 31 F6 BA 10 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 89 EF 48 89 E6 66 C7 04 24 02 00 E8 ?? ?? ?? ?? 85 C0 74 15 8B 54 24 1C 48 89 E6 89 EF 66 C7 44 24 02 00 00 E8 ?? ?? ?? ?? 48 8D 54 24 1C 48 89 E6 89 EF E8 ?? ?? ?? ?? 85 C0 75 10 BE 02 00 00 00 89 EF E8 ?? ?? ?? ?? 85 C0 74 22 BF ?? ?? ?? ?? 45 31 E4 E8 ?? ?? ?? ?? 45 85 ED 0F 84 A7 00 00 00 89 EF E8 ?? ?? }
	condition:
		$pattern
}

rule __encode_dotted_8e15c62ab73c216eec67ec1e9888949d {
	meta:
		aliases = "__encode_dotted"
		size = "160"
		objfiles = "encoded@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 D7 41 56 49 89 F6 41 55 41 54 49 89 FC 55 53 31 DB 48 83 EC 08 EB 59 BE 2E 00 00 00 4C 89 E7 E8 ?? ?? ?? ?? 48 85 C0 49 89 C5 74 07 89 C5 44 29 E5 EB 0A 4C 89 E7 E8 ?? ?? ?? ?? 89 C5 85 ED 74 4C 44 89 F8 29 D8 FF C8 39 C5 73 41 89 D8 FF C3 48 63 D5 89 DF 41 88 2C 06 4C 89 E6 49 8D 3C 3E 01 EB E8 ?? ?? ?? ?? 4D 85 ED 74 10 4D 8D 65 01 4D 85 E4 74 07 41 80 3C 24 00 75 9B 45 85 FF 7E 0C 89 D8 41 C6 04 06 00 8D 43 01 EB 03 83 C8 FF 5A 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule do_dlclose_6aee3ee5edfea15c7fb316ee7b75aadd {
	meta:
		aliases = "do_dlclose"
		size = "625"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 F7 41 56 41 55 49 89 FD 41 54 55 53 48 83 EC 08 48 3B 3D ?? ?? ?? ?? 0F 84 42 02 00 00 48 8B 05 ?? ?? ?? ?? 31 D2 EB 0C 4C 39 E8 74 1E 48 89 C2 48 8B 40 08 48 85 C0 75 EF B0 01 48 C7 05 ?? ?? ?? ?? 09 00 00 00 E9 16 02 00 00 48 85 D2 49 8B 45 08 74 06 48 89 42 08 EB 07 48 89 05 ?? ?? ?? ?? 49 8B 55 00 45 31 F6 8B 42 40 66 83 F8 01 0F 84 9E 01 00 00 FF C8 4C 89 EF 66 89 42 40 E8 ?? ?? ?? ?? E9 D7 01 00 00 4C 8B 24 C7 66 41 FF 4C 24 40 66 41 83 7C 24 40 00 0F 85 71 01 00 00 49 83 BC 24 E8 00 00 00 00 75 0B 49 83 BC 24 50 01 00 00 00 74 33 45 85 FF 74 2E 66 41 8B 44 24 42 A8 08 75 24 }
	condition:
		$pattern
}

rule _dl_load_elf_shared_library_c858488db7bd8000f7b18ceaaed96fed {
	meta:
		aliases = "_dl_load_elf_shared_library"
		size = "2698"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 F8 B8 02 00 00 00 41 56 41 55 41 54 55 53 48 81 EC 08 02 00 00 48 89 14 24 48 89 74 24 08 31 D2 31 F6 48 8B 3C 24 0F 05 48 3D 00 F0 FF FF 76 0C F7 D8 89 05 ?? ?? ?? ?? 48 83 C8 FF 85 C0 79 10 48 C7 05 ?? ?? ?? ?? 01 00 00 00 E9 1F 0A 00 00 4C 63 F8 48 8D B4 24 70 01 00 00 B8 05 00 00 00 4C 89 FF 0F 05 48 3D 00 F0 FF FF 48 89 C2 76 0A F7 D8 89 05 ?? ?? ?? ?? EB 04 85 D2 79 0D 48 C7 05 ?? ?? ?? ?? 01 00 00 00 EB 0F 45 85 C0 74 19 F6 84 24 89 01 00 00 08 75 0F 4C 89 FF B8 03 00 00 00 0F 05 E9 A7 07 00 00 48 8B 2D ?? ?? ?? ?? EB 39 48 8B 84 24 70 01 00 00 48 39 85 B8 01 00 00 75 24 48 }
	condition:
		$pattern
}

rule __GI_getprotobynumber_r_66f84a94c71375bdbc097edda78cb8c0 {
	meta:
		aliases = "getprotobynumber_r, __GI_getprotobynumber_r"
		size = "156"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 FF 41 56 49 89 D6 BA ?? ?? ?? ?? 41 55 49 89 CD 41 54 4D 89 C4 55 48 89 F5 BE ?? ?? ?? ?? 53 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 06 44 39 7D 10 74 17 4C 89 E1 4C 89 EA 4C 89 F6 48 89 EF E8 ?? ?? ?? ?? 85 C0 89 C3 74 E3 83 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 49 83 3C 24 00 B8 00 00 00 00 0F 45 D8 48 83 C4 28 89 D8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule pselect_78e59bf3565f7599350449d619c38623 {
	meta:
		aliases = "__libc_pselect, pselect"
		size = "174"
		objfiles = "pselect@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 FF 41 56 49 89 F6 41 55 49 89 D5 41 54 49 89 CC 55 4C 89 CD 53 4C 89 C3 48 81 EC 98 00 00 00 4D 85 C0 74 24 49 8B 00 BA E8 03 00 00 48 89 D1 48 89 84 24 80 00 00 00 49 8B 40 08 48 99 48 F7 F9 48 89 84 24 88 00 00 00 48 85 ED 74 10 48 89 E2 48 89 EE BF 02 00 00 00 E8 ?? ?? ?? ?? 48 8D 84 24 80 00 00 00 45 31 C0 48 85 DB 4C 89 E1 4C 89 EA 4C 89 F6 4C 0F 45 C0 44 89 FF E8 ?? ?? ?? ?? 48 85 ED 89 C3 74 0F 48 89 E6 31 D2 BF 02 00 00 00 E8 ?? ?? ?? ?? 48 81 C4 98 00 00 00 89 D8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule initstate_1fa3fa5664eae3c90d27ad14d1c3ee5a {
	meta:
		aliases = "initstate"
		size = "110"
		objfiles = "random@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 FF 41 56 49 89 F6 BE ?? ?? ?? ?? 41 55 49 89 D5 BA ?? ?? ?? ?? 41 54 53 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? 4C 89 EA 4C 89 F6 44 89 FF B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 EB 04 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 48 89 D8 5B 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule __decode_dotted_6c3a63481bbb6290764727f50aa9c266 {
	meta:
		aliases = "__decode_dotted"
		size = "246"
		objfiles = "decoded@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 B8 01 00 00 00 41 56 49 89 FE 41 55 45 31 ED 41 54 55 53 48 83 EC 18 89 4C 24 0C 31 C9 48 85 FF 48 89 54 24 10 0F 85 9A 00 00 00 E9 B1 00 00 00 41 80 F8 01 89 D8 8D 6E 01 41 83 DD FF 25 C0 00 00 00 3D C0 00 00 00 75 22 48 63 C5 41 80 F8 01 89 DE 41 0F B6 04 06 41 83 DD FF 83 E6 3F C1 E6 08 41 89 CC 45 31 C0 09 C6 EB 57 44 8D 3C 19 45 8D 67 01 44 3B 64 24 0C 73 67 89 CF 48 03 7C 24 10 48 63 F5 49 8D 34 36 48 63 D3 44 88 04 24 E8 ?? ?? ?? ?? 44 8A 04 24 41 8D 44 1D 00 8D 74 1D 00 48 8B 4C 24 10 44 89 FA 45 84 C0 44 0F 45 E8 48 63 C6 41 80 3C 06 01 19 C0 F7 D0 83 E0 2E 88 04 11 44 89 E1 }
	condition:
		$pattern
}

rule _dl_lookup_hash_05c40b24c913046ead6bca4c72a195dd {
	meta:
		aliases = "_dl_lookup_hash"
		size = "332"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 BF FF FF FF FF 41 56 41 55 49 89 D5 41 54 49 89 F4 55 53 48 83 EC 20 48 89 7C 24 10 89 4C 24 0C E9 EF 00 00 00 49 8B 1C 24 48 8B 43 48 80 F4 01 48 C1 E8 08 4D 85 ED 0F 95 C2 84 D0 74 1E 49 39 DD 74 19 49 8B 45 68 EB 09 48 39 58 08 74 0D 48 8B 00 48 85 C0 75 F2 E9 B3 00 00 00 F6 44 24 0C 02 74 0A 83 7B 30 01 0F 84 A2 00 00 00 8B 7B 50 85 FF 0F 84 97 00 00 00 48 8B 83 B0 00 00 00 31 C9 48 8B 74 24 10 48 89 44 24 18 B8 FF FF FF FF 49 39 C7 74 25 EB 2C 48 C1 E1 04 0F B6 D0 48 FF C6 48 8D 14 11 48 89 D0 48 89 D1 25 00 00 00 F0 48 31 C1 48 C1 E8 18 48 31 C1 8A 06 84 C0 75 D7 41 89 CF 89 FA }
	condition:
		$pattern
}

rule __read_etc_hosts_r_f4e32d7d28c5c98e090228adda33526a {
	meta:
		aliases = "__read_etc_hosts_r"
		size = "830"
		objfiles = "read_etc_hosts_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 44 89 C8 F7 D8 41 56 41 55 4D 89 C5 41 54 55 53 4C 89 CB 48 83 EC 48 83 E0 07 89 54 24 0C 48 89 7C 24 18 48 89 74 24 10 89 4C 24 08 48 8B 94 24 80 00 00 00 74 11 48 98 48 39 C2 0F 82 E3 02 00 00 48 01 C3 48 29 C2 48 83 FA 3F 0F 86 D3 02 00 00 83 7C 24 08 01 48 8D 43 40 4C 8D 72 C0 48 89 44 24 40 0F 84 3A 01 00 00 48 8B 84 24 90 00 00 00 49 83 FE 03 C7 00 FF FF FF FF 0F 86 A3 02 00 00 48 8D 42 BC 48 83 F8 0F 0F 86 95 02 00 00 49 83 FE 0F 0F 86 8B 02 00 00 48 8D 42 B0 48 83 F8 0F 0F 86 7D 02 00 00 4C 8D 72 AC 48 8D 42 A0 4C 8D 63 44 4C 8D 7B 50 48 8D 6B 54 4C 39 F0 73 07 48 8D 6B 60 49 89 }
	condition:
		$pattern
}

rule svcudp_bufcreate_ecf5b194a5ae9f070053003ab2eee29d {
	meta:
		aliases = "__GI_svcudp_bufcreate, svcudp_bufcreate"
		size = "477"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 45 31 FF 41 56 41 55 41 89 FD 41 54 41 89 D4 55 89 F5 53 48 83 EC 28 83 FF FF C7 44 24 1C 10 00 00 00 75 2D BA 11 00 00 00 BE 02 00 00 00 BF 02 00 00 00 E8 ?? ?? ?? ?? 85 C0 41 89 C5 41 B7 01 79 0F BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 E0 00 00 00 31 F6 BA 10 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 44 89 EF 48 89 E6 66 C7 04 24 02 00 E8 ?? ?? ?? ?? 85 C0 74 16 8B 54 24 1C 48 89 E6 44 89 EF 66 C7 44 24 02 00 00 E8 ?? ?? ?? ?? 48 8D 54 24 1C 48 89 E6 44 89 EF E8 ?? ?? ?? ?? 85 C0 74 23 BF ?? ?? ?? ?? 45 31 F6 E8 ?? ?? ?? ?? 45 85 FF 0F 84 14 01 00 00 44 89 EF E8 ?? ?? ?? ?? E9 07 01 00 00 BF 50 01 00 }
	condition:
		$pattern
}

rule __res_query_299cd7da8970ce626147e8416c4a672e {
	meta:
		aliases = "__GI___res_query, __res_query"
		size = "267"
		objfiles = "res_query@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 45 89 C7 41 56 41 89 D6 41 55 41 54 55 48 89 FD 53 48 81 EC 88 00 00 00 48 85 FF 0F 94 C2 FF CE 48 89 4C 24 08 0F 95 C0 48 C7 44 24 78 00 00 00 00 08 C2 74 0D E8 ?? ?? ?? ?? C7 00 03 00 00 00 EB 7A 48 8D 5C 24 10 31 F6 BA 40 00 00 00 48 89 DF E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 8D 64 24 50 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 44 8B 2D ?? ?? ?? ?? BE 01 00 00 00 4C 89 E7 E8 ?? ?? ?? ?? 4C 8D 44 24 78 49 89 D9 B9 ?? ?? ?? ?? 44 89 EA 44 89 F6 48 89 EF E8 ?? ?? ?? ?? 85 C0 89 C3 79 10 E8 ?? ?? ?? ?? C7 00 02 00 00 00 83 CB FF EB 34 48 8B 7C 24 10 }
	condition:
		$pattern
}

rule __GI_xdr_array_e9b52c0159b7dff82ffa1f8bbd18c1f3 {
	meta:
		aliases = "xdr_array, __GI_xdr_array"
		size = "292"
		objfiles = "xdr_array@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 45 89 C7 41 56 49 89 FE 41 55 41 89 CD 41 54 55 48 89 D5 53 48 83 EC 18 48 89 74 24 10 4C 89 4C 24 08 48 8B 1E 48 89 D6 E8 ?? ?? ?? ?? 85 C0 0F 84 D3 00 00 00 44 8B 65 00 45 39 EC 77 0D 83 C8 FF 31 D2 41 F7 F7 41 39 C4 76 0A 41 83 3E 02 0F 85 B3 00 00 00 48 85 DB 75 5A 41 8B 06 83 F8 01 74 0A 83 F8 02 75 4D E9 A0 00 00 00 45 85 E4 0F 84 97 00 00 00 44 89 E5 41 0F AF EF 48 89 EF E8 ?? ?? ?? ?? 48 89 C3 48 8B 44 24 10 48 85 DB 48 89 18 75 13 48 8B 35 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 61 48 89 EA 31 F6 48 89 DF E8 ?? ?? ?? ?? 45 31 ED BD 01 00 00 00 EB 1A 48 89 DE 83 CA FF 4C 89 }
	condition:
		$pattern
}

rule __GI___res_querydomain_c7c3c74a8c034c8c8d1d2537e37cfd76 {
	meta:
		aliases = "__res_querydomain, __GI___res_querydomain"
		size = "334"
		objfiles = "res_query@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 45 89 CF 41 56 4D 89 C6 41 55 41 54 49 89 FC 55 48 89 F5 BE ?? ?? ?? ?? 53 48 81 EC 48 04 00 00 48 8D 9C 24 20 04 00 00 89 54 24 0C BA ?? ?? ?? ?? 89 4C 24 08 48 89 DF E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 DF 4C 8B 2D ?? ?? ?? ?? E8 ?? ?? ?? ?? 4D 85 E4 0F 94 C2 4D 85 F6 0F 94 C0 08 C2 75 0F 41 80 E5 01 75 16 E8 ?? ?? ?? ?? FF C0 75 0D E8 ?? ?? ?? ?? C7 00 FF FF FF FF EB 27 48 85 ED 75 54 4C 89 E7 E8 ?? ?? ?? ?? 48 89 C2 48 8D 40 01 48 3D 01 04 00 00 76 13 E8 ?? ?? ?? ?? C7 00 03 00 00 00 83 C8 FF E9 84 00 00 00 48 85 D2 74 69 48 8D 6A FF 41 80 3C 2C 2E 75 5E }
	condition:
		$pattern
}

rule byte_regex_compile_2088e3bd89a0cb3f3f68a6aeb95774a1 {
	meta:
		aliases = "byte_regex_compile"
		size = "9792"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 48 01 FE 41 56 41 55 41 54 55 48 89 CD 53 48 81 EC 78 01 00 00 48 89 7C 24 08 48 89 BC 24 68 01 00 00 BF 00 05 00 00 48 89 14 24 48 89 74 24 18 48 8B 41 28 48 89 44 24 20 E8 ?? ?? ?? ?? 48 85 C0 48 89 44 24 58 0F 84 33 25 00 00 48 8B 14 24 80 65 38 97 48 C7 45 10 00 00 00 00 48 C7 45 30 00 00 00 00 48 89 55 18 83 3D ?? ?? ?? ?? 00 75 48 BA 00 01 00 00 31 F6 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 31 D2 EB 13 48 63 C2 F6 44 41 01 08 74 07 C6 80 ?? ?? ?? ?? 01 FF C2 81 FA FF 00 00 00 7E E5 C6 05 ?? ?? ?? ?? 01 C7 05 ?? ?? ?? ?? 01 00 00 00 48 83 7D 08 00 75 41 48 8B 7D 00 48 85 }
	condition:
		$pattern
}

rule _dl_parse_158696f97e802856a9900cfbdb6cbe4f {
	meta:
		aliases = "_dl_parse"
		size = "302"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 57 48 89 C8 41 56 45 31 F6 41 55 49 89 FD 41 54 49 89 D4 BA 18 00 00 00 55 53 48 89 D3 31 D2 48 F7 F3 48 83 EC 28 48 89 74 24 18 4C 89 44 24 10 48 89 44 24 08 48 8B 87 B0 00 00 00 48 89 44 24 20 4C 8B BF A8 00 00 00 E9 BF 00 00 00 49 8B 6C 24 08 4D 89 F8 48 8B 4C 24 20 4C 89 E2 48 8B 74 24 18 4C 89 EF FF 54 24 10 85 C0 89 C3 0F 84 92 00 00 00 48 8B 15 ?? ?? ?? ?? 31 C0 48 C1 ED 20 BE ?? ?? ?? ?? BF 02 00 00 00 E8 ?? ?? ?? ?? 85 ED 74 24 48 63 C5 48 8B 4C 24 20 BE ?? ?? ?? ?? 48 6B C0 18 BF 02 00 00 00 8B 14 08 31 C0 49 8D 14 17 E8 ?? ?? ?? ?? 83 FB 00 7D 34 49 8B 54 24 08 31 C0 BE ?? ?? ?? }
	condition:
		$pattern
}

rule memmove_a6c06e32b6594ba680c1304533a662f8 {
	meta:
		aliases = "__GI_memmove, memmove"
		size = "734"
		objfiles = "memmove@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 48 89 F8 48 29 F0 41 56 49 89 FE 41 55 41 54 55 53 48 83 EC 08 48 39 D0 72 0A E8 ?? ?? ?? ?? E9 A9 02 00 00 48 01 D6 48 83 FA 0F 4C 8D 14 17 0F 86 93 02 00 00 4C 89 D1 49 89 D5 83 E1 07 49 29 CD EB 0E 48 FF CE 49 FF CA 48 FF C9 8A 06 41 88 02 48 85 C9 75 ED 48 89 F0 83 E0 07 0F 85 1C 01 00 00 4C 89 EF 45 31 C9 48 89 F1 48 C1 EF 03 4C 89 D0 49 89 F8 41 83 E0 07 49 83 F8 07 0F 87 A4 00 00 00 42 FF 24 C5 ?? ?? ?? ?? 4C 8B 46 F8 48 8D 4E F0 49 8D 42 F8 48 83 C7 06 E9 BF 00 00 00 4C 8B 4E F8 48 8D 4E E8 49 8D 42 F0 48 83 C7 05 E9 A2 00 00 00 4C 8B 46 F8 48 8D 4E E0 49 8D 42 E8 48 83 C7 04 E9 }
	condition:
		$pattern
}

rule _dl_load_shared_library_0d473eaa007cf7857656dd257eed8d78 {
	meta:
		aliases = "_dl_load_shared_library"
		size = "521"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 57 48 8D 41 FF 41 56 41 55 41 89 FD 41 54 49 89 F4 55 53 48 89 D3 48 83 EC 08 48 C7 05 ?? ?? ?? ?? 00 00 00 00 48 FF C0 80 38 00 75 F8 48 29 C8 48 3D 00 04 00 00 0F 87 9E 01 00 00 48 8D 41 FF 31 F6 EB 07 80 FA 2F 48 0F 44 F0 48 FF C0 8A 10 84 D2 75 F0 48 8D 46 01 48 85 F6 48 89 CD 48 0F 45 E8 48 39 CD 74 17 48 89 CA 4C 89 E6 44 89 EF E8 ?? ?? ?? ?? 48 85 C0 0F 85 7E 01 00 00 48 85 DB 74 2A 48 8B 93 F8 00 00 00 48 85 D2 74 1E 48 03 93 A8 00 00 00 4C 89 E1 44 89 EE 48 89 EF E8 13 FE FF FF 48 85 C0 0F 85 4F 01 00 00 48 8B 15 ?? ?? ?? ?? 48 85 D2 74 17 4C 89 E1 44 89 EE 48 89 EF E8 F0 FD FF FF }
	condition:
		$pattern
}

rule __kernel_rem_pio2_e50f1f053054a1f79303daed19b72343 {
	meta:
		aliases = "__kernel_rem_pio2"
		size = "1592"
		objfiles = "k_rem_pio2@libm.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 63 C0 44 8D 79 FF 41 56 49 89 F6 89 D6 8D 4E FD 41 55 41 54 55 53 48 81 EC 98 02 00 00 8B 04 85 ?? ?? ?? ?? 48 89 7C 24 40 BF 18 00 00 00 C7 44 24 5C 00 00 00 00 44 89 44 24 3C 4C 89 4C 24 30 89 44 24 4C 89 C8 8B 5C 24 4C 99 F7 FF 85 C0 89 C1 0F 48 4C 24 5C 31 FF 6B C1 E8 89 CA 89 4C 24 5C 44 29 FA 31 C9 8D 6C 06 E8 41 8D 34 1F EB 2D 48 89 7C 24 08 85 D2 66 0F 12 44 24 08 78 0E 4C 8B 54 24 30 48 63 C2 F2 41 0F 2A 04 82 48 63 C1 FF C2 FF C1 F2 0F 11 84 C4 A0 01 00 00 39 F1 7E CF 31 F6 EB 34 48 8B 5C 24 40 41 8D 04 37 48 63 D1 29 C8 FF C1 66 0F 12 04 D3 48 98 F2 0F 59 84 C4 A0 01 00 00 }
	condition:
		$pattern
}

rule __GI_vsnprintf_335b3a66ebbed5f014bda33ae0dd0c84 {
	meta:
		aliases = "vsnprintf, __GI_vsnprintf"
		size = "199"
		objfiles = "vsnprintf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 CF 41 56 41 55 49 89 F5 41 54 49 89 FC 55 48 89 D5 53 4C 89 E3 48 F7 D3 48 81 EC 88 00 00 00 48 8D 7C 24 58 C7 44 24 04 FE FF FF FF 66 C7 04 24 D0 00 C6 44 24 02 00 C7 44 24 48 00 00 00 00 C7 44 24 50 01 00 00 00 E8 ?? ?? ?? ?? 4C 39 EB 4C 89 FA 48 89 EE 49 0F 47 DD 48 89 E7 48 C7 44 24 38 00 00 00 00 49 8D 04 1C 4C 89 64 24 08 4C 89 64 24 18 4C 89 64 24 20 4C 89 64 24 28 48 89 44 24 10 48 89 44 24 30 E8 ?? ?? ?? ?? 48 85 DB 89 C2 74 1C 48 8B 44 24 10 48 39 44 24 18 75 08 48 FF C8 48 89 44 24 18 48 8B 44 24 18 C6 00 00 48 81 C4 88 00 00 00 89 D0 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule getservent_r_567e9e93ffc864febe6be42d5bed0fbe {
	meta:
		aliases = "__GI_getservent_r, getservent_r"
		size = "485"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 CF 41 56 41 55 49 89 F5 41 54 49 89 FC 55 53 48 89 D3 48 83 EC 28 48 81 FA 17 01 00 00 48 C7 01 00 00 00 00 77 15 BB 22 00 00 00 E8 ?? ?? ?? ?? C7 00 22 00 00 00 E9 95 01 00 00 48 89 E7 BA ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 4D 8D B5 18 01 00 00 E8 ?? ?? ?? ?? 48 8D 83 E8 FE FF FF 48 3D 00 10 00 00 77 15 BB 22 00 00 00 E8 ?? ?? ?? ?? C7 00 22 00 00 00 E9 41 01 00 00 48 83 3D ?? ?? ?? ?? 00 75 30 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 75 15 BB 05 00 00 00 E8 ?? ?? ?? ?? C7 00 05 00 00 00 E9 07 01 00 00 48 8B 15 ?? ?? ?? ?? BE }
	condition:
		$pattern
}

rule __form_query_0fab805473860803f9e63f00ce965f7a {
	meta:
		aliases = "__form_query"
		size = "141"
		objfiles = "formquery@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 CF 41 56 41 89 D6 BA 30 00 00 00 41 55 49 89 F5 31 F6 41 54 41 89 FC 55 44 89 C5 53 48 83 EC 48 48 89 E7 E8 ?? ?? ?? ?? 89 EA 4C 89 FE 48 89 E7 44 89 24 24 C7 44 24 20 01 00 00 00 4C 89 6C 24 30 44 89 74 24 38 C7 44 24 3C 01 00 00 00 E8 ?? ?? ?? ?? 85 C0 89 C3 78 1F 48 63 F0 29 C5 48 8D 7C 24 30 49 8D 34 37 89 EA E8 ?? ?? ?? ?? 8D 14 03 85 C0 89 C3 0F 49 DA 48 83 C4 48 89 D8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule gethostbyaddr_r_f98a9fe4a543207355ff543726bfab65 {
	meta:
		aliases = "__GI_gethostbyaddr_r, gethostbyaddr_r"
		size = "944"
		objfiles = "gethostbyaddr_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 CF 41 56 41 89 F6 41 55 41 54 49 89 FC 55 4C 89 C5 53 4C 89 CB 48 81 EC B8 00 00 00 48 85 FF 48 8B 84 24 F0 00 00 00 89 54 24 1C 48 C7 00 00 00 00 00 0F 84 2E 03 00 00 48 8D 7C 24 40 31 F6 BA 40 00 00 00 E8 ?? ?? ?? ?? 83 7C 24 1C 02 74 0D 83 7C 24 1C 0A 0F 85 0B 03 00 00 EB 06 41 83 FE 04 EB 04 41 83 FE 10 0F 85 F9 02 00 00 48 8B 8C 24 F8 00 00 00 48 8B 84 24 F0 00 00 00 49 89 D9 8B 54 24 1C 49 89 E8 44 89 F6 4C 89 E7 48 89 4C 24 08 4C 89 F9 48 89 04 24 E8 ?? ?? ?? ?? 85 C0 0F 84 F4 02 00 00 48 8B 8C 24 F8 00 00 00 8B 11 83 FA 01 74 09 83 FA 04 0F 85 DC 02 00 00 E8 ?? ?? ?? ?? 48 }
	condition:
		$pattern
}

rule sysctl_f340c471c4b2007611a477a2538a81e3 {
	meta:
		aliases = "sysctl"
		size = "142"
		objfiles = "sysctl@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 CF 41 56 49 89 D6 BA 50 00 00 00 41 55 41 89 F5 31 F6 41 54 49 89 FC 55 4C 89 C5 53 48 83 EC 68 48 8D 5C 24 10 4C 89 4C 24 08 48 89 DF E8 ?? ?? ?? ?? 48 8B 44 24 08 4C 89 64 24 10 48 89 DF 44 89 6C 24 18 4C 89 74 24 20 4C 89 7C 24 28 48 89 6C 24 30 48 89 44 24 38 B8 9C 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 83 C4 68 89 D8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule __regexec_9e3b8d42930314d698ed55f31a20cc73 {
	meta:
		aliases = "regexec, __regexec"
		size = "291"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 CF 41 56 49 89 F6 41 55 41 54 49 89 FC 48 89 F7 55 48 89 D5 53 44 89 C3 48 83 EC 78 E8 ?? ?? ?? ?? 4C 89 E6 41 B9 10 00 00 00 48 8D 7C 24 10 45 33 4C 24 38 B9 10 00 00 00 49 89 C5 FC F3 A5 89 DA 41 C0 E9 04 48 85 ED 8A 44 24 48 41 0F 95 C0 83 E2 01 D1 EB C1 E2 05 83 E3 01 83 E0 9F C1 E3 06 09 D0 09 D8 83 E0 F9 83 C8 04 88 44 24 48 44 89 C0 44 20 C8 41 89 C4 74 1D 48 8D 3C ED 00 00 00 00 89 6C 24 50 E8 ?? ?? ?? ?? 48 85 C0 BA 01 00 00 00 74 79 EB 04 31 C0 EB 13 48 89 44 24 58 48 8D 04 A8 48 89 44 24 60 48 8D 44 24 50 48 8D 7C 24 10 31 C9 49 89 C1 45 89 E8 44 89 EA 4C 89 F6 E8 ?? ?? }
	condition:
		$pattern
}

rule xdrrec_create_902097ddb513b7bcc278f274906e0b6f {
	meta:
		aliases = "__GI_xdrrec_create, xdrrec_create"
		size = "320"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 CF 41 56 49 89 FE BF 80 00 00 00 41 55 41 54 41 89 D4 55 53 89 F3 48 83 EC 18 4C 89 44 24 10 4C 89 4C 24 08 E8 ?? ?? ?? ?? 83 FB 63 48 89 C5 B8 A0 0F 00 00 0F 46 D8 44 8D 6B 03 41 83 E5 FC 41 83 FC 63 44 0F 46 E0 41 83 C4 03 41 83 E4 FC 43 8D 7C 2C 04 E8 ?? ?? ?? ?? 48 85 ED 48 89 C3 0F 94 C2 48 85 C0 0F 94 C0 08 C2 74 2F 48 8B 35 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 48 83 C4 18 48 89 DF 5B 5D 41 5C 41 5D 41 5E 41 5F E9 ?? ?? ?? ?? F6 C3 03 44 89 6D 74 44 89 65 78 48 89 5D 08 48 89 DF 74 0B 48 89 D8 48 83 E0 FC 48 8D 78 04 44 89 E8 48 89 7D 18 48 8D 14 }
	condition:
		$pattern
}

rule getprotobyname_r_38c88446351dc72061c9adf495e0d9bd {
	meta:
		aliases = "__GI_getprotobyname_r, getprotobyname_r"
		size = "204"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 CF 41 56 4D 89 C6 41 55 49 89 FD 41 54 49 89 F4 BE ?? ?? ?? ?? 55 53 48 83 EC 38 48 8D 7C 24 10 48 89 54 24 08 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 2F 49 8B 3C 24 4C 89 EE E8 ?? ?? ?? ?? 85 C0 74 38 49 8B 5C 24 08 EB 10 4C 89 EE E8 ?? ?? ?? ?? 85 C0 74 25 48 83 C3 08 48 8B 3B 48 85 FF 75 E8 48 8B 74 24 08 4C 89 F1 4C 89 FA 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 89 C5 74 B8 83 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 48 8D 7C 24 10 BE 01 00 00 00 E8 ?? ?? ?? ?? 49 83 3E 00 B8 00 00 00 00 0F 45 E8 48 83 C4 38 5B 89 E8 5D 41 5C 41 5D 41 }
	condition:
		$pattern
}

rule __GI_getservbyport_r_f0971dff8a20b00c5ee72ac82825dd4e {
	meta:
		aliases = "getservbyport_r, __GI_getservbyport_r"
		size = "188"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 CF 41 56 4D 89 C6 41 55 4D 89 CD 41 54 49 89 F4 BE ?? ?? ?? ?? 55 48 89 D5 BA ?? ?? ?? ?? 53 48 83 EC 38 89 7C 24 0C 48 8D 7C 24 10 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 1E 8B 44 24 0C 39 45 10 75 15 4D 85 E4 74 27 48 8B 7D 18 4C 89 E6 E8 ?? ?? ?? ?? 85 C0 74 17 4C 89 E9 4C 89 F2 4C 89 FE 48 89 EF E8 ?? ?? ?? ?? 85 C0 89 C3 74 CB 83 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 48 8D 7C 24 10 BE 01 00 00 00 E8 ?? ?? ?? ?? 49 83 7D 00 00 B8 00 00 00 00 0F 45 D8 48 83 C4 38 89 D8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule qsort_0f7ec25e8d9cd7ab4e6525aa1788065c {
	meta:
		aliases = "__GI_qsort, qsort"
		size = "215"
		objfiles = "qsort@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 41 56 41 55 41 54 55 53 48 83 EC 18 48 83 FE 01 0F 97 C2 4D 85 FF 48 89 7C 24 08 0F 95 C0 48 89 0C 24 84 D0 0F 84 99 00 00 00 31 C9 48 8D 04 49 BA 03 00 00 00 48 89 D3 31 D2 48 8D 48 01 48 8D 46 FF 48 F7 F3 48 39 C1 72 E2 48 89 CB 49 0F AF F7 49 0F AF DF 48 89 74 24 10 49 89 DE 4D 89 F5 48 8B 6C 24 08 49 29 DD 4C 01 ED 4C 8D 64 1D 00 48 89 EF 4C 89 E6 FF 14 24 85 C0 7E 21 4C 89 F9 8A 55 00 41 8A 04 24 88 45 00 48 FF C5 41 88 14 24 49 FF C4 48 FF C9 75 E7 49 39 DD 73 C2 4D 01 FE 4C 3B 74 24 10 72 B5 4C 29 FB BA 03 00 00 00 48 89 D8 48 89 D6 31 D2 48 F7 F6 48 85 C0 48 89 C3 75 97 }
	condition:
		$pattern
}

rule ttyname_r_5d79696a9bcb9b5baad65ecd14d026ff {
	meta:
		aliases = "__GI_ttyname_r, ttyname_r"
		size = "350"
		objfiles = "ttyname@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 41 56 41 55 41 54 55 53 89 FB 48 81 EC 58 01 00 00 48 89 74 24 08 48 8D B4 24 A0 00 00 00 E8 ?? ?? ?? ?? 85 C0 79 0C E8 ?? ?? ?? ?? 8B 18 E9 12 01 00 00 89 DF E8 ?? ?? ?? ?? 85 C0 BA ?? ?? ?? ?? 0F 85 E8 00 00 00 E9 ED 00 00 00 48 8D 6A 01 48 8D 9C 24 30 01 00 00 4C 0F BE E0 41 BD 1E 00 00 00 48 89 DF 48 89 EE 4D 29 E5 E8 ?? ?? ?? ?? 48 89 EF 4E 8D 34 23 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 0F 85 84 00 00 00 E9 98 00 00 00 4C 8D 60 13 4C 89 E7 E8 ?? ?? ?? ?? 4C 39 E8 77 6E 4C 89 E6 4C 89 F7 E8 ?? ?? ?? ?? 4C 8D A4 24 30 01 00 00 48 8D 74 24 10 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 75 4A 8B }
	condition:
		$pattern
}

rule __time_localtime_tzi_fbc8f8649e6103da01ce13ae55aeae41 {
	meta:
		aliases = "__time_localtime_tzi"
		size = "744"
		objfiles = "_time_localtime_tzi@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 41 56 41 55 49 89 F5 41 54 55 53 48 83 EC 38 48 89 7C 24 10 C7 44 24 1C 00 00 00 00 48 63 44 24 1C BA 80 3A 09 00 BE F9 FF FF FF 48 C1 E0 05 49 8D 1C 07 48 8B 44 24 10 48 2B 13 48 8B 08 48 B8 7F C5 F6 FF FF FF FF 7F 48 39 C1 7E 08 48 F7 DA BE 07 00 00 00 48 8D 04 11 48 8D 7C 24 20 4C 89 EA 4C 8D 63 18 48 89 44 24 20 E8 ?? ?? ?? ?? 8B 54 24 1C 41 89 55 20 48 8B 03 BB ?? ?? ?? ?? 48 F7 D8 49 89 45 28 EB 16 48 8D 6B 08 4C 89 E6 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 52 48 8B 1B 48 85 DB 75 E5 BE 07 00 00 00 4C 89 E7 E8 ?? ?? ?? ?? 48 83 F8 06 77 3C BF 10 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 }
	condition:
		$pattern
}

rule linear_search_fdes_26faeaa3bbe4020871d59e1b899fd9ac {
	meta:
		aliases = "linear_search_fdes"
		size = "353"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 41 56 41 55 49 89 FD 41 54 55 48 89 F5 48 89 FE 53 48 83 EC 28 8B 47 20 66 C1 E8 03 44 0F B6 E0 44 89 E7 E8 93 FC FF FF 8B 55 00 49 89 C6 85 D2 0F 84 12 01 00 00 48 8D 44 24 20 48 C7 44 24 10 00 00 00 00 48 89 44 24 08 48 8D 44 24 18 48 89 04 24 EB 4C 66 66 66 90 66 66 90 48 8B 55 08 48 89 54 24 20 48 8B 45 10 48 85 D2 48 89 44 24 18 74 19 4C 89 F8 48 2B 44 24 20 48 3B 44 24 18 0F 82 C5 00 00 00 66 66 90 66 66 90 8B 45 00 48 01 E8 48 8D 68 04 8B 40 04 85 C0 0F 84 A8 00 00 00 8B 45 04 85 C0 74 E4 41 F6 45 20 04 74 2E 48 8D 5D 04 48 98 48 29 C3 48 39 5C 24 10 74 1E 48 89 DF E8 05 }
	condition:
		$pattern
}

rule __GI_getnameinfo_5ab60da4cb7f47716e7e7c64992450da {
	meta:
		aliases = "getnameinfo, __GI_getnameinfo"
		size = "774"
		objfiles = "getnameinfo@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 41 56 41 89 CE 41 55 49 89 FD 41 54 55 53 89 F3 48 81 EC B8 02 00 00 4C 89 44 24 08 44 89 4C 24 04 E8 ?? ?? ?? ?? 48 89 44 24 10 8B 00 89 44 24 1C 83 C8 FF F7 84 24 F0 02 00 00 E0 FF FF FF 0F 85 AA 02 00 00 4D 85 ED 0F 94 C2 83 FB 01 0F 96 C0 08 C2 0F 85 91 02 00 00 66 41 8B 55 00 0F B7 C2 83 F8 01 74 1C 83 F8 02 75 05 83 FB 0F EB 0C 83 F8 0A 0F 85 71 02 00 00 83 FB 1B 0F 86 68 02 00 00 4D 85 FF 0F 95 44 24 1A 45 85 F6 0F 95 44 24 1B 8A 44 24 1B 84 44 24 1A 0F 84 88 01 00 00 0F B7 C2 83 F8 02 74 12 83 F8 0A 74 0D FF C8 0F 85 73 01 00 00 E9 1D 01 00 00 F6 84 24 F0 02 00 00 01 0F }
	condition:
		$pattern
}

rule __getgrouplist_internal_b43e330301566fd4f5c0059cdb6bf561 {
	meta:
		aliases = "__getgrouplist_internal"
		size = "270"
		objfiles = "__getgrouplist_internal@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 41 56 41 89 F6 41 55 41 54 55 53 48 81 EC 38 01 00 00 48 89 7C 24 08 C7 02 01 00 00 00 BF 20 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 0F 84 C1 00 00 00 44 89 30 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 49 89 C4 0F 84 A3 00 00 00 41 BD 01 00 00 00 C7 40 50 01 00 00 00 EB 62 44 39 B4 24 20 01 00 00 74 58 48 8B 9C 24 28 01 00 00 EB 46 48 8B 74 24 08 E8 ?? ?? ?? ?? 85 C0 75 34 41 F6 C5 07 75 1B 41 8D 75 08 48 89 EF 48 63 F6 48 C1 E6 02 E8 ?? ?? ?? ?? 48 85 C0 74 49 48 89 C5 8B 84 24 20 01 00 00 49 63 D5 41 FF C5 89 44 95 00 EB 0C 48 83 C3 08 48 8B 3B 48 85 FF 75 B2 48 }
	condition:
		$pattern
}

rule __GI_getgrnam_r_4637c8554922e4eeefe27c93a1236c5c {
	meta:
		aliases = "__GI_getspnam_r, getpwnam_r, getspnam_r, getgrnam_r, __GI_getpwnam_r, __GI_getgrnam_r"
		size = "160"
		objfiles = "getpwnam_r@libc.a, getspnam_r@libc.a, getgrnam_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 41 56 49 89 CE 41 55 4D 89 C5 41 54 49 89 F4 BE ?? ?? ?? ?? 55 53 48 83 EC 08 48 89 3C 24 49 C7 00 00 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 75 09 E8 ?? ?? ?? ?? 8B 18 EB 4D C7 40 50 01 00 00 00 49 89 E8 4C 89 F1 4C 89 FA 4C 89 E6 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 89 C3 75 17 48 8B 34 24 49 8B 3C 24 E8 ?? ?? ?? ?? 85 C0 75 D3 4D 89 65 00 EB 0B 83 F8 02 B8 00 00 00 00 0F 44 D8 48 89 EF E8 ?? ?? ?? ?? 5A 89 D8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule getpwuid_r_5c035b786ac3507c7f1cc76b36c88320 {
	meta:
		aliases = "__GI_getgrgid_r, __GI_getpwuid_r, getgrgid_r, getpwuid_r"
		size = "154"
		objfiles = "getpwuid_r@libc.a, getgrgid_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 41 56 49 89 CE 41 55 4D 89 C5 41 54 49 89 F4 BE ?? ?? ?? ?? 55 53 48 83 EC 08 89 7C 24 04 49 C7 00 00 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 75 09 E8 ?? ?? ?? ?? 8B 18 EB 47 C7 40 50 01 00 00 00 49 89 E8 4C 89 F1 4C 89 FA 4C 89 E6 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 89 C3 75 11 8B 44 24 04 41 39 44 24 10 75 D9 4D 89 65 00 EB 0B 83 F8 02 B8 00 00 00 00 0F 44 D8 48 89 EF E8 ?? ?? ?? ?? 5A 89 D8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule clnttcp_create_6c018a8385aea489d6a82266937d5a7f {
	meta:
		aliases = "__GI_clnttcp_create, clnttcp_create"
		size = "539"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 41 56 49 89 F6 41 55 41 54 49 89 CC 55 53 48 89 FB BF 18 00 00 00 48 83 EC 78 44 89 44 24 0C 44 89 4C 24 08 E8 ?? ?? ?? ?? BF 98 00 00 00 49 89 C5 E8 ?? ?? ?? ?? 4D 85 ED 48 89 C5 0F 94 C2 48 85 C0 0F 94 C0 08 C2 74 2B E8 ?? ?? ?? ?? 48 8B 35 ?? ?? ?? ?? 48 89 C3 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 03 0C 00 00 00 C7 43 10 0C 00 00 00 E9 7D 01 00 00 66 83 7B 02 00 75 24 B9 06 00 00 00 4C 89 FA 4C 89 F6 48 89 DF E8 ?? ?? ?? ?? 66 85 C0 0F 84 5A 01 00 00 66 C1 C8 08 66 89 43 02 41 83 3C 24 00 79 6C BA 06 00 00 00 BE 01 00 00 00 BF 02 00 00 00 E8 ?? ?? ?? ?? 31 F6 89 C7 41 89 04 24 E8 }
	condition:
		$pattern
}

rule __GI_clntunix_create_44a12f4743e0e826c7335b866491fba9 {
	meta:
		aliases = "clntunix_create, __GI_clntunix_create"
		size = "511"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 41 56 49 89 F6 41 55 49 89 CD 41 54 55 53 48 89 FB BF F8 00 00 00 48 83 EC 78 44 89 44 24 0C 44 89 4C 24 08 E8 ?? ?? ?? ?? BF 18 00 00 00 48 89 C5 E8 ?? ?? ?? ?? 48 85 C0 49 89 C4 0F 94 C2 48 85 ED 0F 94 C0 08 C2 74 2B E8 ?? ?? ?? ?? 48 8B 35 ?? ?? ?? ?? 48 89 C3 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 03 0C 00 00 00 C7 43 10 0C 00 00 00 E9 61 01 00 00 41 83 7D 00 00 79 68 31 D2 BE 01 00 00 00 BF 01 00 00 00 E8 ?? ?? ?? ?? 48 8D 7B 02 41 89 45 00 E8 ?? ?? ?? ?? 41 8B 7D 00 85 FF 78 0F 8D 50 03 48 89 DE E8 ?? ?? ?? ?? 85 C0 79 2A E8 ?? ?? ?? ?? C7 00 0C 00 00 00 48 89 C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule openpty_7334a6007cd8da2cdad0d29370f3be16 {
	meta:
		aliases = "__GI_openpty, openpty"
		size = "231"
		objfiles = "openpty@libutil.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 41 56 4D 89 C6 41 55 49 89 CD 41 54 55 53 48 81 EC 18 10 00 00 48 89 7C 24 08 BF 02 00 00 00 48 89 34 24 E8 ?? ?? ?? ?? 89 C5 83 FD FF 0F 84 9D 00 00 00 89 EF E8 ?? ?? ?? ?? 85 C0 0F 85 84 00 00 00 89 EF E8 ?? ?? ?? ?? 85 C0 75 79 4C 8D 64 24 10 BA 00 10 00 00 89 EF 4C 89 E6 E8 ?? ?? ?? ?? 85 C0 75 61 BE 02 01 00 00 4C 89 E7 E8 ?? ?? ?? ?? 83 F8 FF 89 C3 74 4D 4D 85 ED 74 0F 4C 89 EA BE 02 00 00 00 89 C7 E8 ?? ?? ?? ?? 4D 85 F6 74 11 4C 89 F2 BE 14 54 00 00 89 DF 31 C0 E8 ?? ?? ?? ?? 48 8B 44 24 08 89 28 48 8B 04 24 89 18 31 C0 4D 85 FF 74 19 4C 89 E6 4C 89 FF E8 ?? ?? ?? ?? 31 }
	condition:
		$pattern
}

rule pmap_rmtcall_edf9022b79c691b6445e432d8fafe686 {
	meta:
		aliases = "pmap_rmtcall"
		size = "279"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 BA 02 00 00 00 41 56 49 89 F6 BE A0 86 01 00 41 55 4D 89 CD 41 54 49 89 FC 55 BD 10 00 00 00 53 48 81 EC 88 00 00 00 48 89 4C 24 18 4C 89 44 24 10 4C 8D 4C 24 7C 48 8B 0D ?? ?? ?? ?? 4C 8B 05 ?? ?? ?? ?? C7 44 24 7C FF FF FF FF 66 C7 47 02 00 6F E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 0F 84 93 00 00 00 48 8B 44 24 18 4C 89 74 24 20 48 89 DF 4C 89 7C 24 28 4C 89 6C 24 40 48 8D 4C 24 20 4C 8D 4C 24 50 41 B8 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 44 24 30 48 8B 44 24 10 BE 05 00 00 00 48 89 44 24 48 48 8B 84 24 E0 00 00 00 48 89 44 24 50 48 8B 84 24 C8 00 00 00 48 89 44 24 60 48 8B 84 24 C0 00 }
	condition:
		$pattern
}

rule getrpcbynumber_r_5adb9741a7cf76f23956d667e1260cf5 {
	meta:
		aliases = "getrpcbynumber_r"
		size = "117"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 BA ?? ?? ?? ?? 41 56 49 89 CE 41 55 41 54 41 89 FC 55 48 89 F5 BE ?? ?? ?? ?? 53 4C 89 C3 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 44 89 E7 E8 ?? ?? ?? ?? 49 89 D8 4C 89 F1 4C 89 FA 48 89 EE 48 89 C7 E8 BD FA FF FF BE 01 00 00 00 89 C3 48 89 E7 E8 ?? ?? ?? ?? 89 D8 48 83 C4 28 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule getrpcbyname_r_254c39726d5e717955aa1826d6323a79 {
	meta:
		aliases = "getrpcbyname_r"
		size = "117"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 BA ?? ?? ?? ?? 41 56 49 89 CE 41 55 41 54 49 89 FC 55 48 89 F5 BE ?? ?? ?? ?? 53 4C 89 C3 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? 49 89 D8 4C 89 F1 4C 89 FA 48 89 EE 48 89 C7 E8 6E FB FF FF BE 01 00 00 00 89 C3 48 89 E7 E8 ?? ?? ?? ?? 89 D8 48 83 C4 28 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule __md5_Transform_ba12b2e01f9d8b0de819a8eb801d74e8 {
	meta:
		aliases = "__md5_Transform"
		size = "353"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F1 45 31 D2 45 31 C0 41 56 41 55 41 54 55 53 48 83 EC 48 EB 3F 44 89 C0 44 89 D6 41 FF C2 41 0F B6 0C 01 41 8D 40 01 41 0F B6 04 01 C1 E0 08 09 C1 41 8D 40 03 41 0F B6 14 01 41 8D 40 02 41 83 C0 04 41 0F B6 04 01 C1 E2 18 C1 E0 10 09 C2 09 D1 89 0C B4 41 83 F8 3F 76 BB 44 8B 2F 44 8B 4F 04 4C 8D 7F 04 44 8B 47 08 8B 77 0C 4C 8D 77 08 4C 8D 67 0C 41 BB ?? ?? ?? ?? BD ?? ?? ?? ?? 44 89 E9 BB ?? ?? ?? ?? 45 31 D2 E9 95 00 00 00 49 8D 43 04 41 F6 C2 0F 4C 0F 44 D8 44 89 D0 C1 F8 04 83 F8 01 74 25 7F 06 85 C0 74 10 EB 0A 83 F8 02 74 2B 83 F8 03 74 30 89 CA EB 39 44 89 C8 44 89 CA F7 D0 }
	condition:
		$pattern
}

rule __GI_fread_unlocked_d7e3d44478a1a32f94c2001bfcba38d9 {
	meta:
		aliases = "fread_unlocked, __GI_fread_unlocked"
		size = "306"
		objfiles = "fread_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 41 56 41 55 41 54 49 89 CC 55 48 89 FD 53 48 89 D3 48 83 EC 08 0F B7 01 25 83 00 00 00 3D 80 00 00 00 77 15 BE 80 00 00 00 48 89 CF E8 ?? ?? ?? ?? 85 C0 0F 85 E6 00 00 00 4D 85 FF 0F 95 C2 48 85 DB 0F 95 C0 84 D0 0F 84 D2 00 00 00 48 83 C8 FF 31 D2 49 F7 F7 48 39 C3 0F 87 AF 00 00 00 4D 89 FE 49 89 ED 4C 0F AF F3 4C 89 F5 EB 28 48 89 D0 83 E0 01 48 FF CD 41 8B 44 84 40 41 88 45 00 8D 42 FF 41 C7 44 24 44 00 00 00 00 66 41 89 04 24 74 6E 49 FF C5 41 8B 14 24 F6 C2 02 75 CF 49 8B 74 24 18 49 8B 44 24 20 48 29 F0 74 22 48 39 C5 48 89 C3 4C 89 EF 48 0F 46 DD 48 89 DA E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svcudp_recv_3db964487cb7038fbf1009708314949f {
	meta:
		aliases = "svcudp_recv"
		size = "541"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 41 56 41 55 41 54 49 89 FC 55 53 48 83 EC 28 48 8B 6F 48 49 8D 44 24 50 4D 8D 6C 24 60 C7 44 24 24 10 00 00 00 49 8B 74 24 40 48 89 44 24 10 49 83 7D 18 00 49 8D 44 24 14 74 5C 49 89 74 24 50 8B 4D 00 4C 89 EE 48 8B 54 24 10 48 89 4A 08 49 89 44 24 60 49 8D 84 24 98 00 00 00 49 89 55 10 49 C7 45 18 01 00 00 00 31 D2 41 C7 45 08 10 00 00 00 49 89 45 20 49 C7 45 28 B8 00 00 00 41 8B 3C 24 E8 ?? ?? ?? ?? 85 C0 89 C2 78 23 41 8B 45 08 89 44 24 24 EB 19 48 63 55 00 41 8B 3C 24 4C 8D 4C 24 24 49 89 C0 31 C9 E8 ?? ?? ?? ?? 89 C2 8B 44 24 24 83 FA FF 41 89 44 24 10 75 13 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule rtime_df276b9d7b0e233ed347b4eb439de257 {
	meta:
		aliases = "__GI_rtime, rtime"
		size = "370"
		objfiles = "rtime@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 41 56 41 55 49 89 D5 41 54 49 89 FC BF 02 00 00 00 55 53 48 83 EC 28 48 83 FA 01 19 DB 31 D2 83 C3 02 89 DE E8 ?? ?? ?? ?? 85 C0 89 C5 0F 88 28 01 00 00 83 FB 02 66 41 C7 04 24 02 00 66 41 C7 44 24 02 00 25 0F 85 A6 00 00 00 4C 8D 74 24 1C 31 C9 41 B9 10 00 00 00 4D 89 E0 BA 04 00 00 00 89 C7 4C 89 F6 E8 ?? ?? ?? ?? 85 C0 0F 88 92 00 00 00 41 8B 45 04 BA E8 03 00 00 89 6C 24 10 89 D3 31 D2 66 C7 44 24 14 01 00 41 69 4D 00 E8 03 00 00 F7 F3 44 8D 24 01 48 8D 7C 24 10 44 89 E2 BE 01 00 00 00 E8 ?? ?? ?? ?? 85 C0 89 C3 79 0A E8 ?? ?? ?? ?? 83 38 04 74 DE 83 FB 00 7F 0F 75 43 E8 ?? }
	condition:
		$pattern
}

rule _getopt_internal_fec45668b65f4e8eef6c88f7d2ebdf19 {
	meta:
		aliases = "_getopt_internal"
		size = "1942"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 41 56 49 89 CE 41 55 41 54 55 53 48 83 EC 48 8B 05 ?? ?? ?? ?? 48 89 54 24 10 8B 15 ?? ?? ?? ?? 48 8B 4C 24 10 C7 44 24 24 00 00 00 00 89 05 ?? ?? ?? ?? 89 7C 24 18 4C 89 44 24 08 44 89 4C 24 04 89 15 ?? ?? ?? ?? 80 39 3A 0F 44 44 24 24 85 FF 89 44 24 24 0F 8E FC 06 00 00 85 D2 48 C7 05 ?? ?? ?? ?? 00 00 00 00 74 0F 83 3D ?? ?? ?? ?? 00 0F 85 92 00 00 00 EB 0A C7 05 ?? ?? ?? ?? 01 00 00 00 8B 05 ?? ?? ?? ?? BF ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 89 05 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 54 24 10 48 85 C0 0F 95 C0 0F B6 C0 89 05 ?? ?? ?? ?? 8A 02 3C 2D 75 }
	condition:
		$pattern
}

rule sendto_61091211bf087823685595a43e7f5857 {
	meta:
		aliases = "sendto"
		size = "100"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 41 56 49 89 D6 41 55 41 89 CD 41 54 4D 89 C4 55 89 FD BF 01 00 00 00 53 44 89 CB 48 83 EC 18 48 8D 74 24 14 E8 ?? ?? ?? ?? 41 89 D9 4D 89 E0 44 89 E9 4C 89 F2 4C 89 FE 89 EF E8 ?? ?? ?? ?? 8B 7C 24 14 48 89 C3 31 F6 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 18 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule recvfrom_4ea26b49160a9b4a4b762c9aebbefe18 {
	meta:
		aliases = "recvfrom"
		size = "100"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 41 56 49 89 D6 41 55 41 89 CD 41 54 4D 89 C4 55 89 FD BF 01 00 00 00 53 4C 89 CB 48 83 EC 18 48 8D 74 24 14 E8 ?? ?? ?? ?? 49 89 D9 4D 89 E0 44 89 E9 4C 89 F2 4C 89 FE 89 EF E8 ?? ?? ?? ?? 8B 7C 24 14 48 89 C3 31 F6 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 18 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule clntraw_create_e82378521b0bc5638ab036a66b076d29 {
	meta:
		aliases = "clntraw_create"
		size = "252"
		objfiles = "clnt_raw@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 41 56 49 89 FE 41 55 41 54 55 53 48 83 EC 68 E8 ?? ?? ?? ?? 4C 8B A8 C0 00 00 00 48 89 C3 4D 85 ED 4C 89 ED 75 25 BE C8 22 00 00 BF 01 00 00 00 45 31 E4 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 0F 84 A1 00 00 00 48 89 83 C0 00 00 00 49 8D 5D 18 48 8D B5 A8 22 00 00 31 C9 BA 18 00 00 00 C7 44 24 08 00 00 00 00 48 C7 44 24 10 02 00 00 00 48 89 DF 4C 89 74 24 18 4C 89 7C 24 20 E8 ?? ?? ?? ?? 48 89 E6 48 89 DF E8 ?? ?? ?? ?? 85 C0 75 0A BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 43 08 48 89 DF FF 50 20 89 85 C0 22 00 00 48 8B 43 08 48 8B 40 38 48 85 C0 74 05 48 89 DF FF D0 48 8D 75 48 B9 02 00 00 }
	condition:
		$pattern
}

rule __encode_packet_eb104ecfbeb35349f383c135123dfdaa {
	meta:
		aliases = "__encode_packet"
		size = "303"
		objfiles = "encodep@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 4C 89 CE 41 56 49 89 FE 41 55 41 54 55 53 4C 89 CB 48 83 EC 18 44 8B 64 24 50 48 89 54 24 10 48 89 4C 24 08 4C 89 04 24 44 89 E2 E8 ?? ?? ?? ?? 85 C0 89 C2 0F 88 DF 00 00 00 48 98 45 31 ED 48 8D 2C 03 44 89 E3 41 89 D4 29 D3 EB 28 44 89 E8 89 DA 48 89 EE 49 8B 3C C7 E8 ?? ?? ?? ?? 85 C0 89 C2 0F 88 B1 00 00 00 48 98 29 D3 41 01 D4 48 01 C5 41 FF C5 45 3B 6E 20 72 D2 45 31 ED EB 29 48 8B 54 24 10 44 89 E8 48 89 EE 48 8B 3C C2 89 DA E8 ?? ?? ?? ?? 85 C0 89 C2 78 7D 48 98 29 D3 41 01 D4 48 01 C5 41 FF C5 45 3B 6E 24 72 D1 45 31 ED EB 29 48 8B 54 24 08 44 89 E8 48 89 EE 48 8B 3C C2 }
	condition:
		$pattern
}

rule _stdlib_strto_l_44256d37a9b2af3a1870d43ae53616c1 {
	meta:
		aliases = "_stdlib_strto_l"
		size = "362"
		objfiles = "_stdlib_strto_l@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F8 41 56 41 55 41 54 55 89 D5 53 48 89 FB 48 83 EC 18 89 4C 24 0C 48 8B 0D ?? ?? ?? ?? 48 89 74 24 10 EB 03 48 FF C3 8A 13 48 0F BE C2 F6 04 41 20 75 F1 0F BE C2 83 F8 2B 74 10 45 31 ED 83 F8 2D 75 0E 41 BD 01 00 00 00 EB 03 45 31 ED 48 FF C3 F7 C5 EF FF FF FF 4C 89 C7 75 2A 83 C5 0A 80 3B 30 75 17 48 FF C3 83 ED 02 8A 03 48 89 DF 83 C8 20 3C 78 75 05 01 ED 48 FF C3 83 FD 11 B8 10 00 00 00 0F 4D E8 8D 45 FE 31 F6 83 F8 22 77 73 4C 63 E5 48 83 C8 FF 31 D2 49 F7 F4 49 89 C7 41 89 D6 EB 03 48 89 DF 8A 03 8D 48 D0 80 F9 09 76 10 83 C8 20 B9 28 00 00 00 8D 50 A9 3C 60 0F 47 CA 0F B6 C1 }
	condition:
		$pattern
}

rule search_object_22c13c89a028c439d1ace6dbbb383b54 {
	meta:
		aliases = "search_object"
		size = "1620"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 41 55 41 54 55 53 48 81 EC A8 00 00 00 48 89 74 24 30 0F B6 57 20 F6 C2 01 0F 85 F7 02 00 00 8B 4F 20 89 C8 C1 E8 0B 0F 84 61 03 00 00 89 C0 48 89 44 24 48 48 8B 44 24 48 48 8D 1C C5 10 00 00 00 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 48 89 84 24 80 00 00 00 0F 84 A4 02 00 00 48 C7 40 08 00 00 00 00 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 48 89 84 24 88 00 00 00 74 08 48 C7 40 08 00 00 00 00 41 F6 47 20 02 0F 84 85 04 00 00 49 8B 47 18 48 8B 10 48 85 D2 74 23 48 8D AC 24 80 00 00 00 48 89 C3 48 89 EE 4C 89 FF E8 1D FA FF FF 48 8B 53 08 48 83 C3 08 48 85 D2 75 E8 4C 8B A4 24 80 00 00 00 }
	condition:
		$pattern
}

rule __res_search_da3d07888bf892dc115b629b415a6d39 {
	meta:
		aliases = "__res_search"
		size = "753"
		objfiles = "res_query@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 41 55 41 54 55 53 48 83 EC 58 48 8D 5C 24 30 89 74 24 14 89 54 24 10 BE ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 4C 24 08 48 89 DF 44 89 44 24 04 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 DF 4C 8B 25 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4D 85 FF 0F 94 C2 48 83 7C 24 08 00 0F 94 C0 08 C2 75 0F 41 80 E4 01 75 19 E8 ?? ?? ?? ?? FF C0 75 10 E8 ?? ?? ?? ?? C7 00 FF FF FF FF E9 24 02 00 00 E8 ?? ?? ?? ?? 48 89 44 24 18 C7 00 00 00 00 00 45 31 F6 E8 ?? ?? ?? ?? 4C 89 FA 48 89 C5 C7 00 01 00 00 00 EB 0E 3C 2E 0F 94 C0 48 FF C2 0F B6 C0 41 01 C6 8A 02 84 C0 75 EC 45 31 ED 4C }
	condition:
		$pattern
}

rule __GI_gethostbyname2_r_0851c070b0c59ae7d3c2fe0c68b00451 {
	meta:
		aliases = "gethostbyname2_r, __GI_gethostbyname2_r"
		size = "829"
		objfiles = "gethostbyname2_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 41 55 49 89 CD 41 54 4D 89 C4 55 48 89 D5 53 48 81 EC A8 00 00 00 83 FE 02 4C 89 4C 24 10 75 20 4C 8B 8C 24 E0 00 00 00 4C 8B 44 24 10 4C 89 E1 4C 89 EA 48 89 EE E8 ?? ?? ?? ?? E9 E4 02 00 00 83 FE 0A 0F 85 AC 02 00 00 E8 ?? ?? ?? ?? 48 8B 44 24 10 4D 85 FF 48 C7 00 00 00 00 00 0F 84 92 02 00 00 E8 ?? ?? ?? ?? 44 8B 30 C7 00 00 00 00 00 4D 89 E0 48 8B 8C 24 E0 00 00 00 4C 8B 4C 24 10 48 89 EA BE 0A 00 00 00 4C 89 FF 48 89 C3 48 89 0C 24 4C 89 E9 E8 ?? ?? ?? ?? 85 C0 0F 84 81 02 00 00 48 8B 8C 24 E0 00 00 00 8B 11 83 FA 01 74 0F 83 FA 04 74 22 FF C2 0F 85 65 02 00 00 EB 0F }
	condition:
		$pattern
}

rule vfscanf_0aaf9c5895488a7af787fa3158eced9f {
	meta:
		aliases = "__GI_vfscanf, vfscanf"
		size = "1770"
		objfiles = "vfscanf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 41 55 49 89 D5 BA 48 00 00 00 41 54 55 48 89 F5 31 F6 53 48 81 EC 68 02 00 00 48 8D BC 24 10 01 00 00 C7 84 24 58 01 00 00 FF FF FF FF E8 ?? ?? ?? ?? 41 8B 47 50 85 C0 89 44 24 0C 75 21 49 8D 5F 58 48 8D BC 24 30 02 00 00 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8D BC 24 90 01 00 00 4C 89 FE 48 89 EB 41 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 8B 84 24 98 01 00 00 48 C7 84 24 C0 01 00 00 ?? ?? ?? ?? 8A 40 03 C7 84 24 70 01 00 00 00 00 00 00 88 84 24 AC 01 00 00 48 8B 84 24 C8 01 00 00 48 89 84 24 D8 01 00 00 E9 7C 05 00 00 80 A4 24 AD 01 00 00 01 C6 84 24 }
	condition:
		$pattern
}

rule xdr_vector_42d821293d0f104b31bde0a4435e738f {
	meta:
		aliases = "xdr_vector"
		size = "81"
		objfiles = "xdr_array@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 41 89 D6 41 55 41 89 CD 41 54 4D 89 C4 55 31 ED 53 48 89 F3 48 83 EC 08 EB 1A 83 CA FF 31 C0 48 89 DE 4C 89 FF 41 FF D4 85 C0 74 12 44 89 E8 FF C5 48 01 C3 44 39 F5 72 E1 B8 01 00 00 00 5A 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule __uClibc_main_8412ea63020b79e314a9803193ac2f27 {
	meta:
		aliases = "__uClibc_main"
		size = "489"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 41 89 F6 41 55 49 89 CD 41 54 49 89 D4 55 4C 89 C5 53 48 81 EC F8 00 00 00 4C 89 0D ?? ?? ?? ?? 48 8B 84 24 30 01 00 00 48 89 E7 48 89 05 ?? ?? ?? ?? 48 63 C6 48 8D 04 C2 48 8D 50 08 48 89 15 ?? ?? ?? ?? 49 3B 14 24 48 0F 45 C2 BA F0 00 00 00 31 F6 48 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 83 38 00 48 8D 40 08 75 F6 48 89 C3 EB 22 48 8B 03 48 83 F8 0E 77 15 48 C1 E0 04 BA 10 00 00 00 48 89 DE 48 8D 3C 04 E8 ?? ?? ?? ?? 48 83 C3 10 48 83 3B 00 75 D8 48 89 E7 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 44 24 68 BA 00 10 00 00 48 85 C0 48 0F 44 C2 48 83 BC 24 B8 00 }
	condition:
		$pattern
}

rule _fp_out_wide_a215cea268d2f2e9c9b2d61e0ede5825 {
	meta:
		aliases = "_fp_out_wide"
		size = "150"
		objfiles = "_vfwprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 49 89 CE 41 55 45 31 ED 41 54 49 89 F4 55 48 89 D5 53 48 89 D3 48 81 EC 88 00 00 00 40 84 F6 79 2C 48 89 CF E8 ?? ?? ?? ?? 48 63 E8 48 29 EB 48 85 DB 7E 19 44 89 E6 48 89 DA 4C 89 FF 83 E6 7F E8 2D F8 FF FF 48 39 D8 49 89 C5 75 2D 48 85 ED 7E 28 31 C9 48 63 C1 FF C1 41 0F BE 14 06 89 14 84 48 63 C1 48 39 E8 7C EB 48 89 E7 4C 89 FA 48 89 EE E8 ?? ?? ?? ?? 49 01 C5 48 81 C4 88 00 00 00 4C 89 E8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule _fp_out_narrow_fc3b5388172e49e40e2a15a20a0222e6 {
	meta:
		aliases = "_fp_out_narrow"
		size = "120"
		objfiles = "_vfprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 49 89 CE 41 55 45 31 ED 41 54 49 89 F4 55 48 89 D5 53 48 89 D3 48 83 EC 08 40 84 F6 79 2C 48 89 CF E8 ?? ?? ?? ?? 48 63 E8 48 29 EB 48 85 DB 7E 19 44 89 E6 48 89 DA 4C 89 FF 83 E6 7F E8 73 FF FF FF 48 39 D8 49 89 C5 75 18 31 C0 48 85 ED 7E 0E 4C 89 FA 48 89 EE 4C 89 F7 E8 ?? ?? ?? ?? 49 01 C5 5E 5B 5D 41 5C 4C 89 E8 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule _fpmaxtostr_e95e25378ddcb1b8633e2aaff5b9461b {
	meta:
		aliases = "_fpmaxtostr"
		size = "1608"
		objfiles = "_fpmaxtostr@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 49 89 D6 41 55 41 54 49 89 F4 55 53 48 81 EC 18 01 00 00 8A 5E 08 8B 2E 44 8B 6E 04 C6 84 24 F0 00 00 00 65 C6 84 24 00 01 00 00 00 89 D8 8D 53 06 83 C8 20 3C 61 B8 06 00 00 00 0F 44 DA 8B 56 0C 85 ED 0F 48 E8 DB AC 24 50 01 00 00 F6 C2 02 74 0A C6 84 24 00 01 00 00 2B EB 17 80 E2 01 B8 20 00 00 00 BA 00 00 00 00 0F 44 C2 88 84 24 00 01 00 00 DB E8 C6 84 24 01 01 00 00 00 48 C7 44 24 38 00 00 00 00 7A 02 74 0D DF C0 48 C7 44 24 38 08 00 00 00 EB 51 D9 EE D9 C9 DB E9 75 23 7A 21 D9 E8 41 83 C9 FF D8 F1 D9 CA DF EA DD D9 0F 86 02 01 00 00 C6 84 24 00 01 00 00 2D E9 F5 00 00 }
	condition:
		$pattern
}

rule __add_to_environ_ed6c3b09d3483d12604d0853c326a749 {
	meta:
		aliases = "__add_to_environ"
		size = "484"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 49 89 D6 41 55 41 54 55 53 48 83 EC 48 48 89 74 24 10 89 4C 24 0C E8 ?? ?? ?? ?? 48 83 7C 24 10 00 49 89 C4 48 C7 44 24 18 00 00 00 00 74 12 48 8B 7C 24 10 E8 ?? ?? ?? ?? 48 FF C0 48 89 44 24 18 48 8D 7C 24 20 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 45 31 ED E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 2D ?? ?? ?? ?? 48 85 ED 74 3B EB 20 4C 89 E2 4C 89 FE 48 89 DF E8 ?? ?? ?? ?? 85 C0 75 07 42 80 3C 23 3D 74 10 49 FF C5 48 83 C5 08 48 8B 5D 00 48 85 DB 75 D7 48 85 ED 74 0B 48 83 7D 00 00 0F 85 BA 00 00 00 49 C1 E5 03 48 8B 3D ?? ?? ?? ?? 49 8D 75 10 E8 ?? ?? ?? ?? 48 85 C0 48 }
	condition:
		$pattern
}

rule frame_heapsort_55ffb2fe5264995310601cbecddf670f {
	meta:
		aliases = "frame_heapsort"
		size = "144"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 49 89 F6 41 55 41 54 4C 8D 62 10 55 53 48 83 EC 08 4C 8B 6A 08 4C 89 E8 48 D1 E8 89 C3 FF CB 78 1F 44 89 ED 66 66 90 66 90 89 D9 41 89 E8 4C 89 E2 4C 89 F6 4C 89 FF E8 FD FE FF FF FF CB 79 E9 41 8D 6D FF 85 ED 7E 32 48 63 C5 49 8D 1C C4 49 8B 14 24 48 8B 03 41 89 E8 31 C9 4C 89 F6 4C 89 FF FF CD 49 89 04 24 48 89 13 4C 89 E2 E8 C7 FE FF FF 48 83 EB 08 85 ED 7F D5 48 83 C4 08 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule freopen_0925e02130203b47257d0000d6433dd5 {
	meta:
		aliases = "freopen"
		size = "278"
		objfiles = "freopen@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 49 89 F6 41 55 41 54 55 48 89 D5 53 48 83 EC 48 44 8B 6A 50 45 85 ED 75 1E 48 8D 5A 58 48 8D 7C 24 20 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 FF C0 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 5D 00 89 D8 80 E4 9F 66 89 45 00 0F B7 C0 83 E0 30 83 F8 30 74 37 48 89 EF E8 ?? ?? ?? ?? BE ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 FF 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C9 FF 48 89 }
	condition:
		$pattern
}

rule freopen64_dc1adb289637ed2386b2231992b94c7e {
	meta:
		aliases = "freopen64"
		size = "280"
		objfiles = "freopen64@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 49 89 F6 41 55 41 54 55 48 89 D5 53 48 83 EC 48 44 8B 6A 50 45 85 ED 75 1E 48 8D 5A 58 48 8D 7C 24 20 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 FF C0 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 5D 00 89 D8 80 E4 9F 66 89 45 00 0F B7 C0 83 E0 30 83 F8 30 74 37 48 89 EF E8 ?? ?? ?? ?? BE ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 FF 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? B9 FE FF FF FF }
	condition:
		$pattern
}

rule __GI_fwrite_304e419c6d00e9e0585506a839739d8f {
	meta:
		aliases = "fwrite, fread, __GI_fread, __GI_fwrite"
		size = "119"
		objfiles = "fread@libc.a, fwrite@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 49 89 F6 41 55 49 89 D5 41 54 55 48 89 CD 53 48 83 EC 28 44 8B 61 50 45 85 E4 75 1C 48 8D 59 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 E9 4C 89 EA 4C 89 F6 4C 89 FF E8 ?? ?? ?? ?? 45 85 E4 48 89 C3 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 48 89 D8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule __pgsreader_2921f6765fdea4ada7ccdcb1b18c25bc {
	meta:
		aliases = "__pgsreader"
		size = "299"
		objfiles = "__pgsreader@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 49 89 F6 41 55 4D 89 C5 41 54 49 89 CC 55 48 89 D5 53 48 83 EC 38 48 81 F9 FF 00 00 00 77 1F BB 22 00 00 00 E8 ?? ?? ?? ?? C7 00 22 00 00 00 E9 DF 00 00 00 BB 02 00 00 00 E9 BF 00 00 00 41 8B 40 50 85 C0 89 44 24 0C 75 1E 49 8D 58 58 48 8D 7C 24 10 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 31 DB 4C 89 EA 44 89 E6 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 75 0E 41 F6 45 00 04 BB 22 00 00 00 74 74 EB A9 48 89 EF E8 ?? ?? ?? ?? 48 8D 54 28 FF 80 3A 0A 75 05 C6 02 00 EB 0C 48 FF C0 4C 39 E0 75 04 FF C3 EB BC 85 DB 74 04 FF CB EB B4 8A 4D 00 84 C9 0F 95 C2 80 F9 23 }
	condition:
		$pattern
}

rule getrpcent_r_d2d84d1e49685038fad76a0f914abf1f {
	meta:
		aliases = "getrpcent_r"
		size = "109"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 49 89 F6 BE ?? ?? ?? ?? 41 55 49 89 D5 BA ?? ?? ?? ?? 41 54 53 48 89 CB 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 49 89 D8 4C 89 E9 4C 89 F2 4C 89 FE 48 89 C7 E8 C4 FC FF FF BE 01 00 00 00 89 C3 48 89 E7 E8 ?? ?? ?? ?? 89 D8 48 83 C4 20 5B 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule svc_register_f85a5fc3f9e287a85fd262028cf0cd1a {
	meta:
		aliases = "__GI_svc_register, svc_register"
		size = "158"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 4D 89 C6 41 55 49 89 CD 41 54 49 89 F4 4C 89 E7 55 48 89 D5 48 89 EE 53 48 83 EC 18 48 8D 54 24 10 E8 D8 FC FF FF 48 85 C0 74 08 4C 39 68 18 75 55 EB 34 BF 20 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 41 4C 89 60 08 48 89 68 10 4C 89 68 18 E8 ?? ?? ?? ?? 48 8B 90 F0 00 00 00 48 89 13 48 89 98 F0 00 00 00 4D 85 F6 B8 01 00 00 00 74 17 41 0F B7 4F 04 44 89 F2 48 89 EE 4C 89 E7 E8 ?? ?? ?? ?? EB 02 31 C0 48 83 C4 18 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule bsearch_9dafc303cab24b9da4941abf4c097797 {
	meta:
		aliases = "bsearch"
		size = "126"
		objfiles = "bsearch@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 4D 89 C7 41 56 49 89 CE 41 55 45 31 ED 41 54 55 48 89 D5 53 48 83 EC 18 48 85 C9 48 89 7C 24 10 48 89 74 24 08 75 3F EB 42 48 89 E8 4C 8B 64 24 08 48 8B 7C 24 10 4C 29 E8 48 D1 E8 49 8D 5C 05 00 48 89 D8 49 0F AF C6 49 01 C4 4C 89 E6 41 FF D7 83 F8 00 7E 06 4C 8D 6B 01 EB 0A 75 05 4C 89 E0 EB 0A 48 89 DD 49 39 ED 72 BE 31 C0 48 83 C4 18 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule registerrpc_fb0818af048b98be543e8b81f42bad20 {
	meta:
		aliases = "registerrpc"
		size = "297"
		objfiles = "svc_simple@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 4D 89 C7 41 56 49 89 CE 41 55 49 89 D5 41 54 49 89 FC 55 48 89 F5 53 48 83 EC 18 48 85 D2 4C 89 0C 24 75 18 48 8D 7C 24 10 31 D2 BE ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? E9 BE 00 00 00 E8 ?? ?? ?? ?? 48 83 B8 08 01 00 00 00 48 89 C3 75 19 83 CF FF E8 ?? ?? ?? ?? 48 85 C0 48 89 83 08 01 00 00 BF ?? ?? ?? ?? 74 5A 48 89 EE 4C 89 E7 E8 ?? ?? ?? ?? 48 8B BB 08 01 00 00 41 B8 11 00 00 00 B9 ?? ?? ?? ?? 48 89 EA 4C 89 E6 E8 ?? ?? ?? ?? 85 C0 75 17 48 8D 7C 24 10 48 89 E9 4C 89 E2 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 50 BF 28 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C2 75 11 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clntraw_call_0d4cfca42564bd799c7e26dd362b1da8 {
	meta:
		aliases = "clntraw_call"
		size = "433"
		objfiles = "clnt_raw@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 4D 89 CF 41 56 49 89 FE 41 55 41 54 55 BD 10 00 00 00 53 48 81 EC A8 00 00 00 48 89 74 24 18 48 89 54 24 10 48 89 4C 24 08 4C 89 04 24 E8 ?? ?? ?? ?? 4C 8B A8 C0 00 00 00 49 8D 5D 18 4D 85 ED 0F 84 55 01 00 00 48 8B 43 08 31 F6 48 89 DF C7 03 00 00 00 00 FF 50 28 49 8D B5 A8 22 00 00 48 89 DF 48 FF 06 48 8B 43 08 41 8B 95 C0 22 00 00 FF 50 18 85 C0 0F 84 1B 01 00 00 48 8B 43 08 48 8D 74 24 18 48 89 DF FF 50 08 85 C0 0F 84 04 01 00 00 49 8B 3E 48 89 DE 48 8B 47 38 FF 50 08 85 C0 0F 84 EF 00 00 00 31 C0 48 8B 74 24 08 48 89 DF FF 54 24 10 85 C0 0F 84 D9 00 00 00 48 8B 43 08 48 89 DF 4C 8D }
	condition:
		$pattern
}

rule getservbyname_r_4a37d8cf2cda8a990c39e5a9ac736461 {
	meta:
		aliases = "__GI_getservbyname_r, getservbyname_r"
		size = "233"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 4D 89 CF 41 56 49 89 FE 41 55 49 89 F5 BE ?? ?? ?? ?? 41 54 49 89 D4 BA ?? ?? ?? ?? 55 53 48 83 EC 38 48 8D 7C 24 10 48 89 4C 24 08 4C 89 04 24 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 47 49 8B 34 24 4C 89 F7 E8 ?? ?? ?? ?? 85 C0 74 21 49 8B 5C 24 08 EB 10 4C 89 F7 E8 ?? ?? ?? ?? 85 C0 74 0E 48 83 C3 08 48 8B 33 48 85 F6 75 E8 EB 16 4D 85 ED 74 2B 49 8B 7C 24 18 4C 89 EE E8 ?? ?? ?? ?? 85 C0 74 1A 48 8B 14 24 48 8B 74 24 08 4C 89 F9 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 89 C5 74 9F 83 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 48 8D 7C 24 10 BE 01 00 00 00 E8 }
	condition:
		$pattern
}

rule __ns_name_unpack_d83d3b1ef383fcd5142a59ad8aef0c98 {
	meta:
		aliases = "__GI___ns_name_unpack, __ns_name_unpack"
		size = "306"
		objfiles = "ns_name@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 4E 8D 04 01 49 89 FF 41 56 49 89 D6 41 55 49 89 F5 41 54 4D 89 F4 55 53 48 83 EC 18 48 39 FA 0F 92 C2 49 39 F6 4C 89 44 24 10 0F 93 C0 41 83 C9 FF 45 31 C0 08 C2 0F 84 C0 00 00 00 E9 AA 00 00 00 89 D0 25 C0 00 00 00 74 0D 3D C0 00 00 00 0F 85 96 00 00 00 EB 4A 48 63 EA 48 8D 44 29 01 48 3B 44 24 10 0F 83 81 00 00 00 4C 8D 24 2E 4D 39 EC 73 78 48 8D 59 01 45 8D 44 10 01 88 11 48 89 EA 44 89 0C 24 48 89 DF 44 89 44 24 08 E8 ?? ?? ?? ?? 44 8B 44 24 08 44 8B 0C 24 48 8D 0C 2B EB 5B 4C 39 EE 73 45 45 85 C9 79 09 89 F0 44 29 F0 44 8D 48 01 41 0F B6 44 24 01 83 E2 3F C1 E2 08 09 C2 48 63 C2 4D }
	condition:
		$pattern
}

rule __copy_rpcent_a56912834d146f616353350bc2b0cc91 {
	meta:
		aliases = "__copy_rpcent"
		size = "277"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 B8 02 00 00 00 41 56 49 89 CE 41 55 41 54 49 89 FC 55 48 89 F5 53 48 89 D3 48 83 EC 08 48 85 FF 49 C7 00 00 00 00 00 4C 89 04 24 0F 84 D6 00 00 00 BA 18 00 00 00 31 F6 48 89 EF E8 ?? ?? ?? ?? 4C 89 F2 31 F6 48 89 DF E8 ?? ?? ?? ?? 41 8B 44 24 10 49 8B 4C 24 08 31 D2 89 45 10 48 8B 04 D1 48 FF C2 48 85 C0 75 F4 48 8D 04 D5 00 00 00 00 49 39 C6 0F 82 89 00 00 00 4C 8D 6A FF 4C 8D 3C 03 49 29 C6 48 89 5D 08 EB 43 49 8B 44 24 08 4A 8D 1C ED 00 00 00 00 48 8B 3C 18 E8 ?? ?? ?? ?? 48 8D 50 01 49 39 D6 72 59 48 8B 45 08 49 29 D6 4C 89 3C 18 49 8B 44 24 08 49 01 D7 48 8B 34 18 48 8B 45 08 48 8B }
	condition:
		$pattern
}

rule __GI_gethostbyname_r_bef19a81278a2969861ffbaafcc735f5 {
	meta:
		aliases = "gethostbyname_r, __GI_gethostbyname_r"
		size = "897"
		objfiles = "gethostbyname_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 B8 16 00 00 00 41 56 41 55 49 89 D5 41 54 55 53 48 89 CB 48 81 EC B8 00 00 00 48 89 7C 24 30 48 89 74 24 28 4C 89 44 24 20 4C 89 4C 24 18 49 C7 00 00 00 00 00 48 83 7C 24 30 00 0F 84 2C 03 00 00 E8 ?? ?? ?? ?? 44 8B 20 48 89 C5 C7 00 00 00 00 00 48 8B 44 24 18 4C 8B 4C 24 20 49 89 D8 48 8B 54 24 28 48 8B 7C 24 30 4C 89 E9 BE 02 00 00 00 48 89 04 24 E8 ?? ?? ?? ?? 85 C0 0F 84 EB 02 00 00 48 8B 4C 24 18 8B 11 83 FA 01 74 17 83 FA 04 74 12 FF C2 0F 85 D2 02 00 00 83 7D 00 02 0F 85 C8 02 00 00 44 89 E8 44 89 65 00 F7 D8 83 E0 07 74 11 48 98 48 39 C3 0F 82 AA 02 00 00 49 01 C5 48 29 C3 48 8B }
	condition:
		$pattern
}

rule _svcauth_unix_85dd30dd0c617edd32fc763b4dad02b4 {
	meta:
		aliases = "_svcauth_unix"
		size = "433"
		objfiles = "svc_authux@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 B9 01 00 00 00 41 56 49 89 F6 41 55 41 54 55 53 48 83 EC 48 48 89 7C 24 08 4C 8B 6F 30 48 8D 5C 24 10 48 89 DF 49 8D 45 28 49 89 45 08 49 8D 85 28 01 00 00 49 89 45 20 44 8B 7E 40 48 8B 76 38 44 89 FA E8 ?? ?? ?? ?? 48 8B 44 24 18 44 89 FE 48 89 DF FF 50 30 48 85 C0 48 89 C2 0F 84 A9 00 00 00 8B 00 0F C8 89 C0 49 89 45 00 8B 6A 04 0F CD 81 FD FF 00 00 00 0F 87 07 01 00 00 4C 8D 62 08 49 8B 7D 08 89 EB 48 89 DA 4C 89 E6 E8 ?? ?? ?? ?? 49 8B 45 08 44 8D 45 03 41 83 E0 FC C6 04 18 00 44 89 C0 49 8D 14 04 8B 02 0F C8 41 89 45 10 8B 42 04 0F C8 41 89 45 14 8B 72 08 0F CE 83 FE 10 0F 87 BC 00 }
	condition:
		$pattern
}

rule __md5_crypt_9ef77d77690ffad294ce3bca0786e4b3 {
	meta:
		aliases = "__md5_crypt"
		size = "799"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 41 ) 57 BA 03 00 00 00 41 56 41 55 41 54 55 48 89 FD 53 48 89 F3 BE ?? ?? ?? ?? 48 89 DF 49 89 DD 48 81 EC 08 01 00 00 E8 ?? ?? ?? ?? 48 8D 53 03 85 C0 4C 0F 44 EA 4C 89 E9 EB 03 48 FF C1 8A 01 84 C0 0F 95 C2 3C 24 0F 95 C0 84 D0 74 09 49 8D 45 08 48 39 C1 72 E4 48 8D 9C 24 80 00 00 00 41 89 CE 45 29 EE 48 89 DF E8 B5 FC FF FF 48 89 EF E8 ?? ?? ?? ?? 48 89 DF 89 C2 48 89 EE 49 89 C4 41 89 C7 89 44 24 1C E8 3D FE FF FF 48 89 DF BA 03 00 00 00 BE ?? ?? ?? ?? E8 2B FE FF FF 48 89 DF 48 8D 5C 24 20 44 89 F2 4C 89 EE E8 18 FE FF FF 48 89 DF E8 69 FC FF FF 48 89 DF 44 89 E2 48 89 EE E8 02 FE FF FF 48 }
	condition:
		$pattern
}

rule __GI_mallinfo_04d9f96e7e012168e6c9f34592a48fd8 {
	meta:
		aliases = "mallinfo, __GI_mallinfo"
		size = "343"
		objfiles = "mallinfo@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 41 56 41 55 41 54 55 48 89 FD 53 48 83 EC 48 48 8D 7C 24 20 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 3D ?? ?? ?? ?? 00 75 0A BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 31 C9 45 31 C0 48 8B 40 08 C7 44 24 1C 00 00 00 00 48 89 44 24 10 EB 26 89 C8 48 8B 14 C5 ?? ?? ?? ?? EB 13 FF 44 24 1C 48 8B 42 08 48 8B 52 10 48 83 E0 FC 49 01 C0 48 85 D2 75 E8 FF C1 83 F9 0A 76 D5 48 8B 44 24 10 BE 01 00 00 00 C7 44 24 18 01 00 00 00 48 83 E0 FC 4E 8D 3C 00 EB 2D 8D 04 36 89 C0 48 8D 0C C5 ?? ?? ?? ?? 48 8B 51 18 EB 13 FF 44 24 18 48 8B 42 08 48 8B 52 18 }
	condition:
		$pattern
}

rule malloc_8a1e0f926a0c418d8b3f7104b9f72cd0 {
	meta:
		aliases = "malloc"
		size = "2149"
		objfiles = "malloc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 41 56 41 55 41 54 55 53 48 89 FB 48 83 EC 48 48 8D 7C 24 20 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 FB BF 76 12 31 DB E8 ?? ?? ?? ?? C7 00 0C 00 00 00 E9 0C 08 00 00 48 8D 43 17 48 8B 1D ?? ?? ?? ?? 41 BE 20 00 00 00 48 89 C2 48 83 E2 F0 48 83 F8 1F 4C 0F 47 F2 F6 C3 01 75 18 48 85 DB 0F 85 60 03 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 51 03 00 00 49 39 DE 77 24 44 89 F0 C1 E8 03 83 E8 02 48 8D 0C C5 ?? ?? ?? ?? 48 8B 51 08 48 85 D2 74 0A 48 8B 42 10 48 89 41 08 EB 3D 49 81 FE FF 00 00 00 77 3D 45 89 F4 41 C1 EC 03 43 8D 04 24 89 C0 48 8D 0C C5 ?? }
	condition:
		$pattern
}

rule __md5_Encode_a841488af07c6ddbadbd18c047852174 {
	meta:
		aliases = "__md5_Encode"
		size = "75"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 41 ) 89 D2 45 31 C9 45 31 C0 EB 3A 44 89 CA 44 89 C1 41 FF C1 48 8D 14 96 8B 02 88 04 0F 8B 02 41 8D 48 01 C1 E8 08 88 04 0F 8B 02 41 8D 48 02 C1 E8 10 88 04 0F 8B 02 41 8D 48 03 41 83 C0 04 C1 E8 18 88 04 0F 45 39 D0 72 C1 C3 }
	condition:
		$pattern
}

rule pwrite64_2c0a2c8c89c90d8efbb22d49bc3bca89 {
	meta:
		aliases = "__libc_pwrite, pwrite, __libc_pwrite64, pwrite64"
		size = "11"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 41 ) B8 01 00 00 00 E9 50 FF FF FF }
	condition:
		$pattern
}

rule iruserok_0141aa16f0c161afe3524079a40d906a {
	meta:
		aliases = "iruserok"
		size = "11"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 41 ) B8 ?? ?? ?? ?? E9 89 FE FF FF }
	condition:
		$pattern
}

rule __ivaliduser_4d19ed02d6feedc4618786728e6eefb9 {
	meta:
		aliases = "__ivaliduser"
		size = "11"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 41 ) B8 ?? ?? ?? ?? E9 F0 FC FF FF }
	condition:
		$pattern
}

rule getopt_long_only_b2f613f110c3b5ab541f0f55061b9133 {
	meta:
		aliases = "getopt_long_only"
		size = "11"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 41 ) B9 01 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getoffset_8a38dd2d1c23e82ab92e96ee3d639f6b {
	meta:
		aliases = "getoffset"
		size = "108"
		objfiles = "tzset@libc.a"
	strings:
		$pattern = { ( CC | 41 ) B9 ?? ?? ?? ?? 45 31 C0 83 CA FF 8A 0F 49 FF C1 8D 41 D0 3C 09 77 09 0F BE C1 48 FF C7 8D 50 D0 8A 0F 8D 41 D0 3C 09 77 0D 6B D2 0A 0F BE C1 48 FF C7 8D 54 02 D0 41 8A 09 0F BE C1 39 C2 72 04 31 FF EB 23 48 0F BE C1 48 63 D2 49 0F AF C0 4C 8D 04 10 31 D2 80 3F 3A 75 06 48 FF C7 83 CA FF FE C9 7F A7 4C 89 06 48 89 F8 C3 }
	condition:
		$pattern
}

rule strstr_8759f19610c506ac8a84e4d2f365133e {
	meta:
		aliases = "__GI_strstr, strstr"
		size = "187"
		objfiles = "strstr@libc.a"
	strings:
		$pattern = { ( CC | 44 ) 0F B6 16 45 85 D2 0F 84 A7 00 00 00 48 FF CF 48 FF C7 0F B6 07 85 C0 0F 84 9A 00 00 00 44 39 D0 75 ED 4C 8D 5E 01 0F B6 76 01 85 F6 0F 84 81 00 00 00 0F B6 47 01 48 8D 4F 01 EB 2E 0F B6 47 01 48 8D 4F 01 EB 19 85 C0 74 6D 48 FF C1 0F B6 01 44 39 D0 74 0F 85 C0 74 5E 48 FF C1 0F B6 01 44 39 D0 75 E2 48 FF C1 0F B6 01 39 F0 75 F1 0F B6 41 01 41 0F B6 53 01 4D 8D 4B 01 4C 8D 41 01 48 8D 79 FF 39 D0 75 28 85 D2 74 28 41 0F B6 40 01 41 0F B6 51 01 39 D0 75 16 85 D2 74 16 49 83 C0 02 49 83 C1 02 41 0F B6 11 41 0F B6 00 EB D4 85 D2 75 89 48 89 F8 C3 31 C0 C3 }
	condition:
		$pattern
}

rule __stdio_adjust_position_3eb8dde759b7aa8db7eaa01cfd70e3f3 {
	meta:
		aliases = "__stdio_adjust_position"
		size = "133"
		objfiles = "_adjust_pos@libc.a"
	strings:
		$pattern = { ( CC | 44 ) 8B 07 31 C9 53 41 0F B7 C0 89 C2 83 E2 03 74 2D 89 D1 FF C9 74 27 F6 C4 08 74 22 83 F9 01 7F 5D 83 7F 44 00 75 57 0F B6 47 03 29 C1 83 7F 48 00 89 C8 8D 48 FF 7E 06 0F B6 47 02 29 C1 41 80 E0 40 74 06 48 8B 47 08 EB 04 48 8B 47 20 2B 47 18 48 8B 16 8D 1C 01 48 89 D1 48 63 C3 48 29 C1 89 D8 F7 D8 48 39 D1 48 89 0E 0F 4F D8 85 DB 79 10 E8 ?? ?? ?? ?? C7 00 4B 00 00 00 EB 03 83 CB FF 89 D8 5B C3 }
	condition:
		$pattern
}

rule inet_aton_d430df5e8dc60a4c4b9d8502b4fe18bd {
	meta:
		aliases = "__GI_inet_aton, inet_aton"
		size = "137"
		objfiles = "inet_aton@libc.a"
	strings:
		$pattern = { ( CC | 45 ) 31 C0 48 85 FF 41 BA 01 00 00 00 75 61 EB 76 48 0F BE 07 4C 8B 0D ?? ?? ?? ?? 41 F6 04 41 08 74 64 31 D2 EB 15 6B D2 0A 0F BE C1 8D 54 02 D0 81 FA FF 00 00 00 7F 4E 48 FF C7 8A 0F 48 0F BE C1 41 0F B7 04 41 A8 08 75 DC 41 83 FA 03 7F 0A 80 F9 2E 75 31 48 FF C7 EB 0B 48 FF C7 84 C9 74 04 A8 20 74 21 41 C1 E0 08 41 FF C2 41 09 D0 41 83 FA 04 7E 9B 48 85 F6 B8 01 00 00 00 74 09 41 0F C8 44 89 06 C3 31 C0 C3 }
	condition:
		$pattern
}

rule __libc_pread64_563e2730dde361fdbd45736f26daff64 {
	meta:
		aliases = "pread, pread64, __libc_pread, __libc_pread64"
		size = "8"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 45 ) 31 C0 E9 48 FF FF FF }
	condition:
		$pattern
}

rule getopt_bcea34c689fcb89a43a05e1981359dcb {
	meta:
		aliases = "getopt"
		size = "13"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 45 ) 31 C9 45 31 C0 31 C9 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __libc_recv_a9fc4c9a1d9715abba65179cb62f82e2 {
	meta:
		aliases = "recv, __GI_recv, send, __GI_send, __libc_send, __libc_recv"
		size = "11"
		objfiles = "send@libc.a, recv@libc.a"
	strings:
		$pattern = { ( CC | 45 ) 31 C9 45 31 C0 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getopt_long_a640161b3f25582025daab4e1dd74c60 {
	meta:
		aliases = "getopt_long"
		size = "8"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 45 ) 31 C9 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule inet_network_f88d104ad4915a2a6ce264f5f0f83701 {
	meta:
		aliases = "__GI_inet_network, inet_network"
		size = "219"
		objfiles = "inet_net@libc.a"
	strings:
		$pattern = { ( CC | 45 ) 31 DB 45 31 C9 31 F6 80 3F 30 41 BA 0A 00 00 00 75 22 48 FF C7 40 B6 01 41 B2 08 8A 07 3C 78 0F 94 C2 3C 58 0F 94 C0 08 C2 74 09 48 FF C7 40 30 F6 41 B2 10 45 31 C0 EB 65 48 8B 05 ?? ?? ?? ?? 0F B6 D1 0F B7 04 50 A8 08 74 22 41 83 FA 08 0F 94 C2 80 F9 37 0F 97 C0 84 D0 75 76 44 89 C2 0F B6 C1 41 0F AF D2 44 8D 44 02 D0 EB 20 41 83 FA 10 75 31 A8 10 74 2D 83 E0 02 44 89 C2 83 F8 01 19 C0 C1 E2 04 83 E0 20 44 8D 44 10 A9 41 81 F8 FF 00 00 00 77 3C 48 FF C7 BE 01 00 00 00 8A 0F 84 C9 75 95 85 F6 74 2A 44 89 C8 C1 E0 08 45 85 DB 44 0F 45 C8 45 09 C1 80 F9 2E 75 11 41 FF C3 41 83 FB 04 74 0C 48 }
	condition:
		$pattern
}

rule _setjmp_4804825d1d3aedfebdc6d8e8bd249615 {
	meta:
		aliases = "_setjmp"
		size = "8"
		objfiles = "bsd__setjmp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 31 F6 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wmemmove_b9ef295258cc57fcf175201c85738edd {
	meta:
		aliases = "wmemmove"
		size = "65"
		objfiles = "wmemmove@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 39 FE 48 89 D1 49 89 F8 48 89 F2 73 12 EB 28 8B 02 48 FF C9 48 83 C2 04 41 89 00 49 83 C0 04 48 85 C9 75 EB EB 16 48 FF C9 48 8D 14 8D 00 00 00 00 8B 04 16 89 04 17 48 85 C9 75 EA 48 89 F8 C3 }
	condition:
		$pattern
}

rule wait_node_dequeue_23d15d204a3b7debfd46a8067b408971 {
	meta:
		aliases = "wait_node_dequeue"
		size = "42"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 39 FE 75 1E 48 8B 0A 48 89 D0 F0 48 0F B1 0E 0F 94 C1 84 C9 74 04 C3 48 89 C6 48 8B 06 48 39 C2 75 F5 48 8B 02 48 89 06 C3 }
	condition:
		$pattern
}

rule thread_self_fc567cf57d3f04fc77b3c53a5a9fe529 {
	meta:
		aliases = "thread_self"
		size = "69"
		objfiles = "condvar@libpthread.a, specific@libpthread.a, semaphore@libpthread.a, pthread@libpthread.a, errno@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 3B 25 ?? ?? ?? ?? 48 89 E2 B8 ?? ?? ?? ?? 73 33 48 3B 25 ?? ?? ?? ?? 72 0E 48 3B 25 ?? ?? ?? ?? B8 ?? ?? ?? ?? 72 1C 83 3D ?? ?? ?? ?? 00 74 05 E9 ?? ?? ?? ?? 48 81 CA FF FF 1F 00 48 8D 82 01 FD FF FF C3 }
	condition:
		$pattern
}

rule load_field_02154cc944d6342922eab6f4396dde3f {
	meta:
		aliases = "load_field"
		size = "71"
		objfiles = "strftime@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 63 C7 83 FF 07 8B 0C 86 8D 47 3A 48 98 8A 90 ?? ?? ?? ?? B8 6D 01 00 00 74 13 83 FF 05 0F B6 C2 75 0B 81 C1 6C 07 00 00 B8 0F 27 00 00 39 C1 77 0F 83 FF 03 0F 94 C2 85 C9 0F 94 C0 84 D0 74 03 83 C9 FF 89 C8 C3 }
	condition:
		$pattern
}

rule __mulvsi3_db68a7d221da9dc9e249a57026d39317 {
	meta:
		aliases = "__mulvsi3"
		size = "42"
		objfiles = "_mulvsi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 63 CF 48 63 F6 48 83 EC 08 48 0F AF CE 48 89 CA 89 C8 48 C1 FA 20 C1 F8 1F 39 D0 75 07 89 C8 48 83 C4 08 C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule reboot_54f1a89fed5d58467e86158d170eab9f {
	meta:
		aliases = "reboot"
		size = "53"
		objfiles = "reboot@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 63 D7 53 BE 69 19 12 28 48 C7 C7 AD DE E1 FE B8 A9 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_sigblock_ae925dba31f92abc96a910e7e125c070 {
	meta:
		aliases = "sigblock, __GI_sigblock"
		size = "82"
		objfiles = "sigblock@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC 08 01 00 00 89 FF B8 0E 00 00 00 48 8D 94 24 88 00 00 00 48 89 BC 24 80 00 00 00 48 C7 02 00 00 00 00 48 83 C2 08 FF C8 79 F1 48 8D B4 24 80 00 00 00 48 89 E2 31 FF E8 ?? ?? ?? ?? 89 C2 83 C8 FF 39 C2 0F 4F 04 24 48 81 C4 08 01 00 00 C3 }
	condition:
		$pattern
}

rule __GI_sigsetmask_91547ba3c94c44ae5323dfd5b7bf8eae {
	meta:
		aliases = "sigsetmask, __GI_sigsetmask"
		size = "85"
		objfiles = "sigsetmask@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC 08 01 00 00 89 FF B8 0E 00 00 00 48 8D 94 24 88 00 00 00 48 89 BC 24 80 00 00 00 48 C7 02 00 00 00 00 48 83 C2 08 FF C8 79 F1 48 8D B4 24 80 00 00 00 48 89 E2 BF 02 00 00 00 E8 ?? ?? ?? ?? 89 C2 83 C8 FF 39 C2 0F 4F 04 24 48 81 C4 08 01 00 00 C3 }
	condition:
		$pattern
}

rule __sysv_signal_1e6110ddc5ccc3b61704f588fdcbf79d {
	meta:
		aliases = "sysv_signal, __sysv_signal"
		size = "128"
		objfiles = "sysv_signal@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC 48 01 00 00 48 83 FE FF 0F 94 C2 85 FF 0F 9E C0 08 C2 75 05 83 FF 40 7E 11 E8 ?? ?? ?? ?? 48 83 CA FF C7 00 16 00 00 00 EB 48 BA 10 00 00 00 48 89 B4 24 A0 00 00 00 EB 0F 48 63 C2 48 C7 84 C4 A8 00 00 00 00 00 00 00 FF CA 79 ED 48 8D B4 24 A0 00 00 00 48 89 E2 C7 84 24 28 01 00 00 00 00 00 E0 E8 ?? ?? ?? ?? 48 83 CA FF FF C0 48 0F 4F 14 24 48 89 D0 48 81 C4 48 01 00 00 C3 }
	condition:
		$pattern
}

rule __GI_svc_getreq_788b772a72f30f3825ec8bf48f11c706 {
	meta:
		aliases = "svc_getreq, __GI_svc_getreq"
		size = "51"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC 88 00 00 00 31 D2 EB 0C 89 D0 FF C2 48 C7 04 C4 00 00 00 00 83 FA 0F 76 EF 48 63 C7 48 89 E7 48 89 04 24 E8 ?? ?? ?? ?? 48 81 C4 88 00 00 00 C3 }
	condition:
		$pattern
}

rule des_init_98185a5558477d54d93413d71bc77ecf {
	meta:
		aliases = "des_init"
		size = "1029"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC 90 01 00 00 83 3D ?? ?? ?? ?? 01 0F 84 E9 03 00 00 45 31 C9 C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 EB 4E 48 8D 84 24 88 01 00 00 49 63 C9 44 89 C2 48 C1 E1 06 83 E2 20 49 63 F8 48 8D 34 01 44 89 C0 83 E0 01 C1 E0 04 09 C2 44 89 C0 41 FF C0 D1 F8 83 E0 0F 09 C2 48 63 D2 8A 84 11 ?? ?? ?? ?? 88 84 3E 00 FE FF FF 41 83 F8 3F 7E B5 41 FF C1 41 83 F9 07 7F 05 45 31 C0 EB EC 45 31 D2 EB 62 43 8D 14 12 48 8D 8C 24 88 01 00 00 49 63 C1 44 89 CE 49 63 FA 48 63 D2 C1 E6 06 48 C1 E7 0C 48 C1 E2 06 44 09 C6 48 01 CA }
	condition:
		$pattern
}

rule __mulvti3_b9af6af8a9094e679f71adb7d00e7e7e {
	meta:
		aliases = "__mulvti3"
		size = "765"
		objfiles = "_mulvdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC 98 00 00 00 48 89 BC 24 80 00 00 00 4C 8B 84 24 80 00 00 00 48 89 B4 24 88 00 00 00 48 8B BC 24 88 00 00 00 48 89 54 24 70 48 89 4C 24 78 4C 89 C0 48 C1 F8 3F 48 39 C7 75 34 48 8B 4C 24 70 48 8B 7C 24 78 48 89 C8 48 C1 F8 3F 48 39 C7 0F 85 D3 00 00 00 4C 89 C0 48 F7 E9 48 89 C6 48 89 D7 48 89 F0 48 89 FA 48 81 C4 98 00 00 00 C3 4C 8B 5C 24 70 48 8B 54 24 78 4C 89 D8 48 C1 F8 3F 48 39 C2 0F 85 83 01 00 00 45 31 D2 31 D2 4C 89 C0 48 89 D1 4C 89 D6 49 0F AF F0 49 0F AF CB 49 F7 E3 48 01 F1 48 8D 14 11 4C 89 D1 48 89 44 24 40 48 0F AF CF 48 89 F8 48 89 54 24 48 31 D2 48 89 D6 49 0F AF F3 }
	condition:
		$pattern
}

rule direxists_227a372fba0a4c864be3252301f55083 {
	meta:
		aliases = "direxists"
		size = "50"
		objfiles = "tempname@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC 98 00 00 00 48 89 E6 E8 ?? ?? ?? ?? 31 D2 85 C0 75 13 8B 44 24 18 31 D2 25 00 F0 00 00 3D 00 40 00 00 0F 94 C2 89 D0 48 81 C4 98 00 00 00 C3 }
	condition:
		$pattern
}

rule sigignore_aeb7f5afce4edae044418b6ea3315f08 {
	meta:
		aliases = "sigignore"
		size = "67"
		objfiles = "sigignore@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC A8 00 00 00 BA 10 00 00 00 48 C7 04 24 01 00 00 00 EB 0C 48 63 C2 48 C7 44 C4 08 00 00 00 00 FF CA 79 F0 48 89 E6 31 D2 C7 84 24 88 00 00 00 00 00 00 00 E8 ?? ?? ?? ?? 48 81 C4 A8 00 00 00 C3 }
	condition:
		$pattern
}

rule __pthread_manager_sighandler_bbc944214888d9fb8f81c38777c3d168 {
	meta:
		aliases = "__pthread_manager_sighandler"
		size = "103"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC B8 00 00 00 8B 05 ?? ?? ?? ?? 31 D2 85 C0 75 0C 31 D2 83 3D ?? ?? ?? ?? 00 0F 95 C2 85 D2 C7 05 ?? ?? ?? ?? 01 00 00 00 74 32 48 C7 04 24 00 00 00 00 C7 44 24 08 06 00 00 00 8B 3D ?? ?? ?? ?? 48 89 E6 BA A8 00 00 00 E8 ?? ?? ?? ?? 48 FF C0 75 0A E8 ?? ?? ?? ?? 83 38 04 74 DE 48 81 C4 B8 00 00 00 C3 }
	condition:
		$pattern
}

rule snprintf_54d39b834bdc4c8ee49cf3cde03e5a9c {
	meta:
		aliases = "swprintf, __GI_snprintf, snprintf"
		size = "137"
		objfiles = "snprintf@libc.a, swprintf@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC D8 00 00 00 48 89 4C 24 38 0F B6 C8 4C 89 44 24 40 48 8D 04 8D 00 00 00 00 B9 ?? ?? ?? ?? 4C 89 4C 24 48 48 29 C1 48 8D 84 24 CF 00 00 00 FF E1 0F 29 78 F1 0F 29 70 E1 0F 29 68 D1 0F 29 60 C1 0F 29 58 B1 0F 29 50 A1 0F 29 48 91 0F 29 40 81 48 8D 84 24 E0 00 00 00 48 89 E1 C7 04 24 18 00 00 00 C7 44 24 04 30 00 00 00 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 E8 ?? ?? ?? ?? 48 81 C4 D8 00 00 00 C3 }
	condition:
		$pattern
}

rule err_b245397afba0dbdc482d035ebf365e87 {
	meta:
		aliases = "errx, err"
		size = "134"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC D8 00 00 00 48 89 54 24 30 0F B6 D0 48 89 4C 24 38 48 8D 04 95 00 00 00 00 BA ?? ?? ?? ?? 4C 89 44 24 40 4C 89 4C 24 48 48 29 C2 48 8D 84 24 CF 00 00 00 FF E2 0F 29 78 F1 0F 29 70 E1 0F 29 68 D1 0F 29 60 C1 0F 29 58 B1 0F 29 50 A1 0F 29 48 91 0F 29 40 81 48 8D 84 24 E0 00 00 00 48 89 E2 C7 04 24 10 00 00 00 C7 44 24 04 30 00 00 00 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_syslog_4f17e5776fd93321a6b366d662782192 {
	meta:
		aliases = "__GI_fscanf, __GI_fprintf, fwprintf, __GI_asprintf, fscanf, swscanf, fprintf, __GI_sscanf, syslog, sscanf, asprintf, dprintf, fwscanf, __GI_syslog"
		size = "142"
		objfiles = "fprintf@libc.a, swscanf@libc.a, fwscanf@libc.a, sscanf@libc.a, dprintf@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC D8 00 00 00 48 89 54 24 30 0F B6 D0 48 89 4C 24 38 48 8D 04 95 00 00 00 00 BA ?? ?? ?? ?? 4C 89 44 24 40 4C 89 4C 24 48 48 29 C2 48 8D 84 24 CF 00 00 00 FF E2 0F 29 78 F1 0F 29 70 E1 0F 29 68 D1 0F 29 60 C1 0F 29 58 B1 0F 29 50 A1 0F 29 48 91 0F 29 40 81 48 8D 84 24 E0 00 00 00 48 89 E2 C7 04 24 10 00 00 00 C7 44 24 04 30 00 00 00 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 E8 ?? ?? ?? ?? 48 81 C4 D8 00 00 00 C3 }
	condition:
		$pattern
}

rule __GI_sprintf_d844a304a595519b138027611e7f4baa {
	meta:
		aliases = "sprintf, __GI_sprintf"
		size = "149"
		objfiles = "sprintf@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC D8 00 00 00 48 89 54 24 30 0F B6 D0 48 89 4C 24 38 48 8D 04 95 00 00 00 00 BA ?? ?? ?? ?? 4C 89 44 24 40 4C 89 4C 24 48 48 89 E1 48 29 C2 48 8D 84 24 CF 00 00 00 FF E2 0F 29 78 F1 0F 29 70 E1 0F 29 68 D1 0F 29 60 C1 0F 29 58 B1 0F 29 50 A1 0F 29 48 91 0F 29 40 81 48 8D 84 24 E0 00 00 00 48 89 F2 48 83 CE FF C7 04 24 10 00 00 00 C7 44 24 04 30 00 00 00 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 E8 ?? ?? ?? ?? 48 81 C4 D8 00 00 00 C3 }
	condition:
		$pattern
}

rule warn_77524bd231933e6adcf365bf2b85dee9 {
	meta:
		aliases = "warnx, warn"
		size = "147"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC D8 00 00 00 48 89 54 24 30 0F B6 D0 48 89 74 24 28 48 8D 04 95 00 00 00 00 BA ?? ?? ?? ?? 48 89 4C 24 38 4C 89 44 24 40 4C 89 4C 24 48 48 89 E6 48 29 C2 48 8D 84 24 CF 00 00 00 FF E2 0F 29 78 F1 0F 29 70 E1 0F 29 68 D1 0F 29 60 C1 0F 29 58 B1 0F 29 50 A1 0F 29 48 91 0F 29 40 81 48 8D 84 24 E0 00 00 00 C7 04 24 08 00 00 00 C7 44 24 04 30 00 00 00 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 E8 ?? ?? ?? ?? 48 81 C4 D8 00 00 00 C3 }
	condition:
		$pattern
}

rule wprintf_e0fef7b1e267e11058ce53fdb7788479 {
	meta:
		aliases = "printf, __GI_printf, wscanf, scanf, wprintf"
		size = "157"
		objfiles = "scanf@libc.a, printf@libc.a, wprintf@libc.a, wscanf@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC D8 00 00 00 48 89 54 24 30 0F B6 D0 48 89 74 24 28 48 8D 04 95 00 00 00 00 BA ?? ?? ?? ?? 48 89 4C 24 38 4C 89 44 24 40 4C 89 4C 24 48 48 89 FE 48 29 C2 48 8D 84 24 CF 00 00 00 FF E2 0F 29 78 F1 0F 29 70 E1 0F 29 68 D1 0F 29 60 C1 0F 29 58 B1 0F 29 50 A1 0F 29 48 91 0F 29 40 81 48 8D 84 24 E0 00 00 00 48 8B 3D ?? ?? ?? ?? 48 89 E2 C7 04 24 08 00 00 00 C7 44 24 04 30 00 00 00 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 E8 ?? ?? ?? ?? 48 81 C4 D8 00 00 00 C3 }
	condition:
		$pattern
}

rule __GI___libc_open64_d8dc12dd6ea513d88ff1358d7923b3d0 {
	meta:
		aliases = "__libc_open64, __GI_open64, open64, __GI___libc_open64"
		size = "71"
		objfiles = "open64@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC D8 00 00 00 48 89 54 24 30 31 D2 40 F6 C6 40 74 24 48 8D 84 24 E0 00 00 00 C7 04 24 18 00 00 00 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 48 83 C0 10 8B 10 31 C0 E8 ?? ?? ?? ?? 48 81 C4 D8 00 00 00 C3 }
	condition:
		$pattern
}

rule ulimit_f32d4653752ecd0249b4b6b437100588 {
	meta:
		aliases = "ulimit"
		size = "230"
		objfiles = "ulimit@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC E8 00 00 00 83 FF 02 48 8D 84 24 F0 00 00 00 48 89 74 24 38 C7 04 24 08 00 00 00 48 89 44 24 08 48 8D 44 24 30 48 89 44 24 10 74 33 83 FF 04 0F 84 85 00 00 00 83 FF 01 0F 85 8B 00 00 00 48 8D 74 24 20 E8 ?? ?? ?? ?? 48 83 CA FF 85 C0 0F 85 84 00 00 00 48 8B 54 24 20 48 C1 EA 09 EB 79 48 8B 44 24 10 C7 04 24 10 00 00 00 48 83 C0 08 48 8B 10 48 B8 FF FF FF FF FF FF 7F 00 48 39 C2 76 14 48 C7 44 24 20 FF FF FF FF 48 C7 44 24 28 FF FF FF FF EB 11 48 89 D0 48 C1 E0 09 48 89 44 24 20 48 89 44 24 28 48 8D 74 24 20 BF 01 00 00 00 E8 ?? ?? ?? ?? 48 63 D0 EB 1E BF 04 00 00 00 E8 ?? ?? ?? ?? 48 }
	condition:
		$pattern
}

rule pthread_attr_setstacksize_e306e97039f6b646b83e90432117102b {
	meta:
		aliases = "__pthread_attr_setstacksize, pthread_attr_setstacksize"
		size = "21"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 81 FE FF 3F 00 00 B8 16 00 00 00 76 06 48 89 77 30 30 C0 C3 }
	condition:
		$pattern
}

rule valloc_1ab0af5c103933af6971b08af923e019 {
	meta:
		aliases = "valloc"
		size = "44"
		objfiles = "valloc@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 3D ?? ?? ?? ?? 00 53 48 89 FB 75 0E E8 ?? ?? ?? ?? 48 98 48 89 05 ?? ?? ?? ?? 48 89 DE 48 8B 3D ?? ?? ?? ?? 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule frame_dummy_8c3e31201b12dc6cbcca8dd5cf2d64e7 {
	meta:
		aliases = "frame_dummy"
		size = "71"
		objfiles = "crtbeginS"
	strings:
		$pattern = { ( CC | 48 ) 83 3D ?? ?? ?? ?? 00 55 48 89 E5 74 13 48 8D 35 ?? ?? ?? ?? 48 8D 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 3D ?? ?? ?? ?? 00 74 1A 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 0E 48 8D 3D ?? ?? ?? ?? 49 89 C3 C9 41 FF E3 C9 C3 }
	condition:
		$pattern
}

rule __pthread_alt_trylock_08ba02d5623ec65417ed6ca964076924 {
	meta:
		aliases = "__pthread_trylock, __pthread_alt_trylock"
		size = "37"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 3F 00 74 06 B8 10 00 00 00 C3 31 D2 B9 01 00 00 00 48 89 D0 F0 48 0F B1 0F 0F 94 C2 84 D2 74 DE 31 C0 C3 }
	condition:
		$pattern
}

rule __GI_pthread_cond_destroy_b564150feb36c8f2fc5aa0b57fea845a {
	meta:
		aliases = "pthread_cond_destroy, __GI_pthread_cond_destroy"
		size = "13"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 7F 10 01 19 C0 F7 D0 83 E0 10 C3 }
	condition:
		$pattern
}

rule ftrylockfile_79d502e13d9cfbabf1eaba40db91a239 {
	meta:
		aliases = "flockfile, funlockfile, ftrylockfile"
		size = "9"
		objfiles = "funlockfile@libc.a, flockfile@libc.a, ftrylockfile@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 C7 58 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule swab_f6c1790a3078521a1054e1fe0d621c0b {
	meta:
		aliases = "swab"
		size = "34"
		objfiles = "swab@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 E2 FE 48 8D 14 17 EB 12 66 8B 07 48 83 C7 02 66 C1 C8 08 66 89 06 48 83 C6 02 48 39 D7 72 E9 C3 }
	condition:
		$pattern
}

rule _init_4651bf9dcc93232b0ec147283aee7e08 {
	meta:
		aliases = "_fini, _init"
		size = "4"
		objfiles = "crti"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 }
	condition:
		$pattern
}

rule __kernel_tan_857106c42b4107b6cbf4d97485d5501a {
	meta:
		aliases = "__kernel_tan"
		size = "569"
		objfiles = "k_tan@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 0F 28 E8 F2 0F 11 04 24 48 8B 14 24 0F 28 F1 48 C1 EA 20 89 D1 81 E1 FF FF FF 7F 81 F9 FF FF 2F 3E 7F 47 F2 0F 2C C0 85 C0 75 3F 48 8B 14 24 8D 47 01 09 D1 09 C1 75 16 E8 ?? ?? ?? ?? 66 0F 12 2D ?? ?? ?? ?? F2 0F 5E E8 E9 E2 01 00 00 FF CF 0F 84 DA 01 00 00 66 0F 12 05 ?? ?? ?? ?? F2 0F 5E C5 0F 28 E8 E9 C6 01 00 00 81 F9 27 94 E5 3F 7E 36 85 D2 79 10 F2 0F 10 05 ?? ?? ?? ?? 66 0F 57 E8 66 0F 57 F0 66 0F 12 05 ?? ?? ?? ?? F2 0F 5C C5 0F 28 E8 66 0F 12 05 ?? ?? ?? ?? F2 0F 5C C6 0F 57 F6 F2 0F 58 E8 0F 28 D5 81 F9 27 94 E5 3F F2 0F 59 D5 0F 28 CA 0F 28 DA F2 0F 59 CA F2 0F 59 DD 0F }
	condition:
		$pattern
}

rule __fixsfti_712308e65b29deda91ac7e62e83d87c6 {
	meta:
		aliases = "__fixsfti"
		size = "51"
		objfiles = "_fixsfdi@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 0F 2E 05 ?? ?? ?? ?? 7A 02 72 09 48 83 C4 08 E9 ?? ?? ?? ?? 0F 57 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 F7 D8 48 83 D2 00 48 83 C4 08 48 F7 DA C3 }
	condition:
		$pattern
}

rule sem_destroy_ef745794f3ce1785fa63676b76bde11b {
	meta:
		aliases = "__new_sem_destroy, sem_destroy"
		size = "30"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 31 C0 48 83 7F 18 00 74 0E E8 ?? ?? ?? ?? C7 00 10 00 00 00 83 C8 FF 41 58 C3 }
	condition:
		$pattern
}

rule wctomb_7988619b9eb7a65db54a5a01212f9f29 {
	meta:
		aliases = "wctomb"
		size = "20"
		objfiles = "wctomb@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 31 C0 48 85 FF 74 07 31 D2 E8 ?? ?? ?? ?? 5A C3 }
	condition:
		$pattern
}

rule tcsetpgrp_1c3e47f41ee42d8f4b6c13ce528aa910 {
	meta:
		aliases = "tcsetpgrp"
		size = "27"
		objfiles = "tcsetpgrp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 31 C0 48 8D 54 24 04 89 74 24 04 BE 10 54 00 00 E8 ?? ?? ?? ?? 5A C3 }
	condition:
		$pattern
}

rule __old_sem_destroy_6d9495b056381ba97c48163f2ba065d1 {
	meta:
		aliases = "__old_sem_destroy"
		size = "27"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 31 C0 F6 07 01 75 0E E8 ?? ?? ?? ?? C7 00 10 00 00 00 83 C8 FF 5A C3 }
	condition:
		$pattern
}

rule __opensock_aadc152ca49433dce7034e9b42d73083 {
	meta:
		aliases = "__opensock"
		size = "45"
		objfiles = "opensock@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 31 D2 BE 02 00 00 00 BF 0A 00 00 00 E8 ?? ?? ?? ?? 85 C0 79 12 59 31 D2 BE 02 00 00 00 BF 02 00 00 00 E9 ?? ?? ?? ?? 5A C3 }
	condition:
		$pattern
}

rule __pthread_initialize_minimal_bc0ad849dbe26e6f210aa92a41ffbda3 {
	meta:
		aliases = "__pthread_initialize_minimal"
		size = "20"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 31 FF E8 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 58 C3 }
	condition:
		$pattern
}

rule base_from_object_16591403c31bf54c86eca420659cb3f5 {
	meta:
		aliases = "base_from_object"
		size = "82"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 40 80 FF FF 89 F8 74 1F 83 E0 70 83 F8 20 74 1E 7E 11 83 F8 30 74 2F 83 F8 50 66 90 74 09 E8 ?? ?? ?? ?? 85 C0 75 15 31 C0 48 83 C4 08 C3 48 8B 46 08 48 83 C4 08 C3 66 66 90 66 90 83 F8 10 74 E6 E8 ?? ?? ?? ?? 48 8B 46 10 66 90 EB DB }
	condition:
		$pattern
}

rule size_of_encoded_value_4e677f5cab5febe8581939b27b650da4 {
	meta:
		aliases = "size_of_encoded_value"
		size = "82"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 40 80 FF FF 89 F8 74 3F 83 E0 07 83 F8 02 74 21 7E 11 83 F8 03 74 26 83 F8 04 66 90 74 09 E8 ?? ?? ?? ?? 85 C0 75 F7 B8 08 00 00 00 48 83 C4 08 C3 B8 02 00 00 00 48 83 C4 08 66 90 C3 B8 04 00 00 00 48 83 C4 08 C3 31 C0 66 66 90 EB DE }
	condition:
		$pattern
}

rule getusershell_b5ddcb24c6eef89c62afcbe89dc1777a {
	meta:
		aliases = "getusershell"
		size = "57"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 83 3D ?? ?? ?? ?? 00 75 0C E8 7A FE FF FF 48 89 05 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 8B 10 48 85 D2 74 0B 48 83 C0 08 48 89 05 ?? ?? ?? ?? 59 48 89 D0 C3 }
	condition:
		$pattern
}

rule __initbuf_130c47b7197ead03aa63d8d21272e87a {
	meta:
		aliases = "__initbuf"
		size = "43"
		objfiles = "getproto@libc.a, getservice@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 83 3D ?? ?? ?? ?? 00 75 1B BF 19 11 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 75 05 E8 ?? ?? ?? ?? 58 C3 }
	condition:
		$pattern
}

rule __absvti2_b047c821b4d9cd12b904a55fafc0c489 {
	meta:
		aliases = "__absvti2"
		size = "40"
		objfiles = "_absvdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 85 F6 48 89 F8 48 89 F2 78 05 48 83 C4 08 C3 48 F7 D8 48 83 D2 00 48 F7 DA 48 85 D2 79 EC E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __addvdi3_456d01d5ef99b1715b34abd9b81db8cb {
	meta:
		aliases = "__addvdi3"
		size = "45"
		objfiles = "_addvsi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 85 F6 48 8D 04 37 78 13 48 39 C7 0F 9F C2 84 D2 75 11 48 83 C4 08 C3 66 66 66 90 48 39 C7 0F 9C C2 EB EB E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mbtowc_ac707c793f4d684a60f4fe4c1466e6e5 {
	meta:
		aliases = "mbtowc"
		size = "65"
		objfiles = "mbtowc@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 85 F6 75 0E 31 C9 C7 05 ?? ?? ?? ?? 00 00 00 00 EB 26 31 C9 80 3E 00 74 1F B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 F8 FE 89 C1 75 0D C7 05 ?? ?? ?? ?? FF FF 00 00 83 C9 FF 5A 89 C8 C3 }
	condition:
		$pattern
}

rule __absvdi2_1589063159228d3da67e0cf01c422c9c {
	meta:
		aliases = "__absvdi2"
		size = "30"
		objfiles = "_absvsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 85 FF 48 89 F8 78 05 48 83 C4 08 C3 48 F7 D8 48 85 C0 79 F3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule endmntent_49595508d2b541074721458c28172100 {
	meta:
		aliases = "__GI_endmntent, endmntent"
		size = "21"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 85 FF 74 05 E8 ?? ?? ?? ?? 5A B8 01 00 00 00 C3 }
	condition:
		$pattern
}

rule mblen_63267b824941d74136e638e4a8f832c0 {
	meta:
		aliases = "mblen"
		size = "65"
		objfiles = "mblen@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 85 FF 75 0E 31 D2 C7 05 ?? ?? ?? ?? 00 00 00 00 EB 26 31 D2 80 3F 00 74 1F BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 F8 FE 89 C2 75 0D C7 05 ?? ?? ?? ?? FF FF 00 00 83 CA FF 89 D0 5A C3 }
	condition:
		$pattern
}

rule __syscall_error_b736fc4035af5e10d99a76271cbe637f {
	meta:
		aliases = "__syscall_error"
		size = "22"
		objfiles = "__syscall_error@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 89 C1 48 F7 D9 E8 ?? ?? ?? ?? 89 08 83 C8 FF 5A C3 }
	condition:
		$pattern
}

rule __GI_pthread_exit_002540812356977fc450f8b2c6b676d9 {
	meta:
		aliases = "pthread_exit, __GI_pthread_exit"
		size = "12"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 89 E6 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule putw_e2356ac86781c69e3cf1099cf7b931ac {
	meta:
		aliases = "putw"
		size = "35"
		objfiles = "putw@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 89 F1 BA 01 00 00 00 89 7C 24 04 48 8D 7C 24 04 BE 04 00 00 00 E8 ?? ?? ?? ?? 5A FF C8 C3 }
	condition:
		$pattern
}

rule putwc_unlocked_3414b4db72b739b489ddc01bbc9cd986 {
	meta:
		aliases = "fputwc_unlocked, __GI_fputwc_unlocked, putwc_unlocked"
		size = "42"
		objfiles = "fputwc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 89 F2 BE 01 00 00 00 89 7C 24 04 48 8D 7C 24 04 E8 ?? ?? ?? ?? 48 89 C2 83 C8 FF 48 85 D2 0F 45 44 24 04 5A C3 }
	condition:
		$pattern
}

rule _rpcdata_b7a3db014b958b1d3e64a60912aabf9b {
	meta:
		aliases = "_rpcdata"
		size = "40"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 8B 05 ?? ?? ?? ?? 48 85 C0 75 16 BE 58 11 00 00 BF 01 00 00 00 E8 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 59 C3 }
	condition:
		$pattern
}

rule __old_sem_trywait_3778b651db270f2e55d0a826807e9e1e {
	meta:
		aliases = "__old_sem_trywait"
		size = "68"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 8B 0F 48 89 C8 48 83 F0 01 83 E0 01 48 83 F9 01 0F 94 C2 08 D0 74 10 E8 ?? ?? ?? ?? C7 00 0B 00 00 00 83 C8 FF EB 15 48 8D 51 FE 48 89 C8 F0 48 0F B1 17 0F 94 C2 84 D2 74 C5 31 C0 41 59 C3 }
	condition:
		$pattern
}

rule setttyent_95ce6ad94da1ad164d34cfb42f2ec101 {
	meta:
		aliases = "__GI_setttyent, setttyent"
		size = "72"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 8B 3D ?? ?? ?? ?? 48 85 FF 74 07 E8 ?? ?? ?? ?? EB 2A BF ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C7 48 89 05 ?? ?? ?? ?? 31 C0 48 85 FF 74 0F BE 02 00 00 00 E8 ?? ?? ?? ?? B8 01 00 00 00 59 C3 }
	condition:
		$pattern
}

rule endttyent_ee96157325e6c0b2a02a44d4b27c82c5 {
	meta:
		aliases = "__GI_endttyent, endttyent"
		size = "47"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 8B 3D ?? ?? ?? ?? B8 01 00 00 00 48 85 FF 74 18 E8 ?? ?? ?? ?? FF C0 48 C7 05 ?? ?? ?? ?? 00 00 00 00 0F 95 C0 0F B6 C0 5A C3 }
	condition:
		$pattern
}

rule print_and_abort_fc4ca9abdfaaf174f0431dc812072cd0 {
	meta:
		aliases = "print_and_abort"
		size = "38"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 8B 3D ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? BF 01 00 00 00 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __free_initshell_memory_edab68722be06255e0d7ec05773119e3 {
	meta:
		aliases = "__free_initshell_memory"
		size = "52"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 E8 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 58 C3 }
	condition:
		$pattern
}

rule svctcp_stat_7cb49c3f37082b7727379c2e45dd009a {
	meta:
		aliases = "svcunix_stat, svctcp_stat"
		size = "34"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 8B 57 40 31 C0 83 3A 00 74 11 48 8D 7A 10 E8 ?? ?? ?? ?? 83 F8 01 19 C0 83 C0 02 59 C3 }
	condition:
		$pattern
}

rule xdrstdio_setpos_9ae77b6a0c433a43af906c157046a146 {
	meta:
		aliases = "xdrstdio_setpos"
		size = "25"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 8B 7F 18 89 F6 31 D2 E8 ?? ?? ?? ?? 41 5A F7 D0 C1 E8 1F C3 }
	condition:
		$pattern
}

rule xdrstdio_getpos_84cd22520e7793d1ad4e174a29c8fa06 {
	meta:
		aliases = "xdrstdio_getpos"
		size = "16"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 8B 7F 18 E8 ?? ?? ?? ?? 41 5B C3 }
	condition:
		$pattern
}

rule _dl_protect_relro_0855ec744b80e9a44d6db47836050bc4 {
	meta:
		aliases = "_dl_protect_relro"
		size = "142"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 8B 97 A8 01 00 00 48 03 17 49 89 F8 48 8B 05 ?? ?? ?? ?? 48 89 D1 49 03 88 B0 01 00 00 48 F7 D8 48 89 D7 48 21 C7 48 21 C1 48 39 CF 74 59 48 89 CE BA 01 00 00 00 B8 0A 00 00 00 48 29 FE 0F 05 48 3D 00 F0 FF FF 48 89 C2 76 0A F7 D8 89 05 ?? ?? ?? ?? EB 04 85 D2 79 2E 49 8B 50 08 31 C0 BE ?? ?? ?? ?? BF 02 00 00 00 E8 ?? ?? ?? ?? 31 FF B8 3C 00 00 00 0F 05 48 3D 00 F0 FF FF 76 08 F7 D8 89 05 ?? ?? ?? ?? 5E C3 }
	condition:
		$pattern
}

rule __psfs_parse_spec_0c54b6ff1e048cc0c500b9c1637a4886 {
	meta:
		aliases = "__psfs_parse_spec"
		size = "479"
		objfiles = "__psfs_parse_spec@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 4C 8B 57 58 31 C9 41 B9 01 00 00 00 41 8A 02 83 E8 30 3C 09 77 53 81 F9 CB CC CC 0C 7F 15 48 8B 47 58 6B C9 0A 0F B6 10 48 FF C0 48 89 47 58 8D 4C 11 D0 48 8B 77 58 8A 16 8D 42 D0 3C 09 76 D6 80 FA 24 74 19 83 7F 48 00 0F 89 7C 01 00 00 89 4F 6C C7 47 48 FE FF FF FF E9 B0 00 00 00 48 8D 46 01 45 31 C9 48 89 47 58 BE ?? ?? ?? ?? 41 B8 10 00 00 00 48 8B 57 58 8A 06 3A 02 75 0E 44 08 47 71 48 8D 42 01 48 89 47 58 EB DD 48 FF C6 80 3E 00 74 05 45 01 C0 EB DB F6 47 71 10 74 06 C6 47 70 00 EB 3B 45 84 C9 74 1D 83 7F 48 00 0F 89 17 01 00 00 C7 47 48 FE FF FF FF EB 23 48 8D 41 01 48 89 47 }
	condition:
		$pattern
}

rule __fixdfti_054297002685e5e5d96c7dd90456632f {
	meta:
		aliases = "__fixdfti"
		size = "60"
		objfiles = "_fixdfdi@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 66 0F 2E 05 ?? ?? ?? ?? 7A 02 72 10 48 83 C4 08 E9 ?? ?? ?? ?? 66 66 66 90 66 66 90 66 0F 57 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 F7 D8 48 83 D2 00 48 83 C4 08 48 F7 DA C3 }
	condition:
		$pattern
}

rule cabsf_8dcf2cd6d5c3c46aad90c5d99b739188 {
	meta:
		aliases = "cargf, cabsf"
		size = "31"
		objfiles = "cabsf@libm.a, cargf@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 66 0F D6 04 24 F3 0F 5A 04 24 F3 0F 5A 4C 24 04 E8 ?? ?? ?? ?? F2 0F 5A C0 58 C3 }
	condition:
		$pattern
}

rule sysconf_d0df2b1096f3df3274c7c2956a3df9ae {
	meta:
		aliases = "__GI_sysconf, sysconf"
		size = "351"
		objfiles = "sysconf@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 81 FF 95 00 00 00 77 13 89 F8 FF 24 C5 ?? ?? ?? ?? B8 01 00 00 00 E9 3E 01 00 00 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 E2 00 00 00 B8 00 00 02 00 E9 24 01 00 00 B8 64 00 00 00 E9 1A 01 00 00 B8 00 00 01 00 E9 10 01 00 00 E8 ?? ?? ?? ?? EB 0F B8 06 00 00 00 E9 FF 00 00 00 E8 ?? ?? ?? ?? 48 98 E9 F3 00 00 00 B8 00 80 00 00 E9 E9 00 00 00 B8 E8 03 00 00 E9 DF 00 00 00 B8 00 40 00 00 E9 D5 00 00 00 B8 00 10 00 00 E9 CB 00 00 00 B8 F4 01 00 00 E9 C1 00 00 00 B8 08 00 00 00 E9 B7 00 00 00 48 C7 C0 00 00 00 80 E9 AB 00 00 00 B8 40 00 00 00 E9 A1 00 00 00 48 C7 C0 00 80 FF FF E9 95 00 00 00 }
	condition:
		$pattern
}

rule __GI__rpc_dtablesize_f0afb58eb734d9019f721410f96d3ba6 {
	meta:
		aliases = "_rpc_dtablesize, __GI__rpc_dtablesize"
		size = "32"
		objfiles = "rpc_dtablesize@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 83 3D ?? ?? ?? ?? 00 75 0B E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 5A C3 }
	condition:
		$pattern
}

rule __GI___uClibc_init_1ef9c1ff307db332dff8dd421ddf8c8e {
	meta:
		aliases = "__uClibc_init, __GI___uClibc_init"
		size = "67"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 83 3D ?? ?? ?? ?? 00 75 34 B8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 01 00 00 00 48 C7 05 ?? ?? ?? ?? 00 10 00 00 48 85 C0 74 05 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 48 85 C0 74 06 59 E9 ?? ?? ?? ?? 5A C3 }
	condition:
		$pattern
}

rule __assert_454eb2981bc236a0f92fd7f114cc3278 {
	meta:
		aliases = "__GI___assert, __assert"
		size = "77"
		objfiles = "__assert@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 83 3D ?? ?? ?? ?? 00 75 3B 48 89 3C 24 41 89 D0 48 8B 3D ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? 48 85 C9 41 B9 ?? ?? ?? ?? 4C 0F 45 C9 48 89 F1 31 C0 BE ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 01 00 00 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __setutent_68dbbf1a63133c56da3b248972819246 {
	meta:
		aliases = "__setutent"
		size = "154"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 83 3D ?? ?? ?? ?? FF 75 7D 48 8B 3D ?? ?? ?? ?? 31 C0 BE 02 00 00 00 E8 ?? ?? ?? ?? 85 C0 89 05 ?? ?? ?? ?? 79 1A 48 8B 3D ?? ?? ?? ?? 31 F6 31 C0 E8 ?? ?? ?? ?? 85 C0 89 05 ?? ?? ?? ?? 78 33 8B 3D ?? ?? ?? ?? 31 D2 31 C0 BE 01 00 00 00 E8 ?? ?? ?? ?? 85 C0 78 1B 8B 3D ?? ?? ?? ?? 83 C8 01 BE 02 00 00 00 89 C2 31 C0 E8 ?? ?? ?? ?? 85 C0 79 13 C7 05 ?? ?? ?? ?? FF FF FF FF 83 CF FF 5A E9 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 31 D2 31 F6 58 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdr_wrapstring_9e7be073c3467277721f9b087ddd5083 {
	meta:
		aliases = "xdr_wrapstring"
		size = "22"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 83 CA FF E8 ?? ?? ?? ?? 5A 85 C0 0F 95 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule setlocale_cbc0425654733b79ae243e72778c2362 {
	meta:
		aliases = "setlocale"
		size = "61"
		objfiles = "setlocale@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 83 FF 06 48 89 F2 77 2D 48 85 F6 74 21 8A 06 84 C0 74 1B 3C 43 75 06 80 7E 01 00 74 11 BE ?? ?? ?? ?? 48 89 D7 E8 ?? ?? ?? ?? 85 C0 75 07 B8 ?? ?? ?? ?? EB 02 31 C0 5A C3 }
	condition:
		$pattern
}

rule __getutent_8d0b27ec52fc838852d9d22a958966d1 {
	meta:
		aliases = "__getutent"
		size = "51"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 83 FF FF 75 07 E8 58 FF FF FF EB 1C BA 90 01 00 00 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 3D 90 01 00 00 BA ?? ?? ?? ?? 74 02 31 D2 59 48 89 D0 C3 }
	condition:
		$pattern
}

rule xdrstdio_putbytes_50318e03ec7413f0040be15205bd67b2 {
	meta:
		aliases = "xdrstdio_putbytes"
		size = "47"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 85 D2 49 89 F0 B8 01 00 00 00 74 1D 48 8B 4F 18 48 63 F2 4C 89 C7 BA 01 00 00 00 E8 ?? ?? ?? ?? 48 FF C8 0F 94 C0 0F B6 C0 5A C3 }
	condition:
		$pattern
}

rule xdrstdio_getbytes_77ccf8193a8b75f817eb378fbd824765 {
	meta:
		aliases = "xdrstdio_getbytes"
		size = "47"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 85 D2 49 89 F0 B8 01 00 00 00 74 1D 48 8B 4F 18 48 63 F2 4C 89 C7 BA 01 00 00 00 E8 ?? ?? ?? ?? 48 FF C8 0F 94 C0 0F B6 C0 5F C3 }
	condition:
		$pattern
}

rule __old_sem_init_da21dec94e9f264a2ee5da195211f902 {
	meta:
		aliases = "__old_sem_init"
		size = "62"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 85 D2 79 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 0F 85 F6 74 10 E8 ?? ?? ?? ?? C7 00 26 00 00 00 83 C8 FF EB 13 89 D0 C7 47 08 00 00 00 00 48 8D 44 00 01 48 89 07 31 C0 59 C3 }
	condition:
		$pattern
}

rule sem_init_dd9c878a446720d137b957690297eadd {
	meta:
		aliases = "__new_sem_init, sem_init"
		size = "71"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 85 D2 79 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 0F 85 F6 74 10 E8 ?? ?? ?? ?? C7 00 26 00 00 00 83 C8 FF EB 1B 48 C7 07 00 00 00 00 C7 47 08 00 00 00 00 31 C0 89 57 10 48 C7 47 18 00 00 00 00 41 5A C3 }
	condition:
		$pattern
}

rule sigismember_13bae3359f0ab5285d20861034590b27 {
	meta:
		aliases = "__GI_sigdelset, sigaddset, sigdelset, __GI_sigaddset, sigismember"
		size = "35"
		objfiles = "sigdelset@libc.a, sigaddset@libc.a, sigismem@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 85 F6 7E 0B 83 FE 40 7F 06 59 E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 5A C3 }
	condition:
		$pattern
}

rule __addvsi3_3827507451519ed5ecc420a95bda991e {
	meta:
		aliases = "__addvsi3"
		size = "44"
		objfiles = "_addvsi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 85 F6 8D 04 37 78 15 39 C7 0F 9F C2 84 D2 75 13 48 83 C4 08 C3 66 66 66 90 66 66 90 39 C7 0F 9C C2 EB E9 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule killpg_93a7cb87d5586e1f6449aeda290e3369 {
	meta:
		aliases = "killpg"
		size = "32"
		objfiles = "killpg@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 85 FF 78 08 59 F7 DF E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 5A C3 }
	condition:
		$pattern
}

rule __absvsi2_02d8ea0fb2728e05b26ae01ef071fd7d {
	meta:
		aliases = "__absvsi2"
		size = "27"
		objfiles = "_absvsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 85 FF 89 F8 78 06 48 83 C4 08 C3 90 F7 D8 85 C0 79 F4 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule re_compile_pattern_a93c1a076ac55b5736d330a76b47aa9c {
	meta:
		aliases = "__re_compile_pattern, re_compile_pattern"
		size = "59"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 8A 42 38 48 89 D1 83 E0 E9 83 C8 80 88 42 38 48 8B 15 ?? ?? ?? ?? E8 F1 D8 FF FF 31 D2 85 C0 74 11 48 98 48 8B 14 C5 ?? ?? ?? ?? 48 81 C2 ?? ?? ?? ?? 5F 48 89 D0 C3 }
	condition:
		$pattern
}

rule __deregister_frame_75a99e22bb3e6ae91932ea9f7506fcb0 {
	meta:
		aliases = "__deregister_frame"
		size = "33"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 8B 07 85 C0 75 06 48 83 C4 08 C3 90 E8 ?? ?? ?? ?? 48 83 C4 08 48 89 C7 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fileno_unlocked_0a902d39b600dfca4801543ca4ed6f79 {
	meta:
		aliases = "__GI_fileno_unlocked, fileno_unlocked"
		size = "27"
		objfiles = "fileno_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 8B 47 04 85 C0 79 0E E8 ?? ?? ?? ?? C7 00 09 00 00 00 83 C8 FF 5A C3 }
	condition:
		$pattern
}

rule __GI_setstate_r_ec7dfa314db8b99f073f23b94e6a4976 {
	meta:
		aliases = "setstate_r, __GI_setstate_r"
		size = "168"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 8B 4E 18 48 83 C7 04 48 8B 56 10 85 C9 75 09 C7 42 FC 00 00 00 00 EB 15 48 8B 46 08 48 29 D0 48 C1 F8 02 48 8D 04 80 8D 04 01 89 42 FC 8B 47 FC 41 B8 05 00 00 00 99 41 F7 F8 83 FA 04 77 55 48 63 C2 85 D2 89 56 18 8B 0C 85 ?? ?? ?? ?? 44 8B 0C 85 ?? ?? ?? ?? 89 4E 1C 44 89 4E 20 74 22 8B 47 FC 99 41 F7 F8 48 63 D0 44 01 C8 48 8D 14 97 48 89 56 08 99 F7 F9 48 63 D2 48 8D 14 97 48 89 16 48 63 C1 48 89 7E 10 48 8D 04 87 48 89 46 28 31 C0 EB 0E E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 5A C3 }
	condition:
		$pattern
}

rule brk_e670af30af24c00381bf09f4ef60c44b {
	meta:
		aliases = "__GI_brk, brk"
		size = "43"
		objfiles = "brk@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 B8 0C 00 00 00 31 D2 0F 05 48 39 F8 48 89 05 ?? ?? ?? ?? 73 0E E8 ?? ?? ?? ?? 83 CA FF C7 00 0C 00 00 00 89 D0 5A C3 }
	condition:
		$pattern
}

rule ptsname_f8e17a7c236f33d80796b0402d573c0f {
	meta:
		aliases = "ptsname"
		size = "36"
		objfiles = "ptsname@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 BA 1E 00 00 00 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C2 31 C0 85 D2 BA ?? ?? ?? ?? 48 0F 44 C2 5A C3 }
	condition:
		$pattern
}

rule ttyname_429332aded0d813fdbb9748bd645e83d {
	meta:
		aliases = "ttyname"
		size = "36"
		objfiles = "ttyname@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 BA 20 00 00 00 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C2 31 C0 85 D2 BA ?? ?? ?? ?? 48 0F 44 C2 5A C3 }
	condition:
		$pattern
}

rule __GI_strerror_f40bb2bad484cb6f9731cf80e97dd9a8 {
	meta:
		aliases = "strerror, __GI_strerror"
		size = "26"
		objfiles = "strerror@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 BA 32 00 00 00 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule wcwidth_2f4038736ba398beeb3f49f1cbd9de87 {
	meta:
		aliases = "wcwidth"
		size = "25"
		objfiles = "wcwidth@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 BE 01 00 00 00 89 7C 24 04 48 8D 7C 24 04 E8 ?? ?? ?? ?? 5A C3 }
	condition:
		$pattern
}

rule __open_etc_hosts_e4ee1b0988ebbd01fb481f8a63b28196 {
	meta:
		aliases = "__open_etc_hosts"
		size = "42"
		objfiles = "read_etc_hosts_r@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 75 10 59 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E9 ?? ?? ?? ?? 5A C3 }
	condition:
		$pattern
}

rule __GI_localtime_702ee4622085efff266ddbf30475b8da {
	meta:
		aliases = "seed48, localtime, __GI_localtime"
		size = "21"
		objfiles = "seed48@libc.a, localtime@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule rexec_076d74a54cf61d972c7d8f2c06c8dcb4 {
	meta:
		aliases = "rexec"
		size = "18"
		objfiles = "rexec@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 C7 04 24 02 00 00 00 E8 ?? ?? ?? ?? 5A C3 }
	condition:
		$pattern
}

rule __fp_range_check_7709b623b23b5a099a079a09f5bfae93 {
	meta:
		aliases = "__fp_range_check"
		size = "75"
		objfiles = "__fp_range_check@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 DB 6C 24 10 DB 6C 24 20 D9 05 ?? ?? ?? ?? D9 C2 D8 C9 D9 CB DB EB DD DB 75 25 7A 23 D9 EE D9 CB DF EB DD DA 7A 02 74 19 DC C9 DF E9 DF C0 7A 02 74 13 E8 ?? ?? ?? ?? C7 00 22 00 00 00 EB 06 DF C0 DF C0 DF C0 58 C3 }
	condition:
		$pattern
}

rule endusershell_59a99002bcc6ad5840d941378e7c5b6d {
	meta:
		aliases = "endusershell"
		size = "22"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 17 FE FF FF 48 C7 05 ?? ?? ?? ?? 00 00 00 00 5E C3 }
	condition:
		$pattern
}

rule pthread_testcancel_7b7b139bf096b6e97ec33138c67bd4b0 {
	meta:
		aliases = "pthread_testcancel"
		size = "35"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 7C FE FF FF 80 78 7A 00 74 12 80 78 78 00 75 0C 48 89 E6 48 83 CF FF E8 ?? ?? ?? ?? 58 C3 }
	condition:
		$pattern
}

rule setusershell_cc186aa08fbcb615e3cdcfffdfe02b87 {
	meta:
		aliases = "setusershell"
		size = "18"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 96 FE FF FF 48 89 05 ?? ?? ?? ?? 5A C3 }
	condition:
		$pattern
}

rule svcunix_rendezvous_abort_0b65a8924fcc66f5c1e12937b0a26173 {
	meta:
		aliases = "svctcp_rendezvous_abort, svcunix_rendezvous_abort"
		size = "9"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_ctime_f4be497721863e850c8ae13ba1be3f94 {
	meta:
		aliases = "ctime, __GI_ctime"
		size = "18"
		objfiles = "ctime@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 ?? ?? ?? ?? 48 89 C7 58 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule free_mem_2aa6f10f4bd79fbed5418b6a2c9c64ec {
	meta:
		aliases = "free_mem"
		size = "22"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 ?? ?? ?? ?? 48 8B B8 B8 00 00 00 58 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI___rpc_thread_createerr_f541993b62dee055ce603b451554a68b {
	meta:
		aliases = "__rpc_thread_createerr, __GI___rpc_thread_createerr"
		size = "36"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 ?? ?? ?? ?? 48 8D 88 80 00 00 00 48 3D ?? ?? ?? ?? BA ?? ?? ?? ?? 5E 48 0F 45 D1 48 89 D0 C3 }
	condition:
		$pattern
}

rule __rpc_thread_svc_pollfd_d8b47ca33cbb1aeb13ef968982ecdd03 {
	meta:
		aliases = "__GI___rpc_thread_svc_pollfd, __rpc_thread_svc_pollfd"
		size = "36"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 ?? ?? ?? ?? 48 8D 88 A0 00 00 00 48 3D ?? ?? ?? ?? BA ?? ?? ?? ?? 48 0F 45 D1 59 48 89 D0 C3 }
	condition:
		$pattern
}

rule __GI___rpc_thread_svc_max_poll_6a9e0a8d19e5984b3f064383920cbe5f {
	meta:
		aliases = "__rpc_thread_svc_max_pollfd, __GI___rpc_thread_svc_max_pollfd"
		size = "36"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 ?? ?? ?? ?? 48 8D 88 A8 00 00 00 48 3D ?? ?? ?? ?? BA ?? ?? ?? ?? 48 0F 45 D1 48 89 D0 5A C3 }
	condition:
		$pattern
}

rule rand_349e774c5c8446f02021259beb3274a7 {
	meta:
		aliases = "rand"
		size = "11"
		objfiles = "rand@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 ?? ?? ?? ?? 5A C3 }
	condition:
		$pattern
}

rule __rpc_thread_svc_fdset_92ccf0b5ef48ab281e70a19ac40e9ec3 {
	meta:
		aliases = "__GI___rpc_thread_svc_fdset, __rpc_thread_svc_fdset"
		size = "30"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 ?? ?? ?? ?? 5F 48 89 C2 B8 ?? ?? ?? ?? 48 81 FA ?? ?? ?? ?? 48 0F 45 C2 C3 }
	condition:
		$pattern
}

rule __length_question_3e114d4c2fcebe18a73c18a10c5bdfc0 {
	meta:
		aliases = "__length_question"
		size = "19"
		objfiles = "lengthq@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 ?? ?? ?? ?? 8D 50 04 85 C0 0F 49 C2 5A C3 }
	condition:
		$pattern
}

rule sem_open_4e0322767b5bfa4f613fb69dc0cbfc08 {
	meta:
		aliases = "sem_open"
		size = "19"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 ?? ?? ?? ?? C7 00 26 00 00 00 31 C0 5F C3 }
	condition:
		$pattern
}

rule sem_unlink_187dce07bef806061220a2d56dc622b6 {
	meta:
		aliases = "sem_unlink"
		size = "20"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 ?? ?? ?? ?? C7 00 26 00 00 00 83 C8 FF 59 C3 }
	condition:
		$pattern
}

rule bdflush_038bf9f0179413cd6434d5403481cb99 {
	meta:
		aliases = "bdflush"
		size = "20"
		objfiles = "bdflush@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 ?? ?? ?? ?? C7 00 26 00 00 00 83 C8 FF 5A C3 }
	condition:
		$pattern
}

rule sem_close_afc8228c642cfe1f5923662de9869776 {
	meta:
		aliases = "sem_close"
		size = "20"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 ?? ?? ?? ?? C7 00 26 00 00 00 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule __errno_location_6bfceb4a33dfe998fe45a12e5c0cdfe7 {
	meta:
		aliases = "__errno_location"
		size = "18"
		objfiles = "errno@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 A0 FF FF FF 48 8B 80 80 00 00 00 59 C3 }
	condition:
		$pattern
}

rule __h_errno_location_99af7b0bffe57c7965d5e99dbdaae54d {
	meta:
		aliases = "__h_errno_location"
		size = "18"
		objfiles = "errno@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 B2 FF FF FF 48 8B 80 90 00 00 00 5A C3 }
	condition:
		$pattern
}

rule __rpc_thread_svc_cleanup_148386925cb04ffa0a060b0bf7a9fbd6 {
	meta:
		aliases = "__rpc_thread_svc_cleanup"
		size = "38"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 EB 0D 48 8B 70 10 48 8B 78 08 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 80 F0 00 00 00 48 85 C0 75 E2 58 C3 }
	condition:
		$pattern
}

rule __GI_logb_b448dac608331d358b23b92250f2b3fe {
	meta:
		aliases = "logb, __GI_logb"
		size = "97"
		objfiles = "s_logb@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 F2 0F 11 04 24 48 8B 04 24 48 89 C2 48 C1 E8 20 25 FF FF FF 7F 89 C1 09 D1 75 13 E8 ?? ?? ?? ?? 66 0F 12 0D ?? ?? ?? ?? F2 0F 5E C8 EB 2A 3D FF FF EF 7F 7E 09 0F 28 C8 F2 0F 59 C8 EB 1A C1 F8 14 85 C0 75 0A 66 0F 12 0D ?? ?? ?? ?? EB 09 2D FF 03 00 00 F2 0F 2A C8 58 0F 28 C1 C3 }
	condition:
		$pattern
}

rule __GI_scalbln_7f2b01ba77fe6a54825afad96b54c6b9 {
	meta:
		aliases = "scalbln, __GI_scalbln"
		size = "304"
		objfiles = "s_scalbln@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 F2 0F 11 04 24 48 8B 14 24 48 89 D6 48 C1 EE 20 89 F0 25 00 00 F0 7F C1 F8 14 85 C0 75 33 81 E6 FF FF FF 7F 09 F2 0F 84 FE 00 00 00 F2 0F 59 05 ?? ?? ?? ?? F2 0F 11 04 24 48 8B 14 24 48 89 D6 48 C1 EE 20 89 F0 25 00 00 F0 7F C1 F8 14 83 E8 36 3D FF 07 00 00 75 09 F2 0F 58 C0 E9 C9 00 00 00 8D 0C 38 48 81 FF 50 C3 00 00 0F 9F C2 81 F9 FE 07 00 00 0F 9F C0 08 C2 74 1D 0F 28 C8 66 0F 12 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? E9 92 00 00 00 48 81 FF B0 3C FF FF 7C 3A 85 C9 7E 31 F2 0F 11 04 24 48 8B 04 24 81 E6 FF FF 0F 80 C1 E1 14 48 89 C2 89 F0 09 C8 83 E2 FF 48 C1 E0 }
	condition:
		$pattern
}

rule scalbn_9e924c422b197b25eec932c463a5bc0b {
	meta:
		aliases = "__GI_scalbn, scalbn"
		size = "297"
		objfiles = "s_scalbn@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 F2 0F 11 04 24 48 8B 14 24 48 89 D6 48 C1 EE 20 89 F0 25 00 00 F0 7F C1 F8 14 85 C0 75 3F 81 E6 FF FF FF 7F 09 F2 0F 84 F7 00 00 00 F2 0F 59 05 ?? ?? ?? ?? F2 0F 11 04 24 48 8B 14 24 48 89 D0 48 C1 E8 20 81 FF B0 3C FF FF 0F 8C 94 00 00 00 89 C6 25 00 00 F0 7F C1 F8 14 83 E8 36 3D FF 07 00 00 75 09 F2 0F 58 C0 E9 B6 00 00 00 8D 0C 38 81 F9 FE 07 00 00 7F 42 85 C9 7E 31 F2 0F 11 04 24 48 8B 04 24 81 E6 FF FF 0F 80 C1 E1 14 48 89 C2 89 F0 09 C8 83 E2 FF 48 C1 E0 20 48 09 C2 48 89 14 24 66 0F 12 0C 24 0F 28 C1 EB 76 83 F9 CA 7F 3C 81 FF 50 C3 00 00 7E 1A 0F 28 C8 66 0F 12 05 ?? ?? ?? }
	condition:
		$pattern
}

rule cfsetospeed_9ee6e2c8a0dd1b257f3a6a29e79621c9 {
	meta:
		aliases = "__GI_cfsetospeed, cfsetospeed"
		size = "53"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 F7 C6 F0 EF FF FF 74 1B 8D 86 FF EF FF FF 83 F8 0E 76 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 0C 81 67 08 F0 EF FF FF 31 C0 09 77 08 59 C3 }
	condition:
		$pattern
}

rule __GI_cfsetispeed_d0e2ca424dbecbdf494a30ddc9b110ea {
	meta:
		aliases = "cfsetispeed, __GI_cfsetispeed"
		size = "71"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 F7 C6 F0 EF FF FF 74 1B 8D 86 FF EF FF FF 83 F8 0E 76 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 1E 85 F6 75 08 81 0F 00 00 00 80 EB 10 81 67 08 F0 EF FF FF 81 27 FF FF FF 7F 09 77 08 31 C0 5A C3 }
	condition:
		$pattern
}

rule __gthread_mutex_unlock_9c158610b6bb66e460b6e297c4682a93 {
	meta:
		aliases = "__gthread_mutex_lock, __gthread_mutex_unlock"
		size = "17"
		objfiles = "gthr_gnat@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 FF 15 ?? ?? ?? ?? 31 C0 48 83 C4 08 C3 }
	condition:
		$pattern
}

rule __GI_tcgetpgrp_4f96c08abbc2200693f9131ac85cee82 {
	meta:
		aliases = "tcgetpgrp, __GI_tcgetpgrp"
		size = "38"
		objfiles = "tcgetpgrp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 31 C0 BE 0F 54 00 00 48 8D 54 24 14 E8 ?? ?? ?? ?? 89 C2 83 C8 FF 39 C2 0F 4F 44 24 14 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule wcstombs_2557a4f7264b0bc12208346d0dc94881 {
	meta:
		aliases = "wcstombs"
		size = "26"
		objfiles = "wcstombs@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 31 C9 48 89 74 24 10 48 8D 74 24 10 E8 ?? ?? ?? ?? 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule setkey_e985e2f1770fa369fb8ae4cbb6704035 {
	meta:
		aliases = "setkey"
		size = "71"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 31 F6 49 89 E0 EB 2A 48 63 C6 31 C9 49 8D 14 00 C6 02 00 EB 15 F6 07 01 74 0B 48 63 C1 8A 80 ?? ?? ?? ?? 08 02 48 FF C7 FF C1 83 F9 07 7E E6 FF C6 83 FE 07 7E D1 4C 89 C7 E8 C9 FB FF FF 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule __re_match_37d3e2ef8283458e7f6ab1f4edb6fb61 {
	meta:
		aliases = "re_match, __re_match"
		size = "35"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 41 89 C9 48 89 F1 89 54 24 08 4C 89 04 24 31 F6 41 89 D0 31 D2 E8 0D E1 FF FF 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule wcsnrtombs_05c744758ed658f6a8dbd1f51962ae1c {
	meta:
		aliases = "__GI_wcsnrtombs, wcsnrtombs"
		size = "140"
		objfiles = "wcsnrtombs@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 85 FF 49 89 D0 0F 94 C2 48 39 F7 41 B9 01 00 00 00 0F 94 C0 08 C2 74 2D 48 85 FF 48 89 E7 75 1F 48 83 C9 FF 45 30 C9 EB 1C E8 ?? ?? ?? ?? C7 00 54 00 00 00 48 83 C8 FF EB 48 45 31 C0 EB 35 48 89 E7 45 31 C9 49 39 C8 49 0F 46 C8 4C 8B 06 48 89 CA EB 1B 41 8B 00 83 F8 7F 77 CD 84 C0 88 07 74 D8 49 63 C1 49 83 C0 04 48 FF CA 48 01 C7 48 85 D2 75 E0 48 39 E7 74 03 4C 89 06 48 89 C8 48 29 D0 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule putpwent_3c5ab079a7cbab782dbd3a0e7fdafc9e {
	meta:
		aliases = "putpwent"
		size = "103"
		objfiles = "putpwent@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 85 FF 49 89 F2 0F 94 C2 48 85 F6 0F 94 C0 08 C2 74 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 3B 48 8B 47 28 44 8B 4F 14 BE ?? ?? ?? ?? 44 8B 47 10 48 8B 4F 08 48 89 44 24 10 48 8B 47 20 48 89 44 24 08 48 8B 47 18 48 89 04 24 48 8B 17 31 C0 4C 89 D7 E8 ?? ?? ?? ?? C1 F8 1F 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule stime_c396978e1123c94425c2990345d30901 {
	meta:
		aliases = "stime"
		size = "56"
		objfiles = "stime@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 85 FF 75 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 1A 48 8B 07 31 F6 48 89 E7 48 C7 44 24 08 00 00 00 00 48 89 04 24 E8 ?? ?? ?? ?? 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule inet_addr_dcd52f4f196142d7785807e8e8b46f07 {
	meta:
		aliases = "__GI_inet_addr, inet_addr"
		size = "28"
		objfiles = "inet_makeaddr@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 89 E6 E8 ?? ?? ?? ?? 89 C2 83 C8 FF 85 D2 0F 45 04 24 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule getw_0a0cf6cfaf9b8785ddda29f569aa9659 {
	meta:
		aliases = "getw"
		size = "49"
		objfiles = "getw@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 89 F9 BA 01 00 00 00 48 8D 44 24 14 BE 04 00 00 00 48 89 C7 E8 ?? ?? ?? ?? 48 89 C2 83 C8 FF 48 85 D2 0F 45 44 24 14 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule __old_sem_post_a038a70b6ab0b4513c9f08044c096c5e {
	meta:
		aliases = "__old_sem_post"
		size = "175"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 8B 17 48 89 D1 83 E1 01 75 07 BE 03 00 00 00 EB 1D 48 81 FA FE FF FF 7F 7E 10 E8 ?? ?? ?? ?? C7 00 22 00 00 00 83 C8 FF EB 7B 48 8D 72 02 48 89 D0 F0 48 0F B1 37 40 0F 94 C6 40 84 F6 74 C0 48 85 C9 75 5F 48 89 D1 48 C7 44 24 10 00 00 00 00 EB 29 48 8B 79 10 48 8D 74 24 10 EB 04 48 8D 72 10 48 8B 16 48 85 D2 74 08 8B 41 2C 3B 42 2C 7C EC 48 89 51 10 48 89 0E 48 89 F9 48 83 F9 01 75 D1 EB 16 48 8B 47 10 48 89 44 24 10 48 C7 47 10 00 00 00 00 E8 ?? ?? ?? ?? 48 8B 7C 24 10 48 85 FF 75 E0 31 C0 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule __get_hosts_byname_r_46817bfef1790a43b4b106125149d63b {
	meta:
		aliases = "__get_hosts_byname_r"
		size = "48"
		objfiles = "get_hosts_byname_r@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 8B 44 24 20 4C 89 4C 24 08 49 89 C9 4C 89 04 24 31 C9 49 89 D0 89 F2 48 89 FE 31 FF 48 89 44 24 10 E8 ?? ?? ?? ?? 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule __GI_tgamma_3782632392d69c66ba048b3d4bd66860 {
	meta:
		aliases = "tgamma, __GI_tgamma"
		size = "34"
		objfiles = "w_tgamma@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 8D 7C 24 14 E8 ?? ?? ?? ?? 83 7C 24 14 00 79 08 66 0F 57 05 ?? ?? ?? ?? 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule inet_pton4_6a644bb13491e8a4e41e16d843609fb0 {
	meta:
		aliases = "inet_pton4"
		size = "135"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 49 89 F1 31 C9 45 31 C0 48 89 E6 C6 04 24 00 EB 44 8D 42 D0 83 F8 09 77 24 0F B6 06 6B C0 0A 8D 44 10 D0 3D FF 00 00 00 77 52 85 C9 88 06 75 25 41 FF C0 41 83 F8 04 7F 43 B1 01 EB 18 83 FA 2E 0F 94 C0 84 C1 74 35 41 83 F8 04 74 2F 48 FF C6 31 C9 C6 06 00 0F BE 17 48 FF C7 85 D2 75 B2 41 83 F8 03 7E 17 48 89 E6 BA 04 00 00 00 4C 89 CF E8 ?? ?? ?? ?? B8 01 00 00 00 EB 02 31 C0 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule re_search_48b88084187d753e0c48b28a3c9997ab {
	meta:
		aliases = "__re_search, re_search"
		size = "40"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 89 54 24 10 4C 89 4C 24 08 41 89 C9 44 89 04 24 48 89 F1 41 89 D0 31 F6 31 D2 E8 ?? ?? ?? ?? 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule xdrstdio_putlong_fa484968b6bc8779de7ab889964086f5 {
	meta:
		aliases = "xdrstdio_putint32, xdrstdio_putlong"
		size = "53"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 8B 06 BA 01 00 00 00 0F C8 89 44 24 14 48 8D 44 24 14 48 8B 4F 18 BE 04 00 00 00 48 89 C7 E8 ?? ?? ?? ?? 48 FF C8 0F 94 C0 48 83 C4 18 0F B6 C0 C3 }
	condition:
		$pattern
}

rule fgetpwent_5abd21e9b7de4fda56e36ae3f07cbf5b {
	meta:
		aliases = "getspnam, getpwuid, getpwnam, fgetspent, sgetspent, getgrnam, getgrgid, fgetgrent, fgetpwent"
		size = "39"
		objfiles = "fgetgrent@libc.a, fgetpwent@libc.a, getgrgid@libc.a, fgetspent@libc.a, getspnam@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 B9 00 01 00 00 BA ?? ?? ?? ?? 4C 8D 44 24 10 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 44 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule getpwent_ece339ac2255e5b2dcc60ca099afd4f8 {
	meta:
		aliases = "getspent, getgrent, getpwent"
		size = "39"
		objfiles = "getpwent@libc.a, getgrent@libc.a, getspent@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 BA 00 01 00 00 BE ?? ?? ?? ?? 48 8D 4C 24 10 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 44 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule mrand48_044ee80b5569b3a44865b1caef2ab77b {
	meta:
		aliases = "lrand48, mrand48"
		size = "32"
		objfiles = "lrand48@libc.a, mrand48@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 BE ?? ?? ?? ?? 48 8D 54 24 10 48 89 F7 E8 ?? ?? ?? ?? 48 8B 44 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule drand48_79682b1a5ad0d3c6c73f73c5e3d87afa {
	meta:
		aliases = "drand48"
		size = "33"
		objfiles = "drand48@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 BE ?? ?? ?? ?? 48 8D 54 24 10 48 89 F7 E8 ?? ?? ?? ?? 66 0F 12 44 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule jrand48_2ae7b0adf8640b3273e0f6dea72de404 {
	meta:
		aliases = "nrand48, jrand48"
		size = "29"
		objfiles = "jrand48@libc.a, nrand48@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 BE ?? ?? ?? ?? 48 8D 54 24 10 E8 ?? ?? ?? ?? 48 8B 44 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule erand48_41734f76edcee4db855a04d79cecbcaf {
	meta:
		aliases = "erand48"
		size = "30"
		objfiles = "erand48@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 BE ?? ?? ?? ?? 48 8D 54 24 10 E8 ?? ?? ?? ?? 66 0F 12 44 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule getdtablesize_89a36f61e54641b5dc7f6af1ac3932b2 {
	meta:
		aliases = "__GI_getdtablesize, getdtablesize"
		size = "35"
		objfiles = "getdtablesize@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 BF 07 00 00 00 48 89 E6 E8 ?? ?? ?? ?? 89 C2 B8 00 01 00 00 FF C2 0F 4F 04 24 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule __fixxfti_499bad3d96f4a3ce2b0e6e08a4227017 {
	meta:
		aliases = "__fixxfti"
		size = "57"
		objfiles = "_fixxfdi@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 DB 6C 24 20 D9 EE DF E9 77 12 DF C0 48 83 C4 18 E9 ?? ?? ?? ?? 66 66 66 90 66 66 90 D9 E0 DB 3C 24 E8 ?? ?? ?? ?? 48 F7 D8 48 83 D2 00 48 83 C4 18 48 F7 DA C3 }
	condition:
		$pattern
}

rule getservent_74e80d1d8319de3d4243747e6d738504 {
	meta:
		aliases = "getservent"
		size = "46"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 E8 E7 FD FF FF 48 8B 35 ?? ?? ?? ?? 48 8D 4C 24 10 BA 19 11 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 44 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule getprotoent_1a0538cecb7c89f2e358de83ce5b0316 {
	meta:
		aliases = "getprotoent"
		size = "46"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 E8 F9 FD FF FF 48 8B 35 ?? ?? ?? ?? 48 8D 4C 24 10 BA 19 11 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 44 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule __pthread_unlock_d16702b1705f5d1ef4fad41033445482 {
	meta:
		aliases = "__pthread_unlock"
		size = "177"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 EB 15 31 C9 48 89 D0 F0 48 0F B1 0F 0F 94 C2 84 D2 0F 85 8F 00 00 00 48 8B 17 48 83 FA 01 74 E2 49 89 D0 49 83 E0 FE 45 31 D2 4C 89 C0 49 89 F9 48 89 FE EB 1A 8B 48 2C 44 39 D1 7C 06 4C 89 CE 41 89 CA 4C 8D 48 18 48 8B 40 18 48 83 E0 FE 48 85 C0 75 E1 48 39 FE 75 19 49 8B 48 18 48 89 D0 48 83 E1 FE F0 48 0F B1 0F 0F 94 C2 84 D2 74 A7 EB 24 4C 8B 06 49 83 E0 FE 49 8B 40 18 48 89 06 48 8B 07 48 89 C2 48 83 E2 FE F0 48 0F B1 17 0F 94 C2 84 D2 74 EA 49 C7 40 18 00 00 00 00 4C 89 C7 E8 21 FD FF FF 31 C0 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule fdim_c811382213efbb5cdd14c2501cd21e6c {
	meta:
		aliases = "__GI_fdim, fdim"
		size = "72"
		objfiles = "s_fdim@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 F2 0F 11 44 24 10 F2 0F 11 4C 24 08 E8 ?? ?? ?? ?? 83 F8 01 77 0A 66 0F 12 05 ?? ?? ?? ?? EB 1F 66 0F 12 44 24 10 66 0F 2E 44 24 08 77 05 0F 57 C0 EB 0C 66 0F 12 44 24 10 F2 0F 5C 44 24 08 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule __ieee754_scalb_f38a128e4b1d6f7632082c06df9eda85 {
	meta:
		aliases = "__ieee754_scalb"
		size = "213"
		objfiles = "e_scalb@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 F2 0F 11 44 24 10 F2 0F 11 4C 24 08 E8 ?? ?? ?? ?? 85 C0 75 2E 66 0F 12 44 24 08 E8 ?? ?? ?? ?? 85 C0 75 1F 66 0F 12 44 24 08 E8 ?? ?? ?? ?? 85 C0 75 31 66 0F 12 44 24 08 66 0F 2E 05 ?? ?? ?? ?? 76 0E 66 0F 12 44 24 10 F2 0F 59 44 24 08 EB 7B 80 74 24 0F 80 66 0F 12 44 24 10 F2 0F 5E 44 24 08 EB 68 66 0F 12 44 24 08 E8 ?? ?? ?? ?? 66 0F 2E 44 24 08 7A 02 74 10 66 0F 12 44 24 08 F2 0F 5C C0 F2 0F 5E C0 EB 43 66 0F 12 44 24 08 BF E8 FD 00 00 66 0F 2E 05 ?? ?? ?? ?? 77 17 66 0F 12 44 24 08 66 0F 2E 05 ?? ?? ?? ?? 73 16 7A 14 BF 18 02 FF FF 66 0F 12 44 24 10 48 83 C4 18 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_cos_5d3f21f4b751adb83847cb6512ab30aa {
	meta:
		aliases = "cos, __GI_cos"
		size = "207"
		objfiles = "s_cos@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 28 0F 57 C9 F2 0F 11 44 24 08 48 8B 54 24 08 48 89 D0 48 C1 E8 20 25 FF FF FF 7F 3D FB 21 E9 3F 7E 4B 3D FF FF EF 7F 7E 09 F2 0F 5C C0 E9 95 00 00 00 48 8D 7C 24 10 E8 ?? ?? ?? ?? 83 E0 03 83 F8 01 74 30 83 F8 02 74 43 85 C0 48 8B 54 24 10 48 8B 44 24 18 75 50 48 89 44 24 08 66 0F 12 4C 24 08 48 89 54 24 08 66 0F 12 44 24 08 E8 ?? ?? ?? ?? EB 53 66 0F 12 4C 24 18 BF 01 00 00 00 66 0F 12 44 24 10 E8 ?? ?? ?? ?? EB 11 66 0F 12 4C 24 18 66 0F 12 44 24 10 E8 ?? ?? ?? ?? 66 0F 57 05 ?? ?? ?? ?? EB 20 48 89 44 24 08 BF 01 00 00 00 66 0F 12 4C 24 08 48 89 54 24 08 66 0F 12 44 24 08 E8 ?? ?? }
	condition:
		$pattern
}

rule __ieee754_log10_971b791460bc956632420e95de7c9162 {
	meta:
		aliases = "__ieee754_log10"
		size = "267"
		objfiles = "e_log10@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 28 31 C9 F2 0F 11 44 24 08 48 8B 54 24 08 48 89 D6 48 C1 EE 20 81 FE FF FF 0F 00 7F 4C 89 F0 25 FF FF FF 7F 09 D0 75 0A 66 0F 12 15 ?? ?? ?? ?? EB 0B 85 F6 79 14 0F 28 D0 F2 0F 5C D0 F2 0F 5E 15 ?? ?? ?? ?? E9 B6 00 00 00 F2 0F 59 05 ?? ?? ?? ?? B9 CA FF FF FF F2 0F 11 44 24 08 48 8B 54 24 08 48 89 D6 48 C1 EE 20 81 FE FF FF EF 7F 7E 0C 0F 28 D0 F2 0F 58 D0 E9 83 00 00 00 89 F0 F2 0F 11 44 24 08 81 E6 FF FF 0F 00 C1 F8 14 8D 84 01 01 FC FF FF 89 C1 C1 E9 1F 01 C8 F2 0F 2A C8 48 8B 44 24 08 48 89 C2 B8 FF 03 00 00 29 C8 83 E2 FF C1 E0 14 09 F0 48 C1 E0 20 48 09 C2 48 89 54 24 08 66 0F }
	condition:
		$pattern
}

rule hsearch_ad452dc3c90d0324ee76eaa162927d87 {
	meta:
		aliases = "hsearch"
		size = "40"
		objfiles = "hsearch@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 28 41 B8 ?? ?? ?? ?? 48 8D 4C 24 20 48 89 7C 24 08 48 89 74 24 10 E8 ?? ?? ?? ?? 48 8B 44 24 20 48 83 C4 28 C3 }
	condition:
		$pattern
}

rule __GI_clntudp_create_5a6a016fcc5cbddee5279b2e509d362b {
	meta:
		aliases = "clntudp_create, __GI_clntudp_create"
		size = "39"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 28 48 89 4C 24 18 4C 89 44 24 20 C7 44 24 08 60 22 00 00 C7 04 24 60 22 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 C3 }
	condition:
		$pattern
}

rule mbstowcs_86f214002d23777c78e3dd8f5cf51c46 {
	meta:
		aliases = "mbstowcs"
		size = "37"
		objfiles = "mbstowcs@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 28 48 89 74 24 08 48 8D 4C 24 10 48 8D 74 24 08 C7 44 24 10 00 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 C3 }
	condition:
		$pattern
}

rule clock_150c4727e8843c6bab15cb4ac0ce9339 {
	meta:
		aliases = "clock"
		size = "46"
		objfiles = "clock@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? 48 8B 44 24 08 48 03 04 24 48 BA FF FF FF FF FF FF FF 7F 48 83 C4 28 48 69 C0 10 27 00 00 48 21 D0 C3 }
	condition:
		$pattern
}

rule clearenv_15769ec3d48de0df7eff7256f9ab0c63 {
	meta:
		aliases = "clearenv"
		size = "100"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 28 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 3B 3D ?? ?? ?? ?? 75 15 48 85 FF 74 10 E8 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 48 89 E7 BE 01 00 00 00 48 C7 05 ?? ?? ?? ?? 00 00 00 00 E8 ?? ?? ?? ?? 31 C0 48 83 C4 28 C3 }
	condition:
		$pattern
}

rule __close_nameservers_af3423abea9e1035b4bd9601e2e04f73 {
	meta:
		aliases = "__close_nameservers"
		size = "158"
		objfiles = "closenameservers@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 28 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 2A FF C8 89 05 ?? ?? ?? ?? 48 98 48 8B 3C C5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 63 05 ?? ?? ?? ?? 48 C7 04 C5 ?? ?? ?? ?? 00 00 00 00 8B 05 ?? ?? ?? ?? 85 C0 7F CC EB 2A FF C8 89 05 ?? ?? ?? ?? 48 98 48 8B 3C C5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 63 05 ?? ?? ?? ?? 48 C7 04 C5 ?? ?? ?? ?? 00 00 00 00 8B 05 ?? ?? ?? ?? 85 C0 7F CC 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 C3 }
	condition:
		$pattern
}

rule __GI_tan_d8ea805993a6d2a5a0d81b6df970da4f {
	meta:
		aliases = "tan, __GI_tan"
		size = "99"
		objfiles = "s_tan@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 28 BF 01 00 00 00 F2 0F 11 44 24 08 48 8B 54 24 08 0F 57 C9 48 89 D0 48 C1 E8 20 25 FF FF FF 7F 3D FB 21 E9 3F 7E 2F 3D FF FF EF 7F 7E 06 F2 0F 5C C0 EB 27 48 8D 7C 24 10 E8 ?? ?? ?? ?? 83 E0 01 BF 01 00 00 00 66 0F 12 4C 24 18 01 C0 66 0F 12 44 24 10 29 C7 E8 ?? ?? ?? ?? 48 83 C4 28 C3 }
	condition:
		$pattern
}

rule __GI_sin_3110bb4c8bf547ef5ab95a7fe72eaf83 {
	meta:
		aliases = "sin, __GI_sin"
		size = "211"
		objfiles = "s_sin@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 28 F2 0F 11 44 24 08 48 8B 54 24 08 48 89 D0 48 C1 E8 20 25 FF FF FF 7F 3D FB 21 E9 3F 7F 07 0F 57 C9 31 FF EB 50 3D FF FF EF 7F 7E 09 F2 0F 5C C0 E9 95 00 00 00 48 8D 7C 24 10 E8 ?? ?? ?? ?? 83 E0 03 83 F8 01 74 35 83 F8 02 74 43 85 C0 48 8B 54 24 10 48 8B 44 24 18 75 4D 48 89 44 24 08 BF 01 00 00 00 66 0F 12 4C 24 08 48 89 54 24 08 66 0F 12 44 24 08 E8 ?? ?? ?? ?? EB 4E 66 0F 12 4C 24 18 66 0F 12 44 24 10 E8 ?? ?? ?? ?? EB 3B 66 0F 12 4C 24 18 BF 01 00 00 00 66 0F 12 44 24 10 E8 ?? ?? ?? ?? EB 1B 48 89 44 24 08 66 0F 12 4C 24 08 48 89 54 24 08 66 0F 12 44 24 08 E8 ?? ?? ?? ?? 66 0F }
	condition:
		$pattern
}

rule __ieee754_acosh_b3770ef6911f2f3b8af73197e412ffe1 {
	meta:
		aliases = "__ieee754_acosh"
		size = "243"
		objfiles = "e_acosh@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 38 0F 28 D0 F2 0F 11 44 24 08 48 8B 54 24 08 48 89 D0 48 C1 EA 20 81 FA FF FF EF 3F 89 C1 7F 0D F2 0F 5C C2 F2 0F 5E C0 E9 BE 00 00 00 81 FA FF FF AF 41 7E 23 81 FA FF FF EF 7F 7E 09 F2 0F 58 C2 E9 A5 00 00 00 E8 ?? ?? ?? ?? F2 0F 58 05 ?? ?? ?? ?? E9 93 00 00 00 8D 82 00 00 10 C0 09 C8 75 08 0F 57 C0 E9 81 00 00 00 81 FA 00 00 00 40 66 0F 12 0D ?? ?? ?? ?? 7E 3D F2 0F 59 C2 F2 0F 11 54 24 10 F2 0F 5C C1 E8 ?? ?? ?? ?? 66 0F 12 54 24 10 0F 28 CA F2 0F 58 CA F2 0F 58 D0 66 0F 12 05 ?? ?? ?? ?? 48 83 C4 38 F2 0F 5E C2 F2 0F 58 C1 E9 ?? ?? ?? ?? F2 0F 5C D1 0F 28 C2 0F 28 CA F2 0F 58 C2 }
	condition:
		$pattern
}

rule wcrtomb_728c05a539ac3446797a6bad3bc6b82c {
	meta:
		aliases = "__GI_wcrtomb, wcrtomb"
		size = "68"
		objfiles = "wcrtomb@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 38 48 85 FF 75 05 48 89 E7 31 F6 48 8D 44 24 20 89 74 24 20 48 8D 74 24 18 49 89 D0 B9 10 00 00 00 BA 01 00 00 00 48 89 44 24 18 E8 ?? ?? ?? ?? BA 01 00 00 00 48 85 C0 48 0F 44 C2 48 83 C4 38 C3 }
	condition:
		$pattern
}

rule _dl_linux_resolve_418845e03f5f14ec83a064b6731271a2 {
	meta:
		aliases = "_dl_linux_resolve"
		size = "110"
		objfiles = "resolve@libdl.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 38 48 89 04 24 48 89 4C 24 08 48 89 54 24 10 48 89 74 24 18 48 89 7C 24 20 4C 89 44 24 28 4C 89 4C 24 30 48 8B 74 24 40 49 89 F3 4C 01 DE 4C 01 DE 48 C1 E6 03 48 8B 7C 24 38 E8 ?? ?? ?? ?? 49 89 C3 4C 8B 4C 24 30 4C 8B 44 24 28 48 8B 7C 24 20 48 8B 74 24 18 48 8B 54 24 10 48 8B 4C 24 08 48 8B 04 24 48 83 C4 48 41 FF E3 }
	condition:
		$pattern
}

rule xdr_free_646f9c217cfaa27cf1e601aeb4957f12 {
	meta:
		aliases = "xdr_free"
		size = "26"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 38 48 89 FA 31 C0 C7 04 24 02 00 00 00 48 89 E7 FF D2 48 83 C4 38 C3 }
	condition:
		$pattern
}

rule isatty_cb41ce816c740b21b1fc4d59d4aa4502 {
	meta:
		aliases = "__GI_isatty, isatty"
		size = "25"
		objfiles = "isatty@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 48 48 89 E6 E8 ?? ?? ?? ?? 85 C0 0F 94 C0 48 83 C4 48 0F B6 C0 C3 }
	condition:
		$pattern
}

rule ualarm_298871d5c621a8d345287ef5bd75228f {
	meta:
		aliases = "ualarm"
		size = "79"
		objfiles = "ualarm@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 48 89 F6 89 FF 48 8D 54 24 20 48 89 74 24 08 48 89 7C 24 18 48 89 E6 31 FF 48 C7 04 24 00 00 00 00 48 C7 44 24 10 00 00 00 00 E8 ?? ?? ?? ?? 83 CA FF 85 C0 78 0F 48 69 44 24 30 40 42 0F 00 8B 54 24 38 01 C2 89 D0 48 83 C4 48 C3 }
	condition:
		$pattern
}

rule __GI_svcerr_noprog_c3117f66c65421b63a637037c53741bb {
	meta:
		aliases = "svcerr_noprog, __GI_svcerr_noprog"
		size = "69"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 68 48 89 FA 48 8D 77 28 48 8D 44 24 18 C7 44 24 08 01 00 00 00 C7 44 24 10 00 00 00 00 FC 48 89 C7 B9 06 00 00 00 F3 A5 C7 44 24 30 01 00 00 00 48 89 E6 48 89 D7 48 8B 42 08 FF 50 18 48 83 C4 68 C3 }
	condition:
		$pattern
}

rule svcerr_noproc_103dd04f015d1c6586c5fe695fd50c38 {
	meta:
		aliases = "svcerr_noproc"
		size = "69"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 68 48 89 FA 48 8D 77 28 48 8D 44 24 18 C7 44 24 08 01 00 00 00 C7 44 24 10 00 00 00 00 FC 48 89 C7 B9 06 00 00 00 F3 A5 C7 44 24 30 03 00 00 00 48 89 E6 48 89 D7 48 8B 42 08 FF 50 18 48 83 C4 68 C3 }
	condition:
		$pattern
}

rule svcerr_decode_6c67e5cc9ef18f78716a9574e09709ed {
	meta:
		aliases = "__GI_svcerr_decode, svcerr_decode"
		size = "69"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 68 48 89 FA 48 8D 77 28 48 8D 44 24 18 C7 44 24 08 01 00 00 00 C7 44 24 10 00 00 00 00 FC 48 89 C7 B9 06 00 00 00 F3 A5 C7 44 24 30 04 00 00 00 48 89 E6 48 89 D7 48 8B 42 08 FF 50 18 48 83 C4 68 C3 }
	condition:
		$pattern
}

rule svcerr_systemerr_d7f854eff9e19131629e6104d67bf602 {
	meta:
		aliases = "svcerr_systemerr"
		size = "69"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 68 48 89 FA 48 8D 77 28 48 8D 44 24 18 C7 44 24 08 01 00 00 00 C7 44 24 10 00 00 00 00 FC 48 89 C7 B9 06 00 00 00 F3 A5 C7 44 24 30 05 00 00 00 48 89 E6 48 89 D7 48 8B 42 08 FF 50 18 48 83 C4 68 C3 }
	condition:
		$pattern
}

rule svcerr_auth_970f1ffca0566ea3c57a3a6fb2ea1e74 {
	meta:
		aliases = "__GI_svcerr_auth, svcerr_auth"
		size = "47"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 68 48 8B 47 08 89 74 24 20 C7 44 24 08 01 00 00 00 48 89 E6 C7 44 24 10 01 00 00 00 C7 44 24 18 01 00 00 00 FF 50 18 48 83 C4 68 C3 }
	condition:
		$pattern
}

rule svc_sendreply_52515cb035fa5f442587988dd5b4a585 {
	meta:
		aliases = "__GI_svc_sendreply, svc_sendreply"
		size = "85"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 68 48 8D 47 28 49 89 F9 4C 8D 44 24 18 49 89 F2 C7 44 24 08 01 00 00 00 C7 44 24 10 00 00 00 00 48 89 C6 B9 06 00 00 00 FC 4C 89 C7 F3 A5 C7 44 24 30 00 00 00 00 48 89 54 24 38 48 89 E6 4C 89 54 24 40 4C 89 CF 49 8B 41 08 FF 50 18 48 83 C4 68 C3 }
	condition:
		$pattern
}

rule __GI_svcerr_progvers_18f9c77bc8855a839f2b54044d88872a {
	meta:
		aliases = "svcerr_progvers, __GI_svcerr_progvers"
		size = "85"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 68 48 8D 47 28 49 89 F9 4C 8D 44 24 18 49 89 F2 C7 44 24 08 01 00 00 00 C7 44 24 10 00 00 00 00 48 89 C6 B9 06 00 00 00 FC 4C 89 C7 F3 A5 C7 44 24 30 02 00 00 00 4C 89 54 24 38 48 89 E6 48 89 54 24 40 4C 89 CF 49 8B 41 08 FF 50 18 48 83 C4 68 C3 }
	condition:
		$pattern
}

rule strncpy_8430649c32d30b83137b44e94cbae139 {
	meta:
		aliases = "__GI_strncpy, strncpy"
		size = "131"
		objfiles = "strncpy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 FA 03 48 8D 4F FF 76 4F 49 89 D0 49 C1 E8 02 8A 06 48 FF C1 84 C0 88 01 74 2F 8A 46 01 48 FF C1 84 C0 88 01 74 23 8A 46 02 48 FF C1 84 C0 88 01 74 17 8A 46 03 48 FF C1 84 C0 88 01 74 0B 48 83 C6 04 49 FF C8 74 10 EB C6 48 89 C8 48 29 F8 48 29 C2 48 89 D0 EB 21 48 89 D0 83 E0 03 74 1E 8A 16 48 FF C1 48 FF C6 48 FF C8 88 11 74 0F 84 D2 75 ED 48 FF C1 C6 01 00 48 FF C8 75 F5 48 89 F8 C3 }
	condition:
		$pattern
}

rule memset_a862b942bf987fe3d05f0e9c48d99fcb {
	meta:
		aliases = "__GI_memset, memset"
		size = "210"
		objfiles = "memset@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 FA 07 48 89 F9 76 7D 49 B8 01 01 01 01 01 01 01 01 40 0F B6 C6 4C 0F AF C0 F7 C7 07 00 00 00 74 0E 40 88 31 48 FF CA 48 FF C1 F6 C1 07 75 F2 48 89 D0 48 C1 E8 06 74 31 48 81 FA C0 D4 01 00 73 5D 4C 89 01 4C 89 41 08 4C 89 41 10 4C 89 41 18 4C 89 41 20 4C 89 41 28 4C 89 41 30 4C 89 41 38 48 83 C1 40 48 FF C8 75 D8 83 E2 3F 48 89 D0 48 C1 E8 03 74 0C 4C 89 01 48 83 C1 08 48 FF C8 75 F4 83 E2 07 48 85 D2 74 0B 40 88 31 48 FF C1 48 FF CA 75 F5 48 89 F8 C3 66 66 90 66 66 90 4C 0F C3 01 4C 0F C3 41 08 4C 0F C3 41 10 4C 0F C3 41 18 4C 0F C3 41 20 4C 0F C3 41 28 4C 0F C3 41 30 4C 0F C3 41 38 48 }
	condition:
		$pattern
}

rule __GI_memcpy_ebd030231cb309581dcce2de7d705774 {
	meta:
		aliases = "memcpy, __GI_memcpy"
		size = "102"
		objfiles = "memcpy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 FA 20 48 89 D1 49 89 FA FC 76 53 48 89 F8 48 F7 D8 48 83 E0 07 48 29 C1 48 91 F3 A4 48 89 C1 48 83 E9 20 78 35 66 66 90 66 66 90 66 66 90 48 83 E9 20 48 8B 06 48 8B 56 08 4C 8B 46 10 4C 8B 4E 18 48 89 07 48 89 57 08 4C 89 47 10 4C 89 4F 18 48 8D 76 20 48 8D 7F 20 79 D4 48 83 C1 20 F3 A4 4C 89 D0 C3 }
	condition:
		$pattern
}

rule mempcpy_a580c734598d06385b3712b4ad44ce11 {
	meta:
		aliases = "__GI_mempcpy, mempcpy"
		size = "90"
		objfiles = "mempcpy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 FA 20 48 89 D1 FC 76 4A 48 89 F8 48 F7 D8 48 83 E0 07 48 29 C1 48 91 F3 A4 48 89 C1 48 83 E9 20 78 2C 48 83 E9 20 48 8B 06 48 8B 56 08 4C 8B 46 10 4C 8B 4E 18 48 89 07 48 89 57 08 4C 89 47 10 4C 89 4F 18 48 8D 76 20 48 8D 7F 20 79 D4 48 83 C1 20 F3 A4 48 89 F8 C3 }
	condition:
		$pattern
}

rule setbuffer_ed8d939a34f8449af8d9fbef20020cb9 {
	meta:
		aliases = "setbuffer"
		size = "17"
		objfiles = "setbuffer@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 FE 01 48 89 D1 19 D2 83 E2 02 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule setbuf_8e12cb1013bc52d67896fb128c305740 {
	meta:
		aliases = "setbuf"
		size = "19"
		objfiles = "setbuf@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 FE 01 B9 00 10 00 00 19 D2 83 E2 02 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mbsrtowcs_d7b7227c3a1e003b4de2c1abe46fab44 {
	meta:
		aliases = "__GI_mbsrtowcs, mbsrtowcs"
		size = "25"
		objfiles = "mbsrtowcs@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 C9 41 B8 ?? ?? ?? ?? 4C 0F 45 C1 48 89 D1 48 83 CA FF E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mbrlen_d52feeb84af285cb920ea268f5bb037a {
	meta:
		aliases = "__GI_mbrlen, mbrlen"
		size = "28"
		objfiles = "mbrlen@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 D2 48 89 D1 B8 ?? ?? ?? ?? 48 0F 44 C8 48 89 F2 48 89 FE 31 FF E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __gcc_bcmp_90fe9533d9074f641c67b8b5b619f8d5 {
	meta:
		aliases = "__gcc_bcmp"
		size = "60"
		objfiles = "__gcc_bcmp@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 D2 74 27 0F B6 0F 0F B6 06 45 31 C0 38 C1 74 15 EB 1D 41 0F B6 4C 38 01 41 0F B6 44 30 01 49 FF C0 38 C1 75 0A 48 FF CA 75 E8 31 D2 89 D0 C3 0F B6 D1 0F B6 C0 29 C2 89 D0 C3 }
	condition:
		$pattern
}

rule __wcslcpy_bafe3ff4e4c28ab2d206e106727b46d9 {
	meta:
		aliases = "wcsxfrm, __wcslcpy"
		size = "55"
		objfiles = "wcslcpy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 D2 75 0A 48 8D 7C 24 E8 48 89 F1 EB 15 48 FF CA EB F6 48 85 D2 74 07 48 FF CA 48 83 C7 04 48 83 C1 04 8B 01 85 C0 89 07 75 E8 48 29 F1 48 C1 F9 02 48 89 C8 C3 }
	condition:
		$pattern
}

rule strlcpy_36360957cc987d240d738bf0e95613db {
	meta:
		aliases = "strxfrm, __GI_strxfrm, __GI_strlcpy, strlcpy"
		size = "49"
		objfiles = "strlcpy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 D2 75 0A 48 8D 7C 24 FF 48 89 F1 EB 13 48 FF CA EB F6 48 85 D2 74 06 48 FF CA 48 FF C7 48 FF C1 8A 01 84 C0 88 07 75 EA 48 29 F1 48 89 C8 C3 }
	condition:
		$pattern
}

rule sigprocmask_3f4172e7d46d13b968f9743cdb665f41 {
	meta:
		aliases = "__GI_sigprocmask, sigprocmask"
		size = "85"
		objfiles = "sigprocmask@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 F6 48 89 D1 53 0F 95 C2 83 FF 02 0F 97 C0 84 D0 74 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 2F 41 BA 08 00 00 00 48 89 CA 48 63 FF B8 0E 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule pthread_rwlock_init_895533108354240e71d41b8754632866 {
	meta:
		aliases = "pthread_rwlock_init"
		size = "80"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 85 F6 48 C7 07 00 00 00 00 C7 47 08 00 00 00 00 C7 47 10 00 00 00 00 48 C7 47 18 00 00 00 00 48 C7 47 20 00 00 00 00 48 C7 47 28 00 00 00 00 75 10 C7 47 30 01 00 00 00 C7 47 34 00 00 00 00 EB 0B 8B 06 89 47 30 8B 46 04 89 47 34 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_mutex_init_8b20dafee8667cf0c2f0df4a99737f5a {
	meta:
		aliases = "__pthread_mutex_init, pthread_mutex_init"
		size = "48"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 85 F6 48 C7 47 18 00 00 00 00 C7 47 20 00 00 00 00 B8 03 00 00 00 74 02 8B 06 89 47 10 31 C0 C7 47 04 00 00 00 00 48 C7 47 08 00 00 00 00 C3 }
	condition:
		$pattern
}

rule __GI_hcreate_r_465daa7364613852e6fe7bfb88a235f2 {
	meta:
		aliases = "hcreate_r, __GI_hcreate_r"
		size = "121"
		objfiles = "hcreate_r@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 F6 53 48 89 F3 75 0F E8 ?? ?? ?? ?? C7 00 16 00 00 00 31 C0 EB 5F 31 C0 48 83 3E 00 75 57 48 83 CF 01 EB 04 48 83 C7 02 89 FE B9 03 00 00 00 EB 03 83 C1 02 89 C8 0F AF C1 39 F0 73 0A 31 D2 89 F0 F7 F1 85 D2 75 EA 31 D2 89 F0 F7 F1 85 D2 74 D3 89 F7 89 73 08 C7 43 0C 00 00 00 00 FF C7 BE 18 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 03 0F 95 C0 0F B6 C0 5B C3 }
	condition:
		$pattern
}

rule mq_notify_f70ef10baa065aef738e38d9abc59c58 {
	meta:
		aliases = "mq_notify"
		size = "68"
		objfiles = "mq_notify@librt.a"
	strings:
		$pattern = { ( CC | 48 ) 85 F6 53 74 16 83 7E 0C 02 75 10 E8 ?? ?? ?? ?? C7 00 26 00 00 00 83 C8 FF EB 26 48 63 FF B8 F4 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule pthread_insert_list_2a2d279f969ffeab3163f555c376f875 {
	meta:
		aliases = "pthread_insert_list"
		size = "37"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 85 F6 74 1F 85 C9 75 06 EB 0C 48 8D 78 08 48 8B 07 48 85 C0 75 F4 48 89 32 48 8B 07 48 89 42 08 48 89 17 C3 }
	condition:
		$pattern
}

rule twalk_345ed87b8bd5c246c5571534a0bd3cec {
	meta:
		aliases = "twalk"
		size = "24"
		objfiles = "twalk@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 0F 95 C2 48 85 F6 0F 95 C0 84 D0 74 07 31 D2 E9 77 FF FF FF C3 }
	condition:
		$pattern
}

rule dirname_4ead876a487184bb80624d0662c1b977 {
	meta:
		aliases = "dirname"
		size = "106"
		objfiles = "dirname@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 48 89 FE 49 89 F8 75 09 EB 54 48 8D 4E 01 48 89 CE 8A 06 48 89 F1 84 C0 0F 95 C2 3C 2F 0F 95 C0 84 D0 74 05 EB E4 48 FF C1 8A 01 3C 2F 74 F7 84 C0 74 05 49 89 F0 EB D6 49 39 F8 75 1B 80 3F 2F 75 1C 80 7F 01 2F 4C 8D 47 01 75 0C 80 7F 02 00 48 8D 47 02 4C 0F 44 C0 41 C6 00 00 EB 05 BF ?? ?? ?? ?? 48 89 F8 C3 }
	condition:
		$pattern
}

rule dlsym_fa1cbb7e0bdc26a725a482995c65cf64 {
	meta:
		aliases = "dlsym"
		size = "185"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 49 89 F2 48 89 FE 75 09 48 8B 35 ?? ?? ?? ?? EB 6C 48 83 FF FF 74 2F 48 3B 3D ?? ?? ?? ?? 74 5D 48 8B 05 ?? ?? ?? ?? EB 09 48 39 F8 74 4F 48 8B 40 08 48 85 C0 75 F2 31 D2 48 C7 05 ?? ?? ?? ?? 09 00 00 00 EB 6C 4C 8B 0C 24 48 8B 05 ?? ?? ?? ?? 45 31 C0 EB 22 48 8B 08 48 8B 51 28 4C 39 CA 73 12 4D 85 C0 74 06 49 39 50 28 73 07 48 8B 70 20 49 89 C8 48 8B 40 20 48 85 C0 75 D9 31 D2 48 3B 35 ?? ?? ?? ?? 75 03 48 8B 16 B9 00 00 00 80 4C 89 D7 E8 ?? ?? ?? ?? 48 89 C2 B8 0A 00 00 00 48 85 D2 48 0F 45 05 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 89 D0 C3 }
	condition:
		$pattern
}

rule tmpnam_r_7f2fe14cfc56a190a89fd05b32be8365 {
	meta:
		aliases = "tmpnam_r"
		size = "51"
		objfiles = "tmpnam_r@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 53 48 89 FB 74 23 31 C9 31 D2 BE 14 00 00 00 E8 ?? ?? ?? ?? 85 C0 75 11 BE 03 00 00 00 48 89 DF E8 ?? ?? ?? ?? 85 C0 74 02 31 DB 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule hdestroy_r_14bd5f46cb557fedfca2adc4e3381923 {
	meta:
		aliases = "__GI_hdestroy_r, hdestroy_r"
		size = "39"
		objfiles = "hdestroy_r@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 53 48 89 FB 75 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 0F 48 8B 3F E8 ?? ?? ?? ?? 48 C7 03 00 00 00 00 5B C3 }
	condition:
		$pattern
}

rule re_comp_189365167b75df80dcd329919239f7fc {
	meta:
		aliases = "re_comp"
		size = "176"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 53 48 89 FB 75 18 48 83 3D ?? ?? ?? ?? 00 BA ?? ?? ?? ?? 0F 84 8F 00 00 00 E9 88 00 00 00 48 83 3D ?? ?? ?? ?? 00 75 41 BF C8 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? BA ?? ?? ?? ?? 74 65 BF 00 01 00 00 48 C7 05 ?? ?? ?? ?? C8 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? BA ?? ?? ?? ?? 74 3F 80 0D ?? ?? ?? ?? 80 48 89 DF E8 ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? 48 89 C6 B9 ?? ?? ?? ?? 48 89 DF E8 2E D9 FF FF 85 C0 74 13 48 98 48 8B 14 C5 ?? ?? ?? ?? 48 81 C2 ?? ?? ?? ?? EB 02 31 D2 5B 48 89 D0 C3 }
	condition:
		$pattern
}

rule __deregister_frame_info_bases_a6e1a8a383481bcbfa188c24a6ccffd2 {
	meta:
		aliases = "__deregister_frame_info_bases"
		size = "169"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 53 75 0A 5B 31 C0 C3 66 66 90 66 66 90 44 8B 1F 45 85 DB 74 EE 48 8B 1D ?? ?? ?? ?? 48 85 DB 74 2F 48 3B 7B 18 48 8D 15 ?? ?? ?? ?? 75 15 48 8B 43 28 48 89 02 48 89 D8 5B C3 66 66 90 48 3B 7B 18 74 EB 48 8D 53 28 48 8B 5B 28 48 85 DB 75 ED 48 8B 1D ?? ?? ?? ?? 48 85 DB 74 45 48 8D 15 ?? ?? ?? ?? EB 16 48 8B 43 18 48 3B 38 74 21 48 8D 53 28 48 8B 5B 28 48 85 DB 74 26 F6 43 20 01 75 E4 48 3B 7B 18 75 E7 66 66 90 66 66 90 EB 9F 48 8B 43 28 48 89 02 48 8B 7B 18 E8 ?? ?? ?? ?? EB 94 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tdestroy_f696b196d9af439c7f86c31863e7a10d {
	meta:
		aliases = "__GI_tdestroy, tdestroy"
		size = "8"
		objfiles = "tdestroy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 74 02 EB BE C3 }
	condition:
		$pattern
}

rule __GI_perror_da14ea669b179c0822a32bdf4ef9edfd {
	meta:
		aliases = "perror, __GI_perror"
		size = "45"
		objfiles = "perror@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 74 0A 80 3F 00 B9 ?? ?? ?? ?? 75 08 BF ?? ?? ?? ?? 48 89 F9 48 89 FA 48 8B 3D ?? ?? ?? ?? BE ?? ?? ?? ?? 31 C0 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __register_frame_info_bases_80da2f5d450bdbd230daacf71f857ec7 {
	meta:
		aliases = "__register_frame_info_bases"
		size = "66"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 74 3B 44 8B 0F 45 85 C9 74 33 48 8B 05 ?? ?? ?? ?? 48 C7 46 20 00 00 00 00 48 89 7E 18 66 81 4E 20 F8 07 48 C7 06 FF FF FF FF 48 89 56 08 48 89 46 28 48 89 4E 10 48 89 35 ?? ?? ?? ?? F3 C3 }
	condition:
		$pattern
}

rule __GI_mbsinit_ddf4b14d9852b10166004b404905a83d {
	meta:
		aliases = "mbsinit, __GI_mbsinit"
		size = "19"
		objfiles = "mbsinit@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF B8 01 00 00 00 74 08 31 C0 83 3F 00 0F 94 C0 C3 }
	condition:
		$pattern
}

rule __xpg_basename_3d3b138b3bb0251e0ad4f1461de09706 {
	meta:
		aliases = "__xpg_basename"
		size = "61"
		objfiles = "__xpg_basename@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF B8 ?? ?? ?? ?? 74 32 80 3F 00 74 2D 48 8D 57 FF 48 89 F8 80 3F 2F 74 0E 48 FF C2 48 39 D7 76 06 48 89 F8 48 89 FA 48 FF C7 80 3F 00 75 E5 80 38 2F 48 0F 44 D0 C6 42 01 00 C3 }
	condition:
		$pattern
}

rule ctermid_a5b9060da7bc54771f1c0a50dc1e29ac {
	meta:
		aliases = "ctermid"
		size = "22"
		objfiles = "ctermid@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF B8 ?? ?? ?? ?? BE ?? ?? ?? ?? 48 0F 44 F8 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __sigsetjmp_1019c9bada21f06219315cece5b18d95 {
	meta:
		aliases = "__sigsetjmp"
		size = "45"
		objfiles = "setjmp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 1F 48 89 6F 08 4C 89 67 10 4C 89 6F 18 4C 89 77 20 4C 89 7F 28 48 8D 54 24 08 48 89 57 30 48 8B 04 24 48 89 47 38 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __gnat_install_locks_e6eca1a6956dc61cfb04eee8c7e72741 {
	meta:
		aliases = "__gnat_install_locks"
		size = "15"
		objfiles = "gthr_gnat@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 3D ?? ?? ?? ?? 48 89 35 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __udivmodti4_8e1e29ae7a504b2e088e40766b1e913b {
	meta:
		aliases = "__udivmodti4"
		size = "1756"
		objfiles = "_udivmoddi4@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 D0 4C 89 64 24 E0 4D 89 C4 48 89 6C 24 D8 4C 89 6C 24 E8 4C 89 74 24 F0 4C 89 7C 24 F8 48 83 EC 10 48 89 74 24 D0 48 89 4C 24 C0 48 8B 74 24 C0 48 89 7C 24 C8 48 89 54 24 B8 4C 8B 54 24 C8 48 8B 7C 24 B8 4C 8B 44 24 D0 48 85 F6 0F 85 11 01 00 00 4C 39 C7 0F 86 F1 01 00 00 B9 38 00 00 00 48 89 FA 48 D3 EA 84 D2 75 09 48 83 E9 08 75 F0 48 89 FA 48 8B 05 ?? ?? ?? ?? 0F B6 04 10 BA 40 00 00 00 49 89 D5 48 8D 04 01 49 29 C5 0F 85 98 05 00 00 48 89 FE 31 D2 4C 89 C0 48 C1 EE 20 48 89 FB 48 F7 F6 83 E3 FF 31 D2 49 89 D9 4C 0F AF C8 49 89 C3 4C 89 C0 48 F7 F6 4C 89 D0 48 C1 E8 20 48 C1 E2 }
	condition:
		$pattern
}

rule __divti3_445eae8c235a70f5af822faa939ee72c {
	meta:
		aliases = "__divti3"
		size = "1584"
		objfiles = "_divdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 D0 4C 89 6C 24 E8 45 31 ED 48 89 6C 24 D8 4C 89 64 24 E0 4C 89 74 24 F0 4C 89 7C 24 F8 48 83 EC 10 48 89 74 24 D0 48 83 7C 24 D0 00 48 89 7C 24 C8 48 89 54 24 B8 48 89 4C 24 C0 0F 88 2F 04 00 00 48 83 7C 24 C0 00 0F 88 46 04 00 00 48 8B 54 24 D0 48 8B 44 24 C8 48 89 54 24 B0 48 8B 54 24 C0 48 89 44 24 A8 48 8B 44 24 B8 4C 8B 5C 24 A8 4C 8B 44 24 B0 48 89 54 24 A0 48 8B 74 24 A0 48 89 44 24 98 48 8B 7C 24 98 48 85 F6 0F 85 EB 00 00 00 4C 39 C7 0F 86 36 01 00 00 B9 38 00 00 00 48 89 FA 48 D3 EA 84 D2 75 09 48 83 E9 08 75 F0 48 89 FA 48 8B 05 ?? ?? ?? ?? 0F B6 04 10 BA 40 00 00 00 48 }
	condition:
		$pattern
}

rule read_encoded_value_with_base_1660e906a7b7c93cb2d1f30a70c29c63 {
	meta:
		aliases = "read_encoded_value_with_base"
		size = "245"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 D8 48 89 6C 24 E0 48 89 D3 4C 89 6C 24 F0 4C 89 74 24 F8 49 89 F5 4C 89 64 24 E8 48 83 EC 38 40 80 FF 50 49 89 CE 89 FD 74 26 44 0F B6 E7 44 89 E0 83 E0 0F 83 F8 0C 76 05 E8 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 89 C0 48 63 04 82 48 01 D0 FF E0 48 8D 42 07 48 83 E0 F8 48 8B 10 48 83 C0 08 49 89 16 48 8B 5C 24 10 48 8B 6C 24 18 4C 8B 64 24 20 4C 8B 6C 24 28 4C 8B 74 24 30 48 83 C4 38 C3 48 8B 13 48 8D 43 08 48 85 D2 74 D3 41 83 E4 70 41 83 FC 10 4C 0F 44 EB 4C 01 EA 40 84 ED 79 BF 48 8B 12 EB BA 0F B7 13 48 8D 43 02 EB D9 48 63 13 48 8D 43 04 EB D0 48 0F BF 13 48 8D 43 02 EB C6 48 8D 74 }
	condition:
		$pattern
}

rule fde_mixed_encoding_compare_fe6439c32be8cc93325861016218e3d9 {
	meta:
		aliases = "fde_mixed_encoding_compare"
		size = "192"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E0 4C 89 64 24 E8 48 89 F3 4C 89 6C 24 F0 4C 89 74 24 F8 48 83 EC 38 48 63 46 04 49 89 FE 48 8D 7E 04 49 89 D4 48 29 C7 E8 BF F8 FF FF 44 0F B6 E8 4C 89 F6 44 89 EF E8 A0 F6 FF FF 48 8D 4C 24 10 48 8D 53 08 48 89 C6 44 89 EF E8 EC F6 FF FF 49 63 44 24 04 49 8D 7C 24 04 49 83 C4 08 48 29 C7 E8 86 F8 FF FF 0F B6 D8 4C 89 F6 89 DF E8 69 F6 FF FF 48 8D 4C 24 08 4C 89 E2 89 DF 48 89 C6 E8 B7 F6 FF FF 48 8B 44 24 08 48 39 44 24 10 B8 01 00 00 00 48 8B 4C 24 08 48 8B 5C 24 18 4C 8B 64 24 20 4C 8B 6C 24 28 4C 8B 74 24 30 19 D2 48 39 4C 24 10 0F 46 C2 48 83 C4 38 C3 }
	condition:
		$pattern
}

rule fde_single_encoding_compare_92a428d8b96f6cbe5f0c3eba24c7fa4b {
	meta:
		aliases = "fde_single_encoding_compare"
		size = "169"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E0 4C 89 64 24 E8 48 89 FB 4C 89 6C 24 F0 4C 89 74 24 F8 48 83 EC 38 8B 7F 20 49 89 F5 48 89 DE 49 89 D4 49 83 C4 08 66 C1 EF 03 40 0F B6 FF E8 68 FE FF FF 8B 7B 20 48 8D 4C 24 10 49 8D 55 08 48 89 C6 49 89 C6 66 C1 EF 03 40 0F B6 FF E8 A9 FE FF FF 8B 7B 20 48 8D 4C 24 08 4C 89 E2 4C 89 F6 66 C1 EF 03 40 0F B6 FF E8 8E FE FF FF 48 8B 44 24 08 48 39 44 24 10 B8 01 00 00 00 48 8B 4C 24 08 48 8B 5C 24 18 4C 8B 64 24 20 4C 8B 6C 24 28 4C 8B 74 24 30 19 D2 48 39 4C 24 10 0F 46 C2 48 83 C4 38 C3 }
	condition:
		$pattern
}

rule __umodti3_1bcaf7b0c7038fa5c6247fa2f89ff7f2 {
	meta:
		aliases = "__umodti3"
		size = "1470"
		objfiles = "_umoddi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 74 24 C0 48 89 4C 24 B0 48 8B 74 24 B0 48 89 7C 24 B8 48 89 54 24 A8 48 89 5C 24 D0 48 89 6C 24 D8 4C 89 64 24 E0 48 85 F6 4C 89 6C 24 E8 4C 89 74 24 F0 4C 89 7C 24 F8 48 8B 7C 24 A8 4C 8B 54 24 B8 4C 8B 44 24 C0 0F 85 E9 00 00 00 4C 39 C7 0F 86 2B 03 00 00 B9 38 00 00 00 66 66 90 48 89 FA 48 D3 EA 84 D2 75 09 48 83 E9 08 75 F0 48 89 FA 48 8B 05 ?? ?? ?? ?? 31 DB 0F B6 04 10 BA 40 00 00 00 48 8D 04 01 48 29 C2 0F 85 98 04 00 00 48 89 FE 31 D2 4C 89 C0 48 C1 EE 20 49 89 FB 48 F7 F6 41 83 E3 FF 31 D2 4D 89 D9 4C 0F AF C8 4C 89 C0 48 F7 F6 4C 89 D0 48 C1 E8 20 48 C1 E2 20 48 09 C2 49 39 D1 }
	condition:
		$pattern
}

rule __ucmpti2_a5e9b3c6d4a8cd6fd241d6edb5d54075 {
	meta:
		aliases = "__ucmpti2"
		size = "71"
		objfiles = "_ucmpdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 74 24 F0 48 89 4C 24 E0 48 8B 44 24 E0 48 39 44 24 F0 48 89 7C 24 E8 48 89 54 24 D8 72 18 77 10 48 8B 44 24 D8 48 39 44 24 E8 72 0A 66 90 76 0F B8 02 00 00 00 C3 31 C0 66 66 90 66 66 90 C3 B8 01 00 00 00 C3 }
	condition:
		$pattern
}

rule __cmpti2_c1e612c3d3ae61231ce1309c893debe4 {
	meta:
		aliases = "__cmpti2"
		size = "71"
		objfiles = "_cmpdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 74 24 F0 48 89 4C 24 E0 48 8B 44 24 E0 48 39 44 24 F0 48 89 7C 24 E8 48 89 54 24 D8 7C 18 7F 10 48 8B 44 24 D8 48 39 44 24 E8 72 0A 66 90 76 0F B8 02 00 00 00 C3 31 C0 66 66 90 66 66 90 C3 B8 01 00 00 00 C3 }
	condition:
		$pattern
}

rule __clzti2_03efe3be09777520e64d164ae3dfc4f9 {
	meta:
		aliases = "__clzti2"
		size = "76"
		objfiles = "_clzdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 74 24 F0 48 8B 44 24 F0 31 F6 48 89 7C 24 E8 48 85 C0 75 08 48 8B 44 24 E8 40 B6 40 B9 38 00 00 00 48 89 C2 48 D3 EA 84 D2 75 09 48 83 E9 08 75 F0 48 89 C2 48 8B 05 ?? ?? ?? ?? 0F B6 04 10 48 01 C8 29 C6 89 F0 83 C0 40 C3 }
	condition:
		$pattern
}

rule munge_stream_7e820b17d8ecd21521f198c54b90553d {
	meta:
		aliases = "munge_stream"
		size = "25"
		objfiles = "fgetwc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 77 08 48 89 77 10 48 89 77 18 48 89 77 20 48 89 77 28 48 89 77 30 C3 }
	condition:
		$pattern
}

rule __init_scan_cookie_5b29c10b812e3960c9a22de06295d282 {
	meta:
		aliases = "__init_scan_cookie"
		size = "67"
		objfiles = "__scan_cookie@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 77 08 C7 47 10 00 00 00 00 31 C0 C6 47 1D 00 F6 06 02 74 03 8B 46 44 89 47 18 C6 47 1E 00 C6 47 1F 00 48 C7 47 38 ?? ?? ?? ?? 48 C7 47 48 ?? ?? ?? ?? C7 47 40 01 00 00 00 C7 47 44 2E 00 00 00 C3 }
	condition:
		$pattern
}

rule __negti2_547ba91b2638d21b4b8e45302a0fd1b2 {
	meta:
		aliases = "__negti2"
		size = "58"
		objfiles = "_negdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 7C 24 E8 48 89 74 24 F0 31 C0 48 8B 4C 24 E8 48 8B 54 24 F0 48 F7 DA 48 85 C9 0F 95 C0 48 F7 D9 48 29 C2 48 89 4C 24 D8 48 8B 44 24 D8 48 89 54 24 E0 48 8B 54 24 E0 C3 }
	condition:
		$pattern
}

rule __parityti2_1d181ffa344dd83ae5ec3e6b9aec079d {
	meta:
		aliases = "__parityti2"
		size = "74"
		objfiles = "_paritydi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 7C 24 E8 48 89 74 24 F0 48 8B 44 24 F0 48 33 44 24 E8 48 89 C2 48 C1 EA 20 48 31 C2 48 89 D0 48 C1 E8 10 48 31 D0 48 89 C1 48 C1 E9 08 48 31 C1 48 89 C8 48 C1 E8 04 48 31 C1 B8 96 69 00 00 83 E1 0F D3 F8 83 E0 01 C3 }
	condition:
		$pattern
}

rule __ctzti2_cf5760b69ecb71ac3026a8e3f1757fc3 {
	meta:
		aliases = "__ctzti2"
		size = "86"
		objfiles = "_ctzdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 7C 24 E8 48 8B 54 24 E8 48 89 74 24 F0 31 F6 48 85 D2 75 08 48 8B 54 24 F0 40 B6 40 48 89 D0 B9 38 00 00 00 48 F7 D8 48 21 D0 66 66 66 90 48 89 C2 48 D3 EA 84 D2 75 09 48 83 E9 08 75 F0 48 89 C2 48 8B 05 ?? ?? ?? ?? 0F B6 04 10 48 01 C8 8D 44 06 FF C3 }
	condition:
		$pattern
}

rule __ffsti2_ab20be846bd8c4f3e86fc619e8e1550c {
	meta:
		aliases = "__ffsti2"
		size = "91"
		objfiles = "_ffsdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 7C 24 E8 48 8B 54 24 E8 48 89 74 24 F0 31 F6 48 85 D2 75 10 48 8B 44 24 F0 48 85 C0 74 38 48 89 C2 40 B6 40 48 89 D0 B9 38 00 00 00 48 F7 D8 48 21 D0 48 89 C2 48 D3 EA 84 D2 75 09 48 83 E9 08 75 F0 48 89 C2 48 8B 05 ?? ?? ?? ?? 0F B6 04 10 48 01 C8 8D 14 06 89 D0 C3 }
	condition:
		$pattern
}

rule __multi3_8c7602a32c7ea04c132574363a12b558 {
	meta:
		aliases = "__multi3"
		size = "200"
		objfiles = "_muldi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 7C 24 E8 48 8B 7C 24 E8 48 89 54 24 D8 4C 8B 4C 24 D8 48 89 4C 24 E0 48 89 74 24 F0 48 89 F9 48 89 FE 83 E1 FF 4C 89 CA 4C 89 C8 83 E2 FF 49 89 C8 48 C1 E8 20 48 C1 EE 20 4C 0F AF C2 48 0F AF C8 48 0F AF D6 48 0F AF F0 4C 89 C0 48 01 D1 48 C1 E8 20 48 8D 0C 08 48 39 CA 76 0D 48 B8 00 00 00 00 01 00 00 00 48 01 C6 48 89 C8 83 E1 FF 41 83 E0 FF 48 C1 E8 20 48 C1 E1 20 48 8D 04 06 48 0F AF 7C 24 E0 48 89 44 24 C0 48 8B 54 24 C0 4A 8D 04 01 4C 0F AF 4C 24 F0 48 89 44 24 B8 48 8B 44 24 B8 48 89 54 24 D0 48 03 7C 24 D0 48 89 44 24 C8 49 8D 04 39 48 89 44 24 D0 48 8B 44 24 C8 48 8B 54 24 D0 C3 }
	condition:
		$pattern
}

rule vsprintf_0172a0c322275275ed00c0a3a2c8a2f5 {
	meta:
		aliases = "vsprintf"
		size = "15"
		objfiles = "vsprintf@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 D1 48 89 F2 48 83 CE FF E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __ashlti3_03c02c66c68c491c32ae13b2b3532d28 {
	meta:
		aliases = "__ashlti3"
		size = "124"
		objfiles = "_ashldi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 D1 48 89 F8 48 89 F2 48 85 C9 74 4A 48 89 74 24 F0 BE 40 00 00 00 48 89 7C 24 E8 48 29 CE 48 85 F6 7E 3B 48 8B 54 24 E8 89 CF 48 89 D0 48 D3 E0 89 F1 48 89 44 24 D8 48 8B 44 24 F0 48 D3 EA 89 F9 48 D3 E0 48 09 C2 48 89 54 24 E0 48 8B 44 24 D8 48 8B 54 24 E0 F3 C3 66 66 90 66 66 90 48 8B 44 24 E8 89 F1 48 C7 44 24 D8 00 00 00 00 F7 D9 48 D3 E0 48 89 44 24 E0 EB D2 }
	condition:
		$pattern
}

rule __lshrti3_94319bb1841389c508157c1ccb9088d7 {
	meta:
		aliases = "__lshrti3"
		size = "124"
		objfiles = "_lshrdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 D1 48 89 F8 48 89 F2 48 85 C9 74 4A 48 89 74 24 F0 BE 40 00 00 00 48 89 7C 24 E8 48 29 CE 48 85 F6 7E 3B 48 8B 54 24 F0 89 CF 48 89 D0 48 D3 E8 89 F1 48 89 44 24 E0 48 8B 44 24 E8 48 D3 E2 89 F9 48 D3 E8 48 09 C2 48 89 54 24 D8 48 8B 44 24 D8 48 8B 54 24 E0 F3 C3 66 66 90 66 66 90 48 8B 44 24 F0 89 F1 48 C7 44 24 E0 00 00 00 00 F7 D9 48 D3 E8 48 89 44 24 D8 EB D2 }
	condition:
		$pattern
}

rule __ashrti3_8c07779b582b7e44a6d72574cdcd6514 {
	meta:
		aliases = "__ashrti3"
		size = "122"
		objfiles = "_ashrdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 D1 48 89 F8 48 89 F2 48 85 C9 74 4A 48 89 74 24 F0 BE 40 00 00 00 48 89 7C 24 E8 48 29 CE 48 85 F6 7E 3B 48 8B 54 24 F0 89 CF 48 89 D0 48 D3 F8 89 F1 48 89 44 24 E0 48 8B 44 24 E8 48 D3 E2 89 F9 48 D3 E8 48 09 C2 48 89 54 24 D8 48 8B 44 24 D8 48 8B 54 24 E0 F3 C3 66 66 90 66 66 90 48 8B 44 24 F0 89 F1 F7 D9 48 99 48 D3 F8 48 89 54 24 E0 48 89 44 24 D8 EB D4 }
	condition:
		$pattern
}

rule wait3_b5f4a25a1e560060d37f8c8e9154933e {
	meta:
		aliases = "wait3"
		size = "16"
		objfiles = "wait3@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 D1 89 F2 48 89 FE 83 CF FF E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getline_bebe3b34a3b33be12c32da9b0bd733ee {
	meta:
		aliases = "__GI_getline, getline"
		size = "13"
		objfiles = "getline@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 D1 BA 0A 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_find_self_bcbc801a6ba35b565b6faba35141da42 {
	meta:
		aliases = "__pthread_find_self"
		size = "30"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 89 E1 BA ?? ?? ?? ?? EB 04 48 83 C2 20 48 8B 42 10 48 39 C1 77 F3 48 3B 4A 18 72 ED C3 }
	condition:
		$pattern
}

rule bcopy_2ea944f3634d6b0e8aa45b4252edb770 {
	meta:
		aliases = "bcopy"
		size = "14"
		objfiles = "bcopy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F0 48 89 FE 48 89 C7 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clntunix_geterr_4e25031aa67fc805237df58622fa8bc8 {
	meta:
		aliases = "clntunix_geterr"
		size = "26"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F0 48 8B 77 10 B9 06 00 00 00 FC 48 89 C7 48 81 C6 90 00 00 00 F3 A5 C3 }
	condition:
		$pattern
}

rule clnttcp_geterr_1eab824ff5e82b8cd039e6882ebcb354 {
	meta:
		aliases = "clnttcp_geterr"
		size = "23"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F0 48 8B 77 10 B9 06 00 00 00 FC 48 89 C7 48 83 C6 30 F3 A5 C3 }
	condition:
		$pattern
}

rule clntudp_geterr_67a5f6bdaaf182778458e2cd1bc2ee9b {
	meta:
		aliases = "clntudp_geterr"
		size = "23"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F0 48 8B 77 10 B9 06 00 00 00 FC 48 89 C7 48 83 C6 40 F3 A5 C3 }
	condition:
		$pattern
}

rule authunix_marshal_224b9afe0fd166e74aee34c4696cf74e {
	meta:
		aliases = "authunix_marshal"
		size = "31"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F0 48 8B 77 40 48 8B 48 08 48 89 C7 8B 96 C8 01 00 00 48 83 C6 38 4C 8B 59 18 41 FF E3 }
	condition:
		$pattern
}

rule xdr_netobj_5b12e688c806ee4760da7a719f087c8f {
	meta:
		aliases = "xdr_netobj"
		size = "20"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F0 48 8D 76 08 B9 00 04 00 00 48 89 C2 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_pthread_attr_getschedpara_8b48d1c9908f9c04e39ddcef51cfac4e {
	meta:
		aliases = "pthread_attr_getschedparam, __GI_pthread_attr_getschedparam"
		size = "28"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F0 48 8D 77 08 48 83 EC 08 BA 04 00 00 00 48 89 C7 E8 ?? ?? ?? ?? 59 31 C0 C3 }
	condition:
		$pattern
}

rule __compare_and_swap_552e425f23babca07b7eab6fd3d32adc {
	meta:
		aliases = "__compare_and_swap"
		size = "15"
		objfiles = "pt_machine@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F0 F0 48 0F B1 17 0F 94 C2 0F BE C2 C3 }
	condition:
		$pattern
}

rule stpncpy_f8b785f413addbb04f318c96a2f33706 {
	meta:
		aliases = "__GI_stpncpy, stpncpy"
		size = "38"
		objfiles = "stpncpy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F1 49 89 F8 EB 11 8A 01 3C 01 41 88 00 48 83 D9 FF 49 FF C0 48 FF CA 48 85 D2 75 EA 48 29 F1 48 8D 04 0F C3 }
	condition:
		$pattern
}

rule wcpncpy_764447d5e5af4ccd8e4452eecb8b6649 {
	meta:
		aliases = "wcpncpy"
		size = "45"
		objfiles = "wcpncpy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F1 49 89 F8 EB 18 8B 01 41 89 00 41 83 38 00 48 8D 41 04 48 0F 45 C8 49 83 C0 04 48 FF CA 48 85 D2 75 E3 48 29 F1 48 8D 04 0F C3 }
	condition:
		$pattern
}

rule __GI_strcpy_d7f2ed2a5bda2f1a4612d1410c2db50c {
	meta:
		aliases = "strcpy, __GI_stpcpy, stpcpy, __GI_strcpy"
		size = "213"
		objfiles = "stpcpy@libc.a, strcpy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F1 83 E1 07 48 89 FA 74 1B F7 D9 83 C1 08 8A 06 84 C0 88 02 0F 84 B5 00 00 00 48 FF C6 48 FF C2 FF C9 75 EA 49 B8 FF FE FE FE FE FE FE FE 48 8B 06 48 83 C6 08 49 89 C1 4D 01 C1 73 7A 49 31 C1 4D 09 C1 49 FF C1 75 6F 48 89 02 48 83 C2 08 48 8B 06 48 83 C6 08 49 89 C1 4D 01 C1 73 59 49 31 C1 4D 09 C1 49 FF C1 75 4E 48 89 02 48 83 C2 08 48 8B 06 48 83 C6 08 49 89 C1 4D 01 C1 73 38 49 31 C1 4D 09 C1 49 FF C1 75 2D 48 89 02 48 83 C2 08 48 8B 06 48 83 C6 08 49 89 C1 4D 01 C1 73 17 49 31 C1 4D 09 C1 49 FF C1 75 0C 48 89 02 48 83 C2 08 E9 77 FF FF FF 88 02 84 C0 74 12 48 FF C2 88 22 84 E4 74 09 }
	condition:
		$pattern
}

rule bzero_c77613460a8ed1e083b3a6aeee9428ec {
	meta:
		aliases = "bzero"
		size = "210"
		objfiles = "bzero@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F2 31 F6 48 83 FA 07 48 89 F9 76 75 49 89 F0 F7 C7 07 00 00 00 74 15 66 66 66 90 66 66 90 40 88 31 48 FF CA 48 FF C1 F6 C1 07 75 F2 48 89 D0 48 C1 E8 06 74 31 48 81 FA C0 D4 01 00 73 60 4C 89 01 4C 89 41 08 4C 89 41 10 4C 89 41 18 4C 89 41 20 4C 89 41 28 4C 89 41 30 4C 89 41 38 48 83 C1 40 48 FF C8 75 D8 83 E2 3F 48 89 D0 48 C1 E8 03 74 0C 4C 89 01 48 83 C1 08 48 FF C8 75 F4 83 E2 07 48 85 D2 74 0B 40 88 31 48 FF C1 48 FF CA 75 F5 C3 66 66 66 90 66 66 66 90 66 66 66 90 4C 0F C3 01 4C 0F C3 41 08 4C 0F C3 41 10 4C 0F C3 41 18 4C 0F C3 41 20 4C 0F C3 41 28 4C 0F C3 41 30 4C 0F C3 41 38 48 }
	condition:
		$pattern
}

rule gmtime_r_8f97270fe70d65399049aa745a000c2b {
	meta:
		aliases = "mq_getattr, gmtime_r"
		size = "10"
		objfiles = "gmtime_r@libc.a, mq_getsetattr@librt.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F2 31 F6 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __negvti2_27d82227daa0d38920ba139b76ca22fd {
	meta:
		aliases = "__negvti2"
		size = "80"
		objfiles = "_negvdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F2 48 89 FE 48 83 EC 08 48 89 D7 48 F7 DE 48 83 D7 00 48 F7 DF 48 85 D2 78 26 48 89 FA 48 C1 FA 3F 48 89 D0 48 29 F0 48 19 FA 48 89 D0 48 C1 E8 3F 84 C0 75 14 48 89 F0 48 89 FA 48 83 C4 08 C3 48 89 F8 48 C1 E8 3F EB E8 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule vwprintf_82bf1537bdb72391a082982fc38abd5f {
	meta:
		aliases = "vwscanf, __GI_vscanf, vprintf, vscanf, vwprintf"
		size = "18"
		objfiles = "vwprintf@libc.a, vprintf@libc.a, vwscanf@libc.a, vscanf@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F2 48 89 FE 48 8B 3D ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule lrand48_r_919a14f8f8c12efcb152a604d74ef694 {
	meta:
		aliases = "drand48_r, __GI_lrand48_r, mrand48_r, lrand48_r"
		size = "11"
		objfiles = "mrand48_r@libc.a, drand48_r@libc.a, lrand48_r@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F2 48 89 FE E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __subvdi3_4a085f67d452f7b9dfc5b096ed8a4eea {
	meta:
		aliases = "__subvdi3"
		size = "45"
		objfiles = "_subvsi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 48 83 EC 08 48 29 F0 48 85 F6 78 11 48 39 C7 0F 9C C2 84 D2 75 0F 48 83 C4 08 C3 66 90 48 39 C7 0F 9F C2 EB ED E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __negvdi2_ad744da726248d5ba54c965b66d92383 {
	meta:
		aliases = "__negvdi2"
		size = "46"
		objfiles = "_negvsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 48 83 EC 08 48 F7 D8 48 85 FF 78 11 48 85 C0 0F 9F C2 84 D2 75 10 48 83 C4 08 C3 66 90 48 89 C2 48 C1 EA 3F EB EC E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __mulvdi3_314e18ec7572ca57be96625c1d21c129 {
	meta:
		aliases = "__mulvdi3"
		size = "38"
		objfiles = "_mulvsi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 48 83 EC 08 48 F7 EE 48 89 C6 48 89 F1 48 C1 F9 3F 48 39 D1 75 08 48 89 F0 48 83 C4 08 C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule syscall_70947dd7c4abd73c48bdc7157765069c {
	meta:
		aliases = "syscall"
		size = "38"
		objfiles = "syscall@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 48 89 F7 48 89 D6 48 89 CA 4D 89 C2 4D 89 C8 4C 8B 4C 24 08 0F 05 48 3D 01 F0 FF FF 0F 83 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule labs_e5fcc2c052f3c2b52851c447d018fafb {
	meta:
		aliases = "imaxabs, llabs, labs"
		size = "15"
		objfiles = "labs@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 48 99 48 89 D0 48 31 F8 48 29 D0 C3 }
	condition:
		$pattern
}

rule imaxdiv_5c8405b555d66cba83698ae28271fdab {
	meta:
		aliases = "lldiv, ldiv, imaxdiv"
		size = "31"
		objfiles = "ldiv@libc.a, lldiv@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 48 99 48 F7 FE 48 85 FF 48 89 C1 78 0B 48 85 D2 79 06 48 FF C1 48 29 F2 48 89 C8 C3 }
	condition:
		$pattern
}

rule __paritydi2_5f4b230d9f992a8fcf5b30f24006c05f {
	meta:
		aliases = "__paritydi2"
		size = "54"
		objfiles = "_paritysi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 48 C1 E8 20 48 31 F8 48 89 C2 48 C1 EA 10 48 31 C2 48 89 D1 48 C1 E9 08 48 31 D1 48 89 C8 48 C1 E8 04 48 31 C1 B8 96 69 00 00 83 E1 0F D3 F8 83 E0 01 C3 }
	condition:
		$pattern
}

rule __clzdi2_8ba752c39381f45dbf5d7c856218b482 {
	meta:
		aliases = "__clzdi2"
		size = "51"
		objfiles = "_clzsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 B9 38 00 00 00 48 89 C7 48 D3 EF 40 84 FF 75 09 48 83 E9 08 75 EF 48 89 C7 48 8B 05 ?? ?? ?? ?? 0F B6 14 38 B8 40 00 00 00 48 01 CA 48 29 D0 C3 }
	condition:
		$pattern
}

rule __ctzdi2_f3046da8833e38d2b8b49db903c47410 {
	meta:
		aliases = "__ctzdi2"
		size = "66"
		objfiles = "_ctzsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 B9 38 00 00 00 48 F7 D8 48 21 F8 66 90 48 89 C2 48 D3 EA 84 D2 75 09 48 83 E9 08 75 F0 48 89 C2 48 8B 05 ?? ?? ?? ?? 0F B6 04 10 BA 40 00 00 00 48 01 C8 48 29 C2 B8 3F 00 00 00 48 29 D0 C3 }
	condition:
		$pattern
}

rule wcslen_16c738783705715b51d5d3b2236f61f2 {
	meta:
		aliases = "__GI_wcslen, wcslen"
		size = "22"
		objfiles = "wcslen@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 EB 04 48 83 C0 04 83 38 00 75 F7 48 29 F8 48 C1 F8 02 C3 }
	condition:
		$pattern
}

rule __GI_wcsnlen_e08849a256ada6903a580b3cf24ac432 {
	meta:
		aliases = "wcsnlen, __GI_wcsnlen"
		size = "30"
		objfiles = "wcsnlen@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 EB 07 48 83 C0 04 48 FF CE 48 85 F6 74 05 83 38 00 75 EF 48 29 F8 48 C1 F8 02 C3 }
	condition:
		$pattern
}

rule wmemset_066ff7277bd9e37d24371087cc01f75f {
	meta:
		aliases = "wmemset"
		size = "23"
		objfiles = "wmemset@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 EB 09 89 30 48 FF CA 48 83 C0 04 48 85 D2 75 F2 48 89 F8 C3 }
	condition:
		$pattern
}

rule basename_be13cdad1ac8ea015142f50fe4e9fbae {
	meta:
		aliases = "__GI_basename, basename"
		size = "25"
		objfiles = "basename@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 EB 0A 48 FF C0 80 FA 2F 48 0F 44 F8 8A 10 84 D2 75 F0 48 89 F8 C3 }
	condition:
		$pattern
}

rule wcsspn_11f516cfaedbeaea8473a8662eb7b998 {
	meta:
		aliases = "__GI_wcsspn, wcsspn"
		size = "36"
		objfiles = "wcsspn@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 EB 0E 3B 08 74 06 48 83 C2 04 EB 07 48 83 C0 04 48 89 F2 8B 0A 85 C9 75 E9 48 29 F8 48 C1 F8 02 C3 }
	condition:
		$pattern
}

rule wcscspn_3a2d9348253bc6981ce1c317ea4e4e20 {
	meta:
		aliases = "wcscspn"
		size = "45"
		objfiles = "wcscspn@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 EB 13 44 39 C1 74 1B 48 83 C2 04 8B 0A 85 C9 75 F1 48 83 C0 04 44 8B 00 45 85 C0 74 05 48 89 F2 EB E9 48 29 F8 48 C1 F8 02 C3 }
	condition:
		$pattern
}

rule wcsstr_63ebb040054259b83ab5e3e92308c73a {
	meta:
		aliases = "wcswcs, wcsstr"
		size = "47"
		objfiles = "wcsstr@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F9 48 89 F0 44 8B 00 45 85 C0 74 1D 8B 11 41 39 D0 75 0A 48 83 C0 04 48 83 C1 04 EB E7 85 D2 74 06 48 83 C7 04 EB D7 31 FF 48 89 F8 C3 }
	condition:
		$pattern
}

rule difftime_940562aafc4081af1cc175aaf7e49e85 {
	meta:
		aliases = "difftime"
		size = "98"
		objfiles = "difftime@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F9 48 BF 00 00 00 00 00 00 20 00 48 89 C8 48 99 48 F7 FF 48 89 44 24 F8 48 89 F0 48 99 F2 48 0F 2A 44 24 F8 48 C1 64 24 F8 35 48 F7 FF 48 2B 4C 24 F8 F2 48 0F 2A D1 F2 48 0F 2A C8 48 89 C7 48 C1 E7 35 48 29 FE F2 0F 5C C1 F2 48 0F 2A CE F2 0F 59 05 ?? ?? ?? ?? F2 0F 5C D1 F2 0F 58 C2 C3 }
	condition:
		$pattern
}

rule strcat_6b6d1d7f16c5fcb86b4d489c7c4bc36b {
	meta:
		aliases = "__GI_strcat, strcat"
		size = "428"
		objfiles = "strcat@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F9 83 E1 07 48 89 F8 49 B8 FF FE FE FE FE FE FE FE 74 1B F7 D9 83 C1 08 80 38 00 0F 84 BA 00 00 00 48 FF C0 FF C9 75 F0 66 66 90 66 66 90 48 8B 08 48 83 C0 08 4C 89 C2 48 01 CA 73 59 48 31 CA 4C 09 C2 48 FF C2 75 4E 48 8B 08 48 83 C0 08 4C 89 C2 48 01 CA 73 3F 48 31 CA 4C 09 C2 48 FF C2 75 34 48 8B 08 48 83 C0 08 4C 89 C2 48 01 CA 73 25 48 31 CA 4C 09 C2 48 FF C2 75 1A 48 8B 08 48 83 C0 08 4C 89 C2 48 01 CA 73 0B 48 31 CA 4C 09 C2 48 FF C2 74 98 48 83 E8 08 84 C9 74 3D 48 FF C0 84 ED 74 36 48 FF C0 F7 C1 00 00 FF 00 74 2B 48 FF C0 F7 C1 00 00 00 FF 74 20 48 FF C0 48 C1 E9 20 84 C9 74 15 }
	condition:
		$pattern
}

rule __GI_strlen_b4a815cc335dce43801dc2327c45bd76 {
	meta:
		aliases = "strlen, __GI_strlen"
		size = "225"
		objfiles = "strlen@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F9 83 E1 07 48 89 F8 74 15 F7 D9 83 C1 08 80 38 00 0F 84 C4 00 00 00 48 FF C0 FF C9 75 F0 49 B8 FF FE FE FE FE FE FE FE 66 66 90 66 66 90 48 8B 08 48 83 C0 08 4C 89 C2 48 01 CA 73 59 48 31 CA 4C 09 C2 48 FF C2 75 4E 48 8B 08 48 83 C0 08 4C 89 C2 48 01 CA 73 3F 48 31 CA 4C 09 C2 48 FF C2 75 34 48 8B 08 48 83 C0 08 4C 89 C2 48 01 CA 73 25 48 31 CA 4C 09 C2 48 FF C2 75 1A 48 8B 08 48 83 C0 08 4C 89 C2 48 01 CA 73 0B 48 31 CA 4C 09 C2 48 FF C2 74 98 48 83 E8 08 84 C9 74 3D 48 FF C0 84 ED 74 36 48 FF C0 F7 C1 00 00 FF 00 74 2B 48 FF C0 F7 C1 00 00 00 FF 74 20 48 FF C0 48 C1 E9 20 84 C9 74 15 }
	condition:
		$pattern
}

rule strncat_698b12dba81944c5ad7b93224b411e7e {
	meta:
		aliases = "__GI_strncat, strncat"
		size = "119"
		objfiles = "strncat@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F9 8A 01 48 FF C1 84 C0 75 F7 48 83 E9 02 48 83 FA 03 76 50 49 89 D0 49 C1 E8 02 8A 06 84 C0 88 41 01 74 4D 8A 46 01 84 C0 88 41 02 74 43 8A 46 02 84 C0 88 41 03 74 39 8A 46 03 48 83 C1 04 84 C0 88 01 74 2C 48 83 C6 04 49 FF C8 75 CD 83 E2 03 EB 11 8A 06 48 FF C1 84 C0 88 01 74 13 48 FF C6 48 FF CA 48 85 D2 75 EA 84 C0 74 04 C6 41 01 00 48 89 F8 C3 }
	condition:
		$pattern
}

rule wcsncat_9bf34d71e54eea4530a2f5f908f7ae41 {
	meta:
		aliases = "wcsncat"
		size = "53"
		objfiles = "wcsncat@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F9 8B 01 48 83 C1 04 85 C0 75 F6 48 83 E9 04 EB 0B 48 83 C6 04 48 FF CA 48 83 C1 04 48 85 D2 74 08 8B 06 85 C0 89 01 75 E8 48 89 F8 C7 01 00 00 00 00 C3 }
	condition:
		$pattern
}

rule wmemcpy_4067be131ea890537f5176cd8ccc6860 {
	meta:
		aliases = "__GI_wmemcpy, wmemcpy"
		size = "29"
		objfiles = "wmemcpy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F9 EB 0F 8B 06 48 FF CA 48 83 C6 04 89 01 48 83 C1 04 48 85 D2 75 EC 48 89 F8 C3 }
	condition:
		$pattern
}

rule wcsncpy_507aa243b5db5325a21cfbbb199f322c {
	meta:
		aliases = "wcsncpy"
		size = "36"
		objfiles = "wcsncpy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F9 EB 16 8B 06 89 01 83 39 00 48 8D 46 04 48 0F 45 F0 48 83 C1 04 48 FF CA 48 85 D2 75 E5 48 89 F8 C3 }
	condition:
		$pattern
}

rule strpbrk_c96a2c5fd12666ea1d7487ae01986dff {
	meta:
		aliases = "__GI_strpbrk, strpbrk"
		size = "140"
		objfiles = "strpbrk@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 FA 49 89 F8 48 81 EC 00 01 00 00 B9 20 00 00 00 48 89 E7 31 C0 FC F3 48 AB 48 89 F0 66 90 8A 08 84 C9 74 25 88 0C 0C 8A 48 01 84 C9 74 1B 88 0C 0C 8A 48 02 84 C9 74 11 88 0C 0C 8A 48 03 48 83 C0 04 88 0C 0C 84 C9 75 D5 48 8D 42 FC 90 48 83 C0 04 8A 08 38 0C 0C 74 21 8A 48 01 38 0C 0C 74 16 8A 48 02 38 0C 0C 74 0B 8A 48 03 38 0C 0C 75 DD 48 FF C0 48 FF C0 48 FF C0 48 81 C4 00 01 00 00 31 D2 08 C9 48 0F 44 C2 C3 }
	condition:
		$pattern
}

rule __GI_strcspn_828c65427d2ab8d1ebd26e6dd1999db5 {
	meta:
		aliases = "strcspn, __GI_strcspn"
		size = "135"
		objfiles = "strcspn@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 FA 49 89 F8 48 81 EC 00 01 00 00 B9 20 00 00 00 48 89 E7 31 C0 FC F3 48 AB 48 89 F0 66 90 8A 08 84 C9 74 25 88 0C 0C 8A 48 01 84 C9 74 1B 88 0C 0C 8A 48 02 84 C9 74 11 88 0C 0C 8A 48 03 48 83 C0 04 88 0C 0C 84 C9 75 D5 48 8D 42 FC 90 48 83 C0 04 8A 08 38 0C 0C 74 21 8A 48 01 38 0C 0C 74 16 8A 48 02 38 0C 0C 74 0B 8A 48 03 38 0C 0C 75 DD 48 FF C0 48 FF C0 48 FF C0 48 81 C4 00 01 00 00 48 29 D0 C3 }
	condition:
		$pattern
}

rule strspn_36a036259b48b65048d57f80a07b8750 {
	meta:
		aliases = "__GI_strspn, strspn"
		size = "135"
		objfiles = "strspn@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 FA 49 89 F8 48 81 EC 00 01 00 00 B9 20 00 00 00 48 89 E7 31 C0 FC F3 48 AB 48 89 F0 66 90 8A 08 84 C9 74 25 88 0C 0C 8A 48 01 84 C9 74 1B 88 0C 0C 8A 48 02 84 C9 74 11 88 0C 0C 8A 48 03 48 83 C0 04 88 0C 0C 84 C9 75 D5 48 8D 42 FC 90 48 83 C0 04 8A 08 84 0C 0C 74 21 8A 48 01 84 0C 0C 74 16 8A 48 02 84 0C 0C 74 0B 8A 48 03 84 0C 0C 75 DD 48 FF C0 48 FF C0 48 FF C0 48 81 C4 00 01 00 00 48 29 D0 C3 }
	condition:
		$pattern
}

rule __GI_strchr_0b20f6125c0ef68348904290c7e9108e {
	meta:
		aliases = "index, strchr, __GI_strchr"
		size = "417"
		objfiles = "strchr@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 FA 83 E2 07 48 89 F8 74 1F F7 DA 83 C2 08 8A 08 40 38 CE 0F 84 85 01 00 00 84 C9 0F 84 15 01 00 00 48 FF C0 FF CA 75 E6 49 B9 01 01 01 01 01 01 01 01 40 0F B6 D6 4C 0F AF CA 49 B8 FF FE FE FE FE FE FE FE 66 66 66 90 66 66 90 66 66 90 48 8B 08 48 83 C0 08 4C 89 C2 4C 31 C9 48 01 CA 0F 83 DA 00 00 00 48 31 CA 4C 09 C2 48 FF C2 0F 85 CB 00 00 00 4C 31 C9 4C 89 C2 48 01 CA 0F 83 B4 00 00 00 48 31 CA 4C 09 C2 48 FF C2 0F 85 A5 00 00 00 48 8B 08 48 83 C0 08 4C 89 C2 4C 31 C9 48 01 CA 0F 83 97 00 00 00 48 31 CA 4C 09 C2 48 FF C2 0F 85 88 00 00 00 4C 31 C9 4C 89 C2 48 01 CA 73 75 48 31 CA 4C 09 }
	condition:
		$pattern
}

rule wcscat_b85bd1d90e1dba6e9c0e1f03372d4fe6 {
	meta:
		aliases = "__GI_wcscat, wcscat"
		size = "37"
		objfiles = "wcscat@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 FA 8B 02 48 83 C2 04 85 C0 75 F6 48 83 EA 04 8B 06 48 83 C6 04 89 02 48 83 C2 04 85 C0 75 F0 48 89 F8 C3 }
	condition:
		$pattern
}

rule __GI_wcscpy_2ce3e68c723649644a313657006856e9 {
	meta:
		aliases = "wcscpy, __GI_wcscpy"
		size = "23"
		objfiles = "wcscpy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 FA 8B 06 48 83 C6 04 89 02 48 83 C2 04 85 C0 75 F0 48 89 F8 C3 }
	condition:
		$pattern
}

rule l64a_37bb1b84f60b05eb1e6c2e6555e42fa4 {
	meta:
		aliases = "l64a"
		size = "62"
		objfiles = "l64a@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 FA B8 ?? ?? ?? ?? 83 E2 FF 74 30 31 F6 EB 18 48 89 D0 FF C6 48 C1 EA 06 83 E0 3F 8A 80 ?? ?? ?? ?? 88 81 ?? ?? ?? ?? 48 85 D2 48 63 CE 75 E0 C6 81 ?? ?? ?? ?? 00 B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule wait_8c2d9f03f1cff0925ad46691eb81177e {
	meta:
		aliases = "__libc_wait, wait"
		size = "15"
		objfiles = "wait@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 FE 31 C9 31 D2 83 CF FF E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule skip_79354c308d5a5a14d298dea18482dbbc {
	meta:
		aliases = "skip"
		size = "154"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 FE 45 31 C0 EB 7D 83 F9 22 75 06 41 83 F0 01 EB 6F 41 83 F8 01 75 10 3C 5C 75 0C 80 7F 01 22 48 8D 47 01 48 0F 44 F8 8A 07 88 06 48 FF C6 41 83 F8 01 74 4C 83 F9 23 75 0C C6 05 ?? ?? ?? ?? 23 C6 07 00 EB 4B 83 F9 09 0F 94 C2 83 F9 20 0F 94 C0 08 C2 75 05 83 F9 0A 75 26 88 0D ?? ?? ?? ?? C6 07 00 48 FF C7 0F BE 07 83 F8 09 74 F5 83 F8 20 0F 94 C2 83 F8 0A 0F 94 C0 08 C2 75 E5 EB 10 48 FF C7 8A 07 0F BE C8 85 C9 0F 85 76 FF FF FF 48 89 F8 C6 46 FF 00 C3 }
	condition:
		$pattern
}

rule atexit_7ffba7eb313c344d61b5fed7e4507000 {
	meta:
		aliases = "atexit"
		size = "24"
		objfiles = "atexits@uclibc_nonshared.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 31 D2 48 85 C0 74 03 48 8B 10 31 F6 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isblank_6fe18e14d2fb69f3cddb27f0a6491688 {
	meta:
		aliases = "isblank"
		size = "20"
		objfiles = "isblank@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 48 63 FF 0F B7 04 78 25 00 01 00 00 C3 }
	condition:
		$pattern
}

rule iscntrl_4f6ef0e5e96b1df538e60d5ac74bf019 {
	meta:
		aliases = "iscntrl"
		size = "20"
		objfiles = "iscntrl@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 48 63 FF 0F B7 04 78 25 00 02 00 00 C3 }
	condition:
		$pattern
}

rule ispunct_8de8a26f33075b01a7cc854bd8f11e52 {
	meta:
		aliases = "ispunct"
		size = "20"
		objfiles = "ispunct@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 48 63 FF 0F B7 04 78 25 00 04 00 00 C3 }
	condition:
		$pattern
}

rule isalnum_929a9e39945524822f35f73369dc72a5 {
	meta:
		aliases = "isalnum"
		size = "20"
		objfiles = "isalnum@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 48 63 FF 0F B7 04 78 25 00 08 00 00 C3 }
	condition:
		$pattern
}

rule isgraph_9c28c95fc134a803befa6104d91ced74 {
	meta:
		aliases = "isgraph"
		size = "20"
		objfiles = "isgraph@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 48 63 FF 0F B7 04 78 25 80 00 00 00 C3 }
	condition:
		$pattern
}

rule isupper_b5099b5efd66c801d691c36bdc8e9968 {
	meta:
		aliases = "isupper"
		size = "18"
		objfiles = "isupper@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 48 63 FF 0F B7 04 78 83 E0 01 C3 }
	condition:
		$pattern
}

rule islower_85560ed2ca02d5790d024953e265e65e {
	meta:
		aliases = "islower"
		size = "18"
		objfiles = "islower@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 48 63 FF 0F B7 04 78 83 E0 02 C3 }
	condition:
		$pattern
}

rule isalpha_a8ca98121e7645da2cc397713527c499 {
	meta:
		aliases = "isalpha"
		size = "18"
		objfiles = "isalpha@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 48 63 FF 0F B7 04 78 83 E0 04 C3 }
	condition:
		$pattern
}

rule isxdigit_006a36783a5f64bb687de8ce95b032e9 {
	meta:
		aliases = "isxdigit"
		size = "18"
		objfiles = "isxdigit@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 48 63 FF 0F B7 04 78 83 E0 10 C3 }
	condition:
		$pattern
}

rule isspace_92367e79c9b1e4a4086fe394d6234616 {
	meta:
		aliases = "isspace"
		size = "18"
		objfiles = "isspace@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 48 63 FF 0F B7 04 78 83 E0 20 C3 }
	condition:
		$pattern
}

rule isprint_07c36fbd7af1b1fbb0d83d88d7d36624 {
	meta:
		aliases = "isprint"
		size = "18"
		objfiles = "isprint@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 48 63 FF 0F B7 04 78 83 E0 40 C3 }
	condition:
		$pattern
}

rule isctype_caa3849e4415012f5bad0cd0e14d62ba {
	meta:
		aliases = "isctype"
		size = "18"
		objfiles = "isctype@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 48 63 FF 66 23 34 78 0F B7 C6 C3 }
	condition:
		$pattern
}

rule _Unwind_SjLj_Register_d100e92078824c52f174069265aa2c44 {
	meta:
		aliases = "_Unwind_SjLj_Register"
		size = "18"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 48 89 07 48 89 3D ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __re_set_syntax_26e7b8d8a92ed76c586f2e06d4795b45 {
	meta:
		aliases = "re_set_syntax, __re_set_syntax"
		size = "15"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 48 89 3D ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __cmsg_nxthdr_d1b32be3de051d7d4734fd3370e0634e {
	meta:
		aliases = "__GI___cmsg_nxthdr, __cmsg_nxthdr"
		size = "64"
		objfiles = "cmsg_nxthdr@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 06 48 83 F8 0F 76 31 48 83 C0 07 48 8B 57 28 48 03 57 20 48 83 E0 F8 48 8D 0C 06 48 8D 41 10 48 39 D0 77 14 48 8B 01 48 83 C0 07 48 83 E0 F8 48 8D 04 01 48 39 D0 76 02 31 C9 48 89 C8 C3 }
	condition:
		$pattern
}

rule insque_014dfe4af7403aa148816b3dc2282fa1 {
	meta:
		aliases = "insque"
		size = "23"
		objfiles = "insque@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 06 48 89 3E 48 85 C0 74 04 48 89 78 08 48 89 07 48 89 77 08 C3 }
	condition:
		$pattern
}

rule _Unwind_SetGR_2e812c5baa4546d2f13fd0ce5616126e {
	meta:
		aliases = "_Unwind_SetGR"
		size = "12"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 07 48 63 F6 48 89 54 F0 10 C3 }
	condition:
		$pattern
}

rule _Unwind_GetGR_ea18db07665d68b999abc7097c8d70c2 {
	meta:
		aliases = "_Unwind_GetGR"
		size = "12"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 07 48 63 F6 48 8B 44 F0 10 C3 }
	condition:
		$pattern
}

rule _Unwind_SjLj_Unregister_e359974dff09d89cbdfc4dbad0cbc60a {
	meta:
		aliases = "_Unwind_SjLj_Unregister"
		size = "11"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 07 48 89 05 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule _Unwind_GetLanguageSpecificDat_bd7ecac214d8fa05ffe6b2bb8ac0a4a8 {
	meta:
		aliases = "_Unwind_GetLanguageSpecificData"
		size = "8"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 07 48 8B 40 38 C3 }
	condition:
		$pattern
}

rule _Unwind_GetIP_6c29f1487948be040d7b82b09c607780 {
	meta:
		aliases = "_Unwind_GetIP"
		size = "11"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 07 8B 40 08 FF C0 48 98 C3 }
	condition:
		$pattern
}

rule __old_sem_getvalue_6727e01a588523c861e51753519dce55 {
	meta:
		aliases = "__old_sem_getvalue"
		size = "23"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 07 A8 01 74 07 48 D1 E8 89 06 EB 06 C7 06 00 00 00 00 31 C0 C3 }
	condition:
		$pattern
}

rule _Unwind_SetIP_5c66b0a0cdf972348e9b7e0565d41d2b {
	meta:
		aliases = "_Unwind_SetIP"
		size = "9"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 07 FF CE 89 70 08 C3 }
	condition:
		$pattern
}

rule _dl_do_lazy_reloc_82ce4c16d0a389ba962e4a7a73bcbc1f {
	meta:
		aliases = "_dl_do_lazy_reloc"
		size = "56"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 0A 48 8B 52 08 48 8B 07 85 D2 74 27 83 FA 07 75 06 48 01 04 08 EB 1C BF 01 00 00 00 B8 3C 00 00 00 0F 05 48 3D 00 F0 FF FF 76 08 F7 D8 89 05 ?? ?? ?? ?? 31 C0 C3 }
	condition:
		$pattern
}

rule __GI_strcasecmp_8fe85f92680913231b05e6521c25db04 {
	meta:
		aliases = "strcasecmp, __GI_strcasecmp"
		size = "48"
		objfiles = "strcasecmp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 0D ?? ?? ?? ?? 31 C0 48 39 F7 74 14 0F B6 07 0F BF 14 41 0F B6 06 0F BF 04 41 29 C2 89 D0 75 0D 80 3F 00 74 08 48 FF C6 48 FF C7 EB DA C3 }
	condition:
		$pattern
}

rule dlerror_cc90449f96080985854c55261894fde0 {
	meta:
		aliases = "dlerror"
		size = "34"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 15 ?? ?? ?? ?? 31 C0 48 85 D2 74 13 48 8B 04 D5 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 C3 }
	condition:
		$pattern
}

rule getpagesize_61ad0577939437d124cd2ac55d7e20cf {
	meta:
		aliases = "__GI_getpagesize, __getpagesize, getpagesize"
		size = "19"
		objfiles = "getpagesize@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 15 ?? ?? ?? ?? B8 00 10 00 00 48 85 D2 0F 45 C2 C3 }
	condition:
		$pattern
}

rule __GI_execv_3f0102b508291ff6fb4387d577bb9fec {
	meta:
		aliases = "execv, __GI_execv"
		size = "12"
		objfiles = "execv@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 15 ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _Unwind_GetCFA_422647608756a0c665007d01631b2fce {
	meta:
		aliases = "_Unwind_GetCFA"
		size = "16"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 17 31 C0 48 85 D2 74 04 48 8B 42 50 F3 C3 }
	condition:
		$pattern
}

rule remque_2016440df2d1734a1c49f15cc2882d80 {
	meta:
		aliases = "remque"
		size = "25"
		objfiles = "remque@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 17 48 8B 47 08 48 85 D2 74 04 48 89 42 08 48 85 C0 74 03 48 89 10 C3 }
	condition:
		$pattern
}

rule __GI___longjmp_f98d5651168372aaa820147f017ccadc {
	meta:
		aliases = "__longjmp, __GI___longjmp"
		size = "45"
		objfiles = "__longjmp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 1F 48 8B 6F 08 4C 8B 67 10 4C 8B 6F 18 4C 8B 77 20 4C 8B 7F 28 85 F6 B8 01 00 00 00 0F 44 F0 89 F0 48 8B 57 38 48 8B 67 30 FF E2 }
	condition:
		$pattern
}

rule __popcountdi2_cb3b1d677556c36d4494090a80fd980a {
	meta:
		aliases = "__popcountdi2"
		size = "47"
		objfiles = "_popcountsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 35 ?? ?? ?? ?? 31 C9 31 D2 66 66 90 66 90 48 89 F8 48 D3 E8 48 83 C1 08 25 FF 00 00 00 0F B6 04 06 48 01 C2 48 83 F9 40 75 E4 89 D0 C3 }
	condition:
		$pattern
}

rule putchar_unlocked_3865cef6992aeafa2ef1c219d170caae {
	meta:
		aliases = "putchar_unlocked"
		size = "37"
		objfiles = "putchar_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 35 ?? ?? ?? ?? 48 8B 56 18 48 3B 56 30 72 05 E9 ?? ?? ?? ?? 40 88 3A 40 0F B6 C7 48 FF C2 48 89 56 18 C3 }
	condition:
		$pattern
}

rule putwchar_de77d172309ade3482f6a4046fd34aa1 {
	meta:
		aliases = "putwchar"
		size = "48"
		objfiles = "putwchar@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 35 ?? ?? ?? ?? 83 7E 50 00 74 0F 48 8B 56 18 48 3B 56 30 72 0A E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? 40 88 3A 40 0F B6 C7 48 FF C2 48 89 56 18 C3 }
	condition:
		$pattern
}

rule putwchar_unlocked_c5ca242fcb43b0c8b87d944f23b06cb9 {
	meta:
		aliases = "putwchar_unlocked"
		size = "12"
		objfiles = "putwchar_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 35 ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule alphasort_66205ecbea46b32f5b07cd78fa3c13e8 {
	meta:
		aliases = "alphasort64, alphasort"
		size = "19"
		objfiles = "alphasort@libc.a, alphasort64@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 36 48 8B 3F 48 83 C6 13 48 83 C7 13 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getchar_unlocked_1ad19b39eb90bdbbd3815a6025c5d866 {
	meta:
		aliases = "__GI_getchar_unlocked, getchar_unlocked"
		size = "33"
		objfiles = "getchar_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 3D ?? ?? ?? ?? 48 8B 57 18 48 3B 57 28 72 05 E9 ?? ?? ?? ?? 0F B6 02 48 FF C2 48 89 57 18 C3 }
	condition:
		$pattern
}

rule dl_cleanup_c5592dd98d6ffa2590a66e6b37a7ca12 {
	meta:
		aliases = "dl_cleanup"
		size = "34"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 3D ?? ?? ?? ?? 53 EB 11 48 8B 5F 08 BE 01 00 00 00 E8 6D FD FF FF 48 89 DF 48 85 FF 75 EA 5B C3 }
	condition:
		$pattern
}

rule _dl_unmap_cache_92b1affa2342f09df2ee209661fdd996 {
	meta:
		aliases = "_dl_unmap_cache"
		size = "66"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 3D ?? ?? ?? ?? 83 CA FF 48 8D 47 FF 48 83 F8 FD 77 2B 48 8B 35 ?? ?? ?? ?? B8 0B 00 00 00 0F 05 48 3D 00 F0 FF FF 76 08 F7 D8 89 05 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 31 D2 89 D0 C3 }
	condition:
		$pattern
}

rule _dl_app_init_array_59d29e9a7b0f84937a87c34da067ad94 {
	meta:
		aliases = "getwchar_unlocked, getwchar, _dl_app_fini_array, _dl_app_init_array"
		size = "12"
		objfiles = "libdl@libdl.a, getwchar@libc.a, getwchar_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 3D ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _dl_parse_lazy_relocation_info_11d6b6bb2dffb1c3f26769ef0c97da40 {
	meta:
		aliases = "_dl_parse_lazy_relocation_information"
		size = "22"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 3F 48 89 D1 41 B8 ?? ?? ?? ?? 48 89 F2 31 F6 E9 A1 FE FF FF }
	condition:
		$pattern
}

rule _dl_parse_relocation_informati_2ef0db03f832fbc4c1d8a7f5565819be {
	meta:
		aliases = "_dl_parse_relocation_information"
		size = "27"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 3F 48 89 F0 48 89 D1 41 B8 ?? ?? ?? ?? 48 89 C2 48 8B 77 38 E9 B7 FE FF FF }
	condition:
		$pattern
}

rule __collated_compare_fe57234d3a69c9c65af8dc1227302ab6 {
	meta:
		aliases = "__collated_compare"
		size = "34"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 3F 48 8B 36 31 C0 48 39 F7 74 14 48 85 FF B0 01 74 0D 83 C8 FF 48 85 F6 74 05 E9 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule fde_unencoded_compare_a1f7000d01146ec052681e0e505e32e5 {
	meta:
		aliases = "fde_unencoded_compare"
		size = "27"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 42 08 48 39 46 08 B8 01 00 00 00 48 8B 4E 08 19 FF 48 3B 4A 08 0F 46 C7 C3 }
	condition:
		$pattern
}

rule _Unwind_DeleteException_7778519b3c95c990f91fcd70b884a894 {
	meta:
		aliases = "_Unwind_DeleteException"
		size = "25"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 08 48 85 C0 74 0E 48 89 FE 49 89 C3 BF 01 00 00 00 41 FF E3 F3 C3 }
	condition:
		$pattern
}

rule _obstack_allocated_p_104a90ac69cbbd364546cf19460d588c {
	meta:
		aliases = "_obstack_allocated_p"
		size = "35"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 08 EB 04 48 8B 40 08 48 85 C0 74 0A 48 39 F0 73 F2 48 39 30 72 ED 48 85 C0 0F 95 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule __fbufsize_866aee535b10d1e6527dd5daeb8d0999 {
	meta:
		aliases = "__fbufsize"
		size = "9"
		objfiles = "__fbufsize@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 10 48 2B 47 08 C3 }
	condition:
		$pattern
}

rule xdrmem_getpos_ed7fa21a61ae89e363d8e198f4c2a1ac {
	meta:
		aliases = "xdrmem_getpos"
		size = "8"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 18 2B 47 20 C3 }
	condition:
		$pattern
}

rule __pthread_attr_getguardsize_20ccd4b78f280b75b102dc20bda271af {
	meta:
		aliases = "pthread_attr_getguardsize, __pthread_attr_getguardsize"
		size = "10"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 18 48 89 06 31 C0 C3 }
	condition:
		$pattern
}

rule telldir_7a346892aa6f48c113696b74d69cab29 {
	meta:
		aliases = "telldir"
		size = "5"
		objfiles = "telldir@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 20 C3 }
	condition:
		$pattern
}

rule __pthread_attr_getstackaddr_eaaa7cbd5e25d2119a44a50cee592b8a {
	meta:
		aliases = "pthread_attr_getstackaddr, __pthread_attr_getstackaddr"
		size = "10"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 28 48 89 06 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_attr_getstacksize_e7b9edb1f4ff6d31a6fb9153b5c55a6a {
	meta:
		aliases = "__pthread_attr_getstacksize, pthread_attr_getstacksize"
		size = "10"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 30 48 89 06 31 C0 C3 }
	condition:
		$pattern
}

rule _dl_aux_init_a2de79102a49e8341db97124d5ce31ba {
	meta:
		aliases = "_dl_aux_init"
		size = "23"
		objfiles = "dl_support@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 38 48 89 05 ?? ?? ?? ?? 48 8B 47 58 48 89 05 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule _obstack_memory_used_ffcaffbf7fb149407c5da3d0b6568c5e {
	meta:
		aliases = "_obstack_memory_used"
		size = "22"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 57 08 31 C0 EB 08 03 02 29 D0 48 8B 52 08 48 85 D2 75 F3 C3 }
	condition:
		$pattern
}

rule sc_getc_564898519739d0b6b51700d7dea82f20 {
	meta:
		aliases = "sc_getc"
		size = "9"
		objfiles = "vfscanf@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 7F 08 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clntunix_freeres_6a18869a355cfb0332920b4648e6c627 {
	meta:
		aliases = "clntunix_freeres"
		size = "31"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 7F 10 48 89 F1 31 C0 48 89 D6 49 89 CB 48 81 C7 C8 00 00 00 C7 07 02 00 00 00 41 FF E3 }
	condition:
		$pattern
}

rule clntudp_freeres_76967b70467a451c457fcf7ed8c9f12a {
	meta:
		aliases = "clntudp_freeres"
		size = "28"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 7F 10 48 89 F1 31 C0 48 89 D6 49 89 CB 48 83 C7 58 C7 07 02 00 00 00 41 FF E3 }
	condition:
		$pattern
}

rule clnttcp_freeres_14c7adb20ef011c141012c3d33264e22 {
	meta:
		aliases = "clnttcp_freeres"
		size = "28"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 7F 10 48 89 F1 31 C0 48 89 D6 49 89 CB 48 83 C7 68 C7 07 02 00 00 00 41 FF E3 }
	condition:
		$pattern
}

rule xdrstdio_destroy_600330dace8922e5147ebda0eb13424e {
	meta:
		aliases = "hasmntopt, xdrstdio_destroy"
		size = "9"
		objfiles = "xdr_stdio@libc.a, mntent@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 7F 18 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svcunix_getargs_45f8c66df50f9c6862a9b5d8d000e74d {
	meta:
		aliases = "svctcp_getargs, svcunix_getargs"
		size = "22"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 7F 40 48 89 F1 31 C0 48 89 D6 49 89 CB 48 83 C7 10 41 FF E3 }
	condition:
		$pattern
}

rule svcunix_freeargs_437fa1cbb12006b159de2cda03520095 {
	meta:
		aliases = "svctcp_freeargs, svcunix_freeargs"
		size = "28"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 7F 40 48 89 F1 31 C0 48 89 D6 49 89 CB 48 83 C7 10 C7 07 02 00 00 00 41 FF E3 }
	condition:
		$pattern
}

rule svcudp_getargs_3d6a7f54baaa6f3415510a667650c4ab {
	meta:
		aliases = "svcudp_getargs"
		size = "22"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 7F 48 48 89 F1 31 C0 48 89 D6 49 89 CB 48 83 C7 10 41 FF E3 }
	condition:
		$pattern
}

rule svcudp_freeargs_59826f23064bb352ec12154bab3c1255 {
	meta:
		aliases = "svcudp_freeargs"
		size = "28"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 7F 48 48 89 F1 31 C0 48 89 D6 49 89 CB 48 83 C7 10 C7 07 02 00 00 00 41 FF E3 }
	condition:
		$pattern
}

rule __GI_memrchr_3d50a47aedaf356858ebc8ef450509b2 {
	meta:
		aliases = "memrchr, __GI_memrchr"
		size = "237"
		objfiles = "memrchr@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8D 04 17 49 89 D0 EB 0F 48 FF C8 40 38 30 0F 84 D7 00 00 00 49 FF C8 4D 85 C0 74 04 A8 07 75 E8 48 89 C1 40 0F B6 C6 89 C2 C1 E2 08 09 D0 48 98 48 89 C2 48 C1 E2 10 48 09 C2 48 89 D7 48 C1 E7 20 48 09 D7 E9 80 00 00 00 48 83 E9 08 48 89 F8 48 BA FF FE FE FE FE FE FE 7E 48 33 01 48 8D 14 10 48 F7 D0 48 31 C2 48 B8 00 01 01 01 01 01 01 81 48 85 D0 74 4F 40 38 71 07 48 8D 41 07 74 6B 40 38 71 06 48 8D 41 06 74 61 40 38 71 05 48 8D 41 05 74 57 40 38 71 04 48 8D 41 04 74 4D 40 38 71 03 48 8D 41 03 74 43 40 38 71 02 48 8D 41 02 74 39 40 38 71 01 48 8D 41 01 74 2F 40 38 31 75 04 48 89 C8 C3 49 83 }
	condition:
		$pattern
}

rule __GI_wcschrnul_899b0af7a7b8b25b4c1c5c7bdbf4b697 {
	meta:
		aliases = "wcschrnul, __GI_wcschrnul"
		size = "19"
		objfiles = "wcschrnul@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8D 47 FC 48 83 C0 04 8B 10 85 D2 74 04 39 F2 75 F2 C3 }
	condition:
		$pattern
}

rule memcmp_bytes_50224474e20aa66d5176186b07a56e30 {
	meta:
		aliases = "memcmp_bytes"
		size = "42"
		objfiles = "memcmp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8D 4C 24 F8 48 8D 54 24 F0 48 89 7C 24 F8 48 89 74 24 F0 0F B6 31 0F B6 02 48 FF C1 48 FF C2 48 39 C6 74 EF 29 C6 89 F0 C3 }
	condition:
		$pattern
}

rule a64l_a5ec87007c3c0c05361fdb0661395f7e {
	meta:
		aliases = "a64l"
		size = "55"
		objfiles = "a64l@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8D 77 06 31 C9 31 D2 0F BE 07 83 E8 2E 83 F8 4C 77 20 89 C0 0F BE 80 ?? ?? ?? ?? 83 F8 40 74 12 D3 E0 48 FF C7 48 09 C2 48 39 F7 74 05 83 C1 06 EB D5 48 89 D0 C3 }
	condition:
		$pattern
}

rule __register_frame_info_table_ba_ed13f263efe1a6e9b78ea1fb3c2af23a {
	meta:
		aliases = "__register_frame_info_table_bases"
		size = "56"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) C7 46 20 00 00 00 00 80 4E 20 02 66 81 4E 20 F8 07 48 8B 05 ?? ?? ?? ?? 48 89 7E 18 48 C7 06 FF FF FF FF 48 89 56 08 48 89 46 28 48 89 4E 10 48 89 35 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule clone_fab03f1ef3b437887ae65b2b9109b701 {
	meta:
		aliases = "clone"
		size = "83"
		objfiles = "clone@libc.a"
	strings:
		$pattern = { ( CC | 48 ) C7 C0 EA FF FF FF 48 85 FF 0F 84 ?? ?? ?? ?? 48 85 F6 0F 84 ?? ?? ?? ?? 48 83 EE 10 48 89 4E 08 48 89 3E 48 89 D7 4C 89 C2 4D 89 C8 4C 8B 54 24 08 B8 38 00 00 00 0F 05 48 85 C0 0F 8C ?? ?? ?? ?? 74 01 C3 31 ED 58 5F FF D0 48 89 C7 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule setjmp_0c068205abd15f5740fa61e5be775265 {
	meta:
		aliases = "setjmp"
		size = "12"
		objfiles = "bsd_setjmp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) C7 C6 01 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_memccpy_3956e9bff5cbf475aff5f81bf03be7d8 {
	meta:
		aliases = "memccpy, __GI_memccpy"
		size = "32"
		objfiles = "memccpy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) FF C9 48 83 F9 FF 74 10 8A 06 88 07 48 FF C7 38 D0 74 08 48 FF C6 EB E7 31 C0 C3 48 89 F8 C3 }
	condition:
		$pattern
}

rule wcsrtombs_a71c9ad1c4e7d821fd1c5db72704c168 {
	meta:
		aliases = "__GI_wcsrtombs, wcsrtombs"
		size = "15"
		objfiles = "wcsrtombs@libc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 C8 48 89 D1 48 83 CA FF E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule byte_compile_range_372f81427f8643531f296c4b92ef9ca0 {
	meta:
		aliases = "byte_compile_range"
		size = "163"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 CB 4C 89 C1 4C 8B 06 41 BA 0B 00 00 00 49 39 D0 0F 84 87 00 00 00 81 E1 00 00 01 00 49 8D 40 01 48 83 F9 01 45 19 D2 48 89 06 41 F7 D2 41 83 E2 0B 4D 85 DB 74 14 40 0F B6 C7 41 0F BE 3C 03 41 0F B6 00 45 0F B6 04 03 EB 4E 45 0F B6 00 EB 48 4D 85 DB 40 0F B6 C7 74 09 40 0F B6 C7 41 0F B6 04 03 BA 08 00 00 00 89 D1 99 F7 F9 4D 85 DB 89 F9 48 63 F0 41 8A 14 31 74 09 40 0F B6 C7 41 0F B6 0C 03 83 E1 07 B8 01 00 00 00 FF C7 D3 E0 45 31 D2 09 C2 41 88 14 31 44 39 C7 76 B3 44 89 D0 C3 }
	condition:
		$pattern
}

rule sync_file_range_65fa21aacb762d3ec0e104fe321ca062 {
	meta:
		aliases = "sync_file_range"
		size = "68"
		objfiles = "sync_file_range@libc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 D0 49 89 D2 48 89 F2 53 41 89 C9 49 C1 F8 20 41 83 E2 FF 48 C1 FA 20 83 E6 FF 48 63 FF B8 15 01 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule sigorset_5a1b4f6c8c373d8ef8b86f78b78dec0b {
	meta:
		aliases = "sigorset"
		size = "32"
		objfiles = "sigorset@libc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 D0 B9 10 00 00 00 EB 0F 48 63 D1 49 8B 04 D0 48 0B 04 D6 48 89 04 D7 FF C9 79 ED 31 C0 C3 }
	condition:
		$pattern
}

rule sigandset_a4b19d66704a7bcd6f171664e61e28a9 {
	meta:
		aliases = "sigandset"
		size = "32"
		objfiles = "sigandset@libc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 D0 B9 10 00 00 00 EB 0F 48 63 D1 49 8B 04 D0 48 23 04 D6 48 89 04 D7 FF C9 79 ED 31 C0 C3 }
	condition:
		$pattern
}

rule __GI_memchr_d35910629fa8c09f8e52b50cfdacc7fb {
	meta:
		aliases = "memchr, __GI_memchr"
		size = "240"
		objfiles = "memchr@libc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 D0 EB 0F 40 38 37 75 04 48 89 F8 C3 49 FF C8 48 FF C7 4D 85 C0 74 06 40 F6 C7 07 75 E6 40 0F B6 C6 48 89 F9 89 C2 C1 E2 08 09 D0 48 98 48 89 C2 48 C1 E2 10 48 09 C2 48 89 D7 48 C1 E7 20 48 09 D7 E9 85 00 00 00 48 89 F8 48 33 01 48 BA FF FE FE FE FE FE FE 7E 48 83 C1 08 48 8D 14 10 48 F7 D0 48 31 C2 48 B8 00 01 01 01 01 01 01 81 48 85 D0 74 54 40 38 71 F8 48 8D 41 F8 74 70 40 38 71 F9 48 8D 50 01 74 32 40 38 71 FA 48 8D 50 02 74 28 40 38 71 FB 48 8D 50 03 74 1E 40 38 71 FC 48 8D 50 04 74 14 40 38 71 FD 48 8D 50 05 74 0A 40 38 71 FE 48 8D 50 06 75 04 48 89 D0 C3 48 83 C0 07 40 38 71 FF 74 }
	condition:
		$pattern
}

rule byte_insert_op1_026bdf0dbf5a0581fa355a5dc7575653 {
	meta:
		aliases = "byte_insert_op1"
		size = "29"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 F0 48 89 CE 48 8D 49 03 EB 0A 48 FF CE 48 FF C9 8A 06 88 01 4C 39 C6 75 F1 EB C0 }
	condition:
		$pattern
}

rule __addvti3_517dc0fa4a398e4508f0d7e325ec0723 {
	meta:
		aliases = "__addvti3"
		size = "82"
		objfiles = "_addvdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 F1 48 89 FE 48 83 EC 08 49 89 F8 48 01 D6 4C 89 CF 48 11 CF 48 85 C9 78 17 49 39 F9 7E 05 E8 ?? ?? ?? ?? 7D 1D 48 89 F0 48 89 FA 48 83 C4 08 C3 49 39 F9 7C E9 7F EE 49 39 F0 66 66 66 90 73 E5 EB DC 49 39 F0 77 D7 66 66 66 90 66 66 90 EB D5 }
	condition:
		$pattern
}

rule __subvti3_832657e4878ac2b8624c394728dad000 {
	meta:
		aliases = "__subvti3"
		size = "82"
		objfiles = "_subvdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 F1 48 89 FE 48 83 EC 08 49 89 F8 48 29 D6 4C 89 CF 48 19 CF 48 85 C9 78 17 49 39 F9 7D 05 E8 ?? ?? ?? ?? 7E 1D 48 89 F0 48 89 FA 48 83 C4 08 C3 49 39 F9 7F E9 7C EE 49 39 F0 66 66 66 90 76 E5 EB DC 49 39 F0 72 D7 66 66 66 90 66 66 90 EB D5 }
	condition:
		$pattern
}

rule byte_insert_op2_bfd854e9a1d920faeaf5c11d84d2b781 {
	meta:
		aliases = "byte_insert_op2"
		size = "30"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 F1 4C 89 C6 4D 8D 40 05 EB 0B 48 FF CE 49 FF C8 8A 06 41 88 00 4C 39 CE 75 F0 EB AF }
	condition:
		$pattern
}

rule __popcountti2_c19fd09248587f6923c1cda6bf4e53e3 {
	meta:
		aliases = "__popcountti2"
		size = "67"
		objfiles = "_popcountdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 F8 48 8B 3D ?? ?? ?? ?? 53 49 89 F1 31 C9 31 F6 4C 89 C0 4C 89 CA 4C 0F AD C8 48 D3 EA F6 C1 40 48 0F 45 C2 48 83 C1 08 25 FF 00 00 00 0F B6 04 07 48 01 C6 48 81 F9 80 00 00 00 75 D3 5B 89 F0 C3 }
	condition:
		$pattern
}

rule _authenticate_b963dee91a146dde35d47bdc9b47b3fc {
	meta:
		aliases = "__GI__authenticate, _authenticate"
		size = "80"
		objfiles = "svc_auth@libc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 F8 49 89 F1 48 8D 7F 18 48 8D 76 30 B9 06 00 00 00 49 8B 50 38 FC F3 A5 8B 05 ?? ?? ?? ?? 89 42 28 49 8B 40 38 C7 40 38 00 00 00 00 41 8B 40 18 83 F8 03 77 13 48 98 4C 89 CE 4C 89 C7 4C 8B 1C C5 ?? ?? ?? ?? 41 FF E3 B8 02 00 00 00 C3 }
	condition:
		$pattern
}

rule strcasestr_242bf951dda571d61b3f57d148823b71 {
	meta:
		aliases = "__GI_strcasestr, strcasestr"
		size = "70"
		objfiles = "strcasestr@libc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 F9 49 89 F0 41 8A 00 84 C0 74 35 45 8A 11 44 38 D0 74 19 41 0F B6 08 48 8B 15 ?? ?? ?? ?? 41 0F B6 C2 66 8B 04 42 66 3B 04 4A 75 08 49 FF C0 49 FF C1 EB D0 45 84 D2 74 05 48 FF C7 EB C0 31 FF 48 89 F8 C3 }
	condition:
		$pattern
}

rule signalfd_22540706093727f499671010d08d9aca {
	meta:
		aliases = "signalfd"
		size = "49"
		objfiles = "signalfd@libc.a"
	strings:
		$pattern = { ( CC | 4C ) 63 D2 53 BA 08 00 00 00 48 63 FF B8 21 01 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __gcc_personality_sj0_b7e2a1ad15e13f0b62b4d4802574029a {
	meta:
		aliases = "__gcc_personality_sj0"
		size = "539"
		objfiles = "unwind_c@libgcc.a"
	strings:
		$pattern = { ( CC | 4C ) 89 64 24 E0 4C 89 7C 24 F8 4D 89 C4 48 89 5C 24 D0 48 89 6C 24 D8 49 89 CF 4C 89 6C 24 E8 4C 89 74 24 F0 48 83 EC 48 FF CF B8 03 00 00 00 74 23 48 8B 5C 24 18 48 8B 6C 24 20 4C 8B 64 24 28 4C 8B 6C 24 30 4C 8B 74 24 38 4C 8B 7C 24 40 48 83 C4 48 C3 83 E6 02 75 07 B8 08 00 00 00 EB D1 4C 89 C7 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 E9 4D 85 E4 74 08 4C 89 E7 E8 ?? ?? ?? ?? 0F B6 03 48 8D 6B 01 3C FF 74 5C 89 C3 0F 84 F2 00 00 00 44 0F B6 E8 44 89 E8 83 E0 70 83 F8 20 0F 84 4D 01 00 00 0F 8F DE 00 00 00 85 C0 74 09 83 F8 10 0F 85 CC 00 00 00 80 FB 50 0F 84 3E 01 00 00 44 89 E8 83 E0 0F 83 F8 0C }
	condition:
		$pattern
}

rule __modti3_91611985720ac0fa878c0ce2f48db143 {
	meta:
		aliases = "__modti3"
		size = "1708"
		objfiles = "_moddi3@libgcc.a"
	strings:
		$pattern = { ( CC | 4C ) 89 7C 24 F8 48 89 5C 24 D0 48 89 6C 24 D8 4C 89 64 24 E0 4C 89 6C 24 E8 4C 89 74 24 F0 48 83 EC 50 48 89 74 24 10 48 83 7C 24 10 00 48 89 7C 24 08 48 89 54 24 F8 48 89 0C 24 48 C7 44 24 B0 00 00 00 00 0F 88 FA 02 00 00 48 83 3C 24 00 0F 88 DC 02 00 00 48 8B 54 24 10 48 8B 44 24 08 4C 8D 7C 24 E8 48 89 54 24 E0 48 8B 14 24 48 89 44 24 D8 48 8B 44 24 F8 4C 8B 54 24 D8 4C 8B 44 24 E0 48 89 54 24 D0 48 8B 74 24 D0 48 89 44 24 C8 48 8B 7C 24 C8 48 85 F6 0F 85 F2 00 00 00 4C 39 C7 0F 86 D9 01 00 00 B9 38 00 00 00 66 66 66 90 48 89 FA 48 D3 EA 84 D2 75 09 48 83 E9 08 75 F0 48 89 FA 48 8B 05 ?? ?? }
	condition:
		$pattern
}

rule strncasecmp_772d337f7581bd0d6368ce4e3ed67ba8 {
	meta:
		aliases = "__GI_strncasecmp, strncasecmp"
		size = "61"
		objfiles = "strncasecmp@libc.a"
	strings:
		$pattern = { ( CC | 4C ) 8B 05 ?? ?? ?? ?? 48 89 D1 31 C0 48 85 C9 74 2B 48 39 F7 74 16 0F B6 07 41 0F BF 14 40 0F B6 06 41 0F BF 04 40 29 C2 89 D0 75 10 80 3F 00 74 0B 48 FF C9 48 FF C6 48 FF C7 EB D0 C3 }
	condition:
		$pattern
}

rule __mulxc3_269c5997fe7f076bd4725eb7129fa40b {
	meta:
		aliases = "__mulxc3"
		size = "1463"
		objfiles = "_mulxc3@libgcc.a"
	strings:
		$pattern = { ( CC | 4C ) 8B 54 24 08 44 8B 5C 24 10 48 89 5C 24 E0 48 8B 4C 24 28 8B 5C 24 30 4C 8B 44 24 18 4C 89 54 24 C8 44 89 5C 24 D0 DB 6C 24 C8 48 89 4C 24 C8 89 5C 24 D0 44 8B 4C 24 20 48 8B 74 24 38 8B 7C 24 40 48 89 6C 24 E8 4C 89 64 24 F0 4C 89 6C 24 F8 DB 6C 24 C8 4C 89 44 24 C8 44 89 4C 24 D0 DC C9 DB 6C 24 C8 48 89 74 24 C8 89 7C 24 D0 DB 6C 24 C8 4C 89 54 24 C8 44 89 5C 24 D0 DC C9 DB 6C 24 C8 4C 89 44 24 C8 44 89 4C 24 D0 DE C9 DB 6C 24 C8 DE CB D9 C3 D8 E2 D9 C1 D8 C4 D9 C9 DB E8 7A 1F 75 1D DD DC DD DC DF C0 DF C0 48 8B 5C 24 E0 48 8B 6C 24 E8 4C 8B 64 24 F0 4C 8B 6C 24 F8 C3 D9 C9 DB E8 7A 0C 75 }
	condition:
		$pattern
}

rule __divxc3_46e762761bc39f3ad7855a0281302e06 {
	meta:
		aliases = "__divxc3"
		size = "1189"
		objfiles = "_divxc3@libgcc.a"
	strings:
		$pattern = { ( CC | 4C ) 8B 54 24 28 44 8B 5C 24 30 48 8B 74 24 38 8B 7C 24 40 48 89 5C 24 E8 48 89 6C 24 F0 4C 89 54 24 D8 44 89 5C 24 E0 DB 6C 24 D8 48 89 74 24 D8 89 7C 24 E0 4C 89 64 24 F8 4C 8B 44 24 08 44 8B 4C 24 10 48 8B 4C 24 18 8B 5C 24 20 D9 E1 DB 6C 24 D8 D9 E1 DF E9 DF C0 0F 86 97 00 00 00 4C 89 54 24 D8 44 89 5C 24 E0 DB 6C 24 D8 48 89 74 24 D8 89 7C 24 E0 DB 6C 24 D8 4C 89 54 24 D8 44 89 5C 24 E0 DE F9 DB 6C 24 D8 48 89 74 24 D8 89 7C 24 E0 D8 C9 DB 6C 24 D8 4C 89 44 24 D8 44 89 4C 24 E0 DE C1 DB 6C 24 D8 48 89 4C 24 D8 89 5C 24 E0 D8 CA DB 6C 24 D8 4C 89 44 24 D8 44 89 4C 24 E0 DC C1 D9 C9 D8 F2 D9 }
	condition:
		$pattern
}

rule asinh_0df07a24489b436be5b4cf44b90b00f7 {
	meta:
		aliases = "__GI_asinh, asinh"
		size = "317"
		objfiles = "s_asinh@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 0F 28 C8 48 83 EC 30 F2 0F 11 44 24 08 48 8B 54 24 08 48 89 D3 48 C1 EB 20 89 D8 25 FF FF FF 7F 3D FF FF EF 7F 7E 09 F2 0F 58 C8 E9 03 01 00 00 3D FF FF 2F 3E 7F 16 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 0F 87 E6 00 00 00 3D 00 00 B0 41 7E 1A 0F 28 C1 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? F2 0F 58 05 ?? ?? ?? ?? E9 B6 00 00 00 0F 28 C1 3D 00 00 00 40 F2 0F 59 C1 F2 0F 11 44 24 20 7E 4C 0F 28 C1 E8 ?? ?? ?? ?? 0F 28 C8 66 0F 12 44 24 20 F2 0F 58 05 ?? ?? ?? ?? F2 0F 11 4C 24 10 E8 ?? ?? ?? ?? 66 0F 12 4C 24 10 0F 28 D1 F2 0F 58 D1 F2 0F 58 C8 66 0F 12 05 ?? ?? ?? ?? F2 0F 5E C1 F2 0F 58 C2 }
	condition:
		$pattern
}

rule __ieee754_sinh_05cf06be0b0bc2b64a902a3e2897b7a0 {
	meta:
		aliases = "__ieee754_sinh"
		size = "318"
		objfiles = "e_sinh@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 0F 28 D0 48 83 EC 10 F2 0F 11 04 24 48 8B 14 24 48 C1 EA 20 89 D3 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 09 F2 0F 58 D0 E9 09 01 00 00 FF C2 B8 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 0F 4E C2 81 FB FF FF 35 40 66 0F 12 00 F2 0F 11 44 24 08 7F 74 81 FB FF FF 2F 3E 7F 19 0F 28 C2 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 0F 87 C6 00 00 00 0F 28 C2 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 FB FF FF EF 3F 0F 28 C8 66 0F 12 1D ?? ?? ?? ?? 7F 19 0F 28 D0 F2 0F 58 D0 F2 0F 59 C1 F2 0F 58 CB F2 0F 5E C1 F2 0F 5C D0 EB 12 0F 28 C3 0F 28 D1 F2 0F 58 C1 F2 0F 5E D0 F2 0F 58 D1 F2 0F 59 54 24 08 EB 73 81 FB 41 2E }
	condition:
		$pattern
}

rule __ieee754_cosh_4d8d8bbab15f21bdffd399e96538dff9 {
	meta:
		aliases = "__ieee754_cosh"
		size = "279"
		objfiles = "e_cosh@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 0F 28 D0 48 83 EC 10 F2 0F 11 44 24 08 48 8B 54 24 08 48 89 D0 48 C1 E8 20 89 C3 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 0F 8F D0 00 00 00 81 FB 42 2E D6 3F 7F 36 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F 12 0D ?? ?? ?? ?? 0F 28 D0 81 FB FF FF 7F 3C F2 0F 58 D1 0F 8E B5 00 00 00 F2 0F 58 D2 F2 0F 59 C0 F2 0F 5E C2 0F 28 D0 EB 25 81 FB FF FF 35 40 7F 23 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 0F 12 0D ?? ?? ?? ?? 0F 28 D0 F2 0F 59 D1 F2 0F 5E C8 F2 0F 58 D1 EB 79 81 FB 41 2E 86 40 7F 17 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 28 D0 F2 0F 59 15 ?? ?? ?? ?? EB 5A F2 0F 11 44 24 08 48 8B 54 24 08 81 FB CD 33 86 40 48 }
	condition:
		$pattern
}

rule __ieee754_exp_61c1cfd3333dbd7f54f7a1a32eaba76b {
	meta:
		aliases = "__ieee754_exp"
		size = "574"
		objfiles = "e_exp@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 0F 28 D0 F2 0F 11 44 24 F8 48 8B 54 24 F8 48 C1 EA 20 89 D0 89 D1 25 FF FF FF 7F C1 E9 1F 3D 41 2E 86 40 76 58 3D FF FF EF 7F 76 22 48 8B 5C 24 F8 81 E2 FF FF 0F 00 09 DA 74 09 F2 0F 58 D0 E9 F4 01 00 00 85 C9 0F 84 EC 01 00 00 EB 27 66 0F 2E 05 ?? ?? ?? ?? 76 11 66 0F 12 15 ?? ?? ?? ?? F2 0F 59 D2 E9 CF 01 00 00 66 0F 2E 05 ?? ?? ?? ?? 73 0A 7A 08 0F 57 D2 E9 BB 01 00 00 3D 42 2E D6 3F 76 6C 3D B1 A2 F0 3F 48 63 C1 77 20 0F 28 EA 66 0F 12 24 C5 ?? ?? ?? ?? F2 0F 5C 2C C5 ?? ?? ?? ?? 89 C8 F7 D8 29 C8 8D 48 01 EB 39 0F 28 C2 0F 28 EA F2 0F 59 05 ?? ?? ?? ?? F2 0F 58 04 C5 ?? ?? ?? ?? F2 0F }
	condition:
		$pattern
}

rule __GI_expm1_663e31e549a70fa2016c825aca7a9601 {
	meta:
		aliases = "expm1, __GI_expm1"
		size = "833"
		objfiles = "s_expm1@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 0F 28 D8 F2 0F 11 44 24 F8 48 8B 54 24 F8 48 C1 EA 20 89 D0 89 D1 25 FF FF FF 7F 81 E1 00 00 00 80 3D 79 68 43 40 76 73 3D 41 2E 86 40 76 44 3D FF FF EF 7F 76 22 48 8B 5C 24 F8 81 E2 FF FF 0F 00 09 DA 74 09 F2 0F 58 D8 E9 ED 02 00 00 85 C9 0F 84 E5 02 00 00 EB 36 66 0F 2E 05 ?? ?? ?? ?? 76 11 66 0F 12 1D ?? ?? ?? ?? F2 0F 59 DB E9 C8 02 00 00 85 C9 74 24 0F 28 C3 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 73 0F 7A 0D 66 0F 12 1D ?? ?? ?? ?? E9 A0 02 00 00 3D 42 2E D6 3F 0F 86 90 00 00 00 3D B1 A2 F0 3F 77 33 85 C9 66 0F 12 05 ?? ?? ?? ?? 75 13 0F 28 CB B1 01 F2 0F 5C C8 66 0F 12 05 ?? }
	condition:
		$pattern
}

rule __GI_mknod_3d35187dfd24f7b13da2d86b6ad6c9cd {
	meta:
		aliases = "mknod, __GI_mknod"
		size = "43"
		objfiles = "mknod@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 0F B7 D2 89 F6 B8 85 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule ustat_43a1c9d30b1d5f12aa357bca71475b01 {
	meta:
		aliases = "ustat"
		size = "41"
		objfiles = "ustat@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 0F B7 FF B8 88 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __libc_open_191fe39647f58a54091c51d5070b3ee4 {
	meta:
		aliases = "open, __GI___libc_open, __GI_open, __libc_open"
		size = "106"
		objfiles = "open@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 31 C0 48 81 EC D0 00 00 00 40 F6 C6 40 48 89 54 24 30 74 24 48 8D 84 24 E0 00 00 00 C7 04 24 18 00 00 00 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 48 83 C0 10 8B 00 89 C2 48 63 F6 B8 02 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 48 81 C4 D0 00 00 00 5B C3 }
	condition:
		$pattern
}

rule __stdio_READ_fc5c6cdebc27258e07b86d5fe0bc83a0 {
	meta:
		aliases = "__stdio_READ"
		size = "58"
		objfiles = "_READ@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 31 C0 F6 07 04 48 89 FB 75 2D 8B 7F 04 48 85 D2 48 B8 FF FF FF FF FF FF FF 7F 48 0F 48 D0 E8 ?? ?? ?? ?? 48 83 F8 00 7F 0E 75 06 66 83 0B 04 EB 06 66 83 0B 08 31 C0 5B C3 }
	condition:
		$pattern
}

rule __GI_ether_aton_r_d0e42ab205fbb408f00af635bea7d2a0 {
	meta:
		aliases = "ether_aton_r, __GI_ether_aton_r"
		size = "233"
		objfiles = "ether_addr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 31 DB E9 CE 00 00 00 48 0F BE 07 4C 8B 15 ?? ?? ?? ?? 41 8A 0C 42 8D 41 D0 3C 09 8D 41 9F 0F 97 C2 3C 05 0F 97 C0 84 D0 0F 85 B3 00 00 00 4C 8B 0D ?? ?? ?? ?? 0F BE C1 48 0F BE D1 44 8D 40 D0 83 E8 57 4C 8D 5F 01 41 F6 04 51 08 44 0F 44 C0 48 0F BE 47 01 48 83 FB 04 41 8A 0C 42 41 0F 96 C2 80 F9 3A 0F 95 C0 44 84 D0 75 1B 48 83 FB 05 0F 94 C2 84 C9 0F 95 C0 84 D0 74 4E 48 0F BE C1 41 F6 04 41 20 75 43 8D 41 D0 3C 09 8D 41 9F 0F 97 C2 3C 05 0F 97 C0 84 D0 75 46 48 0F BE C1 0F BE D1 4C 8D 5F 02 8D 4A D0 83 EA 57 41 F6 04 41 08 0F 44 CA 80 7F 02 3A 0F 95 C0 44 84 D0 75 21 44 89 C0 C1 E0 04 44 }
	condition:
		$pattern
}

rule gethostid_e0833e6c51cc9a5d0d958c27af737482 {
	meta:
		aliases = "gethostid"
		size = "215"
		objfiles = "hostid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 31 F6 31 C0 BF ?? ?? ?? ?? 48 81 EC 10 02 00 00 E8 ?? ?? ?? ?? 85 C0 89 C3 78 34 48 8D B4 24 0C 02 00 00 BA 04 00 00 00 89 C7 E8 ?? ?? ?? ?? 48 85 C0 74 14 89 DF E8 ?? ?? ?? ?? 48 63 84 24 0C 02 00 00 E9 85 00 00 00 89 DF E8 ?? ?? ?? ?? 48 8D 9C 24 80 01 00 00 BE 40 00 00 00 48 89 DF E8 ?? ?? ?? ?? 85 C0 78 63 80 BC 24 80 01 00 00 00 74 59 48 8D B4 24 D0 01 00 00 4C 8D 8C 24 08 02 00 00 4C 8D 84 24 F8 01 00 00 48 89 E2 B9 74 01 00 00 48 89 DF E8 ?? ?? ?? ?? 48 8B 84 24 F8 01 00 00 48 85 C0 74 24 48 63 50 14 48 8B 40 18 48 8D BC 24 00 02 00 00 48 8B 30 E8 ?? ?? ?? ?? 8B 84 24 00 02 00 00 C1 }
	condition:
		$pattern
}

rule __pthread_kill_other_threads_n_cb8ce2760dcc0597bc952385ef2e16c8 {
	meta:
		aliases = "pthread_kill_other_threads_np, __pthread_kill_other_threads_np"
		size = "112"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 31 F6 31 FF 48 81 EC A0 00 00 00 E8 D2 FE FF FF E8 ?? ?? ?? ?? 48 8D 7C 24 08 E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 31 D2 48 89 E6 C7 84 24 88 00 00 00 00 00 00 00 48 C7 04 24 00 00 00 00 E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 31 D2 48 89 E6 E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 85 FF 7E 0A 31 D2 48 89 E6 E8 ?? ?? ?? ?? 48 81 C4 A0 00 00 00 5B C3 }
	condition:
		$pattern
}

rule nice_76718a248557134d79490ddfbc9a9a27 {
	meta:
		aliases = "nice"
		size = "79"
		objfiles = "nice@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 31 F6 89 FB 31 FF E8 ?? ?? ?? ?? 85 DB 8D 14 18 79 0B 39 C2 7E 11 BA 00 00 00 80 EB 0A 39 C2 B8 FF FF FF 7F 0F 4C D0 31 F6 31 FF E8 ?? ?? ?? ?? 85 C0 75 0A 5B 31 F6 31 FF E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 01 00 00 00 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule umount_9f6f5b3581c8d86fc5bd2e1aaca90f7c {
	meta:
		aliases = "umount"
		size = "40"
		objfiles = "umount@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 31 F6 B8 A6 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule tee_dba89899e0960ee74d44427b10c12502 {
	meta:
		aliases = "tee"
		size = "48"
		objfiles = "tee@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 41 89 CA 48 63 F6 48 63 FF B8 14 01 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_vmsplice_851eba89c9ff19aa5c66e93480494d3c {
	meta:
		aliases = "vmsplice, __GI_vmsplice"
		size = "45"
		objfiles = "vmsplice@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 41 89 CA 48 63 FF B8 16 01 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule ioctl_c581ede6942b702024a9d00e5514dc35 {
	meta:
		aliases = "__GI_ioctl, ioctl"
		size = "104"
		objfiles = "ioctl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 41 B8 10 00 00 00 48 63 F6 48 63 FF 48 81 EC D0 00 00 00 48 8D 84 24 E0 00 00 00 48 89 54 24 30 C7 04 24 18 00 00 00 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 48 83 C0 10 48 8B 10 44 89 C0 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 48 81 C4 D0 00 00 00 5B C3 }
	condition:
		$pattern
}

rule __register_frame_1ea13d3c795eb4caa886d90a6fbcd596 {
	meta:
		aliases = "__register_frame"
		size = "38"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 53 ) 44 8B 17 48 89 FB 45 85 D2 75 04 5B C3 66 90 BF 30 00 00 00 E8 ?? ?? ?? ?? 48 89 DF 48 89 C6 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mq_send_f1ae0eb4af2f188cea53d7f08429d905 {
	meta:
		aliases = "mq_send"
		size = "47"
		objfiles = "mq_send@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 45 31 C0 41 89 CA 48 63 FF B8 F2 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule mq_receive_471e0df798a5f16ff9e6b93ca1c6449e {
	meta:
		aliases = "mq_receive"
		size = "48"
		objfiles = "mq_receive@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 45 31 C0 49 89 CA 48 63 FF B8 F3 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 63 C3 5B C3 }
	condition:
		$pattern
}

rule setsockopt_2687ad771a22bfa70cdf9508dc421b4a {
	meta:
		aliases = "__GI_setsockopt, setsockopt"
		size = "53"
		objfiles = "setsockopt@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 45 89 C0 49 89 CA 48 63 D2 48 63 F6 48 63 FF B8 36 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_splice_6c09b5be13ebb514a7f9d0fca4964981 {
	meta:
		aliases = "splice, __GI_splice"
		size = "51"
		objfiles = "splice@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 45 89 C9 49 89 CA 48 63 D2 48 63 FF B8 13 01 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule __libc_sendto_72e74dc88aebe37f3d166d561afb55b3 {
	meta:
		aliases = "sendto, __GI_sendto, __libc_sendto"
		size = "48"
		objfiles = "sendto@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 45 89 C9 4C 63 D1 48 63 FF B8 2C 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule semctl_d82648993b42815c56772d7c1e32dc9a {
	meta:
		aliases = "semctl"
		size = "103"
		objfiles = "semctl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 F6 48 63 FF 48 81 EC D0 00 00 00 48 8D 84 24 E0 00 00 00 48 89 4C 24 38 C7 04 24 20 00 00 00 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 48 83 C0 18 4C 8B 10 B8 42 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 48 81 C4 D0 00 00 00 5B C3 }
	condition:
		$pattern
}

rule socket_125716247ac6605ab298d82f830216b1 {
	meta:
		aliases = "__GI_socket, socket"
		size = "47"
		objfiles = "socket@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 F6 48 63 FF B8 29 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule semget_36c447ee5c0362b5ebc8dcb49c7324c1 {
	meta:
		aliases = "semget"
		size = "47"
		objfiles = "semget@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 F6 48 63 FF B8 40 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI___libc_lseek_1ec563b9d349b6d0974e33d4cb38a869 {
	meta:
		aliases = "__GI_lseek, __libc_lseek, lseek, __GI___libc_lseek"
		size = "45"
		objfiles = "lseek@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 FF B8 08 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule __libc_readv_d005ab35268a3de9f4d49f547d43d873 {
	meta:
		aliases = "readv, __libc_readv"
		size = "45"
		objfiles = "readv@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 FF B8 13 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule __libc_writev_b127f7546d2af52ff74f248b4909d59e {
	meta:
		aliases = "writev, __libc_writev"
		size = "45"
		objfiles = "writev@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 FF B8 14 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule shmget_7272684c23c9782748f0e7fabad26fa5 {
	meta:
		aliases = "shmget"
		size = "44"
		objfiles = "shmget@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 FF B8 1D 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule shmat_103845211af1cd9e8b7381bdc283afae {
	meta:
		aliases = "shmat"
		size = "45"
		objfiles = "shmat@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 FF B8 1E 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule __libc_sendmsg_fbf95158da3e194ae52596df7a414050 {
	meta:
		aliases = "sendmsg, __GI_sendmsg, __libc_sendmsg"
		size = "45"
		objfiles = "sendmsg@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 FF B8 2E 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule recvmsg_ad6b29f14306a880b58f464388da2c7e {
	meta:
		aliases = "__libc_recvmsg, __GI_recvmsg, recvmsg"
		size = "45"
		objfiles = "recvmsg@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 FF B8 2F 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule klogctl_a380e92963e0b8f9fbfda65da210654f {
	meta:
		aliases = "klogctl"
		size = "44"
		objfiles = "klogctl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 FF B8 67 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_setpriority_44ea68b9d4c336f1df669fbe619ddc48 {
	meta:
		aliases = "setpriority, __GI_setpriority"
		size = "45"
		objfiles = "setpriority@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 89 F6 89 FF B8 8D 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __libc_poll_e2e4d673cf7b6df9540aa4bceb06c219 {
	meta:
		aliases = "poll, __GI_poll, __libc_poll"
		size = "41"
		objfiles = "poll@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 B8 07 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule mprotect_8d24796a4e1e9c5ac883a94b2d019134 {
	meta:
		aliases = "mprotect"
		size = "41"
		objfiles = "mprotect@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 B8 0A 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __libc_msync_72fa1b75a3c030095bff4debde552b69 {
	meta:
		aliases = "msync, __libc_msync"
		size = "41"
		objfiles = "msync@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 B8 1A 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule madvise_807e9e71163f87dd74455c0dd2d60a55 {
	meta:
		aliases = "madvise"
		size = "41"
		objfiles = "madvise@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 B8 1C 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule ioperm_cff3906ef07e12597db2841d2fb22b3d {
	meta:
		aliases = "ioperm"
		size = "41"
		objfiles = "ioperm@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 B8 AD 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI___libc_fcntl_67c3ecc77d3ef4d4bcac028181e2197e {
	meta:
		aliases = "fcntl, __GI_fcntl64, __libc_fcntl64, fcntl64, __GI_fcntl, __libc_fcntl, __GI___libc_fcntl"
		size = "100"
		objfiles = "__syscall_fcntl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 48 63 FF 48 81 EC D0 00 00 00 48 8D 84 24 E0 00 00 00 48 89 54 24 30 C7 04 24 18 00 00 00 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 48 83 C0 10 48 8B 10 B8 48 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 48 81 C4 D0 00 00 00 5B C3 }
	condition:
		$pattern
}

rule shmctl_2b0f12470c489f09a90e634733ec5863 {
	meta:
		aliases = "shmctl"
		size = "44"
		objfiles = "shmctl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 48 63 FF B8 1F 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_dup2_edd20583d7b3929ac91e667bbec1c79a {
	meta:
		aliases = "dup2, __GI_dup2"
		size = "44"
		objfiles = "dup2@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 48 63 FF B8 21 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule shutdown_a875638b81e39bf2c6915e089d9ccee2 {
	meta:
		aliases = "shutdown"
		size = "44"
		objfiles = "shutdown@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 48 63 FF B8 30 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule listen_9bd9d5d6935914ad31013ea7767fe11d {
	meta:
		aliases = "__GI_listen, listen"
		size = "44"
		objfiles = "listen@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 48 63 FF B8 32 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule kill_251bed10069338b67ab7fe51e00475fc {
	meta:
		aliases = "__GI_kill, kill"
		size = "44"
		objfiles = "kill@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 48 63 FF B8 3E 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule msgget_6cdaf27141ae16fd5ea739af1bbfa4db {
	meta:
		aliases = "msgget"
		size = "44"
		objfiles = "msgget@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 48 63 FF B8 44 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule msgctl_4dba53067670f43086788bd3748bf288 {
	meta:
		aliases = "msgctl"
		size = "44"
		objfiles = "msgctl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 48 63 FF B8 47 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule flock_56766d88950333408edcd82dc2c08961 {
	meta:
		aliases = "flock"
		size = "44"
		objfiles = "flock@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 48 63 FF B8 49 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_setpgid_82e9805285ef933b881a005451075fb1 {
	meta:
		aliases = "setpgid, __GI_setpgid"
		size = "44"
		objfiles = "setpgid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 48 63 FF B8 6D 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule sched_setscheduler_486a58fac836759dd54ebe840a4bd57c {
	meta:
		aliases = "sched_setscheduler"
		size = "44"
		objfiles = "sched_setscheduler@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 48 63 FF B8 90 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule access_64a9040aac8c22f6e0c8536147e19e11 {
	meta:
		aliases = "access"
		size = "41"
		objfiles = "access@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 B8 15 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule umount2_19721efe7df961fa41b7abc3e3a30b49 {
	meta:
		aliases = "umount2"
		size = "41"
		objfiles = "umount2@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 B8 A6 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule swapon_317eeaf5eb18150b692c8c0b903bde18 {
	meta:
		aliases = "swapon"
		size = "41"
		objfiles = "swapon@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 B8 A7 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_read_e71aabeec0afc202a527620e7d4a2651 {
	meta:
		aliases = "__libc_read, read, __GI_read"
		size = "39"
		objfiles = "read@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF 31 C0 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule __libc_write_f867541d5bb573f1a0785335e45b1238 {
	meta:
		aliases = "__GI_write, write, __libc_write"
		size = "42"
		objfiles = "write@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 01 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_close_edaf20539e9c2f13a3fdf19621d2cbdb {
	meta:
		aliases = "__libc_close, close, __GI_close"
		size = "41"
		objfiles = "close@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 03 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule dup_77bc0da6af557b89dd07de34d6529e86 {
	meta:
		aliases = "dup"
		size = "41"
		objfiles = "dup@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 20 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule accept_ed43f5518d856e6dafdb44e0fae6b7dd {
	meta:
		aliases = "__GI_accept, __libc_accept, accept"
		size = "41"
		objfiles = "accept@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 2B 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_getsockname_974c4b6199b4d22b1816ee5b1e8ad00c {
	meta:
		aliases = "getsockname, __GI_getsockname"
		size = "41"
		objfiles = "getsockname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 33 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule getpeername_c241b358b649d461ae62f4cd42ef7c3e {
	meta:
		aliases = "getpeername"
		size = "41"
		objfiles = "getpeername@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 34 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule semop_b6506dde45565019cc0433d65619a8e6 {
	meta:
		aliases = "semop"
		size = "41"
		objfiles = "semop@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 41 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule fsync_1b4cc072eccd7f57648bce0ee2e7ba56 {
	meta:
		aliases = "__libc_fsync, fsync"
		size = "41"
		objfiles = "fsync@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 4A 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule fdatasync_8f35a399b7bbabc9e238933e620ecdda {
	meta:
		aliases = "fdatasync"
		size = "41"
		objfiles = "fdatasync@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 4B 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_ftruncate_7238cd3a63a102f0b4dcb3ce1fbdc3b2 {
	meta:
		aliases = "ftruncate, __GI_ftruncate"
		size = "41"
		objfiles = "ftruncate@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 4D 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule fchdir_1cd2841c03ce8761782d13af7ac8e06d {
	meta:
		aliases = "__GI_fchdir, fchdir"
		size = "41"
		objfiles = "fchdir@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 51 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule getrusage_a25dfa8957e3e14cd8ee983137749d0c {
	meta:
		aliases = "getrusage"
		size = "41"
		objfiles = "getrusage@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 62 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_getgroups_e3081267117fd2317758946113d32c83 {
	meta:
		aliases = "getgroups, __GI_getgroups"
		size = "41"
		objfiles = "getgroups@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 73 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule getpgid_bdab1cdfb603fc2cd4867361bcfeb124 {
	meta:
		aliases = "getpgid"
		size = "41"
		objfiles = "getpgid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 79 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_getsid_c7da010f8aeed018ff91cd751525a61a {
	meta:
		aliases = "getsid, __GI_getsid"
		size = "41"
		objfiles = "getsid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 7C 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_fstatfs_53e0a1cd0ffa85d90305c52d009cd2be {
	meta:
		aliases = "__libc_fstatfs, __GI___libc_fstatfs, fstatfs, __GI_fstatfs"
		size = "41"
		objfiles = "fstatfs@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 8A 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule sched_setparam_287e43a03de9ebd38f4937e71f3c5b0a {
	meta:
		aliases = "sched_setparam"
		size = "41"
		objfiles = "sched_setparam@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 8E 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule sched_getparam_ff360f6631df13c2f899b16c58142043 {
	meta:
		aliases = "sched_getparam"
		size = "41"
		objfiles = "sched_getparam@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 8F 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule sched_getscheduler_e98b175a8d888fd15698fb65ec2289bb {
	meta:
		aliases = "sched_getscheduler"
		size = "41"
		objfiles = "sched_getscheduler@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 91 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule sched_get_priority_max_23a18326c01b7d8762c63df8f8714e63 {
	meta:
		aliases = "sched_get_priority_max"
		size = "41"
		objfiles = "sched_get_priority_max@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 92 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule sched_get_priority_min_dcd1c1f9ee45aa34956f6fdca005970e {
	meta:
		aliases = "sched_get_priority_min"
		size = "41"
		objfiles = "sched_get_priority_min@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 93 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule sched_rr_get_interval_22acdc576f51639dac943c7803755885 {
	meta:
		aliases = "sched_rr_get_interval"
		size = "41"
		objfiles = "sched_rr_get_interval@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 94 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule mlockall_2320ecf3e3d2385663e7dc6136e178e9 {
	meta:
		aliases = "mlockall"
		size = "41"
		objfiles = "mlockall@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 97 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule modify_ldt_184d300940e0c4f1081ac23ab433d062 {
	meta:
		aliases = "modify_ldt"
		size = "41"
		objfiles = "modify_ldt@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 9A 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule arch_prctl_4986c510566fe2b5f60afad638adbb59 {
	meta:
		aliases = "arch_prctl"
		size = "41"
		objfiles = "arch_prctl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 9E 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule iopl_8f269431abc59acf55ec5d079a53732d {
	meta:
		aliases = "iopl"
		size = "41"
		objfiles = "iopl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 AC 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule readahead_15f6c2d54ccb2f84cd47c89b9988bb9b {
	meta:
		aliases = "readahead"
		size = "42"
		objfiles = "readahead@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 BB 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule flistxattr_fef781006f688e5cbe817f4dc0348da6 {
	meta:
		aliases = "flistxattr"
		size = "42"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 C4 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule fremovexattr_d76b50bf4d73524bc70e45490ca8a6fd {
	meta:
		aliases = "fremovexattr"
		size = "41"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 C7 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule epoll_create_5ef5ccf1a3aba3d3b9629e52ad5d8c06 {
	meta:
		aliases = "epoll_create"
		size = "41"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 D5 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule clock_settime_6dd8de32f4f41fdcb3e05496de2f7c89 {
	meta:
		aliases = "clock_settime"
		size = "41"
		objfiles = "clock_settime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 E3 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule clock_gettime_b1ff2d78fade4dc13306288e90a53911 {
	meta:
		aliases = "clock_gettime"
		size = "41"
		objfiles = "clock_gettime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 E4 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_clock_getres_441c3d047e282c6bfd04e1087ae45ddd {
	meta:
		aliases = "clock_getres, __GI_clock_getres"
		size = "41"
		objfiles = "clock_getres@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 E5 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule mq_setattr_b8395fa812b25f337a0643a8a2d81ed6 {
	meta:
		aliases = "__GI_mq_setattr, mq_setattr"
		size = "41"
		objfiles = "mq_getsetattr@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 F5 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __pthread_timedsuspend_new_94919b9b163f16b39e9f4411343fa73c {
	meta:
		aliases = "__pthread_timedsuspend_new"
		size = "290"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 48 81 EC 00 02 00 00 48 89 7C 24 08 48 89 34 24 48 8D 7C 24 10 BE 01 00 00 00 E8 ?? ?? ?? ?? 85 C0 BA 01 00 00 00 0F 85 DD 00 00 00 48 8B 54 24 08 48 8D 9C 24 60 01 00 00 48 8D 44 24 10 48 89 DF 48 89 42 40 C7 42 38 00 00 00 00 E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8D 94 24 E0 00 00 00 48 89 DE BF 01 00 00 00 E8 ?? ?? ?? ?? 48 8D BC 24 F0 01 00 00 31 F6 E8 ?? ?? ?? ?? 48 69 84 24 F8 01 00 00 E8 03 00 00 48 8B 0C 24 48 8B 51 08 48 8B 09 48 2B 8C 24 F0 01 00 00 48 29 C2 48 85 D2 48 89 94 24 E8 01 00 00 48 89 8C 24 E0 01 00 00 79 1B 48 8D 82 00 CA 9A 3B 48 89 84 24 E8 01 }
	condition:
		$pattern
}

rule _dl_map_cache_3b6627183fc5cad83bff3399ff353d93 {
	meta:
		aliases = "_dl_map_cache"
		size = "549"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 53 ) 48 81 EC 90 00 00 00 48 8B 15 ?? ?? ?? ?? 48 83 FA FF 89 D0 0F 84 01 02 00 00 48 85 D2 0F 85 F6 01 00 00 48 89 E6 BF ?? ?? ?? ?? B8 04 00 00 00 0F 05 48 3D 00 F0 FF FF 76 0C F7 D8 89 05 ?? ?? ?? ?? 48 83 C8 FF 85 C0 0F 85 BB 01 00 00 31 D2 31 F6 BF ?? ?? ?? ?? B0 02 0F 05 48 3D 00 F0 FF FF 76 0C F7 D8 89 05 ?? ?? ?? ?? 48 83 C8 FF 85 C0 0F 88 92 01 00 00 48 8B 74 24 30 48 63 D8 45 31 C9 49 89 D8 41 BA 01 00 00 00 BA 01 00 00 00 31 FF B8 09 00 00 00 48 89 35 ?? ?? ?? ?? 0F 05 48 3D 00 F0 FF FF 76 0C F7 D8 89 05 ?? ?? ?? ?? 48 83 C8 FF 48 89 05 ?? ?? ?? ?? 48 89 DF B8 03 00 00 00 0F 05 48 3D }
	condition:
		$pattern
}

rule __pthread_initialize_manager_136f865eae79581596634891df385498 {
	meta:
		aliases = "__pthread_initialize_manager"
		size = "512"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 48 81 EC C0 00 00 00 48 8B 05 ?? ?? ?? ?? C7 00 01 00 00 00 48 83 3D ?? ?? ?? ?? 00 75 05 E8 37 FE FF FF 48 8B 3D ?? ?? ?? ?? 48 8D 7C 3F E0 E8 ?? ?? ?? ?? 48 89 C2 48 89 05 ?? ?? ?? ?? 83 C8 FF 48 85 D2 0F 84 AC 01 00 00 48 8B 05 ?? ?? ?? ?? 48 8D BC 24 B0 00 00 00 48 8D 44 42 E0 48 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 FF 89 C3 75 11 48 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 F3 00 00 00 8B 05 ?? ?? ?? ?? 85 C0 0F 44 05 ?? ?? ?? ?? 85 C0 89 05 ?? ?? ?? ?? 0F 84 8B 00 00 00 8B 05 ?? ?? ?? ?? 8A 15 ?? ?? ?? ?? 08 C2 79 7B 48 8B 3D ?? ?? ?? ?? 31 F6 E8 ?? ?? ?? ?? 48 63 8C 24 B0 00 00 00 48 8B }
	condition:
		$pattern
}

rule mq_open_a001cfe6fb6dac51ec38eeb8b3f0610d {
	meta:
		aliases = "mq_open"
		size = "159"
		objfiles = "mq_open@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 48 81 EC D0 00 00 00 48 89 54 24 30 48 89 4C 24 38 80 3F 2F 74 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 6F 31 D2 31 C0 40 F6 C6 40 74 37 48 8D 84 24 E0 00 00 00 C7 04 24 18 00 00 00 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 48 83 C0 10 8B 10 48 8B 44 24 10 C7 04 24 20 00 00 00 48 83 C0 18 48 8B 00 49 89 C2 89 D2 48 63 F6 48 FF C7 B8 F0 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 48 81 C4 D0 00 00 00 5B C3 }
	condition:
		$pattern
}

rule __GI_ppoll_48dc9c86451a508c7d63f2677beae17d {
	meta:
		aliases = "ppoll, __GI_ppoll"
		size = "71"
		objfiles = "ppoll@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 10 48 85 D2 74 13 48 8B 02 48 89 04 24 48 8B 42 08 48 89 E2 48 89 44 24 08 49 89 CA B8 0F 01 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 5A 59 89 D8 5B C3 }
	condition:
		$pattern
}

rule __fresetlockfiles_4d340eb3b9472dfb3aaa8318853f5f21 {
	meta:
		aliases = "__fresetlockfiles"
		size = "68"
		objfiles = "lockfile@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 10 48 89 E7 E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? EB 10 48 8D 7B 58 48 89 E6 E8 ?? ?? ?? ?? 48 8B 5B 38 48 85 DB 75 EB 48 89 E7 E8 ?? ?? ?? ?? 58 5A 5B C3 }
	condition:
		$pattern
}

rule __GI_fmax_4ebbc2204bba0d9f6384e93a1d6d35fc {
	meta:
		aliases = "fmax, __GI_fmax"
		size = "79"
		objfiles = "s_fmax@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 10 F2 0F 11 04 24 48 8B 1C 24 F2 0F 11 4C 24 08 E8 ?? ?? ?? ?? 85 C0 74 25 66 0F 12 44 24 08 E8 ?? ?? ?? ?? 85 C0 74 11 48 89 1C 24 66 0F 12 04 24 66 0F 2E 44 24 08 77 05 48 8B 5C 24 08 48 89 1C 24 66 0F 12 04 24 58 5A 5B C3 }
	condition:
		$pattern
}

rule tanh_543c37c1e0346cb5a505e7b2dee78ea9 {
	meta:
		aliases = "__GI_tanh, tanh"
		size = "237"
		objfiles = "s_tanh@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 10 F2 0F 11 44 24 08 48 8B 54 24 08 48 89 D3 48 C1 EB 20 89 D8 25 FF FF FF 7F 3D FF FF EF 7F 7E 2C 85 DB 66 0F 12 0D ?? ?? ?? ?? 78 10 0F 28 D1 F2 0F 5E D0 F2 0F 58 D1 E9 A5 00 00 00 0F 28 D1 F2 0F 5E D0 F2 0F 5C D1 E9 95 00 00 00 3D FF FF 35 40 7E 0A 66 0F 12 15 ?? ?? ?? ?? EB 78 3D FF FF 7F 3C 7F 11 0F 28 D0 F2 0F 58 15 ?? ?? ?? ?? F2 0F 59 D0 EB 6C 3D FF FF EF 3F 7E 30 E8 ?? ?? ?? ?? F2 0F 58 C0 E8 ?? ?? ?? ?? 66 0F 12 0D ?? ?? ?? ?? 66 0F 12 15 ?? ?? ?? ?? F2 0F 58 C8 F2 0F 5E D1 F2 0F 58 15 ?? ?? ?? ?? EB 29 E8 ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 28 D0 F2 0F }
	condition:
		$pattern
}

rule significand_903f3a67d55176d4648ce1bc862eed47 {
	meta:
		aliases = "significand"
		size = "46"
		objfiles = "s_significand@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 10 F2 0F 11 44 24 08 48 8B 5C 24 08 E8 ?? ?? ?? ?? F7 D8 F2 0F 2A C8 48 89 5C 24 08 66 0F 12 44 24 08 58 5A 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __ieee754_hypot_05a5f94d160d3aa1ba624a4c9455a633 {
	meta:
		aliases = "__ieee754_hypot"
		size = "712"
		objfiles = "e_hypot@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 10 F2 0F 11 44 24 08 48 8B 7C 24 08 F2 0F 11 4C 24 08 48 8B 54 24 08 48 89 F8 49 89 F8 48 C1 E8 20 49 89 D1 89 C6 48 89 D0 48 C1 E8 20 81 E6 FF FF FF 7F 89 C1 81 E1 FF FF FF 7F 39 F1 7E 0C 89 C8 49 89 D0 89 F1 49 89 F9 89 C6 4C 89 C7 48 89 F2 4D 89 C8 48 C1 E2 20 83 E7 FF 41 83 E0 FF 48 09 D7 48 89 CA 89 F0 48 C1 E2 20 48 89 7C 24 08 29 C8 49 09 D0 66 0F 12 44 24 08 3D 00 00 C0 03 4C 89 44 24 08 66 0F 12 4C 24 08 0F 28 F0 0F 28 E1 7E 09 F2 0F 58 C1 E9 24 02 00 00 31 DB 81 FE 00 00 30 5F 0F 8E 8E 00 00 00 81 FE FF FF EF 7F 7E 40 48 89 7C 24 08 81 E6 FF FF 0F 00 66 0F 12 4C 24 08 09 }
	condition:
		$pattern
}

rule __ieee754_atan2_4c4aa8e95cc1407b76cef3aefa3e09c3 {
	meta:
		aliases = "__ieee754_atan2"
		size = "563"
		objfiles = "e_atan2@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 10 F2 0F 11 4C 24 08 48 8B 54 24 08 F2 0F 11 44 24 08 48 8B 4C 24 08 89 D6 48 89 D7 48 89 C8 48 C1 EF 20 48 C1 E9 20 89 C2 89 F0 41 89 F8 F7 D8 41 81 E0 FF FF FF 7F 09 F0 C1 E8 1F 44 09 C0 3D 00 00 F0 7F 77 1B 89 D0 41 89 C9 81 E1 FF FF FF 7F F7 D8 09 D0 C1 E8 1F 09 C8 3D 00 00 F0 7F 76 09 F2 0F 58 C1 E9 C1 01 00 00 8D 87 00 00 10 C0 09 F0 75 08 59 5E 5B E9 ?? ?? ?? ?? 89 F8 44 89 CB C1 F8 1E C1 EB 1F 83 E0 02 09 C3 09 CA 75 18 83 FB 02 0F 84 99 00 00 00 0F 8E 8C 01 00 00 83 FB 03 0F 84 97 00 00 00 44 09 C6 0F 84 B8 00 00 00 41 81 F8 00 00 F0 7F 0F 85 A3 00 00 00 81 F9 00 00 F0 7F }
	condition:
		$pattern
}

rule _Unwind_SjLj_Resume_eadf78154aba8cb5f3011afcdffc8a85 {
	meta:
		aliases = "_Unwind_SjLj_Resume"
		size = "71"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 20 48 83 7F 10 00 48 8B 05 ?? ?? ?? ?? 48 89 44 24 10 48 89 04 24 75 14 48 89 E6 E8 3C FF FF FF 83 F8 07 74 11 E8 ?? ?? ?? ?? 66 90 48 89 E6 E8 58 FE FF FF EB EA 48 8D 7C 24 10 48 89 E6 E8 99 FF FF FF }
	condition:
		$pattern
}

rule _Unwind_SjLj_Resume_or_Rethrow_b40a31dc25e6bd8ca7c232e462034315 {
	meta:
		aliases = "_Unwind_SjLj_Resume_or_Rethrow"
		size = "72"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 20 48 83 7F 10 00 74 24 48 8B 05 ?? ?? ?? ?? 48 89 E6 48 89 44 24 10 48 89 04 24 E8 2C FD FF FF 83 F8 07 74 12 E8 ?? ?? ?? ?? 66 90 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 48 8D 7C 24 10 48 89 E6 E8 58 FE FF FF }
	condition:
		$pattern
}

rule _Unwind_SjLj_ForcedUnwind_829d1ad0d90c19f5430a9458ace97193 {
	meta:
		aliases = "_Unwind_SjLj_ForcedUnwind"
		size = "61"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 20 48 8B 05 ?? ?? ?? ?? 48 89 77 10 48 89 57 18 48 89 E6 48 89 44 24 10 48 89 04 24 E8 1B FE FF FF 83 F8 07 74 06 48 83 C4 20 5B C3 48 8D 7C 24 10 48 89 E6 E8 53 FF FF FF }
	condition:
		$pattern
}

rule __ieee754_j0_ca53541ceeea5c5a5eb374b7d8957601 {
	meta:
		aliases = "__ieee754_j0"
		size = "648"
		objfiles = "e_j0@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 30 F2 0F 11 04 24 48 8B 14 24 48 89 D0 48 C1 E8 20 89 C3 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 11 F2 0F 59 C0 66 0F 12 1D ?? ?? ?? ?? E9 CC 00 00 00 E8 ?? ?? ?? ?? 81 FB FF FF FF 3F F2 0F 11 44 24 28 0F 8E 25 01 00 00 E8 ?? ?? ?? ?? F2 0F 11 44 24 20 66 0F 12 44 24 28 E8 ?? ?? ?? ?? F2 0F 11 44 24 08 81 FB FF FF DF 7F 66 0F 12 44 24 20 F2 0F 5C 44 24 08 F2 0F 11 44 24 10 66 0F 12 44 24 20 F2 0F 58 44 24 08 F2 0F 11 44 24 18 7F 4C 66 0F 12 44 24 28 F2 0F 58 C0 E8 ?? ?? ?? ?? 0F 28 C8 66 0F 12 44 24 20 F2 0F 59 44 24 08 66 0F 57 0D ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 73 10 7A 0E F2 }
	condition:
		$pattern
}

rule __ieee754_y1_b57307709e8a3bf46bbbdeac9c793038 {
	meta:
		aliases = "__ieee754_y1"
		size = "651"
		objfiles = "e_j1@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 50 F2 0F 11 44 24 20 48 8B 44 24 20 48 89 C2 48 C1 EA 20 89 D3 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 17 F2 0F 59 C0 66 0F 12 25 ?? ?? ?? ?? F2 0F 58 44 24 20 E9 EB 00 00 00 09 D8 75 15 66 0F 12 25 ?? ?? ?? ?? F2 0F 5E 25 ?? ?? ?? ?? E9 2B 02 00 00 85 D2 79 0C 0F 57 E4 F2 0F 5E E4 E9 1B 02 00 00 81 FB FF FF FF 3F 0F 8E 15 01 00 00 66 0F 12 44 24 20 E8 ?? ?? ?? ?? F2 0F 11 44 24 30 66 0F 12 44 24 20 E8 ?? ?? ?? ?? F2 0F 11 44 24 38 81 FB FF FF DF 7F 66 0F 12 44 24 30 66 0F 12 4C 24 30 66 0F 57 05 ?? ?? ?? ?? F2 0F 5C 4C 24 38 F2 0F 5C 44 24 38 F2 0F 11 4C 24 48 F2 0F 11 44 24 40 7F }
	condition:
		$pattern
}

rule __ieee754_y0_80b1c802431499cc6b70f977fcc946f5 {
	meta:
		aliases = "__ieee754_y0"
		size = "678"
		objfiles = "e_j0@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 50 F2 0F 11 44 24 28 48 8B 44 24 28 48 89 C2 48 C1 EA 20 89 D3 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 17 F2 0F 59 C0 66 0F 12 25 ?? ?? ?? ?? F2 0F 58 44 24 28 E9 F0 00 00 00 09 D8 75 15 66 0F 12 25 ?? ?? ?? ?? F2 0F 5E 25 ?? ?? ?? ?? E9 46 02 00 00 85 D2 79 0C 0F 57 E4 F2 0F 5E E4 E9 36 02 00 00 81 FB FF FF FF 3F 0F 8E 2B 01 00 00 66 0F 12 44 24 28 E8 ?? ?? ?? ?? F2 0F 11 44 24 30 66 0F 12 44 24 28 E8 ?? ?? ?? ?? F2 0F 11 44 24 38 81 FB FF FF DF 7F 66 0F 12 44 24 30 F2 0F 5C 44 24 38 F2 0F 11 44 24 40 66 0F 12 44 24 30 F2 0F 58 44 24 38 F2 0F 11 44 24 48 7F 4C 66 0F 12 44 24 28 F2 }
	condition:
		$pattern
}

rule __floattixf_006d7fbfc577cd86600274f6108aa188 {
	meta:
		aliases = "__floattixf"
		size = "44"
		objfiles = "_floatdixf@libgcc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 85 FF 48 89 74 24 80 DF 6C 24 80 48 89 7C 24 80 DB 2D ?? ?? ?? ?? DC C9 DF 6C 24 80 78 06 DD D9 5B DE C1 C3 DE C1 5B DE C1 C3 }
	condition:
		$pattern
}

rule ether_line_f5dfc3356b70e9b29f7511255d2c1d80 {
	meta:
		aliases = "ether_line"
		size = "65"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 D3 E8 AC FF FF FF 48 89 C6 83 C8 FF 48 85 F6 74 2B EB 1E 80 F9 23 74 1F 48 8B 05 ?? ?? ?? ?? 48 0F BE D1 F6 04 50 20 75 0E 88 0B 48 FF C6 48 FF C3 8A 0E 84 C9 75 DC C6 03 00 31 C0 5B C3 }
	condition:
		$pattern
}

rule tempnam_cc3fcc7c8fc0759c6b227cbda30d250e {
	meta:
		aliases = "tempnam"
		size = "69"
		objfiles = "tempnam@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F1 48 89 FA BE FF 0F 00 00 48 81 EC 00 10 00 00 48 89 E7 E8 ?? ?? ?? ?? 85 C0 75 1B BE 03 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 85 C0 75 0A 48 89 E7 E8 ?? ?? ?? ?? EB 02 31 C0 48 81 C4 00 10 00 00 5B C3 }
	condition:
		$pattern
}

rule sigwait_09740d8ab1e07c170a03350c5f1149f6 {
	meta:
		aliases = "__sigwait, __GI_sigwait, sigwait"
		size = "29"
		objfiles = "sigwait@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 31 F6 E8 ?? ?? ?? ?? 83 F8 FF BA 01 00 00 00 74 04 89 03 30 D2 5B 89 D0 C3 }
	condition:
		$pattern
}

rule getpw_492ef34aed447fb9667007e61cefb34c {
	meta:
		aliases = "getpw"
		size = "169"
		objfiles = "getpw@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 81 EC 60 01 00 00 48 85 F6 75 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 7E 48 8D 54 24 20 48 8D B4 24 20 01 00 00 4C 8D 84 24 58 01 00 00 B9 00 01 00 00 E8 ?? ?? ?? ?? 85 C0 75 5B 48 8B 84 24 48 01 00 00 44 8B 8C 24 34 01 00 00 BE ?? ?? ?? ?? 44 8B 84 24 30 01 00 00 48 8B 94 24 20 01 00 00 48 89 DF 48 8B 8C 24 28 01 00 00 48 89 44 24 10 48 8B 84 24 40 01 00 00 48 89 44 24 08 48 8B 84 24 38 01 00 00 48 89 04 24 31 C0 E8 ?? ?? ?? ?? 31 D2 85 C0 79 03 83 CA FF 48 81 C4 60 01 00 00 89 D0 5B C3 }
	condition:
		$pattern
}

rule adjtime_c8b95ca307bbd7e9f4edfe5fd5816e8f {
	meta:
		aliases = "adjtime"
		size = "215"
		objfiles = "adjtime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 81 EC D0 00 00 00 48 85 FF 74 5D 48 8B 47 08 B9 40 42 0F 00 48 99 48 F7 F9 48 89 C1 48 03 0F 48 B8 F4 5A D0 7B 63 08 00 00 48 89 D6 48 BA E8 B5 A0 F7 C6 10 00 00 48 8D 04 01 48 39 D0 76 10 E8 ?? ?? ?? ?? 83 CA FF C7 00 16 00 00 00 EB 78 48 69 C1 40 42 0F 00 C7 04 24 01 80 00 00 48 8D 04 06 48 89 44 24 08 EB 07 C7 04 24 00 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 83 CA FF 85 C0 78 49 31 D2 48 85 DB 74 42 48 8B 54 24 08 48 85 D2 79 1F 48 F7 DA B9 40 42 0F 00 48 89 D0 48 99 48 F7 F9 48 89 C1 48 F7 DA 48 F7 D9 48 89 53 08 EB 14 48 89 D0 B9 40 42 0F 00 48 99 48 F7 F9 48 89 C1 48 89 53 08 48 }
	condition:
		$pattern
}

rule xdr_u_char_a63dc7c8bfc25c9d357c28210625fa7f {
	meta:
		aliases = "xdr_u_char"
		size = "46"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 10 0F B6 06 48 8D 74 24 0C 89 44 24 0C E8 ?? ?? ?? ?? 31 D2 85 C0 74 08 8B 44 24 0C B2 01 88 03 5F 41 58 5B 89 D0 C3 }
	condition:
		$pattern
}

rule xdr_char_d71d96e50d7583aae86ef2929c3e7c87 {
	meta:
		aliases = "xdr_char"
		size = "45"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 10 0F BE 06 48 8D 74 24 0C 89 44 24 0C E8 ?? ?? ?? ?? 31 D2 85 C0 74 08 8B 44 24 0C B2 01 88 03 59 5E 5B 89 D0 C3 }
	condition:
		$pattern
}

rule xdrrec_getint32_0c4faed4ecbf42e20b4bff83b8a1bd4e {
	meta:
		aliases = "xdrrec_getint32"
		size = "96"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 10 48 8B 57 18 48 83 7A 68 03 48 8B 4A 58 7E 24 48 8B 42 60 48 29 C8 48 83 F8 03 7E 17 8B 01 0F C8 89 06 48 83 6A 68 04 48 83 42 58 04 BA 01 00 00 00 EB 1F 48 8D 74 24 0C BA 04 00 00 00 E8 48 FF FF FF 31 D2 85 C0 74 0A 8B 44 24 0C B2 01 0F C8 89 03 5B 89 D0 5A 5B C3 }
	condition:
		$pattern
}

rule xdrrec_getlong_2931b59bda5fe31b7d02d33b11f17b40 {
	meta:
		aliases = "xdrrec_getlong"
		size = "102"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 10 48 8B 57 18 48 83 7A 68 03 48 8B 4A 58 7E 27 48 8B 42 60 48 29 C8 48 83 F8 03 7E 1A 8B 01 0F C8 48 98 48 89 06 48 83 6A 68 04 48 83 42 58 04 BA 01 00 00 00 EB 22 48 8D 74 24 0C BA 04 00 00 00 E8 E5 FE FF FF 31 D2 85 C0 74 0D 8B 44 24 0C B2 01 0F C8 48 98 48 89 03 59 5E 5B 89 D0 C3 }
	condition:
		$pattern
}

rule __GI_xdr_u_long_3c676c5e412c0c4b1381f9ab5950764c {
	meta:
		aliases = "xdr_u_long, __GI_xdr_u_long"
		size = "85"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 10 8B 17 83 FA 01 74 0E 72 29 83 FA 02 B8 01 00 00 00 74 34 EB 30 48 8B 47 08 48 8D 74 24 08 FF 10 85 C0 74 21 8B 44 24 08 48 89 03 B8 01 00 00 00 EB 15 48 8B 16 89 D0 48 39 D0 75 09 48 8B 47 08 FF 50 08 EB 02 31 C0 41 58 41 59 5B C3 }
	condition:
		$pattern
}

rule xdr_uint8_t_b9487463c496ce9dc6f7598b3e943362 {
	meta:
		aliases = "xdr_uint8_t"
		size = "87"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 10 8B 17 83 FA 01 74 23 72 0C 83 FA 02 B8 01 00 00 00 74 36 EB 32 0F B6 06 48 8D 74 24 0C 89 44 24 0C 48 8B 47 08 FF 50 48 EB 1F 48 8B 47 08 48 8D 74 24 0C FF 50 40 85 C0 74 0D 8B 44 24 0C 88 03 B8 01 00 00 00 EB 02 31 C0 41 5A 41 5B 5B C3 }
	condition:
		$pattern
}

rule xdr_int8_t_3ece25daa4009a811cc51adf10bdb262 {
	meta:
		aliases = "xdr_int8_t"
		size = "87"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 10 8B 17 83 FA 01 74 23 72 0C 83 FA 02 B8 01 00 00 00 74 36 EB 32 0F BE 06 48 8D 74 24 0C 89 44 24 0C 48 8B 47 08 FF 50 48 EB 1F 48 8B 47 08 48 8D 74 24 0C FF 50 40 85 C0 74 0D 8B 44 24 0C 88 03 B8 01 00 00 00 EB 02 31 C0 41 58 41 59 5B C3 }
	condition:
		$pattern
}

rule __GI_xdr_u_int_e73e1da48c73b322ea563690d6c4b371 {
	meta:
		aliases = "xdr_u_int, __GI_xdr_u_int"
		size = "87"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 10 8B 17 83 FA 01 74 23 72 0C 83 FA 02 B8 01 00 00 00 74 36 EB 32 8B 1E 48 8B 47 08 48 8D 74 24 08 48 89 5C 24 08 FF 50 08 EB 1F 48 8B 47 08 48 8D 74 24 08 FF 10 85 C0 74 0E 48 8B 44 24 08 89 03 B8 01 00 00 00 EB 02 31 C0 41 5A 41 5B 5B C3 }
	condition:
		$pattern
}

rule xdr_uint16_t_dd2354d6e1997d53f019893c370918ba {
	meta:
		aliases = "xdr_uint16_t"
		size = "86"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 10 8B 17 83 FA 01 74 23 72 0C 83 FA 02 B8 01 00 00 00 74 37 EB 33 0F B7 06 48 8D 74 24 0C 89 44 24 0C 48 8B 47 08 FF 50 48 EB 20 48 8B 47 08 48 8D 74 24 0C FF 50 40 85 C0 74 0E 8B 44 24 0C 66 89 03 B8 01 00 00 00 EB 02 31 C0 5E 5F 5B C3 }
	condition:
		$pattern
}

rule xdr_int16_t_c29cef6d0adebc9b0831a4f2f6361923 {
	meta:
		aliases = "xdr_int16_t"
		size = "86"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 10 8B 17 83 FA 01 74 23 72 0C 83 FA 02 B8 01 00 00 00 74 37 EB 33 0F BF 06 48 8D 74 24 0C 89 44 24 0C 48 8B 47 08 FF 50 48 EB 20 48 8B 47 08 48 8D 74 24 0C FF 50 40 85 C0 74 0E 8B 44 24 0C 66 89 03 B8 01 00 00 00 EB 02 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule xdr_enum_d1f04b729138804d9cf587a0e56897dc {
	meta:
		aliases = "__GI_xdr_enum, xdr_enum"
		size = "87"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 10 8B 17 83 FA 01 74 24 72 0C 83 FA 02 B8 01 00 00 00 74 37 EB 33 48 63 06 48 8D 74 24 08 48 89 44 24 08 48 8B 47 08 FF 50 08 EB 1F 48 8B 47 08 48 8D 74 24 08 FF 10 85 C0 74 0E 48 8B 44 24 08 89 03 B8 01 00 00 00 EB 02 31 C0 41 5B 5B 5B C3 }
	condition:
		$pattern
}

rule xdr_float_64f016e367407e2249978d7464fd8944 {
	meta:
		aliases = "xdr_float"
		size = "86"
		objfiles = "xdr_float@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 10 8B 17 83 FA 01 74 24 72 0C 83 FA 02 B8 01 00 00 00 74 37 EB 33 48 63 06 48 8D 74 24 08 48 89 44 24 08 48 8B 47 08 FF 50 08 EB 1F 48 8B 47 08 48 8D 74 24 08 FF 10 85 C0 74 0E 48 8B 44 24 08 89 03 B8 01 00 00 00 EB 02 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_xdr_int_5b5e09bc85874351179c58e047393459 {
	meta:
		aliases = "xdr_int, __GI_xdr_int"
		size = "86"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 10 8B 17 83 FA 01 74 24 72 0C 83 FA 02 B8 01 00 00 00 74 37 EB 33 48 63 06 48 8D 74 24 08 48 89 44 24 08 48 8B 47 08 FF 50 08 EB 1F 48 8B 47 08 48 8D 74 24 08 FF 10 85 C0 74 0E 48 8B 44 24 08 89 03 B8 01 00 00 00 EB 02 31 C0 5E 5F 5B C3 }
	condition:
		$pattern
}

rule xdr_u_short_3970b56ab18de75f5d2ce070e5e2a9c7 {
	meta:
		aliases = "__GI_xdr_u_short, xdr_u_short"
		size = "87"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 10 8B 17 83 FA 01 74 24 72 0C 83 FA 02 B8 01 00 00 00 74 38 EB 34 0F B7 06 48 8D 74 24 08 48 89 44 24 08 48 8B 47 08 FF 50 08 EB 20 48 8B 47 08 48 8D 74 24 08 FF 10 85 C0 74 0F 48 8B 44 24 08 66 89 03 B8 01 00 00 00 EB 02 31 C0 5B 5A 5B C3 }
	condition:
		$pattern
}

rule __GI_xdr_short_61c4c8dab19be5ac9ad3cd3a41b898df {
	meta:
		aliases = "xdr_short, __GI_xdr_short"
		size = "88"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 10 8B 17 83 FA 01 74 25 72 0C 83 FA 02 B8 01 00 00 00 74 39 EB 35 48 0F BF 06 48 8D 74 24 08 48 89 44 24 08 48 8B 47 08 FF 50 08 EB 20 48 8B 47 08 48 8D 74 24 08 FF 10 85 C0 74 0F 48 8B 44 24 08 66 89 03 B8 01 00 00 00 EB 02 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_xdr_bool_715a9c3bdc083cb49d4f490cc8010cc3 {
	meta:
		aliases = "xdr_bool, __GI_xdr_bool"
		size = "99"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 10 8B 17 83 FA 01 74 29 72 0C 83 FA 02 B8 01 00 00 00 74 42 EB 3E 31 C0 83 3E 00 48 8D 74 24 08 0F 95 C0 48 89 44 24 08 48 8B 47 08 FF 50 08 EB 25 48 8B 47 08 48 8D 74 24 08 FF 10 85 C0 74 14 31 C0 48 83 7C 24 08 00 0F 95 C0 89 03 B8 01 00 00 00 EB 02 31 C0 41 59 41 5A 5B C3 }
	condition:
		$pattern
}

rule ctime_r_e442bc67a84647c011dbc33ce6d4b020 {
	meta:
		aliases = "ctime_r"
		size = "33"
		objfiles = "ctime_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 40 48 89 E6 E8 ?? ?? ?? ?? 48 89 DE 48 89 C7 E8 ?? ?? ?? ?? 48 83 C4 40 5B C3 }
	condition:
		$pattern
}

rule __stdio_seek_1e9a3845db7af5ccba11471a31ebead7 {
	meta:
		aliases = "__stdio_seek"
		size = "31"
		objfiles = "_cs_funcs@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 8B 7F 04 48 8B 36 E8 ?? ?? ?? ?? 48 85 C0 89 C2 78 05 48 89 03 31 D2 5B 89 D0 C3 }
	condition:
		$pattern
}

rule ether_ntoa_r_7ca6bc8feaa1fa94337a27a3621ce401 {
	meta:
		aliases = "__GI_ether_ntoa_r, ether_ntoa_r"
		size = "62"
		objfiles = "ether_addr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 BE ?? ?? ?? ?? 48 83 EC 10 0F B6 47 05 0F B6 4F 01 0F B6 17 44 0F B6 4F 03 44 0F B6 47 02 89 44 24 08 0F B6 47 04 48 89 DF 89 04 24 31 C0 E8 ?? ?? ?? ?? 5A 59 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI___glibc_strerror_r_d73082b89e1883f7c4a49a7dc2e3ef41 {
	meta:
		aliases = "__glibc_strerror_r, __GI___glibc_strerror_r"
		size = "14"
		objfiles = "__glibc_strerror_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 E8 ?? ?? ?? ?? 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule authnone_marshal_7875063ba9acda7cb18baf66c856a5e1 {
	meta:
		aliases = "authnone_marshal"
		size = "47"
		objfiles = "auth_none@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 E8 ?? ?? ?? ?? 48 8B 88 B0 00 00 00 48 85 C9 74 16 48 8B 43 08 48 89 DF 8B 51 5C 5B 48 8D 71 48 4C 8B 58 18 41 FF E3 5B 31 C0 C3 }
	condition:
		$pattern
}

rule calloc_0a9b8fc3fa1baf9b01190dd0e9576efc {
	meta:
		aliases = "calloc"
		size = "248"
		objfiles = "calloc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 0F AF DE 48 83 EC 20 48 85 FF 74 1F 31 D2 48 89 D8 48 F7 F7 48 39 C6 74 12 31 DB E8 ?? ?? ?? ?? C7 00 0C 00 00 00 E9 BF 00 00 00 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 0F 84 82 00 00 00 48 8B 40 F8 A8 02 75 7A 48 83 E0 FC 48 8D 50 F8 48 89 D0 48 C1 E8 03 48 83 F8 09 76 0C 31 F6 48 89 DF E8 ?? ?? ?? ?? EB 59 48 83 F8 04 48 C7 03 00 00 00 00 48 C7 43 08 00 00 00 00 48 C7 43 10 00 00 00 00 76 3C 48 83 F8 06 48 C7 43 18 00 00 00 00 48 C7 43 20 00 00 00 00 76 26 48 83 F8 08 48 C7 43 28 00 00 00 00 }
	condition:
		$pattern
}

rule pthread_start_thread_ee1529fc190d1b0cad61a3d21c93348a {
	meta:
		aliases = "pthread_start_thread"
		size = "195"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 81 EC C0 00 00 00 E8 ?? ?? ?? ?? 48 8D B3 C0 00 00 00 31 D2 89 43 28 BF 02 00 00 00 E8 ?? ?? ?? ?? 8B B3 40 01 00 00 85 F6 78 0C 8B 7B 28 48 8D 93 44 01 00 00 EB 21 83 3D ?? ?? ?? ?? 00 7E 1D 8B 7B 28 48 8D 94 24 B0 00 00 00 C7 84 24 B0 00 00 00 00 00 00 00 31 F6 E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 85 C0 74 3F 83 3D ?? ?? ?? ?? 00 7E 36 48 89 1C 24 C7 44 24 08 05 00 00 00 8B 3D ?? ?? ?? ?? 48 89 E6 BA A8 00 00 00 E8 ?? ?? ?? ?? 48 FF C0 75 0A E8 ?? ?? ?? ?? 83 38 04 74 DE 48 89 DF E8 ?? ?? ?? ?? 48 8B BB B8 00 00 00 FF 93 B0 00 00 00 48 89 C7 48 89 E6 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ntp_gettime_d2224f36a1f5d4297215429f433452f0 {
	meta:
		aliases = "ntp_gettime"
		size = "70"
		objfiles = "ntp_gettime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 81 EC D0 00 00 00 48 89 E7 C7 04 24 00 00 00 00 E8 ?? ?? ?? ?? 48 8B 54 24 48 48 89 13 48 8B 54 24 50 48 89 53 08 48 8B 54 24 18 48 89 53 10 48 8B 54 24 20 48 89 53 18 48 81 C4 D0 00 00 00 5B C3 }
	condition:
		$pattern
}

rule __GI_fgetc_unlocked_820cb18c69c975a81fab1a5cc31ce5b4 {
	meta:
		aliases = "__GI___fgetc_unlocked, fgetc_unlocked, __fgetc_unlocked, __GI_getc_unlocked, getc_unlocked, __GI_fgetc_unlocked"
		size = "222"
		objfiles = "fgetc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 83 EC 10 48 8B 47 18 48 3B 47 28 0F 82 95 00 00 00 0F B7 07 25 83 00 00 00 3D 80 00 00 00 77 12 BE 80 00 00 00 E8 ?? ?? ?? ?? 85 C0 0F 85 9E 00 00 00 8B 0B 0F B7 D1 F6 C2 02 74 1C 48 89 C8 83 E0 01 8A 54 83 40 8D 41 FF C7 43 44 00 00 00 00 66 89 03 0F B6 D2 EB 7B 48 8B 43 18 48 39 43 20 75 44 83 7B 04 FE 75 08 83 C9 04 66 89 0B EB 60 80 E6 03 74 0A BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 43 08 48 39 43 10 74 29 48 89 43 28 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 74 36 48 8B 43 20 48 89 43 28 48 8B 43 18 0F B6 10 48 FF C0 48 89 43 18 EB 21 48 8D 74 24 0F BA 01 00 00 00 48 89 DF E8 ?? ?? ?? }
	condition:
		$pattern
}

rule getprotobyname_ad86096ad213231764b8506dfde51a7b {
	meta:
		aliases = "getprotobyname"
		size = "52"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 83 EC 10 E8 60 FB FF FF 48 8B 15 ?? ?? ?? ?? 4C 8D 44 24 08 48 89 DF BE ?? ?? ?? ?? B9 19 11 00 00 E8 ?? ?? ?? ?? 48 8B 44 24 08 5E 5F 5B C3 }
	condition:
		$pattern
}

rule gethostbyname_14586eed00e7b34b64c625e60f15cb78 {
	meta:
		aliases = "__GI_gethostbyname, gethostbyname"
		size = "53"
		objfiles = "gethostbyname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 83 EC 10 E8 ?? ?? ?? ?? 4C 8D 44 24 08 B9 F4 01 00 00 BA ?? ?? ?? ?? 48 89 DF 49 89 C1 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 44 24 08 5A 59 5B C3 }
	condition:
		$pattern
}

rule free_d5bca0f84c7507f954fb158db94eb555 {
	meta:
		aliases = "free"
		size = "452"
		objfiles = "free@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 83 EC 20 48 85 FF 0F 84 AD 01 00 00 BA ?? ?? ?? ?? 48 89 E7 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4B F8 48 8B 05 ?? ?? ?? ?? 48 8D 7B F0 48 89 CA 48 83 E2 FC 48 39 C2 77 2C 48 83 C8 03 48 89 05 ?? ?? ?? ?? 89 D0 C1 E8 03 83 E8 02 48 8D 04 C5 ?? ?? ?? ?? 48 8B 50 08 48 89 57 10 48 89 78 08 E9 3D 01 00 00 80 E1 02 0F 85 17 01 00 00 48 83 C8 01 48 8D 34 17 48 89 05 ?? ?? ?? ?? F6 43 F8 01 4C 8B 56 08 75 2C 4C 8B 4B F0 48 89 F8 4C 29 C8 4C 8B 40 10 48 8B 48 18 49 8B 78 18 48 39 C7 75 48 48 39 79 10 75 42 4C 01 CA 49 89 48 18 4C 89 41 10 4D 89 D1 49 83 E1 }
	condition:
		$pattern
}

rule ftime_2b0d2187648c27c406fa495d45b42417 {
	meta:
		aliases = "ftime"
		size = "89"
		objfiles = "ftime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 83 EC 20 48 8D 74 24 10 48 89 E7 E8 ?? ?? ?? ?? 83 CA FF 85 C0 78 35 48 8B 04 24 BA E8 03 00 00 48 89 D1 48 89 03 48 8B 44 24 08 48 05 E7 03 00 00 48 99 48 F7 F9 31 D2 66 89 43 08 8B 44 24 10 66 89 43 0A 8B 44 24 14 66 89 43 0C 48 83 C4 20 89 D0 5B C3 }
	condition:
		$pattern
}

rule malloc_stats_e3fcc209f9ece1ede8b2eb5990b71ba1 {
	meta:
		aliases = "malloc_stats"
		size = "106"
		objfiles = "mallinfo@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 83 EC 60 48 85 FF 48 0F 44 1D ?? ?? ?? ?? 48 8D 7C 24 30 E8 ?? ?? ?? ?? 8B 44 24 54 8B 74 24 40 8B 7C 24 4C 44 8B 44 24 30 44 8B 4C 24 3C 89 44 24 20 8B 44 24 50 8D 0C 37 41 8D 14 30 89 7C 24 08 89 34 24 48 89 DF BE ?? ?? ?? ?? 89 44 24 18 8B 44 24 44 89 44 24 10 31 C0 E8 ?? ?? ?? ?? 48 83 C4 60 5B C3 }
	condition:
		$pattern
}

rule __uc_malloc_7b57b9a1a8d1824c8cf0847dea49a5a4 {
	meta:
		aliases = "__GI___uc_malloc, __uc_malloc"
		size = "65"
		objfiles = "__uc_malloc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 89 DF E8 ?? ?? ?? ?? 48 85 DB 48 89 C1 0F 94 C2 48 85 C0 0F 95 C0 08 C2 75 1D 48 8B 05 ?? ?? ?? ?? 48 85 C0 75 0A BF 01 00 00 00 E8 ?? ?? ?? ?? 48 89 DF FF D0 EB C8 5B 48 89 C8 C3 }
	condition:
		$pattern
}

rule __pthread_manager_event_a0da9083bfd47ed74d61d3e906550632 {
	meta:
		aliases = "__pthread_manager_event"
		size = "38"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 8B 3D ?? ?? ?? ?? 31 F6 E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule regfree_888cdda41486620f0eb8138084a53f9e {
	meta:
		aliases = "__regfree, regfree"
		size = "75"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 8B 3F E8 ?? ?? ?? ?? 48 8B 7B 20 48 C7 03 00 00 00 00 48 C7 43 08 00 00 00 00 48 C7 43 10 00 00 00 00 E8 ?? ?? ?? ?? 80 63 38 F7 48 8B 7B 28 48 C7 43 20 00 00 00 00 E8 ?? ?? ?? ?? 48 C7 43 28 00 00 00 00 5B C3 }
	condition:
		$pattern
}

rule sc_getc_497b183974c4203dd692581aee1bb696 {
	meta:
		aliases = "sc_getc"
		size = "96"
		objfiles = "vfwscanf@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 8B 7F 08 83 7F 04 FD 75 1F 48 8B 47 18 48 3B 47 10 73 0C 8B 10 48 83 C0 04 48 89 47 18 EB 15 66 83 0F 04 83 C8 FF EB 31 E8 ?? ?? ?? ?? 89 C2 83 FA FF 74 25 48 8B 43 08 3B 53 44 C6 43 1E 01 89 53 2C 8A 40 02 88 43 1C 75 07 BA 2E 00 00 00 EB 06 89 53 04 89 53 28 89 D0 5B C3 }
	condition:
		$pattern
}

rule __GI_vswprintf_9411d873d3c8c21c0aea40af948c937f {
	meta:
		aliases = "vswprintf, __GI_vswprintf"
		size = "164"
		objfiles = "vswprintf@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 49 89 D0 48 F7 D3 48 89 CA 48 C1 EB 02 48 83 C4 80 48 39 F3 48 89 7C 24 08 48 89 7C 24 18 48 0F 47 DE 48 89 7C 24 20 48 89 7C 24 28 48 8D 04 9F 48 89 7C 24 30 4C 89 C6 48 89 E7 C7 44 24 04 FD FF FF FF 66 C7 04 24 50 08 C6 44 24 02 00 C7 44 24 48 00 00 00 00 48 C7 44 24 38 00 00 00 00 48 89 44 24 10 E8 ?? ?? ?? ?? 89 C2 48 8B 44 24 10 48 39 44 24 18 75 11 83 CA FF 48 85 DB 74 19 48 83 E8 04 48 89 44 24 18 48 85 DB 74 0B 48 8B 44 24 18 C7 00 00 00 00 00 48 83 EC 80 89 D0 5B C3 }
	condition:
		$pattern
}

rule system_235a481eb353d47af5ccc10f98212829 {
	meta:
		aliases = "system"
		size = "52"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB BF 01 00 00 00 48 83 EC 10 48 8D 74 24 0C E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 8B 7C 24 0C 31 F6 89 C3 E8 ?? ?? ?? ?? 41 59 41 5A 89 D8 5B C3 }
	condition:
		$pattern
}

rule wait_fa392afdc9c758b561551d5ca13c0ea7 {
	meta:
		aliases = "wait"
		size = "50"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB BF 01 00 00 00 48 83 EC 10 48 8D 74 24 0C E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 8B 7C 24 0C 31 F6 89 C3 E8 ?? ?? ?? ?? 59 5E 89 D8 5B C3 }
	condition:
		$pattern
}

rule __register_frame_table_89cb4bde27ba5c3def1b9f04b77328f4 {
	meta:
		aliases = "__register_frame_table"
		size = "26"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB BF 30 00 00 00 E8 ?? ?? ?? ?? 48 89 DF 48 89 C6 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule malloc_trim_711881b06fc3f9d84513c4a015a3dfae {
	meta:
		aliases = "malloc_trim"
		size = "28"
		objfiles = "free@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 DF BE ?? ?? ?? ?? 5B E9 ED FB FF FF }
	condition:
		$pattern
}

rule pthread_once_cancelhandler_ee58a881baa408c0e50b7e2da4eda360 {
	meta:
		aliases = "pthread_once_cancelhandler"
		size = "41"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB BF ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 03 00 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 5B BF ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wait_node_free_f15d68a36fb384e38ed5644c8174bcc0 {
	meta:
		aliases = "wait_node_free"
		size = "43"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB BF ?? ?? ?? ?? E8 A9 FF FF FF 48 8B 05 ?? ?? ?? ?? 48 89 03 48 89 1D ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 5B C3 }
	condition:
		$pattern
}

rule __ether_line_359213c7c68ea11967579750d4ad6572 {
	meta:
		aliases = "__ether_line"
		size = "75"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB E8 ?? ?? ?? ?? 48 85 C0 74 36 EB 03 48 FF C3 8A 0B 84 C9 0F 95 C2 80 F9 20 0F 95 C0 84 D0 74 0A 80 F9 09 75 E7 EB 03 48 FF C3 8A 03 84 C0 74 10 3C 20 0F 94 C2 3C 09 0F 94 C0 08 C2 75 E9 EB 02 31 DB 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule cuserid_7b2f5114cb473c8d271c6c794d7f866d {
	meta:
		aliases = "cuserid"
		size = "43"
		objfiles = "getlogin@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB E8 ?? ?? ?? ?? 48 85 DB 48 89 C2 74 18 48 89 DF 48 85 C0 B8 ?? ?? ?? ?? 5B 48 0F 44 D0 48 89 D6 E9 ?? ?? ?? ?? 5B C3 }
	condition:
		$pattern
}

rule re_exec_95a194a783095ef9cdcbe04787865d1f {
	meta:
		aliases = "re_exec"
		size = "39"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB E8 ?? ?? ?? ?? 48 89 DE 45 31 C9 41 89 C0 31 C9 89 C2 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 5B F7 D0 C1 E8 1F C3 }
	condition:
		$pattern
}

rule pthread_start_thread_event_cc0501127e2798e7ef9448385737a6e4 {
	meta:
		aliases = "pthread_start_thread_event"
		size = "40"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB E8 ?? ?? ?? ?? 48 8B 7B 30 89 43 28 31 F6 E8 ?? ?? ?? ?? 48 8B 7B 30 E8 ?? ?? ?? ?? 48 89 DF E8 15 FF FF FF }
	condition:
		$pattern
}

rule pthread_attr_init_96f6a93ac15b0cba5f1777b62086ea81 {
	meta:
		aliases = "__GI_pthread_attr_init, pthread_attr_init"
		size = "80"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB E8 ?? ?? ?? ?? BA 00 00 20 00 48 98 C7 03 00 00 00 00 48 29 C2 48 89 43 18 C7 43 04 00 00 00 00 C7 43 08 00 00 00 00 C7 43 0C 01 00 00 00 31 C0 C7 43 10 00 00 00 00 48 C7 43 28 00 00 00 00 C7 43 20 00 00 00 00 48 89 53 30 5B C3 }
	condition:
		$pattern
}

rule pthread_call_handlers_a81ac55d5f5e3d98225d17ed728a16c6 {
	meta:
		aliases = "pthread_call_handlers"
		size = "19"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB EB 06 FF 13 48 8B 5B 08 48 85 DB 75 F5 5B C3 }
	condition:
		$pattern
}

rule clnt_perrno_b2f0703632b169ab18d09a7468662375 {
	meta:
		aliases = "clnt_pcreateerror, clnt_perror, __GI_clnt_perror, clnt_perrno"
		size = "25"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 8B 1D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 DE 48 89 C7 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __stdio_wcommit_314f827a584deaab30d40b60783adaa8 {
	meta:
		aliases = "__stdio_wcommit"
		size = "39"
		objfiles = "_wcommit@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 8B 47 18 48 89 FB 48 8B 77 08 48 89 C2 48 29 F2 74 09 48 89 77 18 E8 ?? ?? ?? ?? 48 8B 43 18 48 2B 43 08 5B C3 }
	condition:
		$pattern
}

rule xdrrec_destroy_0bb8c22692188e00a570ed7612b26041 {
	meta:
		aliases = "xdrrec_destroy"
		size = "23"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 8B 5F 18 48 8B 7B 08 E8 ?? ?? ?? ?? 48 89 DF 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_xdrrec_skiprecord_3a93b4b0b2d9afbec7bfb677582067bb {
	meta:
		aliases = "xdrrec_skiprecord, __GI_xdrrec_skiprecord"
		size = "78"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 8B 5F 18 EB 26 48 89 DF E8 39 FD FF FF 85 C0 74 37 83 7B 70 00 48 C7 43 68 00 00 00 00 75 0C 48 89 DF E8 38 FF FF FF 85 C0 74 1D 48 8B 73 68 48 85 F6 7F D1 83 7B 70 00 74 CB B8 01 00 00 00 C7 43 70 00 00 00 00 EB 02 31 C0 5B C3 }
	condition:
		$pattern
}

rule xdrrec_eof_46cf85a1f6b656710fd06606d53a6cc3 {
	meta:
		aliases = "__GI_xdrrec_eof, xdrrec_eof"
		size = "83"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 8B 5F 18 EB 26 48 89 DF E8 8C FD FF FF 85 C0 74 39 83 7B 70 00 48 C7 43 68 00 00 00 00 75 0C 48 89 DF E8 8B FF FF FF 85 C0 74 1F 48 8B 73 68 48 85 F6 7F D1 83 7B 70 00 74 CB 48 8B 43 60 48 39 43 58 0F 94 C0 0F B6 C0 EB 05 B8 01 00 00 00 5B C3 }
	condition:
		$pattern
}

rule __stdio_rfill_29e41ae8bf1c95009ec2a99306c8c084 {
	meta:
		aliases = "__stdio_rfill"
		size = "37"
		objfiles = "_rfill@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 8B 77 08 48 89 FB 48 8B 57 10 48 29 F2 E8 ?? ?? ?? ?? 48 8B 53 08 48 89 53 18 48 01 C2 48 89 53 20 5B C3 }
	condition:
		$pattern
}

rule _dl_strdup_31f8d290951bc8abe5165c7a5d73bab2 {
	meta:
		aliases = "_dl_strdup"
		size = "56"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 53 ) 48 8D 5F FF 48 89 D8 48 FF C0 80 38 00 75 F8 48 29 F8 8D 78 01 48 63 FF E8 ?? ?? ?? ?? 48 8D 50 FF 48 89 C1 48 FF C3 48 FF C2 8A 03 84 C0 88 02 75 F2 5B 48 89 C8 C3 }
	condition:
		$pattern
}

rule timer_settime_660b5f0604111f15e77bfe59f4b23b15 {
	meta:
		aliases = "timer_settime"
		size = "48"
		objfiles = "timer_settime@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 7F 04 48 63 F6 B8 DF 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule socketpair_394aeadc235e5017addddcd7999558fa {
	meta:
		aliases = "socketpair"
		size = "50"
		objfiles = "socketpair@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 D2 48 63 F6 48 63 FF B8 35 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule getsockopt_3e0351fdd58a862c67b351db8552b3e2 {
	meta:
		aliases = "getsockopt"
		size = "50"
		objfiles = "getsockopt@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 D2 48 63 F6 48 63 FF B8 37 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule epoll_ctl_974387a2d35da275bd05b6b5d3ef43d5 {
	meta:
		aliases = "epoll_ctl"
		size = "50"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 D2 48 63 F6 48 63 FF B8 E9 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule wait4_6f4a427f25f7667f0bf9f5f07f2be843 {
	meta:
		aliases = "__GI_wait4, wait4"
		size = "47"
		objfiles = "wait4@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 D2 48 63 FF B8 3D 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule quotactl_a4e3b6f0dde1387a834e312291595045 {
	meta:
		aliases = "quotactl"
		size = "47"
		objfiles = "quotactl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 D2 48 63 FF B8 B3 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule sendfile64_4961bb2695df9ae51f1d5037cb15cef2 {
	meta:
		aliases = "sendfile, sendfile64"
		size = "48"
		objfiles = "sendfile@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 F6 48 63 FF B8 28 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule query_module_7fdd7f517642d07d2e73fff58aac89f1 {
	meta:
		aliases = "query_module"
		size = "44"
		objfiles = "query_module@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 F6 B8 B2 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __syscall_rt_sigaction_3d620d1dbb95561714f63c673052a8d0 {
	meta:
		aliases = "__syscall_rt_sigaction"
		size = "44"
		objfiles = "__syscall_rt_sigaction@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 FF B8 0D 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule select_b5b4b9e4a081a252f3efd693d5a3b802 {
	meta:
		aliases = "__libc_select, __GI_select, select"
		size = "44"
		objfiles = "select@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 FF B8 17 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule prctl_c3986fa3b616a763a35d84f8224af553 {
	meta:
		aliases = "prctl"
		size = "44"
		objfiles = "prctl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 FF B8 9D 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule fgetxattr_d4226ef33f0330bf1a92ec81129e7257 {
	meta:
		aliases = "fgetxattr"
		size = "45"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 FF B8 C1 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule semtimedop_f130f5f2a30d70b549576f30e0f4f72d {
	meta:
		aliases = "semtimedop"
		size = "44"
		objfiles = "semtimedop@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 FF B8 DC 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __rt_sigtimedwait_be5caa029995178b4219fa45150f007e {
	meta:
		aliases = "__rt_sigtimedwait"
		size = "41"
		objfiles = "__rt_sigtimedwait@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA B8 80 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule mount_926e5cf95e4a84dde4df7048ed91b58c {
	meta:
		aliases = "mount"
		size = "41"
		objfiles = "mount@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA B8 A5 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule init_module_7e077ad9e7b9b846560e83442acf50bd {
	meta:
		aliases = "init_module"
		size = "41"
		objfiles = "init_module@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA B8 AF 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule getxattr_6a8d5c7162d4df9d84ec48588835c716 {
	meta:
		aliases = "getxattr"
		size = "42"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA B8 BF 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule lgetxattr_9951544ecede49eae9692ab7100f4571 {
	meta:
		aliases = "lgetxattr"
		size = "42"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA B8 C0 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule epoll_wait_30f8d4946fa3cdb78319cb1832291915 {
	meta:
		aliases = "epoll_wait"
		size = "47"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4C 63 D1 48 63 D2 48 63 FF B8 E8 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule recvfrom_74b3d32b05da33c15dcea04ddd28811d {
	meta:
		aliases = "__libc_recvfrom, __GI_recvfrom, recvfrom"
		size = "45"
		objfiles = "recvfrom@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4C 63 D1 48 63 FF B8 2D 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule msgsnd_45feec45ec38ec3b81c8f6b77b179c16 {
	meta:
		aliases = "msgsnd"
		size = "44"
		objfiles = "msgsnd@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4C 63 D1 48 63 FF B8 45 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule waitid_68a253b40cc9420fb29ae5bf8e9edcbf {
	meta:
		aliases = "waitid"
		size = "45"
		objfiles = "waitid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4C 63 D1 89 F6 89 FF B8 F7 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_mremap_98392e30af61aa70463f4bdc36cacfdc {
	meta:
		aliases = "mremap, __GI_mremap"
		size = "42"
		objfiles = "mremap@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4C 63 D1 B8 19 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule __ns_name_ntop_715504b9c46a2157b2028c4f94884f38 {
	meta:
		aliases = "__GI___ns_name_ntop, __ns_name_ntop"
		size = "376"
		objfiles = "ns_name@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4C 8D 1C 16 48 89 FB 49 89 F0 48 83 EC 10 E9 25 01 00 00 40 F6 C7 C0 0F 85 3C 01 00 00 49 39 F0 75 05 49 89 F0 EB 10 4D 39 D8 0F 83 29 01 00 00 41 C6 00 2E 49 FF C0 89 F8 49 8D 04 00 4C 39 D8 0F 83 13 01 00 00 48 FF C3 E9 E2 00 00 00 44 8A 0B 45 0F B6 D1 41 8D 4A DE 83 F9 3A 77 35 B8 01 00 00 00 48 BA 05 10 00 42 00 00 00 04 48 D3 E0 48 85 C2 74 1E 49 8D 40 01 4C 39 D8 0F 83 D7 00 00 00 41 C6 00 5C 45 88 48 01 49 83 C0 02 E9 98 00 00 00 41 8D 42 DF 83 F8 5D 0F 86 80 00 00 00 49 8D 40 03 4C 39 D8 0F 83 AC 00 00 00 66 45 0F B6 C9 BA 64 00 00 00 31 C9 44 89 C8 41 BA 64 00 00 00 41 C6 00 5C F6 }
	condition:
		$pattern
}

rule __dn_expand_4aad9398ec7f1344cc454c447883d7df {
	meta:
		aliases = "__dn_expand"
		size = "26"
		objfiles = "res_comp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4D 63 C0 48 89 CB E8 ?? ?? ?? ?? 85 C0 7E 08 80 3B 2E 75 03 C6 03 00 5B C3 }
	condition:
		$pattern
}

rule remap_file_pages_945d71fe0fd9be93e0573c799b3bd172 {
	meta:
		aliases = "remap_file_pages"
		size = "47"
		objfiles = "remap_file_pages@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4D 63 C0 49 89 CA 48 63 D2 B8 D8 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule msgrcv_48061a567bf02d5a7a91419734b1795a {
	meta:
		aliases = "msgrcv"
		size = "47"
		objfiles = "msgrcv@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4D 63 C0 49 89 CA 48 63 FF B8 46 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule fsetxattr_f9ad8f2ec9b41bf0bc05ecf486a341ce {
	meta:
		aliases = "fsetxattr"
		size = "47"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4D 63 C0 49 89 CA 48 63 FF B8 BE 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule setxattr_b58725ec1d5d48e8ecdda98964f2cb51 {
	meta:
		aliases = "setxattr"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4D 63 C0 49 89 CA B8 BC 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule lsetxattr_01baee926ef59dd51162a4c1f9cfaf00 {
	meta:
		aliases = "lsetxattr"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4D 63 C0 49 89 CA B8 BD 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_mmap_9f2f0479527a0506c699600891afa6d9 {
	meta:
		aliases = "mmap, __GI_mmap"
		size = "48"
		objfiles = "mmap@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4D 63 C0 4C 63 D1 48 63 D2 B8 09 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule mq_unlink_2ba0ecb21355ad33c4d94aac77ef9748 {
	meta:
		aliases = "mq_unlink"
		size = "86"
		objfiles = "mq_unlink@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 80 3F 2F 74 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 3E 48 FF C7 B8 F1 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 85 DB 89 D8 79 17 E8 ?? ?? ?? ?? 8B 10 B9 0D 00 00 00 83 FA 01 0F 44 D1 89 10 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule gcvt_0e415ed62e5ea1c438424674812e8ae3 {
	meta:
		aliases = "gcvt"
		size = "38"
		objfiles = "gcvt@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 FF 11 48 89 F3 BA 11 00 00 00 BE ?? ?? ?? ?? B8 01 00 00 00 0F 4E D7 48 89 DF E8 ?? ?? ?? ?? 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule connect_38112dbd0fb7c43959ab9ab69a43bb46 {
	meta:
		aliases = "__libc_connect, __GI_connect, connect"
		size = "43"
		objfiles = "connect@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 D2 48 63 FF B8 2A 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_bind_162c8cbd6a00ea9eb87437c0c148cdb8 {
	meta:
		aliases = "bind, __GI_bind"
		size = "43"
		objfiles = "bind@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 D2 48 63 FF B8 31 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule inotify_add_watch_c1324c655e7e9bf74d345c73c4fb989e {
	meta:
		aliases = "inotify_add_watch"
		size = "43"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 D2 48 63 FF B8 FE 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule fchown_cbcf948e1df81727997941b449010b40 {
	meta:
		aliases = "fchown"
		size = "45"
		objfiles = "fchown@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 D2 89 F6 48 63 FF B8 5D 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_setresuid_92ae15e1530905e4031eac7343a168ab {
	meta:
		aliases = "setresuid, __GI_setresuid"
		size = "44"
		objfiles = "setresuid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 D2 89 F6 89 FF B8 75 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule setresgid_976a020206ac01ca60ac94a74bd01e1f {
	meta:
		aliases = "__GI_setresgid, setresgid"
		size = "44"
		objfiles = "setresgid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 D2 89 F6 89 FF B8 77 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_chown_51d1d08e6d98db7a3583b7bf78437ada {
	meta:
		aliases = "chown, __GI_chown"
		size = "42"
		objfiles = "chown@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 D2 89 F6 B8 5C 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule lchown_0da9aa775aba99ffbcee77e724adaa29 {
	meta:
		aliases = "lchown"
		size = "42"
		objfiles = "lchown@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 D2 89 F6 B8 5E 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule ftok_45e5c1faaf26cd92d39af96655402674 {
	meta:
		aliases = "ftok"
		size = "55"
		objfiles = "ftok@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 F3 48 81 EC 90 00 00 00 48 89 E6 E8 ?? ?? ?? ?? 83 CA FF 85 C0 78 13 0F B6 04 24 0F B7 54 24 08 C1 E3 18 C1 E0 10 09 C2 09 DA 48 81 C4 90 00 00 00 89 D0 5B C3 }
	condition:
		$pattern
}

rule fchmod_205a7d1e1450e3a0d8bf8cebac338cce {
	meta:
		aliases = "fchmod"
		size = "43"
		objfiles = "fchmod@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 F6 48 63 FF B8 5B 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule inotify_rm_watch_a20a3b031279739593ab487005f6d049 {
	meta:
		aliases = "inotify_rm_watch"
		size = "43"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 F6 48 63 FF B8 FF 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_setreuid_733dd49297857f84439f6ced2634dd23 {
	meta:
		aliases = "setreuid, __GI_setreuid"
		size = "42"
		objfiles = "setreuid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 F6 89 FF B8 71 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule setregid_2c8f05c8b266b6602a1db52b3208b2f7 {
	meta:
		aliases = "__GI_setregid, setregid"
		size = "42"
		objfiles = "setregid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 F6 89 FF B8 72 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule getpriority_358a0656f549c77accf294684f253f5c {
	meta:
		aliases = "__GI_getpriority, getpriority"
		size = "57"
		objfiles = "getpriority@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 F6 89 FF B8 8C 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 85 DB 89 DA 78 09 B8 14 00 00 00 29 D8 89 C2 5B 89 D0 C3 }
	condition:
		$pattern
}

rule mkdir_9056c2adf3e8cc3fecc6053067f0ddda {
	meta:
		aliases = "__GI_mkdir, mkdir"
		size = "40"
		objfiles = "mkdir@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 F6 B8 53 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_chmod_c91f9d0dd2071821174bf152b5064a4a {
	meta:
		aliases = "chmod, __GI_chmod"
		size = "40"
		objfiles = "chmod@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 F6 B8 5A 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule delete_module_7d4e12fa03a8e9d5ea3a8162366d709c {
	meta:
		aliases = "delete_module"
		size = "40"
		objfiles = "delete_module@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 F6 B8 B0 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __pthread_internal_tsd_get_f010ec8a701dee428e6f2ad302dc470a {
	meta:
		aliases = "__pthread_internal_tsd_get"
		size = "21"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB 48 63 DB E8 9B FF FF FF 48 8B 84 D8 48 02 00 00 5B C3 }
	condition:
		$pattern
}

rule __pthread_internal_tsd_address_16fc46f4e77bb11261661baeff14cb3e {
	meta:
		aliases = "__pthread_internal_tsd_address"
		size = "21"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB 48 63 DB E8 B0 FF FF FF 48 8D 84 D8 48 02 00 00 5B C3 }
	condition:
		$pattern
}

rule __pthread_manager_adjust_prio_da100ec5aa4c94e96c172832e6fece58 {
	meta:
		aliases = "__pthread_manager_adjust_prio"
		size = "65"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB 48 83 EC 10 3B 3D ?? ?? ?? ?? 7E 2E BF 01 00 00 00 E8 ?? ?? ?? ?? 8D 53 01 39 C3 8B 3D ?? ?? ?? ?? BE 01 00 00 00 0F 4D D3 89 14 24 48 89 E2 E8 ?? ?? ?? ?? 89 1D ?? ?? ?? ?? 58 5A 5B C3 }
	condition:
		$pattern
}

rule getprotobynumber_d1b5b1d5dc18ca8e5706ca9dcb06f985 {
	meta:
		aliases = "getprotobynumber"
		size = "50"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB 48 83 EC 10 E8 5F FC FF FF 48 8B 15 ?? ?? ?? ?? 4C 8D 44 24 08 B9 19 11 00 00 89 DF BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 44 24 08 5A 59 5B C3 }
	condition:
		$pattern
}

rule verr_bc5c0a917a938d43cc792f244dc3dea3 {
	meta:
		aliases = "__GI_verrx, __GI_verr, verrx, verr"
		size = "21"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB 48 89 F7 48 89 D6 E8 ?? ?? ?? ?? 89 DF E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule closelog_intern_04167ca7a6c8c7818cf6e1d2ec7405d0 {
	meta:
		aliases = "closelog_intern"
		size = "86"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB 8B 3D ?? ?? ?? ?? 83 FF FF 74 05 E8 ?? ?? ?? ?? 85 DB C7 05 ?? ?? ?? ?? FF FF FF FF C7 05 ?? ?? ?? ?? 00 00 00 00 75 29 C7 05 ?? ?? ?? ?? 00 00 00 00 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 08 00 00 00 C7 05 ?? ?? ?? ?? FF 00 00 00 5B C3 }
	condition:
		$pattern
}

rule close_6fec519d3864178178ec959ae1a823e3 {
	meta:
		aliases = "close"
		size = "48"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB BF 01 00 00 00 48 83 EC 10 48 8D 74 24 0C E8 ?? ?? ?? ?? 89 DF E8 ?? ?? ?? ?? 8B 7C 24 0C 31 F6 89 C3 E8 ?? ?? ?? ?? 59 5E 89 D8 5B C3 }
	condition:
		$pattern
}

rule tcdrain_b73cccc4717fdec9e1209e9d1e9e5061 {
	meta:
		aliases = "tcdrain"
		size = "49"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB BF 01 00 00 00 48 83 EC 10 48 8D 74 24 0C E8 ?? ?? ?? ?? 89 DF E8 ?? ?? ?? ?? 8B 7C 24 0C 31 F6 89 C3 E8 ?? ?? ?? ?? 5F 41 58 89 D8 5B C3 }
	condition:
		$pattern
}

rule fsync_aac91fc9ecfd124be1d35fb5cd467432 {
	meta:
		aliases = "fsync"
		size = "48"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB BF 01 00 00 00 48 83 EC 10 48 8D 74 24 0C E8 ?? ?? ?? ?? 89 DF E8 ?? ?? ?? ?? 8B 7C 24 0C 89 C3 31 F6 E8 ?? ?? ?? ?? 89 D8 5B 5A 5B C3 }
	condition:
		$pattern
}

rule pthread_key_delete_54f3058f720d6219f30b7b29d8a41045 {
	meta:
		aliases = "pthread_key_delete"
		size = "160"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 FB FF 03 00 00 77 0F 89 D8 48 C1 E0 04 83 B8 ?? ?? ?? ?? 00 75 11 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 16 00 00 00 EB 69 83 3D ?? ?? ?? ?? FF C7 80 ?? ?? ?? ?? 00 00 00 00 48 C7 80 ?? ?? ?? ?? 00 00 00 00 74 3F E8 5A FD FF FF 41 89 D8 89 DF 48 89 C6 41 C1 E8 05 83 E7 1F 48 89 C2 80 7A 50 00 75 1A 44 89 C0 48 8B 8C C2 48 01 00 00 48 85 C9 74 0A 89 F8 48 C7 04 C1 00 00 00 00 48 8B 12 48 39 F2 75 D8 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 5B C3 }
	condition:
		$pattern
}

rule pthread_handle_sigcancel_060d2ac3b81dbfb1eb7a19b1e91e38ec {
	meta:
		aliases = "pthread_handle_sigcancel"
		size = "130"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB E8 2D F8 FF FF 48 3D ?? ?? ?? ?? 75 08 89 DF 5B E9 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 26 48 3B 05 ?? ?? ?? ?? 75 12 8B 3D ?? ?? ?? ?? BA 00 00 00 80 31 F6 E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 80 78 7A 00 74 33 80 78 78 00 75 2D 80 78 79 01 75 0C 48 89 E6 48 83 CF FF E8 ?? ?? ?? ?? 48 8B 78 48 48 85 FF 74 12 48 C7 40 48 00 00 00 00 BE 01 00 00 00 E8 ?? ?? ?? ?? 5B C3 }
	condition:
		$pattern
}

rule __GI_login_tty_d147fbb3b2c94cf975cfd6f208c333a8 {
	meta:
		aliases = "login_tty, __GI_login_tty"
		size = "80"
		objfiles = "login_tty@libutil.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB E8 ?? ?? ?? ?? 31 D2 31 C0 BE 0E 54 00 00 89 DF E8 ?? ?? ?? ?? 83 F8 FF 74 31 31 F6 89 DF E8 ?? ?? ?? ?? BE 01 00 00 00 89 DF E8 ?? ?? ?? ?? BE 02 00 00 00 89 DF E8 ?? ?? ?? ?? 31 C0 83 FB 02 7E 09 89 DF E8 ?? ?? ?? ?? 31 C0 5B C3 }
	condition:
		$pattern
}

rule raise_35f58cd14702758cbe09e3646a438697 {
	meta:
		aliases = "__GI_raise, raise"
		size = "38"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB E8 ?? ?? ?? ?? 89 DE 48 89 C7 E8 ?? ?? ?? ?? 89 C3 31 C0 85 DB 74 0A E8 ?? ?? ?? ?? 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule __GI_raise_e2704d2067d2413d752ef38f97c1cf95 {
	meta:
		aliases = "__raise, raise, __GI_raise"
		size = "18"
		objfiles = "raise@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB E8 ?? ?? ?? ?? 89 DE 89 C7 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_handle_sigrestart_6095d0afa36a65bc1e6bb77ff97c8a36 {
	meta:
		aliases = "pthread_handle_sigrestart"
		size = "32"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB E8 AB F7 FF FF 48 8B 78 40 89 58 38 48 85 FF 74 0A BE 01 00 00 00 E8 ?? ?? ?? ?? 5B C3 }
	condition:
		$pattern
}

rule __exit_handler_ec4af4dc08509d48441f818bbef1cb5d {
	meta:
		aliases = "__exit_handler"
		size = "100"
		objfiles = "__exit_handler@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB EB 48 FF C8 89 05 ?? ?? ?? ?? 48 98 48 C1 E0 05 48 03 05 ?? ?? ?? ?? 48 8B 10 48 83 FA 02 74 08 48 83 FA 03 75 24 EB 13 48 8B 50 08 48 85 D2 74 19 48 8B 70 10 89 DF FF D2 EB 0F 48 8B 50 08 48 85 D2 74 06 48 8B 78 10 FF D2 8B 05 ?? ?? ?? ?? 85 C0 75 AE 5B 48 8B 3D ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getitimer_c0cffa52a0cca455a53f79239c561de8 {
	meta:
		aliases = "getitimer"
		size = "40"
		objfiles = "getitimer@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FF B8 24 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_alarm_a5147f195f45212e8eaf7be700333ff0 {
	meta:
		aliases = "alarm, __GI_alarm"
		size = "40"
		objfiles = "alarm@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FF B8 25 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_setitimer_b6a1f0f10a1b0117a748a691e322d4f5 {
	meta:
		aliases = "setitimer, __GI_setitimer"
		size = "40"
		objfiles = "setitimer@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FF B8 26 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule umask_3162c6cce53b5b0e2fe4ebe74c12e0ad {
	meta:
		aliases = "umask"
		size = "40"
		objfiles = "umask@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FF B8 5F 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule getrlimit_caddc80ecb2b5a26053b890fc485daee {
	meta:
		aliases = "getrlimit64, __GI_getrlimit, getrlimit"
		size = "40"
		objfiles = "getrlimit@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FF B8 61 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule setuid_3c6dbd8893127b3c5a48dacde43b8783 {
	meta:
		aliases = "setuid"
		size = "40"
		objfiles = "setuid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FF B8 69 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule setgid_9bf684e280c2d7b9de77014dfebbf653 {
	meta:
		aliases = "setgid"
		size = "40"
		objfiles = "setgid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FF B8 6A 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule setfsuid_d5d1b9aff25ca07e4bf924b561c8f0d8 {
	meta:
		aliases = "setfsuid"
		size = "40"
		objfiles = "setfsuid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FF B8 7A 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule setfsgid_d89a75b93519befadb106e5e30dd1396 {
	meta:
		aliases = "setfsgid"
		size = "40"
		objfiles = "setfsgid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FF B8 7B 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule setrlimit_044d8d16b11d93d40152196a35b4d2fc {
	meta:
		aliases = "__GI_setrlimit, setrlimit64, setrlimit"
		size = "40"
		objfiles = "setrlimit@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FF B8 A0 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __stdio_trans2r_o_a7ed08d0258b3771c4e5db6415d25c07 {
	meta:
		aliases = "__stdio_trans2r_o"
		size = "90"
		objfiles = "_trans2r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 07 48 89 FB 0F B7 D0 85 D6 75 0D 81 E2 80 08 00 00 75 0C 09 F0 66 89 07 0F B7 03 A8 10 74 14 E8 ?? ?? ?? ?? C7 00 09 00 00 00 66 83 0B 08 83 C8 FF EB 23 A8 40 74 19 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 75 E6 48 8B 43 08 66 83 23 BF 48 89 43 30 66 83 0B 01 31 C0 5B C3 }
	condition:
		$pattern
}

rule __stdio_trans2w_o_7d94a5747318c2482641c6efc19a115a {
	meta:
		aliases = "__stdio_trans2w_o"
		size = "148"
		objfiles = "_trans2w@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 07 48 89 FB 0F B7 D0 85 D6 75 0D 81 E2 80 08 00 00 75 0C 09 F0 66 89 07 0F B7 03 A8 20 74 14 E8 ?? ?? ?? ?? C7 00 09 00 00 00 66 83 0B 08 83 CA FF EB 5B A8 03 74 41 A8 04 75 29 48 8B 53 18 48 39 53 20 75 04 A8 02 74 1B 25 00 04 00 00 48 89 DF 83 F8 01 19 D2 31 F6 83 C2 02 E8 ?? ?? ?? ?? 85 C0 75 C6 48 8B 43 08 66 83 23 FC 48 89 43 28 48 89 43 18 48 89 43 20 66 83 0B 40 31 D2 0F B7 03 F6 C4 0B 75 08 48 8B 43 10 48 89 43 30 5B 89 D0 C3 }
	condition:
		$pattern
}

rule __GI_dirfd_7433bc02f13993829951c36feb88eaa2 {
	meta:
		aliases = "dirfd, __GI_dirfd"
		size = "23"
		objfiles = "dirfd@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 1F 83 FB FF 75 0B E8 ?? ?? ?? ?? C7 00 09 00 00 00 89 D8 5B C3 }
	condition:
		$pattern
}

rule __pthread_mutex_unlock_d13f23a2f23b310028e114ce4e04b448 {
	meta:
		aliases = "pthread_mutex_unlock, __pthread_mutex_unlock"
		size = "127"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 47 10 48 89 FB 83 F8 01 74 19 7F 06 85 C0 74 36 EB 0A 83 F8 02 74 3A 83 F8 03 74 4F B8 16 00 00 00 EB 58 E8 91 FF FF FF 48 39 43 08 75 48 8B 43 04 85 C0 7E 09 FF C8 89 43 04 31 C0 EB 3D 48 C7 43 08 00 00 00 00 48 8D 7B 18 E8 ?? ?? ?? ?? EB E9 E8 63 FF FF FF 48 39 43 08 75 1A 48 83 7B 18 00 74 13 48 C7 43 08 00 00 00 00 48 8D 7B 18 E8 ?? ?? ?? ?? EB C4 B8 01 00 00 00 5B C3 }
	condition:
		$pattern
}

rule system_681a810d029bd247c601c425e9ec42f3 {
	meta:
		aliases = "__libc_system, system"
		size = "335"
		objfiles = "system@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 01 00 00 00 48 83 EC 30 48 85 FF 48 89 3C 24 0F 84 32 01 00 00 BE 01 00 00 00 BF 03 00 00 00 E8 ?? ?? ?? ?? BE 01 00 00 00 BF 02 00 00 00 48 89 44 24 08 E8 ?? ?? ?? ?? 31 F6 BF 11 00 00 00 48 89 44 24 10 E8 ?? ?? ?? ?? 48 89 44 24 18 E8 ?? ?? ?? ?? 83 F8 00 89 C3 7D 35 48 8B 74 24 08 BF 03 00 00 00 E8 ?? ?? ?? ?? 48 8B 74 24 10 BF 02 00 00 00 E8 ?? ?? ?? ?? 48 8B 74 24 18 BF 11 00 00 00 E8 ?? ?? ?? ?? 83 C8 FF E9 B8 00 00 00 75 4B 31 F6 BF 03 00 00 00 E8 ?? ?? ?? ?? 31 F6 BF 02 00 00 00 E8 ?? ?? ?? ?? 31 F6 BF 11 00 00 00 E8 ?? ?? ?? ?? 48 8B 0C 24 BF ?? ?? ?? ?? 45 31 C0 BA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule munmap_731f572df658bbf25431b734547bdab9 {
	meta:
		aliases = "__GI_munmap, munmap"
		size = "38"
		objfiles = "munmap@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 0B 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule pipe_c8ac57d0515c5c0c0878e36205e20f80 {
	meta:
		aliases = "__GI_pipe, pipe"
		size = "38"
		objfiles = "pipe@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 16 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule sched_yield_b2d3dd09f0ac25dd7ae988aee8dfa149 {
	meta:
		aliases = "sched_yield"
		size = "38"
		objfiles = "sched_yield@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 18 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule mincore_6fcc621cda0ad25046dfdb53e570d686 {
	meta:
		aliases = "mincore"
		size = "38"
		objfiles = "mincore@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 1B 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __libc_pause_f2da37ab6501d42f25ec99bac1c8f40b {
	meta:
		aliases = "pause, __libc_pause"
		size = "38"
		objfiles = "pause@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 22 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __libc_nanosleep_e4f8ab62efc2d7c5ad4bbd99230229e2 {
	meta:
		aliases = "nanosleep, __GI_nanosleep, __libc_nanosleep"
		size = "38"
		objfiles = "nanosleep@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 23 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_getpid_0f40364ebad8beae8392c01d0d3b08f6 {
	meta:
		aliases = "getpid, __libc_getpid, __GI_getpid"
		size = "38"
		objfiles = "getpid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 27 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __libc_fork_6c680adadd5584219a39eae18e28dfb5 {
	meta:
		aliases = "__GI_fork, fork, __libc_fork"
		size = "38"
		objfiles = "fork@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 39 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_execve_239305b7034b518a3dc13c27c7cbde6a {
	meta:
		aliases = "execve, __GI_execve"
		size = "38"
		objfiles = "execve@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 3B 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_uname_41ae40ae263bd891d117d03ecc10a4a8 {
	meta:
		aliases = "uname, __GI_uname"
		size = "38"
		objfiles = "uname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 3F 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule shmdt_0f15edfe2afe40cbb3108add3db2e2ab {
	meta:
		aliases = "shmdt"
		size = "38"
		objfiles = "shmdt@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 43 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule truncate_0bbcf77b49c7faf81d42e51d75aeeab1 {
	meta:
		aliases = "__GI_truncate, truncate"
		size = "38"
		objfiles = "truncate@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 4C 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_chdir_a018a749281199e89f89e6edf9d640f1 {
	meta:
		aliases = "chdir, __GI_chdir"
		size = "38"
		objfiles = "chdir@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 50 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule rename_f2308255e69e9ba27dda162bc95eb868 {
	meta:
		aliases = "rename"
		size = "38"
		objfiles = "rename@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 52 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_rmdir_5b90c040e3890f9a65235e2e5c0ef89b {
	meta:
		aliases = "rmdir, __GI_rmdir"
		size = "38"
		objfiles = "rmdir@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 54 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule link_71b7814ca54a3821abfa206d5c1da6a3 {
	meta:
		aliases = "link"
		size = "38"
		objfiles = "link@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 56 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_unlink_297bf42451fdc70e3d2844dc866a9057 {
	meta:
		aliases = "unlink, __GI_unlink"
		size = "38"
		objfiles = "unlink@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 57 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule symlink_2ef218e8b1a5e4d5b22d320e0008c181 {
	meta:
		aliases = "symlink"
		size = "38"
		objfiles = "symlink@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 58 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule readlink_3e5501f5f103ab81d96262b39fbb491d {
	meta:
		aliases = "__GI_readlink, readlink"
		size = "39"
		objfiles = "readlink@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 59 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_gettimeofday_de9553582bbcff13af8f3852fc7e1126 {
	meta:
		aliases = "gettimeofday, __GI_gettimeofday"
		size = "38"
		objfiles = "gettimeofday@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 60 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule sysinfo_1449fe58e85716c13ef57e358f29b9ec {
	meta:
		aliases = "sysinfo"
		size = "38"
		objfiles = "sysinfo@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 63 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_times_2be76c4221cdae4b0af83f15f5443d53 {
	meta:
		aliases = "times, __GI_times"
		size = "39"
		objfiles = "times@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 64 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_getuid_b43276c0b0a410bcae5b953dcf8c3351 {
	meta:
		aliases = "getuid, __GI_getuid"
		size = "38"
		objfiles = "getuid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 66 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_getgid_88d855c1890ddaa64b720b77b063113e {
	meta:
		aliases = "getgid, __GI_getgid"
		size = "38"
		objfiles = "getgid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 68 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_geteuid_d1e6f3f1bff1671e16b93d00cc653a56 {
	meta:
		aliases = "geteuid, __GI_geteuid"
		size = "38"
		objfiles = "geteuid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 6B 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule getegid_36abac95b813331ef0be0c3e71fed9c1 {
	meta:
		aliases = "__GI_getegid, getegid"
		size = "38"
		objfiles = "getegid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 6C 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule getppid_c52743a83804f4c9c9598633da7edefe {
	meta:
		aliases = "getppid"
		size = "38"
		objfiles = "getppid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 6E 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule getpgrp_e6a982044f5b2f0684f2641f00c5a920 {
	meta:
		aliases = "getpgrp"
		size = "38"
		objfiles = "getpgrp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 6F 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule setsid_9eec519a23f841711d11c6892f957020 {
	meta:
		aliases = "__GI_setsid, setsid"
		size = "38"
		objfiles = "setsid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 70 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule setgroups_43bfc6223d135b4bbb058d09287407e3 {
	meta:
		aliases = "__GI_setgroups, setgroups"
		size = "38"
		objfiles = "setgroups@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 74 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule capget_477c7db202f893f879211609d916a9c1 {
	meta:
		aliases = "capget"
		size = "38"
		objfiles = "capget@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 7D 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule capset_9e0b6b9bb78b67b50c0201f5cfa3eed4 {
	meta:
		aliases = "capset"
		size = "38"
		objfiles = "capset@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 7E 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule sigaltstack_64b0a741f1ab0d3a5de11179f89e01f7 {
	meta:
		aliases = "sigaltstack"
		size = "38"
		objfiles = "sigaltstack@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 83 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_utime_f5fb7f62a134c762c8aa06df45fc3518 {
	meta:
		aliases = "utime, __GI_utime"
		size = "38"
		objfiles = "utime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 84 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule personality_c4ec0307d4a6fb7d8e042301dc2dc241 {
	meta:
		aliases = "personality"
		size = "38"
		objfiles = "personality@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 87 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule statfs_1c126f3a5c8190dbec554e371451a4c0 {
	meta:
		aliases = "__GI_statfs, __GI___libc_statfs, __libc_statfs, statfs"
		size = "38"
		objfiles = "statfs@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 89 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule mlock_f06357df0e8409e9bdf7683952f3a30b {
	meta:
		aliases = "mlock"
		size = "38"
		objfiles = "mlock@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 95 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule munlock_1a7548a415836695578d9402fceac357 {
	meta:
		aliases = "munlock"
		size = "38"
		objfiles = "munlock@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 96 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule munlockall_636d73716c293058dc6b0cffeb1002d4 {
	meta:
		aliases = "munlockall"
		size = "38"
		objfiles = "munlockall@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 98 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule vhangup_26edec2e97d076da03aa811b2be5aba4 {
	meta:
		aliases = "vhangup"
		size = "38"
		objfiles = "vhangup@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 99 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule pivot_root_28e7d0d964d87827e2867865e7b1f5e5 {
	meta:
		aliases = "pivot_root"
		size = "38"
		objfiles = "pivot_root@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 9B 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule ntp_adjtime_08da88dfe846731763b76ad7709c3c8a {
	meta:
		aliases = "adjtimex, __GI_adjtimex, ntp_adjtime"
		size = "38"
		objfiles = "adjtimex@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 9F 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule mbrtowc_497c2998aa82b9fd0d57917889375115 {
	meta:
		aliases = "__GI_mbrtowc, mbrtowc"
		size = "113"
		objfiles = "mbrtowc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 ?? ?? ?? ?? 48 89 FB 48 83 EC 20 48 85 C9 48 0F 44 C8 48 85 F6 75 0E 48 8D 74 24 1F 31 DB C6 44 24 1F 00 EB 0A 80 3E 00 74 3A 48 85 D2 74 35 48 89 74 24 08 48 8D 7C 24 10 48 8D 74 24 08 48 83 CA FF 49 89 C8 B9 01 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C2 78 0F 48 85 DB 74 0A 8B 44 24 10 89 03 EB 02 31 D2 48 83 C4 20 48 89 D0 5B C3 }
	condition:
		$pattern
}

rule __old_sem_wait_b644d0bd08613d876a65b056c5ddf429 {
	meta:
		aliases = "__old_sem_wait"
		size = "346"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) B8 ?? ?? ?? ?? 48 89 FB 48 83 EC 30 48 3B 25 ?? ?? ?? ?? 48 89 E2 73 46 48 3B 25 ?? ?? ?? ?? 72 0E 48 3B 25 ?? ?? ?? ?? B8 ?? ?? ?? ?? 72 2F 83 3D ?? ?? ?? ?? 00 74 18 E8 ?? ?? ?? ?? EB 1F 48 8B 44 24 28 48 8B 40 10 48 89 01 E9 E9 00 00 00 48 81 CA FF FF 1F 00 48 8D 82 01 FD FF FF 48 89 44 24 28 48 C7 44 24 10 00 00 00 00 48 C7 44 24 18 ?? ?? ?? ?? 48 8B 7C 24 28 48 8D 74 24 10 E8 39 FF FF FF 48 8B 0B 48 83 F9 01 48 8D 51 FE 0F 95 C0 84 C1 75 0E 48 8B 54 24 28 48 8B 44 24 28 48 89 48 10 48 89 C8 F0 48 0F B1 13 0F 94 C1 84 C9 74 D1 80 E2 01 0F 85 89 00 00 00 48 8B 7C 24 28 E8 ?? ?? ?? ?? 48 }
	condition:
		$pattern
}

rule chroot_3eb1180273b67b73ed136c5869d54629 {
	meta:
		aliases = "chroot"
		size = "38"
		objfiles = "chroot@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 A1 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule sync_99a84973b3ebd009840ed86b25cde8e8 {
	meta:
		aliases = "sync"
		size = "32"
		objfiles = "sync@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 A2 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0B E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 5B C3 }
	condition:
		$pattern
}

rule acct_ba46d60da3be9a466ca5210b04359d2c {
	meta:
		aliases = "acct"
		size = "38"
		objfiles = "acct@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 A3 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule settimeofday_f8f60aacfb550c923fad36170db2dcc0 {
	meta:
		aliases = "__GI_settimeofday, settimeofday"
		size = "38"
		objfiles = "settimeofday@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 A4 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule swapoff_8e3cbab69703767e8b0e57229721cd8f {
	meta:
		aliases = "swapoff"
		size = "38"
		objfiles = "swapoff@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 A8 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule sethostname_eed2d888ebc316e4c5afbbb5b3a506cc {
	meta:
		aliases = "sethostname"
		size = "38"
		objfiles = "sethostname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 AA 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule setdomainname_4f28b1f736d5b57556845976281c29c3 {
	meta:
		aliases = "setdomainname"
		size = "38"
		objfiles = "setdomainname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 AB 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule create_module_6ad26d9e8d2370a8d7d3bf67f7d231f3 {
	meta:
		aliases = "create_module"
		size = "39"
		objfiles = "create_module@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 AE 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule get_kernel_syms_27dc27291fdfedf64945f53b0f4fb664 {
	meta:
		aliases = "get_kernel_syms"
		size = "38"
		objfiles = "get_kernel_syms@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 B1 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule listxattr_67408ed33eb8da20a5d5d71c077822f3 {
	meta:
		aliases = "listxattr"
		size = "39"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 C2 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule llistxattr_fc7514359f829aa27c8a05386dd60b8e {
	meta:
		aliases = "llistxattr"
		size = "39"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 C3 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule removexattr_4ba6a2d557919742b070e84dfa7b2289 {
	meta:
		aliases = "removexattr"
		size = "38"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 C5 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule lremovexattr_9a006d1bee75b8a3bc950315e8d43413 {
	meta:
		aliases = "lremovexattr"
		size = "38"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 C6 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_time_17cce0a6bc9ba1669ae6f31bd88f8e2d {
	meta:
		aliases = "time, __GI_time"
		size = "39"
		objfiles = "time@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 C9 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule timer_gettime_e2f02cb5b7a6b60499e8a646c70c4001 {
	meta:
		aliases = "timer_gettime"
		size = "42"
		objfiles = "timer_gettime@librt.a"
	strings:
		$pattern = { ( CC | 53 ) B8 E0 00 00 00 48 63 7F 04 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule timer_getoverrun_56c371bd69e751d90a9051829ea86d32 {
	meta:
		aliases = "timer_getoverrun"
		size = "42"
		objfiles = "timer_getoverr@librt.a"
	strings:
		$pattern = { ( CC | 53 ) B8 E1 00 00 00 48 63 7F 04 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_utimes_2b4067b3cf6e48a7db31ee0a120e7e20 {
	meta:
		aliases = "utimes, __GI_utimes"
		size = "38"
		objfiles = "utimes@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 EB 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule inotify_init_34286d15ace3aa23b5328d699ba9cb46 {
	meta:
		aliases = "inotify_init"
		size = "38"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 FD 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule xdrstdio_getint32_d298edb949e590656474ce21c5de17d5 {
	meta:
		aliases = "xdrstdio_getint32"
		size = "58"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA 01 00 00 00 48 89 F3 BE 04 00 00 00 48 83 EC 10 48 8B 4F 18 48 8D 44 24 0C 48 89 C7 E8 ?? ?? ?? ?? 31 D2 48 FF C8 75 0A 8B 44 24 0C B2 01 0F C8 89 03 59 5E 5B 89 D0 C3 }
	condition:
		$pattern
}

rule xdrstdio_getlong_de49b831a3cdd838c91e365d5c2ff740 {
	meta:
		aliases = "xdrstdio_getlong"
		size = "63"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA 01 00 00 00 48 89 F3 BE 04 00 00 00 48 83 EC 10 48 8B 4F 18 48 8D 44 24 0C 48 89 C7 E8 ?? ?? ?? ?? 31 D2 48 FF C8 75 0D 8B 44 24 0C B2 01 0F C8 89 C0 48 89 03 41 58 41 59 5B 89 D0 C3 }
	condition:
		$pattern
}

rule set_input_fragment_697d1936a8436a95b308024b2203590f {
	meta:
		aliases = "set_input_fragment"
		size = "76"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA 04 00 00 00 48 89 FB 48 83 EC 10 48 8D 74 24 0C E8 88 FF FF FF 85 C0 74 29 8B 54 24 0C 0F CA 89 D0 89 54 24 0C C1 E8 1F 85 D2 89 43 70 74 13 48 89 D0 25 FF FF FF 7F 48 89 43 68 B8 01 00 00 00 EB 02 31 C0 41 59 41 5A 5B C3 }
	condition:
		$pattern
}

rule utmpname_5b1745300f788821d00b2605280e8995 {
	meta:
		aliases = "utmpname"
		size = "136"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? 48 89 FB BE ?? ?? ?? ?? 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 DB 74 30 48 8B 3D ?? ?? ?? ?? 48 81 FF ?? ?? ?? ?? 74 05 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 85 C0 48 0F 45 D0 48 89 15 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 83 FF FF 74 05 E8 ?? ?? ?? ?? 48 89 E7 BE 01 00 00 00 C7 05 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 48 83 C4 20 31 C0 5B C3 }
	condition:
		$pattern
}

rule __GI_closelog_360dbc0a82e4483e780117add1912d22 {
	meta:
		aliases = "closelog, __GI_closelog"
		size = "59"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 FF E8 82 FF FF FF BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule setgrent_63f1914dc9b6c5c4d25d775c102131bc {
	meta:
		aliases = "setspent, setpwent, setgrent"
		size = "69"
		objfiles = "getpwent_r@libc.a, getgrent_r@libc.a, getspent_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 85 FF 74 05 E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule endnetent_f174803963fbe04ea05a4923c07341ba {
	meta:
		aliases = "__GI_endnetent, endnetent"
		size = "90"
		objfiles = "getnetent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 85 FF 74 10 E8 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 48 89 E7 BE 01 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule endprotoent_d7e3fd16505c9238e0851a2064f1f0bc {
	meta:
		aliases = "__GI_endprotoent, endservent, __GI_endservent, endprotoent"
		size = "90"
		objfiles = "getproto@libc.a, getservice@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 85 FF 74 10 E8 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 BE 01 00 00 00 48 89 E7 C7 05 ?? ?? ?? ?? 00 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule endpwent_335155307178b13d6c68d900ad3e4402 {
	meta:
		aliases = "endspent, endgrent, endpwent"
		size = "80"
		objfiles = "getpwent_r@libc.a, getgrent_r@libc.a, getspent_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 85 FF 74 10 E8 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule endhostent_35a2a6e1f0045ddd9b0f4a8c3f9f7cac {
	meta:
		aliases = "endhostent"
		size = "90"
		objfiles = "gethostent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 48 85 FF 74 10 E8 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule __new_exitfn_6fe4a3f629abcc307320c862bf9f4234 {
	meta:
		aliases = "__new_exitfn"
		size = "176"
		objfiles = "__exit_handler@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? FF C0 39 C2 7D 39 8D 72 14 48 8B 3D ?? ?? ?? ?? 48 63 F6 48 C1 E6 05 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 75 0D E8 ?? ?? ?? ?? C7 00 0C 00 00 00 EB 3C 83 05 ?? ?? ?? ?? 14 48 89 05 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 48 63 D8 FF C0 48 C1 E3 05 48 03 1D ?? ?? ?? ?? 89 05 ?? ?? ?? ?? 48 C7 03 01 00 00 00 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule endutent_791f8b0e2f6563e92104db313d99e98f {
	meta:
		aliases = "endutent"
		size = "78"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 83 FF FF 74 05 E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 C7 05 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule setutent_25c042dbb6261da8ba89c85b06d4ce70 {
	meta:
		aliases = "__GI_setutent, setutent"
		size = "57"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 73 FD FF FF BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule __GI_random_3775a38b8149f5b2dc0670a1263fa1ca {
	meta:
		aliases = "random, __GI_random"
		size = "72"
		objfiles = "random@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 83 EC 30 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 74 24 2C BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 63 44 24 2C 48 83 C4 30 5B C3 }
	condition:
		$pattern
}

rule gethostent_834b5dd26d68ada79211ab4d7d8c9b2d {
	meta:
		aliases = "gethostent"
		size = "90"
		objfiles = "gethostent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 83 EC 30 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 4C 24 28 49 89 C0 BA B2 00 00 00 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 8B 44 24 28 48 83 C4 30 5B C3 }
	condition:
		$pattern
}

rule _create_xid_5e1cb2d4db675b8fce7488cc3501bcc6 {
	meta:
		aliases = "_create_xid"
		size = "123"
		objfiles = "create_xid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 83 EC 40 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 75 2A 48 8D 7C 24 20 31 F6 E8 ?? ?? ?? ?? 48 8B 7C 24 28 48 33 7C 24 20 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 01 00 00 00 48 8D 74 24 38 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 8B 44 24 38 48 83 C4 40 5B C3 }
	condition:
		$pattern
}

rule getmntent_54aeada02e838e9de789a7da7daf6a62 {
	meta:
		aliases = "getmntent"
		size = "123"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 FB 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 3D ?? ?? ?? ?? 00 75 1B BF 00 10 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 75 05 E8 ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? 48 89 DF B9 00 10 00 00 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 E7 48 89 C3 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule pututline_b3fba6858fac004010d4c421898e6f02 {
	meta:
		aliases = "pututline"
		size = "158"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 FB 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? BA 01 00 00 00 48 C7 C6 70 FE FF FF E8 ?? ?? ?? ?? 48 89 DF E8 53 FF FF FF 48 85 C0 BA 01 00 00 00 48 C7 C6 70 FE FF FF 75 07 BA 02 00 00 00 31 F6 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 48 89 DE BA 90 01 00 00 E8 ?? ?? ?? ?? 48 3D 90 01 00 00 B8 00 00 00 00 48 89 E7 48 0F 45 D8 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule setprotoent_353389afcffdbe91369d812b6a0deaa9 {
	meta:
		aliases = "__GI_setservent, __GI_setprotoent, __GI_setnetent, setnetent, setservent, setprotoent"
		size = "115"
		objfiles = "getproto@libc.a, getservice@libc.a, getnetent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 89 FB 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 85 FF 75 18 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? EB 05 E8 ?? ?? ?? ?? 85 DB B8 01 00 00 00 0F 44 05 ?? ?? ?? ?? 48 89 E7 BE 01 00 00 00 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule __GI___uClibc_fini_2d094a893495abb64d424b53f1ba86df {
	meta:
		aliases = "__uClibc_fini, __GI___uClibc_fini"
		size = "70"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BB ?? ?? ?? ?? 48 81 EB ?? ?? ?? ?? 48 C1 FB 03 EB 07 FF 14 DD ?? ?? ?? ?? 48 FF CB 48 83 FB FF 75 F0 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 02 FF D0 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 07 5B 49 89 C3 41 FF E3 5B C3 }
	condition:
		$pattern
}

rule mkdtemp_c747dea29d52de80b92ecd738363985c {
	meta:
		aliases = "mkdtemp"
		size = "30"
		objfiles = "mkdtemp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BE 02 00 00 00 48 89 FB E8 ?? ?? ?? ?? 85 C0 B8 00 00 00 00 48 0F 45 D8 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule mktemp_d5c3e148bbb7f84f0f00630a8982165f {
	meta:
		aliases = "mktemp"
		size = "26"
		objfiles = "mktemp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BE 03 00 00 00 48 89 FB E8 ?? ?? ?? ?? 85 C0 79 03 C6 03 00 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule sigpending_e70aacfd4da9dc2fa94ef47de06dbbdc {
	meta:
		aliases = "sigpending"
		size = "43"
		objfiles = "sigpending@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BE 08 00 00 00 B8 7F 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_sigsuspend_78a15d6def642fe31383c88456ae82a6 {
	meta:
		aliases = "sigsuspend, __libc_sigsuspend, __GI_sigsuspend"
		size = "43"
		objfiles = "sigsuspend@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BE 08 00 00 00 B8 82 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule pause_0a71118d4e3c0894659f7c19c737b677 {
	meta:
		aliases = "pause"
		size = "44"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) BF 01 00 00 00 48 83 EC 10 48 8D 74 24 0C E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 7C 24 0C 31 F6 89 C3 E8 ?? ?? ?? ?? 5A 59 89 D8 5B C3 }
	condition:
		$pattern
}

rule get_current_dir_name_8ad3a8606e21746258f044a0e7fbdbd0 {
	meta:
		aliases = "get_current_dir_name"
		size = "120"
		objfiles = "getdirname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BF ?? ?? ?? ?? 48 81 EC 20 01 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 4C 48 8D B4 24 90 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 75 36 48 89 E6 48 89 DF E8 ?? ?? ?? ?? 85 C0 75 27 48 8B 84 24 90 00 00 00 48 39 04 24 75 19 48 8B 84 24 98 00 00 00 48 39 44 24 08 75 0A 48 89 DF E8 ?? ?? ?? ?? EB 09 31 F6 31 FF E8 ?? ?? ?? ?? 48 81 C4 20 01 00 00 5B C3 }
	condition:
		$pattern
}

rule __GI_abort_558560691cd7d3c39a0e5a9d73696796 {
	meta:
		aliases = "abort, __GI_abort"
		size = "276"
		objfiles = "abort@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BF ?? ?? ?? ?? 48 81 EC 20 01 00 00 E8 ?? ?? ?? ?? BA 10 00 00 00 EB 0F 48 63 C2 48 C7 84 C4 A0 00 00 00 00 00 00 00 FF CA 79 ED 48 8D 9C 24 A0 00 00 00 BE 06 00 00 00 48 89 DF E8 ?? ?? ?? ?? 85 C0 75 0F 31 D2 48 89 DE BF 01 00 00 00 E8 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 75 28 C7 05 ?? ?? ?? ?? 01 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF 06 00 00 00 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 83 F8 01 75 54 BA 98 00 00 00 48 89 E7 31 F6 C7 05 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? BA 10 00 00 00 48 C7 04 24 00 00 00 00 EB 0C 48 63 C2 48 C7 44 C4 08 FF FF FF FF FF CA 79 F0 }
	condition:
		$pattern
}

rule getrpcent_670e03b4c39f0d540fe3c9ab45332eb2 {
	meta:
		aliases = "__GI_getrpcent, getrpcent"
		size = "56"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) E8 59 FE FF FF 48 85 C0 48 89 C3 74 26 48 83 38 00 75 17 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 03 74 09 48 89 DF 5B E9 93 FE FF FF 5B 31 C0 C3 }
	condition:
		$pattern
}

rule endrpcent_c59588c7853f3faa3d21cf0ed9aca717 {
	meta:
		aliases = "__GI_endrpcent, endrpcent"
		size = "59"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) E8 65 FD FF FF 48 85 C0 48 89 C3 74 2B 83 78 14 00 75 25 48 8B 78 08 E8 ?? ?? ?? ?? 48 8B 3B 48 C7 43 08 00 00 00 00 48 85 FF 74 0C E8 ?? ?? ?? ?? 48 C7 03 00 00 00 00 5B C3 }
	condition:
		$pattern
}

rule __pthread_reset_main_thread_ad1dc362f47d899a17dd1aa5714546ab {
	meta:
		aliases = "__pthread_reset_main_thread"
		size = "140"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) E8 87 FD FF FF 83 3D ?? ?? ?? ?? FF 48 89 C3 74 4C 48 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 48 C7 05 ?? ?? ?? ?? 00 00 00 00 E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? FF FF FF FF C7 05 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 89 43 28 48 89 1D ?? ?? ?? ?? 48 89 1B 48 89 5B 08 48 C7 83 80 00 00 00 ?? ?? ?? ?? 48 C7 83 90 00 00 00 ?? ?? ?? ?? 5B C3 }
	condition:
		$pattern
}

rule _buf_35082f46dcedf2fb58637e5fa7fa2965 {
	meta:
		aliases = "_buf"
		size = "45"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 53 ) E8 ?? ?? ?? ?? 48 83 B8 B8 00 00 00 00 48 89 C3 75 11 BF 00 01 00 00 E8 ?? ?? ?? ?? 48 89 83 B8 00 00 00 48 8B 83 B8 00 00 00 5B C3 }
	condition:
		$pattern
}

rule svc_exit_f57330cb3c2c745f78ffb8c84e09c457 {
	meta:
		aliases = "svc_exit"
		size = "37"
		objfiles = "svc_run@libc.a"
	strings:
		$pattern = { ( CC | 53 ) E8 ?? ?? ?? ?? 48 8B 38 48 89 C3 E8 ?? ?? ?? ?? 48 C7 03 00 00 00 00 E8 ?? ?? ?? ?? C7 00 00 00 00 00 5B C3 }
	condition:
		$pattern
}

rule __rpc_thread_clnt_cleanup_24a747c6e94559c408b62e9b599dcc5e {
	meta:
		aliases = "__rpc_thread_clnt_cleanup"
		size = "44"
		objfiles = "clnt_simple@libc.a"
	strings:
		$pattern = { ( CC | 53 ) E8 ?? ?? ?? ?? 48 8B 98 C8 00 00 00 48 85 DB 74 18 48 8B 3B 48 85 FF 74 07 48 8B 47 08 FF 50 20 48 89 DF 5B E9 ?? ?? ?? ?? 5B C3 }
	condition:
		$pattern
}

rule svcraw_create_b972b7a33d18f68bc9e4eca8442f41b0 {
	meta:
		aliases = "svcraw_create"
		size = "121"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 53 ) E8 ?? ?? ?? ?? 48 8B 98 F8 00 00 00 48 85 DB 75 19 BE 70 25 00 00 BF 01 00 00 00 E8 ?? ?? ?? ?? 48 89 C3 31 C0 48 85 DB 74 4C 48 8D 83 E0 23 00 00 48 8D BB B0 23 00 00 C7 83 60 22 00 00 00 00 00 00 66 C7 83 64 22 00 00 00 00 48 C7 83 68 22 00 00 ?? ?? ?? ?? B9 02 00 00 00 48 89 83 90 22 00 00 BA 60 22 00 00 48 89 DE E8 ?? ?? ?? ?? 48 8D 83 60 22 00 00 5B C3 }
	condition:
		$pattern
}

rule freeaddrinfo_5d159e3c02b0282edd39ae3e4bb10317 {
	meta:
		aliases = "__GI_freeaddrinfo, freeaddrinfo"
		size = "22"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { ( CC | 53 ) EB 0C 48 8B 5F 28 E8 ?? ?? ?? ?? 48 89 DF 48 85 FF 75 EF 5B C3 }
	condition:
		$pattern
}

rule __GI_ilogb_6b33920a5d8410af9523320a1a9b1968 {
	meta:
		aliases = "ilogb, __GI_ilogb"
		size = "118"
		objfiles = "s_ilogb@libm.a"
	strings:
		$pattern = { ( CC | 53 ) F2 0F 11 44 24 F8 48 8B 4C 24 F8 48 89 C8 48 C1 E8 20 89 C2 81 E2 FF FF FF 7F 81 FA FF FF 0F 00 7F 39 48 89 C8 89 D3 B9 01 00 00 80 09 C3 74 41 85 D2 B9 ED FB FF FF 74 06 EB 0A FF C9 01 C0 85 C0 7F F8 EB 2C 89 D0 B9 02 FC FF FF C1 E0 0B EB 04 FF C9 01 C0 85 C0 7F F8 EB 16 81 FA FF FF EF 7F B9 FF FF FF 7F 7F 09 C1 FA 14 8D 8A 01 FC FF FF 5B 89 C8 C3 }
	condition:
		$pattern
}

rule __GI_cbrt_88fe052cec60b555703fd8be45495af5 {
	meta:
		aliases = "cbrt, __GI_cbrt"
		size = "411"
		objfiles = "s_cbrt@libm.a"
	strings:
		$pattern = { ( CC | 53 ) F2 0F 11 44 24 F8 48 8B 54 24 F8 48 89 D0 48 C1 E8 20 89 C6 89 C1 81 E6 00 00 00 80 31 F1 81 F9 FF FF EF 7F 7E 09 F2 0F 58 C0 E9 69 01 00 00 F2 0F 11 44 24 F8 48 8B 5C 24 F8 89 CA 09 DA 48 89 D8 0F 84 51 01 00 00 48 89 CA 83 E0 FF 48 C1 E2 20 48 09 D0 81 F9 FF FF 0F 00 48 89 44 24 F8 66 0F 12 44 24 F8 0F 28 D8 7F 49 48 B8 00 00 00 00 00 00 50 43 66 48 0F 6E C0 F2 0F 59 C3 F2 0F 11 44 24 F8 48 8B 54 24 F8 48 89 D0 48 89 D1 BA 03 00 00 00 89 D3 48 C1 E8 20 31 D2 F7 F3 83 E1 FF 05 93 78 7F 29 48 C1 E0 20 48 09 C1 48 89 4C 24 F8 EB 1D 89 C8 BA 03 00 00 00 89 D3 99 F7 FB 89 C1 8D 81 93 78 9F 2A }
	condition:
		$pattern
}

rule __fpclassify_10dbbe32c2e6d1927040456476ab87bf {
	meta:
		aliases = "__GI___fpclassify, __fpclassify"
		size = "71"
		objfiles = "s_fpclassify@libm.a"
	strings:
		$pattern = { ( CC | 53 ) F2 0F 11 44 24 F8 48 8B 54 24 F8 48 89 D0 48 C1 EA 20 89 D1 81 E2 00 00 F0 7F 81 E1 FF FF 0F 00 89 D3 09 C1 B8 02 00 00 00 09 CB 74 17 85 D2 B0 03 74 11 81 FA 00 00 F0 7F B0 04 75 07 31 C0 85 C9 0F 94 C0 5B C3 }
	condition:
		$pattern
}

rule __ieee754_fmod_55b72eb6a822493976bc04f778a676d5 {
	meta:
		aliases = "__ieee754_fmod"
		size = "709"
		objfiles = "e_fmod@libm.a"
	strings:
		$pattern = { ( CC | 53 ) F2 0F 11 44 24 F8 48 8B 54 24 F8 F2 0F 11 4C 24 F8 48 8B 4C 24 F8 48 89 D0 48 C1 EA 20 41 89 C1 48 89 C8 48 C1 E9 20 41 89 C8 41 89 D3 89 D7 41 81 E0 FF FF FF 7F 41 81 E3 00 00 00 80 41 89 C2 44 89 C3 44 31 DF 09 C3 0F 94 C2 81 FF FF FF EF 7F 0F 9F C0 08 C2 75 15 44 89 D0 F7 D8 44 09 D0 C1 E8 1F 44 09 C0 3D 00 00 F0 7F 76 0D F2 0F 59 C1 F2 0F 5E C0 E9 48 02 00 00 44 39 C7 7F 1A 0F 9C C2 45 39 D1 0F 92 C0 08 C2 0F 85 32 02 00 00 45 39 D1 0F 84 F3 01 00 00 81 FF FF FF 0F 00 7F 2E 85 FF 44 89 C8 BA ED FB FF FF 74 06 EB 0A FF CA 01 C0 85 C0 7F F8 EB 21 89 F8 BA 02 FC FF FF C1 E0 0B EB 04 FF CA }
	condition:
		$pattern
}

rule modff_3ec89df3fa893e9dcae34401331dca33 {
	meta:
		aliases = "modff"
		size = "40"
		objfiles = "modff@libm.a"
	strings:
		$pattern = { ( CC | 53 ) F3 0F 5A C0 48 89 FB 48 83 EC 10 48 8D 7C 24 08 E8 ?? ?? ?? ?? F2 0F 5A 4C 24 08 F2 0F 5A C0 F3 0F 11 0B 58 5A 5B C3 }
	condition:
		$pattern
}

rule __scan_getc_708509817fad99d2ce6021619190d6ae {
	meta:
		aliases = "__scan_getc"
		size = "67"
		objfiles = "__scan_cookie@libc.a"
	strings:
		$pattern = { ( CC | 53 ) FF 4F 14 48 89 FB 83 7F 14 00 C7 07 FF FF FF FF 79 09 80 4F 1D 02 83 C8 FF EB 25 80 7F 1D 00 75 13 FF 53 30 83 F8 FF 75 06 80 4B 1D 02 EB 11 89 43 04 EB 04 C6 47 1D 00 8B 43 04 FF 43 10 89 03 5B C3 }
	condition:
		$pattern
}

rule scan_getwc_0ddc443e5cf890c8589d87fc4a0e084a {
	meta:
		aliases = "scan_getwc"
		size = "127"
		objfiles = "vfwscanf@libc.a"
	strings:
		$pattern = { ( CC | 53 ) FF 4F 14 48 89 FB 83 7F 14 00 C7 47 28 FF FF FF FF 79 06 80 4F 1D 02 EB 2A 80 7F 1D 00 75 4E 48 8B 7F 08 83 7F 04 FD 75 1F 48 8B 47 18 48 3B 47 10 73 0C 8B 10 48 83 C0 04 48 89 47 18 EB 1B C6 43 1D 02 83 C8 FF EB 34 E8 ?? ?? ?? ?? 83 F8 FF 89 C2 75 06 80 4B 1D 02 EB 22 48 8B 43 08 C6 43 1E 01 89 53 04 8A 40 02 88 43 1C EB 04 C6 47 1D 00 8B 43 04 FF 43 10 89 43 28 31 C0 5B C3 }
	condition:
		$pattern
}

rule byte_regex_compile_900bd016df9c4d217a22fa20e573e689 {
	meta:
		aliases = "byte_regex_compile"
		size = "11329"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 01 C2 89 E5 57 56 53 81 EC 6C 01 00 00 89 85 D8 FE FF FF 89 45 F0 8B 45 08 89 8D D4 FE FF FF 89 95 04 FF FF FF 8B 40 14 89 85 08 FF FF FF C7 04 24 80 02 00 00 E8 ?? ?? ?? ?? 85 C0 89 C3 0F 84 D9 01 00 00 8B 55 08 8B 8D D4 FE FF FF 80 62 1C 97 89 4A 0C A1 ?? ?? ?? ?? C7 42 08 00 00 00 00 C7 42 18 00 00 00 00 85 C0 0F 84 D2 01 00 00 8B 75 08 89 9D 3C FF FF FF 8B 7E 04 85 FF 0F 84 4C 01 00 00 8B 75 08 31 C0 89 85 50 FF FF FF 31 C0 89 85 40 FF FF FF 31 C0 89 85 14 FF FF FF 31 C0 8B 3E 89 85 10 FF FF FF 31 C0 89 85 34 FF FF FF B8 20 00 00 00 89 85 38 FF FF FF 89 BD 0C FF FF FF 8B 45 F0 39 85 04 }
	condition:
		$pattern
}

rule __ieee754_sqrt_9c216cc83184b72be38543240036cd0f {
	meta:
		aliases = "__ieee754_sqrt"
		size = "435"
		objfiles = "e_sqrt@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 0F 28 C8 53 F2 0F 11 44 24 F8 48 8B 54 24 F8 48 89 D0 48 C1 EA 20 89 C6 89 D0 25 00 00 F0 7F 3D 00 00 F0 7F 75 0D F2 0F 59 C1 F2 0F 58 C8 E9 79 01 00 00 85 D2 7F 20 89 D0 25 FF FF FF 7F 09 F0 0F 84 66 01 00 00 85 D2 74 0D F2 0F 5C C8 F2 0F 5E C9 E9 55 01 00 00 41 89 D0 31 C0 41 C1 F8 14 74 0D EB 36 89 F2 83 E8 15 C1 E6 15 C1 EA 0B 85 D2 74 F1 31 FF EB 04 01 D2 FF C7 F7 C2 00 00 10 00 74 F4 29 F8 B9 20 00 00 00 29 F9 44 8D 40 01 89 F0 D3 E8 89 F9 09 C2 D3 E6 41 8D 98 01 FC FF FF 81 E2 FF FF 0F 00 81 CA 00 00 10 00 F6 C3 01 74 0A 89 F0 01 F6 C1 E8 1F 8D 14 50 89 F0 45 31 C9 01 F6 C1 E8 1F 45 }
	condition:
		$pattern
}

rule __ieee754_atanh_5fdf36c38866992565e3c5b171e822f0 {
	meta:
		aliases = "__ieee754_atanh"
		size = "281"
		objfiles = "e_atanh@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 0F 28 D0 53 48 83 EC 08 F2 0F 11 04 24 48 8B 04 24 48 89 C5 48 89 C2 F7 D8 48 C1 ED 20 09 D0 89 E9 C1 E8 1F 81 E1 FF FF FF 7F 09 C8 3D 00 00 F0 3F 76 0D F2 0F 5C D0 F2 0F 5E D2 E9 D1 00 00 00 81 F9 00 00 F0 3F 75 0D F2 0F 5E 15 ?? ?? ?? ?? E9 BC 00 00 00 81 F9 FF FF 2F 3E 7F 16 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 0F 87 9E 00 00 00 F2 0F 11 14 24 48 8B 14 24 48 BB 00 00 00 00 00 00 E0 3F 48 89 D0 48 89 CA 48 C1 E2 20 83 E0 FF 48 09 D0 81 F9 FF FF DF 3F 48 89 04 24 48 B8 00 00 00 00 00 00 F0 3F 66 0F 12 04 24 0F 28 D8 0F 28 D0 F2 0F 58 D8 7F 21 0F 28 CB 48 89 04 24 F2 0F 59 C8 66 }
	condition:
		$pattern
}

rule __GI_atan_36c47f571e504105475511b870a7cdc9 {
	meta:
		aliases = "atan, __GI_atan"
		size = "510"
		objfiles = "s_atan@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 0F 28 D8 53 48 83 EC 08 F2 0F 11 04 24 48 8B 14 24 48 89 D5 48 89 D0 48 C1 ED 20 89 EB 81 E3 FF FF FF 7F 81 FB FF FF 0F 44 7E 36 81 FB 00 00 F0 7F 7F 0C 0F 94 C2 85 C0 0F 95 C0 84 D0 74 09 F2 0F 58 DB E9 AE 01 00 00 B8 ?? ?? ?? ?? 85 ED BA ?? ?? ?? ?? 48 0F 4E C2 66 0F 12 18 E9 95 01 00 00 81 FB FF FF DB 3F 7F 27 81 FB FF FF 1F 3E 0F 8F AD 00 00 00 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 0F 87 6B 01 00 00 E9 92 00 00 00 E8 ?? ?? ?? ?? 81 FB FF FF F2 3F 0F 28 C8 7F 41 81 FB FF FF E5 3F 66 0F 12 05 ?? ?? ?? ?? 7F 1B 0F 28 D9 31 C0 F2 0F 58 D9 F2 0F 58 0D ?? ?? ?? ?? F2 0F 5C D8 F2 0F }
	condition:
		$pattern
}

rule __ieee754_j1_b5c922e18411daeb8245792f27035e16 {
	meta:
		aliases = "__ieee754_j1"
		size = "567"
		objfiles = "e_j1@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 0F 28 D8 53 48 83 EC 38 F2 0F 11 44 24 08 48 8B 54 24 08 48 89 D5 48 C1 ED 20 89 EB 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 11 66 0F 12 25 ?? ?? ?? ?? F2 0F 5E E0 E9 F1 01 00 00 81 FB FF FF FF 3F 0F 8E 2B 01 00 00 E8 ?? ?? ?? ?? F2 0F 11 44 24 28 E8 ?? ?? ?? ?? F2 0F 11 44 24 30 66 0F 12 44 24 28 E8 ?? ?? ?? ?? F2 0F 11 44 24 10 81 FB FF FF DF 7F 66 0F 12 44 24 30 66 0F 12 4C 24 30 66 0F 57 05 ?? ?? ?? ?? F2 0F 5C 4C 24 10 F2 0F 5C 44 24 10 F2 0F 11 4C 24 20 F2 0F 11 44 24 18 7F 3F 66 0F 12 44 24 28 F2 0F 58 C0 E8 ?? ?? ?? ?? 66 0F 12 4C 24 30 F2 0F 59 4C 24 10 66 0F 2E 0D ?? ?? ?? ?? 76 0E }
	condition:
		$pattern
}

rule __ieee754_asin_c7b967c3f38a37dff2c3b7984a0014fe {
	meta:
		aliases = "__ieee754_asin"
		size = "681"
		objfiles = "e_asin@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 0F 28 D8 53 48 83 EC 48 F2 0F 11 44 24 08 48 8B 54 24 08 48 89 D5 48 C1 ED 20 89 EB 81 E3 FF FF FF 7F 81 FB FF FF EF 3F 7E 30 8D 83 00 00 10 C0 09 D0 75 19 F2 0F 59 05 ?? ?? ?? ?? F2 0F 59 1D ?? ?? ?? ?? F2 0F 58 D8 E9 51 02 00 00 F2 0F 5C D8 F2 0F 5E DB E9 44 02 00 00 81 FB FF FF DF 3F 0F 8F B9 00 00 00 81 FB FF FF 3F 3E 66 0F 12 25 ?? ?? ?? ?? 7F 17 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E C4 0F 87 16 02 00 00 E9 92 00 00 00 0F 28 D0 F2 0F 59 D0 0F 28 CA 0F 28 C2 F2 0F 59 0D ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? F2 0F 58 0D ?? ?? ?? ?? F2 0F 5C 05 ?? ?? ?? ?? F2 0F 59 CA F2 0F 59 C2 F2 0F 5C 0D ?? }
	condition:
		$pattern
}

rule __GI_erfc_56727873216500e67e10b0fb0a25e677 {
	meta:
		aliases = "erfc, __GI_erfc"
		size = "1151"
		objfiles = "s_erf@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 0F 28 D8 53 48 83 EC 58 F2 0F 11 44 24 08 48 8B 54 24 08 48 89 D5 48 C1 ED 20 89 EB 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 23 C1 ED 1F 66 0F 12 05 ?? ?? ?? ?? 8D 44 2D 00 F2 0F 5E C3 89 C0 F2 48 0F 2A C8 F2 0F 58 C8 E9 27 04 00 00 81 FB FF FF EA 3F 0F 8F CE 00 00 00 81 FB FF FF 6F 3C 66 0F 12 25 ?? ?? ?? ?? 7F 0C 0F 28 CC F2 0F 5C C8 E9 FF 03 00 00 0F 28 C8 81 FD FF FF CF 3F F2 0F 59 C8 0F 28 C1 0F 28 D1 F2 0F 59 05 ?? ?? ?? ?? F2 0F 59 15 ?? ?? ?? ?? F2 0F 58 05 ?? ?? ?? ?? F2 0F 5C 15 ?? ?? ?? ?? F2 0F 59 C1 F2 0F 59 D1 F2 0F 58 05 ?? ?? ?? ?? F2 0F 5C 15 ?? ?? ?? ?? F2 0F 59 C1 F2 0F 59 }
	condition:
		$pattern
}

rule __GI_erf_7d953babc3d8ac3402fc4ce020a9c4c8 {
	meta:
		aliases = "erf, __GI_erf"
		size = "1138"
		objfiles = "s_erf@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 0F 28 D8 53 48 83 EC 58 F2 0F 11 44 24 08 48 8B 54 24 08 48 89 D5 48 C1 ED 20 89 EB 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 27 C1 ED 1F BA 01 00 00 00 66 0F 12 05 ?? ?? ?? ?? 8D 44 2D 00 F2 0F 5E C3 29 C2 F2 0F 2A D2 F2 0F 58 D0 E9 16 04 00 00 81 FB FF FF EA 3F 0F 8F D6 00 00 00 81 FB FF FF 2F 3E 7F 3C 81 FB FF FF 7F 00 7F 24 0F 28 D0 F2 0F 59 1D ?? ?? ?? ?? F2 0F 59 15 ?? ?? ?? ?? F2 0F 58 D3 F2 0F 59 15 ?? ?? ?? ?? E9 D6 03 00 00 0F 28 D0 F2 0F 59 15 ?? ?? ?? ?? E9 89 00 00 00 0F 28 C8 F2 0F 59 C8 0F 28 C1 0F 28 D1 F2 0F 59 05 ?? ?? ?? ?? F2 0F 59 15 ?? ?? ?? ?? F2 0F 58 05 ?? ?? ?? ?? F2 }
	condition:
		$pattern
}

rule __ieee754_acos_7de2ebb29ffcfe93e7c8b6a7b70e6a82 {
	meta:
		aliases = "__ieee754_acos"
		size = "818"
		objfiles = "e_acos@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 0F 28 E8 53 48 83 EC 38 F2 0F 11 44 24 08 48 8B 54 24 08 48 89 D1 48 C1 E9 20 89 C8 25 FF FF FF 7F 3D FF FF EF 3F 7E 32 2D 00 00 F0 3F 09 D0 75 19 B8 ?? ?? ?? ?? FF C9 BA ?? ?? ?? ?? 48 0F 4D C2 66 0F 12 20 E9 DD 02 00 00 0F 28 E0 F2 0F 5C E0 F2 0F 5E E4 E9 CD 02 00 00 3D FF FF DF 3F 0F 8F D2 00 00 00 3D 00 00 60 3C 48 B8 18 2D 44 54 FB 21 F9 3F 7F 10 48 89 44 24 08 66 0F 12 64 24 08 E9 A1 02 00 00 0F 28 D0 48 89 44 24 08 66 0F 12 64 24 08 F2 0F 59 D0 0F 28 CA 0F 28 C2 F2 0F 59 0D ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? F2 0F 58 0D ?? ?? ?? ?? F2 0F 5C 05 ?? ?? ?? ?? F2 0F 59 CA F2 0F 59 C2 F2 }
	condition:
		$pattern
}

rule __GI_fdopen_748f3c8a063f9a12e0925dd24248683a {
	meta:
		aliases = "fdopen, __GI_fdopen"
		size = "54"
		objfiles = "fdopen@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 31 C0 48 89 F5 BE 03 00 00 00 53 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 48 63 F8 48 83 FF FF 74 10 41 58 89 D9 48 89 EE 31 D2 5B 5D E9 ?? ?? ?? ?? 5A 5B 5D 31 C0 C3 }
	condition:
		$pattern
}

rule xdrmem_putbytes_87acccbe24ba9a537c32256f02d3824f {
	meta:
		aliases = "xdrmem_putbytes"
		size = "50"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 31 C0 48 89 FD 53 48 83 EC 08 8B 4F 28 39 D1 72 1C 29 D1 89 D3 89 4F 28 48 8B 7F 18 48 89 DA E8 ?? ?? ?? ?? 48 01 5D 18 B8 01 00 00 00 5A 5B 5D C3 }
	condition:
		$pattern
}

rule htab_remove_elt_with_hash_21b26893b45cdd055875afc566035acc {
	meta:
		aliases = "htab_remove_elt_with_hash"
		size = "82"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 31 C0 89 E5 83 EC 18 89 44 24 0C 8B 45 10 89 75 FC 8B 75 08 89 5D F8 89 44 24 08 8B 45 0C 89 34 24 89 44 24 04 E8 ?? ?? ?? ?? 8B 10 89 C3 85 D2 74 15 8B 46 08 85 C0 74 05 89 14 24 FF D0 FF 46 18 C7 03 01 00 00 00 8B 5D F8 8B 75 FC 89 EC 5D C3 }
	condition:
		$pattern
}

rule splay_tree_new_02efc82c57bc959f11bcc942eeb08a87 {
	meta:
		aliases = "splay_tree_new"
		size = "57"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 31 C0 89 E5 83 EC 18 89 44 24 14 B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 89 44 24 10 8B 45 10 89 4C 24 0C 89 44 24 08 8B 45 0C 89 44 24 04 8B 45 08 89 04 24 E8 ?? ?? ?? ?? C9 C3 }
	condition:
		$pattern
}

rule __check_one_fd_2d87797fbc91abdbb8eaf5d7597fe286 {
	meta:
		aliases = "__check_one_fd"
		size = "53"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 31 C0 89 FD 53 89 F3 BE 01 00 00 00 48 83 EC 08 E8 ?? ?? ?? ?? FF C0 75 17 31 C0 89 DE BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 39 E8 74 05 E8 ?? ?? ?? ?? 58 5B 5D C3 }
	condition:
		$pattern
}

rule higher_prime_index_1586999ee89a54d875f7e94b079af947 {
	meta:
		aliases = "higher_prime_index"
		size = "107"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 31 C9 89 E5 56 89 C6 53 BB 1E 00 00 00 83 EC 10 EB 06 89 D3 39 D9 74 1D 89 D8 29 C8 D1 E8 8D 14 08 89 D0 C1 E0 04 3B B0 ?? ?? ?? ?? 76 E4 8D 4A 01 39 D9 75 E3 89 C8 C1 E0 04 39 B0 ?? ?? ?? ?? 72 09 83 C4 10 89 C8 5B 5E 5D C3 B8 ?? ?? ?? ?? 89 44 24 04 A1 ?? ?? ?? ?? 89 74 24 08 89 04 24 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule split_directories_1ed81523503501022d25dee3db5fe0fa {
	meta:
		aliases = "split_directories"
		size = "272"
		objfiles = "make_relative_prefix@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 31 C9 89 E5 57 56 53 89 C3 83 EC 0C 89 55 EC 0F B6 10 84 D2 74 26 40 80 FA 2F 75 F3 41 80 38 2F 75 ED 8D B6 00 00 00 00 8D BC 27 00 00 00 00 40 80 38 2F 74 FA 0F B6 10 84 D2 75 DA 8D 04 8D 08 00 00 00 89 04 24 E8 ?? ?? ?? ?? 85 C0 89 45 F0 74 65 8B 75 F0 89 D8 31 FF 8D B6 00 00 00 00 0F B6 13 43 84 D2 74 15 90 8D B4 26 00 00 00 00 80 FA 2F 74 4F 0F B6 13 43 84 D2 75 F3 89 DA 29 C2 83 FA 01 7E 0D 4A E8 24 FF FF FF 8B 55 F0 89 04 BA 47 8B 55 F0 8D 04 BD 00 00 00 00 8B 4C 02 FC C7 04 02 00 00 00 00 85 C9 74 4B 8B 45 EC 85 C0 74 05 8B 45 EC 89 38 8B 45 F0 83 C4 0C 5B 5E 5F 5D C3 43 80 3B 2F 74 }
	condition:
		$pattern
}

rule dyn_string_prepend_cstr_1ca868ecbb40d529392c04b89e6ca9d1 {
	meta:
		aliases = "dyn_string_prepend, dyn_string_prepend_cstr"
		size = "32"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 31 C9 89 E5 83 EC 18 8B 45 0C 89 4C 24 04 89 44 24 08 8B 45 08 89 04 24 E8 ?? ?? ?? ?? C9 C3 }
	condition:
		$pattern
}

rule cplus_demangle_set_style_376235843f70d36b243959136c70cba2 {
	meta:
		aliases = "cplus_demangle_set_style"
		size = "44"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 31 C9 89 E5 8B 45 08 83 F8 FF 75 0A EB 16 90 83 C1 0C 39 C2 74 0E 8B 91 ?? ?? ?? ?? 85 D2 75 EF 5D 31 C0 C3 5D A3 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule updwtmp_f10f237ac4e24ec2038767db3693e53c {
	meta:
		aliases = "updwtmp"
		size = "87"
		objfiles = "wtent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 31 D2 31 C0 48 89 F5 BE 01 04 00 00 53 48 83 EC 08 E8 ?? ?? ?? ?? 85 C0 89 C3 78 36 31 D2 BE 01 00 00 00 89 C7 E8 ?? ?? ?? ?? 85 C0 75 24 48 89 EE 89 DF BA 90 01 00 00 E8 ?? ?? ?? ?? 89 DF 31 D2 31 F6 E8 ?? ?? ?? ?? 5A 89 DF 5B 5D E9 ?? ?? ?? ?? 58 5B 5D C3 }
	condition:
		$pattern
}

rule sort_pointers_06034e94ed1eec4a3b980da67643ef47 {
	meta:
		aliases = "sort_pointers"
		size = "326"
		objfiles = "sort@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 31 D2 89 E5 31 C0 57 56 53 81 EC 3C 04 00 00 8B 75 0C 8B 7D 10 C1 E0 08 01 D0 42 83 FA 04 75 F5 89 45 F0 31 DB 0F B6 45 F0 89 9D DC FB FF FF 88 85 DB FB FF FF 8B 45 08 C1 E0 02 80 BD DB FB FF FF 00 89 85 E0 FB FF FF 8D 85 F4 FB FF FF 89 85 D4 FB FF FF 8D 45 F0 89 85 D0 FB FF FF 0F 85 C9 00 00 00 8B 8D DC FB FF FF B8 04 00 00 00 29 C8 89 45 F0 31 C0 BA 00 04 00 00 89 44 24 04 8D 85 F0 FB FF FF 89 54 24 08 89 04 24 E8 ?? ?? ?? ?? 8B 8D E0 FB FF FF 8B 45 F0 01 F1 8D 14 06 8D 1C 08 39 DA 73 11 0F B6 02 83 C2 04 FF 84 85 F0 FB FF FF 39 D3 77 EF 8B 85 D0 FB FF FF 39 85 D4 FB FF FF 73 1B 8D 95 F8 }
	condition:
		$pattern
}

rule dyn_string_eq_c1b792ad11644b740ba79823004c5c88 {
	meta:
		aliases = "dyn_string_eq"
		size = "65"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 31 D2 89 E5 53 83 EC 14 8B 4D 08 8B 5D 0C 8B 41 04 3B 43 04 74 09 83 C4 14 89 D0 5B 5D C3 90 8B 51 08 8B 43 08 89 14 24 89 44 24 04 E8 ?? ?? ?? ?? 31 D2 85 C0 0F 94 C2 83 C4 14 5B 89 D0 5D C3 }
	condition:
		$pattern
}

rule splay_tree_successor_d2a7762cb0dd1ba34a809b10a8a4d0f7 {
	meta:
		aliases = "splay_tree_successor"
		size = "98"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 31 D2 89 E5 56 53 83 EC 10 8B 5D 08 8B 75 0C 8B 03 85 C0 74 1D 89 F2 89 D8 E8 31 FA FF FF 89 74 24 04 8B 03 8B 00 89 04 24 FF 53 04 85 C0 7E 0F 8B 13 83 C4 10 89 D0 5B 5E 5D C3 8D 74 26 00 8B 03 8B 50 0C 85 D2 75 09 EB E8 90 8D 74 26 00 89 C2 8B 42 08 85 C0 75 F7 83 C4 10 89 D0 5B 5E 5D C3 }
	condition:
		$pattern
}

rule splay_tree_predecessor_05c67010329a589ccda506daf0c32450 {
	meta:
		aliases = "splay_tree_predecessor"
		size = "93"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 31 D2 89 E5 56 53 83 EC 10 8B 5D 08 8B 75 0C 8B 03 85 C0 74 33 89 F2 89 D8 E8 91 FA FF FF 89 74 24 04 8B 03 8B 00 89 04 24 FF 53 04 85 C0 78 21 8B 03 8B 50 08 85 D2 75 08 EB 0D 8D 74 26 00 89 C2 8B 42 0C 85 C0 75 F7 83 C4 10 89 D0 5B 5E 5D C3 8B 13 83 C4 10 5B 5E 89 D0 5D C3 }
	condition:
		$pattern
}

rule pex_one_b2a28c452ee6f03f8b43b6dae46376ed {
	meta:
		aliases = "pex_one"
		size = "169"
		objfiles = "pex_one@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 31 D2 89 E5 83 EC 28 8B 45 14 89 5D F4 89 75 F8 89 7D FC 8B 7D 24 89 54 24 08 89 44 24 04 C7 04 24 00 00 00 00 E8 ?? ?? ?? ?? 89 7C 24 18 89 C6 8B 45 1C 89 34 24 89 44 24 14 8B 45 18 89 44 24 10 8B 45 10 89 44 24 0C 8B 45 0C 89 44 24 08 8B 45 08 89 44 24 04 E8 ?? ?? ?? ?? 85 C0 89 C3 74 1E 89 34 24 E8 ?? ?? ?? ?? 89 D8 8B 75 F8 8B 5D F4 8B 7D FC 89 EC 5D C3 8D B4 26 00 00 00 00 8B 45 20 89 34 24 89 44 24 08 B8 01 00 00 00 89 44 24 04 E8 ?? ?? ?? ?? 85 C0 75 C6 BB ?? ?? ?? ?? C7 07 00 00 00 00 EB B9 }
	condition:
		$pattern
}

rule tmpfile_8cb70446911c26228b25aea9deb1543e {
	meta:
		aliases = "tmpfile64, tmpfile"
		size = "101"
		objfiles = "tmpfile@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 31 D2 B9 ?? ?? ?? ?? BE FF 0F 00 00 53 48 81 EC 08 10 00 00 48 89 E7 E8 ?? ?? ?? ?? 85 C0 75 35 31 F6 48 89 E7 E8 ?? ?? ?? ?? 85 C0 89 C5 78 25 48 89 E7 E8 ?? ?? ?? ?? BE ?? ?? ?? ?? 89 EF E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 75 0B 89 EF E8 ?? ?? ?? ?? EB 02 31 DB 48 89 D8 48 81 C4 08 10 00 00 5B 5D C3 }
	condition:
		$pattern
}

rule rindex_d66962a54c3282d1091d77823c6ae289 {
	meta:
		aliases = "__GI_strrchr, strrchr, rindex"
		size = "52"
		objfiles = "strrchr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 31 ED 53 40 0F B6 DE 48 83 EC 08 85 DB 75 11 59 5B 5D 31 F6 E9 ?? ?? ?? ?? 48 8D 78 01 48 89 C5 89 DE E8 ?? ?? ?? ?? 48 85 C0 75 ED 5A 5B 48 89 E8 5D C3 }
	condition:
		$pattern
}

rule __GI_globfree_7e9f6ba40cbaffbaa6b5c647f90944a6 {
	meta:
		aliases = "globfree, __GI_globfree64, globfree64, __GI_globfree"
		size = "70"
		objfiles = "glob@libc.a, glob64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 31 ED 53 48 89 FB 48 83 EC 08 48 83 7F 08 00 75 1A EB 2E 48 89 E8 48 03 43 10 48 8B 3C C7 48 85 FF 74 05 E8 ?? ?? ?? ?? 48 FF C5 48 3B 2B 48 8B 7B 08 72 DF E8 ?? ?? ?? ?? 48 C7 43 08 00 00 00 00 58 5B 5D C3 }
	condition:
		$pattern
}

rule join_extricate_func_2b6450e53c385b1e5d5c99131fe9dc59 {
	meta:
		aliases = "join_extricate_func"
		size = "72"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 31 ED 53 48 89 FB 48 83 EC 18 E8 AB FF FF FF 48 89 44 24 10 48 8B 74 24 10 48 89 DF E8 ?? ?? ?? ?? 48 8B 43 10 48 89 DF 48 83 78 68 00 48 C7 40 68 00 00 00 00 40 0F 95 C5 E8 ?? ?? ?? ?? 48 83 C4 18 89 E8 5B 5D C3 }
	condition:
		$pattern
}

rule pthread_free_b3503cd02197f34be3bae30a3ccf6aa5 {
	meta:
		aliases = "pthread_free"
		size = "194"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 31 F6 48 89 FD 53 48 83 EC 08 48 8B 47 20 25 FF 03 00 00 48 C1 E0 05 48 8D 98 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 DF 48 C7 43 10 00 00 00 00 48 C7 43 18 FF FF FF FF E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? FF C8 89 05 ?? ?? ?? ?? 48 8B BD E0 02 00 00 EB 0B 48 8B 1F E8 ?? ?? ?? ?? 48 89 DF 48 85 FF 75 F0 48 8B BD E8 02 00 00 EB 0B 48 8B 1F E8 ?? ?? ?? ?? 48 89 DF 48 85 FF 75 F0 48 81 FD ?? ?? ?? ?? 74 36 83 BD 80 02 00 00 00 75 2D 48 8B B5 90 02 00 00 48 85 F6 74 0C 48 8B BD 88 02 00 00 E8 ?? ?? ?? ?? 41 58 5B 48 8D BD 00 03 E0 FF BE 00 00 20 00 5D E9 ?? ?? ?? ?? 59 5B 5D C3 }
	condition:
		$pattern
}

rule __GI_pthread_cond_signal_2d9f287a2a688358cb6be096b01810f9 {
	meta:
		aliases = "pthread_cond_signal, __GI_pthread_cond_signal"
		size = "75"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 31 F6 48 89 FD 53 48 83 EC 08 E8 ?? ?? ?? ?? 48 8B 5D 10 48 85 DB 74 10 48 8B 43 10 48 89 45 10 48 C7 43 10 00 00 00 00 48 89 EF E8 ?? ?? ?? ?? 48 85 DB 74 0F C6 83 D1 02 00 00 01 48 89 DF E8 AB FB FF FF 5E 5B 5D 31 C0 C3 }
	condition:
		$pattern
}

rule __pthread_wait_for_restart_sig_30cc65ba695402206766d9b3da29fa92 {
	meta:
		aliases = "__pthread_wait_for_restart_signal"
		size = "77"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 31 F6 48 89 FD BF 02 00 00 00 53 48 81 EC 88 00 00 00 48 89 E2 E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? C7 45 38 00 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 8B 45 38 3B 05 ?? ?? ?? ?? 75 ED 48 81 C4 88 00 00 00 5B 5D C3 }
	condition:
		$pattern
}

rule pthread_cond_broadcast_3974ccf27c64e258fc334324da669c95 {
	meta:
		aliases = "__GI_pthread_cond_broadcast, pthread_cond_broadcast"
		size = "79"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 31 F6 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 48 8B 6B 10 48 89 DF 48 C7 43 10 00 00 00 00 E8 ?? ?? ?? ?? EB 1E 48 8B 5D 10 C6 85 D1 02 00 00 01 48 C7 45 10 00 00 00 00 48 89 EF 48 89 DD E8 B7 FF FF FF 48 85 ED 75 DD 59 5B 5D 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_rwlock_unlock_5171446e74c4b4f2cd65caa775b42c6b {
	meta:
		aliases = "pthread_rwlock_unlock"
		size = "345"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 31 F6 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 48 8B 6B 18 48 85 ED 74 7D E8 F4 FC FF FF 48 39 C5 75 7A 83 7B 30 00 48 C7 43 18 00 00 00 00 74 2E 48 8B 6B 28 48 85 ED 74 25 48 8B 45 10 48 89 DF 48 89 43 28 48 C7 45 10 00 00 00 00 E8 ?? ?? ?? ?? 48 89 EF E8 B3 FC FF FF E9 F4 00 00 00 48 8B 6B 20 48 89 DF 48 C7 43 20 00 00 00 00 E8 ?? ?? ?? ?? EB 17 48 8B 5D 10 48 89 EF 48 C7 45 10 00 00 00 00 E8 84 FC FF FF 48 89 DD 48 85 ED 75 E4 E9 BD 00 00 00 8B 43 10 85 C0 75 12 48 89 DF E8 ?? ?? ?? ?? B8 01 00 00 00 E9 A6 00 00 00 FF C8 31 ED 85 C0 89 43 10 75 19 48 8B 6B 28 48 85 ED 74 10 48 8B 45 10 48 }
	condition:
		$pattern
}

rule pthread_rwlock_trywrlock_5266f2afbe4288d1db3ad0e3a586f987 {
	meta:
		aliases = "pthread_rwlock_trywrlock"
		size = "61"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 31 F6 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 83 7B 10 00 75 14 48 83 7B 18 00 75 0D 31 ED E8 97 FF FF FF 48 89 43 18 EB 05 BD 10 00 00 00 48 89 DF E8 ?? ?? ?? ?? 5A 5B 89 E8 5D C3 }
	condition:
		$pattern
}

rule sem_trywait_7192492a59507fe4c31f1f30910959b3 {
	meta:
		aliases = "__new_sem_trywait, sem_trywait"
		size = "61"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 31 F6 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 8B 43 10 85 C0 75 10 83 CD FF E8 ?? ?? ?? ?? C7 00 0B 00 00 00 EB 07 FF C8 31 ED 89 43 10 48 89 DF E8 ?? ?? ?? ?? 41 59 5B 89 E8 5D C3 }
	condition:
		$pattern
}

rule sighold_44df9f2595067b9c4a71b67112fb6976 {
	meta:
		aliases = "sigrelse, sighold"
		size = "74"
		objfiles = "sighold@libc.a, sigrelse@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 31 F6 89 FD BF 02 00 00 00 53 48 81 EC 88 00 00 00 48 89 E2 E8 ?? ?? ?? ?? 85 C0 78 1F 89 EE 48 89 E7 E8 ?? ?? ?? ?? 85 C0 78 11 31 D2 48 89 E6 BF 02 00 00 00 E8 ?? ?? ?? ?? EB 03 83 C8 FF 48 81 C4 88 00 00 00 5B 5D C3 }
	condition:
		$pattern
}

rule __strtofpmax_8c8cc8a3642d69bdaf13da588f9c57c1 {
	meta:
		aliases = "__strtofpmax"
		size = "593"
		objfiles = "__strtofpmax@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 41 89 D0 48 89 F5 53 48 89 FB 48 83 EC 28 4C 8B 15 ?? ?? ?? ?? EB 03 48 FF C3 8A 13 48 0F BE C2 41 F6 04 42 20 75 F0 0F BE C2 83 F8 2B 74 0D 45 31 DB 83 F8 2D 75 0B 41 B3 01 EB 03 45 31 DB 48 FF C3 D9 EE 45 31 C9 83 CE FF D9 05 ?? ?? ?? ?? EB 2E 81 FE 00 00 00 80 83 DE FF 85 F6 75 05 80 F9 30 74 19 FF C6 83 FE 15 7F 12 DC C9 0F BE C1 83 E8 30 89 44 24 80 DB 44 24 80 DE C2 48 FF C3 8A 0B 48 0F BE C1 41 F6 04 42 08 75 C5 80 F9 2E 0F 94 C2 4D 85 C9 0F 94 C0 84 D0 74 08 48 FF C3 49 89 D9 EB DB DF C0 85 F6 0F 89 A4 00 00 00 4D 85 C9 0F 85 93 00 00 00 31 F6 31 D2 EB 4A 44 89 C2 8D 44 32 01 48 98 }
	condition:
		$pattern
}

rule pmap_getmaps_ea9aabf57a5d9ad42aad3aa5b9cad903 {
	meta:
		aliases = "pmap_getmaps"
		size = "187"
		objfiles = "pm_getmaps@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 41 B9 F4 01 00 00 41 B8 32 00 00 00 BA 02 00 00 00 BE A0 86 01 00 48 89 FD 53 48 83 EC 38 48 8D 4C 24 2C 48 C7 44 24 20 00 00 00 00 C7 44 24 2C FF FF FF FF 66 C7 47 02 00 6F E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 61 48 8B 40 08 31 C9 4C 8D 4C 24 20 41 B8 ?? ?? ?? ?? BA ?? ?? ?? ?? BE 04 00 00 00 48 89 DF 48 8B 00 48 C7 44 24 18 00 00 00 00 48 C7 44 24 10 3C 00 00 00 48 C7 04 24 3C 00 00 00 48 C7 44 24 08 00 00 00 00 FF D0 85 C0 74 0D BE ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8B 43 08 48 89 DF FF 50 20 66 C7 45 02 00 00 48 8B 44 24 20 48 83 C4 38 5B 5D C3 }
	condition:
		$pattern
}

rule __getdents_a5d80ab41e5a13ce2a458a9d2789dde8 {
	meta:
		aliases = "__getdents64, __getdents"
		size = "300"
		objfiles = "getdents64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 D0 48 83 C0 1E 48 89 E5 41 57 48 83 E0 F0 49 89 F7 41 56 41 55 41 54 53 48 83 EC 28 89 7D C4 48 89 55 B8 48 29 C4 48 63 FF B8 D9 00 00 00 4C 8D 6C 24 0F 49 83 E5 F0 4C 89 EE 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 4C 63 F3 4D 89 FC 4C 89 EB 49 83 FE FF 4C 89 F0 48 C7 45 D0 FF FF FF FF 0F 85 92 00 00 00 E9 A1 00 00 00 0F B7 43 10 48 8B 4D B8 48 8D 50 07 48 83 E2 F8 49 8D 04 14 48 89 45 C8 49 8D 04 0F 48 39 45 C8 76 24 48 8B 75 D0 8B 7D C4 31 D2 E8 ?? ?? ?? ?? 4D 39 FC 75 66 E8 ?? ?? ?? ?? C7 00 16 00 00 00 48 83 C8 FF EB 5B 48 8B 43 08 48 8D }
	condition:
		$pattern
}

rule byte_alt_match_null_string_p_4686b848cfbb77de3abb563dfbeaa093 {
	meta:
		aliases = "byte_alt_match_null_string_p"
		size = "107"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 D5 53 48 89 F3 48 83 EC 18 48 89 7C 24 10 EB 42 80 39 0F 75 25 48 8D 41 01 48 89 44 24 10 0F BE 40 01 0F B6 51 01 C1 E0 08 01 C2 48 63 D2 48 8D 44 11 03 48 89 44 24 10 EB 18 48 8D 7C 24 10 48 89 EA 48 89 DE E8 9F FE FF FF 84 C0 75 04 31 C0 EB 0F 48 8B 4C 24 10 48 39 D9 72 B4 B8 01 00 00 00 48 83 C4 18 5B 5D C3 }
	condition:
		$pattern
}

rule __GI_jrand48_r_4cabdd380d6101f5f4bfffd44174db66 {
	meta:
		aliases = "jrand48_r, __GI_jrand48_r"
		size = "49"
		objfiles = "jrand48_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 D5 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 83 CA FF 85 C0 78 13 0F B7 43 04 0F B7 53 02 C1 E0 10 09 D0 31 D2 48 89 45 00 89 D0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule __GI_nrand48_r_9028c9b8c293ef726b47bd4e26ceaad3 {
	meta:
		aliases = "nrand48_r, __GI_nrand48_r"
		size = "58"
		objfiles = "nrand48_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 D5 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 83 CA FF 85 C0 78 1C 0F B7 53 04 66 8B 43 02 66 D1 E8 C1 E2 0F 0F B7 C0 09 C2 48 63 D2 48 89 55 00 31 D2 89 D0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule __GI_erand48_r_8704fe162769d6a8dc6c68b3345b9992 {
	meta:
		aliases = "erand48_r, __GI_erand48_r"
		size = "127"
		objfiles = "erand48_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 D5 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 83 CA FF 85 C0 78 61 66 8B 73 02 0F B7 53 04 89 D9 89 F0 C1 E6 14 66 C1 E8 0C C1 E2 04 0F B7 C0 09 C2 48 B8 00 00 00 00 00 00 F0 3F 48 09 C1 0F B7 03 48 C1 E2 20 48 09 D1 31 D2 C1 E0 04 09 C6 48 B8 00 00 00 00 FF FF FF FF 89 F6 48 21 C1 48 09 F1 48 89 0C 24 66 0F 12 04 24 F2 0F 5C 05 ?? ?? ?? ?? F2 0F 11 45 00 89 D0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule __msgwrite_705acd2e318991e0fa41918d89565d73 {
	meta:
		aliases = "__msgwrite"
		size = "201"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 56 41 89 FE 41 55 49 89 D5 41 54 49 89 F4 53 48 81 EC 90 00 00 00 48 8D 5C 24 0F E8 ?? ?? ?? ?? 48 83 E3 F0 89 45 D0 E8 ?? ?? ?? ?? 89 45 D4 E8 ?? ?? ?? ?? 48 8D 75 D0 48 8D 7B 10 BA 0C 00 00 00 89 45 D8 E8 ?? ?? ?? ?? 48 8D 45 C0 C7 43 08 01 00 00 00 C7 43 0C 02 00 00 00 48 C7 03 1C 00 00 00 4C 89 65 C0 4C 89 6D C8 48 89 45 90 48 C7 45 98 01 00 00 00 48 C7 45 80 00 00 00 00 C7 45 88 00 00 00 00 48 89 5D A0 48 C7 45 A8 20 00 00 00 C7 45 B0 00 00 00 00 48 8D 75 80 31 D2 44 89 F7 E8 ?? ?? ?? ?? 85 C0 79 0D E8 ?? ?? ?? ?? 83 38 04 74 E4 83 C8 FF 48 8D 65 E0 5B 41 5C 41 5D 41 5E C9 }
	condition:
		$pattern
}

rule rcmd_f32bd62d588c2b18ce51735f67cfa429 {
	meta:
		aliases = "rcmd"
		size = "1328"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 41 55 41 54 41 BC 00 04 00 00 53 48 81 EC C8 00 00 00 48 89 95 28 FF FF FF 48 89 BD 38 FF FF FF 48 89 8D 20 FF FF FF 4C 89 85 18 FF FF FF 4C 89 8D 10 FF FF FF 66 89 B5 36 FF FF FF E8 ?? ?? ?? ?? 48 81 EC 10 04 00 00 89 85 48 FF FF FF 48 8D 54 24 0F 48 83 E2 F0 EB 45 8B 5D C8 83 FB FF 75 0A E8 ?? ?? ?? ?? 83 38 22 74 1B E8 ?? ?? ?? ?? 89 18 48 8B 85 38 FF FF FF 48 8B 38 E8 ?? ?? ?? ?? E9 8C 04 00 00 4D 01 E4 49 8D 44 24 1E 48 83 E0 F0 48 29 C4 48 8D 54 24 0F 48 83 E2 F0 48 8B 85 38 FF FF FF 48 8D B5 50 FF FF FF 4C 8D 4D C8 4C 8D 45 A8 4C 89 E1 48 8B 38 E8 ?? ?? ?? ?? 85 }
	condition:
		$pattern
}

rule __GI_execvp_6a961f42c7992f6341475542378e8ceb {
	meta:
		aliases = "execvp, __GI_execvp"
		size = "478"
		objfiles = "execvp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 41 55 41 54 49 89 FC 53 48 83 EC 18 48 89 75 C0 80 3F 00 75 10 E8 ?? ?? ?? ?? C7 00 02 00 00 00 E9 9F 01 00 00 BE 2F 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 0F 84 82 00 00 00 48 8B 15 ?? ?? ?? ?? 48 8B 75 C0 4C 89 E7 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 38 08 0F 85 6B 01 00 00 31 C0 EB 03 48 FF C0 48 8B 4D C0 48 8D 14 C5 00 00 00 00 48 83 3C 11 00 75 EA 48 8D 42 2E 48 89 CE 48 83 C6 08 48 83 E0 F0 48 29 C4 48 8B 01 48 8D 5C 24 0F 48 83 E3 F0 48 8D 7B 10 48 89 03 4C 89 63 08 E8 ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? 48 89 DE BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 0A 01 00 00 BF ?? ?? ?? ?? E8 }
	condition:
		$pattern
}

rule byte_re_compile_fastmap_8193dc0916f5b80fb19fb2214a76f760 {
	meta:
		aliases = "byte_re_compile_fastmap"
		size = "920"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 41 55 41 54 49 89 FC 53 48 83 EC 68 48 8B 1F 48 8B 47 10 4C 8B 77 20 48 01 D8 48 89 45 C8 48 8D 44 24 0F 49 89 C0 49 83 E0 F0 0F 84 4C 03 00 00 4C 89 F7 BA 00 01 00 00 31 F6 4C 89 45 B8 45 31 FF E8 ?? ?? ?? ?? 41 8A 44 24 38 4C 8B 45 B8 41 B9 01 00 00 00 BF 05 00 00 00 C6 45 D7 00 83 C8 08 83 E0 FE 41 88 44 24 38 EB 07 48 8B 5D C8 45 31 C9 48 3B 5D C8 74 06 8A 03 3C 01 75 32 45 85 FF 41 8A 54 24 38 0F 84 D7 02 00 00 89 D0 41 FF CF 83 E2 FE 83 E0 01 44 09 C8 41 B9 01 00 00 00 09 C2 44 89 F8 41 88 54 24 38 49 8B 1C C0 EB C2 0F B6 C0 48 FF C3 83 F8 1D 0F 87 9F 02 00 00 89 }
	condition:
		$pattern
}

rule byte_re_match_2_internal_4eb14644373e15b5d04933b17c93bc73 {
	meta:
		aliases = "byte_re_match_2_internal"
		size = "7888"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 41 55 41 54 53 48 81 EC 58 01 00 00 48 89 BD E8 FE FF FF 48 89 B5 E0 FE FF FF 89 95 DC FE FF FF 48 89 8D D0 FE FF FF 44 89 85 CC FE FF FF 44 89 8D C8 FE FF FF 4C 8B 27 48 8B 47 10 44 8B 6D 18 4C 01 E0 48 89 85 28 FF FF FF 48 8D 44 24 0F 48 8B 57 28 48 83 E0 F0 48 89 95 38 FF FF FF 48 8B 57 30 48 89 45 C0 0F 84 43 1E 00 00 48 FF C2 48 89 95 40 FF FF FF 48 83 7F 30 00 75 5C 48 C7 85 58 FF FF FF 00 00 00 00 48 C7 85 60 FF FF FF 00 00 00 00 48 C7 85 68 FF FF FF 00 00 00 00 48 C7 85 70 FF FF FF 00 00 00 00 48 C7 85 78 FF FF FF 00 00 00 00 48 C7 45 88 00 00 00 00 48 C7 45 90 }
	condition:
		$pattern
}

rule clntudp_call_a5dc630fa1ba74e0954d38df38980cf9 {
	meta:
		aliases = "clntudp_call"
		size = "1553"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 41 55 41 54 53 48 81 EC D8 23 00 00 48 89 95 18 DC FF FF 48 89 BD 20 DC FF FF 48 89 B5 58 DC FF FF 48 89 8D 10 DC FF FF BA E8 03 00 00 4C 89 85 08 DC FF FF 4C 89 8D 00 DC FF FF 48 89 D3 4C 8B 67 10 49 8B 44 24 28 49 69 4C 24 20 E8 03 00 00 48 99 48 F7 FB 01 C1 48 8B 45 18 89 8D 30 DC FF FF 48 8B 4D 10 48 89 85 48 DC FF FF 48 89 8D 50 DC FF FF 49 83 7C 24 38 FF 74 41 EB 27 E8 ?? ?? ?? ?? 8B 00 41 C7 44 24 40 03 00 00 00 41 89 44 24 48 B8 03 00 00 00 E9 5E 05 00 00 8B 46 10 E9 48 04 00 00 49 8B 5C 24 38 48 89 9D 48 DC FF FF 49 8B 44 24 30 48 89 85 50 DC FF FF C7 85 2C DC }
	condition:
		$pattern
}

rule iruserok2_7dcb9907a083de4ca3f9dcf0e0d16454 {
	meta:
		aliases = "iruserok2"
		size = "364"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 41 55 49 89 CD 41 54 41 89 F4 53 48 83 EC 68 85 F6 89 7D 8C 48 89 55 80 4C 89 85 78 FF FF FF 75 14 31 F6 BF ?? ?? ?? ?? E8 33 FF FF FF 48 85 C0 48 89 C3 75 06 41 83 CE FF EB 2D 4C 8B 85 78 FF FF FF 48 8B 4D 80 4C 89 EA 8B 75 8C 48 89 C7 E8 FC FB FF FF 48 89 DF 41 89 C6 E8 ?? ?? ?? ?? 45 85 F6 0F 84 EA 00 00 00 44 0B 25 ?? ?? ?? ?? 0F 84 D9 00 00 00 BF 46 00 00 00 E8 ?? ?? ?? ?? 48 89 C1 48 8D 40 1E 48 8D 75 90 4C 8D 45 C8 4C 89 EF 48 83 E0 F0 48 29 C4 48 8D 54 24 0F 48 83 E2 F0 E8 ?? ?? ?? ?? 85 C0 0F 85 A0 00 00 00 48 8B 45 C8 48 85 C0 0F 84 93 00 00 00 48 8B 78 20 E8 }
	condition:
		$pattern
}

rule glob_in_dir_4070ecf091ad2aa60e7a68d7707f3f50 {
	meta:
		aliases = "glob_in_dir"
		size = "1287"
		objfiles = "glob64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 41 89 D6 41 55 41 54 49 89 CC 53 44 89 F3 48 81 EC 68 01 00 00 48 89 BD 88 FE FF FF 48 89 B5 80 FE FF FF 48 89 F7 4C 89 85 78 FE FF FF E8 ?? ?? ?? ?? 83 E3 40 48 8B BD 88 FE FF FF 48 89 85 90 FE FF FF 40 0F 94 C6 40 0F B6 F6 E8 ?? ?? ?? ?? 85 C0 0F 85 F4 00 00 00 41 F7 C6 10 08 00 00 74 14 41 83 CE 10 48 C7 85 98 FE FF FF 00 00 00 00 E9 CB 02 00 00 85 DB 75 1A 48 8B BD 88 FE FF FF BE 5C 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 0F 85 B9 00 00 00 48 8B BD 88 FE FF FF E8 ?? ?? ?? ?? 48 8B 95 90 FE FF FF 48 89 C3 48 8B B5 80 FE FF FF 48 8D 44 02 20 48 83 E0 F0 48 29 C4 4C 8D 64 24 }
	condition:
		$pattern
}

rule if_nameindex_5ac286c44c9e50a0de1d12f5dbd5f839 {
	meta:
		aliases = "__GI_if_nameindex, if_nameindex"
		size = "426"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 45 31 F6 41 55 41 54 53 48 83 EC 28 E8 ?? ?? ?? ?? 85 C0 41 89 C5 0F 88 74 01 00 00 48 C7 45 C8 00 00 00 00 BB A0 00 00 00 8D 14 1B 44 89 EF 48 63 D2 48 8D 42 1E 8D 34 13 89 D3 48 83 E0 F0 48 29 C4 48 8D 44 24 0F 48 83 E0 F0 48 8D 0C 10 48 3B 4D C8 48 8D 55 C0 48 89 45 C8 0F 44 DE 31 C0 BE 12 89 00 00 89 5D C0 E8 ?? ?? ?? ?? 85 C0 78 4D 8B 45 C0 39 D8 74 B1 BA 28 00 00 00 48 98 45 31 FF 48 89 D1 31 D2 48 F7 F1 89 C7 89 45 BC FF C7 48 C1 E7 04 E8 ?? ?? ?? ?? 48 85 C0 49 89 C6 0F 85 BF 00 00 00 44 89 EF E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 69 00 00 00 E9 D2 00 00 00 44 89 }
	condition:
		$pattern
}

rule link_exists_p_dee972cf8f70cf37a237a00db9e07a0d {
	meta:
		aliases = "link_exists_p"
		size = "195"
		objfiles = "glob@libc.a, glob64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 49 89 D6 41 55 49 89 FD 48 89 D7 41 54 53 48 89 F3 48 81 EC 38 01 00 00 48 89 8D A8 FE FF FF 44 89 85 A4 FE FF FF E8 ?? ?? ?? ?? 49 89 C4 48 8D 44 18 20 48 89 DA 4C 89 EE 48 83 E0 F0 48 29 C4 4C 8D 7C 24 0F 49 83 E7 F0 4C 89 FF E8 ?? ?? ?? ?? BA 01 00 00 00 48 89 C7 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 49 8D 54 24 01 48 89 C7 4C 89 F6 E8 ?? ?? ?? ?? F7 85 A4 FE FF FF 00 02 00 00 74 16 48 8B 95 A8 FE FF FF 48 8D B5 40 FF FF FF 4C 89 FF FF 52 40 EB 0F 48 8D B5 B0 FE FF FF 4C 89 FF E8 ?? ?? ?? ?? 85 C0 0F 94 C0 48 8D 65 D8 5B 41 5C 41 5D 41 5E 41 5F C9 0F B6 C0 C3 }
	condition:
		$pattern
}

rule dlopen_062d4fbafac3d5fd56705266ceba3009 {
	meta:
		aliases = "dlopen"
		size = "1242"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 49 89 FE 41 55 41 54 41 89 F4 53 48 83 EC 48 40 F6 C6 03 48 C7 45 D0 00 00 00 00 75 10 48 C7 05 ?? ?? ?? ?? 09 00 00 00 E9 91 04 00 00 80 3D ?? ?? ?? ?? 00 4C 8B 6D 08 75 1D C6 05 ?? ?? ?? ?? 01 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 4D 85 F6 75 0C 48 8B 3D ?? ?? ?? ?? E9 58 04 00 00 E8 ?? ?? ?? ?? 48 8B 35 ?? ?? ?? ?? 31 DB 48 89 F0 EB 1E 48 8B 08 48 8B 51 28 4C 39 EA 73 0E 48 85 DB 74 06 48 39 53 28 73 03 48 89 CB 48 8B 40 20 48 85 C0 75 DD 48 89 75 D0 EB 04 48 89 45 D0 48 8B 45 D0 48 85 C0 48 89 45 98 74 09 48 8B 40 20 48 85 C0 75 E6 BF ?? }
	condition:
		$pattern
}

rule glob_in_dir_32fc12482017bcc9f3bc49e2148d93e4 {
	meta:
		aliases = "glob_in_dir"
		size = "1366"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 89 D7 41 56 41 55 41 54 49 89 CC 53 44 89 FB 48 81 EC 88 02 00 00 48 89 BD 68 FD FF FF 48 89 B5 60 FD FF FF 48 89 F7 4C 89 85 58 FD FF FF E8 ?? ?? ?? ?? 83 E3 40 48 8B BD 68 FD FF FF 48 89 85 70 FD FF FF 40 0F 94 C6 40 0F B6 F6 E8 ?? ?? ?? ?? 85 C0 0F 85 F4 00 00 00 41 F7 C7 10 08 00 00 74 14 41 83 CF 10 48 C7 85 78 FD FF FF 00 00 00 00 E9 1B 03 00 00 85 DB 75 1A 48 8B BD 68 FD FF FF BE 5C 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 0F 85 B9 00 00 00 48 8B BD 68 FD FF FF E8 ?? ?? ?? ?? 48 8B 95 70 FD FF FF 48 89 C3 48 8B B5 60 FD FF FF 48 8D 44 02 20 48 83 E0 F0 48 29 C4 4C 8D 64 24 }
	condition:
		$pattern
}

rule glob_4626557e42945317677348f1a08c0dfd {
	meta:
		aliases = "__GI_glob, __GI_glob64, glob64, glob"
		size = "1443"
		objfiles = "glob@libc.a, glob64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 89 F7 41 56 41 55 49 89 CD 41 54 53 48 81 EC 68 01 00 00 48 85 FF 48 89 95 78 FE FF FF 0F 94 C2 48 85 C9 48 89 BD 80 FE FF FF 0F 94 C0 08 C2 75 08 F7 C6 00 81 FF FF 74 13 E8 ?? ?? ?? ?? 83 CA FF C7 00 16 00 00 00 E9 3F 05 00 00 89 F0 83 E0 08 89 85 8C FE FF FF 75 08 48 C7 41 10 00 00 00 00 48 8B BD 80 FE FF FF BE 2F 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 49 89 C4 75 3F 41 F7 C7 00 50 00 00 0F 84 E8 00 00 00 48 8B 95 80 FE FF FF 80 3A 7E 0F 85 D8 00 00 00 48 89 D7 E8 ?? ?? ?? ?? 48 8B 9D 80 FE FF FF 49 89 C6 48 C7 85 A0 FE FF FF 00 00 00 00 E9 CC 00 00 00 48 3B 85 80 FE FF FF 75 }
	condition:
		$pattern
}

rule search_for_named_library_98888c1ad07f6bcf27bf8405c266219f {
	meta:
		aliases = "search_for_named_library"
		size = "328"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 89 F7 41 56 49 89 CE 41 55 41 54 53 48 83 EC 08 48 85 D2 48 89 7D D0 0F 84 13 01 00 00 48 8D 42 FF 48 FF C0 80 38 00 75 F8 48 29 D0 48 FF CA FF C0 48 63 F8 48 8D 47 1E 48 83 E0 F0 48 29 C4 48 8D 74 24 0F 48 81 EC 20 08 00 00 4C 8D 64 24 0F 48 83 E6 F0 48 8D 4E FF 48 89 F3 49 83 E4 F0 EB 0D 48 FF C2 48 FF C1 48 FF CF 8A 02 88 01 48 85 FF 75 EE 48 89 F0 45 31 ED 80 3B 00 75 09 C6 03 3A 41 BD 01 00 00 00 80 3B 3A 0F 85 93 00 00 00 C6 03 00 80 38 00 49 8D 54 24 FF 74 14 48 8D 48 FF 48 FF C1 48 FF C2 8A 01 84 C0 88 02 74 15 EB F0 B9 ?? ?? ?? ?? 48 FF C1 48 FF C2 8A 01 84 C0 88 }
	condition:
		$pattern
}

rule ruserok_d231822b6734c511f180aab174acb56f {
	meta:
		aliases = "ruserok"
		size = "197"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 89 F7 41 56 49 89 D6 41 55 49 89 CD 41 54 49 89 FC 53 BB 00 04 00 00 48 81 EC 48 04 00 00 48 8D 54 24 0F 48 83 E2 F0 EB 27 83 7D C8 FF 75 7D E8 ?? ?? ?? ?? 83 38 22 75 73 48 01 DB 48 8D 43 1E 48 83 E0 F0 48 29 C4 48 8D 54 24 0F 48 83 E2 F0 48 8D 75 A0 4C 8D 4D C8 4C 8D 45 C0 48 89 D9 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 75 BE 48 8B 45 C0 48 85 C0 74 B5 48 8B 58 18 EB 2A 48 8D 7D CC BA 04 00 00 00 E8 ?? ?? ?? ?? 8B 7D CC 4D 89 E0 4C 89 E9 4C 89 F2 44 89 FE E8 E6 FD FF FF 85 C0 74 0F 48 83 C3 08 48 8B 33 48 85 F6 75 CE 83 C8 FF 48 8D 65 D8 5B 41 5C 41 5D 41 5E 41 5F C9 C3 }
	condition:
		$pattern
}

rule gaih_inet_a7d64b2ea99310f623b8fa2216218870 {
	meta:
		aliases = "gaih_inet"
		size = "2715"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 48 8D 45 90 41 56 49 89 D6 41 55 49 89 F5 41 54 53 48 81 EC D8 00 00 00 48 89 BD 18 FF FF FF 48 89 8D 10 FF FF FF 48 89 45 B8 48 C7 45 C0 00 00 00 00 8B 42 04 C7 85 24 FF FF FF 00 00 00 00 85 C0 0F 94 C2 83 F8 0A 0F 94 C0 08 C2 74 14 41 8B 06 83 F0 08 C1 E8 03 F7 D0 83 E0 01 89 85 24 FF FF FF 48 8D 7D 90 31 F6 BA 18 00 00 00 E8 ?? ?? ?? ?? 49 8B 7E 08 BE ?? ?? ?? ?? 48 85 FF 75 06 EB 49 48 83 C6 07 8A 4E 03 84 C9 74 29 41 8B 56 08 85 D2 74 07 0F BE 06 39 C2 75 E6 41 8B 56 0C 85 D2 74 0E F6 46 02 02 75 08 0F BE 46 01 39 C2 75 D0 84 C9 75 1A 41 83 7E 08 00 B8 07 01 00 00 0F 85 }
	condition:
		$pattern
}

rule clnt_create_b94423e19b1c0e3dbb48304efe341e63 {
	meta:
		aliases = "clnt_create"
		size = "565"
		objfiles = "clnt_generic@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 49 89 CF 41 56 49 89 FE 48 89 CF 41 55 49 89 F5 BE ?? ?? ?? ?? 41 54 49 89 D4 53 48 81 EC F8 00 00 00 E8 ?? ?? ?? ?? 85 C0 75 4F 48 8D 9D E0 FE FF FF BA 6E 00 00 00 31 F6 48 89 DF E8 ?? ?? ?? ?? 48 8D 7B 02 4C 89 F6 66 C7 85 E0 FE FF FF 01 00 E8 ?? ?? ?? ?? 48 8D 4D C8 45 31 C9 45 31 C0 4C 89 E2 4C 89 EE 48 89 DF C7 45 C8 FF FF FF FF E8 ?? ?? ?? ?? E9 A6 01 00 00 48 81 EC 10 04 00 00 BB 00 04 00 00 48 8D 54 24 0F 48 83 E2 F0 EB 37 83 7D CC FF 75 0A E8 ?? ?? ?? ?? 83 38 22 74 10 E8 ?? ?? ?? ?? C7 00 0D 00 00 00 E9 6D 01 00 00 48 01 DB 48 8D 43 1E 48 83 E0 F0 48 29 C4 48 8D 54 }
	condition:
		$pattern
}

rule ruserpass_a038305559696964513c343f9b9581ce {
	meta:
		aliases = "__GI_ruserpass, ruserpass"
		size = "849"
		objfiles = "ruserpass@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 49 89 D7 41 56 49 89 F6 41 55 49 89 FD 41 54 53 48 81 EC A8 04 00 00 E8 ?? ?? ?? ?? 89 C3 E8 ?? ?? ?? ?? 39 C3 0F 85 0C 03 00 00 E8 ?? ?? ?? ?? 89 C3 E8 ?? ?? ?? ?? 39 C3 0F 85 F8 02 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 0F 84 E2 02 00 00 48 89 C7 E8 ?? ?? ?? ?? 48 83 C0 26 48 89 DE 48 83 E0 F0 48 29 C4 4C 8D 64 24 0F 49 83 E4 F0 4C 89 E7 E8 ?? ?? ?? ?? BE ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? 4C 89 E7 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 C7 48 89 05 ?? ?? ?? ?? 75 24 E8 ?? ?? ?? ?? 31 D2 83 38 02 0F 84 85 02 00 00 4C 89 E6 BF ?? ?? ?? ?? 31 C0 E8 ?? ?? }
	condition:
		$pattern
}

rule gaih_inet_serv_c1d4a6d79a5021cf06337ba517c2e116 {
	meta:
		aliases = "gaih_inet_serv"
		size = "174"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 49 89 D7 41 56 49 89 FE 41 55 41 BD 00 04 00 00 41 54 49 89 CC 53 48 89 F3 48 83 EC 38 49 8D 45 1E 48 8D 55 A0 48 8D 73 03 4C 8D 4D C8 4D 89 E8 4C 89 F7 48 83 E0 F0 48 29 C4 48 8D 4C 24 0F 48 83 E1 F0 E8 ?? ?? ?? ?? 85 C0 75 09 48 83 7D C8 00 75 0C EB 26 83 F8 22 75 21 4D 01 ED EB BE 49 C7 04 24 00 00 00 00 0F BE 03 41 89 44 24 08 F6 43 02 02 74 0D 41 8B 47 0C EB 0B B8 08 01 00 00 EB 17 0F BE 43 01 41 89 44 24 0C 48 8B 45 C8 8B 40 10 41 89 44 24 10 31 C0 48 8D 65 D8 5B 41 5C 41 5D 41 5E 41 5F C9 C3 }
	condition:
		$pattern
}

rule sched_setaffinity_6b8ab71c16b776edb7d87873769a6af9 {
	meta:
		aliases = "sched_setaffinity"
		size = "284"
		objfiles = "sched_setaffinity@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 49 89 F7 41 56 49 89 D6 41 55 41 54 53 48 83 EC 08 48 83 3D ?? ?? ?? ?? 00 89 7D D4 0F 85 A0 00 00 00 48 81 EC 90 00 00 00 41 BD 80 00 00 00 4C 8D 64 24 0F 49 83 E4 F0 EB 2F 4B 8D 54 2D 00 48 8D 42 1E 49 8D 74 15 00 49 89 D5 48 83 E0 F0 48 29 C4 48 8D 44 24 0F 48 83 E0 F0 48 8D 0C 10 4C 39 E1 49 89 C4 4C 0F 44 EE E8 ?? ?? ?? ?? 4C 89 E2 48 63 F8 4C 89 EE B8 CC 00 00 00 0F 05 3D 00 F0 FF FF 89 C3 0F 97 C2 31 C0 83 FB EA 0F 94 C0 85 C2 75 A6 85 DB 0F 94 C0 08 D0 74 1B F7 DB E8 ?? ?? ?? ?? 89 18 EB 0B E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 4F 48 63 C3 48 89 05 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getrpcport_7211f0bf5af838e02056aab3c7d87792 {
	meta:
		aliases = "getrpcport"
		size = "198"
		objfiles = "getrpcport@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 49 89 F7 41 56 49 89 D6 41 55 41 89 CD 41 54 49 89 FC 53 BB 00 04 00 00 48 81 EC 58 04 00 00 48 8D 54 24 0F 48 83 E2 F0 EB 27 83 7D CC FF 75 7F E8 ?? ?? ?? ?? 83 38 22 75 75 48 01 DB 48 8D 43 1E 48 83 E0 F0 48 29 C4 48 8D 54 24 0F 48 83 E2 F0 48 8D 75 90 4C 8D 4D CC 4C 8D 45 C0 48 89 D9 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 75 BE 48 8B 45 C0 48 85 C0 74 B5 48 63 50 14 48 8B 40 18 48 8D 5D B0 48 8D 7B 04 48 8B 30 E8 ?? ?? ?? ?? 44 89 E9 4C 89 F2 4C 89 FE 48 89 DF 66 C7 45 B0 02 00 66 C7 45 B2 00 00 E8 ?? ?? ?? ?? 0F B7 C0 EB 02 31 C0 48 8D 65 D8 5B 41 5C 41 5D 41 5E 41 5F C9 C3 }
	condition:
		$pattern
}

rule callrpc_6048ce3db629aa30cf4c62f9429a5626 {
	meta:
		aliases = "callrpc"
		size = "606"
		objfiles = "clnt_simple@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 49 89 FF 41 56 49 89 D6 41 55 49 89 F5 41 54 53 48 81 EC 98 00 00 00 48 89 8D 68 FF FF FF 4C 89 85 60 FF FF FF 4C 89 8D 58 FF FF FF E8 ?? ?? ?? ?? 4C 8B A0 C8 00 00 00 48 89 C3 4D 85 E4 75 24 BE 30 00 00 00 BF 01 00 00 00 E8 ?? ?? ?? ?? 49 89 C4 31 C0 4D 85 E4 0F 84 EC 01 00 00 4C 89 A3 C8 00 00 00 49 83 7C 24 28 00 75 1B BF 00 01 00 00 E8 ?? ?? ?? ?? 49 89 44 24 28 C6 00 00 41 C7 44 24 08 FF FF FF FF 49 83 7C 24 20 00 74 23 4D 39 6C 24 10 75 1C 4D 39 74 24 18 75 15 49 8B 7C 24 28 4C 89 FE E8 ?? ?? ?? ?? 85 C0 0F 84 3B 01 00 00 41 8B 7C 24 08 49 C7 44 24 20 00 00 00 00 83 FF }
	condition:
		$pattern
}

rule execlp_565a3b46c26c03b4cc0a433a220426fe {
	meta:
		aliases = "execl, __GI_execl, __GI_execlp, execlp"
		size = "280"
		objfiles = "execl@libc.a, execlp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 48 81 EC D0 00 00 00 48 8D 45 10 48 89 8D 68 FF FF FF 4C 89 85 70 FF FF FF 48 89 95 60 FF FF FF 4C 89 8D 78 FF FF FF 48 89 F1 48 89 85 38 FF FF FF 48 8D 85 50 FF FF FF C7 85 30 FF FF FF 10 00 00 00 45 31 C0 48 89 85 40 FF FF FF 8B 85 30 FF FF FF 41 FF C0 83 F8 30 73 14 89 C2 48 03 95 40 FF FF FF 83 C0 08 89 85 30 FF FF FF EB 12 48 8B 95 38 FF FF FF 48 8D 42 08 48 89 85 38 FF FF FF 48 83 3A 00 75 C6 41 8D 40 01 48 98 48 8D 04 C5 1E 00 00 00 48 83 E0 F0 48 29 C4 48 8D 45 10 48 8D 74 24 0F 48 83 E6 F0 48 89 0E 48 89 85 38 FF FF FF 48 8D 85 50 FF FF FF C7 85 30 FF FF FF 10 00 00 00 48 }
	condition:
		$pattern
}

rule __GI_execle_5a9a58a9ed32f322592614fa274d88f5 {
	meta:
		aliases = "execle, __GI_execle"
		size = "332"
		objfiles = "execle@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 48 81 EC D0 00 00 00 48 8D 45 10 48 89 8D 68 FF FF FF 4C 89 8D 78 FF FF FF 48 89 95 60 FF FF FF 4C 89 85 70 FF FF FF 48 89 F1 48 89 85 38 FF FF FF 48 8D 85 50 FF FF FF C7 85 30 FF FF FF 10 00 00 00 45 31 C9 48 89 85 40 FF FF FF 8B 85 30 FF FF FF 41 FF C1 83 F8 30 73 14 89 C2 48 03 95 40 FF FF FF 83 C0 08 89 85 30 FF FF FF EB 12 48 8B 95 38 FF FF FF 48 8D 42 08 48 89 85 38 FF FF FF 48 83 3A 00 75 C6 8B 85 30 FF FF FF 83 F8 30 73 14 89 C2 48 03 95 40 FF FF FF 83 C0 08 89 85 30 FF FF FF EB 12 48 8B 95 38 FF FF FF 48 8D 42 08 48 89 85 38 FF FF FF 41 8D 41 01 48 8B 12 48 98 48 8D 04 C5 }
	condition:
		$pattern
}

rule __do_global_ctors_aux_c7eee9804e1ece02a9dab4a96ffaf3db {
	meta:
		aliases = "__do_global_ctors_aux"
		size = "54"
		objfiles = "crtendS"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 53 48 8D 1D ?? ?? ?? ?? 48 83 EC 08 48 8B 05 ?? ?? ?? ?? 48 83 F8 FF 74 12 66 66 90 48 83 EB 08 FF D0 48 8B 03 48 83 F8 FF 75 F1 48 83 C4 08 5B C9 C3 }
	condition:
		$pattern
}

rule __do_global_ctors_aux_d8a14735a7893ad9b45b629a84d08f23 {
	meta:
		aliases = "__do_global_ctors_aux"
		size = "54"
		objfiles = "crtend"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 53 BB ?? ?? ?? ?? 48 83 EC 08 48 8B 05 ?? ?? ?? ?? 48 83 F8 FF 74 14 66 66 90 66 90 48 83 EB 08 FF D0 48 8B 03 48 83 F8 FF 75 F1 48 83 C4 08 5B C9 C3 }
	condition:
		$pattern
}

rule xdrrec_putint32_9e9275d3af336de3eb94cb2cc71ec260 {
	meta:
		aliases = "xdrrec_putint32"
		size = "91"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 83 EC 08 48 8B 5F 18 48 8B 53 20 48 8D 42 04 48 3B 43 28 48 89 D1 48 89 43 20 76 27 48 89 53 20 31 F6 C7 43 38 01 00 00 00 48 89 DF E8 15 FF FF FF 31 D2 85 C0 74 18 48 8B 4B 20 48 8D 41 04 48 89 43 20 8B 45 00 BA 01 00 00 00 0F C8 89 01 5F 5B 5D 89 D0 C3 }
	condition:
		$pattern
}

rule xdrrec_putlong_858455dc27c6de305d767dd00f5441e4 {
	meta:
		aliases = "xdrrec_putlong"
		size = "92"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 83 EC 08 48 8B 5F 18 48 8B 53 20 48 8D 42 04 48 3B 43 28 48 89 D1 48 89 43 20 76 27 48 89 53 20 31 F6 C7 43 38 01 00 00 00 48 89 DF E8 BA FE FF FF 31 D2 85 C0 74 18 48 8B 4B 20 48 8D 41 04 48 89 43 20 8B 45 00 BA 01 00 00 00 0F C8 89 01 41 58 5B 5D 89 D0 C3 }
	condition:
		$pattern
}

rule svcraw_reply_8749358b9f54ffc3fdcc79d4fd887fca {
	meta:
		aliases = "svcraw_reply"
		size = "94"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 83 EC 08 E8 ?? ?? ?? ?? 48 8B 80 F8 00 00 00 48 85 C0 74 3D 48 8D 98 B0 23 00 00 C7 80 B0 23 00 00 00 00 00 00 31 F6 48 8B 43 08 48 89 DF FF 50 28 48 89 EE 48 89 DF E8 ?? ?? ?? ?? 85 C0 74 11 48 8B 43 08 48 89 DF FF 50 20 B8 01 00 00 00 EB 02 31 C0 41 59 5B 5D C3 }
	condition:
		$pattern
}

rule svcraw_recv_62fb097c76de3b5f4458143d1a5fa686 {
	meta:
		aliases = "svcraw_recv"
		size = "81"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 83 EC 08 E8 ?? ?? ?? ?? 48 8B 90 F8 00 00 00 31 C0 48 85 D2 74 30 48 8D 9A B0 23 00 00 31 F6 C7 82 B0 23 00 00 01 00 00 00 48 8B 43 08 48 89 DF FF 50 28 48 89 EE 48 89 DF E8 ?? ?? ?? ?? 85 C0 0F 95 C0 0F B6 C0 41 5A 5B 5D C3 }
	condition:
		$pattern
}

rule confstr_b633261aabd4fcc97e8735e5492c7ff5 {
	meta:
		aliases = "confstr"
		size = "114"
		objfiles = "confstr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 D3 48 83 EC 08 85 FF 75 17 48 85 D2 B9 0E 00 00 00 0F 95 C2 48 85 F6 0F 95 C0 84 D0 74 46 EB 0F E8 ?? ?? ?? ?? 31 C9 C7 00 16 00 00 00 EB 35 48 83 FB 0D 76 14 BA 0E 00 00 00 BE ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? EB 16 48 8D 53 FF BE ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? C6 44 1D FF 00 B9 0E 00 00 00 5A 5B 5D 48 89 C8 C3 }
	condition:
		$pattern
}

rule clntraw_freeres_c4688965715f0100cbda125547898ae2 {
	meta:
		aliases = "clntraw_freeres"
		size = "63"
		objfiles = "clnt_raw@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 D3 48 83 EC 08 E8 ?? ?? ?? ?? 48 8B 80 C0 00 00 00 48 85 C0 74 19 C7 40 18 02 00 00 00 48 89 DE 49 89 EB 59 5B 5D 48 8D 78 18 31 C0 41 FF E3 5A 5B 5D B8 10 00 00 00 C3 }
	condition:
		$pattern
}

rule svcraw_getargs_4b32028b56b6926adba32784d224b23b {
	meta:
		aliases = "svcraw_getargs"
		size = "57"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 D3 48 83 EC 08 E8 ?? ?? ?? ?? 48 8B 80 F8 00 00 00 48 85 C0 74 16 41 58 48 89 DE 49 89 EB 48 8D B8 B0 23 00 00 5B 5D 31 C0 41 FF E3 5E 5B 5D 31 C0 C3 }
	condition:
		$pattern
}

rule svcraw_freeargs_488afcbf8227f2416da49b1fb73febb5 {
	meta:
		aliases = "svcraw_freeargs"
		size = "66"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 D3 48 83 EC 08 E8 ?? ?? ?? ?? 48 8B 80 F8 00 00 00 48 85 C0 74 1F C7 80 B0 23 00 00 02 00 00 00 48 89 DE 49 89 EB 59 5B 5D 48 8D B8 B0 23 00 00 31 C0 41 FF E3 5A 5B 5D 31 C0 C3 }
	condition:
		$pattern
}

rule __pthread_set_own_extricate_if_76da68e49fd047986d012f8c39b9f16a {
	meta:
		aliases = "__pthread_set_own_extricate_if"
		size = "65"
		objfiles = "condvar@libpthread.a, join@libpthread.a, semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 08 48 85 F6 74 08 80 7F 78 00 75 26 EB 0C 48 8B 7F 30 48 89 DE E8 ?? ?? ?? ?? 48 85 ED 48 89 AB D8 02 00 00 75 0C 48 8B 7B 30 5A 5B 5D E9 ?? ?? ?? ?? 58 5B 5D C3 }
	condition:
		$pattern
}

rule __pthread_set_own_extricate_if_8456c44071789732f7675457e8192467 {
	meta:
		aliases = "__pthread_set_own_extricate_if"
		size = "66"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 08 48 85 F6 74 08 80 7F 78 00 75 27 EB 0C 48 8B 7F 30 48 89 DE E8 ?? ?? ?? ?? 48 85 ED 48 89 AB D8 02 00 00 75 0D 48 8B 7B 30 41 58 5B 5D E9 ?? ?? ?? ?? 5E 5B 5D C3 }
	condition:
		$pattern
}

rule tdestroy_recurse_8bba949d52cdd658394b7b5cb3b2a8cc {
	meta:
		aliases = "tdestroy_recurse"
		size = "59"
		objfiles = "tdestroy@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 08 48 8B 7F 08 48 85 FF 74 05 E8 E6 FF FF FF 48 8B 7B 10 48 85 FF 74 08 48 89 EE E8 D5 FF FF FF 48 8B 3B FF D5 58 48 89 DF 5B 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule on_exit_87a05cf06c52c43aca30a8c7312b76a4 {
	meta:
		aliases = "on_exit"
		size = "48"
		objfiles = "on_exit@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 83 CA FF 48 85 C0 74 11 48 89 58 08 48 89 68 10 31 D2 48 C7 00 02 00 00 00 89 D0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule xdr_uint64_t_96181cea9b911e350f1685cae5fe9f08 {
	meta:
		aliases = "xdr_uint64_t"
		size = "166"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 18 8B 07 83 F8 01 74 4A 72 0C 83 F8 02 BA 01 00 00 00 74 7E EB 7A 48 8B 16 48 8D 74 24 14 48 89 D0 89 54 24 10 48 C1 E8 20 89 44 24 14 48 8B 47 08 FF 50 48 31 D2 85 C0 74 58 48 8B 43 08 48 8D 74 24 10 48 89 DF FF 50 48 31 D2 85 C0 0F 95 C2 EB 40 48 8B 47 08 48 8D 74 24 14 FF 50 40 85 C0 74 2E 48 8B 43 08 48 8D 74 24 10 48 89 DF FF 50 40 85 C0 74 1B 8B 44 24 14 BA 01 00 00 00 48 C1 E0 20 48 89 45 00 8B 44 24 10 48 09 45 00 EB 02 31 D2 48 83 C4 18 89 D0 5B 5D C3 }
	condition:
		$pattern
}

rule xdr_int64_t_81c2c00a7d3cb40b9694068f9c190619 {
	meta:
		aliases = "xdr_int64_t"
		size = "167"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 18 8B 07 83 F8 01 74 4A 72 0C 83 F8 02 BA 01 00 00 00 74 7F EB 7B 48 8B 16 48 8D 74 24 14 48 89 D0 89 54 24 10 48 C1 F8 20 89 44 24 14 48 8B 47 08 FF 50 48 31 D2 85 C0 74 59 48 8B 43 08 48 8D 74 24 10 48 89 DF FF 50 48 31 D2 85 C0 0F 95 C2 EB 41 48 8B 47 08 48 8D 74 24 14 FF 50 40 85 C0 74 2F 48 8B 43 08 48 8D 74 24 10 48 89 DF FF 50 40 85 C0 74 1C 48 63 44 24 14 BA 01 00 00 00 48 C1 E0 20 48 89 45 00 8B 44 24 10 48 09 45 00 EB 02 31 D2 48 83 C4 18 89 D0 5B 5D C3 }
	condition:
		$pattern
}

rule __GI_xdr_u_hyper_fad8744dea551645a69578593ac84096 {
	meta:
		aliases = "xdr_u_hyper, __GI_xdr_u_hyper"
		size = "167"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 18 8B 07 85 C0 75 3C 48 8B 16 48 8D 74 24 10 48 89 D0 48 89 54 24 08 48 C1 E8 20 48 89 44 24 10 48 8B 47 08 FF 50 08 31 D2 85 C0 74 66 48 8B 43 08 48 8D 74 24 08 48 89 DF FF 50 08 85 C0 0F 95 C0 EB 49 83 F8 01 75 3E 48 8B 47 08 48 8D 74 24 10 FF 10 85 C0 74 3A 48 8B 43 08 48 8D 74 24 08 48 89 DF FF 10 85 C0 74 28 48 8B 44 24 10 BA 01 00 00 00 48 C1 E0 20 48 89 45 00 48 8B 44 24 08 48 09 45 00 EB 0D 83 F8 02 0F 94 C0 0F B6 D0 EB 02 31 D2 48 83 C4 18 89 D0 5B 5D C3 }
	condition:
		$pattern
}

rule xdr_hyper_db511f5a61200ede47a9ff44b62c83a0 {
	meta:
		aliases = "__GI_xdr_hyper, xdr_hyper"
		size = "167"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 18 8B 07 85 C0 75 3C 48 8B 16 48 8D 74 24 10 48 89 D0 48 89 54 24 08 48 C1 F8 20 48 89 44 24 10 48 8B 47 08 FF 50 08 31 D2 85 C0 74 66 48 8B 43 08 48 8D 74 24 08 48 89 DF FF 50 08 85 C0 0F 95 C0 EB 49 83 F8 01 75 3E 48 8B 47 08 48 8D 74 24 10 FF 10 85 C0 74 3A 48 8B 43 08 48 8D 74 24 08 48 89 DF FF 10 85 C0 74 28 48 8B 44 24 10 BA 01 00 00 00 48 C1 E0 20 48 89 45 00 48 8B 44 24 08 48 09 45 00 EB 0D 83 F8 02 0F 94 C0 0F B6 D0 EB 02 31 D2 48 83 C4 18 89 D0 5B 5D C3 }
	condition:
		$pattern
}

rule __GI_fgetspent_r_67bf5c69defe49bb1b609a3c6bc27dcd {
	meta:
		aliases = "fgetspent_r, fgetgrent_r, __GI_fgetgrent_r, __GI_fgetpwent_r, fgetpwent_r, __GI_fgetspent_r"
		size = "43"
		objfiles = "fgetgrent_r@libc.a, fgetpwent_r@libc.a, fgetspent_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 4C 89 C3 48 83 EC 08 49 C7 00 00 00 00 00 49 89 F8 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 75 03 48 89 2B 5A 5B 5D C3 }
	condition:
		$pattern
}

rule __ether_line_w_1e258e1d69f6718df3f9fd5f098b3432 {
	meta:
		aliases = "__ether_line_w"
		size = "62"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 BE 23 00 00 00 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 48 85 C0 75 12 BE 0A 00 00 00 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 74 03 C6 00 00 58 48 89 DF 48 89 EE 5B 5D E9 36 FF FF FF }
	condition:
		$pattern
}

rule xdrmem_getbytes_906fdb29c93ec5ae663d583954f38773 {
	meta:
		aliases = "xdrmem_getbytes"
		size = "53"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 31 C0 48 89 F7 53 48 83 EC 08 8B 4D 28 39 D1 72 1C 48 8B 75 18 29 D1 89 D3 89 4D 28 48 89 DA E8 ?? ?? ?? ?? 48 01 5D 18 B8 01 00 00 00 59 5B 5D C3 }
	condition:
		$pattern
}

rule xdrrec_getpos_0c1b4d95139be7e5dffdee6ff00cce74 {
	meta:
		aliases = "xdrrec_getpos"
		size = "87"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 31 F6 BA 01 00 00 00 53 48 83 EC 08 48 8B 5F 18 48 8B 3B E8 ?? ?? ?? ?? 48 89 C1 48 83 F9 FF 74 2E 8B 55 00 85 D2 74 0B FF CA B8 FF FF FF FF 75 1E EB 0E 48 8B 43 20 48 2B 43 18 48 8D 04 01 EB 0E 48 8B 43 60 48 2B 43 58 48 29 C1 48 89 C8 5F 5B 5D C3 }
	condition:
		$pattern
}

rule __pthread_alt_lock_5e44e33924aaf2fc5a932cc9e2f48a62 {
	meta:
		aliases = "__pthread_alt_lock"
		size = "95"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 48 89 F7 53 48 83 EC 38 48 8B 5D 00 BA 01 00 00 00 48 85 DB 74 17 48 85 FF 75 08 E8 92 FF FF FF 48 89 C7 48 8D 54 24 10 48 89 7C 24 18 C7 44 24 20 00 00 00 00 48 89 5C 24 10 48 89 D8 F0 48 0F B1 55 00 0F 94 C2 84 D2 74 BE 48 85 DB 74 05 E8 A3 FF FF FF 48 83 C4 38 5B 5D C3 }
	condition:
		$pattern
}

rule sem_post_ead8327b8b24aa942a4e7fa848a3a60e {
	meta:
		aliases = "__new_sem_post, sem_post"
		size = "237"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 81 EC B8 00 00 00 E8 E4 FC FF FF 48 83 B8 A0 00 00 00 00 48 89 C6 75 72 48 89 EF E8 ?? ?? ?? ?? 48 83 7D 18 00 75 31 8B 45 10 3D FF FF FF 7F 75 15 E8 ?? ?? ?? ?? 48 89 EF C7 00 22 00 00 00 E8 ?? ?? ?? ?? EB 61 FF C0 48 89 EF 89 45 10 E8 ?? ?? ?? ?? E9 83 00 00 00 48 8B 5D 18 48 85 DB 74 10 48 8B 43 10 48 89 45 18 48 C7 43 10 00 00 00 00 48 89 EF E8 ?? ?? ?? ?? C6 83 D2 02 00 00 01 48 89 DF E8 ?? ?? ?? ?? EB 51 83 3D ?? ?? ?? ?? 00 79 19 E8 ?? ?? ?? ?? 85 C0 79 10 E8 ?? ?? ?? ?? C7 00 0B 00 00 00 83 C8 FF EB 31 C7 44 24 08 04 00 00 00 48 89 6C 24 10 8B 3D ?? ?? ?? ?? 48 89 E6 }
	condition:
		$pattern
}

rule __GI_sbrk_f95aed774435c440b9adae9573dd0c5f {
	meta:
		aliases = "sbrk, __GI_sbrk"
		size = "74"
		objfiles = "sbrk@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 83 EC 08 48 83 3D ?? ?? ?? ?? 00 75 0B 31 FF E8 ?? ?? ?? ?? 85 C0 78 21 48 85 ED 48 8B 05 ?? ?? ?? ?? 75 05 48 89 C3 EB 14 48 8D 3C 28 48 89 C3 E8 ?? ?? ?? ?? 85 C0 79 04 48 83 CB FF 5A 48 89 D8 5B 5D C3 }
	condition:
		$pattern
}

rule __GI_strsep_885b17cbd2597523a4ffc25f1e3d43f3 {
	meta:
		aliases = "strsep, __GI_strsep"
		size = "96"
		objfiles = "strsep@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 83 EC 08 48 8B 1F 48 85 DB 74 48 8A 16 84 D2 74 3A 80 7E 01 00 75 1B 8A 0B 48 89 D8 38 D1 74 1A 84 C9 74 27 48 8D 7B 01 0F BE F2 E8 ?? ?? ?? ?? EB 08 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 74 0C C6 00 00 48 FF C0 48 89 45 00 EB 08 48 C7 45 00 00 00 00 00 5A 48 89 D8 5B 5D C3 }
	condition:
		$pattern
}

rule clntudp_destroy_f761b7b762c0cfd2b69e35e3c27f426e {
	meta:
		aliases = "clntudp_destroy"
		size = "64"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 83 EC 08 48 8B 5F 10 83 7B 04 00 74 07 8B 3B E8 ?? ?? ?? ?? 48 8B 43 60 48 8B 40 38 48 85 C0 74 06 48 8D 7B 58 FF D0 48 89 DF E8 ?? ?? ?? ?? 58 5B 48 89 EF 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clnttcp_destroy_f7eb49cfac3e3b828da9501c51183aa0 {
	meta:
		aliases = "clnttcp_destroy"
		size = "64"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 83 EC 08 48 8B 5F 10 83 7B 04 00 74 07 8B 3B E8 ?? ?? ?? ?? 48 8B 43 70 48 8B 40 38 48 85 C0 74 06 48 8D 7B 68 FF D0 48 89 DF E8 ?? ?? ?? ?? 58 5B 48 89 EF 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clntunix_destroy_350c100710d7db2c7b9aac28aea507c3 {
	meta:
		aliases = "clntunix_destroy"
		size = "70"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 83 EC 08 48 8B 5F 10 83 7B 04 00 74 07 8B 3B E8 ?? ?? ?? ?? 48 8B 83 D0 00 00 00 48 8B 40 38 48 85 C0 74 09 48 8D BB C8 00 00 00 FF D0 48 89 DF E8 ?? ?? ?? ?? 58 5B 48 89 EF 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule authunix_destroy_6977662a66273db4ccf27bc3e0ea12fc {
	meta:
		aliases = "authunix_destroy"
		size = "70"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 83 EC 08 48 8B 5F 40 48 8B 7B 08 E8 ?? ?? ?? ?? 48 8B 7B 20 48 85 FF 74 05 E8 ?? ?? ?? ?? 48 8B 7D 40 E8 ?? ?? ?? ?? 48 8B 7D 20 48 85 FF 74 05 E8 ?? ?? ?? ?? 58 5B 48 89 EF 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __cxa_finalize_63b570aae33cad5021ca38560fe1309a {
	meta:
		aliases = "__cxa_finalize"
		size = "77"
		objfiles = "__cxa_finalize@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 83 EC 08 8B 1D ?? ?? ?? ?? EB 34 FF CB 48 63 CB 48 C1 E1 05 48 03 0D ?? ?? ?? ?? 48 85 ED 74 06 48 3B 69 18 75 19 31 D2 B8 03 00 00 00 F0 48 0F B1 11 48 83 F8 03 75 07 48 8B 79 10 FF 51 08 85 DB 75 C8 58 5B 5D C3 }
	condition:
		$pattern
}

rule getttynam_575a61386e463fe1f43941c898bb5a6f {
	meta:
		aliases = "getttynam"
		size = "56"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 83 EC 08 E8 ?? ?? ?? ?? EB 0F 48 8B 33 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 0D E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 75 E4 E8 ?? ?? ?? ?? 5E 48 89 D8 5B 5D C3 }
	condition:
		$pattern
}

rule __getutid_db5b4dc38b0bbd5dd53394d37875cb44 {
	meta:
		aliases = "__getutid"
		size = "106"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 83 EC 08 EB 45 8B 4D 00 8D 41 FF 66 83 F8 03 77 05 66 39 0B 74 47 66 83 F9 05 0F 94 C2 66 83 F9 08 0F 94 C0 08 C2 75 0C 66 83 F9 06 74 06 66 83 F9 07 75 16 48 8D 75 28 48 8D 7B 28 BA 04 00 00 00 E8 ?? ?? ?? ?? 85 C0 74 13 8B 3D ?? ?? ?? ?? E8 72 FF FF FF 48 85 C0 48 89 C3 75 A8 5E 48 89 D8 5B 5D C3 }
	condition:
		$pattern
}

rule __GI_fgetc_539950c5b176b846a1a514db270db142 {
	meta:
		aliases = "getc, fgetc, __GI_fgetc"
		size = "128"
		objfiles = "fgetc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 83 EC 28 83 7F 50 00 74 1F 48 8B 47 18 48 3B 47 28 73 0C 0F B6 18 48 FF C0 48 89 47 18 EB 52 E8 ?? ?? ?? ?? 89 C3 EB 49 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8B 45 18 48 3B 45 28 73 0C 0F B6 18 48 FF C0 48 89 45 18 EB 0A 48 89 EF E8 ?? ?? ?? ?? 89 C3 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 89 D8 48 83 C4 28 5B 5D C3 }
	condition:
		$pattern
}

rule __GI_xdr_callhdr_c429209e682ad1afaad3ecd6624b28c7 {
	meta:
		aliases = "xdr_callhdr, __GI_xdr_callhdr"
		size = "110"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 F3 48 83 EC 08 C7 46 08 00 00 00 00 48 C7 46 10 02 00 00 00 83 3F 00 75 48 E8 ?? ?? ?? ?? 85 C0 74 3F 48 8D 73 08 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 2F 48 8D 73 10 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 1F 48 8D 73 18 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 0F 59 48 8D 73 20 48 89 EF 5B 5D E9 ?? ?? ?? ?? 5A 5B 5D 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_attr_setguardsize_ff97678b3d9e070dde8c8ab97bb17c44 {
	meta:
		aliases = "__pthread_attr_setguardsize, pthread_attr_setguardsize"
		size = "61"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 F3 48 83 EC 08 E8 ?? ?? ?? ?? 48 63 F0 48 8D 54 33 FF 48 89 D0 31 D2 48 F7 F6 48 89 C1 B8 16 00 00 00 48 0F AF CE 48 3B 4D 30 73 06 48 89 4D 18 30 C0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule __GI_xdr_opaque_auth_2f55d83a6c9d31fe49db5ca7db5b9551 {
	meta:
		aliases = "xdr_opaque_auth, __GI_xdr_opaque_auth"
		size = "51"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 F3 48 83 EC 08 E8 ?? ?? ?? ?? 85 C0 74 18 48 89 EF 48 8D 53 10 48 8D 73 08 5D 5B 5D B9 90 01 00 00 E9 ?? ?? ?? ?? 5B 5B 5D 31 C0 C3 }
	condition:
		$pattern
}

rule xdr_pmap_75bd662cca70214c396a8b303be84b7a {
	meta:
		aliases = "__GI_xdr_pmap, xdr_pmap"
		size = "74"
		objfiles = "pmap_prot@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 F3 48 83 EC 08 E8 ?? ?? ?? ?? 85 C0 74 2F 48 8D 73 08 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 1F 48 8D 73 10 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 0F 59 48 8D 73 18 48 89 EF 5B 5D E9 ?? ?? ?? ?? 5A 5B 5D 31 C0 C3 }
	condition:
		$pattern
}

rule xdr_replymsg_920297952047947107413ad82eaa34be {
	meta:
		aliases = "__GI_xdr_replymsg, xdr_replymsg"
		size = "78"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 F3 48 83 EC 08 E8 ?? ?? ?? ?? 85 C0 74 32 48 8D 73 08 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 22 83 7B 08 01 75 1C 41 5B 48 8D 53 18 48 8D 73 10 48 89 EF 5B 5D 45 31 C0 B9 ?? ?? ?? ?? E9 ?? ?? ?? ?? 41 5A 5B 5D 31 C0 C3 }
	condition:
		$pattern
}

rule __GI_xdr_rejected_reply_8f8430bcd8d5d4117f5af1b1d473c692 {
	meta:
		aliases = "xdr_rejected_reply, __GI_xdr_rejected_reply"
		size = "87"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 F3 48 83 EC 08 E8 ?? ?? ?? ?? 85 C0 74 3C 8B 03 85 C0 74 06 FF C8 75 32 EB 20 48 8D 73 08 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 20 41 59 48 8D 73 10 48 89 EF 5B 5D E9 ?? ?? ?? ?? 41 58 48 8D 73 08 48 89 EF 5B 5D E9 ?? ?? ?? ?? 5E 5B 5D 31 C0 C3 }
	condition:
		$pattern
}

rule __GI_xdr_accepted_reply_507fdc2954f4f34d2196767c5f2c19d6 {
	meta:
		aliases = "xdr_accepted_reply, __GI_xdr_accepted_reply"
		size = "113"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 F3 48 83 EC 08 E8 ?? ?? ?? ?? 85 C0 74 56 48 8D 73 18 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 46 8B 53 18 85 D2 74 0C 83 FA 02 B8 01 00 00 00 75 37 EB 14 48 8B 73 20 4C 8B 5B 28 48 89 EF 41 58 5B 5D 31 C0 41 FF E3 48 8D 73 20 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 0F 59 48 8D 73 28 48 89 EF 5B 5D E9 ?? ?? ?? ?? 31 C0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule __GI_xdr_authunix_parms_030cc0796fea945de926145f6ff93f8a {
	meta:
		aliases = "xdr_authunix_parms, __GI_xdr_authunix_parms"
		size = "123"
		objfiles = "authunix_prot@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 F3 48 83 EC 08 E8 ?? ?? ?? ?? 85 C0 74 60 48 8D 73 08 BA FF 00 00 00 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 4B 48 8D 73 10 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 3B 48 8D 73 14 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 2B 48 8D 53 18 48 8D 73 20 41 B9 ?? ?? ?? ?? 41 B8 04 00 00 00 B9 10 00 00 00 48 89 EF E8 ?? ?? ?? ?? 85 C0 0F 95 C0 0F B6 C0 EB 02 31 C0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule skip_input_bytes_bdf38138316babc95f075d5ef11e9e6b {
	meta:
		aliases = "skip_input_bytes"
		size = "77"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 F3 48 83 EC 08 EB 31 48 8B 55 58 48 8B 45 60 29 D0 85 C0 75 0E 48 89 EF E8 98 FF FF FF 85 C0 75 17 EB 1F 48 98 48 39 D8 48 0F 4F C3 48 98 48 01 C2 48 29 C3 48 89 55 58 48 85 DB 7F CA B8 01 00 00 00 59 5B 5D C3 }
	condition:
		$pattern
}

rule dl_iterate_phdr_2605263bd07fe88e633ced46b383bc7e {
	meta:
		aliases = "dl_iterate_phdr"
		size = "93"
		objfiles = "dl_iterate_phdr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 F3 48 83 EC 28 48 8B 15 ?? ?? ?? ?? 48 85 D2 74 33 48 8B 05 ?? ?? ?? ?? 66 89 54 24 18 48 89 E7 48 89 F2 48 C7 04 24 00 00 00 00 48 C7 44 24 08 ?? ?? ?? ?? BE 20 00 00 00 48 89 44 24 10 FF D5 85 C0 75 0B 48 89 DE 48 89 EF E8 ?? ?? ?? ?? 48 83 C4 28 5B 5D C3 }
	condition:
		$pattern
}

rule if_freenameindex_2f6f60edecf5f389aaaded6206a74c33 {
	meta:
		aliases = "__GI_if_freenameindex, if_freenameindex"
		size = "48"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 FB 48 83 EC 08 EB 09 48 83 C3 10 E8 ?? ?? ?? ?? 48 8B 7B 08 48 85 FF 75 EE 83 3B 00 75 E9 58 5B 48 89 EF 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _longjmp_a604e997d5b680e2fc631f181478479f {
	meta:
		aliases = "__libc_longjmp, __libc_siglongjmp, siglongjmp, longjmp, _longjmp"
		size = "53"
		objfiles = "longjmp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 89 F3 48 83 EC 08 83 7F 40 00 74 10 48 8D 77 48 31 D2 BF 02 00 00 00 E8 ?? ?? ?? ?? 85 DB B8 01 00 00 00 48 89 EF 0F 44 D8 89 DE E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule encrypt_ceb6e3f8d11b356cd2ec29ac9c657797 {
	meta:
		aliases = "encrypt"
		size = "175"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 89 F3 48 83 EC 18 E8 B5 F8 FF FF 31 FF E8 B3 FC FF FF 48 89 EE 31 FF EB 2F 48 63 C7 31 C9 C7 04 84 00 00 00 00 EB 1A F6 06 01 74 10 48 63 C7 48 63 D1 8B 14 95 ?? ?? ?? ?? 09 14 84 48 FF C6 FF C1 83 F9 1F 7E E1 FF C7 83 FF 01 7E CC 83 FB 01 8B 3C 24 8B 74 24 04 45 19 C0 48 8D 4C 24 04 48 89 E2 41 83 E0 02 41 FF C8 E8 9D FC FF FF 31 FF EB 28 89 FA 48 63 C6 48 63 CF C1 E2 05 8B 04 85 ?? ?? ?? ?? 09 F2 85 04 8C 48 63 D2 0F 95 44 15 00 FF C6 83 FE 1F 7E DA FF C7 83 FF 01 7F 04 31 F6 EB F0 48 83 C4 18 5B 5D C3 }
	condition:
		$pattern
}

rule tmpnam_88256821774b505fd7644d593d811c46 {
	meta:
		aliases = "tmpnam"
		size = "97"
		objfiles = "tmpnam@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD BE 14 00 00 00 53 48 89 FB 48 83 EC 28 48 85 FF 48 0F 44 EC 31 C9 31 D2 48 89 EF E8 ?? ?? ?? ?? 85 C0 75 2D BE 03 00 00 00 48 89 EF E8 ?? ?? ?? ?? 85 C0 75 1C 48 85 DB 75 19 BA 14 00 00 00 48 89 EE BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C3 EB 02 31 DB 48 89 D8 48 83 C4 28 5B 5D C3 }
	condition:
		$pattern
}

rule logout_6ebdcc4c707407b39aed7e53c7f115f8 {
	meta:
		aliases = "logout"
		size = "161"
		objfiles = "logout@libutil.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD BF ?? ?? ?? ?? 53 31 DB 48 81 EC 98 01 00 00 E8 ?? ?? ?? ?? FF C0 74 79 E8 ?? ?? ?? ?? 48 8D 7C 24 08 BA 20 00 00 00 48 89 EE 66 C7 04 24 07 00 E8 ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 45 48 8D 78 2C 31 F6 BA 20 00 00 00 E8 ?? ?? ?? ?? 48 8D 7B 4C BA 00 01 00 00 31 F6 E8 ?? ?? ?? ?? 48 8D BB 58 01 00 00 31 F6 E8 ?? ?? ?? ?? 66 C7 03 08 00 48 89 DF BB 01 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 75 02 31 DB E8 ?? ?? ?? ?? 89 D8 48 81 C4 98 01 00 00 5B 5D C3 }
	condition:
		$pattern
}

rule getlogin_r_375c6f2d90b7683285d3b9bff08df4cd {
	meta:
		aliases = "getlogin_r"
		size = "55"
		objfiles = "getlogin@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD BF ?? ?? ?? ?? 53 48 89 F3 48 83 EC 08 E8 ?? ?? ?? ?? 48 89 C6 83 C8 FF 48 85 F6 74 12 48 89 DA 48 89 EF E8 ?? ?? ?? ?? C6 44 1D FF 00 31 C0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule login_62f6d0c7b4496e6d390aa9b7f807f175 {
	meta:
		aliases = "login"
		size = "100"
		objfiles = "login@libutil.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FE BA 90 01 00 00 53 48 89 FB 48 81 EC 98 01 00 00 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 C7 04 24 07 00 E8 ?? ?? ?? ?? 48 8D 73 08 48 8D 7C 24 08 BA 20 00 00 00 89 44 24 04 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 81 C4 98 01 00 00 5B 5D C3 }
	condition:
		$pattern
}

rule uw_install_context_b3ff91ba13d30641dc051848fa5aa308 {
	meta:
		aliases = "uw_install_context"
		size = "32"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 8B 06 48 89 E5 48 8D 50 40 48 89 05 ?? ?? ?? ?? 48 8B 4A 08 48 8B 68 40 48 8B 62 10 FF E1 }
	condition:
		$pattern
}

rule nan_dd42873838eaef5a9f6dd77150ec622e {
	meta:
		aliases = "__GI_nan, nan"
		size = "119"
		objfiles = "nan@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 48 B8 00 00 00 00 00 00 F8 7F 48 89 E5 41 55 49 89 FD 41 54 53 48 83 EC 08 80 3F 00 74 44 E8 ?? ?? ?? ?? 48 83 C0 24 48 89 E3 4C 89 EA 48 83 E0 F0 BE ?? ?? ?? ?? 48 29 C4 31 C0 4C 8D 64 24 0F 49 83 E4 F0 4C 89 E7 E8 ?? ?? ?? ?? 31 F6 4C 89 E7 E8 ?? ?? ?? ?? F2 0F 11 45 E0 48 8B 45 E0 48 89 DC 48 89 45 E0 66 0F 12 45 E0 48 8D 65 E8 5B 41 5C 41 5D C9 C3 }
	condition:
		$pattern
}

rule _time_t2tm_664121c146c32a41586ddc706a049f3f {
	meta:
		aliases = "_time_t2tm"
		size = "408"
		objfiles = "_time_t2tm@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 49 89 D3 49 89 D1 53 89 F3 48 8B 0F BE ?? ?? ?? ?? C7 42 1C 00 00 00 00 66 44 8B 16 41 0F B7 FA 48 83 FF 07 75 4F 48 63 C3 48 BA F0 51 B8 2E 6D 01 00 00 4C 8D 04 01 48 B8 D8 8C 5C 97 B6 00 00 00 49 8D 04 00 48 39 D0 0F 87 EE 00 00 00 48 89 C8 41 0F B7 CA 48 99 48 F7 FF 8D 42 0B 99 F7 F9 0F B7 46 02 49 8D 88 76 0E 02 00 48 8D 3C 85 01 00 00 00 89 D5 48 89 C8 48 99 48 F7 FF 49 89 C0 48 0F AF C7 48 29 C1 79 06 48 01 F9 49 FF C8 66 41 83 FA 07 75 11 48 8D 47 FF 48 39 C1 75 08 41 FF 41 10 48 8D 4F FE 48 83 FF 3C 49 8D 51 04 7F 0B 41 89 09 49 89 D1 4C 89 C1 EB 06 45 89 01 49 89 D1 48 83 C6 02 66 }
	condition:
		$pattern
}

rule forkpty_b1a1a2e8909ecddfbf9e6839c05c61c6 {
	meta:
		aliases = "forkpty"
		size = "114"
		objfiles = "forkpty@libutil.a"
	strings:
		$pattern = { ( CC | 55 ) 49 89 F1 48 89 FD 49 89 C8 48 89 D1 4C 89 CA 53 48 83 EC 18 48 8D 74 24 10 48 8D 7C 24 14 E8 ?? ?? ?? ?? FF C0 74 3E E8 ?? ?? ?? ?? 83 F8 FF 89 C3 74 32 85 C0 8B 7C 24 14 75 1C E8 ?? ?? ?? ?? 8B 7C 24 10 E8 ?? ?? ?? ?? 85 C0 74 1B BF 01 00 00 00 E8 ?? ?? ?? ?? 89 7D 00 8B 7C 24 10 E8 ?? ?? ?? ?? EB 03 83 CB FF 89 D8 48 83 C4 18 5B 5D C3 }
	condition:
		$pattern
}

rule pthread_initialize_85936bd8a22a75cc1f32235b44dcdc2c {
	meta:
		aliases = "pthread_initialize"
		size = "421"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 81 EC 38 01 00 00 48 83 3D ?? ?? ?? ?? 00 0F 85 84 01 00 00 48 8D 84 24 00 00 C0 FF 48 25 00 00 E0 FF 48 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 EB 11 83 78 50 01 74 07 C7 40 50 00 00 00 00 48 8B 40 38 48 85 C0 75 EA 48 8D 9C 24 20 01 00 00 BF 03 00 00 00 48 89 DE E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA 00 00 20 00 01 C0 29 C2 48 63 C2 48 39 84 24 20 01 00 00 76 15 48 89 DE BF 03 00 00 00 48 89 84 24 20 01 00 00 E8 ?? ?? ?? ?? 48 8D 5C 24 08 48 C7 04 24 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sethostid_fb7144e35b4174d2fc15f0a05395e933 {
	meta:
		aliases = "sethostid"
		size = "116"
		objfiles = "hostid@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 83 EC 08 48 89 3C 24 E8 ?? ?? ?? ?? 85 C0 75 09 E8 ?? ?? ?? ?? 85 C0 74 12 BB 01 00 00 00 E8 ?? ?? ?? ?? C7 00 01 00 00 00 EB 40 31 C0 BA A4 01 00 00 BE 41 00 00 00 BF ?? ?? ?? ?? 83 CB FF E8 ?? ?? ?? ?? 85 C0 89 C5 78 21 89 C7 48 89 E6 BA 08 00 00 00 E8 ?? ?? ?? ?? 31 DB 48 83 F8 08 89 EF 0F 94 C3 FF CB E8 ?? ?? ?? ?? 5A 89 D8 5B 5D C3 }
	condition:
		$pattern
}

rule token_89e9118e86805082faf510d4dac085ee {
	meta:
		aliases = "token"
		size = "424"
		objfiles = "ruserpass@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 83 EC 08 48 8B 05 ?? ?? ?? ?? 0F B7 00 A8 0C 0F 85 8A 01 00 00 48 8B 3D ?? ?? ?? ?? 48 8B 47 18 48 3B 47 28 73 0C 0F B6 08 48 FF C0 48 89 47 18 EB 07 E8 ?? ?? ?? ?? 89 C1 83 F9 FF 0F 84 5D 01 00 00 8D 41 F7 83 F8 01 0F 96 C2 83 F9 20 0F 94 C0 08 C2 75 C0 83 F9 2C 74 BB 83 F9 FF 0F 84 3C 01 00 00 83 F9 22 BB ?? ?? ?? ?? 74 30 EB 65 83 FA 5C 75 24 48 8B 3D ?? ?? ?? ?? 48 8B 47 18 48 3B 47 28 73 0C 0F B6 10 48 FF C0 48 89 47 18 EB 07 E8 ?? ?? ?? ?? 89 C2 88 13 48 FF C3 48 8B 3D ?? ?? ?? ?? 48 8B 47 18 48 3B 47 28 73 0C 0F B6 10 48 FF C0 48 89 47 18 EB 07 E8 ?? ?? ?? ?? 89 C2 83 FA FF 0F }
	condition:
		$pattern
}

rule _dl_run_fini_array_8e0d32ddaaaa14c2b3cecec913e7ac2f {
	meta:
		aliases = "_dl_run_fini_array"
		size = "57"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 83 EC 08 48 8B 87 50 01 00 00 48 85 C0 74 23 48 89 C5 48 8B 87 60 01 00 00 48 03 2F 48 89 C3 48 C1 EB 03 EB 06 89 D8 FF 54 C5 00 FF CB 83 FB FF 75 F3 58 5B 5D C3 }
	condition:
		$pattern
}

rule fmin_05ebbaadf42ae3bec441a0964c6f67aa {
	meta:
		aliases = "__GI_fmin, fmin"
		size = "95"
		objfiles = "s_fmin@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 83 EC 08 F2 0F 11 04 24 48 8B 1C 24 F2 0F 11 0C 24 48 8B 2C 24 48 89 1C 24 E8 ?? ?? ?? ?? 85 C0 74 2D 48 89 2C 24 66 0F 12 04 24 E8 ?? ?? ?? ?? 85 C0 74 18 48 89 2C 24 66 0F 12 04 24 48 89 1C 24 66 0F 12 0C 24 66 0F 2E C1 77 03 48 89 EB 48 89 1C 24 66 0F 12 04 24 58 5B 5D C3 }
	condition:
		$pattern
}

rule pthread_reap_children_94adba75d2b7a89ecaa28df49dc6962a {
	meta:
		aliases = "pthread_reap_children"
		size = "255"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 83 EC 18 E9 D3 00 00 00 48 8B 15 ?? ?? ?? ?? 48 8B 2A EB 7C 39 45 28 48 8B 7D 00 75 70 48 8B 45 08 31 F6 48 89 47 08 48 8B 45 08 48 89 38 48 8B 7D 30 E8 ?? ?? ?? ?? 83 BD A4 02 00 00 00 C6 45 52 01 74 2E 8B 05 ?? ?? ?? ?? 0B 85 A8 02 00 00 F6 C4 08 74 1D C7 85 B0 02 00 00 0C 00 00 00 48 89 AD B8 02 00 00 48 89 2D ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F BE 5D 51 48 8B 7D 30 E8 ?? ?? ?? ?? 85 DB 74 16 48 89 EF E8 AB FE FF FF EB 0C 48 89 FD 48 39 D5 0F 85 7B FF FF FF 83 3D ?? ?? ?? ?? 00 74 14 48 8B 05 ?? ?? ?? ?? 48 8B 38 48 39 C7 75 05 E8 42 FF FF FF 8B 7C 24 14 89 F8 83 E0 7F FF C0 D0 F8 84 C0 }
	condition:
		$pattern
}

rule getttyent_5489460da85c15046cdc158841674c99 {
	meta:
		aliases = "__GI_getttyent, getttyent"
		size = "732"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 83 EC 28 48 83 3D ?? ?? ?? ?? 00 75 0F E8 ?? ?? ?? ?? 31 DB 85 C0 0F 84 B3 02 00 00 48 83 3D ?? ?? ?? ?? 00 75 1B BF 00 10 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 75 05 E8 ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? 48 89 E7 BE ?? ?? ?? ?? 48 83 C2 58 E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 83 C7 58 E8 ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? BE 00 10 00 00 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 0F 84 29 02 00 00 BE 0A 00 00 00 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 75 32 48 8B 3D ?? ?? ?? ?? 48 8B 47 18 48 3B 47 28 73 0C 0F B6 10 48 FF C0 48 89 47 18 EB 07 E8 ?? ?? ?? ?? 89 C2 83 FA }
	condition:
		$pattern
}

rule getchar_d82d64feb99a75213daaa7280bc1b43a {
	meta:
		aliases = "getchar"
		size = "135"
		objfiles = "getchar@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 83 EC 28 48 8B 2D ?? ?? ?? ?? 83 7D 50 00 74 22 48 8B 45 18 48 3B 45 28 73 0C 0F B6 18 48 FF C0 48 89 45 18 EB 55 48 89 EF E8 ?? ?? ?? ?? 89 C3 EB 49 48 8D 5D 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8B 45 18 48 3B 45 28 73 0C 0F B6 18 48 FF C0 48 89 45 18 EB 0A 48 89 EF E8 ?? ?? ?? ?? 89 C3 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 89 D8 48 83 C4 28 5B 5D C3 }
	condition:
		$pattern
}

rule authnone_create_d06d018dfda877325399247645a91480 {
	meta:
		aliases = "__GI_authnone_create, authnone_create"
		size = "186"
		objfiles = "auth_none@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 83 EC 38 E8 ?? ?? ?? ?? 48 8B 98 B0 00 00 00 48 89 C5 48 85 DB 75 20 BF 01 00 00 00 BE 60 00 00 00 E8 ?? ?? ?? ?? 31 FF 48 85 C0 48 89 C3 74 7D 48 89 85 B0 00 00 00 83 7B 5C 00 75 6D FC 48 8D 7B 18 BE ?? ?? ?? ?? B9 06 00 00 00 F3 A5 48 8D 73 18 48 89 DF BA 14 00 00 00 48 C7 43 38 ?? ?? ?? ?? B1 06 F3 A5 48 8D 73 48 48 89 E7 E8 ?? ?? ?? ?? 48 89 DE 48 89 E7 E8 ?? ?? ?? ?? 48 8D 73 18 48 89 E7 E8 ?? ?? ?? ?? 48 8B 44 24 08 48 89 E7 FF 50 20 89 43 5C 48 8B 44 24 08 48 8B 40 38 48 85 C0 74 05 48 89 E7 FF D0 48 89 DF 48 83 C4 38 48 89 F8 5B 5D C3 }
	condition:
		$pattern
}

rule statfs64_60f584c2814ea6f96f402226aaa9e636 {
	meta:
		aliases = "__GI_fstatfs64, fstatfs64, __GI_statfs64, statfs64"
		size = "144"
		objfiles = "statfs64@libc.a, fstatfs64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 F3 48 81 EC 88 00 00 00 48 89 E6 E8 ?? ?? ?? ?? 83 CA FF 85 C0 78 69 48 8B 04 24 48 8D 74 24 50 48 8D 7B 50 BA 28 00 00 00 48 89 03 48 8B 44 24 08 48 89 43 08 48 8B 44 24 10 48 89 43 10 48 8B 44 24 18 48 89 43 18 48 8B 44 24 20 48 89 43 20 48 8B 44 24 28 48 89 43 28 48 8B 44 24 30 48 89 43 30 8B 44 24 3C 89 43 3C 8B 44 24 38 89 43 38 48 8B 44 24 40 48 89 43 40 E8 ?? ?? ?? ?? 31 D2 48 81 C4 88 00 00 00 89 D0 5B 5D C3 }
	condition:
		$pattern
}

rule psignal_76bddc8501b552cb9759b53e22a2d350 {
	meta:
		aliases = "psignal"
		size = "69"
		objfiles = "psignal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 F3 48 83 EC 08 48 85 F6 74 0A 80 3E 00 BD ?? ?? ?? ?? 75 08 BB ?? ?? ?? ?? 48 89 DD E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 89 DA 48 89 E9 41 59 5B 5D 49 89 C0 BE ?? ?? ?? ?? 31 C0 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule popen_569fa8fc1a875db96f8fc20743138b5c {
	meta:
		aliases = "popen"
		size = "485"
		objfiles = "popen@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 F3 48 83 EC 68 48 89 7C 24 08 8A 06 3C 77 74 1C 3C 72 C7 44 24 2C 01 00 00 00 74 18 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 A0 01 00 00 C7 44 24 2C 00 00 00 00 BF 18 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 44 24 18 48 C7 44 24 10 00 00 00 00 0F 84 80 01 00 00 48 8D 7C 24 50 E8 ?? ?? ?? ?? 85 C0 0F 85 5B 01 00 00 48 63 44 24 2C 48 89 DE 8B 44 84 50 89 44 24 28 B8 01 00 00 00 2B 44 24 2C 48 98 8B 44 84 50 89 C7 89 44 24 24 E8 ?? ?? ?? ?? 48 85 C0 48 89 44 24 10 75 17 8B 7C 24 24 E8 ?? ?? ?? ?? 8B 7C 24 28 E8 ?? ?? ?? ?? E9 10 01 00 00 48 8D 7C 24 30 BA ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? }
	condition:
		$pattern
}

rule herror_10d80b46e072d29cf44f91c37cd159da {
	meta:
		aliases = "__GI_herror, herror"
		size = "88"
		objfiles = "herror@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 48 85 FF 74 0A 80 3F 00 BD ?? ?? ?? ?? 75 05 BD ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 00 BA ?? ?? ?? ?? 83 F8 04 77 0A 48 98 48 8B 14 C5 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 49 89 D0 48 89 DA 41 59 5B 48 89 E9 BE ?? ?? ?? ?? 31 C0 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fill_input_buf_1c976b3ab5a786bb1de46983df1b5509 {
	meta:
		aliases = "fill_input_buf"
		size = "68"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 48 8B 47 60 48 8B 6F 50 48 8B 57 48 48 8B 3F 83 E0 03 48 01 C5 29 C2 48 89 EE FF 53 40 31 D2 83 F8 FF 74 11 48 98 48 89 6B 58 B2 01 48 8D 44 05 00 48 89 43 60 89 D0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule svcunix_destroy_7940c3b762aa43ef9c546b5bf68818e0 {
	meta:
		aliases = "svctcp_destroy, svcunix_destroy"
		size = "78"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 48 8B 6F 40 E8 ?? ?? ?? ?? 8B 3B E8 ?? ?? ?? ?? 66 83 7B 04 00 74 08 66 C7 43 04 00 00 EB 13 48 8B 45 18 48 8B 40 38 48 85 C0 74 06 48 8D 7D 10 FF D0 48 89 EF E8 ?? ?? ?? ?? 58 48 89 DF 5B 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svcudp_destroy_747358f2eec5a0c03e16e1a9ec14b1ca {
	meta:
		aliases = "svcudp_destroy"
		size = "72"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 48 8B 6F 48 E8 ?? ?? ?? ?? 8B 3B E8 ?? ?? ?? ?? 48 8B 45 18 48 8B 40 38 48 85 C0 74 06 48 8D 7D 10 FF D0 48 8B 7B 40 E8 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 58 48 89 DF 5B 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_xdr_opaque_5aa762b42166feb40c3dcae05641c1dc {
	meta:
		aliases = "xdr_opaque, __GI_xdr_opaque"
		size = "136"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 85 D2 74 6E 89 D0 31 ED 83 E0 03 74 05 40 B5 04 29 C5 8B 03 83 F8 01 74 09 72 2D 83 F8 02 75 59 EB 50 48 8B 43 08 48 89 DF FF 50 10 85 C0 74 49 85 ED 74 3E 48 8B 43 08 89 EA BE ?? ?? ?? ?? 48 89 DF 4C 8B 58 10 EB 24 48 8B 43 08 48 89 DF FF 50 18 85 C0 74 23 85 ED 74 18 48 8B 43 08 89 EA BE ?? ?? ?? ?? 48 89 DF 4C 8B 58 18 58 5B 5D 41 FF E3 B8 01 00 00 00 EB 02 31 C0 5D 5B 5D C3 }
	condition:
		$pattern
}

rule pthread_mutex_lock_92a90922ac76d7cad67b4098a154e0a2 {
	meta:
		aliases = "__pthread_mutex_lock, pthread_mutex_lock"
		size = "153"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 8B 47 10 83 F8 01 74 26 7F 06 85 C0 74 13 EB 0A 83 F8 02 74 45 83 F8 03 74 65 B8 16 00 00 00 EB 6B 48 8D 7F 18 31 F6 E8 ?? ?? ?? ?? EB 5C E8 9B FD FF FF 48 39 43 08 48 89 C5 75 05 FF 43 04 EB 49 48 8D 7B 18 48 89 C6 E8 ?? ?? ?? ?? 48 89 6B 08 C7 43 04 00 00 00 00 EB 30 E8 6F FD FF FF 48 89 C5 48 39 6B 08 B8 23 00 00 00 74 1F 48 8D 7B 18 48 89 EE E8 ?? ?? ?? ?? 48 89 6B 08 EB 0B 48 8D 7F 18 31 F6 E8 ?? ?? ?? ?? 31 C0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule pthread_rwlock_wrlock_db7dcf535b92696889ce9a534f5de5d2 {
	meta:
		aliases = "pthread_rwlock_wrlock"
		size = "89"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 E8 6B FF FF FF 48 89 C5 48 89 EE 48 89 DF E8 ?? ?? ?? ?? 83 7B 10 00 75 07 48 83 7B 18 00 74 1E 48 8D 7B 28 48 89 EE E8 2E FE FF FF 48 89 DF E8 ?? ?? ?? ?? 48 89 EF E8 B6 FF FF FF EB CA 48 89 6B 18 48 89 DF E8 ?? ?? ?? ?? 59 5B 5D 31 C0 C3 }
	condition:
		$pattern
}

rule __pthread_acquire_f174301b3244be5fcaccc1f5f22f7c7f {
	meta:
		aliases = "__pthread_acquire"
		size = "73"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 18 EB 29 83 FD 31 7F 09 FF C5 E8 ?? ?? ?? ?? EB 1D 48 89 E7 31 F6 48 C7 04 24 00 00 00 00 48 C7 44 24 08 81 84 1E 00 E8 ?? ?? ?? ?? 31 ED B8 01 00 00 00 87 03 48 85 C0 75 C9 48 83 C4 18 5B 5D C3 }
	condition:
		$pattern
}

rule _Unwind_SjLj_RaiseException_fbf77ce0eba89efa0c23c34ade276b44 {
	meta:
		aliases = "_Unwind_SjLj_RaiseException"
		size = "172"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 28 48 8B 05 ?? ?? ?? ?? 48 85 C0 48 89 44 24 10 48 89 04 24 75 06 EB 38 48 89 04 24 48 8B 40 30 48 85 C0 74 1F 49 89 E0 48 89 D9 48 8B 13 BE 01 00 00 00 BF 01 00 00 00 FF D0 83 F8 06 74 1D 83 F8 08 75 54 48 8B 04 24 48 8B 00 48 85 C0 75 C8 B8 05 00 00 00 48 83 C4 28 5B 5D C3 48 8B 04 24 48 C7 43 10 00 00 00 00 48 89 E6 48 89 DF 48 89 43 18 48 8B 44 24 10 48 89 04 24 E8 48 FE FF FF 83 F8 07 75 D0 48 8D 7C 24 10 48 89 E6 E8 B6 FE FF FF 66 66 90 66 66 90 48 83 C4 28 B8 03 00 00 00 5B 5D C3 }
	condition:
		$pattern
}

rule sem_wait_4d7d43f0544465d0f6ecd41218cbe4d4 {
	meta:
		aliases = "__new_sem_wait, sem_wait"
		size = "283"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 28 E8 02 FE FF FF 48 89 44 24 18 48 8B 74 24 18 48 89 DF 48 89 1C 24 48 C7 44 24 08 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 43 10 85 C0 7E 12 FF C8 48 89 DF 89 43 10 E8 ?? ?? ?? ?? E9 CC 00 00 00 48 8B 44 24 18 48 89 E6 C6 80 D2 02 00 00 00 48 8B 7C 24 18 E8 93 FC FF FF 48 8B 44 24 18 80 78 7A 00 74 10 48 8B 44 24 18 BD 01 00 00 00 80 78 78 00 74 10 48 8B 74 24 18 48 8D 7B 18 31 ED E8 15 FC FF FF 48 89 DF E8 ?? ?? ?? ?? 85 ED 74 0E 48 8B 7C 24 18 31 F6 E8 50 FC FF FF EB 62 48 8B 7C 24 18 E8 EC FD FF FF 48 8B 44 24 18 80 B8 D2 02 00 00 00 75 19 48 8B 44 24 18 80 B8 D0 02 00 00 00 }
	condition:
		$pattern
}

rule pthread_rwlock_rdlock_c43f89bd6455dd4cf93e81dcce094127 {
	meta:
		aliases = "pthread_rwlock_rdlock"
		size = "179"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 89 DE 48 83 EC 28 48 8D 4C 24 24 48 8D 54 24 10 48 8D 7C 24 18 48 C7 44 24 18 00 00 00 00 E8 7C FE FF FF 89 C5 48 83 7C 24 18 00 75 0A E8 8D FD FF FF 48 89 44 24 18 48 8B 74 24 18 48 89 DF E8 ?? ?? ?? ?? 89 EE 48 89 DF E8 7B FC FF FF 85 C0 75 22 48 8B 74 24 18 48 8D 7B 20 E8 49 FC FF FF 48 89 DF E8 ?? ?? ?? ?? 48 8B 7C 24 18 E8 CF FD FF FF EB B1 FF 43 10 48 89 DF E8 ?? ?? ?? ?? 85 ED 75 07 83 7C 24 24 00 74 1A 48 8B 44 24 10 48 85 C0 74 05 FF 40 10 EB 0B 48 8B 44 24 18 FF 80 F0 02 00 00 48 83 C4 28 31 C0 5B 5D C3 }
	condition:
		$pattern
}

rule __GI_signal_1521eb2f779f07de39542e237dddeb7c {
	meta:
		aliases = "signal, __bsd_signal, bsd_signal, __GI_signal"
		size = "168"
		objfiles = "signal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 89 FB 48 81 EC 48 01 00 00 48 83 FE FF 0F 94 C2 85 FF 0F 9E C0 08 C2 75 05 83 FF 40 7E 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 6D BA 10 00 00 00 48 89 B4 24 A0 00 00 00 EB 0F 48 63 C2 48 C7 84 C4 A8 00 00 00 00 00 00 00 FF CA 79 ED 48 8D AC 24 A0 00 00 00 89 DE 48 8D 7D 08 E8 ?? ?? ?? ?? 85 C0 78 34 89 DE BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 01 48 89 E2 48 89 EE 19 C0 89 DF 25 00 00 00 10 89 84 24 28 01 00 00 E8 ?? ?? ?? ?? 85 C0 78 06 48 8B 04 24 EB 04 48 83 C8 FF 48 81 C4 48 01 00 00 5B 5D C3 }
	condition:
		$pattern
}

rule __GI_seteuid_4aa661fdd9f4671207b5f9410e686ea1 {
	meta:
		aliases = "setegid, seteuid, __GI_seteuid"
		size = "75"
		objfiles = "setegid@libc.a, seteuid@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 89 FB 48 83 EC 08 83 FF FF 75 0F 89 DD E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 29 83 CA FF 89 FE 89 D7 E8 ?? ?? ?? ?? 83 F8 FF 89 C5 75 16 E8 ?? ?? ?? ?? 83 38 26 75 0C 59 89 DE 89 EF 5B 5D E9 ?? ?? ?? ?? 5A 5B 89 E8 5D C3 }
	condition:
		$pattern
}

rule srandom_r_2b443e6969a77c087f67984d7c8c5e9f {
	meta:
		aliases = "__GI_srandom_r, srandom_r"
		size = "169"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 83 C8 FF 48 89 F5 53 48 83 EC 10 8B 56 18 83 FA 04 0F 87 8C 00 00 00 48 8B 76 10 85 FF B8 01 00 00 00 0F 44 F8 85 D2 89 3E 74 76 44 8B 45 1C 89 FA 48 89 F1 BF 01 00 00 00 EB 37 48 89 D0 41 B9 1D F3 01 00 48 99 49 F7 F9 48 69 C0 14 0B 00 00 48 69 D2 A7 41 00 00 48 29 C2 48 8D 82 FF FF FF 7F 48 83 FA FF 48 0F 4E D0 48 83 C1 04 48 FF C7 89 11 49 63 C0 48 39 C7 7C C1 48 63 45 20 48 89 75 08 41 6B D8 0A 48 8D 04 86 48 89 45 00 EB 0D 48 8D 74 24 0C 48 89 EF E8 ?? ?? ?? ?? FF CB 79 EF 31 C0 59 5E 5B 5D C3 }
	condition:
		$pattern
}

rule initgroups_5b04fb34336bedacc38fb5c2f346e34f {
	meta:
		aliases = "initgroups"
		size = "67"
		objfiles = "initgroups@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 83 CD FF 53 48 83 EC 18 48 8D 54 24 14 C7 44 24 14 FF FF FF 7F E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 17 48 63 7C 24 14 48 89 C6 E8 ?? ?? ?? ?? 48 89 DF 89 C5 E8 ?? ?? ?? ?? 48 83 C4 18 89 E8 5B 5D C3 }
	condition:
		$pattern
}

rule ulckpwdf_904bdf436c6e1f000d189faa72508df8 {
	meta:
		aliases = "ulckpwdf"
		size = "90"
		objfiles = "lckpwdf@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 83 CD FF 53 48 83 EC 28 39 2D ?? ?? ?? ?? 74 40 BE ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 89 C5 C7 05 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 48 83 C4 28 89 E8 5B 5D C3 }
	condition:
		$pattern
}

rule is_ctor_dtor_or_conversion_1178a128fb95e0d7c78ec7aa33c0a43d {
	meta:
		aliases = "is_ctor_dtor_or_conversion"
		size = "43"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 85 C0 89 E5 89 C2 74 17 83 3A 2A 77 12 8B 02 FF 24 85 ?? ?? ?? ?? 8B 52 08 85 D2 75 EB 89 F6 5D 31 C0 C3 5D B8 01 00 00 00 C3 }
	condition:
		$pattern
}

rule has_return_type_efc0bee67a28c06777ace01f02a00750 {
	meta:
		aliases = "has_return_type"
		size = "70"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 85 C0 89 E5 89 C2 74 27 8B 02 83 F8 04 74 24 72 1E 83 E8 19 83 F8 02 77 16 8B 52 04 85 D2 90 75 E7 8D B4 26 00 00 00 00 8D BC 27 00 00 00 00 5D 31 C0 C3 8B 42 04 E8 94 FF FF FF 5D 85 C0 0F 94 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule d_call_offset_88255d33f8bfa21009edfd0788342703 {
	meta:
		aliases = "d_call_offset"
		size = "92"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 85 D2 89 E5 53 89 C3 75 0A 8B 40 0C 0F BE 10 40 89 43 0C 83 FA 68 74 27 83 FA 76 74 05 5B 31 C0 5D C3 89 D8 E8 56 FF FF FF 8B 43 0C 0F B6 10 40 89 43 0C 80 FA 5F 75 E5 8D B4 26 00 00 00 00 89 D8 E8 39 FF FF FF 8B 43 0C 0F B6 10 40 89 43 0C 31 C0 5B 5D 80 FA 5F 0F 94 C0 C3 }
	condition:
		$pattern
}

rule d_add_substitution_728d3091cc37e43b25eceb153d59927e {
	meta:
		aliases = "d_add_substitution"
		size = "42"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 85 D2 89 E5 89 C1 53 89 D3 74 19 8B 50 20 3B 50 24 7D 11 8B 40 1C FF 41 20 89 1C 90 B8 01 00 00 00 5B 5D C3 5B 31 C0 5D C3 }
	condition:
		$pattern
}

rule d_make_empty_4f024cfa7b3c4a68a94981c7cd48332c {
	meta:
		aliases = "d_make_empty"
		size = "42"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 C1 89 E5 53 31 DB 8B 50 14 3B 50 18 7D 15 8D 04 52 8D 1C 85 00 00 00 00 8B 41 10 01 C3 8D 42 01 89 41 14 89 D8 5B 5D C3 }
	condition:
		$pattern
}

rule fibnode_remove_077b92232c2080e4a6eee88f585f924c {
	meta:
		aliases = "fibnode_remove"
		size = "69"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 C1 89 E5 56 53 8B 58 08 31 C0 39 D9 89 DE 0F 95 C0 F7 D8 21 C3 8B 01 85 C0 74 05 3B 48 04 74 1E 8B 51 0C C7 01 00 00 00 00 89 72 08 8B 41 08 89 49 08 89 50 0C 89 D8 89 49 0C 5B 5E 5D C3 89 58 04 EB DD }
	condition:
		$pattern
}

rule fibheap_ins_root_8ba9af6913c541b905a4e2c59d3ae792 {
	meta:
		aliases = "fibheap_ins_root"
		size = "27"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 C1 8B 40 08 89 E5 85 C0 74 04 5D EB C1 90 89 51 08 5D 89 52 08 89 52 0C C3 }
	condition:
		$pattern
}

rule fibnode_insert_after_682101e48d0793c817a93f6116b7371e {
	meta:
		aliases = "fibnode_insert_after"
		size = "46"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 C1 8B 40 0C 89 E5 39 C1 74 14 89 42 0C 8B 41 0C 89 51 0C 89 50 08 5D 89 4A 08 C3 8D 76 00 89 51 0C 89 51 08 5D 89 4A 0C 89 4A 08 C3 }
	condition:
		$pattern
}

rule d_discriminator_314569fd32d22bb073690919cd002aac {
	meta:
		aliases = "d_discriminator"
		size = "45"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 C2 8B 40 0C 89 E5 B9 01 00 00 00 80 38 5F 74 04 5D 89 C8 C3 40 89 42 0C 89 D0 E8 CF FD FF FF 5D 89 C1 C1 E9 1F 83 F1 01 89 C8 C3 }
	condition:
		$pattern
}

rule fibheap_extract_min_81eb979be9c45d252415b2d601509a19 {
	meta:
		aliases = "fibheap_extract_min"
		size = "41"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 31 DB 83 EC 04 8B 45 08 8B 48 04 85 C9 74 10 E8 B8 FD FF FF 8B 58 14 89 04 24 E8 ?? ?? ?? ?? 5A 89 D8 5B 5D C3 }
	condition:
		$pattern
}

rule objalloc_create_eeec88ccf8b7f943a9984d7499f41d92 {
	meta:
		aliases = "objalloc_create"
		size = "89"
		objfiles = "objalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 31 DB 83 EC 04 C7 04 24 0C 00 00 00 E8 ?? ?? ?? ?? 85 C0 74 2E 89 C3 C7 04 24 E0 0F 00 00 E8 ?? ?? ?? ?? 85 C0 89 43 08 74 1F C7 40 04 00 00 00 00 C7 00 00 00 00 00 83 C0 08 89 03 C7 43 04 D8 0F 00 00 5A 89 D8 5B 5D C3 89 1C 24 31 DB E8 ?? ?? ?? ?? EB EE }
	condition:
		$pattern
}

rule lrealpath_89570d9a1c0f26581d728c2bbe4be392 {
	meta:
		aliases = "lrealpath"
		size = "56"
		objfiles = "lrealpath@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 81 EC 14 10 00 00 8B 5D 08 8D 85 FC EF FF FF 89 44 24 04 89 1C 24 E8 ?? ?? ?? ?? 85 C0 74 11 89 04 24 E8 ?? ?? ?? ?? 81 C4 14 10 00 00 5B 5D C3 89 D8 EB EB }
	condition:
		$pattern
}

rule md5_buffer_71d99cb88ff8cdd1d961bd086bcdaac2 {
	meta:
		aliases = "md5_buffer"
		size = "70"
		objfiles = "md5@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 81 EC B4 00 00 00 8D 9D 60 FF FF FF 89 1C 24 E8 ?? ?? ?? ?? 8B 45 0C 89 5C 24 08 89 44 24 04 8B 45 08 89 04 24 E8 ?? ?? ?? ?? 8B 45 10 89 1C 24 89 44 24 04 E8 ?? ?? ?? ?? 81 C4 B4 00 00 00 5B 5D C3 }
	condition:
		$pattern
}

rule dyn_string_release_e44a9c64fee80db1a0c5794f797993da {
	meta:
		aliases = "dyn_string_release"
		size = "34"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 8B 45 08 8B 58 08 C7 40 08 00 00 00 00 89 04 24 E8 ?? ?? ?? ?? 89 D8 5B 5B 5D C3 }
	condition:
		$pattern
}

rule ternary_cleanup_97aab978746313a784914a5ee5fb960b {
	meta:
		aliases = "ternary_cleanup"
		size = "69"
		objfiles = "ternary@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 8B 5D 08 85 DB 74 33 8B 43 04 89 04 24 E8 ?? ?? ?? ?? 80 3B 00 75 16 8B 43 0C 89 04 24 E8 ?? ?? ?? ?? 89 5D 08 5A 5B 5D E9 ?? ?? ?? ?? 8B 43 08 89 04 24 E8 ?? ?? ?? ?? EB DD 58 5B 5D C3 }
	condition:
		$pattern
}

rule xre_comp_2c4d86576dc87eea67c6fad1d9b2bceb {
	meta:
		aliases = "xre_comp"
		size = "168"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 8B 5D 08 85 DB 74 7E A1 ?? ?? ?? ?? 85 C0 75 3F C7 04 24 C8 00 00 00 E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 85 C0 A3 ?? ?? ?? ?? 74 55 B9 C8 00 00 00 89 0D ?? ?? ?? ?? C7 04 24 00 01 00 00 E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 85 C0 A3 ?? ?? ?? ?? 74 30 80 0D ?? ?? ?? ?? 80 89 1C 24 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 89 C2 89 D8 E8 35 D3 FF FF 85 C0 74 21 8B 14 85 ?? ?? ?? ?? 89 D0 5A 5B 5D C3 A1 ?? ?? ?? ?? BA ?? ?? ?? ?? 85 C0 74 EC 8D B6 00 00 00 00 31 D2 89 D0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule xmalloc_0c6c42c5f927841fdb8a9a731376e63c {
	meta:
		aliases = "xmalloc"
		size = "43"
		objfiles = "xmalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 8B 5D 08 85 DB 75 05 BB 01 00 00 00 89 1C 24 E8 ?? ?? ?? ?? 85 C0 74 04 5A 5B 5D C3 89 1C 24 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xregfree_ec0b5c07e416b7f31a963446298b569e {
	meta:
		aliases = "xregfree"
		size = "96"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 8B 5D 08 8B 03 85 C0 74 08 89 04 24 E8 ?? ?? ?? ?? 8B 43 10 C7 03 00 00 00 00 C7 43 04 00 00 00 00 C7 43 08 00 00 00 00 85 C0 74 08 89 04 24 E8 ?? ?? ?? ?? 8B 43 14 80 63 1C F7 C7 43 10 00 00 00 00 85 C0 74 08 89 04 24 E8 ?? ?? ?? ?? C7 43 14 00 00 00 00 58 5B 5D C3 }
	condition:
		$pattern
}

rule fibheap_delete_bd266e79397d285b51986b18a6dc33f2 {
	meta:
		aliases = "fibheap_delete"
		size = "65"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 8B 5D 08 8B 43 04 85 C0 74 25 EB 0D 90 90 90 90 90 90 90 90 90 90 90 90 90 89 D8 E8 F9 FD FF FF 89 04 24 E8 ?? ?? ?? ?? 8B 43 04 85 C0 75 EA 89 5D 08 58 5B 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule dyn_string_delete_94e464ac1e55a8547d55867b19fa0962 {
	meta:
		aliases = "dyn_string_delete"
		size = "32"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 8B 5D 08 8B 43 08 89 04 24 E8 ?? ?? ?? ?? 89 5D 08 58 5B 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fibheap_replace_key_9839046fdc14c054611de30c963bae91 {
	meta:
		aliases = "fibheap_replace_key"
		size = "50"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 10 8B 55 0C 8B 42 14 8B 5A 10 89 54 24 04 89 44 24 0C 8B 45 10 89 44 24 08 8B 45 08 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 89 D8 5B 5D C3 }
	condition:
		$pattern
}

rule fdopen_unlocked_9f36a9f3ae645381811592b2425864d7 {
	meta:
		aliases = "fopen_unlocked, fdopen_unlocked"
		size = "56"
		objfiles = "fopen_unlocked@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 14 8B 45 0C 89 44 24 04 8B 45 08 89 04 24 E8 ?? ?? ?? ?? 85 C0 89 C3 74 11 B8 02 00 00 00 89 44 24 04 89 1C 24 E8 ?? ?? ?? ?? 83 C4 14 89 D8 5B 5D C3 }
	condition:
		$pattern
}

rule freopen_unlocked_989371cbdd45392dcccb3c4f3df5e2a4 {
	meta:
		aliases = "freopen_unlocked"
		size = "63"
		objfiles = "fopen_unlocked@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 14 8B 45 10 89 44 24 08 8B 45 0C 89 44 24 04 8B 45 08 89 04 24 E8 ?? ?? ?? ?? 85 C0 89 C3 74 11 B9 02 00 00 00 89 4C 24 04 89 04 24 E8 ?? ?? ?? ?? 83 C4 14 89 D8 5B 5D C3 }
	condition:
		$pattern
}

rule xstrerror_bcc5c5b1a0971998e29d7b3ce4a9920d {
	meta:
		aliases = "xstrerror"
		size = "68"
		objfiles = "xstrerror@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 14 8B 5D 08 89 1C 24 E8 ?? ?? ?? ?? 85 C0 74 0A 83 C4 14 5B 5D C3 8D 74 26 00 B8 ?? ?? ?? ?? 89 5C 24 08 89 44 24 04 C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 14 B8 ?? ?? ?? ?? 5B 5D C3 }
	condition:
		$pattern
}

rule dyn_string_append_char_e120df857806d9c833b6c82e6207072c {
	meta:
		aliases = "dyn_string_append_char"
		size = "71"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 14 8B 5D 08 8B 43 04 89 1C 24 40 89 44 24 04 E8 ?? ?? ?? ?? 31 D2 85 C0 74 1F 8B 53 04 8B 45 0C 8B 4B 08 88 04 11 8B 53 08 8B 43 04 C6 44 02 01 00 BA 01 00 00 00 FF 43 04 83 C4 14 89 D0 5B 5D C3 }
	condition:
		$pattern
}

rule dyn_string_resize_3fd535c01b5f17ce51b19d9626f3fe0a {
	meta:
		aliases = "dyn_string_resize"
		size = "70"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 14 8B 5D 08 8B 55 0C 8B 0B 42 39 D1 7D 2A 89 C8 8D 76 00 8D BC 27 00 00 00 00 01 C0 39 C2 7F FA 39 C1 74 14 89 03 89 44 24 04 8B 43 08 89 04 24 E8 ?? ?? ?? ?? 89 43 08 83 C4 14 89 D8 5B 5D C3 }
	condition:
		$pattern
}

rule xrealloc_9eb8589363ce56b1de5c05ff8ac9a0fc {
	meta:
		aliases = "xrealloc"
		size = "66"
		objfiles = "xmalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 14 8B 5D 0C 8B 45 08 85 DB 75 05 BB 01 00 00 00 85 C0 74 16 89 5C 24 04 89 04 24 E8 ?? ?? ?? ?? 85 C0 74 10 83 C4 14 5B 5D C3 89 1C 24 E8 ?? ?? ?? ?? EB EC 89 1C 24 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule strsigno_b1a7ea342ddcd99e1c968ed9d7801b47 {
	meta:
		aliases = "strerrno, strsigno"
		size = "98"
		objfiles = "strsignal@libiberty.a, strerror@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 14 A1 ?? ?? ?? ?? 8B 5D 08 85 C0 74 45 85 DB 79 09 31 C0 83 C4 14 5B 5D C3 90 3B 1D ?? ?? ?? ?? 7D EF A1 ?? ?? ?? ?? 85 C0 74 07 8B 04 98 85 C0 75 E1 B8 ?? ?? ?? ?? 89 5C 24 08 89 44 24 04 C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? EB C1 E8 63 FD FF FF 8D 76 00 EB B1 }
	condition:
		$pattern
}

rule dyn_string_new_f55765e3e5e99a328030c148cd8183b5 {
	meta:
		aliases = "dyn_string_new"
		size = "44"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 14 C7 04 24 0C 00 00 00 E8 ?? ?? ?? ?? 89 C3 8B 45 08 89 1C 24 89 44 24 04 E8 ?? ?? ?? ?? 83 C4 14 89 D8 5B 5D C3 }
	condition:
		$pattern
}

rule xre_exec_b942396b7d4b8c0457d893d4a6fed35d {
	meta:
		aliases = "xre_exec"
		size = "65"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 24 8B 5D 08 89 1C 24 E8 ?? ?? ?? ?? 31 C9 31 D2 89 5C 24 04 89 4C 24 14 89 54 24 0C C7 04 24 ?? ?? ?? ?? 89 44 24 10 89 44 24 08 E8 ?? ?? ?? ?? 83 C4 24 5B 5D F7 D0 C1 E8 1F C3 }
	condition:
		$pattern
}

rule pex_unix_exec_child_ea5ea648b678dc1d0c62c4b9cd82afff {
	meta:
		aliases = "pex_unix_exec_child"
		size = "581"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 24 C7 45 F8 01 00 00 00 C7 45 F4 00 00 00 00 8B 45 F4 83 F8 03 7E 27 E9 2D 01 00 00 8B 45 F8 89 04 24 E8 ?? ?? ?? ?? 8B 45 F8 01 C0 89 45 F8 8B 45 F4 40 89 45 F4 8B 45 F4 83 F8 03 7F 0B E8 ?? ?? ?? ?? 85 C0 89 C3 78 D3 83 FB FF 0F 84 F7 00 00 00 85 DB 0F 85 B6 00 00 00 8B 55 18 85 D2 0F 85 35 01 00 00 83 7D 1C 01 90 74 2F B8 01 00 00 00 89 44 24 04 8B 55 1C 89 14 24 E8 ?? ?? ?? ?? 85 C0 0F 88 71 01 00 00 8B 45 1C 89 04 24 E8 ?? ?? ?? ?? 85 C0 0F 88 27 01 00 00 83 7D 20 02 74 2F B8 02 00 00 00 89 44 24 04 8B 55 20 89 14 24 E8 ?? ?? ?? ?? 85 C0 0F 88 3C 01 00 00 8B 45 20 89 04 }
	condition:
		$pattern
}

rule unlink_if_ordinary_32c925dacf7cdfb756342777e240bd91 {
	meta:
		aliases = "unlink_if_ordinary"
		size = "78"
		objfiles = "unlink_if_ordinary@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 74 8B 5D 08 8D 45 A4 89 44 24 04 89 1C 24 E8 ?? ?? ?? ?? 85 C0 75 16 8B 45 B4 25 00 F0 00 00 3D 00 80 00 00 74 14 3D 00 A0 00 00 74 0D 83 C4 74 B8 01 00 00 00 5B 5D C3 89 F6 89 1C 24 E8 ?? ?? ?? ?? 83 C4 74 5B 5D C3 }
	condition:
		$pattern
}

rule string_delete_0ebce8951dc78b625b7c8afdf3eac4f4 {
	meta:
		aliases = "string_delete"
		size = "47"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 89 C3 83 EC 04 8B 00 85 C0 74 1C 89 04 24 E8 ?? ?? ?? ?? C7 43 04 00 00 00 00 C7 43 08 00 00 00 00 C7 03 00 00 00 00 5B 5B 5D C3 }
	condition:
		$pattern
}

rule d_print_error_4508bd9333cf5afcc98053900c54ab55 {
	meta:
		aliases = "d_print_error"
		size = "31"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 89 C3 83 EC 04 8B 40 04 89 04 24 E8 ?? ?? ?? ?? C7 43 04 00 00 00 00 58 5B 5D C3 }
	condition:
		$pattern
}

rule delete_work_stuff_ba8371ee976c7cf89bb19b043ad79e2e {
	meta:
		aliases = "delete_work_stuff"
		size = "24"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 89 C3 83 EC 04 E8 A2 FE FF FF 89 D8 5A 5B 5D E9 38 FF FF FF }
	condition:
		$pattern
}

rule register_Btype_d3b40315acdbbde1c83502997ed44d10 {
	meta:
		aliases = "register_Btype"
		size = "104"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 89 C3 83 EC 14 8B 50 1C 39 50 14 7C 23 85 D2 74 3B 8D 04 12 89 43 1C 8D 04 D5 00 00 00 00 89 44 24 04 8B 43 0C 89 04 24 E8 ?? ?? ?? ?? 89 43 0C 8B 43 14 8D 50 01 89 53 14 8B 53 0C C7 04 82 00 00 00 00 83 C4 14 5B 5D C3 8D 76 00 C7 40 1C 05 00 00 00 C7 04 24 14 00 00 00 E8 ?? ?? ?? ?? 89 43 0C EB CC }
	condition:
		$pattern
}

rule consume_count_with_underscores_db4203afc175ae668b78d604d6c3e141 {
	meta:
		aliases = "consume_count_with_underscores"
		size = "90"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 89 C3 8B 08 0F B6 11 80 FA 5F 74 18 88 D0 2C 30 3C 09 77 23 0F BE C2 8D 50 D0 8D 41 01 89 03 89 D0 5B 5D C3 8D 41 01 89 03 0F B6 41 01 F6 84 00 ?? ?? ?? ?? 04 75 0A BA FF FF FF FF 5B 89 D0 5D C3 89 D8 E8 14 FF FF FF 89 C2 8B 03 80 38 5F 75 E6 40 89 03 EB E6 }
	condition:
		$pattern
}

rule string_prepends_60d06de37bef7598ede66e6940f276aa {
	meta:
		aliases = "string_prepends"
		size = "35"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 89 C3 8B 4A 04 8B 02 39 C8 74 11 29 C1 89 C2 89 D8 5B 5D E9 74 FF FF FF 8D 74 26 00 5B 5D C3 }
	condition:
		$pattern
}

rule byte_store_op2_13665c31e56ff358b0496777c61095e4 {
	meta:
		aliases = "byte_store_op2"
		size = "30"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 8B 5D 08 88 4A 01 C1 F9 08 88 02 88 5A 03 C1 FB 08 88 5A 04 5B 88 4A 02 5D C3 }
	condition:
		$pattern
}

rule xre_set_registers_2741037aa1b6f84f582d570d90455dd2 {
	meta:
		aliases = "xre_set_registers"
		size = "75"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 8B 5D 10 8B 55 08 8B 4D 0C 85 DB 74 1F 0F B6 42 1C 24 F9 0C 02 88 42 1C 8B 45 14 89 19 89 41 04 8B 45 18 89 41 08 5B 5D C3 8D 76 00 80 62 1C F9 C7 01 00 00 00 00 C7 41 08 00 00 00 00 C7 41 04 00 00 00 00 5B 5D C3 }
	condition:
		$pattern
}

rule concat_length_4f72403298b5fc017e1af3c5d3dcf1b3 {
	meta:
		aliases = "concat_length"
		size = "61"
		objfiles = "concat@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 31 F6 53 83 EC 20 8B 55 08 8D 45 0C 89 45 F4 89 C3 85 D2 74 1B 8D B4 26 00 00 00 00 89 14 24 83 C3 04 E8 ?? ?? ?? ?? 8B 53 FC 01 C6 85 D2 75 EC 83 C4 20 89 F0 5B 5E 5D C3 }
	condition:
		$pattern
}

rule dyn_string_insert_char_6ab94b8f6953ddddb505c0d4237c23f4 {
	meta:
		aliases = "dyn_string_insert_char"
		size = "92"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 10 8B 5D 08 8B 75 0C 8B 43 04 89 1C 24 40 89 44 24 04 E8 ?? ?? ?? ?? 31 D2 85 C0 74 2F 8B 4B 04 39 F1 7C 17 90 8D 74 26 00 8B 43 08 89 CA 49 01 C2 39 CE 0F B6 02 88 42 01 7E EE 8B 53 08 8B 45 10 88 04 32 BA 01 00 00 00 FF 43 04 83 C4 10 89 D0 5B 5E 5D C3 }
	condition:
		$pattern
}

rule dyn_string_append_a0ed8f5adeeb9fbf4e398d1b43bd58f0 {
	meta:
		aliases = "dyn_string_append"
		size = "83"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 10 8B 5D 08 8B 75 0C 8B 4B 04 8B 46 04 89 1C 24 01 C8 89 44 24 04 E8 ?? ?? ?? ?? 31 D2 85 C0 74 22 8B 46 08 89 44 24 04 8B 53 08 8B 43 04 01 D0 89 04 24 E8 ?? ?? ?? ?? 8B 46 04 BA 01 00 00 00 01 43 04 83 C4 10 89 D0 5B 5E 5D C3 }
	condition:
		$pattern
}

rule freeargv_3945a80797725eb47b36d4dddee241e0 {
	meta:
		aliases = "freeargv"
		size = "71"
		objfiles = "argv@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 10 8B 75 08 85 F6 74 31 8B 06 85 C0 74 1D 89 F3 89 F6 8D BC 27 00 00 00 00 89 04 24 E8 ?? ?? ?? ?? 8B 43 04 83 C3 04 85 C0 75 EE 89 75 08 83 C4 10 5B 5E 5D E9 ?? ?? ?? ?? 83 C4 10 5B 5E 5D C3 }
	condition:
		$pattern
}

rule objalloc_free_8e812461ac76cb750972dbac494e0fe4 {
	meta:
		aliases = "objalloc_free"
		size = "62"
		objfiles = "objalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 10 8B 75 08 8B 46 08 85 C0 74 1E 8D B4 26 00 00 00 00 8D BC 27 00 00 00 00 8B 18 89 04 24 E8 ?? ?? ?? ?? 85 DB 89 D8 75 F0 89 75 08 83 C4 10 5B 5E 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _objalloc_alloc_35d4a7e8fe9e75629512cf8c0f4ba221 {
	meta:
		aliases = "_objalloc_alloc"
		size = "188"
		objfiles = "objalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 10 8B 75 08 8B 55 0C 89 F6 85 D2 BB 04 00 00 00 74 06 8D 5A 03 83 E3 FC 39 5E 04 73 5C 81 FB FF 01 00 00 77 66 C7 04 24 E0 0F 00 00 E8 ?? ?? ?? ?? 85 C0 89 C2 74 37 8B 46 08 81 FB D8 0F 00 00 C7 42 04 00 00 00 00 89 56 08 C7 46 04 D8 0F 00 00 89 02 8D 42 08 89 DA 89 06 77 AD 01 1E 29 5E 04 8B 16 83 C4 10 29 DA 5B 89 D0 5E 5D C3 83 C4 10 31 D2 5B 89 D0 5E 5D C3 01 1E 29 5E 04 8B 16 83 C4 10 29 DA 5B 89 D0 5E 5D C3 8D 43 08 89 04 24 E8 ?? ?? ?? ?? 85 C0 89 C2 74 D2 8B 46 08 89 56 08 89 02 8B 06 89 42 04 83 C4 10 83 C2 08 5B 89 D0 5E 5D C3 }
	condition:
		$pattern
}

rule dyn_string_copy_6434b2d8add80e690d38ca5ffc94bd1e {
	meta:
		aliases = "dyn_string_copy"
		size = "82"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 10 8B 75 08 8B 5D 0C 39 DE 74 3B 8B 43 04 89 34 24 89 44 24 04 E8 ?? ?? ?? ?? 31 D2 85 C0 74 1D 8B 43 08 89 44 24 04 8B 46 08 89 04 24 E8 ?? ?? ?? ?? 8B 43 04 BA 01 00 00 00 89 46 04 83 C4 10 89 D0 5B 5E 5D C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pex_read_output_24e2c81bc70825ffe96eba44c8cea832 {
	meta:
		aliases = "pex_read_output"
		size = "175"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 20 8B 5D 08 8B 75 0C 8B 43 10 85 C0 74 66 8D 45 F0 31 D2 89 04 24 8D 4D F4 89 D8 E8 59 FB FF FF 85 C0 74 76 85 F6 B8 ?? ?? ?? ?? 74 2C 89 44 24 04 8B 43 10 89 04 24 E8 ?? ?? ?? ?? 8B 4B 14 85 C9 89 43 30 75 1A C7 43 10 00 00 00 00 8B 43 30 83 C4 20 5B 5E 5D C3 89 F6 B8 ?? ?? ?? ?? EB CD 8B 43 10 89 04 24 E8 ?? ?? ?? ?? C7 43 14 00 00 00 00 EB D2 8B 53 0C 31 C0 85 D2 7E D3 8B 43 3C 89 74 24 08 89 54 24 04 89 1C 24 FF 50 18 C7 43 0C FF FF FF FF 89 43 30 EB B3 E8 ?? ?? ?? ?? 8B 55 F0 89 10 31 C0 EB A8 }
	condition:
		$pattern
}

rule cplus_demangle_print_2a4d715f64822deafbeb4653a35254f8 {
	meta:
		aliases = "cplus_demangle_print"
		size = "155"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 30 8B 45 08 8B 75 14 89 45 DC 8B 45 10 40 89 45 E8 89 04 24 E8 ?? ?? ?? ?? 85 C0 74 6D 8B 55 0C 8D 5D DC 89 45 E0 89 D8 C7 45 E4 00 00 00 00 C7 45 EC 00 00 00 00 C7 45 F0 00 00 00 00 C7 45 F4 00 00 00 00 E8 B0 DE FF FF 8B 55 E0 85 D2 74 08 8B 45 E4 3B 45 E8 72 21 31 D2 89 D8 E8 48 DE FF FF 8B 55 E0 85 D2 74 1B 8B 45 E8 89 06 83 C4 30 89 D0 5B 5E 5D C3 8D 76 00 C6 04 02 00 40 89 45 E4 EB E5 8B 45 F4 89 06 EB E3 31 D2 C7 06 01 00 00 00 EB D9 }
	condition:
		$pattern
}

rule squangle_mop_up_d1205a044a2edee96a82def624d36569 {
	meta:
		aliases = "squangle_mop_up"
		size = "164"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 89 C3 83 EC 10 8D B6 00 00 00 00 8B 43 10 85 C0 7E 2E 48 8D 34 85 00 00 00 00 89 43 10 8B 43 08 8B 04 30 85 C0 74 E4 89 04 24 E8 ?? ?? ?? ?? 8B 43 08 C7 04 06 00 00 00 00 8B 43 10 85 C0 7F D2 8B 53 0C 90 8D B4 26 00 00 00 00 8B 43 14 85 C0 7E 2B 48 8D 34 85 00 00 00 00 89 43 14 8B 04 32 85 C0 74 E7 89 04 24 E8 ?? ?? ?? ?? 8B 43 14 8B 53 0C 85 C0 C7 04 16 00 00 00 00 7F D5 85 D2 74 08 89 14 24 E8 ?? ?? ?? ?? 8B 43 08 85 C0 74 08 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 5B 5E 5D C3 }
	condition:
		$pattern
}

rule forget_types_355a5263d190a6fb6e092a6c9e37bae9 {
	meta:
		aliases = "forget_types"
		size = "76"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 89 C3 83 EC 10 8D B6 00 00 00 00 8B 43 20 85 C0 7E 2E 48 8D 34 85 00 00 00 00 89 43 20 8B 43 04 8B 04 30 85 C0 74 E4 89 04 24 E8 ?? ?? ?? ?? 8B 43 04 C7 04 06 00 00 00 00 8B 43 20 85 C0 7F D2 83 C4 10 5B 5E 5D C3 }
	condition:
		$pattern
}

rule ternary_search_0fe4fe50be6d70dc1707df0ef40ebe4c {
	meta:
		aliases = "ternary_search"
		size = "77"
		objfiles = "ternary@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 8B 55 08 8B 5D 0C 85 D2 0F B6 03 74 29 0F BE C8 EB 0F 85 C9 74 2B 43 8B 52 08 0F BE 0B 85 D2 74 15 0F BE 02 89 CE 29 C6 83 FE 00 74 E5 7C 0D 8B 52 0C 85 D2 75 EB 5B 31 C0 5E 5D C3 8B 52 04 EB DC 5B 8B 42 08 5E 5D C3 }
	condition:
		$pattern
}

rule consume_count_bf5fe24df1814ab28b350f32b49f0bf4 {
	meta:
		aliases = "consume_count"
		size = "146"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 89 C6 53 31 DB 83 EC 04 8B 08 0F B6 01 88 45 F7 0F B6 C0 F6 84 00 ?? ?? ?? ?? 04 75 23 EB 4D 8D 04 92 BA 67 66 66 66 01 C0 89 C3 F7 EA 89 D8 C1 F8 1F C1 FA 02 29 C2 8D 14 92 01 D2 39 D3 75 38 0F BE 45 F7 41 89 0E 8D 54 18 D0 0F B6 01 88 45 F7 0F B6 C0 F6 84 00 ?? ?? ?? ?? 04 75 C1 85 D2 79 0F 8D 76 00 8D BC 27 00 00 00 00 BA FF FF FF FF 89 D0 5A 5B 5E 5D C3 8B 16 89 F6 42 89 16 0F B6 02 F6 84 00 ?? ?? ?? ?? 04 75 F0 EB DE }
	condition:
		$pattern
}

rule free_split_directories_7eb11598ed38f2fcd05fdbd13deb0a0b {
	meta:
		aliases = "free_split_directories"
		size = "65"
		objfiles = "make_relative_prefix@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 89 C6 53 83 EC 10 8B 00 85 C0 74 22 89 F3 8D B4 26 00 00 00 00 8D BC 27 00 00 00 00 89 04 24 E8 ?? ?? ?? ?? 8B 43 04 83 C3 04 85 C0 75 EE 89 34 24 E8 ?? ?? ?? ?? 83 C4 10 5B 5E 5D C3 }
	condition:
		$pattern
}

rule delete_non_B_K_work_stuff_a51220133c726d60b230c40d2b92ad6d {
	meta:
		aliases = "delete_non_B_K_work_stuff"
		size = "145"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 89 C6 53 83 EC 10 E8 A1 FF FF FF 8B 46 04 85 C0 74 16 89 04 24 E8 ?? ?? ?? ?? C7 46 04 00 00 00 00 C7 46 24 00 00 00 00 8B 46 40 85 C0 74 34 8B 46 44 85 C0 7E 52 8B 56 40 31 DB 90 8B 04 9A 85 C0 74 0B 89 04 24 E8 ?? ?? ?? ?? 8B 56 40 43 39 5E 44 7F E8 89 14 24 E8 ?? ?? ?? ?? C7 46 40 00 00 00 00 8B 46 4C 85 C0 74 17 E8 0D FF FF FF 8B 46 4C 89 04 24 E8 ?? ?? ?? ?? C7 46 4C 00 00 00 00 83 C4 10 5B 5E 5D C3 8B 56 40 EB C7 }
	condition:
		$pattern
}

rule snarf_numeric_literal_c5b7299baa96cdf818eda0acdaf69c1f {
	meta:
		aliases = "snarf_numeric_literal"
		size = "128"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 89 D6 53 89 C3 8B 00 0F B6 10 80 FA 2D 74 54 80 FA 2B 74 4A 0F B6 10 31 C9 0F B6 C2 F6 84 00 ?? ?? ?? ?? 04 74 32 8D B6 00 00 00 00 88 15 ?? ?? ?? ?? 89 F0 BA ?? ?? ?? ?? E8 1E FF FF FF 8B 03 40 89 03 0F B6 10 0F B6 C2 F6 84 00 ?? ?? ?? ?? 04 75 D9 B9 01 00 00 00 5B 89 C8 5E 5D C3 40 89 03 EB B1 89 F0 BA ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 2D E8 E6 FE FF FF FF 03 8B 03 EB 98 }
	condition:
		$pattern
}

rule xatexit_cleanup_35e30efb2d034b10f0de1288354c339e {
	meta:
		aliases = "xatexit_cleanup"
		size = "54"
		objfiles = "xatexit@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 8B 35 ?? ?? ?? ?? 53 85 F6 74 23 90 8B 5E 04 4B 78 14 8D 76 00 8D BC 27 00 00 00 00 FF 54 9E 08 4B 83 FB FF 75 F6 8B 36 85 F6 89 F6 75 DE 5B 5E 5D C3 }
	condition:
		$pattern
}

rule floatformat_from_double_748546f6020bfe870a93faafb8c9417c {
	meta:
		aliases = "floatformat_from_double"
		size = "638"
		objfiles = "floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 31 F6 53 83 EC 5C 8B 45 0C 8B 55 08 DD 00 8B 42 04 DD 5D A8 89 74 24 04 C1 E8 03 89 44 24 08 8B 45 10 89 04 24 E8 ?? ?? ?? ?? DD 45 A8 D9 EE DD E9 DF E0 9E 0F 87 C3 01 00 00 D9 EE D9 C9 DD E1 DF E0 DD D9 9E 7A 06 0F 84 92 00 00 00 DD E0 DF E0 9E 7A 48 8D B4 26 00 00 00 00 75 3F D9 C0 D8 C1 D9 C9 DD E1 DF E0 DD D9 9E 75 7F 7A 7D DD D8 8B 55 08 8B 42 18 8B 4A 04 89 44 24 08 8B 42 10 89 44 24 04 8B 42 0C 89 04 24 8B 45 10 8B 12 E8 77 FE FF FF 83 C4 5C 5B 5E 5F 5D C3 DD D8 8B 55 08 8B 42 18 8B 4A 04 89 44 24 08 8B 42 10 89 44 24 04 8B 42 0C 89 04 24 8B 45 10 8B 12 E8 49 FE FF FF 8B }
	condition:
		$pattern
}

rule cplus_mangle_opname_270cd99a0129ada3d49e18bd78d470bf {
	meta:
		aliases = "cplus_mangle_opname"
		size = "135"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 31 DB 83 EC 1C 8B 45 08 89 04 24 E8 ?? ?? ?? ?? 83 65 0C 02 C7 45 EC 00 00 00 00 C7 45 E4 ?? ?? ?? ?? 89 45 F0 EB 13 8D 76 00 FF 45 EC 83 C3 0C 83 45 E4 0C 83 7D EC 4F 74 3D 8B B3 ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 39 45 F0 75 DD 8B 83 ?? ?? ?? ?? 83 E0 02 39 45 0C 75 CF 8B 55 F0 8B 7D 08 FC 39 D2 89 D1 F3 A6 75 C0 8B 55 E4 8B 02 83 C4 1C 5B 5E 5F 5D C3 83 C4 1C 31 C0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule expandargv_5e22a6e79fb8051de88319cd89a4ac97 {
	meta:
		aliases = "expandargv"
		size = "661"
		objfiles = "argv@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 31 DB 83 EC 3C 90 8D 74 26 00 8B 55 08 43 3B 1A 0F 8D 1C 02 00 00 8B 55 0C 8D 34 9D 00 00 00 00 8B 02 8B 04 30 80 38 40 75 E0 40 BF ?? ?? ?? ?? 89 7C 24 04 89 04 24 E8 ?? ?? ?? ?? 85 C0 89 45 E4 74 C7 31 D2 B9 02 00 00 00 89 4C 24 08 89 54 24 04 89 04 24 E8 ?? ?? ?? ?? 40 0F 84 BA 01 00 00 8B 4D E4 89 0C 24 E8 ?? ?? ?? ?? 83 F8 FF 89 C7 0F 84 A4 01 00 00 31 C0 31 C9 89 44 24 08 8B 45 E4 89 4C 24 04 89 04 24 E8 ?? ?? ?? ?? 40 0F 84 86 01 00 00 8D 47 01 89 04 24 E8 ?? ?? ?? ?? 8B 55 E4 89 7C 24 08 89 54 24 0C BA 01 00 00 00 89 54 24 04 89 45 DC 89 04 24 E8 ?? ?? ?? ?? 39 C7 89 }
	condition:
		$pattern
}

rule md5_stream_d95147b86d3fa8d1abf2a2a7c349e246 {
	meta:
		aliases = "md5_stream"
		size = "192"
		objfiles = "md5@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 0C 11 00 00 8D BD 58 FF FF FF 89 3C 24 8D B5 10 EF FF FF E8 ?? ?? ?? ?? 31 DB 8B 45 08 89 44 24 0C B8 00 10 00 00 29 D8 89 44 24 08 B8 01 00 00 00 89 44 24 04 8D 04 1E 89 04 24 E8 ?? ?? ?? ?? 01 C3 81 FB FF 0F 00 00 77 3E 85 C0 75 CC 8B 45 08 89 04 24 E8 ?? ?? ?? ?? BA 01 00 00 00 85 C0 75 15 85 DB 75 40 8B 45 0C 89 3C 24 89 44 24 04 E8 ?? ?? ?? ?? 31 D2 81 C4 0C 11 00 00 89 D0 5B 5E 5F 5D C3 8D 74 26 00 85 C0 74 C2 BB 00 10 00 00 89 7C 24 08 89 5C 24 04 89 34 24 E8 ?? ?? ?? ?? E9 72 FF FF FF 89 7C 24 08 89 5C 24 04 89 34 24 E8 ?? ?? ?? ?? EB AE }
	condition:
		$pattern
}

rule byte_re_match_2_internal_fc6c4eca58132cc9c12108375ac691d8 {
	meta:
		aliases = "byte_re_match_2_internal"
		size = "9120"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 2C 01 00 00 89 85 34 FF FF FF 8B 00 8D 74 24 1B 89 95 30 FF FF FF 8B 95 34 FF FF FF 83 E6 F0 89 8D 2C FF FF FF 89 B5 28 FF FF FF 89 85 58 FF FF FF 8B 4A 08 8B 5A 18 8B 7A 18 01 C8 8B 4A 14 43 85 FF 89 85 5C FF FF FF 89 8D 64 FF FF FF 89 9D 68 FF FF FF 75 5A 31 F6 31 DB 31 C9 89 B5 74 FF FF FF 89 9D 78 FF FF FF 89 8D 7C FF FF FF C7 45 80 00 00 00 00 C7 45 84 00 00 00 00 C7 45 8C 00 00 00 00 C7 45 90 00 00 00 00 C7 45 9C 00 00 00 00 C7 45 A0 00 00 00 00 8B 4D 10 85 C9 0F 89 55 01 00 00 B8 FF FF FF FF 8D 65 F4 5B 5E 5F 5D C3 8B 95 68 FF FF FF 8D 04 95 1E 00 00 00 83 E0 F0 }
	condition:
		$pattern
}

rule md5_process_block_641d7e7b7d03c6a450b4b1d29db7728f {
	meta:
		aliases = "md5_process_block"
		size = "2192"
		objfiles = "md5@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 9C 00 00 00 8B 4D 10 8B 55 08 8B 45 0C 8B 5D 10 8B 09 89 55 9C 8B 7D 10 8B 75 9C 89 C2 8B 5B 04 83 E2 FC 89 4D B0 8B 4D 10 8B 7F 0C 01 F2 8B 75 10 89 5D A4 8B 59 10 89 55 A0 89 C2 8B 76 08 89 7D AC 01 DA 39 D0 89 75 A8 89 51 10 76 03 FF 41 14 8B 5D A0 39 5D 9C 0F 83 06 08 00 00 8D 74 26 00 8D BC 27 00 00 00 00 8B 75 9C 8B 45 AC 8B 7D B0 8B 5D A4 8B 36 8B 4D AC 89 75 98 89 F2 8B 75 A8 01 FA 8B 7D 9C 31 F0 8B 75 A4 21 D8 8B 7F 04 31 C8 8B 5D A8 8D 84 10 78 A4 6A D7 8B 55 A4 C1 C8 19 89 7D 94 89 F9 8B 7D AC 01 D0 8B 55 A8 01 F9 8B 7D A8 31 F2 8B 75 A4 21 C2 31 DA 8D 94 0A }
	condition:
		$pattern
}

rule fibheap_extr_min_node_124258a280d38f0b69cd520baa741fc9 {
	meta:
		aliases = "fibheap_extr_min_node"
		size = "480"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC AC 00 00 00 89 85 58 FF FF FF 8B 40 04 8B 70 04 89 85 5C FF FF FF 85 F6 74 28 89 F2 8B 5A 0C 8B 85 58 FF FF FF C7 02 00 00 00 00 E8 28 FD FF FF 39 DE 74 0E 85 DB 74 0A 85 F6 89 DA 75 DE 89 DE EB D8 8B 95 5C FF FF FF 8B 85 58 FF FF FF E8 F5 FE FF FF 8B 95 58 FF FF FF 8B 02 48 85 C0 89 02 75 18 C7 42 04 00 00 00 00 8B 85 5C FF FF FF 81 C4 AC 00 00 00 5B 5E 5F 5D C3 8B 95 5C FF FF FF 31 C9 BB 84 00 00 00 8B 42 0C 8B 95 58 FF FF FF 89 42 04 8D 85 70 FF FF FF 89 5C 24 08 89 4C 24 04 89 04 24 E8 ?? ?? ?? ?? 8B 95 58 FF FF FF 8B 72 08 85 F6 0F 84 BC 00 00 00 8D B4 26 00 00 00 }
	condition:
		$pattern
}

rule fibheap_replace_key_data_cb0e789a566e7158afdfc617728060e0 {
	meta:
		aliases = "fibheap_replace_key_data"
		size = "165"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 04 8B 75 0C 8B 4D 10 8B 7D 08 8B 56 10 39 D1 7C 06 0F 8F 7D 00 00 00 8B 46 14 39 D1 89 4E 10 8B 1E 89 45 F0 8B 45 14 89 46 14 74 3F 85 DB 74 2D 3B 4B 10 7C 05 8D 76 00 7F 23 89 D9 89 F2 EB 10 80 7B 1B 00 8D 74 26 00 79 39 89 DA 89 C1 89 C3 89 F8 E8 41 FF FF FF 8B 03 85 C0 75 E3 8B 47 04 8B 40 10 39 46 10 7D 10 89 77 04 8B 45 F0 5A 5B 5E 5F 5D C3 8D 74 26 00 7E EE 8B 45 F0 5A 5B 5E 5F 5D C3 80 4B 1B 80 8B 47 04 8B 40 10 39 46 10 7C D6 EB E4 C7 45 F0 00 00 00 00 EB CE }
	condition:
		$pattern
}

rule partition_union_1fb981b322ca9bb685d866a8c205c43b {
	meta:
		aliases = "partition_union"
		size = "142"
		objfiles = "partition@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 08 8B 45 0C 8B 55 10 8B 4D 08 8D 04 40 8D 14 52 83 C1 04 8D 1C 81 8D 14 91 8B 33 89 4D EC 8B 0A 89 55 F0 89 F7 39 CE 74 46 8B 43 08 3B 42 08 73 48 8B 75 EC 8D 14 7F 8D 04 49 89 0B 8B 54 96 08 01 54 86 08 8B 53 04 39 DA 89 D0 74 14 8D 74 26 00 8D BC 27 00 00 00 00 89 08 8B 40 04 39 D8 75 F7 8B 75 F0 8B 46 04 89 56 04 89 CE 89 43 04 83 C4 08 89 F0 5B 5E 5F 5D C3 8B 3A 89 D8 89 F1 89 D3 89 45 F0 EB AB }
	condition:
		$pattern
}

rule init_signal_tables_47d9d285c088b249efef9652bacd3c6d {
	meta:
		aliases = "init_error_tables, init_signal_tables"
		size = "386"
		objfiles = "strsignal@libiberty.a, strerror@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 3D ?? ?? ?? ?? 85 FF 75 3D 8B 35 ?? ?? ?? ?? 85 F6 74 33 31 C9 31 D2 EB 0D 90 90 90 90 90 90 90 90 90 90 90 90 90 8B 82 ?? ?? ?? ?? 39 C8 7C 03 8D 48 01 8B 82 ?? ?? ?? ?? 83 C2 0C 85 C0 75 E6 89 0D ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 85 DB 0F 84 98 00 00 00 8B 0D ?? ?? ?? ?? 85 C9 74 08 83 C4 0C 5B 5E 5F 5D C3 A1 ?? ?? ?? ?? 8D 1C 85 00 00 00 00 89 1C 24 E8 ?? ?? ?? ?? 85 C0 A3 ?? ?? ?? ?? 74 DB 83 FB 07 89 C7 89 D8 76 0C F7 C7 04 00 00 00 0F 85 B9 00 00 00 89 C1 31 C0 8B 15 ?? ?? ?? ?? FC C1 E9 02 F3 AB 85 D2 A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 74 A8 8B 35 ?? ?? ?? ?? 31 DB }
	condition:
		$pattern
}

rule strtosigno_ab3aeed924bf497ecc467a649f6115cb {
	meta:
		aliases = "strtoerrno, strtosigno"
		size = "114"
		objfiles = "strsignal@libiberty.a, strerror@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 45 08 85 C0 74 3F A1 ?? ?? ?? ?? 85 C0 74 52 8B 35 ?? ?? ?? ?? 85 F6 7E 38 8B 3D ?? ?? ?? ?? 31 DB 90 8D 74 26 00 8B 04 9F 85 C0 74 13 89 44 24 04 8B 45 08 89 04 24 E8 ?? ?? ?? ?? 85 C0 74 13 43 39 DE 75 E1 83 C4 0C 31 DB 89 D8 5B 5E 5F 5D C3 31 DB 39 DE 74 EE 83 C4 0C 89 D8 5B 5E 5F 5D C3 E8 00 FE FF FF EB A7 }
	condition:
		$pattern
}

rule splay_tree_delete_079cf83135950d5a3290d666c15d42a5 {
	meta:
		aliases = "splay_tree_delete"
		size = "230"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 45 08 8B 38 85 FF 0F 84 B8 00 00 00 8B 50 08 85 D2 74 07 8B 07 89 04 24 FF D2 8B 4D 08 8B 51 0C 85 D2 74 08 8B 47 04 89 04 24 FF D2 C7 07 00 00 00 00 8D 74 26 00 89 FB 31 FF EB 02 89 F3 8B 43 08 85 C0 74 2D 8B 4D 08 8B 51 08 85 D2 74 0A 8B 00 89 04 24 FF D2 8B 43 08 8B 4D 08 8B 51 0C 85 D2 74 0B 8B 40 04 89 04 24 FF D2 8B 43 08 89 38 89 C7 8B 43 0C 85 C0 74 2D 8B 4D 08 8B 51 08 85 D2 74 0A 8B 00 89 04 24 FF D2 8B 43 0C 8B 4D 08 8B 51 0C 85 D2 74 0B 8B 40 04 89 04 24 FF D2 8B 43 0C 89 38 89 C7 8B 55 08 8B 33 8B 42 18 89 1C 24 89 44 24 04 FF 52 14 85 F6 75 80 85 FF }
	condition:
		$pattern
}

rule objalloc_free_block_fc4537eb30468099ceedb23c3d719902 {
	meta:
		aliases = "objalloc_free_block"
		size = "276"
		objfiles = "objalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 45 08 8B 7D 0C 8B 50 08 85 D2 74 36 89 D3 C7 45 EC 00 00 00 00 EB 0D 8D 43 08 39 C7 74 29 8B 1B 85 DB 74 1E 8B 73 04 85 F6 75 EC 39 DF 76 0A 8D 83 E0 0F 00 00 39 C7 72 61 89 5D EC 8B 1B 85 DB 75 E2 E8 ?? ?? ?? ?? 8B 3B 89 D0 39 FA 74 17 8D B4 26 00 00 00 00 8B 18 89 04 24 E8 ?? ?? ?? ?? 39 DF 89 D8 75 F0 8B 55 08 89 7A 08 8B 57 04 85 D2 74 0C 8D 76 00 8B 3F 8B 47 04 85 C0 75 F7 8B 45 08 29 F7 8B 55 08 89 30 8D 87 E0 0F 00 00 89 42 04 83 C4 0C 5B 5E 5F 5D C3 39 DA 74 67 C7 45 F0 00 00 00 00 EB 1B 31 C0 39 55 EC 89 14 24 0F 95 C0 F7 D8 21 45 EC E8 ?? ?? ?? ?? 39 DE }
	condition:
		$pattern
}

rule htab_traverse_noresize_909e52eaf99ff006c06d0332805175c5 {
	meta:
		aliases = "htab_traverse_noresize"
		size = "72"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 45 08 8B 7D 10 8B 58 0C 8B 40 10 8D 34 83 EB 0D 8D B6 00 00 00 00 83 C3 04 39 DE 76 19 83 3B 01 76 F4 89 7C 24 04 89 1C 24 FF 55 0C 85 C0 75 E6 8D B6 00 00 00 00 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule xregcomp_32ddd82d84d326c223bd341d01a05d1d {
	meta:
		aliases = "xregcomp"
		size = "328"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 45 10 8B 75 08 83 E0 01 83 F8 01 C7 06 00 00 00 00 19 FF C7 46 04 00 00 00 00 81 E7 CA 4F FD FF C7 46 08 00 00 00 00 81 C7 FC B2 03 00 C7 04 24 00 01 00 00 E8 ?? ?? ?? ?? F6 45 10 02 89 46 10 0F 84 C3 00 00 00 C7 04 24 00 01 00 00 BB 0C 00 00 00 E8 ?? ?? ?? ?? 85 C0 89 46 14 0F 84 91 00 00 00 31 D2 31 DB EB 18 A1 ?? ?? ?? ?? 0F B6 04 03 83 C3 02 88 04 11 42 81 FA 00 01 00 00 74 1F A1 ?? ?? ?? ?? 8B 4E 14 F6 04 18 01 75 DA 88 D0 83 C3 02 88 04 11 42 81 FA 00 01 00 00 75 E1 F6 45 10 04 74 58 0F B6 56 1C 83 E7 BF 81 CF 00 01 00 00 80 CA 80 88 56 1C C1 6D 10 03 80 E2 }
	condition:
		$pattern
}

rule cplus_demangle_fill_operator_581a06712f81e48157fcdb2dc9f3da45 {
	meta:
		aliases = "cplus_demangle_fill_operator"
		size = "141"
		objfiles = "cp_demint@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 5D 08 85 DB 74 73 8B 4D 0C 85 C9 74 6C 8B 45 0C 89 04 24 E8 ?? ?? ?? ?? 89 C7 A1 ?? ?? ?? ?? 85 C0 74 56 31 F6 31 DB EB 0E 8B 83 ?? ?? ?? ?? 46 83 C3 10 85 C0 74 42 3B BB ?? ?? ?? ?? 75 EA 8B 55 10 39 93 ?? ?? ?? ?? 75 DF 89 44 24 04 8B 45 0C 89 04 24 E8 ?? ?? ?? ?? 85 C0 75 CC 8B 55 08 C1 E6 04 8D 86 ?? ?? ?? ?? 89 42 04 B8 01 00 00 00 C7 02 28 00 00 00 EB 02 31 C0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule splay_tree_remove_27c580de703920b8e8ed36dd831698fe {
	meta:
		aliases = "splay_tree_remove"
		size = "128"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 75 08 8B 5D 0C 89 F0 89 DA E8 A8 FB FF FF 8B 06 85 C0 74 50 89 5C 24 04 8B 00 89 04 24 FF 56 04 85 C0 75 40 8B 4E 0C 8B 16 85 C9 8B 5A 08 8B 7A 0C 74 0A 8B 42 04 89 04 24 FF D1 8B 16 8B 46 18 89 14 24 89 44 24 04 FF 56 14 85 DB 74 1E 85 FF 89 1E 75 06 89 F6 EB 0C 89 C3 8B 43 0C 85 C0 75 F7 89 7B 0C 83 C4 0C 5B 5E 5F 5D C3 89 3E 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule dyn_string_insert_010ad517bf558f93f30298d410cb9f68 {
	meta:
		aliases = "dyn_string_insert"
		size = "137"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 75 08 8B 7D 10 8B 5D 0C 39 F7 74 6E 8B 56 04 8B 47 04 89 34 24 01 D0 89 44 24 04 E8 ?? ?? ?? ?? 31 D2 85 C0 74 4A 8B 4E 04 39 D9 7C 1D 89 F6 8D BC 27 00 00 00 00 8B 46 08 8B 57 04 01 C2 0F B6 04 08 88 04 0A 49 39 CB 7E EC 8B 47 04 89 44 24 08 8B 47 08 89 44 24 04 8B 46 08 01 C3 89 1C 24 E8 ?? ?? ?? ?? 8B 47 04 BA 01 00 00 00 01 46 04 83 C4 0C 89 D0 5B 5E 5F 5D C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ternary_insert_22ab82c7defe3b8bfc66dd42033cfa22 {
	meta:
		aliases = "ternary_insert"
		size = "195"
		objfiles = "ternary@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 75 0C 8B 7D 10 8B 5D 08 8D B4 26 00 00 00 00 8D BC 27 00 00 00 00 8B 0B 85 C9 74 3D 0F B6 1E 0F BE 11 0F BE C3 29 D0 83 F8 00 75 1E 84 DB 74 6D 8D 59 08 46 8B 0B 85 C9 74 1F 0F B6 1E 0F BE 11 0F BE C3 29 D0 83 F8 00 74 E2 7C 49 8D 59 0C EB C5 90 8D 74 26 00 8D 5A 08 C7 04 24 10 00 00 00 E8 ?? ?? ?? ?? 89 03 89 C2 0F B6 06 46 C7 42 08 00 00 00 00 C7 42 0C 00 00 00 00 C7 42 04 00 00 00 00 84 C0 88 02 75 CE 89 7A 08 83 C4 0C 89 F8 5B 5E 5F 5D C3 8D 59 04 E9 79 FF FF FF 8B 5D 14 85 DB 75 0D 8B 79 08 83 C4 0C 89 F8 5B 5E 5F 5D C3 89 79 08 8B 79 08 EB EE }
	condition:
		$pattern
}

rule cplus_demangle_fill_builtin_ty_a5b4ef90310b0d9366931fa8e0b29086 {
	meta:
		aliases = "cplus_demangle_fill_builtin_type"
		size = "137"
		objfiles = "cp_demint@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 7D 08 85 FF 74 6F 8B 75 0C 85 F6 74 68 8B 45 0C 31 F6 31 DB 31 FF 89 04 24 E8 ?? ?? ?? ?? 89 45 F0 EB 0F 8D 76 00 46 83 C7 14 83 C3 14 83 FE 1A 74 43 8B 55 F0 3B 93 ?? ?? ?? ?? 75 E9 8B 83 ?? ?? ?? ?? 89 44 24 04 8B 45 0C 89 04 24 E8 ?? ?? ?? ?? 85 C0 75 D0 8B 55 08 8D 87 ?? ?? ?? ?? 89 42 04 B8 01 00 00 00 C7 02 21 00 00 00 83 C4 0C 5B 5E 5F 5D C3 83 C4 0C 31 C0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule get_field_0c48d3b7d3f59cd5eb1d33ae5d6a529a {
	meta:
		aliases = "get_field"
		size = "195"
		objfiles = "floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 7D 08 89 55 EC 8B 55 0C 8B 75 EC 89 45 F0 01 FA 89 D3 C1 EB 03 85 F6 0F 85 83 00 00 00 89 C8 83 E2 07 C1 E8 03 29 D8 8B 5D F0 8D 4A F8 F7 D9 0F B6 7C 18 FF 89 C3 89 55 E8 D3 FF 8B 75 0C 8B 55 E8 29 D6 EB 2B 90 8B 4D F0 B8 01 00 00 00 0F B6 14 19 89 F1 D3 E0 0F B6 4D E8 48 21 C2 8B 45 EC D3 E2 09 D7 85 C0 75 2B 43 83 45 E8 08 83 EE 08 8B 45 E8 39 45 0C 76 1E 83 FE 07 76 C9 8B 55 F0 0F B6 4D E8 0F B6 04 1A D3 E0 09 C7 8B 45 EC 85 C0 74 D5 4B EB D3 83 C4 0C 89 F8 5B 5E 5F 5D C3 89 D0 8B 55 F0 83 E0 07 8D 48 F8 F7 D9 0F B6 3C 13 4B 89 45 E8 D3 FF EB 82 }
	condition:
		$pattern
}

rule htab_empty_c4fd7c134abe325a8dd8c0db32504dca {
	meta:
		aliases = "htab_empty"
		size = "144"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 7D 08 8B 5F 08 8B 47 10 8B 57 0C 85 DB 89 45 EC 89 55 F0 74 31 89 C6 4E 78 2C 8D 5C 82 FC EB 0C 8D B6 00 00 00 00 83 EB 04 4E 78 1A 8B 03 83 F8 01 76 F3 89 04 24 83 EB 04 FF 57 08 4E 79 ED 8D B4 26 00 00 00 00 8B 45 EC 8B 7D F0 C1 E0 02 83 F8 07 76 12 F7 C7 04 00 00 00 75 1C 8D 76 00 8D BC 27 00 00 00 00 89 C1 31 C0 FC C1 E9 02 F3 AB 83 C4 0C 5B 5E 5F 5D C3 C7 07 00 00 00 00 83 E8 04 83 C7 04 EB E0 }
	condition:
		$pattern
}

rule htab_delete_2b49ec65a6d3364769ecec91c15a3c84 {
	meta:
		aliases = "htab_delete"
		size = "153"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 7D 08 8B 5F 08 8B 57 0C 8B 47 10 85 DB 89 55 F0 74 34 89 C6 4E 78 2F 8D 5C 82 FC EB 06 83 EB 04 4E 78 23 8B 03 83 F8 01 76 F3 89 04 24 83 EB 04 FF 57 08 4E 89 F6 79 EB 8D B4 26 00 00 00 00 8D BC 27 00 00 00 00 8B 47 28 85 C0 74 17 8B 55 F0 89 14 24 FF D0 89 7D 08 8B 4F 28 83 C4 0C 5B 5E 5F 5D FF E1 8B 57 34 85 D2 74 1C 8B 45 F0 89 44 24 04 8B 47 2C 89 04 24 FF D2 89 7C 24 04 8B 47 2C 89 04 24 FF 57 34 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule partition_new_88fb4d151336a50b48a97cd3ea62dbe3 {
	meta:
		aliases = "partition_new"
		size = "89"
		objfiles = "partition@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 7D 08 8D 04 7F 8D 04 85 04 00 00 00 89 04 24 E8 ?? ?? ?? ?? 85 FF 89 C3 89 38 7E 29 31 F6 31 C9 89 C2 8D 74 26 00 8D 42 04 83 C2 0C 89 74 19 04 46 89 44 19 08 B8 01 00 00 00 89 44 19 0C 83 C1 0C 39 F7 75 E1 83 C4 0C 89 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule strverscmp_b9939f6a960a127e35b936af69572757 {
	meta:
		aliases = "strverscmp"
		size = "314"
		objfiles = "strverscmp@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 10 8B 45 08 8B 55 0C C7 45 E8 00 00 00 00 39 D0 0F 84 C1 00 00 00 0F B6 18 40 31 C9 89 45 F0 8D 7A 01 0F B6 02 0F B6 D3 80 FB 30 0F 94 C1 88 45 E7 0F B7 84 12 ?? ?? ?? ?? 0F B6 75 E7 C1 E8 02 83 E0 01 29 F2 8D 04 01 89 45 EC 89 55 E8 74 4E EB 50 8D B6 00 00 00 00 8B 55 F0 0F B6 1A 42 89 55 F0 31 D2 0F B6 07 47 0F B6 CB 80 FB 30 0F 94 C2 88 45 E7 0F B7 84 09 ?? ?? ?? ?? C1 E8 02 83 E0 01 01 C2 8B 45 EC 8B 34 85 ?? ?? ?? ?? 09 F2 0F B6 75 E7 89 55 EC 29 F1 89 4D E8 75 04 84 DB 75 B6 8B 4D EC 31 D2 0F B7 84 36 ?? ?? ?? ?? C1 E1 02 80 7D E7 30 0F 94 C2 C1 E8 02 83 E0 01 01 }
	condition:
		$pattern
}

rule put_field_edd5cc1030518e61f85175703a2eb89a {
	meta:
		aliases = "put_field"
		size = "210"
		objfiles = "floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 10 8B 5D 08 89 45 EC 8B 45 0C 89 55 E8 01 D8 89 C6 C1 EE 03 85 D2 75 08 C1 E9 03 29 F1 8D 71 FF 89 C7 8B 55 EC 83 E7 07 8D 47 F8 89 F9 89 45 F0 F7 D8 89 45 E4 B8 01 00 00 00 D3 E0 0F B6 4D E4 48 8D 1C 16 D3 E0 88 C2 0F B6 45 10 F6 D2 22 13 D3 E0 08 C2 88 13 8B 45 E8 85 C0 75 6A 46 8B 45 0C 8B 5D F0 29 F8 83 C3 08 89 C7 EB 31 8B 55 EC 89 F9 B8 01 00 00 00 D3 E0 88 D9 F6 D8 01 F2 89 55 E4 22 02 8B 55 10 D3 EA 08 D0 8B 55 E4 88 02 8B 45 E8 85 C0 75 25 46 83 C3 08 83 EF 08 39 5D 0C 76 1C 83 FF 07 76 C5 8B 45 10 88 D9 8B 55 EC D3 E8 88 04 32 8B 45 E8 85 C0 74 DB 4E EB D9 83 }
	condition:
		$pattern
}

rule iterative_hash_e8eeed7901c7a41e6880c52b7e47e7fa {
	meta:
		aliases = "iterative_hash"
		size = "841"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 14 8B 55 08 8B 45 10 F6 C2 03 89 55 E4 0F 85 DA 00 00 00 83 7D 0C 0B 0F 86 09 03 00 00 8B 4D 0C 89 C7 C7 45 E8 B9 79 37 9E C7 45 F0 B9 79 37 9E 89 4D EC 90 8D 74 26 00 8B 5D E4 8B 45 E8 8B 55 F0 8B 33 8B 4B 04 01 F0 8B 73 08 01 CA 89 F9 29 D0 01 F1 89 CB 29 C8 C1 EB 0D 29 CA 31 D8 89 C3 29 C2 C1 E3 08 29 C1 31 DA 89 D3 29 D1 C1 EB 0D 29 D0 31 D9 89 CB 29 C8 C1 EB 0C 29 CA 31 D8 89 C3 29 C2 C1 E3 10 29 C1 31 DA 89 D3 29 D1 C1 EB 05 29 D0 31 D9 29 C8 29 CA 89 45 E8 89 C8 89 CF C1 E8 03 31 45 E8 8B 45 E8 8B 4D E8 29 C2 C1 E0 0A 29 CF 31 C2 83 6D EC 0C 89 D0 29 D7 C1 E8 0F }
	condition:
		$pattern
}

rule splay_tree_splay_f8ecac6c3b7b2c6ca026a48d8c009233 {
	meta:
		aliases = "splay_tree_splay"
		size = "401"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C 89 55 E4 8B 10 89 45 E8 85 D2 0F 84 12 01 00 00 8D B4 26 00 00 00 00 8B 45 E8 8B 38 8B 07 89 44 24 04 8B 55 E4 89 14 24 8B 55 E8 FF 52 04 83 F8 00 89 C6 0F 84 E9 00 00 00 0F 8C D8 00 00 00 8B 5F 0C 85 DB 8D 76 00 0F 84 D5 00 00 00 8B 03 89 44 24 04 8B 45 E4 89 04 24 8B 55 E8 FF 52 04 83 F8 00 89 C2 0F 84 F4 00 00 00 0F 8C BA 00 00 00 8B 43 0C 85 C0 89 F6 0F 84 E1 00 00 00 89 F1 C1 E9 1F C6 45 F3 00 85 F6 0F 9F C0 85 D2 0F 9F C2 84 C0 74 23 84 D2 74 4F 8B 53 0C 8B 42 08 89 7A 08 89 43 0C 8B 45 E8 89 5F 0C 89 10 E9 66 FF FF FF 8D B6 00 00 00 00 84 D2 0F 84 58 FF FF FF }
	condition:
		$pattern
}

rule md5_process_bytes_ea435030ce929bbabef6ccacf60adea7 {
	meta:
		aliases = "md5_process_bytes"
		size = "353"
		objfiles = "md5@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C 8B 45 10 8B 75 08 8B 7D 0C 8B 58 18 85 DB 0F 85 90 00 00 00 83 FF 40 76 63 F7 C6 03 00 00 00 0F 84 D4 00 00 00 8B 55 10 83 C2 1C 89 55 E4 89 F6 8D BC 27 00 00 00 00 8B 45 E4 B9 40 00 00 00 83 EF 40 89 4C 24 08 89 74 24 04 83 C6 40 89 04 24 E8 ?? ?? ?? ?? 8B 55 10 89 54 24 08 BA 40 00 00 00 89 54 24 04 89 04 24 E8 ?? ?? ?? ?? 83 FF 40 77 C5 89 FB 83 E3 C0 01 DE 83 E7 3F 85 FF 74 1C 8B 45 10 89 7C 24 08 89 74 24 04 83 C0 1C 89 04 24 E8 ?? ?? ?? ?? 8B 55 10 89 7A 18 83 C4 1C 5B 5E 5F 5D C3 B8 80 00 00 00 29 D8 39 C7 89 7D F0 77 42 8B 55 10 89 74 24 04 83 C2 1C 89 55 E4 }
	condition:
		$pattern
}

rule dyn_string_insert_cstr_986a9c709526e2bcc2f8641c4ad42dba {
	meta:
		aliases = "dyn_string_insert_cstr"
		size = "128"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C 8B 45 10 8B 7D 08 8B 75 0C 89 04 24 E8 ?? ?? ?? ?? 8B 57 04 89 3C 24 89 45 F0 01 D0 89 44 24 04 E8 ?? ?? ?? ?? 31 D2 85 C0 74 42 8B 4F 04 39 F1 7C 15 8B 5D F0 01 CB 8B 57 08 0F B6 04 0A 49 88 04 1A 4B 39 CE 7E F0 8B 45 F0 89 44 24 08 8B 45 10 89 44 24 04 8B 47 08 01 C6 89 34 24 E8 ?? ?? ?? ?? 8B 45 F0 BA 01 00 00 00 01 47 04 83 C4 1C 89 D0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule buildargv_0c7e1e7472be722f8aa2a9ad6a823278 {
	meta:
		aliases = "buildargv"
		size = "540"
		objfiles = "argv@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C 8B 5D 08 C7 45 F0 00 00 00 00 85 DB 0F 84 4E 01 00 00 89 1C 24 31 FF 31 F6 E8 ?? ?? ?? ?? C7 45 EC 00 00 00 00 C7 45 F0 00 00 00 00 C7 45 E4 00 00 00 00 C7 45 E8 00 00 00 00 83 C0 1F 83 E0 F0 29 C4 8D 54 24 17 83 E2 F0 89 55 E0 8D 74 26 00 8D BC 27 00 00 00 00 0F B6 03 F6 84 00 ?? ?? ?? ?? 01 0F 85 46 01 00 00 8B 45 EC 85 C0 74 09 8B 45 EC 48 39 45 E8 7C 38 8B 4D F0 85 C9 0F 84 49 01 00 00 D1 65 EC 8B 45 EC C1 E0 02 89 44 24 04 8B 4D F0 89 0C 24 E8 ?? ?? ?? ?? 85 C0 0F 84 48 01 00 00 8B 55 E8 89 45 F0 C7 04 90 00 00 00 00 0F B6 13 8B 4D E0 84 D2 75 0F EB 51 88 11 31 }
	condition:
		$pattern
}

rule dupargv_ea41cff1b4b4ef17566fd5d5eef853c1 {
	meta:
		aliases = "dupargv"
		size = "218"
		objfiles = "argv@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C 8B 75 08 85 F6 75 12 C7 45 F0 00 00 00 00 8B 45 F0 83 C4 1C 5B 5E 5F 5D C3 8B 0E B8 04 00 00 00 85 C9 74 12 31 C0 90 40 8B 14 86 85 D2 75 F8 8D 04 85 04 00 00 00 89 04 24 E8 ?? ?? ?? ?? 85 C0 89 45 E8 74 C2 89 45 F0 8B 06 C7 45 EC 00 00 00 00 85 C0 74 64 8D 5E 04 89 F7 EB 20 8B 07 89 DF 89 14 24 89 44 24 04 E8 ?? ?? ?? ?? 89 D8 29 F0 89 45 EC 8B 03 83 C3 04 85 C0 74 3D 89 04 24 E8 ?? ?? ?? ?? 40 89 04 24 E8 ?? ?? ?? ?? 8B 4D EC 89 C2 8B 45 E8 85 D2 89 14 08 75 C0 8B 45 E8 89 04 24 E8 ?? ?? ?? ?? C7 45 F0 00 00 00 00 8B 45 F0 83 C4 1C 5B 5E 5F 5D C3 8B 55 EC 8B 4D E8 }
	condition:
		$pattern
}

rule pex_free_ac84717974938db7cc6dada95f376d90 {
	meta:
		aliases = "pex_free"
		size = "256"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C 8B 7D 08 8B 57 0C 85 D2 7E 0D 8B 47 3C 89 54 24 04 89 3C 24 FF 50 0C 8B 47 20 85 C0 0F 84 B8 00 00 00 8B 77 14 85 F6 0F 85 9D 00 00 00 8B 47 1C 85 C0 74 08 89 04 24 E8 ?? ?? ?? ?? 8B 47 20 85 C0 74 08 89 04 24 E8 ?? ?? ?? ?? 8B 47 24 85 C0 74 08 89 04 24 E8 ?? ?? ?? ?? 8B 47 30 85 C0 74 08 89 04 24 E8 ?? ?? ?? ?? 8B 5F 34 85 DB 7E 3B 31 F6 90 8D 74 26 00 8B 47 38 8D 1C B5 00 00 00 00 46 8B 04 18 89 04 24 E8 ?? ?? ?? ?? 8B 47 38 8B 04 18 89 04 24 E8 ?? ?? ?? ?? 39 77 34 7F D7 8B 47 38 89 04 24 E8 ?? ?? ?? ?? 8B 47 3C 8B 40 20 85 C0 74 05 89 3C 24 FF D0 89 3C 24 E8 ?? }
	condition:
		$pattern
}

rule C_alloca_a3b78cd8085af699c1145da49b840d9f {
	meta:
		aliases = "C_alloca"
		size = "126"
		objfiles = "alloca@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C A1 ?? ?? ?? ?? 8B 7D 08 85 C0 74 22 8D 75 F3 3B 70 04 77 0A EB 18 90 3B 73 04 89 D8 76 0E 8B 18 89 04 24 E8 ?? ?? ?? ?? 85 DB 75 EB 89 D8 A3 ?? ?? ?? ?? 31 C0 85 FF 75 08 83 C4 1C 5B 5E 5F 5D C3 8D 47 08 89 04 24 E8 ?? ?? ?? ?? 85 C0 89 C2 74 1E A1 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 89 02 8D 45 F3 89 42 04 83 C4 1C 5B 8D 42 08 5E 5F 5D C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule work_stuff_copy_to_from_a31231d79a0c1cc74c6a50871d3d68cf {
	meta:
		aliases = "work_stuff_copy_to_from"
		size = "720"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C 89 45 E0 89 55 DC E8 AC FA FF FF B8 54 00 00 00 89 44 24 08 8B 45 DC 89 44 24 04 8B 55 E0 89 14 24 E8 ?? ?? ?? ?? 8B 4D DC 8B 41 24 85 C0 0F 85 B8 01 00 00 8B 4D DC 8B 41 20 85 C0 7E 67 C7 45 F0 00 00 00 00 89 F6 8B 55 DC 8B 45 E0 8B 5D F0 8B 78 04 8B 42 04 C1 E3 02 89 DE 01 FE 8B 04 18 89 04 24 E8 ?? ?? ?? ?? 8D 78 01 89 3C 24 E8 ?? ?? ?? ?? 8B 4D E0 89 06 8B 41 04 8B 4D DC 8B 14 18 8B 41 04 8B 04 18 89 14 24 89 7C 24 08 89 44 24 04 E8 ?? ?? ?? ?? 8B 55 DC FF 45 F0 8B 45 F0 39 42 20 7F A2 8B 4D DC 8B 41 18 85 C0 0F 85 FE 01 00 00 8B 4D DC 8B 49 10 85 C9 7E 68 C7 45 }
	condition:
		$pattern
}

rule xre_search_2_1dc3a81223564268df554bec9ae6130e {
	meta:
		aliases = "xre_search_2"
		size = "745"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C 8B 45 08 8B 55 08 8B 5D 1C 8B 7D 10 8B 40 10 8B 52 14 8B 75 20 89 45 EC 8B 45 18 89 55 E8 01 C7 85 DB 78 04 39 FB 7E 0F BB FF FF FF FF 83 C4 2C 89 D8 5B 5E 5F 5D C3 89 D8 01 F0 0F 88 7B 02 00 00 39 C7 0F 8C A5 01 00 00 8B 4D 08 8B 41 08 85 C0 0F 85 62 01 00 00 8B 45 EC 85 C0 74 0D 8B 45 08 F6 40 1C 08 0F 84 ED 01 00 00 8B 4D EC 85 C9 0F 95 45 F3 8D 76 00 39 FB 0F 8D A8 00 00 00 80 7D F3 00 0F 84 9E 00 00 00 8B 55 08 F6 42 1C 01 0F 85 91 00 00 00 85 F6 0F 8E 75 01 00 00 3B 5D 10 0F 8D FE 00 00 00 8D 04 33 39 45 10 C7 45 E4 00 00 00 00 0F 8E 48 01 00 00 8B 45 0C 8D 14 }
	condition:
		$pattern
}

rule partition_print_43ecc53dc7633d60cdc29a96ef44aa61 {
	meta:
		aliases = "partition_print"
		size = "687"
		objfiles = "partition@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C 8B 45 08 8B 7D 0C 8B 10 83 C0 04 89 45 E8 89 55 E4 89 14 24 E8 ?? ?? ?? ?? 8B 4D E4 31 D2 89 45 E0 89 4C 24 08 89 54 24 04 89 04 24 E8 ?? ?? ?? ?? 8B 45 E4 C1 E0 02 89 04 24 E8 ?? ?? ?? ?? 89 45 DC 8B 47 34 85 C0 0F 84 2F 02 00 00 8B 47 10 3B 47 1C 0F 83 09 01 00 00 C6 00 5B 40 89 47 10 8B 45 E4 85 C0 0F 8E 12 01 00 00 C7 45 EC 00 00 00 00 C7 45 F0 00 00 00 00 8D B4 26 00 00 00 00 8D BC 27 00 00 00 00 8B 45 EC 8B 55 E0 80 3C 10 00 0F 85 40 01 00 00 8B 55 E8 8B 4D F0 8B 04 11 8D 04 40 8B 74 82 08 85 F6 7E 33 8B 45 EC 31 D2 8D B4 26 00 00 00 00 8B 4D DC 89 04 91 8B 4D }
	condition:
		$pattern
}

rule concat_copy2_94edbc3c916569af1c62d0696d3fb9f9 {
	meta:
		aliases = "concat_copy2"
		size = "90"
		objfiles = "concat@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C 8B 75 08 8D 45 0C 89 45 F0 8B 3D ?? ?? ?? ?? 89 45 E0 85 F6 74 2B 90 89 34 24 E8 ?? ?? ?? ?? 89 74 24 04 89 3C 24 89 C3 89 44 24 08 01 DF E8 ?? ?? ?? ?? 83 45 E0 04 8B 45 E0 8B 70 FC 85 F6 75 D6 C6 07 00 A1 ?? ?? ?? ?? 83 C4 2C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule concat_copy_a2dbd95fea50d85a1b8f0add448d6c1d {
	meta:
		aliases = "concat_copy"
		size = "88"
		objfiles = "concat@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C 8B 75 0C 8D 45 10 89 45 F0 8B 7D 08 89 45 E0 85 F6 74 2E 8D 74 26 00 89 34 24 E8 ?? ?? ?? ?? 89 74 24 04 89 3C 24 89 C3 89 44 24 08 01 DF E8 ?? ?? ?? ?? 83 45 E0 04 8B 45 E0 8B 70 FC 85 F6 75 D6 C6 07 00 8B 45 08 83 C4 2C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule concat_2f81759d6f544fbe7e1088c86e4cdac9 {
	meta:
		aliases = "concat"
		size = "173"
		objfiles = "concat@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C 8B 7D 08 8D 45 0C 89 45 F0 89 C3 85 FF 74 70 89 F8 31 F6 8D 74 26 00 89 04 24 83 C3 04 E8 ?? ?? ?? ?? 01 C6 8B 43 FC 85 C0 75 EC 8D 46 01 89 04 24 E8 ?? ?? ?? ?? 89 45 DC 8D 45 0C 8B 75 DC 89 45 F0 89 45 E0 89 F6 89 3C 24 E8 ?? ?? ?? ?? 89 7C 24 04 89 34 24 89 C3 89 44 24 08 01 DE E8 ?? ?? ?? ?? 83 45 E0 04 8B 45 E0 8B 78 FC 85 FF 75 D6 C6 06 00 8B 45 DC 83 C4 2C 5B 5E 5F 5D C3 C7 04 24 01 00 00 00 E8 ?? ?? ?? ?? 89 C6 8D 45 0C 89 45 F0 89 75 DC C6 06 00 8B 45 DC 83 C4 2C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule reconcat_bebdb680c9ec69e6ff118d44e69bbaed {
	meta:
		aliases = "reconcat"
		size = "180"
		objfiles = "concat@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C 8B 7D 0C 8D 45 10 89 45 F0 89 C3 85 FF 0F 84 7E 00 00 00 89 F8 31 F6 89 04 24 83 C3 04 E8 ?? ?? ?? ?? 01 C6 8B 43 FC 85 C0 75 EC 8D 46 01 89 04 24 E8 ?? ?? ?? ?? 89 45 DC 8D 45 10 8B 75 DC 89 45 F0 89 45 E0 89 F6 89 3C 24 E8 ?? ?? ?? ?? 89 7C 24 04 89 34 24 89 C3 89 44 24 08 01 DE E8 ?? ?? ?? ?? 83 45 E0 04 8B 45 E0 8B 78 FC 85 FF 75 D6 C6 06 00 8B 45 08 85 C0 74 0B 8B 45 08 89 04 24 E8 ?? ?? ?? ?? 8B 45 DC 83 C4 2C 5B 5E 5F 5D C3 C7 04 24 01 00 00 00 E8 ?? ?? ?? ?? 89 45 DC 8D 45 10 8B 75 DC 89 45 F0 EB C6 }
	condition:
		$pattern
}

rule floatformat_to_double_6ec6a2d82790f02dfb2167817064032f {
	meta:
		aliases = "floatformat_to_double"
		size = "502"
		objfiles = "floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 3C 8B 45 08 8B 48 04 89 C2 8B 40 10 89 D6 89 44 24 04 8B 42 0C 89 04 24 8B 12 8B 45 0C E8 26 FB FF FF 3B 46 18 89 C7 0F 84 1B 01 00 00 8B 55 08 85 C0 8B 75 08 8B 52 20 8B 76 1C 89 55 DC 89 75 D8 0F 85 E9 00 00 00 D9 EE DD 5D E0 8B 45 DC 85 C0 7F 45 E9 9D 00 00 00 85 C0 74 69 8B 75 08 8B 55 D8 8B 46 14 2B 56 1C F7 D8 29 D8 29 D0 31 D2 40 89 44 24 08 52 51 DF 2C 24 83 C4 08 DD 1C 24 E8 ?? ?? ?? ?? DC 45 E0 DD 5D E0 29 5D DC 8B 75 DC 85 F6 7E 60 01 5D D8 8B 5D DC 83 FB 20 7E 05 BB 20 00 00 00 8B 45 08 8B 48 04 89 5C 24 04 8B 55 D8 89 14 24 8B 10 8B 45 0C E8 89 FA FF FF 85 }
	condition:
		$pattern
}

rule htab_find_with_hash_c2844295e77d69a0197a9af311a7f50a {
	meta:
		aliases = "htab_find_with_hash"
		size = "346"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 3C 8B 45 08 C7 45 E4 00 00 00 00 FF 40 1C 8B 50 10 8B 58 38 8B 45 10 89 55 DC 89 5D D4 C1 E3 04 89 45 E0 8D 8B ?? ?? ?? ?? 8B 45 E0 F7 61 04 8B 49 0C 89 C6 8B 45 10 89 D7 89 FE 31 FF 8B 7D 10 89 F2 29 F0 D1 E8 01 C2 8B 83 ?? ?? ?? ?? D3 EA 0F AF D0 29 D7 8B 55 08 8B 72 0C 8B 1C BE 85 DB 0F 84 E2 00 00 00 83 FB 01 74 24 8B 45 0C 89 1C 24 89 44 24 04 FF 52 04 85 C0 0F 85 C8 00 00 00 8B 55 08 8B 5D 08 8B 52 38 8B 73 0C 89 55 D4 8B 4D D4 C1 E1 04 8D 81 ?? ?? ?? ?? 89 45 EC 8B 45 E0 8B 5D EC F7 63 08 8B 99 ?? ?? ?? ?? 89 45 C8 89 D0 89 55 CC 31 D2 89 C2 8B 45 10 83 EB 02 29 }
	condition:
		$pattern
}

rule htab_find_slot_with_hash_a8a67ee45be2068a161330dcb7f38552 {
	meta:
		aliases = "htab_find_slot_with_hash"
		size = "475"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 3C 8B 75 08 83 7D 14 01 8B 46 10 89 45 DC 0F 84 72 01 00 00 8B 4E 38 8B 45 10 8B 7D 10 C7 45 E4 00 00 00 00 89 CB C1 E3 04 89 45 E0 89 4D D0 8B 45 E0 8D 8B ?? ?? ?? ?? F7 61 04 8B 49 0C 89 45 C8 89 D0 89 55 CC 31 D2 89 C2 8B 45 10 29 D0 D1 E8 01 C2 8B 83 ?? ?? ?? ?? D3 EA FF 46 1C 0F AF D0 29 D7 8B 56 0C 8D 1C BD 00 00 00 00 01 DA 8B 02 89 55 D4 85 C0 0F 84 DE 00 00 00 83 F8 01 74 31 8B 4D 0C 89 04 24 89 4C 24 04 FF 56 04 85 C0 74 13 8B 7E 0C 01 FB 89 5D D4 8B 45 D4 83 C4 3C 5B 5E 5F 5D C3 8B 46 38 C7 45 D4 00 00 00 00 89 45 D0 8B 5D D0 8B 4D E4 C1 E3 04 8D 93 ?? ?? ?? }
	condition:
		$pattern
}

rule htab_expand_dce5bd16ecb6006f50a9dba888bc4a72 {
	meta:
		aliases = "htab_expand"
		size = "553"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 4C 89 45 C8 8B 40 0C 8B 55 C8 89 45 CC 89 D1 8B 72 38 8B 52 10 8B 59 18 8D 04 90 89 45 D0 8B 41 14 29 D8 8D 0C 00 39 CA 0F 82 8A 01 00 00 C1 E0 03 39 C2 0F 87 76 01 00 00 8B 4D C8 89 D3 8B 51 30 85 D2 0F 84 8F 01 00 00 BF 04 00 00 00 89 7C 24 08 89 5C 24 04 8B 41 2C 89 04 24 FF D2 31 D2 85 C0 0F 84 3D 01 00 00 8B 4D C8 89 41 0C 8B 41 18 29 41 14 8B 45 CC 89 59 10 89 71 38 C7 41 18 00 00 00 00 89 45 D4 EB 10 83 45 D4 04 8B 55 D4 39 55 D0 0F 86 F5 00 00 00 8B 55 D4 8B 12 83 FA 01 89 55 D8 76 E3 89 14 24 8B 4D C8 FF 11 8B 55 C8 C7 45 E4 00 00 00 00 89 45 DC 8B 42 38 C1 E0 }
	condition:
		$pattern
}

rule demangle_arm_hp_template_386ff36cd26d950a1270c66a8204c3a5 {
	meta:
		aliases = "demangle_arm_hp_template"
		size = "1449"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 4C 8B 32 F6 40 01 10 89 45 C8 89 55 C4 89 4D C0 8D 3C 0E 74 09 80 3F 58 0F 84 2E 02 00 00 8B 55 C8 F7 02 00 18 00 00 75 42 8B 4D C8 F7 01 00 21 00 00 0F 85 E0 00 00 00 83 7D C0 0A 7F 6B 8B 45 C8 83 78 34 FF 0F 84 BE 00 00 00 8B 45 C4 8B 4D C0 8B 10 8B 45 08 E8 5D CC FF FF 8B 55 C4 8B 4D C0 01 0A 83 C4 4C 5B 5E 5F 5D C3 B8 ?? ?? ?? ?? 89 44 24 04 89 34 24 E8 ?? ?? ?? ?? 85 C0 89 C3 74 A7 8D 40 06 89 45 F0 8D 45 F0 E8 98 C6 FF FF 83 F8 FF 74 A3 8B 55 F0 8D 04 02 39 C7 75 8A 80 3A 5F 75 85 E9 B8 00 00 00 8B 4D C4 B8 08 00 00 00 BF ?? ?? ?? ?? FC 8B 19 89 C1 89 DE F3 A6 0F }
	condition:
		$pattern
}

rule xregexec_ab29cbbcd887b4ef79b30fd38060e137 {
	meta:
		aliases = "xregexec"
		size = "341"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 5C 8B 45 0C 8B 75 08 8B 5D 18 89 04 24 E8 ?? ?? ?? ?? 8B 7D 10 FC 89 45 C0 0F B6 4E 1C 80 F1 10 C0 E9 04 85 FF 88 4D BF 8D 7D C8 B9 08 00 00 00 89 7D B8 F3 A5 88 D9 0F 95 45 BE 80 E1 01 D1 EB 88 DA C0 E1 05 80 E2 01 0F B6 45 E4 C0 E2 06 24 9F 08 C8 08 D0 24 F9 0C 04 88 45 E4 0F B6 45 BF 84 45 BE 0F 84 9F 00 00 00 8B 4D 10 89 C8 C1 E0 03 89 4D E8 89 04 24 E8 ?? ?? ?? ?? 89 C2 B8 01 00 00 00 85 D2 74 74 8B 7D 10 31 DB 89 55 EC 8D 04 BA 89 45 F0 8D 45 E8 89 44 24 14 8D 7D C8 8B 45 C0 89 5C 24 0C 89 44 24 10 89 44 24 08 8B 4D 0C 89 3C 24 89 4C 24 04 E8 ?? ?? ?? ?? 85 C0 89 }
	condition:
		$pattern
}

rule cplus_demangle_v3_components_a385e345040c4311cef749ef3a1e7618 {
	meta:
		aliases = "cplus_demangle_v3_components"
		size = "302"
		objfiles = "cp_demint@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 5C 8B 5D 08 8B 7D 0C 89 1C 24 E8 ?? ?? ?? ?? 80 3B 5F 75 0D C7 45 B0 00 00 00 00 80 7B 01 5A 74 14 F7 C7 10 00 00 00 90 0F 84 BA 00 00 00 C7 45 B0 01 00 00 00 8D 75 C0 89 44 24 08 89 74 24 0C 89 7C 24 04 89 1C 24 E8 ?? ?? ?? ?? 8B 45 D8 8D 04 40 C1 E0 02 89 04 24 E8 ?? ?? ?? ?? 89 45 D0 8B 45 E4 C1 E0 02 89 04 24 E8 ?? ?? ?? ?? 8B 55 D0 85 D2 89 45 DC 74 64 85 C0 74 58 8B 55 B0 85 D2 75 45 B8 01 00 00 00 89 44 24 04 89 34 24 E8 ?? ?? ?? ?? 89 C3 83 E7 01 74 08 8B 45 CC 80 38 00 75 55 8B 45 DC 89 04 24 E8 ?? ?? ?? ?? 85 DB 74 53 8B 55 D0 8B 45 10 89 10 83 C4 5C 89 D8 5B }
	condition:
		$pattern
}

rule d_demangle_7a598539447c0f0a0a5b5470709893b7 {
	meta:
		aliases = "d_demangle"
		size = "512"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 6C 89 45 98 89 55 AC 89 4D A8 C7 01 00 00 00 00 89 04 24 E8 ?? ?? ?? ?? 89 45 B0 8B 45 98 80 38 5F 0F 84 93 01 00 00 8B 75 98 BF ?? ?? ?? ?? B9 08 00 00 00 FC F3 A6 75 1F 8B 55 98 0F B6 42 08 3C 2E 0F 84 04 01 00 00 3C 5F 0F 84 FC 00 00 00 3C 24 0F 84 F4 00 00 00 31 DB F6 45 AC 10 0F 84 C3 00 00 00 BF 01 00 00 00 8D 5D C0 89 5C 24 0C 8B 45 B0 89 44 24 08 8B 55 AC 89 54 24 04 8B 75 98 89 34 24 89 E6 E8 ?? ?? ?? ?? 8B 45 D8 8D 04 40 8D 04 85 1E 00 00 00 83 E0 F0 29 C4 8B 45 E4 8D 54 24 1F 83 E2 F0 89 55 D0 8D 04 85 1E 00 00 00 83 E0 F0 29 C4 8D 44 24 1F 83 E0 F0 85 FF 89 }
	condition:
		$pattern
}

rule gnu_special_553addb8def1ea9156f47746390d490c {
	meta:
		aliases = "gnu_special"
		size = "1428"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 6C 8B 1A 89 45 A8 89 55 A4 89 4D A0 80 3B 5F 0F 84 23 01 00 00 FC BF ?? ?? ?? ?? B9 08 00 00 00 89 DE F3 A6 0F 85 8E 00 00 00 8B 55 A4 8D 43 08 89 02 89 D0 E8 DF BF FF FF 83 F8 FF 89 C3 0F 84 E4 00 00 00 8B 7D A4 8B 45 A8 8B 17 42 89 17 E8 E4 D2 FF FF 85 C0 89 C6 0F 84 CA 00 00 00 F7 DB B8 ?? ?? ?? ?? 89 5C 24 08 8D 5D C2 89 1C 24 89 44 24 04 E8 ?? ?? ?? ?? 8B 45 A0 89 DA E8 C6 C5 FF FF 8B 45 A0 89 F2 E8 BC C5 FF FF 89 34 24 E8 ?? ?? ?? ?? 8B 1F 89 1C 24 E8 ?? ?? ?? ?? 01 C3 89 1F BF 01 00 00 00 83 C4 6C 89 F8 5B 5E 5F 5D C3 8D B4 26 00 00 00 00 FC BF ?? ?? ?? ?? B9 03 }
	condition:
		$pattern
}

rule demangle_template_bd68ef415f964cbef6cf813e1c511268 {
	meta:
		aliases = "demangle_template"
		size = "1308"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 6C 8B 5D 0C 89 55 A8 8B 12 89 4D A4 8B 4D A8 89 45 AC 85 DB 8D 42 01 89 01 0F 84 AE 00 00 00 80 7A 01 7A 0F 84 C0 03 00 00 8B 45 A8 E8 E7 DD FF FF 85 C0 89 C3 0F 8E 40 02 00 00 89 45 F0 8B 45 A8 8B 00 89 45 9C 89 04 24 E8 ?? ?? ?? ?? 39 C3 0F 8F 25 02 00 00 8B 55 AC F6 02 04 74 18 8B 75 9C B8 ?? ?? ?? ?? B9 08 00 00 00 FC 89 C7 F3 A6 0F 84 7A 04 00 00 8B 55 9C 89 D9 8B 45 A4 E8 25 E3 FF FF C7 45 B8 00 00 00 00 8B 45 08 85 C0 74 10 8B 45 A8 8B 4D F0 8B 10 8B 45 08 E8 07 E3 FF FF 8B 55 A8 8B 45 F0 01 02 8B 45 B8 85 C0 75 31 EB 22 8B 45 A4 89 DA E8 EC E3 FF FF 8B 45 08 85 }
	condition:
		$pattern
}

rule pex_run_0c7d07d1530892ed2c9e7827a2b1e87a {
	meta:
		aliases = "pex_run"
		size = "1026"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 7C 8B 5D 08 8B 75 18 8B 43 2C 89 75 B0 85 C0 74 16 89 04 24 E8 ?? ?? ?? ?? 40 0F 84 80 01 00 00 C7 43 2C 00 00 00 00 8B 43 10 85 C0 74 2A 8B 45 20 31 D2 8D 4D E4 89 04 24 89 D8 E8 D8 F8 FF FF 85 C0 0F 85 F4 01 00 00 8B 45 E4 83 C4 7C 5B 5E 5F 5D C3 90 8D 74 26 00 8B 43 0C 85 C0 89 45 A8 0F 88 65 02 00 00 F6 45 0C 01 0F 84 3C 01 00 00 85 F6 BF 01 00 00 00 74 11 F6 45 0C 04 0F 85 87 02 00 00 BF FF FF FF FF 31 F6 C7 43 0C FF FF FF FF 85 FF 0F 88 52 01 00 00 85 F6 0F 85 D9 01 00 00 8B 4D 1C 85 C9 0F 84 13 02 00 00 31 D2 8B 43 3C 89 54 24 08 8B 55 1C 89 1C 24 89 54 24 04 FF }
	condition:
		$pattern
}

rule d_expr_primary_e60f9452ba93f03979d1d6c78dba881a {
	meta:
		aliases = "d_expr_primary"
		size = "240"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 89 C3 83 EC 0C 8B 48 0C 0F B6 01 8D 51 01 89 53 0C 3C 4C 74 0C 83 C4 0C 31 C9 5B 89 C8 5E 5F 5D C3 80 79 01 5F 0F 84 87 00 00 00 89 1C 24 E8 ?? ?? ?? ?? 85 C0 89 C6 74 DC 83 38 21 0F 84 8F 00 00 00 8B 53 0C C7 45 F0 31 00 00 00 80 3A 6E 74 73 0F B6 02 31 C9 89 D7 3C 45 74 1F 84 C0 89 D1 75 0C EB B1 8D B6 00 00 00 00 84 C0 74 A7 41 89 4B 0C 0F B6 01 3C 45 75 F1 29 F9 89 FA 89 D8 E8 F6 CC FF FF 89 F1 89 04 24 89 D8 8B 55 F0 E8 77 CC FF FF 89 C1 8B 43 0C 0F B6 10 40 89 43 0C 80 FA 45 0F 85 6D FF FF FF 83 C4 0C 89 C8 5B 5E 5F 5D C3 31 C9 89 4C 24 04 89 1C 24 E8 ?? ?? ?? ?? 89 C1 }
	condition:
		$pattern
}

rule pex_get_status_and_time_de4355b1e854cfe62fb74cc3e1285cb2 {
	meta:
		aliases = "pex_get_status_and_time"
		size = "236"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 89 C3 83 EC 2C 8B 40 18 39 43 28 89 55 E8 89 4D E4 C7 45 F0 01 00 00 00 0F 84 A0 00 00 00 C1 E0 02 89 44 24 04 8B 43 20 89 04 24 E8 ?? ?? ?? ?? F6 03 01 89 43 20 0F 85 8D 00 00 00 8B 73 28 3B 73 18 C7 45 F0 01 00 00 00 7D 70 89 F7 C1 E7 04 8D 76 00 8D BC 27 00 00 00 00 8B 43 3C 31 C9 8B 40 10 89 45 EC 8B 43 24 85 C0 74 03 8D 0C 38 8B 45 08 8D 14 B5 00 00 00 00 46 89 4C 24 0C 8B 4B 20 83 C7 10 89 44 24 18 8B 45 E4 89 44 24 14 8B 45 E8 89 44 24 10 89 D0 01 C8 89 44 24 08 8B 43 1C 8B 04 10 89 1C 24 89 44 24 04 FF 55 EC F7 D0 C1 F8 1F 21 45 F0 39 73 18 7F 9F 89 73 28 8B 45 F0 83 }
	condition:
		$pattern
}

rule demangle_args_7b2d1da2e9c64bb24113dabb4ec6a72f {
	meta:
		aliases = "demangle_args"
		size = "608"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 89 C3 83 EC 2C F6 00 01 89 55 D0 89 4D CC 0F 85 A6 01 00 00 8B 55 D0 8B 02 0F B6 10 31 F6 8D 7D DC 80 FA 5F 74 58 84 D2 74 54 80 FA 65 74 4F 80 FA 4E 0F 94 C1 84 C9 75 68 80 FA 54 74 63 85 F6 0F 85 40 01 00 00 8B 55 D0 8D 4D DC 89 D8 E8 D7 FE FF FF 85 C0 0F 84 21 01 00 00 F6 03 01 0F 85 9B 01 00 00 8D 45 DC BE 01 00 00 00 E8 C9 CB FF FF 8B 55 D0 8B 02 0F B6 10 80 FA 5F 75 A8 8B 4B 50 85 C9 7F AA 80 FA 65 0F 84 98 01 00 00 F6 03 01 0F 85 78 01 00 00 B8 01 00 00 00 E9 DD 00 00 00 8B 55 D0 40 84 C9 89 02 0F 85 F2 00 00 00 C7 45 F0 01 00 00 00 F7 03 00 38 00 00 74 0A 83 7B 20 09 }
	condition:
		$pattern
}

rule demangle_expression_e940a1eb7e3c9b873980d16c25127843 {
	meta:
		aliases = "demangle_expression"
		size = "343"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 BB 01 00 00 00 83 EC 2C 89 4D D4 B9 01 00 00 00 89 45 DC 8B 45 D4 89 55 D8 BA ?? ?? ?? ?? E8 07 B9 FF FF 8B 45 D8 C7 45 E0 00 00 00 00 FF 00 8B 55 D8 8B 12 89 55 F0 0F B6 02 3C 57 0F 84 D9 00 00 00 84 C0 0F 84 FB 00 00 00 8B 45 E0 85 C0 0F 84 E7 00 00 00 8B 55 F0 89 14 24 E8 ?? ?? ?? ?? C7 45 E4 00 00 00 00 C7 45 EC 00 00 00 00 89 45 E8 EB 18 8D B4 26 00 00 00 00 FF 45 E4 83 45 EC 0C 83 7D E4 4F 0F 84 BA 00 00 00 8B 45 EC 8B 98 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 39 45 E8 89 45 D0 72 D6 8B 7D F0 39 C0 89 DE FC 89 C1 F3 A6 75 C8 8B 45 D4 B9 01 00 00 00 BA ?? ?? ?? ?? E8 66 B8 }
	condition:
		$pattern
}

rule d_print_resize_3f20452426a48b2be0fef0258093c315 {
	meta:
		aliases = "d_print_resize"
		size = "98"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 89 C6 53 83 EC 0C 8B 40 04 85 C0 74 48 8B 46 08 89 D7 8B 5E 0C 01 C7 39 DF 77 0C EB 38 39 DF 89 46 04 89 5E 0C 76 2E 8B 46 04 01 DB 89 5C 24 04 89 04 24 E8 ?? ?? ?? ?? 85 C0 75 E1 8B 46 04 89 04 24 E8 ?? ?? ?? ?? C7 46 04 00 00 00 00 C7 46 18 01 00 00 00 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule d_name_430e38fd399630f92e27785976c1f723 {
	meta:
		aliases = "d_name"
		size = "721"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 89 C6 53 83 EC 1C 8B 40 0C 0F B6 10 80 FA 53 74 2D 80 FA 5A 74 76 80 FA 4E 0F 84 9E 00 00 00 89 F0 E8 55 FE FF FF 89 C3 8B 46 0C 80 38 49 0F 84 52 02 00 00 83 C4 1C 89 D8 5B 5E 5F 5D C3 80 78 01 74 0F 84 BF 01 00 00 31 D2 89 F0 E8 CA D8 FF FF BA 01 00 00 00 89 C3 8B 46 0C 80 38 49 75 D4 85 D2 0F 84 1E 02 00 00 89 F0 E8 9C 08 00 00 89 D9 BA 04 00 00 00 89 04 24 89 F0 E8 AB D4 FF FF 83 C4 1C 89 C3 89 D8 5B 5E 5F 5D C3 8D 50 01 89 F0 89 56 0C 31 D2 E8 50 02 00 00 8B 4E 0C 8D 51 01 89 C7 0F B6 01 89 56 0C 3C 45 0F 84 E6 00 00 00 31 DB 83 C4 1C 89 D8 5B 5E 5F 5D C3 8D 50 01 B9 01 00 }
	condition:
		$pattern
}

rule d_template_args_914a8f59c737b0ce7f1e3b9218c5f1b5 {
	meta:
		aliases = "d_template_args"
		size = "202"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 89 C6 53 83 EC 1C 8B 40 2C 8B 4E 0C 89 45 E0 0F B6 01 41 89 4E 0C 3C 49 74 11 83 C4 1C 31 C0 5B 5E 5F 5D C3 8D B4 26 00 00 00 00 8D 7D F0 C7 45 F0 00 00 00 00 EB 3C 8D 74 26 00 3C 58 74 4C 89 34 24 E8 ?? ?? ?? ?? 89 C3 85 DB 74 CD 89 D9 BA 27 00 00 00 89 F0 C7 04 24 00 00 00 00 E8 B9 CB FF FF 85 C0 89 07 74 B2 8B 4E 0C 80 39 45 74 3E 8D 78 08 0F B6 01 3C 4C 75 C1 89 F0 E8 8A FE FF FF 89 C3 EB C4 8D B6 00 00 00 00 41 89 F0 89 4E 0C E8 E5 08 00 00 89 C3 8B 46 0C 0F B6 10 8D 48 01 89 4E 0C 80 FA 45 74 A0 E9 6C FF FF FF 8D 41 01 89 46 0C 8B 45 E0 89 46 2C 8B 45 F0 83 C4 1C 5B 5E 5F }
	condition:
		$pattern
}

rule d_print_function_type_c8b411485bd8e7a990cbf607fa2407ec {
	meta:
		aliases = "d_print_function_type"
		size = "488"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 89 CE 53 89 C3 83 EC 0C 85 C9 89 55 F0 0F 84 BD 01 00 00 8B 41 08 85 C0 0F 85 B2 01 00 00 89 CA BF 01 00 00 00 8B 42 04 8B 08 83 E9 16 83 F9 0F 77 39 89 F8 D3 E0 A9 47 86 00 00 75 52 A9 80 01 00 00 74 27 8B 53 04 85 D2 0F 84 1C 01 00 00 8B 43 08 85 C0 74 52 0F B6 4C 02 FF 80 F9 28 74 67 80 F9 2A 75 3C EB 60 8D 74 26 00 8B 12 85 D2 74 07 8B 42 08 85 C0 74 AD 8B 7B 14 31 C9 89 F2 C7 43 14 00 00 00 00 89 D8 E8 DE FC FF FF EB 7D 8B 53 04 85 D2 0F 84 D1 00 00 00 8B 43 08 85 C0 74 07 80 7C 02 FF 20 74 1F 39 43 0C 0F 86 BA 00 00 00 C6 04 02 20 40 8B 53 04 89 43 08 85 D2 0F 84 C7 00 00 }
	condition:
		$pattern
}

rule splay_tree_foreach_helper_f0276920d13ab654f02c90fab755426e {
	meta:
		aliases = "splay_tree_foreach_helper"
		size = "80"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 89 CE 53 89 D3 83 EC 0C 89 45 F0 31 C0 85 D2 8B 7D 08 75 1B EB 2D 90 8D 74 26 00 89 7C 24 04 89 1C 24 FF D6 85 C0 75 1B 8B 5B 0C 85 DB 74 14 8B 53 08 89 F1 8B 45 F0 89 3C 24 E8 BC FF FF FF 85 C0 74 D8 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule byte_alt_match_null_string_p_0690c6eb5c9fa4f846b9c36b501b084d {
	meta:
		aliases = "byte_alt_match_null_string_p"
		size = "115"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 89 CE 53 89 D3 83 EC 1C 8D 7D F0 89 45 F0 8D B6 00 00 00 00 8D BC 27 00 00 00 00 8B 4D F0 39 D9 73 3F 80 39 0F 74 19 89 F1 89 DA 89 F8 E8 D9 FE FF FF 84 C0 75 E5 83 C4 1C 31 C0 5B 5E 5F 5D C3 8D 41 01 89 45 F0 0F BE 40 01 0F B6 51 01 C1 E0 08 01 C2 8D 44 11 03 89 45 F0 8B 4D F0 39 D9 72 C1 83 C4 1C B8 01 00 00 00 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule byte_insert_op2_209d453330e4d86e742ee41ae26dce5c {
	meta:
		aliases = "byte_insert_op2"
		size = "83"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 89 D6 53 83 EC 08 89 45 F0 8B 45 0C 89 4D EC 8B 7D 08 39 D0 74 21 89 D3 89 C1 89 C2 EB 0D 90 90 90 90 90 90 90 90 90 90 90 90 90 4A 49 0F B6 02 39 D9 88 42 05 75 F4 89 7D 08 8B 4D EC 89 F2 8B 45 F0 83 C4 08 5B 5E 5F 5D E9 4D FF FF FF }
	condition:
		$pattern
}

rule demangle_function_name_61b30f7d42190b859d8d7140ad22c202 {
	meta:
		aliases = "demangle_function_name"
		size = "1076"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 89 D6 53 83 EC 5C 8B 5D 08 89 4D AC 8B 12 89 45 B0 8B 45 AC 89 D9 29 D1 E8 0E F8 FF FF 8B 45 AC BA 01 00 00 00 E8 A1 F6 FF FF 8B 55 AC 8B 42 04 C6 00 00 8D 43 02 8B 7D B0 89 06 F6 47 01 10 74 0A 80 7B 02 58 0F 84 87 02 00 00 8B 45 B0 F7 00 00 3C 00 00 0F 85 A6 01 00 00 8B 55 AC 8B 1A 8B 7D AC 8B 7F 04 29 DF 83 FF 02 89 7D A0 7F 1C 83 7D A0 04 0F 8F C9 01 00 00 80 3B 5F 0F 84 B9 00 00 00 83 C4 5C 5B 5E 5F 5D C3 90 80 3B 6F 75 DF 80 7B 01 70 75 D9 0F BE 43 02 C7 04 24 ?? ?? ?? ?? 89 44 24 04 E8 ?? ?? ?? ?? 85 C0 74 C1 83 FF 09 0F 8F CB 02 00 00 8B 45 A0 C7 45 D8 00 00 00 00 C7 45 }
	condition:
		$pattern
}

rule cplus_demangle_opname_1f504e16b4bd90f20a5bd52a220c95b9 {
	meta:
		aliases = "cplus_demangle_opname"
		size = "1193"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 BE 54 00 00 00 53 81 EC CC 00 00 00 8B 45 08 89 04 24 E8 ?? ?? ?? ?? 8B 55 0C 31 C9 C6 02 00 89 74 24 08 8D 75 90 89 C3 89 4C 24 04 89 34 24 E8 ?? ?? ?? ?? 8B 45 10 89 45 90 8B 45 08 0F B6 10 80 FA 5F 0F 84 72 01 00 00 83 FB 02 7F 20 83 FB 04 0F 8F C4 00 00 00 31 DB 8D 45 90 E8 EA B4 FF FF 81 C4 CC 00 00 00 89 D8 5B 5E 5F 5D C3 80 FA 6F 75 DB 8B 45 08 80 78 01 70 75 D2 0F BE 40 02 C7 04 24 ?? ?? ?? ?? 89 44 24 04 E8 ?? ?? ?? ?? 85 C0 74 BA 83 FB 09 0F 8F 1C 03 00 00 83 EB 03 31 C0 89 9D 6C FF FF FF 31 DB 89 85 68 FF FF FF EB 12 FF 85 68 FF FF FF 83 C3 0C 83 BD 68 FF FF FF 4F 74 }
	condition:
		$pattern
}

rule cplus_demangle_name_to_style_c9f03c0ad6b76f00f423b73fde607d46 {
	meta:
		aliases = "cplus_demangle_name_to_style"
		size = "66"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 BE FF FF FF FF 53 31 DB 83 EC 0C 8B 7D 08 EB 0D 8B B3 ?? ?? ?? ?? 83 C3 0C 85 F6 74 16 8B 83 ?? ?? ?? ?? 89 3C 24 89 44 24 04 E8 ?? ?? ?? ?? 85 C0 75 DD 83 C4 0C 89 F0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule d_number_14764f1f966b283d1732eafba879ba49 {
	meta:
		aliases = "d_number"
		size = "124"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 89 C7 56 53 83 EC 04 8B 48 0C 0F B6 19 89 C8 C7 45 F0 00 00 00 00 80 FB 6E 74 42 88 D8 2C 30 3C 09 77 51 8B 4F 0C 31 F6 8D 74 26 00 0F BE C3 8D 14 B6 8D 74 50 D0 89 CA 8D 41 01 89 47 0C 89 C1 0F B6 5A 01 88 D8 2C 30 3C 09 76 E0 8B 4D F0 85 C9 74 02 F7 DE 5A 89 F0 5B 5E 5F 5D C3 41 89 4F 0C 0F B6 58 01 C7 45 F0 01 00 00 00 88 D8 2C 30 3C 09 76 AF 31 F6 EB D4 }
	condition:
		$pattern
}

rule d_operator_name_931641a5b3ea9fbc1b504469e618395f {
	meta:
		aliases = "d_operator_name"
		size = "305"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 89 C7 56 53 83 EC 1C 8B 40 0C 0F B6 10 88 55 F2 8D 50 01 89 57 0C 0F B6 58 01 83 C0 02 80 7D F2 76 89 47 0C 88 5D F3 0F 84 94 00 00 00 80 7D F2 63 0F 84 C5 00 00 00 C7 45 EC 31 00 00 00 31 C9 8D B6 00 00 00 00 8D BF 00 00 00 00 8B 45 EC 0F B6 5D F2 29 C8 89 C2 C1 EA 1F 01 C2 D1 FA 8D 14 11 89 D0 C1 E0 04 8D B0 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? 3A 18 75 09 0F B6 5D F3 3A 58 01 74 22 7C 1B 8D 4A 01 39 4D EC 75 C3 31 FF 83 C4 1C 89 F8 5B 5E 5F 5D C3 8D B4 26 00 00 00 00 89 55 EC EB E3 89 F8 E8 04 C3 FF FF 85 C0 89 C7 74 DD C7 00 28 00 00 00 89 70 04 83 C4 1C 89 F8 5B 5E 5F 5D C3 88 D8 2C }
	condition:
		$pattern
}

rule byte_re_compile_fastmap_23b04dc49260bddde416de5fc25a9e67 {
	meta:
		aliases = "byte_re_compile_fastmap"
		size = "901"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 89 C7 56 53 83 EC 6C 8B 18 8D 54 24 1B 8B 70 10 83 E2 F0 8B 40 08 89 55 DC 89 34 24 01 D8 89 45 CC B8 00 01 00 00 89 44 24 08 31 C0 89 44 24 04 E8 ?? ?? ?? ?? 0F B6 47 1C C6 45 D2 01 C6 45 D3 00 C7 45 D4 00 00 00 00 0C 08 24 FE 88 47 1C C7 45 D8 05 00 00 00 3B 5D CC 74 21 0F B6 03 3C 01 74 1A 43 3C 1D 77 0C 0F B6 C0 89 F6 FF 24 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 74 26 00 8B 4D D4 85 C9 0F 84 81 02 00 00 0F B6 47 1C FF 4D D4 24 01 8B 4D D4 08 45 D2 0F B6 47 1C 24 FE 0A 45 D2 88 47 1C 8B 45 DC 8B 1C 88 C6 45 D2 01 EB A8 8D 43 02 0F B6 53 02 83 C3 04 0F BE 40 01 C1 E0 08 01 C2 75 93 83 }
	condition:
		$pattern
}

rule d_print_mod_list_82246c73019befeac0e90253491cfbf0 {
	meta:
		aliases = "d_print_mod_list"
		size = "317"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 89 C7 56 89 D6 53 83 EC 0C 85 D2 89 4D EC 75 40 EB 64 8B 56 04 8B 02 83 E8 19 83 F8 02 76 2B 8B 46 0C 8B 5F 10 C7 46 08 01 00 00 00 89 47 10 8B 02 83 F8 23 74 48 83 F8 24 74 2F 83 F8 02 74 52 89 F8 E8 05 FD FF FF 89 5F 10 8B 36 85 F6 74 26 8B 47 04 85 C0 74 1F 8B 46 08 85 C0 75 EC 8B 45 EC 85 C0 74 AD 8B 56 04 EB B5 8B 0E 89 F8 E8 C9 00 00 00 89 5F 10 83 C4 0C 5B 5E 5F 5D C3 8B 0E 89 F8 E8 05 02 00 00 89 5F 10 83 C4 0C 5B 5E 5F 5D C3 8B 47 14 C7 47 14 00 00 00 00 89 45 F0 89 F8 8B 52 04 E8 D3 E2 FF FF 8B 45 F0 F6 07 04 89 47 14 75 52 8B 4F 04 85 C9 74 0B 8B 57 08 8D 42 02 3B 47 0C }
	condition:
		$pattern
}

rule byte_group_match_null_string_p_99a043a23efe4d3ce4063b595dd6943f {
	meta:
		aliases = "byte_group_match_null_string_p"
		size = "258"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 89 CF 56 53 83 EC 1C 89 45 E0 8B 00 89 55 DC 83 C0 02 89 45 F0 8B 55 F0 3B 55 DC 73 1C 0F B6 02 3C 07 74 1F 3C 0F 74 34 8B 55 DC 8D 45 F0 89 F9 E8 57 FE FF FF 84 C0 75 DC 83 C4 1C 31 C0 5B 5E 5F 5D C3 8D 42 02 8B 55 E0 89 02 83 C4 1C B8 01 00 00 00 5B 5E 5F 5D C3 8D 74 26 00 8D 42 01 89 45 F0 0F B6 4A 01 83 C2 03 0F BE 40 01 89 55 F0 89 CE C1 E0 08 01 C6 78 9C 8D 76 00 8B 5D F0 80 7C 33 FD 0E 75 46 8D 54 33 FD 89 F9 89 D8 E8 E9 FE FF FF 84 C0 74 A2 89 F1 8B 75 F0 01 F1 89 4D F0 80 39 0F 75 50 8D 41 01 89 45 F0 0F BE 40 01 0F B6 51 01 C1 E0 08 8D 34 02 8D 41 03 89 45 F0 80 7C 30 FD }
	condition:
		$pattern
}

rule iterate_demangle_function_ddd43f5c728582f1a06fca6726be2a4d {
	meta:
		aliases = "iterate_demangle_function"
		size = "376"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 89 CF 56 53 83 EC 7C 89 45 88 8B 02 8B 75 08 89 55 84 C7 45 90 00 00 00 00 89 45 8C 80 7E 02 00 8D 5E 02 0F 84 F9 00 00 00 8B 55 88 F7 02 00 3C 00 00 0F 85 F5 00 00 00 B8 ?? ?? ?? ?? 89 44 24 04 89 1C 24 E8 ?? ?? ?? ?? 85 C0 0F 84 DC 00 00 00 8D 45 E8 E8 C3 EF FF FF 89 FA 8D 45 E8 E8 D9 F3 FF FF B8 54 00 00 00 89 44 24 08 31 C0 89 44 24 04 8D 45 94 89 04 24 E8 ?? ?? ?? ?? 8B 55 88 8D 45 94 E8 24 F7 FF FF C7 45 90 00 00 00 00 80 7E 02 00 74 7D 89 34 24 89 F9 8B 55 84 8B 45 88 E8 17 FB FF FF 8B 55 84 89 F9 8B 45 88 E8 2A 33 00 00 85 C0 89 45 90 75 59 8B 45 8C 8B 55 84 89 02 89 F8 E8 }
	condition:
		$pattern
}

rule is_ctor_or_dtor_2d693e7fbce8e8e5f02ddbf3011da7f8 {
	meta:
		aliases = "is_ctor_or_dtor"
		size = "212"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 89 CF 56 53 89 C3 83 EC 5C 8D 75 C0 89 55 B0 C7 02 00 00 00 00 C7 01 00 00 00 00 89 74 24 0C 89 04 24 E8 ?? ?? ?? ?? 89 1C 24 89 E3 89 44 24 08 B8 00 40 00 00 89 44 24 04 E8 ?? ?? ?? ?? 8B 45 D8 8D 04 40 8D 04 85 1E 00 00 00 83 E0 F0 29 C4 8B 45 E4 8D 54 24 1F 83 E2 F0 89 55 D0 8D 04 85 1E 00 00 00 83 E0 F0 29 C4 8D 44 24 1F 83 E0 F0 89 45 DC B8 01 00 00 00 89 44 24 04 89 34 24 E8 ?? ?? ?? ?? 89 C2 85 D2 74 12 83 3A 1B 77 0D 8B 02 FF 24 85 ?? ?? ?? ?? 8D 74 26 00 89 DC 31 C0 8D 65 F4 5B 5E 5F 5D C3 8B 52 08 EB D9 8B 52 04 EB D4 8B 42 04 89 07 89 DC B8 01 00 00 00 8D 65 F4 5B 5E 5F }
	condition:
		$pattern
}

rule do_arg_fabc7a63a6081c911464a6d412ea48d1 {
	meta:
		aliases = "do_arg"
		size = "202"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 89 CF 56 89 C6 53 89 D3 83 EC 0C 90 8B 03 89 45 F0 89 F8 E8 74 CC FF FF 8B 46 50 85 C0 7F 4F 8B 03 80 38 6E 75 22 40 89 03 89 D8 E8 9C CA FF FF 85 C0 89 46 50 7E 2D 83 F8 09 7E D0 8B 03 80 38 5F 75 21 40 89 03 EB C4 8B 46 4C 85 C0 74 66 E8 B8 CC FF FF 8B 4E 4C 89 DA 89 F0 E8 1C F5 FF FF 85 C0 75 29 83 C4 0C 31 C0 5B 5E 5F 5D C3 8B 56 4C 48 89 46 50 85 D2 74 EB 89 F8 E8 2C D0 FF FF 83 C4 0C B8 01 00 00 00 5B 5E 5F 5D C3 8B 56 4C 89 F8 E8 15 D0 FF FF 8B 45 F0 8B 0B 8B 55 F0 29 C1 89 F0 E8 D4 D2 FF FF 83 C4 0C B8 01 00 00 00 5B 5E 5F 5D C3 C7 04 24 0C 00 00 00 E8 ?? ?? ?? ?? 89 46 4C }
	condition:
		$pattern
}

rule byte_insert_op1_09e3e4d606ae0d0d7928be645aff340f {
	meta:
		aliases = "byte_insert_op1"
		size = "58"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 89 CF 56 89 D6 53 83 EC 04 89 45 F0 8B 45 08 39 D0 74 15 89 D3 89 C1 89 C2 8D 76 00 4A 49 0F B6 02 39 D9 88 42 03 75 F4 8B 45 F0 89 F2 89 F9 5B 5B 5E 5F 5D EB 96 }
	condition:
		$pattern
}

rule pex_child_error_b33be0ce7ab370afdb4b1aeeda6bc2a8 {
	meta:
		aliases = "pex_child_error"
		size = "284"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 89 CF 56 89 D6 53 83 EC 0C 8B 58 04 89 1C 24 E8 ?? ?? ?? ?? 89 5C 24 04 BB ?? ?? ?? ?? C7 04 24 02 00 00 00 89 44 24 08 E8 ?? ?? ?? ?? B8 18 00 00 00 89 5C 24 04 89 44 24 08 C7 04 24 02 00 00 00 E8 ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 89 74 24 04 C7 04 24 02 00 00 00 89 44 24 08 E8 ?? ?? ?? ?? B9 03 00 00 00 BA ?? ?? ?? ?? 89 4C 24 08 89 54 24 04 C7 04 24 02 00 00 00 E8 ?? ?? ?? ?? 89 3C 24 E8 ?? ?? ?? ?? 89 7C 24 04 C7 04 24 02 00 00 00 89 44 24 08 E8 ?? ?? ?? ?? B8 02 00 00 00 89 44 24 08 B8 ?? ?? ?? ?? 89 44 24 04 C7 04 24 02 00 00 00 E8 ?? ?? ?? ?? 8B 45 08 89 04 24 E8 ?? ?? ?? }
	condition:
		$pattern
}

rule demangle_template_value_parm_e4d7e02607131b0c9871ce31ae461d27 {
	meta:
		aliases = "demangle_template_value_parm"
		size = "1235"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 89 CF 56 89 D6 53 83 EC 5C 8B 12 89 45 A8 8B 5D 08 0F B6 0A 80 F9 59 0F 84 AE 03 00 00 83 FB 03 74 3A 83 FB 05 0F 84 01 01 00 00 83 FB 04 0F 84 51 01 00 00 83 FB 06 90 8D 74 26 00 0F 84 6A 01 00 00 8D 43 FF 83 F8 01 0F 86 B0 00 00 00 B8 01 00 00 00 83 C4 5C 5B 5E 5F 5D C3 90 80 F9 45 0F 84 66 02 00 00 80 F9 51 0F 84 99 00 00 00 80 F9 4B 0F 84 90 00 00 00 80 F9 5F 89 F6 0F 84 61 02 00 00 80 F9 6D C7 45 B4 01 00 00 00 0F 84 FA 02 00 00 89 F0 E8 63 E2 FF FF C7 45 B8 01 00 00 00 89 45 BC 83 7D BC FF 0F 84 EF 00 00 00 8B 45 BC BA ?? ?? ?? ?? 8D 5D D2 89 54 24 04 89 1C 24 89 44 24 08 E8 }
	condition:
		$pattern
}

rule d_cv_qualifiers_6650f9808f57895d3306996aa3200368 {
	meta:
		aliases = "d_cv_qualifiers"
		size = "149"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 89 CF 56 89 D6 53 89 C3 83 EC 04 8B 40 0C 0F B6 00 EB 39 84 C9 75 43 3C 4B 75 6E FF 43 0C 83 FF 01 19 D2 83 43 30 06 83 E2 FD 83 C2 1B 31 C9 89 D8 C7 04 24 00 00 00 00 E8 5F FD FF FF 85 C0 89 06 74 44 8D 70 04 8B 43 0C 0F B6 00 3C 72 0F 94 C2 3C 56 0F 94 C1 84 D2 74 B9 FF 43 0C 84 D2 74 11 83 FF 01 19 D2 83 43 30 09 83 E2 FD 83 C2 19 EB BB 84 C9 74 A8 83 FF 01 19 D2 83 43 30 09 83 E2 FD 83 C2 1A EB A6 31 F6 5B 89 F0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule do_type_61c1df4fa7e32e5ba2ca820788fab690 {
	meta:
		aliases = "do_type"
		size = "2674"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 89 CF 56 89 D6 53 B3 01 83 EC 5C 89 45 A4 8D 45 D0 E8 F6 D6 FF FF 89 F8 E8 EF D6 FF FF C7 45 A8 00 00 00 00 C7 45 BC 01 00 00 00 C7 45 AC 00 00 00 00 8B 0E 0F B6 01 88 45 B7 2C 41 3C 34 77 0C 0F B6 C0 FF 24 85 ?? ?? ?? ?? 89 F6 C7 45 A8 01 00 00 00 31 C0 8B 55 BC 85 D2 0F 95 C3 84 DB 74 4B 84 C0 75 CD 8B 0E 0F B6 01 2C 42 3C 17 76 5C C7 45 E8 00 00 00 00 0F B6 01 2C 43 3C 32 0F 87 38 03 00 00 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8D 41 01 89 06 8D 55 F0 89 F0 E8 DF D5 FF FF 85 C0 0F 85 EA 03 00 00 8D B4 26 00 00 00 00 89 F8 E8 D9 D6 FF FF 8D 45 D0 E8 D1 D6 FF FF 31 C0 83 C4 5C 5B 5E 5F 5D }
	condition:
		$pattern
}

rule demangle_qualified_6c393754cf622ccfe8473503bd8d6bc8 {
	meta:
		aliases = "demangle_qualified"
		size = "941"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 89 D7 56 53 83 EC 4C 89 45 C0 89 4D BC E8 8A E0 FF FF 89 45 CC 8B 45 08 85 C0 74 10 8B 45 C0 C7 45 08 01 00 00 00 F6 40 28 01 74 51 8D 45 E4 E8 88 DA FF FF 8D 45 D8 E8 80 DA FF FF 8B 1F 80 3B 4B 0F 84 E5 02 00 00 0F B6 43 01 8D 73 01 3C 31 7D 12 C7 45 C8 00 00 00 00 8B 45 C8 83 C4 4C 5B 5E 5F 5D C3 3C 39 7E 24 3C 5F 75 E6 89 37 89 F8 E8 27 D9 FF FF 89 45 C4 40 75 33 EB D5 8B 50 2C 83 E2 01 89 55 08 EB A4 8D 74 26 00 88 45 F2 8D 45 F2 C6 45 F3 00 89 04 24 E8 ?? ?? ?? ?? 89 45 C4 80 7B 02 5F 0F 84 33 02 00 00 83 07 02 8B 45 C4 C7 45 C8 01 00 00 00 85 C0 0F 8E FC 00 00 00 8D B6 00 00 }
	condition:
		$pattern
}

rule d_substitution_6056066832c63832313de7822ff74768 {
	meta:
		aliases = "d_substitution"
		size = "316"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 89 D7 56 53 89 C3 83 EC 04 8B 70 0C 0F B6 16 8D 46 01 89 43 0C 80 FA 53 74 08 5E 31 C0 5B 5E 5F 5D C3 0F B6 4E 01 8D 46 02 89 43 0C 80 F9 5F 0F 84 B7 00 00 00 88 C8 2C 30 3C 09 77 59 31 D2 8D B6 00 00 00 00 8D BC 27 00 00 00 00 88 C8 2C 30 3C 09 77 2E 8D 14 D2 0F BE C1 8D 54 90 D0 8B 43 0C 0F B6 08 40 89 43 0C 80 F9 5F 75 DF 42 3B 53 20 7D A7 8B 43 1C FF 43 28 8B 04 90 5E 5B 5E 5F 5D C3 88 C8 2C 41 3C 19 77 90 8D 14 D2 0F BE C1 8D 54 90 C9 EB C8 88 C8 2C 41 3C 19 76 9F 8B 43 08 C1 E8 03 83 E0 01 89 45 F0 75 0E 85 FF 74 0A 0F B6 46 02 2C 43 3C 01 76 75 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? }
	condition:
		$pattern
}

rule get_count_9862bebda631b6c076056a3314da0a8c {
	meta:
		aliases = "get_count"
		size = "129"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 89 D7 56 89 C6 53 31 DB 8B 08 0F B6 11 0F B6 C2 F6 84 00 ?? ?? ?? ?? 04 74 49 0F BE C2 83 E8 30 89 07 8D 41 01 89 06 0F B6 41 01 F6 84 00 ?? ?? ?? ?? 04 74 29 8B 17 90 8D 74 26 00 8D 04 92 0F B6 59 02 0F BE 51 01 41 8D 54 42 D0 0F B6 C3 F6 84 00 ?? ?? ?? ?? 04 75 E3 80 FB 5F 74 0C BB 01 00 00 00 89 D8 5B 5E 5F 5D C3 8D 41 02 BB 01 00 00 00 89 06 89 D8 89 17 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule demangle_signature_ddb86960dc4c35fc9d2f81f8e8365cca {
	meta:
		aliases = "demangle_signature"
		size = "1748"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 89 D7 56 89 C6 53 83 EC 5C 89 4D A4 C7 45 A8 01 00 00 00 C7 45 AC 00 00 00 00 C7 45 B0 00 00 00 00 C7 45 B4 00 00 00 00 C7 45 C0 00 00 00 00 8B 1F 0F B6 13 84 D2 0F 84 D9 04 00 00 88 D0 2C 30 3C 45 77 0A 0F B6 C0 FF 24 85 ?? ?? ?? ?? F7 06 00 03 00 00 75 16 C7 45 A8 00 00 00 00 8B 45 A8 83 C4 5C 5B 5E 5F 5D C3 8D 74 26 00 8B 4D A4 89 FA 89 F0 E8 04 F0 FF FF C7 45 AC 01 00 00 00 89 45 A8 0F B6 45 B0 8B 55 A8 85 D2 0F 95 C2 84 C0 74 2A 84 D2 74 26 F7 06 00 2C 00 00 75 2B 8B 4D A4 89 FA 89 F0 E8 D2 EF FF FF C7 45 AC 01 00 00 00 C7 45 B0 00 00 00 00 89 45 A8 90 8B 45 A8 85 C0 0F 85 68 }
	condition:
		$pattern
}

rule d_print_array_type_fc89de704dce5ef422cf5c077c536e30 {
	meta:
		aliases = "d_print_array_type"
		size = "325"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 89 D7 56 89 CE 53 89 C3 83 EC 0C 85 C9 74 29 89 C8 8D 74 26 00 8D BC 27 00 00 00 00 8B 50 08 85 D2 0F 84 9B 00 00 00 8B 00 85 C0 75 EF 31 C9 89 F2 89 D8 E8 84 FE FF FF 8B 53 04 85 D2 74 08 8B 43 08 3B 43 0C 72 71 BA 20 00 00 00 89 D8 E8 99 E1 FF FF 8B 53 04 85 D2 74 08 8B 43 08 3B 43 0C 72 4C BA 5B 00 00 00 89 D8 E8 7E E1 FF FF 8B 57 04 85 D2 74 07 89 D8 E8 C0 E1 FF FF 8B 53 04 85 D2 74 08 8B 43 08 3B 43 0C 72 13 83 C4 0C 89 D8 5B BA 5D 00 00 00 5E 5F 5D E9 4E E1 FF FF C6 04 02 5D 40 89 43 08 83 C4 0C 5B 5E 5F 5D C3 C6 04 02 5B 40 89 43 08 EB B6 C6 04 02 20 40 89 43 08 EB 91 8B 40 }
	condition:
		$pattern
}

rule string_prependn_ec7ffd6abb31312198cc7c7a7daf5dc8 {
	meta:
		aliases = "string_prependn"
		size = "104"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 89 D7 56 89 CE 53 89 C3 83 EC 0C 85 C9 75 0D 83 C4 0C 5B 5E 5F 5D C3 90 8D 74 26 00 89 CA E8 59 FF FF FF 8B 53 04 8B 03 8D 4A FF 39 C1 72 1A 8D 54 32 FF 89 F6 8D BC 27 00 00 00 00 0F B6 01 49 88 02 4A 8B 03 39 C8 76 F3 89 74 24 08 89 7C 24 04 89 04 24 E8 ?? ?? ?? ?? 01 73 04 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule demangle_template_template_par_883c2c2687a43ba4c587d5c6da6c6724 {
	meta:
		aliases = "demangle_template_template_parm"
		size = "248"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 89 D7 56 BA ?? ?? ?? ?? 53 89 CE 83 EC 1C 89 45 D8 89 C8 E8 34 C7 FF FF 8D 55 F0 89 F8 E8 2A C2 FF FF 85 C0 74 7F 8B 45 F0 85 C0 7E 78 C7 45 DC 00 00 00 00 C7 45 E0 01 00 00 00 EB 41 8B 45 D8 8D 5D E4 89 FA 89 D9 E8 80 EB FF FF 85 C0 89 45 E0 0F 84 94 00 00 00 89 F0 89 DA E8 9C C6 FF FF 89 D8 E8 F5 C2 FF FF FF 45 DC 8B 45 DC 39 45 F0 7E 3A BA ?? ?? ?? ?? 89 F0 E8 CE C6 FF FF 8B 07 0F B6 10 80 FA 5A 74 44 80 FA 7A 75 B0 40 89 F1 89 07 8B 45 D8 89 FA E8 60 FF FF FF 85 C0 89 45 E0 75 C4 EB 07 C7 45 E0 01 00 00 00 8B 46 04 80 78 FF 3E 74 28 89 F0 BA ?? ?? ?? ?? E8 8B C6 FF FF 8B 45 E0 }
	condition:
		$pattern
}

rule byte_compile_range_11ae6bf4b7a5d4e63cb7b80b5f1e7c2b {
	meta:
		aliases = "byte_compile_range"
		size = "168"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 BF 0B 00 00 00 56 53 83 EC 08 8B 32 89 45 EC 8B 5D 0C 39 CE 74 7B 8D 46 01 81 E3 00 00 01 00 89 02 83 FB 01 8B 5D 08 19 FF F7 D7 83 E7 0B 85 DB 74 69 0F B6 45 EC 8B 4D 08 0F BE 14 01 0F B6 06 0F B6 34 01 39 D6 72 49 89 D3 BF 01 00 00 00 88 55 F3 EB 2E 8B 55 08 0F B6 C3 0F B6 0C 02 8B 55 10 89 C8 83 E1 07 C1 E8 03 43 01 D0 0F B6 10 88 55 F2 89 FA D2 E2 0A 55 F2 88 10 FE 45 F3 39 DE 72 0D 8B 4D 08 85 C9 75 CB 0F B6 4D F3 EB CF 31 FF 83 C4 08 89 F8 5B 5E 5F 5D C3 0F BE 55 EC 0F B6 36 EB A0 }
	condition:
		$pattern
}

rule byte_store_op1_4a44f290d0372e4f58079c81f5b6a19c {
	meta:
		aliases = "byte_store_op1"
		size = "16"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 5D 88 4A 01 C1 F9 08 88 02 88 4A 02 C3 }
	condition:
		$pattern
}

rule pex_unix_cleanup_939a034664c2b3234964a30decbd1f50 {
	meta:
		aliases = "hex_init, pex_unix_cleanup"
		size = "5"
		objfiles = "pex_unix@libiberty.a, hex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 5D C3 }
	condition:
		$pattern
}

rule string_init_e9969da2b197013690d77f8c5d1cc11c {
	meta:
		aliases = "string_init"
		size = "25"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 5D C7 40 08 00 00 00 00 C7 40 04 00 00 00 00 C7 00 00 00 00 00 C3 }
	condition:
		$pattern
}

rule d_class_enum_type_db47adb5bd7ac46503ea54ec70383a36 {
	meta:
		aliases = "d_class_enum_type"
		size = "9"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 5D E9 17 FD FF FF }
	condition:
		$pattern
}

rule splay_tree_xmalloc_allocate_1f11c58b08f2de469ecd0e8fde9b9319 {
	meta:
		aliases = "partition_delete, splay_tree_xmalloc_deallocate, splay_tree_xmalloc_allocate"
		size = "9"
		objfiles = "splay_tree@libiberty.a, partition@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule cplus_demangle_ac2366da8d3918d140b934f4b7e2be15 {
	meta:
		aliases = "cplus_demangle"
		size = "909"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 81 EC 88 00 00 00 83 3D ?? ?? ?? ?? FF 89 5D F4 8B 5D 08 89 75 F8 8B 75 0C 89 7D FC 0F 84 4B 01 00 00 B8 54 00 00 00 89 44 24 08 8D 7D 98 31 C0 89 44 24 04 89 3C 24 E8 ?? ?? ?? ?? F7 C6 04 FF 00 00 89 75 98 0F 84 D2 00 00 00 F7 45 98 00 41 00 00 0F 85 E1 00 00 00 F6 45 98 04 90 0F 85 2E 01 00 00 8B 45 98 25 00 80 00 00 66 85 C0 0F 84 09 01 00 00 FC C7 45 F0 00 00 00 00 C7 45 EC 00 00 00 00 BF ?? ?? ?? ?? B9 05 00 00 00 89 DE F3 A6 C7 45 8C 00 00 00 00 0F 97 C2 0F 92 C0 38 C2 75 0A 83 C3 05 C7 45 8C 01 00 00 00 0F B6 03 3C 5F 74 27 3C 3C 74 23 BE ?? ?? ?? ?? 89 74 24 04 89 1C 24 E8 ?? }
	condition:
		$pattern
}

rule d_print_comp_f1f1ce7403a08897a57441c2350bcf69 {
	meta:
		aliases = "d_print_comp"
		size = "6143"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 81 EC B8 00 00 00 85 D2 89 5D F4 89 C3 89 75 F8 89 7D FC 89 95 54 FF FF FF 74 16 8B 50 04 85 D2 89 D6 74 14 8B 85 54 FF FF FF 8B 08 83 F9 32 76 14 89 D8 E8 75 FE FF FF 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 FF 24 8D ?? ?? ?? ?? 8B 4B 08 8D 41 08 3B 43 0C 0F 87 B7 0F 00 00 8D 04 0A C7 00 56 54 54 20 C7 40 04 66 6F 72 20 83 43 08 08 8B 85 54 FF FF FF 8B 50 04 89 D8 E8 7E FF FF FF EB B7 8B 4B 08 8D 41 18 3B 43 0C 0F 87 0A 11 00 00 8D 04 0A BE ?? ?? ?? ?? FC B9 06 00 00 00 89 C7 F3 A5 83 43 08 18 8B 85 54 FF FF FF 8B 50 04 89 D8 E8 47 FF FF FF 8B 4B 04 85 C9 74 0F 8B 53 08 8D 42 04 3B 43 }
	condition:
		$pattern
}

rule fdmatch_65a2995cd7a08c033f3215a5dcfd9e9f {
	meta:
		aliases = "fdmatch"
		size = "103"
		objfiles = "fdmatch@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 81 EC B8 00 00 00 8D 45 A8 89 44 24 04 8B 45 08 89 04 24 E8 ?? ?? ?? ?? 85 C0 74 04 C9 31 C0 C3 8D 85 50 FF FF FF 89 44 24 04 8B 45 0C 89 04 24 E8 ?? ?? ?? ?? 85 C0 75 E3 8B 55 AC 8B 8D 54 FF FF FF 8B 45 A8 31 D1 8B 95 50 FF FF FF 31 D0 09 C1 75 C9 8B 45 B4 3B 85 5C FF FF FF C9 0F 94 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule getpwd_8b5544ac8f434af57f3de00f41103e98 {
	meta:
		aliases = "getpwd"
		size = "277"
		objfiles = "getpwd@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 81 EC C8 00 00 00 89 5D F4 8B 1D ?? ?? ?? ?? 89 75 F8 89 7D FC 85 DB 74 0F 89 D8 8B 75 F8 8B 5D F4 8B 7D FC 89 EC 5D C3 E8 ?? ?? ?? ?? 89 85 40 FF FF FF A1 ?? ?? ?? ?? 8B 95 40 FF FF FF 85 C0 89 02 75 D5 C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 89 C6 74 05 80 38 2F 74 57 BF 01 10 00 00 EB 17 8B 85 40 FF FF FF 8B 18 89 34 24 E8 ?? ?? ?? ?? 83 FB 22 75 29 01 FF 89 3C 24 E8 ?? ?? ?? ?? 89 7C 24 04 89 C6 89 04 24 E8 ?? ?? ?? ?? 85 C0 74 CF 89 F3 89 35 ?? ?? ?? ?? E9 79 FF FF FF 8B 95 40 FF FF FF 31 F6 89 1D ?? ?? ?? ?? 89 1A EB E1 8D 85 44 FF FF FF 89 44 24 04 89 34 24 E8 ?? ?? ?? ?? 85 }
	condition:
		$pattern
}

rule qualifier_string_c4c91bbd71459c3373d0a77062e610c3 {
	meta:
		aliases = "qualifier_string"
		size = "79"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 83 F8 07 77 07 FF 24 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? C9 B8 ?? ?? ?? ?? C3 C9 B8 ?? ?? ?? ?? C3 C9 B8 ?? ?? ?? ?? C3 C9 B8 ?? ?? ?? ?? C3 C9 B8 ?? ?? ?? ?? C3 C9 B8 ?? ?? ?? ?? C3 C9 B8 ?? ?? ?? ?? C3 C9 B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule code_for_qualifier_f3eb25165157161f353e8d35f9f217d5 {
	meta:
		aliases = "code_for_qualifier"
		size = "57"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 83 F8 56 74 25 83 F8 75 74 10 83 F8 43 BA 01 00 00 00 74 0B E8 ?? ?? ?? ?? 90 BA 04 00 00 00 C9 89 D0 C3 8D B4 26 00 00 00 00 C9 BA 02 00 00 00 89 D0 C3 }
	condition:
		$pattern
}

rule xre_match_b60910bbc666037c8c494c77466d6165 {
	meta:
		aliases = "xre_match"
		size = "62"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 89 1C 24 89 74 24 04 8B 4D 10 8B 75 0C 8B 5D 14 8B 55 18 89 4D 0C 8B 45 08 89 4D 18 31 C9 89 5D 10 89 55 14 31 D2 89 75 08 8B 1C 24 8B 74 24 04 89 EC 5D E9 D2 DB FF FF }
	condition:
		$pattern
}

rule cplus_demangle_mangled_name_8809ff0660b568fb2a1d25c734934564 {
	meta:
		aliases = "cplus_demangle_mangled_name"
		size = "83"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 89 1C 24 89 74 24 04 8B 5D 08 8B 75 0C 8B 4B 0C 0F B6 11 8D 41 01 89 43 0C 80 FA 5F 74 0D 8B 1C 24 31 C0 8B 74 24 04 89 EC 5D C3 0F B6 51 01 8D 41 02 89 43 0C 80 FA 5A 75 E4 89 F2 89 D8 8B 74 24 04 8B 1C 24 89 EC 5D E9 1D FC FF FF }
	condition:
		$pattern
}

rule d_print_append_char_9ce23d4e84a58d908615537125e10e2d {
	meta:
		aliases = "d_print_append_char"
		size = "78"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 89 1C 24 89 C3 89 74 24 04 89 D6 8B 40 04 85 C0 74 13 8B 53 08 3B 53 0C 73 16 8B 43 04 89 F1 88 0C 10 FF 43 08 8B 1C 24 8B 74 24 04 89 EC 5D C3 89 D8 BA 01 00 00 00 E8 DE FE FF FF 8B 43 04 85 C0 74 E2 8B 53 08 EB D2 }
	condition:
		$pattern
}

rule d_template_param_05c450944d9e1effbc0e97168058dff1 {
	meta:
		aliases = "d_template_param"
		size = "129"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 89 1C 24 89 C3 89 74 24 04 8B 48 0C 0F B6 11 8D 41 01 89 43 0C 80 FA 54 74 10 31 C0 8B 1C 24 8B 74 24 04 89 EC 5D C3 8D 76 00 80 79 01 5F 75 2A 8D 41 02 31 F6 89 43 0C FF 43 28 89 D8 E8 88 FC FF FF 85 C0 74 D6 C7 00 05 00 00 00 89 70 04 8B 1C 24 8B 74 24 04 89 EC 5D C3 89 D8 E8 19 FE FF FF 85 C0 89 C1 78 B3 8B 43 0C 0F B6 10 40 89 43 0C 80 FA 5F 75 A4 8D 71 01 EB BD }
	condition:
		$pattern
}

rule d_print_mod_a0806f1976c0d67c5c0b3b0c9429df69 {
	meta:
		aliases = "d_print_mod"
		size = "680"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 89 1C 24 89 D3 89 74 24 04 89 C6 8B 02 83 E8 03 83 F8 22 77 07 FF 24 85 ?? ?? ?? ?? 89 DA 89 F0 8B 1C 24 8B 74 24 04 89 EC 5D E9 FB E5 FF FF 8B 52 04 EB EA 8B 4E 04 85 C9 74 0F 8B 56 08 8D 42 09 3B 46 0C 0F 86 3B 02 00 00 B9 09 00 00 00 BA ?? ?? ?? ?? 8D B6 00 00 00 00 89 F0 8B 1C 24 8B 74 24 04 89 EC 5D E9 FF E4 FF FF 8B 4E 04 85 C9 74 0F 8B 56 08 8D 42 09 3B 46 0C 0F 86 E7 01 00 00 B9 09 00 00 00 BA ?? ?? ?? ?? EB CD 8B 4E 04 85 C9 74 0F 8B 56 08 8D 42 06 3B 46 0C 0F 86 AD 01 00 00 B9 06 00 00 00 BA ?? ?? ?? ?? EB AB 8B 56 04 85 D2 0F 84 1F 01 00 00 8B 46 08 3B 46 0C 0F 83 }
	condition:
		$pattern
}

rule d_make_sub_cfa7b0cf840aa048e3432a157d4bfb58 {
	meta:
		aliases = "d_make_sub"
		size = "49"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 89 1C 24 89 D3 89 74 24 04 89 CE E8 FA FE FF FF 85 C0 74 0C C7 00 15 00 00 00 89 58 04 89 70 08 8B 1C 24 8B 74 24 04 89 EC 5D C3 }
	condition:
		$pattern
}

rule xatexit_f61be20f8fee4879a0138fba88c43dd3 {
	meta:
		aliases = "xatexit"
		size = "107"
		objfiles = "xatexit@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 8B 15 ?? ?? ?? ?? 85 D2 74 20 8B 0D ?? ?? ?? ?? 83 79 04 1F 7F 20 8B 41 04 8B 55 08 89 54 81 08 40 89 41 04 31 C0 C9 C3 89 F6 B8 ?? ?? ?? ?? A3 ?? ?? ?? ?? EB D4 C7 04 24 88 00 00 00 E8 ?? ?? ?? ?? 89 C2 B8 FF FF FF FF 85 D2 74 D9 A1 ?? ?? ?? ?? 89 D1 C7 42 04 00 00 00 00 89 15 ?? ?? ?? ?? 89 02 EB B1 }
	condition:
		$pattern
}

rule unlock_stream_5e86d48bceff8542eeda98755446d776 {
	meta:
		aliases = "unlock_stream"
		size = "32"
		objfiles = "fopen_unlocked@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 8B 45 08 85 C0 74 11 BA 02 00 00 00 89 54 24 04 89 04 24 E8 ?? ?? ?? ?? C9 C3 }
	condition:
		$pattern
}

rule xmalloc_set_program_name_20bf03d361860df68f9378e845c2fd5f {
	meta:
		aliases = "xmalloc_set_program_name"
		size = "51"
		objfiles = "xmalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 8B 45 08 A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? 85 C0 74 09 C9 C3 8D B4 26 00 00 00 00 C7 04 24 00 00 00 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? C9 C3 }
	condition:
		$pattern
}

rule xre_compile_pattern_6e21af340ecbc24316c38991e115bf1c {
	meta:
		aliases = "xre_compile_pattern"
		size = "57"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 8B 55 10 0F B6 42 1C 24 E9 0C 80 88 42 1C 8B 0D ?? ?? ?? ?? 89 14 24 8B 45 08 8B 55 0C E8 D8 D2 FF FF 31 D2 85 C0 74 07 8B 14 85 ?? ?? ?? ?? C9 89 D0 C3 }
	condition:
		$pattern
}

rule xexit_39928f6b3498d14139d7bccbd3812349 {
	meta:
		aliases = "xexit"
		size = "28"
		objfiles = "xexit@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 A1 ?? ?? ?? ?? 85 C0 74 02 FF D0 8B 45 08 89 04 24 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule unlock_std_streams_fd4e02c9d61808f5d56ea36da395313f {
	meta:
		aliases = "unlock_std_streams"
		size = "86"
		objfiles = "fopen_unlocked@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 A1 ?? ?? ?? ?? 85 C0 74 11 BA 02 00 00 00 89 54 24 04 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 85 C0 74 11 B9 02 00 00 00 89 4C 24 04 89 04 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 85 C0 74 11 BA 02 00 00 00 89 54 24 04 89 04 24 E8 ?? ?? ?? ?? C9 C3 }
	condition:
		$pattern
}

rule errno_max_3c100300e36a751ddbc2240de6289285 {
	meta:
		aliases = "signo_max, errno_max"
		size = "42"
		objfiles = "strsignal@libiberty.a, strerror@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 A1 ?? ?? ?? ?? 85 C0 74 14 8B 15 ?? ?? ?? ?? A1 ?? ?? ?? ?? 39 D0 7D 02 89 D0 C9 48 C3 E8 C8 FD FF FF EB E5 }
	condition:
		$pattern
}

rule pex_init_common_30026b079ee9ab03a3677b32d85d1d93 {
	meta:
		aliases = "pex_init_common"
		size = "134"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 C7 04 24 44 00 00 00 E8 ?? ?? ?? ?? 8B 55 08 89 10 8B 55 0C C7 40 0C 00 00 00 00 C7 40 14 00 00 00 00 C7 40 18 00 00 00 00 89 50 04 8B 55 10 C7 40 1C 00 00 00 00 C7 40 10 00 00 00 00 C7 40 20 00 00 00 00 89 50 08 8B 55 14 C7 40 24 00 00 00 00 C7 40 28 00 00 00 00 C7 40 2C 00 00 00 00 C7 40 30 00 00 00 00 C7 40 34 00 00 00 00 C7 40 38 00 00 00 00 89 50 3C C7 40 40 00 00 00 00 C9 C3 }
	condition:
		$pattern
}

rule demangle_qualifier_1c74c13332b5bc41573feefe99a72b2f {
	meta:
		aliases = "demangle_qualifier"
		size = "17"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 E8 B5 FF FF FF C9 E9 5F FF FF FF }
	condition:
		$pattern
}

rule d_make_comp_6c30171e747d871af97fa6344a2230e8 {
	meta:
		aliases = "d_make_comp"
		size = "105"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 0C 83 FA 32 89 1C 24 89 D3 89 74 24 04 89 CE 89 7C 24 08 8B 7D 08 77 13 FF 24 95 ?? ?? ?? ?? 85 C9 75 3B 90 8D B4 26 00 00 00 00 31 C0 8B 1C 24 8B 74 24 04 8B 7C 24 08 89 EC 5D C3 85 C9 74 EB 8D 74 26 00 8D BC 27 00 00 00 00 E8 7B FF FF FF 85 C0 74 D9 89 18 89 70 04 89 78 08 EB CF 85 FF 75 E9 EB C7 }
	condition:
		$pattern
}

rule xre_match_2_71d58e1bb38e317f4177a57c1fddc0b6 {
	meta:
		aliases = "xre_match_2"
		size = "75"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 0C 89 1C 24 89 74 24 04 89 7C 24 08 8B 5D 24 8B 75 18 8B 7D 14 8B 45 08 89 5D 18 8B 5D 20 8B 55 0C 89 7D 08 8B 4D 10 89 75 0C 89 5D 14 8B 5D 1C 89 5D 10 8B 1C 24 8B 74 24 04 8B 7C 24 08 89 EC 5D E9 15 DC FF FF }
	condition:
		$pattern
}

rule fibheap_cut_82181554105430a5bb49148493831da0 {
	meta:
		aliases = "fibheap_cut"
		size = "92"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 0C 89 1C 24 89 CB 89 7C 24 08 89 C7 89 D0 89 74 24 04 89 D6 E8 92 FF FF FF 8B 53 18 8B 43 18 81 C2 FF FF FF 7F 81 E2 FF FF FF 7F 25 00 00 00 80 09 D0 89 F2 89 43 18 89 F8 E8 4D FF FF FF 8B 1C 24 C7 06 00 00 00 00 8B 7C 24 08 80 66 1B 7F 8B 74 24 04 89 EC 5D C3 }
	condition:
		$pattern
}

rule fibheap_replace_data_373b78ea0e3b0fa9e70521b4e37817e5 {
	meta:
		aliases = "fibheap_replace_data"
		size = "40"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 10 8B 45 10 8B 55 0C 89 44 24 0C 8B 42 10 89 54 24 04 89 44 24 08 8B 45 08 89 04 24 E8 ?? ?? ?? ?? C9 C3 }
	condition:
		$pattern
}

rule d_source_name_1e0e58d54a8395a22f219d2ee77917df {
	meta:
		aliases = "d_source_name"
		size = "211"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 14 89 5D F4 89 C3 89 75 F8 89 7D FC E8 FA D8 FF FF 31 D2 85 C0 89 45 EC 7E 16 8B 43 0C 89 45 F0 8B 43 04 8B 75 F0 29 F0 39 45 EC 7E 12 89 53 2C 8B 5D F4 89 D0 8B 75 F8 8B 7D FC 89 EC 5D C3 8B 45 F0 8B 4D EC 01 C8 F6 43 08 04 89 43 0C 74 05 80 38 24 74 47 83 7D EC 09 7E 30 8B 75 F0 BA ?? ?? ?? ?? B8 08 00 00 00 FC 89 D7 89 C1 F3 A6 75 1A 8B 4D F0 8B 55 F0 0F B6 41 08 83 C2 08 3C 2E 74 20 3C 5F 74 1C 3C 24 74 18 90 8B 55 F0 89 D8 8B 4D EC E8 63 D7 FF FF 89 C2 EB 91 40 89 43 0C EB B3 80 7A 01 4E 75 E3 8B 43 30 B9 15 00 00 00 8B 55 EC 29 D0 BA ?? ?? ?? ?? 83 C0 16 89 43 30 89 D8 E8 }
	condition:
		$pattern
}

rule floatformat_i387_ext_is_valid_47bb64c5d2b0375643c86e0166710fe8 {
	meta:
		aliases = "floatformat_i387_ext_is_valid"
		size = "106"
		objfiles = "floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 14 89 5D F4 8B 5D 08 89 75 F8 89 7D FC 8B 7D 0C 8B 43 10 8B 4B 04 89 44 24 04 8B 43 0C 89 04 24 89 F8 8B 13 E8 02 FF FF FF 8B 4B 04 89 C6 B8 01 00 00 00 89 44 24 04 8B 43 1C 89 04 24 89 F8 8B 13 E8 E5 FE FF FF 85 F6 8B 5D F4 0F 94 C2 8B 75 F8 8B 7D FC 85 C0 0F 94 C0 89 EC 30 C2 5D 80 F2 01 0F B6 C2 C3 }
	condition:
		$pattern
}

rule string_appendn_51478fac012579e973c3e0495aa3d5fd {
	meta:
		aliases = "string_appendn"
		size = "67"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 85 C9 89 5D F4 89 CB 89 75 F8 89 C6 89 7D FC 89 D7 74 1D 89 CA E8 80 FE FF FF 8B 46 04 89 5C 24 08 89 7C 24 04 89 04 24 E8 ?? ?? ?? ?? 01 5E 04 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 }
	condition:
		$pattern
}

rule string_prepend_a4daf940757fd24c7463ae0bd1fcc55a {
	meta:
		aliases = "string_prepend"
		size = "63"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 85 D2 89 5D F8 89 D3 89 75 FC 89 C6 74 05 80 3A 00 75 0A 8B 5D F8 8B 75 FC 89 EC 5D C3 89 14 24 E8 ?? ?? ?? ?? 89 DA 8B 5D F8 89 C1 89 F0 8B 75 FC 89 EC 5D E9 21 FF FF FF }
	condition:
		$pattern
}

rule string_append_60ac6b14454790f82b9e15a9c97b60d5 {
	meta:
		aliases = "string_append"
		size = "91"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 85 D2 89 75 F8 89 D6 89 7D FC 89 C7 89 5D F4 74 05 80 3A 00 75 14 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 8D B4 26 00 00 00 00 89 14 24 E8 ?? ?? ?? ?? 89 C3 89 C2 89 F8 E8 BD FD FF FF 8B 47 04 89 5C 24 08 89 74 24 04 89 04 24 E8 ?? ?? ?? ?? 01 5F 04 EB C1 }
	condition:
		$pattern
}

rule demangle_class_name_4128457695c1890789b0447785aa6ca5 {
	meta:
		aliases = "demangle_class_name"
		size = "87"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 45 F0 89 D0 89 5D F4 89 75 F8 89 D6 89 7D FC 89 CF E8 63 C1 FF FF 83 F8 FF 89 C3 74 0E 8B 06 89 04 24 E8 ?? ?? ?? ?? 39 C3 7E 0F 31 C0 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 8B 45 F0 89 D9 89 F2 89 3C 24 E8 00 FA FF FF B8 01 00 00 00 EB DD }
	condition:
		$pattern
}

rule choose_temp_base_589790d939da0b230a628bee6c99141f {
	meta:
		aliases = "choose_temp_base"
		size = "110"
		objfiles = "choose_temp@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 5D F4 89 75 F8 89 7D FC E8 ?? ?? ?? ?? 89 04 24 89 C3 E8 ?? ?? ?? ?? 89 C7 8D 40 09 89 04 24 E8 ?? ?? ?? ?? 89 5C 24 04 89 C6 89 04 24 E8 ?? ?? ?? ?? 8D 04 3E C7 00 63 63 58 58 C7 40 04 58 58 58 58 C6 40 08 00 89 34 24 E8 ?? ?? ?? ?? 80 3E 00 74 0F 89 F0 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule demangle_nested_args_9a126a58b6e3b0cefb8cb6dbedeaa01f {
	meta:
		aliases = "demangle_nested_args"
		size = "102"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 5D F4 89 C3 89 75 F8 89 7D FC FF 40 48 8B 78 4C 8B 40 50 C7 43 4C 00 00 00 00 C7 43 50 00 00 00 00 89 45 F0 89 D8 E8 6E FD FF FF 89 C6 8B 43 4C 85 C0 74 10 E8 A0 C9 FF FF 8B 43 4C 89 04 24 E8 ?? ?? ?? ?? 8B 45 F0 89 7B 4C 8B 7D FC FF 4B 48 89 43 50 89 F0 8B 5D F4 8B 75 F8 89 EC 5D C3 }
	condition:
		$pattern
}

rule d_print_append_buffer_832f73615dedc38b8971eb1cccbd062c {
	meta:
		aliases = "d_print_append_buffer"
		size = "98"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 5D F4 89 C3 89 75 F8 89 CE 89 7D FC 89 D7 8B 48 04 85 C9 74 27 8B 53 08 89 F0 01 D0 3B 43 0C 77 28 8B 43 08 8B 53 04 89 74 24 08 89 7C 24 04 01 D0 89 04 24 E8 ?? ?? ?? ?? 01 73 08 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 89 F2 89 D8 E8 37 FF FF FF 8B 4B 04 85 C9 75 C8 EB E1 }
	condition:
		$pattern
}

rule d_make_name_cd1ed2ab1f6a0167e52d391e718e334d {
	meta:
		aliases = "d_make_name"
		size = "67"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 5D F4 89 CB 89 75 F8 89 D6 89 7D FC E8 48 FF FF FF 89 5C 24 08 89 74 24 04 89 C7 89 04 24 E8 ?? ?? ?? ?? 8B 5D F4 8B 75 F8 85 C0 0F 95 C0 0F B6 C0 F7 D8 21 F8 8B 7D FC 89 EC 5D C3 }
	condition:
		$pattern
}

rule htab_traverse_17056ff4365ad48553d41710a375c750 {
	meta:
		aliases = "htab_traverse"
		size = "73"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 5D F4 8B 5D 08 89 75 F8 8B 75 10 89 7D FC 8B 7D 0C 8B 43 14 8B 53 18 29 D0 C1 E0 03 3B 43 10 73 07 89 D8 E8 A1 FD FF FF 89 75 10 8B 75 F8 89 7D 0C 8B 7D FC 89 5D 08 8B 5D F4 89 EC 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule splay_tree_insert_b0dd7e2d2bec62e746411e2170715daf {
	meta:
		aliases = "splay_tree_insert"
		size = "198"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 5D F4 8B 5D 08 89 7D FC 8B 7D 0C 89 75 F8 89 D8 89 FA E8 72 FC FF FF 8B 03 85 C0 74 7C 89 7C 24 04 8B 00 89 04 24 FF 53 04 89 C6 8B 03 85 C0 75 48 8B 43 18 C7 04 24 10 00 00 00 89 44 24 04 FF 53 10 8B 13 85 D2 89 C1 89 38 8B 45 10 89 41 04 74 4B 85 F6 78 57 8B 42 08 89 51 0C 89 41 08 C7 42 08 00 00 00 00 89 0B 89 C8 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 89 F6 85 F6 75 B4 8B 53 0C 85 D2 74 0A 8B 40 04 89 04 24 FF D2 8B 03 8B 55 10 89 50 04 EB D4 8D 76 00 31 F6 EB 94 C7 41 0C 00 00 00 00 C7 41 08 00 00 00 00 EB B9 8B 42 0C 89 51 08 89 41 0C C7 42 0C 00 00 00 00 EB A7 }
	condition:
		$pattern
}

rule pex_input_file_45bcd19fede8227f21d951c6ab4a6298 {
	meta:
		aliases = "pex_input_file"
		size = "164"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 5D F4 8B 5D 08 89 7D FC 8B 7D 0C 89 75 F8 8B 43 18 85 C0 75 07 8B 43 0C 85 C0 7E 1D E8 ?? ?? ?? ?? 31 F6 C7 00 16 00 00 00 89 F0 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 90 8B 43 10 85 C0 75 DC 8B 4D 10 89 FA 89 D8 31 F6 E8 AB FE FF FF 85 C0 89 45 F0 74 D4 83 E7 20 B8 ?? ?? ?? ?? 75 05 B8 ?? ?? ?? ?? 89 44 24 04 8B 45 F0 89 04 24 E8 ?? ?? ?? ?? 85 C0 89 C6 74 17 89 43 2C 8B 45 F0 39 45 10 89 43 10 0F 95 C0 0F B6 C0 89 43 14 EB 99 8B 45 F0 89 04 24 E8 ?? ?? ?? ?? EB 8C }
	condition:
		$pattern
}

rule spaces_82fe2723c270f97a0983447bb600389f {
	meta:
		aliases = "spaces"
		size = "131"
		objfiles = "spaces@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 5D F8 8B 5D 08 39 1D ?? ?? ?? ?? 89 75 FC 7C 19 A1 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 01 D0 29 D8 8B 5D F8 8B 75 FC 89 EC 5D C3 A1 ?? ?? ?? ?? 85 C0 74 08 89 04 24 E8 ?? ?? ?? ?? 8D 43 01 89 04 24 E8 ?? ?? ?? ?? 89 C1 A3 ?? ?? ?? ?? 31 C0 85 C9 74 CD 8D 34 19 39 F1 74 18 89 F2 89 C8 8D B6 00 00 00 00 8D BF 00 00 00 00 4A 39 C2 C6 02 20 75 F8 89 1D ?? ?? ?? ?? C6 06 00 EB 94 }
	condition:
		$pattern
}

rule xstrdup_e29a090d57f5be95ceb34a093b11ec8a {
	meta:
		aliases = "xstrdup"
		size = "60"
		objfiles = "xstrdup@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 5D F8 8B 5D 08 89 75 FC 89 1C 24 E8 ?? ?? ?? ?? 8D 70 01 89 34 24 E8 ?? ?? ?? ?? 89 74 24 08 89 5C 24 04 89 04 24 E8 ?? ?? ?? ?? 8B 5D F8 8B 75 FC 89 EC 5D C3 }
	condition:
		$pattern
}

rule splay_tree_lookup_5dc322591b39c69de3ecf292e071da2d {
	meta:
		aliases = "splay_tree_lookup"
		size = "76"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 5D F8 8B 5D 08 89 75 FC 8B 75 0C 89 D8 89 F2 E8 25 FB FF FF 8B 03 85 C0 75 0F 8B 5D F8 31 C0 8B 75 FC 89 EC 5D C3 8D 76 00 89 74 24 04 8B 00 89 04 24 FF 53 04 85 C0 75 E1 8B 03 8B 5D F8 8B 75 FC 89 EC 5D C3 }
	condition:
		$pattern
}

rule dyn_string_init_59139c3d29c4fe92e7ed063fc98fef71 {
	meta:
		aliases = "dyn_string_init"
		size = "76"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 5D F8 8B 5D 0C 89 75 FC 8B 75 08 85 DB 89 D8 74 28 89 04 24 E8 ?? ?? ?? ?? 89 1E C7 46 04 00 00 00 00 89 46 08 C6 00 00 B8 01 00 00 00 8B 5D F8 8B 75 FC 89 EC 5D C3 89 F6 BB 01 00 00 00 B8 01 00 00 00 EB CC }
	condition:
		$pattern
}

rule htab_remove_elt_00d1787881f237551fbc42d1cbc4328b {
	meta:
		aliases = "htab_find, htab_remove_elt"
		size = "49"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 5D F8 8B 5D 0C 89 75 FC 8B 75 08 89 1C 24 FF 16 89 5C 24 04 89 34 24 89 44 24 08 E8 ?? ?? ?? ?? 8B 5D F8 8B 75 FC 89 EC 5D C3 }
	condition:
		$pattern
}

rule htab_find_slot_78b9fa541a2fe62eab3546387ec21ea9 {
	meta:
		aliases = "htab_find_slot"
		size = "56"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 5D F8 8B 5D 0C 89 75 FC 8B 75 08 89 1C 24 FF 16 8B 55 10 89 5C 24 04 89 34 24 89 54 24 0C 89 44 24 08 E8 ?? ?? ?? ?? 8B 5D F8 8B 75 FC 89 EC 5D C3 }
	condition:
		$pattern
}

rule d_encoding_f142b324c3f05ae901561fb914b746bd {
	meta:
		aliases = "d_encoding"
		size = "903"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 75 F8 89 C6 89 7D FC 89 D7 89 5D F4 8B 50 0C 0F B6 02 3C 47 0F 84 B1 00 00 00 3C 54 0F 84 A9 00 00 00 89 F0 E8 E0 FC FF FF 85 C0 89 C3 74 1A 85 FF 74 16 F6 46 08 01 89 F6 74 61 8D B4 26 00 00 00 00 8D BC 27 00 00 00 00 8B 46 0C 0F B6 00 84 C0 74 36 3C 45 74 32 89 D8 E8 0B D3 FF FF 89 C2 89 F0 E8 02 0D 00 00 89 D9 BA 03 00 00 00 89 04 24 89 F0 E8 C1 D1 FF FF 89 C3 EB 0D 90 90 90 90 90 90 90 90 90 90 90 90 90 89 D8 8B 75 F8 8B 5D F4 8B 7D FC 89 EC 5D C3 90 8B 5B 04 8B 13 8D 42 E7 83 F8 02 76 F3 83 FA 02 75 DE 8B 53 08 8B 02 83 E8 19 83 F8 02 77 0E 90 8B 52 04 8B 02 83 E8 19 }
	condition:
		$pattern
}

rule string_appends_6885ab96050571a5f28708e8b37d1ca7 {
	meta:
		aliases = "string_appends"
		size = "78"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 75 F8 89 D6 89 7D FC 89 C7 8B 46 04 89 5D F4 8B 12 39 C2 74 25 89 C3 89 F8 29 D3 89 DA E8 27 FE FF FF 8B 57 04 8B 06 89 5C 24 08 89 14 24 89 44 24 04 E8 ?? ?? ?? ?? 01 5F 04 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 }
	condition:
		$pattern
}

rule choose_tmpdir_0f03808c4c86fe7e5b303150b41a4498 {
	meta:
		aliases = "choose_tmpdir"
		size = "412"
		objfiles = "make_temp_file@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 75 F8 8B 35 ?? ?? ?? ?? 89 5D F4 89 7D FC 85 F6 74 0F 89 F0 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 89 C7 74 19 B8 07 00 00 00 89 44 24 04 89 3C 24 E8 ?? ?? ?? ?? 85 C0 0F 84 1B 01 00 00 C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 89 C7 74 19 B8 07 00 00 00 89 44 24 04 89 3C 24 E8 ?? ?? ?? ?? 85 C0 0F 84 0D 01 00 00 C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 89 C7 74 54 BE 07 00 00 00 89 74 24 04 89 3C 24 E8 ?? ?? ?? ?? 85 C0 75 3F 85 FF 74 77 89 3C 24 8D 74 26 00 E8 ?? ?? ?? ?? 89 C3 8D 40 02 89 04 24 E8 ?? ?? ?? ?? 89 7C 24 04 89 C6 }
	condition:
		$pattern
}

rule grow_vect_7247ea8be25011dc6843c6bbcd5f4653 {
	meta:
		aliases = "grow_vect"
		size = "68"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 75 FC 89 C6 8B 02 89 5D F8 8B 5D 08 39 C8 73 1D 01 C0 39 C1 89 02 77 21 8B 0A 8B 06 0F AF D9 89 04 24 89 5C 24 04 E8 ?? ?? ?? ?? 89 06 8B 5D F8 8B 75 FC 89 EC 5D C3 89 F6 89 0A EB DB }
	condition:
		$pattern
}

rule xcalloc_f8deb0476257749b07a5a669e964d945 {
	meta:
		aliases = "xcalloc"
		size = "87"
		objfiles = "xmalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 75 FC 8B 75 08 89 5D F8 8B 5D 0C 85 F6 74 2A 85 DB 74 26 8D B6 00 00 00 00 89 5C 24 04 89 34 24 E8 ?? ?? ?? ?? 85 C0 74 1C 8B 5D F8 8B 75 FC 89 EC 5D C3 8D B6 00 00 00 00 BE 01 00 00 00 BB 01 00 00 00 EB D4 0F AF F3 89 34 24 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule htab_clear_slot_4bde7a751f1511e549bef02ab3b3c2fe {
	meta:
		aliases = "htab_clear_slot"
		size = "85"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 75 FC 8B 75 08 89 5D F8 8B 5D 0C 8B 56 0C 39 DA 77 37 8B 46 10 8D 04 82 39 C3 73 2D 8B 03 85 C0 74 27 83 F8 01 74 22 8B 56 08 85 D2 74 05 89 04 24 FF D2 FF 46 18 C7 03 01 00 00 00 8B 5D F8 8B 75 FC 89 EC 5D C3 8D 76 00 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule splay_tree_new_with_allocator_1f9a815a36ee59be7f22bbec0d9d8090 {
	meta:
		aliases = "splay_tree_new_with_allocator"
		size = "77"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 75 FC 8B 75 1C 89 5D F8 8B 5D 14 C7 04 24 1C 00 00 00 89 74 24 04 FF D3 8B 55 08 89 50 04 8B 55 0C C7 00 00 00 00 00 89 58 10 89 70 18 89 50 08 8B 55 10 89 50 0C 8B 55 18 89 50 14 8B 5D F8 8B 75 FC 89 EC 5D C3 }
	condition:
		$pattern
}

rule string_need_8cebc535db465e457892382168005c93 {
	meta:
		aliases = "string_need"
		size = "122"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 7D FC 89 C7 89 5D F4 89 75 F8 8B 08 85 C9 74 3E 8B 58 04 8B 40 08 29 D8 39 D0 7C 0D 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 89 DE 29 CE 8D 1C 32 01 DB 89 5C 24 04 89 0C 24 E8 ?? ?? ?? ?? 89 07 01 F0 8B 0F 89 47 04 01 CB 89 5F 08 EB CE 83 FA 1F 89 D3 7F 0A BA 20 00 00 00 BB 20 00 00 00 89 14 24 E8 ?? ?? ?? ?? 01 C3 89 07 89 47 04 89 5F 08 EB A9 }
	condition:
		$pattern
}

rule save_string_64818600e44289d976329ce6bb0f3c27 {
	meta:
		aliases = "save_string"
		size = "67"
		objfiles = "make_relative_prefix@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 7D FC 89 C7 8D 42 01 89 5D F4 89 75 F8 89 D6 89 04 24 E8 ?? ?? ?? ?? 89 74 24 08 89 7C 24 04 89 C3 89 04 24 E8 ?? ?? ?? ?? 89 D8 8B 7D FC C6 04 33 00 8B 5D F4 8B 75 F8 89 EC 5D C3 }
	condition:
		$pattern
}

rule xstrndup_54dc1ffe83964c92794df089c8792083 {
	meta:
		aliases = "xstrndup"
		size = "81"
		objfiles = "xstrndup@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 7D FC 8B 7D 08 89 5D F4 89 75 F8 8B 75 0C 89 3C 24 E8 ?? ?? ?? ?? 39 F0 89 C3 76 02 89 F3 8D 43 01 89 04 24 E8 ?? ?? ?? ?? C6 04 18 00 89 5C 24 08 89 7C 24 04 89 04 24 E8 ?? ?? ?? ?? 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 }
	condition:
		$pattern
}

rule fibheap_union_a6c4fb7e429eab53e39d318fa781dd68 {
	meta:
		aliases = "fibheap_union"
		size = "114"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 7D FC 8B 7D 08 89 75 F8 8B 75 0C 89 5D F4 8B 5F 08 85 DB 74 49 8B 4E 08 85 C9 74 24 8B 41 08 8B 53 08 89 43 08 89 4A 0C 89 51 08 89 58 0C 8B 06 8B 4E 04 8B 57 04 01 07 8B 41 10 3B 42 10 7C 19 89 34 24 89 FE E8 ?? ?? ?? ?? 89 F0 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 89 4F 04 EB E2 89 3C 24 E8 ?? ?? ?? ?? 8D 76 00 EB DF }
	condition:
		$pattern
}

rule dyn_string_copy_cstr_3d286786b0df03149324e0841db854df {
	meta:
		aliases = "dyn_string_copy_cstr"
		size = "87"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 7D FC 8B 7D 0C 89 5D F4 89 75 F8 8B 75 08 89 3C 24 E8 ?? ?? ?? ?? 89 34 24 89 C3 89 44 24 04 E8 ?? ?? ?? ?? 31 D2 85 C0 74 17 89 7C 24 04 8B 46 08 89 04 24 E8 ?? ?? ?? ?? BA 01 00 00 00 89 5E 04 8B 5D F4 89 D0 8B 75 F8 8B 7D FC 89 EC 5D C3 }
	condition:
		$pattern
}

rule dyn_string_append_cstr_63c314db0ef3fb75182cda3cc79565be {
	meta:
		aliases = "dyn_string_append_cstr"
		size = "97"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 89 7D FC 8B 7D 0C 89 5D F4 8B 5D 08 89 75 F8 89 3C 24 E8 ?? ?? ?? ?? 8B 4B 04 89 1C 24 89 C6 01 C8 89 44 24 04 E8 ?? ?? ?? ?? 31 D2 85 C0 74 1C 89 7C 24 04 8B 53 08 8B 43 04 01 D0 89 04 24 E8 ?? ?? ?? ?? BA 01 00 00 00 01 73 04 8B 5D F4 89 D0 8B 75 F8 8B 7D FC 89 EC 5D C3 }
	condition:
		$pattern
}

rule pwait_7cd41b22cfd38600796c83bc1d121da8 {
	meta:
		aliases = "pwait"
		size = "227"
		objfiles = "pexecute@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 8B 15 ?? ?? ?? ?? 89 75 F8 8B 75 08 89 7D FC 8B 7D 0C 89 5D F4 4E 85 D2 0F 84 9C 00 00 00 85 F6 0F 88 94 00 00 00 A1 ?? ?? ?? ?? 39 C6 0F 8D 87 00 00 00 85 F6 75 05 83 F8 01 74 61 C1 E0 02 89 04 24 E8 ?? ?? ?? ?? 89 44 24 08 89 C3 A1 ?? ?? ?? ?? 89 44 24 04 A1 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 85 C0 74 67 8B 04 B3 89 07 89 1C 24 E8 ?? ?? ?? ?? 8D 5E 01 3B 1D ?? ?? ?? ?? 75 40 A1 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 31 D2 31 C0 89 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? EB 22 B9 01 00 00 00 89 7C 24 08 89 4C 24 04 89 14 24 E8 ?? ?? ?? ?? 85 C0 75 BE 8D 74 26 00 BB FF FF FF FF 89 D8 8B }
	condition:
		$pattern
}

rule htab_create_alloc_ex_91ab691db628e46fac473a822eed3cd3 {
	meta:
		aliases = "htab_create_alloc_ex"
		size = "180"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 8B 45 08 89 5D F4 BB 01 00 00 00 89 75 F8 89 7D FC E8 34 FA FF FF 89 5C 24 04 89 C7 C1 E0 04 8B B0 ?? ?? ?? ?? B8 3C 00 00 00 89 44 24 08 8B 45 18 89 04 24 FF 55 1C 85 C0 74 57 89 C3 8B 45 18 B9 04 00 00 00 89 4C 24 08 89 74 24 04 89 04 24 FF 55 1C 85 C0 89 43 0C 74 3C 8B 45 0C 89 73 10 89 7B 38 89 03 8B 45 10 89 43 04 8B 45 14 89 43 08 8B 45 18 89 43 2C 8B 45 1C 89 43 30 8B 45 20 89 43 34 89 D8 8B 75 F8 8B 5D F4 8B 7D FC 89 EC 5D C3 31 DB EB ED 8B 55 20 85 D2 74 F5 8B 45 18 89 5C 24 04 31 DB 89 04 24 FF 55 20 EB D5 }
	condition:
		$pattern
}

rule htab_create_alloc_e36488bc5dce9fe5eed6043e184eaf1e {
	meta:
		aliases = "htab_create_alloc"
		size = "152"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 8B 45 08 89 75 F8 89 7D FC 89 5D F4 E8 79 F9 FF FF C7 04 24 01 00 00 00 89 C7 C1 E0 04 8B B0 ?? ?? ?? ?? B8 3C 00 00 00 89 44 24 04 FF 55 18 85 C0 74 4A 89 C3 B8 04 00 00 00 89 44 24 04 89 34 24 FF 55 18 85 C0 89 43 0C 74 36 8B 45 0C 89 73 10 89 7B 38 89 03 8B 45 10 89 43 04 8B 45 14 89 43 08 8B 45 18 89 43 24 8B 45 1C 89 43 28 89 D8 8B 75 F8 8B 5D F4 8B 7D FC 89 EC 5D C3 31 DB EB ED 8B 45 1C 85 C0 74 F5 89 1C 24 31 DB FF 55 1C EB DC }
	condition:
		$pattern
}

rule xregerror_c9148e397aee5273c9db772a55e200ce {
	meta:
		aliases = "xregerror"
		size = "118"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 8B 45 08 89 7D FC 8B 7D 14 89 5D F4 89 75 F8 83 F8 10 77 57 8B 1C 85 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 85 FF 8D 70 01 74 17 39 FE 77 22 8B 55 10 89 74 24 08 89 5C 24 04 89 14 24 E8 ?? ?? ?? ?? 89 F0 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 8D 47 FF 89 44 24 08 8B 45 10 89 5C 24 04 89 04 24 E8 ?? ?? ?? ?? C6 00 00 EB D6 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule is_gnu_v3_mangled_dtor_667249b073bf79fd27ab73bbf901d58a {
	meta:
		aliases = "is_gnu_v3_mangled_dtor"
		size = "33"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 8B 45 08 8D 55 FC 8D 4D F8 E8 0C FF FF FF 31 D2 85 C0 74 03 8B 55 F8 C9 89 D0 C3 }
	condition:
		$pattern
}

rule is_gnu_v3_mangled_ctor_681515c9e9ed19a443ef100134f45b46 {
	meta:
		aliases = "is_gnu_v3_mangled_ctor"
		size = "33"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 8B 45 08 8D 55 FC 8D 4D F8 E8 DC FE FF FF 31 D2 85 C0 74 03 8B 55 FC C9 89 D0 C3 }
	condition:
		$pattern
}

rule xmemdup_21c1e765e6e023874b33dce3871a518d {
	meta:
		aliases = "xmemdup"
		size = "60"
		objfiles = "xmemdup@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 8B 45 10 89 5D F8 8B 5D 0C 89 75 FC 8B 75 08 C7 04 24 01 00 00 00 89 44 24 04 E8 ?? ?? ?? ?? 89 5D 10 8B 5D F8 89 75 0C 8B 75 FC 89 45 08 89 EC 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule cplus_demangle_v3_66ba2cb8a5115bd93769a112665f5f97 {
	meta:
		aliases = "cplus_demangle_v3"
		size = "22"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 8B 55 0C 8D 4D FC 8B 45 08 E8 1C FD FF FF C9 C3 }
	condition:
		$pattern
}

rule dyn_string_substring_dd3eeaf9a07fb9ac012c777b3ef61eaa {
	meta:
		aliases = "dyn_string_substring"
		size = "152"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 8B 55 14 89 5D F4 8B 5D 10 89 7D FC 8B 7D 08 89 75 F8 39 DA 7C 0A 8B 4D 0C 8B 41 04 39 C3 7E 0A E8 ?? ?? ?? ?? 90 8D 74 26 00 39 C2 7F F2 29 DA 89 55 F0 89 54 24 04 89 3C 24 E8 ?? ?? ?? ?? 31 D2 85 C0 74 3E 8B 4D F0 49 78 26 8B 75 F0 8D 5C 33 FF 90 8D B4 26 00 00 00 00 8B 75 0C 8B 47 08 8B 56 08 0F B6 14 1A 4B 88 14 08 49 83 F9 FF 75 E9 8B 55 F0 8B 47 08 C6 04 10 00 89 57 04 BA 01 00 00 00 8B 5D F4 89 D0 8B 75 F8 8B 7D FC 89 EC 5D C3 }
	condition:
		$pattern
}

rule xmalloc_failed_a15d4e8483302adf1558921b3c5adde6 {
	meta:
		aliases = "xmalloc_failed"
		size = "131"
		objfiles = "xmalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 A1 ?? ?? ?? ?? 85 C0 74 61 C7 04 24 00 00 00 00 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 29 C8 8B 15 ?? ?? ?? ?? B9 ?? ?? ?? ?? 80 3A 00 75 05 B9 ?? ?? ?? ?? 89 44 24 14 8B 45 08 89 54 24 08 BA ?? ?? ?? ?? 89 4C 24 0C 89 54 24 04 89 44 24 10 A1 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? C7 04 24 01 00 00 00 E8 ?? ?? ?? ?? 8D 76 00 C7 04 24 00 00 00 00 E8 ?? ?? ?? ?? 2D ?? ?? ?? ?? EB A0 }
	condition:
		$pattern
}

rule physmem_total_1277f06f0b998f94d7b0cee3eaf4159c {
	meta:
		aliases = "physmem_total"
		size = "98"
		objfiles = "physmem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 C7 04 24 55 00 00 00 E8 ?? ?? ?? ?? 50 DB 04 24 83 C4 04 C7 04 24 1E 00 00 00 DD 5D F8 E8 ?? ?? ?? ?? D9 EE 89 C2 DD 45 F8 DD E9 DF E0 9E 72 2A 52 DB 04 24 83 C4 04 DD E1 DF E0 9E 72 0C DD D9 DD 45 F8 DE C9 EB 13 8D 76 00 DD D8 8D B4 26 00 00 00 00 8D BC 27 00 00 00 00 C9 C3 }
	condition:
		$pattern
}

rule physmem_available_1a3dca6b972cd7e3305b3ad93c2f9ea7 {
	meta:
		aliases = "physmem_available"
		size = "95"
		objfiles = "physmem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 18 C7 04 24 56 00 00 00 E8 ?? ?? ?? ?? 50 DB 04 24 83 C4 04 DD 5D F8 C7 04 24 1E 00 00 00 E8 ?? ?? ?? ?? D9 EE 89 C2 DD 45 F8 DD E9 DF E0 9E 72 1A 52 DB 04 24 83 C4 04 DD E1 DF E0 DD D9 9E 72 0A DC 4D F8 C9 C3 90 8D 74 26 00 DD D8 E8 ?? ?? ?? ?? D8 0D ?? ?? ?? ?? C9 C3 }
	condition:
		$pattern
}

rule temp_file_7d090ad699c7826ed01e8ae585d44eb9 {
	meta:
		aliases = "temp_file"
		size = "245"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 28 85 C9 89 5D F4 89 CB 89 75 F8 89 7D FC 74 3B F6 C2 04 74 1B 8B 40 08 85 C0 74 23 31 D2 89 54 24 08 89 4C 24 04 89 04 24 E8 ?? ?? ?? ?? 89 C3 89 D8 8B 75 F8 8B 5D F4 8B 7D FC 89 EC 5D C3 89 0C 24 E8 ?? ?? ?? ?? 89 C3 EB E5 8B 40 08 85 C0 89 45 F0 74 65 8B 45 F0 89 04 24 E8 ?? ?? ?? ?? 83 F8 05 7E 18 8B 55 F0 B9 07 00 00 00 FC 8D 74 02 FA B8 ?? ?? ?? ?? 89 C7 F3 A6 74 53 8B 55 F0 BE ?? ?? ?? ?? 31 FF 89 74 24 04 89 7C 24 08 89 14 24 E8 ?? ?? ?? ?? 89 C6 31 C9 89 4C 24 04 89 34 24 E8 ?? ?? ?? ?? 85 C0 78 34 89 04 24 89 F3 E8 ?? ?? ?? ?? E9 76 FF FF FF C7 04 24 00 00 00 00 E8 ?? }
	condition:
		$pattern
}

rule remember_Btype_4a10e27486cd841def73c3880e42e866 {
	meta:
		aliases = "remember_Btype"
		size = "80"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 28 89 45 F0 8D 41 01 89 5D F4 89 75 F8 89 CE 89 7D FC 89 D7 89 04 24 E8 ?? ?? ?? ?? 89 74 24 08 89 7C 24 04 89 C3 89 04 24 E8 ?? ?? ?? ?? 8B 45 F0 C6 04 33 00 8B 50 0C 8B 45 08 89 1C 82 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 }
	condition:
		$pattern
}

rule d_expression_4521d2b57e0de1aaf096885f73baccad {
	meta:
		aliases = "d_expression"
		size = "589"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 28 89 5D F4 89 75 F8 89 7D FC 89 45 EC 8B 40 0C 0F B6 10 80 FA 4C 0F 84 32 01 00 00 80 FA 54 0F 84 4D 01 00 00 80 FA 73 75 0A 80 78 01 72 0F 84 92 01 00 00 8B 45 EC 8D 74 26 00 E8 7B FE FF FF 85 C0 89 C3 0F 84 91 00 00 00 8B 00 83 F8 28 75 6A 8B 43 04 8B 55 EC FC 8B 40 08 8B 4A 30 01 C8 83 E8 02 89 42 30 BA ?? ?? ?? ?? B8 03 00 00 00 8B 4B 04 89 D7 8B 31 89 4D E8 89 C1 F3 A6 0F 84 DE 00 00 00 8B 4D E8 8B 41 0C 83 F8 02 0F 84 F8 00 00 00 83 F8 03 74 60 48 89 F6 75 3E 8B 45 EC E8 56 FF FF FF 89 04 24 89 D9 BA 2B 00 00 00 8B 45 EC E8 E4 C1 FF FF EB 32 89 F6 83 F8 29 0F 84 4B 01 00 }
	condition:
		$pattern
}

rule byte_common_op_match_null_stri_a9b0ce52e6dab930c35873ebe103b7ee {
	meta:
		aliases = "byte_common_op_match_null_string_p"
		size = "232"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 28 89 5D F4 89 75 F8 89 CE 89 7D FC 89 C7 8B 00 89 45 F0 8D 58 01 0F B6 08 89 5D F0 80 F9 1D 77 3A 0F B6 C1 FF 24 85 ?? ?? ?? ?? 89 F1 0F B6 1B 8D 45 F0 E8 33 01 00 00 8D 0C 9E 88 45 E3 0F B6 01 24 03 3C 03 0F 84 83 00 00 00 80 7D E3 00 75 3A 8D 76 00 8D BC 27 00 00 00 00 31 C0 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 0F BE 43 01 0F B6 13 C1 E0 08 01 D0 78 E3 8D 44 03 02 89 45 F0 8D B6 00 00 00 00 8D BF 00 00 00 00 8B 45 F0 89 07 B8 01 00 00 00 EB C6 8D 4B 02 89 4D F0 0F BE 41 01 0F B6 53 02 C1 E0 08 01 C2 75 AF 89 5D F0 0F BE 43 01 0F B6 13 C1 E0 08 01 C2 8D 14 11 89 55 F0 EB C8 }
	condition:
		$pattern
}

rule d_bare_function_type_0d7f4232ce4983c64a01fda351aae492 {
	meta:
		aliases = "d_bare_function_type"
		size = "239"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 28 89 5D F4 89 C3 89 75 F8 89 D6 89 7D FC 8B 40 0C 80 38 4A 74 75 8D 55 F0 31 FF C7 45 F0 00 00 00 00 89 55 E0 0F B6 00 84 C0 74 2F 3C 45 74 2B 89 1C 24 E8 ?? ?? ?? ?? 85 C0 90 0F 84 7C 00 00 00 85 F6 0F 84 78 00 00 00 89 C7 8B 43 0C 31 F6 0F B6 00 84 C0 75 D5 8D 74 26 00 8B 45 F0 85 C0 74 5B 8B 50 08 85 D2 74 32 89 04 24 89 F9 BA 23 00 00 00 89 D8 E8 51 C4 FF FF 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 8D 74 26 00 40 BE 01 00 00 00 89 43 0C EB 80 90 8D 74 26 00 8B 50 04 83 3A 21 75 C6 8B 52 04 83 7A 10 09 75 BD 8B 42 04 29 43 30 31 C0 C7 45 F0 00 00 00 00 EB AC 31 C0 EB B9 89 C1 }
	condition:
		$pattern
}

rule d_print_cast_5ee28af183877a3bbd3a821ed957cf5f {
	meta:
		aliases = "d_print_cast"
		size = "291"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 28 89 5D F4 89 C3 89 75 F8 89 D6 89 7D FC 8B 52 04 83 3A 04 74 15 E8 E0 E7 FF FF 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 8D 76 00 8B 78 14 C7 40 14 00 00 00 00 8B 40 10 89 55 F0 89 45 EC 8D 45 EC 89 43 10 8B 46 04 8B 50 04 89 D8 E8 AA E7 FF FF 8B 53 04 8B 45 EC 85 D2 89 43 10 74 0C 8B 43 08 85 C0 75 48 3B 43 0C 72 63 BA 3C 00 00 00 89 D8 E8 35 E7 FF FF 8B 46 04 8B 50 08 89 D8 E8 78 E7 FF FF 8B 53 04 85 D2 74 51 8B 43 08 85 C0 74 07 80 7C 02 FF 3E 74 51 3B 43 0C 73 3E C6 04 10 3E 40 89 43 08 89 7B 14 E9 6E FF FF FF 80 7C 02 FF 3C 75 B1 3B 43 0C 73 49 C6 04 02 20 40 89 43 08 8B 53 }
	condition:
		$pattern
}

rule d_unqualified_name_40dce271bf268a361a039b9e9e8c5628 {
	meta:
		aliases = "d_unqualified_name"
		size = "378"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 28 89 75 F8 89 C6 89 5D F4 89 7D FC 8B 48 0C 0F B6 11 88 D0 2C 30 3C 09 76 41 88 D0 2C 61 3C 19 77 4C 89 F0 E8 A2 12 00 00 85 C0 89 C3 74 1C 83 38 28 75 17 8B 50 04 8B 46 30 8B 7A 08 83 C0 07 01 F8 89 46 30 8D B6 00 00 00 00 89 D8 8B 75 F8 8B 5D F4 8B 7D FC 89 EC 5D C3 90 8B 5D F4 89 F0 8B 7D FC 8B 75 F8 89 EC 5D E9 AD FE FF FF 80 EA 43 80 FA 01 76 04 31 DB EB D1 8B 7E 2C 85 FF 74 0B 8B 07 85 C0 74 66 83 F8 15 74 61 0F B6 11 89 C8 41 89 4E 0C 80 FA 43 74 5B 80 FA 44 75 D7 0F B6 50 01 83 C0 02 89 46 0C 80 FA 31 0F 84 B7 00 00 00 80 FA 32 0F 84 A2 00 00 00 80 FA 30 75 B6 C7 45 F0 }
	condition:
		$pattern
}

rule remember_Ktype_2b5e52d8586dd71fd2fd5abe3e93b260 {
	meta:
		aliases = "remember_Ktype"
		size = "152"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 28 89 75 F8 89 C6 89 7D FC 89 CF 89 5D F4 89 55 F0 8B 50 18 39 50 10 7C 23 85 D2 74 5E 8D 04 12 89 46 18 8D 04 D5 00 00 00 00 89 44 24 04 8B 46 08 89 04 24 E8 ?? ?? ?? ?? 89 46 08 8D 47 01 89 04 24 E8 ?? ?? ?? ?? 89 7C 24 08 89 C3 8B 45 F0 89 1C 24 89 44 24 04 E8 ?? ?? ?? ?? 8B 46 10 8B 56 08 C6 04 3B 00 89 1C 82 40 89 46 10 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 90 C7 40 18 05 00 00 00 C7 04 24 14 00 00 00 E8 ?? ?? ?? ?? 89 46 08 EB A9 }
	condition:
		$pattern
}

rule remember_type_cf0fe2d3bfba992be214157fb025d3fd {
	meta:
		aliases = "remember_type"
		size = "160"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 28 89 75 F8 89 C6 89 7D FC 89 CF 89 5D F4 8B 40 48 89 55 F0 85 C0 75 39 8B 56 24 39 56 20 7D 3E 8D 47 01 89 04 24 E8 ?? ?? ?? ?? 89 7C 24 08 89 C3 8B 45 F0 89 1C 24 89 44 24 04 E8 ?? ?? ?? ?? 8B 46 20 8B 56 04 C6 04 3B 00 89 1C 82 40 89 46 20 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 85 D2 74 21 8D 04 12 89 46 24 8D 04 D5 00 00 00 00 89 44 24 04 8B 46 04 89 04 24 E8 ?? ?? ?? ?? 89 46 04 EB 9D C7 46 24 03 00 00 00 C7 04 24 0C 00 00 00 E8 ?? ?? ?? ?? 89 46 04 EB 85 }
	condition:
		$pattern
}

rule d_print_expr_op_53e80552cd1cefbe8afa4f359ac38342 {
	meta:
		aliases = "d_print_expr_op"
		size = "151"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 28 89 75 F8 89 C6 89 7D FC 89 D7 89 5D F4 83 3A 28 74 18 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D E9 A7 E6 FF FF 8D B4 26 00 00 00 00 8B 40 04 85 C0 89 45 F0 74 58 8B 5F 04 8B 56 08 8B 4B 08 8D 04 0A 3B 46 0C 76 19 8B 4B 08 89 F0 8B 53 04 8B 75 F8 8B 5D F4 8B 7D FC 89 EC 5D E9 AC E5 FF FF 8B 45 F0 01 C2 8B 43 04 89 4C 24 08 89 14 24 89 44 24 04 E8 ?? ?? ?? ?? 8B 47 04 8B 40 08 01 46 08 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 8B 5A 04 EB B4 }
	condition:
		$pattern
}

rule cplus_demangle_type_9d67a5597dd3012fb12b4d6ca0a32262 {
	meta:
		aliases = "cplus_demangle_type"
		size = "902"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 28 89 75 F8 8B 75 08 89 5D F4 89 7D FC 8B 4E 0C 0F B6 11 80 FA 72 74 0A 80 FA 56 74 05 80 FA 4B 75 3E 31 C9 89 F0 8D 55 F0 E8 7D CD FF FF 85 C0 89 C3 75 0F 31 C0 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 89 34 24 E8 ?? ?? ?? ?? 89 03 8B 55 F0 89 F0 E8 B4 CE FF FF 85 C0 74 D9 8B 45 F0 EB D6 88 D0 2C 30 3C 4A 77 CC 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8D 51 01 89 56 0C 0F B6 41 01 3C 5F 0F 84 94 02 00 00 2C 30 3C 09 0F 87 BB 02 00 00 8B 46 0C 8D 48 01 89 4E 0C 0F B6 40 01 2C 30 3C 09 76 ED 29 D1 89 F0 E8 11 CB FF FF 85 C0 89 C3 74 13 8B 46 0C 0F B6 10 40 89 46 0C 80 FA 5F 0F 84 5D 02 00 00 }
	condition:
		$pattern
}

rule pex_get_times_706be8178c0ff352e5a9ccf91ac7d446 {
	meta:
		aliases = "pex_get_times"
		size = "215"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 28 89 75 F8 8B 75 08 89 5D F4 8B 5D 0C 89 7D FC 8B 46 20 85 C0 0F 84 8F 00 00 00 8B 46 24 85 C0 0F 84 A5 00 00 00 8B 46 18 39 D8 7C 45 89 DA 8B 7D 10 C1 E2 04 8B 76 24 83 FA 07 77 1E 89 D1 B8 01 00 00 00 FC C1 E9 02 F3 A5 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 8D 74 26 00 F7 C7 04 00 00 00 74 DA 8B 06 83 EA 04 83 C6 04 89 07 83 C7 04 EB CB 89 DA 8B 4D 10 29 C2 C1 E2 04 C1 E0 04 83 FA 07 8D 3C 08 76 14 F7 C7 04 00 00 00 74 0C C7 07 00 00 00 00 83 EA 04 83 C7 04 FC 89 D1 31 C0 C1 E9 02 F3 AB 8B 5E 18 EB 83 8D 45 EC 31 D2 89 04 24 8D 4D F0 89 F0 E8 4F FD FF FF 85 C0 0F 85 57 FF FF }
	condition:
		$pattern
}

rule pex_get_status_3fe2948e5b6553e092e1e0580739a9e0 {
	meta:
		aliases = "pex_get_status"
		size = "211"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 28 89 75 F8 8B 75 08 89 5D F4 8B 5D 0C 89 7D FC 8B 46 20 85 C0 0F 84 92 00 00 00 8B 46 18 39 D8 7C 49 8D 14 9D 00 00 00 00 8B 7D 10 83 FA 07 8B 76 20 77 1C 89 D1 BA 01 00 00 00 FC C1 E9 02 F3 A5 8B 5D F4 89 D0 8B 75 F8 8B 7D FC 89 EC 5D C3 F7 C7 04 00 00 00 74 DC 8B 06 83 EA 04 83 C6 04 89 07 83 C7 04 EB CD 8D 74 26 00 8B 55 10 29 C3 8D 3C 82 8D 04 9D 00 00 00 00 83 F8 07 76 1C F7 C7 04 00 00 00 74 14 C7 07 00 00 00 00 83 E8 04 83 C7 04 90 8D B4 26 00 00 00 00 89 C1 31 C0 FC C1 E9 02 F3 AB 8B 5E 18 E9 75 FF FF FF 8D 45 EC 31 D2 89 04 24 8D 4D F0 89 F0 E8 6C FC FF FF 31 D2 85 C0 }
	condition:
		$pattern
}

rule make_temp_file_b8a388b8ae776b5d5cae96669e0ec151 {
	meta:
		aliases = "make_temp_file"
		size = "191"
		objfiles = "make_temp_file@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 28 89 7D FC 8B 7D 08 89 5D F4 89 75 F8 E8 ?? ?? ?? ?? 85 FF 89 45 F0 0F 84 8E 00 00 00 89 3C 24 E8 ?? ?? ?? ?? 89 45 EC 8B 45 F0 89 04 24 E8 ?? ?? ?? ?? 8B 55 EC 89 C3 8D 44 10 09 89 04 24 E8 ?? ?? ?? ?? 89 C6 8B 45 F0 89 34 24 89 44 24 04 E8 ?? ?? ?? ?? 8D 04 1E C7 00 63 63 58 58 C7 40 04 58 58 58 58 C6 40 08 00 83 C0 08 89 7C 24 04 89 04 24 E8 ?? ?? ?? ?? 8B 55 EC 89 34 24 89 54 24 04 E8 ?? ?? ?? ?? 83 F8 FF 74 29 89 04 24 E8 ?? ?? ?? ?? 85 C0 75 1D 89 F0 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 8D 74 26 00 BF ?? ?? ?? ?? E9 68 FF FF FF E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule md5_finish_ctx_53655de48018784069d82ba97d4f6527 {
	meta:
		aliases = "md5_finish_ctx"
		size = "179"
		objfiles = "md5@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 28 89 7D FC 8B 7D 08 89 5D F4 8B 45 0C 89 75 F8 8B 77 18 8B 4F 10 89 45 EC 89 F0 01 C8 39 C6 89 47 10 76 03 FF 47 14 83 FE 37 76 76 C7 45 F0 78 00 00 00 29 75 F0 8B 55 F0 8D 5F 1C 8D 04 33 89 04 24 89 54 24 08 BA ?? ?? ?? ?? 89 54 24 04 E8 ?? ?? ?? ?? 8B 47 10 8B 4D F0 C1 E0 03 01 F1 89 44 0F 1C 8B 57 14 8B 47 10 C1 E2 03 C1 E8 1D 09 C2 89 54 0B 04 83 C1 08 89 7C 24 08 89 1C 24 89 4C 24 04 E8 ?? ?? ?? ?? 8B 45 EC 89 7D 08 8B 5D F4 8B 75 F8 8B 7D FC 89 45 0C 89 EC 5D E9 ?? ?? ?? ?? C7 45 F0 38 00 00 00 29 75 F0 EB 88 }
	condition:
		$pattern
}

rule xre_search_3c535719c2192e008df285d856e58653 {
	meta:
		aliases = "xre_search"
		size = "70"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 28 8B 45 1C 8B 55 10 89 44 24 1C 8B 45 18 89 54 24 20 89 54 24 10 89 44 24 18 8B 45 14 89 44 24 14 8B 45 0C 89 44 24 0C 31 C0 89 44 24 08 31 C0 89 44 24 04 8B 45 08 89 04 24 E8 ?? ?? ?? ?? C9 C3 }
	condition:
		$pattern
}

rule pexecute_ab4bf03c815f52a07ff460b8c950cd23 {
	meta:
		aliases = "pexecute"
		size = "246"
		objfiles = "pexecute@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 38 89 5D F4 8B 5D 20 89 75 F8 8B 75 18 89 7D FC 8B 7D 1C F6 C3 01 0F 84 97 00 00 00 A1 ?? ?? ?? ?? 85 C0 0F 85 A6 00 00 00 8B 45 14 C7 04 24 02 00 00 00 89 44 24 08 8B 45 10 89 44 24 04 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 31 C0 A3 ?? ?? ?? ?? 89 D8 83 E0 04 83 F8 01 8D 45 F0 19 D2 89 44 24 18 31 C0 F7 D2 89 44 24 14 31 C0 83 E2 02 89 44 24 10 8B 45 0C D1 EB 83 E3 01 09 DA 89 54 24 04 89 44 24 0C 8B 45 08 89 44 24 08 A1 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 85 C0 75 47 A1 ?? ?? ?? ?? 40 A3 ?? ?? ?? ?? 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 A1 ?? ?? ?? ?? 85 C0 75 93 B8 FF FF FF FF C7 06 }
	condition:
		$pattern
}

rule pex_input_pipe_ca8c1fba213d60d562c09baf616c2681 {
	meta:
		aliases = "pex_input_pipe"
		size = "201"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 38 89 7D FC 8B 7D 08 89 5D F4 89 75 F8 8B 57 18 85 D2 7F 05 F6 07 02 75 22 E8 ?? ?? ?? ?? 31 F6 C7 00 16 00 00 00 89 F0 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 8D B6 00 00 00 00 8B 47 0C 85 C0 7F D7 8B 47 10 85 C0 75 D0 31 DB 8B 57 3C 83 7D 0C 00 8D 45 EC 89 44 24 04 0F 95 C3 31 F6 89 5C 24 08 89 3C 24 FF 52 14 85 C0 78 BA 8B 45 F0 8B 57 3C 89 5C 24 08 89 3C 24 89 44 24 04 FF 52 1C 85 C0 89 C6 74 08 8B 45 EC 89 47 0C EB 98 E8 ?? ?? ?? ?? 8B 57 3C 89 C3 8B 00 89 3C 24 89 45 E0 8B 45 EC 89 44 24 04 FF 52 0C 8B 45 F0 8B 57 3C 89 3C 24 89 44 24 04 FF 52 0C 8B 45 E0 89 03 E9 62 FF FF }
	condition:
		$pattern
}

rule internal_cplus_demangle_677aa06d6102c52f7ab062c3d889beb3 {
	meta:
		aliases = "internal_cplus_demangle"
		size = "1606"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 48 89 5D F4 89 C3 89 75 F8 8B 4B 30 89 7D FC 8B 40 28 89 55 E0 8B 53 2C 89 4D D4 C7 43 2C 00 00 00 00 89 45 CC 8B 43 38 89 55 D0 C7 43 28 00 00 00 00 C7 43 38 00 00 00 00 89 45 D8 8B 45 E0 C7 43 3C 00 00 00 00 85 C0 75 27 31 C0 8B 4D CC 8B 55 D0 8B 75 F8 8B 7D FC 89 4B 28 8B 4D D4 89 53 2C 8B 55 D8 89 4B 30 89 53 38 8B 5D F4 89 EC 5D C3 80 38 00 74 D4 8D 45 E4 E8 1D EE FF FF F7 03 00 03 00 00 0F 85 88 01 00 00 8B 55 E0 89 55 C8 89 14 24 E8 ?? ?? ?? ?? 83 F8 06 89 45 C4 0F 87 8D 01 00 00 83 7D C4 0A 0F 87 DB 01 00 00 F7 03 00 38 00 00 0F 85 6B 02 00 00 8B 45 C8 89 45 DC 8D 74 26 }
	condition:
		$pattern
}

rule string_append_template_idx_472ad75cf9222572c078c5ba63b1ee0d {
	meta:
		aliases = "string_append_template_idx"
		size = "57"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 48 89 75 FC BE ?? ?? ?? ?? 89 5D F8 89 C3 89 74 24 04 8D 75 D7 89 54 24 08 89 34 24 E8 ?? ?? ?? ?? 89 F2 89 D8 E8 71 FF FF FF 8B 5D F8 8B 75 FC 89 EC 5D C3 }
	condition:
		$pattern
}

rule make_relative_prefix_3aa2a21539457e9d18478188e558ee91 {
	meta:
		aliases = "make_relative_prefix"
		size = "891"
		objfiles = "make_relative_prefix@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 58 89 5D F4 8B 5D 08 89 75 F8 89 7D FC 85 DB 74 0E 8B 45 0C 85 C0 74 07 8B 45 10 85 C0 75 11 31 FF 89 F8 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 89 1C 24 E8 ?? ?? ?? ?? 39 C3 0F 84 15 02 00 00 89 1C 24 E8 ?? ?? ?? ?? 85 C0 89 C3 74 D1 8D 55 F0 E8 95 FE FF FF 8D 55 EC 89 45 D0 8B 45 0C E8 87 FE FF FF 89 1C 24 89 45 D4 E8 ?? ?? ?? ?? 8B 75 D4 85 F6 74 A9 8B 5D D0 85 DB 74 A2 8B 55 F0 89 D7 4F 3B 7D EC 89 55 C8 89 7D F0 75 42 85 FF 0F 8E BF 02 00 00 BE 01 00 00 00 EB 0A 89 F3 8D 76 01 3B 75 C8 74 21 8B 4D D0 8D 5E FF 8B 44 B1 FC 8B 4D D4 8B 54 B1 FC 89 04 24 89 54 24 04 E8 ?? ?? ?? }
	condition:
		$pattern
}

rule mkstemps_0e4e8f0b9dc6293ff3478293b89c756e {
	meta:
		aliases = "mkstemps"
		size = "688"
		objfiles = "mkstemps@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 58 8B 45 08 89 5D F4 8B 5D 0C 89 75 F8 89 7D FC 89 04 24 E8 ?? ?? ?? ?? 89 C2 8D 43 06 39 C2 7D 12 B8 FF FF FF FF 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 8B 45 08 29 DA B9 06 00 00 00 FC 01 C2 B8 ?? ?? ?? ?? 89 55 C4 83 EA 06 89 C7 89 55 C8 89 D6 F3 A6 75 CB 31 C0 89 44 24 04 8D 45 EC 89 04 24 E8 ?? ?? ?? ?? 8B 5D F0 8B 45 EC 89 DE C1 FE 1F 99 0F A4 DE 10 C1 E3 10 31 D6 31 C3 E8 ?? ?? ?? ?? 8B 7D C4 C7 45 CC 00 00 00 00 99 31 C3 8B 45 C4 31 D6 8B 55 C4 01 1D ?? ?? ?? ?? 11 35 ?? ?? ?? ?? 83 E8 05 83 EA 04 83 EF 03 89 45 D0 8B 45 C4 89 55 D4 8B 55 C4 89 7D D8 83 E8 02 4A 89 45 DC }
	condition:
		$pattern
}

rule get_run_time_93d72bcf6640e7b327f0bd1bcab443a9 {
	meta:
		aliases = "get_run_time"
		size = "51"
		objfiles = "getruntime@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 58 8D 45 B8 89 44 24 04 C7 04 24 00 00 00 00 E8 ?? ?? ?? ?? 8B 55 B8 8B 45 C0 8B 4D BC 01 D0 8B 55 C4 69 C0 40 42 0F 00 C9 01 CA 01 D0 C3 }
	condition:
		$pattern
}

rule pex_unix_wait_c0e052d44158acbf4b1d6f9929822d97 {
	meta:
		aliases = "pex_unix_wait"
		size = "178"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 78 8B 45 18 89 5D F4 8B 5D 14 89 75 F8 8B 75 0C 89 7D FC 8B 7D 10 85 C0 75 49 85 DB 74 5D 8D 45 AC 31 C9 89 44 24 0C 89 4C 24 08 89 7C 24 04 89 34 24 E8 ?? ?? ?? ?? 89 C2 8B 45 AC 89 03 8B 45 B0 89 43 04 8B 45 B4 89 43 08 8B 45 B8 89 43 0C 31 C0 85 D2 78 3B 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 B8 0F 00 00 00 89 44 24 04 89 34 24 E8 ?? ?? ?? ?? 85 DB 75 A6 8D 76 00 31 DB 89 5C 24 08 89 7C 24 04 89 34 24 E8 ?? ?? ?? ?? 89 C2 EB BF E8 ?? ?? ?? ?? 8B 10 8B 45 20 89 10 8B 45 1C C7 00 ?? ?? ?? ?? B8 FF FF FF FF EB A9 }
	condition:
		$pattern
}

rule htab_hash_string_6d4541ddfe157148946b604f7192cb6d {
	meta:
		aliases = "htab_hash_string"
		size = "63"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 53 31 DB 0F B6 10 84 D2 74 2A 89 C1 8D B4 26 00 00 00 00 8D BC 27 00 00 00 00 89 D8 0F B6 D2 C1 E0 05 01 D8 8D 04 43 8D 5C 10 8F 0F B6 51 01 41 84 D2 75 E6 89 D8 5B 5D C3 }
	condition:
		$pattern
}

rule fibheap_empty_250e03f58ed12e8208df571933a0a5b8 {
	meta:
		aliases = "fibheap_empty"
		size = "18"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 5D 8B 00 85 C0 0F 94 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule htab_size_d99500dab1bf5ed437b51a1ab8ebde6c {
	meta:
		aliases = "htab_size"
		size = "11"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 5D 8B 40 10 C3 }
	condition:
		$pattern
}

rule floatformat_is_valid_a246bafe27a0a0937d9bffc8c78d8a46 {
	meta:
		aliases = "floatformat_is_valid"
		size = "12"
		objfiles = "floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 5D 8B 48 2C FF E1 }
	condition:
		$pattern
}

rule set_cplus_marker_for_demanglin_37b7582122266d85d5c3d5887fd8574a {
	meta:
		aliases = "set_cplus_marker_for_demangling"
		size = "13"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 5D A2 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule hash_pointer_1b88f5bc1b391315e06646a1297ffc83 {
	meta:
		aliases = "hash_pointer"
		size = "11"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 5D C1 F8 03 C3 }
	condition:
		$pattern
}

rule xre_compile_fastmap_a8d19d00bceb1f2bd1da52fecf382f15 {
	meta:
		aliases = "xre_compile_fastmap"
		size = "12"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 5D E9 64 FC FF FF }
	condition:
		$pattern
}

rule splay_tree_min_0e40d0b8278c25ab5b051f8d3fb493f3 {
	meta:
		aliases = "splay_tree_min"
		size = "29"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 10 85 D2 75 06 EB 0B 89 F6 89 C2 8B 42 08 85 C0 75 F7 5D 89 D0 C3 }
	condition:
		$pattern
}

rule splay_tree_max_d85fbcc6bb60a637776de4c7d78b2796 {
	meta:
		aliases = "splay_tree_max"
		size = "29"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 10 85 D2 75 06 EB 0B 89 F6 89 C2 8B 42 0C 85 C0 75 F7 5D 89 D0 C3 }
	condition:
		$pattern
}

rule fibheap_min_key_796e7d26098f5c93982656b2c3d30b9d {
	meta:
		aliases = "fibheap_min_key"
		size = "20"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 50 04 31 C0 85 D2 74 03 8B 42 10 5D C3 }
	condition:
		$pattern
}

rule fibheap_min_f46a1b8e89b725df86d63cc658d58c79 {
	meta:
		aliases = "fibheap_min"
		size = "20"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 50 04 31 C0 85 D2 74 03 8B 42 14 5D C3 }
	condition:
		$pattern
}

rule cplus_demangle_fill_name_6ab25bb1874d4fbac7bd567709ce6bee {
	meta:
		aliases = "cplus_demangle_fill_name"
		size = "52"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 55 0C 8B 4D 10 85 C0 74 20 85 D2 74 1C 85 C9 74 18 C7 00 00 00 00 00 89 50 04 89 48 08 B8 01 00 00 00 5D C3 90 8D 74 26 00 5D 31 C0 C3 }
	condition:
		$pattern
}

rule cplus_demangle_fill_extended_o_c9c10e21dce82be31ea2fdeabe3ff0a7 {
	meta:
		aliases = "cplus_demangle_fill_extended_operator"
		size = "52"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 55 0C 8B 4D 10 85 C0 74 20 85 D2 78 1C 85 C9 74 18 C7 00 29 00 00 00 89 50 04 89 48 08 B8 01 00 00 00 5D C3 90 8D 74 26 00 5D 31 C0 C3 }
	condition:
		$pattern
}

rule md5_init_ctx_3dfb48858e78573e2c6125f04b12af26 {
	meta:
		aliases = "md5_init_ctx"
		size = "56"
		objfiles = "md5@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 C7 00 01 23 45 67 C7 40 04 89 AB CD EF C7 40 08 FE DC BA 98 C7 40 0C 76 54 32 10 C7 40 14 00 00 00 00 C7 40 10 00 00 00 00 C7 40 18 00 00 00 00 5D C3 }
	condition:
		$pattern
}

rule htab_collisions_78fb9645ffa49e9270f45004df35f63f {
	meta:
		aliases = "htab_collisions"
		size = "44"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 D9 EE 8B 48 1C 85 C9 74 1B DD D8 8B 40 20 31 D2 52 31 D2 50 DF 2C 24 83 C4 08 52 51 DF 2C 24 83 C4 08 DE F9 5D C3 }
	condition:
		$pattern
}

rule eq_pointer_47d703854f6c51f6fc3e46f479931816 {
	meta:
		aliases = "eq_pointer"
		size = "17"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 0C 39 45 08 5D 0F 94 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule pex_unix_close_d0a838e17f26e2f85d87f03e21452947 {
	meta:
		aliases = "pex_unix_pipe, pex_unix_close"
		size = "15"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 0C 89 45 08 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pex_unix_open_read_59f1924bb8bcb84901ae878cd4b06c9e {
	meta:
		aliases = "pex_unix_open_read"
		size = "22"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 0C C7 45 0C 00 00 00 00 89 45 08 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pex_unix_fdopenr_286d3d342a9cfdbf22192c7adf0402d7 {
	meta:
		aliases = "pex_unix_fdopenr"
		size = "22"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 0C C7 45 0C ?? ?? ?? ?? 89 45 08 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pex_unix_open_write_ccaedc3e44f8d8382da30e9b3c0b2edf {
	meta:
		aliases = "pex_unix_open_write"
		size = "29"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 0C C7 45 10 B6 01 00 00 C7 45 0C 41 02 00 00 89 45 08 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule lbasename_f84f143bf578e1a90de9adf09ce14f7f {
	meta:
		aliases = "lbasename"
		size = "50"
		objfiles = "lbasename@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 4D 08 0F B6 11 89 C8 84 D2 75 0A EB 1F 41 0F B6 11 84 D2 74 17 80 FA 2F 8D 74 26 00 75 EF 8D 41 01 89 C1 0F B6 11 84 D2 75 EB 89 F6 5D C3 }
	condition:
		$pattern
}

rule cplus_demangle_init_info_0b4b81b0ea09f873c618b7bc0e0b3ea4 {
	meta:
		aliases = "cplus_demangle_init_info"
		size = "77"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 4D 08 53 8B 5D 10 8B 45 14 8D 14 19 89 50 04 8B 55 0C 89 08 89 48 0C C7 40 14 00 00 00 00 89 50 08 8D 14 1B 89 50 18 89 58 24 C7 40 20 00 00 00 00 C7 40 28 00 00 00 00 C7 40 2C 00 00 00 00 C7 40 30 00 00 00 00 5B 5D C3 }
	condition:
		$pattern
}

rule md5_read_ctx_957115bc852bb54006a4f68afa69d1a8 {
	meta:
		aliases = "md5_read_ctx"
		size = "33"
		objfiles = "md5@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 4D 08 8B 45 0C 8B 11 89 10 8B 51 04 89 50 04 8B 51 08 89 50 08 8B 51 0C 89 50 0C 5D C3 }
	condition:
		$pattern
}

rule htab_elements_7cbe7d2f81c47dbe2243ef1bfe9e4fe0 {
	meta:
		aliases = "htab_elements"
		size = "16"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 55 08 5D 8B 42 14 8B 4A 18 29 C8 C3 }
	condition:
		$pattern
}

rule dyn_string_clear_917cf17530e30ffc8c881f2ffea6ef23 {
	meta:
		aliases = "dyn_string_clear"
		size = "21"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 55 08 8B 42 08 C6 00 00 C7 42 04 00 00 00 00 5D C3 }
	condition:
		$pattern
}

rule htab_set_functions_ex_4f0394428f3848eb87659fa79a610c1e {
	meta:
		aliases = "htab_set_functions_ex"
		size = "43"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 55 08 8B 45 0C 89 02 8B 45 10 89 42 04 8B 45 14 89 42 08 8B 45 18 89 42 2C 8B 45 1C 89 42 30 8B 45 20 89 42 34 5D C3 }
	condition:
		$pattern
}

rule cplus_demangle_fill_component_86019803b61255e073d8fba7a968f193 {
	meta:
		aliases = "cplus_demangle_fill_component"
		size = "82"
		objfiles = "cp_demint@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 55 08 8B 45 0C 8B 4D 14 85 D2 74 05 83 F8 32 76 0B 5D 31 C0 C3 8D B4 26 00 00 00 00 FF 24 85 ?? ?? ?? ?? 85 C9 8D B4 26 00 00 00 00 75 E3 8D B4 26 00 00 00 00 8D BC 27 00 00 00 00 89 02 8B 45 10 89 4A 08 89 42 04 B8 01 00 00 00 5D C3 }
	condition:
		$pattern
}

rule cplus_demangle_fill_ctor_fd9351d79b9f14105e0d1f0273f8d9fa {
	meta:
		aliases = "cplus_demangle_fill_ctor"
		size = "43"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 55 08 8B 4D 10 85 D2 74 1A 85 C9 74 16 8B 45 0C C7 02 06 00 00 00 89 4A 08 89 42 04 B8 01 00 00 00 5D C3 5D 31 C0 C3 }
	condition:
		$pattern
}

rule cplus_demangle_fill_dtor_803e6db0bdcee8fa32b49b7d2f37a77a {
	meta:
		aliases = "cplus_demangle_fill_dtor"
		size = "43"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 55 08 8B 4D 10 85 D2 74 1A 85 C9 74 16 8B 45 0C C7 02 07 00 00 00 89 4A 08 89 42 04 B8 01 00 00 00 5D C3 5D 31 C0 C3 }
	condition:
		$pattern
}

rule splay_tree_foreach_e43f40d7ef0755096a7668cc5485f810 {
	meta:
		aliases = "splay_tree_foreach"
		size = "23"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 55 10 8B 45 08 8B 4D 0C 89 55 08 8B 10 5D E9 69 FB FF FF }
	condition:
		$pattern
}

rule siginterrupt_70cabeae6e589cf89bed10bb70581521 {
	meta:
		aliases = "siginterrupt"
		size = "112"
		objfiles = "sigintr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 F5 31 F6 53 89 FB 48 81 EC A8 00 00 00 48 89 E2 E8 ?? ?? ?? ?? 85 C0 78 46 85 ED 74 19 89 DE BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 A4 24 88 00 00 00 FF FF FF EF EB 17 89 DE BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 8C 24 88 00 00 00 00 00 00 10 31 D2 48 89 E6 89 DF E8 ?? ?? ?? ?? 31 D2 85 C0 79 03 83 CA FF 48 81 C4 A8 00 00 00 89 D0 5B 5D C3 }
	condition:
		$pattern
}

rule daemon_25b2f2882ca3703964ede2a9199a055f {
	meta:
		aliases = "daemon"
		size = "151"
		objfiles = "daemon@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 F5 53 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 83 F8 FF 74 78 85 C0 75 12 E8 ?? ?? ?? ?? FF C0 74 6B E8 ?? ?? ?? ?? 85 C0 74 07 31 FF E8 ?? ?? ?? ?? 85 DB 75 0A BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 ED 75 4E 31 D2 31 C0 BE 02 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 FF 89 C3 74 34 31 F6 89 C7 E8 ?? ?? ?? ?? BE 01 00 00 00 89 DF E8 ?? ?? ?? ?? BE 02 00 00 00 89 DF E8 ?? ?? ?? ?? 83 FB 02 7E 0E 89 DF E8 ?? ?? ?? ?? EB 05 83 C8 FF EB 02 31 C0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule __GI_getrpcbynumber_9c650742e7d04edd7e60097b9f5dc3ef {
	meta:
		aliases = "getrpcbynumber, __GI_getrpcbynumber"
		size = "60"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 FD 53 31 DB 48 83 EC 08 E8 54 FC FF FF 48 85 C0 74 20 31 FF E8 ?? ?? ?? ?? EB 05 39 6B 10 74 0D E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 75 EE E8 ?? ?? ?? ?? 41 59 48 89 D8 5B 5D C3 }
	condition:
		$pattern
}

rule __GI___sigpause_15f9dffda02237f5b27459f52ff51dbe {
	meta:
		aliases = "__sigpause, __GI___sigpause"
		size = "101"
		objfiles = "sigpause@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 FD 53 48 81 EC 88 00 00 00 85 F6 74 20 31 F6 31 FF 48 89 E2 E8 ?? ?? ?? ?? 85 C0 78 39 89 EE 48 89 E7 E8 ?? ?? ?? ?? 85 C0 79 21 EB 29 89 FD 48 8D 44 24 08 BA 0E 00 00 00 48 89 2C 24 48 C7 00 00 00 00 00 48 83 C0 08 FF CA 79 F1 48 89 E7 E8 ?? ?? ?? ?? EB 03 83 C8 FF 48 81 C4 88 00 00 00 5B 5D C3 }
	condition:
		$pattern
}

rule pthread_onexit_process_e16c9f5d90c480364fdca23481ccbe06 {
	meta:
		aliases = "pthread_onexit_process"
		size = "145"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 FD 53 48 81 EC B8 00 00 00 83 3D ?? ?? ?? ?? 00 78 73 E8 05 FE FF FF 48 89 C3 48 89 04 24 C7 44 24 08 02 00 00 00 89 6C 24 10 8B 3D ?? ?? ?? ?? 48 89 E6 BA A8 00 00 00 E8 ?? ?? ?? ?? 48 FF C0 75 0A E8 ?? ?? ?? ?? 83 38 04 74 DE 48 89 DF E8 A5 FF FF FF 48 3B 1D ?? ?? ?? ?? 75 28 8B 3D ?? ?? ?? ?? BA 00 00 00 80 31 F6 E8 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 48 C7 05 ?? ?? ?? ?? 00 00 00 00 48 81 C4 B8 00 00 00 5B 5D C3 }
	condition:
		$pattern
}

rule __GI__exit_74daa264a2f2a971f261a936c8472ec2 {
	meta:
		aliases = "_exit, __GI__exit"
		size = "42"
		objfiles = "_exit@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 FD 53 48 83 EC 08 48 63 FD B8 3C 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 EB E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 EB DE }
	condition:
		$pattern
}

rule setrpcent_61c778b365faeab435a20aa013b29292 {
	meta:
		aliases = "__GI_setrpcent, setrpcent"
		size = "79"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 FD 53 48 83 EC 08 E8 AD FD FF FF 48 85 C0 48 89 C3 74 35 48 8B 38 48 85 FF 75 14 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 03 EB 05 E8 ?? ?? ?? ?? 48 8B 7B 08 E8 ?? ?? ?? ?? 09 6B 14 48 C7 43 08 00 00 00 00 41 58 5B 5D C3 }
	condition:
		$pattern
}

rule __GI_ldexp_690a065c84e97804d90a72d74fcb52ac {
	meta:
		aliases = "ldexp, __GI_ldexp"
		size = "115"
		objfiles = "s_ldexp@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 89 FD 53 48 83 EC 08 F2 0F 11 04 24 48 8B 1C 24 E8 ?? ?? ?? ?? 85 C0 74 4C 48 89 1C 24 0F 57 C9 66 0F 12 04 24 66 0F 2E C1 7A 02 74 38 89 EF E8 ?? ?? ?? ?? F2 0F 11 04 24 48 8B 1C 24 E8 ?? ?? ?? ?? 85 C0 74 14 48 89 1C 24 0F 57 C9 66 0F 12 04 24 66 0F 2E C1 75 0D 7A 0B E8 ?? ?? ?? ?? C7 00 22 00 00 00 48 89 1C 24 66 0F 12 04 24 58 5B 5D C3 }
	condition:
		$pattern
}

rule _dl_dprintf_ed004032bad774fb0aa8d3e4b19f9e38 {
	meta:
		aliases = "_dl_dprintf"
		size = "900"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 89 FD 53 48 89 F3 48 83 C4 80 48 85 F6 48 89 54 24 D8 48 89 4C 24 E0 4C 89 44 24 E8 4C 89 4C 24 F0 0F 84 55 03 00 00 48 8B 35 ?? ?? ?? ?? 45 31 C9 49 83 C8 FF 41 BA 22 00 00 00 BA 03 00 00 00 31 FF B8 09 00 00 00 0F 05 48 3D 00 F0 FF FF 76 0B F7 D8 89 05 ?? ?? ?? ?? 4C 89 C0 48 89 05 ?? ?? ?? ?? 48 05 00 10 00 00 48 3D FF 0F 00 00 77 40 BA 1D 00 00 00 BE ?? ?? ?? ?? 48 63 FD B8 01 00 00 00 0F 05 48 3D 00 F0 FF FF 76 08 F7 D8 89 05 ?? ?? ?? ?? BF 14 00 00 00 B8 3C 00 00 00 0F 05 48 3D 00 F0 FF FF 76 08 F7 D8 89 05 ?? ?? ?? ?? 4C 8D 43 FF 4C 8B 0D ?? ?? ?? ?? 4C 89 C2 48 FF C2 80 3A 00 75 F8 }
	condition:
		$pattern
}

rule fputc_unlocked_99c41ac40abc6c97904900a096c73867 {
	meta:
		aliases = "putc_unlocked, __GI___fputc_unlocked, __fputc_unlocked, __GI_putc_unlocked, fputc_unlocked"
		size = "192"
		objfiles = "fputc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 FD 53 48 89 F3 48 83 EC 18 48 8B 46 18 48 3B 46 30 73 0F 40 88 38 48 FF C0 48 89 46 18 E9 8C 00 00 00 0F B7 06 25 C0 00 00 00 3D C0 00 00 00 74 11 BE 80 00 00 00 48 89 DF E8 ?? ?? ?? ?? 85 C0 75 72 83 7B 04 FE 74 66 48 8B 43 10 48 3B 43 08 74 40 48 3B 43 18 75 0D 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 75 4F 48 8B 43 18 40 88 28 48 FF C0 F6 43 01 01 48 89 43 18 74 35 40 80 FD 0A 75 2F 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 74 22 48 FF 4B 18 EB 22 48 8D 74 24 17 BA 01 00 00 00 48 89 DF 40 88 6C 24 17 E8 ?? ?? ?? ?? 48 85 C0 74 06 40 0F B6 C5 EB 03 83 C8 FF 48 83 C4 18 5B 5D C3 }
	condition:
		$pattern
}

rule ptrace_7506866e8f06b061a6c220c463cc722f {
	meta:
		aliases = "ptrace"
		size = "206"
		objfiles = "ptrace@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 FD 89 FF 53 48 81 EC D8 00 00 00 48 8D 84 24 F0 00 00 00 C7 04 24 10 00 00 00 48 89 4C 24 38 48 89 74 24 28 48 89 54 24 30 4C 8D 54 24 18 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 48 83 C0 08 48 8B 4C 24 10 8B 30 48 8B 44 24 10 C7 04 24 18 00 00 00 48 83 C1 18 48 83 C0 10 48 63 F6 48 8B 10 8D 45 FF C7 04 24 20 00 00 00 83 F8 02 B8 65 00 00 00 4C 0F 47 11 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 48 89 D9 48 F7 D0 48 C1 E8 3F 85 ED 0F 95 C2 84 D0 74 15 83 FD 03 77 10 E8 ?? ?? ?? ?? C7 00 00 00 00 00 48 8B 4C 24 18 48 81 C4 D8 00 00 00 }
	condition:
		$pattern
}

rule string_clear_2f1a8f11dbb3d0b9b1b2b37397d4d7e9 {
	meta:
		aliases = "string_clear"
		size = "10"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 8B 10 89 E5 5D 89 50 04 C3 }
	condition:
		$pattern
}

rule xre_set_syntax_a7941faee6bb093d86a82aa7ff5b4659 {
	meta:
		aliases = "xre_set_syntax"
		size = "19"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) A1 ?? ?? ?? ?? 89 E5 8B 55 08 5D 89 15 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule flush_out_5b195635981aaf0ded727c098112fed6 {
	meta:
		aliases = "flush_out"
		size = "95"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) B8 00 00 00 00 BA 00 00 00 80 48 89 FD 53 48 83 EC 08 FF CE 48 8B 4F 30 48 0F 45 D0 48 8B 47 20 48 29 C8 48 83 E8 04 09 D0 0F C8 89 01 48 8B 77 18 48 8B 57 20 48 8B 3F 48 29 F2 89 D3 FF 55 10 31 D2 39 D8 75 12 48 8B 45 18 B2 01 48 89 45 30 48 83 C0 04 48 89 45 20 5E 5B 5D 89 D0 C3 }
	condition:
		$pattern
}

rule __GI_nanf_0ced4d1dfcd68a7269be4badcb51e6e6 {
	meta:
		aliases = "nanf, __GI_nanf"
		size = "112"
		objfiles = "nan@libm.a"
	strings:
		$pattern = { ( CC | 55 ) B8 00 00 C0 7F 48 89 E5 41 55 49 89 FD 41 54 53 48 83 EC 08 80 3F 00 74 43 E8 ?? ?? ?? ?? 48 83 C0 24 48 89 E3 4C 89 EA 48 83 E0 F0 BE ?? ?? ?? ?? 48 29 C4 31 C0 4C 8D 64 24 0F 49 83 E4 F0 4C 89 E7 E8 ?? ?? ?? ?? 31 F6 4C 89 E7 E8 ?? ?? ?? ?? F3 0F 11 45 E4 8B 45 E4 48 89 DC 89 45 E4 F3 0F 10 45 E4 48 8D 65 E8 5B 41 5C 41 5D C9 C3 }
	condition:
		$pattern
}

rule floatformat_always_valid_77015b1739d67c83c0e1e4a93a716f3d {
	meta:
		aliases = "floatformat_always_valid"
		size = "10"
		objfiles = "floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) B8 01 00 00 00 89 E5 5D C3 }
	condition:
		$pattern
}

rule fibheap_new_e2d3beac2c1d751f4023c30cce9b8b45 {
	meta:
		aliases = "fibheap_new"
		size = "29"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) B8 0C 00 00 00 89 E5 83 EC 08 89 44 24 04 C7 04 24 01 00 00 00 E8 ?? ?? ?? ?? C9 C3 }
	condition:
		$pattern
}

rule pthread_setcanceltype_fa6f39293518a6c0e250a1b4c82cc9d4 {
	meta:
		aliases = "__GI_pthread_setcanceltype, pthread_setcanceltype"
		size = "76"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) B8 16 00 00 00 89 FD 53 48 89 F3 48 83 EC 08 83 FF 01 77 33 E8 48 FE FF FF 48 85 DB 48 89 C2 74 06 0F BE 40 79 89 03 80 7A 7A 00 40 88 6A 79 74 14 66 81 7A 78 00 01 75 0C 48 89 E6 48 83 CF FF E8 ?? ?? ?? ?? 31 C0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule pthread_setcancelstate_89ee08c4e1559f43cdece5e9a85fc3fe {
	meta:
		aliases = "__GI_pthread_setcancelstate, pthread_setcancelstate"
		size = "76"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) B8 16 00 00 00 89 FD 53 48 89 F3 48 83 EC 08 83 FF 01 77 33 E8 FC FD FF FF 48 85 DB 48 89 C2 74 06 0F BE 40 78 89 03 80 7A 7A 00 40 88 6A 78 74 14 66 81 7A 78 00 01 75 0C 48 89 E6 48 83 CF FF E8 ?? ?? ?? ?? 31 C0 59 5B 5D C3 }
	condition:
		$pattern
}

rule frame_dummy_a5e5203fe480c53944e168bb5cf04efd {
	meta:
		aliases = "frame_dummy"
		size = "66"
		objfiles = "crtbeginT, crtbegin"
	strings:
		$pattern = { ( CC | 55 ) B8 ?? ?? ?? ?? 48 85 C0 48 89 E5 74 0F BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 3D ?? ?? ?? ?? 00 74 19 B8 ?? ?? ?? ?? 48 85 C0 74 0F BF ?? ?? ?? ?? 49 89 C3 C9 41 FF E3 66 66 90 C9 C3 }
	condition:
		$pattern
}

rule htab_try_create_2c932cd8ba3e03bc97ae4d066863097a {
	meta:
		aliases = "htab_try_create"
		size = "58"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) B8 ?? ?? ?? ?? 89 E5 83 EC 18 89 44 24 14 B8 ?? ?? ?? ?? 89 44 24 10 8B 45 14 89 44 24 0C 8B 45 10 89 44 24 08 8B 45 0C 89 44 24 04 8B 45 08 89 04 24 E8 ?? ?? ?? ?? C9 C3 }
	condition:
		$pattern
}

rule timer_delete_2a6d7b23653c94633b59401f9f2889c1 {
	meta:
		aliases = "timer_delete"
		size = "67"
		objfiles = "timer_delete@librt.a"
	strings:
		$pattern = { ( CC | 55 ) B8 E2 00 00 00 48 89 FD 53 48 83 EC 08 48 63 7F 04 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 83 C8 FF 85 DB 75 0A 48 89 EF E8 ?? ?? ?? ?? 31 C0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule _ppfs_prepargs_0dad588ad55832bf29bc2f6623964a4b {
	meta:
		aliases = "_ppfs_prepargs"
		size = "67"
		objfiles = "_ppfs_prepargs@libc.a"
	strings:
		$pattern = { ( CC | 55 ) B9 06 00 00 00 FC 53 48 89 FB 48 8D 7F 50 48 83 EC 08 F3 A5 8B 6B 1C 85 ED 7E 23 89 6B 20 C7 43 1C 00 00 00 00 48 89 DF C7 43 08 00 00 00 00 C7 43 0C 00 00 00 00 E8 ?? ?? ?? ?? 89 6B 1C 58 5B 5D C3 }
	condition:
		$pattern
}

rule fibheap_insert_345e84815c18f58c814887f382ddedd2 {
	meta:
		aliases = "fibheap_insert"
		size = "90"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) B9 1C 00 00 00 89 E5 56 53 83 EC 10 8B 75 08 89 4C 24 04 C7 04 24 01 00 00 00 E8 ?? ?? ?? ?? 89 C3 89 43 08 89 DA 89 43 0C 8B 45 10 89 43 14 8B 45 0C 89 43 10 89 F0 E8 83 FA FF FF 8B 56 04 85 D2 74 08 8B 43 10 3B 42 10 7D 03 89 5E 04 FF 06 83 C4 10 89 D8 5B 5E 5D C3 }
	condition:
		$pattern
}

rule pex_init_17311a8039394e4cd23337824ef06eb0 {
	meta:
		aliases = "pex_init"
		size = "42"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) B9 ?? ?? ?? ?? 89 E5 83 EC 18 8B 45 10 89 4C 24 0C 89 44 24 08 8B 45 0C 89 44 24 04 8B 45 08 89 04 24 E8 ?? ?? ?? ?? C9 C3 }
	condition:
		$pattern
}

rule htab_create_785de797c1cee9510da2259a7223b732 {
	meta:
		aliases = "htab_create"
		size = "58"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) B9 ?? ?? ?? ?? 89 E5 83 EC 18 8B 45 14 BA ?? ?? ?? ?? 89 4C 24 14 89 54 24 10 89 44 24 0C 8B 45 10 89 44 24 08 8B 45 0C 89 44 24 04 8B 45 08 89 04 24 E8 ?? ?? ?? ?? C9 C3 }
	condition:
		$pattern
}

rule __GI_xdr_rmtcallres_e07019b5aa305970591bdd5e5237349a {
	meta:
		aliases = "xdr_rmtcallres, __GI_xdr_rmtcallres"
		size = "91"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) B9 ?? ?? ?? ?? BA 08 00 00 00 48 89 FD 53 48 89 F3 48 83 EC 18 48 8B 06 48 8D 74 24 10 48 89 44 24 10 E8 ?? ?? ?? ?? 85 C0 74 26 48 8D 73 08 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 16 48 8B 44 24 10 48 8B 73 10 48 89 EF 48 89 03 31 C0 FF 53 18 EB 02 31 C0 48 83 C4 18 5B 5D C3 }
	condition:
		$pattern
}

rule elem_compare_051adee56d545cc994f3923c276e9d98 {
	meta:
		aliases = "elem_compare"
		size = "30"
		objfiles = "partition@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) B9 FF FF FF FF 89 E5 8B 45 0C 8B 10 8B 45 08 39 10 7C 06 0F 9F C0 0F B6 C8 5D 89 C8 C3 }
	condition:
		$pattern
}

rule fibheap_delete_node_525923add098514e615ff80db1913956 {
	meta:
		aliases = "fibheap_delete_node"
		size = "62"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) BA 00 00 00 80 89 E5 83 EC 18 8B 45 0C 89 5D F8 8B 5D 08 89 75 FC 8B 70 14 89 54 24 08 89 1C 24 89 44 24 04 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 89 F0 8B 5D F8 8B 75 FC 89 EC 5D C3 }
	condition:
		$pattern
}

rule _ppfs_init_14ad457631e7ead363502a082f905a90 {
	meta:
		aliases = "_ppfs_init"
		size = "114"
		objfiles = "_ppfs_init@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BA 00 01 00 00 48 89 F5 31 F6 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? FF 4B 1C 48 8D 43 2C 48 89 2B BA 09 00 00 00 C7 00 08 00 00 00 48 83 C0 04 FF CA 75 F2 48 89 E8 EB 29 83 C8 FF EB 2F 80 FA 25 75 1C 48 FF C0 80 38 25 74 14 48 89 03 48 89 DF E8 ?? ?? ?? ?? 85 C0 78 DF 48 8B 03 EB 03 48 FF C0 8A 10 84 D2 75 D6 48 89 2B 31 C0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule pex_unix_fdopenw_719f90c09bf92ae2b09c59f0a16f5d69 {
	meta:
		aliases = "pex_unix_fdopenw"
		size = "72"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) BA 01 00 00 00 89 E5 B8 02 00 00 00 53 83 EC 14 8B 5D 0C 89 54 24 08 89 44 24 04 89 1C 24 E8 ?? ?? ?? ?? 85 C0 78 18 C7 45 0C ?? ?? ?? ?? 89 5D 08 83 C4 14 5B 5D E9 ?? ?? ?? ?? 8D 74 26 00 83 C4 14 31 C0 5B 5D C3 }
	condition:
		$pattern
}

rule addmntent_7885e957238243c319a77f239b6fb3c9 {
	meta:
		aliases = "addmntent"
		size = "90"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BA 02 00 00 00 48 89 FD 53 48 89 F3 31 F6 48 83 EC 18 E8 ?? ?? ?? ?? 85 C0 BA 01 00 00 00 78 30 8B 43 24 48 8B 13 BE ?? ?? ?? ?? 4C 8B 4B 18 4C 8B 43 10 48 89 EF 48 8B 4B 08 89 44 24 08 8B 43 20 89 04 24 31 C0 E8 ?? ?? ?? ?? 89 C2 C1 EA 1F 48 83 C4 18 89 D0 5B 5D C3 }
	condition:
		$pattern
}

rule sigset_6f735ba1112d75c3bcd6afc265ebabe3 {
	meta:
		aliases = "sigset"
		size = "293"
		objfiles = "sigset@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BA 10 00 00 00 53 89 FB 48 81 EC C8 01 00 00 48 83 FE 02 74 11 EB 4B 48 63 C2 48 C7 84 C4 40 01 00 00 00 00 00 00 FF CA 79 ED 48 8D AC 24 40 01 00 00 89 DE 48 89 EF E8 ?? ?? ?? ?? 85 C0 0F 88 CF 00 00 00 31 D2 31 FF 48 89 EE E8 ?? ?? ?? ?? 85 C0 BA 02 00 00 00 0F 89 BA 00 00 00 E9 B1 00 00 00 48 83 FE FF 0F 94 C2 85 FF 0F 9E C0 08 C2 75 05 83 FF 40 7E 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 8C 00 00 00 BA 10 00 00 00 48 89 B4 24 A0 00 00 00 EB 0F 48 63 C2 48 C7 84 C4 A8 00 00 00 00 00 00 00 FF CA 79 ED 48 8D B4 24 A0 00 00 00 48 89 E2 89 DF C7 84 24 28 01 00 00 00 00 00 00 E8 ?? ?? ?? ?? 85 }
	condition:
		$pattern
}

rule asctime_r_5023584bbfa2410d289b79f72da1856e {
	meta:
		aliases = "__GI_asctime_r, asctime_r"
		size = "224"
		objfiles = "asctime_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BA 1A 00 00 00 48 89 FD 53 48 89 F3 BE ?? ?? ?? ?? 48 89 DF 48 83 EC 08 E8 ?? ?? ?? ?? 8B 45 18 83 F8 06 77 1A 8D 34 40 BA 03 00 00 00 48 89 DF 48 63 F6 48 81 C6 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 10 83 F8 0B 77 1B 8D 34 40 48 8D 7B 04 BA 03 00 00 00 48 63 F6 48 81 C6 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 14 48 8D 4B 13 81 C2 6C 07 00 00 81 FA 0F 27 00 00 77 1D 48 8D 4B 17 89 D0 BE 0A 00 00 00 99 F7 FE 83 C2 30 88 11 48 FF C9 89 C2 80 39 3F 74 E7 48 0F BE 41 FF 48 8D 71 FF 8B 54 05 00 83 FA 63 76 0A C6 41 FF 3F C6 46 FF 3F EB 13 89 D0 BF 0A 00 00 00 99 F7 FF 00 41 FE 83 C2 30 88 51 FF 48 8D 4E FE }
	condition:
		$pattern
}

rule java_demangle_v3_beffbc9d884592a39f715492dbb38e27 {
	meta:
		aliases = "java_demangle_v3"
		size = "207"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) BA 25 00 00 00 89 E5 57 56 53 83 EC 2C 8B 45 08 8D 4D F0 E8 E7 FD FF FF 85 C0 89 45 DC 74 47 89 45 D8 89 45 D4 C7 45 E0 00 00 00 00 8D 76 00 8B 7D D4 0F B6 1F 84 DB 74 27 8B 75 D4 BA ?? ?? ?? ?? B8 07 00 00 00 FC 89 D7 89 C1 F3 A6 75 22 83 45 D4 07 FF 45 E0 8B 7D D4 0F B6 1F 84 DB 75 D9 8B 45 D8 C6 00 00 8B 45 DC 83 C4 2C 5B 5E 5F 5D C3 8B 45 E0 85 C0 7E 05 80 FB 3E 74 12 8B 4D D8 88 19 41 FF 45 D4 89 4D D8 EB A4 8D 74 26 00 8B 45 DC 39 45 D8 76 1C 8B 4D D8 80 79 FF 20 74 08 EB 11 80 7F FF 20 75 0B FF 4D D8 8B 7D D8 39 7D DC 72 EF 8B 45 D8 C6 00 5B C6 40 01 5D 83 C0 02 FF 4D E0 FF 45 D4 89 }
	condition:
		$pattern
}

rule __md5_Final_a406e92e7cb72408060c1c67278586d3 {
	meta:
		aliases = "__md5_Final"
		size = "143"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) BA 40 00 00 00 48 89 FD 53 48 89 F3 31 F6 48 83 EC 58 48 89 E7 E8 ?? ?? ?? ?? 48 8D 73 10 48 8D 7C 24 40 BA 08 00 00 00 C6 04 24 80 E8 34 FD FF FF 8B 43 10 BA 38 00 00 00 C1 E8 03 83 E0 3F 83 F8 37 76 05 BA 78 00 00 00 29 C2 48 89 E6 48 89 DF E8 01 FF FF FF 48 8D 74 24 40 48 89 DF BA 08 00 00 00 E8 EF FE FF FF 48 89 DE 48 89 EF BA 10 00 00 00 E8 ED FC FF FF 48 89 DF BA 58 00 00 00 31 F6 E8 ?? ?? ?? ?? 48 83 C4 58 5B 5D C3 }
	condition:
		$pattern
}

rule getutline_cfc950c8f2ea396af61f5691e4faaad6 {
	meta:
		aliases = "getutline"
		size = "109"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BA ?? ?? ?? ?? 48 89 FD BE ?? ?? ?? ?? 53 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 1C 8B 03 83 E8 06 66 83 F8 01 77 11 48 8D 75 08 48 8D 7B 08 E8 ?? ?? ?? ?? 85 C0 74 13 8B 3D ?? ?? ?? ?? E8 AC FD FF FF 48 85 C0 48 89 C3 75 D1 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 28 5B 5D C3 }
	condition:
		$pattern
}

rule mallopt_eb3fc63c5e9367fde27fcff47c92d45f {
	meta:
		aliases = "mallopt"
		size = "198"
		objfiles = "mallopt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BA ?? ?? ?? ?? 89 F5 BE ?? ?? ?? ?? 53 89 FB 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 43 04 83 F8 05 77 76 89 C0 FF 24 C5 ?? ?? ?? ?? 83 FD 50 77 68 85 ED B9 08 00 00 00 74 18 48 63 C5 B1 20 48 83 C0 17 48 89 C2 48 83 E2 F0 48 83 F8 1F 48 0F 47 CA 48 8B 05 ?? ?? ?? ?? 83 E0 03 48 09 C1 48 89 0D ?? ?? ?? ?? EB 0A 48 63 C5 48 89 05 ?? ?? ?? ?? BB 01 00 00 00 EB 22 48 63 C5 48 89 05 ?? ?? ?? ?? EB ED 48 63 C5 48 89 05 ?? ?? ?? ?? EB E1 89 2D ?? ?? ?? ?? EB D9 31 DB 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 89 D8 48 83 C4 28 5B 5D C3 }
	condition:
		$pattern
}

rule __GI_getnetent_441990104e9b35871d7cfc367a423843 {
	meta:
		aliases = "getnetent, __GI_getnetent"
		size = "412"
		objfiles = "getnetent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 53 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 3D ?? ?? ?? ?? 00 75 1F BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 0F 84 38 01 00 00 48 83 3D ?? ?? ?? ?? 00 75 1B BF 01 10 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 75 05 E8 ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? BE 00 10 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 0F 84 EF 00 00 00 80 38 23 74 B2 BE ?? ?? ?? ?? 48 89 C7 E8 37 FF FF FF 48 85 C0 74 A0 C6 00 00 BE ?? ?? ?? ?? 48 89 DF 48 89 1D ?? ?? ?? ?? E8 1B FF FF FF 48 85 C0 74 84 48 }
	condition:
		$pattern
}

rule _stdio_openlist_dec_use_c6c8be712447245f1cd9ee9a775fc336 {
	meta:
		aliases = "_stdio_openlist_dec_use"
		size = "216"
		objfiles = "fflush_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 53 48 83 EC 48 48 8D 7C 24 20 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? FF C8 0F 85 82 00 00 00 83 3D ?? ?? ?? ?? 00 7E 79 48 89 E7 BA ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 31 ED E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? EB 36 0F B7 07 48 8B 5F 38 25 30 80 00 00 83 F8 30 74 05 48 89 FD EB 1D 48 85 ED 75 09 48 89 1D ?? ?? ?? ?? EB 04 48 89 5D 38 F6 47 01 20 74 05 E8 ?? ?? ?? ?? 48 89 DF 48 85 FF 75 C5 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 8B 05 ?? ?? ?? ?? 48 8D 7C 24 20 BE 01 00 00 00 FF C8 89 05 }
	condition:
		$pattern
}

rule __GI_exit_b0dcacc47736a9f7608d9a6e18bdd4bc {
	meta:
		aliases = "exit, __GI_exit"
		size = "92"
		objfiles = "exit@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 53 89 FB 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 04 89 DF FF D0 BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 48 85 C0 74 05 E8 ?? ?? ?? ?? 89 DF E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule splay_tree_compare_pointers_fddad0d9a63bcc40e4ad57829babf1f8 {
	meta:
		aliases = "splay_tree_compare_pointers"
		size = "26"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) BA FF FF FF FF 89 E5 8B 45 0C 39 45 08 72 06 0F 97 C0 0F B6 D0 5D 89 D0 C3 }
	condition:
		$pattern
}

rule splay_tree_compare_ints_5ee2fc90ce58498d03b64bb3310d11a8 {
	meta:
		aliases = "splay_tree_compare_ints"
		size = "26"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) BA FF FF FF FF 89 E5 8B 45 0C 39 45 08 7C 06 0F 9F C0 0F B6 D0 5D 89 D0 C3 }
	condition:
		$pattern
}

rule firstwhite_81cd6ff63b245c91b7fe705c846304c7 {
	meta:
		aliases = "firstwhite"
		size = "64"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BE 20 00 00 00 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? BE 09 00 00 00 48 89 C5 48 89 DF E8 ?? ?? ?? ?? 48 85 ED 75 05 48 89 C5 EB 0C 48 85 C0 74 07 48 39 C5 48 0F 47 E8 5E 5B 48 89 E8 5D C3 }
	condition:
		$pattern
}

rule putenv_faa6557a1bf48ce8a7f8f611f0070323 {
	meta:
		aliases = "putenv"
		size = "87"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BE 3D 00 00 00 48 89 FD 53 48 83 EC 08 E8 ?? ?? ?? ?? 48 85 C0 48 89 C6 74 2C 48 29 EE 48 89 EF E8 ?? ?? ?? ?? 48 89 EA 48 89 C3 B9 01 00 00 00 31 F6 48 89 C7 E8 ?? ?? ?? ?? 48 89 DF 89 C5 E8 ?? ?? ?? ?? EB 0A 48 89 EF 31 ED E8 ?? ?? ?? ?? 5A 5B 89 E8 5D C3 }
	condition:
		$pattern
}

rule dlinfo_a11b30a91314ff9b111c04dab5dcf2f0 {
	meta:
		aliases = "dlinfo"
		size = "258"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) BE ?? ?? ?? ?? 31 C0 53 48 83 EC 18 48 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? EB 3C 8B 43 30 4C 8B 43 38 48 89 D9 48 8B 3D ?? ?? ?? ?? BE ?? ?? ?? ?? 4C 8B 0C C5 ?? ?? ?? ?? 48 8B 43 08 48 89 44 24 08 0F B7 43 40 89 04 24 48 8B 13 31 C0 E8 ?? ?? ?? ?? 48 8B 5B 18 48 85 DB 75 BF 48 8B 15 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? BE ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? EB 1E 48 8B 13 48 8B 3D ?? ?? ?? ?? BE ?? ?? ?? ?? 31 C0 48 8B 4A 08 E8 ?? ?? ?? ?? 48 8B 5B 20 48 85 DB 75 DD 48 8B 2D ?? ?? ?? ?? EB 42 48 8B 3D ?? ?? ?? ?? 48 89 EA BE ?? ?? ?? ?? 31 C0 48 89 EB E8 ?? }
	condition:
		$pattern
}

rule readdir_0323e6b3da4e0d295b68181121d65ce0 {
	meta:
		aliases = "readdir64, __GI_readdir, __GI_readdir64, readdir"
		size = "143"
		objfiles = "readdir@libc.a, readdir64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BE ?? ?? ?? ?? 48 89 FD 53 48 8D 5F 30 48 83 EC 28 48 89 DA 48 89 E7 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8B 45 08 48 39 45 10 77 25 48 8B 55 28 48 8B 75 18 8B 7D 00 E8 ?? ?? ?? ?? 48 85 C0 7F 04 31 DB EB 30 48 89 45 10 48 C7 45 08 00 00 00 00 48 8B 45 08 48 89 C3 48 03 5D 18 0F B7 53 10 48 01 D0 48 89 45 08 48 8B 43 08 48 89 45 20 48 83 3B 00 74 AD 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 28 5B 5D C3 }
	condition:
		$pattern
}

rule __GI___res_init_3a108c439b11173494368ad3381d2ef4 {
	meta:
		aliases = "__res_init, __GI___res_init"
		size = "298"
		objfiles = "res_init@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BE ?? ?? ?? ?? BA ?? ?? ?? ?? 53 48 83 EC 38 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 05 00 00 00 C7 05 ?? ?? ?? ?? 04 00 00 00 48 C7 05 ?? ?? ?? ?? 01 00 00 00 E8 ?? ?? ?? ?? 66 89 05 ?? ?? ?? ?? 8A 05 ?? ?? ?? ?? 31 C9 8B 35 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 66 C7 05 ?? ?? ?? ?? 02 00 66 C7 05 ?? ?? ?? ?? 00 35 83 E0 F0 C7 05 ?? ?? ?? ?? FF FF FF FF 83 C8 01 85 F6 88 05 ?? ?? ?? ?? 75 17 EB 19 48 63 D1 FF C1 48 8B 04 D5 ?? ?? ?? ?? 48 89 04 D5 ?? ?? ?? ?? 39 F1 7C E7 31 ED 83 3D ?? ?? ?? ?? 00 75 3F EB 45 48 63 DD 48 8D }
	condition:
		$pattern
}

rule _stdio_term_01992624e4bdffc8443e32d5d6e9a086 {
	meta:
		aliases = "_stdio_term"
		size = "135"
		objfiles = "_stdio@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BF ?? ?? ?? ?? 53 48 83 EC 08 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? EB 3C 48 8D 6B 58 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 19 48 8B 43 08 66 C7 03 30 00 48 89 43 28 48 89 43 30 48 89 43 18 48 89 43 20 C7 43 50 01 00 00 00 48 89 EF E8 ?? ?? ?? ?? 48 8B 5B 38 48 85 DB 75 BF 48 8B 1D ?? ?? ?? ?? EB 11 F6 03 40 74 08 48 89 DF E8 ?? ?? ?? ?? 48 8B 5B 38 48 85 DB 75 EA 5A 5B 5D C3 }
	condition:
		$pattern
}

rule vfork_41f8cf3389267ddf4d394f7dea183433 {
	meta:
		aliases = "__vfork, __GI_vfork, vfork"
		size = "21"
		objfiles = "vfork@libc.a"
	strings:
		$pattern = { ( CC | 5F ) B8 3A 00 00 00 0F 05 57 3D 01 F0 FF FF 0F 83 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __fixunsdfdi_a5fdb2ad9f5911eeb446da54b49485d5 {
	meta:
		aliases = "__fixunsdfdi"
		size = "44"
		objfiles = "_fixunsdfsi@libgcc.a"
	strings:
		$pattern = { ( CC | 66 ) 0F 12 0D ?? ?? ?? ?? 66 0F 2E C1 72 18 F2 0F 5C C1 48 B8 00 00 00 00 00 00 00 80 F2 48 0F 2C D0 48 8D 04 02 C3 F2 48 0F 2C C0 C3 }
	condition:
		$pattern
}

rule __GI___signbitf_3d67f3195060b9432f98e04d2d403e57 {
	meta:
		aliases = "__signbitf, __GI___signbitf"
		size = "10"
		objfiles = "s_signbitf@libm.a"
	strings:
		$pattern = { ( CC | 66 ) 0F 7E C0 25 00 00 00 80 C3 }
	condition:
		$pattern
}

rule __GI___finitef_5177647643ac6e382d592fd37ef1fb94 {
	meta:
		aliases = "__finitef, __GI___finitef"
		size = "18"
		objfiles = "s_finitef@libm.a"
	strings:
		$pattern = { ( CC | 66 ) 0F 7E C0 25 FF FF FF 7F 2D 00 00 80 7F C1 E8 1F C3 }
	condition:
		$pattern
}

rule __isnanf_96804cff1f09a4e60bb6241a31df43ec {
	meta:
		aliases = "__GI___isnanf, __isnanf"
		size = "21"
		objfiles = "s_isnanf@libm.a"
	strings:
		$pattern = { ( CC | 66 ) 0F 7E C2 B8 00 00 80 7F 81 E2 FF FF FF 7F 29 D0 C1 E8 1F C3 }
	condition:
		$pattern
}

rule __fpclassifyf_d40db9b120487ce595a4c799606703b6 {
	meta:
		aliases = "__GI___fpclassifyf, __fpclassifyf"
		size = "49"
		objfiles = "s_fpclassifyf@libm.a"
	strings:
		$pattern = { ( CC | 66 ) 0F 7E C2 B8 02 00 00 00 81 E2 FF FF FF 7F 74 1F 81 FA FF FF 7F 00 B0 03 76 15 81 FA FF FF 7F 7F B0 04 76 0B 31 C0 81 FA 00 00 80 7F 0F 96 C0 C3 }
	condition:
		$pattern
}

rule __signbit_df52e1e95e89b65fb2b05f9865739662 {
	meta:
		aliases = "__GI___signbit, __signbit"
		size = "15"
		objfiles = "s_signbit@libm.a"
	strings:
		$pattern = { ( CC | 66 ) 48 0F 7E C0 48 C1 E8 20 25 00 00 00 80 C3 }
	condition:
		$pattern
}

rule __finite_ecf4e9cdbf36c46dfe188a91483b410c {
	meta:
		aliases = "__GI___finite, __finite"
		size = "23"
		objfiles = "s_finite@libm.a"
	strings:
		$pattern = { ( CC | 66 ) 48 0F 7E C0 48 C1 E8 20 25 FF FF FF 7F 2D 00 00 F0 7F C1 E8 1F C3 }
	condition:
		$pattern
}

rule __fpurge_3027686af31e239b94287b0c64505ed0 {
	meta:
		aliases = "__fpurge"
		size = "43"
		objfiles = "__fpurge@libc.a"
	strings:
		$pattern = { ( CC | 66 ) 83 27 BC 48 8B 47 08 C7 47 44 00 00 00 00 C7 47 48 00 00 00 00 C6 47 02 00 48 89 47 28 48 89 47 30 48 89 47 18 48 89 47 20 C3 }
	condition:
		$pattern
}

rule clearerr_unlocked_4b1bacac0b5ac6ee8e7c00e975aef5fe {
	meta:
		aliases = "clearerr_unlocked"
		size = "5"
		objfiles = "clearerr_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 66 ) 83 27 F3 C3 }
	condition:
		$pattern
}

rule __drand48_iterate_79f6e05529e2cbfff278d366f1ec00f4 {
	meta:
		aliases = "__drand48_iterate"
		size = "93"
		objfiles = "drand48_iter@libc.a"
	strings:
		$pattern = { ( CC | 66 ) 83 7E 0E 00 75 1A 48 B8 6D E6 EC DE 05 00 00 00 66 C7 46 0C 0B 00 66 C7 46 0E 01 00 48 89 46 10 0F B7 47 02 0F B7 57 04 0F B7 0F C1 E0 10 48 C1 E2 20 48 09 CA 89 C0 48 09 D0 0F B7 56 0C 48 0F AF 46 10 48 01 D0 66 89 07 48 C1 E8 10 66 89 47 02 48 C1 E8 10 66 89 47 04 31 C0 C3 }
	condition:
		$pattern
}

rule __GI_ffs_ba7a988f94c4d6ffe6fa1ec18357896c {
	meta:
		aliases = "ffs, __GI_ffs"
		size = "72"
		objfiles = "ffs@libc.a"
	strings:
		$pattern = { ( CC | 66 ) 85 FF BA 01 00 00 00 75 08 C1 FF 10 BA 11 00 00 00 40 84 FF 75 06 83 C2 08 C1 FF 08 40 F6 C7 0F 75 06 83 C2 04 C1 FF 04 40 F6 C7 03 75 06 83 C2 02 C1 FF 02 31 C0 85 FF 74 0C 8D 47 01 0F BE D2 83 E0 01 8D 04 02 C3 }
	condition:
		$pattern
}

rule htons_92ad4ec525129c7854c3515f8e3ea768 {
	meta:
		aliases = "ntohs, htons"
		size = "8"
		objfiles = "ntohl@libc.a"
	strings:
		$pattern = { ( CC | 66 ) C1 CF 08 0F B7 C7 C3 }
	condition:
		$pattern
}

rule rand_r_ffbd2f8d9c7e6c4a2418b74fca4f2327 {
	meta:
		aliases = "rand_r"
		size = "76"
		objfiles = "rand_r@libc.a"
	strings:
		$pattern = { ( CC | 69 ) 17 6D 4E C6 41 81 C2 39 30 00 00 89 D0 69 D2 6D 4E C6 41 C1 E8 06 25 00 FC 1F 00 81 C2 39 30 00 00 89 D1 69 D2 6D 4E C6 41 C1 E9 10 81 E1 FF 03 00 00 31 C8 81 C2 39 30 00 00 C1 E0 0A 89 17 C1 EA 10 81 E2 FF 03 00 00 31 D0 C3 }
	condition:
		$pattern
}

rule __do_global_dtors_aux_ca79be8cd6a85c21c31a91f7721fb4dd {
	meta:
		aliases = "__do_global_dtors_aux"
		size = "146"
		objfiles = "crtbeginT, crtbegin"
	strings:
		$pattern = { ( CC | 80 ) 3D ?? ?? ?? ?? 00 55 48 89 E5 74 10 EB 38 90 48 83 C0 08 48 89 05 ?? ?? ?? ?? FF D2 48 8B 05 ?? ?? ?? ?? 48 8B 10 48 85 D2 75 E4 B8 ?? ?? ?? ?? 48 85 C0 74 0A BF ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01 C9 C3 66 66 66 90 66 66 90 55 B8 ?? ?? ?? ?? 48 85 C0 48 89 E5 74 0F BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 3D ?? ?? ?? ?? 00 74 19 B8 ?? ?? ?? ?? 48 85 C0 74 0F BF ?? ?? ?? ?? 49 89 C3 C9 41 FF E3 66 66 90 C9 C3 }
	condition:
		$pattern
}

rule __do_global_dtors_aux_6920d26a00b55c9cdaaa1b604b2acf3a {
	meta:
		aliases = "__do_global_dtors_aux"
		size = "167"
		objfiles = "crtbeginS"
	strings:
		$pattern = { ( CC | 80 ) 3D ?? ?? ?? ?? 00 55 48 89 E5 75 51 48 83 3D ?? ?? ?? ?? 00 74 1B 48 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 0D 48 83 C0 08 48 89 05 ?? ?? ?? ?? FF D2 48 8B 05 ?? ?? ?? ?? 48 8B 10 48 85 D2 75 E4 48 83 3D ?? ?? ?? ?? 00 74 0C 48 8D 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01 C9 C3 48 83 3D ?? ?? ?? ?? 00 55 48 89 E5 74 13 48 8D 35 ?? ?? ?? ?? 48 8D 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 3D ?? ?? ?? ?? 00 74 1A 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 0E 48 8D 3D ?? ?? ?? ?? 49 89 C3 C9 41 FF E3 C9 C3 }
	condition:
		$pattern
}

rule crypt_7eefd9c9ae7c726a1019856fef984837 {
	meta:
		aliases = "crypt"
		size = "27"
		objfiles = "crypt@libcrypt.a"
	strings:
		$pattern = { ( CC | 80 ) 3E 24 75 11 80 7E 01 31 75 0B 80 7E 02 24 75 05 E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule cfmakeraw_c339c164d8e896a1db21dfb3f70eb11c {
	meta:
		aliases = "cfmakeraw"
		size = "37"
		objfiles = "cfmakeraw@libc.a"
	strings:
		$pattern = { ( CC | 81 ) 67 08 CF FE FF FF 81 27 14 FA FF FF C6 47 17 01 C6 47 16 00 83 67 04 FE 81 67 0C B4 7F FF FF 83 4F 08 30 C3 }
	condition:
		$pattern
}

rule mkfifo_2c7fa22eb1f94dc3e502045ccd62b890 {
	meta:
		aliases = "mkfifo"
		size = "13"
		objfiles = "mkfifo@libc.a"
	strings:
		$pattern = { ( CC | 81 ) CE 00 10 00 00 31 D2 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _store_inttype_e7db0e3daff389cbf892884884ef329b {
	meta:
		aliases = "_store_inttype"
		size = "46"
		objfiles = "_store_inttype@libc.a"
	strings:
		$pattern = { ( CC | 81 ) FE 00 01 00 00 75 03 88 17 C3 81 FE 00 08 00 00 74 14 81 FE 00 02 00 00 75 04 66 89 17 C3 81 FE 00 04 00 00 75 04 48 89 17 C3 89 17 C3 }
	condition:
		$pattern
}

rule btowc_35d76700792a5470cc5ef6d0f8fd717d {
	meta:
		aliases = "__GI_btowc, btowc"
		size = "17"
		objfiles = "btowc@libc.a"
	strings:
		$pattern = { ( CC | 81 ) FF 80 00 00 00 B8 FF FF FF FF 0F 43 F8 89 F8 C3 }
	condition:
		$pattern
}

rule pthread_getspecific_8646c4d81d647c039a1c2227587518be {
	meta:
		aliases = "pthread_getspecific"
		size = "67"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 81 ) FF FF 03 00 00 53 89 FB 77 34 E8 5E FF FF FF 89 DA C1 EA 05 89 D2 48 8B 94 D0 48 01 00 00 48 85 D2 74 1B 89 D8 48 C1 E0 04 83 B8 ?? ?? ?? ?? 00 74 0C 48 89 D8 83 E0 1F 48 8B 04 C2 EB 02 31 C0 5B C3 }
	condition:
		$pattern
}

rule __GI_random_r_88e64ce3e011034f230ee1e50824b85b {
	meta:
		aliases = "random_r, __GI_random_r"
		size = "90"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { ( CC | 83 ) 7F 18 00 4C 8B 47 10 75 18 41 69 00 6D 4E C6 41 05 39 30 00 00 25 FF FF FF 7F 41 89 00 89 06 EB 35 48 8B 17 48 8B 4F 08 4C 8B 4F 28 8B 01 01 02 8B 02 48 83 C2 04 D1 E8 4C 39 CA 89 06 48 8D 41 04 72 05 4C 89 C2 EB 07 4C 39 C8 49 0F 43 C0 48 89 17 48 89 47 08 31 C0 C3 }
	condition:
		$pattern
}

rule _ppfs_setargs_b023fdd8cfa8439f4c5c6d266b7c26d5 {
	meta:
		aliases = "_ppfs_setargs"
		size = "457"
		objfiles = "_ppfs_setargs@libc.a"
	strings:
		$pattern = { ( CC | 83 ) 7F 1C 00 48 8D 77 70 0F 85 6F 01 00 00 81 7F 0C 00 00 00 80 75 2D 8B 47 50 48 8D 4F 50 83 F8 30 73 0E 89 C2 48 03 51 10 83 C0 08 89 47 50 EB 0C 48 8B 51 08 48 8D 42 08 48 89 41 08 8B 02 89 06 89 47 0C 81 7F 08 00 00 00 80 75 2D 8B 47 50 48 8D 4F 50 83 F8 30 73 0E 89 C2 48 03 51 10 83 C0 08 89 47 50 EB 0C 48 8B 51 08 48 8D 42 08 48 89 41 08 8B 02 89 06 89 47 08 45 31 C0 E9 EF 00 00 00 49 63 C0 8B 44 87 2C 83 F8 08 0F 84 DC 00 00 00 48 8D 4F 50 7F 1B 83 F8 02 74 43 7F 09 85 C0 79 3D E9 9A 00 00 00 83 F8 07 0F 85 91 00 00 00 EB 55 3D 00 04 00 00 0F 84 84 00 00 00 7F 10 3D 00 01 00 00 74 19 3D }
	condition:
		$pattern
}

rule __length_dotted_174436d6e62c35c2876db2239912a374 {
	meta:
		aliases = "__length_dotted"
		size = "59"
		objfiles = "lengthd@libc.a"
	strings:
		$pattern = { ( CC | 83 ) C8 FF 48 85 FF 74 32 EB 06 44 8D 41 02 EB 25 89 F1 EB 12 89 D0 25 C0 00 00 00 3D C0 00 00 00 74 E8 41 8D 0C 10 48 63 C1 44 8D 41 01 0F B6 14 07 85 D2 75 DF 44 89 C0 29 F0 C3 }
	condition:
		$pattern
}

rule wctob_5cf6c18f5aebbce981a8e3bd1a1f8205 {
	meta:
		aliases = "wctob"
		size = "13"
		objfiles = "wctob@libc.a"
	strings:
		$pattern = { ( CC | 83 ) C8 FF 81 FF 80 00 00 00 0F 42 C7 C3 }
	condition:
		$pattern
}

rule __encode_header_58be5729562e93ec3935acb1919c0cc2 {
	meta:
		aliases = "__encode_header"
		size = "163"
		objfiles = "encodeh@libc.a"
	strings:
		$pattern = { ( CC | 83 ) C8 FF 83 FA 0B 0F 8E 96 00 00 00 0F B6 47 01 88 06 8B 07 88 46 01 83 7F 04 01 19 C9 F7 D1 83 E1 80 83 7F 0C 01 19 D2 F7 D2 83 E2 04 83 7F 10 01 19 C0 F7 D0 83 E0 02 09 C1 8B 47 08 83 E0 0F C1 E0 03 09 C2 83 7F 14 00 0F 95 C0 09 C2 09 D1 88 4E 02 83 7F 18 01 8A 57 1C 19 C0 83 E2 0F F7 D0 83 E0 80 09 D0 88 46 03 0F B6 47 21 88 46 04 8B 47 20 88 46 05 0F B6 47 25 88 46 06 8B 47 24 88 46 07 0F B6 47 29 88 46 08 8B 47 28 88 46 09 0F B6 47 2D 88 46 0A 8B 47 2C 88 46 0B B8 0C 00 00 00 C3 }
	condition:
		$pattern
}

rule __GI_fopen_49ee42930df90b8512b73c45b5907075 {
	meta:
		aliases = "fopen, __GI_fopen"
		size = "10"
		objfiles = "fopen@libc.a"
	strings:
		$pattern = { ( CC | 83 ) C9 FF 31 D2 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule toascii_f2cd184b8363fafbe1eedf2e137d2ceb {
	meta:
		aliases = "toascii"
		size = "6"
		objfiles = "toascii@libc.a"
	strings:
		$pattern = { ( CC | 83 ) E7 7F 89 F8 C3 }
	condition:
		$pattern
}

rule srand48_r_19196b7d792035888cbcb866951de2c2 {
	meta:
		aliases = "__GI_srand48_r, srand48_r"
		size = "52"
		objfiles = "srand48_r@libc.a"
	strings:
		$pattern = { ( CC | 83 ) E7 FF 66 C7 06 0E 33 66 C7 46 0C 0B 00 48 89 F8 66 89 7E 02 66 C7 46 0E 01 00 48 C1 F8 10 66 89 46 04 48 B8 6D E6 EC DE 05 00 00 00 48 89 46 10 31 C0 C3 }
	condition:
		$pattern
}

rule isdigit_e348a6a0c60f04bd5095b6b57b832b68 {
	meta:
		aliases = "isdigit"
		size = "12"
		objfiles = "isdigit@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EF 30 31 C0 83 FF 09 0F 96 C0 C3 }
	condition:
		$pattern
}

rule pthread_rwlockattr_setkind_np_237fb0b7fbbba8eeac06dd8bf302d28a {
	meta:
		aliases = "__GI_pthread_attr_setdetachstate, pthread_attr_setdetachstate, pthread_rwlockattr_setkind_np"
		size = "15"
		objfiles = "rwlock@libpthread.a, attr@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) FE 01 B8 16 00 00 00 77 04 89 37 30 C0 C3 }
	condition:
		$pattern
}

rule pthread_rwlockattr_setpshared_8e7c404793854e24111df1587c21a3de {
	meta:
		aliases = "pthread_rwlockattr_setpshared"
		size = "16"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) FE 01 B8 16 00 00 00 77 05 89 77 04 30 C0 C3 }
	condition:
		$pattern
}

rule pthread_attr_setinheritsched_31120e3e7599263c555d3f89decf0b31 {
	meta:
		aliases = "__GI_pthread_attr_setinheritsched, pthread_attr_setinheritsched"
		size = "16"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) FE 01 B8 16 00 00 00 77 05 89 77 0C 30 C0 C3 }
	condition:
		$pattern
}

rule __pthread_mutexattr_setpshared_f8ceb03085e464132c8d8fcb56974aad {
	meta:
		aliases = "pthread_mutexattr_setpshared, pthread_condattr_setpshared, __pthread_mutexattr_setpshared"
		size = "18"
		objfiles = "condvar@libpthread.a, mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) FE 01 B8 16 00 00 00 77 07 19 C0 F7 D0 83 E0 26 C3 }
	condition:
		$pattern
}

rule __GI_pthread_attr_setschedpoli_0811c96f375dc3002b045bf361a069f6 {
	meta:
		aliases = "pthread_attr_setschedpolicy, __GI_pthread_attr_setschedpolicy"
		size = "16"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) FE 02 B8 16 00 00 00 77 05 89 77 04 30 C0 C3 }
	condition:
		$pattern
}

rule pthread_mutexattr_settype_24f5994df1cb86fe4dbc7c2dceb71691 {
	meta:
		aliases = "pthread_mutexattr_setkind_np, __pthread_mutexattr_settype, __pthread_mutexattr_setkind_np, pthread_mutexattr_settype"
		size = "15"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) FE 03 B8 16 00 00 00 77 04 89 37 30 C0 C3 }
	condition:
		$pattern
}

rule hstrerror_52a45390fba03bf4bd140d19d1650bc3 {
	meta:
		aliases = "hstrerror"
		size = "22"
		objfiles = "herror@libc.a"
	strings:
		$pattern = { ( CC | 83 ) FF 04 B8 ?? ?? ?? ?? 77 0B 48 63 C7 48 8B 04 C5 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule strsignal_cb769e51718e18420790470c7c6f48f5 {
	meta:
		aliases = "__GI_strsignal, strsignal"
		size = "80"
		objfiles = "strsignal@libc.a"
	strings:
		$pattern = { ( CC | 83 ) FF 1F 53 89 F8 BB ?? ?? ?? ?? 76 0B EB 12 80 3B 01 83 D8 00 48 FF C3 85 C0 75 F3 80 3B 00 75 2A 48 63 F7 BA F6 FF FF FF BF ?? ?? ?? ?? 31 C9 E8 ?? ?? ?? ?? 48 8D 58 F1 BA 0F 00 00 00 BE ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule iswctype_a46416ac0f5a84eabd9b47899bd12fb3 {
	meta:
		aliases = "__GI_iswctype, iswctype"
		size = "48"
		objfiles = "iswctype@libc.a"
	strings:
		$pattern = { ( CC | 83 ) FF 7F 0F 96 C2 83 FE 0C 0F 96 C0 31 C9 84 D0 74 1B 48 8B 15 ?? ?? ?? ?? 48 63 CF 89 F0 66 8B 84 00 ?? ?? ?? ?? 66 23 04 4A 0F B7 C8 89 C8 C3 }
	condition:
		$pattern
}

rule __GI_inet_makeaddr_2758a5a9ad15785113050ce6b46bf667 {
	meta:
		aliases = "inet_makeaddr, __GI_inet_makeaddr"
		size = "68"
		objfiles = "inet_addr@libc.a"
	strings:
		$pattern = { ( CC | 83 ) FF 7F 77 0B C1 E7 18 81 E6 FF FF FF 00 EB 27 81 FF FF FF 00 00 77 08 C1 E7 10 0F B7 C6 EB 0F 81 FF FF FF FF 00 77 0F C1 E7 08 40 0F B6 C6 09 F8 89 44 24 FC EB 06 09 F7 89 7C 24 FC 8B 44 24 FC 0F C8 C3 }
	condition:
		$pattern
}

rule __GI_towlower_66d7004649769513de6799d21320bda5 {
	meta:
		aliases = "towupper, towlower, __GI_towupper, __GI_towlower"
		size = "21"
		objfiles = "towupper@libc.a, towlower@libc.a"
	strings:
		$pattern = { ( CC | 83 ) FF 7F 77 0D 48 8B 05 ?? ?? ?? ?? 89 FA 0F BF 3C 50 89 F8 C3 }
	condition:
		$pattern
}

rule _load_inttype_50fd76293e996f00d4c994e71de79faf {
	meta:
		aliases = "_load_inttype"
		size = "85"
		objfiles = "_load_inttype@libc.a"
	strings:
		$pattern = { ( CC | 85 ) D2 78 26 F7 C7 00 0C 00 00 75 26 81 FF 00 01 00 00 8B 16 75 05 0F B6 D2 EB 0C 0F B7 C2 81 FF 00 02 00 00 0F 44 D0 89 D0 C3 F7 C7 00 0C 00 00 74 04 48 8B 06 C3 81 FF 00 01 00 00 8B 16 75 05 0F BE D2 EB 0C 0F BF C2 81 FF 00 02 00 00 0F 44 D0 48 63 C2 C3 }
	condition:
		$pattern
}

rule re_set_registers_8ee7fe1b0c13d1f219421f4fdc6cb3ef {
	meta:
		aliases = "__re_set_registers, re_set_registers"
		size = "56"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 85 ) D2 8A 47 38 74 14 83 E0 F9 83 C8 02 88 47 38 89 16 48 89 4E 08 4C 89 46 10 C3 83 E0 F9 88 47 38 C7 06 00 00 00 00 48 C7 46 10 00 00 00 00 48 C7 46 08 00 00 00 00 C3 }
	condition:
		$pattern
}

rule xdrrec_endofrecord_40adfeed9b0faf5afb23df47feb36a2a {
	meta:
		aliases = "__GI_xdrrec_endofrecord, xdrrec_endofrecord"
		size = "85"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 85 ) F6 48 8B 7F 18 75 14 83 7F 38 00 75 0E 48 8B 57 20 48 8D 42 04 48 3B 47 28 72 11 C7 47 38 00 00 00 00 BE 01 00 00 00 E9 74 FF FF FF 48 8B 47 30 48 29 C2 48 83 EA 04 81 CA 00 00 00 80 0F CA 89 10 48 8B 47 20 48 83 47 20 04 48 89 47 30 B8 01 00 00 00 C3 }
	condition:
		$pattern
}

rule _pthread_cleanup_pop_de7abd6eeaf0db10cd635ad8fa7dc651 {
	meta:
		aliases = "_pthread_cleanup_pop"
		size = "29"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 85 ) F6 53 48 89 FB 74 06 48 8B 7F 08 FF 13 E8 1C FF FF FF 48 8B 53 18 48 89 50 70 5B C3 }
	condition:
		$pattern
}

rule __sigjmp_save_817afc7cb940db950ddb73783a290a09 {
	meta:
		aliases = "__sigjmp_save"
		size = "39"
		objfiles = "sigjmp@libc.a"
	strings:
		$pattern = { ( CC | 85 ) F6 53 48 89 FB 74 16 48 8D 57 48 31 F6 31 FF E8 ?? ?? ?? ?? 85 C0 BA 01 00 00 00 74 02 31 D2 89 53 40 31 C0 5B C3 }
	condition:
		$pattern
}

rule __GI_pthread_attr_setscope_2e39ee7b82bec7b177c4a03e0b9d3e87 {
	meta:
		aliases = "pthread_attr_setscope, __GI_pthread_attr_setscope"
		size = "33"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 85 ) F6 74 11 BA 5F 00 00 00 FF CE B8 16 00 00 00 0F 45 D0 EB 09 C7 47 10 00 00 00 00 31 D2 89 D0 C3 }
	condition:
		$pattern
}

rule tcsendbreak_04ca53d5f0af19bbec903dd84711dc7b {
	meta:
		aliases = "tcsendbreak"
		size = "40"
		objfiles = "tcsendbrk@libc.a"
	strings:
		$pattern = { ( CC | 85 ) F6 7F 09 31 D2 BE 09 54 00 00 EB 14 8D 46 63 BA 64 00 00 00 BE 25 54 00 00 89 D1 99 F7 F9 89 C2 31 C0 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI___fsetlocking_9e25b7317ee9d4220b22b004e87d0dd1 {
	meta:
		aliases = "__fsetlocking, __GI___fsetlocking"
		size = "32"
		objfiles = "__fsetlocking@libc.a"
	strings:
		$pattern = { ( CC | 85 ) F6 8B 57 50 74 12 B8 01 00 00 00 83 FE 02 0F 45 05 ?? ?? ?? ?? 89 47 50 83 E2 01 8D 42 01 C3 }
	condition:
		$pattern
}

rule byte_store_op2_c9d8e7daf981a6a989f249526538367d {
	meta:
		aliases = "byte_store_op2"
		size = "22"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 88 ) 56 01 88 4E 03 C1 FA 08 C1 F9 08 40 88 3E 88 56 02 88 4E 04 C3 }
	condition:
		$pattern
}

rule byte_store_op1_87c185f2476411d241825daa5c0a78f9 {
	meta:
		aliases = "byte_store_op1"
		size = "13"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 88 ) 56 01 C1 FA 08 40 88 3E 88 56 02 C3 }
	condition:
		$pattern
}

rule xdrmem_create_4006cf9b3c1dfaf0016db8b7cde3a484 {
	meta:
		aliases = "__GI_xdrmem_create, xdrmem_create"
		size = "22"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 89 ) 0F 48 C7 47 08 ?? ?? ?? ?? 48 89 77 20 48 89 77 18 89 57 28 C3 }
	condition:
		$pattern
}

rule xdrstdio_create_66a87815d311812c9785539b55af6237 {
	meta:
		aliases = "xdrstdio_create"
		size = "30"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 89 ) 17 48 C7 47 08 ?? ?? ?? ?? 48 89 77 18 C7 47 28 00 00 00 00 48 C7 47 20 00 00 00 00 C3 }
	condition:
		$pattern
}

rule __GI_setenv_360f8dabf01a288ed2fa94fcd4fc3d83 {
	meta:
		aliases = "setenv, __GI_setenv"
		size = "9"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { ( CC | 89 ) D1 31 D2 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tcflow_c8415b642c41ace67eb791e6afb3050a {
	meta:
		aliases = "tcflow"
		size = "14"
		objfiles = "tcflow@libc.a"
	strings:
		$pattern = { ( CC | 89 ) F2 31 C0 BE 0A 54 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tcflush_e9d82f53c14d1176dc899f3520ce070d {
	meta:
		aliases = "tcflush"
		size = "14"
		objfiles = "tcflush@libc.a"
	strings:
		$pattern = { ( CC | 89 ) F2 31 C0 BE 0B 54 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __libc_creat_4b349260194dfd68bcfbf931ff7efc9e {
	meta:
		aliases = "creat64, creat, __libc_creat64, __libc_creat"
		size = "14"
		objfiles = "open@libc.a, creat64@libc.a"
	strings:
		$pattern = { ( CC | 89 ) F2 31 C0 BE 41 02 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __powisf2_42e1bceff67ea00b7f5d40491b904696 {
	meta:
		aliases = "__powisf2"
		size = "76"
		objfiles = "_powisf2@libgcc.a"
	strings:
		$pattern = { ( CC | 89 ) F8 0F 28 C8 C1 F8 1F 89 C2 31 FA 29 C2 F6 C2 01 75 0D F3 0F 10 0D ?? ?? ?? ?? 66 66 90 66 90 D1 EA 74 11 F6 C2 01 F3 0F 59 C0 74 F3 D1 EA F3 0F 59 C8 75 EF 85 FF 79 0F F3 0F 10 05 ?? ?? ?? ?? F3 0F 5E C1 0F 28 C8 0F 28 C1 C3 }
	condition:
		$pattern
}

rule __subvsi3_2659f80c368fd4a6f7516730f41fcf93 {
	meta:
		aliases = "__subvsi3"
		size = "44"
		objfiles = "_subvsi3@libgcc.a"
	strings:
		$pattern = { ( CC | 89 ) F8 48 83 EC 08 29 F0 85 F6 78 14 39 C7 0F 9C C2 84 D2 75 12 48 83 C4 08 C3 66 66 90 66 66 90 39 C7 0F 9F C2 EB EA E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __negvsi2_0b946368791f740041bd56d857b960c1 {
	meta:
		aliases = "__negvsi2"
		size = "44"
		objfiles = "_negvsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 89 ) F8 48 83 EC 08 F7 D8 85 FF 78 14 85 C0 0F 9F C2 84 D2 75 12 48 83 C4 08 C3 66 66 90 66 66 90 89 C2 C1 EA 1F EB EA E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule abs_515b26df566dbbfb8dd37af642fff2b7 {
	meta:
		aliases = "abs"
		size = "10"
		objfiles = "abs@libc.a"
	strings:
		$pattern = { ( CC | 89 ) F8 99 89 D0 31 F8 29 D0 C3 }
	condition:
		$pattern
}

rule div_ffb3b8e783991c8e89020790bbb51a35 {
	meta:
		aliases = "div"
		size = "24"
		objfiles = "div@libc.a"
	strings:
		$pattern = { ( CC | 89 ) F8 99 F7 FE 0F AF F0 89 C1 89 F8 89 CA 29 F0 48 C1 E0 20 48 09 D0 C3 }
	condition:
		$pattern
}

rule __malloc_largebin_index_b5c5a758b244fad19885947517a105d0 {
	meta:
		aliases = "__malloc_largebin_index"
		size = "96"
		objfiles = "malloc@libc.a"
	strings:
		$pattern = { ( CC | 89 ) F8 BA 5F 00 00 00 C1 E8 08 3D FF FF 00 00 77 4C 8D 90 00 FF FF FF C1 EA 10 83 E2 08 89 D1 D3 E0 8D 88 00 F0 FF FF C1 E9 10 83 E1 04 D3 E0 8D 34 0A 8D 88 00 C0 FF FF C1 E9 10 83 E1 02 D3 E0 89 C2 C1 E8 0F F7 D0 C1 EA 0E 21 C2 8D 04 0E 29 C2 8D 4A 13 D3 EF 83 E7 03 8D 54 97 54 89 D0 C3 }
	condition:
		$pattern
}

rule __powidf2_8150c11213571b958a93fb3003722df8 {
	meta:
		aliases = "__powidf2"
		size = "78"
		objfiles = "_powidf2@libgcc.a"
	strings:
		$pattern = { ( CC | 89 ) F8 F2 0F 10 C8 C1 F8 1F 89 C2 31 FA 29 C2 F6 C2 01 75 0C 66 0F 12 0D ?? ?? ?? ?? 66 66 66 90 D1 EA 74 11 F6 C2 01 F2 0F 59 C0 74 F3 D1 EA F2 0F 59 C8 75 EF 85 FF 79 10 66 0F 12 05 ?? ?? ?? ?? F2 0F 5E C1 F2 0F 10 C8 F2 0F 10 C1 C3 }
	condition:
		$pattern
}

rule posix_openpt_e5072460d403d40cfae2fbf7677a26c2 {
	meta:
		aliases = "__GI_posix_openpt, posix_openpt"
		size = "14"
		objfiles = "getpt@libc.a"
	strings:
		$pattern = { ( CC | 89 ) FE 31 C0 BF ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule nl_langinfo_2a59ef421b472a80ea8a0b88a8a74d7a {
	meta:
		aliases = "__GI_nl_langinfo, nl_langinfo"
		size = "73"
		objfiles = "nl_langinfo@libc.a"
	strings:
		$pattern = { ( CC | 89 ) FE C1 FE 08 83 FE 05 77 39 89 F0 0F B6 90 ?? ?? ?? ?? 40 0F B6 C7 8D 0C 02 8D 46 01 0F B6 80 ?? ?? ?? ?? 39 C1 73 1B 8D 41 07 83 E1 40 0F B6 90 ?? ?? ?? ?? 8D 04 09 89 C0 48 8D 84 02 ?? ?? ?? ?? C3 B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __GI_strcmp_ddddab28e2e9476e8bcf8637008fb49a {
	meta:
		aliases = "strcmp, __GI_strcoll, strcoll, __GI_strcmp"
		size = "33"
		objfiles = "strcmp@libc.a"
	strings:
		$pattern = { ( CC | 8A ) 07 3A 06 75 0D 48 FF C7 48 FF C6 84 C0 75 F0 31 C0 C3 B8 01 00 00 00 B9 FF FF FF FF 0F 42 C1 C3 }
	condition:
		$pattern
}

rule __scan_ungetc_1e1a6c322c49b0f2561ce7ef4d4d59c0 {
	meta:
		aliases = "__scan_ungetc"
		size = "32"
		objfiles = "__scan_cookie@libc.a"
	strings:
		$pattern = { ( CC | 8A ) 47 1D FF 47 14 3C 02 75 0A 8B 47 04 C6 47 1D 00 89 07 C3 84 C0 75 07 FF 4F 10 C6 47 1D 01 C3 }
	condition:
		$pattern
}

rule __pthread_getconcurrency_6d95d9ea3b4232aab4c7687be499d076 {
	meta:
		aliases = "pthread_getconcurrency, __libc_current_sigrtmin, __libc_current_sigrtmax, __pthread_getconcurrency"
		size = "7"
		objfiles = "pthread@libpthread.a, allocrtsig@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 05 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule wcpcpy_aca8bedfd5ccc0ba983e1dcd6d76a70b {
	meta:
		aliases = "wcpcpy"
		size = "21"
		objfiles = "wcpcpy@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 06 48 83 C6 04 89 07 48 83 C7 04 85 C0 75 F0 48 8D 47 FC C3 }
	condition:
		$pattern
}

rule __GI_wcschr_e265aa5ac78ed3a73e21c6b2a62882ab {
	meta:
		aliases = "wcschr, __GI_wcschr"
		size = "22"
		objfiles = "wcschr@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 07 39 F0 74 0C 85 C0 74 06 48 83 C7 04 EB F0 31 FF 48 89 F8 C3 }
	condition:
		$pattern
}

rule xdrrec_inline_03d77ba4df5e41f1f63a80f05a5b7398 {
	meta:
		aliases = "xdrrec_inline"
		size = "83"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 07 48 8B 57 18 85 C0 74 06 FF C8 75 42 EB 18 48 8B 7A 20 89 F0 48 8D 0C 07 48 3B 4A 28 77 30 48 89 F8 48 89 4A 20 C3 48 8B 4A 68 89 F6 48 39 CE 7F 1D 48 8B 7A 58 48 8D 04 37 48 3B 42 60 77 0F 48 01 72 58 48 29 F1 48 89 F8 48 89 4A 68 C3 31 C0 C3 }
	condition:
		$pattern
}

rule xdr_int32_t_1f8da2ccf24d8017dd535ff919a72306 {
	meta:
		aliases = "xdr_uint32_t, xdr_int32_t"
		size = "40"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 07 83 F8 01 74 0C 73 15 48 8B 47 08 4C 8B 58 48 EB 08 48 8B 47 08 4C 8B 58 40 41 FF E3 83 F8 02 0F 94 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule pthread_mutexattr_getkind_np_bf2bcf99b78042f4e0796c0c15ef442e {
	meta:
		aliases = "__pthread_mutexattr_gettype, __GI_pthread_attr_getdetachstate, pthread_mutexattr_gettype, __pthread_mutexattr_getkind_np, pthread_attr_getdetachstate, pthread_rwlockattr_getkind_np, pthread_mutexattr_getkind_np"
		size = "7"
		objfiles = "rwlock@libpthread.a, mutex@libpthread.a, attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 07 89 06 31 C0 C3 }
	condition:
		$pattern
}

rule __libc_allocate_rtsig_46f1e6510e7526738d0c53622cc7b423 {
	meta:
		aliases = "__libc_allocate_rtsig"
		size = "55"
		objfiles = "pthread@libpthread.a, allocrtsig@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 0D ?? ?? ?? ?? 83 F9 FF 74 26 8B 15 ?? ?? ?? ?? 39 D1 7F 1C 85 FF 74 0B 8D 41 01 89 05 ?? ?? ?? ?? EB 10 8D 42 FF 89 D1 89 05 ?? ?? ?? ?? EB 03 83 C9 FF 89 C8 C3 }
	condition:
		$pattern
}

rule xdr_long_e1dbf51a8c3dd76d272a1bec8e4f4a0d {
	meta:
		aliases = "__GI_xdr_long, xdr_long"
		size = "51"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 0F 85 C9 75 15 48 8B 16 48 63 C2 48 39 D0 75 19 48 8B 47 08 4C 8B 58 08 EB 0C 83 F9 01 75 0A 48 8B 47 08 4C 8B 18 41 FF E3 31 C0 83 F9 02 0F 94 C0 C3 }
	condition:
		$pattern
}

rule __pthread_restart_new_f7ca6411fb683c31a924c8feff00d74d {
	meta:
		aliases = "__pthread_restart_new"
		size = "14"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 35 ?? ?? ?? ?? 8B 7F 28 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_attr_getschedpolicy_7d87a0480047214eb11c700f0a85c378 {
	meta:
		aliases = "__GI_pthread_attr_getschedpolicy, pthread_rwlockattr_getpshared, pthread_attr_getschedpolicy"
		size = "8"
		objfiles = "rwlock@libpthread.a, attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 47 04 89 06 31 C0 C3 }
	condition:
		$pattern
}

rule cfgetospeed_30fe2efe0d3c7a33d13d5a0f464ad865 {
	meta:
		aliases = "cfgetospeed"
		size = "9"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 47 08 25 0F 10 00 00 C3 }
	condition:
		$pattern
}

rule __GI_pthread_attr_getinheritsc_0274aac5c29a580eb22600b553828fd3 {
	meta:
		aliases = "pthread_attr_getinheritsched, __GI_pthread_attr_getinheritsched"
		size = "8"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 47 0C 89 06 31 C0 C3 }
	condition:
		$pattern
}

rule __GI__seterr_reply_2e74f49b9f64dadebbfad36b256a2feb {
	meta:
		aliases = "_seterr_reply, __GI__seterr_reply"
		size = "231"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 47 10 85 C0 74 0A FF C8 0F 85 91 00 00 00 EB 5C 8B 47 30 85 C0 75 07 C7 06 00 00 00 00 C3 83 F8 05 89 C0 77 37 FF 24 C5 ?? ?? ?? ?? C7 06 08 00 00 00 EB 78 C7 06 09 00 00 00 EB 70 C7 06 0A 00 00 00 EB 68 C7 06 0B 00 00 00 EB 60 C7 06 0C 00 00 00 EB 58 C7 06 00 00 00 00 EB 50 C7 06 10 00 00 00 48 C7 46 08 00 00 00 00 EB 2D 8B 47 18 83 F8 01 74 0D 83 F8 06 75 10 C7 06 06 00 00 00 EB 2B C7 06 07 00 00 00 EB 23 C7 06 10 00 00 00 48 C7 46 08 01 00 00 00 89 C0 48 89 46 10 EB 0D C7 06 10 00 00 00 8B 47 10 48 89 46 08 8B 06 83 F8 07 74 1B 83 F8 09 74 1D 83 F8 06 75 28 48 8B 47 20 48 89 46 08 48 8B }
	condition:
		$pattern
}

rule __pthread_mutex_destroy_aa3b21c3a1eb41d628a397e5a48e2fbe {
	meta:
		aliases = "pthread_mutex_destroy, __pthread_mutex_destroy"
		size = "45"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 47 10 85 C0 78 0A 83 F8 01 7E 0B 83 F8 03 7E 0C B8 16 00 00 00 C3 F6 47 18 01 EB 05 48 83 7F 18 00 74 06 B8 10 00 00 00 C3 31 C0 C3 }
	condition:
		$pattern
}

rule __GI_pthread_attr_getscope_05935359c1ce9b131d550f05f2a33b38 {
	meta:
		aliases = "pthread_attr_getscope, __new_sem_getvalue, sem_getvalue, __GI_pthread_attr_getscope"
		size = "8"
		objfiles = "attr@libpthread.a, semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 47 10 89 06 31 C0 C3 }
	condition:
		$pattern
}

rule xdrmem_inline_379bf3e9df0b5d88aac4fee30b3ca5d3 {
	meta:
		aliases = "xdrmem_inline"
		size = "32"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 47 28 31 D2 39 F0 72 13 48 8B 57 18 29 F0 89 47 28 89 F0 48 8D 04 02 48 89 47 18 48 89 D0 C3 }
	condition:
		$pattern
}

rule xdrmem_getint32_388b46c17bbe706dc4930305f6b27446 {
	meta:
		aliases = "xdrmem_getint32"
		size = "36"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 47 28 31 D2 83 F8 03 76 17 83 E8 04 B2 01 89 47 28 48 8B 47 18 8B 00 0F C8 89 06 48 83 47 18 04 89 D0 C3 }
	condition:
		$pattern
}

rule xdrmem_putint32_201fe442643335908c2673f4c658389a {
	meta:
		aliases = "xdrmem_putlong, xdrmem_putint32"
		size = "39"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 47 28 31 D2 83 F8 03 76 1A 48 8B 57 18 83 E8 04 89 47 28 8B 06 0F C8 89 02 48 83 47 18 04 BA 01 00 00 00 89 D0 C3 }
	condition:
		$pattern
}

rule xdrmem_getlong_b017124e3a97ae63c6d7922ac12c6c52 {
	meta:
		aliases = "xdrmem_getlong"
		size = "39"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 47 28 31 D2 83 F8 03 76 1A 83 E8 04 B2 01 89 47 28 48 8B 47 18 8B 00 0F C8 48 98 48 89 06 48 83 47 18 04 89 D0 C3 }
	condition:
		$pattern
}

rule sigisemptyset_0f2814b175f84b38c1b3fd8133dfaea6 {
	meta:
		aliases = "sigisemptyset"
		size = "33"
		objfiles = "sigisempty@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 47 78 BA 0F 00 00 00 EB 06 48 63 C2 8B 04 C7 85 C0 75 04 FF CA 79 F2 85 C0 0F 94 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule xdrmem_setpos_d6a28b0a1ee0d2573d1f9165fbc06333 {
	meta:
		aliases = "xdrmem_setpos"
		size = "54"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4F 28 89 F6 48 03 77 20 48 03 4F 18 48 39 CE 7F 21 48 89 CA B8 FF FF FF FF 48 29 F2 48 39 C2 7F 11 89 C8 48 89 77 18 29 F0 89 47 28 B8 01 00 00 00 C3 31 C0 C3 }
	condition:
		$pattern
}

rule enqueue_6d0ba486610b33a6d0e5cbc8a38efa90 {
	meta:
		aliases = "enqueue"
		size = "32"
		objfiles = "rwlock@libpthread.a, condvar@libpthread.a, semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 56 2C EB 0F 3B 50 2C 7E 06 48 89 46 10 EB 0C 48 8D 78 10 48 8B 07 48 85 C0 75 E9 48 89 37 C3 }
	condition:
		$pattern
}

rule clntunix_control_e74c6c579fd1140f630a9b6c6856a9af {
	meta:
		aliases = "clntunix_control"
		size = "203"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 8D ) 46 FF 48 83 EC 08 49 89 D0 48 8B 4F 10 83 F8 0E 77 09 89 C0 FF 24 C5 ?? ?? ?? ?? 31 C0 E9 A6 00 00 00 C7 41 04 01 00 00 00 E9 95 00 00 00 C7 41 04 00 00 00 00 E9 89 00 00 00 48 8B 02 48 89 41 08 48 8B 42 08 48 89 41 10 EB 78 48 8B 41 08 48 89 02 48 8B 41 10 48 89 42 08 EB 67 48 8D 71 1C BA 6E 00 00 00 4C 89 C7 E8 ?? ?? ?? ?? EB 54 8B 01 89 02 EB 4E 8B 81 A8 00 00 00 0F C8 EB 30 8B 02 FF C8 0F C8 89 C0 48 89 81 A8 00 00 00 8B 81 B8 00 00 00 0F C8 EB 17 8B 02 0F C8 89 C0 48 89 81 B8 00 00 00 EB 1C 8B 81 B4 00 00 00 0F C8 89 C0 49 89 00 EB 0D 8B 02 0F C8 89 C0 48 89 81 B4 00 00 00 B8 01 00 00 }
	condition:
		$pattern
}

rule clnttcp_control_cd3f3275e817163722f46b775e27ece9 {
	meta:
		aliases = "clnttcp_control"
		size = "172"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 8D ) 46 FF 48 8B 4F 10 83 F8 0E 77 09 89 C0 FF 24 C5 ?? ?? ?? ?? 31 C0 C3 C7 41 04 01 00 00 00 EB 75 C7 41 04 00 00 00 00 EB 6C 48 8B 02 48 89 41 08 48 8B 42 08 C7 41 18 01 00 00 00 48 89 41 10 EB 54 48 8B 41 08 48 89 02 48 8B 41 10 EB 0B 48 8B 41 1C 48 89 02 48 8B 41 24 48 89 42 08 EB 36 8B 01 89 02 EB 30 8B 41 48 0F C8 EB 24 8B 02 FF C8 0F C8 89 C0 48 89 41 48 8B 41 58 0F C8 EB 11 8B 02 0F C8 89 C0 48 89 41 58 EB 0A 8B 41 54 0F C8 89 C0 48 89 02 B8 01 00 00 00 C3 8B 02 0F C8 89 C0 48 89 41 54 B8 01 00 00 00 C3 }
	condition:
		$pattern
}

rule clntudp_control_59f054b8580b20bd2d1ef6dd2e12c4f1 {
	meta:
		aliases = "clntudp_control"
		size = "250"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 8D ) 46 FF 49 89 D0 48 8B 4F 10 83 F8 0E 77 09 89 C0 FF 24 C5 ?? ?? ?? ?? 31 C0 C3 C7 41 04 01 00 00 00 E9 B5 00 00 00 C7 41 04 00 00 00 00 E9 A9 00 00 00 48 8B 02 48 89 41 30 48 8B 42 08 48 89 41 38 E9 95 00 00 00 48 8B 41 30 48 89 02 48 8B 41 38 EB 1C 48 8B 02 48 89 41 20 48 8B 42 08 48 89 41 28 EB 77 48 8B 41 20 48 89 02 48 8B 41 28 49 89 40 08 EB 66 48 8B 41 08 48 89 02 48 8B 41 10 EB ED 8B 01 89 02 EB 53 48 8B 81 90 00 00 00 8B 00 0F C8 EB 41 41 8B 00 48 8B 91 90 00 00 00 FF C8 0F C8 89 C0 48 89 02 48 8B 81 90 00 00 00 8B 40 10 0F C8 EB 20 48 8B 91 90 00 00 00 41 8B 00 0F C8 89 C0 48 89 42 }
	condition:
		$pattern
}

rule __GI_towctrans_42623a165cffe5a5e4aa0db987cd1766 {
	meta:
		aliases = "towctrans, __GI_towctrans"
		size = "47"
		objfiles = "towctrans@libc.a"
	strings:
		$pattern = { ( CC | 8D ) 46 FF 53 89 FB 83 F8 01 77 15 83 FF 7F 77 1B FF CE 75 06 5B E9 ?? ?? ?? ?? 5B E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 16 00 00 00 89 D8 5B C3 }
	condition:
		$pattern
}

rule __sigdelset_ad03890f96d8f12ea139551c55208fbf {
	meta:
		aliases = "__sigdelset"
		size = "30"
		objfiles = "sigsetops@libc.a"
	strings:
		$pattern = { ( CC | 8D ) 4E FF 48 C7 C0 FE FF FF FF 48 63 D1 83 E1 3F 48 C1 EA 06 48 D3 C0 48 21 04 D7 31 C0 C3 }
	condition:
		$pattern
}

rule __sigaddset_074afa3a823ff4da2a43d8182e97b627 {
	meta:
		aliases = "__sigaddset"
		size = "28"
		objfiles = "sigsetops@libc.a"
	strings:
		$pattern = { ( CC | 8D ) 4E FF B8 01 00 00 00 48 63 D1 83 E1 3F 48 C1 EA 06 48 D3 E0 48 09 04 D7 31 C0 C3 }
	condition:
		$pattern
}

rule __sigismember_4972fc843ab45a1eed9fe509ac10b516 {
	meta:
		aliases = "__sigismember"
		size = "32"
		objfiles = "sigsetops@libc.a"
	strings:
		$pattern = { ( CC | 8D ) 4E FF B8 01 00 00 00 48 63 D1 83 E1 3F 48 C1 EA 06 48 D3 E0 48 85 04 D7 0F 95 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule __GI_toupper_9f0ff8c43c07a77d6d8e6a24d1ca8102 {
	meta:
		aliases = "toupper, tolower, __GI_tolower, __GI_toupper"
		size = "30"
		objfiles = "tolower@libc.a, toupper@libc.a"
	strings:
		$pattern = { ( CC | 8D ) 87 80 00 00 00 3D 7F 01 00 00 77 0E 48 8B 05 ?? ?? ?? ?? 48 63 D7 0F BF 3C 50 89 F8 C3 }
	condition:
		$pattern
}

rule testandset_b7d13f32b53596d859070eedfa7542c2 {
	meta:
		aliases = "testandset"
		size = "8"
		objfiles = "pt_machine@libpthread.a"
	strings:
		$pattern = { ( CC | B8 ) 01 00 00 00 87 07 C3 }
	condition:
		$pattern
}

rule xdr_void_62dea3be98d084788202ec199cbcebf6 {
	meta:
		aliases = "old_sem_extricate_func, __GI_xdr_void, __GI__stdlib_mb_cur_max, _stdlib_mb_cur_max, authnone_validate, xdr_void"
		size = "6"
		objfiles = "_stdlib_mb_cur_max@libc.a, xdr@libc.a, auth_none@libc.a, oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | B8 ) 01 00 00 00 C3 }
	condition:
		$pattern
}

rule _svcauth_short_cca2f00a582595d7f5454d6d2948b3e3 {
	meta:
		aliases = "rendezvous_stat, svcraw_stat, svcudp_stat, _svcauth_short"
		size = "6"
		objfiles = "svc_authux@libc.a, svc_udp@libc.a, svc_raw@libc.a, svc_unix@libc.a, svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | B8 ) 02 00 00 00 C3 }
	condition:
		$pattern
}

rule __GI_mbsnrtowcs_89cdc73fc2b76cb437938243452c0591 {
	meta:
		aliases = "mbsnrtowcs, __GI_mbsnrtowcs"
		size = "153"
		objfiles = "mbsnrtowcs@libc.a"
	strings:
		$pattern = { ( CC | B8 ) ?? ?? ?? ?? 48 83 EC 18 4D 85 C0 4C 0F 44 C0 48 85 FF 49 89 D2 0F 94 C2 4C 39 C7 41 B9 01 00 00 00 0F 94 C0 08 C2 74 2D 48 85 FF 48 89 E7 75 1F 48 83 C9 FF 45 30 C9 EB 1C 45 31 C0 EB 47 E8 ?? ?? ?? ?? C7 00 54 00 00 00 48 83 C8 FF EB 44 48 89 E7 45 31 C9 49 39 CA 4C 8B 06 49 0F 46 CA 48 89 CA EB 1C 41 0F B6 00 85 C0 89 07 74 CB 83 F8 7F 7F CB 49 63 C1 49 FF C0 48 FF CA 48 8D 3C 87 48 85 D2 75 DF 48 39 E7 74 03 4C 89 06 48 89 C8 48 29 D0 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule rpc_thread_multi_9dec80f10b80e6ab9f718fde18c116ae {
	meta:
		aliases = "rpc_thread_multi"
		size = "37"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | B8 ) ?? ?? ?? ?? 48 85 C0 74 0F BE ?? ?? ?? ?? BF 02 00 00 00 E9 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __GI_localeconv_07ab5dcbc6e3352a5a21106f39d27d7f {
	meta:
		aliases = "localeconv, __GI_localeconv"
		size = "60"
		objfiles = "localeconv@libc.a"
	strings:
		$pattern = { ( CC | B8 ) ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 48 83 C0 08 48 3D ?? ?? ?? ?? 48 C7 00 ?? ?? ?? ?? 72 ED B8 ?? ?? ?? ?? C6 00 7F 48 FF C0 48 3D ?? ?? ?? ?? 76 F2 B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __rpc_thread_variables_62a90e6bb53968dce702b5e2d5a32686 {
	meta:
		aliases = "__rpc_thread_variables"
		size = "220"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | B8 ) ?? ?? ?? ?? 53 48 85 C0 74 0C BF 02 00 00 00 E8 ?? ?? ?? ?? EB 07 48 8B 05 ?? ?? ?? ?? 48 85 C0 48 89 C3 0F 85 AD 00 00 00 B8 ?? ?? ?? ?? 48 85 C0 74 11 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 18 83 3D ?? ?? ?? ?? 00 75 0F E8 88 FF FF FF C7 05 ?? ?? ?? ?? 01 00 00 00 B8 ?? ?? ?? ?? 48 85 C0 74 0C BF 02 00 00 00 E8 ?? ?? ?? ?? EB 07 48 8B 05 ?? ?? ?? ?? 48 85 C0 48 89 C3 75 55 BE 10 01 00 00 BF 01 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 22 B8 ?? ?? ?? ?? 48 85 C0 74 0F 48 89 DE BF 02 00 00 00 E8 ?? ?? ?? ?? EB 25 48 89 1D ?? ?? ?? ?? EB 1C B8 ?? ?? ?? ?? 48 85 C0 74 0B 5B BF 02 }
	condition:
		$pattern
}

rule __rpc_thread_destroy_6d1ebc8f60529e28a354d346dd4d050e {
	meta:
		aliases = "__rpc_thread_destroy"
		size = "177"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | B8 ) ?? ?? ?? ?? 53 48 85 C0 74 0F BF 02 00 00 00 E8 ?? ?? ?? ?? 48 89 C3 EB 07 48 8B 1D ?? ?? ?? ?? 48 85 DB 0F 84 85 00 00 00 48 81 FB ?? ?? ?? ?? 74 7C E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B BB B0 00 00 00 E8 ?? ?? ?? ?? 48 8B BB B8 00 00 00 E8 ?? ?? ?? ?? 48 8B BB C0 00 00 00 E8 ?? ?? ?? ?? 48 8B BB F8 00 00 00 E8 ?? ?? ?? ?? 48 8B BB D8 00 00 00 E8 ?? ?? ?? ?? 48 8B BB E0 00 00 00 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 48 85 C0 74 0D 5B 31 F6 BF 02 00 00 00 E9 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 5B C3 }
	condition:
		$pattern
}

rule __GI___h_errno_location_6df29da601a97e2ce0e822cd8a3c1c72 {
	meta:
		aliases = "__errno_location, __h_errno_location, __GI___errno_location, __libc_pthread_init, __GI___h_errno_location"
		size = "6"
		objfiles = "libc_pthread_init@libc.a, __errno_location@libc.a, __h_errno_location@libc.a"
	strings:
		$pattern = { ( CC | B8 ) ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule wcstoll_7e01fe78e53cc3030b461927294d8a96 {
	meta:
		aliases = "__GI_wcstoll, wcstoimax, __GI_strtoll, strtoimax, __GI_wcstol, __GI_strtol, strtol, wcstol, strtoll, wcstoll"
		size = "10"
		objfiles = "wcstol@libc.a, strtol@libc.a"
	strings:
		$pattern = { ( CC | B9 ) 01 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_sigwaitinfo_45f0e910e2de754f24803d6f7d686e3f {
	meta:
		aliases = "sigwaitinfo, __GI_sigwaitinfo"
		size = "9"
		objfiles = "__rt_sigtimedwait@libc.a"
	strings:
		$pattern = { ( CC | B9 ) 08 00 00 00 31 D2 EB C7 }
	condition:
		$pattern
}

rule sigtimedwait_2aade9f1b065d003ff0f600b840ee546 {
	meta:
		aliases = "__GI_sigtimedwait, sigtimedwait"
		size = "7"
		objfiles = "__rt_sigtimedwait@libc.a"
	strings:
		$pattern = { ( CC | B9 ) 08 00 00 00 EB D0 }
	condition:
		$pattern
}

rule __GI_fopen64_d7eff41793f2ecee28eb38daf50ba31d {
	meta:
		aliases = "fopen64, __GI_fopen64"
		size = "12"
		objfiles = "fopen64@libc.a"
	strings:
		$pattern = { ( CC | B9 ) FE FF FF FF 31 D2 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __libc_tcdrain_3d7ce05705196c7f47cc6007f3081006 {
	meta:
		aliases = "tcdrain, __libc_tcdrain"
		size = "17"
		objfiles = "tcdrain@libc.a"
	strings:
		$pattern = { ( CC | BA ) 01 00 00 00 BE 09 54 00 00 31 C0 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule vwarn_a387c4b864d27253b6d19799b7858c2a {
	meta:
		aliases = "__GI_vwarn, vwarn"
		size = "10"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | BA ) 01 00 00 00 E9 F7 FD FF FF }
	condition:
		$pattern
}

rule xdr_des_block_bfe7390823d8e150181940fa8372445f {
	meta:
		aliases = "xdr_des_block"
		size = "10"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | BA ) 08 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule atol_7a1238ef70db7b947fbe00265536d22b {
	meta:
		aliases = "atoll, __GI_atol, atol"
		size = "12"
		objfiles = "atol@libc.a"
	strings:
		$pattern = { ( CC | BA ) 0A 00 00 00 31 F6 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule atoi_d8adfd3e57cf0df013df96ab1709cbb4 {
	meta:
		aliases = "__GI_atoi, atoi"
		size = "18"
		objfiles = "atoi@libc.a"
	strings:
		$pattern = { ( CC | BA ) 0A 00 00 00 48 83 EC 08 31 F6 E8 ?? ?? ?? ?? 5A C3 }
	condition:
		$pattern
}

rule __stdio_init_mutex_40a8679dff4e5793d6623de452b8ea95 {
	meta:
		aliases = "__stdio_init_mutex"
		size = "15"
		objfiles = "_stdio@libc.a"
	strings:
		$pattern = { ( CC | BA ) 28 00 00 00 BE ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule usleep_3a3a2a5c918eda8e7fa824ae2678dd66 {
	meta:
		aliases = "usleep"
		size = "52"
		objfiles = "usleep@libc.a"
	strings:
		$pattern = { ( CC | BA ) 40 42 0F 00 89 F8 48 83 EC 18 89 D1 31 D2 48 89 E7 F7 F1 31 F6 89 D2 89 C0 48 69 D2 E8 03 00 00 48 89 04 24 48 89 54 24 08 E8 ?? ?? ?? ?? 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule svcudp_create_7cd5e8264790c1be75a669874afc76bc {
	meta:
		aliases = "__GI_svcudp_create, svcudp_create"
		size = "15"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | BA ) 60 22 00 00 BE 60 22 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sigemptyset_f0990841898392be017d7a4ea7c169a0 {
	meta:
		aliases = "__GI_sigemptyset, sigemptyset"
		size = "20"
		objfiles = "sigempty@libc.a"
	strings:
		$pattern = { ( CC | BA ) 80 00 00 00 48 83 EC 08 31 F6 E8 ?? ?? ?? ?? 5A 31 C0 C3 }
	condition:
		$pattern
}

rule __GI_sigfillset_0f41f09d6b0b1506b53b98a18d551223 {
	meta:
		aliases = "sigfillset, __GI_sigfillset"
		size = "23"
		objfiles = "sigfillset@libc.a"
	strings:
		$pattern = { ( CC | BA ) 80 00 00 00 48 83 EC 08 BE FF 00 00 00 E8 ?? ?? ?? ?? 5A 31 C0 C3 }
	condition:
		$pattern
}

rule _promoted_size_9da0bb022b8a062a82e41585b743790c {
	meta:
		aliases = "_promoted_size"
		size = "46"
		objfiles = "_ppfs_parsespec@libc.a"
	strings:
		$pattern = { ( CC | BA ) ?? ?? ?? ?? 48 83 EA 02 0F BF 02 39 F8 74 09 48 81 FA ?? ?? ?? ?? 77 EC 48 81 EA ?? ?? ?? ?? 48 D1 FA 48 63 C2 0F B6 80 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule gmtime_880dc9c8bf8a420eeb0907fd5bf842d8 {
	meta:
		aliases = "gmtime"
		size = "23"
		objfiles = "gmtime@libc.a"
	strings:
		$pattern = { ( CC | BA ) ?? ?? ?? ?? 48 83 EC 08 31 F6 E8 ?? ?? ?? ?? 5A B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule atexit_b2ba00ed548d75fa1ccaff540b7d5ca4 {
	meta:
		aliases = "atexit"
		size = "24"
		objfiles = "atexit@libc.a"
	strings:
		$pattern = { ( CC | BA ) ?? ?? ?? ?? 48 85 D2 74 07 48 8B 15 ?? ?? ?? ?? 31 F6 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule strtok_c9fde564b625fabca079897b988aa4a4 {
	meta:
		aliases = "__GI_strtok, strtok"
		size = "10"
		objfiles = "strtok@libc.a"
	strings:
		$pattern = { ( CC | BA ) ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule dlclose_14e4961eaae9d5cbbc74b1b990c2b36f {
	meta:
		aliases = "dlclose"
		size = "10"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | BE ) 01 00 00 00 E9 85 FD FF FF }
	condition:
		$pattern
}

rule timelocal_ae5deb625d6542f0fb1be4f85b9638ed {
	meta:
		aliases = "mkstemp64, iswalnum, __GI_iswalnum, mktime, timelocal"
		size = "10"
		objfiles = "iswalnum@libc.a, mkstemp64@libc.a, mktime@libc.a"
	strings:
		$pattern = { ( CC | BE ) 01 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_iswalpha_3c375beb103155c6a33059d7b231a969 {
	meta:
		aliases = "iswalpha, __GI_iswalpha"
		size = "10"
		objfiles = "iswalpha@libc.a"
	strings:
		$pattern = { ( CC | BE ) 02 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule iswblank_bed7e514c64bf14cb88ed13f99892ae5 {
	meta:
		aliases = "__GI_iswblank, iswblank"
		size = "10"
		objfiles = "iswblank@libc.a"
	strings:
		$pattern = { ( CC | BE ) 03 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_iswcntrl_1b7732dee6c5bae2b1d60159ca98eb5b {
	meta:
		aliases = "iswcntrl, __GI_iswcntrl"
		size = "10"
		objfiles = "iswcntrl@libc.a"
	strings:
		$pattern = { ( CC | BE ) 04 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule iswdigit_f1d9f4caefd560dc10bd9efee025460b {
	meta:
		aliases = "svcerr_weakauth, __GI_iswdigit, iswdigit"
		size = "10"
		objfiles = "iswdigit@libc.a, svc@libc.a"
	strings:
		$pattern = { ( CC | BE ) 05 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule iswgraph_7db32519021c9b397fad93748d444d56 {
	meta:
		aliases = "__GI_iswgraph, iswgraph"
		size = "10"
		objfiles = "iswgraph@libc.a"
	strings:
		$pattern = { ( CC | BE ) 06 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_iswlower_3b1c82a68426c71959409111fd79f31f {
	meta:
		aliases = "iswlower, __GI_iswlower"
		size = "10"
		objfiles = "iswlower@libc.a"
	strings:
		$pattern = { ( CC | BE ) 07 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule iswprint_679e3f385c17d4a4a82053da7d05db26 {
	meta:
		aliases = "__GI_iswprint, iswprint"
		size = "10"
		objfiles = "iswprint@libc.a"
	strings:
		$pattern = { ( CC | BE ) 08 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_iswpunct_0ed944a3a3af939bbd07dad461f792ee {
	meta:
		aliases = "iswpunct, __GI_iswpunct"
		size = "10"
		objfiles = "iswpunct@libc.a"
	strings:
		$pattern = { ( CC | BE ) 09 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule iswspace_f0d51a66bd4a587af6ec118880e6a500 {
	meta:
		aliases = "__GI_iswspace, iswspace"
		size = "10"
		objfiles = "iswspace@libc.a"
	strings:
		$pattern = { ( CC | BE ) 0A 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_iswupper_faa9dca734d3f1dd2a9643ea8b61179e {
	meta:
		aliases = "iswupper, __GI_iswupper"
		size = "10"
		objfiles = "iswupper@libc.a"
	strings:
		$pattern = { ( CC | BE ) 0B 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule iswxdigit_d10346bdce587ebb0e65da5c485269b7 {
	meta:
		aliases = "__GI_iswxdigit, iswxdigit"
		size = "10"
		objfiles = "iswxdigit@libc.a"
	strings:
		$pattern = { ( CC | BE ) 0C 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule inet_ntoa_aedd30f4a92f36ce8e0b990c7b4f97a2 {
	meta:
		aliases = "ether_aton, __GI_asctime, hcreate, __GI_inet_ntoa, srand48, ether_ntoa, asctime, inet_ntoa"
		size = "10"
		objfiles = "hsearch@libc.a, asctime@libc.a, ether_addr@libc.a, inet_ntoa@libc.a, srand48@libc.a"
	strings:
		$pattern = { ( CC | BE ) ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule lgamma_8c47b9c6008fc75a3442b25215b4f0fe {
	meta:
		aliases = "getlogin, __ieee754_lgamma, __GI_lgamma, _flushlbf, __ieee754_gamma, __pthread_once_fork_prepare, gamma, __pthread_once_fork_parent, hdestroy, __GI_getlogin, lgamma"
		size = "10"
		objfiles = "_flushlbf@libc.a, w_lgamma@libm.a, hsearch@libc.a, e_gamma@libm.a, e_lgamma@libm.a"
	strings:
		$pattern = { ( CC | BF ) ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __stub1_2b6be1eb3c8d07c259f5da1535d26263 {
	meta:
		aliases = "clntudp_abort, clntunix_abort, __linuxthreads_create_event, clntraw_abort, __pthread_return_void, __stub2, __cyg_profile_func_enter, authnone_destroy, pthread_null_sighandler, pthread_handle_sigdebug, svcraw_destroy, clntraw_geterr, __linuxthreads_death_event, _pthread_cleanup_push_defer, authunix_nextverf, _pthread_cleanup_pop_restore, xdrmem_destroy, noop_handler, clntraw_destroy, __cyg_profile_func_exit, clnttcp_abort, __linuxthreads_reap_event, authnone_verf, __stub1"
		size = "1"
		objfiles = "lckpwdf@libc.a, clnt_raw@libc.a, clnt_udp@libc.a, xdr_mem@libc.a, noophooks@libc.a"
	strings:
		$pattern = { ( CC | C3 ) }
	condition:
		$pattern
}

rule __md5_Init_926032e0aab3f9ea91e4121612375110 {
	meta:
		aliases = "__md5_Init"
		size = "42"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | C7 ) 47 14 00 00 00 00 C7 47 10 00 00 00 00 C7 07 01 23 45 67 C7 47 04 89 AB CD EF C7 47 08 FE DC BA 98 C7 47 0C 76 54 32 10 C3 }
	condition:
		$pattern
}

rule __powixf2_b1fc2a84fa40a1974d169875b70056fa {
	meta:
		aliases = "__powixf2"
		size = "61"
		objfiles = "_powixf2@libgcc.a"
	strings:
		$pattern = { ( CC | DB ) 6C 24 08 89 F8 C1 F8 1F 89 C2 31 FA 29 C2 F6 C2 01 D9 E8 DB C9 EB 02 D9 C9 D1 EA 74 13 D9 C9 F6 C2 01 D8 C8 74 F1 D1 EA DC C9 75 F3 DF C0 EB 02 DD D9 85 FF 79 04 D9 E8 DE F1 F3 C3 }
	condition:
		$pattern
}

rule __fixunsxfdi_d5a6b3d1e030009155f12722743978af {
	meta:
		aliases = "__fixunsxfdi"
		size = "104"
		objfiles = "_fixunsxfsi@libgcc.a"
	strings:
		$pattern = { ( CC | DB ) 6C 24 08 DB 2D ?? ?? ?? ?? D9 C9 DB E9 72 33 D9 7C 24 F6 0F B7 44 24 F6 DE E1 80 CC 0C 66 89 44 24 F4 48 B8 00 00 00 00 00 00 00 80 D9 6C 24 F4 DF 7C 24 E8 D9 6C 24 F6 48 8B 54 24 E8 48 8D 04 02 C3 DD D9 D9 7C 24 F6 0F B7 44 24 F6 80 CC 0C 66 89 44 24 F4 D9 6C 24 F4 DF 7C 24 E8 D9 6C 24 F6 48 8B 44 24 E8 C3 }
	condition:
		$pattern
}

rule __GI_pthread_self_94a1c794f10558b3f9b9062573c664f5 {
	meta:
		aliases = "pthread_self, __GI_pthread_self"
		size = "10"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | E8 ) B6 FF FF FF 48 8B 40 20 C3 }
	condition:
		$pattern
}

rule __re_match_2_a3ba4fc4df09b1a1ddd6bc4472ce28ec {
	meta:
		aliases = "re_match_2, __re_match_2"
		size = "5"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | E9 ) 2B E1 FF FF }
	condition:
		$pattern
}

rule svcfd_create_8e8d23c71f4f29bd84e7b2c074951f75 {
	meta:
		aliases = "svcunixfd_create, svcfd_create"
		size = "5"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | E9 ) 36 FF FF FF }
	condition:
		$pattern
}

rule __re_compile_fastmap_0fac84db41cd84c3653e6e129426762c {
	meta:
		aliases = "re_compile_fastmap, __re_compile_fastmap"
		size = "5"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | E9 ) 63 FC FF FF }
	condition:
		$pattern
}

rule __GI_fmod_22aa66de8a720f160758a4fe68aab955 {
	meta:
		aliases = "ftell, pow, __GI_exp, exp, remainder, __GI_remainder, sqrt, atan2, scalb, __GI_setmntent, __GI_sqrt, __decode_packet, __GI_nearbyint, atanh, __GI_log, log2, mmap64, __ieee754_gamma_r, log10, lgamma_r, ftruncate64, cabs, cosh, truncate64, __GI_ftruncate64, y0, nearbyint, lseek64, j0, xdr_longlong_t, __GI_log10, __GI_acos, fseek, log, sinh, acos, j1, suspend, __GI_atanh, fseeko, ftello, drem, restart, __GI_acosh, __GI_pow, __libc_lseek64, yn, jn, __GI_cabs, asin"
		size = "5"
		objfiles = "w_asin@libm.a, w_atan2@libm.a, truncate64@libc.a, w_remainder@libm.a, ftello@libc.a"
	strings:
		$pattern = { ( CC | E9 ) ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_initialize_254caf1915d414e38380d56bb4684b03 {
	meta:
		aliases = "__pthread_initialize"
		size = "5"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | E9 ) A4 FB FF FF }
	condition:
		$pattern
}

rule _dl_parse_dynamic_info_942f62783667019d2fd96b2a6000ec85 {
	meta:
		aliases = "_dl_parse_dynamic_info"
		size = "306"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | E9 ) B4 00 00 00 49 83 F8 21 7F 73 48 8B 47 08 4A 89 04 C6 48 83 3F 15 75 04 48 89 57 08 48 83 3F 18 75 0B 48 C7 86 C0 00 00 00 01 00 00 00 48 83 3F 1E 75 11 F6 47 08 08 74 0B 48 C7 86 C0 00 00 00 01 00 00 00 48 83 3F 16 75 0B 48 C7 86 B0 00 00 00 01 00 00 00 48 83 3F 1D 75 08 48 C7 46 78 00 00 00 00 48 83 3F 0F 75 4B 48 83 BE E8 00 00 00 00 74 41 48 C7 46 78 00 00 00 00 EB 37 49 81 F8 FF FF FF 6F 7F 2E 49 81 F8 F9 FF FF 6F 75 0B 48 8B 47 08 48 89 86 10 01 00 00 48 81 3F FB FF FF 6F 75 11 F6 47 08 01 74 0B 48 C7 86 C0 00 00 00 01 00 00 00 48 83 C7 10 4C 8B 07 4D 85 C0 0F 85 40 FF FF FF 48 8B 46 }
	condition:
		$pattern
}

rule wmemcmp_8c5d96f084984dff7435e3680cc16d45 {
	meta:
		aliases = "wmemcmp"
		size = "37"
		objfiles = "wmemcmp@libc.a"
	strings:
		$pattern = { ( CC | EB ) 0B 48 83 C7 04 48 83 C6 04 48 FF CA 48 85 D2 74 08 8B 07 3B 06 74 EA EB 03 31 C0 C3 3B 06 19 C0 83 C8 01 C3 }
	condition:
		$pattern
}

rule rawmemchr_e06e0e629646b496bba6ccdea46e4a98 {
	meta:
		aliases = "__GI_rawmemchr, rawmemchr"
		size = "190"
		objfiles = "rawmemchr@libc.a"
	strings:
		$pattern = { ( CC | EB ) 0C 40 38 37 75 04 48 89 F8 C3 48 FF C7 40 F6 C7 07 75 EE 40 0F B6 C6 48 89 F9 89 C2 C1 E2 08 09 D0 48 98 48 89 C2 48 C1 E2 10 48 09 C2 48 89 D7 48 C1 E7 20 48 09 D7 48 89 F8 48 33 01 48 BA FF FE FE FE FE FE FE 7E 48 83 C1 08 48 8D 14 10 48 F7 D0 48 31 C2 48 B8 00 01 01 01 01 01 01 81 48 85 D0 74 D3 40 38 71 F8 48 8D 41 F8 74 4E 40 38 71 F9 48 8D 50 01 74 32 40 38 71 FA 48 8D 50 02 74 28 40 38 71 FB 48 8D 50 03 74 1E 40 38 71 FC 48 8D 50 04 74 14 40 38 71 FD 48 8D 50 05 74 0A 40 38 71 FE 48 8D 50 06 75 04 48 89 D0 C3 48 83 C0 07 40 38 71 FF 0F 85 7B FF FF FF C3 }
	condition:
		$pattern
}

rule wcscoll_25ca9a377c9ce6e76df1724b828a0c39 {
	meta:
		aliases = "wcscmp, __GI_wcscoll, __GI_wcscmp, wcscoll"
		size = "36"
		objfiles = "wcscmp@libc.a"
	strings:
		$pattern = { ( CC | EB ) 0D 83 3F 00 74 14 48 83 C7 04 48 83 C6 04 8B 06 39 07 74 ED 73 07 83 C8 FF C3 31 C0 C3 B8 01 00 00 00 C3 }
	condition:
		$pattern
}

rule __GI_wmemchr_bcf29108158559da106fd6988a9da38c {
	meta:
		aliases = "wmemchr, __GI_wmemchr"
		size = "25"
		objfiles = "wmemchr@libc.a"
	strings:
		$pattern = { ( CC | EB ) 0F 39 37 75 04 48 89 F8 C3 48 83 C7 04 48 FF CA 48 85 D2 75 EC 31 C0 C3 }
	condition:
		$pattern
}

rule __GI_wmempcpy_1c22bd8efcce147d639d2c8c46605ea5 {
	meta:
		aliases = "wmempcpy, __GI_wmempcpy"
		size = "26"
		objfiles = "wmempcpy@libc.a"
	strings:
		$pattern = { ( CC | EB ) 0F 8B 06 48 FF CA 48 83 C6 04 89 07 48 83 C7 04 48 85 D2 75 EC 48 89 F8 C3 }
	condition:
		$pattern
}

rule any_f193759333502c58bc2d158992b667a3 {
	meta:
		aliases = "any"
		size = "35"
		objfiles = "getnetent@libc.a"
	strings:
		$pattern = { ( CC | EB ) 10 38 CA 74 19 48 FF C0 8A 10 84 D2 75 F3 48 FF C7 8A 0F 84 C9 74 05 48 89 F0 EB EC 31 FF 48 89 F8 C3 }
	condition:
		$pattern
}

rule wcsncmp_597710ddb7f72faf2d36ed7c6f84da42 {
	meta:
		aliases = "wcsncmp"
		size = "35"
		objfiles = "wcsncmp@libc.a"
	strings:
		$pattern = { ( CC | EB ) 10 83 3F 00 74 19 48 83 C7 04 48 83 C6 04 48 FF CA 48 85 D2 74 09 8B 07 3B 06 74 E5 2B 06 C3 31 C0 C3 }
	condition:
		$pattern
}

rule wcspbrk_4031c7110ff5f81b1aaaa7cfa0066386 {
	meta:
		aliases = "__GI_wcspbrk, wcspbrk"
		size = "38"
		objfiles = "wcspbrk@libc.a"
	strings:
		$pattern = { ( CC | EB ) 12 39 CA 74 19 48 83 C0 04 8B 10 85 D2 75 F2 48 83 C7 04 8B 0F 85 C9 74 09 48 89 F0 EB EB 48 89 F8 C3 31 C0 C3 }
	condition:
		$pattern
}

rule strchrnul_bab1ed7ceebefd35fb6eeb0ae4d56993 {
	meta:
		aliases = "__GI_strchrnul, strchrnul"
		size = "265"
		objfiles = "strchrnul@libc.a"
	strings:
		$pattern = { ( CC | EB ) 12 8A 07 40 38 F0 74 04 84 C0 75 04 48 89 F8 C3 48 FF C7 40 F6 C7 07 75 E8 40 0F B6 C6 89 C2 C1 E2 08 09 D0 48 98 48 89 C2 48 C1 E2 10 48 09 C2 49 89 D2 49 C1 E2 20 49 09 D2 48 8B 0F 49 B9 FF FE FE FE FE FE FE 7E 49 B8 00 01 01 01 01 01 01 81 48 83 C7 08 4A 8D 04 09 48 89 CA 48 F7 D2 48 31 D0 49 85 C0 75 15 48 89 C8 4C 31 D0 4A 8D 14 08 48 F7 D0 48 31 C2 49 85 D0 74 BE 8A 57 F8 48 8D 47 F8 40 38 F2 74 7F 84 D2 74 7B 8A 57 F9 48 8D 48 01 40 38 F2 74 54 84 D2 74 50 8A 57 FA 48 8D 48 02 40 38 F2 74 44 84 D2 74 40 8A 57 FB 48 8D 48 03 40 38 F2 74 34 84 D2 74 30 8A 57 FC 48 8D 48 04 40 38 F2 74 }
	condition:
		$pattern
}

rule __md5_to64_1df521c4850fd18843d78715ce926229 {
	meta:
		aliases = "__md5_to64"
		size = "28"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | EB ) 15 48 89 F0 48 C1 EE 06 83 E0 3F 8A 80 ?? ?? ?? ?? 88 07 48 FF C7 FF CA 79 E7 C3 }
	condition:
		$pattern
}

rule remove_from_queue_48b51e17db8aeec28dd826c0f7789e92 {
	meta:
		aliases = "remove_from_queue"
		size = "43"
		objfiles = "condvar@libpthread.a, semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | EB ) 1E 48 39 F2 75 15 48 8B 42 10 48 89 07 B8 01 00 00 00 48 C7 42 10 00 00 00 00 C3 48 8D 7A 10 48 8B 17 48 85 D2 75 DA 31 C0 C3 }
	condition:
		$pattern
}

rule __fixunsdfti_662b1ac8e3e0ca1a862c36cd0d302a23 {
	meta:
		aliases = "__fixunsdfti"
		size = "168"
		objfiles = "_fixunsdfdi@libgcc.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 10 C8 66 0F 12 15 ?? ?? ?? ?? 53 F2 0F 59 0D ?? ?? ?? ?? 66 0F 2E CA 73 3B F2 48 0F 2C C9 31 F6 48 85 C9 48 89 CF 78 4C F2 48 0F 2A C9 F2 0F 59 0D ?? ?? ?? ?? F2 0F 58 C8 66 0F 2E CA 73 4F F2 48 0F 2C D1 48 89 F0 31 DB 48 09 D0 48 89 FA 48 09 DA 5B C3 F2 0F 5C CA 48 B8 00 00 00 00 00 00 00 80 31 F6 F2 48 0F 2C C9 48 31 C1 48 85 C9 48 89 CF 79 B4 48 89 C8 83 E1 01 48 D1 E8 48 09 C8 F2 48 0F 2A C8 F2 0F 58 C9 EB A2 66 66 90 F2 0F 5C CA 48 B8 00 00 00 00 00 00 00 80 F2 48 0F 2C D1 48 31 C2 EB 9E }
	condition:
		$pattern
}

rule __divdc3_07a4b1052d08f50ecc8bc516525c8f66 {
	meta:
		aliases = "__divdc3"
		size = "853"
		objfiles = "_divdc3@libgcc.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 10 F2 F2 0F 10 F8 F2 0F 10 15 ?? ?? ?? ?? F2 44 0F 10 C1 F2 0F 10 C3 F2 0F 10 CE 66 0F 54 C2 66 0F 54 CA 66 0F 2E C1 76 47 F2 0F 10 CE F2 0F 10 C6 F2 0F 10 E7 F2 41 0F 10 E8 F2 0F 5E CB F2 0F 59 C1 F2 0F 59 E1 F2 0F 59 E9 F2 0F 58 C3 F2 41 0F 58 E0 F2 0F 5C EF F2 0F 5E E0 F2 0F 5E E8 66 0F 2E E4 7A 43 75 41 F2 0F 10 CD F2 0F 10 C4 C3 F2 0F 10 C3 F2 0F 10 CB F2 41 0F 10 E0 F2 41 0F 10 E8 F2 0F 5E C6 F2 0F 59 C8 F2 0F 59 E0 F2 0F 59 C7 F2 0F 58 CE F2 0F 58 E7 F2 0F 5C E8 F2 0F 5E E1 F2 0F 5E E9 EB B7 66 0F 2E ED 7A 02 74 B7 66 45 0F 57 C9 66 41 0F 2E F1 66 66 66 90 75 14 7A 12 66 41 0F 2E }
	condition:
		$pattern
}

rule __muldc3_63d936812c84703598b4736fdb863994 {
	meta:
		aliases = "__muldc3"
		size = "802"
		objfiles = "_muldc3@libgcc.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 10 F8 F2 44 0F 10 C1 F2 44 0F 10 C8 F2 44 0F 10 D2 F2 0F 59 FA F2 0F 10 E8 F2 44 0F 59 C3 F2 44 0F 59 CB F2 44 0F 59 D1 F2 0F 10 E7 F2 41 0F 5C E0 F2 41 0F 10 F1 F2 41 0F 58 F2 66 0F 2E E4 7A 0B 75 09 F2 0F 10 CE F2 0F 10 C4 C3 66 0F 2E F6 7A 02 74 EF F2 0F 10 C5 66 0F 2E ED 0F 9B C2 F2 0F 5C C5 66 0F 2E C0 0F 9A C0 84 D0 0F 85 AF 00 00 00 F2 0F 10 C1 66 0F 2E C9 0F 9B C2 F2 0F 5C C1 66 0F 2E C0 0F 9A C0 84 D0 0F 85 28 01 00 00 31 C9 66 0F 2E DB 0F 9A C1 31 F6 66 0F 2E D2 40 0F 9A C6 31 FF F2 0F 10 C2 48 85 F6 0F 94 C2 F2 0F 5C C2 66 0F 2E C0 0F 9A C0 84 D0 0F 85 19 02 00 00 F2 0F 10 C3 }
	condition:
		$pattern
}

rule __GI_lrint_5c209059809ea5b07deee5fd6c4297eb {
	meta:
		aliases = "lrint, __GI_lrint"
		size = "329"
		objfiles = "s_lrint@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 E8 48 8B 54 24 E8 48 89 D0 48 C1 EA 20 89 D7 41 89 D0 C1 EF 14 41 C1 E8 1F 81 E7 FF 07 00 00 8D 8F 01 FC FF FF 83 F9 13 7F 59 31 F6 FF C1 0F 8C 0C 01 00 00 49 63 C0 B9 13 04 00 00 66 0F 12 0C C5 ?? ?? ?? ?? F2 0F 58 C1 F2 0F 11 44 24 F8 66 0F 12 44 24 F8 F2 0F 5C C1 66 48 0F 7E C0 48 C1 E8 20 89 C2 C1 E8 14 81 E2 FF FF 0F 00 25 FF 07 00 00 81 CA 00 00 10 00 29 C1 D3 EA 89 D6 E9 B0 00 00 00 83 F9 3E 0F 8F A0 00 00 00 83 F9 33 7E 26 48 89 D6 8D 8F ED FB FF FF 81 E6 FF FF 0F 00 48 81 CE 00 00 10 00 48 D3 E6 8D 8F CD FB FF FF D3 E0 48 09 C6 EB 7C 49 63 C0 66 0F 12 0C C5 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule llrint_7d520fd2ab48590577eb008562fde389 {
	meta:
		aliases = "__GI_llrint, llrint"
		size = "330"
		objfiles = "s_llrint@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 E8 48 8B 54 24 E8 48 89 D6 48 89 D0 48 C1 EE 20 89 F1 41 89 F0 C1 E9 14 41 C1 E8 1F 81 E1 FF 07 00 00 8D 91 01 FC FF FF 83 FA 13 7F 5C 49 63 C0 31 F6 66 0F 12 0C C5 ?? ?? ?? ?? F2 0F 58 C1 F2 0F 11 44 24 F8 66 0F 12 44 24 F8 F2 0F 5C C1 66 48 0F 7E C2 48 C1 EA 20 89 D0 C1 E8 14 25 FF 07 00 00 2D FF 03 00 00 0F 88 C7 00 00 00 81 E2 FF FF 0F 00 B9 14 00 00 00 81 CA 00 00 10 00 29 C1 D3 EA 89 D6 E9 AB 00 00 00 83 FA 3E 0F 8F 9B 00 00 00 83 FA 33 7E 21 81 E6 FF FF 0F 00 89 C0 81 E9 33 04 00 00 48 81 CE 00 00 10 00 48 C1 E6 20 48 09 C6 48 D3 E6 EB 7C 49 63 C0 66 0F 12 0C C5 ?? ?? ?? }
	condition:
		$pattern
}

rule __isinf_834715cbceed0e539414bad977b171ed {
	meta:
		aliases = "__GI___isinf, __isinf"
		size = "52"
		objfiles = "s_isinf@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 48 89 C1 48 89 C2 48 C1 E9 20 89 C8 C1 F9 1E 25 FF FF FF 7F 35 00 00 F0 7F 09 D0 89 C2 F7 DA 09 D0 C1 F8 1F F7 D0 21 C8 C3 }
	condition:
		$pattern
}

rule __isnan_f8ffc086038aea27c5ee096dfed0ed0b {
	meta:
		aliases = "__GI___isnan, __isnan"
		size = "47"
		objfiles = "s_isnan@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 48 89 C2 48 89 C1 F7 D8 48 C1 E9 20 09 D0 C1 E8 1F 81 E1 FF FF FF 7F 09 C1 B8 00 00 F0 7F 29 C8 C1 E8 1F C3 }
	condition:
		$pattern
}

rule fabs_d15ae3e46453ed04b5c85ec554c7799d {
	meta:
		aliases = "__GI_fabs, fabs"
		size = "48"
		objfiles = "s_fabs@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 48 BA 00 00 00 00 FF FF FF 7F 48 89 C1 83 E0 FF 48 21 D1 48 09 C8 48 89 44 24 F8 66 0F 12 4C 24 F8 0F 28 C1 C3 }
	condition:
		$pattern
}

rule __GI_copysign_5c72e606899e70712f77f6af02eb0153 {
	meta:
		aliases = "copysign, __GI_copysign"
		size = "66"
		objfiles = "s_copysign@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 66 48 0F 7E C9 48 C1 E9 20 48 89 C2 81 E1 00 00 00 80 83 E0 FF 48 C1 EA 20 81 E2 FF FF FF 7F 09 CA 48 C1 E2 20 48 09 D0 48 89 44 24 F8 66 0F 12 4C 24 F8 0F 28 C1 C3 }
	condition:
		$pattern
}

rule __GI_rint_09f69f3049d775016991af8b016c84a1 {
	meta:
		aliases = "rint, __GI_rint"
		size = "387"
		objfiles = "s_rint@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 54 24 F8 0F 28 C8 48 89 D6 48 C1 EE 20 89 F0 41 89 F0 C1 F8 14 41 C1 E8 1F 25 FF 07 00 00 8D B8 01 FC FF FF 83 FF 13 0F 8F EA 00 00 00 85 FF 0F 89 A0 00 00 00 89 F0 25 FF FF FF 7F 09 D0 0F 84 33 01 00 00 89 F0 81 E6 00 00 FE FF 25 FF FF 0F 00 09 D0 48 8B 54 24 F8 48 89 D1 89 C2 F7 DA 83 E1 FF 09 D0 C1 E8 0C 25 00 00 08 00 09 C6 48 89 F0 48 C1 E0 20 48 09 C1 49 63 C0 41 C1 E0 1F 48 89 4C 24 F8 66 0F 12 0C C5 ?? ?? ?? ?? 66 0F 12 44 24 F8 F2 0F 58 C1 F2 0F 5C C1 F2 0F 11 44 24 F8 48 8B 4C 24 F8 48 89 C8 48 89 CA 48 C1 E8 20 83 E2 FF 25 FF FF FF 7F 44 09 C0 48 C1 E0 20 48 }
	condition:
		$pattern
}

rule __GI_log1p_2492e244850ae9e9930588a295e894ee {
	meta:
		aliases = "log1p, __GI_log1p"
		size = "803"
		objfiles = "s_log1p@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 54 24 F8 0F 28 D0 48 C1 EA 20 81 FA 79 82 DA 3F 0F 8F 95 00 00 00 89 D0 25 FF FF FF 7F 3D FF FF EF 3F 7E 2E 66 0F 2E 05 ?? ?? ?? ?? 75 17 7A 15 66 0F 12 15 ?? ?? ?? ?? F2 0F 5E 15 ?? ?? ?? ?? E9 D2 02 00 00 F2 0F 5C D2 F2 0F 5E D2 E9 C5 02 00 00 3D FF FF 1F 3E 7F 3B F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 0F 97 C2 3D FF FF 8F 3C 0F 9E C0 84 D0 0F 85 9B 02 00 00 0F 28 C2 F2 0F 59 C2 F2 0F 59 05 ?? ?? ?? ?? F2 0F 58 D0 E9 83 02 00 00 8D 82 3C 41 2D 40 31 F6 B9 01 00 00 00 0F 28 E8 3D 3C 41 2D 40 77 0A 0F 57 ED BE 01 00 00 00 31 C9 81 FA FF FF EF 7F 7E 09 F2 0F 58 }
	condition:
		$pattern
}

rule __kernel_cos_4be9c96587846094f8f463247e9e7428 {
	meta:
		aliases = "__kernel_cos"
		size = "274"
		objfiles = "k_cos@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 54 24 F8 0F 28 E0 48 89 D0 48 C1 E8 20 89 C2 81 E2 FF FF FF 7F 81 FA FF FF 3F 3E 7F 15 F2 0F 2C C0 85 C0 75 0D 66 0F 12 35 ?? ?? ?? ?? E9 D4 00 00 00 0F 28 DC 81 FA 32 33 D3 3F F2 0F 59 DC 0F 28 D3 F2 0F 59 15 ?? ?? ?? ?? F2 0F 58 15 ?? ?? ?? ?? F2 0F 59 D3 F2 0F 5C 15 ?? ?? ?? ?? F2 0F 59 D3 F2 0F 58 15 ?? ?? ?? ?? F2 0F 59 D3 F2 0F 5C 15 ?? ?? ?? ?? F2 0F 59 D3 F2 0F 58 15 ?? ?? ?? ?? F2 0F 59 D3 7F 25 0F 28 C3 F2 0F 59 E1 F2 0F 59 DA 66 0F 12 35 ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? F2 0F 5C DC F2 0F 5C C3 EB 55 81 FA 00 00 E9 3F 7E 0A 66 0F 12 2D ?? ?? ?? ?? EB 18 8D }
	condition:
		$pattern
}

rule __kernel_sin_72518299f4906111f7252ea046065c2e {
	meta:
		aliases = "__kernel_sin"
		size = "187"
		objfiles = "k_sin@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 54 24 F8 0F 28 E8 48 89 D0 48 C1 E8 20 25 FF FF FF 7F 3D FF FF 3F 3E 7F 0C F2 0F 2C C0 85 C0 0F 84 8A 00 00 00 0F 28 DD 85 FF 66 0F 12 35 ?? ?? ?? ?? F2 0F 59 DD 0F 28 D3 0F 28 E3 F2 0F 59 15 ?? ?? ?? ?? F2 0F 59 E5 F2 0F 5C 15 ?? ?? ?? ?? F2 0F 59 D3 F2 0F 58 15 ?? ?? ?? ?? F2 0F 59 D3 F2 0F 5C 15 ?? ?? ?? ?? F2 0F 59 D3 F2 0F 58 15 ?? ?? ?? ?? 75 12 F2 0F 59 DA F2 0F 5C DE F2 0F 59 E3 F2 0F 58 EC EB 27 0F 28 C1 F2 0F 59 D4 F2 0F 59 E6 F2 0F 59 05 ?? ?? ?? ?? F2 0F 5C C2 F2 0F 59 D8 F2 0F 5C D9 F2 0F 58 DC F2 0F 5C EB 0F 28 C5 C3 }
	condition:
		$pattern
}

rule __ieee754_log_c87cb8c465676f43a6e686b4fac02c1a {
	meta:
		aliases = "__ieee754_log"
		size = "633"
		objfiles = "e_log@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 54 24 F8 48 89 D0 48 C1 EA 20 89 C1 31 C0 81 FA FF FF 0F 00 7F 49 89 D0 25 FF FF FF 7F 09 C8 75 0A 66 0F 12 15 ?? ?? ?? ?? EB 0B 85 D2 79 14 0F 28 D0 F2 0F 5C D0 F2 0F 5E 15 ?? ?? ?? ?? E9 2A 02 00 00 F2 0F 59 05 ?? ?? ?? ?? B8 CA FF FF FF F2 0F 11 44 24 F8 48 8B 54 24 F8 48 C1 EA 20 81 FA FF FF EF 7F 0F 28 D0 0F 8F 97 00 00 00 89 D6 89 D7 F2 0F 11 44 24 F8 81 E7 FF FF 0F 00 C1 FE 14 8D B4 30 01 FC FF FF 8D 97 64 5F 09 00 48 8B 44 24 F8 81 E2 00 00 10 00 48 89 C1 89 D0 C1 FA 14 35 00 00 F0 3F 83 E1 FF 01 D6 09 F8 48 C1 E0 20 48 09 C1 8D 47 02 48 89 4C 24 F8 66 0F 12 6C }
	condition:
		$pattern
}

rule __ieee754_log2_29435da672aa95bb5ffb5562e77692a2 {
	meta:
		aliases = "__ieee754_log2"
		size = "505"
		objfiles = "e_log2@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 54 24 F8 48 89 D0 48 C1 EA 20 89 C1 31 C0 81 FA FF FF 0F 00 7F 50 89 D0 25 FF FF FF 7F 09 C8 75 15 F2 0F 5C C0 66 0F 12 2D ?? ?? ?? ?? F2 0F 5E E8 E9 B7 01 00 00 85 D2 79 10 0F 28 E8 F2 0F 5C E8 F2 0F 5E ED E9 A3 01 00 00 F2 0F 59 05 ?? ?? ?? ?? B8 CA FF FF FF F2 0F 11 44 24 F8 48 8B 54 24 F8 48 C1 EA 20 81 FA FF FF EF 7F 0F 28 E8 0F 8F 5B 01 00 00 89 D6 89 D7 F2 0F 11 44 24 F8 81 E7 FF FF 0F 00 C1 FE 14 8D B4 30 01 FC FF FF 8D 97 64 5F 09 00 48 8B 44 24 F8 81 E2 00 00 10 00 48 89 C1 89 D0 C1 FA 14 35 00 00 F0 3F 83 E1 FF 01 D6 09 F8 F2 0F 2A EE 48 C1 E0 20 48 09 C1 8D }
	condition:
		$pattern
}

rule __GI_lround_fab6931e2431ee60b1e99942449752fc {
	meta:
		aliases = "lround, __GI_lround"
		size = "205"
		objfiles = "s_lround@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 54 24 F8 48 89 D0 48 C1 EA 20 89 C7 89 D0 41 89 D0 C1 E8 14 41 C1 F8 1F 81 E2 FF FF 0F 00 25 FF 07 00 00 41 83 C8 01 81 CA 00 00 10 00 8D B0 01 FC FF FF 83 FE 13 7F 2A 85 F6 79 0D 31 C9 49 63 C0 FF C6 48 0F 44 C8 EB 78 89 F1 B8 00 00 08 00 D3 F8 B9 14 00 00 00 8D 04 02 29 F1 D3 E8 89 C2 EB 58 83 FE 3E 7F 4C 83 FE 33 7E 18 8D 88 ED FB FF FF 89 D2 48 D3 E2 8D 88 CD FB FF FF D3 E7 48 09 FA EB 36 8D 88 ED FB FF FF B8 00 00 00 80 D3 E8 8D 04 07 39 F8 83 D2 00 83 FE 14 89 D2 74 1A 48 D3 E2 B9 34 00 00 00 29 F1 D3 E8 89 C0 48 09 C2 EB 07 F2 48 0F 2C C8 EB 07 49 63 C8 48 0F AF }
	condition:
		$pattern
}

rule llround_66275e62fb7dd0ed3e778f9bc7850136 {
	meta:
		aliases = "__GI_llround, llround"
		size = "202"
		objfiles = "s_llround@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 54 24 F8 48 89 D0 48 C1 EA 20 89 D1 41 89 D0 81 E2 FF FF 0F 00 C1 E9 14 41 C1 F8 1F 81 CA 00 00 10 00 81 E1 FF 07 00 00 41 83 C8 01 89 C7 8D B1 01 FC FF FF 83 FE 13 7F 2A 85 F6 79 0D 31 C9 49 63 C0 FF C6 48 0F 44 C8 EB 74 89 F1 B8 00 00 08 00 D3 F8 B9 14 00 00 00 8D 04 02 29 F1 D3 E8 89 C2 EB 54 83 FE 3E 7F 48 83 FE 33 7E 14 48 C1 E2 20 89 C0 81 E9 33 04 00 00 48 09 C2 48 D3 E2 EB 36 81 E9 13 04 00 00 B8 00 00 00 80 D3 E8 8D 04 07 39 F8 83 D2 00 83 FE 14 89 D2 74 1A 48 D3 E2 B9 34 00 00 00 29 F1 D3 E8 89 C0 48 09 C2 EB 07 F2 48 0F 2C C8 EB 07 49 63 C8 48 0F AF CA 48 89 }
	condition:
		$pattern
}

rule modf_f47fa7e09c9c08ed3fc960448b7c0785 {
	meta:
		aliases = "__GI_modf, modf"
		size = "186"
		objfiles = "s_modf@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 54 24 F8 48 89 D6 41 89 D0 48 C1 EE 20 89 F0 C1 F8 14 25 FF 07 00 00 8D 88 01 FC FF FF 83 F9 13 7F 36 85 C9 79 10 81 E6 00 00 00 80 89 F0 48 C1 E0 20 48 89 07 C3 BA FF FF 0F 00 89 F0 D3 FA 21 D0 44 09 C0 74 26 89 D0 F7 D0 21 F0 48 C1 E0 20 48 89 07 F2 0F 5C 07 C3 83 F9 33 7F 0F 8D 88 ED FB FF FF 83 C8 FF D3 E8 85 D0 75 30 F2 0F 11 44 24 F8 48 8B 54 24 F8 F2 0F 11 07 48 89 D0 48 C1 E8 20 25 00 00 00 80 89 C0 48 C1 E0 20 48 89 44 24 F8 66 0F 12 4C 24 F8 0F 28 C1 C3 F7 D0 21 C2 48 89 F0 48 C1 E0 20 48 09 D0 48 89 07 F2 0F 5C 07 C3 }
	condition:
		$pattern
}

rule trunc_60f0fa14df111357c092c05edb02b9e3 {
	meta:
		aliases = "__GI_trunc, trunc"
		size = "145"
		objfiles = "s_trunc@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 54 24 F8 48 89 D6 48 C1 EE 20 89 F0 C1 F8 14 25 FF 07 00 00 8D 88 01 FC FF FF 83 F9 13 7F 30 89 F2 81 E2 00 00 00 80 85 C9 89 D0 78 0F B8 FF FF 0F 00 D3 F8 F7 D0 21 C6 89 D0 09 F0 48 C1 E0 20 48 89 44 24 F8 66 0F 12 4C 24 F8 0F 28 C1 C3 83 F9 33 7E 0D 81 F9 00 04 00 00 75 2C F2 0F 58 C0 C3 8D 88 ED FB FF FF 83 C8 FF D3 E8 F7 D0 21 C2 48 89 F0 48 C1 E0 20 48 09 D0 48 89 44 24 F8 66 0F 12 4C 24 F8 0F 28 C1 C3 }
	condition:
		$pattern
}

rule ceil_1cc1312dcf5777c4b3ca007564d5adde {
	meta:
		aliases = "__GI_ceil, ceil"
		size = "287"
		objfiles = "s_ceil@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 54 24 F8 48 89 D6 48 C1 EE 20 89 F0 C1 F8 14 25 FF 07 00 00 8D B8 01 FC FF FF 83 FF 13 7F 7B 85 FF 79 37 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 0F 86 C3 00 00 00 85 F6 79 07 BE 00 00 00 80 EB 0F 89 F1 09 D1 0F 84 AE 00 00 00 BE 00 00 F0 3F 31 D2 E9 A2 00 00 00 41 B8 FF FF 0F 00 89 F9 89 F0 41 D3 F8 44 21 C0 09 D0 0F 84 A4 00 00 00 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 76 78 85 F6 7E 09 B8 00 00 10 00 D3 F8 01 C6 44 89 C0 F7 D0 21 C6 EB B9 83 FF 33 7E 0D 81 FF 00 04 00 00 75 6F F2 0F 58 C0 C3 8D 88 ED FB FF FF 41 83 C8 FF 41 D3 E8 41 85 D0 74 58 F2 0F }
	condition:
		$pattern
}

rule floor_2357a820968a2003aa5e27583d12bcbf {
	meta:
		aliases = "__GI_floor, floor"
		size = "289"
		objfiles = "s_floor@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 54 24 F8 48 89 D6 48 C1 EE 20 89 F0 C1 F8 14 25 FF 07 00 00 8D B8 01 FC FF FF 83 FF 13 7F 7D 85 FF 79 39 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 0F 86 C5 00 00 00 85 F6 78 04 31 F6 EB 14 89 F0 25 FF FF FF 7F 09 D0 0F 84 AE 00 00 00 BE 00 00 F0 BF 31 D2 E9 A2 00 00 00 41 B8 FF FF 0F 00 89 F9 89 F0 41 D3 F8 44 21 C0 09 D0 0F 84 A4 00 00 00 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 76 78 85 F6 79 09 B8 00 00 10 00 D3 F8 01 C6 44 89 C0 F7 D0 21 C6 EB B9 83 FF 33 7E 0D 81 FF 00 04 00 00 75 6F F2 0F 58 C0 C3 8D 88 ED FB FF FF 41 83 C8 FF 41 D3 E8 41 85 D0 74 58 }
	condition:
		$pattern
}

rule round_7b119fb54ab1077c756436b48393af49 {
	meta:
		aliases = "__GI_round, round"
		size = "267"
		objfiles = "s_round@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 54 24 F8 48 89 D7 48 C1 EF 20 89 F8 C1 F8 14 25 FF 07 00 00 8D B0 01 FC FF FF 83 FE 13 7F 73 85 F6 79 31 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 0F 86 AF 00 00 00 81 E7 00 00 00 80 31 D2 FF C6 0F 85 9F 00 00 00 81 CF 00 00 F0 3F E9 94 00 00 00 41 B8 FF FF 0F 00 89 F1 89 F8 41 D3 F8 44 21 C0 09 D0 0F 84 96 00 00 00 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 76 6A B8 00 00 08 00 31 D2 D3 F8 01 C7 44 89 C0 F7 D0 21 C7 EB 56 83 FE 33 7E 0D 81 FE 00 04 00 00 75 63 F2 0F 58 C0 C3 8D 88 ED FB FF FF 41 83 C8 FF 41 D3 E8 41 85 D0 74 4C F2 0F 58 05 ?? ?? ?? ?? 66 0F }
	condition:
		$pattern
}

rule qzero_53baef34a3915b580893fae54dd8f572 {
	meta:
		aliases = "qone, qzero"
		size = "241"
		objfiles = "e_j1@libm.a, e_j0@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 54 24 F8 B9 ?? ?? ?? ?? 0F 28 E0 48 89 D0 BA ?? ?? ?? ?? 48 C1 E8 20 25 FF FF FF 7F 3D FF FF 1F 40 7F 37 3D 8A 2E 12 40 BA ?? ?? ?? ?? B9 ?? ?? ?? ?? 7F 26 3D 6C DB 06 40 BA ?? ?? ?? ?? B9 ?? ?? ?? ?? 7F 15 3D FF FF FF 3F BA ?? ?? ?? ?? B9 ?? ?? ?? ?? 7F 04 31 D2 31 C9 0F 28 C4 66 0F 12 1D ?? ?? ?? ?? F2 0F 59 C4 0F 28 D3 F2 0F 5E D0 0F 28 CA 0F 28 C2 F2 0F 59 49 28 F2 0F 59 42 28 F2 0F 58 49 20 F2 0F 58 42 20 F2 0F 59 CA F2 0F 59 C2 F2 0F 58 49 18 F2 0F 58 42 18 F2 0F 59 CA F2 0F 59 C2 F2 0F 58 49 10 F2 0F 58 42 10 F2 0F 59 CA F2 0F 59 C2 F2 0F 58 49 08 F2 0F 58 42 08 }
	condition:
		$pattern
}

rule pone_6fde904916db62eb21793696ea5b59c9 {
	meta:
		aliases = "pzero, pone"
		size = "218"
		objfiles = "e_j1@libm.a, e_j0@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 54 24 F8 B9 ?? ?? ?? ?? 48 89 D0 BA ?? ?? ?? ?? 48 C1 E8 20 25 FF FF FF 7F 3D FF FF 1F 40 7F 37 3D 8A 2E 12 40 BA ?? ?? ?? ?? B9 ?? ?? ?? ?? 7F 26 3D 6C DB 06 40 BA ?? ?? ?? ?? B9 ?? ?? ?? ?? 7F 15 3D FF FF FF 3F BA ?? ?? ?? ?? B9 ?? ?? ?? ?? 7F 04 31 D2 31 C9 66 0F 12 1D ?? ?? ?? ?? F2 0F 59 C0 0F 28 D3 F2 0F 5E D0 0F 28 C2 0F 28 CA F2 0F 59 42 28 F2 0F 59 49 20 F2 0F 58 42 20 F2 0F 58 49 18 F2 0F 59 C2 F2 0F 59 CA F2 0F 58 42 18 F2 0F 58 49 10 F2 0F 59 C2 F2 0F 59 CA F2 0F 58 42 10 F2 0F 58 49 08 F2 0F 59 C2 F2 0F 59 CA F2 0F 58 42 08 F2 0F 58 09 F2 0F 59 C2 F2 0F 59 }
	condition:
		$pattern
}

rule __GI_frexp_838367f0272e48fb03780694d860b1e7 {
	meta:
		aliases = "frexp, __GI_frexp"
		size = "153"
		objfiles = "s_frexp@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 54 24 F8 C7 07 00 00 00 00 48 89 D1 48 C1 E9 20 89 C8 25 FF FF FF 7F 3D FF FF EF 7F 7F 72 09 C2 74 6E 3D FF FF 0F 00 7F 27 F2 0F 59 05 ?? ?? ?? ?? C7 07 CA FF FF FF F2 0F 11 44 24 F8 48 8B 54 24 F8 48 89 D1 48 C1 E9 20 89 C8 25 FF FF FF 7F C1 F8 14 03 07 F2 0F 11 44 24 F8 2D FE 03 00 00 89 07 48 8B 44 24 F8 48 89 C2 48 89 C8 25 FF FF 0F 80 83 E2 FF 48 0D 00 00 E0 3F 48 C1 E0 20 48 09 C2 48 89 54 24 F8 66 0F 12 4C 24 F8 0F 28 C1 C3 }
	condition:
		$pattern
}

rule __GI_nextafter_29edca1d11087f54ce688964df50fc19 {
	meta:
		aliases = "nextafter, __GI_nextafter"
		size = "305"
		objfiles = "s_nextafter@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 54 24 F8 F2 0F 11 4C 24 F8 0F 28 D0 48 89 D6 89 D7 48 8B 54 24 F8 48 C1 EE 20 48 89 D1 41 89 D0 89 F2 81 E2 FF FF FF 7F 48 C1 E9 20 81 FA FF FF EF 7F 7E 0A 8D 82 00 00 10 80 09 F8 75 18 89 C8 25 FF FF FF 7F 3D FF FF EF 7F 7E 13 2D 00 00 F0 7F 44 09 C0 74 09 F2 0F 58 D1 E9 C6 00 00 00 66 0F 2E D1 7A 06 0F 84 BA 00 00 00 09 FA 75 34 81 E1 00 00 00 80 89 C8 48 C1 E0 20 48 83 C8 01 48 89 44 24 F8 66 0F 12 44 24 F8 0F 28 D0 F2 0F 59 C0 66 0F 2E C2 0F 85 8A 00 00 00 0F 8A 84 00 00 00 EB 7F 85 F6 78 1B 39 CE 7F 36 0F 94 C2 44 39 C7 0F 97 C0 84 D0 75 29 89 F8 FF C0 75 37 FF C6 }
	condition:
		$pattern
}

rule __GI_carg_c05643826c82343dee55b99a4b6f1686 {
	meta:
		aliases = "carg, __GI_carg"
		size = "20"
		objfiles = "carg@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 4C 24 F8 0F 28 C8 66 0F 12 44 24 F8 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fma_ad65862bb33b73984fa0adc080d6dff4 {
	meta:
		aliases = "__GI_fma, fma"
		size = "9"
		objfiles = "s_fma@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 59 C1 F2 0F 58 C2 C3 }
	condition:
		$pattern
}

rule __floattidf_7ac1a63765c9e2760aa885fc9c4fd523 {
	meta:
		aliases = "__floattidf"
		size = "60"
		objfiles = "_floatdidf@libgcc.a"
	strings:
		$pattern = { ( CC | F2 ) 48 0F 2A C6 48 85 FF 53 48 89 FA F2 0F 59 05 ?? ?? ?? ?? 78 0B F2 48 0F 2A CF 5B F2 0F 58 C1 C3 48 89 F8 83 E2 01 48 D1 E8 48 09 D0 F2 48 0F 2A C8 5B F2 0F 58 C9 F2 0F 58 C1 C3 }
	condition:
		$pattern
}

rule __floattisf_755cf5eefbbd3b86bdf7f971420655fc {
	meta:
		aliases = "__floattisf"
		size = "68"
		objfiles = "_floatdisf@libgcc.a"
	strings:
		$pattern = { ( CC | F2 ) 48 0F 2A C6 48 85 FF 53 48 89 FA F2 0F 59 05 ?? ?? ?? ?? 78 0F F2 48 0F 2A CF 5B F2 0F 58 C1 F2 0F 5A C0 C3 48 89 F8 83 E2 01 48 D1 E8 48 09 D0 F2 48 0F 2A C8 5B F2 0F 58 C9 F2 0F 58 C1 F2 0F 5A C0 C3 }
	condition:
		$pattern
}

rule __isinff_29ae7be8410902c0cd417a47eed2693e {
	meta:
		aliases = "__GI___isinff, __isinff"
		size = "39"
		objfiles = "s_isinff@libm.a"
	strings:
		$pattern = { ( CC | F3 ) 0F 11 44 24 FC 8B 44 24 FC 89 C2 25 FF FF FF 7F 35 00 00 80 7F C1 FA 1E 89 C1 F7 D9 09 C8 C1 F8 1F F7 D0 21 D0 C3 }
	condition:
		$pattern
}

rule coshf_76fb52706816ef3df3c8d6c20b0aa675 {
	meta:
		aliases = "erff, ldexpf, scalbnf, cbrtf, atanhf, sinf, cosf, logf, floorf, tanhf, truncf, lgammaf, fabsf, sinhf, frexpf, logbf, rintf, expf, tgammaf, asinhf, acosf, expm1f, ceilf, roundf, log1pf, tanf, log10f, asinf, acoshf, sqrtf, scalblnf, erfcf, atanf, coshf"
		size = "19"
		objfiles = "tanhf@libm.a, expm1f@libm.a, sinf@libm.a, expf@libm.a, ldexpf@libm.a"
	strings:
		$pattern = { ( CC | F3 ) 0F 5A C0 48 83 EC 08 E8 ?? ?? ?? ?? F2 0F 5A C0 58 C3 }
	condition:
		$pattern
}

rule __fixunssfti_7ff5d0743bfc4c25a9443b68d5c91f7d {
	meta:
		aliases = "__fixunssfti"
		size = "175"
		objfiles = "_fixunssfdi@libgcc.a"
	strings:
		$pattern = { ( CC | F3 ) 0F 5A C0 53 66 0F 12 15 ?? ?? ?? ?? F2 0F 10 C8 F2 0F 59 0D ?? ?? ?? ?? 66 0F 2E CA 73 41 F2 48 0F 2C C9 31 F6 48 85 C9 48 89 CF 78 52 F2 48 0F 2A C9 F2 0F 59 0D ?? ?? ?? ?? F2 0F 58 C8 66 0F 2E CA 73 52 F2 48 0F 2C D1 48 89 F0 31 DB 48 09 D0 48 89 FA 48 09 DA 5B C3 66 66 90 66 66 90 F2 0F 5C CA 48 B8 00 00 00 00 00 00 00 80 31 F6 F2 48 0F 2C C9 48 31 C1 48 85 C9 48 89 CF 79 AE 48 89 C8 83 E1 01 48 D1 E8 48 09 C8 F2 48 0F 2A C8 F2 0F 58 C9 EB 9C F2 0F 5C CA 48 B8 00 00 00 00 00 00 00 80 F2 48 0F 2C D1 48 31 C2 EB 9B }
	condition:
		$pattern
}

rule llroundf_d3b5b767a0285b8ef7c579a0959a22b2 {
	meta:
		aliases = "lroundf, llrintf, lrintf, ilogbf, llroundf"
		size = "9"
		objfiles = "lrintf@libm.a, llrintf@libm.a, llroundf@libm.a, ilogbf@libm.a, lroundf@libm.a"
	strings:
		$pattern = { ( CC | F3 ) 0F 5A C0 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule powf_b655e1a82b86ef778f64370fab64b292 {
	meta:
		aliases = "remainderf, copysignf, atan2f, hypotf, nextafterf, fmodf, powf"
		size = "23"
		objfiles = "hypotf@libm.a, fmodf@libm.a, nextafterf@libm.a, copysignf@libm.a, powf@libm.a"
	strings:
		$pattern = { ( CC | F3 ) 0F 5A C9 48 83 EC 08 F3 0F 5A C0 E8 ?? ?? ?? ?? F2 0F 5A C0 58 C3 }
	condition:
		$pattern
}

rule __divsc3_4e76de84e3b5329f90be64ae6dc55e21 {
	meta:
		aliases = "__divsc3"
		size = "757"
		objfiles = "_divsc3@libgcc.a"
	strings:
		$pattern = { ( CC | F3 ) 44 0F 10 05 ?? ?? ?? ?? 0F 28 F0 0F 28 F9 0F 28 C3 0F 28 CA 0F 28 EA 41 0F 54 C8 41 0F 54 C0 0F 2E C1 76 4B 0F 28 CA 0F 28 C2 0F 28 E6 F3 0F 5E CB 0F 28 D7 F3 0F 59 C1 F3 0F 59 E1 F3 0F 59 D1 F3 0F 58 C3 F3 0F 58 E7 F3 0F 5C D6 F3 0F 5E E0 F3 0F 5E D0 0F 2E E4 7A 48 75 46 F3 0F 11 64 24 F8 F3 0F 11 54 24 FC F3 0F 7E 44 24 F8 C3 90 0F 28 C3 0F 28 CB 0F 28 E7 F3 0F 5E C2 F3 0F 59 C8 F3 0F 59 E0 F3 0F 59 C6 F3 0F 58 CA 0F 28 D7 F3 0F 58 E6 F3 0F 5C D0 F3 0F 5E E1 F3 0F 5E D1 EB B3 0F 2E D2 7A 02 74 B3 45 0F 57 C9 41 0F 2E E9 75 13 7A 11 41 0F 2E D9 7A 0B 66 66 90 66 90 0F 84 EB 01 00 00 31 D2 }
	condition:
		$pattern
}

rule __gcov_flush_32a093eff127b3eedaa06c147dc0694b {
	meta:
		aliases = "__gnat_default_unlock, __enable_execute_stack, __gcov_merge_single, __gcov_merge_add, __gcov_merge_delta, __gcov_init, __gnat_default_lock, __clear_cache, __gcov_flush"
		size = "2"
		objfiles = "_gcov@libgcov.a, gthr_gnat@libgcc.a, _gcov_merge_add@libgcov.a, _gcov_merge_delta@libgcov.a, _gcov_merge_single@libgcov.a"
	strings:
		$pattern = { ( CC | F3 ) C3 }
	condition:
		$pattern
}
