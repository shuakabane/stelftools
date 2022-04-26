// YARA rules, version 0.2.0_2021_07_29


rule exp2_ab090addf6dde2acd7e0f0cba0fcfb8f {
	meta:
		aliases = "__GI_exp2, exp2"
		type = "func"
		size = "16"
		objfiles = "w_exp2@libm.a"
	strings:
		$pattern = { ( CC | 0F ) 28 C8 F2 0F 10 05 ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule carg_813076fe7342df02c80a4f9ade8c23e1 {
	meta:
		aliases = "__GI_carg, carg"
		type = "func"
		size = "14"
		objfiles = "carg@libm.a"
	strings:
		$pattern = { ( CC | 0F ) 28 D1 0F 28 C8 0F 28 C2 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __mulsc3_e6e9f1d35632b70d13f1b21abbe09b0a {
	meta:
		aliases = "__mulsc3"
		type = "func"
		size = "821"
		objfiles = "_mulsc3@libgcc.a"
	strings:
		$pattern = { ( CC | 0F ) 28 E8 F3 0F 59 C2 0F 28 F9 44 0F 28 C5 44 0F 28 C9 F3 0F 59 FB F3 44 0F 59 C3 0F 28 E0 F3 44 0F 59 CA F3 0F 5C E7 41 0F 28 F0 F3 41 0F 58 F1 0F 2E E4 7A 15 75 13 F3 0F 11 64 24 F8 F3 0F 11 74 24 FC F3 0F 7E 44 24 F8 C3 0F 2E F6 7A 02 74 E6 44 0F 28 D5 0F 2E ED F3 44 0F 5C D5 66 66 90 0F 85 55 02 00 00 0F 8A 4F 02 00 00 45 0F 2E D2 0F 84 3F 02 00 00 F3 44 0F 10 1D ?? ?? ?? ?? 44 0F 28 D1 0F 2E C9 41 0F 54 EB F3 44 0F 5C D1 0F 56 2D ?? ?? ?? ?? 75 12 7A 10 45 0F 2E D2 0F 85 3B 02 00 00 0F 8A 35 02 00 00 45 0F 57 D2 44 0F 28 E1 0F 2E D2 44 0F 54 15 ?? ?? ?? ?? 45 0F 54 E3 45 0F 56 D4 41 0F 28 }
	condition:
		$pattern
}

rule __fixunssfdi_0f7f77f817f617047974b82a3a08caf4 {
	meta:
		aliases = "__fixunssfdi"
		type = "func"
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
		type = "func"
		size = "19"
		objfiles = "crtfastmath"
	strings:
		$pattern = { ( CC | 0F ) AE 5C 24 FC 81 4C 24 FC 40 80 00 00 0F AE 54 24 FC C3 }
	condition:
		$pattern
}

rule __decode_header_37359708175ab02075fb7892cad9a122 {
	meta:
		aliases = "__decode_header"
		type = "func"
		size = "161"
		objfiles = "decodeh@libc.a"
	strings:
		$pattern = { ( CC | 0F ) B6 07 0F B6 57 01 C1 E0 08 09 C2 89 16 0F BE 47 02 C1 E8 1F 89 46 04 8A 47 02 C0 E8 03 83 E0 0F 89 46 08 0F B6 47 02 C1 E8 02 83 E0 01 89 46 0C 0F B6 47 02 D1 E8 83 E0 01 89 46 10 0F B6 47 02 83 E0 01 89 46 14 0F BE 47 03 C1 E8 1F 89 46 18 0F B6 47 03 83 E0 0F 89 46 1C 0F B6 47 04 0F B6 57 05 C1 E0 08 09 D0 89 46 20 0F B6 47 06 0F B6 57 07 C1 E0 08 09 D0 89 46 24 0F B6 47 08 0F B6 57 09 C1 E0 08 09 D0 89 46 28 0F B6 47 0A 0F B6 57 0B C1 E0 08 09 D0 89 46 2C B8 0C 00 00 00 C3 }
	condition:
		$pattern
}

rule lbasename_660b301d569d7b273277759b254d7a20 {
	meta:
		aliases = "lbasename"
		type = "func"
		size = "36"
		objfiles = "lbasename@libiberty.a"
	strings:
		$pattern = { ( CC | 0F ) B6 0F 48 89 F8 84 C9 74 18 48 8D 57 01 66 90 80 F9 2F 0F B6 0A 48 0F 44 C2 48 83 C2 01 84 C9 75 EE F3 C3 }
	condition:
		$pattern
}

rule htab_hash_string_ec3f0b1fc5c64c330748de791d270c1e {
	meta:
		aliases = "htab_hash_string"
		type = "func"
		size = "44"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 0F ) B6 17 31 C0 48 8D 4F 01 84 D2 74 1D 0F 1F 00 BE 43 00 00 00 48 83 C1 01 0F AF C6 8D 44 10 8F 0F B6 51 FF 84 D2 75 E8 F3 C3 F3 C3 }
	condition:
		$pattern
}

rule __flbf_f5ba2419795d2f795740a1cdd5576742 {
	meta:
		aliases = "__flbf"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "13"
		objfiles = "__fwritable@libc.a"
	strings:
		$pattern = { ( CC | 0F ) B7 07 C1 E8 05 83 F0 01 83 E0 01 C3 }
	condition:
		$pattern
}

rule ternary_search_36b4287b0cba16553f9153ea3833f349 {
	meta:
		aliases = "ternary_search"
		type = "func"
		size = "85"
		objfiles = "ternary@libiberty.a"
	strings:
		$pattern = { ( CC | 0F ) BE 06 0F 1F 44 00 00 48 85 FF 74 1C 0F BE 17 39 D0 75 1C 85 C0 74 38 48 8B 7F 10 0F BE 46 01 48 83 C6 01 48 85 FF 75 E4 31 C0 C3 0F 1F 40 00 78 0E 48 8B 7F 18 EB D0 0F 1F 84 00 00 00 00 00 48 8B 7F 08 EB C2 66 2E 0F 1F 84 00 00 00 00 00 48 8B 47 10 C3 }
	condition:
		$pattern
}

rule inet_netof_80c4b1fc4828b7c517e0c4381492c95e {
	meta:
		aliases = "__GI_inet_netof, inet_netof"
		type = "func"
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
		type = "func"
		size = "43"
		objfiles = "inet_lnaof@libc.a"
	strings:
		$pattern = { ( CC | 0F ) CF 85 FF 78 0A 89 F9 81 E1 FF FF FF 00 EB 18 89 FA 0F B7 CF 40 0F B6 C7 81 E2 00 00 00 C0 81 FA 00 00 00 80 0F 45 C8 89 C8 C3 }
	condition:
		$pattern
}

rule ntohl_f24c2e84d472595e4e4e43a68927b1b2 {
	meta:
		aliases = "htonl, ntohl"
		type = "func"
		size = "5"
		objfiles = "ntohl@libc.a"
	strings:
		$pattern = { ( CC | 0F ) CF 89 F8 C3 }
	condition:
		$pattern
}

rule pthread_equal_c11f863d6be2c66fb42fa0367477969e {
	meta:
		aliases = "__GI_pthread_equal, eq_pointer, pthread_equal"
		type = "func"
		size = "9"
		objfiles = "hashtab@libiberty.a, pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) C0 48 39 F7 0F 94 C0 C3 }
	condition:
		$pattern
}

rule strcasecmp_604e6ff24629da32355f714a0f1abd7e {
	meta:
		aliases = "__GI_strcasecmp, strcasecmp"
		type = "func"
		size = "48"
		objfiles = "strcasecmp@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C0 48 39 F7 74 1B 0F B6 07 48 8B 0D ?? ?? ?? ?? 0F BF 14 41 0F B6 06 0F BF 04 41 29 C2 89 D0 75 0D 80 3F 00 74 08 48 FF C6 48 FF C7 EB D3 C3 }
	condition:
		$pattern
}

rule fibheap_empty_9205fe8af8b9dae839d179898def1d82 {
	meta:
		aliases = "fibheap_empty"
		type = "func"
		size = "10"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 31 ) C0 48 83 3F 00 0F 94 C0 C3 }
	condition:
		$pattern
}

rule rwlock_can_rdlock_b497feaa1ecde8220ed3e9661004e516 {
	meta:
		aliases = "rwlock_can_rdlock"
		type = "func"
		size = "36"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) C0 48 83 7F 18 00 75 1A 83 7F 30 00 74 0F 48 83 7F 28 00 74 08 31 C0 85 F6 0F 95 C0 C3 B8 01 00 00 00 C3 }
	condition:
		$pattern
}

rule strnlen_a5a5f97420a3ff765302cbf9be6b2005 {
	meta:
		aliases = "__GI_strnlen, strnlen"
		type = "func"
		size = "201"
		objfiles = "strnlen@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C0 48 85 F6 0F 84 BD 00 00 00 48 8D 34 37 48 C7 C0 FF FF FF FF 48 39 FE 48 0F 42 F0 48 89 F8 EB 13 80 38 00 75 0B 48 39 C6 48 0F 46 C6 48 29 F8 C3 48 FF C0 A8 07 75 E9 48 89 C1 49 B9 FF FE FE FE FE FE FE FE 49 B8 80 80 80 80 80 80 80 80 EB 67 48 8B 01 48 83 C1 08 4C 01 C8 49 85 C0 74 55 80 79 F8 00 48 8D 51 F8 75 05 48 89 D0 EB 4E 80 79 F9 00 48 8D 42 01 74 44 80 79 FA 00 48 8D 42 02 74 3A 80 79 FB 00 48 8D 42 03 74 30 80 79 FC 00 48 8D 42 04 74 26 80 79 FD 00 48 8D 42 05 74 1C 80 79 FE 00 48 8D 42 06 74 12 80 79 FF 00 48 8D 42 07 74 08 48 89 F0 48 39 F1 72 94 48 39 C6 48 0F 46 C6 48 29 F8 }
	condition:
		$pattern
}

rule cplus_demangle_fill_name_10526b661c8af30bedf4f31a1734210e {
	meta:
		aliases = "cplus_demangle_fill_name"
		type = "func"
		size = "34"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 31 ) C0 48 85 FF 74 19 48 85 F6 74 14 85 D2 74 10 C7 07 00 00 00 00 48 89 77 08 B0 01 89 57 10 C3 F3 C3 }
	condition:
		$pattern
}

rule __ffsdi2_8a78910301e43abbf21c9564d1583c7b {
	meta:
		aliases = "__ffsdi2"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "25"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) C0 48 C7 07 00 00 00 00 C7 47 08 00 00 00 00 48 C7 47 10 00 00 00 00 C3 }
	condition:
		$pattern
}

rule check_match_983eb99d62f587230ccfd5a6bf6cb8a0 {
	meta:
		aliases = "check_match"
		type = "func"
		size = "91"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 31 ) C0 66 83 7F 06 00 0F 94 C0 85 C8 75 47 48 83 7F 08 00 74 40 0F B6 47 04 83 E0 0F 83 F8 02 7E 05 83 F8 05 75 2F 8B 07 48 FF CA 48 8D 74 06 FF 48 FF C6 48 FF C2 8A 0E 8A 02 84 C9 75 07 0F B6 D0 F7 DA EB 0C 38 C1 74 E7 0F B6 D1 0F B6 C0 29 C2 85 D2 74 02 31 FF 48 89 F8 C3 }
	condition:
		$pattern
}

rule cfgetispeed_60c33ceb298080a4794337b3e0a77ca7 {
	meta:
		aliases = "cfgetispeed"
		type = "func"
		size = "16"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C0 83 3F 00 78 08 8B 47 08 25 0F 10 00 00 C3 }
	condition:
		$pattern
}

rule pthread_setconcurrency_539feb83c6425c7690ee677a08834eb5 {
	meta:
		aliases = "__pthread_setconcurrency, pthread_setconcurrency"
		type = "func"
		size = "9"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) C0 89 3D ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule dyn_string_eq_007cf0b2743834ea3c93f07d8d8df947 {
	meta:
		aliases = "dyn_string_eq"
		type = "func"
		size = "46"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 31 ) C0 8B 56 04 39 57 04 74 06 C3 0F 1F 44 00 00 48 83 EC 08 48 8B 76 08 48 8B 7F 08 E8 ?? ?? ?? ?? 85 C0 0F 94 C0 48 83 C4 08 0F B6 C0 C3 }
	condition:
		$pattern
}

rule xdrstdio_inline_95da5d637ce2b37c162272462d63ab78 {
	meta:
		aliases = "_Unwind_FindEnclosingFunction, _Unwind_GetDataRelBase, _Unwind_GetRegionStart, _Unwind_GetTextRelBase, __GI_pthread_attr_destroy, __GI_pthread_condattr_destroy, __GI_pthread_condattr_init, __GI_wcsftime, __gthread_active_p, __pthread_mutex_init, __pthread_mutex_lock, __pthread_mutex_trylock, __pthread_mutex_unlock, __pthread_mutexattr_destroy, __pthread_return_0, __udiv_w_sdiv, _svcauth_null, authnone_refresh, clntraw_control, grantpt, pthread_attr_destroy, pthread_condattr_destroy, pthread_condattr_init, pthread_mutexattr_destroy, pthread_rwlockattr_destroy, wcsftime, xdrstdio_inline"
		type = "func"
		size = "3"
		objfiles = "grantpt@libc.a, _udiv_w_sdiv@libgcc.a, rwlock@libpthread.a, xdr_stdio@libc.a, unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 31 ) C0 C3 }
	condition:
		$pattern
}

rule pthread_mutexattr_getpshared_31c376d22c9d3e92413779e1c247ac31 {
	meta:
		aliases = "__pthread_mutexattr_getpshared, pthread_condattr_getpshared, pthread_mutexattr_getpshared"
		type = "func"
		size = "9"
		objfiles = "mutex@libpthread.a, condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) C0 C7 06 00 00 00 00 C3 }
	condition:
		$pattern
}

rule pthread_rwlockattr_init_aa67116420e5462cc3551098e4e7fb72 {
	meta:
		aliases = "pthread_rwlockattr_init"
		type = "func"
		size = "16"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) C0 C7 07 00 00 00 00 C7 47 04 00 00 00 00 C3 }
	condition:
		$pattern
}

rule pthread_mutexattr_init_a0139c0de72b46dc02cbec50858dabe6 {
	meta:
		aliases = "__pthread_mutexattr_init, pthread_mutexattr_init"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "12"
		objfiles = "isascii@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C0 F7 C7 80 FF FF FF 0F 94 C0 C3 }
	condition:
		$pattern
}

rule sort_pointers_a56a7795ce18bfce7dd1b07cf61260b7 {
	meta:
		aliases = "sort_pointers"
		type = "func"
		size = "327"
		objfiles = "sort@libiberty.a"
	strings:
		$pattern = { ( CC | 31 ) C9 31 C0 0F 1F 40 00 48 C1 E1 08 48 01 C1 48 83 C0 01 48 83 F8 08 75 EF 41 57 41 BB 08 00 00 00 41 89 CF 31 C0 41 56 41 BE 08 00 00 00 4D 89 F2 41 55 4C 8D 2C FD 00 00 00 00 4D 29 DA 41 54 4D 8D 65 F8 55 BD 80 00 00 00 53 48 81 EC A0 03 00 00 45 84 FF 48 8D 5C 24 98 0F 85 C1 00 00 00 4C 89 5C 24 90 4D 89 DA 48 89 DF 48 89 E9 4F 8D 04 2A F3 48 AB 4A 8D 0C 16 49 01 F0 4C 39 C1 0F 83 B8 00 00 00 0F 1F 00 0F B6 39 48 83 C1 08 83 44 BC 98 01 49 39 C8 77 EF 44 8B 4C 24 9C 8B 4C 24 98 4C 8D 43 04 EB 0F 0F 1F 84 00 00 00 00 00 45 8B 08 41 8B 48 FC 41 01 C9 48 8D BC 24 98 03 00 00 49 83 C0 04 45 89 }
	condition:
		$pattern
}

rule __register_frame_info_table_9a45c5194586f47a7935b5e313ed5c07 {
	meta:
		aliases = "__register_frame_info, __register_frame_info_table"
		type = "func"
		size = "9"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 31 ) C9 31 D2 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule read_uleb128_2091ad81a4fae8922c4301baba112f89 {
	meta:
		aliases = "read_uleb128"
		type = "func"
		size = "38"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a, unwind_c@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 31 ) C9 45 31 C0 0F B6 17 48 83 C7 01 48 89 D0 83 E0 7F 48 D3 E0 83 C1 07 49 09 C0 84 D2 78 E6 48 89 F8 4C 89 06 C3 }
	condition:
		$pattern
}

rule read_sleb128_3a2680db26309f59a1a839b51e610c70 {
	meta:
		aliases = "read_sleb128"
		type = "func"
		size = "61"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 31 ) C9 45 31 C0 0F B6 17 48 83 C7 01 48 89 D0 83 E0 7F 48 D3 E0 83 C1 07 49 09 C0 84 D2 78 E6 83 F9 3F 77 12 83 E2 40 74 0D 48 C7 C0 FF FF FF FF 48 D3 E0 49 09 C0 48 89 F8 4C 89 06 C3 }
	condition:
		$pattern
}

rule strlcat_85a059759eb9710802b4e7bc83f1d377 {
	meta:
		aliases = "__GI_strlcat, strlcat"
		type = "func"
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
		type = "func"
		size = "14"
		objfiles = "setlinebuf@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C9 BA 01 00 00 00 31 F6 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wcstoumax_0b8614121f4839ecf9cde74d5b6b8c69 {
	meta:
		aliases = "__GI_strtoul, __GI_strtoull, __GI_waitpid, __GI_wcstoul, __GI_wcstoull, __libc_waitpid, strtoul, strtoull, strtoumax, waitpid, wcstoul, wcstoull, wcstoumax"
		type = "func"
		size = "7"
		objfiles = "wcstoul@libc.a, waitpid@libc.a, strtoul@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C9 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wcswidth_9306ae589cef1e583d22806c4cc1f68a {
	meta:
		aliases = "__GI_wcswidth, wcswidth"
		type = "func"
		size = "82"
		objfiles = "wcswidth@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C9 EB 0C 89 D0 83 E0 7F 39 C2 75 3F 48 FF C1 48 39 F1 73 28 8B 14 8F 85 D2 75 E8 EB 1F 3D FF 00 00 00 7F 27 83 F8 1F 7E 22 83 E8 7F 83 F8 20 76 1A 48 83 C7 04 FF C2 48 FF CE EB 02 31 D2 48 85 F6 74 0B 8B 07 85 C0 75 D4 EB 03 83 CA FF 89 D0 C3 }
	condition:
		$pattern
}

rule splay_tree_compare_ints_2810d12a7c1e2ab8380724b35f2cd39f {
	meta:
		aliases = "splay_tree_compare_ints"
		type = "func"
		size = "16"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 31 ) D2 39 F7 B8 FF FF FF FF 0F 9F C2 0F 4D C2 C3 }
	condition:
		$pattern
}

rule splay_tree_compare_pointers_bf057d6bc5459946cd84d7a0f095b218 {
	meta:
		aliases = "splay_tree_compare_pointers"
		type = "func"
		size = "17"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 31 ) D2 48 39 F7 B8 FF FF FF FF 0F 97 C2 0F 43 C2 C3 }
	condition:
		$pattern
}

rule wcstof_3cb1ef1313d9618f38d69ea4ff44828f {
	meta:
		aliases = "__GI_strtof, __GI_wcstof, strtof, wcstof"
		type = "func"
		size = "42"
		objfiles = "wcstof@libc.a, strtof@libc.a"
	strings:
		$pattern = { ( CC | 31 ) D2 48 83 EC 38 E8 ?? ?? ?? ?? D9 54 24 28 DB 7C 24 10 D9 44 24 28 DB 3C 24 E8 ?? ?? ?? ?? F3 0F 10 44 24 28 48 83 C4 38 C3 }
	condition:
		$pattern
}

rule wcstod_7e6b75b973efcada245468fd30d65e37 {
	meta:
		aliases = "__GI_strtod, __GI_wcstod, strtod, wcstod"
		type = "func"
		size = "42"
		objfiles = "strtod@libc.a, wcstod@libc.a"
	strings:
		$pattern = { ( CC | 31 ) D2 48 83 EC 38 E8 ?? ?? ?? ?? DD 54 24 20 DB 7C 24 10 DD 44 24 20 DB 3C 24 E8 ?? ?? ?? ?? F2 0F 10 44 24 20 48 83 C4 38 C3 }
	condition:
		$pattern
}

rule __floatuntidf_a9b831b4aa32f2afc5b8f6c59019bed6 {
	meta:
		aliases = "__floatuntidf"
		type = "func"
		size = "276"
		objfiles = "_floatundidf@libgcc.a"
	strings:
		$pattern = { ( CC | 31 ) D2 49 89 F1 53 48 89 F8 48 89 D1 49 89 F8 4C 31 C9 48 31 F8 48 83 EC 10 48 09 C1 48 89 FE 0F 84 B1 00 00 00 4C 89 C8 BE 38 00 00 00 66 66 90 49 89 C2 89 F1 49 D3 EA 45 84 D2 75 09 48 83 EE 08 75 ED 49 89 C2 48 8B 05 ?? ?? ?? ?? 4C 89 CA 42 0F B6 0C 10 4C 89 C0 41 BA 01 00 00 00 01 F1 4C 0F AD C8 48 D3 EA F6 C1 40 48 0F 45 C2 45 31 DB 4D 0F A5 D3 48 89 C7 49 D3 E2 31 C0 83 E1 40 48 89 F9 4D 0F 45 DA 4C 0F 45 D0 4C 89 D0 4C 89 DA 48 83 C0 FF 48 83 D2 FF 4C 21 C0 48 83 C9 01 4C 21 CA 48 89 D3 48 09 C3 48 0F 45 F9 48 85 FF 78 34 F2 48 0F 2A CF 4C 89 D7 4C 89 DE F2 0F 11 0C 24 E8 ?? ?? ?? ?? F2 }
	condition:
		$pattern
}

rule __floatuntisf_c8d350d7f263c3e4bd1d4f58ed374f6f {
	meta:
		aliases = "__floatuntisf"
		type = "func"
		size = "276"
		objfiles = "_floatundisf@libgcc.a"
	strings:
		$pattern = { ( CC | 31 ) D2 49 89 F1 53 48 89 F8 48 89 D1 49 89 F8 4C 31 C9 48 31 F8 48 83 EC 10 48 09 C1 48 89 FE 0F 84 B1 00 00 00 4C 89 C8 BE 38 00 00 00 66 66 90 49 89 C2 89 F1 49 D3 EA 45 84 D2 75 09 48 83 EE 08 75 ED 49 89 C2 48 8B 05 ?? ?? ?? ?? 4C 89 CA 42 0F B6 0C 10 4C 89 C0 41 BA 01 00 00 00 01 F1 4C 0F AD C8 48 D3 EA F6 C1 40 48 0F 45 C2 45 31 DB 4D 0F A5 D3 48 89 C7 49 D3 E2 31 C0 83 E1 40 48 89 F9 4D 0F 45 DA 4C 0F 45 D0 4C 89 D0 4C 89 DA 48 83 C0 FF 48 83 D2 FF 4C 21 C0 48 83 C9 01 4C 21 CA 48 89 D3 48 09 C3 48 0F 45 F9 48 85 FF 78 34 F3 48 0F 2A CF 4C 89 D7 4C 89 DE F3 0F 11 0C 24 E8 ?? ?? ?? ?? F3 }
	condition:
		$pattern
}

rule wcsrchr_5af5afbca6ccfb5048da5f9a2c292626 {
	meta:
		aliases = "wcsrchr"
		type = "func"
		size = "24"
		objfiles = "wcsrchr@libc.a"
	strings:
		$pattern = { ( CC | 31 ) D2 8B 07 39 F0 48 0F 44 D7 85 C0 74 06 48 83 C7 04 EB EE 48 89 D0 C3 }
	condition:
		$pattern
}

rule vwarnx_ddc6f3bfdf32a5fedb3333060daaf400 {
	meta:
		aliases = "__GI_vwarnx, vwarnx"
		type = "func"
		size = "7"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 31 ) D2 E9 2F FF FF FF }
	condition:
		$pattern
}

rule wcstold_b4e14f698767da14cd59fb60f58a9700 {
	meta:
		aliases = "__GI_strtold, __GI_wcstold, strtold, wcstold"
		type = "func"
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
		type = "func"
		size = "42"
		objfiles = "gai_strerror@libc.a"
	strings:
		$pattern = { ( CC | 31 ) D2 EB 1A 48 89 D0 48 C1 E0 04 39 B8 ?? ?? ?? ?? 75 08 48 8B 80 ?? ?? ?? ?? C3 48 FF C2 48 83 FA 0F 76 E0 B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule glob_pattern_p_96d9834645c3bce721cde91eca0b7a98 {
	meta:
		aliases = "__GI_glob_pattern_p, glob_pattern_p"
		type = "func"
		size = "78"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 31 ) D2 EB 3B 3C 5B 74 16 7F 0A 3C 2A 74 3A 3C 3F 75 2A EB 34 3C 5C 74 0D 3C 5D 75 20 EB 1A BA 01 00 00 00 EB 17 85 F6 74 13 80 7F 01 00 48 8D 47 01 74 09 48 89 C7 EB 04 85 D2 75 0C 48 FF C7 8A 07 84 C0 75 BF 31 C0 C3 B8 01 00 00 00 C3 }
	condition:
		$pattern
}

rule _start_7ba89daedb79fd291e18f5fa204e7fcc {
	meta:
		aliases = "_start"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "64"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) F6 48 83 EC 08 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 F6 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 3D FB FF FF 7F 7F 0B 83 C0 04 89 05 ?? ?? ?? ?? EB 0A C7 05 ?? ?? ?? ?? 00 00 00 00 58 C3 }
	condition:
		$pattern
}

rule sigpause_d3010fe72d6379f6b7707fbcdd11fb6d {
	meta:
		aliases = "__GI_sigpause, atof, mkstemp, sigpause"
		type = "func"
		size = "7"
		objfiles = "sigpause@libc.a, mkstemp@libc.a, atof@libc.a"
	strings:
		$pattern = { ( CC | 31 ) F6 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tzset_c73e1ce28b479111226384d7151d565c {
	meta:
		aliases = "__GI_tzset, tzset"
		type = "func"
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
		type = "func"
		size = "7"
		objfiles = "siggetmask@libc.a"
	strings:
		$pattern = { ( CC | 31 ) FF E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule setup_salt_7f7d452a8a3d16d19c1fae19e43d0de2 {
	meta:
		aliases = "setup_salt"
		type = "func"
		size = "73"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 3B ) 3D ?? ?? ?? ?? 74 40 BE 00 00 80 00 B9 01 00 00 00 31 D2 89 3D ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 EB 1D 8B 05 ?? ?? ?? ?? 09 F0 85 CF 0F 44 05 ?? ?? ?? ?? 01 C9 D1 EE FF C2 89 05 ?? ?? ?? ?? 83 FA 17 7E DE C3 }
	condition:
		$pattern
}

rule ascii_to_bin_88edc3a0571de95249cd32376343bb7e {
	meta:
		aliases = "ascii_to_bin"
		type = "func"
		size = "63"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 40 ) 80 FF 7A 7F 36 40 80 FF 60 7E 08 40 0F BE C7 83 E8 3B C3 40 80 FF 5A 7F 22 40 80 FF 40 7E 08 40 0F BE C7 83 E8 35 C3 40 80 FF 39 7F 0E 40 80 FF 2D 7E 08 40 0F BE C7 83 E8 2E C3 31 C0 C3 }
	condition:
		$pattern
}

rule set_cplus_marker_for_demanglin_67d7ceddbaa67f7a334ebbf697772e19 {
	meta:
		aliases = "set_cplus_marker_for_demangling"
		type = "func"
		size = "8"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 40 ) 88 3D ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule iterative_hash_80b3e0acc0f889b7de26d2dfd9cb6752 {
	meta:
		aliases = "iterative_hash"
		type = "func"
		size = "746"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 40 ) F6 C7 03 0F 84 16 02 00 00 B9 B9 79 37 9E 83 FE 0B 41 89 F3 89 C8 0F 86 21 01 00 00 0F 1F 00 44 0F B6 4F 05 44 0F B6 47 06 44 0F B6 57 04 41 C1 E0 10 41 C1 E1 08 45 01 C1 44 0F B6 47 07 45 01 D1 44 0F B6 57 08 41 C1 E0 18 45 01 C8 44 0F B6 4F 09 44 01 C1 44 0F B6 47 0A 41 C1 E1 08 41 C1 E0 10 45 01 C1 44 0F B6 47 0B 45 01 D1 44 0F B6 17 41 C1 E0 18 45 01 C8 44 0F B6 4F 01 44 01 C2 44 0F B6 47 02 41 C1 E1 08 41 C1 E0 10 45 01 C8 44 0F B6 4F 03 45 01 D0 41 C1 E1 18 45 01 C8 41 29 D0 41 29 C8 29 D1 44 01 C0 41 89 D0 41 C1 E8 0D 44 31 C0 41 89 C2 29 C1 29 C2 41 C1 E2 08 41 31 CA 45 89 D0 44 29 }
	condition:
		$pattern
}

rule dysize_c32113a9faa0ce4acb6619d31bd1b4d8 {
	meta:
		aliases = "dysize"
		type = "func"
		size = "52"
		objfiles = "dysize@libc.a"
	strings:
		$pattern = { ( CC | 40 ) F6 C7 03 53 75 26 BA 64 00 00 00 89 F8 89 D3 99 F7 FB 85 D2 75 0F 66 BA 90 01 89 F8 89 D3 99 F7 FB 85 D2 75 07 B8 6E 01 00 00 EB 05 B8 6D 01 00 00 5B C3 }
	condition:
		$pattern
}

rule __ieee754_rem_pio2_51113a7df93e1d29dd3bfc6c62e26b86 {
	meta:
		aliases = "__ieee754_rem_pio2"
		type = "func"
		size = "780"
		objfiles = "e_rem_pio2@libm.a"
	strings:
		$pattern = { ( CC | 41 ) 54 0F 28 C8 55 48 89 FD 53 48 83 EC 30 F2 0F 11 44 24 08 48 8B 44 24 08 49 89 C4 49 C1 EC 20 44 89 E3 81 E3 FF FF FF 7F 81 FB FB 21 E9 3F 7F 11 F2 0F 11 0F 48 C7 47 08 00 00 00 00 E9 07 02 00 00 81 FB 7B D9 02 40 0F 8F A0 00 00 00 45 85 E4 F2 0F 10 05 ?? ?? ?? ?? 7E 4C F2 0F 5C C8 81 FB FB 21 F9 3F 0F 28 C1 74 0A F2 0F 10 15 ?? ?? ?? ?? EB 13 F2 0F 5C 05 ?? ?? ?? ?? F2 0F 10 15 ?? ?? ?? ?? 0F 28 C8 F2 0F 5C CA B9 01 00 00 00 F2 0F 5C C1 F2 0F 11 4D 00 F2 0F 5C C2 F2 0F 11 45 08 E9 5A 02 00 00 81 FB FB 21 F9 3F F2 0F 58 C1 74 0A F2 0F 10 15 ?? ?? ?? ?? EB 10 F2 0F 58 05 ?? ?? ?? ?? F2 0F 10 }
	condition:
		$pattern
}

rule __ieee754_jn_4abbf800450b3052fcd78d1afe6c8a8e {
	meta:
		aliases = "__ieee754_jn"
		type = "func"
		size = "1011"
		objfiles = "e_jn@libm.a"
	strings:
		$pattern = { ( CC | 41 ) 54 0F 28 C8 55 89 FD 53 48 83 EC 50 F2 0F 11 44 24 08 48 8B 44 24 08 49 89 C4 89 C2 F7 D8 49 C1 EC 20 09 D0 44 89 E3 C1 E8 1F 81 E3 FF FF FF 7F 09 D8 3D 00 00 F0 7F 76 09 F2 0F 58 C8 E9 A4 03 00 00 83 FF 00 7D 13 66 0F 57 05 ?? ?? ?? ?? F7 DD 41 81 EC 00 00 00 80 EB 0F 75 0D 48 83 C4 50 5B 5D 41 5C E9 ?? ?? ?? ?? 83 FD 01 75 0D 48 83 C4 50 5B 5D 41 5C E9 ?? ?? ?? ?? 09 DA 0F 84 4F 03 00 00 81 FB FF FF EF 7F 0F 8F 43 03 00 00 E8 ?? ?? ?? ?? F2 0F 2A D5 F2 0F 11 44 24 48 F2 0F 11 54 24 28 66 0F 2E C2 0F 82 4B 01 00 00 81 FB FF FF CF 52 0F 8E EE 00 00 00 89 E8 83 E0 03 83 F8 01 74 45 7F 06 85 }
	condition:
		$pattern
}

rule erfc_275fba6d5001901acd25ab2188826fef {
	meta:
		aliases = "__GI_erfc, erfc"
		type = "func"
		size = "1158"
		objfiles = "s_erf@libm.a"
	strings:
		$pattern = { ( CC | 41 ) 54 0F 28 D8 55 53 48 83 EC 50 F2 0F 11 44 24 08 48 8B 44 24 08 48 C1 E8 20 89 C3 89 C5 41 89 C4 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 23 F2 0F 10 05 ?? ?? ?? ?? C1 ED 1F 8D 44 2D 00 F2 0F 5E C3 89 C0 F2 48 0F 2A C8 F2 0F 58 C8 E9 28 04 00 00 81 FB FF FF EA 3F 0F 8F CD 00 00 00 81 FB FF FF 6F 3C F2 0F 10 25 ?? ?? ?? ?? 7F 0C 0F 28 CC F2 0F 5C CB E9 00 04 00 00 0F 28 CB 3D FF FF CF 3F F2 0F 59 CB 0F 28 C1 0F 28 D1 F2 0F 59 05 ?? ?? ?? ?? F2 0F 59 15 ?? ?? ?? ?? F2 0F 58 05 ?? ?? ?? ?? F2 0F 5C 15 ?? ?? ?? ?? F2 0F 59 C1 F2 0F 59 D1 F2 0F 58 05 ?? ?? ?? ?? F2 0F 5C 15 ?? ?? ?? ?? F2 0F 59 C1 }
	condition:
		$pattern
}

rule tsearch_3a6026614b41579c071771ac0770bbc3 {
	meta:
		aliases = "__GI_tsearch, tsearch"
		type = "func"
		size = "109"
		objfiles = "tsearch@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 31 C0 48 85 F6 49 89 D4 55 48 89 FD 53 48 89 F3 74 54 EB 25 48 8B 30 48 89 EF 41 FF D4 83 F8 00 75 05 48 8B 03 EB 3F 7D 09 48 8B 1B 48 83 C3 08 EB 07 48 8B 1B 48 83 C3 10 48 8B 03 48 85 C0 75 D3 BF 18 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 74 16 48 89 03 48 89 28 48 C7 40 10 00 00 00 00 48 C7 40 08 00 00 00 00 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule cfsetspeed_0c697faf8ca558f32e047035756e9b58 {
	meta:
		aliases = "cfsetspeed"
		type = "func"
		size = "99"
		objfiles = "cfsetspeed@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 31 C0 49 89 FC 55 89 F5 53 EB 3D 8B 1C C5 ?? ?? ?? ?? 39 DD 75 0E 89 EE 4C 89 E7 E8 ?? ?? ?? ?? 89 EE EB 15 3B 2C C5 ?? ?? ?? ?? 75 18 89 DE 4C 89 E7 E8 ?? ?? ?? ?? 89 DE 4C 89 E7 E8 ?? ?? ?? ?? 31 C0 EB 17 48 FF C0 48 83 F8 1F 76 BD E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule tcgetattr_ede7290c4daeaac138976d0e19aafbac {
	meta:
		aliases = "__GI_tcgetattr, tcgetattr"
		type = "func"
		size = "110"
		objfiles = "tcgetattr@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 31 C0 55 53 48 89 F3 BE 01 54 00 00 48 83 EC 30 48 89 E2 E8 ?? ?? ?? ?? 85 C0 89 C5 75 43 8B 04 24 48 8D 74 24 11 48 8D 7B 11 BA 13 00 00 00 89 03 8B 44 24 04 89 43 04 8B 44 24 08 89 43 08 8B 44 24 0C 89 43 0C 8A 44 24 10 88 43 10 E8 ?? ?? ?? ?? BA 0D 00 00 00 48 89 C7 31 F6 E8 ?? ?? ?? ?? 48 83 C4 30 89 E8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule opendir_b28e0742cb014b5bd1927c03c7fd674c {
	meta:
		aliases = "__GI_opendir, opendir"
		type = "func"
		size = "241"
		objfiles = "opendir@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 31 C0 BE 00 08 01 00 55 53 31 DB 48 81 EC 90 00 00 00 E8 ?? ?? ?? ?? 85 C0 89 C5 0F 88 BF 00 00 00 48 89 E6 89 C7 E8 ?? ?? ?? ?? 85 C0 78 17 31 C0 BA 01 00 00 00 BE 02 00 00 00 89 EF E8 ?? ?? ?? ?? 85 C0 79 17 E8 ?? ?? ?? ?? 44 8B 20 48 89 C3 89 EF E8 ?? ?? ?? ?? 44 89 23 EB 74 BF 58 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C7 74 50 48 89 C3 89 28 48 C7 40 20 00 00 00 00 48 C7 40 10 00 00 00 00 48 C7 40 08 00 00 00 00 BE 00 02 00 00 48 8B 44 24 38 48 3D FF 01 00 00 48 0F 47 F0 48 89 77 28 BF 01 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 43 18 75 1E 48 89 DF E8 ?? ?? ?? ?? 89 EF E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule marshal_new_auth_d8fd9aeead2e12f8fa0897febe965b2c {
	meta:
		aliases = "marshal_new_auth"
		type = "func"
		size = "130"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 31 C9 BA 90 01 00 00 55 53 48 89 FB 48 83 EC 30 4C 8B 67 40 48 89 E7 49 8D 74 24 38 E8 ?? ?? ?? ?? 48 89 DE 48 89 E7 E8 ?? ?? ?? ?? 85 C0 74 10 48 8D 73 18 48 89 E7 E8 ?? ?? ?? ?? 85 C0 75 0C BF ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 13 48 8B 44 24 08 48 89 E7 FF 50 20 41 89 84 24 C8 01 00 00 48 8B 44 24 08 48 8B 40 38 48 85 C0 74 05 48 89 E7 FF D0 48 83 C4 30 B8 01 00 00 00 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule pthread_rwlock_destroy_42e3ea2ac6badefb4f6d5b33f38913d4 {
	meta:
		aliases = "pthread_rwlock_destroy"
		type = "func"
		size = "52"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 31 F6 55 53 48 89 FB E8 ?? ?? ?? ?? 44 8B 63 10 48 89 DF 48 8B 6B 18 E8 ?? ?? ?? ?? 45 85 E4 7F 07 31 C0 48 85 ED 74 05 B8 10 00 00 00 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule dyn_string_insert_char_436d89e8f71b66b31299060933396735 {
	meta:
		aliases = "dyn_string_insert_char"
		type = "func"
		size = "103"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 41 89 D4 55 48 63 EE 53 8B 47 04 48 89 FB 8D 70 01 E8 ?? ?? ?? ?? 48 85 C0 74 43 8B 53 04 39 EA 7C 23 48 63 FA 29 EA 48 8D 47 01 48 29 D7 48 8B 4B 08 44 0F B6 44 01 FF 44 88 04 01 48 83 E8 01 48 39 F8 75 E9 48 8B 43 08 44 88 24 28 83 43 04 01 B8 01 00 00 00 5B 5D 41 5C C3 0F 1F 00 5B 5D 31 C0 41 5C C3 }
	condition:
		$pattern
}

rule htab_find_slot_76919dd7820ffcdc94f15c6a6f1a3f89 {
	meta:
		aliases = "htab_find_slot"
		type = "func"
		size = "38"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 41 89 D4 55 48 89 F5 53 48 89 FB 48 89 F7 FF 13 48 89 DF 48 89 EE 44 89 E1 5B 5D 41 5C 89 C2 E9 BA FD FF FF }
	condition:
		$pattern
}

rule d_cv_qualifiers_ff331ddd90db6ba3c68accfb4d3faaea {
	meta:
		aliases = "d_cv_qualifiers"
		type = "func"
		size = "200"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 41 89 D4 55 48 89 F5 53 48 8B 47 18 48 89 FB 0F B6 08 EB 4C 66 2E 0F 1F 84 00 00 00 00 00 84 C0 75 4C 80 F9 4B 0F 85 93 00 00 00 48 83 43 18 01 41 83 FC 01 19 F6 83 43 50 06 83 E6 FD 83 C6 1B 31 C9 31 D2 48 89 DF E8 E2 FE FF FF 48 85 C0 48 89 45 00 74 59 48 8D 68 08 48 8B 43 18 0F B6 08 80 F9 72 0F 94 C0 80 F9 56 0F 94 C2 75 B0 48 83 43 18 01 84 C0 74 17 41 83 FC 01 19 F6 83 43 50 09 83 E6 FD 83 C6 19 EB B7 0F 1F 44 00 00 84 D2 74 9E 41 83 FC 01 19 F6 83 43 50 09 83 E6 FD 83 C6 1A EB 9C 66 2E 0F 1F 84 00 00 00 00 00 5B 5D 31 C0 41 5C C3 66 0F 1F 84 00 00 00 00 00 5B 48 89 E8 5D 41 5C C3 }
	condition:
		$pattern
}

rule xdrrec_setpos_e1e719f29b8d90bd55503c2095b9876d {
	meta:
		aliases = "xdrrec_setpos"
		type = "func"
		size = "115"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 41 89 F4 55 48 89 FD 53 48 8B 5F 18 E8 9A FF FF FF 83 F8 FF 74 54 8B 55 00 44 29 E0 85 D2 74 06 FF CA 75 46 EB 1B 48 8B 53 20 48 98 48 29 C2 48 3B 53 30 76 35 48 3B 53 28 73 2F 48 89 53 20 EB 22 3B 43 68 48 8B 53 58 7D 20 48 98 48 29 C2 48 3B 53 60 77 15 48 3B 53 50 72 0F 48 29 43 68 48 89 53 58 B8 01 00 00 00 EB 02 31 C0 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule getservbyport_be373e13d1811259e2c97dd178d500f1 {
	meta:
		aliases = "__GI_getservbyport, getservbyport"
		type = "func"
		size = "65"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 41 89 FC 53 48 89 F3 48 83 EC 18 E8 13 FC FF FF 48 8B 0D ?? ?? ?? ?? 4C 8D 4C 24 10 48 89 DE 44 89 E7 41 B8 19 11 00 00 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 44 24 10 48 83 C4 18 5B 41 5C C3 }
	condition:
		$pattern
}

rule sigaction_2668670968898c2b233f89515b7709ec {
	meta:
		aliases = "__GI_sigaction, __libc_sigaction, sigaction"
		type = "func"
		size = "234"
		objfiles = "sigaction@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 41 89 FC 55 48 89 D5 53 48 89 F3 48 81 EC 40 01 00 00 48 85 F6 74 42 48 8B 06 48 8D BC 24 B8 00 00 00 48 8D 76 08 BA 80 00 00 00 48 89 84 24 A0 00 00 00 E8 ?? ?? ?? ?? 8B 83 88 00 00 00 48 C7 84 24 B0 00 00 00 ?? ?? ?? ?? 0D 00 00 00 04 48 98 48 89 84 24 A8 00 00 00 31 D2 48 85 ED 74 03 48 89 E2 31 F6 48 85 DB 74 08 48 8D B4 24 A0 00 00 00 41 BA 08 00 00 00 49 63 FC B8 0D 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 48 85 ED 89 C3 74 36 85 C0 78 32 48 8B 04 24 48 8D 74 24 18 48 8D 7D 08 BA 80 00 00 00 48 89 45 00 E8 ?? ?? ?? ?? 48 8B 44 }
	condition:
		$pattern
}

rule putc_64b5ad6c57df1b91e0dabef124e5b57e {
	meta:
		aliases = "__GI_fputc, __GI_putc, fputc, putc"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "110"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 41 89 FC BF 01 00 00 00 53 89 F3 48 81 EC D8 00 00 00 48 8D 74 24 1C 48 89 54 24 30 E8 ?? ?? ?? ?? 48 8D 84 24 F0 00 00 00 C7 04 24 18 00 00 00 89 DE 44 89 E7 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 48 83 C0 10 48 8B 10 31 C0 E8 ?? ?? ?? ?? 8B 7C 24 1C 89 C3 31 F6 E8 ?? ?? ?? ?? 89 D8 48 81 C4 D8 00 00 00 5B 41 5C C3 }
	condition:
		$pattern
}

rule inet_ntop4_d0b80a68767dc0a2580e33d7b8f52e28 {
	meta:
		aliases = "inet_ntop4"
		type = "func"
		size = "267"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 45 31 D2 49 89 F4 FC 55 45 31 C9 48 89 D5 53 48 89 FB 48 83 EC 20 66 8B 05 ?? ?? ?? ?? 48 8D 7C 24 02 66 89 04 24 31 C0 AB AB AB 66 AB AA E9 92 00 00 00 49 63 C2 B1 64 4D 63 C1 4C 8D 1C 03 41 8D 71 01 44 89 CF 41 0F B6 13 89 D0 F6 F1 88 C1 8D 41 30 3C 30 42 88 04 04 75 23 B1 0A 89 D0 31 D2 F6 F1 B9 0A 00 00 00 0F B6 C0 66 F7 F1 83 C2 30 80 FA 30 42 88 14 04 74 24 89 F7 EB 20 B1 0A 89 D0 31 D2 F6 F1 B9 0A 00 00 00 48 63 F6 41 8D 79 02 0F B6 C0 66 F7 F1 83 C2 30 88 14 34 41 0F B6 03 B9 0A 00 00 00 31 D2 48 63 F7 44 8D 4F 02 41 FF C2 66 F7 F1 8D 47 01 48 98 83 C2 30 88 14 34 C6 04 04 2E 41 }
	condition:
		$pattern
}

rule dyn_string_insert_b31f3068e4d43244d5a67cabadf5e3c7 {
	meta:
		aliases = "dyn_string_insert"
		type = "func"
		size = "140"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 39 FA 55 48 89 D5 53 48 89 FB 74 78 41 89 F4 8B 77 04 03 72 04 E8 ?? ?? ?? ?? 48 85 C0 74 5E 8B 43 04 41 8D 54 24 FF 44 39 E0 48 63 C8 7C 28 66 0F 1F 44 00 00 4C 8B 43 08 44 8B 4D 04 45 0F B6 14 08 41 01 C1 83 E8 01 4D 63 C9 48 83 E9 01 39 D0 47 88 14 08 75 DE 48 63 55 04 49 63 FC 48 03 7B 08 48 8B 75 08 E8 ?? ?? ?? ?? 8B 45 04 01 43 04 B8 01 00 00 00 5B 5D 41 5C C3 66 90 5B 5D 31 C0 41 5C C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sched_getaffinity_c514d96bdef5d4a8ade980c17bbd11fc {
	meta:
		aliases = "sched_getaffinity"
		type = "func"
		size = "96"
		objfiles = "sched_getaffinity@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 63 FF 49 89 D4 B8 CC 00 00 00 55 48 89 F5 BE FF FF FF 7F 48 81 FD FF FF FF 7F 53 48 0F 46 F5 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 83 FB FF 89 D8 74 16 48 63 FB 31 F6 48 29 FD 49 8D 3C 3C 48 89 EA E8 ?? ?? ?? ?? 31 C0 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule fstat64_cc894928f3bf2ad2cc69366014fc1338 {
	meta:
		aliases = "__GI_fstat, __GI_fstat64, fstat, fstat64"
		type = "func"
		size = "82"
		objfiles = "fstat@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 63 FF B8 05 00 00 00 55 48 89 F5 53 48 81 EC 90 00 00 00 48 89 E6 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 85 DB 75 0B 48 89 EE 48 89 E7 E8 ?? ?? ?? ?? 48 81 C4 90 00 00 00 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule d_print_array_type_DOT_isra_DOT_4_114b60131d26fe592a33c5e2ad77f10e {
	meta:
		aliases = "d_print_array_type.isra.4"
		type = "func"
		size = "451"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 85 D2 49 89 F4 55 48 89 D5 53 48 89 FB 74 26 48 89 D0 0F 1F 00 8B 48 10 85 C9 0F 84 BD 00 00 00 48 8B 00 48 85 C0 75 ED 31 D2 48 89 EE 48 89 DF E8 28 FE FF FF 48 8B 53 08 48 85 D2 74 7F 0F 1F 80 00 00 00 00 48 8B 43 10 48 3B 43 18 73 6E 48 8D 48 01 48 89 4B 10 C6 04 02 20 48 8B 53 08 48 85 D2 74 69 48 8B 43 10 48 3B 43 18 73 5F 48 8D 48 01 48 89 4B 10 C6 04 02 5B 49 8B 34 24 48 85 F6 74 08 48 89 DF E8 22 DD FF FF 48 8B 53 08 48 85 D2 74 0E 48 8B 43 10 48 3B 43 18 0F 82 DB 00 00 00 48 89 DF BE 5D 00 00 00 5B 5D 41 5C E9 1A DC FF FF 66 2E 0F 1F 84 00 00 00 00 00 BE 20 00 00 00 48 89 DF }
	condition:
		$pattern
}

rule tfind_cd4902c967cb84d316afa141fe9dd188 {
	meta:
		aliases = "__GI_tfind, tfind"
		type = "func"
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
		type = "func"
		size = "90"
		objfiles = "wcstok@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 85 FF 49 89 D4 55 48 89 F5 53 48 89 FB 75 08 48 8B 1A 48 85 DB 74 38 48 89 DF 48 89 EE E8 ?? ?? ?? ?? 48 8D 1C 83 83 3B 00 75 06 31 DB 31 C0 EB 1A 48 89 EE 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 74 0A C7 00 00 00 00 00 48 83 C0 04 49 89 04 24 48 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule strtok_r_95e1fe7d95cceb17df56a3731420047e {
	meta:
		aliases = "__GI_strtok_r, strtok_r"
		type = "func"
		size = "94"
		objfiles = "strtok_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 85 FF 49 89 F4 55 48 89 D5 53 48 89 FB 75 03 48 8B 1A 48 89 DF 4C 89 E6 E8 ?? ?? ?? ?? 48 01 C3 80 3B 00 75 08 31 C0 48 89 5D 00 EB 29 4C 89 E6 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 75 0C 31 F6 48 89 DF E8 ?? ?? ?? ?? EB 06 C6 00 00 48 FF C0 48 89 45 00 48 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule pthread_detach_12da921da8812d6124fe3513e8b29aee {
	meta:
		aliases = "pthread_detach"
		type = "func"
		size = "209"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 89 F8 31 F6 25 FF 03 00 00 49 89 FC 55 48 C1 E0 05 48 8D A8 ?? ?? ?? ?? 53 48 89 EF 48 81 EC B0 00 00 00 E8 ?? ?? ?? ?? 48 8B 45 10 48 85 C0 74 06 4C 39 60 20 74 0F 48 89 EF E8 ?? ?? ?? ?? B8 03 00 00 00 EB 7C 80 78 51 00 74 0F 48 89 EF E8 ?? ?? ?? ?? B8 16 00 00 00 EB 67 48 83 78 68 00 74 0A 48 89 EF E8 ?? ?? ?? ?? EB 54 8A 58 50 C6 40 51 01 48 89 EF E8 ?? ?? ?? ?? 84 DB 74 41 83 3D ?? ?? ?? ?? 00 78 38 E8 F0 FB FF FF 48 89 04 24 C7 44 24 08 01 00 00 00 4C 89 64 24 10 8B 3D ?? ?? ?? ?? BA A8 00 00 00 48 89 E6 E8 ?? ?? ?? ?? 48 FF C0 75 0A E8 ?? ?? ?? ?? 83 38 04 74 DE 31 C0 48 81 C4 }
	condition:
		$pattern
}

rule pthread_kill_a43f604d263877f388aeccec7766fc33 {
	meta:
		aliases = "pthread_kill"
		type = "func"
		size = "110"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 89 F8 41 89 F4 25 FF 03 00 00 31 F6 48 C1 E0 05 55 48 8D A8 ?? ?? ?? ?? 53 48 89 FB 48 89 EF E8 ?? ?? ?? ?? 48 8B 45 10 48 85 C0 74 06 48 39 58 20 74 18 48 89 EF E8 ?? ?? ?? ?? B8 03 00 00 00 EB 24 E8 ?? ?? ?? ?? 8B 00 EB 1B 8B 58 28 48 89 EF E8 ?? ?? ?? ?? 44 89 E6 89 DF E8 ?? ?? ?? ?? FF C0 74 DE 31 C0 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule pthread_kill_all_threads_588c23c61a9a224ad89b1d65b5e729c0 {
	meta:
		aliases = "pthread_kill_all_threads"
		type = "func"
		size = "67"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 8B 05 ?? ?? ?? ?? 41 89 F4 55 89 FD 53 48 8B 18 EB 0D 8B 7B 28 89 EE E8 ?? ?? ?? ?? 48 8B 1B 48 3B 1D ?? ?? ?? ?? 75 EA 45 85 E4 74 0E 8B 7B 28 89 EE 5B 5D 41 5C E9 ?? ?? ?? ?? 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule _dl_run_init_array_a94280d661525d90be53301c2029cbff {
	meta:
		aliases = "_dl_run_init_array"
		type = "func"
		size = "59"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 8B 87 48 01 00 00 48 8B 0F 48 8B 97 58 01 00 00 55 48 85 C0 53 74 1C 49 89 D4 48 8D 2C 08 31 DB 49 C1 EC 03 EB 08 89 D8 FF C3 FF 54 C5 00 44 39 E3 72 F3 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule inet_ntoa_r_abbc8d5e30456a48a4a04202e04d23aa {
	meta:
		aliases = "__GI_inet_ntoa_r, inet_ntoa_r"
		type = "func"
		size = "77"
		objfiles = "inet_ntoa@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 8D 46 0F 45 31 E4 0F CF 55 31 ED 53 89 FB EB 2C 89 DE 31 C9 BA F6 FF FF FF 81 E6 FF 00 00 00 48 89 C7 E8 ?? ?? ?? ?? 48 FF C8 48 85 ED 74 04 C6 45 00 2E C1 EB 08 41 FF C4 48 89 C5 41 83 FC 03 7E CE 5B 5D 41 5C 48 FF C0 C3 }
	condition:
		$pattern
}

rule delete_non_B_K_work_stuff_703c92b7e67c1797375dc245340df9df {
	meta:
		aliases = "delete_non_B_K_work_stuff"
		type = "func"
		size = "203"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 8D 77 30 49 89 FC 48 8D 7F 08 55 53 E8 8C FF FF FF 49 8B 7C 24 08 48 85 FF 74 17 E8 ?? ?? ?? ?? 49 C7 44 24 08 00 00 00 00 41 C7 44 24 34 00 00 00 00 49 8B 44 24 50 48 85 C0 74 43 41 8B 54 24 58 85 D2 7E 29 31 ED 31 DB 0F 1F 40 00 48 8B 3C 28 48 85 FF 74 0A E8 ?? ?? ?? ?? 49 8B 44 24 50 83 C3 01 48 83 C5 08 41 39 5C 24 58 7F DF 48 89 C7 E8 ?? ?? ?? ?? 49 C7 44 24 50 00 00 00 00 49 8B 5C 24 60 48 85 DB 74 3A 48 8B 3B 48 85 FF 74 21 E8 ?? ?? ?? ?? 48 C7 43 08 00 00 00 00 48 C7 43 10 00 00 00 00 48 C7 03 00 00 00 00 49 8B 5C 24 60 48 89 DF E8 ?? ?? ?? ?? 49 C7 44 24 60 00 00 00 00 5B 5D }
	condition:
		$pattern
}

rule __cxa_atexit_74a4667f311466b0ed569a94f7e919f2 {
	meta:
		aliases = "__GI___cxa_atexit, __cxa_atexit"
		type = "func"
		size = "61"
		objfiles = "__cxa_atexit@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 D4 31 D2 48 85 FF 55 48 89 F5 53 48 89 FB 74 22 E8 ?? ?? ?? ?? 83 CA FF 48 85 C0 74 15 48 89 58 08 48 89 68 10 31 D2 4C 89 60 18 48 C7 00 03 00 00 00 5B 5D 41 5C 89 D0 C3 }
	condition:
		$pattern
}

rule pex_get_status_de9bd26132b814d2f4dfbabec2c25860 {
	meta:
		aliases = "pex_get_status"
		type = "func"
		size = "127"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 D4 55 48 63 EE 53 48 89 FB 48 83 EC 10 48 83 7F 38 00 74 50 48 63 43 2C 39 E8 7C 28 48 8B 73 38 48 8D 14 AD 00 00 00 00 4C 89 E7 E8 ?? ?? ?? ?? B8 01 00 00 00 48 83 C4 10 5B 5D 41 5C C3 66 0F 1F 44 00 00 29 C5 49 8D 3C 84 31 F6 48 63 D5 48 C1 E2 02 E8 ?? ?? ?? ?? 48 63 6B 2C EB BE 66 0F 1F 44 00 00 48 8D 4C 24 04 48 8D 54 24 08 31 F6 E8 07 F6 FF FF 85 C0 75 9B EB BA }
	condition:
		$pattern
}

rule splay_tree_new_c850419c6989c13614cf86e6623b709c {
	meta:
		aliases = "splay_tree_new"
		type = "func"
		size = "71"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 D4 55 48 89 F5 53 48 89 FB BF 38 00 00 00 E8 ?? ?? ?? ?? 48 C7 00 00 00 00 00 48 89 58 08 48 89 68 10 4C 89 60 18 48 C7 40 20 ?? ?? ?? ?? 48 C7 40 28 ?? ?? ?? ?? 48 C7 40 30 00 00 00 00 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule fibheap_insert_dd28eca3b80fb9ca61d77fc63ea6af4c {
	meta:
		aliases = "fibheap_insert"
		type = "func"
		size = "162"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 D4 55 48 89 F5 BE 38 00 00 00 53 48 89 FB BF 01 00 00 00 E8 ?? ?? ?? ?? 48 89 40 10 48 89 40 18 4C 89 60 28 48 8B 53 10 48 89 68 20 48 85 D2 74 43 48 8B 4A 18 48 39 CA 74 52 48 89 48 18 48 8B 4A 18 48 89 41 10 48 89 42 18 48 89 50 10 48 8B 53 08 48 85 D2 74 0A 48 8B 72 20 48 39 70 20 7D 04 48 89 43 08 48 83 03 01 5B 5D 41 5C C3 66 0F 1F 44 00 00 48 89 43 10 48 89 40 10 48 89 40 18 EB CC 66 2E 0F 1F 84 00 00 00 00 00 48 89 42 18 48 89 42 10 48 89 50 18 48 89 50 10 EB B0 }
	condition:
		$pattern
}

rule ternary_insert_9aee5a68eeaf5aa56eec6b182da6fc63 {
	meta:
		aliases = "ternary_insert"
		type = "func"
		size = "201"
		objfiles = "ternary@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 D4 55 48 89 FD 53 48 89 F3 0F 1F 00 4C 8B 45 00 4D 85 C0 74 4B 0F B6 13 41 0F BE 30 0F BE C2 29 F0 75 27 48 83 C3 01 84 D2 0F 84 7D 00 00 00 49 8D 68 10 4C 8B 45 00 4D 85 C0 74 24 0F B6 13 41 0F BE 30 0F BE C2 29 F0 74 D9 49 8D 68 08 49 83 C0 18 85 C0 49 0F 49 E8 EB B2 66 90 48 8D 68 10 BF 20 00 00 00 48 83 C3 01 E8 ?? ?? ?? ?? 48 89 45 00 0F B6 53 FF 48 C7 40 10 00 00 00 00 48 C7 40 18 00 00 00 00 48 C7 40 08 00 00 00 00 88 10 80 7B FF 00 75 C6 4C 89 60 10 4C 89 E0 5B 5D 41 5C C3 66 2E 0F 1F 84 00 00 00 00 00 85 C9 74 0C 4D 89 60 10 4C 89 E0 5B 5D 41 5C C3 5B 5D 49 8B 40 10 41 5C }
	condition:
		$pattern
}

rule _pthread_cleanup_push_67f513242058e016d346083fa83d91bd {
	meta:
		aliases = "_pthread_cleanup_push"
		type = "func"
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
		type = "func"
		size = "75"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 D4 55 48 89 FD 53 48 89 F3 E8 68 FF FF FF 48 89 5D 00 48 89 C2 4C 89 65 08 0F BE 40 79 89 45 10 48 8B 42 70 48 85 C0 48 89 45 18 74 0D 48 39 C5 72 08 48 C7 45 18 00 00 00 00 C6 42 79 00 48 89 6A 70 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule pex_get_times_17a6cf31f7ebec9f04c450a3e5947ceb {
	meta:
		aliases = "pex_get_times"
		type = "func"
		size = "143"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 D4 55 89 F5 53 48 89 FB 48 83 EC 10 48 83 7F 38 00 74 61 48 8B 73 40 48 85 F6 74 50 48 63 4B 2C 39 E9 7C 20 48 63 D5 4C 89 E7 48 C1 E2 05 E8 ?? ?? ?? ?? B8 01 00 00 00 48 83 C4 10 5B 5D 41 5C C3 0F 1F 00 29 CD 48 C1 E1 05 31 F6 48 63 D5 49 8D 3C 0C 48 C1 E2 05 E8 ?? ?? ?? ?? 8B 6B 2C 48 8B 73 40 EB BF 0F 1F 80 00 00 00 00 31 C0 EB C8 0F 1F 40 00 48 8D 4C 24 04 48 8D 54 24 08 31 F6 E8 77 F5 FF FF 85 C0 75 8A EB AD }
	condition:
		$pattern
}

rule pthread_sigmask_32dc588768addd40486aa509ac58b4fd {
	meta:
		aliases = "pthread_sigmask"
		type = "func"
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
		type = "func"
		size = "35"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 53 89 FB 48 63 DB 48 83 EC 08 E8 7D FF FF FF 4C 89 A4 D8 48 02 00 00 31 C0 5A 5B 41 5C C3 }
	condition:
		$pattern
}

rule remember_Ktype_fd14eebb2fd7b06edc278c3f698830c4 {
	meta:
		aliases = "remember_Ktype"
		type = "func"
		size = "135"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 48 63 EA 53 8B 47 28 48 89 FB 39 47 20 7C 20 85 C0 74 57 01 C0 89 47 28 48 98 48 8B 7F 10 48 8D 34 C5 00 00 00 00 E8 ?? ?? ?? ?? 48 89 43 10 8D 7D 01 48 63 FF E8 ?? ?? ?? ?? 48 89 EA 4C 89 E6 48 89 C7 E8 ?? ?? ?? ?? C6 04 28 00 48 89 C1 48 63 43 20 48 8B 53 10 8D 70 01 89 73 20 48 89 0C C2 5B 5D 41 5C C3 0F 1F 40 00 C7 47 28 05 00 00 00 BF 28 00 00 00 E8 ?? ?? ?? ?? 48 89 43 10 EB AE }
	condition:
		$pattern
}

rule remember_type_DOT_part_DOT_12_8c54335e7a3539e692b8727619b7dc74 {
	meta:
		aliases = "remember_type.part.12"
		type = "func"
		size = "134"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 48 63 EA 53 8B 47 34 48 89 FB 39 47 30 7C 19 85 C0 75 4F C7 47 34 03 00 00 00 BF 18 00 00 00 E8 ?? ?? ?? ?? 48 89 43 08 8D 7D 01 48 63 FF E8 ?? ?? ?? ?? 48 89 EA 4C 89 E6 48 89 C7 E8 ?? ?? ?? ?? C6 04 28 00 48 89 C1 48 63 43 30 48 8B 53 08 8D 70 01 89 73 30 48 89 0C C2 5B 5D 41 5C C3 0F 1F 00 01 C0 89 47 34 48 98 48 8B 7F 08 48 8D 34 C5 00 00 00 00 E8 ?? ?? ?? ?? 48 89 43 08 EB A8 }
	condition:
		$pattern
}

rule string_prependn_DOT_part_DOT_5_996b025bd5efbc1c8d0cfa4c2ba92659 {
	meta:
		aliases = "string_prependn.part.5"
		type = "func"
		size = "79"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 48 63 EA 89 EE 53 48 89 FB E8 2C FF FF FF 48 8B 43 08 48 8B 3B 48 83 E8 01 48 39 F8 72 17 0F 1F 40 00 0F B6 08 48 83 E8 01 88 4C 28 01 48 8B 3B 48 39 F8 73 ED 48 89 EA 4C 89 E6 E8 ?? ?? ?? ?? 48 01 6B 08 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule string_appendn_DOT_part_DOT_4_1b5980000dbef72ad600143296905dcf {
	meta:
		aliases = "string_appendn.part.4"
		type = "func"
		size = "44"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 48 63 EA 89 EE 53 48 89 FB E8 5C FF FF FF 48 8B 7B 08 48 89 EA 4C 89 E6 E8 ?? ?? ?? ?? 48 01 6B 08 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule pthread_mutex_timedlock_c7dc801c1a3c2acb047be9c3682bf249 {
	meta:
		aliases = "pthread_mutex_timedlock"
		type = "func"
		size = "205"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 48 89 FD 53 48 81 7E 08 FF C9 9A 3B 0F 87 A9 00 00 00 8B 47 10 83 F8 01 74 28 7F 09 85 C0 74 15 E9 96 00 00 00 83 F8 02 74 46 83 F8 03 0F 85 88 00 00 00 EB 6E 48 8D 7F 18 31 F6 E8 ?? ?? ?? ?? EB 2A E8 51 FE FF FF 48 39 45 08 48 89 C3 75 05 FF 45 04 EB 17 48 8D 7D 18 48 89 C6 E8 ?? ?? ?? ?? 48 89 5D 08 C7 45 04 00 00 00 00 31 D2 EB 50 E8 23 FE FF FF 48 39 45 08 48 89 C3 BA 23 00 00 00 74 3D 48 8D 7D 18 4C 89 E2 48 89 C6 E8 ?? ?? ?? ?? 85 C0 BA 6E 00 00 00 74 25 30 D2 48 89 5D 08 EB 1D 48 8D 7F 18 48 89 F2 31 F6 E8 ?? ?? ?? ?? 83 F8 01 19 D2 83 E2 6E EB 05 BA 16 00 00 00 5B 5D }
	condition:
		$pattern
}

rule pthread_once_f7a9de83ac2106807ae73db55c0445fe {
	meta:
		aliases = "__pthread_once, pthread_once"
		type = "func"
		size = "207"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 48 89 FD 53 48 83 EC 20 83 3F 02 75 05 E9 AC 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 00 89 D0 83 E0 03 FF C8 75 23 83 E2 FC 3B 15 ?? ?? ?? ?? 74 18 C7 45 00 00 00 00 00 EB 0F BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 00 89 D0 83 E0 03 FF C8 74 E5 31 DB 85 D2 75 49 8B 05 ?? ?? ?? ?? BF ?? ?? ?? ?? 83 C8 01 89 45 00 E8 ?? ?? ?? ?? 48 89 EA BE ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? 41 FF D4 31 F6 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BB 01 00 00 00 C7 45 00 02 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 DB 74 0A BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 C4 20 }
	condition:
		$pattern
}

rule pmap_unset_d9bfaee8d4b03ed087cbd990caa87307 {
	meta:
		aliases = "__GI_pmap_unset, pmap_unset"
		type = "func"
		size = "217"
		objfiles = "pmap_clnt@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 48 89 FD 53 48 83 EC 50 48 8D 5C 24 30 C7 44 24 4C FF FF FF FF 48 89 DF E8 A9 FE FF FF 85 C0 0F 84 A3 00 00 00 48 8B 0D ?? ?? ?? ?? 4C 8B 05 ?? ?? ?? ?? 4C 8D 4C 24 4C 48 89 DF BA 02 00 00 00 BE A0 86 01 00 C7 44 24 08 90 01 00 00 C7 04 24 90 01 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 67 48 89 6C 24 10 4C 89 64 24 18 48 8D 4C 24 10 48 C7 44 24 20 00 00 00 00 48 C7 44 24 28 00 00 00 00 4C 8D 4C 24 48 4C 8B 50 08 48 8B 05 ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? BA ?? ?? ?? ?? BE 02 00 00 00 48 89 DF 48 89 04 24 48 8B 05 ?? ?? ?? ?? 48 89 44 24 08 41 FF 12 48 8B 43 08 48 89 DF FF 50 20 }
	condition:
		$pattern
}

rule __encode_question_222b9cfed52f5d88af83d97130a32b28 {
	meta:
		aliases = "__encode_question"
		type = "func"
		size = "80"
		objfiles = "encodeq@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 48 89 FD 53 48 8B 3F 89 D3 E8 ?? ?? ?? ?? 85 C0 89 C1 78 2F 29 C3 83 FB 03 7F 05 83 C9 FF EB 23 48 63 D0 0F B6 45 09 83 C1 04 49 8D 14 14 88 02 8B 45 08 88 42 01 0F B6 45 0D 88 42 02 8B 45 0C 88 42 03 5B 5D 41 5C 89 C8 C3 }
	condition:
		$pattern
}

rule wcscasecmp_0ad9d37e485803e18659390d6c4f837f {
	meta:
		aliases = "__GI_wcscasecmp, wcscasecmp"
		type = "func"
		size = "90"
		objfiles = "wcscasecmp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 48 89 FD 53 EB 12 83 7D 00 00 75 04 31 C0 EB 3F 48 83 C5 04 49 83 C4 04 8B 7D 00 41 3B 3C 24 74 E5 E8 ?? ?? ?? ?? 41 8B 3C 24 89 C3 E8 ?? ?? ?? ?? 39 C3 74 D1 8B 7D 00 E8 ?? ?? ?? ?? 41 8B 3C 24 89 C3 E8 ?? ?? ?? ?? 39 C3 19 C0 83 C8 01 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule vdprintf_3e276dae4a6d1b9c31585e063ceac8b6 {
	meta:
		aliases = "__GI_vdprintf, vdprintf"
		type = "func"
		size = "165"
		objfiles = "vdprintf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 53 48 89 D3 48 81 EC C0 00 00 00 48 8D 84 24 80 00 00 00 48 8D 94 24 C0 00 00 00 89 7C 24 04 48 8D 7C 24 58 66 C7 04 24 D0 00 C6 44 24 02 00 48 89 54 24 10 48 89 44 24 08 48 89 44 24 28 48 89 44 24 30 48 89 44 24 18 48 89 44 24 20 C7 44 24 48 00 00 00 00 C7 44 24 50 01 00 00 00 E8 ?? ?? ?? ?? 48 89 DA 4C 89 E6 48 89 E7 48 C7 44 24 38 00 00 00 00 E8 ?? ?? ?? ?? 85 C0 89 C3 7E 12 48 89 E7 E8 ?? ?? ?? ?? 85 C0 B8 FF FF FF FF 0F 45 D8 48 81 C4 C0 00 00 00 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule pthread_cond_wait_3985a8f2d65a627d36433bb1c4230409 {
	meta:
		aliases = "__GI_pthread_cond_wait, pthread_cond_wait"
		type = "func"
		size = "349"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 53 48 89 FB 48 83 EC 20 E8 8D FD FF FF 48 89 44 24 18 41 8B 44 24 10 83 F8 03 74 19 85 C0 74 15 48 8B 44 24 18 49 39 44 24 08 BA 16 00 00 00 0F 85 17 01 00 00 48 8B 44 24 18 48 89 1C 24 48 89 E6 48 C7 44 24 08 ?? ?? ?? ?? C6 80 D1 02 00 00 00 48 8B 7C 24 18 E8 AA FC FF FF 48 8B 74 24 18 48 89 DF E8 ?? ?? ?? ?? 48 8B 44 24 18 80 78 7A 00 74 10 48 8B 44 24 18 BD 01 00 00 00 80 78 78 00 74 10 48 8B 74 24 18 48 8D 7B 10 31 ED E8 E0 FB FF FF 48 89 DF E8 ?? ?? ?? ?? 85 ED 74 0E 48 8B 7C 24 18 31 F6 E8 5A FC FF FF EB 78 4C 89 E7 31 DB E8 ?? ?? ?? ?? 48 8B 7C 24 18 E8 63 FD FF FF 48 }
	condition:
		$pattern
}

rule dyn_string_copy_cstr_c58cb082c93f54c447237271b0e48e99 {
	meta:
		aliases = "dyn_string_copy_cstr"
		type = "func"
		size = "65"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 53 48 89 FB 48 89 F7 E8 ?? ?? ?? ?? 48 89 DF 89 C6 48 89 C5 E8 ?? ?? ?? ?? 31 D2 48 85 C0 74 14 48 8B 7B 08 4C 89 E6 E8 ?? ?? ?? ?? 89 6B 04 BA 01 00 00 00 5B 5D 89 D0 41 5C C3 }
	condition:
		$pattern
}

rule string_append_DOT_part_DOT_8_c591ffe755f322e0e3a888d0ff91b098 {
	meta:
		aliases = "string_append.part.8"
		type = "func"
		size = "58"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 53 48 89 FB 48 89 F7 E8 ?? ?? ?? ?? 48 89 DF 89 C6 48 89 C5 E8 A1 FE FF FF 48 8B 7B 08 48 63 ED 4C 89 E6 48 89 EA E8 ?? ?? ?? ?? 48 01 6B 08 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule dyn_string_append_cstr_74f692aae51141f3add6229091c31ee5 {
	meta:
		aliases = "dyn_string_append_cstr"
		type = "func"
		size = "72"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 53 48 89 FB 48 89 F7 E8 ?? ?? ?? ?? 8B 73 04 48 89 DF 48 89 C5 01 C6 E8 ?? ?? ?? ?? 31 D2 48 85 C0 74 18 48 63 7B 04 4C 89 E6 48 03 7B 08 E8 ?? ?? ?? ?? 01 6B 04 BA 01 00 00 00 5B 5D 89 D0 41 5C C3 }
	condition:
		$pattern
}

rule pthread_attr_setschedparam_55484993d329653135ed4fc2f8eb5042 {
	meta:
		aliases = "__GI_pthread_attr_setschedparam, pthread_attr_setschedparam"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "117"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 53 89 FB 48 83 EC 30 E8 ?? ?? ?? ?? 89 C5 31 C0 85 ED 78 52 48 89 E2 BE 10 89 00 00 89 EF 89 5C 24 10 E8 ?? ?? ?? ?? 85 C0 79 24 E8 ?? ?? ?? ?? 8B 18 89 EF 49 89 C4 E8 ?? ?? ?? ?? B8 06 00 00 00 83 FB 13 0F 44 D8 31 C0 41 89 1C 24 EB 17 89 EF E8 ?? ?? ?? ?? BA 10 00 00 00 48 89 E6 4C 89 E7 E8 ?? ?? ?? ?? 48 83 C4 30 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule svcraw_reply_63c6bf32d84f63b748f602e691eb0379 {
	meta:
		aliases = "svcraw_reply"
		type = "func"
		size = "98"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 53 E8 ?? ?? ?? ?? 48 8B 98 F8 00 00 00 48 85 DB 74 43 48 8B 83 B8 23 00 00 48 8D AB B0 23 00 00 31 F6 C7 83 B0 23 00 00 00 00 00 00 48 89 EF FF 50 28 4C 89 E6 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 14 48 8B 83 B8 23 00 00 48 89 EF FF 50 20 B8 01 00 00 00 EB 02 31 C0 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule trecurse_c16b4f50d0c00f720eed07774eb2d7ea {
	meta:
		aliases = "trecurse"
		type = "func"
		size = "116"
		objfiles = "twalk@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 F4 55 89 D5 53 48 83 7F 08 00 48 89 FB 75 0E 48 83 7F 10 00 75 07 BE 03 00 00 00 EB 46 31 F6 48 89 DF 89 EA 41 FF D4 48 8B 7B 08 48 85 FF 74 0B 8D 55 01 4C 89 E6 E8 C1 FF FF FF 48 89 DF 89 EA BE 01 00 00 00 41 FF D4 48 8B 7B 10 48 85 FF 74 0B 8D 55 01 4C 89 E6 E8 A0 FF FF FF 89 EA BE 02 00 00 00 48 89 DF 4D 89 E3 5B 5D 41 5C 41 FF E3 }
	condition:
		$pattern
}

rule getrpcbyname_9ee0c7b3a151107dc49dd59986903a89 {
	meta:
		aliases = "__GI_getrpcbyname, getrpcbyname"
		type = "func"
		size = "88"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 31 FF 55 53 E8 ?? ?? ?? ?? EB 2E 48 8B 7D 00 4C 89 E6 E8 ?? ?? ?? ?? 85 C0 74 30 48 8B 5D 08 EB 10 4C 89 E6 E8 ?? ?? ?? ?? 85 C0 74 1E 48 83 C3 08 48 8B 3B 48 85 FF 75 E8 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 75 C5 E8 ?? ?? ?? ?? 5B 48 89 E8 5D 41 5C C3 }
	condition:
		$pattern
}

rule seed48_r_bb7285ed8a06f650a20d1dea092e2510 {
	meta:
		aliases = "__GI_seed48_r, seed48_r"
		type = "func"
		size = "88"
		objfiles = "seed48_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 48 8D 7E 06 BA 06 00 00 00 53 48 89 F3 48 83 EC 08 E8 ?? ?? ?? ?? 66 41 8B 44 24 04 48 B9 6D E6 EC DE 05 00 00 00 66 89 43 04 66 41 8B 44 24 02 66 89 43 02 66 41 8B 04 24 48 89 4B 10 66 C7 43 0C 0B 00 66 C7 43 0E 01 00 66 89 03 31 C0 5A 5B 41 5C C3 }
	condition:
		$pattern
}

rule exchange_4ed62b7dd92f4195b1e2aadebd944c31 {
	meta:
		aliases = "exchange"
		type = "func"
		size = "180"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 49 89 F0 55 53 8B 7E 28 8B 6E 2C 8B 1E EB 79 41 89 DA 41 89 E9 45 31 DB 41 29 EA 41 29 F9 45 39 CA 7E 5D 41 89 DB 45 31 D2 45 29 CB EB 24 41 8D 0C 3A 43 8D 04 13 41 FF C2 48 63 C9 48 98 49 8D 0C CC 49 8D 04 C4 48 8B 31 48 8B 10 48 89 11 48 89 30 45 39 CA 7C D7 44 29 CB EB 2C 41 8D 0C 3B 41 8D 04 2B 41 FF C3 48 63 C9 48 98 49 8D 0C CC 49 8D 04 C4 48 8B 31 48 8B 10 48 89 11 48 89 30 45 39 D3 7C D7 44 01 D7 39 EB 7E 08 39 FD 0F 8F 7B FF FF FF 41 8B 40 28 41 03 00 41 2B 40 2C 41 89 40 28 41 8B 00 41 89 40 2C 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule remquo_e2c989a09f5b28aaf90f94893c3b34f3 {
	meta:
		aliases = "__GI_remquo, remquo"
		type = "func"
		size = "109"
		objfiles = "s_remquo@libm.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 53 31 DB 48 83 EC 18 F2 0F 11 44 24 10 F2 0F 5E C1 48 8B 54 24 10 F2 0F 11 4C 24 08 48 8B 44 24 08 48 C1 EA 20 48 C1 E8 20 C1 EA 1F C1 E8 1F 39 C2 0F 94 C3 8D 5C 1B FF 48 63 DB E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 E0 7F 48 0F AF C3 41 89 04 24 F2 0F 10 4C 24 08 F2 0F 10 44 24 10 48 83 C4 18 5B 41 5C E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule cond_extricate_func_5f37f31f0cdf162e5aa25c8e8f0e3ad7 {
	meta:
		aliases = "cond_extricate_func"
		type = "func"
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
		type = "func"
		size = "69"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 53 48 89 F3 48 83 EC 18 E8 A9 FF FF FF 48 89 44 24 10 48 8B 74 24 10 4C 89 E7 E8 ?? ?? ?? ?? 49 8D 7C 24 18 48 89 DE E8 39 FE FF FF 4C 89 E7 89 C3 E8 ?? ?? ?? ?? 89 D8 48 83 C4 18 5B 41 5C C3 }
	condition:
		$pattern
}

rule getservbyname_8e1e786bc2c5c5ad165fa16759688d04 {
	meta:
		aliases = "getservbyname"
		type = "func"
		size = "65"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 53 48 89 F3 48 83 EC 18 E8 E9 FA FF FF 48 8B 0D ?? ?? ?? ?? 4C 8D 4C 24 10 48 89 DE 4C 89 E7 41 B8 19 11 00 00 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 44 24 10 48 83 C4 18 5B 41 5C C3 }
	condition:
		$pattern
}

rule siglongjmp_0ce50aa11f2db21434f5f07bf90c1ab3 {
	meta:
		aliases = "siglongjmp"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "65"
		objfiles = "gethostbyname2@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 53 89 F3 48 83 EC 18 E8 ?? ?? ?? ?? 4C 8D 4C 24 10 89 DE 4C 89 E7 41 B8 00 02 00 00 B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 04 24 E8 ?? ?? ?? ?? 48 8B 44 24 10 48 83 C4 18 5B 41 5C C3 }
	condition:
		$pattern
}

rule byte_common_op_match_null_stri_ee81016f7b32a91ab3530d37cf99176a {
	meta:
		aliases = "byte_common_op_match_null_string_p"
		type = "func"
		size = "270"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 48 89 D5 53 48 83 EC 10 48 8B 0F 48 89 4C 24 08 8A 01 48 8D 79 01 48 89 7C 24 08 3C 0C 77 21 3C 09 0F 83 C8 00 00 00 3C 06 74 35 3C 08 0F 84 B2 00 00 00 84 C0 0F 84 B4 00 00 00 E9 BF 00 00 00 3C 15 74 6A 77 0A 3C 0D 0F 85 B1 00 00 00 EB 46 83 E8 1A 3C 03 0F 87 A4 00 00 00 E9 8F 00 00 00 0F B6 59 01 48 8D 7C 24 08 E8 09 01 00 00 40 88 C6 48 63 DB 48 8D 4C DD 00 8A 01 83 E0 03 3C 03 75 0F 8A 01 40 88 F2 83 E2 03 83 E0 FC 09 D0 88 01 40 84 F6 EB 57 0F BE 47 01 0F B6 51 01 C1 E0 08 01 D0 78 5A 48 98 48 8D 44 01 03 EB 30 48 8D 71 03 48 89 74 24 08 0F BE 46 01 0F B6 51 03 C1 E0 08 }
	condition:
		$pattern
}

rule svc_find_9dc4ccb88bc3a285bd6c6655aa70f163 {
	meta:
		aliases = "svc_find"
		type = "func"
		size = "61"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 48 89 D5 53 48 89 F3 E8 ?? ?? ?? ?? 48 8B 80 F0 00 00 00 31 D2 EB 12 4C 39 60 08 75 06 48 39 58 10 74 0B 48 89 C2 48 8B 00 48 85 C0 75 E9 48 89 55 00 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule gethostname_464545322024336dae2a43d1e6029732 {
	meta:
		aliases = "__GI_gethostname, gethostname"
		type = "func"
		size = "94"
		objfiles = "gethostname@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 48 89 F5 53 48 81 EC 90 01 00 00 48 89 E7 48 89 E3 E8 ?? ?? ?? ?? 83 F8 FF 74 31 48 83 C3 41 48 89 DF E8 ?? ?? ?? ?? 48 FF C0 48 39 E8 76 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 0D 48 89 DE 4C 89 E7 E8 ?? ?? ?? ?? 31 C0 48 81 C4 90 01 00 00 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule getdomainname_abc0f90b16749a5b018acbca3906957b {
	meta:
		aliases = "__GI___libc_getdomainname, __GI_getdomainname, __libc_getdomainname, getdomainname"
		type = "func"
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
		type = "func"
		size = "120"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 48 89 F5 53 48 8B 06 EB 36 90 4D 85 C9 74 21 89 DE 49 89 E8 4C 89 E1 83 CE 02 49 8B 14 24 BF 01 00 00 00 41 FF D1 83 F8 07 74 3D 83 F8 08 75 33 85 DB 75 39 48 8B 45 00 48 8B 00 48 89 45 00 45 31 C9 48 85 C0 BA 05 00 00 00 74 06 4C 8B 48 30 30 D2 31 DB 49 3B 44 24 18 0F 94 C3 C1 E3 02 85 D2 74 A7 B8 02 00 00 00 5B 5D 41 5C C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule forget_types_DOT_isra_DOT_1_606f9059f3173011a17fb16f94d55ef1 {
	meta:
		aliases = "forget_types.isra.1"
		type = "func"
		size = "91"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 48 89 F5 53 8B 45 00 48 63 D0 48 8D 1C D5 F8 FF FF FF EB 20 66 0F 1F 44 00 00 49 8B 14 24 83 E8 01 48 8D 4B F8 89 45 00 48 8B 3C 1A 48 85 FF 75 11 48 89 CB 85 C0 7F E2 5B 5D 41 5C C3 0F 1F 44 00 00 E8 ?? ?? ?? ?? 49 8B 04 24 48 C7 04 18 00 00 00 00 EB AF }
	condition:
		$pattern
}

rule if_nametoindex_f972dad1fdb56a40c7ae4557b7e3564d {
	meta:
		aliases = "__GI_if_nametoindex, if_nametoindex"
		type = "func"
		size = "115"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 53 48 83 EC 30 E8 ?? ?? ?? ?? 85 C0 89 C5 78 52 BA 10 00 00 00 4C 89 E6 48 89 E7 E8 ?? ?? ?? ?? 31 C0 48 89 E2 BE 33 89 00 00 89 EF E8 ?? ?? ?? ?? 85 C0 79 20 E8 ?? ?? ?? ?? 8B 18 89 EF 49 89 C4 E8 ?? ?? ?? ?? 83 FB 16 75 17 41 C7 04 24 26 00 00 00 EB 0D 89 EF E8 ?? ?? ?? ?? 8B 44 24 10 EB 02 31 C0 48 83 C4 30 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __pthread_do_exit_a73e00bb72d90947adc6b5290b3199d7 {
	meta:
		aliases = "__pthread_do_exit"
		type = "func"
		size = "236"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 53 48 89 F3 48 81 EC B0 00 00 00 E8 58 FF FF FF 48 89 DF 48 89 C5 C6 40 78 01 C6 40 79 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 7D 30 48 89 EE E8 ?? ?? ?? ?? 83 BD A4 02 00 00 00 4C 89 65 58 74 2E 8B 05 ?? ?? ?? ?? 0B 85 A8 02 00 00 F6 C4 01 74 1D C7 85 B0 02 00 00 09 00 00 00 48 89 AD B8 02 00 00 48 89 2D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 5D 68 48 8B 7D 30 C6 45 50 01 E8 ?? ?? ?? ?? 48 85 DB 74 08 48 89 DF E8 ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? 48 39 DD 75 46 83 3D ?? ?? ?? ?? 00 78 3D 48 89 1C 24 C7 44 24 08 03 00 00 00 8B 3D ?? ?? ?? ?? BA A8 00 00 00 48 89 E6 E8 ?? ?? ?? ?? 48 }
	condition:
		$pattern
}

rule wcsdup_2ddfb0542661823addfbfdcc0fe4a3ad {
	meta:
		aliases = "wcsdup"
		type = "func"
		size = "58"
		objfiles = "wcsdup@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 53 E8 ?? ?? ?? ?? 48 8D 2C 85 04 00 00 00 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 0E 48 89 EA 4C 89 E6 48 89 C7 E8 ?? ?? ?? ?? 48 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule strdup_928dc0fe883cbf38536f3a6987ccba7a {
	meta:
		aliases = "__GI_strdup, strdup"
		type = "func"
		size = "54"
		objfiles = "strdup@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 53 E8 ?? ?? ?? ?? 48 8D 68 01 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 0E 48 89 EA 4C 89 E6 48 89 C7 E8 ?? ?? ?? ?? 48 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule strndup_10814bf1eca227bcec5f68c16fc201d4 {
	meta:
		aliases = "__GI_strndup, strndup"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "318"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 89 D5 BA ?? ?? ?? ?? 53 89 F3 BE ?? ?? ?? ?? 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 4D 85 E4 89 1D ?? ?? ?? ?? 49 0F 45 C4 85 ED 48 89 05 ?? ?? ?? ?? 74 15 8B 05 ?? ?? ?? ?? F7 C5 07 FC FF FF 0F 44 C5 89 05 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? FF BD 02 00 00 00 75 62 F6 05 ?? ?? ?? ?? 08 74 59 31 D2 BF 01 00 00 00 89 EE E8 ?? ?? ?? ?? 83 F8 FF 89 C7 89 05 ?? ?? ?? ?? 0F 84 93 00 00 00 BA 01 00 00 00 BE 02 00 00 00 31 C0 E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? BE 03 00 00 00 31 C0 E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 80 CC 08 BE 04 00 00 00 89 C2 }
	condition:
		$pattern
}

rule xprt_unregister_79c04f133d40d3bef56e1adbbe70aaa0 {
	meta:
		aliases = "__GI_xprt_unregister, xprt_unregister"
		type = "func"
		size = "138"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 8B 2F 53 E8 ?? ?? ?? ?? 39 C5 7D 73 E8 ?? ?? ?? ?? 48 63 DD 48 8B 80 E8 00 00 00 48 8D 14 DD 00 00 00 00 4C 39 24 10 75 56 81 FD FF 03 00 00 48 C7 04 10 00 00 00 00 7E 04 31 DB EB 39 E8 ?? ?? ?? ?? 89 E9 48 C1 EB 06 48 C7 C2 FE FF FF FF 83 E1 3F 48 D3 C2 48 21 14 D8 EB DE E8 ?? ?? ?? ?? 48 63 D3 48 C1 E2 03 48 03 10 39 2A 75 06 C7 02 FF FF FF FF FF C3 E8 ?? ?? ?? ?? 3B 18 7C DC 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule cplus_demangle_name_to_style_77eed69686d6577052d3314d0d1e5f26 {
	meta:
		aliases = "cplus_demangle_name_to_style"
		type = "func"
		size = "57"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 BD FF FF FF FF 53 BB ?? ?? ?? ?? EB 10 0F 1F 44 00 00 48 83 C3 18 8B 6B 08 85 ED 74 0F 48 8B 33 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 75 E6 5B 89 E8 5D 41 5C C3 }
	condition:
		$pattern
}

rule getnetbyname_be87f83c476990b4a02e4989d3192038 {
	meta:
		aliases = "getnetbyname"
		type = "func"
		size = "101"
		objfiles = "getnetbynm@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 8B 3D ?? ?? ?? ?? 55 53 E8 ?? ?? ?? ?? EB 2E 48 8B 7D 00 4C 89 E6 E8 ?? ?? ?? ?? 85 C0 74 2B 48 8B 5D 08 EB 10 4C 89 E6 E8 ?? ?? ?? ?? 85 C0 74 19 48 83 C3 08 48 8B 3B 48 85 FF 75 E8 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 75 C5 83 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 5B 48 89 E8 5D 41 5C C3 }
	condition:
		$pattern
}

rule nanosleep_63f587e4af7130c1b60d9c182931d535 {
	meta:
		aliases = "__GI_nanosleep, nanosleep"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "105"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC BF ?? ?? ?? ?? 55 48 89 F5 53 31 DB E8 ?? ?? ?? ?? EB 35 48 63 C3 48 C1 E0 04 83 B8 ?? ?? ?? ?? 00 75 23 BF ?? ?? ?? ?? C7 80 ?? ?? ?? ?? 01 00 00 00 48 89 A8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 41 89 1C 24 EB 19 FF C3 81 FB FF 03 00 00 7E C3 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 0B 00 00 00 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __getutid_0edaf2d381893f7e14552485d0c6eece {
	meta:
		aliases = "__getutid"
		type = "func"
		size = "102"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 4C 8D 67 28 55 48 89 FD 53 EB 3E 8B 55 00 8D 42 FF 66 83 F8 03 77 05 66 39 13 74 40 66 83 FA 05 74 12 66 83 FA 08 74 0C 66 83 FA 06 74 06 66 83 FA 07 75 15 48 8D 7B 28 BA 04 00 00 00 4C 89 E6 E8 ?? ?? ?? ?? 85 C0 74 13 8B 3D ?? ?? ?? ?? E8 73 FF FF FF 48 85 C0 48 89 C3 75 AF 48 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __get_next_rpcent_1f19f30a692fc21823440af152194a72 {
	meta:
		aliases = "__get_next_rpcent"
		type = "func"
		size = "275"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 4C 8D A7 48 01 00 00 55 48 89 FD 53 48 8B 55 00 BE 00 10 00 00 4C 89 E7 E8 ?? ?? ?? ?? 48 85 C0 0F 84 E6 00 00 00 4C 89 E7 E8 ?? ?? ?? ?? C6 84 05 47 01 00 00 0A 80 BD 48 01 00 00 23 74 CD BE 23 00 00 00 4C 89 E7 E8 ?? ?? ?? ?? 48 85 C0 75 12 BE 0A 00 00 00 4C 89 E7 E8 ?? ?? ?? ?? 48 85 C0 74 A9 C6 00 00 4C 89 E7 E8 50 FF FF FF 48 85 C0 74 99 48 8D 58 01 C6 00 00 4C 89 A5 30 01 00 00 EB 03 48 FF C3 8A 03 3C 20 74 F7 3C 09 74 F3 4C 8D 65 18 48 89 DF E8 ?? ?? ?? ?? 48 89 DF 89 85 40 01 00 00 4C 89 A5 38 01 00 00 E8 0D FF FF FF 31 FF 48 85 C0 74 33 48 8D 78 01 C6 00 00 EB 2A 3C 20 74 21 3C }
	condition:
		$pattern
}

rule svcunix_reply_aee213947b63da36c090a870ec1f50d4 {
	meta:
		aliases = "svctcp_reply, svcunix_reply"
		type = "func"
		size = "59"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 53 48 83 EC 08 48 8B 47 40 4C 8D 60 10 C7 40 10 00 00 00 00 48 8B 40 08 4C 89 E7 48 89 06 E8 ?? ?? ?? ?? 4C 89 E7 BE 01 00 00 00 89 C3 E8 ?? ?? ?? ?? 5A 89 D8 5B 41 5C C3 }
	condition:
		$pattern
}

rule byte_alt_match_null_string_p_cd88c9995609262604432ccb426ec8a7 {
	meta:
		aliases = "byte_alt_match_null_string_p"
		type = "func"
		size = "111"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 D5 53 48 89 F3 48 83 EC 10 4C 8D 64 24 08 48 89 7C 24 08 EB 3F 80 39 0F 75 24 48 8D 41 01 48 89 44 24 08 0F BE 40 01 0F B6 51 01 C1 E0 08 01 D0 48 98 48 8D 44 01 03 48 89 44 24 08 EB 16 48 89 EA 48 89 DE 4C 89 E7 E8 A1 FE FF FF 84 C0 75 04 31 C0 EB 0F 48 8B 4C 24 08 48 39 D9 72 B7 B8 01 00 00 00 5E 5F 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule d_print_cast_DOT_isra_DOT_6_8b048874031fdea0a8b5f4e7b079db67 {
	meta:
		aliases = "d_print_cast.isra.6"
		type = "func"
		size = "383"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 F5 53 48 89 FB 48 83 EC 10 48 8B 36 83 3E 04 74 12 E8 C5 DB FF FF 48 83 C4 10 5B 5D 41 5C C3 0F 1F 40 00 48 8B 57 20 4C 8B 67 28 48 89 67 20 48 C7 47 28 00 00 00 00 48 89 74 24 08 48 8B 76 08 48 89 14 24 E8 92 DB FF FF 48 8B 04 24 48 89 43 20 48 8B 43 08 48 85 C0 74 29 48 8B 4B 10 48 85 C9 0F 85 B4 00 00 00 31 D2 48 39 53 18 76 14 48 8D 4A 01 48 89 4B 10 C6 04 10 3C EB 13 66 0F 1F 44 00 00 BE 3C 00 00 00 48 89 DF E8 6B DA FF FF 48 8B 45 00 48 89 DF 48 8B 70 10 E8 3B DB FF FF 48 8B 43 08 48 85 C0 74 22 48 8B 4B 10 48 85 C9 75 39 31 D2 48 39 53 18 76 11 48 8D 4A 01 48 89 4B 10 C6 }
	condition:
		$pattern
}

rule xdr_double_34ce6ce8729bb534299c0cff895d562a {
	meta:
		aliases = "xdr_double"
		type = "func"
		size = "155"
		objfiles = "xdr_float@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 F5 53 48 89 FB 48 83 EC 10 8B 07 83 F8 01 74 46 72 0C 83 F8 02 BA 01 00 00 00 74 71 EB 6D 48 63 46 04 48 89 04 24 48 63 06 48 89 E6 48 89 44 24 08 48 8B 47 08 FF 50 08 31 D2 85 C0 74 4F 48 8B 43 08 48 8D 74 24 08 48 89 DF FF 50 08 31 D2 85 C0 0F 95 C2 EB 37 48 8B 47 08 48 8D 74 24 08 FF 10 85 C0 74 26 48 8B 43 08 48 89 E6 48 89 DF FF 10 85 C0 74 16 48 8B 04 24 BA 01 00 00 00 89 45 00 48 8B 44 24 08 89 45 04 EB 02 31 D2 5E 5F 5B 5D 41 5C 89 D0 C3 }
	condition:
		$pattern
}

rule __des_crypt_a5d62d1b317da7f0610d1bf3b67c66a2 {
	meta:
		aliases = "__des_crypt"
		type = "func"
		size = "410"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 F5 53 48 89 FB 48 83 EC 10 E8 7F F5 FF FF 48 89 E2 48 89 E7 EB 11 8A 03 01 C0 88 02 48 FF C2 80 7A FF 01 48 83 DB FF 48 89 D0 48 29 F8 48 83 F8 08 75 E3 48 89 E7 E8 77 FD FF FF 44 0F BE 65 00 0F BE 7D 01 44 88 25 ?? ?? ?? ?? 8A 45 01 84 C0 41 0F 44 C4 88 05 ?? ?? ?? ?? E8 EF F4 FF FF 89 C3 44 89 E7 C1 E3 06 E8 E2 F4 FF FF 09 C3 89 DF E8 47 F9 FF FF 48 8D 54 24 0C 48 8D 4C 24 08 31 F6 31 FF 41 B8 19 00 00 00 E8 77 F9 FF FF 31 D2 85 C0 0F 85 F3 00 00 00 8B 4C 24 0C 8B 74 24 08 C6 05 ?? ?? ?? ?? 00 89 C8 89 CA C1 E8 1A C1 EA 08 83 E0 3F 83 E2 3F 8A 80 ?? ?? ?? ?? 88 05 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule string_appends_DOT_isra_DOT_11_0e875eaf3247e91b9bc6e4ed1a6c7794 {
	meta:
		aliases = "string_appends.isra.11"
		type = "func"
		size = "59"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 F5 53 48 8B 06 48 39 D0 74 27 48 29 C2 48 89 FB 89 D6 49 89 D4 E8 81 FD FF FF 48 8B 7B 08 48 8B 75 00 4D 63 E4 4C 89 E2 E8 ?? ?? ?? ?? 4C 01 63 08 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule obstack_free_182f001303ea6dd3fdad291902ee1670 {
	meta:
		aliases = "obstack_free"
		type = "func"
		size = "109"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 F5 53 48 8B 57 08 48 89 FB EB 25 F6 43 50 01 4C 8B 62 08 48 8B 43 40 74 0B 48 8B 7B 48 48 89 D6 FF D0 EB 05 48 89 D7 FF D0 80 4B 50 02 4C 89 E2 48 85 D2 74 24 48 39 EA 73 D1 48 39 2A 72 CC 48 85 D2 74 15 48 89 6B 18 48 89 6B 10 48 8B 02 48 89 53 08 48 89 43 20 EB 0A 48 85 ED 74 05 E8 ?? ?? ?? ?? 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __pthread_alt_lock_9dbf266119ee263c29cea9baf9da80a8 {
	meta:
		aliases = "__pthread_alt_lock"
		type = "func"
		size = "102"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 48 89 F7 53 48 83 EC 30 4C 8D 64 24 10 48 8B 5D 00 BA 01 00 00 00 48 85 DB 74 15 48 85 FF 75 08 E8 8B FF FF FF 48 89 C7 48 89 7C 24 18 4C 89 E2 C7 44 24 20 00 00 00 00 48 89 5C 24 10 48 89 D8 F0 48 0F B1 55 00 0F 94 C2 84 D2 74 C0 48 85 DB 74 05 E8 9E FF FF FF 48 83 C4 30 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule pathconf_b8862e02f0f2f7d66a839cc70b295cd4 {
	meta:
		aliases = "pathconf"
		type = "func"
		size = "200"
		objfiles = "pathconf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 81 EC 90 00 00 00 80 3F 00 75 10 E8 ?? ?? ?? ?? C7 00 02 00 00 00 E9 87 00 00 00 83 FE 13 77 13 89 F0 FF 24 C5 ?? ?? ?? ?? B8 20 00 00 00 E9 81 00 00 00 E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 62 B8 7F 00 00 00 EB 6D E8 ?? ?? ?? ?? 48 89 EF 48 89 E6 48 89 C3 44 8B 20 E8 ?? ?? ?? ?? 85 C0 79 0A 83 3B 26 75 3C 44 89 23 EB 30 48 8B 44 24 40 EB 42 31 C0 EB 3E 48 89 E6 E8 ?? ?? ?? ?? 85 C0 78 20 8B 44 24 18 25 00 F0 00 00 3D 00 80 00 00 74 1D 3D 00 60 00 00 75 09 EB 14 B8 FF 00 00 00 EB 12 48 83 C8 FF EB 0C B8 00 10 00 00 EB 05 B8 01 00 00 00 48 81 C4 90 00 00 00 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule feof_2de71bea0159b21a0b0be9fd204250a3 {
	meta:
		aliases = "feof"
		type = "func"
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
		type = "func"
		size = "83"
		objfiles = "ferror@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 83 EC 20 44 8B 67 50 45 85 E4 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 45 85 E4 8B 5D 00 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 89 D8 5B 5D 41 5C 83 E0 08 C3 }
	condition:
		$pattern
}

rule getwc_5cbe594d01d37de7b04e47bc8cfb7e00 {
	meta:
		aliases = "__GI_fgetwc, __GI_fileno, fgetwc, fileno, getwc"
		type = "func"
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
		type = "func"
		size = "80"
		objfiles = "clearerr@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 83 EC 20 44 8B 67 50 45 85 E4 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 66 83 65 00 F3 45 85 E4 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule rewind_eac8a33955e34a1f36e5f64ba9423574 {
	meta:
		aliases = "__GI_rewind, rewind"
		type = "func"
		size = "92"
		objfiles = "rewind@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 83 EC 20 44 8B 67 50 45 85 E4 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 66 83 65 00 F7 31 D2 31 F6 48 89 EF E8 ?? ?? ?? ?? 45 85 E4 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule fflush_02d0d0f56e9ea1ecfe73c3ba80ad1a74 {
	meta:
		aliases = "__GI_fflush, fflush"
		type = "func"
		size = "113"
		objfiles = "fflush@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 83 EC 20 48 85 FF 74 4C 48 81 FF ?? ?? ?? ?? 74 43 44 8B 67 50 45 85 E4 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 45 85 E4 89 C3 75 19 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? EB 0A 48 89 EF E8 ?? ?? ?? ?? 89 C3 48 83 C4 20 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule gets_c88887d8b72c5bf8b70e722f171d676f {
	meta:
		aliases = "gets"
		type = "func"
		size = "128"
		objfiles = "gets@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 83 EC 20 48 8B 05 ?? ?? ?? ?? 44 8B 60 50 45 85 E4 74 05 48 89 EB EB 26 48 8D 50 58 48 89 E7 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 83 C7 58 E8 ?? ?? ?? ?? EB D8 48 FF C3 E8 ?? ?? ?? ?? 83 F8 FF 74 0B 3C 0A 88 03 75 ED 48 39 DD 75 04 31 ED EB 03 C6 03 00 45 85 E4 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 48 89 E8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule closedir_2607f0ede770a0c5326c44350fcb6af3 {
	meta:
		aliases = "__GI_closedir, closedir"
		type = "func"
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
		type = "func"
		size = "154"
		objfiles = "ftello64@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 83 EC 30 48 C7 44 24 28 00 00 00 00 44 8B 67 50 45 85 E4 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 0F B7 45 00 31 D2 48 8D 5C 24 28 48 89 EF 48 89 DE 25 40 04 00 00 3D 40 04 00 00 0F 94 C2 FF C2 E8 ?? ?? ?? ?? 85 C0 78 0F 48 89 DE 48 89 EF E8 ?? ?? ?? ?? 85 C0 79 09 48 C7 44 24 28 FF FF FF FF 45 85 E4 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 8B 44 24 28 48 83 C4 30 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule splay_tree_remove_0c5b8100a6402664f372b3a3f547ad10 {
	meta:
		aliases = "splay_tree_remove"
		type = "func"
		size = "126"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 89 F3 E8 11 FB FF FF 48 8B 45 00 48 85 C0 74 58 48 89 DE 48 8B 38 FF 55 08 85 C0 75 4B 48 8B 45 18 48 8B 7D 00 48 85 C0 48 8B 5F 10 4C 8B 67 18 74 0A 48 8B 7F 08 FF D0 48 8B 7D 00 48 8B 75 30 FF 55 28 48 85 DB 74 28 4D 85 E4 48 89 5D 00 75 0A EB 15 0F 1F 44 00 00 48 89 C3 48 8B 43 18 48 85 C0 75 F4 4C 89 63 18 5B 5D 41 5C C3 0F 1F 00 4C 89 65 00 EB F2 }
	condition:
		$pattern
}

rule d_encoding_e04e49c845ce297610087e5fba75c922 {
	meta:
		aliases = "d_encoding"
		type = "func"
		size = "972"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 8B 47 18 0F B6 10 80 FA 54 0F 84 99 00 00 00 80 FA 47 0F 84 90 00 00 00 41 89 F4 E8 18 09 00 00 48 85 C0 48 89 C3 75 20 48 8B 45 18 0F B6 00 3C 45 0F 85 01 01 00 00 48 89 D8 5B 5D 41 5C C3 66 0F 1F 84 00 00 00 00 00 45 85 E4 74 DB F6 45 10 01 75 D5 8B 13 8D 42 E7 83 F8 02 77 11 0F 1F 00 48 8B 5B 08 8B 13 8D 42 E7 83 F8 02 76 F2 83 FA 02 48 89 D8 75 C4 48 8B 43 10 8B 30 8D 56 E7 83 FA 02 77 12 0F 1F 40 00 48 8B 40 08 8B 30 8D 56 E7 83 FA 02 76 F2 48 89 43 10 48 89 D8 EB 9B 66 0F 1F 84 00 00 00 00 00 8B 4D 50 8D 51 14 89 55 50 48 8D 50 01 48 89 55 18 0F B6 10 80 FA 54 0F }
	condition:
		$pattern
}

rule d_print_resize_ebf032f0e0ca32779cdd5d09dd54586f {
	meta:
		aliases = "d_print_resize"
		type = "func"
		size = "101"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 8B 7F 08 48 85 FF 74 50 48 03 75 10 48 8B 5D 18 48 39 DE 49 89 F4 77 18 EB 3E 66 0F 1F 44 00 00 49 39 DC 48 89 45 08 48 89 5D 18 76 2B 48 89 C7 48 01 DB 48 89 DE E8 ?? ?? ?? ?? 48 85 C0 75 E0 48 8B 7D 08 E8 ?? ?? ?? ?? 48 C7 45 08 00 00 00 00 C7 45 30 01 00 00 00 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule _pthread_cleanup_pop_restore_850ad896f69f48477984448c2cb66f5d {
	meta:
		aliases = "__pthread_cleanup_pop_restore, _pthread_cleanup_pop_restore"
		type = "func"
		size = "80"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 89 F3 E8 C7 FE FF FF 85 DB 49 89 C4 74 07 48 8B 7D 08 FF 55 00 48 8B 45 18 41 80 7C 24 7A 00 49 89 44 24 70 8B 45 10 41 88 44 24 79 74 16 66 41 81 7C 24 78 00 01 75 0C 48 89 E6 48 83 CF FF E8 ?? ?? ?? ?? 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule remove_05adc48a0046fce37e76e6d3668b5f82 {
	meta:
		aliases = "__GI_remove, remove"
		type = "func"
		size = "55"
		objfiles = "remove@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 E8 ?? ?? ?? ?? 48 89 EF 48 89 C3 44 8B 20 E8 ?? ?? ?? ?? 85 C0 79 14 83 3B 14 75 0F 44 89 23 48 89 EF 5B 5D 41 5C E9 ?? ?? ?? ?? 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule pthread_reap_children_f8a887cd3205680ba156c5d0985dd04b {
	meta:
		aliases = "pthread_reap_children"
		type = "func"
		size = "258"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 48 83 EC 10 4C 8D 64 24 0C E9 CF 00 00 00 48 8B 15 ?? ?? ?? ?? 48 8B 2A EB 7B 39 45 28 48 8B 7D 00 75 6F 48 8B 45 08 31 F6 48 89 47 08 48 8B 45 08 48 89 38 48 8B 7D 30 E8 ?? ?? ?? ?? 83 BD A4 02 00 00 00 C6 45 52 01 74 2E 8B 05 ?? ?? ?? ?? 0B 85 A8 02 00 00 F6 C4 08 74 1D C7 85 B0 02 00 00 0C 00 00 00 48 89 AD B8 02 00 00 48 89 2D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 5D 51 48 8B 7D 30 E8 ?? ?? ?? ?? 84 DB 74 12 48 89 EF E8 A5 FE FF FF EB 08 48 89 FD 48 39 D5 75 80 83 3D ?? ?? ?? ?? 00 74 14 48 8B 05 ?? ?? ?? ?? 48 8B 38 48 39 C7 75 05 E8 40 FF FF FF 8B 7C 24 0C 40 88 F8 83 E0 7F FF C0 D0 }
	condition:
		$pattern
}

rule byte_common_op_match_null_stri_3c941deec58cfb34a5f6445f28ea86e9 {
	meta:
		aliases = "byte_common_op_match_null_string_p"
		type = "func"
		size = "257"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 48 89 FB 48 83 EC 10 48 8B 07 48 8D 48 01 48 89 4C 24 08 80 38 1D 77 6C 0F B6 38 48 89 D5 FF 24 FD ?? ?? ?? ?? 0F 1F 80 00 00 00 00 44 0F B6 60 01 48 8D 7C 24 08 E8 61 01 00 00 4A 8D 54 E5 00 0F B6 0A 89 CE 83 E6 03 40 80 FE 03 0F 84 9A 00 00 00 84 C0 74 2E 48 8B 4C 24 08 90 48 89 0B 48 83 C4 10 B8 01 00 00 00 5B 5D 41 5C C3 0F 1F 80 00 00 00 00 0F B6 40 01 F6 04 C2 03 75 DE 66 0F 1F 44 00 00 48 83 C4 10 31 C0 5B 5D 41 5C C3 0F 1F 44 00 00 48 8D 70 03 48 89 74 24 08 0F BE 50 04 0F B6 78 03 C1 E2 08 01 FA 75 D8 48 89 4C 24 08 0F B6 48 01 0F BE 40 02 C1 E0 08 01 C1 48 63 C9 48 01 F1 }
	condition:
		$pattern
}

rule d_template_args_cea670846b610f891de11458b976a1ed {
	meta:
		aliases = "d_template_args"
		type = "func"
		size = "226"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 48 89 FB 48 83 EC 10 48 8B 47 18 4C 8B 67 48 48 8D 50 01 48 89 57 18 80 38 49 0F 85 94 00 00 00 48 C7 44 24 08 00 00 00 00 0F B6 40 01 48 8D 6C 24 08 EB 58 0F 1F 84 00 00 00 00 00 48 83 C2 01 48 89 DF 48 89 53 18 E8 A0 00 00 00 48 8B 4B 18 48 8D 71 01 48 89 73 18 80 39 45 75 57 48 89 C2 48 85 D2 74 4F 31 C9 BE 27 00 00 00 48 89 DF E8 18 C4 FF FF 48 85 C0 48 89 45 00 74 37 48 8B 53 18 48 8D 68 10 0F B6 02 3C 45 74 38 3C 4C 74 14 3C 58 74 A8 48 89 DF E8 ?? ?? ?? ?? EB BF 66 0F 1F 44 00 00 48 89 DF E8 30 FE FF FF 48 89 C2 EB AF 0F 1F 00 48 83 C4 10 31 C0 5B 5D 41 5C C3 0F 1F 44 00 00 }
	condition:
		$pattern
}

rule cplus_demangle_type_07f23e4c7194ff9b44b70d8d0819c085 {
	meta:
		aliases = "cplus_demangle_type"
		type = "func"
		size = "1195"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 48 89 FB 48 83 EC 10 48 8B 57 18 0F BE 02 3C 72 74 1A 3C 56 74 16 3C 4B 74 12 8D 48 D0 80 F9 4A 77 3F 0F B6 C9 FF 24 CD ?? ?? ?? ?? 48 8D 74 24 08 31 D2 48 89 DF E8 F1 D2 FF FF 48 85 C0 48 89 C5 74 1E 48 89 DF E8 ?? ?? ?? ?? 48 89 45 00 48 8B 54 24 08 48 85 D2 74 08 8B 43 38 3B 43 3C 7C 0B 31 C0 48 83 C4 10 5B 5D 41 5C C3 48 8B 4B 30 48 63 F0 83 C0 01 48 89 14 F1 89 43 38 48 8B 44 24 08 48 83 C4 10 5B 5D 41 5C C3 90 48 83 C2 01 48 89 57 18 E8 E3 D5 FF FF 31 C9 48 89 C2 BE 22 00 00 00 48 89 DF E8 B1 D1 FF FF 48 89 44 24 08 0F 1F 40 00 48 85 C0 74 A8 8B 53 38 3B 53 3C 7D A0 48 8B 4B }
	condition:
		$pattern
}

rule pex_input_pipe_d4ab8d862a5611ddcd3c398a3bf8b0e0 {
	meta:
		aliases = "pex_input_pipe"
		type = "func"
		size = "178"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 48 89 FB 48 83 EC 10 8B 57 2C 85 D2 7F 13 F6 07 02 74 0E 8B 47 18 85 C0 7F 07 48 83 7F 20 00 74 1B E8 ?? ?? ?? ?? C7 00 16 00 00 00 31 C0 48 83 C4 10 5B 5D 41 5C C3 0F 1F 44 00 00 48 8B 47 70 31 ED 85 F6 40 0F 95 C5 48 89 E6 89 EA FF 50 28 85 C0 78 28 48 8B 43 70 89 EA 8B 74 24 04 48 89 DF FF 50 38 48 85 C0 74 17 8B 14 24 89 53 18 48 83 C4 10 5B 5D 41 5C C3 0F 1F 40 00 31 C0 EB AE E8 ?? ?? ?? ?? 44 8B 20 48 89 C5 48 8B 43 70 8B 34 24 48 89 DF FF 50 18 48 8B 43 70 8B 74 24 04 48 89 DF FF 50 18 44 89 65 00 31 C0 EB 80 }
	condition:
		$pattern
}

rule pex_free_7830c3d47c1a3b9fb83c844fb4202385 {
	meta:
		aliases = "pex_free"
		type = "func"
		size = "253"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 48 89 FB 48 83 EC 10 8B 77 18 85 F6 7E 07 48 8B 47 70 FF 50 18 48 83 7B 38 00 0F 84 BA 00 00 00 8B 53 28 85 D2 0F 85 A1 00 00 00 48 8B 7B 30 48 85 FF 74 05 E8 ?? ?? ?? ?? 48 8B 7B 38 48 85 FF 74 05 E8 ?? ?? ?? ?? 48 8B 7B 40 48 85 FF 74 05 E8 ?? ?? ?? ?? 48 8B 7B 58 48 85 FF 74 05 E8 ?? ?? ?? ?? 8B 43 60 31 ED 45 31 E4 85 C0 7E 36 0F 1F 44 00 00 48 8B 43 68 41 83 C4 01 48 8B 3C 28 E8 ?? ?? ?? ?? 48 8B 43 68 48 8B 3C 28 48 83 C5 08 E8 ?? ?? ?? ?? 44 39 63 60 7F D8 48 8B 7B 68 E8 ?? ?? ?? ?? 48 8B 43 70 48 8B 40 40 48 85 C0 74 05 48 89 DF FF D0 48 83 C4 10 48 89 DF 5B 5D 41 5C E9 ?? }
	condition:
		$pattern
}

rule __pthread_acquire_6fc54c899cb06d7111d2540abb881b0e {
	meta:
		aliases = "__pthread_acquire"
		type = "func"
		size = "75"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 48 89 FB 48 83 EC 10 EB 29 83 FD 31 7F 09 FF C5 E8 ?? ?? ?? ?? EB 1D 31 F6 48 89 E7 48 C7 04 24 00 00 00 00 48 C7 44 24 08 81 84 1E 00 E8 ?? ?? ?? ?? 31 ED B8 01 00 00 00 87 03 48 85 C0 75 C9 58 5A 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule concat_copy2_6ffc39afe850c566e6b3d607cd0e19fa {
	meta:
		aliases = "concat_copy2"
		type = "func"
		size = "181"
		objfiles = "concat@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 48 89 FB 48 83 EC 50 48 85 FF 48 8B 2D ?? ?? ?? ?? 48 8D 44 24 70 48 89 74 24 28 48 89 54 24 30 48 89 4C 24 38 4C 89 44 24 40 48 89 44 24 10 48 8D 44 24 20 4C 89 4C 24 48 C7 44 24 08 08 00 00 00 48 89 44 24 18 75 1A EB 53 66 90 89 D0 48 03 44 24 18 83 C2 08 89 54 24 08 48 8B 18 48 85 DB 74 3B 48 89 DF E8 ?? ?? ?? ?? 48 89 EF 48 89 C2 48 89 DE 49 89 C4 E8 ?? ?? ?? ?? 8B 54 24 08 4C 01 E5 83 FA 2F 76 C5 48 8B 44 24 10 48 8B 18 48 8D 50 08 48 89 54 24 10 48 85 DB 75 C5 C6 45 00 00 48 8B 05 ?? ?? ?? ?? 48 83 C4 50 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule pthread_rwlock_rdlock_6b7ea70e422699dde1526e02ad2bc6fb {
	meta:
		aliases = "pthread_rwlock_rdlock"
		type = "func"
		size = "186"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 48 89 FB 48 89 DE 4C 8D 63 20 48 83 EC 20 48 8D 4C 24 1C 48 8D 54 24 08 48 8D 7C 24 10 48 C7 44 24 10 00 00 00 00 E8 77 FE FF FF 89 C5 48 83 7C 24 10 00 75 0A E8 86 FD FF FF 48 89 44 24 10 48 8B 74 24 10 48 89 DF E8 ?? ?? ?? ?? 89 EE 48 89 DF E8 7C FC FF FF 85 C0 75 21 48 8B 74 24 10 4C 89 E7 E8 4B FC FF FF 48 89 DF E8 ?? ?? ?? ?? 48 8B 7C 24 10 E8 C9 FD FF FF EB B2 FF 43 10 48 89 DF E8 ?? ?? ?? ?? 85 ED 75 07 83 7C 24 1C 00 74 1A 48 8B 44 24 08 48 85 C0 74 05 FF 40 10 EB 0B 48 8B 44 24 10 FF 80 F0 02 00 00 48 83 C4 20 31 C0 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule string_need_9e036f77cd0c9550ef23ed114e46601e {
	meta:
		aliases = "string_need"
		type = "func"
		size = "130"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 48 89 FB 48 8B 3F 48 85 FF 74 49 48 8B 53 08 48 8B 43 10 48 63 CE 48 29 D0 48 39 C8 7D 2A 48 29 FA 8D 2C 16 49 89 D4 4D 63 E4 01 ED 48 63 ED 48 89 EE E8 ?? ?? ?? ?? 49 01 C4 48 89 03 48 01 E8 4C 89 63 08 48 89 43 10 5B 5D 41 5C C3 0F 1F 80 00 00 00 00 83 FE 20 48 63 C6 BD 20 00 00 00 48 0F 4D E8 48 89 EF E8 ?? ?? ?? ?? 48 01 C5 48 89 03 48 89 43 08 48 89 6B 10 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule d_source_name_6a5dfa435c7aef8b1f159309af61c6ac {
	meta:
		aliases = "d_source_name"
		type = "func"
		size = "220"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 48 89 FB 48 8D 7F 18 E8 00 FF FF FF 48 85 C0 48 89 C5 0F 8E B4 00 00 00 4C 8B 63 18 48 8B 43 08 48 63 D5 4C 29 E0 48 39 D0 0F 8C A5 00 00 00 4C 01 E2 F6 43 10 04 48 89 53 18 75 38 83 FD 09 7E 16 BA 08 00 00 00 BE ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 74 35 89 EA 4C 89 E6 48 89 DF E8 F8 FB FF FF 48 89 43 48 5B 5D 41 5C C3 0F 1F 80 00 00 00 00 80 3A 24 75 C3 48 83 C2 01 48 89 53 18 EB B9 66 0F 1F 84 00 00 00 00 00 41 0F B6 44 24 08 3C 2E 74 0E 3C 5F 74 0A 3C 24 75 B9 66 0F 1F 44 00 00 41 80 7C 24 09 4E 75 AB 8B 43 50 BA 15 00 00 00 BE ?? ?? ?? ?? 48 89 DF 83 C0 16 29 E8 89 43 50 }
	condition:
		$pattern
}

rule pthread_rwlock_wrlock_59b5523a98e106f701f8ac17747b90a0 {
	meta:
		aliases = "pthread_rwlock_wrlock"
		type = "func"
		size = "91"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 48 89 FB 4C 8D 63 28 E8 69 FF FF FF 48 89 C5 48 89 EE 48 89 DF E8 ?? ?? ?? ?? 83 7B 10 00 75 07 48 83 7B 18 00 74 1D 48 89 EE 4C 89 E7 E8 35 FE FF FF 48 89 DF E8 ?? ?? ?? ?? 48 89 EF E8 B5 FF FF FF EB CB 48 89 6B 18 48 89 DF E8 ?? ?? ?? ?? 5B 5D 41 5C 31 C0 C3 }
	condition:
		$pattern
}

rule d_print_append_buffer_4c57097e31fed077c20ea2b2ecef1ef4 {
	meta:
		aliases = "d_print_append_buffer"
		type = "func"
		size = "83"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 48 8B 47 08 48 89 FB 48 85 C0 74 3E 48 8B 7F 10 48 89 D5 49 89 F4 48 8D 14 3A 48 3B 53 18 76 18 48 89 EE 48 89 DF E8 61 FF FF FF 48 8B 43 08 48 85 C0 74 16 48 8B 7B 10 48 01 C7 48 89 EA 4C 89 E6 E8 ?? ?? ?? ?? 48 01 6B 10 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule d_expr_primary_05fd5331f029e37a6a908a32c94a1f4c {
	meta:
		aliases = "d_expr_primary"
		type = "func"
		size = "273"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 48 8B 47 18 48 89 FB 48 8D 50 01 48 89 57 18 80 38 4C 0F 85 94 00 00 00 80 78 01 5F 0F 84 9A 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 74 7D 83 38 21 0F 84 B4 00 00 00 48 8B 73 18 41 BC 31 00 00 00 0F B6 0E 80 F9 6E 0F 84 7E 00 00 00 80 F9 45 0F 84 AF 00 00 00 84 C9 74 51 48 8D 4E 01 EB 0C 0F 1F 00 48 83 C1 01 45 84 C0 74 3F 48 89 4B 18 44 0F B6 01 41 80 F8 45 75 E9 89 CA 29 F2 48 89 DF E8 A5 C5 FF FF 48 89 EA 48 89 C1 44 89 E6 48 89 DF E8 14 C5 FF FF 48 8B 53 18 48 8D 4A 01 48 89 4B 18 80 3A 45 74 05 0F 1F 00 31 C0 5B 5D 41 5C C3 66 0F 1F 84 00 00 00 00 00 31 F6 E8 ?? ?? ?? ?? EB }
	condition:
		$pattern
}

rule unlockpt_186971b2046302a582ce89b91a352270 {
	meta:
		aliases = "unlockpt"
		type = "func"
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
		type = "func"
		size = "148"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 8B 47 10 48 89 FB 83 F8 01 74 26 7F 06 85 C0 74 13 EB 0A 83 F8 02 74 4A 83 F8 03 74 5F BD 16 00 00 00 EB 65 5B 5D 41 5C 48 8D 7F 18 E9 D9 FD FF FF E8 F8 FE FF FF 48 39 43 08 49 89 C4 75 07 FF 43 04 31 ED EB 43 48 8D 7B 18 E8 BB FD FF FF 85 C0 89 C5 75 34 4C 89 63 08 C7 43 04 00 00 00 00 EB 27 48 8D 7F 18 E8 C4 FD FF FF 85 C0 89 C5 75 18 E8 B8 FE FF FF 48 89 43 08 EB 0D 5B 5D 41 5C 48 8D 7F 18 E9 A6 FD FF FF 5B 89 E8 5D 41 5C C3 }
	condition:
		$pattern
}

rule choose_temp_base_4ba71469c6a7b002d8b3a39f67328b3a {
	meta:
		aliases = "choose_temp_base"
		type = "func"
		size = "93"
		objfiles = "choose_temp@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 E8 ?? ?? ?? ?? 48 89 C7 49 89 C4 E8 ?? ?? ?? ?? 48 63 E8 48 8D 7D 09 E8 ?? ?? ?? ?? 4C 89 E6 48 89 C3 48 89 C7 E8 ?? ?? ?? ?? 48 01 DD 48 B8 63 63 58 58 58 58 58 58 48 89 DF 48 89 45 00 C6 45 08 00 E8 ?? ?? ?? ?? 80 3B 00 74 08 48 89 D8 5B 5D 41 5C C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fpathconf_dae854f89b641b5915c03c6bfa27d921 {
	meta:
		aliases = "fpathconf"
		type = "func"
		size = "203"
		objfiles = "fpathconf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 89 FD 53 48 81 EC 90 00 00 00 85 FF 79 10 E8 ?? ?? ?? ?? C7 00 09 00 00 00 E9 8C 00 00 00 85 F6 B8 7F 00 00 00 0F 84 91 00 00 00 8D 46 FF 83 F8 12 77 10 89 C0 FF 24 C5 ?? ?? ?? ?? B8 20 00 00 00 EB 79 E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 5A E8 ?? ?? ?? ?? 89 EF 48 89 E6 48 89 C3 44 8B 20 E8 ?? ?? ?? ?? 85 C0 79 0A 83 3B 26 75 3C 44 89 23 EB 30 48 8B 44 24 40 EB 42 31 C0 EB 3E 48 89 E6 E8 ?? ?? ?? ?? 85 C0 78 20 8B 44 24 18 25 00 F0 00 00 3D 00 80 00 00 74 1D 3D 00 60 00 00 75 09 EB 14 B8 FF 00 00 00 EB 12 48 83 C8 FF EB 0C B8 00 10 00 00 EB 05 B8 01 00 00 00 48 81 C4 90 00 00 00 5B 5D }
	condition:
		$pattern
}

rule setlogmask_d133f4aa2d050d3e5455ac045a34194f {
	meta:
		aliases = "setlogmask"
		type = "func"
		size = "80"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 89 FD 53 48 83 EC 20 85 FF 44 8B 25 ?? ?? ?? ?? 74 2F BE ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 89 2D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 C4 20 44 89 E0 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule pthread_rwlock_tryrdlock_79e5f0f83d025c548e231d6ad98db512 {
	meta:
		aliases = "pthread_rwlock_tryrdlock"
		type = "func"
		size = "146"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 BD 10 00 00 00 53 48 89 FB 48 83 EC 20 E8 41 FE FF FF 48 8D 4C 24 1C 48 8D 54 24 08 48 8D 7C 24 10 48 89 DE 48 89 44 24 10 E8 07 FF FF FF 48 8B 74 24 10 48 89 DF 41 89 C4 E8 ?? ?? ?? ?? 31 F6 48 89 DF E8 1D FD FF FF 85 C0 74 06 FF 43 10 40 30 ED 48 89 DF E8 ?? ?? ?? ?? 85 ED 75 26 45 85 E4 75 07 83 7C 24 1C 00 74 1A 48 8B 44 24 08 48 85 C0 74 05 FF 40 10 EB 0B 48 8B 44 24 10 FF 80 F0 02 00 00 48 83 C4 20 89 E8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule srandom_r_b73b88147e0e1988c994f28d884393bd {
	meta:
		aliases = "__GI_srandom_r, srandom_r"
		type = "func"
		size = "176"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 83 C8 FF 55 48 89 F5 53 48 83 EC 10 8B 56 18 83 FA 04 0F 87 8F 00 00 00 48 8B 76 10 85 FF B8 01 00 00 00 0F 44 F8 85 D2 89 3E 74 79 44 8B 4D 1C 89 FA 48 89 F1 BF 01 00 00 00 4D 63 C1 EB 37 48 89 D0 41 BA 1D F3 01 00 48 99 49 F7 FA 48 69 C0 14 0B 00 00 48 69 D2 A7 41 00 00 48 29 C2 48 8D 82 FF FF FF 7F 48 83 FA FF 48 0F 4E D0 48 83 C1 04 48 FF C7 89 11 4C 39 C7 7C C4 48 63 45 20 4C 8D 64 24 0C 48 89 75 08 41 6B D9 0A 48 8D 04 86 48 89 45 00 EB 0B 4C 89 E6 48 89 EF E8 ?? ?? ?? ?? FF CB 79 F1 31 C0 59 5E 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule lckpwdf_3c149ad0fc8ea6b9091fb7c83440186b {
	meta:
		aliases = "lckpwdf"
		type = "func"
		size = "487"
		objfiles = "lckpwdf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 83 C8 FF 55 53 48 81 EC 80 02 00 00 39 05 ?? ?? ?? ?? 0F 85 C1 01 00 00 48 8D BC 24 40 02 00 00 BA ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 31 C0 BE 01 00 00 00 E8 ?? ?? ?? ?? 83 F8 FF 89 C7 89 05 ?? ?? ?? ?? 0F 84 6A 01 00 00 31 D2 31 C0 BE 01 00 00 00 E8 ?? ?? ?? ?? 83 F8 FF 89 C3 75 16 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 1D ?? ?? ?? ?? E9 3F 01 00 00 8B 3D ?? ?? ?? ?? 83 CB 01 31 C0 89 DA BE 02 00 00 00 E8 ?? ?? ?? ?? 85 C0 0F 88 0B 01 00 00 31 F6 BA 98 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 8D AC 24 A0 00 00 00 48 8D 7C 24 08 48 C7 04 24 ?? }
	condition:
		$pattern
}

rule _obstack_begin_7828b57dd885b5fce84365fb81055932 {
	meta:
		aliases = "_obstack_begin"
		type = "func"
		size = "152"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 85 D2 B8 10 00 00 00 55 89 D5 0F 44 E8 85 F6 66 B8 E0 0F 53 0F 44 F0 80 67 50 FE F6 47 50 01 44 8D 65 FF 48 63 C6 48 89 FB 48 89 4F 38 4C 89 47 40 48 89 07 44 89 67 30 74 0B 48 8B 7F 48 48 89 C6 FF D1 EB 05 48 89 C7 FF D1 48 85 C0 48 89 C1 48 89 43 08 75 05 E8 43 02 00 00 49 63 C4 F7 DD 48 8D 44 01 10 48 63 D5 48 21 D0 48 89 43 10 48 89 43 18 48 89 C8 48 03 03 48 89 01 48 89 43 20 B8 01 00 00 00 48 C7 41 08 00 00 00 00 80 63 50 F9 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule stat64_bbdbc81d4a102245f5e99ec634ac9a5e {
	meta:
		aliases = "__GI_stat, __GI_stat64, stat, stat64"
		type = "func"
		size = "79"
		objfiles = "stat@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 B8 04 00 00 00 55 48 89 F5 53 48 81 EC 90 00 00 00 48 89 E6 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 85 DB 75 0B 48 89 EE 48 89 E7 E8 ?? ?? ?? ?? 48 81 C4 90 00 00 00 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule lstat64_826d9ac11ad0acf1713647c7ac3276bd {
	meta:
		aliases = "__GI_lstat, __GI_lstat64, lstat, lstat64"
		type = "func"
		size = "79"
		objfiles = "lstat@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 B8 06 00 00 00 55 48 89 F5 53 48 81 EC 90 00 00 00 48 89 E6 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 85 DB 75 0B 48 89 EE 48 89 E7 E8 ?? ?? ?? ?? 48 81 C4 90 00 00 00 89 D8 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule _obstack_begin_1_48dfaf0184d4a64ba1e0f7cf98dde9ee {
	meta:
		aliases = "_obstack_begin_1"
		type = "func"
		size = "152"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 B8 10 00 00 00 55 89 D5 85 ED 53 0F 44 E8 48 89 FB 85 F6 66 B8 E0 0F 48 89 4F 38 0F 44 F0 4C 89 47 40 80 4B 50 01 F6 43 50 01 44 8D 65 FF 48 63 FE 48 89 3B 4C 89 4B 48 44 89 63 30 74 0A 48 89 FE 4C 89 CF FF D1 EB 02 FF D1 48 85 C0 48 89 C1 48 89 43 08 75 05 E8 AB 01 00 00 49 63 C4 F7 DD 48 8D 44 01 10 48 63 D5 48 21 D0 48 89 43 10 48 89 43 18 48 89 C8 48 03 03 48 89 01 48 89 43 20 B8 01 00 00 00 48 C7 41 08 00 00 00 00 80 63 50 F9 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule wctype_e15094d8178f22e9c115513efe4486e7 {
	meta:
		aliases = "__GI_wctrans, __GI_wctype, wctrans, wctype"
		type = "func"
		size = "64"
		objfiles = "wctrans@libc.a, wctype@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 B8 ?? ?? ?? ?? 49 89 FC 55 BD 01 00 00 00 53 48 8D 58 01 4C 89 E7 48 89 DE E8 ?? ?? ?? ?? 85 C0 75 04 89 E8 EB 13 0F B6 43 FF 48 8D 04 03 80 38 00 74 04 FF C5 EB D8 31 C0 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule timegm_3240a1c925d1436d2ef07c0e6a02cc97 {
	meta:
		aliases = "timegm"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "172"
		objfiles = "xstatconv@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 BA 90 00 00 00 49 89 FC 53 48 89 F3 31 F6 48 89 DF 48 83 EC 08 E8 ?? ?? ?? ?? 49 8B 04 24 48 89 03 49 8B 44 24 08 48 89 43 08 41 8B 44 24 18 89 43 18 49 8B 44 24 10 48 89 43 10 41 8B 44 24 1C 89 43 1C 41 8B 44 24 20 89 43 20 49 8B 44 24 28 48 89 43 28 49 8B 44 24 30 48 89 43 30 49 8B 44 24 38 48 89 43 38 49 8B 44 24 40 48 89 43 40 49 8B 44 24 48 48 89 43 48 49 8B 44 24 58 48 89 43 58 49 8B 44 24 68 48 89 43 68 49 8B 44 24 50 48 89 43 50 49 8B 44 24 60 48 89 43 60 49 8B 44 24 70 48 89 43 70 5A 5B 41 5C C3 }
	condition:
		$pattern
}

rule srandom_760055d0b3360962c922cb2ccffe3fc8 {
	meta:
		aliases = "srand, srandom"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "73"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 53 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? E8 4E FE FF FF BE 01 00 00 00 48 89 C3 48 89 E7 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 28 5B 41 5C C3 }
	condition:
		$pattern
}

rule getutid_318fd190641581536e04e3f35b029906 {
	meta:
		aliases = "__GI_getutid, getutid"
		type = "func"
		size = "73"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 53 48 89 FB 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 DF E8 CE FE FF FF BE 01 00 00 00 48 89 C3 48 89 E7 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 28 5B 41 5C C3 }
	condition:
		$pattern
}

rule sethostent_1b82fb4773dd243d9c0dc8989ae00637 {
	meta:
		aliases = "sethostent"
		type = "func"
		size = "71"
		objfiles = "gethostent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 53 89 FB 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 85 DB BE 01 00 00 00 0F 95 C0 48 89 E7 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 C4 28 5B 41 5C C3 }
	condition:
		$pattern
}

rule pclose_639369db9335fe699af5601d50d6788a {
	meta:
		aliases = "pclose"
		type = "func"
		size = "193"
		objfiles = "popen@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 55 48 89 FD 53 48 83 EC 30 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? 48 85 DB 74 36 48 39 6B 08 75 0C 48 8B 03 48 89 05 ?? ?? ?? ?? EB 24 48 89 DA 48 8B 1B 48 85 DB 75 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 0C 48 39 6B 08 75 E2 48 8B 03 48 89 02 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 85 DB 74 3A 48 89 DF 44 8B 63 10 E8 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 48 8D 5C 24 2C 31 D2 48 89 DE 44 89 E7 E8 ?? ?? ?? ?? 85 C0 78 06 8B 44 24 2C EB 0D E8 ?? ?? ?? ?? 83 38 04 74 DF 83 C8 FF 48 83 C4 30 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule __res_init_89475fc7b1bb523e664adfe65949a1fc {
	meta:
		aliases = "__GI___res_init, __res_init"
		type = "func"
		size = "307"
		objfiles = "res_init@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 54 BE ?? ?? ?? ?? BA ?? ?? ?? ?? 55 53 48 83 EC 30 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 05 00 00 00 C7 05 ?? ?? ?? ?? 04 00 00 00 48 C7 05 ?? ?? ?? ?? 01 00 00 00 E8 ?? ?? ?? ?? 66 89 05 ?? ?? ?? ?? 8A 05 ?? ?? ?? ?? 31 C9 8B 35 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 66 C7 05 ?? ?? ?? ?? 02 00 66 C7 05 ?? ?? ?? ?? 00 35 83 E0 F0 C7 05 ?? ?? ?? ?? FF FF FF FF 83 C8 01 85 F6 88 05 ?? ?? ?? ?? 75 17 EB 19 48 63 D1 FF C1 48 8B 04 D5 ?? ?? ?? ?? 48 89 04 D5 ?? ?? ?? ?? 39 F1 7C E7 83 3D ?? ?? ?? ?? 00 74 4E 4C 8D 64 24 20 31 ED }
	condition:
		$pattern
}

rule __dl_iterate_phdr_b5ae0f2735e08c4fa5f55754203973d3 {
	meta:
		aliases = "__GI___dl_iterate_phdr, __dl_iterate_phdr"
		type = "func"
		size = "105"
		objfiles = "dl_iterate_phdr@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 31 C0 41 54 49 89 FC 55 48 89 F5 53 48 83 EC 28 48 8B 1D ?? ?? ?? ?? EB 3E 48 8B 03 48 89 EA BE 20 00 00 00 48 89 E7 48 89 04 24 48 8B 43 08 48 89 44 24 08 48 8B 83 A0 01 00 00 48 89 44 24 10 48 8B 83 98 01 00 00 66 89 44 24 18 41 FF D4 85 C0 75 09 48 8B 5B 18 48 85 DB 75 BD 48 83 C4 28 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule xdr_pointer_02e843fa1f18f52780446d28259a7b04 {
	meta:
		aliases = "xdr_pointer"
		type = "func"
		size = "101"
		objfiles = "xdr_reference@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 31 C0 41 89 D5 41 54 49 89 CC 55 48 89 FD 53 48 89 F3 48 83 EC 18 48 83 3E 00 48 8D 74 24 14 0F 95 C0 89 44 24 14 E8 ?? ?? ?? ?? 31 D2 85 C0 74 25 83 7C 24 14 00 75 0B B2 01 48 C7 03 00 00 00 00 EB 13 44 89 EA 4C 89 E1 48 89 DE 48 89 EF E8 ?? ?? ?? ?? 89 C2 48 83 C4 18 89 D0 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule sleep_d464420134f4d82137f445052d85d109 {
	meta:
		aliases = "__GI_sleep, sleep"
		type = "func"
		size = "415"
		objfiles = "sleep@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 31 C0 BA 10 00 00 00 41 54 55 53 48 81 EC B8 01 00 00 85 FF 75 14 E9 74 01 00 00 48 63 C2 48 C7 84 C4 20 01 00 00 00 00 00 00 FF CA 79 ED 48 8D 9C 24 20 01 00 00 89 FF BE 11 00 00 00 48 89 BC 24 A0 01 00 00 48 C7 84 24 A8 01 00 00 00 00 00 00 48 89 DF E8 ?? ?? ?? ?? 85 C0 0F 88 2B 01 00 00 48 8D AC 24 A0 00 00 00 31 FF 48 89 DE 48 89 EA E8 ?? ?? ?? ?? 85 C0 0F 85 0E 01 00 00 BE 11 00 00 00 48 89 EF E8 ?? ?? ?? ?? 85 C0 BA 10 00 00 00 74 14 E9 C1 00 00 00 48 63 C2 48 C7 84 C4 20 01 00 00 00 00 00 00 FF CA 79 ED 48 8D BC 24 20 01 00 00 BE 11 00 00 00 E8 ?? ?? ?? ?? 85 C0 0F 88 C6 00 00 00 }
	condition:
		$pattern
}

rule __malloc_trim_e014baae7fea2343aa6113b1c1d71655 {
	meta:
		aliases = "__malloc_trim"
		type = "func"
		size = "150"
		objfiles = "free@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 31 D2 49 89 F5 41 54 55 53 48 83 EC 08 48 8B 46 60 8B 8E A4 06 00 00 48 8B 68 08 48 83 E5 FC 48 8D 44 29 DF 48 29 F8 48 F7 F1 48 8D 58 FF 48 0F AF D9 48 85 DB 7E 53 31 FF E8 ?? ?? ?? ?? 49 89 C4 48 89 E8 49 03 45 60 49 39 C4 75 3D 48 F7 DB 48 89 DF E8 ?? ?? ?? ?? 31 FF E8 ?? ?? ?? ?? 48 83 F8 FF 74 25 4C 89 E2 48 29 C2 74 1D 49 8B 45 60 49 29 95 B8 06 00 00 48 29 D5 48 83 CD 01 48 89 68 08 B8 01 00 00 00 EB 02 31 C0 5A 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule rresvport_448fef3693e529494c8ec95797698693 {
	meta:
		aliases = "__GI_rresvport, rresvport"
		type = "func"
		size = "151"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 31 D2 BE 01 00 00 00 41 54 49 89 FC BF 02 00 00 00 55 53 48 83 EC 18 66 C7 04 24 02 00 C7 44 24 04 00 00 00 00 E8 ?? ?? ?? ?? 85 C0 89 C3 78 55 BA 10 00 00 00 48 89 E6 89 DF 41 8B 04 24 66 C1 C8 08 66 89 44 24 02 E8 ?? ?? ?? ?? 85 C0 79 38 E8 ?? ?? ?? ?? 83 38 62 48 89 C5 74 09 89 DF E8 ?? ?? ?? ?? EB 1F 41 8B 04 24 FF C8 3D 00 02 00 00 41 89 04 24 75 B9 89 DF E8 ?? ?? ?? ?? C7 45 00 0B 00 00 00 83 CB FF 48 83 C4 18 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule fseeko64_f29b4aff1d2a2a213c8992869bac2164 {
	meta:
		aliases = "__GI_fseeko64, fseeko64"
		type = "func"
		size = "218"
		objfiles = "fseeko64@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 41 89 D4 55 48 89 FD 53 48 83 EC 38 83 FA 02 48 89 74 24 28 76 13 83 CB FF E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 A0 00 00 00 44 8B 6F 50 45 85 ED 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? F6 45 00 40 74 0D 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 75 53 41 83 FC 01 75 11 48 8D 74 24 28 48 89 EF E8 ?? ?? ?? ?? 85 C0 78 3C 48 8D 74 24 28 44 89 E2 48 89 EF E8 ?? ?? ?? ?? 85 C0 78 28 66 83 65 00 B8 48 8B 45 08 31 DB C7 45 48 00 00 00 00 C6 45 02 00 48 89 45 18 48 89 45 20 48 89 45 28 48 89 45 30 EB 03 83 CB FF 45 85 ED 75 0D 48 89 E7 BE 01 00 00 00 }
	condition:
		$pattern
}

rule fwide_0a8c03d95e3441ee24d64140a944d0ec {
	meta:
		aliases = "fwide"
		type = "func"
		size = "139"
		objfiles = "fwide@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 41 89 F4 55 48 89 FD 53 48 83 EC 28 44 8B 6F 50 45 85 ED 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 45 85 E4 74 21 8B 4D 00 F7 C1 80 08 00 00 75 16 45 85 E4 B8 00 08 00 00 BA 80 00 00 00 0F 4E C2 09 C8 66 89 45 00 45 85 ED 0F B7 5D 00 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 89 D8 81 E3 80 00 00 00 48 83 C4 28 25 00 08 00 00 29 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule ungetwc_3793606bc587d62c9d3cfc85b4604671 {
	meta:
		aliases = "__GI_ungetwc, ungetwc"
		type = "func"
		size = "177"
		objfiles = "ungetwc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 41 89 FC 55 48 89 F5 53 48 83 EC 28 44 8B 6E 50 45 85 ED 75 1C 48 8D 5E 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 0F B7 45 00 25 03 08 00 00 3D 00 08 00 00 77 11 BE 00 08 00 00 48 89 EF E8 ?? ?? ?? ?? 85 C0 75 37 0F B7 45 00 A8 02 74 0A A8 01 75 2B 83 7D 44 00 75 25 41 83 FC FF 74 1F 8B 45 00 C7 45 44 01 00 00 00 FF C0 66 89 45 00 66 83 65 00 FB 83 E0 01 44 89 64 85 40 EB 04 41 83 CC FF 45 85 ED 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 44 89 E0 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule ungetc_a965224ac477a14e7dc110ef44ea174b {
	meta:
		aliases = "__GI_ungetc, ungetc"
		type = "func"
		size = "222"
		objfiles = "ungetc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 41 89 FC 55 48 89 F5 53 48 83 EC 28 44 8B 6E 50 45 85 ED 75 1C 48 8D 5E 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8B 45 18 48 3B 45 28 73 1B 41 83 FC FF 74 15 48 3B 45 08 76 0F 44 38 60 FF 75 09 48 FF C8 48 89 45 18 EB 59 0F B7 45 00 25 83 00 00 00 3D 80 00 00 00 77 11 BE 80 00 00 00 48 89 EF E8 ?? ?? ?? ?? 85 C0 75 3F 0F B7 45 00 A8 02 74 0A A8 01 75 33 83 7D 44 00 75 2D 41 83 FC FF 74 27 48 8B 45 08 C7 45 44 01 00 00 00 48 89 45 28 8B 45 00 FF C0 66 89 45 00 83 E0 01 44 89 64 85 40 66 83 65 00 FB EB 04 41 83 CC FF 45 85 ED 75 0D 48 89 E7 BE 01 }
	condition:
		$pattern
}

rule pwait_b5d03b60ff8d990c8791f82a97b909d6 {
	meta:
		aliases = "pwait"
		type = "func"
		size = "259"
		objfiles = "pexecute@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 41 89 FC 55 53 8D 5F FF 48 83 EC 18 48 8B 3D ?? ?? ?? ?? 48 85 FF 0F 84 C0 00 00 00 85 DB 0F 88 B8 00 00 00 48 63 0D ?? ?? ?? ?? 39 CB 0F 8D A9 00 00 00 85 DB 49 89 F5 75 09 83 F9 01 0F 84 A9 00 00 00 48 8D 3C 8D 00 00 00 00 E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 89 C2 48 89 C5 E8 ?? ?? ?? ?? 85 C0 74 68 48 63 DB 48 89 EF 8B 44 9D 00 41 89 45 00 E8 ?? ?? ?? ?? 44 3B 25 ?? ?? ?? ?? 44 89 E0 74 11 48 83 C4 18 5B 5D 41 5C 41 5D C3 66 0F 1F 44 00 00 48 8B 3D ?? ?? ?? ?? 44 89 64 24 0C E8 ?? ?? ?? ?? 8B 44 24 0C 48 C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 }
	condition:
		$pattern
}

rule __ns_name_uncompress_2c1a10040e5866f4b2cdc4d3ee489a8f {
	meta:
		aliases = "__GI___ns_name_uncompress, __ns_name_uncompress"
		type = "func"
		size = "77"
		objfiles = "ns_name@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 CC 55 4C 89 C5 41 B8 FF 00 00 00 53 48 81 EC 08 01 00 00 48 89 E1 E8 ?? ?? ?? ?? 83 F8 FF 89 C3 74 12 48 89 EA 4C 89 E6 48 89 E7 E8 ?? ?? ?? ?? FF C0 75 03 83 CB FF 48 81 C4 08 01 00 00 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule splay_tree_insert_7ec6d2015229554fa69e52190cd0579e {
	meta:
		aliases = "splay_tree_insert"
		type = "func"
		size = "238"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 D4 55 48 89 F5 53 48 89 FB 48 83 EC 08 E8 F8 FB FF FF 48 8B 03 48 85 C0 0F 84 7E 00 00 00 48 89 EE 48 8B 38 FF 53 08 41 89 C5 48 8B 03 48 85 C0 74 28 45 85 ED 75 23 48 8B 53 18 48 85 D2 74 09 48 8B 78 08 FF D2 48 8B 03 4C 89 60 08 48 83 C4 08 5B 5D 41 5C 41 5D C3 66 90 48 8B 73 30 BF 20 00 00 00 FF 53 20 48 8B 13 48 89 28 4C 89 60 08 48 85 D2 74 45 45 85 ED 78 58 48 8B 4A 10 48 89 50 18 48 89 48 10 48 C7 42 10 00 00 00 00 48 89 03 48 83 C4 08 5B 5D 41 5C 41 5D C3 48 8B 73 30 BF 20 00 00 00 FF 53 20 48 8B 13 48 89 28 4C 89 60 08 48 85 D2 75 C3 0F 1F 00 48 C7 40 18 00 00 00 00 }
	condition:
		$pattern
}

rule fgetpos64_2f9eb78aaa151e8f1c76ca032b849bcf {
	meta:
		aliases = "fgetpos, fgetpos64"
		type = "func"
		size = "131"
		objfiles = "fgetpos64@libc.a, fgetpos@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 F4 55 48 89 FD 53 48 83 EC 28 44 8B 6F 50 45 85 ED 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 EF 83 CB FF E8 ?? ?? ?? ?? 48 85 C0 49 89 04 24 78 1B 8B 45 48 31 DB 41 89 44 24 08 8B 45 4C 41 89 44 24 0C 0F B6 45 02 41 89 44 24 10 45 85 ED 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule fsetpos64_66d716988b848d65c754263c654c95f8 {
	meta:
		aliases = "fsetpos, fsetpos64"
		type = "func"
		size = "128"
		objfiles = "fsetpos@libc.a, fsetpos64@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 F4 55 48 89 FD 53 48 83 EC 28 44 8B 6F 50 45 85 ED 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 49 8B 34 24 31 D2 48 89 EF E8 ?? ?? ?? ?? 85 C0 89 C3 75 18 41 8B 44 24 08 89 45 48 41 8B 44 24 0C 89 45 4C 41 8B 44 24 10 88 45 02 45 85 ED 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule putgrent_f9d7c0bcfdac7ca5edaf3e484d1e0b3e {
	meta:
		aliases = "putgrent"
		type = "func"
		size = "210"
		objfiles = "putgrent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 F4 55 48 89 FD 53 48 83 EC 28 48 85 FF 74 05 48 85 F6 75 13 83 CB FF E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 98 00 00 00 44 8B 6E 50 45 85 ED 75 1C 48 8D 5E 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 44 8B 45 10 48 8B 4D 08 31 C0 48 8B 55 00 BE ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 78 3F 48 8B 5D 18 BE ?? ?? ?? ?? 48 8B 13 48 85 D2 75 15 4C 89 E6 BF 0A 00 00 00 31 DB E8 ?? ?? ?? ?? 85 C0 79 1E EB 19 31 C0 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 78 0B 48 83 C3 08 BE ?? ?? ?? ?? EB CA 83 CB FF 45 85 ED 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 }
	condition:
		$pattern
}

rule __pthread_lock_45a11607ae0047db54fd48f8dfadd13b {
	meta:
		aliases = "__pthread_lock"
		type = "func"
		size = "174"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 F4 55 53 48 89 FB 48 83 EC 18 48 83 3F 00 74 05 45 31 ED EB 18 31 D2 B9 01 00 00 00 48 89 D0 F0 48 0F B1 0F 0F 94 C2 84 D2 74 E5 EB 70 48 8B 2B 40 F6 C5 01 75 0E 48 89 E9 BA 01 00 00 00 48 83 C9 01 EB 16 4D 85 E4 75 08 E8 FC FE FF FF 49 89 C4 4C 89 E1 31 D2 48 83 C9 01 4D 85 E4 74 05 49 89 6C 24 18 48 89 E8 F0 48 0F B1 0B 0F 94 C1 84 C9 74 BA 85 D2 75 1D 4C 89 E7 E8 10 FF FF FF 49 83 7C 24 18 00 74 A6 41 FF C5 EB EB 4C 89 E7 E8 D4 FD FF FF 41 FF CD 41 83 FD FF 75 EF 48 83 C4 18 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule fputs_unlocked_24f1219a2acde5641c27a3c7f3e02faf {
	meta:
		aliases = "__GI_fputs_unlocked, fputs_unlocked"
		type = "func"
		size = "56"
		objfiles = "fputs_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 53 48 89 F3 E8 ?? ?? ?? ?? 48 89 D9 48 89 C2 4C 89 E7 BE 01 00 00 00 49 89 C5 E8 ?? ?? ?? ?? 5B 48 89 C2 83 C8 FF 41 5C 4C 39 EA 41 5D 0F 44 C2 C3 }
	condition:
		$pattern
}

rule d_print_function_type_DOT_isra_DOT_5_62daae4244bf4224e6b543686098d79c {
	meta:
		aliases = "d_print_function_type.isra.5"
		type = "func"
		size = "623"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 55 48 89 D5 53 48 89 CB 48 83 EC 08 48 85 C9 0F 84 05 01 00 00 8B 79 10 85 FF 0F 85 FA 00 00 00 48 89 C8 BA 01 00 00 00 EB 2B 0F 1F 80 00 00 00 00 41 F7 C0 80 01 00 00 0F 85 DB 01 00 00 48 8B 00 48 85 C0 0F 84 DF 00 00 00 8B 48 10 85 C9 0F 85 D4 00 00 00 4C 8B 40 08 45 8B 00 41 8D 48 EA 83 F9 0F 77 D9 49 89 D0 49 D3 E0 41 F7 C0 47 86 00 00 74 BD 49 8B 44 24 08 48 85 C0 74 1C 49 8B 54 24 10 48 85 D2 74 07 80 7C 10 FF 20 74 2B 49 3B 54 24 18 0F 82 BC 01 00 00 BE 20 00 00 00 4C 89 E7 E8 32 E0 FF FF 49 8B 44 24 08 48 85 C0 0F 84 4C 01 00 00 49 8B 54 24 10 49 39 54 24 18 0F 86 }
	condition:
		$pattern
}

rule _charpad_e1545eae02f239cc08c6e8f7e5b1dcce {
	meta:
		aliases = "_charpad"
		type = "func"
		size = "77"
		objfiles = "_vfprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 55 48 89 D5 53 48 89 D3 48 83 EC 18 4C 8D 6C 24 17 40 88 74 24 17 EB 03 48 FF CB 48 85 DB 74 15 4C 89 E2 BE 01 00 00 00 4C 89 EF E8 ?? ?? ?? ?? 48 FF C8 74 E3 48 83 C4 18 48 29 DD 5B 48 89 E8 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule _charpad_9c1b2964869e50f1a32586e34e71dbb7 {
	meta:
		aliases = "_charpad"
		type = "func"
		size = "70"
		objfiles = "_vfwprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 55 48 89 D5 53 48 89 D3 48 83 EC 18 89 34 24 EB 03 48 FF CB 48 85 DB 74 15 4C 89 E2 BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 FF C8 74 E3 48 83 C4 18 48 29 DD 5B 48 89 E8 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule _Unwind_Backtrace_73c042674c84e7b782efdfef542aabf5 {
	meta:
		aliases = "_Unwind_Backtrace"
		type = "func"
		size = "89"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 55 48 89 F5 53 48 83 EC 18 48 8B 05 ?? ?? ?? ?? 48 89 04 24 EB 13 66 66 90 83 FB 05 74 27 48 8B 04 24 48 8B 00 48 89 04 24 48 83 3C 24 01 48 89 EE 48 89 E7 19 DB 83 E3 05 41 FF D4 85 C0 74 D9 BB 03 00 00 00 48 83 C4 18 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule putspent_a2d454dad9e6bea9e382f12986c3a63a {
	meta:
		aliases = "putspent"
		type = "func"
		size = "232"
		objfiles = "putspent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 55 48 89 F5 53 48 83 EC 28 44 8B 6E 50 45 85 ED 75 1C 48 8D 5E 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 49 8B 4C 24 08 49 8B 14 24 B8 ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 EF 48 85 C9 48 0F 44 C8 31 C0 31 DB E8 ?? ?? ?? ?? 85 C0 79 30 EB 65 0F B6 83 ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 EF 49 8B 14 04 B8 ?? ?? ?? ?? 48 83 FA FF 48 0F 45 F0 31 C0 E8 ?? ?? ?? ?? 85 C0 78 3A 48 FF C3 48 83 FB 05 76 CC 49 8B 54 24 40 48 83 FA FF 74 13 31 C0 BE ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 85 C0 78 13 48 89 EE BF 0A 00 00 00 31 DB E8 ?? ?? ?? ?? 85 C0 7F 03 83 CB }
	condition:
		$pattern
}

rule byte_group_match_null_string_p_890e97639e055e242e1c6630864420ef {
	meta:
		aliases = "byte_group_match_null_string_p"
		type = "func"
		size = "365"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 55 48 89 F5 53 48 89 D3 48 83 EC 18 48 8B 07 48 8D 78 02 48 89 7C 24 08 48 39 FD 0F 86 CE 00 00 00 0F B6 07 3C 07 0F 84 FD 00 00 00 3C 0F 0F 85 CD 00 00 00 48 8D 47 01 48 83 C7 03 48 89 44 24 08 0F BE 57 FF 44 0F B6 6F FE 48 89 7C 24 08 C1 E2 08 41 01 D5 78 C1 4D 63 ED 42 80 7C 2F FD 0E 4A 8D 74 2F FD 74 7C 0F BE 47 FF 44 0F B6 6F FE 48 89 DA C1 E0 08 44 01 E8 4C 63 E8 4A 8D 34 2F E8 E4 FE FF FF 84 C0 74 66 4C 89 EF 48 03 7C 24 08 48 89 7C 24 08 EB 80 90 4C 89 E8 48 03 44 24 08 48 89 44 24 08 80 38 0F 0F 85 9A 00 00 00 48 8D 50 01 48 89 54 24 08 0F BE 48 02 44 0F B6 68 01 }
	condition:
		$pattern
}

rule xprt_register_dc33293a0491a2a17d3ec9eb5ac0a4a6 {
	meta:
		aliases = "__GI_xprt_register, xprt_register"
		type = "func"
		size = "278"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 55 53 48 83 EC 08 44 8B 2F E8 ?? ?? ?? ?? 48 83 B8 E8 00 00 00 00 48 89 C5 75 24 E8 ?? ?? ?? ?? 48 98 48 8D 3C C5 00 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 85 E8 00 00 00 0F 84 C8 00 00 00 E8 ?? ?? ?? ?? 41 39 C5 0F 8D BA 00 00 00 48 8B 85 E8 00 00 00 49 63 DD 41 81 FD FF 03 00 00 4C 89 24 D8 7F 1B E8 ?? ?? ?? ?? 44 89 E9 48 C1 EB 06 BA 01 00 00 00 83 E1 3F 48 D3 E2 48 09 14 D8 31 DB EB 2F E8 ?? ?? ?? ?? 48 89 C1 48 63 C3 48 8D 14 C5 00 00 00 00 48 89 D0 48 03 01 83 38 FF 75 0F 44 89 28 48 8B 01 66 C7 44 10 04 C3 00 EB 57 FF C3 E8 ?? ?? ?? ?? 49 89 C4 8B 00 39 C3 7C C3 8D }
	condition:
		$pattern
}

rule htab_delete_95103c2cfca85d91bb17ea7feca8740c {
	meta:
		aliases = "htab_delete"
		type = "func"
		size = "179"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 55 53 48 83 EC 08 48 83 7F 10 00 48 8B 5F 20 4C 8B 6F 18 74 35 83 EB 01 78 30 48 63 C3 49 8D 6C C5 00 EB 0E 0F 1F 44 00 00 48 83 ED 08 83 EB 01 78 18 48 8B 7D 00 48 83 FF 01 76 ED 41 FF 54 24 10 48 83 ED 08 83 EB 01 79 E8 49 8B 44 24 48 48 85 C0 74 1D 4C 89 EF FF D0 49 8B 44 24 48 48 83 C4 08 4C 89 E7 5B 5D 41 5C 41 5D FF E0 0F 1F 40 00 49 8B 44 24 60 48 85 C0 74 26 49 8B 7C 24 50 4C 89 EE FF D0 49 8B 7C 24 50 49 8B 44 24 60 48 83 C4 08 5B 5D 4C 89 E6 41 5C 41 5D FF E0 0F 1F 00 48 83 C4 08 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule unsetenv_8529209b038c9705d846967a2b5f56d3 {
	meta:
		aliases = "__GI_unsetenv, unsetenv"
		type = "func"
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
		type = "func"
		size = "130"
		objfiles = "puts@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 55 53 48 83 EC 28 48 8B 2D ?? ?? ?? ?? 44 8B 6D 50 45 85 ED 75 1C 48 8D 5D 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 EE 4C 89 E7 E8 ?? ?? ?? ?? 83 F8 FF 89 C3 74 18 48 89 EE BF 0A 00 00 00 E8 ?? ?? ?? ?? 8D 53 01 83 F8 FF 89 C3 0F 45 DA 45 85 ED 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule authunix_validate_a21cb8ffca4f1f6f1264bd8e33823abc {
	meta:
		aliases = "authunix_validate"
		type = "func"
		size = "161"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 55 53 48 83 EC 38 83 3E 02 75 7F 48 8B 6F 40 8B 56 10 48 89 E7 48 8B 76 08 B9 01 00 00 00 E8 ?? ?? ?? ?? 48 8B 7D 20 48 85 FF 74 0D E8 ?? ?? ?? ?? 48 C7 45 20 00 00 00 00 48 8D 5D 18 48 89 E7 48 89 DE E8 ?? ?? ?? ?? 85 C0 74 0E FC B9 06 00 00 00 4C 89 E7 48 89 DE EB 26 48 89 DE 48 89 E7 C7 04 24 02 00 00 00 E8 ?? ?? ?? ?? FC 48 C7 45 20 00 00 00 00 B9 06 00 00 00 4C 89 E7 48 89 EE F3 A5 4C 89 E7 E8 02 FE FF FF 48 83 C4 38 B8 01 00 00 00 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule dladdr_00c0996c938bbbfc569d4a3ffe3b2417 {
	meta:
		aliases = "dladdr"
		type = "func"
		size = "249"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 55 53 48 89 F3 48 83 EC 08 E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 31 F6 EB 1B 48 8B 50 28 4C 39 E2 73 0E 48 85 F6 74 06 48 39 56 28 73 03 48 89 C6 48 8B 40 18 48 85 C0 75 E0 48 85 F6 0F 84 A8 00 00 00 48 8B 46 08 45 31 C0 45 31 ED 45 31 C9 45 31 D2 48 89 03 48 8B 46 28 48 89 43 08 4C 8B 9E B0 00 00 00 48 8B AE A8 00 00 00 EB 43 48 8B 46 58 44 89 C2 8B 0C 90 EB 30 89 CF 48 8B 16 48 6B C7 18 4A 03 54 18 08 4C 39 E2 77 16 45 85 C9 74 05 49 39 D2 73 0C 41 89 CD 49 89 D2 41 B9 01 00 00 00 48 8B 46 78 8B 0C B8 85 C9 75 CC 41 FF C0 44 3B 46 50 72 B7 45 85 C9 74 1A 44 89 E8 48 6B C0 }
	condition:
		$pattern
}

rule do_close_96f6224e67b3bfa99628f34e168951c2 {
	meta:
		aliases = "do_close"
		type = "func"
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
		type = "func"
		size = "220"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 48 63 EE 53 48 89 FB 48 83 EC 08 48 03 AF 38 01 00 00 48 8B 97 B0 00 00 00 48 8B 4D 08 48 89 C8 48 C1 F8 20 48 6B C0 18 44 8B 24 10 4C 03 A7 A8 00 00 00 83 F9 07 74 34 48 8B 15 ?? ?? ?? ?? 31 C0 BE ?? ?? ?? ?? BF 02 00 00 00 E8 ?? ?? ?? ?? BF 01 00 00 00 B8 3C 00 00 00 0F 05 48 3D 00 F0 FF FF 76 08 F7 D8 89 05 ?? ?? ?? ?? 48 8B 73 38 48 89 DA B9 01 00 00 00 4C 89 E7 4C 8B 6D 00 48 8B 2B E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 75 37 48 8B 15 ?? ?? ?? ?? 31 C0 4C 89 E1 BE ?? ?? ?? ?? BF 02 00 00 00 E8 ?? ?? ?? ?? BF 01 00 00 00 B8 3C 00 00 00 0F 05 48 3D 00 F0 FF FF 76 08 F7 D8 89 05 ?? }
	condition:
		$pattern
}

rule universal_f4a9854381085191cdc741462802ed71 {
	meta:
		aliases = "universal"
		type = "func"
		size = "355"
		objfiles = "svc_simple@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 48 89 F5 53 48 81 EC 78 22 00 00 48 8B 47 10 48 C7 84 24 68 22 00 00 00 00 00 00 48 85 C0 75 30 31 D2 BE ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 85 C0 0F 85 19 01 00 00 BA 04 00 00 00 BE ?? ?? ?? ?? BF 02 00 00 00 E8 ?? ?? ?? ?? E9 9C 00 00 00 44 8B 27 41 89 C5 E8 ?? ?? ?? ?? 48 8B 98 00 01 00 00 E9 A6 00 00 00 44 39 63 08 0F 85 98 00 00 00 44 39 6B 0C 0F 85 8E 00 00 00 31 F6 BA 60 22 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 8B 45 08 48 8B 73 10 48 89 E2 48 89 EF FF 50 10 85 C0 75 0D 48 89 EF E8 ?? ?? ?? ?? E9 A4 00 00 00 48 89 E7 FF 13 48 85 C0 75 0E 48 81 7B 18 ?? ?? ?? ?? 0F 85 8C 00 00 }
	condition:
		$pattern
}

rule clnt_sperror_eab800d32e62411fefd2368e8df992e7 {
	meta:
		aliases = "__GI_clnt_sperror, clnt_sperror"
		type = "func"
		size = "401"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 48 89 F5 53 48 89 FB 48 81 EC 28 04 00 00 E8 9E FE FF FF 49 89 C5 31 C0 4D 85 ED 0F 84 5D 01 00 00 48 8B 43 08 48 89 DF 48 8D B4 24 00 04 00 00 FF 50 10 48 89 EA BE ?? ?? ?? ?? 4C 89 EF 31 C0 E8 ?? ?? ?? ?? 8B BC 24 00 04 00 00 48 98 49 8D 5C 05 00 E8 ?? ?? ?? ?? 48 89 DF 48 89 C6 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 83 BC 24 00 04 00 00 11 48 8D 2C 03 0F 87 D2 00 00 00 8B 84 24 00 04 00 00 FF 24 C5 ?? ?? ?? ?? 8B BC 24 08 04 00 00 48 89 E6 BA 00 04 00 00 E8 ?? ?? ?? ?? 48 89 E2 BE ?? ?? ?? ?? 48 89 EF 31 C0 E8 ?? ?? ?? ?? E9 B8 00 00 00 8B 94 24 08 04 00 00 31 C0 EB 1C 39 14 }
	condition:
		$pattern
}

rule md5_finish_ctx_81748da32e806a398f88105631f36d67 {
	meta:
		aliases = "md5_finish_ctx"
		type = "func"
		size = "171"
		objfiles = "md5@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 48 89 F5 53 48 89 FB 48 83 EC 08 8B 47 18 8B 57 10 01 C2 39 D0 89 57 10 76 04 83 47 14 01 83 F8 37 77 78 41 BD 38 00 00 00 41 29 C5 41 89 C4 4C 89 EA BE ?? ?? ?? ?? 4A 8D 7C 23 1C E8 ?? ?? ?? ?? 8B 43 10 4B 8D 74 25 00 48 8D 7B 1C C1 E0 03 89 44 33 1C 8B 4B 14 8B 43 10 8D 14 CD 00 00 00 00 C1 E8 1D 09 D0 48 89 DA 89 44 33 20 48 83 C6 08 E8 ?? ?? ?? ?? 8B 03 89 45 00 8B 43 04 89 45 04 8B 43 08 89 45 08 8B 43 0C 89 45 0C 48 83 C4 08 48 89 E8 5B 5D 41 5C 41 5D C3 41 BD 78 00 00 00 41 29 C5 EB 86 }
	condition:
		$pattern
}

rule splay_tree_delete_91e66851c9bc831b2838cb9e587a8d3a {
	meta:
		aliases = "splay_tree_delete"
		type = "func"
		size = "271"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 48 89 FD 53 48 83 EC 08 48 8B 1F 48 85 DB 0F 84 DF 00 00 00 48 8B 47 10 48 85 C0 74 05 48 8B 3B FF D0 48 8B 45 18 48 85 C0 74 06 48 8B 7B 08 FF D0 48 C7 03 00 00 00 00 0F 1F 00 45 31 E4 EB 7F 0F 1F 00 48 8B 4D 10 48 89 C2 48 85 C9 74 09 48 8B 38 FF D1 48 8B 53 10 48 8B 45 18 49 89 D5 48 85 C0 74 0A 48 8B 7A 08 FF D0 4C 8B 6B 10 48 8B 43 18 4D 89 65 00 48 85 C0 74 60 48 8B 4D 10 48 89 C2 48 85 C9 74 09 48 8B 38 FF D1 48 8B 53 18 48 8B 45 18 49 89 D4 48 85 C0 74 0A 48 8B 7A 08 FF D0 4C 8B 63 18 4D 89 2C 24 4C 8B 2B 48 8B 75 30 48 89 DF FF 55 28 4D 85 ED 74 27 4C 89 EB 48 8B 43 10 }
	condition:
		$pattern
}

rule d_name_b8bb4e46fe3cafc1db8cc011d1ac2850 {
	meta:
		aliases = "d_name"
		type = "func"
		size = "1038"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 48 89 FD 53 48 83 EC 28 48 8B 47 18 0F B6 10 80 FA 53 0F 84 B3 01 00 00 80 FA 5A 0F 84 3A 01 00 00 80 FA 4E 74 2D 0F 1F 44 00 00 E8 EB F3 FF FF 48 8B 55 18 48 89 C3 80 3A 49 0F 84 DB 01 00 00 48 83 C4 28 48 89 D8 5B 5D 41 5C 41 5D C3 0F 1F 44 00 00 48 8D 50 01 48 89 57 18 80 38 4E 0F 85 DF 00 00 00 48 8D 74 24 18 BA 01 00 00 00 E8 C8 C0 FF FF 48 85 C0 49 89 C5 0F 84 C4 00 00 00 48 8B 45 18 45 31 E4 0F B6 18 66 90 84 DB 0F 84 A8 00 00 00 8D 53 D0 80 FA 09 0F 86 4C 02 00 00 8D 43 9F 3C 19 0F 86 41 02 00 00 8D 43 BD 3C 01 0F 86 36 02 00 00 80 FB 53 0F 84 7D 02 00 00 80 FB 49 0F 84 }
	condition:
		$pattern
}

rule fclose_80524c5b8c0a5cdf8045465dbd39bfe0 {
	meta:
		aliases = "__GI_fclose, fclose"
		type = "func"
		size = "262"
		objfiles = "fclose@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 48 89 FD 53 48 83 EC 48 44 8B 6F 50 45 85 ED 75 1E 48 8D 5F 58 48 8D 7C 24 20 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 45 31 E4 F6 45 00 40 74 0B 48 89 EF E8 ?? ?? ?? ?? 41 89 C4 8B 7D 04 E8 ?? ?? ?? ?? 83 CA FF 85 C0 BE ?? ?? ?? ?? 44 0F 48 E2 89 55 04 48 89 E7 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 FF C0 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 66 25 00 60 83 C8 30 45 85 ED 66 89 45 00 75 0F 48 8D 7C 24 20 BE 01 00 00 00 E8 ?? ?? ?? ?? F6 45 01 40 74 09 48 8B 7D 08 E8 ?? ?? ?? ?? BA ?? ?? ?? }
	condition:
		$pattern
}

rule memalign_fe991eb8a47dc5c16d087d95e6bc5bc8 {
	meta:
		aliases = "memalign"
		type = "func"
		size = "411"
		objfiles = "memalign@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 48 89 FD 53 48 89 F3 48 83 EC 28 48 83 FF 10 77 10 48 89 F7 E8 ?? ?? ?? ?? 48 89 C3 E9 67 01 00 00 48 83 FF 1F B8 20 00 00 00 BF 20 00 00 00 48 0F 46 E8 48 8D 45 FF 48 85 C5 75 05 EB 0B 48 01 FF 48 39 EF 72 F8 48 89 FD 48 89 E7 BA ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 FB BF 76 12 31 DB E8 ?? ?? ?? ?? C7 00 0C 00 00 00 E9 0B 01 00 00 48 8D 43 17 41 BD 20 00 00 00 48 83 F8 1F 76 07 49 89 C5 49 83 E5 F0 49 8D 7C 2D 20 31 DB E8 ?? ?? ?? ?? 48 85 C0 48 89 C6 0F 84 CF 00 00 00 31 D2 4C 8D 60 F0 48 F7 F5 48 85 D2 74 7B 48 8D 44 2E FF 48 89 EA 48 }
	condition:
		$pattern
}

rule getpwd_563a504668ca53300331e995ba771c0c {
	meta:
		aliases = "getpwd"
		type = "func"
		size = "273"
		objfiles = "getpwd@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 53 48 81 EC 28 01 00 00 48 8B 2D ?? ?? ?? ?? 48 85 ED 74 17 48 81 C4 28 01 00 00 48 89 E8 5B 5D 41 5C 41 5D C3 66 0F 1F 44 00 00 E8 ?? ?? ?? ?? 49 89 C5 8B 05 ?? ?? ?? ?? 85 C0 41 89 45 00 75 D3 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 74 05 80 38 2F 74 5A BB 01 10 00 00 EB 19 0F 1F 40 00 45 8B 65 00 48 89 EF E8 ?? ?? ?? ?? 41 83 FC 22 75 2E 48 01 DB 48 89 DF E8 ?? ?? ?? ?? 48 89 DE 48 89 C7 48 89 C5 E8 ?? ?? ?? ?? 48 85 C0 74 D0 48 89 2D ?? ?? ?? ?? E9 75 FF FF FF 0F 1F 40 00 44 89 25 ?? ?? ?? ?? 45 89 65 00 31 ED EB E1 48 8D 94 24 90 00 00 00 48 89 C6 BF 01 00 00 00 E8 }
	condition:
		$pattern
}

rule initshells_75ac48929023399cd72c73d833bf65fb {
	meta:
		aliases = "initshells"
		type = "func"
		size = "336"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 53 48 81 EC 98 00 00 00 E8 BA FF FF FF BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 49 89 C4 B8 ?? ?? ?? ?? 4D 85 E4 0F 84 10 01 00 00 4C 89 E7 E8 ?? ?? ?? ?? 48 89 E6 89 C7 E8 ?? ?? ?? ?? FF C0 0F 84 E4 00 00 00 8B 7C 24 30 FF C7 E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 0F 84 C9 00 00 00 8B 44 24 30 BA 03 00 00 00 BE 08 00 00 00 89 D1 31 D2 F7 F1 89 C7 E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 0F 84 9E 00 00 00 BE 02 00 00 00 4C 89 E7 E8 ?? ?? ?? ?? 48 8B 2D ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? 44 8B 6C 24 30 EB 46 48 FF C3 8A 03 3C 23 74 3D 3C 2F 74 06 84 C0 75 EF EB 33 84 }
	condition:
		$pattern
}

rule xregerror_232cc1cd20ca681a5f257825e92fe780 {
	meta:
		aliases = "xregerror"
		type = "func"
		size = "125"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 53 48 83 EC 08 83 FF 10 77 69 48 63 FF 48 89 CD 49 89 D5 4C 8B 24 FD ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? 48 85 ED 48 8D 58 01 74 13 48 39 EB 77 22 48 89 DA 4C 89 E6 4C 89 EF E8 ?? ?? ?? ?? 48 83 C4 08 48 89 D8 5B 5D 41 5C 41 5D C3 66 0F 1F 44 00 00 48 8D 55 FF 4C 89 E6 4C 89 EF E8 ?? ?? ?? ?? C6 00 00 48 83 C4 08 48 89 D8 5B 5D 41 5C 41 5D C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule d_print_mod_list_2dc2e37aba7028f59fd004ce048ed270 {
	meta:
		aliases = "d_print_mod_list"
		type = "func"
		size = "401"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 53 48 89 F3 48 83 EC 08 48 85 F6 74 6D 48 83 7F 08 00 48 89 FD 41 89 D5 75 10 EB 5E 0F 1F 80 00 00 00 00 48 83 7D 08 00 74 50 8B 73 10 85 F6 75 41 48 8B 73 08 45 85 ED 8B 06 75 08 8D 50 E7 83 FA 02 76 2E 48 8B 53 18 83 F8 23 C7 43 10 01 00 00 00 4C 8B 65 20 48 89 55 20 74 29 83 F8 24 74 46 83 F8 02 74 5F 48 89 EF E8 7D F9 FF FF 4C 89 65 20 48 8B 1B 48 85 DB 75 A9 48 83 C4 08 5B 5D 41 5C 41 5D C3 48 8B 0B 48 8D 56 10 48 89 EF 48 83 C6 08 E8 F3 FC FF FF 4C 89 65 20 48 83 C4 08 5B 5D 41 5C 41 5D C3 48 8B 13 48 89 EF 48 83 C6 08 E8 E5 00 00 00 4C 89 65 20 48 83 C4 08 5B 5D 41 5C 41 }
	condition:
		$pattern
}

rule clnt_spcreateerror_5283ca5d700f539c64dbe267f257687d {
	meta:
		aliases = "__GI_clnt_spcreateerror, clnt_spcreateerror"
		type = "func"
		size = "260"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 53 48 89 FB 48 81 EC 08 04 00 00 E8 BE FF FF FF 48 85 C0 49 89 C5 0F 84 D2 00 00 00 E8 ?? ?? ?? ?? 48 89 DA 49 89 C4 BE ?? ?? ?? ?? 4C 89 EF 31 C0 E8 ?? ?? ?? ?? 41 8B 3C 24 48 98 49 8D 5C 05 00 E8 ?? ?? ?? ?? 48 89 DF 48 89 C6 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 01 C3 41 8B 04 24 83 F8 0C 74 3F 83 F8 0E 75 7D BE ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 41 8B 7C 24 08 48 01 C3 E8 ?? ?? ?? ?? 48 89 DF 48 89 C6 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 01 C3 EB 43 BE ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 41 8B 7C 24 10 48 8D 2C 03 BA }
	condition:
		$pattern
}

rule d_expression_538e2ea4a0c1ef6f722e5f96212e0d89 {
	meta:
		aliases = "d_expression"
		type = "func"
		size = "539"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 53 48 89 FB 48 83 EC 08 48 8B 57 18 0F B6 02 3C 4C 0F 84 8C 01 00 00 3C 54 0F 84 9C 01 00 00 3C 73 74 58 48 89 DF E8 C0 F5 FF FF 48 85 C0 48 89 C5 0F 84 9E 00 00 00 8B 00 83 F8 28 0F 84 A9 00 00 00 83 F8 29 74 74 83 F8 2A 0F 85 85 00 00 00 48 89 DF E8 A3 FF FF FF 48 89 EA 48 89 C1 BE 2B 00 00 00 48 83 C4 08 48 89 DF 5B 5D 41 5C 41 5D E9 26 C3 FF FF 66 0F 1F 44 00 00 80 7A 01 72 75 A2 48 83 C2 02 48 89 57 18 E8 ?? ?? ?? ?? 48 89 DF 48 89 C5 E8 B2 F6 FF FF 48 8B 73 18 49 89 C4 80 3E 49 0F 84 42 01 00 00 48 89 C1 48 89 EA BE 01 00 00 00 EB AD 0F 1F 44 00 00 8B 45 08 83 F8 02 74 52 }
	condition:
		$pattern
}

rule pex_input_file_31351a84720c81d2dac679fec8e31a1c {
	meta:
		aliases = "pex_input_file"
		type = "func"
		size = "162"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 53 48 89 FB 48 83 EC 08 8B 4F 2C 85 C9 75 0E 8B 47 18 85 C0 7F 07 48 83 7F 20 00 74 1E E8 ?? ?? ?? ?? C7 00 16 00 00 00 31 C0 48 83 C4 08 5B 5D 41 5C 41 5D C3 66 0F 1F 44 00 00 48 8D 7F 10 89 F5 49 89 D4 E8 82 F9 FF FF 48 85 C0 49 89 C5 74 3C 83 E5 20 B8 ?? ?? ?? ?? BE ?? ?? ?? ?? 48 0F 44 F0 4C 89 EF E8 ?? ?? ?? ?? 48 85 C0 74 22 31 D2 4D 39 E5 4C 89 6B 20 0F 95 C2 48 89 43 50 89 53 28 48 83 C4 08 5B 5D 41 5C 41 5D C3 31 C0 EB 99 4C 89 EF E8 ?? ?? ?? ?? 31 C0 EB 8D }
	condition:
		$pattern
}

rule rendezvous_request_7d8f2e1b02220bba36370691b3ba1f3c {
	meta:
		aliases = "rendezvous_request"
		type = "func"
		size = "112"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 53 48 89 FB 48 83 EC 28 48 8B 6F 40 4C 8D 64 24 1C C7 44 24 1C 10 00 00 00 8B 3B 4C 89 E2 48 89 E6 E8 ?? ?? ?? ?? 85 C0 89 C7 79 0C E8 ?? ?? ?? ?? 83 38 04 75 28 EB D9 8B 55 04 8B 75 00 E8 AF FB FF FF 48 8D 78 14 BA 10 00 00 00 48 89 E6 48 89 C3 E8 ?? ?? ?? ?? 8B 44 24 1C 89 43 10 48 83 C4 28 31 C0 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule concat_3f2de0bc5e6cdcf9d8db487c14d7eecb {
	meta:
		aliases = "concat"
		type = "func"
		size = "348"
		objfiles = "concat@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 53 48 89 FB 48 83 EC 58 48 85 FF 48 8D 84 24 80 00 00 00 48 89 74 24 28 48 89 54 24 30 48 89 4C 24 38 4C 89 44 24 40 48 89 44 24 10 48 8D 44 24 20 4C 89 4C 24 48 C7 44 24 08 08 00 00 00 48 89 44 24 18 0F 84 DD 00 00 00 49 89 C4 31 ED EB 17 0F 1F 00 89 C2 83 C0 08 4C 01 E2 89 44 24 08 48 8B 3A 48 85 FF 74 27 E8 ?? ?? ?? ?? 48 01 C5 8B 44 24 08 83 F8 2F 76 DB 48 8B 54 24 10 48 8B 3A 48 8D 42 08 48 89 44 24 10 48 85 FF 75 D9 48 8D 7D 01 E8 ?? ?? ?? ?? 49 89 C5 48 8D 84 24 80 00 00 00 C7 44 24 08 08 00 00 00 4C 89 ED 48 89 44 24 10 48 8D 44 24 20 48 89 44 24 18 EB 1B 0F 1F 44 00 00 }
	condition:
		$pattern
}

rule d_bare_function_type_3cf3fa5095919dfc7f82b0483270928d {
	meta:
		aliases = "d_bare_function_type"
		type = "func"
		size = "254"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 89 F5 53 48 89 FB 48 83 EC 18 48 8B 57 18 80 3A 4A 0F 84 AC 00 00 00 48 C7 44 24 08 00 00 00 00 4C 8D 6C 24 08 45 31 E4 EB 0A 90 48 8B 53 18 31 ED 49 89 C4 0F B6 02 3C 45 74 40 84 C0 74 3C 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 74 67 85 ED 75 DB 31 C9 48 89 C2 BE 26 00 00 00 48 89 DF E8 49 CA FF FF 48 85 C0 49 89 45 00 74 48 48 8B 53 18 4C 8D 68 10 0F B6 02 3C 45 75 C1 90 48 8B 44 24 08 48 85 C0 74 2E 48 8B 48 10 48 85 C9 74 47 48 89 C1 4C 89 E2 48 89 DF BE 23 00 00 00 E8 0A CA FF FF 48 83 C4 18 5B 5D 41 5C 41 5D C3 0F 1F 80 00 00 00 00 48 83 C4 18 31 C0 5B 5D 41 5C 41 5D C3 0F 1F 00 }
	condition:
		$pattern
}

rule getmntent_r_7ec8f4ba924974a4112885f898918317 {
	meta:
		aliases = "__GI_getmntent_r, getmntent_r"
		type = "func"
		size = "293"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 CD 41 54 49 89 FC 55 48 89 F5 53 48 89 D3 48 83 EC 18 48 85 FF 0F 84 F6 00 00 00 48 85 F6 0F 84 ED 00 00 00 48 85 D2 0F 84 E4 00 00 00 EB 0A 8A 03 3C 23 74 04 3C 0A 75 18 4C 89 E2 44 89 EE 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 75 E3 E9 C0 00 00 00 4C 8D 64 24 10 BE ?? ?? ?? ?? 48 89 DF 48 C7 44 24 10 00 00 00 00 4C 89 E2 E8 ?? ?? ?? ?? 48 85 C0 48 89 45 00 0F 84 95 00 00 00 31 FF 4C 89 E2 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 45 08 74 7D 31 FF 4C 89 E2 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 45 10 74 65 31 FF 4C 89 E2 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 85 C0 BE }
	condition:
		$pattern
}

rule _stdio_fopen_1eb1f93e6bdc6f590f47db27cec260b7 {
	meta:
		aliases = "_stdio_fopen"
		type = "func"
		size = "561"
		objfiles = "_fopen@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 CD 41 54 55 48 89 D5 53 48 89 FB 48 83 EC 48 8A 06 3C 72 74 3E 3C 77 41 BC 41 02 00 00 74 37 3C 61 66 41 BC 41 04 74 2E E8 ?? ?? ?? ?? 48 85 ED C7 00 16 00 00 00 0F 84 E1 01 00 00 F6 45 01 20 0F 84 D7 01 00 00 48 89 EF E8 ?? ?? ?? ?? E9 CA 01 00 00 45 31 E4 80 7E 01 62 48 8D 46 01 48 0F 45 C6 80 78 01 2B 75 0A 44 89 E0 83 C8 01 44 8D 60 01 48 85 ED 75 2C BF 80 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 0F 84 92 01 00 00 48 8D 78 58 66 C7 00 00 20 48 C7 40 08 00 00 00 00 E8 ?? ?? ?? ?? 45 85 ED 78 45 44 89 E2 8D 43 01 44 89 6D 04 83 E2 03 FF C2 21 D0 39 D0 0F 85 67 FF FF FF 89 D8 F7 }
	condition:
		$pattern
}

rule dyn_string_substring_cc0dfda98e530bc3350e6b474b578d84 {
	meta:
		aliases = "dyn_string_substring"
		type = "func"
		size = "178"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 D5 41 54 41 89 CC 41 29 D4 55 53 48 83 EC 08 39 D1 0F 8C 92 00 00 00 8B 46 04 48 89 F5 39 C2 0F 8F 84 00 00 00 39 C1 0F 8F 7C 00 00 00 44 89 E6 48 89 FB E8 ?? ?? ?? ?? 48 85 C0 74 5F 44 89 E2 83 EA 01 78 37 48 63 CA 89 D2 48 8D 41 FF 48 89 C7 48 29 D7 49 63 D5 EB 07 0F 1F 00 48 83 E8 01 49 89 C8 4C 03 45 08 48 39 F8 45 0F B6 0C 10 4C 8B 43 08 45 88 0C 08 48 89 C1 75 E0 48 8B 53 08 49 63 C4 C6 04 02 00 44 89 63 04 48 83 C4 08 5B 5D 41 5C B8 01 00 00 00 41 5D C3 90 48 83 C4 08 31 C0 5B 5D 41 5C 41 5D C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdr_string_4f90182a82c6ab4cc172b920e93e23e2 {
	meta:
		aliases = "__GI_xdr_string, xdr_string"
		type = "func"
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
		type = "func"
		size = "152"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 F5 41 54 55 48 89 FD 53 31 DB 48 81 EC 98 00 00 00 48 89 E6 E8 ?? ?? ?? ?? 85 C0 75 66 8B 44 24 18 25 00 F0 00 00 3D 00 80 00 00 75 56 BE ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 41 48 89 C7 E8 ?? ?? ?? ?? 89 C7 48 89 E6 E8 ?? ?? ?? ?? 85 C0 78 1C 8B 44 24 1C 85 C0 74 05 44 39 E8 75 0F F6 44 24 18 12 75 08 48 83 7C 24 10 01 76 0F 48 85 DB 74 0A 48 89 DF 31 DB E8 ?? ?? ?? ?? 48 81 C4 98 00 00 00 48 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule putwc_302df8488cc5c5ce4a59d3669a36430d {
	meta:
		aliases = "fputwc, putwc"
		type = "func"
		size = "97"
		objfiles = "fputwc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 FD 41 54 55 48 89 F5 53 48 83 EC 28 44 8B 66 50 45 85 E4 75 1C 48 8D 5E 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 EE 44 89 EF E8 ?? ?? ?? ?? 45 85 E4 89 C3 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule bindresvport_407e50e015980c46bbdcd2d88813465c {
	meta:
		aliases = "__GI_bindresvport, bindresvport"
		type = "func"
		size = "216"
		objfiles = "bindresvport@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 FD 41 54 55 53 48 89 F3 48 83 EC 18 48 85 F6 75 1A BA 10 00 00 00 31 F6 48 89 E7 E8 ?? ?? ?? ?? 48 89 E3 66 C7 04 24 02 00 EB 19 66 83 3E 02 74 13 E8 ?? ?? ?? ?? C7 00 60 00 00 00 83 C8 FF E9 85 00 00 00 66 83 3D ?? ?? ?? ?? 00 75 1B E8 ?? ?? ?? ?? BA A8 01 00 00 89 D1 99 F7 F9 66 81 C2 58 02 66 89 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 ED 49 89 C4 C7 00 62 00 00 00 83 C8 FF EB 38 66 8B 05 ?? ?? ?? ?? 48 89 DE 44 89 EF 89 C2 FF C0 66 C1 CA 08 66 3D 00 04 66 89 53 02 BA 58 02 00 00 0F 4C D0 FF C5 66 89 15 ?? ?? ?? ?? BA 10 00 00 00 E8 ?? ?? ?? ?? 81 FD A7 01 00 00 7F 0B 85 C0 79 07 41 83 }
	condition:
		$pattern
}

rule lockf64_2069361860def5c5f9a2a3288823ab2e {
	meta:
		aliases = "__GI_lockf, __GI_lockf64, lockf, lockf64"
		type = "func"
		size = "223"
		objfiles = "lockf@libc.a, lockf64@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 FD 41 54 55 89 F5 31 F6 53 48 89 D3 BA 20 00 00 00 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? 83 FD 01 66 C7 44 24 02 01 00 48 C7 44 24 08 00 00 00 00 48 89 5C 24 10 74 5A 7F 06 85 ED 74 4C EB 6C 83 FD 02 74 5A 83 FD 03 75 62 48 89 E2 31 C0 BE 05 00 00 00 44 89 EF 66 C7 04 24 00 00 E8 ?? ?? ?? ?? 83 CA FF 85 C0 78 66 66 83 3C 24 02 74 5D 8B 5C 24 18 E8 ?? ?? ?? ?? 39 C3 74 50 E8 ?? ?? ?? ?? C7 00 0D 00 00 00 EB 2D 66 C7 04 24 02 00 EB 13 BE 07 00 00 00 66 C7 04 24 01 00 EB 1D 66 C7 04 24 01 00 BE 06 00 00 00 EB 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CA FF EB 13 48 89 E2 44 89 EF 31 C0 E8 }
	condition:
		$pattern
}

rule read_491c3cad1fea36f1a10c020855681855 {
	meta:
		aliases = "read"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "69"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 FD BF 01 00 00 00 41 54 49 89 F4 53 89 D3 48 83 EC 10 48 8D 74 24 0C E8 ?? ?? ?? ?? 89 DA 4C 89 E6 44 89 EF E8 ?? ?? ?? ?? 8B 7C 24 0C 31 F6 89 C3 E8 ?? ?? ?? ?? 41 5D 5A 89 D8 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule _obstack_newchunk_620173b5a912fd34b1d6e9d324a457c8 {
	meta:
		aliases = "_obstack_newchunk"
		type = "func"
		size = "311"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 48 63 F6 41 54 55 53 48 89 FB 48 83 EC 08 4C 8B 67 18 48 63 47 30 4C 2B 67 10 4C 8B 6F 08 49 8D 44 04 64 4C 89 E2 48 C1 FA 03 48 01 D0 48 8B 17 48 01 F0 48 39 D0 48 89 D5 48 0F 4D E8 F6 47 50 01 48 8B 47 38 74 0B 48 8B 7F 48 48 89 EE FF D0 EB 05 48 89 EF FF D0 48 85 C0 48 89 C6 75 05 E8 0A 01 00 00 48 89 43 08 4C 89 68 08 48 8D 04 28 48 89 43 20 48 89 06 8B 53 30 89 D0 F7 D0 48 63 E8 48 63 C2 48 8D 44 06 10 48 21 C5 31 C0 83 FA 0E 7E 30 4C 89 E7 48 C1 EF 02 48 8D 4F FF EB 16 48 8B 53 10 48 8D 04 8D 00 00 00 00 48 FF C9 8B 14 02 89 54 05 00 48 85 C9 79 E5 48 8D 04 BD 00 00 00 00 48 89 C2 }
	condition:
		$pattern
}

rule _time_t2tm_e2c48d1db7a9892573b809ac29ed2f13 {
	meta:
		aliases = "_time_t2tm"
		type = "func"
		size = "420"
		objfiles = "_time_t2tm@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 48 63 F6 48 B8 D8 8C 5C 97 B6 00 00 00 49 89 D3 49 89 D1 49 BD F0 51 B8 2E 6D 01 00 00 41 54 55 48 8D 2C 06 48 81 C6 76 0E 02 00 53 BB ?? ?? ?? ?? 48 8B 3F C7 42 1C 00 00 00 00 66 44 8B 13 66 41 83 FA 07 41 0F B7 CA 75 37 48 8D 44 3D 00 4C 39 E8 76 08 45 31 DB E9 3C 01 00 00 48 89 F8 48 01 F7 48 99 48 F7 F9 B9 07 00 00 00 8D 42 0B 99 F7 F9 0F B7 43 02 48 8D 0C 85 01 00 00 00 41 89 D4 48 89 F8 48 99 48 F7 F9 49 89 C0 48 0F AF C1 48 29 C7 79 06 48 01 CF 49 FF C8 66 41 83 FA 07 75 11 48 8D 41 FF 48 39 C7 75 08 41 FF 41 10 48 8D 79 FE 48 83 F9 3C 49 8D 49 04 7F 0B 41 89 39 49 89 C9 4C 89 C7 }
	condition:
		$pattern
}

rule pex_unix_wait_2c40652a91df27b96f5290587ee4304e {
	meta:
		aliases = "pex_unix_wait"
		type = "func"
		size = "176"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 48 89 F7 4D 89 CD 41 54 41 89 F4 55 48 89 D5 53 48 89 CB 48 81 EC 98 00 00 00 45 85 C0 75 4F 48 85 DB 74 59 31 D2 48 89 E1 48 89 EE 44 89 E7 E8 ?? ?? ?? ?? 48 8B 14 24 48 89 13 48 8B 54 24 08 48 89 53 08 48 8B 54 24 10 48 89 53 10 48 8B 54 24 18 48 89 53 18 85 C0 78 34 31 C0 48 81 C4 98 00 00 00 5B 5D 41 5C 41 5D C3 0F 1F 40 00 BE 0F 00 00 00 E8 ?? ?? ?? ?? 48 85 DB 75 A7 31 D2 48 89 EE 44 89 E7 E8 ?? ?? ?? ?? EB CA 66 90 E8 ?? ?? ?? ?? 8B 10 48 8B 84 24 C0 00 00 00 89 10 49 C7 45 00 ?? ?? ?? ?? B8 FF FF FF FF EB AE }
	condition:
		$pattern
}

rule pthread_cancel_358488f959801b30de89e2b3e05832f9 {
	meta:
		aliases = "pthread_cancel"
		type = "func"
		size = "186"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 48 89 F8 31 F6 25 FF 03 00 00 41 54 48 C1 E0 05 4C 8D A0 ?? ?? ?? ?? 55 48 89 FD 4C 89 E7 53 48 83 EC 08 E8 ?? ?? ?? ?? 49 8B 5C 24 10 48 85 DB 74 06 48 39 6B 20 74 64 4C 89 E7 E8 ?? ?? ?? ?? B8 03 00 00 00 EB 69 4C 89 E7 E8 ?? ?? ?? ?? EB 47 48 8B 83 D8 02 00 00 31 ED 44 8B 6B 28 48 85 C0 74 11 48 89 DE 48 8B 38 FF 50 08 89 C5 88 83 D0 02 00 00 4C 89 E7 E8 ?? ?? ?? ?? 85 ED 74 0A 48 89 DF E8 ?? ?? ?? ?? EB 0E 8B 35 ?? ?? ?? ?? 44 89 EF E8 ?? ?? ?? ?? 31 C0 EB 14 80 7B 78 01 0F BE 43 7A C6 43 7A 01 74 9D 85 C0 75 99 EB A1 5E 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule pthread_getschedparam_6c69ce1cd2691830da6ce4c25bec8e9f {
	meta:
		aliases = "__GI_pthread_getschedparam, pthread_getschedparam"
		type = "func"
		size = "144"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 48 89 F8 49 89 F5 25 FF 03 00 00 31 F6 41 54 48 C1 E0 05 49 89 D4 55 48 89 FD 53 48 8D 98 ?? ?? ?? ?? 48 83 EC 08 48 89 DF E8 ?? ?? ?? ?? 48 8B 43 10 48 85 C0 74 06 48 39 68 20 74 2E 48 89 DF E8 ?? ?? ?? ?? B8 03 00 00 00 EB 3A 4C 89 E6 89 EF E8 ?? ?? ?? ?? FF C0 75 09 E8 ?? ?? ?? ?? 8B 00 EB 23 31 C0 41 89 5D 00 EB 1B 8B 68 28 48 89 DF E8 ?? ?? ?? ?? 89 EF E8 ?? ?? ?? ?? 83 F8 FF 89 C3 75 C8 EB D4 5A 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule pex_init_common_2473dfef93d231e2e119cbc134ca31e2 {
	meta:
		aliases = "pex_init_common"
		type = "func"
		size = "155"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 CD 41 54 49 89 D4 55 48 89 F5 53 89 FB BF 80 00 00 00 48 83 EC 08 E8 ?? ?? ?? ?? 89 18 48 89 68 08 4C 89 60 10 C7 40 18 00 00 00 00 48 C7 40 20 00 00 00 00 C7 40 28 00 00 00 00 C7 40 2C 00 00 00 00 48 C7 40 30 00 00 00 00 48 C7 40 38 00 00 00 00 48 C7 40 40 00 00 00 00 C7 40 48 00 00 00 00 48 C7 40 50 00 00 00 00 48 C7 40 58 00 00 00 00 C7 40 60 00 00 00 00 48 C7 40 68 00 00 00 00 4C 89 68 70 48 C7 40 78 00 00 00 00 48 83 C4 08 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule dyn_string_insert_cstr_ebb5185c7c92fc046d3a3929791a217c {
	meta:
		aliases = "dyn_string_insert_cstr"
		type = "func"
		size = "165"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 D5 41 54 41 89 F4 55 53 48 89 FB 48 89 D7 48 83 EC 08 E8 ?? ?? ?? ?? 8B 73 04 48 89 DF 48 89 C5 01 C6 E8 ?? ?? ?? ?? 48 85 C0 74 68 8B 53 04 48 63 C5 44 39 E2 7C 31 4C 63 D2 44 29 E2 4A 8D 0C 10 49 83 EA 01 49 29 D2 49 01 C2 90 4C 8B 43 08 49 89 C9 49 29 C1 47 0F B6 0C 08 45 88 0C 08 48 83 E9 01 4C 39 D1 75 E4 49 63 FC 48 03 7B 08 4C 89 EE 48 89 C2 E8 ?? ?? ?? ?? 01 6B 04 48 83 C4 08 B8 01 00 00 00 5B 5D 41 5C 41 5D C3 0F 1F 80 00 00 00 00 48 83 C4 08 31 C0 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule wcsncasecmp_7e6758b3d51486277b3fe3ca2742ef52 {
	meta:
		aliases = "__GI_wcsncasecmp, wcsncasecmp"
		type = "func"
		size = "110"
		objfiles = "wcsncasecmp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 D5 41 54 49 89 F4 55 48 89 FD 53 48 83 EC 08 EB 11 83 7D 00 00 74 10 48 83 C5 04 49 83 C4 04 49 FF CD 4D 85 ED 75 04 31 C0 EB 37 8B 7D 00 41 3B 3C 24 74 DD E8 ?? ?? ?? ?? 41 8B 3C 24 89 C3 E8 ?? ?? ?? ?? 39 C3 74 C9 8B 7D 00 E8 ?? ?? ?? ?? 41 8B 3C 24 89 C3 E8 ?? ?? ?? ?? 39 C3 19 C0 83 C8 01 5A 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule pthread_atfork_46813445732f51e0f891a426eabf2f11 {
	meta:
		aliases = "pthread_atfork"
		type = "func"
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
		type = "func"
		size = "168"
		objfiles = "timer_create@librt.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 D5 41 54 49 89 F4 55 53 89 FB 48 83 EC 58 48 85 F6 75 13 C7 44 24 0C 00 00 00 00 C7 44 24 08 0E 00 00 00 49 89 E4 41 83 7C 24 0C 02 74 66 BF 08 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 74 54 48 89 04 24 48 8D 54 24 4C 4C 89 E6 48 63 FB B8 DE 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 83 FB FF 74 15 41 8B 44 24 0C 49 89 6D 00 89 45 00 8B 44 24 4C 89 45 04 EB 0D 48 89 EF E8 ?? ?? ?? ?? EB 03 83 CB FF 48 83 C4 58 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule demangle_class_name_a197709a047c530aaf6124446d4049db {
	meta:
		aliases = "demangle_class_name"
		type = "func"
		size = "119"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 D5 41 54 49 89 FC 48 89 F7 55 53 48 89 F3 48 83 EC 08 E8 B5 C6 FF FF 83 F8 FF 89 C5 74 46 48 8B 3B E8 ?? ?? ?? ?? 31 F6 39 C5 7E 10 48 83 C4 08 89 F0 5B 5D 41 5C 41 5D C3 0F 1F 00 48 89 DE 4C 89 E9 89 EA 4C 89 E7 E8 B0 F7 FF FF 48 83 C4 08 BE 01 00 00 00 5B 5D 41 5C 89 F0 41 5D C3 66 0F 1F 44 00 00 48 83 C4 08 31 F6 5B 5D 41 5C 89 F0 41 5D C3 }
	condition:
		$pattern
}

rule fgetws_unlocked_c781fe478dcce998a680c68059be4d5c {
	meta:
		aliases = "__GI_fgetws_unlocked, fgetws_unlocked"
		type = "func"
		size = "81"
		objfiles = "fgetws_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 D5 41 54 49 89 FC 55 89 F5 53 48 89 FB 48 83 EC 08 EB 02 FF CD 83 FD 01 7E 18 4C 89 EF E8 ?? ?? ?? ?? 83 F8 FF 74 0B 89 03 48 83 C3 04 83 F8 0A 75 E1 4C 39 E3 75 05 45 31 E4 EB 06 C7 03 00 00 00 00 5A 5B 5D 4C 89 E0 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule regerror_e7707d9b123e33864ff135a6eaa2630b {
	meta:
		aliases = "__regerror, regerror"
		type = "func"
		size = "112"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 D5 41 54 55 48 89 CD 53 48 83 EC 08 83 FF 10 76 05 E8 ?? ?? ?? ?? 48 63 C7 48 8B 1C C5 ?? ?? ?? ?? 48 81 C3 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 85 ED 4C 8D 60 01 74 27 49 39 EC 76 14 48 8D 55 FF 48 89 DE 4C 89 EF E8 ?? ?? ?? ?? C6 00 00 EB 0E 4C 89 E2 48 89 DE 4C 89 EF E8 ?? ?? ?? ?? 41 5A 5B 5D 4C 89 E0 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule sigaction_07fbf8c1fc8892dc354696af8fb780dc {
	meta:
		aliases = "__GI_sigaction, sigaction"
		type = "func"
		size = "218"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 D5 41 54 55 48 89 F5 53 89 FB 48 81 EC A8 00 00 00 3B 3D ?? ?? ?? ?? 0F 84 A2 00 00 00 3B 3D ?? ?? ?? ?? 0F 84 96 00 00 00 3B 3D ?? ?? ?? ?? 75 08 85 FF 0F 8F 86 00 00 00 31 F6 48 85 ED 74 3E BA 98 00 00 00 48 89 EE 48 89 E7 E8 ?? ?? ?? ?? 48 83 7D 00 01 76 24 85 DB 7E 20 83 FB 40 7F 1B F6 85 88 00 00 00 04 74 0A 48 C7 04 24 ?? ?? ?? ?? EB 08 48 C7 04 24 ?? ?? ?? ?? 48 89 E6 4C 89 EA 89 DF E8 ?? ?? ?? ?? 83 F8 FF 74 3B 8D 43 FF 83 F8 3F 77 31 4D 85 ED 74 0F 48 63 C3 48 8B 04 C5 ?? ?? ?? ?? 49 89 45 00 48 85 ED 74 18 48 8B 45 00 48 63 D3 48 89 04 D5 ?? ?? ?? ?? EB 07 B8 16 00 00 00 }
	condition:
		$pattern
}

rule cplus_demangle_v3_components_2c74593871fb5890a883ba1f619f6026 {
	meta:
		aliases = "cplus_demangle_v3_components"
		type = "func"
		size = "317"
		objfiles = "cp_demint@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 D5 41 54 55 89 F5 53 48 89 FB 48 83 EC 68 E8 ?? ?? ?? ?? 80 3B 5F 0F 84 B8 00 00 00 40 F6 C5 10 41 BC 01 00 00 00 0F 84 CD 00 00 00 48 89 C2 48 89 E1 89 EE 48 89 DF E8 ?? ?? ?? ?? 48 63 44 24 2C 48 8D 3C 40 48 C1 E7 03 E8 ?? ?? ?? ?? 48 63 7C 24 3C 48 89 C3 48 89 44 24 20 48 C1 E7 03 E8 ?? ?? ?? ?? 48 85 DB 48 89 44 24 30 74 7E 48 85 C0 0F 84 AD 00 00 00 45 85 E4 74 40 48 89 E7 E8 ?? ?? ?? ?? 48 89 C3 83 E5 01 48 8B 7C 24 30 74 0A 48 8B 44 24 18 80 38 00 75 71 E8 ?? ?? ?? ?? 48 85 DB 74 6C 48 8B 44 24 20 49 89 45 00 48 89 D8 48 83 C4 68 5B 5D 41 5C 41 5D C3 BE 01 00 00 00 48 89 E7 }
	condition:
		$pattern
}

rule logwtmp_201af1682d9272c85058895a6eddf41a {
	meta:
		aliases = "logwtmp"
		type = "func"
		size = "167"
		objfiles = "logwtmp@libutil.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 D5 BA 90 01 00 00 41 54 49 89 FC 55 48 89 F5 31 F6 53 48 81 EC 98 01 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 85 ED 74 0B 80 7D 00 00 B8 07 00 00 00 75 05 B8 08 00 00 00 66 89 04 24 E8 ?? ?? ?? ?? 48 8D 7C 24 08 4C 89 E6 BA 1F 00 00 00 89 44 24 04 E8 ?? ?? ?? ?? 48 8D 7C 24 2C 48 89 EE BA 1F 00 00 00 E8 ?? ?? ?? ?? 48 8D 7C 24 4C BA FF 00 00 00 4C 89 EE E8 ?? ?? ?? ?? 48 8D BC 24 58 01 00 00 31 F6 E8 ?? ?? ?? ?? 48 89 E6 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 81 C4 98 01 00 00 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule xdrrec_getbytes_9898509f2caf9a3ff5b140fde4888101 {
	meta:
		aliases = "xdrrec_getbytes"
		type = "func"
		size = "110"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 41 89 D4 55 53 48 83 EC 08 48 8B 6F 18 EB 41 8B 45 68 85 C0 75 14 83 7D 70 00 75 40 48 89 EF E8 E8 FE FF FF 85 C0 75 28 EB 32 41 39 C4 89 C3 4C 89 EE 41 0F 46 DC 48 89 EF 89 DA E8 6D FE FF FF 85 C0 74 18 89 D8 48 29 45 68 41 29 DC 49 01 C5 45 85 E4 75 BA B8 01 00 00 00 EB 02 31 C0 41 5B 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule vswscanf_889bff707294fe44daffe2d1ce48272d {
	meta:
		aliases = "__GI_vswscanf, vswscanf"
		type = "func"
		size = "135"
		objfiles = "vswscanf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 49 89 D4 53 48 89 FB 48 83 C4 80 48 89 7C 24 18 48 89 7C 24 08 E8 ?? ?? ?? ?? 48 8D 04 83 48 8D 7C 24 58 48 89 5C 24 28 48 89 5C 24 30 C7 44 24 04 FD FF FF FF 48 89 44 24 10 48 89 44 24 20 66 C7 04 24 21 08 C6 44 24 02 00 C7 44 24 48 00 00 00 00 C7 44 24 50 01 00 00 00 E8 ?? ?? ?? ?? 4C 89 E2 4C 89 EE 48 89 E7 48 C7 44 24 38 00 00 00 00 E8 ?? ?? ?? ?? 48 83 EC 80 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule htab_traverse_noresize_f7f0e03eb8a17c41654bfd6ccda87f1d {
	meta:
		aliases = "htab_traverse_noresize"
		type = "func"
		size = "71"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 49 89 D4 55 53 48 83 EC 08 48 8B 5F 18 48 8B 47 20 48 8D 2C C3 EB 0B 66 90 48 83 C3 08 48 39 DD 76 13 48 83 3B 01 76 F1 4C 89 E6 48 89 DF 41 FF D5 85 C0 75 E4 48 83 C4 08 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule demangle_args_0f98bb460fa1c9c4b06716017dd14395 {
	meta:
		aliases = "demangle_args"
		type = "func"
		size = "744"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 49 89 D4 55 53 48 89 FB 48 83 EC 38 F6 07 01 0F 85 40 02 00 00 49 8B 55 00 0F B6 02 31 ED 3C 5F 0F 84 3C 01 00 00 84 C0 0F 84 34 01 00 00 3C 65 0F 84 2C 01 00 00 3C 54 90 74 08 3C 4E 0F 85 6E 01 00 00 48 8D 42 01 49 89 45 00 80 3A 4E 0F 84 C3 01 00 00 C7 04 24 01 00 00 00 F7 03 00 38 00 00 74 0A 83 7B 30 09 0F 8F 16 02 00 00 48 8D 74 24 04 4C 89 EF E8 7F BF FF FF 85 C0 0F 84 AF 01 00 00 8B 44 24 04 F7 03 00 3C 00 00 74 07 83 E8 01 89 44 24 04 85 C0 0F 88 94 01 00 00 39 43 30 7F 16 E9 8A 01 00 00 66 90 48 8B 7C 24 10 48 85 FF 75 6A BD 01 00 00 00 8B 73 68 85 F6 0F 8E 86 00 }
	condition:
		$pattern
}

rule md5_stream_dbac96527ba414addfba1a2167e9c023 {
	meta:
		aliases = "md5_stream"
		type = "func"
		size = "267"
		objfiles = "md5@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 49 89 FC 55 53 48 81 EC F8 10 00 00 C7 04 24 01 23 45 67 C7 44 24 04 89 AB CD EF C7 44 24 08 FE DC BA 98 C7 44 24 0C 76 54 32 10 C7 44 24 14 00 00 00 00 C7 44 24 10 00 00 00 00 C7 44 24 18 00 00 00 00 66 0F 1F 44 00 00 31 DB BD 00 10 00 00 EB 0C 0F 1F 80 00 00 00 00 48 85 C0 74 2B 48 8D 84 24 A0 00 00 00 48 89 EA 4C 89 E1 48 29 DA BE 01 00 00 00 48 8D 3C 18 E8 ?? ?? ?? ?? 48 01 C3 48 81 FB FF 0F 00 00 76 D0 48 85 C0 74 1B 48 8D BC 24 A0 00 00 00 48 89 E2 BE 00 10 00 00 E8 ?? ?? ?? ?? EB A4 0F 1F 40 00 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 89 C5 75 23 48 85 DB 49 89 E4 75 30 4C 89 }
	condition:
		$pattern
}

rule vwarn_work_a3d7a617488c5c85ce458bfd8ad4133a {
	meta:
		aliases = "vwarn_work"
		type = "func"
		size = "202"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 49 89 FC 55 53 BB ?? ?? ?? ?? 48 83 EC 68 85 D2 74 19 E8 ?? ?? ?? ?? 8B 38 48 89 E6 BA 40 00 00 00 BB ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 8B 68 50 85 ED 75 23 48 8D 7C 24 40 48 8D 50 58 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 83 C7 58 E8 ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 31 C0 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 4D 85 E4 74 16 48 8B 3D ?? ?? ?? ?? 4C 89 EA 4C 89 E6 48 83 EB 02 E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 31 C0 48 89 E2 48 89 DE E8 ?? ?? ?? ?? 85 ED 75 0F 48 8D 7C 24 40 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 68 5B 5D 41 5C 41 }
	condition:
		$pattern
}

rule __wcstofpmax_4b90fc16f01492875ead9fa845120172 {
	meta:
		aliases = "__wcstofpmax"
		type = "func"
		size = "578"
		objfiles = "__wcstofpmax@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 49 89 FC 55 89 D5 53 48 89 FB 48 83 EC 28 EB 04 48 83 C3 04 8B 3B E8 ?? ?? ?? ?? 85 C0 75 F1 8B 03 83 F8 2B 74 0D 45 31 C9 83 F8 2D 75 0C 41 B1 01 EB 03 45 31 C9 48 83 C3 04 D9 EE 31 F6 83 C9 FF D9 05 ?? ?? ?? ?? EB 2C 81 F9 00 00 00 80 83 D9 FF 85 C9 75 05 83 FA 30 74 16 FF C1 83 F9 15 7F 0F DC C9 8D 42 D0 89 44 24 80 DB 44 24 80 DE C2 48 83 C3 04 8B 13 4C 8B 15 ?? ?? ?? ?? 48 63 C2 41 F6 04 42 08 75 C1 83 FA 2E 75 0E 48 85 F6 75 09 48 83 C3 04 48 89 DE EB DA DD D8 85 C9 0F 89 A0 00 00 00 48 85 F6 0F 85 8F 00 00 00 44 8D 46 01 31 FF EB 49 FF C7 42 8D 04 07 48 98 80 B8 ?? }
	condition:
		$pattern
}

rule initstate_r_020337a058783133062e5378c36ae8c2 {
	meta:
		aliases = "__GI_initstate_r, initstate_r"
		type = "func"
		size = "185"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 55 48 89 CD 53 48 83 EC 08 48 83 FA 7F 76 0E 48 81 FA 00 01 00 00 19 DB 83 C3 04 EB 19 48 83 FA 1F 77 0A 31 DB 48 83 FA 07 77 0B EB 64 48 83 FA 40 19 DB 83 C3 02 48 63 C3 4D 8D 65 04 89 5D 18 48 63 14 85 ?? ?? ?? ?? 8B 04 85 ?? ?? ?? ?? 48 89 EE 4C 89 65 10 89 45 20 89 55 1C 49 8D 14 94 48 89 55 28 E8 ?? ?? ?? ?? 31 C0 85 DB 41 C7 45 00 00 00 00 00 74 33 48 8B 45 08 4C 29 E0 48 C1 F8 02 48 8D 04 80 8D 04 03 41 89 45 00 31 C0 EB 19 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 5F 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule getcwd_7084089976b4c209bf377e9961ac1e26 {
	meta:
		aliases = "__GI_getcwd, getcwd"
		type = "func"
		size = "197"
		objfiles = "getcwd@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 55 48 89 FD 53 48 83 EC 08 48 85 F6 75 2C 48 85 FF 74 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 8E 00 00 00 E8 ?? ?? ?? ?? BA 00 10 00 00 3D 00 10 00 00 0F 4D D0 48 63 DA EB 0B 48 85 FF 48 89 F3 49 89 FC 75 10 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 74 5F 49 89 C4 48 89 DE 4C 89 E7 B8 4F 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 85 DB 78 22 48 85 ED 75 2E 4D 85 ED 75 13 48 63 F3 4C 89 E7 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 75 16 4C 89 E5 EB 11 48 85 ED 75 0A 4C 89 E7 E8 ?? ?? ?? ?? EB 02 31 ED 5A 5B 48 89 E8 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule strerror_r_883c03c7479dd91154aea4c2c912e748 {
	meta:
		aliases = "__GI___xpg_strerror_r, __xpg_strerror_r, strerror_r"
		type = "func"
		size = "196"
		objfiles = "__xpg_strerror_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 55 53 48 89 D3 48 83 EC 48 83 FF 7C 77 20 89 F8 BD ?? ?? ?? ?? EB 0A 80 7D 00 01 83 D8 00 48 FF C5 85 C0 75 F2 45 31 E4 80 7D 00 00 75 30 48 63 F7 48 8D 7C 24 31 31 C9 BA F6 FF FF FF 41 BC 16 00 00 00 E8 ?? ?? ?? ?? 48 8D 68 F2 BA 0E 00 00 00 BE ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 4D 85 ED B8 00 00 00 00 48 89 EF 48 0F 44 D8 E8 ?? ?? ?? ?? 8D 50 01 48 63 C2 48 39 D8 B8 22 00 00 00 0F 47 D3 44 0F 47 E0 85 D2 74 17 48 63 DA 48 89 EE 4C 89 EF 48 89 DA E8 ?? ?? ?? ?? 42 C6 44 2B FF 00 45 85 E4 74 08 E8 ?? ?? ?? ?? 44 89 20 48 83 C4 48 44 89 E0 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule __encode_answer_dd2b90513cc210870f5ee3184e6be38d {
	meta:
		aliases = "__encode_answer"
		type = "func"
		size = "161"
		objfiles = "encodea@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 55 89 D5 53 48 89 FB 48 83 EC 08 48 8B 3F E8 ?? ?? ?? ?? 85 C0 41 89 C4 78 75 29 C5 8B 43 14 83 C0 0A 39 C5 7D 06 41 83 CC FF EB 63 0F B6 43 09 49 63 FC 49 8D 7C 3D 00 88 07 8B 43 08 88 47 01 0F B6 43 0D 88 47 02 8B 43 0C 88 47 03 0F B6 43 13 88 47 04 0F B6 43 12 88 47 05 0F B6 43 11 88 47 06 8B 43 10 88 47 07 0F B6 43 15 88 47 08 8B 43 14 88 47 09 48 63 53 14 48 83 C7 0A 48 8B 73 18 E8 ?? ?? ?? ?? 8B 43 14 83 C0 0A 41 01 C4 5A 5B 5D 44 89 E0 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule getspent_r_682c74159ccc7457f3e7bc40c12c8a6d {
	meta:
		aliases = "__GI_getgrent_r, __GI_getpwent_r, __GI_getspent_r, getgrent_r, getpwent_r, getspent_r"
		type = "func"
		size = "173"
		objfiles = "getgrent_r@libc.a, getspent_r@libc.a, getpwent_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 BE ?? ?? ?? ?? 41 54 49 89 FC 55 48 89 CD 53 48 89 D3 BA ?? ?? ?? ?? 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 C7 45 00 00 00 00 00 48 83 3D ?? ?? ?? ?? 00 75 2B BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 75 09 E8 ?? ?? ?? ?? 8B 18 EB 2B C7 40 50 01 00 00 00 4C 8B 05 ?? ?? ?? ?? 48 89 D9 4C 89 EA 4C 89 E6 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 89 C3 75 04 4C 89 65 00 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 89 D8 48 83 C4 28 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule fibheap_consolidate_ad063603114aa74c70d55f6b93c072e1 {
	meta:
		aliases = "fibheap_consolidate"
		type = "func"
		size = "431"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 31 C0 B9 41 00 00 00 41 54 55 53 48 81 EC 18 02 00 00 49 8B 5D 10 48 89 E7 49 89 E4 F3 48 AB 48 85 DB 0F 84 7B 01 00 00 49 8D 6D 10 0F 1F 80 00 00 00 00 48 89 DE 48 89 EF E8 5D FF FF FF 8B 73 30 81 E6 FF FF FF 7F 4C 63 C6 4A 8B 04 C4 48 85 C0 75 5E E9 9B 00 00 00 0F 1F 00 48 8B 52 10 48 8B 4A 18 48 39 CA 74 73 48 89 48 18 48 8B 4A 18 48 89 41 10 48 89 42 18 48 89 50 10 8B 53 30 83 C6 01 48 89 18 8D 4A 01 81 E2 00 00 00 80 81 E1 FF FF FF 7F 09 CA 89 53 30 80 60 33 7F 4A C7 04 C4 00 00 00 00 4C 63 C6 4A 8B 04 C4 48 85 C0 74 42 48 8B 78 20 48 39 7B 20 7E 09 48 89 C2 48 89 D8 48 89 }
	condition:
		$pattern
}

rule writetcp_62716c6eb7945641e80949ebebb33279 {
	meta:
		aliases = "writetcp"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "116"
		objfiles = "fgets_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 41 89 F4 55 48 89 D5 53 48 89 FB 48 83 EC 08 85 F6 7F 3D EB 4A 48 8B 45 18 48 3B 45 28 73 13 8A 10 48 FF C0 88 13 48 FF C3 80 FA 0A 48 89 45 18 EB 1C 48 89 EF E8 ?? ?? ?? ?? 83 F8 FF 75 08 F6 45 00 08 74 10 EB 18 88 03 48 FF C3 3C 0A 74 05 41 FF CC 75 C0 4C 39 EB 76 05 C6 03 00 EB 03 45 31 ED 5A 5B 5D 41 5C 4C 89 E8 41 5D C3 }
	condition:
		$pattern
}

rule _dl_fixup_5fd599812018fea04067f0a065bdb7eb {
	meta:
		aliases = "_dl_fixup"
		type = "func"
		size = "279"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 41 89 F4 55 53 48 83 EC 08 48 8B 7F 20 48 85 FF 74 0F E8 ?? ?? ?? ?? 85 C0 89 C5 0F 85 E4 00 00 00 49 8B 5D 00 BD 01 00 00 00 48 83 BB 08 01 00 00 00 66 8B 53 42 0F 85 C9 00 00 00 48 8B B3 B8 00 00 00 48 8B 83 C0 00 00 00 48 85 F6 74 4F 80 E2 01 75 4A 8B BB 90 01 00 00 41 89 C0 85 FF 74 29 89 F8 4C 8B 0B 48 8D 4E E8 4C 6B D0 18 48 83 C1 18 48 8B 41 10 48 8B 11 4C 01 C8 FF CF 4A 89 04 0A 75 EA 45 29 D0 4C 01 D6 44 89 C2 4C 89 EF E8 ?? ?? ?? ?? 66 83 4B 42 01 89 C5 EB 02 31 ED 48 83 BB 40 01 00 00 00 B8 02 00 00 00 44 0F 45 E0 48 83 BB 38 01 00 00 00 74 4A F6 43 42 02 74 0E }
	condition:
		$pattern
}

rule pthread_cleanup_upto_1bf2d43b3535bdde6b616b93b461c6e4 {
	meta:
		aliases = "pthread_cleanup_upto"
		type = "func"
		size = "171"
		objfiles = "ptlongjmp@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 41 BC ?? ?? ?? ?? 55 53 48 83 EC 08 48 3B 25 ?? ?? ?? ?? 48 89 E5 73 3B 48 3B 25 ?? ?? ?? ?? 72 0F 48 3B 25 ?? ?? ?? ?? 41 BC ?? ?? ?? ?? 72 23 83 3D ?? ?? ?? ?? 00 74 0A E8 ?? ?? ?? ?? 49 89 C4 EB 10 48 89 E8 48 0D FF FF 1F 00 4C 8D A0 01 FD FF FF 49 8B 5C 24 70 EB 13 48 39 EB 77 04 31 DB EB 15 48 8B 7B 08 FF 13 48 8B 5B 18 48 85 DB 74 06 49 3B 5D 30 72 E2 49 8B 84 24 A0 00 00 00 49 89 5C 24 70 48 85 C0 74 12 49 3B 45 30 73 0C 49 C7 84 24 A0 00 00 00 00 00 00 00 58 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule splay_tree_foreach_helper_3cd215c28e5b24ce5538048a9c82823a {
	meta:
		aliases = "splay_tree_foreach_helper"
		type = "func"
		size = "109"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 49 89 D4 55 48 89 CD 53 48 89 F3 48 83 EC 08 48 85 F6 75 1B EB 43 0F 1F 00 48 89 EE 48 89 DF 41 FF D4 85 C0 75 1F 48 8B 5B 18 48 85 DB 74 2A 48 8B 73 10 48 89 E9 4C 89 E2 4C 89 EF E8 B8 FF FF FF 85 C0 74 D4 48 83 C4 08 5B 5D 41 5C 41 5D C3 66 0F 1F 84 00 00 00 00 00 48 83 C4 08 31 C0 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule fwrite_unlocked_574a3e3121b84bd1c6f2fd61150c1b29 {
	meta:
		aliases = "__GI_fwrite_unlocked, fwrite_unlocked"
		type = "func"
		size = "128"
		objfiles = "fwrite_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 49 89 D4 55 48 89 F5 53 48 89 CB 48 83 EC 08 0F B7 01 25 C0 00 00 00 3D C0 00 00 00 74 11 BE 80 00 00 00 48 89 CF E8 ?? ?? ?? ?? 85 C0 75 40 48 85 ED 74 3B 4D 85 E4 74 36 48 83 C8 FF 31 D2 48 F7 F5 49 39 C4 77 19 4C 0F AF E5 48 89 DA 4C 89 EF 4C 89 E6 E8 ?? ?? ?? ?? 31 D2 48 F7 F5 EB 11 66 83 0B 08 E8 ?? ?? ?? ?? C7 00 16 00 00 00 31 C0 5A 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule remember_Btype_DOT_isra_DOT_2_ac24d39434c7ea8e9e0655550d5d0479 {
	meta:
		aliases = "remember_Btype.isra.2"
		type = "func"
		size = "73"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 49 89 F4 55 48 63 E9 53 48 63 DA 8D 7B 01 48 83 EC 08 48 63 FF E8 ?? ?? ?? ?? 48 89 DA 4C 89 E6 48 89 C7 E8 ?? ?? ?? ?? C6 04 18 00 49 89 C0 49 8B 45 00 4C 89 04 E8 48 83 C4 08 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule __stdio_fwrite_2c5de8fa3ee744520a9ca67180a80314 {
	meta:
		aliases = "__stdio_fwrite"
		type = "func"
		size = "259"
		objfiles = "_fwrite@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 49 89 F4 55 48 89 D5 53 48 83 EC 08 F6 42 01 02 0F 85 C6 00 00 00 83 7A 04 FE 48 8B 7A 18 48 8B 42 10 75 21 48 89 C3 48 29 FB 48 39 DE 48 0F 46 DE 4C 89 EE 48 89 DA E8 ?? ?? ?? ?? 48 01 5D 18 E9 AC 00 00 00 48 29 F8 48 39 C6 77 77 48 89 F2 4C 89 EE E8 ?? ?? ?? ?? 4C 01 65 18 F6 45 01 01 0F 84 8B 00 00 00 4C 89 E2 BE 0A 00 00 00 4C 89 EF E8 ?? ?? ?? ?? 48 85 C0 74 76 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 74 69 4C 39 E0 4C 89 E3 BE 0A 00 00 00 48 0F 46 D8 4C 89 E0 48 29 D8 48 89 DA 49 01 C5 4C 89 EF E8 ?? ?? ?? ?? 48 85 C0 48 89 C2 74 3E 49 8D 44 1D 00 48 29 D0 48 29 45 18 49 29 }
	condition:
		$pattern
}

rule lsearch_fd3c6b71d08545fa9e79ca0899fac8b5 {
	meta:
		aliases = "lsearch"
		type = "func"
		size = "67"
		objfiles = "lsearch@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 49 89 F4 55 48 89 D5 53 48 89 CB 48 83 EC 08 E8 ?? ?? ?? ?? 48 85 C0 75 1B 48 89 DF 48 89 DA 4C 89 EE 48 0F AF 7D 00 49 8D 3C 3C E8 ?? ?? ?? ?? 48 FF 45 00 5A 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule pex_child_error_DOT_isra_DOT_2_93ddf9a3883cd5377152a4ecaff76dd2 {
	meta:
		aliases = "pex_child_error.isra.2"
		type = "func"
		size = "221"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 49 89 F4 55 48 89 D5 53 89 CB 48 83 EC 08 E8 ?? ?? ?? ?? 4C 89 EE 48 89 C2 BF 02 00 00 00 E8 ?? ?? ?? ?? BA 18 00 00 00 BE ?? ?? ?? ?? BF 02 00 00 00 E8 ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? 4C 89 E6 48 89 C2 BF 02 00 00 00 E8 ?? ?? ?? ?? BA 03 00 00 00 BE ?? ?? ?? ?? BF 02 00 00 00 E8 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 48 89 EE 48 89 C2 BF 02 00 00 00 E8 ?? ?? ?? ?? BA 02 00 00 00 BE ?? ?? ?? ?? BF 02 00 00 00 E8 ?? ?? ?? ?? 89 DF E8 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 89 DF 48 89 C5 E8 ?? ?? ?? ?? 48 89 EA 48 89 C6 BF 02 00 00 00 E8 ?? ?? ?? ?? BF 02 00 00 00 BA 01 00 00 }
	condition:
		$pattern
}

rule svc_unregister_ea5aec2f1864be43794be61762f9d223 {
	meta:
		aliases = "__GI_svc_unregister, svc_unregister"
		type = "func"
		size = "101"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 49 89 F4 55 53 48 83 EC 18 48 8D 54 24 10 E8 66 FD FF FF 48 85 C0 48 89 C3 74 38 48 8B 44 24 10 48 8B 2B 48 85 C0 75 0E E8 ?? ?? ?? ?? 48 89 A8 F0 00 00 00 EB 03 48 89 28 48 89 DF 48 C7 03 00 00 00 00 E8 ?? ?? ?? ?? 4C 89 E6 4C 89 EF E8 ?? ?? ?? ?? 48 83 C4 18 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule fputws_unlocked_3c748e7412d1112442eb46642c4483cb {
	meta:
		aliases = "__GI_fputws_unlocked, fputws_unlocked"
		type = "func"
		size = "50"
		objfiles = "fputws_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 53 48 89 F3 E8 ?? ?? ?? ?? 48 89 DA 4C 89 EF 48 89 C6 49 89 C4 E8 ?? ?? ?? ?? 5B 4C 39 E0 41 5C 41 5D 0F 94 C0 0F B6 C0 FF C8 C3 }
	condition:
		$pattern
}

rule fputws_99a800bf3357b96d85730affeec177c2 {
	meta:
		aliases = "__GI_fputs, __GI_fputws, fputs, fputws"
		type = "func"
		size = "97"
		objfiles = "fputws@libc.a, fputs@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 55 48 89 F5 53 48 83 EC 28 44 8B 66 50 45 85 E4 75 1C 48 8D 5E 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 EE 4C 89 EF E8 ?? ?? ?? ?? 45 85 E4 89 C3 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule concat_copy_126b7fe96e04c57336d67e5c0f6d2d13 {
	meta:
		aliases = "concat_copy"
		type = "func"
		size = "179"
		objfiles = "concat@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 55 48 89 FD 53 48 89 F3 48 83 EC 58 48 85 F6 48 8D 84 24 80 00 00 00 48 89 54 24 30 48 89 4C 24 38 4C 89 44 24 40 4C 89 4C 24 48 48 89 44 24 10 48 8D 44 24 20 C7 44 24 08 10 00 00 00 48 89 44 24 18 75 1B EB 54 0F 1F 00 89 CA 48 03 54 24 18 83 C1 08 89 4C 24 08 48 8B 1A 48 85 DB 74 3B 48 89 DF E8 ?? ?? ?? ?? 48 89 EF 48 89 C2 48 89 DE 49 89 C4 E8 ?? ?? ?? ?? 8B 4C 24 08 4C 01 E5 83 F9 2F 76 C5 48 8B 54 24 10 48 8B 1A 48 8D 42 08 48 89 44 24 10 48 85 DB 75 C5 C6 45 00 00 48 83 C4 58 4C 89 E8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule strtosigno_5486667c55fc0be2449253edb2d6ad4f {
	meta:
		aliases = "strtoerrno, strtosigno"
		type = "func"
		size = "111"
		objfiles = "strerror@libiberty.a, strsignal@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 55 53 48 83 EC 08 48 85 FF 74 47 48 83 3D ?? ?? ?? ?? 00 74 4C 44 8B 25 ?? ?? ?? ?? 41 83 FC 00 7E 30 48 8B 2D ?? ?? ?? ?? 31 DB 66 0F 1F 44 00 00 48 8B 75 00 48 85 F6 74 0C 4C 89 EF E8 ?? ?? ?? ?? 85 C0 74 0E 83 C3 01 48 83 C5 08 44 39 E3 75 DF 31 DB 48 83 C4 08 89 D8 5B 5D 41 5C 41 5D C3 E8 23 FE FF FF EB AD }
	condition:
		$pattern
}

rule getenv_9846ab84a3ac04f412967f4e4fb1d964 {
	meta:
		aliases = "__GI_getenv, getenv"
		type = "func"
		size = "90"
		objfiles = "getenv@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 55 53 48 83 EC 08 48 8B 2D ?? ?? ?? ?? 48 85 ED 74 37 E8 ?? ?? ?? ?? 4C 63 E0 EB 24 4C 89 E2 48 89 DE 4C 89 EF E8 ?? ?? ?? ?? 85 C0 75 0E 4A 8D 04 23 80 38 3D 75 05 48 FF C0 EB 0F 48 83 C5 08 48 8B 5D 00 48 85 DB 75 D3 31 C0 5A 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule C_alloca_4830e97f38c4b79c593201445aec2a23 {
	meta:
		aliases = "C_alloca"
		type = "func"
		size = "229"
		objfiles = "alloca@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 55 53 48 83 EC 18 8B 05 ?? ?? ?? ?? 85 C0 0F 84 B5 00 00 00 48 8B 3D ?? ?? ?? ?? 44 8B 25 ?? ?? ?? ?? 48 8D 6C 24 0F 48 85 FF 74 7D 0F 1F 44 00 00 41 83 FC 00 7E 52 48 39 6F 08 77 54 4D 85 ED 48 89 3D ?? ?? ?? ?? 74 6E 49 8D 7D 10 E8 ?? ?? ?? ?? 48 85 C0 74 7C 48 8B 15 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 83 C0 10 48 89 50 F0 48 8D 54 24 0F 48 89 50 F8 48 83 C4 18 5B 5D 41 5C 41 5D C3 0F 1F 84 00 00 00 00 00 74 B2 48 39 6F 08 73 AC 48 8B 1F E8 ?? ?? ?? ?? 48 85 DB 74 0B 48 89 DF EB 8E 66 0F 1F 44 00 00 31 FF 4D 85 ED 48 89 3D ?? ?? ?? ?? 75 92 48 83 C4 18 31 C0 5B 5D 41 5C }
	condition:
		$pattern
}

rule tdelete_c6a08af3e01dd4401327163ce1615341 {
	meta:
		aliases = "tdelete"
		type = "func"
		size = "204"
		objfiles = "tdelete@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 55 53 48 89 D3 48 83 EC 08 48 85 F6 0F 84 A9 00 00 00 4C 8B 26 48 89 F5 4D 85 E4 EB 16 48 8D 68 08 49 89 C4 48 8D 40 10 85 D2 48 0F 49 E8 48 83 7D 00 00 0F 84 82 00 00 00 48 8B 45 00 4C 89 EF 48 8B 30 FF D3 83 F8 00 89 C2 48 8B 45 00 75 CD 48 8B 58 08 48 8B 48 10 48 85 DB 74 12 48 85 C9 74 47 48 8B 51 08 48 85 D2 75 0F 48 89 59 08 48 89 CB EB 35 48 89 C2 48 89 F1 48 8B 42 08 48 89 D6 48 85 C0 75 EE 48 8B 42 10 48 89 D3 48 89 41 08 48 8B 45 00 48 8B 40 08 48 89 42 08 48 8B 45 00 48 8B 40 10 48 89 42 10 48 8B 7D 00 E8 ?? ?? ?? ?? 4C 89 E0 48 89 5D 00 EB 02 31 C0 5A 5B 5D 41 }
	condition:
		$pattern
}

rule msync_0ce154178588923eeef54445e970974d {
	meta:
		aliases = "msync"
		type = "func"
		size = "68"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD BF 01 00 00 00 41 54 49 89 F4 53 89 D3 48 83 EC 10 48 8D 74 24 0C E8 ?? ?? ?? ?? 89 DA 4C 89 E6 4C 89 EF E8 ?? ?? ?? ?? 8B 7C 24 0C 31 F6 89 C3 E8 ?? ?? ?? ?? 5E 5F 89 D8 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule ether_hostton_af21c2daec834d12197a7c2f480bcbe5 {
	meta:
		aliases = "ether_hostton"
		type = "func"
		size = "130"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD BF ?? ?? ?? ?? 41 54 49 89 F4 BE ?? ?? ?? ?? 55 53 83 CB FF 48 81 EC 08 01 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 74 45 EB 23 4C 89 E6 48 89 E7 E8 88 FF FF FF 48 85 C0 48 89 C6 74 10 4C 89 EF E8 ?? ?? ?? ?? 85 C0 75 04 31 DB EB 18 48 89 EA BE 00 01 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 85 C0 75 C8 83 CB FF 48 89 EF E8 ?? ?? ?? ?? 48 81 C4 08 01 00 00 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule getresuid_3ae8953890bf70ef5acfc50131099116 {
	meta:
		aliases = "getresuid"
		type = "func"
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
		type = "func"
		size = "107"
		objfiles = "getresgid@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 B8 78 00 00 00 49 89 D5 41 54 49 89 F4 55 48 89 FD 53 48 83 EC 18 48 8D 54 24 0C 48 8D 74 24 10 48 8D 7C 24 14 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 85 DB 75 17 8B 44 24 14 89 45 00 8B 44 24 10 41 89 04 24 8B 44 24 0C 41 89 45 00 48 83 C4 18 89 D8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule __malloc_consolidate_4ee31d85b1a2d946327caa3286353d82 {
	meta:
		aliases = "__malloc_consolidate"
		type = "func"
		size = "407"
		objfiles = "free@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 BA 01 00 00 00 41 54 55 53 48 89 FB 48 83 EC 08 48 8B 07 48 85 C0 0F 84 01 01 00 00 83 E0 FD 4C 8D 5F 70 4C 8D 57 08 48 89 07 C1 E8 03 83 E8 02 4C 8D 6C C7 08 49 8B 0A 48 85 C9 0F 84 CE 00 00 00 49 C7 02 00 00 00 00 48 8B 41 08 4C 8B 61 10 49 89 C0 49 83 E0 FE A8 01 4A 8D 14 01 48 8B 6A 08 75 2B 4C 8B 09 48 89 C8 4C 29 C8 48 8B 78 10 48 8B 70 18 48 8B 4F 18 48 39 C1 75 41 48 39 4E 10 75 3B 4D 01 C8 48 89 77 18 48 89 7E 10 48 89 EF 48 83 E7 FC 48 3B 53 60 74 58 8B 44 17 08 48 89 7A 08 83 E0 01 85 C0 75 24 48 8B 72 10 48 8B 42 18 48 39 56 18 75 06 48 39 50 10 74 05 E8 ?? ?? ?? ?? 49 01 F8 }
	condition:
		$pattern
}

rule localtime_r_2ac701d4eaad5dd18386d8e83c136901 {
	meta:
		aliases = "__GI_localtime_r, localtime_r"
		type = "func"
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
		type = "func"
		size = "91"
		objfiles = "_time_mktime@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 BA ?? ?? ?? ?? 49 89 FD 41 54 53 89 F3 BE ?? ?? ?? ?? 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 DE 4C 89 EF BA ?? ?? ?? ?? E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 C3 48 89 E7 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 20 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule rewinddir_bca9c52ed9cb75b7433d9b15cecb197c {
	meta:
		aliases = "rewinddir"
		type = "func"
		size = "98"
		objfiles = "rewinddir@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 BE ?? ?? ?? ?? 41 54 4C 8D 67 30 53 4C 89 E2 48 89 FB 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? 8B 3B 31 D2 31 F6 E8 ?? ?? ?? ?? 48 C7 43 10 00 00 00 00 48 C7 43 08 00 00 00 00 BE 01 00 00 00 48 C7 43 20 00 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 83 C4 20 5B 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule fork_78c7efa20475e9f57db4645210a3d8b1 {
	meta:
		aliases = "__fork, fork"
		type = "func"
		size = "236"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 55 BF ?? ?? ?? ?? 41 54 55 53 48 83 EC 18 E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 4C 8B 2D ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? E8 BF FF FF FF E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 41 89 C4 75 74 BD ?? ?? ?? ?? 48 85 ED 74 56 48 89 E7 E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 48 89 E6 E8 ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? 48 85 ED 74 27 48 89 E7 E8 ?? ?? ?? ?? 31 F6 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 48 89 E6 E8 ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 89 EF EB 1C BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF }
	condition:
		$pattern
}

rule __fixunsxfti_0f24325c884fb3e55f0ea48966496a59 {
	meta:
		aliases = "__fixunsxfti"
		type = "func"
		size = "416"
		objfiles = "_fixunsxfdi@libgcc.a"
	strings:
		$pattern = { ( CC | 41 ) 55 D9 EE 31 C0 31 D2 41 54 48 83 EC 18 DB 6C 24 30 D9 C9 DF E9 0F 87 94 00 00 00 D8 0D ?? ?? ?? ?? D9 05 ?? ?? ?? ?? D9 C9 DB E9 0F 83 8E 00 00 00 DD D9 D9 7C 24 0E 0F B7 44 24 0E 80 CC 0C 66 89 44 24 0C D9 6C 24 0C DF 3C 24 D9 6C 24 0E 48 8B 0C 24 45 31 E4 48 89 CE 49 89 CD 4C 89 E7 E8 ?? ?? ?? ?? DB 6C 24 30 DE E1 D9 EE DF E9 0F 87 B3 00 00 00 D9 05 ?? ?? ?? ?? D9 C9 DB E9 73 73 DD D9 D9 7C 24 0E 0F B7 44 24 0E 80 CC 0C 66 89 44 24 0C D9 6C 24 0C DF 3C 24 D9 6C 24 0E 48 8B 0C 24 48 89 C8 31 D2 4C 01 E0 4C 11 EA EB 02 DD D8 48 83 C4 18 41 5C 41 5D C3 66 66 90 66 90 D9 7C 24 0E 0F B7 44 24 }
	condition:
		$pattern
}

rule fibheap_replace_key_data_04ebcb29e97bbffeb8afd81b748b2604 {
	meta:
		aliases = "fibheap_replace_key_data"
		type = "func"
		size = "186"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 56 31 C0 41 55 41 54 55 53 48 3B 56 20 48 89 F3 7F 7A 4C 8B 76 28 48 89 56 20 48 89 4E 28 48 8B 2E 74 66 48 85 ED 49 89 FD 74 54 48 3B 55 20 7F 4E 48 89 EA 48 89 DE E8 43 FA FF FF 4C 8B 65 00 4D 85 E4 74 32 80 7D 33 00 79 64 4C 89 E2 48 89 EE 4C 89 EF E8 26 FA FF FF 49 8B 04 24 48 85 C0 74 15 41 80 7C 24 33 00 4C 89 E5 79 42 49 89 C4 EB D9 0F 1F 44 00 00 48 8B 53 20 0F 1F 40 00 49 8B 45 08 48 39 50 20 7D 16 4C 89 F0 5B 5D 41 5C 41 5D 41 5E C3 66 2E 0F 1F 84 00 00 00 00 00 49 89 5D 08 EB E4 66 2E 0F 1F 84 00 00 00 00 00 80 4D 33 80 48 8B 53 20 EB C6 }
	condition:
		$pattern
}

rule xdr_pmaplist_24998e2acfa974889817c0725e936c86 {
	meta:
		aliases = "__GI_xdr_pmaplist, xdr_pmaplist"
		type = "func"
		size = "147"
		objfiles = "pmap_prot2@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 45 31 E4 55 48 89 FD 53 48 89 F3 48 83 EC 10 83 3F 02 4C 8D 74 24 0C 41 0F 94 C4 45 31 ED 31 C0 48 83 3B 00 4C 89 F6 48 89 EF 0F 95 C0 89 44 24 0C E8 ?? ?? ?? ?? 85 C0 74 46 83 7C 24 0C 00 75 07 B8 01 00 00 00 EB 3A 45 85 E4 74 07 4C 8B 2B 49 83 C5 20 B9 ?? ?? ?? ?? BA 28 00 00 00 48 89 DE 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 13 45 85 E4 74 05 4C 89 EB EB A7 48 8B 1B 48 83 C3 20 EB 9E 31 C0 5A 59 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule do_arg_dc57d2d2dd97959c23235fde88e823e9 {
	meta:
		aliases = "do_arg"
		type = "func"
		size = "382"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 49 89 FC 55 48 89 D5 53 48 89 F3 48 83 EC 10 4C 8B 2E 8B 47 68 0F 1F 44 00 00 85 C0 48 C7 45 10 00 00 00 00 48 C7 45 08 00 00 00 00 48 C7 45 00 00 00 00 00 7F 45 48 8B 03 80 38 6E 0F 85 C0 00 00 00 48 83 C0 01 48 89 DF 48 89 03 E8 79 C0 FF FF 85 C0 41 89 44 24 68 7E 7A 83 F8 09 0F 8F 87 00 00 00 48 C7 45 10 00 00 00 00 48 C7 45 08 00 00 00 00 48 C7 45 00 00 00 00 00 49 8B 74 24 60 83 E8 01 41 89 44 24 68 48 85 F6 74 47 48 8B 56 08 48 89 EF E8 01 C8 FF FF 48 83 C4 10 B8 01 00 00 00 5B 5D 41 5C 41 5D 41 5E C3 BF 18 00 00 00 E8 ?? ?? ?? ?? 49 89 44 24 60 49 89 C6 0F 1F 44 00 00 }
	condition:
		$pattern
}

rule demangle_template_value_parm_32153da1b0a4e3c5b4999ecfaa813127 {
	meta:
		aliases = "demangle_template_value_parm"
		type = "func"
		size = "1306"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 49 89 FC 55 48 89 D5 53 48 89 F3 48 83 EC 30 48 8B 36 0F B6 06 3C 59 0F 84 ED 00 00 00 83 F9 03 0F 84 5C 01 00 00 83 F9 05 74 37 83 F9 04 0F 84 96 00 00 00 83 F9 06 0F 84 7D 02 00 00 8D 51 FF 83 FA 01 0F 86 D1 01 00 00 B8 01 00 00 00 48 83 C4 30 5B 5D 41 5C 41 5D 41 5E C3 0F 1F 80 00 00 00 00 3C 6D 0F 84 30 03 00 00 BA 01 00 00 00 BE ?? ?? ?? ?? 48 89 EF E8 AE F4 FF FF 48 89 DF E8 A6 EE FF FF 31 D2 85 C0 7E 2F 48 8D 74 24 10 B2 01 48 89 EF 88 44 24 10 C6 44 24 11 00 E8 88 F4 FF FF BA 01 00 00 00 BE ?? ?? ?? ?? 48 89 EF E8 76 F4 FF FF BA 01 00 00 00 48 83 C4 30 89 D0 5B 5D 41 }
	condition:
		$pattern
}

rule rendezvous_request_224df30e55a0177dc2187f59edade860 {
	meta:
		aliases = "rendezvous_request"
		type = "func"
		size = "162"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 49 89 FC 55 53 48 81 EC 90 00 00 00 48 8B 6F 40 4C 8D AC 24 8C 00 00 00 C7 84 24 8C 00 00 00 6E 00 00 00 41 8B 3C 24 4C 89 EA 48 89 E6 E8 ?? ?? ?? ?? 85 C0 89 C3 79 0C E8 ?? ?? ?? ?? 83 38 04 75 48 EB D4 4C 8D 64 24 70 BA 10 00 00 00 31 F6 4C 89 E7 E8 ?? ?? ?? ?? 66 C7 44 24 70 01 00 8B 55 04 89 DF 8B 75 00 E8 0B FA FF FF 48 8D 78 14 BA 10 00 00 00 4C 89 E6 48 89 C3 E8 ?? ?? ?? ?? 8B 84 24 8C 00 00 00 89 43 10 48 81 C4 90 00 00 00 31 C0 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule htab_empty_000858554c5be1c837c6ada68b9c974a {
	meta:
		aliases = "htab_empty"
		type = "func"
		size = "107"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 49 89 FC 55 53 48 83 7F 10 00 4C 8B 6F 20 4C 8B 77 18 74 37 44 89 EB 83 EB 01 78 2F 48 63 C3 49 8D 2C C6 EB 0E 0F 1F 44 00 00 48 83 ED 08 83 EB 01 78 18 48 8B 7D 00 48 83 FF 01 76 ED 41 FF 54 24 10 48 83 ED 08 83 EB 01 79 E8 5B 5D 41 5C 4A 8D 14 ED 00 00 00 00 4C 89 F7 31 F6 41 5D 41 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svcudp_reply_fd5b6353166da58bbb29e3798fd3d8ce {
	meta:
		aliases = "svcudp_reply"
		type = "func"
		size = "545"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 49 89 FC 55 53 48 89 F3 31 F6 48 83 EC 10 4C 8B 6F 48 49 8B 45 18 49 8D 6D 10 41 C7 45 10 00 00 00 00 48 89 EF FF 50 28 49 8B 45 08 48 89 DE 48 89 EF 48 89 03 E8 ?? ?? ?? ?? 85 C0 0F 84 CC 01 00 00 49 8B 45 18 48 89 EF FF 50 20 49 8D 74 24 60 41 89 C6 49 8B 44 24 40 49 63 D6 48 83 7E 18 00 74 17 41 8B 3C 24 49 89 54 24 58 31 D2 49 89 44 24 50 E8 ?? ?? ?? ?? EB 18 45 8B 4C 24 10 41 8B 3C 24 4D 8D 44 24 14 31 C9 48 89 C6 E8 ?? ?? ?? ?? 44 39 F0 0F 85 73 01 00 00 49 83 BD D0 01 00 00 00 0F 84 9B 00 00 00 45 85 F6 0F 88 92 00 00 00 4D 8B 6C 24 48 49 8B AD D0 01 00 00 48 8B 55 18 }
	condition:
		$pattern
}

rule _stdio_init_330c8b492ddc0dfe154cbbedb6304f7d {
	meta:
		aliases = "_stdio_init"
		type = "func"
		size = "107"
		objfiles = "_stdio@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 53 BB 01 00 00 00 48 83 EC 08 E8 ?? ?? ?? ?? 31 FF 49 89 C5 44 8B 30 44 8B 25 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 DA BF 01 00 00 00 29 C2 89 D0 C1 E0 08 41 31 C4 66 44 89 25 ?? ?? ?? ?? 44 8B 25 ?? ?? ?? ?? E8 ?? ?? ?? ?? 29 C3 C1 E3 08 41 31 DC 66 44 89 25 ?? ?? ?? ?? 45 89 75 00 58 5B 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule floatformat_i387_ext_is_valid_796b6cade1ce5dd6b670a753f15be3a0 {
	meta:
		aliases = "floatformat_i387_ext_is_valid"
		type = "func"
		size = "94"
		objfiles = "floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 55 48 89 F5 53 44 8B 6F 04 48 89 FB 44 8B 27 8B 4F 0C 44 8B 47 10 48 89 EF 44 89 EA 44 89 E6 E8 06 FF FF FF 8B 4B 1C 44 89 EA 44 89 E6 48 89 EF 41 B8 01 00 00 00 49 89 C6 E8 EC FE FF FF 5B 48 85 C0 5D 0F 94 C2 4D 85 F6 41 5C 0F 95 C0 31 D0 41 5D 0F B6 C0 41 5E C3 }
	condition:
		$pattern
}

rule d_print_comp_d58674ddfc19805385b90a0225b15923 {
	meta:
		aliases = "d_print_comp"
		type = "func"
		size = "6813"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 55 48 89 F5 53 48 89 FB 48 81 EC 90 00 00 00 48 85 F6 48 8B 7F 08 0F 84 F6 01 00 00 48 85 FF 0F 84 45 01 00 00 8B 06 83 F8 32 0F 87 E2 01 00 00 89 C2 FF 24 D5 ?? ?? ?? ?? 90 48 8B 46 10 83 38 2F 0F 85 CB 01 00 00 48 8B 40 10 83 38 30 0F 85 BE 01 00 00 48 8B 43 10 48 3B 43 18 0F 83 58 16 00 00 48 8D 50 01 48 89 53 10 C6 04 07 28 48 8B 45 10 48 89 DF 48 8B 70 08 E8 7C FF FF FF 48 8B 43 08 48 85 C0 74 12 48 8B 53 10 48 8D 4A 02 48 3B 4B 18 0F 86 5D 18 00 00 BA 02 00 00 00 BE ?? ?? ?? ?? 48 89 DF E8 0F FE FF FF 48 8B 75 08 48 89 DF E8 B3 FE FF FF 48 8B 43 08 48 85 C0 74 12 48 8B }
	condition:
		$pattern
}

rule xdr_rmtcall_args_b4f04f0ad6ebbbc0641dfc934b875f16 {
	meta:
		aliases = "__GI_xdr_rmtcall_args, xdr_rmtcall_args"
		type = "func"
		size = "226"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 55 48 89 F5 53 48 89 FB 48 83 EC 10 E8 ?? ?? ?? ?? 85 C0 0F 84 B6 00 00 00 48 8D 75 08 48 89 DF E8 ?? ?? ?? ?? 85 C0 0F 84 A2 00 00 00 48 8D 75 10 48 89 DF E8 ?? ?? ?? ?? 85 C0 0F 84 8E 00 00 00 48 8B 43 08 48 89 DF 48 C7 44 24 08 00 00 00 00 FF 50 20 48 8D 74 24 08 48 89 DF 41 89 C6 E8 ?? ?? ?? ?? 85 C0 74 67 48 8B 43 08 48 89 DF FF 50 20 48 8B 75 20 41 89 C5 48 89 DF 31 C0 FF 55 28 85 C0 74 4A 48 8B 43 08 48 89 DF FF 50 20 44 89 EA 41 89 C4 89 C0 48 29 D0 44 89 F6 48 89 DF 48 89 45 18 48 8B 43 08 FF 50 28 48 8D 75 18 48 89 DF E8 ?? ?? ?? ?? 85 C0 74 14 48 8B 43 08 44 89 E6 }
	condition:
		$pattern
}

rule make_temp_file_ea5e1c7e36a60200441e09616d320f61 {
	meta:
		aliases = "make_temp_file"
		type = "func"
		size = "180"
		objfiles = "make_temp_file@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 55 48 89 FD 53 E8 ?? ?? ?? ?? 48 85 ED 49 89 C5 0F 84 84 00 00 00 48 89 EF E8 ?? ?? ?? ?? 41 89 C6 48 63 D8 4C 89 EF E8 ?? ?? ?? ?? 4C 63 E0 49 8D 7C 1C 09 E8 ?? ?? ?? ?? 4C 89 EE 48 89 C3 48 89 C7 E8 ?? ?? ?? ?? 4A 8D 04 23 48 BA 63 63 58 58 58 58 58 58 4A 8D 7C 23 08 48 89 EE 48 89 10 C6 40 08 00 E8 ?? ?? ?? ?? 44 89 F6 48 89 DF E8 ?? ?? ?? ?? 83 F8 FF 74 30 89 C7 E8 ?? ?? ?? ?? 85 C0 75 25 48 89 D8 5B 5D 41 5C 41 5D 41 5E C3 66 2E 0F 1F 84 00 00 00 00 00 31 DB 45 31 F6 BD ?? ?? ?? ?? E9 7B FF FF FF E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __ieee754_remainder_dc6ebd5f754a5c3ba5220753f0e298f3 {
	meta:
		aliases = "__ieee754_remainder"
		type = "func"
		size = "333"
		objfiles = "e_remainder@libm.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 55 53 48 83 EC 30 F2 0F 11 44 24 08 48 8B 44 24 08 F2 0F 11 4C 24 28 49 89 C6 41 89 C5 48 8B 44 24 28 49 C1 EE 20 48 89 C2 41 89 C4 48 C1 EA 20 89 D5 81 E5 FF FF FF 7F 89 E8 44 09 E0 74 24 44 89 F3 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7F 13 81 FD FF FF EF 7F 7E 1A 8D 85 00 00 10 80 44 09 E0 74 26 F2 0F 59 44 24 28 F2 0F 5E C0 E9 C8 00 00 00 81 FD FF FF DF 7F 7F 0F F2 0F 10 4C 24 28 F2 0F 58 C9 E8 ?? ?? ?? ?? 29 EB 45 29 E5 44 09 EB 75 0D F2 0F 59 05 ?? ?? ?? ?? E9 9A 00 00 00 E8 ?? ?? ?? ?? 0F 28 C8 F2 0F 10 44 24 28 F2 0F 11 4C 24 10 E8 ?? ?? ?? ?? 81 FD FF FF 1F 00 0F 28 D0 }
	condition:
		$pattern
}

rule __udivti3_ea1fd8efbaad64c90bfba969df975e09 {
	meta:
		aliases = "__udivti3"
		type = "func"
		size = "1368"
		objfiles = "_udivdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 55 53 48 89 74 24 F8 48 89 4C 24 E8 48 8B 74 24 E8 48 89 7C 24 F0 48 89 54 24 E0 48 8B 5C 24 F0 48 8B 7C 24 E0 4C 8B 44 24 F8 48 85 F6 0F 85 0A 01 00 00 4C 39 C7 0F 86 7F 01 00 00 BA 38 00 00 00 48 89 FE 89 D1 48 D3 EE 40 84 F6 75 09 48 83 EA 08 75 ED 48 89 FE B8 40 00 00 00 48 29 D0 48 8B 15 ?? ?? ?? ?? 0F B6 14 32 48 29 D0 74 25 89 C1 89 C2 48 89 DE 48 D3 E7 B9 40 00 00 00 29 C1 4C 89 C0 48 D3 EE 89 D1 48 D3 E0 49 89 F0 48 D3 E3 49 09 C0 48 89 FE 31 D2 4C 89 C0 48 C1 EE 20 49 89 FB 48 F7 F6 31 D2 41 83 E3 FF 49 89 C1 49 89 C2 4C 89 C0 48 F7 F6 48 89 D8 48 C1 E8 20 4D 0F AF }
	condition:
		$pattern
}

rule getwc_unlocked_522761e7ffb5a3ec92ad1891ff054bd8 {
	meta:
		aliases = "__GI_fgetwc_unlocked, fgetwc_unlocked, getwc_unlocked"
		type = "func"
		size = "303"
		objfiles = "fgetwc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 55 53 48 89 FB 48 83 EC 10 0F B7 07 25 03 08 00 00 3D 00 08 00 00 77 15 BE 00 08 00 00 83 CD FF E8 ?? ?? ?? ?? 85 C0 0F 85 EF 00 00 00 0F B7 03 A8 02 74 33 A8 01 75 06 83 7B 44 00 74 06 C6 43 02 00 EB 06 8A 43 03 88 43 02 8B 03 48 89 C2 FF C8 83 E2 01 66 89 03 8B 6C 93 40 C7 43 44 00 00 00 00 E9 A0 00 00 00 48 83 7B 08 00 75 11 48 8D 74 24 0F 48 89 DF E8 66 FF FF FF 48 FF 43 10 83 7B 48 00 75 04 C6 43 02 00 4C 8D 6B 48 48 8B 43 20 48 8B 73 18 41 89 C4 41 29 F4 74 3D 49 63 EC 4C 89 E9 48 89 E7 48 89 EA E8 ?? ?? ?? ?? 48 83 F8 00 48 89 C2 7C 15 B8 01 00 00 00 8B 2C 24 48 0F 44 }
	condition:
		$pattern
}

rule cplus_demangle_0cebf7f256873aaaff2556b3d80d7b91 {
	meta:
		aliases = "cplus_demangle"
		type = "func"
		size = "930"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 55 53 48 89 FB 48 83 EC 70 8B 15 ?? ?? ?? ?? 83 FA FF 0F 84 92 00 00 00 31 C0 B9 0E 00 00 00 48 89 E7 F7 C6 04 FF 00 00 48 89 E5 F3 48 AB 74 4A 89 34 24 F7 04 24 00 41 00 00 89 F2 75 50 F6 C2 04 0F 85 2B 01 00 00 80 E6 80 75 76 48 89 DE 48 89 EF E8 03 4D 00 00 48 89 EF 48 89 C3 E8 A8 F3 FF FF 48 89 D8 48 83 C4 70 5B 5D 41 5C 41 5D 41 5E C3 0F 1F 84 00 00 00 00 00 81 E2 04 FF 00 00 09 F2 89 14 24 F7 04 24 00 41 00 00 74 B0 89 D6 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 75 C8 8B 14 24 F6 C6 40 74 99 EB BE 0F 1F 00 E8 ?? ?? ?? ?? 48 83 C4 70 5B 5D 41 5C 41 5D 41 5E C3 66 0F 1F 44 00 00 }
	condition:
		$pattern
}

rule demangle_nested_args_2d8c4e2d1456b5b0aa9746e9016e14de {
	meta:
		aliases = "demangle_nested_args"
		type = "func"
		size = "129"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 55 53 83 47 5C 01 48 89 FB 4C 8B 6F 60 44 8B 67 68 48 C7 47 60 00 00 00 00 C7 47 68 00 00 00 00 E8 E5 FC FF FF 48 8B 6B 60 41 89 C6 48 85 ED 74 32 48 8B 7D 00 48 85 FF 74 21 E8 ?? ?? ?? ?? 48 C7 45 08 00 00 00 00 48 C7 45 10 00 00 00 00 48 C7 45 00 00 00 00 00 48 8B 6B 60 48 89 EF E8 ?? ?? ?? ?? 4C 89 6B 60 44 89 63 68 44 89 F0 83 6B 5C 01 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule svc_run_5c7f423553bbe7c59bad945c8607e614 {
	meta:
		aliases = "svc_run"
		type = "func"
		size = "213"
		objfiles = "svc_run@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 41 54 55 53 E8 ?? ?? ?? ?? 8B 18 49 89 C6 85 DB 75 0F E8 ?? ?? ?? ?? 48 83 38 00 0F 84 A7 00 00 00 48 63 FB 45 31 ED 48 C1 E7 03 E8 ?? ?? ?? ?? 48 89 C5 EB 33 E8 ?? ?? ?? ?? 48 8B 10 49 63 DD 41 FF C5 48 C1 E3 03 4C 8D 64 1D 00 8B 14 1A 41 89 14 24 48 8B 00 66 41 C7 44 24 06 00 00 8B 44 18 04 66 41 89 44 24 04 41 8B 06 41 39 C5 7C C5 48 63 F0 83 CA FF 48 89 EF E8 ?? ?? ?? ?? 83 F8 FF 89 C6 74 06 85 C0 74 32 EB 28 48 89 EF E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 38 04 0F 84 63 FF FF FF 5B 5D 41 5C 41 5D 41 5E BF ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? E9 }
	condition:
		$pattern
}

rule parse_printf_format_cb80a87d0d1601ca55402dc164f08c28 {
	meta:
		aliases = "parse_printf_format"
		type = "func"
		size = "277"
		objfiles = "parse_printf_format@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 45 31 ED 41 54 49 89 FC 55 48 89 D5 53 48 89 F3 48 89 FE 48 81 EC 00 01 00 00 48 89 E7 E8 ?? ?? ?? ?? 85 C0 0F 88 D4 00 00 00 8B 44 24 1C 85 C0 0F 8E BC 00 00 00 4C 63 E8 4C 39 EB 4C 89 E9 48 0F 46 CB 31 D2 EB 0E 8B 44 94 2C 48 FF C2 89 45 00 48 83 C5 04 48 39 CA 72 ED E9 9F 00 00 00 3C 25 0F 85 88 00 00 00 49 FF C4 41 80 3C 24 25 74 7E 48 89 E7 4C 89 24 24 E8 ?? ?? ?? ?? 81 7C 24 0C 00 00 00 80 4C 8B 24 24 75 16 49 FF C5 48 85 DB 74 0E C7 45 00 00 00 00 00 48 FF CB 48 83 C5 04 81 7C 24 08 00 00 00 80 75 16 49 FF C5 48 85 DB 74 0E C7 45 00 00 00 00 00 48 FF CB 48 83 C5 04 31 D2 EB }
	condition:
		$pattern
}

rule authunix_refresh_f46d1363507c182061fda52a9c05748c {
	meta:
		aliases = "authunix_refresh"
		type = "func"
		size = "235"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 45 31 ED 41 54 55 48 89 FD 53 48 83 EC 70 48 8B 5F 40 48 8B 43 08 48 39 47 08 0F 84 B7 00 00 00 48 FF 43 30 48 C7 44 24 38 00 00 00 00 4C 8D 74 24 30 48 C7 44 24 50 00 00 00 00 8B 53 10 B9 01 00 00 00 48 8B 73 08 48 89 E7 E8 ?? ?? ?? ?? 4C 89 F6 48 89 E7 E8 ?? ?? ?? ?? 85 C0 74 52 48 8D 7C 24 60 31 F6 E8 ?? ?? ?? ?? 48 8B 44 24 60 31 F6 48 89 E7 C7 04 24 00 00 00 00 48 89 44 24 30 48 8B 44 24 08 FF 50 28 4C 89 F6 48 89 E7 E8 ?? ?? ?? ?? 85 C0 41 89 C5 74 16 FC B9 06 00 00 00 48 89 EF 48 89 DE F3 A5 48 89 EF E8 CA FE FF FF 48 8D 74 24 30 48 89 E7 C7 04 24 02 00 00 00 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svc_getreqset_db6ad65ba65549bc107679ef7ede9434 {
	meta:
		aliases = "__GI_svc_getreqset, svc_getreqset"
		type = "func"
		size = "89"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 45 31 ED 41 54 55 53 48 89 FB 49 89 DC E8 ?? ?? ?? ?? 41 89 C6 EB 30 41 8B 2C 24 EB 17 8D 58 FF 42 8D 3C 2B E8 ?? ?? ?? ?? B8 01 00 00 00 88 D9 D3 E0 31 C5 89 EF E8 ?? ?? ?? ?? 85 C0 75 DE 49 83 C4 04 41 83 C5 20 45 39 F5 7C CB 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule readtcp_4fc041bc29e23e589c806e24a1d833c0 {
	meta:
		aliases = "readtcp"
		type = "func"
		size = "134"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 49 89 F5 41 54 41 89 D4 55 48 89 FD 53 48 83 EC 10 8B 1F BA B8 88 00 00 BE 01 00 00 00 48 89 E7 89 1C 24 66 C7 44 24 04 01 00 E8 ?? ?? ?? ?? 83 F8 FF 74 06 85 C0 74 31 EB 0A E8 ?? ?? ?? ?? 83 38 04 EB 0B 0F BF 44 24 06 A8 18 75 1C A8 20 75 18 F6 44 24 06 01 74 BB 49 63 D4 4C 89 EE 89 DF E8 ?? ?? ?? ?? 85 C0 7F 0D 48 8B 45 40 C7 00 00 00 00 00 83 C8 FF 5F 41 58 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule seekdir_9ace79e43e0cd385341ebdf68a71f1ae {
	meta:
		aliases = "seekdir"
		type = "func"
		size = "102"
		objfiles = "seekdir@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 49 89 F5 BE ?? ?? ?? ?? 41 54 4C 8D 67 30 53 4C 89 E2 48 89 FB 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? 8B 3B 4C 89 EE 31 D2 E8 ?? ?? ?? ?? 48 C7 43 08 00 00 00 00 48 89 43 20 BE 01 00 00 00 48 C7 43 10 00 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 83 C4 28 5B 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule writetcp_62fbc3b2dcb51a7eda8078c00264b270 {
	meta:
		aliases = "writetcp"
		type = "func"
		size = "91"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 49 89 FD 41 54 41 89 D4 55 48 89 F5 53 89 D3 EB 36 41 8B 7D 00 48 63 D3 48 89 EE E8 ?? ?? ?? ?? 83 F8 FF 49 89 C6 75 18 E8 ?? ?? ?? ?? 8B 00 45 89 F4 41 C7 45 30 03 00 00 00 41 89 45 38 EB 0B 29 C3 48 98 48 01 C5 85 DB 7F C6 5B 5D 44 89 E0 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule __parsespent_0d69872f44b717dba46a5519edbdd95b {
	meta:
		aliases = "__parsespent"
		type = "func"
		size = "158"
		objfiles = "__parsespent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 49 89 FD 41 54 45 31 E4 55 48 89 F5 53 48 83 EC 10 4C 8D 74 24 08 49 63 C4 41 83 FC 01 0F B6 80 ?? ?? ?? ?? 49 8D 5C 05 00 7F 17 48 89 2B BE 3A 00 00 00 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 75 3C EB 46 BA 0A 00 00 00 4C 89 F6 48 89 EF E8 ?? ?? ?? ?? 48 89 03 48 39 6C 24 08 75 07 48 C7 03 FF FF FF FF 41 83 FC 08 48 8B 44 24 08 75 09 31 D2 80 38 00 74 18 EB 11 80 38 3A 75 0C 48 8D 68 01 41 FF C4 C6 00 00 EB 8E BA 16 00 00 00 89 D0 5A 59 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule __parsepwent_50a221e5a5cb04ba8e310053bbe285ab {
	meta:
		aliases = "__parsepwent"
		type = "func"
		size = "149"
		objfiles = "__parsepwent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 49 89 FD 41 54 45 31 E4 55 53 48 89 F3 48 83 EC 10 4C 8D 74 24 08 49 63 C4 0F B6 80 ?? ?? ?? ?? 49 8D 6C 05 00 44 89 E0 83 E0 06 83 F8 02 74 1E 41 83 FC 06 48 89 5D 00 74 45 BE 3A 00 00 00 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 75 27 EB 35 BA 0A 00 00 00 4C 89 F6 48 89 DF E8 ?? ?? ?? ?? 48 89 C2 48 8B 44 24 08 48 39 D8 74 18 80 38 3A 75 13 89 55 00 48 8D 58 01 41 FF C4 C6 00 00 EB 97 31 C0 EB 03 83 C8 FF 5A 59 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule byte_group_match_null_string_p_caa67b78b838b47f4bacc575bdb6316b {
	meta:
		aliases = "byte_group_match_null_string_p"
		type = "func"
		size = "309"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 49 89 FD 41 54 49 89 F4 55 48 89 D5 53 48 83 EC 10 48 8B 07 4C 8D 74 24 08 48 83 C0 02 48 89 44 24 08 E9 ED 00 00 00 8A 02 3C 07 0F 84 C2 00 00 00 3C 0F 0F 85 C9 00 00 00 48 8D 42 01 48 89 44 24 08 0F BE 40 01 0F B6 4A 01 48 83 C2 03 48 89 54 24 08 C1 E0 08 89 C2 01 CA 79 5C E9 B3 00 00 00 48 8D 74 1F FD 48 89 EA E8 1F FF FF FF 84 C0 0F 84 AC 00 00 00 48 89 D9 48 03 4C 24 08 48 89 4C 24 08 80 39 0F 75 3F 48 8D 41 01 48 89 44 24 08 0F BE 40 01 0F B6 51 01 C1 E0 08 8D 14 10 48 8D 41 03 48 89 44 24 08 48 63 C2 80 3C 01 0E 74 07 48 89 4C 24 08 EB 0F 48 8B 7C 24 08 48 63 DA 80 7C 1F FD }
	condition:
		$pattern
}

rule __parsegrent_60f397b5bd983fc1306f1f3f3de44944 {
	meta:
		aliases = "__parsegrent"
		type = "func"
		size = "271"
		objfiles = "__parsegrent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 49 89 FD 41 54 55 31 ED 53 48 89 F3 48 83 EC 10 4C 8B 37 48 63 C5 83 FD 01 0F B6 80 ?? ?? ?? ?? 4D 8D 64 05 00 7F 25 49 89 1C 24 BE 3A 00 00 00 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 0F 84 BC 00 00 00 48 8D 58 01 FF C5 C6 00 00 EB C7 48 8D 74 24 08 BA 0A 00 00 00 48 89 DF E8 ?? ?? ?? ?? 41 89 04 24 48 8B 4C 24 08 48 39 D9 0F 84 8D 00 00 00 80 39 3A 0F 85 84 00 00 00 80 79 01 00 BE 01 00 00 00 74 33 C6 01 2C 80 39 2C 75 23 C6 01 00 48 FF C1 8A 01 84 C0 74 65 3C 2C 74 61 48 0F BE D0 48 8B 05 ?? ?? ?? ?? F6 04 50 20 75 50 FF C6 48 FF C1 80 39 00 75 D0 48 8D 51 08 48 63 C6 48 83 E2 F8 48 8D }
	condition:
		$pattern
}

rule __ieee754_lgamma_r_cc8f978f2628a6c90b80479683d83f71 {
	meta:
		aliases = "__ieee754_lgamma_r"
		type = "func"
		size = "2020"
		objfiles = "e_lgamma_r@libm.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 49 89 FD 41 54 55 53 48 83 EC 50 F2 0F 11 44 24 30 48 8B 44 24 30 C7 07 01 00 00 00 49 89 C6 49 C1 EE 20 44 89 F5 81 E5 FF FF FF 7F 81 FD FF FF EF 7F 7E 0C 0F 28 E8 F2 0F 59 E8 E9 90 07 00 00 41 89 C4 89 E8 44 09 E0 74 59 81 FD FF FF 8F 3B 7F 36 45 85 F6 79 16 C7 07 FF FF FF FF F2 0F 10 44 24 30 66 0F 57 05 ?? ?? ?? ?? EB 06 F2 0F 10 44 24 30 E8 ?? ?? ?? ?? 0F 28 E8 66 0F 57 2D ?? ?? ?? ?? E9 48 07 00 00 45 85 F6 78 0E 0F 57 C0 F2 0F 11 44 24 40 E9 F2 01 00 00 81 FD FF FF 2F 43 7E 15 F2 0F 10 2D ?? ?? ?? ?? F2 0F 5E 2D ?? ?? ?? ?? E9 18 07 00 00 48 8B 44 24 30 48 C1 E8 20 89 C3 81 }
	condition:
		$pattern
}

rule reconcat_cca5113a4253b222bed2d86f40ef700e {
	meta:
		aliases = "reconcat"
		type = "func"
		size = "371"
		objfiles = "concat@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 49 89 FD 41 54 55 53 48 89 F3 48 83 EC 50 48 85 F6 48 8D 84 24 80 00 00 00 48 89 54 24 30 48 89 4C 24 38 4C 89 44 24 40 4C 89 4C 24 48 48 89 44 24 10 48 8D 44 24 20 C7 44 24 08 10 00 00 00 48 89 44 24 18 0F 84 F4 00 00 00 49 89 C4 48 89 F7 31 ED EB 1C 0F 1F 84 00 00 00 00 00 89 C2 83 C0 08 4C 01 E2 89 44 24 08 48 8B 3A 48 85 FF 74 27 E8 ?? ?? ?? ?? 48 01 C5 8B 44 24 08 83 F8 2F 76 DB 48 8B 54 24 10 48 8B 3A 48 8D 42 08 48 89 44 24 10 48 85 FF 75 D9 48 8D 7D 01 E8 ?? ?? ?? ?? 49 89 C6 48 8D 84 24 80 00 00 00 C7 44 24 08 10 00 00 00 4C 89 F5 48 89 44 24 10 48 8D 44 24 20 48 89 44 24 }
	condition:
		$pattern
}

rule splay_tree_splay_6a939dc82ca532d03e0f8c796bd0cdd1 {
	meta:
		aliases = "splay_tree_splay"
		type = "func"
		size = "403"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 49 89 FD 41 54 55 53 48 8B 2F 48 85 ED 0F 84 4E 01 00 00 49 89 F6 66 0F 1F 44 00 00 48 8B 75 00 4C 89 F7 41 FF 55 08 85 C0 41 89 C4 0F 84 2F 01 00 00 48 8B 5D 18 48 0F 48 5D 10 48 85 DB 0F 84 1D 01 00 00 48 8B 33 4C 89 F7 41 FF 55 08 85 C0 0F 84 F6 00 00 00 78 5C 48 83 7B 18 00 0F 84 E9 00 00 00 44 89 E1 31 D2 C1 E9 1F 45 85 E4 40 0F 9F C6 85 C0 0F 9F C0 0F 8E 7F 00 00 00 40 84 F6 74 7A 48 8B 53 18 48 8B 42 10 48 89 5A 10 48 89 43 18 48 89 55 18 48 8B 42 10 48 89 6A 10 48 89 45 18 49 89 55 00 48 89 D5 E9 6E FF FF FF 66 0F 1F 44 00 00 48 8B 53 10 48 85 D2 0F 84 8B 00 00 00 44 89 E6 }
	condition:
		$pattern
}

rule sigwait_72c37297225ea27dd79d65707b6645b2 {
	meta:
		aliases = "sigwait"
		type = "func"
		size = "365"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 55 49 89 FD 41 54 55 BD 01 00 00 00 53 48 81 EC 10 02 00 00 48 89 74 24 08 E8 EA FD FF FF 48 8D 9C 24 80 01 00 00 48 89 84 24 08 02 00 00 48 89 DF 49 89 DE E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 4C 8D A4 24 E0 00 00 00 49 8D 5C 24 08 EB 6B 89 EE 4C 89 EF E8 ?? ?? ?? ?? 85 C0 74 5B 3B 2D ?? ?? ?? ?? 74 53 3B 2D ?? ?? ?? ?? 74 4B 3B 2D ?? ?? ?? ?? 74 43 89 EE 4C 89 F7 E8 ?? ?? ?? ?? 48 63 C5 48 83 3C C5 ?? ?? ?? ?? 01 77 2B 48 89 DF 48 C7 84 24 E0 00 00 00 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 D2 4C 89 E6 89 EF C7 84 24 68 01 00 00 00 00 00 00 E8 ?? ?? ?? ?? FF C5 83 FD 41 7E }
	condition:
		$pattern
}

rule pmap_set_b29de437835aa17c8cdd3e911eb9c42e {
	meta:
		aliases = "__GI_pmap_set, pmap_set"
		type = "func"
		size = "255"
		objfiles = "pmap_clnt@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 89 CE 41 55 41 89 D5 41 54 49 89 F4 55 48 89 FD 53 48 83 EC 50 48 8D 5C 24 30 C7 44 24 4C FF FF FF FF 48 89 DF E8 C6 FD FF FF 85 C0 0F 84 BB 00 00 00 48 8B 0D ?? ?? ?? ?? 4C 8B 05 ?? ?? ?? ?? 4C 8D 4C 24 4C 48 89 DF BA 02 00 00 00 BE A0 86 01 00 C7 44 24 08 90 01 00 00 C7 04 24 90 01 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 7F 49 63 C5 48 89 6C 24 10 4C 89 64 24 18 48 89 44 24 20 41 0F B7 C6 48 8D 4C 24 10 48 89 44 24 28 48 8B 05 ?? ?? ?? ?? 4C 8D 4C 24 48 4C 8B 53 08 41 B8 ?? ?? ?? ?? BA ?? ?? ?? ?? BE 01 00 00 00 48 89 DF 48 89 04 24 48 8B 05 ?? ?? ?? ?? 48 89 44 24 08 41 FF 12 85 }
	condition:
		$pattern
}

rule xdr_bytes_c13722e36fe9563f1cc5902c5d747de1 {
	meta:
		aliases = "__GI_xdr_bytes, xdr_bytes"
		type = "func"
		size = "177"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 89 CE 41 55 49 89 F5 41 54 49 89 FC 55 48 89 D5 53 48 8B 1E 48 89 D6 E8 ?? ?? ?? ?? 85 C0 74 7C 8B 6D 00 44 39 F5 76 07 41 83 3C 24 02 75 6D 41 8B 04 24 83 F8 01 74 09 72 36 83 F8 02 75 5D EB 44 85 ED 74 5B 48 85 DB 75 26 89 EF E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 49 89 45 00 75 13 48 8B 35 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 2C 48 89 DE 89 EA 4C 89 E7 5B 5D 41 5C 41 5D 41 5E E9 ?? ?? ?? ?? 48 85 DB 74 16 48 89 DF E8 ?? ?? ?? ?? 49 C7 45 00 00 00 00 00 EB 04 31 C0 EB 05 B8 01 00 00 00 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule sigqueue_e6c2d6292e87478751f61762a024ef4a {
	meta:
		aliases = "sigqueue"
		type = "func"
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
		type = "func"
		size = "423"
		objfiles = "error@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 89 FE 41 55 4D 89 C5 41 54 41 89 F4 55 89 CD 53 48 89 D3 0F B6 D0 48 8D 04 95 00 00 00 00 BA ?? ?? ?? ?? 48 81 EC D0 00 00 00 48 29 C2 48 8D 84 24 CF 00 00 00 4C 89 4C 24 48 FF E2 0F 29 78 F1 0F 29 70 E1 0F 29 68 D1 0F 29 60 C1 0F 29 58 B1 0F 29 50 A1 0F 29 48 91 0F 29 40 81 83 3D ?? ?? ?? ?? 00 74 35 39 0D ?? ?? ?? ?? 75 20 48 8B 3D ?? ?? ?? ?? 48 39 FB 0F 84 17 01 00 00 48 89 DE E8 ?? ?? ?? ?? 85 C0 0F 84 07 01 00 00 48 89 1D ?? ?? ?? ?? 89 2D ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 04 FF D0 EB 1A 48 8B 15 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? BE }
	condition:
		$pattern
}

rule pwrite_3a6bb03e40ba3b9614bb4ea107551310 {
	meta:
		aliases = "pread, pread64, pwrite"
		type = "func"
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
		type = "func"
		size = "82"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 89 FE BF 01 00 00 00 41 55 49 89 F5 41 54 49 89 D4 53 89 CB 48 83 EC 18 48 8D 74 24 14 E8 ?? ?? ?? ?? 89 D9 4C 89 E2 4C 89 EE 44 89 F7 E8 ?? ?? ?? ?? 8B 7C 24 14 48 89 C3 31 F6 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 18 5B 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule makefd_xprt_2fb508c4468481243f4756c45f9c646f {
	meta:
		aliases = "makefd_xprt"
		type = "func"
		size = "190"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 41 89 FE BF 50 01 00 00 41 55 41 89 F5 41 54 41 89 D4 55 53 E8 ?? ?? ?? ?? BF D0 01 00 00 48 89 C3 E8 ?? ?? ?? ?? 48 85 DB 48 89 C5 74 05 48 85 C0 75 25 48 8B 35 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 DF 31 DB E8 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? EB 58 48 8D 78 10 C7 00 02 00 00 00 41 B9 ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? 48 89 D9 44 89 E2 44 89 EE E8 ?? ?? ?? ?? 48 8D 45 40 48 C7 43 48 00 00 00 00 48 89 6B 40 C7 43 10 00 00 00 00 48 C7 43 08 ?? ?? ?? ?? 48 89 DF 48 89 43 30 66 C7 43 04 00 00 44 89 33 E8 ?? ?? ?? ?? 48 89 D8 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule put_field_1e219e19b7d7b362ca01b0e9408c6e19 {
	meta:
		aliases = "put_field"
		type = "func"
		size = "197"
		objfiles = "floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 56 42 8D 04 01 55 41 89 C2 41 C1 EA 03 85 F6 53 75 0C C1 EA 03 83 EA 01 44 29 D2 41 89 D2 83 E0 07 BA 01 00 00 00 44 89 D5 44 8D 58 F8 89 C1 48 01 FD D3 E2 41 0F B6 D9 41 F7 DB 83 EA 01 44 89 D9 D3 E2 48 D3 E3 F7 D2 22 55 00 09 DA 88 55 00 41 8D 52 01 41 83 EA 01 85 F6 BD 01 00 00 00 41 0F 45 D2 45 89 C2 41 29 C2 EB 38 0F 1F 40 00 44 89 D1 89 D3 41 89 EB 48 01 FB 41 D3 E3 4D 89 CE 41 F7 DB 44 22 1B 89 C1 49 D3 EE 45 09 F3 44 88 1B 8D 4A 01 83 C0 08 83 EA 01 85 F6 0F 44 D1 41 83 EA 08 41 39 C0 76 17 41 83 FA 07 76 C1 4C 89 CB 89 C1 41 89 D3 48 D3 EB 42 88 1C 1F EB D2 5B 5D 41 5E C3 }
	condition:
		$pattern
}

rule sgetspent_r_a0c2f17ef8f95076a07c053c3370a3ea {
	meta:
		aliases = "__GI_sgetspent_r, sgetspent_r"
		type = "func"
		size = "111"
		objfiles = "sgetspent_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 48 81 F9 FF 00 00 00 49 89 F6 49 C7 00 00 00 00 00 41 55 4D 89 C5 41 54 49 89 CC 55 48 89 D5 53 48 89 FB 77 12 E8 ?? ?? ?? ?? C7 00 22 00 00 00 B8 22 00 00 00 EB 2D 48 39 D7 74 15 E8 ?? ?? ?? ?? 4C 39 E0 73 DF 48 89 DE 48 89 EF E8 ?? ?? ?? ?? 48 89 EE 4C 89 F7 E8 ?? ?? ?? ?? 85 C0 75 04 4D 89 75 00 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule ___path_search_26b1372aa110591254fa66532499db20 {
	meta:
		aliases = "___path_search"
		type = "func"
		size = "219"
		objfiles = "tempname@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 48 85 C9 49 89 FE 41 55 49 89 F5 41 54 49 89 CC 55 53 48 89 D3 74 1D 80 39 00 74 18 48 89 CF E8 ?? ?? ?? ?? 48 83 F8 05 48 89 C5 76 12 BD 05 00 00 00 EB 0B 41 BC ?? ?? ?? ?? BD 04 00 00 00 48 85 DB 75 3B BF ?? ?? ?? ?? BB ?? ?? ?? ?? E8 4C FD FF FF 85 C0 75 28 48 89 DE 48 89 DF E8 ?? ?? ?? ?? 85 C0 74 0C 48 89 DF E8 31 FD FF FF 85 C0 75 0D E8 ?? ?? ?? ?? C7 00 02 00 00 00 EB 32 48 89 DF E8 ?? ?? ?? ?? 48 89 C2 EB 03 48 FF CA 48 83 FA 01 76 07 80 7C 1A FF 2F 74 F0 48 8D 44 15 08 49 39 C5 73 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 1A 4D 89 E1 49 89 E8 48 89 D9 BE ?? ?? ?? ?? 4C 89 }
	condition:
		$pattern
}

rule cplus_demangle_fill_builtin_ty_7a269aaa96b7082944141cb4f0112b6b {
	meta:
		aliases = "cplus_demangle_fill_builtin_type"
		type = "func"
		size = "139"
		objfiles = "cp_demint@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 56 48 85 FF 49 89 FE 41 55 41 54 55 53 74 70 48 85 F6 49 89 F5 74 68 48 89 F7 31 DB E8 ?? ?? ?? ?? 89 C5 EB 14 66 2E 0F 1F 84 00 00 00 00 00 48 83 C3 01 48 83 FB 1A 74 46 48 89 DA 41 89 DC 48 C1 E2 05 39 AA ?? ?? ?? ?? 75 E4 48 8B B2 ?? ?? ?? ?? 4C 89 EF E8 ?? ?? ?? ?? 85 C0 75 D1 5B 49 C1 E4 05 41 C7 06 21 00 00 00 B0 01 5D 49 81 C4 ?? ?? ?? ?? 4D 89 66 08 41 5C 41 5D 41 5E C3 5B 5D 41 5C 41 5D 31 C0 41 5E C3 }
	condition:
		$pattern
}

rule pthread_setschedparam_718b67d08448b839bf77a20b23b978f3 {
	meta:
		aliases = "__GI_pthread_setschedparam, pthread_setschedparam"
		type = "func"
		size = "166"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 56 48 89 F8 49 89 D6 25 FF 03 00 00 41 55 48 C1 E0 05 41 89 F5 31 F6 41 54 49 89 FC 55 48 8D A8 ?? ?? ?? ?? 53 48 89 EF E8 ?? ?? ?? ?? 48 8B 5D 10 48 85 DB 74 06 4C 39 63 20 74 4C 48 89 EF E8 ?? ?? ?? ?? B8 03 00 00 00 EB 51 48 89 EF E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 00 EB 40 31 C0 45 85 ED 74 03 41 8B 06 89 43 2C 48 89 EF E8 ?? ?? ?? ?? 31 C0 83 3D ?? ?? ?? ?? 00 78 20 8B 7B 2C E8 ?? ?? ?? ?? 31 C0 EB 14 8B 7B 28 4C 89 F2 44 89 EE E8 ?? ?? ?? ?? FF C0 75 C2 EB AF 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule memmem_958c52464163a033c0cff4e7784be3da {
	meta:
		aliases = "__GI_memmem, memmem"
		type = "func"
		size = "96"
		objfiles = "memmem@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 48 89 F8 49 89 D6 41 55 41 54 55 48 8D 2C 37 48 29 CD 48 85 C9 53 48 89 FB 74 3A 48 39 CE 73 26 EB 31 8A 03 41 3A 06 75 18 48 8D 7B 01 4C 89 EA 4C 89 E6 E8 ?? ?? ?? ?? 85 C0 75 05 48 89 D8 EB 14 48 FF C3 EB 08 4C 8D 69 FF 4C 8D 62 01 48 39 EB 76 CF 31 C0 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule xdr_reference_e389ec92d003100ccc5d4c167585a0d0 {
	meta:
		aliases = "__GI_xdr_reference, xdr_reference"
		type = "func"
		size = "149"
		objfiles = "xdr_reference@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 CE 41 55 49 89 F5 41 54 49 89 FC 55 89 D5 53 48 8B 1E 48 85 DB 75 48 8B 07 83 F8 01 74 0C 83 F8 02 BD 01 00 00 00 74 5E EB 35 89 D7 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 49 89 45 00 75 15 48 8B 35 ?? ?? ?? ?? BF ?? ?? ?? ?? 31 ED E8 ?? ?? ?? ?? EB 34 48 63 D5 31 F6 48 89 C7 E8 ?? ?? ?? ?? 83 CA FF 31 C0 48 89 DE 4C 89 E7 41 FF D6 41 83 3C 24 02 89 C5 75 10 48 89 DF E8 ?? ?? ?? ?? 49 C7 45 00 00 00 00 00 5B 89 E8 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule getprotoent_r_458c8eddeff22ca7d7d67225af11eea5 {
	meta:
		aliases = "__GI_getprotoent_r, getprotoent_r"
		type = "func"
		size = "451"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 CE 41 55 49 89 FD 41 54 49 89 F4 55 53 48 89 D3 48 83 EC 20 48 81 FA 17 01 00 00 48 C7 01 00 00 00 00 77 15 BB 22 00 00 00 E8 ?? ?? ?? ?? C7 00 22 00 00 00 E9 77 01 00 00 48 89 E7 BA ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 49 8D AC 24 18 01 00 00 E8 ?? ?? ?? ?? 48 8D 83 E8 FE FF FF 48 3D 00 10 00 00 77 15 BB 22 00 00 00 E8 ?? ?? ?? ?? C7 00 22 00 00 00 E9 22 01 00 00 48 83 3D ?? ?? ?? ?? 00 75 27 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 75 0C E8 ?? ?? ?? ?? 8B 18 E9 F1 00 00 00 48 8B 15 ?? ?? ?? ?? BE 00 10 00 00 48 89 EF E8 ?? ?? }
	condition:
		$pattern
}

rule __get_hosts_byaddr_r_843765afbfd4bbd6f3bfe8480a75db7d {
	meta:
		aliases = "__get_hosts_byaddr_r"
		type = "func"
		size = "138"
		objfiles = "get_hosts_byaddr_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 CE 41 55 4D 89 C5 41 54 4D 89 CC 55 89 D5 53 48 83 EC 50 83 FA 02 74 07 83 FA 0A 75 5A EB 05 83 FE 04 EB 03 83 FE 10 75 4E 48 8D 5C 24 20 48 89 FE B9 2E 00 00 00 89 EF 48 89 DA E8 ?? ?? ?? ?? 48 8B 84 24 88 00 00 00 4D 89 E9 4D 89 F0 B9 02 00 00 00 89 EA 48 89 DE 31 FF 4C 89 24 24 48 89 44 24 10 48 8B 84 24 80 00 00 00 48 89 44 24 08 E8 ?? ?? ?? ?? EB 02 31 C0 48 83 C4 50 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule pex_one_f6e0fef69a376f4061f99a9f910116cb {
	meta:
		aliases = "pex_one"
		type = "func"
		size = "149"
		objfiles = "pex_one@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 D6 31 D2 41 55 49 89 F5 48 89 CE 41 54 55 89 FD 31 FF 53 48 83 EC 20 4C 8B 64 24 58 4C 89 44 24 18 4C 89 4C 24 10 E8 ?? ?? ?? ?? 4C 8B 4C 24 10 4C 8B 44 24 18 89 EE 4C 89 24 24 4C 89 F1 4C 89 EA 48 89 C7 48 89 C3 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 74 18 48 89 DF E8 ?? ?? ?? ?? 48 83 C4 20 48 89 E8 5B 5D 41 5C 41 5D 41 5E C3 48 8B 54 24 50 BE 01 00 00 00 48 89 DF E8 ?? ?? ?? ?? 85 C0 75 D2 41 C7 04 24 00 00 00 00 BD ?? ?? ?? ?? EB C3 }
	condition:
		$pattern
}

rule _dl_add_elf_hash_table_506293f6c99d164ed1e5128a9f169750 {
	meta:
		aliases = "_dl_add_elf_hash_table"
		type = "func"
		size = "254"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 D6 41 55 49 89 CD 41 54 49 89 FC 55 48 89 F5 53 48 8B 1D ?? ?? ?? ?? 48 85 DB 75 2F BF C8 01 00 00 E8 ?? ?? ?? ?? BA C8 01 00 00 48 89 C3 48 89 05 ?? ?? ?? ?? EB 06 C6 00 00 48 FF C0 48 FF CA 48 83 FA FF 75 F1 EB 3B 48 89 C3 48 8B 43 18 48 85 C0 75 F4 BF C8 01 00 00 E8 ?? ?? ?? ?? BA C8 01 00 00 48 89 43 18 EB 06 C6 00 00 48 FF C0 48 FF CA 48 83 FA FF 75 F1 48 8B 43 18 48 89 58 20 48 89 C3 48 C7 43 18 00 00 00 00 66 C7 43 42 00 00 4C 89 E7 E8 ?? ?? ?? ?? 4C 89 6B 10 48 89 43 08 C7 43 30 03 00 00 00 49 8B 56 20 48 85 D2 74 1E 8B 02 89 43 50 8B 42 04 48 83 C2 08 48 89 53 58 89 43 70 }
	condition:
		$pattern
}

rule rwlock_have_already_8eb3acbd89d435d673fe7be35e062ac3 {
	meta:
		aliases = "rwlock_have_already"
		type = "func"
		size = "200"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 D6 41 55 49 89 CD 41 54 49 89 FC 55 48 89 F5 53 83 7E 30 01 48 8B 1F 74 09 31 D2 31 C9 E9 83 00 00 00 48 85 DB 75 08 E8 EE FE FF FF 48 89 C3 48 8B 93 E0 02 00 00 EB 09 48 39 6A 08 74 0A 48 8B 12 48 85 D2 75 F2 EB 05 48 85 D2 75 5C 83 BB F0 02 00 00 00 7F 53 48 8B 93 E8 02 00 00 48 85 D2 74 0C 48 8B 02 48 89 83 E8 02 00 00 EB 0D BF 18 00 00 00 E8 ?? ?? ?? ?? 48 89 C2 48 85 D2 74 1C C7 42 10 01 00 00 00 48 89 6A 08 48 8B 83 E0 02 00 00 48 89 02 48 89 93 E0 02 00 00 48 83 FA 01 19 C9 83 E1 01 31 C0 EB 07 31 C9 B8 01 00 00 00 41 89 4D 00 49 89 16 49 89 1C 24 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule vsnprintf_d8c5448065aed751b0f38b5ad7cdb1e0 {
	meta:
		aliases = "__GI_vsnprintf, vsnprintf"
		type = "func"
		size = "189"
		objfiles = "vsnprintf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 D6 41 55 49 89 CD 41 54 55 48 89 F5 53 48 89 FB 48 83 C4 80 48 8D 7C 24 58 C7 44 24 04 FE FF FF FF 66 C7 04 24 D0 00 C6 44 24 02 00 C7 44 24 48 00 00 00 00 C7 44 24 50 01 00 00 00 E8 ?? ?? ?? ?? 48 89 D8 4C 89 EA 4C 89 F6 48 F7 D0 48 89 E7 48 C7 44 24 38 00 00 00 00 48 39 C5 48 89 5C 24 08 48 89 5C 24 18 48 0F 47 E8 48 89 5C 24 20 48 89 5C 24 28 48 8D 04 2B 48 89 44 24 10 48 89 44 24 30 E8 ?? ?? ?? ?? 48 85 ED 89 C2 74 1C 48 8B 44 24 18 48 3B 44 24 10 75 08 48 FF C8 48 89 44 24 18 48 8B 44 24 18 C6 00 00 48 83 EC 80 89 D0 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule __pthread_alt_timedlock_7a493bff1975e8f17ff4af51352ecfac {
	meta:
		aliases = "__pthread_alt_timedlock"
		type = "func"
		size = "238"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 D6 41 55 49 89 F5 41 54 45 31 E4 55 48 89 FD BF ?? ?? ?? ?? 53 48 83 EC 10 E8 77 FC FF FF 48 8B 3D ?? ?? ?? ?? 48 85 FF 74 0D 48 8B 07 49 89 FC 48 89 05 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 4D 85 E4 75 1F BF 18 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 49 89 C4 75 0D 4C 89 EE 48 89 EF E8 ?? ?? ?? ?? EB 72 48 8B 5D 00 BA 01 00 00 00 48 85 DB 74 15 4D 85 ED 75 08 E8 70 FD FF FF 49 89 C5 4D 89 6C 24 08 4C 89 E2 41 C7 44 24 10 00 00 00 00 49 89 1C 24 48 89 D8 F0 48 0F B1 55 00 0F 94 C2 84 D2 74 C0 48 85 DB 74 25 4C 89 F6 4C 89 EF E8 ?? ?? ?? ?? 85 C0 75 16 B0 01 41 87 44 24 10 31 D2 48 85 }
	condition:
		$pattern
}

rule xdr_union_303f71a56feda0238f6d3bb24a25b9fd {
	meta:
		aliases = "__GI_xdr_union, xdr_union"
		type = "func"
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
		type = "func"
		size = "108"
		objfiles = "getgrouplist@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 D6 48 89 CA 41 55 41 89 F5 41 54 49 89 CC 55 53 8B 19 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 75 0E 85 DB 74 37 BB 01 00 00 00 45 89 2E EB 30 41 39 1C 24 41 0F 4E 1C 24 85 DB 74 12 48 63 D3 48 89 C6 4C 89 F7 48 C1 E2 02 E8 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 41 3B 1C 24 7D 03 83 CB FF 89 D8 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule sem_timedwait_e6b8ca8b133e7e78655407a96ce6f368 {
	meta:
		aliases = "sem_timedwait"
		type = "func"
		size = "362"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 41 54 49 89 FC 55 53 48 83 EC 10 E8 5A FF FF FF 4C 89 E7 48 89 C6 48 89 C5 E8 ?? ?? ?? ?? 41 8B 44 24 10 85 C0 7E 14 FF C8 4C 89 E7 41 89 44 24 10 E8 ?? ?? ?? ?? E9 1A 01 00 00 49 81 7E 08 FF C9 9A 3B 76 18 4C 89 E7 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 A7 00 00 00 4C 89 24 24 48 C7 44 24 08 ?? ?? ?? ?? 48 89 E6 C6 85 D2 02 00 00 00 48 89 EF E8 D0 FD FF FF 80 7D 7A 00 74 0B 80 7D 78 00 BB 01 00 00 00 74 0F 49 8D 7C 24 18 48 89 EE 31 DB E8 5D FD FF FF 4C 89 E7 4D 8D 6C 24 18 E8 ?? ?? ?? ?? 85 DB 74 0F 31 F6 48 89 EF E8 95 FD FF FF E9 8D 00 00 00 4C 89 F6 48 89 }
	condition:
		$pattern
}

rule _Unwind_Find_FDE_96b57a118ca1848a02a435289153efed {
	meta:
		aliases = "_Unwind_Find_FDE"
		type = "func"
		size = "311"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 41 54 55 53 48 89 FB 48 83 EC 10 48 8B 2D ?? ?? ?? ?? 48 85 ED 74 25 48 3B 7D 00 72 16 E9 E2 00 00 00 66 66 66 90 66 66 90 48 39 5D 00 0F 86 D1 00 00 00 48 8B 6D 28 48 85 ED 75 ED 4C 8D 2D ?? ?? ?? ?? 45 31 E4 66 66 90 48 8B 2D ?? ?? ?? ?? 48 85 ED 0F 84 9B 00 00 00 48 8B 45 28 48 89 DE 48 89 EF 48 89 05 ?? ?? ?? ?? E8 DA F8 FF FF 49 89 C4 48 8B 05 ?? ?? ?? ?? 4C 89 EA 48 85 C0 74 1D 48 8B 4D 00 48 39 08 73 07 EB 12 48 39 08 72 0D 48 8D 50 28 48 8B 40 28 48 85 C0 75 EE 4D 85 E4 48 89 45 28 48 89 2A 74 9F 48 8B 45 08 49 89 06 48 8B 45 10 49 89 46 08 0F B7 45 20 66 C1 E8 03 }
	condition:
		$pattern
}

rule xdrrec_putbytes_60fb8397b335a4c126a74d961201c172 {
	meta:
		aliases = "xdrrec_putbytes"
		type = "func"
		size = "119"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 41 89 D5 41 54 55 53 48 8B 6F 18 EB 50 48 8B 7D 20 48 8B 5D 28 4C 89 F6 29 FB 41 39 DD 41 0F 46 DD 41 89 DC 41 29 DD 4C 89 E2 4D 01 E6 E8 ?? ?? ?? ?? 4C 89 E0 48 03 45 20 48 3B 45 28 48 89 45 20 75 1A 45 85 ED 74 1A 31 F6 C7 45 38 01 00 00 00 48 89 EF E8 B4 FB FF FF 85 C0 74 0A 45 85 ED 75 AB B8 01 00 00 00 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule __md5_Update_6e3bf54a027568a97c9b7bbd93cdc957 {
	meta:
		aliases = "__md5_Update"
		type = "func"
		size = "169"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 41 89 D5 42 8D 14 ED 00 00 00 00 41 54 55 48 89 FD 53 8B 47 10 89 C1 8D 04 02 C1 E9 03 83 E1 3F 39 D0 89 47 10 73 03 FF 47 14 41 BC 40 00 00 00 44 89 E8 31 DB 41 29 CC C1 E8 1D 01 45 14 45 39 E5 72 40 48 8D 5D 18 89 CF 44 89 E2 4C 89 F6 48 8D 3C 3B E8 ?? ?? ?? ?? 48 89 DE 48 89 EF 44 89 E3 E8 3E FE FF FF EB 11 89 DE 48 89 EF 83 C3 40 49 8D 34 36 E8 2B FE FF FF 8D 43 3F 44 39 E8 72 E7 31 C9 44 89 EA 89 DE 89 C8 29 DA 48 8D 7C 05 18 49 8D 34 36 5B 5D 41 5C 41 5D 41 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule rtime_6e3efa3966109694c592a24f52000880 {
	meta:
		aliases = "__GI_rtime, rtime"
		type = "func"
		size = "372"
		objfiles = "rtime@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 49 89 D5 41 54 49 89 FC BF 02 00 00 00 55 53 48 83 EC 30 48 83 FA 01 19 DB 31 D2 83 C3 02 89 DE E8 ?? ?? ?? ?? 85 C0 89 C5 0F 88 2E 01 00 00 83 FB 02 66 41 C7 04 24 02 00 66 41 C7 44 24 02 00 25 0F 85 AC 00 00 00 48 8D 74 24 2C 31 C9 41 B9 10 00 00 00 4D 89 E0 BA 04 00 00 00 89 C7 E8 ?? ?? ?? ?? 85 C0 0F 88 9B 00 00 00 41 8B 4D 04 BE E8 03 00 00 31 D2 89 C8 F7 F6 89 C1 41 69 45 00 E8 03 00 00 4C 8D 6C 24 20 89 6C 24 20 66 C7 44 24 24 01 00 44 8D 24 01 44 89 E2 BE 01 00 00 00 4C 89 EF E8 ?? ?? ?? ?? 85 C0 89 C3 79 0A E8 ?? ?? ?? ?? 83 38 04 74 E0 83 FB 00 7F 0F 75 47 E8 ?? }
	condition:
		$pattern
}

rule vsscanf_5a53f87f19a37bad676689e46a1642e8 {
	meta:
		aliases = "__GI_vsscanf, vsscanf"
		type = "func"
		size = "148"
		objfiles = "vsscanf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 49 89 D5 41 54 53 48 89 FB 48 81 EC 88 00 00 00 48 8D 7C 24 58 C7 44 24 04 FE FF FF FF 66 C7 04 24 A1 00 C6 44 24 02 00 C7 44 24 48 00 00 00 00 C7 44 24 50 01 00 00 00 E8 ?? ?? ?? ?? 48 89 DF 48 89 5C 24 18 48 89 5C 24 08 48 C7 44 24 38 00 00 00 00 E8 ?? ?? ?? ?? 48 8D 04 03 4C 89 EA 4C 89 F6 48 89 E7 48 89 5C 24 30 48 89 44 24 10 48 89 44 24 20 48 89 44 24 28 E8 ?? ?? ?? ?? 48 81 C4 88 00 00 00 5B 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule vfwprintf_1b4a0da9ac32c6f2ec2007e197f5ab98 {
	meta:
		aliases = "__GI_vfwprintf, vfwprintf"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "502"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 49 89 FD 41 54 55 53 48 81 EC D0 00 00 00 E8 5C FE FF FF 48 89 84 24 C8 00 00 00 4C 89 E8 48 8B B4 24 C8 00 00 00 25 FF 03 00 00 48 C7 84 24 B8 00 00 00 ?? ?? ?? ?? 48 C1 E0 05 48 8D A8 ?? ?? ?? ?? 48 89 EF 48 89 AC 24 B0 00 00 00 E8 ?? ?? ?? ?? 48 8B 5D 10 48 85 DB 74 06 4C 39 6B 20 74 12 48 89 EF E8 ?? ?? ?? ?? B8 03 00 00 00 E9 6C 01 00 00 48 8B 84 24 C8 00 00 00 48 39 C3 75 12 48 89 EF E8 ?? ?? ?? ?? B8 23 00 00 00 E9 4D 01 00 00 80 7B 51 00 75 07 48 83 7B 68 00 74 12 48 89 EF E8 ?? ?? ?? ?? B8 16 00 00 00 E9 2E 01 00 00 80 7B 50 00 0F 85 CA 00 00 00 48 8B BC 24 C8 00 }
	condition:
		$pattern
}

rule clntraw_create_3e6de9bdc1acf135103cc30a59c5e911 {
	meta:
		aliases = "clntraw_create"
		type = "func"
		size = "250"
		objfiles = "clnt_raw@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 49 89 FD 41 54 55 53 48 83 EC 60 E8 ?? ?? ?? ?? 48 8B 98 C0 00 00 00 48 89 C5 48 85 DB 49 89 DC 75 24 BE C8 22 00 00 BF 01 00 00 00 E8 ?? ?? ?? ?? 31 D2 48 85 C0 0F 84 A7 00 00 00 49 89 C4 48 89 85 C0 00 00 00 48 8D 6B 18 49 8D B4 24 A8 22 00 00 31 C9 BA 18 00 00 00 C7 44 24 08 00 00 00 00 48 C7 44 24 10 02 00 00 00 48 89 EF 4C 89 6C 24 18 4C 89 74 24 20 E8 ?? ?? ?? ?? 48 89 E6 48 89 EF E8 ?? ?? ?? ?? 85 C0 75 0A BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 43 20 48 89 EF FF 50 20 41 89 84 24 C0 22 00 00 48 8B 43 20 48 8B 40 38 48 85 C0 74 05 48 89 EF FF D0 49 8D 74 24 48 BA 60 22 }
	condition:
		$pattern
}

rule get_input_bytes_a13f9394e8b4f11f59b72964414e0ceb {
	meta:
		aliases = "get_input_bytes"
		type = "func"
		size = "95"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 49 89 FD 41 54 55 89 D5 53 EB 3B 49 8B 75 58 49 8B 45 60 29 F0 75 0E 4C 89 EF E8 DF FD FF FF 85 C0 75 23 EB 2A 39 C5 41 89 C4 4C 89 F7 44 0F 4E E5 49 63 DC 44 29 E5 48 89 DA 49 01 DE E8 ?? ?? ?? ?? 49 01 5D 58 85 ED 7F C1 B8 01 00 00 00 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule pexecute_cb1f358b00284a115fdbed28eea0fd96 {
	meta:
		aliases = "pexecute"
		type = "func"
		size = "286"
		objfiles = "pexecute@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 4D 89 C5 41 54 4D 89 CC 55 48 89 FD 53 48 83 EC 20 8B 5C 24 50 F6 C3 01 0F 84 8B 00 00 00 48 83 3D ?? ?? ?? ?? 00 0F 85 A5 00 00 00 48 89 D6 BF 02 00 00 00 48 89 CA E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 48 89 05 ?? ?? ?? ?? 48 89 C7 41 89 DB D1 EB 48 8D 54 24 1C 41 D1 EB 89 DE 45 31 C9 41 83 E3 01 83 E6 02 48 89 14 24 44 09 DE 45 31 C0 4C 89 F1 48 89 EA E8 ?? ?? ?? ?? 48 85 C0 75 76 8B 05 ?? ?? ?? ?? 83 C0 01 89 05 ?? ?? ?? ?? 48 83 C4 20 5B 5D 41 5C 41 5D 41 5E C3 66 2E 0F 1F 84 00 00 00 00 00 48 8B 3D ?? ?? ?? ?? 48 85 FF 75 9B 49 C7 00 ?? ?? ?? ?? B8 FF FF FF FF }
	condition:
		$pattern
}

rule readdir_r_68e0d8674e022ae200db1850f148e77f {
	meta:
		aliases = "__GI_readdir64_r, __GI_readdir_r, readdir64_r, readdir_r"
		type = "func"
		size = "217"
		objfiles = "readdir_r@libc.a, readdir64_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 BE ?? ?? ?? ?? 41 55 49 89 D5 41 54 45 31 E4 55 48 89 FD 53 48 8D 5F 30 48 83 EC 20 48 89 DA 48 89 E7 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8B 45 08 48 39 45 10 77 35 48 8B 55 28 48 8B 75 18 8B 7D 00 E8 ?? ?? ?? ?? 48 83 F8 00 7F 13 49 C7 45 00 00 00 00 00 74 52 E8 ?? ?? ?? ?? 8B 18 EB 4B 48 89 45 10 48 C7 45 08 00 00 00 00 48 8B 45 08 49 89 C4 4C 03 65 18 41 0F B7 54 24 10 48 01 C2 48 89 55 08 49 8B 44 24 08 48 89 45 20 49 83 3C 24 00 74 99 41 0F B7 54 24 10 4C 89 E6 4C 89 F7 E8 ?? ?? ?? ?? 49 89 45 00 31 DB 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 4D 85 E4 B8 00 00 00 00 0F }
	condition:
		$pattern
}

rule readunix_d7b6431aede319fbb31e0400608c429a {
	meta:
		aliases = "readunix"
		type = "func"
		size = "293"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 FE 41 55 41 54 41 89 D4 55 48 89 F5 53 48 83 EC 60 8B 1F 4C 8D 6C 24 50 BA B8 88 00 00 BE 01 00 00 00 4C 89 EF 89 5C 24 50 66 C7 44 24 54 01 00 E8 ?? ?? ?? ?? 83 F8 FF 74 0A 85 C0 0F 84 C5 00 00 00 EB 0A E8 ?? ?? ?? ?? 83 38 04 EB 0F 0F BF 44 24 56 A8 18 0F 85 AC 00 00 00 A8 20 0F 85 A4 00 00 00 F6 44 24 56 01 74 AE 49 63 C4 48 8D 4C 24 5C 41 B8 04 00 00 00 48 89 44 24 48 48 8D 44 24 40 BA 10 00 00 00 BE 01 00 00 00 89 DF 48 89 6C 24 40 48 89 44 24 10 48 C7 44 24 18 01 00 00 00 48 C7 04 24 00 00 00 00 C7 44 24 08 00 00 00 00 48 C7 44 24 20 ?? ?? ?? ?? 48 C7 44 24 28 28 00 00 00 C7 }
	condition:
		$pattern
}

rule writeunix_bbe8805d2b99e77eeaf8f2b01992abf4 {
	meta:
		aliases = "writeunix"
		type = "func"
		size = "95"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 FE 41 55 41 89 D5 41 54 49 89 F4 55 89 D5 53 EB 3A 41 8B 3E 48 63 D5 4C 89 E6 E8 11 FF FF FF 83 F8 FF 89 C3 75 1E E8 ?? ?? ?? ?? 8B 00 41 89 DD 41 C7 86 90 00 00 00 03 00 00 00 41 89 86 98 00 00 00 EB 0B 29 C5 48 98 49 01 C4 85 ED 7F C2 5B 5D 41 5C 44 89 E8 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule svc_getreq_poll_4b18ab2a51e1e678d6f1986420989116 {
	meta:
		aliases = "__GI_svc_getreq_poll, svc_getreq_poll"
		type = "func"
		size = "109"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 FE 41 55 41 89 F5 41 54 45 31 E4 55 31 ED 53 EB 41 48 63 C5 49 8D 04 C6 8B 18 83 FB FF 74 31 66 8B 40 06 66 85 C0 74 28 41 FF C4 A8 20 74 1A E8 ?? ?? ?? ?? 48 8B 80 E8 00 00 00 48 63 D3 48 8B 3C D0 E8 ?? ?? ?? ?? EB 07 89 DF E8 ?? ?? ?? ?? FF C5 E8 ?? ?? ?? ?? 3B 28 7D 05 45 39 EC 7C B1 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule fgetws_e4126582bb8394683ceec76b3d52a7ff {
	meta:
		aliases = "__GI_fgets, fgets, fgetws"
		type = "func"
		size = "109"
		objfiles = "fgets@libc.a, fgetws@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 FE 41 55 41 89 F5 41 54 55 48 89 D5 53 48 83 EC 20 44 8B 62 50 45 85 E4 75 1C 48 8D 5A 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 EA 44 89 EE 4C 89 F7 E8 ?? ?? ?? ?? 45 85 E4 48 89 C3 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 48 89 D8 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule pthread_create_e11e1e21b5f622193748f5002d72dea2 {
	meta:
		aliases = "pthread_create"
		type = "func"
		size = "178"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 FE 41 55 49 89 CD 41 54 49 89 D4 55 53 48 89 F3 48 81 EC B0 00 00 00 83 3D ?? ?? ?? ?? 00 79 0E E8 ?? ?? ?? ?? 85 C0 BA 0B 00 00 00 78 6E E8 AD F8 FF FF 48 8D 54 24 28 31 F6 BF 02 00 00 00 48 89 C5 48 89 04 24 C7 44 24 08 00 00 00 00 48 89 5C 24 10 4C 89 64 24 18 4C 89 6C 24 20 E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? BA A8 00 00 00 48 89 E6 E8 ?? ?? ?? ?? 48 FF C0 75 0A E8 ?? ?? ?? ?? 83 38 04 74 DE 48 89 EF E8 39 FA FF FF 83 7D 60 00 75 07 48 8B 45 58 49 89 06 8B 55 60 48 81 C4 B0 00 00 00 89 D0 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule lfind_d2840f5b0fbdbcb1191f05edd54aeced {
	meta:
		aliases = "__GI_lfind, lfind"
		type = "func"
		size = "66"
		objfiles = "lfind@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 FE 41 55 49 89 CD 41 54 4D 89 C4 55 48 89 F5 53 8B 1A EB 15 48 89 EE 4C 89 F7 41 FF D4 85 C0 75 05 48 89 EE EB 0C 4C 01 ED FF CB 83 FB FF 75 E4 31 F6 5B 5D 41 5C 41 5D 41 5E 48 89 F0 C3 }
	condition:
		$pattern
}

rule gethostent_r_40cf1c70c26b8a04ffeb403c8310afb5 {
	meta:
		aliases = "__GI_gethostent_r, gethostent_r"
		type = "func"
		size = "206"
		objfiles = "gethostent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 FE 41 55 49 89 F5 BE ?? ?? ?? ?? 41 54 49 89 D4 BA ?? ?? ?? ?? 55 4C 89 C5 53 48 89 CB 48 83 EC 40 48 8D 7C 24 20 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 3D ?? ?? ?? ?? 00 75 1F E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 75 0E 48 C7 03 00 00 00 00 BB 02 00 00 00 EB 4E 48 8B 3D ?? ?? ?? ?? 31 F6 4D 89 E9 4D 89 F0 B9 01 00 00 00 BA 02 00 00 00 48 89 5C 24 08 48 89 6C 24 10 4C 89 24 24 E8 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 89 C3 75 17 48 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 48 8D 7C 24 20 BE 01 00 00 00 E8 ?? ?? ?? ?? 89 D8 48 83 C4 40 5B 5D 41 }
	condition:
		$pattern
}

rule demangle_template_template_par_e09da42f8f4ae6e091eab025e6108742 {
	meta:
		aliases = "demangle_template_template_parm"
		type = "func"
		size = "362"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 FE 48 89 D7 41 55 49 89 D5 41 54 49 89 F4 BE ?? ?? ?? ?? 55 BD 01 00 00 00 53 48 83 EC 30 E8 C9 C8 FF FF 48 8D 74 24 0C 4C 89 E7 E8 BC C2 FF FF 85 C0 74 18 8B 44 24 0C 31 DB 85 C0 0F 8F 9C 00 00 00 66 2E 0F 1F 84 00 00 00 00 00 49 8B 45 08 80 78 FF 3E 0F 84 C1 00 00 00 4C 89 EF BE ?? ?? ?? ?? E8 85 C8 FF FF 48 83 C4 30 89 E8 5B 5D 41 5C 41 5D 41 5E C3 66 0F 1F 44 00 00 48 8D 54 24 10 4C 89 E6 4C 89 F7 E8 10 E5 FF FF 85 C0 89 C5 0F 85 9E 00 00 00 48 8B 7C 24 10 48 85 FF 74 20 E8 ?? ?? ?? ?? 48 C7 44 24 18 00 00 00 00 48 C7 44 24 20 00 00 00 00 48 C7 44 24 10 00 00 00 00 85 ED 74 47 }
	condition:
		$pattern
}

rule __stdio_WRITE_81ea020b2b017d5d65edfa8ff545eabd {
	meta:
		aliases = "__stdio_WRITE"
		type = "func"
		size = "150"
		objfiles = "_WRITE@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 BE FF FF FF FF FF FF FF 7F 41 55 49 89 D5 41 54 49 89 F4 55 48 89 FD 53 48 89 D3 48 83 FB 00 74 66 8B 7D 04 4C 89 F2 4C 89 E6 48 0F 4D D3 E8 ?? ?? ?? ?? 48 85 C0 78 08 48 29 C3 49 01 C4 EB DB 48 8B 55 08 48 8B 45 10 66 83 4D 00 08 48 29 D0 74 32 48 39 D8 48 89 C1 48 0F 47 CB 41 8A 04 24 3C 0A 88 02 75 06 F6 45 01 01 75 0D 48 FF C2 48 FF C9 74 05 49 FF C4 EB E3 48 89 55 18 48 2B 55 08 48 29 D3 49 29 DD 5B 5D 41 5C 4C 89 E8 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule pthread_setspecific_2114a2709e7824f90d89b23f6167f486 {
	meta:
		aliases = "pthread_setspecific"
		type = "func"
		size = "139"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 56 81 FF FF 03 00 00 49 89 F6 41 55 41 54 55 89 FD 53 77 66 89 F8 48 C1 E0 04 83 B8 ?? ?? ?? ?? 00 74 57 41 89 ED 41 C1 ED 05 45 89 EC E8 0E FE FF FF 4A 83 BC E0 48 01 00 00 00 48 89 C3 75 21 BE 08 00 00 00 BF 20 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 BA 0C 00 00 00 74 26 4A 89 84 E3 48 01 00 00 44 89 E8 48 89 EA 48 8B 84 C3 48 01 00 00 83 E2 1F 4C 89 34 D0 31 D2 EB 05 BA 16 00 00 00 5B 5D 41 5C 41 5D 41 5E 89 D0 C3 }
	condition:
		$pattern
}

rule _uintmaxtostr_368d5c14b53ec9035d523f08a09513e0 {
	meta:
		aliases = "_uintmaxtostr"
		type = "func"
		size = "201"
		objfiles = "_uintmaxtostr@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 85 D2 41 89 D1 41 55 41 54 55 89 CD 53 79 13 41 F7 D9 48 85 F6 79 0B 48 F7 DE 41 BC 01 00 00 00 EB 03 45 31 E4 83 C8 FF 31 D2 C6 07 00 41 F7 F1 44 8D 5A 01 89 C3 45 39 CB 75 05 FF C3 45 31 DB 49 89 F2 41 89 F0 49 C1 EA 20 45 85 D2 74 3B 44 89 D0 31 D2 41 F7 F1 41 89 D5 41 89 D6 41 89 C2 31 D2 44 89 C0 41 F7 F1 45 0F AF F3 89 D1 89 C6 31 D2 41 8D 04 0E 44 0F AF EB 41 F7 F1 41 8D 74 35 00 44 8D 04 06 89 D1 EB 0D 44 89 C0 31 D2 41 F7 F1 89 D1 41 89 C0 8D 41 30 8D 14 29 48 FF CF 83 F9 09 0F 47 C2 88 07 44 89 C0 44 09 D0 75 9A 45 85 E4 74 06 48 FF CF C6 07 2D 5B 5D 41 5C 41 5D 41 5E 48 89 F8 }
	condition:
		$pattern
}

rule regcomp_095453f71b23153ef4ee4dd3aa34a3b4 {
	meta:
		aliases = "__regcomp, regcomp"
		type = "func"
		size = "324"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 89 D0 49 89 F6 83 E0 01 41 55 83 F8 01 41 54 41 89 D4 55 48 19 ED 81 E5 CA 4F FD 00 53 48 89 FB 48 C7 07 00 00 00 00 48 C7 47 08 00 00 00 00 48 C7 47 10 00 00 00 00 BF 00 01 00 00 E8 ?? ?? ?? ?? 48 81 C5 FC B2 03 00 41 F6 C4 02 48 89 43 20 74 56 BF 00 01 00 00 41 BD 0C 00 00 00 E8 ?? ?? ?? ?? 31 F6 48 85 C0 48 89 43 28 75 31 E9 C4 00 00 00 48 63 C6 48 8B 7B 28 40 88 F2 48 8D 0C 00 48 8B 05 ?? ?? ?? ?? F6 04 08 01 74 0A 48 8B 05 ?? ?? ?? ?? 8A 14 08 89 F0 FF C6 88 14 07 81 FE FF 00 00 00 76 CC EB 08 48 C7 43 28 00 00 00 00 41 F6 C4 04 8A 43 38 74 10 48 83 E5 BF 83 C8 80 48 81 CD 00 01 00 }
	condition:
		$pattern
}

rule __decode_question_562f4f640afb444f70b7066ef709b31f {
	meta:
		aliases = "__decode_question"
		type = "func"
		size = "123"
		objfiles = "decodeq@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 B9 00 01 00 00 41 55 41 89 F5 41 54 49 89 D4 55 48 89 FD 53 48 81 EC 00 01 00 00 48 89 E2 E8 ?? ?? ?? ?? 85 C0 89 C3 78 3E 48 89 E7 E8 ?? ?? ?? ?? 42 8D 0C 2B 49 89 04 24 83 C3 04 48 63 C9 0F B6 44 0D 00 0F B6 54 29 01 C1 E0 08 09 D0 41 89 44 24 08 0F B6 44 29 02 0F B6 54 29 03 C1 E0 08 09 D0 41 89 44 24 0C 48 81 C4 00 01 00 00 89 D8 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule vasprintf_df0db35718ece34fb16f524a1418a9f1 {
	meta:
		aliases = "__GI_vasprintf, vasprintf"
		type = "func"
		size = "146"
		objfiles = "vasprintf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 B9 06 00 00 00 49 89 F6 FC 41 55 48 89 D6 49 89 FD 41 54 55 48 89 D5 4C 89 F2 53 48 83 EC 30 48 8D 44 24 10 48 89 C7 F3 A5 31 F6 31 FF 48 89 C1 E8 ?? ?? ?? ?? 85 C0 89 C3 49 C7 45 00 00 00 00 00 78 3E FF C3 4C 63 E3 4C 89 E7 E8 ?? ?? ?? ?? 48 85 C0 48 89 C7 49 89 45 00 74 25 48 89 E9 4C 89 F2 4C 89 E6 E8 ?? ?? ?? ?? 85 C0 89 C3 79 11 49 8B 7D 00 E8 ?? ?? ?? ?? 49 C7 45 00 00 00 00 00 48 83 C4 30 89 D8 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule getpass_f2400cee35f887f1bd65a826dcd21f0b {
	meta:
		aliases = "getpass"
		type = "func"
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
		type = "func"
		size = "171"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 56 BF 03 00 00 00 41 55 41 54 55 31 ED 53 48 81 EC 00 01 00 00 E8 ?? ?? ?? ?? 85 C0 89 C3 74 14 48 63 F8 48 C1 E7 02 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 74 37 BE FF 00 00 00 48 89 E7 E8 ?? ?? ?? ?? FF C0 74 26 C6 84 24 FF 00 00 00 00 E8 ?? ?? ?? ?? 41 89 C5 E8 ?? ?? ?? ?? 48 89 EE 89 DF 41 89 C4 E8 ?? ?? ?? ?? 85 C0 79 05 E8 ?? ?? ?? ?? 83 F8 10 B9 10 00 00 00 49 89 E8 0F 4E C8 44 89 E2 44 89 EE 48 89 E7 E8 ?? ?? ?? ?? 48 89 EF 48 89 C3 E8 ?? ?? ?? ?? 48 81 C4 00 01 00 00 48 89 D8 5B 5D 41 5C 41 5D 41 5E C3 }
	condition:
		$pattern
}

rule __ieee754_pow_ce76f9ca5b08221ff14725d7aeacd561 {
	meta:
		aliases = "__ieee754_pow"
		type = "func"
		size = "2091"
		objfiles = "e_pow@libm.a"
	strings:
		$pattern = { ( CC | 41 ) 57 0F 28 D0 44 0F 28 C1 41 56 41 55 41 54 55 53 48 83 EC 68 F2 0F 11 44 24 08 48 8B 44 24 08 F2 0F 11 4C 24 08 48 8B 54 24 08 48 89 C1 41 89 C6 48 89 D0 48 C1 E9 20 48 C1 E8 20 41 89 CD 89 C3 89 C6 41 89 C4 81 E3 FF FF FF 7F 89 D8 09 D0 75 0E F2 44 0F 10 05 ?? ?? ?? ?? E9 B8 07 00 00 89 CD 41 89 CF 81 E5 FF FF FF 7F 81 FD 00 00 F0 7F 7F 1A 0F 94 44 24 5F 75 05 45 85 F6 75 0E 81 FB 00 00 F0 7F 7F 06 75 0E 85 D2 74 0A F2 44 0F 58 C2 E9 81 07 00 00 45 85 FF 79 65 81 FB FF FF 3F 43 41 B9 02 00 00 00 7F 5A 81 FB FF FF EF 3F 7E 4F 89 D8 C1 F8 14 2D FF 03 00 00 83 F8 14 7E 1B B9 34 00 00 00 29 C1 }
	condition:
		$pattern
}

rule iterate_demangle_function_9eb2d02170d4f698c240381986b9e8a9 {
	meta:
		aliases = "iterate_demangle_function"
		type = "func"
		size = "415"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 31 C0 41 56 41 55 41 54 49 89 F4 55 48 89 CD 53 48 81 EC A8 00 00 00 80 79 02 00 4C 8B 3E 0F 84 4F 01 00 00 F7 07 00 3C 00 00 49 89 FD 48 89 D3 0F 85 4F 01 00 00 48 8D 79 02 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 0F 84 38 01 00 00 48 8B 53 08 48 8D 7C 24 10 4C 8D 74 24 30 48 89 DE 48 C7 44 24 20 00 00 00 00 48 C7 44 24 18 00 00 00 00 48 C7 44 24 10 00 00 00 00 E8 C0 B4 FF FF 31 C0 B9 0E 00 00 00 4C 89 F7 F3 48 AB 4C 89 EE 4C 89 F7 E8 E8 B4 FF FF 80 7D 02 00 0F 84 A6 00 00 00 48 89 E9 48 89 DA 4C 89 E6 4C 89 EF E8 ED F0 FF FF 48 89 DA 4C 89 E6 4C 89 EF E8 6F F5 FF FF 85 C0 0F 85 81 00 00 }
	condition:
		$pattern
}

rule rexec_af_6b4269c3669c3d1bf0b0d8e6744f1399 {
	meta:
		aliases = "__GI_rexec_af, rexec_af"
		type = "func"
		size = "1103"
		objfiles = "rexec@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 31 C0 49 89 FF 66 C1 CE 08 41 56 41 55 41 54 55 53 48 81 EC E8 01 00 00 4C 8D AC 24 A0 01 00 00 48 89 54 24 48 48 89 4C 24 40 48 89 54 24 28 48 89 4C 24 30 BA ?? ?? ?? ?? 0F B7 CE 4C 89 EF BE 20 00 00 00 4C 89 44 24 20 4C 89 4C 24 18 0F B7 9C 24 20 02 00 00 E8 ?? ?? ?? ?? 4C 8D A4 24 50 01 00 00 31 F6 BA 30 00 00 00 C6 84 24 BF 01 00 00 00 4C 89 E7 E8 ?? ?? ?? ?? 49 8B 3F 48 8D 8C 24 C8 01 00 00 4C 89 EE 4C 89 E2 89 9C 24 54 01 00 00 C7 84 24 58 01 00 00 01 00 00 00 C7 84 24 50 01 00 00 02 00 00 00 41 83 CD FF E8 ?? ?? ?? ?? 85 C0 0F 85 7F 03 00 00 48 8B 84 24 C8 01 00 00 48 8B 70 20 48 }
	condition:
		$pattern
}

rule __get_myaddress_7cbc51c3f5ff82e3281f3ac598a2368d {
	meta:
		aliases = "__get_myaddress"
		type = "func"
		size = "308"
		objfiles = "pmap_clnt@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 31 D2 BE 02 00 00 00 41 56 41 55 49 89 FD BF 02 00 00 00 41 54 55 53 48 81 EC 48 10 00 00 E8 ?? ?? ?? ?? 85 C0 41 89 C4 BF ?? ?? ?? ?? 78 33 48 8D 94 24 30 10 00 00 31 C0 BE 12 89 00 00 44 89 E7 C7 84 24 30 10 00 00 00 10 00 00 48 89 A4 24 38 10 00 00 E8 ?? ?? ?? ?? 85 C0 79 14 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF 01 00 00 00 E8 ?? ?? ?? ?? 4C 8D BC 24 00 10 00 00 41 BE 01 00 00 00 48 8B 9C 24 38 10 00 00 8B AC 24 30 10 00 00 EB 74 FC B9 0A 00 00 00 4C 89 FF 48 89 DE F3 A5 31 C0 4C 89 FA BE 13 89 00 00 44 89 E7 E8 ?? ?? ?? ?? 85 C0 79 07 BF ?? ?? ?? ?? EB A7 0F BF 84 24 10 10 00 00 A8 01 74 }
	condition:
		$pattern
}

rule get_myaddress_eecc8179611df10ca85bc7f14890fedb {
	meta:
		aliases = "get_myaddress"
		type = "func"
		size = "290"
		objfiles = "get_myaddress@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 31 D2 BE 02 00 00 00 41 56 41 55 49 89 FD BF 02 00 00 00 41 54 55 53 48 81 EC 48 10 00 00 E8 ?? ?? ?? ?? 85 C0 41 89 C4 BF ?? ?? ?? ?? 78 33 48 8D 94 24 30 10 00 00 31 C0 BE 12 89 00 00 44 89 E7 C7 84 24 30 10 00 00 00 10 00 00 48 89 A4 24 38 10 00 00 E8 ?? ?? ?? ?? 85 C0 79 14 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF 01 00 00 00 E8 ?? ?? ?? ?? 4C 8D BC 24 00 10 00 00 45 31 F6 48 8B 9C 24 38 10 00 00 8B AC 24 30 10 00 00 EB 68 FC B9 0A 00 00 00 4C 89 FF 48 89 DE F3 A5 31 C0 4C 89 FA BE 13 89 00 00 44 89 E7 E8 ?? ?? ?? ?? 85 C0 79 07 BF ?? ?? ?? ?? EB AA 0F BF 84 24 10 10 00 00 A8 01 74 2A 66 83 }
	condition:
		$pattern
}

rule _vfprintf_internal_b51788c16cb89344fb31df2c4aeafa2b {
	meta:
		aliases = "_vfprintf_internal"
		type = "func"
		size = "1678"
		objfiles = "_vfprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 49 89 D4 55 53 48 89 F3 48 81 EC 08 02 00 00 48 8D 6C 24 40 48 89 7C 24 30 48 89 EF E8 ?? ?? ?? ?? 85 C0 79 33 48 8B 5C 24 40 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 48 89 C6 C7 44 24 38 FF FF FF FF 0F 84 2A 06 00 00 48 8B 54 24 30 48 89 DF E8 ?? ?? ?? ?? E9 10 06 00 00 48 89 EF 4C 89 E6 E8 ?? ?? ?? ?? 48 8D 44 24 40 48 89 DF C7 44 24 38 00 00 00 00 48 83 C0 08 48 89 44 24 28 48 8D 84 24 40 01 00 00 48 83 C0 7F 48 89 44 24 20 48 8D 44 24 40 48 83 C0 60 48 89 44 24 18 48 8D 44 24 40 48 83 C0 70 48 89 44 24 10 EB 03 48 FF C3 8A 03 84 C0 74 04 3C 25 75 F3 48 39 FB 74 2C 48 89 DD }
	condition:
		$pattern
}

rule _vfwprintf_internal_810ab8a8305cbee9763ae65eb05e8af0 {
	meta:
		aliases = "_vfwprintf_internal"
		type = "func"
		size = "1981"
		objfiles = "_vfwprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 49 89 D4 BA 00 01 00 00 55 48 89 F5 31 F6 53 48 81 EC 28 03 00 00 48 8D 9C 24 40 01 00 00 48 89 7C 24 28 48 89 DF E8 ?? ?? ?? ?? 48 8D 8C 24 10 03 00 00 48 8D B4 24 F8 02 00 00 48 83 CA FF 31 FF FF 8C 24 5C 01 00 00 48 89 AC 24 40 01 00 00 C7 84 24 54 01 00 00 80 00 00 00 C7 84 24 10 03 00 00 00 00 00 00 48 89 AC 24 F8 02 00 00 E8 ?? ?? ?? ?? 48 FF C0 75 11 48 C7 84 24 40 01 00 00 ?? ?? ?? ?? E9 85 00 00 00 48 8D 43 2C BA 09 00 00 00 C7 00 08 00 00 00 48 83 C0 04 FF CA 75 F2 48 8D 9C 24 40 01 00 00 48 89 E8 EB 30 83 FA 25 75 27 48 83 C0 04 83 38 25 74 1E 48 89 DF 48 89 }
	condition:
		$pattern
}

rule vfwscanf_1f5c6d1c05b1a9736bb5efe092bee642 {
	meta:
		aliases = "__GI_vfwscanf, vfwscanf"
		type = "func"
		size = "1830"
		objfiles = "vfwscanf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 49 89 D4 BA 48 00 00 00 55 48 89 F5 31 F6 53 48 81 EC A8 01 00 00 4C 8D 6C 24 40 48 89 7C 24 28 C7 84 24 88 00 00 00 FF FF FF FF 4C 89 EF E8 ?? ?? ?? ?? 48 8B 44 24 28 8B 40 50 85 C0 89 44 24 34 75 26 48 8B 5C 24 28 48 8D BC 24 60 01 00 00 BE ?? ?? ?? ?? 48 83 C3 58 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8D 9C 24 C0 00 00 00 48 8B 74 24 28 41 B7 01 48 89 DF E8 ?? ?? ?? ?? 48 8B 84 24 C8 00 00 00 48 C7 84 24 F0 00 00 00 ?? ?? ?? ?? 48 8D 94 24 10 01 00 00 8A 40 03 48 C7 84 24 08 01 00 00 ?? ?? ?? ?? C7 84 24 A0 00 00 00 00 00 00 00 48 89 54 24 08 88 84 24 DC }
	condition:
		$pattern
}

rule demangle_qualified_f3711cc70f50b9a505f2ef73c63c78f4 {
	meta:
		aliases = "demangle_qualified"
		type = "func"
		size = "1269"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 49 89 F4 55 48 89 FD 53 89 CB 48 83 EC 78 48 89 54 24 10 89 4C 24 0C 44 89 44 24 1C E8 77 E3 FF FF 85 DB 89 44 24 18 74 18 48 B8 01 00 00 00 01 00 00 00 48 85 45 38 0F 95 C0 0F B6 C0 89 44 24 0C 49 8B 04 24 48 C7 44 24 40 00 00 00 00 48 C7 44 24 38 00 00 00 00 48 C7 44 24 30 00 00 00 00 48 C7 44 24 60 00 00 00 00 48 C7 44 24 58 00 00 00 00 48 C7 44 24 50 00 00 00 00 80 38 4B 0F 84 DD 03 00 00 0F B6 50 01 80 FA 31 0F 8C A7 03 00 00 80 FA 39 0F 8E 1E 01 00 00 80 FA 5F 0F 85 95 03 00 00 48 83 C0 01 4C 89 E7 49 89 04 24 E8 35 E1 FF FF 83 F8 FF 89 C3 0F 84 7A 03 00 00 41 BE }
	condition:
		$pattern
}

rule _Unwind_ForcedUnwind_Phase2_801d7524b06d2aa8bd0d5022988612b7 {
	meta:
		aliases = "_Unwind_ForcedUnwind_Phase2"
		type = "func"
		size = "179"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 49 89 FC 55 48 89 F5 53 48 83 EC 08 4C 8B 7F 10 4C 8B 77 18 48 8B 06 EB 68 4C 8B 68 30 BE 0A 00 00 00 31 DB 4D 89 F1 49 89 E8 4C 89 E1 49 8B 14 24 BF 01 00 00 00 41 FF D7 85 C0 75 58 83 FB 05 74 58 4D 85 ED 66 66 90 74 23 49 89 E8 4C 89 E1 49 8B 14 24 BE 0A 00 00 00 BF 01 00 00 00 41 FF D5 83 F8 07 89 C3 74 32 83 F8 08 75 28 48 8B 7D 00 E8 ?? ?? ?? ?? 48 8B 45 00 48 8B 00 48 89 45 00 48 85 C0 75 93 BE 1A 00 00 00 BB 05 00 00 00 45 31 ED EB 8F BB 02 00 00 00 48 83 C4 08 89 D8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule clnttcp_call_fdc04b094318a076ea3aa43f9c2501c6 {
	meta:
		aliases = "clnttcp_call"
		type = "func"
		size = "646"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 49 89 FC 55 53 48 81 EC C8 00 00 00 48 89 54 24 40 48 89 4C 24 38 48 89 74 24 58 4C 89 44 24 30 4C 89 4C 24 28 48 8B 5F 10 48 8B 84 24 08 01 00 00 48 8B 94 24 00 01 00 00 48 8D 4B 48 48 8D 6B 68 48 89 4C 24 48 83 7B 18 00 75 08 48 89 43 10 48 89 53 08 48 83 7C 24 30 00 75 15 48 83 7B 08 00 75 0E 45 31 ED 48 83 7B 10 00 41 0F 95 C5 EB 06 41 BD 01 00 00 00 48 8D 43 48 48 8D 54 24 78 48 8D 4B 30 4C 8D 74 24 60 41 BF 02 00 00 00 48 89 44 24 20 48 89 54 24 08 48 89 4C 24 18 C7 43 68 00 00 00 00 C7 43 30 00 00 00 00 48 89 EF 48 8B 54 24 48 8B 02 FF C8 89 02 48 8B 74 24 20 0F }
	condition:
		$pattern
}

rule clntunix_call_bf5345a55c57455468ed5bb95efc5bdf {
	meta:
		aliases = "clntunix_call"
		type = "func"
		size = "717"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 49 89 FC 55 53 48 81 EC C8 00 00 00 48 89 54 24 40 48 89 4C 24 38 48 89 74 24 58 4C 89 44 24 30 4C 89 4C 24 28 48 8B 5F 10 48 8B 84 24 08 01 00 00 48 8B 94 24 00 01 00 00 48 8D 8B A8 00 00 00 48 8D AB C8 00 00 00 48 89 4C 24 50 83 7B 18 00 75 08 48 89 43 10 48 89 53 08 48 83 7C 24 30 00 75 15 48 83 7B 08 00 75 0E 45 31 ED 48 83 7B 10 00 41 0F 95 C5 EB 06 41 BD 01 00 00 00 48 8D 83 A8 00 00 00 48 8D 54 24 78 48 8D 8B 90 00 00 00 4C 8D 74 24 60 41 BF 02 00 00 00 48 89 44 24 20 48 89 54 24 08 48 89 4C 24 18 C7 83 C8 00 00 00 00 00 00 00 C7 83 90 00 00 00 00 00 00 00 48 89 }
	condition:
		$pattern
}

rule cplus_demangle_fill_operator_ae7365a40dab374c8808b57ff49c72d6 {
	meta:
		aliases = "cplus_demangle_fill_operator"
		type = "func"
		size = "193"
		objfiles = "cp_demint@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 49 89 FC 55 53 48 83 EC 08 48 85 FF 0F 84 96 00 00 00 48 85 F6 48 89 F5 0F 84 8A 00 00 00 48 89 F7 41 89 D7 E8 ?? ?? ?? ?? 4C 8B 05 ?? ?? ?? ?? 41 89 C6 4D 85 C0 74 70 31 DB 31 C9 EB 20 66 2E 0F 1F 84 00 00 00 00 00 83 C3 01 89 D9 48 8D 34 49 4C 8B 04 F5 ?? ?? ?? ?? 4D 85 C0 74 4A 48 8D 0C 49 44 39 34 CD ?? ?? ?? ?? 4C 8D 2C CD 00 00 00 00 75 D4 45 39 BD ?? ?? ?? ?? 75 CB 4C 89 C6 48 89 EF E8 ?? ?? ?? ?? 85 C0 75 BC 49 81 C5 ?? ?? ?? ?? 41 C7 04 24 28 00 00 00 B0 01 4D 89 6C 24 08 EB 06 0F 1F 40 00 31 C0 48 83 C4 08 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule htab_expand_1e8ded54adce98b87b666ddb502c5396 {
	meta:
		aliases = "htab_expand"
		type = "func"
		size = "555"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 49 89 FC 55 53 48 83 EC 18 48 8B 57 28 48 2B 57 30 4C 8B 6F 20 48 8B 6F 18 44 8B 77 68 48 8D 3C 12 4A 8D 5C ED 00 49 39 FD 0F 82 6A 01 00 00 48 C1 E2 03 49 39 D5 0F 87 53 01 00 00 49 8B 44 24 58 48 85 C0 0F 84 72 01 00 00 49 8B 7C 24 50 BA 08 00 00 00 4C 89 EE FF D0 48 85 C0 0F 84 70 01 00 00 49 89 44 24 18 4D 89 6C 24 20 49 89 ED 49 8B 44 24 30 45 89 74 24 68 49 29 44 24 28 49 C7 44 24 30 00 00 00 00 EB 14 0F 1F 80 00 00 00 00 49 83 C5 08 4C 39 EB 0F 86 CF 00 00 00 4D 8B 75 00 49 83 FE 01 76 E9 4C 89 F7 41 FF 14 24 41 8B 54 24 68 41 89 C0 89 C6 4D 8B 4C 24 18 48 C1 E2 }
	condition:
		$pattern
}

rule objalloc_free_block_fbe87065eac7736c39c32a6b56ffaab1 {
	meta:
		aliases = "objalloc_free_block"
		type = "func"
		size = "354"
		objfiles = "objalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 49 89 FC 55 53 48 83 EC 18 48 8B 7F 10 48 85 FF 74 46 49 89 F5 48 89 FB 45 31 FF EB 14 0F 1F 00 48 8D 53 10 49 39 D5 74 37 48 8B 1B 48 85 DB 74 27 48 8B 6B 08 48 85 ED 75 E6 49 39 DD 76 0C 48 8D AB E0 0F 00 00 49 39 ED 72 71 49 89 DF 48 8B 1B 48 85 DB 75 DB 66 90 E8 ?? ?? ?? ?? 0F 1F 00 48 8B 1B 48 39 DF 75 0B EB 16 66 0F 1F 44 00 00 4C 89 EF 4C 8B 2F E8 ?? ?? ?? ?? 4C 39 EB 75 F0 49 89 5C 24 10 48 83 7B 08 00 74 0E 0F 1F 40 00 48 8B 1B 48 83 7B 08 00 75 F6 48 81 C3 E0 0F 00 00 49 89 2C 24 48 29 EB 41 89 5C 24 08 48 83 C4 18 5B 5D 41 5C 41 5D 41 5E 41 5F C3 48 85 DB 74 }
	condition:
		$pattern
}

rule realloc_a9612454f0de7bf4eea58c663e6e0a46 {
	meta:
		aliases = "realloc"
		type = "func"
		size = "878"
		objfiles = "realloc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 49 89 FC 55 53 48 89 F3 48 83 EC 38 48 85 FF 75 10 48 89 F7 E8 ?? ?? ?? ?? 48 89 C3 E9 33 03 00 00 48 85 F6 75 0A E8 ?? ?? ?? ?? E9 24 03 00 00 48 8D 7C 24 10 BA ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 FB BF 76 12 31 DB E8 ?? ?? ?? ?? C7 00 0C 00 00 00 E9 EE 02 00 00 48 8D 43 17 41 B9 20 00 00 00 48 83 F8 1F 76 07 49 89 C1 49 83 E1 F0 49 8B 54 24 F8 4D 8D 44 24 F0 49 89 D5 49 83 E5 FC F6 C2 02 0F 85 C9 01 00 00 4D 39 CD 4C 89 E9 0F 83 5C 01 00 00 4B 8D 2C 28 48 3B 2D ?? ?? ?? ?? 75 3E 48 8B 45 08 48 83 E0 FC 4A 8D 0C 28 49 8D 41 20 }
	condition:
		$pattern
}

rule _stdlib_wcsto_l_cb04583eafc4a33981a06cb53a39c6cd {
	meta:
		aliases = "_stdlib_wcsto_l"
		type = "func"
		size = "354"
		objfiles = "_stdlib_wcsto_l@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 49 89 FC 55 89 D5 53 48 89 FB 48 83 EC 18 48 89 74 24 10 89 4C 24 0C EB 04 48 83 C3 04 8B 3B E8 ?? ?? ?? ?? 85 C0 75 F1 8B 03 83 F8 2B 74 0D 45 31 ED 83 F8 2D 75 0C 41 B5 01 EB 03 45 31 ED 48 83 C3 04 F7 C5 EF FF FF FF 4C 89 E7 75 2D 83 C5 0A 83 3B 30 75 1A 48 83 C3 04 83 ED 02 8B 03 48 89 DF 83 C8 20 83 F8 78 75 06 01 ED 48 83 C3 04 83 FD 11 B8 10 00 00 00 0F 4D E8 8D 45 FE 31 F6 83 F8 22 77 78 48 83 C9 FF 4C 63 E5 31 D2 48 89 C8 49 F7 F4 49 89 C7 41 88 D6 EB 03 48 89 DF 8B 0B 8D 41 D0 8D 51 D0 83 F8 09 76 14 89 C8 B2 28 83 C8 20 83 F8 60 76 08 88 C8 83 C8 20 8D 50 A9 }
	condition:
		$pattern
}

rule clntudp_bufcreate_996a33aa49315aae54967cd16dc95298 {
	meta:
		aliases = "__GI_clntudp_bufcreate, clntudp_bufcreate"
		type = "func"
		size = "681"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 49 89 FC BF 18 00 00 00 55 53 48 81 EC B8 00 00 00 48 89 74 24 28 48 89 54 24 20 48 89 4C 24 18 4C 89 44 24 10 4C 89 4C 24 08 48 89 4C 24 30 4C 89 44 24 38 E8 ?? ?? ?? ?? 44 8B B4 24 F0 00 00 00 44 8B AC 24 F8 00 00 00 49 89 C7 41 83 C6 03 41 83 C5 03 41 83 E6 FC 41 83 E5 FC 44 89 F0 44 89 EB 48 8D BC 03 A0 00 00 00 E8 ?? ?? ?? ?? 4D 85 FF 48 89 C5 74 05 48 85 C0 75 2B E8 ?? ?? ?? ?? 48 8B 35 ?? ?? ?? ?? 48 89 C3 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 03 0C 00 00 00 C7 43 10 0C 00 00 00 E9 C8 01 00 00 66 41 83 7C 24 02 00 48 8D 84 18 9C 00 00 00 48 89 85 90 00 00 00 75 2A 48 }
	condition:
		$pattern
}

rule _dl_do_reloc_b4ec564a4a6be83bae77a9deb6f7876b {
	meta:
		aliases = "_dl_do_reloc"
		type = "func"
		size = "333"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 31 ED 53 48 89 D3 48 83 EC 08 4C 8B 27 4C 03 22 48 8B 52 08 41 89 D6 48 C1 EA 20 48 63 C2 48 6B C0 18 85 D2 4C 8D 2C 01 41 8B 45 00 74 71 31 C9 41 83 FE 05 89 C0 0F 94 C1 4D 8D 3C 00 31 C0 01 C9 41 83 FE 07 48 89 FA 0F 94 C0 4C 89 FF 09 C1 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 75 42 41 8A 45 04 C0 E8 04 3C 02 74 37 48 8B 15 ?? ?? ?? ?? 31 C0 4C 89 F9 BE ?? ?? ?? ?? BF 02 00 00 00 E8 ?? ?? ?? ?? BF 01 00 00 00 B8 3C 00 00 00 0F 05 48 3D 00 F0 FF FF 76 08 F7 D8 89 05 ?? ?? ?? ?? 41 83 FE 12 77 0A 44 89 F0 FF 24 C5 ?? ?? ?? ?? 83 C8 FF E9 81 00 00 00 48 8B 43 10 48 2B 03 48 }
	condition:
		$pattern
}

rule inet_pton_b317ce62bb4a5bd3fc0737a7dfb3eb6c {
	meta:
		aliases = "__GI_inet_pton, inet_pton"
		type = "func"
		size = "498"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 48 89 F5 53 48 83 EC 38 83 FF 02 48 89 54 24 08 74 0B 83 FF 0A 0F 85 B1 01 00 00 EB 12 48 8B 74 24 08 48 89 EF E8 46 FF FF FF E9 AB 01 00 00 48 8D 7C 24 20 31 F6 BA 10 00 00 00 E8 ?? ?? ?? ?? 80 7D 00 3A 49 89 C4 4C 8D 70 10 75 0D 48 FF C5 80 7D 00 3A 0F 85 6E 01 00 00 49 89 EF 48 C7 44 24 18 00 00 00 00 E9 86 00 00 00 89 DE BF ?? ?? ?? ?? 48 FF C5 E8 ?? ?? ?? ?? 48 85 C0 48 89 C2 74 20 B8 ?? ?? ?? ?? 41 C1 E5 04 29 C2 41 09 D5 41 81 FD FF FF 00 00 0F 86 8C 00 00 00 E9 26 01 00 00 83 FB 3A 75 57 83 7C 24 14 00 75 16 48 83 7C 24 18 00 0F 85 0E 01 00 00 49 89 EF 4C 89 }
	condition:
		$pattern
}

rule __pthread_alt_unlock_678f4ff90ad491b047c11ca056ec81ad {
	meta:
		aliases = "__pthread_alt_unlock"
		type = "func"
		size = "221"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 48 89 FD 53 48 83 EC 08 48 8B 55 00 48 83 FA 01 77 17 31 C9 48 89 D0 F0 48 0F B1 4D 00 0F 94 C2 84 D2 74 E4 E9 9F 00 00 00 48 89 D3 41 BE 00 00 00 80 49 89 ED 49 89 D4 49 89 EF EB 42 83 7B 10 00 74 21 48 89 DA 4C 89 EE 48 89 EF E8 01 FF FF FF 48 89 DF E8 6E FF FF FF 49 39 ED 49 8B 5D 00 75 1D EB 1B 48 8B 43 08 8B 40 2C 44 39 F0 7C 09 49 89 DC 4D 89 EF 41 89 C6 49 89 DD 48 8B 1B 48 83 FB 01 75 B8 41 81 FE 00 00 00 80 0F 84 76 FF FF FF B8 01 00 00 00 41 87 44 24 10 48 85 C0 0F 85 63 FF FF FF 4C 89 FE 48 89 EF 4C 89 E2 E8 9F FE FF FF 49 8B 7C 24 08 5E 5B 5D 41 5C 41 5D }
	condition:
		$pattern
}

rule statvfs64_2ab0070f3728d992991bf090f77d481f {
	meta:
		aliases = "__GI_statvfs, statvfs, statvfs64"
		type = "func"
		size = "682"
		objfiles = "statvfs64@libc.a, statvfs@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 48 89 FD 53 48 89 F3 48 81 EC E8 05 00 00 48 8D B4 24 30 05 00 00 E8 ?? ?? ?? ?? 83 CA FF 85 C0 0F 88 67 02 00 00 48 8B 84 24 38 05 00 00 48 63 94 24 68 05 00 00 48 8D 7B 58 31 F6 48 89 03 48 89 43 08 48 8B 84 24 40 05 00 00 48 89 43 10 48 8B 84 24 48 05 00 00 48 89 43 18 48 8B 84 24 50 05 00 00 48 89 43 20 48 8B 84 24 58 05 00 00 48 89 43 28 48 8B 84 24 60 05 00 00 48 89 43 30 48 63 84 24 6C 05 00 00 48 C1 E0 20 48 09 D0 BA 18 00 00 00 48 89 43 40 48 8B 84 24 70 05 00 00 48 89 43 50 E8 ?? ?? ?? ?? 48 8B 43 30 48 8D B4 24 A0 04 00 00 48 C7 43 48 00 00 00 00 48 89 EF }
	condition:
		$pattern
}

rule work_stuff_copy_to_from_fb832f85beb5ae66c6115894f8c436d2 {
	meta:
		aliases = "work_stuff_copy_to_from"
		type = "func"
		size = "822"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 48 89 FD 53 48 89 F3 48 83 EC 08 E8 27 FC FF FF 48 89 EF E8 FF F8 FF FF 48 8B 03 48 89 45 00 48 8B 43 08 48 89 45 08 48 8B 43 10 48 89 45 10 48 8B 43 18 48 89 45 18 48 8B 43 20 48 89 45 20 48 8B 43 28 48 89 45 28 48 8B 43 30 48 89 45 30 48 8B 43 38 48 89 45 38 48 8B 43 40 48 89 45 40 48 8B 43 48 48 89 45 48 48 8B 43 50 48 89 45 50 48 8B 43 58 48 89 45 58 48 8B 43 60 48 89 45 60 48 8B 43 68 48 89 45 68 48 63 43 34 85 C0 0F 85 A4 01 00 00 8B 7B 30 45 31 E4 85 FF 7E 5C 66 2E 0F 1F 84 00 00 00 00 00 48 8B 43 08 4E 8D 2C E5 00 00 00 00 4A 8B 3C E0 E8 ?? ?? ?? ?? 4C 03 6D }
	condition:
		$pattern
}

rule __dns_lookup_8cba802fdea4f983657f241e7ab98374 {
	meta:
		aliases = "__dns_lookup"
		type = "func"
		size = "1864"
		objfiles = "dnslookup@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 4C 89 CD 53 48 81 EC 28 01 00 00 48 89 7C 24 28 BF 00 02 00 00 89 74 24 24 89 54 24 20 48 89 4C 24 18 4C 89 44 24 10 E8 ?? ?? ?? ?? BF 01 04 00 00 49 89 C6 E8 ?? ?? ?? ?? 4D 85 F6 48 89 44 24 08 0F 84 48 06 00 00 48 85 C0 0F 84 3F 06 00 00 83 7C 24 20 00 0F 84 34 06 00 00 48 8B 44 24 28 80 38 00 0F 84 26 06 00 00 48 89 C7 E8 ?? ?? ?? ?? 48 8B 54 24 28 48 8D 9C 24 C0 00 00 00 BE ?? ?? ?? ?? 48 89 DF 80 7C 02 FF 2E BA ?? ?? ?? ?? 0F 94 44 24 47 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? BE 01 00 00 00 48 89 DF 99 F7 7C 24 20 0F B7 05 ?? ?? ?? ?? 89 }
	condition:
		$pattern
}

rule __pthread_manager_7e7b4105b77e14af2bd2351887d31595 {
	meta:
		aliases = "__pthread_manager"
		type = "func"
		size = "1781"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 53 48 81 EC 98 01 00 00 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 48 8D 9C 24 00 01 00 00 89 7C 24 24 48 89 DF E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? BE 05 00 00 00 48 89 DF E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 85 C0 74 12 8B 35 ?? ?? ?? ?? 85 F6 7E 08 48 89 DF E8 ?? ?? ?? ?? 48 8D B4 24 00 01 00 00 31 D2 BF 02 00 00 00 E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 8B 78 2C E8 ?? ?? ?? ?? 48 8D 5C 24 50 8B 7C 24 24 BA A8 00 00 00 48 89 DE E8 ?? ?? ?? ?? 48 FF C0 75 0A E8 ?? ?? ?? ?? 83 38 04 74 E0 8B 44 24 24 66 C7 84 24 84 01 00 00 01 00 }
	condition:
		$pattern
}

rule clnt_broadcast_af63b6355b801dc659a44df3c485b6d8 {
	meta:
		aliases = "clnt_broadcast"
		type = "func"
		size = "1475"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 53 48 81 EC F8 29 00 00 48 89 7C 24 40 48 89 74 24 38 48 89 54 24 30 48 89 4C 24 28 4C 89 44 24 20 4C 89 4C 24 18 E8 ?? ?? ?? ?? BF 02 00 00 00 BA 11 00 00 00 BE 02 00 00 00 48 89 44 24 48 C7 84 24 E8 29 00 00 01 00 00 00 E8 ?? ?? ?? ?? 85 C0 41 89 C6 BF ?? ?? ?? ?? 0F 88 5C 03 00 00 48 8D 8C 24 E8 29 00 00 89 C7 41 B8 04 00 00 00 BA 06 00 00 00 BE 01 00 00 00 E8 ?? ?? ?? ?? 85 C0 BF ?? ?? ?? ?? 0F 88 30 03 00 00 48 8D 44 24 60 48 8D 94 24 A0 29 00 00 BE 12 89 00 00 44 89 F7 44 89 B4 24 E0 29 00 00 66 C7 84 24 E4 29 00 00 01 00 48 89 84 24 A8 29 00 00 31 C0 C7 84 24 }
	condition:
		$pattern
}

rule scandir64_ed1b9fb8823bbd8aa1d7b4920a5a797b {
	meta:
		aliases = "scandir, scandir64"
		type = "func"
		size = "360"
		objfiles = "scandir64@libc.a, scandir@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 53 48 83 EC 28 48 89 74 24 10 48 89 54 24 08 48 89 0C 24 E8 ?? ?? ?? ?? 49 89 C7 83 C8 FF 4D 85 FF 0F 84 29 01 00 00 E8 ?? ?? ?? ?? 48 89 C5 8B 00 45 31 F6 45 31 ED 89 44 24 24 C7 45 00 00 00 00 00 48 C7 44 24 18 00 00 00 00 E9 85 00 00 00 48 83 7C 24 08 00 74 14 4C 89 E7 FF 54 24 08 85 C0 75 09 C7 45 00 00 00 00 00 EB 69 C7 45 00 00 00 00 00 4C 3B 6C 24 18 75 33 4D 85 ED 48 C7 44 24 18 0A 00 00 00 4B 8D 44 2D 00 48 0F 44 44 24 18 4C 89 F7 48 89 C6 48 89 44 24 18 48 C1 E6 03 E8 ?? ?? ?? ?? 48 85 C0 74 3F 49 89 C6 41 0F B7 5C 24 10 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 48 }
	condition:
		$pattern
}

rule __ivaliduser2_45943a24954509f407fa04c503fb61e2 {
	meta:
		aliases = "__ivaliduser2"
		type = "func"
		size = "754"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 53 48 83 EC 68 48 89 7C 24 18 89 74 24 14 48 89 54 24 08 48 89 0C 24 48 C7 44 24 50 00 00 00 00 48 C7 44 24 48 00 00 00 00 E9 7C 02 00 00 48 8B 54 24 48 48 8B 44 24 50 C6 44 02 FF 00 48 8B 5C 24 50 48 89 DE EB 03 48 FF C6 8A 0E 84 C9 0F 84 56 02 00 00 48 8B 05 ?? ?? ?? ?? 48 0F BE D1 F6 04 50 20 75 E2 80 F9 23 0F 84 3C 02 00 00 BE 0A 00 00 00 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 75 4E 48 8B 54 24 18 48 8B 42 18 48 3B 42 28 73 11 0F B6 10 48 8B 4C 24 18 48 FF C0 48 89 41 18 EB 0C 48 8B 7C 24 18 E8 ?? ?? ?? ?? 89 C2 83 FA 0A 0F 84 F5 01 00 00 FF C2 75 C7 E9 EC 01 00 00 48 }
	condition:
		$pattern
}

rule strftime_aa3b1bc8286570645dc53ce2757e3ce3 {
	meta:
		aliases = "__GI_strftime, strftime"
		type = "func"
		size = "1408"
		objfiles = "strftime@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 53 48 89 D3 48 81 EC A8 00 00 00 48 89 7C 24 30 48 89 74 24 28 48 89 CF 31 F6 48 89 4C 24 20 E8 ?? ?? ?? ?? 31 FF 48 3D FF 4E 98 45 40 0F 9E C7 E8 ?? ?? ?? ?? 48 8D 4C 24 70 48 8B 44 24 28 48 89 DA C7 44 24 4C 00 00 00 00 48 89 CB 48 89 4C 24 08 48 83 C3 15 48 89 44 24 40 48 89 5C 24 18 48 83 7C 24 40 00 0F 84 F7 04 00 00 8A 02 84 C0 75 2F 83 7C 24 4C 00 75 18 48 8B 6C 24 30 C6 45 00 00 48 8B 44 24 28 48 2B 44 24 40 E9 D4 04 00 00 FF 4C 24 4C 48 63 44 24 4C 48 8B 54 C4 50 EB BF 3C 25 74 07 48 89 54 24 38 EB 10 48 8D 42 01 48 89 44 24 38 8A 42 01 3C 25 75 0E 48 89 D3 }
	condition:
		$pattern
}

rule demangle_expression_4b443b07b5cec5ec13d42fe09db6a43b {
	meta:
		aliases = "demangle_expression"
		type = "func"
		size = "416"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 53 48 89 F3 48 83 EC 38 48 89 7C 24 18 48 89 74 24 10 48 89 D7 48 89 54 24 08 BE ?? ?? ?? ?? BA 01 00 00 00 89 4C 24 24 E8 DA EF FF FF 48 8B 0B B8 01 00 00 00 4C 8D 61 01 48 89 4C 24 28 31 C9 4C 89 23 41 0F B6 14 24 80 FA 57 0F 84 E4 00 00 00 66 0F 1F 44 00 00 84 D2 0F 84 18 01 00 00 85 C9 0F 84 99 00 00 00 4C 89 E7 45 31 F6 E8 ?? ?? ?? ?? 48 89 C3 EB 0E 49 83 C6 01 49 83 FE 4F 0F 84 F2 00 00 00 4B 8D 04 76 4C 8B 2C C5 ?? ?? ?? ?? 48 8D 2C C5 00 00 00 00 4C 89 EF E8 ?? ?? ?? ?? 48 39 C3 49 89 C7 72 CE 48 89 C2 4C 89 E6 4C 89 EF E8 ?? ?? ?? ?? 85 C0 75 BC 48 8B 7C 24 }
	condition:
		$pattern
}

rule des_setkey_2b208f85040c63967de7ee82e901e89f {
	meta:
		aliases = "des_setkey"
		type = "func"
		size = "585"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 53 48 89 FB 48 83 EC 08 E8 C5 F7 FF FF 44 8B 4B 04 44 8B 13 41 0F C9 44 89 C8 41 0F CA 44 09 D0 74 16 44 3B 15 ?? ?? ?? ?? 75 0D 44 3B 0D ?? ?? ?? ?? 0F 84 FC 01 00 00 44 89 D2 44 89 D0 45 89 D0 C1 EA 11 C1 E8 09 41 C1 E8 19 83 E2 7F 83 E0 7F 44 89 C9 45 89 C0 44 89 15 ?? ?? ?? ?? 44 8B 2C 85 ?? ?? ?? ?? 41 D1 EA 44 0B 2C 95 ?? ?? ?? ?? 8B 2C 85 ?? ?? ?? ?? 0B 2C 95 ?? ?? ?? ?? 44 89 CE 41 83 E2 7F C1 E9 19 46 0B 2C 85 ?? ?? ?? ?? 42 0B 2C 85 ?? ?? ?? ?? 44 89 CF 89 C9 C1 EE 11 46 0B 2C 95 ?? ?? ?? ?? 42 0B 2C 95 ?? ?? ?? ?? 83 E6 7F C1 EF 09 44 0B 2C 8D ?? ?? ?? ?? }
	condition:
		$pattern
}

rule scan_getwc_e63df33fc26a20608f8a02576c7fb25c {
	meta:
		aliases = "scan_getwc"
		type = "func"
		size = "181"
		objfiles = "vfscanf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 53 48 89 FB 48 83 EC 18 44 8B 67 14 41 FF CC 45 85 E4 44 89 67 14 79 09 80 4F 1D 02 83 C8 FF EB 7C 4C 8D 6F 20 4C 8D 7C 24 0F 48 C7 C5 FD FF FF FF C7 47 14 FF FF FF 7F EB 2F 8B 03 4C 89 E9 BA 01 00 00 00 4C 89 FE 48 89 E7 88 44 24 0F E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 78 08 8B 04 24 89 43 28 EB 34 48 83 F8 FE 75 0C 48 89 DF E8 ?? ?? ?? ?? 85 C0 79 C5 48 83 FD FD 75 0D 48 83 C5 02 C7 43 28 FF FF FF FF EB 0F E8 ?? ?? ?? ?? C7 00 54 00 00 00 C6 43 1F 01 44 89 63 14 89 E8 48 83 C4 18 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule internal_cplus_demangle_5e52636c974961e8b934ceb810a980c2 {
	meta:
		aliases = "internal_cplus_demangle"
		type = "func"
		size = "1806"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 53 48 89 FB 48 83 EC 58 48 85 F6 8B 6F 38 44 8B 67 3C 44 8B 77 48 48 89 74 24 18 44 8B 6F 40 C7 47 3C 00 00 00 00 C7 47 38 00 00 00 00 C7 47 48 00 00 00 00 C7 47 4C 00 00 00 00 0F 84 26 03 00 00 80 3E 00 0F 84 1D 03 00 00 F7 07 00 03 00 00 48 C7 44 24 40 00 00 00 00 48 89 F2 48 C7 44 24 38 00 00 00 00 48 C7 44 24 30 00 00 00 00 0F 85 E3 00 00 00 48 89 D7 48 89 54 24 08 E8 ?? ?? ?? ?? 48 83 F8 06 48 8B 54 24 08 0F 86 77 01 00 00 BF ?? ?? ?? ?? B9 06 00 00 00 48 89 D6 F3 A6 0F 84 AA 01 00 00 BF ?? ?? ?? ?? B9 06 00 00 00 48 89 D6 F3 A6 0F 84 95 01 00 00 48 83 F8 0A 0F }
	condition:
		$pattern
}

rule floatformat_to_double_da602d0eef4af30d74741ada0e6e179b {
	meta:
		aliases = "floatformat_to_double"
		type = "func"
		size = "698"
		objfiles = "floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 53 48 89 FB 48 89 F7 48 83 EC 28 44 8B 73 04 44 8B 3B 8B 4B 0C 44 8B 43 10 48 89 74 24 10 48 89 54 24 18 44 89 FE 44 89 F2 E8 C9 FD FF FF 8B 53 18 48 39 D0 0F 84 A5 01 00 00 48 85 C0 49 89 C4 44 8B 6B 20 8B 6B 1C 0F 85 22 01 00 00 66 0F 57 E4 44 89 FE 44 89 F2 F2 0F 11 64 24 08 45 85 ED 41 BE 20 00 00 00 7F 54 E9 AE 00 00 00 66 2E 0F 1F 84 00 00 00 00 00 4D 85 E4 75 5F 8B 53 1C 2B 53 14 8D 7A 01 29 EF 44 29 FF 48 85 C0 0F 88 0C 01 00 00 F2 48 0F 2A C0 E8 ?? ?? ?? ?? F2 0F 58 44 24 08 45 31 E4 F2 0F 11 44 24 08 45 29 FD 44 01 FD 8B 53 04 45 85 ED 8B 33 7E 5F 41 83 FD }
	condition:
		$pattern
}

rule svc_getreq_common_6ab03a119babb5670f36fddb00c87ea5 {
	meta:
		aliases = "__GI_svc_getreq_common, svc_getreq_common"
		type = "func"
		size = "441"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 53 89 FB 48 63 DB 48 81 EC 58 05 00 00 48 8D 84 24 90 01 00 00 48 89 E5 48 89 A4 24 E8 04 00 00 48 89 84 24 00 05 00 00 E8 ?? ?? ?? ?? 49 89 C4 48 8B 80 E8 00 00 00 48 8B 1C D8 48 85 DB 0F 84 5A 01 00 00 4C 8D BC 24 28 05 00 00 4C 8D B4 24 E0 04 00 00 4C 8D AC 24 10 05 00 00 48 81 C5 20 03 00 00 48 8B 43 08 48 8D B4 24 B0 04 00 00 48 89 DF FF 10 85 C0 0F 84 00 01 00 00 48 8B 84 24 C8 04 00 00 83 BC 24 E0 04 00 00 00 B9 06 00 00 00 FC 4C 89 FF 4C 89 F6 48 89 AC 24 40 05 00 00 48 89 84 24 10 05 00 00 48 8B 84 24 D0 04 00 00 48 89 9C 24 48 05 00 00 F3 A5 48 89 84 24 18 }
	condition:
		$pattern
}

rule ttyname_r_f9d54f68fde72932b482bca1d48086ed {
	meta:
		aliases = "__GI_ttyname_r, ttyname_r"
		type = "func"
		size = "341"
		objfiles = "ttyname@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 53 89 FB 48 81 EC 58 01 00 00 48 89 74 24 08 48 8D B4 24 A0 00 00 00 48 89 14 24 E8 ?? ?? ?? ?? 85 C0 79 0C E8 ?? ?? ?? ?? 8B 18 E9 08 01 00 00 89 DF E8 ?? ?? ?? ?? 85 C0 0F 84 ED 00 00 00 4C 8D B4 24 30 01 00 00 BA ?? ?? ?? ?? E9 D1 00 00 00 4C 8D 62 01 4C 89 F7 48 0F BE D8 41 BD 1E 00 00 00 4D 8D 3C 1E 4C 89 E6 49 29 DD E8 ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 75 7D E9 91 00 00 00 48 8D 58 13 48 89 DF E8 ?? ?? ?? ?? 4C 39 E8 77 67 48 89 DE 4C 89 FF E8 ?? ?? ?? ?? 48 8D 74 24 10 4C 89 F7 E8 ?? ?? ?? ?? 85 C0 75 4B 8B 44 24 28 25 00 F0 00 00 3D 00 20 }
	condition:
		$pattern
}

rule _stdlib_strto_l_8a035be1c8391b4f73b605b7dcbf53bd {
	meta:
		aliases = "_stdlib_strto_l"
		type = "func"
		size = "340"
		objfiles = "_stdlib_strto_l@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 89 D5 53 48 89 FB 48 83 EC 18 48 89 74 24 10 89 4C 24 0C EB 03 48 FF C3 8A 0B 48 8B 05 ?? ?? ?? ?? 48 0F BE D1 F6 04 50 20 75 EA 80 F9 2B 74 0D 45 31 ED 80 F9 2D 75 0B 41 B5 01 EB 03 45 31 ED 48 FF C3 F7 C5 EF FF FF FF 48 89 F9 75 2A 83 C5 0A 80 3B 30 75 17 48 FF C3 83 ED 02 8A 03 48 89 D9 83 C8 20 3C 78 75 05 01 ED 48 FF C3 83 FD 11 B8 10 00 00 00 0F 4D E8 8D 45 FE 31 F6 83 F8 22 77 6C 48 83 CF FF 4C 63 E5 31 D2 48 89 F8 49 F7 F4 49 89 C7 41 88 D6 EB 03 48 89 D9 8A 03 8D 50 D0 80 FA 09 76 0C 83 C8 20 B2 28 3C 60 76 03 8D 50 A9 0F B6 C2 39 E8 7D 35 48 FF C3 4C 39 FE }
	condition:
		$pattern
}

rule vsyslog_418d5e8ce2bc85e13729b325bfa08a42 {
	meta:
		aliases = "__GI_vsyslog, vsyslog"
		type = "func"
		size = "793"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 89 FD 53 48 81 EC 88 05 00 00 48 8D 9C 24 B0 04 00 00 48 89 74 24 08 48 89 14 24 31 F6 BA 98 00 00 00 48 89 DF E8 ?? ?? ?? ?? 48 8D 7B 08 48 C7 84 24 B0 04 00 00 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 94 24 10 04 00 00 48 89 DE BF 0D 00 00 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D BC 24 50 05 00 00 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 49 89 C7 44 8B 20 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 E9 B8 01 00 00 00 83 E1 07 D3 E0 85 05 ?? ?? ?? ?? 0F 84 40 02 00 00 F7 C5 00 FC FF FF 0F 85 34 02 00 00 83 3D ?? ?? ?? ?? 00 78 09 83 3D ?? ?? ?? ?? 00 75 17 8B 35 ?? ?? ?? ?? 48 8B 3D }
	condition:
		$pattern
}

rule fstatvfs64_db9f947c1c1654493360ab027ec8706b {
	meta:
		aliases = "fstatvfs, fstatvfs64"
		type = "func"
		size = "680"
		objfiles = "fstatvfs64@libc.a, fstatvfs@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 89 FD 53 48 89 F3 48 81 EC E8 05 00 00 48 8D B4 24 30 05 00 00 E8 ?? ?? ?? ?? 83 CA FF 85 C0 0F 88 66 02 00 00 48 8B 84 24 38 05 00 00 48 63 94 24 68 05 00 00 48 8D 7B 58 31 F6 48 89 03 48 89 43 08 48 8B 84 24 40 05 00 00 48 89 43 10 48 8B 84 24 48 05 00 00 48 89 43 18 48 8B 84 24 50 05 00 00 48 89 43 20 48 8B 84 24 58 05 00 00 48 89 43 28 48 8B 84 24 60 05 00 00 48 89 43 30 48 63 84 24 6C 05 00 00 48 C1 E0 20 48 09 D0 BA 18 00 00 00 48 89 43 40 48 8B 84 24 70 05 00 00 48 89 43 50 E8 ?? ?? ?? ?? 48 8B 43 30 48 8D B4 24 A0 04 00 00 48 C7 43 48 00 00 00 00 89 EF 48 89 }
	condition:
		$pattern
}

rule byte_re_search_2_382fae1efc84b17474e4390b50103715 {
	meta:
		aliases = "byte_re_search_2"
		type = "func"
		size = "834"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 89 D5 45 01 C5 41 54 49 89 FC 55 53 44 89 CB 48 83 EC 48 45 39 E9 4C 8B 7F 20 8B AC 24 80 00 00 00 48 89 74 24 20 89 54 24 1C 48 89 4C 24 28 44 89 44 24 34 4C 8B 77 28 41 8D 04 29 0F 8F 67 02 00 00 44 89 CA C1 EA 1F 84 D2 0F 85 59 02 00 00 85 C0 0F 88 D9 02 00 00 44 89 EA 44 29 CA 41 39 C5 0F 4C EA 48 83 7F 10 00 0F 85 02 02 00 00 4D 85 FF 74 0C 41 F6 44 24 38 08 0F 84 81 02 00 00 48 63 44 24 1C 48 8B 7C 24 28 4D 85 FF 0F 95 44 24 33 48 29 C7 48 89 7C 24 38 0F 1F 80 00 00 00 00 44 39 EB 0F 8D 9F 00 00 00 80 7C 24 33 00 0F 84 94 00 00 00 41 F6 44 24 38 01 0F 85 88 00 00 00 }
	condition:
		$pattern
}

rule __pthread_destroy_specifics_dad55e38a8c6feaa6fdccbfa78ee55da {
	meta:
		aliases = "__pthread_destroy_specifics"
		type = "func"
		size = "234"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 45 31 ED 41 54 55 53 48 83 EC 08 E8 15 FF FF FF B9 01 00 00 00 48 89 C5 EB 6B 48 63 C3 48 83 BC C5 48 01 00 00 00 74 53 41 89 DF 45 31 E4 49 89 C6 41 C1 E7 05 EB 3E 43 8D 04 3C 48 98 48 C1 E0 04 48 8B 90 ?? ?? ?? ?? 49 63 C4 48 C1 E0 03 4A 03 84 F5 48 01 00 00 48 85 D2 48 8B 38 74 13 48 85 FF 74 0E 48 C7 00 00 00 00 00 FF D2 B9 01 00 00 00 41 FF C4 41 83 FC 1F 7E BC FF C3 83 FB 1F 7E 98 41 FF C5 85 C9 74 0C 41 83 FD 03 7F 06 31 DB 31 C9 EB E8 48 8B 7D 30 48 89 EE 45 31 E4 E8 ?? ?? ?? ?? EB 24 49 63 DC 48 8B BC DD 48 01 00 00 48 85 FF 74 11 E8 ?? ?? ?? ?? 48 C7 84 DD 48 01 00 }
	condition:
		$pattern
}

rule gnu_special_b5aa20479f3519978400e7802cdd1fcd {
	meta:
		aliases = "gnu_special"
		type = "func"
		size = "1602"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 49 89 D5 41 54 49 89 FC 55 48 89 F5 53 48 83 EC 58 48 8B 1E 80 3B 5F 0F 84 A5 00 00 00 BF ?? ?? ?? ?? B9 08 00 00 00 48 89 DE F3 A6 0F 84 A0 01 00 00 BF ?? ?? ?? ?? B9 03 00 00 00 48 89 DE F3 A6 75 67 0F B6 43 03 3C 69 0F 94 C2 3C 66 0F 85 16 02 00 00 84 D2 0F 85 16 02 00 00 41 BE ?? ?? ?? ?? 48 8D 43 04 48 89 45 00 0F B6 43 04 3C 51 0F 84 34 03 00 00 3C 74 0F 84 4C 03 00 00 3C 4B 0F 84 24 03 00 00 4C 89 EA 48 89 EE 4C 89 E7 E8 96 CE FF FF 89 C3 85 DB 74 10 48 8B 45 00 80 38 00 0F 84 FB 03 00 00 0F 1F 00 31 DB 48 83 C4 58 89 D8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 0F 1F 44 00 00 }
	condition:
		$pattern
}

rule floatformat_from_double_58fa14457b8a59f5d0ce9d8515ef0c6b {
	meta:
		aliases = "floatformat_from_double"
		type = "func"
		size = "671"
		objfiles = "floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 49 89 D5 41 54 55 48 89 FD 53 48 83 EC 28 8B 57 04 4C 89 EF F2 0F 10 06 31 F6 C1 EA 03 F2 0F 11 04 24 E8 ?? ?? ?? ?? 66 0F 57 C9 F2 0F 10 04 24 66 0F 2E C8 0F 87 F0 01 00 00 66 0F 2E C1 7A 1A 75 18 48 83 C4 28 5B 5D 41 5C 41 5D 41 5E 41 5F C3 66 0F 1F 84 00 00 00 00 00 66 0F 2E C0 0F 8A 96 01 00 00 66 0F 28 C8 F2 0F 58 C8 66 0F 2E C8 0F 8B 54 01 00 00 48 8D 7C 24 1C E8 ?? ?? ?? ?? 8B 5C 24 1C 8B 45 14 F2 0F 11 04 24 01 D8 83 F8 01 0F 8E D3 01 00 00 44 8D 48 FF 8B 4D 0C 8B 55 04 44 8B 45 10 8B 75 00 4C 89 EF 4D 63 C9 E8 B7 FB FF FF F2 0F 10 04 24 44 8B 65 20 44 8B 7D 1C 49 BE }
	condition:
		$pattern
}

rule memcmp_7063472372ec2530a20570ed1c90e1cd {
	meta:
		aliases = "__GI_memcmp, bcmp, memcmp"
		type = "func"
		size = "728"
		objfiles = "memcmp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 49 89 D5 41 54 55 53 48 83 EC 08 48 83 FA 0F 77 20 E9 A7 02 00 00 0F B6 06 0F B6 17 48 29 C2 48 89 D0 0F 85 88 02 00 00 48 FF C7 48 FF C6 49 FF CD 40 F6 C6 07 49 89 F7 75 DC 48 89 F8 49 89 FE 83 E0 07 0F 85 D8 00 00 00 4C 89 E9 48 C1 E9 03 48 89 C8 83 E0 03 48 83 F8 01 74 46 72 33 48 83 F8 03 48 8B 16 48 8B 07 74 14 49 89 C1 48 83 EF 10 48 89 D0 48 83 EE 10 48 83 C1 02 EB 67 49 89 C2 49 89 D0 48 83 EF 08 48 83 EE 08 48 FF C1 EB 47 48 85 C9 0F 84 E8 01 00 00 48 8B 17 48 8B 06 EB 1E 48 FF C9 4C 8B 17 4C 8B 06 74 60 48 83 C7 08 48 83 C6 08 4D 39 C2 48 8B 17 48 8B 06 75 56 48 39 }
	condition:
		$pattern
}

rule demangle_function_name_8888ded622679bdc04de72b8c789d827 {
	meta:
		aliases = "demangle_function_name"
		type = "func"
		size = "1160"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 49 89 F5 41 54 49 89 FC 55 48 89 CD 53 48 89 D3 48 89 CA 48 83 EC 48 48 8B 36 48 29 F2 85 D2 0F 85 4D 01 00 00 BE 01 00 00 00 48 89 DF E8 08 C1 FF FF 48 8B 43 08 C6 00 00 41 F7 04 24 00 10 00 00 48 8D 45 02 49 89 45 00 74 0A 80 7D 02 58 0F 84 4D 01 00 00 41 F7 04 24 00 3C 00 00 48 8B 2B 74 45 BF ?? ?? ?? ?? B9 05 00 00 00 48 89 EE F3 A6 75 1F 41 83 44 24 38 01 48 89 6B 08 48 83 C4 48 5B 5D 41 5C 41 5D 41 5E 41 5F C3 66 0F 1F 44 00 00 BF ?? ?? ?? ?? B9 05 00 00 00 48 89 EE F3 A6 0F 84 DB 00 00 00 4C 8B 6B 08 44 0F B6 75 00 49 29 ED 49 83 FD 02 0F 8E 9D 00 00 00 41 80 FE 6F 0F }
	condition:
		$pattern
}

rule partition_print_c4cc150dbe15d72cbd802630a6a6fd0d {
	meta:
		aliases = "partition_print"
		type = "func"
		size = "452"
		objfiles = "partition@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 49 89 F5 41 54 55 48 8D 6F 08 53 48 83 EC 38 8B 07 48 89 74 24 18 48 63 D8 41 89 C7 89 44 24 2C 48 89 DF E8 ?? ?? ?? ?? 31 F6 48 89 DA 48 89 C7 49 89 C4 E8 ?? ?? ?? ?? 48 8D 3C 9D 00 00 00 00 E8 ?? ?? ?? ?? 4C 89 EE BF 5B 00 00 00 49 89 C6 E8 ?? ?? ?? ?? 45 85 FF 48 89 6C 24 20 48 C7 44 24 10 00 00 00 00 0F 8E FF 00 00 00 66 0F 1F 44 00 00 48 8B 7C 24 10 41 80 3C 3C 00 89 F8 0F 85 CD 00 00 00 48 8B 4C 24 20 48 63 11 48 8D 14 52 8B 5C D5 10 85 DB 0F 8E FC 00 00 00 31 D2 0F 1F 40 00 41 89 04 96 48 98 48 B9 AB AA AA AA AA AA AA AA 41 C6 04 04 01 48 8D 04 40 48 83 C2 01 48 89 4C }
	condition:
		$pattern
}

rule writeunix_6d4572c9273fb2e388fa28c183fb3cb4 {
	meta:
		aliases = "writeunix"
		type = "func"
		size = "262"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 49 89 FD 41 54 41 89 D4 55 48 89 F5 53 89 D3 48 83 EC 68 E9 CE 00 00 00 45 8B 75 00 E8 ?? ?? ?? ?? 89 44 24 50 E8 ?? ?? ?? ?? 89 44 24 54 E8 ?? ?? ?? ?? 48 8D 74 24 50 BA 0C 00 00 00 BF ?? ?? ?? ?? 89 44 24 58 E8 ?? ?? ?? ?? 48 63 C3 C7 05 ?? ?? ?? ?? 01 00 00 00 C7 05 ?? ?? ?? ?? 02 00 00 00 48 89 44 24 48 48 8D 44 24 40 48 C7 05 ?? ?? ?? ?? 1C 00 00 00 48 89 6C 24 40 48 C7 44 24 18 01 00 00 00 48 89 44 24 10 48 C7 04 24 00 00 00 00 C7 44 24 08 00 00 00 00 48 C7 44 24 20 ?? ?? ?? ?? 48 C7 44 24 28 20 00 00 00 C7 44 24 30 00 00 00 00 31 D2 48 89 E6 44 89 F7 E8 ?? ?? ?? ?? 85 }
	condition:
		$pattern
}

rule do_type_792daab5eb62ac05cd5c7c941c97ff01 {
	meta:
		aliases = "do_type"
		type = "func"
		size = "3526"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 49 89 FD 41 54 45 31 E4 55 BD 01 00 00 00 53 48 89 F3 48 83 EC 68 48 C7 42 10 00 00 00 00 48 C7 42 08 00 00 00 00 48 89 14 24 48 C7 44 24 30 00 00 00 00 48 C7 44 24 28 00 00 00 00 48 C7 44 24 20 00 00 00 00 48 C7 02 00 00 00 00 66 0F 1F 44 00 00 85 ED 0F 95 C1 31 C0 85 C0 0F 85 A9 02 00 00 84 C9 0F 84 A1 02 00 00 4C 8B 3B 45 0F B6 37 41 8D 46 BF 3C 34 0F 87 7E 02 00 00 0F B6 C0 FF 24 C5 ?? ?? ?? ?? 0F 1F 40 00 41 F6 45 00 02 74 59 48 8B 44 24 28 48 39 44 24 20 45 89 F2 74 16 48 8D 7C 24 20 BE ?? ?? ?? ?? E8 6B E2 FF FF 4C 8B 3B 45 0F B6 17 41 0F BE FA E8 DB DE FF FF 89 C7 E8 }
	condition:
		$pattern
}

rule dupargv_f8de52005b2229397e16f31a78a6b5bf {
	meta:
		aliases = "dupargv"
		type = "func"
		size = "234"
		objfiles = "argv@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 49 89 FD 41 54 55 53 48 83 EC 08 48 85 FF 0F 84 8C 00 00 00 4C 8B 3F 4D 85 FF 0F 84 91 00 00 00 48 8D 5F 08 31 D2 48 89 D8 90 48 83 C0 08 83 C2 01 48 83 78 F8 00 75 F2 8D 7A 01 48 63 FF 48 C1 E7 03 E8 ?? ?? ?? ?? 48 85 C0 49 89 C6 74 51 4D 89 EC 31 ED EB 26 0F 1F 40 00 49 8B 34 24 48 89 DD 49 89 DC 48 89 C7 48 83 C3 08 4C 29 ED E8 ?? ?? ?? ?? 4C 8B 7B F8 4D 85 FF 74 4E 4C 89 FF E8 ?? ?? ?? ?? 8D 78 01 48 63 FF E8 ?? ?? ?? ?? 48 85 C0 49 89 04 2E 75 C2 4C 89 F7 E8 ?? ?? ?? ?? 48 83 C4 08 31 C0 5B 5D 41 5C 41 5D 41 5E 41 5F C3 BF 08 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 49 89 C6 74 }
	condition:
		$pattern
}

rule _ppfs_parsespec_774d3bacb0dc6b58c8fc86f652d2d174 {
	meta:
		aliases = "_ppfs_parsespec"
		type = "func"
		size = "1102"
		objfiles = "_ppfs_parsespec@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 49 89 FD 41 54 55 53 48 83 EC 68 C7 44 24 50 00 00 00 00 C7 44 24 54 00 00 00 00 C7 44 24 30 08 00 00 00 C7 44 24 34 08 00 00 00 8B 47 1C 89 44 24 0C 44 8B 4F 14 41 81 E1 80 00 00 00 75 05 48 8B 0F EB 42 45 31 C0 49 63 D0 49 8B 4D 00 48 8D 34 95 00 00 00 00 8B 44 0E FC 88 44 14 10 40 88 C7 0F BE C0 3B 44 0E FC 0F 85 C8 03 00 00 40 84 FF 74 09 41 FF C0 41 83 F8 1F 76 CB 48 8D 4C 24 11 C6 44 24 2F 00 45 31 C0 45 31 D2 83 CB FF 41 BB 00 00 00 80 EB 03 48 89 E9 80 39 2A 48 89 CD 75 13 44 89 C0 48 8D 69 01 F7 D8 48 98 C7 44 84 30 00 00 00 00 31 FF EB 16 81 FF FE 0F 00 00 7F 0B 6B }
	condition:
		$pattern
}

rule __psfs_do_numeric_dbc85d094ff51a20d46f4475923cc0a3 {
	meta:
		aliases = "__psfs_do_numeric"
		type = "func"
		size = "1077"
		objfiles = "__psfs_do_numeric@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 49 89 FD 41 54 55 53 48 89 F3 48 81 EC E8 00 00 00 8B 47 68 89 44 24 18 FF C8 83 7C 24 18 01 48 98 44 8A B0 ?? ?? ?? ?? 75 56 BD ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 85 C0 78 08 0F B6 45 00 3B 03 74 16 48 89 DF E8 ?? ?? ?? ?? 48 81 FD ?? ?? ?? ?? 76 2C E9 BB 03 00 00 48 FF C5 80 7D 00 00 75 CD 41 80 7D 70 00 0F 84 AE 03 00 00 41 FF 45 60 41 8B 75 64 31 D2 49 8B 7D 50 E9 77 01 00 00 48 89 DF E8 ?? ?? ?? ?? 8B 13 83 C8 FF 85 D2 0F 88 88 03 00 00 83 FA 2B 74 0A 83 FA 2D 4C 8D 64 24 30 75 11 48 89 DF 88 54 24 30 E8 ?? ?? ?? ?? 4C 8D 64 24 31 41 F6 C6 EF 75 53 83 3B 30 75 46 48 89 }
	condition:
		$pattern
}

rule getsubopt_91b965e06dd1547292c2a6e65ba50cb6 {
	meta:
		aliases = "getsubopt"
		type = "func"
		size = "237"
		objfiles = "getsubopt@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 83 CE FF 41 55 41 54 55 53 48 83 EC 18 48 89 7C 24 10 48 89 74 24 08 48 89 14 24 4C 8B 27 41 80 3C 24 00 0F 84 AD 00 00 00 BE 2C 00 00 00 4C 89 E7 E8 ?? ?? ?? ?? 48 89 C2 48 89 C3 BE 3D 00 00 00 4C 29 E2 4C 89 E7 49 89 DD E8 ?? ?? ?? ?? 48 85 C0 4C 0F 45 E8 45 31 F6 4D 89 EF 4D 29 E7 EB 46 4C 89 FA 48 89 EE 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 75 31 42 80 7C 3D 00 00 75 29 49 8D 55 01 31 C0 49 39 DD 48 0F 45 C2 48 8B 14 24 48 89 02 80 3B 00 74 06 C6 03 00 48 FF C3 48 8B 44 24 10 48 89 18 EB 32 41 FF C6 48 8B 54 24 08 49 63 C6 48 8B 2C C2 48 85 ED 75 A9 48 8B 04 24 4C 89 20 80 3B 00 74 }
	condition:
		$pattern
}

rule cplus_demangle_opname_c6bc27e4ba486484a99b89b1337dc9c3 {
	meta:
		aliases = "cplus_demangle_opname"
		type = "func"
		size = "1036"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 89 D6 41 55 41 54 49 89 FC 55 48 89 F5 53 48 81 EC B8 00 00 00 48 8D 5C 24 40 E8 ?? ?? ?? ?? B9 0E 00 00 00 49 89 C5 48 89 DF 31 C0 C6 45 00 00 F3 48 AB 41 0F B6 04 24 44 89 74 24 40 3C 5F 0F 84 86 00 00 00 41 83 FD 02 7E 60 3C 6F 0F 84 08 01 00 00 41 83 FD 04 7E 52 BA 04 00 00 00 BE ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 75 3C 41 0F BE 74 24 04 BF ?? ?? ?? ?? 49 83 C4 05 E8 ?? ?? ?? ?? 48 85 C0 74 23 48 8D 54 24 20 48 8D 74 24 18 48 89 DF 4C 89 64 24 18 E8 0C E9 FF FF 85 C0 75 48 0F 1F 84 00 00 00 00 00 31 ED 48 89 DF E8 C6 C6 FF FF 48 81 C4 B8 00 00 00 89 E8 5B 5D 41 5C 41 }
	condition:
		$pattern
}

rule _dl_lookup_hash_9abc74637f7519125c0fbb1b087671c0 {
	meta:
		aliases = "_dl_lookup_hash"
		type = "func"
		size = "324"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 BE FF FF FF FF 41 55 49 89 D5 41 54 49 89 F4 55 53 48 83 EC 20 89 4C 24 0C 83 E1 02 48 89 7C 24 10 89 4C 24 08 E9 E4 00 00 00 49 8B 1C 24 F6 43 49 01 75 23 4D 85 ED 74 1E 49 39 DD 74 19 49 8B 45 68 EB 09 48 39 58 08 74 0D 48 8B 00 48 85 C0 75 F2 E9 B2 00 00 00 83 7C 24 08 00 74 0A 83 7B 30 01 0F 84 A1 00 00 00 8B 7B 50 85 FF 0F 84 96 00 00 00 48 8B 83 B0 00 00 00 B9 FF FF FF FF 49 39 CE 48 89 44 24 18 75 34 48 8B 74 24 10 31 C9 EB 22 0F B6 D0 48 C1 E1 04 48 FF C6 48 01 CA 48 89 D0 25 00 00 00 F0 48 89 C1 48 C1 E8 18 48 31 D1 48 31 C1 8A 06 84 C0 75 D8 41 89 CE 89 FA 4C 89 F0 4C }
	condition:
		$pattern
}

rule demangle_template_0fd326e360486c904f52480694fe5ba5 {
	meta:
		aliases = "demangle_template"
		type = "func"
		size = "1735"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 45 89 C6 41 55 49 89 D5 41 54 49 89 FC 55 48 89 F5 53 48 83 EC 78 48 8B 06 45 85 C0 44 89 4C 24 18 48 8D 50 01 48 89 16 0F 84 46 01 00 00 80 78 01 7A 48 89 CB 0F 84 B1 00 00 00 48 89 F7 E8 29 E8 FF FF 85 C0 89 44 24 2C 89 44 24 08 0F 8E 19 02 00 00 4C 8B 45 00 4C 89 C7 4C 89 44 24 10 E8 ?? ?? ?? ?? 48 63 54 24 08 39 C2 0F 8F FB 01 00 00 41 F6 04 24 04 4C 8B 44 24 10 74 15 BF ?? ?? ?? ?? B9 08 00 00 00 4C 89 C6 F3 A6 0F 84 64 05 00 00 4C 89 C6 4C 89 EF E8 CF ED FF FF 31 C0 48 85 DB 48 63 54 24 2C 4C 8B 45 00 74 08 85 D2 0F 85 4F 05 00 00 49 01 D0 85 C0 4C 89 45 00 0F 84 86 01 00 00 }
	condition:
		$pattern
}

rule frame_downheap_86330478c45d259a9c0200c15aac40de {
	meta:
		aliases = "frame_downheap"
		type = "func"
		size = "178"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 45 89 C6 41 55 49 89 D5 41 54 55 8D 6C 09 01 53 48 83 EC 18 44 39 C5 48 89 7C 24 10 48 89 74 24 08 7D 7C 41 89 CF EB 3C 66 66 66 90 49 63 C7 49 8B 14 24 48 8B 7C 24 10 49 8D 5C C5 00 48 8B 33 FF 54 24 08 85 C0 79 57 49 8B 04 24 48 8B 13 41 89 EF 48 89 03 8D 44 2D 01 49 89 14 24 41 39 C6 7E 3D 89 C5 8D 5D 01 48 63 C5 4D 8D 64 C5 00 41 39 DE 7E B8 48 C1 E0 03 48 8B 7C 24 10 4D 8D 64 05 00 4A 8B 54 28 08 49 8B 34 24 FF 54 24 08 85 C0 79 99 48 63 C3 89 DD 4D 8D 64 C5 00 EB 8D 48 83 C4 18 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule __fake_pread_write_782cc1a0fe853f98e6fa6d52d8e225e4 {
	meta:
		aliases = "__fake_pread_write"
		type = "func"
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
		type = "func"
		size = "165"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 45 89 C6 41 55 49 89 F5 31 F6 41 54 41 89 FC 55 48 89 D5 BA 01 00 00 00 53 48 89 CB 48 83 EC 08 E8 ?? ?? ?? ?? 48 83 F8 FF 49 89 C7 74 60 31 D2 48 89 DE 44 89 E7 E8 ?? ?? ?? ?? 48 FF C0 74 4E 41 FF CE 75 10 48 89 EA 4C 89 EE 44 89 E7 E8 ?? ?? ?? ?? EB 0E 48 89 EA 4C 89 EE 44 89 E7 E8 ?? ?? ?? ?? 48 89 C5 E8 ?? ?? ?? ?? 31 D2 4C 89 FE 44 89 E7 48 89 C3 44 8B 28 E8 ?? ?? ?? ?? 48 FF C0 75 06 48 83 FD FF 75 05 44 89 2B EB 04 48 83 CD FF 5A 5B 48 89 E8 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule setvbuf_7cb4a7245b056a6f8c66df0039910495 {
	meta:
		aliases = "__GI_setvbuf, setvbuf"
		type = "func"
		size = "275"
		objfiles = "setvbuf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 CE 41 55 41 89 D5 41 54 49 89 F4 55 48 89 FD 53 48 83 EC 28 44 8B 7F 50 45 85 FF 75 1C 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 41 83 FD 02 76 13 83 CB FF E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 98 00 00 00 8B 55 00 83 CB FF F7 C2 CF 08 00 00 0F 85 86 00 00 00 44 89 E8 80 E6 FC C1 E0 08 09 C2 41 83 FD 02 66 89 55 00 74 05 4D 85 F6 75 0A 45 31 E4 45 31 F6 31 DB EB 28 31 DB 4D 85 E4 75 21 48 8B 45 10 48 2B 45 08 4C 39 F0 74 4C 4C 89 F7 E8 ?? ?? ?? ?? 48 85 C0 74 3F 49 89 C4 66 BB 00 40 8B 45 00 F6 C4 40 74 10 48 8B 7D 08 80 E4 BF 66 89 45 }
	condition:
		$pattern
}

rule ptsname_r_f1876e4c3f8397c4312a676a2c93ea10 {
	meta:
		aliases = "__GI_ptsname_r, ptsname_r"
		type = "func"
		size = "171"
		objfiles = "ptsname@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 D6 41 55 49 89 F5 41 54 55 53 89 FB 48 83 EC 18 E8 ?? ?? ?? ?? 48 8D 54 24 0C 44 8B 38 49 89 C4 BE 30 54 04 80 31 C0 89 DF E8 ?? ?? ?? ?? 85 C0 75 57 48 63 74 24 0C 48 8D 5C 24 0B 31 C9 BA F6 FF FF FF 48 89 DF E8 ?? ?? ?? ?? 48 29 C3 48 89 C5 48 83 C3 0A 49 39 DE 73 0F B8 22 00 00 00 41 C7 04 24 22 00 00 00 EB 2D BE ?? ?? ?? ?? 4C 89 EF E8 ?? ?? ?? ?? 48 89 EE 4C 89 EF E8 ?? ?? ?? ?? 31 C0 45 89 3C 24 EB 0D 41 C7 04 24 19 00 00 00 B8 19 00 00 00 48 83 C4 18 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule _time_mktime_tzi_aa3b1b0bb973830621c2484406dcb3c6 {
	meta:
		aliases = "_time_mktime_tzi"
		type = "func"
		size = "608"
		objfiles = "_time_mktime_tzi@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 D6 BA 38 00 00 00 41 55 41 54 55 53 48 81 EC 88 00 00 00 4C 8D 64 24 40 48 89 7C 24 30 89 74 24 2C 48 89 FE 4C 89 E7 E8 ?? ?? ?? ?? 31 C0 41 80 7E 38 00 C7 44 24 3C 00 00 00 00 0F 45 44 24 60 85 C0 89 44 24 60 74 19 85 C0 0F 9F C0 0F B6 C0 8D 44 00 FF 41 89 44 24 20 C7 44 24 3C 01 00 00 00 41 8B 4C 24 14 BF 90 01 00 00 45 8B 4C 24 10 41 BA 0C 00 00 00 49 8D 6C 24 14 4D 8D 6C 24 18 49 8D 5C 24 1C 4D 8D 44 24 10 89 C8 99 F7 FF 89 C6 41 89 44 24 18 44 89 C8 99 41 F7 FA 41 89 C2 41 89 44 24 1C 6B C0 0C 41 8D 0C 0A 69 F6 90 01 00 00 41 29 C1 29 F1 45 85 C9 44 89 C8 41 89 4C 24 14 }
	condition:
		$pattern
}

rule vfscanf_24901e348d1da1c6956efee386e35f41 {
	meta:
		aliases = "__GI_vfscanf, vfscanf"
		type = "func"
		size = "1688"
		objfiles = "vfscanf@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 D6 BA 48 00 00 00 41 55 41 54 55 48 89 F5 31 F6 53 48 81 EC 68 02 00 00 4C 8D A4 24 10 01 00 00 48 89 3C 24 C7 84 24 58 01 00 00 FF FF FF FF 4C 89 E7 E8 ?? ?? ?? ?? 48 8B 04 24 8B 40 50 85 C0 89 44 24 0C 75 25 48 8B 1C 24 48 8D BC 24 30 02 00 00 BE ?? ?? ?? ?? 48 83 C3 58 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8D 9C 24 90 01 00 00 48 8B 34 24 41 B7 01 48 89 DF 49 89 DD E8 ?? ?? ?? ?? 48 8B 84 24 98 01 00 00 48 C7 84 24 C0 01 00 00 ?? ?? ?? ?? 8A 40 03 C7 84 24 70 01 00 00 00 00 00 00 88 84 24 AC 01 00 00 48 8B 84 24 C8 01 00 00 48 89 84 24 D8 01 00 00 E9 2B 05 00 }
	condition:
		$pattern
}

rule inet_ntop_08f24476d56bb0915b61bd975581b1b1 {
	meta:
		aliases = "__GI_inet_ntop, inet_ntop"
		type = "func"
		size = "518"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 F6 41 55 41 54 55 53 48 83 EC 68 83 FF 02 48 89 54 24 08 89 4C 24 04 74 0B 83 FF 0A 0F 85 BF 01 00 00 EB 16 8B 54 24 04 48 8B 74 24 08 4C 89 F7 E8 BA FE FF FF E9 A2 01 00 00 48 8D 7C 24 40 BA 20 00 00 00 31 F6 E8 ?? ?? ?? ?? 31 C9 89 C8 BE 02 00 00 00 48 63 F9 99 83 C1 02 F7 FE 42 0F B6 54 37 01 48 63 F0 41 0F B6 04 3E C1 E0 08 09 D0 83 F9 0F 89 44 B4 40 7E D4 41 83 CC FF 31 C9 44 89 E2 44 89 E6 EB 36 48 63 C1 83 7C 84 40 00 75 12 83 FA FF 75 09 89 CA BB 01 00 00 00 EB 1C FF C3 EB 18 83 FA FF 74 13 41 83 FC FF 74 05 44 39 EB 7E 06 41 89 DD 41 89 D4 89 F2 FF C1 83 F9 07 7E C5 }
	condition:
		$pattern
}

rule __decode_answer_8dd45bc6d84d74e6f50a45327480801a {
	meta:
		aliases = "__decode_answer"
		type = "func"
		size = "238"
		objfiles = "decodea@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 FE 41 55 41 54 41 89 F4 55 48 89 CD B9 00 01 00 00 53 89 D3 48 81 EC 18 01 00 00 4C 8D 7C 24 10 4C 89 FA E8 ?? ?? ?? ?? 85 C0 89 C1 0F 88 A2 00 00 00 44 8D 69 0A 44 29 E3 44 29 EB 89 5C 24 0C 79 07 89 D9 E9 8B 00 00 00 46 8D 24 21 4C 89 FF E8 ?? ?? ?? ?? 49 63 DC 48 89 45 00 41 83 C4 0A 49 8D 1C 1E 0F B6 03 0F B6 53 01 48 8D 4B 04 C1 E0 08 09 C2 89 55 08 0F B6 43 02 0F B6 53 03 C1 E0 08 09 C2 89 55 0C 0F B6 43 04 0F B6 51 03 C1 E0 18 09 C2 0F B6 41 01 C1 E0 10 09 C2 0F B6 41 02 83 C9 FF C1 E0 08 09 C2 89 55 10 0F B6 43 08 0F B6 53 09 48 83 C3 0A 44 89 65 20 48 89 5D 18 C1 E0 }
	condition:
		$pattern
}

rule getaddrinfo_5936b69b83ef90bd4e94577310c5f896 {
	meta:
		aliases = "__GI_getaddrinfo, getaddrinfo"
		type = "func"
		size = "674"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 FE 41 55 41 54 49 89 D4 55 48 89 F5 53 48 81 EC 88 00 00 00 48 85 FF 48 89 4C 24 08 48 C7 44 24 78 00 00 00 00 74 12 80 3F 2A 75 0D 80 7F 01 00 B8 00 00 00 00 4C 0F 44 F0 48 85 ED 74 13 80 7D 00 2A 75 0D 80 7D 01 00 B8 00 00 00 00 48 0F 44 E8 4C 89 F0 48 09 E8 0F 84 23 02 00 00 4D 85 E4 75 17 48 8D 5C 24 30 BA 30 00 00 00 31 F6 48 89 DF 49 89 DC E8 ?? ?? ?? ?? 41 8B 04 24 A9 C0 FB FF FF 0F 85 FF 01 00 00 A8 02 74 09 4D 85 F6 0F 84 F2 01 00 00 48 85 ED 74 68 80 7D 00 00 74 62 48 8D 74 24 70 BA 0A 00 00 00 48 89 EF 48 89 6C 24 60 E8 ?? ?? ?? ?? 89 44 24 68 48 8B 44 24 70 80 38 }
	condition:
		$pattern
}

rule getdelim_7c5e4f4b453dd30070e871c8be556281 {
	meta:
		aliases = "__GI_getdelim, getdelim"
		type = "func"
		size = "271"
		objfiles = "getdelim@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 FE 41 55 41 54 49 89 F4 55 48 89 CD 53 48 83 EC 38 48 85 FF 89 54 24 0C 74 0A 48 85 F6 74 05 48 85 C9 75 14 48 83 CD FF E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 BF 00 00 00 44 8B 79 50 45 85 FF 75 1E 48 8D 59 58 48 8D 7C 24 10 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 49 8B 1E 48 85 DB 75 08 49 C7 04 24 00 00 00 00 41 BD 01 00 00 00 49 8B 04 24 49 39 C5 72 22 48 8D 70 40 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 75 06 48 83 CD FF EB 4E 49 83 04 24 40 48 89 C3 49 89 06 48 8B 45 18 48 3B 45 28 73 0C 0F B6 10 48 FF C0 48 89 45 18 EB 0F 48 89 EF E8 ?? ?? ?? ?? 83 F8 FF 89 }
	condition:
		$pattern
}

rule classify_object_over_fdes_57000c67157945e36e9c76c713abff0a {
	meta:
		aliases = "classify_object_over_fdes"
		type = "func"
		size = "335"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 FE 41 55 41 54 55 48 89 F5 53 48 83 EC 28 44 8B 06 48 C7 44 24 08 00 00 00 00 45 85 C0 0F 84 F3 00 00 00 48 8D 44 24 20 45 31 ED 45 31 FF 48 C7 44 24 10 00 00 00 00 48 89 04 24 8B 45 04 85 C0 0F 84 BB 00 00 00 48 8D 5D 04 48 98 45 0F B6 E7 48 29 C3 49 39 DD 74 52 48 89 DF E8 DA FB FF FF 44 0F B6 E0 4C 89 F6 41 89 C7 44 89 E7 E8 C8 F9 FF FF 48 89 44 24 10 41 0F B7 46 20 66 25 F8 07 66 3D F8 07 0F 84 A0 00 00 00 41 0F B7 46 20 49 89 DD 66 C1 E8 03 0F B6 C0 41 39 C7 74 0C 41 80 4E 20 04 66 66 66 90 66 66 90 48 8B 0C 24 48 8B 74 24 10 48 8D 55 08 44 89 E7 E8 CB F9 FF FF 44 89 E7 }
	condition:
		$pattern
}

rule strptime_e55ab1fa86405a6e32342f25de9cba19 {
	meta:
		aliases = "__GI_strptime, strptime"
		type = "func"
		size = "1056"
		objfiles = "strptime@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 FE 41 55 41 54 55 53 48 81 EC 98 00 00 00 48 89 54 24 08 31 D2 48 63 C2 FF C2 83 FA 0C C7 44 84 20 00 00 00 80 7E EE 49 89 F5 C7 44 24 14 00 00 00 00 41 8A 45 00 84 C0 75 50 83 7C 24 14 00 75 39 83 7C 24 38 07 8B 44 24 14 0F 45 44 24 38 31 C9 89 44 24 38 48 63 D1 8B 44 94 20 3D 00 00 00 80 74 08 48 8B 5C 24 08 89 04 93 FF C1 83 F9 07 7E E3 4C 89 F7 E9 8B 03 00 00 FF 4C 24 14 48 63 44 24 14 4C 8B 6C C4 60 EB A8 3C 25 0F 85 3B 03 00 00 49 FF C5 41 8A 45 00 3C 25 0F 84 2C 03 00 00 3C 4F 74 09 3C 45 40 B6 3F 75 11 EB 04 B0 40 EB 02 B0 80 83 C8 3F 49 FF C5 40 88 C6 41 8A 55 00 84 }
	condition:
		$pattern
}

rule __decode_dotted_d7a4ca697b4b9712e95aad1fe0ce83f3 {
	meta:
		aliases = "__decode_dotted"
		type = "func"
		size = "244"
		objfiles = "decoded@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 FE 41 55 41 54 55 53 48 83 EC 18 48 85 FF 48 89 54 24 10 89 4C 24 0C 0F 84 BF 00 00 00 41 B0 01 45 31 ED 31 C9 E9 97 00 00 00 0F B6 D8 41 80 F8 01 8D 6E 01 89 D8 41 83 DD FF 25 C0 00 00 00 3D C0 00 00 00 75 22 48 63 C5 41 80 F8 01 89 DE 41 0F B6 04 06 41 83 DD FF 83 E6 3F C1 E6 08 41 89 CC 45 31 C0 09 C6 EB 56 44 8D 3C 0B 45 8D 67 01 44 3B 64 24 0C 73 65 89 CF 48 03 7C 24 10 48 63 F5 49 8D 34 36 48 63 D3 44 88 04 24 E8 ?? ?? ?? ?? 44 8A 04 24 41 8D 44 1D 00 8D 34 2B 48 8B 4C 24 10 44 89 FA 45 84 C0 44 0F 45 E8 48 63 C6 41 80 3C 06 01 19 C0 F7 D0 83 E0 2E 88 04 11 44 89 E1 48 }
	condition:
		$pattern
}

rule __prefix_array_e9e73f7a1548e407bee881cca40d3aef {
	meta:
		aliases = "__prefix_array"
		type = "func"
		size = "201"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 FE 41 55 41 54 55 53 48 83 EC 18 48 89 74 24 10 48 89 54 24 08 E8 ?? ?? ?? ?? 48 83 F8 01 49 89 C5 75 0B 45 31 ED 41 80 3E 2F 41 0F 95 C5 45 31 E4 EB 78 48 8B 44 24 10 4A 8D 2C E0 48 8B 7D 00 E8 ?? ?? ?? ?? 49 8D 7C 05 02 4C 8D 78 01 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 75 1F EB 11 48 8B 44 24 10 49 FF CC 4A 8B 3C E0 E8 ?? ?? ?? ?? 4D 85 E4 75 EA B8 01 00 00 00 EB 3A 4C 89 EA 4C 89 F6 48 89 C7 E8 ?? ?? ?? ?? C6 00 2F 48 8B 75 00 48 8D 78 01 4C 89 FA 49 FF C4 E8 ?? ?? ?? ?? 48 8B 7D 00 E8 ?? ?? ?? ?? 48 89 5D 00 4C 3B 64 24 08 72 81 31 C0 48 83 C4 18 5B 5D 41 5C 41 5D 41 5E 41 5F }
	condition:
		$pattern
}

rule __res_search_94578a5cb129e9df4a7053c12cd0551c {
	meta:
		aliases = "__res_search"
		type = "func"
		size = "727"
		objfiles = "res_query@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 FE 41 55 41 54 55 53 48 83 EC 58 48 8D 5C 24 30 89 74 24 1C 89 54 24 18 BE ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 4C 24 10 48 89 DF 44 89 44 24 0C E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 DF 4C 8B 25 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4D 85 F6 74 17 48 83 7C 24 10 00 74 0F 41 80 E4 01 75 19 E8 ?? ?? ?? ?? FF C0 75 10 E8 ?? ?? ?? ?? C7 00 FF FF FF FF E9 1B 02 00 00 E8 ?? ?? ?? ?? 48 89 44 24 20 C7 00 00 00 00 00 45 31 FF E8 ?? ?? ?? ?? 4C 89 F2 48 89 C5 C7 00 01 00 00 00 EB 0E 3C 2E 0F 94 C0 48 FF C2 0F B6 C0 41 01 C7 8A 02 84 C0 75 EC 45 31 ED 4C 39 F2 76 0B 45 31 }
	condition:
		$pattern
}

rule clntraw_call_5f737ec0cce3144153d49f69609ee462 {
	meta:
		aliases = "clntraw_call"
		type = "func"
		size = "475"
		objfiles = "clnt_raw@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 FE 41 55 41 BD 10 00 00 00 41 54 55 53 48 81 EC C8 00 00 00 48 89 74 24 38 48 89 54 24 30 48 89 4C 24 28 4C 89 44 24 20 4C 89 4C 24 18 E8 ?? ?? ?? ?? 48 8B 98 C0 00 00 00 48 85 DB 4C 8D 63 18 0F 84 7A 01 00 00 48 8D 44 24 58 48 8D AB A8 22 00 00 4C 8D 7C 24 40 48 89 44 24 08 48 8B 43 20 31 F6 4C 89 E7 C7 43 18 00 00 00 00 FF 50 28 48 FF 45 00 48 89 EE 4C 89 E7 48 8B 43 20 8B 93 C0 22 00 00 FF 50 18 85 C0 0F 84 11 01 00 00 48 8B 43 20 48 8D 74 24 38 4C 89 E7 FF 50 08 85 C0 0F 84 FA 00 00 00 49 8B 3E 4C 89 E6 48 8B 47 38 FF 50 08 85 C0 0F 84 E5 00 00 00 31 C0 48 8B 74 24 28 4C }
	condition:
		$pattern
}

rule gethostbyname2_r_ac5f7c4680e4726bedafd7f1f3902af6 {
	meta:
		aliases = "__GI_gethostbyname2_r, gethostbyname2_r"
		type = "func"
		size = "827"
		objfiles = "gethostbyname2_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 FE 41 55 49 89 CD 41 54 4D 89 C4 55 48 89 D5 53 48 81 EC A8 00 00 00 83 FE 02 4C 89 4C 24 18 75 20 4C 8B 8C 24 E0 00 00 00 4C 8B 44 24 18 4C 89 E1 4C 89 EA 48 89 EE E8 ?? ?? ?? ?? E9 E2 02 00 00 83 FE 0A 0F 85 CD 02 00 00 E8 ?? ?? ?? ?? 48 8B 44 24 18 4D 85 F6 48 C7 00 00 00 00 00 0F 84 B3 02 00 00 E8 ?? ?? ?? ?? 44 8B 38 C7 00 00 00 00 00 4D 89 E0 48 8B 8C 24 E0 00 00 00 4C 8B 4C 24 18 48 89 EA BE 0A 00 00 00 4C 89 F7 48 89 C3 48 89 0C 24 4C 89 E9 E8 ?? ?? ?? ?? 85 C0 0F 84 7F 02 00 00 48 8B 8C 24 E0 00 00 00 8B 11 83 FA 01 74 0F 83 FA 04 74 22 FF C2 0F 85 63 02 00 00 EB 0F }
	condition:
		$pattern
}

rule _wstdio_fwrite_80a6786245faa5a27b3392fe327eaa19 {
	meta:
		aliases = "_wstdio_fwrite"
		type = "func"
		size = "250"
		objfiles = "_wfwrite@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 FE 41 55 49 89 F5 41 54 55 48 89 D5 53 48 83 EC 58 83 7A 04 FD 75 3E 48 8B 7A 18 48 8B 42 10 48 89 F3 48 29 F8 48 C1 F8 02 48 39 F0 48 0F 46 D8 48 85 DB 0F 84 A9 00 00 00 48 89 DA 4C 89 F6 E8 ?? ?? ?? ?? 48 8D 04 9D 00 00 00 00 48 01 45 18 E9 8D 00 00 00 0F B7 02 25 40 08 00 00 3D 40 08 00 00 74 14 BE 00 08 00 00 48 89 D7 45 31 E4 E8 ?? ?? ?? ?? 85 C0 75 67 4C 8D 7D 48 45 31 E4 4C 89 74 24 48 EB 54 4C 89 EA 48 8D 74 24 48 4D 89 F8 4C 29 E2 B9 40 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 83 F8 FF 48 89 C3 74 35 48 85 C0 75 0C 4B 8D 44 A6 04 B3 01 48 89 44 24 48 48 89 EA 48 89 DE 48 }
	condition:
		$pattern
}

rule hsearch_r_d5c8688b08a9c858e9619db35010632f {
	meta:
		aliases = "__GI_hsearch_r, hsearch_r"
		type = "func"
		size = "429"
		objfiles = "hsearch_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 4D 89 C6 41 55 41 54 55 53 48 83 EC 58 48 89 74 24 28 48 89 4C 24 18 48 89 74 24 50 48 89 7C 24 30 89 54 24 24 48 89 7C 24 48 E8 ?? ?? ?? ?? 89 C6 89 C1 EB 13 48 8B 5C 24 30 89 CA 89 F0 C1 E0 04 0F BE 14 13 8D 34 02 FF C9 83 F9 FF 75 E6 41 8B 46 08 31 D2 49 8B 0E 89 44 24 3C 89 F0 48 89 CB F7 74 24 3C B8 01 00 00 00 48 89 4C 24 40 85 D2 89 D5 0F 44 E8 89 E8 48 6B C0 18 48 01 C3 8B 03 85 C0 0F 84 99 00 00 00 39 E8 75 18 48 8B 73 08 48 8B 7C 24 30 E8 ?? ?? ?? ?? 85 C0 75 06 48 8D 43 08 EB 67 8B 54 24 3C 89 E8 89 EB 83 EA 02 89 D1 31 D2 F7 F1 8B 44 24 3C 44 8D 6A 01 44 29 E8 89 44 24 }
	condition:
		$pattern
}

rule do_des_7797cfa54f84183add4a68e20cfcd1cc {
	meta:
		aliases = "do_des"
		type = "func"
		size = "761"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 83 F8 00 41 89 F9 41 89 F2 49 89 CF B8 01 00 00 00 41 56 41 55 49 89 D5 41 54 55 44 89 C5 53 0F 84 C6 02 00 00 7E 0E 41 BE ?? ?? ?? ?? 41 BC ?? ?? ?? ?? EB 0E F7 DD 41 BE ?? ?? ?? ?? 41 BC ?? ?? ?? ?? 44 89 CA 4C 89 CE 41 0F B6 C1 C1 EA 18 89 C0 48 C1 EE 10 89 D2 44 89 D7 48 89 44 24 F8 81 E6 FF 00 00 00 8B 1C 95 ?? ?? ?? ?? 0B 1C 85 ?? ?? ?? ?? 4C 89 C8 C1 EF 18 0B 1C B5 ?? ?? ?? ?? 0F B6 C4 45 0F B6 DA 4D 89 D0 0B 1C 85 ?? ?? ?? ?? 89 FF 44 89 D9 49 C1 E8 10 0B 1C BD ?? ?? ?? ?? 49 89 C1 41 81 E0 FF 00 00 00 4C 89 D0 0B 1C 8D ?? ?? ?? ?? 0F B6 C4 42 0B 1C 85 ?? ?? ?? ?? 44 8B 1C 95 }
	condition:
		$pattern
}

rule authunix_create_58820913b279b8421d5eeea0ae766520 {
	meta:
		aliases = "__GI_authunix_create, authunix_create"
		type = "func"
		size = "395"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 CF 41 56 41 89 D6 41 55 41 89 F5 41 54 49 89 FC BF 48 00 00 00 55 53 48 81 EC 18 02 00 00 4C 89 44 24 08 E8 ?? ?? ?? ?? BF D0 01 00 00 48 89 C5 E8 ?? ?? ?? ?? 48 85 ED 48 89 C3 74 05 48 85 C0 75 28 48 8B 35 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 EF 31 ED E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? E9 08 01 00 00 FC 48 C7 45 38 ?? ?? ?? ?? 48 89 45 40 48 8D 78 18 BE ?? ?? ?? ?? B9 06 00 00 00 F3 A5 48 8D 70 18 48 8D 7D 18 B1 06 F3 A5 48 8D BC 24 00 02 00 00 31 F6 48 C7 40 30 00 00 00 00 E8 ?? ?? ?? ?? 48 8B 84 24 00 02 00 00 4C 89 A4 24 D8 01 00 00 4C 8D A4 24 A0 01 00 00 44 89 }
	condition:
		$pattern
}

rule pmap_getport_70eb86aa1904177286428dc5d1b44dc1 {
	meta:
		aliases = "__GI_pmap_getport, pmap_getport"
		type = "func"
		size = "282"
		objfiles = "pm_getport@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 CF 41 56 49 89 D6 BA 02 00 00 00 41 55 49 89 F5 BE A0 86 01 00 41 54 49 89 FC 55 53 48 83 EC 48 48 8B 0D ?? ?? ?? ?? 4C 8B 05 ?? ?? ?? ?? 4C 8D 4C 24 38 66 C7 44 24 3E 00 00 C7 44 24 38 FF FF FF FF 66 C7 47 02 00 6F C7 44 24 08 90 01 00 00 C7 04 24 90 01 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 0F 84 92 00 00 00 E8 ?? ?? ?? ?? 48 89 C5 48 8B 05 ?? ?? ?? ?? 45 89 FF 4C 89 6C 24 10 4C 89 74 24 18 48 8D 4C 24 10 4C 89 7C 24 20 48 C7 44 24 28 00 00 00 00 4C 8D 4C 24 3E 4C 8B 53 08 48 89 04 24 41 B8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? BA ?? ?? ?? ?? BE 03 00 00 00 48 89 DF 48 89 44 24 08 41 }
	condition:
		$pattern
}

rule htab_find_with_hash_b92e3cd2252bb59b54d0fa9dbc1b9b95 {
	meta:
		aliases = "htab_find_with_hash"
		type = "func"
		size = "317"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 D0 41 89 D7 41 56 49 89 F6 41 55 41 54 55 48 89 FD 53 44 89 FB 48 83 EC 18 8B 47 68 83 47 38 01 4C 8B 67 20 48 8B 75 18 48 C1 E0 04 48 8D B8 ?? ?? ?? ?? 44 8B 88 ?? ?? ?? ?? 8B 47 04 8B 4F 0C 49 0F AF C0 48 C1 E8 20 29 C2 D1 EA 01 D0 D3 E8 41 0F AF C1 29 C3 89 D8 4C 8B 2C C6 4D 85 ED 0F 84 B7 00 00 00 49 83 FD 01 74 37 4C 89 44 24 08 4C 89 F6 4C 89 EF FF 55 08 85 C0 0F 85 9E 00 00 00 8B 45 68 48 8B 75 18 4C 8B 44 24 08 48 C1 E0 04 48 8D B8 ?? ?? ?? ?? 44 8B 88 ?? ?? ?? ?? 8B 4F 0C 8B 47 08 45 8D 6F 01 41 83 E9 02 8B 55 3C 4C 0F AF C0 49 C1 E8 20 45 29 C7 41 D1 EF 45 01 C7 41 D3 EF }
	condition:
		$pattern
}

rule svcunix_create_2abe529156b0cd7815624d44fc9e9e0d {
	meta:
		aliases = "svcunix_create"
		type = "func"
		size = "380"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 D7 41 56 41 89 F6 41 55 45 31 ED 41 54 49 89 CC 55 89 FD 53 48 81 EC 88 00 00 00 83 FF FF C7 44 24 7C 10 00 00 00 75 29 31 D2 BE 01 00 00 00 BF 01 00 00 00 E8 ?? ?? ?? ?? 85 C0 89 C5 41 B5 01 79 0F BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 D1 00 00 00 31 F6 BA 6E 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 4C 89 E7 66 C7 04 24 01 00 E8 ?? ?? ?? ?? FF C0 48 8D 7C 24 02 4C 89 E6 89 C2 89 44 24 7C E8 ?? ?? ?? ?? 8B 54 24 7C 48 89 E6 89 EF 83 C2 02 89 54 24 7C E8 ?? ?? ?? ?? 48 8D 54 24 7C 48 89 E6 89 EF E8 ?? ?? ?? ?? 85 C0 75 10 BE 02 00 00 00 89 EF E8 ?? ?? ?? ?? 85 C0 74 22 BF ?? ?? ?? ?? 45 31 E4 E8 }
	condition:
		$pattern
}

rule svctcp_create_e445b595309b66303f96352dd7a006c2 {
	meta:
		aliases = "svctcp_create"
		type = "func"
		size = "370"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 D7 41 56 41 89 F6 41 55 45 31 ED 41 54 55 89 FD 53 48 83 EC 28 83 FF FF C7 44 24 1C 10 00 00 00 75 2C BA 06 00 00 00 BE 01 00 00 00 BF 02 00 00 00 E8 ?? ?? ?? ?? 85 C0 89 C5 41 B5 01 79 0F BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 C2 00 00 00 31 F6 BA 10 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 89 EF 48 89 E6 66 C7 04 24 02 00 E8 ?? ?? ?? ?? 85 C0 74 15 8B 54 24 1C 48 89 E6 89 EF 66 C7 44 24 02 00 00 E8 ?? ?? ?? ?? 48 8D 54 24 1C 48 89 E6 89 EF E8 ?? ?? ?? ?? 85 C0 75 10 BE 02 00 00 00 89 EF E8 ?? ?? ?? ?? 85 C0 74 22 BF ?? ?? ?? ?? 45 31 E4 E8 ?? ?? ?? ?? 45 85 ED 0F 84 9D 00 00 00 89 EF E8 ?? ?? }
	condition:
		$pattern
}

rule __encode_dotted_74997264edc053d756a2b1aaf94d2292 {
	meta:
		aliases = "__encode_dotted"
		type = "func"
		size = "162"
		objfiles = "encoded@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 D7 41 56 49 89 F6 41 55 41 54 49 89 FC 55 53 31 DB 48 83 EC 08 EB 5B BE 2E 00 00 00 4C 89 E7 E8 ?? ?? ?? ?? 48 85 C0 49 89 C5 74 07 89 C5 44 29 E5 EB 0A 4C 89 E7 E8 ?? ?? ?? ?? 89 C5 85 ED 74 4E 44 89 F8 29 D8 FF C8 39 C5 73 43 89 D8 FF C3 48 63 D5 89 DF 41 88 2C 06 4C 89 E6 49 8D 3C 3E 8D 5C 1D 00 E8 ?? ?? ?? ?? 4D 85 ED 74 10 4D 8D 65 01 4D 85 E4 74 07 41 80 3C 24 00 75 99 45 85 FF 7E 0C 89 D8 41 C6 04 06 00 8D 43 01 EB 03 83 C8 FF 5A 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule __gen_tempname_2f2f57de7d3607100837b6f31950563f {
	meta:
		aliases = "__gen_tempname"
		type = "func"
		size = "557"
		objfiles = "tempname@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 F7 41 56 41 55 41 54 55 48 89 FD 53 48 81 EC B8 00 00 00 E8 ?? ?? ?? ?? 49 89 C6 8B 00 48 89 EF 89 44 24 0C E8 ?? ?? ?? ?? 48 83 F8 05 76 27 48 8D 44 28 FA BE ?? ?? ?? ?? 48 89 04 24 48 89 C7 E8 ?? ?? ?? ?? 85 C0 75 0D C7 44 24 08 00 00 00 00 E9 A9 01 00 00 41 C7 06 16 00 00 00 E9 B2 01 00 00 31 F6 31 C0 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 41 89 C4 79 18 31 C0 BE 00 08 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 41 89 C4 78 29 48 8D B4 24 A0 00 00 00 BA 06 00 00 00 44 89 E7 E8 ?? ?? ?? ?? 44 89 E7 48 89 C3 E8 ?? ?? ?? ?? 83 FB 06 0F 84 91 00 00 00 48 8D 7C 24 10 31 F6 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule do_dlclose_295a0f4376cf85f6bb323616a09f33b9 {
	meta:
		aliases = "do_dlclose"
		type = "func"
		size = "628"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 F7 41 56 41 55 49 89 FD 41 54 55 53 48 83 EC 08 48 3B 3D ?? ?? ?? ?? 0F 84 45 02 00 00 48 8B 05 ?? ?? ?? ?? 31 D2 EB 0C 4C 39 E8 74 1E 48 89 C2 48 8B 40 08 48 85 C0 75 EF B0 01 48 C7 05 ?? ?? ?? ?? 09 00 00 00 E9 19 02 00 00 48 85 D2 49 8B 45 08 74 06 48 89 42 08 EB 07 48 89 05 ?? ?? ?? ?? 49 8B 55 00 45 31 F6 8B 42 40 66 83 F8 01 0F 84 A1 01 00 00 FF C8 4C 89 EF 66 89 42 40 E8 ?? ?? ?? ?? E9 DA 01 00 00 4C 8B 24 C7 41 8B 44 24 40 FF C8 66 85 C0 66 41 89 44 24 40 0F 85 71 01 00 00 49 83 BC 24 E8 00 00 00 00 75 0B 49 83 BC 24 50 01 00 00 00 74 33 45 85 FF 74 2E 66 41 8B 44 24 42 A8 }
	condition:
		$pattern
}

rule _dl_load_elf_shared_library_32096c60dd81564818b7e5ae74884c4d {
	meta:
		aliases = "_dl_load_elf_shared_library"
		type = "func"
		size = "2711"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 F8 B8 02 00 00 00 41 56 41 55 41 54 55 53 48 81 EC 18 02 00 00 48 89 54 24 10 48 89 74 24 18 31 D2 31 F6 48 8B 7C 24 10 0F 05 48 3D 00 F0 FF FF 76 0C F7 D8 89 05 ?? ?? ?? ?? 48 83 C8 FF 85 C0 79 10 48 C7 05 ?? ?? ?? ?? 01 00 00 00 E9 20 0A 00 00 4C 63 F8 48 8D B4 24 80 01 00 00 B8 05 00 00 00 4C 89 FF 0F 05 48 3D 00 F0 FF FF 76 0A F7 D8 89 05 ?? ?? ?? ?? EB 04 85 C0 79 0D 48 C7 05 ?? ?? ?? ?? 01 00 00 00 EB 0F 45 85 C0 74 19 F6 84 24 99 01 00 00 08 75 0F 4C 89 FF B8 03 00 00 00 0F 05 E9 A7 07 00 00 48 8B 2D ?? ?? ?? ?? EB 39 48 8B 84 24 80 01 00 00 48 39 85 B8 01 00 00 75 24 48 8B }
	condition:
		$pattern
}

rule tcsetattr_18c2a17aa6c473be1bb49484f32d3b6d {
	meta:
		aliases = "__GI_tcsetattr, tcsetattr"
		type = "func"
		size = "271"
		objfiles = "tcsetattr@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 FF 41 56 41 55 41 54 55 53 48 89 D3 48 83 EC 38 83 FE 01 74 10 83 FE 02 74 22 85 F6 BD 02 54 00 00 74 1E EB 07 BD 03 54 00 00 EB 15 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 B4 00 00 00 BD 04 54 00 00 8B 03 48 8D 73 11 48 8D 7C 24 11 BA 13 00 00 00 25 FF FF FF 7F 89 04 24 8B 43 04 89 44 24 04 8B 43 08 89 44 24 08 8B 43 0C 89 44 24 0C 8A 43 10 88 44 24 10 E8 ?? ?? ?? ?? 31 C0 48 89 E2 48 89 EE 44 89 FF E8 ?? ?? ?? ?? 85 C0 41 89 C4 75 68 48 81 FD 02 54 00 00 75 5F E8 ?? ?? ?? ?? BE 01 54 00 00 44 8B 28 48 89 C5 48 89 E2 31 C0 44 89 FF E8 ?? ?? ?? ?? 85 C0 74 06 44 89 6D 00 EB 38 8B 4B 08 }
	condition:
		$pattern
}

rule getprotobynumber_r_66f84a94c71375bdbc097edda78cb8c0 {
	meta:
		aliases = "__GI_getprotobynumber_r, getprotobynumber_r"
		type = "func"
		size = "156"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 FF 41 56 49 89 D6 BA ?? ?? ?? ?? 41 55 49 89 CD 41 54 4D 89 C4 55 48 89 F5 BE ?? ?? ?? ?? 53 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 06 44 39 7D 10 74 17 4C 89 E1 4C 89 EA 4C 89 F6 48 89 EF E8 ?? ?? ?? ?? 85 C0 89 C3 74 E3 83 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 49 83 3C 24 00 B8 00 00 00 00 0F 45 D8 48 83 C4 28 89 D8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule pselect_637917062602689f2e211b946e448560 {
	meta:
		aliases = "__libc_pselect, pselect"
		type = "func"
		size = "174"
		objfiles = "pselect@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 FF 41 56 49 89 F6 41 55 49 89 D5 41 54 49 89 CC 55 4C 89 CD 53 4C 89 C3 48 81 EC 98 00 00 00 4D 85 C0 74 24 49 8B 00 BA E8 03 00 00 48 89 D1 48 89 84 24 80 00 00 00 49 8B 40 08 48 99 48 F7 F9 48 89 84 24 88 00 00 00 48 85 ED 74 10 48 89 E2 48 89 EE BF 02 00 00 00 E8 ?? ?? ?? ?? 31 C0 48 85 DB 74 08 48 8D 84 24 80 00 00 00 49 89 C0 4C 89 E1 4C 89 EA 4C 89 F6 44 89 FF E8 ?? ?? ?? ?? 48 85 ED 89 C3 74 0F 48 89 E6 31 D2 BF 02 00 00 00 E8 ?? ?? ?? ?? 48 81 C4 98 00 00 00 89 D8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule initstate_1fa3fa5664eae3c90d27ad14d1c3ee5a {
	meta:
		aliases = "initstate"
		type = "func"
		size = "110"
		objfiles = "random@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 89 FF 41 56 49 89 F6 BE ?? ?? ?? ?? 41 55 49 89 D5 BA ?? ?? ?? ?? 41 54 53 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? 4C 89 EA 4C 89 F6 44 89 FF B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 EB 04 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 48 89 D8 5B 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule cplus_mangle_opname_a3118f8690a6c8759d06e0ca1676b1df {
	meta:
		aliases = "cplus_mangle_opname"
		type = "func"
		size = "161"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 BF ?? ?? ?? ?? 41 56 49 89 FE 41 55 41 89 F5 41 54 55 53 31 DB 48 83 EC 18 E8 ?? ?? ?? ?? 41 89 C4 48 98 48 89 44 24 08 EB 11 0F 1F 00 48 83 C3 01 49 83 C7 18 48 83 FB 4F 74 52 49 8B 2F 48 89 EF E8 ?? ?? ?? ?? 41 39 C4 75 E2 41 8B 47 08 44 31 E8 A8 02 75 D7 48 8B 54 24 08 4C 89 F6 48 89 EF E8 ?? ?? ?? ?? 85 C0 75 C3 48 8D 04 5B 48 8B 04 C5 ?? ?? ?? ?? 48 83 C4 18 5B 5D 41 5C 41 5D 41 5E 41 5F C3 0F 1F 84 00 00 00 00 00 48 83 C4 18 31 C0 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule __read_etc_hosts_r_bf1adb3f43ef5bfa39d98982943a46b6 {
	meta:
		aliases = "__read_etc_hosts_r"
		type = "func"
		size = "826"
		objfiles = "read_etc_hosts_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 44 89 C8 F7 D8 41 56 41 55 4D 89 C5 41 54 55 53 4C 89 CB 48 83 EC 48 83 E0 07 89 54 24 0C 48 89 7C 24 18 48 89 74 24 10 89 4C 24 08 48 8B 94 24 80 00 00 00 74 11 48 98 48 39 C2 0F 82 DF 02 00 00 48 01 C3 48 29 C2 48 83 FA 3F 0F 86 CF 02 00 00 83 7C 24 08 01 48 8D 43 40 4C 8D 72 C0 48 89 44 24 40 0F 84 B3 00 00 00 48 8B 84 24 90 00 00 00 49 83 FE 03 C7 00 FF FF FF FF 0F 86 9F 02 00 00 48 8D 42 BC 48 83 F8 0F 0F 86 91 02 00 00 49 83 FE 0F 0F 86 87 02 00 00 48 8D 42 B0 48 83 F8 0F 0F 86 79 02 00 00 4C 8D 72 AC 48 8D 42 A0 4C 8D 63 44 4C 8D 7B 50 48 8D 6B 54 4C 39 F0 73 07 48 8D 6B 60 49 89 }
	condition:
		$pattern
}

rule __md5_Transform_c8d755c0a88fab9403cd2719a838f03c {
	meta:
		aliases = "__md5_Transform"
		type = "func"
		size = "341"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 41 ) 57 45 31 C9 45 31 C0 41 56 41 55 41 54 55 53 48 83 EC 48 49 89 E2 41 8D 40 01 44 89 C9 41 FF C1 0F B6 14 06 41 8D 40 02 0F B6 04 06 C1 E2 08 C1 E0 10 09 C2 44 89 C0 0F B6 04 06 09 C2 41 8D 40 03 41 83 C0 04 0F B6 04 06 C1 E0 18 09 C2 41 83 F8 3F 41 89 14 8A 76 BE 44 8B 2F 44 8B 4F 04 4C 8D 7F 04 44 8B 47 08 8B 77 0C 4C 8D 77 08 4C 8D 67 0C 41 BB ?? ?? ?? ?? BD ?? ?? ?? ?? 44 89 E9 BB ?? ?? ?? ?? 45 31 D2 E9 8F 00 00 00 49 8D 43 04 41 F6 C2 0F 4C 0F 44 D8 44 89 D0 C1 F8 04 83 F8 01 74 20 7F 06 85 C0 74 0E EB 3F 83 F8 02 74 23 83 F8 03 74 28 EB 33 44 89 C8 44 89 C2 F7 D0 21 F0 EB 09 89 F0 89 }
	condition:
		$pattern
}

rule fflush_unlocked_3768501ede607f86986e5c361dec002b {
	meta:
		aliases = "__GI_fflush_unlocked, fflush_unlocked"
		type = "func"
		size = "340"
		objfiles = "fflush_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 45 31 FF 41 56 41 55 41 54 55 53 48 89 FB 48 83 EC 28 48 81 FF ?? ?? ?? ?? 74 0F 48 85 FF 41 BF 00 01 00 00 0F 85 F1 00 00 00 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 45 31 E4 41 83 CE FF E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 FF C0 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 2D ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? EB 75 F6 45 00 40 74 6B 83 3D ?? ?? ?? ?? 02 74 1C 48 8D 5D 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 44 }
	condition:
		$pattern
}

rule svcudp_bufcreate_cc3b242beedb488317243a5e30051dbe {
	meta:
		aliases = "__GI_svcudp_bufcreate, svcudp_bufcreate"
		type = "func"
		size = "471"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 45 31 FF 41 56 41 55 41 89 FD 41 54 41 89 D4 55 89 F5 53 48 83 EC 28 83 FF FF C7 44 24 1C 10 00 00 00 75 2D BA 11 00 00 00 BE 02 00 00 00 BF 02 00 00 00 E8 ?? ?? ?? ?? 85 C0 41 89 C5 41 B7 01 79 0F BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 DA 00 00 00 31 F6 BA 10 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 44 89 EF 48 89 E6 66 C7 04 24 02 00 E8 ?? ?? ?? ?? 85 C0 74 16 8B 54 24 1C 48 89 E6 44 89 EF 66 C7 44 24 02 00 00 E8 ?? ?? ?? ?? 48 8D 54 24 1C 48 89 E6 44 89 EF E8 ?? ?? ?? ?? 85 C0 74 23 BF ?? ?? ?? ?? 45 31 F6 E8 ?? ?? ?? ?? 45 85 FF 0F 84 0E 01 00 00 44 89 EF E8 ?? ?? ?? ?? E9 01 01 00 00 BF 50 01 00 }
	condition:
		$pattern
}

rule re_search_2_7b281d8d91e146d50886cbef84b7e5e2 {
	meta:
		aliases = "__re_search_2, re_search_2"
		type = "func"
		size = "554"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 45 89 C7 41 01 D7 41 56 41 55 41 89 D5 41 54 49 89 FC 55 53 44 89 CB 48 83 EC 38 45 85 C9 48 89 74 24 28 48 89 4C 24 20 44 89 44 24 1C 48 8B 47 28 4C 8B 77 20 8B 6C 24 70 48 89 44 24 30 0F 88 BD 01 00 00 45 39 F9 0F 8F B4 01 00 00 89 EA 44 01 CA 79 07 44 89 CD F7 DD EB 0C 44 89 F8 44 29 C8 44 39 FA 0F 4F E8 49 83 7C 24 10 00 74 27 85 ED 7E 23 49 8B 04 24 8A 00 3C 0B 74 0C 3C 09 75 15 41 80 7C 24 38 00 78 0D 85 DB 0F 8F 70 01 00 00 BD 01 00 00 00 4D 85 F6 0F 84 F9 00 00 00 41 F6 44 24 38 08 75 11 4C 89 E7 E8 ?? ?? ?? ?? 83 F8 FE 0F 84 4E 01 00 00 4D 85 F6 0F 84 D7 00 00 00 44 39 FB 0F 8D }
	condition:
		$pattern
}

rule __res_query_a5f19e141225eb28ac8245b35febcfe6 {
	meta:
		aliases = "__GI___res_query, __res_query"
		type = "func"
		size = "261"
		objfiles = "res_query@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 45 89 C7 41 56 41 89 D6 41 55 41 54 55 48 89 FD 53 48 81 EC 88 00 00 00 48 85 FF 48 89 4C 24 08 48 C7 44 24 78 00 00 00 00 74 04 FF CE 74 0D E8 ?? ?? ?? ?? C7 00 03 00 00 00 EB 7A 48 8D 5C 24 10 31 F6 BA 40 00 00 00 48 89 DF E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 8D 64 24 50 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 44 8B 2D ?? ?? ?? ?? BE 01 00 00 00 4C 89 E7 E8 ?? ?? ?? ?? 4C 8D 44 24 78 49 89 D9 B9 ?? ?? ?? ?? 44 89 EA 44 89 F6 48 89 EF E8 ?? ?? ?? ?? 85 C0 89 C3 79 10 E8 ?? ?? ?? ?? C7 00 02 00 00 00 83 CB FF EB 34 48 8B 7C 24 10 E8 ?? ?? ?? ?? 44 }
	condition:
		$pattern
}

rule xregexec_f59a212d1c7e78f279acaf25c2c98ed2 {
	meta:
		aliases = "xregexec"
		type = "func"
		size = "501"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 45 89 C7 41 56 49 89 F6 41 54 49 89 CC 55 48 89 D5 53 48 89 FB 48 89 F7 48 83 C4 80 E8 ?? ?? ?? ?? F6 43 38 10 49 89 C0 75 09 48 85 ED 0F 85 AB 00 00 00 48 8B 03 48 8B 53 38 48 8D 7C 24 40 45 31 C9 4C 89 F1 31 F6 48 89 44 24 40 48 8B 43 08 48 89 54 24 78 83 E2 DF 48 89 44 24 48 48 8B 43 10 48 89 44 24 50 48 8B 43 18 48 89 44 24 58 48 8B 43 20 48 89 44 24 60 48 8B 43 28 48 89 44 24 68 48 8B 43 30 44 89 44 24 10 48 C7 44 24 08 00 00 00 00 44 89 04 24 48 89 44 24 70 44 89 F8 41 D1 EF 83 E0 01 41 83 E7 01 C1 E0 05 41 C1 E7 06 09 C2 83 E2 B9 44 09 FA 83 CA 04 88 54 24 78 31 D2 E8 E8 CB FF FF }
	condition:
		$pattern
}

rule __res_querydomain_3a9fcc5bbd65bb9a0b8d2496ca28ee12 {
	meta:
		aliases = "__GI___res_querydomain, __res_querydomain"
		type = "func"
		size = "328"
		objfiles = "res_query@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 45 89 CF 41 56 4D 89 C6 41 55 49 89 F5 BE ?? ?? ?? ?? 41 54 49 89 FC 55 53 48 81 EC 48 04 00 00 48 8D 9C 24 20 04 00 00 89 54 24 0C BA ?? ?? ?? ?? 89 4C 24 08 48 89 DF E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 DF 48 8B 2D ?? ?? ?? ?? E8 ?? ?? ?? ?? 4D 85 E4 74 14 4D 85 F6 74 0F 40 80 E5 01 75 16 E8 ?? ?? ?? ?? FF C0 75 0D E8 ?? ?? ?? ?? C7 00 FF FF FF FF EB 27 4D 85 ED 75 54 4C 89 E7 E8 ?? ?? ?? ?? 48 89 C2 48 8D 40 01 48 3D 01 04 00 00 76 13 E8 ?? ?? ?? ?? C7 00 03 00 00 00 83 C8 FF E9 84 00 00 00 48 85 D2 74 69 48 8D 6A FF 41 80 3C 2C 2E 75 5E 48 8D 5C 24 10 48 }
	condition:
		$pattern
}

rule byte_regex_compile_3a0f2e5f846b890d9ec9d13ee520075f {
	meta:
		aliases = "byte_regex_compile"
		type = "func"
		size = "10077"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 48 01 FE 41 56 41 55 49 89 CD 41 54 55 53 48 81 EC D8 01 00 00 48 89 7C 24 60 48 89 BC 24 C8 01 00 00 BF 00 05 00 00 48 89 54 24 58 48 89 74 24 70 48 8B 41 28 48 89 44 24 78 E8 ?? ?? ?? ?? 48 85 C0 48 89 84 24 B0 00 00 00 0F 84 E4 26 00 00 48 8B 54 24 58 41 80 65 38 97 49 C7 45 10 00 00 00 00 49 C7 45 30 00 00 00 00 49 89 55 18 83 3D ?? ?? ?? ?? 00 75 48 BA 00 01 00 00 31 F6 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C9 EB 1A 48 8B 05 ?? ?? ?? ?? 48 63 D1 F6 44 50 01 08 74 07 C6 82 ?? ?? ?? ?? 01 FF C1 81 F9 FF 00 00 00 7E DE C6 05 ?? ?? ?? ?? 01 C7 05 ?? ?? ?? ?? 01 00 00 00 49 83 7D 08 00 75 44 }
	condition:
		$pattern
}

rule demangle_arm_hp_template_939e41abc062cff5f4fb939d082a704b {
	meta:
		aliases = "demangle_arm_hp_template"
		type = "func"
		size = "2033"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 48 63 C2 41 89 D7 41 56 49 89 F6 41 55 41 54 55 48 89 FD 53 48 89 CB 48 83 EC 78 44 8B 27 48 8B 0E 48 89 44 24 08 41 F7 C4 00 10 00 00 4C 8D 2C 01 74 0B 41 80 7D 00 58 0F 84 90 01 00 00 44 8B 65 00 41 F7 C4 00 18 00 00 74 69 48 89 CF BE ?? ?? ?? ?? 48 89 4C 24 10 E8 ?? ?? ?? ?? 48 85 C0 48 89 C2 48 8B 4C 24 10 74 4A 4C 8D 64 24 28 48 8D 40 06 48 89 4C 24 18 48 89 54 24 10 4C 89 E7 48 89 44 24 28 E8 44 CE FF FF 83 F8 FF 0F 84 85 00 00 00 48 8B 74 24 28 48 98 48 8B 54 24 10 48 8B 4C 24 18 48 01 F0 49 39 C5 0F 84 A9 04 00 00 44 8B 65 00 41 81 E4 00 21 00 00 74 5B 48 89 CF BE ?? ?? ?? ?? 48 }
	condition:
		$pattern
}

rule _dl_parse_158696f97e802856a9900cfbdb6cbe4f {
	meta:
		aliases = "_dl_parse"
		type = "func"
		size = "302"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 57 48 89 C8 41 56 45 31 F6 41 55 49 89 FD 41 54 49 89 D4 BA 18 00 00 00 55 53 48 89 D3 31 D2 48 F7 F3 48 83 EC 28 48 89 74 24 18 4C 89 44 24 10 48 89 44 24 08 48 8B 87 B0 00 00 00 48 89 44 24 20 4C 8B BF A8 00 00 00 E9 BF 00 00 00 49 8B 6C 24 08 4D 89 F8 48 8B 4C 24 20 4C 89 E2 48 8B 74 24 18 4C 89 EF FF 54 24 10 85 C0 89 C3 0F 84 92 00 00 00 48 8B 15 ?? ?? ?? ?? 31 C0 48 C1 ED 20 BE ?? ?? ?? ?? BF 02 00 00 00 E8 ?? ?? ?? ?? 85 ED 74 24 48 63 C5 48 8B 4C 24 20 BE ?? ?? ?? ?? 48 6B C0 18 BF 02 00 00 00 8B 14 08 31 C0 49 8D 14 17 E8 ?? ?? ?? ?? 83 FB 00 7D 34 49 8B 54 24 08 31 C0 BE ?? ?? ?? }
	condition:
		$pattern
}

rule md5_process_block_9a4ac42e29ff7951361a57e23865e252 {
	meta:
		aliases = "md5_process_block"
		type = "func"
		size = "2093"
		objfiles = "md5@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 48 89 F0 48 83 E0 FC 41 56 48 01 F8 41 55 41 54 55 48 89 FD 53 8B 1A 8B 7A 08 48 89 44 24 F0 8B 42 0C 89 5C 24 E0 48 89 54 24 F8 8B 5A 04 89 7C 24 E4 89 44 24 E8 89 F0 03 42 10 48 39 C6 89 42 10 76 04 83 42 14 01 48 3B 6C 24 F0 0F 83 B2 07 00 00 0F 1F 40 00 44 8B 5D 00 8B 4C 24 E8 8B 44 24 E0 8B 7C 24 E4 8B 75 04 44 8B 55 14 44 8B 4D 18 41 8D 94 03 78 A4 6A D7 89 C8 31 F8 89 74 24 C4 44 89 54 24 EC 21 D8 44 89 4C 24 D4 31 C8 8D 8C 0E 56 B7 C7 E8 01 D0 89 FA C1 C8 19 31 DA 01 D8 21 C2 31 FA 01 CA 8B 4D 08 C1 CA 14 01 C2 8D B4 39 DB 70 20 24 89 C7 89 4C 24 C8 31 DF 41 89 D7 89 F9 8B 7D 0C }
	condition:
		$pattern
}

rule split_directories_edf61513fe392886f460ee9557a24801 {
	meta:
		aliases = "split_directories"
		type = "func"
		size = "432"
		objfiles = "make_relative_prefix@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 48 89 F8 31 C9 41 56 41 55 41 54 49 89 FC 55 48 89 F5 53 48 83 EC 18 0F BE 17 EB 0E 66 90 83 FA 2F 0F 84 1F 01 00 00 0F BE 10 48 83 C0 01 85 D2 75 EC 8D 79 02 48 63 FF 48 C1 E7 03 E8 ?? ?? ?? ?? 48 85 C0 49 89 C6 0F 84 4B 01 00 00 41 BF 08 00 00 00 45 31 ED 4C 89 E1 EB 0B 0F 1F 00 83 FA 2F 74 7F 48 89 D9 48 8D 59 01 0F BE 53 FF 85 D2 75 EC 4C 29 E1 4D 63 FD 48 85 C9 48 89 CB 7E 28 8D 79 01 48 63 DB 41 83 C5 01 48 63 FF E8 ?? ?? ?? ?? 48 89 DA 4C 89 E6 48 89 C7 E8 ?? ?? ?? ?? C6 04 18 00 4B 89 04 FE 49 63 C5 49 83 7C C6 F8 00 49 C7 04 C6 00 00 00 00 0F 84 E0 00 00 00 48 85 ED 0F 84 A7 00 }
	condition:
		$pattern
}

rule memmove_cfeec897d2255588ed8c394618d75ecd {
	meta:
		aliases = "__GI_memmove, memmove"
		type = "func"
		size = "702"
		objfiles = "memmove@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 48 89 F8 48 29 F0 41 56 49 89 FE 41 55 41 54 55 53 48 83 EC 08 48 39 D0 72 0A E8 ?? ?? ?? ?? E9 89 02 00 00 48 83 FA 0F 48 8D 1C 16 48 8D 34 3A 0F 86 72 02 00 00 48 89 F1 49 89 D5 83 E1 07 49 29 CD EB 0D 48 FF CB 48 FF CE 48 FF C9 8A 03 88 06 48 85 C9 75 EE 48 89 D8 83 E0 07 0F 85 FC 00 00 00 4D 89 E8 49 C1 E8 03 4C 89 C0 83 E0 07 48 83 F8 07 77 0B 48 8B 7B F8 FF 24 C5 ?? ?? ?? ?? 48 89 D9 48 89 F0 45 31 C9 EB 7C 48 8D 4B F0 48 8D 46 F8 49 83 C0 06 E9 A3 00 00 00 48 8D 4B E8 48 8D 46 F0 49 89 F9 49 83 C0 05 E9 87 00 00 00 48 8D 4B E0 48 8D 46 E8 49 83 C0 04 EB 71 48 8D 4B D8 48 8D 46 E0 }
	condition:
		$pattern
}

rule _dl_load_shared_library_a6554ab1394d0ac5fdaf1bd1c4a848e0 {
	meta:
		aliases = "_dl_load_shared_library"
		type = "func"
		size = "531"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 41 ) 57 48 8D 41 FF 41 56 41 55 41 89 FD 41 54 49 89 F4 55 53 48 89 D3 48 83 EC 18 48 C7 05 ?? ?? ?? ?? 00 00 00 00 48 FF C0 80 38 00 75 F8 48 29 C8 48 3D 00 04 00 00 0F 87 A5 01 00 00 48 8D 41 FF 31 F6 EB 07 80 FA 2F 48 0F 44 F0 48 FF C0 8A 10 84 D2 75 F0 48 8D 46 01 48 85 F6 48 89 CD 48 0F 45 E8 48 39 CD 74 17 48 89 CA 4C 89 E6 44 89 EF E8 ?? ?? ?? ?? 48 85 C0 0F 85 85 01 00 00 48 85 DB 74 2A 48 8B 93 F8 00 00 00 48 85 D2 74 1E 48 03 93 A8 00 00 00 4C 89 E1 44 89 EE 48 89 EF E8 11 FE FF FF 48 85 C0 0F 85 56 01 00 00 48 8B 15 ?? ?? ?? ?? 48 85 D2 74 17 4C 89 E1 44 89 EE 48 89 EF E8 EE FD FF FF }
	condition:
		$pattern
}

rule frame_heapsort_01fab97e780876f47025ce56f9c33a53 {
	meta:
		aliases = "frame_heapsort"
		type = "func"
		size = "210"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 41 ) 57 48 8D 42 10 41 56 41 55 41 54 49 89 D4 55 53 48 83 EC 18 4C 8B 7A 08 48 89 44 24 10 48 89 7C 24 08 48 89 34 24 4D 89 FE 49 D1 EE 44 89 F0 45 89 F5 83 E8 01 78 34 44 89 FD 31 DB 66 66 90 44 89 E9 48 8B 54 24 10 48 8B 34 24 48 8B 7C 24 08 29 D9 41 89 E8 83 E9 01 48 83 C3 01 E8 DE FE FF FF 44 89 F0 29 D8 83 E8 01 79 D4 45 89 FD 41 8D 45 FF 85 C0 7E 4C 48 98 31 ED 49 8D 5C C4 10 48 8B 03 49 8B 54 24 10 45 89 E8 48 8B 34 24 48 8B 7C 24 08 41 29 E8 41 83 E8 01 31 C9 48 83 C5 01 49 89 44 24 10 48 89 13 48 83 EB 08 48 8B 54 24 10 E8 89 FE FF FF 44 89 F8 29 E8 83 E8 01 85 C0 7F BD 48 83 C4 18 5B }
	condition:
		$pattern
}

rule demangle_signature_21145c727b93fac078df28eeac665d89 {
	meta:
		aliases = "demangle_signature"
		type = "func"
		size = "2497"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 48 8D 47 30 41 BF 01 00 00 00 41 56 49 89 FE 41 55 49 89 D5 41 54 45 31 E4 55 31 ED 53 48 89 F3 48 81 EC 88 00 00 00 4C 8B 0B C7 44 24 14 00 00 00 00 C7 44 24 10 00 00 00 00 48 89 44 24 08 41 0F BE 39 40 84 FF 0F 84 24 02 00 00 66 90 8D 47 D0 3C 45 0F 87 45 05 00 00 0F B6 C0 FF 24 C5 ?? ?? ?? ?? 0F 1F 00 48 85 ED 48 8D 4C 24 20 48 8D 54 24 40 49 0F 44 E9 41 B8 01 00 00 00 41 B9 01 00 00 00 48 89 DE 4C 89 F7 48 C7 44 24 30 00 00 00 00 48 C7 44 24 28 00 00 00 00 48 C7 44 24 20 00 00 00 00 48 C7 44 24 50 00 00 00 00 48 C7 44 24 48 00 00 00 00 48 C7 44 24 40 00 00 00 00 E8 0A CE FF FF 85 C0 }
	condition:
		$pattern
}

rule svcudp_recv_73ae803a1202f40695f3162d6a55ba13 {
	meta:
		aliases = "svcudp_recv"
		type = "func"
		size = "567"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 48 8D 47 50 48 8D 57 60 49 89 F7 41 56 4C 8D B7 98 00 00 00 41 55 41 54 49 89 FC 55 53 48 8D 5F 14 48 83 EC 38 48 8B 6F 48 48 89 44 24 10 48 89 54 24 08 48 8B 4C 24 10 4C 8B 6C 24 08 C7 44 24 34 10 00 00 00 49 8B 74 24 40 48 89 4C 24 20 49 83 7D 18 00 74 4F 49 89 74 24 50 8B 45 00 31 D2 4C 89 EE 48 89 41 08 49 89 4D 10 49 C7 45 18 01 00 00 00 41 C7 45 08 10 00 00 00 4D 89 75 20 49 C7 45 28 B8 00 00 00 41 8B 3C 24 49 89 5C 24 60 E8 ?? ?? ?? ?? 85 C0 89 C2 78 23 41 8B 45 08 89 44 24 34 EB 19 48 63 55 00 41 8B 3C 24 4C 8D 4C 24 34 49 89 D8 31 C9 E8 ?? ?? ?? ?? 89 C2 8B 44 24 34 83 FA FF 41 }
	condition:
		$pattern
}

rule __kernel_rem_pio2_b32808da863f93837110e51749183b8b {
	meta:
		aliases = "__kernel_rem_pio2"
		type = "func"
		size = "1611"
		objfiles = "k_rem_pio2@libm.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 63 C0 44 8D 79 FF 0F 57 C9 41 56 49 89 F6 89 D6 8D 4E FD 41 55 41 54 55 89 F5 53 48 81 EC 88 02 00 00 8B 04 85 ?? ?? ?? ?? 48 89 7C 24 38 BF 18 00 00 00 C7 44 24 44 00 00 00 00 44 89 44 24 34 4C 89 4C 24 28 89 44 24 40 89 C8 8B 74 24 40 99 F7 FF 85 C0 89 C1 0F 48 4C 24 44 44 01 FE 89 C8 89 CA 89 4C 24 44 FF C0 44 29 FA 31 C9 6B C0 18 29 C5 EB 24 85 D2 0F 28 C1 78 0D 48 8B 5C 24 28 48 63 C2 F2 0F 2A 04 83 48 63 C1 FF C2 FF C1 F2 0F 11 84 C4 90 01 00 00 39 F1 7E D8 0F 57 D2 31 F6 EB 32 48 8B 5C 24 38 48 63 D1 89 F8 29 C8 FF C1 48 98 F2 0F 10 04 D3 F2 0F 59 84 C4 90 01 00 00 F2 0F 58 C8 }
	condition:
		$pattern
}

rule byte_regex_compile_488c8ef77a18a01b89cd188b6c6861c1 {
	meta:
		aliases = "byte_regex_compile"
		type = "func"
		size = "11350"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 CF 41 56 41 55 41 54 55 53 48 89 F3 48 81 EC 68 01 00 00 48 8B 41 28 48 89 7C 24 18 48 89 BC 24 D8 00 00 00 BF 00 05 00 00 48 89 54 24 10 48 89 44 24 20 E8 ?? ?? ?? ?? 48 85 C0 48 89 44 24 28 0F 84 EE 00 00 00 8B 2D ?? ?? ?? ?? 48 8B 44 24 10 41 80 67 38 97 49 C7 47 10 00 00 00 00 49 C7 47 30 00 00 00 00 85 ED 49 89 47 18 0F 84 1A 01 00 00 49 83 7F 08 00 0F 84 CF 00 00 00 48 8B 54 24 18 49 8B 2F 48 8B 7C 24 10 48 03 5C 24 18 45 31 ED 48 89 6C 24 08 C7 44 24 40 00 00 00 00 45 31 F6 C7 44 24 68 20 00 00 00 C7 44 24 44 00 00 00 00 45 31 DB 48 89 F8 83 E0 02 48 89 5C 24 30 48 89 44 24 }
	condition:
		$pattern
}

rule getservent_r_35704e56e5f332b30cd8775b5d5d3ca8 {
	meta:
		aliases = "__GI_getservent_r, getservent_r"
		type = "func"
		size = "505"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 CF 41 56 41 55 49 89 F5 41 54 49 89 FC 55 53 48 89 D3 48 83 EC 28 48 81 FA 17 01 00 00 48 C7 01 00 00 00 00 77 15 BB 22 00 00 00 E8 ?? ?? ?? ?? C7 00 22 00 00 00 E9 A9 01 00 00 48 89 E7 BA ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 4D 8D B5 18 01 00 00 E8 ?? ?? ?? ?? 48 8D 83 E8 FE FF FF 48 3D 00 10 00 00 77 15 BB 22 00 00 00 E8 ?? ?? ?? ?? C7 00 22 00 00 00 E9 55 01 00 00 48 83 3D ?? ?? ?? ?? 00 75 30 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 75 15 BB 05 00 00 00 E8 ?? ?? ?? ?? C7 00 05 00 00 00 E9 1B 01 00 00 48 8B 15 ?? ?? ?? ?? BE }
	condition:
		$pattern
}

rule _getopt_internal_a7676637f78060d789b98166a3cdcd82 {
	meta:
		aliases = "_getopt_internal"
		type = "func"
		size = "1929"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 CF 41 56 41 55 49 89 F5 41 54 55 53 48 83 EC 58 8B 05 ?? ?? ?? ?? 48 89 54 24 28 8B 15 ?? ?? ?? ?? 48 8B 4C 24 28 89 7C 24 30 89 44 24 3C 89 05 ?? ?? ?? ?? B8 00 00 00 00 4C 89 44 24 20 44 89 4C 24 1C 89 15 ?? ?? ?? ?? 80 39 3A 0F 45 44 24 3C 85 FF 89 44 24 3C 0F 8E EE 06 00 00 85 D2 48 C7 05 ?? ?? ?? ?? 00 00 00 00 74 0F 83 3D ?? ?? ?? ?? 00 0F 85 90 00 00 00 EB 0A C7 05 ?? ?? ?? ?? 01 00 00 00 8B 05 ?? ?? ?? ?? BF ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 89 05 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 28 48 85 C0 0F 95 C0 0F B6 C0 89 05 ?? ?? ?? ?? 8A 11 80 FA }
	condition:
		$pattern
}

rule __form_query_0fab805473860803f9e63f00ce965f7a {
	meta:
		aliases = "__form_query"
		type = "func"
		size = "141"
		objfiles = "formquery@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 CF 41 56 41 89 D6 BA 30 00 00 00 41 55 49 89 F5 31 F6 41 54 41 89 FC 55 44 89 C5 53 48 83 EC 48 48 89 E7 E8 ?? ?? ?? ?? 89 EA 4C 89 FE 48 89 E7 44 89 24 24 C7 44 24 20 01 00 00 00 4C 89 6C 24 30 44 89 74 24 38 C7 44 24 3C 01 00 00 00 E8 ?? ?? ?? ?? 85 C0 89 C3 78 1F 48 63 F0 29 C5 48 8D 7C 24 30 49 8D 34 37 89 EA E8 ?? ?? ?? ?? 8D 14 03 85 C0 89 C3 0F 49 DA 48 83 C4 48 89 D8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule gethostbyaddr_r_07ed7068526ca5bc5d41958a6d06a04d {
	meta:
		aliases = "__GI_gethostbyaddr_r, gethostbyaddr_r"
		type = "func"
		size = "954"
		objfiles = "gethostbyaddr_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 CF 41 56 41 89 F6 41 55 41 54 4D 89 C4 55 48 89 FD 53 4C 89 CB 48 81 EC B8 00 00 00 48 85 FF 48 8B 84 24 F0 00 00 00 89 54 24 1C 48 C7 00 00 00 00 00 0F 84 60 03 00 00 48 8D 7C 24 40 31 F6 BA 40 00 00 00 E8 ?? ?? ?? ?? 83 7C 24 1C 02 74 0D 83 7C 24 1C 0A 0F 85 3D 03 00 00 EB 06 41 83 FE 04 EB 04 41 83 FE 10 0F 85 2B 03 00 00 48 8B 8C 24 F8 00 00 00 48 8B 84 24 F0 00 00 00 49 89 D9 8B 54 24 1C 4D 89 E0 44 89 F6 48 89 EF 48 89 4C 24 08 4C 89 F9 48 89 04 24 E8 ?? ?? ?? ?? 85 C0 0F 84 FE 02 00 00 48 8B 8C 24 F8 00 00 00 8B 11 83 FA 01 74 09 83 FA 04 0F 85 E6 02 00 00 E8 ?? ?? ?? ?? 48 }
	condition:
		$pattern
}

rule sysctl_f340c471c4b2007611a477a2538a81e3 {
	meta:
		aliases = "sysctl"
		type = "func"
		size = "142"
		objfiles = "sysctl@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 CF 41 56 49 89 D6 BA 50 00 00 00 41 55 41 89 F5 31 F6 41 54 49 89 FC 55 4C 89 C5 53 48 83 EC 68 48 8D 5C 24 10 4C 89 4C 24 08 48 89 DF E8 ?? ?? ?? ?? 48 8B 44 24 08 4C 89 64 24 10 48 89 DF 44 89 6C 24 18 4C 89 74 24 20 4C 89 7C 24 28 48 89 6C 24 30 48 89 44 24 38 B8 9C 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 83 C4 68 89 D8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule regexec_1a14cdcfa15ddb80b6d347dffd3e1604 {
	meta:
		aliases = "__regexec, regexec"
		type = "func"
		size = "292"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 CF 41 56 49 89 F6 41 55 41 54 49 89 FC 48 89 F7 55 48 89 D5 53 44 89 C3 48 83 EC 78 E8 ?? ?? ?? ?? 4C 89 E6 41 B1 10 48 8D 7C 24 10 45 33 4C 24 38 B9 10 00 00 00 49 89 C5 FC F3 A5 88 DA 41 C0 E9 04 48 85 ED 8A 44 24 48 41 0F 95 C0 83 E2 01 D1 EB C1 E2 05 83 E3 01 83 E0 9F C1 E3 06 09 D0 09 D8 83 E0 F9 83 C8 04 88 44 24 48 44 88 C0 44 20 C8 41 88 C4 0F 84 90 00 00 00 48 8D 3C ED 00 00 00 00 89 6C 24 50 E8 ?? ?? ?? ?? 48 85 C0 BA 01 00 00 00 74 79 48 89 44 24 58 48 8D 04 A8 48 89 44 24 60 48 8D 44 24 50 48 8D 7C 24 10 31 C9 49 89 C1 45 89 E8 44 89 EA 4C 89 F6 E8 ?? ?? ?? ?? 45 84 E4 }
	condition:
		$pattern
}

rule pex_run_1ef5c0de74ceec21ef8e5fcf5ff1fe6a {
	meta:
		aliases = "pex_run"
		type = "func"
		size = "1220"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 CF 41 56 49 89 FE 41 55 4D 89 CD 41 54 4D 89 C4 55 53 89 F3 48 83 EC 58 48 8B 7F 50 48 89 54 24 20 48 85 FF 74 16 E8 ?? ?? ?? ?? 83 F8 FF 0F 84 78 02 00 00 49 C7 46 50 00 00 00 00 49 83 7E 20 00 74 39 48 8B 8C 24 90 00 00 00 48 8D 54 24 48 31 F6 4C 89 F7 E8 22 FD FF FF 85 C0 0F 85 4A 01 00 00 48 8B 44 24 48 48 83 C4 58 5B 5D 41 5C 41 5D 41 5E 41 5F C3 66 0F 1F 44 00 00 41 8B 6E 18 85 ED 0F 88 04 02 00 00 F6 C3 01 0F 84 57 01 00 00 4D 85 E4 C7 44 24 34 00 00 00 00 0F 84 7A 03 00 00 F6 C3 04 C7 44 24 28 FF FF FF FF 0F 85 29 03 00 00 41 C7 46 18 FF FF FF FF 8B 4C 24 28 85 C9 0F 88 F1 }
	condition:
		$pattern
}

rule xdrrec_create_0b900b14bc8364e1edda25836095c352 {
	meta:
		aliases = "__GI_xdrrec_create, xdrrec_create"
		type = "func"
		size = "308"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 CF 41 56 49 89 FE BF 80 00 00 00 41 55 41 54 41 89 D4 55 53 89 F3 48 83 EC 18 4C 89 44 24 10 4C 89 4C 24 08 E8 ?? ?? ?? ?? 83 FB 63 48 89 C5 B8 A0 0F 00 00 0F 46 D8 44 8D 6B 03 41 83 E5 FC 41 83 FC 63 44 0F 46 E0 41 83 C4 03 41 83 E4 FC 43 8D 7C 25 04 89 FF E8 ?? ?? ?? ?? 48 85 ED 48 89 C3 74 05 48 85 C0 75 2F 48 8B 35 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 48 83 C4 18 48 89 DF 5B 5D 41 5C 41 5D 41 5E 41 5F E9 ?? ?? ?? ?? 48 89 45 08 48 89 C1 83 E0 03 44 89 6D 74 44 89 65 78 74 07 48 29 C3 48 8D 4B 04 44 89 EA 48 89 4D 18 48 8D 04 11 48 89 45 50 49 C7 46 }
	condition:
		$pattern
}

rule getprotobyname_r_38c88446351dc72061c9adf495e0d9bd {
	meta:
		aliases = "__GI_getprotobyname_r, getprotobyname_r"
		type = "func"
		size = "204"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 CF 41 56 4D 89 C6 41 55 49 89 FD 41 54 49 89 F4 BE ?? ?? ?? ?? 55 53 48 83 EC 38 48 8D 7C 24 10 48 89 54 24 08 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 2F 49 8B 3C 24 4C 89 EE E8 ?? ?? ?? ?? 85 C0 74 38 49 8B 5C 24 08 EB 10 4C 89 EE E8 ?? ?? ?? ?? 85 C0 74 25 48 83 C3 08 48 8B 3B 48 85 FF 75 E8 48 8B 74 24 08 4C 89 F1 4C 89 FA 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 89 C5 74 B8 83 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 48 8D 7C 24 10 BE 01 00 00 00 E8 ?? ?? ?? ?? 49 83 3E 00 B8 00 00 00 00 0F 45 E8 48 83 C4 38 5B 89 E8 5D 41 5C 41 5D 41 }
	condition:
		$pattern
}

rule getservbyport_r_f0971dff8a20b00c5ee72ac82825dd4e {
	meta:
		aliases = "__GI_getservbyport_r, getservbyport_r"
		type = "func"
		size = "188"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 CF 41 56 4D 89 C6 41 55 4D 89 CD 41 54 49 89 F4 BE ?? ?? ?? ?? 55 48 89 D5 BA ?? ?? ?? ?? 53 48 83 EC 38 89 7C 24 0C 48 8D 7C 24 10 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 1E 8B 44 24 0C 39 45 10 75 15 4D 85 E4 74 27 48 8B 7D 18 4C 89 E6 E8 ?? ?? ?? ?? 85 C0 74 17 4C 89 E9 4C 89 F2 4C 89 FE 48 89 EF E8 ?? ?? ?? ?? 85 C0 89 C3 74 CB 83 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 48 8D 7C 24 10 BE 01 00 00 00 E8 ?? ?? ?? ?? 49 83 7D 00 00 B8 00 00 00 00 0F 45 D8 48 83 C4 38 89 D8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule pthread_cond_timedwait_362b4fffe0e898076821ceab98b4c803 {
	meta:
		aliases = "__GI_pthread_cond_timedwait, pthread_cond_timedwait"
		type = "func"
		size = "465"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 41 56 41 55 41 54 49 89 F4 55 48 89 FD 53 48 83 EC 28 E8 55 FF FF FF 48 89 44 24 18 41 8B 44 24 10 83 F8 03 74 19 85 C0 74 15 48 8B 44 24 18 49 39 44 24 08 BA 16 00 00 00 0F 85 7C 01 00 00 48 8B 44 24 18 48 89 2C 24 48 89 E6 48 C7 44 24 08 ?? ?? ?? ?? C6 80 D1 02 00 00 00 48 8B 7C 24 18 E8 72 FE FF FF 48 8B 74 24 18 48 89 EF E8 ?? ?? ?? ?? 48 8B 44 24 18 80 78 7A 00 74 10 48 8B 44 24 18 BB 01 00 00 00 80 78 78 00 74 10 48 8B 74 24 18 48 8D 7D 10 31 DB E8 A8 FD FF FF 48 89 EF E8 ?? ?? ?? ?? 85 DB 74 11 48 8B 7C 24 18 31 F6 E8 22 FE FF FF E9 D8 00 00 00 4C 8D 75 10 4C 89 E7 45 31 }
	condition:
		$pattern
}

rule qsort_eabb14f961aa2ae35d8e1dd55c2632d9 {
	meta:
		aliases = "__GI_qsort, qsort"
		type = "func"
		size = "216"
		objfiles = "qsort@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 41 56 41 55 41 54 55 53 48 83 EC 18 48 83 FE 01 48 89 7C 24 08 48 89 0C 24 0F 86 A5 00 00 00 48 85 D2 0F 84 9C 00 00 00 48 8D 7E FF 31 C9 48 8D 04 49 BA 03 00 00 00 48 89 D3 31 D2 48 8D 48 01 48 89 F8 48 F7 F3 48 39 C1 72 E3 48 89 CB 49 0F AF F7 49 0F AF DF 48 89 74 24 10 49 89 DE 4D 89 F5 48 8B 6C 24 08 49 29 DD 4C 01 ED 4C 8D 64 1D 00 48 89 EF 4C 89 E6 FF 14 24 85 C0 7E 21 4C 89 F9 8A 55 00 41 8A 04 24 88 45 00 48 FF C5 41 88 14 24 49 FF C4 48 FF C9 75 E7 49 39 DD 73 C2 4D 01 FE 4C 3B 74 24 10 72 B5 4C 29 FB BA 03 00 00 00 48 89 D8 48 89 D6 31 D2 48 F7 F6 48 85 C0 48 89 C3 75 }
	condition:
		$pattern
}

rule __time_localtime_tzi_4d7878546b73c9ea2e88bfd60b8d320d {
	meta:
		aliases = "__time_localtime_tzi"
		type = "func"
		size = "725"
		objfiles = "_time_localtime_tzi@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 41 56 41 55 49 89 F5 41 54 55 53 48 83 EC 48 48 89 7C 24 20 C7 44 24 2C 00 00 00 00 48 63 44 24 2C 48 8B 4C 24 20 49 B8 7F C5 F6 FF FF FF FF 7F BE F9 FF FF FF 48 8B 11 48 C1 E0 05 49 8D 1C 07 B8 80 3A 09 00 48 2B 03 4C 39 C2 7E 08 48 F7 D8 BE 07 00 00 00 48 8D 7C 24 30 48 01 D0 4C 89 EA 48 89 44 24 30 4C 8D 63 18 E8 ?? ?? ?? ?? 8B 44 24 2C 41 89 45 20 48 8B 03 BB ?? ?? ?? ?? 48 F7 D8 49 89 45 28 EB 1B 48 8D 6B 08 4C 89 E6 48 89 EF E8 ?? ?? ?? ?? 85 C0 75 05 48 89 E8 EB 57 48 8B 1B 48 85 DB 75 E0 BE 07 00 00 00 4C 89 E7 E8 ?? ?? ?? ?? 48 83 F8 06 77 37 BF 10 00 00 00 E8 ?? ?? ?? }
	condition:
		$pattern
}

rule linear_search_fdes_9abf856fe07ed0905f54656be7e447da {
	meta:
		aliases = "linear_search_fdes"
		type = "func"
		size = "353"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 41 56 41 55 49 89 FD 41 54 55 48 89 F5 48 89 FE 53 48 83 EC 28 0F B7 47 20 66 C1 E8 03 44 0F B6 E0 44 89 E7 E8 B2 FC FF FF 8B 55 00 49 89 C6 85 D2 0F 84 11 01 00 00 48 8D 44 24 20 48 C7 44 24 10 00 00 00 00 48 89 44 24 08 48 8D 44 24 18 48 89 04 24 EB 4B 66 66 90 66 66 90 48 8B 55 08 48 89 54 24 20 48 8B 45 10 48 85 D2 48 89 44 24 18 74 19 4C 89 F8 48 2B 44 24 20 48 3B 44 24 18 0F 82 C5 00 00 00 66 66 90 66 66 90 8B 45 00 48 01 E8 48 8D 68 04 8B 40 04 85 C0 0F 84 A8 00 00 00 8B 45 04 85 C0 74 E4 41 F6 45 20 04 74 2E 48 8D 5D 04 48 98 48 29 C3 48 39 5C 24 10 74 1E 48 89 DF E8 15 }
	condition:
		$pattern
}

rule getnameinfo_4d178e2fd2df9533404ad46f464712c4 {
	meta:
		aliases = "__GI_getnameinfo, getnameinfo"
		type = "func"
		size = "792"
		objfiles = "getnameinfo@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 41 56 41 89 CE 41 55 49 89 FD 41 54 55 53 89 F3 48 81 EC B8 02 00 00 4C 89 44 24 08 44 89 4C 24 04 E8 ?? ?? ?? ?? 48 89 44 24 10 8B 00 89 44 24 1C 83 C8 FF F7 84 24 F0 02 00 00 E0 FF FF FF 0F 85 BC 02 00 00 4D 85 ED 0F 84 AE 02 00 00 83 FB 01 0F 86 A5 02 00 00 66 41 8B 45 00 66 83 F8 01 74 1E 66 83 F8 02 75 05 83 FB 0F EB 0D 66 83 F8 0A 0F 85 85 02 00 00 83 FB 1B 0F 86 7C 02 00 00 4D 85 FF 0F 95 44 24 1A 45 85 F6 0F 95 44 24 1B 80 7C 24 1A 00 0F 84 93 01 00 00 80 7C 24 1B 00 0F 84 88 01 00 00 66 83 F8 02 74 14 66 83 F8 0A 74 0E 66 FF C8 0F 85 73 01 00 00 E9 1D 01 00 00 F6 84 24 }
	condition:
		$pattern
}

rule __getgrouplist_internal_a4a1759c6a774542b6d0b6b6f942daad {
	meta:
		aliases = "__getgrouplist_internal"
		type = "func"
		size = "275"
		objfiles = "__getgrouplist_internal@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 41 56 41 89 F6 41 55 45 31 ED 41 54 55 53 48 81 EC 38 01 00 00 48 89 7C 24 08 C7 02 01 00 00 00 BF 20 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 0F 84 C6 00 00 00 44 89 30 BE ?? ?? ?? ?? BF ?? ?? ?? ?? 49 89 C5 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 0F 84 A5 00 00 00 41 BC 01 00 00 00 C7 40 50 01 00 00 00 EB 64 44 39 B4 24 20 01 00 00 74 5A 48 8B 9C 24 28 01 00 00 EB 48 48 8B 74 24 08 E8 ?? ?? ?? ?? 85 C0 75 36 41 F6 C4 07 75 1C 41 8D 74 24 08 4C 89 EF 48 63 F6 48 C1 E6 02 E8 ?? ?? ?? ?? 48 85 C0 74 4A 49 89 C5 8B 84 24 20 01 00 00 49 63 D4 41 FF C4 41 89 44 95 00 EB 0C 48 83 C3 08 48 8B 3B 48 }
	condition:
		$pattern
}

rule getspnam_r_4637c8554922e4eeefe27c93a1236c5c {
	meta:
		aliases = "__GI_getgrnam_r, __GI_getpwnam_r, __GI_getspnam_r, getgrnam_r, getpwnam_r, getspnam_r"
		type = "func"
		size = "160"
		objfiles = "getspnam_r@libc.a, getgrnam_r@libc.a, getpwnam_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 41 56 49 89 CE 41 55 4D 89 C5 41 54 49 89 F4 BE ?? ?? ?? ?? 55 53 48 83 EC 08 48 89 3C 24 49 C7 00 00 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 75 09 E8 ?? ?? ?? ?? 8B 18 EB 4D C7 40 50 01 00 00 00 49 89 E8 4C 89 F1 4C 89 FA 4C 89 E6 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 89 C3 75 17 48 8B 34 24 49 8B 3C 24 E8 ?? ?? ?? ?? 85 C0 75 D3 4D 89 65 00 EB 0B 83 F8 02 B8 00 00 00 00 0F 44 D8 48 89 EF E8 ?? ?? ?? ?? 5A 89 D8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule getpwuid_r_5c035b786ac3507c7f1cc76b36c88320 {
	meta:
		aliases = "__GI_getgrgid_r, __GI_getpwuid_r, getgrgid_r, getpwuid_r"
		type = "func"
		size = "154"
		objfiles = "getgrgid_r@libc.a, getpwuid_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 41 56 49 89 CE 41 55 4D 89 C5 41 54 49 89 F4 BE ?? ?? ?? ?? 55 53 48 83 EC 08 89 7C 24 04 49 C7 00 00 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 75 09 E8 ?? ?? ?? ?? 8B 18 EB 47 C7 40 50 01 00 00 00 49 89 E8 4C 89 F1 4C 89 FA 4C 89 E6 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 89 C3 75 11 8B 44 24 04 41 39 44 24 10 75 D9 4D 89 65 00 EB 0B 83 F8 02 B8 00 00 00 00 0F 44 D8 48 89 EF E8 ?? ?? ?? ?? 5A 89 D8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule clnttcp_create_e922d15417eebd00c56a329b0b97c26f {
	meta:
		aliases = "__GI_clnttcp_create, clnttcp_create"
		type = "func"
		size = "535"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 41 56 49 89 F6 41 55 49 89 CD 41 54 55 53 48 89 FB BF 18 00 00 00 48 83 EC 78 44 89 44 24 0C 44 89 4C 24 08 E8 ?? ?? ?? ?? BF 98 00 00 00 49 89 C4 E8 ?? ?? ?? ?? 4D 85 E4 48 89 C5 74 05 48 85 C0 75 2B E8 ?? ?? ?? ?? 48 8B 35 ?? ?? ?? ?? 48 89 C3 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 03 0C 00 00 00 C7 43 10 0C 00 00 00 E9 7F 01 00 00 66 83 7B 02 00 75 24 B9 06 00 00 00 4C 89 FA 4C 89 F6 48 89 DF E8 ?? ?? ?? ?? 66 85 C0 0F 84 5C 01 00 00 66 C1 C8 08 66 89 43 02 41 83 7D 00 00 79 6C BA 06 00 00 00 BE 01 00 00 00 BF 02 00 00 00 E8 ?? ?? ?? ?? 31 F6 89 C7 41 89 45 00 E8 ?? ?? ?? ?? 41 8B }
	condition:
		$pattern
}

rule openpty_7334a6007cd8da2cdad0d29370f3be16 {
	meta:
		aliases = "__GI_openpty, openpty"
		type = "func"
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
		type = "func"
		size = "279"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 BA 02 00 00 00 41 56 49 89 F6 BE A0 86 01 00 41 55 4D 89 CD 41 54 49 89 FC 55 BD 10 00 00 00 53 48 81 EC 88 00 00 00 48 89 4C 24 18 4C 89 44 24 10 4C 8D 4C 24 7C 48 8B 0D ?? ?? ?? ?? 4C 8B 05 ?? ?? ?? ?? C7 44 24 7C FF FF FF FF 66 C7 47 02 00 6F E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 0F 84 93 00 00 00 48 8B 44 24 18 4C 89 74 24 20 48 89 DF 4C 89 7C 24 28 4C 89 6C 24 40 48 8D 4C 24 20 4C 8D 4C 24 50 41 B8 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 44 24 30 48 8B 44 24 10 BE 05 00 00 00 48 89 44 24 48 48 8B 84 24 E0 00 00 00 48 89 44 24 50 48 8B 84 24 C8 00 00 00 48 89 44 24 60 48 8B 84 24 C0 00 }
	condition:
		$pattern
}

rule getrpcbynumber_r_6c34f01db6b01a1e0e1e4905e820b016 {
	meta:
		aliases = "getrpcbynumber_r"
		type = "func"
		size = "117"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 BA ?? ?? ?? ?? 41 56 49 89 CE 41 55 41 54 41 89 FC 55 48 89 F5 BE ?? ?? ?? ?? 53 4C 89 C3 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 44 89 E7 E8 ?? ?? ?? ?? 49 89 D8 4C 89 F1 4C 89 FA 48 89 EE 48 89 C7 E8 E4 FA FF FF BE 01 00 00 00 89 C3 48 89 E7 E8 ?? ?? ?? ?? 89 D8 48 83 C4 28 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule getrpcbyname_r_906653a355ac6f18e0ed0673b28b1eb9 {
	meta:
		aliases = "getrpcbyname_r"
		type = "func"
		size = "117"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 D7 BA ?? ?? ?? ?? 41 56 49 89 CE 41 55 41 54 49 89 FC 55 48 89 F5 BE ?? ?? ?? ?? 53 4C 89 C3 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? 49 89 D8 4C 89 F1 4C 89 FA 48 89 EE 48 89 C7 E8 95 FB FF FF BE 01 00 00 00 89 C3 48 89 E7 E8 ?? ?? ?? ?? 89 D8 48 83 C4 28 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule expandargv_95ce13f6b8ceafd8cc53bbbd515880e5 {
	meta:
		aliases = "expandargv"
		type = "func"
		size = "625"
		objfiles = "argv@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 41 56 41 55 41 54 45 31 E4 55 53 48 83 EC 38 8B 17 48 89 3C 24 EB 07 0F 1F 40 00 41 89 DC 41 8D 5C 24 01 39 D3 0F 8D 00 02 00 00 49 8B 07 48 63 EB 4C 8D 2C ED 00 00 00 00 48 8B 04 E8 80 38 40 75 D9 48 8D 78 01 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 49 89 C6 0F 84 BF 01 00 00 31 F6 BA 02 00 00 00 48 89 C7 E8 ?? ?? ?? ?? 83 F8 FF 0F 84 9F 01 00 00 4C 89 F7 E8 ?? ?? ?? ?? 48 83 F8 FF 48 89 44 24 08 0F 84 88 01 00 00 31 D2 31 F6 4C 89 F7 E8 ?? ?? ?? ?? 83 F8 FF 0F 84 73 01 00 00 4C 8B 54 24 08 49 8D 7A 01 4C 89 54 24 10 E8 ?? ?? ?? ?? 4C 8B 54 24 10 4C 89 F1 BE 01 00 00 00 48 89 C7 }
	condition:
		$pattern
}

rule fread_unlocked_eba5236d24fd35782a73dfa6688a8eb2 {
	meta:
		aliases = "__GI_fread_unlocked, fread_unlocked"
		type = "func"
		size = "304"
		objfiles = "fread_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 41 56 41 55 41 54 49 89 CC 55 48 89 FD 53 48 89 D3 48 83 EC 08 0F B7 01 25 83 00 00 00 3D 80 00 00 00 77 15 BE 80 00 00 00 48 89 CF E8 ?? ?? ?? ?? 85 C0 0F 85 E4 00 00 00 4D 85 FF 0F 84 DB 00 00 00 48 85 DB 0F 84 D2 00 00 00 48 83 C8 FF 31 D2 49 F7 F7 48 39 C3 0F 87 AF 00 00 00 49 89 DE 49 89 ED 4D 0F AF F7 4C 89 F5 EB 28 48 89 D0 83 E0 01 48 FF CD 41 8B 44 84 40 41 88 45 00 8D 42 FF 41 C7 44 24 44 00 00 00 00 66 41 89 04 24 74 6E 49 FF C5 41 8B 14 24 F6 C2 02 75 CF 49 8B 74 24 18 49 8B 44 24 20 48 29 F0 74 22 48 39 C5 48 89 C3 4C 89 EF 48 0F 46 DD 48 89 DA E8 ?? ?? ?? ?? 49 01 }
	condition:
		$pattern
}

rule htab_create_alloc_ex_22076d66252e45cebb2be53211858984 {
	meta:
		aliases = "htab_create_alloc_ex"
		type = "func"
		size = "203"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 41 56 41 55 41 54 55 4C 89 CD 53 4C 89 C3 48 83 EC 18 48 89 14 24 48 89 4C 24 08 E8 3B FC FF FF 41 89 C4 89 C0 BA 70 00 00 00 48 C1 E0 04 BE 01 00 00 00 48 89 DF 44 8B A8 ?? ?? ?? ?? FF D5 48 85 C0 49 89 C6 74 6E BA 08 00 00 00 4C 89 EE 48 89 DF FF D5 48 85 C0 49 89 46 18 74 46 48 8B 04 24 4D 89 6E 20 45 89 66 68 4D 89 3E 49 89 5E 50 49 89 6E 58 49 89 46 08 48 8B 44 24 08 49 89 46 10 48 8B 44 24 50 49 89 46 60 48 83 C4 18 4C 89 F0 5B 5D 41 5C 41 5D 41 5E 41 5F C3 0F 1F 80 00 00 00 00 48 83 7C 24 50 00 74 0A 4C 89 F6 48 89 DF FF 54 24 50 48 83 C4 18 31 C0 5B 5D 41 5C 41 5D 41 5E }
	condition:
		$pattern
}

rule htab_create_alloc_c4df4ed506dbdbb2ca3379aacbe01fb4 {
	meta:
		aliases = "htab_create_alloc"
		type = "func"
		size = "180"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 41 56 41 55 4D 89 CD 41 54 55 53 4C 89 C3 48 83 EC 18 48 89 14 24 48 89 4C 24 08 E8 FB FC FF FF 89 C5 89 C0 BE 70 00 00 00 48 C1 E0 04 BF 01 00 00 00 44 8B A0 ?? ?? ?? ?? FF D3 48 85 C0 49 89 C6 74 5B BE 08 00 00 00 4C 89 E7 FF D3 48 85 C0 49 89 46 18 74 3D 48 8B 04 24 4D 89 66 20 41 89 6E 68 4D 89 3E 49 89 5E 40 4D 89 6E 48 49 89 46 08 48 8B 44 24 08 49 89 46 10 48 83 C4 18 4C 89 F0 5B 5D 41 5C 41 5D 41 5E 41 5F C3 0F 1F 80 00 00 00 00 4D 85 ED 74 06 4C 89 F7 41 FF D5 48 83 C4 18 31 C0 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule clntunix_create_c2268b2e7a650a441a4b5870843f1128 {
	meta:
		aliases = "__GI_clntunix_create, clntunix_create"
		type = "func"
		size = "505"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 41 56 49 89 CE 41 55 49 89 FD BF F8 00 00 00 41 54 55 53 48 83 EC 78 48 89 54 24 08 44 89 44 24 04 44 89 0C 24 E8 ?? ?? ?? ?? BF 18 00 00 00 48 89 C5 E8 ?? ?? ?? ?? 48 85 C0 49 89 C4 74 05 48 85 ED 75 2B E8 ?? ?? ?? ?? 48 8B 35 ?? ?? ?? ?? 48 89 C3 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 03 0C 00 00 00 C7 43 10 0C 00 00 00 E9 60 01 00 00 41 83 3E 00 79 66 31 D2 BE 01 00 00 00 BF 01 00 00 00 E8 ?? ?? ?? ?? 49 8D 7D 02 89 C3 41 89 06 E8 ?? ?? ?? ?? 85 DB 78 11 8D 50 03 4C 89 EE 89 DF E8 ?? ?? ?? ?? 85 C0 79 29 E8 ?? ?? ?? ?? C7 00 0C 00 00 00 48 89 C3 E8 ?? ?? ?? ?? 8B 00 89 43 10 41 8B }
	condition:
		$pattern
}

rule sendto_61091211bf087823685595a43e7f5857 {
	meta:
		aliases = "sendto"
		type = "func"
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
		type = "func"
		size = "100"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 41 56 49 89 D6 41 55 41 89 CD 41 54 4D 89 C4 55 89 FD BF 01 00 00 00 53 4C 89 CB 48 83 EC 18 48 8D 74 24 14 E8 ?? ?? ?? ?? 49 89 D9 4D 89 E0 44 89 E9 4C 89 F2 4C 89 FE 89 EF E8 ?? ?? ?? ?? 8B 7C 24 14 48 89 C3 31 F6 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 18 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule add_fdes_f96cba092d126b51e89d56032481c046 {
	meta:
		aliases = "add_fdes"
		type = "func"
		size = "294"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 48 89 FE 41 56 41 55 49 89 FD 41 54 55 48 89 D5 53 48 83 EC 28 0F B7 47 20 66 C1 E8 03 44 0F B6 E0 44 89 E7 E8 42 FB FF FF 8B 75 00 49 89 C6 85 F6 0F 84 DB 00 00 00 48 8D 44 24 20 48 C7 44 24 10 00 00 00 00 48 89 44 24 08 EB 35 48 83 7D 08 00 74 19 49 8B 17 48 85 D2 74 11 48 8B 42 08 48 89 6C C2 10 48 83 C0 01 48 89 42 08 8B 45 00 48 01 E8 8B 48 04 48 8D 68 04 85 C9 0F 84 91 00 00 00 8B 45 04 85 C0 74 E4 41 F6 45 20 04 74 2E 48 8D 5D 04 48 98 48 29 C3 48 39 5C 24 10 74 1E 48 89 DF E8 C4 FC FF FF 4C 89 EE 0F B6 F8 41 89 C4 E8 B6 FA FF FF 48 89 5C 24 10 49 89 C6 45 85 E4 74 8A 48 }
	condition:
		$pattern
}

rule __encode_packet_eb104ecfbeb35349f383c135123dfdaa {
	meta:
		aliases = "__encode_packet"
		type = "func"
		size = "303"
		objfiles = "encodep@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 4C 89 CE 41 56 49 89 FE 41 55 41 54 55 53 4C 89 CB 48 83 EC 18 44 8B 64 24 50 48 89 54 24 10 48 89 4C 24 08 4C 89 04 24 44 89 E2 E8 ?? ?? ?? ?? 85 C0 89 C2 0F 88 DF 00 00 00 48 98 45 31 ED 48 8D 2C 03 44 89 E3 41 89 D4 29 D3 EB 28 44 89 E8 89 DA 48 89 EE 49 8B 3C C7 E8 ?? ?? ?? ?? 85 C0 89 C2 0F 88 B1 00 00 00 48 98 29 D3 41 01 D4 48 01 C5 41 FF C5 45 3B 6E 20 72 D2 45 31 ED EB 29 48 8B 54 24 10 44 89 E8 48 89 EE 48 8B 3C C2 89 DA E8 ?? ?? ?? ?? 85 C0 89 C2 78 7D 48 98 29 D3 41 01 D4 48 01 C5 41 FF C5 45 3B 6E 24 72 D1 45 31 ED EB 29 48 8B 54 24 08 44 89 E8 48 89 EE 48 8B 3C C2 }
	condition:
		$pattern
}

rule readtcp_22e1c7b14083eb00bb4fb9792ae38c31 {
	meta:
		aliases = "readtcp"
		type = "func"
		size = "221"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 BE E8 03 00 00 41 56 41 55 41 54 41 89 D4 55 31 ED 53 48 89 FB 48 83 EC 28 48 8B 4F 10 48 89 C8 48 99 48 F7 FE 48 89 C1 48 69 47 08 E8 03 00 00 45 85 E4 44 8D 2C 01 0F 84 8A 00 00 00 8B 07 4C 8D 74 24 10 66 C7 44 24 14 01 00 89 44 24 10 44 89 EA BE 01 00 00 00 4C 89 F7 E8 ?? ?? ?? ?? 83 F8 FF 89 C5 74 0D 85 C0 75 21 C7 43 30 05 00 00 00 EB 3E E8 ?? ?? ?? ?? 83 38 04 74 D2 C7 43 30 04 00 00 00 8B 00 89 43 38 EB 3C 8B 3B 49 63 D4 4C 89 FE E8 ?? ?? ?? ?? 83 F8 FF 89 C5 74 17 85 C0 75 24 C7 43 38 68 00 00 00 C7 43 30 04 00 00 00 83 CD FF EB 11 E8 ?? ?? ?? ?? 8B 00 C7 43 30 04 00 00 }
	condition:
		$pattern
}

rule readunix_46d00534574975e8bd2c740f6366b8c5 {
	meta:
		aliases = "readunix"
		type = "func"
		size = "405"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 BE E8 03 00 00 41 56 41 55 41 89 D5 41 54 55 48 89 FD 53 31 DB 48 83 EC 78 48 8B 4F 10 48 89 C8 48 99 48 F7 FE 48 89 C1 48 69 47 08 E8 03 00 00 45 85 ED 44 8D 24 01 0F 84 42 01 00 00 8B 07 4C 8D 74 24 60 66 C7 44 24 64 01 00 89 44 24 60 44 89 E2 BE 01 00 00 00 4C 89 F7 E8 ?? ?? ?? ?? 83 F8 FF 89 C3 74 13 85 C0 75 30 C7 85 90 00 00 00 05 00 00 00 E9 EA 00 00 00 E8 ?? ?? ?? ?? 83 38 04 74 CC C7 85 90 00 00 00 04 00 00 00 8B 00 89 85 98 00 00 00 E9 E5 00 00 00 44 8B 65 00 49 63 C5 48 8D 4C 24 6C 48 89 44 24 58 48 8D 44 24 50 41 B8 04 00 00 00 BA 10 00 00 00 BE 01 00 00 00 4C 89 7C }
	condition:
		$pattern
}

rule search_object_399bcb4aa6a990793301fce1bcf77aca {
	meta:
		aliases = "search_object"
		type = "func"
		size = "1701"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 41 55 41 54 55 53 48 81 EC A8 00 00 00 48 89 74 24 28 0F B6 57 20 F6 C2 01 0F 85 48 03 00 00 8B 4F 20 89 C8 C1 E8 0B 89 C3 85 C0 48 89 5C 24 30 0F 84 5C 04 00 00 48 83 7C 24 30 00 0F 84 0D 03 00 00 48 8B 44 24 30 48 8D 1C C5 10 00 00 00 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 48 89 84 24 80 00 00 00 0F 84 E7 02 00 00 48 C7 40 08 00 00 00 00 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 48 89 84 24 88 00 00 00 74 08 48 C7 40 08 00 00 00 00 41 F6 47 20 02 0F 84 92 04 00 00 49 8B 47 18 48 8B 10 48 85 D2 74 23 48 8D AC 24 80 00 00 00 48 89 C3 48 89 EE 4C 89 FF E8 0F FA FF FF 48 8B 53 08 48 83 C3 }
	condition:
		$pattern
}

rule xdr_array_397c49a5b5d9ffc40e96d1aa6e6eba9f {
	meta:
		aliases = "__GI_xdr_array, xdr_array"
		type = "func"
		size = "286"
		objfiles = "xdr_array@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 41 89 CE 41 55 45 89 C5 41 54 55 48 89 D5 53 48 83 EC 18 48 89 74 24 10 4C 89 4C 24 08 48 8B 1E 48 89 D6 E8 ?? ?? ?? ?? 85 C0 0F 84 CD 00 00 00 44 8B 65 00 45 39 F4 77 0D 83 C8 FF 31 D2 41 F7 F5 41 39 C4 76 0A 41 83 3F 02 0F 85 AD 00 00 00 48 85 DB 75 5A 41 8B 07 83 F8 01 74 0A 83 F8 02 75 4D E9 9A 00 00 00 45 85 E4 0F 84 91 00 00 00 44 89 ED 41 0F AF EC 48 89 EF E8 ?? ?? ?? ?? 48 89 C3 48 8B 44 24 10 48 85 DB 48 89 18 75 13 48 8B 35 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 5B 48 89 EA 31 F6 48 89 DF E8 ?? ?? ?? ?? 45 31 F6 BD 01 00 00 00 45 89 ED EB 17 48 89 DE 83 CA }
	condition:
		$pattern
}

rule htab_find_slot_with_hash_bb34b9767de35a6c4ddd6dc0fccd8d82 {
	meta:
		aliases = "htab_find_slot_with_hash"
		type = "func"
		size = "543"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 41 89 D6 41 55 41 54 55 53 48 83 EC 28 83 F9 01 48 8B 6F 20 48 89 74 24 08 89 4C 24 1C 0F 84 86 01 00 00 41 8B 47 68 45 89 F5 44 89 F6 44 89 F3 48 C1 E0 04 4C 8D 90 ?? ?? ?? ?? 44 8B 98 ?? ?? ?? ?? 41 8B 42 04 41 8B 4A 0C 41 83 47 38 01 49 0F AF C5 48 C1 E8 20 29 C6 D1 EE 01 F0 49 8B 77 18 D3 E8 41 0F AF C3 29 C3 41 89 D9 49 C1 E1 03 4E 8D 24 0E 4C 89 4C 24 10 49 8B 3C 24 48 85 FF 0F 84 6D 01 00 00 48 83 FF 01 74 37 48 8B 74 24 08 41 FF 57 08 85 C0 4C 8B 4C 24 10 0F 85 E7 00 00 00 41 8B 47 68 49 8B 77 18 45 31 E4 48 C1 E0 04 4C 8D 90 ?? ?? ?? ?? 44 8B 98 ?? ?? ?? ?? 41 8B }
	condition:
		$pattern
}

rule xdr_vector_e702eb7aa11dfd37745fb93f5e66d4bb {
	meta:
		aliases = "xdr_vector"
		type = "func"
		size = "78"
		objfiles = "xdr_array@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 41 89 D6 41 55 4D 89 C5 41 54 41 89 CC 55 31 ED 53 48 89 F3 48 83 EC 08 EB 17 83 CA FF 31 C0 48 89 DE 4C 89 FF 41 FF D5 85 C0 74 0F 4C 01 E3 FF C5 44 39 F5 72 E4 B8 01 00 00 00 5A 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule _fp_out_wide_680d94f35263fe3e593bf6b2e3abe891 {
	meta:
		aliases = "_fp_out_wide"
		type = "func"
		size = "150"
		objfiles = "_vfwprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 49 89 CE 41 55 45 31 ED 41 54 49 89 F4 55 53 48 89 D3 48 81 EC 88 00 00 00 40 84 F6 79 2F 48 89 CF E8 ?? ?? ?? ?? 48 63 E8 48 29 EB 48 85 DB 7E 19 44 89 E6 48 89 DA 4C 89 FF 83 E6 7F E8 B4 F7 FF FF 48 39 D8 49 89 C5 75 30 48 89 EB 48 85 DB 7E 28 31 C9 48 63 C1 FF C1 41 0F BE 14 06 89 14 84 48 63 C1 48 39 D8 7C EB 48 89 E7 4C 89 FA 48 89 DE E8 ?? ?? ?? ?? 49 01 C5 48 81 C4 88 00 00 00 4C 89 E8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule _fp_out_narrow_e119984b27c2abe7a3940e8925d23fb3 {
	meta:
		aliases = "_fp_out_narrow"
		type = "func"
		size = "120"
		objfiles = "_vfprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 49 89 CE 41 55 45 31 ED 41 54 49 89 F4 55 53 48 89 D3 48 83 EC 08 40 84 F6 79 2F 48 89 CF E8 ?? ?? ?? ?? 48 63 E8 48 29 EB 48 85 DB 7E 19 44 89 E6 48 89 DA 4C 89 FF 83 E6 7F E8 6D FF FF FF 48 39 D8 49 89 C5 75 1B 48 89 EB 31 C0 48 85 DB 7E 0E 4C 89 FA 48 89 DE 4C 89 F7 E8 ?? ?? ?? ?? 49 01 C5 5A 5B 5D 41 5C 4C 89 E8 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule _fpmaxtostr_e58c1d519841f5875fe03a4fa15c74f6 {
	meta:
		aliases = "_fpmaxtostr"
		type = "func"
		size = "1570"
		objfiles = "_fpmaxtostr@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 49 89 D6 41 55 41 54 49 89 F4 55 53 48 81 EC 18 01 00 00 8A 5E 08 8B 2E 44 8B 6E 04 C6 84 24 F0 00 00 00 65 C6 84 24 00 01 00 00 00 88 D8 8D 53 06 83 C8 20 3C 61 B8 06 00 00 00 0F 44 DA 8B 56 0C 85 ED 0F 48 E8 DB AC 24 50 01 00 00 F6 C2 02 74 0A C6 84 24 00 01 00 00 2B EB 11 80 E2 01 B0 20 B2 00 0F 44 C2 88 84 24 00 01 00 00 DB E8 C6 84 24 01 01 00 00 00 48 C7 44 24 38 00 00 00 00 7A 02 74 0D DD D8 48 C7 44 24 38 08 00 00 00 EB 51 D9 EE D9 C9 DB E9 75 23 7A 21 D9 E8 41 83 C9 FF D8 F1 D9 CA DF EA DD D9 0F 86 07 01 00 00 C6 84 24 00 01 00 00 2D E9 FA 00 00 00 DD D9 D9 EE DF }
	condition:
		$pattern
}

rule __add_to_environ_d390743b2b70c4486adda4f07904cfa5 {
	meta:
		aliases = "__add_to_environ"
		type = "func"
		size = "485"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 49 89 D6 41 55 41 54 55 53 48 83 EC 48 48 89 74 24 10 89 4C 24 0C E8 ?? ?? ?? ?? 48 83 7C 24 10 00 49 89 C4 48 C7 44 24 18 00 00 00 00 74 12 48 8B 7C 24 10 E8 ?? ?? ?? ?? 48 FF C0 48 89 44 24 18 48 8D 7C 24 20 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 45 31 ED E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 2D ?? ?? ?? ?? 48 85 ED 74 3B EB 20 4C 89 E2 4C 89 FE 48 89 DF E8 ?? ?? ?? ?? 85 C0 75 07 42 80 3C 23 3D 74 10 49 FF C5 48 83 C5 08 48 8B 5D 00 48 85 DB 75 D7 48 85 ED 74 0B 48 83 7D 00 00 0F 85 BB 00 00 00 49 C1 E5 03 48 8B 3D ?? ?? ?? ?? 49 8D 75 10 E8 ?? ?? ?? ?? 48 85 C0 48 }
	condition:
		$pattern
}

rule freopen_a979002adabfb2da741caf577a6f3583 {
	meta:
		aliases = "freopen"
		type = "func"
		size = "275"
		objfiles = "freopen@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 49 89 F6 41 55 41 54 55 48 89 D5 53 48 83 EC 48 44 8B 6A 50 45 85 ED 75 1E 48 8D 5A 58 48 8D 7C 24 20 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 FF C0 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 5D 00 89 D8 80 E4 9F 66 89 45 00 83 E0 30 83 F8 30 74 37 48 89 EF E8 ?? ?? ?? ?? BE ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 FF 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C9 FF 48 89 EA 4C 89 }
	condition:
		$pattern
}

rule freopen64_c493d98786d830cfecef646be73cd7b5 {
	meta:
		aliases = "freopen64"
		type = "func"
		size = "277"
		objfiles = "freopen64@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 49 89 F6 41 55 41 54 55 48 89 D5 53 48 83 EC 48 44 8B 6A 50 45 85 ED 75 1E 48 8D 5A 58 48 8D 7C 24 20 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 FF C0 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 5D 00 89 D8 80 E4 9F 66 89 45 00 83 E0 30 83 F8 30 74 37 48 89 EF E8 ?? ?? ?? ?? BE ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 FF 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? B9 FE FF FF FF 48 89 EA }
	condition:
		$pattern
}

rule fwrite_304e419c6d00e9e0585506a839739d8f {
	meta:
		aliases = "__GI_fread, __GI_fwrite, fread, fwrite"
		type = "func"
		size = "119"
		objfiles = "fwrite@libc.a, fread@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 49 89 F6 41 55 49 89 D5 41 54 55 48 89 CD 53 48 83 EC 28 44 8B 61 50 45 85 E4 75 1C 48 8D 59 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 E9 4C 89 EA 4C 89 F6 4C 89 FF E8 ?? ?? ?? ?? 45 85 E4 48 89 C3 75 0D 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 48 89 D8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule md5_process_bytes_be697894e17c439407b4b780296f1f34 {
	meta:
		aliases = "md5_process_bytes"
		type = "func"
		size = "417"
		objfiles = "md5@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 49 89 F6 41 55 49 89 D5 41 54 55 53 48 83 EC 18 8B 5A 18 85 DB 0F 85 D6 00 00 00 49 83 FE 40 0F 86 9E 00 00 00 41 F6 C7 03 0F 84 02 01 00 00 49 8D 6D 1C 4D 89 F4 4C 89 FB 48 8B 03 4C 89 EA BE 40 00 00 00 48 89 EF 49 83 EC 40 48 83 C3 40 48 89 45 00 48 8B 43 C8 48 89 45 08 48 8B 43 D0 48 89 45 10 48 8B 43 D8 48 89 45 18 48 8B 43 E0 48 89 45 20 48 8B 43 E8 48 89 45 28 48 8B 43 F0 48 89 45 30 48 8B 43 F8 48 89 45 38 E8 ?? ?? ?? ?? 49 83 FC 40 77 A3 49 8D 46 BF 48 C1 E8 06 48 8D 50 01 48 F7 D8 48 C1 E0 06 4D 8D 74 06 C0 48 C1 E2 06 49 01 D7 4C 89 F6 48 83 E6 C0 49 01 F7 41 83 }
	condition:
		$pattern
}

rule __pgsreader_e8989641b65b3445650e8a87988a614f {
	meta:
		aliases = "__pgsreader"
		type = "func"
		size = "301"
		objfiles = "__pgsreader@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 49 89 F6 41 55 4D 89 C5 41 54 49 89 CC 55 48 89 D5 53 48 83 EC 38 48 81 F9 FF 00 00 00 77 15 BB 22 00 00 00 E8 ?? ?? ?? ?? C7 00 22 00 00 00 E9 E1 00 00 00 41 8B 40 50 85 C0 89 44 24 0C 74 0D 4A 8D 44 25 00 31 DB 48 89 04 24 EB 20 49 8D 58 58 48 8D 7C 24 10 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? EB D3 4C 89 EA 44 89 E6 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 75 15 41 0F B7 45 00 83 E0 04 83 F8 01 19 DB 83 E3 20 83 C3 02 EB 6A 48 89 EF E8 ?? ?? ?? ?? 48 8D 54 05 FF 80 3A 0A 75 05 C6 02 00 EB 0C 48 FF C0 4C 39 E0 75 04 FF C3 EB B5 85 DB 74 04 FF CB EB AD 8A }
	condition:
		$pattern
}

rule getrpcent_r_6583be4c9681b82b4290cce477acff9e {
	meta:
		aliases = "getrpcent_r"
		type = "func"
		size = "109"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 49 89 F6 BE ?? ?? ?? ?? 41 55 49 89 D5 BA ?? ?? ?? ?? 41 54 53 48 89 CB 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 49 89 D8 4C 89 E9 4C 89 F2 4C 89 FE 48 89 C7 E8 EA FC FF FF BE 01 00 00 00 89 C3 48 89 E7 E8 ?? ?? ?? ?? 89 D8 48 83 C4 20 5B 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule svc_register_7e525cab8be2f4f90ba9c473a9474385 {
	meta:
		aliases = "__GI_svc_register, svc_register"
		type = "func"
		size = "158"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 4D 89 C6 41 55 49 89 CD 41 54 49 89 F4 4C 89 E7 55 48 89 D5 48 89 EE 53 48 83 EC 18 48 8D 54 24 10 E8 C8 FC FF FF 48 85 C0 74 08 4C 39 68 18 75 55 EB 34 BF 20 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 41 4C 89 60 08 48 89 68 10 4C 89 68 18 E8 ?? ?? ?? ?? 48 8B 90 F0 00 00 00 48 89 13 48 89 98 F0 00 00 00 4D 85 F6 B8 01 00 00 00 74 17 41 0F B7 4F 04 44 89 F2 48 89 EE 4C 89 E7 E8 ?? ?? ?? ?? EB 02 31 C0 48 83 C4 18 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule ether_ntohost_6a91f2dafffa411101acf76f61d83ce2 {
	meta:
		aliases = "ether_ntohost"
		type = "func"
		size = "165"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF BF ?? ?? ?? ?? 41 56 49 89 F6 BE ?? ?? ?? ?? 41 55 41 54 55 53 83 CB FF 48 81 EC 18 01 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 74 60 EB 36 4C 89 E6 48 89 E7 E8 02 FF FF FF 48 85 C0 48 89 C3 74 2B BA 06 00 00 00 4C 89 E6 4C 89 F7 E8 ?? ?? ?? ?? 85 C0 75 17 48 89 DE 4C 89 FF 31 DB E8 ?? ?? ?? ?? EB 20 4C 8D A4 24 00 01 00 00 48 89 EA BE 00 01 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 85 C0 75 AD 83 CB FF 48 89 EF E8 ?? ?? ?? ?? 48 81 C4 18 01 00 00 89 D8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule __uClibc_main_99c0be8fa65f8634a0a9a91e04b7d75d {
	meta:
		aliases = "__uClibc_main"
		type = "func"
		size = "509"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 4D 89 C7 41 56 41 89 F6 41 55 49 89 CD 41 54 49 89 D4 55 53 48 81 EC 08 01 00 00 4C 89 0D ?? ?? ?? ?? 48 8B 84 24 40 01 00 00 48 89 7C 24 08 48 89 05 ?? ?? ?? ?? 48 63 C6 48 8D 14 C5 00 00 00 00 4A 8D 44 22 08 48 89 05 ?? ?? ?? ?? 49 3B 04 24 75 0B 49 8D 04 14 48 89 05 ?? ?? ?? ?? 48 8D 7C 24 10 BA F0 00 00 00 31 F6 E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 83 38 00 48 8D 40 08 75 F6 48 8D 6C 24 10 48 89 C3 EB 23 48 8B 03 48 83 F8 0E 77 16 48 C1 E0 04 BA 10 00 00 00 48 89 DE 48 8D 7C 05 00 E8 ?? ?? ?? ?? 48 83 C3 10 48 83 3B 00 75 D7 48 8D 7C 24 10 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 44 24 }
	condition:
		$pattern
}

rule bsearch_b4449e02b3f95649dd5fce39d9dfd849 {
	meta:
		aliases = "bsearch"
		type = "func"
		size = "125"
		objfiles = "bsearch@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 4D 89 C7 41 56 49 89 CE 41 55 45 31 ED 41 54 55 48 89 D5 53 48 83 EC 18 48 85 C9 48 89 7C 24 10 48 89 74 24 08 75 3E EB 41 48 89 E8 4C 8B 64 24 08 48 8B 7C 24 10 4C 29 E8 48 D1 E8 4A 8D 1C 28 48 89 D8 49 0F AF C6 49 01 C4 4C 89 E6 41 FF D7 83 F8 00 7E 06 4C 8D 6B 01 EB 0A 75 05 4C 89 E0 EB 0A 48 89 DD 49 39 ED 72 BF 31 C0 48 83 C4 18 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule registerrpc_fb0818af048b98be543e8b81f42bad20 {
	meta:
		aliases = "registerrpc"
		type = "func"
		size = "297"
		objfiles = "svc_simple@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 4D 89 C7 41 56 49 89 CE 41 55 49 89 D5 41 54 49 89 FC 55 48 89 F5 53 48 83 EC 18 48 85 D2 4C 89 0C 24 75 18 48 8D 7C 24 10 31 D2 BE ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? E9 BE 00 00 00 E8 ?? ?? ?? ?? 48 83 B8 08 01 00 00 00 48 89 C3 75 19 83 CF FF E8 ?? ?? ?? ?? 48 85 C0 48 89 83 08 01 00 00 BF ?? ?? ?? ?? 74 5A 48 89 EE 4C 89 E7 E8 ?? ?? ?? ?? 48 8B BB 08 01 00 00 41 B8 11 00 00 00 B9 ?? ?? ?? ?? 48 89 EA 4C 89 E6 E8 ?? ?? ?? ?? 85 C0 75 17 48 8D 7C 24 10 48 89 E9 4C 89 E2 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 50 BF 28 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C2 75 11 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule splay_tree_new_with_allocator_852bb4a55de37d9831f47d958ea6da0d {
	meta:
		aliases = "splay_tree_new_with_allocator"
		type = "func"
		size = "88"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 4D 89 C7 41 56 49 89 D6 41 55 49 89 FD BF 38 00 00 00 41 54 49 89 F4 4C 89 CE 55 4C 89 CD 53 48 89 CB 48 83 EC 08 FF D1 48 C7 00 00 00 00 00 4C 89 68 08 4C 89 60 10 4C 89 70 18 48 89 58 20 4C 89 78 28 48 89 68 30 48 83 C4 08 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule getservbyname_r_4a37d8cf2cda8a990c39e5a9ac736461 {
	meta:
		aliases = "__GI_getservbyname_r, getservbyname_r"
		type = "func"
		size = "233"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 4D 89 CF 41 56 49 89 FE 41 55 49 89 F5 BE ?? ?? ?? ?? 41 54 49 89 D4 BA ?? ?? ?? ?? 55 53 48 83 EC 38 48 8D 7C 24 10 48 89 4C 24 08 4C 89 04 24 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 47 49 8B 34 24 4C 89 F7 E8 ?? ?? ?? ?? 85 C0 74 21 49 8B 5C 24 08 EB 10 4C 89 F7 E8 ?? ?? ?? ?? 85 C0 74 0E 48 83 C3 08 48 8B 33 48 85 F6 75 E8 EB 16 4D 85 ED 74 2B 49 8B 7C 24 18 4C 89 EE E8 ?? ?? ?? ?? 85 C0 74 1A 48 8B 14 24 48 8B 74 24 08 4C 89 F9 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 89 C5 74 9F 83 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 48 8D 7C 24 10 BE 01 00 00 00 E8 }
	condition:
		$pattern
}

rule __ns_name_unpack_5c541685f7f04789b865431d6632639d {
	meta:
		aliases = "__GI___ns_name_unpack, __ns_name_unpack"
		type = "func"
		size = "318"
		objfiles = "ns_name@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 4E 8D 04 01 49 89 FF 41 56 49 89 D6 41 55 49 89 F5 41 54 55 53 48 83 EC 28 48 39 FA 4C 89 44 24 20 0F 82 D0 00 00 00 48 39 F2 0F 83 C7 00 00 00 C7 44 24 14 01 00 00 00 29 54 24 14 48 89 F0 48 29 F8 49 89 D4 41 83 C9 FF 45 31 C0 48 89 44 24 18 E9 B2 00 00 00 40 0F B6 D7 89 D0 25 C0 00 00 00 74 0D 3D C0 00 00 00 0F 85 89 00 00 00 EB 47 48 63 EA 48 8D 44 29 01 48 3B 44 24 20 73 78 4C 8D 24 2E 4D 39 EC 73 6F 48 8D 59 01 45 8D 44 10 01 40 88 39 48 89 EA 44 89 0C 24 48 89 DF 44 89 44 24 08 E8 ?? ?? ?? ?? 44 8B 44 24 08 44 8B 0C 24 48 8D 0C 2B EB 51 4C 39 EE 73 3B 8B 44 24 14 01 F0 41 83 F9 FF }
	condition:
		$pattern
}

rule fnmatch_cb03e9e35800f452c7d09ac98624f88a {
	meta:
		aliases = "__GI_fnmatch, fnmatch"
		type = "func"
		size = "1238"
		objfiles = "fnmatch_old@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 89 D0 41 89 D2 83 E0 04 41 89 D3 41 83 E2 10 41 56 41 89 D6 41 83 E6 01 41 55 49 89 F5 41 54 55 48 89 F5 53 48 83 EC 10 89 44 24 08 89 D0 D1 E8 83 F0 01 83 E0 01 88 44 24 07 89 D0 83 E0 02 89 04 24 E9 56 04 00 00 45 85 D2 45 89 D7 74 23 84 D2 78 1F 48 0F BE C2 48 8D 0C 00 48 8B 05 ?? ?? ?? ?? F6 04 08 01 74 0A 48 8B 05 ?? ?? ?? ?? 8A 14 08 48 FF C7 80 FA 3F 74 24 7F 0E 80 FA 2A 0F 85 DC 03 00 00 E9 D3 00 00 00 80 FA 5B 0F 84 DB 01 00 00 80 FA 5C 0F 85 C5 03 00 00 EB 48 8A 45 00 84 C0 0F 84 15 04 00 00 45 84 F6 44 88 F2 74 08 3C 2F 0F 84 05 04 00 00 83 7C 24 08 00 0F 84 D6 03 00 00 3C 2E }
	condition:
		$pattern
}

rule xregcomp_18bc160f37d6613a6d378f28be0957d0 {
	meta:
		aliases = "xregcomp"
		type = "func"
		size = "381"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 89 D0 49 89 FF 83 E0 01 41 56 41 55 41 89 D5 41 54 55 53 48 83 EC 18 83 F8 01 48 C7 07 00 00 00 00 4D 19 E4 48 C7 47 08 00 00 00 00 48 C7 47 10 00 00 00 00 49 81 E4 CA 4F FD FF BF 00 01 00 00 48 89 74 24 08 49 81 C4 FC B2 03 00 E8 ?? ?? ?? ?? 41 F6 C5 02 49 89 47 20 0F 85 A7 00 00 00 49 C7 47 28 00 00 00 00 41 F6 C5 04 0F 85 7D 00 00 00 41 80 67 38 7F 41 0F B6 47 38 41 C1 ED 03 48 8B 5C 24 08 41 83 E5 01 41 C1 E5 04 48 89 DF 83 E0 EF 44 09 E8 41 88 47 38 E8 ?? ?? ?? ?? 48 89 DF 4C 89 F9 4C 89 E2 48 89 C6 BB 08 00 00 00 E8 CA D0 FF FF 83 F8 10 74 20 85 C0 89 C3 75 1A 49 83 7F 20 00 74 11 }
	condition:
		$pattern
}

rule pex_get_status_and_time_9dfae1c44ab7349d97ea428289995851 {
	meta:
		aliases = "pex_get_status_and_time"
		type = "func"
		size = "274"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 B8 01 00 00 00 41 56 41 55 41 54 55 53 48 89 FB 48 83 EC 28 89 74 24 14 48 63 77 2C 39 77 48 48 89 54 24 18 0F 84 B2 00 00 00 48 8B 7F 38 48 C1 E6 02 49 89 CF E8 ?? ?? ?? ?? F6 03 01 48 89 43 38 0F 85 A7 00 00 00 44 8B 6B 48 44 3B 6B 2C 0F 8D B3 00 00 00 49 63 ED 4C 89 F8 41 BC 01 00 00 00 49 89 EE 49 C1 E6 05 4D 89 F7 45 89 EE 49 89 C5 0F 1F 44 00 00 48 8B 53 40 48 8B 43 70 BF 00 00 00 00 48 8B 73 30 4C 8B 4C 24 18 44 8B 44 24 14 48 85 D2 4A 8D 0C 3A 48 8B 53 38 48 8B 34 EE 48 8B 40 20 48 0F 44 CF 4C 89 2C 24 48 89 DF 48 8D 14 AA FF D0 85 C0 B8 00 00 00 00 44 0F 48 E0 41 83 C6 01 48 83 }
	condition:
		$pattern
}

rule __copy_rpcent_3394df0e0e0ec57d7782629663a22e68 {
	meta:
		aliases = "__copy_rpcent"
		type = "func"
		size = "277"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 B8 02 00 00 00 49 89 CF 41 56 41 55 41 54 49 89 F4 55 48 89 FD 53 48 89 D3 48 83 EC 08 48 85 FF 49 C7 00 00 00 00 00 4C 89 04 24 0F 84 D6 00 00 00 BA 18 00 00 00 31 F6 4C 89 E7 E8 ?? ?? ?? ?? 4C 89 FA 31 F6 48 89 DF E8 ?? ?? ?? ?? 8B 45 10 31 D2 41 89 44 24 10 48 8B 45 08 48 8B 04 D0 48 FF C2 48 85 C0 75 F0 48 8D 04 D5 00 00 00 00 49 39 C7 0F 82 8A 00 00 00 4C 8D 6A FF 4C 8D 34 03 49 29 C7 49 89 5C 24 08 EB 43 48 8B 45 08 4A 8D 1C ED 00 00 00 00 48 8B 3C 18 E8 ?? ?? ?? ?? 48 8D 50 01 49 39 D7 72 5A 49 8B 44 24 08 49 29 D7 4C 89 34 18 48 8B 45 08 49 01 D6 48 8B 34 18 49 8B 44 24 08 48 8B }
	condition:
		$pattern
}

rule gethostbyname_r_6134815e9c440d42397ff4f7a4b39c5c {
	meta:
		aliases = "__GI_gethostbyname_r, gethostbyname_r"
		type = "func"
		size = "899"
		objfiles = "gethostbyname_r@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 B8 16 00 00 00 41 56 41 55 49 89 D5 41 54 55 53 48 89 CB 48 81 EC B8 00 00 00 48 89 7C 24 30 48 89 74 24 28 4C 89 44 24 20 4C 89 4C 24 18 49 C7 00 00 00 00 00 48 83 7C 24 30 00 0F 84 2E 03 00 00 E8 ?? ?? ?? ?? 8B 28 49 89 C4 C7 00 00 00 00 00 48 8B 44 24 18 4C 8B 4C 24 20 49 89 D8 48 8B 54 24 28 48 8B 7C 24 30 4C 89 E9 BE 02 00 00 00 48 89 04 24 E8 ?? ?? ?? ?? 85 C0 0F 84 EE 02 00 00 48 8B 4C 24 18 8B 11 83 FA 01 74 18 83 FA 04 74 13 FF C2 0F 85 D5 02 00 00 41 83 3C 24 02 0F 85 CA 02 00 00 44 89 E8 41 89 2C 24 F7 D8 83 E0 07 74 11 48 98 48 39 C3 0F 82 AC 02 00 00 49 01 C5 48 29 C3 48 8B }
	condition:
		$pattern
}

rule _svcauth_unix_85dd30dd0c617edd32fc763b4dad02b4 {
	meta:
		aliases = "_svcauth_unix"
		type = "func"
		size = "433"
		objfiles = "svc_authux@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 B9 01 00 00 00 41 56 49 89 F6 41 55 41 54 55 53 48 83 EC 48 48 89 7C 24 08 4C 8B 6F 30 48 8D 5C 24 10 48 89 DF 49 8D 45 28 49 89 45 08 49 8D 85 28 01 00 00 49 89 45 20 44 8B 7E 40 48 8B 76 38 44 89 FA E8 ?? ?? ?? ?? 48 8B 44 24 18 44 89 FE 48 89 DF FF 50 30 48 85 C0 48 89 C2 0F 84 A9 00 00 00 8B 00 0F C8 89 C0 49 89 45 00 8B 6A 04 0F CD 81 FD FF 00 00 00 0F 87 07 01 00 00 4C 8D 62 08 49 8B 7D 08 89 EB 48 89 DA 4C 89 E6 E8 ?? ?? ?? ?? 49 8B 45 08 44 8D 45 03 41 83 E0 FC C6 04 18 00 44 89 C0 49 8D 14 04 8B 02 0F C8 41 89 45 10 8B 42 04 0F C8 41 89 45 14 8B 72 08 0F CE 83 FE 10 0F 87 BC 00 }
	condition:
		$pattern
}

rule __md5_crypt_4d2f5e8915558a12d00d4b8fe6b7131c {
	meta:
		aliases = "__md5_crypt"
		type = "func"
		size = "777"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 41 ) 57 BA 03 00 00 00 41 56 41 55 41 54 55 48 89 FD 53 48 89 F3 BE ?? ?? ?? ?? 48 89 DF 49 89 DF 48 81 EC 08 01 00 00 E8 ?? ?? ?? ?? 48 8D 53 03 85 C0 4C 0F 44 FA 49 8D 4F 08 4C 89 F8 EB 03 48 FF C0 8A 10 84 D2 74 0A 80 FA 24 74 05 48 39 C8 72 ED 4C 8D B4 24 80 00 00 00 44 29 F8 48 8D 5C 24 20 89 44 24 14 4C 8D A4 24 E0 00 00 00 4C 89 F7 E8 B7 FC FF FF 48 89 EF E8 ?? ?? ?? ?? 48 89 EE 89 C2 4C 89 F7 49 89 C5 89 44 24 1C 89 44 24 18 E8 32 FE FF FF BA 03 00 00 00 BE ?? ?? ?? ?? 4C 89 F7 E8 20 FE FF FF 8B 54 24 14 4C 89 FE 4C 89 F7 E8 11 FE FF FF 48 89 DF E8 6E FC FF FF 48 89 DF 44 89 EA 48 89 EE }
	condition:
		$pattern
}

rule mallinfo_7f2568bbb9e96c2413dff6c93d517b1d {
	meta:
		aliases = "__GI_mallinfo, mallinfo"
		type = "func"
		size = "343"
		objfiles = "mallinfo@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 41 56 41 55 41 54 55 48 89 FD 53 48 83 EC 48 48 8D 7C 24 20 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 3D ?? ?? ?? ?? 00 75 0A BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 31 C9 45 31 C0 48 8B 40 08 C7 44 24 1C 00 00 00 00 48 89 44 24 10 EB 26 89 C8 48 8B 14 C5 ?? ?? ?? ?? EB 13 FF 44 24 1C 48 8B 42 08 48 8B 52 10 48 83 E0 FC 49 01 C0 48 85 D2 75 E8 FF C1 83 F9 0A 76 D5 48 8B 44 24 10 BE 01 00 00 00 C7 44 24 18 01 00 00 00 48 83 E0 FC 4D 8D 3C 00 EB 2D 8D 04 36 89 C0 48 8D 0C C5 ?? ?? ?? ?? 48 8B 51 18 EB 13 FF 44 24 18 48 8B 42 08 48 8B 52 18 }
	condition:
		$pattern
}

rule __open_nameservers_e152b173d4f5ac17f5c7c44db3d1f86d {
	meta:
		aliases = "__open_nameservers"
		type = "func"
		size = "589"
		objfiles = "opennameservers@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 41 56 41 55 41 54 55 53 48 81 EC D8 00 00 00 48 8D BC 24 B0 00 00 00 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 0F 8F EA 01 00 00 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 49 89 C5 0F 85 9D 01 00 00 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 49 89 C5 0F 85 82 01 00 00 E9 A4 01 00 00 48 FF C6 8A 0E 84 C9 0F 84 70 01 00 00 48 8B 05 ?? ?? ?? ?? 48 0F BE D1 F6 04 50 20 75 E2 80 F9 0A 0F 84 56 01 00 00 45 31 F6 80 F9 23 75 58 E9 49 01 00 00 49 63 C6 41 FF C6 48 89 B4 C4 80 00 00 00 EB 03 48 FF C6 8A 0E 84 C9 74 1E 48 }
	condition:
		$pattern
}

rule malloc_10b62c11a94c9316aaaa80f3d3103446 {
	meta:
		aliases = "malloc"
		type = "func"
		size = "2187"
		objfiles = "malloc@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 41 56 41 55 41 54 55 53 48 89 FB 48 83 EC 48 48 8D 7C 24 20 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 FB BF 76 12 31 DB E8 ?? ?? ?? ?? C7 00 0C 00 00 00 E9 32 08 00 00 48 8D 43 17 41 BD 20 00 00 00 48 83 F8 1F 76 07 49 89 C5 49 83 E5 F0 48 8B 1D ?? ?? ?? ?? F6 C3 01 75 18 48 85 DB 0F 85 AF 03 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 A0 03 00 00 49 39 DD 77 26 44 89 E8 C1 E8 03 83 E8 02 89 C1 48 8B 14 CD ?? ?? ?? ?? 48 85 D2 74 0E 48 8B 42 10 48 89 04 CD ?? ?? ?? ?? EB 3D 49 81 FD FF 00 00 00 77 3D 45 89 EC 41 C1 EC 03 43 8D 04 24 89 C0 48 8D 0C C5 ?? }
	condition:
		$pattern
}

rule _time_tzset_4a617d125015b8862dd1f5f870a52a75 {
	meta:
		aliases = "_time_tzset"
		type = "func"
		size = "1023"
		objfiles = "tzset@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 41 56 41 55 41 89 FD 41 54 55 53 48 81 EC C8 00 00 00 48 8D BC 24 90 00 00 00 48 C7 84 24 B8 00 00 00 00 00 00 00 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 75 5E 31 F6 31 C0 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 41 89 C4 78 44 BD 44 00 00 00 48 89 E3 48 89 EA 48 89 DE 44 89 E7 E8 ?? ?? ?? ?? 48 83 F8 00 7C 1E 74 08 48 01 C3 48 29 C5 75 E2 48 39 E3 76 0F 80 7B FF 0A 75 09 C6 43 FF 00 48 89 E3 EB 02 31 DB 44 89 E7 E8 ?? ?? ?? ?? 48 85 DB 74 06 8A 03 84 C0 75 2C 31 F6 BA 40 00 00 00 BF ?? ?? ?? ?? C6 05 ?? ?? ?? }
	condition:
		$pattern
}

rule fcloseall_43a48b3cf7336a9b90982580f337d6b7 {
	meta:
		aliases = "fcloseall"
		type = "func"
		size = "243"
		objfiles = "fcloseall@libc.a"
	strings:
		$pattern = { ( CC | 41 ) 57 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 41 56 41 55 45 31 ED 41 54 55 53 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 FF C0 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 2D ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? EB 5D 44 8B 65 50 4C 8B 75 38 45 85 E4 75 1C 48 8D 5D 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 0F B7 45 00 83 E0 30 83 F8 30 74 13 48 89 EF E8 ?? ?? ?? ?? 85 C0 B8 FF FF FF FF 44 0F 45 E8 45 85 E4 75 0D BE }
	condition:
		$pattern
}

rule __md5_Encode_a841488af07c6ddbadbd18c047852174 {
	meta:
		aliases = "__md5_Encode"
		type = "func"
		size = "75"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 41 ) 89 D2 45 31 C9 45 31 C0 EB 3A 44 89 CA 44 89 C1 41 FF C1 48 8D 14 96 8B 02 88 04 0F 8B 02 41 8D 48 01 C1 E8 08 88 04 0F 8B 02 41 8D 48 02 C1 E8 10 88 04 0F 8B 02 41 8D 48 03 41 83 C0 04 C1 E8 18 88 04 0F 45 39 D0 72 C1 C3 }
	condition:
		$pattern
}

rule pwrite64_2c0a2c8c89c90d8efbb22d49bc3bca89 {
	meta:
		aliases = "__libc_pwrite, __libc_pwrite64, pwrite, pwrite64"
		type = "func"
		size = "11"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 41 ) B8 01 00 00 00 E9 50 FF FF FF }
	condition:
		$pattern
}

rule higher_prime_index_a6c1dbb9ee6f1f081b087b654420ca39 {
	meta:
		aliases = "higher_prime_index"
		type = "func"
		size = "138"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) B8 1E 00 00 00 31 C0 EB 0E 66 0F 1F 44 00 00 8D 41 01 44 39 C0 74 40 44 89 C1 29 C1 D1 E9 01 C1 89 CE 48 C1 E6 04 8B 96 ?? ?? ?? ?? 48 39 D7 77 DE 39 C8 41 89 C8 74 1F 29 C1 D1 E9 01 C1 89 CE 48 C1 E6 04 8B 96 ?? ?? ?? ?? 48 39 FA 73 E2 8D 41 01 44 39 C0 75 C0 89 C2 48 C1 E2 04 8B 92 ?? ?? ?? ?? 48 39 D7 77 02 F3 C3 48 83 EC 08 48 89 FA 48 8B 3D ?? ?? ?? ?? BE ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __ivaliduser_80bae242ee05b25478b79c375facf55c {
	meta:
		aliases = "__ivaliduser"
		type = "func"
		size = "11"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 41 ) B8 ?? ?? ?? ?? E9 03 FD FF FF }
	condition:
		$pattern
}

rule iruserok_0141aa16f0c161afe3524079a40d906a {
	meta:
		aliases = "iruserok"
		type = "func"
		size = "11"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 41 ) B8 ?? ?? ?? ?? E9 89 FE FF FF }
	condition:
		$pattern
}

rule getopt_long_only_b2f613f110c3b5ab541f0f55061b9133 {
	meta:
		aliases = "getopt_long_only"
		type = "func"
		size = "11"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 41 ) B9 01 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule htab_try_create_81a66384326297d84e394fa6c21db849 {
	meta:
		aliases = "htab_try_create"
		type = "func"
		size = "17"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) B9 ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? E9 1F FE FF FF }
	condition:
		$pattern
}

rule htab_create_579be7ca679b79486b4b18f912205f1c {
	meta:
		aliases = "htab_create"
		type = "func"
		size = "17"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) B9 ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? E9 3F FE FF FF }
	condition:
		$pattern
}

rule get_field_2dbe848f7d175489d144154cf482d2e7 {
	meta:
		aliases = "get_field"
		type = "func"
		size = "199"
		objfiles = "floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | 44 ) 01 C1 41 56 41 89 CA 41 C1 EA 03 85 F6 53 0F 85 93 00 00 00 C1 EA 03 83 E1 07 83 EA 01 41 89 C9 8D 49 F8 44 29 D2 89 D0 F7 D9 83 C2 01 0F B6 04 07 D3 F8 48 98 45 89 C2 BB 01 00 00 00 45 29 CA EB 36 0F 1F 44 00 00 44 89 D1 41 89 DE 41 D3 E6 44 89 F1 83 E9 01 41 21 CB 44 89 C9 41 D3 E3 4D 63 DB 4C 09 D8 8D 4A 01 41 83 C1 08 83 EA 01 85 F6 0F 44 D1 41 83 EA 08 45 39 C8 76 22 89 D1 41 83 FA 07 44 0F B6 1C 0F 76 BD 44 89 C9 41 D3 E3 4D 63 DB 4C 09 D8 EB CD 0F 1F 80 00 00 00 00 5B 41 5E C3 0F 1F 40 00 44 89 D0 83 E1 07 41 8D 52 FF 0F B6 04 07 41 89 C9 8D 49 F8 F7 D9 D3 F8 48 98 E9 6F FF FF FF }
	condition:
		$pattern
}

rule __stdio_adjust_position_1a810d861b36b6c345c05e34dd00320a {
	meta:
		aliases = "__stdio_adjust_position"
		type = "func"
		size = "131"
		objfiles = "_adjust_pos@libc.a"
	strings:
		$pattern = { ( CC | 44 ) 8B 07 31 D2 53 41 0F B7 C0 89 C1 83 E1 03 74 28 89 CA FF CA 74 22 F6 C4 08 74 1D 83 FA 02 74 5B 83 7F 44 00 75 55 0F B6 57 03 F7 DA 83 7F 48 00 7E 06 0F B6 47 02 29 C2 41 80 E0 40 74 06 48 8B 47 08 EB 04 48 8B 47 20 2B 57 18 48 8B 0E 8D 1C 02 48 89 CA 48 63 C3 48 29 C2 48 89 D0 48 89 16 89 DA F7 DA 48 39 C8 0F 4F DA 85 DB 79 10 E8 ?? ?? ?? ?? C7 00 4B 00 00 00 EB 03 83 CB FF 89 D8 5B C3 }
	condition:
		$pattern
}

rule pread64_563e2730dde361fdbd45736f26daff64 {
	meta:
		aliases = "__libc_pread, __libc_pread64, pread, pread64"
		type = "func"
		size = "8"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 45 ) 31 C0 E9 48 FF FF FF }
	condition:
		$pattern
}

rule mq_send_a80320b95502b532b206009e842ac653 {
	meta:
		aliases = "mq_send"
		type = "func"
		size = "5"
		objfiles = "mq_send@librt.a"
	strings:
		$pattern = { ( CC | 45 ) 31 C0 EB D0 }
	condition:
		$pattern
}

rule getopt_bcea34c689fcb89a43a05e1981359dcb {
	meta:
		aliases = "getopt"
		type = "func"
		size = "13"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 45 ) 31 C9 45 31 C0 31 C9 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule send_a9fc4c9a1d9715abba65179cb62f82e2 {
	meta:
		aliases = "__GI_recv, __GI_send, __libc_recv, __libc_send, recv, send"
		type = "func"
		size = "11"
		objfiles = "recv@libc.a, send@libc.a"
	strings:
		$pattern = { ( CC | 45 ) 31 C9 45 31 C0 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getopt_long_a640161b3f25582025daab4e1dd74c60 {
	meta:
		aliases = "getopt_long"
		type = "func"
		size = "8"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 45 ) 31 C9 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule inet_network_89a8da4a6dfda1543ce5225220ab1747 {
	meta:
		aliases = "__GI_inet_network, inet_network"
		type = "func"
		size = "219"
		objfiles = "inet_net@libc.a"
	strings:
		$pattern = { ( CC | 45 ) 31 DB 45 31 C9 80 3F 30 74 0A 31 F6 41 BA 0A 00 00 00 EB 25 48 FF C7 8A 07 3C 78 74 11 3C 58 74 0D BE 01 00 00 00 41 BA 08 00 00 00 EB 0B 48 FF C7 31 F6 41 BA 10 00 00 00 45 31 C0 EB 60 48 8B 05 ?? ?? ?? ?? 0F B6 D1 0F B7 04 50 A8 08 74 1C 41 83 FA 08 75 05 80 F9 37 77 77 44 89 C2 0F B6 C1 41 0F AF D2 44 8D 44 02 D0 EB 21 41 83 FA 10 75 32 A8 10 74 2E 83 E0 02 83 F8 01 44 89 C0 19 D2 C1 E0 04 83 E2 E0 29 D0 44 8D 40 A9 41 81 F8 FF 00 00 00 77 3C 48 FF C7 BE 01 00 00 00 8A 0F 84 C9 75 9A 85 F6 74 2A 44 89 C8 C1 E0 08 45 85 DB 44 0F 45 C8 45 09 C1 80 F9 2E 75 11 41 FF C3 41 83 FB 04 74 0C 48 }
	condition:
		$pattern
}

rule ether_aton_r_90d3fcd726c76f188a9a59c6dbfa3281 {
	meta:
		aliases = "__GI_ether_aton_r, ether_aton_r"
		type = "func"
		size = "209"
		objfiles = "ether_addr@libc.a"
	strings:
		$pattern = { ( CC | 45 ) 31 DB E9 B7 00 00 00 48 0F BE 07 4C 8B 15 ?? ?? ?? ?? 41 8A 14 42 8D 42 D0 3C 09 76 0B 8D 42 9F 3C 05 0F 87 A2 00 00 00 4C 8B 05 ?? ?? ?? ?? 48 0F BE C2 41 F6 04 40 08 0F BE C2 74 06 44 8D 48 D0 EB 04 44 8D 48 A9 48 0F BE 47 01 49 83 FB 04 48 8D 4F 01 40 0F 96 C7 41 8A 14 42 77 05 80 FA 3A 75 15 49 83 FB 05 75 4A 84 D2 74 46 48 0F BE C2 41 F6 04 40 20 75 3B 8D 42 D0 3C 09 76 07 8D 42 9F 3C 05 77 44 48 0F BE C2 41 F6 04 40 08 0F BE C2 74 05 8D 50 D0 EB 03 8D 50 A9 48 FF C1 40 84 FF 74 05 80 39 3A 75 21 44 89 C8 C1 E0 04 44 8D 0C 02 48 8D 79 01 46 88 0C 1E 49 FF C3 49 83 FB 05 0F 86 3F FF FF }
	condition:
		$pattern
}

rule strncmp_c78e26b387d5b26da80132cd32588865 {
	meta:
		aliases = "strncmp"
		type = "func"
		size = "51"
		objfiles = "strncmp@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 01 F2 EB 1B 0F 1F 00 48 83 C7 01 48 83 C6 01 0F B6 47 FF 0F B6 4E FF 38 C8 75 14 84 C0 74 05 48 39 D6 75 E3 31 C0 C3 0F 1F 84 00 00 00 00 00 29 C8 C3 }
	condition:
		$pattern
}

rule _setjmp_4804825d1d3aedfebdc6d8e8bd249615 {
	meta:
		aliases = "_setjmp"
		type = "func"
		size = "8"
		objfiles = "bsd__setjmp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 31 F6 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wmemmove_a4d09019e5ea1ac51a0e9b019c7ed8eb {
	meta:
		aliases = "wmemmove"
		type = "func"
		size = "61"
		objfiles = "wmemmove@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 39 FE 48 89 D1 48 89 FA 73 11 EB 27 8B 06 48 FF C9 48 83 C6 04 89 02 48 83 C2 04 48 85 C9 75 EC EB 16 48 FF C9 48 8D 14 8D 00 00 00 00 8B 04 16 89 04 17 48 85 C9 75 EA 48 89 F8 C3 }
	condition:
		$pattern
}

rule wait_node_dequeue_23d15d204a3b7debfd46a8067b408971 {
	meta:
		aliases = "wait_node_dequeue"
		type = "func"
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
		type = "func"
		size = "69"
		objfiles = "rwlock@libpthread.a, semaphore@libpthread.a, pthread@libpthread.a, cancel@libpthread.a, signals@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 3B 25 ?? ?? ?? ?? 48 89 E2 B8 ?? ?? ?? ?? 73 33 48 3B 25 ?? ?? ?? ?? 72 0E 48 3B 25 ?? ?? ?? ?? B8 ?? ?? ?? ?? 72 1C 83 3D ?? ?? ?? ?? 00 74 05 E9 ?? ?? ?? ?? 48 81 CA FF FF 1F 00 48 8D 82 01 FD FF FF C3 }
	condition:
		$pattern
}

rule spaces_e6c11297328fa42476a1d332b372a286 {
	meta:
		aliases = "spaces"
		type = "func"
		size = "125"
		objfiles = "spaces@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 63 15 ?? ?? ?? ?? 53 48 63 DF 39 DA 7C 11 48 8B 05 ?? ?? ?? ?? 48 29 DA 48 01 D0 5B C3 66 90 48 8B 3D ?? ?? ?? ?? 48 85 FF 74 05 E8 ?? ?? ?? ?? 8D 7B 01 48 63 FF E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 74 31 48 63 CB 48 01 C1 48 39 C8 48 89 CA 74 16 66 2E 0F 1F 84 00 00 00 00 00 48 83 EA 01 C6 02 20 48 39 C2 75 F4 89 1D ?? ?? ?? ?? C6 01 00 31 D2 EB A0 31 C0 5B C3 }
	condition:
		$pattern
}

rule load_field_602df527b9ba5855f417c930869cc104 {
	meta:
		aliases = "load_field"
		type = "func"
		size = "65"
		objfiles = "strftime@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 63 C7 83 FF 07 8B 14 86 8D 47 3A 48 98 8A 88 ?? ?? ?? ?? B8 6D 01 00 00 74 13 83 FF 05 0F B6 C1 75 0B 81 C2 6C 07 00 00 B8 0F 27 00 00 39 C2 77 09 83 FF 03 75 07 85 D2 75 03 83 CA FF 89 D0 C3 }
	condition:
		$pattern
}

rule __mulvsi3_df6d7718cba0cbbd21fa4a96505823ba {
	meta:
		aliases = "__mulvsi3"
		type = "func"
		size = "42"
		objfiles = "_mulvsi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 63 CE 48 63 FF 48 83 EC 08 48 0F AF CF 48 89 CA 89 C8 48 C1 FA 20 C1 F8 1F 39 D0 75 07 89 C8 48 83 C4 08 C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule reboot_54f1a89fed5d58467e86158d170eab9f {
	meta:
		aliases = "reboot"
		type = "func"
		size = "53"
		objfiles = "reboot@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 63 D7 53 BE 69 19 12 28 48 C7 C7 AD DE E1 FE B8 A9 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule partition_union_0368ff9c87f4e4ce0e3e8916a33e82af {
	meta:
		aliases = "partition_union"
		type = "func"
		size = "139"
		objfiles = "partition@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 63 F6 48 83 C7 08 48 63 D2 48 8D 04 76 48 8D 0C C7 48 8D 04 52 48 8D 34 C7 4C 63 01 8B 06 44 39 C0 74 4C 8B 56 10 39 51 10 73 4C 48 63 D0 4F 8D 04 40 48 8D 14 52 46 8B 44 C7 10 44 01 44 D7 10 48 8B 79 08 89 01 48 39 CF 48 89 FA 74 0C 90 89 02 48 8B 52 08 48 39 CA 75 F5 48 8B 56 08 48 89 7E 08 48 89 51 08 C3 0F 1F 84 00 00 00 00 00 F3 C3 66 0F 1F 44 00 00 48 89 F2 48 89 CE 48 89 D1 89 C2 44 89 C0 4C 63 C2 EB A1 }
	condition:
		$pattern
}

rule splay_tree_xmalloc_allocate_99822f6becf3ab817549c8a4836c0ad2 {
	meta:
		aliases = "splay_tree_xmalloc_allocate"
		type = "func"
		size = "8"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 63 FF E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sigblock_b1c882eeba763c4fd28bc52f291bbecd {
	meta:
		aliases = "__GI_sigblock, sigblock"
		type = "func"
		size = "83"
		objfiles = "sigblock@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC 08 01 00 00 89 FF B8 0E 00 00 00 48 8D 94 24 88 00 00 00 48 89 BC 24 80 00 00 00 48 C7 02 00 00 00 00 48 83 C2 08 FF C8 79 F1 48 8D B4 24 80 00 00 00 48 89 E2 31 FF E8 ?? ?? ?? ?? 83 CA FF 85 C0 78 03 8B 14 24 89 D0 48 81 C4 08 01 00 00 C3 }
	condition:
		$pattern
}

rule sigsetmask_a5d8992ca3939ad6c58262bf0af7d3c1 {
	meta:
		aliases = "__GI_sigsetmask, sigsetmask"
		type = "func"
		size = "86"
		objfiles = "sigsetmask@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC 08 01 00 00 89 FF B8 0E 00 00 00 48 8D 94 24 88 00 00 00 48 89 BC 24 80 00 00 00 48 C7 02 00 00 00 00 48 83 C2 08 FF C8 79 F1 48 8D B4 24 80 00 00 00 48 89 E2 BF 02 00 00 00 E8 ?? ?? ?? ?? 83 CA FF 85 C0 78 03 8B 14 24 89 D0 48 81 C4 08 01 00 00 C3 }
	condition:
		$pattern
}

rule sysv_signal_587ca10cb110945f087ff9be588976b4 {
	meta:
		aliases = "__sysv_signal, sysv_signal"
		type = "func"
		size = "123"
		objfiles = "sysv_signal@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC 48 01 00 00 48 83 FE FF 74 09 85 FF 7E 05 83 FF 40 7E 11 E8 ?? ?? ?? ?? 48 83 CA FF C7 00 16 00 00 00 EB 49 BA 10 00 00 00 48 89 B4 24 A0 00 00 00 EB 0F 48 63 C2 48 C7 84 C4 A8 00 00 00 00 00 00 00 FF CA 79 ED 48 8D B4 24 A0 00 00 00 48 89 E2 C7 84 24 28 01 00 00 00 00 00 E0 E8 ?? ?? ?? ?? 48 83 CA FF 85 C0 78 04 48 8B 14 24 48 89 D0 48 81 C4 48 01 00 00 C3 }
	condition:
		$pattern
}

rule svc_getreq_cad4bef3d7427b7d2111b5c163c87c20 {
	meta:
		aliases = "__GI_svc_getreq, svc_getreq"
		type = "func"
		size = "49"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC 88 00 00 00 31 D2 89 D0 FF C2 83 FA 0F 48 C7 04 C4 00 00 00 00 76 EF 48 63 C7 48 89 E7 48 89 04 24 E8 ?? ?? ?? ?? 48 81 C4 88 00 00 00 C3 }
	condition:
		$pattern
}

rule get_run_time_b37d8e2b582df0b8d61895784c62861b {
	meta:
		aliases = "get_run_time"
		type = "func"
		size = "61"
		objfiles = "getruntime@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC 98 00 00 00 31 FF 48 89 E6 E8 ?? ?? ?? ?? 48 8B 04 24 48 8B 54 24 10 48 69 C0 40 42 0F 00 48 03 44 24 08 48 69 D2 40 42 0F 00 48 01 D0 48 03 44 24 18 48 81 C4 98 00 00 00 C3 }
	condition:
		$pattern
}

rule direxists_227a372fba0a4c864be3252301f55083 {
	meta:
		aliases = "direxists"
		type = "func"
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
		type = "func"
		size = "67"
		objfiles = "sigignore@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC A8 00 00 00 BA 10 00 00 00 48 C7 04 24 01 00 00 00 EB 0C 48 63 C2 48 C7 44 C4 08 00 00 00 00 FF CA 79 F0 48 89 E6 31 D2 C7 84 24 88 00 00 00 00 00 00 00 E8 ?? ?? ?? ?? 48 81 C4 A8 00 00 00 C3 }
	condition:
		$pattern
}

rule swprintf_54d39b834bdc4c8ee49cf3cde03e5a9c {
	meta:
		aliases = "__GI_snprintf, snprintf, swprintf"
		type = "func"
		size = "137"
		objfiles = "swprintf@libc.a, snprintf@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC D8 00 00 00 48 89 4C 24 38 0F B6 C8 4C 89 44 24 40 48 8D 04 8D 00 00 00 00 B9 ?? ?? ?? ?? 4C 89 4C 24 48 48 29 C1 48 8D 84 24 CF 00 00 00 FF E1 0F 29 78 F1 0F 29 70 E1 0F 29 68 D1 0F 29 60 C1 0F 29 58 B1 0F 29 50 A1 0F 29 48 91 0F 29 40 81 48 8D 84 24 E0 00 00 00 48 89 E1 C7 04 24 18 00 00 00 C7 44 24 04 30 00 00 00 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 E8 ?? ?? ?? ?? 48 81 C4 D8 00 00 00 C3 }
	condition:
		$pattern
}

rule errx_b245397afba0dbdc482d035ebf365e87 {
	meta:
		aliases = "err, errx"
		type = "func"
		size = "134"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC D8 00 00 00 48 89 54 24 30 0F B6 D0 48 89 4C 24 38 48 8D 04 95 00 00 00 00 BA ?? ?? ?? ?? 4C 89 44 24 40 4C 89 4C 24 48 48 29 C2 48 8D 84 24 CF 00 00 00 FF E2 0F 29 78 F1 0F 29 70 E1 0F 29 68 D1 0F 29 60 C1 0F 29 58 B1 0F 29 50 A1 0F 29 48 91 0F 29 40 81 48 8D 84 24 E0 00 00 00 48 89 E2 C7 04 24 10 00 00 00 C7 44 24 04 30 00 00 00 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule syslog_4f17e5776fd93321a6b366d662782192 {
	meta:
		aliases = "__GI_asprintf, __GI_fprintf, __GI_fscanf, __GI_sscanf, __GI_syslog, asprintf, dprintf, fprintf, fscanf, fwprintf, fwscanf, sscanf, swscanf, syslog"
		type = "func"
		size = "142"
		objfiles = "syslog@libc.a, fwscanf@libc.a, dprintf@libc.a, swscanf@libc.a, fwprintf@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC D8 00 00 00 48 89 54 24 30 0F B6 D0 48 89 4C 24 38 48 8D 04 95 00 00 00 00 BA ?? ?? ?? ?? 4C 89 44 24 40 4C 89 4C 24 48 48 29 C2 48 8D 84 24 CF 00 00 00 FF E2 0F 29 78 F1 0F 29 70 E1 0F 29 68 D1 0F 29 60 C1 0F 29 58 B1 0F 29 50 A1 0F 29 48 91 0F 29 40 81 48 8D 84 24 E0 00 00 00 48 89 E2 C7 04 24 10 00 00 00 C7 44 24 04 30 00 00 00 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 E8 ?? ?? ?? ?? 48 81 C4 D8 00 00 00 C3 }
	condition:
		$pattern
}

rule sprintf_d844a304a595519b138027611e7f4baa {
	meta:
		aliases = "__GI_sprintf, sprintf"
		type = "func"
		size = "149"
		objfiles = "sprintf@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC D8 00 00 00 48 89 54 24 30 0F B6 D0 48 89 4C 24 38 48 8D 04 95 00 00 00 00 BA ?? ?? ?? ?? 4C 89 44 24 40 4C 89 4C 24 48 48 89 E1 48 29 C2 48 8D 84 24 CF 00 00 00 FF E2 0F 29 78 F1 0F 29 70 E1 0F 29 68 D1 0F 29 60 C1 0F 29 58 B1 0F 29 50 A1 0F 29 48 91 0F 29 40 81 48 8D 84 24 E0 00 00 00 48 89 F2 48 83 CE FF C7 04 24 10 00 00 00 C7 44 24 04 30 00 00 00 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 E8 ?? ?? ?? ?? 48 81 C4 D8 00 00 00 C3 }
	condition:
		$pattern
}

rule warnx_77524bd231933e6adcf365bf2b85dee9 {
	meta:
		aliases = "warn, warnx"
		type = "func"
		size = "147"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC D8 00 00 00 48 89 54 24 30 0F B6 D0 48 89 74 24 28 48 8D 04 95 00 00 00 00 BA ?? ?? ?? ?? 48 89 4C 24 38 4C 89 44 24 40 4C 89 4C 24 48 48 89 E6 48 29 C2 48 8D 84 24 CF 00 00 00 FF E2 0F 29 78 F1 0F 29 70 E1 0F 29 68 D1 0F 29 60 C1 0F 29 58 B1 0F 29 50 A1 0F 29 48 91 0F 29 40 81 48 8D 84 24 E0 00 00 00 C7 04 24 08 00 00 00 C7 44 24 04 30 00 00 00 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 E8 ?? ?? ?? ?? 48 81 C4 D8 00 00 00 C3 }
	condition:
		$pattern
}

rule wscanf_e0fef7b1e267e11058ce53fdb7788479 {
	meta:
		aliases = "__GI_printf, printf, scanf, wprintf, wscanf"
		type = "func"
		size = "157"
		objfiles = "printf@libc.a, scanf@libc.a, wprintf@libc.a, wscanf@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 81 EC D8 00 00 00 48 89 54 24 30 0F B6 D0 48 89 74 24 28 48 8D 04 95 00 00 00 00 BA ?? ?? ?? ?? 48 89 4C 24 38 4C 89 44 24 40 4C 89 4C 24 48 48 89 FE 48 29 C2 48 8D 84 24 CF 00 00 00 FF E2 0F 29 78 F1 0F 29 70 E1 0F 29 68 D1 0F 29 60 C1 0F 29 58 B1 0F 29 50 A1 0F 29 48 91 0F 29 40 81 48 8D 84 24 E0 00 00 00 48 8B 3D ?? ?? ?? ?? 48 89 E2 C7 04 24 08 00 00 00 C7 44 24 04 30 00 00 00 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 E8 ?? ?? ?? ?? 48 81 C4 D8 00 00 00 C3 }
	condition:
		$pattern
}

rule open64_d8dc12dd6ea513d88ff1358d7923b3d0 {
	meta:
		aliases = "__GI___libc_open64, __GI_open64, __libc_open64, open64"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "21"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 81 FE FF 3F 00 00 B8 16 00 00 00 76 06 48 89 77 30 30 C0 C3 }
	condition:
		$pattern
}

rule xmalloc_set_program_name_43b413c4415fccfb9bc883d55cf5ada0 {
	meta:
		aliases = "xmalloc_set_program_name"
		type = "func"
		size = "47"
		objfiles = "xmalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 3D ?? ?? ?? ?? 00 48 89 3D ?? ?? ?? ?? 74 07 C3 66 0F 1F 44 00 00 48 83 EC 08 31 FF E8 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 83 C4 08 C3 }
	condition:
		$pattern
}

rule valloc_1ab0af5c103933af6971b08af923e019 {
	meta:
		aliases = "valloc"
		type = "func"
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
		type = "func"
		size = "71"
		objfiles = "crtbeginS"
	strings:
		$pattern = { ( CC | 48 ) 83 3D ?? ?? ?? ?? 00 55 48 89 E5 74 13 48 8D 35 ?? ?? ?? ?? 48 8D 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 3D ?? ?? ?? ?? 00 74 1A 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 0E 48 8D 3D ?? ?? ?? ?? 49 89 C3 C9 41 FF E3 C9 C3 }
	condition:
		$pattern
}

rule __pthread_trylock_08ba02d5623ec65417ed6ca964076924 {
	meta:
		aliases = "__pthread_alt_trylock, __pthread_trylock"
		type = "func"
		size = "37"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 3F 00 74 06 B8 10 00 00 00 C3 31 D2 B9 01 00 00 00 48 89 D0 F0 48 0F B1 0F 0F 94 C2 84 D2 74 DE 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_cond_destroy_b564150feb36c8f2fc5aa0b57fea845a {
	meta:
		aliases = "__GI_pthread_cond_destroy, pthread_cond_destroy"
		type = "func"
		size = "13"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 7F 10 01 19 C0 F7 D0 83 E0 10 C3 }
	condition:
		$pattern
}

rule funlockfile_79d502e13d9cfbabf1eaba40db91a239 {
	meta:
		aliases = "flockfile, ftrylockfile, funlockfile"
		type = "func"
		size = "9"
		objfiles = "flockfile@libc.a, ftrylockfile@libc.a, funlockfile@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 C7 58 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule swab_f6c1790a3078521a1054e1fe0d621c0b {
	meta:
		aliases = "swab"
		type = "func"
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
		type = "func"
		size = "4"
		objfiles = "crti"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 }
	condition:
		$pattern
}

rule __kernel_tan_4fa629f6d12c6a149f7f5cbe00211073 {
	meta:
		aliases = "__kernel_tan"
		type = "func"
		size = "566"
		objfiles = "k_tan@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 0F 28 E8 F2 0F 11 04 24 48 8B 04 24 0F 28 F1 48 89 C2 48 C1 EA 20 89 D1 81 E1 FF FF FF 7F 81 F9 FF FF 2F 3E 7F 47 F2 0F 2C C5 85 C0 75 7D 48 8B 04 24 09 C1 8D 47 01 09 C1 75 16 E8 ?? ?? ?? ?? F2 0F 10 2D ?? ?? ?? ?? F2 0F 5E E8 E9 DC 01 00 00 FF CF 0F 84 D4 01 00 00 F2 0F 10 05 ?? ?? ?? ?? F2 0F 5E C5 0F 28 E8 E9 C0 01 00 00 81 F9 27 94 E5 3F 7E 36 85 D2 79 10 F2 0F 10 05 ?? ?? ?? ?? 66 0F 57 E8 66 0F 57 F0 F2 0F 10 05 ?? ?? ?? ?? F2 0F 5C C5 0F 28 E8 F2 0F 10 05 ?? ?? ?? ?? F2 0F 5C C6 0F 57 F6 F2 0F 58 E8 0F 28 D5 81 F9 27 94 E5 3F F2 0F 59 D5 0F 28 CA 0F 28 DA F2 0F 59 CA F2 0F }
	condition:
		$pattern
}

rule __fixsfti_712308e65b29deda91ac7e62e83d87c6 {
	meta:
		aliases = "__fixsfti"
		type = "func"
		size = "51"
		objfiles = "_fixsfdi@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 0F 2E 05 ?? ?? ?? ?? 7A 02 72 09 48 83 C4 08 E9 ?? ?? ?? ?? 0F 57 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 F7 D8 48 83 D2 00 48 83 C4 08 48 F7 DA C3 }
	condition:
		$pattern
}

rule xre_compile_pattern_c089c8c985bdd61f1f4c1b8f086403dc {
	meta:
		aliases = "xre_compile_pattern"
		type = "func"
		size = "63"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 0F B6 42 38 48 89 D1 83 E0 E9 83 C8 80 88 42 38 48 8B 15 ?? ?? ?? ?? E8 A0 D2 FF FF 85 C0 74 14 48 98 48 8B 04 C5 ?? ?? ?? ?? 48 83 C4 08 C3 0F 1F 44 00 00 31 C0 48 83 C4 08 C3 }
	condition:
		$pattern
}

rule sem_destroy_ef745794f3ce1785fa63676b76bde11b {
	meta:
		aliases = "__new_sem_destroy, sem_destroy"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "20"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 31 FF E8 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 58 C3 }
	condition:
		$pattern
}

rule base_from_object_ad73a710ef6af7ba4114483f75268f75 {
	meta:
		aliases = "base_from_object"
		type = "func"
		size = "78"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 40 80 FF FF 89 F8 74 1F 83 E0 70 83 F8 20 74 1E 7E 11 83 F8 30 74 20 83 F8 50 66 90 74 09 E8 ?? ?? ?? ?? 85 C0 75 19 31 C0 48 83 C4 08 C3 48 8B 46 08 48 83 C4 08 C3 48 8B 46 10 48 83 C4 08 C3 83 F8 10 74 E2 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule size_of_encoded_value_0c8bf92037781ff89cbf060fb02e44a5 {
	meta:
		aliases = "size_of_encoded_value"
		type = "func"
		size = "82"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 40 80 FF FF 89 F8 74 3F 83 E0 07 83 F8 02 74 2D 7E 11 83 F8 03 74 1A 83 F8 04 66 90 74 09 E8 ?? ?? ?? ?? 85 C0 75 F7 B8 08 00 00 00 48 83 C4 08 C3 B8 04 00 00 00 48 83 C4 08 66 90 C3 B8 02 00 00 00 48 83 C4 08 C3 31 C0 66 66 90 EB DE }
	condition:
		$pattern
}

rule mq_receive_71d0dd2ae846370e485cd6f1bac6ec55 {
	meta:
		aliases = "mq_receive"
		type = "func"
		size = "16"
		objfiles = "mq_receive@librt.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 45 31 C0 E8 C9 FF FF FF 5A 48 98 C3 }
	condition:
		$pattern
}

rule signo_max_fd18016577b587b9c23c66666b741d24 {
	meta:
		aliases = "signo_max"
		type = "func"
		size = "55"
		objfiles = "strsignal@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 83 3D ?? ?? ?? ?? 00 74 22 83 3D ?? ?? ?? ?? 41 B8 41 00 00 00 0F 4D 05 ?? ?? ?? ?? 48 83 C4 08 83 E8 01 C3 0F 1F 80 00 00 00 00 E8 1B FF FF FF EB D7 }
	condition:
		$pattern
}

rule errno_max_47cb310bd0ee7c185982e6a4983cdc83 {
	meta:
		aliases = "errno_max"
		type = "func"
		size = "55"
		objfiles = "strerror@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 83 3D ?? ?? ?? ?? 00 74 22 8B 05 ?? ?? ?? ?? 39 05 ?? ?? ?? ?? 0F 4D 05 ?? ?? ?? ?? 48 83 C4 08 83 E8 01 C3 0F 1F 80 00 00 00 00 E8 1B FF FF FF EB D7 }
	condition:
		$pattern
}

rule getusershell_968545815219b1f2624884368db7b2b3 {
	meta:
		aliases = "getusershell"
		type = "func"
		size = "57"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 83 3D ?? ?? ?? ?? 00 75 0C E8 8B FE FF FF 48 89 05 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 8B 10 48 85 D2 74 0B 48 83 C0 08 48 89 05 ?? ?? ?? ?? 59 48 89 D0 C3 }
	condition:
		$pattern
}

rule __initbuf_130c47b7197ead03aa63d8d21272e87a {
	meta:
		aliases = "__initbuf"
		type = "func"
		size = "43"
		objfiles = "getservice@libc.a, getproto@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 83 3D ?? ?? ?? ?? 00 75 1B BF 19 11 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 75 05 E8 ?? ?? ?? ?? 58 C3 }
	condition:
		$pattern
}

rule __addvdi3_2b839c2776af93c720cdcb64c46152a2 {
	meta:
		aliases = "__addvdi3"
		type = "func"
		size = "45"
		objfiles = "_addvsi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 85 F6 48 8D 04 3E 78 13 48 39 F8 0F 9C C2 84 D2 75 11 48 83 C4 08 C3 66 66 66 90 48 39 F8 0F 9F C2 EB EB E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mbtowc_ac707c793f4d684a60f4fe4c1466e6e5 {
	meta:
		aliases = "mbtowc"
		type = "func"
		size = "65"
		objfiles = "mbtowc@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 85 F6 75 0E 31 C9 C7 05 ?? ?? ?? ?? 00 00 00 00 EB 26 31 C9 80 3E 00 74 1F B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 F8 FE 89 C1 75 0D C7 05 ?? ?? ?? ?? FF FF 00 00 83 C9 FF 5A 89 C8 C3 }
	condition:
		$pattern
}

rule endmntent_49595508d2b541074721458c28172100 {
	meta:
		aliases = "__GI_endmntent, endmntent"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "22"
		objfiles = "__syscall_error@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 89 C1 48 F7 D9 E8 ?? ?? ?? ?? 89 08 83 C8 FF 5A C3 }
	condition:
		$pattern
}

rule pthread_exit_002540812356977fc450f8b2c6b676d9 {
	meta:
		aliases = "__GI_pthread_exit, pthread_exit"
		type = "func"
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
		type = "func"
		size = "35"
		objfiles = "putw@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 89 F1 BA 01 00 00 00 89 7C 24 04 48 8D 7C 24 04 BE 04 00 00 00 E8 ?? ?? ?? ?? 5A FF C8 C3 }
	condition:
		$pattern
}

rule putwc_unlocked_dff6ff38344fedac15f8073d0cc82306 {
	meta:
		aliases = "__GI_fputwc_unlocked, fputwc_unlocked, putwc_unlocked"
		type = "func"
		size = "42"
		objfiles = "fputwc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 89 F2 BE 01 00 00 00 89 7C 24 04 48 8D 7C 24 04 E8 ?? ?? ?? ?? 83 CA FF 48 85 C0 74 04 8B 54 24 04 89 D0 5A C3 }
	condition:
		$pattern
}

rule _rpcdata_b7a3db014b958b1d3e64a60912aabf9b {
	meta:
		aliases = "_rpcdata"
		type = "func"
		size = "40"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 8B 05 ?? ?? ?? ?? 48 85 C0 75 16 BE 58 11 00 00 BF 01 00 00 00 E8 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 59 C3 }
	condition:
		$pattern
}

rule _dl_protect_relro_fa89fb58fa958e8b10d859fc15337a4d {
	meta:
		aliases = "_dl_protect_relro"
		type = "func"
		size = "139"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 8B 17 48 03 97 A8 01 00 00 49 89 F8 48 8B 05 ?? ?? ?? ?? 48 89 D1 49 03 88 B0 01 00 00 48 F7 D8 48 89 C7 48 21 D7 48 21 C1 48 39 CF 74 56 48 89 CE BA 01 00 00 00 B8 0A 00 00 00 48 29 FE 0F 05 48 3D 00 F0 FF FF 76 0A F7 D8 89 05 ?? ?? ?? ?? EB 04 85 C0 79 2E 49 8B 50 08 31 C0 BE ?? ?? ?? ?? BF 02 00 00 00 E8 ?? ?? ?? ?? 31 FF B8 3C 00 00 00 0F 05 48 3D 00 F0 FF FF 76 08 F7 D8 89 05 ?? ?? ?? ?? 59 C3 }
	condition:
		$pattern
}

rule __old_sem_trywait_47dbad38176bda6a1caabb7815317539 {
	meta:
		aliases = "__old_sem_trywait"
		type = "func"
		size = "58"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 8B 17 F6 C2 01 74 06 48 83 FA 01 75 10 E8 ?? ?? ?? ?? C7 00 0B 00 00 00 83 C8 FF EB 15 48 8D 4A FE 48 89 D0 F0 48 0F B1 0F 0F 94 C2 84 D2 74 CF 31 C0 41 59 C3 }
	condition:
		$pattern
}

rule setttyent_95ce6ad94da1ad164d34cfb42f2ec101 {
	meta:
		aliases = "__GI_setttyent, setttyent"
		type = "func"
		size = "72"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 8B 3D ?? ?? ?? ?? 48 85 FF 74 07 E8 ?? ?? ?? ?? EB 2A BF ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C7 48 89 05 ?? ?? ?? ?? 31 C0 48 85 FF 74 0F BE 02 00 00 00 E8 ?? ?? ?? ?? B8 01 00 00 00 59 C3 }
	condition:
		$pattern
}

rule unlock_std_streams_89bde230cebcd314b07034a43ea1aefd {
	meta:
		aliases = "unlock_std_streams"
		type = "func"
		size = "85"
		objfiles = "fopen_unlocked@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 8B 3D ?? ?? ?? ?? 48 85 FF 74 0A BE 02 00 00 00 E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 85 FF 74 0A BE 02 00 00 00 E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 85 FF 74 14 BE 02 00 00 00 48 83 C4 08 E9 ?? ?? ?? ?? 66 0F 1F 44 00 00 48 83 C4 08 C3 }
	condition:
		$pattern
}

rule endttyent_ee96157325e6c0b2a02a44d4b27c82c5 {
	meta:
		aliases = "__GI_endttyent, endttyent"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "52"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 E8 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 58 C3 }
	condition:
		$pattern
}

rule svcunix_stat_7cb49c3f37082b7727379c2e45dd009a {
	meta:
		aliases = "svctcp_stat, svcunix_stat"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "16"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 8B 7F 18 E8 ?? ?? ?? ?? 41 5B C3 }
	condition:
		$pattern
}

rule __psfs_parse_spec_4ddbaffccd69ce3fdd653fa425588091 {
	meta:
		aliases = "__psfs_parse_spec"
		type = "func"
		size = "475"
		objfiles = "__psfs_parse_spec@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 4C 8B 57 58 31 D2 41 B1 01 41 8A 02 83 E8 30 3C 09 77 53 81 FA CB CC CC 0C 7F 15 48 8B 47 58 6B D2 0A 0F B6 08 48 FF C0 48 89 47 58 8D 54 11 D0 48 8B 77 58 8A 0E 8D 41 D0 3C 09 76 D6 80 F9 24 74 19 83 7F 48 00 0F 89 7B 01 00 00 89 57 6C C7 47 48 FE FF FF FF E9 A6 00 00 00 48 8D 46 01 45 31 C9 48 89 47 58 BE ?? ?? ?? ?? 41 B8 10 00 00 00 48 8B 4F 58 8A 06 3A 01 75 0E 44 08 47 71 48 8D 41 01 48 89 47 58 EB DD 48 FF C6 80 3E 00 74 05 45 01 C0 EB DB F6 47 71 10 74 08 C6 47 70 00 31 D2 EB 50 45 84 C9 74 13 83 7F 48 00 0F 89 14 01 00 00 C7 47 48 FE FF FF FF EB E4 83 7F 48 FE 0F 84 01 01 }
	condition:
		$pattern
}

rule __fixdfti_054297002685e5e5d96c7dd90456632f {
	meta:
		aliases = "__fixdfti"
		type = "func"
		size = "60"
		objfiles = "_fixdfdi@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 66 0F 2E 05 ?? ?? ?? ?? 7A 02 72 10 48 83 C4 08 E9 ?? ?? ?? ?? 66 66 66 90 66 66 90 66 0F 57 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 F7 D8 48 83 D2 00 48 83 C4 08 48 F7 DA C3 }
	condition:
		$pattern
}

rule cargf_8dcf2cd6d5c3c46aad90c5d99b739188 {
	meta:
		aliases = "cabsf, cargf"
		type = "func"
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
		type = "func"
		size = "351"
		objfiles = "sysconf@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 81 FF 95 00 00 00 77 13 89 F8 FF 24 C5 ?? ?? ?? ?? B8 01 00 00 00 E9 3E 01 00 00 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 E2 00 00 00 B8 00 00 02 00 E9 24 01 00 00 B8 64 00 00 00 E9 1A 01 00 00 B8 00 00 01 00 E9 10 01 00 00 E8 ?? ?? ?? ?? EB 0F B8 06 00 00 00 E9 FF 00 00 00 E8 ?? ?? ?? ?? 48 98 E9 F3 00 00 00 B8 00 80 00 00 E9 E9 00 00 00 B8 E8 03 00 00 E9 DF 00 00 00 B8 00 40 00 00 E9 D5 00 00 00 B8 00 10 00 00 E9 CB 00 00 00 B8 F4 01 00 00 E9 C1 00 00 00 B8 08 00 00 00 E9 B7 00 00 00 48 C7 C0 00 00 00 80 E9 AB 00 00 00 B8 40 00 00 00 E9 A1 00 00 00 48 C7 C0 00 80 FF FF E9 95 00 00 00 }
	condition:
		$pattern
}

rule _rpc_dtablesize_f0afb58eb734d9019f721410f96d3ba6 {
	meta:
		aliases = "__GI__rpc_dtablesize, _rpc_dtablesize"
		type = "func"
		size = "32"
		objfiles = "rpc_dtablesize@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 83 3D ?? ?? ?? ?? 00 75 0B E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 5A C3 }
	condition:
		$pattern
}

rule __uClibc_init_1ef9c1ff307db332dff8dd421ddf8c8e {
	meta:
		aliases = "__GI___uClibc_init, __uClibc_init"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "61"
		objfiles = "setlocale@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 83 FF 06 48 89 F2 77 2D 48 85 F6 74 21 8A 06 84 C0 74 1B 3C 43 75 06 80 7E 01 00 74 11 BE ?? ?? ?? ?? 48 89 D7 E8 ?? ?? ?? ?? 85 C0 75 07 B8 ?? ?? ?? ?? EB 02 31 C0 5A C3 }
	condition:
		$pattern
}

rule __getutent_2b4051deaa0be32e3e2d7536e6fb4ee5 {
	meta:
		aliases = "__getutent"
		type = "func"
		size = "55"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 83 FF FF 75 09 E8 58 FF FF FF 31 D2 EB 20 BA 90 01 00 00 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 D2 48 3D 90 01 00 00 B8 ?? ?? ?? ?? 48 0F 44 D0 59 48 89 D0 C3 }
	condition:
		$pattern
}

rule xdrstdio_putbytes_50318e03ec7413f0040be15205bd67b2 {
	meta:
		aliases = "xdrstdio_putbytes"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "71"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 85 D2 79 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 0F 85 F6 74 10 E8 ?? ?? ?? ?? C7 00 26 00 00 00 83 C8 FF EB 1B 48 C7 07 00 00 00 00 C7 47 08 00 00 00 00 31 C0 89 57 10 48 C7 47 18 00 00 00 00 41 5A C3 }
	condition:
		$pattern
}

rule sigismember_13bae3359f0ab5285d20861034590b27 {
	meta:
		aliases = "__GI_sigaddset, __GI_sigdelset, sigaddset, sigdelset, sigismember"
		type = "func"
		size = "35"
		objfiles = "sigismem@libc.a, sigdelset@libc.a, sigaddset@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 85 F6 7E 0B 83 FE 40 7F 06 59 E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 5A C3 }
	condition:
		$pattern
}

rule __addvsi3_6f495a3e0eec583f9fb2c46916ad5ee0 {
	meta:
		aliases = "__addvsi3"
		type = "func"
		size = "44"
		objfiles = "_addvsi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 85 F6 8D 04 3E 78 15 39 F8 0F 9C C2 84 D2 75 13 48 83 C4 08 C3 66 66 66 90 66 66 90 39 F8 0F 9F C2 EB E9 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule killpg_93a7cb87d5586e1f6449aeda290e3369 {
	meta:
		aliases = "killpg"
		type = "func"
		size = "32"
		objfiles = "killpg@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 85 FF 78 08 59 F7 DF E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 5A C3 }
	condition:
		$pattern
}

rule re_compile_pattern_5c8ab23ec11e206eff18729c1af25840 {
	meta:
		aliases = "__re_compile_pattern, re_compile_pattern"
		type = "func"
		size = "60"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 8A 42 38 48 89 D1 83 E0 E9 83 C8 80 88 42 38 48 8B 15 ?? ?? ?? ?? E8 D4 D7 FF FF 31 D2 85 C0 74 11 48 98 48 8B 14 C5 ?? ?? ?? ?? 48 81 C2 ?? ?? ?? ?? 41 5B 48 89 D0 C3 }
	condition:
		$pattern
}

rule __deregister_frame_75a99e22bb3e6ae91932ea9f7506fcb0 {
	meta:
		aliases = "__deregister_frame"
		type = "func"
		size = "33"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 8B 07 85 C0 75 06 48 83 C4 08 C3 90 E8 ?? ?? ?? ?? 48 83 C4 08 48 89 C7 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fileno_unlocked_0a902d39b600dfca4801543ca4ed6f79 {
	meta:
		aliases = "__GI_fileno_unlocked, fileno_unlocked"
		type = "func"
		size = "27"
		objfiles = "fileno_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 8B 47 04 85 C0 79 0E E8 ?? ?? ?? ?? C7 00 09 00 00 00 83 C8 FF 5A C3 }
	condition:
		$pattern
}

rule setstate_r_199350a23654e5c9307dcf8d75d4e733 {
	meta:
		aliases = "__GI_setstate_r, setstate_r"
		type = "func"
		size = "169"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 8B 4E 18 48 83 C7 04 48 8B 56 10 85 C9 75 09 C7 42 FC 00 00 00 00 EB 15 48 8B 46 08 48 29 D0 48 C1 F8 02 48 8D 04 80 8D 04 01 89 42 FC 8B 47 FC 41 B8 05 00 00 00 99 41 F7 F8 83 FA 04 77 56 48 63 C2 85 D2 89 56 18 8B 0C 85 ?? ?? ?? ?? 44 8B 0C 85 ?? ?? ?? ?? 89 4E 1C 44 89 4E 20 74 23 8B 47 FC 99 41 F7 F8 48 63 D0 41 8D 04 01 48 8D 14 97 48 89 56 08 99 F7 F9 48 63 D2 48 8D 14 97 48 89 16 48 63 C1 48 89 7E 10 48 8D 04 87 48 89 46 28 31 C0 EB 0E E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 5A C3 }
	condition:
		$pattern
}

rule brk_e670af30af24c00381bf09f4ef60c44b {
	meta:
		aliases = "__GI_brk, brk"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "36"
		objfiles = "ttyname@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 BA 20 00 00 00 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C2 31 C0 85 D2 BA ?? ?? ?? ?? 48 0F 44 C2 5A C3 }
	condition:
		$pattern
}

rule strerror_f40bb2bad484cb6f9731cf80e97dd9a8 {
	meta:
		aliases = "__GI_strerror, strerror"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "42"
		objfiles = "read_etc_hosts_r@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 75 10 59 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E9 ?? ?? ?? ?? 5A C3 }
	condition:
		$pattern
}

rule seed48_702ee4622085efff266ddbf30475b8da {
	meta:
		aliases = "__GI_localtime, localtime, seed48"
		type = "func"
		size = "21"
		objfiles = "localtime@libc.a, seed48@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule rexec_076d74a54cf61d972c7d8f2c06c8dcb4 {
	meta:
		aliases = "rexec"
		type = "func"
		size = "18"
		objfiles = "rexec@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 C7 04 24 02 00 00 00 E8 ?? ?? ?? ?? 5A C3 }
	condition:
		$pattern
}

rule __fp_range_check_336904d82c6d403d47b817e07b6baedf {
	meta:
		aliases = "__fp_range_check"
		type = "func"
		size = "75"
		objfiles = "__fp_range_check@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 DB 6C 24 10 DB 6C 24 20 D9 05 ?? ?? ?? ?? D9 C2 D8 C9 D9 CB DB EB DD DB 75 25 7A 23 D9 EE D9 CB DF EB DD DA 7A 02 74 19 DC C9 DF E9 DD D8 7A 02 74 13 E8 ?? ?? ?? ?? C7 00 22 00 00 00 EB 06 DD D8 DD D8 DD D8 58 C3 }
	condition:
		$pattern
}

rule endusershell_df5ba968f023ef9dc9530248bc2d58ea {
	meta:
		aliases = "endusershell"
		type = "func"
		size = "22"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 28 FE FF FF 48 C7 05 ?? ?? ?? ?? 00 00 00 00 5E C3 }
	condition:
		$pattern
}

rule pthread_testcancel_7b7b139bf096b6e97ec33138c67bd4b0 {
	meta:
		aliases = "pthread_testcancel"
		type = "func"
		size = "35"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 7C FE FF FF 80 78 7A 00 74 12 80 78 78 00 75 0C 48 89 E6 48 83 CF FF E8 ?? ?? ?? ?? 58 C3 }
	condition:
		$pattern
}

rule svcunix_rendezvous_abort_0b65a8924fcc66f5c1e12937b0a26173 {
	meta:
		aliases = "svctcp_rendezvous_abort, svcunix_rendezvous_abort"
		type = "func"
		size = "9"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ctime_f4be497721863e850c8ae13ba1be3f94 {
	meta:
		aliases = "__GI_ctime, ctime"
		type = "func"
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
		type = "func"
		size = "22"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 ?? ?? ?? ?? 48 8B B8 B8 00 00 00 58 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __rpc_thread_createerr_f541993b62dee055ce603b451554a68b {
	meta:
		aliases = "__GI___rpc_thread_createerr, __rpc_thread_createerr"
		type = "func"
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
		type = "func"
		size = "36"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 ?? ?? ?? ?? 48 8D 88 A0 00 00 00 48 3D ?? ?? ?? ?? BA ?? ?? ?? ?? 48 0F 45 D1 59 48 89 D0 C3 }
	condition:
		$pattern
}

rule __rpc_thread_svc_max_pollfd_6a9e0a8d19e5984b3f064383920cbe5f {
	meta:
		aliases = "__GI___rpc_thread_svc_max_pollfd, __rpc_thread_svc_max_pollfd"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "18"
		objfiles = "errno@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 A0 FF FF FF 48 8B 80 80 00 00 00 59 C3 }
	condition:
		$pattern
}

rule setusershell_7713966c43a417bdc4e7f2ef003103bc {
	meta:
		aliases = "setusershell"
		type = "func"
		size = "18"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 A7 FE FF FF 48 89 05 ?? ?? ?? ?? 5A C3 }
	condition:
		$pattern
}

rule __h_errno_location_99af7b0bffe57c7965d5e99dbdaae54d {
	meta:
		aliases = "__h_errno_location"
		type = "func"
		size = "18"
		objfiles = "errno@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 B2 FF FF FF 48 8B 80 90 00 00 00 5A C3 }
	condition:
		$pattern
}

rule mq_timedreceive_6f785460050c8c44a126e801e61bfacb {
	meta:
		aliases = "mq_timedreceive"
		type = "func"
		size = "13"
		objfiles = "mq_receive@librt.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 E8 BC FF FF FF 59 48 98 C3 }
	condition:
		$pattern
}

rule __rpc_thread_svc_cleanup_148386925cb04ffa0a060b0bf7a9fbd6 {
	meta:
		aliases = "__rpc_thread_svc_cleanup"
		type = "func"
		size = "38"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 EB 0D 48 8B 70 10 48 8B 78 08 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 80 F0 00 00 00 48 85 C0 75 E2 58 C3 }
	condition:
		$pattern
}

rule scalbln_0eaadaa55299edf3bd63e1af552ca1ba {
	meta:
		aliases = "__GI_scalbln, scalbln"
		type = "func"
		size = "288"
		objfiles = "s_scalbln@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 F2 0F 11 04 24 48 8B 04 24 48 89 C1 89 C2 48 C1 E9 20 89 C8 25 00 00 F0 7F C1 F8 14 75 33 81 E1 FF FF FF 7F 09 D1 0F 84 EE 00 00 00 F2 0F 59 05 ?? ?? ?? ?? F2 0F 11 04 24 48 8B 04 24 48 89 C1 48 C1 E9 20 89 C8 25 00 00 F0 7F C1 F8 14 83 E8 36 3D FF 07 00 00 75 09 F2 0F 58 C0 E9 B9 00 00 00 01 F8 48 81 FF 50 C3 00 00 7F 07 3D FE 07 00 00 7E 1D 0F 28 C8 F2 0F 10 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? E9 8A 00 00 00 48 81 FF B0 3C FF FF 7C 35 85 C0 7E 2C F2 0F 11 04 24 48 8B 14 24 C1 E0 14 81 E1 FF FF 0F 80 09 C8 48 C1 E0 20 83 E2 FF 48 09 C2 48 89 14 24 F2 0F 10 0C 24 }
	condition:
		$pattern
}

rule scalbn_32432596dda4f9ed89726a0ebb7551fe {
	meta:
		aliases = "__GI_scalbn, scalbn"
		type = "func"
		size = "284"
		objfiles = "s_scalbn@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 F2 0F 11 04 24 48 8B 04 24 48 89 C1 89 C2 48 C1 E9 20 89 C8 25 00 00 F0 7F C1 F8 14 75 3C 81 E1 FF FF FF 7F 09 D1 0F 84 EA 00 00 00 F2 0F 59 05 ?? ?? ?? ?? F2 0F 11 04 24 48 8B 04 24 48 C1 E8 20 81 FF B0 3C FF FF 0F 8C 8D 00 00 00 89 C1 25 00 00 F0 7F C1 F8 14 83 E8 36 3D FF 07 00 00 75 09 F2 0F 58 C0 E9 AC 00 00 00 01 F8 3D FE 07 00 00 7F 3D 85 C0 7E 2C F2 0F 11 04 24 48 8B 14 24 C1 E0 14 81 E1 FF FF 0F 80 09 C8 48 C1 E0 20 83 E2 FF 48 09 C2 48 89 14 24 F2 0F 10 0C 24 0F 28 C1 EB 73 83 F8 CA 7F 3C 81 FF 50 C3 00 00 7E 1A 0F 28 C8 F2 0F 10 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? F2 0F 59 05 }
	condition:
		$pattern
}

rule logb_80fa6554686a26e723402301dab40258 {
	meta:
		aliases = "__GI_logb, logb"
		type = "func"
		size = "95"
		objfiles = "s_logb@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 F2 0F 11 04 24 48 8B 14 24 48 89 D0 48 C1 E8 20 25 FF FF FF 7F 89 C1 09 D1 75 13 E8 ?? ?? ?? ?? F2 0F 10 0D ?? ?? ?? ?? F2 0F 5E C8 EB 28 3D FF FF EF 7F 7E 09 0F 28 C8 F2 0F 59 C8 EB 18 C1 F8 14 75 0A F2 0F 10 0D ?? ?? ?? ?? EB 09 2D FF 03 00 00 F2 0F 2A C8 58 0F 28 C1 C3 }
	condition:
		$pattern
}

rule significand_9acb59ea19fd49409a9a756a69cbe4b6 {
	meta:
		aliases = "significand"
		type = "func"
		size = "31"
		objfiles = "s_significand@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 F2 0F 11 04 24 E8 ?? ?? ?? ?? F7 D8 F2 0F 10 04 24 F2 0F 2A C8 58 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule cfsetospeed_fa76ad5eb2894f9727ef8b1a2d14e2a6 {
	meta:
		aliases = "__GI_cfsetospeed, cfsetospeed"
		type = "func"
		size = "56"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 F7 C6 F0 EF FF FF 74 1B 8D 86 FF EF FF FF 83 F8 0E 76 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 0F 8B 47 08 25 F0 EF FF FF 09 F0 89 47 08 31 C0 59 C3 }
	condition:
		$pattern
}

rule cfsetispeed_be1f54b703c9675203a8b8c652b00e6e {
	meta:
		aliases = "__GI_cfsetispeed, cfsetispeed"
		type = "func"
		size = "74"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 F7 C6 F0 EF FF FF 74 1B 8D 86 FF EF FF FF 83 F8 0E 76 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 21 85 F6 75 08 81 0F 00 00 00 80 EB 13 8B 47 08 81 27 FF FF FF 7F 25 F0 EF FF FF 09 F0 89 47 08 31 C0 5A C3 }
	condition:
		$pattern
}

rule __gthread_mutex_unlock_9c158610b6bb66e460b6e297c4682a93 {
	meta:
		aliases = "__gthread_mutex_lock, __gthread_mutex_unlock"
		type = "func"
		size = "17"
		objfiles = "gthr_gnat@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 FF 15 ?? ?? ?? ?? 31 C0 48 83 C4 08 C3 }
	condition:
		$pattern
}

rule tcgetpgrp_9dbfbd35910cb68dcbf9e671199050cb {
	meta:
		aliases = "__GI_tcgetpgrp, tcgetpgrp"
		type = "func"
		size = "39"
		objfiles = "tcgetpgrp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 31 C0 BE 0F 54 00 00 48 8D 54 24 14 E8 ?? ?? ?? ?? 83 CA FF 85 C0 78 04 8B 54 24 14 89 D0 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule wcstombs_2557a4f7264b0bc12208346d0dc94881 {
	meta:
		aliases = "wcstombs"
		type = "func"
		size = "26"
		objfiles = "wcstombs@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 31 C9 48 89 74 24 10 48 8D 74 24 10 E8 ?? ?? ?? ?? 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule setkey_7e1ece318fe5832cd4613213a3d828e8 {
	meta:
		aliases = "setkey"
		type = "func"
		size = "71"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 31 F6 49 89 E0 EB 2A 48 63 C6 31 C9 49 8D 14 00 C6 02 00 EB 15 F6 07 01 74 0B 48 63 C1 8A 80 ?? ?? ?? ?? 08 02 48 FF C7 FF C1 83 F9 07 7E E6 FF C6 83 FE 07 7E D1 4C 89 C7 E8 DB FB FF FF 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule re_match_70b58a5a39158fde95b11c6c664786cf {
	meta:
		aliases = "__re_match, re_match"
		type = "func"
		size = "35"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 41 89 C9 48 89 F1 89 54 24 08 4C 89 04 24 31 F6 41 89 D0 31 D2 E8 51 E2 FF FF 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule xre_match_55caae996e13f1cf7eb5053c1775e5b3 {
	meta:
		aliases = "xre_match"
		type = "func"
		size = "35"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 41 89 C9 48 89 F1 89 54 24 08 4C 89 04 24 31 F6 41 89 D0 31 D2 E8 C2 AD FF FF 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule strsigno_733bef70a4b714cdd6ea1b69979a7ad7 {
	meta:
		aliases = "strerrno, strsigno"
		type = "func"
		size = "127"
		objfiles = "strerror@libiberty.a, strsignal@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 83 3D ?? ?? ?? ?? 00 74 62 85 FF 78 4E 3B 3D ?? ?? ?? ?? 7D 46 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 1A 48 63 D7 48 8B 04 D0 48 85 C0 74 0E 48 83 C4 18 C3 66 0F 1F 84 00 00 00 00 00 89 FA BE ?? ?? ?? ?? BF ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 48 83 C4 18 C3 0F 1F 00 31 C0 48 83 C4 18 C3 66 0F 1F 84 00 00 00 00 00 89 7C 24 0C E8 97 FE FF FF 8B 7C 24 0C EB 8F }
	condition:
		$pattern
}

rule putpwent_af3457adbfe0e3601061883c4b874a01 {
	meta:
		aliases = "putpwent"
		type = "func"
		size = "97"
		objfiles = "putpwent@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 85 FF 49 89 F2 74 05 48 85 F6 75 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 3B 48 8B 47 28 44 8B 4F 14 BE ?? ?? ?? ?? 44 8B 47 10 48 8B 4F 08 48 89 44 24 10 48 8B 47 20 48 89 44 24 08 48 8B 47 18 48 89 04 24 48 8B 17 31 C0 4C 89 D7 E8 ?? ?? ?? ?? C1 F8 1F 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule wcsnrtombs_ab4707dfd5230acc46275ec8cbe587fd {
	meta:
		aliases = "__GI_wcsnrtombs, wcsnrtombs"
		type = "func"
		size = "123"
		objfiles = "wcsnrtombs@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 85 FF 74 11 48 39 F7 B8 01 00 00 00 75 10 48 89 E7 30 C0 EB 09 48 89 E7 48 83 C9 FF 31 C0 48 39 D1 4C 8B 06 4C 63 C8 48 0F 47 CA 48 89 CA EB 2E 41 8B 00 83 F8 7F 76 11 E8 ?? ?? ?? ?? C7 00 54 00 00 00 48 83 C8 FF EB 28 84 C0 88 07 75 05 45 31 C0 EB 0F 49 83 C0 04 4C 01 CF 48 FF CA 48 85 D2 75 CD 48 39 E7 74 03 4C 89 06 48 89 C8 48 29 D0 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule stime_c396978e1123c94425c2990345d30901 {
	meta:
		aliases = "stime"
		type = "func"
		size = "56"
		objfiles = "stime@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 85 FF 75 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 1A 48 8B 07 31 F6 48 89 E7 48 C7 44 24 08 00 00 00 00 48 89 04 24 E8 ?? ?? ?? ?? 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule inet_addr_012295f2b0fb1b7b8ba5964ed85bb592 {
	meta:
		aliases = "__GI_inet_addr, inet_addr"
		type = "func"
		size = "29"
		objfiles = "inet_makeaddr@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 89 E6 E8 ?? ?? ?? ?? 83 CA FF 85 C0 74 03 8B 14 24 89 D0 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule getw_90cd386d4c2417d5419e881656c749d1 {
	meta:
		aliases = "getw"
		type = "func"
		size = "49"
		objfiles = "getw@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 89 F9 BA 01 00 00 00 48 8D 44 24 14 BE 04 00 00 00 48 89 C7 E8 ?? ?? ?? ?? 83 CA FF 48 85 C0 74 04 8B 54 24 14 89 D0 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule xexit_1e52182c4afcd86c9eaace9db223d8b3 {
	meta:
		aliases = "xexit"
		type = "func"
		size = "31"
		objfiles = "xexit@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 0A 89 7C 24 0C FF D0 8B 7C 24 0C E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule find_stack_direction_b9e1a405ca6bcc2047c4ba6bd835fbc0 {
	meta:
		aliases = "find_stack_direction"
		type = "func"
		size = "67"
		objfiles = "alloca@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 20 48 8D 54 24 0F 48 39 D0 19 C0 83 E0 02 83 E8 01 89 05 ?? ?? ?? ?? 48 83 C4 18 C3 0F 1F 44 00 00 48 8D 44 24 0F 48 89 05 ?? ?? ?? ?? E8 BF FF FF FF EB E3 }
	condition:
		$pattern
}

rule xdrstdio_putlong_2cfcd9bf5280883c87bd34e5e6319e27 {
	meta:
		aliases = "xdrstdio_putlong"
		type = "func"
		size = "51"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 8B 06 BA 01 00 00 00 0F C8 89 44 24 14 48 8B 4F 18 48 8D 7C 24 14 BE 04 00 00 00 E8 ?? ?? ?? ?? 48 FF C8 0F 94 C0 48 83 C4 18 0F B6 C0 C3 }
	condition:
		$pattern
}

rule __old_sem_post_d456b9505a4dfcf37d6a4daa9c5a20d1 {
	meta:
		aliases = "__old_sem_post"
		type = "func"
		size = "178"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 8B 17 48 89 D1 83 E1 01 75 07 BE 03 00 00 00 EB 1D 48 81 FA FE FF FF 7F 7E 10 E8 ?? ?? ?? ?? C7 00 22 00 00 00 83 C8 FF EB 7E 48 8D 72 02 48 89 D0 F0 48 0F B1 37 40 0F 94 C6 40 84 F6 74 C0 48 85 C9 75 62 4C 8D 44 24 10 48 89 D1 48 C7 44 24 10 00 00 00 00 EB 27 48 8B 79 10 4C 89 C6 EB 04 48 8D 72 10 48 8B 16 48 85 D2 74 08 8B 41 2C 3B 42 2C 7C EC 48 89 51 10 48 89 0E 48 89 F9 48 83 F9 01 75 D3 EB 16 48 8B 47 10 48 89 44 24 10 48 C7 47 10 00 00 00 00 E8 ?? ?? ?? ?? 48 8B 7C 24 10 48 85 FF 75 E0 31 C0 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule __get_hosts_byname_r_46817bfef1790a43b4b106125149d63b {
	meta:
		aliases = "__get_hosts_byname_r"
		type = "func"
		size = "48"
		objfiles = "get_hosts_byname_r@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 8B 44 24 20 4C 89 4C 24 08 49 89 C9 4C 89 04 24 31 C9 49 89 D0 89 F2 48 89 FE 31 FF 48 89 44 24 10 E8 ?? ?? ?? ?? 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule cplus_demangle_v3_5d6692dcc868f22a850d052e9fd15c0a {
	meta:
		aliases = "cplus_demangle_v3"
		type = "func"
		size = "19"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 8D 54 24 08 E8 22 FD FF FF 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule is_gnu_v3_mangled_dtor_fb92b0c2fd5bfc411698be72c17b4868 {
	meta:
		aliases = "is_gnu_v3_mangled_dtor"
		type = "func"
		size = "35"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 8D 54 24 0C 48 8D 74 24 08 E8 0D F6 FF FF 31 D2 85 C0 0F 45 54 24 0C 48 83 C4 18 89 D0 C3 }
	condition:
		$pattern
}

rule is_gnu_v3_mangled_ctor_12549f04bdb61328a3a266c2eaf3d5a8 {
	meta:
		aliases = "is_gnu_v3_mangled_ctor"
		type = "func"
		size = "35"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 8D 54 24 0C 48 8D 74 24 08 E8 3D F6 FF FF 31 D2 85 C0 0F 45 54 24 08 48 83 C4 18 89 D0 C3 }
	condition:
		$pattern
}

rule tgamma_3782632392d69c66ba048b3d4bd66860 {
	meta:
		aliases = "__GI_tgamma, tgamma"
		type = "func"
		size = "34"
		objfiles = "w_tgamma@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 8D 7C 24 14 E8 ?? ?? ?? ?? 83 7C 24 14 00 79 08 66 0F 57 05 ?? ?? ?? ?? 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule inet_pton4_bb2dd1d96a6913214e35a4c01cb0ba81 {
	meta:
		aliases = "inet_pton4"
		type = "func"
		size = "135"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 49 89 F1 31 C9 45 31 C0 48 89 E6 C6 04 24 00 EB 48 0F BE C0 48 FF C7 8D 50 D0 83 FA 09 77 23 0F B6 06 6B C0 0A 8D 04 02 3D FF 00 00 00 77 4D 85 C9 88 06 75 24 41 FF C0 41 83 F8 04 7F 3E B1 01 EB 17 83 F8 2E 75 35 85 C9 74 31 41 83 F8 04 74 2B 48 FF C6 31 C9 C6 06 00 8A 07 84 C0 75 B2 41 83 F8 03 7E 17 48 89 E6 BA 04 00 00 00 4C 89 CF E8 ?? ?? ?? ?? B8 01 00 00 00 EB 02 31 C0 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule re_search_48b88084187d753e0c48b28a3c9997ab {
	meta:
		aliases = "__re_search, re_search"
		type = "func"
		size = "40"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 89 54 24 10 4C 89 4C 24 08 41 89 C9 44 89 04 24 48 89 F1 41 89 D0 31 F6 31 D2 E8 ?? ?? ?? ?? 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule xdrstdio_putint32_bb02d719d377849eb3ce67baa47e9dcd {
	meta:
		aliases = "xdrstdio_putint32"
		type = "func"
		size = "50"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 8B 06 BA 01 00 00 00 0F C8 89 44 24 14 48 8B 4F 18 48 8D 7C 24 14 BE 04 00 00 00 E8 ?? ?? ?? ?? 48 FF C8 0F 94 C0 48 83 C4 18 0F B6 C0 C3 }
	condition:
		$pattern
}

rule mbsnrtowcs_0f39b2b797812c921557be9cb515046b {
	meta:
		aliases = "__GI_mbsnrtowcs, mbsnrtowcs"
		type = "func"
		size = "147"
		objfiles = "mbsnrtowcs@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 B8 ?? ?? ?? ?? 4D 85 C0 4C 0F 44 C0 48 85 FF 74 11 4C 39 C7 B8 01 00 00 00 75 10 48 89 E7 30 C0 EB 09 48 89 E7 48 83 C9 FF 31 C0 48 39 D1 48 98 4C 8B 0E 48 0F 47 CA 4C 8D 14 85 00 00 00 00 48 89 CA EB 33 41 8A 01 44 0F B6 C0 84 C0 44 89 07 75 05 45 31 C9 EB 25 41 83 F8 7F 7E 11 E8 ?? ?? ?? ?? C7 00 54 00 00 00 48 83 C8 FF EB 1C 49 FF C1 4C 01 D7 48 FF CA 48 85 D2 75 C8 48 39 E7 74 03 4C 89 0E 48 89 C8 48 29 D0 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule sgetspent_5abd21e9b7de4fda56e36ae3f07cbf5b {
	meta:
		aliases = "fgetgrent, fgetpwent, fgetspent, getgrgid, getgrnam, getpwnam, getpwuid, getspnam, sgetspent"
		type = "func"
		size = "39"
		objfiles = "fgetspent@libc.a, getgrnam@libc.a, fgetpwent@libc.a, getgrgid@libc.a, getpwuid@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 B9 00 01 00 00 BA ?? ?? ?? ?? 4C 8D 44 24 10 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 44 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule getspent_ece339ac2255e5b2dcc60ca099afd4f8 {
	meta:
		aliases = "getgrent, getpwent, getspent"
		type = "func"
		size = "39"
		objfiles = "getpwent@libc.a, getspent@libc.a, getgrent@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 BA 00 01 00 00 BE ?? ?? ?? ?? 48 8D 4C 24 10 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 44 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule java_demangle_v3_de2f45e74a8a5694412a333d293a3386 {
	meta:
		aliases = "java_demangle_v3"
		type = "func"
		size = "195"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 BE 25 00 00 00 48 8D 54 24 08 E8 FD FC FF FF 48 85 C0 0F 84 A3 00 00 00 49 89 C2 49 89 C0 45 31 C9 41 BB 07 00 00 00 0F 1F 44 00 00 41 0F B6 10 84 D2 74 1F BF ?? ?? ?? ?? 4C 89 C6 4C 89 D9 F3 A6 75 19 49 83 C0 07 41 0F B6 10 41 83 C1 01 84 D2 75 E1 41 C6 02 00 48 83 C4 18 C3 45 85 C9 74 05 80 FA 3E 74 16 41 88 12 49 83 C0 01 49 83 C2 01 EB B9 66 0F 1F 84 00 00 00 00 00 49 39 C2 4C 89 D2 76 1F 41 80 7A FF 20 74 0F EB 16 0F 1F 80 00 00 00 00 80 7A FF 20 75 09 48 83 EA 01 48 39 C2 75 F1 C6 02 5B 4C 8D 52 02 C6 42 01 5D 41 83 E9 01 49 83 C0 01 E9 71 FF FF FF 31 C0 EB 98 }
	condition:
		$pattern
}

rule mrand48_044ee80b5569b3a44865b1caef2ab77b {
	meta:
		aliases = "lrand48, mrand48"
		type = "func"
		size = "32"
		objfiles = "lrand48@libc.a, mrand48@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 BE ?? ?? ?? ?? 48 8D 54 24 10 48 89 F7 E8 ?? ?? ?? ?? 48 8B 44 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule drand48_96440a156ce9b4e7c1d4e8622db3b675 {
	meta:
		aliases = "drand48"
		type = "func"
		size = "33"
		objfiles = "drand48@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 BE ?? ?? ?? ?? 48 8D 54 24 10 48 89 F7 E8 ?? ?? ?? ?? F2 0F 10 44 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule nrand48_2ae7b0adf8640b3273e0f6dea72de404 {
	meta:
		aliases = "jrand48, nrand48"
		type = "func"
		size = "29"
		objfiles = "nrand48@libc.a, jrand48@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 BE ?? ?? ?? ?? 48 8D 54 24 10 E8 ?? ?? ?? ?? 48 8B 44 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule erand48_1598afd3e403ca7ad66f0261e6232310 {
	meta:
		aliases = "erand48"
		type = "func"
		size = "30"
		objfiles = "erand48@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 BE ?? ?? ?? ?? 48 8D 54 24 10 E8 ?? ?? ?? ?? F2 0F 10 44 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule getdtablesize_dfee7b08f00fab4ddc9e3eb87662577f {
	meta:
		aliases = "__GI_getdtablesize, getdtablesize"
		type = "func"
		size = "36"
		objfiles = "getdtablesize@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 BF 07 00 00 00 48 89 E6 E8 ?? ?? ?? ?? 85 C0 BA 00 01 00 00 78 03 8B 14 24 89 D0 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule physmem_total_aa76e49827d51a6a21c89b421b8cf406 {
	meta:
		aliases = "physmem_total"
		type = "func"
		size = "89"
		objfiles = "physmem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 BF 55 00 00 00 E8 ?? ?? ?? ?? F2 48 0F 2A C0 BF 1E 00 00 00 F2 0F 11 44 24 08 E8 ?? ?? ?? ?? 66 0F 57 C9 F2 0F 10 44 24 08 F2 48 0F 2A D0 66 0F 2E C1 72 18 66 0F 2E D1 72 12 F2 0F 59 C2 48 83 C4 18 C3 66 0F 1F 84 00 00 00 00 00 66 0F 28 C1 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule physmem_available_b1802cf6bf2433c8634ea307366fb811 {
	meta:
		aliases = "physmem_available"
		type = "func"
		size = "98"
		objfiles = "physmem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 BF 56 00 00 00 E8 ?? ?? ?? ?? F2 48 0F 2A C0 BF 1E 00 00 00 F2 0F 11 44 24 08 E8 ?? ?? ?? ?? 66 0F 57 C9 F2 0F 10 44 24 08 F2 48 0F 2A D0 66 0F 2E C1 72 18 66 0F 2E D1 72 12 F2 0F 59 C2 48 83 C4 18 C3 66 0F 1F 84 00 00 00 00 00 E8 ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule __fixxfti_2f63816b5402482e546ce7b0f877efa4 {
	meta:
		aliases = "__fixxfti"
		type = "func"
		size = "57"
		objfiles = "_fixxfdi@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 DB 6C 24 20 D9 EE DF E9 77 12 DD D8 48 83 C4 18 E9 ?? ?? ?? ?? 66 66 66 90 66 66 90 D9 E0 DB 3C 24 E8 ?? ?? ?? ?? 48 F7 D8 48 83 D2 00 48 83 C4 18 48 F7 DA C3 }
	condition:
		$pattern
}

rule getprotoent_af6dec1895eba4853228e0c08ab1670b {
	meta:
		aliases = "getprotoent"
		type = "func"
		size = "46"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 E8 09 FE FF FF 48 8B 35 ?? ?? ?? ?? 48 8D 4C 24 10 BA 19 11 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 44 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule getservent_94762819f992c068c82285b0dae9aee2 {
	meta:
		aliases = "getservent"
		type = "func"
		size = "46"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 E8 D3 FD FF FF 48 8B 35 ?? ?? ?? ?? 48 8D 4C 24 10 BA 19 11 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 44 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule __pthread_unlock_d388ce8f0079dabd0e7f20c151d93045 {
	meta:
		aliases = "__pthread_unlock"
		type = "func"
		size = "177"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 EB 15 31 C9 48 89 D0 F0 48 0F B1 0F 0F 94 C2 84 D2 0F 85 8F 00 00 00 48 8B 17 48 83 FA 01 74 E2 49 89 D0 49 83 E0 FE 45 31 D2 4C 89 C0 49 89 F9 48 89 FE EB 1A 8B 48 2C 44 39 D1 7C 06 4C 89 CE 41 89 CA 4C 8D 48 18 48 8B 40 18 48 83 E0 FE 48 85 C0 75 E1 48 39 FE 75 19 49 8B 48 18 48 89 D0 48 83 E1 FE F0 48 0F B1 0F 0F 94 C2 84 D2 74 A7 EB 24 4C 8B 06 49 83 E0 FE 49 8B 40 18 48 89 06 48 8B 07 48 89 C2 48 83 E2 FE F0 48 0F B1 17 0F 94 C2 84 D2 74 EA 49 C7 40 18 00 00 00 00 4C 89 C7 E8 16 FD FF FF 31 C0 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule fdim_369ba422650696768a06d3e91a765b13 {
	meta:
		aliases = "__GI_fdim, fdim"
		type = "func"
		size = "72"
		objfiles = "s_fdim@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 F2 0F 11 44 24 10 F2 0F 11 4C 24 08 E8 ?? ?? ?? ?? 83 F8 01 77 0A F2 0F 10 05 ?? ?? ?? ?? EB 1F F2 0F 10 44 24 10 66 0F 2E 44 24 08 77 05 0F 57 C0 EB 0C F2 0F 10 44 24 10 F2 0F 5C 44 24 08 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule fmin_969f94b5321f5ce82048439e5929d38c {
	meta:
		aliases = "__GI_fmin, fmin"
		type = "func"
		size = "77"
		objfiles = "s_fmin@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 F2 0F 11 44 24 10 F2 0F 11 4C 24 08 E8 ?? ?? ?? ?? 85 C0 74 29 F2 0F 10 44 24 08 E8 ?? ?? ?? ?? 85 C0 75 08 F2 0F 10 44 24 08 EB 0C F2 0F 10 44 24 10 F2 0F 5D 44 24 08 F2 0F 11 44 24 10 F2 0F 10 44 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule fmax_48185d15b6d608671592b6c1206df457 {
	meta:
		aliases = "__GI_fmax, fmax"
		type = "func"
		size = "77"
		objfiles = "s_fmax@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 F2 0F 11 44 24 10 F2 0F 11 4C 24 08 E8 ?? ?? ?? ?? 85 C0 74 29 F2 0F 10 44 24 08 E8 ?? ?? ?? ?? 85 C0 75 08 F2 0F 10 44 24 08 EB 0C F2 0F 10 44 24 10 F2 0F 5F 44 24 08 F2 0F 11 44 24 10 F2 0F 10 44 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule __ieee754_scalb_64d330da0740a6bfc2df9d93ad1c9f84 {
	meta:
		aliases = "__ieee754_scalb"
		type = "func"
		size = "213"
		objfiles = "e_scalb@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 F2 0F 11 44 24 10 F2 0F 11 4C 24 08 E8 ?? ?? ?? ?? 85 C0 75 2E F2 0F 10 44 24 08 E8 ?? ?? ?? ?? 85 C0 75 1F F2 0F 10 44 24 08 E8 ?? ?? ?? ?? 85 C0 75 31 F2 0F 10 44 24 08 66 0F 2E 05 ?? ?? ?? ?? 76 0E F2 0F 10 44 24 10 F2 0F 59 44 24 08 EB 7B 80 74 24 0F 80 F2 0F 10 44 24 10 F2 0F 5E 44 24 08 EB 68 F2 0F 10 44 24 08 E8 ?? ?? ?? ?? 66 0F 2E 44 24 08 7A 02 74 10 F2 0F 10 44 24 08 F2 0F 5C C0 F2 0F 5E C0 EB 43 F2 0F 10 44 24 08 BF E8 FD 00 00 66 0F 2E 05 ?? ?? ?? ?? 77 1F F2 0F 10 44 24 08 66 0F 2E 05 ?? ?? ?? ?? 73 09 7A 07 BF 18 02 FF FF EB 06 F2 0F 2C 7C 24 08 F2 0F 10 44 24 10 48 }
	condition:
		$pattern
}

rule cos_10de0b95ec48ef431934f1a832bd56b6 {
	meta:
		aliases = "__GI_cos, cos"
		type = "func"
		size = "159"
		objfiles = "s_cos@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 28 0F 57 C9 F2 0F 11 44 24 08 48 8B 44 24 08 48 C1 E8 20 25 FF FF FF 7F 3D FB 21 E9 3F 7E 34 3D FF FF EF 7F 7E 06 F2 0F 5C C0 EB 6B 48 8D 7C 24 10 E8 ?? ?? ?? ?? 83 E0 03 83 F8 01 74 1C 83 F8 02 74 2F 85 C0 F2 0F 10 4C 24 18 F2 0F 10 44 24 10 75 3A E8 ?? ?? ?? ?? EB 3D F2 0F 10 4C 24 18 BF 01 00 00 00 F2 0F 10 44 24 10 E8 ?? ?? ?? ?? EB 11 F2 0F 10 4C 24 18 F2 0F 10 44 24 10 E8 ?? ?? ?? ?? 66 0F 57 05 ?? ?? ?? ?? EB 0A BF 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 C3 }
	condition:
		$pattern
}

rule __ieee754_log10_41176ed9492667649b6883cbfbd1cf7e {
	meta:
		aliases = "__ieee754_log10"
		type = "func"
		size = "267"
		objfiles = "e_log10@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 28 31 C9 F2 0F 11 44 24 08 48 8B 44 24 08 48 89 C6 89 C2 48 C1 EE 20 81 FE FF FF 0F 00 7F 4C 89 F0 25 FF FF FF 7F 09 D0 75 0A F2 0F 10 15 ?? ?? ?? ?? EB 0B 85 F6 79 14 0F 28 D0 F2 0F 5C D0 F2 0F 5E 15 ?? ?? ?? ?? E9 B4 00 00 00 F2 0F 59 05 ?? ?? ?? ?? B9 CA FF FF FF F2 0F 11 44 24 08 48 8B 44 24 08 48 89 C6 48 C1 EE 20 81 FE FF FF EF 7F 7E 0C 0F 28 D0 F2 0F 58 D0 E9 81 00 00 00 89 F0 F2 0F 11 44 24 08 48 8B 54 24 08 C1 F8 14 81 E6 FF FF 0F 00 8D 84 01 01 FC FF FF 83 E2 FF 89 C1 C1 E9 1F 8D 04 01 F2 0F 2A C8 B8 FF 03 00 00 29 C8 C1 E0 14 09 F0 48 C1 E0 20 48 09 C2 48 89 54 24 08 F2 0F }
	condition:
		$pattern
}

rule hsearch_ad452dc3c90d0324ee76eaa162927d87 {
	meta:
		aliases = "hsearch"
		type = "func"
		size = "40"
		objfiles = "hsearch@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 28 41 B8 ?? ?? ?? ?? 48 8D 4C 24 20 48 89 7C 24 08 48 89 74 24 10 E8 ?? ?? ?? ?? 48 8B 44 24 20 48 83 C4 28 C3 }
	condition:
		$pattern
}

rule clntudp_create_5a6a016fcc5cbddee5279b2e509d362b {
	meta:
		aliases = "__GI_clntudp_create, clntudp_create"
		type = "func"
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
		type = "func"
		size = "37"
		objfiles = "mbstowcs@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 28 48 89 74 24 08 48 8D 4C 24 10 48 8D 74 24 08 C7 44 24 10 00 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 C3 }
	condition:
		$pattern
}

rule clock_d52c350153d76354876c49b438a3dc61 {
	meta:
		aliases = "clock"
		type = "func"
		size = "46"
		objfiles = "clock@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? 48 8B 04 24 48 03 44 24 08 48 BA FF FF FF FF FF FF FF 7F 48 83 C4 28 48 69 C0 10 27 00 00 48 21 D0 C3 }
	condition:
		$pattern
}

rule xre_search_20e07d6bfc9175d8cff5d2ae0a2789d0 {
	meta:
		aliases = "xre_search"
		type = "func"
		size = "40"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 28 89 54 24 10 4C 89 4C 24 08 41 89 C9 44 89 04 24 48 89 F1 41 89 D0 31 F6 31 D2 E8 CD CF FF FF 48 83 C4 28 C3 }
	condition:
		$pattern
}

rule clearenv_15769ec3d48de0df7eff7256f9ab0c63 {
	meta:
		aliases = "clearenv"
		type = "func"
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
		type = "func"
		size = "158"
		objfiles = "closenameservers@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 28 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 2A FF C8 89 05 ?? ?? ?? ?? 48 98 48 8B 3C C5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 63 05 ?? ?? ?? ?? 48 C7 04 C5 ?? ?? ?? ?? 00 00 00 00 8B 05 ?? ?? ?? ?? 85 C0 7F CC EB 2A FF C8 89 05 ?? ?? ?? ?? 48 98 48 8B 3C C5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 63 05 ?? ?? ?? ?? 48 C7 04 C5 ?? ?? ?? ?? 00 00 00 00 8B 05 ?? ?? ?? ?? 85 C0 7F CC 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 C3 }
	condition:
		$pattern
}

rule tan_a99107c8aeb1e6ab1e9aec63126c7cb0 {
	meta:
		aliases = "__GI_tan, tan"
		type = "func"
		size = "96"
		objfiles = "s_tan@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 28 BF 01 00 00 00 F2 0F 11 44 24 08 48 8B 44 24 08 0F 57 C9 48 C1 E8 20 25 FF FF FF 7F 3D FB 21 E9 3F 7E 2F 3D FF FF EF 7F 7E 06 F2 0F 5C C0 EB 27 48 8D 7C 24 10 E8 ?? ?? ?? ?? 83 E0 01 BF 01 00 00 00 01 C0 F2 0F 10 4C 24 18 F2 0F 10 44 24 10 29 C7 E8 ?? ?? ?? ?? 48 83 C4 28 C3 }
	condition:
		$pattern
}

rule sin_4e017df5c81036633e6996f6c7fead0e {
	meta:
		aliases = "__GI_sin, sin"
		type = "func"
		size = "163"
		objfiles = "s_sin@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 28 F2 0F 11 44 24 08 48 8B 44 24 08 48 C1 E8 20 25 FF FF FF 7F 3D FB 21 E9 3F 7F 07 0F 57 C9 31 FF EB 39 3D FF FF EF 7F 7E 06 F2 0F 5C C0 EB 6B 48 8D 7C 24 10 E8 ?? ?? ?? ?? 83 E0 03 83 F8 01 74 21 83 F8 02 74 2F 85 C0 F2 0F 10 4C 24 18 F2 0F 10 44 24 10 75 37 BF 01 00 00 00 E8 ?? ?? ?? ?? EB 38 F2 0F 10 4C 24 18 F2 0F 10 44 24 10 E8 ?? ?? ?? ?? EB 25 F2 0F 10 4C 24 18 BF 01 00 00 00 F2 0F 10 44 24 10 E8 ?? ?? ?? ?? EB 05 E8 ?? ?? ?? ?? 66 0F 57 05 ?? ?? ?? ?? 48 83 C4 28 C3 }
	condition:
		$pattern
}

rule __ieee754_acosh_d734c2387b99d47fa7b8cdf780e7edec {
	meta:
		aliases = "__ieee754_acosh"
		type = "func"
		size = "252"
		objfiles = "e_acosh@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 38 0F 28 D0 F2 0F 11 44 24 08 48 8B 44 24 08 48 89 C2 89 C1 48 C1 EA 20 81 FA FF FF EF 3F 7F 0D F2 0F 5C C2 F2 0F 5E C0 E9 C7 00 00 00 81 FA FF FF AF 41 7E 29 81 FA FF FF EF 7F 7E 0C 0F 28 C2 F2 0F 58 C2 E9 AB 00 00 00 0F 28 C2 E8 ?? ?? ?? ?? F2 0F 58 05 ?? ?? ?? ?? E9 96 00 00 00 8D 82 00 00 10 C0 09 C8 75 08 0F 57 C0 E9 84 00 00 00 81 FA 00 00 00 40 F2 0F 10 0D ?? ?? ?? ?? 7E 40 0F 28 C2 F2 0F 11 54 24 10 F2 0F 59 C2 F2 0F 5C C1 E8 ?? ?? ?? ?? F2 0F 10 54 24 10 0F 28 CA F2 0F 58 CA F2 0F 58 D0 F2 0F 10 05 ?? ?? ?? ?? 48 83 C4 38 F2 0F 5E C2 F2 0F 58 C1 E9 ?? ?? ?? ?? F2 0F 5C D1 0F }
	condition:
		$pattern
}

rule __ieee754_acos_cd5d47a9299cad13e9de3e6a88ba1f8e {
	meta:
		aliases = "__ieee754_acos"
		type = "func"
		size = "766"
		objfiles = "e_acos@libm.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 38 0F 28 E8 F2 0F 11 44 24 08 48 8B 44 24 08 48 89 C1 48 C1 E9 20 89 C8 25 FF FF FF 7F 3D FF FF EF 3F 7E 36 48 8B 54 24 08 2D 00 00 F0 3F 09 D0 75 18 85 C9 0F 57 E4 0F 8F B6 02 00 00 F2 0F 10 25 ?? ?? ?? ?? E9 A9 02 00 00 0F 28 E5 F2 0F 5C E5 F2 0F 5E E4 E9 99 02 00 00 3D FF FF DF 3F 0F 8F C0 00 00 00 3D 00 00 60 3C F2 0F 10 1D ?? ?? ?? ?? 7F 08 0F 28 E3 E9 77 02 00 00 0F 28 D5 0F 28 E3 F2 0F 59 D5 0F 28 CA 0F 28 C2 F2 0F 59 0D ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? F2 0F 58 0D ?? ?? ?? ?? F2 0F 5C 05 ?? ?? ?? ?? F2 0F 59 CA F2 0F 59 C2 F2 0F 5C 0D ?? ?? ?? ?? F2 0F 58 05 ?? ?? ?? ?? F2 }
	condition:
		$pattern
}

rule wcrtomb_728c05a539ac3446797a6bad3bc6b82c {
	meta:
		aliases = "__GI_wcrtomb, wcrtomb"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "79"
		objfiles = "ualarm@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 48 89 F6 89 FF 48 8D 54 24 20 48 89 74 24 08 48 89 7C 24 18 48 89 E6 31 FF 48 C7 04 24 00 00 00 00 48 C7 44 24 10 00 00 00 00 E8 ?? ?? ?? ?? 83 CA FF 85 C0 78 0F 48 69 44 24 30 40 42 0F 00 8B 54 24 38 01 C2 89 D0 48 83 C4 48 C3 }
	condition:
		$pattern
}

rule svcerr_noprog_c3117f66c65421b63a637037c53741bb {
	meta:
		aliases = "__GI_svcerr_noprog, svcerr_noprog"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "85"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 68 48 8D 47 28 49 89 F9 4C 8D 44 24 18 49 89 F2 C7 44 24 08 01 00 00 00 C7 44 24 10 00 00 00 00 48 89 C6 B9 06 00 00 00 FC 4C 89 C7 F3 A5 C7 44 24 30 00 00 00 00 48 89 54 24 38 48 89 E6 4C 89 54 24 40 4C 89 CF 49 8B 41 08 FF 50 18 48 83 C4 68 C3 }
	condition:
		$pattern
}

rule svcerr_progvers_18f9c77bc8855a839f2b54044d88872a {
	meta:
		aliases = "__GI_svcerr_progvers, svcerr_progvers"
		type = "func"
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
		type = "func"
		size = "131"
		objfiles = "strncpy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 FA 03 48 8D 4F FF 76 4F 49 89 D0 49 C1 E8 02 8A 06 48 FF C1 84 C0 88 01 74 2F 8A 46 01 48 FF C1 84 C0 88 01 74 23 8A 46 02 48 FF C1 84 C0 88 01 74 17 8A 46 03 48 FF C1 84 C0 88 01 74 0B 48 83 C6 04 49 FF C8 74 10 EB C6 48 89 C8 48 29 F8 48 29 C2 48 89 D0 EB 21 48 89 D0 83 E0 03 74 1E 8A 16 48 FF C1 48 FF C6 48 FF C8 88 11 74 0F 84 D2 75 ED 48 FF C1 C6 01 00 48 FF C8 75 F5 48 89 F8 C3 }
	condition:
		$pattern
}

rule strncmp_a3a01e90d963400282720af913b06fff {
	meta:
		aliases = "__GI_strncmp, strncmp"
		type = "func"
		size = "128"
		objfiles = "strncmp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 FA 03 77 06 31 C0 31 C9 EB 64 49 89 D0 49 C1 E8 02 8A 07 8A 0E 84 C0 74 5A 38 C8 75 56 8A 47 01 8A 4E 01 84 C0 74 4C 38 C8 75 48 8A 47 02 8A 4E 02 84 C0 74 3E 38 C8 75 3A 8A 47 03 8A 4E 03 84 C0 74 30 38 C8 75 2C 48 83 C7 04 48 83 C6 04 49 FF C8 75 BD 83 E2 03 EB 15 8A 07 8A 0E 84 C0 74 12 38 C8 75 0E 48 FF C7 48 FF C6 48 FF CA 48 85 D2 75 E6 0F B6 D0 0F B6 C1 29 C2 89 D0 C3 }
	condition:
		$pattern
}

rule memset_a862b942bf987fe3d05f0e9c48d99fcb {
	meta:
		aliases = "__GI_memset, memset"
		type = "func"
		size = "210"
		objfiles = "memset@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 83 FA 07 48 89 F9 76 7D 49 B8 01 01 01 01 01 01 01 01 40 0F B6 C6 4C 0F AF C0 F7 C7 07 00 00 00 74 0E 40 88 31 48 FF CA 48 FF C1 F6 C1 07 75 F2 48 89 D0 48 C1 E8 06 74 31 48 81 FA C0 D4 01 00 73 5D 4C 89 01 4C 89 41 08 4C 89 41 10 4C 89 41 18 4C 89 41 20 4C 89 41 28 4C 89 41 30 4C 89 41 38 48 83 C1 40 48 FF C8 75 D8 83 E2 3F 48 89 D0 48 C1 E8 03 74 0C 4C 89 01 48 83 C1 08 48 FF C8 75 F4 83 E2 07 48 85 D2 74 0B 40 88 31 48 FF C1 48 FF CA 75 F5 48 89 F8 C3 66 66 90 66 66 90 4C 0F C3 01 4C 0F C3 41 08 4C 0F C3 41 10 4C 0F C3 41 18 4C 0F C3 41 20 4C 0F C3 41 28 4C 0F C3 41 30 4C 0F C3 41 38 48 }
	condition:
		$pattern
}

rule memcpy_ebd030231cb309581dcce2de7d705774 {
	meta:
		aliases = "__GI_memcpy, memcpy"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "25"
		objfiles = "mbsrtowcs@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 C9 41 B8 ?? ?? ?? ?? 4C 0F 45 C1 48 89 D1 48 83 CA FF E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule temp_file_DOT_isra_DOT_2_843f66a6a974ba0f588f6cde4528bc6a {
	meta:
		aliases = "temp_file.isra.2"
		type = "func"
		size = "181"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 85 D2 48 89 D0 74 20 83 E6 04 74 73 48 8B 3F 48 85 FF 74 73 48 89 C6 31 D2 31 C0 E9 ?? ?? ?? ?? 0F 1F 80 00 00 00 00 53 48 8B 1F 48 85 DB 74 6F 48 89 DF E8 ?? ?? ?? ?? 83 F8 05 7E 15 48 98 BF ?? ?? ?? ?? B9 07 00 00 00 48 8D 74 03 FA F3 A6 74 3D 48 89 DF 31 D2 BE ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? 48 89 C3 31 F6 48 89 DF E8 ?? ?? ?? ?? 85 C0 78 33 89 C7 E8 ?? ?? ?? ?? 48 89 D8 5B F3 C3 66 0F 1F 44 00 00 48 89 D7 E9 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 C3 EB CA 0F 1F 00 5B 31 FF E9 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 31 C0 5B EB CB }
	condition:
		$pattern
}

rule mbrlen_d52feeb84af285cb920ea268f5bb037a {
	meta:
		aliases = "__GI_mbrlen, mbrlen"
		type = "func"
		size = "28"
		objfiles = "mbrlen@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 D2 48 89 D1 B8 ?? ?? ?? ?? 48 0F 44 C8 48 89 F2 48 89 FE 31 FF E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __gcc_bcmp_20843e8413be0f486f409189f5a384ae {
	meta:
		aliases = "__gcc_bcmp"
		type = "func"
		size = "62"
		objfiles = "__gcc_bcmp@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 D2 74 29 0F B6 0F 0F B6 06 45 31 C0 38 C1 74 16 EB 1F 41 0F B6 4C 38 01 41 0F B6 44 30 01 49 83 C0 01 38 C1 75 0B 48 83 EA 01 75 E6 31 D2 89 D0 C3 0F B6 D1 0F B6 C0 29 C2 89 D0 C3 }
	condition:
		$pattern
}

rule wcsxfrm_bafe3ff4e4c28ab2d206e106727b46d9 {
	meta:
		aliases = "__wcslcpy, wcsxfrm"
		type = "func"
		size = "55"
		objfiles = "wcslcpy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 D2 75 0A 48 8D 7C 24 E8 48 89 F1 EB 15 48 FF CA EB F6 48 85 D2 74 07 48 FF CA 48 83 C7 04 48 83 C1 04 8B 01 85 C0 89 07 75 E8 48 29 F1 48 C1 F9 02 48 89 C8 C3 }
	condition:
		$pattern
}

rule strxfrm_36360957cc987d240d738bf0e95613db {
	meta:
		aliases = "__GI_strlcpy, __GI_strxfrm, strlcpy, strxfrm"
		type = "func"
		size = "49"
		objfiles = "strlcpy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 D2 75 0A 48 8D 7C 24 FF 48 89 F1 EB 13 48 FF CA EB F6 48 85 D2 74 06 48 FF CA 48 FF C7 48 FF C1 8A 01 84 C0 88 07 75 EA 48 29 F1 48 89 C8 C3 }
	condition:
		$pattern
}

rule pthread_rwlock_init_895533108354240e71d41b8754632866 {
	meta:
		aliases = "pthread_rwlock_init"
		type = "func"
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
		type = "func"
		size = "48"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 85 F6 48 C7 47 18 00 00 00 00 C7 47 20 00 00 00 00 B8 03 00 00 00 74 02 8B 06 89 47 10 31 C0 C7 47 04 00 00 00 00 48 C7 47 08 00 00 00 00 C3 }
	condition:
		$pattern
}

rule hcreate_r_465daa7364613852e6fe7bfb88a235f2 {
	meta:
		aliases = "__GI_hcreate_r, hcreate_r"
		type = "func"
		size = "121"
		objfiles = "hcreate_r@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 F6 53 48 89 F3 75 0F E8 ?? ?? ?? ?? C7 00 16 00 00 00 31 C0 EB 5F 31 C0 48 83 3E 00 75 57 48 83 CF 01 EB 04 48 83 C7 02 89 FE B9 03 00 00 00 EB 03 83 C1 02 89 C8 0F AF C1 39 F0 73 0A 31 D2 89 F0 F7 F1 85 D2 75 EA 31 D2 89 F0 F7 F1 85 D2 74 D3 89 F7 89 73 08 C7 43 0C 00 00 00 00 FF C7 BE 18 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 03 0F 95 C0 0F B6 C0 5B C3 }
	condition:
		$pattern
}

rule sigprocmask_701f20587654fc5958f4746ee1f7115e {
	meta:
		aliases = "__GI_sigprocmask, sigprocmask"
		type = "func"
		size = "73"
		objfiles = "sigprocmask@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 F6 53 74 15 83 FF 02 76 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 2C 41 BA 08 00 00 00 48 63 FF B8 0E 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule mq_notify_f70ef10baa065aef738e38d9abc59c58 {
	meta:
		aliases = "mq_notify"
		type = "func"
		size = "68"
		objfiles = "mq_notify@librt.a"
	strings:
		$pattern = { ( CC | 48 ) 85 F6 53 74 16 83 7E 0C 02 75 10 E8 ?? ?? ?? ?? C7 00 26 00 00 00 83 C8 FF EB 26 48 63 FF B8 F4 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule xrealloc_b0382f835161c89f57290a111c659b52 {
	meta:
		aliases = "xrealloc"
		type = "func"
		size = "58"
		objfiles = "xmalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 85 F6 53 B8 01 00 00 00 48 89 F3 48 0F 44 D8 48 85 FF 74 13 48 89 DE E8 ?? ?? ?? ?? 48 85 C0 74 10 5B C3 0F 1F 40 00 48 89 DF E8 ?? ?? ?? ?? EB EB 48 89 DF E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_insert_list_2a2d279f969ffeab3163f555c376f875 {
	meta:
		aliases = "pthread_insert_list"
		type = "func"
		size = "37"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 85 F6 74 1F 85 C9 75 06 EB 0C 48 8D 78 08 48 8B 07 48 85 C0 75 F4 48 89 32 48 8B 07 48 89 42 08 48 89 17 C3 }
	condition:
		$pattern
}

rule inet_aton_3579efef4e86cda272d46b31a4966fae {
	meta:
		aliases = "__GI_inet_aton, inet_aton"
		type = "func"
		size = "141"
		objfiles = "inet_aton@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 0F 84 81 00 00 00 45 31 C0 41 BA 01 00 00 00 EB 5F 48 0F BE 07 4C 8B 0D ?? ?? ?? ?? 41 F6 04 41 08 74 64 31 D2 EB 15 6B D2 0A 0F BE C1 8D 54 02 D0 81 FA FF 00 00 00 7F 4E 48 FF C7 8A 0F 48 0F BE C1 41 0F B7 04 41 A8 08 75 DC 41 83 FA 04 74 0A 80 F9 2E 75 31 48 FF C7 EB 0B 48 FF C7 84 C9 74 04 A8 20 74 21 41 C1 E0 08 41 FF C2 41 09 D0 41 83 FA 04 7E 9B 48 85 F6 B8 01 00 00 00 74 09 41 0F C8 44 89 06 C3 31 C0 C3 }
	condition:
		$pattern
}

rule cplus_demangle_fill_component_f5c872d40f95d7f580787177a0b84439 {
	meta:
		aliases = "cplus_demangle_fill_component"
		type = "func"
		size = "101"
		objfiles = "cp_demint@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 49 89 CA 74 38 8D 4E FF 31 C0 83 F9 31 77 36 41 B8 01 00 00 00 49 D3 E0 48 B9 80 FD E7 F7 02 02 00 00 49 85 C8 75 26 48 B9 0F 02 00 08 7C FC 03 00 49 85 C8 75 1C F3 C3 0F 1F 44 00 00 31 C0 66 0F 1F 44 00 00 F3 C3 66 0F 1F 44 00 00 4D 85 D2 75 F3 89 37 48 89 57 08 B8 01 00 00 00 4C 89 57 10 C3 }
	condition:
		$pattern
}

rule dlsym_edfc66229fe0af61a257eb542914b43c {
	meta:
		aliases = "dlsym"
		type = "func"
		size = "185"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 49 89 F2 75 09 48 8B 35 ?? ?? ?? ?? EB 6F 48 83 FF FF 48 89 FE 74 2F 48 3B 3D ?? ?? ?? ?? 74 5D 48 8B 05 ?? ?? ?? ?? EB 09 48 39 F8 74 4F 48 8B 40 08 48 85 C0 75 F2 31 D2 48 C7 05 ?? ?? ?? ?? 09 00 00 00 EB 6C 4C 8B 0C 24 48 8B 05 ?? ?? ?? ?? 45 31 C0 EB 22 48 8B 08 48 8B 51 28 4C 39 CA 73 12 4D 85 C0 74 06 49 39 50 28 73 07 48 8B 70 20 49 89 C8 48 8B 40 20 48 85 C0 75 D9 31 D2 48 3B 35 ?? ?? ?? ?? 75 03 48 8B 16 B9 00 00 00 80 4C 89 D7 E8 ?? ?? ?? ?? 48 89 C2 B8 0A 00 00 00 48 85 D2 48 0F 45 05 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 89 D0 C3 }
	condition:
		$pattern
}

rule tmpnam_r_7f2fe14cfc56a190a89fd05b32be8365 {
	meta:
		aliases = "tmpnam_r"
		type = "func"
		size = "51"
		objfiles = "tmpnam_r@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 53 48 89 FB 74 23 31 C9 31 D2 BE 14 00 00 00 E8 ?? ?? ?? ?? 85 C0 75 11 BE 03 00 00 00 48 89 DF E8 ?? ?? ?? ?? 85 C0 74 02 31 DB 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule ternary_cleanup_f9f7b8cd48977d89788aca5390f536a1 {
	meta:
		aliases = "ternary_cleanup"
		type = "func"
		size = "66"
		objfiles = "ternary@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 53 48 89 FB 74 37 48 8B 7F 08 E8 ?? ?? ?? ?? 80 3B 00 75 19 48 8B 7B 18 E8 ?? ?? ?? ?? 48 89 DF 5B E9 ?? ?? ?? ?? 0F 1F 80 00 00 00 00 48 8B 7B 10 E8 ?? ?? ?? ?? EB DC 0F 1F 44 00 00 5B C3 }
	condition:
		$pattern
}

rule xre_comp_9cad698b2a2af3f1af83f86127241e63 {
	meta:
		aliases = "xre_comp"
		type = "func"
		size = "180"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 53 48 89 FB 74 47 48 83 3D ?? ?? ?? ?? 00 74 55 48 89 DF 80 0D ?? ?? ?? ?? 80 E8 ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? B9 ?? ?? ?? ?? 48 89 C6 48 89 DF E8 47 D2 FF FF 85 C0 74 73 48 98 48 8B 04 C5 ?? ?? ?? ?? 5B C3 0F 1F 80 00 00 00 00 48 83 3D ?? ?? ?? ?? 00 B8 ?? ?? ?? ?? 5B 48 0F 45 C7 C3 0F 1F 44 00 00 BF C8 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 74 25 BF 00 01 00 00 48 C7 05 ?? ?? ?? ?? C8 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 0F 85 70 FF FF FF B8 ?? ?? ?? ?? 5B C3 66 0F 1F 44 00 00 31 C0 5B C3 }
	condition:
		$pattern
}

rule hdestroy_r_14bd5f46cb557fedfca2adc4e3381923 {
	meta:
		aliases = "__GI_hdestroy_r, hdestroy_r"
		type = "func"
		size = "39"
		objfiles = "hdestroy_r@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 53 48 89 FB 75 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 0F 48 8B 3F E8 ?? ?? ?? ?? 48 C7 03 00 00 00 00 5B C3 }
	condition:
		$pattern
}

rule re_comp_eb0c6f4f94aebee51ef2fb1dcc8cfa75 {
	meta:
		aliases = "re_comp"
		type = "func"
		size = "176"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 53 48 89 FB 75 18 48 83 3D ?? ?? ?? ?? 00 BA ?? ?? ?? ?? 0F 84 8F 00 00 00 E9 88 00 00 00 48 83 3D ?? ?? ?? ?? 00 75 41 BF C8 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? BA ?? ?? ?? ?? 74 65 BF 00 01 00 00 48 C7 05 ?? ?? ?? ?? C8 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? BA ?? ?? ?? ?? 74 3F 80 0D ?? ?? ?? ?? 80 48 89 DF E8 ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? 48 89 C6 B9 ?? ?? ?? ?? 48 89 DF E8 11 D8 FF FF 85 C0 74 13 48 98 48 8B 14 C5 ?? ?? ?? ?? 48 81 C2 ?? ?? ?? ?? EB 02 31 D2 5B 48 89 D0 C3 }
	condition:
		$pattern
}

rule __deregister_frame_info_bases_2aacbb44cbd05ab5ed7451363005239c {
	meta:
		aliases = "__deregister_frame_info_bases"
		type = "func"
		size = "169"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 53 75 0A 5B 31 C0 C3 66 66 90 66 66 90 44 8B 1F 45 85 DB 74 EE 48 8B 1D ?? ?? ?? ?? 48 85 DB 74 2F 48 39 7B 18 48 8D 15 ?? ?? ?? ?? 75 15 48 8B 43 28 48 89 02 48 89 D8 5B C3 66 66 90 48 39 7B 18 74 EB 48 8D 53 28 48 8B 5B 28 48 85 DB 75 ED 48 8B 1D ?? ?? ?? ?? 48 85 DB 74 45 48 8D 15 ?? ?? ?? ?? EB 19 48 8B 43 18 48 39 38 74 21 48 8B 43 28 48 85 C0 74 2A 48 8D 53 28 48 89 C3 F6 43 20 01 75 E1 48 39 7B 18 75 E4 66 66 90 EB 9F 48 8B 43 28 48 89 02 48 8B 7B 18 E8 ?? ?? ?? ?? EB 94 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xmalloc_04bb0429648656f16ce482bd3a3e083c {
	meta:
		aliases = "xmalloc"
		type = "func"
		size = "39"
		objfiles = "xmalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 53 B8 01 00 00 00 48 89 FB 48 0F 44 D8 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 74 02 5B C3 48 89 DF E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tdestroy_f696b196d9af439c7f86c31863e7a10d {
	meta:
		aliases = "__GI_tdestroy, tdestroy"
		type = "func"
		size = "8"
		objfiles = "tdestroy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 74 02 EB BE C3 }
	condition:
		$pattern
}

rule perror_da14ea669b179c0822a32bdf4ef9edfd {
	meta:
		aliases = "__GI_perror, perror"
		type = "func"
		size = "45"
		objfiles = "perror@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 74 0A 80 3F 00 B9 ?? ?? ?? ?? 75 08 BF ?? ?? ?? ?? 48 89 F9 48 89 FA 48 8B 3D ?? ?? ?? ?? BE ?? ?? ?? ?? 31 C0 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule unlock_stream_3113d28524a6dc671ffbb2023dead0e7 {
	meta:
		aliases = "unlock_stream"
		type = "func"
		size = "18"
		objfiles = "fopen_unlocked@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 74 0B BE 02 00 00 00 E9 ?? ?? ?? ?? 90 F3 C3 }
	condition:
		$pattern
}

rule twalk_cf1b02f211d2ca02ecacd1699bdf3fac {
	meta:
		aliases = "twalk"
		type = "func"
		size = "18"
		objfiles = "twalk@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 74 0C 48 85 F6 74 07 31 D2 E9 7B FF FF FF C3 }
	condition:
		$pattern
}

rule cplus_demangle_fill_ctor_474b8a7d9b10a7f40815783643ded99d {
	meta:
		aliases = "cplus_demangle_fill_ctor"
		type = "func"
		size = "35"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 74 1B 48 85 D2 74 16 C7 07 06 00 00 00 89 77 08 B8 01 00 00 00 48 89 57 10 C3 0F 1F 00 31 C0 C3 }
	condition:
		$pattern
}

rule cplus_demangle_fill_dtor_a98d243a906881e26408cfef171e16e3 {
	meta:
		aliases = "cplus_demangle_fill_dtor"
		type = "func"
		size = "35"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 74 1B 48 85 D2 74 16 C7 07 07 00 00 00 89 77 08 B8 01 00 00 00 48 89 57 10 C3 0F 1F 00 31 C0 C3 }
	condition:
		$pattern
}

rule cplus_demangle_fill_extended_o_b26e2088e565bc3001b30a0612244084 {
	meta:
		aliases = "cplus_demangle_fill_extended_operator"
		type = "func"
		size = "51"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 74 2B 89 F0 C1 E8 1F 84 C0 75 22 48 85 D2 74 1D C7 07 29 00 00 00 89 77 08 B8 01 00 00 00 48 89 57 10 C3 66 2E 0F 1F 84 00 00 00 00 00 31 C0 C3 }
	condition:
		$pattern
}

rule __register_frame_info_bases_80da2f5d450bdbd230daacf71f857ec7 {
	meta:
		aliases = "__register_frame_info_bases"
		type = "func"
		size = "66"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 74 3B 44 8B 0F 45 85 C9 74 33 48 8B 05 ?? ?? ?? ?? 48 C7 46 20 00 00 00 00 48 89 7E 18 66 81 4E 20 F8 07 48 C7 06 FF FF FF FF 48 89 56 08 48 89 46 28 48 89 4E 10 48 89 35 ?? ?? ?? ?? F3 C3 }
	condition:
		$pattern
}

rule dirname_2d1bb4698cb857e16569c01c17d0cf7a {
	meta:
		aliases = "dirname"
		type = "func"
		size = "100"
		objfiles = "dirname@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 74 56 48 89 F9 48 89 FE EB 07 48 8D 41 01 48 89 C1 8A 01 84 C0 74 04 3C 2F 75 EF 48 89 C8 EB 03 48 FF C0 8A 10 80 FA 2F 74 F6 84 D2 74 05 48 89 CE EB DB 48 39 FE 75 1B 80 3F 2F 75 1B 80 7F 01 2F 48 8D 77 01 75 0C 80 7F 02 00 48 8D 47 02 48 0F 44 F0 C6 06 00 EB 05 BF ?? ?? ?? ?? 48 89 F8 C3 }
	condition:
		$pattern
}

rule mbsinit_ddf4b14d9852b10166004b404905a83d {
	meta:
		aliases = "__GI_mbsinit, mbsinit"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "15"
		objfiles = "gthr_gnat@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) 89 3D ?? ?? ?? ?? 48 89 35 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __multi3_34863a0a3f056de2265eaa8d2bfd39e8 {
	meta:
		aliases = "__multi3"
		type = "func"
		size = "194"
		objfiles = "_muldi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 54 24 D8 4C 8B 44 24 D8 48 89 7C 24 E8 4C 8B 4C 24 E8 48 89 74 24 F0 48 89 4C 24 E0 4C 89 C2 4C 89 C0 83 E2 FF 4C 89 C9 4C 89 CE 48 C1 E8 20 83 E1 FF 48 C1 EE 20 48 89 D7 48 0F AF F9 48 0F AF D6 48 0F AF C8 48 0F AF F0 48 8D 0C 0A 48 89 F8 48 C1 E8 20 48 01 C1 48 39 CA 76 0D 48 B8 00 00 00 00 01 00 00 00 48 01 C6 48 89 C8 83 E1 FF 83 E7 FF 48 C1 E8 20 48 C1 E1 20 48 8D 04 06 4C 0F AF 4C 24 E0 4C 0F AF 44 24 F0 48 89 44 24 C0 48 8D 04 39 48 8B 54 24 C0 48 89 44 24 B8 48 8B 44 24 B8 48 89 54 24 D0 48 89 44 24 C8 4B 8D 04 01 48 01 44 24 D0 48 8B 44 24 C8 48 8B 54 24 D0 C3 }
	condition:
		$pattern
}

rule __udivmodti4_b54826861702f4857eb1e18d260ee55c {
	meta:
		aliases = "__udivmodti4"
		type = "func"
		size = "1702"
		objfiles = "_udivmoddi4@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 D0 48 89 6C 24 D8 4C 89 C5 4C 89 64 24 E0 4C 89 6C 24 E8 4C 89 74 24 F0 4C 89 7C 24 F8 48 83 EC 10 48 89 74 24 D0 48 89 4C 24 C0 48 8B 74 24 C0 48 89 7C 24 C8 48 89 54 24 B8 4C 8B 44 24 C8 4C 8B 4C 24 B8 4C 8B 54 24 D0 48 85 F6 0F 85 3A 01 00 00 4D 39 D1 0F 86 F2 01 00 00 BA 38 00 00 00 4C 89 CE 89 D1 48 D3 EE 40 84 F6 75 09 48 83 EA 08 75 ED 4C 89 CE B8 40 00 00 00 48 29 D0 48 8B 15 ?? ?? ?? ?? 49 89 C5 0F B6 14 32 49 29 D5 74 26 44 89 E9 4C 89 C6 4C 89 D0 49 D3 E1 B9 40 00 00 00 44 29 E9 48 D3 EE 44 89 E9 48 D3 E0 49 89 F2 49 D3 E0 49 09 C2 4C 89 CE 31 D2 4C 89 D0 48 C1 EE 20 4D }
	condition:
		$pattern
}

rule __divti3_c531909ad294bce2e2df56f968977054 {
	meta:
		aliases = "__divti3"
		type = "func"
		size = "1571"
		objfiles = "_divdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 D0 4C 89 6C 24 E8 45 31 ED 48 89 6C 24 D8 4C 89 64 24 E0 49 89 D0 4C 89 74 24 F0 4C 89 7C 24 F8 48 83 EC 10 48 89 74 24 D0 48 83 7C 24 D0 00 49 89 C9 48 89 F8 48 89 F2 48 89 7C 24 C8 4C 89 44 24 B8 48 89 4C 24 C0 0F 88 26 03 00 00 48 83 7C 24 C0 00 0F 88 F8 02 00 00 48 8B 54 24 D0 48 8B 44 24 C8 48 89 54 24 B0 48 8B 54 24 C0 48 89 44 24 A8 48 8B 44 24 B8 48 8B 5C 24 A8 4C 8B 44 24 B0 48 89 54 24 A0 48 8B 74 24 A0 48 89 44 24 98 48 8B 7C 24 98 48 85 F6 0F 85 0E 01 00 00 4C 39 C7 0F 86 5A 01 00 00 BA 38 00 00 00 48 89 FE 89 D1 48 D3 EE 40 84 F6 75 09 48 83 EA 08 75 ED 48 89 FE B8 40 }
	condition:
		$pattern
}

rule read_encoded_value_with_base_21547f89ca3ebc7f8b7366e2a1eac216 {
	meta:
		aliases = "read_encoded_value_with_base"
		type = "func"
		size = "251"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 D8 48 89 6C 24 E0 48 89 D3 4C 89 6C 24 F0 4C 89 74 24 F8 49 89 F5 4C 89 64 24 E8 48 83 EC 38 40 80 FF 50 49 89 CE 89 FD 74 6A 44 0F B6 E7 44 89 E0 83 E0 0F 83 F8 0C 76 05 E8 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 89 C0 48 63 04 82 48 01 D0 FF E0 48 8B 13 48 8D 43 08 48 85 D2 74 17 41 83 E4 70 41 83 FC 10 4C 0F 44 EB 4C 01 EA 40 84 ED 79 03 48 8B 12 49 89 16 48 8B 5C 24 10 48 8B 6C 24 18 4C 8B 64 24 20 4C 8B 6C 24 28 4C 8B 74 24 30 48 83 C4 38 C3 48 8D 42 07 48 83 E0 F8 48 8B 10 48 83 C0 08 EB CE 48 63 13 48 8D 43 04 EB A9 48 0F BF 13 48 8D 43 02 EB 9F 48 8D 74 24 08 48 89 DF E8 E7 FC FF }
	condition:
		$pattern
}

rule fde_mixed_encoding_compare_4a4916f1aa6494198ef97515697c49c9 {
	meta:
		aliases = "fde_mixed_encoding_compare"
		type = "func"
		size = "181"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E0 4C 89 64 24 E8 48 89 F3 4C 89 6C 24 F0 4C 89 74 24 F8 48 83 EC 38 48 63 46 04 49 89 FE 48 8D 7E 04 49 89 D4 48 29 C7 E8 CF F8 FF FF 44 0F B6 E8 4C 89 F6 44 89 EF E8 C0 F6 FF FF 48 8D 53 08 48 8D 4C 24 10 48 89 C6 44 89 EF E8 FC F6 FF FF 49 63 44 24 04 49 8D 7C 24 04 49 83 C4 08 48 29 C7 E8 96 F8 FF FF 0F B6 D8 4C 89 F6 89 DF E8 89 F6 FF FF 48 8D 4C 24 08 4C 89 E2 48 89 C6 89 DF E8 C7 F6 FF FF 48 8B 54 24 08 48 39 54 24 10 B8 01 00 00 00 77 02 19 C0 48 8B 5C 24 18 4C 8B 64 24 20 4C 8B 6C 24 28 4C 8B 74 24 30 48 83 C4 38 C3 }
	condition:
		$pattern
}

rule fde_single_encoding_compare_0a3dda6eebaf1c3773514f7d193de8f6 {
	meta:
		aliases = "fde_single_encoding_compare"
		type = "func"
		size = "161"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E0 4C 89 64 24 E8 48 89 FB 4C 89 6C 24 F0 4C 89 74 24 F8 48 83 EC 38 0F B7 7F 20 49 89 F5 48 89 DE 49 89 D4 49 83 C4 08 66 C1 EF 03 40 0F B6 FF E8 77 FE FF FF 0F B7 7B 20 48 8D 4C 24 10 49 8D 55 08 48 89 C6 49 89 C6 66 C1 EF 03 40 0F B6 FF E8 A7 FE FF FF 0F B7 7B 20 48 8D 4C 24 08 4C 89 E2 4C 89 F6 66 C1 EF 03 40 0F B6 FF E8 8B FE FF FF 48 8B 54 24 08 48 39 54 24 10 B8 01 00 00 00 77 02 19 C0 48 8B 5C 24 18 4C 8B 64 24 20 4C 8B 6C 24 28 4C 8B 74 24 30 48 83 C4 38 C3 }
	condition:
		$pattern
}

rule __floatuntixf_757fef68cc5ed408145f9e60f2077628 {
	meta:
		aliases = "__floatuntixf"
		type = "func"
		size = "69"
		objfiles = "_floatundixf@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 74 24 80 48 85 F6 49 89 F8 DF 6C 24 80 78 1F D9 05 ?? ?? ?? ?? 4C 89 44 24 80 4D 85 C0 DC C9 DF 6C 24 80 78 19 DD D9 DE C1 C3 66 66 66 90 D9 05 ?? ?? ?? ?? DC C1 EB DD 66 66 90 66 66 90 DE C1 DE C1 C3 }
	condition:
		$pattern
}

rule __umodti3_4e4ee373dcbb20389710506d6f33a1f8 {
	meta:
		aliases = "__umodti3"
		type = "func"
		size = "1454"
		objfiles = "_umoddi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 74 24 C0 48 89 4C 24 B0 48 8B 74 24 B0 48 89 7C 24 B8 48 89 54 24 A8 48 89 5C 24 D0 48 89 6C 24 D8 4C 89 64 24 E0 48 85 F6 4C 89 6C 24 E8 4C 89 74 24 F0 4C 89 7C 24 F8 4C 8B 44 24 A8 4C 8B 54 24 B8 4C 8B 4C 24 C0 0F 85 F8 00 00 00 4D 39 C8 0F 86 8C 01 00 00 BA 38 00 00 00 66 66 90 4C 89 C6 89 D1 48 D3 EE 40 84 F6 75 09 48 83 EA 08 75 ED 4C 89 C6 B8 40 00 00 00 31 DB 48 29 D0 48 8B 15 ?? ?? ?? ?? 0F B6 14 32 48 29 D0 0F 85 08 03 00 00 4C 89 C6 31 D2 4C 89 C8 48 C1 EE 20 4D 89 C3 48 F7 F6 31 D2 41 83 E3 FF 48 89 C7 4C 89 C8 48 F7 F6 4C 89 D0 48 C1 E8 20 49 0F AF FB 48 C1 E2 20 48 09 C2 48 }
	condition:
		$pattern
}

rule __ucmpti2_a5e9b3c6d4a8cd6fd241d6edb5d54075 {
	meta:
		aliases = "__ucmpti2"
		type = "func"
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
		type = "func"
		size = "71"
		objfiles = "_cmpdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 74 24 F0 48 89 4C 24 E0 48 8B 44 24 E0 48 39 44 24 F0 48 89 7C 24 E8 48 89 54 24 D8 7C 18 7F 10 48 8B 44 24 D8 48 39 44 24 E8 72 0A 66 90 76 0F B8 02 00 00 00 C3 31 C0 66 66 90 66 66 90 C3 B8 01 00 00 00 C3 }
	condition:
		$pattern
}

rule __clzti2_c22f2aff2b8a62abc30908d0283069ba {
	meta:
		aliases = "__clzti2"
		type = "func"
		size = "82"
		objfiles = "_clzdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 74 24 F0 48 8B 44 24 F0 31 F6 48 89 7C 24 E8 48 85 C0 75 08 48 8B 44 24 E8 40 B6 40 BA 38 00 00 00 48 89 C7 89 D1 48 D3 EF 40 84 FF 75 09 48 83 EA 08 75 ED 48 89 C7 B8 40 00 00 00 48 29 D0 48 8B 15 ?? ?? ?? ?? 0F B6 14 3A 48 29 D0 01 F0 C3 }
	condition:
		$pattern
}

rule munge_stream_7e820b17d8ecd21521f198c54b90553d {
	meta:
		aliases = "munge_stream"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "58"
		objfiles = "_negdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 7C 24 E8 48 89 74 24 F0 31 C0 48 8B 4C 24 E8 48 8B 54 24 F0 48 F7 DA 48 85 C9 0F 95 C0 48 F7 D9 48 29 C2 48 89 4C 24 D8 48 8B 44 24 D8 48 89 54 24 E0 48 8B 54 24 E0 C3 }
	condition:
		$pattern
}

rule __parityti2_eb6fcc642c81bc0721c0a79bdc4cc7c1 {
	meta:
		aliases = "__parityti2"
		type = "func"
		size = "74"
		objfiles = "_paritydi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 7C 24 E8 48 89 74 24 F0 48 8B 44 24 E8 48 33 44 24 F0 48 89 C2 48 C1 EA 20 48 31 C2 48 89 D0 48 C1 E8 10 48 31 D0 48 89 C2 48 C1 EA 08 48 31 C2 B8 96 69 00 00 48 89 D1 48 C1 E9 04 48 31 D1 83 E1 0F D3 F8 83 E0 01 C3 }
	condition:
		$pattern
}

rule __ctzti2_1a79380eacb7a9befbb55d774f82ec9a {
	meta:
		aliases = "__ctzti2"
		type = "func"
		size = "86"
		objfiles = "_ctzdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 7C 24 E8 48 8B 54 24 E8 48 89 74 24 F0 31 F6 48 85 D2 75 08 48 8B 54 24 F0 40 B6 40 48 89 D0 B9 38 00 00 00 48 F7 D8 48 21 D0 66 66 66 90 48 89 C2 48 D3 EA 84 D2 75 09 48 83 E9 08 75 F0 48 89 C2 48 8B 05 ?? ?? ?? ?? 0F B6 04 10 48 8D 44 01 FF 01 F0 C3 }
	condition:
		$pattern
}

rule __ffsti2_632556634212eecae50289b40a56ceaa {
	meta:
		aliases = "__ffsti2"
		type = "func"
		size = "92"
		objfiles = "_ffsdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 7C 24 E8 48 8B 54 24 E8 48 89 74 24 F0 31 F6 48 85 D2 75 0F 48 8B 54 24 F0 31 C0 48 85 D2 74 38 40 B6 40 48 89 D0 B9 38 00 00 00 48 F7 D8 48 21 D0 48 89 C2 48 D3 EA 84 D2 75 09 48 83 E9 08 75 F0 48 89 C2 48 8B 05 ?? ?? ?? ?? 0F B6 04 10 48 8D 44 01 FF 8D 44 30 01 F3 C3 }
	condition:
		$pattern
}

rule vsprintf_0172a0c322275275ed00c0a3a2c8a2f5 {
	meta:
		aliases = "vsprintf"
		type = "func"
		size = "15"
		objfiles = "vsprintf@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 D1 48 89 F2 48 83 CE FF E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule splay_tree_foreach_2c82552e5a8d0fc5f912527f9f587cc9 {
	meta:
		aliases = "splay_tree_foreach"
		type = "func"
		size = "14"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 D1 48 89 F2 48 8B 37 E9 C2 FA FF FF }
	condition:
		$pattern
}

rule __ashlti3_03c02c66c68c491c32ae13b2b3532d28 {
	meta:
		aliases = "__ashlti3"
		type = "func"
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
		type = "func"
		size = "124"
		objfiles = "_lshrdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 D1 48 89 F8 48 89 F2 48 85 C9 74 4A 48 89 74 24 F0 BE 40 00 00 00 48 89 7C 24 E8 48 29 CE 48 85 F6 7E 3B 48 8B 54 24 F0 89 CF 48 89 D0 48 D3 E8 89 F1 48 89 44 24 E0 48 8B 44 24 E8 48 D3 E2 89 F9 48 D3 E8 48 09 C2 48 89 54 24 D8 48 8B 44 24 D8 48 8B 54 24 E0 F3 C3 66 66 90 66 66 90 48 8B 44 24 F0 89 F1 48 C7 44 24 E0 00 00 00 00 F7 D9 48 D3 E8 48 89 44 24 D8 EB D2 }
	condition:
		$pattern
}

rule __ashrti3_fed3d6e98ba0d42b92a9348a1369fe1f {
	meta:
		aliases = "__ashrti3"
		type = "func"
		size = "127"
		objfiles = "_ashrdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 D1 48 89 F8 48 89 F2 48 85 C9 74 4A 48 89 74 24 F0 BE 40 00 00 00 48 89 7C 24 E8 48 29 CE 48 85 F6 7E 3B 48 8B 54 24 F0 89 CF 48 89 D0 48 D3 F8 89 F1 48 89 44 24 E0 48 8B 44 24 E8 48 D3 E2 89 F9 48 D3 E8 48 09 C2 48 89 54 24 D8 48 8B 44 24 D8 48 8B 54 24 E0 F3 C3 66 66 90 66 66 90 48 8B 44 24 F0 89 F1 F7 D9 48 89 C2 48 D3 F8 48 C1 FA 3F 48 89 44 24 D8 48 89 54 24 E0 EB CF }
	condition:
		$pattern
}

rule fibheap_replace_data_4b76da8d374a0a2d1b5f59ce097e335c {
	meta:
		aliases = "fibheap_replace_data"
		type = "func"
		size = "12"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 D1 48 8B 56 20 E9 34 FF FF FF }
	condition:
		$pattern
}

rule wait3_b5f4a25a1e560060d37f8c8e9154933e {
	meta:
		aliases = "wait3"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "30"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 89 E1 BA ?? ?? ?? ?? EB 04 48 83 C2 20 48 8B 42 10 48 39 C1 77 F3 48 3B 4A 18 72 ED C3 }
	condition:
		$pattern
}

rule __mulvdi3_300975fee83ad27be084a3a7fc092703 {
	meta:
		aliases = "__mulvdi3"
		type = "func"
		size = "38"
		objfiles = "_mulvsi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F0 48 83 EC 08 48 F7 EF 48 89 C6 48 89 F1 48 C1 F9 3F 48 39 D1 75 08 48 89 F0 48 83 C4 08 C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule bcopy_2ea944f3634d6b0e8aa45b4252edb770 {
	meta:
		aliases = "bcopy"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "20"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F0 48 8D 76 08 B9 00 04 00 00 48 89 C2 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_attr_getschedparam_8b48d1c9908f9c04e39ddcef51cfac4e {
	meta:
		aliases = "__GI_pthread_attr_getschedparam, pthread_attr_getschedparam"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "38"
		objfiles = "stpncpy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F1 49 89 F8 EB 11 8A 01 3C 01 41 88 00 48 83 D9 FF 49 FF C0 48 FF CA 48 85 D2 75 EA 48 29 F1 48 8D 04 0F C3 }
	condition:
		$pattern
}

rule strcpy_d7f2ed2a5bda2f1a4612d1410c2db50c {
	meta:
		aliases = "__GI_stpcpy, __GI_strcpy, stpcpy, strcpy"
		type = "func"
		size = "213"
		objfiles = "strcpy@libc.a, stpcpy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F1 83 E1 07 48 89 FA 74 1B F7 D9 83 C1 08 8A 06 84 C0 88 02 0F 84 B5 00 00 00 48 FF C6 48 FF C2 FF C9 75 EA 49 B8 FF FE FE FE FE FE FE FE 48 8B 06 48 83 C6 08 49 89 C1 4D 01 C1 73 7A 49 31 C1 4D 09 C1 49 FF C1 75 6F 48 89 02 48 83 C2 08 48 8B 06 48 83 C6 08 49 89 C1 4D 01 C1 73 59 49 31 C1 4D 09 C1 49 FF C1 75 4E 48 89 02 48 83 C2 08 48 8B 06 48 83 C6 08 49 89 C1 4D 01 C1 73 38 49 31 C1 4D 09 C1 49 FF C1 75 2D 48 89 02 48 83 C2 08 48 8B 06 48 83 C6 08 49 89 C1 4D 01 C1 73 17 49 31 C1 4D 09 C1 49 FF C1 75 0C 48 89 02 48 83 C2 08 E9 77 FF FF FF 88 02 84 C0 74 12 48 FF C2 88 22 84 E4 74 09 }
	condition:
		$pattern
}

rule bzero_c77613460a8ed1e083b3a6aeee9428ec {
	meta:
		aliases = "bzero"
		type = "func"
		size = "210"
		objfiles = "bzero@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F2 31 F6 48 83 FA 07 48 89 F9 76 75 49 89 F0 F7 C7 07 00 00 00 74 15 66 66 66 90 66 66 90 40 88 31 48 FF CA 48 FF C1 F6 C1 07 75 F2 48 89 D0 48 C1 E8 06 74 31 48 81 FA C0 D4 01 00 73 60 4C 89 01 4C 89 41 08 4C 89 41 10 4C 89 41 18 4C 89 41 20 4C 89 41 28 4C 89 41 30 4C 89 41 38 48 83 C1 40 48 FF C8 75 D8 83 E2 3F 48 89 D0 48 C1 E8 03 74 0C 4C 89 01 48 83 C1 08 48 FF C8 75 F4 83 E2 07 48 85 D2 74 0B 40 88 31 48 FF C1 48 FF CA 75 F5 C3 66 66 66 90 66 66 66 90 66 66 66 90 4C 0F C3 01 4C 0F C3 41 08 4C 0F C3 41 10 4C 0F C3 41 18 4C 0F C3 41 20 4C 0F C3 41 28 4C 0F C3 41 30 4C 0F C3 41 38 48 }
	condition:
		$pattern
}

rule dyn_string_prepend_cstr_cf9289c0212bde0e10f352a6426aeb45 {
	meta:
		aliases = "dyn_string_prepend_cstr"
		type = "func"
		size = "10"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F2 31 F6 E9 46 FF FF FF }
	condition:
		$pattern
}

rule dyn_string_prepend_5d2c2b5acc9d27058aeb5da880d28f94 {
	meta:
		aliases = "dyn_string_prepend"
		type = "func"
		size = "10"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F2 31 F6 E9 66 FF FF FF }
	condition:
		$pattern
}

rule mq_getattr_8f97270fe70d65399049aa745a000c2b {
	meta:
		aliases = "gmtime_r, mq_getattr"
		type = "func"
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
		type = "func"
		size = "80"
		objfiles = "_negvdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F2 48 89 FE 48 83 EC 08 48 89 D7 48 F7 DE 48 83 D7 00 48 F7 DF 48 85 D2 78 26 48 89 FA 48 C1 FA 3F 48 89 D0 48 29 F0 48 19 FA 48 89 D0 48 C1 E8 3F 84 C0 75 14 48 89 F0 48 89 FA 48 83 C4 08 C3 48 89 F8 48 C1 E8 3F EB E8 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule vwscanf_82bf1537bdb72391a082982fc38abd5f {
	meta:
		aliases = "__GI_vscanf, vprintf, vscanf, vwprintf, vwscanf"
		type = "func"
		size = "18"
		objfiles = "vwscanf@libc.a, vprintf@libc.a, vscanf@libc.a, vwprintf@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F2 48 89 FE 48 8B 3D ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mrand48_r_919a14f8f8c12efcb152a604d74ef694 {
	meta:
		aliases = "__GI_lrand48_r, drand48_r, lrand48_r, mrand48_r"
		type = "func"
		size = "11"
		objfiles = "mrand48_r@libc.a, drand48_r@libc.a, lrand48_r@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F2 48 89 FE E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pex_unix_open_read_2f3188aa3dcd3c605480ab30122b6660 {
	meta:
		aliases = "pex_unix_open_read"
		type = "func"
		size = "12"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F7 31 C0 31 F6 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pex_unix_open_write_e849bbb7c0d3a4f1f16dd4e739e103d2 {
	meta:
		aliases = "pex_unix_open_write"
		type = "func"
		size = "20"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F7 BA B6 01 00 00 BE 41 02 00 00 31 C0 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pex_unix_pipe_3d96b09e629cae87daecfec89870a4e5 {
	meta:
		aliases = "pex_unix_pipe"
		type = "func"
		size = "8"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F7 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __subvdi3_361da2be219daeec3240c66c57a4151a {
	meta:
		aliases = "__subvdi3"
		type = "func"
		size = "45"
		objfiles = "_subvsi3@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 48 83 EC 08 48 29 F0 48 85 F6 78 11 48 39 F8 0F 9F C2 84 D2 75 0F 48 83 C4 08 C3 66 90 48 39 F8 0F 9C C2 EB ED E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __negvdi2_ad744da726248d5ba54c965b66d92383 {
	meta:
		aliases = "__negvdi2"
		type = "func"
		size = "46"
		objfiles = "_negvsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 48 83 EC 08 48 F7 D8 48 85 FF 78 11 48 85 C0 0F 9F C2 84 D2 75 10 48 83 C4 08 C3 66 90 48 89 C2 48 C1 EA 3F EB EC E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule syscall_70947dd7c4abd73c48bdc7157765069c {
	meta:
		aliases = "syscall"
		type = "func"
		size = "38"
		objfiles = "syscall@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 48 89 F7 48 89 D6 48 89 CA 4D 89 C2 4D 89 C8 4C 8B 4C 24 08 0F 05 48 3D 01 F0 FF FF 0F 83 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule llabs_e5fcc2c052f3c2b52851c447d018fafb {
	meta:
		aliases = "imaxabs, labs, llabs"
		type = "func"
		size = "15"
		objfiles = "labs@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 48 99 48 89 D0 48 31 F8 48 29 D0 C3 }
	condition:
		$pattern
}

rule lldiv_5c8405b555d66cba83698ae28271fdab {
	meta:
		aliases = "imaxdiv, ldiv, lldiv"
		type = "func"
		size = "31"
		objfiles = "ldiv@libc.a, lldiv@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 48 99 48 F7 FE 48 85 FF 48 89 C1 78 0B 48 85 D2 79 06 48 FF C1 48 29 F2 48 89 C8 C3 }
	condition:
		$pattern
}

rule __paritydi2_63e3a72091ac3d5866ea36bd96093506 {
	meta:
		aliases = "__paritydi2"
		type = "func"
		size = "54"
		objfiles = "_paritysi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 48 C1 E8 20 48 31 F8 48 89 C2 48 C1 EA 10 48 31 C2 48 89 D0 48 C1 E8 08 48 31 D0 48 89 C1 48 C1 E9 04 48 31 C1 B8 96 69 00 00 83 E1 0F D3 F8 83 E0 01 C3 }
	condition:
		$pattern
}

rule difftime_e478394585231651f96291e3e251976a {
	meta:
		aliases = "difftime"
		type = "func"
		size = "90"
		objfiles = "difftime@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 49 B8 00 00 00 00 00 00 20 00 48 89 F9 48 99 49 F7 F8 48 89 C7 48 89 F0 48 99 F2 48 0F 2A C7 49 F7 F8 48 C1 E7 35 48 29 F9 F2 48 0F 2A D1 F2 48 0F 2A C8 49 89 C0 49 C1 E0 35 4C 29 C6 F2 0F 5C C1 F2 48 0F 2A CE F2 0F 59 05 ?? ?? ?? ?? F2 0F 5C D1 F2 0F 58 C2 C3 }
	condition:
		$pattern
}

rule __clzdi2_f9c99260d5c5c8d69634055f46399b55 {
	meta:
		aliases = "__clzdi2"
		type = "func"
		size = "51"
		objfiles = "_clzsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 B9 38 00 00 00 48 89 C7 48 D3 EF 40 84 FF 75 09 48 83 E9 08 75 EF 48 89 C7 48 8B 15 ?? ?? ?? ?? B8 40 00 00 00 48 29 C8 0F B6 14 3A 48 29 D0 C3 }
	condition:
		$pattern
}

rule __ctzdi2_5b6dfc3326b2fa238370ce3f216554de {
	meta:
		aliases = "__ctzdi2"
		type = "func"
		size = "52"
		objfiles = "_ctzsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 B9 38 00 00 00 48 F7 D8 48 21 F8 66 90 48 89 C2 48 D3 EA 84 D2 75 09 48 83 E9 08 75 F0 48 89 C2 48 8B 05 ?? ?? ?? ?? 0F B6 04 10 48 8D 44 01 FF C3 }
	condition:
		$pattern
}

rule wcslen_16c738783705715b51d5d3b2236f61f2 {
	meta:
		aliases = "__GI_wcslen, wcslen"
		type = "func"
		size = "22"
		objfiles = "wcslen@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 EB 04 48 83 C0 04 83 38 00 75 F7 48 29 F8 48 C1 F8 02 C3 }
	condition:
		$pattern
}

rule wcsnlen_e08849a256ada6903a580b3cf24ac432 {
	meta:
		aliases = "__GI_wcsnlen, wcsnlen"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "45"
		objfiles = "wcscspn@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F8 EB 13 44 39 C1 74 1B 48 83 C2 04 8B 0A 85 C9 75 F1 48 83 C0 04 44 8B 00 45 85 C0 74 05 48 89 F2 EB E9 48 29 F8 48 C1 F8 02 C3 }
	condition:
		$pattern
}

rule skip_d1d27f1059cae8e2d2a9ab514d5faaf0 {
	meta:
		aliases = "skip"
		type = "func"
		size = "136"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F9 31 F6 EB 73 80 FA 22 75 05 83 F6 01 EB 66 83 FE 01 75 11 80 FA 5C 75 0C 80 7F 01 22 48 8D 47 01 48 0F 44 F8 8A 07 88 01 48 FF C1 83 FE 01 74 44 80 FA 23 75 0C C6 05 ?? ?? ?? ?? 23 C6 07 00 EB 3C 0F BE C2 83 F8 09 74 0A 83 F8 20 74 05 80 FA 0A 75 21 88 15 ?? ?? ?? ?? C6 07 00 48 FF C7 8A 07 3C 09 0F BE D0 74 F4 83 FA 20 74 EF 83 FA 0A 75 0B EB E8 48 FF C7 8A 17 84 D2 75 87 48 89 F8 C6 41 FF 00 C3 }
	condition:
		$pattern
}

rule wcswcs_63ebb040054259b83ab5e3e92308c73a {
	meta:
		aliases = "wcsstr, wcswcs"
		type = "func"
		size = "47"
		objfiles = "wcsstr@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F9 48 89 F0 44 8B 00 45 85 C0 74 1D 8B 11 41 39 D0 75 0A 48 83 C0 04 48 83 C1 04 EB E7 85 D2 74 06 48 83 C7 04 EB D7 31 FF 48 89 F8 C3 }
	condition:
		$pattern
}

rule strcat_6b6d1d7f16c5fcb86b4d489c7c4bc36b {
	meta:
		aliases = "__GI_strcat, strcat"
		type = "func"
		size = "428"
		objfiles = "strcat@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F9 83 E1 07 48 89 F8 49 B8 FF FE FE FE FE FE FE FE 74 1B F7 D9 83 C1 08 80 38 00 0F 84 BA 00 00 00 48 FF C0 FF C9 75 F0 66 66 90 66 66 90 48 8B 08 48 83 C0 08 4C 89 C2 48 01 CA 73 59 48 31 CA 4C 09 C2 48 FF C2 75 4E 48 8B 08 48 83 C0 08 4C 89 C2 48 01 CA 73 3F 48 31 CA 4C 09 C2 48 FF C2 75 34 48 8B 08 48 83 C0 08 4C 89 C2 48 01 CA 73 25 48 31 CA 4C 09 C2 48 FF C2 75 1A 48 8B 08 48 83 C0 08 4C 89 C2 48 01 CA 73 0B 48 31 CA 4C 09 C2 48 FF C2 74 98 48 83 E8 08 84 C9 74 3D 48 FF C0 84 ED 74 36 48 FF C0 F7 C1 00 00 FF 00 74 2B 48 FF C0 F7 C1 00 00 00 FF 74 20 48 FF C0 48 C1 E9 20 84 C9 74 15 }
	condition:
		$pattern
}

rule strlen_b4a815cc335dce43801dc2327c45bd76 {
	meta:
		aliases = "__GI_strlen, strlen"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "29"
		objfiles = "wmemcpy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F9 EB 0F 8B 06 48 FF CA 48 83 C6 04 89 01 48 83 C1 04 48 85 D2 75 EC 48 89 F8 C3 }
	condition:
		$pattern
}

rule __absvdi2_c1a6d59b82f50054fb452942cb9a2ee5 {
	meta:
		aliases = "__absvdi2"
		type = "func"
		size = "17"
		objfiles = "_absvsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 FA 48 C1 FA 3F 48 89 D0 48 31 F8 48 29 D0 C3 }
	condition:
		$pattern
}

rule strpbrk_c96a2c5fd12666ea1d7487ae01986dff {
	meta:
		aliases = "__GI_strpbrk, strpbrk"
		type = "func"
		size = "140"
		objfiles = "strpbrk@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 FA 49 89 F8 48 81 EC 00 01 00 00 B9 20 00 00 00 48 89 E7 31 C0 FC F3 48 AB 48 89 F0 66 90 8A 08 84 C9 74 25 88 0C 0C 8A 48 01 84 C9 74 1B 88 0C 0C 8A 48 02 84 C9 74 11 88 0C 0C 8A 48 03 48 83 C0 04 88 0C 0C 84 C9 75 D5 48 8D 42 FC 90 48 83 C0 04 8A 08 38 0C 0C 74 21 8A 48 01 38 0C 0C 74 16 8A 48 02 38 0C 0C 74 0B 8A 48 03 38 0C 0C 75 DD 48 FF C0 48 FF C0 48 FF C0 48 81 C4 00 01 00 00 31 D2 08 C9 48 0F 44 C2 C3 }
	condition:
		$pattern
}

rule strcspn_828c65427d2ab8d1ebd26e6dd1999db5 {
	meta:
		aliases = "__GI_strcspn, strcspn"
		type = "func"
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
		type = "func"
		size = "135"
		objfiles = "strspn@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 FA 49 89 F8 48 81 EC 00 01 00 00 B9 20 00 00 00 48 89 E7 31 C0 FC F3 48 AB 48 89 F0 66 90 8A 08 84 C9 74 25 88 0C 0C 8A 48 01 84 C9 74 1B 88 0C 0C 8A 48 02 84 C9 74 11 88 0C 0C 8A 48 03 48 83 C0 04 88 0C 0C 84 C9 75 D5 48 8D 42 FC 90 48 83 C0 04 8A 08 84 0C 0C 74 21 8A 48 01 84 0C 0C 74 16 8A 48 02 84 0C 0C 74 0B 8A 48 03 84 0C 0C 75 DD 48 FF C0 48 FF C0 48 FF C0 48 81 C4 00 01 00 00 48 29 D0 C3 }
	condition:
		$pattern
}

rule __floattisf_ec6c010b3f28be7449d28622465324a1 {
	meta:
		aliases = "__floattidf, __floattisf"
		type = "func"
		size = "268"
		objfiles = "_floatdidf@libgcc.a, _floatdisf@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 FA 53 49 89 F3 48 C1 FA 3F 48 89 F8 49 89 FA 48 89 D1 48 31 F8 48 83 EC 10 4C 31 D9 48 09 C1 0F 84 DA 00 00 00 4C 89 D9 4C 89 D8 BA 38 00 00 00 48 C1 F9 3F 48 31 C8 48 29 C8 66 66 66 90 48 89 C6 89 D1 48 D3 EE 40 84 F6 75 09 48 83 EA 08 75 ED 48 89 C6 B8 40 00 00 00 48 29 D0 48 8B 15 ?? ?? ?? ?? 0F B6 14 32 48 29 D0 0F 84 81 00 00 00 BA 41 00 00 00 4C 89 D6 4C 89 DF 29 C2 41 B8 01 00 00 00 89 D1 4C 0F AD DE 48 D3 FF F6 C2 40 48 0F 45 F7 45 31 C9 31 D2 4D 0F A5 C1 49 D3 E0 83 E1 40 48 89 F7 4D 0F 45 C8 4C 0F 45 C2 4C 89 C0 4C 89 CA 48 83 C0 FF 48 83 D2 FF 4C 21 D0 48 83 CE 01 4C 21 DA 48 }
	condition:
		$pattern
}

rule strchr_0b20f6125c0ef68348904290c7e9108e {
	meta:
		aliases = "__GI_strchr, index, strchr"
		type = "func"
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
		type = "func"
		size = "37"
		objfiles = "wcscat@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 FA 8B 02 48 83 C2 04 85 C0 75 F6 48 83 EA 04 8B 06 48 83 C6 04 89 02 48 83 C2 04 85 C0 75 F0 48 89 F8 C3 }
	condition:
		$pattern
}

rule wcscpy_2ce3e68c723649644a313657006856e9 {
	meta:
		aliases = "__GI_wcscpy, wcscpy"
		type = "func"
		size = "23"
		objfiles = "wcscpy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 FA 8B 06 48 83 C6 04 89 02 48 83 C2 04 85 C0 75 F0 48 89 F8 C3 }
	condition:
		$pattern
}

rule wait_8c2d9f03f1cff0925ad46691eb81177e {
	meta:
		aliases = "__libc_wait, wait"
		type = "func"
		size = "15"
		objfiles = "wait@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 FE 31 C9 31 D2 83 CF FF E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule l64a_548d6cdd2790aa90cb9fc82f9d0b3e44 {
	meta:
		aliases = "l64a"
		type = "func"
		size = "65"
		objfiles = "l64a@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 89 FE B8 ?? ?? ?? ?? 83 E6 FF 74 33 EB 2D 48 89 F2 48 63 C1 FF C1 83 E2 3F 48 C1 EE 06 8A 92 ?? ?? ?? ?? 88 90 ?? ?? ?? ?? 75 E3 48 63 C1 C6 80 ?? ?? ?? ?? 00 B8 ?? ?? ?? ?? C3 31 C9 EB CF C3 }
	condition:
		$pattern
}

rule atexit_7ffba7eb313c344d61b5fed7e4507000 {
	meta:
		aliases = "atexit"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "18"
		objfiles = "isctype@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 48 63 FF 66 23 34 78 0F B7 C6 C3 }
	condition:
		$pattern
}

rule choose_tmpdir_6426190c5240271afa335c755bc42a86 {
	meta:
		aliases = "choose_tmpdir"
		type = "func"
		size = "472"
		objfiles = "make_temp_file@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 48 85 C0 74 04 F3 C3 66 90 41 54 BF ?? ?? ?? ?? 55 53 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 62 BE 07 00 00 00 48 89 C7 E8 ?? ?? ?? ?? 85 C0 75 51 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 8D 78 02 44 8D 60 01 89 C5 E8 ?? ?? ?? ?? 48 89 DE 48 89 C7 E8 ?? ?? ?? ?? C6 04 28 2F 42 C6 04 20 00 5B 5D 48 89 05 ?? ?? ?? ?? 41 5C C3 0F 1F 80 00 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C3 48 85 DB 74 26 BE 07 00 00 00 48 89 DF E8 ?? ?? ?? ?? 85 C0 75 15 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 94 66 0F 1F 84 00 00 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? }
	condition:
		$pattern
}

rule _Unwind_SjLj_Register_d100e92078824c52f174069265aa2c44 {
	meta:
		aliases = "_Unwind_SjLj_Register"
		type = "func"
		size = "18"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 48 89 07 48 89 3D ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule xre_set_syntax_26e7b8d8a92ed76c586f2e06d4795b45 {
	meta:
		aliases = "__re_set_syntax, re_set_syntax, xre_set_syntax"
		type = "func"
		size = "15"
		objfiles = "regex_old@libc.a, regex@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 48 89 3D ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __cmsg_nxthdr_d1b32be3de051d7d4734fd3370e0634e {
	meta:
		aliases = "__GI___cmsg_nxthdr, __cmsg_nxthdr"
		type = "func"
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
		type = "func"
		size = "23"
		objfiles = "insque@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 06 48 89 3E 48 85 C0 74 04 48 89 78 08 48 89 07 48 89 77 08 C3 }
	condition:
		$pattern
}

rule d_number_DOT_isra_DOT_0_5d61a7753c642c24469af354e167e206 {
	meta:
		aliases = "d_number.isra.0"
		type = "func"
		size = "101"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 07 45 31 C0 48 0F BE 08 80 F9 6E 74 41 8D 41 D0 3C 09 77 4B 48 8B 07 48 8D 50 01 31 C0 90 48 8D 04 80 48 89 17 48 83 C2 01 48 8D 44 41 D0 48 0F BE 4A FF 8D 71 D0 40 80 FE 09 76 E2 48 89 C2 48 F7 DA 45 85 C0 48 0F 45 C2 C3 0F 1F 40 00 48 8D 50 01 41 B0 01 48 89 17 48 0F BE 48 01 EB AE 31 C0 EB D9 }
	condition:
		$pattern
}

rule _Unwind_SetGR_2e812c5baa4546d2f13fd0ce5616126e {
	meta:
		aliases = "_Unwind_SetGR"
		type = "func"
		size = "12"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 07 48 63 F6 48 89 54 F0 10 C3 }
	condition:
		$pattern
}

rule _Unwind_GetGR_ea18db07665d68b999abc7097c8d70c2 {
	meta:
		aliases = "_Unwind_GetGR"
		type = "func"
		size = "12"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 07 48 63 F6 48 8B 44 F0 10 C3 }
	condition:
		$pattern
}

rule splay_tree_min_befef4efb1740cbe87a50988584a5155 {
	meta:
		aliases = "splay_tree_min"
		type = "func"
		size = "33"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 07 48 85 C0 75 0B EB 14 66 0F 1F 44 00 00 48 89 D0 48 8B 50 10 48 85 D2 75 F4 F3 C3 31 C0 C3 }
	condition:
		$pattern
}

rule splay_tree_max_03789d0585884db27e93c40ad7c7a383 {
	meta:
		aliases = "splay_tree_max"
		type = "func"
		size = "33"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 07 48 85 C0 75 0B EB 14 66 0F 1F 44 00 00 48 89 D0 48 8B 50 18 48 85 D2 75 F4 F3 C3 31 C0 C3 }
	condition:
		$pattern
}

rule _Unwind_SjLj_Unregister_e359974dff09d89cbdfc4dbad0cbc60a {
	meta:
		aliases = "_Unwind_SjLj_Unregister"
		type = "func"
		size = "11"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 07 48 89 05 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule _Unwind_GetLanguageSpecificDat_bd7ecac214d8fa05ffe6b2bb8ac0a4a8 {
	meta:
		aliases = "_Unwind_GetLanguageSpecificData"
		type = "func"
		size = "8"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 07 48 8B 40 38 C3 }
	condition:
		$pattern
}

rule _Unwind_SetIP_73a2973280719f21f1e0299b08cef355 {
	meta:
		aliases = "_Unwind_SetIP"
		type = "func"
		size = "10"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 07 83 EE 01 89 70 08 C3 }
	condition:
		$pattern
}

rule _Unwind_GetIP_e2f6559d1b1a849b913658ff53bf60cf {
	meta:
		aliases = "_Unwind_GetIP"
		type = "func"
		size = "12"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 07 8B 40 08 83 C0 01 48 98 C3 }
	condition:
		$pattern
}

rule __old_sem_getvalue_6727e01a588523c861e51753519dce55 {
	meta:
		aliases = "__old_sem_getvalue"
		type = "func"
		size = "23"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 07 A8 01 74 07 48 D1 E8 89 06 EB 06 C7 06 00 00 00 00 31 C0 C3 }
	condition:
		$pattern
}

rule _Unwind_GetIPInfo_d7af4f846b77137185b3d2292e4e436f {
	meta:
		aliases = "_Unwind_GetIPInfo"
		type = "func"
		size = "18"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 07 C7 06 00 00 00 00 8B 40 08 83 C0 01 48 98 C3 }
	condition:
		$pattern
}

rule _dl_do_lazy_reloc_eb71af634ab6cae4aa4427189708dfe7 {
	meta:
		aliases = "_dl_do_lazy_reloc"
		type = "func"
		size = "56"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 0A 48 8B 52 08 48 8B 07 85 D2 74 27 83 FA 07 75 06 48 01 04 01 EB 1C BF 01 00 00 00 B8 3C 00 00 00 0F 05 48 3D 00 F0 FF FF 76 08 F7 D8 89 05 ?? ?? ?? ?? 31 C0 C3 }
	condition:
		$pattern
}

rule dlerror_cc90449f96080985854c55261894fde0 {
	meta:
		aliases = "dlerror"
		type = "func"
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
		type = "func"
		size = "19"
		objfiles = "getpagesize@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 15 ?? ?? ?? ?? B8 00 10 00 00 48 85 D2 0F 45 C2 C3 }
	condition:
		$pattern
}

rule execv_3f0102b508291ff6fb4387d577bb9fec {
	meta:
		aliases = "__GI_execv, execv"
		type = "func"
		size = "12"
		objfiles = "execv@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 15 ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule consume_count_9420b1cef55a6d9b4b3f1a24ea1d7bb4 {
	meta:
		aliases = "consume_count"
		type = "func"
		size = "78"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 17 31 C0 0F BE 0A 48 83 C2 01 0F B6 F1 F6 84 36 ?? ?? ?? ?? 04 74 2F 0F 1F 80 00 00 00 00 8D 04 80 48 89 17 48 83 C2 01 8D 44 41 D0 0F BE 4A FF 0F B6 F1 F6 84 36 ?? ?? ?? ?? 04 75 E1 85 C0 78 05 F3 C3 0F 1F 00 B8 FF FF FF FF C3 }
	condition:
		$pattern
}

rule _Unwind_GetCFA_422647608756a0c665007d01631b2fce {
	meta:
		aliases = "_Unwind_GetCFA"
		type = "func"
		size = "16"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 17 31 C0 48 85 D2 74 04 48 8B 42 50 F3 C3 }
	condition:
		$pattern
}

rule remque_2016440df2d1734a1c49f15cc2882d80 {
	meta:
		aliases = "remque"
		type = "func"
		size = "25"
		objfiles = "remque@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 17 48 8B 47 08 48 85 D2 74 04 48 89 42 08 48 85 C0 74 03 48 89 10 C3 }
	condition:
		$pattern
}

rule consume_count_with_underscores_ffc740f948c00c615fd0a8400868a2d6 {
	meta:
		aliases = "consume_count_with_underscores"
		type = "func"
		size = "95"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 17 53 48 89 FB 0F BE 02 3C 5F 74 1A 8D 48 D0 80 F9 09 77 42 48 83 C2 01 83 E8 30 48 89 17 5B C3 66 0F 1F 44 00 00 48 8D 42 01 48 89 07 0F B6 42 01 F6 84 00 ?? ?? ?? ?? 04 74 1B E8 6E FF FF FF 48 8B 13 80 3A 5F 75 0E 48 83 C2 01 48 89 13 5B C3 0F 1F 44 00 00 B8 FF FF FF FF 5B C3 }
	condition:
		$pattern
}

rule __longjmp_f98d5651168372aaa820147f017ccadc {
	meta:
		aliases = "__GI___longjmp, __longjmp"
		type = "func"
		size = "45"
		objfiles = "__longjmp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 1F 48 8B 6F 08 4C 8B 67 10 4C 8B 6F 18 4C 8B 77 20 4C 8B 7F 28 85 F6 B8 01 00 00 00 0F 44 F0 89 F0 48 8B 57 38 48 8B 67 30 FF E2 }
	condition:
		$pattern
}

rule __popcountdi2_d4844a4f4da402283c58654c73cc96be {
	meta:
		aliases = "__popcountdi2"
		type = "func"
		size = "48"
		objfiles = "_popcountsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 35 ?? ?? ?? ?? 48 0F B6 C7 B9 08 00 00 00 0F B6 14 06 48 89 F8 48 D3 E8 83 C1 08 25 FF 00 00 00 0F B6 04 06 01 C2 83 F9 40 75 E7 89 D0 C3 }
	condition:
		$pattern
}

rule putchar_unlocked_3865cef6992aeafa2ef1c219d170caae {
	meta:
		aliases = "putchar_unlocked"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "12"
		objfiles = "putwchar_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 35 ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule alphasort64_66205ecbea46b32f5b07cd78fa3c13e8 {
	meta:
		aliases = "alphasort, alphasort64"
		type = "func"
		size = "19"
		objfiles = "alphasort64@libc.a, alphasort@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 36 48 8B 3F 48 83 C6 13 48 83 C7 13 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getchar_unlocked_1ad19b39eb90bdbbd3815a6025c5d866 {
	meta:
		aliases = "__GI_getchar_unlocked, getchar_unlocked"
		type = "func"
		size = "33"
		objfiles = "getchar_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 3D ?? ?? ?? ?? 48 8B 57 18 48 3B 57 28 72 05 E9 ?? ?? ?? ?? 0F B6 02 48 FF C2 48 89 57 18 C3 }
	condition:
		$pattern
}

rule dl_cleanup_657036a6a39d235ae9696c1aff790c86 {
	meta:
		aliases = "dl_cleanup"
		type = "func"
		size = "34"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 3D ?? ?? ?? ?? 53 EB 11 48 8B 5F 08 BE 01 00 00 00 E8 6A FD FF FF 48 89 DF 48 85 FF 75 EA 5B C3 }
	condition:
		$pattern
}

rule _dl_unmap_cache_92b1affa2342f09df2ee209661fdd996 {
	meta:
		aliases = "_dl_unmap_cache"
		type = "func"
		size = "66"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 3D ?? ?? ?? ?? 83 CA FF 48 8D 47 FF 48 83 F8 FD 77 2B 48 8B 35 ?? ?? ?? ?? B8 0B 00 00 00 0F 05 48 3D 00 F0 FF FF 76 08 F7 D8 89 05 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 31 D2 89 D0 C3 }
	condition:
		$pattern
}

rule getwchar_unlocked_59d29e9a7b0f84937a87c34da067ad94 {
	meta:
		aliases = "_dl_app_fini_array, _dl_app_init_array, getwchar, getwchar_unlocked"
		type = "func"
		size = "12"
		objfiles = "getwchar@libc.a, libdl@libdl.a, getwchar_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 3D ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _dl_parse_lazy_relocation_info_11d6b6bb2dffb1c3f26769ef0c97da40 {
	meta:
		aliases = "_dl_parse_lazy_relocation_information"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "34"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 3F 48 8B 36 31 C0 48 39 F7 74 14 48 85 FF B0 01 74 0D 83 C8 FF 48 85 F6 74 05 E9 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule htab_set_functions_ex_aafc7684d625c9c773f59e3e4230f1fe {
	meta:
		aliases = "htab_set_functions_ex"
		type = "func"
		size = "29"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 44 24 08 48 89 37 48 89 57 08 48 89 4F 10 4C 89 47 50 4C 89 4F 58 48 89 47 60 C3 }
	condition:
		$pattern
}

rule fibheap_rem_root_DOT_isra_DOT_4_0310df3ce037659b9771695997b1ed3b {
	meta:
		aliases = "fibheap_rem_root.isra.4"
		type = "func"
		size = "88"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 46 10 48 39 C6 74 47 48 8B 16 48 85 D2 74 06 48 3B 72 08 74 29 48 8B 56 18 48 89 42 10 48 8B 4E 10 48 89 51 18 48 C7 06 00 00 00 00 48 89 76 10 48 89 76 18 48 89 07 C3 66 0F 1F 44 00 00 48 89 42 08 EB D1 66 2E 0F 1F 84 00 00 00 00 00 48 C7 07 00 00 00 00 C3 }
	condition:
		$pattern
}

rule fibheap_cut_85050c6b6f25966fabbbc5c995fa8c12 {
	meta:
		aliases = "fibheap_cut"
		type = "func"
		size = "194"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 46 10 4C 8B 06 31 C9 48 39 C6 48 0F 45 C8 4D 85 C0 74 06 49 3B 70 08 74 6D 48 8B 4E 18 48 89 41 10 48 8B 46 10 48 89 48 18 8B 42 30 48 C7 06 00 00 00 00 48 89 76 10 48 89 76 18 8D 88 FF FF FF 7F 25 00 00 00 80 81 E1 FF FF FF 7F 09 C8 89 42 30 48 8B 47 10 48 85 C0 74 34 48 8B 50 18 48 39 D0 74 4B 48 89 56 18 48 8B 50 18 48 89 72 10 48 89 70 18 48 89 46 10 48 C7 06 00 00 00 00 80 66 33 7F C3 0F 1F 00 49 89 48 08 EB 8D 66 90 48 89 77 10 48 89 76 10 48 89 76 18 48 C7 06 00 00 00 00 80 66 33 7F C3 0F 1F 84 00 00 00 00 00 48 89 70 18 48 89 70 10 48 89 46 18 48 89 46 10 EB B7 }
	condition:
		$pattern
}

rule fibheap_min_key_4c971c9cc10e6bc912d1839ecd498220 {
	meta:
		aliases = "fibheap_min_key"
		type = "func"
		size = "19"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 08 48 85 C0 74 07 48 8B 40 20 C3 66 90 31 C0 C3 }
	condition:
		$pattern
}

rule fibheap_min_9acff4320e08311cadb92d1a4f2fb357 {
	meta:
		aliases = "fibheap_min"
		type = "func"
		size = "19"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 08 48 85 C0 74 07 48 8B 40 28 C3 66 90 31 C0 C3 }
	condition:
		$pattern
}

rule _Unwind_DeleteException_7778519b3c95c990f91fcd70b884a894 {
	meta:
		aliases = "_Unwind_DeleteException"
		type = "func"
		size = "25"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 08 48 85 C0 74 0E 48 89 FE 49 89 C3 BF 01 00 00 00 41 FF E3 F3 C3 }
	condition:
		$pattern
}

rule dyn_string_clear_bc1c4fd4a99ae81c55f941e0ea643756 {
	meta:
		aliases = "dyn_string_clear"
		type = "func"
		size = "15"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 08 C6 00 00 C7 47 04 00 00 00 00 C3 }
	condition:
		$pattern
}

rule _obstack_allocated_p_104a90ac69cbbd364546cf19460d588c {
	meta:
		aliases = "_obstack_allocated_p"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "8"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 18 2B 47 20 C3 }
	condition:
		$pattern
}

rule pthread_attr_getguardsize_20ccd4b78f280b75b102dc20bda271af {
	meta:
		aliases = "__pthread_attr_getguardsize, pthread_attr_getguardsize"
		type = "func"
		size = "10"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 18 48 89 06 31 C0 C3 }
	condition:
		$pattern
}

rule cplus_demangle_mangled_name_0ce36a3cd000a2ccf73acbde1ff61941 {
	meta:
		aliases = "cplus_demangle_mangled_name"
		type = "func"
		size = "43"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 18 48 8D 50 01 48 89 57 18 80 38 5F 75 17 48 8D 50 02 48 89 57 18 80 78 01 5A 75 09 E9 0C FC FF FF 0F 1F 40 00 31 C0 C3 }
	condition:
		$pattern
}

rule telldir_7a346892aa6f48c113696b74d69cab29 {
	meta:
		aliases = "htab_size, telldir"
		type = "func"
		size = "5"
		objfiles = "telldir@libc.a, hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 20 C3 }
	condition:
		$pattern
}

rule htab_elements_72e41c2da0cd9b70b565650a43a4741e {
	meta:
		aliases = "htab_elements"
		type = "func"
		size = "9"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 28 48 2B 47 30 C3 }
	condition:
		$pattern
}

rule pthread_attr_getstackaddr_eaaa7cbd5e25d2119a44a50cee592b8a {
	meta:
		aliases = "__pthread_attr_getstackaddr, pthread_attr_getstackaddr"
		type = "func"
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
		type = "func"
		size = "10"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 30 48 89 06 31 C0 C3 }
	condition:
		$pattern
}

rule floatformat_is_valid_298d5d9be03a30015a1d162453a2490f {
	meta:
		aliases = "floatformat_is_valid"
		type = "func"
		size = "6"
		objfiles = "floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 30 FF E0 }
	condition:
		$pattern
}

rule _dl_aux_init_a2de79102a49e8341db97124d5ce31ba {
	meta:
		aliases = "_dl_aux_init"
		type = "func"
		size = "23"
		objfiles = "dl_support@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 38 48 89 05 ?? ?? ?? ?? 48 8B 47 58 48 89 05 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule fde_unencoded_compare_9021564e8cd289d14806c835a4d45264 {
	meta:
		aliases = "fde_unencoded_compare"
		type = "func"
		size = "19"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 4A 08 48 39 4E 08 B8 01 00 00 00 77 02 19 C0 F3 C3 }
	condition:
		$pattern
}

rule _obstack_memory_used_ffcaffbf7fb149407c5da3d0b6568c5e {
	meta:
		aliases = "_obstack_memory_used"
		type = "func"
		size = "22"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 57 08 31 C0 EB 08 03 02 29 D0 48 8B 52 08 48 85 D2 75 F3 C3 }
	condition:
		$pattern
}

rule d_substitution_f38f6d2757660f642d8703e5fcf8103f {
	meta:
		aliases = "d_substitution"
		type = "func"
		size = "386"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 57 18 48 8D 42 01 48 89 47 18 80 3A 53 0F 85 AC 00 00 00 48 8D 42 02 48 89 47 18 0F BE 42 01 8D 48 D0 80 F9 09 77 4F 31 D2 3C 5F 0F 84 98 00 00 00 31 D2 EB 23 66 0F 1F 84 00 00 00 00 00 8D 14 D2 8D 54 90 D0 48 8B 47 18 48 8D 48 01 48 89 4F 18 0F BE 00 3C 5F 74 6E 8D 48 D0 80 F9 09 76 DE 8D 48 BF 80 F9 19 77 57 8D 14 D2 8D 54 90 C9 EB D4 0F 1F 44 00 00 3C 5F 74 AD 8D 48 BF 80 F9 19 76 AF 8B 4F 10 C1 E9 03 83 E1 01 75 11 85 F6 74 0D 0F B6 52 02 83 EA 43 80 FA 01 0F 96 C1 0F B6 C9 BA ?? ?? ?? ?? 0F 1F 84 00 00 00 00 00 38 02 74 2C 48 83 C2 38 48 81 FA ?? ?? ?? ?? 75 EF 31 C0 C3 0F 1F 40 00 }
	condition:
		$pattern
}

rule sc_getc_564898519739d0b6b51700d7dea82f20 {
	meta:
		aliases = "sc_getc"
		type = "func"
		size = "9"
		objfiles = "vfscanf@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 7F 08 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clntudp_freeres_8e364fe34886ee4810dd79ff2daf5734 {
	meta:
		aliases = "clntudp_freeres"
		type = "func"
		size = "29"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 7F 10 48 89 F1 31 C0 48 89 D6 49 89 CB C7 47 58 02 00 00 00 48 83 C7 58 41 FF E3 }
	condition:
		$pattern
}

rule clnttcp_freeres_f77fd281130ced480d4125b5cd639dba {
	meta:
		aliases = "clnttcp_freeres"
		type = "func"
		size = "29"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 7F 10 48 89 F1 31 C0 48 89 D6 49 89 CB C7 47 68 02 00 00 00 48 83 C7 68 41 FF E3 }
	condition:
		$pattern
}

rule clntunix_freeres_8e63063a6344ce5fd657966e3121c53b {
	meta:
		aliases = "clntunix_freeres"
		type = "func"
		size = "35"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 7F 10 48 89 F1 31 C0 48 89 D6 49 89 CB C7 87 C8 00 00 00 02 00 00 00 48 81 C7 C8 00 00 00 41 FF E3 }
	condition:
		$pattern
}

rule xdrstdio_destroy_600330dace8922e5147ebda0eb13424e {
	meta:
		aliases = "hasmntopt, xdrstdio_destroy"
		type = "func"
		size = "9"
		objfiles = "mntent@libc.a, xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 7F 18 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svcunix_getargs_45f8c66df50f9c6862a9b5d8d000e74d {
	meta:
		aliases = "svctcp_getargs, svcunix_getargs"
		type = "func"
		size = "22"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 7F 40 48 89 F1 31 C0 48 89 D6 49 89 CB 48 83 C7 10 41 FF E3 }
	condition:
		$pattern
}

rule svcunix_freeargs_bfa76f6750495ea9545cb3a7621092ce {
	meta:
		aliases = "svctcp_freeargs, svcunix_freeargs"
		type = "func"
		size = "29"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 7F 40 48 89 F1 31 C0 48 89 D6 49 89 CB C7 47 10 02 00 00 00 48 83 C7 10 41 FF E3 }
	condition:
		$pattern
}

rule svcudp_getargs_3d6a7f54baaa6f3415510a667650c4ab {
	meta:
		aliases = "svcudp_getargs"
		type = "func"
		size = "22"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 7F 48 48 89 F1 31 C0 48 89 D6 49 89 CB 48 83 C7 10 41 FF E3 }
	condition:
		$pattern
}

rule svcudp_freeargs_a559007cdcc7ecfcf33babb7e9e37487 {
	meta:
		aliases = "svcudp_freeargs"
		type = "func"
		size = "29"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 7F 48 48 89 F1 31 C0 48 89 D6 49 89 CB C7 47 10 02 00 00 00 48 83 C7 10 41 FF E3 }
	condition:
		$pattern
}

rule cplus_demangle_init_info_8fe0b02beb214425e95c8af6f74e9348 {
	meta:
		aliases = "cplus_demangle_init_info"
		type = "func"
		size = "64"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8D 04 17 48 89 39 89 71 10 48 89 79 18 C7 41 28 00 00 00 00 48 89 41 08 8D 04 12 89 51 3C C7 41 38 00 00 00 00 C7 41 40 00 00 00 00 89 41 2C 48 C7 41 48 00 00 00 00 C7 41 50 00 00 00 00 C3 }
	condition:
		$pattern
}

rule memrchr_b3d947f00e1ec3ce210b5df3672b90ff {
	meta:
		aliases = "__GI_memrchr, memrchr"
		type = "func"
		size = "233"
		objfiles = "memrchr@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8D 04 17 49 89 D0 EB 0F 48 FF C8 40 38 30 0F 84 D3 00 00 00 49 FF C8 4D 85 C0 74 04 A8 07 75 E8 48 89 C1 40 0F B6 C6 49 BA FF FE FE FE FE FE FE 7E 89 C2 49 B9 00 01 01 01 01 01 01 81 C1 E2 08 09 C2 48 63 D2 48 89 D0 48 C1 E0 10 48 09 D0 48 89 C7 48 C1 E7 20 48 09 C7 EB 6E 48 83 E9 08 48 89 F8 48 33 01 48 89 C2 4C 01 D0 48 F7 D2 48 31 C2 49 85 D1 74 4F 40 38 71 07 48 8D 41 07 74 67 40 38 71 06 48 8D 41 06 74 5D 40 38 71 05 48 8D 41 05 74 53 40 38 71 04 48 8D 41 04 74 49 40 38 71 03 48 8D 41 03 74 3F 40 38 71 02 48 8D 41 02 74 35 40 38 71 01 48 8D 41 01 74 2B 40 38 31 75 04 48 89 C8 C3 49 83 }
	condition:
		$pattern
}

rule wcschrnul_899b0af7a7b8b25b4c1c5c7bdbf4b697 {
	meta:
		aliases = "__GI_wcschrnul, wcschrnul"
		type = "func"
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
		type = "func"
		size = "42"
		objfiles = "memcmp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8D 4C 24 F8 48 8D 54 24 F0 48 89 7C 24 F8 48 89 74 24 F0 0F B6 31 0F B6 02 48 FF C1 48 FF C2 48 39 C6 74 EF 29 C6 89 F0 C3 }
	condition:
		$pattern
}

rule a64l_8298e4119f4b00145f73c4158e1e8c4a {
	meta:
		aliases = "a64l"
		type = "func"
		size = "56"
		objfiles = "a64l@libc.a"
	strings:
		$pattern = { ( CC | 48 ) 8D 77 06 31 D2 31 C9 0F BE 07 83 E8 2E 83 F8 4C 77 21 89 C0 8A 80 ?? ?? ?? ?? 3C 40 74 15 0F BE C0 48 FF C7 D3 E0 48 09 C2 48 39 F7 74 05 83 C1 06 EB D4 48 89 D0 C3 }
	condition:
		$pattern
}

rule hash_pointer_e271763c71d1ddf82a3be3c9b48dbbd1 {
	meta:
		aliases = "hash_pointer"
		type = "func"
		size = "7"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) C1 FF 03 89 F8 C3 }
	condition:
		$pattern
}

rule __register_frame_info_table_ba_ed13f263efe1a6e9b78ea1fb3c2af23a {
	meta:
		aliases = "__register_frame_info_table_bases"
		type = "func"
		size = "56"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 48 ) C7 46 20 00 00 00 00 80 4E 20 02 66 81 4E 20 F8 07 48 8B 05 ?? ?? ?? ?? 48 89 7E 18 48 C7 06 FF FF FF FF 48 89 56 08 48 89 46 28 48 89 4E 10 48 89 35 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule clone_fab03f1ef3b437887ae65b2b9109b701 {
	meta:
		aliases = "clone"
		type = "func"
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
		type = "func"
		size = "12"
		objfiles = "bsd_setjmp@libc.a"
	strings:
		$pattern = { ( CC | 48 ) C7 C6 01 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule memccpy_d31524f52eae078c979217f07e4199b6 {
	meta:
		aliases = "__GI_memccpy, memccpy"
		type = "func"
		size = "32"
		objfiles = "memccpy@libc.a"
	strings:
		$pattern = { ( CC | 48 ) FF C9 48 83 F9 FF 75 03 31 C0 C3 8A 06 88 07 48 FF C7 38 D0 74 05 48 FF C6 EB E4 48 89 F8 C3 }
	condition:
		$pattern
}

rule wcsrtombs_a71c9ad1c4e7d821fd1c5db72704c168 {
	meta:
		aliases = "__GI_wcsrtombs, wcsrtombs"
		type = "func"
		size = "15"
		objfiles = "wcsrtombs@libc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 C8 48 89 D1 48 83 CA FF E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule byte_compile_range_cd5be65ad11023e48f03fd4b382a5166 {
	meta:
		aliases = "byte_compile_range"
		type = "func"
		size = "194"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 49 ) 89 CA 48 8B 0E B8 0B 00 00 00 48 39 D1 0F 84 9E 00 00 00 48 8D 41 01 41 81 E0 00 00 01 00 49 83 F8 01 48 89 06 19 C0 F7 D0 83 E0 0B 4D 85 D2 0F 84 82 00 00 00 0F B6 09 40 0F B6 FF 41 0F BE 14 3A 45 0F B6 04 0A 41 39 D0 72 66 41 BB 01 00 00 00 EB 32 0F 1F 40 00 89 D0 83 C2 01 41 0F B6 34 02 48 89 F0 89 F1 44 89 DE 48 C1 E8 03 83 E1 07 83 E0 1F D3 E6 4C 01 C8 0F B6 38 09 FE 41 39 D0 40 88 30 72 2A 4D 85 D2 75 CD 89 D0 89 D1 44 89 DE C1 F8 03 83 E1 07 83 C2 01 48 98 D3 E6 4C 01 C8 0F B6 38 09 FE 41 39 D0 40 88 30 73 D7 90 31 C0 F3 C3 0F 1F 40 00 40 0F BE D7 44 0F B6 01 EB 85 }
	condition:
		$pattern
}

rule byte_compile_range_f35825660286b64b56a95b7b6f59eb0c {
	meta:
		aliases = "byte_compile_range"
		type = "func"
		size = "163"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 CB 4C 89 C1 4C 8B 06 41 BA 0B 00 00 00 49 39 D0 0F 84 87 00 00 00 81 E1 00 00 01 00 49 8D 40 01 48 83 F9 01 45 19 D2 48 89 06 41 F7 D2 41 83 E2 0B 4D 85 DB 74 14 40 0F B6 C7 41 0F BE 3C 03 41 0F B6 00 45 0F B6 04 03 EB 4E 45 0F B6 00 EB 48 4D 85 DB 40 0F B6 C7 74 09 40 0F B6 C7 41 0F B6 04 03 BA 08 00 00 00 89 D1 99 F7 F9 4D 85 DB 89 F9 48 63 F0 41 8A 14 31 74 09 40 0F B6 C7 41 0F B6 0C 03 83 E1 07 B8 01 00 00 00 FF C7 D3 E0 45 31 D2 09 D0 41 88 04 31 44 39 C7 76 B3 44 89 D0 C3 }
	condition:
		$pattern
}

rule strncasecmp_700057271fdc3082540a490339dbcb63 {
	meta:
		aliases = "__GI_strncasecmp, strncasecmp"
		type = "func"
		size = "59"
		objfiles = "strncasecmp@libc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 D0 31 C0 4D 85 C0 74 30 48 39 F7 74 1B 0F B6 07 48 8B 0D ?? ?? ?? ?? 0F BF 14 41 0F B6 06 0F BF 04 41 29 C2 89 D0 75 10 80 3F 00 74 0B 49 FF C8 48 FF C6 48 FF C7 EB CB C3 }
	condition:
		$pattern
}

rule wcsncpy_c40128ffa3cd72d1265f556545f5eb4c {
	meta:
		aliases = "wcsncpy"
		type = "func"
		size = "38"
		objfiles = "wcsncpy@libc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 D0 48 89 F9 EB 15 8B 06 48 8D 56 04 85 C0 89 01 48 0F 45 F2 48 83 C1 04 49 FF C8 4D 85 C0 75 E6 48 89 F8 C3 }
	condition:
		$pattern
}

rule sync_file_range_65fa21aacb762d3ec0e104fe321ca062 {
	meta:
		aliases = "sync_file_range"
		type = "func"
		size = "68"
		objfiles = "sync_file_range@libc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 D0 49 89 D2 48 89 F2 53 41 89 C9 49 C1 F8 20 41 83 E2 FF 48 C1 FA 20 83 E6 FF 48 63 FF B8 15 01 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule sigorset_4f5ef22d34f3589d218049520b36ee56 {
	meta:
		aliases = "sigorset"
		type = "func"
		size = "32"
		objfiles = "sigorset@libc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 D0 B9 10 00 00 00 EB 0F 48 63 D1 48 8B 04 D6 49 0B 04 D0 48 89 04 D7 FF C9 79 ED 31 C0 C3 }
	condition:
		$pattern
}

rule sigandset_7ca128ffa03349fd462024a41cad1b4a {
	meta:
		aliases = "sigandset"
		type = "func"
		size = "32"
		objfiles = "sigandset@libc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 D0 B9 10 00 00 00 EB 0F 48 63 D1 48 8B 04 D6 49 23 04 D0 48 89 04 D7 FF C9 79 ED 31 C0 C3 }
	condition:
		$pattern
}

rule memchr_37ad7984bf221489726f52111cbf7e47 {
	meta:
		aliases = "__GI_memchr, memchr"
		type = "func"
		size = "236"
		objfiles = "memchr@libc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 D0 EB 0F 40 38 37 75 04 48 89 F8 C3 49 FF C8 48 FF C7 4D 85 C0 74 06 40 F6 C7 07 75 E6 40 0F B6 C6 48 89 F9 49 BA FF FE FE FE FE FE FE 7E 89 C2 49 B9 00 01 01 01 01 01 01 81 C1 E2 08 09 C2 48 63 D2 48 89 D0 48 C1 E0 10 48 09 D0 48 89 C7 48 C1 E7 20 48 09 C7 EB 73 48 89 FA 48 33 11 48 83 C1 08 48 89 D0 4C 01 D2 48 F7 D0 48 31 D0 49 85 C1 74 54 40 38 71 F8 48 8D 41 F8 74 6C 40 38 71 F9 48 8D 50 01 74 32 40 38 71 FA 48 8D 50 02 74 28 40 38 71 FB 48 8D 50 03 74 1E 40 38 71 FC 48 8D 50 04 74 14 40 38 71 FD 48 8D 50 05 74 0A 40 38 71 FE 48 8D 50 06 75 04 48 89 D0 C3 48 83 C0 07 40 38 71 FF 74 }
	condition:
		$pattern
}

rule wcpncpy_6852a899bf9d33aeae080893db9c7ce5 {
	meta:
		aliases = "wcpncpy"
		type = "func"
		size = "46"
		objfiles = "wcpncpy@libc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 D1 48 89 F1 49 89 F8 EB 16 8B 01 48 8D 51 04 85 C0 41 89 00 48 0F 45 CA 49 83 C0 04 49 FF C9 4D 85 C9 75 E5 48 29 F1 48 8D 04 0F C3 }
	condition:
		$pattern
}

rule posix_fadvise64_a9307008d06491b3d5790cc15a139272 {
	meta:
		aliases = "posix_fadvise, posix_fadvise64"
		type = "func"
		size = "41"
		objfiles = "posix_fadvise@libc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 D2 48 89 F2 4C 63 C1 48 C1 FA 1F 48 63 FF B8 DD 00 00 00 0F 05 89 C1 89 C2 31 C0 F7 DA 81 F9 00 F0 FF FF 0F 47 C2 C3 }
	condition:
		$pattern
}

rule __subvti3_2c053f0c27233874c208d2cb34f4646e {
	meta:
		aliases = "__subvti3"
		type = "func"
		size = "82"
		objfiles = "_subvdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 F1 48 89 FE 48 83 EC 08 49 89 F8 48 29 D6 4C 89 CF 48 19 CF 48 85 C9 78 1A 4C 39 CF 7F 07 7C 25 4C 39 C6 76 20 66 66 90 66 66 90 66 66 90 E8 ?? ?? ?? ?? 4C 39 CF 7C ED 66 66 90 66 66 90 7F 05 4C 39 C6 72 E0 48 89 F0 48 89 FA 48 83 C4 08 C3 }
	condition:
		$pattern
}

rule __popcountti2_28d2d526252ac1c83bcef1dc570dc04e {
	meta:
		aliases = "__popcountti2"
		type = "func"
		size = "78"
		objfiles = "_popcountdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 F8 48 8B 3D ?? ?? ?? ?? 49 89 F1 49 0F B6 C0 53 B9 08 00 00 00 0F B6 34 07 66 66 90 66 90 4C 89 C0 4C 89 CA 4C 0F AD C8 48 D3 EA F6 C1 40 48 0F 45 C2 83 C1 08 25 FF 00 00 00 0F B6 04 07 01 C6 81 F9 80 00 00 00 75 D6 5B 89 F0 C3 }
	condition:
		$pattern
}

rule __addvti3_cbc950714db036cb4e0de17e91857d19 {
	meta:
		aliases = "__addvti3"
		type = "func"
		size = "82"
		objfiles = "_addvdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 49 ) 89 F8 49 89 F1 48 89 D6 48 83 EC 08 48 89 CF 4C 01 C6 4C 11 CF 48 85 C9 78 1A 4C 39 CF 7C 07 7F 25 4C 39 C6 73 20 66 66 90 66 66 90 66 66 90 E8 ?? ?? ?? ?? 4C 39 CF 7F ED 66 66 90 66 66 90 7C 05 4C 39 C6 77 E0 48 89 F0 48 89 FA 48 83 C4 08 C3 }
	condition:
		$pattern
}

rule _authenticate_b963dee91a146dde35d47bdc9b47b3fc {
	meta:
		aliases = "__GI__authenticate, _authenticate"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "49"
		objfiles = "signalfd@libc.a"
	strings:
		$pattern = { ( CC | 4C ) 63 D2 53 BA 08 00 00 00 48 63 FF B8 21 01 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule __mulvti3_c6f48daab25e59de07cd195e9548100e {
	meta:
		aliases = "__mulvti3"
		type = "func"
		size = "773"
		objfiles = "_mulvdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 4C ) 89 64 24 F0 4C 89 6C 24 F8 49 89 D4 48 89 5C 24 E8 48 81 EC A8 00 00 00 49 89 CD 48 89 BC 24 80 00 00 00 4C 8B 9C 24 80 00 00 00 49 89 F8 48 89 B4 24 88 00 00 00 4C 8B 94 24 88 00 00 00 49 89 F1 48 89 54 24 70 48 89 4C 24 78 4C 89 D8 48 C1 F8 3F 49 39 C2 75 4C 48 8B 74 24 70 4C 8B 44 24 78 48 89 F0 48 C1 F8 3F 49 39 C0 0F 85 E4 00 00 00 48 89 F0 49 F7 EB 48 89 C6 48 89 D7 48 8B 9C 24 90 00 00 00 4C 8B A4 24 98 00 00 00 48 89 F0 4C 8B AC 24 A0 00 00 00 48 89 FA 48 81 C4 A8 00 00 00 C3 4C 8B 64 24 70 48 8B 54 24 78 4C 89 E0 48 C1 F8 3F 48 39 C2 0F 85 56 01 00 00 31 DB 31 D2 4C 89 D8 48 89 D7 }
	condition:
		$pattern
}

rule __modti3_1709ab81a63fd6bc4fb6b04b4335eb60 {
	meta:
		aliases = "__modti3"
		type = "func"
		size = "1729"
		objfiles = "_moddi3@libgcc.a"
	strings:
		$pattern = { ( CC | 4C ) 89 6C 24 E8 4C 89 74 24 F0 49 89 D0 4C 89 7C 24 F8 48 89 5C 24 D0 49 89 C9 48 89 6C 24 D8 4C 89 64 24 E0 48 83 EC 40 48 89 34 24 48 83 3C 24 00 48 89 F8 48 89 F2 48 89 7C 24 F8 4C 89 44 24 E8 48 89 4C 24 F0 48 C7 44 24 A0 00 00 00 00 0F 88 3B 03 00 00 48 83 7C 24 F0 00 0F 88 0F 03 00 00 48 8B 14 24 48 8B 44 24 F8 4C 8D 7C 24 D8 48 89 54 24 D0 48 8B 54 24 F0 48 89 44 24 C8 48 8B 44 24 E8 4C 8B 54 24 C8 4C 8B 4C 24 D0 48 89 54 24 C0 48 8B 74 24 C0 48 89 44 24 B8 4C 8B 44 24 B8 48 85 F6 0F 85 06 01 00 00 4D 39 C8 0F 86 D3 01 00 00 BA 38 00 00 00 4C 89 C6 89 D1 48 D3 EE 40 84 F6 75 09 48 83 EA }
	condition:
		$pattern
}

rule __gcc_personality_sj0_b25fa8aea3c3432bccd961dcd249856a {
	meta:
		aliases = "__gcc_personality_sj0"
		type = "func"
		size = "565"
		objfiles = "unwind_c@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 4C ) 89 6C 24 E8 4C 89 7C 24 F8 4D 89 C5 48 89 5C 24 D0 48 89 6C 24 D8 49 89 CF 4C 89 64 24 E0 4C 89 74 24 F0 48 83 EC 58 83 EF 01 B8 03 00 00 00 74 23 48 8B 5C 24 28 48 8B 6C 24 30 4C 8B 64 24 38 4C 8B 6C 24 40 4C 8B 74 24 48 4C 8B 7C 24 50 48 83 C4 58 C3 83 E6 02 75 07 B8 08 00 00 00 EB D1 4C 89 C7 C7 44 24 24 00 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 E1 4D 85 ED 74 08 4C 89 EF E8 ?? ?? ?? ?? 0F B6 2B 48 83 C3 01 40 80 FD FF 74 7D 44 0F B6 E5 44 89 E0 83 E0 70 83 F8 20 0F 84 70 01 00 00 0F 8E 13 01 00 00 83 F8 40 0F 84 6E 01 00 00 83 F8 50 74 16 83 F8 30 66 66 90 0F 85 0A 01 00 00 4C 89 }
	condition:
		$pattern
}

rule get_count_1092c5644fdbaa29e3b1fe65a1aed0c3 {
	meta:
		aliases = "get_count"
		type = "func"
		size = "122"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 4C ) 8B 07 31 C0 41 0F BE 10 0F B6 CA F6 84 09 ?? ?? ?? ?? 04 74 53 49 8D 48 01 83 EA 30 B0 01 89 16 48 89 0F 45 0F BE 40 01 45 0F B6 C8 43 F6 84 09 ?? ?? ?? ?? 04 74 31 0F 1F 84 00 00 00 00 00 8D 04 92 48 83 C1 01 41 8D 54 40 D0 44 0F BE 01 41 0F B6 C0 F6 84 00 ?? ?? ?? ?? 04 75 E2 41 80 F8 5F B8 01 00 00 00 74 07 F3 C3 0F 1F 44 00 00 48 83 C1 01 48 89 0F 89 16 C3 }
	condition:
		$pattern
}

rule byte_insert_op1_28685403f2253015554d4955fd6f498d {
	meta:
		aliases = "byte_insert_op1"
		type = "func"
		size = "24"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 4C ) 8D 41 03 EB 0B 48 FF C9 49 FF C8 8A 01 41 88 00 48 39 F1 75 F0 EB C5 }
	condition:
		$pattern
}

rule byte_insert_op2_cd026eaa79d71dc018a162900cb75020 {
	meta:
		aliases = "byte_insert_op2"
		type = "func"
		size = "25"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 4D ) 8D 48 05 EB 0C 49 FF C8 49 FF C9 41 8A 00 41 88 01 49 39 F0 75 EF EB B9 }
	condition:
		$pattern
}

rule asinh_3a9afc2df0e77d12646c0afc4ed66601 {
	meta:
		aliases = "__GI_asinh, asinh"
		type = "func"
		size = "320"
		objfiles = "s_asinh@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 0F 28 C8 48 83 EC 30 F2 0F 11 44 24 08 48 8B 44 24 08 48 89 C3 48 C1 EB 20 89 D8 25 FF FF FF 7F 3D FF FF EF 7F 7E 09 F2 0F 58 C9 E9 06 01 00 00 3D FF FF 2F 3E 7F 19 0F 28 C1 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 0F 87 E6 00 00 00 3D 00 00 B0 41 7E 1A 0F 28 C1 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? F2 0F 58 05 ?? ?? ?? ?? E9 B6 00 00 00 0F 28 C1 3D 00 00 00 40 F2 0F 59 C1 F2 0F 11 44 24 20 7E 4C 0F 28 C1 E8 ?? ?? ?? ?? 0F 28 C8 F2 0F 10 05 ?? ?? ?? ?? F2 0F 11 4C 24 10 F2 0F 58 44 24 20 E8 ?? ?? ?? ?? F2 0F 10 4C 24 10 0F 28 D1 F2 0F 58 D1 F2 0F 58 C8 F2 0F 10 05 ?? ?? ?? ?? F2 0F 5E C1 F2 }
	condition:
		$pattern
}

rule __ieee754_sqrt_a80c5feb1f0c4d4a4d2b53054dd62118 {
	meta:
		aliases = "__ieee754_sqrt"
		type = "func"
		size = "428"
		objfiles = "e_sqrt@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 0F 28 C8 F2 0F 11 44 24 F8 48 8B 44 24 F8 48 89 C2 89 C6 48 C1 EA 20 89 D0 25 00 00 F0 7F 3D 00 00 F0 7F 75 0D F2 0F 59 C1 F2 0F 58 C8 E9 74 01 00 00 85 D2 7F 20 89 D0 25 FF FF FF 7F 09 F0 0F 84 61 01 00 00 85 D2 74 0D F2 0F 5C C9 F2 0F 5E C9 E9 50 01 00 00 41 89 D0 31 C9 41 C1 F8 14 74 0D EB 3A 89 F2 83 E9 15 C1 E6 15 C1 EA 0B 85 D2 74 F1 31 FF EB 04 01 D2 FF C7 F7 C2 00 00 10 00 74 F4 8D 47 FF 41 89 C8 B9 20 00 00 00 29 F9 41 29 C0 89 F0 D3 E8 40 88 F9 09 C2 D3 E6 45 8D 98 01 FC FF FF 81 E2 FF FF 0F 00 81 CA 00 00 10 00 41 F6 C3 01 74 0A 89 F0 01 F6 C1 E8 1F 8D 14 50 89 F0 8D 0C 36 45 31 }
	condition:
		$pattern
}

rule __ieee754_hypot_5aea7ef16064e7699f8126e9985caa3c {
	meta:
		aliases = "__ieee754_hypot"
		type = "func"
		size = "725"
		objfiles = "e_hypot@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 0F 28 D0 0F 28 C1 48 83 EC 10 0F 28 DA F2 0F 11 54 24 08 48 8B 44 24 08 F2 0F 11 44 24 08 48 C1 E8 20 89 C6 48 8B 44 24 08 81 E6 FF FF FF 7F 48 C1 E8 20 89 C1 81 E1 FF FF FF 7F 39 F1 7E 0C 89 C8 0F 28 D8 0F 28 C2 89 F1 89 C6 F2 0F 11 5C 24 08 48 8B 44 24 08 48 89 F2 48 C1 E2 20 48 89 C7 83 E7 FF 48 09 D7 48 89 CA 48 89 7C 24 08 48 C1 E2 20 F2 0F 10 4C 24 08 F2 0F 11 44 24 08 48 8B 44 24 08 0F 28 F1 49 89 C0 89 F0 41 83 E0 FF 29 C8 49 09 D0 3D 00 00 C0 03 4C 89 44 24 08 F2 0F 10 44 24 08 0F 28 E0 7E 09 F2 0F 58 C8 E9 1B 02 00 00 31 DB 81 FE 00 00 30 5F 0F 8E 8E 00 00 00 81 FE FF FF EF 7F 7E }
	condition:
		$pattern
}

rule __ieee754_sinh_14736aef47a39af459bc48f464ba4413 {
	meta:
		aliases = "__ieee754_sinh"
		type = "func"
		size = "311"
		objfiles = "e_sinh@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 0F 28 D0 48 83 EC 10 F2 0F 11 04 24 48 8B 04 24 48 C1 E8 20 89 C3 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 09 F2 0F 58 D2 E9 02 01 00 00 85 C0 79 0A F2 0F 10 05 ?? ?? ?? ?? EB 08 F2 0F 10 05 ?? ?? ?? ?? 81 FB FF FF 35 40 F2 0F 11 44 24 08 7F 74 81 FB FF FF 2F 3E 7F 19 0F 28 C2 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 0F 87 BD 00 00 00 0F 28 C2 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 FB FF FF EF 3F 0F 28 C8 F2 0F 10 1D ?? ?? ?? ?? 7F 19 0F 28 D0 F2 0F 58 D0 F2 0F 59 C1 F2 0F 58 CB F2 0F 5E C1 F2 0F 5C D0 EB 12 0F 28 C3 0F 28 D1 F2 0F 58 C1 F2 0F 5E D0 F2 0F 58 D1 F2 0F 59 54 24 08 EB 6A 81 FB }
	condition:
		$pattern
}

rule __ieee754_cosh_113c432edf22437157157ec6c3887400 {
	meta:
		aliases = "__ieee754_cosh"
		type = "func"
		size = "268"
		objfiles = "e_cosh@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 0F 28 D0 48 83 EC 10 F2 0F 11 44 24 08 48 8B 44 24 08 48 C1 E8 20 89 C3 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 0F 8F C8 00 00 00 81 FB 42 2E D6 3F 7F 36 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? F2 0F 10 0D ?? ?? ?? ?? 81 FB FF FF 7F 3C 0F 28 D0 F2 0F 58 D1 0F 8E AD 00 00 00 F2 0F 58 D2 F2 0F 59 C0 F2 0F 5E C2 0F 28 D0 EB 25 81 FB FF FF 35 40 7F 23 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? F2 0F 10 0D ?? ?? ?? ?? 0F 28 D0 F2 0F 59 D1 F2 0F 5E C8 F2 0F 58 D1 EB 71 81 FB 41 2E 86 40 7F 17 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 28 D0 F2 0F 59 15 ?? ?? ?? ?? EB 52 81 FB CD 33 86 40 F2 0F 11 44 24 08 48 8B 44 24 08 7E 0F 81 FB }
	condition:
		$pattern
}

rule __ieee754_atanh_5af366030cba2cd1057bb739cded4c8c {
	meta:
		aliases = "__ieee754_atanh"
		type = "func"
		size = "254"
		objfiles = "e_atanh@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 0F 28 D0 48 83 EC 10 F2 0F 11 44 24 08 48 8B 54 24 08 48 89 D3 89 D0 48 C1 EB 20 F7 D8 09 D0 89 D9 81 E1 FF FF FF 7F C1 E8 1F 09 C8 3D 00 00 F0 3F 76 0D F2 0F 5C D2 F2 0F 5E D2 E9 B6 00 00 00 81 F9 00 00 F0 3F 75 0D F2 0F 5E 15 ?? ?? ?? ?? E9 A1 00 00 00 81 F9 FF FF 2F 3E 7F 19 0F 28 C2 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 0F 87 80 00 00 00 F2 0F 11 54 24 08 48 8B 44 24 08 48 89 CA 48 C1 E2 20 83 E0 FF 48 09 D0 81 F9 FF FF DF 3F 48 89 44 24 08 F2 0F 10 44 24 08 0F 28 D8 0F 28 D0 F2 0F 58 D8 F2 0F 10 05 ?? ?? ?? ?? 7F 18 0F 28 CB F2 0F 5C C2 F2 0F 59 CA F2 0F 5E C8 0F 28 C3 F2 0F }
	condition:
		$pattern
}

rule mknod_3d35187dfd24f7b13da2d86b6ad6c9cd {
	meta:
		aliases = "__GI_mknod, mknod"
		type = "func"
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
		type = "func"
		size = "41"
		objfiles = "ustat@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 0F B7 FF B8 88 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule open_191fe39647f58a54091c51d5070b3ee4 {
	meta:
		aliases = "__GI___libc_open, __GI_open, __libc_open, open"
		type = "func"
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
		type = "func"
		size = "58"
		objfiles = "_READ@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 31 C0 F6 07 04 48 89 FB 75 2D 8B 7F 04 48 85 D2 48 B8 FF FF FF FF FF FF FF 7F 48 0F 48 D0 E8 ?? ?? ?? ?? 48 83 F8 00 7F 0E 75 06 66 83 0B 04 EB 06 66 83 0B 08 31 C0 5B C3 }
	condition:
		$pattern
}

rule __pthread_manager_sighandler_a1fb760c59a36a7eb37569430b36e269 {
	meta:
		aliases = "__pthread_manager_sighandler"
		type = "func"
		size = "105"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 31 D2 48 81 EC B0 00 00 00 8B 05 ?? ?? ?? ?? 85 C0 75 0C 31 D2 83 3D ?? ?? ?? ?? 00 0F 95 C2 85 D2 C7 05 ?? ?? ?? ?? 01 00 00 00 74 32 48 C7 04 24 00 00 00 00 C7 44 24 08 06 00 00 00 8B 3D ?? ?? ?? ?? BA A8 00 00 00 48 89 E6 E8 ?? ?? ?? ?? 48 FF C0 75 0A E8 ?? ?? ?? ?? 83 38 04 74 DE 48 81 C4 B0 00 00 00 5B C3 }
	condition:
		$pattern
}

rule gethostid_391981d4030f2af3920cc56a1d9af35f {
	meta:
		aliases = "gethostid"
		type = "func"
		size = "226"
		objfiles = "hostid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 31 F6 31 C0 BF ?? ?? ?? ?? 48 81 EC 10 02 00 00 E8 ?? ?? ?? ?? 85 C0 89 C3 78 31 48 8D B4 24 0C 02 00 00 BA 04 00 00 00 89 C7 E8 ?? ?? ?? ?? 48 85 C0 0F 84 94 00 00 00 89 DF E8 ?? ?? ?? ?? 48 63 84 24 0C 02 00 00 E9 8C 00 00 00 48 8D 9C 24 80 01 00 00 BE 40 00 00 00 48 89 DF E8 ?? ?? ?? ?? 85 C0 78 63 80 BC 24 80 01 00 00 00 74 59 48 8D B4 24 D0 01 00 00 4C 8D 8C 24 FC 01 00 00 4C 8D 84 24 F0 01 00 00 48 89 E2 B9 74 01 00 00 48 89 DF E8 ?? ?? ?? ?? 48 8B 84 24 F0 01 00 00 48 85 C0 74 24 48 63 50 14 48 8B 40 18 48 8D BC 24 00 02 00 00 48 8B 30 E8 ?? ?? ?? ?? 8B 84 24 00 02 00 00 C1 C0 10 EB }
	condition:
		$pattern
}

rule pthread_kill_other_threads_np_cb8ce2760dcc0597bc952385ef2e16c8 {
	meta:
		aliases = "__pthread_kill_other_threads_np, pthread_kill_other_threads_np"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "40"
		objfiles = "umount@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 31 F6 B8 A6 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule tee_5cc011efd1ccf07c126f53d4ccd3908f {
	meta:
		aliases = "tee"
		type = "func"
		size = "46"
		objfiles = "tee@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 41 89 CA 48 63 F6 48 63 FF B8 14 01 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule vmsplice_c2028172147519b890c192d7792872bd {
	meta:
		aliases = "__GI_vmsplice, vmsplice"
		type = "func"
		size = "43"
		objfiles = "vmsplice@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 41 89 CA 48 63 FF B8 16 01 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule __syscall_mq_timedsend_40089193cb6c6f0b1b8d924bb356e6fe {
	meta:
		aliases = "__syscall_mq_timedsend"
		type = "func"
		size = "43"
		objfiles = "mq_send@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 41 89 CA 48 63 FF B8 F2 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule ioctl_c581ede6942b702024a9d00e5514dc35 {
	meta:
		aliases = "__GI_ioctl, ioctl"
		type = "func"
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
		type = "func"
		size = "38"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 53 ) 44 8B 17 48 89 FB 45 85 D2 75 04 5B C3 66 90 BF 30 00 00 00 E8 ?? ?? ?? ?? 48 89 DF 48 89 C6 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule setsockopt_444809c541432e161dd45157924fedbe {
	meta:
		aliases = "__GI_setsockopt, setsockopt"
		type = "func"
		size = "52"
		objfiles = "setsockopt@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 45 89 C0 49 89 CA 48 63 D2 48 63 F6 48 63 FF B8 36 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule splice_2aeacef70e80652a579c08d216aef544 {
	meta:
		aliases = "__GI_splice, splice"
		type = "func"
		size = "49"
		objfiles = "splice@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 45 89 C9 49 89 CA 48 63 D2 48 63 FF B8 13 01 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sendto_264c5b1d88f42958e420b7697267ce20 {
	meta:
		aliases = "__GI_sendto, __libc_sendto, sendto"
		type = "func"
		size = "46"
		objfiles = "sendto@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 45 89 C9 4C 63 D1 48 63 FF B8 2C 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule semctl_d82648993b42815c56772d7c1e32dc9a {
	meta:
		aliases = "semctl"
		type = "func"
		size = "103"
		objfiles = "semctl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 F6 48 63 FF 48 81 EC D0 00 00 00 48 8D 84 24 E0 00 00 00 48 89 4C 24 38 C7 04 24 20 00 00 00 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 48 83 C0 18 4C 8B 10 B8 42 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 48 81 C4 D0 00 00 00 5B C3 }
	condition:
		$pattern
}

rule socket_0c4184994c9caa3b374a271e11e367db {
	meta:
		aliases = "__GI_socket, socket"
		type = "func"
		size = "46"
		objfiles = "socket@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 F6 48 63 FF B8 29 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule semget_bb8ee840b416d0cbf3b1f9fda7fe47cf {
	meta:
		aliases = "semget"
		type = "func"
		size = "46"
		objfiles = "semget@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 F6 48 63 FF B8 40 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule lseek_3f65aa6662a7058346ff895ee6de7e6d {
	meta:
		aliases = "__GI___libc_lseek, __GI_lseek, __libc_lseek, lseek"
		type = "func"
		size = "43"
		objfiles = "lseek@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 FF B8 08 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule readv_9900e3226f2ea2f0202a2b88534579b7 {
	meta:
		aliases = "__libc_readv, readv"
		type = "func"
		size = "43"
		objfiles = "readv@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 FF B8 13 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule writev_ba3d3fbf98e7656548dd600bbdb4fd2d {
	meta:
		aliases = "__libc_writev, writev"
		type = "func"
		size = "43"
		objfiles = "writev@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 FF B8 14 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule shmget_3b2873860eae543fee1a3e65beb3931a {
	meta:
		aliases = "shmget"
		type = "func"
		size = "43"
		objfiles = "shmget@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 FF B8 1D 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule shmat_1c6e31e1156e0c0525a48df5eaeb07c4 {
	meta:
		aliases = "shmat"
		type = "func"
		size = "43"
		objfiles = "shmat@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 FF B8 1E 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sendmsg_fc70c4357f5f95d134db2a6802889f98 {
	meta:
		aliases = "__GI_sendmsg, __libc_sendmsg, sendmsg"
		type = "func"
		size = "43"
		objfiles = "sendmsg@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 FF B8 2E 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule recvmsg_14def53d269bb5722f34f27ad2f3ed06 {
	meta:
		aliases = "__GI_recvmsg, __libc_recvmsg, recvmsg"
		type = "func"
		size = "43"
		objfiles = "recvmsg@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 FF B8 2F 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule klogctl_a380e92963e0b8f9fbfda65da210654f {
	meta:
		aliases = "klogctl"
		type = "func"
		size = "44"
		objfiles = "klogctl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 48 63 FF B8 67 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule setpriority_9e4649b22dcc4b1ecadfb2cd025743fa {
	meta:
		aliases = "__GI_setpriority, setpriority"
		type = "func"
		size = "44"
		objfiles = "setpriority@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 89 F6 89 FF B8 8D 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule poll_8a8ff1272ec459539e5abc5a0aa49180 {
	meta:
		aliases = "__GI_poll, __libc_poll, poll"
		type = "func"
		size = "40"
		objfiles = "poll@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 B8 07 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule mprotect_311f1e6e71cb2849ff99f6ee0909c897 {
	meta:
		aliases = "mprotect"
		type = "func"
		size = "40"
		objfiles = "mprotect@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 B8 0A 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule msync_a8edd7b64285b20b8986cca3398c5ad3 {
	meta:
		aliases = "__libc_msync, msync"
		type = "func"
		size = "40"
		objfiles = "msync@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 B8 1A 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule madvise_34e4d69fd463442f1715036734f5b099 {
	meta:
		aliases = "madvise"
		type = "func"
		size = "40"
		objfiles = "madvise@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 B8 1C 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule ioperm_51b9bcde86192f4e2d8c70b9f839f552 {
	meta:
		aliases = "ioperm"
		type = "func"
		size = "40"
		objfiles = "ioperm@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 D2 B8 AD 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule fcntl64_67c3ecc77d3ef4d4bcac028181e2197e {
	meta:
		aliases = "__GI___libc_fcntl, __GI_fcntl, __GI_fcntl64, __libc_fcntl, __libc_fcntl64, fcntl, fcntl64"
		type = "func"
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
		type = "func"
		size = "44"
		objfiles = "shmctl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 48 63 FF B8 1F 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule dup2_ef2a7fc8c0d275bc740d0392ce6643b4 {
	meta:
		aliases = "__GI_dup2, dup2"
		type = "func"
		size = "43"
		objfiles = "dup2@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 48 63 FF B8 21 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule shutdown_848333efaa8fe4b23d403bbdcca16c36 {
	meta:
		aliases = "shutdown"
		type = "func"
		size = "43"
		objfiles = "shutdown@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 48 63 FF B8 30 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule listen_a5f99806bc9dc6b33609d1b4bf54c704 {
	meta:
		aliases = "__GI_listen, listen"
		type = "func"
		size = "43"
		objfiles = "listen@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 48 63 FF B8 32 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule kill_251bed10069338b67ab7fe51e00475fc {
	meta:
		aliases = "__GI_kill, kill"
		type = "func"
		size = "44"
		objfiles = "kill@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 48 63 FF B8 3E 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule msgget_fd835b313337f7a5b4154ab2b6437c80 {
	meta:
		aliases = "msgget"
		type = "func"
		size = "43"
		objfiles = "msgget@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 48 63 FF B8 44 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule msgctl_4dba53067670f43086788bd3748bf288 {
	meta:
		aliases = "msgctl"
		type = "func"
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
		type = "func"
		size = "44"
		objfiles = "flock@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 48 63 FF B8 49 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule setpgid_82e9805285ef933b881a005451075fb1 {
	meta:
		aliases = "__GI_setpgid, setpgid"
		type = "func"
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
		type = "func"
		size = "44"
		objfiles = "sched_setscheduler@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 48 63 FF B8 90 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule access_cac533f2fed59cc73ca1371306bcc1a9 {
	meta:
		aliases = "access"
		type = "func"
		size = "40"
		objfiles = "access@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 B8 15 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule umount2_2ed0463cd2e0215ac71a68091a9b1be8 {
	meta:
		aliases = "umount2"
		type = "func"
		size = "40"
		objfiles = "umount2@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 B8 A6 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule swapon_a4ef517509a2202c89b1a1ad124bfd2d {
	meta:
		aliases = "swapon"
		type = "func"
		size = "40"
		objfiles = "swapon@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 F6 B8 A7 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule read_c6e1fc2efc5cbff7a61083e904a45c10 {
	meta:
		aliases = "__GI_read, __libc_read, read"
		type = "func"
		size = "37"
		objfiles = "read@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF 31 C0 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule write_ec594c7fd2b7298dcc4d59c1b8b6133a {
	meta:
		aliases = "__GI_write, __libc_write, write"
		type = "func"
		size = "40"
		objfiles = "write@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 01 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule close_88a6d7d0f522c8d65a97dc2ff3baa692 {
	meta:
		aliases = "__GI_close, __libc_close, close"
		type = "func"
		size = "40"
		objfiles = "close@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 03 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule dup_57c74eff9b363830ff71ed95abfad1dc {
	meta:
		aliases = "dup"
		type = "func"
		size = "40"
		objfiles = "dup@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 20 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule accept_79992bb5707c48b7bc6131522c3a8b0a {
	meta:
		aliases = "__GI_accept, __libc_accept, accept"
		type = "func"
		size = "40"
		objfiles = "accept@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 2B 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule getsockname_14bfdc1ff2e6931fd550177be66a9b83 {
	meta:
		aliases = "__GI_getsockname, getsockname"
		type = "func"
		size = "40"
		objfiles = "getsockname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 33 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule getpeername_2dcd5b412ec11f24dfa8d5af5eb3a15d {
	meta:
		aliases = "getpeername"
		type = "func"
		size = "40"
		objfiles = "getpeername@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 34 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule semop_f4a34e1d2ef1d74644f2821db6c74867 {
	meta:
		aliases = "semop"
		type = "func"
		size = "40"
		objfiles = "semop@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 41 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule fsync_6d40e3beaed1392154c0d49e9c49b68a {
	meta:
		aliases = "__libc_fsync, fsync"
		type = "func"
		size = "40"
		objfiles = "fsync@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 4A 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule fdatasync_3e58988fc3824d6cf533d593f1c19279 {
	meta:
		aliases = "fdatasync"
		type = "func"
		size = "40"
		objfiles = "fdatasync@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 4B 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule ftruncate_82cd601269d41ec1af196e9b9a5472c2 {
	meta:
		aliases = "__GI_ftruncate, ftruncate"
		type = "func"
		size = "40"
		objfiles = "ftruncate@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 4D 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule fchdir_628f5e03a5d1cc322380f56452cf44d2 {
	meta:
		aliases = "__GI_fchdir, fchdir"
		type = "func"
		size = "40"
		objfiles = "fchdir@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 51 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule getrusage_ce835a60e4144b9031cbd495618aa9b4 {
	meta:
		aliases = "getrusage"
		type = "func"
		size = "40"
		objfiles = "getrusage@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 62 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule getgroups_eb2f6a1863c64c9e9f52dea41fdce090 {
	meta:
		aliases = "__GI_getgroups, getgroups"
		type = "func"
		size = "40"
		objfiles = "getgroups@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 73 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule getpgid_bdab1cdfb603fc2cd4867361bcfeb124 {
	meta:
		aliases = "getpgid"
		type = "func"
		size = "41"
		objfiles = "getpgid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 79 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule getsid_c7da010f8aeed018ff91cd751525a61a {
	meta:
		aliases = "__GI_getsid, getsid"
		type = "func"
		size = "41"
		objfiles = "getsid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 7C 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule fstatfs_af87f6abc1d4b29a536360a3decc850a {
	meta:
		aliases = "__GI___libc_fstatfs, __GI_fstatfs, __libc_fstatfs, fstatfs"
		type = "func"
		size = "40"
		objfiles = "fstatfs@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 8A 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sched_setparam_287e43a03de9ebd38f4937e71f3c5b0a {
	meta:
		aliases = "sched_setparam"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "41"
		objfiles = "sched_getscheduler@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 91 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule sched_get_priority_max_9fb3ec56c249071ae6d34552a3bf7276 {
	meta:
		aliases = "sched_get_priority_max"
		type = "func"
		size = "40"
		objfiles = "sched_get_priority_max@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 92 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sched_get_priority_min_e5dbe2e587981ade4e76b125b7244fe2 {
	meta:
		aliases = "sched_get_priority_min"
		type = "func"
		size = "40"
		objfiles = "sched_get_priority_min@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 93 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sched_rr_get_interval_22acdc576f51639dac943c7803755885 {
	meta:
		aliases = "sched_rr_get_interval"
		type = "func"
		size = "41"
		objfiles = "sched_rr_get_interval@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 94 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule mlockall_e7d890f81ff9aa019be1cf0ebe7cf631 {
	meta:
		aliases = "mlockall"
		type = "func"
		size = "40"
		objfiles = "mlockall@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 97 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule modify_ldt_cb75b6f60767e43a5bfa0fdf1b90cc73 {
	meta:
		aliases = "modify_ldt"
		type = "func"
		size = "40"
		objfiles = "modify_ldt@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 9A 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule arch_prctl_9a8a0faefb38d2760b1c60973e9c4cfc {
	meta:
		aliases = "arch_prctl"
		type = "func"
		size = "40"
		objfiles = "arch_prctl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 9E 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule iopl_ca5ffcb795454221a3ee171898a07f06 {
	meta:
		aliases = "iopl"
		type = "func"
		size = "40"
		objfiles = "iopl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 AC 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule readahead_15f6c2d54ccb2f84cd47c89b9988bb9b {
	meta:
		aliases = "readahead"
		type = "func"
		size = "42"
		objfiles = "readahead@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 BB 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule flistxattr_9090b10d5fb58ce27d735f14b62270a3 {
	meta:
		aliases = "flistxattr"
		type = "func"
		size = "40"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 C4 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule fremovexattr_b26e7171bed0d0d61413c8a560c4aa8f {
	meta:
		aliases = "fremovexattr"
		type = "func"
		size = "40"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 C7 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule epoll_create_8d6786838b0ee86b1286daaacecdaba9 {
	meta:
		aliases = "epoll_create"
		type = "func"
		size = "40"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 D5 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule clock_settime_0e2a2216c377a1e6286d14cc0f0b9361 {
	meta:
		aliases = "clock_settime"
		type = "func"
		size = "40"
		objfiles = "clock_settime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 E3 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule clock_gettime_2a8704b873b233e5d8f707876f82a23a {
	meta:
		aliases = "clock_gettime"
		type = "func"
		size = "40"
		objfiles = "clock_gettime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 E4 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule clock_getres_9dbbb812a14a591185166e2664abb7a1 {
	meta:
		aliases = "__GI_clock_getres, clock_getres"
		type = "func"
		size = "40"
		objfiles = "clock_getres@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 E5 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule mq_setattr_b8395fa812b25f337a0643a8a2d81ed6 {
	meta:
		aliases = "__GI_mq_setattr, mq_setattr"
		type = "func"
		size = "41"
		objfiles = "mq_getsetattr@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 48 63 FF B8 F5 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule _dl_map_cache_49ea0cf99ae9b7ea151f041a224faab3 {
	meta:
		aliases = "_dl_map_cache"
		type = "func"
		size = "550"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 53 ) 48 81 EC 90 00 00 00 48 8B 15 ?? ?? ?? ?? 48 83 FA FF 89 D0 0F 84 02 02 00 00 48 85 D2 0F 85 F7 01 00 00 48 89 E6 BF ?? ?? ?? ?? B8 04 00 00 00 0F 05 48 3D 00 F0 FF FF 76 0C F7 D8 89 05 ?? ?? ?? ?? 48 83 C8 FF 85 C0 0F 85 BC 01 00 00 31 D2 31 F6 BF ?? ?? ?? ?? B0 02 0F 05 48 3D 00 F0 FF FF 76 0C F7 D8 89 05 ?? ?? ?? ?? 48 83 C8 FF 85 C0 0F 88 93 01 00 00 48 8B 74 24 30 48 63 D8 45 31 C9 49 89 D8 41 BA 01 00 00 00 BA 01 00 00 00 31 FF B8 09 00 00 00 48 89 35 ?? ?? ?? ?? 0F 05 48 3D 00 F0 FF FF 76 0C F7 D8 89 05 ?? ?? ?? ?? 48 83 C8 FF 48 89 05 ?? ?? ?? ?? 48 89 DF B8 03 00 00 00 0F 05 48 3D }
	condition:
		$pattern
}

rule __pthread_initialize_manager_136f865eae79581596634891df385498 {
	meta:
		aliases = "__pthread_initialize_manager"
		type = "func"
		size = "512"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 48 81 EC C0 00 00 00 48 8B 05 ?? ?? ?? ?? C7 00 01 00 00 00 48 83 3D ?? ?? ?? ?? 00 75 05 E8 37 FE FF FF 48 8B 3D ?? ?? ?? ?? 48 8D 7C 3F E0 E8 ?? ?? ?? ?? 48 89 C2 48 89 05 ?? ?? ?? ?? 83 C8 FF 48 85 D2 0F 84 AC 01 00 00 48 8B 05 ?? ?? ?? ?? 48 8D BC 24 B0 00 00 00 48 8D 44 42 E0 48 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 FF 89 C3 75 11 48 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 F3 00 00 00 8B 05 ?? ?? ?? ?? 85 C0 0F 44 05 ?? ?? ?? ?? 85 C0 89 05 ?? ?? ?? ?? 0F 84 8B 00 00 00 8B 05 ?? ?? ?? ?? 8A 15 ?? ?? ?? ?? 08 C2 79 7B 48 8B 3D ?? ?? ?? ?? 31 F6 E8 ?? ?? ?? ?? 48 63 8C 24 B0 00 00 00 48 8B }
	condition:
		$pattern
}

rule mq_open_f3d6a30de13764dfb7382f23ff20eafb {
	meta:
		aliases = "mq_open"
		type = "func"
		size = "161"
		objfiles = "mq_open@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 48 81 EC D0 00 00 00 48 89 54 24 30 48 89 4C 24 38 80 3F 2F 74 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 71 40 F6 C6 40 75 06 31 D2 31 C0 EB 37 48 8D 84 24 E0 00 00 00 C7 04 24 18 00 00 00 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 48 83 C0 10 8B 10 48 8B 44 24 10 C7 04 24 20 00 00 00 48 83 C0 18 48 8B 00 49 89 C2 89 D2 48 63 F6 48 FF C7 B8 F0 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 48 81 C4 D0 00 00 00 5B C3 }
	condition:
		$pattern
}

rule fibheap_delete_7c89741389a23317408280be8c75d21d {
	meta:
		aliases = "fibheap_delete"
		type = "func"
		size = "48"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 7F 08 00 48 89 FB 74 1C 0F 1F 44 00 00 48 89 DF E8 18 FC FF FF 48 89 C7 E8 ?? ?? ?? ?? 48 83 7B 08 00 75 E9 48 89 DF 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fibheap_extract_min_24975e199a81bf7b75b25a903aae8f6a {
	meta:
		aliases = "fibheap_extract_min"
		type = "func"
		size = "36"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 7F 08 00 74 18 E8 83 FD FF FF 48 89 C7 48 8B 58 28 E8 ?? ?? ?? ?? 48 89 D8 5B C3 66 90 31 DB EB F5 }
	condition:
		$pattern
}

rule ppoll_48dc9c86451a508c7d63f2677beae17d {
	meta:
		aliases = "__GI_ppoll, ppoll"
		type = "func"
		size = "71"
		objfiles = "ppoll@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 10 48 85 D2 74 13 48 8B 02 48 89 04 24 48 8B 42 08 48 89 E2 48 89 44 24 08 49 89 CA B8 0F 01 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 5A 59 89 D8 5B C3 }
	condition:
		$pattern
}

rule tanh_baeea9ed930152dc7a3a0c08680a722e {
	meta:
		aliases = "__GI_tanh, tanh"
		type = "func"
		size = "237"
		objfiles = "s_tanh@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 10 F2 0F 11 44 24 08 48 8B 44 24 08 48 89 C3 48 C1 EB 20 89 D8 25 FF FF FF 7F 3D FF FF EF 7F 7E 2C 85 DB F2 0F 10 0D ?? ?? ?? ?? 78 10 0F 28 D1 F2 0F 5E D0 F2 0F 58 D1 E9 A5 00 00 00 0F 28 D1 F2 0F 5E D0 F2 0F 5C D1 E9 95 00 00 00 3D FF FF 35 40 7E 0A F2 0F 10 15 ?? ?? ?? ?? EB 78 3D FF FF 7F 3C 7F 11 0F 28 D0 F2 0F 58 15 ?? ?? ?? ?? F2 0F 59 D0 EB 6C 3D FF FF EF 3F 7E 30 E8 ?? ?? ?? ?? F2 0F 58 C0 E8 ?? ?? ?? ?? F2 0F 10 0D ?? ?? ?? ?? F2 0F 10 15 ?? ?? ?? ?? F2 0F 58 C8 F2 0F 5E D1 F2 0F 58 15 ?? ?? ?? ?? EB 29 E8 ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F 28 D0 F2 0F }
	condition:
		$pattern
}

rule __ieee754_atan2_a769eaf6102d2a887028ff618d17fa6b {
	meta:
		aliases = "__ieee754_atan2"
		type = "func"
		size = "563"
		objfiles = "e_atan2@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 10 F2 0F 11 4C 24 08 48 8B 44 24 08 F2 0F 11 44 24 08 89 C6 49 89 C1 48 8B 44 24 08 49 C1 E9 20 44 89 CF 48 89 C1 89 C2 89 F0 F7 D8 81 E7 FF FF FF 7F 48 C1 E9 20 09 F0 C1 E8 1F 09 F8 3D 00 00 F0 7F 77 1B 89 D0 41 89 C8 81 E1 FF FF FF 7F F7 D8 09 D0 C1 E8 1F 09 C8 3D 00 00 F0 7F 76 09 F2 0F 58 C1 E9 C3 01 00 00 41 8D 81 00 00 10 C0 09 F0 75 08 59 5E 5B E9 ?? ?? ?? ?? 44 89 CB 44 89 C0 C1 FB 1E C1 E8 1F 83 E3 02 09 C3 09 CA 75 18 83 FB 02 0F 84 97 00 00 00 0F 8E 8C 01 00 00 83 FB 03 0F 84 95 00 00 00 09 FE 0F 84 B7 00 00 00 81 FF 00 00 F0 7F 0F 85 A3 00 00 00 81 F9 00 00 F0 7F 75 53 }
	condition:
		$pattern
}

rule _Unwind_SjLj_Resume_cecf309da8d750cb2a30a6da6e0e50cf {
	meta:
		aliases = "_Unwind_SjLj_Resume"
		type = "func"
		size = "71"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 20 48 83 7F 10 00 48 8B 05 ?? ?? ?? ?? 48 89 44 24 10 48 89 04 24 75 14 48 89 E6 E8 3C FF FF FF 83 F8 07 74 11 E8 ?? ?? ?? ?? 66 90 48 89 E6 E8 48 FE FF FF EB EA 48 8D 7C 24 10 48 89 E6 E8 99 FF FF FF }
	condition:
		$pattern
}

rule _Unwind_SjLj_Resume_or_Rethrow_57279a9bb3ce6b85c4b22a6a51733f3f {
	meta:
		aliases = "_Unwind_SjLj_Resume_or_Rethrow"
		type = "func"
		size = "72"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 20 48 83 7F 10 00 74 24 48 8B 05 ?? ?? ?? ?? 48 89 E6 48 89 44 24 10 48 89 04 24 E8 1C FD FF FF 83 F8 07 74 12 E8 ?? ?? ?? ?? 66 90 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 48 8D 7C 24 10 48 89 E6 E8 58 FE FF FF }
	condition:
		$pattern
}

rule _Unwind_SjLj_ForcedUnwind_024499a30fe2810bddf8785ea0885796 {
	meta:
		aliases = "_Unwind_SjLj_ForcedUnwind"
		type = "func"
		size = "61"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 20 48 8B 05 ?? ?? ?? ?? 48 89 77 10 48 89 57 18 48 89 E6 48 89 44 24 10 48 89 04 24 E8 0B FE FF FF 83 F8 07 74 06 48 83 C4 20 5B C3 48 8D 7C 24 10 48 89 E6 E8 53 FF FF FF }
	condition:
		$pattern
}

rule __ieee754_j0_97a04ed11458fdd3e3f7e51cef37af28 {
	meta:
		aliases = "__ieee754_j0"
		type = "func"
		size = "621"
		objfiles = "e_j0@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 30 F2 0F 11 04 24 48 8B 04 24 48 C1 E8 20 89 C3 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 11 F2 0F 59 C0 F2 0F 10 1D ?? ?? ?? ?? E9 C8 00 00 00 E8 ?? ?? ?? ?? 81 FB FF FF FF 3F F2 0F 11 44 24 28 0F 8E 0D 01 00 00 E8 ?? ?? ?? ?? F2 0F 11 44 24 08 F2 0F 10 44 24 28 E8 ?? ?? ?? ?? F2 0F 10 4C 24 08 81 FB FF FF DF 7F F2 0F 11 44 24 10 F2 0F 58 C8 F2 0F 11 4C 24 20 7F 64 F2 0F 10 44 24 28 F2 0F 58 C0 E8 ?? ?? ?? ?? 0F 28 C8 F2 0F 10 44 24 08 66 0F 57 0D ?? ?? ?? ?? F2 0F 59 44 24 10 66 0F 2E 05 ?? ?? ?? ?? 73 20 7A 1E F2 0F 10 44 24 08 F2 0F 5C 44 24 10 F2 0F 5E C8 F2 0F 11 44 24 18 F2 0F }
	condition:
		$pattern
}

rule pex_unix_exec_child_f02debcffdd7cf4e7647c12685ec8177 {
	meta:
		aliases = "pex_unix_exec_child"
		type = "func"
		size = "669"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 40 C7 44 24 38 01 00 00 00 C7 44 24 3C 00 00 00 00 8B 44 24 3C 48 89 7C 24 18 89 74 24 14 48 89 54 24 20 48 89 4C 24 28 44 89 44 24 0C 83 F8 03 44 89 4C 24 10 7E 2C E9 38 01 00 00 8B 7C 24 38 E8 ?? ?? ?? ?? 8B 44 24 38 01 C0 89 44 24 38 8B 44 24 3C 83 C0 01 89 44 24 3C 8B 44 24 3C 83 F8 03 7F 0B E8 ?? ?? ?? ?? 85 C0 89 C3 78 CE 83 FB FF 0F 84 FD 00 00 00 85 DB 0F 85 AD 00 00 00 8B 54 24 0C 85 D2 0F 85 71 01 00 00 8B 7C 24 10 83 FF 01 74 23 BE 01 00 00 00 E8 ?? ?? ?? ?? 85 C0 0F 88 2F 01 00 00 8B 7C 24 10 E8 ?? ?? ?? ?? 85 C0 0F 88 65 01 00 00 83 7C 24 50 02 74 27 8B 7C 24 50 BE 02 }
	condition:
		$pattern
}

rule __ieee754_y1_87134c76ddf912795886e61e87f668f5 {
	meta:
		aliases = "__ieee754_y1"
		type = "func"
		size = "657"
		objfiles = "e_j1@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 50 F2 0F 11 44 24 28 48 8B 44 24 28 48 89 C2 48 C1 EA 20 89 D3 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 17 F2 0F 59 C0 F2 0F 10 25 ?? ?? ?? ?? F2 0F 58 44 24 28 E9 EC 00 00 00 09 D8 75 15 F2 0F 10 25 ?? ?? ?? ?? F2 0F 5E 25 ?? ?? ?? ?? E9 31 02 00 00 85 D2 79 0C 0F 57 E4 F2 0F 5E E4 E9 21 02 00 00 81 FB FF FF FF 3F 0F 8E 1B 01 00 00 F2 0F 10 44 24 28 E8 ?? ?? ?? ?? F2 0F 11 44 24 30 F2 0F 10 44 24 28 E8 ?? ?? ?? ?? F2 0F 11 44 24 38 81 FB FF FF DF 7F F2 0F 10 44 24 30 66 0F 57 05 ?? ?? ?? ?? F2 0F 5C 44 24 38 F2 0F 11 44 24 40 7F 5A F2 0F 10 44 24 28 F2 0F 58 C0 E8 ?? ?? ?? ?? 0F 28 }
	condition:
		$pattern
}

rule __ieee754_y0_fa56950e3ed860f0a5ae7462f68b4ddb {
	meta:
		aliases = "__ieee754_y0"
		type = "func"
		size = "664"
		objfiles = "e_j0@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 50 F2 0F 11 44 24 28 48 8B 44 24 28 48 89 C2 48 C1 EA 20 89 D3 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 17 F2 0F 59 C0 F2 0F 10 25 ?? ?? ?? ?? F2 0F 58 44 24 28 E9 EE 00 00 00 09 D8 75 15 F2 0F 10 25 ?? ?? ?? ?? F2 0F 5E 25 ?? ?? ?? ?? E9 38 02 00 00 85 D2 79 0C 0F 57 E4 F2 0F 5E E4 E9 28 02 00 00 81 FB FF FF FF 3F 0F 8E 1D 01 00 00 F2 0F 10 44 24 28 E8 ?? ?? ?? ?? F2 0F 11 44 24 30 F2 0F 10 44 24 28 E8 ?? ?? ?? ?? F2 0F 11 44 24 38 81 FB FF FF DF 7F F2 0F 10 44 24 30 F2 0F 5C 44 24 38 F2 0F 11 44 24 40 7F 64 F2 0F 10 44 24 28 F2 0F 58 C0 E8 ?? ?? ?? ?? 0F 28 C8 F2 0F 10 44 24 30 66 }
	condition:
		$pattern
}

rule __floattixf_8321e2ebc4fbbb66c08dec1d1de6eb43 {
	meta:
		aliases = "__floattixf"
		type = "func"
		size = "44"
		objfiles = "_floatdixf@libgcc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 85 FF 48 89 74 24 80 DF 6C 24 80 48 89 7C 24 80 D9 05 ?? ?? ?? ?? DC C9 DF 6C 24 80 78 06 DD D9 5B DE C1 C3 DE C1 5B DE C1 C3 }
	condition:
		$pattern
}

rule md5_buffer_230475b40968b303d100a5a96fe81af2 {
	meta:
		aliases = "md5_buffer"
		type = "func"
		size = "94"
		objfiles = "md5@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 D3 48 81 EC A0 00 00 00 48 89 E2 C7 04 24 01 23 45 67 C7 44 24 04 89 AB CD EF C7 44 24 08 FE DC BA 98 C7 44 24 0C 76 54 32 10 C7 44 24 14 00 00 00 00 C7 44 24 10 00 00 00 00 C7 44 24 18 00 00 00 00 E8 ?? ?? ?? ?? 48 89 DE 48 89 E7 E8 ?? ?? ?? ?? 48 81 C4 A0 00 00 00 5B C3 }
	condition:
		$pattern
}

rule ether_line_c356d8d78f41f8017f904c1e3cf9e1a3 {
	meta:
		aliases = "ether_line"
		type = "func"
		size = "65"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 D3 E8 BA FF FF FF 48 89 C6 83 C8 FF 48 85 F6 74 2B EB 1E 80 F9 23 74 1F 48 8B 05 ?? ?? ?? ?? 48 0F BE D1 F6 04 50 20 75 0E 88 0B 48 FF C6 48 FF C3 8A 0E 84 C9 75 DC C6 03 00 31 C0 5B C3 }
	condition:
		$pattern
}

rule tempnam_cc3fcc7c8fc0759c6b227cbda30d250e {
	meta:
		aliases = "tempnam"
		type = "func"
		size = "69"
		objfiles = "tempnam@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F1 48 89 FA BE FF 0F 00 00 48 81 EC 00 10 00 00 48 89 E7 E8 ?? ?? ?? ?? 85 C0 75 1B BE 03 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 85 C0 75 0A 48 89 E7 E8 ?? ?? ?? ?? EB 02 31 C0 48 81 C4 00 10 00 00 5B C3 }
	condition:
		$pattern
}

rule sigwait_09740d8ab1e07c170a03350c5f1149f6 {
	meta:
		aliases = "__GI_sigwait, __sigwait, sigwait"
		type = "func"
		size = "29"
		objfiles = "sigwait@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 31 F6 E8 ?? ?? ?? ?? 83 F8 FF BA 01 00 00 00 74 04 89 03 30 D2 5B 89 D0 C3 }
	condition:
		$pattern
}

rule calloc_8277459a80a66a68a7ee8fe52c1049f3 {
	meta:
		aliases = "calloc"
		type = "func"
		size = "248"
		objfiles = "calloc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 0F AF DF 48 83 EC 20 48 85 FF 74 1F 31 D2 48 89 D8 48 F7 F7 48 39 C6 74 12 31 DB E8 ?? ?? ?? ?? C7 00 0C 00 00 00 E9 BF 00 00 00 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 0F 84 82 00 00 00 48 8B 40 F8 A8 02 75 7A 48 83 E0 FC 48 8D 50 F8 48 89 D0 48 C1 E8 03 48 83 F8 09 76 0C 31 F6 48 89 DF E8 ?? ?? ?? ?? EB 59 48 83 F8 04 48 C7 03 00 00 00 00 48 C7 43 08 00 00 00 00 48 C7 43 10 00 00 00 00 76 3C 48 83 F8 06 48 C7 43 18 00 00 00 00 48 C7 43 20 00 00 00 00 76 26 48 83 F8 09 48 C7 43 28 00 00 00 00 }
	condition:
		$pattern
}

rule getpw_492ef34aed447fb9667007e61cefb34c {
	meta:
		aliases = "getpw"
		type = "func"
		size = "169"
		objfiles = "getpw@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 81 EC 60 01 00 00 48 85 F6 75 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 7E 48 8D 54 24 20 48 8D B4 24 20 01 00 00 4C 8D 84 24 58 01 00 00 B9 00 01 00 00 E8 ?? ?? ?? ?? 85 C0 75 5B 48 8B 84 24 48 01 00 00 44 8B 8C 24 34 01 00 00 BE ?? ?? ?? ?? 44 8B 84 24 30 01 00 00 48 8B 94 24 20 01 00 00 48 89 DF 48 8B 8C 24 28 01 00 00 48 89 44 24 10 48 8B 84 24 40 01 00 00 48 89 44 24 08 48 8B 84 24 38 01 00 00 48 89 04 24 31 C0 E8 ?? ?? ?? ?? 31 D2 85 C0 79 03 83 CA FF 48 81 C4 60 01 00 00 89 D0 5B C3 }
	condition:
		$pattern
}

rule adjtime_a479587a1f9795ce015b2947e8effcb6 {
	meta:
		aliases = "adjtime"
		type = "func"
		size = "222"
		objfiles = "adjtime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 81 EC D0 00 00 00 48 85 FF 74 5C 48 8B 47 08 B9 40 42 0F 00 48 99 48 F7 F9 48 89 C1 48 03 0F 48 B8 F4 5A D0 7B 63 08 00 00 48 89 D6 48 BA E8 B5 A0 F7 C6 10 00 00 48 8D 04 01 48 39 D0 76 10 E8 ?? ?? ?? ?? 83 CA FF C7 00 16 00 00 00 EB 7F 48 69 C1 40 42 0F 00 C7 04 24 01 80 00 00 48 01 F0 48 89 44 24 08 EB 07 C7 04 24 00 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 83 CA FF 85 C0 78 51 31 D2 48 85 DB 74 4A 48 8B 4C 24 08 48 85 C9 79 24 48 89 C8 BE 40 42 0F 00 48 F7 D8 48 99 48 F7 FE 48 89 C8 48 F7 DA 48 89 53 08 48 99 48 F7 FE 48 89 C1 EB 17 48 89 C8 BA 40 42 0F 00 48 89 D6 48 99 48 F7 FE 48 }
	condition:
		$pattern
}

rule xdr_u_char_a63dc7c8bfc25c9d357c28210625fa7f {
	meta:
		aliases = "xdr_u_char"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "102"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 10 48 8B 57 18 48 83 7A 68 03 48 8B 4A 58 7E 27 48 8B 42 60 48 29 C8 48 83 F8 03 7E 1A 8B 01 0F C8 48 98 48 89 06 48 83 6A 68 04 48 83 42 58 04 BA 01 00 00 00 EB 22 48 8D 74 24 0C BA 04 00 00 00 E8 E5 FE FF FF 31 D2 85 C0 74 0D 8B 44 24 0C B2 01 0F C8 48 98 48 89 03 59 5E 5B 89 D0 C3 }
	condition:
		$pattern
}

rule xdr_u_long_3c676c5e412c0c4b1381f9ab5950764c {
	meta:
		aliases = "__GI_xdr_u_long, xdr_u_long"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "87"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 10 8B 17 83 FA 01 74 23 72 0C 83 FA 02 B8 01 00 00 00 74 36 EB 32 0F BE 06 48 8D 74 24 0C 89 44 24 0C 48 8B 47 08 FF 50 48 EB 1F 48 8B 47 08 48 8D 74 24 0C FF 50 40 85 C0 74 0D 8B 44 24 0C 88 03 B8 01 00 00 00 EB 02 31 C0 41 58 41 59 5B C3 }
	condition:
		$pattern
}

rule xdr_u_int_e73e1da48c73b322ea563690d6c4b371 {
	meta:
		aliases = "__GI_xdr_u_int, xdr_u_int"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "86"
		objfiles = "xdr_float@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 10 8B 17 83 FA 01 74 24 72 0C 83 FA 02 B8 01 00 00 00 74 37 EB 33 48 63 06 48 8D 74 24 08 48 89 44 24 08 48 8B 47 08 FF 50 08 EB 1F 48 8B 47 08 48 8D 74 24 08 FF 10 85 C0 74 0E 48 8B 44 24 08 89 03 B8 01 00 00 00 EB 02 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule xdr_int_5b5e09bc85874351179c58e047393459 {
	meta:
		aliases = "__GI_xdr_int, xdr_int"
		type = "func"
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
		type = "func"
		size = "87"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 10 8B 17 83 FA 01 74 24 72 0C 83 FA 02 B8 01 00 00 00 74 38 EB 34 0F B7 06 48 8D 74 24 08 48 89 44 24 08 48 8B 47 08 FF 50 08 EB 20 48 8B 47 08 48 8D 74 24 08 FF 10 85 C0 74 0F 48 8B 44 24 08 66 89 03 B8 01 00 00 00 EB 02 31 C0 5B 5A 5B C3 }
	condition:
		$pattern
}

rule xdr_short_61c4c8dab19be5ac9ad3cd3a41b898df {
	meta:
		aliases = "__GI_xdr_short, xdr_short"
		type = "func"
		size = "88"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 10 8B 17 83 FA 01 74 25 72 0C 83 FA 02 B8 01 00 00 00 74 39 EB 35 48 0F BF 06 48 8D 74 24 08 48 89 44 24 08 48 8B 47 08 FF 50 08 EB 20 48 8B 47 08 48 8D 74 24 08 FF 10 85 C0 74 0F 48 8B 44 24 08 66 89 03 B8 01 00 00 00 EB 02 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule xdr_bool_715a9c3bdc083cb49d4f490cc8010cc3 {
	meta:
		aliases = "__GI_xdr_bool, xdr_bool"
		type = "func"
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
		type = "func"
		size = "33"
		objfiles = "ctime_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 83 EC 40 48 89 E6 E8 ?? ?? ?? ?? 48 89 DE 48 89 C7 E8 ?? ?? ?? ?? 48 83 C4 40 5B C3 }
	condition:
		$pattern
}

rule __absvti2_634dafe64c84e752dc41f42cdebfaf28 {
	meta:
		aliases = "__absvti2"
		type = "func"
		size = "28"
		objfiles = "_absvdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 48 89 F8 48 C1 FB 3F 48 89 F2 48 31 D8 48 31 DA 48 29 D8 48 19 DA 5B C3 }
	condition:
		$pattern
}

rule __stdio_seek_1e9a3845db7af5ccba11471a31ebead7 {
	meta:
		aliases = "__stdio_seek"
		type = "func"
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
		type = "func"
		size = "62"
		objfiles = "ether_addr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 BE ?? ?? ?? ?? 48 83 EC 10 0F B6 47 05 0F B6 4F 01 0F B6 17 44 0F B6 4F 03 44 0F B6 47 02 89 44 24 08 0F B6 47 04 48 89 DF 89 04 24 31 C0 E8 ?? ?? ?? ?? 5A 59 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule __glibc_strerror_r_d73082b89e1883f7c4a49a7dc2e3ef41 {
	meta:
		aliases = "__GI___glibc_strerror_r, __glibc_strerror_r"
		type = "func"
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
		type = "func"
		size = "47"
		objfiles = "auth_none@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F3 E8 ?? ?? ?? ?? 48 8B 88 B0 00 00 00 48 85 C9 74 16 48 8B 43 08 48 89 DF 8B 51 5C 5B 48 8D 71 48 4C 8B 58 18 41 FF E3 5B 31 C0 C3 }
	condition:
		$pattern
}

rule lrealpath_ad146cae67c6a27b351cdebd288a7278 {
	meta:
		aliases = "lrealpath"
		type = "func"
		size = "43"
		objfiles = "lrealpath@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 81 EC 00 10 00 00 48 89 E6 E8 ?? ?? ?? ?? 48 85 C0 48 0F 44 C3 48 89 C7 E8 ?? ?? ?? ?? 48 81 C4 00 10 00 00 5B C3 }
	condition:
		$pattern
}

rule ntp_gettime_d2224f36a1f5d4297215429f433452f0 {
	meta:
		aliases = "ntp_gettime"
		type = "func"
		size = "70"
		objfiles = "ntp_gettime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 81 EC D0 00 00 00 48 89 E7 C7 04 24 00 00 00 00 E8 ?? ?? ?? ?? 48 8B 54 24 48 48 89 13 48 8B 54 24 50 48 89 53 08 48 8B 54 24 18 48 89 53 10 48 8B 54 24 20 48 89 53 18 48 81 C4 D0 00 00 00 5B C3 }
	condition:
		$pattern
}

rule fibheap_union_55e352c7042865428664a07ab15a0206 {
	meta:
		aliases = "fibheap_union"
		type = "func"
		size = "132"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 83 EC 10 48 8B 47 10 48 85 C0 74 5F 48 8B 56 10 48 85 D2 74 30 48 8B 48 10 48 8B 7A 10 48 89 51 18 48 89 47 18 48 89 78 10 48 89 4A 10 48 8B 06 48 8B 53 08 48 01 03 48 8B 46 08 48 8B 4A 20 48 39 48 20 7C 16 48 89 F7 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 10 5B C3 0F 1F 44 00 00 48 89 43 08 EB E4 66 2E 0F 1F 84 00 00 00 00 00 48 89 74 24 08 E8 ?? ?? ?? ?? 48 8B 74 24 08 48 89 F0 EB D1 }
	condition:
		$pattern
}

rule getc_unlocked_820cb18c69c975a81fab1a5cc31ce5b4 {
	meta:
		aliases = "__GI___fgetc_unlocked, __GI_fgetc_unlocked, __GI_getc_unlocked, __fgetc_unlocked, fgetc_unlocked, getc_unlocked"
		type = "func"
		size = "222"
		objfiles = "fgetc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 83 EC 10 48 8B 47 18 48 3B 47 28 0F 82 95 00 00 00 0F B7 07 25 83 00 00 00 3D 80 00 00 00 77 12 BE 80 00 00 00 E8 ?? ?? ?? ?? 85 C0 0F 85 9E 00 00 00 8B 0B 0F B7 D1 F6 C2 02 74 1C 48 89 C8 83 E0 01 8A 54 83 40 8D 41 FF C7 43 44 00 00 00 00 66 89 03 0F B6 D2 EB 7B 48 8B 43 18 48 39 43 20 75 44 83 7B 04 FE 75 08 83 C9 04 66 89 0B EB 60 80 E6 03 74 0A BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 43 08 48 39 43 10 74 29 48 89 43 28 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 74 36 48 8B 43 20 48 89 43 28 48 8B 43 18 0F B6 10 48 FF C0 48 89 43 18 EB 21 48 8D 74 24 0F BA 01 00 00 00 48 89 DF E8 ?? ?? ?? }
	condition:
		$pattern
}

rule htab_traverse_2b729915da6b0d4bb88095d5fdc3a635 {
	meta:
		aliases = "htab_traverse"
		type = "func"
		size = "62"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 83 EC 10 48 8B 47 28 48 2B 47 30 48 C1 E0 03 48 3B 47 20 73 17 48 89 54 24 08 48 89 34 24 E8 88 F5 FF FF 48 8B 54 24 08 48 8B 34 24 48 83 C4 10 48 89 DF 5B E9 72 FF FF FF }
	condition:
		$pattern
}

rule getprotobyname_9197d2c004cca5b2b8b21cf59ad6895b {
	meta:
		aliases = "getprotobyname"
		type = "func"
		size = "52"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 83 EC 10 E8 70 FB FF FF 48 8B 15 ?? ?? ?? ?? 4C 8D 44 24 08 48 89 DF BE ?? ?? ?? ?? B9 19 11 00 00 E8 ?? ?? ?? ?? 48 8B 44 24 08 5E 5F 5B C3 }
	condition:
		$pattern
}

rule gethostbyname_14586eed00e7b34b64c625e60f15cb78 {
	meta:
		aliases = "__GI_gethostbyname, gethostbyname"
		type = "func"
		size = "53"
		objfiles = "gethostbyname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 83 EC 10 E8 ?? ?? ?? ?? 4C 8D 44 24 08 B9 F4 01 00 00 BA ?? ?? ?? ?? 48 89 DF 49 89 C1 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 44 24 08 5A 59 5B C3 }
	condition:
		$pattern
}

rule free_3611a85d818b1671f071bdcc46e38cfe {
	meta:
		aliases = "free"
		type = "func"
		size = "451"
		objfiles = "free@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 83 EC 20 48 85 FF 0F 84 AC 01 00 00 BA ?? ?? ?? ?? 48 89 E7 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4B F8 48 8B 05 ?? ?? ?? ?? 48 8D 7B F0 49 89 F9 48 89 CA 48 83 E2 FC 48 39 C2 77 2C 48 83 C8 03 48 89 05 ?? ?? ?? ?? 89 D0 C1 E8 03 83 E8 02 48 8B 14 C5 ?? ?? ?? ?? 48 89 57 10 48 89 3C C5 ?? ?? ?? ?? E9 39 01 00 00 80 E1 02 0F 85 13 01 00 00 48 83 C8 01 48 8D 34 17 48 89 05 ?? ?? ?? ?? F6 43 F8 01 4C 8B 5E 08 75 2C 4C 8B 53 F0 48 89 F8 4C 29 D0 4C 8B 40 10 48 8B 48 18 4D 8B 48 18 49 39 C1 75 44 4C 39 49 10 75 3E 4C 01 D2 49 89 48 18 4C 89 41 10 4C 89 DF }
	condition:
		$pattern
}

rule ftime_2b0d2187648c27c406fa495d45b42417 {
	meta:
		aliases = "ftime"
		type = "func"
		size = "89"
		objfiles = "ftime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 83 EC 20 48 8D 74 24 10 48 89 E7 E8 ?? ?? ?? ?? 83 CA FF 85 C0 78 35 48 8B 04 24 BA E8 03 00 00 48 89 D1 48 89 03 48 8B 44 24 08 48 05 E7 03 00 00 48 99 48 F7 F9 31 D2 66 89 43 08 8B 44 24 10 66 89 43 0A 8B 44 24 14 66 89 43 0C 48 83 C4 20 89 D0 5B C3 }
	condition:
		$pattern
}

rule xre_exec_8ccc7cb3f9081f4b6cae41ad24d7b936 {
	meta:
		aliases = "xre_exec"
		type = "func"
		size = "63"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 83 EC 20 E8 ?? ?? ?? ?? 48 C7 44 24 08 00 00 00 00 89 44 24 10 48 89 D9 89 04 24 45 31 C9 41 89 C0 31 D2 31 F6 BF ?? ?? ?? ?? E8 3C CE FF FF 48 83 C4 20 F7 D0 C1 E8 1F 5B C3 }
	condition:
		$pattern
}

rule malloc_stats_c94d1291b2622a3621eeffd0418ded55 {
	meta:
		aliases = "malloc_stats"
		type = "func"
		size = "106"
		objfiles = "mallinfo@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 83 EC 60 48 85 FF 48 0F 44 1D ?? ?? ?? ?? 48 8D 7C 24 30 E8 ?? ?? ?? ?? 8B 44 24 54 8B 74 24 40 8B 7C 24 4C 44 8B 44 24 30 44 8B 4C 24 3C 89 44 24 20 8B 44 24 50 8D 0C 3E 41 8D 14 30 89 7C 24 08 89 34 24 48 89 DF BE ?? ?? ?? ?? 89 44 24 18 8B 44 24 44 89 44 24 10 31 C0 E8 ?? ?? ?? ?? 48 83 C4 60 5B C3 }
	condition:
		$pattern
}

rule __uc_malloc_1296210660250fdf1637a4ae60d3ef1b {
	meta:
		aliases = "__GI___uc_malloc, __uc_malloc"
		type = "func"
		size = "53"
		objfiles = "__uc_malloc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 89 DF E8 ?? ?? ?? ?? 48 85 DB 74 22 48 85 C0 75 1D 48 8B 05 ?? ?? ?? ?? 48 85 C0 75 0A BF 01 00 00 00 E8 ?? ?? ?? ?? 48 89 DF FF D0 EB D1 5B C3 }
	condition:
		$pattern
}

rule posix_memalign_44bb16dbd22ae5ca4ac2f264781e7d99 {
	meta:
		aliases = "posix_memalign"
		type = "func"
		size = "40"
		objfiles = "posix_memalign@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 89 F7 40 F6 C7 07 48 89 D6 B8 16 00 00 00 75 11 E8 ?? ?? ?? ?? 48 83 F8 01 48 89 03 19 C0 83 E0 0C 5B C3 }
	condition:
		$pattern
}

rule __pthread_manager_event_a0da9083bfd47ed74d61d3e906550632 {
	meta:
		aliases = "__pthread_manager_event"
		type = "func"
		size = "38"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 8B 3D ?? ?? ?? ?? 31 F6 E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xregfree_ba08a55e65811a1000f90f0f48449596 {
	meta:
		aliases = "xregfree"
		type = "func"
		size = "90"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 8B 3F 48 85 FF 74 05 E8 ?? ?? ?? ?? 48 8B 7B 20 48 C7 03 00 00 00 00 48 C7 43 08 00 00 00 00 48 C7 43 10 00 00 00 00 48 85 FF 74 05 E8 ?? ?? ?? ?? 48 8B 7B 28 80 63 38 F7 48 C7 43 20 00 00 00 00 48 85 FF 74 05 E8 ?? ?? ?? ?? 48 C7 43 28 00 00 00 00 5B C3 }
	condition:
		$pattern
}

rule regfree_888cdda41486620f0eb8138084a53f9e {
	meta:
		aliases = "__regfree, regfree"
		type = "func"
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
		type = "func"
		size = "96"
		objfiles = "vfwscanf@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 8B 7F 08 83 7F 04 FD 75 1F 48 8B 47 18 48 3B 47 10 73 0C 8B 10 48 83 C0 04 48 89 47 18 EB 15 66 83 0F 04 83 C8 FF EB 31 E8 ?? ?? ?? ?? 89 C2 83 FA FF 74 25 48 8B 43 08 3B 53 44 C6 43 1E 01 89 53 2C 8A 40 02 88 43 1C 75 07 BA 2E 00 00 00 EB 06 89 53 04 89 53 28 89 D0 5B C3 }
	condition:
		$pattern
}

rule dyn_string_delete_e52069da957e7131c156a9809ab22bf2 {
	meta:
		aliases = "dyn_string_delete"
		type = "func"
		size = "22"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 8B 7F 08 E8 ?? ?? ?? ?? 48 89 DF 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule vswprintf_72396a150029ee4d03bc9c42fdc0551c {
	meta:
		aliases = "__GI_vswprintf, vswprintf"
		type = "func"
		size = "164"
		objfiles = "vswprintf@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 49 89 D0 48 F7 D3 48 89 CA 48 C1 EB 02 48 83 C4 80 48 39 F3 48 89 7C 24 08 48 89 7C 24 18 48 0F 47 DE 48 89 7C 24 20 48 89 7C 24 28 48 8D 04 9F 48 89 7C 24 30 4C 89 C6 48 89 E7 C7 44 24 04 FD FF FF FF 66 C7 04 24 50 08 C6 44 24 02 00 C7 44 24 48 00 00 00 00 48 C7 44 24 38 00 00 00 00 48 89 44 24 10 E8 ?? ?? ?? ?? 89 C2 48 8B 44 24 18 48 3B 44 24 10 75 11 83 CA FF 48 85 DB 74 19 48 83 E8 04 48 89 44 24 18 48 85 DB 74 0B 48 8B 44 24 18 C7 00 00 00 00 00 48 83 EC 80 89 D0 5B C3 }
	condition:
		$pattern
}

rule system_235a481eb353d47af5ccc10f98212829 {
	meta:
		aliases = "system"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "26"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB BF 30 00 00 00 E8 ?? ?? ?? ?? 48 89 DF 48 89 C6 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule malloc_trim_66fca3eeb456e88daac1feb7295d8c31 {
	meta:
		aliases = "malloc_trim"
		type = "func"
		size = "28"
		objfiles = "free@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 DF BE ?? ?? ?? ?? 5B E9 F4 FB FF FF }
	condition:
		$pattern
}

rule pthread_once_cancelhandler_ee58a881baa408c0e50b7e2da4eda360 {
	meta:
		aliases = "pthread_once_cancelhandler"
		type = "func"
		size = "41"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB BF ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 03 00 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 5B BF ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wait_node_free_ab1213a4373809e196758c1764863b6f {
	meta:
		aliases = "wait_node_free"
		type = "func"
		size = "43"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB BF ?? ?? ?? ?? E8 A7 FF FF FF 48 8B 05 ?? ?? ?? ?? 48 89 03 48 89 1D ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 5B C3 }
	condition:
		$pattern
}

rule __ether_line_529159ffae907d0436b2540d3412341c {
	meta:
		aliases = "__ether_line"
		type = "func"
		size = "61"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB E8 ?? ?? ?? ?? 48 85 C0 75 05 EB 26 48 FF C3 8A 03 84 C0 74 0D 3C 20 74 09 3C 09 75 EF EB 03 48 FF C3 8A 03 84 C0 74 0A 3C 20 74 F3 3C 09 75 04 EB ED 31 DB 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule cuserid_7b2f5114cb473c8d271c6c794d7f866d {
	meta:
		aliases = "cuserid"
		type = "func"
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
		type = "func"
		size = "39"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB E8 ?? ?? ?? ?? 48 89 DE 45 31 C9 41 89 C0 31 C9 89 C2 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 5B F7 D0 C1 E8 1F C3 }
	condition:
		$pattern
}

rule pthread_start_thread_event_19ce97c0d5dad2347732efc07424141b {
	meta:
		aliases = "pthread_start_thread_event"
		type = "func"
		size = "40"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB E8 ?? ?? ?? ?? 48 8B 7B 30 89 43 28 31 F6 E8 ?? ?? ?? ?? 48 8B 7B 30 E8 ?? ?? ?? ?? 48 89 DF E8 14 FF FF FF }
	condition:
		$pattern
}

rule pthread_attr_init_96f6a93ac15b0cba5f1777b62086ea81 {
	meta:
		aliases = "__GI_pthread_attr_init, pthread_attr_init"
		type = "func"
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
		type = "func"
		size = "19"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB EB 06 FF 13 48 8B 5B 08 48 85 DB 75 F5 5B C3 }
	condition:
		$pattern
}

rule unlink_if_ordinary_6cedcd2ecdc209ab5b07b8a356de540b {
	meta:
		aliases = "unlink_if_ordinary"
		type = "func"
		size = "93"
		objfiles = "unlink_if_ordinary@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FE 48 89 FB BF 01 00 00 00 48 81 EC 90 00 00 00 48 89 E2 E8 ?? ?? ?? ?? 85 C0 B9 01 00 00 00 75 12 8B 54 24 18 81 E2 00 D0 00 00 81 FA 00 80 00 00 74 12 48 81 C4 90 00 00 00 89 C8 5B C3 0F 1F 80 00 00 00 00 48 89 DF E8 ?? ?? ?? ?? 48 81 C4 90 00 00 00 89 C1 89 C8 5B C3 }
	condition:
		$pattern
}

rule clnt_perror_b2f0703632b169ab18d09a7468662375 {
	meta:
		aliases = "__GI_clnt_perror, clnt_pcreateerror, clnt_perrno, clnt_perror"
		type = "func"
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
		type = "func"
		size = "39"
		objfiles = "_wcommit@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 8B 47 18 48 89 FB 48 8B 77 08 48 89 C2 48 29 F2 74 09 48 89 77 18 E8 ?? ?? ?? ?? 48 8B 43 18 48 2B 43 08 5B C3 }
	condition:
		$pattern
}

rule d_template_param_b73252a58c16ea8aca3c1379a7ce4473 {
	meta:
		aliases = "d_template_param"
		type = "func"
		size = "124"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 8B 47 18 48 89 FB 48 8D 50 01 48 89 57 18 80 38 54 75 5B 80 78 01 5F 74 5D 48 8D 7F 18 E8 6C FF FF FF 48 85 C0 78 47 48 8B 53 18 48 8D 70 01 48 8D 4A 01 48 89 4B 18 80 3A 5F 75 32 83 43 40 01 8B 53 28 3B 53 2C 7D 26 48 63 C2 83 C2 01 48 8D 0C 40 48 8B 43 20 89 53 28 48 8D 04 C8 48 85 C0 74 0C C7 00 05 00 00 00 48 89 70 08 5B C3 31 C0 5B C3 0F 1F 40 00 31 F6 EB B5 }
	condition:
		$pattern
}

rule fibheap_replace_key_7d53c473b8e1d35e345476cb0414aad4 {
	meta:
		aliases = "fibheap_replace_key"
		type = "func"
		size = "19"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 8B 4E 28 48 8B 5E 20 E8 ?? ?? ?? ?? 48 63 C3 5B C3 }
	condition:
		$pattern
}

rule d_unqualified_name_e415c91d7ab5de9310fa3e4aaff63b3a {
	meta:
		aliases = "d_unqualified_name"
		type = "func"
		size = "410"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 8B 57 18 48 89 FB 0F B6 02 8D 48 D0 80 F9 09 0F 86 99 00 00 00 8D 48 9F 80 F9 19 76 69 8D 48 BD 31 C0 80 F9 01 77 59 48 8B 4F 48 48 85 C9 74 10 8B 01 85 C0 0F 85 84 00 00 00 8B 41 10 01 43 50 48 8D 42 01 48 89 43 18 0F B6 02 3C 43 0F 84 BB 00 00 00 3C 44 75 27 48 8D 42 02 48 89 43 18 0F B6 42 01 3C 31 74 67 3C 32 0F 84 1F 01 00 00 3C 30 BE 01 00 00 00 74 5B 66 0F 1F 44 00 00 31 C0 5B C3 0F 1F 40 00 E8 13 FE FF FF 48 85 C0 74 F0 83 38 28 75 EB 48 8B 48 08 8B 53 50 03 51 10 83 C2 07 89 53 50 5B C3 0F 1F 80 00 00 00 00 5B E9 BA CF FF FF 66 2E 0F 1F 84 00 00 00 00 00 83 F8 15 0F 85 79 FF FF }
	condition:
		$pattern
}

rule dyn_string_release_032871977c0ebcd53260f76d7d6d28fd {
	meta:
		aliases = "dyn_string_release"
		type = "func"
		size = "23"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 8B 5F 08 48 C7 47 08 00 00 00 00 E8 ?? ?? ?? ?? 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule xdrrec_destroy_0bb8c22692188e00a570ed7612b26041 {
	meta:
		aliases = "xdrrec_destroy"
		type = "func"
		size = "23"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 8B 5F 18 48 8B 7B 08 E8 ?? ?? ?? ?? 48 89 DF 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdrrec_skiprecord_d2c822fb947a7ee0869b4a7731fd3145 {
	meta:
		aliases = "__GI_xdrrec_skiprecord, xdrrec_skiprecord"
		type = "func"
		size = "78"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 8B 5F 18 EB 26 48 89 DF E8 3C FD FF FF 85 C0 74 37 83 7B 70 00 48 C7 43 68 00 00 00 00 75 0C 48 89 DF E8 38 FF FF FF 85 C0 74 1D 48 8B 73 68 48 85 F6 7F D1 83 7B 70 00 74 CB B8 01 00 00 00 C7 43 70 00 00 00 00 EB 02 31 C0 5B C3 }
	condition:
		$pattern
}

rule xdrrec_eof_24fb0882c7963a923678ae1347cdde8d {
	meta:
		aliases = "__GI_xdrrec_eof, xdrrec_eof"
		type = "func"
		size = "83"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 48 8B 5F 18 EB 26 48 89 DF E8 8F FD FF FF 85 C0 74 39 83 7B 70 00 48 C7 43 68 00 00 00 00 75 0C 48 89 DF E8 8B FF FF FF 85 C0 74 1F 48 8B 73 68 48 85 F6 7F D1 83 7B 70 00 74 CB 48 8B 43 60 48 39 43 58 0F 94 C0 0F B6 C0 EB 05 B8 01 00 00 00 5B C3 }
	condition:
		$pattern
}

rule __stdio_rfill_29e41ae8bf1c95009ec2a99306c8c084 {
	meta:
		aliases = "__stdio_rfill"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "48"
		objfiles = "timer_settime@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 7F 04 48 63 F6 B8 DF 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule socketpair_653216f136112eb669f998d430fa77ed {
	meta:
		aliases = "socketpair"
		type = "func"
		size = "49"
		objfiles = "socketpair@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 D2 48 63 F6 48 63 FF B8 35 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule getsockopt_661cd3a8043618f213096d55a25a561f {
	meta:
		aliases = "getsockopt"
		type = "func"
		size = "49"
		objfiles = "getsockopt@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 D2 48 63 F6 48 63 FF B8 37 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule epoll_ctl_07a02650d40b95bf770d4a0382890fd6 {
	meta:
		aliases = "epoll_ctl"
		type = "func"
		size = "49"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 D2 48 63 F6 48 63 FF B8 E9 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule wait4_6f4a427f25f7667f0bf9f5f07f2be843 {
	meta:
		aliases = "__GI_wait4, wait4"
		type = "func"
		size = "47"
		objfiles = "wait4@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 D2 48 63 FF B8 3D 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule quotactl_cb5a6a934020d0d9bff35f5797fc3254 {
	meta:
		aliases = "quotactl"
		type = "func"
		size = "46"
		objfiles = "quotactl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 D2 48 63 FF B8 B3 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sendfile64_f45a701f3c1ffca116f6ed0c36a34ffd {
	meta:
		aliases = "sendfile, sendfile64"
		type = "func"
		size = "46"
		objfiles = "sendfile@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 F6 48 63 FF B8 28 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule __syscall_rt_sigaction_da51070d690dc72f22087f6c400aab48 {
	meta:
		aliases = "__syscall_rt_sigaction"
		type = "func"
		size = "43"
		objfiles = "__syscall_rt_sigaction@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 FF B8 0D 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule select_eca936c475871f03a11e1f63b3193afa {
	meta:
		aliases = "__GI_select, __libc_select, select"
		type = "func"
		size = "43"
		objfiles = "select@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 FF B8 17 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule prctl_66c7c9d938c47410b2b23be4ae9b3a60 {
	meta:
		aliases = "prctl"
		type = "func"
		size = "43"
		objfiles = "prctl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 FF B8 9D 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule fgetxattr_f9728e501774ff71d225c03d9a756899 {
	meta:
		aliases = "fgetxattr"
		type = "func"
		size = "43"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 FF B8 C1 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule semtimedop_83c9ef457bff48ff6e55069c91c38e6c {
	meta:
		aliases = "semtimedop"
		type = "func"
		size = "43"
		objfiles = "semtimedop@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 FF B8 DC 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule __syscall_mq_timedreceive_6813dd1e931bc60b1758b020e06372bb {
	meta:
		aliases = "__syscall_mq_timedreceive"
		type = "func"
		size = "43"
		objfiles = "mq_receive@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA 48 63 FF B8 F3 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule __rt_sigtimedwait_fc7666cfdba6fba345b7a3a2a8ce64ea {
	meta:
		aliases = "__rt_sigtimedwait"
		type = "func"
		size = "40"
		objfiles = "__rt_sigtimedwait@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA B8 80 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule mount_86415b394b86a77c87abbe3fc9f3c5f5 {
	meta:
		aliases = "mount"
		type = "func"
		size = "40"
		objfiles = "mount@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA B8 A5 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule init_module_36c282e0ac37aae5d680e8b1fecb1296 {
	meta:
		aliases = "init_module"
		type = "func"
		size = "40"
		objfiles = "init_module@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA B8 AF 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule getxattr_725ff8785e7a30a909594dac0bee8c50 {
	meta:
		aliases = "getxattr"
		type = "func"
		size = "40"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA B8 BF 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule lgetxattr_13b504305d38913988316e8406b85896 {
	meta:
		aliases = "lgetxattr"
		type = "func"
		size = "40"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 49 89 CA B8 C0 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule epoll_wait_473d10d69163f64db7147af4c793b6e1 {
	meta:
		aliases = "epoll_wait"
		type = "func"
		size = "46"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4C 63 D1 48 63 D2 48 63 FF B8 E8 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule recvfrom_e021c2bc00e4b73c078e114a6f235068 {
	meta:
		aliases = "__GI_recvfrom, __libc_recvfrom, recvfrom"
		type = "func"
		size = "43"
		objfiles = "recvfrom@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4C 63 D1 48 63 FF B8 2D 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule msgsnd_1aa3112d9bb5d565c299d81e9f6b72f4 {
	meta:
		aliases = "msgsnd"
		type = "func"
		size = "43"
		objfiles = "msgsnd@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4C 63 D1 48 63 FF B8 45 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule waitid_b2235f3387a94a7fc80c241f0019400a {
	meta:
		aliases = "waitid"
		type = "func"
		size = "44"
		objfiles = "waitid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4C 63 D1 89 F6 89 FF B8 F7 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule mremap_ced076848a0ed17344bd811c421518f9 {
	meta:
		aliases = "__GI_mremap, mremap"
		type = "func"
		size = "40"
		objfiles = "mremap@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4C 63 D1 B8 19 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule __dn_expand_4aad9398ec7f1344cc454c447883d7df {
	meta:
		aliases = "__dn_expand"
		type = "func"
		size = "26"
		objfiles = "res_comp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4D 63 C0 48 89 CB E8 ?? ?? ?? ?? 85 C0 7E 08 80 3B 2E 75 03 C6 03 00 5B C3 }
	condition:
		$pattern
}

rule remap_file_pages_e75405de75f3250046163d9b6c51c98e {
	meta:
		aliases = "remap_file_pages"
		type = "func"
		size = "46"
		objfiles = "remap_file_pages@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4D 63 C0 49 89 CA 48 63 D2 B8 D8 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule msgrcv_78d5caa0065c55fd8f2e8b561d38dc72 {
	meta:
		aliases = "msgrcv"
		type = "func"
		size = "46"
		objfiles = "msgrcv@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4D 63 C0 49 89 CA 48 63 FF B8 46 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule fsetxattr_110524458eee20fe647f38ddd9fe08d1 {
	meta:
		aliases = "fsetxattr"
		type = "func"
		size = "46"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4D 63 C0 49 89 CA 48 63 FF B8 BE 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setxattr_f15fd2fa1d94045cf14f806fbce27e5a {
	meta:
		aliases = "setxattr"
		type = "func"
		size = "43"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4D 63 C0 49 89 CA B8 BC 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule lsetxattr_d09968ed2094b9724a16d03e40bc65a2 {
	meta:
		aliases = "lsetxattr"
		type = "func"
		size = "43"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4D 63 C0 49 89 CA B8 BD 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule mmap_98fb6d2b249c5572a0858ab72200fb4e {
	meta:
		aliases = "__GI_mmap, mmap"
		type = "func"
		size = "46"
		objfiles = "mmap@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 4D 63 C0 4C 63 D1 48 63 D2 B8 09 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule mq_unlink_2ba0ecb21355ad33c4d94aac77ef9748 {
	meta:
		aliases = "mq_unlink"
		type = "func"
		size = "86"
		objfiles = "mq_unlink@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 80 3F 2F 74 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 3E 48 FF C7 B8 F1 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 85 DB 89 D8 79 17 E8 ?? ?? ?? ?? 8B 10 B9 0D 00 00 00 83 FA 01 0F 44 D1 89 10 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule gcvt_bac9347dca3fc1ce55901f275deed995 {
	meta:
		aliases = "gcvt"
		type = "func"
		size = "35"
		objfiles = "gcvt@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 FF 11 48 89 F3 BA 11 00 00 00 BE ?? ?? ?? ?? B0 01 0F 4E D7 48 89 DF E8 ?? ?? ?? ?? 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule connect_5c1ad78febb33d8a86da1750247a6a60 {
	meta:
		aliases = "__GI_connect, __libc_connect, connect"
		type = "func"
		size = "42"
		objfiles = "connect@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 D2 48 63 FF B8 2A 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule bind_5ad2b198006eb87521a84a36d131354f {
	meta:
		aliases = "__GI_bind, bind"
		type = "func"
		size = "42"
		objfiles = "bind@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 D2 48 63 FF B8 31 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule inotify_add_watch_f08e014e8b29bc3c1f2964f3ec694b72 {
	meta:
		aliases = "inotify_add_watch"
		type = "func"
		size = "42"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 D2 48 63 FF B8 FE 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule fchown_ccafcb2998cd85a6f933e99e328d5805 {
	meta:
		aliases = "fchown"
		type = "func"
		size = "44"
		objfiles = "fchown@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 D2 89 F6 48 63 FF B8 5D 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setresuid_92ae15e1530905e4031eac7343a168ab {
	meta:
		aliases = "__GI_setresuid, setresuid"
		type = "func"
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
		type = "func"
		size = "44"
		objfiles = "setresgid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 D2 89 F6 89 FF B8 77 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule chown_617821a5d5d530ad6535388748db9152 {
	meta:
		aliases = "__GI_chown, chown"
		type = "func"
		size = "41"
		objfiles = "chown@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 D2 89 F6 B8 5C 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule lchown_59ad8747f86df93eb3936a9454343541 {
	meta:
		aliases = "lchown"
		type = "func"
		size = "41"
		objfiles = "lchown@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 D2 89 F6 B8 5E 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule string_append_template_idx_58c505adb424e9d4c3bc40a83051ff37 {
	meta:
		aliases = "string_append_template_idx"
		type = "func"
		size = "48"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 89 F2 31 C0 48 89 FB BE ?? ?? ?? ?? 48 83 EC 30 48 89 E7 E8 ?? ?? ?? ?? 80 3C 24 00 74 0B 48 89 E6 48 89 DF E8 96 FF FF FF 48 83 C4 30 5B C3 }
	condition:
		$pattern
}

rule pex_unix_fdopenw_c928898c4d4c1f82a3abfdb2b5b1e036 {
	meta:
		aliases = "pex_unix_fdopenw"
		type = "func"
		size = "52"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 89 F3 31 C0 BA 01 00 00 00 BE 02 00 00 00 89 DF E8 ?? ?? ?? ?? 85 C0 78 16 89 DF BE ?? ?? ?? ?? 5B E9 ?? ?? ?? ?? 66 0F 1F 84 00 00 00 00 00 31 C0 5B C3 }
	condition:
		$pattern
}

rule ftok_da5fd679b00271b1b62fc20d9c1e754e {
	meta:
		aliases = "ftok"
		type = "func"
		size = "55"
		objfiles = "ftok@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 F3 48 81 EC 90 00 00 00 48 89 E6 E8 ?? ?? ?? ?? 83 CA FF 85 C0 78 13 0F B6 14 24 0F B7 44 24 08 C1 E3 18 C1 E2 10 09 C2 09 DA 48 81 C4 90 00 00 00 89 D0 5B C3 }
	condition:
		$pattern
}

rule fdmatch_149318fc16256bf81b128acf8a40363a {
	meta:
		aliases = "fdmatch"
		type = "func"
		size = "107"
		objfiles = "fdmatch@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 89 F3 89 FE BF 01 00 00 00 48 81 EC 20 01 00 00 48 89 E2 E8 ?? ?? ?? ?? 85 C0 74 13 31 C0 48 81 C4 20 01 00 00 5B C3 0F 1F 84 00 00 00 00 00 48 8D 94 24 90 00 00 00 89 DE BF 01 00 00 00 E8 ?? ?? ?? ?? 85 C0 75 D5 48 8B 84 24 90 00 00 00 48 39 04 24 75 C7 48 8B 84 24 98 00 00 00 48 39 44 24 08 0F 94 C0 0F B6 C0 EB B4 }
	condition:
		$pattern
}

rule fchmod_205a7d1e1450e3a0d8bf8cebac338cce {
	meta:
		aliases = "fchmod"
		type = "func"
		size = "43"
		objfiles = "fchmod@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 F6 48 63 FF B8 5B 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule inotify_rm_watch_c09f08e4d311da3210980e232a0482af {
	meta:
		aliases = "inotify_rm_watch"
		type = "func"
		size = "42"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 F6 48 63 FF B8 FF 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setreuid_385849b46dda9e3c967f83e3bfc63b0c {
	meta:
		aliases = "__GI_setreuid, setreuid"
		type = "func"
		size = "41"
		objfiles = "setreuid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 F6 89 FF B8 71 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setregid_8990283012badfcf0e9b499c3521b29a {
	meta:
		aliases = "__GI_setregid, setregid"
		type = "func"
		size = "41"
		objfiles = "setregid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 F6 89 FF B8 72 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule getpriority_358a0656f549c77accf294684f253f5c {
	meta:
		aliases = "__GI_getpriority, getpriority"
		type = "func"
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
		type = "func"
		size = "40"
		objfiles = "mkdir@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 F6 B8 53 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule chmod_c91f9d0dd2071821174bf152b5064a4a {
	meta:
		aliases = "__GI_chmod, chmod"
		type = "func"
		size = "40"
		objfiles = "chmod@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 F6 B8 5A 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule delete_module_1da854d5cdabf9d1eeb8e71933f569be {
	meta:
		aliases = "delete_module"
		type = "func"
		size = "39"
		objfiles = "delete_module@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 F6 B8 B0 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule __pthread_internal_tsd_get_f010ec8a701dee428e6f2ad302dc470a {
	meta:
		aliases = "__pthread_internal_tsd_get"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "65"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB 48 83 EC 10 3B 3D ?? ?? ?? ?? 7E 2E BF 01 00 00 00 E8 ?? ?? ?? ?? 8D 53 01 39 C3 8B 3D ?? ?? ?? ?? BE 01 00 00 00 0F 4D D3 89 14 24 48 89 E2 E8 ?? ?? ?? ?? 89 1D ?? ?? ?? ?? 58 5A 5B C3 }
	condition:
		$pattern
}

rule getprotobynumber_b08a31b23b7dd973eab88d58795509b4 {
	meta:
		aliases = "getprotobynumber"
		type = "func"
		size = "50"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB 48 83 EC 10 E8 6F FC FF FF 48 8B 15 ?? ?? ?? ?? 4C 8D 44 24 08 B9 19 11 00 00 89 DF BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 44 24 08 5A 59 5B C3 }
	condition:
		$pattern
}

rule ldexp_e5d9cee36ca170ed13d4d0473762960a {
	meta:
		aliases = "__GI_ldexp, ldexp"
		type = "func"
		size = "99"
		objfiles = "s_ldexp@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB 48 83 EC 10 F2 0F 11 44 24 08 E8 ?? ?? ?? ?? 85 C0 74 43 0F 57 C9 F2 0F 10 44 24 08 66 0F 2E C1 7A 02 74 32 89 DF E8 ?? ?? ?? ?? F2 0F 11 44 24 08 E8 ?? ?? ?? ?? 85 C0 74 11 0F 57 C9 F2 0F 10 44 24 08 66 0F 2E C1 75 0D 7A 0B E8 ?? ?? ?? ?? C7 00 22 00 00 00 F2 0F 10 44 24 08 58 5A 5B C3 }
	condition:
		$pattern
}

rule verrx_bc5c0a917a938d43cc792f244dc3dea3 {
	meta:
		aliases = "__GI_verr, __GI_verrx, verr, verrx"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "48"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB BF 01 00 00 00 48 83 EC 10 48 8D 74 24 0C E8 ?? ?? ?? ?? 89 DF E8 ?? ?? ?? ?? 8B 7C 24 0C 89 C3 31 F6 E8 ?? ?? ?? ?? 89 D8 5B 5A 5B C3 }
	condition:
		$pattern
}

rule pthread_key_delete_86416a6c681e32c129498f18d2299ad1 {
	meta:
		aliases = "pthread_key_delete"
		type = "func"
		size = "156"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 FB FF 03 00 00 77 0F 89 D8 48 C1 E0 04 83 B8 ?? ?? ?? ?? 00 75 11 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 16 00 00 00 EB 65 83 3D ?? ?? ?? ?? FF C7 80 ?? ?? ?? ?? 00 00 00 00 48 C7 80 ?? ?? ?? ?? 00 00 00 00 74 3B E8 5E FD FF FF 48 89 C6 89 D8 C1 E8 05 48 89 F2 89 C7 48 89 D8 83 E0 1F 80 7A 50 00 75 15 48 8B 8C FA 48 01 00 00 48 85 C9 74 08 48 C7 04 C1 00 00 00 00 48 8B 12 48 39 F2 75 DD BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 5B C3 }
	condition:
		$pattern
}

rule pthread_handle_sigcancel_10dd9fc777675c7ca5f626c6fb984ee1 {
	meta:
		aliases = "pthread_handle_sigcancel"
		type = "func"
		size = "130"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB E8 25 F8 FF FF 48 3D ?? ?? ?? ?? 75 08 89 DF 5B E9 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 26 48 3B 05 ?? ?? ?? ?? 75 12 8B 3D ?? ?? ?? ?? BA 00 00 00 80 31 F6 E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 80 78 7A 00 74 33 80 78 78 00 75 2D 80 78 79 01 75 0C 48 89 E6 48 83 CF FF E8 ?? ?? ?? ?? 48 8B 78 48 48 85 FF 74 12 48 C7 40 48 00 00 00 00 BE 01 00 00 00 E8 ?? ?? ?? ?? 5B C3 }
	condition:
		$pattern
}

rule login_tty_d147fbb3b2c94cf975cfd6f208c333a8 {
	meta:
		aliases = "__GI_login_tty, login_tty"
		type = "func"
		size = "80"
		objfiles = "login_tty@libutil.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB E8 ?? ?? ?? ?? 31 D2 31 C0 BE 0E 54 00 00 89 DF E8 ?? ?? ?? ?? 83 F8 FF 74 31 31 F6 89 DF E8 ?? ?? ?? ?? BE 01 00 00 00 89 DF E8 ?? ?? ?? ?? BE 02 00 00 00 89 DF E8 ?? ?? ?? ?? 31 C0 83 FB 02 7E 09 89 DF E8 ?? ?? ?? ?? 31 C0 5B C3 }
	condition:
		$pattern
}

rule xstrerror_c43e43669b9181a59a249b25a4a25119 {
	meta:
		aliases = "xstrerror"
		type = "func"
		size = "40"
		objfiles = "xstrerror@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB E8 ?? ?? ?? ?? 48 85 C0 74 03 5B C3 90 89 DA BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 5B C3 }
	condition:
		$pattern
}

rule raise_35f58cd14702758cbe09e3646a438697 {
	meta:
		aliases = "__GI_raise, raise"
		type = "func"
		size = "38"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB E8 ?? ?? ?? ?? 89 DE 48 89 C7 E8 ?? ?? ?? ?? 89 C3 31 C0 85 DB 74 0A E8 ?? ?? ?? ?? 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule raise_e2704d2067d2413d752ef38f97c1cf95 {
	meta:
		aliases = "__GI_raise, __raise, raise"
		type = "func"
		size = "18"
		objfiles = "raise@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB E8 ?? ?? ?? ?? 89 DE 89 C7 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_handle_sigrestart_8c63eb449d23f11b5f1dbfd0e10da285 {
	meta:
		aliases = "pthread_handle_sigrestart"
		type = "func"
		size = "32"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB E8 A3 F7 FF FF 48 8B 78 40 89 58 38 48 85 FF 74 0A BE 01 00 00 00 E8 ?? ?? ?? ?? 5B C3 }
	condition:
		$pattern
}

rule __exit_handler_ec4af4dc08509d48441f818bbef1cb5d {
	meta:
		aliases = "__exit_handler"
		type = "func"
		size = "100"
		objfiles = "__exit_handler@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB EB 48 FF C8 89 05 ?? ?? ?? ?? 48 98 48 C1 E0 05 48 03 05 ?? ?? ?? ?? 48 8B 10 48 83 FA 02 74 08 48 83 FA 03 75 24 EB 13 48 8B 50 08 48 85 D2 74 19 48 8B 70 10 89 DF FF D2 EB 0F 48 8B 50 08 48 85 D2 74 06 48 8B 78 10 FF D2 8B 05 ?? ?? ?? ?? 85 C0 75 AE 5B 48 8B 3D ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getitimer_459d25f7b8abddf9883d6b1ceef4b1e4 {
	meta:
		aliases = "getitimer"
		type = "func"
		size = "39"
		objfiles = "getitimer@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FF B8 24 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule alarm_fe38bdffcae10f68cc9c07f86faa75c0 {
	meta:
		aliases = "__GI_alarm, alarm"
		type = "func"
		size = "39"
		objfiles = "alarm@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FF B8 25 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setitimer_3e5f69f6f526f172b4792f25e2acb222 {
	meta:
		aliases = "__GI_setitimer, setitimer"
		type = "func"
		size = "39"
		objfiles = "setitimer@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FF B8 26 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule umask_3162c6cce53b5b0e2fe4ebe74c12e0ad {
	meta:
		aliases = "umask"
		type = "func"
		size = "40"
		objfiles = "umask@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FF B8 5F 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule getrlimit64_53abd820a7baef0175de297f4c6624c4 {
	meta:
		aliases = "__GI_getrlimit, getrlimit, getrlimit64"
		type = "func"
		size = "39"
		objfiles = "getrlimit@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FF B8 61 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setuid_00072aa7d04881fcee97441852c3e0c7 {
	meta:
		aliases = "setuid"
		type = "func"
		size = "39"
		objfiles = "setuid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FF B8 69 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setgid_47265311a697b80629e7aea249a4bd24 {
	meta:
		aliases = "setgid"
		type = "func"
		size = "39"
		objfiles = "setgid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FF B8 6A 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setfsuid_8837f7d11690fb4b7afdf16332ffedd7 {
	meta:
		aliases = "setfsuid"
		type = "func"
		size = "39"
		objfiles = "setfsuid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FF B8 7A 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setfsgid_69344fa249b51aade54fe45a2a7d4c9f {
	meta:
		aliases = "setfsgid"
		type = "func"
		size = "39"
		objfiles = "setfsgid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FF B8 7B 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setrlimit64_b6aa7b384ab0cd110f752e8da5f90418 {
	meta:
		aliases = "__GI_setrlimit, setrlimit, setrlimit64"
		type = "func"
		size = "39"
		objfiles = "setrlimit@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FF B8 A0 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule __stdio_trans2r_o_3be1e8b4c78d700a7b1d9f67b0fe97dd {
	meta:
		aliases = "__stdio_trans2r_o"
		type = "func"
		size = "90"
		objfiles = "_trans2r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 07 48 89 FB 0F B7 D0 85 F2 75 0D 81 E2 80 08 00 00 75 0C 09 F0 66 89 07 0F B7 03 A8 10 74 14 E8 ?? ?? ?? ?? C7 00 09 00 00 00 66 83 0B 08 83 C8 FF EB 23 A8 40 74 19 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 75 E6 48 8B 43 08 66 83 23 BF 48 89 43 30 66 83 0B 01 31 C0 5B C3 }
	condition:
		$pattern
}

rule __stdio_trans2w_o_a1a6e5ac44c870086576c4f87b745659 {
	meta:
		aliases = "__stdio_trans2w_o"
		type = "func"
		size = "149"
		objfiles = "_trans2w@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 07 48 89 FB 0F B7 D0 85 F2 75 0D 81 E2 80 08 00 00 75 0C 09 F0 66 89 07 0F B7 03 A8 20 74 14 E8 ?? ?? ?? ?? C7 00 09 00 00 00 66 83 0B 08 83 CA FF EB 5C A8 03 74 41 A8 04 75 29 48 8B 53 18 48 39 53 20 75 04 A8 02 74 1B 25 00 04 00 00 48 89 DF 83 F8 01 19 D2 31 F6 83 C2 02 E8 ?? ?? ?? ?? 85 C0 75 C6 48 8B 43 08 66 83 23 FC 48 89 43 28 48 89 43 18 48 89 43 20 8B 03 31 D2 83 C8 40 F6 C4 0B 66 89 03 75 08 48 8B 43 10 48 89 43 30 5B 89 D0 C3 }
	condition:
		$pattern
}

rule dyn_string_resize_4fcfa7fe3cf80ee33dacd7db148d8c86 {
	meta:
		aliases = "dyn_string_resize"
		type = "func"
		size = "49"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 07 48 89 FB 39 F0 7F 22 89 C2 0F 1F 40 00 01 D2 39 D6 7D FA 39 D0 74 12 48 8B 7B 08 89 13 48 63 F2 E8 ?? ?? ?? ?? 48 89 43 08 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule dirfd_7433bc02f13993829951c36feb88eaa2 {
	meta:
		aliases = "__GI_dirfd, dirfd"
		type = "func"
		size = "23"
		objfiles = "dirfd@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 1F 83 FB FF 75 0B E8 ?? ?? ?? ?? C7 00 09 00 00 00 89 D8 5B C3 }
	condition:
		$pattern
}

rule pthread_mutex_unlock_d13f23a2f23b310028e114ce4e04b448 {
	meta:
		aliases = "__pthread_mutex_unlock, pthread_mutex_unlock"
		type = "func"
		size = "127"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 47 10 48 89 FB 83 F8 01 74 19 7F 06 85 C0 74 36 EB 0A 83 F8 02 74 3A 83 F8 03 74 4F B8 16 00 00 00 EB 58 E8 91 FF FF FF 48 39 43 08 75 48 8B 43 04 85 C0 7E 09 FF C8 89 43 04 31 C0 EB 3D 48 C7 43 08 00 00 00 00 48 8D 7B 18 E8 ?? ?? ?? ?? EB E9 E8 63 FF FF FF 48 39 43 08 75 1A 48 83 7B 18 00 74 13 48 C7 43 08 00 00 00 00 48 8D 7B 18 E8 ?? ?? ?? ?? EB C4 B8 01 00 00 00 5B C3 }
	condition:
		$pattern
}

rule __scan_getc_c6e37eac5669f153a563217f1523c1d2 {
	meta:
		aliases = "__scan_getc"
		type = "func"
		size = "70"
		objfiles = "__scan_cookie@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 47 14 48 89 FB C7 07 FF FF FF FF FF C8 85 C0 89 47 14 79 09 80 4F 1D 02 83 C8 FF EB 25 80 7F 1D 00 75 13 FF 53 30 83 F8 FF 75 06 80 4B 1D 02 EB 11 89 43 04 EB 04 C6 47 1D 00 8B 43 04 FF 43 10 89 03 5B C3 }
	condition:
		$pattern
}

rule scan_getwc_c6ee5775dda9aaaad86acb068187f7be {
	meta:
		aliases = "scan_getwc"
		type = "func"
		size = "130"
		objfiles = "vfwscanf@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 47 14 48 89 FB C7 47 28 FF FF FF FF FF C8 85 C0 89 47 14 79 06 80 4F 1D 02 EB 2A 80 7F 1D 00 75 4E 48 8B 7F 08 83 7F 04 FD 75 1F 48 8B 47 18 48 3B 47 10 73 0C 8B 10 48 83 C0 04 48 89 47 18 EB 1B C6 43 1D 02 83 C8 FF EB 34 E8 ?? ?? ?? ?? 83 F8 FF 89 C2 75 06 80 4B 1D 02 EB 22 48 8B 43 08 C6 43 1E 01 89 53 04 8A 40 02 88 43 1C EB 04 C6 47 1D 00 8B 43 04 FF 43 10 89 43 28 31 C0 5B C3 }
	condition:
		$pattern
}

rule register_Btype_d9724c301eb12563f95e6cf261c2f6e8 {
	meta:
		aliases = "register_Btype"
		type = "func"
		size = "110"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 57 24 48 89 FB 8B 77 2C 39 F2 7C 5A 85 F6 74 36 01 F6 89 77 2C 48 8B 7F 18 48 63 F6 48 C1 E6 03 E8 ?? ?? ?? ?? 8B 53 24 48 89 43 18 8D 4A 01 89 4B 24 48 63 CA 48 C7 04 C8 00 00 00 00 89 D0 5B C3 0F 1F 44 00 00 C7 47 2C 05 00 00 00 BF 28 00 00 00 E8 ?? ?? ?? ?? 8B 53 24 48 89 43 18 EB CC 66 0F 1F 44 00 00 48 8B 47 18 EB C0 }
	condition:
		$pattern
}

rule system_681a810d029bd247c601c425e9ec42f3 {
	meta:
		aliases = "__libc_system, system"
		type = "func"
		size = "335"
		objfiles = "system@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 01 00 00 00 48 83 EC 30 48 85 FF 48 89 3C 24 0F 84 32 01 00 00 BE 01 00 00 00 BF 03 00 00 00 E8 ?? ?? ?? ?? BE 01 00 00 00 BF 02 00 00 00 48 89 44 24 08 E8 ?? ?? ?? ?? 31 F6 BF 11 00 00 00 48 89 44 24 10 E8 ?? ?? ?? ?? 48 89 44 24 18 E8 ?? ?? ?? ?? 83 F8 00 89 C3 7D 35 48 8B 74 24 08 BF 03 00 00 00 E8 ?? ?? ?? ?? 48 8B 74 24 10 BF 02 00 00 00 E8 ?? ?? ?? ?? 48 8B 74 24 18 BF 11 00 00 00 E8 ?? ?? ?? ?? 83 C8 FF E9 B8 00 00 00 75 4B 31 F6 BF 03 00 00 00 E8 ?? ?? ?? ?? 31 F6 BF 02 00 00 00 E8 ?? ?? ?? ?? 31 F6 BF 11 00 00 00 E8 ?? ?? ?? ?? 48 8B 0C 24 BF ?? ?? ?? ?? 45 31 C0 BA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule munmap_581cfaa042a40f4fbe4b37f97f307536 {
	meta:
		aliases = "__GI_munmap, munmap"
		type = "func"
		size = "37"
		objfiles = "munmap@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 0B 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule pipe_2141c750bd93e5de2a15f48d5b6a8cf2 {
	meta:
		aliases = "__GI_pipe, pipe"
		type = "func"
		size = "37"
		objfiles = "pipe@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 16 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sched_yield_cb939c006b8ff3f89eb7c25fcc20357c {
	meta:
		aliases = "sched_yield"
		type = "func"
		size = "37"
		objfiles = "sched_yield@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 18 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule mincore_a268b3b2e449615debea71fedbec0949 {
	meta:
		aliases = "mincore"
		type = "func"
		size = "37"
		objfiles = "mincore@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 1B 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule pause_7f795ff181c269ac95907652e22eaf6a {
	meta:
		aliases = "__libc_pause, pause"
		type = "func"
		size = "37"
		objfiles = "pause@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 22 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule nanosleep_d7ebdd0dd3a1c6a0846326fe08ad754d {
	meta:
		aliases = "__GI_nanosleep, __libc_nanosleep, nanosleep"
		type = "func"
		size = "37"
		objfiles = "nanosleep@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 23 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule getpid_963edc45d49c008809bd1020d8e46082 {
	meta:
		aliases = "__GI_getpid, __libc_getpid, getpid"
		type = "func"
		size = "37"
		objfiles = "getpid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 27 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule fork_f1720d0c174360aed1d43b8bd114378b {
	meta:
		aliases = "__GI_fork, __libc_fork, fork"
		type = "func"
		size = "37"
		objfiles = "fork@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 39 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule execve_c2438c64f15482ff5d73b6023a7ee8c0 {
	meta:
		aliases = "__GI_execve, execve"
		type = "func"
		size = "37"
		objfiles = "execve@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 3B 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule uname_4c512c4d702ae1efd2ca17f3d26812ed {
	meta:
		aliases = "__GI_uname, uname"
		type = "func"
		size = "37"
		objfiles = "uname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 3F 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule shmdt_60b604baa9aa309365efbfa8249892a5 {
	meta:
		aliases = "shmdt"
		type = "func"
		size = "37"
		objfiles = "shmdt@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 43 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule truncate_429263e4ac6dc8aa2d4e394a7e3d15b7 {
	meta:
		aliases = "__GI_truncate, truncate"
		type = "func"
		size = "37"
		objfiles = "truncate@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 4C 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule chdir_a018a749281199e89f89e6edf9d640f1 {
	meta:
		aliases = "__GI_chdir, chdir"
		type = "func"
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
		type = "func"
		size = "38"
		objfiles = "rename@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 52 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule rmdir_f83b4b42e56eb6667378da6a786d34ba {
	meta:
		aliases = "__GI_rmdir, rmdir"
		type = "func"
		size = "37"
		objfiles = "rmdir@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 54 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule link_24bf7eaf0e03e88b0fd05bc669bc5b07 {
	meta:
		aliases = "link"
		type = "func"
		size = "37"
		objfiles = "link@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 56 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule unlink_5dd8e4cb58bc42965551019be00a721e {
	meta:
		aliases = "__GI_unlink, unlink"
		type = "func"
		size = "37"
		objfiles = "unlink@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 57 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule symlink_f8f32bbfb55311d5a8b711d84b518de2 {
	meta:
		aliases = "symlink"
		type = "func"
		size = "37"
		objfiles = "symlink@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 58 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule readlink_7a5783aa8320987cc6eec3415150ef80 {
	meta:
		aliases = "__GI_readlink, readlink"
		type = "func"
		size = "37"
		objfiles = "readlink@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 59 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule gettimeofday_6563ce3a51ffef4fc066679b1d7b12c7 {
	meta:
		aliases = "__GI_gettimeofday, gettimeofday"
		type = "func"
		size = "37"
		objfiles = "gettimeofday@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 60 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sysinfo_554a27db7c301d3811611e95bafb65d2 {
	meta:
		aliases = "sysinfo"
		type = "func"
		size = "37"
		objfiles = "sysinfo@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 63 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule times_9d5a653523db47a77d3f707e3e8a2153 {
	meta:
		aliases = "__GI_times, times"
		type = "func"
		size = "37"
		objfiles = "times@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 64 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule getuid_b5d9cf79b6eba76d3a75ecf05ae23df7 {
	meta:
		aliases = "__GI_getuid, getuid"
		type = "func"
		size = "37"
		objfiles = "getuid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 66 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule getgid_49175c28f718bde5dae0ab9a51eaac24 {
	meta:
		aliases = "__GI_getgid, getgid"
		type = "func"
		size = "37"
		objfiles = "getgid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 68 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule geteuid_d1e6f3f1bff1671e16b93d00cc653a56 {
	meta:
		aliases = "__GI_geteuid, geteuid"
		type = "func"
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
		type = "func"
		size = "38"
		objfiles = "getegid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 6C 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule getppid_7f5dae6735010b953fd29bc006e06389 {
	meta:
		aliases = "getppid"
		type = "func"
		size = "37"
		objfiles = "getppid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 6E 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule getpgrp_14b557861bd3e8ec4ea80652ee1e7d4d {
	meta:
		aliases = "getpgrp"
		type = "func"
		size = "37"
		objfiles = "getpgrp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 6F 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setsid_59ee9d9c6a8df33aca4b03e5348b323b {
	meta:
		aliases = "__GI_setsid, setsid"
		type = "func"
		size = "37"
		objfiles = "setsid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 70 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setgroups_88418b91821ef067c0a8ccc46d6cd45b {
	meta:
		aliases = "__GI_setgroups, setgroups"
		type = "func"
		size = "37"
		objfiles = "setgroups@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 74 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule capget_13a6d0e1b71731ec716dbe24af528c33 {
	meta:
		aliases = "capget"
		type = "func"
		size = "37"
		objfiles = "capget@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 7D 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule capset_0a4b933b42e44dad2f951f0b049fb5b5 {
	meta:
		aliases = "capset"
		type = "func"
		size = "37"
		objfiles = "capset@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 7E 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sigaltstack_aa2d89c16a047be70e28288a75692330 {
	meta:
		aliases = "sigaltstack"
		type = "func"
		size = "37"
		objfiles = "sigaltstack@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 83 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule utime_04a8c40cb56e3ed6278ebc82b377cec8 {
	meta:
		aliases = "__GI_utime, utime"
		type = "func"
		size = "37"
		objfiles = "utime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 84 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule personality_94dbd7bec05f49835034f7bfe1e7ee0a {
	meta:
		aliases = "personality"
		type = "func"
		size = "37"
		objfiles = "personality@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 87 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule statfs_76811c3e5f45b690cfcb933522f1df2b {
	meta:
		aliases = "__GI___libc_statfs, __GI_statfs, __libc_statfs, statfs"
		type = "func"
		size = "37"
		objfiles = "statfs@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 89 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule mlock_60d38f6d766942ee13afdacb468b8648 {
	meta:
		aliases = "mlock"
		type = "func"
		size = "37"
		objfiles = "mlock@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 95 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule munlock_7527e9733b0eb67c62f4aee5466eaa52 {
	meta:
		aliases = "munlock"
		type = "func"
		size = "37"
		objfiles = "munlock@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 96 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule munlockall_7b5bc97d95f0ce19173d1261468241f0 {
	meta:
		aliases = "munlockall"
		type = "func"
		size = "37"
		objfiles = "munlockall@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 98 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule vhangup_05335b4fb0a3d2773f22998fc11954c7 {
	meta:
		aliases = "vhangup"
		type = "func"
		size = "37"
		objfiles = "vhangup@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 99 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule pivot_root_3d676c97fad7152d3698c9273092f2eb {
	meta:
		aliases = "pivot_root"
		type = "func"
		size = "37"
		objfiles = "pivot_root@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 9B 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule ntp_adjtime_e144a6d4863c934d93fd60653356f83e {
	meta:
		aliases = "__GI_adjtimex, adjtimex, ntp_adjtime"
		type = "func"
		size = "37"
		objfiles = "adjtimex@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 9F 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule mbrtowc_497c2998aa82b9fd0d57917889375115 {
	meta:
		aliases = "__GI_mbrtowc, mbrtowc"
		type = "func"
		size = "113"
		objfiles = "mbrtowc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 ?? ?? ?? ?? 48 89 FB 48 83 EC 20 48 85 C9 48 0F 44 C8 48 85 F6 75 0E 48 8D 74 24 1F 31 DB C6 44 24 1F 00 EB 0A 80 3E 00 74 3A 48 85 D2 74 35 48 89 74 24 08 48 8D 7C 24 10 48 8D 74 24 08 48 83 CA FF 49 89 C8 B9 01 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C2 78 0F 48 85 DB 74 0A 8B 44 24 10 89 03 EB 02 31 D2 48 83 C4 20 48 89 D0 5B C3 }
	condition:
		$pattern
}

rule chroot_3eb1180273b67b73ed136c5869d54629 {
	meta:
		aliases = "chroot"
		type = "func"
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
		type = "func"
		size = "32"
		objfiles = "sync@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 A2 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0B E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 5B C3 }
	condition:
		$pattern
}

rule acct_41342ab0a381f643f7efe916c8157995 {
	meta:
		aliases = "acct"
		type = "func"
		size = "37"
		objfiles = "acct@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 A3 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule settimeofday_5382b4403b6f5f3bde36c3e2b4fabf73 {
	meta:
		aliases = "__GI_settimeofday, settimeofday"
		type = "func"
		size = "37"
		objfiles = "settimeofday@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 A4 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule swapoff_cdb868c5d2f753bc7058d5c57ac581c2 {
	meta:
		aliases = "swapoff"
		type = "func"
		size = "37"
		objfiles = "swapoff@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 A8 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sethostname_455b72fe77c80f722332fffd481419f4 {
	meta:
		aliases = "sethostname"
		type = "func"
		size = "37"
		objfiles = "sethostname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 AA 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setdomainname_c671d1da9615e9ea80bb2741a8d7aeb3 {
	meta:
		aliases = "setdomainname"
		type = "func"
		size = "37"
		objfiles = "setdomainname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 AB 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule listxattr_d9b00acdb3e9c27efaaee35d3c3c7b50 {
	meta:
		aliases = "listxattr"
		type = "func"
		size = "37"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 C2 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule llistxattr_23c4e93b99199780770dd8d158d0c830 {
	meta:
		aliases = "llistxattr"
		type = "func"
		size = "37"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 C3 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule removexattr_97d0677862fc829dcf8f6912fe295869 {
	meta:
		aliases = "removexattr"
		type = "func"
		size = "37"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 C5 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule lremovexattr_781401d8a6ba6a4746dc4a98d50b16be {
	meta:
		aliases = "lremovexattr"
		type = "func"
		size = "37"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 C6 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule time_233f9b8e4f6d1e1aeb4cf5d8334fc8f0 {
	meta:
		aliases = "__GI_time, time"
		type = "func"
		size = "37"
		objfiles = "time@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 C9 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule timer_gettime_e2f02cb5b7a6b60499e8a646c70c4001 {
	meta:
		aliases = "timer_gettime"
		type = "func"
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
		type = "func"
		size = "42"
		objfiles = "timer_getoverr@librt.a"
	strings:
		$pattern = { ( CC | 53 ) B8 E1 00 00 00 48 63 7F 04 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule utimes_a93fa1117b6c94c8fb6709800cbaf0a8 {
	meta:
		aliases = "__GI_utimes, utimes"
		type = "func"
		size = "37"
		objfiles = "utimes@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 EB 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule inotify_init_26cc638603ee9814ccc49676ff6e6e01 {
	meta:
		aliases = "inotify_init"
		type = "func"
		size = "37"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 FD 00 00 00 0F 05 48 89 C3 48 81 FB 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 48 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule xdrstdio_getint32_8819b743f35baa6a8fa6b1d3b3283b38 {
	meta:
		aliases = "xdrstdio_getint32"
		type = "func"
		size = "55"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA 01 00 00 00 48 89 F3 BE 04 00 00 00 48 83 EC 10 48 8B 4F 18 48 8D 7C 24 0C E8 ?? ?? ?? ?? 31 D2 48 FF C8 75 0A 8B 44 24 0C B2 01 0F C8 89 03 59 5E 5B 89 D0 C3 }
	condition:
		$pattern
}

rule xdrstdio_getlong_4942562edc8440ee0e181cd629dd1ee8 {
	meta:
		aliases = "xdrstdio_getlong"
		type = "func"
		size = "60"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA 01 00 00 00 48 89 F3 BE 04 00 00 00 48 83 EC 10 48 8B 4F 18 48 8D 7C 24 0C E8 ?? ?? ?? ?? 31 D2 48 FF C8 75 0D 8B 44 24 0C B2 01 0F C8 89 C0 48 89 03 41 58 41 59 5B 89 D0 C3 }
	condition:
		$pattern
}

rule set_input_fragment_ecd0f2a35c0f57c1fa5c8dd19adc8cf5 {
	meta:
		aliases = "set_input_fragment"
		type = "func"
		size = "76"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA 04 00 00 00 48 89 FB 48 83 EC 10 48 8D 74 24 0C E8 8A FF FF FF 85 C0 74 29 8B 54 24 0C 0F CA 89 D0 89 54 24 0C C1 E8 1F 85 D2 89 43 70 74 13 48 89 D0 25 FF FF FF 7F 48 89 43 68 B8 01 00 00 00 EB 02 31 C0 41 59 41 5A 5B C3 }
	condition:
		$pattern
}

rule utmpname_5b1745300f788821d00b2605280e8995 {
	meta:
		aliases = "utmpname"
		type = "func"
		size = "136"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? 48 89 FB BE ?? ?? ?? ?? 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 DB 74 30 48 8B 3D ?? ?? ?? ?? 48 81 FF ?? ?? ?? ?? 74 05 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 85 C0 48 0F 45 D0 48 89 15 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 83 FF FF 74 05 E8 ?? ?? ?? ?? 48 89 E7 BE 01 00 00 00 C7 05 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 48 83 C4 20 31 C0 5B C3 }
	condition:
		$pattern
}

rule closelog_360dbc0a82e4483e780117add1912d22 {
	meta:
		aliases = "__GI_closelog, closelog"
		type = "func"
		size = "59"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 FF E8 82 FF FF FF BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule setspent_63f1914dc9b6c5c4d25d775c102131bc {
	meta:
		aliases = "setgrent, setpwent, setspent"
		type = "func"
		size = "69"
		objfiles = "getgrent_r@libc.a, getspent_r@libc.a, getpwent_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 85 FF 74 05 E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule endnetent_f174803963fbe04ea05a4923c07341ba {
	meta:
		aliases = "__GI_endnetent, endnetent"
		type = "func"
		size = "90"
		objfiles = "getnetent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 85 FF 74 10 E8 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 48 89 E7 BE 01 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule endservent_d7e3fd16505c9238e0851a2064f1f0bc {
	meta:
		aliases = "__GI_endprotoent, __GI_endservent, endprotoent, endservent"
		type = "func"
		size = "90"
		objfiles = "getservice@libc.a, getproto@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 85 FF 74 10 E8 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 BE 01 00 00 00 48 89 E7 C7 05 ?? ?? ?? ?? 00 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule endspent_335155307178b13d6c68d900ad3e4402 {
	meta:
		aliases = "endgrent, endpwent, endspent"
		type = "func"
		size = "80"
		objfiles = "getgrent_r@libc.a, getspent_r@libc.a, getpwent_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 85 FF 74 10 E8 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule endhostent_35a2a6e1f0045ddd9b0f4a8c3f9f7cac {
	meta:
		aliases = "endhostent"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "57"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 73 FD FF FF BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule random_3775a38b8149f5b2dc0670a1263fa1ca {
	meta:
		aliases = "__GI_random, random"
		type = "func"
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
		type = "func"
		size = "90"
		objfiles = "gethostent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 83 EC 30 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 4C 24 28 49 89 C0 BA B2 00 00 00 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 8B 44 24 28 48 83 C4 30 5B C3 }
	condition:
		$pattern
}

rule _create_xid_c0401287f6e7ddf970e924ff7309f353 {
	meta:
		aliases = "_create_xid"
		type = "func"
		size = "123"
		objfiles = "create_xid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 83 EC 40 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 75 2A 48 8D 7C 24 20 31 F6 E8 ?? ?? ?? ?? 48 8B 7C 24 20 48 33 7C 24 28 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 01 00 00 00 48 8D 74 24 38 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 8B 44 24 38 48 83 C4 40 5B C3 }
	condition:
		$pattern
}

rule getmntent_54aeada02e838e9de789a7da7daf6a62 {
	meta:
		aliases = "getmntent"
		type = "func"
		size = "123"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 FB 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 3D ?? ?? ?? ?? 00 75 1B BF 00 10 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 75 05 E8 ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? 48 89 DF B9 00 10 00 00 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 E7 48 89 C3 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule pututline_951057dc3db20418ea021763c675f466 {
	meta:
		aliases = "pututline"
		type = "func"
		size = "158"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 FB 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? BA 01 00 00 00 48 C7 C6 70 FE FF FF E8 ?? ?? ?? ?? 48 89 DF E8 57 FF FF FF 48 85 C0 BA 01 00 00 00 48 C7 C6 70 FE FF FF 75 07 BA 02 00 00 00 31 F6 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 48 89 DE BA 90 01 00 00 E8 ?? ?? ?? ?? 48 3D 90 01 00 00 B8 00 00 00 00 48 89 E7 48 0F 45 D8 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule setservent_353389afcffdbe91369d812b6a0deaa9 {
	meta:
		aliases = "__GI_setnetent, __GI_setprotoent, __GI_setservent, setnetent, setprotoent, setservent"
		type = "func"
		size = "115"
		objfiles = "getnetent@libc.a, getservice@libc.a, getproto@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 89 FB 48 83 EC 20 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 85 FF 75 18 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? EB 05 E8 ?? ?? ?? ?? 85 DB B8 01 00 00 00 0F 44 05 ?? ?? ?? ?? 48 89 E7 BE 01 00 00 00 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule __uClibc_fini_2d094a893495abb64d424b53f1ba86df {
	meta:
		aliases = "__GI___uClibc_fini, __uClibc_fini"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "43"
		objfiles = "sigpending@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BE 08 00 00 00 B8 7F 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 5B C3 }
	condition:
		$pattern
}

rule sigsuspend_78a15d6def642fe31383c88456ae82a6 {
	meta:
		aliases = "__GI_sigsuspend, __libc_sigsuspend, sigsuspend"
		type = "func"
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
		type = "func"
		size = "44"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) BF 01 00 00 00 48 83 EC 10 48 8D 74 24 0C E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 7C 24 0C 31 F6 89 C3 E8 ?? ?? ?? ?? 5A 59 89 D8 5B C3 }
	condition:
		$pattern
}

rule objalloc_create_18395ee3377292c35453f6c52c26de1f {
	meta:
		aliases = "objalloc_create"
		type = "func"
		size = "96"
		objfiles = "objalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) BF 18 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 3D BF E0 0F 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 43 10 74 2E 48 C7 00 00 00 00 00 48 C7 40 08 00 00 00 00 48 83 C0 10 48 89 03 C7 43 08 D0 0F 00 00 48 89 D8 5B C3 0F 1F 84 00 00 00 00 00 31 C0 5B C3 48 89 DF E8 ?? ?? ?? ?? 31 C0 5B C3 }
	condition:
		$pattern
}

rule get_current_dir_name_8ad3a8606e21746258f044a0e7fbdbd0 {
	meta:
		aliases = "get_current_dir_name"
		type = "func"
		size = "120"
		objfiles = "getdirname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BF ?? ?? ?? ?? 48 81 EC 20 01 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 4C 48 8D B4 24 90 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 75 36 48 89 E6 48 89 DF E8 ?? ?? ?? ?? 85 C0 75 27 48 8B 84 24 90 00 00 00 48 39 04 24 75 19 48 8B 84 24 98 00 00 00 48 39 44 24 08 75 0A 48 89 DF E8 ?? ?? ?? ?? EB 09 31 F6 31 FF E8 ?? ?? ?? ?? 48 81 C4 20 01 00 00 5B C3 }
	condition:
		$pattern
}

rule abort_558560691cd7d3c39a0e5a9d73696796 {
	meta:
		aliases = "__GI_abort, abort"
		type = "func"
		size = "276"
		objfiles = "abort@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BF ?? ?? ?? ?? 48 81 EC 20 01 00 00 E8 ?? ?? ?? ?? BA 10 00 00 00 EB 0F 48 63 C2 48 C7 84 C4 A0 00 00 00 00 00 00 00 FF CA 79 ED 48 8D 9C 24 A0 00 00 00 BE 06 00 00 00 48 89 DF E8 ?? ?? ?? ?? 85 C0 75 0F 31 D2 48 89 DE BF 01 00 00 00 E8 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 75 28 C7 05 ?? ?? ?? ?? 01 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF 06 00 00 00 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 83 F8 01 75 54 BA 98 00 00 00 48 89 E7 31 F6 C7 05 ?? ?? ?? ?? 02 00 00 00 E8 ?? ?? ?? ?? BA 10 00 00 00 48 C7 04 24 00 00 00 00 EB 0C 48 63 C2 48 C7 44 C4 08 FF FF FF FF FF CA 79 F0 }
	condition:
		$pattern
}

rule __pthread_reset_main_thread_6f735ae83deeb1e07d8071b5423b46cd {
	meta:
		aliases = "__pthread_reset_main_thread"
		type = "func"
		size = "140"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) E8 7F FD FF FF 83 3D ?? ?? ?? ?? FF 48 89 C3 74 4C 48 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 48 C7 05 ?? ?? ?? ?? 00 00 00 00 E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? FF FF FF FF C7 05 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 89 43 28 48 89 1D ?? ?? ?? ?? 48 89 1B 48 89 5B 08 48 C7 83 80 00 00 00 ?? ?? ?? ?? 48 C7 83 90 00 00 00 ?? ?? ?? ?? 5B C3 }
	condition:
		$pattern
}

rule getrpcent_df8bea5513198a28018bc3ef8e3468f2 {
	meta:
		aliases = "__GI_getrpcent, getrpcent"
		type = "func"
		size = "56"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) E8 7F FE FF FF 48 85 C0 48 89 C3 74 26 48 83 38 00 75 17 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 03 74 09 48 89 DF 5B E9 B9 FE FF FF 5B 31 C0 C3 }
	condition:
		$pattern
}

rule endrpcent_ce2a43bff82a56b4740e90fbcd7dba35 {
	meta:
		aliases = "__GI_endrpcent, endrpcent"
		type = "func"
		size = "59"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) E8 8C FD FF FF 48 85 C0 48 89 C3 74 2B 83 78 14 00 75 25 48 8B 78 08 E8 ?? ?? ?? ?? 48 8B 3B 48 C7 43 08 00 00 00 00 48 85 FF 74 0C E8 ?? ?? ?? ?? 48 C7 03 00 00 00 00 5B C3 }
	condition:
		$pattern
}

rule _buf_35082f46dcedf2fb58637e5fa7fa2965 {
	meta:
		aliases = "_buf"
		type = "func"
		size = "45"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 53 ) E8 ?? ?? ?? ?? 48 83 B8 B8 00 00 00 00 48 89 C3 75 11 BF 00 01 00 00 E8 ?? ?? ?? ?? 48 89 83 B8 00 00 00 48 8B 83 B8 00 00 00 5B C3 }
	condition:
		$pattern
}

rule freopen_unlocked_4055eda460634cf049c59e12199515a6 {
	meta:
		aliases = "fdopen_unlocked, fopen_unlocked, freopen_unlocked"
		type = "func"
		size = "32"
		objfiles = "fopen_unlocked@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 0D BE 02 00 00 00 48 89 C7 E8 ?? ?? ?? ?? 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule svc_exit_f57330cb3c2c745f78ffb8c84e09c457 {
	meta:
		aliases = "svc_exit"
		type = "func"
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
		type = "func"
		size = "44"
		objfiles = "clnt_simple@libc.a"
	strings:
		$pattern = { ( CC | 53 ) E8 ?? ?? ?? ?? 48 8B 98 C8 00 00 00 48 85 DB 74 18 48 8B 3B 48 85 FF 74 07 48 8B 47 08 FF 50 20 48 89 DF 5B E9 ?? ?? ?? ?? 5B C3 }
	condition:
		$pattern
}

rule svcraw_create_f1910851cd244c422afaf4c8bca643ff {
	meta:
		aliases = "svcraw_create"
		type = "func"
		size = "124"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 53 ) E8 ?? ?? ?? ?? 48 8B 98 F8 00 00 00 48 85 DB 75 19 BE 70 25 00 00 BF 01 00 00 00 E8 ?? ?? ?? ?? 31 D2 48 85 C0 74 4F 48 89 C3 48 8D 83 E0 23 00 00 48 8D BB B0 23 00 00 BA 60 22 00 00 C7 83 60 22 00 00 00 00 00 00 66 C7 83 64 22 00 00 00 00 B9 02 00 00 00 48 C7 83 68 22 00 00 ?? ?? ?? ?? 48 89 83 90 22 00 00 48 89 DE E8 ?? ?? ?? ?? 48 8D 93 60 22 00 00 5B 48 89 D0 C3 }
	condition:
		$pattern
}

rule freeaddrinfo_5d159e3c02b0282edd39ae3e4bb10317 {
	meta:
		aliases = "__GI_freeaddrinfo, freeaddrinfo"
		type = "func"
		size = "22"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { ( CC | 53 ) EB 0C 48 8B 5F 28 E8 ?? ?? ?? ?? 48 89 DF 48 85 FF 75 EF 5B C3 }
	condition:
		$pattern
}

rule __fpclassify_15046b4b71946957558ca3a5c54fb16e {
	meta:
		aliases = "__GI___fpclassify, __fpclassify"
		type = "func"
		size = "71"
		objfiles = "s_fpclassify@libm.a"
	strings:
		$pattern = { ( CC | 53 ) F2 0F 11 44 24 F8 48 8B 44 24 F8 48 89 C2 48 C1 EA 20 89 D1 81 E2 00 00 F0 7F 81 E1 FF FF 0F 00 09 C1 B8 02 00 00 00 89 CB 09 D3 74 17 85 D2 B0 03 74 11 81 FA 00 00 F0 7F B0 04 75 07 31 C0 85 C9 0F 94 C0 5B C3 }
	condition:
		$pattern
}

rule ilogb_e78add134ed35af45ddecf246401ab94 {
	meta:
		aliases = "__GI_ilogb, ilogb"
		type = "func"
		size = "117"
		objfiles = "s_ilogb@libm.a"
	strings:
		$pattern = { ( CC | 53 ) F2 0F 11 44 24 F8 48 8B 44 24 F8 48 C1 E8 20 89 C2 81 E2 FF FF FF 7F 81 FA FF FF 0F 00 7F 3B 48 8B 44 24 F8 89 D3 B9 01 00 00 80 09 C3 74 41 85 D2 B9 ED FB FF FF 74 06 EB 0A FF C9 01 C0 85 C0 7F F8 EB 2C 89 D0 B9 02 FC FF FF C1 E0 0B EB 04 FF C9 01 C0 85 C0 7F F8 EB 16 81 FA FF FF EF 7F B9 FF FF FF 7F 7F 09 C1 FA 14 8D 8A 01 FC FF FF 5B 89 C8 C3 }
	condition:
		$pattern
}

rule cbrt_fb89f642bfbbdc31a7a05abe3699d186 {
	meta:
		aliases = "__GI_cbrt, cbrt"
		type = "func"
		size = "406"
		objfiles = "s_cbrt@libm.a"
	strings:
		$pattern = { ( CC | 53 ) F2 0F 11 44 24 F8 48 8B 44 24 F8 48 C1 E8 20 89 C6 81 E6 00 00 00 80 89 F1 31 C1 81 F9 FF FF EF 7F 7E 09 F2 0F 58 C0 E9 67 01 00 00 F2 0F 11 44 24 F8 48 8B 44 24 F8 89 CA 09 C2 0F 84 52 01 00 00 48 89 CA 83 E0 FF 48 C1 E2 20 48 09 D0 81 F9 FF FF 0F 00 48 89 44 24 F8 F2 0F 10 44 24 F8 0F 28 D8 7F 48 48 B8 00 00 00 00 00 00 50 43 BA 03 00 00 00 66 48 0F 6E C0 89 D3 31 D2 F2 0F 59 C3 F2 0F 11 44 24 F8 48 8B 44 24 F8 48 8B 4C 24 F8 48 C1 E8 20 83 E1 FF F7 F3 05 93 78 7F 29 48 C1 E0 20 48 09 C1 48 89 4C 24 F8 EB 1D 89 C8 BA 03 00 00 00 89 D3 99 F7 FB 89 C1 8D 81 93 78 9F 2A 48 C1 E0 20 48 89 44 }
	condition:
		$pattern
}

rule modff_3ec89df3fa893e9dcae34401331dca33 {
	meta:
		aliases = "modff"
		type = "func"
		size = "40"
		objfiles = "modff@libm.a"
	strings:
		$pattern = { ( CC | 53 ) F3 0F 5A C0 48 89 FB 48 83 EC 10 48 8D 7C 24 08 E8 ?? ?? ?? ?? F2 0F 5A 4C 24 08 F2 0F 5A C0 F3 0F 11 0B 58 5A 5B C3 }
	condition:
		$pattern
}

rule atan_56a8cfe56a377425638f6d121e4ee465 {
	meta:
		aliases = "__GI_atan, atan"
		type = "func"
		size = "512"
		objfiles = "s_atan@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 0F 28 D8 53 48 83 EC 08 F2 0F 11 04 24 48 8B 04 24 48 89 C5 48 C1 ED 20 89 EB 81 E3 FF FF FF 7F 81 FB FF FF 0F 44 7E 35 81 FB 00 00 F0 7F 7F 06 75 0D 85 C0 74 09 F2 0F 58 DB E9 B9 01 00 00 85 ED 7F 0D F2 0F 10 1D ?? ?? ?? ?? E9 A8 01 00 00 F2 0F 10 1D ?? ?? ?? ?? E9 9B 01 00 00 81 FB FF FF DB 3F 7F 2A 81 FB FF FF 1F 3E 0F 8F B3 00 00 00 0F 28 C3 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 0F 87 6E 01 00 00 E9 95 00 00 00 0F 28 C3 E8 ?? ?? ?? ?? 81 FB FF FF F2 3F 0F 28 C8 7F 41 81 FB FF FF E5 3F F2 0F 10 05 ?? ?? ?? ?? 7F 1B 0F 28 D9 31 C0 F2 0F 58 D9 F2 0F 58 0D ?? ?? ?? ?? F2 0F 5C D8 }
	condition:
		$pattern
}

rule __ieee754_j1_627c4a187b74632fc9006ea8f5eda63b {
	meta:
		aliases = "__ieee754_j1"
		type = "func"
		size = "578"
		objfiles = "e_j1@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 0F 28 D8 53 48 83 EC 38 F2 0F 11 44 24 08 48 8B 44 24 08 48 89 C5 48 C1 ED 20 89 EB 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 11 F2 0F 10 25 ?? ?? ?? ?? F2 0F 5E E3 E9 FC 01 00 00 81 FB FF FF FF 3F 0F 8E 33 01 00 00 0F 28 C3 E8 ?? ?? ?? ?? F2 0F 11 44 24 30 E8 ?? ?? ?? ?? F2 0F 11 44 24 10 F2 0F 10 44 24 30 E8 ?? ?? ?? ?? F2 0F 11 44 24 18 81 FB FF FF DF 7F F2 0F 10 44 24 10 F2 0F 5C 44 24 18 F2 0F 11 44 24 28 7F 62 F2 0F 10 44 24 30 F2 0F 58 C0 E8 ?? ?? ?? ?? 0F 28 C8 F2 0F 10 44 24 10 F2 0F 59 44 24 18 66 0F 2E 05 ?? ?? ?? ?? 76 26 F2 0F 10 44 24 10 66 0F 57 05 ?? ?? ?? ?? F2 0F 5C 44 24 18 }
	condition:
		$pattern
}

rule __ieee754_asin_8b896afb144b93b12171151312b42f0f {
	meta:
		aliases = "__ieee754_asin"
		type = "func"
		size = "684"
		objfiles = "e_asin@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 0F 28 D8 53 48 83 EC 48 F2 0F 11 44 24 08 48 8B 44 24 08 48 89 C5 48 C1 ED 20 89 EB 81 E3 FF FF FF 7F 81 FB FF FF EF 3F 7E 33 48 89 C2 8D 83 00 00 10 C0 09 D0 75 19 F2 0F 59 05 ?? ?? ?? ?? F2 0F 59 1D ?? ?? ?? ?? F2 0F 58 D8 E9 51 02 00 00 F2 0F 5C DB F2 0F 5E DB E9 44 02 00 00 81 FB FF FF DF 3F 0F 8F BC 00 00 00 81 FB FF FF 3F 3E F2 0F 10 25 ?? ?? ?? ?? 7F 1A 0F 28 C3 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E C4 0F 87 13 02 00 00 E9 92 00 00 00 0F 28 D3 F2 0F 59 D3 0F 28 CA 0F 28 C2 F2 0F 59 0D ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? F2 0F 58 0D ?? ?? ?? ?? F2 0F 5C 05 ?? ?? ?? ?? F2 0F 59 CA F2 0F 59 }
	condition:
		$pattern
}

rule erf_058c20886efaaee72eb281ada32b28b1 {
	meta:
		aliases = "__GI_erf, erf"
		type = "func"
		size = "1149"
		objfiles = "s_erf@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 0F 28 D8 53 48 83 EC 58 F2 0F 11 44 24 08 48 8B 44 24 08 48 89 C5 48 C1 ED 20 89 EB 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 27 F2 0F 10 05 ?? ?? ?? ?? C1 ED 1F 8D 44 2D 00 BA 01 00 00 00 F2 0F 5E C3 29 C2 F2 0F 2A D2 F2 0F 58 D0 E9 21 04 00 00 81 FB FF FF EA 3F 0F 8F D6 00 00 00 81 FB FF FF 2F 3E 7F 3C 81 FB FF FF 7F 00 7F 24 0F 28 D3 F2 0F 59 1D ?? ?? ?? ?? F2 0F 59 15 ?? ?? ?? ?? F2 0F 58 D3 F2 0F 59 15 ?? ?? ?? ?? E9 E1 03 00 00 0F 28 D3 F2 0F 59 15 ?? ?? ?? ?? E9 89 00 00 00 0F 28 CB F2 0F 59 CB 0F 28 C1 0F 28 D1 F2 0F 59 05 ?? ?? ?? ?? F2 0F 59 15 ?? ?? ?? ?? F2 0F 58 05 ?? ?? ?? ?? F2 }
	condition:
		$pattern
}

rule fdopen_d0b139ab452977164ee2df647ea15065 {
	meta:
		aliases = "__GI_fdopen, fdopen"
		type = "func"
		size = "53"
		objfiles = "fdopen@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 31 C0 48 89 F5 BE 03 00 00 00 53 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 83 F8 FF 74 13 41 58 89 D9 48 89 EE 48 63 F8 5B 5D 31 D2 E9 ?? ?? ?? ?? 5A 5B 5D 31 C0 C3 }
	condition:
		$pattern
}

rule xdrmem_putbytes_87acccbe24ba9a537c32256f02d3824f {
	meta:
		aliases = "xdrmem_putbytes"
		type = "func"
		size = "50"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 31 C0 48 89 FD 53 48 83 EC 08 8B 4F 28 39 D1 72 1C 29 D1 89 D3 89 4F 28 48 8B 7F 18 48 89 DA E8 ?? ?? ?? ?? 48 01 5D 18 B8 01 00 00 00 5A 5B 5D C3 }
	condition:
		$pattern
}

rule __check_one_fd_2d87797fbc91abdbb8eaf5d7597fe286 {
	meta:
		aliases = "__check_one_fd"
		type = "func"
		size = "53"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 31 C0 89 FD 53 89 F3 BE 01 00 00 00 48 83 EC 08 E8 ?? ?? ?? ?? FF C0 75 17 31 C0 89 DE BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 39 E8 74 05 E8 ?? ?? ?? ?? 58 5B 5D C3 }
	condition:
		$pattern
}

rule htab_remove_elt_with_hash_4e2074c58398dd26aa62eeccc3da40e4 {
	meta:
		aliases = "htab_remove_elt_with_hash"
		type = "func"
		size = "58"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 31 C9 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 48 8B 38 48 89 C5 48 85 FF 74 18 48 8B 43 10 48 85 C0 74 02 FF D0 48 C7 45 00 01 00 00 00 48 83 43 30 01 48 83 C4 08 5B 5D C3 }
	condition:
		$pattern
}

rule updwtmp_f10f237ac4e24ec2038767db3693e53c {
	meta:
		aliases = "updwtmp"
		type = "func"
		size = "87"
		objfiles = "wtent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 31 D2 31 C0 48 89 F5 BE 01 04 00 00 53 48 83 EC 08 E8 ?? ?? ?? ?? 85 C0 89 C3 78 36 31 D2 BE 01 00 00 00 89 C7 E8 ?? ?? ?? ?? 85 C0 75 24 48 89 EE 89 DF BA 90 01 00 00 E8 ?? ?? ?? ?? 89 DF 31 D2 31 F6 E8 ?? ?? ?? ?? 5A 89 DF 5B 5D E9 ?? ?? ?? ?? 58 5B 5D C3 }
	condition:
		$pattern
}

rule tmpfile64_8cb70446911c26228b25aea9deb1543e {
	meta:
		aliases = "tmpfile, tmpfile64"
		type = "func"
		size = "101"
		objfiles = "tmpfile@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 31 D2 B9 ?? ?? ?? ?? BE FF 0F 00 00 53 48 81 EC 08 10 00 00 48 89 E7 E8 ?? ?? ?? ?? 85 C0 75 35 31 F6 48 89 E7 E8 ?? ?? ?? ?? 85 C0 89 C5 78 25 48 89 E7 E8 ?? ?? ?? ?? BE ?? ?? ?? ?? 89 EF E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 75 0B 89 EF E8 ?? ?? ?? ?? EB 02 31 DB 48 89 D8 48 81 C4 08 10 00 00 5B 5D C3 }
	condition:
		$pattern
}

rule strrchr_9d4984b0ebb3046048b975babcba1092 {
	meta:
		aliases = "__GI_strrchr, rindex, strrchr"
		type = "func"
		size = "53"
		objfiles = "strrchr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 31 ED 53 40 0F B6 DE 48 83 EC 08 40 84 F6 75 11 59 5B 5D 31 F6 E9 ?? ?? ?? ?? 48 8D 78 01 48 89 C5 89 DE E8 ?? ?? ?? ?? 48 85 C0 75 ED 5A 5B 48 89 E8 5D C3 }
	condition:
		$pattern
}

rule globfree64_7e9f6ba40cbaffbaa6b5c647f90944a6 {
	meta:
		aliases = "__GI_globfree, __GI_globfree64, globfree, globfree64"
		type = "func"
		size = "70"
		objfiles = "glob64@libc.a, glob@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 31 ED 53 48 89 FB 48 83 EC 08 48 83 7F 08 00 75 1A EB 2E 48 89 E8 48 03 43 10 48 8B 3C C7 48 85 FF 74 05 E8 ?? ?? ?? ?? 48 FF C5 48 3B 2B 48 8B 7B 08 72 DF E8 ?? ?? ?? ?? 48 C7 43 08 00 00 00 00 58 5B 5D C3 }
	condition:
		$pattern
}

rule join_extricate_func_2b6450e53c385b1e5d5c99131fe9dc59 {
	meta:
		aliases = "join_extricate_func"
		type = "func"
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
		type = "func"
		size = "194"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 31 F6 48 89 FD 53 48 83 EC 08 48 8B 47 20 25 FF 03 00 00 48 C1 E0 05 48 8D 98 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 DF 48 C7 43 10 00 00 00 00 48 C7 43 18 FF FF FF FF E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? FF C8 89 05 ?? ?? ?? ?? 48 8B BD E0 02 00 00 EB 0B 48 8B 1F E8 ?? ?? ?? ?? 48 89 DF 48 85 FF 75 F0 48 8B BD E8 02 00 00 EB 0B 48 8B 1F E8 ?? ?? ?? ?? 48 89 DF 48 85 FF 75 F0 48 81 FD ?? ?? ?? ?? 74 36 83 BD 80 02 00 00 00 75 2D 48 8B B5 90 02 00 00 48 85 F6 74 0C 48 8B BD 88 02 00 00 E8 ?? ?? ?? ?? 41 58 5B 48 8D BD 00 03 E0 FF BE 00 00 20 00 5D E9 ?? ?? ?? ?? 59 5B 5D C3 }
	condition:
		$pattern
}

rule pthread_cond_signal_fdc24a15e143bbc5586e27d1fb2e3820 {
	meta:
		aliases = "__GI_pthread_cond_signal, pthread_cond_signal"
		type = "func"
		size = "75"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 31 F6 48 89 FD 53 48 83 EC 08 E8 ?? ?? ?? ?? 48 8B 5D 10 48 85 DB 74 10 48 8B 43 10 48 89 45 10 48 C7 43 10 00 00 00 00 48 89 EF E8 ?? ?? ?? ?? 48 85 DB 74 0F C6 83 D1 02 00 00 01 48 89 DF E8 AA FB FF FF 5E 5B 5D 31 C0 C3 }
	condition:
		$pattern
}

rule __pthread_wait_for_restart_sig_30cc65ba695402206766d9b3da29fa92 {
	meta:
		aliases = "__pthread_wait_for_restart_signal"
		type = "func"
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
		type = "func"
		size = "79"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 31 F6 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 48 8B 6B 10 48 89 DF 48 C7 43 10 00 00 00 00 E8 ?? ?? ?? ?? EB 1E 48 8B 5D 10 C6 85 D1 02 00 00 01 48 C7 45 10 00 00 00 00 48 89 EF 48 89 DD E8 B7 FF FF FF 48 85 ED 75 DD 59 5B 5D 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_rwlock_unlock_f37113e15446673e26217a897b7ae475 {
	meta:
		aliases = "pthread_rwlock_unlock"
		type = "func"
		size = "348"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 31 F6 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 48 8B 6B 18 48 85 ED 74 7D E8 EC FC FF FF 48 39 C5 75 7A 83 7B 30 00 48 C7 43 18 00 00 00 00 74 2E 48 8B 6B 28 48 85 ED 74 25 48 8B 45 10 48 89 DF 48 89 43 28 48 C7 45 10 00 00 00 00 E8 ?? ?? ?? ?? 48 89 EF E8 AB FC FF FF E9 F7 00 00 00 48 8B 6B 20 48 89 DF 48 C7 43 20 00 00 00 00 E8 ?? ?? ?? ?? EB 17 48 8B 5D 10 48 89 EF 48 C7 45 10 00 00 00 00 E8 7C FC FF FF 48 89 DD 48 85 ED 75 E4 E9 C0 00 00 00 8B 43 10 85 C0 75 12 48 89 DF E8 ?? ?? ?? ?? B8 01 00 00 00 E9 A9 00 00 00 FF C8 31 ED 85 C0 89 43 10 75 19 48 8B 6B 28 48 85 ED 74 10 48 8B 45 10 48 }
	condition:
		$pattern
}

rule pthread_rwlock_trywrlock_5266f2afbe4288d1db3ad0e3a586f987 {
	meta:
		aliases = "pthread_rwlock_trywrlock"
		type = "func"
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
		type = "func"
		size = "61"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 31 F6 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 8B 43 10 85 C0 75 10 83 CD FF E8 ?? ?? ?? ?? C7 00 0B 00 00 00 EB 07 FF C8 31 ED 89 43 10 48 89 DF E8 ?? ?? ?? ?? 41 59 5B 89 E8 5D C3 }
	condition:
		$pattern
}

rule sigrelse_44df9f2595067b9c4a71b67112fb6976 {
	meta:
		aliases = "sighold, sigrelse"
		type = "func"
		size = "74"
		objfiles = "sigrelse@libc.a, sighold@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 31 F6 89 FD BF 02 00 00 00 53 48 81 EC 88 00 00 00 48 89 E2 E8 ?? ?? ?? ?? 85 C0 78 1F 89 EE 48 89 E7 E8 ?? ?? ?? ?? 85 C0 78 11 31 D2 48 89 E6 BF 02 00 00 00 E8 ?? ?? ?? ?? EB 03 83 C8 FF 48 81 C4 88 00 00 00 5B 5D C3 }
	condition:
		$pattern
}

rule __strtofpmax_47d233e2faacf0c886de7f417bf703d9 {
	meta:
		aliases = "__strtofpmax"
		type = "func"
		size = "578"
		objfiles = "__strtofpmax@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 41 89 D0 48 89 F5 53 48 89 FB 48 83 EC 28 EB 03 48 FF C3 8A 13 4C 8B 15 ?? ?? ?? ?? 48 0F BE C2 41 F6 04 42 20 75 E9 80 FA 2B 74 0D 45 31 DB 80 FA 2D 75 0B 41 B3 01 EB 03 45 31 DB 48 FF C3 D9 EE 31 F6 83 C9 FF D9 05 ?? ?? ?? ?? EB 2E 81 F9 00 00 00 80 83 D9 FF 85 C9 75 05 80 FA 30 74 19 FF C1 83 F9 15 7F 12 DC C9 0F BE C2 83 E8 30 89 44 24 80 DB 44 24 80 DE C2 48 FF C3 8A 13 48 0F BE C2 41 F6 04 42 08 75 C5 80 FA 2E 75 0D 48 85 F6 75 08 48 FF C3 48 89 DE EB E1 DD D8 85 C9 0F 89 A3 00 00 00 48 85 F6 0F 85 92 00 00 00 44 8D 4E 01 45 31 C0 EB 4A 41 FF C0 43 8D 04 08 48 98 80 B8 ?? ?? ?? ?? 00 }
	condition:
		$pattern
}

rule pmap_getmaps_c3e654991829285528e823e1be90a94d {
	meta:
		aliases = "pmap_getmaps"
		type = "func"
		size = "187"
		objfiles = "pm_getmaps@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 41 B9 F4 01 00 00 41 B8 32 00 00 00 BA 02 00 00 00 BE A0 86 01 00 48 89 FD 53 48 83 EC 38 48 8D 4C 24 2C 48 C7 44 24 20 00 00 00 00 C7 44 24 2C FF FF FF FF 66 C7 47 02 00 6F E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 61 48 8B 40 08 31 C9 4C 8D 4C 24 20 41 B8 ?? ?? ?? ?? BA ?? ?? ?? ?? BE 04 00 00 00 48 89 DF 48 8B 00 48 C7 44 24 10 3C 00 00 00 48 C7 44 24 18 00 00 00 00 48 C7 04 24 3C 00 00 00 48 C7 44 24 08 00 00 00 00 FF D0 85 C0 74 0D BE ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8B 43 08 48 89 DF FF 50 20 66 C7 45 02 00 00 48 8B 44 24 20 48 83 C4 38 5B 5D C3 }
	condition:
		$pattern
}

rule fibheap_extr_min_node_1b5e01e6119e56c36801a5340227c8d0 {
	meta:
		aliases = "fibheap_extr_min_node"
		type = "func"
		size = "210"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 45 31 C0 53 48 89 FB 48 83 EC 08 48 8B 6F 08 48 8B 55 08 EB 2A 66 2E 0F 1F 84 00 00 00 00 00 4C 8B 49 18 4C 39 C9 74 4F 4C 89 4A 18 48 8B 79 18 48 89 57 10 48 89 51 18 48 89 4A 10 4C 89 D2 48 85 D2 74 4B 4C 39 C2 74 46 48 C7 02 00 00 00 00 48 8B 4B 10 4D 85 C0 4C 0F 44 C2 4C 8B 52 18 48 85 C9 75 BB 48 89 53 10 48 89 52 10 48 89 52 18 EB CA 0F 1F 44 00 00 48 89 51 18 48 89 51 10 48 89 4A 18 48 89 4A 10 EB B3 66 0F 1F 44 00 00 48 8D 7B 10 48 89 EE E8 54 FD FF FF 48 83 2B 01 75 16 48 C7 43 08 00 00 00 00 48 83 C4 08 48 89 E8 5B 5D C3 0F 1F 40 00 48 8B 45 18 48 89 DF 48 89 43 08 E8 88 FD FF FF }
	condition:
		$pattern
}

rule _exit_3df918f919cd08f91435959ee9cfd79e {
	meta:
		aliases = "__GI__exit, _exit"
		type = "func"
		size = "43"
		objfiles = "_exit@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 63 EF 53 48 83 EC 08 48 89 EF B8 3C 00 00 00 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 EB E8 ?? ?? ?? ?? 89 DA F7 DA 89 10 EB DE }
	condition:
		$pattern
}

rule jrand48_r_4cabdd380d6101f5f4bfffd44174db66 {
	meta:
		aliases = "__GI_jrand48_r, jrand48_r"
		type = "func"
		size = "49"
		objfiles = "jrand48_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 D5 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 83 CA FF 85 C0 78 13 0F B7 43 04 0F B7 53 02 C1 E0 10 09 D0 31 D2 48 89 45 00 89 D0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule nrand48_r_0e88ac9542acbd82e8f294c797c5ad6c {
	meta:
		aliases = "__GI_nrand48_r, nrand48_r"
		type = "func"
		size = "57"
		objfiles = "nrand48_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 D5 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 83 CA FF 85 C0 78 1B 66 8B 43 02 0F B7 53 04 66 D1 E8 C1 E2 0F 0F B7 C0 09 D0 31 D2 48 98 48 89 45 00 89 D0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule erand48_r_479ae23ab5ef854bdd007efecaf3cc77 {
	meta:
		aliases = "__GI_erand48_r, erand48_r"
		type = "func"
		size = "127"
		objfiles = "erand48_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 D5 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 83 CA FF 85 C0 78 61 66 8B 73 02 0F B7 43 04 89 D9 89 F2 C1 E6 14 66 C1 EA 0C C1 E0 04 0F B7 D2 09 C2 48 B8 00 00 00 00 00 00 F0 3F 48 09 C1 0F B7 03 48 C1 E2 20 48 09 D1 31 D2 C1 E0 04 09 C6 48 B8 00 00 00 00 FF FF FF FF 89 F6 48 21 C1 48 09 F1 48 89 0C 24 F2 0F 10 04 24 F2 0F 5C 05 ?? ?? ?? ?? F2 0F 11 45 00 89 D0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule is_ctor_or_dtor_df0b7164ebf6a7df316ab26ab2581e28 {
	meta:
		aliases = "is_ctor_or_dtor"
		type = "func"
		size = "262"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 55 49 89 FD 41 54 49 89 D4 53 48 89 F3 48 83 EC 68 C7 06 00 00 00 00 C7 02 00 00 00 00 E8 ?? ?? ?? ?? 49 8D 54 05 00 89 45 BC 48 8D 7D 80 BE 01 00 00 00 4C 89 6D 80 C7 45 90 00 40 00 00 48 89 55 88 8D 14 00 48 98 48 8D 04 C5 16 00 00 00 4C 89 6D 98 C7 45 A8 00 00 00 00 89 55 AC 48 63 D2 C7 45 B8 00 00 00 00 48 8D 14 52 48 83 E0 F0 C7 45 C0 00 00 00 00 48 C7 45 C8 00 00 00 00 C7 45 D0 00 00 00 00 48 8D 14 D5 10 00 00 00 48 29 D4 48 89 E2 48 29 C4 48 89 55 A0 48 89 65 B0 E8 ?? ?? ?? ?? 48 89 C1 31 C0 0F 1F 00 48 85 C9 74 1F 83 39 1B 77 1A 8B 39 FF 24 FD ?? ?? ?? ?? 0F 1F 44 00 00 }
	condition:
		$pattern
}

rule nan_55e924c3c1a4d8ae9b4c9791797674ca {
	meta:
		aliases = "__GI_nan, nan"
		type = "func"
		size = "101"
		objfiles = "nan@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 55 49 89 FD 41 54 53 48 83 EC 08 80 3F 00 75 0A F2 0F 10 05 ?? ?? ?? ?? EB 3B E8 ?? ?? ?? ?? 48 83 C0 24 48 89 E3 4C 89 EA 48 83 E0 F0 BE ?? ?? ?? ?? 48 29 C4 31 C0 4C 8D 64 24 0F 49 83 E4 F0 4C 89 E7 E8 ?? ?? ?? ?? 31 F6 4C 89 E7 E8 ?? ?? ?? ?? 48 89 DC 48 8D 65 E8 5B 41 5C 41 5D C9 C3 }
	condition:
		$pattern
}

rule nanf_da26161b67457fd42c595f0ba662902c {
	meta:
		aliases = "__GI_nanf, nanf"
		type = "func"
		size = "101"
		objfiles = "nan@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 55 49 89 FD 41 54 53 48 83 EC 08 80 3F 00 75 0A F3 0F 10 05 ?? ?? ?? ?? EB 3B E8 ?? ?? ?? ?? 48 83 C0 24 48 89 E3 4C 89 EA 48 83 E0 F0 BE ?? ?? ?? ?? 48 29 C4 31 C0 4C 8D 64 24 0F 49 83 E4 F0 4C 89 E7 E8 ?? ?? ?? ?? 31 F6 4C 89 E7 E8 ?? ?? ?? ?? 48 89 DC 48 8D 65 E8 5B 41 5C 41 5D C9 C3 }
	condition:
		$pattern
}

rule __msgwrite_c92c6e9f41f486cde81ac38810f9334b {
	meta:
		aliases = "__msgwrite"
		type = "func"
		size = "204"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 56 41 89 FE 41 55 49 89 D5 41 54 49 89 F4 53 48 81 EC 90 00 00 00 48 8D 5C 24 0F E8 ?? ?? ?? ?? 48 83 E3 F0 89 45 D0 E8 ?? ?? ?? ?? 89 45 D4 E8 ?? ?? ?? ?? 48 8D 7B 10 48 8D 75 D0 BA 0C 00 00 00 89 45 D8 E8 ?? ?? ?? ?? 48 8D 45 C0 C7 43 08 01 00 00 00 C7 43 0C 02 00 00 00 48 C7 03 1C 00 00 00 48 89 5D A0 48 8D 5D 80 4C 89 65 C0 4C 89 6D C8 48 89 45 90 48 C7 45 98 01 00 00 00 48 C7 45 80 00 00 00 00 C7 45 88 00 00 00 00 48 C7 45 A8 20 00 00 00 C7 45 B0 00 00 00 00 31 D2 48 89 DE 44 89 F7 E8 ?? ?? ?? ?? 85 C0 79 0D E8 ?? ?? ?? ?? 83 38 04 74 E5 83 C8 FF 48 8D 65 E0 5B 41 5C 41 5D }
	condition:
		$pattern
}

rule execvp_6a961f42c7992f6341475542378e8ceb {
	meta:
		aliases = "__GI_execvp, execvp"
		type = "func"
		size = "478"
		objfiles = "execvp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 41 55 41 54 49 89 FC 53 48 83 EC 18 48 89 75 C0 80 3F 00 75 10 E8 ?? ?? ?? ?? C7 00 02 00 00 00 E9 9F 01 00 00 BE 2F 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 0F 84 82 00 00 00 48 8B 15 ?? ?? ?? ?? 48 8B 75 C0 4C 89 E7 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 38 08 0F 85 6B 01 00 00 31 C0 EB 03 48 FF C0 48 8B 4D C0 48 8D 14 C5 00 00 00 00 48 83 3C 11 00 75 EA 48 8D 42 2E 48 89 CE 48 83 C6 08 48 83 E0 F0 48 29 C4 48 8B 01 48 8D 5C 24 0F 48 83 E3 F0 48 8D 7B 10 48 89 03 4C 89 63 08 E8 ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? 48 89 DE BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 0A 01 00 00 BF ?? ?? ?? ?? E8 }
	condition:
		$pattern
}

rule byte_re_match_2_internal_a3ea3c52e872e49c847c0f6d3091731d {
	meta:
		aliases = "byte_re_match_2_internal"
		type = "func"
		size = "7564"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 41 55 41 54 53 48 81 EC 68 01 00 00 48 89 B5 E0 FE FF FF 44 89 8D C8 FE FF FF 48 89 BD E8 FE FF FF 89 95 DC FE FF FF 4C 8D 4C 24 0F 48 89 8D D0 FE FF FF 44 89 85 CC FE FF FF 4C 8B 27 48 8B 47 10 49 83 E1 F0 8B 75 18 4C 01 E0 48 89 85 28 FF FF FF 48 8B 57 28 48 89 95 38 FF FF FF 48 8B 4F 30 48 FF C1 48 89 8D 40 FF FF FF 48 83 7F 30 00 75 5C 48 C7 85 58 FF FF FF 00 00 00 00 48 C7 85 60 FF FF FF 00 00 00 00 48 C7 85 68 FF FF FF 00 00 00 00 48 C7 85 70 FF FF FF 00 00 00 00 48 C7 85 78 FF FF FF 00 00 00 00 48 C7 45 88 00 00 00 00 48 C7 45 90 00 00 00 00 48 C7 45 A8 00 00 00 }
	condition:
		$pattern
}

rule clntudp_call_dc8c4f065759a3270a12e38db73d1d0a {
	meta:
		aliases = "clntudp_call"
		type = "func"
		size = "1596"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 41 55 41 54 53 48 81 EC F8 23 00 00 48 89 B5 58 DC FF FF 48 89 95 18 DC FF FF 48 89 8D 10 DC FF FF 4C 89 85 08 DC FF FF 41 B8 E8 03 00 00 48 89 BD 20 DC FF FF 4C 89 8D 00 DC FF FF 4C 8B 67 10 48 8B 4D 18 48 8B 75 10 49 8B 7C 24 28 48 89 F8 48 99 49 F7 F8 48 89 C7 49 69 44 24 20 E8 03 00 00 01 C7 89 BD 30 DC FF FF 49 83 7C 24 38 FF 75 10 48 89 8D 40 DC FF FF 48 89 B5 48 DC FF FF EB 18 49 8B 4C 24 38 48 89 8D 40 DC FF FF 49 8B 44 24 30 48 89 85 48 DC FF FF 48 8D 4D A0 48 8D 95 D8 FE FF FF 48 8D 85 50 FF FF FF C7 85 2C DC FF FF 00 00 00 00 C7 85 34 DC FF FF 02 00 00 00 48 }
	condition:
		$pattern
}

rule search_for_named_library_e1d7c4c32fe1b637dbdf6577a361238a {
	meta:
		aliases = "search_for_named_library"
		type = "func"
		size = "330"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC 18 48 85 D2 89 75 D4 48 89 4D C8 0F 84 18 01 00 00 48 8D 42 FF 48 FF C0 80 38 00 75 F8 48 29 D0 48 FF CA FF C0 4C 63 C0 49 8D 40 1E 48 83 E0 F0 48 29 C4 48 8D 74 24 0F 48 81 EC 20 08 00 00 4C 8D 64 24 0F 48 83 E6 F0 48 8D 4E FF 48 89 F3 49 83 E4 F0 EB 0D 48 FF C2 48 FF C1 49 FF C8 8A 02 88 01 4D 85 C0 75 EE 4D 8D 6C 24 FF 4C 8D 77 FF 48 89 F0 45 31 FF 80 3B 00 75 09 C6 03 3A 41 BF 01 00 00 00 80 3B 3A 0F 85 8F 00 00 00 C6 03 00 80 38 00 74 17 48 8D 50 FF 4C 89 E9 48 FF C2 48 FF C1 8A 02 84 C0 88 01 74 18 EB F0 4C 89 EA B9 ?? ?? ?? ?? 48 FF C1 48 }
	condition:
		$pattern
}

rule if_nameindex_3b78eadf27ec6a161e8a0a274e0a17fa {
	meta:
		aliases = "__GI_if_nameindex, if_nameindex"
		type = "func"
		size = "445"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC 28 E8 ?? ?? ?? ?? 85 C0 41 89 C5 48 C7 45 B8 00 00 00 00 0F 88 81 01 00 00 4C 8D 65 C0 48 C7 45 C8 00 00 00 00 BE A0 00 00 00 8D 1C 36 44 89 EF 48 63 D3 48 8D 42 1E 48 83 E0 F0 48 29 C4 48 8D 44 24 0F 48 83 E0 F0 48 8D 0C 10 48 3B 4D C8 8D 14 16 48 89 45 C8 BE 12 89 00 00 0F 44 DA 31 C0 4C 89 E2 89 5D C0 E8 ?? ?? ?? ?? 85 C0 79 0D 44 89 EF E8 ?? ?? ?? ?? E9 E0 00 00 00 8B 45 C0 39 D8 75 04 89 C6 EB A3 BA 28 00 00 00 48 98 45 31 F6 48 89 D1 31 D2 48 F7 F1 8D 78 01 41 89 C7 48 C1 E7 04 E8 ?? ?? ?? ?? 48 85 C0 48 89 45 B8 0F 85 BB 00 00 00 44 89 EF }
	condition:
		$pattern
}

rule buildargv_d27a8daac2813845ee512a572866cbe4 {
	meta:
		aliases = "buildargv"
		type = "func"
		size = "606"
		objfiles = "argv@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 41 55 41 54 53 48 89 FB 48 83 EC 28 48 85 FF 0F 84 29 02 00 00 E8 ?? ?? ?? ?? 48 83 C0 1F 45 31 F6 C7 45 C8 00 00 00 00 48 83 E0 F0 C7 45 CC 00 00 00 00 45 31 E4 48 29 C4 45 31 ED 45 31 FF 48 8D 44 24 0F 48 89 45 C0 48 83 65 C0 F0 0F 1F 00 0F B6 03 0F B6 D0 F6 84 12 ?? ?? ?? ?? 01 0F 85 44 01 00 00 8B 55 C8 85 D2 0F 84 49 01 00 00 8B 4D C8 8D 51 FF 39 55 CC 0F 8D 3A 01 00 00 48 63 55 CC 4D 8D 14 D6 84 C0 48 8B 55 C0 75 1E EB 68 0F 1F 84 00 00 00 00 00 88 02 45 31 E4 48 83 C2 01 48 83 C3 01 0F B6 03 84 C0 74 4C 0F B6 F0 F6 84 36 ?? ?? ?? ?? 40 74 0F 44 89 EE 44 09 FE 44 }
	condition:
		$pattern
}

rule iruserok2_ce4c74117e6181fa1f9f41a63fec86c9 {
	meta:
		aliases = "iruserok2"
		type = "func"
		size = "364"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 41 55 49 89 CD 41 54 41 89 F4 53 48 83 EC 68 85 F6 89 7D 8C 48 89 55 80 4C 89 85 78 FF FF FF 75 14 31 F6 BF ?? ?? ?? ?? E8 33 FF FF FF 48 85 C0 48 89 C3 75 06 41 83 CE FF EB 2D 4C 8B 85 78 FF FF FF 48 8B 4D 80 4C 89 EA 8B 75 8C 48 89 C7 E8 0F FC FF FF 48 89 DF 41 89 C6 E8 ?? ?? ?? ?? 45 85 F6 0F 84 EA 00 00 00 44 0B 25 ?? ?? ?? ?? 0F 84 D9 00 00 00 BF 46 00 00 00 E8 ?? ?? ?? ?? 48 89 C1 48 8D 40 1E 48 8D 75 90 4C 8D 45 C8 4C 89 EF 48 83 E0 F0 48 29 C4 48 8D 54 24 0F 48 83 E2 F0 E8 ?? ?? ?? ?? 85 C0 0F 85 A0 00 00 00 48 8B 45 C8 48 85 C0 0F 84 93 00 00 00 48 8B 78 20 E8 }
	condition:
		$pattern
}

rule realpath_acfb169cc589aba726ed9c0d1c60a63f {
	meta:
		aliases = "realpath"
		type = "func"
		size = "707"
		objfiles = "realpath@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 41 55 49 89 F5 41 54 49 89 FC 53 48 81 EC 38 10 00 00 48 85 FF 75 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 7F 02 00 00 80 3F 00 75 10 E8 ?? ?? ?? ?? C7 00 02 00 00 00 E9 6A 02 00 00 48 85 F6 C7 85 C0 EF FF FF 00 00 00 00 75 1A 48 81 EC 10 10 00 00 C7 85 C0 EF FF FF 01 00 00 00 4C 8D 6C 24 0F 49 83 E5 F0 4C 89 E7 E8 ?? ?? ?? ?? 48 3D FD 0F 00 00 0F 87 F5 00 00 00 48 8D 5D CF 4C 89 E6 48 29 C3 48 89 DF E8 ?? ?? ?? ?? 49 8D 85 FE 0F 00 00 48 89 85 B0 EF FF FF 80 3B 2F 74 62 BE FF 0F 00 00 4C 89 EF E8 ?? ?? ?? ?? 48 85 C0 0F 84 F2 01 00 00 4C 89 EF E8 ?? ?? ?? ?? 4D 8D 64 05 }
	condition:
		$pattern
}

rule glob_in_dir_93253160aebc73d344e91266dd19d244 {
	meta:
		aliases = "glob_in_dir"
		type = "func"
		size = "1306"
		objfiles = "glob64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 41 89 D6 41 55 41 54 49 89 CC 53 44 89 F3 48 81 EC 68 01 00 00 48 89 BD 88 FE FF FF 48 89 B5 80 FE FF FF 48 89 F7 4C 89 85 78 FE FF FF E8 ?? ?? ?? ?? 83 E3 40 48 8B BD 88 FE FF FF 48 89 85 90 FE FF FF 40 0F 94 C6 40 0F B6 F6 E8 ?? ?? ?? ?? 85 C0 0F 85 CE 00 00 00 41 F7 C6 10 08 00 00 0F 85 B8 00 00 00 85 DB 75 1A 48 8B BD 88 FE FF FF BE 5C 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 0F 85 A3 00 00 00 48 8B BD 88 FE FF FF E8 ?? ?? ?? ?? 48 8B 95 90 FE FF FF 48 89 C3 48 8B B5 80 FE FF FF 48 8D 44 10 20 48 83 E0 F0 48 29 C4 4C 8D 64 24 0F 49 83 E4 F0 4C 89 E7 E8 ?? ?? ?? ?? BA 01 00 }
	condition:
		$pattern
}

rule d_demangle_55a3aa4ec58bb26f365ce42456b24057 {
	meta:
		aliases = "d_demangle"
		type = "func"
		size = "650"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 49 89 D6 41 55 41 89 F5 41 54 53 48 89 FB 48 83 EC 68 48 C7 02 00 00 00 00 E8 ?? ?? ?? ?? 80 3B 5F 49 89 C4 0F 84 DE 01 00 00 BF ?? ?? ?? ?? B9 08 00 00 00 48 89 DE F3 A6 0F 84 F9 00 00 00 41 F6 C5 10 0F 84 D7 01 00 00 BA 01 00 00 00 4A 8D 04 23 48 89 9D 70 FF FF FF 48 89 5D 88 48 89 E3 44 89 6D 80 C7 45 98 00 00 00 00 48 89 85 78 FF FF FF 43 8D 04 24 44 89 65 AC C7 45 A8 00 00 00 00 C7 45 B0 00 00 00 00 89 45 9C 48 98 48 C7 45 B8 00 00 00 00 48 8D 04 40 C7 45 C0 00 00 00 00 48 8D 04 C5 10 00 00 00 48 29 C4 49 63 C4 48 8D 04 C5 16 00 00 00 48 89 E1 48 89 4D 90 48 83 E0 }
	condition:
		$pattern
}

rule link_exists_p_dee972cf8f70cf37a237a00db9e07a0d {
	meta:
		aliases = "link_exists_p"
		type = "func"
		size = "195"
		objfiles = "glob64@libc.a, glob@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 49 89 D6 41 55 49 89 FD 48 89 D7 41 54 53 48 89 F3 48 81 EC 38 01 00 00 48 89 8D A8 FE FF FF 44 89 85 A4 FE FF FF E8 ?? ?? ?? ?? 49 89 C4 48 8D 44 18 20 48 89 DA 4C 89 EE 48 83 E0 F0 48 29 C4 4C 8D 7C 24 0F 49 83 E7 F0 4C 89 FF E8 ?? ?? ?? ?? BA 01 00 00 00 48 89 C7 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 49 8D 54 24 01 48 89 C7 4C 89 F6 E8 ?? ?? ?? ?? F7 85 A4 FE FF FF 00 02 00 00 74 16 48 8B 95 A8 FE FF FF 48 8D B5 40 FF FF FF 4C 89 FF FF 52 40 EB 0F 48 8D B5 B0 FE FF FF 4C 89 FF E8 ?? ?? ?? ?? 85 C0 0F 94 C0 48 8D 65 D8 5B 41 5C 41 5D 41 5E 41 5F C9 0F B6 C0 C3 }
	condition:
		$pattern
}

rule dlopen_8a2067f36abed218191f0d1517aa3f21 {
	meta:
		aliases = "dlopen"
		type = "func"
		size = "1235"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 49 89 FE 41 55 41 54 41 89 F4 53 48 83 EC 48 40 F6 C6 03 48 C7 45 D0 00 00 00 00 75 10 48 C7 05 ?? ?? ?? ?? 09 00 00 00 E9 8A 04 00 00 80 3D ?? ?? ?? ?? 00 4C 8B 6D 08 75 1D C6 05 ?? ?? ?? ?? 01 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 4D 85 F6 75 0C 48 8B 3D ?? ?? ?? ?? E9 51 04 00 00 E8 ?? ?? ?? ?? 48 8B 35 ?? ?? ?? ?? 31 DB 48 89 F0 EB 1E 48 8B 08 48 8B 51 28 4C 39 EA 73 0E 48 85 DB 74 06 48 39 53 28 73 03 48 89 CB 48 8B 40 20 48 85 C0 75 DD 48 89 75 D0 EB 04 48 89 45 D0 48 8B 45 D0 48 85 C0 48 89 45 98 74 09 48 8B 40 20 48 85 C0 75 E6 BF ?? }
	condition:
		$pattern
}

rule make_relative_prefix_e5649d2af71bfdc17055efc4eacf6036 {
	meta:
		aliases = "make_relative_prefix"
		type = "func"
		size = "1087"
		objfiles = "make_relative_prefix@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 49 89 FE 41 55 41 54 53 48 83 EC 38 48 85 FF 48 89 55 B8 0F 84 FF 02 00 00 48 85 F6 49 89 F5 0F 84 F3 02 00 00 48 83 7D B8 00 0F 84 E8 02 00 00 E8 ?? ?? ?? ?? 4C 39 F0 49 89 C7 0F 84 F0 02 00 00 4C 89 F7 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 0F 84 C3 02 00 00 48 8D 75 C4 48 89 C7 E8 E7 FD FF FF 48 8D 75 C8 4C 89 EF 49 89 C6 48 89 45 B0 E8 D4 FD FF FF 48 89 DF 49 89 C5 E8 ?? ?? ?? ?? 4D 85 F6 0F 84 90 02 00 00 4D 85 ED 0F 84 87 02 00 00 8B 45 C4 44 8D 60 FF 44 3B 65 C8 44 89 65 C4 0F 84 02 02 00 00 48 8B 7D B8 48 8D 75 CC E8 95 FD FF FF 48 85 C0 49 89 C6 0F 84 25 02 00 00 8B }
	condition:
		$pattern
}

rule clnt_create_75b550bab29ca4c02449f1f5c18a0739 {
	meta:
		aliases = "clnt_create"
		type = "func"
		size = "586"
		objfiles = "clnt_generic@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 49 89 FE 48 89 CF 41 55 49 89 F5 BE ?? ?? ?? ?? 41 54 49 89 D4 53 48 81 EC 08 01 00 00 48 89 8D D8 FE FF FF E8 ?? ?? ?? ?? 85 C0 75 4F 48 8D 9D E0 FE FF FF BA 6E 00 00 00 31 F6 48 89 DF E8 ?? ?? ?? ?? 48 8D 7B 02 4C 89 F6 66 C7 85 E0 FE FF FF 01 00 E8 ?? ?? ?? ?? 48 8D 4D CC 45 31 C9 45 31 C0 4C 89 E2 4C 89 EE 48 89 DF C7 45 CC FF FF FF FF E8 ?? ?? ?? ?? E9 B7 01 00 00 48 81 EC 10 04 00 00 4C 8D BD 50 FF FF FF BB 00 04 00 00 48 8D 54 24 0F 48 83 E2 F0 EB 37 83 7D C8 FF 75 0A E8 ?? ?? ?? ?? 83 38 22 74 10 E8 ?? ?? ?? ?? C7 00 0D 00 00 00 E9 77 01 00 00 48 01 DB 48 8D 43 }
	condition:
		$pattern
}

rule glob64_5e8f98256a96f83094f86bf928ed90a5 {
	meta:
		aliases = "__GI_glob, __GI_glob64, glob, glob64"
		type = "func"
		size = "1488"
		objfiles = "glob64@libc.a, glob@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 89 F7 41 56 41 55 41 54 49 89 CC 53 48 81 EC 78 01 00 00 48 85 FF 48 89 BD 78 FE FF FF 48 89 95 70 FE FF FF 74 0D 48 85 C9 74 08 F7 C6 00 81 FF FF 74 13 E8 ?? ?? ?? ?? 83 CA FF C7 00 16 00 00 00 E9 72 05 00 00 89 F0 83 E0 08 89 85 84 FE FF FF 75 08 48 C7 41 10 00 00 00 00 48 8B BD 78 FE FF FF BE 2F 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 49 89 C5 75 3F 41 F7 C7 00 50 00 00 0F 84 E2 00 00 00 48 8B 95 78 FE FF FF 80 3A 7E 0F 85 D2 00 00 00 48 89 D7 E8 ?? ?? ?? ?? 48 8B 9D 78 FE FF FF 49 89 C6 48 C7 85 90 FE FF FF 00 00 00 00 E9 C6 00 00 00 48 3B 85 78 FE FF FF 75 21 48 8B 8D 78 FE }
	condition:
		$pattern
}

rule gaih_inet_6e6ff5bbdd4563cc520cb0c119a3135f {
	meta:
		aliases = "gaih_inet"
		type = "func"
		size = "2756"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 48 8D 45 90 41 56 49 89 D6 41 55 49 89 F5 41 54 53 48 81 EC F8 00 00 00 48 89 BD 18 FF FF FF 48 89 8D 10 FF FF FF 48 89 45 C8 48 C7 45 C0 00 00 00 00 8B 42 04 85 C0 74 0F 83 F8 0A C7 85 24 FF FF FF 00 00 00 00 75 14 41 8B 06 83 F0 08 C1 E8 03 F7 D0 83 E0 01 89 85 24 FF FF FF 48 8D 7D 90 31 F6 BA 18 00 00 00 E8 ?? ?? ?? ?? 49 8B 7E 08 BE ?? ?? ?? ?? 48 85 FF 75 06 EB 49 48 83 C6 07 8A 4E 03 84 C9 74 29 41 8B 56 08 85 D2 74 07 0F BE 06 39 C2 75 E6 41 8B 56 0C 85 D2 74 0E F6 46 02 02 75 08 0F BE 46 01 39 C2 75 D0 84 C9 75 1A 41 83 7E 08 00 B8 07 01 00 00 0F 85 EF 09 00 00 E9 D3 }
	condition:
		$pattern
}

rule ruserok_e05c0ea886f8043a937f6dd9dcc3df0a {
	meta:
		aliases = "ruserok"
		type = "func"
		size = "203"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 49 89 D7 41 56 49 89 CE 41 55 4C 8D 6D A0 41 54 49 89 FC 53 BB 00 04 00 00 48 81 EC 58 04 00 00 89 75 9C 48 8D 54 24 0F 48 83 E2 F0 EB 27 83 7D C8 FF 75 7F E8 ?? ?? ?? ?? 83 38 22 75 75 48 01 DB 48 8D 43 1E 48 83 E0 F0 48 29 C4 48 8D 54 24 0F 48 83 E2 F0 4C 8D 4D C8 4C 8D 45 C0 48 89 D9 4C 89 EE 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 75 BF 48 8B 45 C0 48 85 C0 74 B6 48 8B 58 18 4C 8D 6D CC EB 29 BA 04 00 00 00 4C 89 EF E8 ?? ?? ?? ?? 8B 7D CC 8B 75 9C 4D 89 E0 4C 89 F1 4C 89 FA E8 E0 FD FF FF 85 C0 74 0F 48 83 C3 08 48 8B 33 48 85 F6 75 CF 83 C8 FF 48 8D 65 D8 5B 41 5C 41 5D 41 5E 41 }
	condition:
		$pattern
}

rule ruserpass_0800708dacf332078c105f6fb92c0be5 {
	meta:
		aliases = "__GI_ruserpass, ruserpass"
		type = "func"
		size = "839"
		objfiles = "ruserpass@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 49 89 D7 41 56 49 89 F6 41 55 49 89 FD 41 54 53 48 81 EC A8 04 00 00 E8 ?? ?? ?? ?? 89 C3 E8 ?? ?? ?? ?? 39 C3 0F 85 02 03 00 00 E8 ?? ?? ?? ?? 89 C3 E8 ?? ?? ?? ?? 39 C3 0F 85 EE 02 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 0F 84 D8 02 00 00 48 89 C7 E8 ?? ?? ?? ?? 48 83 C0 26 48 89 DE 48 83 E0 F0 48 29 C4 4C 8D 64 24 0F 49 83 E4 F0 4C 89 E7 E8 ?? ?? ?? ?? BE ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? 4C 89 E7 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 C7 48 89 05 ?? ?? ?? ?? 75 24 E8 ?? ?? ?? ?? 31 D2 83 38 02 0F 84 7B 02 00 00 4C 89 E6 BF ?? ?? ?? ?? 31 C0 E8 ?? ?? }
	condition:
		$pattern
}

rule sched_setaffinity_84b5c1e19073315e6944aa2bc5f59650 {
	meta:
		aliases = "sched_setaffinity"
		type = "func"
		size = "278"
		objfiles = "sched_setaffinity@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 49 89 F7 41 56 49 89 D6 41 55 41 54 53 48 83 EC 08 48 83 3D ?? ?? ?? ?? 00 89 7D D4 0F 85 8B 00 00 00 48 81 EC 90 00 00 00 41 BD 80 00 00 00 4C 8D 64 24 0F 49 83 E4 F0 EB 2F 4B 8D 54 2D 00 48 8D 42 1E 49 8D 74 15 00 49 89 D5 48 83 E0 F0 48 29 C4 48 8D 44 24 0F 48 83 E0 F0 48 8D 0C 10 4C 39 E1 49 89 C4 4C 0F 44 EE E8 ?? ?? ?? ?? 4C 89 E2 48 63 F8 4C 89 EE B8 CC 00 00 00 0F 05 3D 00 F0 FF FF 89 C3 76 05 83 F8 EA 74 AE 85 DB 74 08 81 FB 00 F0 FF FF 76 0B F7 DB E8 ?? ?? ?? ?? 89 18 EB 25 48 63 C3 48 89 05 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? EB 1A 41 80 3C 06 00 74 10 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getrpcport_4851e09dbcb30ffc8db824907da44ad3 {
	meta:
		aliases = "getrpcport"
		type = "func"
		size = "198"
		objfiles = "getrpcport@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 49 89 F7 41 56 49 89 D6 41 55 41 89 CD 41 54 49 89 FC 53 BB 00 04 00 00 48 81 EC 58 04 00 00 48 8D 54 24 0F 48 83 E2 F0 EB 27 83 7D CC FF 75 7F E8 ?? ?? ?? ?? 83 38 22 75 75 48 01 DB 48 8D 43 1E 48 83 E0 F0 48 29 C4 48 8D 54 24 0F 48 83 E2 F0 4C 8D 4D CC 4C 8D 45 C0 48 8D 75 90 48 89 D9 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 75 BE 48 8B 45 C0 48 85 C0 74 B5 48 63 50 14 48 8B 40 18 48 8D 5D B0 48 8D 7B 04 48 8B 30 E8 ?? ?? ?? ?? 44 89 E9 4C 89 F2 4C 89 FE 48 89 DF 66 C7 45 B0 02 00 66 C7 45 B2 00 00 E8 ?? ?? ?? ?? 0F B7 C0 EB 02 31 C0 48 8D 65 D8 5B 41 5C 41 5D 41 5E 41 5F C9 C3 }
	condition:
		$pattern
}

rule callrpc_efd04d298bac2e52de6d52fde0d441bf {
	meta:
		aliases = "callrpc"
		type = "func"
		size = "610"
		objfiles = "clnt_simple@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 49 89 FF 41 56 49 89 D6 41 55 49 89 F5 41 54 53 48 81 EC 98 00 00 00 48 89 8D 68 FF FF FF 4C 89 85 60 FF FF FF 4C 89 8D 58 FF FF FF E8 ?? ?? ?? ?? 4C 8B A0 C8 00 00 00 48 89 C3 4D 85 E4 75 24 BE 30 00 00 00 BF 01 00 00 00 E8 ?? ?? ?? ?? 31 D2 48 85 C0 0F 84 F1 01 00 00 49 89 C4 48 89 83 C8 00 00 00 49 83 7C 24 28 00 75 1B BF 00 01 00 00 E8 ?? ?? ?? ?? 49 89 44 24 28 C6 00 00 41 C7 44 24 08 FF FF FF FF 49 83 7C 24 20 00 74 23 4D 39 6C 24 10 75 1C 4D 39 74 24 18 75 15 49 8B 7C 24 28 4C 89 FE E8 ?? ?? ?? ?? 85 C0 0F 84 3B 01 00 00 41 8B 7C 24 08 49 C7 44 24 20 00 00 00 00 83 FF }
	condition:
		$pattern
}

rule rcmd_17ded2457027f732583f792651a218c2 {
	meta:
		aliases = "rcmd"
		type = "func"
		size = "1283"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 49 89 FF 41 56 4C 8D 75 B8 41 55 4C 8D AD 60 FF FF FF 41 54 41 BC 00 04 00 00 53 48 81 EC B8 00 00 00 48 89 95 48 FF FF FF 48 89 8D 40 FF FF FF 4C 89 85 38 FF FF FF 4C 89 8D 30 FF FF FF 66 89 B5 56 FF FF FF E8 ?? ?? ?? ?? 48 81 EC 10 04 00 00 89 85 5C FF FF FF 48 8D 54 24 0F 48 83 E2 F0 EB 3E 8B 5D C8 83 FB FF 75 0A E8 ?? ?? ?? ?? 83 38 22 74 14 E8 ?? ?? ?? ?? 89 18 49 8B 3F E8 ?? ?? ?? ?? E9 5F 04 00 00 4D 01 E4 49 8D 44 24 1E 48 83 E0 F0 48 29 C4 48 8D 54 24 0F 48 83 E2 F0 49 8B 3F 4C 8D 4D C8 4D 89 F0 4C 89 E1 4C 89 EE E8 ?? ?? ?? ?? 85 C0 75 A9 48 83 7D B8 00 74 A2 48 8B }
	condition:
		$pattern
}

rule gaih_inet_serv_1d0265232c8482001c40e879fc262ec2 {
	meta:
		aliases = "gaih_inet_serv"
		type = "func"
		size = "181"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 49 89 FF 41 56 4C 8D 76 03 41 55 41 BD 00 04 00 00 41 54 49 89 CC 53 48 89 F3 48 83 EC 48 48 89 55 98 49 8D 45 1E 4C 8D 4D C8 48 8D 55 A0 4D 89 E8 4C 89 F6 4C 89 FF 48 83 E0 F0 48 29 C4 48 8D 4C 24 0F 48 83 E1 F0 E8 ?? ?? ?? ?? 85 C0 75 09 48 83 7D C8 00 75 0C EB 42 83 F8 22 75 3D 4D 01 ED EB BF 49 C7 04 24 00 00 00 00 0F BE 03 41 89 44 24 08 F6 43 02 02 74 09 48 8B 55 98 8B 42 0C EB 04 0F BE 43 01 41 89 44 24 0C 48 8B 45 C8 8B 40 10 41 89 44 24 10 31 C0 EB 05 B8 08 01 00 00 48 8D 65 D8 5B 41 5C 41 5D 41 5E 41 5F C9 C3 }
	condition:
		$pattern
}

rule glob_in_dir_5a7d413fec763f50e84b5b43cbd456eb {
	meta:
		aliases = "glob_in_dir"
		type = "func"
		size = "1342"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 4D 89 C7 41 56 41 89 D6 41 55 41 54 49 89 CC 53 44 89 F3 48 81 EC 98 02 00 00 48 89 BD 60 FD FF FF 48 89 B5 58 FD FF FF 48 89 F7 E8 ?? ?? ?? ?? 83 E3 40 48 8B BD 60 FD FF FF 48 89 85 68 FD FF FF 40 0F 94 C6 40 0F B6 F6 E8 ?? ?? ?? ?? 85 C0 0F 85 C8 00 00 00 41 F7 C6 10 08 00 00 0F 85 B2 00 00 00 85 DB 75 1A 48 8B BD 60 FD FF FF BE 5C 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 0F 85 9D 00 00 00 48 8B BD 60 FD FF FF E8 ?? ?? ?? ?? 48 8B 95 68 FD FF FF 48 89 C3 48 8B B5 58 FD FF FF 48 8D 44 10 20 48 83 E0 F0 48 29 C4 4C 8D 64 24 0F 49 83 E4 F0 4C 89 E7 E8 ?? ?? ?? ?? BA 01 00 00 00 48 89 }
	condition:
		$pattern
}

rule execlp_565a3b46c26c03b4cc0a433a220426fe {
	meta:
		aliases = "__GI_execl, __GI_execlp, execl, execlp"
		type = "func"
		size = "280"
		objfiles = "execlp@libc.a, execl@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 48 81 EC D0 00 00 00 48 8D 45 10 48 89 8D 68 FF FF FF 4C 89 85 70 FF FF FF 48 89 95 60 FF FF FF 4C 89 8D 78 FF FF FF 48 89 F1 48 89 85 38 FF FF FF 48 8D 85 50 FF FF FF C7 85 30 FF FF FF 10 00 00 00 45 31 C0 48 89 85 40 FF FF FF 8B 85 30 FF FF FF 41 FF C0 83 F8 30 73 14 89 C2 48 03 95 40 FF FF FF 83 C0 08 89 85 30 FF FF FF EB 12 48 8B 95 38 FF FF FF 48 8D 42 08 48 89 85 38 FF FF FF 48 83 3A 00 75 C6 41 8D 40 01 48 98 48 8D 04 C5 1E 00 00 00 48 83 E0 F0 48 29 C4 48 8D 45 10 48 8D 74 24 0F 48 83 E6 F0 48 89 0E 48 89 85 38 FF FF FF 48 8D 85 50 FF FF FF C7 85 30 FF FF FF 10 00 00 00 48 }
	condition:
		$pattern
}

rule execle_5a9a58a9ed32f322592614fa274d88f5 {
	meta:
		aliases = "__GI_execle, execle"
		type = "func"
		size = "332"
		objfiles = "execle@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 48 81 EC D0 00 00 00 48 8D 45 10 48 89 8D 68 FF FF FF 4C 89 8D 78 FF FF FF 48 89 95 60 FF FF FF 4C 89 85 70 FF FF FF 48 89 F1 48 89 85 38 FF FF FF 48 8D 85 50 FF FF FF C7 85 30 FF FF FF 10 00 00 00 45 31 C9 48 89 85 40 FF FF FF 8B 85 30 FF FF FF 41 FF C1 83 F8 30 73 14 89 C2 48 03 95 40 FF FF FF 83 C0 08 89 85 30 FF FF FF EB 12 48 8B 95 38 FF FF FF 48 8D 42 08 48 89 85 38 FF FF FF 48 83 3A 00 75 C6 8B 85 30 FF FF FF 83 F8 30 73 14 89 C2 48 03 95 40 FF FF FF 83 C0 08 89 85 30 FF FF FF EB 12 48 8B 95 38 FF FF FF 48 8D 42 08 48 89 85 38 FF FF FF 41 8D 41 01 48 8B 12 48 98 48 8D 04 C5 }
	condition:
		$pattern
}

rule __do_global_ctors_aux_05b2f1c9224bb81d83dabc32d083adbc {
	meta:
		aliases = "__do_global_ctors_aux"
		type = "func"
		size = "50"
		objfiles = "crtend"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 53 48 83 EC 08 48 8B 05 ?? ?? ?? ?? 48 83 F8 FF 74 15 31 DB FF D0 48 8B 83 ?? ?? ?? ?? 48 83 EB 08 48 83 F8 FF 75 ED 48 83 C4 08 5B C9 C3 }
	condition:
		$pattern
}

rule __do_global_ctors_aux_d02b2befe96c7b9dbc237d617301bd42 {
	meta:
		aliases = "__do_global_ctors_aux"
		type = "func"
		size = "55"
		objfiles = "crtendS"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 53 48 83 EC 08 48 8B 05 ?? ?? ?? ?? 48 83 F8 FF 74 1A 48 8D 1D ?? ?? ?? ?? 66 66 90 FF D0 48 8B 43 F8 48 83 EB 08 48 83 F8 FF 75 F0 48 83 C4 08 5B C9 C3 }
	condition:
		$pattern
}

rule xmemdup_b2defc40777a06a5dffd22b319e102eb {
	meta:
		aliases = "xmemdup"
		type = "func"
		size = "45"
		objfiles = "xmemdup@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 48 89 D6 53 48 89 FB BF 01 00 00 00 48 83 EC 08 E8 ?? ?? ?? ?? 48 83 C4 08 48 89 DE 48 89 EA 5B 5D 48 89 C7 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdrrec_putint32_9e9275d3af336de3eb94cb2cc71ec260 {
	meta:
		aliases = "xdrrec_putint32"
		type = "func"
		size = "91"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 83 EC 08 48 8B 5F 18 48 8B 53 20 48 8D 42 04 48 3B 43 28 48 89 D1 48 89 43 20 76 27 48 89 53 20 31 F6 C7 43 38 01 00 00 00 48 89 DF E8 15 FF FF FF 31 D2 85 C0 74 18 48 8B 4B 20 48 8D 41 04 48 89 43 20 8B 45 00 BA 01 00 00 00 0F C8 89 01 5F 5B 5D 89 D0 C3 }
	condition:
		$pattern
}

rule xdrrec_putlong_ddd0b595ee35642189edede4f9aab6e8 {
	meta:
		aliases = "xdrrec_putlong"
		type = "func"
		size = "93"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 83 EC 08 48 8B 5F 18 48 8B 53 20 48 8D 42 04 48 3B 43 28 48 89 D1 48 89 43 20 76 27 48 89 53 20 31 F6 C7 43 38 01 00 00 00 48 89 DF E8 BA FE FF FF 31 D2 85 C0 74 19 48 8B 4B 20 48 8D 41 04 48 89 43 20 48 8B 45 00 BA 01 00 00 00 0F C8 89 01 41 58 5B 5D 89 D0 C3 }
	condition:
		$pattern
}

rule svcraw_recv_5cf9e1845dd6213109fb7314bc332df9 {
	meta:
		aliases = "svcraw_recv"
		type = "func"
		size = "84"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 83 EC 08 E8 ?? ?? ?? ?? 48 8B 90 F8 00 00 00 31 C0 48 85 D2 74 33 48 8B 82 B8 23 00 00 48 8D 9A B0 23 00 00 31 F6 C7 82 B0 23 00 00 01 00 00 00 48 89 DF FF 50 28 48 89 EE 48 89 DF E8 ?? ?? ?? ?? 85 C0 0F 95 C0 0F B6 C0 41 59 5B 5D C3 }
	condition:
		$pattern
}

rule cplus_demangle_print_5475f127919ebb0f8ba989e2c6356027 {
	meta:
		aliases = "cplus_demangle_print"
		type = "func"
		size = "193"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 CB 48 83 EC 48 89 3C 24 8D 7A 01 48 63 FF 48 89 7C 24 18 E8 ?? ?? ?? ?? 48 85 C0 48 89 44 24 08 0F 84 8B 00 00 00 48 89 EE 48 89 E7 48 C7 44 24 10 00 00 00 00 48 C7 44 24 20 00 00 00 00 48 C7 44 24 28 00 00 00 00 C7 44 24 30 00 00 00 00 E8 35 C3 FF FF 48 8B 44 24 08 48 85 C0 74 0C 48 8B 54 24 10 48 3B 54 24 18 72 27 31 F6 48 89 E7 E8 35 C2 FF FF 48 8B 44 24 08 48 85 C0 74 21 48 8B 54 24 18 48 89 13 48 83 C4 48 5B 5D C3 0F 1F 40 00 C6 04 10 00 48 8B 44 24 08 48 85 C0 75 DF 48 63 54 24 30 48 89 13 48 83 C4 48 5B 5D C3 0F 1F 00 48 C7 03 01 00 00 00 EB CC }
	condition:
		$pattern
}

rule confstr_aa3b80a011bf238e96a30ead0ff7425d {
	meta:
		aliases = "confstr"
		type = "func"
		size = "100"
		objfiles = "confstr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 D3 48 83 EC 08 85 FF 75 0C 48 85 D2 74 46 48 85 F6 75 11 EB 3F E8 ?? ?? ?? ?? C7 00 16 00 00 00 31 C0 EB 35 48 83 FA 0D 76 14 BA 0E 00 00 00 BE ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? EB 16 48 8D 52 FF BE ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? C6 44 1D FF 00 B8 0E 00 00 00 5A 5B 5D C3 }
	condition:
		$pattern
}

rule clntraw_freeres_c4688965715f0100cbda125547898ae2 {
	meta:
		aliases = "clntraw_freeres"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "66"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 D3 48 83 EC 08 E8 ?? ?? ?? ?? 48 8B 80 F8 00 00 00 48 85 C0 74 1F C7 80 B0 23 00 00 02 00 00 00 48 89 DE 49 89 EB 59 5B 5D 48 8D B8 B0 23 00 00 31 C0 41 FF E3 5A 5B 5D 31 C0 C3 }
	condition:
		$pattern
}

rule byte_alt_match_null_string_p_5fb258dd01862fbfcca0280f310f1ab5 {
	meta:
		aliases = "byte_alt_match_null_string_p"
		type = "func"
		size = "129"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 D3 48 83 EC 18 48 89 7C 24 08 0F 1F 80 00 00 00 00 48 39 FD 76 2C 80 3F 0F 75 36 48 8D 47 01 48 89 44 24 08 0F BE 47 02 0F B6 57 01 C1 E0 08 01 D0 48 98 48 8D 7C 07 03 48 39 FD 48 89 7C 24 08 77 D4 48 83 C4 18 B8 01 00 00 00 5B 5D C3 0F 1F 00 48 8D 7C 24 08 48 89 DA 48 89 EE E8 88 FE FF FF 84 C0 74 0C 48 8B 7C 24 08 EB A5 0F 1F 44 00 00 48 83 C4 18 31 C0 5B 5D C3 }
	condition:
		$pattern
}

rule dyn_string_copy_ba8d16b4b55bfaafe388d70114552b2d {
	meta:
		aliases = "dyn_string_copy"
		type = "func"
		size = "70"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 08 48 39 F7 74 30 8B 76 04 E8 ?? ?? ?? ?? 31 D2 48 85 C0 74 18 48 8B 75 08 48 8B 7B 08 E8 ?? ?? ?? ?? 8B 45 04 BA 01 00 00 00 89 43 04 48 83 C4 08 89 D0 5B 5D C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_set_own_extricate_if_76da68e49fd047986d012f8c39b9f16a {
	meta:
		aliases = "__pthread_set_own_extricate_if"
		type = "func"
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
		type = "func"
		size = "66"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 08 48 85 F6 74 08 80 7F 78 00 75 27 EB 0C 48 8B 7F 30 48 89 DE E8 ?? ?? ?? ?? 48 85 ED 48 89 AB D8 02 00 00 75 0D 48 8B 7B 30 41 58 5B 5D E9 ?? ?? ?? ?? 5E 5B 5D C3 }
	condition:
		$pattern
}

rule snarf_numeric_literal_aa05818eba9c30d8a113c4fbce7d56a0 {
	meta:
		aliases = "snarf_numeric_literal"
		type = "func"
		size = "175"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 08 48 8B 07 0F B6 10 80 FA 2D 74 71 80 FA 2B 74 5C 0F B6 CA 31 C0 F6 84 09 ?? ?? ?? ?? 04 74 42 89 D0 EB 1C 90 48 8B 03 48 8D 50 01 48 89 13 0F B6 40 01 0F B6 D0 F6 84 12 ?? ?? ?? ?? 04 74 1D 84 C0 88 05 ?? ?? ?? ?? 74 DB BE ?? ?? ?? ?? 48 89 EF E8 2E FF FF FF EB CC 0F 1F 40 00 B8 01 00 00 00 48 83 C4 08 5B 5D C3 0F 1F 40 00 48 8D 50 01 48 89 17 0F B6 50 01 EB 97 0F 1F 00 BE ?? ?? ?? ?? 48 89 EF C6 05 ?? ?? ?? ?? 2D E8 F4 FE FF FF 48 8B 03 48 8D 50 01 48 89 13 0F B6 50 01 E9 6D FF FF FF }
	condition:
		$pattern
}

rule htab_clear_slot_a7eed5ca2ae6498a95cc53d5118db34b {
	meta:
		aliases = "htab_clear_slot"
		type = "func"
		size = "84"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 08 48 8B 47 18 48 39 F0 77 3A 48 8B 57 20 48 8D 04 D0 48 39 C6 73 2D 48 8B 3E 48 85 FF 74 25 48 83 FF 01 74 1F 48 8B 43 10 48 85 C0 74 02 FF D0 48 C7 45 00 01 00 00 00 48 83 43 30 01 48 83 C4 08 5B 5D C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tdestroy_recurse_8bba949d52cdd658394b7b5cb3b2a8cc {
	meta:
		aliases = "tdestroy_recurse"
		type = "func"
		size = "59"
		objfiles = "tdestroy@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 08 48 8B 7F 08 48 85 FF 74 05 E8 E6 FF FF FF 48 8B 7B 10 48 85 FF 74 08 48 89 EE E8 D5 FF FF FF 48 8B 3B FF D5 58 48 89 DF 5B 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule d_print_expr_op_54991aaf074ea831188c4a69f588d67e {
	meta:
		aliases = "d_print_expr_op"
		type = "func"
		size = "138"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 08 83 3E 28 74 0F 48 83 C4 08 5B 5D EB 77 0F 1F 80 00 00 00 00 48 8B 4F 08 48 85 C9 74 57 48 8B 46 08 48 8B 7F 10 48 63 50 10 49 89 C0 48 8D 34 3A 48 3B 73 18 76 16 49 8B 70 08 48 83 C4 08 48 89 DF 5B 5D E9 FC FE FF FF 0F 1F 40 00 48 8B 70 08 48 01 CF E8 ?? ?? ?? ?? 48 8B 45 08 48 63 40 10 48 01 43 10 48 83 C4 08 5B 5D C3 66 0F 1F 84 00 00 00 00 00 4C 8B 46 08 49 63 50 10 EB B8 }
	condition:
		$pattern
}

rule d_print_mod_5f22dd8c3924c4b168ebeb8a817a5dcb {
	meta:
		aliases = "d_print_mod"
		type = "func"
		size = "915"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 08 8B 06 83 E8 03 83 F8 22 0F 87 26 02 00 00 FF 24 C5 ?? ?? ?? ?? 0F 1F 80 00 00 00 00 48 8B 57 08 48 85 D2 0F 84 6B 02 00 00 48 8B 47 10 48 85 C0 0F 84 0E 02 00 00 80 7C 02 FF 28 0F 85 03 02 00 00 0F 1F 00 48 8B 75 08 48 89 DF E8 04 E5 FF FF 48 8B 43 08 48 85 C0 74 12 48 8B 53 10 48 8D 4A 03 48 3B 4B 18 0F 86 D9 02 00 00 BA 03 00 00 00 BE ?? ?? ?? ?? EB 45 0F 1F 44 00 00 48 8B 76 08 48 83 C4 08 48 89 DF 5B 5D E9 C6 E4 FF FF 66 0F 1F 44 00 00 48 8B 47 08 48 85 C0 74 12 48 8B 57 10 48 8D 4A 09 48 3B 4F 18 0F 86 35 02 00 00 BA 09 00 00 00 BE ?? ?? ?? ?? 0F 1F 00 }
	condition:
		$pattern
}

rule dyn_string_append_e9a5e53dcdf3416a329ed1f07c5aff6b {
	meta:
		aliases = "dyn_string_append"
		type = "func"
		size = "67"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 08 8B 77 04 03 75 04 E8 ?? ?? ?? ?? 31 D2 48 85 C0 74 1C 48 63 7B 04 48 8B 75 08 48 03 7B 08 E8 ?? ?? ?? ?? 8B 45 04 01 43 04 BA 01 00 00 00 48 83 C4 08 89 D0 5B 5D C3 }
	condition:
		$pattern
}

rule splay_tree_lookup_0d73b9ad4e4cef3b05408fbf4268c8b9 {
	meta:
		aliases = "splay_tree_lookup"
		type = "func"
		size = "57"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 08 E8 8F FA FF FF 48 8B 03 48 85 C0 74 17 48 89 EE 48 8B 38 FF 53 08 85 C0 75 0A 48 8B 03 48 83 C4 08 5B 5D C3 48 83 C4 08 31 C0 5B 5D C3 }
	condition:
		$pattern
}

rule on_exit_87a05cf06c52c43aca30a8c7312b76a4 {
	meta:
		aliases = "on_exit"
		type = "func"
		size = "48"
		objfiles = "on_exit@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 83 CA FF 48 85 C0 74 11 48 89 58 08 48 89 68 10 31 D2 48 C7 00 02 00 00 00 89 D0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule xdr_uint64_t_f74921c89a77c85a5b6667d4781255de {
	meta:
		aliases = "xdr_uint64_t"
		type = "func"
		size = "165"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 18 8B 07 83 F8 01 74 4A 72 0C 83 F8 02 BA 01 00 00 00 74 7D EB 79 48 8B 16 48 8D 74 24 14 48 89 D0 89 54 24 10 48 C1 E8 20 89 44 24 14 48 8B 47 08 FF 50 48 31 D2 85 C0 74 57 48 8B 43 08 48 8D 74 24 10 48 89 DF FF 50 48 31 D2 85 C0 0F 95 C2 EB 3F 48 8B 47 08 48 8D 74 24 14 FF 50 40 85 C0 74 2D 48 8B 43 08 48 8D 74 24 10 48 89 DF FF 50 40 85 C0 74 1A 8B 44 24 14 8B 54 24 10 48 C1 E0 20 48 09 D0 BA 01 00 00 00 48 89 45 00 EB 02 31 D2 48 83 C4 18 89 D0 5B 5D C3 }
	condition:
		$pattern
}

rule xdr_int64_t_60b33b5146e6245d5e7bfbd742303e7c {
	meta:
		aliases = "xdr_int64_t"
		type = "func"
		size = "166"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 18 8B 07 83 F8 01 74 4A 72 0C 83 F8 02 BA 01 00 00 00 74 7E EB 7A 48 8B 16 48 8D 74 24 14 48 89 D0 89 54 24 10 48 C1 F8 20 89 44 24 14 48 8B 47 08 FF 50 48 31 D2 85 C0 74 58 48 8B 43 08 48 8D 74 24 10 48 89 DF FF 50 48 31 D2 85 C0 0F 95 C2 EB 40 48 8B 47 08 48 8D 74 24 14 FF 50 40 85 C0 74 2E 48 8B 43 08 48 8D 74 24 10 48 89 DF FF 50 40 85 C0 74 1B 48 63 44 24 14 8B 54 24 10 48 C1 E0 20 48 09 D0 BA 01 00 00 00 48 89 45 00 EB 02 31 D2 48 83 C4 18 89 D0 5B 5D C3 }
	condition:
		$pattern
}

rule xdr_u_hyper_42ab2237d7b46be0573522240f155c8a {
	meta:
		aliases = "__GI_xdr_u_hyper, xdr_u_hyper"
		type = "func"
		size = "163"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 18 8B 07 85 C0 75 3C 48 8B 16 48 8D 74 24 10 48 89 D0 48 89 54 24 08 48 C1 E8 20 48 89 44 24 10 48 8B 47 08 FF 50 08 31 D2 85 C0 74 62 48 8B 43 08 48 8D 74 24 08 48 89 DF FF 50 08 85 C0 0F 95 C0 EB 45 83 F8 01 75 3A 48 8B 47 08 48 8D 74 24 10 FF 10 85 C0 74 36 48 8B 43 08 48 8D 74 24 08 48 89 DF FF 10 85 C0 74 24 48 8B 44 24 10 BA 01 00 00 00 48 C1 E0 20 48 0B 44 24 08 48 89 45 00 EB 0D 83 F8 02 0F 94 C0 0F B6 D0 EB 02 31 D2 48 83 C4 18 89 D0 5B 5D C3 }
	condition:
		$pattern
}

rule xdr_hyper_d75816feb68ac638a377da8097fc74a9 {
	meta:
		aliases = "__GI_xdr_hyper, xdr_hyper"
		type = "func"
		size = "163"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 18 8B 07 85 C0 75 3C 48 8B 16 48 8D 74 24 10 48 89 D0 48 89 54 24 08 48 C1 F8 20 48 89 44 24 10 48 8B 47 08 FF 50 08 31 D2 85 C0 74 62 48 8B 43 08 48 8D 74 24 08 48 89 DF FF 50 08 85 C0 0F 95 C0 EB 45 83 F8 01 75 3A 48 8B 47 08 48 8D 74 24 10 FF 10 85 C0 74 36 48 8B 43 08 48 8D 74 24 08 48 89 DF FF 10 85 C0 74 24 48 8B 44 24 10 BA 01 00 00 00 48 C1 E0 20 48 0B 44 24 08 48 89 45 00 EB 0D 83 F8 02 0F 94 C0 0F B6 D0 EB 02 31 D2 48 83 C4 18 89 D0 5B 5D C3 }
	condition:
		$pattern
}

rule htab_find_6933f4f6b19aa63a67004dcbc01fe5cf {
	meta:
		aliases = "htab_find"
		type = "func"
		size = "36"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 89 F7 48 83 EC 08 FF 13 48 83 C4 08 48 89 DF 48 89 EE 5B 5D 89 C2 E9 9C FE FF FF }
	condition:
		$pattern
}

rule htab_remove_elt_49d60494d961465c3d5b92f2f502b189 {
	meta:
		aliases = "htab_remove_elt"
		type = "func"
		size = "33"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 89 F7 48 83 EC 08 FF 13 48 83 C4 08 48 89 DF 48 89 EE 5B 5D 89 C2 EB 9F }
	condition:
		$pattern
}

rule fgetspent_r_67bf5c69defe49bb1b609a3c6bc27dcd {
	meta:
		aliases = "__GI_fgetgrent_r, __GI_fgetpwent_r, __GI_fgetspent_r, fgetgrent_r, fgetpwent_r, fgetspent_r"
		type = "func"
		size = "43"
		objfiles = "fgetpwent_r@libc.a, fgetspent_r@libc.a, fgetgrent_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 4C 89 C3 48 83 EC 08 49 C7 00 00 00 00 00 49 89 F8 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 75 03 48 89 2B 5A 5B 5D C3 }
	condition:
		$pattern
}

rule __ether_line_w_6f89c59e5e6afd5ccbc305dfe86062d2 {
	meta:
		aliases = "__ether_line_w"
		type = "func"
		size = "62"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 BE 23 00 00 00 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 48 85 C0 75 12 BE 0A 00 00 00 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 74 03 C6 00 00 58 48 89 DF 48 89 EE 5B 5D E9 44 FF FF FF }
	condition:
		$pattern
}

rule byte_re_match_2_internal_6ca09b5ada5afe23e2b0710c13106b0d {
	meta:
		aliases = "byte_re_match_2_internal"
		type = "func"
		size = "8643"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F8 48 89 E5 41 57 41 56 41 55 41 54 53 48 81 EC 48 01 00 00 48 89 4D B0 48 8B 0F 48 8B 40 30 48 89 BD 30 FF FF FF 48 83 EC 40 4C 8D 64 24 0F 48 89 75 98 44 89 8D 6C FF FF FF 49 89 CE 4C 03 77 10 48 8B 7F 28 49 83 E4 F0 48 85 C0 89 55 84 44 89 45 80 44 8B 4D 18 BE 10 00 00 00 48 89 BD 28 FF FF FF 48 8D 78 01 48 89 85 50 FF FF FF 48 89 BD 58 FF FF FF 0F 85 75 13 00 00 48 C7 85 F0 FE FF FF 00 00 00 00 48 C7 85 F8 FE FF FF 00 00 00 00 45 31 D2 48 C7 85 10 FF FF FF 00 00 00 00 48 C7 85 18 FF FF FF 00 00 00 00 45 31 FF 48 C7 85 40 FF FF FF 00 00 00 00 48 C7 85 48 FF FF FF 00 00 00 00 45 31 }
	condition:
		$pattern
}

rule xdrmem_getbytes_906fdb29c93ec5ae663d583954f38773 {
	meta:
		aliases = "xdrmem_getbytes"
		type = "func"
		size = "53"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 31 C0 48 89 F7 53 48 83 EC 08 8B 4D 28 39 D1 72 1C 48 8B 75 18 29 D1 89 D3 89 4D 28 48 89 DA E8 ?? ?? ?? ?? 48 01 5D 18 B8 01 00 00 00 59 5B 5D C3 }
	condition:
		$pattern
}

rule xmalloc_failed_b867c68f97ee19987cb1f3fb3ceca9b4 {
	meta:
		aliases = "xmalloc_failed"
		type = "func"
		size = "107"
		objfiles = "xmalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 31 FF 53 48 83 EC 08 48 8B 1D ?? ?? ?? ?? 48 85 DB 74 43 E8 ?? ?? ?? ?? 49 89 C1 49 29 D9 48 8B 15 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 49 89 E8 BE ?? ?? ?? ?? 80 3A 00 48 0F 44 C8 31 C0 E8 ?? ?? ?? ?? BF 01 00 00 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 49 89 C1 49 81 E9 ?? ?? ?? ?? EB B7 }
	condition:
		$pattern
}

rule string_prepend_DOT_part_DOT_7_8d918d0ad537a7428f2ff897dba87130 {
	meta:
		aliases = "string_prepend.part.7"
		type = "func"
		size = "48"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 48 89 F7 53 48 89 F3 48 83 EC 08 E8 ?? ?? ?? ?? 85 C0 75 08 48 83 C4 08 5B 5D C3 90 48 83 C4 08 48 89 DE 48 89 EF 5B 5D 89 C2 EB 80 }
	condition:
		$pattern
}

rule sem_post_93a4c19062f24ad852442b8ca92a5cc3 {
	meta:
		aliases = "__new_sem_post, sem_post"
		type = "func"
		size = "237"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 81 EC B8 00 00 00 E8 DB FC FF FF 48 83 B8 A0 00 00 00 00 48 89 C6 75 72 48 89 EF E8 ?? ?? ?? ?? 48 83 7D 18 00 75 31 8B 45 10 3D FF FF FF 7F 75 15 E8 ?? ?? ?? ?? 48 89 EF C7 00 22 00 00 00 E8 ?? ?? ?? ?? EB 61 FF C0 48 89 EF 89 45 10 E8 ?? ?? ?? ?? E9 83 00 00 00 48 8B 5D 18 48 85 DB 74 10 48 8B 43 10 48 89 45 18 48 C7 43 10 00 00 00 00 48 89 EF E8 ?? ?? ?? ?? C6 83 D2 02 00 00 01 48 89 DF E8 ?? ?? ?? ?? EB 51 83 3D ?? ?? ?? ?? 00 79 19 E8 ?? ?? ?? ?? 85 C0 79 10 E8 ?? ?? ?? ?? C7 00 0B 00 00 00 83 C8 FF EB 31 C7 44 24 08 04 00 00 00 48 89 6C 24 10 8B 3D ?? ?? ?? ?? BA A8 00 }
	condition:
		$pattern
}

rule xatexit_0652b6b3acccca4c663218df069f46e1 {
	meta:
		aliases = "xatexit"
		type = "func"
		size = "132"
		objfiles = "xatexit@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 83 EC 08 48 83 3D ?? ?? ?? ?? 00 74 5D 48 8B 1D ?? ?? ?? ?? 48 63 43 08 83 F8 1F 8D 50 01 7F 1A 89 53 08 48 89 6C C3 10 31 C0 48 83 C4 08 5B 5D C3 66 0F 1F 84 00 00 00 00 00 BF 10 01 00 00 E8 ?? ?? ?? ?? 48 85 C0 74 2E 48 89 18 C7 40 08 00 00 00 00 48 89 C3 48 89 05 ?? ?? ?? ?? BA 01 00 00 00 31 C0 EB BA 0F 1F 40 00 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? EB 96 B8 FF FF FF FF EB AC }
	condition:
		$pattern
}

rule sbrk_f95aed774435c440b9adae9573dd0c5f {
	meta:
		aliases = "__GI_sbrk, sbrk"
		type = "func"
		size = "74"
		objfiles = "sbrk@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 83 EC 08 48 83 3D ?? ?? ?? ?? 00 75 0B 31 FF E8 ?? ?? ?? ?? 85 C0 78 21 48 85 ED 48 8B 05 ?? ?? ?? ?? 75 05 48 89 C3 EB 14 48 8D 3C 28 48 89 C3 E8 ?? ?? ?? ?? 85 C0 79 04 48 83 CB FF 5A 48 89 D8 5B 5D C3 }
	condition:
		$pattern
}

rule _objalloc_alloc_93459a63ac4f94260c3eb032b5e0aebe {
	meta:
		aliases = "_objalloc_alloc"
		type = "func"
		size = "252"
		objfiles = "objalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 83 EC 08 48 85 F6 75 1A 8B 57 08 83 FA 07 0F 87 CF 00 00 00 BB 08 00 00 00 EB 22 0F 1F 80 00 00 00 00 8B 57 08 48 8D 5E 07 48 83 E3 F8 89 D0 48 39 C3 76 56 48 81 FB FF 01 00 00 77 6D BF E0 0F 00 00 E8 ?? ?? ?? ?? 48 85 C0 0F 84 8A 00 00 00 48 8B 55 10 48 C7 40 08 00 00 00 00 48 89 10 48 89 45 10 BA D0 0F 00 00 48 8D 44 18 10 29 DA 89 55 08 48 89 45 00 48 83 C4 08 48 29 D8 5B 5D C3 66 2E 0F 1F 84 00 00 00 00 00 48 89 D8 89 D9 48 F7 D8 48 03 5D 00 29 CA 89 55 08 48 89 5D 00 48 83 C4 08 48 01 D8 5B 5D C3 90 48 8D 7B 10 E8 ?? ?? ?? ?? 48 85 C0 74 22 48 8B 55 10 48 89 10 48 8B 55 }
	condition:
		$pattern
}

rule freeargv_4728983b5c7afac973096a0582fa513b {
	meta:
		aliases = "freeargv"
		type = "func"
		size = "71"
		objfiles = "argv@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 83 EC 08 48 85 FF 74 32 48 8B 3F 48 89 EB 48 85 FF 74 18 0F 1F 80 00 00 00 00 48 83 C3 08 E8 ?? ?? ?? ?? 48 8B 3B 48 85 FF 75 EF 48 83 C4 08 48 89 EF 5B 5D E9 ?? ?? ?? ?? 90 48 83 C4 08 5B 5D C3 }
	condition:
		$pattern
}

rule strsep_885b17cbd2597523a4ffc25f1e3d43f3 {
	meta:
		aliases = "__GI_strsep, strsep"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "70"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 83 EC 08 48 8B 5F 40 48 8B 7B 08 E8 ?? ?? ?? ?? 48 8B 7B 20 48 85 FF 74 05 E8 ?? ?? ?? ?? 48 8B 7D 40 E8 ?? ?? ?? ?? 48 8B 7D 20 48 85 FF 74 05 E8 ?? ?? ?? ?? 58 5B 48 89 EF 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule objalloc_free_eba637125649fef6faa3e2508e37e863 {
	meta:
		aliases = "objalloc_free"
		type = "func"
		size = "54"
		objfiles = "objalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 83 EC 08 48 8B 7F 10 48 85 FF 75 09 EB 14 0F 1F 40 00 48 89 DF 48 8B 1F E8 ?? ?? ?? ?? 48 85 DB 75 F0 48 83 C4 08 48 89 EF 5B 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __cxa_finalize_63b570aae33cad5021ca38560fe1309a {
	meta:
		aliases = "__cxa_finalize"
		type = "func"
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
		type = "func"
		size = "56"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 83 EC 08 E8 ?? ?? ?? ?? EB 0F 48 8B 33 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 0D E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 75 E4 E8 ?? ?? ?? ?? 5E 48 89 D8 5B 5D C3 }
	condition:
		$pattern
}

rule getc_539950c5b176b846a1a514db270db142 {
	meta:
		aliases = "__GI_fgetc, fgetc, getc"
		type = "func"
		size = "128"
		objfiles = "fgetc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 83 EC 28 83 7F 50 00 74 1F 48 8B 47 18 48 3B 47 28 73 0C 0F B6 18 48 FF C0 48 89 47 18 EB 52 E8 ?? ?? ?? ?? 89 C3 EB 49 48 8D 5F 58 BE ?? ?? ?? ?? 48 89 E7 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8B 45 18 48 3B 45 28 73 0C 0F B6 18 48 FF C0 48 89 45 18 EB 0A 48 89 EF E8 ?? ?? ?? ?? 89 C3 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 89 D8 48 83 C4 28 5B 5D C3 }
	condition:
		$pattern
}

rule xdr_callmsg_08123761d2406bdb623e2a8eda74dae7 {
	meta:
		aliases = "__GI_xdr_callmsg, xdr_callmsg"
		type = "func"
		size = "820"
		objfiles = "rpc_cmsg@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 F3 48 83 EC 08 83 3F 00 0F 85 E7 00 00 00 8B 4E 40 81 F9 90 01 00 00 0F 87 03 03 00 00 8B 46 58 3D 90 01 00 00 0F 87 F5 02 00 00 48 8B 57 08 8D 71 03 83 C0 03 83 E0 FC 83 E6 FC 8D 74 06 28 FF 52 30 48 85 C0 48 89 C2 0F 84 A7 00 00 00 48 8B 03 0F C8 89 02 8B 43 08 0F C8 89 42 04 83 7B 08 00 0F 85 B9 02 00 00 48 8B 43 10 0F C8 89 42 08 48 83 7B 10 02 0F 85 A5 02 00 00 48 8B 43 18 48 8D 6A 20 0F C8 89 42 0C 48 8B 43 20 0F C8 89 42 10 48 8B 43 28 0F C8 89 42 14 8B 43 30 0F C8 89 42 18 8B 43 40 0F C8 89 42 1C 8B 43 40 85 C0 74 1A 48 8B 73 38 48 89 EF 89 C2 E8 ?? ?? ?? ?? 8B 43 }
	condition:
		$pattern
}

rule xdr_callhdr_c429209e682ad1afaad3ecd6624b28c7 {
	meta:
		aliases = "__GI_xdr_callhdr, xdr_callhdr"
		type = "func"
		size = "110"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 F3 48 83 EC 08 C7 46 08 00 00 00 00 48 C7 46 10 02 00 00 00 83 3F 00 75 48 E8 ?? ?? ?? ?? 85 C0 74 3F 48 8D 73 08 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 2F 48 8D 73 10 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 1F 48 8D 73 18 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 0F 59 48 8D 73 20 48 89 EF 5B 5D E9 ?? ?? ?? ?? 5A 5B 5D 31 C0 C3 }
	condition:
		$pattern
}

rule xstrndup_3204fb48bc4f011b7a24901b24afca7c {
	meta:
		aliases = "xstrndup"
		type = "func"
		size = "57"
		objfiles = "xstrndup@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 F3 48 83 EC 08 E8 ?? ?? ?? ?? 48 39 D8 48 0F 46 D8 48 8D 7B 01 E8 ?? ?? ?? ?? C6 04 18 00 48 83 C4 08 48 89 DA 5B 48 89 EE 48 89 C7 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_attr_setguardsize_c05af2c187dadc93f1f24ac63261920b {
	meta:
		aliases = "__pthread_attr_setguardsize, pthread_attr_setguardsize"
		type = "func"
		size = "61"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 F3 48 83 EC 08 E8 ?? ?? ?? ?? 48 63 F0 48 8D 54 1E FF 48 89 D0 31 D2 48 F7 F6 48 89 C1 B8 16 00 00 00 48 0F AF CE 48 3B 4D 30 73 06 48 89 4D 18 30 C0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule xdr_opaque_auth_2f55d83a6c9d31fe49db5ca7db5b9551 {
	meta:
		aliases = "__GI_xdr_opaque_auth, xdr_opaque_auth"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "78"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 F3 48 83 EC 08 E8 ?? ?? ?? ?? 85 C0 74 32 48 8D 73 08 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 22 83 7B 08 01 75 1C 41 5B 48 8D 53 18 48 8D 73 10 48 89 EF 5B 5D 45 31 C0 B9 ?? ?? ?? ?? E9 ?? ?? ?? ?? 41 5A 5B 5D 31 C0 C3 }
	condition:
		$pattern
}

rule xdr_rejected_reply_8f8430bcd8d5d4117f5af1b1d473c692 {
	meta:
		aliases = "__GI_xdr_rejected_reply, xdr_rejected_reply"
		type = "func"
		size = "87"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 F3 48 83 EC 08 E8 ?? ?? ?? ?? 85 C0 74 3C 8B 03 85 C0 74 06 FF C8 75 32 EB 20 48 8D 73 08 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 20 41 59 48 8D 73 10 48 89 EF 5B 5D E9 ?? ?? ?? ?? 41 58 48 8D 73 08 48 89 EF 5B 5D E9 ?? ?? ?? ?? 5E 5B 5D 31 C0 C3 }
	condition:
		$pattern
}

rule xdr_accepted_reply_507fdc2954f4f34d2196767c5f2c19d6 {
	meta:
		aliases = "__GI_xdr_accepted_reply, xdr_accepted_reply"
		type = "func"
		size = "113"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 F3 48 83 EC 08 E8 ?? ?? ?? ?? 85 C0 74 56 48 8D 73 18 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 46 8B 53 18 85 D2 74 0C 83 FA 02 B8 01 00 00 00 75 37 EB 14 48 8B 73 20 4C 8B 5B 28 48 89 EF 41 58 5B 5D 31 C0 41 FF E3 48 8D 73 20 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 0F 59 48 8D 73 28 48 89 EF 5B 5D E9 ?? ?? ?? ?? 31 C0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule xdr_authunix_parms_030cc0796fea945de926145f6ff93f8a {
	meta:
		aliases = "__GI_xdr_authunix_parms, xdr_authunix_parms"
		type = "func"
		size = "123"
		objfiles = "authunix_prot@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 F3 48 83 EC 08 E8 ?? ?? ?? ?? 85 C0 74 60 48 8D 73 08 BA FF 00 00 00 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 4B 48 8D 73 10 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 3B 48 8D 73 14 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 2B 48 8D 53 18 48 8D 73 20 41 B9 ?? ?? ?? ?? 41 B8 04 00 00 00 B9 10 00 00 00 48 89 EF E8 ?? ?? ?? ?? 85 C0 0F 95 C0 0F B6 C0 EB 02 31 C0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule skip_input_bytes_844981db35484a3893036c54dbe80c27 {
	meta:
		aliases = "skip_input_bytes"
		type = "func"
		size = "75"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 F3 48 83 EC 08 EB 2F 48 8B 55 58 48 8B 45 60 29 D0 75 0E 48 89 EF E8 9A FF FF FF 85 C0 75 17 EB 1F 48 98 48 39 C3 48 0F 4E C3 48 98 48 01 C2 48 29 C3 48 89 55 58 48 85 DB 7F CC B8 01 00 00 00 59 5B 5D C3 }
	condition:
		$pattern
}

rule dl_iterate_phdr_2605263bd07fe88e633ced46b383bc7e {
	meta:
		aliases = "dl_iterate_phdr"
		type = "func"
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
		type = "func"
		size = "48"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 FB 48 83 EC 08 EB 09 48 83 C3 10 E8 ?? ?? ?? ?? 48 8B 7B 08 48 85 FF 75 EE 83 3B 00 75 E9 58 5B 48 89 EF 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tmpnam_648e8f61292d4a4dcab4b9b3ee15d07f {
	meta:
		aliases = "tmpnam"
		type = "func"
		size = "98"
		objfiles = "tmpnam@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 89 FB 48 83 EC 28 48 85 FF 75 03 48 89 E5 31 C9 31 D2 BE 14 00 00 00 48 89 EF E8 ?? ?? ?? ?? 85 C0 75 2D BE 03 00 00 00 48 89 EF E8 ?? ?? ?? ?? 85 C0 75 1C 48 85 DB 75 19 BA 14 00 00 00 48 89 EE BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C3 EB 02 31 DB 48 89 D8 48 83 C4 28 5B 5D C3 }
	condition:
		$pattern
}

rule free_split_directories_7da63bc6216a33ab9199ae96118b4ec8 {
	meta:
		aliases = "free_split_directories"
		type = "func"
		size = "56"
		objfiles = "make_relative_prefix@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 8D 5D 08 48 83 EC 08 48 8B 3F 48 85 FF 74 15 0F 1F 00 48 83 C3 08 E8 ?? ?? ?? ?? 48 8B 7B F8 48 85 FF 75 EE 48 83 C4 08 48 89 EF 5B 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule siglongjmp_a604e997d5b680e2fc631f181478479f {
	meta:
		aliases = "__libc_longjmp, __libc_siglongjmp, _longjmp, longjmp, siglongjmp"
		type = "func"
		size = "53"
		objfiles = "longjmp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 89 F3 48 83 EC 08 83 7F 40 00 74 10 48 8D 77 48 31 D2 BF 02 00 00 00 E8 ?? ?? ?? ?? 85 DB B8 01 00 00 00 48 89 EF 0F 44 D8 89 DE E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule encrypt_dd06b43141aecc1ad7bf8b1399acbd3b {
	meta:
		aliases = "encrypt"
		type = "func"
		size = "180"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 89 F3 48 83 EC 18 E8 7F F8 FF FF 31 FF E8 A7 FC FF FF 48 89 E9 31 FF EB 2F 48 63 C7 31 D2 48 89 C6 C7 04 84 00 00 00 00 EB 17 F6 01 01 74 0D 48 63 C2 8B 04 85 ?? ?? ?? ?? 09 04 B4 48 FF C1 FF C2 83 FA 1F 7E E4 FF C7 83 FF 01 7E CC 83 FB 01 8B 3C 24 8B 74 24 04 45 19 C0 48 8D 4C 24 04 48 89 E2 41 83 E0 02 41 FF C8 E8 94 FC FF FF 31 FF EB 23 89 F0 48 63 CE 42 8B 14 84 44 09 C8 85 14 8D ?? ?? ?? ?? 48 98 0F 95 44 05 00 FF C6 83 FE 1F 7E DF FF C7 83 FF 01 7F 0E 41 89 F9 31 F6 4C 63 C7 41 C1 E1 05 EB CA 48 83 C4 18 5B 5D C3 }
	condition:
		$pattern
}

rule xdrrec_getpos_2fb6cb593f829755e3898481c771c173 {
	meta:
		aliases = "xdrrec_getpos"
		type = "func"
		size = "83"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD BA 01 00 00 00 31 F6 53 48 83 EC 08 48 8B 5F 18 48 8B 3B E8 ?? ?? ?? ?? 48 89 C2 48 83 FA FF 74 2A 8B 4D 00 85 C9 74 0B FF C9 B8 FF FF FF FF 75 1A EB 0D 48 8B 43 20 48 2B 43 18 48 01 D0 EB 0B 48 89 D0 48 2B 43 60 48 03 43 58 5F 5B 5D C3 }
	condition:
		$pattern
}

rule logout_6ebdcc4c707407b39aed7e53c7f115f8 {
	meta:
		aliases = "logout"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "32"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 48 8B 06 48 89 E5 48 8D 50 40 48 89 05 ?? ?? ?? ?? 48 8B 4A 08 48 8B 68 40 48 8B 62 10 FF E1 }
	condition:
		$pattern
}

rule __getdents64_525770fb71243fbb3c5f7f0af40e7d32 {
	meta:
		aliases = "__getdents, __getdents64"
		type = "func"
		size = "288"
		objfiles = "getdents64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 48 8D 42 1E 48 89 E5 41 57 48 83 E0 F0 49 89 F7 41 56 49 89 D6 41 55 41 54 49 89 F4 53 48 83 EC 18 89 7D CC 48 63 FF 48 29 C4 B8 D9 00 00 00 4C 8D 6C 24 0F 49 83 E5 F0 4C 89 EE 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 89 D8 48 83 C9 FF 48 63 D3 FF C0 0F 84 A5 00 00 00 49 8D 54 15 00 4F 8D 34 37 4C 89 EB 48 89 4D D0 48 89 55 C0 EB 7F 0F B7 43 10 48 8D 50 07 48 83 E2 F8 4D 8D 2C 14 4D 39 F5 76 24 48 8B 75 D0 8B 7D CC 31 D2 E8 ?? ?? ?? ?? 4D 39 FC 75 61 E8 ?? ?? ?? ?? 48 83 C9 FF C7 00 16 00 00 00 EB 56 48 8B 43 08 48 8D 73 13 49 8D 7C 24 13 48 89 45 }
	condition:
		$pattern
}

rule fibheap_delete_node_1127da2a7ed75c29c4ad936f7e8ac74d {
	meta:
		aliases = "fibheap_delete_node"
		type = "func"
		size = "49"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 BA 00 00 00 00 00 00 00 80 48 89 FD 53 48 83 EC 08 48 8B 5E 28 48 89 D9 E8 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 48 83 C4 08 48 89 D8 5B 5D C3 }
	condition:
		$pattern
}

rule forkpty_b1a1a2e8909ecddfbf9e6839c05c61c6 {
	meta:
		aliases = "forkpty"
		type = "func"
		size = "114"
		objfiles = "forkpty@libutil.a"
	strings:
		$pattern = { ( CC | 55 ) 49 89 F1 48 89 FD 49 89 C8 48 89 D1 4C 89 CA 53 48 83 EC 18 48 8D 74 24 10 48 8D 7C 24 14 E8 ?? ?? ?? ?? FF C0 74 3E E8 ?? ?? ?? ?? 83 F8 FF 89 C3 74 32 85 C0 8B 7C 24 14 75 1C E8 ?? ?? ?? ?? 8B 7C 24 10 E8 ?? ?? ?? ?? 85 C0 74 1B BF 01 00 00 00 E8 ?? ?? ?? ?? 89 7D 00 8B 7C 24 10 E8 ?? ?? ?? ?? EB 03 83 CB FF 89 D8 48 83 C4 18 5B 5D C3 }
	condition:
		$pattern
}

rule __ns_name_ntop_ea57f76d8b93a760e5c4974c33ab9974 {
	meta:
		aliases = "__GI___ns_name_ntop, __ns_name_ntop"
		type = "func"
		size = "381"
		objfiles = "ns_name@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 4C 8D 14 16 49 89 F0 53 48 BB 05 10 00 42 00 00 00 04 48 83 EC 18 E9 0D 01 00 00 44 0F B6 D8 41 F6 C3 C0 0F 85 1F 01 00 00 49 39 F0 75 05 49 89 F0 EB 10 4D 39 D0 0F 83 0C 01 00 00 41 C6 00 2E 49 FF C0 44 89 D8 49 8D 04 00 4C 39 D0 0F 83 F5 00 00 00 48 FF C7 E9 C4 00 00 00 8A 17 8D 4A DE 80 F9 3A 0F 87 FB 00 00 00 B8 01 00 00 00 48 D3 E0 48 85 C3 0F 84 EA 00 00 00 49 8D 40 01 4C 39 D0 0F 83 C1 00 00 00 41 C6 00 5C 41 88 50 01 49 83 C0 02 E9 81 00 00 00 49 8D 40 03 4C 39 D0 0F 83 A3 00 00 00 44 0F B6 CA B2 64 31 C9 44 89 C8 BD 64 00 00 00 41 C6 00 5C F6 F2 89 CA 0F B6 C0 8A 80 ?? ?? ?? ?? 41 }
	condition:
		$pattern
}

rule __pthread_timedsuspend_new_05d937c8e141336ea25a83e2355ae320 {
	meta:
		aliases = "__pthread_timedsuspend_new"
		type = "func"
		size = "298"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 81 EC 08 02 00 00 48 89 7C 24 08 48 89 34 24 48 8D 7C 24 10 BE 01 00 00 00 E8 ?? ?? ?? ?? 85 C0 BA 01 00 00 00 0F 85 E3 00 00 00 48 8B 54 24 08 48 8D 9C 24 60 01 00 00 48 8D 44 24 10 48 89 DF 48 89 42 40 C7 42 38 00 00 00 00 E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8D 94 24 E0 00 00 00 48 89 DE BF 01 00 00 00 E8 ?? ?? ?? ?? 48 8D AC 24 F0 01 00 00 48 8D 9C 24 E0 01 00 00 31 F6 48 89 EF E8 ?? ?? ?? ?? 48 69 84 24 F8 01 00 00 E8 03 00 00 48 8B 0C 24 48 8B 51 08 48 8B 09 48 2B 8C 24 F0 01 00 00 48 29 C2 48 85 D2 48 89 94 24 E8 01 00 00 48 89 8C 24 E0 01 00 00 79 1B 48 }
	condition:
		$pattern
}

rule pthread_initialize_85936bd8a22a75cc1f32235b44dcdc2c {
	meta:
		aliases = "pthread_initialize"
		type = "func"
		size = "421"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 81 EC 38 01 00 00 48 83 3D ?? ?? ?? ?? 00 0F 85 84 01 00 00 48 8D 84 24 00 00 C0 FF 48 25 00 00 E0 FF 48 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 EB 11 83 78 50 01 74 07 C7 40 50 00 00 00 00 48 8B 40 38 48 85 C0 75 EA 48 8D 9C 24 20 01 00 00 BF 03 00 00 00 48 89 DE E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA 00 00 20 00 01 C0 29 C2 48 63 C2 48 39 84 24 20 01 00 00 76 15 48 89 DE BF 03 00 00 00 48 89 84 24 20 01 00 00 E8 ?? ?? ?? ?? 48 8D 5C 24 08 48 C7 04 24 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule des_init_1ab69a5f5095bbc8c00d6ac39407a358 {
	meta:
		aliases = "des_init"
		type = "func"
		size = "1071"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 81 EC 90 01 00 00 83 3D ?? ?? ?? ?? 01 0F 84 0F 04 00 00 45 31 C0 C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 EB 4C 49 63 F8 48 8D 84 24 88 01 00 00 31 F6 48 C1 E7 06 4C 8D 0C 07 89 F2 89 F0 48 63 CE 83 E2 01 D1 F8 83 E0 0F C1 E2 04 09 C2 89 F0 FF C6 83 E0 20 09 C2 83 FE 3F 48 63 D2 8A 84 3A ?? ?? ?? ?? 42 88 84 09 00 FE FF FF 7E CC 41 FF C0 41 83 F8 07 7E AE 45 31 D2 EB 39 41 0F B6 83 00 FE FF FF 48 63 CE 89 F2 09 DA FF C6 48 63 D2 C1 E0 04 0A 84 29 00 FE FF FF 83 FE 3F 42 88 84 0A ?? ?? ?? ?? 7E D5 FF C7 83 }
	condition:
		$pattern
}

rule sethostid_fb7144e35b4174d2fc15f0a05395e933 {
	meta:
		aliases = "sethostid"
		type = "func"
		size = "116"
		objfiles = "hostid@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 83 EC 08 48 89 3C 24 E8 ?? ?? ?? ?? 85 C0 75 09 E8 ?? ?? ?? ?? 85 C0 74 12 BB 01 00 00 00 E8 ?? ?? ?? ?? C7 00 01 00 00 00 EB 40 31 C0 BA A4 01 00 00 BE 41 00 00 00 BF ?? ?? ?? ?? 83 CB FF E8 ?? ?? ?? ?? 85 C0 89 C5 78 21 89 C7 48 89 E6 BA 08 00 00 00 E8 ?? ?? ?? ?? 31 DB 48 83 F8 08 89 EF 0F 94 C3 FF CB E8 ?? ?? ?? ?? 5A 89 D8 5B 5D C3 }
	condition:
		$pattern
}

rule token_56acefc5f391c5ab05df9a4d9cde1705 {
	meta:
		aliases = "token"
		type = "func"
		size = "390"
		objfiles = "ruserpass@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 83 EC 08 48 8B 05 ?? ?? ?? ?? 0F B7 00 A8 0C 0F 85 68 01 00 00 48 8B 3D ?? ?? ?? ?? 48 8B 47 18 48 3B 47 28 73 0C 0F B6 10 48 FF C0 48 89 47 18 EB 10 E8 ?? ?? ?? ?? 83 F8 FF 89 C2 0F 84 3B 01 00 00 8D 42 F7 83 F8 01 76 CB 83 FA 20 74 C6 83 FA 2C 74 C1 83 FA 22 BB ?? ?? ?? ?? 74 30 EB 5E 83 FA 5C 75 24 48 8B 3D ?? ?? ?? ?? 48 8B 47 18 48 3B 47 28 73 0C 0F B6 10 48 FF C0 48 89 47 18 EB 07 E8 ?? ?? ?? ?? 89 C2 88 13 48 FF C3 48 8B 3D ?? ?? ?? ?? 48 8B 47 18 48 3B 47 28 73 0C 0F B6 10 48 FF C0 48 89 47 18 EB 0C E8 ?? ?? ?? ?? 83 F8 FF 89 C2 74 7F 83 FA 22 75 A4 EB 78 BB ?? ?? ?? ?? 88 15 }
	condition:
		$pattern
}

rule xatexit_cleanup_cd12ded3690a38d8688b5a596380f705 {
	meta:
		aliases = "xatexit_cleanup"
		type = "func"
		size = "63"
		objfiles = "xatexit@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 83 EC 08 48 8B 2D ?? ?? ?? ?? 48 85 ED 74 26 66 0F 1F 44 00 00 8B 5D 08 83 EB 01 78 0F 48 63 C3 83 EB 01 FF 54 C5 10 83 FB FF 75 F1 48 8B 6D 00 48 85 ED 75 E0 48 83 C4 08 5B 5D C3 }
	condition:
		$pattern
}

rule _dl_run_fini_array_8e0d32ddaaaa14c2b3cecec913e7ac2f {
	meta:
		aliases = "_dl_run_fini_array"
		type = "func"
		size = "57"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 83 EC 08 48 8B 87 50 01 00 00 48 85 C0 74 23 48 89 C5 48 8B 87 60 01 00 00 48 03 2F 48 89 C3 48 C1 EB 03 EB 06 89 D8 FF 54 C5 00 FF CB 83 FB FF 75 F3 58 5B 5D C3 }
	condition:
		$pattern
}

rule __fresetlockfiles_874c5ad4af07dc088773deb63f32aaac {
	meta:
		aliases = "__fresetlockfiles"
		type = "func"
		size = "72"
		objfiles = "lockfile@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 83 EC 18 48 89 E7 E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? 48 8B 2D ?? ?? ?? ?? EB 10 48 8D 7D 58 48 89 E6 E8 ?? ?? ?? ?? 48 8B 6D 38 48 85 ED 75 EB 48 89 E7 E8 ?? ?? ?? ?? 48 83 C4 18 5B 5D C3 }
	condition:
		$pattern
}

rule getttyent_2338fd7d4d6d62825b5855102f4ae088 {
	meta:
		aliases = "__GI_getttyent, getttyent"
		type = "func"
		size = "719"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 83 EC 28 48 83 3D ?? ?? ?? ?? 00 75 0F E8 ?? ?? ?? ?? 31 DB 85 C0 0F 84 A6 02 00 00 48 83 3D ?? ?? ?? ?? 00 75 1B BF 00 10 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 75 05 E8 ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? 48 89 E7 BE ?? ?? ?? ?? 48 83 C2 58 E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 83 C7 58 E8 ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? BE 00 10 00 00 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 75 07 31 DB E9 25 02 00 00 BE 0A 00 00 00 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 75 32 48 8B 3D ?? ?? ?? ?? 48 8B 47 18 48 3B 47 28 73 0C 0F B6 10 48 FF C0 48 89 47 18 EB 07 E8 ?? ?? ?? ?? 89 }
	condition:
		$pattern
}

rule getchar_d82d64feb99a75213daaa7280bc1b43a {
	meta:
		aliases = "getchar"
		type = "func"
		size = "135"
		objfiles = "getchar@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 83 EC 28 48 8B 2D ?? ?? ?? ?? 83 7D 50 00 74 22 48 8B 45 18 48 3B 45 28 73 0C 0F B6 18 48 FF C0 48 89 45 18 EB 55 48 89 EF E8 ?? ?? ?? ?? 89 C3 EB 49 48 8D 5D 58 48 89 E7 BE ?? ?? ?? ?? 48 89 DA E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8B 45 18 48 3B 45 28 73 0C 0F B6 18 48 FF C0 48 89 45 18 EB 0A 48 89 EF E8 ?? ?? ?? ?? 89 C3 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 89 D8 48 83 C4 28 5B 5D C3 }
	condition:
		$pattern
}

rule authnone_create_3da98768cd6a6bb2978700dbaee7df12 {
	meta:
		aliases = "__GI_authnone_create, authnone_create"
		type = "func"
		size = "190"
		objfiles = "auth_none@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 83 EC 38 E8 ?? ?? ?? ?? 48 8B 98 B0 00 00 00 48 89 C5 48 85 DB 75 27 BF 01 00 00 00 BE 60 00 00 00 E8 ?? ?? ?? ?? 48 89 C7 31 C0 48 85 FF 0F 84 80 00 00 00 48 89 FB 48 89 BD B0 00 00 00 83 7B 5C 00 75 6D FC 48 8D 7B 18 BE ?? ?? ?? ?? B9 06 00 00 00 F3 A5 48 8D 73 18 48 89 DF BA 14 00 00 00 48 C7 43 38 ?? ?? ?? ?? B1 06 F3 A5 48 8D 73 48 48 89 E7 E8 ?? ?? ?? ?? 48 89 DE 48 89 E7 E8 ?? ?? ?? ?? 48 8D 73 18 48 89 E7 E8 ?? ?? ?? ?? 48 8B 44 24 08 48 89 E7 FF 50 20 89 43 5C 48 8B 44 24 08 48 8B 40 38 48 85 C0 74 05 48 89 E7 FF D0 48 89 D8 48 83 C4 38 5B 5D C3 }
	condition:
		$pattern
}

rule concat_length_b19ce43963a06cdda32d69987da175b4 {
	meta:
		aliases = "concat_length"
		type = "func"
		size = "153"
		objfiles = "concat@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 83 EC 58 48 85 FF 48 8D 44 24 70 48 89 74 24 28 48 89 54 24 30 48 89 4C 24 38 4C 89 44 24 40 48 89 44 24 10 48 8D 44 24 20 4C 89 4C 24 48 C7 44 24 08 08 00 00 00 48 89 44 24 18 74 55 48 89 C5 31 DB EB 1D 66 0F 1F 84 00 00 00 00 00 89 D0 83 C2 08 48 01 E8 89 54 24 08 48 8B 38 48 85 FF 74 27 E8 ?? ?? ?? ?? 8B 54 24 08 48 01 C3 83 FA 2F 76 DB 48 8B 44 24 10 48 8B 38 48 8D 50 08 48 89 54 24 10 48 85 FF 75 D9 48 83 C4 58 48 89 D8 5B 5D C3 31 DB EB F2 }
	condition:
		$pattern
}

rule statfs64_60f584c2814ea6f96f402226aaa9e636 {
	meta:
		aliases = "__GI_fstatfs64, __GI_statfs64, fstatfs64, statfs64"
		type = "func"
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
		type = "func"
		size = "69"
		objfiles = "psignal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 F3 48 83 EC 08 48 85 F6 74 0A 80 3E 00 BD ?? ?? ?? ?? 75 08 BB ?? ?? ?? ?? 48 89 DD E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 89 DA 48 89 E9 41 59 5B 5D 49 89 C0 BE ?? ?? ?? ?? 31 C0 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule popen_b1ccdb9af12ab2088e3e20f98ea03327 {
	meta:
		aliases = "popen"
		type = "func"
		size = "485"
		objfiles = "popen@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 F3 48 83 EC 68 48 89 7C 24 08 8A 06 3C 77 74 1C 3C 72 C7 44 24 2C 01 00 00 00 74 18 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 A0 01 00 00 C7 44 24 2C 00 00 00 00 BF 18 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 C7 44 24 10 00 00 00 00 0F 84 85 01 00 00 48 8D 7C 24 50 48 89 44 24 18 E8 ?? ?? ?? ?? 85 C0 0F 85 5B 01 00 00 48 63 44 24 2C 48 89 DE 8B 44 84 50 89 44 24 28 B8 01 00 00 00 2B 44 24 2C 48 98 8B 44 84 50 89 C7 89 44 24 24 E8 ?? ?? ?? ?? 48 85 C0 48 89 44 24 10 75 17 8B 7C 24 24 E8 ?? ?? ?? ?? 8B 7C 24 28 E8 ?? ?? ?? ?? E9 10 01 00 00 48 8D 7C 24 30 BA ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? }
	condition:
		$pattern
}

rule pthread_start_thread_9407a27b6847ffaf24aef9b545b9db18 {
	meta:
		aliases = "pthread_start_thread"
		type = "func"
		size = "196"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 81 EC C8 00 00 00 E8 ?? ?? ?? ?? 48 8D B3 C0 00 00 00 31 D2 89 43 28 BF 02 00 00 00 E8 ?? ?? ?? ?? 8B B3 40 01 00 00 85 F6 78 0C 8B 7B 28 48 8D 93 44 01 00 00 EB 21 83 3D ?? ?? ?? ?? 00 7E 1D 8B 7B 28 48 8D 94 24 B0 00 00 00 C7 84 24 B0 00 00 00 00 00 00 00 31 F6 E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 85 C0 74 3F 83 3D ?? ?? ?? ?? 00 7E 36 48 89 1C 24 C7 44 24 08 05 00 00 00 8B 3D ?? ?? ?? ?? BA A8 00 00 00 48 89 E6 E8 ?? ?? ?? ?? 48 FF C0 75 0A E8 ?? ?? ?? ?? 83 38 04 74 DE 48 89 DF E8 ?? ?? ?? ?? 48 8B BB B8 00 00 00 FF 93 B0 00 00 00 48 89 C7 48 89 E6 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule splay_tree_predecessor_9c246c1b4b7e934b8dbdff2d2aa91ef8 {
	meta:
		aliases = "splay_tree_predecessor"
		type = "func"
		size = "89"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 48 83 3F 00 74 41 48 89 F5 E8 E9 F9 FF FF 48 8B 03 48 89 EE 48 8B 38 FF 53 08 85 C0 48 8B 03 78 1A 48 8B 40 10 48 85 C0 75 08 EB 1B 0F 1F 00 48 89 D0 48 8B 50 18 48 85 D2 75 F4 48 83 C4 08 5B 5D C3 0F 1F 44 00 00 48 83 C4 08 31 C0 5B 5D C3 }
	condition:
		$pattern
}

rule splay_tree_successor_649a7622388ba8e3186bc68eef8c56de {
	meta:
		aliases = "splay_tree_successor"
		type = "func"
		size = "100"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 48 83 3F 00 74 51 48 89 F5 E8 89 F9 FF FF 48 8B 03 48 89 EE 48 8B 38 FF 53 08 85 C0 48 8B 03 7E 0E 48 83 C4 08 5B 5D C3 0F 1F 80 00 00 00 00 48 8B 40 18 48 85 C0 75 0A EB 1D 0F 1F 44 00 00 48 89 D0 48 8B 50 10 48 85 D2 75 F4 48 83 C4 08 5B 5D C3 0F 1F 44 00 00 31 C0 EB C6 }
	condition:
		$pattern
}

rule herror_10d80b46e072d29cf44f91c37cd159da {
	meta:
		aliases = "__GI_herror, herror"
		type = "func"
		size = "88"
		objfiles = "herror@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 48 85 FF 74 0A 80 3F 00 BD ?? ?? ?? ?? 75 05 BD ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 00 BA ?? ?? ?? ?? 83 F8 04 77 0A 48 98 48 8B 14 C5 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 49 89 D0 48 89 DA 41 59 5B 48 89 E9 BE ?? ?? ?? ?? 31 C0 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xcalloc_e2591480d736bae1a8b4ae0509fa0917 {
	meta:
		aliases = "xcalloc"
		type = "func"
		size = "72"
		objfiles = "xmalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 48 85 FF 74 22 48 85 F6 48 89 F5 74 1A 48 89 EE 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 74 16 48 83 C4 08 5B 5D C3 0F 1F 00 BD 01 00 00 00 BB 01 00 00 00 EB DA 48 89 EF 48 0F AF FB E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule d_print_append_char_2243b41f6c1ca943df6135ea837bba82 {
	meta:
		aliases = "d_print_append_char"
		type = "func"
		size = "73"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 48 8B 47 08 48 85 C0 74 15 48 8B 57 10 48 3B 57 18 89 F5 73 12 40 88 2C 10 48 83 43 10 01 48 83 C4 08 5B 5D C3 66 90 BE 01 00 00 00 E8 F6 FE FF FF 48 8B 43 08 48 85 C0 74 E4 48 8B 53 10 EB D5 }
	condition:
		$pattern
}

rule d_operator_name_daffe75d3eead769b8c61ffb564a28e4 {
	meta:
		aliases = "d_operator_name"
		type = "func"
		size = "352"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 48 8B 47 18 48 8D 50 01 48 89 57 18 0F B6 38 48 8D 50 02 48 89 53 18 0F B6 68 01 40 80 FF 76 74 76 40 80 FD 76 0F 84 BC 00 00 00 BE 31 00 00 00 31 D2 0F 1F 44 00 00 89 F0 29 D0 89 C1 C1 E9 1F 01 C8 D1 F8 01 D0 48 63 C8 48 8D 0C 49 4C 8B 04 CD ?? ?? ?? ?? 4C 8D 0C CD ?? ?? ?? ?? 41 0F B6 08 40 38 F9 74 19 40 38 CF 7D 27 89 C6 39 F2 75 C6 31 C0 48 83 C4 08 5B 5D C3 0F 1F 44 00 00 41 0F B6 48 01 40 38 E9 0F 84 8A 00 00 00 40 38 CD 7C D9 8D 50 01 EB D6 8D 45 D0 3C 09 77 8D 48 89 DF E8 21 D1 FF FF 8B 53 28 3B 53 2C 7D C3 48 63 CA 83 C2 01 48 8D 34 49 48 8B 4B 20 89 53 28 }
	condition:
		$pattern
}

rule fill_input_buf_1c976b3ab5a786bb1de46983df1b5509 {
	meta:
		aliases = "fill_input_buf"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "72"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 48 8B 6F 48 E8 ?? ?? ?? ?? 8B 3B E8 ?? ?? ?? ?? 48 8B 45 18 48 8B 40 38 48 85 C0 74 06 48 8D 7D 10 FF D0 48 8B 7B 40 E8 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 58 48 89 DF 5B 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdr_opaque_5aa762b42166feb40c3dcae05641c1dc {
	meta:
		aliases = "__GI_xdr_opaque, xdr_opaque"
		type = "func"
		size = "136"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 85 D2 74 6E 89 D0 31 ED 83 E0 03 74 05 40 B5 04 29 C5 8B 03 83 F8 01 74 09 72 2D 83 F8 02 75 59 EB 50 48 8B 43 08 48 89 DF FF 50 10 85 C0 74 49 85 ED 74 3E 48 8B 43 08 89 EA BE ?? ?? ?? ?? 48 89 DF 4C 8B 58 10 EB 24 48 8B 43 08 48 89 DF FF 50 18 85 C0 74 23 85 ED 74 18 48 8B 43 08 89 EA BE ?? ?? ?? ?? 48 89 DF 4C 8B 58 18 58 5B 5D 41 FF E3 B8 01 00 00 00 EB 02 31 C0 5D 5B 5D C3 }
	condition:
		$pattern
}

rule squangle_mop_up_8ff63c47df83a6538e2b842bf0f6f679 {
	meta:
		aliases = "squangle_mop_up"
		type = "func"
		size = "208"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 8B 43 20 48 63 D0 48 8D 2C D5 F8 FF FF FF EB 21 0F 1F 80 00 00 00 00 48 8B 53 10 83 E8 01 89 43 20 48 8B 3C 2A 48 8D 55 F8 48 85 FF 75 59 48 89 D5 85 C0 7F E2 8B 43 24 48 8B 7B 18 48 63 D0 48 8D 2C D5 F8 FF FF FF EB 1C 66 0F 1F 44 00 00 48 8B 0C 2F 83 E8 01 48 8D 55 F8 89 43 24 48 85 C9 75 45 48 89 D5 85 C0 7F E6 48 85 FF 74 05 E8 ?? ?? ?? ?? 48 8B 7B 10 48 85 FF 74 44 48 83 C4 08 5B 5D E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 43 10 48 C7 04 28 00 00 00 00 E9 63 FF FF FF 66 2E 0F 1F 84 00 00 00 00 00 48 89 CF E8 ?? ?? ?? ?? 48 8B 43 18 48 C7 04 28 00 00 00 00 E9 75 FF FF }
	condition:
		$pattern
}

rule pthread_mutex_lock_2b570bf80064d800e67677ca7112de87 {
	meta:
		aliases = "__pthread_mutex_lock, pthread_mutex_lock"
		type = "func"
		size = "153"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 8B 47 10 83 F8 01 74 26 7F 06 85 C0 74 13 EB 0A 83 F8 02 74 45 83 F8 03 74 65 B8 16 00 00 00 EB 6B 48 8D 7F 18 31 F6 E8 ?? ?? ?? ?? EB 5C E8 95 FD FF FF 48 39 43 08 48 89 C5 75 05 FF 43 04 EB 49 48 8D 7B 18 48 89 C6 E8 ?? ?? ?? ?? 48 89 6B 08 C7 43 04 00 00 00 00 EB 30 E8 69 FD FF FF 48 89 C5 48 39 6B 08 B8 23 00 00 00 74 1F 48 8D 7B 18 48 89 EE E8 ?? ?? ?? ?? 48 89 6B 08 EB 0B 48 8D 7F 18 31 F6 E8 ?? ?? ?? ?? 31 C0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule xstrdup_b6b33080e63714b00243c9d12833e856 {
	meta:
		aliases = "xstrdup"
		type = "func"
		size = "46"
		objfiles = "xstrdup@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 48 8D 68 01 48 89 EF E8 ?? ?? ?? ?? 48 83 C4 08 48 89 DE 48 89 EA 5B 5D 48 89 C7 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _Unwind_SjLj_RaiseException_2c428ca28e669facefe70e997b1a9b4d {
	meta:
		aliases = "_Unwind_SjLj_RaiseException"
		type = "func"
		size = "172"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 28 48 8B 05 ?? ?? ?? ?? 48 85 C0 48 89 44 24 10 48 89 04 24 74 3D 48 89 E5 EB 04 48 89 04 24 48 8B 40 30 48 85 C0 74 1F 49 89 E8 48 89 D9 48 8B 13 BE 01 00 00 00 BF 01 00 00 00 FF D0 83 F8 06 74 1D 83 F8 08 75 51 48 8B 04 24 48 8B 00 48 85 C0 75 C8 B8 05 00 00 00 48 83 C4 28 5B 5D C3 48 8B 04 24 48 C7 43 10 00 00 00 00 48 89 E6 48 89 DF 48 89 43 18 48 8B 44 24 10 48 89 04 24 E8 45 FE FF FF 83 F8 07 75 D0 48 8D 7C 24 10 48 89 E6 E8 B3 FE FF FF 66 66 90 48 83 C4 28 B8 03 00 00 00 5B 5D C3 }
	condition:
		$pattern
}

rule get_cie_encoding_73f98909846eb0e7c99b8c85cd1afcd5 {
	meta:
		aliases = "get_cie_encoding"
		type = "func"
		size = "189"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 28 80 7F 09 7A 74 09 48 83 C4 28 31 C0 5B 5D C3 48 8D 6F 09 48 89 EF E8 ?? ?? ?? ?? 48 8D 7C 05 01 48 8D 6C 24 18 48 89 EE E8 9A FB FF FF 48 8D 74 24 10 48 89 C7 E8 BD FB FF FF 80 7B 08 01 48 8D 78 01 74 0E 48 89 C7 48 89 EE E8 78 FB FF FF 48 89 C7 48 89 EE E8 6D FB FF FF 0F B6 53 0A 80 FA 52 74 47 48 8D 6C 24 20 48 83 C3 0A EB 16 80 FA 4C 75 93 0F B6 53 01 48 83 C0 01 48 83 C3 01 80 FA 52 74 26 80 FA 50 75 E5 0F B6 38 48 8D 50 01 31 F6 48 89 E9 83 E7 7F E8 AA FD FF FF 0F B6 53 01 48 83 C3 01 80 FA 52 75 DA 0F B6 00 48 83 C4 28 5B 5D C3 }
	condition:
		$pattern
}

rule sem_wait_cf80a23934a86a2808e48dd5cbabcda9 {
	meta:
		aliases = "__new_sem_wait, sem_wait"
		type = "func"
		size = "283"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 28 E8 F9 FD FF FF 48 89 44 24 18 48 8B 74 24 18 48 89 DF 48 89 1C 24 48 C7 44 24 08 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 43 10 85 C0 7E 12 FF C8 48 89 DF 89 43 10 E8 ?? ?? ?? ?? E9 CC 00 00 00 48 8B 44 24 18 48 89 E6 C6 80 D2 02 00 00 00 48 8B 7C 24 18 E8 8A FC FF FF 48 8B 44 24 18 80 78 7A 00 74 10 48 8B 44 24 18 BD 01 00 00 00 80 78 78 00 74 10 48 8B 74 24 18 48 8D 7B 18 31 ED E8 0C FC FF FF 48 89 DF E8 ?? ?? ?? ?? 85 ED 74 0E 48 8B 7C 24 18 31 F6 E8 47 FC FF FF EB 62 48 8B 7C 24 18 E8 E3 FD FF FF 48 8B 44 24 18 80 B8 D2 02 00 00 00 75 19 48 8B 44 24 18 80 B8 D0 02 00 00 00 }
	condition:
		$pattern
}

rule signal_3e51a54835ab33f1abe6514b9646a1b8 {
	meta:
		aliases = "__GI_signal, __bsd_signal, bsd_signal, signal"
		type = "func"
		size = "162"
		objfiles = "signal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 89 FB 48 81 EC 48 01 00 00 48 83 FE FF 74 09 85 FF 7E 05 83 FF 40 7E 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 6D BA 10 00 00 00 48 89 B4 24 A0 00 00 00 EB 0F 48 63 C2 48 C7 84 C4 A8 00 00 00 00 00 00 00 FF CA 79 ED 48 8D AC 24 A0 00 00 00 89 DE 48 8D 7D 08 E8 ?? ?? ?? ?? 85 C0 78 34 89 DE BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 01 48 89 E2 48 89 EE 19 C0 89 DF 25 00 00 00 10 89 84 24 28 01 00 00 E8 ?? ?? ?? ?? 85 C0 78 06 48 8B 04 24 EB 04 48 83 C8 FF 48 81 C4 48 01 00 00 5B 5D C3 }
	condition:
		$pattern
}

rule seteuid_4aa661fdd9f4671207b5f9410e686ea1 {
	meta:
		aliases = "__GI_seteuid, setegid, seteuid"
		type = "func"
		size = "75"
		objfiles = "seteuid@libc.a, setegid@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 89 FB 48 83 EC 08 83 FF FF 75 0F 89 DD E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 29 83 CA FF 89 FE 89 D7 E8 ?? ?? ?? ?? 83 F8 FF 89 C5 75 16 E8 ?? ?? ?? ?? 83 38 26 75 0C 59 89 DE 89 EF 5B 5D E9 ?? ?? ?? ?? 5A 5B 89 E8 5D C3 }
	condition:
		$pattern
}

rule __ieee754_yn_5343d0fb76db08366dd14d90e11087b3 {
	meta:
		aliases = "__ieee754_yn"
		type = "func"
		size = "581"
		objfiles = "e_jn@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 53 89 FB 48 83 EC 28 F2 0F 11 44 24 10 48 8B 44 24 10 48 89 C6 89 C2 F7 D8 48 C1 EE 20 09 D0 89 F1 C1 E8 1F 81 E1 FF FF FF 7F 09 C8 3D 00 00 F0 7F 76 0C 0F 28 C8 F2 0F 58 C8 E9 FB 01 00 00 09 CA 75 15 F2 0F 10 0D ?? ?? ?? ?? F2 0F 5E 0D ?? ?? ?? ?? E9 E2 01 00 00 85 F6 79 0C 0F 57 C9 F2 0F 5E C9 E9 D2 01 00 00 83 FF 00 7D 12 F7 DB BD 01 00 00 00 89 D8 83 E0 01 01 C0 29 C5 EB 18 75 11 F2 0F 10 44 24 10 48 83 C4 28 5B 5D E9 ?? ?? ?? ?? BD 01 00 00 00 83 FB 01 75 18 F2 0F 10 44 24 10 E8 ?? ?? ?? ?? F2 0F 2A CD F2 0F 59 C8 E9 86 01 00 00 81 F9 00 00 F0 7F 0F 57 C9 0F 84 77 01 00 00 81 F9 FF FF }
	condition:
		$pattern
}

rule __ieee754_fmod_824a1e1257474e91ea68ebe8487dbcad {
	meta:
		aliases = "__ieee754_fmod"
		type = "func"
		size = "695"
		objfiles = "e_fmod@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 53 F2 0F 11 44 24 F8 48 8B 44 24 F8 F2 0F 11 4C 24 F8 48 89 C2 41 89 C0 48 8B 44 24 F8 48 C1 EA 20 41 89 D3 48 89 C1 41 81 E3 00 00 00 80 41 89 C2 48 C1 E9 20 44 89 DE 41 89 C9 31 D6 41 81 E1 FF FF FF 7F 44 89 C8 44 09 D0 74 1D 81 FE FF FF EF 7F 7F 15 44 89 D0 F7 D8 44 09 D0 C1 E8 1F 44 09 C8 3D 00 00 F0 7F 76 0D F2 0F 59 C1 F2 0F 5E C0 E9 3D 02 00 00 44 39 CE 7F 15 0F 8C 32 02 00 00 45 39 D0 0F 82 29 02 00 00 0F 84 74 01 00 00 81 FE FF FF 0F 00 7F 2E 85 F6 44 89 C0 BA ED FB FF FF 74 06 EB 0A FF CA 01 C0 85 C0 7F F8 EB 21 89 F0 BA 02 FC FF FF C1 E0 0B EB 04 FF CA 01 C0 85 C0 7F F8 EB 0B 89 }
	condition:
		$pattern
}

rule initgroups_5b04fb34336bedacc38fb5c2f346e34f {
	meta:
		aliases = "initgroups"
		type = "func"
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
		type = "func"
		size = "90"
		objfiles = "lckpwdf@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 83 CD FF 53 48 83 EC 28 39 2D ?? ?? ?? ?? 74 40 BE ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? BE 01 00 00 00 48 89 E7 89 C5 C7 05 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 48 83 C4 28 89 E8 5B 5D C3 }
	condition:
		$pattern
}

rule d_call_offset_a1810eaf0cb1f17cbedf05b7aef7b6e1 {
	meta:
		aliases = "d_call_offset"
		type = "func"
		size = "118"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 85 F6 53 48 89 FB 75 0F 48 8B 47 18 48 8D 50 01 48 89 57 18 0F BE 30 83 FE 68 74 53 83 FE 76 74 0E 5B 31 C0 5D C3 66 0F 1F 84 00 00 00 00 00 48 8D 6B 18 48 89 EF E8 F4 FD FF FF 48 8B 43 18 48 8D 50 01 48 89 53 18 80 38 5F 75 D5 0F 1F 00 48 89 EF E8 D8 FD FF FF 48 8B 43 18 48 8D 50 01 48 89 53 18 80 38 5F 5B 5D 0F 94 C0 0F B6 C0 C3 48 8D 6B 18 EB DA }
	condition:
		$pattern
}

rule siginterrupt_70cabeae6e589cf89bed10bb70581521 {
	meta:
		aliases = "siginterrupt"
		type = "func"
		size = "112"
		objfiles = "sigintr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 F5 31 F6 53 89 FB 48 81 EC A8 00 00 00 48 89 E2 E8 ?? ?? ?? ?? 85 C0 78 46 85 ED 74 19 89 DE BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 A4 24 88 00 00 00 FF FF FF EF EB 17 89 DE BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 8C 24 88 00 00 00 00 00 00 10 31 D2 48 89 E6 89 DF E8 ?? ?? ?? ?? 31 D2 85 C0 79 03 83 CA FF 48 81 C4 A8 00 00 00 89 D0 5B 5D C3 }
	condition:
		$pattern
}

rule dyn_string_init_93771ce539eb51ac72616b1dc1db84ca {
	meta:
		aliases = "dyn_string_init"
		type = "func"
		size = "61"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 F5 53 48 89 FB 48 63 FE 48 83 EC 08 85 F6 75 0A BF 01 00 00 00 BD 01 00 00 00 E8 ?? ?? ?? ?? 89 2B 48 89 43 08 C7 43 04 00 00 00 00 C6 00 00 48 83 C4 08 5B B8 01 00 00 00 5D C3 }
	condition:
		$pattern
}

rule dyn_string_append_char_03f8cac0efe6506db78bd537ad622570 {
	meta:
		aliases = "dyn_string_append_char"
		type = "func"
		size = "81"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 F5 53 48 89 FB 48 83 EC 08 8B 47 04 8D 70 01 E8 ?? ?? ?? ?? 48 85 C0 74 2D 48 63 43 04 48 8B 53 08 40 88 2C 02 48 63 43 04 48 8B 53 08 C6 44 02 01 00 83 43 04 01 48 83 C4 08 5B B8 01 00 00 00 5D C3 0F 1F 40 00 48 83 C4 08 31 C0 5B 5D C3 }
	condition:
		$pattern
}

rule pex_read_output_743b8141242cdcbf86ed39a5a757fcb9 {
	meta:
		aliases = "pex_read_output"
		type = "func"
		size = "180"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 F5 53 48 89 FB 48 83 EC 18 48 83 7F 20 00 74 4E 48 8D 4C 24 04 48 8D 54 24 08 31 F6 E8 1D F7 FF FF 85 C0 74 79 48 8B 7B 20 85 ED BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 0F 44 F2 E8 ?? ?? ?? ?? 8B 53 28 48 89 43 58 85 D2 75 3D 48 C7 43 20 00 00 00 00 48 83 C4 18 5B 5D C3 66 0F 1F 44 00 00 8B 77 18 85 F6 7E 49 48 8B 47 70 89 EA FF 50 30 48 89 43 58 C7 43 18 FF FF FF FF 48 83 C4 18 5B 5D C3 66 0F 1F 44 00 00 48 8B 7B 20 E8 ?? ?? ?? ?? C7 43 28 00 00 00 00 48 8B 43 58 EB AD 66 90 E8 ?? ?? ?? ?? 8B 54 24 04 89 10 31 C0 EB A4 90 31 C0 EB 9F }
	condition:
		$pattern
}

rule daemon_25b2f2882ca3703964ede2a9199a055f {
	meta:
		aliases = "daemon"
		type = "func"
		size = "151"
		objfiles = "daemon@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 F5 53 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? 83 F8 FF 74 78 85 C0 75 12 E8 ?? ?? ?? ?? FF C0 74 6B E8 ?? ?? ?? ?? 85 C0 74 07 31 FF E8 ?? ?? ?? ?? 85 DB 75 0A BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 ED 75 4E 31 D2 31 C0 BE 02 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 FF 89 C3 74 34 31 F6 89 C7 E8 ?? ?? ?? ?? BE 01 00 00 00 89 DF E8 ?? ?? ?? ?? BE 02 00 00 00 89 DF E8 ?? ?? ?? ?? 83 FB 02 7E 0E 89 DF E8 ?? ?? ?? ?? EB 05 83 C8 FF EB 02 31 C0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule getrpcbynumber_706031ab33cbb389ff302e7a85b95d5f {
	meta:
		aliases = "__GI_getrpcbynumber, getrpcbynumber"
		type = "func"
		size = "60"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 FD 53 31 DB 48 83 EC 08 E8 7B FC FF FF 48 85 C0 74 20 31 FF E8 ?? ?? ?? ?? EB 05 39 6B 10 74 0D E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 75 EE E8 ?? ?? ?? ?? 41 58 48 89 D8 5B 5D C3 }
	condition:
		$pattern
}

rule __sigpause_15f9dffda02237f5b27459f52ff51dbe {
	meta:
		aliases = "__GI___sigpause, __sigpause"
		type = "func"
		size = "101"
		objfiles = "sigpause@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 FD 53 48 81 EC 88 00 00 00 85 F6 74 20 31 F6 31 FF 48 89 E2 E8 ?? ?? ?? ?? 85 C0 78 39 89 EE 48 89 E7 E8 ?? ?? ?? ?? 85 C0 79 21 EB 29 89 FD 48 8D 44 24 08 BA 0E 00 00 00 48 89 2C 24 48 C7 00 00 00 00 00 48 83 C0 08 FF CA 79 F1 48 89 E7 E8 ?? ?? ?? ?? EB 03 83 C8 FF 48 81 C4 88 00 00 00 5B 5D C3 }
	condition:
		$pattern
}

rule pthread_onexit_process_790083741f5ebafad3a742285e22e1e5 {
	meta:
		aliases = "pthread_onexit_process"
		type = "func"
		size = "145"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 FD 53 48 81 EC B8 00 00 00 83 3D ?? ?? ?? ?? 00 78 73 E8 FD FD FF FF 48 89 C3 48 89 04 24 C7 44 24 08 02 00 00 00 89 6C 24 10 8B 3D ?? ?? ?? ?? BA A8 00 00 00 48 89 E6 E8 ?? ?? ?? ?? 48 FF C0 75 0A E8 ?? ?? ?? ?? 83 38 04 74 DE 48 89 DF E8 A5 FF FF FF 48 3B 1D ?? ?? ?? ?? 75 28 8B 3D ?? ?? ?? ?? BA 00 00 00 80 31 F6 E8 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? 00 00 00 00 48 C7 05 ?? ?? ?? ?? 00 00 00 00 48 81 C4 B8 00 00 00 5B 5D C3 }
	condition:
		$pattern
}

rule setrpcent_c56fd3150c0d6c8c38eff5d7de9d97d0 {
	meta:
		aliases = "__GI_setrpcent, setrpcent"
		type = "func"
		size = "78"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 FD 53 48 83 EC 08 E8 D3 FD FF FF 48 85 C0 48 89 C3 74 35 48 8B 38 48 85 FF 75 14 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 03 EB 05 E8 ?? ?? ?? ?? 48 8B 7B 08 E8 ?? ?? ?? ?? 09 6B 14 48 C7 43 08 00 00 00 00 5F 5B 5D C3 }
	condition:
		$pattern
}

rule _dl_dprintf_50ef77d246263e53c291c547d7d14859 {
	meta:
		aliases = "_dl_dprintf"
		type = "func"
		size = "892"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 89 FD 53 48 89 F3 48 83 C4 80 48 85 F6 48 89 54 24 D8 48 89 4C 24 E0 4C 89 44 24 E8 4C 89 4C 24 F0 0F 84 4D 03 00 00 48 8B 35 ?? ?? ?? ?? 45 31 C9 49 83 C8 FF 41 BA 22 00 00 00 BA 03 00 00 00 31 FF B8 09 00 00 00 0F 05 48 3D 00 F0 FF FF 76 0B F7 D8 89 05 ?? ?? ?? ?? 4C 89 C0 48 89 05 ?? ?? ?? ?? 48 05 00 10 00 00 48 3D FF 0F 00 00 77 40 BA 1D 00 00 00 BE ?? ?? ?? ?? 48 63 FD B8 01 00 00 00 0F 05 48 3D 00 F0 FF FF 76 08 F7 D8 89 05 ?? ?? ?? ?? BF 14 00 00 00 B8 3C 00 00 00 0F 05 48 3D 00 F0 FF FF 76 08 F7 D8 89 05 ?? ?? ?? ?? 4C 8D 43 FF 4C 8B 0D ?? ?? ?? ?? 4C 89 C2 48 FF C2 80 3A 00 75 F8 }
	condition:
		$pattern
}

rule putc_unlocked_99c41ac40abc6c97904900a096c73867 {
	meta:
		aliases = "__GI___fputc_unlocked, __GI_putc_unlocked, __fputc_unlocked, fputc_unlocked, putc_unlocked"
		type = "func"
		size = "192"
		objfiles = "fputc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 FD 53 48 89 F3 48 83 EC 18 48 8B 46 18 48 3B 46 30 73 0F 40 88 38 48 FF C0 48 89 46 18 E9 8C 00 00 00 0F B7 06 25 C0 00 00 00 3D C0 00 00 00 74 11 BE 80 00 00 00 48 89 DF E8 ?? ?? ?? ?? 85 C0 75 72 83 7B 04 FE 74 66 48 8B 43 10 48 3B 43 08 74 40 48 3B 43 18 75 0D 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 75 4F 48 8B 43 18 40 88 28 48 FF C0 F6 43 01 01 48 89 43 18 74 35 40 80 FD 0A 75 2F 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 74 22 48 FF 4B 18 EB 22 48 8D 74 24 17 BA 01 00 00 00 48 89 DF 40 88 6C 24 17 E8 ?? ?? ?? ?? 48 85 C0 74 06 40 0F B6 C5 EB 03 83 C8 FF 48 83 C4 18 5B 5D C3 }
	condition:
		$pattern
}

rule ptrace_f90bac79e20463e6b1d7be804f6d9336 {
	meta:
		aliases = "ptrace"
		type = "func"
		size = "193"
		objfiles = "ptrace@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 FD 89 FF 53 48 81 EC D8 00 00 00 48 8D 84 24 F0 00 00 00 C7 04 24 10 00 00 00 48 89 4C 24 38 48 89 74 24 28 48 89 54 24 30 4C 8D 54 24 18 48 89 44 24 08 48 8D 44 24 20 48 89 44 24 10 48 83 C0 08 48 8B 4C 24 10 8B 30 48 8B 44 24 10 C7 04 24 18 00 00 00 48 83 C1 18 48 83 C0 10 48 63 F6 48 8B 10 8D 45 FF C7 04 24 20 00 00 00 83 F8 02 B8 65 00 00 00 4C 0F 47 11 0F 05 48 3D 00 F0 FF FF 48 89 C3 76 0F E8 ?? ?? ?? ?? 89 DA 48 83 CB FF F7 DA 89 10 48 85 DB 48 89 D8 78 19 85 ED 74 15 83 FD 03 77 10 E8 ?? ?? ?? ?? C7 00 00 00 00 00 48 8B 44 24 18 48 81 C4 D8 00 00 00 5B 5D C3 }
	condition:
		$pattern
}

rule dyn_string_new_b7468690a92cf9bf4144865171b2d644 {
	meta:
		aliases = "dyn_string_new"
		type = "func"
		size = "69"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 FD BF 10 00 00 00 53 48 83 EC 08 E8 ?? ?? ?? ?? 85 ED 48 89 C3 48 63 FD 75 0A BF 01 00 00 00 BD 01 00 00 00 E8 ?? ?? ?? ?? 89 2B C6 00 00 48 89 43 08 C7 43 04 00 00 00 00 48 83 C4 08 48 89 D8 5B 5D C3 }
	condition:
		$pattern
}

rule flush_out_6451a4eccc9ad69fca09e04934c34ba6 {
	meta:
		aliases = "flush_out"
		type = "func"
		size = "95"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) B8 00 00 00 00 BA 00 00 00 80 48 89 FD 53 48 83 EC 08 FF CE 48 8B 4F 30 48 0F 45 D0 48 8B 47 20 48 29 C8 48 83 E8 04 09 C2 0F CA 89 11 48 8B 77 18 48 8B 57 20 48 8B 3F 48 29 F2 89 D3 FF 55 10 31 D2 39 D8 75 12 48 8B 45 18 B2 01 48 89 45 30 48 83 C0 04 48 89 45 20 5E 5B 5D 89 D0 C3 }
	condition:
		$pattern
}

rule pthread_setcanceltype_fa6f39293518a6c0e250a1b4c82cc9d4 {
	meta:
		aliases = "__GI_pthread_setcanceltype, pthread_setcanceltype"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "66"
		objfiles = "crtbegin, crtbeginT"
	strings:
		$pattern = { ( CC | 55 ) B8 ?? ?? ?? ?? 48 85 C0 48 89 E5 74 0F BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 3D ?? ?? ?? ?? 00 74 19 B8 ?? ?? ?? ?? 48 85 C0 74 0F BF ?? ?? ?? ?? 49 89 C3 C9 41 FF E3 66 66 90 C9 C3 }
	condition:
		$pattern
}

rule __old_sem_wait_1d8019b104a57e644286c9d1c370a18b {
	meta:
		aliases = "__old_sem_wait"
		type = "func"
		size = "344"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) B8 ?? ?? ?? ?? 53 48 89 FB 48 83 EC 38 48 3B 25 ?? ?? ?? ?? 48 89 E2 73 35 48 3B 25 ?? ?? ?? ?? 72 0E 48 3B 25 ?? ?? ?? ?? B8 ?? ?? ?? ?? 72 1E 83 3D ?? ?? ?? ?? 00 74 07 E8 ?? ?? ?? ?? EB 0E 48 81 CA FF FF 1F 00 48 8D 82 01 FD FF FF 48 8D 6C 24 10 48 89 44 24 28 48 C7 44 24 10 00 00 00 00 48 C7 44 24 18 ?? ?? ?? ?? 48 8B 7C 24 28 48 89 EE E8 46 FF FF FF 48 8B 0B F6 C1 01 74 0A 48 83 F9 01 48 8D 51 FE 75 0E 48 8B 54 24 28 48 8B 44 24 28 48 89 48 10 48 89 C8 F0 48 0F B1 13 0F 94 C1 84 C9 74 D1 80 E2 01 0F 85 93 00 00 00 48 8B 7C 24 28 E8 ?? ?? ?? ?? 48 8B 7C 24 28 31 F6 E8 F8 FE FF FF 48 8B }
	condition:
		$pattern
}

rule timer_delete_2a6d7b23653c94633b59401f9f2889c1 {
	meta:
		aliases = "timer_delete"
		type = "func"
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
		type = "func"
		size = "67"
		objfiles = "_ppfs_prepargs@libc.a"
	strings:
		$pattern = { ( CC | 55 ) B9 06 00 00 00 FC 53 48 89 FB 48 8D 7F 50 48 83 EC 08 F3 A5 8B 6B 1C 85 ED 7E 23 89 6B 20 C7 43 1C 00 00 00 00 48 89 DF C7 43 08 00 00 00 00 C7 43 0C 00 00 00 00 E8 ?? ?? ?? ?? 89 6B 1C 58 5B 5D C3 }
	condition:
		$pattern
}

rule xdr_rmtcallres_e07019b5aa305970591bdd5e5237349a {
	meta:
		aliases = "__GI_xdr_rmtcallres, xdr_rmtcallres"
		type = "func"
		size = "91"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) B9 ?? ?? ?? ?? BA 08 00 00 00 48 89 FD 53 48 89 F3 48 83 EC 18 48 8B 06 48 8D 74 24 10 48 89 44 24 10 E8 ?? ?? ?? ?? 85 C0 74 26 48 8D 73 08 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 16 48 8B 44 24 10 48 8B 73 10 48 89 EF 48 89 03 31 C0 FF 53 18 EB 02 31 C0 48 83 C4 18 5B 5D C3 }
	condition:
		$pattern
}

rule byte_re_compile_fastmap_bf3a86caf405c54fb41f8175ad155980 {
	meta:
		aliases = "byte_re_compile_fastmap"
		type = "func"
		size = "902"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BA 00 01 00 00 31 F6 48 89 E5 41 57 41 B7 01 41 56 41 55 41 54 49 89 FC 53 48 83 EC 68 4C 8B 6F 20 48 8B 1F 48 8B 47 10 4C 8D 74 24 0F 4C 89 EF 49 83 E6 F0 48 01 D8 48 89 45 C8 E8 ?? ?? ?? ?? 41 8A 44 24 38 49 8D 55 0A C6 45 D3 00 45 31 C0 C7 45 D4 05 00 00 00 48 89 55 B8 83 C8 08 83 E0 FE 41 88 44 24 38 48 3B 5D C8 74 06 8A 03 3C 01 75 30 45 85 C0 41 8A 54 24 38 0F 84 D7 02 00 00 88 D0 41 FF C8 83 E2 FE 83 E0 01 41 09 C7 44 89 C0 44 09 FA 41 B7 01 41 88 54 24 38 49 8B 1C C6 EB C4 48 FF C3 3C 1D 0F 87 99 02 00 00 0F B6 C0 FF 24 C5 ?? ?? ?? ?? 31 D2 E9 D1 00 00 00 31 D2 E9 EE 00 00 00 41 80 }
	condition:
		$pattern
}

rule byte_re_compile_fastmap_9c2047150441cafb42affb2ec8f1b732 {
	meta:
		aliases = "byte_re_compile_fastmap"
		type = "func"
		size = "1144"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) BA 00 01 00 00 48 89 E5 41 57 41 56 41 55 41 54 49 89 FC 53 48 83 EC 38 48 8B 5F 20 4C 8B 2F 48 83 EC 40 48 8D 74 24 0F 4D 89 EE 4C 03 77 10 48 89 DF 48 83 E6 F0 F6 C3 01 0F 85 D8 00 00 00 40 F6 C7 02 0F 85 E6 00 00 00 40 F6 C7 04 0F 85 AC 00 00 00 89 D1 31 C0 C1 E9 03 F6 C2 04 F3 48 AB 74 0A C7 07 00 00 00 00 48 83 C7 04 F6 C2 02 74 0A 31 C0 48 83 C7 02 66 89 47 FE 83 E2 01 74 03 C6 07 00 41 0F B6 44 24 38 4C 8D 43 01 45 31 FF B9 01 00 00 00 83 C8 08 83 E0 FE 41 88 44 24 38 B8 05 00 00 00 4D 39 F5 74 25 41 0F B6 55 00 80 FA 01 74 1B 80 FA 1D 4D 8D 4D 01 0F 87 06 03 00 00 FF 24 D5 ?? ?? ?? }
	condition:
		$pattern
}

rule _ppfs_init_108d6e9bd4cf81ad7f997862f13bfd3e {
	meta:
		aliases = "_ppfs_init"
		type = "func"
		size = "114"
		objfiles = "_ppfs_init@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BA 00 01 00 00 48 89 F5 31 F6 53 48 89 FB 48 83 EC 08 E8 ?? ?? ?? ?? FF 4B 1C 48 8D 43 2C 48 89 2B BA 09 00 00 00 C7 00 08 00 00 00 48 83 C0 04 FF CA 75 F2 48 89 E8 EB 29 80 FA 25 75 21 48 FF C0 80 38 25 74 19 48 89 03 48 89 DF E8 ?? ?? ?? ?? 85 C0 79 05 83 C8 FF EB 13 48 8B 03 EB 03 48 FF C0 8A 10 84 D2 75 D1 48 89 2B 31 C0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule addmntent_7885e957238243c319a77f239b6fb3c9 {
	meta:
		aliases = "addmntent"
		type = "func"
		size = "90"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BA 02 00 00 00 48 89 FD 53 48 89 F3 31 F6 48 83 EC 18 E8 ?? ?? ?? ?? 85 C0 BA 01 00 00 00 78 30 8B 43 24 48 8B 13 BE ?? ?? ?? ?? 4C 8B 4B 18 4C 8B 43 10 48 89 EF 48 8B 4B 08 89 44 24 08 8B 43 20 89 04 24 31 C0 E8 ?? ?? ?? ?? 89 C2 C1 EA 1F 48 83 C4 18 89 D0 5B 5D C3 }
	condition:
		$pattern
}

rule sigset_4bdb7795a2c8cc65892cea98a443ac53 {
	meta:
		aliases = "sigset"
		type = "func"
		size = "287"
		objfiles = "sigset@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BA 10 00 00 00 53 89 FB 48 81 EC C8 01 00 00 48 83 FE 02 74 11 EB 4B 48 63 C2 48 C7 84 C4 40 01 00 00 00 00 00 00 FF CA 79 ED 48 8D AC 24 40 01 00 00 89 DE 48 89 EF E8 ?? ?? ?? ?? 85 C0 0F 88 C9 00 00 00 31 D2 31 FF 48 89 EE E8 ?? ?? ?? ?? 85 C0 BA 02 00 00 00 0F 89 B4 00 00 00 E9 AB 00 00 00 48 83 FE FF 74 09 85 FF 7E 05 83 FF 40 7E 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 8C 00 00 00 BA 10 00 00 00 48 89 B4 24 A0 00 00 00 EB 0F 48 63 C2 48 C7 84 C4 A8 00 00 00 00 00 00 00 FF CA 79 ED 48 8D B4 24 A0 00 00 00 48 89 E2 89 DF C7 84 24 28 01 00 00 00 00 00 00 E8 ?? ?? ?? ?? 85 C0 BA 10 00 00 00 }
	condition:
		$pattern
}

rule asctime_r_5023584bbfa2410d289b79f72da1856e {
	meta:
		aliases = "__GI_asctime_r, asctime_r"
		type = "func"
		size = "224"
		objfiles = "asctime_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BA 1A 00 00 00 48 89 FD 53 48 89 F3 BE ?? ?? ?? ?? 48 89 DF 48 83 EC 08 E8 ?? ?? ?? ?? 8B 45 18 83 F8 06 77 1A 8D 34 40 BA 03 00 00 00 48 89 DF 48 63 F6 48 81 C6 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 10 83 F8 0B 77 1B 8D 34 40 48 8D 7B 04 BA 03 00 00 00 48 63 F6 48 81 C6 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 55 14 48 8D 4B 13 81 C2 6C 07 00 00 81 FA 0F 27 00 00 77 1D 48 8D 4B 17 89 D0 BE 0A 00 00 00 99 F7 FE 83 C2 30 88 11 48 FF C9 89 C2 80 39 3F 74 E7 48 0F BE 41 FF 48 8D 71 FF 8B 54 05 00 83 FA 63 76 0A C6 41 FF 3F C6 46 FF 3F EB 13 89 D0 BF 0A 00 00 00 99 F7 FF 00 41 FE 83 C2 30 88 51 FF 48 8D 4E FE }
	condition:
		$pattern
}

rule __md5_Final_4c4a625ab25b941a201b17451028627b {
	meta:
		aliases = "__md5_Final"
		type = "func"
		size = "143"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) BA 40 00 00 00 48 89 FD 53 48 89 F3 31 F6 48 83 EC 58 48 89 E7 E8 ?? ?? ?? ?? 48 8D 73 10 48 8D 7C 24 40 BA 08 00 00 00 C6 04 24 80 E8 3F FD FF FF 8B 43 10 BA 38 00 00 00 C1 E8 03 83 E0 3F 83 F8 37 76 05 BA 78 00 00 00 29 C2 48 89 E6 48 89 DF E8 00 FF FF FF 48 8D 74 24 40 48 89 DF BA 08 00 00 00 E8 EE FE FF FF 48 89 DE 48 89 EF BA 10 00 00 00 E8 F8 FC FF FF 48 89 DF BA 58 00 00 00 31 F6 E8 ?? ?? ?? ?? 48 83 C4 58 5B 5D C3 }
	condition:
		$pattern
}

rule mallopt_63363b0cc69fed4515bfaef3b412d55a {
	meta:
		aliases = "mallopt"
		type = "func"
		size = "196"
		objfiles = "mallopt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BA ?? ?? ?? ?? 89 F5 BE ?? ?? ?? ?? 53 89 FB 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 43 04 83 F8 05 77 74 89 C0 FF 24 C5 ?? ?? ?? ?? 83 FD 50 77 66 85 ED BA 08 00 00 00 74 16 48 63 C5 B2 20 48 83 C0 17 48 83 F8 1F 76 07 48 89 C2 48 83 E2 F0 48 8B 05 ?? ?? ?? ?? 83 E0 03 48 09 C2 48 89 15 ?? ?? ?? ?? EB 22 48 63 C5 48 89 05 ?? ?? ?? ?? EB 16 48 63 C5 48 89 05 ?? ?? ?? ?? EB 0A 48 63 C5 48 89 05 ?? ?? ?? ?? BB 01 00 00 00 EB 0A 89 2D ?? ?? ?? ?? EB F1 31 DB 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 89 D8 48 83 C4 28 5B 5D C3 }
	condition:
		$pattern
}

rule getnetent_03d47c6f3017bb60a426f40ab25db526 {
	meta:
		aliases = "__GI_getnetent, getnetent"
		type = "func"
		size = "400"
		objfiles = "getnetent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 53 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 3D ?? ?? ?? ?? 00 75 1F BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 0F 84 2C 01 00 00 48 83 3D ?? ?? ?? ?? 00 75 1B BF 01 10 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 75 05 E8 ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? BE 00 10 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 0F 84 E3 00 00 00 80 38 23 74 B2 BE ?? ?? ?? ?? 48 89 C7 E8 37 FF FF FF 48 85 C0 74 A0 C6 00 00 BE ?? ?? ?? ?? 48 89 DF 48 89 1D ?? ?? ?? ?? E8 1B FF FF FF 48 85 C0 74 84 48 }
	condition:
		$pattern
}

rule _stdio_openlist_dec_use_c6c8be712447245f1cd9ee9a775fc336 {
	meta:
		aliases = "_stdio_openlist_dec_use"
		type = "func"
		size = "216"
		objfiles = "fflush_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 53 48 83 EC 48 48 8D 7C 24 20 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? FF C8 0F 85 82 00 00 00 83 3D ?? ?? ?? ?? 00 7E 79 48 89 E7 BA ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 31 ED E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? EB 36 0F B7 07 48 8B 5F 38 25 30 80 00 00 83 F8 30 74 05 48 89 FD EB 1D 48 85 ED 75 09 48 89 1D ?? ?? ?? ?? EB 04 48 89 5D 38 F6 47 01 20 74 05 E8 ?? ?? ?? ?? 48 89 DF 48 85 FF 75 C5 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 8B 05 ?? ?? ?? ?? 48 8D 7C 24 20 BE 01 00 00 00 FF C8 89 05 }
	condition:
		$pattern
}

rule setstate_1956d185527f75b1751d76e202dfe148 {
	meta:
		aliases = "setstate"
		type = "func"
		size = "90"
		objfiles = "random@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 53 48 89 FB 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 DF BE ?? ?? ?? ?? 48 8B 2D ?? ?? ?? ?? 31 DB E8 ?? ?? ?? ?? 85 C0 78 04 48 8D 5D FC 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 28 5B 5D C3 }
	condition:
		$pattern
}

rule getutline_95fcd549ecf45cc52a1ddc7129e696c8 {
	meta:
		aliases = "getutline"
		type = "func"
		size = "112"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 53 48 89 FB 48 8D 6B 08 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 1B 8B 03 83 E8 06 66 83 F8 01 77 10 48 8D 7B 08 48 89 EE E8 ?? ?? ?? ?? 85 C0 74 13 8B 3D ?? ?? ?? ?? E8 A9 FD FF FF 48 85 C0 48 89 C3 75 D2 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 28 5B 5D C3 }
	condition:
		$pattern
}

rule exit_b0dcacc47736a9f7608d9a6e18bdd4bc {
	meta:
		aliases = "__GI_exit, exit"
		type = "func"
		size = "92"
		objfiles = "exit@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BA ?? ?? ?? ?? BE ?? ?? ?? ?? 53 89 FB 48 83 EC 28 48 89 E7 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 04 89 DF FF D0 BE 01 00 00 00 48 89 E7 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 48 85 C0 74 05 E8 ?? ?? ?? ?? 89 DF E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule firstwhite_81cd6ff63b245c91b7fe705c846304c7 {
	meta:
		aliases = "firstwhite"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "258"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) BE ?? ?? ?? ?? 31 C0 53 48 83 EC 18 48 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? EB 3C 8B 43 30 4C 8B 43 38 48 89 D9 48 8B 3D ?? ?? ?? ?? BE ?? ?? ?? ?? 4C 8B 0C C5 ?? ?? ?? ?? 48 8B 43 08 48 89 44 24 08 0F B7 43 40 89 04 24 48 8B 13 31 C0 E8 ?? ?? ?? ?? 48 8B 5B 18 48 85 DB 75 BF 48 8B 15 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? BE ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? EB 1E 48 8B 13 48 8B 3D ?? ?? ?? ?? BE ?? ?? ?? ?? 31 C0 48 8B 4A 08 E8 ?? ?? ?? ?? 48 8B 5B 20 48 85 DB 75 DD 48 8B 2D ?? ?? ?? ?? EB 42 48 8B 3D ?? ?? ?? ?? 48 89 EA BE ?? ?? ?? ?? 31 C0 48 89 EB E8 ?? }
	condition:
		$pattern
}

rule readdir64_f2df44eefd066c3bf11f5fc1c63d9d6a {
	meta:
		aliases = "__GI_readdir, __GI_readdir64, readdir, readdir64"
		type = "func"
		size = "143"
		objfiles = "readdir64@libc.a, readdir@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BE ?? ?? ?? ?? 48 89 FD 53 48 8D 5F 30 48 83 EC 28 48 89 DA 48 89 E7 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8B 45 08 48 39 45 10 77 25 48 8B 55 28 48 8B 75 18 8B 7D 00 E8 ?? ?? ?? ?? 48 85 C0 7F 04 31 DB EB 30 48 89 45 10 48 C7 45 08 00 00 00 00 48 8B 45 08 48 89 C3 48 03 5D 18 0F B7 53 10 48 01 C2 48 89 55 08 48 8B 43 08 48 89 45 20 48 83 3B 00 74 AD 48 89 E7 BE 01 00 00 00 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 28 5B 5D C3 }
	condition:
		$pattern
}

rule _stdio_term_01992624e4bdffc8443e32d5d6e9a086 {
	meta:
		aliases = "_stdio_term"
		type = "func"
		size = "135"
		objfiles = "_stdio@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BF ?? ?? ?? ?? 53 48 83 EC 08 E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? EB 3C 48 8D 6B 58 48 89 EF E8 ?? ?? ?? ?? 85 C0 74 19 48 8B 43 08 66 C7 03 30 00 48 89 43 28 48 89 43 30 48 89 43 18 48 89 43 20 C7 43 50 01 00 00 00 48 89 EF E8 ?? ?? ?? ?? 48 8B 5B 38 48 85 DB 75 BF 48 8B 1D ?? ?? ?? ?? EB 11 F6 03 40 74 08 48 89 DF E8 ?? ?? ?? ?? 48 8B 5B 38 48 85 DB 75 EA 5A 5B 5D C3 }
	condition:
		$pattern
}

rule vfork_41f8cf3389267ddf4d394f7dea183433 {
	meta:
		aliases = "__GI_vfork, __vfork, vfork"
		type = "func"
		size = "21"
		objfiles = "vfork@libc.a"
	strings:
		$pattern = { ( CC | 5F ) B8 3A 00 00 00 0F 05 57 3D 01 F0 FF FF 0F 83 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __fixunsdfti_d91db2b9ac5da2143575a6130f6a7780 {
	meta:
		aliases = "__fixunsdfti"
		type = "func"
		size = "157"
		objfiles = "_fixunsdfdi@libgcc.a"
	strings:
		$pattern = { ( CC | 66 ) 0F 28 C8 53 F2 0F 10 15 ?? ?? ?? ?? F2 0F 59 0D ?? ?? ?? ?? 66 0F 2E CA 73 35 F2 48 0F 2C F1 48 85 F6 78 46 F2 48 0F 2A CE F2 0F 59 0D ?? ?? ?? ?? F2 0F 58 C8 66 0F 2E CA 73 49 F2 48 0F 2C C9 5B 48 89 C8 31 D2 31 C9 48 09 C8 48 09 F2 C3 F2 0F 5C CA 48 B8 00 00 00 00 00 00 00 80 F2 48 0F 2C F1 48 31 C6 48 85 F6 79 BA 48 89 F0 48 89 F2 48 D1 E8 83 E2 01 48 09 D0 F2 48 0F 2A C8 F2 0F 58 C9 EB A5 F2 0F 5C CA 48 B8 00 00 00 00 00 00 00 80 F2 48 0F 2C C9 48 31 C1 EB A4 }
	condition:
		$pattern
}

rule __muldc3_ac8a44aea981d7ec6861a284339046c9 {
	meta:
		aliases = "__muldc3"
		type = "func"
		size = "863"
		objfiles = "_muldc3@libgcc.a"
	strings:
		$pattern = { ( CC | 66 ) 0F 28 E8 F2 0F 59 C2 66 0F 28 F9 66 44 0F 28 C5 66 44 0F 28 C9 F2 0F 59 FB F2 44 0F 59 C3 66 0F 28 E0 F2 44 0F 59 CA F2 0F 5C E7 66 41 0F 28 F0 F2 41 0F 58 F1 66 0F 2E E4 7A 0B 75 09 66 0F 28 CE 66 0F 28 C4 C3 66 0F 2E F6 66 66 90 66 90 7A 02 74 EA 66 44 0F 28 D5 66 0F 2E ED F2 44 0F 5C D5 0F 85 75 02 00 00 0F 8A 6F 02 00 00 66 45 0F 2E D2 0F 84 5E 02 00 00 F2 44 0F 10 1D ?? ?? ?? ?? 66 0F 2E C9 66 44 0F 28 D1 66 41 0F 54 EB F2 44 0F 5C D1 66 0F 56 2D ?? ?? ?? ?? 75 17 7A 15 66 45 0F 2E D2 0F 85 5B 02 00 00 66 66 66 90 0F 8A 51 02 00 00 66 45 0F 57 D2 66 44 0F 28 E1 66 0F 2E D2 66 44 0F 54 }
	condition:
		$pattern
}

rule __signbitf_3d67f3195060b9432f98e04d2d403e57 {
	meta:
		aliases = "__GI___signbitf, __signbitf"
		type = "func"
		size = "10"
		objfiles = "s_signbitf@libm.a"
	strings:
		$pattern = { ( CC | 66 ) 0F 7E C0 25 00 00 00 80 C3 }
	condition:
		$pattern
}

rule __finitef_5177647643ac6e382d592fd37ef1fb94 {
	meta:
		aliases = "__GI___finitef, __finitef"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "5"
		objfiles = "clearerr_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 66 ) 83 27 F3 C3 }
	condition:
		$pattern
}

rule __drand48_iterate_4ac7b6e3dfac5476b0dde586ef3a16a5 {
	meta:
		aliases = "__drand48_iterate"
		type = "func"
		size = "93"
		objfiles = "drand48_iter@libc.a"
	strings:
		$pattern = { ( CC | 66 ) 83 7E 0E 00 75 1A 48 B8 6D E6 EC DE 05 00 00 00 66 C7 46 0C 0B 00 66 C7 46 0E 01 00 48 89 46 10 0F B7 47 04 0F B7 17 48 C1 E0 20 48 09 D0 0F B7 57 02 C1 E2 10 89 D2 48 09 D0 0F B7 56 0C 48 0F AF 46 10 48 01 D0 66 89 07 48 C1 E8 10 66 89 47 02 48 C1 E8 10 66 89 47 04 31 C0 C3 }
	condition:
		$pattern
}

rule __libc_sa_len_394574cf8fab914885221b0bae82167c {
	meta:
		aliases = "__libc_sa_len"
		type = "func"
		size = "52"
		objfiles = "sa_len@libc.a"
	strings:
		$pattern = { ( CC | 66 ) 83 FF 02 89 F8 74 26 77 07 66 FF C8 75 16 EB 0E 66 83 FF 04 74 17 66 83 FF 0A 75 08 EB 09 B8 6E 00 00 00 C3 31 C0 C3 B8 1C 00 00 00 C3 B8 10 00 00 00 C3 }
	condition:
		$pattern
}

rule ffs_278b35755f16a325c7bc29607403d16d {
	meta:
		aliases = "__GI_ffs, ffs"
		type = "func"
		size = "65"
		objfiles = "ffs@libc.a"
	strings:
		$pattern = { ( CC | 66 ) 85 FF B2 01 75 05 C1 FF 10 B2 11 40 84 FF 75 06 83 C2 08 C1 FF 08 40 F6 C7 0F 75 06 83 C2 04 C1 FF 04 40 F6 C7 03 75 06 83 C2 02 C1 FF 02 31 C0 85 FF 74 0B 8D 47 01 0F BE D2 83 E0 01 01 D0 C3 }
	condition:
		$pattern
}

rule ntohs_92ad4ec525129c7854c3515f8e3ea768 {
	meta:
		aliases = "htons, ntohs"
		type = "func"
		size = "8"
		objfiles = "ntohl@libc.a"
	strings:
		$pattern = { ( CC | 66 ) C1 CF 08 0F B7 C7 C3 }
	condition:
		$pattern
}

rule rand_r_478603922d24ed60e25f9a0adbc8ed3b {
	meta:
		aliases = "rand_r"
		type = "func"
		size = "78"
		objfiles = "rand_r@libc.a"
	strings:
		$pattern = { ( CC | 69 ) 0F 6D 4E C6 41 81 C1 39 30 00 00 89 C8 69 C9 6D 4E C6 41 C1 E8 06 25 00 FC 1F 00 81 C1 39 30 00 00 89 CA 69 C9 6D 4E C6 41 C1 EA 10 81 E2 FF 03 00 00 31 D0 81 C1 39 30 00 00 C1 E0 0A 89 CA 89 0F C1 EA 10 81 E2 FF 03 00 00 31 D0 C3 }
	condition:
		$pattern
}

rule __do_global_dtors_aux_ca79be8cd6a85c21c31a91f7721fb4dd {
	meta:
		aliases = "__do_global_dtors_aux"
		type = "func"
		size = "146"
		objfiles = "crtbegin, crtbeginT"
	strings:
		$pattern = { ( CC | 80 ) 3D ?? ?? ?? ?? 00 55 48 89 E5 74 10 EB 38 90 48 83 C0 08 48 89 05 ?? ?? ?? ?? FF D2 48 8B 05 ?? ?? ?? ?? 48 8B 10 48 85 D2 75 E4 B8 ?? ?? ?? ?? 48 85 C0 74 0A BF ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01 C9 C3 66 66 66 90 66 66 90 55 B8 ?? ?? ?? ?? 48 85 C0 48 89 E5 74 0F BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 3D ?? ?? ?? ?? 00 74 19 B8 ?? ?? ?? ?? 48 85 C0 74 0F BF ?? ?? ?? ?? 49 89 C3 C9 41 FF E3 66 66 90 C9 C3 }
	condition:
		$pattern
}

rule __do_global_dtors_aux_6920d26a00b55c9cdaaa1b604b2acf3a {
	meta:
		aliases = "__do_global_dtors_aux"
		type = "func"
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
		type = "func"
		size = "27"
		objfiles = "crypt@libcrypt.a"
	strings:
		$pattern = { ( CC | 80 ) 3E 24 75 11 80 7E 01 31 75 0B 80 7E 02 24 75 05 E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mkfifo_2c7fa22eb1f94dc3e502045ccd62b890 {
	meta:
		aliases = "mkfifo"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "67"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 81 ) FF FF 03 00 00 53 89 FB 77 34 E8 5E FF FF FF 89 DA C1 EA 05 89 D2 48 8B 94 D0 48 01 00 00 48 85 D2 74 1B 89 D8 48 C1 E0 04 83 B8 ?? ?? ?? ?? 00 74 0C 48 89 D8 83 E0 1F 48 8B 04 C2 EB 02 31 C0 5B C3 }
	condition:
		$pattern
}

rule random_r_15865f38ae347669c65c8126e85dd22d {
	meta:
		aliases = "__GI_random_r, random_r"
		type = "func"
		size = "90"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { ( CC | 83 ) 7F 18 00 4C 8B 47 10 75 18 41 69 00 6D 4E C6 41 05 39 30 00 00 25 FF FF FF 7F 41 89 00 89 06 EB 35 48 8B 07 48 8B 4F 08 4C 8B 4F 28 8B 10 03 11 89 10 48 83 C0 04 D1 EA 4C 39 C8 89 16 48 8D 51 04 72 05 4C 89 C0 EB 07 4C 39 CA 49 0F 43 D0 48 89 07 48 89 57 08 31 C0 C3 }
	condition:
		$pattern
}

rule _ppfs_setargs_3507f258aafe1799076b13fc7b86675a {
	meta:
		aliases = "_ppfs_setargs"
		type = "func"
		size = "436"
		objfiles = "_ppfs_setargs@libc.a"
	strings:
		$pattern = { ( CC | 83 ) 7F 1C 00 0F 85 5A 01 00 00 81 7F 0C 00 00 00 80 75 2A 8B 47 50 83 F8 30 73 0E 89 C2 48 03 57 60 83 C0 08 89 47 50 EB 0C 48 8B 57 58 48 8D 42 08 48 89 47 58 8B 02 89 47 70 89 47 0C 81 7F 08 00 00 00 80 48 8D 4F 70 75 2A 8B 47 50 83 F8 30 73 0E 89 C2 48 03 57 60 83 C0 08 89 47 50 EB 0C 48 8B 57 58 48 8D 42 08 48 89 47 58 8B 02 89 47 70 89 47 08 31 F6 E9 DE 00 00 00 48 63 C6 FF C6 8B 44 87 2C 83 F8 08 0F 84 CC 00 00 00 7F 1B 83 F8 02 74 3F 7F 09 85 C0 79 39 E9 8E 00 00 00 83 F8 07 0F 85 85 00 00 00 EB 51 3D 00 04 00 00 74 7C 7F 10 3D 00 01 00 00 74 19 3D 00 02 00 00 75 6C EB 10 3D 00 08 00 00 }
	condition:
		$pattern
}

rule __length_dotted_bdca8727ea5ef8deabb7222ff15a7eb0 {
	meta:
		aliases = "__length_dotted"
		type = "func"
		size = "57"
		objfiles = "lengthd@libc.a"
	strings:
		$pattern = { ( CC | 83 ) C8 FF 48 85 FF 89 F1 75 1D C3 44 0F B6 C0 44 89 C0 25 C0 00 00 00 3D C0 00 00 00 75 05 8D 51 02 EB 11 41 8D 0C 10 48 63 C1 8D 51 01 8A 04 07 84 C0 75 D7 89 D0 29 F0 C3 }
	condition:
		$pattern
}

rule wctob_5cf6c18f5aebbce981a8e3bd1a1f8205 {
	meta:
		aliases = "wctob"
		type = "func"
		size = "13"
		objfiles = "wctob@libc.a"
	strings:
		$pattern = { ( CC | 83 ) C8 FF 81 FF 80 00 00 00 0F 42 C7 C3 }
	condition:
		$pattern
}

rule __encode_header_e8c7385a92a4dbd3322681c2a1ebb46b {
	meta:
		aliases = "__encode_header"
		type = "func"
		size = "193"
		objfiles = "encodeh@libc.a"
	strings:
		$pattern = { ( CC | 83 ) C8 FF 83 FA 0B 49 89 F8 49 89 F1 0F 8E AE 00 00 00 0F B6 47 01 88 06 8B 07 88 46 01 83 7F 04 01 41 8B 50 08 19 FF F7 D7 83 E7 80 41 83 78 0C 01 19 F6 F7 D6 83 E6 04 41 83 78 10 01 19 C9 83 E2 0F F7 D1 C1 E2 03 83 E1 02 41 83 78 14 00 0F 95 C0 09 D0 09 F8 09 F0 09 C8 41 88 41 02 41 83 78 18 01 41 8A 50 1C 19 C0 83 E2 0F F7 D0 83 E0 80 09 D0 41 88 41 03 41 0F B6 40 21 41 88 41 04 41 8B 40 20 41 88 41 05 41 0F B6 40 25 41 88 41 06 41 8B 40 24 41 88 41 07 41 0F B6 40 29 41 88 41 08 41 8B 40 28 41 88 41 09 41 0F B6 40 2D 41 88 41 0A 41 8B 40 2C 41 88 41 0B B8 0C 00 00 00 C3 }
	condition:
		$pattern
}

rule fopen_49ee42930df90b8512b73c45b5907075 {
	meta:
		aliases = "__GI_fopen, fopen"
		type = "func"
		size = "10"
		objfiles = "fopen@libc.a"
	strings:
		$pattern = { ( CC | 83 ) C9 FF 31 D2 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getoffset_ead857a81f0bc3fdf87c439149f36507 {
	meta:
		aliases = "getoffset"
		type = "func"
		size = "111"
		objfiles = "tzset@libc.a"
	strings:
		$pattern = { ( CC | 83 ) CA FF 41 B9 ?? ?? ?? ?? 45 31 C0 41 89 D2 8A 0F 49 FF C1 8D 41 D0 3C 09 77 09 0F BE C1 48 FF C7 8D 50 D0 8A 0F 8D 41 D0 3C 09 77 0D 6B D2 0A 0F BE C1 48 FF C7 8D 54 02 D0 41 8A 09 0F BE C1 39 C2 72 04 31 FF EB 23 48 0F BE C1 48 63 D2 49 0F AF C0 4C 8D 04 02 31 D2 80 3F 3A 75 06 48 FF C7 44 89 D2 FE C9 7F A7 4C 89 06 48 89 F8 C3 }
	condition:
		$pattern
}

rule toascii_f2cd184b8363fafbe1eedf2e137d2ceb {
	meta:
		aliases = "toascii"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "16"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) FE 01 B8 16 00 00 00 77 05 89 77 0C 30 C0 C3 }
	condition:
		$pattern
}

rule pthread_mutexattr_setpshared_f8ceb03085e464132c8d8fcb56974aad {
	meta:
		aliases = "__pthread_mutexattr_setpshared, pthread_condattr_setpshared, pthread_mutexattr_setpshared"
		type = "func"
		size = "18"
		objfiles = "mutex@libpthread.a, condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) FE 01 B8 16 00 00 00 77 07 19 C0 F7 D0 83 E0 26 C3 }
	condition:
		$pattern
}

rule pthread_attr_setschedpolicy_0811c96f375dc3002b045bf361a069f6 {
	meta:
		aliases = "__GI_pthread_attr_setschedpolicy, pthread_attr_setschedpolicy"
		type = "func"
		size = "16"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) FE 02 B8 16 00 00 00 77 05 89 77 04 30 C0 C3 }
	condition:
		$pattern
}

rule pthread_mutexattr_settype_24f5994df1cb86fe4dbc7c2dceb71691 {
	meta:
		aliases = "__pthread_mutexattr_setkind_np, __pthread_mutexattr_settype, pthread_mutexattr_setkind_np, pthread_mutexattr_settype"
		type = "func"
		size = "15"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) FE 03 B8 16 00 00 00 77 04 89 37 30 C0 C3 }
	condition:
		$pattern
}

rule d_make_comp_5db324b0a41e386f7fb57c31fb0fee29 {
	meta:
		aliases = "d_make_comp"
		type = "func"
		size = "115"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 83 ) FE 32 77 53 89 F0 FF 24 C5 ?? ?? ?? ?? 66 90 48 85 D2 74 43 44 8B 4F 28 31 C0 44 3B 4F 2C 7D 39 4D 63 C1 41 83 C1 01 4F 8D 14 40 4C 8B 47 20 44 89 4F 28 4F 8D 04 D0 4D 85 C0 74 1D 41 89 30 49 89 50 08 4C 89 C0 49 89 48 10 C3 0F 1F 40 00 48 85 D2 75 0B 0F 1F 00 31 C0 F3 C3 0F 1F 40 00 48 85 C9 74 F3 44 8B 4F 28 31 C0 44 3B 4F 2C 7D E9 EB AE }
	condition:
		$pattern
}

rule hstrerror_52a45390fba03bf4bd140d19d1650bc3 {
	meta:
		aliases = "hstrerror"
		type = "func"
		size = "22"
		objfiles = "herror@libc.a"
	strings:
		$pattern = { ( CC | 83 ) FF 04 B8 ?? ?? ?? ?? 77 0B 48 63 C7 48 8B 04 C5 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule qualifier_string_f88368aac6e366bdbaf0631631f9a0a4 {
	meta:
		aliases = "qualifier_string"
		type = "func"
		size = "153"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 83 ) FF 07 0F 87 87 00 00 00 89 FF FF 24 FD ?? ?? ?? ?? 66 0F 1F 44 00 00 B8 ?? ?? ?? ?? C3 66 90 B8 ?? ?? ?? ?? C3 66 2E 0F 1F 84 00 00 00 00 00 B8 ?? ?? ?? ?? C3 66 2E 0F 1F 84 00 00 00 00 00 B8 ?? ?? ?? ?? C3 66 2E 0F 1F 84 00 00 00 00 00 B8 ?? ?? ?? ?? C3 66 2E 0F 1F 84 00 00 00 00 00 B8 ?? ?? ?? ?? C3 66 2E 0F 1F 84 00 00 00 00 00 B8 ?? ?? ?? ?? C3 66 2E 0F 1F 84 00 00 00 00 00 B8 ?? ?? ?? ?? C3 66 2E 0F 1F 84 00 00 00 00 00 48 83 EC 08 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule strsignal_b11c7a9b69a8587c5009cad4936dfa96 {
	meta:
		aliases = "__GI_strsignal, strsignal"
		type = "func"
		size = "80"
		objfiles = "strsignal@libc.a"
	strings:
		$pattern = { ( CC | 83 ) FF 1F 53 77 1B 89 F8 BB ?? ?? ?? ?? EB 09 80 3B 01 83 D8 00 48 FF C3 85 C0 75 F3 80 3B 00 75 2A 48 63 F7 BA F6 FF FF FF BF ?? ?? ?? ?? 31 C9 E8 ?? ?? ?? ?? 48 8D 58 F1 BA 0F 00 00 00 BE ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule code_for_qualifier_1aa5e554336974ca77816f371c2f239c {
	meta:
		aliases = "code_for_qualifier"
		type = "func"
		size = "70"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 83 ) FF 56 74 3B 83 FF 75 74 26 83 FF 43 74 11 48 83 EC 08 E8 ?? ?? ?? ?? 0F 1F 84 00 00 00 00 00 B8 01 00 00 00 C3 66 2E 0F 1F 84 00 00 00 00 00 B8 04 00 00 00 C3 66 2E 0F 1F 84 00 00 00 00 00 B8 02 00 00 00 C3 }
	condition:
		$pattern
}

rule iswctype_170a4dacb0303a6e5acbf26d09cfc9fc {
	meta:
		aliases = "__GI_iswctype, iswctype"
		type = "func"
		size = "41"
		objfiles = "iswctype@libc.a"
	strings:
		$pattern = { ( CC | 83 ) FF 7F 77 05 83 FE 0C 76 03 31 C0 C3 48 8B 15 ?? ?? ?? ?? 48 63 CF 89 F0 66 8B 84 00 ?? ?? ?? ?? 66 23 04 4A 0F B7 C0 C3 }
	condition:
		$pattern
}

rule inet_makeaddr_a2e9a1cc719d21468aa69c8c4f04a98a {
	meta:
		aliases = "__GI_inet_makeaddr, inet_makeaddr"
		type = "func"
		size = "68"
		objfiles = "inet_addr@libc.a"
	strings:
		$pattern = { ( CC | 83 ) FF 7F 77 0B 81 E6 FF FF FF 00 C1 E7 18 EB 27 81 FF FF FF 00 00 77 08 0F B7 C6 C1 E7 10 EB 0F 81 FF FF FF FF 00 77 0F 40 0F B6 C6 C1 E7 08 09 F8 89 44 24 FC EB 06 09 FE 89 74 24 FC 8B 44 24 FC 0F C8 C3 }
	condition:
		$pattern
}

rule towupper_66d7004649769513de6799d21320bda5 {
	meta:
		aliases = "__GI_towlower, __GI_towupper, towlower, towupper"
		type = "func"
		size = "21"
		objfiles = "towlower@libc.a, towupper@libc.a"
	strings:
		$pattern = { ( CC | 83 ) FF 7F 77 0D 48 8B 05 ?? ?? ?? ?? 89 FA 0F BF 3C 50 89 F8 C3 }
	condition:
		$pattern
}

rule cplus_demangle_set_style_1986e8063253e4b182b63e3e10767648 {
	meta:
		aliases = "cplus_demangle_set_style"
		type = "func"
		size = "49"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 83 ) FF FF BA ?? ?? ?? ?? 75 0A EB 1C 0F 1F 40 00 39 F8 74 14 48 83 C2 18 8B 42 08 85 C0 75 F1 F3 C3 0F 1F 80 00 00 00 00 89 3D ?? ?? ?? ?? 89 F8 C3 }
	condition:
		$pattern
}

rule xre_set_registers_b92beb81f5153824d332f6a8f5423cf7 {
	meta:
		aliases = "xre_set_registers"
		type = "func"
		size = "56"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 85 ) D2 75 1C 80 67 38 F9 C7 06 00 00 00 00 48 C7 46 10 00 00 00 00 48 C7 46 08 00 00 00 00 C3 90 0F B6 47 38 83 E0 F9 83 C8 02 88 47 38 89 16 48 89 4E 08 4C 89 46 10 C3 }
	condition:
		$pattern
}

rule _load_inttype_50fd76293e996f00d4c994e71de79faf {
	meta:
		aliases = "_load_inttype"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "39"
		objfiles = "sigjmp@libc.a"
	strings:
		$pattern = { ( CC | 85 ) F6 53 48 89 FB 74 16 48 8D 57 48 31 F6 31 FF E8 ?? ?? ?? ?? 85 C0 BA 01 00 00 00 74 02 31 D2 89 53 40 31 C0 5B C3 }
	condition:
		$pattern
}

rule pthread_attr_setscope_2e39ee7b82bec7b177c4a03e0b9d3e87 {
	meta:
		aliases = "__GI_pthread_attr_setscope, pthread_attr_setscope"
		type = "func"
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
		type = "func"
		size = "40"
		objfiles = "tcsendbrk@libc.a"
	strings:
		$pattern = { ( CC | 85 ) F6 7F 09 31 D2 BE 09 54 00 00 EB 14 8D 46 63 BA 64 00 00 00 BE 25 54 00 00 89 D1 99 F7 F9 89 C2 31 C0 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __fsetlocking_9e25b7317ee9d4220b22b004e87d0dd1 {
	meta:
		aliases = "__GI___fsetlocking, __fsetlocking"
		type = "func"
		size = "32"
		objfiles = "__fsetlocking@libc.a"
	strings:
		$pattern = { ( CC | 85 ) F6 8B 57 50 74 12 B8 01 00 00 00 83 FE 02 0F 45 05 ?? ?? ?? ?? 89 47 50 83 E2 01 8D 42 01 C3 }
	condition:
		$pattern
}

rule register_printf_function_8da1fe83892bf8f69cfa7dc35ecbdb28 {
	meta:
		aliases = "register_printf_function"
		type = "func"
		size = "99"
		objfiles = "register_printf_function@libc.a"
	strings:
		$pattern = { ( CC | 85 ) FF 74 5B 48 85 D2 74 56 4C 8B 0D ?? ?? ?? ?? 45 31 C0 49 8D 49 0A 48 FF C9 0F BE 01 84 C0 4C 0F 44 C1 39 F8 75 06 49 89 C8 4C 89 C9 4C 39 C9 77 E5 4D 85 C0 74 28 48 85 F6 74 1C 44 89 C0 41 88 38 29 C8 48 98 48 89 34 C5 ?? ?? ?? ?? 48 89 14 C5 ?? ?? ?? ?? EB 04 41 C6 00 00 31 C0 C3 83 C8 FF C3 }
	condition:
		$pattern
}

rule byte_store_op2_c9d8e7daf981a6a989f249526538367d {
	meta:
		aliases = "byte_store_op2"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "30"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 89 ) 17 48 C7 47 08 ?? ?? ?? ?? 48 89 77 18 C7 47 28 00 00 00 00 48 C7 47 20 00 00 00 00 C3 }
	condition:
		$pattern
}

rule setenv_360f8dabf01a288ed2fa94fcd4fc3d83 {
	meta:
		aliases = "__GI_setenv, setenv"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "14"
		objfiles = "tcflush@libc.a"
	strings:
		$pattern = { ( CC | 89 ) F2 31 C0 BE 0B 54 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule creat64_4b349260194dfd68bcfbf931ff7efc9e {
	meta:
		aliases = "__libc_creat, __libc_creat64, creat, creat64"
		type = "func"
		size = "14"
		objfiles = "open@libc.a, creat64@libc.a"
	strings:
		$pattern = { ( CC | 89 ) F2 31 C0 BE 41 02 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pex_unix_fdopenr_175adfb56eb622058af8f007c8d1d34f {
	meta:
		aliases = "pex_unix_fdopenr"
		type = "func"
		size = "12"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 89 ) F7 BE ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pex_unix_close_6761fc353c3878054d9bbe13ca116bd7 {
	meta:
		aliases = "pex_unix_close"
		type = "func"
		size = "7"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 89 ) F7 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __powisf2_9b8253b555f1fdafa6c5952b3f63f55f {
	meta:
		aliases = "__powisf2"
		type = "func"
		size = "75"
		objfiles = "_powisf2@libgcc.a"
	strings:
		$pattern = { ( CC | 89 ) F8 0F 28 C8 C1 F8 1F 89 C2 31 FA 29 C2 F6 C2 01 75 08 F3 0F 10 0D ?? ?? ?? ?? 89 D0 66 66 90 D1 E8 74 10 A8 01 F3 0F 59 C0 74 F4 D1 E8 F3 0F 59 C8 75 F0 85 FF 79 0F F3 0F 10 05 ?? ?? ?? ?? F3 0F 5E C1 0F 28 C8 0F 28 C1 C3 }
	condition:
		$pattern
}

rule __subvsi3_7f0e0e880e6794eff1b72c749a940696 {
	meta:
		aliases = "__subvsi3"
		type = "func"
		size = "44"
		objfiles = "_subvsi3@libgcc.a"
	strings:
		$pattern = { ( CC | 89 ) F8 48 83 EC 08 29 F0 85 F6 78 14 39 F8 0F 9F C2 84 D2 75 12 48 83 C4 08 C3 66 66 90 66 66 90 39 F8 0F 9C C2 EB EA E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __negvsi2_0b946368791f740041bd56d857b960c1 {
	meta:
		aliases = "__negvsi2"
		type = "func"
		size = "44"
		objfiles = "_negvsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 89 ) F8 48 83 EC 08 F7 D8 85 FF 78 14 85 C0 0F 9F C2 84 D2 75 12 48 83 C4 08 C3 66 66 90 66 66 90 89 C2 C1 EA 1F EB EA E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __powidf2_9c13e8d193703de24a7d69983d0d2ef8 {
	meta:
		aliases = "__powidf2"
		type = "func"
		size = "77"
		objfiles = "_powidf2@libgcc.a"
	strings:
		$pattern = { ( CC | 89 ) F8 66 0F 28 C8 C1 F8 1F 89 C2 31 FA 29 C2 F6 C2 01 75 08 F2 0F 10 0D ?? ?? ?? ?? 89 D0 66 90 D1 E8 74 10 A8 01 F2 0F 59 C0 74 F4 D1 E8 F2 0F 59 C8 75 F0 85 FF 79 10 F2 0F 10 05 ?? ?? ?? ?? F2 0F 5E C1 66 0F 28 C8 66 0F 28 C1 C3 }
	condition:
		$pattern
}

rule abs_515b26df566dbbfb8dd37af642fff2b7 {
	meta:
		aliases = "abs"
		type = "func"
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
		type = "func"
		size = "24"
		objfiles = "div@libc.a"
	strings:
		$pattern = { ( CC | 89 ) F8 99 F7 FE 0F AF F0 89 C1 89 F8 89 CA 29 F0 48 C1 E0 20 48 09 D0 C3 }
	condition:
		$pattern
}

rule __malloc_largebin_index_505c5e40fd58a6ec8d175f279a28f712 {
	meta:
		aliases = "__malloc_largebin_index"
		type = "func"
		size = "110"
		objfiles = "malloc@libc.a"
	strings:
		$pattern = { ( CC | 89 ) FA 41 89 F9 B8 5F 00 00 00 C1 EA 08 81 FA FF FF 00 00 77 58 8D BA 00 FF FF FF B0 0D C1 EF 10 83 E7 08 40 88 F9 29 F8 D3 E2 8D B2 00 F0 FF FF C1 EE 10 83 E6 04 40 88 F1 29 F0 D3 E2 8D 8A 00 C0 FF FF C1 E9 10 83 E1 02 D3 E2 29 C8 41 89 D0 C1 EA 0F 41 C1 E8 0E F7 D2 44 21 C2 01 D0 8D 48 06 41 D3 E9 41 83 E1 03 41 8D 44 81 20 C3 }
	condition:
		$pattern
}

rule __absvsi2_3a74914e60d5c85ccc25670e57a5c844 {
	meta:
		aliases = "__absvsi2"
		type = "func"
		size = "12"
		objfiles = "_absvsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 89 ) FA C1 FA 1F 89 D0 31 F8 29 D0 C3 }
	condition:
		$pattern
}

rule posix_openpt_e5072460d403d40cfae2fbf7677a26c2 {
	meta:
		aliases = "__GI_posix_openpt, posix_openpt"
		type = "func"
		size = "14"
		objfiles = "getpt@libc.a"
	strings:
		$pattern = { ( CC | 89 ) FE 31 C0 BF ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule nl_langinfo_16dffd8df3d833092b2bab5bea248391 {
	meta:
		aliases = "__GI_nl_langinfo, nl_langinfo"
		type = "func"
		size = "75"
		objfiles = "nl_langinfo@libc.a"
	strings:
		$pattern = { ( CC | 89 ) FE C1 FE 08 83 FE 05 77 3B 89 F0 0F B6 90 ?? ?? ?? ?? 40 0F B6 C7 8D 0C 02 8D 46 01 0F B6 80 ?? ?? ?? ?? 39 C1 73 1D 8D 41 07 83 E1 40 89 C0 0F B6 90 ?? ?? ?? ?? 8D 04 09 89 C0 48 8D 84 02 ?? ?? ?? ?? C3 B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule strstr_8dbf807eba24496a480e82d8aa142cf1 {
	meta:
		aliases = "__GI_strstr, strstr"
		type = "func"
		size = "193"
		objfiles = "strstr@libc.a"
	strings:
		$pattern = { ( CC | 8A ) 06 84 C0 44 0F B6 D0 0F 84 AC 00 00 00 48 FF CF 48 FF C7 8A 07 84 C0 0F 84 A0 00 00 00 0F B6 C0 44 39 D0 75 EB 8A 46 01 4C 8D 5E 01 84 C0 0F 84 85 00 00 00 0F B6 F0 0F B6 47 01 48 8D 57 01 EB 30 0F B6 47 01 48 8D 57 01 EB 1B 85 C0 74 6E 48 FF C2 8A 0A 0F B6 C1 44 39 D0 74 0F 84 C9 74 5D 48 FF C2 0F B6 02 44 39 D0 75 E0 48 FF C2 0F B6 02 39 F0 75 F1 41 0F B6 4B 01 0F B6 42 01 4D 8D 4B 01 4C 8D 42 01 48 8D 7A FF 39 C8 75 27 85 C9 74 27 41 8A 41 01 41 38 40 01 0F B6 C8 75 16 84 C0 74 16 49 83 C0 02 49 83 C1 02 41 0F B6 09 41 0F B6 00 EB D5 85 C9 75 88 48 89 F8 C3 31 C0 C3 }
	condition:
		$pattern
}

rule strcoll_ddddab28e2e9476e8bcf8637008fb49a {
	meta:
		aliases = "__GI_strcmp, __GI_strcoll, strcmp, strcoll"
		type = "func"
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
		type = "func"
		size = "32"
		objfiles = "__scan_cookie@libc.a"
	strings:
		$pattern = { ( CC | 8A ) 47 1D FF 47 14 3C 02 75 0A 8B 47 04 C6 47 1D 00 89 07 C3 84 C0 75 07 FF 4F 10 C6 47 1D 01 C3 }
	condition:
		$pattern
}

rule init_signal_tables_e50ef9f6720f8c97dd31a6d8a2acf7fd {
	meta:
		aliases = "init_error_tables, init_signal_tables"
		type = "func"
		size = "163"
		objfiles = "strerror@libiberty.a, strsignal@libiberty.a"
	strings:
		$pattern = { ( CC | 8B ) 05 ?? ?? ?? ?? 85 C0 75 29 31 C0 BA ?? ?? ?? ?? 0F 1F 80 00 00 00 00 8B 0A 8D 71 01 39 C1 0F 4D C6 48 83 C2 10 48 83 7A 08 00 75 EB 89 05 ?? ?? ?? ?? 48 83 3D ?? ?? ?? ?? 00 74 03 C3 66 90 55 53 48 83 EC 08 8B 05 ?? ?? ?? ?? 8D 2C C5 00 00 00 00 48 63 ED 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 48 89 05 ?? ?? ?? ?? 74 2F 48 89 EA 31 F6 48 89 C7 E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 0F 1F 40 00 48 63 32 48 83 C2 10 48 89 0C F3 48 8B 4A 08 48 85 C9 75 EC 48 83 C4 08 5B 5D C3 }
	condition:
		$pattern
}

rule pthread_getconcurrency_6d95d9ea3b4232aab4c7687be499d076 {
	meta:
		aliases = "__libc_current_sigrtmax, __libc_current_sigrtmin, __pthread_getconcurrency, pthread_getconcurrency"
		type = "func"
		size = "7"
		objfiles = "allocrtsig@libc.a, pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 05 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule elem_compare_c4f4bfd59bfdc2921bec650d7161647a {
	meta:
		aliases = "elem_compare"
		type = "func"
		size = "18"
		objfiles = "partition@libiberty.a"
	strings:
		$pattern = { ( CC | 8B ) 06 31 D2 39 07 B8 FF FF FF FF 0F 9F C2 0F 4D C2 C3 }
	condition:
		$pattern
}

rule wcpcpy_aca8bedfd5ccc0ba983e1dcd6d76a70b {
	meta:
		aliases = "wcpcpy"
		type = "func"
		size = "21"
		objfiles = "wcpcpy@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 06 48 83 C6 04 89 07 48 83 C7 04 85 C0 75 F0 48 8D 47 FC C3 }
	condition:
		$pattern
}

rule wcschr_e265aa5ac78ed3a73e21c6b2a62882ab {
	meta:
		aliases = "__GI_wcschr, wcschr"
		type = "func"
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
		type = "func"
		size = "83"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 07 48 8B 57 18 85 C0 74 06 FF C8 75 42 EB 18 48 8B 7A 20 89 F0 48 8D 0C 07 48 3B 4A 28 77 30 48 89 F8 48 89 4A 20 C3 48 8B 4A 68 89 F6 48 39 CE 7F 1D 48 8B 7A 58 48 8D 04 37 48 3B 42 60 77 0F 48 01 72 58 48 29 F1 48 89 F8 48 89 4A 68 C3 31 C0 C3 }
	condition:
		$pattern
}

rule xdr_uint32_t_1f8da2ccf24d8017dd535ff919a72306 {
	meta:
		aliases = "xdr_int32_t, xdr_uint32_t"
		type = "func"
		size = "40"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 07 83 F8 01 74 0C 73 15 48 8B 47 08 4C 8B 58 48 EB 08 48 8B 47 08 4C 8B 58 40 41 FF E3 83 F8 02 0F 94 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule pthread_rwlockattr_getkind_np_bf2bcf99b78042f4e0796c0c15ef442e {
	meta:
		aliases = "__GI_pthread_attr_getdetachstate, __pthread_mutexattr_getkind_np, __pthread_mutexattr_gettype, pthread_attr_getdetachstate, pthread_mutexattr_getkind_np, pthread_mutexattr_gettype, pthread_rwlockattr_getkind_np"
		type = "func"
		size = "7"
		objfiles = "mutex@libpthread.a, rwlock@libpthread.a, attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 07 89 06 31 C0 C3 }
	condition:
		$pattern
}

rule __libc_allocate_rtsig_46f1e6510e7526738d0c53622cc7b423 {
	meta:
		aliases = "__libc_allocate_rtsig"
		type = "func"
		size = "55"
		objfiles = "allocrtsig@libc.a, pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 0D ?? ?? ?? ?? 83 F9 FF 74 26 8B 15 ?? ?? ?? ?? 39 D1 7F 1C 85 FF 74 0B 8D 41 01 89 05 ?? ?? ?? ?? EB 10 8D 42 FF 89 D1 89 05 ?? ?? ?? ?? EB 03 83 C9 FF 89 C8 C3 }
	condition:
		$pattern
}

rule xdr_long_e1dbf51a8c3dd76d272a1bec8e4f4a0d {
	meta:
		aliases = "__GI_xdr_long, xdr_long"
		type = "func"
		size = "51"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 0F 85 C9 75 15 48 8B 16 48 63 C2 48 39 D0 75 19 48 8B 47 08 4C 8B 58 08 EB 0C 83 F9 01 75 0A 48 8B 47 08 4C 8B 18 41 FF E3 31 C0 83 F9 02 0F 94 C0 C3 }
	condition:
		$pattern
}

rule md5_read_ctx_a04181dc7c20e88560d125749673b140 {
	meta:
		aliases = "md5_read_ctx"
		type = "func"
		size = "26"
		objfiles = "md5@libiberty.a"
	strings:
		$pattern = { ( CC | 8B ) 17 48 89 F0 89 16 8B 57 04 89 56 04 8B 57 08 89 56 08 8B 57 0C 89 56 0C C3 }
	condition:
		$pattern
}

rule __pthread_restart_new_f7ca6411fb683c31a924c8feff00d74d {
	meta:
		aliases = "__pthread_restart_new"
		type = "func"
		size = "14"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 35 ?? ?? ?? ?? 8B 7F 28 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_rwlockattr_getpshared_7d87a0480047214eb11c700f0a85c378 {
	meta:
		aliases = "__GI_pthread_attr_getschedpolicy, pthread_attr_getschedpolicy, pthread_rwlockattr_getpshared"
		type = "func"
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
		type = "func"
		size = "9"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 47 08 25 0F 10 00 00 C3 }
	condition:
		$pattern
}

rule cfmakeraw_7287fc8ca15ecac7f9da2c1f0bfbc7bd {
	meta:
		aliases = "cfmakeraw"
		type = "func"
		size = "40"
		objfiles = "cfmakeraw@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 47 08 81 27 14 FA FF FF 83 67 04 FE C6 47 17 01 81 67 0C B4 7F FF FF C6 47 16 00 25 CF FE FF FF 83 C8 30 89 47 08 C3 }
	condition:
		$pattern
}

rule pthread_attr_getinheritsched_0274aac5c29a580eb22600b553828fd3 {
	meta:
		aliases = "__GI_pthread_attr_getinheritsched, pthread_attr_getinheritsched"
		type = "func"
		size = "8"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 47 0C 89 06 31 C0 C3 }
	condition:
		$pattern
}

rule _seterr_reply_2e74f49b9f64dadebbfad36b256a2feb {
	meta:
		aliases = "__GI__seterr_reply, _seterr_reply"
		type = "func"
		size = "231"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 47 10 85 C0 74 0A FF C8 0F 85 91 00 00 00 EB 5C 8B 47 30 85 C0 75 07 C7 06 00 00 00 00 C3 83 F8 05 89 C0 77 37 FF 24 C5 ?? ?? ?? ?? C7 06 08 00 00 00 EB 78 C7 06 09 00 00 00 EB 70 C7 06 0A 00 00 00 EB 68 C7 06 0B 00 00 00 EB 60 C7 06 0C 00 00 00 EB 58 C7 06 00 00 00 00 EB 50 C7 06 10 00 00 00 48 C7 46 08 00 00 00 00 EB 2D 8B 47 18 83 F8 01 74 0D 83 F8 06 75 10 C7 06 06 00 00 00 EB 2B C7 06 07 00 00 00 EB 23 C7 06 10 00 00 00 48 C7 46 08 01 00 00 00 89 C0 48 89 46 10 EB 0D C7 06 10 00 00 00 8B 47 10 48 89 46 08 8B 06 83 F8 07 74 1B 83 F8 09 74 1D 83 F8 06 75 28 48 8B 47 20 48 89 46 08 48 8B }
	condition:
		$pattern
}

rule pthread_mutex_destroy_aa3b21c3a1eb41d628a397e5a48e2fbe {
	meta:
		aliases = "__pthread_mutex_destroy, pthread_mutex_destroy"
		type = "func"
		size = "45"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 47 10 85 C0 78 0A 83 F8 01 7E 0B 83 F8 03 7E 0C B8 16 00 00 00 C3 F6 47 18 01 EB 05 48 83 7F 18 00 74 06 B8 10 00 00 00 C3 31 C0 C3 }
	condition:
		$pattern
}

rule sem_getvalue_05935359c1ce9b131d550f05f2a33b38 {
	meta:
		aliases = "__GI_pthread_attr_getscope, __new_sem_getvalue, pthread_attr_getscope, sem_getvalue"
		type = "func"
		size = "8"
		objfiles = "semaphore@libpthread.a, attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 47 10 89 06 31 C0 C3 }
	condition:
		$pattern
}

rule xdrmem_inline_379bf3e9df0b5d88aac4fee30b3ca5d3 {
	meta:
		aliases = "xdrmem_inline"
		type = "func"
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
		type = "func"
		size = "36"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 47 28 31 D2 83 F8 03 76 17 83 E8 04 B2 01 89 47 28 48 8B 47 18 8B 00 0F C8 89 06 48 83 47 18 04 89 D0 C3 }
	condition:
		$pattern
}

rule xdrmem_putint32_201fe442643335908c2673f4c658389a {
	meta:
		aliases = "xdrmem_putint32"
		type = "func"
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
		type = "func"
		size = "39"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 47 28 31 D2 83 F8 03 76 1A 83 E8 04 B2 01 89 47 28 48 8B 47 18 8B 00 0F C8 48 98 48 89 06 48 83 47 18 04 89 D0 C3 }
	condition:
		$pattern
}

rule xdrmem_putlong_9bc8cda551e6234909ea6418ce7e2fc1 {
	meta:
		aliases = "xdrmem_putlong"
		type = "func"
		size = "40"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 47 28 31 D2 83 F8 03 76 1B 48 8B 57 18 83 E8 04 89 47 28 48 8B 06 0F C8 89 02 48 83 47 18 04 BA 01 00 00 00 89 D0 C3 }
	condition:
		$pattern
}

rule htab_collisions_efdb2a82d6506f1a578969f8336a37d9 {
	meta:
		aliases = "htab_collisions"
		type = "func"
		size = "30"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 8B ) 47 38 66 0F 57 C0 85 C0 74 11 8B 57 3C F2 48 0F 2A C8 F2 48 0F 2A C2 F2 0F 5E C1 F3 C3 }
	condition:
		$pattern
}

rule sigisemptyset_0f2814b175f84b38c1b3fd8133dfaea6 {
	meta:
		aliases = "sigisemptyset"
		type = "func"
		size = "33"
		objfiles = "sigisempty@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 47 78 BA 0F 00 00 00 EB 06 48 63 C2 8B 04 C7 85 C0 75 04 FF CA 79 F2 85 C0 0F 94 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule d_make_name_9323febe57e320eec74b699bddb1dcb7 {
	meta:
		aliases = "d_make_name"
		type = "func"
		size = "70"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 8B ) 4F 28 3B 4F 2C 7D 23 48 63 C1 83 C1 01 4C 8D 04 40 48 8B 47 20 89 4F 28 4A 8D 04 C0 48 85 C0 74 09 48 85 F6 74 04 85 D2 75 0D 31 C0 0F 1F 00 C3 0F 1F 80 00 00 00 00 C7 00 00 00 00 00 48 89 70 08 89 50 10 C3 }
	condition:
		$pattern
}

rule xdrmem_setpos_d6a28b0a1ee0d2573d1f9165fbc06333 {
	meta:
		aliases = "xdrmem_setpos"
		type = "func"
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
		type = "func"
		size = "32"
		objfiles = "condvar@libpthread.a, rwlock@libpthread.a, semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 56 2C EB 0F 3B 50 2C 7E 06 48 89 46 10 EB 0C 48 8D 78 10 48 8B 07 48 85 C0 75 E9 48 89 37 C3 }
	condition:
		$pattern
}

rule clntunix_control_ad93da43d04c19462028b3b77ecdc8d0 {
	meta:
		aliases = "clntunix_control"
		type = "func"
		size = "208"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 8D ) 46 FF 48 83 EC 08 49 89 D0 48 8B 4F 10 83 F8 0E 77 09 89 C0 FF 24 C5 ?? ?? ?? ?? 31 C0 E9 AB 00 00 00 C7 41 04 01 00 00 00 E9 9A 00 00 00 C7 41 04 00 00 00 00 E9 8E 00 00 00 48 8B 02 48 89 41 08 48 8B 42 08 48 89 41 10 EB 7D 48 8B 41 08 48 89 02 48 8B 41 10 48 89 42 08 EB 6C 48 8D 71 1C BA 6E 00 00 00 4C 89 C7 E8 ?? ?? ?? ?? EB 59 8B 01 89 02 EB 53 48 8B 81 A8 00 00 00 0F C8 EB 33 8B 02 FF C8 0F C8 89 C0 48 89 81 A8 00 00 00 48 8B 81 B8 00 00 00 0F C8 EB 19 48 8B 02 0F C8 89 C0 48 89 81 B8 00 00 00 EB 1E 48 8B 81 B4 00 00 00 0F C8 89 C0 49 89 00 EB 0E 48 8B 02 0F C8 89 C0 48 89 81 B4 00 00 }
	condition:
		$pattern
}

rule clnttcp_control_4d8b6b49fcb295eb0ec0d1c680b0e337 {
	meta:
		aliases = "clnttcp_control"
		type = "func"
		size = "177"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 8D ) 46 FF 48 8B 4F 10 83 F8 0E 77 09 89 C0 FF 24 C5 ?? ?? ?? ?? 31 C0 C3 C7 41 04 01 00 00 00 EB 79 C7 41 04 00 00 00 00 EB 70 48 8B 02 48 89 41 08 48 8B 42 08 C7 41 18 01 00 00 00 48 89 41 10 EB 58 48 8B 41 08 48 89 02 48 8B 41 10 EB 0B 48 8B 41 1C 48 89 02 48 8B 41 24 48 89 42 08 EB 3A 8B 01 89 02 EB 34 48 8B 41 48 0F C8 EB 27 8B 02 FF C8 0F C8 89 C0 48 89 41 48 48 8B 41 58 0F C8 EB 13 48 8B 02 0F C8 89 C0 48 89 41 58 EB 0B 48 8B 41 54 0F C8 89 C0 48 89 02 B8 01 00 00 00 C3 48 8B 02 0F C8 89 C0 48 89 41 54 B8 01 00 00 00 C3 }
	condition:
		$pattern
}

rule clntudp_control_58752df3a8246176adcdab15ca495c29 {
	meta:
		aliases = "clntudp_control"
		type = "func"
		size = "252"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 8D ) 46 FF 49 89 D0 48 8B 4F 10 83 F8 0E 77 09 89 C0 FF 24 C5 ?? ?? ?? ?? 31 C0 C3 C7 41 04 01 00 00 00 E9 B7 00 00 00 C7 41 04 00 00 00 00 E9 AB 00 00 00 48 8B 02 48 89 41 30 48 8B 42 08 48 89 41 38 E9 97 00 00 00 48 8B 41 30 48 89 02 48 8B 41 38 EB 29 48 8B 02 48 89 41 20 48 8B 42 08 48 89 41 28 EB 79 48 8B 41 20 48 89 02 48 8B 41 28 EB 0B 48 8B 41 08 48 89 02 48 8B 41 10 49 89 40 08 EB 5B 8B 01 89 02 EB 55 48 8B 81 90 00 00 00 48 8B 00 0F C8 EB 42 8B 02 48 8B 91 90 00 00 00 FF C8 0F C8 89 C0 48 89 02 48 8B 81 90 00 00 00 48 8B 40 10 0F C8 EB 21 48 8B 02 48 8B 91 90 00 00 00 0F C8 89 C0 48 89 }
	condition:
		$pattern
}

rule towctrans_42623a165cffe5a5e4aa0db987cd1766 {
	meta:
		aliases = "__GI_towctrans, towctrans"
		type = "func"
		size = "47"
		objfiles = "towctrans@libc.a"
	strings:
		$pattern = { ( CC | 8D ) 46 FF 53 89 FB 83 F8 01 77 15 83 FF 7F 77 1B FF CE 75 06 5B E9 ?? ?? ?? ?? 5B E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 16 00 00 00 89 D8 5B C3 }
	condition:
		$pattern
}

rule partition_new_74244911927ee0c5f6f2cb7e90a76dc4 {
	meta:
		aliases = "partition_new"
		type = "func"
		size = "66"
		objfiles = "partition@libiberty.a"
	strings:
		$pattern = { ( CC | 8D ) 47 FF 53 89 FB 48 98 48 8D 04 40 48 8D 3C C5 20 00 00 00 E8 ?? ?? ?? ?? 31 C9 85 DB 89 18 48 8D 50 08 7E 1B 0F 1F 00 89 0A 83 C1 01 C7 42 10 01 00 00 00 48 89 52 08 48 83 C2 18 39 D9 75 E8 5B C3 }
	condition:
		$pattern
}

rule __sigdelset_ad03890f96d8f12ea139551c55208fbf {
	meta:
		aliases = "__sigdelset"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "32"
		objfiles = "sigsetops@libc.a"
	strings:
		$pattern = { ( CC | 8D ) 4E FF B8 01 00 00 00 48 63 D1 83 E1 3F 48 C1 EA 06 48 D3 E0 48 85 04 D7 0F 95 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule toupper_9f0ff8c43c07a77d6d8e6a24d1ca8102 {
	meta:
		aliases = "__GI_tolower, __GI_toupper, tolower, toupper"
		type = "func"
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
		type = "func"
		size = "8"
		objfiles = "pt_machine@libpthread.a"
	strings:
		$pattern = { ( CC | B8 ) 01 00 00 00 87 07 C3 }
	condition:
		$pattern
}

rule xdr_void_62dea3be98d084788202ec199cbcebf6 {
	meta:
		aliases = "__GI__stdlib_mb_cur_max, __GI_xdr_void, _stdlib_mb_cur_max, authnone_validate, floatformat_always_valid, old_sem_extricate_func, xdr_void"
		type = "func"
		size = "6"
		objfiles = "floatformat@libiberty.a, xdr@libc.a, auth_none@libc.a, _stdlib_mb_cur_max@libc.a, oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | B8 ) 01 00 00 00 C3 }
	condition:
		$pattern
}

rule svcudp_stat_cca2f00a582595d7f5454d6d2948b3e3 {
	meta:
		aliases = "_svcauth_short, rendezvous_stat, svcraw_stat, svcudp_stat"
		type = "func"
		size = "6"
		objfiles = "svc_authux@libc.a, svc_tcp@libc.a, svc_udp@libc.a, svc_unix@libc.a, svc_raw@libc.a"
	strings:
		$pattern = { ( CC | B8 ) 02 00 00 00 C3 }
	condition:
		$pattern
}

rule rpc_thread_multi_9dec80f10b80e6ab9f718fde18c116ae {
	meta:
		aliases = "rpc_thread_multi"
		type = "func"
		size = "37"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | B8 ) ?? ?? ?? ?? 48 85 C0 74 0F BE ?? ?? ?? ?? BF 02 00 00 00 E9 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule localeconv_07ab5dcbc6e3352a5a21106f39d27d7f {
	meta:
		aliases = "__GI_localeconv, localeconv"
		type = "func"
		size = "60"
		objfiles = "localeconv@libc.a"
	strings:
		$pattern = { ( CC | B8 ) ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 48 83 C0 08 48 3D ?? ?? ?? ?? 48 C7 00 ?? ?? ?? ?? 72 ED B8 ?? ?? ?? ?? C6 00 7F 48 FF C0 48 3D ?? ?? ?? ?? 76 F2 B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __rpc_thread_variables_7f9512a591a03d83d18bf78c951f8a34 {
	meta:
		aliases = "__rpc_thread_variables"
		type = "func"
		size = "220"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | B8 ) ?? ?? ?? ?? 53 48 85 C0 74 0C BF 02 00 00 00 E8 ?? ?? ?? ?? EB 07 48 8B 05 ?? ?? ?? ?? 48 85 C0 48 89 C3 0F 85 AD 00 00 00 B8 ?? ?? ?? ?? 48 85 C0 74 11 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 18 83 3D ?? ?? ?? ?? 00 75 0F E8 88 FF FF FF C7 05 ?? ?? ?? ?? 01 00 00 00 B8 ?? ?? ?? ?? 48 85 C0 74 0C BF 02 00 00 00 E8 ?? ?? ?? ?? EB 07 48 8B 05 ?? ?? ?? ?? 48 85 C0 48 89 C3 75 55 BE 10 01 00 00 BF 01 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 74 25 48 89 C3 B8 ?? ?? ?? ?? 48 85 C0 74 0F 48 89 DE BF 02 00 00 00 E8 ?? ?? ?? ?? EB 25 48 89 1D ?? ?? ?? ?? EB 1C B8 ?? ?? ?? ?? 48 85 C0 74 0B 5B BF 02 }
	condition:
		$pattern
}

rule __rpc_thread_destroy_6d1ebc8f60529e28a354d346dd4d050e {
	meta:
		aliases = "__rpc_thread_destroy"
		type = "func"
		size = "177"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | B8 ) ?? ?? ?? ?? 53 48 85 C0 74 0F BF 02 00 00 00 E8 ?? ?? ?? ?? 48 89 C3 EB 07 48 8B 1D ?? ?? ?? ?? 48 85 DB 0F 84 85 00 00 00 48 81 FB ?? ?? ?? ?? 74 7C E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B BB B0 00 00 00 E8 ?? ?? ?? ?? 48 8B BB B8 00 00 00 E8 ?? ?? ?? ?? 48 8B BB C0 00 00 00 E8 ?? ?? ?? ?? 48 8B BB F8 00 00 00 E8 ?? ?? ?? ?? 48 8B BB D8 00 00 00 E8 ?? ?? ?? ?? 48 8B BB E0 00 00 00 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 48 85 C0 74 0D 5B 31 F6 BF 02 00 00 00 E9 ?? ?? ?? ?? 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 5B C3 }
	condition:
		$pattern
}

rule __libc_pthread_init_6df29da601a97e2ce0e822cd8a3c1c72 {
	meta:
		aliases = "__GI___errno_location, __GI___h_errno_location, __errno_location, __h_errno_location, __libc_pthread_init"
		type = "func"
		size = "6"
		objfiles = "__errno_location@libc.a, __h_errno_location@libc.a, libc_pthread_init@libc.a"
	strings:
		$pattern = { ( CC | B8 ) ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule wcstoll_7e01fe78e53cc3030b461927294d8a96 {
	meta:
		aliases = "__GI_strtol, __GI_strtoll, __GI_wcstol, __GI_wcstoll, strtoimax, strtol, strtoll, wcstoimax, wcstol, wcstoll"
		type = "func"
		size = "10"
		objfiles = "strtol@libc.a, wcstol@libc.a"
	strings:
		$pattern = { ( CC | B9 ) 01 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sigwaitinfo_1827c0241ee21bc2776ef9f807a2816f {
	meta:
		aliases = "__GI_sigwaitinfo, sigwaitinfo"
		type = "func"
		size = "9"
		objfiles = "__rt_sigtimedwait@libc.a"
	strings:
		$pattern = { ( CC | B9 ) 08 00 00 00 31 D2 EB C8 }
	condition:
		$pattern
}

rule sigtimedwait_887b8c45788e26b3cc615dba2aa8e084 {
	meta:
		aliases = "__GI_sigtimedwait, sigtimedwait"
		type = "func"
		size = "7"
		objfiles = "__rt_sigtimedwait@libc.a"
	strings:
		$pattern = { ( CC | B9 ) 08 00 00 00 EB D1 }
	condition:
		$pattern
}

rule pex_init_10696b7984a423ede6965fc7ac958e24 {
	meta:
		aliases = "pex_init"
		type = "func"
		size = "10"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | B9 ) ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fopen64_d7eff41793f2ecee28eb38daf50ba31d {
	meta:
		aliases = "__GI_fopen64, fopen64"
		type = "func"
		size = "12"
		objfiles = "fopen64@libc.a"
	strings:
		$pattern = { ( CC | B9 ) FE FF FF FF 31 D2 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tcdrain_3d7ce05705196c7f47cc6007f3081006 {
	meta:
		aliases = "__libc_tcdrain, tcdrain"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "10"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | BA ) 08 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule atoll_7a1238ef70db7b947fbe00265536d22b {
	meta:
		aliases = "__GI_atol, atol, atoll"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "20"
		objfiles = "sigempty@libc.a"
	strings:
		$pattern = { ( CC | BA ) 80 00 00 00 48 83 EC 08 31 F6 E8 ?? ?? ?? ?? 5A 31 C0 C3 }
	condition:
		$pattern
}

rule sigfillset_0f41f09d6b0b1506b53b98a18d551223 {
	meta:
		aliases = "__GI_sigfillset, sigfillset"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "10"
		objfiles = "strtok@libc.a"
	strings:
		$pattern = { ( CC | BA ) ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule dlclose_4ceb6d8abf3bb3357fb8b43ed1e9023e {
	meta:
		aliases = "dlclose"
		type = "func"
		size = "10"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | BE ) 01 00 00 00 E9 82 FD FF FF }
	condition:
		$pattern
}

rule timelocal_ae5deb625d6542f0fb1be4f85b9638ed {
	meta:
		aliases = "__GI_iswalnum, iswalnum, mkstemp64, mktime, timelocal"
		type = "func"
		size = "10"
		objfiles = "iswalnum@libc.a, mktime@libc.a, mkstemp64@libc.a"
	strings:
		$pattern = { ( CC | BE ) 01 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule iswalpha_3c375beb103155c6a33059d7b231a969 {
	meta:
		aliases = "__GI_iswalpha, iswalpha"
		type = "func"
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
		type = "func"
		size = "10"
		objfiles = "iswblank@libc.a"
	strings:
		$pattern = { ( CC | BE ) 03 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule iswcntrl_1b7732dee6c5bae2b1d60159ca98eb5b {
	meta:
		aliases = "__GI_iswcntrl, iswcntrl"
		type = "func"
		size = "10"
		objfiles = "iswcntrl@libc.a"
	strings:
		$pattern = { ( CC | BE ) 04 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svcerr_weakauth_f1d9f4caefd560dc10bd9efee025460b {
	meta:
		aliases = "__GI_iswdigit, iswdigit, svcerr_weakauth"
		type = "func"
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
		type = "func"
		size = "10"
		objfiles = "iswgraph@libc.a"
	strings:
		$pattern = { ( CC | BE ) 06 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule iswlower_3b1c82a68426c71959409111fd79f31f {
	meta:
		aliases = "__GI_iswlower, iswlower"
		type = "func"
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
		type = "func"
		size = "10"
		objfiles = "iswprint@libc.a"
	strings:
		$pattern = { ( CC | BE ) 08 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule iswpunct_0ed944a3a3af939bbd07dad461f792ee {
	meta:
		aliases = "__GI_iswpunct, iswpunct"
		type = "func"
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
		type = "func"
		size = "10"
		objfiles = "iswspace@libc.a"
	strings:
		$pattern = { ( CC | BE ) 0A 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule iswupper_faa9dca734d3f1dd2a9643ea8b61179e {
	meta:
		aliases = "__GI_iswupper, iswupper"
		type = "func"
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
		type = "func"
		size = "10"
		objfiles = "iswxdigit@libc.a"
	strings:
		$pattern = { ( CC | BE ) 0C 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fibheap_new_a8e74c40b27797e9696ef9fe8016ef07 {
	meta:
		aliases = "fibheap_new"
		type = "func"
		size = "15"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | BE ) 18 00 00 00 BF 01 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule srand48_aedd30f4a92f36ce8e0b990c7b4f97a2 {
	meta:
		aliases = "__GI_asctime, __GI_inet_ntoa, asctime, ether_aton, ether_ntoa, hcreate, inet_ntoa, srand48"
		type = "func"
		size = "10"
		objfiles = "ether_addr@libc.a, srand48@libc.a, hsearch@libc.a, asctime@libc.a, inet_ntoa@libc.a"
	strings:
		$pattern = { ( CC | BE ) ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule lgamma_8c47b9c6008fc75a3442b25215b4f0fe {
	meta:
		aliases = "__GI_getlogin, __GI_lgamma, __ieee754_gamma, __ieee754_lgamma, __pthread_once_fork_parent, __pthread_once_fork_prepare, _flushlbf, gamma, getlogin, hdestroy, lgamma"
		type = "func"
		size = "10"
		objfiles = "_flushlbf@libc.a, w_gamma@libm.a, getlogin@libc.a, e_gamma@libm.a, e_lgamma@libm.a"
	strings:
		$pattern = { ( CC | BF ) ?? ?? ?? ?? E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdrmem_destroy_2b6be1eb3c8d07c259f5da1535d26263 {
	meta:
		aliases = "__cyg_profile_func_enter, __cyg_profile_func_exit, __linuxthreads_create_event, __linuxthreads_death_event, __linuxthreads_reap_event, __pthread_return_void, __stub1, __stub2, _pthread_cleanup_pop_restore, _pthread_cleanup_push_defer, authnone_destroy, authnone_verf, authunix_nextverf, clntraw_abort, clntraw_destroy, clntraw_geterr, clnttcp_abort, clntudp_abort, clntunix_abort, noop_handler, pthread_handle_sigdebug, pthread_null_sighandler, svcraw_destroy, xdrmem_destroy"
		type = "func"
		size = "1"
		objfiles = "resolv@libresolv.a, pthread@libpthread.a, nsl@libnsl.a, clnt_raw@libc.a, signals@libpthread.a"
	strings:
		$pattern = { ( CC | C3 ) }
	condition:
		$pattern
}

rule md5_init_ctx_785a9f69cbb00f34f11c6385aac1fc08 {
	meta:
		aliases = "md5_init_ctx"
		type = "func"
		size = "49"
		objfiles = "md5@libiberty.a"
	strings:
		$pattern = { ( CC | C7 ) 07 01 23 45 67 C7 47 04 89 AB CD EF C7 47 08 FE DC BA 98 C7 47 0C 76 54 32 10 C7 47 14 00 00 00 00 C7 47 10 00 00 00 00 C7 47 18 00 00 00 00 C3 }
	condition:
		$pattern
}

rule __md5_Init_926032e0aab3f9ea91e4121612375110 {
	meta:
		aliases = "__md5_Init"
		type = "func"
		size = "42"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | C7 ) 47 14 00 00 00 00 C7 47 10 00 00 00 00 C7 07 01 23 45 67 C7 47 04 89 AB CD EF C7 47 08 FE DC BA 98 C7 47 0C 76 54 32 10 C3 }
	condition:
		$pattern
}

rule __powixf2_3162832f16e942f47efd179f448fde21 {
	meta:
		aliases = "__powixf2"
		type = "func"
		size = "83"
		objfiles = "_powixf2@libgcc.a"
	strings:
		$pattern = { ( CC | DB ) 6C 24 08 89 F8 C1 F8 1F 89 C2 31 FA 29 C2 F6 C2 01 D9 C0 75 08 DD D8 D9 05 ?? ?? ?? ?? 89 D0 D1 E8 74 22 D9 C9 A8 01 D8 C8 74 14 D1 E8 DC C9 75 F4 DD D8 85 FF 78 14 F3 C3 66 66 90 66 66 90 D9 C9 D1 E8 75 DE DD D9 85 FF 79 EC D8 3D ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __fixunsxfdi_9e08200ce6971d7f691c4f298f527980 {
	meta:
		aliases = "__fixunsxfdi"
		type = "func"
		size = "104"
		objfiles = "_fixunsxfsi@libgcc.a"
	strings:
		$pattern = { ( CC | DB ) 6C 24 08 D9 05 ?? ?? ?? ?? D9 C9 DB E9 72 33 D9 7C 24 F6 0F B7 44 24 F6 DE E1 80 CC 0C 66 89 44 24 F4 48 B8 00 00 00 00 00 00 00 80 D9 6C 24 F4 DF 7C 24 E8 D9 6C 24 F6 48 8B 54 24 E8 48 8D 04 02 C3 DD D9 D9 7C 24 F6 0F B7 44 24 F6 80 CC 0C 66 89 44 24 F4 D9 6C 24 F4 DF 7C 24 E8 D9 6C 24 F6 48 8B 44 24 E8 C3 }
	condition:
		$pattern
}

rule __mulxc3_0d0b5b49d5c6c80391eb82a6f56f92c1 {
	meta:
		aliases = "__mulxc3"
		type = "func"
		size = "1249"
		objfiles = "_mulxc3@libgcc.a"
	strings:
		$pattern = { ( CC | DB ) 6C 24 08 DB 6C 24 28 DE C9 DB 6C 24 18 DB 6C 24 38 DC C9 DB 6C 24 08 DE C9 DB 6C 24 18 DB 6C 24 28 DE C9 D9 C3 D8 E3 D9 C2 D8 C2 D9 C9 DB E8 7A 0B 75 09 DD DC DD DC DD D8 DD D8 C3 D9 C9 DB E8 7A 0B 75 09 DD DD DD DB DD D8 DD D8 C3 DB 6C 24 08 D8 E0 DB 6C 24 08 DF E8 0F 85 29 02 00 00 0F 8A 23 02 00 00 DF E8 0F 84 C1 01 00 00 48 F7 44 24 10 00 80 00 00 D9 E8 D9 C0 74 08 DD D8 D9 05 ?? ?? ?? ?? DB 7C 24 08 DB 6C 24 18 D8 E0 DB 7C 24 E8 DB 6C 24 18 DF E8 75 0C 7A 0A DB 6C 24 E8 DF E8 75 06 7A 04 DD D8 D9 EE 48 F7 44 24 20 00 80 00 00 D9 E1 74 02 D9 E0 DB 7C 24 18 DB 6C 24 28 DF E8 0F 8A 18 03 }
	condition:
		$pattern
}

rule __divxc3_8f436d82be7ce37b6f189ff7796b675e {
	meta:
		aliases = "__divxc3"
		type = "func"
		size = "823"
		objfiles = "_divxc3@libgcc.a"
	strings:
		$pattern = { ( CC | DB ) 6C 24 28 D9 E1 DB 6C 24 38 D9 E1 DF E9 DD D8 76 3E DB 6C 24 28 DB 6C 24 38 DE F9 DB 6C 24 28 D8 C9 DB 6C 24 38 DE C1 DB 6C 24 08 D8 CA DB 6C 24 18 DC C1 D9 C9 D8 F2 D9 C9 DE CB DB 6C 24 08 DE EB D9 CA DE F1 D9 C9 DB E8 7A 3A 75 38 F3 C3 DB 6C 24 38 DB 6C 24 28 DE F9 DB 6C 24 38 D8 C9 DB 6C 24 28 DE C1 DB 6C 24 18 D8 CA DB 6C 24 08 DC C1 D9 C9 D8 F2 D9 CB DE C9 DB 6C 24 18 DE E1 DE F1 D9 C9 EB C2 D9 C9 DB E8 7A 05 75 03 D9 C9 C3 D9 EE DB 6C 24 28 DF E9 0F 85 91 02 00 00 90 0F 8A 8A 02 00 00 DB 6C 24 38 DF E9 DD D8 0F 84 37 02 00 00 DB 6C 24 08 31 C9 D8 E0 DF E8 DB 6C 24 08 0F 9B C1 DF E8 0F }
	condition:
		$pattern
}

rule pthread_self_94a1c794f10558b3f9b9062573c664f5 {
	meta:
		aliases = "__GI_pthread_self, pthread_self"
		type = "func"
		size = "10"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | E8 ) B6 FF FF FF 48 8B 40 20 C3 }
	condition:
		$pattern
}

rule svcunixfd_create_ab2659501a85bb011ba958bb2904667e {
	meta:
		aliases = "svcfd_create, svcunixfd_create"
		type = "func"
		size = "5"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | E9 ) 3D FF FF FF }
	condition:
		$pattern
}

rule re_match_2_a0eb1c993303c8472384260af67a66d6 {
	meta:
		aliases = "__re_match_2, re_match_2"
		type = "func"
		size = "5"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | E9 ) 6F E2 FF FF }
	condition:
		$pattern
}

rule re_compile_fastmap_30f9ea1898f9028c5d7f600ca8316765 {
	meta:
		aliases = "__re_compile_fastmap, re_compile_fastmap"
		type = "func"
		size = "5"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | E9 ) 75 FC FF FF }
	condition:
		$pattern
}

rule yn_22aa66de8a720f160758a4fe68aab955 {
	meta:
		aliases = "__GI_acos, __GI_acosh, __GI_asin, __GI_atan2, __GI_atanh, __GI_cabs, __GI_cosh, __GI_exp, __GI_fmod, __GI_fseek, __GI_ftell, __GI_ftruncate64, __GI_hypot, __GI_log, __GI_log10, __GI_lseek64, __GI_nearbyint, __GI_pow, __GI_remainder, __GI_setmntent, __GI_sinh, __GI_sqrt, __decode_packet, __deregister_frame_info, __ieee754_gamma_r, __libc_lseek64, acos, acosh, asin, atan2, atanh, cabs, cosh, drem, exp, fmod, fseek, fseeko, ftell, ftello, ftruncate64, hypot, j0, j1, jn, lgamma_r, log, log10, log2, lseek64, mmap64, mq_close, nearbyint, partition_delete, pow, remainder, restart, scalb, setmntent, sinh, splay_tree_xmalloc_deallocate, sqrt, suspend, truncate64, vfork, xdr_longlong_t, xdr_u_longlong_t, y0, y1, yn"
		type = "func"
		size = "5"
		objfiles = "mmap64@libc.a, semaphore@libpthread.a, pthread@libpthread.a, w_fmod@libm.a, xdr@libc.a"
	strings:
		$pattern = { ( CC | E9 ) ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_initialize_254caf1915d414e38380d56bb4684b03 {
	meta:
		aliases = "__pthread_initialize"
		type = "func"
		size = "5"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | E9 ) A4 FB FF FF }
	condition:
		$pattern
}

rule xre_match_2_23c7128f821105a6618c244bb3d379c6 {
	meta:
		aliases = "xre_match_2"
		type = "func"
		size = "5"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | E9 ) AB AD FF FF }
	condition:
		$pattern
}

rule _dl_parse_dynamic_info_942f62783667019d2fd96b2a6000ec85 {
	meta:
		aliases = "_dl_parse_dynamic_info"
		type = "func"
		size = "300"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | E9 ) B4 00 00 00 49 83 F8 21 7F 73 48 8B 47 08 4A 89 04 C6 48 83 3F 15 75 04 48 89 57 08 48 83 3F 18 75 0B 48 C7 86 C0 00 00 00 01 00 00 00 48 83 3F 1E 75 11 F6 47 08 08 74 0B 48 C7 86 C0 00 00 00 01 00 00 00 48 83 3F 16 75 0B 48 C7 86 B0 00 00 00 01 00 00 00 48 83 3F 1D 75 08 48 C7 46 78 00 00 00 00 48 83 3F 0F 75 4B 48 83 BE E8 00 00 00 00 74 41 48 C7 46 78 00 00 00 00 EB 37 49 81 F8 FF FF FF 6F 7F 2E 49 81 F8 F9 FF FF 6F 75 0B 48 8B 47 08 48 89 86 10 01 00 00 48 81 3F FB FF FF 6F 75 11 F6 47 08 01 74 0B 48 C7 86 C0 00 00 00 01 00 00 00 48 83 C7 10 4C 8B 07 4D 85 C0 0F 85 40 FF FF FF 48 8B 46 }
	condition:
		$pattern
}

rule xre_search_2_ae321f1f68b9af9ac9bd041a6b41583f {
	meta:
		aliases = "xre_search_2"
		type = "func"
		size = "5"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | E9 ) BB CF FF FF }
	condition:
		$pattern
}

rule xre_compile_fastmap_5bdd41f0b91e3f5165f83221ab990e5d {
	meta:
		aliases = "xre_compile_fastmap"
		type = "func"
		size = "5"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | E9 ) EB A9 FF FF }
	condition:
		$pattern
}

rule wmemcmp_96f2e7fa65c0eb63ba4f583da235b35d {
	meta:
		aliases = "wmemcmp"
		type = "func"
		size = "33"
		objfiles = "wmemcmp@libc.a"
	strings:
		$pattern = { ( CC | EB ) 0B 48 83 C7 04 48 83 C6 04 48 FF CA 48 85 D2 75 03 31 C0 C3 8B 07 3B 06 74 E7 19 C0 83 C8 01 C3 }
	condition:
		$pattern
}

rule rawmemchr_b4ed49151941069ba118aa175498e7d9 {
	meta:
		aliases = "__GI_rawmemchr, rawmemchr"
		type = "func"
		size = "189"
		objfiles = "rawmemchr@libc.a"
	strings:
		$pattern = { ( CC | EB ) 0C 40 38 37 75 04 48 89 F8 C3 48 FF C7 40 F6 C7 07 75 EE 40 0F B6 C6 48 89 F9 49 B9 FF FE FE FE FE FE FE 7E 89 C2 49 B8 00 01 01 01 01 01 01 81 C1 E2 08 09 C2 48 63 D2 48 89 D0 48 C1 E0 10 48 09 D0 48 89 C7 48 C1 E7 20 48 09 C7 48 89 FA 48 33 11 48 83 C1 08 48 89 D0 4C 01 CA 48 F7 D0 48 31 D0 49 85 C0 74 E5 40 38 71 F8 48 8D 41 F8 74 4A 40 38 71 F9 48 8D 50 01 74 32 40 38 71 FA 48 8D 50 02 74 28 40 38 71 FB 48 8D 50 03 74 1E 40 38 71 FC 48 8D 50 04 74 14 40 38 71 FD 48 8D 50 05 74 0A 40 38 71 FE 48 8D 50 06 75 04 48 89 D0 C3 48 83 C0 07 40 38 71 FF 75 91 C3 }
	condition:
		$pattern
}

rule wmemchr_bcf29108158559da106fd6988a9da38c {
	meta:
		aliases = "__GI_wmemchr, wmemchr"
		type = "func"
		size = "25"
		objfiles = "wmemchr@libc.a"
	strings:
		$pattern = { ( CC | EB ) 0F 39 37 75 04 48 89 F8 C3 48 83 C7 04 48 FF CA 48 85 D2 75 EC 31 C0 C3 }
	condition:
		$pattern
}

rule wmempcpy_1c22bd8efcce147d639d2c8c46605ea5 {
	meta:
		aliases = "__GI_wmempcpy, wmempcpy"
		type = "func"
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
		type = "func"
		size = "35"
		objfiles = "getnetent@libc.a"
	strings:
		$pattern = { ( CC | EB ) 10 38 CA 74 19 48 FF C0 8A 10 84 D2 75 F3 48 FF C7 8A 0F 84 C9 74 05 48 89 F0 EB EC 31 FF 48 89 F8 C3 }
	condition:
		$pattern
}

rule wcsncmp_7eeac8cba4f923b297057c61aa3588b1 {
	meta:
		aliases = "wcsncmp"
		type = "func"
		size = "35"
		objfiles = "wcsncmp@libc.a"
	strings:
		$pattern = { ( CC | EB ) 10 83 3F 00 74 10 48 83 C7 04 48 83 C6 04 48 FF CA 48 85 D2 75 03 31 C0 C3 8B 07 3B 06 74 E2 2B 06 C3 }
	condition:
		$pattern
}

rule wcscoll_4f7f0460fd51d3641619f1a13ffb5a88 {
	meta:
		aliases = "__GI_wcscmp, __GI_wcscoll, wcscmp, wcscoll"
		type = "func"
		size = "30"
		objfiles = "wcscmp@libc.a"
	strings:
		$pattern = { ( CC | EB ) 10 83 3F 00 75 03 31 C0 C3 48 83 C7 04 48 83 C6 04 8B 06 39 07 74 EA 19 C0 83 C8 01 C3 }
	condition:
		$pattern
}

rule strchrnul_3001fb4f11b6c04a49b985b728539567 {
	meta:
		aliases = "__GI_strchrnul, strchrnul"
		type = "func"
		size = "268"
		objfiles = "strchrnul@libc.a"
	strings:
		$pattern = { ( CC | EB ) 12 8A 07 40 38 F0 74 04 84 C0 75 04 48 89 F8 C3 48 FF C7 40 F6 C7 07 75 E8 40 0F B6 C6 49 BA FF FE FE FE FE FE FE 7E 49 B9 00 01 01 01 01 01 01 81 89 C2 C1 E2 08 09 C2 48 63 D2 48 89 D0 48 C1 E0 10 48 09 D0 49 89 C0 49 C1 E0 20 49 09 C0 48 8B 0F 48 83 C7 08 48 89 C8 4A 8D 14 11 48 F7 D0 48 31 D0 49 85 C1 75 17 48 89 C8 4C 31 C0 48 89 C2 4C 01 D0 48 F7 D2 48 31 C2 49 85 D1 74 D0 8A 57 F8 48 8D 47 F8 40 38 F2 74 7F 84 D2 74 7B 8A 57 F9 48 8D 48 01 40 38 F2 74 54 84 D2 74 50 8A 57 FA 48 8D 48 02 40 38 F2 74 44 84 D2 74 40 8A 57 FB 48 8D 48 03 40 38 F2 74 34 84 D2 74 30 8A 57 FC 48 8D 48 04 40 }
	condition:
		$pattern
}

rule __md5_to64_1df521c4850fd18843d78715ce926229 {
	meta:
		aliases = "__md5_to64"
		type = "func"
		size = "28"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | EB ) 15 48 89 F0 48 C1 EE 06 83 E0 3F 8A 80 ?? ?? ?? ?? 88 07 48 FF C7 FF CA 79 E7 C3 }
	condition:
		$pattern
}

rule wcspbrk_7b77017bcde1479df230e33a4d7216fe {
	meta:
		aliases = "__GI_wcspbrk, wcspbrk"
		type = "func"
		size = "38"
		objfiles = "wcspbrk@libc.a"
	strings:
		$pattern = { ( CC | EB ) 16 39 CA 75 04 48 89 F8 C3 48 83 C0 04 8B 10 85 D2 75 EE 48 83 C7 04 8B 0F 85 C9 74 05 48 89 F0 EB EB 31 C0 C3 }
	condition:
		$pattern
}

rule remove_from_queue_48b51e17db8aeec28dd826c0f7789e92 {
	meta:
		aliases = "remove_from_queue"
		type = "func"
		size = "43"
		objfiles = "condvar@libpthread.a, semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | EB ) 1E 48 39 F2 75 15 48 8B 42 10 48 89 07 B8 01 00 00 00 48 C7 42 10 00 00 00 00 C3 48 8D 7A 10 48 8B 17 48 85 D2 75 DA 31 C0 C3 }
	condition:
		$pattern
}

rule mq_timedsend_b50344ae560ff72de39704d716de0100 {
	meta:
		aliases = "mq_timedsend"
		type = "func"
		size = "2"
		objfiles = "mq_send@librt.a"
	strings:
		$pattern = { ( CC | EB ) CE }
	condition:
		$pattern
}

rule __fixunsdfdi_d1094b37570a00432627fb7717156dd4 {
	meta:
		aliases = "__fixunsdfdi"
		type = "func"
		size = "44"
		objfiles = "_fixunsdfsi@libgcc.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 10 0D ?? ?? ?? ?? 66 0F 2E C1 72 18 F2 0F 5C C1 48 B8 00 00 00 00 00 00 00 80 F2 48 0F 2C D0 48 8D 04 02 C3 F2 48 0F 2C C0 C3 }
	condition:
		$pattern
}

rule llrint_b335e2361c189ae8088494b66902a1e9 {
	meta:
		aliases = "__GI_llrint, llrint"
		type = "func"
		size = "328"
		objfiles = "s_llrint@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 E0 48 8B 44 24 E0 0F 28 D0 48 89 C6 48 C1 EE 20 89 F1 41 89 F0 C1 E9 14 41 C1 E8 1F 81 E1 FF 07 00 00 8D 91 01 FC FF FF 83 FA 13 7F 5C 49 63 C0 31 F6 F2 0F 10 0C C5 ?? ?? ?? ?? F2 0F 58 D1 F2 0F 11 54 24 F8 F2 0F 10 44 24 F8 F2 0F 5C C1 66 48 0F 7E C2 48 C1 EA 20 89 D0 C1 E8 14 25 FF 07 00 00 2D FF 03 00 00 0F 88 C5 00 00 00 81 E2 FF FF 0F 00 B9 14 00 00 00 81 CA 00 00 10 00 29 C1 D3 EA 89 D6 E9 A9 00 00 00 83 FA 3E 0F 8F 99 00 00 00 83 FA 33 7E 21 81 E6 FF FF 0F 00 89 C0 81 E9 33 04 00 00 48 81 CE 00 00 10 00 48 C1 E6 20 48 09 C6 48 D3 E6 EB 7A 49 63 C0 F2 0F 10 04 C5 ?? ?? ?? }
	condition:
		$pattern
}

rule lrint_c7e21148ec75ae3bfbf689ed590c08e4 {
	meta:
		aliases = "__GI_lrint, lrint"
		type = "func"
		size = "318"
		objfiles = "s_lrint@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 E0 48 8B 44 24 E0 0F 28 D0 48 89 C7 48 C1 EF 20 89 FE 41 89 F8 C1 EE 14 41 C1 E8 1F 81 E6 FF 07 00 00 8D 8E 01 FC FF FF 83 F9 13 7F 59 31 D2 FF C1 0F 8C FE 00 00 00 49 63 C0 B9 13 04 00 00 F2 0F 10 0C C5 ?? ?? ?? ?? F2 0F 58 D1 F2 0F 11 54 24 F8 F2 0F 10 44 24 F8 F2 0F 5C C1 66 48 0F 7E C0 48 C1 E8 20 89 C2 C1 E8 14 81 E2 FF FF 0F 00 25 FF 07 00 00 81 CA 00 00 10 00 29 C1 D3 EA 89 D2 E9 A2 00 00 00 83 F9 3E 0F 8F 92 00 00 00 83 F9 33 7E 1A 89 C2 8D 8E CD FB FF FF 48 89 F8 25 FF FF 0F 00 D3 E2 48 0D 00 00 10 00 EB 65 49 63 C0 F2 0F 10 04 C5 ?? ?? ?? ?? F2 0F 58 D0 F2 0F 11 54 24 }
	condition:
		$pattern
}

rule rint_468b3e3ff630538b23d4ba47c8827a63 {
	meta:
		aliases = "__GI_rint, rint"
		type = "func"
		size = "373"
		objfiles = "s_rint@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 0F 28 C8 48 89 C7 89 C6 48 C1 EF 20 89 F8 41 89 F8 C1 F8 14 41 C1 E8 1F 25 FF 07 00 00 8D 88 01 FC FF FF 83 F9 13 0F 8F DA 00 00 00 85 C9 0F 89 9A 00 00 00 89 F8 25 FF FF FF 7F 09 F0 0F 84 23 01 00 00 89 FA 48 8B 4C 24 F8 81 E7 00 00 FE FF 81 E2 FF FF 0F 00 09 F2 89 D0 83 E1 FF F7 D8 09 D0 C1 E8 0C 25 00 00 08 00 09 F8 48 C1 E0 20 48 09 C1 49 63 C0 41 C1 E0 1F 48 89 4C 24 F8 F2 0F 10 0C C5 ?? ?? ?? ?? F2 0F 10 44 24 F8 F2 0F 58 C1 F2 0F 5C C1 F2 0F 11 44 24 F8 48 8B 44 24 F8 48 8B 54 24 F8 48 C1 E8 20 83 E2 FF 25 FF FF FF 7F 44 09 C0 48 C1 E0 20 48 09 C2 48 89 }
	condition:
		$pattern
}

rule log1p_c4505868dd243171273752870ca3d1e9 {
	meta:
		aliases = "__GI_log1p, log1p"
		type = "func"
		size = "790"
		objfiles = "s_log1p@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 0F 28 D0 48 89 C2 48 C1 EA 20 81 FA 79 82 DA 3F 0F 8F 9A 00 00 00 89 D0 25 FF FF FF 7F 3D FF FF EF 3F 7E 2E 66 0F 2E 15 ?? ?? ?? ?? 75 17 7A 15 F2 0F 10 15 ?? ?? ?? ?? F2 0F 5E 15 ?? ?? ?? ?? E9 C2 02 00 00 F2 0F 5C D2 F2 0F 5E D2 E9 B5 02 00 00 3D FF FF 1F 3E 7F 38 0F 28 C2 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 76 0B 3D FF FF 8F 3C 0F 8E 8E 02 00 00 0F 28 C2 F2 0F 59 C2 F2 0F 59 05 ?? ?? ?? ?? F2 0F 58 D0 E9 76 02 00 00 8D 82 3C 41 2D 40 3D 3C 41 2D 40 76 23 0F 57 F6 B9 01 00 00 00 0F 28 EA 31 F6 E9 0C 01 00 00 81 FA FF FF EF 7F 7E 09 F2 0F 58 D2 E9 }
	condition:
		$pattern
}

rule __ieee754_exp_5194ccdafc2fac626c106eeee449e470 {
	meta:
		aliases = "__ieee754_exp"
		type = "func"
		size = "565"
		objfiles = "e_exp@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 0F 28 D0 48 89 C2 48 C1 EA 20 89 D0 89 D1 25 FF FF FF 7F C1 E9 1F 3D 41 2E 86 40 76 58 3D FF FF EF 7F 76 22 48 8B 44 24 F8 81 E2 FF FF 0F 00 09 C2 74 09 F2 0F 58 D2 E9 EA 01 00 00 85 C9 0F 84 E2 01 00 00 EB 27 66 0F 2E 15 ?? ?? ?? ?? 76 11 F2 0F 10 15 ?? ?? ?? ?? F2 0F 59 D2 E9 C5 01 00 00 66 0F 2E 15 ?? ?? ?? ?? 73 3B 7A 39 0F 57 D2 E9 B1 01 00 00 3D 42 2E D6 3F 76 6F 3D B1 A2 F0 3F 77 23 0F 28 EA 48 63 C1 F2 0F 10 24 C5 ?? ?? ?? ?? F2 0F 5C 2C C5 ?? ?? ?? ?? 89 C8 F7 D8 29 C8 8D 48 01 EB 3C 0F 28 C2 48 63 C1 0F 28 EA F2 0F 59 05 ?? ?? ?? ?? F2 0F 58 04 C5 ?? }
	condition:
		$pattern
}

rule expm1_2a1489a62abc98a65b78e1c9e7adb3d0 {
	meta:
		aliases = "__GI_expm1, expm1"
		type = "func"
		size = "818"
		objfiles = "s_expm1@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 0F 28 D8 48 89 C2 48 C1 EA 20 89 D0 89 D1 25 FF FF FF 7F 81 E1 00 00 00 80 3D 79 68 43 40 76 73 3D 41 2E 86 40 76 44 3D FF FF EF 7F 76 22 48 8B 44 24 F8 81 E2 FF FF 0F 00 09 C2 74 09 F2 0F 58 DB E9 DD 02 00 00 85 C9 0F 84 D5 02 00 00 EB 36 66 0F 2E 1D ?? ?? ?? ?? 76 11 F2 0F 10 1D ?? ?? ?? ?? F2 0F 59 DB E9 B8 02 00 00 85 C9 74 6D 0F 28 C3 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 73 54 7A 52 F2 0F 10 1D ?? ?? ?? ?? E9 90 02 00 00 3D 42 2E D6 3F 0F 86 92 00 00 00 3D B1 A2 F0 3F 77 33 85 C9 F2 0F 10 05 ?? ?? ?? ?? 75 13 0F 28 CB B1 01 F2 0F 5C C8 F2 0F 10 }
	condition:
		$pattern
}

rule qzero_1365bafe3c7502c479384011c5737762 {
	meta:
		aliases = "qone, qzero"
		type = "func"
		size = "258"
		objfiles = "e_j1@libm.a, e_j0@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 0F 28 E0 48 C1 E8 20 89 C1 81 E1 FF FF FF 7F 81 F9 FF FF 1F 40 7E 0C BE ?? ?? ?? ?? B8 ?? ?? ?? ?? EB 45 81 F9 8A 2E 12 40 7E 0C BE ?? ?? ?? ?? B8 ?? ?? ?? ?? EB 31 81 F9 6C DB 06 40 7E 0C BE ?? ?? ?? ?? B8 ?? ?? ?? ?? EB 1D 31 C0 BA ?? ?? ?? ?? 81 F9 00 00 00 40 48 89 C6 48 0F 4D F2 BA ?? ?? ?? ?? 48 0F 4D C2 0F 28 C4 F2 0F 10 1D ?? ?? ?? ?? F2 0F 59 C4 0F 28 D3 F2 0F 5E D0 0F 28 CA 0F 28 C2 F2 0F 59 48 28 F2 0F 59 46 28 F2 0F 58 48 20 F2 0F 58 46 20 F2 0F 59 CA F2 0F 59 C2 F2 0F 58 48 18 F2 0F 58 46 18 F2 0F 59 CA F2 0F 59 C2 F2 0F 58 48 10 F2 0F 58 46 10 F2 }
	condition:
		$pattern
}

rule __kernel_cos_0d1ac010ac4270d4b3e390f162be1b0f {
	meta:
		aliases = "__kernel_cos"
		type = "func"
		size = "271"
		objfiles = "k_cos@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 0F 28 E0 48 C1 E8 20 89 C2 81 E2 FF FF FF 7F 81 FA FF FF 3F 3E 7F 15 F2 0F 2C C4 85 C0 75 0D F2 0F 10 35 ?? ?? ?? ?? E9 D4 00 00 00 0F 28 DC 81 FA 32 33 D3 3F F2 0F 59 DC 0F 28 D3 F2 0F 59 15 ?? ?? ?? ?? F2 0F 58 15 ?? ?? ?? ?? F2 0F 59 D3 F2 0F 5C 15 ?? ?? ?? ?? F2 0F 59 D3 F2 0F 58 15 ?? ?? ?? ?? F2 0F 59 D3 F2 0F 5C 15 ?? ?? ?? ?? F2 0F 59 D3 F2 0F 58 15 ?? ?? ?? ?? F2 0F 59 D3 7F 25 0F 28 C3 F2 0F 59 E1 F2 0F 59 DA F2 0F 59 05 ?? ?? ?? ?? F2 0F 10 35 ?? ?? ?? ?? F2 0F 5C DC F2 0F 5C C3 EB 55 81 FA 00 00 E9 3F 7E 0A F2 0F 10 2D ?? ?? ?? ?? EB 18 8D 82 00 00 }
	condition:
		$pattern
}

rule __kernel_sin_da30b2fe3a9188da263a60015c41d4db {
	meta:
		aliases = "__kernel_sin"
		type = "func"
		size = "184"
		objfiles = "k_sin@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 0F 28 E8 48 C1 E8 20 25 FF FF FF 7F 3D FF FF 3F 3E 7F 0C F2 0F 2C C5 85 C0 0F 84 8A 00 00 00 0F 28 DD 85 FF F2 0F 10 35 ?? ?? ?? ?? F2 0F 59 DD 0F 28 D3 0F 28 E3 F2 0F 59 15 ?? ?? ?? ?? F2 0F 59 E5 F2 0F 5C 15 ?? ?? ?? ?? F2 0F 59 D3 F2 0F 58 15 ?? ?? ?? ?? F2 0F 59 D3 F2 0F 5C 15 ?? ?? ?? ?? F2 0F 59 D3 F2 0F 58 15 ?? ?? ?? ?? 75 12 F2 0F 59 DA F2 0F 5C DE F2 0F 59 E3 F2 0F 58 EC EB 27 0F 28 C1 F2 0F 59 D4 F2 0F 59 E6 F2 0F 59 05 ?? ?? ?? ?? F2 0F 5C C2 F2 0F 59 D8 F2 0F 5C D9 F2 0F 58 DC F2 0F 5C EB 0F 28 C5 C3 }
	condition:
		$pattern
}

rule __ieee754_log_c61b5860320698f7a6a064e06b5d4cfb {
	meta:
		aliases = "__ieee754_log"
		type = "func"
		size = "635"
		objfiles = "e_log@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 45 31 C0 48 89 C6 89 C2 48 C1 EE 20 81 FE FF FF 0F 00 7F 4D 89 F0 25 FF FF FF 7F 09 D0 75 0A F2 0F 10 15 ?? ?? ?? ?? EB 0B 85 F6 79 14 0F 28 D0 F2 0F 5C D0 F2 0F 5E 15 ?? ?? ?? ?? E9 2B 02 00 00 F2 0F 59 05 ?? ?? ?? ?? 41 B8 CA FF FF FF F2 0F 11 44 24 F8 48 8B 44 24 F8 48 89 C6 48 C1 EE 20 81 FE FF FF EF 7F 0F 28 D0 0F 8F 94 00 00 00 89 F7 F2 0F 11 44 24 F8 48 8B 4C 24 F8 81 E7 FF FF 0F 00 C1 FE 14 8D 97 64 5F 09 00 83 E1 FF 81 E2 00 00 10 00 89 D0 C1 FA 14 35 00 00 F0 3F 09 F8 48 C1 E0 20 48 09 C1 41 8D 84 30 01 FC FF FF 48 89 4C 24 F8 8D 34 10 8D 47 02 F2 0F }
	condition:
		$pattern
}

rule __ieee754_log2_bccc46d79bf3a479535799ac9d64e533 {
	meta:
		aliases = "__ieee754_log2"
		type = "func"
		size = "506"
		objfiles = "e_log2@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 45 31 C0 48 89 C6 89 C2 48 C1 EE 20 81 FE FF FF 0F 00 7F 54 89 F0 25 FF FF FF 7F 09 D0 75 15 F2 0F 5C C0 F2 0F 10 2D ?? ?? ?? ?? F2 0F 5E E8 E9 B7 01 00 00 85 F6 79 10 0F 28 E8 F2 0F 5C E8 F2 0F 5E ED E9 A3 01 00 00 F2 0F 59 05 ?? ?? ?? ?? 41 B8 CA FF FF FF F2 0F 11 44 24 F8 48 8B 44 24 F8 48 89 C6 48 C1 EE 20 81 FE FF FF EF 7F 0F 28 E8 0F 8F 57 01 00 00 89 F7 F2 0F 11 44 24 F8 48 8B 4C 24 F8 81 E7 FF FF 0F 00 C1 FE 14 8D 97 64 5F 09 00 83 E1 FF 81 E2 00 00 10 00 89 D0 C1 FA 14 35 00 00 F0 3F 09 F8 48 C1 E0 20 48 09 C1 41 8D 84 30 01 FC FF FF 48 89 4C 24 F8 01 }
	condition:
		$pattern
}

rule __isinf_ed8787e60aec716c44e0b1f25f062ab1 {
	meta:
		aliases = "__GI___isinf, __isinf"
		type = "func"
		size = "51"
		objfiles = "s_isinf@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 48 89 C1 48 C1 E9 20 89 CA C1 F9 1E 81 E2 FF FF FF 7F 81 F2 00 00 F0 7F 09 C2 89 D0 F7 D8 09 D0 C1 F8 1F F7 D0 21 C8 C3 }
	condition:
		$pattern
}

rule lround_97eb4bb6a36c12387ea8ce7a5ee35597 {
	meta:
		aliases = "__GI_lround, lround"
		type = "func"
		size = "209"
		objfiles = "s_lround@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 48 89 C2 41 89 C1 48 C1 EA 20 41 89 D0 41 89 D2 89 D7 41 C1 E8 14 41 C1 FA 1F 81 E7 FF FF 0F 00 41 81 E0 FF 07 00 00 41 83 CA 01 81 CF 00 00 10 00 41 8D B0 01 FC FF FF 83 FE 13 7F 27 85 F6 79 0A 31 C0 FF C6 75 7E 49 63 C2 C3 40 88 F1 B8 00 00 08 00 D3 F8 B9 14 00 00 00 01 F8 29 F1 D3 E8 89 C2 EB 5A 83 FE 3E 7F 4F 83 FE 33 7E 19 41 8D 88 CD FB FF FF 89 C2 89 F8 D3 E2 41 8D 88 ED FB FF FF 48 D3 E0 EB 2C 41 8D 88 ED FB FF FF B8 00 00 00 80 D3 E8 44 01 C8 44 39 C8 83 D7 00 83 FE 14 89 FA 74 19 48 D3 E2 B9 34 00 00 00 29 F1 D3 E8 89 C0 48 09 C2 EB 06 F2 48 0F 2C C0 }
	condition:
		$pattern
}

rule trunc_d05d2901ebf2edd69502b11b09e6a6e8 {
	meta:
		aliases = "__GI_trunc, trunc"
		type = "func"
		size = "142"
		objfiles = "s_trunc@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 48 89 C2 89 C6 48 C1 EA 20 89 D0 C1 F8 14 25 FF 07 00 00 8D 88 01 FC FF FF 83 F9 13 7F 2E 89 D6 81 E6 00 00 00 80 85 C9 89 F0 78 0D B8 FF FF 0F 00 D3 F8 F7 D0 21 D0 09 F0 48 C1 E0 20 48 89 44 24 F8 F2 0F 10 4C 24 F8 0F 28 C1 C3 83 F9 33 7E 0D 81 F9 00 04 00 00 75 29 F2 0F 58 C0 C3 8D 88 ED FB FF FF 83 C8 FF 48 C1 E2 20 D3 E8 F7 D0 21 F0 48 09 C2 48 89 54 24 F8 F2 0F 10 4C 24 F8 0F 28 C1 C3 }
	condition:
		$pattern
}

rule llround_100b59bba63db1a60852083a944e19d5 {
	meta:
		aliases = "__GI_llround, llround"
		type = "func"
		size = "194"
		objfiles = "s_llround@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 48 89 C2 89 C7 48 C1 EA 20 89 D1 41 89 D0 81 E2 FF FF 0F 00 C1 E9 14 41 C1 F8 1F 81 CA 00 00 10 00 81 E1 FF 07 00 00 41 83 C8 01 8D B1 01 FC FF FF 83 FE 13 7F 27 85 F6 79 0A 31 C0 FF C6 75 76 49 63 C0 C3 40 88 F1 B8 00 00 08 00 D3 F8 B9 14 00 00 00 01 D0 29 F1 D3 E8 89 C2 EB 52 83 FE 3E 7F 47 83 FE 33 7E 14 48 C1 E2 20 89 C0 81 E9 33 04 00 00 48 09 C2 48 D3 E2 EB 34 81 E9 13 04 00 00 B8 00 00 00 80 D3 E8 01 F8 39 F8 83 D2 00 83 FE 14 89 D2 74 19 48 D3 E2 B9 34 00 00 00 29 F1 D3 E8 89 C0 48 09 C2 EB 06 F2 48 0F 2C C0 C3 49 63 C0 48 0F AF C2 C3 }
	condition:
		$pattern
}

rule modf_97f0978505eb700fa7897ee2035ca1fd {
	meta:
		aliases = "__GI_modf, modf"
		type = "func"
		size = "209"
		objfiles = "s_modf@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 48 89 C6 41 89 C0 48 C1 EE 20 89 F0 C1 F8 14 25 FF 07 00 00 8D 88 01 FC FF FF 83 F9 13 7F 41 85 C9 79 10 81 E6 00 00 00 80 89 F0 48 C1 E0 20 48 89 07 C3 BA FF FF 0F 00 D3 FA 89 D0 21 F0 44 09 C0 74 32 89 D0 F7 D0 21 F0 48 C1 E0 20 48 89 44 24 F8 48 89 07 F2 0F 10 4C 24 F8 F2 0F 5C C1 C3 83 F9 33 7F 10 8D 88 ED FB FF FF 83 C8 FF D3 E8 41 85 C0 75 2D F2 0F 11 44 24 F8 48 8B 44 24 F8 F2 0F 11 07 48 C1 E8 20 25 00 00 00 80 89 C0 48 C1 E0 20 48 89 44 24 F8 F2 0F 10 4C 24 F8 0F 28 C1 C3 89 C2 48 89 F0 F7 D2 48 C1 E0 20 44 21 C2 48 09 D0 48 89 44 24 F8 48 89 07 F2 0F }
	condition:
		$pattern
}

rule floor_1dc884331863dca47a8245b3fe00c87c {
	meta:
		aliases = "__GI_floor, floor"
		type = "func"
		size = "299"
		objfiles = "s_floor@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 48 89 C6 41 89 C1 89 C2 48 C1 EE 20 89 F0 C1 F8 14 25 FF 07 00 00 8D B8 01 FC FF FF 83 FF 13 0F 8F 80 00 00 00 85 FF 79 3A F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 0F 86 C6 00 00 00 85 F6 78 04 31 F6 EB 15 89 F0 25 FF FF FF 7F 44 09 C8 0F 84 AE 00 00 00 BE 00 00 F0 BF 31 D2 E9 A2 00 00 00 41 B8 FF FF 0F 00 40 88 F9 41 D3 F8 44 89 C0 21 F0 44 09 C8 0F 84 A2 00 00 00 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 76 76 85 F6 79 09 B8 00 00 10 00 D3 F8 01 C6 44 89 C0 F7 D0 21 C6 EB B7 83 FF 33 7E 0D 81 FF 00 04 00 00 75 6D F2 0F 58 C0 C3 8D 88 ED FB FF FF }
	condition:
		$pattern
}

rule ceil_a20348c4daa6850d8fd355250984902a {
	meta:
		aliases = "__GI_ceil, ceil"
		type = "func"
		size = "293"
		objfiles = "s_ceil@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 48 89 C6 41 89 C1 89 C2 48 C1 EE 20 89 F0 C1 F8 14 25 FF 07 00 00 8D B8 01 FC FF FF 83 FF 13 7F 7E 85 FF 79 38 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 0F 86 C4 00 00 00 85 F6 79 07 BE 00 00 00 80 EB 10 44 89 C8 09 F0 0F 84 AE 00 00 00 BE 00 00 F0 3F 31 D2 E9 A2 00 00 00 41 B8 FF FF 0F 00 40 88 F9 41 D3 F8 44 89 C0 21 F0 44 09 C8 0F 84 A2 00 00 00 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 76 76 85 F6 7E 09 B8 00 00 10 00 D3 F8 01 C6 44 89 C0 F7 D0 21 C6 EB B7 83 FF 33 7E 0D 81 FF 00 04 00 00 75 6D F2 0F 58 C0 C3 8D 88 ED FB FF FF 41 83 C8 FF 41 D3 }
	condition:
		$pattern
}

rule round_204031e1879693a7d1410edaff49f54e {
	meta:
		aliases = "__GI_round, round"
		type = "func"
		size = "269"
		objfiles = "s_round@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 48 89 C7 89 C2 48 C1 EF 20 89 F8 C1 F8 14 25 FF 07 00 00 8D B0 01 FC FF FF 83 FE 13 7F 75 85 F6 79 31 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 0F 86 AF 00 00 00 81 E7 00 00 00 80 31 D2 FF C6 0F 85 9F 00 00 00 81 CF 00 00 F0 3F E9 94 00 00 00 41 B8 FF FF 0F 00 40 88 F1 41 D3 F8 44 89 C0 21 F8 09 D0 0F 84 95 00 00 00 F2 0F 58 05 ?? ?? ?? ?? 66 0F 2E 05 ?? ?? ?? ?? 76 69 B8 00 00 08 00 44 89 C2 D3 F8 F7 D2 8D 3C 38 21 D7 31 D2 EB 54 83 FE 33 7E 0D 81 FE 00 04 00 00 75 61 F2 0F 58 C0 C3 8D 88 ED FB FF FF 41 83 C8 FF 41 D3 E8 44 85 C2 74 4A F2 0F 58 05 ?? ?? }
	condition:
		$pattern
}

rule pzero_d28a4ef8eab476777d3466c5338b382d {
	meta:
		aliases = "pone, pzero"
		type = "func"
		size = "235"
		objfiles = "e_j1@libm.a, e_j0@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 48 C1 E8 20 89 C1 81 E1 FF FF FF 7F 81 F9 FF FF 1F 40 7E 0C BE ?? ?? ?? ?? B8 ?? ?? ?? ?? EB 45 81 F9 8A 2E 12 40 7E 0C BE ?? ?? ?? ?? B8 ?? ?? ?? ?? EB 31 81 F9 6C DB 06 40 7E 0C BE ?? ?? ?? ?? B8 ?? ?? ?? ?? EB 1D 31 C0 BA ?? ?? ?? ?? 81 F9 00 00 00 40 48 89 C6 48 0F 4D F2 BA ?? ?? ?? ?? 48 0F 4D C2 F2 0F 10 1D ?? ?? ?? ?? F2 0F 59 C0 0F 28 D3 F2 0F 5E D0 0F 28 C2 0F 28 CA F2 0F 59 46 28 F2 0F 59 48 20 F2 0F 58 46 20 F2 0F 58 48 18 F2 0F 59 C2 F2 0F 59 CA F2 0F 58 46 18 F2 0F 58 48 10 F2 0F 59 C2 F2 0F 59 CA F2 0F 58 46 10 F2 0F 58 48 08 F2 0F 59 C2 F2 0F 59 }
	condition:
		$pattern
}

rule __isnan_b4b20b3934886b49895f68002e4f1d39 {
	meta:
		aliases = "__GI___isnan, __isnan"
		type = "func"
		size = "46"
		objfiles = "s_isnan@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 89 C2 48 89 C1 F7 DA 48 C1 E9 20 09 C2 81 E1 FF FF FF 7F B8 00 00 F0 7F C1 EA 1F 09 CA 29 D0 C1 E8 1F C3 }
	condition:
		$pattern
}

rule frexp_17c87361eea287d7734160407e73a583 {
	meta:
		aliases = "__GI_frexp, frexp"
		type = "func"
		size = "156"
		objfiles = "s_frexp@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 C7 07 00 00 00 00 48 89 C1 48 C1 E9 20 89 CA 81 E2 FF FF FF 7F 81 FA FF FF EF 7F 7F 73 09 D0 74 6F 81 FA FF FF 0F 00 7F 28 F2 0F 59 05 ?? ?? ?? ?? C7 07 CA FF FF FF F2 0F 11 44 24 F8 48 8B 44 24 F8 48 89 C1 48 C1 E9 20 89 CA 81 E2 FF FF FF 7F 8B 07 C1 FA 14 F2 0F 11 44 24 F8 2D FE 03 00 00 01 D0 48 8B 54 24 F8 89 07 48 89 C8 25 FF FF 0F 80 48 0D 00 00 E0 3F 83 E2 FF 48 C1 E0 20 48 09 C2 48 89 54 24 F8 F2 0F 10 4C 24 F8 0F 28 C1 C3 }
	condition:
		$pattern
}

rule nextafter_5a7eff2bca725d71400b9c07196ec035 {
	meta:
		aliases = "__GI_nextafter, nextafter"
		type = "func"
		size = "280"
		objfiles = "s_nextafter@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 44 24 F8 F2 0F 11 4C 24 F8 0F 28 D0 48 89 C1 89 C2 48 8B 44 24 F8 48 C1 E9 20 89 CF 48 89 C6 81 E7 FF FF FF 7F 41 89 C1 48 C1 EE 20 81 FF FF FF EF 7F 41 89 F0 7E 0A 8D 87 00 00 10 80 09 D0 75 18 89 F0 25 FF FF FF 7F 3D FF FF EF 7F 7E 13 2D 00 00 F0 7F 44 09 C8 74 09 F2 0F 58 D1 E9 AA 00 00 00 66 0F 2E D1 7A 06 0F 84 9E 00 00 00 09 D7 75 2E 41 81 E0 00 00 00 80 44 89 C0 48 C1 E0 20 48 83 C8 01 48 89 44 24 F8 F2 0F 10 44 24 F8 0F 28 D0 F2 0F 59 C0 66 0F 2E C2 75 70 7A 6E EB 69 85 C9 78 15 39 F1 7F 20 75 05 44 39 CA 77 19 89 D0 FF C0 75 27 FF C1 EB 23 85 F6 79 0B 39 F1 7F }
	condition:
		$pattern
}

rule fabs_42c3443df36e0d36fcd0b4e41d769b1b {
	meta:
		aliases = "__GI_fabs, fabs"
		type = "func"
		size = "48"
		objfiles = "s_fabs@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 4C 24 F8 48 BA 00 00 00 00 FF FF FF 7F 48 89 C8 48 21 D1 83 E0 FF 48 09 C8 48 89 44 24 F8 F2 0F 10 4C 24 F8 0F 28 C1 C3 }
	condition:
		$pattern
}

rule copysign_41d451cd1947a8dc3e797eb2f127fe3f {
	meta:
		aliases = "__GI_copysign, copysign"
		type = "func"
		size = "67"
		objfiles = "s_copysign@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 11 44 24 F8 48 8B 54 24 F8 66 48 0F 7E C8 48 8B 4C 24 F8 48 C1 E8 20 48 C1 EA 20 25 00 00 00 80 81 E2 FF FF FF 7F 83 E1 FF 09 D0 48 C1 E0 20 48 09 C1 48 89 4C 24 F8 F2 0F 10 4C 24 F8 0F 28 C1 C3 }
	condition:
		$pattern
}

rule fma_ad65862bb33b73984fa0adc080d6dff4 {
	meta:
		aliases = "__GI_fma, fma"
		type = "func"
		size = "9"
		objfiles = "s_fma@libm.a"
	strings:
		$pattern = { ( CC | F2 ) 0F 59 C1 F2 0F 58 C2 C3 }
	condition:
		$pattern
}

rule __divdc3_e8d406568a1fce1ae7c865a688d50ce2 {
	meta:
		aliases = "__divdc3"
		type = "func"
		size = "880"
		objfiles = "_divdc3@libgcc.a"
	strings:
		$pattern = { ( CC | F2 ) 44 0F 10 05 ?? ?? ?? ?? 66 0F 28 F0 66 0F 28 F9 66 0F 28 C3 66 0F 28 CA 66 0F 28 EA 66 41 0F 54 C0 66 41 0F 54 C8 66 0F 2E C1 76 45 66 0F 28 CA 66 0F 28 C2 66 0F 28 E6 F2 0F 5E CB 66 0F 28 D7 F2 0F 59 C1 F2 0F 59 E1 F2 0F 59 D1 F2 0F 58 C3 F2 0F 58 E7 F2 0F 5C D6 F2 0F 5E E0 F2 0F 5E D0 66 0F 2E E4 7A 41 75 3F 66 0F 28 CA 66 0F 28 C4 C3 66 0F 28 C3 66 0F 28 CB 66 0F 28 E7 F2 0F 5E C2 F2 0F 59 C8 F2 0F 59 E0 F2 0F 59 C6 F2 0F 58 CA 66 0F 28 D7 F2 0F 58 E6 F2 0F 5C D0 F2 0F 5E E1 F2 0F 5E D1 EB B9 66 0F 2E D2 7A 02 74 B9 66 45 0F 57 C9 66 41 0F 2E E9 75 11 66 66 66 90 7A 0B 66 41 0F 2E D9 0F }
	condition:
		$pattern
}

rule __isinff_fc1b801f3557aaa0460df9714140dffc {
	meta:
		aliases = "__GI___isinff, __isinff"
		type = "func"
		size = "41"
		objfiles = "s_isinff@libm.a"
	strings:
		$pattern = { ( CC | F3 ) 0F 11 44 24 FC 8B 4C 24 FC 89 CA C1 F9 1E 81 E2 FF FF FF 7F 81 F2 00 00 80 7F 89 D0 F7 D8 09 D0 C1 F8 1F F7 D0 21 C8 C3 }
	condition:
		$pattern
}

rule truncf_76fb52706816ef3df3c8d6c20b0aa675 {
	meta:
		aliases = "acosf, acoshf, asinf, asinhf, atanf, atanhf, cbrtf, ceilf, cosf, coshf, erfcf, erff, expf, expm1f, fabsf, floorf, frexpf, ldexpf, lgammaf, log10f, log1pf, logbf, logf, rintf, roundf, scalblnf, scalbnf, sinf, sinhf, sqrtf, tanf, tanhf, tgammaf, truncf"
		type = "func"
		size = "19"
		objfiles = "rintf@libm.a, lgammaf@libm.a, tanf@libm.a, asinhf@libm.a, cosf@libm.a"
	strings:
		$pattern = { ( CC | F3 ) 0F 5A C0 48 83 EC 08 E8 ?? ?? ?? ?? F2 0F 5A C0 58 C3 }
	condition:
		$pattern
}

rule __fixunssfti_356153a045c1eed8bd3983fe64a12530 {
	meta:
		aliases = "__fixunssfti"
		type = "func"
		size = "168"
		objfiles = "_fixunssfdi@libgcc.a"
	strings:
		$pattern = { ( CC | F3 ) 0F 5A C0 53 F2 0F 10 15 ?? ?? ?? ?? 66 0F 28 C8 F2 0F 59 0D ?? ?? ?? ?? 66 0F 2E CA 73 35 F2 48 0F 2C F1 48 85 F6 78 46 F2 48 0F 2A CE F2 0F 59 0D ?? ?? ?? ?? F2 0F 58 C8 66 0F 2E CA 73 50 F2 48 0F 2C C9 5B 48 89 C8 31 D2 31 C9 48 09 C8 48 09 F2 C3 F2 0F 5C CA 48 B8 00 00 00 00 00 00 00 80 F2 48 0F 2C F1 48 31 C6 48 85 F6 79 BA 48 89 F0 48 89 F2 48 D1 E8 83 E2 01 48 09 D0 F2 48 0F 2A C8 F2 0F 58 C9 EB A5 66 66 66 90 66 66 90 F2 0F 5C CA 48 B8 00 00 00 00 00 00 00 80 F2 48 0F 2C C9 48 31 C1 EB 9D }
	condition:
		$pattern
}

rule lroundf_d3b5b767a0285b8ef7c579a0959a22b2 {
	meta:
		aliases = "ilogbf, llrintf, llroundf, lrintf, lroundf"
		type = "func"
		size = "9"
		objfiles = "lroundf@libm.a, ilogbf@libm.a, llroundf@libm.a, lrintf@libm.a, llrintf@libm.a"
	strings:
		$pattern = { ( CC | F3 ) 0F 5A C0 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule remainderf_b655e1a82b86ef778f64370fab64b292 {
	meta:
		aliases = "atan2f, copysignf, fmodf, hypotf, nextafterf, powf, remainderf"
		type = "func"
		size = "23"
		objfiles = "nextafterf@libm.a, remainderf@libm.a, fmodf@libm.a, atan2f@libm.a, powf@libm.a"
	strings:
		$pattern = { ( CC | F3 ) 0F 5A C9 48 83 EC 08 F3 0F 5A C0 E8 ?? ?? ?? ?? F2 0F 5A C0 58 C3 }
	condition:
		$pattern
}

rule __divsc3_02d6ff932d87a2161ac0863c8a58ee80 {
	meta:
		aliases = "__divsc3"
		type = "func"
		size = "825"
		objfiles = "_divsc3@libgcc.a"
	strings:
		$pattern = { ( CC | F3 ) 44 0F 10 05 ?? ?? ?? ?? 0F 28 F0 0F 28 F9 0F 28 C3 0F 28 CA 0F 28 EA 41 0F 54 C8 41 0F 54 C0 0F 2E C1 76 4B 0F 28 CA 0F 28 C2 0F 28 E6 F3 0F 5E CB 0F 28 D7 F3 0F 59 C1 F3 0F 59 E1 F3 0F 59 D1 F3 0F 58 C3 F3 0F 58 E7 F3 0F 5C D6 F3 0F 5E E0 F3 0F 5E D0 0F 2E E4 7A 48 75 46 F3 0F 11 64 24 F8 F3 0F 11 54 24 FC F3 0F 7E 44 24 F8 C3 90 0F 28 C3 0F 28 CB 0F 28 E7 F3 0F 5E C2 F3 0F 59 C8 F3 0F 59 E0 F3 0F 59 C6 F3 0F 58 CA 0F 28 D7 F3 0F 58 E6 F3 0F 5C D0 F3 0F 5E E1 F3 0F 5E D1 EB B3 0F 2E D2 7A 02 74 B3 45 0F 57 C9 41 0F 2E E9 75 0C 7A 0A 41 0F 2E D9 0F 84 1A 02 00 00 0F 28 C6 31 C9 F3 0F 5C C6 }
	condition:
		$pattern
}

rule pex_unix_cleanup_32a093eff127b3eedaa06c147dc0694b {
	meta:
		aliases = "__clear_cache, __enable_execute_stack, __gcov_flush, __gcov_init, __gcov_merge_add, __gcov_merge_delta, __gcov_merge_single, __gnat_default_lock, __gnat_default_unlock, hex_init, pex_unix_cleanup"
		type = "func"
		size = "2"
		objfiles = "pex_unix@libiberty.a, _gcov_merge_add@libgcov.a, _gcov_merge_single@libgcov.a, _enable_execute_stack@libgcc.a, _clear_cache@libgcc.a"
	strings:
		$pattern = { ( CC | F3 ) C3 }
	condition:
		$pattern
}

