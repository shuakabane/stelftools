// YARA rules, version 0.1.1_2020_04_26

rule __libc_sa_len_159e9a7f09564d24c6e7ab45d2e82f54 {
	meta:
		aliases = "__libc_sa_len"
		size = "50"
		objfiles = "sa_len@libc.a"
	strings:
		$pattern = { ( CC | 0F ) B7 44 24 04 83 F8 02 74 22 7F 05 48 75 14 EB 0C 83 F8 04 74 16 83 F8 0A 75 08 EB 09 B8 6E 00 00 00 C3 31 C0 C3 B8 1C 00 00 00 C3 B8 10 00 00 00 C3 }
	condition:
		$pattern
}

rule _setjmp_86a04ba6e89ace15ef2af6c36c199d43 {
	meta:
		aliases = "_setjmp"
		size = "34"
		objfiles = "bsd__setjmp@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C0 8B 54 24 04 89 1A 89 72 04 89 7A 08 8D 4C 24 04 89 4A 10 8B 0C 24 89 4A 14 89 6A 0C 89 42 18 C3 }
	condition:
		$pattern
}

rule __pthread_return_0_95da5d637ce2b37c162272462d63ab78 {
	meta:
		aliases = "__GI_wcsftime, clntraw_control, grantpt, authnone_refresh, __pthread_mutex_lock, pthread_condattr_init, __GI_pthread_condattr_init, xdrstdio_inline, pthread_rwlockattr_destroy, pthread_mutexattr_destroy, __GI_pthread_attr_destroy, pthread_attr_destroy, __pthread_mutex_trylock, __pthread_mutex_unlock, __pthread_mutexattr_destroy, pthread_condattr_destroy, __GI_pthread_condattr_destroy, __pthread_mutex_init, _svcauth_null, wcsftime, __pthread_return_0"
		size = "3"
		objfiles = "rwlock@libpthread.a, clnt_raw@libc.a, mutex@libpthread.a, xdr_stdio@libc.a, svc_auth@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C0 C3 }
	condition:
		$pattern
}

rule isascii_4753db78c3069a1678987d120d74ebed {
	meta:
		aliases = "isascii"
		size = "14"
		objfiles = "isascii@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C0 F7 44 24 04 80 FF FF FF 0F 94 C0 C3 }
	condition:
		$pattern
}

rule rwlock_can_rdlock_00459d34c82a6341972a31ccaa7aa14e {
	meta:
		aliases = "rwlock_can_rdlock"
		size = "37"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) C9 83 78 0C 00 75 1A 83 78 18 00 74 0F 83 78 14 00 74 09 31 C9 85 D2 0F 95 C1 EB 05 B9 01 00 00 00 89 C8 C3 }
	condition:
		$pattern
}

rule _start_a74091ded31fe9341c86ffba27b8ff00 {
	meta:
		aliases = "_start"
		size = "34"
		objfiles = "crt1, Scrt1"
	strings:
		$pattern = { ( CC | 31 ) ED 5E 89 E1 83 E4 F0 50 54 52 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 51 56 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? F4 }
	condition:
		$pattern
}

rule fibheap_rem_root_cefdfff3d5962e9a26293dcc238fda47 {
	meta:
		aliases = "fibheap_rem_root"
		size = "34"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 3B ) 52 08 55 89 E5 53 89 C3 74 0D 89 D0 E8 FE FD FF FF 89 43 08 5B 5D C3 C7 40 08 00 00 00 00 5B 5D C3 }
	condition:
		$pattern
}

rule ascii_to_bin_75c43256ea50e9b81ec327e061ab7f1e {
	meta:
		aliases = "ascii_to_bin"
		size = "48"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 3C ) 7A 7F 29 3C 60 7E 07 0F BE C0 83 E8 3B C3 3C 5A 7F 1A 3C 40 7E 07 0F BE C0 83 E8 35 C3 3C 39 7F 0B 3C 2D 7E 07 0F BE C0 83 E8 2E C3 31 C0 C3 }
	condition:
		$pattern
}

rule __cxa_atexit_4cf14b0e504dc17b04adce554e88e343 {
	meta:
		aliases = "__GI___cxa_atexit, __cxa_atexit"
		size = "57"
		objfiles = "__cxa_atexit@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 31 C0 83 EC 08 8B 5C 24 10 85 DB 74 27 E8 ?? ?? ?? ?? 89 C2 83 C8 FF 85 D2 74 19 89 5A 04 8B 44 24 14 89 42 08 8B 44 24 18 C7 02 03 00 00 00 89 42 0C 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule __stdio_READ_845a21a6fb53d1187cd4eb277b195a84 {
	meta:
		aliases = "__stdio_READ"
		size = "68"
		objfiles = "_READ@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 31 C0 83 EC 08 8B 5C 24 10 8B 54 24 18 F6 03 04 75 2D 85 D2 79 05 BA FF FF FF 7F 50 52 FF 74 24 1C FF 73 04 E8 ?? ?? ?? ?? 83 C4 10 83 F8 00 7F 0E 75 06 66 83 0B 04 EB 06 66 83 0B 08 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule wcsrchr_94a7195b8fbccf48162218b40d6d376f {
	meta:
		aliases = "wcsrchr"
		size = "30"
		objfiles = "wcsrchr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 31 C0 8B 54 24 08 8B 5C 24 0C 8B 0A 39 D9 75 02 89 D0 85 C9 74 05 83 C2 04 EB EF 5B C3 }
	condition:
		$pattern
}

rule glob_pattern_p_cacd843fdc96a49e52a1b1beeea4f01f {
	meta:
		aliases = "__GI_glob_pattern_p, glob_pattern_p"
		size = "93"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 31 C9 8B 5C 24 0C 8B 54 24 08 EB 3F 0F BE C0 83 F8 5B 74 1A 7F 0C 83 F8 2A 74 3A 83 F8 3F 75 2A EB 33 83 F8 5C 74 0E 83 F8 5D 75 1E EB 18 B9 01 00 00 00 EB 15 85 DB 74 11 8D 42 01 80 7A 01 00 74 08 89 C2 EB 04 85 C9 75 0B 42 8A 02 84 C0 75 BB 31 C0 EB 05 B8 01 00 00 00 5B C3 }
	condition:
		$pattern
}

rule xdrmem_inline_d953d4624f5c1d79fa4ea7ad33acb5aa {
	meta:
		aliases = "xdrmem_inline"
		size = "36"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 31 D2 8B 4C 24 08 8B 5C 24 0C 8B 41 14 39 D8 72 0E 8B 51 0C 29 D8 89 41 14 8D 04 1A 89 41 0C 89 D0 5B C3 }
	condition:
		$pattern
}

rule _dl_parse_lazy_relocation_info_81bbf97068f0f918ea6fd246b2699aee {
	meta:
		aliases = "_dl_parse_lazy_relocation_information"
		size = "35"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 53 ) 31 D2 8B 5C 24 08 8B 44 24 10 8B 4C 24 0C 89 44 24 08 C7 44 24 0C ?? ?? ?? ?? 8B 03 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule logout_e4eccd3eb88f1d6a946d4ae14b3fa19c {
	meta:
		aliases = "logout"
		size = "173"
		objfiles = "logout@libutil.a"
	strings:
		$pattern = { ( CC | 53 ) 31 DB 81 EC 94 01 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 40 0F 84 86 00 00 00 E8 ?? ?? ?? ?? 66 C7 44 24 08 07 00 53 6A 20 FF B4 24 98 01 00 00 8D 44 24 1C 8D 5C 24 14 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 74 4A 8D 40 2C 51 6A 20 6A 00 50 E8 ?? ?? ?? ?? 83 C4 0C 8D 43 4C 68 00 01 00 00 6A 00 50 E8 ?? ?? ?? ?? 58 8D 83 54 01 00 00 5A 6A 00 50 E8 ?? ?? ?? ?? 66 C7 03 08 00 89 1C 24 E8 ?? ?? ?? ?? BB 01 00 00 00 83 C4 10 85 C0 75 02 31 DB E8 ?? ?? ?? ?? 89 D8 81 C4 88 01 00 00 5B C3 }
	condition:
		$pattern
}

rule pthread_key_create_1c0d4b83ea5f7094679ece0001cede9f {
	meta:
		aliases = "pthread_key_create"
		size = "108"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 31 DB 83 EC 14 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 EB 38 83 3C DD ?? ?? ?? ?? 00 75 2D 8B 44 24 14 83 EC 0C C7 04 DD ?? ?? ?? ?? 01 00 00 00 89 04 DD ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 20 89 18 31 C0 EB 1B 43 81 FB FF 03 00 00 7E C0 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 0B 00 00 00 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule xdrmem_setpos_cab36b70905b9c11bdb2d8f153fbb271 {
	meta:
		aliases = "xdrmem_setpos"
		size = "38"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 31 DB 8B 4C 24 08 8B 54 24 0C 8B 41 14 03 51 10 03 41 0C 39 C2 7F 0A 29 D0 89 51 0C 89 41 14 B3 01 89 D8 5B C3 }
	condition:
		$pattern
}

rule wcswidth_cc1715ddf0070470afc7b72e2acc3efc {
	meta:
		aliases = "__GI_wcswidth, wcswidth"
		size = "57"
		objfiles = "wcswidth@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 31 DB 8B 4C 24 08 8B 54 24 0C EB 19 3D FF 00 00 00 7F 1E 83 F8 1F 7E 19 83 E8 7F 83 F8 20 76 11 83 C1 04 43 4A 85 D2 74 0B 8B 01 85 C0 75 DD EB 03 83 CB FF 89 D8 5B C3 }
	condition:
		$pattern
}

rule sync_file_range_3d06f6540ffb5ed30dae4106a5a12f4e {
	meta:
		aliases = "__GI_sync_file_range, sync_file_range"
		size = "51"
		objfiles = "sync_file_range@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 56 57 55 B8 3A 01 00 00 8B 5C 24 14 8B 4C 24 18 8B 54 24 1C 8B 74 24 20 8B 7C 24 24 8B 6C 24 28 CD 80 5D 5F 5E 5B 3D 00 F0 FF FF 0F 87 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule tempnam_395d1a876db810192f53fa2e453be014 {
	meta:
		aliases = "tempnam"
		size = "84"
		objfiles = "tempnam@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC 08 10 00 00 FF B4 24 14 10 00 00 FF B4 24 14 10 00 00 68 FF 0F 00 00 8D 5C 24 15 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 1F 50 50 6A 03 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 0E 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 EB 02 31 C0 81 C4 08 10 00 00 5B C3 }
	condition:
		$pattern
}

rule __GI_abort_af3eea174228993c429526720ddb4f20 {
	meta:
		aliases = "abort, __GI_abort"
		size = "273"
		objfiles = "abort@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC 24 01 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 20 00 00 00 83 C4 10 EB 0B C7 84 84 98 00 00 00 00 00 00 00 48 79 F2 53 53 6A 06 8D 9C 24 A4 00 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 0E 51 6A 00 53 6A 01 E8 ?? ?? ?? ?? 83 C4 10 80 3D ?? ?? ?? ?? 00 75 2F C6 05 ?? ?? ?? ?? 01 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 06 00 00 00 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 A0 ?? ?? ?? ?? 3C 01 75 58 52 68 8C 00 00 00 6A 00 C6 05 ?? ?? ?? ?? 02 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 44 24 1C 00 00 00 00 B8 20 00 00 00 83 C4 10 EB 08 C7 44 84 10 FF FF FF FF 48 79 F5 C7 84 }
	condition:
		$pattern
}

rule __bsd_signal_126cff4a00751967edf4b225069665be {
	meta:
		aliases = "signal, bsd_signal, __GI_signal, __bsd_signal"
		size = "175"
		objfiles = "signal@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC 28 01 00 00 8B 84 24 34 01 00 00 8B 9C 24 30 01 00 00 83 F8 FF 74 09 85 DB 7E 05 83 FB 40 7E 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 74 89 84 24 9C 00 00 00 B8 20 00 00 00 EB 0B C7 84 84 A0 00 00 00 00 00 00 00 48 79 F2 52 52 53 8D 84 24 AC 00 00 00 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 41 50 50 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 83 F8 01 19 C0 25 00 00 00 10 89 84 24 24 01 00 00 8D 44 24 14 50 8D 84 24 A4 00 00 00 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 06 8B 44 24 10 EB 03 83 C8 FF 81 C4 28 01 00 00 5B C3 }
	condition:
		$pattern
}

rule getpw_aaf7d69b8c2011a7da762f1fbcd34c8c {
	meta:
		aliases = "getpw"
		size = "164"
		objfiles = "getpw@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC 28 01 00 00 8B 9C 24 34 01 00 00 85 DB 75 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 78 83 EC 0C 8D 84 24 30 01 00 00 50 68 00 01 00 00 8D 44 24 1C 50 8D 84 24 20 01 00 00 50 FF B4 24 4C 01 00 00 E8 ?? ?? ?? ?? 83 C4 20 85 C0 75 48 83 EC 0C FF B4 24 2C 01 00 00 FF B4 24 2C 01 00 00 FF B4 24 2C 01 00 00 FF B4 24 2C 01 00 00 FF B4 24 2C 01 00 00 FF B4 24 2C 01 00 00 FF B4 24 2C 01 00 00 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 30 31 D2 85 C0 79 03 83 CA FF 89 D0 81 C4 28 01 00 00 5B C3 }
	condition:
		$pattern
}

rule login_ffdf707cf50e799cd180990604aace82 {
	meta:
		aliases = "login"
		size = "104"
		objfiles = "login@libutil.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC 88 01 00 00 8B 9C 24 90 01 00 00 8D 44 24 08 52 68 80 01 00 00 53 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 C7 44 24 18 07 00 E8 ?? ?? ?? ?? 89 44 24 1C 83 C4 0C 8D 43 08 6A 20 50 8D 44 24 1C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 C4 98 01 00 00 5B C3 }
	condition:
		$pattern
}

rule sighold_d063cca957229e0116569f85807e14b5 {
	meta:
		aliases = "sigrelse, sighold"
		size = "77"
		objfiles = "sigrelse@libc.a, sighold@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC 8C 00 00 00 8D 5C 24 0C 53 6A 00 6A 02 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 26 52 52 FF B4 24 98 00 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 10 50 6A 00 53 6A 02 E8 ?? ?? ?? ?? 83 C4 10 EB 03 83 C8 FF 81 C4 88 00 00 00 5B C3 }
	condition:
		$pattern
}

rule ntp_gettime_6040e48ccca8596f95e056f528b202a8 {
	meta:
		aliases = "ntp_gettime"
		size = "67"
		objfiles = "ntp_gettime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC 94 00 00 00 8D 44 24 14 8B 9C 24 9C 00 00 00 C7 44 24 14 00 00 00 00 50 E8 ?? ?? ?? ?? 8B 54 24 40 89 53 04 8B 54 24 3C 89 13 8B 54 24 24 89 53 08 8B 54 24 28 89 53 0C 81 C4 98 00 00 00 5B C3 }
	condition:
		$pattern
}

rule siginterrupt_ef9099f9103969e6562fc293f65a5059 {
	meta:
		aliases = "siginterrupt"
		size = "132"
		objfiles = "sigintr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC 9C 00 00 00 8B 9C 24 A4 00 00 00 8D 44 24 10 50 6A 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 55 83 BC 24 A4 00 00 00 00 74 1A 52 52 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 A4 24 A0 00 00 00 FF FF FF EF EB 18 50 50 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 8C 24 A0 00 00 00 00 00 00 10 83 C4 0C 6A 00 8D 44 24 14 50 53 E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 79 03 83 CA FF 89 D0 81 C4 98 00 00 00 5B C3 }
	condition:
		$pattern
}

rule pthread_kill_other_threads_np_ef522cdd3f9ba471c81f8def25326919 {
	meta:
		aliases = "__pthread_kill_other_threads_np, pthread_kill_other_threads_np"
		size = "122"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC A0 00 00 00 6A 00 6A 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 8D 44 24 1C 8D 5C 24 18 50 E8 ?? ?? ?? ?? C7 84 24 A0 00 00 00 00 00 00 00 C7 44 24 1C 00 00 00 00 83 C4 0C 6A 00 53 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 6A 00 53 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 7E 0D 52 6A 00 53 50 E8 ?? ?? ?? ?? 83 C4 10 81 C4 98 00 00 00 5B C3 }
	condition:
		$pattern
}

rule __GI_gethostname_033ba6011e5d85bfb15ec275db31d1f0 {
	meta:
		aliases = "gethostname, __GI_gethostname"
		size = "98"
		objfiles = "gethostname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC A4 01 00 00 8D 44 24 1E 50 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 40 74 3E 83 EC 0C 8D 5C 24 5F 53 E8 ?? ?? ?? ?? 83 C4 10 40 3B 84 24 A4 01 00 00 76 10 E8 ?? ?? ?? ?? 83 CA FF C7 00 16 00 00 00 EB 14 50 50 53 FF B4 24 AC 01 00 00 E8 ?? ?? ?? ?? 31 D2 83 C4 10 89 D0 81 C4 98 01 00 00 5B C3 }
	condition:
		$pattern
}

rule __libc_getdomainname_697f99fee411f6ddffe6bd60370a0f43 {
	meta:
		aliases = "__GI___libc_getdomainname, __GI_getdomainname, getdomainname, __libc_getdomainname"
		size = "101"
		objfiles = "getdomainname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC A4 01 00 00 8D 44 24 1E 50 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 40 74 41 83 EC 0C 8D 9C 24 63 01 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 40 3B 84 24 A4 01 00 00 76 10 E8 ?? ?? ?? ?? 83 CA FF C7 00 16 00 00 00 EB 14 50 50 53 FF B4 24 AC 01 00 00 E8 ?? ?? ?? ?? 31 D2 83 C4 10 89 D0 81 C4 98 01 00 00 5B C3 }
	condition:
		$pattern
}

rule pthread_onexit_process_b24716c4aa4fecdc0b984d9dac9d3080 {
	meta:
		aliases = "pthread_onexit_process"
		size = "149"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC A8 00 00 00 83 3D ?? ?? ?? ?? 00 78 7D E8 ?? ?? ?? ?? C7 44 24 18 02 00 00 00 89 C3 89 44 24 14 8B 84 24 B0 00 00 00 89 44 24 1C 8D 44 24 14 52 68 94 00 00 00 50 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 40 75 0A E8 ?? ?? ?? ?? 83 38 04 74 DA 89 D8 E8 ?? ?? ?? ?? 3B 1D ?? ?? ?? ?? 75 2A 50 68 00 00 00 80 6A 00 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 10 81 C4 A8 00 00 00 5B C3 }
	condition:
		$pattern
}

rule pthread_create_65a68a9c90c79b93df1f35322b7bd266 {
	meta:
		aliases = "pthread_create"
		size = "180"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC A8 00 00 00 83 3D ?? ?? ?? ?? 00 79 12 E8 ?? ?? ?? ?? BA 0B 00 00 00 85 C0 0F 88 88 00 00 00 E8 ?? ?? ?? ?? C7 44 24 18 00 00 00 00 89 44 24 14 89 C3 8B 84 24 B4 00 00 00 89 44 24 1C 8B 84 24 B8 00 00 00 89 44 24 20 8B 84 24 BC 00 00 00 89 44 24 24 51 8D 44 24 2C 50 6A 00 6A 02 E8 ?? ?? ?? ?? 83 C4 10 8D 44 24 14 52 68 94 00 00 00 50 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 40 75 0A E8 ?? ?? ?? ?? 83 38 04 74 DA 89 D8 E8 ?? ?? ?? ?? 83 7B 34 00 75 0C 8B 84 24 B0 00 00 00 8B 53 30 89 10 8B 53 34 89 D0 81 C4 A8 00 00 00 5B C3 }
	condition:
		$pattern
}

rule pthread_start_thread_543024a6f08190f1cafbbf674971a706 {
	meta:
		aliases = "pthread_start_thread"
		size = "207"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC A8 00 00 00 8B 9C 24 B0 00 00 00 E8 ?? ?? ?? ?? 89 43 14 50 8D 43 64 6A 00 50 6A 02 E8 ?? ?? ?? ?? 8B 93 E4 00 00 00 83 C4 10 85 D2 78 0B 50 8D 83 E8 00 00 00 50 52 EB 1F 83 3D ?? ?? ?? ?? 00 7E 21 C7 84 24 A4 00 00 00 00 00 00 00 51 8D 84 24 A8 00 00 00 50 6A 00 FF 73 14 E8 ?? ?? ?? ?? 83 C4 10 A1 ?? ?? ?? ?? 85 C0 74 47 83 3D ?? ?? ?? ?? 00 7E 3E 89 5C 24 10 C7 44 24 14 05 00 00 00 8D 44 24 10 52 68 94 00 00 00 50 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 40 75 0A E8 ?? ?? ?? ?? 83 38 04 74 DA 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C FF 73 60 FF 53 5C 5A 59 8D 94 24 B0 00 00 00 }
	condition:
		$pattern
}

rule __pthread_initialize_manager_0a5e7de495f1b66a73c2b00d902fcea8 {
	meta:
		aliases = "__pthread_initialize_manager"
		size = "517"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC A8 00 00 00 A1 ?? ?? ?? ?? C7 00 01 00 00 00 83 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 EC 0C 8D 44 00 E0 50 E8 ?? ?? ?? ?? 89 C2 A3 ?? ?? ?? ?? 83 C4 10 83 C8 FF 85 D2 0F 84 B6 01 00 00 A1 ?? ?? ?? ?? 83 EC 0C 8D 44 42 E0 A3 ?? ?? ?? ?? 8D 84 24 AC 00 00 00 50 E8 ?? ?? ?? ?? 83 C4 10 40 75 13 83 EC 0C FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 F1 00 00 00 A1 ?? ?? ?? ?? 85 C0 74 05 A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 0F 84 88 00 00 00 A1 ?? ?? ?? ?? 8A 15 ?? ?? ?? ?? 08 C2 79 79 31 D2 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF B4 24 A0 00 00 00 68 00 0F 00 00 FF 35 ?? ?? ?? ?? 68 ?? }
	condition:
		$pattern
}

rule __pthread_timedsuspend_new_697b51c7f0ee16fbaf85236fa1f4575a {
	meta:
		aliases = "__pthread_timedsuspend_new"
		size = "282"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC C0 01 00 00 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? BA 01 00 00 00 83 C4 10 85 C0 0F 85 DF 00 00 00 8B 94 24 C0 01 00 00 8D 44 24 0C 83 EC 0C 89 42 24 C7 42 20 00 00 00 00 8D 9C 24 34 01 00 00 53 E8 ?? ?? ?? ?? 58 5A FF 35 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 0C 8D 84 24 AC 00 00 00 50 53 6A 01 E8 ?? ?? ?? ?? 83 C4 10 51 51 6A 00 8D 84 24 BC 01 00 00 50 E8 ?? ?? ?? ?? 69 84 24 C4 01 00 00 E8 03 00 00 8B 8C 24 D4 01 00 00 8B 51 04 8B 09 2B 8C 24 C0 01 00 00 29 C2 89 94 24 BC 01 00 00 89 8C 24 B8 01 00 00 83 C4 10 85 D2 79 17 8D 82 00 CA 9A 3B 89 84 24 AC 01 00 00 8D 41 FF 89 84 24 A8 01 00 }
	condition:
		$pattern
}

rule gethostid_16d2b3b3778401f6ae7384300e6d6043 {
	meta:
		aliases = "gethostid"
		size = "222"
		objfiles = "hostid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC D0 01 00 00 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 78 39 50 6A 04 8D 84 24 CC 01 00 00 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 15 83 EC 0C 53 E8 ?? ?? ?? ?? 8B 84 24 D4 01 00 00 E9 86 00 00 00 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 50 50 6A 40 8D 9C 24 6F 01 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 67 80 BC 24 63 01 00 00 00 74 5D 50 50 8D 84 24 C0 01 00 00 50 8D 84 24 CC 01 00 00 50 68 4C 01 00 00 8D 44 24 2B 50 8D 84 24 BC 01 00 00 50 53 E8 ?? ?? ?? ?? 8B 84 24 E0 01 00 00 83 C4 20 85 C0 74 25 8D 94 24 BC 01 00 00 51 FF 70 0C 8B 40 10 FF 30 52 E8 ?? ?? ?? ?? 8B 84 24 }
	condition:
		$pattern
}

rule get_current_dir_name_ad2d011f3d47289c4c1f461b1191066c {
	meta:
		aliases = "get_current_dir_name"
		size = "146"
		objfiles = "getdirname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC D4 00 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 74 65 51 51 8D 44 24 70 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 4D 52 52 8D 44 24 10 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 39 8B 54 24 0C 8B 44 24 08 3B 54 24 6C 75 2B 3B 44 24 68 75 25 8B 54 24 64 8B 44 24 60 3B 94 24 C4 00 00 00 75 14 3B 84 24 C0 00 00 00 75 0B 83 EC 0C 53 E8 ?? ?? ?? ?? EB 0B 50 50 6A 00 6A 00 E8 ?? ?? ?? ?? 81 C4 D8 00 00 00 5B C3 }
	condition:
		$pattern
}

rule wait_node_dequeue_23380196b25635b606f6ab6f656ac24f {
	meta:
		aliases = "wait_node_dequeue"
		size = "40"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 39 C2 75 19 8B 19 89 C8 F0 0F B1 1A 0F 94 C3 84 DB 74 04 EB 0C 89 C2 8B 02 39 C1 75 F8 8B 01 89 02 58 5B C3 }
	condition:
		$pattern
}

rule memcmp_bytes_376db57c6f77abf65891ed4cab70b551 {
	meta:
		aliases = "memcmp_bytes"
		size = "35"
		objfiles = "memcmp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 89 E1 89 44 24 04 89 14 24 8D 5C 24 04 0F B6 03 0F B6 11 43 41 39 D0 74 F4 29 D0 5A 59 5B C3 }
	condition:
		$pattern
}

rule clnt_perrno_a56b6513e8282a7db22c7544c43028ed {
	meta:
		aliases = "clnt_perrno"
		size = "32"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 1D ?? ?? ?? ?? FF 74 24 10 E8 ?? ?? ?? ?? 52 53 50 E8 ?? ?? ?? ?? 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule __GI_strsignal_f7aac266772192793963dcdce72120d6 {
	meta:
		aliases = "strsignal, __GI_strsignal"
		size = "86"
		objfiles = "strsignal@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 44 24 10 83 F8 1F 77 19 89 C1 BB ?? ?? ?? ?? EB 07 80 3B 01 83 D9 00 43 85 C9 75 F5 80 3B 00 75 2A 83 EC 0C 99 6A 00 6A F6 52 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 1C 8D 58 F1 6A 0F 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_dirfd_af91852396a07f16857363fea2299d6d {
	meta:
		aliases = "dirfd, __GI_dirfd"
		size = "32"
		objfiles = "dirfd@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 44 24 10 8B 18 83 FB FF 75 0B E8 ?? ?? ?? ?? C7 00 09 00 00 00 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule create_module_a46061681895330e5b526f92e75eb93d {
	meta:
		aliases = "create_module"
		size = "79"
		objfiles = "create_module@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 44 24 10 8B 4C 24 14 53 89 C3 B8 7F 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0B E8 ?? ?? ?? ?? F7 DB 89 18 EB 05 83 F8 FF 75 1B E8 ?? ?? ?? ?? 89 C1 8B 10 83 C8 FF 83 FA 7D 7E 0A 89 D0 C7 01 00 00 00 00 F7 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule timer_gettime_132d0ff8d6816272926dbd694a635adb {
	meta:
		aliases = "timer_gettime"
		size = "53"
		objfiles = "timer_gettime@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 44 24 10 8B 4C 24 14 8B 50 04 87 D3 B8 05 01 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule xdrrec_putint32_373f85cfe6d8bcd1f5190e704dbe5730 {
	meta:
		aliases = "xdrrec_putint32"
		size = "82"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 44 24 10 8B 58 0C 8B 53 10 89 D1 8D 42 04 89 43 10 3B 43 14 76 22 89 53 10 C7 43 1C 01 00 00 00 31 D2 89 D8 E8 ?? ?? ?? ?? 31 D2 85 C0 74 18 8B 4B 10 8D 41 04 89 43 10 8B 44 24 14 BA 01 00 00 00 8B 00 0F C8 89 01 89 D0 5A 59 5B C3 }
	condition:
		$pattern
}

rule xdrrec_putlong_0a5bd83ff558a34c7cfd44eb5751841c {
	meta:
		aliases = "xdrrec_putlong"
		size = "82"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 44 24 10 8B 58 0C 8B 53 10 89 D1 8D 42 04 89 43 10 3B 43 14 76 22 89 53 10 C7 43 1C 01 00 00 00 31 D2 89 D8 E8 ?? ?? ?? ?? 31 D2 85 C0 74 18 8B 4B 10 8D 41 04 89 43 10 8B 44 24 14 BA 01 00 00 00 8B 00 0F C8 89 01 89 D0 5B 5A 5B C3 }
	condition:
		$pattern
}

rule xdrrec_eof_045f37614bfed502b95473752736585f {
	meta:
		aliases = "__GI_xdrrec_eof, xdrrec_eof"
		size = "84"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 44 24 10 8B 58 0C EB 23 89 D8 E8 ?? ?? ?? ?? 85 C0 74 33 C7 43 34 00 00 00 00 83 7B 38 00 75 0B 89 D8 E8 ?? ?? ?? ?? 85 C0 74 1B 8B 53 34 85 D2 7F D6 83 7B 38 00 74 D0 8B 43 2C 3B 43 30 0F 94 C0 0F B6 C0 EB 05 B8 01 00 00 00 5B 5A 5B C3 }
	condition:
		$pattern
}

rule __GI_xdrrec_skiprecord_6212ff85398148449cc103bde633bc0e {
	meta:
		aliases = "xdrrec_skiprecord, __GI_xdrrec_skiprecord"
		size = "81"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 44 24 10 8B 58 0C EB 23 89 D8 E8 ?? ?? ?? ?? 85 C0 74 33 C7 43 34 00 00 00 00 83 7B 38 00 75 0B 89 D8 E8 ?? ?? ?? ?? 85 C0 74 1B 8B 53 34 85 D2 7F D6 83 7B 38 00 74 D0 B8 01 00 00 00 C7 43 38 00 00 00 00 EB 02 31 C0 59 5B 5B C3 }
	condition:
		$pattern
}

rule clnttcp_control_a1a9539c3db092847df8cc2f5f52bd1d {
	meta:
		aliases = "clnttcp_control"
		size = "173"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 44 24 10 8B 5C 24 18 8B 48 08 8B 44 24 14 48 83 F8 0E 77 07 FF 24 85 ?? ?? ?? ?? 31 C0 E9 82 00 00 00 C7 41 04 01 00 00 00 EB 74 C7 41 04 00 00 00 00 EB 6B 8B 13 8B 43 04 89 41 0C 89 51 08 C7 41 10 01 00 00 00 EB 57 8B 51 08 8B 41 0C 89 43 04 89 13 EB 4A 8D 41 14 52 6A 10 50 53 E8 ?? ?? ?? ?? B8 01 00 00 00 83 C4 10 EB 38 8B 01 EB 24 8B 41 30 0F C8 EB 1D 8B 03 48 0F C8 89 41 30 8B 41 40 0F C8 EB 0E 8B 03 0F C8 89 41 40 EB 10 8B 41 3C 0F C8 89 03 EB 07 8B 03 0F C8 89 41 3C B8 01 00 00 00 5A 59 5B C3 }
	condition:
		$pattern
}

rule clntunix_control_61b75c40a123f1de5d04b6df463eab1a {
	meta:
		aliases = "clntunix_control"
		size = "184"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 44 24 10 8B 5C 24 18 8B 48 08 8B 44 24 14 48 83 F8 0E 77 07 FF 24 85 ?? ?? ?? ?? 31 C0 E9 8D 00 00 00 C7 41 04 01 00 00 00 EB 7F C7 41 04 00 00 00 00 EB 76 8B 13 8B 43 04 89 41 0C 89 51 08 EB 69 8B 51 08 8B 41 0C 89 43 04 89 13 EB 5C 8D 41 14 52 6A 6E 50 53 E8 ?? ?? ?? ?? B8 01 00 00 00 83 C4 10 EB 4A 8B 01 EB 33 8B 81 90 00 00 00 0F C8 EB 29 8B 03 48 0F C8 89 81 90 00 00 00 8B 81 A0 00 00 00 0F C8 EB 14 8B 03 0F C8 89 81 A0 00 00 00 EB 16 8B 81 9C 00 00 00 0F C8 89 03 EB 0A 8B 03 0F C8 89 81 9C 00 00 00 B8 01 00 00 00 5A 59 5B C3 }
	condition:
		$pattern
}

rule clntudp_control_2f120e07487bca21aa2d725775e2d223 {
	meta:
		aliases = "clntudp_control"
		size = "209"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 44 24 10 8B 5C 24 18 8B 48 08 8B 44 24 14 48 83 F8 0E 77 07 FF 24 85 ?? ?? ?? ?? 31 C0 E9 A6 00 00 00 C7 41 04 01 00 00 00 E9 95 00 00 00 C7 41 04 00 00 00 00 E9 89 00 00 00 8B 13 8B 43 04 89 41 28 89 51 24 EB 7C 8B 51 24 8B 41 28 EB 13 8B 13 8B 43 04 89 41 20 89 51 1C EB 67 8B 51 1C 8B 41 20 89 43 04 89 13 EB 5A 8D 41 08 52 6A 10 50 53 E8 ?? ?? ?? ?? B8 01 00 00 00 83 C4 10 EB 48 8B 01 EB 31 8B 41 58 8B 00 0F C8 EB 28 8B 51 58 8B 03 48 0F C8 89 02 8B 41 58 8B 40 10 0F C8 EB 14 8B 51 58 8B 03 0F C8 89 42 10 EB 16 8B 41 58 8B 40 0C 0F C8 89 03 EB 0A 8B 51 58 8B 03 0F C8 89 42 0C }
	condition:
		$pattern
}

rule __GI_freeaddrinfo_f6076f1412c7674860b17bc2d2245ec4 {
	meta:
		aliases = "freeaddrinfo, __GI_freeaddrinfo"
		size = "35"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 44 24 10 EB 11 83 EC 0C 8B 58 1C 50 E8 ?? ?? ?? ?? 89 D8 83 C4 10 85 C0 75 EB 58 5A 5B C3 }
	condition:
		$pattern
}

rule tcsendbreak_ad0ab8bbf3f7f77da9bdeb3c8d09ebe8 {
	meta:
		aliases = "tcsendbreak"
		size = "57"
		objfiles = "tcsendbrk@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 44 24 14 8B 4C 24 10 85 C0 7F 0A 53 6A 00 68 09 54 00 00 EB 14 83 C0 63 52 BA 64 00 00 00 89 D3 99 F7 FB 50 68 25 54 00 00 51 E8 ?? ?? ?? ?? 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule __old_sem_trywait_092406366adca41bf8958b46cc579620 {
	meta:
		aliases = "__old_sem_trywait"
		size = "58"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 4C 24 10 8B 11 F6 C2 01 74 05 83 FA 01 75 10 E8 ?? ?? ?? ?? C7 00 0B 00 00 00 83 C8 FF EB 12 8D 5A FE 89 D0 F0 0F B1 19 0F 94 C2 84 D2 74 D4 31 C0 59 5B 5B C3 }
	condition:
		$pattern
}

rule ustat_e616588d940011980e6a3cc81edd6ea1 {
	meta:
		aliases = "ustat"
		size = "76"
		objfiles = "ustat@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 4C 24 10 8B 5C 24 14 89 DA 89 C8 0F AC D0 08 C1 E0 08 C1 EA 08 0F B6 D1 09 D0 8B 4C 24 18 0F B7 D0 87 D3 B8 3E 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule mq_notify_f393b202ce3c1407af93a7de1565a14d {
	meta:
		aliases = "mq_notify"
		size = "76"
		objfiles = "mq_notify@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 4C 24 14 8B 54 24 10 85 C9 74 16 83 79 08 02 75 10 E8 ?? ?? ?? ?? C7 00 26 00 00 00 83 C8 FF EB 22 87 D3 B8 19 01 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_chmod_d969997bf30a715240cbf983f5cfc800 {
	meta:
		aliases = "chmod, __GI_chmod"
		size = "51"
		objfiles = "chmod@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 0F B7 4C 24 14 87 D3 B8 0F 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule mkdir_c75f6d8d429666afc26c8790a3ec4173 {
	meta:
		aliases = "__GI_mkdir, mkdir"
		size = "51"
		objfiles = "mkdir@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 0F B7 4C 24 14 87 D3 B8 27 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule fchmod_128ff79998de65b6d2e5144a1891151e {
	meta:
		aliases = "fchmod"
		size = "51"
		objfiles = "fchmod@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 0F B7 4C 24 14 87 D3 B8 5E 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule clock_settime_d271a41051df3cedc8b47173ae4eb47e {
	meta:
		aliases = "clock_settime"
		size = "50"
		objfiles = "clock_settime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 08 01 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule link_7545badbc2c8eb1a93604aa18556cf91 {
	meta:
		aliases = "link"
		size = "50"
		objfiles = "link@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 09 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule clock_gettime_99b477ac47cd6c4f6cdfcc63011c143c {
	meta:
		aliases = "clock_gettime"
		size = "50"
		objfiles = "clock_gettime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 09 01 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_clock_getres_0542852280987b6c24f657065a1157f7 {
	meta:
		aliases = "clock_getres, __GI_clock_getres"
		size = "50"
		objfiles = "clock_getres@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 0A 01 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_utimes_41f12f2059df4c013af83820d0695860 {
	meta:
		aliases = "utimes, __GI_utimes"
		size = "50"
		objfiles = "utimes@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 0F 01 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule utime_8b40c2c332e0723952335712e32d8bcd {
	meta:
		aliases = "__GI_utime, utime"
		size = "50"
		objfiles = "utime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 1E 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule access_dece0c30da42d5b2355fc8920f397b68 {
	meta:
		aliases = "access"
		size = "50"
		objfiles = "access@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 21 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule kill_ebe48f5615c17b4824626480fef6dd04 {
	meta:
		aliases = "__GI_kill, kill"
		size = "50"
		objfiles = "kill@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 25 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule inotify_rm_watch_a1cdb77f9d5a8dc0661187b02a503da4 {
	meta:
		aliases = "inotify_rm_watch"
		size = "50"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 25 01 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule rename_5620d01e1d2c11e7ef92556edf774563 {
	meta:
		aliases = "rename"
		size = "50"
		objfiles = "rename@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 26 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule umount2_076e33fb1294178be25875f5bd1c72a6 {
	meta:
		aliases = "umount2"
		size = "50"
		objfiles = "umount2@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 34 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule setpgid_00835177ffacf6bfc28038b7b32a1b7d {
	meta:
		aliases = "__GI_setpgid, setpgid"
		size = "50"
		objfiles = "setpgid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 39 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule ulimit_15d72ee70453831d1b06e3485849b26d {
	meta:
		aliases = "ulimit"
		size = "50"
		objfiles = "ulimit@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 3A 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_dup2_986b550725acc20971dad11472093bd5 {
	meta:
		aliases = "dup2, __GI_dup2"
		size = "50"
		objfiles = "dup2@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 3F 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule sethostname_423c734673fee4345715809795104f96 {
	meta:
		aliases = "sethostname"
		size = "50"
		objfiles = "sethostname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 4A 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_setrlimit_2e70908c9a9cfc4ebfd43b6e8796c9a7 {
	meta:
		aliases = "setrlimit, __GI_setrlimit"
		size = "50"
		objfiles = "setrlimit@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 4B 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule getrusage_346a22c58b2f38dc9e341c64cf4d3b3a {
	meta:
		aliases = "getrusage"
		size = "50"
		objfiles = "getrusage@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 4D 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_gettimeofday_6d71676dce28ddf5ccbe36538f9a9b2f {
	meta:
		aliases = "gettimeofday, __GI_gettimeofday"
		size = "50"
		objfiles = "gettimeofday@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 4E 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_settimeofday_aa2e740ab7d84c7e57dd97f68cfbbf26 {
	meta:
		aliases = "settimeofday, __GI_settimeofday"
		size = "50"
		objfiles = "settimeofday@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 4F 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule symlink_213841c9cac092e17287f4238df024e7 {
	meta:
		aliases = "symlink"
		size = "50"
		objfiles = "symlink@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 53 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule swapon_4d0ad6b20d80395d619bc8733294ac3d {
	meta:
		aliases = "swapon"
		size = "50"
		objfiles = "swapon@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 57 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_munmap_daef5c6ef5c40d728a7da7d8c1cb50b4 {
	meta:
		aliases = "munmap, __GI_munmap"
		size = "50"
		objfiles = "munmap@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 5B 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule truncate_9ab46b4cfbb745c5ac7b4c2c5ecef294 {
	meta:
		aliases = "__GI_truncate, truncate"
		size = "50"
		objfiles = "truncate@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 5C 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_ftruncate_aa97faa8c7590e8933a2cb5d03f70144 {
	meta:
		aliases = "ftruncate, __GI_ftruncate"
		size = "50"
		objfiles = "ftruncate@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 5D 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_getpriority_f6703dfedbefe1439d247d02e8d6fb79 {
	meta:
		aliases = "getpriority, __GI_getpriority"
		size = "65"
		objfiles = "getpriority@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 60 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 DA 85 DB 78 09 B8 14 00 00 00 29 D8 89 C2 89 D0 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_statfs_4e50f52197fe0f98bf0d418994561253 {
	meta:
		aliases = "__libc_statfs, statfs, __GI___libc_statfs, __GI_statfs"
		size = "50"
		objfiles = "statfs@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 63 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_fstatfs_626538cf26dc5d87ceb849275f79ae92 {
	meta:
		aliases = "fstatfs, __libc_fstatfs, __GI___libc_fstatfs, __GI_fstatfs"
		size = "50"
		objfiles = "fstatfs@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 64 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __socketcall_83c893d75d6e30d3a524e70efad4e7e7 {
	meta:
		aliases = "__socketcall"
		size = "50"
		objfiles = "__socketcall@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 66 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule getitimer_8a8ea19da5d0fef12335476cb581beab {
	meta:
		aliases = "getitimer"
		size = "50"
		objfiles = "getitimer@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 69 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule setdomainname_f043c3830b999c6d649f252947f53307 {
	meta:
		aliases = "setdomainname"
		size = "50"
		objfiles = "setdomainname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 79 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule delete_module_806f9d507d186b9f04ea57979bc92252 {
	meta:
		aliases = "delete_module"
		size = "50"
		objfiles = "delete_module@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 81 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule bdflush_c4257b5f0d5fa45c323bbb92d7c7ca78 {
	meta:
		aliases = "bdflush"
		size = "50"
		objfiles = "bdflush@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 86 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule flock_95a45f923a4a9dbbae2cba153bf4e4f8 {
	meta:
		aliases = "flock"
		size = "50"
		objfiles = "flock@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 8F 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule mlock_7f0e132a4f696bf62fa721473dd1807f {
	meta:
		aliases = "mlock"
		size = "50"
		objfiles = "mlock@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 96 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule munlock_04c725f6736a30014b873e204f193bce {
	meta:
		aliases = "munlock"
		size = "50"
		objfiles = "munlock@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 97 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule sched_setparam_6aa3feba4308326468042fc2ce22ea9b {
	meta:
		aliases = "sched_setparam"
		size = "50"
		objfiles = "sched_setparam@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 9A 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule sched_getparam_73f5526584f93e2a2b5d4b6e91bd8710 {
	meta:
		aliases = "sched_getparam"
		size = "50"
		objfiles = "sched_getparam@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 9B 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule sched_rr_get_interval_0917553b495bb1491148bc6bd645f123 {
	meta:
		aliases = "sched_rr_get_interval"
		size = "50"
		objfiles = "sched_rr_get_interval@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 A1 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_nanosleep_73e90979a3dcfd70c3a1b9915a43a160 {
	meta:
		aliases = "__libc_nanosleep, nanosleep, __GI_nanosleep"
		size = "50"
		objfiles = "nanosleep@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 A2 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule capget_077451264cdc04e0cd74706e07580742 {
	meta:
		aliases = "capget"
		size = "50"
		objfiles = "capget@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 B8 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule capset_fb951c7e7744fe84f5d60f0c4021b217 {
	meta:
		aliases = "capset"
		size = "50"
		objfiles = "capset@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 B9 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule sigaltstack_d894642c5ef99819467cd67ba193ddf9 {
	meta:
		aliases = "sigaltstack"
		size = "50"
		objfiles = "sigaltstack@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 BA 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule getrlimit_cf35a07e14d0775a013816b89f40b330 {
	meta:
		aliases = "__GI_getrlimit, getrlimit"
		size = "50"
		objfiles = "getrlimit@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 BF 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule setreuid_c132c4d1cbd39a72794484f1b788ec6d {
	meta:
		aliases = "__GI_setreuid, setreuid"
		size = "50"
		objfiles = "setreuid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 CB 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule setregid_b06bcc5d4f5394b5391834b79b718dd5 {
	meta:
		aliases = "__GI_setregid, setregid"
		size = "50"
		objfiles = "setregid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 CC 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule getgroups_d03dd2166c9728762787d1960206c2e8 {
	meta:
		aliases = "__GI_getgroups, getgroups"
		size = "50"
		objfiles = "getgroups@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 CD 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule setgroups_73180b4ad75ae77de6a2e96b98130ab4 {
	meta:
		aliases = "__GI_setgroups, setgroups"
		size = "50"
		objfiles = "setgroups@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 CE 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule pivot_root_c2181950677e39f3220c4da8a16f91fe {
	meta:
		aliases = "pivot_root"
		size = "50"
		objfiles = "pivot_root@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 D9 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule removexattr_45577b536869f075ea6e2cff5824900f {
	meta:
		aliases = "removexattr"
		size = "50"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 EB 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 59 5B 5B C3 }
	condition:
		$pattern
}

rule lremovexattr_e3474aca6909be71cdc8ec3a71272666 {
	meta:
		aliases = "lremovexattr"
		size = "50"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 EC 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5B 5A 5B C3 }
	condition:
		$pattern
}

rule fremovexattr_7b7a11f3e3a3cf6ddbc2350df610374a {
	meta:
		aliases = "fremovexattr"
		size = "50"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 ED 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_ether_ntoa_r_803c30c36981a68f72fea8181cbd566e {
	meta:
		aliases = "ether_ntoa_r, __GI_ether_ntoa_r"
		size = "59"
		objfiles = "ether_addr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 5C 24 14 0F B6 42 05 50 0F B6 42 04 50 0F B6 42 03 50 0F B6 42 02 50 0F B6 42 01 50 0F B6 02 50 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule _dl_strdup_40b07bb91dc944da3f175761a9eb323d {
	meta:
		aliases = "_dl_strdup"
		size = "55"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8D 5A FF 89 D8 40 80 38 00 75 FA 83 EC 0C 29 D0 40 50 E8 ?? ?? ?? ?? 83 C4 10 89 C1 8D 50 FF 43 42 8A 03 88 02 84 C0 75 F6 89 C8 59 5B 5B C3 }
	condition:
		$pattern
}

rule __GI_fabs_471b6b283f2125caeaf21fe2cb9bce5d {
	meta:
		aliases = "fabs, __GI_fabs"
		size = "32"
		objfiles = "s_fabs@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 14 8B 44 24 10 81 E2 FF FF FF 7F 89 04 24 89 54 24 04 DD 04 24 58 5A 5B C3 }
	condition:
		$pattern
}

rule copysign_f723d3bfe4940b80a147cce3e671dd3e {
	meta:
		aliases = "__GI_copysign, copysign"
		size = "48"
		objfiles = "s_copysign@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 14 8B 4C 24 1C 89 D3 81 E1 00 00 00 80 81 E3 FF FF FF 7F 8B 44 24 10 89 DA 89 04 24 09 CA 89 54 24 04 DD 04 24 58 5A 5B C3 }
	condition:
		$pattern
}

rule towctrans_c4aed3b0c8d4bb396a3427872c784e33 {
	meta:
		aliases = "__GI_towctrans, towctrans"
		size = "65"
		objfiles = "towctrans@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 14 8B 5C 24 10 8D 42 FF 83 F8 01 77 1C 83 FB 7F 77 22 4A 75 08 58 5A 5B E9 ?? ?? ?? ?? 89 5C 24 10 5B 58 5B E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 16 00 00 00 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule pthread_getspecific_45d2685bd22d521e5d916ccd4ea7ea32 {
	meta:
		aliases = "pthread_getspecific"
		size = "61"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 81 FB FF 03 00 00 77 27 E8 ?? ?? ?? ?? 89 DA C1 EA 05 8B 84 90 EC 00 00 00 85 C0 74 12 83 3C DD ?? ?? ?? ?? 00 74 08 83 E3 1F 8B 04 98 EB 02 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule _pthread_cleanup_pop_a3d82f439ff87c89a5ca1c05eeba655a {
	meta:
		aliases = "_pthread_cleanup_pop"
		size = "41"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 83 7C 24 14 00 74 0B 83 EC 0C FF 73 04 FF 13 83 C4 10 E8 ?? ?? ?? ?? 8B 53 0C 89 50 3C 59 5B 5B C3 }
	condition:
		$pattern
}

rule __sigjmp_save_458a20bc75168d5b8571d442177c9840 {
	meta:
		aliases = "__sigjmp_save"
		size = "52"
		objfiles = "sigjmp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 83 7C 24 14 00 74 1A 50 8D 43 1C 50 6A 00 6A 00 E8 ?? ?? ?? ?? 83 C4 10 BA 01 00 00 00 85 C0 74 02 31 D2 89 53 18 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule __uc_malloc_1ce521265eaf074691fd11c76e62cbba {
	meta:
		aliases = "__GI___uc_malloc, __uc_malloc"
		size = "62"
		objfiles = "__uc_malloc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 DB 74 22 85 C0 75 1E A1 ?? ?? ?? ?? 85 C0 75 0A 83 EC 0C 6A 01 E8 ?? ?? ?? ?? 83 EC 0C 53 FF D0 83 C4 10 EB CE 5A 59 5B C3 }
	condition:
		$pattern
}

rule tmpnam_r_0d893fac8fb64c7055f5173416c0e6e5 {
	meta:
		aliases = "tmpnam_r"
		size = "56"
		objfiles = "tmpnam_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 85 DB 74 24 6A 00 6A 00 6A 14 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 11 50 50 6A 03 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 02 31 DB 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_hdestroy_r_7a8668e0d741711047d153185a2f8563 {
	meta:
		aliases = "hdestroy_r, __GI_hdestroy_r"
		size = "48"
		objfiles = "hdestroy_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 85 DB 75 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 13 83 EC 0C FF 33 E8 ?? ?? ?? ?? C7 03 00 00 00 00 83 C4 10 58 5A 5B C3 }
	condition:
		$pattern
}

rule re_comp_3fb4df97c01f8ccd108c1a109630c77c {
	meta:
		aliases = "re_comp"
		size = "182"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 85 DB 75 17 BA ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 0F 84 92 00 00 00 E9 8B 00 00 00 83 3D ?? ?? ?? ?? 00 75 46 83 EC 0C 68 C8 00 00 00 E8 ?? ?? ?? ?? 83 C4 10 A3 ?? ?? ?? ?? BA ?? ?? ?? ?? 85 C0 74 66 83 EC 0C C7 05 ?? ?? ?? ?? C8 00 00 00 68 00 01 00 00 E8 ?? ?? ?? ?? 83 C4 10 A3 ?? ?? ?? ?? BA ?? ?? ?? ?? 85 C0 74 3E 80 0D ?? ?? ?? ?? 80 83 EC 0C 53 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 89 C2 89 D8 C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 0F 8B 14 85 ?? ?? ?? ?? 81 C2 ?? ?? ?? ?? EB 02 31 D2 89 D0 5B 5A 5B C3 }
	condition:
		$pattern
}

rule longjmp_c58d96e261b4572a4acc8e21caf950eb {
	meta:
		aliases = "longjmp"
		size = "27"
		objfiles = "ptlongjmp@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 89 D8 E8 ?? ?? ?? ?? 50 50 FF 74 24 1C 53 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule siglongjmp_9f71c8875ec70b27d7436a9a117a55a7 {
	meta:
		aliases = "siglongjmp"
		size = "27"
		objfiles = "ptlongjmp@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 89 D8 E8 ?? ?? ?? ?? 52 52 FF 74 24 1C 53 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_mutex_unlock_65d849127bebd6d144b9d461ba9eb542 {
	meta:
		aliases = "__pthread_mutex_unlock, pthread_mutex_unlock"
		size = "138"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 8B 43 0C 83 F8 01 74 19 7F 06 85 C0 74 33 EB 0A 83 F8 02 74 3F 83 F8 03 74 51 B8 16 00 00 00 EB 5D E8 ?? ?? ?? ?? 39 43 08 75 4E 8B 43 04 85 C0 7E 08 48 89 43 04 31 C0 EB 44 C7 43 08 00 00 00 00 83 EC 0C 8D 43 10 50 E8 ?? ?? ?? ?? 31 C0 83 C4 10 EB 2A E8 ?? ?? ?? ?? 39 43 08 75 1B 83 7B 10 00 74 15 C7 43 08 00 00 00 00 83 EC 0C 8D 43 10 50 E8 ?? ?? ?? ?? EB D4 B8 01 00 00 00 5B 5A 5B C3 }
	condition:
		$pattern
}

rule __stdio_trans2r_o_96053398952db6ae98fccdeb7677033f {
	meta:
		aliases = "__stdio_trans2r_o"
		size = "101"
		objfiles = "_trans2r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 8B 4C 24 14 8B 03 0F B7 D0 85 D1 75 0D 81 E2 80 08 00 00 75 0C 09 C8 66 89 03 0F B7 03 A8 10 74 14 E8 ?? ?? ?? ?? C7 00 09 00 00 00 66 83 0B 08 83 C8 FF EB 24 A8 40 74 1A 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 E3 66 83 23 BF 8B 43 08 89 43 1C 66 83 0B 01 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule __stdio_trans2w_o_87881e6ccb2a21965c23e93468395bab {
	meta:
		aliases = "__stdio_trans2w_o"
		size = "158"
		objfiles = "_trans2w@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 8B 4C 24 14 8B 03 0F B7 D0 85 D1 75 0D 81 E2 80 08 00 00 75 0D 09 C8 66 89 03 0F B7 13 F6 C2 20 74 14 E8 ?? ?? ?? ?? C7 00 09 00 00 00 66 83 0B 08 83 CA FF EB 5A F6 C2 03 74 41 F6 C2 04 75 2C 8B 43 14 3B 43 10 75 05 F6 C2 02 74 1F 81 E2 00 04 00 00 83 FA 01 52 19 C0 83 C0 02 50 6A 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 C1 66 83 23 FC 8B 43 08 89 43 18 89 43 10 89 43 14 66 83 0B 40 31 D2 0F B7 03 F6 C4 0B 75 06 8B 43 0C 89 43 1C 89 D0 5A 59 5B C3 }
	condition:
		$pattern
}

rule sc_getc_3056c2b0723593ac9b21d47b11a03dab {
	meta:
		aliases = "sc_getc"
		size = "106"
		objfiles = "vfwscanf@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 8B 53 08 83 7A 04 FD 75 1B 8B 42 10 3B 42 0C 73 0A 8B 08 83 C0 04 89 42 10 EB 1F 66 83 0A 04 83 C8 FF EB 3A 83 EC 0C 52 E8 ?? ?? ?? ?? 89 C1 83 C4 10 83 C8 FF 83 F9 FF 74 24 8B 43 08 C6 43 1A 01 89 4B 28 3B 4B 38 8A 40 02 88 43 18 75 07 B9 2E 00 00 00 EB 06 89 4B 04 89 4B 24 89 C8 5B 5A 5B C3 }
	condition:
		$pattern
}

rule __stdio_wcommit_e2eccef50d20afc9857c120cf1017734 {
	meta:
		aliases = "__stdio_wcommit"
		size = "43"
		objfiles = "_wcommit@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 8B 53 08 8B 43 10 29 D0 74 0F 89 53 10 51 50 52 53 E8 ?? ?? ?? ?? 83 C4 10 8B 43 10 2B 43 08 5A 59 5B C3 }
	condition:
		$pattern
}

rule pthread_start_thread_event_febed0829ec908719d68ed793044baab {
	meta:
		aliases = "pthread_start_thread_event"
		size = "45"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 E8 ?? ?? ?? ?? 31 D2 89 43 14 8B 43 1C E8 ?? ?? ?? ?? 83 EC 0C FF 73 1C E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule login_tty_2be46a244ef31d4e1491d738acc6fb2f {
	meta:
		aliases = "__GI_login_tty, login_tty"
		size = "96"
		objfiles = "login_tty@libutil.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 E8 ?? ?? ?? ?? 50 6A 00 68 0E 54 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 40 74 36 50 50 6A 00 53 E8 ?? ?? ?? ?? 59 58 6A 01 53 E8 ?? ?? ?? ?? 58 5A 6A 02 53 E8 ?? ?? ?? ?? 83 C4 10 31 D2 83 FB 02 7E 0E 83 EC 0C 53 E8 ?? ?? ?? ?? 31 D2 83 C4 10 89 D0 5A 59 5B C3 }
	condition:
		$pattern
}

rule cuserid_5700f9d94039601f9609e52c59382645 {
	meta:
		aliases = "cuserid"
		size = "42"
		objfiles = "getlogin@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 E8 ?? ?? ?? ?? 85 DB 74 15 85 C0 75 05 B8 ?? ?? ?? ?? 52 52 50 53 E8 ?? ?? ?? ?? 83 C4 10 5A 59 5B C3 }
	condition:
		$pattern
}

rule __exit_handler_408f0897299d53df9fcdc9e500d18914 {
	meta:
		aliases = "__exit_handler"
		size = "96"
		objfiles = "__exit_handler@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 EB 3B 48 A3 ?? ?? ?? ?? C1 E0 04 8D 04 02 8B 10 83 FA 02 74 07 83 FA 03 75 23 EB 0F 8B 50 04 85 D2 74 1A 51 51 FF 70 08 53 EB 0D 8B 50 04 85 D2 74 0B 83 EC 0C FF 70 08 FF D2 83 C4 10 A1 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 85 C0 75 B6 89 54 24 10 58 5A 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __scan_getc_e707f976ff3be64721ce9e37a3cc351e {
	meta:
		aliases = "__scan_getc"
		size = "80"
		objfiles = "__scan_cookie@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 FF 4B 10 C7 03 FF FF FF FF 83 7B 10 00 79 09 80 4B 19 02 83 C8 FF EB 2C 80 7B 19 00 75 1A 83 EC 0C 53 FF 53 2C 83 C4 10 83 F8 FF 75 06 80 4B 19 02 EB 11 89 43 04 EB 04 C6 43 19 00 FF 43 0C 8B 43 04 89 03 5A 59 5B C3 }
	condition:
		$pattern
}

rule qone_66df46849af6086d4d1dd737ae9a928b {
	meta:
		aliases = "qone"
		size = "192"
		objfiles = "e_j1@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 14 8B 4C 24 10 89 D8 25 FF FF FF 7F 3D FF FF 1F 40 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 3D 3D 8A 2E 12 40 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 2A 3D 6C DB 06 40 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 17 3D FF FF FF 3F 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 04 31 C0 31 D2 89 0C 24 89 5C 24 04 DD 04 24 D8 C8 D9 E8 DC F1 DD 40 28 D8 CA DC 40 20 D8 CA DC 40 18 D8 CA DC 40 10 D8 CA DC 40 08 D8 CA DC 00 DD 42 28 D8 CB DC 42 20 D8 CB DC 42 18 D8 CB DC 42 10 D8 CB DC 42 08 D8 CB DC 02 DE CB D9 CA DE C1 DE F9 D8 05 ?? ?? ?? ?? DD 04 24 DE F9 59 5B 5B C3 }
	condition:
		$pattern
}

rule qzero_6a28d0a67a44019660fac53ec9eef77a {
	meta:
		aliases = "qzero"
		size = "192"
		objfiles = "e_j0@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 14 8B 4C 24 10 89 D8 25 FF FF FF 7F 3D FF FF 1F 40 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 3D 3D 8A 2E 12 40 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 2A 3D 6C DB 06 40 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 17 3D FF FF FF 3F 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 04 31 C0 31 D2 89 0C 24 89 5C 24 04 DD 04 24 D8 C8 D9 E8 DC F1 DD 40 28 D8 CA DC 40 20 D8 CA DC 40 18 D8 CA DC 40 10 D8 CA DC 40 08 D8 CA DC 00 DD 42 28 D8 CB DC 42 20 D8 CB DC 42 18 D8 CB DC 42 10 D8 CB DC 42 08 D8 CB DC 02 DE CB D9 CA DE C1 DE F9 D8 25 ?? ?? ?? ?? DD 04 24 DE F9 59 5B 5B C3 }
	condition:
		$pattern
}

rule pzero_f2dae7ca2a772f2d810c2045c2918c19 {
	meta:
		aliases = "pone, pzero"
		size = "181"
		objfiles = "e_j1@libm.a, e_j0@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 14 8B 4C 24 10 89 D8 25 FF FF FF 7F 3D FF FF 1F 40 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 3D 3D 8A 2E 12 40 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 2A 3D 6C DB 06 40 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 17 3D FF FF FF 3F 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 04 31 C0 31 D2 89 0C 24 89 5C 24 04 DD 04 24 D8 C8 DD 14 24 D9 E8 DC F1 DD 40 28 D8 CA DC 40 20 D8 CA DC 40 18 D8 CA DC 40 10 D8 CA DC 40 08 D8 CA DC 00 DD 42 20 D8 CB DC 42 18 D8 CB DC 42 10 D8 CB DC 42 08 D8 CB DC 02 58 5A 5B DE CB D9 CA D8 C1 DE FA DE C1 C3 }
	condition:
		$pattern
}

rule __stdio_seek_1464e31af6b22d0df08ae9bcb6dcd1f2 {
	meta:
		aliases = "__stdio_seek"
		size = "51"
		objfiles = "_cs_funcs@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 14 FF 74 24 18 FF 73 04 FF 33 8B 44 24 1C FF 70 04 E8 ?? ?? ?? ?? 83 C4 10 89 C1 85 D2 78 07 89 03 89 53 04 31 C9 89 C8 5A 59 5B C3 }
	condition:
		$pattern
}

rule token_2c3c15a3db8887fa1c5c6a9c6f013bdf {
	meta:
		aliases = "token"
		size = "395"
		objfiles = "ruserpass@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 A1 ?? ?? ?? ?? 0F B7 00 A8 0C 0F 85 71 01 00 00 8B 0D ?? ?? ?? ?? 8B 41 10 3B 41 18 73 09 0F B6 10 40 89 41 10 EB 0E 83 EC 0C 51 E8 ?? ?? ?? ?? 83 C4 10 89 C2 83 FA FF 0F 84 43 01 00 00 8D 42 F7 83 F8 01 76 CA 83 FA 20 74 C5 83 FA 2C 74 C0 83 FA FF 0F 84 28 01 00 00 BB ?? ?? ?? ?? 83 FA 22 74 2F EB 5E 83 FA 5C 75 25 8B 0D ?? ?? ?? ?? 8B 41 10 3B 41 18 73 09 0F B6 10 40 89 41 10 EB 0E 83 EC 0C 51 E8 ?? ?? ?? ?? 83 C4 10 89 C2 88 13 43 8B 0D ?? ?? ?? ?? 8B 41 10 3B 41 18 73 09 0F B6 10 40 89 41 10 EB 0E 83 EC 0C 51 E8 ?? ?? ?? ?? 83 C4 10 89 C2 83 FA FF 74 7F 83 FA 22 75 A4 EB 78 BB }
	condition:
		$pattern
}

rule dl_cleanup_161f3bf60b1851915ca132e7b06c82eb {
	meta:
		aliases = "dl_cleanup"
		size = "34"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 A1 ?? ?? ?? ?? EB 0F 8B 58 04 BA 01 00 00 00 E8 ?? ?? ?? ?? 89 D8 85 C0 75 ED 58 5A 5B C3 }
	condition:
		$pattern
}

rule fork_7c18923723de70858840b220850d26dc {
	meta:
		aliases = "__GI_fork, __libc_fork, fork"
		size = "38"
		objfiles = "fork@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 02 00 00 00 CD 80 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_getpid_79b35d357e5e26b5da72e4f104bc68d1 {
	meta:
		aliases = "__libc_getpid, getpid, __GI_getpid"
		size = "38"
		objfiles = "getpid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 14 00 00 00 CD 80 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule pause_9dc45fecb7ee36b9e63bda5dc8ef9b36 {
	meta:
		aliases = "__libc_pause, pause"
		size = "38"
		objfiles = "pause@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 1D 00 00 00 CD 80 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule inotify_init_87b6f02c863341e9844626e7c4e2525f {
	meta:
		aliases = "inotify_init"
		size = "38"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 23 01 00 00 CD 80 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 59 5B 5B C3 }
	condition:
		$pattern
}

rule sync_bc4fc496ae5c3cc53ea28f55c1e313c7 {
	meta:
		aliases = "sync"
		size = "33"
		objfiles = "sync@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 24 00 00 00 CD 80 89 C3 3D 00 F0 FF FF 76 09 E8 ?? ?? ?? ?? F7 DB 89 18 58 5A 5B C3 }
	condition:
		$pattern
}

rule getppid_8b59cc8e10976e7ab634e6a8cf99b63a {
	meta:
		aliases = "getppid"
		size = "38"
		objfiles = "getppid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 40 00 00 00 CD 80 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule getpgrp_37211c95a2ee10881d8908d35589cb33 {
	meta:
		aliases = "getpgrp"
		size = "38"
		objfiles = "getpgrp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 41 00 00 00 CD 80 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_setsid_3d2d52970292609e348bccdc3e873edc {
	meta:
		aliases = "setsid, __GI_setsid"
		size = "38"
		objfiles = "setsid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 42 00 00 00 CD 80 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule vhangup_c4a8b06b4ce655d753c5c6005f140b51 {
	meta:
		aliases = "vhangup"
		size = "38"
		objfiles = "vhangup@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 6F 00 00 00 CD 80 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule munlockall_691555f979705252316657628e5ce7c7 {
	meta:
		aliases = "munlockall"
		size = "38"
		objfiles = "munlockall@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 99 00 00 00 CD 80 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule sched_yield_ac4af533b0f701cb77ef62fccde391b7 {
	meta:
		aliases = "sched_yield"
		size = "38"
		objfiles = "sched_yield@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 9E 00 00 00 CD 80 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule getuid_f9f1b6a7048b12a12ee4d9d5fc6d99c6 {
	meta:
		aliases = "__GI_getuid, getuid"
		size = "38"
		objfiles = "getuid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 C7 00 00 00 CD 80 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule getgid_e51a2937fd84f0615e482e6fa6a4938a {
	meta:
		aliases = "__GI_getgid, getgid"
		size = "38"
		objfiles = "getgid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 C8 00 00 00 CD 80 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule geteuid_35bb592f3cb6ad0a2ce7945ed508d73f {
	meta:
		aliases = "__GI_geteuid, geteuid"
		size = "38"
		objfiles = "geteuid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 C9 00 00 00 CD 80 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule getegid_ced882226c792795cffb6eed960ae92b {
	meta:
		aliases = "__GI_getegid, getegid"
		size = "38"
		objfiles = "getegid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 CA 00 00 00 CD 80 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule authnone_marshal_555b23c3a80a1202a14bc1dc12935cc7 {
	meta:
		aliases = "authnone_marshal"
		size = "51"
		objfiles = "auth_none@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 31 D2 8B 5C 24 14 8B 80 98 00 00 00 85 C0 74 14 52 8B 53 04 FF 70 3C 83 C0 28 50 53 FF 52 0C 83 C4 10 89 C2 89 D0 5A 59 5B C3 }
	condition:
		$pattern
}

rule raise_39acc1f7927a4588da0ebe747ae56cef {
	meta:
		aliases = "__GI_raise, raise"
		size = "46"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 53 53 FF 74 24 18 50 E8 ?? ?? ?? ?? 89 C3 83 C4 10 31 C0 85 DB 74 0A E8 ?? ?? ?? ?? 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule __pthread_reset_main_thread_40344193dc7fcbc5731b195367bc1769 {
	meta:
		aliases = "__pthread_reset_main_thread"
		size = "138"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? FF 89 C3 74 51 83 EC 0C FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 FF 35 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 E8 ?? ?? ?? ?? 58 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? FF FF FF FF C7 05 ?? ?? ?? ?? FF FF FF FF 83 C4 10 E8 ?? ?? ?? ?? 89 43 14 89 1D ?? ?? ?? ?? 89 1B 89 5B 04 C7 43 44 ?? ?? ?? ?? C7 43 4C ?? ?? ?? ?? 59 5B 5B C3 }
	condition:
		$pattern
}

rule svc_exit_c665e6ed1803ce8657563c05b6a36df8 {
	meta:
		aliases = "svc_exit"
		size = "43"
		objfiles = "svc_run@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 83 EC 0C 89 C3 FF 30 E8 ?? ?? ?? ?? C7 03 00 00 00 00 E8 ?? ?? ?? ?? C7 00 00 00 00 00 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule daemon_480f8f2e5a92e105484c3b23fd86ecbc {
	meta:
		aliases = "daemon"
		size = "173"
		objfiles = "daemon@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 83 F8 FF 0F 84 90 00 00 00 85 C0 75 15 E8 ?? ?? ?? ?? 40 0F 84 80 00 00 00 E8 ?? ?? ?? ?? 85 C0 74 0A 83 EC 0C 6A 00 E8 ?? ?? ?? ?? 83 7C 24 10 00 75 10 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 7C 24 14 00 75 54 50 6A 00 6A 02 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C3 83 F8 FF 74 3B 50 50 6A 00 53 E8 ?? ?? ?? ?? 59 58 6A 01 53 E8 ?? ?? ?? ?? 58 5A 6A 02 53 E8 ?? ?? ?? ?? 83 C4 10 83 FB 02 7E 15 83 EC 0C 53 E8 ?? ?? ?? ?? 31 C0 83 C4 10 EB 07 83 C8 FF EB 02 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule _buf_2531250b243e888bc4676dd53e709880 {
	meta:
		aliases = "_buf"
		size = "52"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 89 C3 83 B8 9C 00 00 00 00 75 16 83 EC 0C 68 00 01 00 00 E8 ?? ?? ?? ?? 83 C4 10 89 83 9C 00 00 00 8B 83 9C 00 00 00 59 5B 5B C3 }
	condition:
		$pattern
}

rule getrpcent_81c6519b49771059483ba54677de91a1 {
	meta:
		aliases = "__GI_getrpcent, getrpcent"
		size = "62"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 89 C3 85 C0 74 29 83 38 00 75 1A 51 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 03 85 C0 74 0A 89 D8 5B 5A 5B E9 ?? ?? ?? ?? 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_endrpcent_bd2f9639e7d1af8916e6bb95c3f39a96 {
	meta:
		aliases = "endrpcent, __GI_endrpcent"
		size = "70"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 89 C3 85 C0 74 33 83 78 0C 00 75 2D 83 EC 0C FF 70 04 E8 ?? ?? ?? ?? 8B 03 83 C4 10 C7 43 04 00 00 00 00 85 C0 74 12 83 EC 0C 50 E8 ?? ?? ?? ?? C7 03 00 00 00 00 83 C4 10 58 5A 5B C3 }
	condition:
		$pattern
}

rule __GI_setrpcent_3e184e8c0e6e74b95947f89b03190145 {
	meta:
		aliases = "setrpcent, __GI_setrpcent"
		size = "81"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 89 C3 85 C0 74 3E 8B 00 85 C0 75 15 50 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 03 EB 09 83 EC 0C 50 E8 ?? ?? ?? ?? 59 FF 73 04 E8 ?? ?? ?? ?? C7 43 04 00 00 00 00 8B 44 24 20 83 C4 10 09 43 0C 58 5A 5B C3 }
	condition:
		$pattern
}

rule pthread_handle_sigcancel_55c3abdfaba018a92aee7b537470c132 {
	meta:
		aliases = "pthread_handle_sigcancel"
		size = "145"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 8B 5C 24 10 3D ?? ?? ?? ?? 75 0C 89 5C 24 10 58 5A 5B E9 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 2C 3B 05 ?? ?? ?? ?? 75 16 50 68 00 00 00 80 6A 00 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 80 78 42 00 74 32 80 78 40 00 75 2C 80 78 41 01 75 0E 50 50 8D 44 24 10 50 6A FF E8 ?? ?? ?? ?? 8B 50 28 85 D2 74 11 C7 40 28 00 00 00 00 50 50 6A 01 52 E8 ?? ?? ?? ?? 5B 58 5B C3 }
	condition:
		$pattern
}

rule __pthread_cleanup_push_defer_819fc91b2170d3d10726fa468f638e46 {
	meta:
		aliases = "_pthread_cleanup_push_defer, __pthread_cleanup_push_defer"
		size = "67"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 8B 5C 24 10 89 C2 8B 44 24 14 89 03 8B 44 24 18 89 43 04 0F BE 42 41 89 43 08 8B 42 3C 89 43 0C 85 C0 74 0B 39 C3 72 07 C7 43 0C 00 00 00 00 C6 42 41 00 89 5A 3C 58 5A 5B C3 }
	condition:
		$pattern
}

rule _pthread_cleanup_push_396754eec267f8bc840363f8ed6468b7 {
	meta:
		aliases = "_pthread_cleanup_push"
		size = "56"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 8B 5C 24 10 89 C2 8B 44 24 14 89 03 8B 44 24 18 89 43 04 8B 42 3C 89 43 0C 85 C0 74 0B 39 C3 72 07 C7 43 0C 00 00 00 00 89 5A 3C 58 5A 5B C3 }
	condition:
		$pattern
}

rule svcraw_reply_7ab9debaf3de65da513ff86a829e209e {
	meta:
		aliases = "svcraw_reply"
		size = "91"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 8B 80 BC 00 00 00 85 C0 74 42 8D 98 94 23 00 00 C7 80 94 23 00 00 00 00 00 00 51 51 8B 43 04 6A 00 53 FF 50 14 58 5A FF 74 24 1C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 14 83 EC 0C 8B 43 04 53 FF 50 10 B8 01 00 00 00 83 C4 10 EB 02 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule svcraw_recv_0aaf846171451055b9d5ee9915cb0e23 {
	meta:
		aliases = "svcraw_recv"
		size = "75"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 8B 90 BC 00 00 00 31 C0 85 D2 74 32 8D 9A 94 23 00 00 C7 82 94 23 00 00 01 00 00 00 50 50 8B 43 04 6A 00 53 FF 50 14 59 58 FF 74 24 1C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 95 C0 0F B6 C0 5B 5A 5B C3 }
	condition:
		$pattern
}

rule __rpc_thread_clnt_cleanup_9e0211c9a3dece7bb9d3b8e73a96c32a {
	meta:
		aliases = "__rpc_thread_clnt_cleanup"
		size = "54"
		objfiles = "clnt_simple@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 8B 98 A4 00 00 00 85 DB 74 1F 8B 13 85 D2 74 0D 83 EC 0C 8B 42 04 52 FF 50 10 83 C4 10 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 58 5A 5B C3 }
	condition:
		$pattern
}

rule svcraw_create_42727d921ba05f46adfea003e220f18f {
	meta:
		aliases = "svcraw_create"
		size = "118"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 8B 98 BC 00 00 00 85 DB 75 19 53 53 68 3C 25 00 00 6A 01 E8 ?? ?? ?? ?? 83 C4 10 89 C3 31 C0 85 DB 74 46 8D 83 AC 23 00 00 C7 83 60 22 00 00 00 00 00 00 89 83 84 22 00 00 8D 83 94 23 00 00 66 C7 83 64 22 00 00 00 00 C7 83 68 22 00 00 ?? ?? ?? ?? 6A 02 68 60 22 00 00 53 50 E8 ?? ?? ?? ?? 8D 83 60 22 00 00 83 C4 10 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_pthread_attr_init_4e5bb89c6c05416848fba09cdcb052c4 {
	meta:
		aliases = "pthread_attr_init, __GI_pthread_attr_init"
		size = "80"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? BA 00 00 20 00 8B 5C 24 10 29 C2 89 43 14 C7 03 00 00 00 00 C7 43 04 00 00 00 00 C7 43 08 00 00 00 00 C7 43 0C 01 00 00 00 C7 43 10 00 00 00 00 C7 43 1C 00 00 00 00 C7 43 18 00 00 00 00 89 53 20 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule __stdio_rfill_43dc2bdff889fd4ee81deae55001404f {
	meta:
		aliases = "__stdio_rfill"
		size = "40"
		objfiles = "_rfill@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 0C 8B 5C 24 14 8B 53 08 8B 43 0C 29 D0 50 52 53 E8 ?? ?? ?? ?? 8B 53 08 89 53 10 01 C2 89 53 14 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule __GI___glibc_strerror_r_2be96166dfc3e38afa56f176ba22bc43 {
	meta:
		aliases = "__glibc_strerror_r, __GI___glibc_strerror_r"
		size = "29"
		objfiles = "__glibc_strerror_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 0C 8B 5C 24 18 FF 74 24 1C 53 FF 74 24 1C E8 ?? ?? ?? ?? 89 D8 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule __GI_clnt_perror_3939fb0d85d1d07b440da8e59a520875 {
	meta:
		aliases = "clnt_perror, __GI_clnt_perror"
		size = "40"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 8B 1D ?? ?? ?? ?? FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 89 5C 24 24 89 44 24 20 83 C4 18 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mkdtemp_7bfb747448b41a38b8dff78295fb2599 {
	meta:
		aliases = "mkdtemp"
		size = "35"
		objfiles = "mkdtemp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 8B 5C 24 18 6A 02 53 E8 ?? ?? ?? ?? 85 C0 0F 94 C0 0F B6 C0 F7 D8 21 C3 83 C4 18 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_fdopen_f86f9bb4161332bb47cbe40ad7a050b3 {
	meta:
		aliases = "fdopen, __GI_fdopen"
		size = "50"
		objfiles = "fdopen@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 8B 5C 24 18 6A 03 53 E8 ?? ?? ?? ?? 83 C4 10 31 D2 83 F8 FF 74 12 53 6A 00 FF 74 24 1C 50 E8 ?? ?? ?? ?? 83 C4 10 89 C2 89 D0 5A 59 5B C3 }
	condition:
		$pattern
}

rule mktemp_165371c000a092e57a44d5b3dd84fa7c {
	meta:
		aliases = "mktemp"
		size = "32"
		objfiles = "mktemp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 8B 5C 24 18 6A 03 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 03 C6 03 00 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule jrand48_r_56cc6305f4f03b7c63b37749e6927c55 {
	meta:
		aliases = "__GI_jrand48_r, jrand48_r"
		size = "55"
		objfiles = "jrand48_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 8B 5C 24 18 FF 74 24 1C 53 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 15 0F B7 43 04 0F B7 53 02 C1 E0 10 09 D0 8B 54 24 18 89 02 31 D2 89 D0 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_nrand48_r_8d67804bee1aa758c9ea3a362ff8063b {
	meta:
		aliases = "nrand48_r, __GI_nrand48_r"
		size = "61"
		objfiles = "nrand48_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 8B 5C 24 18 FF 74 24 1C 53 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 1B 0F B7 43 04 C1 E0 0F 66 8B 53 02 66 D1 EA 0F B7 D2 09 D0 8B 54 24 18 89 02 31 D2 89 D0 5A 59 5B C3 }
	condition:
		$pattern
}

rule __kernel_sin_fc93a6850c6ac0c2e1939bf81d685439 {
	meta:
		aliases = "__kernel_sin"
		size = "233"
		objfiles = "k_sin@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 8B 5C 24 1C 8B 4C 24 18 89 D8 25 FF FF FF 7F DD 44 24 20 3D FF FF 3F 3E 7F 33 D9 7C 24 0E 66 8B 44 24 0E 80 CC 0C 89 0C 24 89 5C 24 04 66 89 44 24 0C DD 04 24 D9 6C 24 0C DB 5C 24 08 D9 6C 24 0E 8B 44 24 08 85 C0 0F 84 87 00 00 00 89 0C 24 89 5C 24 04 DD 04 24 D8 C8 83 7C 24 28 00 DD 04 24 D8 C9 DD 05 ?? ?? ?? ?? D8 CA DC 25 ?? ?? ?? ?? D8 CA DC 05 ?? ?? ?? ?? D8 CA DC 25 ?? ?? ?? ?? D8 CA DC 05 ?? ?? ?? ?? DD 05 ?? ?? ?? ?? 75 13 DD DC D9 C9 D9 CA DE C9 DE E2 DE C9 DD 04 24 DE C1 EB 24 D9 05 ?? ?? ?? ?? D8 CD D9 CA 89 0C 24 89 5C 24 04 D8 CB DE EA D9 CB DE C9 DE E3 DE C9 DE C1 DD }
	condition:
		$pattern
}

rule pthread_atfork_faed0347eb086b50d4509912335cc116 {
	meta:
		aliases = "pthread_atfork"
		size = "113"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 14 6A 18 E8 ?? ?? ?? ?? 89 C3 83 C4 10 B8 0C 00 00 00 85 DB 74 54 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 00 89 D9 8B 54 24 24 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 01 8B 54 24 2C 8D 4B 08 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 01 8B 54 24 34 8D 4B 10 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 83 C4 20 59 5B 5B C3 }
	condition:
		$pattern
}

rule clnt_pcreateerror_3d4cda24ff988d5d56eac6cc11771ee8 {
	meta:
		aliases = "clnt_pcreateerror"
		size = "33"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 14 8B 1D ?? ?? ?? ?? FF 74 24 1C E8 ?? ?? ?? ?? 5A 59 53 50 E8 ?? ?? ?? ?? 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule xdrrec_destroy_ffe6f3fc0c011f9c2cc796c4c9a4f0aa {
	meta:
		aliases = "xdrrec_destroy"
		size = "32"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 14 8B 44 24 1C 8B 58 0C FF 73 04 E8 ?? ?? ?? ?? 89 5C 24 20 83 C4 18 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule re_exec_9a961186e122e40bfefd7c4cabf20599 {
	meta:
		aliases = "re_exec"
		size = "43"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 14 8B 5C 24 1C 53 E8 ?? ?? ?? ?? 59 5A 6A 00 50 6A 00 50 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 28 F7 D0 C1 E8 1F 5B C3 }
	condition:
		$pattern
}

rule malloc_trim_9a842ca2d24efd70cb4d7bd983bc389e {
	meta:
		aliases = "malloc_trim"
		size = "34"
		objfiles = "free@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 14 8B 5C 24 1C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 D8 83 C4 18 BA ?? ?? ?? ?? 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_once_cancelhandler_a94de5eed754edbb1bd890ded79f6d49 {
	meta:
		aliases = "pthread_once_cancelhandler"
		size = "53"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 14 8B 5C 24 1C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 03 00 00 00 00 C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 44 24 20 ?? ?? ?? ?? 83 C4 18 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __regfree_afa23526cf9bf2917fd51194077a1c46 {
	meta:
		aliases = "regfree, __regfree"
		size = "76"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 14 8B 5C 24 1C FF 33 E8 ?? ?? ?? ?? C7 03 00 00 00 00 C7 43 04 00 00 00 00 C7 43 08 00 00 00 00 5A FF 73 10 E8 ?? ?? ?? ?? C7 43 10 00 00 00 00 80 63 1C F7 58 FF 73 14 E8 ?? ?? ?? ?? C7 43 14 00 00 00 00 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule gcvt_951db78c61c8723715c67f5febe68129 {
	meta:
		aliases = "gcvt"
		size = "49"
		objfiles = "gcvt@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 14 8B 5C 24 28 FF 74 24 20 FF 74 24 20 8B 44 24 2C 83 F8 11 7E 05 B8 11 00 00 00 50 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule __dn_expand_03d3132339aa15fbcbb02a08905e3ab7 {
	meta:
		aliases = "__dn_expand"
		size = "49"
		objfiles = "res_comp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 14 8B 5C 24 28 FF 74 24 2C 53 FF 74 24 2C FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 20 85 C0 7E 08 80 3B 2E 75 03 C6 03 00 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_getttyent_c72f818d00338906ed7da75d32c708ee {
	meta:
		aliases = "getttyent, __GI_getttyent"
		size = "678"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 83 3D ?? ?? ?? ?? 00 75 0F E8 ?? ?? ?? ?? 31 DB 85 C0 0F 84 83 02 00 00 83 3D ?? ?? ?? ?? 00 75 1E 83 EC 0C 68 00 10 00 00 E8 ?? ?? ?? ?? 83 C4 10 A3 ?? ?? ?? ?? 85 C0 75 05 E8 ?? ?? ?? ?? 50 A1 ?? ?? ?? ?? 83 C0 38 50 68 ?? ?? ?? ?? 8D 44 24 14 50 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C0 38 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 50 8B 1D ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 68 00 10 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 F0 01 00 00 51 51 6A 0A 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 30 8B 15 ?? ?? ?? ?? 8B 42 10 3B 42 18 73 09 0F B6 08 40 89 42 10 EB 0E 83 EC 0C 52 E8 ?? ?? ?? ?? 83 C4 10 89 C1 }
	condition:
		$pattern
}

rule __GI_xdr_u_long_58863c4d310a8f487d2c800dce404db2 {
	meta:
		aliases = "xdr_u_long, __GI_xdr_u_long"
		size = "88"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 8B 4C 24 20 8B 5C 24 24 8B 11 83 FA 01 74 0E 72 2D B8 01 00 00 00 83 FA 02 74 34 EB 30 50 50 8B 41 04 8D 54 24 1C 52 51 FF 10 83 C4 10 85 C0 74 1C 8B 44 24 14 89 03 B8 01 00 00 00 EB 11 50 50 8B 41 04 53 51 FF 50 04 83 C4 10 EB 02 31 C0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule xdr_uint8_t_13211a7794e717b20641112249629860 {
	meta:
		aliases = "xdr_uint8_t"
		size = "100"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 8B 4C 24 20 8B 5C 24 24 8B 11 83 FA 01 74 28 72 0C B8 01 00 00 00 83 FA 02 74 40 EB 3C 0F B6 03 89 44 24 14 8D 44 24 14 53 53 8B 51 04 50 51 FF 52 24 83 C4 10 EB 24 8D 44 24 14 52 52 8B 51 04 50 51 FF 52 20 83 C4 10 85 C0 74 0D 8B 44 24 14 88 03 B8 01 00 00 00 EB 02 31 C0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule __GI_xdr_u_short_8bdef77fd140b4597e3c4dd58e827100 {
	meta:
		aliases = "xdr_u_short, __GI_xdr_u_short"
		size = "100"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 8B 4C 24 20 8B 5C 24 24 8B 11 83 FA 01 74 28 72 0C B8 01 00 00 00 83 FA 02 74 40 EB 3C 0F B7 03 89 44 24 14 8D 44 24 14 53 53 8B 51 04 50 51 FF 52 04 83 C4 10 EB 24 8D 44 24 14 52 52 8B 51 04 50 51 FF 12 83 C4 10 85 C0 74 0E 8B 44 24 14 66 89 03 B8 01 00 00 00 EB 02 31 C0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule xdr_int8_t_d188b456a0fc9d30b6c266863314902e {
	meta:
		aliases = "xdr_int8_t"
		size = "100"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 8B 4C 24 20 8B 5C 24 24 8B 11 83 FA 01 74 28 72 0C B8 01 00 00 00 83 FA 02 74 40 EB 3C 0F BE 03 89 44 24 14 50 50 8B 51 04 8D 44 24 1C 50 51 FF 52 24 83 C4 10 EB 24 50 50 8B 41 04 8D 54 24 1C 52 51 FF 50 20 83 C4 10 85 C0 74 0D 8B 44 24 14 88 03 B8 01 00 00 00 EB 02 31 C0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule xdr_short_0ea138b62048424af272c7635a883ec1 {
	meta:
		aliases = "__GI_xdr_short, xdr_short"
		size = "100"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 8B 4C 24 20 8B 5C 24 24 8B 11 83 FA 01 74 28 72 0C B8 01 00 00 00 83 FA 02 74 40 EB 3C 0F BF 03 89 44 24 14 52 52 8B 51 04 8D 44 24 1C 50 51 FF 52 04 83 C4 10 EB 24 50 50 8B 41 04 8D 54 24 1C 52 51 FF 10 83 C4 10 85 C0 74 0E 8B 44 24 14 66 89 03 B8 01 00 00 00 EB 02 31 C0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule xdr_uint16_t_b800cb22db5e85cb5022f04924cce8d3 {
	meta:
		aliases = "xdr_uint16_t"
		size = "101"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 8B 4C 24 20 8B 5C 24 24 8B 11 83 FA 01 74 28 72 0C B8 01 00 00 00 83 FA 02 74 41 EB 3D 0F B7 03 89 44 24 14 8D 44 24 14 53 53 8B 51 04 50 51 FF 52 24 83 C4 10 EB 25 8D 44 24 14 52 52 8B 51 04 50 51 FF 52 20 83 C4 10 85 C0 74 0E 8B 44 24 14 66 89 03 B8 01 00 00 00 EB 02 31 C0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule xdr_int16_t_1cb331688ec6641d19d4d9d9bfabfb8f {
	meta:
		aliases = "xdr_int16_t"
		size = "101"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 8B 4C 24 20 8B 5C 24 24 8B 11 83 FA 01 74 28 72 0C B8 01 00 00 00 83 FA 02 74 41 EB 3D 0F BF 03 89 44 24 14 50 50 8B 51 04 8D 44 24 1C 50 51 FF 52 24 83 C4 10 EB 25 50 50 8B 41 04 8D 54 24 1C 52 51 FF 50 20 83 C4 10 85 C0 74 0E 8B 44 24 14 66 89 03 B8 01 00 00 00 EB 02 31 C0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule xdr_bool_4e9f9b2d3bf8218fc7144430ca6ec709 {
	meta:
		aliases = "__GI_xdr_bool, xdr_bool"
		size = "110"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 8B 4C 24 20 8B 5C 24 24 8B 11 83 FA 01 74 2D 72 0C B8 01 00 00 00 83 FA 02 74 4A EB 46 31 C0 83 3B 00 0F 95 C0 89 44 24 14 50 50 8B 51 04 8D 44 24 1C 50 51 FF 52 04 83 C4 10 EB 29 50 50 8B 41 04 8D 54 24 1C 52 51 FF 10 83 C4 10 85 C0 74 13 31 C0 83 7C 24 14 00 0F 95 C0 89 03 B8 01 00 00 00 EB 02 31 C0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule __GI_mbrtowc_037bbfafdc4cbdf64cb3a0c87ee6c57d {
	meta:
		aliases = "mbrtowc, __GI_mbrtowc"
		size = "111"
		objfiles = "mbrtowc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 8B 54 24 2C 8B 5C 24 20 8B 44 24 24 85 D2 75 05 BA ?? ?? ?? ?? 85 C0 75 0D 31 DB 8D 44 24 17 C6 44 24 17 00 EB 0C 80 38 00 74 37 83 7C 24 28 00 74 30 89 44 24 0C 83 EC 0C 52 6A 01 6A FF 8D 44 24 24 50 8D 44 24 2C 50 E8 ?? ?? ?? ?? 83 C4 20 89 C2 85 C0 78 0E 85 DB 74 0A 8B 44 24 10 89 03 EB 02 31 D2 89 D0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule __pthread_manager_adjust_prio_4cf96cf509d56d77450b73c19bc8e9a1 {
	meta:
		aliases = "__pthread_manager_adjust_prio"
		size = "76"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 8B 5C 24 20 3B 1D ?? ?? ?? ?? 7E 37 83 EC 0C 6A 01 E8 ?? ?? ?? ?? 83 C4 0C 39 C3 0F 9C C0 0F B6 C0 8D 04 03 89 44 24 18 8D 44 24 18 50 6A 01 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 1D ?? ?? ?? ?? 83 C4 10 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule __GI___fgetc_unlocked_a8c421194d2423dabb3cc9829e1d3697 {
	meta:
		aliases = "__GI_fgetc_unlocked, __fgetc_unlocked, __GI_getc_unlocked, fgetc_unlocked, getc_unlocked, __GI___fgetc_unlocked"
		size = "220"
		objfiles = "fgetc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 8B 5C 24 20 8B 43 10 3B 43 18 0F 82 99 00 00 00 0F B7 03 25 83 00 00 00 3D 80 00 00 00 77 18 52 52 68 80 00 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 97 00 00 00 8B 0B 0F B7 D1 F6 C2 02 74 19 83 E2 01 8D 41 FF 66 89 03 8A 54 93 24 C7 43 28 00 00 00 00 0F B6 D2 EB 77 8B 43 10 39 43 14 75 47 83 7B 04 FE 75 08 83 C9 04 66 89 0B EB 5E 80 E6 03 74 10 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 8B 43 08 39 43 0C 74 25 83 EC 0C 89 43 18 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 2E 8B 43 14 89 43 18 8B 43 10 0F B6 10 40 89 43 10 EB 1F 50 6A 01 8D 44 24 1F 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 }
	condition:
		$pattern
}

rule cos_47683ee3b207f8be56a14e0f5494bc8e {
	meta:
		aliases = "__GI_cos, cos"
		size = "206"
		objfiles = "s_cos@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 8B 5C 24 24 8B 4C 24 20 89 D8 25 FF FF FF 7F 3D FB 21 E9 3F 7F 08 6A 00 6A 00 53 51 EB 49 3D FF FF EF 7F 7E 11 89 0C 24 89 5C 24 04 DD 04 24 D8 E0 E9 8F 00 00 00 50 8D 44 24 0C 50 53 51 E8 ?? ?? ?? ?? 83 E0 03 83 C4 10 83 F8 01 74 23 83 F8 02 74 3C 85 C0 75 51 FF 74 24 14 FF 74 24 14 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? 83 C4 10 EB 54 83 EC 0C 6A 01 FF 74 24 24 FF 74 24 24 FF 74 24 24 FF 74 24 24 E8 ?? ?? ?? ?? D9 E0 EB 33 FF 74 24 14 FF 74 24 14 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? D9 E0 EB C4 83 EC 0C 6A 01 FF 74 24 24 FF 74 24 24 FF 74 24 24 FF 74 24 24 E8 ?? ?? ?? ?? 83 C4 }
	condition:
		$pattern
}

rule __GI_sin_6beb845958ec36fd93c9e4bb3934d9d4 {
	meta:
		aliases = "sin, __GI_sin"
		size = "211"
		objfiles = "s_sin@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 8B 5C 24 24 8B 4C 24 20 89 D8 25 FF FF FF 7F 3D FB 21 E9 3F 7F 0D 83 EC 0C 6A 00 6A 00 6A 00 53 51 EB 4E 3D FF FF EF 7F 7E 11 89 0C 24 89 5C 24 04 DD 04 24 D8 E0 E9 8F 00 00 00 50 8D 44 24 0C 50 53 51 E8 ?? ?? ?? ?? 83 E0 03 83 C4 10 83 F8 01 74 28 83 F8 02 74 3A 85 C0 75 54 83 EC 0C 6A 01 FF 74 24 24 FF 74 24 24 FF 74 24 24 FF 74 24 24 E8 ?? ?? ?? ?? 83 C4 20 EB 4F FF 74 24 14 FF 74 24 14 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? EB 35 83 EC 0C 6A 01 FF 74 24 24 FF 74 24 24 FF 74 24 24 FF 74 24 24 E8 ?? ?? ?? ?? D9 E0 EB C6 FF 74 24 14 FF 74 24 14 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? }
	condition:
		$pattern
}

rule tan_b533e0ef53539f0e37f74a0e917bdb5d {
	meta:
		aliases = "__GI_tan, tan"
		size = "117"
		objfiles = "s_tan@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 8B 5C 24 24 8B 4C 24 20 89 D8 25 FF FF FF 7F 3D FB 21 E9 3F 7F 0D 83 EC 0C 6A 01 6A 00 6A 00 53 51 EB 41 3D FF FF EF 7F 7E 0E 89 0C 24 89 5C 24 04 DD 04 24 D8 E0 EB 34 50 8D 44 24 0C 50 53 51 E8 ?? ?? ?? ?? 83 E0 01 BA 01 00 00 00 01 C0 29 C2 89 14 24 FF 74 24 24 FF 74 24 24 FF 74 24 24 FF 74 24 24 E8 ?? ?? ?? ?? 83 C4 20 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule shmat_35567290b38e544da9609921849fb1ce {
	meta:
		aliases = "shmat"
		size = "61"
		objfiles = "shmat@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 8D 44 24 14 52 52 6A 00 FF 74 24 30 50 FF 74 24 3C FF 74 24 38 6A 15 E8 ?? ?? ?? ?? 83 C4 20 89 C3 E8 ?? ?? ?? ?? 89 DA F7 D8 39 C3 77 04 8B 54 24 14 89 D0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule getmntent_d6559b2f58e82c3911df2c1b255845a3 {
	meta:
		aliases = "getmntent"
		size = "126"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 14 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 3D ?? ?? ?? ?? 00 75 1E 83 EC 0C 68 00 10 00 00 E8 ?? ?? ?? ?? 83 C4 10 A3 ?? ?? ?? ?? 85 C0 75 05 E8 ?? ?? ?? ?? 68 00 10 00 00 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 2C E8 ?? ?? ?? ?? 89 C3 58 5A 6A 01 8D 44 24 14 50 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule __new_exitfn_5804f9da6c28ae492f90d86857f28af9 {
	meta:
		aliases = "__new_exitfn"
		size = "171"
		objfiles = "__exit_handler@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 14 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 40 83 C4 10 39 C2 7D 39 C1 E2 04 50 50 8D 82 40 01 00 00 50 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 75 0D E8 ?? ?? ?? ?? C7 00 0C 00 00 00 EB 32 83 05 ?? ?? ?? ?? 14 A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 C3 40 C1 E3 04 A3 ?? ?? ?? ?? 03 1D ?? ?? ?? ?? C7 03 01 00 00 00 50 50 6A 01 8D 44 24 14 50 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule srand_5075175c64c996ac23d58ea27d247c13 {
	meta:
		aliases = "srandom, srand"
		size = "67"
		objfiles = "random@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 14 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 5A 68 ?? ?? ?? ?? FF 74 24 2C E8 ?? ?? ?? ?? 59 58 6A 01 53 E8 ?? ?? ?? ?? 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule sethostent_8a213a8f6bd19b77144b33cf03a9163a {
	meta:
		aliases = "sethostent"
		size = "63"
		objfiles = "gethostent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 14 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 5A 83 7C 24 28 00 0F 95 05 ?? ?? ?? ?? 6A 01 53 E8 ?? ?? ?? ?? 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule endutent_26d62957ad151890d825bd37e1b8c4f7 {
	meta:
		aliases = "endutent"
		size = "86"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 14 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 83 F8 FF 74 0C 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 C7 05 ?? ?? ?? ?? FF FF FF FF 52 52 6A 01 53 E8 ?? ?? ?? ?? 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule setpwent_c8677bf57d351f58f68849252919efb4 {
	meta:
		aliases = "setgrent, setspent, setpwent"
		size = "75"
		objfiles = "getgrent_r@libc.a, getpwent_r@libc.a, getspent_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 14 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 0C 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 50 50 6A 01 53 E8 ?? ?? ?? ?? 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule endgrent_388f7d68c5e644cf15134cf29cd318ff {
	meta:
		aliases = "endspent, endpwent, endgrent"
		size = "85"
		objfiles = "getgrent_r@libc.a, getpwent_r@libc.a, getspent_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 14 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 16 83 EC 0C 50 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 10 51 51 6A 01 53 E8 ?? ?? ?? ?? 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule endservent_0d96bf4fc2561ebab2649fbb03aaf667 {
	meta:
		aliases = "endnetent, __GI_endservent, __GI_endprotoent, endprotoent, __GI_endnetent, endservent"
		size = "92"
		objfiles = "getnetent@libc.a, getproto@libc.a, getservice@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 14 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 16 83 EC 0C 50 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 10 C6 05 ?? ?? ?? ?? 00 50 50 6A 01 53 E8 ?? ?? ?? ?? 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule endhostent_ce00f365e586a1d7d85c5423ffb69ec1 {
	meta:
		aliases = "endhostent"
		size = "92"
		objfiles = "gethostent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 14 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 C6 05 ?? ?? ?? ?? 00 85 C0 74 16 83 EC 0C 50 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 10 50 50 6A 01 53 E8 ?? ?? ?? ?? 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule closelog_6f8b191d7ca074aa37f3d8ba9e720d20 {
	meta:
		aliases = "__GI_closelog, closelog"
		size = "63"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 14 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 00 00 00 00 E8 ?? ?? ?? ?? 58 5A 6A 01 53 E8 ?? ?? ?? ?? 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule __GI_setutent_cd7c84a10d02e5b3ac34f2547c251a00 {
	meta:
		aliases = "setutent, __GI_setutent"
		size = "56"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 14 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 5A 6A 01 53 E8 ?? ?? ?? ?? 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule pututline_d01d7aa49f3c33ebd804440d0d5a6fe6 {
	meta:
		aliases = "pututline"
		size = "157"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 8B 5C 24 24 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 14 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 6A 01 68 80 FE FF FF FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 D8 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 0A 50 6A 01 68 80 FE FF FF EB 05 50 6A 02 6A 00 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 68 80 01 00 00 53 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A 3D 80 01 00 00 59 0F 94 C0 0F B6 C0 6A 01 F7 D8 21 C3 8D 44 24 14 50 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule utmpname_1a1a29705455203ee92794c5f99d1e4d {
	meta:
		aliases = "utmpname"
		size = "155"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 8B 5C 24 24 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 14 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 DB 74 37 A1 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 0C 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 A3 ?? ?? ?? ?? 85 C0 75 0A C7 05 ?? ?? ?? ?? ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 F8 FF 74 0C 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 50 50 6A 01 C7 05 ?? ?? ?? ?? FF FF FF FF 8D 44 24 14 50 E8 ?? ?? ?? ?? 31 C0 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule mallopt_b02f5f57e21c69f9c07ac1b85ee06361 {
	meta:
		aliases = "mallopt"
		size = "181"
		objfiles = "mallopt@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 8B 5C 24 28 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 14 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 8B 44 24 20 83 C0 04 83 F8 05 77 5B FF 24 85 ?? ?? ?? ?? 83 FB 50 77 4F BA 08 00 00 00 85 DB 74 0F 8D 43 0B B2 10 83 F8 0F 76 05 89 C2 83 E2 F8 A1 ?? ?? ?? ?? 83 E0 03 09 C2 89 15 ?? ?? ?? ?? EB 06 89 1D ?? ?? ?? ?? BB 01 00 00 00 EB 1A 89 1D ?? ?? ?? ?? EB F1 89 1D ?? ?? ?? ?? EB E9 89 1D ?? ?? ?? ?? EB E1 31 DB 50 50 6A 01 8D 44 24 14 50 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule __GI_gethostent_r_781786c1b9102efc492ef53b799e1d24 {
	meta:
		aliases = "gethostent_r, __GI_gethostent_r"
		size = "178"
		objfiles = "gethostent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 8B 5C 24 30 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 14 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 3D ?? ?? ?? ?? 00 75 1B E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 85 C0 75 0D C7 03 00 00 00 00 BB 02 00 00 00 EB 4E 83 EC 0C FF 74 24 3C 53 FF 74 24 3C FF 74 24 3C FF 74 24 3C 6A 01 6A 02 6A 00 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 30 89 C3 80 3D ?? ?? ?? ?? 00 75 1B 83 EC 0C FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 10 51 51 6A 01 8D 44 24 14 50 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule xdr_u_char_21f4916d548c55b3976e714f2e7b55e8 {
	meta:
		aliases = "xdr_u_char"
		size = "53"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8B 5C 24 2C 0F B6 03 89 44 24 1C 8D 44 24 1C 50 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 74 08 8B 44 24 14 B2 01 88 03 89 D0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule xdr_char_783c1091a76e3c374dee6e51b3d1a475 {
	meta:
		aliases = "xdr_char"
		size = "53"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8B 5C 24 2C 0F BE 03 89 44 24 1C 8D 44 24 1C 50 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 74 08 8B 44 24 14 B2 01 88 03 89 D0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule ftime_84ce1c5e150b989e9645c5b92c7c60a3 {
	meta:
		aliases = "ftime"
		size = "87"
		objfiles = "ftime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 10 8B 5C 24 28 50 8D 44 24 1C 50 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 2F 8B 44 24 10 BA E8 03 00 00 89 03 89 D1 8B 44 24 14 05 E7 03 00 00 99 F7 F9 66 89 43 04 31 D2 8B 44 24 08 66 89 43 06 8B 44 24 0C 66 89 43 08 89 D0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule getrlimit64_7985f53cfe332f81b440d0000b54ce39 {
	meta:
		aliases = "getrlimit64"
		size = "109"
		objfiles = "getrlimit64@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 18 8B 5C 24 2C 50 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 46 8B 44 24 10 83 F8 FF 75 0F C7 03 FF FF FF FF C7 43 04 FF FF FF FF EB 09 89 03 C7 43 04 00 00 00 00 8B 44 24 14 83 F8 FF 75 10 C7 43 08 FF FF FF FF C7 43 0C FF FF FF FF EB 0A 89 43 08 C7 43 0C 00 00 00 00 31 D2 89 D0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule sendto_d38dda3181a091ce13860e9a2f9eb52e {
	meta:
		aliases = "sendto"
		size = "70"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 1C 50 6A 01 E8 ?? ?? ?? ?? 58 5A FF 74 24 3C FF 74 24 3C FF 74 24 3C FF 74 24 3C FF 74 24 3C FF 74 24 3C E8 ?? ?? ?? ?? 83 C4 18 6A 00 89 C3 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule close_c5c195d89a383cbfa7d98141a0fc5e4a {
	meta:
		aliases = "close"
		size = "48"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 1C 50 6A 01 E8 ?? ?? ?? ?? 58 FF 74 24 2C E8 ?? ?? ?? ?? 59 89 C3 58 6A 00 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule __GI_nanosleep_6e99d212695ceec3891435901ea7973a {
	meta:
		aliases = "nanosleep, __GI_nanosleep"
		size = "53"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 1C 50 6A 01 E8 ?? ?? ?? ?? 59 5B FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 89 C3 58 5A 6A 00 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule recvfrom_0b5cad18b5f097bbcbb639ad3d5d601c {
	meta:
		aliases = "recvfrom"
		size = "70"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 1C 50 6A 01 E8 ?? ?? ?? ?? 59 5B FF 74 24 3C FF 74 24 3C FF 74 24 3C FF 74 24 3C FF 74 24 3C FF 74 24 3C E8 ?? ?? ?? ?? 83 C4 18 6A 00 89 C3 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule wait_f62998a482170cde13f7c89dcfb26a0d {
	meta:
		aliases = "system, fsync, tcdrain, wait"
		size = "48"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 1C 50 6A 01 E8 ?? ?? ?? ?? 59 FF 74 24 2C E8 ?? ?? ?? ?? 89 C3 58 5A 6A 00 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule __GI_waitpid_7fafe2d4042f052134436ac4f9e768f2 {
	meta:
		aliases = "lseek, accept, sendmsg, waitpid, __GI_waitpid"
		size = "58"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 1C 50 6A 01 E8 ?? ?? ?? ?? 83 C4 0C FF 74 24 2C FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 59 89 C3 58 6A 00 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule read_f76fa2a31d5e51010722d3c9bb015e20 {
	meta:
		aliases = "recvmsg, write, msync, connect, read"
		size = "58"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 1C 50 6A 01 E8 ?? ?? ?? ?? 83 C4 0C FF 74 24 2C FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 89 C3 58 5A 6A 00 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule open_c3e4c32824a18fe6219437d3ee788c33 {
	meta:
		aliases = "open"
		size = "66"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 1C 50 6A 01 E8 ?? ?? ?? ?? 8D 44 24 3C 89 44 24 20 83 C4 0C FF 74 24 2C FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 59 89 C3 58 6A 00 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule open64_766a79d83351659da9ab1ae56794f7b2 {
	meta:
		aliases = "fcntl, open64"
		size = "66"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 1C 50 6A 01 E8 ?? ?? ?? ?? 8D 44 24 3C 89 44 24 20 83 C4 0C FF 74 24 2C FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 89 C3 58 5A 6A 00 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule pause_cd038074e2abf5b2d7cfe1d35b0356fb {
	meta:
		aliases = "pause"
		size = "43"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 1C 50 6A 01 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 89 C3 58 6A 00 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule pwrite_6894871a989d3f602582424ca6f209e8 {
	meta:
		aliases = "pread, send, recv, pwrite"
		size = "60"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 1C 50 6A 01 E8 ?? ?? ?? ?? FF 74 24 3C FF 74 24 3C FF 74 24 3C FF 74 24 3C E8 ?? ?? ?? ?? 83 C4 18 6A 00 89 C3 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule fesetenv_812417178b5157999574ae078d78b64d {
	meta:
		aliases = "__GI_fesetenv, fesetenv"
		size = "230"
		objfiles = "fesetenv@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 D9 74 24 04 8B 5C 24 28 83 FB FF 75 2D 8B 44 24 04 C7 44 24 10 00 00 00 00 66 83 64 24 08 C2 66 81 64 24 16 00 F8 83 C8 3D 66 C7 44 24 14 00 00 80 E4 F3 66 89 44 24 04 EB 30 83 FB FE 66 8B 4C 24 16 75 37 66 81 64 24 04 C2 F3 66 83 64 24 08 C2 66 81 E1 00 F8 C7 44 24 10 00 00 00 00 66 C7 44 24 14 00 00 66 89 4C 24 16 C7 44 24 18 00 00 00 00 66 C7 44 24 1C 00 00 EB 5C 8B 13 8B 44 24 04 66 81 E2 3D 0C 66 25 C2 F3 66 81 E1 00 F8 09 D0 66 89 44 24 04 8B 53 04 8B 44 24 08 83 E2 3D 83 E0 C2 09 D0 66 89 44 24 08 8B 43 0C 89 44 24 10 8B 43 10 66 89 44 24 14 66 8B 43 12 66 25 FF 07 09 C1 66 }
	condition:
		$pattern
}

rule __fresetlockfiles_7661b92e2fb8972b4fed85af7237aa86 {
	meta:
		aliases = "__fresetlockfiles"
		size = "72"
		objfiles = "lockfile@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 24 8D 5C 24 20 53 E8 ?? ?? ?? ?? 59 58 6A 01 53 E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? EB 0F 52 52 50 8D 43 38 50 E8 ?? ?? ?? ?? 8B 5B 20 83 C4 10 85 DB 8D 44 24 14 75 E6 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule forkpty_a952664f2b85103cdc11d8880061adf4 {
	meta:
		aliases = "forkpty"
		size = "129"
		objfiles = "forkpty@libutil.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 24 FF 74 24 38 FF 74 24 38 FF 74 24 38 8D 44 24 28 50 8D 44 24 30 50 E8 ?? ?? ?? ?? 83 C4 20 40 74 52 E8 ?? ?? ?? ?? 89 C3 83 F8 FF 74 46 85 C0 75 27 83 EC 0C FF 74 24 20 E8 ?? ?? ?? ?? 58 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 28 83 EC 0C 6A 01 E8 ?? ?? ?? ?? 8B 44 24 20 8B 54 24 14 83 EC 0C 89 10 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 EB 03 83 CB FF 89 D8 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule __GI___res_init_8428edf922574b15d88a3ea678dc72a9 {
	meta:
		aliases = "__res_init, __GI___res_init"
		size = "289"
		objfiles = "res_init@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 2C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 20 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 05 00 00 00 C7 05 ?? ?? ?? ?? 04 00 00 00 C7 05 ?? ?? ?? ?? 01 00 00 00 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 66 A3 ?? ?? ?? ?? A0 ?? ?? ?? ?? 83 E0 F0 83 C4 10 83 C8 01 31 D2 C7 05 ?? ?? ?? ?? 00 00 00 00 66 C7 05 ?? ?? ?? ?? 02 00 66 C7 05 ?? ?? ?? ?? 00 35 A2 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? FF FF FF FF 85 C9 75 11 EB 13 8B 04 95 ?? ?? ?? ?? 89 04 95 ?? ?? ?? ?? 42 39 CA 7C ED 31 DB 83 3D ?? ?? ?? ?? 00 75 3E EB 44 52 52 8D 44 24 2C 50 FF 34 9D }
	condition:
		$pattern
}

rule _create_xid_c60d5fc9f1ccb407dd8c20d6d8a5beeb {
	meta:
		aliases = "_create_xid"
		size = "129"
		objfiles = "create_xid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 2C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 18 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 80 3D ?? ?? ?? ?? 00 75 2D 51 51 6A 00 8D 44 24 28 50 E8 ?? ?? ?? ?? 58 5A 68 ?? ?? ?? ?? 8B 44 24 2C 33 44 24 28 50 E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01 83 C4 10 8D 44 24 24 51 51 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 5A 6A 01 53 E8 ?? ?? ?? ?? 8B 44 24 34 83 C4 38 5B C3 }
	condition:
		$pattern
}

rule __GI_random_7c427e1235d31eff265f99d3e8c484d4 {
	meta:
		aliases = "random, __GI_random"
		size = "72"
		objfiles = "random@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 2C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 20 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 58 8D 44 24 2C 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 5A 6A 01 53 E8 ?? ?? ?? ?? 8B 44 24 34 83 C4 38 5B C3 }
	condition:
		$pattern
}

rule gethostent_5a5ce7ca8678f827c376a93af8ad0dc0 {
	meta:
		aliases = "gethostent"
		size = "89"
		objfiles = "gethostent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 2C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 20 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 04 24 8D 44 24 34 50 68 8A 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 18 6A 01 53 E8 ?? ?? ?? ?? 8B 44 24 34 83 C4 38 5B C3 }
	condition:
		$pattern
}

rule malloc_stats_75dfa012a8c55cf2cad16f02a4ccafe9 {
	meta:
		aliases = "malloc_stats"
		size = "87"
		objfiles = "mallinfo@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 38 8B 5C 24 40 85 DB 75 06 8B 1D ?? ?? ?? ?? 8D 44 24 10 83 EC 0C 50 E8 ?? ?? ?? ?? 8B 4C 24 2C 8B 44 24 38 8B 54 24 1C 83 EC 08 FF 74 24 48 FF 74 24 48 FF 74 24 40 50 51 FF 74 24 44 01 C8 52 01 CA 50 52 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 78 5B C3 }
	condition:
		$pattern
}

rule __GI_svcerr_progvers_4d64721feeeda0549c1e9bb533946bc6 {
	meta:
		aliases = "svcerr_progvers, __GI_svcerr_progvers"
		size = "84"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 38 8B 5C 24 40 8D 54 24 14 C7 44 24 0C 01 00 00 00 C7 44 24 10 00 00 00 00 8D 43 20 51 6A 0C 50 52 E8 ?? ?? ?? ?? 8B 44 24 54 C7 44 24 30 02 00 00 00 89 44 24 34 8B 44 24 58 89 44 24 38 58 5A 8B 53 08 8D 44 24 10 50 53 FF 52 0C 83 C4 48 5B C3 }
	condition:
		$pattern
}

rule __GI_svc_sendreply_c4325aa12a07e34f864ee830ad969556 {
	meta:
		aliases = "svc_sendreply, __GI_svc_sendreply"
		size = "84"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 38 8B 5C 24 40 8D 54 24 14 C7 44 24 0C 01 00 00 00 C7 44 24 10 00 00 00 00 8D 43 20 51 6A 0C 50 52 E8 ?? ?? ?? ?? 8B 44 24 58 C7 44 24 30 00 00 00 00 89 44 24 34 8B 44 24 54 89 44 24 38 58 5A 8B 53 08 8D 44 24 10 50 53 FF 52 0C 83 C4 48 5B C3 }
	condition:
		$pattern
}

rule __GI_svcerr_noprog_274116d571140389c7b4e9109bba7411 {
	meta:
		aliases = "svcerr_noprog, __GI_svcerr_noprog"
		size = "68"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 38 8B 5C 24 40 8D 54 24 14 C7 44 24 0C 01 00 00 00 C7 44 24 10 00 00 00 00 8D 43 20 51 6A 0C 50 52 E8 ?? ?? ?? ?? C7 44 24 30 01 00 00 00 58 5A 8B 53 08 8D 44 24 10 50 53 FF 52 0C 83 C4 48 5B C3 }
	condition:
		$pattern
}

rule svcerr_noproc_0e300fff4bf97e524dafa98c7019b520 {
	meta:
		aliases = "svcerr_noproc"
		size = "68"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 38 8B 5C 24 40 8D 54 24 14 C7 44 24 0C 01 00 00 00 C7 44 24 10 00 00 00 00 8D 43 20 51 6A 0C 50 52 E8 ?? ?? ?? ?? C7 44 24 30 03 00 00 00 58 5A 8B 53 08 8D 44 24 10 50 53 FF 52 0C 83 C4 48 5B C3 }
	condition:
		$pattern
}

rule svcerr_decode_9b4c5d0ae77c52c14d12b3ac3cd4f850 {
	meta:
		aliases = "__GI_svcerr_decode, svcerr_decode"
		size = "68"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 38 8B 5C 24 40 8D 54 24 14 C7 44 24 0C 01 00 00 00 C7 44 24 10 00 00 00 00 8D 43 20 51 6A 0C 50 52 E8 ?? ?? ?? ?? C7 44 24 30 04 00 00 00 58 5A 8B 53 08 8D 44 24 10 50 53 FF 52 0C 83 C4 48 5B C3 }
	condition:
		$pattern
}

rule svcerr_systemerr_70f8ec5717587086b873dbadf9fbd1ff {
	meta:
		aliases = "svcerr_systemerr"
		size = "68"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 38 8B 5C 24 40 8D 54 24 14 C7 44 24 0C 01 00 00 00 C7 44 24 10 00 00 00 00 8D 43 20 51 6A 0C 50 52 E8 ?? ?? ?? ?? C7 44 24 30 05 00 00 00 58 5A 8B 53 08 8D 44 24 10 50 53 FF 52 0C 83 C4 48 5B C3 }
	condition:
		$pattern
}

rule pmap_unset_70ae8c5b3bf4c1aa86425e39738467f7 {
	meta:
		aliases = "__GI_pmap_unset, pmap_unset"
		size = "178"
		objfiles = "pmap_clnt@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 38 8D 5C 24 20 C7 44 24 34 FF FF FF FF 89 D8 E8 ?? ?? ?? ?? 85 C0 0F 84 8C 00 00 00 68 90 01 00 00 68 90 01 00 00 8D 44 24 3C 50 FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 6A 02 68 A0 86 01 00 53 E8 ?? ?? ?? ?? 83 C4 20 89 C3 85 C0 74 5B 8B 44 24 40 C7 44 24 18 00 00 00 00 89 44 24 10 8B 44 24 44 89 44 24 14 C7 44 24 1C 00 00 00 00 8D 54 24 10 8D 44 24 30 8B 4B 04 FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? 6A 02 53 FF 11 83 C4 14 8B 43 04 53 FF 50 10 8B 44 24 40 83 C4 10 EB 02 31 C0 83 C4 38 5B C3 }
	condition:
		$pattern
}

rule timegm_0fc2f0f1b85eca5e9e77b706a54fbb43 {
	meta:
		aliases = "timegm"
		size = "55"
		objfiles = "timegm@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 3C 6A 30 6A 00 8D 5C 24 14 53 E8 ?? ?? ?? ?? 58 5A 68 ?? ?? ?? ?? 8D 44 24 24 50 E8 ?? ?? ?? ?? 83 C4 0C 53 6A 01 FF 74 24 4C E8 ?? ?? ?? ?? 83 C4 48 5B C3 }
	condition:
		$pattern
}

rule stat_1208af9499c9d71cb29f52272d72e6ef {
	meta:
		aliases = "__GI_stat, stat"
		size = "72"
		objfiles = "stat@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 48 8B 54 24 50 8D 4C 24 08 87 D3 B8 6A 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF EB 13 85 C0 75 0F 50 50 FF 74 24 5C 51 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 48 5B C3 }
	condition:
		$pattern
}

rule lstat_57b223931df8f8a60653acc308330bca {
	meta:
		aliases = "__GI_lstat, lstat"
		size = "72"
		objfiles = "lstat@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 48 8B 54 24 50 8D 4C 24 08 87 D3 B8 6B 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF EB 13 85 C0 75 0F 50 50 FF 74 24 5C 51 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 48 5B C3 }
	condition:
		$pattern
}

rule __GI_fstat_43d9ca03517d222bf60e4d6abe08f21a {
	meta:
		aliases = "fstat, __GI_fstat"
		size = "72"
		objfiles = "fstat@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 48 8B 54 24 50 8D 4C 24 08 87 D3 B8 6C 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF EB 13 85 C0 75 0F 50 50 FF 74 24 5C 51 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 48 5B C3 }
	condition:
		$pattern
}

rule __GI_fstatfs64_bdaa2a93a7b943a45b4b2e0a2e535741 {
	meta:
		aliases = "statfs64, fstatfs64, __GI_statfs64, __GI_fstatfs64"
		size = "165"
		objfiles = "statfs64@libc.a, fstatfs64@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 50 8D 44 24 10 8B 5C 24 5C 50 FF 74 24 5C E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 7E 8B 44 24 08 89 03 8B 44 24 0C 89 43 04 8B 44 24 10 C7 43 0C 00 00 00 00 89 43 08 8B 44 24 14 C7 43 14 00 00 00 00 89 43 10 8B 44 24 18 C7 43 1C 00 00 00 00 89 43 18 8B 44 24 1C C7 43 24 00 00 00 00 89 43 20 8B 44 24 20 C7 43 2C 00 00 00 00 89 43 28 8B 44 24 28 89 43 34 8B 44 24 24 89 43 30 8B 44 24 2C 89 43 38 50 6A 14 8D 44 24 3C 50 8D 43 40 50 E8 ?? ?? ?? ?? 31 D2 83 C4 10 89 D0 83 C4 48 5B C3 }
	condition:
		$pattern
}

rule __GI_vswprintf_44914d4aafefe118b306e92b942ce986 {
	meta:
		aliases = "vswprintf, __GI_vswprintf"
		size = "157"
		objfiles = "vswprintf@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 58 8B 54 24 60 8B 44 24 64 89 D3 C7 44 24 0C FD FF FF FF F7 D3 C1 EB 02 66 C7 44 24 08 50 08 C6 44 24 0A 00 C7 44 24 34 00 00 00 00 C7 44 24 28 00 00 00 00 39 C3 76 02 89 C3 8D 04 9A 89 54 24 10 89 44 24 14 89 54 24 18 89 54 24 1C 89 54 24 20 89 54 24 24 50 FF 74 24 70 FF 74 24 70 8D 44 24 14 50 E8 ?? ?? ?? ?? 89 C2 8B 44 24 24 83 C4 10 39 44 24 18 75 0E 83 CA FF 85 DB 74 15 83 E8 04 89 44 24 18 85 DB 74 0A 8B 44 24 18 C7 00 00 00 00 00 89 D0 83 C4 58 5B C3 }
	condition:
		$pattern
}

rule vswscanf_04d196883bd7a7c3dbfcef411e48df8f {
	meta:
		aliases = "__GI_vswscanf, vswscanf"
		size = "122"
		objfiles = "vswscanf@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 64 8B 5C 24 6C 89 5C 24 24 89 5C 24 1C 53 E8 ?? ?? ?? ?? 5A 8D 04 83 89 44 24 20 89 44 24 28 8D 44 24 4C 89 5C 24 2C 89 5C 24 30 C7 44 24 18 FD FF FF FF 8D 5C 24 14 66 C7 44 24 14 21 08 C6 44 24 16 00 C7 44 24 40 00 00 00 00 C7 44 24 48 01 00 00 00 50 E8 ?? ?? ?? ?? C7 44 24 38 00 00 00 00 83 C4 0C FF 74 24 6C FF 74 24 6C 53 E8 ?? ?? ?? ?? 83 C4 68 5B C3 }
	condition:
		$pattern
}

rule __GI_stat64_126c0c0d7ca05fdaa874caf75b60c026 {
	meta:
		aliases = "stat64, __GI_stat64"
		size = "72"
		objfiles = "stat64@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 68 8B 54 24 70 8D 4C 24 08 87 D3 B8 C3 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF EB 13 85 C0 75 0F 50 50 FF 74 24 7C 51 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 68 5B C3 }
	condition:
		$pattern
}

rule __GI_lstat64_d6460cf34be6386394961e1ecaaa02a9 {
	meta:
		aliases = "lstat64, __GI_lstat64"
		size = "72"
		objfiles = "lstat64@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 68 8B 54 24 70 8D 4C 24 08 87 D3 B8 C4 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF EB 13 85 C0 75 0F 50 50 FF 74 24 7C 51 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 68 5B C3 }
	condition:
		$pattern
}

rule __GI_fstat64_963b4acb8c2cb437e6a6cb16ccccc13e {
	meta:
		aliases = "fstat64, __GI_fstat64"
		size = "72"
		objfiles = "fstat64@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 68 8B 54 24 70 8D 4C 24 08 87 D3 B8 C5 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF EB 13 85 C0 75 0F 50 50 FF 74 24 7C 51 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 68 5B C3 }
	condition:
		$pattern
}

rule ftok_59f24aa05994d7e328d172e64dad5f1e {
	meta:
		aliases = "ftok"
		size = "59"
		objfiles = "ftok@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 70 8D 44 24 18 8B 5C 24 7C 50 FF 74 24 7C E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 14 0F B6 44 24 10 0F B7 54 24 1C C1 E0 10 C1 E3 18 09 C2 09 DA 89 D0 83 C4 68 5B C3 }
	condition:
		$pattern
}

rule pthread_insert_list_d8890819af1b1e3afc6d3a13c3208ec5 {
	meta:
		aliases = "pthread_insert_list"
		size = "36"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 85 D2 89 C3 74 1B 83 7C 24 08 00 75 05 EB 09 8D 58 04 8B 03 85 C0 75 F7 89 11 8B 03 89 41 04 89 0B 5B C3 }
	condition:
		$pattern
}

rule byte_store_op2_9f98f7ed00f156f1ae3e929a77342680 {
	meta:
		aliases = "byte_store_op2"
		size = "27"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 88 4A 01 8B 5C 24 08 88 02 C1 F9 08 88 5A 03 C1 FB 08 88 4A 02 88 5A 04 5B C3 }
	condition:
		$pattern
}

rule __pthread_alt_trylock_b8fab5bacd23b1291d19a4a3b400d199 {
	meta:
		aliases = "__pthread_alt_trylock"
		size = "43"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C1 83 EC 04 83 39 00 74 07 B8 10 00 00 00 EB 16 31 D2 BB 01 00 00 00 89 D0 F0 0F B1 19 0F 94 C2 84 D2 74 E0 31 C0 59 5B C3 }
	condition:
		$pattern
}

rule __pthread_trylock_bae437b6f55f460f0caf9a043c69d7bc {
	meta:
		aliases = "__pthread_trylock"
		size = "43"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C1 83 EC 04 83 39 00 74 07 B8 10 00 00 00 EB 16 31 D2 BB 01 00 00 00 89 D0 F0 0F B1 19 0F 94 C2 84 D2 74 E0 31 C0 5A 5B C3 }
	condition:
		$pattern
}

rule wait_node_free_fdd3dac2fbe59eb820e0203863acd391 {
	meta:
		aliases = "wait_node_free"
		size = "43"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C3 83 EC 08 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 89 03 89 1D ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 59 5B 5B C3 }
	condition:
		$pattern
}

rule scan_getwc_7f6718fd20dca61f3b520e82c12ad0ba {
	meta:
		aliases = "scan_getwc"
		size = "126"
		objfiles = "vfwscanf@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C3 83 EC 08 C7 40 24 FF FF FF FF FF 48 10 83 78 10 00 78 3D 80 78 19 00 75 4F 8B 50 08 83 7A 04 FD 75 1B 8B 42 10 3B 42 0C 73 0A 8B 08 83 C0 04 89 42 10 EB 22 C6 43 19 02 83 C8 FF EB 3A 83 EC 0C 52 E8 ?? ?? ?? ?? 83 C4 10 89 C1 83 F8 FF 75 06 80 4B 19 02 EB E2 8B 43 08 C6 43 1A 01 89 4B 04 8A 40 02 88 43 18 EB 04 C6 40 19 00 FF 43 0C 8B 43 04 89 43 24 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule pthread_call_handlers_8a67a4a8cb3771c54028fa121aec0196 {
	meta:
		aliases = "pthread_call_handlers"
		size = "21"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C3 83 EC 08 EB 05 FF 13 8B 5B 04 85 DB 75 F7 58 5A 5B C3 }
	condition:
		$pattern
}

rule __ether_line_3d6ab3ce1bc5dc2902173110a8db989a {
	meta:
		aliases = "__ether_line"
		size = "66"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C3 83 EC 10 52 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 26 EB 01 43 8A 03 84 C0 74 0B 3C 20 74 07 3C 09 75 F1 EB 01 43 8A 03 84 C0 74 0C 3C 20 74 F5 3C 09 74 F1 84 C0 75 02 31 DB 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __md5_to64_050f465771dae8fe78fb0e67cdde9a98 {
	meta:
		aliases = "__md5_to64"
		size = "27"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C3 EB 11 89 D0 C1 EA 06 83 E0 3F 8A 80 ?? ?? ?? ?? 88 03 43 49 79 EC 5B C3 }
	condition:
		$pattern
}

rule remove_from_queue_bddc60c439e8cadce80d14185a605e22 {
	meta:
		aliases = "remove_from_queue"
		size = "41"
		objfiles = "condvar@libpthread.a, semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C3 EB 1A 39 D1 75 13 8B 41 08 89 03 B8 01 00 00 00 C7 41 08 00 00 00 00 EB 0B 8D 59 08 8B 0B 85 C9 75 E0 31 C0 5B C3 }
	condition:
		$pattern
}

rule _dl_parse_relocation_informati_8b33979b53185afe1db1cb97db8fa35d {
	meta:
		aliases = "_dl_parse_relocation_information"
		size = "36"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 4C 24 0C 8B 5C 24 10 8B 00 8B 50 1C C7 44 24 0C ?? ?? ?? ?? 89 5C 24 08 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __isnan_a3058c025a33bf28be8c671cddf6ddc1 {
	meta:
		aliases = "__GI_isnan, __GI___isnan, isnan, __isnan"
		size = "40"
		objfiles = "s_isnan@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 54 24 0C 89 C1 89 D3 F7 D9 09 C1 81 E3 FF FF FF 7F C1 E9 1F B8 00 00 F0 7F 09 CB 29 D8 5B C1 E8 1F C3 }
	condition:
		$pattern
}

rule __libc_pread_ab437036bdc503b3efe105177bd491a7 {
	meta:
		aliases = "pread, __libc_pread"
		size = "35"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 54 24 0C 8B 5C 24 14 8B 4C 24 10 C7 44 24 0C 00 00 00 00 89 5C 24 08 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __libc_pwrite_836767b914a40cd805208d5b651fa233 {
	meta:
		aliases = "pwrite, __libc_pwrite"
		size = "35"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 54 24 0C 8B 5C 24 14 8B 4C 24 10 C7 44 24 0C 01 00 00 00 89 5C 24 08 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __ivaliduser_4cb977d63e8241d987efa085926f8e6e {
	meta:
		aliases = "iruserok, __ivaliduser"
		size = "35"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 54 24 0C 8B 5C 24 14 8B 4C 24 10 C7 44 24 0C ?? ?? ?? ?? 89 5C 24 08 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wmemset_e6e6029d0bd2d455dec444a1e46d2310 {
	meta:
		aliases = "wmemset"
		size = "29"
		objfiles = "wmemset@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 5C 24 0C 8B 4C 24 10 89 C2 EB 06 89 1A 49 83 C2 04 85 C9 75 F6 5B C3 }
	condition:
		$pattern
}

rule swab_bd8bdcabd296e119212f85a0bdbe88be {
	meta:
		aliases = "swab"
		size = "43"
		objfiles = "swab@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 10 8B 54 24 08 83 E0 FE 8B 4C 24 0C 8D 1C 02 EB 10 66 8B 02 83 C2 02 66 C1 C8 08 66 89 01 83 C1 02 39 DA 72 EC 5B C3 }
	condition:
		$pattern
}

rule __decode_header_d1271dc122a2ef348963ffc8626054ce {
	meta:
		aliases = "__decode_header"
		size = "171"
		objfiles = "decodeh@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 8B 5C 24 0C 0F B6 01 0F B6 51 01 C1 E0 08 09 D0 89 03 0F BE 41 02 C1 E8 1F 89 43 04 8A 41 02 C0 E8 03 83 E0 0F 89 43 08 0F B6 41 02 C1 E8 02 83 E0 01 89 43 0C 0F B6 41 02 D1 E8 83 E0 01 89 43 10 0F B6 41 02 83 E0 01 89 43 14 0F BE 41 03 C1 E8 1F 89 43 18 0F B6 41 03 83 E0 0F 89 43 1C 0F B6 41 04 0F B6 51 05 C1 E0 08 09 D0 89 43 20 0F B6 41 06 0F B6 51 07 C1 E0 08 09 D0 89 43 24 0F B6 41 08 0F B6 51 09 C1 E0 08 09 D0 89 43 28 0F B6 41 0A 0F B6 51 0B C1 E0 08 09 D0 89 43 2C B8 0C 00 00 00 5B C3 }
	condition:
		$pattern
}

rule __re_set_registers_e6bfe7b77c1a0c67d00b5a3ad25125f4 {
	meta:
		aliases = "re_set_registers, __re_set_registers"
		size = "75"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 8B 5C 24 10 8B 54 24 0C 85 DB 8A 41 1C 74 1B 83 E0 F9 83 C8 02 88 41 1C 89 1A 8B 44 24 14 89 42 04 8B 44 24 18 89 42 08 EB 1A 83 E0 F9 88 41 1C C7 02 00 00 00 00 C7 42 08 00 00 00 00 C7 42 04 00 00 00 00 5B C3 }
	condition:
		$pattern
}

rule __GI_isinf_a046a0c5dae8872fc96349a6c5714414 {
	meta:
		aliases = "__isinf, isinf, __GI___isinf, __GI_isinf"
		size = "43"
		objfiles = "s_isinf@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 08 89 C8 89 CB C1 FB 1E 25 FF FF FF 7F 35 00 00 F0 7F 09 D0 89 C2 F7 DA 09 D0 C1 F8 1F F7 D0 21 D8 5B C3 }
	condition:
		$pattern
}

rule _store_inttype_143c0b748ea92cd69f31844fa7264b88 {
	meta:
		aliases = "_store_inttype"
		size = "61"
		objfiles = "_store_inttype@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 5C 24 08 8B 44 24 10 8B 54 24 14 81 F9 00 01 00 00 75 04 88 03 EB 1E 81 F9 00 08 00 00 75 07 89 03 89 53 04 EB 0F 81 F9 00 02 00 00 75 05 66 89 03 EB 02 89 03 5B C3 }
	condition:
		$pattern
}

rule wmemcmp_2c8dc008ce43ffd5c93d6ad0081692b3 {
	meta:
		aliases = "wmemcmp"
		size = "47"
		objfiles = "wmemcmp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 10 8B 54 24 08 8B 44 24 0C EB 07 83 C2 04 83 C0 04 49 85 C9 74 08 8B 1A 3B 18 74 EF EB 04 31 C0 EB 07 3B 18 19 C0 83 C8 01 5B C3 }
	condition:
		$pattern
}

rule wcsncmp_982dd00bc05d934843418ef9760bbc4c {
	meta:
		aliases = "wcsncmp"
		size = "45"
		objfiles = "wcsncmp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 8B 5C 24 10 EB 0C 83 3A 00 74 15 83 C2 04 83 C1 04 4B 85 DB 74 0A 8B 02 3B 01 74 EA 2B 01 EB 02 31 C0 5B C3 }
	condition:
		$pattern
}

rule __GI___fpclassify_42fd13f78d9458654e37c4f691f31238 {
	meta:
		aliases = "__fpclassify, __GI___fpclassify"
		size = "61"
		objfiles = "s_fpclassify@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 0C 8B 44 24 08 89 D3 81 E2 00 00 F0 7F 81 E3 FF FF 0F 00 89 D1 09 C3 B8 02 00 00 00 09 D9 74 17 B0 03 85 D2 74 11 B0 04 81 FA 00 00 F0 7F 75 07 31 C0 85 DB 0F 94 C0 5B C3 }
	condition:
		$pattern
}

rule imaxabs_6fffb1da0cca1f26547089953ff51a6b {
	meta:
		aliases = "llabs, imaxabs"
		size = "30"
		objfiles = "llabs@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 0C 8B 44 24 08 89 D3 89 C1 89 DB C1 FB 1F 89 D9 31 DA 31 C8 29 C8 19 DA 5B C3 }
	condition:
		$pattern
}

rule __cmsg_nxthdr_1ff127c182c3798c7b767e3423486ee8 {
	meta:
		aliases = "__GI___cmsg_nxthdr, __cmsg_nxthdr"
		size = "59"
		objfiles = "cmsg_nxthdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 0C 8B 5C 24 08 8B 02 83 F8 0B 76 25 83 C0 03 83 E0 FC 8D 0C 02 8B 53 14 03 53 10 8D 41 0C 39 D0 77 0F 8B 01 83 C0 03 83 E0 FC 8D 04 01 39 D0 76 02 31 C9 89 C8 5B C3 }
	condition:
		$pattern
}

rule enqueue_38cc412bb8ab6fb18625bc5845bcdb8e {
	meta:
		aliases = "enqueue"
		size = "29"
		objfiles = "rwlock@libpthread.a, condvar@libpthread.a, semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5A 18 EB 0D 3B 59 18 7E 05 89 4A 08 EB 09 8D 41 08 8B 08 85 C9 75 ED 89 10 5B C3 }
	condition:
		$pattern
}

rule rand_r_1a5a8f8af44d4d13b4618f9f6c1a77d7 {
	meta:
		aliases = "rand_r"
		size = "82"
		objfiles = "rand_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 69 13 6D 4E C6 41 81 C2 39 30 00 00 89 D0 69 D2 6D 4E C6 41 C1 E8 06 81 C2 39 30 00 00 89 D1 25 00 FC 1F 00 69 D2 6D 4E C6 41 C1 E9 10 81 C2 39 30 00 00 81 E1 FF 03 00 00 89 13 31 C8 5B C1 EA 10 C1 E0 0A 81 E2 FF 03 00 00 31 D0 C3 }
	condition:
		$pattern
}

rule __fsetlocking_5d3630f74317fe8e044322da6d3ec7ed {
	meta:
		aliases = "__GI___fsetlocking, __fsetlocking"
		size = "41"
		objfiles = "__fsetlocking@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 4C 24 0C 85 C9 8B 43 34 74 13 BA 01 00 00 00 83 F9 02 74 06 8B 15 ?? ?? ?? ?? 89 53 34 83 E0 01 5B 40 C3 }
	condition:
		$pattern
}

rule wcsncat_3c851dcdfd197457eafede2860a481da {
	meta:
		aliases = "wcsncat"
		size = "58"
		objfiles = "wcsncat@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 0C 8B 4C 24 10 8B 54 24 08 8B 02 83 C2 04 85 C0 75 F7 83 EA 04 EB 07 83 C3 04 49 83 C2 04 85 C9 74 08 8B 03 89 02 85 C0 75 ED C7 02 00 00 00 00 8B 44 24 08 5B C3 }
	condition:
		$pattern
}

rule wcsncpy_6f5c2407a6a0ff32ae9479568d97c359 {
	meta:
		aliases = "wcsncpy"
		size = "40"
		objfiles = "wcsncpy@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 0C 8B 4C 24 10 8B 54 24 08 EB 0F 8B 03 89 02 85 C0 74 03 83 C3 04 83 C2 04 49 85 C9 75 ED 8B 44 24 08 5B C3 }
	condition:
		$pattern
}

rule wmemcpy_f4f538fd44ac6ad2caa16f5b50024a3e {
	meta:
		aliases = "__GI_wmemcpy, wmemcpy"
		size = "36"
		objfiles = "wmemcpy@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 10 8B 4C 24 08 8B 54 24 0C EB 0B 8B 02 4B 89 01 83 C2 04 83 C1 04 85 DB 75 F1 8B 44 24 08 5B C3 }
	condition:
		$pattern
}

rule wmempcpy_18fb2dfb65a0cd8d36b6ccd728c2b931 {
	meta:
		aliases = "__GI_wmempcpy, wmempcpy"
		size = "34"
		objfiles = "wmempcpy@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 10 8B 54 24 08 8B 4C 24 0C EB 0B 8B 01 4B 89 02 83 C1 04 83 C2 04 85 DB 75 F1 89 D0 5B C3 }
	condition:
		$pattern
}

rule memccpy_8d123573c37bb812cf900c3dca80f7c5 {
	meta:
		aliases = "__GI_memccpy, memccpy"
		size = "41"
		objfiles = "memccpy@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 14 8B 54 24 08 8B 4C 24 0C 4B 83 FB FF 74 0E 8A 01 88 02 42 3A 44 24 10 74 07 41 EB EC 31 C0 EB 02 89 D0 5B C3 }
	condition:
		$pattern
}

rule system_d8d804fc9c0bb2a518dacc45b21e1dab {
	meta:
		aliases = "__libc_system, system"
		size = "305"
		objfiles = "system@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 01 00 00 00 83 EC 28 83 7C 24 30 00 0F 84 18 01 00 00 51 51 6A 01 6A 03 E8 ?? ?? ?? ?? 89 44 24 1C 58 5A 6A 01 6A 02 E8 ?? ?? ?? ?? 89 44 24 20 5B 58 6A 00 6A 11 E8 ?? ?? ?? ?? 89 44 24 24 E8 ?? ?? ?? ?? 83 C4 10 89 C3 83 F8 00 7D 2F 51 51 FF 74 24 14 6A 03 E8 ?? ?? ?? ?? 58 5A FF 74 24 18 6A 02 E8 ?? ?? ?? ?? 5B 58 FF 74 24 1C 6A 11 E8 ?? ?? ?? ?? 83 C8 FF E9 AA 00 00 00 75 4A 51 51 6A 00 6A 03 E8 ?? ?? ?? ?? 58 5A 6A 00 6A 02 E8 ?? ?? ?? ?? 5B 58 6A 00 6A 11 E8 ?? ?? ?? ?? C7 04 24 00 00 00 00 FF 74 24 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 14 6A 7F E8 ?? }
	condition:
		$pattern
}

rule __sigismember_1e3ce8830f2033ddf0ba43e53074c277 {
	meta:
		aliases = "__sigismember"
		size = "36"
		objfiles = "sigsetops@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 01 00 00 00 8B 4C 24 0C 8B 54 24 08 49 89 CB 83 E1 1F C1 EB 05 D3 E0 85 04 9A 5B 0F 95 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule __sigaddset_0142825e4fdf7ee4497883501762b64a {
	meta:
		aliases = "__sigaddset"
		size = "32"
		objfiles = "sigsetops@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 01 00 00 00 8B 4C 24 0C 8B 5C 24 08 49 89 CA 83 E1 1F C1 EA 05 D3 E0 09 04 93 31 C0 5B C3 }
	condition:
		$pattern
}

rule __GI_pthread_setcancelstate_e69152c49fe6d340d85f388edd355f68 {
	meta:
		aliases = "pthread_setcancelstate, __GI_pthread_setcancelstate"
		size = "78"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) B8 16 00 00 00 83 EC 08 8B 5C 24 14 83 7C 24 10 01 77 36 E8 ?? ?? ?? ?? 85 DB 89 C2 74 06 0F BE 40 40 89 03 8A 44 24 10 88 42 40 80 7A 42 00 74 16 66 81 7A 40 00 01 75 0E 53 53 8D 44 24 10 50 6A FF E8 ?? ?? ?? ?? 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_pthread_setcanceltype_b2db65448c7f61950115a0bfc5e0f24b {
	meta:
		aliases = "pthread_setcanceltype, __GI_pthread_setcanceltype"
		size = "78"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) B8 16 00 00 00 83 EC 08 8B 5C 24 14 83 7C 24 10 01 77 36 E8 ?? ?? ?? ?? 85 DB 89 C2 74 06 0F BE 40 41 89 03 8A 44 24 10 88 42 41 80 7A 42 00 74 16 66 81 7A 40 00 01 75 0E 53 53 8D 44 24 10 50 6A FF E8 ?? ?? ?? ?? 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule sigset_1c5325946b236d507e834ef0973cdd2c {
	meta:
		aliases = "sigset"
		size = "283"
		objfiles = "sigset@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 20 00 00 00 81 EC A8 01 00 00 8B 94 24 B4 01 00 00 8B 9C 24 B0 01 00 00 83 FA 02 74 0D EB 49 C7 84 84 28 01 00 00 00 00 00 00 48 79 F2 50 50 53 8D 9C 24 34 01 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 88 C4 00 00 00 50 6A 00 53 6A 00 E8 ?? ?? ?? ?? 83 C4 10 BA 02 00 00 00 85 C0 0F 89 AC 00 00 00 E9 A4 00 00 00 83 FA FF 74 09 85 DB 7E 05 83 FB 40 7E 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 86 00 00 00 B8 20 00 00 00 89 94 24 9C 00 00 00 EB 0B C7 84 84 A0 00 00 00 00 00 00 00 48 79 F2 C7 84 24 20 01 00 00 00 00 00 00 51 8D 44 24 14 50 8D 84 24 A4 00 00 00 50 53 E8 ?? ?? ?? ?? 83 C4 10 BA 20 }
	condition:
		$pattern
}

rule __rpc_thread_variables_2eacb018e40c20fd9e2d1a267349a621 {
	meta:
		aliases = "__rpc_thread_variables"
		size = "225"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 ?? ?? ?? ?? 83 EC 08 85 C0 74 0F 83 EC 0C 6A 02 E8 ?? ?? ?? ?? 83 C4 10 EB 05 A1 ?? ?? ?? ?? 89 C3 85 C0 0F 85 B0 00 00 00 B8 ?? ?? ?? ?? 85 C0 74 16 50 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 EB 18 83 3D ?? ?? ?? ?? 00 75 0F E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 01 00 00 00 B8 ?? ?? ?? ?? 85 C0 74 0F 83 EC 0C 6A 02 E8 ?? ?? ?? ?? 83 C4 10 EB 05 A1 ?? ?? ?? ?? 89 C3 85 C0 75 56 50 50 68 C8 00 00 00 6A 01 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 74 20 B8 ?? ?? ?? ?? 85 C0 74 0F 50 50 53 6A 02 E8 ?? ?? ?? ?? 83 C4 10 EB 27 89 1D ?? ?? ?? ?? EB 1F B8 ?? ?? ?? ?? 85 C0 74 0F 83 EC 0C }
	condition:
		$pattern
}

rule __rpc_thread_destroy_2007302d19c4d3e78acf03dcf44ba7f9 {
	meta:
		aliases = "__rpc_thread_destroy"
		size = "190"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 ?? ?? ?? ?? 83 EC 08 85 C0 74 11 83 EC 0C 6A 02 E8 ?? ?? ?? ?? 83 C4 10 89 C3 EB 06 8B 1D ?? ?? ?? ?? 85 DB 0F 84 8E 00 00 00 81 FB ?? ?? ?? ?? 0F 84 82 00 00 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 0C FF B3 98 00 00 00 E8 ?? ?? ?? ?? 58 FF B3 9C 00 00 00 E8 ?? ?? ?? ?? 58 FF B3 A0 00 00 00 E8 ?? ?? ?? ?? 58 FF B3 BC 00 00 00 E8 ?? ?? ?? ?? 58 FF B3 AC 00 00 00 E8 ?? ?? ?? ?? 58 FF B3 B0 00 00 00 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 83 C4 10 85 C0 74 10 51 51 6A 00 6A 02 E8 ?? ?? ?? ?? 83 C4 10 EB 0A C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 58 5A 5B C3 }
	condition:
		$pattern
}

rule __old_sem_wait_f89baa5f4dcd914fc6cf5202106503f0 {
	meta:
		aliases = "__old_sem_wait"
		size = "317"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) B8 ?? ?? ?? ?? 83 EC 18 8D 54 24 18 8B 5C 24 20 3B 15 ?? ?? ?? ?? 73 3F 3B 15 ?? ?? ?? ?? 72 0D B8 ?? ?? ?? ?? 3B 15 ?? ?? ?? ?? 72 2A 83 3D ?? ?? ?? ?? 00 74 15 E8 ?? ?? ?? ?? EB 1A 8B 44 24 14 8B 40 08 89 01 E9 D1 00 00 00 81 CA FF FF 1F 00 8D 82 21 FE FF FF 89 44 24 14 C7 44 24 0C 00 00 00 00 C7 44 24 10 ?? ?? ?? ?? 8B 44 24 14 8D 54 24 0C E8 ?? ?? ?? ?? 8B 0B F6 C1 01 74 0A 83 F9 01 74 05 8D 51 FE EB 0B 8B 54 24 14 8B 44 24 14 89 48 08 89 C8 F0 0F B1 13 0F 94 C1 84 C9 74 D7 80 E2 01 0F 85 80 00 00 00 8B 44 24 14 83 EC 0C 50 E8 ?? ?? ?? ?? 8B 44 24 24 31 D2 E8 ?? ?? ?? ?? 8B 44 24 24 83 }
	condition:
		$pattern
}

rule __sigdelset_7137c81630271ad6795492ce54ea1557 {
	meta:
		aliases = "__sigdelset"
		size = "32"
		objfiles = "sigsetops@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 FE FF FF FF 8B 4C 24 0C 8B 5C 24 08 49 89 CA 83 E1 1F C1 EA 05 D3 C0 21 04 93 31 C0 5B C3 }
	condition:
		$pattern
}

rule set_input_fragment_5bc0b3b11d88af699eecb3597c5e49fa {
	meta:
		aliases = "set_input_fragment"
		size = "69"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B9 04 00 00 00 83 EC 18 89 C3 8D 54 24 14 E8 ?? ?? ?? ?? 85 C0 74 26 8B 54 24 14 0F CA 89 D0 89 54 24 14 C1 E8 1F 85 D2 89 43 38 74 10 81 E2 FF FF FF 7F B8 01 00 00 00 89 53 34 EB 02 31 C0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule sigpending_e6e1bc547f729f5928e5808ae8d5818b {
	meta:
		aliases = "sigpending"
		size = "51"
		objfiles = "sigpending@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B9 08 00 00 00 83 EC 08 8B 54 24 10 87 D3 B8 B0 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_sigsuspend_cfeb270bade9c6e47c7706f09109782c {
	meta:
		aliases = "__libc_sigsuspend, sigsuspend, __GI_sigsuspend"
		size = "51"
		objfiles = "sigsuspend@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B9 08 00 00 00 83 EC 08 8B 54 24 10 87 D3 B8 B3 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule load_field_b9cbf83bde4576ad83b3146bde23b5fc {
	meta:
		aliases = "load_field"
		size = "61"
		objfiles = "strftime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B9 6D 01 00 00 8B 14 82 8A 98 ?? ?? ?? ?? 83 F8 07 74 15 83 F8 05 74 05 0F B6 CB EB 0B 81 C2 6C 07 00 00 B9 0F 27 00 00 39 CA 77 09 83 F8 03 75 07 85 D2 75 03 83 CA FF 89 D0 5B C3 }
	condition:
		$pattern
}

rule brk_96a8dd69d54fc6d1396ff8dd54350fab {
	meta:
		aliases = "__GI_brk, brk"
		size = "54"
		objfiles = "brk@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BA 2D 00 00 00 83 EC 08 89 D0 8B 5C 24 10 89 D9 89 DB CD 80 89 CB 31 C9 A3 ?? ?? ?? ?? 39 D8 73 0E E8 ?? ?? ?? ?? 83 C9 FF C7 00 0C 00 00 00 89 C8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __uClibc_fini_7420dc9aa618aef83c0f21bd110df823 {
	meta:
		aliases = "__GI___uClibc_fini, __uClibc_fini"
		size = "63"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BB ?? ?? ?? ?? 81 EB ?? ?? ?? ?? 83 EC 08 C1 FB 02 EB 07 FF 14 9D ?? ?? ?? ?? 4B 83 FB FF 75 F3 A1 ?? ?? ?? ?? 85 C0 74 02 FF D0 8B 0D ?? ?? ?? ?? 85 C9 74 05 5B 58 5B FF E1 58 5A 5B C3 }
	condition:
		$pattern
}

rule atexit_281742c794a17c521544e0b44af3191b {
	meta:
		aliases = "atexit"
		size = "48"
		objfiles = "atexits@uclibc_nonshared.a"
	strings:
		$pattern = { ( CC | 53 ) E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 83 EC 08 31 D2 8B 83 ?? ?? ?? ?? 85 C0 74 02 8B 10 50 52 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule byte_regex_compile_06f9e515fb55aa765370b4e0f7178e5f {
	meta:
		aliases = "byte_regex_compile"
		size = "11332"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 01 C2 89 E5 57 56 53 81 EC 6C 01 00 00 89 85 DC FE FF FF 89 45 F0 8B 45 08 89 8D D8 FE FF FF 89 95 08 FF FF FF 8B 40 14 89 85 0C FF FF FF C7 04 24 80 02 00 00 E8 ?? ?? ?? ?? 85 C0 89 C3 0F 84 D9 01 00 00 8B 55 08 8B 8D D8 FE FF FF 80 62 1C 97 89 4A 0C A1 ?? ?? ?? ?? C7 42 08 00 00 00 00 C7 42 18 00 00 00 00 85 C0 0F 84 D2 01 00 00 8B 75 08 89 9D 3C FF FF FF 8B 7E 04 85 FF 0F 84 4C 01 00 00 8B 75 08 31 C0 89 85 50 FF FF FF 31 C0 89 85 40 FF FF FF 31 C0 89 85 18 FF FF FF 31 C0 8B 3E 89 85 14 FF FF FF 31 C0 89 85 34 FF FF FF B8 20 00 00 00 89 85 38 FF FF FF 89 BD 10 FF FF FF 8B 45 F0 39 85 08 }
	condition:
		$pattern
}

rule __gthread_active_p_e0763f81f247ccb6313a6363fe1d24ce {
	meta:
		aliases = "_Unwind_GetRegionStart, _Unwind_GetTextRelBase, _Unwind_FindEnclosingFunction, __udiv_w_sdiv, _Unwind_GetDataRelBase, __gthread_active_p"
		size = "7"
		objfiles = "unwind_sjlj@libgcc.a, _udiv_w_sdiv@libgcc.a, gthr_gnat@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 31 C0 89 E5 5D C3 }
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

rule __ffssi2_f28932962eec5c751b739c0689c4967f {
	meta:
		aliases = "__ffssi2"
		size = "18"
		objfiles = "_ffssi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 31 C0 89 E5 8B 55 08 85 D2 74 04 0F BC C2 40 5D C3 }
	condition:
		$pattern
}

rule __popcountsi2_7a6d660c03a39e1ef0aeb24633600619 {
	meta:
		aliases = "__popcountsi2"
		size = "82"
		objfiles = "_popcountsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 31 C9 89 E5 56 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 45 08 8B B3 ?? ?? ?? ?? 0F B6 D0 5B 8A 0C 16 0F B6 D4 C1 E8 10 8A 14 16 81 E2 FF 00 00 00 01 D1 0F B6 D0 C1 E8 08 8A 14 16 8A 04 06 81 E2 FF 00 00 00 01 D1 25 FF 00 00 00 01 C8 5E 5D C3 }
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

rule __popcountdi2_4d60b3d07fd1fd74f342b314436ccd1e {
	meta:
		aliases = "__popcountdi2"
		size = "101"
		objfiles = "_popcountdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 31 C9 89 E5 57 56 53 83 EC 0C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 45 08 8B 55 0C 89 45 E8 89 55 EC 31 F6 8B BB ?? ?? ?? ?? 90 8D 74 26 00 8B 55 EC 8B 45 E8 0F AD D0 D3 EA F6 C1 20 74 04 89 D0 31 D2 25 FF 00 00 00 83 C1 08 8A 04 07 25 FF 00 00 00 01 C6 83 F9 40 75 D5 83 C4 0C 89 F0 5B 5E 5F 5D C3 }
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

rule _Unwind_GetCFA_26c19aabc2fd48c58b068b92ea63b845 {
	meta:
		aliases = "_Unwind_GetCFA"
		size = "21"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 31 D2 89 E5 8B 45 08 8B 00 85 C0 74 03 8B 50 28 89 D0 5D C3 }
	condition:
		$pattern
}

rule mmap64_a5c3135a6cedbfd7327ca5f28ba365ea {
	meta:
		aliases = "mmap64"
		size = "88"
		objfiles = "mmap64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 56 57 8B 54 24 28 8B 4C 24 2C F7 C2 FF 0F 00 00 75 36 0F AC CA 0C C1 E9 0C 75 2D 89 D5 8B 5C 24 14 8B 4C 24 18 8B 54 24 1C 8B 74 24 20 8B 7C 24 24 B8 C0 00 00 00 CD 80 5F 5E 5B 5D 3D 01 F0 FF FF 0F 87 ?? ?? ?? ?? C3 5F 5E 5B 5D B8 EA FF FF FF E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __libc_posix_fadvise64_1511e449734dfa79da8f4d5a23eebe5a {
	meta:
		aliases = "__GI___libc_posix_fadvise64, __libc_posix_fadvise64"
		size = "42"
		objfiles = "posix_fadvise64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 56 57 B8 10 01 00 00 8B 5C 24 14 8B 4C 24 18 8B 54 24 1C 8B 74 24 20 8B 7C 24 24 8B 6C 24 28 CD 80 5F 5E 5B 5D F7 D8 C3 }
	condition:
		$pattern
}

rule _dl_load_elf_shared_library_186eb88a12ee797af8e93823e97ea5ce {
	meta:
		aliases = "_dl_load_elf_shared_library"
		size = "2690"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 0C 01 00 00 31 C9 31 D2 8B BC 24 28 01 00 00 53 89 FB B8 05 00 00 00 CD 80 5B 89 44 24 1C 3D 00 F0 FF FF 76 09 F7 D8 A3 ?? ?? ?? ?? EB 07 83 7C 24 1C 00 79 0F C7 05 ?? ?? ?? ?? 01 00 00 00 E9 29 0A 00 00 8D 8C 24 C8 00 00 00 8B 44 24 1C 53 89 C3 B8 6C 00 00 00 CD 80 5B 89 C2 3D 00 F0 FF FF 76 09 F7 D8 A3 ?? ?? ?? ?? EB 04 85 D2 79 0C C7 05 ?? ?? ?? ?? 01 00 00 00 EB 14 83 BC 24 20 01 00 00 00 74 1E F6 84 24 D1 00 00 00 08 75 14 8B 7C 24 1C 53 89 FB B8 06 00 00 00 CD 80 5B E9 C9 07 00 00 8B 2D ?? ?? ?? ?? EB 44 31 D2 0F B7 84 24 C8 00 00 00 39 95 E0 00 00 00 75 2F 39 85 DC 00 }
	condition:
		$pattern
}

rule __decode_answer_ef2d381c69cefba15404a63fcbf1bc80 {
	meta:
		aliases = "__decode_answer"
		size = "249"
		objfiles = "decodea@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 0C 01 00 00 8B 9C 24 24 01 00 00 8B B4 24 28 01 00 00 8B AC 24 2C 01 00 00 68 00 01 00 00 8D 44 24 10 50 53 FF B4 24 2C 01 00 00 E8 ?? ?? ?? ?? 83 C4 10 89 C7 85 C0 0F 88 A9 00 00 00 01 C3 29 DE 89 5C 24 04 83 EE 0A 89 74 24 08 79 07 89 F7 E9 91 00 00 00 8B 9C 24 20 01 00 00 03 5C 24 04 83 EC 0C 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 45 00 8D 73 04 0F B6 03 0F B6 53 01 C1 E0 08 09 D0 89 45 04 0F B6 43 02 0F B6 53 03 C1 E0 08 09 D0 89 45 08 0F B6 53 04 0F B6 46 01 C1 E2 18 C1 E0 10 0F B6 4E 02 C1 E1 08 09 C2 0F B6 46 03 09 C2 09 D1 89 4D 0C 0F B6 53 08 0F B6 43 09 C1 E2 08 83 C3 0A }
	condition:
		$pattern
}

rule __decode_question_7d1ebebb86dcc250d2627e3a9fff7437 {
	meta:
		aliases = "__decode_question"
		size = "126"
		objfiles = "decodeq@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 0C 01 00 00 8B 9C 24 24 01 00 00 8B BC 24 28 01 00 00 68 00 01 00 00 8D 6C 24 10 55 53 FF B4 24 2C 01 00 00 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 78 39 83 EC 0C 01 C3 83 C6 04 55 E8 ?? ?? ?? ?? 89 07 03 9C 24 30 01 00 00 83 C4 10 0F B6 03 0F B6 53 01 C1 E0 08 09 D0 89 47 04 0F B6 43 02 0F B6 53 03 C1 E0 08 09 D0 89 47 08 81 C4 0C 01 00 00 89 F0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule clnt_spcreateerror_10be61839cb9211d2c9adbbc13b00bcd {
	meta:
		aliases = "__GI_clnt_spcreateerror, clnt_spcreateerror"
		size = "242"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 0C 04 00 00 E8 ?? ?? ?? ?? 89 C5 85 C0 0F 84 CC 00 00 00 E8 ?? ?? ?? ?? 53 FF B4 24 24 04 00 00 89 C7 68 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? FF 37 8D 5C 05 00 E8 ?? ?? ?? ?? 83 C4 0C 50 53 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 01 C3 8B 07 83 F8 0C 74 3E 83 F8 0E 75 7D 51 51 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 FF 77 04 01 C3 E8 ?? ?? ?? ?? 52 50 53 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 01 C3 EB 44 50 50 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 0C 68 00 04 00 00 8D 34 03 8D 5C 24 14 53 FF 77 08 E8 ?? ?? ?? ?? 5F }
	condition:
		$pattern
}

rule __GI_svc_getreq_common_cbd53753f74fe454690dd2bb1105795b {
	meta:
		aliases = "svc_getreq_common, __GI_svc_getreq_common"
		size = "413"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 0C 05 00 00 8D 44 24 0C 89 84 24 D8 04 00 00 8D 84 24 9C 01 00 00 89 84 24 E4 04 00 00 E8 ?? ?? ?? ?? 89 C5 8B 90 B4 00 00 00 8B 84 24 20 05 00 00 8B 1C 82 85 DB 0F 84 50 01 00 00 50 50 8B 43 08 8D B4 24 C4 04 00 00 56 53 FF 10 83 C4 10 85 C0 0F 84 0E 01 00 00 8D 84 24 2C 03 00 00 8D 94 24 F8 04 00 00 89 84 24 04 05 00 00 8B 84 24 C8 04 00 00 89 84 24 EC 04 00 00 8B 84 24 CC 04 00 00 89 84 24 F0 04 00 00 8B 84 24 D0 04 00 00 89 84 24 F4 04 00 00 8D 84 24 D4 04 00 00 89 9C 24 08 05 00 00 57 6A 0C 50 52 E8 ?? ?? ?? ?? 83 C4 10 83 BC 24 D4 04 00 00 00 75 1F 8B 94 24 08 05 00 00 }
	condition:
		$pattern
}

rule vfwscanf_64728dd51e6d5c8124d33ef502ffe06c {
	meta:
		aliases = "__GI_vfwscanf, vfwscanf"
		size = "1712"
		objfiles = "vfwscanf@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 10 01 00 00 C7 44 24 4C FF FF FF FF 6A 24 6A 00 8D 44 24 30 50 E8 ?? ?? ?? ?? 8B 84 24 30 01 00 00 8B 40 34 89 44 24 20 83 C4 10 85 C0 75 29 8B 9C 24 20 01 00 00 50 83 C3 38 53 68 ?? ?? ?? ?? 8D 84 24 FC 00 00 00 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 50 50 FF B4 24 28 01 00 00 8D 84 24 BC 00 00 00 50 E8 ?? ?? ?? ?? 8B 84 24 C8 00 00 00 C7 84 24 EC 00 00 00 ?? ?? ?? ?? 8B 9C 24 34 01 00 00 8A 40 03 C7 84 24 FC 00 00 00 ?? ?? ?? ?? 88 84 24 D8 00 00 00 C7 44 24 68 00 00 00 00 C6 44 24 1F 01 83 C4 10 E9 32 05 00 00 80 A4 24 C9 00 00 00 01 C6 44 24 68 01 C6 44 24 69 }
	condition:
		$pattern
}

rule ether_hostton_90c8c13d7e86aeff3c582a48f8c86c74 {
	meta:
		aliases = "ether_hostton"
		size = "138"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 14 01 00 00 83 CB FF 8B AC 24 28 01 00 00 8B BC 24 2C 01 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 74 4A EB 21 31 DB EB 38 89 FA 89 D8 E8 ?? ?? ?? ?? 85 C0 74 10 52 52 50 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 DF 50 56 68 00 01 00 00 8D 5C 24 18 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 CB 83 CB FF 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 81 C4 0C 01 00 00 89 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule des_init_f2a9c7c55f1ab9228196609f769a0a2d {
	meta:
		aliases = "des_init"
		size = "902"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 14 02 00 00 83 3D ?? ?? ?? ?? 01 0F 84 64 03 00 00 31 FF C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 EB 3C 89 F9 8D 84 24 14 02 00 00 C1 E1 06 89 F2 83 E2 20 8D 1C 01 89 F0 83 E0 01 C1 E0 04 09 C2 89 F0 D1 F8 83 E0 0F 09 C2 8A 84 11 ?? ?? ?? ?? 88 84 33 00 FE FF FF 46 83 FE 3F 7E C5 47 83 FF 07 7F 04 31 F6 EB F1 31 ED EB 44 89 EA 8D 84 24 14 02 00 00 C1 E2 07 89 F9 01 C2 89 EB C1 E1 06 0F B6 84 3A 00 FE FF FF C1 E0 04 09 F1 C1 E3 0C 0A 84 32 40 FE FF FF 46 88 84 0B ?? ?? ?? ?? 83 FE 3F 7E C7 47 83 FF }
	condition:
		$pattern
}

rule __GI_authunix_create_default_4729854b6cfc1267abc50f6b797dea4f {
	meta:
		aliases = "authunix_create_default, __GI_authunix_create_default"
		size = "170"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 18 01 00 00 31 F6 6A 03 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 74 19 83 EC 0C 8D 04 85 00 00 00 00 50 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 74 3D 50 50 68 FF 00 00 00 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 40 74 26 C6 84 24 0B 01 00 00 00 E8 ?? ?? ?? ?? 89 C5 E8 ?? ?? ?? ?? 89 C7 50 50 56 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 05 E8 ?? ?? ?? ?? 83 EC 0C 83 F8 10 56 7E 05 B8 10 00 00 00 50 57 55 8D 44 24 28 50 E8 ?? ?? ?? ?? 83 C4 14 89 C3 56 E8 ?? ?? ?? ?? 81 C4 1C 01 00 00 89 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_openpty_1a9a9689fd183f395882929f7aa630aa {
	meta:
		aliases = "openpty, __GI_openpty"
		size = "252"
		objfiles = "openpty@libutil.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 18 10 00 00 8B AC 24 38 10 00 00 6A 02 E8 ?? ?? ?? ?? 83 C4 10 89 C6 83 C8 FF 83 FE FF 0F 84 C8 00 00 00 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 A5 00 00 00 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 91 00 00 00 57 68 00 10 00 00 8D 7C 24 14 57 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 79 53 53 68 02 01 00 00 57 E8 ?? ?? ?? ?? 83 C4 10 89 C3 83 F8 FF 74 62 85 ED 74 0D 51 55 6A 02 50 E8 ?? ?? ?? ?? 83 C4 10 83 BC 24 30 10 00 00 00 74 16 52 FF B4 24 34 10 00 00 68 14 54 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 8B 84 24 20 10 00 00 89 30 8B 84 24 24 10 00 00 89 18 31 C0 83 BC 24 }
	condition:
		$pattern
}

rule clnt_sperror_13ab08e4b4c771537f3291ebc0aed347 {
	meta:
		aliases = "__GI_clnt_sperror, clnt_sperror"
		size = "371"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 1C 04 00 00 8B 9C 24 30 04 00 00 E8 ?? ?? ?? ?? 89 C5 31 C0 85 ED 0F 84 46 01 00 00 50 50 8B 53 04 8D 84 24 18 04 00 00 50 53 FF 52 08 83 C4 0C FF B4 24 38 04 00 00 68 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? FF B4 24 20 04 00 00 8D 5C 05 00 E8 ?? ?? ?? ?? 83 C4 0C 50 53 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 83 BC 24 10 04 00 00 11 8D 34 03 0F 87 C3 00 00 00 8B 84 24 10 04 00 00 FF 24 85 ?? ?? ?? ?? 50 68 00 04 00 00 8D 5C 24 18 53 FF B4 24 20 04 00 00 E8 ?? ?? ?? ?? 83 C4 0C 53 68 ?? ?? ?? ?? E9 A3 00 00 00 8B 3C C5 ?? ?? ?? ?? 81 C7 ?? ?? ?? ?? EB 1C 8B 94 24 14 04 00 00 31 }
	condition:
		$pattern
}

rule realpath_5c771d8da28aa10c69c1e9d25a0ccbdd {
	meta:
		aliases = "realpath"
		size = "565"
		objfiles = "realpath@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 1C 10 00 00 8B B4 24 30 10 00 00 8B BC 24 34 10 00 00 85 F6 75 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 FA 01 00 00 80 3E 00 75 10 E8 ?? ?? ?? ?? C7 00 02 00 00 00 E9 E5 01 00 00 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 3D FD 0F 00 00 0F 87 AA 01 00 00 8D 6C 24 1C 29 C5 50 50 56 8D 9D FF 0F 00 00 53 E8 ?? ?? ?? ?? 8D 87 FE 0F 00 00 89 44 24 1C 83 C4 10 80 BD FF 0F 00 00 2F 74 3E 56 56 68 FF 0F 00 00 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 8B 01 00 00 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 8D 34 07 80 7E FF 2F 74 04 C6 06 2F 46 C7 44 24 10 00 00 00 00 E9 20 01 00 00 8D 77 01 8D 9D 00 10 }
	condition:
		$pattern
}

rule clnt_broadcast_e395daf58dd3049663c727da6ec3acb8 {
	meta:
		aliases = "clnt_broadcast"
		size = "1462"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 1C 29 00 00 E8 ?? ?? ?? ?? 89 44 24 04 C7 84 24 10 29 00 00 01 00 00 00 51 6A 11 6A 02 6A 02 E8 ?? ?? ?? ?? 89 44 24 1C 83 C4 10 85 C0 79 0A 83 EC 0C 68 ?? ?? ?? ?? EB 29 83 EC 0C 6A 04 8D 84 24 20 29 00 00 50 6A 06 6A 01 FF 74 24 28 E8 ?? ?? ?? ?? 83 C4 20 85 C0 79 1A 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BB 03 00 00 00 83 C4 10 E9 17 05 00 00 8B 44 24 0C 66 C7 84 24 0C 29 00 00 01 00 89 84 24 08 29 00 00 8D 44 24 28 89 84 24 04 29 00 00 8D 84 24 00 29 00 00 C7 84 24 00 29 00 00 60 22 00 00 52 50 68 12 89 00 00 FF 74 24 18 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 1D 83 EC 0C 68 ?? }
	condition:
		$pattern
}

rule ether_ntohost_7258e656f75b483b98078cfced44be8f {
	meta:
		aliases = "ether_ntohost"
		size = "159"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 24 01 00 00 83 CB FF 8B AC 24 3C 01 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 74 66 EB 3D 50 50 53 31 DB FF B4 24 3C 01 00 00 E8 ?? ?? ?? ?? 83 C4 10 EB 42 8D BC 24 16 01 00 00 89 D8 89 FA E8 ?? ?? ?? ?? 89 C3 85 C0 74 11 50 6A 06 57 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 C3 51 56 68 00 01 00 00 8D 5C 24 22 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 C1 83 CB FF 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 81 C4 1C 01 00 00 89 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fstatvfs_6f97e3d1543bb3ca051b5c303eeacc1d {
	meta:
		aliases = "__GI_statvfs, statvfs, fstatvfs"
		size = "692"
		objfiles = "statvfs@libc.a, fstatvfs@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 24 05 00 00 8B 9C 24 38 05 00 00 8D 84 24 C8 04 00 00 8B B4 24 3C 05 00 00 50 53 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 0F 88 73 02 00 00 8B 84 24 C4 04 00 00 89 06 89 46 04 8B 84 24 C8 04 00 00 89 46 08 8B 84 24 CC 04 00 00 89 46 0C 8B 84 24 D0 04 00 00 89 46 10 8B 84 24 D4 04 00 00 89 46 14 8B 84 24 D8 04 00 00 89 46 18 8B 84 24 DC 04 00 00 C7 46 24 00 00 00 00 89 46 20 8B 84 24 E4 04 00 00 89 46 2C 50 8D 46 30 6A 18 6A 00 50 E8 ?? ?? ?? ?? 8B 46 18 89 46 1C C7 46 28 00 00 00 00 5F 5D 8D 84 24 70 04 00 00 50 53 E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 0F 88 E2 01 00 00 E8 ?? ?? }
	condition:
		$pattern
}

rule __getgrouplist_internal_1933f7b48d6e33b61e8579028edae64e {
	meta:
		aliases = "__getgrouplist_internal"
		size = "275"
		objfiles = "__getgrouplist_internal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 28 01 00 00 8B 84 24 44 01 00 00 C7 00 01 00 00 00 6A 20 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 0F 84 DB 00 00 00 8B 84 24 34 01 00 00 89 06 51 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C7 85 C0 0F 84 B4 00 00 00 BD 01 00 00 00 C7 40 34 01 00 00 00 EB 66 8B 84 24 34 01 00 00 39 84 24 14 01 00 00 74 56 8B 9C 24 18 01 00 00 EB 47 52 52 FF B4 24 38 01 00 00 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 2E F7 C5 07 00 00 00 75 19 50 50 8D 04 AD 20 00 00 00 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 43 89 C6 8B 84 24 14 01 00 00 89 04 AE 45 EB 09 83 C3 04 8B 03 85 C0 75 B3 83 EC }
	condition:
		$pattern
}

rule __res_querydomain_2200db02092953cb8234c42d0715498d {
	meta:
		aliases = "__GI___res_querydomain, __res_querydomain"
		size = "321"
		objfiles = "res_query@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 30 04 00 00 8B BC 24 44 04 00 00 8B AC 24 48 04 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 9C 24 28 04 00 00 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 5A 6A 01 53 8B 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 FF 74 17 83 BC 24 50 04 00 00 00 74 0D 83 E6 01 75 15 E8 ?? ?? ?? ?? 40 75 0D E8 ?? ?? ?? ?? C7 00 FF FF FF FF EB 27 85 ED 75 51 83 EC 0C 57 E8 ?? ?? ?? ?? 89 C2 83 C4 10 8D 40 01 3D 01 04 00 00 76 13 E8 ?? ?? ?? ?? C7 00 03 00 00 00 83 C8 FF E9 91 00 00 00 85 D2 74 63 8D 72 FF 80 3C 37 2E 75 5A 53 56 57 8D 5C 24 27 53 E8 ?? ?? ?? ?? C6 44 34 2B 00 89 D8 83 C4 }
	condition:
		$pattern
}

rule __GI_vsyslog_08d69afb604136a915c5d75851223ea2 {
	meta:
		aliases = "vsyslog, __GI_vsyslog"
		size = "749"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 40 05 00 00 8B B4 24 54 05 00 00 68 8C 00 00 00 6A 00 8D 9C 24 A8 04 00 00 53 E8 ?? ?? ?? ?? C7 84 24 AC 04 00 00 ?? ?? ?? ?? 58 8D 84 24 AC 04 00 00 50 E8 ?? ?? ?? ?? 83 C4 0C 8D 84 24 14 04 00 00 50 53 6A 0D E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 44 24 14 83 C4 0C 8B 38 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 84 24 34 05 00 00 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 05 ?? ?? ?? ?? 89 F1 83 C4 10 83 E1 07 D3 F8 A8 01 0F 84 22 02 00 00 F7 C6 00 FC FF FF 0F 85 16 02 00 00 83 3D ?? ?? ?? ?? 00 78 09 80 3D ?? ?? ?? ?? 00 75 1D A0 ?? ?? ?? ?? 55 83 C8 08 6A 00 0F B6 C0 50 }
	condition:
		$pattern
}

rule get_myaddress_07614cf3a5d94eb64ac6444c68f1295f {
	meta:
		aliases = "get_myaddress"
		size = "302"
		objfiles = "get_myaddress@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 40 10 00 00 6A 00 6A 02 6A 02 E8 ?? ?? ?? ?? 83 C4 10 89 C5 85 C0 79 0A 83 EC 0C 68 ?? ?? ?? ?? EB 41 8D 44 24 14 C7 84 24 34 10 00 00 00 10 00 00 89 84 24 38 10 00 00 8D 84 24 34 10 00 00 53 50 68 12 89 00 00 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 C7 44 24 08 00 00 00 00 79 19 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 01 00 00 00 E8 ?? ?? ?? ?? 8B B4 24 38 10 00 00 8B BC 24 34 10 00 00 EB 78 8D 9C 24 14 10 00 00 51 6A 20 56 53 E8 ?? ?? ?? ?? 83 C4 0C 53 68 13 89 00 00 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 0A 83 EC 0C 68 ?? ?? ?? ?? EB AE 0F BF 84 24 24 10 00 00 A8 01 74 35 66 }
	condition:
		$pattern
}

rule __get_myaddress_07aedc4ec29b7984037ba44d9ee94c54 {
	meta:
		aliases = "__get_myaddress"
		size = "318"
		objfiles = "pmap_clnt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 40 10 00 00 89 44 24 08 6A 00 6A 02 6A 02 E8 ?? ?? ?? ?? 83 C4 10 89 C5 85 C0 79 0A 83 EC 0C 68 ?? ?? ?? ?? EB 41 8D 44 24 14 C7 84 24 34 10 00 00 00 10 00 00 89 84 24 38 10 00 00 8D 84 24 34 10 00 00 53 50 68 12 89 00 00 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 C7 44 24 08 01 00 00 00 79 19 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 01 00 00 00 E8 ?? ?? ?? ?? 8B B4 24 38 10 00 00 8B BC 24 34 10 00 00 EB 7E 8D 9C 24 14 10 00 00 51 6A 20 56 53 E8 ?? ?? ?? ?? 83 C4 0C 53 68 13 89 00 00 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 0A 83 EC 0C 68 ?? ?? ?? ?? EB AE 0F BF 84 24 24 10 00 00 A8 }
	condition:
		$pattern
}

rule fstatvfs64_fe10382b76402460930f722fd7010a12 {
	meta:
		aliases = "statvfs64, fstatvfs64"
		size = "748"
		objfiles = "fstatvfs64@libc.a, statvfs64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 44 05 00 00 8B 9C 24 58 05 00 00 8D 84 24 D4 04 00 00 8B B4 24 5C 05 00 00 50 53 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 0F 88 AB 02 00 00 8B 84 24 D0 04 00 00 89 06 89 46 04 8B 84 24 D4 04 00 00 8B 94 24 D8 04 00 00 89 56 0C 89 46 08 8B 84 24 DC 04 00 00 8B 94 24 E0 04 00 00 89 56 14 89 46 10 8B 84 24 E4 04 00 00 8B 94 24 E8 04 00 00 89 56 1C 89 46 18 8B 84 24 EC 04 00 00 8B 94 24 F0 04 00 00 89 56 24 89 46 20 8B 84 24 F4 04 00 00 8B 94 24 F8 04 00 00 89 56 2C 89 46 28 8B 84 24 FC 04 00 00 C7 46 3C 00 00 00 00 89 46 38 8B 84 24 04 05 00 00 89 46 44 50 8D 46 48 6A 18 6A 00 50 }
	condition:
		$pattern
}

rule __pthread_manager_0da78eddf949f0a38dd242453104abdb {
	meta:
		aliases = "__pthread_manager"
		size = "1633"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 58 01 00 00 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8D 9C 24 D0 00 00 00 53 E8 ?? ?? ?? ?? 5F 5D FF 35 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 59 5E 6A 05 53 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 15 A1 ?? ?? ?? ?? 85 C0 7E 0C 52 52 50 53 E8 ?? ?? ?? ?? 83 C4 10 55 6A 00 8D 84 24 CC 00 00 00 50 6A 02 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 5F FF 70 18 E8 ?? ?? ?? ?? 83 C4 10 56 68 94 00 00 00 8D 44 24 38 50 FF B4 24 6C 01 00 00 E8 ?? ?? ?? ?? 83 C4 10 40 75 0A E8 ?? ?? ?? ?? 83 38 04 74 D9 8B 94 24 60 01 00 00 66 C7 84 24 48 01 00 00 01 00 89 94 24 44 01 00 00 53 68 }
	condition:
		$pattern
}

rule _vfprintf_internal_5a10df1b1ad64db20cf84da3424b55f4 {
	meta:
		aliases = "_vfprintf_internal"
		size = "1466"
		objfiles = "_vfprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 64 01 00 00 8B 9C 24 7C 01 00 00 53 8D 74 24 1C 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 3E 8B 5C 24 10 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 C7 04 24 FF FF FF FF 0F 84 6A 05 00 00 52 FF B4 24 74 01 00 00 50 53 E8 ?? ?? ?? ?? C7 44 24 10 FF FF FF FF 83 C4 10 E9 4B 05 00 00 50 50 FF B4 24 80 01 00 00 56 E8 ?? ?? ?? ?? C7 44 24 10 00 00 00 00 89 DA 83 C4 10 EB 01 43 8A 03 84 C0 74 04 3C 25 75 F5 39 D3 74 27 89 DE 31 C0 29 D6 85 F6 7E 12 55 FF B4 24 74 01 00 00 56 52 E8 ?? ?? ?? ?? 83 C4 10 39 F0 0F 85 F3 04 00 00 01 34 24 80 3B 00 0F 84 EE 04 00 00 8D 53 01 80 7B 01 25 0F 84 D2 }
	condition:
		$pattern
}

rule __GI_rexec_af_e9d54071fde049b4cde08fe635685162 {
	meta:
		aliases = "rexec_af, __GI_rexec_af"
		size = "1142"
		objfiles = "rexec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 7C 01 00 00 8B 84 24 98 01 00 00 89 44 24 04 8B 84 24 9C 01 00 00 89 44 24 08 8B 84 24 94 01 00 00 66 C1 C8 08 0F B7 C0 0F B7 9C 24 A8 01 00 00 50 68 ?? ?? ?? ?? 6A 20 8D BC 24 58 01 00 00 57 E8 ?? ?? ?? ?? C6 84 24 7B 01 00 00 00 83 C4 0C 6A 20 6A 00 8D B4 24 38 01 00 00 56 E8 ?? ?? ?? ?? 8D 84 24 84 01 00 00 89 9C 24 40 01 00 00 C7 84 24 44 01 00 00 01 00 00 00 C7 84 24 3C 01 00 00 02 00 00 00 50 56 57 83 CF FF 8B 84 24 AC 01 00 00 FF 30 E8 ?? ?? ?? ?? 83 C4 20 85 C0 0F 85 BF 03 00 00 8B 84 24 74 01 00 00 8B 40 18 85 C0 74 4E 57 68 01 04 00 00 50 68 ?? ?? ?? ?? E8 ?? ?? ?? }
	condition:
		$pattern
}

rule universal_e2c2a6eec6e638b160672b8ab9eebb3b {
	meta:
		aliases = "universal"
		size = "347"
		objfiles = "svc_simple@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 7C 22 00 00 8B 84 24 90 22 00 00 8B AC 24 94 22 00 00 C7 84 24 78 22 00 00 00 00 00 00 8B 78 08 85 FF 75 2D 56 6A 00 68 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 0D 01 00 00 53 6A 04 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? E9 91 00 00 00 8B 30 E8 ?? ?? ?? ?? 8B 98 C0 00 00 00 E9 9C 00 00 00 39 73 04 0F 85 90 00 00 00 39 7B 08 0F 85 87 00 00 00 51 68 60 22 00 00 6A 00 8D 74 24 24 56 E8 ?? ?? ?? ?? 83 C4 0C 8B 45 08 56 FF 73 0C 55 FF 50 08 83 C4 10 85 C0 0F 84 9E 00 00 00 83 EC 0C 56 FF 13 83 C4 10 85 C0 75 0D 81 7B 10 ?? ?? ?? ?? 0F 85 90 00 00 00 52 50 FF 73 10 55 E8 ?? }
	condition:
		$pattern
}

rule _vfwprintf_internal_4ffb868948c02180563ee93ee0f8e1cb {
	meta:
		aliases = "_vfwprintf_internal"
		size = "1802"
		objfiles = "_vfwprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 80 02 00 00 8B B4 24 98 02 00 00 68 BC 00 00 00 6A 00 8D 84 24 2C 01 00 00 50 E8 ?? ?? ?? ?? 8D 84 24 7C 02 00 00 FF 8C 24 48 01 00 00 89 B4 24 30 01 00 00 C7 84 24 40 01 00 00 80 00 00 00 C7 84 24 7C 02 00 00 00 00 00 00 89 B4 24 84 02 00 00 50 6A FF 8D 84 24 8C 02 00 00 50 6A 00 E8 ?? ?? ?? ?? 83 C4 20 40 75 10 C7 84 24 20 01 00 00 ?? ?? ?? ?? E9 A0 00 00 00 BA 09 00 00 00 8D 84 24 48 01 00 00 C7 00 08 00 00 00 83 C0 04 4A 75 F4 89 F0 EB 37 83 FA 25 75 2F 83 C0 04 83 38 25 74 27 89 84 24 20 01 00 00 83 EC 0C 8D 84 24 2C 01 00 00 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 59 8B 84 }
	condition:
		$pattern
}

rule byte_regex_compile_c7b0844fabcb14f94de3ae5871bfca19 {
	meta:
		aliases = "byte_regex_compile"
		size = "8402"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 88 01 00 00 01 C2 8B BC 24 9C 01 00 00 89 44 24 24 89 4C 24 20 89 84 24 84 01 00 00 89 54 24 30 8B 47 14 89 44 24 34 68 80 02 00 00 E8 ?? ?? ?? ?? 89 44 24 6C 83 C4 10 85 C0 0F 84 C5 1F 00 00 8B 54 24 14 C7 47 08 00 00 00 00 80 67 1C 97 89 57 0C C7 47 18 00 00 00 00 83 3D ?? ?? ?? ?? 00 75 46 51 68 00 01 00 00 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 83 C4 10 8B 15 ?? ?? ?? ?? EB 0F F6 44 42 01 08 74 07 C6 80 ?? ?? ?? ?? 01 40 3D FF 00 00 00 7E EA C6 05 ?? ?? ?? ?? 01 C7 05 ?? ?? ?? ?? 01 00 00 00 83 7F 04 00 75 43 8B 07 85 C0 74 0C 52 52 6A 20 50 E8 ?? ?? ?? ?? EB 0A 83 EC }
	condition:
		$pattern
}

rule svcunix_create_aecabc159309b983a378be11f5b199cb {
	meta:
		aliases = "svcunix_create"
		size = "408"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 8C 00 00 00 31 ED 8B B4 24 A0 00 00 00 8B BC 24 AC 00 00 00 C7 84 24 88 00 00 00 10 00 00 00 83 FE FF 75 2B 50 6A 00 6A 01 6A 01 E8 ?? ?? ?? ?? 66 BD 01 00 83 C4 10 89 C6 85 C0 79 12 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 EA 00 00 00 50 6A 6E 6A 00 8D 5C 24 26 53 E8 ?? ?? ?? ?? 66 C7 44 24 2A 01 00 89 3C 24 E8 ?? ?? ?? ?? 83 C4 0C 40 89 84 24 8C 00 00 00 50 57 8D 44 24 28 50 E8 ?? ?? ?? ?? 8B 84 24 98 00 00 00 83 C0 02 89 84 24 98 00 00 00 83 C4 0C 50 53 56 E8 ?? ?? ?? ?? 83 C4 0C 8D 84 24 8C 00 00 00 50 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 11 53 53 6A 02 56 E8 ?? ?? ?? }
	condition:
		$pattern
}

rule _fp_out_wide_d4abf342196b039e8682745dc27ee937 {
	meta:
		aliases = "_fp_out_wide"
		size = "148"
		objfiles = "_vfwprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 8C 00 00 00 31 ED 8B BC 24 A4 00 00 00 8B 9C 24 A8 00 00 00 89 F8 84 C0 79 35 83 EC 0C FF B4 24 B8 00 00 00 E8 ?? ?? ?? ?? 83 C4 10 29 C3 89 C6 85 DB 7E 19 83 E7 7F 89 D9 89 FA 8B 84 24 A0 00 00 00 E8 ?? ?? ?? ?? 89 C5 39 D8 75 34 89 F3 85 DB 7E 2E 31 D2 8B 8C 24 AC 00 00 00 0F BE 04 11 89 44 94 14 42 39 DA 7C EC 50 FF B4 24 A4 00 00 00 53 8D 44 24 20 50 E8 ?? ?? ?? ?? 83 C4 10 01 C5 81 C4 8C 00 00 00 89 E8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __uClibc_main_4ba46b2601f99b0089ae21403386ae03 {
	meta:
		aliases = "__uClibc_main"
		size = "432"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 8C 00 00 00 8B 84 24 B8 00 00 00 8B BC 24 A8 00 00 00 A3 ?? ?? ?? ?? 8B 84 24 B4 00 00 00 A3 ?? ?? ?? ?? 8B 84 24 A4 00 00 00 8B AC 24 AC 00 00 00 8D 14 87 8D 42 04 A3 ?? ?? ?? ?? 3B 07 75 06 89 15 ?? ?? ?? ?? 51 6A 78 6A 00 8D 44 24 20 50 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 83 38 00 8D 40 04 75 F8 89 C3 EB 1B 8B 03 83 F8 0E 77 11 52 6A 08 53 8D 44 C4 20 50 E8 ?? ?? ?? ?? 83 C4 10 83 C3 08 83 3B 00 75 E0 E8 ?? ?? ?? ?? 8B 44 24 48 85 C0 75 04 66 B8 00 10 A3 ?? ?? ?? ?? 83 7C 24 70 FF 75 20 E8 ?? ?? ?? ?? 89 C3 E8 ?? ?? ?? ?? 39 C3 75 2F E8 ?? ?? ?? ?? 89 C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __ieee754_pow_84c0906e1533110753f045a99429df61 {
	meta:
		aliases = "__ieee754_pow"
		size = "2029"
		objfiles = "e_pow@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 8C 00 00 00 8B AC 24 AC 00 00 00 8B 9C 24 A0 00 00 00 89 6C 24 60 89 5C 24 38 8B 4C 24 60 8B BC 24 A8 00 00 00 81 E1 FF FF FF 7F 8B B4 24 A4 00 00 00 8B 44 24 38 89 4C 24 68 89 74 24 3C 89 44 24 6C 89 FA 09 F9 75 0C 31 FF BD 00 00 F0 3F E9 7C 07 00 00 8B 44 24 3C 89 44 24 5C 25 FF FF FF 7F 89 44 24 64 3D 00 00 F0 7F 7F 23 0F 94 44 24 43 80 7C 24 43 00 74 07 83 7C 24 6C 00 75 10 81 7C 24 68 00 00 F0 7F 7F 06 75 23 85 D2 74 1F 89 7C 24 18 89 6C 24 1C DD 44 24 18 89 5C 24 18 89 74 24 1C DD 44 24 18 DE C1 E9 16 07 00 00 83 7C 24 5C 00 0F 89 85 00 00 00 C7 44 24 58 02 00 00 00 81 }
	condition:
		$pattern
}

rule __gen_tempname_f35150a129293ec2eb11163242b41d9a {
	meta:
		aliases = "__gen_tempname"
		size = "639"
		objfiles = "tempname@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 8C 00 00 00 E8 ?? ?? ?? ?? 89 44 24 10 8B 00 89 44 24 1C 83 EC 0C FF B4 24 AC 00 00 00 E8 ?? ?? ?? ?? 83 C4 10 83 F8 05 76 2F 8B 94 24 A0 00 00 00 8D 44 02 FA 89 44 24 14 52 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 C7 44 24 18 00 00 00 00 0F 84 FA 01 00 00 8B 4C 24 10 C7 01 16 00 00 00 E9 03 02 00 00 50 50 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C7 85 C0 79 1A 50 50 68 00 08 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C7 85 C0 78 27 55 6A 06 8D 84 24 8A 00 00 00 50 57 E8 ?? ?? ?? ?? 89 3C 24 89 C3 E8 ?? ?? ?? ?? 83 C4 10 83 FB 06 0F 84 AB 00 00 00 56 56 }
	condition:
		$pattern
}

rule __kernel_rem_pio2_466006a727a05ac1ddbf7d171373207b {
	meta:
		aliases = "__kernel_rem_pio2"
		size = "1478"
		objfiles = "k_rem_pio2@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 8C 02 00 00 D9 EE 8B 8C 24 A8 02 00 00 8B 84 24 B0 02 00 00 8B 9C 24 AC 02 00 00 8D 51 FD 8B 04 85 ?? ?? ?? ?? 89 44 24 30 4B 89 D0 89 5C 24 2C 99 BB 18 00 00 00 F7 FB 89 44 24 44 31 D2 F7 D0 C1 F8 1F 21 44 24 44 6B 44 24 44 E8 8D 7C 01 E8 8B 44 24 44 8B 4C 24 2C 2B 44 24 2C 03 4C 24 30 EB 1B D9 C0 85 C0 78 0C DD D8 8B 9C 24 B4 02 00 00 DB 04 83 DD 9C D4 90 01 00 00 40 42 39 CA 7E E1 DD D8 31 C9 EB 27 8B 44 24 2C 8B 9C 24 A0 02 00 00 01 C8 29 D0 DD 04 D3 DC 8C C4 90 01 00 00 42 DE C1 3B 54 24 2C 7E DE DD 5C CC 50 41 3B 4C 24 30 7F 06 31 D2 D9 EE EB E9 8B 74 24 30 DD 44 F4 50 }
	condition:
		$pattern
}

rule getpass_d9d92ab2cbb6d6e36d4b24e54485c6d2 {
	meta:
		aliases = "getpass"
		size = "359"
		objfiles = "getpass@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 94 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C6 89 C3 85 C0 75 0C 8B 35 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 83 EC 0C 31 ED 56 E8 ?? ?? ?? ?? 5A 59 8D 7C 24 1C 57 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 49 8D 44 24 50 55 6A 3C 57 50 E8 ?? ?? ?? ?? 83 64 24 30 F6 89 34 24 E8 ?? ?? ?? ?? 83 C4 0C 57 6A 02 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 94 C0 0F B6 E8 3B 35 ?? ?? ?? ?? 74 0F 6A 00 6A 02 6A 00 56 E8 ?? ?? ?? ?? 83 C4 10 51 51 53 FF B4 24 AC 00 00 00 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 0C 56 68 FF 00 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? }
	condition:
		$pattern
}

rule sigaction_00ee9b1fbd45d68bffc43c7c446d53a5 {
	meta:
		aliases = "__GI_sigaction, sigaction"
		size = "223"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 9C 00 00 00 8B 9C 24 B0 00 00 00 8B BC 24 B4 00 00 00 8B AC 24 B8 00 00 00 3B 1D ?? ?? ?? ?? 0F 84 9E 00 00 00 3B 1D ?? ?? ?? ?? 0F 84 92 00 00 00 3B 1D ?? ?? ?? ?? 75 08 85 DB 0F 8F 82 00 00 00 31 C0 85 FF 74 45 8D 74 24 10 50 68 8C 00 00 00 57 56 E8 ?? ?? ?? ?? 83 C4 10 83 3F 01 76 28 85 DB 7E 24 83 FB 40 7F 1F F6 87 84 00 00 00 04 74 0A C7 44 24 10 ?? ?? ?? ?? EB 08 C7 44 24 10 ?? ?? ?? ?? 89 F0 EB 04 8D 44 24 10 56 55 50 53 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 40 74 2E 8D 43 FF 83 F8 3F 77 24 85 ED 74 0A 8B 04 9D ?? ?? ?? ?? 89 45 00 85 FF 74 12 8B 07 89 04 9D ?? ?? ?? ?? EB }
	condition:
		$pattern
}

rule __GI_getnameinfo_8c21d5518f5b10ee342d790847c4dbb0 {
	meta:
		aliases = "getnameinfo, __GI_getnameinfo"
		size = "862"
		objfiles = "getnameinfo@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 9C 02 00 00 E8 ?? ?? ?? ?? 89 04 24 8B AC 24 B0 02 00 00 8B 00 8B 9C 24 B4 02 00 00 89 44 24 08 83 C8 FF F7 84 24 C8 02 00 00 E0 FF FF FF 0F 85 19 03 00 00 85 ED 0F 84 0C 03 00 00 83 FB 01 0F 86 03 03 00 00 66 8B 55 00 0F B7 C2 83 F8 01 74 1C 83 F8 02 75 05 83 FB 0F EB 0C 83 F8 0A 0F 85 E4 02 00 00 83 FB 1B 0F 86 DB 02 00 00 83 BC 24 B8 02 00 00 00 0F 95 44 24 05 83 BC 24 BC 02 00 00 00 0F 95 44 24 06 80 7C 24 05 00 0F 84 B9 01 00 00 80 7C 24 06 00 0F 84 AE 01 00 00 0F B7 C2 83 F8 02 74 11 83 F8 0A 74 0C 48 0F 85 9A 01 00 00 E9 2F 01 00 00 F6 84 24 C8 02 00 00 01 0F 85 C3 00 }
	condition:
		$pattern
}

rule _time_tzset_1c05558c40e228dd1419121a742172f6 {
	meta:
		aliases = "_time_tzset"
		size = "950"
		objfiles = "tzset@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC A0 00 00 00 C7 84 24 9C 00 00 00 00 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 84 24 94 00 00 00 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 75 61 50 50 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C7 85 C0 78 46 BE 44 00 00 00 8D 5C 24 14 50 56 53 57 E8 ?? ?? ?? ?? 83 C4 10 83 F8 00 7C 1E 74 06 01 C3 29 C6 75 E7 8D 44 24 14 39 C3 76 0E 80 7B FF 0A 75 08 C6 43 FF 00 89 C3 EB 02 31 DB 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 85 DB 74 06 8A 03 84 C0 75 2C C6 05 ?? ?? ?? ?? 00 50 6A 30 6A 00 68 ?? ?? ?? ?? E8 ?? ?? }
	condition:
		$pattern
}

rule pthread_join_a24db8e82cc1af3da19ddc7e2d6b8a84 {
	meta:
		aliases = "pthread_join"
		size = "487"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC AC 00 00 00 E8 ?? ?? ?? ?? 8B AC 24 C0 00 00 00 89 84 24 A8 00 00 00 89 E8 8B 94 24 A8 00 00 00 25 FF 03 00 00 C7 84 24 A4 00 00 00 ?? ?? ?? ?? C1 E0 04 8D B0 ?? ?? ?? ?? 89 F0 89 B4 24 A0 00 00 00 E8 ?? ?? ?? ?? 8B 5E 08 85 DB 74 05 39 6B 10 74 10 83 EC 0C 56 E8 ?? ?? ?? ?? B8 03 00 00 00 EB 19 8B 84 24 A8 00 00 00 39 C3 75 16 83 EC 0C 56 E8 ?? ?? ?? ?? B8 23 00 00 00 83 C4 10 E9 52 01 00 00 80 7B 2D 00 75 06 83 7B 38 00 74 10 83 EC 0C 56 E8 ?? ?? ?? ?? B8 16 00 00 00 EB DC 80 7B 2C 00 0F 85 C2 00 00 00 8B 84 24 A8 00 00 00 8D 94 24 A0 00 00 00 E8 ?? ?? ?? ?? 8B 84 24 A8 00 }
	condition:
		$pattern
}

rule __GI_sleep_6f89aafc55f6e993a62da70d692aaecb {
	meta:
		aliases = "sleep, __GI_sleep"
		size = "393"
		objfiles = "sleep@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC AC 01 00 00 B8 20 00 00 00 8B 94 24 C0 01 00 00 85 D2 75 10 E9 58 01 00 00 C7 84 84 24 01 00 00 00 00 00 00 48 79 F2 C7 84 24 A8 01 00 00 00 00 00 00 89 94 24 A4 01 00 00 50 50 6A 11 8D 9C 24 30 01 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 88 20 01 00 00 50 8D B4 24 A8 00 00 00 56 53 6A 00 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 04 01 00 00 50 50 6A 11 56 E8 ?? ?? ?? ?? 83 C4 10 BA 20 00 00 00 85 C0 74 10 E9 B3 00 00 00 C7 84 94 24 01 00 00 00 00 00 00 4A 79 F2 50 50 6A 11 8D 84 24 30 01 00 00 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 88 BF 00 00 00 50 8D 44 24 1C 50 6A 00 6A 11 E8 ?? }
	condition:
		$pattern
}

rule __open_nameservers_c050c23e3ab681dcf60f1a6a2062c609 {
	meta:
		aliases = "__open_nameservers"
		size = "579"
		objfiles = "opennameservers@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC C0 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 84 24 B8 00 00 00 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 3D ?? ?? ?? ?? 00 0F 8F EA 01 00 00 55 55 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C5 85 C0 0F 85 97 01 00 00 57 57 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C5 85 C0 0F 85 79 01 00 00 E9 9E 01 00 00 43 8A 0B 84 C9 0F 84 69 01 00 00 0F BE D1 A1 ?? ?? ?? ?? F6 04 50 20 75 E7 80 F9 0A 0F 84 52 01 00 00 C7 44 24 08 00 00 00 00 80 F9 23 75 4F E9 40 01 00 00 8B 44 24 08 89 9C 84 98 00 00 00 EB 01 43 8A 0B 84 C9 74 19 0F BE }
	condition:
		$pattern
}

rule __psfs_do_numeric_786cef53b12022e1bc0979ce0974aa13 {
	meta:
		aliases = "__psfs_do_numeric"
		size = "1129"
		objfiles = "__psfs_do_numeric@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC CC 00 00 00 8B 84 24 E0 00 00 00 8B BC 24 E4 00 00 00 8B 40 3C 89 04 24 0F B6 A8 ?? ?? ?? ?? 48 75 63 BB ?? ?? ?? ?? 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 07 0F B6 03 3B 07 74 19 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 81 FB ?? ?? ?? ?? 76 33 E9 F8 03 00 00 43 80 3B 00 75 CA 8B 94 24 E0 00 00 00 80 7A 44 00 0F 84 E8 03 00 00 FF 42 34 6A 00 6A 00 FF 72 38 FF 72 2C E8 ?? ?? ?? ?? E9 B3 03 00 00 83 EC 0C 57 E8 ?? ?? ?? ?? 8B 17 83 C4 10 83 C8 FF 85 D2 0F 88 BA 03 00 00 83 FA 2B 74 0B 83 FA 2D 74 06 8D 74 24 1D EB 14 88 54 24 1D 83 EC 0C 57 E8 ?? ?? ?? ?? 8D 74 24 2E 83 C4 10 }
	condition:
		$pattern
}

rule parse_printf_format_45023e9af5b4dd56d2548254ff64e989 {
	meta:
		aliases = "parse_printf_format"
		size = "236"
		objfiles = "parse_printf_format@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC D4 00 00 00 31 ED 8B BC 24 E8 00 00 00 8B 9C 24 EC 00 00 00 8B B4 24 F0 00 00 00 57 8D 44 24 1C 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 88 A8 00 00 00 8B 44 24 28 85 C0 0F 8E 96 00 00 00 89 C5 89 C1 39 D8 76 02 89 D9 31 D2 EB 0A 8B 44 94 38 42 89 06 83 C6 04 39 CA 72 F2 EB 7E 3C 25 75 73 47 80 3F 25 74 6D 89 7C 24 10 83 EC 0C 8D 44 24 1C 50 E8 ?? ?? ?? ?? 8B 7C 24 20 83 C4 10 81 7C 24 18 00 00 00 80 75 0F 45 85 DB 74 0A C7 06 00 00 00 00 4B 83 C6 04 81 7C 24 14 00 00 00 80 75 0F 45 85 DB 74 0A C7 06 00 00 00 00 4B 83 C6 04 31 D2 8B 4C 24 2C EB 15 8B 44 94 38 83 F8 08 74 0B 45 85 }
	condition:
		$pattern
}

rule _fpmaxtostr_89c88685b7f9df62e56a78104e52845e {
	meta:
		aliases = "_fpmaxtostr"
		size = "1478"
		objfiles = "_fpmaxtostr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC DC 00 00 00 8B 84 24 00 01 00 00 8B 94 24 00 01 00 00 DB AC 24 F4 00 00 00 8B 40 04 89 44 24 14 8A 4A 08 8B 2A 88 C8 88 4C 24 1E 83 C8 20 C6 84 24 C2 00 00 00 65 3C 61 75 07 83 C1 06 88 4C 24 1E 85 ED 79 05 BD 06 00 00 00 8B 94 24 00 01 00 00 C6 84 24 D2 00 00 00 00 8B 42 0C A8 02 74 0A C6 84 24 D2 00 00 00 2B EB 0C A8 01 74 08 C6 84 24 D2 00 00 00 20 DD E0 DF E0 C6 84 24 D3 00 00 00 00 C7 44 24 58 00 00 00 00 9E 7A 02 74 0C DD D8 C7 44 24 58 08 00 00 00 EB 65 D9 EE D9 C9 DD E1 DF E0 9E 75 2A 7A 28 D9 E8 D8 F1 D9 CA C7 44 24 10 FF FF FF FF DD EA DF E0 DD D9 9E 0F 86 1B 01 00 }
	condition:
		$pattern
}

rule __md5_crypt_8b6071482aaed7f7c1d6bbae5629bfe8 {
	meta:
		aliases = "__md5_crypt"
		size = "736"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC E0 00 00 00 8B 9C 24 F8 00 00 00 6A 03 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 89 DD 83 C4 10 85 C0 75 03 8D 6B 03 89 EE EB 01 46 8A 06 84 C0 74 0B 3C 24 74 07 8D 45 08 39 C6 72 EE 8D 5C 24 70 29 EE 89 D8 E8 ?? ?? ?? ?? 83 EC 0C FF B4 24 FC 00 00 00 E8 ?? ?? ?? ?? 83 C4 10 89 C7 89 C1 8B 94 24 F0 00 00 00 89 D8 E8 ?? ?? ?? ?? 89 D8 B9 03 00 00 00 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 F1 89 EA 89 D8 8D 5C 24 18 89 74 24 04 E8 ?? ?? ?? ?? 89 D8 E8 ?? ?? ?? ?? 89 D8 89 F9 8B 94 24 F0 00 00 00 E8 ?? ?? ?? ?? 89 D8 8B 4C 24 04 89 EA E8 ?? ?? ?? ?? 89 D8 89 F9 8B 94 24 F0 00 00 00 E8 ?? ?? ?? }
	condition:
		$pattern
}

rule ttyname_r_3444dbcd6ceef5144b4298b15b9778d7 {
	meta:
		aliases = "__GI_ttyname_r, ttyname_r"
		size = "373"
		objfiles = "ttyname@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC E4 00 00 00 8B 9C 24 F8 00 00 00 8D 44 24 6C 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 0C E8 ?? ?? ?? ?? 8B 18 E9 39 01 00 00 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 BA ?? ?? ?? ?? 85 C0 0F 85 0A 01 00 00 E9 0F 01 00 00 8D 7A 01 BD 1E 00 00 00 0F BE F0 50 50 57 29 F5 8D 9C 24 C8 00 00 00 53 01 F3 E8 ?? ?? ?? ?? 89 5C 24 18 89 3C 24 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 0F 85 A5 00 00 00 E9 C0 00 00 00 83 EC 0C 8D 70 0B 56 E8 ?? ?? ?? ?? 83 C4 10 39 E8 0F 87 89 00 00 00 50 50 56 FF 74 24 14 E8 ?? ?? ?? ?? 5A 59 8D 44 24 14 50 8D B4 24 C8 00 00 00 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 62 }
	condition:
		$pattern
}

rule __dns_lookup_afa617ba2ac7d9be08908ff0610921ab {
	meta:
		aliases = "__dns_lookup"
		size = "1876"
		objfiles = "dnslookup@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC E8 00 00 00 8B BC 24 10 01 00 00 68 00 02 00 00 E8 ?? ?? ?? ?? C7 04 24 01 04 00 00 89 C5 E8 ?? ?? ?? ?? 89 44 24 1C 83 C4 10 85 ED 0F 84 59 06 00 00 85 C0 0F 84 51 06 00 00 83 BC 24 F8 00 00 00 00 0F 84 43 06 00 00 8B 84 24 F0 00 00 00 80 38 00 0F 84 33 06 00 00 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 0C 8B 94 24 F4 00 00 00 80 7C 02 FF 2E 0F 94 44 24 37 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 9C 24 C4 00 00 00 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 99 F7 BC 24 08 01 00 00 0F B7 05 ?? ?? ?? ?? 89 54 24 38 89 44 24 3C 58 5A 6A 01 53 E8 ?? ?? ?? ?? C7 44 24 24 }
	condition:
		$pattern
}

rule authunix_create_c2126e373038033180a1acf8f2060937 {
	meta:
		aliases = "__GI_authunix_create, authunix_create"
		size = "377"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC E8 01 00 00 6A 28 E8 ?? ?? ?? ?? C7 04 24 B0 01 00 00 89 C7 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 FF 74 04 85 C0 75 29 50 50 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 3C 24 E8 ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 31 FF E9 17 01 00 00 8D 58 0C C7 47 20 ?? ?? ?? ?? 89 47 24 55 6A 0C 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 0C 8D 47 0C 6A 0C 53 50 E8 ?? ?? ?? ?? 59 5B 6A 00 C7 46 18 00 00 00 00 8D 84 24 E0 01 00 00 50 E8 ?? ?? ?? ?? 8B 84 24 E4 01 00 00 89 84 24 CC 01 00 00 8B 84 24 00 02 00 00 89 84 24 D0 01 00 00 8B 84 24 04 02 00 00 89 84 24 D4 01 00 00 8B 84 24 08 02 00 00 }
	condition:
		$pattern
}

rule vfscanf_1bd03602e282eaed8390b478bbc03837 {
	meta:
		aliases = "__GI_vfscanf, vfscanf"
		size = "1722"
		objfiles = "vfscanf@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC F0 01 00 00 C7 84 24 34 01 00 00 FF FF FF FF 6A 24 6A 00 8D 84 24 18 01 00 00 50 E8 ?? ?? ?? ?? 8B 84 24 10 02 00 00 8B 40 34 89 44 24 18 83 C4 10 85 C0 75 29 8B 9C 24 00 02 00 00 55 83 C3 38 53 68 ?? ?? ?? ?? 8D 84 24 E4 01 00 00 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 57 57 FF B4 24 08 02 00 00 8D 84 24 A4 01 00 00 BD 01 00 00 00 50 E8 ?? ?? ?? ?? 8B 84 24 B0 01 00 00 C7 84 24 D4 01 00 00 ?? ?? ?? ?? 8B 9C 24 14 02 00 00 8A 40 03 C7 84 24 50 01 00 00 00 00 00 00 88 84 24 C0 01 00 00 8B 84 24 D8 01 00 00 89 84 24 E4 01 00 00 83 C4 10 E9 45 05 00 00 80 A4 24 B1 01 }
	condition:
		$pattern
}

rule getoffset_99b149a6ae3b9a86dbf33b71b5fd1cf8 {
	meta:
		aliases = "getoffset"
		size = "107"
		objfiles = "tzset@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 89 C1 BD ?? ?? ?? ?? 31 FF 89 14 24 83 CE FF 8A 11 45 8D 42 D0 3C 09 77 07 0F BE C2 41 8D 70 D0 8A 19 8D 43 D0 3C 09 77 0B 6B D6 0A 0F BE C3 41 8D 74 02 D0 8A 55 00 0F BE C2 39 C6 72 04 31 C9 EB 1A 0F AF C7 8D 3C 30 31 F6 80 39 3A 75 04 41 83 CE FF FE CA 7F B8 8B 04 24 89 38 89 C8 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_inet_aton_27d4173fa25162634da44ae6a83366cf {
	meta:
		aliases = "inet_aton, __GI_inet_aton"
		size = "148"
		objfiles = "inet_aton@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 4C 24 18 85 C9 74 7D 31 F6 C7 04 24 01 00 00 00 EB 51 0F BE 01 8B 2D ?? ?? ?? ?? F6 44 45 00 08 74 62 31 FF EB 10 6B C7 0A 8D 7C 18 D0 81 FF FF 00 00 00 7F 4F 41 8A 11 0F BE DA 0F B7 44 5D 00 A8 08 75 E2 83 3C 24 03 7F 08 80 FA 2E 75 35 41 EB 09 41 84 D2 74 04 A8 20 74 29 C1 E6 08 FF 04 24 09 FE 83 3C 24 04 7E A9 B8 01 00 00 00 83 7C 24 1C 00 74 11 8B 44 24 1C 0F CE 89 30 B8 01 00 00 00 EB 02 31 C0 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule ether_aton_r_06e7eee1e53da81311c3814af6a04f8e {
	meta:
		aliases = "__GI_ether_aton_r, ether_aton_r"
		size = "220"
		objfiles = "ether_addr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 4C 24 18 C7 04 24 00 00 00 00 E9 A7 00 00 00 0F BE 01 8B 2D ?? ?? ?? ?? 8A 54 45 00 8D 42 D0 3C 09 76 0B 8D 42 9F 3C 05 0F 87 94 00 00 00 8B 35 ?? ?? ?? ?? 0F BE C2 F6 04 46 08 74 05 8D 78 D0 EB 03 8D 78 A9 0F BE 41 01 83 3C 24 04 8D 59 01 0F 96 C1 8A 54 45 00 84 C9 74 05 80 FA 3A 75 13 83 3C 24 05 75 3E 84 D2 74 3A 0F BE C2 F6 04 46 20 75 31 8D 42 D0 3C 09 76 07 8D 42 9F 3C 05 77 41 0F BE C2 F6 04 46 08 74 05 8D 50 D0 EB 03 8D 50 A9 43 84 C9 74 05 80 3B 3A 75 26 89 F8 C1 E0 04 8D 3C 10 8B 0C 24 8B 54 24 1C 89 F8 88 04 0A 8D 4B 01 FF 04 24 83 3C 24 05 0F 86 4F FF FF FF }
	condition:
		$pattern
}

rule _dl_linux_resolver_0f2e9c9f843ee02540ba85888eca98a5 {
	meta:
		aliases = "_dl_linux_resolver"
		size = "136"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 5C 24 18 8B 44 24 1C 03 83 9C 00 00 00 8B 4B 58 8B 50 04 8B 00 C1 EA 08 C1 E2 04 8B 3C 0A 03 7B 54 89 04 24 8B 2B 6A 01 53 FF 73 1C 57 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 75 37 FF 73 04 57 BF 01 00 00 00 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? 53 89 FB B8 01 00 00 00 CD 80 5B 83 C4 14 3D 00 F0 FF FF 76 07 F7 D8 A3 ?? ?? ?? ?? 8B 04 24 89 34 28 89 F0 5F 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_strcasestr_59feccc1ddd14a3cc1292bd5e66c17f4 {
	meta:
		aliases = "strcasestr, __GI_strcasestr"
		size = "83"
		objfiles = "strcasestr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 7C 24 18 8B 6C 24 1C 89 FE 89 EB 8A 03 84 C0 75 04 89 F8 EB 30 8A 16 88 54 24 03 38 D0 74 16 0F B6 06 8B 15 ?? ?? ?? ?? 0F B6 0B 66 8B 04 42 66 3B 04 4A 75 04 43 46 EB D2 80 7C 24 03 00 74 03 47 EB C4 31 C0 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _dl_do_reloc_8fe002682c19d86a5a5d7db215cb1f50 {
	meta:
		aliases = "_dl_do_reloc"
		size = "193"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 31 F6 8B 6C 24 1C 8B 44 24 24 8B 55 00 89 14 24 8B 10 89 54 24 04 8B 40 04 0F B6 F8 C1 E8 08 89 C3 C1 E3 04 03 5C 24 28 85 C0 8B 0B 74 3E 31 C0 83 FF 05 0F 94 C0 31 D2 01 C0 83 FF 07 0F 94 C2 09 C2 52 55 FF 74 24 28 8B 44 24 38 01 C8 50 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 75 0F 8A 43 0C BA 01 00 00 00 C0 E8 04 3C 02 75 45 8B 14 24 03 54 24 04 83 FF 08 77 07 FF 24 BD ?? ?? ?? ?? 83 CA FF EB 2D 29 D6 01 32 EB 25 89 32 EB 21 8B 45 00 01 02 EB 1A 85 F6 74 16 8D 4A FF 8B 5B 08 8D 56 FF EB 07 42 41 4B 8A 02 88 01 85 DB 75 F5 31 D2 89 D0 5E 5F 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _dl_lookup_hash_5b6c2493b6c00f03ce65175cda86ac84 {
	meta:
		aliases = "_dl_lookup_hash"
		size = "244"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 83 CF FF 8B 6C 24 20 E9 B8 00 00 00 8B 75 00 F6 46 25 01 75 26 83 7C 24 24 00 74 1F 39 74 24 24 74 19 8B 54 24 24 8B 42 34 EB 07 39 70 04 74 0B 8B 00 85 C0 75 F5 E9 86 00 00 00 F6 44 24 28 02 74 06 83 7E 18 01 74 79 8B 5E 28 85 DB 74 72 8B 46 58 83 FF FF 89 04 24 75 28 8B 4C 24 1C 31 FF EB 1A C1 E7 04 41 0F B6 D0 8D 14 17 89 D0 89 D7 25 00 00 00 F0 31 C7 C1 E8 18 31 C7 8A 01 84 C0 75 E0 8B 56 54 89 F8 89 54 24 04 31 D2 F7 F3 8B 46 2C 8B 1C 90 EB 26 89 D8 C1 E0 04 03 04 24 FF 74 24 28 8B 54 24 08 8B 4C 24 20 E8 ?? ?? ?? ?? 89 C2 58 85 D2 75 17 8B 46 3C 8B 1C 98 85 DB 75 D6 }
	condition:
		$pattern
}

rule inet_network_5647fc6d8b2f2e78763d4b739ce89021 {
	meta:
		aliases = "__GI_inet_network, inet_network"
		size = "223"
		objfiles = "inet_net@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 8B 4C 24 1C C7 04 24 00 00 00 00 C7 44 24 04 00 00 00 00 80 39 30 74 09 31 F6 BD 0A 00 00 00 EB 1F 41 8A 01 3C 78 74 10 3C 58 74 0C BE 01 00 00 00 BD 08 00 00 00 EB 08 41 31 F6 BD 10 00 00 00 31 FF EB 50 0F B6 DA A1 ?? ?? ?? ?? 0F B7 04 58 A8 08 74 15 83 FD 08 75 05 80 FA 37 77 67 89 F8 0F AF C5 8D 7C 18 D0 EB 1D 83 FD 10 75 2C A8 10 74 28 83 E0 02 89 FA 83 F8 01 19 C0 C1 E2 04 83 E0 20 8D 7C 10 A9 81 FF FF 00 00 00 77 37 41 BE 01 00 00 00 8A 11 84 D2 75 AA 85 F6 74 27 83 3C 24 00 74 05 C1 64 24 04 08 09 7C 24 04 80 FA 2E 75 0F FF 04 24 83 3C 24 04 74 0A 41 E9 52 FF FF FF }
	condition:
		$pattern
}

rule __GI_strstr_6798ee8ab4528fee7ceb72f88c679859 {
	meta:
		aliases = "strstr, __GI_strstr"
		size = "198"
		objfiles = "strstr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 8B 54 24 20 8B 5C 24 1C 0F B6 2A 85 ED 0F 84 9F 00 00 00 4B 43 0F B6 03 85 C0 0F 84 96 00 00 00 39 E8 75 F0 8D 42 01 89 44 24 04 0F B6 52 01 89 14 24 85 D2 74 7C 0F B6 43 01 8D 4B 01 39 D0 EB 28 0F B6 43 01 8D 4B 01 EB 14 85 C0 74 68 41 0F B6 01 39 E8 74 0C 85 C0 74 5C 41 0F B6 01 39 E8 75 E8 41 0F B6 01 3B 04 24 75 F3 8B 5C 24 04 8B 7C 24 04 0F B6 41 01 0F B6 53 01 47 8D 71 01 8D 59 FF 39 D0 75 28 85 C0 74 28 0F B6 46 01 0F B6 57 01 39 D0 75 18 85 D2 74 18 83 C6 02 83 C7 02 0F B6 06 0F B6 17 39 D0 75 04 89 D0 EB D8 85 D2 75 8F 89 D8 EB 02 31 C0 5A 59 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule pthread_cancel_acfb2a3ab147c7f7b934db75aa907613 {
	meta:
		aliases = "pthread_cancel"
		size = "178"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 31 D2 8B 74 24 20 89 F0 25 FF 03 00 00 C1 E0 04 8D B8 ?? ?? ?? ?? 89 F8 E8 ?? ?? ?? ?? 8B 5F 08 85 DB 74 05 39 73 10 74 10 83 EC 0C 57 E8 ?? ?? ?? ?? B8 03 00 00 00 EB 6A 0F BE 43 42 80 7B 40 01 C6 43 42 01 74 04 85 C0 74 0B 83 EC 0C 57 E8 ?? ?? ?? ?? EB 4B 8B 83 BC 01 00 00 31 F6 8B 6B 14 85 C0 74 13 52 52 53 FF 30 FF 50 04 83 C4 10 89 C6 88 83 B8 01 00 00 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 85 F6 74 0B 83 EC 0C 53 E8 ?? ?? ?? ?? EB 0E 56 56 FF 35 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 31 C0 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule pthread_setschedparam_af1aa1252503bd7d3978841b22efa5e8 {
	meta:
		aliases = "__GI_pthread_setschedparam, pthread_setschedparam"
		size = "168"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 31 D2 8B 7C 24 20 8B 6C 24 24 89 F8 25 FF 03 00 00 C1 E0 04 8D B0 ?? ?? ?? ?? 89 F0 E8 ?? ?? ?? ?? 8B 5E 08 85 DB 74 05 39 7B 10 74 10 83 EC 0C 56 E8 ?? ?? ?? ?? B8 03 00 00 00 EB 59 57 FF 74 24 2C 55 FF 73 14 E8 ?? ?? ?? ?? 83 C4 10 40 75 12 83 EC 0C 56 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 00 EB 33 31 C0 85 ED 74 06 8B 54 24 28 8B 02 83 EC 0C 89 43 18 56 E8 ?? ?? ?? ?? 83 C4 10 31 C0 83 3D ?? ?? ?? ?? 00 78 10 83 EC 0C FF 73 18 E8 ?? ?? ?? ?? 31 C0 83 C4 10 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __encode_dotted_f1b368f84366af0c51de945f5f74309b {
	meta:
		aliases = "__encode_dotted"
		size = "144"
		objfiles = "encoded@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 31 DB 8B 7C 24 20 EB 59 52 52 6A 2E 57 E8 ?? ?? ?? ?? 83 C4 10 89 C5 85 C0 74 06 89 C6 29 FE EB 0E 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 F6 74 4B 8B 44 24 28 29 D8 48 39 C6 73 40 8B 54 24 24 89 F0 88 04 1A 43 50 89 D0 01 D8 56 57 50 01 F3 E8 ?? ?? ?? ?? 83 C4 10 85 ED 74 0C 8D 7D 01 85 FF 74 05 80 3F 00 75 9E 83 7C 24 28 00 7E 0D 8B 44 24 24 C6 04 18 00 8D 43 01 EB 03 83 C8 FF 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule bsearch_8728cb81fd3e7d3e3755505b3200cf38 {
	meta:
		aliases = "bsearch"
		size = "91"
		objfiles = "bsearch@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 31 ED 8B 74 24 28 83 7C 24 2C 00 75 39 EB 3B 89 F0 8B 7C 24 24 29 E8 D1 E8 8D 5C 05 00 8B 44 24 2C 0F AF C3 01 C7 50 50 57 FF 74 24 2C FF 54 24 40 83 C4 10 83 F8 00 7E 05 8D 6B 01 EB 08 75 04 89 F8 EB 08 89 DE 39 F5 72 C5 31 C0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _fp_out_narrow_62811f8e795039622a06149add6dff88 {
	meta:
		aliases = "_fp_out_narrow"
		size = "106"
		objfiles = "_vfprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 31 ED 8B 7C 24 24 8B 5C 24 28 89 F8 84 C0 79 2F 83 EC 0C FF 74 24 38 E8 ?? ?? ?? ?? 83 C4 10 29 C3 89 C6 85 DB 7E 16 83 E7 7F 89 D9 89 FA 8B 44 24 20 E8 ?? ?? ?? ?? 89 C5 39 D8 75 1C 89 F3 31 C0 85 DB 7E 12 51 FF 74 24 24 53 FF 74 24 38 E8 ?? ?? ?? ?? 83 C4 10 01 C5 83 C4 0C 89 E8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __pthread_destroy_specifics_5019d084e30de3ab9ff36aab801875dd {
	meta:
		aliases = "__pthread_destroy_specifics"
		size = "211"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 31 ED E8 ?? ?? ?? ?? 89 C6 C7 44 24 08 01 00 00 00 EB 58 31 FF 83 BC 9E EC 00 00 00 00 75 40 EB 43 89 D8 C1 E0 05 01 F8 8B 0C C5 ?? ?? ?? ?? 8D 04 BD 00 00 00 00 03 84 9E EC 00 00 00 85 C9 8B 10 74 1B 85 D2 74 17 83 EC 0C C7 00 00 00 00 00 52 FF D1 C7 44 24 18 01 00 00 00 83 C4 10 47 83 FF 1F 7E BD 43 83 FB 1F 7E A9 45 83 7C 24 08 00 74 11 83 FD 03 7F 0C 31 DB C7 44 24 08 00 00 00 00 EB E2 8B 46 1C 89 F2 E8 ?? ?? ?? ?? 31 DB EB 23 8B 84 9E EC 00 00 00 85 C0 74 17 83 EC 0C 50 E8 ?? ?? ?? ?? C7 84 9E EC 00 00 00 00 00 00 00 83 C4 10 43 83 FB 1F 7E D8 83 EC 0C FF 76 1C E8 ?? }
	condition:
		$pattern
}

rule __GI_svc_getreqset_ede7b418cd436d6e818b68e0d8cccb49 {
	meta:
		aliases = "svc_getreqset, __GI_svc_getreqset"
		size = "94"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 31 ED E8 ?? ?? ?? ?? 8B 7C 24 20 89 44 24 08 EB 38 8B 37 EB 1C 83 EC 0C 8D 44 1D FF 50 E8 ?? ?? ?? ?? 8D 4B FF B8 01 00 00 00 D3 E0 31 C6 83 C4 10 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 75 D2 83 C7 04 83 C5 20 3B 6C 24 08 7C C2 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule svc_getreq_poll_05818e28c7352cc06e8694bb0b048a4d {
	meta:
		aliases = "__GI_svc_getreq_poll, svc_getreq_poll"
		size = "103"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 31 F6 31 FF 8B 6C 24 24 EB 41 8B 54 24 20 8D 04 F2 8B 18 83 FB FF 74 32 66 8B 40 06 66 85 C0 74 29 47 A8 20 74 18 E8 ?? ?? ?? ?? 83 EC 0C 8B 80 B4 00 00 00 FF 34 98 E8 ?? ?? ?? ?? EB 09 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 46 E8 ?? ?? ?? ?? 3B 30 7D 04 39 EF 7C B2 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule xdr_vector_c30beaefc136581a9e9d04e4b1f44ae4 {
	meta:
		aliases = "xdr_vector"
		size = "62"
		objfiles = "xdr_array@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 31 F6 8B 6C 24 2C 8B 7C 24 30 8B 5C 24 24 EB 14 50 6A FF 53 FF 74 24 2C FF D7 83 C4 10 85 C0 74 0E 01 EB 46 3B 74 24 28 72 E6 B8 01 00 00 00 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __psfs_parse_spec_ea056ee73a83f5d3015c9ca38568adf1 {
	meta:
		aliases = "__psfs_parse_spec"
		size = "447"
		objfiles = "__psfs_parse_spec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 31 FF BD 01 00 00 00 8B 5C 24 20 8B 43 30 89 44 24 08 8A 00 83 E8 30 3C 09 77 4B 81 FF CB CC CC 0C 7F 11 6B CF 0A 8B 43 30 0F B6 10 40 8D 7C 11 D0 89 43 30 8B 73 30 8A 16 8D 42 D0 3C 09 76 DB 80 FA 24 74 19 83 7B 24 00 0F 89 53 01 00 00 89 7B 40 C7 43 24 FE FF FF FF E9 A1 00 00 00 8D 46 01 31 ED 89 43 30 BE ?? ?? ?? ?? B9 10 00 00 00 8B 53 30 8A 06 3A 02 75 0B 08 4B 45 8D 42 01 89 43 30 EB E2 46 80 3E 00 74 04 01 C9 EB E2 F6 43 45 10 74 06 C6 43 44 00 EB 3A 89 E8 84 C0 74 1B 83 7B 24 00 0F 89 F8 00 00 00 C7 43 24 FE FF FF FF EB 21 8D 41 01 89 43 30 EB 58 83 7B 24 FE 0F 84 }
	condition:
		$pattern
}

rule __pthread_lock_fb3244e5b0dd725e2182c68e6e3d4b43 {
	meta:
		aliases = "__pthread_lock"
		size = "139"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 89 C3 89 D7 83 38 00 75 14 31 D2 B9 01 00 00 00 89 D0 F0 0F B1 0B 0F 94 C2 84 D2 75 5F 31 ED 8B 33 F7 C6 01 00 00 00 75 0C 89 F1 BA 01 00 00 00 83 C9 01 EB 12 85 FF 75 07 E8 ?? ?? ?? ?? 89 C7 89 F9 31 D2 83 C9 01 85 FF 74 03 89 77 0C 89 F0 F0 0F B1 0B 0F 94 C1 84 C9 74 C4 85 D2 75 17 89 F8 E8 ?? ?? ?? ?? 83 7F 0C 00 74 B3 45 EB F0 89 F8 E8 ?? ?? ?? ?? 4D 83 FD FF 75 F3 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule do_dlclose_f48561a4a048b0de33c0bb6ca19f3532 {
	meta:
		aliases = "do_dlclose"
		size = "553"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 89 C5 3B 05 ?? ?? ?? ?? 89 54 24 04 0F 84 06 02 00 00 A1 ?? ?? ?? ?? 31 D2 EB 09 39 E8 74 1A 89 C2 8B 40 04 85 C0 75 F3 B0 01 C7 05 ?? ?? ?? ?? 09 00 00 00 E9 E1 01 00 00 85 D2 8B 45 04 74 05 89 42 04 EB 05 A3 ?? ?? ?? ?? 8B 55 00 8B 42 20 C7 44 24 08 00 00 00 00 66 83 F8 01 0F 84 6C 01 00 00 48 83 EC 0C 66 89 42 20 55 E8 ?? ?? ?? ?? 31 C0 83 C4 10 E9 A0 01 00 00 8B 45 08 8B 54 24 08 8B 3C 90 66 FF 4F 20 66 83 7F 20 00 0F 85 37 01 00 00 83 7F 74 00 75 09 83 BF A8 00 00 00 00 74 2D 83 7C 24 04 00 74 26 66 8B 47 22 A8 08 75 1E 83 C8 08 83 EC 0C 66 89 47 22 57 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __get_next_rpcent_2bf11fb749e551e2af926bcdbf6962a4 {
	meta:
		aliases = "__get_next_rpcent"
		size = "268"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 89 C7 50 8D B7 A8 00 00 00 FF 37 68 00 10 00 00 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 92 00 00 00 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 C6 84 38 A7 00 00 00 0A 80 BF A8 00 00 00 23 74 C4 50 50 6A 23 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 11 55 55 6A 0A 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 A2 C6 00 00 89 F0 E8 ?? ?? ?? ?? 85 C0 74 94 8D 58 01 C6 00 00 89 B7 9C 00 00 00 EB 01 43 8A 03 3C 20 74 F9 3C 09 74 F5 83 EC 0C 8D 6F 10 89 EE 53 E8 ?? ?? ?? ?? 83 C4 10 89 87 A4 00 00 00 89 AF A0 00 00 00 89 D8 E8 ?? ?? ?? ?? 31 D2 85 C0 74 36 EB 04 31 C0 EB 46 8D 50 01 C6 00 00 EB 28 3C 20 }
	condition:
		$pattern
}

rule get_input_bytes_168b901466545159c49ef149ec970647 {
	meta:
		aliases = "get_input_bytes"
		size = "82"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 89 C7 89 D5 89 CE EB 32 8B 57 2C 8B 47 30 29 D0 75 0D 89 F8 E8 ?? ?? ?? ?? 85 C0 75 1D EB 24 89 C3 39 F0 7E 02 89 F3 51 53 52 55 E8 ?? ?? ?? ?? 01 5F 2C 01 DD 29 DE 83 C4 10 85 F6 7F CA B8 01 00 00 00 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __copy_rpcent_ccbeef8871cf601921eb1d55e3fe35bd {
	meta:
		aliases = "__copy_rpcent"
		size = "267"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 89 C7 89 D6 89 CB 8B 44 24 24 85 FF C7 00 00 00 00 00 B8 02 00 00 00 0F 84 DF 00 00 00 50 6A 0C 6A 00 52 E8 ?? ?? ?? ?? 83 C4 0C FF 74 24 24 6A 00 53 E8 ?? ?? ?? ?? 8B 47 08 89 46 08 31 D2 83 C4 10 8B 4F 04 8B 04 91 42 85 C0 75 F8 8D 04 95 00 00 00 00 39 44 24 20 0F 82 99 00 00 00 8D 6A FF 8B 54 24 20 89 5E 04 29 C2 01 C3 89 54 24 04 89 5C 24 08 EB 4B 8B 47 04 8D 1C AD 00 00 00 00 83 EC 0C FF 34 18 E8 ?? ?? ?? ?? 83 C4 10 8D 50 01 39 54 24 04 72 60 8B 46 04 8B 4C 24 08 89 0C 18 01 D1 29 54 24 04 89 4C 24 08 50 8B 47 04 52 FF 34 18 8B 46 04 FF 34 18 E8 ?? ?? ?? ?? 83 C4 10 }
	condition:
		$pattern
}

rule rwlock_have_already_abe612d3f526a32c777a5b61e40fa9cd {
	meta:
		aliases = "rwlock_have_already"
		size = "172"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 89 C7 89 D6 89 CD 8B 18 83 7A 18 01 74 04 31 D2 EB 71 85 DB 75 07 E8 ?? ?? ?? ?? 89 C3 8B 93 C0 01 00 00 EB 07 39 72 04 74 08 8B 12 85 D2 75 F5 EB 04 85 D2 75 53 83 BB C8 01 00 00 00 7F 4A 8B 93 C4 01 00 00 85 D2 74 0A 8B 02 89 83 C4 01 00 00 EB 0F 83 EC 0C 6A 0C E8 ?? ?? ?? ?? 83 C4 10 89 C2 B9 01 00 00 00 85 D2 74 1A C7 42 08 01 00 00 00 89 72 04 8B 83 C0 01 00 00 89 02 89 93 C0 01 00 00 31 C9 31 F6 EB 07 31 C9 BE 01 00 00 00 8B 44 24 20 89 08 89 55 00 89 F0 89 1F 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule pthread_cleanup_upto_1aed8a0dda7c38c31bc4156db7fc323b {
	meta:
		aliases = "pthread_cleanup_upto"
		size = "146"
		objfiles = "ptlongjmp@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 89 C7 BE ?? ?? ?? ?? 8D 44 24 0C 3B 05 ?? ?? ?? ?? 73 36 3B 05 ?? ?? ?? ?? 72 0D BE ?? ?? ?? ?? 3B 05 ?? ?? ?? ?? 72 21 83 3D ?? ?? ?? ?? 00 74 0D E8 ?? ?? ?? ?? 89 C6 EB 0F 31 DB EB 2F 0D FF FF 1F 00 8D B0 21 FE FF FF 8D 6C 24 0C 8B 5E 3C EB 12 39 EB 76 E4 83 EC 0C FF 73 04 FF 13 8B 5B 0C 83 C4 10 85 DB 74 05 3B 5F 10 72 E5 8B 46 54 89 5E 3C 85 C0 74 0C 3B 47 10 73 07 C7 46 54 00 00 00 00 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __md5_Update_b9c8c3011fc3beeca44574140bcdac7d {
	meta:
		aliases = "__md5_Update"
		size = "154"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 89 CF 89 C6 89 54 24 08 8D 14 FD 00 00 00 00 8B 40 10 89 C1 01 D0 C1 E9 03 89 46 10 83 E1 3F 39 D0 73 03 FF 46 14 89 F8 BD 40 00 00 00 C1 E8 1D 29 CD 01 46 14 31 DB 39 EF 72 3B 50 55 FF 74 24 10 8D 5E 18 8D 04 0B 50 E8 ?? ?? ?? ?? 89 DA 89 F0 E8 ?? ?? ?? ?? 89 EB 83 C4 10 EB 10 8B 54 24 08 89 F0 01 DA 83 C3 40 E8 ?? ?? ?? ?? 8D 43 3F 39 F8 72 E9 31 C9 29 DF 52 57 8B 44 24 10 01 D8 50 8D 44 0E 18 50 E8 ?? ?? ?? ?? 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __malloc_trim_1a1aefbf1d40839633fecdd9d23b5be5 {
	meta:
		aliases = "__malloc_trim"
		size = "141"
		objfiles = "free@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 89 D5 8B 8A 5C 03 00 00 8B 52 2C 8B 72 04 83 E6 FC 89 F2 29 C2 8D 44 0A EF 31 D2 F7 F1 8D 58 FF 0F AF D9 85 DB 7E 55 83 EC 0C 6A 00 E8 ?? ?? ?? ?? 89 C7 89 F0 03 45 2C 83 C4 10 39 C7 75 3D 83 EC 0C F7 DB 53 E8 ?? ?? ?? ?? C7 04 24 00 00 00 00 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 74 1E 89 F9 29 C1 74 18 8B 45 2C 29 8D 68 03 00 00 29 CE 83 CE 01 89 70 04 B8 01 00 00 00 EB 02 31 C0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _stdlib_strto_l_c401e361b6480ac8bda8cbd485853b65 {
	meta:
		aliases = "_stdlib_strto_l"
		size = "277"
		objfiles = "_stdlib_strto_l@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 15 ?? ?? ?? ?? 8B 4C 24 20 8B 74 24 28 89 CB EB 01 43 0F BE 03 F6 04 42 20 75 F6 83 F8 2B 74 0E 31 ED 83 F8 2D 75 0A BD 01 00 00 00 EB 02 31 ED 43 89 CF F7 C6 EF FF FF FF 75 24 83 C6 0A 80 3B 30 75 12 43 83 EE 02 89 DF 8A 03 83 C8 20 3C 78 75 03 01 F6 43 83 FE 10 7E 05 BE 10 00 00 00 8D 46 FE 31 D2 83 F8 22 77 61 83 C8 FF 31 D2 F7 F6 88 54 24 0B 31 D2 89 44 24 04 EB 02 89 DF 8A 03 8D 48 D0 80 F9 09 76 0C 83 C8 20 B1 28 3C 60 76 03 8D 48 A9 0F B6 C1 39 F0 7D 2F 43 3B 54 24 04 77 08 75 1C 3A 4C 24 0B 76 16 8A 44 24 2C 21 C5 E8 ?? ?? ?? ?? 83 CA FF C7 00 22 00 00 00 EB BC }
	condition:
		$pattern
}

rule getenv_7d91481b499c1254c89b3a32fac62b37 {
	meta:
		aliases = "__GI_getenv, getenv"
		size = "83"
		objfiles = "getenv@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 35 ?? ?? ?? ?? 8B 6C 24 20 85 F6 74 34 83 EC 0C 55 E8 ?? ?? ?? ?? 83 C4 10 89 C7 EB 1E 50 57 53 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 0B 8D 04 3B 80 38 3D 75 03 40 EB 0B 83 C6 04 8B 1E 85 DB 75 DC 31 C0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule getsubopt_47c7ff55f6166a55c0107ae30dbf690f {
	meta:
		aliases = "getsubopt"
		size = "203"
		objfiles = "getsubopt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 44 24 20 8B 30 C7 44 24 08 FF FF FF FF 80 3E 00 0F 84 A1 00 00 00 52 52 6A 2C 56 E8 ?? ?? ?? ?? 83 C4 0C 89 C3 29 F0 50 6A 3D 56 E8 ?? ?? ?? ?? 83 C4 10 89 C5 85 C0 75 02 89 DD C7 44 24 08 00 00 00 00 EB 46 89 EA 29 F2 89 54 24 04 50 52 57 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 2A 8B 44 24 04 80 3C 07 00 75 20 31 C0 39 DD 74 03 8D 45 01 8B 54 24 28 89 02 80 3B 00 74 04 C6 03 00 43 8B 44 24 20 89 18 EB 30 FF 44 24 08 8B 54 24 08 8B 44 24 24 8B 3C 90 85 FF 75 AB 8B 54 24 28 89 32 80 3B 00 74 04 C6 03 00 43 8B 44 24 20 89 18 C7 44 24 08 FF FF FF FF 8B 44 24 08 83 C4 0C 5B 5E }
	condition:
		$pattern
}

rule xdrrec_putbytes_9fbf85822e68b3a02069334892ebef44 {
	meta:
		aliases = "xdrrec_putbytes"
		size = "108"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 44 24 20 8B 6C 24 24 8B 7C 24 28 8B 58 0C EB 43 8B 53 10 8B 43 14 29 D0 89 C6 39 F8 76 02 89 FE 50 56 55 52 E8 ?? ?? ?? ?? 01 73 10 8B 43 10 29 F7 83 C4 10 3B 43 14 75 18 85 FF 74 14 31 D2 C7 43 1C 01 00 00 00 89 D8 E8 ?? ?? ?? ?? 85 C0 74 0B 01 F5 85 FF 75 B9 B8 01 00 00 00 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule xdrrec_getbytes_a4fe0588ad50b2f8e8051ffc7087d41b {
	meta:
		aliases = "xdrrec_getbytes"
		size = "101"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 44 24 20 8B 6C 24 24 8B 7C 24 28 8B 70 0C EB 38 8B 46 34 85 C0 75 13 83 7E 38 00 75 36 89 F0 E8 ?? ?? ?? ?? 85 C0 75 20 EB 29 89 C3 39 F8 76 02 89 FB 89 D9 89 EA 89 F0 E8 ?? ?? ?? ?? 85 C0 74 12 29 5E 34 01 DD 29 DF 85 FF 75 C4 B8 01 00 00 00 EB 02 31 C0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule regerror_39c3e252b0c2d688199765b6b81a538d {
	meta:
		aliases = "__regerror, regerror"
		size = "104"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 44 24 20 8B 6C 24 28 8B 7C 24 2C 83 F8 10 76 05 E8 ?? ?? ?? ?? 83 EC 0C 8B 1C 85 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 85 FF 8D 70 01 74 21 39 FE 76 11 50 8D 47 FF 50 53 55 E8 ?? ?? ?? ?? C6 00 00 EB 09 51 56 53 55 E8 ?? ?? ?? ?? 83 C4 10 83 C4 0C 89 F0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _time_t2tm_32850b2b2cb48db257e554756f5e06bf {
	meta:
		aliases = "_time_t2tm"
		size = "355"
		objfiles = "_time_t2tm@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 44 24 20 8B 74 24 28 8B 18 C7 46 1C 00 00 00 00 C7 44 24 08 ?? ?? ?? ?? 8B 44 24 08 66 8B 28 0F B7 CD 83 F9 07 75 29 89 D8 99 F7 F9 8D 42 0B 99 F7 F9 89 54 24 04 8B 54 24 08 0F B7 42 02 8D 0C 85 01 00 00 00 8B 44 24 24 8D 9C 18 76 0E 02 00 89 D8 99 F7 F9 89 C7 0F AF C1 29 C3 79 03 01 CB 4F 66 83 FD 07 75 0D 8D 41 FF 39 C3 75 06 FF 46 10 8D 59 FE 83 F9 3C 8D 56 04 7F 08 89 1E 89 D6 89 FB EB 04 89 3E 89 D6 83 44 24 08 02 8B 44 24 08 66 83 38 00 75 81 83 7A FC 04 75 0C C7 42 FC 03 00 00 00 BB 6D 01 00 00 01 1A 8D 5A F8 8B 43 F8 C1 E0 02 03 43 FC 6B C0 19 03 42 F8 C1 E0 02 }
	condition:
		$pattern
}

rule svcudp_enablecache_1f88d5ffc8c85f49fe5b1a018c695397 {
	meta:
		aliases = "svcudp_enablecache"
		size = "193"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 44 24 20 8B 7C 24 24 8B 68 30 83 BD B0 01 00 00 00 74 08 56 68 ?? ?? ?? ?? EB 6D 83 EC 0C 6A 2C E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 75 08 53 68 ?? ?? ?? ?? EB 52 83 EC 0C 89 FE 89 38 C7 40 0C 00 00 00 00 C1 E6 04 56 E8 ?? ?? ?? ?? 83 C4 10 89 43 04 85 C0 75 08 51 68 ?? ?? ?? ?? EB 29 52 56 8D 34 BD 00 00 00 00 6A 00 50 E8 ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 83 C4 10 89 43 08 85 C0 75 1A 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 EB 15 52 56 6A 00 50 E8 ?? ?? ?? ?? 89 9D B0 01 00 00 B8 01 00 00 00 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_initstate_r_be618b6520925acb7ec228c5d3a1b046 {
	meta:
		aliases = "initstate_r, __GI_initstate_r"
		size = "171"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 44 24 28 8B 6C 24 24 8B 7C 24 2C 83 F8 7F 76 0C 3D 00 01 00 00 19 DB 83 C3 04 EB 16 83 F8 1F 77 09 31 DB 83 F8 07 77 0A EB 58 83 F8 40 19 DB 83 C3 02 8B 04 9D ?? ?? ?? ?? 8D 75 04 89 47 10 8B 14 9D ?? ?? ?? ?? 8D 04 86 89 5F 0C 89 57 14 89 47 18 89 77 08 57 FF 74 24 24 E8 ?? ?? ?? ?? C7 45 00 00 00 00 00 59 58 31 C0 85 DB 74 2D 8B 47 04 29 F0 C1 F8 02 8D 04 80 01 D8 89 45 00 31 C0 EB 19 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_lfind_c8ca37138f3ccfb57fc1cc698c6d9dda {
	meta:
		aliases = "lfind, __GI_lfind"
		size = "65"
		objfiles = "lfind@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 44 24 28 8B 74 24 24 8B 6C 24 2C 8B 7C 24 30 8B 18 EB 16 50 50 56 FF 74 24 2C FF D7 83 C4 10 85 C0 75 04 89 F0 EB 0A 01 EE 4B 83 FB FF 75 E4 31 C0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __ns_name_unpack_470fa5abd6ce80ce2f6f986e6c82a78a {
	meta:
		aliases = "__GI___ns_name_unpack, __ns_name_unpack"
		size = "265"
		objfiles = "ns_name@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 44 24 2C 8B 54 24 30 01 C2 89 54 24 04 8B 54 24 20 39 54 24 28 0F 82 A5 00 00 00 8B 54 24 24 39 54 24 28 0F 83 97 00 00 00 8B 74 24 28 89 C1 31 ED C7 44 24 08 FF FF FF FF E9 97 00 00 00 89 D8 25 C0 00 00 00 74 09 3D C0 00 00 00 75 72 EB 2D 8D 44 19 01 3B 44 24 04 73 66 8D 34 1A 3B 74 24 24 73 5D 88 19 8D 79 01 50 53 52 57 E8 ?? ?? ?? ?? 8D 6C 1D 01 8D 0C 1F 83 C4 10 EB 58 3B 54 24 24 73 3D 83 7C 24 08 00 79 09 2B 54 24 28 42 89 54 24 08 83 E3 3F 0F B6 46 01 C1 E3 08 8B 74 24 20 09 C3 01 DE 3B 74 24 20 72 15 3B 74 24 24 73 0F 8B 44 24 24 83 C5 02 2B 44 24 20 39 C5 7C 15 }
	condition:
		$pattern
}

rule imaxdiv_9040d428900bd199969720bb2a395250 {
	meta:
		aliases = "lldiv, imaxdiv"
		size = "112"
		objfiles = "lldiv@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 44 24 2C 8B 54 24 30 8B 74 24 28 8B 5C 24 24 89 04 24 89 54 24 04 52 50 56 53 E8 ?? ?? ?? ?? 83 C4 10 FF 74 24 04 FF 74 24 04 56 53 89 C7 89 D5 E8 ?? ?? ?? ?? 83 C4 10 85 F6 78 11 85 D2 79 0D 83 C7 01 83 D5 00 2B 04 24 1B 54 24 04 8B 4C 24 20 89 41 08 89 51 0C 89 39 89 69 04 89 C8 83 C4 0C 5B 5E 5F 5D C2 04 00 }
	condition:
		$pattern
}

rule __pthread_unlock_c248d999565f5a5de8a34fa81d5453c9 {
	meta:
		aliases = "__pthread_unlock"
		size = "158"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 4C 24 20 EB 0F 31 DB 89 D0 F0 0F B1 19 0F 94 C2 84 D2 75 78 8B 11 83 FA 01 74 EA 89 D7 83 E7 FE 89 F8 89 CD 89 CE C7 04 24 00 00 00 00 EB 16 8B 58 18 3B 1C 24 7C 05 89 EE 89 1C 24 8D 68 0C 8B 40 0C 83 E0 FE 85 C0 75 E6 39 CE 75 15 8B 5F 0C 89 D0 83 E3 FE F0 0F B1 19 0F 94 C2 84 D2 74 B4 EB 1C 8B 3E 83 E7 FE 8B 47 0C 89 06 8B 01 89 C2 83 E2 FE F0 0F B1 11 0F 94 C2 84 D2 74 EE C7 47 0C 00 00 00 00 89 F8 E8 ?? ?? ?? ?? 83 C4 0C 31 C0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _dl_fixup_d408b364404d18b24ec5815b6d620cba {
	meta:
		aliases = "_dl_fixup"
		size = "286"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 54 24 20 8B 42 10 85 C0 74 19 51 51 FF 74 24 2C 50 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 0F 85 E9 00 00 00 8B 44 24 20 BE 01 00 00 00 8B 18 66 8B 43 22 83 7B 5C 00 0F 85 D0 00 00 00 8B B3 84 00 00 00 8B AB 88 00 00 00 85 F6 74 4F A8 01 75 4B 8B 8B C8 00 00 00 89 F0 85 C9 74 27 8D 14 CD 00 00 00 00 89 54 24 08 8D 56 F8 8B 3B 83 C2 08 89 F8 03 02 01 38 49 75 F4 8B 54 24 08 2B 6C 24 08 8D 04 16 52 55 50 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 66 83 4B 22 01 89 C6 EB 02 31 F6 83 BB A0 00 00 00 00 74 08 C7 44 24 24 02 00 00 00 83 BB 9C 00 00 00 00 74 55 F6 43 22 02 74 10 83 7C 24 }
	condition:
		$pattern
}

rule __decode_dotted_1777b2bc1e9afceb8537a5c244ec0069 {
	meta:
		aliases = "__decode_dotted"
		size = "215"
		objfiles = "decoded@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 54 24 24 83 7C 24 20 00 0F 84 B6 00 00 00 31 ED 31 C9 C6 44 24 0B 01 E9 8C 00 00 00 80 7C 24 0B 01 89 D8 8D 72 01 83 DD FF 25 C0 00 00 00 3D C0 00 00 00 75 23 80 7C 24 0B 01 89 DA 8B 5C 24 20 83 DD FF 83 E2 3F 0F B6 04 33 C1 E2 08 89 CF 09 C2 C6 44 24 0B 00 EB 4E 8D 04 19 89 C7 89 44 24 04 47 3B 7C 24 2C 73 5C 50 53 8B 44 24 28 01 F0 50 8B 44 24 34 01 C8 50 E8 ?? ?? ?? ?? 83 C4 10 8D 14 1E 80 7C 24 0B 00 74 02 01 DD 8B 4C 24 20 8B 5C 24 28 80 3C 11 01 8B 4C 24 04 19 C0 F7 D0 83 E0 2E 88 04 0B 89 F9 8B 44 24 20 0F B6 1C 10 85 DB 0F 85 64 FF FF FF 80 7C 24 0B 01 89 E8 83 }
	condition:
		$pattern
}

rule __GI_memmem_66d38250d01aa88c836461cfeed6ce64 {
	meta:
		aliases = "memmem, __GI_memmem"
		size = "93"
		objfiles = "memmem@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 5C 24 20 8B 54 24 24 8B 7C 24 2C 8B 6C 24 28 8D 34 13 89 D8 29 FE 85 FF 74 33 EB 04 89 D8 EB 2D 39 FA 73 23 EB 25 8A 03 3A 45 00 75 19 50 8D 47 FF 50 8D 45 01 50 8D 43 01 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 D6 43 39 F3 76 DB 31 C0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __ieee754_atanh_0b15a3c7c9835b1796b73e0f981ab474 {
	meta:
		aliases = "__ieee754_atanh"
		size = "236"
		objfiles = "e_atanh@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 5C 24 20 8B 74 24 24 89 D8 89 F7 F7 D8 09 D8 81 E7 FF FF FF 7F C1 E8 1F 89 F5 09 F8 3D 00 00 F0 3F 76 10 89 1C 24 89 74 24 04 DD 04 24 D8 E0 D8 F0 EB 18 81 FF 00 00 F0 3F 75 1C 89 1C 24 89 74 24 04 DD 04 24 DC 35 ?? ?? ?? ?? DD 1C 24 8B 1C 24 8B 74 24 04 EB 7B 81 FF FF FF 2F 3E 7F 1B 89 1C 24 89 74 24 04 DD 04 24 DC 05 ?? ?? ?? ?? D9 EE D9 C9 DA E9 DF E0 9E 77 58 89 1C 24 89 7C 24 04 DD 04 24 D9 C0 D9 C1 DE C2 81 FF FF FF DF 3F D9 E8 7F 10 D9 C2 D8 CA D9 C9 52 52 DE E2 DE F1 DE C1 EB 06 DE E1 50 50 DE F9 83 EC 08 DD 1C 24 E8 ?? ?? ?? ?? 83 C4 10 DC 0D ?? ?? ?? ?? 85 ED }
	condition:
		$pattern
}

rule __GI_setstate_r_b9455eade1ea557cead508ef92d0ebd2 {
	meta:
		aliases = "setstate_r, __GI_setstate_r"
		size = "153"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 5C 24 24 8B 74 24 20 83 C6 04 8B 4B 0C 8B 53 08 85 C9 75 09 C7 42 FC 00 00 00 00 EB 10 8B 43 04 29 D0 C1 F8 02 8D 04 80 01 C8 89 42 FC 8B 46 FC BF 05 00 00 00 99 F7 FF 83 FA 04 77 3E 8B 0C 95 ?? ?? ?? ?? 8B 2C 95 ?? ?? ?? ?? 89 4B 10 89 6B 14 89 53 0C 85 D2 74 16 8B 46 FC 99 F7 FF 8D 14 86 01 E8 89 53 04 99 F7 F9 8D 14 96 89 13 8D 04 8E 89 73 08 89 43 18 31 C0 EB 0E E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __stdio_fwrite_7ee07b39d9ce3c975ef7466481691341 {
	meta:
		aliases = "__stdio_fwrite"
		size = "240"
		objfiles = "_fwrite@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 5C 24 28 8B 6C 24 20 8B 7C 24 24 F6 43 01 02 0F 85 B1 00 00 00 83 7B 04 FE 8B 53 10 8B 43 0C 75 1E 29 D0 89 FE 39 C7 76 02 89 C6 50 56 55 52 E8 ?? ?? ?? ?? 01 73 10 83 C4 10 E9 9F 00 00 00 29 D0 39 C7 77 68 51 57 55 52 E8 ?? ?? ?? ?? 01 7B 10 83 C4 10 F6 43 01 01 0F 84 80 00 00 00 52 57 6A 0A 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 6F 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 5F 89 FE 39 C7 76 02 89 C6 89 F8 29 F0 01 C5 50 56 6A 0A 55 E8 ?? ?? ?? ?? 83 C4 10 89 C2 85 C0 74 3E 8D 44 35 00 29 D0 29 43 10 29 C7 EB 31 3B 53 08 74 14 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 }
	condition:
		$pattern
}

rule _stdlib_wcsto_l_75315b7d105cb147f42ddcc5c6e71199 {
	meta:
		aliases = "_stdlib_wcsto_l"
		size = "316"
		objfiles = "_stdlib_wcsto_l@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 6C 24 20 8B 74 24 28 89 EB EB 03 83 C3 04 83 EC 0C FF 33 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 EC 8B 03 83 F8 2B 74 11 C6 44 24 0A 00 83 F8 2D 75 0F C6 44 24 0A 01 EB 05 C6 44 24 0A 00 83 C3 04 89 EF F7 C6 EF FF FF FF 75 29 83 C6 0A 83 3B 30 75 17 83 C3 04 83 EE 02 89 DF 8B 03 83 C8 20 83 F8 78 75 05 01 F6 83 C3 04 83 FE 10 7E 05 BE 10 00 00 00 8D 46 FE 31 ED 83 F8 22 77 73 83 C8 FF 31 D2 F7 F6 89 44 24 04 88 54 24 0B EB 02 89 DF 8B 13 8D 42 D0 83 F8 09 77 05 8D 4A D0 EB 14 89 D0 B1 28 83 C8 20 83 F8 60 76 08 88 D0 83 C8 20 8D 48 A9 0F B6 C1 39 F0 7D 36 83 C3 04 3B 6C 24 04 }
	condition:
		$pattern
}

rule __GI_getcwd_6a42c54071917ef52693cd7e0e5c6902 {
	meta:
		aliases = "getcwd, __GI_getcwd"
		size = "185"
		objfiles = "getcwd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 6C 24 24 8B 7C 24 20 85 ED 75 29 85 FF 74 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 86 00 00 00 E8 ?? ?? ?? ?? 89 C3 3D 00 10 00 00 7D 0F BB 00 10 00 00 EB 08 89 EB 89 FE 85 FF 75 12 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 74 57 89 F2 89 D9 87 D3 B8 B7 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0B E8 ?? ?? ?? ?? F7 DB 89 18 EB 22 85 C0 78 1E 85 FF 75 2E 85 ED 75 12 52 52 50 56 E8 ?? ?? ?? ?? 83 C4 10 89 C7 85 C0 75 18 89 F7 EB 14 85 FF 75 0E 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 EB 02 31 FF 83 C4 0C 89 F8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_xdr_reference_4982710af1bb6234d7b4b0b1266a10ba {
	meta:
		aliases = "xdr_reference, __GI_xdr_reference"
		size = "149"
		objfiles = "xdr_reference@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 6C 24 24 8B 7C 24 20 8B 74 24 28 8B 5D 00 85 DB 75 4B 8B 07 83 F8 01 74 0C BE 01 00 00 00 83 F8 02 74 60 EB 38 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 89 C3 89 45 00 85 C0 75 16 51 51 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 F6 EB 30 52 56 6A 00 50 E8 ?? ?? ?? ?? 83 C4 10 50 6A FF 53 57 FF 54 24 3C 83 C4 10 89 C6 83 3F 02 75 13 83 EC 0C 53 E8 ?? ?? ?? ?? C7 45 00 00 00 00 00 83 C4 10 83 C4 0C 89 F0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fread_unlocked_154671778141a11479606f113b4b0f78 {
	meta:
		aliases = "__GI_fread_unlocked, fread_unlocked"
		size = "275"
		objfiles = "fread_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 6C 24 2C 8B 5C 24 28 0F B7 45 00 25 83 00 00 00 3D 80 00 00 00 77 18 56 56 68 80 00 00 00 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 D2 00 00 00 83 7C 24 24 00 0F 84 C7 00 00 00 85 DB 0F 84 BF 00 00 00 83 C8 FF 31 D2 F7 74 24 24 39 C3 0F 87 9E 00 00 00 0F AF 5C 24 24 8B 7C 24 20 89 DE 89 5C 24 08 EB 1B 83 E0 01 4E 8B 44 85 24 88 07 8D 42 FF 66 89 45 00 C7 45 28 00 00 00 00 74 63 47 8B 55 00 0F B7 C2 A8 02 75 DB 8B 55 10 8B 45 14 29 D0 74 1D 89 F3 39 C6 76 02 89 C3 51 53 52 57 E8 ?? ?? ?? ?? 01 5D 10 83 C4 10 29 DE 74 33 01 DF 0F B7 45 00 F6 C4 03 74 18 83 EC 0C 68 ?? ?? ?? }
	condition:
		$pattern
}

rule sgetspent_r_33dd0def94ef4e31f36fa082d8ec76f6 {
	meta:
		aliases = "__GI_sgetspent_r, sgetspent_r"
		size = "122"
		objfiles = "sgetspent_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 6C 24 30 8B 7C 24 2C 8B 5C 24 20 8B 74 24 28 81 FF FF 00 00 00 C7 45 00 00 00 00 00 77 12 E8 ?? ?? ?? ?? C7 00 22 00 00 00 B8 22 00 00 00 EB 3A 39 F3 74 1C 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 39 F8 73 DA 52 52 53 56 E8 ?? ?? ?? ?? 83 C4 10 50 50 56 FF 74 24 30 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 07 8B 54 24 24 89 55 00 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __pthread_alt_unlock_9a2d441c80ab198fecf8a835cf795b64 {
	meta:
		aliases = "__pthread_alt_unlock"
		size = "174"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 74 24 20 8B 16 83 FA 01 77 14 31 C9 89 D0 F0 0F B1 0E 0F 94 C2 84 D2 74 EA E9 80 00 00 00 89 D3 89 F5 89 D7 89 34 24 C7 44 24 04 00 00 00 80 EB 3A 83 7B 08 00 74 1B 89 D9 89 EA 89 F0 E8 ?? ?? ?? ?? 89 D8 E8 ?? ?? ?? ?? 8B 5D 00 39 F5 75 1B EB 19 8B 43 04 8B 40 18 3B 44 24 04 7C 09 89 DF 89 2C 24 89 44 24 04 89 DD 8B 1B 83 FB 01 75 C1 81 7C 24 04 00 00 00 80 74 89 89 D8 87 47 08 85 C0 75 80 89 F0 89 F9 8B 14 24 E8 ?? ?? ?? ?? 8B 47 04 83 C4 0C 5B 5E 5F 5D E9 ?? ?? ?? ?? 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_wcsncasecmp_7ff4e4ed96f450df924a2d75ebd18a3f {
	meta:
		aliases = "wcsncasecmp, __GI_wcsncasecmp"
		size = "111"
		objfiles = "wcsncasecmp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 74 24 20 8B 7C 24 24 8B 6C 24 28 EB 0C 83 3E 00 74 4B 83 C6 04 83 C7 04 4D 85 ED 74 40 8B 06 3B 07 74 EA 83 EC 0C 50 E8 ?? ?? ?? ?? 5A 89 C3 FF 37 E8 ?? ?? ?? ?? 83 C4 10 39 C3 74 D0 83 EC 0C FF 36 E8 ?? ?? ?? ?? 89 C3 58 FF 37 E8 ?? ?? ?? ?? 83 C4 10 39 C3 19 C0 83 C8 01 EB 02 31 C0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __drand48_iterate_50d9d455f61c59fcf1c6134974b32574 {
	meta:
		aliases = "__drand48_iterate"
		size = "168"
		objfiles = "drand48_iter@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 74 24 24 66 83 7E 0E 00 75 1A C7 46 10 6D E6 EC DE C7 46 14 05 00 00 00 66 C7 46 0C 0B 00 66 C7 46 0E 01 00 8B 54 24 20 31 DB 89 D1 0F B7 42 02 C1 E0 10 C7 44 24 04 00 00 00 00 89 04 24 0F B7 42 04 0F B7 09 31 D2 89 C2 B8 00 00 00 00 8B 7E 10 09 C8 09 DA 8B 0C 24 09 C1 0F AF FA 8B 56 14 89 C8 0F AF D1 01 D7 F7 66 10 89 C1 0F B7 46 0C 8D 1C 17 31 D2 01 C8 8B 4C 24 20 11 DA 66 89 01 0F AC D0 10 C1 EA 10 66 89 41 02 0F AC D0 10 C1 EA 10 66 89 41 04 83 C4 0C 31 C0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_qsort_db65d5795d0edc3991674521c7b34d48 {
	meta:
		aliases = "qsort, __GI_qsort"
		size = "175"
		objfiles = "qsort@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 74 24 24 83 FE 01 0F 86 93 00 00 00 83 7C 24 28 00 0F 84 88 00 00 00 31 C9 8D 04 49 BA 03 00 00 00 89 D3 31 D2 8D 48 01 8D 46 FF F7 F3 39 C1 72 E8 8B 5C 24 28 0F AF 74 24 28 0F AF D9 89 74 24 08 89 5C 24 04 8B 6C 24 04 8B 74 24 20 29 DD 01 EE 50 50 8D 3C 1E 57 56 FF 54 24 3C 83 C4 10 85 C0 7E 15 8B 4C 24 28 8A 16 8A 07 88 06 46 88 17 47 49 75 F3 39 DD 73 D1 8B 74 24 28 8B 44 24 08 01 74 24 04 39 44 24 04 72 BB 29 F3 BA 03 00 00 00 89 D8 89 D6 31 D2 F7 F6 89 C3 85 C0 75 A2 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_scalbln_f708810a2c3516d3c34c0bdd2fda7a61 {
	meta:
		aliases = "scalbln, __GI_scalbln"
		size = "323"
		objfiles = "s_scalbln@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 74 24 24 8B 5C 24 20 89 F0 8B 4C 24 28 25 00 00 F0 7F 89 F5 C1 F8 14 89 DA 85 C0 75 37 81 E5 FF FF FF 7F 09 EA 0F 84 FE 00 00 00 89 1C 24 89 74 24 04 DD 04 24 D8 0D ?? ?? ?? ?? DD 1C 24 8B 74 24 04 8B 1C 24 89 F0 89 F5 25 00 00 F0 7F C1 F8 14 83 E8 36 3D FF 07 00 00 75 11 89 1C 24 89 74 24 04 DD 04 24 D8 C0 E9 B3 00 00 00 8D 3C 08 81 F9 50 C3 00 00 7F 08 81 FF FE 07 00 00 7E 1F 56 53 68 3C E4 37 7E 68 9C 75 00 88 E8 ?? ?? ?? ?? 83 C4 10 DC 0D ?? ?? ?? ?? E9 81 00 00 00 81 F9 B0 3C FF FF 7D 1C 56 53 68 1F 6E A5 01 68 59 F3 F8 C2 E8 ?? ?? ?? ?? 83 C4 10 DD 05 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule scalbn_746c28cfa89239a4d89301cb393bcabd {
	meta:
		aliases = "__GI_scalbn, scalbn"
		size = "335"
		objfiles = "s_scalbn@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 74 24 24 8B 5C 24 20 89 F0 8B 4C 24 28 25 00 00 F0 7F 89 F5 C1 F8 14 89 DA 85 C0 75 50 81 E5 FF FF FF 7F 09 EA 0F 84 0A 01 00 00 89 1C 24 89 74 24 04 DD 04 24 D8 0D ?? ?? ?? ?? 81 F9 B0 3C FF FF DD 1C 24 8B 1C 24 8B 74 24 04 7C 11 89 F0 89 F5 25 00 00 F0 7F C1 F8 14 83 E8 36 EB 0F 89 1C 24 89 74 24 04 DD 04 24 E9 91 00 00 00 3D FF 07 00 00 75 11 89 1C 24 89 74 24 04 DD 04 24 D8 C0 E9 A6 00 00 00 8D 3C 08 81 FF FE 07 00 00 7E 1C 56 53 68 3C E4 37 7E 68 9C 75 00 88 E8 ?? ?? ?? ?? 83 C4 10 DD 05 ?? ?? ?? ?? EB 7D 85 FF 7E 11 C1 E7 14 81 E5 FF FF 0F 80 89 EA 09 FA 89 D6 EB }
	condition:
		$pattern
}

rule tdelete_9b2f05a45013ac0d09d86997d04fccf0 {
	meta:
		aliases = "tdelete"
		size = "157"
		objfiles = "tdelete@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 74 24 24 8B 6C 24 20 8B 5C 24 28 85 F6 74 7C 8B 3E 85 FF EB 0F 89 C7 7D 05 8D 70 04 EB 03 8D 70 08 83 3E 00 74 65 50 50 8B 06 FF 30 55 FF D3 83 C4 10 83 F8 00 8B 06 75 DC 8B 58 04 8B 48 08 85 DB 74 0E 85 C9 74 31 8B 51 04 85 D2 75 0B 89 59 04 89 CB EB 23 89 C2 89 D9 8B 42 04 89 D3 85 C0 75 F3 8B 42 08 89 41 04 8B 06 8B 40 04 89 42 04 8B 06 8B 40 08 89 42 08 83 EC 0C FF 36 E8 ?? ?? ?? ?? 89 F8 83 C4 10 89 1E EB 02 31 C0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __stdio_WRITE_81e2347994ec666d6d1603494b9f4aa0 {
	meta:
		aliases = "__stdio_WRITE"
		size = "126"
		objfiles = "_WRITE@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 7C 24 20 8B 74 24 24 8B 5C 24 28 83 FB 00 74 5A 89 DD 7C 04 89 D8 EB 05 B8 FF FF FF 7F 52 50 56 FF 77 04 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 06 29 C3 01 C6 EB D6 8B 57 08 8B 47 0C 66 83 0F 08 29 D0 74 23 39 D8 77 02 89 C5 8A 06 88 02 3C 0A 75 06 F6 47 01 01 75 07 42 4D 74 03 46 EB EB 89 57 10 2B 57 08 29 D3 29 5C 24 28 8B 44 24 28 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_fgets_unlocked_f246ed790b6d8424be2735eb538bc5b8 {
	meta:
		aliases = "fgets_unlocked, __GI_fgets_unlocked"
		size = "105"
		objfiles = "fgets_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 7C 24 20 8B 74 24 24 8B 6C 24 28 89 FB 85 F6 7F 38 EB 42 8B 45 10 3B 45 18 73 0E 8A 10 40 88 13 43 80 FA 0A 89 45 10 EB 1E 83 EC 0C 55 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 75 08 F6 45 00 08 74 0C EB 13 88 03 43 3C 0A 74 03 4E 75 C7 39 FB 76 05 C6 03 00 EB 02 31 FF 83 C4 0C 89 F8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_fgetws_unlocked_62ca60bfd6b89c6c9c1f6d30888d46c1 {
	meta:
		aliases = "fgetws_unlocked, __GI_fgetws_unlocked"
		size = "80"
		objfiles = "fgetws_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 7C 24 20 8B 74 24 24 8B 6C 24 28 89 FB EB 01 4E 83 FE 01 7E 1B 83 EC 0C 55 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 74 0A 89 03 83 C3 04 83 F8 0A 75 DF 39 FB 75 04 31 FF EB 06 C7 03 00 00 00 00 83 C4 0C 89 F8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __ns_name_ntop_21cb12b67b9a04ce340dad596ffb18a7 {
	meta:
		aliases = "__GI___ns_name_ntop, __ns_name_ntop"
		size = "358"
		objfiles = "ns_name@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 7C 24 24 8B 44 24 20 03 7C 24 28 8B 5C 24 24 89 44 24 08 E9 FB 00 00 00 F7 C5 C0 00 00 00 0F 85 18 01 00 00 3B 5C 24 24 75 06 8B 5C 24 24 EB 0C 39 FB 0F 83 04 01 00 00 C6 03 2E 43 8D 04 2B 39 F8 0F 83 F5 00 00 00 FF 44 24 08 E9 BB 00 00 00 8B 4C 24 08 8A 11 0F B6 C2 83 F8 2E 74 1B 7F 0A 83 F8 22 74 14 83 F8 24 EB 0D 83 F8 40 74 0A 83 F8 5C 74 05 83 F8 3B 75 16 8D 43 01 39 F8 0F 83 B8 00 00 00 C6 03 5C 88 53 01 83 C3 02 EB 77 83 E8 21 83 F8 5D 76 68 8D 43 03 39 F8 0F 83 9A 00 00 00 66 0F B6 F2 89 F0 B2 64 F6 F2 0F B6 C0 B9 64 00 00 00 31 D2 8A 80 ?? ?? ?? ?? C6 03 5C 88 }
	condition:
		$pattern
}

rule writetcp_e8e04af8bf9acbb8d099c62c3187b6d3 {
	meta:
		aliases = "writetcp"
		size = "73"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 7C 24 28 8B 6C 24 20 8B 74 24 24 89 FB EB 24 50 53 56 FF 75 00 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 0E 8B 45 2C 83 CF FF C7 00 00 00 00 00 EB 08 29 C3 01 C6 85 DB 7F D8 83 C4 0C 89 F8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule writetcp_ebf5d39b7915c6169d10d3418225388b {
	meta:
		aliases = "writetcp"
		size = "82"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 7C 24 28 8B 6C 24 20 8B 74 24 24 89 FB EB 2D 50 53 56 FF 75 00 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 75 16 E8 ?? ?? ?? ?? 83 CF FF 8B 00 C7 45 24 03 00 00 00 89 45 28 EB 08 29 C3 01 C6 85 DB 7F CF 83 C4 0C 89 F8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule writeunix_3ce50f69e30dcbb2611665075a51e196 {
	meta:
		aliases = "writeunix"
		size = "86"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 7C 24 28 8B 6C 24 20 8B 74 24 24 89 FB EB 31 89 D9 89 F2 8B 45 00 E8 ?? ?? ?? ?? 83 F8 FF 75 1C E8 ?? ?? ?? ?? 83 CF FF 8B 00 C7 85 84 00 00 00 03 00 00 00 89 85 88 00 00 00 EB 08 29 C3 01 C6 85 DB 7F CB 83 C4 0C 89 F8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __pthread_alt_timedlock_9ab6ad6c65ed7b9d0a20d83eeece02e5 {
	meta:
		aliases = "__pthread_alt_timedlock"
		size = "209"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C B8 ?? ?? ?? ?? 31 F6 8B 7C 24 20 8B 6C 24 24 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 85 C0 74 09 89 C6 8B 00 A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 85 F6 75 26 83 EC 0C 6A 0C E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 75 13 50 50 55 57 E8 ?? ?? ?? ?? BA 01 00 00 00 83 C4 10 EB 66 8B 1F BA 01 00 00 00 85 DB 74 10 85 ED 75 07 E8 ?? ?? ?? ?? 89 C5 89 6E 04 89 F2 C7 46 08 00 00 00 00 89 1E 89 D8 F0 0F B1 17 0F 94 C2 84 D2 74 CF 85 DB 74 25 57 57 FF 74 24 30 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 12 B0 01 87 46 08 31 D2 85 C0 74 13 89 E8 E8 ?? ?? ?? ?? 89 F0 E8 ?? ?? ?? ?? BA 01 00 00 00 83 }
	condition:
		$pattern
}

rule _stdio_init_4c74d8f99938a3136f24ca37e7369371 {
	meta:
		aliases = "_stdio_init"
		size = "97"
		objfiles = "_stdio@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C BB 01 00 00 00 E8 ?? ?? ?? ?? 83 EC 0C 89 C7 8B 35 ?? ?? ?? ?? 8B 28 6A 00 E8 ?? ?? ?? ?? 89 DA 29 C2 C7 04 24 01 00 00 00 89 D0 C1 E0 08 31 C6 66 89 35 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 29 C3 C1 E3 08 31 DE 66 89 35 ?? ?? ?? ?? 89 2F 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _dl_load_shared_library_601de0b42bb41717835f588b0185ef21 {
	meta:
		aliases = "_dl_load_shared_library"
		size = "491"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C C7 05 ?? ?? ?? ?? 00 00 00 00 8B 5C 24 2C 8B 74 24 28 8D 43 FF 40 80 38 00 75 FA 29 D8 3D 00 04 00 00 0F 87 98 01 00 00 8D 43 FF 31 C9 EB 07 80 FA 2F 75 02 89 C1 40 8A 10 84 D2 75 F2 89 DF 85 C9 74 03 8D 79 01 39 DF 74 1A 50 53 FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 78 01 00 00 85 F6 74 27 8B 4E 7C 85 C9 74 20 83 EC 0C 03 4E 54 FF 74 24 30 89 F8 8B 54 24 30 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 4D 01 00 00 8B 0D ?? ?? ?? ?? 85 C9 74 1D 83 EC 0C 89 F8 FF 74 24 30 8B 54 24 30 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 26 01 00 00 85 F6 74 2A 8B 8E B4 00 00 00 85 }
	condition:
		$pattern
}

rule svc_run_dd4ba7f0da16bc14c3e46361b57529f7 {
	meta:
		aliases = "svc_run"
		size = "215"
		objfiles = "svc_run@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C E8 ?? ?? ?? ?? 89 44 24 08 8B 18 85 DB 75 0E E8 ?? ?? ?? ?? 83 38 00 0F 84 AB 00 00 00 83 EC 0C 8D 04 DD 00 00 00 00 31 ED 50 E8 ?? ?? ?? ?? 83 C4 10 89 C7 EB 27 E8 ?? ?? ?? ?? 8D 1C ED 00 00 00 00 8D 34 1F 45 8B 10 8B 14 1A 89 16 8B 00 66 C7 46 06 00 00 8B 44 18 04 66 89 46 04 8B 54 24 08 8B 02 39 C5 7C CF 51 6A FF 50 57 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 74 06 85 C0 74 2E EB 31 83 EC 0C 57 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 38 04 0F 84 67 FF FF FF 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 EB 1D 83 EC 0C EB 0A 52 52 50 57 E8 ?? ?? ?? ?? 58 57 E8 ?? ?? ?? ?? 83 }
	condition:
		$pattern
}

rule dladdr_4294debceb3421edacbe854717775376 {
	meta:
		aliases = "dladdr"
		size = "234"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 31 C9 EB 17 8B 50 14 3B 54 24 20 73 0B 85 C9 74 05 39 51 14 73 02 89 C1 8B 40 0C 85 C0 75 E5 85 C9 0F 84 AA 00 00 00 8B 54 24 24 8B 41 04 31 F6 31 ED 89 02 31 FF 8B 41 14 89 42 04 8B 59 58 89 5C 24 04 8B 41 54 C7 44 24 08 00 00 00 00 89 04 24 EB 3D 8B 41 2C 8B 14 B0 EB 30 89 D0 8B 5C 24 04 C1 E0 04 8B 44 18 04 03 01 3B 44 24 20 77 15 85 FF 74 06 39 44 24 08 73 0B 89 D5 89 44 24 08 BF 01 00 00 00 8B 41 3C 8B 14 90 85 D2 75 CC 46 3B 71 28 72 BE 85 FF 74 21 8B 44 24 04 8B 54 24 24 C1 E5 04 8B 44 05 00 01 04 24 8B 1C 24 89 5A 08 8B 44 24 08 89 42 }
	condition:
		$pattern
}

rule __fake_pread_write_bd4ce513745f2dec4fb61bffe2f46cfb {
	meta:
		aliases = "__fake_pread_write"
		size = "138"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 89 C7 89 D6 89 CB 6A 01 6A 00 50 E8 ?? ?? ?? ?? 89 44 24 18 83 C4 10 83 7C 24 08 FF 74 58 50 6A 00 FF 74 24 28 57 E8 ?? ?? ?? ?? 83 C4 10 40 74 45 83 7C 24 24 01 75 0B 50 53 56 57 E8 ?? ?? ?? ?? EB 09 55 53 56 57 E8 ?? ?? ?? ?? 83 C4 10 89 C6 E8 ?? ?? ?? ?? 89 C3 8B 28 51 6A 00 FF 74 24 10 57 E8 ?? ?? ?? ?? 83 C4 10 40 75 05 83 FE FF 75 04 89 2B EB 03 83 CE FF 83 C4 0C 89 F0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __encode_answer_7fdd63082f0b4b1f5d7beae19670d58a {
	meta:
		aliases = "__encode_answer"
		size = "160"
		objfiles = "encodea@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 5C 24 24 8B 6C 24 28 8B 74 24 2C 56 55 FF 33 E8 ?? ?? ?? ?? 83 C4 10 89 C7 85 C0 78 71 29 C6 8B 43 10 83 C0 0A 39 C6 7D 05 83 CF FF EB 60 0F B6 43 05 8D 54 3D 00 88 02 8B 43 04 88 42 01 0F B6 43 09 88 42 02 8B 43 08 88 42 03 0F B6 43 0F 88 42 04 0F B6 43 0E 88 42 05 0F B6 43 0D 88 42 06 8B 43 0C 88 42 07 0F B6 43 11 88 42 08 8B 43 10 88 42 09 50 FF 73 10 FF 73 14 83 C2 0A 52 E8 ?? ?? ?? ?? 8B 43 10 83 C4 10 83 C0 0A 01 C7 83 C4 0C 89 F8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fnmatch_68b1b9b4405f6956670a0382a986f7e4 {
	meta:
		aliases = "__GI_fnmatch, fnmatch"
		size = "1165"
		objfiles = "fnmatch_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 5C 24 24 8B 7C 24 28 E9 47 04 00 00 8B 44 24 2C 83 E0 10 89 04 24 74 1D 84 D2 78 19 0F BE C2 8D 0C 00 A1 ?? ?? ?? ?? F6 04 08 01 74 08 A1 ?? ?? ?? ?? 8A 14 08 0F BE CA 43 83 F9 3F 74 24 7F 0E 83 F9 2A 0F 85 DA 03 00 00 E9 C5 00 00 00 83 F9 5B 0F 84 CB 01 00 00 83 F9 5C 0F 85 C3 03 00 00 EB 49 8A 07 84 C0 0F 84 08 04 00 00 8A 54 24 2C 80 E2 01 74 08 3C 2F 0F 84 F7 03 00 00 F6 44 24 2C 04 0F 84 CA 03 00 00 3C 2E 0F 85 C2 03 00 00 3B 7C 24 28 0F 84 DA 03 00 00 84 D2 0F 84 B0 03 00 00 80 7F FF 2F E9 4D 03 00 00 F6 44 24 2C 02 75 2E 8A 13 43 84 D2 0F 84 B7 03 00 00 83 3C 24 }
	condition:
		$pattern
}

rule __encode_packet_74e8a82da3051e4e63a1a7cd83de184f {
	meta:
		aliases = "__encode_packet"
		size = "228"
		objfiles = "encodep@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 5C 24 38 8B 7C 24 3C 57 53 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 88 B7 00 00 00 8D 34 03 89 FB 29 C3 89 C7 31 ED EB 21 50 53 56 8B 44 24 30 FF 34 A8 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 88 90 00 00 00 01 C6 29 C3 01 C7 45 8B 44 24 20 3B 68 20 72 D6 31 ED EB 1D 51 53 56 8B 44 24 34 FF 34 A8 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 66 01 C6 29 C3 01 C7 45 8B 44 24 20 3B 68 24 72 DA 31 ED EB 1D 52 53 56 8B 44 24 38 FF 34 A8 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 3C 01 C6 29 C3 01 C7 45 8B 44 24 20 3B 68 28 72 DA 31 ED EB 1D 50 53 56 8B 44 24 3C FF 34 A8 E8 ?? ?? ?? ?? 83 C4 10 85 C0 }
	condition:
		$pattern
}

rule getgrouplist_95589f22eb328f16b88fb801e4f1a0c2 {
	meta:
		aliases = "getgrouplist"
		size = "120"
		objfiles = "getgrouplist@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 6C 24 30 8B 5C 24 28 8B 75 00 55 53 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 89 C7 85 C0 75 11 85 F6 74 41 8B 44 24 28 89 18 BB 01 00 00 00 EB 37 8B 5D 00 39 F3 7E 02 89 F3 85 DB 74 16 50 8D 04 9D 00 00 00 00 50 57 FF 74 24 34 E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 3B 5D 00 7D 03 83 CB FF 83 C4 0C 89 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _uintmaxtostr_7b669c58ecff4dcab32a676abfb1598e {
	meta:
		aliases = "_uintmaxtostr"
		size = "209"
		objfiles = "_uintmaxtostr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 74 24 30 8B 7C 24 24 8B 4C 24 28 8B 5C 24 2C 85 F6 79 17 F7 DE 85 DB 79 11 F7 D9 83 D3 00 C7 44 24 04 01 00 00 00 F7 DB EB 08 C7 44 24 04 00 00 00 00 83 C8 FF 31 D2 F7 F6 42 C6 07 00 39 F2 89 44 24 08 89 54 24 0C 75 0D 40 C7 44 24 0C 00 00 00 00 89 44 24 08 89 CD 89 D9 31 DB 89 CB 85 DB 74 33 89 D8 31 D2 F7 F6 89 14 24 89 C3 31 D2 89 E8 F7 F6 89 C5 8B 44 24 0C 0F AF 04 24 8D 04 02 8B 14 24 0F AF 54 24 08 8D 4C 15 00 31 D2 F7 F6 8D 2C 01 EB 08 89 E8 31 D2 F7 F6 89 C5 4F 83 FA 09 77 05 83 C2 30 EB 04 03 54 24 34 88 17 89 EA 09 DA 75 AA 83 7C 24 04 00 74 04 4F C6 07 2D 83 }
	condition:
		$pattern
}

rule __ieee754_log_9d2593f5a594d894f46fa64e88ccda6a {
	meta:
		aliases = "__ieee754_log"
		size = "549"
		objfiles = "e_log@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 31 DB 8B 6C 24 2C 8B 7C 24 28 89 E9 81 FD FF FF 0F 00 7F 4F 89 E8 25 FF FF FF 7F 09 F8 75 08 D9 05 ?? ?? ?? ?? EB 10 85 ED 79 17 89 3C 24 89 6C 24 04 DD 04 24 D8 E0 DC 35 ?? ?? ?? ?? E9 D4 01 00 00 89 3C 24 89 6C 24 04 DD 04 24 D8 0D ?? ?? ?? ?? BB CA FF FF FF DD 1C 24 8B 6C 24 04 8B 3C 24 89 E9 81 F9 FF FF EF 7F 7E 11 89 3C 24 89 6C 24 04 DD 04 24 D8 C0 E9 9A 01 00 00 89 C8 81 E1 FF FF 0F 00 C1 F8 14 89 4C 24 0C 81 C1 64 5F 09 00 8B 54 24 0C 81 E1 00 00 10 00 8D B4 03 01 FC FF FF 89 CB 8B 44 24 0C 81 F3 00 00 F0 3F 83 C0 02 09 DA 89 3C 24 C1 F9 14 89 54 24 04 DD 04 24 25 }
	condition:
		$pattern
}

rule __ieee754_log2_ccd04c2929de1520753546a68e96e907 {
	meta:
		aliases = "__ieee754_log2"
		size = "447"
		objfiles = "e_log2@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 31 DB 8B 6C 24 2C 8B 7C 24 28 89 E9 81 FD FF FF 0F 00 7F 5F 89 E8 25 FF FF FF 7F 09 F8 75 1C 89 3C 24 89 6C 24 04 DD 04 24 D8 E0 DD 14 24 D9 05 ?? ?? ?? ?? DE F1 E9 75 01 00 00 85 ED 79 13 89 3C 24 89 6C 24 04 DD 04 24 D8 E0 D8 F0 E9 5E 01 00 00 89 3C 24 89 6C 24 04 DD 04 24 D8 0D ?? ?? ?? ?? BB CA FF FF FF DD 1C 24 8B 6C 24 04 8B 3C 24 89 E9 81 F9 FF FF EF 7F 7E 11 89 3C 24 89 6C 24 04 DD 04 24 D8 C0 E9 24 01 00 00 89 C8 81 E1 FF FF 0F 00 C1 F8 14 89 4C 24 0C 81 C1 64 5F 09 00 8B 54 24 0C 81 E1 00 00 10 00 8D B4 03 01 FC FF FF 89 CB C1 F9 14 81 F3 00 00 F0 3F 01 CE 09 DA }
	condition:
		$pattern
}

rule erand48_r_5c7f81c3fe074728cda08a02fb39ca35 {
	meta:
		aliases = "__GI_erand48_r, erand48_r"
		size = "127"
		objfiles = "erand48_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 31 FF 8B 6C 24 28 FF 74 24 2C 55 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 54 66 8B 5D 02 89 FA 0F B7 4D 04 89 D8 81 E2 FF FF 0F 00 66 C1 E8 0C 81 CA 00 00 F0 3F 0F B7 C0 C1 E1 04 81 E2 00 00 F0 FF 09 C1 89 D7 0F B7 45 00 C1 E3 14 09 CF C1 E0 04 89 DE 09 C6 89 7C 24 04 89 34 24 8B 44 24 28 DD 04 24 DC 25 ?? ?? ?? ?? 31 D2 DD 18 83 C4 0C 89 D0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule svcudp_reply_7ddd700de7b5cda39897941dcd99803e {
	meta:
		aliases = "svcudp_reply"
		size = "501"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 44 24 28 8B 5C 24 2C 8B 78 30 8D 77 08 C7 47 08 00 00 00 00 8B 46 04 6A 00 56 FF 50 14 8B 47 04 89 03 5D 58 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 AD 01 00 00 83 EC 0C 8B 46 04 56 FF 50 10 8B 54 24 30 89 C3 83 C2 3C 83 C4 10 83 7A 0C 00 74 1F 8B 4C 24 20 8B 41 2C 89 59 38 89 41 34 56 6A 00 52 FF 31 E8 ?? ?? ?? ?? 83 C4 10 89 C5 EB 23 8B 44 24 20 52 52 83 C0 10 8B 54 24 28 FF 72 0C 50 6A 00 53 FF 72 2C FF 32 E8 ?? ?? ?? ?? 83 C4 20 89 C5 39 DD 0F 85 47 01 00 00 83 BF B0 01 00 00 00 74 04 85 ED 79 0A B8 01 00 00 00 E9 32 01 00 00 8B 4C 24 20 8B 79 30 8B B7 B0 01 00 00 }
	condition:
		$pattern
}

rule __GI_xdr_array_fd323fb9387d511056c3877788ed4eec {
	meta:
		aliases = "xdr_array, __GI_xdr_array"
		size = "267"
		objfiles = "xdr_array@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 44 24 2C 8B 74 24 30 8B 18 56 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 D2 00 00 00 8B 3E 3B 7C 24 2C 77 0D 83 C8 FF 31 D2 F7 74 24 30 39 C7 76 0D 8B 54 24 20 83 3A 02 0F 85 B0 00 00 00 85 DB 75 5F 8B 54 24 20 8B 02 83 F8 01 74 0A 83 F8 02 75 4F E9 9B 00 00 00 85 FF 0F 84 93 00 00 00 8B 74 24 30 83 EC 0C 0F AF F7 56 E8 ?? ?? ?? ?? 89 C3 8B 44 24 34 83 C4 10 85 DB 89 18 75 16 53 53 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 F6 EB 55 51 56 6A 00 53 E8 ?? ?? ?? ?? 83 C4 10 31 ED BE 01 00 00 00 EB 16 52 6A FF 53 45 FF 74 24 2C FF 54 24 44 03 5C 24 40 89 C6 83 }
	condition:
		$pattern
}

rule xdr_union_09344715bac76c9a8395ccfc3475cfd6 {
	meta:
		aliases = "__GI_xdr_union, xdr_union"
		size = "130"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 44 24 30 8B 74 24 28 8B 7C 24 2C 89 44 24 10 8B 5C 24 34 8B 6C 24 38 57 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 4B 8B 07 EB 1D 39 03 75 16 8B 44 24 08 C7 44 24 28 FF FF FF FF 89 44 24 24 89 74 24 20 EB 24 83 C3 08 8B 4B 04 85 C9 75 DC 85 ED 74 1F 8B 4C 24 08 C7 44 24 28 FF FF FF FF 89 4C 24 24 89 74 24 20 89 E9 83 C4 0C 5B 5E 5F 5D FF E1 83 C4 0C 31 C0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_log1p_9e8196ed7806581b08632b6bb853406c {
	meta:
		aliases = "log1p, __GI_log1p"
		size = "795"
		objfiles = "s_log1p@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 5C 24 2C 8B 4C 24 28 89 DA 81 FB 79 82 DA 3F 0F 8F B8 00 00 00 89 DE 81 E6 FF FF FF 7F 81 FE FF FF EF 3F 7E 3D D9 05 ?? ?? ?? ?? 89 0C 24 89 5C 24 04 DD 04 24 DA E9 DF E0 9E 75 13 7A 11 D9 05 ?? ?? ?? ?? DC 35 ?? ?? ?? ?? E9 A4 02 00 00 89 0C 24 89 5C 24 04 DD 04 24 D8 E0 D8 F0 E9 91 02 00 00 81 FE FF FF 1F 3E 7F 43 D9 05 ?? ?? ?? ?? 89 0C 24 89 5C 24 04 DD 04 24 DE C1 D9 EE D9 C9 DA E9 DF E0 9E 76 0C 81 FE FF FF 8F 3C 0F 8E 6E 02 00 00 89 0C 24 89 5C 24 04 DD 04 24 D8 C8 D8 0D ?? ?? ?? ?? DD 04 24 E9 75 01 00 00 8D 83 3C 41 2D 40 3D 3C 41 2D 40 76 13 89 0C 24 89 5C 24 }
	condition:
		$pattern
}

rule __ieee754_exp_fc1a4877cd3f8d367ef8541d5d98ac89 {
	meta:
		aliases = "__ieee754_exp"
		size = "581"
		objfiles = "e_exp@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 5C 24 2C 8B 4C 24 28 89 DA 89 DF 81 E2 FF FF FF 7F 89 DE C1 EF 1F 81 FA 41 2E 86 40 0F 86 81 00 00 00 81 FA FF FF EF 7F 76 25 81 E6 FF FF 0F 00 09 CE 74 11 89 0C 24 89 5C 24 04 DD 04 24 D8 C0 E9 DC 01 00 00 85 FF 0F 84 DE 01 00 00 EB 4B DD 05 ?? ?? ?? ?? 89 0C 24 89 5C 24 04 DD 04 24 DA E9 DF E0 9E 76 1B B9 9C 75 00 88 BB 3C E4 37 7E 89 0C 24 89 5C 24 04 DD 04 24 D8 C8 E9 A0 01 00 00 DD 05 ?? ?? ?? ?? 89 0C 24 89 5C 24 04 DD 04 24 D9 C9 DA E9 DF E0 9E 76 09 31 C9 31 DB E9 88 01 00 00 81 FA 42 2E D6 3F 0F 86 91 00 00 00 81 FA B1 A2 F0 3F 77 23 89 0C 24 89 5C 24 04 DD 04 }
	condition:
		$pattern
}

rule xdr_bytes_0ae14619b520b3d0715cc3b3523a40b5 {
	meta:
		aliases = "__GI_xdr_bytes, xdr_bytes"
		size = "199"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 6C 24 2C 8B 44 24 34 89 44 24 10 8B 7C 24 28 8B 74 24 30 8B 5D 00 56 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 86 00 00 00 8B 36 3B 74 24 08 76 05 83 3F 02 75 79 8B 07 83 F8 01 74 09 72 3A 83 F8 02 75 6B EB 4B 85 F6 74 69 85 DB 75 2B 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 89 C3 89 45 00 85 C0 75 16 50 50 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 EB 31 89 74 24 28 89 5C 24 24 89 7C 24 20 83 C4 0C 5B 5E 5F 5D E9 ?? ?? ?? ?? 85 DB 74 1E 83 EC 0C 53 E8 ?? ?? ?? ?? C7 45 00 00 00 00 00 B8 01 00 00 00 83 C4 10 EB 09 31 C0 EB 05 B8 01 00 00 00 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule getpwuid_r_ed40c1faabc4a642f9697592d9ba9bd1 {
	meta:
		aliases = "__GI_getpwuid_r, getgrgid_r, __GI_getgrgid_r, getpwuid_r"
		size = "142"
		objfiles = "getgrgid_r@libc.a, getpwuid_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 6C 24 38 8B 7C 24 2C C7 45 00 00 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 75 09 E8 ?? ?? ?? ?? 8B 18 EB 4D C7 40 34 01 00 00 00 83 EC 0C 56 FF 74 24 3C FF 74 24 3C 57 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 20 89 C3 85 C0 75 0E 8B 44 24 20 39 47 08 75 D7 89 7D 00 EB 0C 31 C0 83 FB 02 0F 95 C0 F7 D8 21 C3 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 83 C4 0C 89 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule getspnam_r_4b8fd72cde4f80875c48536dbf4b838a {
	meta:
		aliases = "__GI_getspnam_r, __GI_getgrnam_r, getpwnam_r, __GI_getpwnam_r, getgrnam_r, getspnam_r"
		size = "153"
		objfiles = "getpwnam_r@libc.a, getspnam_r@libc.a, getgrnam_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 6C 24 38 8B 7C 24 2C C7 45 00 00 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 75 09 E8 ?? ?? ?? ?? 8B 18 EB 58 C7 40 34 01 00 00 00 83 EC 0C 56 FF 74 24 3C FF 74 24 3C 57 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 20 89 C3 85 C0 75 19 50 50 FF 74 24 28 FF 37 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 CC 89 7D 00 EB 0C 31 C0 83 FB 02 0F 95 C0 F7 D8 21 C3 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 83 C4 0C 89 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule srandom_r_028717090b1706a29c8cf1fb5cd0f9b1 {
	meta:
		aliases = "__GI_srandom_r, srandom_r"
		size = "150"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 83 C9 FF 8B 74 24 30 8B 44 24 2C 8B 56 0C 83 FA 04 77 72 8B 5E 08 85 C0 75 02 B0 01 89 03 85 D2 74 61 89 C2 89 D9 8B 46 10 BF 01 00 00 00 89 04 24 EB 2A 89 D0 BD 1D F3 01 00 99 F7 FD 89 44 24 04 69 D2 A7 41 00 00 69 C0 14 0B 00 00 29 C2 79 06 81 C2 FF FF FF 7F 83 C1 04 47 89 11 3B 3C 24 7C D1 8B 46 14 89 5E 04 8D 04 83 89 06 6B 1C 24 0A EB 0D 8D 44 24 14 50 56 E8 ?? ?? ?? ?? 58 5A 4B 79 F0 31 C9 83 C4 18 89 C8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule makefd_xprt_dc940dc7ee98f9c978f71b73ddc4b1d5 {
	meta:
		aliases = "makefd_xprt"
		size = "181"
		objfiles = "svc_unix@libc.a, svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 89 D5 89 CF 89 44 24 14 68 34 01 00 00 E8 ?? ?? ?? ?? C7 04 24 B0 01 00 00 89 C3 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 DB 74 04 85 C0 75 26 52 52 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 31 DB EB 51 C7 00 02 00 00 00 50 50 8D 46 08 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 57 55 50 E8 ?? ?? ?? ?? 8D 46 20 C7 43 30 00 00 00 00 89 73 2C 89 43 24 C7 43 0C 00 00 00 00 C7 43 08 ?? ?? ?? ?? 66 C7 43 04 00 00 8B 44 24 28 83 C4 14 89 03 53 E8 ?? ?? ?? ?? 83 C4 1C 89 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule exchange_cd5b6fa2b4c4ee7deec4585812587b42 {
	meta:
		aliases = "exchange"
		size = "219"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 89 D6 89 04 24 8B 42 14 89 44 24 04 8B 06 8B 52 18 89 44 24 0C 89 54 24 08 E9 8B 00 00 00 8B 6C 24 0C 8B 7C 24 08 2B 6C 24 08 2B 7C 24 04 C7 44 24 14 00 00 00 00 C7 44 24 10 00 00 00 00 39 FD 7F 29 EB 5B 8B 44 24 0C 8B 4C 24 04 29 F8 03 4C 24 10 03 44 24 10 8B 14 24 8D 0C 8A 8D 04 82 8B 19 8B 10 89 11 89 18 FF 44 24 10 39 7C 24 10 7C D3 29 7C 24 0C EB 32 8B 4C 24 04 8B 04 24 03 4C 24 14 8B 14 24 8D 0C 88 8B 44 24 08 03 44 24 14 8B 19 8D 04 82 8B 10 89 11 89 18 FF 44 24 14 39 6C 24 14 7C D2 01 6C 24 04 8B 44 24 08 39 44 24 0C 7E 0C 8B 54 24 04 39 D0 0F 8F 5F FF FF FF 8B 16 }
	condition:
		$pattern
}

rule __regcomp_b567774134b882dd0bef11858a5899c1 {
	meta:
		aliases = "regcomp, __regcomp"
		size = "324"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 8B 6C 24 34 8B 74 24 2C 89 E8 83 E0 01 C7 06 00 00 00 00 83 F8 01 C7 46 04 00 00 00 00 19 DB C7 46 08 00 00 00 00 68 00 01 00 00 E8 ?? ?? ?? ?? 81 E3 CA 4F FD 00 83 C4 10 81 C3 FC B2 03 00 89 46 10 F7 C5 02 00 00 00 74 54 83 EC 0C BF 0C 00 00 00 68 00 01 00 00 E8 ?? ?? ?? ?? 83 C4 10 31 C9 89 46 14 85 C0 75 2C E9 C6 00 00 00 8B 46 14 8D 3C 09 89 44 24 08 A1 ?? ?? ?? ?? 88 CA F6 04 38 01 74 08 A1 ?? ?? ?? ?? 8A 14 38 8B 44 24 08 88 14 08 41 81 F9 FF 00 00 00 76 D1 EB 07 C7 46 14 00 00 00 00 F7 C5 04 00 00 00 8A 46 1C 74 0B 83 E3 BF 83 C8 80 80 CF 01 EB 03 83 E0 7F C1 ED 03 }
	condition:
		$pattern
}

rule lsearch_52fd66679f18b6cad165f7340c4c65b0 {
	meta:
		aliases = "lsearch"
		size = "72"
		objfiles = "lsearch@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 8B 7C 24 2C 8B 6C 24 30 8B 74 24 34 8B 5C 24 38 FF 74 24 3C 53 56 55 57 E8 ?? ?? ?? ?? 83 C4 20 85 C0 75 15 50 53 57 0F AF 1E 8D 44 1D 00 50 E8 ?? ?? ?? ?? FF 06 83 C4 10 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __prefix_array_ee5ea7a266c1b830be5c9bb8ee24b154 {
	meta:
		aliases = "__prefix_array"
		size = "180"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 89 C5 83 F8 01 75 0D 8B 44 24 20 80 38 2F 0F 95 C0 0F B6 E8 31 FF EB 79 8B 54 24 24 83 EC 0C 8D 34 BA FF 36 E8 ?? ?? ?? ?? 5B 8D 50 01 8D 44 28 02 89 54 24 14 50 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 75 20 EB 13 83 EC 0C 4F 8B 44 24 30 FF 34 B8 E8 ?? ?? ?? ?? 83 C4 10 85 FF 75 E9 B8 01 00 00 00 EB 35 51 55 FF 74 24 28 50 E8 ?? ?? ?? ?? 83 C4 0C 47 C6 00 2F 40 FF 74 24 0C FF 36 50 E8 ?? ?? ?? ?? 5A FF 36 E8 ?? ?? ?? ?? 89 1E 83 C4 10 3B 7C 24 28 72 81 31 C0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fflush_unlocked_47c0d2ddb3697949234ed6f099037425 {
	meta:
		aliases = "__GI_fflush_unlocked, fflush_unlocked"
		size = "321"
		objfiles = "fflush_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 31 ED 8B 5C 24 30 81 FB ?? ?? ?? ?? 74 0D BD 00 01 00 00 85 DB 0F 85 EF 00 00 00 57 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 31 FF 8D 5C 24 18 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 A1 ?? ?? ?? ?? 5E 40 6A 01 53 A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 5A 6A 01 8B 35 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 EB 78 F6 06 40 74 70 83 3D ?? ?? ?? ?? 02 74 1F 8D 5E 38 50 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 89 E8 0B 06 66 35 40 01 A9 40 03 00 00 }
	condition:
		$pattern
}

rule __parsepwent_d8389d6b3184f29a336b544562424631 {
	meta:
		aliases = "__parsepwent"
		size = "122"
		objfiles = "__parsepwent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 31 F6 8B 6C 24 30 8B 5C 24 34 0F B6 86 ?? ?? ?? ?? 8D 7C 05 00 89 F0 83 E0 06 83 F8 02 74 1A 89 1F 83 FE 06 74 3E 52 52 6A 3A 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 24 EB 2F 50 6A 0A 8D 44 24 20 50 53 E8 ?? ?? ?? ?? 89 C2 8B 44 24 28 83 C4 10 39 D8 74 14 80 38 3A 75 0F 89 17 8D 58 01 46 C6 00 00 EB A6 31 C0 EB 03 83 C8 FF 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __parsegrent_45b07ecdc84f8f05ca224eea21a29ae6 {
	meta:
		aliases = "__parsegrent"
		size = "223"
		objfiles = "__parsegrent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 31 F6 8B 6C 24 30 8B 5C 24 34 8B 45 00 89 44 24 08 0F B6 86 ?? ?? ?? ?? 83 FE 01 8D 7C 05 00 7F 20 89 1F 52 52 6A 3A 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 95 00 00 00 8D 58 01 46 C6 00 00 EB D0 50 6A 0A 8D 44 24 20 50 53 E8 ?? ?? ?? ?? 89 07 8B 4C 24 28 83 C4 10 39 D9 74 71 80 39 3A 75 6C BB 01 00 00 00 80 79 01 00 74 2B C6 01 2C 80 39 2C 75 1D C6 01 00 41 8A 01 84 C0 74 4F 3C 2C 74 4B 0F BE D0 A1 ?? ?? ?? ?? F6 04 50 20 75 3D 43 41 80 39 00 75 D8 8D 51 04 83 E2 FC 8D 04 9A 3B 44 24 08 77 27 89 D9 89 55 0C 49 74 15 8B 44 24 18 40 89 02 83 C2 04 49 74 08 40 80 38 00 75 FA }
	condition:
		$pattern
}

rule __parsespent_a606532d5731d258facec8ec3b24e752 {
	meta:
		aliases = "__parsespent"
		size = "132"
		objfiles = "__parsespent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 31 FF 8B 6C 24 30 8B 5C 24 34 0F B6 87 ?? ?? ?? ?? 83 FF 01 8D 74 05 00 7F 15 89 1E 52 52 6A 3A 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 38 EB 3F 50 6A 0A 8D 44 24 20 50 53 E8 ?? ?? ?? ?? 83 C4 10 89 06 39 5C 24 18 75 06 C7 06 FF FF FF FF 8B 44 24 18 83 FF 08 75 09 31 D2 80 38 00 74 15 EB 0E 80 38 3A 75 09 8D 58 01 47 C6 00 00 EB 9C BA 16 00 00 00 83 C4 1C 89 D0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __error_at_line_547e6d99595f50e9481ad9c4e99b8c53 {
	meta:
		aliases = "error_at_line, __error_at_line"
		size = "311"
		objfiles = "error@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 83 3D ?? ?? ?? ?? 00 8B 6C 24 30 8B 7C 24 34 8B 5C 24 38 8B 74 24 3C 74 35 39 35 ?? ?? ?? ?? 75 21 A1 ?? ?? ?? ?? 39 C3 0F 84 FA 00 00 00 52 52 53 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 E6 00 00 00 89 1D ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 83 EC 0C FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 04 FF D0 EB 1A 50 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 DB 74 15 56 53 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 8D 44 24 44 89 44 24 18 53 50 FF 74 24 48 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 05 ?? ?? ?? ?? 83 C4 10 }
	condition:
		$pattern
}

rule _dl_parse_0c53e824294c303903841894da01f815 {
	meta:
		aliases = "_dl_parse"
		size = "223"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 89 C5 89 CE C1 6C 24 30 03 89 54 24 0C 8B 40 58 89 44 24 18 8B 55 54 C7 44 24 10 00 00 00 00 89 54 24 14 E9 96 00 00 00 83 EC 0C 8B 5E 04 FF 74 24 20 FF 74 24 28 56 FF 74 24 24 55 FF 54 24 54 83 C4 20 89 C7 85 C0 74 6E FF 35 ?? ?? ?? ?? C1 EB 08 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? 83 C4 0C 85 DB 74 1E 8B 54 24 18 8B 44 24 14 C1 E3 04 03 04 13 50 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? 83 C4 0C 83 FF 00 7D 19 FF 75 04 0F B6 46 04 50 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? 83 C4 10 EB 2D 7E 14 FF 75 04 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? 83 C4 0C EB 17 FF 44 24 10 83 C6 08 8B 44 24 }
	condition:
		$pattern
}

rule byte_group_match_null_string_p_bdb647561118e4b8ccf324c0394630bd {
	meta:
		aliases = "byte_group_match_null_string_p"
		size = "260"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 89 C5 8B 00 89 D7 83 C0 02 89 CE 89 44 24 18 E9 D3 00 00 00 0F B6 02 83 F8 07 0F 84 A9 00 00 00 83 F8 0F 0F 85 AD 00 00 00 8D 42 01 89 44 24 18 0F B6 4A 01 0F BE 40 01 89 CB 83 C2 03 C1 E0 08 89 54 24 18 01 C3 79 50 E9 9A 00 00 00 89 4C 24 18 EB 50 8D 54 18 FD 89 F1 E8 ?? ?? ?? ?? 84 C0 0F 84 8D 00 00 00 89 D9 03 4C 24 18 89 4C 24 18 80 39 0F 75 2E 8D 41 01 89 44 24 18 0F BE 40 01 0F B6 51 01 C1 E0 08 8D 1C 02 8D 41 03 89 44 24 18 80 7C 18 FD 0E 75 B5 8B 44 24 18 80 7C 18 FD 0E 74 B0 8B 44 24 18 0F BE 50 FF 0F B6 48 FE C1 E2 08 8D 1C 11 89 F1 8D 14 18 E8 ?? ?? ?? ?? 84 C0 }
	condition:
		$pattern
}

rule byte_common_op_match_null_stri_386528a3f0308c5edcf598f34a6652e3 {
	meta:
		aliases = "byte_common_op_match_null_string_p"
		size = "259"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 89 CF 8B 08 89 C5 89 4C 24 18 0F B6 01 8D 71 01 83 F8 0C 89 74 24 18 77 24 83 F8 09 0F 83 C2 00 00 00 83 F8 06 74 39 83 F8 08 0F 84 AA 00 00 00 85 C0 0F 84 AC 00 00 00 E9 B5 00 00 00 83 F8 15 74 68 77 0B 83 F8 0D 0F 85 A5 00 00 00 EB 42 83 E8 1A 83 F8 03 0F 87 97 00 00 00 E9 84 00 00 00 0F B6 59 01 8D 44 24 18 89 F9 E8 ?? ?? ?? ?? 8D 0C 9F 89 C6 8A 01 83 E0 03 3C 03 75 0E 8A 01 89 F2 83 E2 03 83 E0 FC 09 D0 88 01 89 F0 84 C0 EB 51 0F BE 46 01 0F B6 51 01 C1 E0 08 01 D0 78 52 8D 44 01 03 89 44 24 18 EB 3A 8D 59 03 89 5C 24 18 0F BE 43 01 0F B6 51 03 C1 E0 08 01 C2 75 32 89 }
	condition:
		$pattern
}

rule inet_pton4_54ab8bf1cf512780de5d794b9cc9b64c {
	meta:
		aliases = "inet_pton4"
		size = "134"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 89 D5 89 C3 31 D2 31 FF 8D 74 24 18 C6 44 24 18 00 EB 3D 8D 41 D0 83 F8 09 77 21 0F B6 06 6B C0 0A 8D 44 08 D0 3D FF 00 00 00 77 49 88 06 85 D2 75 1E 47 83 FF 04 7F 3D B2 01 EB 14 83 F9 2E 75 34 85 D2 74 30 83 FF 04 74 2B 46 31 D2 C6 06 00 0F BE 0B 43 85 C9 75 BB 83 FF 03 7E 18 50 6A 04 8D 44 24 20 50 55 E8 ?? ?? ?? ?? B8 01 00 00 00 83 C4 10 EB 02 31 C0 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __fake_pread_write64_0b6a9734da91fde90e99ad3e6b873e9c {
	meta:
		aliases = "__fake_pread_write64"
		size = "198"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 89 D5 89 CB 89 44 24 10 8B 54 24 34 8B 44 24 30 89 54 24 0C 89 44 24 08 6A 01 6A 00 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 89 C6 89 D7 83 FA FF 75 05 83 F8 FF 74 7A 6A 00 FF 74 24 10 FF 74 24 10 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 42 75 03 40 74 5E 83 7C 24 38 01 75 0E 52 53 55 FF 74 24 1C E8 ?? ?? ?? ?? EB 0C 50 53 55 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 89 C5 E8 ?? ?? ?? ?? 89 C3 8B 10 89 54 24 14 6A 00 57 56 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 42 75 10 40 75 0D 83 FD FF 75 10 8B 44 24 14 89 03 EB 0B 8B 54 24 14 89 13 EB 03 83 CD FF 83 C4 1C 89 E8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _stdlib_strto_ll_2287c3beff3afe36e69f4f76adabd991 {
	meta:
		aliases = "_stdlib_strto_ll"
		size = "508"
		objfiles = "_stdlib_strto_ll@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 15 ?? ?? ?? ?? 8B 5C 24 30 89 5C 24 14 EB 04 FF 44 24 14 8B 4C 24 14 0F BE 01 F6 04 42 20 75 EF 83 F8 2B 74 11 C6 44 24 13 00 83 F8 2D 75 10 C6 44 24 13 01 EB 05 C6 44 24 13 00 FF 44 24 14 89 D9 F7 44 24 38 EF FF FF FF 75 3D 83 44 24 38 0A 8B 44 24 14 80 38 30 75 20 83 6C 24 38 02 40 89 44 24 14 89 C2 8A 00 89 D1 83 C8 20 3C 78 75 09 D1 64 24 38 42 89 54 24 14 83 7C 24 38 10 7E 08 C7 44 24 38 10 00 00 00 8B 44 24 38 31 FF 83 E8 02 31 ED 83 F8 22 76 09 E9 F6 00 00 00 8B 4C 24 14 8B 44 24 14 8A 10 8D 42 D0 3C 09 76 0D 83 CA 20 B0 28 80 FA 60 76 03 8D 42 A9 0F B6 C0 8B 54 }
	condition:
		$pattern
}

rule __re_search_2_b2429092296656604f63d346b4c12565 {
	meta:
		aliases = "re_search_2, __re_search_2"
		size = "532"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 44 24 30 8B 54 24 30 8B 6C 24 38 8B 7C 24 40 8B 40 10 01 EF 89 44 24 18 8B 5C 24 44 8B 52 14 8B 74 24 48 89 54 24 14 89 7C 24 10 85 DB 0F 88 C5 01 00 00 39 FB 0F 8F BD 01 00 00 89 D8 01 F0 79 06 89 DE F7 DE EB 0C 3B 44 24 10 7E 06 8B 74 24 10 29 DE 8B 44 24 30 83 78 08 00 74 25 85 F6 7E 21 89 C2 8B 00 8A 00 3C 0B 74 0A 3C 09 75 13 80 7A 1C 00 78 0D 85 DB 0F 8F 7B 01 00 00 BE 01 00 00 00 83 7C 24 18 00 0F 84 0C 01 00 00 8B 7C 24 30 F6 47 1C 08 75 15 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FE 0F 84 51 01 00 00 83 7C 24 18 00 0F 84 E2 00 00 00 3B 5C 24 10 0F 8D D8 00 00 }
	condition:
		$pattern
}

rule __GI_getprotoent_r_8ccc2a6592e0f369b2325573025b9973 {
	meta:
		aliases = "getprotoent_r, __GI_getprotoent_r"
		size = "445"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 44 24 3C 8B 5C 24 38 8B 6C 24 30 8B 7C 24 34 81 FB 8B 00 00 00 C7 00 00 00 00 00 77 15 E8 ?? ?? ?? ?? BB 22 00 00 00 C7 00 22 00 00 00 E9 79 01 00 00 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D B7 8C 00 00 00 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 83 74 FF FF FF 83 C4 10 3D 00 10 00 00 77 15 E8 ?? ?? ?? ?? BB 22 00 00 00 C7 00 22 00 00 00 E9 1C 01 00 00 83 3D ?? ?? ?? ?? 00 75 33 50 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 A3 ?? ?? ?? ?? 85 C0 75 16 E8 ?? ?? ?? ?? 8B 18 E9 EA 00 00 00 BB 02 00 00 00 E9 E0 00 00 00 50 FF 35 ?? ?? ?? }
	condition:
		$pattern
}

rule getservent_r_ea5247f2e5d1b5909bed1d1a08cce99a {
	meta:
		aliases = "__GI_getservent_r, getservent_r"
		size = "464"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 44 24 3C 8B 5C 24 38 8B 7C 24 30 8B 6C 24 34 81 FB 8B 00 00 00 C7 00 00 00 00 00 77 15 E8 ?? ?? ?? ?? BB 22 00 00 00 C7 00 22 00 00 00 E9 8C 01 00 00 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 8C 00 00 00 89 44 24 18 8D 83 74 FF FF FF 83 C4 10 3D 00 10 00 00 77 15 E8 ?? ?? ?? ?? BB 22 00 00 00 C7 00 22 00 00 00 E9 2B 01 00 00 83 3D ?? ?? ?? ?? 00 75 32 50 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 A3 ?? ?? ?? ?? 85 C0 75 15 E8 ?? ?? ?? ?? BB 05 00 00 00 C7 00 05 00 00 00 E9 F0 00 00 00 50 FF 35 }
	condition:
		$pattern
}

rule mbsnrtowcs_4b9c720e9f192111ab6c1764dfc31931 {
	meta:
		aliases = "__GI_mbsnrtowcs, mbsnrtowcs"
		size = "145"
		objfiles = "mbsnrtowcs@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 44 24 40 8B 54 24 30 8B 6C 24 34 8B 4C 24 3C 85 C0 75 05 B8 ?? ?? ?? ?? 85 D2 74 0B BF 01 00 00 00 39 C2 75 25 EB 1D 8D 54 24 18 83 C9 FF EB 18 31 F6 EB 3E E8 ?? ?? ?? ?? C7 00 54 00 00 00 83 C8 FF EB 3D 8D 54 24 18 31 FF 8B 5C 24 38 39 CB 76 02 89 CB 8B 75 00 89 D9 EB 13 0F B6 06 89 02 85 C0 74 CC 83 F8 7F 7F CB 46 8D 14 BA 49 85 C9 75 E9 8D 44 24 18 39 C2 74 03 89 75 00 89 D8 29 C8 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __malloc_consolidate_590a7007e467e89046e87ae25742e5ac {
	meta:
		aliases = "__malloc_consolidate"
		size = "424"
		objfiles = "free@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 54 24 30 8B 02 BA 01 00 00 00 85 C0 0F 84 21 01 00 00 8B 4C 24 30 83 E0 FD 89 01 83 C1 34 8B 44 24 30 8B 54 24 30 83 C0 04 89 4C 24 18 89 44 24 0C 8B 02 8B 4C 24 0C C1 E8 03 8D 44 81 F8 89 44 24 10 8B 44 24 0C 8B 08 85 C9 0F 84 C0 00 00 00 C7 00 00 00 00 00 8B 51 08 89 54 24 14 8B 41 04 89 C7 83 E7 FE A8 01 8D 1C 39 8B 53 04 89 54 24 08 75 20 8B 29 89 C8 29 E8 8B 70 08 8B 50 0C 8B 4E 0C 39 C1 75 3D 39 4A 08 75 38 01 EF 89 56 0C 89 72 08 8B 44 24 30 8B 6C 24 08 83 E5 FC 3B 58 2C 74 51 8B 44 2B 04 89 6B 04 83 E0 01 85 C0 75 1F 8B 53 08 8B 43 0C 8B 72 0C 39 DE 75 05 39 70 }
	condition:
		$pattern
}

rule __GI_wcsnrtombs_5a2512cc7c363242d381ef6f32c10748 {
	meta:
		aliases = "wcsnrtombs, __GI_wcsnrtombs"
		size = "134"
		objfiles = "wcsnrtombs@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 54 24 30 8B 6C 24 34 8B 44 24 3C 85 D2 74 0B BF 01 00 00 00 39 EA 75 27 EB 1F 31 FF 8D 54 24 0C 83 C8 FF EB 1A E8 ?? ?? ?? ?? C7 00 54 00 00 00 83 C8 FF EB 41 31 F6 EB 2E 31 FF 8D 54 24 0C 8B 5C 24 38 39 C3 76 02 89 C3 8B 75 00 89 D9 EB 13 8B 06 83 F8 7F 77 CE 88 02 84 C0 74 D8 83 C6 04 01 FA 49 85 C9 75 E9 8D 44 24 0C 39 C2 74 03 89 75 00 89 D8 29 C8 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _obstack_newchunk_de8219b3bf21a0c7eee1b6bc120bb02b {
	meta:
		aliases = "_obstack_newchunk"
		size = "285"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 5C 24 30 8B 43 04 89 44 24 14 8B 6B 0C 8B 3B 2B 6B 08 89 E8 89 EA C1 FA 03 03 44 24 34 03 43 18 8D 44 02 64 39 C7 7D 02 89 C7 F6 43 28 01 8B 43 1C 74 08 51 51 57 FF 73 24 EB 04 83 EC 0C 57 FF D0 83 C4 10 89 C6 85 C0 75 05 E8 ?? ?? ?? ?? 89 43 04 8B 54 24 14 89 50 04 8D 04 38 89 43 10 89 06 8B 53 18 89 D0 F7 D0 8D 4C 16 08 21 C1 31 C0 89 4C 24 18 83 FA 02 7E 31 89 EF C1 EF 02 89 F9 89 7C 24 08 EB 18 8D 04 8D 00 00 00 00 8B 7C 24 18 89 44 24 0C 8B 53 08 8B 14 02 89 14 07 49 85 C9 79 E3 8B 44 24 08 C1 E0 02 89 C2 EB 0E 8B 43 08 8B 4C 24 18 8A 04 10 88 04 11 42 39 EA 7C EE }
	condition:
		$pattern
}

rule realloc_ed3d94dc9d7af88d9760c1738c72afff {
	meta:
		aliases = "realloc"
		size = "808"
		objfiles = "realloc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 5C 24 34 83 7C 24 30 00 75 10 83 EC 0C 53 E8 ?? ?? ?? ?? 89 C3 E9 F9 02 00 00 85 DB 75 11 83 EC 0C FF 74 24 3C E8 ?? ?? ?? ?? E9 E4 02 00 00 57 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 FB DF 76 12 E8 ?? ?? ?? ?? 31 DB C7 00 0C 00 00 00 E9 AC 02 00 00 8D 43 0B C7 44 24 04 10 00 00 00 83 F8 0F 76 07 83 E0 F8 89 44 24 04 8B 7C 24 30 83 EF 08 8B 57 04 89 D0 83 E0 FC 89 44 24 08 F6 C2 02 0F 85 94 01 00 00 8B 4C 24 04 89 C3 39 C8 0F 83 31 01 00 00 8D 34 07 3B 35 ?? ?? ?? ?? 75 38 8B 46 04 89 D9 83 E0 FC 01 C1 }
	condition:
		$pattern
}

rule bindresvport_701650105b24f5da95bb55db77fadac1 {
	meta:
		aliases = "__GI_bindresvport, bindresvport"
		size = "202"
		objfiles = "bindresvport@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 5C 24 34 8B 6C 24 30 85 DB 75 1B 52 6A 10 6A 00 8D 5C 24 18 53 E8 ?? ?? ?? ?? 66 C7 44 24 1C 02 00 83 C4 10 EB 16 66 83 3B 02 74 10 E8 ?? ?? ?? ?? C7 00 60 00 00 00 83 C8 FF EB 7E 66 83 3D ?? ?? ?? ?? 00 75 1B E8 ?? ?? ?? ?? BA A8 01 00 00 89 D1 99 F7 F9 66 81 C2 58 02 66 89 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 F6 89 C7 C7 00 62 00 00 00 83 C8 FF EB 34 66 A1 ?? ?? ?? ?? 89 C2 40 66 C1 CA 08 66 3D FF 03 66 89 53 02 66 A3 ?? ?? ?? ?? 7E 09 66 C7 05 ?? ?? ?? ?? 58 02 50 6A 10 53 55 46 E8 ?? ?? ?? ?? 83 C4 10 81 FE A7 01 00 00 7F 09 85 C0 79 05 83 3F 62 74 BB 83 C4 1C 5B 5E 5F }
	condition:
		$pattern
}

rule __read_etc_hosts_r_8e500fd50c651d81104c17145a8bb47a {
	meta:
		aliases = "__read_etc_hosts_r"
		size = "724"
		objfiles = "read_etc_hosts_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 5C 24 44 8B 54 24 48 89 D8 F7 D8 83 E0 03 74 0C 39 C2 0F 82 A0 02 00 00 01 C3 29 C2 83 FA 1F 0F 86 93 02 00 00 8D 43 20 8D 6A E0 89 44 24 18 83 7C 24 3C 01 0F 84 17 01 00 00 8B 44 24 50 83 FD 03 C7 00 FF FF FF FF 0F 86 6B 02 00 00 8D 42 DC 83 F8 07 0F 86 5F 02 00 00 83 FD 0F 0F 86 56 02 00 00 8D 42 D0 83 F8 07 0F 86 4A 02 00 00 8D 43 30 8D 6A D4 89 44 24 14 8D 42 C8 8D 7B 24 39 E8 72 05 8D 73 2C EB 05 8D 73 38 89 C5 83 FD 4F 0F 86 23 02 00 00 E8 ?? ?? ?? ?? 89 44 24 30 85 C0 74 20 8B 54 24 18 8B 44 24 14 89 14 24 89 7C 24 04 89 54 24 08 89 44 24 0C 89 74 24 18 E9 AE 00 }
	condition:
		$pattern
}

rule svcudp_recv_06c3e9811b2bcb38a181117deba115c2 {
	meta:
		aliases = "svcudp_recv"
		size = "493"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 6C 24 30 8B 75 30 8D 45 34 8D 7D 3C C7 44 24 18 10 00 00 00 89 44 24 04 83 7F 0C 00 8D 55 10 74 4E 8B 45 2C 89 45 34 8B 4C 24 04 8B 06 89 41 04 8D 45 58 89 55 3C 89 47 10 89 4F 08 C7 47 0C 01 00 00 00 C7 47 04 10 00 00 00 C7 47 14 DC 00 00 00 50 6A 00 57 FF 75 00 E8 ?? ?? ?? ?? 83 C4 10 89 C2 85 C0 78 25 8B 47 04 89 44 24 18 EB 1C 53 53 8D 44 24 20 50 52 6A 00 FF 36 FF 75 2C FF 75 00 E8 ?? ?? ?? ?? 83 C4 20 89 C2 8B 44 24 18 83 FA FF 89 45 0C 75 13 E8 ?? ?? ?? ?? 83 38 04 0F 84 61 FF FF FF E9 2A 01 00 00 83 FA 0F 0F 8E 21 01 00 00 8D 5E 08 C7 46 08 01 00 00 00 51 51 8B }
	condition:
		$pattern
}

rule svc_unregister_8d25b163dafdbc70839c4a712361588d {
	meta:
		aliases = "__GI_svc_unregister, svc_unregister"
		size = "94"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 6C 24 30 8B 7C 24 34 8D 4C 24 18 89 FA 89 E8 E8 ?? ?? ?? ?? 89 C3 85 C0 74 34 8B 44 24 18 8B 33 85 C0 75 0D E8 ?? ?? ?? ?? 89 B0 B8 00 00 00 EB 02 89 30 83 EC 0C C7 03 00 00 00 00 53 E8 ?? ?? ?? ?? 58 5A 57 55 E8 ?? ?? ?? ?? 83 C4 10 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_getdelim_3b1662aba32b56ad474ff73ae26a39ee {
	meta:
		aliases = "getdelim, __GI_getdelim"
		size = "254"
		objfiles = "getdelim@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 6C 24 34 8B 7C 24 3C 83 7C 24 30 00 74 08 85 ED 74 04 85 FF 75 1B E8 ?? ?? ?? ?? 83 CF FF C7 00 16 00 00 00 E9 C3 00 00 00 83 CF FF E9 A3 00 00 00 8B 47 34 89 44 24 08 85 C0 75 1F 8D 5F 38 51 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 44 24 30 8B 18 85 DB 75 07 C7 45 00 00 00 00 00 BE 01 00 00 00 8B 45 00 39 C6 72 1F 83 C0 40 52 52 50 53 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 74 9C 83 45 00 40 8B 44 24 30 89 18 8B 47 10 3B 47 18 73 09 0F B6 10 40 89 47 10 EB 0E 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 89 C2 83 FA FF 74 0B 46 88 54 33 FE }
	condition:
		$pattern
}

rule registerrpc_6c64af1b19f9c2523f7de0b130dde6d7 {
	meta:
		aliases = "registerrpc"
		size = "266"
		objfiles = "svc_simple@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 6C 24 38 8B 7C 24 30 8B 74 24 34 85 ED 75 0A 50 6A 00 68 ?? ?? ?? ?? EB 61 E8 ?? ?? ?? ?? 89 C3 83 B8 C4 00 00 00 00 75 21 83 EC 0C 6A FF E8 ?? ?? ?? ?? 83 C4 10 89 83 C4 00 00 00 85 C0 75 0A 83 EC 0C 68 ?? ?? ?? ?? EB 57 50 50 56 57 E8 ?? ?? ?? ?? C7 04 24 11 00 00 00 68 ?? ?? ?? ?? 56 57 FF B3 C4 00 00 00 E8 ?? ?? ?? ?? 83 C4 20 85 C0 75 13 56 57 68 ?? ?? ?? ?? 8D 44 24 24 50 E8 ?? ?? ?? ?? EB 53 83 EC 0C 6A 18 E8 ?? ?? ?? ?? 83 C4 10 89 C2 85 C0 75 13 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 44 24 28 EB 2D 8B 44 24 3C 89 7A 04 89 02 89 6A 08 8B 44 24 40 89 42 0C 8B }
	condition:
		$pattern
}

rule _stdlib_wcsto_ll_1481c2c23a55646c1ce5b4e69c80d7a1 {
	meta:
		aliases = "_stdlib_wcsto_ll"
		size = "535"
		objfiles = "_stdlib_wcsto_ll@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 30 89 74 24 14 EB 05 83 44 24 14 04 83 EC 0C 8B 44 24 20 FF 30 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 E6 8B 54 24 14 8B 02 83 F8 2B 74 11 C6 44 24 13 00 83 F8 2D 75 11 C6 44 24 13 01 EB 05 C6 44 24 13 00 83 44 24 14 04 89 F3 F7 44 24 38 EF FF FF FF 75 42 83 44 24 38 0A 8B 44 24 14 83 38 30 75 25 83 6C 24 38 02 83 C0 04 89 44 24 14 89 C2 8B 00 89 D3 83 C8 20 83 F8 78 75 0B D1 64 24 38 83 C2 04 89 54 24 14 83 7C 24 38 10 7E 08 C7 44 24 38 10 00 00 00 8B 44 24 38 31 FF 83 E8 02 31 ED 83 F8 22 76 09 E9 02 01 00 00 8B 5C 24 14 8B 44 24 14 8B 08 8D 41 D0 83 F8 09 77 05 8D 51 }
	condition:
		$pattern
}

rule __GI_xdr_pmaplist_b6bf74fcfa9535389edf49e4bd94c3fd {
	meta:
		aliases = "xdr_pmaplist, __GI_xdr_pmaplist"
		size = "127"
		objfiles = "pmap_prot2@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 30 8B 5C 24 34 83 3E 02 0F 94 C0 0F B6 F8 31 ED EB 02 89 EB 31 C0 83 3B 00 0F 95 C0 89 44 24 18 50 50 8D 44 24 20 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 37 83 7C 24 18 00 75 07 B8 01 00 00 00 EB 2B 85 FF 74 05 8B 2B 83 C5 10 68 ?? ?? ?? ?? 6A 14 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 0B 85 FF 75 AE 8B 1B 83 C3 10 EB A9 31 C0 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fwide_fe7d17455b5cee17668ce94fc710e73b {
	meta:
		aliases = "fwide"
		size = "132"
		objfiles = "fwide@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 30 8B 6C 24 34 8B 7E 34 85 FF 75 1F 8D 5E 38 52 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 85 ED 74 1C 8B 06 A9 80 08 00 00 75 13 BA 00 08 00 00 85 ED 7F 05 BA 80 00 00 00 09 D0 66 89 06 0F B7 1E 85 FF 75 11 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 81 E3 80 00 00 00 25 00 08 00 00 83 C4 1C 29 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule putgrent_53bea0ae03f408f43c777cf4b0396816 {
	meta:
		aliases = "putgrent"
		size = "204"
		objfiles = "putgrent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 30 8B 7C 24 34 85 F6 74 04 85 FF 75 13 E8 ?? ?? ?? ?? 83 CB FF C7 00 16 00 00 00 E9 98 00 00 00 8B 6F 34 85 ED 75 1F 8D 5F 38 50 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C FF 76 08 FF 76 04 FF 36 68 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 83 C4 20 85 C0 78 3D 8B 5E 0C BA ?? ?? ?? ?? 8B 03 85 C0 75 15 53 53 57 6A 0A E8 ?? ?? ?? ?? 31 DB 83 C4 10 85 C0 79 1F EB 1A 51 50 52 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 0A 83 C3 04 BA ?? ?? ?? ?? EB CB 83 CB FF 85 ED 75 11 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 1C 89 D8 5B }
	condition:
		$pattern
}

rule __GI_setvbuf_fa046d77de66d7b55c16e1d64e26cbca {
	meta:
		aliases = "setvbuf, __GI_setvbuf"
		size = "259"
		objfiles = "setvbuf@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 30 8B 7C 24 34 8B 6C 24 3C 8B 46 34 89 44 24 08 85 C0 75 1F 8D 5E 38 52 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 83 7C 24 38 02 76 13 E8 ?? ?? ?? ?? 83 CB FF C7 00 16 00 00 00 E9 8A 00 00 00 8B 06 83 CB FF A9 CF 08 00 00 75 7E 80 E4 FC 66 89 06 8B 44 24 38 C1 E0 08 66 09 06 83 7C 24 38 02 74 04 85 ED 75 08 31 FF 31 ED 31 DB EB 26 31 DB 85 FF 75 20 8B 46 0C 2B 46 08 39 E8 74 49 83 EC 0C 55 E8 ?? ?? ?? ?? 83 C4 10 89 C7 85 C0 74 37 66 BB 00 40 8B 06 F6 C4 40 74 14 83 EC 0C 80 E4 BF 66 89 06 FF 76 08 E8 ?? ?? ?? ?? 83 C4 10 66 }
	condition:
		$pattern
}

rule fsetpos_724e250614b2633ec157a13eff800a8e {
	meta:
		aliases = "fsetpos"
		size = "122"
		objfiles = "fsetpos@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 30 8B 7C 24 34 8B 6E 34 85 ED 75 1F 8D 5E 38 51 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 52 6A 00 FF 37 56 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 75 12 8B 47 04 89 46 2C 8B 47 08 89 46 30 8B 47 0C 88 46 02 85 ED 75 11 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 1C 89 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fsetpos64_16ea63a959aaec8582567db6ab54dfce {
	meta:
		aliases = "fsetpos64"
		size = "124"
		objfiles = "fsetpos64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 30 8B 7C 24 34 8B 6E 34 85 ED 75 1F 8D 5E 38 52 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 6A 00 FF 77 04 FF 37 56 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 75 12 8B 47 08 89 46 2C 8B 47 0C 89 46 30 8B 47 10 88 46 02 85 ED 75 11 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 1C 89 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fgetpos_6563ca554ecaea8a22f065c81ea1e306 {
	meta:
		aliases = "fgetpos"
		size = "126"
		objfiles = "fgetpos@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 30 8B 7C 24 34 8B 6E 34 85 ED 75 1F 8D 5E 38 52 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C 83 CB FF 56 E8 ?? ?? ?? ?? 83 C4 10 89 07 85 C0 78 15 8B 46 2C 31 DB 89 47 04 8B 46 30 89 47 08 0F B6 46 02 89 47 0C 85 ED 75 11 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 1C 89 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fgetpos64_e32f63fa5158ca3a8a626c86ecaed71b {
	meta:
		aliases = "fgetpos64"
		size = "131"
		objfiles = "fgetpos64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 30 8B 7C 24 34 8B 6E 34 85 ED 75 1F 8D 5E 38 52 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C 83 CB FF 56 E8 ?? ?? ?? ?? 89 57 04 83 C4 10 89 07 83 7F 04 00 78 15 8B 46 2C 31 DB 89 47 08 8B 46 30 89 47 0C 0F B6 46 02 89 47 10 85 ED 75 11 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 1C 89 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule lround_8e290cbfb3b608f5218231328d57b084 {
	meta:
		aliases = "__GI_lround, lround"
		size = "220"
		objfiles = "s_lround@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 34 8B 5C 24 30 89 F0 89 F1 C1 E8 14 81 E1 FF FF 0F 00 25 FF 07 00 00 89 F7 C1 FF 1F 81 C9 00 00 10 00 8D 90 01 FC FF FF 83 CF 01 89 DD 89 4C 24 04 83 FA 13 7F 2C 85 D2 79 10 89 F8 42 0F 84 87 00 00 00 31 C0 E9 80 00 00 00 88 D1 B8 00 00 08 00 D3 F8 03 44 24 04 B9 14 00 00 00 29 D1 D3 E8 EB 65 83 FA 1E 7F 31 8D B0 ED FB FF FF B8 00 00 00 80 89 F1 D3 E8 8D 1C 03 39 EB 83 54 24 04 00 83 FA 14 8B 44 24 04 74 3E D3 E0 B9 34 00 00 00 29 D1 D3 EB 09 D8 EB 2F D9 7C 24 16 66 8B 44 24 16 80 CC 0C 89 5C 24 08 89 74 24 0C 66 89 44 24 14 DD 44 24 08 D9 6C 24 14 DB 5C 24 10 D9 }
	condition:
		$pattern
}

rule putspent_9afa9c87919c594dcc6cec9d14c9aaae {
	meta:
		aliases = "putspent"
		size = "218"
		objfiles = "putspent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 34 8B 7C 24 30 8B 6E 34 85 ED 75 1F 8D 5E 38 50 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 47 04 85 C0 75 05 B8 ?? ?? ?? ?? 50 31 DB FF 37 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 2C EB 5E 0F B6 83 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B 04 07 83 F8 FF 74 05 BA ?? ?? ?? ?? 51 50 52 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 35 43 83 FB 05 76 D1 8B 47 20 83 F8 FF 74 14 51 50 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 13 52 52 56 6A 0A E8 ?? ?? ?? ?? 31 DB 83 C4 10 85 C0 7F 03 83 CB FF 85 ED 75 11 50 50 6A 01 8D 44 24 18 50 }
	condition:
		$pattern
}

rule ungetwc_ce9d70b1f739c48291026067cb28c57d {
	meta:
		aliases = "__GI_ungetwc, ungetwc"
		size = "170"
		objfiles = "ungetwc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 34 8B 7C 24 30 8B 6E 34 85 ED 75 1F 8D 5E 38 51 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 0F B7 06 25 03 08 00 00 3D 00 08 00 00 77 14 52 52 68 00 08 00 00 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 30 0F B7 06 A8 02 74 0A A8 01 75 25 83 7E 28 00 75 1F 83 FF FF 74 1A 66 FF 06 C7 46 28 01 00 00 00 0F B7 06 66 83 26 FB 83 E0 01 89 7C 86 24 EB 03 83 CF FF 85 ED 75 11 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 1C 89 F8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_ungetc_8cb994fb4b11e35d8980e489541905bc {
	meta:
		aliases = "ungetc, __GI_ungetc"
		size = "207"
		objfiles = "ungetc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 34 8B 7C 24 30 8B 6E 34 85 ED 75 1F 8D 5E 38 51 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 46 10 3B 46 18 73 17 83 FF FF 74 12 3B 46 08 76 0D 89 FA 38 50 FF 75 06 48 89 46 10 EB 53 0F B7 06 25 83 00 00 00 3D 80 00 00 00 77 14 52 52 68 80 00 00 00 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 36 0F B7 06 A8 02 74 0A A8 01 75 2B 83 7E 28 00 75 25 83 FF FF 74 20 66 FF 06 8B 46 08 89 46 18 C7 46 28 01 00 00 00 0F B7 06 83 E0 01 89 7C 86 24 66 83 26 FB EB 03 83 CF FF 85 ED 75 11 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 1C }
	condition:
		$pattern
}

rule vasprintf_33b50e71de5709b2f28b32467026fc10 {
	meta:
		aliases = "__GI_vasprintf, vasprintf"
		size = "115"
		objfiles = "vasprintf@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 38 8B 6C 24 34 8B 7C 24 30 89 74 24 18 56 55 6A 00 6A 00 E8 ?? ?? ?? ?? 83 C4 10 89 C3 C7 07 00 00 00 00 85 C0 78 38 83 EC 0C 43 53 E8 ?? ?? ?? ?? 83 C4 10 89 07 85 C0 74 25 56 55 53 50 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 79 13 83 EC 0C FF 37 E8 ?? ?? ?? ?? C7 07 00 00 00 00 83 C4 10 83 C4 1C 89 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule free_0f04f046856e1c6cf0b1a15d9d55a529 {
	meta:
		aliases = "free"
		size = "412"
		objfiles = "free@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 7C 24 30 85 FF 0F 84 81 01 00 00 56 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4F F8 A1 ?? ?? ?? ?? 83 C4 10 8B 51 04 89 D3 83 E3 FC 39 C3 77 20 C1 EB 03 83 C8 03 A3 ?? ?? ?? ?? 8D 14 9D ?? ?? ?? ?? 8B 42 FC 89 41 08 89 4A FC E9 18 01 00 00 80 E2 02 0F 85 EF 00 00 00 83 C8 01 8D 34 19 A3 ?? ?? ?? ?? 8B 46 04 89 44 24 08 F6 41 04 01 75 21 8B 6F F8 89 C8 29 E8 8B 78 08 8B 50 0C 8B 4F 0C 39 C1 75 3C 39 4A 08 75 37 01 EB 89 57 0C 89 7A 08 8B 6C 24 08 83 E5 FC 3B 35 ?? ?? ?? ?? 74 52 8B 44 2E 04 89 6E 04 83 E0 01 85 C0 }
	condition:
		$pattern
}

rule __GI_unsetenv_cd85b9dbb1952c4430ab04aa8190890f {
	meta:
		aliases = "unsetenv, __GI_unsetenv"
		size = "186"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 7C 24 30 85 FF 74 16 80 3F 00 74 11 53 53 6A 3D 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 7D 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 0C 89 C5 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 83 C4 10 EB 2B 51 55 57 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 18 80 3C 2B 3D 75 12 89 F2 8B 42 04 8D 4A 04 89 02 85 C0 74 07 89 CA EB F0 83 C6 04 8B 1E 85 DB 75 CF 52 52 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 31 C0 83 C4 10 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule memalign_151cc3bac922a03b152ad79af2ca8222 {
	meta:
		aliases = "memalign"
		size = "385"
		objfiles = "memalign@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 7C 24 30 8B 5C 24 34 83 FF 08 77 10 83 EC 0C 53 E8 ?? ?? ?? ?? 89 C3 E9 50 01 00 00 83 FF 0F 77 05 BF 10 00 00 00 8D 47 FF BA 10 00 00 00 85 F8 75 04 EB 08 01 D2 39 FA 72 FA 89 D7 52 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 FB DF 76 12 E8 ?? ?? ?? ?? 31 DB C7 00 0C 00 00 00 E9 F8 00 00 00 8D 43 0B C7 44 24 08 10 00 00 00 83 F8 0F 76 07 83 E0 F8 89 44 24 08 83 EC 0C 31 DB 8B 54 24 14 8D 44 3A 10 50 E8 ?? ?? ?? ?? 83 C4 10 89 C5 85 C0 0F 84 B0 00 00 00 31 D2 8D 70 F8 F7 F7 85 D2 74 60 89 FA 8D 44 3D FF F7 }
	condition:
		$pattern
}

rule __GI_getmntent_r_e7965f57424a6d22f0279f8013ce4a7c {
	meta:
		aliases = "getmntent_r, __GI_getmntent_r"
		size = "299"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 7C 24 30 8B 5C 24 34 8B 74 24 38 8B 6C 24 3C 85 FF 0F 84 00 01 00 00 85 DB 0F 84 F8 00 00 00 85 F6 0F 84 F0 00 00 00 EB 0A 8A 06 3C 23 74 04 3C 0A 75 15 50 57 55 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 E6 E9 CF 00 00 00 C7 44 24 18 00 00 00 00 50 8D 7C 24 1C 57 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 10 89 03 85 C0 0F 84 A9 00 00 00 50 57 68 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? 83 C4 10 89 43 04 85 C0 0F 84 8D 00 00 00 50 57 68 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? 83 C4 10 89 43 08 85 C0 74 75 55 57 68 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? 83 C4 10 89 43 0C 85 C0 75 07 C7 43 0C ?? ?? ?? }
	condition:
		$pattern
}

rule expm1_bc0341494ab3ca28db6a0a7a499889f5 {
	meta:
		aliases = "__GI_expm1, expm1"
		size = "911"
		objfiles = "s_expm1@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 7C 24 34 8B 74 24 30 89 FA 89 FB 81 E2 FF FF FF 7F 81 E3 00 00 00 80 89 F9 81 FA 79 68 43 40 0F 86 9B 00 00 00 81 FA 41 2E 86 40 76 74 81 FA FF FF EF 7F 76 39 81 E1 FF FF 0F 00 09 F1 74 10 89 74 24 08 89 7C 24 0C DD 44 24 08 D8 C0 EB 0E 85 DB 0F 84 1C 03 00 00 D9 05 ?? ?? ?? ?? DD 5C 24 08 8B 74 24 08 8B 7C 24 0C E9 05 03 00 00 DD 05 ?? ?? ?? ?? 89 74 24 08 89 7C 24 0C DD 44 24 08 DA E9 DF E0 9E 76 1A BE 9C 75 00 88 BF 3C E4 37 7E 89 74 24 08 89 7C 24 0C DD 44 24 08 D8 C8 EB BC 85 DB 74 1B 89 74 24 08 89 7C 24 0C DD 44 24 08 DC 05 ?? ?? ?? ?? D9 EE DA E9 DF E0 9E 77 97 }
	condition:
		$pattern
}

rule __GI_svc_register_8973d2746dc33fa881d077499345c03a {
	meta:
		aliases = "svc_register, __GI_svc_register"
		size = "137"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 7C 24 34 8B 74 24 38 8D 4C 24 18 89 F2 89 F8 8B 6C 24 3C E8 ?? ?? ?? ?? 85 C0 74 07 39 68 0C 75 56 EB 2F 83 EC 0C 6A 10 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 74 41 89 78 04 89 70 08 89 68 0C E8 ?? ?? ?? ?? 8B 90 B8 00 00 00 89 13 89 98 B8 00 00 00 B8 01 00 00 00 83 7C 24 40 00 74 1B 8B 44 24 30 0F B7 40 04 50 FF 74 24 44 56 57 E8 ?? ?? ?? ?? 83 C4 10 EB 02 31 C0 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __pgsreader_449307f7d75ce3405a4f024935cbb8b9 {
	meta:
		aliases = "__pgsreader"
		size = "273"
		objfiles = "__pgsreader@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 7C 24 3C 8B 74 24 38 8B 6C 24 40 81 FF FF 00 00 00 77 1F E8 ?? ?? ?? ?? BB 22 00 00 00 C7 00 22 00 00 00 E9 D7 00 00 00 BB 02 00 00 00 E9 B5 00 00 00 8B 45 34 89 44 24 08 85 C0 75 1F 8D 5D 38 50 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 31 DB 51 55 57 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 0D BB 22 00 00 00 F6 45 00 04 74 6E EB AD 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 8D 54 30 FF 80 3A 0A 75 05 C6 02 00 EB 08 40 39 F8 75 03 43 EB C1 85 DB 74 03 4B EB BA 8A 06 84 C0 74 B4 3C 23 74 B0 0F BE D0 A1 ?? ?? ?? ?? F6 04 50 20 75 A2 81 7C 24 30 }
	condition:
		$pattern
}

rule readtcp_df1bc16db0a3b7767cde839923b4c8c2 {
	meta:
		aliases = "readtcp"
		size = "194"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C BA E8 03 00 00 89 D3 8B 74 24 30 8B 6C 24 38 69 4E 08 E8 03 00 00 8B 46 0C 99 F7 FB 66 31 DB 85 ED 8D 3C 01 0F 84 87 00 00 00 8B 06 66 C7 44 24 18 01 00 89 44 24 14 50 57 6A 01 8D 44 24 20 50 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 74 0D 85 C0 75 24 C7 46 24 05 00 00 00 EB 16 E8 ?? ?? ?? ?? 83 38 04 74 D3 C7 46 24 04 00 00 00 8B 00 89 46 28 83 CB FF EB 3C 50 55 FF 74 24 3C FF 36 E8 ?? ?? ?? ?? 83 C4 10 89 C3 83 F8 FF 74 14 85 C0 75 21 C7 46 28 68 00 00 00 C7 46 24 04 00 00 00 EB D0 E8 ?? ?? ?? ?? 8B 00 C7 46 24 04 00 00 00 89 46 28 83 C4 1C 89 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_ptsname_r_2db313e4201d7c847dccfe26184add5a {
	meta:
		aliases = "ptsname_r, __GI_ptsname_r"
		size = "156"
		objfiles = "ptsname@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C E8 ?? ?? ?? ?? 89 C6 8B 28 53 8D 44 24 1C 50 68 30 54 04 80 FF 74 24 3C E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 5E 83 EC 0C 6A 00 6A F6 8B 44 24 2C 99 52 50 8D 44 24 33 8D 5C 24 28 50 E8 ?? ?? ?? ?? 83 C4 20 29 C3 83 C3 15 89 C7 39 5C 24 38 73 0D B8 22 00 00 00 C7 06 22 00 00 00 EB 30 51 51 68 ?? ?? ?? ?? FF 74 24 40 E8 ?? ?? ?? ?? 58 5A 57 FF 74 24 40 E8 ?? ?? ?? ?? 31 C0 83 C4 10 89 2E EB 0B C7 06 19 00 00 00 B8 19 00 00 00 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_pthread_cond_timedwait_a036ca881ee41f870bd30f4635efb265 {
	meta:
		aliases = "pthread_cond_timedwait, __GI_pthread_cond_timedwait"
		size = "434"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C E8 ?? ?? ?? ?? 8B 6C 24 34 89 44 24 18 8B 74 24 30 8B 45 0C 83 F8 03 74 16 85 C0 74 12 8B 44 24 18 BA 16 00 00 00 39 45 08 0F 85 72 01 00 00 8B 44 24 18 89 74 24 10 C7 44 24 14 ?? ?? ?? ?? 8D 54 24 10 C6 80 B9 01 00 00 00 8B 44 24 18 E8 ?? ?? ?? ?? 89 F0 8B 54 24 18 E8 ?? ?? ?? ?? 8B 44 24 18 80 78 42 00 74 0F 8B 44 24 18 BB 01 00 00 00 80 78 40 00 74 0E 8B 54 24 18 8D 46 08 E8 ?? ?? ?? ?? 31 DB 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 85 DB 74 12 8B 44 24 18 31 D2 E8 ?? ?? ?? ?? 51 51 E9 B6 00 00 00 83 EC 0C 31 FF 55 E8 ?? ?? ?? ?? 83 C4 10 8B 44 24 18 52 52 FF 74 24 40 50 E8 }
	condition:
		$pattern
}

rule sem_timedwait_90f7b76c76d946535ecbeff78dc24dee {
	meta:
		aliases = "sem_timedwait"
		size = "345"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C E8 ?? ?? ?? ?? 8B 7C 24 30 89 C2 89 C6 89 F8 8B 6C 24 34 E8 ?? ?? ?? ?? 8B 47 08 85 C0 7E 11 48 83 EC 0C 89 47 08 57 E8 ?? ?? ?? ?? 31 C0 EB 20 81 7D 04 FF C9 9A 3B 76 1F 83 EC 0C 57 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 83 C4 10 E9 F2 00 00 00 89 7C 24 14 C7 44 24 18 ?? ?? ?? ?? 8D 54 24 14 C6 86 BA 01 00 00 00 89 F0 E8 ?? ?? ?? ?? 80 7E 42 00 74 0B BB 01 00 00 00 80 7E 40 00 74 0C 8D 47 0C 89 F2 E8 ?? ?? ?? ?? 31 DB 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 85 DB 74 0B 31 D2 89 F0 E8 ?? ?? ?? ?? EB 73 51 51 55 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 2C 89 F2 89 }
	condition:
		$pattern
}

rule __GI_readdir_r_4962a3c606450bd0542272f0534d8fa6 {
	meta:
		aliases = "readdir_r, __GI_readdir_r"
		size = "196"
		objfiles = "readdir_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 31 FF 8B 74 24 34 8B 6C 24 3C 8D 5E 18 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 46 08 3B 46 04 77 36 51 FF 76 14 FF 76 0C FF 36 E8 ?? ?? ?? ?? 83 C4 10 83 F8 00 7F 16 C7 45 00 00 00 00 00 75 04 31 DB EB 47 E8 ?? ?? ?? ?? 8B 18 EB 3E 89 46 08 C7 46 04 00 00 00 00 8B 46 04 89 C7 03 7E 0C 0F B7 57 08 01 D0 89 46 04 8B 47 04 89 46 10 83 3F 00 74 A6 52 31 DB 0F B7 47 08 50 57 FF 74 24 40 E8 ?? ?? ?? ?? 83 C4 10 89 45 00 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 31 C0 85 FF 0F 94 C0 F7 D8 21 C3 83 C4 2C 89 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule readdir64_r_601dc6984ab23058fc6e074f1f4f8304 {
	meta:
		aliases = "__GI_readdir64_r, readdir64_r"
		size = "198"
		objfiles = "readdir64_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 31 FF 8B 74 24 34 8B 6C 24 3C 8D 5E 18 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 46 08 3B 46 04 77 36 51 FF 76 14 FF 76 0C FF 36 E8 ?? ?? ?? ?? 83 C4 10 83 F8 00 7F 16 C7 45 00 00 00 00 00 75 04 31 DB EB 49 E8 ?? ?? ?? ?? 8B 18 EB 40 89 46 08 C7 46 04 00 00 00 00 8B 46 04 89 C7 03 7E 0C 0F B7 57 10 01 D0 89 46 04 8B 47 08 89 46 10 8B 07 0B 47 04 74 A4 52 31 DB 0F B7 47 10 50 57 FF 74 24 40 E8 ?? ?? ?? ?? 83 C4 10 89 45 00 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 31 C0 85 FF 0F 94 C0 F7 D8 21 C3 83 C4 2C 89 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fcloseall_28fa6d6ddcdee85d8392a5527b089e39 {
	meta:
		aliases = "fcloseall"
		size = "240"
		objfiles = "fcloseall@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 18 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 5D 40 A3 ?? ?? ?? ?? 58 6A 01 53 E8 ?? ?? ?? ?? 83 C4 0C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 5F 6A 01 8B 35 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? C7 44 24 18 00 00 00 00 83 C4 10 EB 63 8B 7E 34 8B 6E 20 85 FF 75 1F 8D 5E 38 52 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 0F B7 06 83 E0 30 83 F8 30 74 18 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 08 C7 44 24 08 FF FF FF FF 85 FF 75 11 }
	condition:
		$pattern
}

rule __GI_getprotobyname_r_92e97715d4e928575e288898726aabea {
	meta:
		aliases = "getprotobyname_r, __GI_getprotobyname_r"
		size = "194"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 6C 24 34 8B 74 24 38 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F BE 05 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 EB 2F 51 51 55 FF 36 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 39 8B 5E 04 EB 13 52 52 55 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 24 83 C3 04 8B 03 85 C0 75 E7 FF 74 24 40 FF 74 24 40 FF 74 24 40 56 E8 ?? ?? ?? ?? 83 C4 10 89 C7 85 C0 74 B6 80 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 55 55 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 8B 44 24 50 83 38 00 0F 94 C0 0F B6 C0 F7 D8 83 C4 2C 21 F8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _dl_dprintf_e6784124ac870fdc74cc9f3f3606e67f {
	meta:
		aliases = "_dl_dprintf"
		size = "704"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 6C 24 38 85 ED 0F 84 A5 02 00 00 8B 0D ?? ?? ?? ?? C7 44 24 18 00 00 00 00 31 C0 BA 03 00 00 00 BE 22 00 00 00 83 CF FF 53 89 C3 55 8B 6C 24 18 B8 C0 00 00 00 CD 80 5D 5B 3D 00 F0 FF FF 76 0A F7 D8 A3 ?? ?? ?? ?? 83 C8 FF A3 ?? ?? ?? ?? 40 75 45 B9 ?? ?? ?? ?? BA 1D 00 00 00 8B 7C 24 34 53 89 FB B8 04 00 00 00 CD 80 5B 3D 00 F0 FF FF 76 07 F7 D8 A3 ?? ?? ?? ?? BF 14 00 00 00 53 89 FB B8 01 00 00 00 CD 80 5B 3D 00 F0 FF FF 76 07 F7 D8 A3 ?? ?? ?? ?? 8D 75 FF 8B 1D ?? ?? ?? ?? 89 F2 42 80 3A 00 75 FA A1 ?? ?? ?? ?? 29 EA 48 39 C2 72 45 B9 ?? ?? ?? ?? BA 0B 00 00 00 8B 7C }
	condition:
		$pattern
}

rule getservbyname_r_8ce7ab8e0bb37cd36e5000b226aa0beb {
	meta:
		aliases = "__GI_getservbyname_r, getservbyname_r"
		size = "224"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 6C 24 38 8B 74 24 3C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F BE 05 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 EB 4D 51 51 FF 36 FF 74 24 3C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 23 8B 5E 04 EB 16 52 52 50 FF 74 24 3C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 0B 83 C3 04 8B 03 85 C0 75 E4 EB 16 85 ED 74 2D 50 50 55 FF 76 0C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 1B FF 74 24 44 FF 74 24 44 FF 74 24 44 56 E8 ?? ?? ?? ?? 83 C4 10 89 C7 85 C0 74 98 80 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 8B }
	condition:
		$pattern
}

rule __GI_getprotobynumber_r_e85d8592453ff8391394266a695d2f05 {
	meta:
		aliases = "getprotobynumber_r, __GI_getprotobynumber_r"
		size = "149"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 74 24 38 8B 6C 24 40 8B 7C 24 44 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F BE 05 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 EB 09 8B 44 24 30 39 46 08 74 15 57 55 FF 74 24 40 56 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 74 E2 80 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 56 56 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 31 C0 83 3F 00 0F 94 C0 F7 D8 83 C4 2C 21 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule getservbyport_r_5488893ebab3061976099b0254362f4b {
	meta:
		aliases = "__GI_getservbyport_r, getservbyport_r"
		size = "175"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 7C 24 38 8B 74 24 3C 8B 6C 24 48 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F BE 05 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 EB 1F 8B 44 24 30 39 46 08 75 16 85 FF 74 2A 50 50 57 FF 76 0C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 18 55 FF 74 24 44 FF 74 24 44 56 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 74 C9 80 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 51 51 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 31 C0 83 7D 00 00 0F 94 C0 F7 D8 83 C4 2C 21 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule xdr_rmtcall_args_7102c4178a637ec0510df6cbf51ea5b6 {
	meta:
		aliases = "__GI_xdr_rmtcall_args, xdr_rmtcall_args"
		size = "228"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 24 8B 5C 24 38 8B 74 24 3C 56 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 B9 00 00 00 50 50 8D 46 04 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 A2 00 00 00 8D 46 08 55 55 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 8B 00 00 00 C7 44 24 18 00 00 00 00 83 EC 0C 8B 43 04 53 FF 50 10 89 44 24 18 59 5F 8D 44 24 20 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 61 83 EC 0C 8B 43 04 53 FF 50 10 89 C5 58 5A FF 76 10 53 FF 56 14 83 C4 10 85 C0 74 45 83 EC 0C 8B 43 04 53 FF 50 10 89 C7 29 E8 89 46 0C 5D 58 8B 43 04 FF 74 24 10 53 FF 50 14 5A 8D 46 0C 59 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 14 50 50 }
	condition:
		$pattern
}

rule lrint_633c6331d73fba216fd8b1b67ab9b5ab {
	meta:
		aliases = "__GI_lrint, lrint"
		size = "322"
		objfiles = "s_lrint@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 24 8B 5C 24 3C 8B 4C 24 38 89 D8 C1 E8 14 89 C2 89 C5 C1 ED 0B 81 E2 FF 07 00 00 81 EA FF 03 00 00 83 FA 13 7F 61 31 F6 42 0F 8C 03 01 00 00 89 5C 24 04 89 0C 24 DD 04 ED ?? ?? ?? ?? DD 04 24 D8 C1 DD 1C 24 8B 0C 24 8B 5C 24 04 89 4C 24 18 89 5C 24 1C DD 44 24 18 DE E1 B9 13 04 00 00 DD 1C 24 8B 54 24 04 89 D0 89 D6 C1 E8 14 81 E6 FF FF 0F 00 25 FF 07 00 00 81 CE 00 00 10 00 29 C1 D3 EE E9 A5 00 00 00 83 FA 1E 7F 73 89 0C 24 89 5C 24 04 DD 04 ED ?? ?? ?? ?? DD 04 24 D8 C1 DD 1C 24 8B 0C 24 8B 5C 24 04 89 4C 24 18 89 5C 24 1C DD 44 24 18 DE E1 DD 1C 24 8B 54 24 04 8B 04 24 89 }
	condition:
		$pattern
}

rule __ieee754_sqrt_b620f1f9c9cc3cb67c16997b784f045c {
	meta:
		aliases = "__ieee754_sqrt"
		size = "463"
		objfiles = "e_sqrt@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 24 8B 5C 24 3C 8B 4C 24 38 89 D8 C7 44 24 08 00 00 00 00 25 00 00 F0 7F C7 44 24 0C 00 00 00 00 89 DE 89 CF 3D 00 00 F0 7F 75 13 89 0C 24 89 5C 24 04 DD 04 24 D8 C8 DD 04 24 DE C1 EB 25 85 DB 7F 30 89 D8 25 FF FF FF 7F 09 C8 0F 84 66 01 00 00 85 DB 74 1D 89 0C 24 89 5C 24 04 DD 04 24 D8 E0 D8 F0 DD 1C 24 8B 0C 24 8B 5C 24 04 E9 45 01 00 00 89 F3 31 C0 C1 FB 14 74 0D EB 34 89 FE 83 E8 15 C1 EE 0B C1 E7 15 85 F6 74 F1 31 D2 EB 03 01 F6 42 F7 C6 00 00 10 00 74 F5 29 D0 B9 20 00 00 00 29 D1 8D 58 01 89 F8 D3 E8 88 D1 09 C6 D3 E7 89 F2 81 EB FF 03 00 00 81 E2 FF FF 0F 00 89 5C 24 }
	condition:
		$pattern
}

rule pmap_getmaps_48a97799a771ca81ce764e9b2a982920 {
	meta:
		aliases = "pmap_getmaps"
		size = "155"
		objfiles = "pm_getmaps@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 24 8B 6C 24 38 C7 44 24 20 00 00 00 00 C7 44 24 1C FF FF FF FF 66 C7 45 02 00 6F 68 F4 01 00 00 6A 32 8D 44 24 24 50 6A 02 68 A0 86 01 00 55 E8 ?? ?? ?? ?? 83 C4 20 89 C3 85 C0 74 46 8B 50 04 31 FF 8D 44 24 18 BE 3C 00 00 00 57 56 50 68 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 6A 04 53 FF 12 83 C4 20 85 C0 74 10 50 50 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C 8B 43 04 53 FF 50 10 83 C4 10 66 C7 45 02 00 00 8B 44 24 18 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule round_ad17e0e4fa3be322ecdd3a649a4707a9 {
	meta:
		aliases = "__GI_round, round"
		size = "374"
		objfiles = "s_round@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 24 8B 74 24 3C 8B 5C 24 38 89 F0 C7 44 24 10 00 00 00 00 C1 F8 14 C7 44 24 14 00 00 00 00 25 FF 07 00 00 89 F5 89 DF 8D 90 01 FC FF FF 83 FA 13 0F 8F 94 00 00 00 85 D2 79 3B 89 5C 24 08 89 74 24 0C DD 44 24 08 DC 05 ?? ?? ?? ?? D9 EE D9 C9 DA E9 DF E0 9E 0F 86 F1 00 00 00 81 E5 00 00 00 80 31 FF 42 0F 85 E2 00 00 00 81 CD 00 00 F0 3F E9 D7 00 00 00 C7 44 24 04 FF FF 0F 00 88 D1 D3 7C 24 04 8B 44 24 04 21 F0 09 D8 0F 84 CB 00 00 00 89 5C 24 08 89 74 24 0C DD 44 24 08 DC 05 ?? ?? ?? ?? D9 EE D9 C9 DA E9 DF E0 9E 0F 86 9A 00 00 00 B8 00 00 08 00 31 FF D3 F8 01 C5 8B 44 24 04 F7 }
	condition:
		$pattern
}

rule __GI_ceil_a6bb38b8f25d6d0df39f235ed24e672b {
	meta:
		aliases = "ceil, __GI_ceil"
		size = "392"
		objfiles = "s_ceil@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 24 8B 74 24 3C 8B 5C 24 38 89 F0 C7 44 24 10 00 00 00 00 C1 F8 14 C7 44 24 14 00 00 00 00 25 FF 07 00 00 89 F7 89 DD 8D 90 01 FC FF FF 83 FA 13 0F 8F 9A 00 00 00 85 D2 79 42 89 5C 24 08 89 74 24 0C DD 44 24 08 DC 05 ?? ?? ?? ?? D9 EE D9 C9 DA E9 DF E0 9E 0F 86 03 01 00 00 85 F6 79 07 BF 00 00 00 80 EB 0F 89 F1 09 D9 0F 84 EE 00 00 00 BF 00 00 F0 3F 31 ED E9 E2 00 00 00 C7 44 24 04 FF FF 0F 00 88 D1 D3 7C 24 04 8B 44 24 04 21 F0 09 D8 0F 84 D6 00 00 00 89 5C 24 08 89 74 24 0C DD 44 24 08 DC 05 ?? ?? ?? ?? D9 EE D9 C9 DA E9 DF E0 9E 0F 86 A5 00 00 00 85 F6 7E 09 B8 00 00 10 00 }
	condition:
		$pattern
}

rule __GI_floor_ad24955af99a055abbc6d44f0bd18e5d {
	meta:
		aliases = "floor, __GI_floor"
		size = "394"
		objfiles = "s_floor@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 24 8B 74 24 3C 8B 5C 24 38 89 F0 C7 44 24 10 00 00 00 00 C1 F8 14 C7 44 24 14 00 00 00 00 25 FF 07 00 00 89 F7 89 DD 8D 90 01 FC FF FF 83 FA 13 0F 8F 9C 00 00 00 85 D2 79 44 89 5C 24 08 89 74 24 0C DD 44 24 08 DC 05 ?? ?? ?? ?? D9 EE D9 C9 DA E9 DF E0 9E 0F 86 05 01 00 00 85 F6 78 04 31 FF EB 14 89 F0 25 FF FF FF 7F 09 D8 0F 84 EE 00 00 00 BF 00 00 F0 BF 31 ED E9 E2 00 00 00 C7 44 24 04 FF FF 0F 00 88 D1 D3 7C 24 04 8B 44 24 04 21 F0 09 D8 0F 84 D6 00 00 00 89 5C 24 08 89 74 24 0C DD 44 24 08 DC 05 ?? ?? ?? ?? D9 EE D9 C9 DA E9 DF E0 9E 0F 86 A5 00 00 00 85 F6 79 09 B8 00 00 }
	condition:
		$pattern
}

rule __GI_rint_7c927cfed4b8de53d9813752ad0cfb7a {
	meta:
		aliases = "rint, __GI_rint"
		size = "355"
		objfiles = "s_rint@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 24 DD 44 24 38 C7 44 24 10 00 00 00 00 C7 44 24 14 00 00 00 00 DD 1C 24 8B 54 24 04 8B 04 24 89 C7 89 D0 C1 E8 1F 89 D6 89 44 24 1C 89 D0 C1 F8 14 25 FF 07 00 00 8D 90 01 FC FF FF 83 FA 13 0F 8F B7 00 00 00 85 D2 79 79 89 F0 25 FF FF FF 7F 09 F8 0F 84 FA 00 00 00 89 F0 81 E6 00 00 FE FF 25 FF FF 0F 00 89 F1 09 F8 8B 14 24 89 C3 89 54 24 08 F7 DB 09 D8 C1 E8 0C 25 00 00 08 00 09 C1 8B 44 24 1C 89 4C 24 0C DD 04 C5 ?? ?? ?? ?? DD 44 24 08 D8 C1 C1 64 24 1C 1F DE E1 DD 5C 24 08 8B 54 24 0C 8B 44 24 08 89 D1 8B 54 24 1C 81 E1 FF FF FF 7F 89 04 24 09 CA 89 54 24 04 E9 90 00 00 00 }
	condition:
		$pattern
}

rule fork_731ac04a52b6d72e4548e3eb3267b9cc {
	meta:
		aliases = "__fork, fork"
		size = "247"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 28 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 2D ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C7 85 C0 75 7F BE ?? ?? ?? ?? 85 F6 74 5E 83 EC 0C 8D 5C 24 24 53 E8 ?? ?? ?? ?? 58 5A 6A 01 53 E8 ?? ?? ?? ?? 59 58 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 85 F6 74 2B 83 EC 0C 53 E8 ?? ?? ?? ?? 58 5A 6A 00 53 E8 ?? ?? ?? ?? 59 5E 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 E8 E8 ?? ?? ?? ?? EB 28 83 EC 0C }
	condition:
		$pattern
}

rule xdrrec_create_c2a98ca09e9fc02d8002f58f7176bb71 {
	meta:
		aliases = "__GI_xdrrec_create, xdrrec_create"
		size = "283"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 28 8B 44 24 3C 8B 4C 24 48 89 44 24 24 89 4C 24 20 8B 44 24 4C 8B 4C 24 50 8B 74 24 40 8B 7C 24 44 89 44 24 1C 89 4C 24 18 6A 44 E8 ?? ?? ?? ?? 83 C4 10 89 C3 83 FE 63 77 05 BE A0 0F 00 00 8D 6E 03 83 E5 FC 83 FF 63 77 05 BF A0 0F 00 00 83 C7 03 83 EC 0C 83 E7 FC 8D 44 2F 04 50 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 DB 74 04 85 C0 75 2A 57 57 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 89 74 24 40 83 C4 2C 5B 5E 5F 5D E9 ?? ?? ?? ?? 89 6B 3C 89 7B 40 89 43 04 89 C2 A8 03 74 06 83 E0 FC 8D 50 04 8D 04 2A 89 53 0C 89 43 28 8B 4C 24 18 C7 41 04 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule hsearch_r_cb3d42543ffa3b5ef7bf98bb9ea280ec {
	meta:
		aliases = "__GI_hsearch_r, hsearch_r"
		size = "364"
		objfiles = "hsearch_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 28 8B 44 24 3C 8B 54 24 40 89 54 24 20 89 44 24 1C 50 E8 ?? ?? ?? ?? 83 C4 10 89 C1 EB 10 8B 5C 24 10 89 C2 C1 E2 04 0F BE 04 0B 8D 04 02 49 83 F9 FF 75 EA 8B 54 24 40 8B 52 04 89 54 24 08 31 D2 F7 74 24 08 89 D6 85 D2 75 04 66 BE 01 00 6B C6 0C 8B 4C 24 40 8B 09 89 CB 89 4C 24 0C 01 C3 8B 03 85 C0 74 7A 39 F0 75 23 52 52 FF 73 04 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 0E 8D 43 04 8B 5C 24 3C 89 03 E9 A8 00 00 00 8B 54 24 08 89 F0 83 EA 02 89 F3 89 D1 31 D2 F7 F1 8D 6A 01 39 EB 77 04 03 5C 24 08 29 EB 39 F3 74 31 6B C3 0C 8B 7C 24 0C 01 C7 8B 07 89 44 24 18 39 F0 75 15 }
	condition:
		$pattern
}

rule __add_to_environ_500dca5401aa2401decb4d32d7fb0adf {
	meta:
		aliases = "__add_to_environ"
		size = "454"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 28 FF 74 24 3C E8 ?? ?? ?? ?? 83 C4 10 89 C7 C7 44 24 08 00 00 00 00 83 7C 24 34 00 74 14 83 EC 0C FF 74 24 40 E8 ?? ?? ?? ?? 83 C4 10 40 89 44 24 08 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 31 ED 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 83 C4 10 85 F6 74 32 EB 1D 50 57 FF 74 24 38 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 06 80 3C 3B 3D 74 0A 45 83 C6 04 8B 1E 85 DB 75 DD 85 F6 74 09 83 3E 00 0F 85 B8 00 00 00 C1 E5 02 53 53 8D 45 08 50 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 0F 84 F0 00 00 00 83 7C 24 38 00 74 09 8B 44 24 38 89 04 }
	condition:
		$pattern
}

rule scandir_a6f9831bbdc7a5b2490f86340f98f691 {
	meta:
		aliases = "scandir"
		size = "368"
		objfiles = "scandir@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 28 FF 74 24 3C E8 ?? ?? ?? ?? 89 44 24 1C 83 C4 10 83 C8 FF 83 7C 24 0C 00 0F 84 43 01 00 00 E8 ?? ?? ?? ?? 31 ED 89 C6 8B 00 89 44 24 18 C7 06 00 00 00 00 C7 44 24 10 00 00 00 00 C7 44 24 14 00 00 00 00 E9 84 00 00 00 83 7C 24 38 00 74 17 83 EC 0C 57 FF 54 24 48 83 C4 10 85 C0 75 08 C7 06 00 00 00 00 EB 66 C7 06 00 00 00 00 3B 6C 24 14 75 32 C7 44 24 14 0A 00 00 00 85 ED 74 08 8D 54 2D 00 89 54 24 14 51 51 8B 44 24 1C C1 E0 02 50 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 45 89 44 24 10 83 EC 0C 0F B7 5F 08 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 2D 52 53 57 50 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule scandir64_be648353a7b72078f92b816ff027da63 {
	meta:
		aliases = "scandir64"
		size = "368"
		objfiles = "scandir64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 28 FF 74 24 3C E8 ?? ?? ?? ?? 89 44 24 1C 83 C4 10 83 C8 FF 83 7C 24 0C 00 0F 84 43 01 00 00 E8 ?? ?? ?? ?? 31 ED 89 C6 8B 00 89 44 24 18 C7 06 00 00 00 00 C7 44 24 10 00 00 00 00 C7 44 24 14 00 00 00 00 E9 84 00 00 00 83 7C 24 38 00 74 17 83 EC 0C 57 FF 54 24 48 83 C4 10 85 C0 75 08 C7 06 00 00 00 00 EB 66 C7 06 00 00 00 00 3B 6C 24 14 75 32 C7 44 24 14 0A 00 00 00 85 ED 74 08 8D 54 2D 00 89 54 24 14 51 51 8B 44 24 1C C1 E0 02 50 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 45 89 44 24 10 83 EC 0C 0F B7 5F 10 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 2D 52 53 57 50 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __ieee754_log10_eec55039e336830bbccefc0551738031 {
	meta:
		aliases = "__ieee754_log10"
		size = "234"
		objfiles = "e_log10@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 31 C9 8B 7C 24 44 8B 74 24 40 89 FD 81 FF FF FF 0F 00 7F 55 89 F8 25 FF FF FF 7F 09 F0 75 08 D9 05 ?? ?? ?? ?? EB 12 85 FF 79 19 89 74 24 08 89 7C 24 0C DD 44 24 08 D8 E0 DC 35 ?? ?? ?? ?? E9 97 00 00 00 89 74 24 08 89 7C 24 0C DD 44 24 08 D8 0D ?? ?? ?? ?? B9 CA FF FF FF DD 5C 24 08 8B 7C 24 0C 8B 74 24 08 89 FD 81 FD FF FF EF 7F 7E 10 89 74 24 08 89 7C 24 0C DD 44 24 08 D8 C0 EB 5A 89 E8 81 E5 FF FF 0F 00 C1 F8 14 8D 84 01 01 FC FF FF 89 E9 89 C3 C1 EB 1F 01 D8 50 B8 FF 03 00 00 29 D8 DB 04 24 C1 E0 14 83 EC 04 09 C1 51 56 DD 5C 24 20 E8 ?? ?? ?? ?? DD 44 24 20 DD 05 ?? }
	condition:
		$pattern
}

rule remquo_d898589449af2c47a77aaa210c27b611 {
	meta:
		aliases = "__GI_remquo, remquo"
		size = "119"
		objfiles = "s_remquo@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 31 DB DD 44 24 40 8B 7C 24 4C 8B 74 24 48 DD 5C 24 20 89 74 24 18 89 7C 24 1C DD 44 24 18 DC 7C 24 20 8B 54 24 24 89 F8 C1 EA 1F 8B 6C 24 50 C1 E8 1F 39 C2 0F 94 C3 8D 5C 1B FF DD 1C 24 E8 ?? ?? ?? ?? DD 1C 24 E8 ?? ?? ?? ?? 83 E0 7F 0F AF D8 89 5D 00 89 74 24 48 DD 44 24 20 89 7C 24 4C DD 5C 24 40 83 C4 2C 5B 5E 5F 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svctcp_create_caa564b407b4839e01987b0e31ddcadc {
	meta:
		aliases = "svctcp_create"
		size = "364"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 31 ED 8B 74 24 40 C7 44 24 28 10 00 00 00 83 FE FF 75 2B 53 6A 06 6A 01 6A 02 E8 ?? ?? ?? ?? 66 BD 01 00 83 C4 10 89 C6 85 C0 79 12 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 D0 00 00 00 8D 5C 24 18 51 6A 10 6A 00 53 E8 ?? ?? ?? ?? 66 C7 44 24 28 02 00 58 5A 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 16 66 C7 44 24 1A 00 00 50 FF 74 24 2C 53 56 E8 ?? ?? ?? ?? 83 C4 10 57 8D 44 24 2C 50 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 11 53 53 6A 02 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 28 83 EC 0C 31 FF 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 ED 0F 84 A2 00 00 00 83 EC 0C 56 E8 ?? ?? ?? }
	condition:
		$pattern
}

rule svcudp_bufcreate_968b78f4e75b4833245f0007e937895a {
	meta:
		aliases = "__GI_svcudp_bufcreate, svcudp_bufcreate"
		size = "487"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 31 F6 8B 6C 24 40 8B 7C 24 44 C7 44 24 28 10 00 00 00 83 FD FF 75 2B 53 6A 11 6A 02 6A 02 E8 ?? ?? ?? ?? 66 BE 01 00 83 C4 10 89 C5 85 C0 79 12 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 F6 00 00 00 8D 5C 24 14 51 6A 10 6A 00 53 E8 ?? ?? ?? ?? 66 C7 44 24 24 02 00 58 5A 53 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 16 66 C7 44 24 16 00 00 50 FF 74 24 2C 53 55 E8 ?? ?? ?? ?? 83 C4 10 50 8D 44 24 2C 50 53 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 2B 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 F6 C7 44 24 08 00 00 00 00 0F 84 22 01 00 00 83 EC 0C 55 E8 ?? ?? ?? ?? EB 7B 83 EC 0C 68 }
	condition:
		$pattern
}

rule _svcauth_unix_2df354484a93fa6856f626300c18bad2 {
	meta:
		aliases = "_svcauth_unix"
		size = "392"
		objfiles = "svc_authux@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 44 24 40 8B 78 18 8D 47 18 89 47 04 8D 87 18 01 00 00 89 47 14 8B 54 24 44 8B 52 20 89 54 24 08 6A 01 52 8B 4C 24 4C FF 71 1C 8D 5C 24 20 53 E8 ?? ?? ?? ?? 5E 5D FF 74 24 10 53 8B 44 24 28 FF 50 18 83 C4 10 89 C2 85 C0 0F 84 8D 00 00 00 8B 00 0F C8 89 07 8B 72 04 0F CE 81 FE FF 00 00 00 0F 87 F3 00 00 00 8D 5A 08 51 56 53 FF 77 04 8D 6E 03 E8 ?? ?? ?? ?? 83 E5 FC 8B 47 04 83 C4 10 8D 14 2B C6 04 30 00 8B 02 0F C8 89 47 08 8B 42 04 0F C8 89 47 0C 8B 4A 08 0F C9 83 F9 10 0F 87 B5 00 00 00 8D 5A 0C 31 F6 89 4F 10 EB 0E 8B 57 14 8B 03 83 C3 04 0F C8 89 04 B2 46 39 CE 72 EE }
	condition:
		$pattern
}

rule __GI_inet_pton_d5875cc912ccdd00fa8bf0791041c9bf {
	meta:
		aliases = "inet_pton, __GI_inet_pton"
		size = "458"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 44 24 40 8B 7C 24 44 83 F8 02 74 0B 83 F8 0A 0F 85 93 01 00 00 EB 10 8B 54 24 48 89 F8 E8 ?? ?? ?? ?? E9 93 01 00 00 53 6A 10 6A 00 8D 44 24 28 50 E8 ?? ?? ?? ?? 89 C3 8D 40 10 89 44 24 24 83 C4 10 80 3F 3A 75 0A 47 80 3F 3A 0F 85 67 01 00 00 89 7C 24 18 C7 44 24 10 00 00 00 00 EB 79 51 51 56 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 47 83 C4 10 85 C0 74 1B C1 E5 04 2D ?? ?? ?? ?? 09 C5 81 FD FF FF 00 00 0F 86 86 00 00 00 E9 29 01 00 00 83 FE 3A 75 50 83 7C 24 0C 00 75 15 83 7C 24 10 00 0F 85 12 01 00 00 89 5C 24 10 89 7C 24 18 EB 68 80 3F 00 0F 84 FF 00 00 00 8D 53 02 3B 54 24 14 }
	condition:
		$pattern
}

rule authunix_validate_8b69eaf45f9fae36a6852937c2057296 {
	meta:
		aliases = "authunix_validate"
		size = "154"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 44 24 44 8B 6C 24 40 83 38 02 75 79 8B 75 24 6A 01 FF 70 08 FF 70 04 8D 7C 24 20 57 E8 ?? ?? ?? ?? 8B 46 10 83 C4 10 85 C0 74 13 83 EC 0C 50 E8 ?? ?? ?? ?? C7 46 10 00 00 00 00 83 C4 10 8D 5E 0C 50 50 53 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 06 56 6A 0C 53 EB 1E C7 44 24 14 02 00 00 00 51 51 53 57 E8 ?? ?? ?? ?? 83 C4 0C C7 46 10 00 00 00 00 6A 0C 56 55 E8 ?? ?? ?? ?? 83 C4 10 89 E8 E8 ?? ?? ?? ?? 83 C4 2C B8 01 00 00 00 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule bcmp_b4224e76d4efefe15b438c7c9cd081e1 {
	meta:
		aliases = "memcmp, __GI_memcmp, bcmp"
		size = "677"
		objfiles = "memcmp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 4C 24 40 8B 5C 24 44 83 7C 24 48 0F 77 1B E9 79 02 00 00 0F B6 03 0F B6 11 29 C2 89 D0 0F 85 72 02 00 00 FF 4C 24 48 41 43 89 5C 24 04 F6 C3 03 75 E1 89 C8 89 4C 24 08 83 E0 03 0F 85 B4 00 00 00 8B 7C 24 48 C1 EF 02 89 F8 83 E0 03 83 F8 01 74 2F 72 27 83 F8 03 8B 11 8B 03 74 0F 89 D5 83 E9 08 89 C2 83 EB 08 83 C7 02 EB 50 89 C6 83 E9 04 83 EB 04 47 89 54 24 28 EB 2D 8B 01 8B 13 EB 19 8B 01 4F 89 44 24 0C 83 C1 04 8B 33 83 C3 04 8B 01 8B 13 39 74 24 0C 75 4B 8B 71 04 39 D0 89 74 24 28 8B 73 04 75 43 8B 69 08 8B 53 08 39 74 24 28 74 08 89 F2 8B 44 24 28 EB 2F 8B 41 0C 39 }
	condition:
		$pattern
}

rule __GI_trunc_d00518585708bf9dd298fb8b1bbe127c {
	meta:
		aliases = "trunc, __GI_trunc"
		size = "248"
		objfiles = "s_trunc@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 54 24 44 8B 44 24 40 89 D7 C7 44 24 18 00 00 00 00 C1 FF 14 C7 44 24 1C 00 00 00 00 81 E7 FF 07 00 00 C7 44 24 10 00 00 00 00 C7 44 24 14 00 00 00 00 C7 44 24 08 00 00 00 00 8D B7 01 FC FF FF C7 44 24 0C 00 00 00 00 89 D5 89 44 24 24 83 FE 13 7F 45 81 E2 00 00 00 80 85 F6 79 16 89 54 24 1C C7 44 24 18 00 00 00 00 8B 44 24 18 8B 54 24 1C EB 6B B8 FF FF 0F 00 89 F1 D3 F8 F7 D0 21 C5 C7 44 24 10 00 00 00 00 09 EA 8B 44 24 10 89 54 24 14 8B 54 24 14 EB 46 83 FE 33 7E 20 81 FE 00 04 00 00 75 39 89 04 24 89 54 24 04 DD 04 24 D8 C0 DD 1C 24 8B 04 24 8B 54 24 04 EB 21 8D 8F ED }
	condition:
		$pattern
}

rule _stdio_fopen_e146ac16569452bf0ed184e16d4ec643 {
	meta:
		aliases = "_stdio_fopen"
		size = "559"
		objfiles = "_fopen@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 54 24 44 8B 74 24 40 8B 6C 24 48 8B 7C 24 4C 8A 02 3C 72 74 3E BB 41 02 00 00 3C 77 74 37 66 BB 41 04 3C 61 74 2F E8 ?? ?? ?? ?? 85 ED C7 00 16 00 00 00 0F 84 E2 01 00 00 F6 45 01 20 0F 84 D8 01 00 00 83 EC 0C 55 E8 ?? ?? ?? ?? 31 ED E9 C3 01 00 00 31 DB 8D 42 01 80 7A 01 62 74 02 89 D0 80 78 01 2B 75 08 89 D8 83 C8 01 8D 58 01 85 ED 75 32 83 EC 0C 6A 50 E8 ?? ?? ?? ?? 83 C4 10 89 C5 85 C0 0F 84 94 01 00 00 83 EC 0C 66 C7 00 00 20 C7 40 08 00 00 00 00 8D 40 38 50 E8 ?? ?? ?? ?? 83 C4 10 85 FF 78 49 89 DA 8D 46 01 81 E2 03 80 00 00 89 7D 04 42 21 D0 39 D0 0F 85 65 FF FF }
	condition:
		$pattern
}

rule lockf64_d9f0549fbd0754a803bd9fdcfc4e09eb {
	meta:
		aliases = "__GI_lockf64, lockf64"
		size = "270"
		objfiles = "lockf64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 5C 24 48 8B 74 24 4C 89 D8 8B 7C 24 44 99 39 D6 75 04 39 DB 74 10 E8 ?? ?? ?? ?? C7 00 4B 00 00 00 E9 86 00 00 00 8D 6C 24 14 51 6A 18 6A 00 55 E8 ?? ?? ?? ?? 66 C7 44 24 26 01 00 C7 44 24 28 00 00 00 00 C7 44 24 2C 00 00 00 00 89 5C 24 30 89 74 24 34 83 C4 10 83 FF 01 74 5E 7F 06 85 FF 74 4F EB 72 83 FF 02 74 5F 83 FF 03 75 68 66 C7 44 24 14 00 00 52 55 6A 0C FF 74 24 4C E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 70 66 83 7C 24 14 02 74 66 8B 5C 24 28 E8 ?? ?? ?? ?? 39 C3 74 59 E8 ?? ?? ?? ?? C7 00 0D 00 00 00 83 CA FF EB 4B 66 C7 44 24 14 02 00 EB 15 BA 07 00 00 00 66 }
	condition:
		$pattern
}

rule fclose_c178141cbecb9a2b457cf9c42d953825 {
	meta:
		aliases = "__GI_fclose, fclose"
		size = "265"
		objfiles = "fclose@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 74 24 40 8B 6E 34 85 ED 75 1F 8D 5E 38 57 53 68 ?? ?? ?? ?? 8D 44 24 28 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 31 FF F6 06 40 74 0E 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 89 C7 83 EC 0C FF 76 04 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 03 83 CF FF C7 46 04 FF FF FF FF 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 18 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 40 A3 ?? ?? ?? ?? 58 5A 6A 01 53 E8 ?? ?? ?? ?? 83 C4 10 66 81 26 00 60 66 83 0E 30 85 ED 75 11 55 55 6A 01 8D 44 24 28 50 E8 ?? ?? ?? ?? 83 C4 10 F6 46 01 40 74 0E 83 EC 0C FF 76 08 E8 ?? ?? }
	condition:
		$pattern
}

rule freopen64_74556b886e6a88d99e0ed354c1353d64 {
	meta:
		aliases = "freopen64"
		size = "260"
		objfiles = "freopen64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 74 24 48 8B 6E 34 85 ED 75 1F 8D 5E 38 50 53 68 ?? ?? ?? ?? 8D 44 24 28 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 7C 24 18 57 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 5B 40 A3 ?? ?? ?? ?? 58 6A 01 57 E8 ?? ?? ?? ?? 8B 1E 89 D8 83 C4 10 80 E4 9F 66 89 06 0F B7 C0 83 E0 30 83 F8 30 74 3B 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 0C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A 59 6A 01 57 FF 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 6A FE 56 FF 74 24 4C FF 74 24 4C E8 ?? ?? }
	condition:
		$pattern
}

rule freopen_e8cff71dc5114ecf02706cca40c08038 {
	meta:
		aliases = "freopen"
		size = "260"
		objfiles = "freopen@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 74 24 48 8B 6E 34 85 ED 75 1F 8D 5E 38 50 53 68 ?? ?? ?? ?? 8D 44 24 28 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 7C 24 18 57 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 5B 40 A3 ?? ?? ?? ?? 58 6A 01 57 E8 ?? ?? ?? ?? 8B 1E 89 D8 83 C4 10 80 E4 9F 66 89 06 0F B7 C0 83 E0 30 83 F8 30 74 3B 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 0C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A 59 6A 01 57 FF 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 6A FF 56 FF 74 24 4C FF 74 24 4C E8 ?? ?? }
	condition:
		$pattern
}

rule __GI_fseeko64_0661a93203888b2445bf867670b5cee5 {
	meta:
		aliases = "fseeko64, __GI_fseeko64"
		size = "227"
		objfiles = "fseeko64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 7C 24 4C 8B 44 24 44 8B 54 24 48 8B 74 24 40 89 44 24 20 89 54 24 24 83 FF 02 76 13 E8 ?? ?? ?? ?? 83 CB FF C7 00 16 00 00 00 E9 A2 00 00 00 8B 6E 34 85 ED 75 1F 8D 5E 38 50 53 68 ?? ?? ?? ?? 8D 44 24 1C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 F6 06 40 74 10 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 4F 83 FF 01 75 14 51 51 8D 44 24 28 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 36 52 57 8D 44 24 28 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 22 66 83 26 B8 8B 46 08 31 DB 89 46 10 89 46 14 89 46 18 89 46 1C C7 46 2C 00 00 00 00 C6 46 02 00 EB 03 83 CB FF 85 ED 75 11 }
	condition:
		$pattern
}

rule _getopt_internal_77fecce7829363715506d4043a761ddc {
	meta:
		aliases = "_getopt_internal"
		size = "1821"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C A1 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 89 44 24 10 8B 44 24 48 89 15 ?? ?? ?? ?? 8B 74 24 4C 80 38 3A 75 08 C7 44 24 10 00 00 00 00 83 7C 24 40 00 0F 8E AF 06 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 85 D2 74 0B 80 3D ?? ?? ?? ?? 00 75 7C EB 0A C7 05 ?? ?? ?? ?? 01 00 00 00 83 EC 0C A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 E8 ?? ?? ?? ?? 83 C4 10 8B 54 24 48 85 C0 0F 95 05 ?? ?? ?? ?? 8A 02 3C 2D 75 0E 42 C6 05 ?? ?? ?? ?? 02 89 54 24 48 EB 1F 3C 2B 75 0D FF 44 24 48 C6 05 ?? ?? ?? ?? 00 EB 0E 80 3D ?? ?? ?? ?? 00 0F 94 }
	condition:
		$pattern
}

rule llround_89d63973a6272cc6695f35e6a1821e76 {
	meta:
		aliases = "__GI_llround, llround"
		size = "334"
		objfiles = "s_llround@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C DD 44 24 40 DD 5C 24 08 8B 54 24 0C 8B 44 24 08 89 D5 89 C7 C1 ED 14 89 D0 81 E5 FF 07 00 00 81 E2 FF FF 0F 00 C1 F8 1F 81 CA 00 00 10 00 83 C8 01 8D 9D 01 FC FF FF 89 44 24 14 83 FB 13 7F 36 85 DB 79 19 31 F6 31 FF 43 0F 85 EC 00 00 00 89 C1 89 C6 C1 F9 1F 89 CF E9 DE 00 00 00 88 D9 B8 00 00 08 00 D3 F8 B9 14 00 00 00 8D 04 02 29 D9 D3 E8 89 C6 EB 4F 83 FB 3E 7F 73 83 FB 33 7E 29 89 D1 31 DB 89 CB B9 00 00 00 00 89 C8 8D 8D CD FB FF FF 09 F8 89 DF 89 C6 0F A5 F7 D3 E6 F6 C1 20 74 76 89 F7 31 F6 EB 70 8D 8D ED FB FF FF B8 00 00 00 80 D3 E8 8D 34 07 39 FE 83 D2 00 83 FB 14 }
	condition:
		$pattern
}

rule __ieee754_yn_e8efab04bf84c52afeaf6a88eb5946ad {
	meta:
		aliases = "__ieee754_yn"
		size = "660"
		objfiles = "e_jn@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C DD 44 24 44 8B 6C 24 40 DD 54 24 08 8B 44 24 08 8B 54 24 0C 89 D6 89 C2 F7 D8 09 D0 89 F1 C1 E8 1F 81 E1 FF FF FF 7F 09 C8 3D 00 00 F0 7F 76 04 D8 C0 EB 12 DD D8 09 CA 75 1B D9 05 ?? ?? ?? ?? DC 35 ?? ?? ?? ?? DD 1C 24 8B 34 24 8B 7C 24 04 E9 26 02 00 00 85 F6 79 12 31 F6 31 FF 89 34 24 89 7C 24 04 DD 04 24 D8 F0 EB DB C7 44 24 14 01 00 00 00 85 ED 79 0D F7 DD 89 E8 83 E0 01 01 C0 29 44 24 14 85 ED 75 14 DD 44 24 08 DD 5C 24 40 83 C4 2C 5B 5E 5F 5D E9 ?? ?? ?? ?? 83 FD 01 75 29 50 50 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? DB 44 24 24 DE C9 DD 5C 24 10 8B 74 24 10 8B 7C 24 }
	condition:
		$pattern
}

rule __ieee754_atan2_68eca3ed94659656662c1bf3eb097103 {
	meta:
		aliases = "__ieee754_atan2"
		size = "662"
		objfiles = "e_atan2@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C DD 44 24 48 8B 4C 24 40 8B 5C 24 44 DD 5C 24 10 8B 54 24 14 8B 44 24 10 89 C5 89 D0 25 FF FF FF 7F 89 54 24 1C 89 44 24 24 89 E8 F7 D8 09 E8 89 DF C1 E8 1F 89 CA 0B 44 24 24 3D 00 00 F0 7F 77 1C 89 C8 81 E7 FF FF FF 7F F7 D8 09 C8 89 5C 24 20 C1 E8 1F 09 F8 3D 00 00 F0 7F 76 15 89 4C 24 08 89 5C 24 0C DD 44 24 08 DC 44 24 10 E9 FD 01 00 00 8B 44 24 1C 2D 00 00 F0 3F 09 E8 75 14 89 5C 24 44 89 4C 24 40 83 C4 2C 5B 5E 5F 5D E9 ?? ?? ?? ?? 8B 44 24 1C 8B 74 24 20 C1 F8 1E C1 EE 1F 83 E0 02 09 C6 09 FA 75 18 83 FE 02 0F 84 A3 00 00 00 0F 8E C2 01 00 00 83 FE 03 0F 84 A3 00 00 }
	condition:
		$pattern
}

rule __ieee754_remainder_20b1620014ae79f297ff2e8ef47914e7 {
	meta:
		aliases = "__ieee754_remainder"
		size = "402"
		objfiles = "e_remainder@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C DD 44 24 48 8B 74 24 40 8B 7C 24 44 DD 5C 24 10 8B 54 24 14 8B 44 24 10 89 D5 89 44 24 24 81 E5 FF FF FF 7F 89 FB 89 74 24 20 09 E8 74 26 81 E3 FF FF FF 7F 89 7C 24 1C 81 FB FF FF EF 7F 7F 14 81 FD FF FF EF 7F 7E 23 8D 85 00 00 10 80 0B 44 24 24 74 17 89 74 24 08 89 7C 24 0C DD 44 24 08 DC 4C 24 10 D8 F0 E9 18 01 00 00 81 FD FF FF DF 7F 7F 22 DD 44 24 10 D8 C0 83 EC 08 DD 1C 24 57 56 E8 ?? ?? ?? ?? DD 5C 24 18 8B 74 24 18 8B 7C 24 1C 83 C4 10 8B 44 24 24 29 EB 29 44 24 20 0B 5C 24 20 75 17 89 74 24 08 89 7C 24 0C DD 44 24 08 DC 0D ?? ?? ?? ?? E9 C7 00 00 00 51 51 57 56 E8 }
	condition:
		$pattern
}

rule __GI_mallinfo_a941f2defc7f612859dd6a37406d03e6 {
	meta:
		aliases = "mallinfo, __GI_mallinfo"
		size = "314"
		objfiles = "mallinfo@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 30 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 28 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 3D ?? ?? ?? ?? 00 75 10 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 A1 ?? ?? ?? ?? 31 C9 8B 40 04 C7 44 24 0C 00 00 00 00 89 44 24 08 C7 44 24 14 00 00 00 00 EB 1F 8B 14 8D ?? ?? ?? ?? EB 11 FF 44 24 14 8B 42 04 83 E0 FC 01 44 24 0C 8B 52 08 85 D2 75 EB 41 83 F9 09 76 DC 8B 44 24 08 8B 54 24 0C 83 E0 FC BB 01 00 00 00 C7 44 24 10 01 00 00 00 8D 2C 10 EB 20 8D 0C DD ?? ?? ?? ?? 8B 51 0C EB 0F FF 44 24 10 8B 42 04 8B 52 0C 83 E0 FC 01 C5 39 CA 75 ED 43 83 FB 5F 76 }
	condition:
		$pattern
}

rule __res_search_502bb5f3274c589e4fb04e022a13edd3 {
	meta:
		aliases = "__res_search"
		size = "719"
		objfiles = "res_query@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 30 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 7C 24 28 57 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5B 5D 6A 01 57 8B 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 7C 24 40 00 74 14 83 7C 24 4C 00 74 0D 83 E6 01 75 18 E8 ?? ?? ?? ?? 40 75 10 E8 ?? ?? ?? ?? C7 00 FF FF FF FF E9 5F 02 00 00 E8 ?? ?? ?? ?? 89 44 24 04 C7 00 00 00 00 00 E8 ?? ?? ?? ?? 89 C5 C7 00 01 00 00 00 C7 44 24 0C 00 00 00 00 8B 54 24 40 EB 0D 3C 2E 0F 94 C0 0F B6 C0 01 44 24 0C 42 8A 02 84 C0 75 ED C7 44 24 10 00 00 00 00 3B 54 24 40 76 0D 31 C0 80 7A FF 2E 0F 94 C0 89 44 24 10 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule rtime_3a8c7e313f23f2c8b4de30e67cdffd96 {
	meta:
		aliases = "__GI_rtime, rtime"
		size = "351"
		objfiles = "rtime@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 30 8B 6C 24 4C 8B 7C 24 44 83 FD 01 6A 00 19 DB 83 C3 02 53 6A 02 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 0F 88 26 01 00 00 66 C7 07 02 00 66 C7 47 02 00 25 83 FB 02 0F 85 A8 00 00 00 50 50 6A 10 57 6A 00 6A 04 8D 44 24 40 50 56 E8 ?? ?? ?? ?? 83 C4 20 85 C0 0F 88 9A 00 00 00 69 4D 00 E8 03 00 00 BA E8 03 00 00 8B 45 04 89 D3 31 D2 F7 F3 89 74 24 1C 66 C7 44 24 20 01 00 8D 3C 01 55 57 6A 01 8D 44 24 28 50 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 79 0A E8 ?? ?? ?? ?? 83 38 04 74 DF 83 FB 00 7F 0F 75 4F E8 ?? ?? ?? ?? C7 00 6E 00 00 00 EB 42 8D 54 24 0C C7 44 24 24 10 00 00 00 53 53 8D }
	condition:
		$pattern
}

rule llrint_d908fd95bd2999d664d58145c46d1df9 {
	meta:
		aliases = "__GI_llrint, llrint"
		size = "440"
		objfiles = "s_llrint@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 34 8B 5C 24 4C 8B 4C 24 48 89 DD 89 DF C1 ED 14 89 DE 81 E5 FF 07 00 00 89 CA C1 EF 1F 8D 85 01 FC FF FF 89 7C 24 0C 83 F8 13 7F 67 89 5C 24 04 89 0C 24 DD 04 FD ?? ?? ?? ?? DD 04 24 D8 C1 31 F6 31 FF DD 1C 24 8B 0C 24 8B 5C 24 04 89 4C 24 28 89 5C 24 2C DD 44 24 28 DE E1 DD 1C 24 8B 54 24 04 89 D0 C1 E8 14 25 FF 07 00 00 2D FF 03 00 00 0F 88 21 01 00 00 81 E2 FF FF 0F 00 B9 14 00 00 00 81 CA 00 00 10 00 29 C1 D3 EA 89 D6 E9 A9 00 00 00 83 F8 3E 0F 8F CB 00 00 00 83 F8 33 7E 3C 81 E6 FF FF 0F 00 31 DB 81 CE 00 00 10 00 89 F1 89 CB B9 00 00 00 00 89 C8 89 DF 09 D0 8D 8D CD FB }
	condition:
		$pattern
}

rule inet_ntop4_4583ae5aa498ff44f76282c8f974c21d {
	meta:
		aliases = "inet_ntop4"
		size = "264"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C 31 ED FC 89 44 24 14 66 A1 ?? ?? ?? ?? 66 89 44 24 2B 8D 7C 24 2D 31 C0 89 54 24 10 89 4C 24 0C 31 DB AB AB AB 66 AB AA E9 8A 00 00 00 8B 44 24 14 B1 64 01 E8 8D 73 01 89 44 24 18 89 DF 66 0F B6 10 89 D0 F6 F1 88 C1 8D 41 30 88 44 1C 2B 3C 30 75 24 B1 0A 89 D0 F6 F1 31 D2 B9 0A 00 00 00 66 0F B6 C0 66 F7 F1 83 C2 30 88 54 1C 2B 80 FA 30 74 22 89 F7 EB 1E B1 0A 89 D0 F6 F1 66 0F B6 C0 B9 0A 00 00 00 31 D2 66 F7 F1 83 C2 30 8D 7B 02 88 54 34 2B 8B 54 24 18 B9 0A 00 00 00 8D 5F 02 45 66 0F B6 02 31 D2 C6 44 3C 2C 2E 66 F7 F1 83 C2 30 88 54 3C 2B 83 FD 03 0F 8E 6D FF FF FF C6 }
	condition:
		$pattern
}

rule tcsetattr_1b68f8d0b19c0afe29992cf581c326dc {
	meta:
		aliases = "__GI_tcsetattr, tcsetattr"
		size = "258"
		objfiles = "tcsetattr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C 8B 44 24 54 8B 7C 24 58 83 F8 01 74 10 83 F8 02 74 22 BE 02 54 00 00 85 C0 74 1E EB 07 BE 03 54 00 00 EB 15 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 B6 00 00 00 BE 04 54 00 00 8B 07 25 FF FF FF 7F 89 44 24 18 8B 47 04 89 44 24 1C 8B 47 08 89 44 24 20 8B 47 0C 89 44 24 24 8A 47 10 88 44 24 28 8D 47 11 52 6A 13 50 8D 44 24 35 50 E8 ?? ?? ?? ?? 83 C4 0C 8D 44 24 1C 50 56 FF 74 24 5C E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 75 65 81 FE 02 54 00 00 75 5D E8 ?? ?? ?? ?? 89 C6 8B 28 50 8D 44 24 1C 50 68 01 54 00 00 FF 74 24 5C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 04 89 2E EB 35 8B 4F 08 8B 5C }
	condition:
		$pattern
}

rule clnttcp_call_486e2d6daa9012f230e54066ad753c8a {
	meta:
		aliases = "clnttcp_call"
		size = "590"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C 8B 4C 24 50 8B 44 24 68 8B 54 24 6C 8B 59 08 8D 4B 30 8D 73 4C 89 0C 24 83 7B 10 00 75 06 89 53 0C 89 43 08 83 7C 24 60 00 75 3E 83 7B 08 00 75 38 31 C0 83 7B 0C 00 0F 95 C0 89 44 24 04 EB 31 B8 03 00 00 00 C7 43 24 03 00 00 00 E9 EE 01 00 00 31 C0 E9 E7 01 00 00 B8 05 00 00 00 C7 43 24 05 00 00 00 E9 D6 01 00 00 C7 44 24 04 01 00 00 00 C7 44 24 08 02 00 00 00 C7 06 00 00 00 00 C7 43 24 00 00 00 00 8B 04 24 8D 53 30 FF 08 8B 38 55 8B 46 04 FF 73 48 0F CF 52 56 FF 50 0C 83 C4 10 85 C0 74 3E 8D 44 24 54 51 51 8B 56 04 50 56 FF 52 04 83 C4 10 85 C0 74 29 8B 54 24 50 8B 02 52 }
	condition:
		$pattern
}

rule clntunix_call_30d81654bcde0c58b9526feefbafecbe {
	meta:
		aliases = "clntunix_call"
		size = "644"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C 8B 4C 24 50 8B 44 24 68 8B 54 24 6C 8B 59 08 8D 8B 90 00 00 00 8D B3 AC 00 00 00 89 0C 24 83 7B 10 00 75 06 89 53 0C 89 43 08 83 7C 24 60 00 75 44 83 7B 08 00 75 3E 31 C0 83 7B 0C 00 0F 95 C0 89 44 24 04 EB 37 B8 03 00 00 00 C7 83 84 00 00 00 03 00 00 00 E9 1B 02 00 00 31 C0 E9 14 02 00 00 B8 05 00 00 00 C7 83 84 00 00 00 05 00 00 00 E9 00 02 00 00 C7 44 24 04 01 00 00 00 C7 44 24 08 02 00 00 00 C7 06 00 00 00 00 C7 83 84 00 00 00 00 00 00 00 8B 04 24 8D 93 90 00 00 00 FF 08 8B 38 55 8B 46 04 FF B3 A8 00 00 00 0F CF 52 56 FF 50 0C 83 C4 10 85 C0 74 3E 8D 44 24 54 51 51 8B }
	condition:
		$pattern
}

rule __ieee754_rem_pio2_dc087f506f6f8abae0e86825f0c0da9b {
	meta:
		aliases = "__ieee754_rem_pio2"
		size = "757"
		objfiles = "e_rem_pio2@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C 8B 5C 24 54 8B 4C 24 50 89 DE 8B 7C 24 58 81 E6 FF FF FF 7F 89 DD 81 FE FB 21 E9 3F 7F 18 89 0F 89 5F 04 C7 47 08 00 00 00 00 C7 47 0C 00 00 00 00 E9 F5 01 00 00 81 FE 7B D9 02 40 0F 8F 9E 00 00 00 85 DB DD 05 ?? ?? ?? ?? 7E 4B 89 4C 24 08 89 5C 24 0C DD 44 24 08 DE E1 81 FE FB 21 F9 3F 74 10 DD 05 ?? ?? ?? ?? D9 C1 D8 E1 DD 1F DD 07 EB 14 DD 05 ?? ?? ?? ?? DE E9 DD 05 ?? ?? ?? ?? D9 C1 D8 E1 DD 17 DE EA DE E9 DD 5F 08 BB 01 00 00 00 E9 4D 02 00 00 89 4C 24 08 89 5C 24 0C DD 44 24 08 DE C1 81 FE FB 21 F9 3F 74 10 DD 05 ?? ?? ?? ?? D9 C1 D8 C1 DD 1F DD 07 EB 14 DD 05 ?? ?? }
	condition:
		$pattern
}

rule __ieee754_hypot_0989f5764fa7f68b6fb05407a533215b {
	meta:
		aliases = "__ieee754_hypot"
		size = "801"
		objfiles = "e_hypot@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C 8B 7C 24 54 8B 5C 24 5C 89 FD 8B 74 24 50 81 E5 FF FF FF 7F 8B 4C 24 58 89 6C 24 34 89 DD 81 E5 FF FF FF 7F 3B 6C 24 34 7E 14 89 E8 8B 6C 24 34 89 4C 24 28 89 5C 24 2C 89 44 24 34 EB 0A 89 74 24 28 89 7C 24 2C 89 CE DD 44 24 28 8B 44 24 34 89 74 24 18 DD 5C 24 20 89 6C 24 1C 89 44 24 24 29 E8 8B 4C 24 20 8B 5C 24 24 8B 74 24 18 8B 7C 24 1C 3D 00 00 C0 03 7E 1F 89 4C 24 10 89 5C 24 14 DD 44 24 10 89 74 24 10 89 7C 24 14 DD 44 24 10 DE C1 E9 7A 02 00 00 C7 44 24 30 00 00 00 00 81 7C 24 34 00 00 30 5F 0F 8E 87 00 00 00 81 7C 24 34 FF FF EF 7F 7E 53 81 64 24 34 FF FF 0F 00 8B }
	condition:
		$pattern
}

rule nextafter_6f4dc7105d7e170c18a8f7c32117be38 {
	meta:
		aliases = "__GI_nextafter, nextafter"
		size = "477"
		objfiles = "s_nextafter@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C 8B 7C 24 58 8B 5C 24 54 89 7C 24 20 8B 4C 24 50 8B 44 24 20 8B 6C 24 5C 89 44 24 34 89 D8 25 FF FF FF 7F C7 44 24 18 00 00 00 00 C7 44 24 1C 00 00 00 00 C7 44 24 10 00 00 00 00 C7 44 24 14 00 00 00 00 C7 44 24 08 00 00 00 00 C7 44 24 0C 00 00 00 00 89 DE 89 CA 89 6C 24 24 89 44 24 30 3D FF FF EF 7F 7E 09 2D 00 00 F0 7F 09 C8 75 1F 8B 44 24 24 89 44 24 2C 25 FF FF FF 7F 3D FF FF EF 7F 7E 26 2D 00 00 F0 7F 0B 44 24 34 74 1B 89 0C 24 89 5C 24 04 DD 04 24 89 3C 24 89 6C 24 04 DD 04 24 DE C1 E9 C7 00 00 00 89 0C 24 89 5C 24 04 DD 04 24 89 3C 24 89 6C 24 04 DD 04 24 D9 C9 DA E9 }
	condition:
		$pattern
}

rule __wcstofpmax_fac032948db5c504f20defba96b687a4 {
	meta:
		aliases = "__wcstofpmax"
		size = "528"
		objfiles = "__wcstofpmax@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C 8B 7C 24 58 8B 74 24 50 EB 03 83 C6 04 83 EC 0C FF 36 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 EC 8B 06 83 F8 2B 74 0D 31 ED 83 F8 2D 75 0B 66 BD 01 00 EB 02 31 ED 83 C6 04 D9 EE A1 ?? ?? ?? ?? 31 C9 83 CA FF 89 44 24 2C D9 05 ?? ?? ?? ?? EB 29 81 FA 00 00 00 80 83 DA FF 85 D2 75 05 83 F8 30 74 14 42 83 FA 15 7F 0E DC C9 83 E8 30 50 DB 04 24 DE C2 83 C4 04 83 C6 04 8B 06 8B 5C 24 2C F6 04 43 08 75 CB 83 F8 2E 75 0B 85 C9 75 07 83 C6 04 89 F1 EB E4 DD D8 85 D2 79 6C 85 C9 75 5F 31 DB 31 FF EB 30 47 80 BC 1F ?? ?? ?? ?? 00 75 25 DD D8 53 DB 04 24 DC 35 ?? ?? ?? ?? 83 C4 04 85 ED 74 }
	condition:
		$pattern
}

rule writeunix_ccf4ff3028ac6676b6b981b1406e3724 {
	meta:
		aliases = "writeunix"
		size = "241"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C 8B 7C 24 58 8B 74 24 54 89 FB E9 C9 00 00 00 8B 44 24 50 8B 28 E8 ?? ?? ?? ?? 89 44 24 28 E8 ?? ?? ?? ?? 89 44 24 2C E8 ?? ?? ?? ?? 89 44 24 30 50 6A 0C 8D 44 24 30 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 44 24 44 89 74 24 44 89 5C 24 48 89 44 24 24 C7 44 24 28 01 00 00 00 C7 44 24 1C 00 00 00 00 C7 44 24 20 00 00 00 00 C7 44 24 2C ?? ?? ?? ?? C7 44 24 30 18 00 00 00 C7 44 24 34 00 00 00 00 C7 05 ?? ?? ?? ?? 01 00 00 00 C7 05 ?? ?? ?? ?? 02 00 00 00 C7 05 ?? ?? ?? ?? 18 00 00 00 83 C4 10 50 6A 00 8D 44 24 14 50 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 1C E8 ?? ?? ?? ?? 83 38 04 74 }
	condition:
		$pattern
}

rule __strtofpmax_0191943f49ad931dc38a21d9a77b8a78 {
	meta:
		aliases = "__strtofpmax"
		size = "541"
		objfiles = "__strtofpmax@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C A1 ?? ?? ?? ?? 8B 7C 24 58 8B 74 24 50 89 44 24 2C EB 01 46 0F BE 06 8B 54 24 2C F6 04 42 20 75 F2 83 F8 2B 74 17 C7 44 24 0C 00 00 00 00 83 F8 2D 75 13 C7 44 24 0C 01 00 00 00 EB 08 C7 44 24 0C 00 00 00 00 46 D9 EE 31 DB 83 C9 FF D9 05 ?? ?? ?? ?? EB 2B 81 F9 00 00 00 80 83 D9 FF 85 C9 75 05 80 FA 30 74 18 41 83 F9 15 7F 12 8B 44 24 1C DC C9 83 E8 30 50 DB 04 24 DE C2 83 C4 04 46 8A 16 8B 44 24 2C 0F BE EA 89 6C 24 1C F6 04 68 08 75 C2 80 FA 2E 75 09 85 DB 75 05 46 89 F3 EB DF DD D8 85 C9 79 6E 85 DB 75 61 31 FF EB 33 47 80 BC 1F ?? ?? ?? ?? 00 75 28 DD D8 53 DB 04 24 DC }
	condition:
		$pattern
}

rule readunix_e71d5be20e13c7f2b30096b1614c7922 {
	meta:
		aliases = "readunix"
		size = "359"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C BA E8 03 00 00 89 D3 8B 74 24 50 8B 6C 24 58 69 4E 08 E8 03 00 00 8B 46 0C 99 F7 FB 66 31 DB 85 ED 8D 3C 01 0F 84 2C 01 00 00 8B 06 66 C7 44 24 34 01 00 89 44 24 30 50 57 6A 01 8D 44 24 3C 50 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 74 10 85 C0 75 30 C7 86 84 00 00 00 05 00 00 00 EB 1C E8 ?? ?? ?? ?? 83 38 04 74 D0 C7 86 84 00 00 00 04 00 00 00 8B 00 89 86 88 00 00 00 83 CB FF E9 D5 00 00 00 8B 44 24 54 8B 3E 89 44 24 28 8D 44 24 28 89 44 24 14 89 6C 24 2C C7 44 24 18 01 00 00 00 C7 44 24 0C 00 00 00 00 C7 44 24 10 00 00 00 00 C7 44 24 1C ?? ?? ?? ?? C7 44 24 20 18 00 00 00 C7 44 }
	condition:
		$pattern
}

rule __time_localtime_tzi_7a318c941c1bce0f20a5603cd22dc980 {
	meta:
		aliases = "__time_localtime_tzi"
		size = "717"
		objfiles = "_time_localtime_tzi@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C C7 44 24 0C 00 00 00 00 6B 44 24 0C 18 8B 4C 24 50 8B 5C 24 58 01 C3 B8 80 3A 09 00 8B 11 B9 F9 FF FF FF 2B 03 81 FA 7F C5 F6 7F 7E 07 F7 D8 B9 07 00 00 00 8D 04 02 89 44 24 38 56 FF 74 24 58 51 8D 44 24 44 50 E8 ?? ?? ?? ?? 8B 74 24 64 8B 7C 24 1C 83 C4 10 89 7E 20 8D 7B 10 8B 03 BB ?? ?? ?? ?? F7 D8 89 46 24 EB 15 8D 73 04 51 51 57 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 4B 8B 1B 85 DB 75 E7 52 52 6A 07 57 E8 ?? ?? ?? ?? 83 C4 10 83 F8 06 77 37 83 EC 0C 6A 0C E8 ?? ?? ?? ?? 83 C4 10 89 C2 85 C0 74 24 A1 ?? ?? ?? ?? 8D 5A 04 89 02 89 15 ?? ?? ?? ?? 50 50 57 53 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __ieee754_fmod_6f3ba00bb3455a2e598a5195fbe5f8f7 {
	meta:
		aliases = "__ieee754_fmod"
		size = "849"
		objfiles = "e_fmod@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C DD 44 24 58 8B 7C 24 54 8B 74 24 50 DD 54 24 10 89 FA C7 44 24 20 00 00 00 00 DD 1C 24 8B 0C 24 8B 5C 24 04 89 4C 24 34 89 F9 81 E1 00 00 00 80 81 E3 FF FF FF 7F 8B 44 24 34 81 E2 FF FF FF 7F C7 44 24 24 00 00 00 00 C7 44 24 18 00 00 00 00 C7 44 24 1C 00 00 00 00 89 F5 89 4C 24 30 09 D8 74 1E 81 FA FF FF EF 7F 7F 16 8B 44 24 34 F7 D8 0B 44 24 34 C1 E8 1F 09 D8 3D 00 00 F0 7F 76 23 89 74 24 08 89 7C 24 0C DD 44 24 08 DC 4C 24 10 D8 F0 DD 5C 24 08 8B 74 24 08 8B 7C 24 0C E9 93 02 00 00 39 DA 7F 16 0F 8C 89 02 00 00 3B 74 24 34 0F 82 7F 02 00 00 0F 84 41 02 00 00 81 FA FF FF }
	condition:
		$pattern
}

rule clntraw_create_eb1fb0a5cc26dd472395d2a75471bf5c {
	meta:
		aliases = "clntraw_create"
		size = "234"
		objfiles = "clnt_raw@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C E8 ?? ?? ?? ?? 89 C3 8B A8 A0 00 00 00 89 EF 85 ED 75 23 50 50 68 A0 22 00 00 6A 01 E8 ?? ?? ?? ?? 31 F6 83 C4 10 89 C7 85 C0 0F 84 A9 00 00 00 89 83 A0 00 00 00 8B 44 24 50 8D 5D 0C 89 44 24 18 8B 44 24 54 89 44 24 1C 8D 87 84 22 00 00 C7 44 24 10 00 00 00 00 C7 44 24 14 02 00 00 00 6A 00 6A 18 50 53 E8 ?? ?? ?? ?? 5E 58 8D 44 24 14 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 10 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C 8B 43 04 53 FF 50 10 89 87 9C 22 00 00 83 C4 10 8B 43 04 8B 40 1C 85 C0 74 09 83 EC 0C 53 FF D0 83 C4 10 8D 47 24 6A 02 68 60 22 00 00 50 53 E8 }
	condition:
		$pattern
}

rule do_des_124b871f721cc745931c40b91a71fc85 {
	meta:
		aliases = "do_des"
		size = "839"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 40 89 D5 BA 01 00 00 00 89 0C 24 83 7C 24 58 00 0F 84 21 03 00 00 7E 12 C7 44 24 34 ?? ?? ?? ?? C7 44 24 38 ?? ?? ?? ?? EB 14 F7 5C 24 58 C7 44 24 34 ?? ?? ?? ?? C7 44 24 38 ?? ?? ?? ?? 89 C2 89 C1 0F B6 DC C1 EA 18 25 FF 00 00 00 89 EE 89 54 24 04 89 5C 24 08 89 44 24 0C C1 EE 18 89 E8 C1 E9 10 89 EA 81 E5 FF 00 00 00 81 E1 FF 00 00 00 89 6C 24 10 8B 6C 24 08 8B 1C B5 ?? ?? ?? ?? 0B 1C AD ?? ?? ?? ?? 8B 6C 24 04 0F B6 FC C1 EA 10 8B 04 8D ?? ?? ?? ?? 0B 04 AD ?? ?? ?? ?? 8B 6C 24 0C 81 E2 FF 00 00 00 0B 04 AD ?? ?? ?? ?? 8B 6C 24 10 0B 04 95 ?? ?? ?? ?? 0B 1C BD ?? ?? ?? ?? }
	condition:
		$pattern
}

rule malloc_91634fe9811716a0f5c5deff3695a8f4 {
	meta:
		aliases = "malloc"
		size = "1908"
		objfiles = "malloc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 40 8B 5C 24 54 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 38 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 FB DF 76 12 E8 ?? ?? ?? ?? 31 DB C7 00 0C 00 00 00 E9 25 07 00 00 8D 43 0B C7 44 24 14 10 00 00 00 83 F8 0F 76 07 83 E0 F8 89 44 24 14 8B 1D ?? ?? ?? ?? F6 C3 01 75 1D 85 DB 0F 85 F0 02 00 00 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 E9 DB 02 00 00 39 5C 24 14 77 1B 8B 44 24 14 D1 E8 8D 88 ?? ?? ?? ?? 8B 51 FC 85 D2 74 08 8B 42 08 89 41 FC EB 39 81 7C 24 14 FF 00 00 00 77 37 8B 44 24 14 C1 E8 03 89 44 24 24 8D 0C C5 ?? ?? ?? ?? 8B 51 0C 39 CA 0F 84 }
	condition:
		$pattern
}

rule modf_e6ea9d780c7b7dd1998e032447c3d3da {
	meta:
		aliases = "__GI_modf, modf"
		size = "429"
		objfiles = "s_modf@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 44 8B 74 24 5C 8B 5C 24 58 89 F0 C7 44 24 30 00 00 00 00 C1 F8 14 C7 44 24 34 00 00 00 00 25 FF 07 00 00 C7 44 24 28 00 00 00 00 C7 44 24 2C 00 00 00 00 C7 44 24 20 00 00 00 00 8D 88 01 FC FF FF C7 44 24 24 00 00 00 00 C7 44 24 18 00 00 00 00 C7 44 24 1C 00 00 00 00 C7 44 24 10 00 00 00 00 C7 44 24 14 00 00 00 00 C7 44 24 08 00 00 00 00 C7 44 24 0C 00 00 00 00 89 74 24 38 89 5C 24 3C 83 F9 13 7F 7D 85 C9 79 22 89 F0 C7 44 24 30 00 00 00 00 25 00 00 00 80 8B 4C 24 60 89 44 24 34 DD 44 24 30 DD 19 E9 E9 00 00 00 BA FF FF 0F 00 8B 44 24 38 D3 FA 21 D0 0B 44 24 3C 75 2A 8B 44 24 }
	condition:
		$pattern
}

rule __GI_clntunix_create_212f9f72cf3927b02d1ac6d1bcb11c78 {
	meta:
		aliases = "clntunix_create, __GI_clntunix_create"
		size = "480"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 48 8B 5C 24 5C 8B 6C 24 68 68 C4 00 00 00 E8 ?? ?? ?? ?? C7 04 24 0C 00 00 00 89 C6 E8 ?? ?? ?? ?? 83 C4 10 89 C7 85 C0 74 04 85 F6 75 2B E8 ?? ?? ?? ?? 89 C3 50 50 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 03 0C 00 00 00 C7 43 08 0C 00 00 00 E9 FF 00 00 00 83 7D 00 00 79 6C 50 6A 00 6A 01 6A 01 E8 ?? ?? ?? ?? 89 45 00 8D 43 02 89 04 24 E8 ?? ?? ?? ?? 8B 55 00 83 C4 10 85 D2 78 13 83 C0 03 51 50 53 52 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 2C E8 ?? ?? ?? ?? 89 C3 C7 00 0C 00 00 00 E8 ?? ?? ?? ?? 8B 00 89 43 08 8B 45 00 83 F8 FF 0F 84 01 01 00 00 83 EC 0C 50 E9 91 00 00 00 }
	condition:
		$pattern
}

rule clnttcp_create_51cb3fdd9591d7d59059662a7c59ea91 {
	meta:
		aliases = "__GI_clnttcp_create, clnttcp_create"
		size = "501"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 48 8B 5C 24 5C 8B 6C 24 68 6A 0C E8 ?? ?? ?? ?? C7 04 24 64 00 00 00 89 C7 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 FF 74 04 85 C0 75 2B E8 ?? ?? ?? ?? 89 C3 50 50 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 03 0C 00 00 00 C7 43 08 0C 00 00 00 E9 20 01 00 00 66 83 7B 02 00 75 24 6A 06 FF 74 24 5C FF 74 24 5C 53 E8 ?? ?? ?? ?? 83 C4 10 66 85 C0 0F 84 56 01 00 00 66 C1 C8 08 66 89 43 02 83 7D 00 00 79 68 50 6A 06 6A 01 6A 02 E8 ?? ?? ?? ?? 89 45 00 5A 59 6A 00 50 E8 ?? ?? ?? ?? 8B 45 00 83 C4 10 85 C0 78 11 51 6A 10 53 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 2B E8 ?? ?? ?? ?? 89 C3 }
	condition:
		$pattern
}

rule regexec_fa28edf829b8e02a3a678407a4735d13 {
	meta:
		aliases = "__regexec, regexec"
		size = "276"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 48 8B 74 24 5C 8B 5C 24 6C 8B 6C 24 64 FF 74 24 60 E8 ?? ?? ?? ?? 83 C4 10 89 44 24 08 8A 46 1C 83 F0 10 C0 E8 04 85 ED 0F 95 C2 89 D7 21 C7 8D 44 24 10 52 6A 20 56 50 E8 ?? ?? ?? ?? 88 DA 8A 44 24 3C 83 E2 01 D1 EB 83 E0 9F C1 E2 05 83 E3 01 C1 E3 06 09 D0 09 D8 89 FA 83 E0 F9 83 C8 04 88 44 24 3C 83 C4 10 31 C0 84 D2 74 2F 89 6C 24 30 83 EC 0C 8D 04 ED 00 00 00 00 50 E8 ?? ?? ?? ?? 83 C4 10 BA 01 00 00 00 85 C0 74 77 89 44 24 34 8D 04 A8 89 44 24 38 8D 44 24 30 56 56 50 FF 74 24 14 6A 00 FF 74 24 1C FF 74 24 6C 8D 44 24 2C 50 E8 ?? ?? ?? ?? 89 C6 89 F8 83 C4 20 84 C0 74 3D }
	condition:
		$pattern
}

rule authunix_refresh_8e9244ca03147060e1a8195c2d8f214b {
	meta:
		aliases = "authunix_refresh"
		size = "227"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C 31 ED 8B 7C 24 60 8B 5F 24 8B 47 04 3B 43 04 0F 84 BD 00 00 00 FF 43 18 C7 44 24 30 00 00 00 00 C7 44 24 40 00 00 00 00 6A 01 FF 73 08 FF 73 04 8D 74 24 20 56 E8 ?? ?? ?? ?? 58 5A 8D 44 24 34 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 54 50 50 6A 00 8D 44 24 50 50 E8 ?? ?? ?? ?? 8B 44 24 54 C7 44 24 24 00 00 00 00 89 44 24 3C 59 5D 6A 00 56 8B 44 24 28 FF 50 14 58 5A 8D 44 24 34 50 56 E8 ?? ?? ?? ?? 83 C4 10 89 C5 85 C0 74 14 50 6A 0C 53 57 E8 ?? ?? ?? ?? 89 F8 E8 ?? ?? ?? ?? 83 C4 10 C7 44 24 14 02 00 00 00 50 50 8D 44 24 34 50 8D 5C 24 20 53 E8 ?? ?? ?? ?? 8B 44 24 28 83 C4 }
	condition:
		$pattern
}

rule __ivaliduser2_f19c90b2ef68568861acdbf530c100bf {
	meta:
		aliases = "__ivaliduser2"
		size = "737"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C 89 44 24 10 89 54 24 0C 89 4C 24 08 C7 44 24 48 00 00 00 00 C7 44 24 44 00 00 00 00 E9 81 02 00 00 8B 54 24 48 8B 44 24 44 C6 44 02 FF 00 8B 5C 24 48 89 DE EB 01 46 8A 0E 84 C9 0F 84 61 02 00 00 0F BE D1 A1 ?? ?? ?? ?? F6 04 50 20 75 E7 80 F9 23 0F 84 4A 02 00 00 57 57 6A 0A 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 47 8B 54 24 10 8B 42 10 3B 42 18 73 0D 0F B6 10 8B 4C 24 10 40 89 41 10 EB 11 83 EC 0C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 89 C2 83 FA 0A 0F 84 06 02 00 00 42 75 CA E9 FE 01 00 00 A1 ?? ?? ?? ?? 0F BF 04 08 88 03 43 8A 13 84 D2 74 11 0F BE C2 8D 0C 00 A1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule strerror_r_cff65ef553823e1a5abd20aee7fa9291 {
	meta:
		aliases = "__GI___xpg_strerror_r, __xpg_strerror_r, strerror_r"
		size = "183"
		objfiles = "__xpg_strerror_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C 8B 44 24 60 8B 7C 24 68 83 F8 7C 77 1B 89 C1 BE ?? ?? ?? ?? EB 07 80 3E 01 83 D9 00 46 85 C9 75 F5 31 ED 80 3E 00 75 2F 83 EC 0C BD 16 00 00 00 99 6A 00 6A F6 52 50 8D 44 24 67 50 E8 ?? ?? ?? ?? 83 C4 1C 8D 70 F2 6A 0E 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 10 31 C0 83 7C 24 64 00 0F 95 C0 83 EC 0C F7 D8 21 C7 56 E8 ?? ?? ?? ?? 83 C4 10 8D 58 01 39 FB 76 07 89 FB BD 22 00 00 00 85 DB 74 18 50 53 56 FF 74 24 70 E8 ?? ?? ?? ?? 8B 44 24 74 83 C4 10 C6 44 18 FF 00 85 ED 74 07 E8 ?? ?? ?? ?? 89 28 83 C4 4C 89 E8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_gethostbyname_r_677d15dda5101358d5f663c13a108889 {
	meta:
		aliases = "gethostbyname_r, __GI_gethostbyname_r"
		size = "818"
		objfiles = "gethostbyname_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C 8B 44 24 70 8B 6C 24 68 8B 5C 24 6C C7 00 00 00 00 00 B8 16 00 00 00 83 7C 24 60 00 0F 84 01 03 00 00 E8 ?? ?? ?? ?? 89 C6 8B 38 C7 00 00 00 00 00 50 FF 74 24 78 FF 74 24 78 53 55 FF 74 24 78 6A 02 FF 74 24 7C E8 ?? ?? ?? ?? 83 C4 20 85 C0 0F 84 CD 02 00 00 8B 4C 24 74 8B 11 83 FA 01 74 15 83 FA 04 74 10 42 0F 85 B6 02 00 00 83 3E 02 0F 85 AD 02 00 00 89 E8 89 3E F7 D8 83 E0 03 74 0C 39 C3 0F 82 95 02 00 00 01 C5 29 C3 8B 44 24 74 83 FB 03 C7 00 FF FF FF FF 0F 86 7E 02 00 00 8D 43 FC 83 F8 07 0F 86 72 02 00 00 8D 55 04 8D 43 F4 89 14 24 83 F8 1F 89 6D 04 C7 42 04 00 00 00 }
	condition:
		$pattern
}

rule __res_query_426c246664fe80e78ab4980b4ac06ec4 {
	meta:
		aliases = "__GI___res_query, __res_query"
		size = "244"
		objfiles = "res_query@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C 8B 6C 24 60 C7 44 24 48 00 00 00 00 85 ED 74 07 83 7C 24 64 01 74 0D E8 ?? ?? ?? ?? C7 00 03 00 00 00 EB 76 51 6A 28 6A 00 8D 7C 24 1C 57 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 44 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 5A 6A 01 8B 35 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 5A 59 57 8D 44 24 54 50 68 ?? ?? ?? ?? 56 FF B4 24 80 00 00 00 55 E8 ?? ?? ?? ?? 83 C4 20 89 C3 85 C0 79 10 E8 ?? ?? ?? ?? C7 00 02 00 00 00 83 CB FF EB 44 83 EC 0C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 8B 44 24 68 39 44 24 14 75 1C 3B 5C 24 70 7E 04 8B 5C 24 }
	condition:
		$pattern
}

rule __ieee754_asin_b1da6709392c943cfdd607ff6c2738d0 {
	meta:
		aliases = "__ieee754_asin"
		size = "609"
		objfiles = "e_asin@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C 8B 74 24 64 8B 5C 24 60 89 F7 89 F5 81 E7 FF FF FF 7F 81 FF FF FF EF 3F 7E 4C 8D 8F 00 00 10 C0 09 D9 75 21 89 5C 24 08 89 74 24 0C DD 44 24 08 DC 0D ?? ?? ?? ?? DD 44 24 08 DC 0D ?? ?? ?? ?? E9 C0 00 00 00 89 5C 24 08 89 74 24 0C DD 44 24 08 D8 E0 D8 F0 DD 5C 24 08 8B 5C 24 08 8B 74 24 0C E9 E0 01 00 00 81 FF FF FF DF 3F 0F 8F 9A 00 00 00 81 FF FF FF 3F 3E D9 E8 7F 1F 89 5C 24 08 89 74 24 0C DD 44 24 08 DC 05 ?? ?? ?? ?? DA E9 DF E0 9E 0F 87 AD 01 00 00 EB 71 89 5C 24 08 89 74 24 0C DD 44 24 08 D8 C8 DD 05 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 }
	condition:
		$pattern
}

rule getaddrinfo_f4291827f00ff8711b43d51d6b7569d3 {
	meta:
		aliases = "__GI_getaddrinfo, getaddrinfo"
		size = "652"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C 8B 74 24 64 8B 7C 24 68 C7 44 24 48 00 00 00 00 83 7C 24 60 00 74 19 8B 44 24 60 80 38 2A 75 10 80 78 01 00 0F 95 C0 0F B6 C0 F7 D8 21 44 24 60 85 F6 74 12 80 3E 2A 75 0D 31 C0 80 7E 01 00 0F 95 C0 F7 D8 21 C6 8B 54 24 60 09 F2 0F 84 21 02 00 00 85 FF 75 14 57 6A 20 6A 00 8D 5C 24 28 53 89 DF E8 ?? ?? ?? ?? 83 C4 10 8B 07 A9 C0 FB FF FF 0F 85 03 02 00 00 A8 02 74 0B 83 7C 24 60 00 0F 84 F4 01 00 00 85 F6 74 67 80 3E 00 74 62 89 74 24 3C 53 6A 0A 8D 44 24 4C 50 56 E8 ?? ?? ?? ?? 89 44 24 50 83 C4 10 8B 44 24 44 80 38 00 74 21 8B 07 25 00 04 00 00 85 C0 0F 85 B3 01 00 00 8D }
	condition:
		$pattern
}

rule clntraw_call_7e971bd00a66aced505a346e75cd8f6c {
	meta:
		aliases = "clntraw_call"
		size = "420"
		objfiles = "clnt_raw@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C BE 10 00 00 00 E8 ?? ?? ?? ?? 8B B8 A0 00 00 00 85 FF 8D 5F 0C 0F 84 78 01 00 00 C7 03 00 00 00 00 56 56 8B 43 04 6A 00 53 FF 50 14 8D 87 84 22 00 00 FF 00 83 C4 0C 8B 53 04 FF B7 9C 22 00 00 50 53 FF 52 0C 83 C4 10 85 C0 0F 84 3E 01 00 00 8D 44 24 64 51 51 8B 53 04 50 53 FF 52 04 83 C4 10 85 C0 0F 84 25 01 00 00 8B 54 24 60 8B 02 52 52 8B 50 20 53 50 FF 52 04 83 C4 10 85 C0 0F 84 0A 01 00 00 55 55 FF 74 24 74 53 FF 54 24 78 83 C4 10 85 C0 0F 84 F4 00 00 00 83 EC 0C 8B 43 04 53 FF 50 10 C7 04 24 01 00 00 00 E8 ?? ?? ?? ?? C7 03 01 00 00 00 8B 43 04 59 5E 6A 00 53 8D 6C 24 }
	condition:
		$pattern
}

rule _dl_map_cache_912e38b2e752d69ea596f4cacf3dbc91 {
	meta:
		aliases = "_dl_map_cache"
		size = "501"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 50 83 C8 FF 8B 15 ?? ?? ?? ?? 83 FA FF 0F 84 D4 01 00 00 85 D2 0F 85 CA 01 00 00 BE ?? ?? ?? ?? 8D 4C 24 0C 89 F0 53 89 C3 B8 6A 00 00 00 CD 80 5B 89 C3 89 C1 3D 00 F0 FF FF 76 0D F7 D9 89 0D ?? ?? ?? ?? E9 8D 01 00 00 85 C0 0F 85 85 01 00 00 31 D2 53 89 F3 B8 05 00 00 00 CD 80 5B 89 C5 89 C7 3D 00 F0 FF FF 76 0D F7 DF 89 3D ?? ?? ?? ?? E9 60 01 00 00 85 C0 0F 88 58 01 00 00 8B 4C 24 20 BE 01 00 00 00 89 0D ?? ?? ?? ?? C7 44 24 4C 00 00 00 00 89 D8 89 F2 53 89 C3 55 8B 6C 24 4C B8 C0 00 00 00 CD 80 5D 5B 89 C1 3D 00 F0 FF FF 76 0B F7 D9 89 0D ?? ?? ?? ?? 83 C9 FF 89 0D ?? ?? }
	condition:
		$pattern
}

rule __GI_clntudp_bufcreate_d08d97ee591fec1c3edf3ee2b158a541 {
	meta:
		aliases = "clntudp_bufcreate, __GI_clntudp_bufcreate"
		size = "568"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 58 6A 0C E8 ?? ?? ?? ?? 8B BC 24 88 00 00 00 8B 9C 24 8C 00 00 00 83 C7 03 83 C3 03 83 E7 FC 83 E3 FC 89 C5 8D 44 1F 64 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 ED 74 04 85 C0 75 2E E8 ?? ?? ?? ?? 51 51 FF 35 ?? ?? ?? ?? 89 C3 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 C7 03 0C 00 00 00 C7 43 08 0C 00 00 00 E9 9B 01 00 00 8D 44 18 60 89 46 58 8B 44 24 60 66 83 78 02 00 75 28 6A 11 FF 74 24 6C FF 74 24 6C 50 E8 ?? ?? ?? ?? 83 C4 10 66 85 C0 0F 84 6D 01 00 00 8B 54 24 60 66 C1 C8 08 66 89 42 02 C7 45 04 ?? ?? ?? ?? 89 75 08 52 6A 10 FF 74 24 68 8D 46 08 50 E8 ?? ?? ?? ?? 8B 54 24 }
	condition:
		$pattern
}

rule vwarn_work_b3bd893e8dcadde38829ed482019f9c6 {
	meta:
		aliases = "vwarn_work"
		size = "199"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 5C 89 C7 89 D5 BB ?? ?? ?? ?? 85 C9 74 1C E8 ?? ?? ?? ?? BB ?? ?? ?? ?? 51 6A 40 8D 54 24 14 52 FF 30 E8 ?? ?? ?? ?? 83 C4 10 A1 ?? ?? ?? ?? 8B 70 34 85 F6 75 27 83 C0 38 52 50 68 ?? ?? ?? ?? 8D 44 24 58 50 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C0 38 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 50 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 FF 74 14 51 55 57 83 EB 02 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 52 8D 44 24 10 50 53 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 F6 75 11 50 50 6A 01 8D 44 24 58 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 5C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_inet_ntop_ee5f50aef5acef97648031ca2b64b2ed {
	meta:
		aliases = "inet_ntop, __GI_inet_ntop"
		size = "462"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 5C 8B 44 24 70 83 F8 02 74 0B 83 F8 0A 0F 85 9E 01 00 00 EB 18 8B 54 24 78 8B 4C 24 7C 8B 44 24 74 E8 ?? ?? ?? ?? 89 C2 E9 91 01 00 00 50 6A 20 6A 00 8D 44 24 48 50 E8 ?? ?? ?? ?? 31 C9 83 C4 10 EB 27 89 C8 BA 02 00 00 00 89 D6 99 F7 FE 8B 54 24 74 89 C3 0F B6 04 0A 0F B6 54 0A 01 C1 E0 08 83 C1 02 09 D0 89 44 9C 3C 83 F9 0F 7E D4 31 D2 83 CF FF 83 C8 FF EB 2E 83 7C 94 3C 00 75 11 83 F8 FF 75 09 89 D0 BB 01 00 00 00 EB 18 43 EB 15 83 F8 FF 74 10 83 FF FF 74 04 39 EB 7E 04 89 DD 89 C7 83 C8 FF 42 83 FA 07 7E CD 83 F8 FF 74 0D 83 FF FF 74 04 39 EB 7E 04 89 DD 89 C7 83 FF FF 74 }
	condition:
		$pattern
}

rule _ppfs_parsespec_778afdfa6ad276f41e338ceafd6e5473 {
	meta:
		aliases = "_ppfs_parsespec"
		size = "966"
		objfiles = "_ppfs_parsespec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 5C 8B 44 24 70 C7 44 24 44 00 00 00 00 C7 44 24 48 00 00 00 00 C7 44 24 50 08 00 00 00 C7 44 24 54 08 00 00 00 8B 54 24 70 8B 40 18 89 44 24 14 8B 7A 10 81 E7 80 00 00 00 75 11 8B 12 EB 46 89 DD E9 89 01 00 00 46 E9 98 01 00 00 31 F6 8B 44 24 70 8D 0C B5 00 00 00 00 8B 10 8B 44 0A FC 88 44 34 24 88 C3 0F BE C0 3B 44 0A FC 0F 85 43 03 00 00 84 DB 74 06 46 83 FE 1F 76 D2 C6 44 24 43 00 8D 54 24 25 C7 44 24 0C 00 00 00 00 C7 44 24 10 00 00 00 00 EB 02 89 F2 89 D6 80 3A 2A 75 10 6B 44 24 10 FC 8D 72 01 C7 44 04 50 00 00 00 00 31 DB 8B 2D ?? ?? ?? ?? EB 10 81 FB FE 0F 00 00 7F 07 }
	condition:
		$pattern
}

rule gethostbyname2_r_1d8fa76cf50b5dd72ce511f05558984b {
	meta:
		aliases = "__GI_gethostbyname2_r, gethostbyname2_r"
		size = "815"
		objfiles = "gethostbyname2_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 5C 8B 44 24 74 8B 6C 24 78 8B B4 24 80 00 00 00 83 F8 02 75 2D 50 50 FF B4 24 90 00 00 00 FF B4 24 90 00 00 00 56 FF B4 24 90 00 00 00 55 FF B4 24 8C 00 00 00 E8 ?? ?? ?? ?? 83 C4 20 E9 DF 02 00 00 83 F8 0A 0F 85 A4 02 00 00 E8 ?? ?? ?? ?? 8B 84 24 84 00 00 00 C7 00 00 00 00 00 83 7C 24 70 00 0F 84 87 02 00 00 E8 ?? ?? ?? ?? 89 C3 8B 38 C7 00 00 00 00 00 50 FF B4 24 8C 00 00 00 FF B4 24 8C 00 00 00 56 FF B4 24 8C 00 00 00 55 6A 0A FF B4 24 8C 00 00 00 E8 ?? ?? ?? ?? 83 C4 20 85 C0 0F 84 79 02 00 00 8B 8C 24 88 00 00 00 8B 11 83 FA 01 74 0E 83 FA 04 74 21 42 0F 85 5F 02 00 00 }
	condition:
		$pattern
}

rule __ieee754_jn_95741633db466b8af55880bc44d4a0ae {
	meta:
		aliases = "__ieee754_jn"
		size = "963"
		objfiles = "e_jn@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 5C 8B 4C 24 74 8B 5C 24 78 89 C8 89 DE F7 D8 09 C8 81 E6 FF FF FF 7F C1 E8 1F 8B 7C 24 70 09 F0 89 DD 89 CA 3D 00 00 F0 7F 76 13 89 4C 24 08 89 5C 24 0C DD 44 24 08 D8 C0 E9 77 03 00 00 85 FF 79 0E F7 DF 81 F3 00 00 00 80 81 ED 00 00 00 80 85 FF 75 14 89 5C 24 74 89 4C 24 70 83 C4 5C 5B 5E 5F 5D E9 ?? ?? ?? ?? 83 FF 01 75 14 89 5C 24 74 89 4C 24 70 83 C4 5C 5B 5E 5F 5D E9 ?? ?? ?? ?? 09 F2 0F 84 21 03 00 00 81 FE FF FF EF 7F 0F 8F 15 03 00 00 50 50 53 51 E8 ?? ?? ?? ?? 83 C4 10 DD 5C 24 48 57 DB 04 24 83 C4 04 DD 54 24 28 DD 44 24 48 DA E9 DF E0 9E 0F 82 49 01 00 00 81 FE FF }
	condition:
		$pattern
}

rule __GI_erfc_c835ed489d471a9b160229a6b675eee1 {
	meta:
		aliases = "erfc, __GI_erfc"
		size = "943"
		objfiles = "s_erf@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 5C 8B 5C 24 74 8B 4C 24 70 89 DE 89 5C 24 4C 81 E6 FF FF FF 7F 81 FE FF FF EF 7F 7E 2C C1 6C 24 4C 1F 8B 44 24 4C 31 D2 01 C0 52 50 DF 2C 24 83 C4 08 89 4C 24 08 89 5C 24 0C DD 44 24 08 DC 3D ?? ?? ?? ?? E9 6D 01 00 00 81 FE FF FF EA 3F 0F 8F BB 00 00 00 81 FE FF FF 6F 3C D9 E8 7F 11 89 4C 24 08 89 5C 24 0C DD 44 24 08 E9 1C 03 00 00 89 4C 24 08 89 5C 24 0C DD 44 24 08 D8 C8 81 7C 24 4C FF FF CF 3F DD 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? DD 05 ?? ?? ?? ?? D8 CA DC 05 ?? ?? ?? ?? D8 CA DC 05 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule erf_b61cb2b11cbeb6ef29b589ac1caff735 {
	meta:
		aliases = "__GI_erf, erf"
		size = "916"
		objfiles = "s_erf@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 5C 8B 5C 24 74 8B 4C 24 70 89 DE 89 5C 24 4C 81 E6 FF FF FF 7F 81 FE FF FF EF 7F 7E 30 C1 6C 24 4C 1F 8B 44 24 4C BA 01 00 00 00 01 C0 29 C2 52 DB 04 24 83 C4 04 89 4C 24 08 89 5C 24 0C DD 44 24 08 DC 3D ?? ?? ?? ?? E9 68 01 00 00 81 FE FF FF EA 3F 0F 8F C7 00 00 00 81 FE FF FF 2F 3E 7F 4E 81 FE FF FF 7F 00 7F 2B D9 05 ?? ?? ?? ?? 89 4C 24 08 89 5C 24 0C DD 44 24 08 DC C9 DC 0D ?? ?? ?? ?? DD 54 24 08 DE C1 D8 0D ?? ?? ?? ?? E9 F2 02 00 00 89 4C 24 08 89 5C 24 0C DD 44 24 08 DC 0D ?? ?? ?? ?? DD 44 24 08 E9 06 01 00 00 89 4C 24 08 89 5C 24 0C DD 44 24 08 D8 C8 DD 05 ?? ?? ?? }
	condition:
		$pattern
}

rule timer_create_ebc13f47c17c63cde7e4aaec778be04c {
	meta:
		aliases = "timer_create"
		size = "158"
		objfiles = "timer_create@librt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 5C 8B 6C 24 74 85 ED 75 14 C7 44 24 20 00 00 00 00 C7 44 24 1C 0E 00 00 00 8D 6C 24 18 83 7D 08 02 74 68 83 EC 0C 6A 08 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 74 55 89 44 24 18 8D 54 24 58 8B 7C 24 70 89 E9 53 89 FB B8 03 01 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 83 FB FF 74 14 8B 45 08 89 06 8B 44 24 58 89 46 04 8B 44 24 78 89 30 EB 11 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 EB 03 83 CB FF 83 C4 5C 89 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _wstdio_fwrite_dc60a1672c3970604852e100761539e3 {
	meta:
		aliases = "_wstdio_fwrite"
		size = "234"
		objfiles = "_wfwrite@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 5C 8B 6C 24 78 8B 7C 24 74 83 7D 04 FD 75 39 8B 55 10 8B 45 0C 29 D0 89 FB C1 F8 02 39 C7 76 02 89 C3 85 DB 0F 84 B0 00 00 00 51 53 FF 74 24 78 52 E8 ?? ?? ?? ?? 8D 04 9D 00 00 00 00 83 C4 10 01 45 10 E9 92 00 00 00 0F B7 45 00 25 40 08 00 00 3D 40 08 00 00 74 18 52 52 68 00 08 00 00 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 04 31 FF EB 6A 8B 44 24 70 31 F6 89 44 24 58 EB 58 83 EC 0C 8D 45 2C 50 89 F8 29 F0 6A 40 50 8D 44 24 70 50 8D 54 24 34 52 E8 ?? ?? ?? ?? 83 C4 20 89 C3 83 F8 FF 74 35 85 C0 75 0E 8B 54 24 70 B3 01 8D 44 B2 04 89 44 24 58 50 55 53 8D 44 24 24 50 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule gethostbyaddr_r_adf34e7a725b689e1e369ba90e1a04d7 {
	meta:
		aliases = "__GI_gethostbyaddr_r, gethostbyaddr_r"
		size = "884"
		objfiles = "gethostbyaddr_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 5C 8B 84 24 88 00 00 00 8B 74 24 70 8B AC 24 80 00 00 00 8B 9C 24 84 00 00 00 85 F6 C7 00 00 00 00 00 0F 84 0C 03 00 00 8D 44 24 20 57 6A 28 6A 00 50 E8 ?? ?? ?? ?? 83 C4 10 83 7C 24 78 02 74 0D 83 7C 24 78 0A 0F 85 E8 02 00 00 EB 07 83 7C 24 74 04 EB 05 83 7C 24 74 10 0F 85 D4 02 00 00 FF B4 24 8C 00 00 00 FF B4 24 8C 00 00 00 53 55 FF B4 24 8C 00 00 00 FF B4 24 8C 00 00 00 FF B4 24 8C 00 00 00 56 E8 ?? ?? ?? ?? 83 C4 20 85 C0 0F 84 D0 02 00 00 8B 8C 24 8C 00 00 00 8B 11 83 FA 01 74 09 83 FA 04 0F 85 B9 02 00 00 E8 ?? ?? ?? ?? 8B 84 24 8C 00 00 00 83 FB 03 C7 00 FF FF FF FF }
	condition:
		$pattern
}

rule __GI_strftime_7f1f776ce962d433bcddbef5ed89c9e5 {
	meta:
		aliases = "strftime, __GI_strftime"
		size = "1284"
		objfiles = "strftime@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 64 6A 00 FF B4 24 88 00 00 00 E8 ?? ?? ?? ?? 3D FF 4E 98 45 0F 9E C0 0F B6 C0 89 04 24 E8 ?? ?? ?? ?? 8B 84 24 84 00 00 00 8B 8C 24 88 00 00 00 89 44 24 2C C7 44 24 34 00 00 00 00 83 C4 10 83 7C 24 1C 00 0F 84 AA 04 00 00 8A 01 84 C0 75 29 83 7C 24 24 00 75 14 8B 54 24 70 C6 02 00 8B 44 24 74 2B 44 24 1C E9 8B 04 00 00 FF 4C 24 24 8B 5C 24 24 8B 4C 9C 34 EB C6 3C 25 74 06 89 4C 24 18 EB 0E 8D 71 01 89 74 24 18 8A 41 01 3C 25 75 0F 89 CE C7 44 24 20 01 00 00 00 E9 1B 04 00 00 3C 4F 74 10 3C 45 74 10 B3 3F C7 44 24 20 02 00 00 00 EB 17 B0 40 EB 02 B0 80 FF 44 24 18 88 C3 83 CB }
	condition:
		$pattern
}

rule vsnprintf_3b199a4b134209c1367307bff2850f0e {
	meta:
		aliases = "__GI_vsnprintf, vsnprintf"
		size = "178"
		objfiles = "vsnprintf@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 68 8B 74 24 7C 8D 44 24 50 89 F3 8B BC 24 80 00 00 00 C7 44 24 1C FE FF FF FF 66 C7 44 24 18 D0 00 C6 44 24 1A 00 C7 44 24 44 00 00 00 00 C7 44 24 4C 01 00 00 00 8D 6C 24 18 F7 D3 50 E8 ?? ?? ?? ?? C7 44 24 3C 00 00 00 00 83 C4 10 39 FB 76 02 89 FB 8D 04 1E 89 74 24 14 89 44 24 18 89 44 24 28 89 74 24 1C 89 74 24 20 89 74 24 24 50 FF B4 24 80 00 00 00 FF B4 24 80 00 00 00 55 E8 ?? ?? ?? ?? 83 C4 10 89 C2 85 DB 74 16 8B 44 24 18 39 44 24 1C 75 05 48 89 44 24 1C 8B 44 24 1C C6 00 00 83 C4 5C 89 D0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule strptime_ae140a3b2bca89cd001ac953e9a222c2 {
	meta:
		aliases = "__GI_strptime, strptime"
		size = "953"
		objfiles = "strptime@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 6C 31 C0 8B AC 24 80 00 00 00 C7 44 84 20 00 00 00 80 40 83 F8 0C 7E F2 8B BC 24 84 00 00 00 C7 44 24 08 00 00 00 00 8A 07 84 C0 75 48 83 7C 24 08 00 75 33 83 7C 24 38 07 75 08 C7 44 24 38 00 00 00 00 31 D2 8B 44 94 20 3D 00 00 00 80 74 0A 8B 8C 24 88 00 00 00 89 04 91 42 83 FA 07 7E E5 89 E8 E9 44 03 00 00 FF 4C 24 08 8B 5C 24 08 8B 7C 9C 54 EB B2 3C 25 0F 85 00 03 00 00 47 8A 07 3C 25 0F 84 F5 02 00 00 3C 4F 74 08 B1 3F 3C 45 75 0E EB 04 B0 40 EB 02 B0 80 88 C1 47 83 C9 3F 8A 17 84 D2 0F 84 FF 02 00 00 88 D0 83 C8 20 83 E8 61 3C 19 0F 87 EF 02 00 00 0F BE C2 8A 90 ?? ?? ?? }
	condition:
		$pattern
}

rule __ieee754_lgamma_r_c44bf37a90c801b4add8a76869bcab7a {
	meta:
		aliases = "__ieee754_lgamma_r"
		size = "1734"
		objfiles = "e_lgamma_r@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 6C 8B 8C 24 88 00 00 00 8B B4 24 84 00 00 00 8B 9C 24 80 00 00 00 89 74 24 50 C7 01 01 00 00 00 89 D8 8B 6C 24 50 81 E5 FF FF FF 7F 81 FD FF FF EF 7F 7E 13 89 5C 24 08 89 74 24 0C DD 44 24 08 D8 C8 E9 71 06 00 00 89 5C 24 54 09 E8 74 53 81 FD FF FF 8F 3B 7F 31 83 7C 24 50 00 79 17 8B 8C 24 88 00 00 00 81 F6 00 00 00 80 C7 01 FF FF FF FF 55 55 EB 02 57 57 56 53 E8 ?? ?? ?? ?? 83 C4 10 D9 E0 E9 30 06 00 00 83 7C 24 50 00 78 0B D9 EE DD 5C 24 48 E9 03 02 00 00 81 FD FF FF 2F 43 7E 07 D9 EE E9 97 01 00 00 89 F7 81 E7 FF FF FF 7F 81 FF FF FF CF 3F 7F 32 83 EC 0C 6A 00 6A 00 6A 00 }
	condition:
		$pattern
}

rule __GI_cbrt_a380d2537fd622bf17ed594969934d50 {
	meta:
		aliases = "cbrt, __GI_cbrt"
		size = "369"
		objfiles = "s_cbrt@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 6C 8B 9C 24 84 00 00 00 8B 8C 24 80 00 00 00 89 5C 24 4C 89 4C 24 48 8B 44 24 4C 8B 74 24 4C 25 00 00 00 80 81 E6 FF FF FF 7F 89 44 24 54 81 FE FF FF EF 7F 7E 1B 89 0C 24 89 5C 24 04 DD 04 24 D8 C0 DD 1C 24 8B 0C 24 8B 5C 24 04 E9 08 01 00 00 89 4C 24 40 89 5C 24 44 8B 44 24 40 09 F0 0F 84 F4 00 00 00 89 4C 24 38 89 74 24 3C DD 44 24 38 81 FE FF FF 0F 00 7F 3D D9 EE B9 03 00 00 00 31 D2 DD 5C 24 30 C7 44 24 34 00 00 50 43 DD 44 24 30 D8 C9 DD 54 24 60 8B 74 24 64 89 F0 F7 F1 89 C1 DD 5C 24 28 81 C1 93 78 7F 29 89 4C 24 2C DD 44 24 28 EB 20 89 F0 B9 03 00 00 00 99 D9 EE F7 F9 }
	condition:
		$pattern
}

rule initshells_ac7592a96b6586d559949bcfe35cd733 {
	meta:
		aliases = "initshells"
		size = "320"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 6C E8 ?? ?? ?? ?? 50 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C7 B8 ?? ?? ?? ?? 85 FF 0F 84 09 01 00 00 83 EC 0C 57 E8 ?? ?? ?? ?? 5E 5D 8D 54 24 1C 52 50 E8 ?? ?? ?? ?? 83 C4 10 40 0F 84 D3 00 00 00 83 EC 0C 8B 44 24 4C 40 50 E8 ?? ?? ?? ?? 83 C4 10 A3 ?? ?? ?? ?? 85 C0 0F 84 B5 00 00 00 BA 03 00 00 00 53 53 6A 04 8B 44 24 4C 89 D1 31 D2 F7 F1 50 E8 ?? ?? ?? ?? 83 C4 10 A3 ?? ?? ?? ?? 85 C0 0F 84 8C 00 00 00 51 51 6A 02 57 E8 ?? ?? ?? ?? 8B 6C 24 50 8B 35 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 83 C4 10 EB 3B 43 8A 03 3C 23 74 34 3C 2F 74 06 84 C0 75 F1 EB 2A 84 C0 }
	condition:
		$pattern
}

rule __md5_Transform_c7785f7d0957b565d556f7bf5ddf1df6 {
	meta:
		aliases = "__md5_Transform"
		size = "318"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 70 89 C5 6A 40 52 8D 44 24 38 50 E8 ?? ?? ?? ?? 8B 45 00 8D 4D 04 89 44 24 38 89 4C 24 1C 8D 45 08 8B 7D 04 8D 4D 0C 89 44 24 20 8B 75 08 89 4C 24 24 8B 5D 0C 8B 4C 24 38 C7 44 24 28 ?? ?? ?? ?? C7 44 24 2C ?? ?? ?? ?? C7 44 24 30 ?? ?? ?? ?? C7 44 24 34 00 00 00 00 83 C4 10 E9 9A 00 00 00 F6 44 24 24 0F 75 05 83 44 24 18 04 8B 44 24 24 C1 F8 04 83 F8 01 74 22 7F 06 85 C0 74 10 EB 0A 83 F8 02 74 26 83 F8 03 74 29 89 CA EB 30 89 F8 89 FA F7 D0 21 F2 21 D8 EB 0A 89 D8 89 FA F7 D0 21 DA 21 F0 09 C2 8D 14 11 EB 13 89 F8 31 F0 31 D8 EB 08 89 D8 F7 D0 09 F8 31 F0 8D 14 01 8B 4C 24 }
	condition:
		$pattern
}

rule iruserfopen_979412321dc04a6b890b878c91dc5c09 {
	meta:
		aliases = "iruserfopen"
		size = "148"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 74 89 C6 89 D5 31 DB 8D 7C 24 1C 57 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 6B 8B 44 24 24 25 00 F0 00 00 3D 00 80 00 00 75 5B 53 53 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 74 45 83 EC 0C 50 E8 ?? ?? ?? ?? 5A 59 57 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 1A 8B 44 24 2C 85 C0 74 04 39 E8 75 0E F6 44 24 24 12 75 07 83 7C 24 28 01 76 12 85 DB 74 0E 83 EC 0C 53 31 DB E8 ?? ?? ?? ?? 83 C4 10 83 C4 6C 89 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _time_mktime_tzi_817e6d2eb6d35d2203c043743e29184a {
	meta:
		aliases = "_time_mktime_tzi"
		size = "717"
		objfiles = "_time_mktime_tzi@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 7C 8D 6C 24 48 51 6A 2C FF B4 24 98 00 00 00 55 E8 ?? ?? ?? ?? 83 C4 10 8B 84 24 98 00 00 00 80 78 28 00 75 08 C7 44 24 68 00 00 00 00 C7 44 24 44 00 00 00 00 83 7C 24 68 00 74 16 0F 9F C0 0F B6 C0 C7 44 24 44 01 00 00 00 8D 44 00 FF 89 44 24 68 8B 4D 14 8D 55 18 89 C8 89 54 24 2C BB 90 01 00 00 8D 75 10 99 F7 FB 89 45 18 BA 0C 00 00 00 69 C0 90 01 00 00 29 C1 8D 45 1C 89 44 24 30 89 D3 8B 45 10 8D 7D 14 99 F7 FB 01 C1 89 45 1C 6B C0 0C 89 4D 14 29 06 8B 45 10 85 C0 79 08 83 C0 0C 89 45 10 FF 0F 81 07 6C 07 00 00 BB ?? ?? ?? ?? 8B 4D 14 F6 C1 03 75 36 BA 64 00 00 00 89 C8 89 }
	condition:
		$pattern
}

rule des_setkey_cc14afa7c086f800f79db7bee4e3ac62 {
	meta:
		aliases = "des_setkey"
		size = "666"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 89 C3 83 EC 30 E8 ?? ?? ?? ?? 8B 03 8B 4B 04 0F C8 89 C2 0F C9 09 CA 74 14 3B 05 ?? ?? ?? ?? 75 0C 3B 0D ?? ?? ?? ?? 0F 84 61 02 00 00 89 C3 89 C6 C1 EB 19 89 C5 89 C7 A3 ?? ?? ?? ?? 89 C8 89 5C 24 04 C1 E8 19 89 CA C1 EE 11 89 44 24 0C 83 E6 7F 8B 44 24 04 C1 ED 09 89 CB 83 E5 7F 8B 04 85 ?? ?? ?? ?? 89 6C 24 08 8B 2C B5 ?? ?? ?? ?? 09 C5 8B 44 24 0C C1 EA 09 89 0D ?? ?? ?? ?? 83 E2 7F 8B 04 85 ?? ?? ?? ?? 09 C5 C7 44 24 28 00 00 00 00 8B 04 95 ?? ?? ?? ?? C7 44 24 2C 00 00 00 00 D1 EF 09 C5 89 6C 24 24 8B 6C 24 08 C1 EB 11 83 E7 7F 8B 04 AD ?? ?? ?? ?? 83 E3 7F 0B 04 BD ?? ?? ?? }
	condition:
		$pattern
}

rule byte_compile_range_482bb761deb27cbead2d5ff62a70217d {
	meta:
		aliases = "byte_compile_range"
		size = "204"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 89 D5 8B 12 89 C7 8B 5C 24 18 BE 0B 00 00 00 39 CA 0F 84 AA 00 00 00 81 E3 00 00 01 00 8D 42 01 83 FB 01 89 45 00 19 F6 F7 D6 83 E6 0B 83 7C 24 14 00 74 16 89 F9 0F B6 C1 8B 4C 24 14 0F BE 3C 01 0F B6 02 0F B6 2C 01 EB 03 0F B6 2A 89 FB EB 6C 83 7C 24 14 00 74 1B 0F B6 C3 8B 7C 24 14 BA 08 00 00 00 89 D1 0F B6 04 07 99 F7 F9 89 C6 89 C1 EB 19 0F B6 D3 89 D0 B9 08 00 00 00 99 F7 F9 0F B6 D3 89 C6 89 D0 99 F7 F9 89 C1 8B 7C 24 1C 83 7C 24 14 00 8A 14 0F 89 D9 74 0B 0F B6 C3 8B 7C 24 14 0F B6 0C 07 83 E1 07 B8 01 00 00 00 D3 E0 09 C2 8B 44 24 1C 43 88 14 30 31 F6 39 EB 76 90 89 F0 5B }
	condition:
		$pattern
}

rule byte_insert_op2_407a04efb9b96dd2d2b94edb91780103 {
	meta:
		aliases = "byte_insert_op2"
		size = "50"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 89 D6 8B 54 24 18 89 CF 89 C5 8B 5C 24 14 8D 4A 05 EB 06 4A 49 8A 02 88 01 39 F2 75 F6 89 F9 89 E8 89 5C 24 14 5B 5E 5F 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_random_r_a181e47f13e412999a890d66cf38c531 {
	meta:
		aliases = "random_r, __GI_random_r"
		size = "95"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 5C 24 14 8B 6C 24 18 8B 73 08 83 7B 0C 00 75 17 69 06 6D 4E C6 41 05 39 30 00 00 25 FF FF FF 7F 89 06 89 45 00 EB 2C 8B 4B 04 8B 13 8B 7B 18 8B 01 01 02 8B 02 83 C2 04 D1 E8 39 FA 89 45 00 8D 41 04 72 04 89 F2 EB 06 39 F8 72 02 89 F0 89 13 89 43 04 31 C0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule syscall_fa970c4170346219d0a1ba116897c543 {
	meta:
		aliases = "syscall"
		size = "50"
		objfiles = "syscall@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 6C 24 2C 8B 7C 24 28 8B 74 24 24 8B 54 24 20 8B 4C 24 1C 8B 5C 24 18 8B 44 24 14 CD 80 5B 5E 5F 5D 3D 01 F0 FF FF 0F 83 ?? ?? ?? ?? C3 }
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

rule __ctzsi2_430b2af1f308fe442df8d8ad794efb17 {
	meta:
		aliases = "__ctzsi2"
		size = "9"
		objfiles = "_ctzsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 0F BC 45 08 5D C3 }
	condition:
		$pattern
}

rule __clzsi2_20c6a287ca150669449d1d0c724ad73a {
	meta:
		aliases = "__clzsi2"
		size = "12"
		objfiles = "_clzsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 0F BD 45 08 83 F0 1F 5D C3 }
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

rule __do_global_ctors_aux_c23362c6eb3ea285c2ce5674f4dbd4e4 {
	meta:
		aliases = "__do_global_ctors_aux"
		size = "38"
		objfiles = "crtend"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 BB ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 F8 FF 74 0C 83 EB 04 FF D0 8B 03 83 F8 FF 75 F4 58 5B 5D C3 }
	condition:
		$pattern
}

rule base_from_object_077d8ecb6c3cecec115297e00b2b3479 {
	meta:
		aliases = "base_from_object"
		size = "86"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 3C FF 74 1D 83 E0 70 83 F8 20 74 21 7E 0F 83 F8 30 74 2B 83 F8 50 74 09 E8 ?? ?? ?? ?? 85 C0 75 13 31 C0 5A 5B 5D C3 8D B6 00 00 00 00 8B 42 04 5A 5B 5D C3 83 F8 10 74 E8 E8 ?? ?? ?? ?? 8B 42 08 EB E0 }
	condition:
		$pattern
}

rule size_of_encoded_value_2d3c79fbc4e72dd3fb91ec4d0ce7cf07 {
	meta:
		aliases = "size_of_encoded_value"
		size = "84"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 3C FF 74 39 83 E0 07 83 F8 02 74 21 7E 0F 83 F8 03 74 0E 83 F8 04 74 1E E8 ?? ?? ?? ?? 85 C0 75 F7 B8 04 00 00 00 5A 5B 5D C3 8D 76 00 B8 02 00 00 00 5A 5B 5D C3 B8 08 00 00 00 EB E9 31 C0 EB E5 }
	condition:
		$pattern
}

rule __do_global_dtors_aux_584b87652b6d3ffd4316e3648bee6925 {
	meta:
		aliases = "__do_global_dtors_aux"
		size = "222"
		objfiles = "crtbeginS"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 80 BB ?? ?? ?? ?? 00 75 5E 8B 8B ?? ?? ?? ?? 85 C9 74 25 83 EC 0C 8B 93 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 10 EB 11 8D B6 00 00 00 00 83 C0 04 89 83 ?? ?? ?? ?? FF D2 8B 83 ?? ?? ?? ?? 8B 10 85 D2 75 E9 8B 83 ?? ?? ?? ?? 85 C0 74 12 83 EC 0C 8D 83 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 10 C6 83 ?? ?? ?? ?? 01 8B 5D FC C9 C3 90 55 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 83 ?? ?? ?? ?? 85 C0 74 19 8D 83 ?? ?? ?? ?? 53 6A 00 50 8D 83 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 10 8B 83 ?? ?? ?? ?? 85 C0 74 19 8B 93 ?? ?? ?? ?? 85 D2 }
	condition:
		$pattern
}

rule __negvsi2_f0671ae39c28d963c620bb437d76e80f {
	meta:
		aliases = "__negvsi2"
		size = "60"
		objfiles = "_negvsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 45 08 89 C2 F7 DA 85 C0 78 12 85 D2 0F 9F C0 84 C0 75 10 89 D0 5A 5B 5D C3 8D 76 00 89 D0 C1 E8 1F EB EC E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __deregister_frame_06a762d139915cd593509d223897c234 {
	meta:
		aliases = "__deregister_frame"
		size = "53"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 45 08 8B 10 85 D2 74 14 83 EC 0C 50 E8 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 8B 5D FC C9 C3 }
	condition:
		$pattern
}

rule __register_frame_info_table_e54fcf853c012bd5b389bee07b2d4c9f {
	meta:
		aliases = "__register_frame_info, __register_frame_info_table"
		size = "44"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 45 0C 6A 00 6A 00 50 8B 45 08 50 E8 ?? ?? ?? ?? 83 C4 10 8B 5D FC C9 C3 }
	condition:
		$pattern
}

rule __addvsi3_f15df59fbf99fb61fbae3aaff0dba49d {
	meta:
		aliases = "__addvsi3"
		size = "60"
		objfiles = "_addvsi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 45 0C 8B 4D 08 85 C0 8D 14 01 78 10 39 D1 0F 9F C0 84 C0 75 0E 89 D0 5A 5B 5D C3 90 39 D1 0F 9C C0 EB EE E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __subvsi3_721c8672f340b892486e49a2dc44a9b4 {
	meta:
		aliases = "__subvsi3"
		size = "60"
		objfiles = "_subvsi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 4D 08 8B 45 0C 89 CA 29 C2 85 C0 78 0F 39 D1 0F 9C C0 84 C0 75 0D 89 D0 5A 5B 5D C3 39 D1 0F 9F C0 EB EF E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __absvsi2_728115f9dcc60fe6ca8c566c300b4ede {
	meta:
		aliases = "__absvsi2"
		size = "43"
		objfiles = "_absvsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 55 08 89 D0 85 D2 78 04 5A 5B 5D C3 F7 D8 85 C0 79 F6 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule frame_dummy_88011a284d4ff4bb0049ca69377ba4ae {
	meta:
		aliases = "frame_dummy"
		size = "94"
		objfiles = "crtbeginS"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 83 ?? ?? ?? ?? 85 C0 74 19 8D 83 ?? ?? ?? ?? 53 6A 00 50 8D 83 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 10 8B 83 ?? ?? ?? ?? 85 C0 74 19 8B 93 ?? ?? ?? ?? 85 D2 74 0F 83 EC 0C 8D 83 ?? ?? ?? ?? 50 FF D2 83 C4 10 8B 5D FC C9 C3 }
	condition:
		$pattern
}

rule __fixsfdi_93c8bc6b5651a25cfadc8972e636176b {
	meta:
		aliases = "__fixsfdi"
		size = "80"
		objfiles = "_fixsfdi@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? D9 45 08 D9 EE DD E9 DF E0 F6 C4 45 74 13 83 EC 10 D9 1C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 5D FC C9 C3 83 EC 10 D9 E0 D9 1C 24 E8 ?? ?? ?? ?? 8B 5D FC F7 D8 83 D2 00 83 C4 10 F7 DA C9 C3 }
	condition:
		$pattern
}

rule __fixxfdi_2e621349d594f96759fabd6c7ff14793 {
	meta:
		aliases = "__fixxfdi"
		size = "84"
		objfiles = "_fixxfdi@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? DB 6D 08 D9 83 ?? ?? ?? ?? DD E9 DF E0 F6 C4 45 74 13 83 EC 10 DB 3C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 5D FC C9 C3 83 EC 10 D9 E0 DB 3C 24 E8 ?? ?? ?? ?? 8B 5D FC F7 D8 83 D2 00 83 C4 10 F7 DA C9 C3 }
	condition:
		$pattern
}

rule __fixdfdi_3bacd3f47cffe526ca1e4eb1b5b67dae {
	meta:
		aliases = "__fixdfdi"
		size = "84"
		objfiles = "_fixdfdi@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? DD 45 08 D9 83 ?? ?? ?? ?? DD E9 DF E0 F6 C4 45 74 13 83 EC 10 DD 1C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 5D FC C9 C3 83 EC 10 D9 E0 DD 1C 24 E8 ?? ?? ?? ?? 8B 5D FC F7 D8 83 D2 00 83 C4 10 F7 DA C9 C3 }
	condition:
		$pattern
}

rule __gthread_mutex_unlock_acb29e780f57b7c61233a2c86561aebb {
	meta:
		aliases = "__gthread_mutex_unlock"
		size = "31"
		objfiles = "gthr_gnat@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? FF 93 ?? ?? ?? ?? 31 C0 59 5B 5D C3 }
	condition:
		$pattern
}

rule __gthread_mutex_lock_8faa12d58ab59dbf83e706fa12d1584e {
	meta:
		aliases = "__gthread_mutex_lock"
		size = "31"
		objfiles = "gthr_gnat@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? FF 93 ?? ?? ?? ?? 31 C0 5A 5B 5D C3 }
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

rule __register_frame_table_0cb9895e154004523f1435bd51c242ff {
	meta:
		aliases = "__register_frame_table"
		size = "46"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 10 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 6A 18 E8 ?? ?? ?? ?? 5A 59 50 8B 45 08 50 E8 ?? ?? ?? ?? 83 C4 10 8B 5D FC C9 C3 }
	condition:
		$pattern
}

rule __deregister_frame_info_efe255031bd14ecca230e024a47a0b2f {
	meta:
		aliases = "__deregister_frame_info"
		size = "33"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 10 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 45 08 50 E8 ?? ?? ?? ?? 8B 5D FC C9 C3 }
	condition:
		$pattern
}

rule fopen_unlocked_9f36a9f3ae645381811592b2425864d7 {
	meta:
		aliases = "fdopen_unlocked, fopen_unlocked"
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

rule uw_install_context_58d72f59b881eabced19955667d0ddaf {
	meta:
		aliases = "uw_install_context"
		size = "38"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 8B 02 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 8D 50 20 8B 4A 04 8B 68 20 8B 62 08 FF E1 }
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

rule __register_frame_info_bases_4e08c0f629984bc3048b580df585499c {
	meta:
		aliases = "__register_frame_info_bases"
		size = "84"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 4D 08 8B 55 0C 85 C9 74 37 8B 01 85 C0 74 31 8B 45 10 C7 02 FF FF FF FF 89 42 04 8B 45 14 89 42 08 C7 42 10 00 00 00 00 8B 83 ?? ?? ?? ?? 89 4A 0C 66 81 4A 10 F8 07 89 42 14 89 93 ?? ?? ?? ?? 5B 5D C3 }
	condition:
		$pattern
}

rule __powisf2_60f192fb6f362282ea5ae412e3609a79 {
	meta:
		aliases = "__powisf2"
		size = "88"
		objfiles = "_powisf2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 4D 0C 89 C8 C1 F8 1F 89 C2 31 CA D9 45 08 29 C2 D9 C0 F6 C2 01 75 0A DD D8 D9 E8 EB 04 89 F6 D9 C9 D1 EA 74 13 D9 C9 D8 C8 F6 C2 01 74 F1 D1 EA DC C9 75 F3 DD D8 EB 02 DD D9 85 C9 79 06 D8 BB ?? ?? ?? ?? 5B 5D C3 }
	condition:
		$pattern
}

rule __powidf2_ca4cff5a0194b33d95e7766acaacf340 {
	meta:
		aliases = "__powidf2"
		size = "90"
		objfiles = "_powidf2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 4D 10 89 C8 C1 F8 1F 89 C2 31 CA DD 45 08 29 C2 D9 C0 F6 C2 01 75 0C DD D8 D9 83 ?? ?? ?? ?? EB 02 D9 C9 D1 EA 74 13 D9 C9 D8 C8 F6 C2 01 74 F1 D1 EA DC C9 75 F3 DD D8 EB 02 DD D9 85 C9 79 06 D8 BB ?? ?? ?? ?? 5B 5D C3 }
	condition:
		$pattern
}

rule __powixf2_654907814e14fc40fca6ef77e997aa68 {
	meta:
		aliases = "__powixf2"
		size = "90"
		objfiles = "_powixf2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 4D 14 89 C8 C1 F8 1F 89 C2 31 CA DB 6D 08 29 C2 D9 C0 F6 C2 01 75 0C DD D8 D9 83 ?? ?? ?? ?? EB 02 D9 C9 D1 EA 74 13 D9 C9 D8 C8 F6 C2 01 74 F1 D1 EA DC C9 75 F3 DD D8 EB 02 DD D9 85 C9 79 06 D8 BB ?? ?? ?? ?? 5B 5D C3 }
	condition:
		$pattern
}

rule _fini_6378da484a4f365704364c2fc1aaf10f {
	meta:
		aliases = "_init, _fini"
		size = "15"
		objfiles = "crti"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 E8 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? }
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

rule execlp_5a2fca074960bf8f014fa2f5510151b1 {
	meta:
		aliases = "__GI_execlp, execlp"
		size = "100"
		objfiles = "execlp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 31 F6 8D 45 10 83 EC 10 89 45 F4 8B 55 F4 46 8D 42 04 89 45 F4 83 3A 00 75 F1 8D 04 B5 22 00 00 00 83 E0 F0 29 C4 8B 45 0C 8D 5C 24 0F 83 E3 F0 89 D9 89 03 8D 45 10 89 45 F4 8B 45 F4 83 C1 04 4E 8D 50 04 89 55 F4 8B 00 89 01 75 ED 50 50 53 FF 75 08 E8 ?? ?? ?? ?? 8D 65 F8 5B 5E 5D C3 }
	condition:
		$pattern
}

rule execl_efc015865777dce350cacb8ac2a88947 {
	meta:
		aliases = "__GI_execl, execl"
		size = "105"
		objfiles = "execl@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 31 F6 8D 45 10 83 EC 10 89 45 F4 8B 55 F4 46 8D 42 04 89 45 F4 83 3A 00 75 F1 8D 04 B5 22 00 00 00 83 E0 F0 29 C4 8B 45 0C 8D 5C 24 0F 83 E3 F0 89 D9 89 03 8D 45 10 89 45 F4 8B 45 F4 83 C1 04 4E 8D 50 04 89 55 F4 8B 00 89 01 75 ED 50 FF 35 ?? ?? ?? ?? 53 FF 75 08 E8 ?? ?? ?? ?? 8D 65 F8 5B 5E 5D C3 }
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

rule getrpcport_dfb991ced464e028b8af66b4bbad6901 {
	meta:
		aliases = "getrpcport"
		size = "162"
		objfiles = "getrpcport@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 BB 00 04 00 00 81 EC 40 04 00 00 8B 75 08 8D 54 24 0F 83 E2 F0 EB 21 83 7D F0 FF 75 77 E8 ?? ?? ?? ?? 83 38 22 75 6D 01 DB 8D 43 1E 83 E0 F0 29 C4 8D 54 24 0F 83 E2 F0 50 50 8D 45 F0 50 8D 45 F4 50 8D 45 CC 53 52 50 56 E8 ?? ?? ?? ?? 83 C4 20 85 C0 75 C2 8B 45 F4 85 C0 74 BB 51 8D 55 E4 FF 70 0C 8B 40 10 8D 5D E0 FF 30 52 E8 ?? ?? ?? ?? FF 75 14 FF 75 10 FF 75 0C 66 C7 45 E0 02 00 53 66 C7 45 E2 00 00 E8 ?? ?? ?? ?? 83 C4 20 0F B7 C0 EB 02 31 C0 8D 65 F8 5B 5E 5D C3 }
	condition:
		$pattern
}

rule _Unwind_SjLj_Resume_or_Rethrow_e4bc250dd584d8a37f6cb23568aad5c2 {
	meta:
		aliases = "_Unwind_SjLj_Resume_or_Rethrow"
		size = "90"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 83 EC 10 8B 4D 08 8B 71 0C 85 F6 74 22 8B 83 ?? ?? ?? ?? 8D 75 F0 89 45 F4 89 45 F0 89 F2 89 C8 E8 AA FC FF FF 83 F8 07 74 15 E8 ?? ?? ?? ?? 83 EC 0C 51 E8 ?? ?? ?? ?? 8D 65 F8 5B 5E 5D C3 8D 45 F4 89 F2 E8 16 FE FF FF }
	condition:
		$pattern
}

rule _Unwind_SjLj_Resume_adbfdc569c030c4c28e213fe61243c3a {
	meta:
		aliases = "_Unwind_SjLj_Resume"
		size = "88"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 83 EC 10 8B 4D 08 8B 83 ?? ?? ?? ?? 89 45 F4 89 45 F0 8B 41 0C 85 C0 75 16 8D 75 F0 89 C8 89 F2 E8 FA FE FF FF 83 F8 07 74 13 E8 ?? ?? ?? ?? 8D 75 F0 89 C8 89 F2 E8 F4 FD FF FF EB E8 8D 45 F4 89 F2 E8 78 FF FF FF }
	condition:
		$pattern
}

rule _Unwind_SjLj_ForcedUnwind_c71f955e79045c8d4adc37a60e359273 {
	meta:
		aliases = "_Unwind_SjLj_ForcedUnwind"
		size = "79"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 83 EC 10 8D 75 F0 8B 93 ?? ?? ?? ?? 8B 45 08 89 55 F4 89 55 F0 8B 55 0C 89 50 0C 8B 55 10 89 50 10 89 F2 E8 A7 FD FF FF 83 F8 07 74 07 83 C4 10 5B 5E 5D C3 8D 45 F4 89 F2 E8 21 FF FF FF }
	condition:
		$pattern
}

rule __deregister_frame_info_bases_7521c2600126b64564f94cc4ec11e25a {
	meta:
		aliases = "__deregister_frame_info_bases"
		size = "172"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 55 08 85 D2 75 09 8D 65 F8 31 C0 5B 5E 5D C3 8B 02 85 C0 74 F1 8B B3 ?? ?? ?? ?? 85 F6 74 2E 8D 8B ?? ?? ?? ?? 3B 56 0C 75 19 8B 46 14 89 01 89 F0 8D 65 F8 5B 5E 5D C3 8D B6 00 00 00 00 3B 56 0C 74 E7 8D 4E 14 8B 76 14 85 F6 75 F1 8B B3 ?? ?? ?? ?? 85 F6 74 3E 8D 8B ?? ?? ?? ?? EB 11 8B 46 0C 3B 10 74 17 8D 4E 14 8B 76 14 85 F6 74 25 F6 46 10 01 75 E9 3B 56 0C 75 EB EB AD 8B 46 14 83 EC 0C 89 01 8B 46 0C 50 E8 ?? ?? ?? ?? 83 C4 10 89 F0 EB 9C E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __register_frame_052c3a53ad2430fd0eb97f87d54cea34 {
	meta:
		aliases = "__register_frame"
		size = "55"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 75 08 8B 06 85 C0 74 16 83 EC 0C 6A 18 E8 ?? ?? ?? ?? 5A 59 50 56 E8 ?? ?? ?? ?? 83 C4 10 8D 65 F8 5B 5E 5D C3 }
	condition:
		$pattern
}

rule __do_global_ctors_aux_c080c72a3380caa54398aaf67b15be36 {
	meta:
		aliases = "__do_global_ctors_aux"
		size = "50"
		objfiles = "crtendS"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8D 83 ?? ?? ?? ?? 8D 70 FC 8B 40 FC 83 F8 FF 74 0C 83 EE 04 FF D0 8B 06 83 F8 FF 75 F4 5B 5E 5D C3 }
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

rule read_uleb128_f200068803a17451bb061a46ee0fe3f8 {
	meta:
		aliases = "read_uleb128"
		size = "59"
		objfiles = "unwind_c@libgcc.a, unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 31 FF 83 EC 08 31 F6 89 45 F0 89 55 F4 8B 45 F0 89 F1 83 C6 07 8A 10 40 89 45 F0 89 D0 83 E0 7F D3 E0 09 C7 84 D2 78 E5 8B 45 F4 89 38 8B 45 F0 5A 59 5E 5F 5D C3 }
	condition:
		$pattern
}

rule read_sleb128_7857f4e4b3f12edd1e30320776cb6ce7 {
	meta:
		aliases = "read_sleb128"
		size = "109"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 31 FF 83 EC 0C 89 45 EC 89 55 F0 C7 45 F4 00 00 00 00 8B 45 EC 8A 10 40 88 D1 89 45 EC 81 E1 FF 00 00 00 89 C8 89 CE 83 E0 7F 89 F9 D3 E0 8B 4D F4 83 C7 07 09 C1 84 D2 89 4D F4 78 D5 83 FF 1F 77 14 83 E6 40 74 0F 83 C8 FF 89 F9 8B 75 F4 D3 E0 09 C6 89 75 F4 8B 45 F0 8B 55 F4 89 10 8B 45 EC 83 C4 0C 5E 5F 5D C3 }
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

rule glob_in_dir_f3b4c3c298358632aa0d6133acc3be09 {
	meta:
		aliases = "glob_in_dir"
		size = "1330"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 08 02 00 00 89 95 08 FE FF FF 89 8D 04 FE FF FF 89 85 0C FE FF FF 52 E8 ?? ?? ?? ?? 8B 9D 04 FE FF FF 83 C4 10 83 E3 40 89 85 10 FE FF FF 0F 94 C0 0F B6 C0 50 8B 75 08 FF B5 0C FE FF FF E8 ?? ?? ?? ?? 5A 85 C0 59 0F 85 E1 00 00 00 F7 85 04 FE FF FF 10 08 00 00 0F 85 B1 00 00 00 85 DB 75 1A 50 50 6A 5C FF B5 0C FE FF FF E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 B3 00 00 00 83 EC 0C FF B5 0C FE FF FF E8 ?? ?? ?? ?? 8B 95 10 FE FF FF 89 C6 83 C4 10 8D 44 02 20 83 E0 F0 29 C4 8D 5C 24 0F 50 52 83 E3 F0 FF B5 08 FE FF FF 53 E8 ?? ?? ?? ?? 83 C4 0C 6A 01 68 ?? ?? ?? ?? 50 E8 ?? ?? }
	condition:
		$pattern
}

rule byte_re_match_2_internal_7a059b2f445643554aa6b2af500cd8ff {
	meta:
		aliases = "byte_re_match_2_internal"
		size = "6828"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 0C 01 00 00 89 85 50 FF FF FF 89 95 4C FF FF FF 89 8D 48 FF FF FF 8B 00 8B 95 50 FF FF FF 89 85 6C FF FF FF 89 D3 03 42 08 89 85 70 FF FF FF 8D 44 24 0F 8B 4A 14 83 E0 F0 89 8D 78 FF FF FF 8B 52 18 89 45 C8 0F 84 47 1A 00 00 42 89 95 7C FF FF FF 83 7B 18 00 75 44 C7 45 88 00 00 00 00 C7 45 8C 00 00 00 00 C7 45 90 00 00 00 00 C7 45 94 00 00 00 00 C7 45 98 00 00 00 00 C7 45 A0 00 00 00 00 C7 45 A4 00 00 00 00 C7 45 B0 00 00 00 00 C7 45 B4 00 00 00 00 E9 DC 00 00 00 8B B5 7C FF FF FF 8D 04 B5 1E 00 00 00 83 E0 F0 29 C4 8D 54 24 0F 29 C4 8D 7C 24 0F 29 C4 83 E7 F0 89 7D 8C }
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

rule set_fast_math_b1fe011bed1e169613aa8b7fa2ea67d9 {
	meta:
		aliases = "set_fast_math"
		size = "198"
		objfiles = "crtfastmath"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 1C 02 00 00 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 9C 9C 58 89 C2 35 00 00 20 00 50 9D 9C 58 9D 31 D0 A9 00 00 20 00 74 54 31 C0 87 DE 0F A2 87 DE 85 C0 74 48 B8 01 00 00 00 87 DF 0F A2 87 DF 89 D6 F7 C2 00 00 00 02 74 33 0F AE 9D E4 FD FF FF 8B BD E4 FD FF FF 89 F8 80 CC 80 81 E6 00 00 00 01 89 85 E0 FD FF FF 75 1B 8B 95 E0 FD FF FF 89 95 E4 FD FF FF 0F AE 95 E4 FD FF FF 8D 65 F4 5B 5E 5F 5D C3 8D 85 E8 FD FF FF 52 68 00 02 00 00 6A 00 50 E8 ?? ?? ?? ?? 0F AE 85 E8 FD FF FF 81 CF 40 80 00 00 83 C4 10 F6 85 04 FE FF FF 40 0F 44 BD E0 FD FF FF 89 BD E0 FD FF FF EB AB }
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

rule ruserok_8b42d9d99af5d1eb3e6601d336618e7a {
	meta:
		aliases = "ruserok"
		size = "164"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 3C 04 00 00 BB 00 04 00 00 8B 75 08 8B 7D 14 8D 54 24 0F 83 E2 F0 EB 21 83 7D E8 FF 75 73 E8 ?? ?? ?? ?? 83 38 22 75 69 01 DB 8D 43 1E 83 E0 F0 29 C4 8D 54 24 0F 83 E2 F0 50 50 8D 45 E8 50 8D 45 F0 50 8D 45 D4 53 52 50 56 E8 ?? ?? ?? ?? 83 C4 20 85 C0 75 C2 8B 45 F0 85 C0 74 BB 8B 58 10 EB 29 51 6A 04 50 8D 45 EC 50 E8 ?? ?? ?? ?? 58 8B 4D 10 5A 8B 45 EC 8B 55 0C 56 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 0C 83 C3 04 8B 03 85 C0 75 D1 83 C8 FF 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule ruserpass_dd1a5b07ac47eacb82b37a4d6b96d156 {
	meta:
		aliases = "__GI_ruserpass, ruserpass"
		size = "870"
		objfiles = "ruserpass@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 6C 04 00 00 8B 7D 08 E8 ?? ?? ?? ?? 89 C3 E8 ?? ?? ?? ?? 39 C3 0F 85 36 03 00 00 E8 ?? ?? ?? ?? 89 C3 E8 ?? ?? ?? ?? 39 C3 0F 85 22 03 00 00 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 0F 84 08 03 00 00 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C0 26 83 C4 10 83 E0 F0 29 C4 8D 5C 24 0F 50 83 E3 F0 50 56 53 E8 ?? ?? ?? ?? 59 5E 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 58 5A 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 A3 ?? ?? ?? ?? 85 C0 75 22 E8 ?? ?? ?? ?? 31 D2 83 38 02 0F 84 B1 02 00 00 56 56 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 61 02 00 00 8D 9D 9C FB FF FF 51 51 6A 02 50 }
	condition:
		$pattern
}

rule search_object_480a140a6cd2176c394e4869f69c4d33 {
	meta:
		aliases = "search_object"
		size = "1596"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 8C 00 00 00 89 45 8C 89 55 88 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8A 50 10 F6 C2 01 0F 85 A2 01 00 00 8B 48 10 89 C8 C1 E8 0B 0F 84 0A 02 00 00 89 45 9C 8B 45 9C 83 EC 0C 8D 34 85 08 00 00 00 56 E8 ?? ?? ?? ?? 83 C4 10 89 45 E4 85 C0 0F 84 5A 01 00 00 83 EC 0C C7 40 04 00 00 00 00 56 E8 ?? ?? ?? ?? 83 C4 10 89 45 E8 85 C0 74 07 C7 40 04 00 00 00 00 8B 55 8C F6 42 10 02 0F 84 2F 03 00 00 8B 55 8C 8B 42 0C 8B 08 85 C9 74 19 89 C6 8D 7D E4 89 FA 8B 45 8C E8 AB F9 FF FF 8B 4E 04 83 C6 04 85 C9 75 EC 8B 7D E4 89 7D 98 85 FF 74 0C 8B 45 9C 3B 47 04 0F 85 72 05 00 00 8D 93 ?? }
	condition:
		$pattern
}

rule gaih_inet_6af42b98c5deb8cbad81f44d87d22654 {
	meta:
		aliases = "gaih_inet"
		size = "2447"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 8C 00 00 00 8D 45 D4 8B 55 10 89 45 F0 C7 45 EC 00 00 00 00 8B 7D 0C 8B 42 04 85 C0 74 0F C7 85 68 FF FF FF 00 00 00 00 83 F8 0A 75 16 8B 4D 10 8B 01 83 F0 08 C1 E8 03 F7 D0 83 E0 01 89 85 68 FF FF FF 50 8D 45 D4 6A 10 6A 00 50 E8 ?? ?? ?? ?? 8B 55 10 83 C4 10 8B 4A 0C 85 C9 74 07 BB ?? ?? ?? ?? EB 0E 8B 45 10 83 78 08 00 75 F0 EB 53 83 C3 07 8A 53 03 88 95 7F FF FF FF 84 D2 74 2C 8B 45 10 8B 50 08 85 D2 74 07 0F BE 03 39 C2 75 DF 85 C9 74 0E F6 43 02 02 75 08 0F BE 43 01 39 C1 75 CD 80 BD 7F FF FF FF 00 75 1C 8B 55 10 B8 07 01 00 00 83 7A 08 00 0F 85 C1 08 00 00 E9 8C }
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

rule fibheap_extr_min_node_c10936bb9f37fd5e582a785a53964ed5 {
	meta:
		aliases = "fibheap_extr_min_node"
		size = "480"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC AC 00 00 00 89 85 58 FF FF FF 8B 40 04 8B 70 04 89 85 5C FF FF FF 85 F6 74 28 89 F2 8B 5A 0C 8B 85 58 FF FF FF C7 02 00 00 00 00 E8 08 FD FF FF 39 DE 74 0E 85 DB 74 0A 85 F6 89 DA 75 DE 89 DE EB D8 8B 95 5C FF FF FF 8B 85 58 FF FF FF E8 F5 FE FF FF 8B 95 58 FF FF FF 8B 02 48 85 C0 89 02 75 18 C7 42 04 00 00 00 00 8B 85 5C FF FF FF 81 C4 AC 00 00 00 5B 5E 5F 5D C3 8B 95 5C FF FF FF 31 C9 BB 84 00 00 00 8B 42 0C 8B 95 58 FF FF FF 89 42 04 8D 85 70 FF FF FF 89 5C 24 08 89 4C 24 04 89 04 24 E8 ?? ?? ?? ?? 8B 95 58 FF FF FF 8B 72 08 85 F6 0F 84 BC 00 00 00 8D B4 26 00 00 00 }
	condition:
		$pattern
}

rule clnt_create_098c8e38b552b82b2c28cf849fdced54 {
	meta:
		aliases = "clnt_create"
		size = "503"
		objfiles = "clnt_generic@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC C4 00 00 00 68 ?? ?? ?? ?? FF 75 14 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 4D 8D 9D 46 FF FF FF 51 6A 6E 6A 00 53 E8 ?? ?? ?? ?? 58 5A FF 75 08 8D 85 48 FF FF FF 66 C7 85 46 FF FF FF 01 00 50 E8 ?? ?? ?? ?? 5F 58 8D 45 EC 6A 00 6A 00 50 FF 75 10 FF 75 0C C7 45 EC FF FF FF FF 53 E8 ?? ?? ?? ?? E9 41 01 00 00 81 EC 10 04 00 00 BB 00 04 00 00 8D 54 24 0F 83 E2 F0 EB 31 83 7D E4 FF 75 0A E8 ?? ?? ?? ?? 83 38 22 74 10 E8 ?? ?? ?? ?? C7 00 0D 00 00 00 E9 4C 01 00 00 01 DB 8D 43 1E 83 E0 F0 29 C4 8D 54 24 0F 83 E2 F0 8D 45 E4 56 56 50 8D 45 F0 50 8D 45 B4 53 52 50 FF 75 08 E8 ?? ?? }
	condition:
		$pattern
}

rule link_exists_p_3b23ed79e1a32127b2aa4a5a309a8ba3 {
	meta:
		aliases = "link_exists_p"
		size = "163"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC C8 00 00 00 89 8D 3C FF FF FF 89 85 40 FF FF FF 89 D3 51 E8 ?? ?? ?? ?? 89 C6 83 C4 10 8D 44 18 20 83 E0 F0 29 C4 8D 7C 24 0F 50 53 83 E7 F0 FF B5 40 FF FF FF 57 E8 ?? ?? ?? ?? 83 C4 0C 6A 01 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 0C 8D 56 01 52 FF B5 3C FF FF FF 50 E8 ?? ?? ?? ?? 83 C4 10 F7 45 0C 00 02 00 00 74 0F 50 50 8D 45 9C 50 8B 45 08 57 FF 50 20 EB 0F 8D 85 44 FF FF FF 56 56 50 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 94 C0 0F B6 C0 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule link_exists_p_3b2593f02f401251a8aa6b72c38dc67a {
	meta:
		aliases = "link_exists_p"
		size = "163"
		objfiles = "glob64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC D8 00 00 00 89 8D 2C FF FF FF 89 85 30 FF FF FF 89 D3 51 E8 ?? ?? ?? ?? 89 C6 83 C4 10 8D 44 18 20 83 E0 F0 29 C4 8D 7C 24 0F 50 53 83 E7 F0 FF B5 30 FF FF FF 57 E8 ?? ?? ?? ?? 83 C4 0C 6A 01 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 0C 8D 56 01 52 FF B5 2C FF FF FF 50 E8 ?? ?? ?? ?? 83 C4 10 F7 45 0C 00 02 00 00 74 0F 8D 45 94 51 51 50 8B 45 08 57 FF 50 20 EB 0F 8D 85 34 FF FF FF 52 52 50 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 94 C0 0F B6 C0 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule glob_2f0ffe4a73a8c16457cc4aac288c1153 {
	meta:
		aliases = "__GI_glob, glob"
		size = "1326"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC DC 00 00 00 8B 7D 14 83 7D 08 00 74 0D 85 FF 74 09 F7 45 0C 00 81 FF FF 74 13 E8 ?? ?? ?? ?? 83 CA FF C7 00 16 00 00 00 E9 EF 04 00 00 8B 45 0C 83 E0 08 89 85 24 FF FF FF 75 07 C7 47 08 00 00 00 00 50 50 6A 2F FF 75 08 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 75 3D F7 45 0C 00 50 00 00 0F 84 CC 00 00 00 8B 55 08 80 3A 7E 0F 85 C0 00 00 00 83 EC 0C 52 E8 ?? ?? ?? ?? 83 C4 10 8B 5D 08 89 85 34 FF FF FF C7 85 30 FF FF FF 00 00 00 00 E9 B4 00 00 00 3B 45 08 75 1E 8B 5D 08 C7 85 34 FF FF FF 01 00 00 00 43 89 9D 30 FF FF FF BB ?? ?? ?? ?? E9 91 00 00 00 2B 45 08 89 85 34 FF FF FF }
	condition:
		$pattern
}

rule __GI_glob64_824c179231f9aa5c570febe69ce94a31 {
	meta:
		aliases = "glob64, __GI_glob64"
		size = "1329"
		objfiles = "glob64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC EC 00 00 00 8B 7D 14 83 7D 08 00 74 0D 85 FF 74 09 F7 45 0C 00 81 FF FF 74 13 E8 ?? ?? ?? ?? 83 CA FF C7 00 16 00 00 00 E9 F2 04 00 00 8B 45 0C 83 E0 08 89 85 14 FF FF FF 75 07 C7 47 08 00 00 00 00 51 51 6A 2F FF 75 08 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 75 3D F7 45 0C 00 50 00 00 0F 84 CC 00 00 00 8B 55 08 80 3A 7E 0F 85 C0 00 00 00 83 EC 0C 52 E8 ?? ?? ?? ?? 83 C4 10 8B 5D 08 89 85 24 FF FF FF C7 85 20 FF FF FF 00 00 00 00 E9 B4 00 00 00 3B 45 08 75 1E 8B 5D 08 C7 85 24 FF FF FF 01 00 00 00 43 89 9D 20 FF FF FF BB ?? ?? ?? ?? E9 91 00 00 00 2B 45 08 89 85 24 FF FF FF }
	condition:
		$pattern
}

rule glob_in_dir_d1e292f0a58c6a80a72def5944e955ad {
	meta:
		aliases = "glob_in_dir"
		size = "1200"
		objfiles = "glob64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC F8 00 00 00 89 95 10 FF FF FF 89 85 14 FF FF FF 89 CF 52 E8 ?? ?? ?? ?? 89 FB 89 85 18 FF FF FF 83 E3 40 5A 0F 94 C0 59 8B 75 08 0F B6 C0 50 FF B5 14 FF FF FF E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 D5 00 00 00 F7 C7 10 08 00 00 0F 85 AD 00 00 00 85 DB 75 1A 50 50 6A 5C FF B5 14 FF FF FF E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 AB 00 00 00 83 EC 0C FF B5 14 FF FF FF E8 ?? ?? ?? ?? 8B 95 18 FF FF FF 89 C6 83 C4 10 8D 44 02 20 83 E0 F0 29 C4 8D 5C 24 0F 50 52 83 E3 F0 FF B5 10 FF FF FF 53 E8 ?? ?? ?? ?? 83 C4 0C 6A 01 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 0C 8D 56 01 52 FF B5 14 }
	condition:
		$pattern
}

rule fibheap_replace_key_data_c394fc5742cc15955d199ef36d4afdc3 {
	meta:
		aliases = "fibheap_replace_key_data"
		size = "202"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 04 8B 7D 0C 8B 4D 10 8B 57 10 39 D1 7C 06 0F 8F A5 00 00 00 8B 47 14 39 D1 89 4F 10 8B 37 89 45 F0 8B 45 14 89 47 14 74 63 85 F6 74 4B 3B 4E 10 7C 08 8D B6 00 00 00 00 7F 3E 8B 45 08 89 F1 89 FA E8 52 FF FF FF 8B 1E 85 DB 74 2C 80 7E 1B 00 78 10 EB 4F 8D 74 26 00 80 7B 1B 00 79 47 89 DE 89 C3 8B 45 08 89 D9 89 F2 E8 2A FF FF FF 8B 03 85 C0 75 E4 8D 74 26 00 8B 55 08 8B 42 04 8B 40 10 39 47 10 7D 12 8B 45 08 89 78 04 8B 45 F0 5A 5B 5E 5F 5D C3 8D 76 00 7E EC 8B 45 F0 5A 5B 5E 5F 5D C3 89 F3 80 4B 1B 80 8B 55 08 8B 42 04 8B 40 10 39 47 10 7C CF EB DF C7 45 F0 00 00 00 00 }
	condition:
		$pattern
}

rule __floatdisf_a819303ae5a4e39ca6a0f15b401911ca {
	meta:
		aliases = "__floatdisf"
		size = "135"
		objfiles = "_floatdisf@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 75 08 8B 7D 0C 89 F0 89 FA 83 E8 01 81 DA 00 00 E0 FF 81 FA FF FF 3F 00 72 20 76 4E 31 D2 89 F0 25 FF 07 00 00 89 D1 09 C1 74 0F 89 F0 25 00 F8 FF FF 89 C6 81 CE 00 08 00 00 89 FA 89 F0 89 D0 50 89 C2 DB 04 24 C1 FA 1F D8 8B ?? ?? ?? ?? 31 D2 89 14 24 56 DF 2C 24 DE C1 D9 5D F0 D9 45 F0 83 C4 0C 5B 5E 5F 5D C3 89 F6 83 F8 FE 76 CB EB AB }
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

rule sched_setaffinity_47fe25600e5635a3cb0d003f30f4a9b7 {
	meta:
		aliases = "sched_setaffinity"
		size = "229"
		objfiles = "sched_setaffinity@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 83 3D ?? ?? ?? ?? 00 0F 85 86 00 00 00 81 EC 90 00 00 00 BE 80 00 00 00 8D 5C 24 0F 83 E3 F0 EB 21 8D 0C 36 8D 41 1E 83 E0 F0 29 C4 8D 54 24 0F 83 E2 F0 8D 04 0A 39 D8 74 04 89 CE EB 02 01 CE 89 D3 E8 ?? ?? ?? ?? 89 F1 89 C7 89 DA 53 89 FB B8 F2 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 05 83 F8 EA 74 BB 85 FF 74 08 81 FF 00 F0 FF FF 76 1B E8 ?? ?? ?? ?? F7 DF 89 38 EB 0B E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 47 89 3D ?? ?? ?? ?? A1 ?? ?? ?? ?? EB 0A 8B 7D 10 80 3C 07 00 75 DA 40 3B 45 0C 72 F1 8B 7D 08 8B 4D 0C 8B 55 10 53 89 FB B8 F1 00 00 00 CD 80 5B 89 C3 }
	condition:
		$pattern
}

rule search_for_named_library_6206370f04613da7545529739770ee8a {
	meta:
		aliases = "search_for_named_library"
		size = "251"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 89 55 EC 89 45 F0 89 CA 85 C9 0F 84 D8 00 00 00 8D 41 FF 40 80 38 00 75 FA 29 D0 4A 8D 70 01 83 C0 1F 83 E0 F0 29 C4 8D 5C 24 0F 81 EC 20 08 00 00 83 E3 F0 8D 44 24 0F 89 DF 83 E0 F0 8D 4B FF 89 45 E8 EB 07 42 41 4E 8A 02 88 01 85 F6 75 F5 89 D8 80 3F 00 75 08 C6 07 3A BE 01 00 00 00 80 3F 3A 75 7A C6 07 00 8B 4D E8 80 38 00 8D 51 FF 74 0F 8D 48 FF 41 42 8A 01 88 02 84 C0 74 11 EB F4 B9 ?? ?? ?? ?? 41 42 8A 01 88 02 84 C0 75 F6 8B 5D E8 4B 89 D8 40 80 38 00 75 FA 8D 50 FF B9 ?? ?? ?? ?? 41 42 8A 01 88 02 84 C0 75 F6 43 80 3B 00 75 FA 8B 4D F0 8D 53 FF 49 41 42 8A 01 }
	condition:
		$pattern
}

rule _Unwind_RaiseException_Phase2_4e621880c08e4a30217f409b988fb2f9 {
	meta:
		aliases = "_Unwind_RaiseException_Phase2"
		size = "145"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 89 D7 89 45 F0 8B 02 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? EB 54 89 F6 8B 50 18 31 C9 8B 75 F0 3B 46 10 0F 94 C0 25 FF 00 00 00 89 C6 C1 E6 02 85 C9 75 43 85 D2 74 28 50 50 8B 45 F0 57 50 8B 45 F0 8B 48 04 51 8B 00 50 89 F0 83 C8 02 50 6A 01 FF D2 83 C4 20 83 F8 07 74 21 83 F8 08 75 17 85 F6 75 20 8B 07 8B 00 89 07 85 C0 75 AA B9 05 00 00 00 31 D2 EB A6 B8 02 00 00 00 8D 65 F4 5B 5E 5F 5D C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule init_error_tables_47d9d285c088b249efef9652bacd3c6d {
	meta:
		aliases = "init_signal_tables, init_error_tables"
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

rule __GI_nan_f06e08084b42e471c61a485bf2dc5284 {
	meta:
		aliases = "nan, __GI_nan"
		size = "87"
		objfiles = "nan@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 7D 08 80 3F 00 75 08 D9 05 ?? ?? ?? ?? EB 36 89 E3 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C0 24 83 C4 10 83 E0 F0 29 C4 8D 74 24 0F 50 83 E6 F0 57 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 5F 58 6A 00 56 E8 ?? ?? ?? ?? 89 DC 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_nanf_76d39ad9e0b3fbc25d39dd705b42d720 {
	meta:
		aliases = "nanf, __GI_nanf"
		size = "87"
		objfiles = "nan@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 7D 08 80 3F 00 75 08 D9 05 ?? ?? ?? ?? EB 36 89 E3 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C0 24 83 C4 10 83 E0 F0 29 C4 8D 74 24 0F 51 83 E6 F0 57 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 58 5A 6A 00 56 E8 ?? ?? ?? ?? 89 DC 8D 65 F4 5B 5E 5F 5D C3 }
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

rule __negvdi2_82c7b13142d6de65ebc28523e8633563 {
	meta:
		aliases = "__negvdi2"
		size = "92"
		objfiles = "_negvdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 45 08 8B 55 0C 89 C6 89 D7 F7 DE 83 D7 00 F7 DF 85 D2 78 26 89 FA 89 F0 89 D2 C1 FA 1F 89 D0 29 F0 19 FA 89 D0 31 D2 C1 E8 1F 84 C0 75 13 83 C4 0C 89 F0 89 FA 5B 5E 5F 5D C3 89 F8 C1 E8 1F EB E9 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __mulvsi3_09257319a31d4123d8c8f281280de4a0 {
	meta:
		aliases = "__mulvsi3"
		size = "60"
		objfiles = "_mulvsi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 45 0C F7 6D 08 89 C6 89 D0 89 F1 89 C2 C1 F9 1F C1 FA 1F 39 C1 75 0A 83 C4 0C 89 F0 5B 5E 5F 5D C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __absvdi2_aca87ef35f816b01c0c0c209253b973b {
	meta:
		aliases = "__absvdi2"
		size = "64"
		objfiles = "_absvdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 55 0C 8B 45 08 89 C6 89 D7 85 D2 78 0D 83 C4 0C 89 F0 89 FA 5B 5E 5F 5D C3 90 F7 DE 83 D7 00 F7 DF 85 FF 79 E8 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __addvdi3_e91a4fbb5f72fd6b616bc7fe9b27f37a {
	meta:
		aliases = "__addvdi3"
		size = "102"
		objfiles = "_addvdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 75 08 8B 45 10 01 F0 8B 7D 0C 8B 55 14 8B 4D 14 11 FA 89 45 E8 89 55 EC 85 C9 78 1E 39 D7 7E 0A E8 ?? ?? ?? ?? 90 8D 74 26 00 7D 1E 8B 45 E8 8B 55 EC 83 C4 0C 5B 5E 5F 5D C3 3B 7D EC 7C E1 7F EB 3B 75 E8 73 E6 EB D8 89 F6 39 C6 77 D2 EB DC }
	condition:
		$pattern
}

rule __subvdi3_cad0342903d42f3f252512c78615b9c5 {
	meta:
		aliases = "__subvdi3"
		size = "102"
		objfiles = "_subvdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 75 08 8B 7D 0C 89 F0 89 FA 2B 45 10 8B 4D 14 1B 55 14 89 45 E8 89 55 EC 85 C9 78 1E 39 D7 7D 0A E8 ?? ?? ?? ?? 90 8D 74 26 00 7E 1E 8B 45 E8 8B 55 EC 83 C4 0C 5B 5E 5F 5D C3 3B 7D EC 7F E1 7C EB 3B 75 E8 76 E6 EB D8 89 F6 39 C6 72 D2 EB DC }
	condition:
		$pattern
}

rule __divsc3_e01951d2b9766c6ea90db3222f0f8022 {
	meta:
		aliases = "__divsc3"
		size = "936"
		objfiles = "_divsc3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 7D 10 8B 4D 14 89 7D E8 8B 75 08 D9 45 E8 D9 E1 89 4D E8 D9 45 E8 D9 E1 DA E9 DF E0 F6 C4 45 75 5B 89 7D E8 D9 45 E8 89 4D E8 D9 45 E8 DE F9 89 7D E8 D9 45 E8 D8 C9 89 4D E8 D9 45 E8 DE C1 89 75 E8 D9 45 E8 D8 CA D8 45 0C D8 F1 D9 45 0C DE CB D9 45 E8 DE EB D9 CA DE F1 D9 C9 DD E0 DF E0 80 E4 45 80 FC 40 75 4A D9 5D E8 8B 45 E8 D9 5D E8 8B 55 E8 83 C4 0C 5B 5E 5F 5D C3 89 4D E8 D9 45 E8 89 7D E8 D9 45 E8 DC F9 89 4D E8 D9 45 E8 D8 CA 89 75 E8 DE C1 D9 45 0C D8 CA D9 45 E8 DC C1 D9 C9 D8 F2 D9 CB DE C9 D8 6D 0C DE F1 D9 C9 EB AA }
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

rule iterative_hash_0a1b85e9b13afdd435c3dfa167c5baf6 {
	meta:
		aliases = "iterative_hash"
		size = "841"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 14 8B 55 08 8B 45 10 F6 C2 03 89 55 E4 0F 85 DA 00 00 00 83 7D 0C 0B 0F 86 09 03 00 00 8B 4D 0C 89 C7 C7 45 E8 B9 79 37 9E C7 45 EC B9 79 37 9E 89 4D F0 90 8D 74 26 00 8B 5D E4 8B 45 E8 8B 55 EC 8B 33 8B 4B 04 01 F0 8B 73 08 01 CA 89 F9 29 D0 01 F1 89 CB 29 C8 C1 EB 0D 29 CA 31 D8 89 C3 29 C2 C1 E3 08 29 C1 31 DA 89 D3 29 D1 C1 EB 0D 29 D0 31 D9 89 CB 29 C8 C1 EB 0C 29 CA 31 D8 89 C3 29 C2 C1 E3 10 29 C1 31 DA 89 D3 29 D1 C1 EB 05 29 D0 31 D9 29 C8 29 CA 89 45 E8 89 C8 89 CF C1 E8 03 31 45 E8 8B 45 E8 8B 4D E8 29 C2 C1 E0 0A 29 CF 31 C2 83 6D F0 0C 89 D0 29 D7 C1 E8 0F }
	condition:
		$pattern
}

rule _Unwind_ForcedUnwind_Phase2_c814316fdd7ff31611406920b3ef398e {
	meta:
		aliases = "_Unwind_ForcedUnwind_Phase2"
		size = "202"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C 89 45 E4 89 D7 8B 55 E4 8B 40 0C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 52 10 89 45 E8 89 55 EC EB 7A 90 8D 74 26 00 8B 40 18 31 F6 89 45 F0 B8 0A 00 00 00 8B 4D EC 52 8B 55 E4 51 57 52 8B 55 E4 8B 4A 04 51 8B 12 52 50 6A 01 FF 55 E8 83 C4 20 85 C0 75 5D 83 FE 05 74 5D 8B 45 F0 85 C0 74 27 8B 75 E4 50 50 8B 45 E4 57 56 8B 48 04 51 8B 10 52 6A 0A 6A 01 FF 55 F0 83 C4 20 89 C6 83 F8 07 74 34 83 F8 08 75 2A 83 EC 0C 8B 07 50 E8 ?? ?? ?? ?? 8B 07 83 C4 10 8B 00 89 07 8B 07 85 C0 75 85 B0 1A BE 05 00 00 00 C7 45 F0 00 00 00 00 EB 82 BE 02 00 00 00 8D 65 F4 89 F0 5B 5E 5F }
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

rule execvp_9979608c49b26da7cb2a97c62a5b7896 {
	meta:
		aliases = "__GI_execvp, execvp"
		size = "442"
		objfiles = "execvp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C 8B 75 08 80 3E 00 75 10 E8 ?? ?? ?? ?? C7 00 02 00 00 00 E9 8E 01 00 00 50 50 6A 2F 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 79 57 FF 35 ?? ?? ?? ?? FF 75 0C 56 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 38 08 0F 85 5C 01 00 00 31 C0 EB 01 40 8D 14 85 00 00 00 00 8B 4D 0C 83 3C 11 00 75 EF 8D 42 26 83 E0 F0 29 C4 8B 01 8D 5C 24 0F 83 E3 F0 89 03 89 C8 83 C0 04 89 73 04 56 52 50 8D 43 08 50 E8 ?? ?? ?? ?? 83 C4 0C FF 35 ?? ?? ?? ?? 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 E9 04 01 00 00 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C7 85 C0 75 07 BF ?? ?? ?? ?? EB 09 }
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

rule read_encoded_value_with_base_511a60e70f6403967640455b41c95f3c {
	meta:
		aliases = "read_encoded_value_with_base"
		size = "205"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 89 55 DC 89 CE 89 C7 3C 50 74 20 25 FF 00 00 00 89 45 E0 83 E0 0F 83 F8 0C 76 05 E8 ?? ?? ?? ?? 8B 84 83 ?? ?? ?? ?? 01 D8 FF E0 8D 41 03 83 E0 FC 8B 10 8D 48 04 8B 45 08 89 10 83 C4 1C 89 C8 5B 5E 5F 5D C3 8D B6 00 00 00 00 8B 11 8D 49 04 85 D2 74 E2 8B 45 E0 83 E0 70 89 45 E0 83 7D E0 10 74 16 8B 75 DC 89 F8 01 F2 84 C0 79 C8 8B 12 EB C4 8B 11 8D 49 08 EB D7 89 75 DC EB E5 66 8B 01 8D 49 02 89 C2 81 E2 FF FF 00 00 EB C2 0F BF 11 8D 49 02 EB BA 8D 55 F0 89 C8 E8 1B FD FF FF 8B 55 F0 89 C1 EB A9 8D 55 F0 89 C8 E8 CA FC FF FF 8B 55 }
	condition:
		$pattern
}

rule get_cie_encoding_7439ee12cec8c233a799073f96cabfea {
	meta:
		aliases = "get_cie_encoding"
		size = "189"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 89 C6 8D 78 09 80 78 09 7A 74 0A 8D 65 F4 31 C0 5B 5E 5F 5D C3 83 EC 0C 57 E8 ?? ?? ?? ?? 8D 55 EC 83 C4 10 89 55 E0 8D 44 07 01 E8 FB FB FF FF 8D 55 E8 E8 33 FC FF FF 80 7E 08 01 74 67 8B 55 E0 E8 E5 FB FF FF 8B 55 E0 89 FE E8 DB FB FF FF 8A 57 01 80 FA 52 75 12 EB 3C 90 80 FA 4C 75 AB 8A 56 02 40 46 80 FA 52 74 2C 80 FA 50 75 EC 83 EC 0C 8D 48 01 8A 00 8D 55 F0 25 FF 00 00 00 52 83 E0 7F 31 D2 E8 11 FE FF FF 8A 56 02 83 C4 10 46 80 FA 52 75 D4 8A 00 8D 65 F4 25 FF 00 00 00 5B 5E 5F 5D C3 40 EB 9E }
	condition:
		$pattern
}

rule _Unwind_SjLj_RaiseException_1695d4fb6d87b8a69d0cf6746bf7f928 {
	meta:
		aliases = "_Unwind_SjLj_RaiseException"
		size = "173"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 83 ?? ?? ?? ?? 8B 75 08 89 45 F0 89 45 EC 85 C0 74 39 8D 7D EC EB 06 8D 76 00 89 45 EC 8B 40 18 85 C0 74 1E 52 52 57 56 8B 4E 04 51 8B 16 52 6A 01 6A 01 FF D0 83 C4 20 83 F8 06 74 1B 83 F8 08 75 48 8B 45 EC 8B 00 85 C0 75 CF B8 05 00 00 00 8D 65 F4 5B 5E 5F 5D C3 8B 45 EC C7 46 0C 00 00 00 00 89 46 10 8B 45 F0 89 45 EC 89 FA 89 F0 E8 F6 FD FF FF 83 F8 07 75 D7 8D 45 F0 89 FA E8 87 FE FF FF 8D B4 26 00 00 00 00 8D 65 F4 B8 03 00 00 00 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _Unwind_Backtrace_325530e37569860fa0885187ddc7b50a {
	meta:
		aliases = "_Unwind_Backtrace"
		size = "89"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 83 ?? ?? ?? ?? 8D 7D F0 89 45 F0 EB 0D 83 FE 05 74 27 8B 45 F0 8B 00 89 45 F0 83 7D F0 01 19 F6 50 50 8B 45 0C 50 57 FF 55 08 83 E6 05 83 C4 10 85 C0 74 D9 BE 03 00 00 00 8D 65 F4 89 F0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _Unwind_Find_FDE_d19f24e8a74f9ddb7a43bdb0b8de6fb4 {
	meta:
		aliases = "_Unwind_Find_FDE"
		size = "279"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B BB ?? ?? ?? ?? 8B 75 08 85 FF 75 09 EB 7A 8B 7F 14 85 FF 74 73 3B 37 72 F5 89 F2 89 F8 E8 88 F9 FF FF 89 45 E0 85 C0 74 5F 8B 55 0C 8B 47 04 89 02 8B 47 08 89 42 04 8B 47 10 66 C1 E8 03 F6 47 10 04 0F 85 A1 00 00 00 25 FF 00 00 00 25 FF 00 00 00 89 FA 89 C6 E8 8F EF FF FF 83 EC 0C 8B 4D E0 8D 55 F0 83 C1 08 52 89 C2 89 F0 E8 D9 EF FF FF 8B 55 0C 8B 45 F0 83 C4 10 89 42 08 8B 45 E0 8D 65 F4 5B 5E 5F 5D C3 C7 45 E0 00 00 00 00 8B BB ?? ?? ?? ?? 85 FF 74 E4 8B 47 14 89 F2 89 83 ?? ?? ?? ?? 89 F8 E8 FF F8 FF FF 8D 8B ?? ?? ?? ?? 89 }
	condition:
		$pattern
}

rule __mulxc3_d062517510dc1a67a0853483f2807a86 {
	meta:
		aliases = "__mulxc3"
		size = "1318"
		objfiles = "_mulxc3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? DB 6D 0C DB 6D 24 DC C9 8B 55 08 DB 6D 18 DB 6D 30 DC C9 DB 6D 0C DE C9 DB 6D 18 DE CB D9 C3 D8 E2 D9 C1 D8 C4 D9 C9 DD E0 DF E0 80 E4 45 80 FC 40 75 19 DD DC DD DC DD D8 DD D8 DB 3A 89 D0 DB 7A 0C 83 C4 1C 5B 5E 5F 5D C2 04 00 D9 C9 DD E0 DF E0 80 E4 45 80 FC 40 75 0A DD DD DD DB DD D8 DD D8 EB D7 DB 6D 0C D8 E0 DB 6D 0C DD E8 DF E0 80 E4 45 80 F4 40 0F 84 AF 00 00 00 DD D8 DB 6D 18 D8 E0 DB 6D 18 DD E8 DF E0 80 E4 45 80 F4 40 0F 84 32 04 00 00 DD D8 DB 6D 30 DD E8 DF E0 80 E4 45 80 F4 40 0F 95 C0 DB 6D 24 31 C9 88 C1 DD E8 DF E0 }
	condition:
		$pattern
}

rule __GI_pthread_cond_wait_a7e235d208fd518b972f8443ea9401c8 {
	meta:
		aliases = "pthread_cond_wait, __GI_pthread_cond_wait"
		size = "318"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C E8 ?? ?? ?? ?? 8B 7D 0C 89 45 F0 8B 75 08 8B 47 0C 83 F8 03 74 15 85 C0 74 11 8B 45 F0 BA 16 00 00 00 39 47 08 0F 85 00 01 00 00 8B 45 F0 89 75 E8 C7 45 EC ?? ?? ?? ?? 8D 55 E8 C6 80 B9 01 00 00 00 8B 45 F0 E8 ?? ?? ?? ?? 89 F0 8B 55 F0 E8 ?? ?? ?? ?? 8B 45 F0 80 78 42 00 74 0E 8B 45 F0 BB 01 00 00 00 80 78 40 00 74 0D 8B 55 F0 8D 46 08 E8 ?? ?? ?? ?? 31 DB 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 85 DB 74 0E 8B 45 F0 31 D2 E8 ?? ?? ?? ?? 57 57 EB 6E 83 EC 0C 31 DB 57 E8 ?? ?? ?? ?? 83 C4 10 8B 45 F0 E8 ?? ?? ?? ?? 8B 45 F0 80 B8 B9 01 00 00 00 75 18 8B 45 F0 80 B8 B8 01 }
	condition:
		$pattern
}

rule __mulsc3_493bc87654a853608f48ffdb1be818e0 {
	meta:
		aliases = "__mulsc3"
		size = "1316"
		objfiles = "_mulsc3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 24 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 75 08 8B 55 10 89 75 D8 8B 7D 0C D9 45 D8 89 55 D8 8B 4D 14 D9 45 D8 DC C9 D9 C9 89 7D D8 D9 5D F0 D9 45 D8 89 4D D8 D9 45 D8 DC C9 D9 C9 89 75 D8 D9 5D EC D9 45 D8 DE C9 89 7D D8 D9 5D E8 D9 45 D8 DE C9 D9 5D E4 D9 45 F0 D9 45 EC D9 C1 D8 E1 D9 45 E8 D9 45 E4 D9 C1 D8 C1 D9 CB DD E0 DF E0 80 E4 45 80 FC 40 75 1C DD DC DD D8 DD D8 DD DA D9 5D D8 8B 45 D8 D9 5D D8 8B 55 D8 83 C4 24 5B 5E 5F 5D C3 D9 CB DD E0 DF E0 80 E4 45 80 FC 40 75 0A DD DD DD D8 DD D8 DD D9 EB D4 89 75 D8 D9 45 D8 D8 E0 D9 45 D8 DD E8 DF E0 80 E4 45 80 F4 40 }
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

rule gaih_inet_serv_3c187d60a9d7386790f798ae1a2f44f1 {
	meta:
		aliases = "gaih_inet_serv"
		size = "147"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C 89 D3 89 45 D0 89 4D CC 8B 7D 08 BE 00 04 00 00 8D 46 1E 83 E0 F0 29 C4 8D 54 24 0F 50 50 8D 45 F0 50 83 E2 F0 8D 45 E0 56 52 50 8D 43 03 50 FF 75 D0 E8 ?? ?? ?? ?? 83 C4 20 85 C0 75 08 83 7D F0 00 75 0B EB 23 83 F8 22 75 1E 01 F6 EB C1 C7 07 00 00 00 00 0F BE 03 89 47 04 F6 43 02 02 74 0F 8B 55 CC 8B 42 0C EB 0B B8 08 01 00 00 EB 12 0F BE 43 01 89 47 08 8B 45 F0 8B 40 08 89 47 0C 31 C0 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule iruserok2_734b8a8bf8a39bcecf5e8b3dc0ffe86b {
	meta:
		aliases = "iruserok2"
		size = "331"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C 89 D6 89 45 CC 89 4D C8 85 D2 75 12 31 D2 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 85 C0 75 05 83 CF FF EB 28 57 57 FF 75 0C FF 75 C8 8B 4D 08 8B 55 CC E8 ?? ?? ?? ?? 89 1C 24 89 C7 E8 ?? ?? ?? ?? 83 C4 10 85 FF 0F 84 ED 00 00 00 0B 35 ?? ?? ?? ?? 0F 84 DE 00 00 00 83 EC 0C 6A 46 E8 ?? ?? ?? ?? 83 C4 10 8D 50 1E 83 E2 F0 29 D4 8D 55 F0 8D 4C 24 0F 83 EC 0C 83 E1 F0 52 50 8D 45 D4 51 50 FF 75 08 E8 ?? ?? ?? ?? 83 C4 20 85 C0 0F 85 A2 00 00 00 8B 45 F0 85 C0 0F 84 97 00 00 00 83 EC 0C FF 70 14 E8 ?? ?? ?? ?? 83 C0 09 89 04 24 E8 ?? ?? ?? ?? 89 C3 8B 45 F0 59 5E FF 70 14 53 }
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

rule htab_find_with_hash_3609c2534220bfe155de3a58bf39f710 {
	meta:
		aliases = "htab_find_with_hash"
		size = "330"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C 8B 45 08 C7 45 E4 00 00 00 00 8B 58 38 FF 40 1C 8B 50 10 8B 45 10 89 5D D4 C1 E3 04 8D 8B ?? ?? ?? ?? 89 55 DC 89 45 E0 F7 61 04 8B 49 0C 89 C6 8B 45 10 89 D7 89 FE 31 FF 8B 7D 10 89 F2 29 F0 D1 E8 01 C2 8B 83 ?? ?? ?? ?? D3 EA 0F AF D0 29 D7 8B 55 08 8B 72 0C 8B 1C BE 85 DB 0F 84 D5 00 00 00 83 FB 01 74 24 8B 45 0C 89 1C 24 89 44 24 04 FF 52 04 85 C0 0F 85 BB 00 00 00 8B 55 08 8B 5D 08 8B 52 38 8B 73 0C 89 55 D4 8B 4D D4 C1 E1 04 8D 81 ?? ?? ?? ?? 8B 99 ?? ?? ?? ?? 89 45 EC 8B 40 08 F7 65 E0 83 EB 02 89 D0 31 D2 89 C2 8B 45 10 29 D0 D1 E8 01 C2 8B 45 EC 8B 48 0C D3 }
	condition:
		$pattern
}

rule __getdents64_d6c8decc7479db773a13cab27d5369f5 {
	meta:
		aliases = "__getdents64"
		size = "276"
		objfiles = "getdents64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C 8B 45 10 8B 7D 08 83 C0 1E 8B 55 10 83 E0 F0 29 C4 8D 44 24 0F 83 E0 F0 89 45 D4 89 C1 53 89 FB B8 DC 00 00 00 CD 80 5B 89 45 EC 3D 00 F0 FF FF 76 0F E8 ?? ?? ?? ?? F7 5D EC 8B 55 EC 89 10 EB 5C 83 7D EC FF 74 56 8B 75 0C 8B 5D D4 C7 45 E0 FF FF FF FF C7 45 E4 FF FF FF FF E9 90 00 00 00 0F B7 43 10 8D 48 03 8B 45 0C 83 E1 FC 03 45 10 8D 3C 0E 89 7D DC 39 C7 76 28 6A 00 FF 75 E4 FF 75 E0 FF 75 08 E8 ?? ?? ?? ?? 83 C4 10 3B 75 0C 75 6C E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 61 8B 43 08 8B 53 0C 89 55 E4 89 45 E0 8B 03 8B 53 04 89 56 04 89 06 8B 43 08 8B 53 0C 89 }
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

rule reconcat_455c53b402f3168cbeae9563dad68d6f {
	meta:
		aliases = "reconcat"
		size = "179"
		objfiles = "concat@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C 8B 7D 0C 8D 45 10 89 45 F0 89 C3 85 FF 0F 84 7E 00 00 00 89 F8 31 F6 89 04 24 83 C3 04 E8 ?? ?? ?? ?? 01 C6 8B 43 FC 85 C0 75 EC 8D 46 01 89 04 24 E8 ?? ?? ?? ?? 89 45 DC 8D 45 10 8B 75 DC 89 45 F0 89 45 E0 89 F6 89 3C 24 E8 ?? ?? ?? ?? 89 7C 24 04 89 34 24 89 C3 89 44 24 08 01 DE E8 ?? ?? ?? ?? 83 45 E0 04 8B 45 E0 8B 78 FC 85 FF 75 D6 C6 06 00 8B 45 08 85 C0 74 0B 8B 45 08 89 04 24 E8 ?? ?? ?? ?? 8B 45 DC 83 C4 2C 5B 5E 5F 5D C3 C7 04 24 01 00 00 00 E8 ?? ?? ?? ?? 89 C6 8D 45 10 89 45 F0 89 75 DC EB C7 }
	condition:
		$pattern
}

rule __divdc3_667a39becfa9fdc725bfe858c1286fd9 {
	meta:
		aliases = "__divdc3"
		size = "917"
		objfiles = "_divdc3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? DD 45 0C 8B 75 1C 8B 7D 20 DD 5D E0 DD 45 14 89 75 C8 89 7D CC DD 5D D8 DD 45 24 8B 4D 08 DD 55 D0 DD 45 C8 D9 E1 D9 C1 D9 E1 DA E9 DF E0 F6 C4 45 75 3F DD 45 C8 D8 F1 DD 45 C8 D8 C9 DE C2 DD 45 E0 D8 C9 DC 45 D8 D8 F2 DD 45 D8 DE CA D9 C9 DC 65 E0 DE F2 DD E0 DF E0 80 E4 45 80 FC 40 75 43 DD 19 89 C8 DD 59 08 83 C4 2C 5B 5E 5F 5D C2 04 00 DD D8 89 75 C8 89 7D CC DD 45 C8 DC 7D D0 DD 45 D0 D8 C9 DD 45 C8 DE C1 DD 45 D8 D8 CA DC 45 E0 D8 F1 D9 CA DC 4D E0 DD 45 D8 DE E1 DE F1 D9 C9 EB B1 D9 C9 DD E0 DF E0 80 E4 45 80 FC 40 75 04 D9 }
	condition:
		$pattern
}

rule __GI_if_nameindex_5eb03edb3fb8ba3fcfe2f7fbe3f49b14 {
	meta:
		aliases = "if_nameindex, __GI_if_nameindex"
		size = "410"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C E8 ?? ?? ?? ?? C7 45 E0 00 00 00 00 89 45 D8 85 C0 0F 88 6F 01 00 00 C7 45 F0 00 00 00 00 BB 80 00 00 00 8D 0C 1B 8D 41 1E 83 E0 F0 29 C4 8D 54 24 0F 83 E2 F0 8D 04 0A 3B 45 F0 75 04 01 CB EB 02 89 CB 50 8D 45 EC 50 68 12 89 00 00 FF 75 D8 89 55 F0 89 5D EC E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 48 8B 45 EC 39 D8 74 BA C1 E8 05 83 EC 0C 89 45 DC 31 FF 8D 04 C5 08 00 00 00 50 E8 ?? ?? ?? ?? 83 C4 10 89 45 E0 85 C0 0F 85 CD 00 00 00 83 EC 0C FF 75 D8 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 69 00 00 00 E9 D9 00 00 00 83 EC 0C FF 75 D8 E8 ?? ?? ?? ?? C7 45 E0 00 00 00 00 E9 C2 00 }
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

rule htab_find_slot_with_hash_3dd1a2e17cbca5bba41baeac0d3fd09f {
	meta:
		aliases = "htab_find_slot_with_hash"
		size = "475"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 3C 8B 75 08 83 7D 14 01 8B 46 10 89 45 DC 0F 84 72 01 00 00 8B 4E 38 8B 45 10 8B 7D 10 C7 45 E4 00 00 00 00 89 CB C1 E3 04 89 4D D0 8D 8B ?? ?? ?? ?? 89 45 E0 F7 61 04 8B 49 0C 89 45 C8 89 D0 89 55 CC 31 D2 89 C2 8B 45 10 29 D0 D1 E8 01 C2 8B 83 ?? ?? ?? ?? D3 EA FF 46 1C 0F AF D0 29 D7 8B 56 0C 8D 1C BD 00 00 00 00 01 DA 8B 02 89 55 D4 85 C0 0F 84 E1 00 00 00 83 F8 01 74 31 8B 4D 0C 89 04 24 89 4C 24 04 FF 56 04 85 C0 74 13 8B 7E 0C 01 FB 89 5D D4 8B 45 D4 83 C4 3C 5B 5E 5F 5D C3 8B 46 38 C7 45 D4 00 00 00 00 89 45 D0 8B 5D D0 8B 4D E4 C1 E3 04 8D 93 ?? ?? ?? ?? 8B 9B }
	condition:
		$pattern
}

rule htab_expand_52fde2d286d41ebea88bb161d17af77a {
	meta:
		aliases = "htab_expand"
		size = "546"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 4C 89 45 C8 8B 40 0C 8B 55 C8 89 45 CC 89 D1 8B 72 38 8B 52 10 8B 59 18 8D 04 90 89 45 D0 8B 41 14 29 D8 8D 0C 00 39 CA 0F 82 83 01 00 00 C1 E0 03 39 C2 0F 87 6F 01 00 00 8B 4D C8 89 D3 8B 51 30 85 D2 0F 84 88 01 00 00 BF 04 00 00 00 89 7C 24 08 89 5C 24 04 8B 41 2C 89 04 24 FF D2 31 D2 85 C0 0F 84 36 01 00 00 8B 4D C8 89 41 0C 8B 41 18 29 41 14 8B 45 CC 89 59 10 89 71 38 C7 41 18 00 00 00 00 89 45 D4 EB 10 83 45 D4 04 8B 55 D4 39 55 D0 0F 86 EE 00 00 00 8B 55 D4 8B 12 83 FA 01 89 55 D8 76 E3 89 14 24 8B 4D C8 FF 11 8B 55 C8 C7 45 E4 00 00 00 00 89 45 DC 8B 42 38 C1 E0 }
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

rule callrpc_bb5b057af24e7322a51eb1c76b7feb2a {
	meta:
		aliases = "callrpc"
		size = "530"
		objfiles = "clnt_simple@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 4C C7 45 B8 00 00 00 00 C7 45 BC 00 00 00 00 C7 45 B0 00 00 00 00 C7 45 B4 00 00 00 00 E8 ?? ?? ?? ?? 8B 7D 0C 89 C3 8B B0 A4 00 00 00 85 F6 75 20 50 50 6A 18 6A 01 E8 ?? ?? ?? ?? 83 C4 10 89 C6 31 C0 85 F6 0F 84 B7 01 00 00 89 B3 A4 00 00 00 83 7E 14 00 75 1D 83 EC 0C 68 00 01 00 00 E8 ?? ?? ?? ?? 83 C4 10 89 46 14 C6 00 00 C7 46 04 FF FF FF FF 83 7E 10 00 74 25 39 7E 08 75 20 8B 45 10 39 46 0C 75 18 50 50 FF 75 08 FF 76 14 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 23 01 00 00 8B 46 04 C7 46 10 00 00 00 00 83 F8 FF 74 13 83 EC 0C 50 E8 ?? ?? ?? ?? C7 46 04 FF FF FF FF 83 C4 }
	condition:
		$pattern
}

rule dlopen_dcd943e0f52521888111742f7403d15c {
	meta:
		aliases = "dlopen"
		size = "1129"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 4C C7 45 F0 00 00 00 00 F6 45 0C 03 75 0F C7 05 ?? ?? ?? ?? 09 00 00 00 E9 3A 04 00 00 8B 7D 04 80 3D ?? ?? ?? ?? 00 75 1B C6 05 ?? ?? ?? ?? 01 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 83 7D 08 00 75 0A A1 ?? ?? ?? ?? E9 05 04 00 00 E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 89 D8 31 F6 EB 17 8B 08 8B 51 14 39 FA 73 0B 85 F6 74 05 39 56 14 73 02 89 CE 8B 40 10 85 C0 75 E5 89 5D F0 EB 03 89 45 F0 8B 45 F0 89 45 C0 85 C0 74 07 8B 40 10 85 C0 75 EC 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 C7 45 D0 02 00 00 00 85 C0 75 09 8B 4D 0C 83 E1 02 89 4D D0 83 EC 0C }
	condition:
		$pattern
}

rule __muldc3_c763231fbfa76dd1f81981520204399e {
	meta:
		aliases = "__muldc3"
		size = "1449"
		objfiles = "_muldc3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 54 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? DD 45 0C 8B 55 1C 8B 4D 20 DD 5D C0 DD 45 14 89 55 B0 89 4D B4 DD 55 B8 DD 45 B0 DC 4D C0 8B 75 24 8B 7D 28 89 75 B0 89 7D B4 DD 5D E8 DD 45 B0 D8 C9 DD 5D E0 DD 45 B0 DC 4D C0 89 55 B0 89 4D B4 DD 5D D8 DD 45 B0 DE C9 DD 5D D0 DD 45 E8 DD 45 E0 D9 C1 D8 E1 DD 45 D8 DD 45 D0 D9 C1 D8 C1 D9 CB DD E0 DF E0 80 E4 45 80 FC 40 75 1A DD DC DD D8 DD D8 DD DA 8B 45 08 DD 18 DD 58 08 83 C4 54 5B 5E 5F 5D C2 04 00 D9 CB DD E0 DF E0 80 E4 45 80 FC 40 75 0A DD DD DD D8 DD D8 DD D9 EB D6 DD 45 C0 D8 E0 DD 45 C0 DD E8 DF E0 80 E4 45 80 F4 40 0F }
	condition:
		$pattern
}

rule byte_re_compile_fastmap_b5de09cce3407a234a1c8c1e40c50f95 {
	meta:
		aliases = "byte_re_compile_fastmap"
		size = "800"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 5C 89 C6 8B 40 10 89 45 E0 8B 1E 8B 56 08 8D 44 24 0F 01 DA 83 E0 F0 89 55 E4 89 45 F0 0F 84 E8 02 00 00 57 68 00 01 00 00 6A 00 31 FF FF 75 E0 E8 ?? ?? ?? ?? 8A 46 1C 83 C8 08 83 C4 10 83 E0 FE C6 45 EA 01 88 46 1C C6 45 EB 00 C7 45 EC 05 00 00 00 EB 07 8B 5D E4 C6 45 EA 00 3B 5D E4 74 06 8A 03 3C 01 75 28 85 FF 8A 56 1C 0F 84 84 02 00 00 88 D0 83 E2 FE 83 E0 01 4F 0A 45 EA 09 C2 8B 45 F0 88 56 1C 8B 1C B8 C6 45 EA 01 EB CD 0F B6 C0 43 83 F8 1D 0F 87 55 02 00 00 FF 24 85 ?? ?? ?? ?? 31 D2 E9 CC 00 00 00 31 D2 E9 E6 00 00 00 80 4E 1C 01 E9 4D 02 00 00 0F B6 43 01 8B 55 }
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

rule __mulvdi3_304bef162af6644a5bae3dbb7e0194cb {
	meta:
		aliases = "__mulvdi3"
		size = "449"
		objfiles = "_mulvdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 5C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 45 08 8B 55 0C 89 45 B8 8B 45 10 8B 7D B8 89 55 BC 89 45 B0 89 F8 8B 55 14 8B 4D BC C1 F8 1F 89 55 B4 39 C1 75 25 89 D1 8B 55 B0 89 D0 89 55 A4 C1 F8 1F 39 C1 75 78 89 D0 F7 EF 89 C6 89 D7 83 C4 5C 89 F0 89 FA 5B 5E 5F 5D C3 8B 45 B0 8B 55 B4 89 45 DC C1 F8 1F 39 C2 0F 85 C5 00 00 00 8B 55 DC C7 45 E4 00 00 00 00 89 55 E0 8B 45 E0 F7 E7 89 45 C0 8B 45 E0 89 55 A8 89 55 C4 F7 E1 85 C9 89 C6 89 D7 78 7E 8B 45 DC 85 C0 78 6F 8B 55 A8 31 C9 01 F2 11 F9 89 D0 C1 F8 1F 39 C8 0F 85 A1 00 00 00 89 55 C4 8B 75 C0 8B 7D C4 EB 90 89 7D E8 }
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

rule __msgwrite_5031c64693b1ede4752fa23a8499b89e {
	meta:
		aliases = "__msgwrite"
		size = "179"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 6C 89 D6 89 CF 89 45 C0 E8 ?? ?? ?? ?? 8D 5C 24 0F 89 45 E0 E8 ?? ?? ?? ?? 89 45 E4 E8 ?? ?? ?? ?? 83 E3 F0 89 45 E8 50 8D 45 E0 6A 0C 50 8D 43 0C 50 E8 ?? ?? ?? ?? 8D 45 EC C7 43 04 01 00 00 00 C7 43 08 02 00 00 00 C7 03 18 00 00 00 89 75 EC 89 7D F0 89 45 CC C7 45 D0 01 00 00 00 C7 45 C4 00 00 00 00 C7 45 C8 00 00 00 00 89 5D D4 C7 45 D8 18 00 00 00 C7 45 DC 00 00 00 00 83 C4 10 50 8D 45 C4 6A 00 50 FF 75 C0 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 0D E8 ?? ?? ?? ?? 83 38 04 74 E0 83 C8 FF 8D 65 F4 5B 5E 5F 5D C3 }
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

rule rcmd_505da2628fc2c74d9d35bc42b4a81e26 {
	meta:
		aliases = "rcmd"
		size = "1156"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 7C BE 00 04 00 00 8B 45 0C 66 89 45 86 E8 ?? ?? ?? ?? 81 EC 10 04 00 00 89 45 8C 8D 54 24 0F 83 E2 F0 EB 3C 8B 5D EC 83 FB FF 75 0A E8 ?? ?? ?? ?? 83 38 22 74 19 E8 ?? ?? ?? ?? 83 EC 0C 89 18 8B 55 08 FF 32 E8 ?? ?? ?? ?? E9 18 04 00 00 01 F6 8D 46 1E 83 E0 F0 29 C4 8D 54 24 0F 83 E2 F0 8D 45 EC 57 57 50 8D 45 E4 50 8D 45 94 56 52 50 8B 45 08 FF 30 E8 ?? ?? ?? ?? 83 C4 20 85 C0 75 A3 8B 45 E4 85 C0 74 9C 66 C7 45 CC 01 00 66 C7 45 D4 01 00 8B 55 08 8B 00 83 EC 0C BF 01 00 00 00 89 02 68 00 00 40 00 E8 ?? ?? ?? ?? C7 45 E0 FF 03 00 00 89 45 88 83 C4 10 83 EC 0C 8D 75 E0 }
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

rule execle_d1aef69061b32c529a1b68035d6dc64b {
	meta:
		aliases = "__GI_execle, execle"
		size = "111"
		objfiles = "execle@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 8D 45 10 83 EC 1C 31 F6 89 45 F0 8B 55 F0 46 8D 42 04 89 45 F0 83 3A 00 75 F1 8D 42 08 89 45 F0 8D 04 B5 22 00 00 00 83 E0 F0 8B 7A 04 29 C4 8B 45 0C 8D 5C 24 0F 83 E3 F0 89 D9 89 03 8D 45 10 89 45 F0 8B 45 F0 83 C1 04 4E 8D 50 04 89 55 F0 8B 00 89 01 75 ED 50 57 53 FF 75 08 E8 ?? ?? ?? ?? 8D 65 F4 5B 5E 5F 5D C3 }
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

rule __divxc3_db1227d6bfc28f9901b4e29ac5b46d30 {
	meta:
		aliases = "__divxc3"
		size = "867"
		objfiles = "_divxc3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 DB 6D 24 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? D9 E1 DB 6D 30 D9 E1 DA E9 DF E0 8B 4D 08 F6 C4 45 75 49 DB 6D 24 DB 6D 30 DE F9 DB 6D 24 D8 C9 DB 6D 30 DE C1 DB 6D 0C D8 CA DB 6D 18 DC C1 D9 C9 D8 F2 D9 C9 DE CB DB 6D 0C DE EB D9 CA DE F1 D9 C9 DD E0 DF E0 80 E4 45 80 FC 40 75 3A DB 39 89 C8 DB 79 0C 5B 5E 5F 5D C2 04 00 DB 6D 30 DB 6D 24 DC F9 DB 6D 30 D8 CA DE C1 DB 6D 18 D8 CA DB 6D 0C DC C1 D9 C9 D8 F2 D9 CB DE C9 DB 6D 18 DE E1 DE F1 D9 C9 EB BA D9 C9 DD E0 DF E0 80 E4 45 80 FC 40 75 04 D9 C9 EB B4 D9 83 ?? ?? ?? ?? DB 6D 24 DD E9 DF E0 80 E4 45 80 F4 40 75 13 DB 6D 30 DD }
	condition:
		$pattern
}

rule frame_heapsort_5f7e378c3a732f2ba7e9bbafa5310ff3 {
	meta:
		aliases = "frame_heapsort"
		size = "128"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 10 89 45 EC 8D 41 08 8B 49 04 89 45 F0 89 C8 D1 E8 89 55 E8 89 C6 89 4D F4 4E 78 1B 50 50 8B 45 F4 8B 4D F0 50 8B 55 E8 56 8B 45 EC E8 08 FF FF FF 83 C4 10 4E 79 E5 8B 7D F4 4F 85 FF 7E 33 8B 55 F4 8B 4D F0 8D 74 91 FC 8B 45 F0 8B 4D F0 8B 10 8B 06 89 01 89 16 8B 55 E8 50 50 8B 45 EC 57 4F 6A 00 83 EE 04 E8 CE FE FF FF 83 C4 10 85 FF 7F D7 8D 65 F8 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __ashrdi3_c8efd75c773a602995b4f84635b0451a {
	meta:
		aliases = "__ashrdi3"
		size = "117"
		objfiles = "_ashrdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 10 8B 45 08 8B 55 0C 8B 75 10 89 45 E8 89 55 EC 85 F6 74 3A C7 45 F4 20 00 00 00 8B 55 10 8B 4D F4 29 D1 89 4D F4 8B 45 F4 85 C0 7E 2E 8B 45 EC 8A 4D 10 89 C7 8B 55 E8 D3 FF 8A 4D F4 D3 E0 8A 4D 10 89 C6 D3 EA 09 D6 89 75 E8 89 7D EC 8B 45 E8 8B 55 EC 83 C4 10 5E 5F 5D C3 8B 45 EC 8B 4D F4 89 C7 89 C6 F7 D9 C1 FF 1F D3 FE EB DA }
	condition:
		$pattern
}

rule fde_single_encoding_compare_e7c92e97bfde018187f2cccbc32f77d4 {
	meta:
		aliases = "fde_single_encoding_compare"
		size = "122"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 10 8B 75 08 89 F2 8B 46 10 66 C1 E8 03 25 FF 00 00 00 E8 B2 FE FF FF 83 EC 0C 89 C7 8B 46 10 8B 4D 0C 8D 55 F4 66 C1 E8 03 52 83 C1 08 25 FF 00 00 00 89 FA E8 F0 FE FF FF 8B 46 10 8B 4D 10 8D 55 F0 66 C1 E8 03 89 14 24 83 C1 08 25 FF 00 00 00 89 FA E8 D1 FE FF FF 8B 45 F0 83 C4 10 BA 01 00 00 00 39 45 F4 77 02 19 D2 8D 65 F8 89 D0 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fde_mixed_encoding_compare_a513fb487be6421b9853948d49f7ead5 {
	meta:
		aliases = "fde_mixed_encoding_compare"
		size = "146"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 10 8B 7D 0C 8B 77 04 8D 47 04 29 F0 E8 78 F8 FF FF 8B 55 08 89 C6 81 E6 FF 00 00 00 89 F0 E8 B6 F6 FF FF 83 EC 0C 8D 55 F4 8D 4F 08 52 89 C2 89 F0 E8 03 F7 FF FF 8B 55 10 8B 45 10 8B 4A 04 83 C0 04 29 C8 E8 40 F8 FF FF 8B 55 08 89 C6 81 E6 FF 00 00 00 89 F0 E8 7E F6 FF FF 8B 4D 10 8D 55 F0 83 C1 08 89 14 24 89 C2 89 F0 E8 C9 F6 FF FF 8B 45 F0 83 C4 10 BA 01 00 00 00 39 45 F4 77 02 19 D2 8D 65 F8 89 D0 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __muldi3_2faa60df3e6d438e73b8e2e5b8537b60 {
	meta:
		aliases = "__muldi3"
		size = "69"
		objfiles = "_muldi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 10 C7 45 EC 00 00 00 00 8B 4D 08 8B 75 10 8B 7D 0C 89 C8 F7 E6 0F AF F7 8B 7D 14 89 55 EC 0F AF CF 8B 55 EC C7 45 E8 00 00 00 00 01 D1 89 45 E8 01 CE 8B 45 E8 89 F2 83 C4 10 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __ashldi3_2d71a16e20a4ad8bfed74c98cd79ff31 {
	meta:
		aliases = "__ashldi3"
		size = "117"
		objfiles = "_ashldi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 10 C7 45 F0 00 00 00 00 8B 45 10 C7 45 F4 00 00 00 00 8B 75 08 8B 7D 0C 85 C0 74 35 BA 20 00 00 00 8B 4D 10 29 CA 85 D2 7E 32 8A 4D 10 89 F0 D3 E0 89 75 EC 88 D1 D3 6D EC 89 FA 8A 4D 10 89 45 F0 8B 45 EC D3 E2 09 C2 89 55 F4 8B 75 F0 8B 7D F4 83 C4 10 89 F0 89 FA 5E 5F 5D C3 89 D1 C7 45 F0 00 00 00 00 F7 D9 D3 E6 89 75 F4 EB DD }
	condition:
		$pattern
}

rule __lshrdi3_3cb3bb015bde3a94063662a9e61350fb {
	meta:
		aliases = "__lshrdi3"
		size = "119"
		objfiles = "_lshrdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 10 C7 45 F0 00 00 00 00 8B 45 10 C7 45 F4 00 00 00 00 8B 75 08 8B 7D 0C 85 C0 74 35 BA 20 00 00 00 8B 4D 10 29 CA 85 D2 7E 32 8A 4D 10 89 F8 D3 E8 89 7D EC 88 D1 D3 65 EC 89 F2 8A 4D 10 89 45 F4 8B 45 EC D3 EA 09 C2 89 55 F0 8B 75 F0 8B 7D F4 83 C4 10 89 F0 89 FA 5E 5F 5D C3 89 D1 89 F8 F7 D9 D3 E8 C7 45 F4 00 00 00 00 89 45 F0 EB DB }
	condition:
		$pattern
}

rule frame_downheap_277c3e40a04669dc640b15c8285713f0 {
	meta:
		aliases = "frame_downheap"
		size = "183"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 20 89 45 EC 8B 45 08 89 55 E8 89 4D E4 8D 7C 00 01 3B 7D 0C 0F 8D 8F 00 00 00 89 45 F0 EB 3A 8B 55 F0 8B 4D E4 50 8B 45 F4 8D 34 91 8B 00 50 8B 06 50 8B 45 EC 50 FF 55 E8 83 C4 10 85 C0 79 69 8B 4D F4 8B 16 89 7D F0 8B 01 89 06 8D 44 3F 01 89 11 39 45 0C 7E 52 89 C7 8B 45 E4 8D 77 01 39 75 0C 8D 04 B8 89 45 F4 7E B5 8D 04 BD 00 00 00 00 51 8B 4D E4 8B 55 E4 01 C2 8B 4C 01 04 89 55 F4 51 8B 02 50 8B 45 EC 50 FF 55 E8 83 C4 10 85 C0 79 8C 8B 45 E4 89 F7 8D 04 B0 89 45 F4 E9 7C FF FF FF 8D B6 00 00 00 00 8D 65 F8 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __udivdi3_d03b49869bcbf204f79abc412550c8be {
	meta:
		aliases = "__udivdi3"
		size = "307"
		objfiles = "_udivdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 28 C7 45 D8 00 00 00 00 8B 45 10 8B 55 14 89 D7 89 45 F4 89 C1 8B 55 0C 8B 45 08 C7 45 DC 00 00 00 00 89 45 EC 89 55 E8 85 FF 75 21 39 D1 0F 86 85 00 00 00 F7 F1 89 C1 31 C0 89 45 DC 89 4D D8 8B 45 D8 8B 55 DC 83 C4 28 5E 5F 5D C3 3B 7D E8 0F 87 93 00 00 00 0F BD C7 83 F0 1F 89 45 E4 74 78 8B 55 E4 B8 20 00 00 00 29 D0 8A 4D E4 89 45 F0 89 FA D3 E2 8B 45 F4 8A 4D F0 D3 E8 89 D7 8A 4D E4 09 C7 8B 75 F4 8B 45 E8 8B 55 EC D3 E6 D3 E0 8A 4D F0 D3 EA 09 D0 8B 55 E8 D3 EA 89 45 D4 F7 F7 89 D7 89 45 D0 F7 E6 89 C6 39 D7 72 72 74 64 8B 4D D0 31 C0 EB 82 90 8B 75 F4 85 F6 74 39 8B }
	condition:
		$pattern
}

rule __umoddi3_4f3c48048568a525c9b818a7eeb600d5 {
	meta:
		aliases = "__umoddi3"
		size = "415"
		objfiles = "_umoddi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 30 C7 45 D0 00 00 00 00 8B 45 10 8B 55 14 8B 75 08 8B 7D 0C C7 45 D4 00 00 00 00 89 45 EC 89 C1 89 55 E8 89 75 F0 89 7D E0 85 D2 75 2C 89 FA 39 F8 0F 86 E4 00 00 00 89 F0 F7 F1 89 55 D0 C7 45 D4 00 00 00 00 8B 45 D0 8B 55 D4 83 C4 30 5E 5F 5D C3 8D B4 26 00 00 00 00 8B 4D E0 39 4D E8 76 18 89 75 D0 89 7D D4 8B 45 D0 8B 55 D4 83 C4 30 5E 5F 5D C3 90 8D 74 26 00 0F BD 45 E8 83 F0 1F 89 45 DC 0F 84 C0 00 00 00 8B 55 DC B8 20 00 00 00 29 D0 8A 4D DC 89 45 E4 8B 55 E8 D3 E2 8B 45 EC 8A 4D E4 D3 E8 09 C2 8A 4D DC 8B 75 EC 8B 45 E0 D3 E6 D3 E0 89 55 F4 8A 4D E4 8B 55 F0 8B 7D F0 }
	condition:
		$pattern
}

rule __divdi3_1bfcb3148416c6ec7100df590110b7d7 {
	meta:
		aliases = "__divdi3"
		size = "407"
		objfiles = "_divdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 30 C7 45 D0 00 00 00 00 8B 55 0C 8B 45 08 89 55 DC 8B 75 10 8B 7D 14 8B 4D DC 89 45 D8 C7 45 D4 00 00 00 00 89 F0 89 FA C7 45 E4 00 00 00 00 85 C9 0F 88 02 01 00 00 85 FF 0F 88 E1 00 00 00 89 D7 89 C6 89 C1 8B 55 D8 8B 45 DC 89 55 F0 89 45 EC 85 FF 75 24 39 C6 77 51 85 F6 0F 84 08 01 00 00 8B 45 EC 89 FA F7 F1 89 C6 8B 45 F0 F7 F1 89 C1 89 F0 EB 14 8D 74 26 00 3B 7D EC 76 3B 31 C9 31 C0 8D B4 26 00 00 00 00 89 4D D0 89 45 D4 8B 4D E4 8B 45 D0 8B 55 D4 85 C9 74 07 F7 D8 83 D2 00 F7 DA 83 C4 30 5E 5F 5D C3 89 D0 8B 55 EC F7 F6 89 C1 31 C0 EB D2 89 F6 0F BD C7 83 F0 1F 89 45 }
	condition:
		$pattern
}

rule __udivmoddi4_507c85e3db6bdc180a8cd408a78fd94b {
	meta:
		aliases = "__udivmoddi4"
		size = "529"
		objfiles = "_udivmoddi4@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 38 C7 45 D0 00 00 00 00 8B 45 10 8B 55 14 8B 75 08 8B 7D 0C C7 45 D4 00 00 00 00 C7 45 C8 00 00 00 00 C7 45 CC 00 00 00 00 89 45 D8 89 45 E0 89 55 C4 89 75 EC 89 7D E4 85 D2 75 3D 39 F8 0F 86 2D 01 00 00 31 C9 89 F0 89 FA F7 75 D8 8B 75 18 85 F6 74 18 89 55 D0 C7 45 D4 00 00 00 00 8B 55 18 8B 75 D0 8B 7D D4 89 32 89 7A 04 89 C2 89 C8 EB 2E 8D B4 26 00 00 00 00 8B 4D E4 39 4D C4 76 38 8B 45 18 85 C0 74 14 8B 45 18 89 75 D0 89 7D D4 8B 75 D0 8B 7D D4 89 30 89 78 04 31 D2 31 C0 89 55 C8 89 45 CC 8B 55 CC 8B 45 C8 83 C4 38 5E 5F 5D C3 8D B6 00 00 00 00 0F BD 45 C4 83 F0 1F 89 }
	condition:
		$pattern
}

rule __moddi3_60c88c9d15aa694a2d703c09da92ac75 {
	meta:
		aliases = "__moddi3"
		size = "507"
		objfiles = "_moddi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 50 C7 45 B8 00 00 00 00 8B 45 10 8B 55 14 8B 7D 0C C7 45 BC 00 00 00 00 89 45 B0 89 55 B4 8B 75 08 C7 45 C4 00 00 00 00 85 FF 0F 88 5C 01 00 00 8B 4D B4 85 C9 0F 88 3F 01 00 00 8D 4D F0 89 45 D8 89 4D DC 89 55 D4 89 C1 89 75 E0 89 7D CC 85 D2 75 28 89 FA 39 F8 0F 86 04 01 00 00 89 F0 F7 F1 89 55 B8 C7 45 BC 00 00 00 00 8B 4D DC 8B 45 B8 8B 55 BC 89 01 89 51 04 EB 1E 8B 45 CC 39 45 D4 76 36 89 75 B8 89 7D BC 8B 55 B8 8B 4D BC 89 55 F0 89 4D F4 8D 74 26 00 8B 45 C4 85 C0 74 0A F7 5D F0 83 55 F4 00 F7 5D F4 8B 45 F0 8B 55 F4 83 C4 50 5E 5F 5D C3 89 F6 0F BD 45 D4 83 F0 1F 89 }
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

rule add_fdes_67020cdbab87321b0a2e79cbfb873d9b {
	meta:
		aliases = "add_fdes"
		size = "284"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 89 CF 83 EC 30 89 55 D4 89 45 D8 89 C2 8B 40 10 66 C1 E8 03 25 FF 00 00 00 89 45 E0 E8 CA FB FF FF 89 45 E4 8B 07 85 C0 0F 84 E2 00 00 00 C7 45 DC 00 00 00 00 EB 38 8D 74 26 00 8B 4F 08 85 C9 74 19 8B 45 D4 8B 10 85 D2 74 10 8B 42 04 89 7C 82 08 40 89 42 04 90 8D 74 26 00 89 F8 8B 17 01 D0 8D 78 04 8B 40 04 85 C0 0F 84 A1 00 00 00 8B 47 04 85 C0 74 E5 8B 55 D8 F6 42 10 04 74 2C 8D 77 04 29 C6 39 75 DC 74 22 89 F0 E8 0B FD FF FF 8B 55 D8 89 45 E0 31 C0 8A 45 E0 E8 4B FB FF FF 89 75 DC 89 45 E4 90 8D 74 26 00 8B 75 E0 85 F6 74 89 8A 45 E0 83 EC 0C 25 FF 00 00 00 8B 55 E4 89 C6 8D }
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

rule classify_object_over_fdes_0809f2e3d2dd942c272f5f6e3a5ad8b7 {
	meta:
		aliases = "classify_object_over_fdes"
		size = "334"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 89 D6 83 EC 30 89 45 D0 8B 02 C7 45 D8 00 00 00 00 85 C0 0F 84 FF 00 00 00 31 D2 C7 45 DC 00 00 00 00 C7 45 E0 00 00 00 00 EB 2B 8B 7D D8 8B 4D D0 47 89 7D D8 39 11 0F 86 C4 00 00 00 89 11 8B 55 E4 89 F0 8B 0E 01 C8 8D 70 04 8B 40 04 85 C0 0F 84 C2 00 00 00 8B 46 04 85 C0 74 E5 8D 4E 04 29 C1 89 4D E4 39 D1 0F 84 B5 00 00 00 8B 45 E4 E8 06 FC FF FF 88 C2 89 45 DC 81 E2 FF 00 00 00 88 45 D7 89 D7 8B 55 D0 89 F8 E8 3C FA FF FF 8B 4D D0 89 45 E0 8B 41 10 25 F8 07 00 00 66 3D F8 07 0F 84 87 00 00 00 8B 55 D0 8B 42 10 66 C1 E8 03 25 FF 00 00 00 39 45 DC 74 04 80 4A 10 04 83 EC 0C 8D }
	condition:
		$pattern
}

rule linear_search_fdes_44621ec1548ed0563212bb814fa4f29b {
	meta:
		aliases = "linear_search_fdes"
		size = "308"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 89 D7 83 EC 30 89 45 D8 89 4D D4 89 C2 8B 40 10 66 C1 E8 03 25 FF 00 00 00 89 45 E0 E8 0A FD FF FF 8B 37 89 45 E4 85 F6 0F 84 F6 00 00 00 C7 45 DC 00 00 00 00 EB 39 8D 74 26 00 8B 57 08 89 55 F4 85 D2 8B 47 0C 89 45 F0 74 11 8B 45 D4 8B 55 F4 29 D0 3B 45 F0 0F 82 CA 00 00 00 89 F8 8B 37 01 F0 8B 48 04 8D 78 04 85 C9 0F 84 B4 00 00 00 8B 47 04 85 C0 74 E5 8B 55 D8 F6 42 10 04 74 2B 8D 77 04 29 C6 39 75 DC 74 21 89 F0 E8 4A FE FF FF 8B 55 D8 89 45 E0 31 C0 8A 45 E0 E8 8A FC FF FF 89 75 DC 89 45 E4 8D 74 26 00 8B 4D E0 85 C9 74 89 8A 45 E0 83 EC 0C 25 FF 00 00 00 8D 4F 08 89 C6 8D }
	condition:
		$pattern
}

rule __gcc_bcmp_3226f26563642b07bfe42ee783aa1504 {
	meta:
		aliases = "__gcc_bcmp"
		size = "76"
		objfiles = "__gcc_bcmp@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 8B 55 10 8B 7D 0C 85 D2 74 24 8B 45 08 31 F6 8A 08 8A 07 38 C1 74 14 EB 1D 89 F6 8B 45 08 8A 4C 06 01 8A 44 3E 01 46 38 C1 75 0B 4A 75 ED 31 D2 5E 89 D0 5F 5D C3 31 D2 25 FF 00 00 00 88 CA 5E 29 C2 5F 89 D0 5D C3 }
	condition:
		$pattern
}

rule __negdi2_f5b364febb08ec522c1830b1981ecccc {
	meta:
		aliases = "__negdi2"
		size = "36"
		objfiles = "_negdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 8B 7D 08 8B 75 0C F7 DE 85 FF 0F 95 C1 81 E1 FF 00 00 00 29 CE F7 DF 89 F8 89 F2 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __ucmpdi2_396f017ee7e339fe57ade6bc14e0f933 {
	meta:
		aliases = "__ucmpdi2"
		size = "51"
		objfiles = "_ucmpdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 8B 7D 0C 8B 55 14 8B 75 08 8B 45 10 39 D7 72 11 77 06 39 C6 72 0B 76 0F B8 02 00 00 00 5E 5F 5D C3 31 C0 5E 5F 5D C3 B8 01 00 00 00 EB EF }
	condition:
		$pattern
}

rule __cmpdi2_783fb819ce09af2f4a1fdd9650feee2b {
	meta:
		aliases = "__cmpdi2"
		size = "51"
		objfiles = "_cmpdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 8B 7D 0C 8B 55 14 8B 75 08 8B 45 10 39 D7 7C 11 7F 06 39 C6 72 0B 76 0F B8 02 00 00 00 5E 5F 5D C3 31 C0 5E 5F 5D C3 B8 01 00 00 00 EB EF }
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

rule __gnat_default_lock_939a034664c2b3234964a30decbd1f50 {
	meta:
		aliases = "__gcov_merge_add, hex_init, __gcov_init, __gcov_merge_single, __gcov_merge_delta, __gcov_flush, pex_unix_cleanup, __gnat_default_unlock, __clear_cache, __enable_execute_stack, __gnat_default_lock"
		size = "5"
		objfiles = "gthr_gnat@libgcc.a, _gcov_merge_add@libgcov.a, _gcov@libgcov.a, hex@libiberty.a, _gcov_merge_single@libgcov.a"
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
		aliases = "splay_tree_xmalloc_deallocate, partition_delete, splay_tree_xmalloc_allocate"
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

rule __do_global_dtors_aux_5c3b0af7193dd9fec60c65089a83d1c1 {
	meta:
		aliases = "__do_global_dtors_aux"
		size = "161"
		objfiles = "crtbeginT, crtbegin"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 80 3D ?? ?? ?? ?? 00 74 0C EB 35 83 C0 04 A3 ?? ?? ?? ?? FF D2 A1 ?? ?? ?? ?? 8B 10 85 D2 75 EB B8 ?? ?? ?? ?? 85 C0 74 10 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 C6 05 ?? ?? ?? ?? 01 C9 C3 90 8D B4 26 00 00 00 00 55 B8 ?? ?? ?? ?? 89 E5 83 EC 08 E8 00 00 00 00 5A 81 C2 ?? ?? ?? ?? 85 C0 74 15 52 6A 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 A1 ?? ?? ?? ?? 85 C0 74 16 B8 ?? ?? ?? ?? 85 C0 74 0D 83 EC 0C 68 ?? ?? ?? ?? FF D0 83 C4 10 C9 C3 }
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

rule _Unwind_DeleteException_0618b99142f535676beeb626500df4e1 {
	meta:
		aliases = "_Unwind_DeleteException"
		size = "28"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 8B 55 08 8B 42 08 85 C0 74 0A 51 51 52 6A 01 FF D0 83 C4 10 C9 C3 }
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

rule htab_find_00d1787881f237551fbc42d1cbc4328b {
	meta:
		aliases = "htab_remove_elt, htab_find"
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

rule _Unwind_GetIP_5178ae0015ce09d43f6b257115a785f2 {
	meta:
		aliases = "_Unwind_GetIP"
		size = "14"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 5D 8B 00 8B 40 04 40 C3 }
	condition:
		$pattern
}

rule _Unwind_GetLanguageSpecificDat_db2ca7ad0509ff40bc44f5b5339a7dac {
	meta:
		aliases = "_Unwind_GetLanguageSpecificData"
		size = "13"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 5D 8B 00 8B 40 1C C3 }
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

rule _Unwind_SetIP_b770eeb82fb02dcc792dfcdd24557910 {
	meta:
		aliases = "_Unwind_SetIP"
		size = "17"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 10 8B 45 0C 48 89 42 04 5D C3 }
	condition:
		$pattern
}

rule _Unwind_GetGR_cd9365e5820d040545eb89d1a212d6d5 {
	meta:
		aliases = "_Unwind_GetGR"
		size = "17"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 10 8B 45 0C 5D 8B 44 82 08 C3 }
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

rule __paritydi2_a09aade3f40fb1b59922caef0d41aa23 {
	meta:
		aliases = "__paritydi2"
		size = "47"
		objfiles = "_paritydi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 55 0C 31 C2 5D 89 D0 C1 E8 10 31 D0 89 C1 C1 E9 08 31 C1 89 C8 C1 E8 04 31 C1 B8 96 69 00 00 83 E1 0F D3 F8 83 E0 01 C3 }
	condition:
		$pattern
}

rule __ctzdi2_2b54d5ac3ca5ac2b1a8f0b7e67cff1bc {
	meta:
		aliases = "__ctzdi2"
		size = "32"
		objfiles = "_ctzdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 55 0C 85 C0 74 0A 31 D2 0F BC C0 8D 04 02 5D C3 89 D0 BA 20 00 00 00 EB EF }
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

rule _Unwind_SetGR_3a2d2dff537d7590c4890a8adbed7191 {
	meta:
		aliases = "_Unwind_SetGR"
		size = "20"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 55 10 8B 08 8B 45 0C 89 54 81 08 5D C3 }
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

rule __paritysi2_ffde1a4ca7ca592c82c80d2f3daac350 {
	meta:
		aliases = "__paritysi2"
		size = "42"
		objfiles = "_paritysi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 55 08 5D 89 D0 C1 E8 10 31 D0 89 C1 C1 E9 08 31 C1 89 C8 C1 E8 04 31 C1 B8 96 69 00 00 83 E1 0F D3 F8 83 E0 01 C3 }
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

rule __ffsdi2_61df219adaf7c26f672139118bbccf52 {
	meta:
		aliases = "__ffsdi2"
		size = "47"
		objfiles = "_ffsdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 55 08 8B 4D 0C 85 D2 74 13 89 D0 BA 01 00 00 00 0F BC C0 01 D0 5D C3 90 8D 74 26 00 31 C0 85 C9 74 F3 89 C8 BA 21 00 00 00 EB E5 }
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

rule __clzdi2_88f099d13221b3e7b94b14cde4edbbb6 {
	meta:
		aliases = "__clzdi2"
		size = "39"
		objfiles = "_clzdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 55 0C 8B 45 08 85 D2 74 13 89 D0 31 D2 0F BD C0 83 F0 1F 5D 8D 04 02 C3 8D 74 26 00 BA 20 00 00 00 EB EA }
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

rule __gcc_personality_sj0_e83781a979af7fbed0dea38f3072f6ab {
	meta:
		aliases = "__gcc_personality_sj0"
		size = "502"
		objfiles = "unwind_c@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) B8 03 00 00 00 89 E5 57 56 53 83 EC 1C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 83 7D 08 01 74 08 8D 65 F4 5B 5E 5F 5D C3 F6 45 0C 02 75 12 8D 65 F4 B8 08 00 00 00 5B 5E 5F 5D C3 90 8D 74 26 00 83 EC 0C 8B 45 1C 50 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 74 D9 8B 45 1C 85 C0 74 0F 83 EC 0C 8B 45 1C 50 E8 ?? ?? ?? ?? 83 C4 10 8A 06 46 3C FF 74 57 89 C7 0F 84 E7 00 00 00 25 FF 00 00 00 89 45 E0 83 E0 70 83 F8 20 0F 84 32 01 00 00 0F 8F D2 00 00 00 85 C0 74 09 83 F8 10 0F 85 C0 00 00 00 89 FA 80 FA 50 0F 84 28 01 00 00 8B 45 E0 83 E0 0F 83 F8 0C 0F 87 A6 00 00 00 8B 84 83 ?? ?? ?? ?? 01 D8 FF E0 83 C6 }
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

rule frame_dummy_0709a25f180b87b1806a0b04ebaf7560 {
	meta:
		aliases = "frame_dummy"
		size = "81"
		objfiles = "crtbeginT, crtbegin"
	strings:
		$pattern = { ( CC | 55 ) B8 ?? ?? ?? ?? 89 E5 83 EC 08 E8 00 00 00 00 5A 81 C2 ?? ?? ?? ?? 85 C0 74 15 52 6A 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 A1 ?? ?? ?? ?? 85 C0 74 16 B8 ?? ?? ?? ?? 85 C0 74 0D 83 EC 0C 68 ?? ?? ?? ?? FF D0 83 C4 10 C9 C3 }
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

rule fde_unencoded_compare_b0fc74d10843d45a3d775879183bdd7e {
	meta:
		aliases = "fde_unencoded_compare"
		size = "28"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) B9 01 00 00 00 89 E5 8B 45 10 8B 50 08 8B 45 0C 39 50 08 77 02 19 C9 89 C8 5D C3 }
	condition:
		$pattern
}

rule fibheap_insert_2953b24f7b7062a16eafc5944c29c5e9 {
	meta:
		aliases = "fibheap_insert"
		size = "90"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) B9 1C 00 00 00 89 E5 56 53 83 EC 10 8B 75 08 89 4C 24 04 C7 04 24 01 00 00 00 E8 ?? ?? ?? ?? 89 C3 89 43 08 89 DA 89 43 0C 8B 45 10 89 43 14 8B 45 0C 89 43 10 89 F0 E8 63 FA FF FF 8B 56 04 85 D2 74 08 8B 43 10 3B 42 10 7D 03 89 5E 04 FF 06 83 C4 10 89 D8 5B 5E 5D C3 }
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

rule clntudp_call_4e2966857d6dd23f40f8f5e7031d1bb9 {
	meta:
		aliases = "clntudp_call"
		size = "1372"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) BA E8 03 00 00 89 E5 57 56 53 81 EC 3C 23 00 00 89 D3 8B 45 08 8B 70 08 69 4E 1C E8 03 00 00 8B 46 20 99 F7 FB 01 C1 89 8D C4 DC FF FF 83 7E 28 FF 75 37 8B 45 24 8B 55 20 89 85 DC DC FF FF 89 95 E0 DC FF FF EB 35 E8 ?? ?? ?? ?? 8B 00 C7 46 2C 03 00 00 00 89 46 30 B8 03 00 00 00 E9 F1 04 00 00 8B 40 0C E9 FB 03 00 00 8B 4E 28 89 8D DC DC FF FF 8B 5E 24 89 9D E0 DC FF FF C7 85 C0 DC FF FF 00 00 00 00 C7 85 C8 DC FF FF 02 00 00 00 C7 85 D4 DC FF FF 00 00 00 00 C7 85 D8 DC FF FF 00 00 00 00 8D 46 38 89 85 BC DC FF FF 83 7D 10 00 0F 84 D2 00 00 00 C7 46 38 00 00 00 00 57 8B 95 BC DC FF FF 57 8B }
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

rule __floatdidf_d1dd229decd9b611dc5831094a8157ed {
	meta:
		aliases = "__floatdixf, __floatdidf"
		size = "41"
		objfiles = "_floatdixf@libgcc.a, _floatdidf@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? 89 E5 31 D2 52 DB 45 0C D8 89 ?? ?? ?? ?? 8B 45 08 50 DF 2C 24 DE C1 83 C4 08 5D C3 }
	condition:
		$pattern
}

rule __fixunssfdi_6b80ee3418470e652ec6630d02beb9f2 {
	meta:
		aliases = "__fixunssfdi"
		size = "103"
		objfiles = "_fixunssfdi@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? 89 E5 57 56 31 FF 83 EC 10 D9 7D F6 D9 45 08 D9 81 ?? ?? ?? ?? D8 C9 66 8B 45 F6 B4 0C 57 66 89 45 F4 89 FA D9 6D F4 DF 7D E8 D9 6D F6 8B 45 E8 89 C6 89 C2 56 B8 00 00 00 00 DF 2C 24 D8 89 ?? ?? ?? ?? DE C1 D9 6D F4 DF 7D E8 D9 6D F6 8B 75 E8 83 C4 18 09 F0 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __fixunsdfdi_6d5f5adaeb59a7147bccc25581340170 {
	meta:
		aliases = "__fixunsdfdi"
		size = "103"
		objfiles = "_fixunsdfdi@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? 89 E5 57 56 31 FF 83 EC 10 D9 7D F6 DD 45 08 D9 81 ?? ?? ?? ?? D8 C9 66 8B 45 F6 B4 0C 57 66 89 45 F4 89 FA D9 6D F4 DF 7D E8 D9 6D F6 8B 45 E8 89 C6 89 C2 56 B8 00 00 00 00 DF 2C 24 D8 89 ?? ?? ?? ?? DE C1 D9 6D F4 DF 7D E8 D9 6D F6 8B 75 E8 83 C4 18 09 F0 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __fixunsxfdi_6339d6ae666daafe16509ee65738108f {
	meta:
		aliases = "__fixunsxfdi"
		size = "191"
		objfiles = "_fixunsxfdi@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? 89 E5 57 56 83 EC 10 DB 6D 08 D9 81 ?? ?? ?? ?? DD E1 DF E0 F6 C4 45 0F 84 86 00 00 00 D9 81 ?? ?? ?? ?? D9 7D F6 D8 CA 66 8B 45 F6 B4 0C 31 FF 66 89 45 F4 D9 6D F4 DF 7D E8 D9 6D F6 8B 45 E8 89 C6 89 F7 BE 00 00 00 00 57 56 DF 2C 24 83 C4 08 85 FF 78 24 DE EA DD E9 DF E0 F6 C4 45 74 23 D9 6D F4 DF 7D E8 D9 6D F6 31 D2 8B 45 E8 01 F0 11 FA 83 C4 10 5E 5F 5D C3 D8 81 ?? ?? ?? ?? EB D4 89 F6 D9 E0 D9 6D F4 DF 7D E8 D9 6D F6 31 D2 8B 45 E8 29 C6 19 D7 89 F0 83 C4 10 89 FA 5E 5F 5D C3 90 DD D8 DD D8 83 C4 10 31 C0 31 D2 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __fixunssfsi_7127ffdb6c8508c95fd3c4c59589b5cc {
	meta:
		aliases = "__fixunssfsi"
		size = "101"
		objfiles = "_fixunssfsi@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? 89 E5 83 EC 08 D9 45 08 D9 81 ?? ?? ?? ?? D9 C9 DD E1 DF E0 F6 C4 01 75 22 D9 7D FE DE E1 66 8B 45 FE B4 0C 66 89 45 FC D9 6D FC DB 5D F8 D9 6D FE 8B 45 F8 C9 2D 00 00 00 80 C3 DD D9 D9 7D FE 66 8B 45 FE B4 0C 66 89 45 FC D9 6D FC DB 5D F8 D9 6D FE 8B 45 F8 C9 C3 }
	condition:
		$pattern
}

rule __fixunsxfsi_7606407ebfb62ae92d81abdf6a925632 {
	meta:
		aliases = "__fixunsxfsi"
		size = "101"
		objfiles = "_fixunsxfsi@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? 89 E5 83 EC 08 DB 6D 08 D9 81 ?? ?? ?? ?? D9 C9 DD E1 DF E0 F6 C4 01 75 22 D9 7D FE DE E1 66 8B 45 FE B4 0C 66 89 45 FC D9 6D FC DB 5D F8 D9 6D FE 8B 45 F8 C9 2D 00 00 00 80 C3 DD D9 D9 7D FE 66 8B 45 FE B4 0C 66 89 45 FC D9 6D FC DB 5D F8 D9 6D FE 8B 45 F8 C9 C3 }
	condition:
		$pattern
}

rule __fixunsdfsi_72af16eab553df64f872c9e13d2256e5 {
	meta:
		aliases = "__fixunsdfsi"
		size = "101"
		objfiles = "_fixunsdfsi@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? 89 E5 83 EC 08 DD 45 08 D9 81 ?? ?? ?? ?? D9 C9 DD E1 DF E0 F6 C4 01 75 22 D9 7D FE DE E1 66 8B 45 FE B4 0C 66 89 45 FC D9 6D FC DB 5D F8 D9 6D FE 8B 45 F8 C9 2D 00 00 00 80 C3 DD D9 D9 7D FE 66 8B 45 FE B4 0C 66 89 45 FC D9 6D FC DB 5D F8 D9 6D FE 8B 45 F8 C9 C3 }
	condition:
		$pattern
}

rule _Unwind_SjLj_Unregister_70a2d13113640d898de358198239c63f {
	meta:
		aliases = "_Unwind_SjLj_Unregister"
		size = "28"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? 89 E5 8B 45 08 5D 8B 00 89 81 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __gnat_install_locks_16c57423e07ae75735d6ab62075ce14b {
	meta:
		aliases = "__gnat_install_locks"
		size = "35"
		objfiles = "gthr_gnat@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? 89 E5 8B 45 08 89 81 ?? ?? ?? ?? 8B 45 0C 89 81 ?? ?? ?? ?? 5D C3 }
	condition:
		$pattern
}

rule __register_frame_info_table_ba_62d5db559e03c8e7d03d9adaa3ce1613 {
	meta:
		aliases = "__register_frame_info_table_bases"
		size = "76"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? 89 E5 8B 45 0C 8B 55 10 89 50 04 8B 55 14 89 50 08 8B 55 08 C7 40 10 00 00 00 00 89 50 0C 80 48 10 02 66 81 48 10 F8 07 8B 91 ?? ?? ?? ?? C7 00 FF FF FF FF 89 50 14 89 81 ?? ?? ?? ?? 5D C3 }
	condition:
		$pattern
}

rule _Unwind_SjLj_Register_7c662c10096806da12ad06df1977a517 {
	meta:
		aliases = "_Unwind_SjLj_Register"
		size = "34"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? 89 E5 8B 81 ?? ?? ?? ?? 8B 55 08 89 02 89 91 ?? ?? ?? ?? 5D C3 }
	condition:
		$pattern
}

rule __GI_strrchr_1064dcfd946443de55f2d95baa3ddb8b {
	meta:
		aliases = "strrchr, rindex, __GI_strrchr"
		size = "33"
		objfiles = "strrchr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 31 C9 83 EC 04 8B 74 24 0C 8B 44 24 10 88 C4 AC 38 E0 75 03 8D 4E FF 84 C0 75 F4 89 C8 5A 5E C3 }
	condition:
		$pattern
}

rule setup_salt_2ad62df661c2665d58567910cb1a954e {
	meta:
		aliases = "setup_salt"
		size = "66"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 56 ) 3B 05 ?? ?? ?? ?? 53 74 35 BE 00 00 80 00 BB 01 00 00 00 31 D2 31 C9 A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 EB 0B 85 C3 74 02 09 F1 01 DB 42 D1 EE 83 FA 17 7E F0 89 0D ?? ?? ?? ?? 5B 5E C3 }
	condition:
		$pattern
}

rule tmpfile64_71f42f699352b81a553f537fd7697e23 {
	meta:
		aliases = "tmpfile, tmpfile64"
		size = "114"
		objfiles = "tmpfile@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 04 10 00 00 68 ?? ?? ?? ?? 6A 00 68 FF 0F 00 00 8D 5C 24 11 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 40 51 51 6A 00 53 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 78 2D 83 EC 0C 53 E8 ?? ?? ?? ?? 58 5A 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 75 10 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 EB 02 31 DB 89 D8 81 C4 04 10 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule __ns_name_uncompress_6eeb195eae0093de4003f6d7afd80c45 {
	meta:
		aliases = "__GI___ns_name_uncompress, __ns_name_uncompress"
		size = "95"
		objfiles = "ns_name@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 10 01 00 00 68 FF 00 00 00 8D 74 24 15 56 FF B4 24 2C 01 00 00 FF B4 24 2C 01 00 00 FF B4 24 2C 01 00 00 E8 ?? ?? ?? ?? 83 C4 20 89 C3 83 F8 FF 74 1B 52 FF B4 24 24 01 00 00 FF B4 24 24 01 00 00 56 E8 ?? ?? ?? ?? 83 C4 10 40 75 03 83 CB FF 89 D8 81 C4 04 01 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_initialize_b832a3fef68cfb0a8bd612a4214d3494 {
	meta:
		aliases = "pthread_initialize"
		size = "419"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 24 01 00 00 83 3D ?? ?? ?? ?? 00 0F 85 85 01 00 00 8D 84 24 24 01 C0 FF 25 00 00 E0 FF A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 EB 10 83 78 34 01 74 07 C7 40 34 00 00 00 00 8B 40 20 85 C0 75 EC 50 50 8D 9C 24 24 01 00 00 53 6A 03 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA 00 00 20 00 01 C0 83 C4 10 29 C2 39 94 24 1C 01 00 00 76 14 89 94 24 1C 01 00 00 50 50 53 6A 03 E8 ?? ?? ?? ?? 83 C4 10 C7 44 24 10 ?? ?? ?? ?? 83 EC 0C 8D 5C 24 20 8D 74 24 1C 53 E8 ?? ?? ?? ?? C7 84 24 A4 00 00 00 }
	condition:
		$pattern
}

rule __libc_sigaction_82b15281d822de0ae568ffe35db55563 {
	meta:
		aliases = "__GI_sigaction, sigaction, __libc_sigaction"
		size = "217"
		objfiles = "sigaction@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 24 01 00 00 8B 9C 24 34 01 00 00 8B B4 24 38 01 00 00 85 DB 74 4F 8B 03 89 84 24 98 00 00 00 8D 43 04 52 68 80 00 00 00 50 8D 84 24 B0 00 00 00 50 E8 ?? ?? ?? ?? 8B 83 84 00 00 00 0D 00 00 00 04 89 84 24 AC 00 00 00 83 C4 10 B8 ?? ?? ?? ?? F6 83 84 00 00 00 04 75 05 B8 ?? ?? ?? ?? 89 84 24 A0 00 00 00 31 D2 85 F6 74 04 8D 54 24 0C 31 C0 85 DB 74 07 8D 84 24 98 00 00 00 6A 08 52 50 FF B4 24 3C 01 00 00 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 F6 74 35 85 C0 78 31 8B 44 24 0C 89 06 50 68 80 00 00 00 8D 44 24 20 50 8D 46 04 50 E8 ?? ?? ?? ?? 8B 44 24 20 89 86 84 00 00 00 8B 44 24 24 83 C4 10 }
	condition:
		$pattern
}

rule pthread_sigmask_7950de283ee846a6e8a559b30a8cb6b6 {
	meta:
		aliases = "pthread_sigmask"
		size = "177"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 84 00 00 00 8B 84 24 94 00 00 00 8B B4 24 90 00 00 00 85 C0 74 6E 8D 5C 24 04 52 68 80 00 00 00 50 53 E8 ?? ?? ?? ?? 83 C4 10 83 FE 01 74 3C 83 FE 02 74 06 85 F6 74 14 EB 46 51 51 FF 35 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 58 5A EB 02 51 51 FF 35 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 7E 1A 52 52 50 EB 08 51 51 FF 35 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 89 D8 83 C4 10 EB 04 8D 44 24 04 52 FF B4 24 9C 00 00 00 50 56 E8 ?? ?? ?? ?? 83 C4 10 31 D2 40 75 07 E8 ?? ?? ?? ?? 8B 10 81 C4 84 00 00 00 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule adjtime_1acfce74c8cb9ad7b6062920747e327d {
	meta:
		aliases = "adjtime"
		size = "193"
		objfiles = "adjtime@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 84 00 00 00 8B 8C 24 90 00 00 00 8B B4 24 94 00 00 00 85 C9 74 45 8B 41 04 BB 40 42 0F 00 99 F7 FB 89 D3 89 C2 03 11 8D 82 61 08 00 00 3D C2 10 00 00 76 10 E8 ?? ?? ?? ?? 83 CA FF C7 00 16 00 00 00 EB 6E 69 C2 40 42 0F 00 C7 44 24 04 01 80 00 00 8D 04 03 89 44 24 08 EB 08 C7 44 24 04 00 00 00 00 83 EC 0C 8D 44 24 10 50 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 38 31 D2 85 F6 74 32 8B 54 24 08 85 D2 79 17 F7 DA 89 D0 B9 40 42 0F 00 99 F7 F9 89 C1 F7 DA F7 D9 89 56 04 EB 0F 89 D0 B9 40 42 0F 00 99 F7 F9 89 C1 89 56 04 89 0E 31 D2 81 C4 84 00 00 00 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule __sigpause_e2d971c959694ecb430f15ce27ed77b4 {
	meta:
		aliases = "__GI___sigpause, __sigpause"
		size = "120"
		objfiles = "sigpause@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 84 00 00 00 8B B4 24 90 00 00 00 83 BC 24 94 00 00 00 00 74 28 52 8D 5C 24 08 53 6A 00 6A 00 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 3D 50 50 56 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 1B EB 2B 89 74 24 04 8D 54 24 08 B8 1E 00 00 00 C7 02 00 00 00 00 83 C2 04 48 79 F4 83 EC 0C 8D 44 24 10 50 E8 ?? ?? ?? ?? 83 C4 10 EB 03 83 C8 FF 81 C4 84 00 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule __pthread_wait_for_restart_sig_b4e2f386248f85896c48d2ce79b7e5fd {
	meta:
		aliases = "__pthread_wait_for_restart_signal"
		size = "89"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 88 00 00 00 8D 5C 24 08 8B B4 24 94 00 00 00 53 6A 00 6A 02 E8 ?? ?? ?? ?? 59 58 FF 35 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? C7 46 20 00 00 00 00 83 C4 10 83 EC 0C 8D 44 24 10 50 E8 ?? ?? ?? ?? 8B 46 20 83 C4 10 3B 05 ?? ?? ?? ?? 75 E5 81 C4 84 00 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule logwtmp_1c5c13b8168cba3d1e94dba17325be01 {
	meta:
		aliases = "logwtmp"
		size = "172"
		objfiles = "logwtmp@libutil.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 88 01 00 00 8B B4 24 98 01 00 00 68 80 01 00 00 6A 00 8D 44 24 10 50 E8 ?? ?? ?? ?? 83 C4 10 85 F6 74 0A B8 07 00 00 00 80 3E 00 75 05 B8 08 00 00 00 66 89 44 24 04 E8 ?? ?? ?? ?? 89 44 24 08 50 6A 1F FF B4 24 98 01 00 00 8D 44 24 18 8D 5C 24 10 50 E8 ?? ?? ?? ?? 83 C4 0C 6A 1F 56 8D 44 24 3C 50 E8 ?? ?? ?? ?? 83 C4 0C 68 FF 00 00 00 FF B4 24 A0 01 00 00 8D 44 24 5C 50 E8 ?? ?? ?? ?? 59 5E 6A 00 8D 84 24 64 01 00 00 50 E8 ?? ?? ?? ?? 58 5A 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 C4 94 01 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule __libc_pselect_4fea01a25b28d1ca97c1b858d18b5880 {
	meta:
		aliases = "pselect, __libc_pselect"
		size = "164"
		objfiles = "pselect@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 94 00 00 00 8B 9C 24 B0 00 00 00 8B B4 24 B4 00 00 00 85 DB 74 1D 8B 03 BA E8 03 00 00 89 84 24 8C 00 00 00 89 D1 8B 43 04 99 F7 F9 89 84 24 90 00 00 00 85 F6 74 11 52 8D 44 24 10 50 56 6A 02 E8 ?? ?? ?? ?? 83 C4 10 31 C0 85 DB 74 07 8D 84 24 8C 00 00 00 83 EC 0C 50 FF B4 24 BC 00 00 00 FF B4 24 BC 00 00 00 FF B4 24 BC 00 00 00 FF B4 24 BC 00 00 00 E8 ?? ?? ?? ?? 83 C4 20 89 C3 85 F6 74 12 50 6A 00 8D 44 24 14 50 6A 02 E8 ?? ?? ?? ?? 83 C4 10 89 D8 81 C4 94 00 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_vdprintf_66c67a6511d0a0db7875ab9794c80e6e {
	meta:
		aliases = "vdprintf, __GI_vdprintf"
		size = "169"
		objfiles = "vdprintf@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 94 00 00 00 8D 44 24 54 8D 94 24 94 00 00 00 89 44 24 0C 89 44 24 1C 89 44 24 20 89 44 24 14 89 44 24 18 8B 84 24 A0 00 00 00 89 54 24 10 89 44 24 08 66 C7 44 24 04 D0 00 C6 44 24 06 00 C7 44 24 30 00 00 00 00 C7 44 24 38 01 00 00 00 83 EC 0C 8D 44 24 48 8D 74 24 10 50 E8 ?? ?? ?? ?? C7 44 24 34 00 00 00 00 83 C4 0C FF B4 24 AC 00 00 00 FF B4 24 AC 00 00 00 56 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 7E 13 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 03 83 CB FF 89 D8 81 C4 94 00 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule __pthread_do_exit_c62d3a7ad5a263dc6f43cb871cc2e7d6 {
	meta:
		aliases = "__pthread_do_exit"
		size = "251"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC A4 00 00 00 E8 ?? ?? ?? ?? 83 EC 0C 89 C3 C6 40 40 01 C6 40 41 00 FF B4 24 C0 00 00 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 43 1C 89 DA E8 ?? ?? ?? ?? 8B 84 24 C0 00 00 00 89 43 30 83 C4 10 83 BB 9C 01 00 00 00 74 2B A1 ?? ?? ?? ?? 0B 83 A0 01 00 00 F6 C4 01 74 1B C7 83 A8 01 00 00 09 00 00 00 89 9B AC 01 00 00 89 1D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 0C 8B 73 38 C6 43 2C 01 FF 73 1C E8 ?? ?? ?? ?? 83 C4 10 85 F6 74 0C 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 8B 35 ?? ?? ?? ?? 39 F3 75 4C 83 3D ?? ?? ?? ?? 00 78 43 89 74 24 10 C7 44 24 14 03 00 00 00 8D 44 24 10 52 68 94 00 00 00 50 FF 35 ?? }
	condition:
		$pattern
}

rule __new_sem_post_feb627530b79d8c6ec69a0f5c60542ea {
	meta:
		aliases = "sem_post, __new_sem_post"
		size = "240"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC A4 00 00 00 E8 ?? ?? ?? ?? 8B B4 24 B0 00 00 00 83 78 54 00 75 77 89 C2 89 F0 E8 ?? ?? ?? ?? 83 7E 0C 00 75 3A 8B 46 08 3D FF FF FF 7F 75 19 E8 ?? ?? ?? ?? 83 EC 0C C7 00 22 00 00 00 56 E8 ?? ?? ?? ?? 83 C8 FF EB 0F 40 83 EC 0C 89 46 08 56 E8 ?? ?? ?? ?? 31 C0 83 C4 10 E9 84 00 00 00 8B 5E 0C 85 DB 74 0D 8B 43 08 89 46 0C C7 43 08 00 00 00 00 83 EC 0C 56 E8 ?? ?? ?? ?? C6 83 BA 01 00 00 01 89 1C 24 E8 ?? ?? ?? ?? EB C8 83 3D ?? ?? ?? ?? 00 79 19 E8 ?? ?? ?? ?? 85 C0 79 10 E8 ?? ?? ?? ?? C7 00 0B 00 00 00 83 C8 FF EB 34 C7 44 24 14 04 00 00 00 89 74 24 18 8D 44 24 10 56 68 94 00 00 }
	condition:
		$pattern
}

rule __encode_header_20ce32b1df503c533e175f809f8c9d39 {
	meta:
		aliases = "__encode_header"
		size = "177"
		objfiles = "encodeh@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 C8 FF 8B 5C 24 0C 8B 74 24 10 83 7C 24 14 0B 0F 8E 96 00 00 00 0F B6 43 01 88 06 8B 03 88 46 01 83 7B 04 01 19 C9 F7 D1 83 E1 80 83 7B 0C 01 19 D2 F7 D2 83 E2 04 83 7B 10 01 19 C0 F7 D0 83 E0 02 09 C1 8B 43 08 83 E0 0F C1 E0 03 09 C2 83 7B 14 00 0F 95 C0 09 C2 09 D1 88 4E 02 83 7B 18 01 19 C0 8A 53 1C F7 D0 83 E0 80 83 E2 0F 09 D0 88 46 03 0F B6 43 21 88 46 04 8B 43 20 88 46 05 0F B6 43 25 88 46 06 8B 43 24 88 46 07 0F B6 43 29 88 46 08 8B 43 28 88 46 09 0F B6 43 2D 88 46 0A 8B 43 2C 88 46 0B B8 0C 00 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule xdrmem_getbytes_14a60dcbe2a43c65661ec31d1bfc53a1 {
	meta:
		aliases = "xdrmem_getbytes"
		size = "56"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 31 C0 8B 5C 24 10 8B 74 24 18 8B 53 14 39 F2 72 1E 29 F2 89 53 14 50 56 FF 73 0C FF 74 24 20 E8 ?? ?? ?? ?? 01 73 0C B8 01 00 00 00 83 C4 10 5B 5B 5E C3 }
	condition:
		$pattern
}

rule xdrmem_putbytes_6e2ee824feaa3fe6a0a029fcf11b69c7 {
	meta:
		aliases = "xdrmem_putbytes"
		size = "56"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 31 C0 8B 5C 24 10 8B 74 24 18 8B 53 14 39 F2 72 1E 29 F2 89 53 14 51 56 FF 74 24 1C FF 73 0C E8 ?? ?? ?? ?? 01 73 0C B8 01 00 00 00 83 C4 10 5A 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_kill_819602e4eb1aed2f4a6097170e1fb580 {
	meta:
		aliases = "pthread_kill"
		size = "110"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 31 D2 8B 5C 24 10 89 D8 25 FF 03 00 00 C1 E0 04 8D B0 ?? ?? ?? ?? 89 F0 E8 ?? ?? ?? ?? 8B 46 08 85 C0 74 05 39 58 10 74 13 83 EC 0C 56 E8 ?? ?? ?? ?? BA 03 00 00 00 83 C4 10 EB 27 83 EC 0C 8B 58 14 56 E8 ?? ?? ?? ?? 5E 58 FF 74 24 1C 53 E8 ?? ?? ?? ?? 83 C4 10 31 D2 40 75 07 E8 ?? ?? ?? ?? 8B 10 89 D0 59 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_rwlock_trywrlock_414b6cc1f0aedd00bf2eb736dc3578c8 {
	meta:
		aliases = "pthread_rwlock_trywrlock"
		size = "64"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 31 D2 8B 5C 24 10 89 D8 E8 ?? ?? ?? ?? 83 7B 08 00 75 12 83 7B 0C 00 75 0C E8 ?? ?? ?? ?? 31 F6 89 43 0C EB 05 BE 10 00 00 00 83 EC 0C 53 E8 ?? ?? ?? ?? 89 F0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_pthread_cond_broadcast_c365b382ba35579c0a266fec901132fe {
	meta:
		aliases = "pthread_cond_broadcast, __GI_pthread_cond_broadcast"
		size = "78"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 31 D2 8B 5C 24 10 89 D8 E8 ?? ?? ?? ?? 83 EC 0C 8B 73 08 C7 43 08 00 00 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 EB 1A 8B 5E 08 C6 86 B9 01 00 00 01 C7 46 08 00 00 00 00 89 F0 89 DE E8 ?? ?? ?? ?? 85 F6 75 E2 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule __new_sem_trywait_ad18748e60e10ee73a2c4f68efd0760a {
	meta:
		aliases = "sem_trywait, __new_sem_trywait"
		size = "64"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 31 D2 8B 5C 24 10 89 D8 E8 ?? ?? ?? ?? 8B 43 08 85 C0 75 10 E8 ?? ?? ?? ?? 83 CE FF C7 00 0B 00 00 00 EB 06 48 31 F6 89 43 08 83 EC 0C 53 E8 ?? ?? ?? ?? 89 F0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_getschedparam_410b13090a986f1610067087a7e7eafc {
	meta:
		aliases = "__GI_pthread_getschedparam, pthread_getschedparam"
		size = "134"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 31 D2 8B 74 24 10 89 F0 25 FF 03 00 00 C1 E0 04 8D 98 ?? ?? ?? ?? 89 D8 E8 ?? ?? ?? ?? 8B 43 08 85 C0 74 05 39 70 10 74 13 83 EC 0C 53 E8 ?? ?? ?? ?? B8 03 00 00 00 83 C4 10 EB 41 83 EC 0C 8B 70 14 53 E8 ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 83 C4 10 89 C3 83 F8 FF 74 12 51 51 FF 74 24 20 56 E8 ?? ?? ?? ?? 83 C4 10 40 75 09 E8 ?? ?? ?? ?? 8B 00 EB 08 8B 44 24 14 89 18 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_cond_signal_4f1374a2b6e2a344e7a8e8247134c0e9 {
	meta:
		aliases = "__GI_pthread_cond_signal, pthread_cond_signal"
		size = "74"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 31 D2 8B 74 24 10 89 F0 E8 ?? ?? ?? ?? 8B 5E 08 85 DB 74 0D 8B 43 08 89 46 08 C7 43 08 00 00 00 00 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 85 DB 74 0E C6 83 B9 01 00 00 01 89 D8 E8 ?? ?? ?? ?? 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_getrpcbynumber_df01a3f7d1008c44f251efd78e49069d {
	meta:
		aliases = "getrpcbynumber, __GI_getrpcbynumber"
		size = "62"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 31 DB 8B 74 24 10 E8 ?? ?? ?? ?? 85 C0 74 24 83 EC 0C 6A 00 E8 ?? ?? ?? ?? 83 C4 10 EB 05 39 73 08 74 0B E8 ?? ?? ?? ?? 89 C3 85 C0 75 F0 E8 ?? ?? ?? ?? 89 D8 5A 5B 5E C3 }
	condition:
		$pattern
}

rule globfree64_089f63f204780f378f815b0433f30f4b {
	meta:
		aliases = "__GI_globfree, __GI_globfree64, globfree, globfree64"
		size = "76"
		objfiles = "glob@libc.a, glob64@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 31 F6 8B 5C 24 10 83 7B 04 00 75 1E EB 35 89 F2 8B 43 04 03 53 08 8B 04 90 85 C0 74 0C 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 46 3B 33 72 E0 83 EC 0C FF 73 04 E8 ?? ?? ?? ?? C7 43 04 00 00 00 00 83 C4 10 58 5B 5E C3 }
	condition:
		$pattern
}

rule sbrk_5da6f61f4a99247f0e8249a8087cb0eb {
	meta:
		aliases = "__GI_sbrk, sbrk"
		size = "78"
		objfiles = "sbrk@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 83 3D ?? ?? ?? ?? 00 8B 74 24 10 75 11 83 EC 0C 6A 00 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 22 85 F6 A1 ?? ?? ?? ?? 75 04 89 C3 EB 18 83 EC 0C 89 C3 8D 04 30 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 03 83 CB FF 89 D8 5A 5B 5E C3 }
	condition:
		$pattern
}

rule __pthread_set_own_extricate_if_fb8c2424281d38480bc1208870dae02f {
	meta:
		aliases = "__pthread_set_own_extricate_if"
		size = "59"
		objfiles = "condvar@libpthread.a, join@libpthread.a, semaphore@libpthread.a, oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 89 C3 89 D6 85 D2 74 08 80 78 40 00 75 24 EB 0A 8B 40 1C 89 DA E8 ?? ?? ?? ?? 89 B3 BC 01 00 00 85 F6 75 0E 83 EC 0C FF 73 1C E8 ?? ?? ?? ?? 83 C4 10 58 5B 5E C3 }
	condition:
		$pattern
}

rule tdestroy_recurse_39d0e29fe4f9be5039aef81d82a5ad9c {
	meta:
		aliases = "tdestroy_recurse"
		size = "56"
		objfiles = "tdestroy@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 89 C3 8B 40 04 89 D6 85 C0 74 05 E8 EB FF FF FF 8B 43 08 85 C0 74 07 89 F2 E8 DD FF FF FF 83 EC 0C FF 33 FF D6 89 1C 24 E8 ?? ?? ?? ?? 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule skip_input_bytes_96a6469f5764feed44b0125e9f5b81b1 {
	meta:
		aliases = "skip_input_bytes"
		size = "63"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 89 C6 89 D3 EB 27 8B 4E 2C 8B 46 30 29 C8 75 0D 89 F0 E8 ?? ?? ?? ?? 85 C0 75 12 EB 19 89 C2 39 D8 7E 02 89 DA 8D 04 11 29 D3 89 46 2C 85 DB 7F D5 B8 01 00 00 00 59 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_free_d4488e7baee84995766efc8b9f3ee590 {
	meta:
		aliases = "pthread_free"
		size = "194"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 89 C6 8B 58 10 31 D2 81 E3 FF 03 00 00 C1 E3 04 81 C3 ?? ?? ?? ?? 89 D8 E8 ?? ?? ?? ?? 83 EC 0C C7 43 08 00 00 00 00 C7 43 0C FF FF FF FF 53 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 48 A3 ?? ?? ?? ?? 8B 86 C0 01 00 00 EB 0D 83 EC 0C 8B 18 50 E8 ?? ?? ?? ?? 89 D8 83 C4 10 85 C0 75 EC 8B 86 C4 01 00 00 EB 10 83 EC 0C 8B 18 50 E8 ?? ?? ?? ?? 89 D8 83 C4 10 85 C0 75 EC 81 FE ?? ?? ?? ?? 74 3A 83 BE 88 01 00 00 00 75 31 8B 86 90 01 00 00 85 C0 74 11 52 52 50 FF B6 8C 01 00 00 E8 ?? ?? ?? ?? 83 C4 10 50 50 8D 86 E0 01 E0 FF 68 00 00 20 00 50 E8 ?? ?? ?? ?? 83 C4 10 58 5B 5E C3 }
	condition:
		$pattern
}

rule __getutid_9b93099605536ab3c71997f54e94198f {
	meta:
		aliases = "__getutid"
		size = "94"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 89 C6 EB 3F 8B 16 8D 42 FF 66 83 F8 03 77 05 66 39 13 74 3F 66 83 FA 05 74 12 66 83 FA 08 74 0C 66 83 FA 06 74 06 66 83 FA 07 75 17 50 8D 46 28 6A 04 50 8D 43 28 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 10 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 85 C0 75 B1 89 D8 59 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_strchrnul_21821305a27e14ba5ed80f3813a031b4 {
	meta:
		aliases = "strchrnul, __GI_strchrnul"
		size = "179"
		objfiles = "strchrnul@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8A 44 24 14 88 44 24 03 8B 44 24 10 EB 15 8A 10 3A 54 24 03 0F 84 90 00 00 00 84 D2 0F 84 88 00 00 00 40 A8 03 75 E7 0F B6 54 24 03 89 C3 89 D0 C1 E0 08 09 D0 89 C6 C1 E6 10 09 C6 8B 0B 83 C3 04 89 CA 8D 81 FF FE FE 7E F7 D2 31 D0 A9 00 01 01 81 75 16 89 C8 31 F0 8D 90 FF FE FE 7E F7 D0 31 C2 81 E2 00 01 01 81 74 D2 8A 53 FC 8D 43 FC 3A 54 24 03 74 34 84 D2 74 30 8A 53 FD 8D 43 FD 3A 54 24 03 74 24 84 D2 74 20 8A 53 FE 8D 43 FE 3A 54 24 03 74 14 84 D2 74 10 8A 53 FF 8D 43 FF 3A 54 24 03 74 04 84 D2 75 92 5A 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_memrchr_83fb48196ea9fce60c609d30b79a18fb {
	meta:
		aliases = "memrchr, __GI_memrchr"
		size = "176"
		objfiles = "memrchr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8A 44 24 14 8B 5C 24 18 88 44 24 03 8B 44 24 10 01 D8 EB 0E 48 8A 54 24 03 38 10 0F 84 86 00 00 00 4B 85 DB 74 04 A8 03 75 EA 0F B6 54 24 03 89 C1 89 D0 C1 E0 08 09 D0 89 C6 C1 E6 10 09 C6 EB 4C 83 E9 04 89 F0 33 01 8D 90 FF FE FE 7E F7 D0 31 C2 81 E2 00 01 01 81 74 30 8A 54 24 03 8D 41 03 38 51 03 74 41 8A 54 24 03 8D 41 02 38 51 02 74 35 8A 54 24 03 8D 41 01 38 51 01 74 29 8A 44 24 03 38 01 75 04 89 C8 EB 1D 83 EB 04 83 FB 03 77 AF 89 C8 EB 09 48 8A 54 24 03 38 10 74 08 4B 83 FB FF 75 F1 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule __cxa_finalize_8892782fac60c3f18809300811f48266 {
	meta:
		aliases = "__cxa_finalize"
		size = "74"
		objfiles = "__cxa_finalize@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 1D ?? ?? ?? ?? 8B 74 24 10 EB 31 4B 89 D9 C1 E1 04 03 0D ?? ?? ?? ?? 85 F6 74 05 3B 71 0C 75 1C 31 D2 B8 03 00 00 00 F0 0F B1 11 83 F8 03 75 0C 83 EC 0C FF 71 08 FF 51 04 83 C4 10 85 DB 75 CB 58 5B 5E C3 }
	condition:
		$pattern
}

rule div_89cd5f2e83d2d086643c18b1fc66dc79 {
	meta:
		aliases = "div"
		size = "42"
		objfiles = "div@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 4C 24 14 8B 74 24 10 89 C8 99 F7 7C 24 18 8B 54 24 18 89 06 0F AF D0 29 D1 89 F0 89 4E 04 5A 5B 5E C2 04 00 }
	condition:
		$pattern
}

rule _dl_run_fini_array_fda5bdc8da718080e4e4e6bf486786f7 {
	meta:
		aliases = "_dl_run_fini_array"
		size = "47"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 54 24 10 8B 82 A8 00 00 00 85 C0 74 18 89 C6 8B 9A B0 00 00 00 C1 EB 02 03 32 EB 03 FF 14 9E 4B 83 FB FF 75 F7 58 5B 5E C3 }
	condition:
		$pattern
}

rule ether_line_b4b76468425332acf11af2ba99f4e50d {
	meta:
		aliases = "ether_line"
		size = "71"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 54 24 14 8B 44 24 10 8B 74 24 18 E8 ?? ?? ?? ?? 89 C3 83 C8 FF 85 DB 74 24 EB 17 80 F9 23 74 18 0F BE D1 A1 ?? ?? ?? ?? F6 04 50 20 75 0A 88 0E 43 46 8A 0B 84 C9 75 E3 C6 06 00 31 C0 5B 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_xdr_opaque_f5002cd6d17fa75912e9f58758eacc94 {
	meta:
		aliases = "xdr_opaque, __GI_xdr_opaque"
		size = "158"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 54 24 18 8B 5C 24 10 8B 4C 24 14 85 D2 74 7C 89 D0 31 F6 83 E0 03 74 06 66 BE 04 00 29 C6 8B 03 83 F8 01 74 09 72 34 83 F8 02 75 66 EB 5D 50 8B 43 04 52 51 53 FF 50 08 83 C4 10 85 C0 74 53 85 F6 74 48 8B 43 04 89 74 24 18 C7 44 24 14 ?? ?? ?? ?? 89 5C 24 10 8B 48 08 EB 2B 50 8B 43 04 52 51 53 FF 50 0C 83 C4 10 85 C0 74 26 85 F6 74 1B 8B 43 04 89 74 24 18 C7 44 24 14 ?? ?? ?? ?? 89 5C 24 10 8B 48 0C 5B 5B 5E FF E1 B8 01 00 00 00 EB 02 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule herror_419f6c0afe5d9c2b243c672371bb36d9 {
	meta:
		aliases = "__GI_herror, herror"
		size = "80"
		objfiles = "herror@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 10 85 DB 74 0A BE ?? ?? ?? ?? 80 3B 00 75 05 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B 00 83 F8 04 77 07 8B 14 85 ?? ?? ?? ?? 83 EC 0C 52 56 53 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule _ppfs_prepargs_a7b1a5c7932cbde0ea35c28f7442e734 {
	meta:
		aliases = "_ppfs_prepargs"
		size = "66"
		objfiles = "_ppfs_prepargs@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 10 8B 44 24 14 8B 73 18 89 43 4C 85 F6 7E 27 83 EC 0C 89 73 1C C7 43 18 00 00 00 00 C7 43 04 00 00 00 00 C7 43 08 00 00 00 00 53 E8 ?? ?? ?? ?? 89 73 18 83 C4 10 58 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_double_d4a6294759b083f37c5df1da804249f2 {
	meta:
		aliases = "xdr_double"
		size = "109"
		objfiles = "xdr_float@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 10 8B 74 24 14 8B 03 83 F8 01 74 2A 72 08 83 F8 02 0F 94 C0 EB 44 50 50 8B 43 04 8D 56 04 52 53 FF 50 04 83 C4 10 85 C0 74 35 50 50 8B 43 04 56 53 FF 50 04 EB 1C 50 50 8B 43 04 8D 56 04 52 53 FF 10 83 C4 10 85 C0 74 16 51 51 8B 43 04 56 53 FF 10 83 C4 10 85 C0 0F 95 C0 0F B6 C0 EB 02 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule psignal_257c1eee98c916ea5c5ffd0d04523669 {
	meta:
		aliases = "psignal"
		size = "69"
		objfiles = "psignal@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 14 85 DB 74 0A BE ?? ?? ?? ?? 80 3B 00 75 07 BB ?? ?? ?? ?? 89 DE 83 EC 0C FF 74 24 1C E8 ?? ?? ?? ?? 89 04 24 56 53 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_xdr_callhdr_4dc92d26d787957756081e2c0c92b807 {
	meta:
		aliases = "xdr_callhdr, __GI_xdr_callhdr"
		size = "130"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 14 8B 74 24 10 C7 43 04 00 00 00 00 C7 43 08 02 00 00 00 83 3E 00 75 5C 50 50 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 4C 50 50 8D 43 04 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 39 50 50 8D 43 08 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 26 50 50 8D 43 0C 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 13 8D 43 10 89 74 24 10 89 44 24 14 59 5B 5E E9 ?? ?? ?? ?? 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_seteuid_eaccc4a129305672e7693e1a65c54c04 {
	meta:
		aliases = "setegid, seteuid, __GI_seteuid"
		size = "82"
		objfiles = "seteuid@libc.a, setegid@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 83 FE FF 75 10 E8 ?? ?? ?? ?? 83 CB FF C7 00 16 00 00 00 EB 2E 53 6A FF 56 6A FF E8 ?? ?? ?? ?? 83 C4 10 89 C3 83 F8 FF 75 19 E8 ?? ?? ?? ?? 83 38 26 75 0F 51 51 56 6A FF E8 ?? ?? ?? ?? 83 C4 10 89 C3 89 D8 5A 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_if_freenameindex_d89895aff0528afab358430432891a1f {
	meta:
		aliases = "if_freenameindex, __GI_if_freenameindex"
		size = "52"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 89 F3 EB 0F 83 EC 0C 83 C3 08 50 E8 ?? ?? ?? ?? 83 C4 10 8B 43 04 85 C0 75 EA 83 3B 00 75 E5 89 74 24 10 58 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_xprt_unregister_821fa697a37378584ebb1c1e174feb84 {
	meta:
		aliases = "xprt_unregister, __GI_xprt_unregister"
		size = "119"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 8B 1E E8 ?? ?? ?? ?? 39 C3 7D 5F E8 ?? ?? ?? ?? 8D 14 9D 00 00 00 00 8B 80 B4 00 00 00 39 34 10 75 48 C7 04 10 00 00 00 00 81 FB FF 03 00 00 7F 13 E8 ?? ?? ?? ?? 89 D9 C1 E9 05 89 DA 83 E2 1F 0F B3 14 88 31 F6 EB 19 E8 ?? ?? ?? ?? 8D 14 F5 00 00 00 00 03 10 39 1A 75 06 C7 02 FF FF FF FF 46 E8 ?? ?? ?? ?? 3B 30 7C DE 5B 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_strsep_91a123daa9cb2a4f823ec92b7677e3b4 {
	meta:
		aliases = "strsep, __GI_strsep"
		size = "96"
		objfiles = "strsep@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 8B 44 24 14 8B 1E 85 DB 74 47 8A 10 84 D2 74 3B 80 78 01 00 75 1D 8A 0B 89 D8 38 D1 74 21 84 C9 74 29 50 50 0F BE C2 50 8D 43 01 50 E8 ?? ?? ?? ?? EB 09 51 51 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 08 C6 00 00 40 89 06 EB 06 C7 06 00 00 00 00 89 D8 5A 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_mutex_lock_885e23d49abbd7b85d5e325b45c1d22f {
	meta:
		aliases = "__pthread_mutex_lock, pthread_mutex_lock"
		size = "151"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 8B 46 0C 83 F8 01 74 25 7F 06 85 C0 74 13 EB 0A 83 F8 02 74 41 83 F8 03 74 5E B8 16 00 00 00 EB 69 8D 46 10 31 D2 E8 ?? ?? ?? ?? EB 0F E8 ?? ?? ?? ?? 89 C3 39 46 08 75 07 FF 46 04 31 C0 EB 4A 8D 46 10 89 DA E8 ?? ?? ?? ?? 89 5E 08 C7 46 04 00 00 00 00 EB E6 E8 ?? ?? ?? ?? 89 C3 B8 23 00 00 00 39 5E 08 74 23 50 50 8D 46 10 53 50 E8 ?? ?? ?? ?? 89 5E 08 EB 0D 8D 46 10 51 51 6A 00 50 E8 ?? ?? ?? ?? 31 C0 83 C4 10 5A 5B 5E C3 }
	condition:
		$pattern
}

rule _longjmp_be9e6548214836180c2cfadd5a9f8fd0 {
	meta:
		aliases = "__libc_longjmp, __libc_siglongjmp, longjmp, siglongjmp, _longjmp"
		size = "51"
		objfiles = "longjmp@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 8B 5C 24 14 83 7E 18 00 74 11 8D 46 1C 52 6A 00 50 6A 02 E8 ?? ?? ?? ?? 83 C4 10 85 DB 75 02 B3 01 50 50 53 56 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clntudp_destroy_8f549cd315194b2c0f3c5e07fad6387d {
	meta:
		aliases = "clntudp_destroy"
		size = "76"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 8B 5E 08 83 7B 04 00 74 0D 83 EC 0C FF 33 E8 ?? ?? ?? ?? 83 C4 10 8B 43 3C 8B 50 1C 85 D2 74 0C 83 EC 0C 8D 43 38 50 FF D2 83 C4 10 83 EC 0C 53 E8 ?? ?? ?? ?? 89 74 24 20 83 C4 14 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clnttcp_destroy_3d747f0e4cbecef177b7b95e4e6c4b6b {
	meta:
		aliases = "clnttcp_destroy"
		size = "76"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 8B 5E 08 83 7B 04 00 74 0D 83 EC 0C FF 33 E8 ?? ?? ?? ?? 83 C4 10 8B 43 50 8B 50 1C 85 D2 74 0C 83 EC 0C 8D 43 4C 50 FF D2 83 C4 10 83 EC 0C 53 E8 ?? ?? ?? ?? 89 74 24 20 83 C4 14 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clntunix_destroy_61e5462b6605355242f06f066eee6cb3 {
	meta:
		aliases = "clntunix_destroy"
		size = "82"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 8B 5E 08 83 7B 04 00 74 0D 83 EC 0C FF 33 E8 ?? ?? ?? ?? 83 C4 10 8B 83 B0 00 00 00 8B 50 1C 85 D2 74 0F 83 EC 0C 8D 83 AC 00 00 00 50 FF D2 83 C4 10 83 EC 0C 53 E8 ?? ?? ?? ?? 89 74 24 20 83 C4 14 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getttynam_2828fb055fa1bf0856c820dcc4347521 {
	meta:
		aliases = "getttynam"
		size = "55"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 E8 ?? ?? ?? ?? EB 11 51 51 FF 33 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 0B E8 ?? ?? ?? ?? 89 C3 85 C0 75 E4 E8 ?? ?? ?? ?? 89 D8 5A 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_hcreate_r_48c7eae2ffee45054c0fcc81a28e6413 {
	meta:
		aliases = "hcreate_r, __GI_hcreate_r"
		size = "127"
		objfiles = "hcreate_r@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 14 85 F6 75 0F E8 ?? ?? ?? ?? C7 00 16 00 00 00 31 C0 EB 5F 31 C0 83 3E 00 75 58 8B 4C 24 10 83 C9 01 EB 03 83 C1 02 BB 03 00 00 00 EB 03 83 C3 02 89 D8 0F AF C3 39 C8 73 0A 31 D2 89 C8 F7 F3 85 D2 75 EA 31 D2 89 C8 F7 F3 85 D2 74 D6 89 4E 04 C7 46 08 00 00 00 00 51 51 6A 0C 8B 46 04 40 50 E8 ?? ?? ?? ?? 83 C4 10 89 06 85 C0 0F 95 C0 0F B6 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule confstr_f0abb6d24626c284a4a1c106ad3795db {
	meta:
		aliases = "confstr"
		size = "104"
		objfiles = "confstr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 14 8B 5C 24 18 83 7C 24 10 00 75 0F 85 DB 74 04 85 F6 75 16 B8 0E 00 00 00 EB 41 E8 ?? ?? ?? ?? C7 00 16 00 00 00 31 C0 EB 32 83 FB 0D 76 10 53 6A 0E 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? EB 15 8D 43 FF 51 50 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? C6 44 1E FF 00 B8 0E 00 00 00 83 C4 10 5A 5B 5E C3 }
	condition:
		$pattern
}

rule _obstack_begin_c55b4d64ccc4b9e447d95ce5d7c0ba41 {
	meta:
		aliases = "_obstack_begin"
		size = "140"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 18 8B 5C 24 10 8B 54 24 14 8B 4C 24 1C 85 F6 75 04 66 BE 04 00 85 D2 75 04 66 BA E0 0F 89 4B 1C 8B 44 24 20 89 13 80 63 28 FE 89 43 20 8D 46 FF 89 43 18 F6 43 28 01 74 08 50 50 52 FF 73 24 EB 05 83 EC 0C FF 33 FF D1 83 C4 10 89 C2 89 43 04 85 C0 75 05 E8 ?? ?? ?? ?? 8D 44 30 07 F7 DE 21 F0 89 43 08 89 43 0C 89 D0 03 03 89 02 89 43 10 C7 42 04 00 00 00 00 B8 01 00 00 00 80 63 28 F9 5A 5B 5E C3 }
	condition:
		$pattern
}

rule sethostid_4a394e53c2cca5d1a84444d7dce8316d {
	meta:
		aliases = "sethostid"
		size = "111"
		objfiles = "hostid@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 E8 ?? ?? ?? ?? 85 C0 75 09 E8 ?? ?? ?? ?? 85 C0 74 12 E8 ?? ?? ?? ?? BB 01 00 00 00 C7 00 01 00 00 00 EB 40 53 68 A4 01 00 00 6A 41 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 CB FF 83 C4 10 89 C6 85 C0 78 22 51 6A 04 8D 44 24 18 31 DB 50 56 E8 ?? ?? ?? ?? 89 34 24 83 F8 04 0F 94 C3 4B E8 ?? ?? ?? ?? 83 C4 10 89 D8 5A 5B 5E C3 }
	condition:
		$pattern
}

rule __pthread_attr_setguardsize_1e0d70aedc815ecc07f3a6522d51a301 {
	meta:
		aliases = "pthread_attr_setguardsize, __pthread_attr_setguardsize"
		size = "54"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 E8 ?? ?? ?? ?? 8B 54 24 14 89 C6 8B 5C 24 10 8D 54 02 FF 89 D0 31 D2 F7 F6 89 C1 B8 16 00 00 00 0F AF CE 3B 4B 20 73 05 89 4B 14 30 C0 5B 5B 5E C3 }
	condition:
		$pattern
}

rule __pthread_cleanup_pop_restore_9c7fcdd01c495626ad0376603e26416b {
	meta:
		aliases = "_pthread_cleanup_pop_restore, __pthread_cleanup_pop_restore"
		size = "78"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 E8 ?? ?? ?? ?? 8B 74 24 10 89 C3 83 7C 24 14 00 74 0B 83 EC 0C FF 76 04 FF 16 83 C4 10 8B 46 0C 89 43 3C 8B 46 08 88 43 41 80 7B 42 00 74 16 66 81 7B 40 00 01 75 0E 53 53 8D 44 24 0C 50 6A FF E8 ?? ?? ?? ?? 59 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_rwlock_wrlock_df6a860f98b16d18c7712620517b9f87 {
	meta:
		aliases = "pthread_rwlock_wrlock"
		size = "88"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 E8 ?? ?? ?? ?? 8B 74 24 10 89 C3 89 DA 89 F0 E8 ?? ?? ?? ?? 83 7E 08 00 75 06 83 7E 0C 00 74 1F 89 DA 8D 46 14 E8 ?? ?? ?? ?? 83 EC 0C 56 E8 ?? ?? ?? ?? 89 D8 E8 ?? ?? ?? ?? 83 C4 10 EB CC 83 EC 0C 89 5E 0C 56 E8 ?? ?? ?? ?? 83 C4 14 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule svcraw_getargs_b98179ce9300503bf2580d889ff4c60f {
	meta:
		aliases = "svcraw_getargs"
		size = "54"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 E8 ?? ?? ?? ?? 8B 74 24 14 8B 5C 24 18 8B 80 BC 00 00 00 85 C0 74 14 05 94 23 00 00 89 5C 24 14 89 44 24 10 89 F1 58 5B 5E FF E1 31 C0 5E 5B 5E C3 }
	condition:
		$pattern
}

rule clntraw_freeres_d3822af9ff3357f92e4e60294ab4ad1c {
	meta:
		aliases = "clntraw_freeres"
		size = "62"
		objfiles = "clnt_raw@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 E8 ?? ?? ?? ?? 8B 74 24 14 8B 5C 24 18 8B 90 A0 00 00 00 85 D2 74 19 8D 42 0C C7 42 0C 02 00 00 00 89 F1 89 5C 24 14 89 44 24 10 5B 5B 5E FF E1 B8 10 00 00 00 5A 5B 5E C3 }
	condition:
		$pattern
}

rule svcraw_freeargs_62be0d0dd34304fed2ea1fbada79e698 {
	meta:
		aliases = "svcraw_freeargs"
		size = "65"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 E8 ?? ?? ?? ?? 8B 74 24 14 8B 5C 24 18 8B 90 BC 00 00 00 85 D2 74 1F 8D 82 94 23 00 00 C7 82 94 23 00 00 02 00 00 00 89 F1 89 5C 24 14 89 44 24 10 5B 5B 5E FF E1 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule flush_out_39cbed046d6f105fcf6d68962338de9a {
	meta:
		aliases = "flush_out"
		size = "82"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 4A 0F 95 C2 8B 48 18 89 C6 0F B6 D2 8B 40 10 4A 29 C8 81 E2 00 00 00 80 83 E8 04 09 D0 0F C8 89 01 8B 46 0C 8B 5E 10 29 C3 53 50 FF 36 FF 56 08 83 C4 10 31 D2 39 D8 75 0E 8B 46 0C B2 01 89 46 18 83 C0 04 89 46 10 89 D0 5B 5B 5E C3 }
	condition:
		$pattern
}

rule fill_input_buf_e057e6838eabf11ef77811fccc891529 {
	meta:
		aliases = "fill_input_buf"
		size = "57"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 89 C3 8B 50 30 8B 70 28 83 E2 03 8B 40 24 01 D6 29 D0 50 56 FF 33 FF 53 20 83 C4 10 31 D2 83 F8 FF 74 0B 8D 04 06 89 73 2C 89 43 30 B2 01 89 D0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule _ppfs_init_7f23dd978560f4138c0cb1e89c3773dd {
	meta:
		aliases = "_ppfs_init"
		size = "111"
		objfiles = "_ppfs_init@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 5C 24 14 8B 74 24 18 68 BC 00 00 00 6A 00 53 E8 ?? ?? ?? ?? FF 4B 18 89 33 8D 43 28 BA 09 00 00 00 83 C4 10 C7 00 08 00 00 00 83 C0 04 4A 75 F4 89 F0 EB 27 83 C8 FF EB 2C 80 FA 25 75 1C 40 80 38 25 74 16 83 EC 0C 89 03 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 DE 8B 03 EB 01 40 8A 10 84 D2 75 D8 89 33 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule _authenticate_df94f6e68188a959ec9787aba3410e7a {
	meta:
		aliases = "__GI__authenticate, _authenticate"
		size = "89"
		objfiles = "svc_auth@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 5C 24 14 8B 74 24 18 6A 0C 8D 53 0C 8D 46 18 50 52 E8 ?? ?? ?? ?? 8B 53 1C A1 ?? ?? ?? ?? 83 C4 10 89 42 20 8B 43 1C C7 40 28 00 00 00 00 8B 43 0C 83 F8 03 77 14 89 74 24 14 89 5C 24 10 8B 0C 85 ?? ?? ?? ?? 5B 5B 5E FF E1 B8 02 00 00 00 5A 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_seed48_r_40b37feb198b00d1327d9c9076c36b58 {
	meta:
		aliases = "seed48_r, __GI_seed48_r"
		size = "81"
		objfiles = "seed48_r@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 5C 24 18 8B 74 24 14 6A 06 53 8D 43 06 50 E8 ?? ?? ?? ?? 66 8B 46 04 66 89 43 04 66 8B 46 02 66 89 43 02 66 8B 06 C7 43 10 6D E6 EC DE 66 89 03 C7 43 14 05 00 00 00 66 C7 43 0C 0B 00 66 C7 43 0E 01 00 31 C0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule mempcpy_b930ef2d821c66b1e2908efada814b15 {
	meta:
		aliases = "__GI_mempcpy, mempcpy"
		size = "33"
		objfiles = "mempcpy@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 5C 24 1C 8B 74 24 14 53 FF 74 24 1C 56 E8 ?? ?? ?? ?? 8D 04 1E 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule addmntent_3c5e524ca7ed427f7bf36aef8173d9e5 {
	meta:
		aliases = "addmntent"
		size = "77"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 74 24 14 8B 5C 24 18 6A 02 6A 00 56 E8 ?? ?? ?? ?? 83 C4 10 BA 01 00 00 00 85 C0 78 24 FF 73 14 FF 73 10 FF 73 0C FF 73 08 FF 73 04 FF 33 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 20 89 C2 C1 EA 1F 89 D0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule __xstat_conv_88b6b06efd928c6f79214cfd6dc826bd {
	meta:
		aliases = "__xstat_conv"
		size = "125"
		objfiles = "xstatconv@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 74 24 14 8B 5C 24 18 6A 58 6A 00 53 E8 ?? ?? ?? ?? 0F B7 06 C7 43 04 00 00 00 00 89 03 8B 46 04 89 43 0C 0F B7 46 08 89 43 10 0F B7 46 0A 89 43 14 0F B7 46 0C 89 43 18 0F B7 46 0E 89 43 1C 0F B7 46 10 C7 43 24 00 00 00 00 89 43 20 8B 46 14 89 43 2C 8B 46 18 89 43 30 8B 46 1C 89 43 34 8B 46 20 89 43 38 8B 46 28 89 43 40 8B 46 30 89 43 48 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule __xstat64_conv_3d4786d8c4f9cb7310a989356f5f21dc {
	meta:
		aliases = "__xstat64_conv"
		size = "146"
		objfiles = "xstatconv@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 74 24 14 8B 5C 24 18 6A 60 6A 00 53 E8 ?? ?? ?? ?? 0F B7 06 C7 43 04 00 00 00 00 89 03 8B 46 58 8B 56 5C 89 53 5C 89 43 58 8B 46 0C 89 43 0C 8B 46 10 89 43 10 8B 46 14 89 43 14 8B 46 18 89 43 18 8B 46 1C 89 43 1C 0F B7 46 20 C7 43 24 00 00 00 00 89 43 20 8B 46 2C 8B 56 30 89 53 30 89 43 2C 8B 46 34 89 43 34 8B 46 38 C7 43 3C 00 00 00 00 89 43 38 8B 46 40 89 43 40 8B 46 48 89 43 48 8B 46 50 89 43 50 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule xdrrec_getpos_92d6f52bb382a9138e6c26a70ee7a9e1 {
	meta:
		aliases = "xdrrec_getpos"
		size = "72"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 74 24 14 8B 5E 0C 6A 01 6A 00 FF 33 E8 ?? ?? ?? ?? 83 C4 10 89 C1 83 C8 FF 83 F9 FF 74 20 8B 16 85 D2 74 05 4A 75 17 EB 0B 8B 43 10 2B 43 0C 8D 04 01 EB 0A 8B 43 30 2B 43 2C 29 C1 89 C8 5A 5B 5E C3 }
	condition:
		$pattern
}

rule updwtmp_50e9badd87b267eb4d0062428b8803c0 {
	meta:
		aliases = "updwtmp"
		size = "96"
		objfiles = "wtent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 74 24 18 6A 00 68 01 04 00 00 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 78 3A 51 6A 00 6A 01 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 28 52 68 80 01 00 00 56 53 E8 ?? ?? ?? ?? 83 C4 0C 6A 00 6A 00 53 E8 ?? ?? ?? ?? 89 5C 24 20 83 C4 14 5B 5E E9 ?? ?? ?? ?? 58 5B 5E C3 }
	condition:
		$pattern
}

rule dlinfo_e923b7ad05650ab34c9bc6a3377e97ac {
	meta:
		aliases = "dlinfo"
		size = "220"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 83 C4 10 EB 2E FF 73 04 0F B7 43 20 50 8B 43 18 FF 34 85 ?? ?? ?? ?? FF 73 1C 53 FF 33 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 5B 0C 83 C4 20 85 DB 75 CE 53 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? EB 19 8B 03 FF 70 04 50 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 5B 10 83 C4 10 85 DB 75 E0 8B 35 ?? ?? ?? ?? EB 39 51 56 68 ?? ?? ?? ?? 89 F3 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 19 8B 03 FF 70 04 50 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 5B 10 }
	condition:
		$pattern
}

rule firstwhite_cfba3160739e0130d32518ce671cb17b {
	meta:
		aliases = "firstwhite"
		size = "50"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 89 C3 6A 20 50 E8 ?? ?? ?? ?? 59 5E 89 C6 6A 09 53 E8 ?? ?? ?? ?? 83 C4 10 85 F6 74 08 85 C0 74 06 39 C6 76 02 89 C6 89 F0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule __ether_line_w_74266ad6d55c7519085e0aca2caf74d3 {
	meta:
		aliases = "__ether_line_w"
		size = "56"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 89 C3 89 D6 6A 23 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 11 50 50 6A 0A 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 03 C6 00 00 89 F2 89 D8 5E 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __check_one_fd_2fe27dc3f836c7e5d97b1fc5ffa6dede {
	meta:
		aliases = "__check_one_fd"
		size = "52"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 89 C6 89 D3 6A 01 50 E8 ?? ?? ?? ?? 83 C4 10 40 75 19 50 50 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 39 F0 74 05 E8 ?? ?? ?? ?? 58 5B 5E C3 }
	condition:
		$pattern
}

rule svctcp_reply_7aa5d9eb0565fa0393c1e2e8f574408a {
	meta:
		aliases = "svcunix_reply, svctcp_reply"
		size = "58"
		objfiles = "svc_unix@libc.a, svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 8B 44 24 18 8B 54 24 1C 8B 40 2C C7 40 08 00 00 00 00 8D 70 08 8B 40 04 89 02 52 56 E8 ?? ?? ?? ?? 89 C3 58 5A 6A 01 56 E8 ?? ?? ?? ?? 89 D8 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_significand_26a11434ecd3d6d2a3d1eb55b659792b {
	meta:
		aliases = "significand, __GI_significand"
		size = "45"
		objfiles = "s_significand@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 8B 5C 24 18 8B 74 24 1C 56 53 E8 ?? ?? ?? ?? F7 D8 50 DB 04 24 83 EC 04 DD 1C 24 56 53 E8 ?? ?? ?? ?? 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule putenv_333a36c7bfc1ff4a5f2c6333b8a1f230 {
	meta:
		aliases = "putenv"
		size = "80"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 8B 74 24 18 6A 3D 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 25 29 F0 52 52 50 56 E8 ?? ?? ?? ?? 6A 01 89 C3 56 6A 00 50 E8 ?? ?? ?? ?? 83 C4 14 89 C6 53 E8 ?? ?? ?? ?? EB 0B 83 EC 0C 56 E8 ?? ?? ?? ?? 31 F6 89 F0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_opaque_auth_2b8a68d2f67bb93e97d3a79a3b69e311 {
	meta:
		aliases = "__GI_xdr_opaque_auth, xdr_opaque_auth"
		size = "59"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 8B 74 24 18 8B 5C 24 1C 53 56 E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 74 18 8D 43 08 68 90 01 00 00 50 8D 43 04 50 56 E8 ?? ?? ?? ?? 83 C4 10 89 C2 89 D0 5B 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_xdr_replymsg_67aa4ab65f591cdca36638abc203aceb {
	meta:
		aliases = "xdr_replymsg, __GI_xdr_replymsg"
		size = "87"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 8B 74 24 18 8B 5C 24 1C 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 36 8D 43 04 51 51 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 23 83 7B 04 01 75 1D 83 EC 0C 8D 43 0C 6A 00 68 ?? ?? ?? ?? 50 8D 43 08 50 56 E8 ?? ?? ?? ?? 83 C4 20 EB 02 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_pmap_74a6e0c9086d7cf1ad7d564079f19c95 {
	meta:
		aliases = "__GI_xdr_pmap, xdr_pmap"
		size = "90"
		objfiles = "pmap_prot@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 8B 74 24 18 8B 5C 24 1C 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 39 50 50 8D 43 04 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 26 50 50 8D 43 08 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 13 8D 43 0C 89 74 24 10 89 44 24 14 59 5B 5E E9 ?? ?? ?? ?? 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_xdr_rejected_reply_5d0e6fe14a204043f18aacc2a1de47b0 {
	meta:
		aliases = "xdr_rejected_reply, __GI_xdr_rejected_reply"
		size = "101"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 8B 74 24 18 8B 5C 24 1C 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 44 8B 03 85 C0 74 05 48 75 3B EB 26 50 50 8D 43 04 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 26 8D 43 08 89 74 24 10 89 44 24 14 5B 5B 5E E9 ?? ?? ?? ?? 8D 43 04 89 74 24 10 89 44 24 14 59 5B 5E E9 ?? ?? ?? ?? 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_xdr_accepted_reply_b745f0a69d3d9a894688d16274756211 {
	meta:
		aliases = "xdr_accepted_reply, __GI_xdr_accepted_reply"
		size = "128"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 8B 74 24 18 8B 5C 24 1C 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 5F 50 50 8D 43 0C 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 4C 8B 53 0C 85 D2 74 0C B8 01 00 00 00 83 FA 02 75 3D EB 13 8B 43 10 89 74 24 10 89 44 24 14 8B 4B 14 58 5B 5E FF E1 50 50 8D 43 10 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 13 8D 43 14 89 74 24 10 89 44 24 14 58 5B 5E E9 ?? ?? ?? ?? 31 C0 5E 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_authunix_parms_f51dd3a95664a9e3532f0d45ea7e3708 {
	meta:
		aliases = "__GI_xdr_authunix_parms, xdr_authunix_parms"
		size = "132"
		objfiles = "authunix_prot@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 8B 74 24 18 8B 5C 24 1C 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 63 50 8D 43 04 68 FF 00 00 00 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 4C 50 50 8D 43 08 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 39 50 50 8D 43 0C 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 26 8D 43 10 51 51 68 ?? ?? ?? ?? 6A 04 6A 10 50 8D 43 14 50 56 E8 ?? ?? ?? ?? 83 C4 20 85 C0 0F 95 C0 0F B6 C0 EB 02 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule strlcat_3286cee47a9b35c7bcfb53f476092849 {
	meta:
		aliases = "__GI_strlcat, strlcat"
		size = "61"
		objfiles = "strlcat@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 31 C9 8B 54 24 1C 8B 5C 24 20 8B 74 24 24 39 F1 72 06 8D 54 24 0F EB 10 80 3A 00 74 0B 42 41 EB ED 41 39 F1 83 D2 00 43 8A 03 88 02 84 C0 75 F1 83 C4 10 89 C8 5B 5E C3 }
	condition:
		$pattern
}

rule encrypt_b47a7daf224b858635c261c0a940a6a6 {
	meta:
		aliases = "encrypt"
		size = "152"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 31 DB 8B 74 24 1C E8 ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? 89 F1 EB 24 31 D2 C7 44 9C 08 00 00 00 00 EB 12 F6 01 01 74 0B 8B 04 95 ?? ?? ?? ?? 09 44 9C 08 41 42 83 FA 1F 7E E9 43 83 FB 01 7E D7 83 7C 24 20 01 19 DB 8B 54 24 0C 83 E3 02 8D 4C 24 08 4B 8B 44 24 08 53 8D 5C 24 10 53 E8 ?? ?? ?? ?? 31 DB 58 5A EB 1D 89 D8 8B 14 8D ?? ?? ?? ?? C1 E0 05 09 C8 85 54 9C 08 0F 95 04 06 41 83 F9 1F 7E E4 43 83 FB 01 7F 04 31 C9 EB F1 83 C4 10 5B 5E C3 }
	condition:
		$pattern
}

rule _stdio_term_fb6389d54396b700faac1ef1138273cf {
	meta:
		aliases = "_stdio_term"
		size = "136"
		objfiles = "_stdio@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? EB 3A 83 EC 0C 8D 73 38 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 14 8B 43 08 66 C7 03 30 00 89 43 18 89 43 1C 89 43 10 89 43 14 83 EC 0C C7 43 34 01 00 00 00 56 E8 ?? ?? ?? ?? 8B 5B 20 83 C4 10 85 DB 75 BF 8B 1D ?? ?? ?? ?? EB 14 F6 03 40 74 0C 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 8B 5B 20 85 DB 75 E8 58 5B 5E C3 }
	condition:
		$pattern
}

rule __wcslcpy_87774503142b2a3a63efa66630f9fa69 {
	meta:
		aliases = "wcsxfrm, __wcslcpy"
		size = "68"
		objfiles = "wcslcpy@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 44 24 24 8B 4C 24 1C 8B 74 24 20 85 C0 75 0A 8D 4C 24 0C 31 DB 89 F2 EB 10 8D 58 FF EB F7 85 DB 74 04 4B 83 C1 04 83 C2 04 8B 02 89 01 85 C0 75 ED 29 F2 83 C4 10 C1 FA 02 5B 89 D0 5E C3 }
	condition:
		$pattern
}

rule __GI_strxfrm_7e4500289543f3f39d6355a7c0813a78 {
	meta:
		aliases = "__GI_strlcpy, strxfrm, strlcpy, __GI_strxfrm"
		size = "61"
		objfiles = "strlcpy@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 44 24 24 8B 4C 24 1C 8B 74 24 20 85 C0 75 0A 8D 4C 24 0F 31 DB 89 F2 EB 0C 8D 58 FF EB F7 85 DB 74 02 4B 41 42 8A 02 88 01 84 C0 75 F1 29 F2 83 C4 10 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_fputs_unlocked_d2c3621195138ba1673ab64555a59981 {
	meta:
		aliases = "fputs_unlocked, __GI_fputs_unlocked"
		size = "51"
		objfiles = "fputs_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 5C 24 1C 53 E8 ?? ?? ?? ?? 83 C4 10 89 C6 FF 74 24 14 50 6A 01 53 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 39 F0 75 02 89 C2 89 D0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_key_delete_97708dc64c0b6d2fdc1ff18e5d3a3496 {
	meta:
		aliases = "pthread_key_delete"
		size = "157"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 5C 24 1C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 81 FB FF 03 00 00 77 0A 83 3C DD ?? ?? ?? ?? 00 75 14 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 16 00 00 00 EB 5B C7 04 DD ?? ?? ?? ?? 00 00 00 00 C7 04 DD ?? ?? ?? ?? 00 00 00 00 83 3D ?? ?? ?? ?? FF 74 2D E8 ?? ?? ?? ?? 89 DE C1 EE 05 83 E3 1F 89 C2 80 7A 2C 00 75 12 8B 8C B2 EC 00 00 00 85 C9 74 07 C7 04 99 00 00 00 00 8B 12 39 C2 75 E2 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule svctcp_destroy_8f1fb4e8db7b6491b1e0d492ba00bd8a {
	meta:
		aliases = "svcunix_destroy, svctcp_destroy"
		size = "89"
		objfiles = "svc_unix@libc.a, svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 5C 24 1C 8B 73 2C 53 E8 ?? ?? ?? ?? 59 FF 33 E8 ?? ?? ?? ?? 83 C4 10 66 83 7B 04 00 74 08 66 C7 43 04 00 00 EB 16 8B 46 0C 8B 50 1C 85 D2 74 0C 83 EC 0C 8D 46 08 50 FF D2 83 C4 10 83 EC 0C 56 E8 ?? ?? ?? ?? 89 5C 24 20 83 C4 14 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svcudp_destroy_6c0410118f09cdd805ab10c056f1d982 {
	meta:
		aliases = "svcudp_destroy"
		size = "84"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 5C 24 1C 8B 73 30 53 E8 ?? ?? ?? ?? 58 FF 33 E8 ?? ?? ?? ?? 8B 46 0C 8B 50 1C 83 C4 10 85 D2 74 0C 83 EC 0C 8D 46 08 50 FF D2 83 C4 10 83 EC 0C FF 73 2C E8 ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 89 5C 24 20 83 C4 14 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_fgetspent_r_87d796c483507ca6907ec6bb79491b76 {
	meta:
		aliases = "fgetspent_r, __GI_fgetgrent_r, fgetpwent_r, fgetgrent_r, __GI_fgetpwent_r, __GI_fgetspent_r"
		size = "55"
		objfiles = "fgetspent_r@libc.a, fgetpwent_r@libc.a, fgetgrent_r@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 5C 24 2C 8B 74 24 20 C7 03 00 00 00 00 FF 74 24 1C FF 74 24 2C FF 74 24 2C 56 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 20 85 C0 75 02 89 33 5A 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_fputws_unlocked_68bd56f42bd40b30c43be42201f32fdd {
	meta:
		aliases = "fputws_unlocked, __GI_fputws_unlocked"
		size = "46"
		objfiles = "fputws_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 74 24 1C 56 E8 ?? ?? ?? ?? 83 C4 0C 89 C3 FF 74 24 18 50 56 E8 ?? ?? ?? ?? 39 D8 0F 94 C0 0F B6 C0 83 C4 14 48 5B 5E C3 }
	condition:
		$pattern
}

rule getlogin_r_d0d4b27cf0a84449b60838ac0c698d0c {
	meta:
		aliases = "getlogin_r"
		size = "58"
		objfiles = "getlogin@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 74 24 1C 8B 5C 24 20 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 74 13 52 53 50 56 E8 ?? ?? ?? ?? C6 44 1E FF 00 31 D2 83 C4 10 89 D0 59 5B 5E C3 }
	condition:
		$pattern
}

rule xdrrec_setpos_457d4e27d12fb3c10bd5aed0f5d8c563 {
	meta:
		aliases = "xdrrec_setpos"
		size = "100"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 74 24 1C 8B 5E 0C 56 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 74 44 8B 16 2B 44 24 14 85 D2 74 05 4A 75 37 EB 14 8B 53 10 29 C2 3B 53 18 76 2B 3B 53 14 73 26 89 53 10 EB 1A 8B 53 2C 3B 43 34 7D 19 29 C2 3B 53 30 77 12 3B 53 28 72 0D 29 43 34 89 53 2C B8 01 00 00 00 EB 02 31 C0 59 5B 5E C3 }
	condition:
		$pattern
}

rule authunix_destroy_19fc340456e39d433dfc6db8b538e85f {
	meta:
		aliases = "authunix_destroy"
		size = "87"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 74 24 1C 8B 5E 24 FF 73 04 E8 ?? ?? ?? ?? 8B 43 10 83 C4 10 85 C0 74 0C 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C FF 76 24 E8 ?? ?? ?? ?? 8B 46 10 83 C4 10 85 C0 74 0C 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 89 74 24 10 58 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_ftell_c696decca2bd132fb15f420a442ba902 {
	meta:
		aliases = "ftello, ftell, __GI_ftell"
		size = "52"
		objfiles = "ftello@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 89 C3 89 C6 C1 FB 1F 39 D3 75 04 39 C0 74 0E E8 ?? ?? ?? ?? 83 CE FF C7 00 4B 00 00 00 89 F0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule setlogmask_ca26684f72d666dc5628e998cfee4e27 {
	meta:
		aliases = "setlogmask"
		size = "85"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 0F B6 35 ?? ?? ?? ?? 83 7C 24 20 00 74 37 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 10 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 44 24 30 A2 ?? ?? ?? ?? 58 5A 6A 01 53 E8 ?? ?? ?? ?? 83 C4 10 89 F2 83 C4 14 0F B6 C2 5B 5E C3 }
	condition:
		$pattern
}

rule ulckpwdf_c176aa3a24062f30eaf585d4bcbda25f {
	meta:
		aliases = "ulckpwdf"
		size = "95"
		objfiles = "lckpwdf@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 83 CE FF 83 3D ?? ?? ?? ?? FF 74 46 53 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 10 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? FF FF FF FF 89 C6 58 5A 6A 01 53 E8 ?? ?? ?? ?? 83 C4 10 89 F0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule __pthread_acquire_46137bb357154b6209fbdcdda7b3d979 {
	meta:
		aliases = "__pthread_acquire"
		size = "76"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 89 C3 31 F6 EB 30 83 FE 31 7F 08 E8 ?? ?? ?? ?? 46 EB 23 C7 44 24 0C 00 00 00 00 C7 44 24 10 81 84 1E 00 52 52 6A 00 31 F6 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 B8 01 00 00 00 87 03 85 C0 75 C5 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule byte_alt_match_null_string_p_2487a303cb2a03179a196b9e72106bcd {
	meta:
		aliases = "byte_alt_match_null_string_p"
		size = "86"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 89 D3 89 CE EB 1D 80 39 0F 75 1E 8D 41 01 89 44 24 10 0F BE 40 01 0F B6 51 01 C1 E0 08 01 C2 8D 44 11 03 89 44 24 10 EB 15 8D 44 24 10 89 F1 89 DA E8 ?? ?? ?? ?? 84 C0 75 04 31 C0 EB 0D 8B 4C 24 10 39 D9 72 C0 B8 01 00 00 00 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule getchar_89049f54ce64c565780e49c407785beb {
	meta:
		aliases = "getchar"
		size = "134"
		objfiles = "getchar@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 35 ?? ?? ?? ?? 83 7E 34 00 74 1E 8B 46 10 3B 46 18 73 09 0F B6 18 40 89 46 10 EB 5C 83 EC 0C 56 E8 ?? ?? ?? ?? 89 C3 EB 4C 8D 5E 38 52 53 68 ?? ?? ?? ?? 8D 44 24 10 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 46 10 83 C4 10 3B 46 18 73 09 0F B6 18 40 89 46 10 EB 0E 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 89 C3 50 50 6A 01 8D 44 24 10 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_fgetwc_unlocked_7d2e9d1399dac4935bcf0cbe2b7da6b5 {
	meta:
		aliases = "fgetwc_unlocked, getwc_unlocked, __GI_fgetwc_unlocked"
		size = "279"
		objfiles = "fgetwc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 20 0F B7 03 25 03 08 00 00 3D 00 08 00 00 77 1B 50 50 68 00 08 00 00 53 E8 ?? ?? ?? ?? 83 CE FF 83 C4 10 85 C0 0F 85 DC 00 00 00 0F B7 03 A8 02 74 31 A8 01 75 06 83 7B 28 00 74 06 C6 43 02 00 EB 06 8A 43 03 88 43 02 8B 03 89 C2 48 83 E2 01 66 89 03 8B 74 93 24 C7 43 28 00 00 00 00 E9 92 00 00 00 83 7B 08 00 75 0E 8D 54 24 13 89 D8 E8 ?? ?? ?? ?? FF 43 0C 83 7B 2C 00 75 04 C6 43 02 00 8B 43 14 8B 53 10 89 C6 29 D6 74 38 8D 43 2C 50 56 52 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 83 F8 00 7C 13 75 05 B8 01 00 00 00 01 43 10 00 43 02 8B 74 24 0C EB 3D 83 F8 FE 75 31 89 F0 01 }
	condition:
		$pattern
}

rule xdr_uint64_t_f5faca5dd249f3d7a22e68d212a4f7c7 {
	meta:
		aliases = "xdr_uint64_t"
		size = "190"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 20 8B 74 24 24 8B 03 83 F8 01 74 53 72 13 BA 01 00 00 00 83 F8 02 0F 84 92 00 00 00 E9 8B 00 00 00 8B 46 04 89 44 24 10 8B 06 89 44 24 0C 8D 44 24 10 52 52 8B 53 04 50 53 FF 52 24 83 C4 10 31 D2 85 C0 74 69 8D 44 24 0C 56 56 8B 53 04 50 53 FF 52 24 31 D2 83 C4 10 85 C0 0F 95 C2 EB 4F 8D 44 24 10 51 51 8B 53 04 50 53 FF 52 20 83 C4 10 85 C0 74 38 8D 44 24 0C 52 52 8B 53 04 50 53 FF 52 20 83 C4 10 85 C0 74 23 8B 44 24 10 31 D2 89 C2 B8 00 00 00 00 89 56 04 89 06 8B 44 24 0C BA 01 00 00 00 09 06 83 4E 04 00 EB 02 31 D2 83 C4 14 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_int64_t_91b66ff2fc7d89acbe6b889a84ff9b0a {
	meta:
		aliases = "xdr_int64_t"
		size = "198"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 20 8B 74 24 24 8B 03 83 F8 01 74 5C 72 13 BA 01 00 00 00 83 F8 02 0F 84 9A 00 00 00 E9 93 00 00 00 8B 56 04 8B 06 89 D0 89 44 24 10 89 C2 C1 FA 1F 8B 06 89 44 24 0C 50 50 8B 53 04 8D 44 24 18 50 53 FF 52 24 83 C4 10 31 D2 85 C0 74 68 8D 44 24 0C 56 56 8B 53 04 50 53 FF 52 24 31 D2 83 C4 10 85 C0 0F 95 C2 EB 4E 51 51 8B 43 04 8D 54 24 18 52 53 FF 50 20 83 C4 10 85 C0 74 37 8D 44 24 0C 52 52 8B 53 04 50 53 FF 52 20 83 C4 10 85 C0 74 22 8B 44 24 10 99 89 C2 B8 00 00 00 00 89 56 04 89 06 8B 44 24 0C BA 01 00 00 00 09 06 83 4E 04 00 EB 02 31 D2 83 C4 14 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_xdr_u_hyper_99c9ab42ade2823d0f03f88b4f0bbb5e {
	meta:
		aliases = "xdr_u_hyper, __GI_xdr_u_hyper"
		size = "180"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 20 8B 74 24 24 8B 03 85 C0 75 3C 8B 46 04 89 44 24 10 8B 06 89 44 24 0C 8D 44 24 10 52 52 8B 53 04 50 53 FF 52 04 83 C4 10 31 D2 85 C0 74 75 8D 44 24 0C 56 56 8B 53 04 50 53 FF 52 04 83 C4 10 85 C0 0F 95 C0 EB 56 83 F8 01 75 4B 8D 44 24 10 51 51 8B 53 04 50 53 FF 12 83 C4 10 85 C0 74 42 8D 44 24 0C 52 52 8B 53 04 50 53 FF 12 83 C4 10 85 C0 74 2E 8B 44 24 10 31 D2 89 C2 B8 00 00 00 00 89 56 04 89 06 8B 44 24 0C BA 01 00 00 00 09 06 83 4E 04 00 EB 0D 83 F8 02 0F 94 C0 0F B6 D0 EB 02 31 D2 83 C4 14 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_hyper_ba139af8bf0ee3515bfe0b87b2b6ffaf {
	meta:
		aliases = "__GI_xdr_hyper, xdr_hyper"
		size = "188"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 20 8B 74 24 24 8B 03 85 C0 75 45 8B 56 04 8B 06 89 D0 89 44 24 10 89 C2 C1 FA 1F 8B 06 89 44 24 0C 50 50 8B 53 04 8D 44 24 18 50 53 FF 52 04 83 C4 10 31 D2 85 C0 74 74 8D 44 24 0C 56 56 8B 53 04 50 53 FF 52 04 83 C4 10 85 C0 0F 95 C0 EB 55 83 F8 01 75 4A 51 51 8B 43 04 8D 54 24 18 52 53 FF 10 83 C4 10 85 C0 74 41 8D 44 24 0C 52 52 8B 53 04 50 53 FF 12 83 C4 10 85 C0 74 2D 8B 44 24 10 99 89 C2 B8 00 00 00 00 89 56 04 89 06 8B 44 24 0C BA 01 00 00 00 09 06 83 4E 04 00 EB 0D 83 F8 02 0F 94 C0 0F B6 D0 EB 02 31 D2 83 C4 14 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule xdrrec_getlong_0f19e228a0a9e93cc253a46d115ab288 {
	meta:
		aliases = "xdrrec_getlong"
		size = "97"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 20 8B 74 24 24 8B 53 0C 8B 4A 2C 83 7A 34 03 7E 1F 8B 42 30 29 C8 83 F8 03 7E 15 8B 01 0F C8 89 06 83 6A 34 04 83 42 2C 04 BA 01 00 00 00 EB 21 8D 44 24 10 51 6A 04 50 53 E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 74 0A 8B 44 24 10 B2 01 0F C8 89 06 83 C4 14 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule xdrrec_getint32_ca5addca5644d7ccbad730a0db780ab2 {
	meta:
		aliases = "xdrrec_getint32"
		size = "97"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 20 8B 74 24 24 8B 53 0C 8B 4A 2C 83 7A 34 03 7E 1F 8B 42 30 29 C8 83 F8 03 7E 15 8B 01 0F C8 89 06 83 6A 34 04 83 42 2C 04 BA 01 00 00 00 EB 21 8D 44 24 10 52 6A 04 50 53 E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 74 0A 8B 44 24 10 B2 01 0F C8 89 06 83 C4 14 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule __des_crypt_bc9604b435301a871e98a4b6f0f24bef {
	meta:
		aliases = "__des_crypt"
		size = "389"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 20 8B 74 24 24 E8 ?? ?? ?? ?? 8D 54 24 04 EB 0E 8A 03 01 C0 88 02 42 80 7A FF 01 83 DB FF 8D 4C 24 04 89 D0 29 C8 83 F8 08 75 E5 89 C8 E8 ?? ?? ?? ?? 8A 06 8A 56 01 88 44 24 03 A2 ?? ?? ?? ?? 8A 46 01 84 C0 75 04 8A 44 24 03 A2 ?? ?? ?? ?? 0F BE C2 E8 ?? ?? ?? ?? 89 C3 0F BE 44 24 03 C1 E3 06 E8 ?? ?? ?? ?? 09 C3 89 D8 E8 ?? ?? ?? ?? 8D 4C 24 10 6A 19 31 D2 8D 44 24 10 50 31 C0 E8 ?? ?? ?? ?? 59 31 D2 5B 85 C0 0F 85 E5 00 00 00 8B 54 24 10 C6 05 ?? ?? ?? ?? 00 89 D0 89 D1 C1 E8 1A C1 E9 08 8A 80 ?? ?? ?? ?? 83 E1 3F A2 ?? ?? ?? ?? 89 D0 C1 E8 14 83 E0 3F 8A 80 ?? ?? ?? }
	condition:
		$pattern
}

rule tanh_234cb83a249f3888ebd8328c7728a1fb {
	meta:
		aliases = "__GI_tanh, tanh"
		size = "238"
		objfiles = "s_tanh@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 24 8B 4C 24 20 89 D8 89 DE 25 FF FF FF 7F 3D FF FF EF 7F 7E 30 85 DB D9 E8 78 15 89 4C 24 08 89 5C 24 0C DD 44 24 08 D8 F9 DE C1 E9 B0 00 00 00 89 4C 24 08 89 5C 24 0C DD 44 24 08 D8 F9 DE E1 E9 9B 00 00 00 D9 E8 3D FF FF 35 40 0F 8F 88 00 00 00 DD D8 3D FF FF 7F 3C 7F 1A 89 4C 24 08 89 5C 24 0C DD 44 24 08 DC 05 ?? ?? ?? ?? DD 44 24 08 DE C9 EB 6B 3D FF FF EF 3F 7E 36 52 52 53 51 E8 ?? ?? ?? ?? D8 C0 DD 1C 24 E8 ?? ?? ?? ?? 31 C0 DC 05 ?? ?? ?? ?? BA 00 00 00 C0 89 44 24 18 89 54 24 1C DD 44 24 18 DE F1 DC 05 ?? ?? ?? ?? EB 25 50 50 53 51 E8 ?? ?? ?? ?? DC 0D ?? ?? ?? }
	condition:
		$pattern
}

rule __ieee754_sinh_9d46e4e8ec8a1ca1b7829b4278e2bed0 {
	meta:
		aliases = "__ieee754_sinh"
		size = "334"
		objfiles = "e_sinh@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 24 8B 4C 24 20 89 DE 81 E6 FF FF FF 7F 81 FE FF FF EF 7F 7E 11 89 0C 24 89 5C 24 04 DD 04 24 D8 C0 E9 06 01 00 00 85 DB 79 08 D9 05 ?? ?? ?? ?? EB 06 D9 05 ?? ?? ?? ?? DD 5C 24 08 81 FE FF FF 35 40 7F 6F 81 FE FF FF 2F 3E 7F 1F 89 0C 24 89 5C 24 04 DD 04 24 DC 05 ?? ?? ?? ?? D9 E8 D9 C9 DA E9 DF E0 9E 0F 87 CB 00 00 00 50 50 53 51 E8 ?? ?? ?? ?? DD 1C 24 E8 ?? ?? ?? ?? 83 C4 10 D9 C0 81 FE FF FF EF 3F D9 E8 7F 18 D9 CA D8 C1 DD 1C 24 D9 C0 D8 C9 D9 C9 DE C2 DE F1 DD 04 24 DE E1 EB 0A DD DA D9 C9 D8 C1 D8 F9 DE C1 DC 4C 24 08 EB 79 81 FE 41 2E 86 40 7F 17 52 52 53 51 E8 }
	condition:
		$pattern
}

rule __ieee754_cosh_6d689d438faef44857f02b1877b1496a {
	meta:
		aliases = "__ieee754_cosh"
		size = "267"
		objfiles = "e_cosh@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 24 8B 4C 24 20 89 DE 81 E6 FF FF FF 7F 81 FE FF FF EF 7F 7E 11 89 4C 24 08 89 5C 24 0C DD 44 24 08 E9 CF 00 00 00 81 FE 42 2E D6 3F 7F 37 50 50 53 51 E8 ?? ?? ?? ?? DD 1C 24 E8 ?? ?? ?? ?? 83 C4 10 D9 E8 D9 C1 D8 C1 81 FE FF FF 7F 3C 0F 8E A5 00 00 00 D9 CA D8 C8 D9 CA D8 C0 DE FA DE C1 E9 98 00 00 00 81 FE FF FF 35 40 7F 23 56 56 53 51 E8 ?? ?? ?? ?? DD 1C 24 E8 ?? ?? ?? ?? D9 05 ?? ?? ?? ?? D9 C1 D8 C9 D9 C9 DE F2 DE C1 EB 5A 81 FE 41 2E 86 40 7F 19 52 52 53 51 E8 ?? ?? ?? ?? DD 1C 24 E8 ?? ?? ?? ?? D8 0D ?? ?? ?? ?? EB 39 81 FE CD 33 86 40 7E 10 81 FE CE 33 86 40 75 }
	condition:
		$pattern
}

rule __GI_xdr_rmtcallres_c6acbbd62f3c368106178e71aa10b27e {
	meta:
		aliases = "xdr_rmtcallres, __GI_xdr_rmtcallres"
		size = "91"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 24 8B 74 24 20 8B 03 89 44 24 10 68 ?? ?? ?? ?? 6A 04 8D 44 24 18 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 27 50 50 8D 43 04 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 14 8B 44 24 10 89 03 50 50 FF 73 08 56 FF 53 0C 83 C4 10 EB 02 31 C0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule putc_unlocked_3285cd6d795474f19a1a1b20ef0fa5ce {
	meta:
		aliases = "__fputc_unlocked, __GI___fputc_unlocked, fputc_unlocked, __GI_putc_unlocked, putc_unlocked"
		size = "197"
		objfiles = "fputc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 24 8B 74 24 20 8B 43 10 3B 43 1C 73 0D 89 F2 88 10 40 89 43 10 E9 95 00 00 00 0F B7 03 25 C0 00 00 00 3D C0 00 00 00 74 14 52 52 68 80 00 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 77 83 7B 04 FE 75 07 89 F1 0F B6 C1 EB 6D 8B 43 0C 3B 43 08 74 40 3B 43 10 75 10 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 4D 8B 43 10 89 F2 88 10 40 89 43 10 F6 43 01 01 74 35 80 FA 0A 75 30 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 20 FF 4B 10 EB 22 89 F0 88 44 24 13 50 6A 01 8D 44 24 1B 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 07 89 F2 0F B6 C2 EB 03 83 C8 FF 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule __pthread_once_b1c81f286cf744b05109003a8c47f3bd {
	meta:
		aliases = "pthread_once, __pthread_once"
		size = "226"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 74 24 20 83 3E 02 75 05 E9 C7 00 00 00 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 16 83 C4 10 89 D0 83 E0 03 48 75 27 83 E2 FC 3B 15 ?? ?? ?? ?? 74 1C C7 06 00 00 00 00 EB 14 51 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 8B 16 89 D0 83 E0 03 48 74 E2 31 DB 85 D2 75 52 83 EC 0C A1 ?? ?? ?? ?? 83 C8 01 89 06 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 56 68 ?? ?? ?? ?? 8D 5C 24 10 53 E8 ?? ?? ?? ?? FF 54 24 34 58 5A 6A 00 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? BB 01 00 00 00 C7 06 02 00 00 00 83 C4 10 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 DB }
	condition:
		$pattern
}

rule getc_28533b1cefabf1ab94ce337a9bba49c5 {
	meta:
		aliases = "__GI_fgetc, fgetc, getc"
		size = "132"
		objfiles = "fgetc@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 74 24 20 83 7E 34 00 74 1E 8B 46 10 3B 46 18 73 09 0F B6 18 40 89 46 10 EB 5C 83 EC 0C 56 E8 ?? ?? ?? ?? 89 C3 EB 4C 8D 5E 38 52 53 68 ?? ?? ?? ?? 8D 44 24 10 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 46 10 83 C4 10 3B 46 18 73 09 0F B6 18 40 89 46 10 EB 0E 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 89 C3 50 50 6A 01 8D 44 24 10 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule readtcp_2ca2e3de1aa0c3df0bb4a26faacc40ed {
	meta:
		aliases = "readtcp"
		size = "124"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 74 24 20 8B 1E 89 5C 24 0C 66 C7 44 24 10 01 00 50 68 B8 88 00 00 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 74 06 85 C0 74 36 EB 0A E8 ?? ?? ?? ?? 83 38 04 EB 0B 0F BF 44 24 12 A8 18 75 21 A8 20 75 1D F6 44 24 12 01 74 B7 50 FF 74 24 2C FF 74 24 2C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 7F 0C 8B 46 2C C7 00 00 00 00 00 83 C8 FF 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule __pthread_alt_lock_0ba3a161190ed44f0f32a53394f0c8c6 {
	meta:
		aliases = "__pthread_alt_lock"
		size = "85"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 74 24 20 8B 54 24 24 8B 1E B9 01 00 00 00 85 DB 74 13 85 D2 75 07 E8 ?? ?? ?? ?? 89 C2 89 54 24 0C 8D 4C 24 08 C7 44 24 10 00 00 00 00 89 5C 24 08 89 D8 F0 0F B1 0E 0F 94 C1 84 C9 74 C9 85 DB 74 07 89 D0 E8 ?? ?? ?? ?? 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule unlockpt_c3f68d5f84e2d290f5d22dda30182b48 {
	meta:
		aliases = "unlockpt"
		size = "71"
		objfiles = "unlockpt@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 E8 ?? ?? ?? ?? 89 C3 8B 30 C7 44 24 10 00 00 00 00 50 8D 44 24 14 50 68 31 54 04 40 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 74 0C 83 CA FF 83 3B 16 75 04 89 33 31 D2 83 C4 14 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule __new_sem_wait_54b1b4ea9a00f244da5566d4996906ed {
	meta:
		aliases = "sem_wait, __new_sem_wait"
		size = "273"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 E8 ?? ?? ?? ?? 8B 5C 24 20 89 44 24 10 8B 54 24 10 89 D8 89 5C 24 08 C7 44 24 0C ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 43 08 85 C0 7E 15 83 EC 0C 48 89 43 08 53 E8 ?? ?? ?? ?? 83 C4 10 E9 C4 00 00 00 8B 44 24 10 8D 54 24 08 C6 80 BA 01 00 00 00 8B 44 24 10 E8 ?? ?? ?? ?? 8B 44 24 10 80 78 42 00 74 0F 8B 44 24 10 BE 01 00 00 00 80 78 40 00 74 0E 8B 54 24 10 8D 43 0C E8 ?? ?? ?? ?? 31 F6 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 F6 74 0D 8B 44 24 10 31 D2 E8 ?? ?? ?? ?? EB 5A 8B 44 24 10 E8 ?? ?? ?? ?? 8B 44 24 10 80 B8 BA 01 00 00 00 75 17 8B 44 24 10 80 B8 B8 01 00 00 00 74 DD 8B 44 24 10 }
	condition:
		$pattern
}

rule join_extricate_func_a57f9ca20b50047366c155b8017ffe16 {
	meta:
		aliases = "join_extricate_func"
		size = "66"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 E8 ?? ?? ?? ?? 8B 5C 24 20 89 44 24 10 8B 54 24 10 89 D8 E8 ?? ?? ?? ?? 8B 43 08 83 78 38 00 0F 95 C2 83 EC 0C C7 40 38 00 00 00 00 0F B6 F2 53 E8 ?? ?? ?? ?? 89 F0 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule cond_extricate_func_1563cf641f7860d165ff388535021a52 {
	meta:
		aliases = "cond_extricate_func"
		size = "60"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 E8 ?? ?? ?? ?? 8B 5C 24 20 89 44 24 10 8B 54 24 10 89 D8 E8 ?? ?? ?? ?? 8B 54 24 24 8D 43 08 E8 ?? ?? ?? ?? 83 EC 0C 89 C6 53 E8 ?? ?? ?? ?? 89 F0 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule new_sem_extricate_func_7219cd865faa9cc8d4f3f4a9244f3505 {
	meta:
		aliases = "new_sem_extricate_func"
		size = "60"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 E8 ?? ?? ?? ?? 8B 5C 24 20 89 44 24 10 8B 54 24 10 89 D8 E8 ?? ?? ?? ?? 8B 54 24 24 8D 43 0C E8 ?? ?? ?? ?? 83 EC 0C 89 C6 53 E8 ?? ?? ?? ?? 89 F0 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_reap_children_0a8be2b5416062c6422834fd627d9723 {
	meta:
		aliases = "pthread_reap_children"
		size = "244"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 E9 C7 00 00 00 8B 0D ?? ?? ?? ?? 8B 31 EB 75 39 46 14 8B 16 75 6C 8B 46 04 89 42 04 8B 46 04 89 10 31 D2 8B 46 1C E8 ?? ?? ?? ?? C6 46 2E 01 83 BE 9C 01 00 00 00 74 2B A1 ?? ?? ?? ?? 0B 86 A0 01 00 00 F6 C4 08 74 1B C7 86 A8 01 00 00 0C 00 00 00 89 B6 AC 01 00 00 89 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 0C 0F BE 5E 2D FF 76 1C E8 ?? ?? ?? ?? 83 C4 10 85 DB 74 0F 89 F0 E8 ?? ?? ?? ?? EB 06 89 D6 39 CE 75 87 83 3D ?? ?? ?? ?? 00 74 12 A1 ?? ?? ?? ?? 8B 10 39 C2 75 07 89 D0 E8 ?? ?? ?? ?? 8B 4C 24 10 88 C8 83 E0 7F 40 D0 F8 84 C0 7E 19 83 E1 7F BA 01 00 00 00 89 C8 E8 ?? ?? ?? ?? 83 }
	condition:
		$pattern
}

rule setstate_bdfaac75fc3a63cb4849ca4518c15069 {
	meta:
		aliases = "setstate"
		size = "93"
		objfiles = "random@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 31 F6 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 10 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 5A 68 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 03 8D 73 FC 50 50 6A 01 8D 44 24 10 50 E8 ?? ?? ?? ?? 89 F0 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule getnetent_5786b9ba3a2bdda358726609ede993f5 {
	meta:
		aliases = "__GI_getnetent, getnetent"
		size = "382"
		objfiles = "getnetent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 10 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 3D ?? ?? ?? ?? 00 75 21 51 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 A3 ?? ?? ?? ?? 85 C0 0F 84 14 01 00 00 83 3D ?? ?? ?? ?? 00 75 1E 83 EC 0C 68 01 10 00 00 E8 ?? ?? ?? ?? 83 C4 10 A3 ?? ?? ?? ?? 85 C0 75 05 E8 ?? ?? ?? ?? 52 FF 35 ?? ?? ?? ?? 68 00 10 00 00 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 0F 84 C9 00 00 00 80 38 23 74 B0 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74 A2 C6 00 00 BA ?? ?? ?? ?? 89 D8 89 1D ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74 }
	condition:
		$pattern
}

rule getrpcbyname_r_eb835e6a8113c3bbf67ddcde6b597827 {
	meta:
		aliases = "getrpcbyname_r"
		size = "90"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 10 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 FF 74 24 2C E8 ?? ?? ?? ?? 59 5E FF 74 24 38 FF 74 24 38 8B 4C 24 38 8B 54 24 34 E8 ?? ?? ?? ?? 89 C6 58 5A 6A 01 53 E8 ?? ?? ?? ?? 89 F0 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule getrpcbynumber_r_e8e13f6a51ca4363dd23fc3c5e55491f {
	meta:
		aliases = "getrpcbynumber_r"
		size = "90"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 10 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5E FF 74 24 2C E8 ?? ?? ?? ?? 5A 59 FF 74 24 38 FF 74 24 38 8B 54 24 34 8B 4C 24 38 E8 ?? ?? ?? ?? 59 89 C6 58 6A 01 53 E8 ?? ?? ?? ?? 89 F0 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule initstate_66cdcadd57bd3fd0f030d1c5a429f617 {
	meta:
		aliases = "initstate"
		size = "87"
		objfiles = "random@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 10 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? FF 74 24 3C FF 74 24 3C FF 74 24 3C E8 ?? ?? ?? ?? 83 C4 18 6A 01 53 E8 ?? ?? ?? ?? 83 EE 04 89 F0 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule getrpcent_r_c42aefac941de660c2328feee7413ad2 {
	meta:
		aliases = "getrpcent_r"
		size = "85"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 10 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 5E FF 74 24 34 FF 74 24 34 8B 4C 24 34 8B 54 24 30 E8 ?? ?? ?? ?? 89 C6 58 5A 6A 01 53 E8 ?? ?? ?? ?? 89 F0 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_getutid_7757f259b8832d00830575f73e1151f0 {
	meta:
		aliases = "getutid, __GI_getutid"
		size = "66"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 74 24 10 56 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 30 E8 ?? ?? ?? ?? 89 C3 58 5A 6A 01 56 E8 ?? ?? ?? ?? 89 D8 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule getutent_d35f86338302e0c148a97b70496073f8 {
	meta:
		aliases = "getutent"
		size = "67"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 74 24 10 56 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 89 C3 58 6A 01 56 E8 ?? ?? ?? ?? 89 D8 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule _time_mktime_94a7ece153751e236417951c5eda2993 {
	meta:
		aliases = "_time_mktime"
		size = "83"
		objfiles = "_time_mktime@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 74 24 10 56 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 68 ?? ?? ?? ?? FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 89 C3 58 5A 6A 01 56 E8 ?? ?? ?? ?? 89 D8 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule initgroups_457c1cb69f080bf9ccd5f4b45b12930e {
	meta:
		aliases = "initgroups"
		size = "76"
		objfiles = "initgroups@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 83 CE FF 8D 44 24 14 C7 44 24 14 FF FF FF 7F 50 FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 74 19 50 50 53 FF 74 24 1C E8 ?? ?? ?? ?? 89 1C 24 89 C6 E8 ?? ?? ?? ?? 83 C4 10 89 F0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule getutline_e1e5fe936d49f9478b08f2c658d80aea {
	meta:
		aliases = "getutline"
		size = "117"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 8B 74 24 24 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 10 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 EB 21 8B 03 83 E8 06 66 83 F8 01 77 16 50 50 8D 46 08 50 8D 43 08 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 10 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 85 C0 75 CF 51 51 6A 01 8D 44 24 10 50 E8 ?? ?? ?? ?? 89 D8 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule exit_92009d95869b71367a0451d2692523a2 {
	meta:
		aliases = "__GI_exit, exit"
		size = "103"
		objfiles = "exit@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 8B 74 24 24 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 10 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 09 83 EC 0C 56 FF D0 83 C4 10 50 50 6A 01 53 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 83 C4 10 85 C0 74 05 E8 ?? ?? ?? ?? 83 EC 0C 56 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_openlog_be589ff58021c5e359eeb7d1a2bd8be5 {
	meta:
		aliases = "openlog, __GI_openlog"
		size = "297"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 8B 74 24 24 8B 5C 24 2C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 10 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 F6 74 06 89 35 ?? ?? ?? ?? 8B 44 24 24 85 DB A2 ?? ?? ?? ?? 74 0E F7 C3 07 FC FF FF 75 06 89 1D ?? ?? ?? ?? BB 02 00 00 00 83 3D ?? ?? ?? ?? FF 75 56 F6 05 ?? ?? ?? ?? 08 74 4D 56 6A 00 53 6A 01 E8 ?? ?? ?? ?? 83 C4 10 A3 ?? ?? ?? ?? 83 F8 FF 0F 84 8D 00 00 00 51 6A 01 6A 02 50 E8 ?? ?? ?? ?? 58 5A 6A 03 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 80 CC 08 50 6A 04 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 A1 ?? ?? ?? ?? 83 F8 FF 74 52 80 3D ?? ?? ?? }
	condition:
		$pattern
}

rule readdir_3db7441dd527feeb5476b22cb945b89d {
	meta:
		aliases = "__GI_readdir, readdir"
		size = "132"
		objfiles = "readdir@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 8B 74 24 24 8D 5E 18 53 68 ?? ?? ?? ?? 8D 44 24 10 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 46 08 3B 46 04 77 23 52 FF 76 14 FF 76 0C FF 36 E8 ?? ?? ?? ?? 83 C4 10 85 C0 7F 04 31 DB EB 26 89 46 08 C7 46 04 00 00 00 00 8B 46 04 89 C3 03 5E 0C 0F B7 53 08 01 D0 89 46 04 8B 43 04 89 46 10 83 3B 00 74 B9 50 50 6A 01 8D 44 24 10 50 E8 ?? ?? ?? ?? 89 D8 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule readdir64_6c298d060a8d31d21d5a79c26aec2088 {
	meta:
		aliases = "__GI_readdir64, readdir64"
		size = "134"
		objfiles = "readdir64@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 8B 74 24 24 8D 5E 18 53 68 ?? ?? ?? ?? 8D 44 24 10 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 46 08 3B 46 04 77 23 52 FF 76 14 FF 76 0C FF 36 E8 ?? ?? ?? ?? 83 C4 10 85 C0 7F 04 31 DB EB 28 89 46 08 C7 46 04 00 00 00 00 8B 46 04 89 C3 03 5E 0C 0F B7 53 10 01 D0 89 46 04 8B 43 08 89 46 10 8B 03 0B 43 04 74 B7 50 50 6A 01 8D 44 24 10 50 E8 ?? ?? ?? ?? 89 D8 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_pointer_8fe6063c9005f759b462427f26752f9f {
	meta:
		aliases = "xdr_pointer"
		size = "90"
		objfiles = "xdr_reference@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 1C 31 C0 8B 5C 24 2C 8B 74 24 28 83 3B 00 0F 95 C0 89 44 24 18 8D 44 24 18 50 56 E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 74 25 83 7C 24 10 00 75 0A B2 01 C7 03 00 00 00 00 EB 14 FF 74 24 2C FF 74 24 2C 53 56 E8 ?? ?? ?? ?? 83 C4 10 89 C2 83 C4 14 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule lseek64_911b7e04e9a2df68f864f398c5fa53eb {
	meta:
		aliases = "lseek64"
		size = "68"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 1C 8D 44 24 18 8B 5C 24 2C 8B 74 24 30 50 6A 01 E8 ?? ?? ?? ?? FF 74 24 3C 56 53 FF 74 24 3C E8 ?? ?? ?? ?? 83 C4 18 6A 00 89 C3 FF 74 24 1C 89 D6 E8 ?? ?? ?? ?? 89 D8 89 F2 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule pread64_35cf6f4a8cedea687a42f86da83c10ef {
	meta:
		aliases = "pread64"
		size = "70"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 1C 8D 44 24 18 8B 74 24 38 8B 5C 24 34 50 6A 01 E8 ?? ?? ?? ?? 89 34 24 53 FF 74 24 3C FF 74 24 3C FF 74 24 3C E8 ?? ?? ?? ?? 83 C4 18 6A 00 89 C3 FF 74 24 1C E8 ?? ?? ?? ?? 89 D8 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_rwlock_rdlock_5fca6b496d963bd1cde73799db669c35 {
	meta:
		aliases = "pthread_rwlock_rdlock"
		size = "171"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 20 8B 5C 24 2C 8D 54 24 14 C7 44 24 1C 00 00 00 00 8D 4C 24 18 8D 44 24 1C 52 89 DA E8 ?? ?? ?? ?? 89 C6 83 C4 10 83 7C 24 10 00 75 09 E8 ?? ?? ?? ?? 89 44 24 10 8B 54 24 10 89 D8 E8 ?? ?? ?? ?? 89 F2 89 D8 E8 ?? ?? ?? ?? 85 C0 75 20 8B 54 24 10 8D 43 10 E8 ?? ?? ?? ?? 83 EC 0C 53 E8 ?? ?? ?? ?? 8B 44 24 20 E8 ?? ?? ?? ?? EB B5 83 EC 0C FF 43 08 53 E8 ?? ?? ?? ?? 83 C4 10 85 F6 75 07 83 7C 24 08 00 74 17 8B 44 24 0C 85 C0 74 05 FF 40 08 EB 0A 8B 44 24 10 FF 80 C8 01 00 00 83 C4 14 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule __error_9402e2398908dcf63de459ddad3f2784 {
	meta:
		aliases = "error, __error"
		size = "209"
		objfiles = "error@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 20 8B 74 24 2C 8B 5C 24 30 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 04 FF D0 EB 1A 51 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 8D 44 24 2C 89 44 24 10 52 50 FF 74 24 30 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 05 ?? ?? ?? ?? 83 C4 10 85 DB 74 20 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 0C 50 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 8B 15 ?? ?? ?? ?? 83 7A 34 00 74 1D 8B 42 10 3B 42 1C 73 09 C6 00 0A 40 89 42 10 EB 19 53 53 52 6A 0A E8 ?? ?? ?? ?? EB 0A 51 51 52 6A 0A E8 ?? ?? ?? ?? 83 C4 10 85 F6 74 09 83 EC 0C 56 E8 ?? }
	condition:
		$pattern
}

rule tmpnam_3d66935dda1ef5fea1615b1735b13bf7 {
	meta:
		aliases = "tmpnam"
		size = "90"
		objfiles = "tmpnam@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 24 8B 5C 24 30 89 DE 85 DB 75 04 8D 74 24 10 6A 00 6A 00 6A 14 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 2A 52 52 6A 03 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 19 85 DB 75 17 50 6A 14 56 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 89 C3 EB 02 31 DB 89 D8 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule __ieee754_acosh_044260771e35cc05a1f1074776ff90f3 {
	meta:
		aliases = "__ieee754_acosh"
		size = "269"
		objfiles = "e_acosh@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 24 8B 74 24 34 8B 5C 24 30 81 FE FF FF EF 3F 7F 15 89 5C 24 08 89 74 24 0C DD 44 24 08 D8 E0 D8 F0 E9 DD 00 00 00 81 FE FF FF AF 41 7E 32 81 FE FF FF EF 7F 7E 13 89 5C 24 08 89 74 24 0C DD 44 24 08 D8 C0 E9 BA 00 00 00 50 50 56 53 E8 ?? ?? ?? ?? 83 C4 10 DC 05 ?? ?? ?? ?? E9 A3 00 00 00 8D 86 00 00 10 C0 09 D8 75 07 D9 EE E9 92 00 00 00 81 FE 00 00 00 40 D9 E8 7E 4D 83 EC 10 89 5C 24 18 89 74 24 1C DD 44 24 18 D8 C8 DE E1 DD 1C 24 E8 ?? ?? ?? ?? 89 5C 24 18 89 74 24 1C DD 44 24 18 D8 C0 DD 44 24 18 DE C2 D9 C9 DD 54 24 18 D9 05 ?? ?? ?? ?? DE F1 DE C1 DD 5C 24 40 83 C4 34 5B 5E E9 }
	condition:
		$pattern
}

rule _stdio_openlist_dec_use_b7d18b8fa982b242958290a77dc6cab5 {
	meta:
		aliases = "_stdio_openlist_dec_use"
		size = "228"
		objfiles = "fflush_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 28 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 20 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 48 0F 85 91 00 00 00 83 3D ?? ?? ?? ?? 00 0F 8E 84 00 00 00 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 31 F6 8D 44 24 10 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 83 C4 10 EB 37 0F B7 02 25 30 80 00 00 8B 5A 20 83 F8 30 74 04 89 D6 EB 21 85 F6 75 08 89 1D ?? ?? ?? ?? EB 03 89 5E 20 F6 42 01 20 74 0C 83 EC 0C 52 E8 ?? ?? ?? ?? 83 C4 10 89 DA 85 D2 75 C5 52 52 6A 01 8D 44 24 10 50 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 10 A1 ?? ?? }
	condition:
		$pattern
}

rule popen_b2966e09a1e3f0aadbf984219d3cf576 {
	meta:
		aliases = "popen"
		size = "506"
		objfiles = "popen@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 34 8B 5C 24 44 8A 03 3C 77 74 23 C7 44 24 10 01 00 00 00 3C 72 74 1F E8 ?? ?? ?? ?? C7 00 16 00 00 00 C7 04 24 00 00 00 00 E9 BF 01 00 00 C7 44 24 10 00 00 00 00 83 EC 0C 6A 0C E8 ?? ?? ?? ?? 89 44 24 14 83 C4 10 85 C0 C7 04 24 00 00 00 00 0F 84 97 01 00 00 83 EC 0C 8D 44 24 38 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 68 01 00 00 8B 44 24 10 8B 44 84 2C 89 44 24 0C B8 01 00 00 00 2B 44 24 10 8B 44 84 2C 89 44 24 08 51 51 53 50 E8 ?? ?? ?? ?? 89 44 24 10 83 C4 10 85 C0 75 1B 83 EC 0C FF 74 24 14 E8 ?? ?? ?? ?? 5A FF 74 24 18 E8 ?? ?? ?? ?? E9 19 01 00 00 50 68 ?? ?? ?? ?? 68 ?? ?? ?? }
	condition:
		$pattern
}

rule readunix_c78ac1238663fbf2b6361c0bfadd3da6 {
	meta:
		aliases = "readunix"
		size = "268"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 34 8B 74 24 40 8B 1E 89 5C 24 28 66 C7 44 24 2C 01 00 50 68 B8 88 00 00 6A 01 8D 44 24 34 50 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 74 0A 85 C0 0F 84 C2 00 00 00 EB 0A E8 ?? ?? ?? ?? 83 38 04 EB 0F 0F BF 44 24 2E A8 18 0F 85 A9 00 00 00 A8 20 0F 85 A1 00 00 00 F6 44 24 2E 01 74 AB 8B 44 24 44 C7 44 24 10 01 00 00 00 89 44 24 20 8B 44 24 48 89 44 24 24 8D 44 24 20 89 44 24 0C C7 44 24 04 00 00 00 00 C7 44 24 08 00 00 00 00 C7 44 24 14 ?? ?? ?? ?? C7 44 24 18 1C 00 00 00 C7 44 24 1C 00 00 00 00 C7 44 24 30 01 00 00 00 83 EC 0C 6A 04 8D 44 24 40 50 6A 10 6A 01 53 E8 ?? ?? ?? ?? 83 C4 20 85 }
	condition:
		$pattern
}

rule __get_hosts_byaddr_r_3d5338a1e7c565c51c9ac4c35a7dbf29 {
	meta:
		aliases = "__get_hosts_byaddr_r"
		size = "97"
		objfiles = "get_hosts_byaddr_r@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 34 8B 74 24 48 8B 44 24 44 83 FE 02 74 07 83 FE 0A 75 42 EB 05 83 F8 04 EB 03 83 F8 10 75 36 6A 2E 8D 5C 24 0A 53 FF 74 24 48 56 E8 ?? ?? ?? ?? 58 FF 74 24 68 FF 74 24 68 FF 74 24 68 FF 74 24 68 FF 74 24 68 6A 02 56 53 6A 00 E8 ?? ?? ?? ?? 83 C4 30 EB 02 31 C0 83 C4 34 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_pmap_set_c838ef1dd3af10a3c09b96853a96a7d3 {
	meta:
		aliases = "pmap_set, __GI_pmap_set"
		size = "214"
		objfiles = "pmap_clnt@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 34 8D 5C 24 1C 8B 74 24 4C 89 D8 C7 44 24 30 FF FF FF FF E8 ?? ?? ?? ?? 85 C0 0F 84 AA 00 00 00 68 90 01 00 00 68 90 01 00 00 8D 44 24 38 50 FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 6A 02 68 A0 86 01 00 53 E8 ?? ?? ?? ?? 83 C4 20 89 C3 85 C0 74 79 8B 44 24 40 8D 54 24 0C 89 44 24 0C 8B 44 24 44 89 44 24 10 8B 44 24 48 89 44 24 14 0F B7 C6 89 44 24 18 8D 44 24 2C 8B 4B 04 FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? 6A 01 53 FF 11 83 C4 20 85 C0 74 18 56 56 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? C7 44 24 3C 00 00 00 00 83 C4 10 83 EC 0C 8B 43 04 53 FF 50 10 8B 44 24 }
	condition:
		$pattern
}

rule __GI_tcgetattr_167863af6c82e3e55acd9818b001cd7c {
	meta:
		aliases = "tcgetattr, __GI_tcgetattr"
		size = "112"
		objfiles = "tcgetattr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 38 8D 44 24 14 8B 5C 24 48 50 68 01 54 00 00 FF 74 24 4C E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 75 43 8B 44 24 10 89 03 8B 44 24 14 89 43 04 8B 44 24 18 89 43 08 8B 44 24 1C 89 43 0C 8A 44 24 20 88 43 10 50 6A 13 8D 44 24 29 50 8D 43 11 50 E8 ?? ?? ?? ?? 83 C4 0C 6A 0D 6A 00 50 E8 ?? ?? ?? ?? 83 C4 10 89 F0 83 C4 34 5B 5E C3 }
	condition:
		$pattern
}

rule __ieee754_j0_54592c351e67b99111d33aa070fed0f1 {
	meta:
		aliases = "__ieee754_j0"
		size = "537"
		objfiles = "e_j0@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 44 8B 5C 24 54 8B 4C 24 50 89 DE 81 E6 FF FF FF 7F 81 FE FF FF EF 7F 7E 1D 89 4C 24 08 89 5C 24 0C DD 44 24 08 D8 C8 DD 54 24 08 DC 3D ?? ?? ?? ?? E9 D9 01 00 00 50 50 53 51 E8 ?? ?? ?? ?? 83 C4 10 81 FE FF FF FF 3F DD 5C 24 38 0F 8E 04 01 00 00 51 51 FF 74 24 44 FF 74 24 44 E8 ?? ?? ?? ?? DD 5C 24 40 58 5A FF 74 24 44 FF 74 24 44 E8 ?? ?? ?? ?? DD 5C 24 28 DD 44 24 40 DC 64 24 28 DD 5C 24 30 DD 44 24 40 DC 44 24 28 DD 5C 24 38 83 C4 10 81 FE FF FF DF 7F 7F 39 83 EC 10 DD 44 24 48 D8 C0 DD 1C 24 E8 ?? ?? ?? ?? D9 E0 DD 44 24 40 DC 4C 24 28 83 C4 10 D9 EE DA E9 DF E0 9E 76 0A DC 74 }
	condition:
		$pattern
}

rule __md5_Final_9c34de1fcdbb9c5ab6eec4826c0fd189 {
	meta:
		aliases = "__md5_Final"
		size = "132"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 58 89 C6 89 D3 6A 40 6A 00 8D 44 24 18 50 E8 ?? ?? ?? ?? C6 44 24 1C 80 83 C4 0C 8D 43 10 6A 08 50 8D 44 24 58 50 E8 ?? ?? ?? ?? 8B 43 10 83 C4 10 C1 E8 03 B9 38 00 00 00 83 E0 3F 83 F8 37 76 05 B9 78 00 00 00 8D 54 24 0C 29 C1 89 D8 E8 ?? ?? ?? ?? 8D 54 24 4C 89 D8 B9 08 00 00 00 E8 ?? ?? ?? ?? 50 6A 10 53 56 E8 ?? ?? ?? ?? 83 C4 0C 6A 58 6A 00 53 E8 ?? ?? ?? ?? 83 C4 64 5B 5E C3 }
	condition:
		$pattern
}

rule vsscanf_7df30aa4e30371f7c4fdd769842f1d26 {
	meta:
		aliases = "__GI_vsscanf, vsscanf"
		size = "126"
		objfiles = "vsscanf@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 60 8D 44 24 48 8B 5C 24 6C 8D 74 24 10 C7 44 24 14 FE FF FF FF 66 C7 44 24 10 A1 00 C6 44 24 12 00 C7 44 24 3C 00 00 00 00 C7 44 24 44 01 00 00 00 50 E8 ?? ?? ?? ?? 89 5C 24 24 89 5C 24 1C 89 1C 24 C7 44 24 34 00 00 00 00 E8 ?? ?? ?? ?? 83 C4 0C 03 44 24 10 89 5C 24 24 89 44 24 14 89 44 24 1C 89 44 24 20 FF 74 24 6C FF 74 24 6C 56 E8 ?? ?? ?? ?? 83 C4 64 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_rawmemchr_9fa95c4b01108a2e8a0194a0328e6a77 {
	meta:
		aliases = "rawmemchr, __GI_rawmemchr"
		size = "99"
		objfiles = "rawmemchr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8A 5C 24 10 8B 44 24 0C EB 05 38 18 74 50 40 A8 03 75 F7 0F B6 D3 89 C1 89 D0 C1 E0 08 09 D0 89 C6 C1 E6 10 09 C6 89 F2 33 11 83 C1 04 8D 82 FF FE FE 7E F7 D2 31 D0 A9 00 01 01 81 74 E8 8D 41 FC 38 59 FC 74 18 8D 41 FD 38 59 FD 74 10 8D 41 FE 38 59 FE 74 08 8D 41 FF 38 59 FF 75 C8 5B 5E C3 }
	condition:
		$pattern
}

rule a64l_e9e50c6b70ddeb29be8a7902c9acd059 {
	meta:
		aliases = "a64l"
		size = "57"
		objfiles = "a64l@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 44 24 0C 31 DB 89 C2 31 C9 8D 70 06 0F BE 02 83 E8 2E 83 F8 4C 77 1A 0F BE 80 ?? ?? ?? ?? 83 F8 40 74 0E D3 E0 42 09 C3 39 F2 74 05 83 C1 06 EB DB 89 D8 5B 5E C3 }
	condition:
		$pattern
}

rule dirname_cfcca6dc51260af020b3902d5305f20a {
	meta:
		aliases = "dirname"
		size = "94"
		objfiles = "dirname@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 44 24 0C 85 C0 74 4C 89 C3 89 C6 EB 05 8D 53 01 89 D3 8A 13 84 D2 74 05 80 FA 2F 75 F0 89 DA EB 01 42 8A 0A 80 F9 2F 74 F8 84 C9 74 04 89 DE EB DF 39 C6 75 19 80 38 2F 75 19 8D 70 01 80 78 01 2F 75 0B 8D 50 02 80 78 02 00 75 02 89 D6 C6 06 00 EB 05 B8 ?? ?? ?? ?? 5B 5E C3 }
	condition:
		$pattern
}

rule xdrrec_inline_4b77322aa8a75eb15cfbe4afe7265ea7 {
	meta:
		aliases = "xdrrec_inline"
		size = "75"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 44 24 0C 8B 74 24 10 8B 50 0C 8B 00 85 C0 74 05 48 75 30 EB 10 8B 42 10 8D 0C 30 3B 4A 14 77 23 89 4A 10 EB 20 8B 4A 34 39 CE 77 17 8B 5A 2C 8D 04 33 3B 42 30 77 0C 01 72 2C 29 F1 89 D8 89 4A 34 EB 02 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule ldiv_1361f7e9808bef7a7de5280c1d7bbac6 {
	meta:
		aliases = "ldiv"
		size = "45"
		objfiles = "ldiv@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 44 24 10 8B 5C 24 14 99 F7 FB 8B 74 24 0C 89 C1 83 7C 24 10 00 78 07 85 D2 79 03 41 29 DA 89 56 04 89 0E 89 F0 5B 5E C2 04 00 }
	condition:
		$pattern
}

rule __GI_strcasecmp_c0c1060beeadf6184fb7c099398590ff {
	meta:
		aliases = "strcasecmp, __GI_strcasecmp"
		size = "54"
		objfiles = "strcasecmp@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 4C 24 0C 8B 5C 24 10 31 C0 8B 35 ?? ?? ?? ?? 39 D9 74 14 0F B6 01 0F BF 14 46 0F B6 03 0F BF 04 46 29 C2 89 D0 75 09 80 39 00 74 04 43 41 EB DF 5B 5E C3 }
	condition:
		$pattern
}

rule _ppfs_setargs_b3e21d02cc2102481f384f4b1b557660 {
	meta:
		aliases = "_ppfs_setargs"
		size = "271"
		objfiles = "_ppfs_setargs@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 4C 24 0C 8D 59 50 83 79 18 00 0F 85 B0 00 00 00 81 79 08 00 00 00 80 75 11 8B 41 4C 8D 50 04 89 51 4C 8B 00 89 41 50 89 41 08 81 79 04 00 00 00 80 75 11 8B 41 4C 8D 50 04 89 51 4C 8B 00 89 41 50 89 41 04 31 F6 EB 71 8B 44 B1 28 83 F8 08 74 67 8B 51 4C 7F 0E 83 F8 02 74 50 7E 4E 83 F8 07 75 49 EB 29 3D 00 04 00 00 74 40 7E 3E 3D 00 08 00 00 74 09 3D 07 08 00 00 75 30 EB 1F 8D 42 08 89 41 4C 8B 02 8B 52 04 89 53 04 EB 26 8B 51 4C 8D 42 08 89 41 4C DD 02 DD 1B EB 19 8B 51 4C 8D 42 0C 89 41 4C DB 2A DB 3B EB 0A 8D 42 04 89 41 4C 8B 02 89 03 83 C3 0C 46 3B 71 1C 7C 8A EB 2E 81 79 08 00 00 }
	condition:
		$pattern
}

rule re_match_e13552410118e48547e308ba7ec5672c {
	meta:
		aliases = "__re_match, re_match"
		size = "53"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 4C 24 14 8B 54 24 1C 8B 74 24 10 8B 5C 24 18 8B 44 24 0C 89 4C 24 1C 89 54 24 18 89 4C 24 10 31 D2 31 C9 89 74 24 0C 89 5C 24 14 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _dl_do_lazy_reloc_240e4d034368ddd68b5961176d319ff9 {
	meta:
		aliases = "_dl_do_lazy_reloc"
		size = "45"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 54 24 14 8B 44 24 0C 31 C9 8B 72 04 8B 00 81 E6 FF 00 00 00 8B 1A 74 0D 83 C9 FF 83 FE 07 75 05 01 04 18 31 C9 89 C8 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_wcsspn_b20ff0f5e96b0c7707ac8e71ec3aed4e {
	meta:
		aliases = "wcsspn, __GI_wcsspn"
		size = "42"
		objfiles = "wcsspn@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 89 F0 EB 0C 3B 08 74 05 83 C2 04 EB 05 83 C0 04 89 DA 8B 0A 85 C9 75 EC 29 F0 5B C1 F8 02 5E C3 }
	condition:
		$pattern
}

rule sigorset_43f9f578805518e5a047d5c29138bed0 {
	meta:
		aliases = "sigorset"
		size = "38"
		objfiles = "sigorset@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 8B 4C 24 14 BA 20 00 00 00 EB 09 8B 04 91 0B 04 93 89 04 96 4A 79 F4 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule sigandset_df33989e756858d5fc8c388897651f2f {
	meta:
		aliases = "sigandset"
		size = "38"
		objfiles = "sigandset@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 8B 4C 24 14 BA 20 00 00 00 EB 09 8B 04 91 23 04 93 89 04 96 4A 79 F4 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_strpbrk_97328c1efb0b5563725e022ea0866173 {
	meta:
		aliases = "strpbrk, __GI_strpbrk"
		size = "39"
		objfiles = "strpbrk@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 10 8B 44 24 0C EB 0C 38 D9 74 14 42 8A 0A 84 C9 75 F5 40 8A 18 84 DB 74 04 89 F2 EB EF 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule wcspbrk_deb37cdda1bc8ea5a6b62f47af3a6157 {
	meta:
		aliases = "__GI_wcspbrk, wcspbrk"
		size = "43"
		objfiles = "wcspbrk@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 10 8B 44 24 0C EB 10 39 D9 74 18 83 C2 04 8B 0A 85 C9 75 F3 83 C0 04 8B 18 85 DB 74 04 89 F2 EB ED 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule ilogb_49f02f5b6d9a168455fdc5d522981e71 {
	meta:
		aliases = "__GI_ilogb, ilogb"
		size = "107"
		objfiles = "s_ilogb@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 10 8B 5C 24 0C 89 F1 89 D8 81 E1 FF FF FF 7F 81 F9 FF FF 0F 00 7F 34 89 CA BB 01 00 00 80 09 C2 74 3F BB ED FB FF FF 85 C9 74 05 EB 09 4B 01 C0 85 C0 7F F9 EB 2B 89 CA BB 02 FC FF FF C1 E2 0B EB 03 4B 01 D2 85 D2 7F F9 EB 16 BB FF FF FF 7F 81 F9 FF FF EF 7F 7F 09 C1 F9 14 8D 99 01 FC FF FF 89 D8 5B 5E C3 }
	condition:
		$pattern
}

rule pread64_327143c83c685cef96a3d8e6c93b1405 {
	meta:
		aliases = "__libc_pread64, pread64"
		size = "45"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 1C 8B 44 24 0C 8B 54 24 10 8B 4C 24 14 8B 5C 24 18 89 74 24 10 C7 44 24 14 00 00 00 00 89 5C 24 0C 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __libc_pwrite64_575b60da21363f116ccb9b747570b24e {
	meta:
		aliases = "pwrite64, __libc_pwrite64"
		size = "45"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 1C 8B 44 24 0C 8B 54 24 10 8B 4C 24 14 8B 5C 24 18 89 74 24 10 C7 44 24 14 01 00 00 00 89 5C 24 0C 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule skip_9759c23ca510295672c505785254b1c1 {
	meta:
		aliases = "skip"
		size = "131"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 89 C2 53 31 F6 89 C3 EB 67 83 F9 22 75 05 83 F6 01 EB 5C 83 FE 01 75 0F 3C 5C 75 0B 8D 42 01 80 7A 01 22 75 02 89 C2 8A 02 88 03 43 83 FE 01 74 3E 83 F9 23 75 0C C6 05 ?? ?? ?? ?? 23 C6 02 00 EB 37 83 F9 09 74 0A 83 F9 20 74 05 83 F9 0A 75 1E 88 0D ?? ?? ?? ?? C6 02 00 42 0F BE 02 83 F8 09 74 F7 83 F8 20 74 F2 83 F8 0A 75 0C EB EB 42 8A 02 0F BE C8 85 C9 75 90 C6 43 FF 00 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule check_match_da2835dbc7b1837fdc26017f2482730d {
	meta:
		aliases = "check_match"
		size = "91"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 56 ) 89 C6 53 31 C0 66 83 7E 0E 00 0F 94 C0 85 44 24 0C 75 40 83 7E 04 00 74 3A 0F B6 46 0C 83 E0 0F 83 F8 02 7E 05 83 F8 05 75 29 03 16 8D 5A FF 8D 51 FF 43 42 8A 03 8A 0A 84 C0 75 07 0F B6 D1 F7 DA EB 0C 38 C8 74 EB 0F B6 D0 0F B6 C1 29 C2 85 D2 74 02 31 F6 89 F0 5B 5E C3 }
	condition:
		$pattern
}

rule any_f6c89b92e8aa1756e71e0894321dd54a {
	meta:
		aliases = "any"
		size = "37"
		objfiles = "getnetent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 89 D6 53 89 C3 EB 0C 38 D0 74 14 41 8A 01 84 C0 75 F5 43 8A 13 84 D2 74 04 89 F1 EB EF 31 DB 89 D8 5B 5E C3 }
	condition:
		$pattern
}

rule index_8a31351c1888fb1843961e913f53be1b {
	meta:
		aliases = "strchr, __GI_strchr, index"
		size = "30"
		objfiles = "strchr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 74 24 08 8B 44 24 0C 88 C4 AC 38 E0 74 09 84 C0 75 F7 BE 01 00 00 00 89 F0 48 5E C3 }
	condition:
		$pattern
}

rule __GI_svc_getreq_b08daaf283ebbd91f1473ab62f12d59d {
	meta:
		aliases = "svc_getreq, __GI_svc_getreq"
		size = "59"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 31 C0 81 EC 88 00 00 00 B9 20 00 00 00 8D 54 24 08 89 54 24 04 89 D7 FC F3 AB 8B 84 24 90 00 00 00 89 44 24 08 83 EC 0C 8D 44 24 14 50 E8 ?? ?? ?? ?? 81 C4 98 00 00 00 5F C3 }
	condition:
		$pattern
}

rule sysctl_72bce8473b24c1258a94b1063321b024 {
	meta:
		aliases = "sysctl"
		size = "109"
		objfiles = "sysctl@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 31 C0 83 EC 38 B9 0A 00 00 00 FC 8D 7C 24 10 F3 AB 8B 44 24 40 8D 7C 24 10 89 44 24 10 8B 44 24 44 89 44 24 14 8B 44 24 48 89 44 24 18 8B 44 24 4C 89 44 24 1C 8B 44 24 50 89 44 24 20 8B 44 24 54 89 44 24 24 53 89 FB B8 95 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 83 C4 38 5F C3 }
	condition:
		$pattern
}

rule strlen_3983eff887e7a3586eaf7b0b0c3a295b {
	meta:
		aliases = "__GI_strlen, strlen"
		size = "19"
		objfiles = "strlen@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 31 C0 8B 7C 24 08 83 C9 FF F2 AE F7 D1 49 89 C8 5F C3 }
	condition:
		$pattern
}

rule memchr_1c0fb819850398050fc6f9ad07b87ec7 {
	meta:
		aliases = "__GI_memchr, memchr"
		size = "35"
		objfiles = "memchr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 31 D2 8B 4C 24 10 8B 7C 24 08 8B 44 24 0C 85 C9 74 0C F2 AE 74 05 BF 01 00 00 00 4F 89 FA 89 D0 5F C3 }
	condition:
		$pattern
}

rule sigqueue_be650bc337fefe38ec7e41f8e5e782f3 {
	meta:
		aliases = "sigqueue"
		size = "135"
		objfiles = "sigqueue@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 53 81 EC 88 00 00 00 8B BC 24 94 00 00 00 68 80 00 00 00 6A 00 8D 5C 24 10 53 E8 ?? ?? ?? ?? 8B 84 24 A4 00 00 00 C7 44 24 1C FF FF FF FF 89 44 24 14 E8 ?? ?? ?? ?? 89 44 24 20 E8 ?? ?? ?? ?? 89 44 24 24 8B 84 24 A8 00 00 00 89 44 24 28 8B 8C 24 A4 00 00 00 89 DA 53 89 FB B8 B2 00 00 00 CD 80 5B 83 C4 10 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 81 C4 84 00 00 00 5B 5F C3 }
	condition:
		$pattern
}

rule _exit_d824590045fd5175581e5a4e7a65f434 {
	meta:
		aliases = "__GI__exit, _exit"
		size = "40"
		objfiles = "_exit@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 53 83 EC 04 8B 7C 24 10 53 89 FB B8 01 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 EC E8 ?? ?? ?? ?? F7 DB 89 18 EB E1 }
	condition:
		$pattern
}

rule signalfd_a9109198952a1b599161d58e6e507d13 {
	meta:
		aliases = "signalfd"
		size = "79"
		objfiles = "signalfd@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 53 83 EC 04 8B 7C 24 10 8B 4C 24 14 83 7C 24 18 00 74 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 27 BA 08 00 00 00 53 89 FB B8 41 01 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 5B 5F C3 }
	condition:
		$pattern
}

rule __GI_open_2a38df59c17c094e7cfb77be502adffc {
	meta:
		aliases = "__libc_open, __GI___libc_open, open, __GI_open"
		size = "75"
		objfiles = "open@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 53 83 EC 14 31 C0 8B 4C 24 24 8B 7C 24 20 F6 C1 40 74 0C 8D 44 24 2C 89 44 24 10 8B 44 24 28 0F B7 D0 53 89 FB B8 05 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 83 C4 14 5B 5F C3 }
	condition:
		$pattern
}

rule __GI_fcntl_4f8304f8fb43f6ff31436762fc2e60eb {
	meta:
		aliases = "fcntl, __GI___libc_fcntl, __libc_fcntl, __GI_fcntl"
		size = "87"
		objfiles = "__syscall_fcntl@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 53 83 EC 14 8B 4C 24 24 8D 44 24 2C 89 44 24 10 8B 7C 24 20 8D 41 F4 8B 54 24 28 83 F8 02 77 0E 50 52 51 57 E8 ?? ?? ?? ?? 83 C4 10 EB 22 53 89 FB B8 37 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 83 C4 14 5B 5F C3 }
	condition:
		$pattern
}

rule truncate64_2af00164cf24688d8b2bfdd4801030a5 {
	meta:
		aliases = "truncate64"
		size = "80"
		objfiles = "truncate64@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 53 83 EC 14 8B 54 24 28 8B 44 24 24 89 D0 8B 7C 24 20 89 C2 89 44 24 08 C1 FA 1F 8B 4C 24 24 89 54 24 0C 8B 54 24 08 53 89 FB B8 C1 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 83 C4 14 5B 5F C3 }
	condition:
		$pattern
}

rule ftruncate64_7a061a3124c181d59ea2b899504668de {
	meta:
		aliases = "__GI_ftruncate64, ftruncate64"
		size = "80"
		objfiles = "ftruncate64@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 53 83 EC 14 8B 54 24 28 8B 44 24 24 89 D0 8B 7C 24 20 89 C2 89 44 24 08 C1 FA 1F 8B 4C 24 24 89 54 24 0C 8B 54 24 08 53 89 FB B8 C2 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 83 C4 14 5B 5F C3 }
	condition:
		$pattern
}

rule _dl_protect_relro_bf0525679e1b112d7df365463a87a28a {
	meta:
		aliases = "_dl_protect_relro"
		size = "127"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 57 ) 53 8B 5C 24 0C A1 ?? ?? ?? ?? F7 D8 8B 93 D4 00 00 00 03 13 89 D1 89 D7 03 8B D8 00 00 00 21 C7 21 C1 39 CF 74 55 29 F9 BA 01 00 00 00 53 89 FB B8 7D 00 00 00 CD 80 5B 89 C2 3D 00 F0 FF FF 76 09 F7 D8 A3 ?? ?? ?? ?? EB 04 85 D2 79 2D FF 73 04 31 FF 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? 53 89 FB B8 01 00 00 00 CD 80 5B 83 C4 0C 3D 00 F0 FF FF 76 07 F7 D8 A3 ?? ?? ?? ?? 5B 5F C3 }
	condition:
		$pattern
}

rule dl_iterate_phdr_0fc0f88f4c3260f0322ad3d56942bdc3 {
	meta:
		aliases = "__dl_iterate_phdr, dl_iterate_phdr"
		size = "89"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 31 C0 83 EC 10 8B 1D ?? ?? ?? ?? 8B 7C 24 20 8B 74 24 24 EB 36 8B 03 89 04 24 8B 43 04 89 44 24 04 8B 83 D0 00 00 00 89 44 24 08 8B 83 CC 00 00 00 66 89 44 24 0C 50 56 6A 10 8D 44 24 0C 50 FF D7 83 C4 10 85 C0 75 07 8B 5B 0C 85 DB 75 C6 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule strncasecmp_2aa7b8f2fa0063a3de4d712c5deb6a64 {
	meta:
		aliases = "__GI_strncasecmp, strncasecmp"
		size = "65"
		objfiles = "strncasecmp@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 31 C0 8B 4C 24 10 8B 5C 24 14 8B 74 24 18 8B 3D ?? ?? ?? ?? 85 F6 74 22 39 D9 74 14 0F B6 01 0F BF 14 47 0F B6 03 0F BF 04 47 29 C2 89 D0 75 0A 80 39 00 74 05 4E 43 41 EB DA 5B 5E 5F C3 }
	condition:
		$pattern
}

rule tsearch_a59d3b865012d52248e6a43f4a53b398 {
	meta:
		aliases = "__GI_tsearch, tsearch"
		size = "101"
		objfiles = "tsearch@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 31 C0 8B 5C 24 14 8B 74 24 10 8B 7C 24 18 85 DB 74 4C EB 21 8B 03 EB 46 52 52 FF 30 56 FF D7 83 C4 10 83 F8 00 74 ED 7D 07 8B 1B 83 C3 04 EB 05 8B 1B 83 C3 08 8B 03 85 C0 75 DD 83 EC 0C 6A 0C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 12 89 03 89 30 C7 40 08 00 00 00 00 C7 40 04 00 00 00 00 5B 5E 5F C3 }
	condition:
		$pattern
}

rule cfsetspeed_362e43168579cb3848d6ad3215872358 {
	meta:
		aliases = "cfsetspeed"
		size = "98"
		objfiles = "cfsetspeed@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 31 C0 8B 7C 24 10 8B 74 24 14 EB 3C 8B 1C C5 ?? ?? ?? ?? 39 DE 75 0E 50 50 56 57 E8 ?? ?? ?? ?? 5B 58 56 EB 15 3B 34 C5 ?? ?? ?? ?? 75 19 51 51 53 57 E8 ?? ?? ?? ?? 58 5A 53 57 E8 ?? ?? ?? ?? 31 C0 83 C4 10 EB 14 40 83 F8 1F 76 BF E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_detach_cd84016c529d336b5b66347c8a461bbe {
	meta:
		aliases = "pthread_detach"
		size = "217"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 31 D2 81 EC A0 00 00 00 8B BC 24 B0 00 00 00 89 F8 25 FF 03 00 00 C1 E0 04 8D B0 ?? ?? ?? ?? 89 F0 E8 ?? ?? ?? ?? 8B 46 08 85 C0 74 05 39 78 10 74 10 83 EC 0C 56 E8 ?? ?? ?? ?? B8 03 00 00 00 EB 14 80 78 2D 00 74 13 83 EC 0C 56 E8 ?? ?? ?? ?? B8 16 00 00 00 83 C4 10 EB 71 83 78 38 00 74 0D 83 EC 0C 56 E8 ?? ?? ?? ?? 31 C0 EB E8 83 EC 0C C6 40 2D 01 0F BE 58 2C 56 E8 ?? ?? ?? ?? 83 C4 10 85 DB 74 44 83 3D ?? ?? ?? ?? 00 78 3B E8 ?? ?? ?? ?? C7 44 24 10 01 00 00 00 89 44 24 0C 89 7C 24 14 8D 44 24 0C 56 68 94 00 00 00 50 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 40 75 0A E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __stdio_adjust_position_80ebe6485abb7015916ff97b8d16b5df {
	meta:
		aliases = "__stdio_adjust_position"
		size = "168"
		objfiles = "_adjust_pos@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 31 D2 83 EC 10 8B 5C 24 20 8B 7C 24 24 8B 33 0F B7 C6 89 C1 83 E1 03 74 2A 89 CA 4A 74 25 F6 C4 08 74 20 83 FA 01 7F 71 83 7B 28 00 75 6B 0F B6 43 03 29 C2 83 7B 2C 00 8D 52 FF 7E 06 0F B6 43 02 29 C2 66 F7 C6 40 00 74 05 8B 43 08 EB 03 8B 43 14 2B 43 10 8B 0F 8B 5F 04 8D 34 02 89 DA 89 F0 89 74 24 08 C1 F8 1F 89 44 24 0C 89 C8 2B 44 24 08 1B 54 24 0C 89 07 89 57 04 39 5F 04 7C 08 7F 04 39 0F 76 02 F7 DE 85 F6 79 10 E8 ?? ?? ?? ?? C7 00 4B 00 00 00 EB 03 83 CE FF 83 C4 10 89 F0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_rwlock_destroy_1144e10ea8e869f8e049be5298753f9c {
	meta:
		aliases = "pthread_rwlock_destroy"
		size = "53"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 31 D2 8B 5C 24 10 89 D8 E8 ?? ?? ?? ?? 83 EC 0C 8B 73 08 8B 7B 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 F6 7F 06 31 C0 85 FF 74 05 B8 10 00 00 00 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_rwlock_unlock_782a732dd9f4066bd045988fbbd7e01e {
	meta:
		aliases = "pthread_rwlock_unlock"
		size = "319"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 31 D2 8B 7C 24 10 89 F8 E8 ?? ?? ?? ?? 8B 5F 0C 85 DB 74 78 E8 ?? ?? ?? ?? 39 C3 75 76 C7 47 0C 00 00 00 00 83 7F 18 00 74 2E 8B 5F 14 85 DB 74 27 8B 43 08 83 EC 0C 89 47 14 C7 43 08 00 00 00 00 57 E8 ?? ?? ?? ?? 89 D8 E8 ?? ?? ?? ?? 31 C0 83 C4 10 E9 E0 00 00 00 83 EC 0C 8B 77 10 C7 47 10 00 00 00 00 57 E8 ?? ?? ?? ?? 83 C4 10 EB 13 8B 5E 08 89 F0 C7 46 08 00 00 00 00 89 DE E8 ?? ?? ?? ?? 85 F6 75 E9 E9 AA 00 00 00 8B 47 08 85 C0 75 10 83 EC 0C 57 E8 ?? ?? ?? ?? B8 01 00 00 00 EB AD 48 31 DB 89 47 08 85 C0 75 14 8B 5F 14 85 DB 74 0D 8B 43 08 89 47 14 C7 43 08 00 00 00 00 83 EC 0C 57 }
	condition:
		$pattern
}

rule opendir_5dff6b7bc593ef49dcca1035e0e8af22 {
	meta:
		aliases = "__GI_opendir, opendir"
		size = "241"
		objfiles = "opendir@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 31 DB 83 EC 68 68 00 08 01 00 FF 74 24 7C E8 ?? ?? ?? ?? 83 C4 10 89 C7 85 C0 0F 88 C5 00 00 00 53 53 8D 44 24 10 50 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 12 51 6A 01 6A 02 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 16 E8 ?? ?? ?? ?? 83 EC 0C 89 C3 8B 30 57 E8 ?? ?? ?? ?? 89 33 EB 75 83 EC 0C 6A 30 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 74 4E 89 38 C7 40 10 00 00 00 00 C7 40 08 00 00 00 00 C7 40 04 00 00 00 00 8B 44 24 38 89 43 14 3D FF 01 00 00 77 07 C7 43 14 00 02 00 00 52 52 FF 73 14 6A 01 E8 ?? ?? ?? ?? 83 C4 10 89 43 0C 85 C0 75 24 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C 57 E8 ?? ?? ?? }
	condition:
		$pattern
}

rule setkey_749e8015ce452b67866add0af08f1147 {
	meta:
		aliases = "setkey"
		size = "68"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 31 F6 83 EC 10 8B 5C 24 20 8D 7C 24 08 EB 1F 8D 14 37 31 C9 C6 02 00 EB 0F F6 03 01 74 08 8A 81 ?? ?? ?? ?? 08 02 43 41 83 F9 07 7E EC 46 83 FE 07 7E DC 89 F8 E8 ?? ?? ?? ?? 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_strcspn_11bb43e56c6a9fa65487dbb0121de1de {
	meta:
		aliases = "strcspn, __GI_strcspn"
		size = "48"
		objfiles = "strcspn@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 31 F6 8B 5C 24 10 8B 7C 24 14 EB 15 0F BE C0 52 52 50 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 08 43 46 8A 03 84 C0 75 E5 89 F0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule strspn_894a506e982133e84cfe65d830490adb {
	meta:
		aliases = "__GI_strspn, strspn"
		size = "50"
		objfiles = "strspn@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 31 F6 8B 7C 24 14 8B 5C 24 10 EB 13 38 C8 74 09 42 8A 0A 84 C9 75 F5 EB 10 84 C0 74 0C 46 43 8A 03 84 C0 74 04 89 FA EB E8 89 F0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_inet_ntoa_r_01a30dde8b3a96e976810ca26da3d22b {
	meta:
		aliases = "inet_ntoa_r, __GI_inet_ntoa_r"
		size = "79"
		objfiles = "inet_ntoa@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 31 FF 8B 4C 24 14 8B 44 24 10 83 C1 0F 31 F6 0F C8 89 C3 EB 2B 83 EC 0C 89 D8 25 FF 00 00 00 31 D2 6A 00 6A F6 52 50 51 E8 ?? ?? ?? ?? 83 C4 20 85 F6 8D 48 FF 74 03 C6 06 2E C1 EB 08 47 89 CE 83 FF 03 7E D0 8D 41 01 5B 5E 5F C3 }
	condition:
		$pattern
}

rule rendezvous_request_b6fd55f8d2f2d28738f9d678276b8fb2 {
	meta:
		aliases = "rendezvous_request"
		size = "154"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 81 EC 90 00 00 00 8B B4 24 A0 00 00 00 8B 7E 2C C7 84 24 8C 00 00 00 6E 00 00 00 8D 54 24 0E 50 8D 84 24 90 00 00 00 50 52 FF 36 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 79 0C E8 ?? ?? ?? ?? 83 38 04 75 48 EB CB 50 6A 10 6A 00 8D B4 24 88 00 00 00 56 E8 ?? ?? ?? ?? 66 C7 84 24 8C 00 00 00 01 00 89 D8 8B 4F 04 8B 17 E8 ?? ?? ?? ?? 83 C4 0C 89 C3 6A 10 8D 40 10 56 50 E8 ?? ?? ?? ?? 8B 84 24 9C 00 00 00 83 C4 10 89 43 0C 81 C4 90 00 00 00 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule lckpwdf_1e092417e2018086b2e2434bf7e3d295 {
	meta:
		aliases = "lckpwdf"
		size = "461"
		objfiles = "lckpwdf@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 C8 FF 81 EC 40 02 00 00 83 3D ?? ?? ?? ?? FF 0F 85 AA 01 00 00 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 84 24 2C 02 00 00 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 5A 6A 01 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 A3 ?? ?? ?? ?? 83 F8 FF 0F 84 51 01 00 00 57 6A 00 6A 01 50 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 0F 84 1F 01 00 00 83 C8 01 56 50 6A 02 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 88 02 01 00 00 53 68 8C 00 00 00 6A 00 8D 5C 24 14 53 E8 ?? ?? ?? ?? C7 44 24 18 ?? ?? ?? ?? 59 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 84 24 9C 00 00 00 00 00 00 00 83 C4 0C 8D B4 24 98 00 }
	condition:
		$pattern
}

rule __length_dotted_d499c644bc96708f8303fc627b2a8f63 {
	meta:
		aliases = "__length_dotted"
		size = "65"
		objfiles = "lengthd@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 C8 FF 8B 74 24 10 8B 7C 24 14 85 F6 74 2B EB 05 8D 59 02 EB 20 89 F9 EB 11 89 D0 25 C0 00 00 00 3D C0 00 00 00 74 E9 8D 0C 13 0F B6 14 0E 8D 59 01 85 D2 75 E4 89 D8 29 F8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule frexp_a1dc49af7a1d72bfbdb8f40d0419cd8b {
	meta:
		aliases = "__GI_frexp, frexp"
		size = "138"
		objfiles = "s_frexp@libm.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 08 8B 5C 24 1C 8B 7C 24 20 89 D8 8B 4C 24 18 25 FF FF FF 7F 89 DE 89 CA C7 07 00 00 00 00 3D FF FF EF 7F 7F 50 09 C2 74 4C 3D FF FF 0F 00 7F 29 89 0C 24 89 5C 24 04 DD 04 24 D8 0D ?? ?? ?? ?? DD 1C 24 8B 5C 24 04 8B 0C 24 89 D8 89 DE 25 FF FF FF 7F C7 07 CA FF FF FF C1 F8 14 81 E6 FF FF 0F 80 03 07 89 F2 2D FE 03 00 00 81 CA 00 00 E0 3F 89 07 89 D3 89 0C 24 89 5C 24 04 DD 04 24 58 5A 5B 5E 5F C3 }
	condition:
		$pattern
}

rule tcgetsid_536e7620951cf78b93a350254241306d {
	meta:
		aliases = "tcgetsid"
		size = "134"
		objfiles = "tcgetsid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 80 3D ?? ?? ?? ?? 00 8B 7C 24 20 75 2F E8 ?? ?? ?? ?? 89 C3 8B 30 50 8D 44 24 10 50 68 29 54 00 00 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 42 83 3B 16 75 43 C6 05 ?? ?? ?? ?? 01 89 33 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 74 29 83 EC 0C 50 E8 ?? ?? ?? ?? 89 44 24 1C 83 C4 10 40 75 10 E8 ?? ?? ?? ?? 83 38 03 75 06 C7 00 19 00 00 00 8B 44 24 0C EB 03 83 C8 FF 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule lockf_5bb40d4c0a682ff07327a62c14cec1ae {
	meta:
		aliases = "__GI_lockf, lockf"
		size = "216"
		objfiles = "lockf@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 89 E6 8B 5C 24 24 8B 7C 24 20 51 6A 10 6A 00 56 E8 ?? ?? ?? ?? 8B 44 24 38 66 C7 44 24 12 01 00 C7 44 24 14 00 00 00 00 89 44 24 18 83 C4 10 83 FB 01 74 55 7F 06 85 DB 74 47 EB 67 83 FB 02 74 55 83 FB 03 75 5D 66 C7 04 24 00 00 52 56 6A 05 57 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 69 66 83 3C 24 02 74 60 8B 5C 24 0C E8 ?? ?? ?? ?? 39 C3 74 53 E8 ?? ?? ?? ?? C7 00 0D 00 00 00 EB 2D 66 C7 04 24 02 00 EB 13 BA 07 00 00 00 66 C7 04 24 01 00 EB 1D 66 C7 04 24 01 00 BA 06 00 00 00 EB 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CA FF EB 16 50 8D 44 24 04 50 52 57 E8 ?? ?? ?? ?? 83 C4 }
	condition:
		$pattern
}

rule putchar_91d742f473a5ccd9a53386363751d0e3 {
	meta:
		aliases = "putchar"
		size = "148"
		objfiles = "putchar@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 35 ?? ?? ?? ?? 8B 7C 24 20 83 7E 34 00 74 22 8B 46 10 3B 46 1C 73 0D 89 FA 88 10 40 0F B6 DA 89 46 10 EB 60 53 53 56 57 E8 ?? ?? ?? ?? 89 C3 EB 50 8D 5E 38 51 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 46 10 83 C4 10 3B 46 1C 73 0D 89 FA 88 10 40 0F B6 DA 89 46 10 EB 0E 52 52 56 57 E8 ?? ?? ?? ?? 83 C4 10 89 C3 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 10 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule puts_bf457e57ef70761855bbf312598d66f4 {
	meta:
		aliases = "puts"
		size = "124"
		objfiles = "puts@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 35 ?? ?? ?? ?? 8B 7E 34 85 FF 75 1F 8D 5E 38 50 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 51 51 56 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 89 C3 83 F8 FF 74 16 52 52 56 6A 0A E8 ?? ?? ?? ?? 83 C4 10 40 75 05 83 CB FF EB 01 43 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 10 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule calloc_fcff0f411a3e9234687252fc13cd56be {
	meta:
		aliases = "calloc"
		size = "244"
		objfiles = "calloc@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 54 24 20 8B 4C 24 24 89 D3 0F AF D9 85 D2 74 1E 89 D7 89 D8 31 D2 F7 F7 39 C1 74 12 E8 ?? ?? ?? ?? 31 DB C7 00 0C 00 00 00 E9 B6 00 00 00 56 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 74 73 8B 40 FC A8 02 75 6C 83 E0 FC 8D 50 FC 89 D0 C1 E8 02 83 F8 09 76 0F 51 52 6A 00 53 E8 ?? ?? ?? ?? 83 C4 10 EB 4D C7 03 00 00 00 00 C7 43 04 00 00 00 00 C7 43 08 00 00 00 00 83 F8 04 76 34 C7 43 0C 00 00 00 00 C7 43 10 00 00 00 00 83 F8 06 76 21 C7 43 14 00 00 00 00 C7 43 18 00 00 00 00 83 }
	condition:
		$pattern
}

rule readahead_528b3f7db2edbd4ca3a2b5936ae8b54e {
	meta:
		aliases = "readahead"
		size = "86"
		objfiles = "readahead@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 54 24 28 8B 44 24 24 89 D0 8B 7C 24 20 89 C2 89 44 24 08 C1 FA 1F 8B 74 24 2C 89 54 24 0C 8B 4C 24 08 8B 54 24 24 53 89 FB B8 E1 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 83 C4 10 89 F0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule ppoll_defccf856d7006fc38a3d2eb7c424a74 {
	meta:
		aliases = "__GI_ppoll, ppoll"
		size = "84"
		objfiles = "ppoll@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 54 24 28 8B 7C 24 20 8B 74 24 2C 85 D2 74 11 8B 0A 8B 42 04 89 44 24 0C 89 4C 24 08 8D 54 24 08 8B 4C 24 24 53 89 FB B8 35 01 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 83 C4 10 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __kernel_cos_95191bbc7da880ddb9e89e29e216a170 {
	meta:
		aliases = "__kernel_cos"
		size = "273"
		objfiles = "k_cos@libm.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 5C 24 24 8B 4C 24 20 89 DA 81 E2 FF FF FF 7F DD 44 24 28 81 FA FF FF 3F 3E 7F 37 D9 7C 24 0E 66 8B 44 24 0E 80 CC 0C 89 0C 24 89 5C 24 04 66 89 44 24 0C DD 04 24 D9 6C 24 0C DB 5C 24 08 D9 6C 24 0E 8B 44 24 08 D9 E8 85 C0 0F 84 B1 00 00 00 DD D8 89 0C 24 89 5C 24 04 DD 04 24 D8 C8 81 FA 32 33 D3 3F DD 05 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 7F 1E D9 05 ?? ?? ?? ?? D8 CA D9 CA DE C9 DD 04 24 DE CB D9 CA DD 14 24 DE EA DE E1 D9 E8 EB 49 81 FA 00 00 E9 3F 7E 08 D9 05 ?? ?? ?? }
	condition:
		$pattern
}

rule logb_1da00c6b1d6db05f2ae2f81d36e44a20 {
	meta:
		aliases = "__GI_logb, logb"
		size = "110"
		objfiles = "s_logb@libm.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 5C 24 24 8B 4C 24 20 89 DE 81 E6 FF FF FF 7F 89 F7 09 CF 75 16 50 50 53 51 E8 ?? ?? ?? ?? 83 C4 10 D9 05 ?? ?? ?? ?? DE F1 EB 35 81 FE FF FF EF 7F 7E 10 89 4C 24 08 89 5C 24 0C DD 44 24 08 D8 C8 EB 1D 89 F0 C1 F8 14 85 C0 75 08 D9 05 ?? ?? ?? ?? EB 0C 2D FF 03 00 00 50 DB 04 24 83 C4 04 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_atan_74859b0bcd4b7b3678d24ef3ffd6c9f7 {
	meta:
		aliases = "atan, __GI_atan"
		size = "498"
		objfiles = "s_atan@libm.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 5C 24 24 8B 4C 24 20 89 DE 89 DF 81 E6 FF FF FF 7F 81 FE FF FF 0F 44 7E 43 81 FE 00 00 F0 7F 7F 06 75 17 85 C9 74 13 89 4C 24 08 89 5C 24 0C DD 44 24 08 D8 C0 E9 58 01 00 00 85 FF 7F 0F B9 18 2D 44 54 BB FB 21 F9 BF E9 8B 01 00 00 B9 18 2D 44 54 BB FB 21 F9 3F E9 7C 01 00 00 81 FE FF FF DB 3F 7F 32 81 FE FF FF 1F 3E 0F 8F A7 00 00 00 89 4C 24 08 89 5C 24 0C DD 44 24 08 DC 05 ?? ?? ?? ?? D9 E8 D9 C9 DA E9 DF E0 9E 0F 87 47 01 00 00 E9 81 00 00 00 50 50 53 51 E8 ?? ?? ?? ?? 83 C4 10 81 FE FF FF F2 3F 7F 3B 81 FE FF FF E5 3F D9 E8 7F 14 D9 C1 D8 C2 31 C0 DE E1 D9 05 ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_lseek64_c24d4957c9e752b98f7c154855d0c571 {
	meta:
		aliases = "__libc_lseek64, lseek64, __GI_lseek64"
		size = "95"
		objfiles = "llseek@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 5C 24 28 8B 4C 24 24 89 D9 8B 7C 24 2C 89 CB 8D 74 24 08 C1 FB 1F 8B 44 24 20 8B 54 24 24 53 89 C3 B8 8C 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF EB 04 85 C0 74 05 89 F0 99 EB 08 8B 44 24 08 8B 54 24 0C 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule fflush_93a22b501911da46837877b2ae54b32f {
	meta:
		aliases = "__GI_fflush, fflush"
		size = "117"
		objfiles = "fflush@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 85 F6 74 50 81 FE ?? ?? ?? ?? 74 48 8B 7E 34 85 FF 75 1F 8D 5E 38 52 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 FF 75 1E 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? EB 0B 83 EC 0C 56 E8 ?? ?? ?? ?? 89 C3 83 C4 10 83 C4 10 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_xdr_string_80b08e3b1f3f45275c572c69ba7cea8d {
	meta:
		aliases = "xdr_string, __GI_xdr_string"
		size = "222"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 8B 7C 24 24 8B 06 8B 1F 85 C0 74 0E 83 F8 02 75 21 85 DB 75 0D E9 AA 00 00 00 85 DB 0F 84 A9 00 00 00 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 89 44 24 0C 50 50 8D 44 24 14 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 81 00 00 00 8B 44 24 0C 3B 44 24 28 77 77 8B 16 83 FA 01 74 09 72 40 83 FA 02 75 69 EB 4A 40 74 5D 85 DB 75 2A 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 89 C3 89 07 85 C0 75 16 50 50 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 EB 14 8B 44 24 0C C6 04 03 00 50 FF 74 24 10 53 56 E8 ?? ?? ?? ?? 83 C4 10 EB 1F 83 EC 0C 53 E8 ?? ?? ?? ?? B8 01 00 00 00 C7 07 }
	condition:
		$pattern
}

rule vfwprintf_52cd976a09c64264dbfc92200937a617 {
	meta:
		aliases = "__GI_vfwprintf, vfwprintf"
		size = "136"
		objfiles = "vfwprintf@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 8B 7E 34 85 FF 75 1F 8D 5E 38 50 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 0F B7 06 25 40 08 00 00 3D 40 08 00 00 74 17 51 51 68 00 08 00 00 56 E8 ?? ?? ?? ?? 83 CB FF 83 C4 10 85 C0 75 14 52 FF 74 24 2C FF 74 24 2C 56 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 10 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_vfprintf_5c689d4fef8ceedc4ec1dc187d328e82 {
	meta:
		aliases = "vfprintf, __GI_vfprintf"
		size = "136"
		objfiles = "vfprintf@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 8B 7E 34 85 FF 75 1F 8D 5E 38 50 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 0F B7 06 25 C0 00 00 00 3D C0 00 00 00 74 17 51 51 68 80 00 00 00 56 E8 ?? ?? ?? ?? 83 CB FF 83 C4 10 85 C0 75 14 52 FF 74 24 2C FF 74 24 2C 56 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 10 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule rewind_06111fa498725561c514ccc538b6458b {
	meta:
		aliases = "__GI_rewind, rewind"
		size = "94"
		objfiles = "rewind@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 8B 7E 34 85 FF 75 1F 8D 5E 38 51 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 66 83 26 F7 52 6A 00 6A 00 56 E8 ?? ?? ?? ?? 83 C4 10 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule clearerr_cf262ba79360967cd13bdbf8ef8cf94a {
	meta:
		aliases = "clearerr"
		size = "80"
		objfiles = "clearerr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 8B 7E 34 85 FF 75 1F 8D 5E 38 52 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 66 83 26 F3 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_fgetwc_47b2021f9ad3c9dae34d9b79ccbd71b9 {
	meta:
		aliases = "__GI_fileno, getwc, fgetwc, fileno, __GI_fgetwc"
		size = "92"
		objfiles = "fgetwc@libc.a, fileno@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 8B 7E 34 85 FF 75 1F 8D 5E 38 52 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 10 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule feof_b526fee2c1b92d4e105059e36f26512e {
	meta:
		aliases = "feof"
		size = "83"
		objfiles = "feof@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 8B 7E 34 85 FF 75 1F 8D 5E 38 52 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 1E 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 10 83 E0 04 5B 5E 5F C3 }
	condition:
		$pattern
}

rule ferror_1a759d3f9423393938fe93fd33c83bd3 {
	meta:
		aliases = "ferror"
		size = "83"
		objfiles = "ferror@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 8B 7E 34 85 FF 75 1F 8D 5E 38 52 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 1E 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 10 83 E0 08 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_putc_86c5438cba725a7dd860bf3f983c677e {
	meta:
		aliases = "putc, __GI_fputc, fputc, __GI_putc"
		size = "146"
		objfiles = "fputc@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 24 8B 7C 24 20 83 7E 34 00 74 22 8B 46 10 3B 46 1C 73 0D 89 FA 88 10 40 0F B6 DA 89 46 10 EB 60 53 53 56 57 E8 ?? ?? ?? ?? 89 C3 EB 50 8D 5E 38 51 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 46 10 83 C4 10 3B 46 1C 73 0D 89 FA 88 10 40 0F B6 DA 89 46 10 EB 0E 52 52 56 57 E8 ?? ?? ?? ?? 83 C4 10 89 C3 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 10 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule putwc_27a00bae78ad279095482cf1967e990f {
	meta:
		aliases = "__GI_fputws, fputs, __GI_fputs, fputws, fputwc, putwc"
		size = "95"
		objfiles = "fputws@libc.a, fputwc@libc.a, fputs@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 24 8B 7E 34 85 FF 75 1F 8D 5E 38 51 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 52 52 56 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 10 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule fgets_1c2fc372b815e752ffcd0a80282d91cc {
	meta:
		aliases = "__GI_fgets, fgetws, fgets"
		size = "98"
		objfiles = "fgetws@libc.a, fgets@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 28 8B 7E 34 85 FF 75 1F 8D 5E 38 51 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 52 56 FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 10 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule fread_6bf25374bc468acb0c81effce8a40356 {
	meta:
		aliases = "__GI_fwrite, fwrite, __GI_fread, fread"
		size = "101"
		objfiles = "fread@libc.a, fwrite@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 2C 8B 7E 34 85 FF 75 1F 8D 5E 38 52 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 56 FF 74 24 2C FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 10 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule closedir_2edda8802461191b57151e97958a67d3 {
	meta:
		aliases = "__GI_closedir, closedir"
		size = "112"
		objfiles = "closedir@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 7C 24 20 83 3F FF 75 10 E8 ?? ?? ?? ?? C7 00 09 00 00 00 83 C8 FF EB 4A 8D 5F 18 56 53 68 ?? ?? ?? ?? 8D 74 24 0C 56 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 1F C7 07 FF FF FF FF 5A 59 6A 01 56 E8 ?? ?? ?? ?? 58 FF 77 0C E8 ?? ?? ?? ?? 89 3C 24 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule ptrace_c6915996b8a67b47530e96fdfa629191 {
	meta:
		aliases = "ptrace"
		size = "115"
		objfiles = "ptrace@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 7C 24 20 8D 44 24 30 89 44 24 08 8B 4C 24 24 8D 47 FF 8B 54 24 28 8B 74 24 2C 83 F8 02 77 04 8D 74 24 0C 53 89 FB B8 1A 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF EB 1E 85 C0 78 1A 85 FF 74 16 83 FF 03 77 11 E8 ?? ?? ?? ?? C7 00 00 00 00 00 8B 44 24 0C EB 02 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule gets_e89af77a809ea88fbbe47b296b39a3a5 {
	meta:
		aliases = "gets"
		size = "125"
		objfiles = "gets@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 A1 ?? ?? ?? ?? 8B 74 24 20 8B 78 34 85 FF 74 04 89 F3 EB 2A 83 C0 38 52 50 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C0 38 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 EB D3 43 E8 ?? ?? ?? ?? 83 F8 FF 74 0A 88 03 3C 0A 75 EF 39 DE 75 04 31 F6 EB 03 C6 03 00 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 10 89 F0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule rewinddir_4c64d31a6a55013ed88af25e22b56060 {
	meta:
		aliases = "rewinddir"
		size = "89"
		objfiles = "rewinddir@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 14 8B 5C 24 24 8D 73 18 56 68 ?? ?? ?? ?? 8D 7C 24 0C 57 E8 ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 83 C4 0C 6A 00 6A 00 FF 33 E8 ?? ?? ?? ?? C7 43 08 00 00 00 00 C7 43 04 00 00 00 00 C7 43 10 00 00 00 00 58 5A 6A 01 57 E8 ?? ?? ?? ?? 83 C4 20 5B 5E 5F C3 }
	condition:
		$pattern
}

rule seekdir_b6d2caa835cdc7e3e3a9875606105224 {
	meta:
		aliases = "seekdir"
		size = "87"
		objfiles = "seekdir@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 14 8B 5C 24 24 8D 73 18 56 68 ?? ?? ?? ?? 8D 7C 24 0C 57 E8 ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 83 C4 0C 6A 00 FF 74 24 2C FF 33 E8 ?? ?? ?? ?? C7 43 04 00 00 00 00 89 43 10 C7 43 08 00 00 00 00 58 5A 6A 01 57 E8 ?? ?? ?? ?? 83 C4 20 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_asctime_r_9547919b9324769df681c6d9ceef31b0 {
	meta:
		aliases = "asctime_r, __GI_asctime_r"
		size = "214"
		objfiles = "asctime_r@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 14 8B 74 24 24 8B 5C 24 28 6A 1A 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8B 46 18 83 C4 10 83 F8 06 77 15 8D 04 40 51 05 ?? ?? ?? ?? 6A 03 50 53 E8 ?? ?? ?? ?? 83 C4 10 8B 46 10 83 F8 0B 77 18 8D 04 40 52 05 ?? ?? ?? ?? 6A 03 50 8D 43 04 50 E8 ?? ?? ?? ?? 83 C4 10 8B 56 14 8D 4B 13 81 C2 6C 07 00 00 81 FA 0F 27 00 00 77 1A 8D 4B 17 89 D0 BB 0A 00 00 00 99 F7 FB 83 C2 30 88 11 49 89 C2 80 39 3F 74 E9 0F BE 41 FF 8D 59 FF 8B 14 06 83 FA 63 76 0A C6 41 FF 3F C6 43 FF 3F EB 17 89 D0 BF 0A 00 00 00 99 F7 FF 89 44 24 0C 83 C2 30 00 41 FE 88 51 FF 8D 4B FE 80 79 FE 30 74 C7 80 7B FF 30 75 04 }
	condition:
		$pattern
}

rule localtime_r_f56340bc2564f7179fc50835e01ab1f5 {
	meta:
		aliases = "__GI_localtime_r, localtime_r"
		size = "99"
		objfiles = "localtime_r@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 14 8B 74 24 24 8B 7C 24 28 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 0C 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 81 3E FF 4E 98 45 0F 9E C0 89 04 24 E8 ?? ?? ?? ?? 83 C4 0C 68 ?? ?? ?? ?? 57 56 E8 ?? ?? ?? ?? 58 5A 6A 01 53 E8 ?? ?? ?? ?? 83 C4 20 89 F8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule getpwent_r_1db372f6fd22c31d31dc4c3efa2abb1d {
	meta:
		aliases = "__GI_getspent_r, __GI_getgrent_r, __GI_getpwent_r, getgrent_r, getspent_r, getpwent_r"
		size = "171"
		objfiles = "getgrent_r@libc.a, getpwent_r@libc.a, getspent_r@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 14 8B 74 24 30 8B 7C 24 24 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 06 00 00 00 00 83 C4 10 83 3D ?? ?? ?? ?? 00 75 2D 52 52 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 A3 ?? ?? ?? ?? 85 C0 75 09 E8 ?? ?? ?? ?? 8B 18 EB 2E C7 40 34 01 00 00 00 83 EC 0C FF 35 ?? ?? ?? ?? FF 74 24 38 FF 74 24 38 57 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 20 89 C3 85 C0 75 02 89 3E 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 20 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_rresvport_9af63d0e454683725751c455ed5b96b1 {
	meta:
		aliases = "rresvport, __GI_rresvport"
		size = "143"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 14 8B 7C 24 24 66 C7 44 24 04 02 00 C7 44 24 08 00 00 00 00 6A 00 6A 01 6A 02 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 79 10 83 CB FF EB 54 83 EC 0C 53 E8 ?? ?? ?? ?? EB 43 8B 07 66 C1 C8 08 66 89 44 24 02 89 E0 52 6A 10 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 2B E8 ?? ?? ?? ?? 89 C6 83 38 62 75 CB FF 0F 81 3F 00 02 00 00 75 CC 83 EC 0C 53 E8 ?? ?? ?? ?? C7 06 0B 00 00 00 83 CB FF 83 C4 10 83 C4 10 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __old_sem_post_7b225da5dc92760074f0f6e2b7680b75 {
	meta:
		aliases = "__old_sem_post"
		size = "165"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 20 8B 4C 24 30 8B 11 89 D7 83 E7 01 75 07 BE 03 00 00 00 EB 1B 81 FA FF FF FF 7F 75 10 E8 ?? ?? ?? ?? C7 00 22 00 00 00 83 C8 FF EB 6C 8D 72 02 89 D0 F0 0F B1 31 0F 94 C3 84 DB 74 C8 85 FF 75 56 89 D1 C7 44 24 1C 00 00 00 00 EB 21 8B 71 08 8D 5C 24 1C EB 03 8D 5A 08 8B 13 85 D2 74 08 8B 41 18 3B 42 18 7C EF 89 51 08 89 0B 89 F1 83 F9 01 75 DA EB 1A 8B 42 08 89 44 24 1C 83 EC 0C C7 42 08 00 00 00 00 52 E8 ?? ?? ?? ?? 83 C4 10 8B 54 24 1C 85 D2 75 DE 31 C0 83 C4 20 5B 5E 5F C3 }
	condition:
		$pattern
}

rule rendezvous_request_5d6517fda809d8cd01e6c536eae37e92 {
	meta:
		aliases = "rendezvous_request"
		size = "102"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 20 8B 74 24 30 8B 5E 2C C7 44 24 1C 10 00 00 00 8D 7C 24 0C 50 8D 44 24 20 50 57 FF 36 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 0C E8 ?? ?? ?? ?? 83 38 04 75 25 EB D3 8B 4B 04 8B 13 E8 ?? ?? ?? ?? 56 89 C3 6A 10 8D 40 10 57 50 E8 ?? ?? ?? ?? 8B 44 24 2C 83 C4 10 89 43 0C 83 C4 20 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule ftello64_7e3f253ca8b88b0f14fbec32f85c1331 {
	meta:
		aliases = "__GI_ftello64, ftello64"
		size = "172"
		objfiles = "ftello64@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 20 8B 74 24 30 C7 44 24 18 00 00 00 00 C7 44 24 1C 00 00 00 00 8B 7E 34 85 FF 75 1F 8D 5E 38 50 53 68 ?? ?? ?? ?? 8D 44 24 14 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 0F B7 06 25 40 04 00 00 51 3D 40 04 00 00 0F 94 C0 0F B6 C0 40 50 8D 5C 24 20 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 10 52 52 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 10 C7 44 24 18 FF FF FF FF C7 44 24 1C FF FF FF FF 85 FF 75 11 50 50 6A 01 8D 44 24 14 50 E8 ?? ?? ?? ?? 83 C4 10 8B 44 24 18 8B 54 24 1C 83 C4 20 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_asinh_a54eeb54c2b60d33b7fb462d093194c4 {
	meta:
		aliases = "asinh, __GI_asinh"
		size = "319"
		objfiles = "s_asinh@libm.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 20 8B 74 24 34 8B 5C 24 30 89 F2 89 F7 81 E2 FF FF FF 7F 81 FA FF FF EF 7F 7E 1B 89 1C 24 89 74 24 04 DD 04 24 D8 C0 DD 1C 24 8B 1C 24 8B 74 24 04 E9 F3 00 00 00 81 FA FF FF 2F 3E 7F 1F 89 1C 24 89 74 24 04 DD 04 24 DC 05 ?? ?? ?? ?? D9 E8 D9 C9 DA E9 DF E0 9E 0F 87 CC 00 00 00 81 FA 00 00 B0 41 7E 1C 50 50 56 53 E8 ?? ?? ?? ?? DD 1C 24 E8 ?? ?? ?? ?? DC 05 ?? ?? ?? ?? E9 91 00 00 00 89 1C 24 89 74 24 04 DD 04 24 D8 C8 81 FA 00 00 00 40 DD 5C 24 08 7E 3B 51 51 56 53 E8 ?? ?? ?? ?? DD 5C 24 28 D9 E8 DC 44 24 18 DD 54 24 18 DD 1C 24 E8 ?? ?? ?? ?? DD 44 24 28 D8 C0 D9 C9 DC 44 24 }
	condition:
		$pattern
}

rule pmap_getport_6f824d917965b3e14cc45a510881e40d {
	meta:
		aliases = "__GI_pmap_getport, pmap_getport"
		size = "239"
		objfiles = "pm_getport@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 20 8B 7C 24 30 66 C7 44 24 1E 00 00 C7 44 24 18 FF FF FF FF 66 C7 47 02 00 6F 68 90 01 00 00 68 90 01 00 00 8D 44 24 20 50 FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 6A 02 68 A0 86 01 00 57 E8 ?? ?? ?? ?? 83 C4 20 89 C3 85 C0 0F 84 89 00 00 00 E8 ?? ?? ?? ?? C7 44 24 14 00 00 00 00 89 C6 8B 44 24 34 89 44 24 08 8B 44 24 38 89 44 24 0C 8B 44 24 3C 89 44 24 10 8D 54 24 08 8D 44 24 1E 8B 4B 04 FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? 6A 03 53 FF 11 83 C4 20 85 C0 74 18 C7 06 0E 00 00 00 50 50 8D 46 04 8B 53 04 50 53 FF 52 08 83 C4 10 EB 0E 66 83 7C 24 1E 00 }
	condition:
		$pattern
}

rule __kernel_tan_1d1ccdc5d3f3e50fe11fa44d09a9b3ba {
	meta:
		aliases = "__kernel_tan"
		size = "593"
		objfiles = "k_tan@libm.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 20 8B 7C 24 34 8B 74 24 30 89 F9 8B 5C 24 40 81 E1 FF FF FF 7F 89 FA DD 44 24 38 81 F9 FF FF 2F 3E 7F 71 D9 7C 24 1E 66 8B 44 24 1E 80 CC 0C 89 74 24 08 89 7C 24 0C 66 89 44 24 1C DD 44 24 08 D9 6C 24 1C DB 5C 24 18 D9 6C 24 1E 8B 44 24 18 85 C0 75 40 DD D8 09 F1 8D 43 01 09 C1 75 17 50 50 57 56 E8 ?? ?? ?? ?? 83 C4 10 DC 3D ?? ?? ?? ?? E9 B7 01 00 00 4B 0F 84 BC 01 00 00 89 74 24 08 89 7C 24 0C DD 44 24 08 D8 3D ?? ?? ?? ?? E9 99 01 00 00 81 F9 27 94 E5 3F 7E 36 85 D2 79 08 81 F7 00 00 00 80 D9 E0 89 74 24 08 89 7C 24 0C DD 44 24 08 DC 2D ?? ?? ?? ?? DD 05 ?? ?? ?? ?? DE E2 DE }
	condition:
		$pattern
}

rule __GI_authnone_create_45e0d088aaccf6a89fa1bb8961bd8797 {
	meta:
		aliases = "authnone_create, __GI_authnone_create"
		size = "175"
		objfiles = "auth_none@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 20 E8 ?? ?? ?? ?? 89 C3 8B B0 98 00 00 00 85 F6 75 1C 50 50 6A 40 6A 01 E8 ?? ?? ?? ?? 83 C4 10 89 C6 31 C0 85 F6 74 7B 89 B3 98 00 00 00 83 7E 3C 00 75 6D 8D 5E 0C 50 6A 0C 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 0C 6A 0C 53 56 E8 ?? ?? ?? ?? 8D 46 28 C7 46 20 ?? ?? ?? ?? 6A 00 6A 14 50 8D 7C 24 24 57 E8 ?? ?? ?? ?? 83 C4 18 56 57 E8 ?? ?? ?? ?? 59 58 53 57 E8 ?? ?? ?? ?? 8B 44 24 1C 89 3C 24 FF 50 10 89 46 3C 8B 44 24 1C 83 C4 10 8B 40 1C 85 C0 74 09 83 EC 0C 57 FF D0 83 C4 10 89 F0 83 C4 20 5B 5E 5F C3 }
	condition:
		$pattern
}

rule if_indextoname_d9364165cf5bc4039f794852aab012d1 {
	meta:
		aliases = "if_indextoname"
		size = "119"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 20 E8 ?? ?? ?? ?? 89 C6 31 C0 85 F6 78 5D 8B 44 24 30 89 44 24 10 50 8D 5C 24 04 53 68 10 89 00 00 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 22 E8 ?? ?? ?? ?? 83 EC 0C 89 C7 8B 18 56 E8 ?? ?? ?? ?? 83 C4 10 83 FB 13 75 02 B3 06 31 C0 89 1F EB 1B 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 0C 6A 10 53 FF 74 24 40 E8 ?? ?? ?? ?? 83 C4 10 83 C4 20 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_if_nametoindex_f80d9288302f2d96d8a6f0d0c72fa77b {
	meta:
		aliases = "if_nametoindex, __GI_if_nametoindex"
		size = "117"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 20 E8 ?? ?? ?? ?? 89 C6 85 C0 78 5B 52 6A 10 FF 74 24 38 8D 5C 24 0C 53 E8 ?? ?? ?? ?? 83 C4 0C 53 68 33 89 00 00 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 22 E8 ?? ?? ?? ?? 83 EC 0C 89 C7 8B 18 56 E8 ?? ?? ?? ?? 83 C4 10 83 FB 16 75 1A C7 07 26 00 00 00 EB 12 83 EC 0C 56 E8 ?? ?? ?? ?? 8B 44 24 20 83 C4 10 EB 02 31 C0 83 C4 20 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pclose_5c0c70806da34de802ab228a01fecb60 {
	meta:
		aliases = "pclose"
		size = "190"
		objfiles = "popen@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 24 8B 7C 24 34 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 83 C4 10 85 DB 74 32 39 7B 04 75 1C 8B 03 A3 ?? ?? ?? ?? EB 24 E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 17 8B 44 24 1C EB 5F 89 DA 8B 1B 85 DB 74 E5 39 7B 04 75 F3 8B 03 89 02 52 52 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 85 DB 74 36 83 EC 0C 8B 73 08 53 E8 ?? ?? ?? ?? 89 3C 24 E8 ?? ?? ?? ?? 83 C4 10 50 6A 00 8D 44 24 24 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 A8 E8 ?? ?? ?? ?? 83 38 04 74 E1 83 C8 FF 83 C4 20 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __ieee754_acos_b2df5d8cf4fedfb0ffb0cc501e5e8be1 {
	meta:
		aliases = "__ieee754_acos"
		size = "648"
		objfiles = "e_acos@libm.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 30 8B 74 24 44 8B 5C 24 40 89 F1 81 E1 FF FF FF 7F 81 F9 FF FF EF 3F 7E 36 81 E9 00 00 F0 3F 09 D9 75 17 D9 EE 85 F6 0F 8F 4F 02 00 00 DD D8 DD 05 ?? ?? ?? ?? E9 42 02 00 00 89 5C 24 08 89 74 24 0C DD 44 24 08 D8 E0 D8 F0 E9 2D 02 00 00 81 F9 FF FF DF 3F 0F 8F 95 00 00 00 81 F9 00 00 60 3C DD 05 ?? ?? ?? ?? 0F 8E 0F 02 00 00 89 5C 24 08 89 74 24 0C DD 44 24 08 D8 C8 DD 05 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DD 05 ?? ?? ?? ?? D8 CA DC 25 ?? ?? ?? ?? D8 CA DC 05 ?? ?? ?? ?? D8 CA }
	condition:
		$pattern
}

rule __ieee754_j1_daac4fc00309a7e644a357a9bd7cf79c {
	meta:
		aliases = "__ieee754_j1"
		size = "542"
		objfiles = "e_j1@libm.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 40 8B 5C 24 54 8B 4C 24 50 89 DE 89 DF 81 E6 FF FF FF 7F 81 FE FF FF EF 7F 7E 17 89 4C 24 08 89 5C 24 0C DD 44 24 08 DC 3D ?? ?? ?? ?? E9 E0 01 00 00 81 FE FF FF FF 3F 0F 8E 31 01 00 00 50 50 53 51 E8 ?? ?? ?? ?? 59 5B DD 5C 24 38 FF 74 24 3C FF 74 24 3C E8 ?? ?? ?? ?? DD 5C 24 48 58 5A FF 74 24 3C FF 74 24 3C E8 ?? ?? ?? ?? 8B 54 24 4C 8B 44 24 48 81 F2 00 00 00 80 DD 5C 24 28 89 44 24 30 89 54 24 34 DD 44 24 30 DC 64 24 28 DD 5C 24 30 DD 44 24 48 DC 64 24 28 DD 5C 24 38 83 C4 10 81 FE FF FF DF 7F 7F 39 83 EC 10 DD 44 24 40 D8 C0 DD 1C 24 E8 ?? ?? ?? ?? DD 44 24 48 DC 4C 24 28 }
	condition:
		$pattern
}

rule __form_query_60549f8ab31be993a8e4ef9e077d1c23 {
	meta:
		aliases = "__form_query"
		size = "128"
		objfiles = "formquery@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 44 8B 7C 24 60 8B 74 24 64 6A 30 6A 00 8D 5C 24 10 53 E8 ?? ?? ?? ?? 8B 44 24 60 C7 44 24 34 01 00 00 00 89 44 24 14 8B 44 24 64 89 44 24 44 8B 44 24 68 89 44 24 48 C7 44 24 4C 01 00 00 00 83 C4 0C 56 57 53 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 78 1F 29 DE 50 8D 04 1F 56 50 8D 44 24 40 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 04 89 C3 EB 02 01 C3 83 C4 40 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pathconf_d996e28aff8239f366816073570b676e {
	meta:
		aliases = "pathconf"
		size = "196"
		objfiles = "pathconf@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 60 8B 74 24 70 8B 44 24 74 80 3E 00 75 0D E8 ?? ?? ?? ?? C7 00 02 00 00 00 EB 21 83 F8 13 77 11 FF 24 85 ?? ?? ?? ?? B8 20 00 00 00 E9 87 00 00 00 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 77 B8 7F 00 00 00 EB 70 E8 ?? ?? ?? ?? 89 C3 8B 38 52 52 8D 44 24 10 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 09 83 3B 26 75 D2 89 3B EB 37 8B 44 24 2C EB 44 31 C0 EB 40 50 50 8D 44 24 10 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 B0 8B 44 24 18 25 00 F0 00 00 3D 00 80 00 00 74 17 3D 00 60 00 00 75 99 EB 0E B8 FF 00 00 00 EB 0C B8 00 10 00 00 EB 05 B8 01 00 00 00 83 C4 60 5B 5E 5F C3 }
	condition:
		$pattern
}

rule fpathconf_16eef14aea7fb9bdf249dc3247e2cb4f {
	meta:
		aliases = "fpathconf"
		size = "204"
		objfiles = "fpathconf@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 60 8B 74 24 70 8B 54 24 74 85 F6 79 0D E8 ?? ?? ?? ?? C7 00 09 00 00 00 EB 31 B8 7F 00 00 00 85 D2 0F 84 99 00 00 00 8D 42 FF 83 F8 12 77 11 FF 24 85 ?? ?? ?? ?? B8 20 00 00 00 E9 80 00 00 00 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 70 E8 ?? ?? ?? ?? 89 C3 8B 38 52 52 8D 44 24 10 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 09 83 3B 26 75 D9 89 3B EB 37 8B 44 24 2C EB 44 31 C0 EB 40 50 50 8D 44 24 10 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 B7 8B 44 24 18 25 00 F0 00 00 3D 00 80 00 00 74 17 3D 00 60 00 00 75 A0 EB 0E B8 FF 00 00 00 EB 0C B8 00 10 00 00 EB 05 B8 01 00 00 00 83 C4 60 }
	condition:
		$pattern
}

rule __ieee754_y0_bedce0aa68d9d5bc67210e6e731da69a {
	meta:
		aliases = "__ieee754_y0"
		size = "534"
		objfiles = "e_j0@libm.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 60 8B 74 24 74 8B 5C 24 70 89 F7 89 D8 81 E7 FF FF FF 7F 81 FF FF FF EF 7F 7E 23 89 5C 24 08 89 74 24 0C DD 44 24 08 D8 C8 DD 44 24 08 DE C1 DD 54 24 08 DC 3D ?? ?? ?? ?? E9 CC 01 00 00 09 F8 75 11 D9 05 ?? ?? ?? ?? DC 35 ?? ?? ?? ?? E9 B7 01 00 00 85 F6 79 09 D9 EE D8 F0 E9 AA 01 00 00 81 FF FF FF FF 3F 0F 8E DB 00 00 00 51 51 56 53 E8 ?? ?? ?? ?? DD 5C 24 50 58 5A 56 53 E8 ?? ?? ?? ?? DD 54 24 58 DD 44 24 50 D8 E1 DD 5C 24 60 DD 44 24 50 DE C1 DD 5C 24 68 83 C4 10 81 FF FF FF DF 7F 7F 41 83 EC 10 89 5C 24 18 89 74 24 1C DD 44 24 18 D8 C0 DD 1C 24 E8 ?? ?? ?? ?? D9 E0 DD 44 24 }
	condition:
		$pattern
}

rule __ieee754_y1_5df55fc2a12a0e600dd6312117519069 {
	meta:
		aliases = "__ieee754_y1"
		size = "574"
		objfiles = "e_j1@libm.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 60 8B 74 24 74 8B 5C 24 70 89 F7 89 D8 81 E7 FF FF FF 7F 81 FF FF FF EF 7F 7E 23 89 5C 24 08 89 74 24 0C DD 44 24 08 D8 C8 DD 44 24 08 DE C1 DD 54 24 08 DC 3D ?? ?? ?? ?? E9 F4 01 00 00 09 F8 75 11 D9 05 ?? ?? ?? ?? DC 35 ?? ?? ?? ?? E9 DF 01 00 00 85 F6 79 09 D9 EE D8 F0 E9 D2 01 00 00 81 FF FF FF FF 3F 0F 8E F8 00 00 00 51 51 56 53 E8 ?? ?? ?? ?? DD 5C 24 50 58 5A 56 53 E8 ?? ?? ?? ?? 8B 54 24 54 8B 44 24 50 81 F2 00 00 00 80 DD 54 24 58 89 44 24 60 89 54 24 64 DD 44 24 60 D8 E1 DD 5C 24 60 DD 44 24 50 DE E1 DD 5C 24 68 83 C4 10 81 FF FF FF DF 7F 7F 41 83 EC 10 89 5C 24 18 89 }
	condition:
		$pattern
}

rule scan_getwc_29a76456da55b6bbe120cda14d8214cd {
	meta:
		aliases = "scan_getwc"
		size = "152"
		objfiles = "vfscanf@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 C3 83 EC 10 FF 48 10 8B 78 10 85 FF 79 09 80 48 19 02 83 C8 FF EB 76 BE FD FF FF FF C7 40 10 FF FF FF 7F EB 29 8B 03 88 44 24 0F 8D 43 1C 50 6A 01 8D 44 24 17 50 8D 44 24 14 50 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 79 27 83 F8 FE 75 10 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 C7 83 FE FD 75 16 66 BE FF FF C7 43 24 FF FF FF FF EB 18 8B 44 24 08 89 43 24 EB 0F E8 ?? ?? ?? ?? C7 00 54 00 00 00 C6 43 1B 01 89 7B 10 89 F0 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule marshal_new_auth_a13558e7daaa5337966207c6523e8ec3 {
	meta:
		aliases = "marshal_new_auth"
		size = "138"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 C3 83 EC 20 8B 78 24 6A 00 68 90 01 00 00 8D 47 1C 50 8D 74 24 14 56 E8 ?? ?? ?? ?? 59 58 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 13 8D 43 0C 52 52 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 0F 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 11 83 EC 0C 56 8B 44 24 1C FF 50 10 89 87 AC 01 00 00 83 C4 10 8B 44 24 0C 8B 50 1C 85 D2 74 0D 83 EC 0C 8D 44 24 14 50 FF D2 83 C4 10 83 C4 20 B8 01 00 00 00 5B 5E 5F C3 }
	condition:
		$pattern
}

rule do_close_11e6f1366d55d16c3bca829ac03b34e8 {
	meta:
		aliases = "do_close"
		size = "32"
		objfiles = "rtime@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 C3 E8 ?? ?? ?? ?? 83 EC 0C 89 C6 8B 38 53 E8 ?? ?? ?? ?? 89 3E 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule _charpad_3de615833753328b47c9f024268f00a4 {
	meta:
		aliases = "_charpad"
		size = "54"
		objfiles = "_vfprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 C7 83 EC 10 89 CE 89 CB 88 54 24 0F EB 01 4B 85 DB 74 14 8D 44 24 0F 52 57 6A 01 50 E8 ?? ?? ?? ?? 83 C4 10 48 74 E7 29 DE 83 C4 10 89 F0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule _charpad_1285ce4b5f7a431741eff89f23f10031 {
	meta:
		aliases = "_charpad"
		size = "54"
		objfiles = "_vfwprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 C7 83 EC 10 89 CE 89 CB 89 54 24 0C EB 01 4B 85 DB 74 14 50 57 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 48 74 E7 29 DE 83 C4 10 89 F0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __rt_sigtimedwait_812cb69102fbae880c0bc94ec48f24b6 {
	meta:
		aliases = "__rt_sigtimedwait"
		size = "53"
		objfiles = "__rt_sigtimedwait@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 D3 89 C7 89 CA 8B 74 24 10 89 D9 53 89 FB B8 B1 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule byte_insert_op1_ef1df006f13922c123df2253ae5ef5b5 {
	meta:
		aliases = "byte_insert_op1"
		size = "40"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 D3 8B 54 24 10 89 CE 89 C7 8D 4A 03 EB 06 4A 49 8A 02 88 01 39 DA 75 F6 89 F1 89 F8 5B 5E 5F E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule trecurse_65903b12621c65a9f14a2d0e2bf04dfe {
	meta:
		aliases = "trecurse"
		size = "95"
		objfiles = "twalk@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 D7 89 C3 89 CE 83 78 04 00 75 0C 83 78 08 00 75 06 50 51 6A 03 EB 3A 51 56 6A 00 53 FF D7 8B 43 04 83 C4 10 85 C0 74 0A 8D 4E 01 89 FA E8 CA FF FF FF 52 56 6A 01 53 FF D7 8B 43 08 83 C4 10 85 C0 74 0A 8D 4E 01 89 FA E8 AF FF FF FF 50 56 6A 02 53 FF D7 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule _dl_add_elf_hash_table_5c669e80f6baa72ea4f7f36f30495270 {
	meta:
		aliases = "_dl_add_elf_hash_table"
		size = "219"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 1D ?? ?? ?? ?? 8B 74 24 14 8B 7C 24 18 85 DB 75 2C 83 EC 0C 68 E8 00 00 00 E8 ?? ?? ?? ?? BA E8 00 00 00 89 C3 83 C4 10 A3 ?? ?? ?? ?? EB 04 C6 00 00 40 4A 83 FA FF 75 F6 EB 35 89 C3 8B 43 0C 85 C0 75 F7 83 EC 0C 68 E8 00 00 00 E8 ?? ?? ?? ?? BA E8 00 00 00 83 C4 10 89 43 0C EB 04 C6 00 00 40 4A 83 FA FF 75 F6 8B 43 0C 89 58 10 89 C3 83 EC 0C C7 43 0C 00 00 00 00 66 C7 43 22 00 00 FF 74 24 1C E8 ?? ?? ?? ?? 89 43 04 8B 44 24 2C C7 43 18 03 00 00 00 89 43 08 83 C4 10 8B 4F 10 85 C9 74 17 8B 01 89 43 28 8B 51 04 89 53 38 8D 51 08 89 53 2C 8D 04 82 89 43 3C 31 D2 89 33 89 73 14 EB 08 }
	condition:
		$pattern
}

rule _dl_run_init_array_520c102fc8dbbdf9b60cfff9d934d60b {
	meta:
		aliases = "_dl_run_init_array"
		size = "49"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 44 24 10 8B 08 8B 90 AC 00 00 00 8B 80 A4 00 00 00 85 C0 74 14 89 D7 8D 34 01 C1 EF 02 31 DB EB 04 FF 14 9E 43 39 FB 72 F8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule svctcp_recv_acf56bfaa7c600490eb9fc2f2d6cccd0 {
	meta:
		aliases = "svctcp_recv"
		size = "73"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 44 24 10 8B 7C 24 14 83 EC 0C 8B 70 2C 8D 5E 08 C7 46 08 01 00 00 00 53 E8 ?? ?? ?? ?? 59 58 57 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 0C 8B 07 89 46 04 B8 01 00 00 00 EB 08 C7 06 00 00 00 00 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule svcunix_recv_206bf8dd2ee41c5855628dc06b609303 {
	meta:
		aliases = "svcunix_recv"
		size = "94"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 44 24 10 8B 7C 24 14 83 EC 0C 8B 70 2C 8D 5E 08 C7 46 08 01 00 00 00 53 E8 ?? ?? ?? ?? 59 58 57 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 21 8B 07 89 46 04 B8 01 00 00 00 C7 47 24 01 00 00 00 C7 47 28 ?? ?? ?? ?? C7 47 2C 1C 00 00 00 EB 08 C7 06 00 00 00 00 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule dlsym_5b3a9670736cbc108876b7ef9c99ca72 {
	meta:
		aliases = "dlsym"
		size = "156"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 4C 24 10 89 CA 85 C9 75 08 8B 15 ?? ?? ?? ?? EB 56 83 F9 FF 74 26 3B 0D ?? ?? ?? ?? 74 49 A1 ?? ?? ?? ?? EB 07 39 C8 74 3E 8B 40 04 85 C0 75 F5 C7 05 ?? ?? ?? ?? 09 00 00 00 EB 58 8B 7C 24 0C A1 ?? ?? ?? ?? 31 F6 EB 1A 8B 18 8B 4B 14 39 F9 73 0E 85 F6 74 05 39 4E 14 73 05 8B 50 10 89 DE 8B 40 10 85 C0 75 E2 31 C0 3B 15 ?? ?? ?? ?? 75 02 8B 02 68 00 00 00 80 50 52 FF 74 24 20 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 0A C7 05 ?? ?? ?? ?? 0A 00 00 00 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_mknod_b8ef70435fdebbe8142f8c7577ab510d {
	meta:
		aliases = "mknod, __GI_mknod"
		size = "84"
		objfiles = "mknod@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 4C 24 18 8B 5C 24 1C 89 DA 89 C8 0F AC D0 08 C1 EA 08 89 C2 0F B7 74 24 14 0F B6 C1 C1 E2 08 8B 7C 24 10 09 C2 89 F1 0F B7 D2 53 89 FB B8 0E 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule _dl_parse_dynamic_info_5453be681e68fd5f33518baf6f8aa8cd {
	meta:
		aliases = "_dl_parse_dynamic_info"
		size = "258"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 54 24 10 8B 5C 24 14 8B 7C 24 18 8B 74 24 1C E9 8E 00 00 00 83 F9 21 7F 58 8B 42 04 89 04 8B 83 3A 15 75 03 89 7A 04 83 3A 18 75 07 C7 43 60 01 00 00 00 83 3A 1E 75 0D F6 42 04 08 74 07 C7 43 60 01 00 00 00 83 3A 16 75 07 C7 43 58 01 00 00 00 83 3A 1D 75 07 C7 43 3C 00 00 00 00 83 3A 0F 75 3D 83 7B 74 00 74 37 C7 43 3C 00 00 00 00 EB 2E 81 F9 FF FF FF 6F 7F 26 81 F9 FA FF FF 6F 75 09 8B 42 04 89 83 88 00 00 00 81 3A FB FF FF 6F 75 0D F6 42 04 01 74 07 C7 43 60 01 00 00 00 83 C2 08 8B 0A 85 C9 0F 85 68 FF FF FF 8B 43 10 85 C0 74 06 8D 04 06 89 43 10 8B 43 0C 85 C0 74 06 8D 04 06 89 }
	condition:
		$pattern
}

rule pthread_setspecific_ab6d33c9143128a31a7f423ef86d1b95 {
	meta:
		aliases = "pthread_setspecific"
		size = "109"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 81 FB FF 03 00 00 77 55 83 3C DD ?? ?? ?? ?? 00 74 4B E8 ?? ?? ?? ?? 89 DE C1 EE 05 89 C7 83 BC B0 EC 00 00 00 00 75 20 50 50 6A 04 6A 20 E8 ?? ?? ?? ?? 83 C4 10 89 C2 B8 0C 00 00 00 85 D2 74 21 89 94 B7 EC 00 00 00 83 E3 1F 8B 94 B7 EC 00 00 00 8B 44 24 14 89 04 9A 31 C0 EB 05 B8 16 00 00 00 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_mutex_trylock_82f5194e649fc66eadbf70fd605cbef4 {
	meta:
		aliases = "__pthread_mutex_trylock, pthread_mutex_trylock"
		size = "137"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 8B 43 0C 83 F8 01 74 24 7F 06 85 C0 74 13 EB 0A 83 F8 02 74 44 83 F8 03 74 57 BE 16 00 00 00 EB 5B 8D 43 10 5B 5E 5F E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C7 39 43 08 75 07 FF 43 04 31 F6 EB 3D 8D 43 10 E8 ?? ?? ?? ?? 89 C6 85 C0 75 2F 89 7B 08 C7 43 04 00 00 00 00 EB 23 8D 43 10 E8 ?? ?? ?? ?? 89 C6 85 C0 75 15 E8 ?? ?? ?? ?? 89 43 08 EB 0B 8D 43 10 5B 5E 5F E9 ?? ?? ?? ?? 89 F0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule obstack_free_836b03b4d8cb240a14848f759e98e6e5 {
	meta:
		aliases = "obstack_free"
		size = "96"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 8B 74 24 14 8B 53 04 EB 23 8B 7A 04 F6 43 28 01 8B 43 20 74 08 51 51 52 FF 73 24 EB 04 83 EC 0C 52 FF D0 83 C4 10 80 4B 28 02 89 FA 85 D2 74 1C 39 F2 73 D5 39 32 72 D1 85 D2 74 10 89 73 0C 89 73 08 8B 02 89 53 04 89 43 10 EB 09 85 F6 74 05 E8 ?? ?? ?? ?? 5B 5E 5F C3 }
	condition:
		$pattern
}

rule wcstok_9f19e224e03565282523d9ef8971da6a {
	meta:
		aliases = "wcstok"
		size = "84"
		objfiles = "wcstok@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 8B 74 24 14 8B 7C 24 18 85 DB 75 06 8B 1F 85 DB 74 35 52 52 56 53 E8 ?? ?? ?? ?? 83 C4 10 8D 1C 83 83 3B 00 75 06 31 DB 31 C0 EB 19 50 50 56 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 09 C7 00 00 00 00 00 83 C0 04 89 07 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule strtok_r_743ac83a9d2bf117e1377539e9d52605 {
	meta:
		aliases = "__GI_strtok_r, strtok_r"
		size = "89"
		objfiles = "strtok_r@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 8B 7C 24 14 8B 74 24 18 85 DB 75 02 8B 1E 51 51 57 53 E8 ?? ?? ?? ?? 83 C4 10 01 C3 80 3B 00 75 06 31 C0 89 1E EB 27 52 52 57 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 0F 50 50 6A 00 53 E8 ?? ?? ?? ?? 83 C4 10 EB 04 C6 00 00 40 89 06 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __getdents_1ae20c862c5afb7b7dcb5b2031200a32 {
	meta:
		aliases = "__getdents"
		size = "111"
		objfiles = "getdents@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 14 52 FF 74 24 1C 53 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 7E 4A 8D 3C 03 EB 41 8B 43 08 89 43 04 8B 43 10 66 89 43 08 8A 43 12 88 43 0A 50 0F B7 43 08 83 E8 13 50 8D 43 13 50 8D 43 0B 50 E8 ?? ?? ?? ?? 83 C4 0C 0F B7 43 08 50 53 53 E8 ?? ?? ?? ?? 0F B7 43 08 83 C4 10 01 C3 39 FB 72 BB 89 F0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_tfind_eed1067871271953a2dc105709ab72c7 {
	meta:
		aliases = "tfind, __GI_tfind"
		size = "66"
		objfiles = "tfind@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 14 8B 7C 24 10 8B 74 24 18 85 DB 74 29 EB 21 52 52 FF 30 57 FF D6 83 C4 10 83 F8 00 75 04 8B 03 EB 16 7D 07 8B 1B 83 C3 04 EB 05 8B 1B 83 C3 08 8B 03 85 C0 75 D9 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule fwrite_unlocked_3fab115914527fad40096310b76317e4 {
	meta:
		aliases = "__GI_fwrite_unlocked, fwrite_unlocked"
		size = "116"
		objfiles = "fwrite_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 1C 8B 74 24 14 8B 7C 24 18 0F B7 03 25 C0 00 00 00 3D C0 00 00 00 74 14 52 52 68 80 00 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 3C 85 F6 74 38 85 FF 74 34 83 C8 FF 31 D2 F7 F6 39 C7 77 1A 50 89 F0 0F AF C7 53 50 FF 74 24 1C E8 ?? ?? ?? ?? 31 D2 F7 F6 83 C4 10 EB 11 66 83 0B 08 E8 ?? ?? ?? ?? C7 00 16 00 00 00 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule re_match_2_629ac7dd0f20575f9a3899fcd5b08fd8 {
	meta:
		aliases = "__re_match_2, re_match_2"
		size = "63"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 2C 8B 74 24 20 89 5C 24 20 8B 5C 24 28 8B 7C 24 1C 8B 44 24 10 8B 54 24 14 8B 4C 24 18 89 5C 24 1C 8B 5C 24 24 89 74 24 14 89 7C 24 10 89 5C 24 18 5B 5E 5F E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_pthread_attr_setschedpara_1e199539c4066c065b1c7cd6e6e06fe2 {
	meta:
		aliases = "pthread_attr_setschedparam, __GI_pthread_attr_setschedparam"
		size = "75"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 10 8B 7C 24 14 83 EC 0C FF 76 04 E8 ?? ?? ?? ?? 89 C3 58 FF 76 04 E8 ?? ?? ?? ?? 8B 17 83 C4 10 39 C2 7C 18 39 DA 7F 14 50 8D 46 08 6A 04 57 50 E8 ?? ?? ?? ?? 31 C0 83 C4 10 EB 05 B8 16 00 00 00 5B 5E 5F C3 }
	condition:
		$pattern
}

rule wcsstr_9887b12654a526cef72d07c3a00876e9 {
	meta:
		aliases = "wcswcs, wcsstr"
		size = "54"
		objfiles = "wcsstr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 10 8B 7C 24 14 89 F0 89 FA 8B 1A 85 DB 75 04 89 F0 EB 19 8B 08 39 CB 75 08 83 C2 04 83 C0 04 EB E8 85 C9 74 05 83 C6 04 EB DB 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule wcscspn_a6aaad37f029d6b3b57981c412c0ea1f {
	meta:
		aliases = "wcscspn"
		size = "50"
		objfiles = "wcscspn@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 10 8B 7C 24 14 89 F0 EB 10 39 D9 74 16 83 C2 04 8B 0A 85 C9 75 F3 83 C0 04 8B 18 85 DB 74 04 89 FA EB ED 29 F0 5B C1 F8 02 5E 5F C3 }
	condition:
		$pattern
}

rule __encode_question_714b2a18bb950bcc03ec83f7b937857c {
	meta:
		aliases = "__encode_question"
		size = "83"
		objfiles = "encodeq@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 10 8B 7C 24 14 8B 5C 24 18 50 53 57 FF 36 E8 ?? ?? ?? ?? 83 C4 10 89 C1 85 C0 78 2B 29 C3 83 FB 03 7F 05 83 C9 FF EB 1F 8D 14 07 83 C1 04 0F B6 46 05 88 02 8B 46 04 88 42 01 0F B6 46 09 88 42 02 8B 46 08 88 42 03 89 C8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule wcscasecmp_ddc5e0ce7b15d664655ecb48af92e86a {
	meta:
		aliases = "__GI_wcscasecmp, wcscasecmp"
		size = "103"
		objfiles = "wcscasecmp@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 10 8B 7C 24 14 EB 0B 83 3E 00 74 46 83 C6 04 83 C7 04 8B 06 3B 07 74 EF 83 EC 0C 50 E8 ?? ?? ?? ?? 5A 89 C3 FF 37 E8 ?? ?? ?? ?? 83 C4 10 39 C3 74 D5 83 EC 0C FF 36 E8 ?? ?? ?? ?? 89 C3 58 FF 37 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 39 C3 72 0B EB 04 31 D2 EB 05 BA 01 00 00 00 89 D0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule sched_getaffinity_3fc626ac7d66e7f8277dd613ca415db6 {
	meta:
		aliases = "sched_getaffinity"
		size = "90"
		objfiles = "sched_getaffinity@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 14 8B 7C 24 10 89 F1 85 F6 79 05 B9 FF FF FF 7F 8B 54 24 18 53 89 FB B8 F2 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0B E8 ?? ?? ?? ?? F7 DB 89 18 EB 03 43 75 05 83 C8 FF EB 15 29 C6 52 56 6A 00 03 44 24 24 50 E8 ?? ?? ?? ?? 31 C0 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule _obstack_begin_1_f60a34664eb37d8cc5426a47d9409f89 {
	meta:
		aliases = "_obstack_begin_1"
		size = "143"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 18 8B 5C 24 10 8B 54 24 14 8B 4C 24 1C 8B 7C 24 24 85 F6 75 04 66 BE 04 00 85 D2 75 04 66 BA E0 0F 89 4B 1C 8B 44 24 20 89 13 80 4B 28 01 89 43 20 8D 46 FF 89 43 18 89 7B 24 F6 43 28 01 74 06 50 50 52 57 EB 05 83 EC 0C FF 33 FF D1 83 C4 10 89 C2 89 43 04 85 C0 75 05 E8 ?? ?? ?? ?? 8D 44 30 07 F7 DE 21 F0 89 43 08 89 43 0C 89 D0 03 03 89 02 89 43 10 C7 42 04 00 00 00 00 B8 01 00 00 00 80 63 28 F9 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_strndup_8fa7dcf63642a9adf64b474b5d43bcc6 {
	meta:
		aliases = "strndup, __GI_strndup"
		size = "63"
		objfiles = "strndup@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 52 52 FF 74 24 1C 57 E8 ?? ?? ?? ?? 89 C6 8D 40 01 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 74 10 50 56 57 53 E8 ?? ?? ?? ?? C6 04 33 00 83 C4 10 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule getnetbyname_2c79a68179ee188fb51b5a87041580af {
	meta:
		aliases = "getnetbyname"
		size = "106"
		objfiles = "getnetbynm@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 83 EC 0C 0F BE 05 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 10 EB 2F 51 51 57 FF 36 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 29 8B 5E 04 EB 13 52 52 57 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 14 83 C3 04 8B 03 85 C0 75 E7 E8 ?? ?? ?? ?? 89 C6 85 C0 75 C6 80 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 89 F0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule wcsdup_da19ca3ca987ff9e298d16d8d70b89c6 {
	meta:
		aliases = "wcsdup"
		size = "58"
		objfiles = "wcsdup@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 83 EC 0C 57 E8 ?? ?? ?? ?? 8D 34 85 04 00 00 00 89 34 24 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 74 0C 50 56 57 53 E8 ?? ?? ?? ?? 83 C4 10 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule strdup_7b4dae6f98244a7ce2b57c8e57e5d042 {
	meta:
		aliases = "__GI_strdup, strdup"
		size = "54"
		objfiles = "strdup@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 83 EC 0C 57 E8 ?? ?? ?? ?? 8D 70 01 89 34 24 E8 ?? ?? ?? ?? 83 C4 10 89 C3 85 C0 74 0C 50 56 57 53 E8 ?? ?? ?? ?? 83 C4 10 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule getrpcbyname_fbca9fa376ea67bbb7a6cd21baabdec0 {
	meta:
		aliases = "__GI_getrpcbyname, getrpcbyname"
		size = "91"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 83 EC 0C 6A 00 E8 ?? ?? ?? ?? 83 C4 10 EB 2F 53 53 57 FF 36 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 2E 8B 5E 04 EB 13 51 51 57 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 19 83 C3 04 8B 03 85 C0 75 E7 E8 ?? ?? ?? ?? 89 C6 85 C0 75 C6 E8 ?? ?? ?? ?? 89 F0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule xdr_callmsg_a186988f5710acd384ea3f456bff34f0 {
	meta:
		aliases = "__GI_xdr_callmsg, xdr_callmsg"
		size = "865"
		objfiles = "rpc_cmsg@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 8B 5C 24 14 83 3F 00 0F 85 ED 00 00 00 8B 43 20 3D 90 01 00 00 0F 87 32 03 00 00 8B 53 2C 81 FA 90 01 00 00 0F 87 23 03 00 00 83 C2 03 83 C0 03 83 E2 FC 83 E0 FC 51 51 8B 4F 04 8D 44 10 28 50 57 FF 51 18 83 C4 10 89 C2 85 C0 0F 84 A9 00 00 00 8B 03 8D 72 04 0F C8 89 02 8B 43 04 0F C8 89 42 04 83 7B 04 00 0F 85 E1 02 00 00 8B 43 08 8D 4A 08 0F C8 89 46 04 83 7B 08 02 0F 85 CC 02 00 00 8B 43 0C 8D 73 18 0F C8 89 41 04 8D 7A 20 8B 43 10 0F C8 89 42 10 8B 43 14 0F C8 89 42 14 8B 43 18 0F C8 89 42 18 8B 46 08 0F C8 89 42 1C 8B 46 08 85 C0 74 19 52 50 FF 76 04 57 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getnetbyaddr_a36a45b7a9a695d7b9b34262d7977a0b {
	meta:
		aliases = "getnetbyaddr"
		size = "73"
		objfiles = "getnetbyad@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 8B 74 24 14 0F BE 05 ?? ?? ?? ?? 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 EB 0A 39 73 08 75 05 39 7B 0C 74 0B E8 ?? ?? ?? ?? 89 C3 85 C0 75 EB 80 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule wmemmove_469812cbb003d4042cbbb2c76a8015af {
	meta:
		aliases = "wmemmove"
		size = "66"
		objfiles = "wmemmove@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 8B 74 24 14 8B 4C 24 18 39 FE 72 25 89 FB 89 F2 EB 0B 8B 02 49 89 03 83 C2 04 83 C3 04 85 C9 75 F1 EB 12 49 8D 14 8D 00 00 00 00 8B 04 16 89 04 17 85 C9 75 EE 89 F8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule stpncpy_350b46d40b84d9a4f9b1292301ece59d {
	meta:
		aliases = "__GI_stpncpy, stpncpy"
		size = "45"
		objfiles = "stpncpy@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 8B 74 24 14 8B 5C 24 18 89 F2 89 F9 EB 0B 8A 02 3C 01 88 01 83 DA FF 41 4B 85 DB 75 F1 29 F2 5B 5E 8D 04 17 5F C3 }
	condition:
		$pattern
}

rule wcpncpy_af1f8176e20a170947d3cd1c413e6854 {
	meta:
		aliases = "wcpncpy"
		size = "49"
		objfiles = "wcpncpy@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 8B 74 24 14 8B 5C 24 18 89 F2 89 F9 EB 0F 8B 02 89 01 85 C0 74 03 83 C2 04 83 C1 04 4B 85 DB 75 ED 29 F2 5B 5E 8D 04 17 5F C3 }
	condition:
		$pattern
}

rule pthread_mutex_timedlock_0cf9c470a5edbe0643d6ff61d15808bb {
	meta:
		aliases = "pthread_mutex_timedlock"
		size = "191"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 14 8B 74 24 10 81 7F 04 FF C9 9A 3B 0F 87 95 00 00 00 8B 46 0C 83 F8 01 74 23 7F 09 85 C0 74 11 E9 82 00 00 00 83 F8 02 74 3C 83 F8 03 75 78 EB 5E 8D 46 10 31 D2 E8 ?? ?? ?? ?? EB 0F E8 ?? ?? ?? ?? 89 C3 39 46 08 75 07 FF 46 04 31 D2 EB 63 8D 46 10 89 DA E8 ?? ?? ?? ?? 89 5E 08 C7 46 04 00 00 00 00 EB E6 E8 ?? ?? ?? ?? BA 23 00 00 00 89 C3 39 46 08 74 3C 50 8D 46 10 57 53 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 24 89 5E 08 EB BD 8D 46 10 51 57 6A 00 50 E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 75 0E EB 07 BA 16 00 00 00 EB 05 BA 6E 00 00 00 89 D0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule ___path_search_b3de51969a96122615197d761b98aa1b {
	meta:
		aliases = "___path_search"
		size = "203"
		objfiles = "tempname@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 1C 8B 5C 24 18 85 FF 74 1F 80 3F 00 74 1A 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 89 C6 83 F8 05 76 11 BE 05 00 00 00 EB 0A BF ?? ?? ?? ?? BE 04 00 00 00 85 DB 75 3B B8 ?? ?? ?? ?? BB ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 75 28 50 50 53 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 0B 89 D8 E8 ?? ?? ?? ?? 85 C0 75 0D E8 ?? ?? ?? ?? C7 00 02 00 00 00 EB 32 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 89 C2 EB 01 4A 83 FA 01 76 07 80 7C 13 FF 2F 74 F3 8D 44 32 08 39 44 24 14 73 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 19 51 51 57 56 53 52 68 ?? ?? ?? ?? FF 74 24 2C E8 ?? ?? ?? ?? 31 C0 83 C4 20 5B }
	condition:
		$pattern
}

rule wctrans_d6275519c949212fc55b1c924c9ebd87 {
	meta:
		aliases = "__GI_wctrans, wctype, __GI_wctype, wctrans"
		size = "61"
		objfiles = "wctrans@libc.a, wctype@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 B8 ?? ?? ?? ?? 8B 7C 24 10 BE 01 00 00 00 8D 58 01 50 50 53 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 04 89 F0 EB 11 0F B6 43 FF 8D 04 03 80 38 00 74 03 46 EB DA 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule sigwait_66eaa88e866f3c7a145964fe326c7992 {
	meta:
		aliases = "sigwait"
		size = "365"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 BE 01 00 00 00 81 EC B0 01 00 00 E8 ?? ?? ?? ?? 8B BC 24 C0 01 00 00 89 84 24 AC 01 00 00 83 EC 0C 8D 9C 24 38 01 00 00 53 E8 ?? ?? ?? ?? 58 5A FF 35 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 E9 82 00 00 00 50 50 56 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 71 3B 35 ?? ?? ?? ?? 74 69 3B 35 ?? ?? ?? ?? 74 61 3B 35 ?? ?? ?? ?? 74 59 50 50 56 8D 84 24 38 01 00 00 50 E8 ?? ?? ?? ?? 83 C4 10 83 3C B5 ?? ?? ?? ?? 01 77 3C C7 84 24 A0 00 00 00 ?? ?? ?? ?? 83 EC 0C 8D 84 24 B0 00 00 00 8D 9C 24 AC 00 00 00 50 E8 ?? ?? ?? ?? C7 84 24 34 01 00 00 00 00 00 00 83 C4 0C 6A 00 53 56 E8 ?? ?? ?? ?? 83 C4 10 }
	condition:
		$pattern
}

rule pthread_rwlock_tryrdlock_b815086f18804ec6dfaedb9d171ade6a {
	meta:
		aliases = "pthread_rwlock_tryrdlock"
		size = "141"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 BE 10 00 00 00 83 EC 10 E8 ?? ?? ?? ?? 8B 5C 24 20 89 44 24 0C 83 EC 0C 8D 54 24 10 8D 4C 24 14 8D 44 24 18 52 89 DA E8 ?? ?? ?? ?? 8B 54 24 1C 89 C7 89 D8 E8 ?? ?? ?? ?? 31 D2 89 D8 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 06 66 31 F6 FF 43 08 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 F6 75 22 85 FF 75 07 83 7C 24 04 00 74 17 8B 44 24 08 85 C0 74 05 FF 40 08 EB 0A 8B 44 24 0C FF 80 C8 01 00 00 83 C4 10 89 F0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pmap_rmtcall_fe0434d2c8108c4be8acd538db2c9a31 {
	meta:
		aliases = "pmap_rmtcall"
		size = "198"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 BE 10 00 00 00 83 EC 38 8B 7C 24 48 8D 44 24 34 C7 44 24 34 FF FF FF FF 66 C7 47 02 00 6F 50 FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 6A 02 68 A0 86 01 00 57 E8 ?? ?? ?? ?? 83 C4 20 89 C3 85 C0 74 73 8B 44 24 44 8D 54 24 04 89 44 24 04 8B 44 24 48 89 44 24 08 8B 44 24 4C 89 44 24 0C 8B 44 24 54 89 44 24 14 8B 44 24 50 89 44 24 18 8B 44 24 68 89 44 24 1C 8B 44 24 5C 89 44 24 24 8B 44 24 58 89 44 24 28 8D 44 24 1C 8B 4B 04 FF 74 24 64 FF 74 24 64 50 68 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? 6A 05 53 FF 11 83 C4 14 89 C6 8B 43 04 53 FF 50 10 83 C4 10 66 C7 47 02 00 00 89 F0 83 C4 30 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_remove_5713e800181ffe9095ca1e02b487d5d5 {
	meta:
		aliases = "remove, __GI_remove"
		size = "55"
		objfiles = "remove@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 E8 ?? ?? ?? ?? 8B 74 24 10 83 EC 0C 8B 38 89 C3 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 13 83 3B 14 75 0E 89 3B 89 74 24 10 5B 5E 5F E9 ?? ?? ?? ?? 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_sighandler_b0776d88c0e559598b49223e07d5e846 {
	meta:
		aliases = "pthread_sighandler"
		size = "88"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 E8 ?? ?? ?? ?? 8B 74 24 10 89 C3 80 78 58 00 74 09 C6 40 58 00 89 70 20 EB 37 8B 78 54 85 FF 75 03 89 60 54 83 EC 5C 89 E2 8D 44 24 70 51 51 6A 58 50 52 E8 ?? ?? ?? ?? 83 C4 14 56 FF 14 B5 ?? ?? ?? ?? 83 C4 60 85 FF 75 07 C7 43 54 00 00 00 00 5B 5E 5F C3 }
	condition:
		$pattern
}

rule xprt_register_b4dc6386de82eb6a88198a89bb340869 {
	meta:
		aliases = "__GI_xprt_register, xprt_register"
		size = "217"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 E8 ?? ?? ?? ?? 8B 74 24 10 89 C3 83 B8 B4 00 00 00 00 8B 3E 75 22 E8 ?? ?? ?? ?? 83 EC 0C C1 E0 02 50 E8 ?? ?? ?? ?? 83 C4 10 89 83 B4 00 00 00 85 C0 0F 84 9A 00 00 00 E8 ?? ?? ?? ?? 39 C7 0F 8D 8D 00 00 00 8B 83 B4 00 00 00 81 FF FF 03 00 00 89 34 B8 7F 13 E8 ?? ?? ?? ?? 89 F9 C1 E9 05 89 FA 83 E2 1F 0F AB 14 88 31 DB EB 23 E8 ?? ?? ?? ?? 8D 0C DD 00 00 00 00 89 CA 03 10 83 3A FF 75 0D 89 3A 8B 00 66 C7 44 08 04 C3 00 EB 43 43 E8 ?? ?? ?? ?? 89 C6 8B 00 39 C3 7C D0 40 89 06 E8 ?? ?? ?? ?? 89 C3 50 50 8B 06 C1 E0 03 50 FF 33 E8 ?? ?? ?? ?? 83 C4 10 89 03 89 C2 85 C0 74 11 8B 06 89 7C }
	condition:
		$pattern
}

rule pthread_sighandler_rt_162ab4d063a533c81e026b2018ff8647 {
	meta:
		aliases = "pthread_sighandler_rt"
		size = "74"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 E8 ?? ?? ?? ?? 8B 7C 24 10 89 C3 80 78 58 00 74 09 C6 40 58 00 89 78 20 EB 29 8B 70 54 85 F6 75 03 89 60 54 50 FF 74 24 1C FF 74 24 1C 57 FF 14 BD ?? ?? ?? ?? 83 C4 10 85 F6 75 07 C7 43 54 00 00 00 00 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __pthread_perform_cleanup_d89b1c0bbba3a2c8131699ab5be1ebd6 {
	meta:
		aliases = "__pthread_perform_cleanup"
		size = "62"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 E8 ?? ?? ?? ?? 8B 7C 24 10 89 C6 8B 58 3C EB 12 39 FB 76 12 83 EC 0C FF 73 04 FF 13 8B 5B 0C 83 C4 10 85 DB 75 EA 83 BE 74 01 00 00 00 74 08 5B 5E 5F E9 ?? ?? ?? ?? 5B 5E 5F C3 }
	condition:
		$pattern
}

rule mq_send_7ce2c74b93583ce533e06838cdb49612 {
	meta:
		aliases = "mq_send"
		size = "61"
		objfiles = "mq_send@librt.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 31 FF 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 44 24 10 53 89 C3 B8 17 01 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule mq_receive_20d2ccd0240181351e0fed6cd5291765 {
	meta:
		aliases = "mq_receive"
		size = "61"
		objfiles = "mq_receive@librt.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 31 FF 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 44 24 10 53 89 C3 B8 18 01 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule timer_settime_bae3ea26d42c26fa20555195c4dd1815 {
	meta:
		aliases = "timer_settime"
		size = "62"
		objfiles = "timer_settime@librt.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 44 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 78 04 53 89 FB B8 04 01 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule splice_04d91c1243cf06d0d0aa9fde826aa7bd {
	meta:
		aliases = "__GI_splice, splice"
		size = "69"
		objfiles = "splice@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 55 8B 6C 24 24 B8 39 01 00 00 CD 80 5D 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule __syscall_ipc_00f1b287f0148d733e0901f290044c0a {
	meta:
		aliases = "__syscall_ipc"
		size = "69"
		objfiles = "__syscall_ipc@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 55 8B 6C 24 24 B8 75 00 00 00 CD 80 5D 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule remap_file_pages_4e35203f79e5e0d89cde6fe4e01da971 {
	meta:
		aliases = "remap_file_pages"
		size = "63"
		objfiles = "remap_file_pages@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 B8 01 01 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule mount_4855967185c1033d91efcbdef71bfa59 {
	meta:
		aliases = "mount"
		size = "63"
		objfiles = "mount@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 B8 15 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule init_module_9a1c628f679c937f1a455ab6f701e0fd {
	meta:
		aliases = "init_module"
		size = "63"
		objfiles = "init_module@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 B8 80 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_select_496b7e3d4929e33baf36f6e39ca98718 {
	meta:
		aliases = "select, __libc_select, __GI_select"
		size = "63"
		objfiles = "select@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 B8 8E 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_mremap_013f416175a9d5855f0eefef1ef3d6b1 {
	meta:
		aliases = "mremap, __GI_mremap"
		size = "63"
		objfiles = "mremap@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 B8 A3 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule query_module_dc2c9a04e15cb1639e9ccffdcd32ce24 {
	meta:
		aliases = "query_module"
		size = "63"
		objfiles = "query_module@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 B8 A7 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule prctl_0846397d3af1a0d197ea53b23cb3508a {
	meta:
		aliases = "prctl"
		size = "63"
		objfiles = "prctl@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 B8 AC 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule setxattr_e82070a09fb5f46d4765a37d5d8c15c2 {
	meta:
		aliases = "setxattr"
		size = "63"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 B8 E2 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5F 5E 5F C3 }
	condition:
		$pattern
}

rule lsetxattr_c9481b4a66d4dc41ae0c3491c182c4fa {
	meta:
		aliases = "lsetxattr"
		size = "63"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 B8 E3 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5E 5E 5F C3 }
	condition:
		$pattern
}

rule fsetxattr_1364e5065ba8c6683f77c0bddf1d3a9e {
	meta:
		aliases = "fsetxattr"
		size = "63"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 B8 E4 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 59 5E 5F C3 }
	condition:
		$pattern
}

rule sigprocmask_426b7bf025b50bab012d1bf1ec73159d {
	meta:
		aliases = "__GI_sigprocmask, sigprocmask"
		size = "85"
		objfiles = "sigprocmask@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 7C 24 10 8B 54 24 18 85 C9 74 15 83 FF 02 76 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 27 BE 08 00 00 00 53 89 FB B8 AF 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_strncpy_855e8f2c92e38af254328b071f54fd54 {
	meta:
		aliases = "strncpy, __GI_strncpy"
		size = "38"
		objfiles = "strncpy@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 74 24 14 8B 4C 24 18 8B 7C 24 10 41 49 74 09 AC AA 84 C0 75 F7 49 F3 AA 8B 44 24 10 5A 5E 5F C3 }
	condition:
		$pattern
}

rule strcpy_25e830002e76d977a2cf7c0f6516f752 {
	meta:
		aliases = "__GI_strcpy, strcpy"
		size = "27"
		objfiles = "strcpy@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 74 24 14 8B 7C 24 10 AC AA 84 C0 75 FA 8B 44 24 10 5A 5E 5F C3 }
	condition:
		$pattern
}

rule epoll_wait_b4e632e8b79f1d86276df75925691389 {
	meta:
		aliases = "epoll_wait"
		size = "59"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 00 01 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule waitid_05d2ed8e0a28d02a0cc193bd28135440 {
	meta:
		aliases = "waitid"
		size = "59"
		objfiles = "waitid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 1C 01 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule tee_8c5a26f2a3c9e216e8570e06b5f93ca7 {
	meta:
		aliases = "tee"
		size = "59"
		objfiles = "tee@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 3B 01 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule vmsplice_0ff8ada55d79614be90a00dc0aaa7c11 {
	meta:
		aliases = "__GI_vmsplice, vmsplice"
		size = "59"
		objfiles = "vmsplice@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 3C 01 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_wait4_f19cd2ea4158684f3d7d21cb20087386 {
	meta:
		aliases = "wait4, __GI_wait4"
		size = "59"
		objfiles = "wait4@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 72 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule quotactl_a5b385dde70a74d26b62efc7e5a822f5 {
	meta:
		aliases = "quotactl"
		size = "59"
		objfiles = "quotactl@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 83 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule __syscall_rt_sigaction_084fa09887b12ae86a4bea23fdbd5177 {
	meta:
		aliases = "__syscall_rt_sigaction"
		size = "59"
		objfiles = "__syscall_rt_sigaction@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 AE 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule sendfile_b30f3669ced1e08161e4f99458dc86d7 {
	meta:
		aliases = "sendfile"
		size = "59"
		objfiles = "sendfile@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 BB 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule getxattr_ec6551260cf27595c04635ef501266db {
	meta:
		aliases = "getxattr"
		size = "59"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 E5 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule lgetxattr_c0b3a6126a2c4a5785d0a322a604270d {
	meta:
		aliases = "lgetxattr"
		size = "59"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 E6 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5F 5E 5F C3 }
	condition:
		$pattern
}

rule fgetxattr_5b948ab6f67406debaf413c7285a4659 {
	meta:
		aliases = "fgetxattr"
		size = "59"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 E7 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5E 5E 5F C3 }
	condition:
		$pattern
}

rule sendfile64_67d5b1fde9a1f906ac9c88152705f796 {
	meta:
		aliases = "sendfile64"
		size = "59"
		objfiles = "sendfile64@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 EF 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule epoll_ctl_afc17b5462c75d50f828ab4536b84fa8 {
	meta:
		aliases = "epoll_ctl"
		size = "59"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 FF 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 59 5E 5F C3 }
	condition:
		$pattern
}

rule mq_open_56366f7cb1c8bff2fa9e81ce60d891a2 {
	meta:
		aliases = "mq_open"
		size = "105"
		objfiles = "mq_open@librt.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 14 8B 7C 24 20 8B 4C 24 24 80 3F 2F 74 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 41 F6 C1 40 75 06 31 D2 31 F6 EB 10 8D 44 24 30 8B 54 24 28 89 44 24 10 8B 74 24 2C 47 0F B7 D2 53 89 FB B8 15 01 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 83 C4 14 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_kill_all_threads_fd03fbe526459aa77e66501a1a304177 {
	meta:
		aliases = "pthread_kill_all_threads"
		size = "62"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 89 C6 A1 ?? ?? ?? ?? 53 89 D7 8B 18 EB 10 50 50 56 FF 73 14 E8 ?? ?? ?? ?? 8B 1B 83 C4 10 3B 1D ?? ?? ?? ?? 75 E8 85 FF 74 0E 51 51 56 FF 73 14 E8 ?? ?? ?? ?? 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_memmove_ad78593e4bf89b0547145e77f94ba18f {
	meta:
		aliases = "memmove, __GI_memmove"
		size = "39"
		objfiles = "memmove@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 44 24 0C 8B 74 24 10 8B 4C 24 14 39 F0 73 06 89 C7 F3 A4 EB 0C 8D 74 0E FF 8D 7C 08 FF FD F3 A4 FC 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_memcpy_c818e813ab21bd0b0d235e919f913a2f {
	meta:
		aliases = "memcpy, __GI_memcpy"
		size = "39"
		objfiles = "memcpy@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 44 24 14 8B 74 24 10 89 C1 8B 7C 24 0C C1 E9 02 F3 A5 A8 02 74 02 66 A5 A8 01 74 01 A4 8B 44 24 0C 5E 5F C3 }
	condition:
		$pattern
}

rule strncmp_aea55172a8fbe75e3f4316664e505052 {
	meta:
		aliases = "__GI_strncmp, strncmp"
		size = "37"
		objfiles = "strncmp@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 74 24 0C 8B 7C 24 10 8B 4C 24 14 41 49 74 08 AC AE 75 08 84 C0 75 F5 31 C0 EB 04 19 C0 0C 01 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_strcmp_124e63b6cd601cb0633c0125291d4f19 {
	meta:
		aliases = "strcmp, strcoll, __GI_strcoll, __GI_strcmp"
		size = "29"
		objfiles = "strcmp@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 74 24 0C 8B 7C 24 10 AC AE 75 08 84 C0 75 F8 31 C0 EB 04 19 C0 0C 01 5E 5F C3 }
	condition:
		$pattern
}

rule strcat_13d9dfae57f820c45bb3e84f017ac3e4 {
	meta:
		aliases = "__GI_strcat, strcat"
		size = "31"
		objfiles = "strcat@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 74 24 10 31 C0 83 C9 FF 8B 7C 24 0C F2 AE 4F AC AA 84 C0 75 FA 8B 44 24 0C 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_strncat_b92f09c4c76b5a91294531dea3667ed5 {
	meta:
		aliases = "strncat, __GI_strncat"
		size = "46"
		objfiles = "strncat@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 74 24 10 8B 54 24 14 31 C0 83 C9 FF 8B 7C 24 0C F2 AE 4F 89 D1 41 49 74 08 AC AA 84 C0 75 F7 EB 03 31 C0 AA 8B 44 24 0C 5E 5F C3 }
	condition:
		$pattern
}

rule umask_5e611764bd6004aa142baa918756405d {
	meta:
		aliases = "umask"
		size = "48"
		objfiles = "umask@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 0F B7 7C 24 10 53 89 FB B8 3C 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 0F B7 C7 5A 59 5F C3 }
	condition:
		$pattern
}

rule mq_unlink_7542e80a14e636575852ad98e377a0f6 {
	meta:
		aliases = "mq_unlink"
		size = "90"
		objfiles = "mq_unlink@librt.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 44 24 10 80 38 2F 74 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 39 8D 78 01 53 89 FB B8 16 01 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 85 FF 79 13 E8 ?? ?? ?? ?? 8B 10 83 FA 01 75 02 B2 0D 89 10 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule timer_getoverrun_e058554a74ca5e3747c106d41d6eb3c2 {
	meta:
		aliases = "timer_getoverrun"
		size = "49"
		objfiles = "timer_getoverr@librt.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 44 24 10 8B 78 04 53 89 FB B8 06 01 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule timer_delete_2f43558f145f6f190ff4891c3f53ad36 {
	meta:
		aliases = "timer_delete"
		size = "69"
		objfiles = "timer_delete@librt.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 54 24 10 8B 7A 04 53 89 FB B8 07 01 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0B E8 ?? ?? ?? ?? F7 DF 89 38 EB 04 85 C0 74 05 83 C8 FF EB 0E 83 EC 0C 52 E8 ?? ?? ?? ?? 31 C0 83 C4 10 5A 59 5F C3 }
	condition:
		$pattern
}

rule __libc_close_f025c519eafd74bdf8d4609e75bf04a4 {
	meta:
		aliases = "close, __GI_close, __libc_close"
		size = "46"
		objfiles = "close@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 06 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule __GI_unlink_0cb820b3134c5b51acea994c05232cae {
	meta:
		aliases = "unlink, __GI_unlink"
		size = "46"
		objfiles = "unlink@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 0A 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule __GI_chdir_3e1835a7199d1b4f03b4820dc866e71c {
	meta:
		aliases = "chdir, __GI_chdir"
		size = "46"
		objfiles = "chdir@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 0C 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule __GI_time_2f1df178fb5ced708779f9c80024a7bd {
	meta:
		aliases = "time, __GI_time"
		size = "46"
		objfiles = "time@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 0D 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule umount_da2c58ed2db40919dfcf7468710e2971 {
	meta:
		aliases = "umount"
		size = "46"
		objfiles = "umount@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 16 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule stime_77f1541a557f603e01065b7c24f9178d {
	meta:
		aliases = "stime"
		size = "46"
		objfiles = "stime@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 19 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule alarm_865bd3d9917822e0bc378f956373b011 {
	meta:
		aliases = "__GI_alarm, alarm"
		size = "46"
		objfiles = "alarm@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 1B 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule nice_bb6ec2626d6c8337259b63d2d60894b1 {
	meta:
		aliases = "nice"
		size = "66"
		objfiles = "nice@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 22 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0B E8 ?? ?? ?? ?? F7 DF 89 38 EB 04 85 C0 74 05 83 C8 FF EB 0E 57 57 6A 00 6A 00 E8 ?? ?? ?? ?? 83 C4 10 5A 59 5F C3 }
	condition:
		$pattern
}

rule __GI_rmdir_18d8ef251eec0cd54eff72af325ed740 {
	meta:
		aliases = "rmdir, __GI_rmdir"
		size = "46"
		objfiles = "rmdir@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 28 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule dup_92ac0606a707111d6221ff6405d110f0 {
	meta:
		aliases = "dup"
		size = "46"
		objfiles = "dup@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 29 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule __GI_pipe_11450804b95a038606daff666c2fcaa2 {
	meta:
		aliases = "pipe, __GI_pipe"
		size = "46"
		objfiles = "pipe@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 2A 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule __GI_times_17de4551b79eb1b6bec992c6e7d78825 {
	meta:
		aliases = "times, __GI_times"
		size = "46"
		objfiles = "times@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 2B 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule acct_325b4f0a3e3f515ff700bffe1736eb6b {
	meta:
		aliases = "acct"
		size = "46"
		objfiles = "acct@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 33 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule chroot_7f13c8e1e8d3ea8f5c891a3231b770d1 {
	meta:
		aliases = "chroot"
		size = "46"
		objfiles = "chroot@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 3D 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule iopl_176564d5a815531b10fec05597709045 {
	meta:
		aliases = "iopl"
		size = "46"
		objfiles = "iopl@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 6E 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule swapoff_b34d6148ea9de87150d1e01ee72f5dad {
	meta:
		aliases = "swapoff"
		size = "46"
		objfiles = "swapoff@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 73 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule sysinfo_9fcc8fe5cfe130c34980b1e36e076f9c {
	meta:
		aliases = "sysinfo"
		size = "46"
		objfiles = "sysinfo@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 74 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule __libc_fsync_0ec62e0241dfb1a141f32a691cb6ebf5 {
	meta:
		aliases = "fsync, __libc_fsync"
		size = "46"
		objfiles = "fsync@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 76 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule __GI_uname_7e66b1637da67ceef6bb5036a6a72cd1 {
	meta:
		aliases = "uname, __GI_uname"
		size = "46"
		objfiles = "uname@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 7A 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule ntp_adjtime_df2913791bdd2249948e5a92539887fe {
	meta:
		aliases = "adjtimex, __GI_adjtimex, ntp_adjtime"
		size = "46"
		objfiles = "adjtimex@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 7C 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule get_kernel_syms_d2581edc873946e8fdb937154550fff7 {
	meta:
		aliases = "get_kernel_syms"
		size = "46"
		objfiles = "get_kernel_syms@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 82 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule getpgid_13811cfff7633cc2a3700ad7f437e1eb {
	meta:
		aliases = "getpgid"
		size = "46"
		objfiles = "getpgid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 84 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule fchdir_5e7063a5cc28abfeffea4f32833f470c {
	meta:
		aliases = "__GI_fchdir, fchdir"
		size = "46"
		objfiles = "fchdir@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 85 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule personality_78bb0dfee8f9340842ddde106cd4622c {
	meta:
		aliases = "personality"
		size = "46"
		objfiles = "personality@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 88 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule __GI_getsid_2e9affb63995f7d667a0ec2e8fd43f6b {
	meta:
		aliases = "getsid, __GI_getsid"
		size = "46"
		objfiles = "getsid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 93 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule fdatasync_c0a518c86e2f607cd4f2def74fec78a1 {
	meta:
		aliases = "fdatasync"
		size = "46"
		objfiles = "fdatasync@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 94 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule mlockall_5668ea53a4948439d4de63d08dfa458d {
	meta:
		aliases = "mlockall"
		size = "46"
		objfiles = "mlockall@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 98 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule sched_getscheduler_4de9fe64bfe6efa6afd47397a9295290 {
	meta:
		aliases = "sched_getscheduler"
		size = "46"
		objfiles = "sched_getscheduler@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 9D 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule sched_get_priority_max_277c3da45c12b0706875a83aeff869b0 {
	meta:
		aliases = "sched_get_priority_max"
		size = "46"
		objfiles = "sched_get_priority_max@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 9F 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule sched_get_priority_min_170d783114462b8457892243c1f4a88e {
	meta:
		aliases = "sched_get_priority_min"
		size = "46"
		objfiles = "sched_get_priority_min@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 A0 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule setuid_8c4895fe2779032e89a74f8053656485 {
	meta:
		aliases = "setuid"
		size = "46"
		objfiles = "setuid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 D5 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule setgid_dcb4e8aa06972e4ffe74166782435571 {
	meta:
		aliases = "setgid"
		size = "46"
		objfiles = "setgid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 D6 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule setfsuid_92e5e96bed8da754111e4bfd7e5647b3 {
	meta:
		aliases = "setfsuid"
		size = "46"
		objfiles = "setfsuid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 D7 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule setfsgid_ce7763748c07756ca45f52d67b5165b5 {
	meta:
		aliases = "setfsgid"
		size = "46"
		objfiles = "setfsgid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 D8 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule epoll_create_0968f22ddbf1a24e14744410999d466a {
	meta:
		aliases = "epoll_create"
		size = "46"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 FE 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5F 5A 5F C3 }
	condition:
		$pattern
}

rule __libc_read_4b71412f99e38164268c73d285ab1ab4 {
	meta:
		aliases = "__GI_read, read, __libc_read"
		size = "54"
		objfiles = "read@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 03 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule __GI_write_51590a204e0c66e1f13d97d6a14da6be {
	meta:
		aliases = "__libc_write, write, __GI_write"
		size = "54"
		objfiles = "write@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 04 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule execve_ba8eda44e57e16a331feb9810501bc14 {
	meta:
		aliases = "__GI_execve, execve"
		size = "54"
		objfiles = "execve@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 0B 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule __GI_lseek_b165ac9f0383693c824852ed6c2fea69 {
	meta:
		aliases = "__libc_lseek, lseek, __GI___libc_lseek, __GI_lseek"
		size = "54"
		objfiles = "lseek@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 13 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule mq_setattr_032460859c946605f1509955db9e7e48 {
	meta:
		aliases = "__GI_mq_setattr, mq_setattr"
		size = "54"
		objfiles = "mq_getsetattr@librt.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 1A 01 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule inotify_add_watch_6076ac165f3eeaa42a1dd3d5f408141f {
	meta:
		aliases = "inotify_add_watch"
		size = "54"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 24 01 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5F 5A 5F C3 }
	condition:
		$pattern
}

rule readlink_7c717d1f5242d7689584d4992983ffaf {
	meta:
		aliases = "__GI_readlink, readlink"
		size = "54"
		objfiles = "readlink@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 55 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule setpriority_bed4e08b68b4c5d7582988c1a534eddc {
	meta:
		aliases = "__GI_setpriority, setpriority"
		size = "54"
		objfiles = "setpriority@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 61 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule ioperm_b0fc2dba84914ef3539d8706ed70a180 {
	meta:
		aliases = "ioperm"
		size = "54"
		objfiles = "ioperm@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 65 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule klogctl_c50cec314f7021e491f10144c06c6098 {
	meta:
		aliases = "klogctl"
		size = "54"
		objfiles = "klogctl@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 67 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule __GI_setitimer_b09249f200b7efa749d891618b15bf52 {
	meta:
		aliases = "setitimer, __GI_setitimer"
		size = "54"
		objfiles = "setitimer@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 68 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule modify_ldt_ec60b402f647a75390b7bc78c211571a {
	meta:
		aliases = "modify_ldt"
		size = "54"
		objfiles = "modify_ldt@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 7B 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule mprotect_c261ae93098879a3f4e1decd3d66e163 {
	meta:
		aliases = "mprotect"
		size = "54"
		objfiles = "mprotect@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 7D 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule msync_e577549488c89c72544d3c6d18609ce5 {
	meta:
		aliases = "__libc_msync, msync"
		size = "54"
		objfiles = "msync@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 90 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule __libc_readv_735e2414d0e434e6a0db94065a8bb1fb {
	meta:
		aliases = "readv, __libc_readv"
		size = "54"
		objfiles = "readv@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 91 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule writev_0203f7ace60538f1b04b35eb3e04af85 {
	meta:
		aliases = "__libc_writev, writev"
		size = "54"
		objfiles = "writev@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 92 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule sched_setscheduler_6a5d4c7b0670703a18289ab93655f1fc {
	meta:
		aliases = "sched_setscheduler"
		size = "54"
		objfiles = "sched_setscheduler@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 9C 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule poll_757e1bd210e1381650c2db4adb94a779 {
	meta:
		aliases = "__GI_poll, __libc_poll, poll"
		size = "54"
		objfiles = "poll@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 A8 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule lchown_e36f479d93358a33409b93b635a4b4a3 {
	meta:
		aliases = "lchown"
		size = "54"
		objfiles = "lchown@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 C6 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule fchown_fed0bb50393fe038da38a1a394ebb68a {
	meta:
		aliases = "fchown"
		size = "54"
		objfiles = "fchown@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 CF 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule setresuid_f14d153d5c9a139e9bc045cd6658101c {
	meta:
		aliases = "__GI_setresuid, setresuid"
		size = "54"
		objfiles = "setresuid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 D0 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule getresuid_76953a7cf0d85394dcb23f564f586393 {
	meta:
		aliases = "getresuid"
		size = "54"
		objfiles = "getresuid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 D1 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule setresgid_ced1bf02ab139946dfa0deff09c5b9f1 {
	meta:
		aliases = "__GI_setresgid, setresgid"
		size = "54"
		objfiles = "setresgid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 D2 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule getresgid_7eb0ee30a5b5666a93a9f4c89bcd0183 {
	meta:
		aliases = "getresgid"
		size = "54"
		objfiles = "getresgid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 D3 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule chown_3452e497b9fef1d4207df59b98a791e8 {
	meta:
		aliases = "__GI_chown, chown"
		size = "54"
		objfiles = "chown@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 D4 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule mincore_b2ea7ff4b36e777024e14d62dd259936 {
	meta:
		aliases = "mincore"
		size = "54"
		objfiles = "mincore@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 DA 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule madvise_e6ed3ca53174c11e25ba5906f52a1773 {
	meta:
		aliases = "madvise"
		size = "54"
		objfiles = "madvise@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 DB 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule listxattr_88f8cd6e9f943e5da7c1b0bbdc896ddb {
	meta:
		aliases = "listxattr"
		size = "54"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 E8 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule llistxattr_74db8d3b26e2decc91f9b2ba04778b40 {
	meta:
		aliases = "llistxattr"
		size = "54"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 E9 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 59 5F 5F C3 }
	condition:
		$pattern
}

rule flistxattr_9666509dee20c0152b274b58f685ce64 {
	meta:
		aliases = "flistxattr"
		size = "54"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 EA 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5F 5A 5F C3 }
	condition:
		$pattern
}

rule __GI_ioctl_5db998eb4d85195b5f7b9ce0ce76a72c {
	meta:
		aliases = "ioctl, __GI_ioctl"
		size = "63"
		objfiles = "ioctl@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 18 8D 44 24 2C 8B 7C 24 20 8B 4C 24 24 89 44 24 14 8B 54 24 28 53 89 FB B8 36 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 83 C4 18 5F C3 }
	condition:
		$pattern
}

rule __GI_fcntl64_dac7a519acf3cd3fd904a48f0f206f30 {
	meta:
		aliases = "__libc_fcntl64, __GI___libc_fcntl64, fcntl64, __GI_fcntl64"
		size = "63"
		objfiles = "__syscall_fcntl64@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 18 8D 44 24 2C 8B 7C 24 20 8B 4C 24 24 89 44 24 14 8B 54 24 28 53 89 FB B8 DD 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 83 C4 18 5F C3 }
	condition:
		$pattern
}

rule svc_find_d6e3b33edf5c75a9636eb180e39f5443 {
	meta:
		aliases = "svc_find"
		size = "48"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 89 C7 56 89 CE 53 89 D3 E8 ?? ?? ?? ?? 31 D2 8B 80 B8 00 00 00 EB 0E 39 78 04 75 05 39 58 08 74 08 89 C2 8B 00 85 C0 75 EE 89 16 5B 5E 5F C3 }
	condition:
		$pattern
}

rule memset_4fdeef21c59ed6ad14eaadf1728f8556 {
	meta:
		aliases = "__GI_memset, memset"
		size = "21"
		objfiles = "memset@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 8B 44 24 0C 8B 4C 24 10 8B 7C 24 08 F3 AA 8B 44 24 08 5F C3 }
	condition:
		$pattern
}

rule reboot_de0d407802a39ecc04a0d9116c8dfe66 {
	meta:
		aliases = "reboot"
		size = "56"
		objfiles = "reboot@libc.a"
	strings:
		$pattern = { ( CC | 57 ) B9 69 19 12 28 83 EC 08 BF AD DE E1 FE 8B 54 24 10 53 89 FB B8 58 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule __GI_vfork_8837c96e046fb66dd5409ab00bac5407 {
	meta:
		aliases = "__vfork, vfork, __GI_vfork"
		size = "21"
		objfiles = "vfork@libc.a"
	strings:
		$pattern = { ( CC | 59 ) B8 BE 00 00 00 CD 80 51 3D 01 F0 FF FF 0F 83 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule _dl_linux_resolve_48dc21b5baf82a847c8db41a53b07526 {
	meta:
		aliases = "_dl_linux_resolve"
		size = "26"
		objfiles = "resolve@libdl.a"
	strings:
		$pattern = { ( CC | 60 ) 8D 44 24 20 FF 70 04 FF 30 E8 ?? ?? ?? ?? 89 44 24 28 83 C4 08 61 C2 04 00 }
	condition:
		$pattern
}

rule ether_aton_1765ba9cf3268ad7cd06e17a63193840 {
	meta:
		aliases = "ether_aton"
		size = "17"
		objfiles = "ether_addr@libc.a"
	strings:
		$pattern = { ( CC | 68 ) ?? ?? ?? ?? FF 74 24 08 E8 ?? ?? ?? ?? 59 5A C3 }
	condition:
		$pattern
}

rule sigblock_6c831794e0d4eb591f0ebd72fe6ae513 {
	meta:
		aliases = "__GI_sigblock, sigblock"
		size = "88"
		objfiles = "sigblock@libc.a"
	strings:
		$pattern = { ( CC | 81 ) EC 0C 01 00 00 8B 84 24 10 01 00 00 8D 94 24 90 00 00 00 89 84 24 8C 00 00 00 B8 1E 00 00 00 C7 02 00 00 00 00 83 C2 04 48 79 F4 50 8D 44 24 10 50 8D 84 24 94 00 00 00 50 6A 00 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 04 8B 54 24 0C 89 D0 81 C4 0C 01 00 00 C3 }
	condition:
		$pattern
}

rule __GI_sigsetmask_4ef71a2ddb5b537e4847af68a82e9ab5 {
	meta:
		aliases = "sigsetmask, __GI_sigsetmask"
		size = "88"
		objfiles = "sigsetmask@libc.a"
	strings:
		$pattern = { ( CC | 81 ) EC 0C 01 00 00 8B 84 24 10 01 00 00 8D 94 24 90 00 00 00 89 84 24 8C 00 00 00 B8 1E 00 00 00 C7 02 00 00 00 00 83 C2 04 48 79 F4 50 8D 44 24 10 50 8D 84 24 94 00 00 00 50 6A 02 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 04 8B 54 24 0C 89 D0 81 C4 0C 01 00 00 C3 }
	condition:
		$pattern
}

rule sysv_signal_edffe4b0e17a9e9c601da31ab04f14b2 {
	meta:
		aliases = "__sysv_signal, sysv_signal"
		size = "132"
		objfiles = "sysv_signal@libc.a"
	strings:
		$pattern = { ( CC | 81 ) EC 2C 01 00 00 8B 84 24 34 01 00 00 8B 94 24 30 01 00 00 83 F8 FF 74 09 85 D2 7E 05 83 FA 40 7E 10 E8 ?? ?? ?? ?? 83 CA FF C7 00 16 00 00 00 EB 49 89 84 24 A0 00 00 00 B8 20 00 00 00 EB 0B C7 84 84 A4 00 00 00 00 00 00 00 48 79 F2 C7 84 24 24 01 00 00 00 00 00 E0 50 8D 44 24 18 50 8D 84 24 A8 00 00 00 50 52 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 04 8B 54 24 14 89 D0 81 C4 2C 01 00 00 C3 }
	condition:
		$pattern
}

rule sigignore_c29c880b86ad588ef585ddc4274f48be {
	meta:
		aliases = "sigignore"
		size = "70"
		objfiles = "sigignore@libc.a"
	strings:
		$pattern = { ( CC | 81 ) EC 9C 00 00 00 B8 20 00 00 00 C7 44 24 10 01 00 00 00 EB 08 C7 44 84 14 00 00 00 00 48 79 F5 C7 84 24 94 00 00 00 00 00 00 00 50 6A 00 8D 44 24 18 50 FF B4 24 AC 00 00 00 E8 ?? ?? ?? ?? 81 C4 AC 00 00 00 C3 }
	condition:
		$pattern
}

rule __pthread_manager_sighandler_708bee531596e90e986c1caaeccb8d9c {
	meta:
		aliases = "__pthread_manager_sighandler"
		size = "104"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 81 ) EC AC 00 00 00 31 D2 A1 ?? ?? ?? ?? 85 C0 75 0C 31 D2 83 3D ?? ?? ?? ?? 00 0F 95 C2 C7 05 ?? ?? ?? ?? 01 00 00 00 85 D2 74 36 C7 44 24 18 00 00 00 00 C7 44 24 1C 06 00 00 00 8D 44 24 18 52 68 94 00 00 00 50 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 40 75 0A E8 ?? ?? ?? ?? 83 38 04 74 DA 81 C4 AC 00 00 00 C3 }
	condition:
		$pattern
}

rule ftrylockfile_c8ec7981dc8c7ffca74d62d23a333721 {
	meta:
		aliases = "flockfile, funlockfile, ftrylockfile"
		size = "10"
		objfiles = "flockfile@libc.a, ftrylockfile@libc.a, funlockfile@libc.a"
	strings:
		$pattern = { ( CC | 83 ) 44 24 04 38 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wctob_26cd5e5c08574a4f8fbcc53087ee907a {
	meta:
		aliases = "wctob"
		size = "15"
		objfiles = "wctob@libc.a"
	strings:
		$pattern = { ( CC | 83 ) C8 FF 83 7C 24 04 7F 77 04 8B 44 24 04 C3 }
	condition:
		$pattern
}

rule __compare_and_swap_da6bc935bd94d38c95a233b58433c0c9 {
	meta:
		aliases = "__compare_and_swap"
		size = "27"
		objfiles = "pt_machine@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 8B 54 24 08 8B 4C 24 10 8B 44 24 0C F0 0F B1 0A 0F 94 C1 0F BE C1 5A C3 }
	condition:
		$pattern
}

rule dysize_15d48c80523ddb7caabef0239be11864 {
	meta:
		aliases = "dysize"
		size = "59"
		objfiles = "dysize@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 F6 44 24 08 03 75 2A BA 64 00 00 00 8B 44 24 08 89 D1 99 F7 F9 85 D2 75 11 66 BA 90 01 8B 44 24 08 89 D1 99 F7 F9 85 D2 75 07 B8 6E 01 00 00 EB 05 B8 6D 01 00 00 5A C3 }
	condition:
		$pattern
}

rule wctomb_e118f66e39ccc690f4436ffa6d9bb3f7 {
	meta:
		aliases = "wctomb"
		size = "33"
		objfiles = "wctomb@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 31 C0 8B 54 24 10 85 D2 74 10 50 6A 00 FF 74 24 1C 52 E8 ?? ?? ?? ?? 83 C4 10 83 C4 0C C3 }
	condition:
		$pattern
}

rule __new_sem_destroy_2b71b62e993588949a1ae16b0df41495 {
	meta:
		aliases = "sem_destroy, __new_sem_destroy"
		size = "35"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 31 D2 8B 44 24 10 83 78 0C 00 74 0E E8 ?? ?? ?? ?? 83 CA FF C7 00 10 00 00 00 89 D0 83 C4 0C C3 }
	condition:
		$pattern
}

rule __old_sem_destroy_bb52630ad454d99131b4ad0653c6b8f7 {
	meta:
		aliases = "__old_sem_destroy"
		size = "34"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 31 D2 8B 44 24 10 F6 00 01 75 0E E8 ?? ?? ?? ?? 83 CA FF C7 00 10 00 00 00 89 D0 83 C4 0C C3 }
	condition:
		$pattern
}

rule __pthread_manager_event_087b51e5613a5891288a2652aee22514 {
	meta:
		aliases = "__pthread_manager_event"
		size = "39"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 31 D2 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 0C FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 FF 74 24 1C E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clntudp_create_1c85c456333072fe3ebd8195e7a7d766 {
	meta:
		aliases = "__GI_clntudp_create, clntudp_create"
		size = "46"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 68 60 22 00 00 68 60 22 00 00 FF 74 24 2C FF 74 24 2C FF 74 24 2C FF 74 24 2C FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __pthread_once_fork_child_e2bca4cbcfac885af695ea2d8acb50f5 {
	meta:
		aliases = "__pthread_once_fork_child"
		size = "66"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 3D FB FF FF 7F 7F 0A 83 C0 04 A3 ?? ?? ?? ?? EB 0A C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 0C C3 }
	condition:
		$pattern
}

rule mkfifo_517c8a5b49f4f2910edf32b54c7571bb {
	meta:
		aliases = "mkfifo"
		size = "28"
		objfiles = "mkfifo@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 6A 00 6A 00 8B 44 24 1C 80 CC 10 50 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule wait_848edee9a935c6ac0d34b0cf205e4666 {
	meta:
		aliases = "__libc_wait, wait"
		size = "22"
		objfiles = "wait@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 6A 00 6A 00 FF 74 24 18 6A FF E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule setlinebuf_1fc803af3875c734cd6dc73c41c02088 {
	meta:
		aliases = "setlinebuf"
		size = "22"
		objfiles = "setlinebuf@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 6A 00 6A 01 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI_wcstoull_94d3925005c9f6c3778188d300b054a5 {
	meta:
		aliases = "strtoull, __GI_wcstoul, wcstoul, wcstouq, strtoumax, __GI_strtoull, wcstoumax, __GI_strtoul, strtoul, waitpid, wcstoull, strtouq, __libc_waitpid, __GI_waitpid, __GI_wcstoull"
		size = "26"
		objfiles = "wcstoull@libc.a, strtoul@libc.a, strtoull@libc.a, wcstoul@libc.a, waitpid@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 6A 00 FF 74 24 1C FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule wcstoq_da26619b63cd9d4af4cd0f247526cc20 {
	meta:
		aliases = "wcstoll, strtoll, strtoq, wcstol, strtol, __GI_wcstol, __GI_wcstoll, wcstoimax, __GI_strtoll, strtoimax, __GI_strtol, wcstoq"
		size = "26"
		objfiles = "wcstol@libc.a, strtoll@libc.a, strtol@libc.a, wcstoll@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 6A 01 FF 74 24 1C FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule fopen64_6d9960f22b094ae24daeea2b9222c169 {
	meta:
		aliases = "__GI_fopen64, fopen64"
		size = "24"
		objfiles = "fopen64@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 6A FE 6A 00 FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI_fopen_f364830bff6399e8f176c673f485beb3 {
	meta:
		aliases = "fopen, __GI_fopen"
		size = "24"
		objfiles = "fopen@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 6A FF 6A 00 FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __uClibc_init_888b56e92f48d71503167afcf4ef72b3 {
	meta:
		aliases = "__GI___uClibc_init, __uClibc_init"
		size = "64"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 80 3D ?? ?? ?? ?? 00 75 30 B8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01 C7 05 ?? ?? ?? ?? 00 10 00 00 85 C0 74 05 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 85 C0 74 08 83 C4 0C E9 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule __GI___assert_1b84df86489cb640f7f464016a609cb5 {
	meta:
		aliases = "__assert, __GI___assert"
		size = "76"
		objfiles = "__assert@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 80 3D ?? ?? ?? ?? 00 8B 44 24 1C 75 37 C6 05 ?? ?? ?? ?? 01 85 C0 75 05 B8 ?? ?? ?? ?? 52 FF 74 24 14 50 FF 74 24 24 FF 74 24 24 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 20 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule valloc_0af78c501517704be6efe9fe718791e5 {
	meta:
		aliases = "valloc"
		size = "43"
		objfiles = "valloc@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 83 3D ?? ?? ?? ?? 00 75 0A E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 50 50 FF 74 24 18 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI__rpc_dtablesize_3442f6a0d0ea01b7e201c2e2b4e327cf {
	meta:
		aliases = "_rpc_dtablesize, __GI__rpc_dtablesize"
		size = "31"
		objfiles = "rpc_dtablesize@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 83 3D ?? ?? ?? ?? 00 75 0A E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule getusershell_13ef730fd5df2143c31d13cda861c71f {
	meta:
		aliases = "getusershell"
		size = "47"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 83 3D ?? ?? ?? ?? 00 75 0A E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 10 85 D2 74 08 83 C0 04 A3 ?? ?? ?? ?? 89 D0 83 C4 0C C3 }
	condition:
		$pattern
}

rule __initbuf_a50b3cd4d5c9b7f670b71142d5e1bf2e {
	meta:
		aliases = "__initbuf"
		size = "46"
		objfiles = "getservice@libc.a, getproto@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 83 3D ?? ?? ?? ?? 00 75 1E 83 EC 0C 68 8D 10 00 00 E8 ?? ?? ?? ?? 83 C4 10 A3 ?? ?? ?? ?? 85 C0 75 05 E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule __setutent_829ed4cea1d5980a0f5c4827bfb2001c {
	meta:
		aliases = "__setutent"
		size = "156"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 83 3D ?? ?? ?? ?? FF 75 7C 50 50 6A 02 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 A3 ?? ?? ?? ?? 85 C0 79 1B 50 50 6A 00 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 A3 ?? ?? ?? ?? 85 C0 78 30 51 6A 00 6A 01 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 19 83 C8 01 52 50 6A 02 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 16 83 EC 0C C7 05 ?? ?? ?? ?? FF FF FF FF 6A FF E8 ?? ?? ?? ?? EB 10 51 6A 00 6A 00 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __getutent_9e27da1819fd11baec5abb7a4e36163a {
	meta:
		aliases = "__getutent"
		size = "55"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 83 F8 FF 75 07 E8 ?? ?? ?? ?? EB 20 52 68 80 01 00 00 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 10 BA ?? ?? ?? ?? 3D 80 01 00 00 74 02 31 D2 89 D0 83 C4 0C C3 }
	condition:
		$pattern
}

rule __syscall_error_7095d0f450288135e89da6abbfa1fea7 {
	meta:
		aliases = "__syscall_error"
		size = "21"
		objfiles = "__syscall_error@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 89 C2 F7 DA E8 ?? ?? ?? ?? 89 10 83 C8 FF 83 C4 0C C3 }
	condition:
		$pattern
}

rule __GI_getchar_unlocked_c67a0ca2ad15f7d592c3037fc64fded0 {
	meta:
		aliases = "getchar_unlocked, __GI_getchar_unlocked"
		size = "46"
		objfiles = "getchar_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 15 ?? ?? ?? ?? 8B 42 10 3B 42 18 73 09 0F B6 08 40 89 42 10 EB 0E 83 EC 0C 52 E8 ?? ?? ?? ?? 83 C4 10 89 C1 89 C8 83 C4 0C C3 }
	condition:
		$pattern
}

rule putwchar_2460c313e6733c2fbea3a9fcf3f3caa3 {
	meta:
		aliases = "putwchar"
		size = "69"
		objfiles = "putwchar@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 15 ?? ?? ?? ?? 8B 4C 24 10 83 7A 34 00 74 1E 8B 42 10 3B 42 1C 73 0B 88 08 40 0F B6 C9 89 42 10 EB 19 50 50 52 51 E8 ?? ?? ?? ?? EB 09 50 50 52 51 E8 ?? ?? ?? ?? 89 C1 83 C4 10 89 C8 83 C4 0C C3 }
	condition:
		$pattern
}

rule putchar_unlocked_6487ad10238c7291bc760463db2a3721 {
	meta:
		aliases = "putchar_unlocked"
		size = "52"
		objfiles = "putchar_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 15 ?? ?? ?? ?? 8B 4C 24 10 8B 42 10 3B 42 1C 73 0B 88 08 40 0F B6 C9 89 42 10 EB 0E 50 50 52 51 E8 ?? ?? ?? ?? 83 C4 10 89 C1 89 C8 83 C4 0C C3 }
	condition:
		$pattern
}

rule __GI_sysconf_47d67534037f1329c78cb14710c3b484 {
	meta:
		aliases = "sysconf, __GI_sysconf"
		size = "325"
		objfiles = "sysconf@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 10 3D 95 00 00 00 77 11 FF 24 85 ?? ?? ?? ?? B8 01 00 00 00 E9 22 01 00 00 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 E5 00 00 00 B8 00 00 02 00 E9 08 01 00 00 B8 64 00 00 00 E9 FE 00 00 00 B8 00 00 01 00 E9 F4 00 00 00 83 C4 0C E9 ?? ?? ?? ?? B8 06 00 00 00 E9 E2 00 00 00 83 C4 0C E9 ?? ?? ?? ?? B8 00 80 00 00 E9 D0 00 00 00 B8 E8 03 00 00 E9 C6 00 00 00 B8 00 40 00 00 E9 BC 00 00 00 B8 00 10 00 00 E9 B2 00 00 00 B8 F4 01 00 00 E9 A8 00 00 00 B8 08 00 00 00 E9 9E 00 00 00 B8 00 00 00 80 E9 94 00 00 00 B8 00 80 FF FF E9 8A 00 00 00 B8 FF FF 00 00 E9 80 00 00 00 B8 09 00 00 00 EB 79 }
	condition:
		$pattern
}

rule __GI_perror_5687398cbbd7e3d8b697e2b5036cd865 {
	meta:
		aliases = "perror, __GI_perror"
		size = "50"
		objfiles = "perror@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 10 85 C0 74 0A BA ?? ?? ?? ?? 80 38 00 75 07 B8 ?? ?? ?? ?? 89 C2 52 50 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI_endmntent_b733078a1c623ced96b1d762b5e1a021 {
	meta:
		aliases = "endmntent, __GI_endmntent"
		size = "32"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 10 85 C0 74 0C 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 B8 01 00 00 00 83 C4 0C C3 }
	condition:
		$pattern
}

rule ctermid_cefdccd3beca7d1a72543dfe31f3634e {
	meta:
		aliases = "ctermid"
		size = "33"
		objfiles = "ctermid@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 10 85 C0 75 05 B8 ?? ?? ?? ?? 52 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule killpg_3a552397eb60665c97df7828228149dc {
	meta:
		aliases = "killpg"
		size = "43"
		objfiles = "killpg@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 10 85 C0 78 0E F7 D8 89 44 24 10 83 C4 0C E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 83 C4 0C C3 }
	condition:
		$pattern
}

rule fileno_unlocked_70e7b53a80bf10ca8612118c41007002 {
	meta:
		aliases = "__GI_fileno_unlocked, fileno_unlocked"
		size = "32"
		objfiles = "fileno_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 10 8B 40 04 85 C0 79 0E E8 ?? ?? ?? ?? C7 00 09 00 00 00 83 C8 FF 83 C4 0C C3 }
	condition:
		$pattern
}

rule svcunix_stat_b9ef69e5544d5edda93fefab77863149 {
	meta:
		aliases = "svctcp_stat, svcunix_stat"
		size = "44"
		objfiles = "svc_unix@libc.a, svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 10 8B 50 2C 31 C0 83 3A 00 74 17 83 EC 0C 8D 42 08 50 E8 ?? ?? ?? ?? 83 C4 10 83 F8 01 19 C0 83 C0 02 83 C4 0C C3 }
	condition:
		$pattern
}

rule putpwent_80d17a19f3086246022156b4b8657121 {
	meta:
		aliases = "putpwent"
		size = "79"
		objfiles = "putpwent@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 10 8B 54 24 14 85 C0 74 04 85 D2 75 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 28 83 EC 0C FF 70 18 FF 70 14 FF 70 10 FF 70 0C FF 70 08 FF 70 04 FF 30 68 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 30 C1 F8 1F 83 C4 0C C3 }
	condition:
		$pattern
}

rule xdr_netobj_cee6b055bcdff51538596f40be78729a {
	meta:
		aliases = "xdr_netobj"
		size = "30"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 14 68 00 04 00 00 50 83 C0 04 50 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule sigdelset_f657b9531bb3871fec8523f286c72564 {
	meta:
		aliases = "__GI_sigaddset, sigismember, __GI_sigdelset, sigaddset, sigdelset"
		size = "42"
		objfiles = "sigaddset@libc.a, sigdelset@libc.a, sigismem@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 14 85 C0 7E 0D 83 F8 40 7F 08 83 C4 0C E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 83 C4 0C C3 }
	condition:
		$pattern
}

rule __GI_mbrlen_9ca82023638247df2c187a2369ce7e4c {
	meta:
		aliases = "mbrlen, __GI_mbrlen"
		size = "36"
		objfiles = "mbrlen@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 18 85 C0 75 05 B8 ?? ?? ?? ?? 50 FF 74 24 18 FF 74 24 18 6A 00 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __old_sem_init_f69a02c58270ada5c36a05df3deabf3d {
	meta:
		aliases = "__old_sem_init"
		size = "70"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 18 8B 54 24 10 85 C0 79 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 12 83 7C 24 14 00 74 10 E8 ?? ?? ?? ?? C7 00 26 00 00 00 83 C8 FF EB 0F 8D 44 00 01 C7 42 04 00 00 00 00 89 02 31 C0 83 C4 0C C3 }
	condition:
		$pattern
}

rule mbsrtowcs_0bf1db9b392dda6e0e7333922ed6bef4 {
	meta:
		aliases = "__GI_mbsrtowcs, mbsrtowcs"
		size = "43"
		objfiles = "mbsrtowcs@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 1C 85 C0 75 05 B8 ?? ?? ?? ?? 83 EC 0C 50 FF 74 24 28 6A FF FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule cfsetospeed_99dc1f0ad3c37d5dd979b599487804af {
	meta:
		aliases = "__GI_cfsetospeed, cfsetospeed"
		size = "62"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 4C 24 14 8B 54 24 10 F7 C1 F0 EF FF FF 74 1B 8D 81 FF EF FF FF 83 F8 0E 76 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 0C 81 62 08 F0 EF FF FF 09 4A 08 31 C0 83 C4 0C C3 }
	condition:
		$pattern
}

rule cfsetispeed_d5d786648125f2b9b5d7e00941cb746c {
	meta:
		aliases = "__GI_cfsetispeed, cfsetispeed"
		size = "80"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 4C 24 14 8B 54 24 10 F7 C1 F0 EF FF FF 74 1B 8D 81 FF EF FF FF 83 F8 0E 76 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 1E 85 C9 75 08 81 0A 00 00 00 80 EB 10 81 62 08 F0 EF FF FF 81 22 FF FF FF 7F 09 4A 08 31 C0 83 C4 0C C3 }
	condition:
		$pattern
}

rule mblen_80b9722d897e1212d92e282eb43ec5ed {
	meta:
		aliases = "mblen"
		size = "72"
		objfiles = "mblen@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 54 24 10 85 D2 75 0E 31 C0 C7 05 ?? ?? ?? ?? 00 00 00 00 EB 2B 31 C0 80 3A 00 74 24 50 68 ?? ?? ?? ?? FF 74 24 1C 52 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FE 75 0C C7 05 ?? ?? ?? ?? FF FF 00 00 B0 FF 83 C4 0C C3 }
	condition:
		$pattern
}

rule setbuf_96feea50eda9dbfa4d2316fc5be58d36 {
	meta:
		aliases = "setbuf"
		size = "35"
		objfiles = "setbuf@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 54 24 14 68 00 10 00 00 83 FA 01 19 C0 83 E0 02 50 52 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule setlocale_dc6a20ef126a1e84e7cecba721d451a2 {
	meta:
		aliases = "setlocale"
		size = "67"
		objfiles = "setlocale@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 54 24 14 83 7C 24 10 06 77 2F 85 D2 74 24 8A 02 84 C0 74 1E 3C 43 75 06 80 7A 01 00 74 14 50 50 68 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 07 B8 ?? ?? ?? ?? EB 02 31 C0 83 C4 0C C3 }
	condition:
		$pattern
}

rule setbuffer_591634d5dddb42f1c510d90d386b61fe {
	meta:
		aliases = "setbuffer"
		size = "34"
		objfiles = "setbuffer@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 54 24 14 83 FA 01 FF 74 24 18 19 C0 83 E0 02 50 52 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule mbtowc_d09f7dae46b7297921decad2c37cb445 {
	meta:
		aliases = "mbtowc"
		size = "75"
		objfiles = "mbtowc@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 54 24 14 85 D2 75 0E 31 C0 C7 05 ?? ?? ?? ?? 00 00 00 00 EB 2E 31 C0 80 3A 00 74 27 68 ?? ?? ?? ?? FF 74 24 1C 52 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 83 F8 FE 75 0C C7 05 ?? ?? ?? ?? FF FF 00 00 B0 FF 83 C4 0C C3 }
	condition:
		$pattern
}

rule __new_sem_init_5752aeee8aaf132d23299bf3f0bbb33c {
	meta:
		aliases = "sem_init, __new_sem_init"
		size = "80"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 54 24 18 8B 44 24 10 85 D2 79 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 12 83 7C 24 14 00 74 10 E8 ?? ?? ?? ?? C7 00 26 00 00 00 83 C8 FF EB 19 C7 00 00 00 00 00 C7 40 04 00 00 00 00 89 50 08 C7 40 0C 00 00 00 00 31 C0 83 C4 0C C3 }
	condition:
		$pattern
}

rule closelog_intern_f4578de1b3e17ca9670c1eb100ba343d {
	meta:
		aliases = "closelog_intern"
		size = "87"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C A1 ?? ?? ?? ?? 83 F8 FF 74 0C 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 C7 05 ?? ?? ?? ?? FF FF FF FF C6 05 ?? ?? ?? ?? 00 83 7C 24 10 00 75 22 C6 05 ?? ?? ?? ?? 00 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 08 00 00 00 C6 05 ?? ?? ?? ?? FF 83 C4 0C C3 }
	condition:
		$pattern
}

rule setttyent_6b48c7dfe8b625af7cac2807c48ff520 {
	meta:
		aliases = "__GI_setttyent, setttyent"
		size = "78"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C A1 ?? ?? ?? ?? 85 C0 74 0B 83 EC 0C 50 E8 ?? ?? ?? ?? EB 29 51 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 31 D2 A3 ?? ?? ?? ?? 85 C0 74 12 52 52 6A 02 50 E8 ?? ?? ?? ?? BA 01 00 00 00 83 C4 10 89 D0 83 C4 0C C3 }
	condition:
		$pattern
}

rule _rpcdata_d8315762a74d3c5e3dc5446da0e182fd {
	meta:
		aliases = "_rpcdata"
		size = "38"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C A1 ?? ?? ?? ?? 85 C0 75 16 50 50 68 B0 10 00 00 6A 01 E8 ?? ?? ?? ?? 83 C4 10 A3 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule endttyent_c4531f4aeaed9778c569cc08bc7139ac {
	meta:
		aliases = "__GI_endttyent, endttyent"
		size = "51"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C B8 01 00 00 00 8B 15 ?? ?? ?? ?? 85 D2 74 1D 83 EC 0C 52 E8 ?? ?? ?? ?? 83 C4 10 40 0F 95 C0 0F B6 C0 C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 0C C3 }
	condition:
		$pattern
}

rule xdrstdio_putbytes_c83146688b231deae67be2e6e2234a93 {
	meta:
		aliases = "xdrstdio_getbytes, xdrstdio_putbytes"
		size = "49"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C B8 01 00 00 00 8B 54 24 18 85 D2 74 1D 8B 44 24 10 FF 70 0C 6A 01 52 FF 74 24 20 E8 ?? ?? ?? ?? 83 C4 10 48 0F 94 C0 0F B6 C0 83 C4 0C C3 }
	condition:
		$pattern
}

rule cargf_ccc3b2fa51b5a2b62b96aed5abcd2e52 {
	meta:
		aliases = "cargf"
		size = "34"
		objfiles = "cargf@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C D9 44 24 10 6A 00 6A 00 83 EC 08 DD 1C 24 E8 ?? ?? ?? ?? D9 5C 24 18 D9 44 24 18 83 C4 1C C3 }
	condition:
		$pattern
}

rule __fp_range_check_8adae0c519438f57bbd9843015344b85 {
	meta:
		aliases = "__fp_range_check"
		size = "83"
		objfiles = "__fp_range_check@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C DB 6C 24 10 DB 6C 24 1C D9 05 ?? ?? ?? ?? D9 C2 D8 C9 D9 CB DD E3 DF E0 DD DB 9E 75 29 7A 27 D9 EE D9 CB DD EB DF E0 DD DA 9E 7A 02 74 1A DC C9 DA E9 DF E0 9E 7A 02 74 13 E8 ?? ?? ?? ?? C7 00 22 00 00 00 EB 06 DD D8 DD D8 DD D8 83 C4 0C C3 }
	condition:
		$pattern
}

rule svcunix_rendezvous_abort_7b18fb7eb8835737cf1335975f3c258f {
	meta:
		aliases = "svctcp_rendezvous_abort, svcunix_rendezvous_abort"
		size = "8"
		objfiles = "svc_unix@libc.a, svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __raise_a9ef0b92c90e6c96f4b1888939a72f32 {
	meta:
		aliases = "__GI_raise, raise, __raise"
		size = "24"
		objfiles = "raise@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? 52 52 FF 74 24 18 50 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule pthread_testcancel_45323f636125aabd2c8bd781d035a08f {
	meta:
		aliases = "pthread_testcancel"
		size = "38"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? 80 78 42 00 74 14 80 78 40 00 75 0E 50 50 8D 44 24 14 50 6A FF E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule free_mem_65b43250bf55945a353ae8d4300a62f1 {
	meta:
		aliases = "free_mem"
		size = "26"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? 83 EC 0C FF B0 9C 00 00 00 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule on_exit_2485981248c5d6065a1c88f635f02cc9 {
	meta:
		aliases = "on_exit"
		size = "43"
		objfiles = "on_exit@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? 89 C2 83 C8 FF 85 D2 74 16 8B 44 24 10 89 42 04 8B 44 24 14 C7 02 02 00 00 00 89 42 08 31 C0 83 C4 0C C3 }
	condition:
		$pattern
}

rule __pthread_internal_tsd_address_4fb6176c918d2e0a448249852cef3cd2 {
	meta:
		aliases = "__pthread_internal_tsd_address"
		size = "25"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? 89 C2 8B 44 24 10 83 C4 0C 8D 84 82 6C 01 00 00 C3 }
	condition:
		$pattern
}

rule __errno_location_301e38cc2b684e098f76a6fa4cfe1944 {
	meta:
		aliases = "__errno_location"
		size = "15"
		objfiles = "errno@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? 8B 40 44 83 C4 0C C3 }
	condition:
		$pattern
}

rule __h_errno_location_34686d9d02b67124970dd3b629b76657 {
	meta:
		aliases = "__h_errno_location"
		size = "15"
		objfiles = "errno@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? 8B 40 4C 83 C4 0C C3 }
	condition:
		$pattern
}

rule pthread_handle_sigrestart_9143f0b325a2b565bbb90aec7941cb69 {
	meta:
		aliases = "pthread_handle_sigrestart"
		size = "36"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? 8B 54 24 10 89 50 20 8B 40 24 85 C0 74 0A 51 51 6A 01 50 E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule __pthread_internal_tsd_set_4c96a8313dc359cbddc8c410272432b7 {
	meta:
		aliases = "__pthread_internal_tsd_set"
		size = "29"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? 8B 54 24 10 8B 4C 24 14 89 8C 90 6C 01 00 00 31 C0 83 C4 0C C3 }
	condition:
		$pattern
}

rule __pthread_internal_tsd_get_2f2163e797e1ec8f4c93731bb3de47f5 {
	meta:
		aliases = "__pthread_internal_tsd_get"
		size = "23"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? 8B 54 24 10 8B 84 90 6C 01 00 00 83 C4 0C C3 }
	condition:
		$pattern
}

rule setusershell_9b8305e03524586058e616fa6f351c4f {
	meta:
		aliases = "setusershell"
		size = "17"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule __GI___rpc_thread_svc_fdset_3802f0dd16e03932865532be7f69e7e9 {
	meta:
		aliases = "__rpc_thread_svc_fdset, __GI___rpc_thread_svc_fdset"
		size = "28"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 02 89 C2 89 D0 83 C4 0C C3 }
	condition:
		$pattern
}

rule __GI___rpc_thread_createerr_c9ccc3e11a7b5f5010f8182705fada83 {
	meta:
		aliases = "__rpc_thread_createerr, __GI___rpc_thread_createerr"
		size = "32"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 8D 90 80 00 00 00 89 D0 83 C4 0C C3 }
	condition:
		$pattern
}

rule __GI___rpc_thread_svc_pollfd_88d4c94775af3fa47562ae7832bb21e0 {
	meta:
		aliases = "__rpc_thread_svc_pollfd, __GI___rpc_thread_svc_pollfd"
		size = "32"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 8D 90 90 00 00 00 89 D0 83 C4 0C C3 }
	condition:
		$pattern
}

rule __rpc_thread_svc_max_pollfd_3b6c04d5bbccaed47f19d67af3adf01d {
	meta:
		aliases = "__GI___rpc_thread_svc_max_pollfd, __rpc_thread_svc_max_pollfd"
		size = "32"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 8D 90 94 00 00 00 89 D0 83 C4 0C C3 }
	condition:
		$pattern
}

rule sem_open_0a8d7a1b494d521ce13b4f43915d5266 {
	meta:
		aliases = "sem_open"
		size = "20"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? C7 00 26 00 00 00 31 C0 83 C4 0C C3 }
	condition:
		$pattern
}

rule sem_unlink_86bb2750c653e2882ee6698c514ddcbc {
	meta:
		aliases = "sem_close, sem_unlink"
		size = "21"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? C7 00 26 00 00 00 83 C8 FF 83 C4 0C C3 }
	condition:
		$pattern
}

rule endusershell_6b72a0524bbc3e531e186b8f026e96a3 {
	meta:
		aliases = "endusershell"
		size = "22"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 0C C3 }
	condition:
		$pattern
}

rule __rpc_thread_svc_cleanup_34b08eb789ff0f6f89523bdfe9659e7f {
	meta:
		aliases = "__rpc_thread_svc_cleanup"
		size = "40"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C EB 10 51 51 FF 70 08 FF 70 04 E8 ?? ?? ?? ?? 83 C4 10 E8 ?? ?? ?? ?? 8B 80 B8 00 00 00 85 C0 75 E1 83 C4 0C C3 }
	condition:
		$pattern
}

rule putw_cdd955782a8c797da8f017e6a8f1a878 {
	meta:
		aliases = "putw"
		size = "26"
		objfiles = "putw@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C FF 74 24 14 6A 01 6A 04 8D 44 24 1C 50 E8 ?? ?? ?? ?? 83 C4 1C 48 C3 }
	condition:
		$pattern
}

rule exp2_ba99a1a4a68a311e7f6ecc19c80e47b3 {
	meta:
		aliases = "__GI_exp2, exp2"
		size = "27"
		objfiles = "w_exp2@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C FF 74 24 14 FF 74 24 14 68 00 00 00 40 6A 00 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule setenv_4fdd275cf9526350d23714454b085344 {
	meta:
		aliases = "__GI_setenv, setenv"
		size = "26"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C FF 74 24 18 6A 00 FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule getline_c8b2b08b388920c809d9b5f8c41ddeaa {
	meta:
		aliases = "__GI_getline, getline"
		size = "26"
		objfiles = "getline@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C FF 74 24 18 6A 0A FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule fseeko_7ba7d87fac272bbbbb6337a10e4d8ec0 {
	meta:
		aliases = "fseek, __GI_fseek, fseeko"
		size = "27"
		objfiles = "fseeko@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C FF 74 24 18 8B 44 24 18 99 52 50 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule vsprintf_84bca47eb9c9b9870791b88e976ce846 {
	meta:
		aliases = "vsprintf"
		size = "26"
		objfiles = "vsprintf@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C FF 74 24 18 FF 74 24 18 6A FF FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule wait3_1828b34f17923a387c645ea00e28fddd {
	meta:
		aliases = "wait3"
		size = "26"
		objfiles = "wait3@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C FF 74 24 18 FF 74 24 18 FF 74 24 18 6A FF E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule svcudp_create_be65e047c136afb13ba3dffdcef51965 {
	meta:
		aliases = "__GI_svcudp_create, svcudp_create"
		size = "26"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 68 60 22 00 00 68 60 22 00 00 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule sigfillset_acb5dc9774cb18baaabbe1c308214b26 {
	meta:
		aliases = "__GI_sigfillset, sigfillset"
		size = "28"
		objfiles = "sigfillset@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 68 80 00 00 00 68 FF 00 00 00 FF 74 24 1C E8 ?? ?? ?? ?? 31 C0 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI_sigemptyset_ddd66b097091bd74486ae62d891953f6 {
	meta:
		aliases = "sigemptyset, __GI_sigemptyset"
		size = "25"
		objfiles = "sigempty@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 68 80 00 00 00 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? 31 C0 83 C4 1C C3 }
	condition:
		$pattern
}

rule print_and_abort_5a701051e65f98517898b9f9f7c02332 {
	meta:
		aliases = "print_and_abort"
		size = "36"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 01 00 00 00 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule gmtime_75979fcb2575583fee6d93c88e383870 {
	meta:
		aliases = "gmtime"
		size = "28"
		objfiles = "gmtime@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 68 ?? ?? ?? ?? 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule lgamma_6ef4550f4268b481d14e1b0dbb3bef41 {
	meta:
		aliases = "__ieee754_gamma, __GI_strtok, gamma, __GI_lgamma, __GI_gamma, strtok, __ieee754_lgamma, lgamma"
		size = "25"
		objfiles = "e_lgamma@libm.a, w_gamma@libm.a, w_lgamma@libm.a, strtok@libc.a, e_gamma@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 68 ?? ?? ?? ?? FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __opensock_b6abdb18333a581f113cd4bc0daa997e {
	meta:
		aliases = "__opensock"
		size = "40"
		objfiles = "opensock@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 6A 00 6A 02 6A 0A E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 0F 50 6A 00 6A 02 6A 02 E8 ?? ?? ?? ?? 83 C4 10 83 C4 0C C3 }
	condition:
		$pattern
}

rule xdrstdio_setpos_351b00f9a19a0d1e85c56dc2d5124e5c {
	meta:
		aliases = "xdrstdio_setpos"
		size = "30"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 6A 00 FF 74 24 1C 8B 44 24 1C FF 70 0C E8 ?? ?? ?? ?? 83 C4 1C F7 D0 C1 E8 1F C3 }
	condition:
		$pattern
}

rule wcstold_1da02766b2a304b7f969428fc4c15b06 {
	meta:
		aliases = "__GI_strtold, __GI_wcstold, strtold, wcstold"
		size = "22"
		objfiles = "wcstold@libc.a, strtold@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 6A 00 FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule strtof_2ff06c8b56e3ed2678dab280e38803b5 {
	meta:
		aliases = "__GI_strtof, wcstof, __GI_wcstof, strtof"
		size = "49"
		objfiles = "strtof@libc.a, wcstof@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 6A 00 FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? D9 54 24 14 83 EC 10 DB 7C 24 0C D9 44 24 24 DB 3C 24 E8 ?? ?? ?? ?? D9 44 24 24 83 C4 2C C3 }
	condition:
		$pattern
}

rule __libc_tcdrain_ece8572524f4f38470473afe7e0d75d1 {
	meta:
		aliases = "tcdrain, __libc_tcdrain"
		size = "23"
		objfiles = "tcdrain@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 6A 01 68 09 54 00 00 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule rexec_2731b55e540a31b08bc8fbc856a277eb {
	meta:
		aliases = "rexec"
		size = "38"
		objfiles = "rexec@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 6A 02 FF 74 24 2C FF 74 24 2C FF 74 24 2C FF 74 24 2C FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __GI_pthread_attr_getschedpara_dfca650f122af66fec7183124e98e3ea {
	meta:
		aliases = "pthread_attr_getschedparam, __GI_pthread_attr_getschedparam"
		size = "28"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 6A 04 8B 44 24 18 83 C0 08 50 FF 74 24 20 E8 ?? ?? ?? ?? 31 C0 83 C4 1C C3 }
	condition:
		$pattern
}

rule xdr_des_block_281d3f6b14721a1bf43bfa9b5f807fd5 {
	meta:
		aliases = "xdr_des_block"
		size = "22"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 6A 08 FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI_atoi_e6c5c8392e7b41865e74c28a5b36180c {
	meta:
		aliases = "__GI_atol, atoll, atol, atoi, __GI_atoi"
		size = "20"
		objfiles = "atoll@libc.a, atol@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 6A 0A 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __stdio_init_mutex_e8477ce8c8596db1b5d786497a344fa7 {
	meta:
		aliases = "__stdio_init_mutex"
		size = "23"
		objfiles = "_stdio@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 6A 18 68 ?? ?? ?? ?? FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule ptsname_4ae796fa0fd26b2be9b729f3a34f3ec1 {
	meta:
		aliases = "ptsname"
		size = "39"
		objfiles = "ptsname@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 6A 1E 68 ?? ?? ?? ?? FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 BA ?? ?? ?? ?? 85 C0 74 02 31 D2 89 D0 83 C4 0C C3 }
	condition:
		$pattern
}

rule ttyname_29059a276508967c9bf72db143ca7974 {
	meta:
		aliases = "ttyname"
		size = "39"
		objfiles = "ttyname@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 6A 20 68 ?? ?? ?? ?? FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 BA ?? ?? ?? ?? 85 C0 74 02 31 D2 89 D0 83 C4 0C C3 }
	condition:
		$pattern
}

rule strerror_9a1d611ea3b0860357aa95dfa5649b6b {
	meta:
		aliases = "__GI_strerror, strerror"
		size = "28"
		objfiles = "strerror@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 6A 32 68 ?? ?? ?? ?? FF 74 24 1C E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule xdr_wrapstring_e6fb2d0c47c0ef795b266861e39c75f4 {
	meta:
		aliases = "xdr_wrapstring"
		size = "30"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 6A FF FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 85 C0 0F 95 C0 0F B6 C0 83 C4 1C C3 }
	condition:
		$pattern
}

rule clntunix_geterr_1d2023a1cc3b80b213e548aa9924fec8 {
	meta:
		aliases = "clntunix_geterr"
		size = "31"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 8B 44 24 14 8B 40 08 6A 0C 05 84 00 00 00 50 FF 74 24 20 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule clnttcp_geterr_75317976540eb5ad06e6e70b2b04955d {
	meta:
		aliases = "clnttcp_geterr"
		size = "29"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 8B 44 24 14 8B 40 08 6A 0C 83 C0 24 50 FF 74 24 20 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule clntudp_geterr_5bbb55fb131d80d9f11bd68d12fb7fdd {
	meta:
		aliases = "clntudp_geterr"
		size = "29"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 8B 44 24 14 8B 40 08 6A 0C 83 C0 2C 50 FF 74 24 20 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule authunix_marshal_413cda8d79ca47720c31fe7e42dc4b17 {
	meta:
		aliases = "authunix_marshal"
		size = "35"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 8B 44 24 14 8B 4C 24 18 8B 40 24 8B 51 04 FF B0 AC 01 00 00 83 C0 1C 50 51 FF 52 0C 83 C4 1C C3 }
	condition:
		$pattern
}

rule lrand48_r_c7069002931132f2dfc08888133d95bf {
	meta:
		aliases = "drand48_r, mrand48_r, __GI_lrand48_r, lrand48_r"
		size = "22"
		objfiles = "lrand48_r@libc.a, drand48_r@libc.a, mrand48_r@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 8B 44 24 14 FF 74 24 18 50 50 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule inet_makeaddr_2297b7a15e7bba0c9a0100ab54e820e3 {
	meta:
		aliases = "__GI_inet_makeaddr, inet_makeaddr"
		size = "86"
		objfiles = "inet_addr@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 8B 54 24 18 8B 4C 24 14 8B 44 24 1C 83 FA 7F 77 0A C1 E2 18 25 FF FF FF 00 EB 22 81 FA FF FF 00 00 77 0A C1 E2 10 25 FF FF 00 00 EB 10 81 FA FF FF FF 00 77 08 C1 E2 08 25 FF 00 00 00 09 C2 89 54 24 0C 8B 44 24 0C 0F C8 89 01 89 C8 83 C4 10 C2 04 00 }
	condition:
		$pattern
}

rule tcsetpgrp_79bb396ce4563d96f53110f6af775116 {
	meta:
		aliases = "tcsetpgrp"
		size = "26"
		objfiles = "tcsetpgrp@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 8D 44 24 18 50 68 10 54 00 00 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule fegetexcept_bd801f4e58f6024406709586f66fc07e {
	meta:
		aliases = "fegetexcept"
		size = "22"
		objfiles = "fegetexcept@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 9B D9 7C 24 0E 0F B7 44 24 0E F7 D0 83 E0 3D 83 C4 10 C3 }
	condition:
		$pattern
}

rule fedisableexcept_0b823bd366459d2215b696167b9ac17b {
	meta:
		aliases = "fedisableexcept"
		size = "40"
		objfiles = "fedisblxcpt@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 9B D9 7C 24 0E 8B 54 24 14 66 8B 44 24 0E 83 E2 3D 09 C2 66 89 54 24 0E D9 6C 24 0E F7 D0 83 E0 3D 83 C4 10 C3 }
	condition:
		$pattern
}

rule feenableexcept_5210e053cc46d2601c0c1887fb4ccedd {
	meta:
		aliases = "feenableexcept"
		size = "42"
		objfiles = "feenablxcpt@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 9B D9 7C 24 0E 8B 54 24 14 66 8B 44 24 0E 83 E2 3D F7 D2 21 C2 66 89 54 24 0E D9 6C 24 0E F7 D0 83 E0 3D 83 C4 10 C3 }
	condition:
		$pattern
}

rule fesetround_b65cf4b428431b50e31719fe431df7bd {
	meta:
		aliases = "fesetround"
		size = "49"
		objfiles = "fesetround@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 B8 01 00 00 00 8B 54 24 14 F7 C2 FF F3 FF FF 75 19 D9 7C 24 0E 66 8B 44 24 0E 80 E4 F3 09 D0 66 89 44 24 0E D9 6C 24 0E 31 C0 83 C4 10 C3 }
	condition:
		$pattern
}

rule fegetround_5d09321ef96675113212579dc7a14075 {
	meta:
		aliases = "fegetround"
		size = "20"
		objfiles = "fegetround@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 D9 7C 24 0C 8B 44 24 0C 83 C4 10 25 00 0C 00 00 C3 }
	condition:
		$pattern
}

rule fegetexceptflag_113f649375ddc0496a8a08eb8b33e06b {
	meta:
		aliases = "fegetexceptflag"
		size = "32"
		objfiles = "fgetexcptflg@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 DD 7C 24 0E 8B 44 24 18 8B 54 24 14 66 23 44 24 0E 83 E0 3D 66 89 02 31 C0 83 C4 10 C3 }
	condition:
		$pattern
}

rule __GI_execv_92df585bcb680a694716f24b55d276c9 {
	meta:
		aliases = "execv, __GI_execv"
		size = "26"
		objfiles = "execv@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 FF 35 ?? ?? ?? ?? FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule tcflow_45c4d19095b26dc1eda2c2501922787c {
	meta:
		aliases = "tcflow"
		size = "25"
		objfiles = "tcflow@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 FF 74 24 18 68 0A 54 00 00 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule tcflush_acccf3798a3e54f80f515709d5cc118c {
	meta:
		aliases = "tcflush"
		size = "25"
		objfiles = "tcflush@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 FF 74 24 18 68 0B 54 00 00 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule creat64_bb2a987ff4b1e8f90f178160074caed3 {
	meta:
		aliases = "creat, __libc_creat, __libc_creat64, creat64"
		size = "25"
		objfiles = "open@libc.a, creat64@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 FF 74 24 18 68 41 02 00 00 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule gmtime_r_1a2c0490f5b8cdeeb9221e9da900869e {
	meta:
		aliases = "bzero, mq_getattr, gmtime_r"
		size = "22"
		objfiles = "gmtime_r@libc.a, mq_getsetattr@librt.a, bzero@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 FF 74 24 18 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI_fputwc_unlocked_173166608ee9ab184afff2d4ff75d1ae {
	meta:
		aliases = "fputwc_unlocked, putwc_unlocked, __GI_fputwc_unlocked"
		size = "39"
		objfiles = "fputwc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 FF 74 24 18 6A 01 8D 44 24 1C 50 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 74 04 8B 54 24 10 89 D0 83 C4 0C C3 }
	condition:
		$pattern
}

rule scalbnf_312f3131b70190222fba14e3c3defea1 {
	meta:
		aliases = "frexpf, ldexpf, scalbnf"
		size = "34"
		objfiles = "scalbnf@libm.a, ldexpf@libm.a, frexpf@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 FF 74 24 18 D9 44 24 18 83 EC 08 DD 1C 24 E8 ?? ?? ?? ?? D9 5C 24 18 D9 44 24 18 83 C4 1C C3 }
	condition:
		$pattern
}

rule vprintf_207313f1bf35dacd417d7e4d154f43e5 {
	meta:
		aliases = "vwprintf, vscanf, __GI_vscanf, vwscanf, vprintf"
		size = "26"
		objfiles = "vprintf@libc.a, vwscanf@libc.a, vscanf@libc.a, vwprintf@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 FF 74 24 18 FF 74 24 18 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __open_etc_hosts_a0d3bbdd2ef4591fd1ff5b8e9be085f6 {
	meta:
		aliases = "__open_etc_hosts"
		size = "49"
		objfiles = "read_etc_hosts_r@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 14 50 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 C4 0C C3 }
	condition:
		$pattern
}

rule hcreate_dec9bb6027f4362fd7a2fa48e394d09b {
	meta:
		aliases = "srand48, ether_ntoa, inet_ntoa, asctime, __GI_asctime, __GI_inet_ntoa, hcreate"
		size = "21"
		objfiles = "inet_ntoa@libc.a, ether_addr@libc.a, hsearch@libc.a, asctime@libc.a, srand48@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 68 ?? ?? ?? ?? FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule seed48_0ae95ce91e5b77a2d2152eeb67234a6c {
	meta:
		aliases = "localtime, __GI_localtime, seed48"
		size = "26"
		objfiles = "localtime@libc.a, seed48@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 68 ?? ?? ?? ?? FF 74 24 1C E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule msgget_e458b89c26e8a0e1bf2cadb865d78916 {
	meta:
		aliases = "msgget"
		size = "28"
		objfiles = "msgget@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 00 6A 00 6A 00 FF 74 24 28 FF 74 24 28 6A 0D E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule getopt_73d9a2a92ea759c7f11861a497219353 {
	meta:
		aliases = "getopt"
		size = "30"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 00 6A 00 6A 00 FF 74 24 2C FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule setpgrp_721621c23187554cb8fe7355555668f1 {
	meta:
		aliases = "setpgrp"
		size = "16"
		objfiles = "setpgrp@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 00 6A 00 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule semget_873eeff3006c98b86bb16911a218ecae {
	meta:
		aliases = "semget"
		size = "30"
		objfiles = "semget@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 00 6A 00 FF 74 24 28 FF 74 24 28 FF 74 24 28 6A 02 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule shmget_251d76a115608505a3e6f16862c3a27a {
	meta:
		aliases = "shmget"
		size = "30"
		objfiles = "shmget@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 00 6A 00 FF 74 24 28 FF 74 24 28 FF 74 24 28 6A 17 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule shmdt_6fe2a87d75fb3fe145bb7833f2c30d45 {
	meta:
		aliases = "shmdt"
		size = "26"
		objfiles = "shmdt@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 00 FF 74 24 1C 6A 00 6A 00 6A 00 6A 16 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __GI_sigwait_891804856819af3fea19a04e92554394 {
	meta:
		aliases = "__sigwait, sigwait, __GI_sigwait"
		size = "41"
		objfiles = "sigwait@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 89 C2 B8 01 00 00 00 83 FA FF 74 08 8B 44 24 14 89 10 31 C0 83 C4 0C C3 }
	condition:
		$pattern
}

rule mkstemp_6bf719c25f6fbaef08052b0889ae3660 {
	meta:
		aliases = "sigpause, atof, __GI_sigpause, mkstemp"
		size = "18"
		objfiles = "atof@libc.a, mkstemp@libc.a, sigpause@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule semop_4ff30196d89a0596c11eac4e39b97cc6 {
	meta:
		aliases = "semop"
		size = "30"
		objfiles = "semop@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 00 FF 74 24 20 6A 00 FF 74 24 2C FF 74 24 28 6A 01 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule msgsnd_82fb1fc43de364856509119360ead8a0 {
	meta:
		aliases = "msgsnd"
		size = "32"
		objfiles = "msgsnd@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 00 FF 74 24 20 FF 74 24 2C FF 74 24 2C FF 74 24 28 6A 0B E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule msgctl_c784d3b65409928b73e69886a9433989 {
	meta:
		aliases = "msgctl"
		size = "34"
		objfiles = "msgctl@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 00 FF 74 24 24 6A 00 8B 44 24 28 80 CC 01 50 FF 74 24 28 6A 0E E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule shmctl_b38322b8887697e429bb6b94b70c81f6 {
	meta:
		aliases = "shmctl"
		size = "34"
		objfiles = "shmctl@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 00 FF 74 24 24 6A 00 8B 44 24 28 80 CC 01 50 FF 74 24 28 6A 18 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule getopt_long_5d42e09a7d64217d3fc867dd1c125d52 {
	meta:
		aliases = "getopt_long"
		size = "34"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 00 FF 74 24 2C FF 74 24 2C FF 74 24 2C FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule wcwidth_78f03635613bddb9c898623c373dfd21 {
	meta:
		aliases = "wcwidth"
		size = "19"
		objfiles = "wcwidth@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 01 8D 44 24 1C 50 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI_iswalnum_eaca46bf57de9d027c256de54e89e0bb {
	meta:
		aliases = "mkstemp64, iswalnum, timelocal, mktime, __GI_iswalnum"
		size = "18"
		objfiles = "mkstemp64@libc.a, iswalnum@libc.a, mktime@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 01 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule getopt_long_only_a545fbc6bb82e03ece201d1e19058f87 {
	meta:
		aliases = "getopt_long_only"
		size = "34"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 01 FF 74 24 2C FF 74 24 2C FF 74 24 2C FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule iswalpha_44c9108329ea01c01c96bfbe167c0d14 {
	meta:
		aliases = "__GI_iswalpha, iswalpha"
		size = "18"
		objfiles = "iswalpha@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 02 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI_iswblank_12c91398970349ed99af2a374a090970 {
	meta:
		aliases = "iswblank, __GI_iswblank"
		size = "18"
		objfiles = "iswblank@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 03 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule iswcntrl_17abbf6e0cfad2cdc355b0ed43c61f82 {
	meta:
		aliases = "__GI_iswcntrl, iswcntrl"
		size = "18"
		objfiles = "iswcntrl@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 04 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule iswdigit_7720675966c0239ac00d65240257cbfe {
	meta:
		aliases = "__GI_iswdigit, svcerr_weakauth, iswdigit"
		size = "18"
		objfiles = "iswdigit@libc.a, svc@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 05 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule iswgraph_5cf1edafc72fde55f5ce817127416ca1 {
	meta:
		aliases = "__GI_iswgraph, iswgraph"
		size = "18"
		objfiles = "iswgraph@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 06 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule iswlower_811272950758197137b571be4e4a9401 {
	meta:
		aliases = "__GI_iswlower, iswlower"
		size = "18"
		objfiles = "iswlower@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 07 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI_iswprint_aa17969fa700d34c154503a9c1bd3274 {
	meta:
		aliases = "iswprint, __GI_iswprint"
		size = "18"
		objfiles = "iswprint@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 08 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule iswpunct_f01b91b2f7168b88182a0c205db198e3 {
	meta:
		aliases = "__GI_iswpunct, iswpunct"
		size = "18"
		objfiles = "iswpunct@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 09 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule iswspace_8a2d299e515635b593fc10dc69dbc515 {
	meta:
		aliases = "__GI_iswspace, iswspace"
		size = "18"
		objfiles = "iswspace@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 0A FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI_iswupper_2a94a97715b7d870b4e9aaefb774a9a4 {
	meta:
		aliases = "iswupper, __GI_iswupper"
		size = "18"
		objfiles = "iswupper@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 0B FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI_iswxdigit_3a0e6c29b954679706b683ac4d0f3d31 {
	meta:
		aliases = "iswxdigit, __GI_iswxdigit"
		size = "18"
		objfiles = "iswxdigit@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 0C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule pthread_exit_39f92ad3f0513c1dba52111101f0ee78 {
	meta:
		aliases = "__GI_pthread_exit, pthread_exit"
		size = "17"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 8D 44 24 14 50 FF 74 24 1C E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_ldexp_71c1188463d2f115d3a80655f0d4b603 {
	meta:
		aliases = "ldexp, __GI_ldexp"
		size = "125"
		objfiles = "s_ldexp@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 DD 44 24 18 DD 5C 24 08 FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 57 DD 04 24 D9 EE D9 C9 DA E9 DF E0 9E 7A 02 74 47 51 FF 74 24 1C FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? DD 5C 24 10 58 5A FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 10 DD 04 24 D9 EE D9 C9 DA E9 DF E0 9E 75 0D 7A 0B E8 ?? ?? ?? ?? C7 00 22 00 00 00 DD 04 24 83 C4 0C C3 }
	condition:
		$pattern
}

rule __pthread_restart_new_23553472710228b44b3866640c93363f {
	meta:
		aliases = "__pthread_restart_new"
		size = "25"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 FF 35 ?? ?? ?? ?? 8B 44 24 1C FF 70 14 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule putwchar_unlocked_345f9bb7f93a5503c0dea9c2ba4ece7a {
	meta:
		aliases = "putwchar_unlocked"
		size = "22"
		objfiles = "putwchar_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 FF 35 ?? ?? ?? ?? FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule posix_openpt_0f9e16f68c2cfdcfdc9b739892296ac2 {
	meta:
		aliases = "__GI_posix_openpt, posix_openpt"
		size = "21"
		objfiles = "getpt@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 FF 74 24 18 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __length_question_fdc9f36dbd9bfa7adaca9eee68ac31d5 {
	meta:
		aliases = "__length_question"
		size = "30"
		objfiles = "lengthq@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 03 83 C0 04 83 C4 0C C3 }
	condition:
		$pattern
}

rule __GI_verrx_1c97125b3f40865ae46e521e13ed7a6f {
	meta:
		aliases = "verrx, verr, __GI_verr, __GI_verrx"
		size = "26"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 FF 74 24 20 FF 74 24 20 E8 ?? ?? ?? ?? 58 FF 74 24 1C E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule semtimedop_5670cf2deb8ea5192aa67bf4bb262b4d {
	meta:
		aliases = "semtimedop"
		size = "32"
		objfiles = "semtimedop@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 FF 74 24 24 FF 74 24 20 6A 00 FF 74 24 2C FF 74 24 28 6A 04 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule restart_ecd6961fe1548a07e4419cf5eac61cc2 {
	meta:
		aliases = "suspend, restart"
		size = "13"
		objfiles = "rwlock@libpthread.a, spinlock@libpthread.a, pthread@libpthread.a, join@libpthread.a, condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 50 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule hdestroy_07f21806b50c232838a1f6ebf5d39e92 {
	meta:
		aliases = "__pthread_once_fork_parent, getlogin, _flushlbf, __GI_getlogin, __pthread_once_fork_prepare, hdestroy"
		size = "17"
		objfiles = "hsearch@libc.a, _flushlbf@libc.a, getlogin@libc.a, mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule tzset_bcd04f4458945647b09065086156a9cb {
	meta:
		aliases = "__GI_tzset, tzset"
		size = "33"
		objfiles = "tzset@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 6A 00 E8 ?? ?? ?? ?? 3D FF 4E 98 45 0F 9E C0 0F B6 C0 89 04 24 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule siggetmask_d18a200418b3537944a888bec6d146dc {
	meta:
		aliases = "siggetmask"
		size = "14"
		objfiles = "siggetmask@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 6A 00 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __pthread_initialize_minimal_15438525c1a6f0474405ca8d0e4e2a8b {
	meta:
		aliases = "__pthread_initialize_minimal"
		size = "19"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule re_search_2183e4d8f03ca681e9ba33fafe22c649 {
	meta:
		aliases = "__re_search, re_search"
		size = "42"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 8B 44 24 24 50 FF 74 24 34 FF 74 24 34 FF 74 24 34 50 FF 74 24 34 6A 00 6A 00 FF 74 24 3C E8 ?? ?? ?? ?? 83 C4 3C C3 }
	condition:
		$pattern
}

rule re_compile_pattern_f2ef2cf07b7a6e70161fcf829e276db6 {
	meta:
		aliases = "__re_compile_pattern, re_compile_pattern"
		size = "67"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 8B 54 24 24 8A 42 1C 83 E0 E9 83 C8 80 88 42 1C 52 8B 54 24 24 8B 44 24 20 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 74 0D 8B 14 85 ?? ?? ?? ?? 81 C2 ?? ?? ?? ?? 89 D0 83 C4 0C C3 }
	condition:
		$pattern
}

rule __free_initshell_memory_0a61e774b9096f285cb9c6473510cece {
	meta:
		aliases = "__free_initshell_memory"
		size = "50"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 FF 35 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 1C C3 }
	condition:
		$pattern
}

rule getwchar_unlocked_8d2509fbeabb04bc47cf41d0b9e2530e {
	meta:
		aliases = "_dl_app_fini_array, getwchar, _dl_app_init_array, getwchar_unlocked"
		size = "18"
		objfiles = "getwchar_unlocked@libc.a, getwchar@libc.a, libdl@libdl.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI_ctime_24905b5dda7060cf4eb875e8c4bf40ce {
	meta:
		aliases = "ctime, __GI_ctime"
		size = "24"
		objfiles = "ctime@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 FF 74 24 1C E8 ?? ?? ?? ?? 89 44 24 20 83 C4 1C E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wcsrtombs_ce57aba5bc61bf8cfdb2613bdce28092 {
	meta:
		aliases = "__GI_wcsrtombs, wcsrtombs"
		size = "30"
		objfiles = "wcsrtombs@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 FF 74 24 28 FF 74 24 28 6A FF FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __get_hosts_byname_r_91bd0f259fa5b0cd350385f3bba8c771 {
	meta:
		aliases = "__get_hosts_byname_r"
		size = "44"
		objfiles = "get_hosts_byname_r@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 FF 74 24 34 FF 74 24 34 FF 74 24 34 FF 74 24 34 FF 74 24 34 6A 00 FF 74 24 38 FF 74 24 38 6A 00 E8 ?? ?? ?? ?? 83 C4 3C C3 }
	condition:
		$pattern
}

rule __libc_open64_9165478e24a6d5c355c5f08accf4b480 {
	meta:
		aliases = "open64, __GI___libc_open64, __GI_open64, __libc_open64"
		size = "45"
		objfiles = "open64@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 31 C0 8B 54 24 24 F6 C2 40 74 0C 8D 44 24 2C 89 44 24 18 8B 44 24 28 80 CE 80 51 50 52 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule wcstombs_bf27eda4f472de889886876b7730e3eb {
	meta:
		aliases = "wcstombs"
		size = "35"
		objfiles = "wcstombs@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8B 44 24 24 89 44 24 18 6A 00 FF 74 24 2C 8D 44 24 20 50 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule xdrstdio_putlong_f58de9cdea0dd22f0a0a409479faae2a {
	meta:
		aliases = "xdrstdio_putint32, xdrstdio_putlong"
		size = "47"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8B 44 24 24 8D 54 24 18 8B 00 0F C8 89 44 24 18 8B 44 24 20 FF 70 0C 6A 01 6A 04 52 E8 ?? ?? ?? ?? 48 0F 94 C0 0F B6 C0 83 C4 2C C3 }
	condition:
		$pattern
}

rule mbstowcs_09ad7621fd0a992148df8aa2c648140c {
	meta:
		aliases = "mbstowcs"
		size = "46"
		objfiles = "mbstowcs@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8B 44 24 24 C7 44 24 10 00 00 00 00 89 44 24 18 8D 44 24 10 50 FF 74 24 2C 8D 44 24 20 50 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule setrlimit64_9d7e309af59f606ffc3678d2732cbeda {
	meta:
		aliases = "setrlimit64"
		size = "86"
		objfiles = "setrlimit64@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8B 4C 24 24 8B 51 04 8B 01 83 FA 00 77 05 83 F8 FE 76 0A C7 44 24 14 FF FF FF FF EB 04 89 44 24 14 8B 51 0C 8B 41 08 83 FA 00 77 05 83 F8 FE 76 0A C7 44 24 18 FF FF FF FF EB 04 89 44 24 18 50 50 8D 44 24 1C 50 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule xdrstdio_getint32_b0e0e19afb9cd509141511f66b736891 {
	meta:
		aliases = "xdrstdio_getlong, xdrstdio_getint32"
		size = "55"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8B 54 24 20 8D 44 24 18 FF 72 0C 6A 01 6A 04 50 E8 ?? ?? ?? ?? 83 C4 10 31 D2 48 75 11 8B 54 24 24 8B 44 24 18 0F C8 89 02 BA 01 00 00 00 89 D0 83 C4 1C C3 }
	condition:
		$pattern
}

rule getgrent_975d0e0bc0166ffe58a24e49d939ba0d {
	meta:
		aliases = "getspent, getpwent, getgrent"
		size = "36"
		objfiles = "getgrent@libc.a, getspent@libc.a, getpwent@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8D 44 24 18 50 68 00 01 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 28 83 C4 2C C3 }
	condition:
		$pattern
}

rule warnx_89f442b8cc556aa0298d5f44dc23623b {
	meta:
		aliases = "warn, warnx"
		size = "27"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8D 44 24 24 89 44 24 18 51 51 50 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule wprintf_84203de9a76a1350b67c27a76abfb69a {
	meta:
		aliases = "wscanf, __GI_printf, scanf, printf, wprintf"
		size = "32"
		objfiles = "wprintf@libc.a, scanf@libc.a, printf@libc.a, wscanf@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8D 44 24 24 89 44 24 18 52 50 FF 74 24 28 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __GI_sprintf_41fec4642f4d9a0c14e4c2b512a44fe9 {
	meta:
		aliases = "sprintf, __GI_sprintf"
		size = "31"
		objfiles = "sprintf@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8D 44 24 28 89 44 24 18 50 FF 74 24 28 6A FF FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule err_dcce67024a6ef6d0ef2d8cceb00297d8 {
	meta:
		aliases = "errx, err"
		size = "26"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8D 44 24 28 89 44 24 18 52 50 FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sscanf_b8d2de1a3389a9ac7063fcf8ecd732a9 {
	meta:
		aliases = "fscanf, __GI_fprintf, asprintf, __GI_fscanf, fwscanf, syslog, fwprintf, __GI_sscanf, dprintf, __GI_syslog, __GI_asprintf, swscanf, fprintf, sscanf"
		size = "30"
		objfiles = "fwscanf@libc.a, fwprintf@libc.a, syslog@libc.a, asprintf@libc.a, fprintf@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8D 44 24 28 89 44 24 18 52 50 FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule snprintf_8bd6d358af3d92600852784dc3535348 {
	meta:
		aliases = "__GI_snprintf, swprintf, snprintf"
		size = "33"
		objfiles = "snprintf@libc.a, swprintf@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8D 44 24 2C 89 44 24 18 50 FF 74 24 2C FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule semctl_6b0963c867093d2481450cfaa2fc639a {
	meta:
		aliases = "semctl"
		size = "55"
		objfiles = "semctl@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8D 44 24 30 89 44 24 14 8B 44 24 2C 89 44 24 18 50 50 6A 00 8D 44 24 24 50 8B 44 24 38 80 CC 01 50 FF 74 24 38 FF 74 24 38 6A 03 E8 ?? ?? ?? ?? 83 C4 3C C3 }
	condition:
		$pattern
}

rule lrintf_ae59cb3ea4cc505a336a4a795ec11feb {
	meta:
		aliases = "llrintf, lroundf, llroundf, ilogbf, lrintf"
		size = "19"
		objfiles = "ilogbf@libm.a, lrintf@libm.a, llrintf@libm.a, llroundf@libm.a, lroundf@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C D9 44 24 20 DD 1C 24 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule ceilf_a4ed7d1ef71bac89a28737c2f33b4283 {
	meta:
		aliases = "cbrtf, sinhf, fabsf, erfcf, tanf, roundf, atanf, sqrtf, acosf, acoshf, lgammaf, cosf, truncf, erff, asinhf, coshf, floorf, logbf, asinf, atanhf, expf, logf, log1pf, rintf, sinf, tanhf, log10f, expm1f, ceilf"
		size = "27"
		objfiles = "lgammaf@libm.a, floorf@libm.a, asinf@libm.a, expm1f@libm.a, logf@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C D9 44 24 20 DD 1C 24 E8 ?? ?? ?? ?? D9 5C 24 18 D9 44 24 18 83 C4 1C C3 }
	condition:
		$pattern
}

rule hypotf_1e2978707d238f6fac2f7eea075fd954 {
	meta:
		aliases = "remainderf, powf, fmodf, copysignf, nextafterf, atan2f, hypotf"
		size = "35"
		objfiles = "powf@libm.a, fmodf@libm.a, nextafterf@libm.a, atan2f@libm.a, remainderf@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C D9 44 24 24 DD 5C 24 08 D9 44 24 20 DD 1C 24 E8 ?? ?? ?? ?? D9 5C 24 18 D9 44 24 18 83 C4 1C C3 }
	condition:
		$pattern
}

rule getservbyname_16a31ef8f7e62de12459b2fda9de28d5 {
	meta:
		aliases = "__GI_getservbyport, getservbyport, getservbyname"
		size = "52"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C E8 ?? ?? ?? ?? 50 50 8D 44 24 20 50 68 8D 10 00 00 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 3C FF 74 24 3C E8 ?? ?? ?? ?? 8B 44 24 38 83 C4 3C C3 }
	condition:
		$pattern
}

rule gethostbyaddr_98bcb7b3b137c439cb8c40fcca6ee5ac {
	meta:
		aliases = "__GI_gethostbyaddr, gethostbyaddr"
		size = "54"
		objfiles = "gethostbyaddr@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C E8 ?? ?? ?? ?? 50 8D 44 24 1C 50 68 D8 01 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 3C FF 74 24 3C FF 74 24 3C E8 ?? ?? ?? ?? 8B 44 24 38 83 C4 3C C3 }
	condition:
		$pattern
}

rule gethostbyname2_c5a44e902777eb1fdd07eb11965e1e0c {
	meta:
		aliases = "gethostbyname2"
		size = "51"
		objfiles = "gethostbyname2@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C E8 ?? ?? ?? ?? 52 50 8D 44 24 20 50 68 D8 01 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 3C FF 74 24 3C E8 ?? ?? ?? ?? 8B 44 24 38 83 C4 3C C3 }
	condition:
		$pattern
}

rule __GI_gethostbyname_26e7684a2f16b0f611316a12fa264a9b {
	meta:
		aliases = "gethostbyname, __GI_gethostbyname"
		size = "48"
		objfiles = "gethostbyname@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C E8 ?? ?? ?? ?? 52 52 50 8D 44 24 24 50 68 CC 01 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 3C E8 ?? ?? ?? ?? 8B 44 24 38 83 C4 3C C3 }
	condition:
		$pattern
}

rule getprotobynumber_cece215ae69e7eef8eca3b3b36f673a2 {
	meta:
		aliases = "getprotobyname, getprotobynumber"
		size = "49"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C E8 ?? ?? ?? ?? 83 EC 0C 8D 44 24 24 50 68 8D 10 00 00 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 3C E8 ?? ?? ?? ?? 8B 44 24 38 83 C4 3C C3 }
	condition:
		$pattern
}

rule getprotoent_bf7f7e9a3f3e9dc0e68cd2ca6ae9ac32 {
	meta:
		aliases = "getservent, getprotoent"
		size = "42"
		objfiles = "getservice@libc.a, getproto@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C E8 ?? ?? ?? ?? 8D 44 24 18 50 68 8D 10 00 00 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 28 83 C4 2C C3 }
	condition:
		$pattern
}

rule getw_03fac15503baa0b04fc72a0eae46d190 {
	meta:
		aliases = "getw"
		size = "41"
		objfiles = "getw@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C FF 74 24 20 6A 01 6A 04 8D 44 24 24 50 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 74 04 8B 54 24 18 89 D0 83 C4 1C C3 }
	condition:
		$pattern
}

rule clearenv_491b4c8e9212de7f97d3fdb22ac89a84 {
	meta:
		aliases = "clearenv"
		size = "107"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 3B 05 ?? ?? ?? ?? 75 1A 85 C0 74 16 83 EC 0C 50 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 10 50 50 6A 01 C7 05 ?? ?? ?? ?? 00 00 00 00 8D 44 24 18 50 E8 ?? ?? ?? ?? 31 C0 83 C4 2C C3 }
	condition:
		$pattern
}

rule setnetent_e8e33c0347b592015d837b52fa78f42e {
	meta:
		aliases = "__GI_setnetent, setnetent"
		size = "115"
		objfiles = "getnetent@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 75 18 50 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? EB 09 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 7C 24 20 00 74 07 C6 05 ?? ?? ?? ?? 01 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __GI_setprotoent_9529e22ccd3c771c3f9b5a05d73e3e30 {
	meta:
		aliases = "setprotoent, __GI_setprotoent"
		size = "115"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 75 18 51 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? EB 09 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 7C 24 20 00 74 07 C6 05 ?? ?? ?? ?? 01 52 52 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule setservent_76eccaf7c2bd69a2cfcd5649d94a5b4f {
	meta:
		aliases = "__GI_setservent, setservent"
		size = "115"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 75 18 52 52 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? EB 09 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 7C 24 20 00 74 07 C6 05 ?? ?? ?? ?? 01 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __close_nameservers_4bbd4f5403e52f4a44057071dec3b972 {
	meta:
		aliases = "__close_nameservers"
		size = "155"
		objfiles = "closenameservers@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 25 48 83 EC 0C A3 ?? ?? ?? ?? FF 34 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 04 85 ?? ?? ?? ?? 00 00 00 00 A1 ?? ?? ?? ?? 83 C4 10 85 C0 7F CF EB 28 48 83 EC 0C A3 ?? ?? ?? ?? FF 34 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 C7 04 85 ?? ?? ?? ?? 00 00 00 00 A1 ?? ?? ?? ?? 85 C0 7F CF 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __GI_strtod_933c5f43d5ab233ccdd1cdce8fe5644f {
	meta:
		aliases = "strtod, __GI_wcstod, wcstod, __GI_strtod"
		size = "49"
		objfiles = "strtod@libc.a, wcstod@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 6A 00 FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? DD 54 24 18 83 EC 10 DB 7C 24 0C DD 44 24 28 DB 3C 24 E8 ?? ?? ?? ?? DD 44 24 28 83 C4 3C C3 }
	condition:
		$pattern
}

rule __GI_feraiseexcept_b0ab73eac1b5a1fa77dec2ac00c3b2cd {
	meta:
		aliases = "feraiseexcept, __GI_feraiseexcept"
		size = "94"
		objfiles = "fraiseexcpt@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 8B 44 24 24 A8 01 74 07 D9 EE D8 F0 9B DD D8 A8 04 74 09 D9 EE D9 E8 DE F1 9B DD D8 A8 08 74 0F D9 74 24 04 66 83 4C 24 08 08 D9 64 24 04 9B A8 10 74 0F D9 74 24 04 66 83 4C 24 08 10 D9 64 24 04 9B A8 20 74 0F D9 74 24 04 66 83 4C 24 08 20 D9 64 24 04 9B 31 C0 83 C4 20 C3 }
	condition:
		$pattern
}

rule drand48_66ff26d2d33e037c7e60e0154eafbb07 {
	meta:
		aliases = "drand48"
		size = "31"
		objfiles = "drand48@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 8D 44 24 14 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? DD 44 24 20 83 C4 2C C3 }
	condition:
		$pattern
}

rule erand48_4637a1c154b0a5220007e6e060e80b61 {
	meta:
		aliases = "erand48"
		size = "30"
		objfiles = "erand48@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 8D 44 24 14 50 68 ?? ?? ?? ?? FF 74 24 2C E8 ?? ?? ?? ?? DD 44 24 20 83 C4 2C C3 }
	condition:
		$pattern
}

rule modff_f9f1157fbde5b024a240a89660d40af6 {
	meta:
		aliases = "modff"
		size = "45"
		objfiles = "modff@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 8D 44 24 14 50 D9 44 24 28 83 EC 08 DD 1C 24 E8 ?? ?? ?? ?? 8B 44 24 34 DD 44 24 20 D9 18 D9 5C 24 14 D9 44 24 14 83 C4 2C C3 }
	condition:
		$pattern
}

rule __GI_tcgetpgrp_f4401064c54adef256659aa6bcec0c6c {
	meta:
		aliases = "tcgetpgrp, __GI_tcgetpgrp"
		size = "42"
		objfiles = "tcgetpgrp@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 8D 44 24 1C 50 68 0F 54 00 00 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 04 8B 54 24 18 89 D0 83 C4 1C C3 }
	condition:
		$pattern
}

rule lrand48_c2d8da80d32f32540d98b5d5f50bd587 {
	meta:
		aliases = "mrand48, lrand48"
		size = "31"
		objfiles = "mrand48@libc.a, lrand48@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 8D 44 24 1C 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 28 83 C4 2C C3 }
	condition:
		$pattern
}

rule nrand48_b4f49879994ad0f55ed666ca9d4a8004 {
	meta:
		aliases = "jrand48, nrand48"
		size = "30"
		objfiles = "nrand48@libc.a, jrand48@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 8D 44 24 1C 50 68 ?? ?? ?? ?? FF 74 24 2C E8 ?? ?? ?? ?? 8B 44 24 28 83 C4 2C C3 }
	condition:
		$pattern
}

rule tgamma_96393af6e1991ca57572368591bc9b16 {
	meta:
		aliases = "__GI_tgamma, tgamma"
		size = "37"
		objfiles = "w_tgamma@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 8D 44 24 1C 50 FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 83 7C 24 18 00 79 02 D9 E0 83 C4 1C C3 }
	condition:
		$pattern
}

rule feclearexcept_5481d703c16f5fc2554e66b94895b54d {
	meta:
		aliases = "feclearexcept"
		size = "32"
		objfiles = "fclrexcpt@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 D9 74 24 04 8B 44 24 24 83 E0 3D 83 F0 3D 66 21 44 24 08 D9 64 24 04 31 C0 83 C4 20 C3 }
	condition:
		$pattern
}

rule fesetexceptflag_5a21b10f2db8d53dbc700dea54dc65d2 {
	meta:
		aliases = "fesetexceptflag"
		size = "46"
		objfiles = "fsetexcptflg@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 D9 74 24 04 8B 44 24 28 8B 4C 24 24 83 E0 3D 89 C2 F7 D2 66 23 01 23 54 24 08 09 C2 66 89 54 24 08 D9 64 24 04 31 C0 83 C4 20 C3 }
	condition:
		$pattern
}

rule socketpair_3ff7cc89d6e46a7808350997c2a33a29 {
	meta:
		aliases = "socketpair"
		size = "51"
		objfiles = "socketpair@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8B 44 24 28 89 44 24 14 8B 44 24 2C 89 44 24 18 8B 44 24 30 89 44 24 1C 8B 44 24 34 89 44 24 20 8D 44 24 14 50 6A 08 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __libc_send_aa8c351a1548a966f673f917dc1af735 {
	meta:
		aliases = "send, __GI_send, __libc_send"
		size = "51"
		objfiles = "send@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8B 44 24 28 89 44 24 14 8B 44 24 2C 89 44 24 18 8B 44 24 30 89 44 24 1C 8B 44 24 34 89 44 24 20 8D 44 24 14 50 6A 09 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __libc_recv_6ec4911cea1b9f9222b30f8d859d44ff {
	meta:
		aliases = "recv, __GI_recv, __libc_recv"
		size = "51"
		objfiles = "recv@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8B 44 24 28 89 44 24 14 8B 44 24 2C 89 44 24 18 8B 44 24 30 89 44 24 1C 8B 44 24 34 89 44 24 20 8D 44 24 14 50 6A 0A E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule socket_9e10f60359d7d1aadc718a5a248015ea {
	meta:
		aliases = "__GI_socket, socket"
		size = "43"
		objfiles = "socket@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8B 44 24 28 89 44 24 18 8B 44 24 2C 89 44 24 1C 8B 44 24 30 89 44 24 20 8D 44 24 18 50 6A 01 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __GI_bind_6d1ea7ec396d0f9c10cb256f24d761eb {
	meta:
		aliases = "bind, __GI_bind"
		size = "43"
		objfiles = "bind@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8B 44 24 28 89 44 24 18 8B 44 24 2C 89 44 24 1C 8B 44 24 30 89 44 24 20 8D 44 24 18 50 6A 02 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __libc_connect_ba8a3c3562e6535089bbd872abbc9301 {
	meta:
		aliases = "__GI_connect, connect, __libc_connect"
		size = "43"
		objfiles = "connect@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8B 44 24 28 89 44 24 18 8B 44 24 2C 89 44 24 1C 8B 44 24 30 89 44 24 20 8D 44 24 18 50 6A 03 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule accept_681d082753dd4d5bc2087c0f365cb33f {
	meta:
		aliases = "__libc_accept, __GI_accept, accept"
		size = "43"
		objfiles = "accept@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8B 44 24 28 89 44 24 18 8B 44 24 2C 89 44 24 1C 8B 44 24 30 89 44 24 20 8D 44 24 18 50 6A 05 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __GI_getsockname_398e5d068fd58918361146ef3e5cefdf {
	meta:
		aliases = "getsockname, __GI_getsockname"
		size = "43"
		objfiles = "getsockname@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8B 44 24 28 89 44 24 18 8B 44 24 2C 89 44 24 1C 8B 44 24 30 89 44 24 20 8D 44 24 18 50 6A 06 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule getpeername_71b63369faec4fccaf9ab5fa9c90d463 {
	meta:
		aliases = "getpeername"
		size = "43"
		objfiles = "getpeername@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8B 44 24 28 89 44 24 18 8B 44 24 2C 89 44 24 1C 8B 44 24 30 89 44 24 20 8D 44 24 18 50 6A 07 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __libc_sendmsg_1d8d12223f92a0aceb7b64f521572efc {
	meta:
		aliases = "__GI_sendmsg, sendmsg, __libc_sendmsg"
		size = "43"
		objfiles = "sendmsg@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8B 44 24 28 89 44 24 18 8B 44 24 2C 89 44 24 1C 8B 44 24 30 89 44 24 20 8D 44 24 18 50 6A 10 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __libc_recvmsg_7414edcbbe4d5a3ce30b60e65289406d {
	meta:
		aliases = "__GI_recvmsg, recvmsg, __libc_recvmsg"
		size = "43"
		objfiles = "recvmsg@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8B 44 24 28 89 44 24 18 8B 44 24 2C 89 44 24 1C 8B 44 24 30 89 44 24 20 8D 44 24 18 50 6A 11 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule listen_52fed9462e0c70044d975ebc4e489814 {
	meta:
		aliases = "__GI_listen, listen"
		size = "35"
		objfiles = "listen@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8B 44 24 28 89 44 24 1C 8B 44 24 2C 89 44 24 20 8D 44 24 1C 50 6A 04 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule shutdown_cd0327eef5809e239304eaac64cd74d8 {
	meta:
		aliases = "shutdown"
		size = "35"
		objfiles = "shutdown@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8B 44 24 28 89 44 24 1C 8B 44 24 2C 89 44 24 20 8D 44 24 1C 50 6A 0D E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule msgrcv_5a015c7f9e1284296f0a766bbb3b5722 {
	meta:
		aliases = "msgrcv"
		size = "49"
		objfiles = "msgrcv@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8B 44 24 34 89 44 24 20 8B 44 24 2C 89 44 24 1C 6A 00 8D 44 24 20 50 FF 74 24 40 FF 74 24 3C FF 74 24 38 6A 0C E8 ?? ?? ?? ?? 83 C4 3C C3 }
	condition:
		$pattern
}

rule getdtablesize_8afe0c147f3f8960f4b9ad1bb13c07c4 {
	meta:
		aliases = "__GI_getdtablesize, getdtablesize"
		size = "37"
		objfiles = "getdtablesize@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8D 44 24 1C 50 6A 07 E8 ?? ?? ?? ?? 83 C4 10 BA 00 01 00 00 85 C0 78 04 8B 54 24 14 89 D0 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI_inet_addr_faa891ff430f65413742bcb6736e1fe2 {
	meta:
		aliases = "inet_addr, __GI_inet_addr"
		size = "37"
		objfiles = "inet_makeaddr@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8D 44 24 20 50 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 74 04 8B 54 24 18 89 D0 83 C4 1C C3 }
	condition:
		$pattern
}

rule usleep_f4fa512b58f82cb6fb60bac68af42e41 {
	meta:
		aliases = "usleep"
		size = "48"
		objfiles = "usleep@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 BA 40 42 0F 00 89 D1 31 D2 8B 44 24 28 F7 F1 69 D2 E8 03 00 00 89 44 24 1C 89 54 24 20 6A 00 8D 44 24 20 50 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __ieee754_scalb_ab9b01b0160ea489e5b5af1f5eba7a21 {
	meta:
		aliases = "__ieee754_scalb"
		size = "287"
		objfiles = "e_scalb@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 DD 44 24 28 DD 5C 24 10 DD 44 24 30 DD 5C 24 08 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 16 51 51 FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 0C DD 44 24 08 DC 0C 24 E9 D2 00 00 00 52 52 FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 2C D9 EE DD 04 24 DD E1 DF E0 DD D9 9E 76 0B DD 44 24 08 DE C9 E9 A3 00 00 00 DD D8 80 74 24 07 80 DD 44 24 08 DC 34 24 E9 90 00 00 00 50 50 FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 10 DD 04 24 D9 C9 DD E9 DF E0 9E 7A 02 74 08 D9 C0 DE E1 D8 F0 EB 68 DD D8 D9 05 ?? ?? ?? ?? DD 04 24 DA E9 DF E0 9E 76 0A C7 44 24 }
	condition:
		$pattern
}

rule __GI_fdim_895ace5b42b4f092ca23678449673006 {
	meta:
		aliases = "fdim, __GI_fdim"
		size = "81"
		objfiles = "s_fdim@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 DD 44 24 28 DD 5C 24 18 DD 44 24 30 DD 5C 24 10 FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 83 F8 01 77 08 D9 05 ?? ?? ?? ?? EB 1D DD 44 24 10 DD 44 24 08 D9 C9 DA E9 DF E0 9E 77 04 D9 EE EB 08 DD 44 24 10 DC 64 24 08 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI_fmin_6ca034e026af154983dabd778fae594d {
	meta:
		aliases = "fmin, __GI_fmin"
		size = "94"
		objfiles = "s_fmin@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 DD 44 24 28 DD 5C 24 18 DD 44 24 30 DD 5C 24 10 FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 2F 50 50 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 11 DD 44 24 08 DD 44 24 10 D9 C9 DA E9 DF E0 9E 77 08 DD 44 24 08 DD 5C 24 10 DD 44 24 10 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI_fmax_c165e180ed91f7f76a01f497ceb45b4d {
	meta:
		aliases = "fmax, __GI_fmax"
		size = "94"
		objfiles = "s_fmax@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 DD 44 24 28 DD 5C 24 18 DD 44 24 30 DD 5C 24 10 FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 2F 50 50 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 11 DD 44 24 10 DD 44 24 08 D9 C9 DA E9 DF E0 9E 77 08 DD 44 24 08 DD 5C 24 10 DD 44 24 10 83 C4 1C C3 }
	condition:
		$pattern
}

rule hsearch_3d53ee1e779b62ca34769545fe2cbc81 {
	meta:
		aliases = "hsearch"
		size = "38"
		objfiles = "hsearch@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 28 68 ?? ?? ?? ?? 8D 44 24 28 50 FF 74 24 3C FF 74 24 3C FF 74 24 3C E8 ?? ?? ?? ?? 8B 44 24 38 83 C4 3C C3 }
	condition:
		$pattern
}

rule clock_77b53b920fba9feb56df5b96b3d45a18 {
	meta:
		aliases = "clock"
		size = "36"
		objfiles = "clock@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 28 8D 44 24 18 50 E8 ?? ?? ?? ?? 8B 44 24 20 03 44 24 1C 83 C4 2C 69 C0 10 27 00 00 25 FF FF FF 7F C3 }
	condition:
		$pattern
}

rule fgetspent_a7773e5d3145ef4863b1ee448a617097 {
	meta:
		aliases = "fgetpwent, sgetspent, getgrnam, getspnam, getpwnam, getpwuid, getgrgid, fgetgrent, fgetspent"
		size = "40"
		objfiles = "sgetspent@libc.a, getgrnam@libc.a, fgetgrent@libc.a, getpwuid@libc.a, getpwnam@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 28 8D 44 24 24 50 68 00 01 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 3C E8 ?? ?? ?? ?? 8B 44 24 38 83 C4 3C C3 }
	condition:
		$pattern
}

rule feupdateenv_485b86573a53c4e812aaf102ca988eaf {
	meta:
		aliases = "feupdateenv"
		size = "40"
		objfiles = "feupdateenv@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 28 DD 7C 24 26 66 83 64 24 26 3D FF 74 24 2C E8 ?? ?? ?? ?? 58 0F B7 44 24 26 50 E8 ?? ?? ?? ?? 31 C0 83 C4 2C C3 }
	condition:
		$pattern
}

rule __GI_wcrtomb_a8a7887b59cc35af75c40ad93c93c3f8 {
	meta:
		aliases = "wcrtomb, __GI_wcrtomb"
		size = "68"
		objfiles = "wcrtomb@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 2C 8B 54 24 30 8B 4C 24 34 85 D2 75 06 8D 54 24 14 31 C9 8D 44 24 28 89 4C 24 28 89 44 24 24 83 EC 0C FF 74 24 44 6A 10 6A 01 8D 44 24 3C 50 52 E8 ?? ?? ?? ?? 83 C4 20 85 C0 75 02 B0 01 83 C4 2C C3 }
	condition:
		$pattern
}

rule feholdexcept_5a552e6f9e0b06b947bbf30fe2b08a5d {
	meta:
		aliases = "feholdexcept"
		size = "46"
		objfiles = "feholdexcpt@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 2C D9 74 24 10 8D 44 24 10 52 6A 1C 50 FF 74 24 3C E8 ?? ?? ?? ?? 66 83 4C 24 20 3F 66 83 64 24 24 C0 D9 64 24 20 31 C0 83 C4 3C C3 }
	condition:
		$pattern
}

rule ualarm_baedc581ed9d3d338099316b50282647 {
	meta:
		aliases = "ualarm"
		size = "80"
		objfiles = "ualarm@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 30 8B 44 24 38 C7 44 24 10 00 00 00 00 89 44 24 14 8B 44 24 34 89 44 24 1C 8D 44 24 20 C7 44 24 18 00 00 00 00 50 8D 44 24 14 50 6A 00 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 0C 69 54 24 24 40 42 0F 00 03 54 24 28 89 D0 83 C4 2C C3 }
	condition:
		$pattern
}

rule __libc_sendto_410aaa21bf82c35acb5a8f5810fb2da5 {
	meta:
		aliases = "__GI_sendto, sendto, __libc_sendto"
		size = "67"
		objfiles = "sendto@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 34 8B 44 24 38 89 44 24 1C 8B 44 24 3C 89 44 24 20 8B 44 24 40 89 44 24 24 8B 44 24 44 89 44 24 28 8B 44 24 48 89 44 24 2C 8B 44 24 4C 89 44 24 30 8D 44 24 1C 50 6A 0B E8 ?? ?? ?? ?? 83 C4 3C C3 }
	condition:
		$pattern
}

rule __libc_recvfrom_8c80a4f60bdf4fd190baf2fce61d61bf {
	meta:
		aliases = "__GI_recvfrom, recvfrom, __libc_recvfrom"
		size = "67"
		objfiles = "recvfrom@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 34 8B 44 24 38 89 44 24 1C 8B 44 24 3C 89 44 24 20 8B 44 24 40 89 44 24 24 8B 44 24 44 89 44 24 28 8B 44 24 48 89 44 24 2C 8B 44 24 4C 89 44 24 30 8D 44 24 1C 50 6A 0C E8 ?? ?? ?? ?? 83 C4 3C C3 }
	condition:
		$pattern
}

rule setsockopt_dfb7f4a8f0b61da6fa6e27b5772cfcc0 {
	meta:
		aliases = "__GI_setsockopt, setsockopt"
		size = "59"
		objfiles = "setsockopt@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 34 8B 44 24 38 89 44 24 20 8B 44 24 3C 89 44 24 24 8B 44 24 40 89 44 24 28 8B 44 24 44 89 44 24 2C 8B 44 24 48 89 44 24 30 8D 44 24 20 50 6A 0E E8 ?? ?? ?? ?? 83 C4 3C C3 }
	condition:
		$pattern
}

rule getsockopt_189d892cce55ebd35a1d7d94a0965a3d {
	meta:
		aliases = "getsockopt"
		size = "59"
		objfiles = "getsockopt@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 34 8B 44 24 38 89 44 24 20 8B 44 24 3C 89 44 24 24 8B 44 24 40 89 44 24 28 8B 44 24 44 89 44 24 2C 8B 44 24 48 89 44 24 30 8D 44 24 20 50 6A 0F E8 ?? ?? ?? ?? 83 C4 3C C3 }
	condition:
		$pattern
}

rule xdr_free_aabd1443fd9fe33a1577c1e983c04090 {
	meta:
		aliases = "xdr_free"
		size = "28"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 34 C7 44 24 1C 02 00 00 00 FF 74 24 3C 8D 44 24 20 50 FF 54 24 40 83 C4 3C C3 }
	condition:
		$pattern
}

rule __GI_svcerr_auth_38b2934ac75f82cb31687e04aadea1ef {
	meta:
		aliases = "svcerr_auth, __GI_svcerr_auth"
		size = "55"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 44 8B 44 24 4C 8B 4C 24 48 89 44 24 24 C7 44 24 18 01 00 00 00 C7 44 24 1C 01 00 00 00 C7 44 24 20 01 00 00 00 8B 51 08 8D 44 24 14 50 51 FF 52 0C 83 C4 4C C3 }
	condition:
		$pattern
}

rule ctime_r_7cec4e053e4c6efd6e0056a80c87fe57 {
	meta:
		aliases = "ctime_r"
		size = "33"
		objfiles = "ctime_r@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 44 8D 44 24 18 50 FF 74 24 4C E8 ?? ?? ?? ?? 5A 59 FF 74 24 4C 50 E8 ?? ?? ?? ?? 83 C4 4C C3 }
	condition:
		$pattern
}

rule isatty_e2010327c8c72c43d69a91e098ac602c {
	meta:
		aliases = "__GI_isatty, isatty"
		size = "29"
		objfiles = "isatty@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 54 8D 44 24 18 50 FF 74 24 5C E8 ?? ?? ?? ?? 85 C0 0F 94 C0 0F B6 C0 83 C4 5C C3 }
	condition:
		$pattern
}

rule direxists_189edcc4230a7353de12eb22a39bfcbb {
	meta:
		aliases = "direxists"
		size = "48"
		objfiles = "tempname@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 74 8D 54 24 1C 52 50 E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 75 13 8B 44 24 24 31 D2 25 00 F0 00 00 3D 00 40 00 00 0F 94 C2 89 D0 83 C4 6C C3 }
	condition:
		$pattern
}

rule byte_store_op1_9636c530a5bdf6c36d1e38893bdd7c2a {
	meta:
		aliases = "byte_store_op1"
		size = "12"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 88 ) 4A 01 88 02 C1 F9 08 88 4A 02 C3 }
	condition:
		$pattern
}

rule munge_stream_a38f180d9720851a3896e95d852f3038 {
	meta:
		aliases = "munge_stream"
		size = "19"
		objfiles = "fgetwc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 89 ) 50 08 89 50 0C 89 50 10 89 50 14 89 50 18 89 50 1C C3 }
	condition:
		$pattern
}

rule _promoted_size_f1382f7fd58ef2e09f252298750f8e1d {
	meta:
		aliases = "_promoted_size"
		size = "41"
		objfiles = "_ppfs_parsespec@libc.a"
	strings:
		$pattern = { ( CC | 89 ) C1 BA ?? ?? ?? ?? 83 EA 02 0F BF 02 39 C8 74 08 81 FA ?? ?? ?? ?? 77 EE 81 EA ?? ?? ?? ?? D1 FA 0F B6 82 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __malloc_largebin_index_fe9c6e3c345640aa3758de37cd6e678a {
	meta:
		aliases = "__malloc_largebin_index"
		size = "38"
		objfiles = "malloc@libc.a"
	strings:
		$pattern = { ( CC | 89 ) C2 53 C1 EA 08 89 C3 81 FA FF FF 00 00 B8 5F 00 00 00 77 0F 0F BD C2 8D 48 06 D3 EB 83 E3 03 8D 44 83 20 5B C3 }
	condition:
		$pattern
}

rule __GI_mmap_4e79fd119af355899e568b048df9ce0b {
	meta:
		aliases = "mmap, __GI_mmap"
		size = "27"
		objfiles = "mmap@libc.a"
	strings:
		$pattern = { ( CC | 89 ) DA B8 5A 00 00 00 8D 5C 24 04 CD 80 89 D3 3D 00 F0 FF FF 0F 87 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __pthread_find_self_72a60145a432932cb4a0d1e15c2e7706 {
	meta:
		aliases = "__pthread_find_self"
		size = "25"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 89 ) E1 BA ?? ?? ?? ?? EB 03 83 C2 10 8B 42 08 39 C1 77 F6 3B 4A 0C 72 F1 C3 }
	condition:
		$pattern
}

rule thread_self_e74c8f77ff3f89dbea0e2d9a5b4c5494 {
	meta:
		aliases = "thread_self"
		size = "63"
		objfiles = "rwlock@libpthread.a, signals@libpthread.a, mutex@libpthread.a, cancel@libpthread.a, spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 89 ) E2 B8 ?? ?? ?? ?? 3B 25 ?? ?? ?? ?? 73 2F 3B 25 ?? ?? ?? ?? 72 0D B8 ?? ?? ?? ?? 3B 25 ?? ?? ?? ?? 72 1A 83 3D ?? ?? ?? ?? 00 74 05 E9 ?? ?? ?? ?? 81 CA FF FF 1F 00 8D 82 21 FE FF FF C3 }
	condition:
		$pattern
}

rule __libc_allocate_rtsig_af3222989d73d6f06d2bf8ea75c1c891 {
	meta:
		aliases = "__libc_allocate_rtsig"
		size = "56"
		objfiles = "pthread@libpthread.a, allocrtsig@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 0D ?? ?? ?? ?? 83 F9 FF 74 27 8B 15 ?? ?? ?? ?? 39 D1 7F 1D 83 7C 24 04 00 74 0A 8D 41 01 A3 ?? ?? ?? ?? EB 0F 8D 42 FF 89 D1 A3 ?? ?? ?? ?? EB 03 83 C9 FF 89 C8 C3 }
	condition:
		$pattern
}

rule dlerror_cc6ce66afae3e16b02286f75b476e629 {
	meta:
		aliases = "dlerror"
		size = "30"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 8B ) 15 ?? ?? ?? ?? 31 C0 85 D2 74 11 8B 04 95 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 C3 }
	condition:
		$pattern
}

rule _dl_unmap_cache_ab6f9b22be6b305a2f5d72ffbf9e560b {
	meta:
		aliases = "_dl_unmap_cache"
		size = "63"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 8B ) 15 ?? ?? ?? ?? 83 C9 FF 8D 42 FF 83 F8 FD 77 2B 8B 0D ?? ?? ?? ?? 87 D3 B8 5B 00 00 00 CD 80 87 D3 3D 00 F0 FF FF 76 07 F7 D8 A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 31 C9 89 C8 C3 }
	condition:
		$pattern
}

rule __get_pc_thunk_bx_37f86caa53dde6570f57a89c5dd1662f {
	meta:
		aliases = "__get_pc_thunk_bx"
		size = "4"
		objfiles = "crti, crtn"
	strings:
		$pattern = { ( CC | 8B ) 1C 24 C3 }
	condition:
		$pattern
}

rule __flbf_cb729161db8025af83533ec7547101d2 {
	meta:
		aliases = "__flbf"
		size = "13"
		objfiles = "__flbf@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 0F B7 00 25 00 01 00 00 C3 }
	condition:
		$pattern
}

rule feof_unlocked_96dbdeeff5ca93546c03885036c15e24 {
	meta:
		aliases = "feof_unlocked"
		size = "11"
		objfiles = "feof_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 0F B7 00 83 E0 04 C3 }
	condition:
		$pattern
}

rule ferror_unlocked_1f50c5b1758efe4cd2b7c20a125c7232 {
	meta:
		aliases = "ferror_unlocked"
		size = "11"
		objfiles = "ferror_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 0F B7 00 83 E0 08 C3 }
	condition:
		$pattern
}

rule __freading_2dcd87d06bd569aa03e239c737089d9e {
	meta:
		aliases = "__freading"
		size = "11"
		objfiles = "__freading@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 0F B7 00 83 E0 23 C3 }
	condition:
		$pattern
}

rule __fwriting_44b2017ecd567b0310b273565e4a1a60 {
	meta:
		aliases = "__fwriting"
		size = "11"
		objfiles = "__fwriting@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 0F B7 00 83 E0 50 C3 }
	condition:
		$pattern
}

rule __freadable_b409fbd107f80c840769d971eed05ef0 {
	meta:
		aliases = "__freadable"
		size = "17"
		objfiles = "__freadable@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 0F B7 00 C1 E8 04 83 F0 01 83 E0 01 C3 }
	condition:
		$pattern
}

rule __fwritable_7051ce874f650c00de6dc0d40cf9fd20 {
	meta:
		aliases = "__fwritable"
		size = "17"
		objfiles = "__fwritable@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 0F B7 00 C1 E8 05 83 F0 01 83 E0 01 C3 }
	condition:
		$pattern
}

rule htonl_f0b2ac96b2a9c6535f6815b42030bed8 {
	meta:
		aliases = "ntohl, htonl"
		size = "7"
		objfiles = "ntohl@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 0F C8 C3 }
	condition:
		$pattern
}

rule __signbitf_a28913a857df5a318d19f9ea8d93b380 {
	meta:
		aliases = "__GI___signbitf, __signbitf"
		size = "10"
		objfiles = "s_signbitf@libm.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 25 00 00 00 80 C3 }
	condition:
		$pattern
}

rule __finitef_cccf44cc4b0eebb7dffeb2542f200426 {
	meta:
		aliases = "finitef, __GI___finitef, __finitef"
		size = "18"
		objfiles = "s_finitef@libm.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 25 FF FF FF 7F 2D 00 00 80 7F C1 E8 1F C3 }
	condition:
		$pattern
}

rule __collated_compare_525eddaa88a75303f5129b0dc869561f {
	meta:
		aliases = "__collated_compare"
		size = "47"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 31 C9 8B 10 8B 44 24 08 8B 00 39 C2 74 1A B1 01 85 D2 74 14 83 C9 FF 85 C0 74 0D 89 44 24 08 89 54 24 04 E9 ?? ?? ?? ?? 89 C8 C3 }
	condition:
		$pattern
}

rule _obstack_memory_used_dc2a54c5e95c7cdf24f9cc7ce52a5d51 {
	meta:
		aliases = "_obstack_memory_used"
		size = "27"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 31 C9 8B 50 04 EB 09 8B 02 29 D0 8B 52 04 01 C1 85 D2 75 F3 89 C8 C3 }
	condition:
		$pattern
}

rule __fpurge_c2eb9759c978699911667dd75cf93c50 {
	meta:
		aliases = "__fpurge"
		size = "42"
		objfiles = "__fpurge@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 66 83 20 BC 8B 50 08 89 50 18 89 50 1C 89 50 10 89 50 14 C7 40 28 00 00 00 00 C7 40 2C 00 00 00 00 C6 40 02 00 C3 }
	condition:
		$pattern
}

rule clearerr_unlocked_8c764c7d676ccffde1ff2f2dfe5720bc {
	meta:
		aliases = "clearerr_unlocked"
		size = "9"
		objfiles = "clearerr_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 66 83 20 F3 C3 }
	condition:
		$pattern
}

rule ntohs_abb47f3111edd8b51bf0127264a91b58 {
	meta:
		aliases = "htons, ntohs"
		size = "12"
		objfiles = "ntohl@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 66 C1 C8 08 0F B7 C0 C3 }
	condition:
		$pattern
}

rule cfmakeraw_f2901acc1c88ab3b3519d21239597cc1 {
	meta:
		aliases = "cfmakeraw"
		size = "41"
		objfiles = "cfmakeraw@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 81 60 08 CF FE FF FF 81 20 14 FA FF FF C6 40 17 01 83 60 04 FE 81 60 0C B4 7F FF FF 83 48 08 30 C6 40 16 00 C3 }
	condition:
		$pattern
}

rule pthread_cond_destroy_bf15198941e2982ca6dd52c8956c1838 {
	meta:
		aliases = "__GI_pthread_cond_destroy, pthread_cond_destroy"
		size = "16"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 83 78 08 01 19 C0 F7 D0 83 E0 10 C3 }
	condition:
		$pattern
}

rule __GI_xdrrec_endofrecord_6c4eda75ed068649ea5b958b6e6daf0c {
	meta:
		aliases = "xdrrec_endofrecord, __GI_xdrrec_endofrecord"
		size = "84"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 83 7C 24 08 00 8B 48 0C 75 11 83 79 1C 00 75 0B 8B 51 10 8D 42 04 3B 41 14 72 13 C7 41 1C 00 00 00 00 BA 01 00 00 00 89 C8 E9 ?? ?? ?? ?? 8B 41 18 29 C2 83 EA 04 81 CA 00 00 00 80 0F CA 89 10 8B 41 10 83 41 10 04 89 41 18 B8 01 00 00 00 C3 }
	condition:
		$pattern
}

rule toascii_2512460995700c0f5996e06f2a68a499 {
	meta:
		aliases = "toascii"
		size = "8"
		objfiles = "toascii@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 83 E0 7F C3 }
	condition:
		$pattern
}

rule isdigit_f03eb0c52d2f467b29a636eef12a35a2 {
	meta:
		aliases = "isdigit"
		size = "17"
		objfiles = "isdigit@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 83 E8 30 83 F8 09 0F 96 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule __GI_btowc_a1224ff3f0aa6828e1ce619685927b9d {
	meta:
		aliases = "btowc, __GI_btowc"
		size = "13"
		objfiles = "btowc@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 83 F8 7F 76 03 83 C8 FF C3 }
	condition:
		$pattern
}

rule setjmp_99ce58d3572fa80f5c80bc78c67a778d {
	meta:
		aliases = "setjmp"
		size = "42"
		objfiles = "bsd_setjmp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 89 18 89 70 04 89 78 08 8D 4C 24 04 89 48 10 8B 0C 24 89 48 14 89 68 0C 6A 01 FF 74 24 08 E8 ?? ?? ?? ?? 59 5A C3 }
	condition:
		$pattern
}

rule __sigsetjmp_29edfdaeb6afd5e91b998a0e624d668d {
	meta:
		aliases = "__sigsetjmp"
		size = "33"
		objfiles = "setjmp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 89 18 89 70 04 89 78 08 8D 4C 24 04 89 48 10 8B 0C 24 89 48 14 89 68 0C E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule basename_73da9c3c73a9f10f260db5c1902bd08b {
	meta:
		aliases = "__GI_basename, basename"
		size = "23"
		objfiles = "basename@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 89 C2 EB 08 42 80 F9 2F 75 02 89 D0 8A 0A 84 C9 75 F2 C3 }
	condition:
		$pattern
}

rule remque_10c0f8cd79236b847235a8439924eaf0 {
	meta:
		aliases = "remque"
		size = "23"
		objfiles = "remque@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 10 8B 40 04 85 D2 74 03 89 42 04 85 C0 74 02 89 10 C3 }
	condition:
		$pattern
}

rule pthread_attr_getdetachstate_f1910983a54cef9177564bec55e19797 {
	meta:
		aliases = "pthread_mutexattr_gettype, __pthread_mutexattr_gettype, __GI_pthread_attr_getdetachstate, __pthread_mutexattr_getkind_np, pthread_mutexattr_getkind_np, pthread_rwlockattr_getkind_np, pthread_attr_getdetachstate"
		size = "15"
		objfiles = "rwlock@libpthread.a, attr@libpthread.a, mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 10 8B 44 24 08 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule cfgetospeed_8b87194ff10627aae8fdf7766d049e05 {
	meta:
		aliases = "cfgetospeed"
		size = "13"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 40 08 25 0F 10 00 00 C3 }
	condition:
		$pattern
}

rule sc_getc_f05a2db01e53054c5dfad9358c52ad9e {
	meta:
		aliases = "sc_getc"
		size = "16"
		objfiles = "vfscanf@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 40 08 89 44 24 04 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdrstdio_getpos_dc8ca3cc6c0bf02202e93dd779d2d651 {
	meta:
		aliases = "hasmntopt, xdrstdio_destroy, xdrstdio_getpos"
		size = "16"
		objfiles = "xdr_stdio@libc.a, mntent@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 40 0C 89 44 24 04 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule telldir_670b71030e7208655a643bfb5dda5477 {
	meta:
		aliases = "telldir"
		size = "8"
		objfiles = "telldir@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 40 10 C3 }
	condition:
		$pattern
}

rule __GI_wcschrnul_19c6d19b76da9d919789b1e1b5734ae6 {
	meta:
		aliases = "wcschrnul, __GI_wcschrnul"
		size = "25"
		objfiles = "wcschrnul@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 4C 24 08 83 E8 04 83 C0 04 8B 10 85 D2 74 04 39 CA 75 F3 C3 }
	condition:
		$pattern
}

rule __GI_wcschr_fd24e4ad57a1d75364f1f35db2e201d5 {
	meta:
		aliases = "wcschr, __GI_wcschr"
		size = "26"
		objfiles = "wcschr@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 4C 24 08 8B 10 39 CA 74 0B 85 D2 74 05 83 C0 04 EB F1 31 C0 C3 }
	condition:
		$pattern
}

rule __pthread_mutex_init_78682bf18a08529fbd9455d569b6e07b {
	meta:
		aliases = "pthread_mutex_init, __pthread_mutex_init"
		size = "53"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 4C 24 08 BA 03 00 00 00 85 C9 C7 40 10 00 00 00 00 C7 40 14 00 00 00 00 74 02 8B 11 89 50 0C C7 40 04 00 00 00 00 C7 40 08 00 00 00 00 31 C0 C3 }
	condition:
		$pattern
}

rule __GI_pthread_attr_getschedpoli_cb3bf975196f4bf05554dd110bc96783 {
	meta:
		aliases = "pthread_attr_getschedpolicy, pthread_rwlockattr_getpshared, __GI_pthread_attr_getschedpolicy"
		size = "16"
		objfiles = "rwlock@libpthread.a, attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 50 04 8B 44 24 08 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule sem_getvalue_bf01487b64a973dd33d77632c300357d {
	meta:
		aliases = "__new_sem_getvalue, sem_getvalue"
		size = "16"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 50 08 8B 44 24 08 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_attr_getinheritsched_467a4efaa4ddb4792886d5ffa5b1df1c {
	meta:
		aliases = "__GI_pthread_attr_getinheritsched, pthread_attr_getinheritsched"
		size = "16"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 50 0C 8B 44 24 08 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_attr_getscope_017ad18cec422befc27664a9ac92e393 {
	meta:
		aliases = "__GI_pthread_attr_getscope, pthread_attr_getscope"
		size = "16"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 50 10 8B 44 24 08 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule __pthread_attr_getguardsize_88a28a419baab63607b16b64b3aebbfe {
	meta:
		aliases = "pthread_attr_getguardsize, __pthread_attr_getguardsize"
		size = "16"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 50 14 8B 44 24 08 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule __pthread_attr_getstackaddr_c88e6caf6b9456cde7277674cbdadb30 {
	meta:
		aliases = "pthread_attr_getstackaddr, __pthread_attr_getstackaddr"
		size = "16"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 50 1C 8B 44 24 08 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule __pthread_attr_getstacksize_dc7a64c2315e36c9e6022584d127f7c4 {
	meta:
		aliases = "pthread_attr_getstacksize, __pthread_attr_getstacksize"
		size = "16"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 50 20 8B 44 24 08 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule __init_scan_cookie_6ef958eae9c95a95b8d50579ec0ced07 {
	meta:
		aliases = "__init_scan_cookie"
		size = "72"
		objfiles = "__scan_cookie@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 08 31 C9 89 50 08 C7 40 0C 00 00 00 00 C6 40 19 00 F6 02 02 74 03 8B 4A 28 89 48 14 C6 40 1A 00 C6 40 1B 00 C7 40 30 ?? ?? ?? ?? C7 40 3C ?? ?? ?? ?? C7 40 34 01 00 00 00 C7 40 38 2E 00 00 00 C3 }
	condition:
		$pattern
}

rule __GI_sigwaitinfo_faccbca0b6bad3fb4d363490fd47900a {
	meta:
		aliases = "sigwaitinfo, __GI_sigwaitinfo"
		size = "23"
		objfiles = "__rt_sigtimedwait@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 08 31 C9 C7 44 24 04 08 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_vwarnx_253a37e4f537ccc5659b79682313bd94 {
	meta:
		aliases = "vwarnx, __GI_vwarnx"
		size = "15"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 08 31 C9 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tdestroy_8964637c7b9ae7f838fe29aa782cfaa4 {
	meta:
		aliases = "__GI_tdestroy, tdestroy"
		size = "18"
		objfiles = "tdestroy@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 08 85 C0 74 05 E9 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule twalk_98f2171ff7f2dc475e27bda354139c03 {
	meta:
		aliases = "twalk"
		size = "24"
		objfiles = "twalk@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 08 85 C0 74 0B 85 D2 74 07 31 C9 E9 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __GI_srand48_r_ebb0e7c4ab8909dab5bf3089b8003e8e {
	meta:
		aliases = "srand48_r, __GI_srand48_r"
		size = "55"
		objfiles = "srand48_r@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 08 89 C1 C1 F9 10 66 89 42 02 31 C0 66 89 4A 04 66 C7 02 0E 33 C7 42 10 6D E6 EC DE C7 42 14 05 00 00 00 66 C7 42 0C 0B 00 66 C7 42 0E 01 00 C3 }
	condition:
		$pattern
}

rule __old_sem_getvalue_fdd2167143cdfdae85f9c9e4908cc089 {
	meta:
		aliases = "__old_sem_getvalue"
		size = "29"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 08 8B 00 A8 01 74 06 D1 E8 89 02 EB 06 C7 02 00 00 00 00 31 C0 C3 }
	condition:
		$pattern
}

rule sigtimedwait_2d2bf51cea7cbd14135ec7717b69ec02 {
	meta:
		aliases = "__GI_sigtimedwait, sigtimedwait"
		size = "25"
		objfiles = "__rt_sigtimedwait@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 08 8B 4C 24 0C C7 44 24 04 08 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svcunixfd_create_e63fbd4454ec064dc8f9d0b775e2be85 {
	meta:
		aliases = "svcfd_create, svcunixfd_create"
		size = "17"
		objfiles = "svc_unix@libc.a, svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 08 8B 4C 24 0C E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_vwarn_43fd1032e1ca011a69b78fa05ca77933 {
	meta:
		aliases = "vwarn, __GI_vwarn"
		size = "18"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 08 B9 01 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdrstdio_create_3b45c650439d00b193b876ff729499d0 {
	meta:
		aliases = "xdrstdio_create"
		size = "39"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 0C 89 10 C7 40 04 ?? ?? ?? ?? 8B 54 24 08 C7 40 14 00 00 00 00 89 50 0C C7 40 10 00 00 00 00 C3 }
	condition:
		$pattern
}

rule clntunix_freeres_5f8a1cc9fca4abb9921c8a792f5e2ca1 {
	meta:
		aliases = "clntunix_freeres"
		size = "36"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 0C 8B 4C 24 08 8B 40 08 05 AC 00 00 00 C7 00 02 00 00 00 89 54 24 08 89 44 24 04 FF E1 }
	condition:
		$pattern
}

rule clntudp_freeres_7f3238df42c20f388b004fbfee0782b1 {
	meta:
		aliases = "clntudp_freeres"
		size = "34"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 0C 8B 4C 24 08 8B 40 08 83 C0 38 C7 00 02 00 00 00 89 54 24 08 89 44 24 04 FF E1 }
	condition:
		$pattern
}

rule clnttcp_freeres_9cba01471569f35f0792a1d1d0659e5a {
	meta:
		aliases = "clnttcp_freeres"
		size = "34"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 0C 8B 4C 24 08 8B 40 08 83 C0 4C C7 00 02 00 00 00 89 54 24 08 89 44 24 04 FF E1 }
	condition:
		$pattern
}

rule svcunix_freeargs_bfec9dbc9e68cac70cd6ac3f54a6e76c {
	meta:
		aliases = "svctcp_freeargs, svcunix_freeargs"
		size = "34"
		objfiles = "svc_unix@libc.a, svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 0C 8B 4C 24 08 8B 40 2C 83 C0 08 C7 00 02 00 00 00 89 54 24 08 89 44 24 04 FF E1 }
	condition:
		$pattern
}

rule svcudp_freeargs_78289c506c4f9842067d59aa1809f55c {
	meta:
		aliases = "svcudp_freeargs"
		size = "34"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 0C 8B 4C 24 08 8B 40 30 83 C0 08 C7 00 02 00 00 00 89 54 24 08 89 44 24 04 FF E1 }
	condition:
		$pattern
}

rule labs_9206eec894c56790c6ede6426d1a11e1 {
	meta:
		aliases = "abs, labs"
		size = "10"
		objfiles = "labs@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 99 31 D0 29 D0 C3 }
	condition:
		$pattern
}

rule __pthread_setconcurrency_54cf6a653520c3791886f194f83332a1 {
	meta:
		aliases = "pthread_setconcurrency, __pthread_setconcurrency"
		size = "12"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 A3 ?? ?? ?? ?? 31 C0 C3 }
	condition:
		$pattern
}

rule __GI_ffs_1b3ac6831c570a243d25f3a2669a3a41 {
	meta:
		aliases = "ffs, __GI_ffs"
		size = "65"
		objfiles = "ffs@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 B2 01 66 85 C0 75 05 C1 F8 10 B2 11 84 C0 75 06 C1 F8 08 83 C2 08 A8 0F 75 06 C1 F8 04 83 C2 04 A8 03 75 06 C1 F8 02 83 C2 02 31 C9 85 C0 74 0A 40 0F BE D2 83 E0 01 8D 0C 02 89 C8 C3 }
	condition:
		$pattern
}

rule dlclose_750318a9e1ee858a81008fdcdc0707b9 {
	meta:
		aliases = "dlclose"
		size = "14"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 BA 01 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_rwlockattr_init_9cccfab68f4bd16a32525f638f9dcc39 {
	meta:
		aliases = "pthread_rwlockattr_init"
		size = "20"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 C7 00 00 00 00 00 C7 40 04 00 00 00 00 31 C0 C3 }
	condition:
		$pattern
}

rule __GI_pthread_cond_init_057ef04232bf5edac022d3faadf51fdb {
	meta:
		aliases = "pthread_cond_init, __GI_pthread_cond_init"
		size = "27"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 C7 00 00 00 00 00 C7 40 04 00 00 00 00 C7 40 08 00 00 00 00 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_mutexattr_init_a8bcb8367c737460394990dca0e230b0 {
	meta:
		aliases = "__pthread_mutexattr_init, pthread_mutexattr_init"
		size = "13"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 C7 00 03 00 00 00 31 C0 C3 }
	condition:
		$pattern
}

rule fegetenv_ff9412d8c158f90eb25852371c6570eb {
	meta:
		aliases = "fegetenv"
		size = "11"
		objfiles = "fegetenv@libm.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 D9 30 D9 20 31 C0 C3 }
	condition:
		$pattern
}

rule __re_compile_fastmap_08954bb79c8aadcdb928571c8d2dfa6d {
	meta:
		aliases = "re_compile_fastmap, __re_compile_fastmap"
		size = "9"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_equal_d0ba95a9976b90bd2839b9a76661bc0b {
	meta:
		aliases = "__GI_pthread_equal, pthread_equal"
		size = "15"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 08 39 44 24 04 0F 94 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule pthread_attr_setscope_eab52c90b7ecc1eed445e196b254028e {
	meta:
		aliases = "__GI_pthread_attr_setscope, pthread_attr_setscope"
		size = "37"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 08 85 C0 74 0F 48 0F 94 C0 0F B6 C0 48 83 E0 B7 83 C0 5F C3 8B 44 24 04 C7 40 10 00 00 00 00 31 C0 C3 }
	condition:
		$pattern
}

rule alphasort_0b8952c11d0122f6e2461be9483226b1 {
	meta:
		aliases = "alphasort"
		size = "31"
		objfiles = "alphasort@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 08 8B 00 83 C0 0B 89 44 24 08 8B 44 24 04 8B 00 83 C0 0B 89 44 24 04 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule alphasort64_8e3845784a90450e364e6b0b22024a07 {
	meta:
		aliases = "alphasort64"
		size = "31"
		objfiles = "alphasort64@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 08 8B 00 83 C0 13 89 44 24 08 8B 44 24 04 8B 00 83 C0 13 89 44 24 04 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule crypt_5c2a3ea3ac9666d0318ee0715859eca4 {
	meta:
		aliases = "crypt"
		size = "43"
		objfiles = "crypt@libcrypt.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 08 8B 54 24 04 80 38 24 75 11 80 78 01 31 75 0B 80 78 02 24 75 05 E9 ?? ?? ?? ?? 89 44 24 08 89 54 24 04 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_mutexattr_getpshared_d162f5566ce13c5224d3d871a682088e {
	meta:
		aliases = "pthread_mutexattr_getpshared, pthread_condattr_getpshared, __pthread_mutexattr_getpshared"
		size = "13"
		objfiles = "condvar@libpthread.a, mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 08 C7 00 00 00 00 00 31 C0 C3 }
	condition:
		$pattern
}

rule svctcp_getargs_f2010ca047da84c236d5692be15bb42f {
	meta:
		aliases = "svcunix_getargs, svctcp_getargs"
		size = "28"
		objfiles = "svc_unix@libc.a, svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 0C 8B 4C 24 08 89 44 24 08 8B 44 24 04 8B 40 2C 83 C0 08 89 44 24 04 FF E1 }
	condition:
		$pattern
}

rule svcudp_getargs_29c29b075819c3abbba8283cefacca9e {
	meta:
		aliases = "svcudp_getargs"
		size = "28"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 0C 8B 4C 24 08 89 44 24 08 8B 44 24 04 8B 40 30 83 C0 08 89 44 24 04 FF E1 }
	condition:
		$pattern
}

rule xdrmem_getlong_af7399d5b7380180d4ba8a73461386d4 {
	meta:
		aliases = "xdrmem_getint32, xdrmem_getlong"
		size = "45"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 31 D2 8B 41 14 83 F8 03 76 1C 83 E8 04 89 41 14 8B 41 0C 8B 54 24 08 8B 00 0F C8 89 02 BA 01 00 00 00 83 41 0C 04 89 D0 C3 }
	condition:
		$pattern
}

rule xdrmem_putlong_90e7f75a8ad23c5d9487754c581f1fcf {
	meta:
		aliases = "xdrmem_putint32, xdrmem_putlong"
		size = "45"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 31 D2 8B 41 14 83 F8 03 76 1C 83 E8 04 8B 51 0C 89 41 14 8B 44 24 08 8B 00 0F C8 89 02 BA 01 00 00 00 83 41 0C 04 89 D0 C3 }
	condition:
		$pattern
}

rule isctype_c53864b289c0bcecca036bb75ce522ba {
	meta:
		aliases = "isctype"
		size = "22"
		objfiles = "isctype@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 15 ?? ?? ?? ?? 8B 44 24 08 66 23 04 4A 0F B7 C0 C3 }
	condition:
		$pattern
}

rule __GI_iswctype_ead14de79bc7e82d3de3851cab381a6a {
	meta:
		aliases = "iswctype, __GI_iswctype"
		size = "43"
		objfiles = "iswctype@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 44 24 08 83 F9 7F 77 05 83 F8 0C 76 03 31 C0 C3 8B 15 ?? ?? ?? ?? 66 8B 84 00 ?? ?? ?? ?? 66 23 04 4A 0F B7 C0 C3 }
	condition:
		$pattern
}

rule __GI___longjmp_eb3a20b3fbb1ee7d783df9086f759789 {
	meta:
		aliases = "__longjmp, __GI___longjmp"
		size = "27"
		objfiles = "__longjmp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 44 24 08 8B 51 14 8B 19 8B 71 04 8B 79 08 8B 69 0C 8B 61 10 FF E2 }
	condition:
		$pattern
}

rule __GI_strnlen_2627ae82c3a3a930f82b5500b21212d8 {
	meta:
		aliases = "strnlen, __GI_strnlen"
		size = "25"
		objfiles = "strnlen@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 54 24 08 89 C8 42 EB 06 80 38 00 74 04 40 4A 75 F7 29 C8 C3 }
	condition:
		$pattern
}

rule __GI_wcsnlen_36302110b5f494905b96409ac1c860a2 {
	meta:
		aliases = "wcsnlen, __GI_wcsnlen"
		size = "31"
		objfiles = "wcsnlen@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 54 24 08 89 C8 EB 04 83 C0 04 4A 85 D2 74 05 83 38 00 75 F3 29 C8 C1 F8 02 C3 }
	condition:
		$pattern
}

rule _seterr_reply_59c845979f0501151a6dcb4e2dbd5b63 {
	meta:
		aliases = "__GI__seterr_reply, _seterr_reply"
		size = "222"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 54 24 08 8B 41 08 85 C0 74 09 48 0F 85 8A 00 00 00 EB 59 8B 41 18 85 C0 75 07 C7 02 00 00 00 00 C3 83 F8 05 77 37 FF 24 85 ?? ?? ?? ?? C7 02 08 00 00 00 EB 72 C7 02 09 00 00 00 EB 6A C7 02 0A 00 00 00 EB 62 C7 02 0B 00 00 00 EB 5A C7 02 0C 00 00 00 EB 52 C7 02 00 00 00 00 EB 4A C7 02 10 00 00 00 C7 42 04 00 00 00 00 EB 2A 8B 41 0C 83 F8 01 74 0D 83 F8 06 75 10 C7 02 06 00 00 00 EB 26 C7 02 07 00 00 00 EB 1E C7 02 10 00 00 00 C7 42 04 01 00 00 00 89 42 08 EB 0C C7 02 10 00 00 00 8B 41 08 89 42 04 8B 02 83 F8 07 74 17 83 F8 09 74 19 83 F8 06 75 20 8B 41 10 89 42 04 8B 41 14 89 42 }
	condition:
		$pattern
}

rule sigisemptyset_e0c0da2183a27d0672fc18368960797b {
	meta:
		aliases = "sigisemptyset"
		size = "33"
		objfiles = "sigisempty@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 BA 1F 00 00 00 8B 41 7C EB 03 8B 04 91 85 C0 75 03 4A 79 F6 85 C0 0F 94 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule __GI_wcscpy_0f951888864d99ea1790520f1b317919 {
	meta:
		aliases = "wcscpy, __GI_wcscpy"
		size = "27"
		objfiles = "wcscpy@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 08 8B 54 24 04 8B 01 83 C1 04 89 02 83 C2 04 85 C0 75 F2 8B 44 24 04 C3 }
	condition:
		$pattern
}

rule insque_4228ecb3365a2a6475c5c48f4c1e3a95 {
	meta:
		aliases = "insque"
		size = "25"
		objfiles = "insque@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 08 8B 54 24 04 8B 01 89 11 85 C0 74 03 89 50 04 89 02 89 4A 04 C3 }
	condition:
		$pattern
}

rule wcscat_8e5b7da4c2d40df2b4b974446bf27159 {
	meta:
		aliases = "__GI_wcscat, wcscat"
		size = "39"
		objfiles = "wcscat@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 08 8B 54 24 04 8B 02 83 C2 04 85 C0 75 F7 83 EA 04 8B 01 83 C1 04 89 02 83 C2 04 85 C0 75 F2 8B 44 24 04 C3 }
	condition:
		$pattern
}

rule wmemchr_0f94b3815a389062d9126f0f515c4037 {
	meta:
		aliases = "__GI_wmemchr, wmemchr"
		size = "29"
		objfiles = "wmemchr@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 08 8B 54 24 0C 8B 44 24 04 EB 08 39 08 74 0A 83 C0 04 4A 85 D2 75 F4 31 C0 C3 }
	condition:
		$pattern
}

rule __GI_inet_netof_96bd25f4808937f22b3fe0927e46091d {
	meta:
		aliases = "inet_netof, __GI_inet_netof"
		size = "42"
		objfiles = "inet_netof@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 0F CA 85 D2 78 06 89 D0 C1 E8 18 C3 89 D0 25 00 00 00 C0 3D 00 00 00 80 75 06 89 D0 C1 E8 10 C3 89 D0 C1 E8 08 C3 }
	condition:
		$pattern
}

rule inet_lnaof_cefabd363d92963170b8a044827c9fd2 {
	meta:
		aliases = "inet_lnaof"
		size = "40"
		objfiles = "inet_lnaof@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 0F CA 85 D2 78 08 89 D0 25 FF FF FF 00 C3 89 D0 25 00 00 00 C0 3D 00 00 00 80 75 04 0F B7 C2 C3 0F B6 C2 C3 }
	condition:
		$pattern
}

rule cfgetispeed_ddb0341be13e72682af0a69cb0667538 {
	meta:
		aliases = "cfgetispeed"
		size = "20"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 31 C0 83 3A 00 78 08 8B 42 08 25 0F 10 00 00 C3 }
	condition:
		$pattern
}

rule gai_strerror_2b1419d789939a62d80d203c0658865e {
	meta:
		aliases = "gai_strerror"
		size = "37"
		objfiles = "gai_strerror@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 31 C0 EB 12 39 14 C5 ?? ?? ?? ?? 75 08 8B 04 C5 ?? ?? ?? ?? C3 40 83 F8 0F 76 E9 B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __GI_clnt_sperrno_4c713e0849366ed00a7e291dc9cc5efe {
	meta:
		aliases = "clnt_sperrno, __GI_clnt_sperrno"
		size = "42"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 31 C0 EB 17 39 14 C5 ?? ?? ?? ?? 75 0D 8B 04 C5 ?? ?? ?? ?? 05 ?? ?? ?? ?? C3 40 83 F8 11 76 E4 B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __fpending_99bb0d200616076e9e117985062ab56c {
	meta:
		aliases = "__fpending"
		size = "18"
		objfiles = "__fpending@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 31 C0 F6 02 40 74 06 8B 42 10 2B 42 08 C3 }
	condition:
		$pattern
}

rule l64a_a249624712e2f0f09d2f182c54d79634 {
	meta:
		aliases = "l64a"
		size = "54"
		objfiles = "l64a@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 31 C9 B8 ?? ?? ?? ?? 85 D2 75 16 C3 89 D0 C1 EA 06 83 E0 3F 8A 80 ?? ?? ?? ?? 88 81 ?? ?? ?? ?? 41 85 D2 75 E7 B8 ?? ?? ?? ?? C6 81 ?? ?? ?? ?? 00 C3 }
	condition:
		$pattern
}

rule __GI_towupper_48138e3d9f8c60c2c473cafe14662f16 {
	meta:
		aliases = "towupper, towlower, __GI_towlower, __GI_towupper"
		size = "21"
		objfiles = "towlower@libc.a, towupper@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 83 FA 7F 77 09 A1 ?? ?? ?? ?? 0F BF 14 50 89 D0 C3 }
	condition:
		$pattern
}

rule __isinff_857eb5077641af5ea7a2e12f74cef8dc {
	meta:
		aliases = "isinff, __GI___isinff, __isinff"
		size = "33"
		objfiles = "s_isinff@libm.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 89 D0 C1 FA 1E 25 FF FF FF 7F 35 00 00 80 7F 89 C1 F7 D9 09 C8 C1 F8 1F F7 D0 21 D0 C3 }
	condition:
		$pattern
}

rule wcslen_95bb5ca1b15db730fbdf52d886799988 {
	meta:
		aliases = "__GI_wcslen, wcslen"
		size = "22"
		objfiles = "wcslen@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 89 D0 EB 03 83 C0 04 83 38 00 75 F8 29 D0 C1 F8 02 C3 }
	condition:
		$pattern
}

rule __GI_nl_langinfo_1348c04be901cd4fa7bec0c00882ae92 {
	meta:
		aliases = "nl_langinfo, __GI_nl_langinfo"
		size = "65"
		objfiles = "nl_langinfo@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 89 D1 C1 F9 08 83 F9 05 77 2D 0F B6 81 ?? ?? ?? ?? 81 E2 FF 00 00 00 8D 14 10 0F B6 81 ?? ?? ?? ?? 39 C2 73 12 0F B6 82 ?? ?? ?? ?? 83 E2 40 8D 84 50 ?? ?? ?? ?? C3 B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __scan_ungetc_9edc81e09c8124ee370ad3d6a632a164 {
	meta:
		aliases = "__scan_ungetc"
		size = "36"
		objfiles = "__scan_cookie@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8A 42 19 FF 42 10 3C 02 75 0A 8B 42 04 C6 42 19 00 89 02 C3 84 C0 75 07 FF 4A 0C C6 42 19 01 C3 }
	condition:
		$pattern
}

rule __fbufsize_315ef90ae72c125d2e04bdec80b2ac72 {
	meta:
		aliases = "__fbufsize"
		size = "11"
		objfiles = "__fbufsize@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 42 0C 2B 42 08 C3 }
	condition:
		$pattern
}

rule xdrmem_getpos_26516add248bf2fd21db96d36609d094 {
	meta:
		aliases = "xdrmem_getpos"
		size = "11"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 42 0C 2B 42 10 C3 }
	condition:
		$pattern
}

rule pthread_mutex_destroy_f8b1bdf7a6c2e74a2630b8c03a52bb38 {
	meta:
		aliases = "__pthread_mutex_destroy, pthread_mutex_destroy"
		size = "48"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 42 0C 85 C0 78 0A 83 F8 01 7E 0B 83 F8 03 7E 0C B8 16 00 00 00 C3 F6 42 10 01 EB 04 83 7A 10 00 74 06 B8 10 00 00 00 C3 31 C0 C3 }
	condition:
		$pattern
}

rule _load_inttype_bfc63bc1e8e1448063be80fd044528f6 {
	meta:
		aliases = "_load_inttype"
		size = "86"
		objfiles = "_load_inttype@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 44 24 08 83 7C 24 0C 00 78 22 F6 C6 08 75 22 8B 00 81 FA 00 01 00 00 75 05 0F B6 C0 EB 0B 81 FA 00 02 00 00 75 03 0F B7 C0 31 D2 C3 F6 C6 08 74 06 8B 50 04 8B 00 C3 8B 00 81 FA 00 01 00 00 75 05 0F BE C0 EB 09 81 FA 00 02 00 00 75 01 98 99 C3 }
	condition:
		$pattern
}

rule pthread_attr_setstackaddr_311951e8a9dd1bdacdbb1dbbcc8195c2 {
	meta:
		aliases = "__pthread_attr_setstackaddr, pthread_attr_setstackaddr"
		size = "21"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 44 24 08 89 42 1C 31 C0 C7 42 18 01 00 00 00 C3 }
	condition:
		$pattern
}

rule xdrmem_create_0cb9c6b61297d01958e32b28fd04af72 {
	meta:
		aliases = "__GI_xdrmem_create, xdrmem_create"
		size = "35"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 44 24 10 8B 4C 24 08 89 4A 10 89 02 C7 42 04 ?? ?? ?? ?? 89 4A 0C 8B 44 24 0C 89 42 14 C3 }
	condition:
		$pattern
}

rule pthread_rwlock_init_02f13dcc3a42bfc1bedef51678ccc5ec {
	meta:
		aliases = "pthread_rwlock_init"
		size = "83"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 4C 24 08 85 C9 C7 02 00 00 00 00 C7 42 04 00 00 00 00 C7 42 08 00 00 00 00 C7 42 0C 00 00 00 00 C7 42 10 00 00 00 00 C7 42 14 00 00 00 00 75 10 C7 42 18 01 00 00 00 C7 42 1C 00 00 00 00 EB 0B 8B 01 89 42 18 8B 41 04 89 42 1C 31 C0 C3 }
	condition:
		$pattern
}

rule stpcpy_756aa47fd45fe1e8d02c3ce0a4eee26f {
	meta:
		aliases = "__GI_stpcpy, stpcpy"
		size = "22"
		objfiles = "stpcpy@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 4C 24 08 8A 01 41 88 02 42 84 C0 75 F6 8D 42 FF C3 }
	condition:
		$pattern
}

rule wcpcpy_9b4370c47d3709a1502a3b6a17cd0b09 {
	meta:
		aliases = "wcpcpy"
		size = "26"
		objfiles = "wcpcpy@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 4C 24 08 8B 01 83 C1 04 89 02 83 C2 04 85 C0 75 F2 8D 42 FC C3 }
	condition:
		$pattern
}

rule xdr_float_4273dee23da4e5503e962141101bd8b8 {
	meta:
		aliases = "xdr_float"
		size = "50"
		objfiles = "xdr_float@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 4C 24 08 8B 02 83 F8 01 74 0A 73 17 8B 42 04 8B 48 04 EB 0D 8B 42 04 89 4C 24 08 89 54 24 04 8B 08 FF E1 83 F8 02 0F 94 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule xdr_uint32_t_b99c859feb793efa5ddaf9bf8c665f60 {
	meta:
		aliases = "xdr_int32_t, xdr_uint32_t"
		size = "51"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 4C 24 08 8B 02 83 F8 01 74 0A 73 18 8B 42 04 8B 48 24 EB 0E 8B 42 04 89 4C 24 08 89 54 24 04 8B 48 20 FF E1 83 F8 02 0F 94 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule xdr_long_f060e38d16e332385a915687f429ce46 {
	meta:
		aliases = "__GI_xdr_long, xdr_long"
		size = "52"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 4C 24 08 8B 02 85 C0 75 08 8B 42 04 8B 48 04 EB 12 83 F8 01 75 0F 8B 42 04 89 4C 24 08 89 54 24 04 8B 08 FF E1 83 F8 02 0F 94 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule __GI_wcscoll_d12081b632ea83b04fb875937ca6d645 {
	meta:
		aliases = "wcscmp, wcscoll, __GI_wcscmp, __GI_wcscoll"
		size = "42"
		objfiles = "wcscmp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 4C 24 08 EB 0B 83 3A 00 74 12 83 C2 04 83 C1 04 8B 01 39 02 74 EF 73 07 83 C8 FF C3 31 C0 C3 B8 01 00 00 00 C3 }
	condition:
		$pattern
}

rule tolower_d7d4521aee6b4c2c35428947fe099a90 {
	meta:
		aliases = "__GI_toupper, toupper, __GI_tolower, tolower"
		size = "29"
		objfiles = "toupper@libc.a, tolower@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8D 82 80 00 00 00 3D 7F 01 00 00 77 09 A1 ?? ?? ?? ?? 0F BF 14 50 89 D0 C3 }
	condition:
		$pattern
}

rule isblank_5417f1fb8e36c6e932252b09ead9d0c1 {
	meta:
		aliases = "isblank"
		size = "19"
		objfiles = "isblank@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 25 00 01 00 00 C3 }
	condition:
		$pattern
}

rule iscntrl_2dc04f106681d2b774e1ee052ef468e0 {
	meta:
		aliases = "iscntrl"
		size = "19"
		objfiles = "iscntrl@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 25 00 02 00 00 C3 }
	condition:
		$pattern
}

rule ispunct_c3c3c53a2845a213d1fc619013cac873 {
	meta:
		aliases = "ispunct"
		size = "19"
		objfiles = "ispunct@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 25 00 04 00 00 C3 }
	condition:
		$pattern
}

rule isalnum_175659f72d6ba97b50950d48352e9f19 {
	meta:
		aliases = "isalnum"
		size = "19"
		objfiles = "isalnum@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 25 00 08 00 00 C3 }
	condition:
		$pattern
}

rule isgraph_49a9f6fcd3b0abca144dbbfe94b15c05 {
	meta:
		aliases = "isgraph"
		size = "19"
		objfiles = "isgraph@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 25 80 00 00 00 C3 }
	condition:
		$pattern
}

rule isupper_77cef65e7bce598ddaaadae7de98a90e {
	meta:
		aliases = "isupper"
		size = "17"
		objfiles = "isupper@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 83 E0 01 C3 }
	condition:
		$pattern
}

rule islower_2d1974ca068d02645740cc133ae551f7 {
	meta:
		aliases = "islower"
		size = "17"
		objfiles = "islower@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 83 E0 02 C3 }
	condition:
		$pattern
}

rule isalpha_ae2fe3c00f0d2b34d5515092d9ace8ee {
	meta:
		aliases = "isalpha"
		size = "17"
		objfiles = "isalpha@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 83 E0 04 C3 }
	condition:
		$pattern
}

rule isxdigit_e58c5ce5bf1ea730964dd0478cb4d0f7 {
	meta:
		aliases = "isxdigit"
		size = "17"
		objfiles = "isxdigit@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 83 E0 10 C3 }
	condition:
		$pattern
}

rule isspace_3135b1d20b0674a3cfa314f46d0b2e18 {
	meta:
		aliases = "isspace"
		size = "17"
		objfiles = "isspace@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 83 E0 20 C3 }
	condition:
		$pattern
}

rule isprint_b16ef400bdbcab1927214d045ea4d492 {
	meta:
		aliases = "isprint"
		size = "17"
		objfiles = "isprint@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 83 E0 40 C3 }
	condition:
		$pattern
}

rule isnanf_cce8ab31bee5ab03c17cf85f3c0c7526 {
	meta:
		aliases = "__isnanf, __GI___isnanf, isnanf"
		size = "21"
		objfiles = "s_isnanf@libm.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 B8 00 00 80 7F 81 E2 FF FF FF 7F 29 D0 C1 E8 1F C3 }
	condition:
		$pattern
}

rule mbsinit_5cd63a44de22623256fcbd89e65a7b8d {
	meta:
		aliases = "__GI_mbsinit, mbsinit"
		size = "22"
		objfiles = "mbsinit@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 B8 01 00 00 00 85 D2 74 08 31 C0 83 3A 00 0F 94 C0 C3 }
	condition:
		$pattern
}

rule testandset_6e2058efc0be77b2011c946b97a6239e {
	meta:
		aliases = "testandset"
		size = "12"
		objfiles = "pt_machine@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 B8 01 00 00 00 87 02 C3 }
	condition:
		$pattern
}

rule __fpclassifyf_09749c32236500d95a770b7c26fc67aa {
	meta:
		aliases = "__GI___fpclassifyf, __fpclassifyf"
		size = "49"
		objfiles = "s_fpclassifyf@libm.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 B8 02 00 00 00 81 E2 FF FF FF 7F 74 1F B0 03 81 FA FF FF 7F 00 76 15 B0 04 81 FA FF FF 7F 7F 76 0B 31 C0 81 FA 00 00 80 7F 0F 96 C0 C3 }
	condition:
		$pattern
}

rule hstrerror_d9078c5439f7fc15dd1cf5d3b9b5bdc4 {
	meta:
		aliases = "hstrerror"
		size = "22"
		objfiles = "herror@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 B8 ?? ?? ?? ?? 83 FA 04 77 07 8B 04 95 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __xpg_basename_b2c1575fb0d06802b24c83a72c1da299 {
	meta:
		aliases = "__xpg_basename"
		size = "55"
		objfiles = "__xpg_basename@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 B8 ?? ?? ?? ?? 85 D2 74 29 80 3A 00 74 24 8D 4A FF 89 D0 80 3A 2F 74 09 41 39 CA 76 04 89 D0 89 D1 42 80 3A 00 75 EC 80 38 2F 75 02 89 C1 C6 41 01 00 C3 }
	condition:
		$pattern
}

rule __signbit_a15013df25cdf9c83fe3321f1ed1810b {
	meta:
		aliases = "__GI___signbit, __signbit"
		size = "12"
		objfiles = "s_signbit@libm.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 89 D0 25 00 00 00 80 C3 }
	condition:
		$pattern
}

rule __finite_52f0fe301eafa063e375e8223ee96caa {
	meta:
		aliases = "__GI___finite, finite, __GI_finite, __finite"
		size = "20"
		objfiles = "s_finite@libm.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 89 D0 25 FF FF FF 7F 2D 00 00 F0 7F C1 E8 1F C3 }
	condition:
		$pattern
}

rule bcopy_e79a9bddcac1b665c852d06cb17f5513 {
	meta:
		aliases = "bcopy"
		size = "21"
		objfiles = "bcopy@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 8B 44 24 04 89 44 24 08 89 54 24 04 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _obstack_allocated_p_5e50d0b9e479c150a51c2772def87ab6 {
	meta:
		aliases = "_obstack_allocated_p"
		size = "32"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 8B 44 24 04 8B 40 04 85 C0 74 08 39 D0 73 F5 39 10 72 F1 85 C0 0F 95 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule pthread_attr_setstacksize_b6965425ae27b0150c591b7fc658a2d7 {
	meta:
		aliases = "__pthread_attr_setstacksize, pthread_attr_setstacksize"
		size = "27"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 B8 16 00 00 00 81 FA FF 3F 00 00 76 09 8B 44 24 04 89 50 20 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_mutexattr_setpshared_e2e13198bfa7a09b07b01a90b52bdfa4 {
	meta:
		aliases = "pthread_condattr_setpshared, __pthread_mutexattr_setpshared, pthread_mutexattr_setpshared"
		size = "22"
		objfiles = "condvar@libpthread.a, mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 B8 16 00 00 00 83 FA 01 77 07 19 C0 F7 D0 83 E0 26 C3 }
	condition:
		$pattern
}

rule pthread_attr_setdetachstate_7d2bf4c3248c20b172c5bb9a6c21fd7c {
	meta:
		aliases = "__GI_pthread_attr_setdetachstate, pthread_rwlockattr_setkind_np, pthread_attr_setdetachstate"
		size = "23"
		objfiles = "rwlock@libpthread.a, attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 B8 16 00 00 00 83 FA 01 77 08 8B 44 24 04 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_rwlockattr_setpshared_c2041dd93d21e27f9e9f1907bbb7c96b {
	meta:
		aliases = "pthread_rwlockattr_setpshared"
		size = "24"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 B8 16 00 00 00 83 FA 01 77 09 8B 44 24 04 89 50 04 31 C0 C3 }
	condition:
		$pattern
}

rule __GI_pthread_attr_setinheritsc_ef355c139453c5b28a7b300640a40178 {
	meta:
		aliases = "pthread_attr_setinheritsched, __GI_pthread_attr_setinheritsched"
		size = "24"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 B8 16 00 00 00 83 FA 01 77 09 8B 44 24 04 89 50 0C 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_attr_setschedpolicy_3f713cd82669e1afbef6384c0d61c4a9 {
	meta:
		aliases = "__GI_pthread_attr_setschedpolicy, pthread_attr_setschedpolicy"
		size = "24"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 B8 16 00 00 00 83 FA 02 77 09 8B 44 24 04 89 50 04 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_mutexattr_settype_c966b71060253b953a535d91cc13d1cf {
	meta:
		aliases = "__pthread_mutexattr_settype, pthread_mutexattr_setkind_np, __pthread_mutexattr_setkind_np, pthread_mutexattr_settype"
		size = "23"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 B8 16 00 00 00 83 FA 03 77 08 8B 44 24 04 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule re_set_syntax_d334f8e170de709da20dbec8f104bb34 {
	meta:
		aliases = "__re_set_syntax, re_set_syntax"
		size = "16"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | A1 ) ?? ?? ?? ?? 8B 54 24 04 89 15 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __getpagesize_1aa5a313fb0e75d8095bb092c574fd16 {
	meta:
		aliases = "getpagesize, __GI_getpagesize, __getpagesize"
		size = "19"
		objfiles = "getpagesize@libc.a"
	strings:
		$pattern = { ( CC | A1 ) ?? ?? ?? ?? BA 00 10 00 00 85 C0 74 02 89 C2 89 D0 C3 }
	condition:
		$pattern
}

rule old_sem_extricate_func_62dea3be98d084788202ec199cbcebf6 {
	meta:
		aliases = "__GI__stdlib_mb_cur_max, authnone_validate, __GI_xdr_void, _stdlib_mb_cur_max, xdr_void, old_sem_extricate_func"
		size = "6"
		objfiles = "_stdlib_mb_cur_max@libc.a, auth_none@libc.a, oldsemaphore@libpthread.a, xdr@libc.a"
	strings:
		$pattern = { ( CC | B8 ) 01 00 00 00 C3 }
	condition:
		$pattern
}

rule svcudp_stat_cca2f00a582595d7f5454d6d2948b3e3 {
	meta:
		aliases = "rendezvous_stat, svcraw_stat, _svcauth_short, svcudp_stat"
		size = "6"
		objfiles = "svc_authux@libc.a, svc_raw@libc.a, svc_tcp@libc.a, svc_udp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | B8 ) 02 00 00 00 C3 }
	condition:
		$pattern
}

rule rpc_thread_multi_4eb704be6009cc7748903d2a16f38407 {
	meta:
		aliases = "rpc_thread_multi"
		size = "45"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | B8 ) ?? ?? ?? ?? 83 EC 0C 85 C0 74 13 50 50 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? 83 C4 10 EB 0A C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule localeconv_8c4e2f0553461534b2f97513db4347e7 {
	meta:
		aliases = "__GI_localeconv, localeconv"
		size = "53"
		objfiles = "localeconv@libc.a"
	strings:
		$pattern = { ( CC | B8 ) ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 83 C0 04 3D ?? ?? ?? ?? C7 00 ?? ?? ?? ?? 72 F0 B8 ?? ?? ?? ?? C6 00 7F 40 3D ?? ?? ?? ?? 76 F5 B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule clone_8ef3be04e211ed0fcf605010e196ea48 {
	meta:
		aliases = "clone"
		size = "108"
		objfiles = "clone@libc.a"
	strings:
		$pattern = { ( CC | B8 ) EA FF FF FF 8B 4C 24 04 85 C9 74 5A 8B 4C 24 08 85 C9 74 52 83 E1 F0 83 E9 1C 8B 44 24 10 89 41 0C 8B 44 24 04 89 41 08 C7 41 04 00 00 00 00 C7 01 00 00 00 00 53 56 57 8B 74 24 24 8B 54 24 20 8B 5C 24 18 8B 7C 24 28 B8 78 00 00 00 CD 80 5F 5E 5B 85 C0 7C 10 74 01 C3 89 F5 FF D3 89 C3 B8 01 00 00 00 CD 80 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule atexit_c7012cf53c9ab3bab3043d61798c8164 {
	meta:
		aliases = "atexit"
		size = "35"
		objfiles = "atexit@libc.a"
	strings:
		$pattern = { ( CC | BA ) ?? ?? ?? ?? 83 EC 0C 85 D2 74 06 8B 15 ?? ?? ?? ?? 50 52 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __md5_Init_8e121a7e9e17edad5669c991716c95fb {
	meta:
		aliases = "__md5_Init"
		size = "42"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | C7 ) 40 14 00 00 00 00 C7 40 10 00 00 00 00 C7 00 01 23 45 67 C7 40 04 89 AB CD EF C7 40 08 FE DC BA 98 C7 40 0C 76 54 32 10 C3 }
	condition:
		$pattern
}

rule difftime_eee53188a5d0022713b18094cf9e7408 {
	meta:
		aliases = "difftime"
		size = "11"
		objfiles = "difftime@libc.a"
	strings:
		$pattern = { ( CC | DB ) 44 24 04 DB 44 24 08 DE E9 C3 }
	condition:
		$pattern
}

rule __GI___fma_394493ef54a844d9006d78ae6390ed25 {
	meta:
		aliases = "__fma, __GI_fma, __GI___fma"
		size = "13"
		objfiles = "s_fma@libm.a"
	strings:
		$pattern = { ( CC | DD ) 44 24 0C DC 4C 24 04 DC 44 24 14 C3 }
	condition:
		$pattern
}

rule carg_4aef79cd6c2785d18b6a685d2b1fd7ee {
	meta:
		aliases = "__GI_carg, carg"
		size = "21"
		objfiles = "carg@libm.a"
	strings:
		$pattern = { ( CC | DD ) 44 24 0C DD 44 24 04 DD 5C 24 0C DD 5C 24 04 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fetestexcept_82bad7d8bdca270f1e3e172d05c36c8d {
	meta:
		aliases = "fetestexcept"
		size = "10"
		objfiles = "ftestexcept@libm.a"
	strings:
		$pattern = { ( CC | DF ) E0 23 44 24 04 83 E0 3D C3 }
	condition:
		$pattern
}

rule __GI_pthread_self_5daf75c711fb4c0b7a9c42ce329f9df7 {
	meta:
		aliases = "pthread_self, __GI_pthread_self"
		size = "9"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | E8 ) ?? ?? ?? ?? 8B 40 10 C3 }
	condition:
		$pattern
}

