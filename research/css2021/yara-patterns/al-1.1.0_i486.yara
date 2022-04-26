// YARA rules, version 0.2.0_2021_07_29


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

rule eq_pointer_c11f863d6be2c66fb42fa0367477969e {
	meta:
		aliases = "eq_pointer"
		type = "func"
		size = "9"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 31 ) C0 48 39 F7 0F 94 C0 C3 }
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

rule _setjmp_86a04ba6e89ace15ef2af6c36c199d43 {
	meta:
		aliases = "_setjmp"
		type = "func"
		size = "34"
		objfiles = "bsd__setjmp@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C0 8B 54 24 04 89 1A 89 72 04 89 7A 08 8D 4C 24 04 89 4A 10 8B 0C 24 89 4A 14 89 6A 0C 89 42 18 C3 }
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
		aliases = "__GI_pthread_attr_destroy, __GI_pthread_condattr_destroy, __GI_pthread_condattr_init, __pthread_mutex_init, __pthread_mutex_lock, __pthread_mutex_trylock, __pthread_mutex_unlock, __pthread_mutexattr_destroy, __pthread_return_0, _svcauth_null, authnone_refresh, clntraw_control, grantpt, pthread_attr_destroy, pthread_condattr_destroy, pthread_condattr_init, pthread_mutexattr_destroy, pthread_rwlockattr_destroy, wcsftime, xdrstdio_inline"
		type = "func"
		size = "3"
		objfiles = "grantpt@libc.a, clnt_raw@libc.a, svc_auth@libc.a, wcsftime@libc.a, rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) C0 C3 }
	condition:
		$pattern
}

rule isascii_4753db78c3069a1678987d120d74ebed {
	meta:
		aliases = "__GI_isascii, isascii"
		type = "func"
		size = "14"
		objfiles = "isascii@libc.a"
	strings:
		$pattern = { ( CC | 31 ) C0 F7 44 24 04 80 FF FF FF 0F 94 C0 C3 }
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

rule rwlock_can_rdlock_00459d34c82a6341972a31ccaa7aa14e {
	meta:
		aliases = "rwlock_can_rdlock"
		type = "func"
		size = "37"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) C9 83 78 0C 00 75 1A 83 78 18 00 74 0F 83 78 14 00 74 09 31 C9 85 D2 0F 95 C1 EB 05 B9 01 00 00 00 89 C8 C3 }
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

rule sem_destroy_66ac37ed6944e6782eff71e1fca99447 {
	meta:
		aliases = "__new_sem_destroy, sem_destroy"
		type = "func"
		size = "29"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) D2 8B 44 24 04 83 78 0C 00 74 0E E8 ?? ?? ?? ?? C7 00 10 00 00 00 83 CA FF 89 D0 C3 }
	condition:
		$pattern
}

rule __old_sem_destroy_67e8b1c5157f62197c45f0faecb1f6cf {
	meta:
		aliases = "__old_sem_destroy"
		type = "func"
		size = "28"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) D2 8B 44 24 04 F6 00 01 75 0E E8 ?? ?? ?? ?? C7 00 10 00 00 00 83 CA FF 89 D0 C3 }
	condition:
		$pattern
}

rule __pthread_manager_event_dd3c14fa9e05fdcf0638fc1de0afc815 {
	meta:
		aliases = "__pthread_manager_event"
		type = "func"
		size = "32"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 31 ) D2 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 74 24 08 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _start_a74091ded31fe9341c86ffba27b8ff00 {
	meta:
		aliases = "_start"
		type = "func"
		size = "34"
		objfiles = "crt1"
	strings:
		$pattern = { ( CC | 31 ) ED 5E 89 E1 83 E4 F0 50 54 52 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 51 56 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? F4 }
	condition:
		$pattern
}

rule _start_8e5893c191f185e234a418a5dd8add5d {
	meta:
		aliases = "_start"
		type = "func"
		size = "49"
		objfiles = "Scrt1"
	strings:
		$pattern = { ( CC | 31 ) ED 5E 89 E1 83 E4 F0 50 54 52 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? FF B3 ?? ?? ?? ?? FF B3 ?? ?? ?? ?? 51 56 FF B3 ?? ?? ?? ?? E8 ?? ?? ?? ?? F4 }
	condition:
		$pattern
}

rule ascii_to_bin_706e527a7d3cdb9228ce2b71457f6f6e {
	meta:
		aliases = "ascii_to_bin"
		type = "func"
		size = "48"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 3C ) 7A 77 29 3C 60 76 07 0F B6 C0 83 E8 3B C3 3C 5A 77 1A 3C 40 76 07 0F B6 C0 83 E8 35 C3 3C 39 77 0B 3C 2D 76 07 0F B6 C0 83 E8 2E C3 31 C0 C3 }
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

rule C_alloca_7daf787fabc37e28a99f8d671c171564 {
	meta:
		aliases = "C_alloca"
		type = "func"
		size = "157"
		objfiles = "alloca@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 53 48 83 EC 10 48 8B 3D ?? ?? ?? ?? 48 85 FF 74 27 48 8D 6C 24 0F 48 39 6F 08 72 0F EB 6F 0F 1F 40 00 48 39 6B 08 73 12 48 89 DF 48 8B 1F E8 ?? ?? ?? ?? 48 85 DB 75 EA 31 DB 4D 85 E4 48 89 1D ?? ?? ?? ?? 74 3C 49 8D 7C 24 10 E8 ?? ?? ?? ?? 48 85 C0 74 3D 48 8B 15 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 83 C0 10 48 89 50 F0 48 8D 54 24 0F 48 89 50 F8 48 83 C4 10 5B 5D 41 5C C3 0F 1F 44 00 00 48 83 C4 10 31 C0 5B 5D 41 5C C3 48 89 FB EB A8 E8 ?? ?? ?? ?? }
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

rule xre_set_syntax_26e7b8d8a92ed76c586f2e06d4795b45 {
	meta:
		aliases = "xre_set_syntax"
		type = "func"
		size = "15"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 48 89 3D ?? ?? ?? ?? C3 }
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

rule htab_size_7a346892aa6f48c113696b74d69cab29 {
	meta:
		aliases = "htab_size"
		type = "func"
		size = "5"
		objfiles = "hashtab@libiberty.a"
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

rule suspend_7e7c6eb2f9410c7059cbbed1cb6911cf {
	meta:
		aliases = "restart, suspend"
		type = "func"
		size = "8"
		objfiles = "rwlock@libpthread.a, spinlock@libpthread.a, semaphore@libpthread.a, manager@libpthread.a, pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 50 ) E8 ?? ?? ?? ?? 58 C3 }
	condition:
		$pattern
}

rule restart_3fbab53a4950c8a5ffabe663afbf1237 {
	meta:
		aliases = "restart"
		type = "func"
		size = "8"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 50 ) E8 ?? ?? ?? ?? 59 C3 }
	condition:
		$pattern
}

rule restart_83f4df226a0b24d9da08621b3266c0dc {
	meta:
		aliases = "restart"
		type = "func"
		size = "8"
		objfiles = "rwlock@libpthread.a, condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 50 ) E8 ?? ?? ?? ?? 5A C3 }
	condition:
		$pattern
}

rule setup_salt_9da7ec327de282aae6c3f3edb1ca637e {
	meta:
		aliases = "setup_salt"
		type = "func"
		size = "60"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 53 ) 3B 05 ?? ?? ?? ?? 74 31 A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 31 DB B9 00 00 80 00 BA 01 00 00 00 EB 0F 85 D0 74 06 09 0D ?? ?? ?? ?? 01 D2 D1 E9 43 83 FB 17 7E EC 5B C3 }
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

rule sync_file_range_3d06f6540ffb5ed30dae4106a5a12f4e {
	meta:
		aliases = "__GI_sync_file_range, sync_file_range"
		type = "func"
		size = "51"
		objfiles = "sync_file_range@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 56 57 55 B8 3A 01 00 00 8B 5C 24 14 8B 4C 24 18 8B 54 24 1C 8B 74 24 20 8B 7C 24 24 8B 6C 24 28 CD 80 5D 5F 5E 5B 3D 00 F0 FF FF 0F 87 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule pthread_key_create_d46bd0fa5e0d66ba67d84802de0347c8 {
	meta:
		aliases = "pthread_key_create"
		type = "func"
		size = "95"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 DB 58 EB 35 83 3C DD ?? ?? ?? ?? 00 75 2A C7 04 DD ?? ?? ?? ?? 01 00 00 00 8B 44 24 0C 89 04 DD ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 0C 89 18 31 C0 EB 18 43 81 FB FF 03 00 00 7E C3 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 0B 00 00 00 5B 5B C3 }
	condition:
		$pattern
}

rule __GI_config_open_af70835cbd0acc627fecb900c9c6ef11 {
	meta:
		aliases = "__GI_config_open"
		type = "func"
		size = "44"
		objfiles = "parse_config@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 68 ?? ?? ?? ?? FF 74 24 0C E8 ?? ?? ?? ?? 89 C3 58 5A 31 C0 85 DB 74 11 6A 18 6A 01 E8 ?? ?? ?? ?? 5A 59 85 C0 74 02 89 18 5B C3 }
	condition:
		$pattern
}

rule pthread_atfork_31b6be4b8def872960d3c6561d8d9110 {
	meta:
		aliases = "pthread_atfork"
		type = "func"
		size = "103"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 6A 18 E8 ?? ?? ?? ?? 89 C3 58 B8 0C 00 00 00 85 DB 74 51 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 00 89 D9 8B 54 24 10 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4B 08 6A 01 8B 54 24 18 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4B 10 6A 01 8B 54 24 20 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 83 C4 14 5B C3 }
	condition:
		$pattern
}

rule tempnam_c25f63ab7bd3edf2b41af5ca72d68b3c {
	meta:
		aliases = "tempnam"
		type = "func"
		size = "79"
		objfiles = "tempnam@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC 00 10 00 00 FF B4 24 0C 10 00 00 FF B4 24 0C 10 00 00 68 FF 0F 00 00 8D 5C 24 0D 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 1A 6A 00 6A 03 53 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 09 53 E8 ?? ?? ?? ?? 5A EB 02 31 C0 81 C4 00 10 00 00 5B C3 }
	condition:
		$pattern
}

rule getpw_2cec64ce1c8677f1e1742128eff7a651 {
	meta:
		aliases = "getpw"
		type = "func"
		size = "158"
		objfiles = "getpw@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC 20 01 00 00 8B 9C 24 2C 01 00 00 85 DB 75 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 72 8D 84 24 1C 01 00 00 50 68 00 01 00 00 8D 44 24 08 50 8D 84 24 0C 01 00 00 50 FF B4 24 38 01 00 00 E8 ?? ?? ?? ?? 83 C4 14 85 C0 75 45 FF B4 24 18 01 00 00 FF B4 24 18 01 00 00 FF B4 24 18 01 00 00 FF B4 24 18 01 00 00 FF B4 24 18 01 00 00 FF B4 24 18 01 00 00 FF B4 24 18 01 00 00 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 24 31 D2 85 C0 79 03 83 CA FF 89 D0 81 C4 20 01 00 00 5B C3 }
	condition:
		$pattern
}

rule gethostname_b712a6ee6da4144b8344518a8cbb1bfa {
	meta:
		aliases = "__GI_gethostname, gethostname"
		type = "func"
		size = "88"
		objfiles = "gethostname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC 88 01 00 00 8D 44 24 02 50 E8 ?? ?? ?? ?? 59 83 CA FF 40 74 36 8D 5C 24 43 53 E8 ?? ?? ?? ?? 5A 40 3B 84 24 94 01 00 00 76 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CA FF EB 11 53 FF B4 24 94 01 00 00 E8 ?? ?? ?? ?? 31 D2 58 59 89 D0 81 C4 88 01 00 00 5B C3 }
	condition:
		$pattern
}

rule getdomainname_f7a619f52b083c41b855d50eb3d96e10 {
	meta:
		aliases = "__GI_getdomainname, getdomainname"
		type = "func"
		size = "91"
		objfiles = "getdomainname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC 88 01 00 00 8D 44 24 02 50 E8 ?? ?? ?? ?? 59 83 CA FF 40 74 39 8D 9C 24 47 01 00 00 53 E8 ?? ?? ?? ?? 5A 40 3B 84 24 94 01 00 00 76 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CA FF EB 11 53 FF B4 24 94 01 00 00 E8 ?? ?? ?? ?? 31 D2 58 59 89 D0 81 C4 88 01 00 00 5B C3 }
	condition:
		$pattern
}

rule hypot_40d6dc07de69a88c5b186729e931aed9 {
	meta:
		aliases = "__GI_hypot, __ieee754_hypot, hypot"
		type = "func"
		size = "738"
		objfiles = "e_hypot@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC 98 00 00 00 DD 84 24 A0 00 00 00 DD 54 24 70 8B 4C 24 74 81 E1 FF FF FF 7F DD 84 24 A8 00 00 00 DD 54 24 68 8B 54 24 6C 81 E2 FF FF FF 7F 39 CA 7E 13 DD 5C 24 78 DD 9C 24 80 00 00 00 89 D0 89 CA 89 C1 EB 1D DD D8 DD D8 DD 84 24 A0 00 00 00 DD 5C 24 78 DD 84 24 A8 00 00 00 DD 9C 24 80 00 00 00 DD 44 24 78 DD 5C 24 60 89 4C 24 64 DD 44 24 60 DD 9C 24 88 00 00 00 DD 84 24 80 00 00 00 DD 5C 24 58 89 54 24 5C DD 44 24 58 DD 94 24 90 00 00 00 89 C8 29 D0 3D 00 00 C0 03 7E 0E DD 84 24 88 00 00 00 DE C1 E9 2B 02 00 00 DD D8 31 DB 81 F9 00 00 30 5F 0F 8E 89 00 00 00 81 F9 FF FF EF 7F 7E 42 81 }
	condition:
		$pattern
}

rule get_current_dir_name_792eacb1651885c1ffdafe33d098a7e3 {
	meta:
		aliases = "get_current_dir_name"
		type = "func"
		size = "133"
		objfiles = "getdirname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC C0 00 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 58 85 DB 74 5A 8D 44 24 60 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A 59 85 C0 75 45 89 E0 50 53 E8 ?? ?? ?? ?? 5A 59 85 C0 75 36 8B 04 24 8B 54 24 04 3B 54 24 64 75 29 3B 44 24 60 75 23 8B 44 24 58 8B 54 24 5C 3B 94 24 BC 00 00 00 75 12 3B 84 24 B8 00 00 00 75 09 53 E8 ?? ?? ?? ?? 5B EB 0B 6A 00 6A 00 E8 ?? ?? ?? ?? 5A 59 81 C4 C0 00 00 00 5B C3 }
	condition:
		$pattern
}

rule __getutent_46cce8905fb9883291ad63e169d937eb {
	meta:
		aliases = "__getutent"
		type = "func"
		size = "90"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 3D ?? ?? ?? ?? 00 79 0E E8 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 78 3E 8B 1D ?? ?? ?? ?? B9 ?? ?? ?? ?? BA 80 01 00 00 89 D8 53 89 C3 B8 03 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0B E8 ?? ?? ?? ?? F7 DB 89 18 EB 0D B8 ?? ?? ?? ?? 81 FB 80 01 00 00 74 02 31 C0 5B C3 }
	condition:
		$pattern
}

rule ntp_gettime_c780063d3196b3a3c0258632ad6a1b53 {
	meta:
		aliases = "ntp_gettime"
		type = "func"
		size = "61"
		objfiles = "ntp_gettime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 C4 80 8B 9C 24 88 00 00 00 C7 04 24 00 00 00 00 89 E0 50 E8 ?? ?? ?? ?? 8B 54 24 2C 89 53 04 8B 54 24 28 89 13 8B 54 24 10 89 53 08 8B 54 24 14 89 53 0C 81 C4 84 00 00 00 5B C3 }
	condition:
		$pattern
}

rule wait_node_dequeue_23380196b25635b606f6ab6f656ac24f {
	meta:
		aliases = "wait_node_dequeue"
		type = "func"
		size = "40"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 39 C2 75 19 8B 19 89 C8 F0 0F B1 1A 0F 94 C3 84 DB 74 04 EB 0C 89 C2 8B 02 39 C1 75 F8 8B 01 89 02 58 5B C3 }
	condition:
		$pattern
}

rule __pthread_alt_trylock_af5025bd1f1c2fe7c44d6ff060de24bd {
	meta:
		aliases = "__pthread_alt_trylock"
		type = "func"
		size = "43"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 89 C1 83 39 00 74 07 B8 10 00 00 00 EB 16 BB 01 00 00 00 31 D2 89 D0 F0 0F B1 19 0F 94 C2 84 D2 74 E0 31 C0 59 5B C3 }
	condition:
		$pattern
}

rule __pthread_trylock_f807340fd021bb346f626e9679a7a5f9 {
	meta:
		aliases = "__pthread_trylock"
		type = "func"
		size = "43"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 89 C1 83 39 00 74 07 B8 10 00 00 00 EB 16 BB 01 00 00 00 31 D2 89 D0 F0 0F B1 19 0F 94 C2 84 D2 74 E0 31 C0 5A 5B C3 }
	condition:
		$pattern
}

rule set_input_fragment_df460e012c50347cb86b0c8440cfd87e {
	meta:
		aliases = "set_input_fragment"
		type = "func"
		size = "63"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 89 C3 89 E2 B9 04 00 00 00 E8 ?? ?? ?? ?? 85 C0 74 24 8B 14 24 0F CA 89 14 24 89 D0 C1 E8 1F 89 43 38 85 D2 74 10 81 E2 FF FF FF 7F 89 53 34 B8 01 00 00 00 EB 02 31 C0 5A 5B C3 }
	condition:
		$pattern
}

rule pause_822f7c73ae3ad2e452c0da2a1cde7dd2 {
	meta:
		aliases = "pause"
		type = "func"
		size = "39"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 89 E0 50 6A 01 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 6A 00 FF 74 24 0C E8 ?? ?? ?? ?? 89 D8 83 C4 14 5B C3 }
	condition:
		$pattern
}

rule wait_593d4632d655ae75a9db77d772cf7bf1 {
	meta:
		aliases = "close, fsync, system, tcdrain, wait"
		type = "func"
		size = "43"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 89 E0 50 6A 01 E8 ?? ?? ?? ?? FF 74 24 14 E8 ?? ?? ?? ?? 89 C3 6A 00 FF 74 24 10 E8 ?? ?? ?? ?? 89 D8 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule nanosleep_cfabef1ece34ce793be11fd3ac6ee861 {
	meta:
		aliases = "__GI_nanosleep, nanosleep"
		type = "func"
		size = "47"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 89 E0 50 6A 01 E8 ?? ?? ?? ?? FF 74 24 18 FF 74 24 18 E8 ?? ?? ?? ?? 89 C3 6A 00 FF 74 24 14 E8 ?? ?? ?? ?? 89 D8 83 C4 1C 5B C3 }
	condition:
		$pattern
}

rule write_966d33990ea41d94ea545ad487f15973 {
	meta:
		aliases = "__GI_waitpid, accept, connect, lseek, msync, read, recvmsg, sendmsg, waitpid, write"
		type = "func"
		size = "51"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 89 E0 50 6A 01 E8 ?? ?? ?? ?? FF 74 24 1C FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 89 C3 6A 00 FF 74 24 18 E8 ?? ?? ?? ?? 89 D8 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule send_c2940d127b00fb25b0bbd004ee5c830a {
	meta:
		aliases = "epoll_wait, pread, pwrite, recv, send"
		type = "func"
		size = "55"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 89 E0 50 6A 01 E8 ?? ?? ?? ?? FF 74 24 20 FF 74 24 20 FF 74 24 20 FF 74 24 20 E8 ?? ?? ?? ?? 89 C3 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? 89 D8 83 C4 24 5B C3 }
	condition:
		$pattern
}

rule pread64_3fd4b52564f21760479f7720c6235597 {
	meta:
		aliases = "epoll_pwait, pread64"
		type = "func"
		size = "59"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 89 E0 50 6A 01 E8 ?? ?? ?? ?? FF 74 24 24 FF 74 24 24 FF 74 24 24 FF 74 24 24 FF 74 24 24 E8 ?? ?? ?? ?? 89 C3 6A 00 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule sendto_adbb9932833bf12a98c13181fc3b9948 {
	meta:
		aliases = "recvfrom, sendto"
		type = "func"
		size = "66"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 89 E0 50 6A 01 E8 ?? ?? ?? ?? FF 74 24 28 FF 74 24 28 FF 74 24 28 FF 74 24 28 FF 74 24 28 FF 74 24 28 E8 ?? ?? ?? ?? 89 C3 83 C4 20 6A 00 FF 74 24 04 E8 ?? ?? ?? ?? 89 D8 83 C4 0C 5B C3 }
	condition:
		$pattern
}

rule shmat_539c4e301a5812ef1c2d8dfde91bcd11 {
	meta:
		aliases = "shmat"
		type = "func"
		size = "54"
		objfiles = "shmat@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 89 E0 6A 00 FF 74 24 14 50 FF 74 24 20 FF 74 24 1C 6A 15 E8 ?? ?? ?? ?? 89 C3 E8 ?? ?? ?? ?? F7 D8 83 C4 18 89 DA 39 C3 77 03 8B 14 24 89 D0 5A 5B C3 }
	condition:
		$pattern
}

rule __old_sem_trywait_f9a117d540128cbc71fb6cc950984e83 {
	meta:
		aliases = "__old_sem_trywait"
		type = "func"
		size = "57"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 8B 4C 24 0C 8B 11 F6 C2 01 74 05 83 FA 01 75 10 E8 ?? ?? ?? ?? C7 00 0B 00 00 00 83 C8 FF EB 12 8D 5A FE 89 D0 F0 0F B1 19 0F 94 C2 84 D2 74 D4 31 C0 5B 5B C3 }
	condition:
		$pattern
}

rule nextafterf_961e749b56926fbbf27780dba1c9d2ac {
	meta:
		aliases = "nextafterf"
		type = "func"
		size = "159"
		objfiles = "s_nextafterf@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 8B 4C 24 0C 8B 54 24 10 89 CB 81 E3 FF FF FF 7F 81 FB 00 00 80 7F 7F 0E 89 D0 25 FF FF FF 7F 3D 00 00 80 7F 7E 0A D9 44 24 10 D8 44 24 0C EB 4A D9 44 24 0C D9 44 24 10 D9 C9 DA E9 DF E0 9E 7A 02 74 51 85 DB 75 0B 81 E2 00 00 00 80 83 CA 01 EB 3E 85 C9 79 04 85 D2 79 04 39 D1 7E 05 8D 51 FF EB 03 8D 51 01 89 D0 25 00 00 80 7F 3D 00 00 80 7F 75 0C D9 44 24 0C D8 C0 D9 5C 24 10 EB 14 3D FF FF 7F 00 7F 09 D9 44 24 0C D8 C8 D9 1C 24 89 54 24 10 D9 44 24 10 58 5B C3 }
	condition:
		$pattern
}

rule xdr_u_long_18d060fd160240e7416349fd6006e170 {
	meta:
		aliases = "__GI_xdr_u_long, xdr_u_long"
		type = "func"
		size = "77"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 8B 4C 24 0C 8B 5C 24 10 8B 11 83 FA 01 74 0E 72 27 B8 01 00 00 00 83 FA 02 74 2B EB 27 8B 41 04 89 E2 52 51 FF 10 5A 59 85 C0 74 18 8B 04 24 89 03 B8 01 00 00 00 EB 0E 8B 41 04 53 51 FF 50 04 59 5B EB 02 31 C0 5A 5B C3 }
	condition:
		$pattern
}

rule xdr_uint8_t_c700bb70b6102e4b1f573a763c424b92 {
	meta:
		aliases = "xdr_uint8_t"
		type = "func"
		size = "86"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 8B 4C 24 0C 8B 5C 24 10 8B 11 83 FA 01 74 22 72 0C B8 01 00 00 00 83 FA 02 74 34 EB 30 0F B6 03 89 04 24 89 E0 8B 51 04 50 51 FF 52 24 5B 5A EB 1E 89 E0 8B 51 04 50 51 FF 52 20 5A 59 85 C0 74 0C 8B 04 24 88 03 B8 01 00 00 00 EB 02 31 C0 59 5B C3 }
	condition:
		$pattern
}

rule xdr_u_short_8905bcb326c22100dfa27e7c7ada0bdf {
	meta:
		aliases = "__GI_xdr_u_short, xdr_u_short"
		type = "func"
		size = "86"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 8B 4C 24 0C 8B 5C 24 10 8B 11 83 FA 01 74 22 72 0C B8 01 00 00 00 83 FA 02 74 34 EB 30 0F B7 03 89 04 24 89 E0 8B 51 04 50 51 FF 52 04 5B 5A EB 1E 89 E0 8B 51 04 50 51 FF 12 5A 59 85 C0 74 0D 8B 04 24 66 89 03 B8 01 00 00 00 EB 02 31 C0 5B 5B C3 }
	condition:
		$pattern
}

rule xdr_int8_t_ef2daf937c5a85afdec978908bd6463e {
	meta:
		aliases = "xdr_int8_t"
		type = "func"
		size = "86"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 8B 4C 24 0C 8B 5C 24 10 8B 11 83 FA 01 74 22 72 0C B8 01 00 00 00 83 FA 02 74 34 EB 30 0F BE 03 89 04 24 8B 51 04 89 E0 50 51 FF 52 24 5B 5A EB 1E 8B 41 04 89 E2 52 51 FF 50 20 5A 59 85 C0 74 0C 8B 04 24 88 03 B8 01 00 00 00 EB 02 31 C0 59 5B C3 }
	condition:
		$pattern
}

rule xdr_short_03e8595d67a843632b19b3707b0414f4 {
	meta:
		aliases = "__GI_xdr_short, xdr_short"
		type = "func"
		size = "86"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 8B 4C 24 0C 8B 5C 24 10 8B 11 83 FA 01 74 22 72 0C B8 01 00 00 00 83 FA 02 74 34 EB 30 0F BF 03 89 04 24 8B 51 04 89 E0 50 51 FF 52 04 59 5B EB 1E 8B 41 04 89 E2 52 51 FF 10 59 5A 85 C0 74 0D 8B 04 24 66 89 03 B8 01 00 00 00 EB 02 31 C0 5A 5B C3 }
	condition:
		$pattern
}

rule xdr_uint16_t_14f7ecec644e6121f585335a6e1adb23 {
	meta:
		aliases = "xdr_uint16_t"
		type = "func"
		size = "87"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 8B 4C 24 0C 8B 5C 24 10 8B 11 83 FA 01 74 22 72 0C B8 01 00 00 00 83 FA 02 74 35 EB 31 0F B7 03 89 04 24 89 E0 8B 51 04 50 51 FF 52 24 5B 5A EB 1F 89 E0 8B 51 04 50 51 FF 52 20 5A 59 85 C0 74 0D 8B 04 24 66 89 03 B8 01 00 00 00 EB 02 31 C0 59 5B C3 }
	condition:
		$pattern
}

rule xdr_int16_t_2a60b15b058ef58e6c23a090f51cc6f5 {
	meta:
		aliases = "xdr_int16_t"
		type = "func"
		size = "87"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 8B 4C 24 0C 8B 5C 24 10 8B 11 83 FA 01 74 22 72 0C B8 01 00 00 00 83 FA 02 74 35 EB 31 0F BF 03 89 04 24 8B 51 04 89 E0 50 51 FF 52 24 5B 5A EB 1F 8B 41 04 89 E2 52 51 FF 50 20 5A 59 85 C0 74 0D 8B 04 24 66 89 03 B8 01 00 00 00 EB 02 31 C0 5B 5B C3 }
	condition:
		$pattern
}

rule xdr_bool_1c35d36f053432b6ea9a4b980595b137 {
	meta:
		aliases = "__GI_xdr_bool, xdr_bool"
		type = "func"
		size = "96"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 8B 4C 24 0C 8B 5C 24 10 8B 11 83 FA 01 74 27 72 0C B8 01 00 00 00 83 FA 02 74 3E EB 3A 31 C0 83 3B 00 0F 95 C0 89 04 24 8B 51 04 89 E0 50 51 FF 52 04 5B 5A EB 23 8B 41 04 89 E2 52 51 FF 10 5A 59 85 C0 74 12 31 C0 83 3C 24 00 0F 95 C0 89 03 B8 01 00 00 00 EB 02 31 C0 5B 5B C3 }
	condition:
		$pattern
}

rule open_b001febdad687ffe67ae378f3bc7d601 {
	meta:
		aliases = "__GI_open, __libc_open, open"
		type = "func"
		size = "66"
		objfiles = "open@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 8B 4C 24 10 31 D2 F6 C1 40 74 0B 8D 44 24 18 89 04 24 8B 54 24 14 8B 44 24 0C 53 89 C3 B8 05 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 5B C3 }
	condition:
		$pattern
}

rule ioctl_7e351bfc56b54f9bed0f69a813eb2679 {
	meta:
		aliases = "__GI_ioctl, ioctl"
		type = "func"
		size = "59"
		objfiles = "ioctl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 8B 4C 24 10 8D 44 24 18 89 04 24 8B 54 24 14 8B 44 24 0C 53 89 C3 B8 36 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 5B C3 }
	condition:
		$pattern
}

rule fcntl64_8b863a195b65166308d9e6b45aa5501d {
	meta:
		aliases = "__GI_fcntl64, fcntl64"
		type = "func"
		size = "59"
		objfiles = "__syscall_fcntl64@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 8B 4C 24 10 8D 44 24 18 89 04 24 8B 54 24 14 8B 44 24 0C 53 89 C3 B8 DD 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 5B C3 }
	condition:
		$pattern
}

rule __fcntl_nocancel_16b20a95567aa07cbf790921c9d45b2e {
	meta:
		aliases = "__GI___fcntl_nocancel, __fcntl_nocancel"
		type = "func"
		size = "84"
		objfiles = "__syscall_fcntl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 8B 4C 24 10 8D 44 24 18 89 04 24 8B 54 24 14 8D 41 F4 83 F8 02 77 11 8B 44 24 0C 53 89 C3 B8 DD 00 00 00 CD 80 5B EB 0F 8B 44 24 0C 53 89 C3 B8 37 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 59 5B C3 }
	condition:
		$pattern
}

rule fcntl_76652a2735a2b958640d7575b4657042 {
	meta:
		aliases = "__GI___libc_fcntl, __GI_fcntl, __libc_fcntl, fcntl"
		type = "func"
		size = "84"
		objfiles = "__syscall_fcntl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 8B 4C 24 10 8D 44 24 18 89 04 24 8B 54 24 14 8D 41 F4 83 F8 02 77 11 8B 44 24 0C 53 89 C3 B8 DD 00 00 00 CD 80 5B EB 0F 8B 44 24 0C 53 89 C3 B8 37 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 5B C3 }
	condition:
		$pattern
}

rule __pthread_manager_adjust_prio_48f8acf8e80d0c29fcc757812287a316 {
	meta:
		aliases = "__pthread_manager_adjust_prio"
		type = "func"
		size = "66"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 8B 5C 24 0C 3B 1D ?? ?? ?? ?? 7E 2F 6A 01 E8 ?? ?? ?? ?? 5A 39 C3 0F 9C C0 0F B6 C0 8D 04 03 89 04 24 89 E0 50 6A 01 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 1D ?? ?? ?? ?? 83 C4 0C 58 5B C3 }
	condition:
		$pattern
}

rule getc_unlocked_e8150f2fa63846a8bbb3e1cc896ad04e {
	meta:
		aliases = "__GI___fgetc_unlocked, __GI_fgetc_unlocked, __GI_getc_unlocked, __fgetc_unlocked, fgetc_unlocked, getc_unlocked"
		type = "func"
		size = "204"
		objfiles = "fgetc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 8B 5C 24 0C 8B 43 10 3B 43 18 0F 82 8C 00 00 00 0F B7 03 25 83 00 00 00 3D 80 00 00 00 77 15 68 80 00 00 00 53 E8 ?? ?? ?? ?? 5A 59 85 C0 0F 85 8C 00 00 00 8B 0B 0F B7 D1 F6 C2 02 74 19 83 E2 01 8A 54 93 24 8D 41 FF 66 89 03 C7 43 28 00 00 00 00 0F B6 D2 EB 6C 8B 43 10 39 43 14 75 3D 83 7B 04 FE 75 08 83 C9 04 66 89 0B EB 53 80 E6 03 74 0B 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 8B 43 08 39 43 0C 74 20 89 43 18 53 E8 ?? ?? ?? ?? 59 85 C0 74 2D 8B 43 14 89 43 18 8B 43 10 0F B6 10 40 89 43 10 EB 1E 6A 01 8D 44 24 07 50 53 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 07 0F B6 54 24 03 EB 03 83 CA FF 89 }
	condition:
		$pattern
}

rule xdr_char_65d0e7954b07e3df222353585ed9b874 {
	meta:
		aliases = "xdr_char"
		type = "func"
		size = "46"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 8B 5C 24 10 0F B6 03 89 04 24 89 E0 50 FF 74 24 10 E8 ?? ?? ?? ?? 5A 59 31 D2 85 C0 74 07 8B 04 24 88 03 B2 01 89 D0 59 5B C3 }
	condition:
		$pattern
}

rule xdr_u_char_0d059ed51640fd4ed08f050b41919dbc {
	meta:
		aliases = "xdr_u_char"
		type = "func"
		size = "46"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 8B 5C 24 10 0F B6 03 89 04 24 89 E0 50 FF 74 24 10 E8 ?? ?? ?? ?? 5A 59 31 D2 85 C0 74 07 8B 04 24 88 03 B2 01 89 D0 5B 5B C3 }
	condition:
		$pattern
}

rule memcmp_bytes_14ed3635c44c0407e1232abf3828ce6a {
	meta:
		aliases = "memcmp_bytes"
		type = "func"
		size = "35"
		objfiles = "memcmp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 89 44 24 04 89 14 24 8D 5C 24 04 89 E1 0F B6 03 0F B6 11 43 41 39 D0 74 F4 29 D0 5A 59 5B C3 }
	condition:
		$pattern
}

rule pause_8df412fe61ee045ec354f08819d7362b {
	meta:
		aliases = "__libc_pause, pause"
		type = "func"
		size = "27"
		objfiles = "pause@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 89 E3 53 6A 00 6A 00 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule sigrelse_5e4987a68d7b81f344dc4555a7641c11 {
	meta:
		aliases = "sighold, sigrelse"
		type = "func"
		size = "57"
		objfiles = "sigrelse@libc.a, sighold@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 89 E3 53 6A 00 6A 02 E8 ?? ?? ?? ?? FF 74 24 1C 53 E8 ?? ?? ?? ?? 83 C4 14 83 CA FF 85 C0 78 0F 6A 00 53 6A 02 E8 ?? ?? ?? ?? 89 C2 83 C4 0C 89 D0 5A 59 5B C3 }
	condition:
		$pattern
}

rule getrlimit64_9f6e4980695dbd8ce0ddb02315d8c791 {
	meta:
		aliases = "getrlimit64"
		type = "func"
		size = "104"
		objfiles = "getrlimit64@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 14 89 E0 50 FF 74 24 14 E8 ?? ?? ?? ?? 5A 59 83 CA FF 85 C0 78 45 8B 04 24 83 F8 FF 75 0F C7 03 FF FF FF FF C7 43 04 FF FF FF FF EB 09 89 03 C7 43 04 00 00 00 00 8B 44 24 04 83 F8 FF 75 10 C7 43 08 FF FF FF FF C7 43 0C FF FF FF FF EB 0A 89 43 08 C7 43 0C 00 00 00 00 31 D2 89 D0 5A 59 5B C3 }
	condition:
		$pattern
}

rule open64_8c90e6ff205b5f5400c2e16316f751d2 {
	meta:
		aliases = "fcntl, open, open64"
		type = "func"
		size = "61"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8D 44 24 04 50 6A 01 E8 ?? ?? ?? ?? 8D 44 24 24 89 44 24 08 FF 74 24 20 FF 74 24 20 FF 74 24 20 E8 ?? ?? ?? ?? 89 C3 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? 89 D8 83 C4 24 5B C3 }
	condition:
		$pattern
}

rule __fpclassify_e4a69a8c76f26553ec406da8d3337a33 {
	meta:
		aliases = "__GI___fpclassify, __fpclassify"
		type = "func"
		size = "70"
		objfiles = "s_fpclassify@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 DD 44 24 10 DD 1C 24 8B 44 24 04 89 C2 81 E2 FF FF 0F 00 0B 14 24 25 00 00 F0 7F B9 02 00 00 00 89 D3 09 C3 74 16 B1 03 85 C0 74 10 B1 04 3D 00 00 F0 7F 75 07 31 C9 85 D2 0F 94 C1 89 C8 5A 59 5B C3 }
	condition:
		$pattern
}

rule tanh_02e0bca13156d6a73b9ff3b785357bd4 {
	meta:
		aliases = "__GI_tanh, tanh"
		type = "func"
		size = "200"
		objfiles = "s_tanh@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 DD 44 24 10 DD 1C 24 8B 5C 24 04 89 D8 25 FF FF FF 7F 3D FF FF EF 7F 7E 22 85 DB 78 0F D9 E8 DD 44 24 10 D8 F9 DE C1 E9 94 00 00 00 D9 E8 DD 44 24 10 D8 F9 DE E1 E9 85 00 00 00 3D FF FF 35 40 7E 04 D9 E8 EB 74 3D FF FF 7F 3C 7F 10 DD 44 24 10 DC 05 ?? ?? ?? ?? DC 4C 24 10 EB 63 3D FF FF EF 3F 7E 2B FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? D8 C0 DD 1C 24 E8 ?? ?? ?? ?? D8 05 ?? ?? ?? ?? D8 3D ?? ?? ?? ?? DC 05 ?? ?? ?? ?? EB 29 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? D8 0D ?? ?? ?? ?? DD 1C 24 E8 ?? ?? ?? ?? D9 C0 D9 E0 D9 C9 D8 05 ?? ?? ?? ?? DE F9 59 58 85 DB 79 02 D9 E0 58 5A 5B C3 }
	condition:
		$pattern
}

rule forkpty_6bedad1d44a7e459af7017c830da06fc {
	meta:
		aliases = "forkpty"
		type = "func"
		size = "114"
		objfiles = "forkpty@libutil.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 FF 74 24 1C FF 74 24 1C FF 74 24 1C 8D 44 24 0C 50 8D 44 24 14 50 E8 ?? ?? ?? ?? 83 C4 14 40 74 44 E8 ?? ?? ?? ?? 89 C3 83 F8 FF 74 38 85 C0 75 1F FF 74 24 04 E8 ?? ?? ?? ?? FF 74 24 04 E8 ?? ?? ?? ?? 5A 59 85 C0 74 1F 6A 01 E8 ?? ?? ?? ?? 8B 54 24 04 8B 44 24 10 89 10 FF 34 24 E8 ?? ?? ?? ?? 58 EB 03 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule mbrtowc_50d57e561b7f036e75864a73a71c7493 {
	meta:
		aliases = "__GI_mbrtowc, mbrtowc"
		type = "func"
		size = "119"
		objfiles = "mbrtowc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 0C 8B 5C 24 14 8B 44 24 18 8B 54 24 20 85 D2 75 05 BA ?? ?? ?? ?? 85 C0 75 0D C6 44 24 0B 00 31 DB 8D 44 24 0B EB 18 80 38 00 75 0C 85 DB 74 3B C7 03 00 00 00 00 EB 33 83 7C 24 1C 00 74 2C 89 04 24 52 6A 01 6A FF 8D 44 24 0C 50 8D 44 24 14 50 E8 ?? ?? ?? ?? 89 C2 83 C4 14 85 C0 78 0E 85 DB 74 0A 8B 44 24 04 89 03 EB 02 31 D2 89 D0 83 C4 0C 5B C3 }
	condition:
		$pattern
}

rule getmntent_63ace6badde1a3ff436e389f43aaea4c {
	meta:
		aliases = "getmntent"
		type = "func"
		size = "117"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 3D ?? ?? ?? ?? 00 75 19 68 00 10 00 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 5A 85 C0 75 05 E8 ?? ?? ?? ?? 68 00 10 00 00 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 24 E8 ?? ?? ?? ?? 89 C3 6A 01 8D 44 24 14 50 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule __new_exitfn_80fafb6d5d2b6b77fa8adfdc6e30f4ee {
	meta:
		aliases = "__new_exitfn"
		type = "func"
		size = "165"
		objfiles = "__exit_handler@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? A1 ?? ?? ?? ?? 40 83 C4 10 39 C2 7D 37 C1 E2 04 8D 82 40 01 00 00 50 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 58 5A 85 DB 75 0D E8 ?? ?? ?? ?? C7 00 0C 00 00 00 EB 33 89 1D ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 14 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? A1 ?? ?? ?? ?? 89 C3 C1 E3 04 03 1D ?? ?? ?? ?? 40 A3 ?? ?? ?? ?? C7 03 01 00 00 00 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 89 D8 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule closelog_23791260e74c0b92bcf3be285ce9d292 {
	meta:
		aliases = "__GI_closelog, closelog"
		type = "func"
		size = "54"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? 6A 01 53 E8 ?? ?? ?? ?? 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule srandom_5a55eb0b773ad73123d997030b6cebe4 {
	meta:
		aliases = "srand, srandom"
		type = "func"
		size = "61"
		objfiles = "random@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 2C E8 ?? ?? ?? ?? 6A 01 53 E8 ?? ?? ?? ?? 83 C4 30 5B C3 }
	condition:
		$pattern
}

rule sethostent_aac1a747a710c7eee59575d6da7e36c5 {
	meta:
		aliases = "sethostent"
		type = "func"
		size = "64"
		objfiles = "gethostent_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 7C 24 18 00 74 07 C6 05 ?? ?? ?? ?? 01 6A 01 53 E8 ?? ?? ?? ?? 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule endutent_70c6068737b28cf95734faeb1f4e4162 {
	meta:
		aliases = "__GI_endutent, endutent"
		type = "func"
		size = "81"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 83 C4 10 85 C9 78 0B 87 CB B8 06 00 00 00 CD 80 87 CB C7 05 ?? ?? ?? ?? FF FF FF FF 6A 01 53 E8 ?? ?? ?? ?? 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule openlog_10fce32c1354f36a1840c8dbec88fc81 {
	meta:
		aliases = "__GI_openlog, openlog"
		type = "func"
		size = "64"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 4C 24 30 8B 54 24 2C 8B 44 24 28 E8 ?? ?? ?? ?? 6A 01 53 E8 ?? ?? ?? ?? 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule setprotoent_d93becebaefdfd2ceefb5b3142a474bd {
	meta:
		aliases = "__GI_setnetent, __GI_setprotoent, setnetent, setprotoent"
		type = "func"
		size = "96"
		objfiles = "getnet@libc.a, getproto@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 07 50 E8 ?? ?? ?? ?? 58 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 58 83 7C 24 18 00 74 07 C6 05 ?? ?? ?? ?? 01 6A 01 53 E8 ?? ?? ?? ?? 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule setservent_9909a840373615e6c5b8eede40b1e246 {
	meta:
		aliases = "__GI_setservent, setservent"
		type = "func"
		size = "96"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 07 50 E8 ?? ?? ?? ?? 58 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 59 83 7C 24 18 00 74 07 C6 05 ?? ?? ?? ?? 01 6A 01 53 E8 ?? ?? ?? ?? 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule setspent_ce98578a56224f5e1c929d87665c5432 {
	meta:
		aliases = "setgrent, setpwent, setspent"
		type = "func"
		size = "66"
		objfiles = "getgrent_r@libc.a, getpwent_r@libc.a, getspent_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 07 50 E8 ?? ?? ?? ?? 58 6A 01 53 E8 ?? ?? ?? ?? 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule endspent_e4fcc5f576143fdc424c02508d9d3fe1 {
	meta:
		aliases = "endgrent, endpwent, endspent"
		type = "func"
		size = "76"
		objfiles = "getgrent_r@libc.a, getpwent_r@libc.a, getspent_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 11 50 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 58 6A 01 53 E8 ?? ?? ?? ?? 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule endprotoent_a4fe55b18bbe578f070411ce5006e39f {
	meta:
		aliases = "__GI_endnetent, __GI_endprotoent, endnetent, endprotoent"
		type = "func"
		size = "83"
		objfiles = "getnet@libc.a, getproto@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 11 50 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 59 C6 05 ?? ?? ?? ?? 00 6A 01 53 E8 ?? ?? ?? ?? 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule endservent_f32607158fabbe08179333c5ee2ef86e {
	meta:
		aliases = "__GI_endservent, endservent"
		type = "func"
		size = "83"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 11 50 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 5A C6 05 ?? ?? ?? ?? 00 6A 01 53 E8 ?? ?? ?? ?? 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule setutent_11fafa420a8fa2ce780158be4170bf2c {
	meta:
		aliases = "__GI_setutent, endhostent, setutent"
		type = "func"
		size = "52"
		objfiles = "gethostent_r@libc.a, utent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 01 53 E8 ?? ?? ?? ?? 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule clearenv_b05377ffc223db4fe9f717d1233fda2c {
	meta:
		aliases = "clearenv"
		type = "func"
		size = "80"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 6A 01 53 E8 ?? ?? ?? ?? 31 C0 83 C4 2C 5B C3 }
	condition:
		$pattern
}

rule pututline_4452f045837fc25448cc70baa91c5283 {
	meta:
		aliases = "__GI_pututline, pututline"
		type = "func"
		size = "151"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 8B 5C 24 18 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 01 68 80 FE FF FF FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 D8 E8 ?? ?? ?? ?? 83 C4 1C 85 C0 74 09 6A 01 68 80 FE FF FF EB 04 6A 02 6A 00 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 68 80 01 00 00 53 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 3D 80 01 00 00 0F 94 C0 0F B6 C0 F7 D8 21 C3 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 89 D8 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule utmpname_4b273939c2f8560e53b6cbf0007a224f {
	meta:
		aliases = "__GI_utmpname, utmpname"
		type = "func"
		size = "140"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 8B 5C 24 18 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 DB 74 2D A1 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 07 50 E8 ?? ?? ?? ?? 59 53 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 5A 85 C0 75 0A C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 85 C9 78 15 87 CB B8 06 00 00 00 CD 80 87 CB C7 05 ?? ?? ?? ?? FF FF FF FF 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 31 C0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule ftime_fcd198517bff791d607b8574b12ff386 {
	meta:
		aliases = "ftime"
		type = "func"
		size = "73"
		objfiles = "ftime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 8B 5C 24 18 89 E0 50 8D 44 24 0C 50 E8 ?? ?? ?? ?? 8B 44 24 10 89 03 8B 44 24 14 05 E7 03 00 00 BA E8 03 00 00 89 D1 99 F7 F9 66 89 43 04 8B 44 24 08 66 89 43 06 8B 44 24 0C 66 89 43 08 31 C0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule mallopt_85526a5cdb499eca0bcb9006e4d6afb0 {
	meta:
		aliases = "mallopt"
		type = "func"
		size = "175"
		objfiles = "mallopt@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 8B 5C 24 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 14 8B 44 24 18 83 C0 04 83 F8 05 77 5B FF 24 85 ?? ?? ?? ?? 83 FB 50 77 4F BA 08 00 00 00 85 DB 74 0F 8D 43 0B B2 10 83 F8 0F 76 05 89 C2 83 E2 F8 A1 ?? ?? ?? ?? 83 E0 03 09 C2 89 15 ?? ?? ?? ?? EB 16 89 1D ?? ?? ?? ?? EB 0E 89 1D ?? ?? ?? ?? EB 06 89 1D ?? ?? ?? ?? BB 01 00 00 00 EB 0A 89 1D ?? ?? ?? ?? EB F1 31 DB 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 89 D8 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule gethostent_r_851ea925ba67f4db77298336aa6ceb65 {
	meta:
		aliases = "__GI_gethostent_r, gethostent_r"
		type = "func"
		size = "149"
		objfiles = "gethostent_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 8B 5C 24 24 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 3D ?? ?? ?? ?? 00 75 1B E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 85 C0 75 0D C7 03 00 00 00 00 BB 02 00 00 00 EB 35 FF 74 24 28 53 FF 74 24 28 FF 74 24 28 FF 74 24 28 6A 01 6A 02 6A 00 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 83 C4 24 80 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 89 D8 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule system_8ecfb275c1be1db014de920f648b5dda {
	meta:
		aliases = "__libc_system, system"
		type = "func"
		size = "270"
		objfiles = "system@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 B8 01 00 00 00 83 7C 24 18 00 0F 84 F5 00 00 00 6A 01 6A 03 E8 ?? ?? ?? ?? 89 44 24 08 6A 01 6A 02 E8 ?? ?? ?? ?? 89 44 24 14 6A 00 6A 11 E8 ?? ?? ?? ?? 89 44 24 20 E8 ?? ?? ?? ?? 89 C3 83 C4 18 83 F8 00 7D 28 FF 34 24 6A 03 E8 ?? ?? ?? ?? FF 74 24 0C 6A 02 E8 ?? ?? ?? ?? FF 74 24 18 6A 11 E8 ?? ?? ?? ?? 83 C8 FF E9 94 00 00 00 75 3F 6A 00 6A 03 E8 ?? ?? ?? ?? 6A 00 6A 02 E8 ?? ?? ?? ?? 6A 00 6A 11 E8 ?? ?? ?? ?? 6A 00 FF 74 24 34 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 2C 6A 7F E8 ?? ?? ?? ?? 6A 01 6A 03 E8 ?? ?? ?? ?? 6A 01 6A 02 E8 ?? ?? ?? ?? 8D 44 24 }
	condition:
		$pattern
}

rule cosh_ece81f619972620e9478be34f630f9bf {
	meta:
		aliases = "__GI_cosh, __ieee754_cosh, cosh"
		type = "func"
		size = "279"
		objfiles = "e_cosh@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 DD 44 24 18 DD 54 24 08 8B 5C 24 0C 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 0F 8F E8 00 00 00 DD D8 81 FB 42 2E D6 3F 7F 3A FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? DD 1C 24 E8 ?? ?? ?? ?? D9 E8 D9 C1 D8 C1 59 58 81 FB FF FF 7F 3C 0F 8E B9 00 00 00 D9 CA D8 C8 D9 CA D8 C0 DE FA DE C1 E9 AC 00 00 00 81 FB FF FF 35 40 7F 27 FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? DD 1C 24 E8 ?? ?? ?? ?? D9 05 ?? ?? ?? ?? D9 C1 D8 C9 D9 C9 DE F2 DE C1 EB 6B 81 FB 41 2E 86 40 7F 1D FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? DD 1C 24 E8 ?? ?? ?? ?? D8 0D ?? ?? ?? ?? EB 46 DD 44 24 18 DD 1C 24 8B 04 24 81 FB CD 33 }
	condition:
		$pattern
}

rule atanh_28748105185428e1a8798c76b5f5c193 {
	meta:
		aliases = "__GI_atanh, __ieee754_atanh, atanh"
		type = "func"
		size = "202"
		objfiles = "e_atanh@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 DD 44 24 18 DD 54 24 08 8B 5C 24 0C 89 DA 81 E2 FF FF FF 7F 8B 44 24 08 F7 D8 0B 44 24 08 C1 E8 1F 09 D0 3D 00 00 F0 3F 76 09 D8 E0 D8 F0 E9 82 00 00 00 DD D8 81 FA 00 00 F0 3F 75 0C DD 44 24 18 DC 35 ?? ?? ?? ?? EB 6C 81 FA FF FF 2F 3E 7F 15 DD 44 24 18 DC 05 ?? ?? ?? ?? D9 EE D9 C9 DA E9 DF E0 9E 77 57 DD 44 24 18 DD 1C 24 89 54 24 04 DD 04 24 81 FA FF FF DF 3F D9 C0 D8 C1 7F 12 D9 C0 D8 CA D9 CA DC 2D ?? ?? ?? ?? DE FA DE C1 EB 06 D9 E8 DE E2 DE F1 83 EC 08 DD 1C 24 E8 ?? ?? ?? ?? D8 0D ?? ?? ?? ?? 58 5A DD 54 24 18 85 DB 79 08 D9 E0 DD 5C 24 18 EB 02 DD D8 DD 44 24 18 83 C4 10 }
	condition:
		$pattern
}

rule random_45141f1aa22574fe44ae705ff1f9c25b {
	meta:
		aliases = "__GI_random, random"
		type = "func"
		size = "66"
		objfiles = "random@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 14 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 44 24 20 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 01 53 E8 ?? ?? ?? ?? 8B 44 24 30 83 C4 34 5B C3 }
	condition:
		$pattern
}

rule getttyent_faf727a10ead25314f426547b218d9fc {
	meta:
		aliases = "__GI_getttyent, getttyent"
		type = "func"
		size = "637"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 14 83 3D ?? ?? ?? ?? 00 75 0F E8 ?? ?? ?? ?? 31 DB 85 C0 0F 84 5A 02 00 00 83 3D ?? ?? ?? ?? 00 75 19 68 00 10 00 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 5B 85 C0 75 05 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C0 38 50 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C0 38 50 E8 ?? ?? ?? ?? 83 C4 10 8B 1D ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 68 00 10 00 00 53 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 07 31 DB E9 DC 01 00 00 6A 0A 53 E8 ?? ?? ?? ?? 5A 59 85 C0 75 2B 8B 15 ?? ?? ?? ?? 8B 42 10 3B 42 18 73 09 0F B6 08 40 89 42 10 EB 09 52 E8 ?? ?? ?? ?? 89 C1 5B 83 F9 0A 74 A8 41 74 A5 EB D6 43 8A 0B 0F }
	condition:
		$pattern
}

rule siginterrupt_979df3a44f95e713399f83ea12ec0057 {
	meta:
		aliases = "siginterrupt"
		type = "func"
		size = "103"
		objfiles = "sigintr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 14 8B 5C 24 1C 89 E0 50 6A 00 53 E8 ?? ?? ?? ?? 83 C4 0C 83 CA FF 85 C0 78 43 83 7C 24 20 00 74 15 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 64 24 0C FF FF FF EF EB 13 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 4C 24 0C 00 00 00 10 58 5A 6A 00 8D 44 24 04 50 53 E8 ?? ?? ?? ?? 89 C2 83 C4 0C 89 D0 83 C4 14 5B C3 }
	condition:
		$pattern
}

rule frexp_3d5b901bea49278d3fc619ceaefe061a {
	meta:
		aliases = "__GI_frexp, frexp"
		type = "func"
		size = "151"
		objfiles = "s_frexp@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 8B 5C 24 28 DD 44 24 20 DD 54 24 10 8B 4C 24 14 8B 44 24 10 89 CA 81 E2 FF FF FF 7F C7 03 00 00 00 00 81 FA FF FF EF 7F 7F 5E 09 D0 74 5A 81 FA FF FF 0F 00 7F 22 D8 0D ?? ?? ?? ?? DD 54 24 20 DD 5C 24 08 8B 4C 24 0C 89 CA 81 E2 FF FF FF 7F C7 03 CA FF FF FF EB 02 DD D8 8B 03 2D FE 03 00 00 C1 FA 14 01 D0 89 03 DD 44 24 20 DD 1C 24 81 E1 FF FF 0F 80 81 C9 00 00 E0 3F 89 4C 24 04 DD 04 24 DD 5C 24 20 EB 02 DD D8 DD 44 24 20 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule sinh_5929730d445d55ac7e265b5785fa5c77 {
	meta:
		aliases = "__GI_sinh, __ieee754_sinh, sinh"
		type = "func"
		size = "317"
		objfiles = "e_sinh@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 DD 44 24 20 DD 54 24 08 8B 44 24 0C 89 C3 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 07 D8 C0 E9 09 01 00 00 DD D8 85 C0 79 08 D9 05 ?? ?? ?? ?? EB 06 D9 05 ?? ?? ?? ?? DD 5C 24 10 81 FB FF FF 35 40 7F 70 81 FB FF FF 2F 3E 7F 19 DD 44 24 20 DC 05 ?? ?? ?? ?? D9 E8 D9 C9 DA E9 DF E0 9E 0F 87 CC 00 00 00 FF 74 24 24 FF 74 24 24 E8 ?? ?? ?? ?? DD 1C 24 E8 ?? ?? ?? ?? D9 C0 59 58 81 FB FF FF EF 3F 7F 1C DC C1 D9 C9 DD 5C 24 20 D9 C0 D8 C9 D9 C9 DC 05 ?? ?? ?? ?? DE F9 DC 6C 24 20 EB 0A DD D9 D9 E8 D8 C1 D8 F9 DE C1 DD 44 24 10 DE C9 EB 79 81 FB 41 2E 86 40 7F 1B FF 74 24 24 FF 74 24 24 E8 }
	condition:
		$pattern
}

rule _create_xid_327939fb19f582a0a7d5b9685f1143fd {
	meta:
		aliases = "_create_xid"
		type = "func"
		size = "119"
		objfiles = "create_xid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 80 3D ?? ?? ?? ?? 00 75 29 6A 00 8D 44 24 14 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B 44 24 1C 33 44 24 20 50 E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01 83 C4 10 8D 44 24 18 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 01 53 E8 ?? ?? ?? ?? 8B 44 24 28 83 C4 2C 5B C3 }
	condition:
		$pattern
}

rule fesetenv_edd50c49b1628c27c5d2a291333ec303 {
	meta:
		aliases = "__GI_fesetenv, fesetenv"
		type = "func"
		size = "223"
		objfiles = "fesetenv@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 8B 5C 24 24 D9 34 24 83 FB FF 75 2B 8B 04 24 83 C8 3D 80 E4 F3 66 89 04 24 66 83 64 24 04 C2 C7 44 24 0C 00 00 00 00 66 C7 44 24 10 00 00 66 81 64 24 12 00 F8 EB 2F 83 FB FE 66 8B 4C 24 12 75 36 66 81 24 24 C2 F3 66 83 64 24 04 C2 C7 44 24 0C 00 00 00 00 66 C7 44 24 10 00 00 66 81 E1 00 F8 66 89 4C 24 12 C7 44 24 14 00 00 00 00 66 C7 44 24 18 00 00 EB 5A 8B 03 66 25 3D 0C 8B 14 24 66 81 E2 C2 F3 09 D0 66 89 04 24 8B 43 04 83 E0 3D 8B 54 24 04 83 E2 C2 09 D0 66 89 44 24 04 8B 43 0C 89 44 24 0C 8B 43 10 66 89 44 24 10 66 8B 43 12 66 25 FF 07 66 81 E1 00 F8 09 C1 66 89 4C 24 12 8B 43 }
	condition:
		$pattern
}

rule __pthread_manager_sighandler_8a8fe005722aec901831678d5301d8fe {
	meta:
		aliases = "__pthread_manager_sighandler"
		type = "func"
		size = "93"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C A1 ?? ?? ?? ?? 31 D2 85 C0 75 0C 31 D2 83 3D ?? ?? ?? ?? 00 0F 95 C2 C7 05 ?? ?? ?? ?? 01 00 00 00 85 D2 74 2F C7 04 24 00 00 00 00 C7 44 24 04 06 00 00 00 89 E3 6A 1C 53 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 40 75 0A E8 ?? ?? ?? ?? 83 38 04 74 E2 83 C4 1C 5B C3 }
	condition:
		$pattern
}

rule scalbn_8d78df67fdb38402e3327549072edb4c {
	meta:
		aliases = "__GI_scalbln, __GI_scalbn, scalbln, scalbn"
		type = "func"
		size = "297"
		objfiles = "s_scalbn@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8B 5C 24 30 DD 44 24 28 DD 54 24 18 8B 54 24 1C 8B 4C 24 18 89 D0 25 00 00 F0 7F C1 F8 14 75 2F 81 E2 FF FF FF 7F 09 CA 0F 84 EC 00 00 00 D8 0D ?? ?? ?? ?? DD 54 24 28 DD 5C 24 10 8B 54 24 14 89 D0 25 00 00 F0 7F C1 F8 14 83 E8 36 EB 02 DD D8 3D FF 07 00 00 75 0B DD 44 24 28 D8 C0 E9 B1 00 00 00 01 D8 3D FE 07 00 00 7F 36 81 FB B0 3C FF FF 7C 54 85 C0 7E 1D DD 44 24 28 DD 5C 24 08 C1 E0 14 81 E2 FF FF 0F 80 09 D0 89 44 24 0C DD 44 24 08 EB 7F 83 F8 CA 7F 58 81 FB 50 C3 00 00 7E 26 FF 74 24 2C FF 74 24 2C 68 3C E4 37 7E 68 9C 75 00 88 E8 ?? ?? ?? ?? 83 C4 10 DD 5C 24 28 DD 05 ?? ?? }
	condition:
		$pattern
}

rule trunc_f26888a12c86391c82f6f272c4966144 {
	meta:
		aliases = "__GI_trunc, trunc"
		type = "func"
		size = "212"
		objfiles = "s_trunc@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 C7 44 24 10 00 00 00 00 C7 44 24 14 00 00 00 00 C7 44 24 08 00 00 00 00 C7 44 24 0C 00 00 00 00 C7 04 24 00 00 00 00 C7 44 24 04 00 00 00 00 DD 44 24 28 DD 5C 24 18 8B 54 24 1C 8B 5C 24 18 89 D0 C1 F8 14 25 FF 07 00 00 8D 88 01 FC FF FF 83 F9 13 7F 3D 89 D3 81 E3 00 00 00 80 85 C9 79 12 89 5C 24 14 C7 44 24 10 00 00 00 00 DD 44 24 10 EB 51 B8 FF FF 0F 00 D3 F8 F7 D0 21 D0 09 D8 89 44 24 0C C7 44 24 08 00 00 00 00 DD 44 24 08 EB 32 83 F9 33 7E 10 81 F9 00 04 00 00 75 29 DD 44 24 28 D8 C0 EB 1D 8B 54 24 1C 89 54 24 04 8D 88 ED FB FF FF 83 C8 FF D3 E8 F7 D0 21 D8 89 04 24 DD 04 24 DD }
	condition:
		$pattern
}

rule sleep_bae4534def951448e746ae63ab38f764 {
	meta:
		aliases = "__GI_sleep, sleep"
		type = "func"
		size = "146"
		objfiles = "sleep@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 24 8B 44 24 2C 31 DB 85 C0 74 7D C7 44 24 18 00 00 00 00 C7 44 24 14 00 00 01 00 C7 44 24 20 00 00 00 00 89 44 24 1C 89 E0 50 6A 00 6A 11 E8 ?? ?? ?? ?? 83 C4 0C 83 3C 24 01 75 10 8D 44 24 14 50 50 6A 00 E8 ?? ?? ?? ?? 83 C4 0C 8D 44 24 1C 50 50 E8 ?? ?? ?? ?? 5A 59 31 DB 85 C0 74 11 31 DB 81 7C 24 20 FF 64 CD 1D 0F 9F C3 03 5C 24 1C F6 44 24 16 01 75 11 6A 00 8D 44 24 18 50 6A 02 E8 ?? ?? ?? ?? 83 C4 0C 89 D8 83 C4 24 5B C3 }
	condition:
		$pattern
}

rule __pthread_initialize_manager_df62dd3218d749ea823eac5297d6df6e {
	meta:
		aliases = "__pthread_initialize_manager"
		type = "func"
		size = "456"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 24 A1 ?? ?? ?? ?? C7 00 01 00 00 00 83 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8D 44 00 E0 50 E8 ?? ?? ?? ?? 89 C2 A3 ?? ?? ?? ?? 59 83 C8 FF 85 D2 0F 84 84 01 00 00 A1 ?? ?? ?? ?? 8D 44 42 E0 A3 ?? ?? ?? ?? 8D 44 24 1C 50 E8 ?? ?? ?? ?? 5A 40 75 14 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C8 FF 5B E9 54 01 00 00 A1 ?? ?? ?? ?? 85 C0 74 05 A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 0F 84 80 00 00 00 A1 ?? ?? ?? ?? 8A 15 ?? ?? ?? ?? 08 C2 79 71 A1 ?? ?? ?? ?? 31 D2 E8 ?? ?? ?? ?? FF 74 24 1C 68 00 0F 00 00 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 83 C4 10 83 F8 FF 74 32 }
	condition:
		$pattern
}

rule log10_aa3d9dc5089043dd544c7c0247a10399 {
	meta:
		aliases = "__GI_log10, __ieee754_log10, log10"
		type = "func"
		size = "229"
		objfiles = "e_log10@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 24 DD 44 24 2C DD 5C 24 1C 8B 4C 24 20 8B 54 24 1C 31 DB 81 F9 FF FF 0F 00 7F 48 89 C8 25 FF FF FF 7F 09 D0 75 0D D9 EE D8 3D ?? ?? ?? ?? E9 AA 00 00 00 85 C9 79 11 DD 44 24 2C D8 E0 DC 35 ?? ?? ?? ?? E9 95 00 00 00 DD 44 24 2C D8 0D ?? ?? ?? ?? DD 54 24 2C DD 5C 24 14 8B 4C 24 18 BB CA FF FF FF 81 F9 FF FF EF 7F 7E 08 DD 44 24 2C D8 C0 EB 6A 89 C8 C1 F8 14 8D 84 03 01 FC FF FF 89 C2 C1 EA 1F 8D 04 02 50 DB 04 24 83 C4 04 DD 44 24 2C DD 5C 24 0C B8 FF 03 00 00 29 D0 C1 E0 14 81 E1 FF FF 0F 00 09 C8 89 44 24 10 FF 74 24 10 FF 74 24 10 DD 5C 24 08 E8 ?? ?? ?? ?? DD 44 24 08 DD 05 ?? ?? }
	condition:
		$pattern
}

rule sysctl_a29549633932f27de83c766d910b0d49 {
	meta:
		aliases = "sysctl"
		type = "func"
		size = "91"
		objfiles = "sysctl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 28 8B 44 24 30 89 04 24 8B 44 24 34 89 44 24 04 8B 44 24 38 89 44 24 08 8B 44 24 3C 89 44 24 0C 8B 44 24 40 89 44 24 10 8B 44 24 44 89 44 24 14 89 E1 87 CB B8 95 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule malloc_stats_f01556d03d12447db99ad90e6634ce62 {
	meta:
		aliases = "malloc_stats"
		type = "func"
		size = "79"
		objfiles = "mallinfo@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 28 8B 5C 24 30 85 DB 75 06 8B 1D ?? ?? ?? ?? 89 E0 50 E8 ?? ?? ?? ?? 8B 44 24 1C 8B 4C 24 10 8B 14 24 FF 74 24 24 FF 74 24 24 FF 74 24 1C 50 51 FF 74 24 20 52 8D 04 01 50 01 CA 52 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 54 5B C3 }
	condition:
		$pattern
}

rule signal_fc9fe89dd9159edeaad7e7210c81353b {
	meta:
		aliases = "__GI_signal, bsd_signal, signal"
		type = "func"
		size = "135"
		objfiles = "signal@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 28 8B 5C 24 30 8B 44 24 34 83 F8 FF 74 09 85 DB 7E 05 83 FB 40 7E 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CA FF EB 56 89 44 24 14 C7 44 24 20 00 00 00 00 C7 44 24 24 00 00 00 00 53 8D 44 24 24 50 E8 ?? ?? ?? ?? 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 F8 01 19 C0 25 00 00 00 10 89 44 24 18 89 E0 50 8D 44 24 18 50 53 E8 ?? ?? ?? ?? 83 C4 0C 83 CA FF 85 C0 78 03 8B 14 24 89 D0 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule pmap_unset_cefb065dfae3c12ceba0fb217d42321e {
	meta:
		aliases = "__GI_pmap_unset, pmap_unset"
		type = "func"
		size = "173"
		objfiles = "pmap_clnt@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 28 C7 44 24 24 FF FF FF FF 8D 5C 24 10 89 D8 E8 ?? ?? ?? ?? 85 C0 0F 84 87 00 00 00 68 90 01 00 00 68 90 01 00 00 8D 44 24 2C 50 FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 6A 02 68 A0 86 01 00 53 E8 ?? ?? ?? ?? 89 C3 83 C4 20 85 C0 74 56 8B 44 24 30 89 04 24 8B 44 24 34 89 44 24 04 C7 44 24 08 00 00 00 00 C7 44 24 0C 00 00 00 00 8D 44 24 20 89 E2 8B 4B 04 FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? 6A 02 53 FF 11 83 C4 20 8B 43 04 53 FF 50 10 8B 44 24 24 59 EB 02 31 C0 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule svc_sendreply_2b84aa5124d3d12685ec3d651961d84b {
	meta:
		aliases = "__GI_svc_sendreply, svc_sendreply"
		type = "func"
		size = "81"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 30 8B 5C 24 38 C7 44 24 04 01 00 00 00 C7 44 24 08 00 00 00 00 8D 54 24 0C 8D 43 20 6A 0C 50 52 E8 ?? ?? ?? ?? C7 44 24 24 00 00 00 00 8B 44 24 4C 89 44 24 28 8B 44 24 48 89 44 24 2C 8B 53 08 8D 44 24 0C 50 53 FF 52 0C 83 C4 44 5B C3 }
	condition:
		$pattern
}

rule svcerr_noprog_3ccc32a16412d9fd0ea691b4fd7e709b {
	meta:
		aliases = "__GI_svcerr_noprog, svcerr_noprog"
		type = "func"
		size = "65"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 30 8B 5C 24 38 C7 44 24 04 01 00 00 00 C7 44 24 08 00 00 00 00 8D 54 24 0C 8D 43 20 6A 0C 50 52 E8 ?? ?? ?? ?? C7 44 24 24 01 00 00 00 8B 53 08 8D 44 24 0C 50 53 FF 52 0C 83 C4 44 5B C3 }
	condition:
		$pattern
}

rule svcerr_progvers_1db920763b141324ad660635e64059b5 {
	meta:
		aliases = "__GI_svcerr_progvers, svcerr_progvers"
		type = "func"
		size = "81"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 30 8B 5C 24 38 C7 44 24 04 01 00 00 00 C7 44 24 08 00 00 00 00 8D 54 24 0C 8D 43 20 6A 0C 50 52 E8 ?? ?? ?? ?? C7 44 24 24 02 00 00 00 8B 44 24 48 89 44 24 28 8B 44 24 4C 89 44 24 2C 8B 53 08 8D 44 24 0C 50 53 FF 52 0C 83 C4 44 5B C3 }
	condition:
		$pattern
}

rule svcerr_noproc_0876b08a2280a5562ad613fae77cc0d9 {
	meta:
		aliases = "svcerr_noproc"
		type = "func"
		size = "65"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 30 8B 5C 24 38 C7 44 24 04 01 00 00 00 C7 44 24 08 00 00 00 00 8D 54 24 0C 8D 43 20 6A 0C 50 52 E8 ?? ?? ?? ?? C7 44 24 24 03 00 00 00 8B 53 08 8D 44 24 0C 50 53 FF 52 0C 83 C4 44 5B C3 }
	condition:
		$pattern
}

rule svcerr_decode_e68bd0d26959fb686e5fc7847832b702 {
	meta:
		aliases = "__GI_svcerr_decode, svcerr_decode"
		type = "func"
		size = "65"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 30 8B 5C 24 38 C7 44 24 04 01 00 00 00 C7 44 24 08 00 00 00 00 8D 54 24 0C 8D 43 20 6A 0C 50 52 E8 ?? ?? ?? ?? C7 44 24 24 04 00 00 00 8B 53 08 8D 44 24 0C 50 53 FF 52 0C 83 C4 44 5B C3 }
	condition:
		$pattern
}

rule svcerr_systemerr_a35ee1a2b2868c8b7a1704e51093a0b1 {
	meta:
		aliases = "svcerr_systemerr"
		type = "func"
		size = "65"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 30 8B 5C 24 38 C7 44 24 04 01 00 00 00 C7 44 24 08 00 00 00 00 8D 54 24 0C 8D 43 20 6A 0C 50 52 E8 ?? ?? ?? ?? C7 44 24 24 05 00 00 00 8B 53 08 8D 44 24 0C 50 53 FF 52 0C 83 C4 44 5B C3 }
	condition:
		$pattern
}

rule asinh_bddfa08f4925cd2bb4f361fb32d28bde {
	meta:
		aliases = "__GI_asinh, asinh"
		type = "func"
		size = "314"
		objfiles = "s_asinh@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 34 DD 44 24 3C DD 54 24 1C 8B 5C 24 20 89 DA 81 E2 FF FF FF 7F 81 FA FF FF EF 7F 7E 07 D8 C0 E9 02 01 00 00 DD D8 81 FA FF FF 2F 3E 7F 19 DD 44 24 3C DC 05 ?? ?? ?? ?? D9 E8 D9 C9 DA E9 DF E0 9E 0F 87 E7 00 00 00 81 FA 00 00 B0 41 7E 22 FF 74 24 40 FF 74 24 40 E8 ?? ?? ?? ?? DD 1C 24 E8 ?? ?? ?? ?? DC 05 ?? ?? ?? ?? 58 5A E9 AB 00 00 00 81 FA 00 00 00 40 DD 44 24 3C D8 C8 DD 5C 24 0C 7E 4A FF 74 24 40 FF 74 24 40 E8 ?? ?? ?? ?? DD 5C 24 34 D9 E8 DD 44 24 14 D8 C1 DD 54 24 14 DD 1C 24 DD 5C 24 08 E8 ?? ?? ?? ?? DD 44 24 34 D8 C0 D9 C9 DC 44 24 34 DD 44 24 08 DE F1 DE C1 83 EC 08 DD 1C }
	condition:
		$pattern
}

rule __kernel_tan_4b9a7c86dba3ce571bfe8dbe46184ff8 {
	meta:
		aliases = "__kernel_tan"
		type = "func"
		size = "522"
		objfiles = "k_tan@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 38 DD 44 24 48 8B 5C 24 50 DD 44 24 40 DD 54 24 18 8B 54 24 1C 89 D1 81 E1 FF FF FF 7F 81 F9 FF FF 2F 3E 7F 66 D9 7C 24 36 66 8B 44 24 36 80 CC 0C 66 89 44 24 34 D9 6C 24 34 DB 54 24 30 D9 6C 24 36 8B 44 24 30 85 C0 75 7D DD D9 DD 54 24 10 0B 4C 24 10 8D 43 01 09 C1 75 18 83 EC 08 DD 1C 24 E8 ?? ?? ?? ?? 58 5A DC 3D ?? ?? ?? ?? E9 87 01 00 00 DD D8 4B 0F 84 82 01 00 00 DD 44 24 40 D8 3D ?? ?? ?? ?? E9 6F 01 00 00 DD D8 81 F9 27 94 E5 3F 7E 34 85 D2 79 0C DD 44 24 40 D9 E0 DD 5C 24 40 D9 E0 DD 44 24 40 DC 2D ?? ?? ?? ?? DD 5C 24 40 DD 05 ?? ?? ?? ?? DE E1 DC 44 24 40 DD 5C 24 40 D9 EE }
	condition:
		$pattern
}

rule stat_1511767dc3e599aaacf5d934dfa6799e {
	meta:
		aliases = "__GI_stat, stat"
		type = "func"
		size = "67"
		objfiles = "stat@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 40 8B 54 24 48 89 E1 87 D3 B8 6A 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF EB 10 85 C0 75 0C FF 74 24 4C 51 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 40 5B C3 }
	condition:
		$pattern
}

rule lstat_5e1476ed1da0a799cf9631d901d57855 {
	meta:
		aliases = "__GI_lstat, lstat"
		type = "func"
		size = "67"
		objfiles = "lstat@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 40 8B 54 24 48 89 E1 87 D3 B8 6B 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF EB 10 85 C0 75 0C FF 74 24 4C 51 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 40 5B C3 }
	condition:
		$pattern
}

rule fstat_179afcf93d32eff5e5a7cce23b282a72 {
	meta:
		aliases = "__GI_fstat, fstat"
		type = "func"
		size = "67"
		objfiles = "fstat@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 40 8B 54 24 48 89 E1 87 D3 B8 6C 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF EB 10 85 C0 75 0C FF 74 24 4C 51 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 40 5B C3 }
	condition:
		$pattern
}

rule vswprintf_2218a44e64b850c531b7ffd1b6a6aeed {
	meta:
		aliases = "__GI_vswprintf, vswprintf"
		type = "func"
		size = "155"
		objfiles = "vswprintf@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 50 8B 54 24 58 8B 44 24 5C C7 44 24 04 FD FF FF FF 66 C7 04 24 50 08 C6 44 24 02 00 C7 44 24 2C 00 00 00 00 C7 44 24 20 00 00 00 00 89 D3 F7 D3 C1 EB 02 39 C3 76 02 89 C3 89 54 24 08 8D 04 9A 89 44 24 0C 89 54 24 10 89 54 24 14 89 54 24 18 89 54 24 1C FF 74 24 64 FF 74 24 64 8D 44 24 08 50 E8 ?? ?? ?? ?? 89 C2 8B 44 24 1C 83 C4 0C 3B 44 24 0C 75 0E 83 CA FF 85 DB 74 15 83 E8 04 89 44 24 10 85 DB 74 0A 8B 44 24 10 C7 00 00 00 00 00 89 D0 83 C4 50 5B C3 }
	condition:
		$pattern
}

rule vswscanf_2381d69cf8516d10586081e8ee335d36 {
	meta:
		aliases = "__GI_vswscanf, vswscanf"
		type = "func"
		size = "116"
		objfiles = "vswscanf@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 50 8B 5C 24 58 89 5C 24 10 89 5C 24 08 53 E8 ?? ?? ?? ?? 5A 8D 04 83 89 44 24 0C 89 44 24 14 89 5C 24 18 89 5C 24 1C C7 44 24 04 FD FF FF FF 66 C7 04 24 21 08 C6 44 24 02 00 C7 44 24 2C 00 00 00 00 C7 44 24 34 01 00 00 00 89 E3 8D 44 24 38 50 E8 ?? ?? ?? ?? C7 44 24 24 00 00 00 00 FF 74 24 64 FF 74 24 64 53 E8 ?? ?? ?? ?? 83 C4 60 5B C3 }
	condition:
		$pattern
}

rule fdopendir_b7116022da9f452142514667d456284c {
	meta:
		aliases = "fdopendir"
		type = "func"
		size = "106"
		objfiles = "opendir@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 58 8B 5C 24 60 89 E0 50 53 E8 ?? ?? ?? ?? 5A 59 85 C0 75 4C 8B 44 24 10 25 00 F0 00 00 3D 00 40 00 00 74 0D E8 ?? ?? ?? ?? C7 00 14 00 00 00 EB 2F 6A 03 53 E8 ?? ?? ?? ?? 5A 59 83 F8 FF 74 20 83 E0 03 48 75 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 0D 8B 54 24 30 89 D8 E8 ?? ?? ?? ?? EB 02 31 C0 83 C4 58 5B C3 }
	condition:
		$pattern
}

rule ftok_b49165c6a5ee8032ca339b4f8ae6870b {
	meta:
		aliases = "ftok"
		type = "func"
		size = "55"
		objfiles = "ftok@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 58 8B 5C 24 64 89 E0 50 FF 74 24 64 E8 ?? ?? ?? ?? 5A 59 83 CA FF 85 C0 78 13 0F B6 14 24 C1 E2 10 0F B7 44 24 0C 09 C2 C1 E3 18 09 DA 89 D0 83 C4 58 5B C3 }
	condition:
		$pattern
}

rule stat64_3db0bbef9b7d109dcf13513208beb270 {
	meta:
		aliases = "__GI_stat64, stat64"
		type = "func"
		size = "67"
		objfiles = "stat64@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 60 8B 54 24 68 89 E1 87 D3 B8 C3 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF EB 10 85 C0 75 0C FF 74 24 6C 51 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 60 5B C3 }
	condition:
		$pattern
}

rule lstat64_957edea1520df57dac3d603b3e6011ea {
	meta:
		aliases = "__GI_lstat64, lstat64"
		type = "func"
		size = "67"
		objfiles = "lstat64@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 60 8B 54 24 68 89 E1 87 D3 B8 C4 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF EB 10 85 C0 75 0C FF 74 24 6C 51 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 60 5B C3 }
	condition:
		$pattern
}

rule fstat64_f9e2d390721ec860c3a70a6bef878b2d {
	meta:
		aliases = "__GI_fstat64, fstat64"
		type = "func"
		size = "67"
		objfiles = "fstat64@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 60 8B 54 24 68 89 E1 87 D3 B8 C5 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF EB 10 85 C0 75 0C FF 74 24 6C 51 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 60 5B C3 }
	condition:
		$pattern
}

rule __ether_line_99e777a75d9501bc44a734d3817b3278 {
	meta:
		aliases = "__ether_line"
		type = "func"
		size = "58"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C3 52 50 E8 ?? ?? ?? ?? 5A 59 85 C0 75 03 EB 22 43 8A 03 84 C0 74 0B 3C 20 74 07 3C 09 75 F1 EB 01 43 8A 03 84 C0 74 0A 3C 20 74 F5 3C 09 75 04 EB EF 31 DB 89 D8 5B C3 }
	condition:
		$pattern
}

rule pthread_insert_list_b4f8e514296fa1de8e42a4baed3a7009 {
	meta:
		aliases = "pthread_insert_list"
		type = "func"
		size = "36"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C3 85 D2 74 1B 83 7C 24 08 00 75 05 EB 09 8D 58 04 8B 03 85 C0 75 F7 89 11 8B 03 89 41 04 89 0B 5B C3 }
	condition:
		$pattern
}

rule __malloc_largebin_index_6fff5e8b07ec6ef3e12086439ce65f45 {
	meta:
		aliases = "__malloc_largebin_index"
		type = "func"
		size = "38"
		objfiles = "malloc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C3 89 C2 C1 EA 08 B8 5F 00 00 00 81 FA FF FF 00 00 77 0F 0F BD C2 8D 48 06 D3 EB 83 E3 03 8D 44 83 20 5B C3 }
	condition:
		$pattern
}

rule skip_and_NUL_space_6ab6ef96e83cdfaddeb82be486cb65f7 {
	meta:
		aliases = "skip_and_NUL_space"
		type = "func"
		size = "43"
		objfiles = "opennameservers@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C3 8A 0B 84 C9 74 1E 0F B6 D1 A1 ?? ?? ?? ?? F6 04 50 20 74 10 C6 03 00 80 F9 0A 74 08 80 F9 23 74 03 43 EB DC 89 D8 5B C3 }
	condition:
		$pattern
}

rule closelog_intern_f78ee5b1252e166d6ae364baa636917d {
	meta:
		aliases = "closelog_intern"
		type = "func"
		size = "74"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C3 A1 ?? ?? ?? ?? 83 F8 FF 74 07 50 E8 ?? ?? ?? ?? 58 C7 05 ?? ?? ?? ?? FF FF FF FF C6 05 ?? ?? ?? ?? 00 85 DB 75 1F C6 05 ?? ?? ?? ?? 00 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01 C6 05 ?? ?? ?? ?? FF 5B C3 }
	condition:
		$pattern
}

rule wait_node_free_96567fd368b0cf80d608ef14bfd07fcf {
	meta:
		aliases = "wait_node_free"
		type = "func"
		size = "38"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C3 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 89 03 89 1D ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 5B C3 }
	condition:
		$pattern
}

rule scan_getwc_c860a46f59139a14beb6ae2ccd151630 {
	meta:
		aliases = "scan_getwc"
		type = "func"
		size = "118"
		objfiles = "vfwscanf@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C3 C7 40 24 FF FF FF FF 8B 40 10 48 89 43 10 85 C0 78 38 80 7B 19 00 75 4A 8B 53 08 83 7A 04 FD 75 1B 8B 42 10 3B 42 0C 73 0A 8B 08 83 C0 04 89 42 10 EB 1D C6 43 19 02 83 C8 FF EB 35 52 E8 ?? ?? ?? ?? 89 C1 58 83 F9 FF 75 06 80 4B 19 02 EB E7 C6 43 1A 01 89 4B 04 8B 43 08 8A 40 02 88 43 18 EB 04 C6 43 19 00 FF 43 0C 8B 43 04 89 43 24 31 C0 5B C3 }
	condition:
		$pattern
}

rule __set_h_errno_a6ddf4c91e419aa229e87f147c2f8e39 {
	meta:
		aliases = "__set_h_errno"
		type = "func"
		size = "14"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C3 E8 ?? ?? ?? ?? 89 18 89 D8 5B C3 }
	condition:
		$pattern
}

rule __syscall_error_6af36d18eb5fecfcd2bdcf03240db486 {
	meta:
		aliases = "__syscall_error"
		type = "func"
		size = "17"
		objfiles = "__syscall_error@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C3 E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule pthread_call_handlers_996121e43ac17f2bb569af12a0bcd73c {
	meta:
		aliases = "pthread_call_handlers"
		type = "func"
		size = "16"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C3 EB 05 FF 13 8B 5B 04 85 DB 75 F7 5B C3 }
	condition:
		$pattern
}

rule skip_nospace_2aad12861903189b6f25850352d64ee5 {
	meta:
		aliases = "skip_nospace"
		type = "func"
		size = "40"
		objfiles = "opennameservers@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C3 EB 0B 80 F9 0A 75 05 C6 03 00 EB 15 43 8A 0B 84 C9 74 0E 0F B6 D1 A1 ?? ?? ?? ?? F6 04 50 20 74 E1 89 D8 5B C3 }
	condition:
		$pattern
}

rule __md5_to64_49bcf00391895a547b877ac98b8de652 {
	meta:
		aliases = "__md5_to64"
		type = "func"
		size = "27"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C3 EB 11 89 D0 83 E0 3F 8A 80 ?? ?? ?? ?? 88 03 43 C1 EA 06 49 79 EC 5B C3 }
	condition:
		$pattern
}

rule remove_from_queue_404163357bb882ed6948038be913cc2f {
	meta:
		aliases = "remove_from_queue"
		type = "func"
		size = "41"
		objfiles = "condvar@libpthread.a, semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C3 EB 1A 39 D1 75 13 8B 41 08 89 03 C7 41 08 00 00 00 00 B8 01 00 00 00 EB 0B 8D 59 08 8B 0B 85 C9 75 E0 31 C0 5B C3 }
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

rule load_field_f321749c5bf1fe4e965ccd4223987199 {
	meta:
		aliases = "load_field"
		type = "func"
		size = "59"
		objfiles = "strftime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 14 82 8A 98 ?? ?? ?? ?? B9 6D 01 00 00 83 F8 07 74 13 0F B6 CB 83 F8 05 75 0B 81 C2 6C 07 00 00 B9 0F 27 00 00 39 CA 77 09 83 F8 03 75 07 85 D2 75 03 83 CA FF 89 D0 5B C3 }
	condition:
		$pattern
}

rule clnt_perrno_4fdb18028d5c736834e79cad156b011a {
	meta:
		aliases = "clnt_pcreateerror, clnt_perrno"
		type = "func"
		size = "28"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 1D ?? ?? ?? ?? FF 74 24 08 E8 ?? ?? ?? ?? 53 50 E8 ?? ?? ?? ?? 83 C4 0C 5B C3 }
	condition:
		$pattern
}

rule clnt_perror_ddbfa452b0006be980ec8a72509c415f {
	meta:
		aliases = "__GI_clnt_perror, clnt_perror"
		type = "func"
		size = "36"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 1D ?? ?? ?? ?? FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? 5A 59 89 5C 24 0C 89 44 24 08 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mq_unlink_7a870a7c94f4720463d8cf5604b031fa {
	meta:
		aliases = "mq_unlink"
		type = "func"
		size = "82"
		objfiles = "mq_unlink@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 80 38 2F 74 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 36 8D 48 01 87 CB B8 16 01 00 00 CD 80 87 CB 89 C3 3D 00 F0 FF FF 76 0B E8 ?? ?? ?? ?? F7 DB 89 18 EB 04 85 C0 79 13 E8 ?? ?? ?? ?? 8B 10 83 FA 01 75 02 B2 0D 89 10 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule dirfd_a316d1d909f6da10072f9e7770f3bbf1 {
	meta:
		aliases = "__GI_dirfd, dirfd"
		type = "func"
		size = "27"
		objfiles = "dirfd@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 18 83 FB FF 75 0B E8 ?? ?? ?? ?? C7 00 09 00 00 00 89 D8 5B C3 }
	condition:
		$pattern
}

rule timer_getoverrun_abaabb835966505eb124be75630a20e5 {
	meta:
		aliases = "timer_getoverrun"
		type = "func"
		size = "43"
		objfiles = "timer_getoverr@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 48 04 87 CB B8 06 01 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule llabs_7e56ecd29126203efd64d0b46dd8d488 {
	meta:
		aliases = "imaxabs, llabs"
		type = "func"
		size = "30"
		objfiles = "llabs@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 54 24 0C 89 C1 89 D3 89 DB C1 FB 1F 89 D9 31 C8 31 DA 29 C8 19 DA 5B C3 }
	condition:
		$pattern
}

rule mq_timedsend_f62a30623161be2fd9fda3b5ffa0883f {
	meta:
		aliases = "mq_timedreceive, mq_timedsend"
		type = "func"
		size = "35"
		objfiles = "mq_send@librt.a, mq_receive@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 54 24 0C 8B 4C 24 10 8B 5C 24 18 89 5C 24 0C 8B 5C 24 14 89 5C 24 08 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pread_8810fe4c8dbaf93db0b2807cdd400643 {
	meta:
		aliases = "__libc_pread, mq_receive, mq_send, pread"
		type = "func"
		size = "35"
		objfiles = "mq_send@librt.a, pread_write@libc.a, mq_receive@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 54 24 0C 8B 4C 24 10 C7 44 24 0C 00 00 00 00 8B 5C 24 14 89 5C 24 08 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pwrite_9e46946a9d5e5d4a028f8a7e5d42a695 {
	meta:
		aliases = "__libc_pwrite, pwrite"
		type = "func"
		size = "35"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 54 24 0C 8B 4C 24 10 C7 44 24 0C 01 00 00 00 8B 5C 24 14 89 5C 24 08 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule iruserok_973f2be830416d2da8e15c406d16eec7 {
	meta:
		aliases = "__ivaliduser, iruserok"
		type = "func"
		size = "35"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 54 24 0C 8B 4C 24 10 C7 44 24 0C ?? ?? ?? ?? 8B 5C 24 14 89 5C 24 08 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdrrec_putint32_34fb36d125ec2fc37ae52660925b0ce1 {
	meta:
		aliases = "xdrrec_putint32"
		type = "func"
		size = "77"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 58 0C 8B 53 10 8D 42 04 89 43 10 89 D1 3B 43 14 76 22 89 53 10 C7 43 1C 01 00 00 00 31 D2 89 D8 E8 ?? ?? ?? ?? 31 D2 85 C0 74 18 8B 4B 10 8D 41 04 89 43 10 8B 44 24 0C 8B 00 0F C8 89 01 BA 01 00 00 00 89 D0 5B C3 }
	condition:
		$pattern
}

rule xdrrec_eof_fd72849aacf67bb54ab925f34c0234f8 {
	meta:
		aliases = "__GI_xdrrec_eof, xdrrec_eof"
		type = "func"
		size = "79"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 58 0C EB 23 89 D8 E8 ?? ?? ?? ?? 85 C0 74 33 C7 43 34 00 00 00 00 83 7B 38 00 75 0B 89 D8 E8 ?? ?? ?? ?? 85 C0 74 1B 8B 53 34 85 D2 7F D6 83 7B 38 00 74 D0 8B 43 2C 3B 43 30 0F 94 C0 0F B6 C0 EB 05 B8 01 00 00 00 5B C3 }
	condition:
		$pattern
}

rule xdrrec_skiprecord_93e08e2a92b88d7240d658fc8038ab48 {
	meta:
		aliases = "__GI_xdrrec_skiprecord, xdrrec_skiprecord"
		type = "func"
		size = "76"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 58 0C EB 23 89 D8 E8 ?? ?? ?? ?? 85 C0 74 33 C7 43 34 00 00 00 00 83 7B 38 00 75 0B 89 D8 E8 ?? ?? ?? ?? 85 C0 74 1B 8B 53 34 85 D2 7F D6 83 7B 38 00 74 D0 C7 43 38 00 00 00 00 B8 01 00 00 00 EB 02 31 C0 5B C3 }
	condition:
		$pattern
}

rule xdrrec_destroy_9f823f77d5631bd0571266e94236f6e8 {
	meta:
		aliases = "xdrrec_destroy"
		type = "func"
		size = "27"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 58 0C FF 73 04 E8 ?? ?? ?? ?? 58 89 5C 24 08 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wmemset_357bef8bdfa803522ea2431254217c2a {
	meta:
		aliases = "wmemset"
		type = "func"
		size = "29"
		objfiles = "wmemset@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 5C 24 0C 8B 4C 24 10 89 C2 EB 06 89 1A 83 C2 04 49 85 C9 75 F6 5B C3 }
	condition:
		$pattern
}

rule strpbrk_c3f279d4cd0516c265dc72d9ea47ddf2 {
	meta:
		aliases = "__GI_strpbrk, strpbrk"
		type = "func"
		size = "35"
		objfiles = "strpbrk@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 EB 0C 38 D9 74 16 42 8A 0A 84 C9 75 F5 40 8A 18 84 DB 74 06 8B 54 24 0C EB ED 31 C0 5B C3 }
	condition:
		$pattern
}

rule freeaddrinfo_fff30ef1883818390156dbdaafa20051 {
	meta:
		aliases = "__GI_freeaddrinfo, freeaddrinfo"
		type = "func"
		size = "25"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 EB 0C 8B 58 1C 50 E8 ?? ?? ?? ?? 89 D8 5A 85 C0 75 F0 5B C3 }
	condition:
		$pattern
}

rule wcspbrk_cdd88d21c3f86c1ae4cbaac47f47a095 {
	meta:
		aliases = "__GI_wcspbrk, wcspbrk"
		type = "func"
		size = "39"
		objfiles = "wcspbrk@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 EB 10 39 D9 74 1A 83 C2 04 8B 0A 85 C9 75 F3 83 C0 04 8B 18 85 DB 74 06 8B 54 24 0C EB EB 31 C0 5B C3 }
	condition:
		$pattern
}

rule _exit_c0f8682d3d28e5ac9ce888c2da764d27 {
	meta:
		aliases = "_Exit, __GI__exit, _exit"
		type = "func"
		size = "36"
		objfiles = "_exit@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 01 00 00 00 CD 80 87 CB 89 C3 3D 00 F0 FF FF 76 E8 E8 ?? ?? ?? ?? F7 DB 89 18 EB DD }
	condition:
		$pattern
}

rule close_6614712807f2dd6aeafe33e497bb5f3f {
	meta:
		aliases = "__GI_close, __libc_close, close"
		type = "func"
		size = "40"
		objfiles = "close@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 06 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule unlink_c68e1a53c37d61bae770abf08d26a239 {
	meta:
		aliases = "__GI_unlink, unlink"
		type = "func"
		size = "40"
		objfiles = "unlink@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 0A 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule chdir_0c7bd231ac777132a3b199ab99fb0351 {
	meta:
		aliases = "__GI_chdir, chdir"
		type = "func"
		size = "40"
		objfiles = "chdir@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 0C 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule umount_b330e4fd10096a6828516d1300246bce {
	meta:
		aliases = "umount"
		type = "func"
		size = "40"
		objfiles = "umount@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 16 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule stime_43191f59dc626b8b95e0dd24916a1ce2 {
	meta:
		aliases = "stime"
		type = "func"
		size = "40"
		objfiles = "stime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 19 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule alarm_872ea2bb33f6ee3cd118bb3701afd8ba {
	meta:
		aliases = "__GI_alarm, alarm"
		type = "func"
		size = "40"
		objfiles = "alarm@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 1B 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule nice_66b0d0db78e8fb201447ace548684017 {
	meta:
		aliases = "nice"
		type = "func"
		size = "59"
		objfiles = "nice@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 22 00 00 00 CD 80 87 CB 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF EB 12 83 C8 FF 85 DB 75 0B 6A 00 6A 00 E8 ?? ?? ?? ?? 5A 59 5B C3 }
	condition:
		$pattern
}

rule rmdir_8f41f2744d1875a98c38872cd41611a0 {
	meta:
		aliases = "__GI_rmdir, rmdir"
		type = "func"
		size = "40"
		objfiles = "rmdir@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 28 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule dup_33d8276006e6485665a9a08edde0f66a {
	meta:
		aliases = "dup"
		type = "func"
		size = "40"
		objfiles = "dup@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 29 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule pipe_ccf11459236acf2d77dde4245c8d00a1 {
	meta:
		aliases = "__GI_pipe, pipe"
		type = "func"
		size = "40"
		objfiles = "pipe@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 2A 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule acct_899a5e636e9d328b122d142adb26ae1c {
	meta:
		aliases = "acct"
		type = "func"
		size = "40"
		objfiles = "acct@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 33 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule umask_626464d040673edf33f3c65ab2bea6f4 {
	meta:
		aliases = "umask"
		type = "func"
		size = "43"
		objfiles = "umask@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 3C 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 0F B7 C0 5B C3 }
	condition:
		$pattern
}

rule chroot_471b2cd29725aa5c9e4d46c6a9f6ca4d {
	meta:
		aliases = "chroot"
		type = "func"
		size = "40"
		objfiles = "chroot@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 3D 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule epoll_create1_8f4afb5d78d0b4bfa52765c7d39ef22b {
	meta:
		aliases = "epoll_create1"
		type = "func"
		size = "40"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 49 01 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule inotify_init1_36cc1c0df3fccccc9dd44af2d753759c {
	meta:
		aliases = "inotify_init1"
		type = "func"
		size = "40"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 4C 01 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule iopl_cfc204ae0f074180d4ceecb756db4c62 {
	meta:
		aliases = "iopl"
		type = "func"
		size = "40"
		objfiles = "iopl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 6E 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule swapoff_08f0f037c2692b58ba750ac1d3d73142 {
	meta:
		aliases = "swapoff"
		type = "func"
		size = "40"
		objfiles = "swapoff@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 73 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sysinfo_70ecc210c13af6f32cd4a69e155f2688 {
	meta:
		aliases = "sysinfo"
		type = "func"
		size = "40"
		objfiles = "sysinfo@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 74 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule fsync_a6cdc80583d359aca31d57c23865a7a7 {
	meta:
		aliases = "__libc_fsync, fsync"
		type = "func"
		size = "40"
		objfiles = "fsync@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 76 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule uname_5a0a2d1e61e71e6d6208b929444ef3a5 {
	meta:
		aliases = "__GI_uname, uname"
		type = "func"
		size = "40"
		objfiles = "uname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 7A 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule ntp_adjtime_ad7dc23951e0d2e00f1a0f8c91dc5fa1 {
	meta:
		aliases = "__GI_adjtimex, adjtimex, ntp_adjtime"
		type = "func"
		size = "40"
		objfiles = "adjtimex@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 7C 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule getpgid_969633136aa8a2de2d7b873ad0668010 {
	meta:
		aliases = "__getpgid, getpgid"
		type = "func"
		size = "40"
		objfiles = "getpgid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 84 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule fchdir_3d947ea7fab523456771697a05530848 {
	meta:
		aliases = "__GI_fchdir, fchdir"
		type = "func"
		size = "40"
		objfiles = "fchdir@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 85 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule personality_ddcf5497567b28dd9c4e8def6a298975 {
	meta:
		aliases = "personality"
		type = "func"
		size = "40"
		objfiles = "personality@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 88 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule getsid_0c374ffef357f16546f6988d3aab3a00 {
	meta:
		aliases = "__GI_getsid, getsid"
		type = "func"
		size = "40"
		objfiles = "getsid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 93 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule fdatasync_77acdcccf9942b836be6b3be39955014 {
	meta:
		aliases = "fdatasync"
		type = "func"
		size = "40"
		objfiles = "fdatasync@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 94 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule mlockall_cc3607e74b224e968c31c784323bd4b7 {
	meta:
		aliases = "mlockall"
		type = "func"
		size = "40"
		objfiles = "mlockall@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 98 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sched_getscheduler_32966e4f407f0c628a980123a92d7aa9 {
	meta:
		aliases = "sched_getscheduler"
		type = "func"
		size = "40"
		objfiles = "sched_getscheduler@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 9D 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sched_get_priority_max_93a943b1b86f225c0c3429262dc831fa {
	meta:
		aliases = "sched_get_priority_max"
		type = "func"
		size = "40"
		objfiles = "sched_get_priority_max@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 9F 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sched_get_priority_min_74560b6fe4ad2baa0f860d045a77e4d0 {
	meta:
		aliases = "sched_get_priority_min"
		type = "func"
		size = "40"
		objfiles = "sched_get_priority_min@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 A0 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setuid_874e8745d0b741e004be27a282144c8c {
	meta:
		aliases = "setuid"
		type = "func"
		size = "40"
		objfiles = "setuid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 D5 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setgid_11e5205ab1c4745175f782ff9a236cd2 {
	meta:
		aliases = "setgid"
		type = "func"
		size = "40"
		objfiles = "setgid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 D6 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setfsuid_c676079f300ea6a21fc3281a499c9921 {
	meta:
		aliases = "setfsuid"
		type = "func"
		size = "40"
		objfiles = "setfsuid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 D7 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setfsgid_d776e965eff0d553a179bd4d07fbbf0f {
	meta:
		aliases = "setfsgid"
		type = "func"
		size = "40"
		objfiles = "setfsgid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 D8 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule epoll_create_0bebd7c6bb3f5958aec0d1e3564339b3 {
	meta:
		aliases = "epoll_create"
		type = "func"
		size = "40"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 87 CB B8 FE 00 00 00 CD 80 87 CB 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule tcsendbreak_460a56959c29162b001262d77741a62b {
	meta:
		aliases = "tcsendbreak"
		type = "func"
		size = "52"
		objfiles = "tcsendbrk@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 8B 44 24 0C 85 C0 7F 09 6A 00 68 09 54 00 00 EB 13 83 C0 63 BA 64 00 00 00 89 D3 99 F7 FB 50 68 25 54 00 00 51 E8 ?? ?? ?? ?? 83 C4 0C 5B C3 }
	condition:
		$pattern
}

rule xdrmem_setpos_72cb6fad845e965777219a083e18843a {
	meta:
		aliases = "xdrmem_setpos"
		type = "func"
		size = "38"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 8B 54 24 0C 03 51 10 8B 41 14 03 41 0C 31 DB 39 C2 7F 0A 89 51 0C 29 D0 89 41 14 B3 01 89 D8 5B C3 }
	condition:
		$pattern
}

rule re_set_registers_7206b1d369dfabfdd87020020d1cae74 {
	meta:
		aliases = "re_set_registers"
		type = "func"
		size = "75"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 8B 54 24 0C 8B 5C 24 10 85 DB 8A 41 1C 74 1B 83 E0 F9 83 C8 02 88 41 1C 89 1A 8B 44 24 14 89 42 04 8B 44 24 18 89 42 08 EB 1A 83 E0 F9 88 41 1C C7 02 00 00 00 00 C7 42 08 00 00 00 00 C7 42 04 00 00 00 00 5B C3 }
	condition:
		$pattern
}

rule __decode_header_9f78c609ebfcad62d398b4b86f9f4f21 {
	meta:
		aliases = "__decode_header"
		type = "func"
		size = "166"
		objfiles = "decodeh@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 8B 5C 24 0C 0F B6 51 01 0F B6 01 C1 E0 08 09 C2 89 13 0F BE 41 02 C1 E8 1F 89 43 04 8A 41 02 C0 E8 03 83 E0 0F 89 43 08 0F B6 41 02 C1 E8 02 83 E0 01 89 43 0C 0F B6 41 02 D1 E8 83 E0 01 89 43 10 0F B6 41 02 83 E0 01 89 43 14 0F BE 41 03 C1 E8 1F 89 43 18 0F B6 41 03 83 E0 0F 89 43 1C 0F B6 41 04 C1 E0 08 0F B6 51 05 09 D0 89 43 20 0F B6 41 06 C1 E0 08 0F B6 51 07 09 D0 89 43 24 0F B6 41 08 C1 E0 08 0F B6 51 09 09 D0 89 43 28 0F B6 41 0A C1 E0 08 0F B6 51 0B 09 D0 89 43 2C 5B C3 }
	condition:
		$pattern
}

rule ffsll_c4a8f162c81a1a8c2970aa73cdd1e8a6 {
	meta:
		aliases = "ffsll"
		type = "func"
		size = "56"
		objfiles = "ffsll@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 8B 5C 24 0C 89 C8 89 DA F7 D8 83 D2 00 F7 DA 21 DA 83 FA 00 77 0A 89 4C 24 08 5B E9 ?? ?? ?? ?? 89 D9 89 CB C1 FB 1F 51 E8 ?? ?? ?? ?? 5A 83 C0 20 5B C3 }
	condition:
		$pattern
}

rule xdrmem_inline_73f81dd4e3715ff18c72a7b5a0fcef2d {
	meta:
		aliases = "xdrmem_inline"
		type = "func"
		size = "36"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 8B 5C 24 0C 8B 41 14 31 D2 39 D8 72 0E 29 D8 89 41 14 8B 51 0C 8D 04 1A 89 41 0C 89 D0 5B C3 }
	condition:
		$pattern
}

rule __sigismember_153421a36092b719bf7f04011c9e23e0 {
	meta:
		aliases = "__GI___sigismember, __sigismember"
		type = "func"
		size = "36"
		objfiles = "sigsetops@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 49 89 CB C1 EB 05 83 E1 1F B8 01 00 00 00 D3 E0 8B 54 24 08 85 04 9A 0F 95 C0 0F B6 C0 5B C3 }
	condition:
		$pattern
}

rule _dl_parse_relocation_informati_2ea3537a34315f4c2da4a95c39b7b155 {
	meta:
		aliases = "_dl_parse_relocation_information"
		type = "func"
		size = "36"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 44 24 08 8B 00 8B 50 1C C7 44 24 0C ?? ?? ?? ?? 8B 5C 24 10 89 5C 24 08 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule timer_gettime_5544b7b4a7fd28e6c43a5f5cd031d025 {
	meta:
		aliases = "timer_gettime"
		type = "func"
		size = "47"
		objfiles = "timer_gettime@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 44 24 08 8B 50 04 87 D3 B8 05 01 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule read_3a6e3b0576a05d8cd2cd08b7f0009672 {
	meta:
		aliases = "__GI_read, __libc_read, read"
		type = "func"
		size = "48"
		objfiles = "read@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 03 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule write_62fae76f46b8a81897ae25f0d018706b {
	meta:
		aliases = "__GI_write, __libc_write, write"
		type = "func"
		size = "48"
		objfiles = "write@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 04 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule execve_a9e2aeb8e7bb40b0c8f738262e8765a2 {
	meta:
		aliases = "__GI_execve, execve"
		type = "func"
		size = "48"
		objfiles = "execve@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 0B 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule lseek_9cabd2f8d7813d6f72821f63ea31623c {
	meta:
		aliases = "__GI_lseek, __libc_lseek, lseek"
		type = "func"
		size = "48"
		objfiles = "lseek@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 13 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule mq_setattr_0675b5b135a3c432e4845e2a8faa6f8e {
	meta:
		aliases = "__GI_mq_setattr, mq_setattr"
		type = "func"
		size = "48"
		objfiles = "mq_getsetattr@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 1A 01 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule inotify_add_watch_2adf8124cc5b5ba5623acc9daf469f08 {
	meta:
		aliases = "inotify_add_watch"
		type = "func"
		size = "48"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 24 01 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule mkdirat_9e5c6cee330361a7b782d491f3f1d9ab {
	meta:
		aliases = "mkdirat"
		type = "func"
		size = "48"
		objfiles = "mkdirat@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 28 01 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule futimesat_3ec48af74021c8782df4d492971e77ab {
	meta:
		aliases = "futimesat"
		type = "func"
		size = "48"
		objfiles = "futimesat@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 2B 01 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule unlinkat_4a0857663397f851cf744a8aa383c101 {
	meta:
		aliases = "unlinkat"
		type = "func"
		size = "48"
		objfiles = "unlinkat@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 2D 01 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule symlinkat_ae9f2fda3d6dbc83246bf67ac9583059 {
	meta:
		aliases = "symlinkat"
		type = "func"
		size = "48"
		objfiles = "symlinkat@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 30 01 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule readlink_b4a38474445064b15df0e2e3faf568d1 {
	meta:
		aliases = "__GI_readlink, readlink"
		type = "func"
		size = "48"
		objfiles = "readlink@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 55 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setpriority_a68fffa43e27a93f560bd3d760b34e59 {
	meta:
		aliases = "__GI_setpriority, setpriority"
		type = "func"
		size = "48"
		objfiles = "setpriority@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 61 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule ioperm_61a71aaeac9edaeecbea58413a7471c8 {
	meta:
		aliases = "ioperm"
		type = "func"
		size = "48"
		objfiles = "ioperm@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 65 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule klogctl_300ea097ba995fecab5316e625f3252a {
	meta:
		aliases = "klogctl"
		type = "func"
		size = "48"
		objfiles = "klogctl@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 67 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setitimer_cb182266344a495fcd0b025618390462 {
	meta:
		aliases = "__GI_setitimer, setitimer"
		type = "func"
		size = "48"
		objfiles = "setitimer@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 68 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule modify_ldt_4b7b3d64b5c87ddb039103fec63b05fe {
	meta:
		aliases = "modify_ldt"
		type = "func"
		size = "48"
		objfiles = "modify_ldt@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 7B 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule mprotect_53340538b1e5251e6e97a57e663f6269 {
	meta:
		aliases = "mprotect"
		type = "func"
		size = "48"
		objfiles = "mprotect@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 7D 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule msync_7c62e36927158ac04cddc07276279395 {
	meta:
		aliases = "__libc_msync, msync"
		type = "func"
		size = "48"
		objfiles = "msync@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 90 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule readv_5997d1abcfe3f9075dc95d48f5f1adfc {
	meta:
		aliases = "readv"
		type = "func"
		size = "48"
		objfiles = "readv@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 91 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule writev_d01184816506504c0ece16af5b69a347 {
	meta:
		aliases = "writev"
		type = "func"
		size = "48"
		objfiles = "writev@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 92 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sched_setscheduler_46ea69f0c8752024cc74e622f914e2e3 {
	meta:
		aliases = "sched_setscheduler"
		type = "func"
		size = "48"
		objfiles = "sched_setscheduler@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 9C 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule poll_8ca1125ae16be3dee28b9e46168c6869 {
	meta:
		aliases = "__GI_poll, poll"
		type = "func"
		size = "48"
		objfiles = "poll@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 A8 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule lchown_a85dded025f066d26934523878bf05eb {
	meta:
		aliases = "lchown"
		type = "func"
		size = "48"
		objfiles = "lchown@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 C6 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule fchown_e274e3e3269bc116a07e412c2cec96e3 {
	meta:
		aliases = "fchown"
		type = "func"
		size = "48"
		objfiles = "fchown@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 CF 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setresuid_c1ee0a4d257cf8b6c18f1a8a0955dd16 {
	meta:
		aliases = "__GI_setresuid, setresuid"
		type = "func"
		size = "48"
		objfiles = "setresuid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 D0 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule getresuid_86713db81a1a08ed3b7009bdc47eb811 {
	meta:
		aliases = "getresuid"
		type = "func"
		size = "48"
		objfiles = "getresuid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 D1 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setresgid_003f20d62898003cff16ee8133714524 {
	meta:
		aliases = "__GI_setresgid, setresgid"
		type = "func"
		size = "48"
		objfiles = "setresgid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 D2 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule getresgid_df09491321341016871e8f3631e7f042 {
	meta:
		aliases = "getresgid"
		type = "func"
		size = "48"
		objfiles = "getresgid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 D3 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule chown_bba969156cd163734669aa889b327802 {
	meta:
		aliases = "__GI_chown, chown"
		type = "func"
		size = "48"
		objfiles = "chown@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 D4 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule mincore_1778a313757694255eb9c7478f5fb7ff {
	meta:
		aliases = "mincore"
		type = "func"
		size = "48"
		objfiles = "mincore@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 DA 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule madvise_aa4e828bca5dfed5e796f04e3921f528 {
	meta:
		aliases = "madvise"
		type = "func"
		size = "48"
		objfiles = "madvise@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 DB 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule listxattr_aa66a991d2faa69484d2195c9e9d0d73 {
	meta:
		aliases = "listxattr"
		type = "func"
		size = "48"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 E8 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule llistxattr_22c7e17b9ad4b66fb7b3219f11f883cf {
	meta:
		aliases = "llistxattr"
		type = "func"
		size = "48"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 E9 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule flistxattr_290d9c162c454f0cfbb27905968ead86 {
	meta:
		aliases = "flistxattr"
		type = "func"
		size = "48"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 54 24 10 8B 44 24 08 53 89 C3 B8 EA 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule ustat_8731f9e9ef23241daec90362be3c8bed {
	meta:
		aliases = "ustat"
		type = "func"
		size = "44"
		objfiles = "ustat@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 10 8B 54 24 08 87 D3 B8 3E 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule swab_f15ce667d1078cb383f3c759dd52a476 {
	meta:
		aliases = "swab"
		type = "func"
		size = "43"
		objfiles = "swab@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 44 24 10 83 E0 FE 8D 1C 02 8B 4C 24 0C EB 10 66 8B 02 66 C1 C8 08 83 C2 02 66 89 01 83 C1 02 39 DA 72 EC 5B C3 }
	condition:
		$pattern
}

rule timer_delete_a14b86d677fa97b87ef4962e47b2ef2d {
	meta:
		aliases = "timer_delete"
		type = "func"
		size = "60"
		objfiles = "timer_delete@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4A 04 87 CB B8 07 01 00 00 CD 80 87 CB 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF EB 10 83 C8 FF 85 DB 75 09 52 E8 ?? ?? ?? ?? 31 C0 5A 5B C3 }
	condition:
		$pattern
}

rule mq_notify_0a2bc0080de0c774e2ccea96fc38b7ea {
	meta:
		aliases = "mq_notify"
		type = "func"
		size = "67"
		objfiles = "mq_notify@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 85 C9 74 13 83 79 08 02 75 0D E8 ?? ?? ?? ?? C7 00 26 00 00 00 EB 1E 87 D3 B8 19 01 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule clock_settime_cda619dfe2c45ad25a11d49274459911 {
	meta:
		aliases = "clock_settime"
		type = "func"
		size = "44"
		objfiles = "clock_settime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 08 01 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule link_c6bb4aec6c915997a1bdb6d72325fde6 {
	meta:
		aliases = "link"
		type = "func"
		size = "44"
		objfiles = "link@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 09 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule clock_gettime_22f31d7c79dfeec861d91ac010209776 {
	meta:
		aliases = "clock_gettime"
		type = "func"
		size = "44"
		objfiles = "clock_gettime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 09 01 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule clock_getres_e91f6d9fc917835c4cf15d132d5a3d60 {
	meta:
		aliases = "__GI_clock_getres, clock_getres"
		type = "func"
		size = "44"
		objfiles = "clock_getres@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 0A 01 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule chmod_b45ba1a85653330e392d03d9e1bf9408 {
	meta:
		aliases = "__GI_chmod, chmod"
		type = "func"
		size = "44"
		objfiles = "chmod@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 0F 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule utimes_ff62db6f27f928050f8c67831bb02378 {
	meta:
		aliases = "__GI_utimes, utimes"
		type = "func"
		size = "44"
		objfiles = "utimes@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 0F 01 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule utime_a5f5f9b2084670e26f07706cff6f8c72 {
	meta:
		aliases = "__GI_utime, utime"
		type = "func"
		size = "44"
		objfiles = "utime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 1E 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule access_d7b5c1378c0726f4e8d7d8934f8221fc {
	meta:
		aliases = "access"
		type = "func"
		size = "44"
		objfiles = "access@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 21 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule kill_781af69f517408312bf43fd2337b872a {
	meta:
		aliases = "__GI_kill, kill"
		type = "func"
		size = "44"
		objfiles = "kill@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 25 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule inotify_rm_watch_f1d4aa0f0d9fdb5dd16b31e196000f7c {
	meta:
		aliases = "inotify_rm_watch"
		type = "func"
		size = "44"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 25 01 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule rename_aa708b7ce6f19d89a0324923ae7576c7 {
	meta:
		aliases = "rename"
		type = "func"
		size = "44"
		objfiles = "rename@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 26 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule mkdir_96a7c309978bf539dd4c9ca6e704d63f {
	meta:
		aliases = "__GI_mkdir, mkdir"
		type = "func"
		size = "44"
		objfiles = "mkdir@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 27 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule umount2_f7522eb799748b79327d323350c57918 {
	meta:
		aliases = "umount2"
		type = "func"
		size = "44"
		objfiles = "umount2@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 34 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setpgid_30470614b4fae28c0af69a83a77a8000 {
	meta:
		aliases = "__GI_setpgid, setpgid"
		type = "func"
		size = "44"
		objfiles = "setpgid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 39 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule ulimit_13dac362857b378aba3de5757865af8f {
	meta:
		aliases = "ulimit"
		type = "func"
		size = "44"
		objfiles = "ulimit@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 3A 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule dup2_273c9e202a27fa9b3eed88af7d3e12ef {
	meta:
		aliases = "__GI_dup2, dup2"
		type = "func"
		size = "44"
		objfiles = "dup2@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 3F 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule timerfd_create_2ff49d88c3202b25f70f774ebd4a22b0 {
	meta:
		aliases = "timerfd_create"
		type = "func"
		size = "44"
		objfiles = "timerfd@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 42 01 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule timerfd_gettime_83a9d723972ca175120baadd56fd8edf {
	meta:
		aliases = "timerfd_gettime"
		type = "func"
		size = "44"
		objfiles = "timerfd@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 46 01 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sethostname_7bd6bd06684d86c34b2e8abfa7f2201d {
	meta:
		aliases = "sethostname"
		type = "func"
		size = "44"
		objfiles = "sethostname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 4A 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setrlimit_c7336c3ca0886ac865fbb881d895f41a {
	meta:
		aliases = "__GI_setrlimit, setrlimit"
		type = "func"
		size = "44"
		objfiles = "setrlimit@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 4B 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule pipe2_0f1bce31d1b153c41726b31910ddffc2 {
	meta:
		aliases = "__GI_pipe2, pipe2"
		type = "func"
		size = "44"
		objfiles = "pipe2@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 4B 01 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule getrusage_01502b9a285394fd59535d2ba1886512 {
	meta:
		aliases = "getrusage"
		type = "func"
		size = "44"
		objfiles = "getrusage@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 4D 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule gettimeofday_7d330373b06b3d85194db0eca733ecb3 {
	meta:
		aliases = "__GI_gettimeofday, gettimeofday"
		type = "func"
		size = "44"
		objfiles = "gettimeofday@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 4E 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule settimeofday_d38570fec8d225b3cd679066b55b8376 {
	meta:
		aliases = "__GI_settimeofday, settimeofday"
		type = "func"
		size = "44"
		objfiles = "settimeofday@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 4F 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule symlink_7d26882cee61de48f3399df3daee4890 {
	meta:
		aliases = "symlink"
		type = "func"
		size = "44"
		objfiles = "symlink@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 53 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule swapon_dd12a0d2e168a6fc82e26b5970d8e2be {
	meta:
		aliases = "swapon"
		type = "func"
		size = "44"
		objfiles = "swapon@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 57 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule munmap_a458b3778cf792fc683b605c45fb405f {
	meta:
		aliases = "__GI_munmap, munmap"
		type = "func"
		size = "44"
		objfiles = "munmap@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 5B 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule truncate_13cd5ee55280bf7267604b601730e6f7 {
	meta:
		aliases = "__GI_truncate, truncate"
		type = "func"
		size = "44"
		objfiles = "truncate@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 5C 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule ftruncate_6befe00d7a8373b7cd3e519d450442e1 {
	meta:
		aliases = "__GI_ftruncate, ftruncate"
		type = "func"
		size = "44"
		objfiles = "ftruncate@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 5D 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule fchmod_513635dd10743a99c19fb6ae4fc91070 {
	meta:
		aliases = "fchmod"
		type = "func"
		size = "44"
		objfiles = "fchmod@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 5E 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule getpriority_128e8caff37bc6fa8e5bfdc40181461d {
	meta:
		aliases = "__GI_getpriority, getpriority"
		type = "func"
		size = "56"
		objfiles = "getpriority@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 60 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF EB 0B 85 DB 78 07 B8 14 00 00 00 29 D8 5B C3 }
	condition:
		$pattern
}

rule statfs_b358acf49d4606aac2aa3f9bb673929e {
	meta:
		aliases = "__libc_statfs, statfs"
		type = "func"
		size = "44"
		objfiles = "statfs@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 63 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule fstatfs_e462e7ac8a1e8dad217f0c356208a420 {
	meta:
		aliases = "__libc_fstatfs, fstatfs"
		type = "func"
		size = "44"
		objfiles = "fstatfs@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 64 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule __socketcall_1076d559f631f171818d59f7b5adc368 {
	meta:
		aliases = "__socketcall"
		type = "func"
		size = "44"
		objfiles = "__socketcall@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 66 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule getitimer_cdd81c5675cda99fc229ab8ab3ffd72d {
	meta:
		aliases = "getitimer"
		type = "func"
		size = "44"
		objfiles = "getitimer@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 69 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setdomainname_9e4d65c0c7c1d04690da5e8ca5ae9827 {
	meta:
		aliases = "setdomainname"
		type = "func"
		size = "44"
		objfiles = "setdomainname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 79 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule delete_module_dabf7442ab2c34ea6166e20405f028fe {
	meta:
		aliases = "delete_module"
		type = "func"
		size = "44"
		objfiles = "delete_module@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 81 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule bdflush_3694b188e7c10f61e6ac9624b9a3b5c2 {
	meta:
		aliases = "bdflush"
		type = "func"
		size = "44"
		objfiles = "bdflush@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 86 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule flock_251596f3d81721ba3c71735cef96faaf {
	meta:
		aliases = "flock"
		type = "func"
		size = "44"
		objfiles = "flock@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 8F 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule mlock_711ab1078e992c0f7adb5b0fe5318948 {
	meta:
		aliases = "mlock"
		type = "func"
		size = "44"
		objfiles = "mlock@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 96 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule munlock_1a1c3700b241553b7db01025ba8d002e {
	meta:
		aliases = "munlock"
		type = "func"
		size = "44"
		objfiles = "munlock@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 97 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sched_setparam_141b3d29b01afef46bca06b395d215c3 {
	meta:
		aliases = "sched_setparam"
		type = "func"
		size = "44"
		objfiles = "sched_setparam@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 9A 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sched_getparam_6bfa84df589c829c53ea95dd4228b129 {
	meta:
		aliases = "sched_getparam"
		type = "func"
		size = "44"
		objfiles = "sched_getparam@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 9B 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sched_rr_get_interval_8902bf090e9d79765bf7ba3340d3f423 {
	meta:
		aliases = "sched_rr_get_interval"
		type = "func"
		size = "44"
		objfiles = "sched_rr_get_interval@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 A1 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule nanosleep_66d8ad1e996b2f0928eecec048fcd516 {
	meta:
		aliases = "__GI_nanosleep, __libc_nanosleep, nanosleep"
		type = "func"
		size = "44"
		objfiles = "nanosleep@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 A2 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule capget_014ef2c3dd4a186581f7f4b8a2cd387d {
	meta:
		aliases = "capget"
		type = "func"
		size = "44"
		objfiles = "capget@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 B8 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule capset_9121ea4eeaf904e4d05bf39a92641c31 {
	meta:
		aliases = "capset"
		type = "func"
		size = "44"
		objfiles = "capset@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 B9 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sigaltstack_e073814e521540d9e54107042ad15c2b {
	meta:
		aliases = "sigaltstack"
		type = "func"
		size = "44"
		objfiles = "sigaltstack@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 BA 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule getrlimit_c6a91a20a90df7394afb401d3d6d3742 {
	meta:
		aliases = "__GI_getrlimit, getrlimit"
		type = "func"
		size = "44"
		objfiles = "getrlimit@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 BF 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setreuid_916d62265adcdff29078d61d7877c8c1 {
	meta:
		aliases = "__GI_setreuid, setreuid"
		type = "func"
		size = "44"
		objfiles = "setreuid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 CB 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setregid_eae054507792e0edb5b8681e09bf0f12 {
	meta:
		aliases = "__GI_setregid, setregid"
		type = "func"
		size = "44"
		objfiles = "setregid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 CC 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule getgroups_e7b60e14a8752d45d092b67cb7c458b4 {
	meta:
		aliases = "__GI_getgroups, getgroups"
		type = "func"
		size = "44"
		objfiles = "getgroups@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 CD 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule setgroups_2975e9bbc0c3bc340de0229075a1ab04 {
	meta:
		aliases = "__GI_setgroups, setgroups"
		type = "func"
		size = "44"
		objfiles = "setgroups@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 CE 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule pivot_root_d96974e5281e8135d0cd3be49ebc1240 {
	meta:
		aliases = "pivot_root"
		type = "func"
		size = "44"
		objfiles = "pivot_root@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 D9 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule removexattr_a3cbaebb3c5631ca1aa2b278512723c4 {
	meta:
		aliases = "removexattr"
		type = "func"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 EB 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule lremovexattr_ea5726d939d4a8f77816385d9f33d997 {
	meta:
		aliases = "lremovexattr"
		type = "func"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 EC 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule fremovexattr_820a56f3cfcffd3b60a35f9be079b07c {
	meta:
		aliases = "fremovexattr"
		type = "func"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 87 D3 B8 ED 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule wcsncmp_90197f1ac46757f3d958e6677c9844a5 {
	meta:
		aliases = "wcsncmp"
		type = "func"
		size = "45"
		objfiles = "wcsncmp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 8B 5C 24 10 EB 0C 83 3A 00 74 0B 83 C2 04 83 C1 04 4B 85 DB 75 04 31 C0 EB 08 8B 02 3B 01 74 E6 2B 01 5B C3 }
	condition:
		$pattern
}

rule ether_ntoa_r_a2aa7d475e76f62160efb521df33bbd2 {
	meta:
		aliases = "__GI_ether_ntoa_r, ether_ntoa_r"
		type = "func"
		size = "56"
		objfiles = "ether_addr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 5C 24 0C 0F B6 42 05 50 0F B6 42 04 50 0F B6 42 03 50 0F B6 42 02 50 0F B6 42 01 50 0F B6 02 50 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 20 89 D8 5B C3 }
	condition:
		$pattern
}

rule _dl_strdup_69351ac2126211fcafe0b06f81210414 {
	meta:
		aliases = "_dl_strdup"
		type = "func"
		size = "45"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8D 5A FF 89 D8 40 80 38 00 75 FA 29 D0 40 50 E8 ?? ?? ?? ?? 89 C1 8D 50 FF 58 42 43 8A 03 88 02 84 C0 75 F6 89 C8 5B C3 }
	condition:
		$pattern
}

rule sigpending_e19d42acee1bcd40e4cb57e526cd39d3 {
	meta:
		aliases = "sigpending"
		type = "func"
		size = "45"
		objfiles = "sigpending@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 B9 08 00 00 00 87 D3 B8 B0 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sigsuspend_4a19b92285673d68e6e8c9d1d53a1e18 {
	meta:
		aliases = "__GI_sigsuspend, sigsuspend"
		type = "func"
		size = "45"
		objfiles = "sigsuspend@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 B9 08 00 00 00 87 D3 B8 B3 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule reboot_0e9ef1203701489b236ec6b1dc81f7ea {
	meta:
		aliases = "reboot"
		type = "func"
		size = "52"
		objfiles = "reboot@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 BB AD DE E1 FE B9 69 19 12 28 89 D8 53 89 C3 B8 58 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
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

rule enqueue_38cc412bb8ab6fb18625bc5845bcdb8e {
	meta:
		aliases = "enqueue"
		type = "func"
		size = "29"
		objfiles = "rwlock@libpthread.a, condvar@libpthread.a, semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5A 18 EB 0D 3B 59 18 7E 05 89 4A 08 EB 09 8D 41 08 8B 08 85 C9 75 ED 89 10 5B C3 }
	condition:
		$pattern
}

rule __cxa_atexit_09b892ba179e1890718127a6775bc4fa {
	meta:
		aliases = "__GI___cxa_atexit, __cxa_atexit"
		type = "func"
		size = "52"
		objfiles = "__cxa_atexit@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 31 C0 85 DB 74 27 E8 ?? ?? ?? ?? 89 C2 83 C8 FF 85 D2 74 19 89 5A 04 8B 44 24 0C 89 42 08 8B 44 24 10 89 42 0C C7 02 03 00 00 00 31 C0 5B C3 }
	condition:
		$pattern
}

rule __uc_malloc_8f32e0da30d8125e51bb3d721e8b83e0 {
	meta:
		aliases = "__GI___uc_malloc, __uc_malloc"
		type = "func"
		size = "56"
		objfiles = "__uc_malloc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 53 E8 ?? ?? ?? ?? 59 85 DB 74 26 85 C0 75 22 83 3D ?? ?? ?? ?? 00 75 07 6A 01 E8 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 58 5A EB CF 5B C3 }
	condition:
		$pattern
}

rule re_exec_e759a91be48d564e5eb04e6c37726b29 {
	meta:
		aliases = "re_exec"
		type = "func"
		size = "43"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 53 E8 ?? ?? ?? ?? C7 04 24 00 00 00 00 50 6A 00 50 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? F7 D0 C1 E8 1F 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule malloc_trim_bb9fdb7f09a75b8d5f3c027a29ac504a {
	meta:
		aliases = "malloc_trim"
		type = "func"
		size = "29"
		objfiles = "free@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 BA ?? ?? ?? ?? 89 D8 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_once_cancelhandler_b0cd0b64b57e98e1b5808a0681f99b67 {
	meta:
		aliases = "pthread_once_cancelhandler"
		type = "func"
		size = "47"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 03 00 00 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5B 58 C7 44 24 08 ?? ?? ?? ?? 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mkdtemp_d88006595aa9ea7fa3851276246c08e0 {
	meta:
		aliases = "mkdtemp"
		type = "func"
		size = "37"
		objfiles = "mkdtemp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 68 C0 01 00 00 6A 02 53 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 0F 94 C0 0F B6 C0 F7 D8 21 C3 89 D8 5B C3 }
	condition:
		$pattern
}

rule rand_r_e282aa635e9217bca6e56dcfe9757397 {
	meta:
		aliases = "rand_r"
		type = "func"
		size = "84"
		objfiles = "rand_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 69 0B 6D 4E C6 41 81 C1 39 30 00 00 89 C8 C1 E8 06 69 C9 6D 4E C6 41 81 C1 39 30 00 00 25 00 FC 1F 00 89 CA C1 EA 10 81 E2 FF 03 00 00 31 D0 69 C9 6D 4E C6 41 81 C1 39 30 00 00 C1 E0 0A 89 CA C1 EA 10 81 E2 FF 03 00 00 31 D0 89 0B 5B C3 }
	condition:
		$pattern
}

rule mktemp_5b1d327562c52e87f4908d684b2d16aa {
	meta:
		aliases = "mktemp"
		type = "func"
		size = "29"
		objfiles = "mktemp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 6A 00 6A 03 53 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 79 03 C6 03 00 89 D8 5B C3 }
	condition:
		$pattern
}

rule fdopen_395b2c361899da6fab2cd742480efcd0 {
	meta:
		aliases = "__GI_fdopen, fdopen"
		type = "func"
		size = "44"
		objfiles = "fdopen@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 6A 03 53 E8 ?? ?? ?? ?? 5A 59 31 D2 83 F8 FF 74 12 53 6A 00 FF 74 24 14 50 E8 ?? ?? ?? ?? 89 C2 83 C4 10 89 D0 5B C3 }
	condition:
		$pattern
}

rule putenv_c7033a9315c72f577810e8131a951d8d {
	meta:
		aliases = "putenv"
		type = "func"
		size = "44"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 6A 3D 53 E8 ?? ?? ?? ?? 5A 59 85 C0 74 0F B9 01 00 00 00 31 D2 89 D8 5B E9 ?? ?? ?? ?? 89 5C 24 08 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_getspecific_eddc629f20fe641e371df79507b3a715 {
	meta:
		aliases = "pthread_getspecific"
		type = "func"
		size = "53"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 81 FB FF 03 00 00 77 24 E8 ?? ?? ?? ?? 89 DA C1 EA 05 8B 44 90 74 85 C0 74 12 83 3C DD ?? ?? ?? ?? 00 74 08 83 E3 1F 8B 04 98 EB 02 31 C0 5B C3 }
	condition:
		$pattern
}

rule _pthread_cleanup_pop_3396db332c4061848958b32413d1afd2 {
	meta:
		aliases = "_pthread_cleanup_pop"
		type = "func"
		size = "31"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 83 7C 24 0C 00 74 06 FF 73 04 FF 13 5A E8 ?? ?? ?? ?? 8B 53 0C 89 50 3C 5B C3 }
	condition:
		$pattern
}

rule __sigjmp_save_3a08c86fae6836696e3a109020070e7f {
	meta:
		aliases = "__sigjmp_save"
		type = "func"
		size = "46"
		objfiles = "sigjmp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 83 7C 24 0C 00 74 19 8D 43 1C 50 6A 00 6A 00 E8 ?? ?? ?? ?? 83 C4 0C BA 01 00 00 00 85 C0 74 02 31 D2 89 53 18 31 C0 5B C3 }
	condition:
		$pattern
}

rule __GI_config_close_603f452bac109accddcffbb230bc5112 {
	meta:
		aliases = "__GI_config_close"
		type = "func"
		size = "44"
		objfiles = "parse_config@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 85 DB 74 21 FF 33 E8 ?? ?? ?? ?? 58 80 7B 14 00 74 09 FF 73 04 E8 ?? ?? ?? ?? 58 89 5C 24 08 5B E9 ?? ?? ?? ?? 5B C3 }
	condition:
		$pattern
}

rule tmpnam_r_fabc4fc70585c1356427b3c1f1ef9b3c {
	meta:
		aliases = "tmpnam_r"
		type = "func"
		size = "51"
		objfiles = "tmpnam_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 85 DB 74 24 6A 00 6A 00 6A 14 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 11 6A 00 6A 03 53 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 02 31 DB 89 D8 5B C3 }
	condition:
		$pattern
}

rule hdestroy_r_11f2d75781778816b483f4ca4e88b5a8 {
	meta:
		aliases = "__GI_hdestroy_r, hdestroy_r"
		type = "func"
		size = "38"
		objfiles = "hdestroy_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 85 DB 75 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 0E FF 33 E8 ?? ?? ?? ?? C7 03 00 00 00 00 58 5B C3 }
	condition:
		$pattern
}

rule re_comp_05b7253734bf39b41fb32f837322ce09 {
	meta:
		aliases = "re_comp"
		type = "func"
		size = "160"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 85 DB 75 14 BA ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 0F 84 81 00 00 00 EB 7D 83 3D ?? ?? ?? ?? 00 75 3C 68 C8 00 00 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 5A BA ?? ?? ?? ?? 85 C0 74 5D C7 05 ?? ?? ?? ?? C8 00 00 00 68 00 01 00 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 59 BA ?? ?? ?? ?? 85 C0 74 3A 80 0D ?? ?? ?? ?? 80 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 89 C2 89 D8 E8 ?? ?? ?? ?? 5A 85 C0 74 10 0F B7 84 00 ?? ?? ?? ?? 8D 90 ?? ?? ?? ?? EB 02 31 D2 89 D0 5B C3 }
	condition:
		$pattern
}

rule byte_store_op2_28dc7fb9fb9a091ae8f6833edf8f3317 {
	meta:
		aliases = "byte_store_op2"
		type = "func"
		size = "27"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 88 02 88 4A 01 C1 F9 08 88 4A 02 88 5A 03 C1 FB 08 88 5A 04 5B C3 }
	condition:
		$pattern
}

rule siglongjmp_475a409d5d6ada9387382fdda67bcfc4 {
	meta:
		aliases = "longjmp, siglongjmp"
		type = "func"
		size = "22"
		objfiles = "ptlongjmp@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 89 D8 E8 ?? ?? ?? ?? FF 74 24 0C 53 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_mutex_unlock_0e4dab2b25f9c72b95679dd06a438ae7 {
	meta:
		aliases = "__pthread_mutex_unlock, pthread_mutex_unlock"
		type = "func"
		size = "125"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 43 0C 83 F8 01 74 19 7F 06 85 C0 74 33 EB 0A 83 F8 02 74 37 83 F8 03 74 49 B8 16 00 00 00 EB 55 E8 ?? ?? ?? ?? 39 43 08 75 46 8B 43 04 85 C0 7E 08 48 89 43 04 31 C0 EB 3C C7 43 08 00 00 00 00 8D 43 10 50 E8 ?? ?? ?? ?? EB 20 E8 ?? ?? ?? ?? 39 43 08 75 1B 83 7B 10 00 74 15 C7 43 08 00 00 00 00 8D 43 10 50 E8 ?? ?? ?? ?? 31 C0 5B EB 05 B8 01 00 00 00 5B C3 }
	condition:
		$pattern
}

rule __sigaddset_a0b2dce9ddf206cde67fd512ea066dce {
	meta:
		aliases = "__GI___sigaddset, __sigaddset"
		type = "func"
		size = "32"
		objfiles = "sigsetops@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 4C 24 0C 49 89 CA C1 EA 05 83 E1 1F B8 01 00 00 00 D3 E0 09 04 93 31 C0 5B C3 }
	condition:
		$pattern
}

rule __sigdelset_4c865c2b04e52bce1aaab48e6401d397 {
	meta:
		aliases = "__GI___sigdelset, __sigdelset"
		type = "func"
		size = "32"
		objfiles = "sigsetops@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 4C 24 0C 49 89 CA C1 EA 05 83 E1 1F B8 FE FF FF FF D3 C0 21 04 93 31 C0 5B C3 }
	condition:
		$pattern
}

rule __stdio_trans2r_o_cac8c1654cc39dc3193abc6510b7effc {
	meta:
		aliases = "__stdio_trans2r_o"
		type = "func"
		size = "91"
		objfiles = "_trans2r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 4C 24 0C 8B 03 0F B7 D0 85 CA 75 0D 81 E2 80 08 00 00 75 0C 09 C8 66 89 03 0F B7 03 A8 10 74 14 E8 ?? ?? ?? ?? C7 00 09 00 00 00 66 83 0B 08 83 C8 FF EB 1F A8 40 74 15 53 E8 ?? ?? ?? ?? 5A 85 C0 75 E8 8B 43 08 89 43 1C 66 83 23 BF 66 83 0B 01 31 C0 5B C3 }
	condition:
		$pattern
}

rule __stdio_trans2w_o_7312a53e99e19cac398bf111602cba8e {
	meta:
		aliases = "__stdio_trans2w_o"
		type = "func"
		size = "153"
		objfiles = "_trans2w@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 4C 24 0C 8B 03 0F B7 D0 85 CA 75 0D 81 E2 80 08 00 00 75 0D 09 C8 66 89 03 0F B7 13 F6 C2 20 74 14 E8 ?? ?? ?? ?? C7 00 09 00 00 00 66 83 0B 08 83 CA FF EB 5A F6 C2 03 74 40 F6 C2 04 75 2B 8B 43 14 3B 43 10 75 05 F6 C2 02 74 1E 81 E2 00 04 00 00 83 FA 01 19 C0 83 C0 02 50 6A 00 53 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 C2 66 83 23 FC 8B 43 08 89 43 18 89 43 10 89 43 14 8B 03 83 C8 40 66 89 03 31 D2 F6 C4 0B 75 06 8B 43 0C 89 43 1C 89 D0 5B C3 }
	condition:
		$pattern
}

rule __fsetlocking_4741a05d9e8a78091574276d70fc3a85 {
	meta:
		aliases = "__GI___fsetlocking, __fsetlocking"
		type = "func"
		size = "41"
		objfiles = "__fsetlocking@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 4C 24 0C 8B 43 34 85 C9 74 13 BA 01 00 00 00 83 F9 02 74 06 8B 15 ?? ?? ?? ?? 89 53 34 83 E0 01 40 5B C3 }
	condition:
		$pattern
}

rule _store_inttype_ce10a843349cb445e561ee3034cbcd4f {
	meta:
		aliases = "_store_inttype"
		type = "func"
		size = "61"
		objfiles = "_store_inttype@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 4C 24 0C 8B 44 24 10 8B 54 24 14 81 F9 00 01 00 00 75 04 88 03 EB 1E 81 F9 00 08 00 00 75 07 89 03 89 53 04 EB 0F 81 F9 00 02 00 00 75 05 66 89 03 EB 02 89 03 5B C3 }
	condition:
		$pattern
}

rule towctrans_7d275e5480f892f2a597f49e4380823a {
	meta:
		aliases = "__GI_towctrans, towctrans"
		type = "func"
		size = "57"
		objfiles = "towctrans@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 4C 24 0C 8D 41 FF 83 F8 01 77 17 89 DA 83 CA 20 8D 42 9F 83 F8 19 77 15 83 F9 02 75 12 83 E2 DF EB 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 89 DA 89 D0 5B C3 }
	condition:
		$pattern
}

rule _dl_parse_lazy_relocation_info_6e12d6311756fde7ac4c9b2fe8272242 {
	meta:
		aliases = "_dl_parse_lazy_relocation_information"
		type = "func"
		size = "35"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 4C 24 0C C7 44 24 0C ?? ?? ?? ?? 8B 44 24 10 89 44 24 08 31 D2 8B 03 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sc_getc_2c43f7a5010d108b37f0790fa881e518 {
	meta:
		aliases = "sc_getc"
		type = "func"
		size = "96"
		objfiles = "vfwscanf@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 53 08 83 7A 04 FD 75 1B 8B 42 10 3B 42 0C 73 0A 8B 08 83 C0 04 89 42 10 EB 1A 66 83 0A 04 83 C8 FF EB 35 52 E8 ?? ?? ?? ?? 89 C1 5A 83 C8 FF 83 F9 FF 74 24 C6 43 1A 01 89 4B 28 8B 43 08 8A 40 02 88 43 18 3B 4B 38 75 07 B9 2E 00 00 00 EB 06 89 4B 04 89 4B 24 89 C8 5B C3 }
	condition:
		$pattern
}

rule __stdio_rfill_e576940dd42eaf73744b7e24796aa6b9 {
	meta:
		aliases = "__stdio_rfill"
		type = "func"
		size = "37"
		objfiles = "_rfill@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 53 08 8B 43 0C 29 D0 50 52 53 E8 ?? ?? ?? ?? 8B 53 08 89 53 10 01 C2 89 53 14 83 C4 0C 5B C3 }
	condition:
		$pattern
}

rule __stdio_wcommit_8bf541b82354d8952ab68840fef9ad6a {
	meta:
		aliases = "__stdio_wcommit"
		type = "func"
		size = "37"
		objfiles = "_wcommit@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 53 08 8B 43 10 29 D0 74 0E 89 53 10 50 52 53 E8 ?? ?? ?? ?? 83 C4 0C 8B 43 10 2B 43 08 5B C3 }
	condition:
		$pattern
}

rule __cmsg_nxthdr_724519eda3349abcc503a059a1241534 {
	meta:
		aliases = "__GI___cmsg_nxthdr, __cmsg_nxthdr"
		type = "func"
		size = "59"
		objfiles = "cmsg_nxthdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 54 24 0C 8B 02 83 F8 0B 76 25 83 C0 03 83 E0 FC 8D 0C 02 8B 53 14 03 53 10 8D 41 0C 39 D0 77 0F 8B 01 83 C0 03 83 E0 FC 8D 04 01 39 D0 76 02 31 C9 89 C8 5B C3 }
	condition:
		$pattern
}

rule sigorset_fbc8d3e28014c78a846db0e943e2ed38 {
	meta:
		aliases = "sigorset"
		type = "func"
		size = "32"
		objfiles = "sigorset@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 54 24 0C 8B 4C 24 10 8B 02 0B 01 89 03 8B 42 04 0B 41 04 89 43 04 31 C0 5B C3 }
	condition:
		$pattern
}

rule sigandset_a57de1504055124419aeba34b48b5ec1 {
	meta:
		aliases = "sigandset"
		type = "func"
		size = "32"
		objfiles = "sigandset@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 54 24 0C 8B 4C 24 10 8B 02 23 01 89 03 8B 42 04 23 41 04 89 43 04 31 C0 5B C3 }
	condition:
		$pattern
}

rule __stdio_READ_512a45d6630b2c9044040740dcf65b67 {
	meta:
		aliases = "__stdio_READ"
		type = "func"
		size = "62"
		objfiles = "_READ@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 54 24 10 31 C0 F6 03 04 75 2C 85 D2 79 05 BA FF FF FF 7F 52 FF 74 24 10 FF 73 04 E8 ?? ?? ?? ?? 83 C4 0C 83 F8 00 7F 0E 75 06 66 83 0B 04 EB 06 66 83 0B 08 31 C0 5B C3 }
	condition:
		$pattern
}

rule __scan_getc_f03047fd4f89a1ac2cf1e0289307fb4c {
	meta:
		aliases = "__scan_getc"
		type = "func"
		size = "72"
		objfiles = "__scan_cookie@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 C7 03 FF FF FF FF 8B 43 10 48 89 43 10 85 C0 79 09 80 4B 19 02 83 C8 FF EB 27 80 7B 19 00 75 15 53 FF 53 2C 5A 83 F8 FF 75 06 80 4B 19 02 EB 11 89 43 04 EB 04 C6 43 19 00 FF 43 0C 8B 43 04 89 03 5B C3 }
	condition:
		$pattern
}

rule login_tty_3ae07ae7b421e7b13d1f3c886f36eba8 {
	meta:
		aliases = "__GI_login_tty, login_tty"
		type = "func"
		size = "79"
		objfiles = "login_tty@libutil.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 E8 ?? ?? ?? ?? 6A 00 68 0E 54 00 00 53 E8 ?? ?? ?? ?? 83 C4 0C 83 CA FF 40 74 2B 6A 00 53 E8 ?? ?? ?? ?? 6A 01 53 E8 ?? ?? ?? ?? 6A 02 53 E8 ?? ?? ?? ?? 83 C4 18 31 D2 83 FB 02 7E 09 53 E8 ?? ?? ?? ?? 31 D2 58 89 D0 5B C3 }
	condition:
		$pattern
}

rule cuserid_8b36f793bccdc80d28be925fee32f443 {
	meta:
		aliases = "cuserid"
		type = "func"
		size = "34"
		objfiles = "getlogin@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 E8 ?? ?? ?? ?? 85 DB 74 12 85 C0 75 05 B8 ?? ?? ?? ?? 50 53 E8 ?? ?? ?? ?? 59 5B 5B C3 }
	condition:
		$pattern
}

rule pthread_start_thread_event_fdb020c6a802bcb819974f1437fdc089 {
	meta:
		aliases = "pthread_start_thread_event"
		type = "func"
		size = "37"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 E8 ?? ?? ?? ?? 89 43 14 8B 43 1C 31 D2 E8 ?? ?? ?? ?? FF 73 1C E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _pthread_cleanup_push_defer_0589ae6f86c4bdb4ca62d7d8a27c358c {
	meta:
		aliases = "__pthread_cleanup_push_defer, _pthread_cleanup_push_defer"
		type = "func"
		size = "62"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 E8 ?? ?? ?? ?? 89 C2 8B 44 24 0C 89 03 8B 44 24 10 89 43 04 0F B6 42 41 89 43 08 8B 42 3C 89 43 0C 85 C0 74 0B 39 C3 72 07 C7 43 0C 00 00 00 00 C6 42 41 00 89 5A 3C 5B C3 }
	condition:
		$pattern
}

rule _pthread_cleanup_push_938937bbad97a6f960aa025668221e41 {
	meta:
		aliases = "_pthread_cleanup_push"
		type = "func"
		size = "51"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 E8 ?? ?? ?? ?? 89 C2 8B 44 24 0C 89 03 8B 44 24 10 89 43 04 8B 42 3C 89 43 0C 85 C0 74 0B 39 C3 72 07 C7 43 0C 00 00 00 00 89 5A 3C 5B C3 }
	condition:
		$pattern
}

rule pthread_attr_init_43eb6ff4d784a86498903132c51c3320 {
	meta:
		aliases = "__GI_pthread_attr_init, pthread_attr_init"
		type = "func"
		size = "75"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 E8 ?? ?? ?? ?? C7 03 00 00 00 00 C7 43 04 00 00 00 00 C7 43 08 00 00 00 00 C7 43 0C 01 00 00 00 C7 43 10 00 00 00 00 89 43 14 C7 43 1C 00 00 00 00 C7 43 18 00 00 00 00 BA 00 00 20 00 29 C2 89 53 20 31 C0 5B C3 }
	condition:
		$pattern
}

rule __exit_handler_4d0acade595b930978bcf07c643cb56e {
	meta:
		aliases = "__exit_handler"
		type = "func"
		size = "88"
		objfiles = "__exit_handler@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 EB 38 48 A3 ?? ?? ?? ?? C1 E0 04 8D 04 02 8B 10 83 FA 02 74 07 83 FA 03 75 20 EB 11 8B 50 04 85 D2 74 17 FF 70 08 53 FF D2 5A 59 EB 0D 8B 50 04 85 D2 74 06 FF 70 08 FF D2 58 A1 ?? ?? ?? ?? 85 C0 8B 15 ?? ?? ?? ?? 75 B9 89 54 24 08 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule regfree_8255f013d928058506992f1d663c5417 {
	meta:
		aliases = "__GI_regfree, regfree"
		type = "func"
		size = "71"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 FF 33 E8 ?? ?? ?? ?? C7 03 00 00 00 00 C7 43 04 00 00 00 00 C7 43 08 00 00 00 00 FF 73 10 E8 ?? ?? ?? ?? C7 43 10 00 00 00 00 80 63 1C F7 FF 73 14 E8 ?? ?? ?? ?? C7 43 14 00 00 00 00 83 C4 0C 5B C3 }
	condition:
		$pattern
}

rule jrand48_r_83d71c2efab5bd20099a70fdf8bf06fd {
	meta:
		aliases = "__GI_jrand48_r, jrand48_r"
		type = "func"
		size = "49"
		objfiles = "jrand48_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 FF 74 24 0C 53 E8 ?? ?? ?? ?? 5A 59 83 CA FF 85 C0 78 15 0F B7 43 04 C1 E0 10 0F B7 53 02 09 D0 8B 54 24 10 89 02 31 D2 89 D0 5B C3 }
	condition:
		$pattern
}

rule nrand48_r_b0d19233fa999b586187102e2fc294ed {
	meta:
		aliases = "__GI_nrand48_r, nrand48_r"
		type = "func"
		size = "55"
		objfiles = "nrand48_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 FF 74 24 0C 53 E8 ?? ?? ?? ?? 5A 59 83 CA FF 85 C0 78 1B 66 8B 43 02 66 D1 E8 0F B7 C0 0F B7 53 04 C1 E2 0F 09 D0 8B 54 24 10 89 02 31 D2 89 D0 5B C3 }
	condition:
		$pattern
}

rule wcsncat_3c851dcdfd197457eafede2860a481da {
	meta:
		aliases = "wcsncat"
		type = "func"
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
		type = "func"
		size = "40"
		objfiles = "wcsncpy@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 0C 8B 4C 24 10 8B 54 24 08 EB 0F 8B 03 89 02 85 C0 74 03 83 C3 04 83 C2 04 49 85 C9 75 ED 8B 44 24 08 5B C3 }
	condition:
		$pattern
}

rule glob_pattern_p_1b81b3ee1af0bed3fe7a8e6918c85f45 {
	meta:
		aliases = "__GI_glob_pattern_p, glob_pattern_p"
		type = "func"
		size = "85"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 0C 8B 54 24 08 31 C9 EB 37 3C 5B 74 16 77 0A 3C 2A 74 37 3C 3F 75 28 EB 31 3C 5C 74 0D 3C 5D 75 1E EB 18 B9 01 00 00 00 EB 15 85 DB 74 11 8D 42 01 80 7A 01 00 74 08 89 C2 EB 04 85 C9 75 0B 42 8A 02 84 C0 75 C3 31 C0 EB 05 B8 01 00 00 00 5B C3 }
	condition:
		$pattern
}

rule authnone_marshal_21fedaee820e4357f28b087583e6993b {
	meta:
		aliases = "authnone_marshal"
		type = "func"
		size = "45"
		objfiles = "auth_none@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 0C E8 ?? ?? ?? ?? 8B 80 98 00 00 00 31 D2 85 C0 74 13 8B 53 04 FF 70 3C 83 C0 28 50 53 FF 52 0C 89 C2 83 C4 0C 89 D0 5B C3 }
	condition:
		$pattern
}

rule __glibc_strerror_r_814991ee05c5cdbc2b6343e60e7aa014 {
	meta:
		aliases = "__GI___glibc_strerror_r, __glibc_strerror_r"
		type = "func"
		size = "26"
		objfiles = "__glibc_strerror_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 0C FF 74 24 10 53 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 0C 89 D8 5B C3 }
	condition:
		$pattern
}

rule __stdio_seek_349eeb10bf10fa87a4a0513803fcf9d0 {
	meta:
		aliases = "__stdio_seek"
		type = "func"
		size = "46"
		objfiles = "_cs_funcs@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 0C FF 74 24 10 FF 73 04 FF 33 8B 44 24 14 FF 70 04 E8 ?? ?? ?? ?? 83 C4 10 89 C1 85 D2 78 07 89 03 89 53 04 31 C9 89 C8 5B C3 }
	condition:
		$pattern
}

rule clnttcp_control_ebc34a71350d1540f9ec319ec58b1000 {
	meta:
		aliases = "clnttcp_control"
		type = "func"
		size = "169"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 10 8B 44 24 08 8B 48 08 8B 44 24 0C 48 83 F8 0E 77 07 FF 24 85 ?? ?? ?? ?? 31 C0 E9 83 00 00 00 C7 41 04 01 00 00 00 EB 75 C7 41 04 00 00 00 00 EB 6C 8B 13 8B 43 04 89 41 0C 89 51 08 C7 41 10 01 00 00 00 EB 58 8B 51 08 8B 41 0C 89 43 04 89 13 EB 4B 8D 41 14 6A 10 50 53 E8 ?? ?? ?? ?? B8 01 00 00 00 83 C4 0C EB 3A 8B 01 EB 26 8B 41 30 0F C8 EB 1F 8B 03 48 0F C8 89 41 30 EB 20 8B 41 40 0F C8 EB 0E 8B 03 0F C8 89 41 40 EB 10 8B 41 3C 0F C8 89 03 EB 07 8B 03 0F C8 89 41 3C B8 01 00 00 00 5B C3 }
	condition:
		$pattern
}

rule clntunix_control_747605d6113dcee6a1e273d5567e5313 {
	meta:
		aliases = "clntunix_control"
		type = "func"
		size = "183"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 10 8B 44 24 08 8B 48 08 8B 44 24 0C 48 83 F8 0E 77 07 FF 24 85 ?? ?? ?? ?? 31 C0 E9 91 00 00 00 C7 41 04 01 00 00 00 E9 80 00 00 00 C7 41 04 00 00 00 00 EB 77 8B 13 8B 43 04 89 41 0C 89 51 08 EB 6A 8B 51 08 8B 41 0C 89 43 04 89 13 EB 5D 8D 41 14 6A 6E 50 53 E8 ?? ?? ?? ?? B8 01 00 00 00 83 C4 0C EB 4C 8B 01 EB 35 8B 81 90 00 00 00 0F C8 EB 2B 8B 03 48 0F C8 89 81 90 00 00 00 EB 2C 8B 81 A0 00 00 00 0F C8 EB 14 8B 03 0F C8 89 81 A0 00 00 00 EB 16 8B 81 9C 00 00 00 0F C8 89 03 EB 0A 8B 03 0F C8 89 81 9C 00 00 00 B8 01 00 00 00 5B C3 }
	condition:
		$pattern
}

rule clntudp_control_36d056258402100d18ff12d5d485d104 {
	meta:
		aliases = "clntudp_control"
		type = "func"
		size = "205"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 10 8B 44 24 08 8B 48 08 8B 44 24 0C 48 83 F8 0E 77 07 FF 24 85 ?? ?? ?? ?? 31 C0 E9 A7 00 00 00 C7 41 04 01 00 00 00 E9 96 00 00 00 C7 41 04 00 00 00 00 E9 8A 00 00 00 8B 13 8B 43 04 89 41 28 89 51 24 EB 7D 8B 51 24 8B 41 28 EB 13 8B 13 8B 43 04 89 41 20 89 51 1C EB 68 8B 51 1C 8B 41 20 89 43 04 89 13 EB 5B 8D 41 08 6A 10 50 53 E8 ?? ?? ?? ?? B8 01 00 00 00 83 C4 0C EB 4A 8B 01 EB 33 8B 41 58 8B 00 0F C8 EB 2A 8B 03 48 0F C8 8B 51 58 89 02 EB 2C 8B 41 58 8B 40 10 0F C8 EB 14 8B 03 0F C8 8B 51 58 89 42 10 EB 16 8B 41 58 8B 40 0C 0F C8 89 03 EB 0A 8B 03 0F C8 8B 51 58 89 42 0C B8 01 }
	condition:
		$pattern
}

rule wmemcmp_2cf584a240ba0dc8c819bd8436b326ee {
	meta:
		aliases = "wmemcmp"
		type = "func"
		size = "43"
		objfiles = "wmemcmp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 10 8B 4C 24 08 8B 54 24 0C EB 07 83 C1 04 83 C2 04 4B 85 DB 75 04 31 C0 EB 0B 8B 01 3B 02 74 EB 19 C0 83 C8 01 5B C3 }
	condition:
		$pattern
}

rule wmemcpy_d1f0e65abe964825a8ca62981a4d12e8 {
	meta:
		aliases = "__GI_wmemcpy, wmemcpy"
		type = "func"
		size = "36"
		objfiles = "wmemcpy@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 10 8B 4C 24 08 8B 54 24 0C EB 0B 8B 02 89 01 83 C1 04 83 C2 04 4B 85 DB 75 F1 8B 44 24 08 5B C3 }
	condition:
		$pattern
}

rule wmempcpy_09e02fba98b8369af5caa50aad44449f {
	meta:
		aliases = "__GI_wmempcpy, wmempcpy"
		type = "func"
		size = "34"
		objfiles = "wmempcpy@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 10 8B 54 24 08 8B 4C 24 0C EB 0B 8B 01 89 02 83 C2 04 83 C1 04 4B 85 DB 75 F1 89 D0 5B C3 }
	condition:
		$pattern
}

rule memccpy_d0f1f8f8b136a54a7660e53e648ea303 {
	meta:
		aliases = "__GI_memccpy, memccpy"
		type = "func"
		size = "41"
		objfiles = "memccpy@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 14 8B 54 24 08 8B 4C 24 0C 4B 83 FB FF 75 04 31 C0 EB 10 8A 01 88 02 42 3A 44 24 10 74 03 41 EB E8 89 D0 5B C3 }
	condition:
		$pattern
}

rule gcvt_3224c159b8cd98e0b0345f4ea45f747d {
	meta:
		aliases = "gcvt"
		type = "func"
		size = "46"
		objfiles = "gcvt@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 14 FF 74 24 0C FF 74 24 0C 8B 44 24 18 83 F8 11 7E 05 B8 11 00 00 00 50 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 14 89 D8 5B C3 }
	condition:
		$pattern
}

rule __dn_expand_e74342b2b7031edfcfa042b4e3887d54 {
	meta:
		aliases = "__dn_expand"
		type = "func"
		size = "44"
		objfiles = "res_comp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 14 FF 74 24 18 53 FF 74 24 18 FF 74 24 18 FF 74 24 18 E8 ?? ?? ?? ?? 83 C4 14 85 C0 7E 08 80 3B 2E 75 03 C6 03 00 5B C3 }
	condition:
		$pattern
}

rule token_f9727ad0cd6123a64d3d6a6b161d37c4 {
	meta:
		aliases = "token"
		type = "func"
		size = "353"
		objfiles = "ruserpass@libc.a"
	strings:
		$pattern = { ( CC | 53 ) A1 ?? ?? ?? ?? 0F B7 00 A8 0C 0F 85 4C 01 00 00 8B 15 ?? ?? ?? ?? 8B 42 10 3B 42 18 73 09 0F B6 08 40 89 42 10 EB 12 52 E8 ?? ?? ?? ?? 89 C1 58 83 F9 FF 0F 84 23 01 00 00 8D 41 F7 83 F8 01 76 CF 83 F9 20 74 CA 83 F9 2C 74 C5 BB ?? ?? ?? ?? 83 F9 22 74 2A EB 54 83 FA 5C 75 20 8B 0D ?? ?? ?? ?? 8B 41 10 3B 41 18 73 09 0F B6 10 40 89 41 10 EB 09 51 E8 ?? ?? ?? ?? 89 C2 58 88 13 43 8B 0D ?? ?? ?? ?? 8B 41 10 3B 41 18 73 09 0F B6 10 40 89 41 10 EB 0E 51 E8 ?? ?? ?? ?? 89 C2 58 83 FA FF 74 75 83 FA 22 75 AE EB 6E 88 0D ?? ?? ?? ?? BB ?? ?? ?? ?? EB 28 83 FA 5C 75 20 8B 0D ?? ?? ?? ?? 8B 41 10 3B }
	condition:
		$pattern
}

rule __setutent_8d16f4f8aa28b37deab69c6d55441b3a {
	meta:
		aliases = "__setutent"
		type = "func"
		size = "148"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) A1 ?? ?? ?? ?? 85 C0 79 7B 8B 15 ?? ?? ?? ?? B9 02 00 08 00 87 D3 B8 05 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF A3 ?? ?? ?? ?? 85 C0 79 35 8B 15 ?? ?? ?? ?? B9 00 00 08 00 87 D3 B8 05 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF A3 ?? ?? ?? ?? 85 C0 78 1E 6A 01 6A 02 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 0A 6A 00 6A 00 50 E8 ?? ?? ?? ?? 83 C4 0C 5B C3 }
	condition:
		$pattern
}

rule dl_cleanup_45db4c2a8f7289b1d247061757dd8d0b {
	meta:
		aliases = "dl_cleanup"
		type = "func"
		size = "29"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 53 ) A1 ?? ?? ?? ?? EB 0F 8B 58 04 BA 01 00 00 00 E8 ?? ?? ?? ?? 89 D8 85 C0 75 ED 5B C3 }
	condition:
		$pattern
}

rule fork_31775a774d77c5d341de3c4c936664ec {
	meta:
		aliases = "__GI_fork, __libc_fork, fork"
		type = "func"
		size = "32"
		objfiles = "fork@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 02 00 00 00 CD 80 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule inotify_init_2dce25e3cdf8c8ddecf1551e169b6ecb {
	meta:
		aliases = "inotify_init"
		type = "func"
		size = "32"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 23 01 00 00 CD 80 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sync_91797e3143937be1df9112298278667b {
	meta:
		aliases = "sync"
		type = "func"
		size = "28"
		objfiles = "sync@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 24 00 00 00 CD 80 89 C3 3D 00 F0 FF FF 76 09 E8 ?? ?? ?? ?? F7 DB 89 18 5B C3 }
	condition:
		$pattern
}

rule setsid_f59dc5ff5c93b33e164eeda86a8d8172 {
	meta:
		aliases = "__GI_setsid, setsid"
		type = "func"
		size = "32"
		objfiles = "setsid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 42 00 00 00 CD 80 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule vhangup_55d94d674b8fd071e9c517442fc2689f {
	meta:
		aliases = "vhangup"
		type = "func"
		size = "32"
		objfiles = "vhangup@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 6F 00 00 00 CD 80 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule munlockall_1b691053ec9d551b2dd637da93c6a55a {
	meta:
		aliases = "munlockall"
		type = "func"
		size = "32"
		objfiles = "munlockall@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 99 00 00 00 CD 80 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule sched_yield_cbba1463f9ba841c9be6b32d101bc6b3 {
	meta:
		aliases = "sched_yield"
		type = "func"
		size = "32"
		objfiles = "sched_yield@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 9E 00 00 00 CD 80 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B C3 }
	condition:
		$pattern
}

rule __rpc_thread_variables_b8903f31c40265af185ad78e5b924212 {
	meta:
		aliases = "__rpc_thread_variables"
		type = "func"
		size = "196"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 ?? ?? ?? ?? 85 C0 74 0A 6A 02 E8 ?? ?? ?? ?? 5A EB 05 A1 ?? ?? ?? ?? 89 C3 85 C0 0F 85 9D 00 00 00 B8 ?? ?? ?? ?? 85 C0 74 13 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 5B EB 18 83 3D ?? ?? ?? ?? 00 75 0F E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 01 00 00 00 B8 ?? ?? ?? ?? 85 C0 74 0A 6A 02 E8 ?? ?? ?? ?? 5A EB 05 A1 ?? ?? ?? ?? 89 C3 85 C0 75 4B 68 C8 00 00 00 6A 01 E8 ?? ?? ?? ?? 59 5B 85 C0 74 1F 89 C3 B8 ?? ?? ?? ?? 85 C0 74 0C 53 6A 02 E8 ?? ?? ?? ?? 58 5A EB 22 89 1D ?? ?? ?? ?? EB 1A B8 ?? ?? ?? ?? 85 C0 74 0A 6A 02 E8 ?? ?? ?? ?? 59 EB 05 A1 ?? ?? ?? ?? 89 C3 89 D8 5B C3 }
	condition:
		$pattern
}

rule __rpc_thread_destroy_c65674572b9a06fe4eb81524e51d667f {
	meta:
		aliases = "__rpc_thread_destroy"
		type = "func"
		size = "159"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | 53 ) B8 ?? ?? ?? ?? 85 C0 74 0C 6A 02 E8 ?? ?? ?? ?? 89 C3 58 EB 06 8B 1D ?? ?? ?? ?? 85 DB 74 7D 81 FB ?? ?? ?? ?? 74 75 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF B3 98 00 00 00 E8 ?? ?? ?? ?? FF B3 9C 00 00 00 E8 ?? ?? ?? ?? FF B3 A0 00 00 00 E8 ?? ?? ?? ?? FF B3 BC 00 00 00 E8 ?? ?? ?? ?? FF B3 AC 00 00 00 E8 ?? ?? ?? ?? FF B3 B0 00 00 00 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 1C B8 ?? ?? ?? ?? 85 C0 74 0D 6A 00 6A 02 E8 ?? ?? ?? ?? 59 5B EB 0A C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 5B C3 }
	condition:
		$pattern
}

rule __uClibc_fini_c321cc52eacbcb14e53140df9f326853 {
	meta:
		aliases = "__GI___uClibc_fini, __uClibc_fini"
		type = "func"
		size = "56"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { ( CC | 53 ) BB ?? ?? ?? ?? 81 EB ?? ?? ?? ?? C1 FB 02 EB 07 FF 14 9D ?? ?? ?? ?? 4B 83 FB FF 75 F3 A1 ?? ?? ?? ?? 85 C0 74 02 FF D0 8B 0D ?? ?? ?? ?? 85 C9 74 03 5B FF E1 5B C3 }
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

rule atexit_dc6a1f05a0481860f86153e8a9f68152 {
	meta:
		aliases = "atexit"
		type = "func"
		size = "44"
		objfiles = "atexits@uclibc_nonshared.a"
	strings:
		$pattern = { ( CC | 53 ) E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 93 ?? ?? ?? ?? 31 C0 85 D2 74 02 8B 02 50 6A 00 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 0C 5B C3 }
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

rule __pthread_reset_main_thread_52781152d8e5ec74de3b82b7fd0e5c14 {
	meta:
		aliases = "__pthread_reset_main_thread"
		type = "func"
		size = "128"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) E8 ?? ?? ?? ?? 89 C3 83 3D ?? ?? ?? ?? FF 74 4C FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? FF FF FF FF C7 05 ?? ?? ?? ?? FF FF FF FF 83 C4 0C E8 ?? ?? ?? ?? 89 43 14 89 1D ?? ?? ?? ?? 89 1B 89 5B 04 C7 43 44 ?? ?? ?? ?? C7 43 4C ?? ?? ?? ?? 5B C3 }
	condition:
		$pattern
}

rule _buf_67122ad37bc8057098ffb437a812dca6 {
	meta:
		aliases = "_buf"
		type = "func"
		size = "42"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 53 ) E8 ?? ?? ?? ?? 89 C3 83 B8 9C 00 00 00 00 75 11 68 00 01 00 00 E8 ?? ?? ?? ?? 89 83 9C 00 00 00 5A 8B 83 9C 00 00 00 5B C3 }
	condition:
		$pattern
}

rule getrpcent_4c7761ee112cc50013e9c035623dd610 {
	meta:
		aliases = "__GI_getrpcent, getrpcent"
		type = "func"
		size = "52"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) E8 ?? ?? ?? ?? 89 C3 85 C0 74 24 83 38 00 75 17 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 03 59 5A 85 C0 74 08 89 D8 5B E9 ?? ?? ?? ?? 31 C0 5B C3 }
	condition:
		$pattern
}

rule endrpcent_2bfc174a49d390453b694b5f1fc8a1fb {
	meta:
		aliases = "__GI_endrpcent, endrpcent"
		type = "func"
		size = "55"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) E8 ?? ?? ?? ?? 89 C3 85 C0 74 29 83 78 0C 00 75 23 FF 70 04 E8 ?? ?? ?? ?? C7 43 04 00 00 00 00 8B 03 5A 85 C0 74 0D 50 E8 ?? ?? ?? ?? C7 03 00 00 00 00 59 5B C3 }
	condition:
		$pattern
}

rule setrpcent_b9825c6b401d215287b64b538be27e92 {
	meta:
		aliases = "__GI_setrpcent, setrpcent"
		type = "func"
		size = "71"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) E8 ?? ?? ?? ?? 89 C3 85 C0 74 39 8B 00 85 C0 75 15 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 03 58 5A EB 07 50 E8 ?? ?? ?? ?? 58 FF 73 04 E8 ?? ?? ?? ?? C7 43 04 00 00 00 00 8B 44 24 0C 09 43 0C 59 5B C3 }
	condition:
		$pattern
}

rule svc_exit_8a20004159e4ccd7b457507ba046e58e {
	meta:
		aliases = "svc_exit"
		type = "func"
		size = "35"
		objfiles = "svc_run@libc.a"
	strings:
		$pattern = { ( CC | 53 ) E8 ?? ?? ?? ?? 89 C3 FF 30 E8 ?? ?? ?? ?? C7 03 00 00 00 00 E8 ?? ?? ?? ?? C7 00 00 00 00 00 58 5B C3 }
	condition:
		$pattern
}

rule svcraw_recv_be6c6990605a8987ffaf4a3d2c078457 {
	meta:
		aliases = "svcraw_recv"
		type = "func"
		size = "69"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 53 ) E8 ?? ?? ?? ?? 8B 90 BC 00 00 00 31 C0 85 D2 74 31 8D 9A 94 23 00 00 C7 82 94 23 00 00 01 00 00 00 8B 82 98 23 00 00 6A 00 53 FF 50 14 FF 74 24 14 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 95 C0 0F B6 C0 5B C3 }
	condition:
		$pattern
}

rule __rpc_thread_clnt_cleanup_376911b029dffd9ac12dfea74077b0d9 {
	meta:
		aliases = "__rpc_thread_clnt_cleanup"
		type = "func"
		size = "39"
		objfiles = "clnt_simple@libc.a"
	strings:
		$pattern = { ( CC | 53 ) E8 ?? ?? ?? ?? 8B 98 A4 00 00 00 85 DB 74 15 8B 13 85 D2 74 08 8B 42 04 52 FF 50 10 5A 53 E8 ?? ?? ?? ?? 58 5B C3 }
	condition:
		$pattern
}

rule svcraw_create_9e032dc8ada19987f857a3da83cc62e8 {
	meta:
		aliases = "svcraw_create"
		type = "func"
		size = "112"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 53 ) E8 ?? ?? ?? ?? 8B 98 BC 00 00 00 85 DB 75 16 68 3C 25 00 00 6A 01 E8 ?? ?? ?? ?? 5A 59 31 D2 85 C0 74 48 89 C3 C7 83 60 22 00 00 00 00 00 00 66 C7 83 64 22 00 00 00 00 C7 83 68 22 00 00 ?? ?? ?? ?? 8D 83 AC 23 00 00 89 83 84 22 00 00 6A 02 68 60 22 00 00 53 8D 83 94 23 00 00 50 E8 ?? ?? ?? ?? 8D 93 60 22 00 00 83 C4 10 89 D0 5B C3 }
	condition:
		$pattern
}

rule raise_6275daf246362165415fd98570c5cb9a {
	meta:
		aliases = "__GI_raise, raise"
		type = "func"
		size = "38"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) E8 ?? ?? ?? ?? FF 74 24 08 50 E8 ?? ?? ?? ?? 89 C3 59 58 31 C0 85 DB 74 0A E8 ?? ?? ?? ?? 89 18 83 C8 FF 5B C3 }
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

rule mmap64_a5c3135a6cedbfd7327ca5f28ba365ea {
	meta:
		aliases = "mmap64"
		type = "func"
		size = "88"
		objfiles = "mmap64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 56 57 8B 54 24 28 8B 4C 24 2C F7 C2 FF 0F 00 00 75 36 0F AC CA 0C C1 E9 0C 75 2D 89 D5 8B 5C 24 14 8B 4C 24 18 8B 54 24 1C 8B 74 24 20 8B 7C 24 24 B8 C0 00 00 00 CD 80 5F 5E 5B 5D 3D 01 F0 FF FF 0F 87 ?? ?? ?? ?? C3 5F 5E 5B 5D B8 EA FF FF FF E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule posix_fadvise64_1511e449734dfa79da8f4d5a23eebe5a {
	meta:
		aliases = "posix_fadvise64"
		type = "func"
		size = "42"
		objfiles = "posix_fadvise64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 56 57 B8 10 01 00 00 8B 5C 24 14 8B 4C 24 18 8B 54 24 1C 8B 74 24 20 8B 7C 24 24 8B 6C 24 28 CD 80 5F 5E 5B 5D F7 D8 C3 }
	condition:
		$pattern
}

rule authunix_create_default_64d615954a30f1ff01fb1e91b99c8acf {
	meta:
		aliases = "__GI_authunix_create_default, authunix_create_default"
		type = "func"
		size = "151"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 00 01 00 00 6A 03 E8 ?? ?? ?? ?? 89 C3 59 31 F6 85 C0 74 14 8D 04 85 00 00 00 00 50 E8 ?? ?? ?? ?? 5A 89 C6 85 C0 74 37 68 FF 00 00 00 8D 44 24 04 50 E8 ?? ?? ?? ?? 5F 5D 40 74 23 C6 84 24 FF 00 00 00 00 E8 ?? ?? ?? ?? 89 C5 E8 ?? ?? ?? ?? 89 C7 56 53 E8 ?? ?? ?? ?? 5A 59 85 C0 79 05 E8 ?? ?? ?? ?? 56 83 F8 10 7E 05 B8 10 00 00 00 50 57 55 8D 44 24 10 50 E8 ?? ?? ?? ?? 89 C3 56 E8 ?? ?? ?? ?? 89 D8 81 C4 18 01 00 00 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule clnt_spcreateerror_f0f555ac6720c195bd9a82c3d0211c44 {
	meta:
		aliases = "__GI_clnt_spcreateerror, clnt_spcreateerror"
		type = "func"
		size = "218"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 00 04 00 00 E8 ?? ?? ?? ?? 89 C5 85 C0 0F 84 B4 00 00 00 E8 ?? ?? ?? ?? 89 C7 FF B4 24 14 04 00 00 68 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 8D 5C 05 00 FF 37 E8 ?? ?? ?? ?? 50 53 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 01 C3 83 C4 1C 8B 07 83 F8 0C 74 35 83 F8 0E 75 6B 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 59 01 C3 FF 77 04 E8 ?? ?? ?? ?? 50 53 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 01 C3 83 C4 18 EB 3B 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8D 34 03 C7 04 24 00 04 00 00 8D 5C 24 0C 53 FF 77 08 E8 ?? ?? ?? ?? 53 56 E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 8D 1C 06 83 C4 20 C6 03 }
	condition:
		$pattern
}

rule svc_getreq_common_57a0d413456f44295f1efe192c17507c {
	meta:
		aliases = "__GI_svc_getreq_common, svc_getreq_common"
		type = "func"
		size = "394"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 00 05 00 00 89 A4 24 CC 04 00 00 8D 84 24 90 01 00 00 89 84 24 D8 04 00 00 E8 ?? ?? ?? ?? 89 C5 8B 90 B4 00 00 00 8B 84 24 14 05 00 00 8B 1C 82 85 DB 0F 84 41 01 00 00 8B 43 08 8D 94 24 B0 04 00 00 52 53 FF 10 5F 5A 85 C0 0F 84 0C 01 00 00 8D 84 24 20 03 00 00 89 84 24 F8 04 00 00 89 9C 24 FC 04 00 00 8B 84 24 BC 04 00 00 89 84 24 E0 04 00 00 8B 84 24 C0 04 00 00 89 84 24 E4 04 00 00 8B 84 24 C4 04 00 00 89 84 24 E8 04 00 00 8D 94 24 EC 04 00 00 8D 84 24 C8 04 00 00 6A 0C 50 52 E8 ?? ?? ?? ?? 83 C4 0C 83 BC 24 C8 04 00 00 00 75 1F A1 ?? ?? ?? ?? 8B 94 24 FC 04 00 00 89 42 20 }
	condition:
		$pattern
}

rule openpty_acce98079e23d9561776536ce58d66e2 {
	meta:
		aliases = "__GI_openpty, openpty"
		type = "func"
		size = "229"
		objfiles = "openpty@libutil.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 00 10 00 00 8B AC 24 20 10 00 00 6A 02 E8 ?? ?? ?? ?? 89 C6 5F 83 C8 FF 83 FE FF 0F 84 B3 00 00 00 56 E8 ?? ?? ?? ?? 5B 85 C0 0F 85 9A 00 00 00 56 E8 ?? ?? ?? ?? 59 85 C0 0F 85 8B 00 00 00 68 00 10 00 00 8D 7C 24 04 57 56 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 74 68 02 01 00 00 57 E8 ?? ?? ?? ?? 89 C3 58 5A 83 FB FF 74 60 85 ED 74 0C 55 6A 02 53 E8 ?? ?? ?? ?? 83 C4 0C 83 BC 24 24 10 00 00 00 74 15 FF B4 24 24 10 00 00 68 14 54 00 00 53 E8 ?? ?? ?? ?? 83 C4 0C 8B 84 24 14 10 00 00 89 30 8B 84 24 18 10 00 00 89 18 31 C0 83 BC 24 1C 10 00 00 00 74 1D 57 FF B4 24 20 10 00 00 E8 ?? ?? }
	condition:
		$pattern
}

rule __res_querydomain_77f0a4bdfee1e4a93cf5407a84267a7e {
	meta:
		aliases = "__GI___res_querydomain, __res_querydomain"
		type = "func"
		size = "229"
		objfiles = "res_query@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 04 04 00 00 8B 9C 24 18 04 00 00 8B BC 24 1C 04 00 00 8B AC 24 28 04 00 00 85 DB 74 04 85 ED 75 0D E8 ?? ?? ?? ?? C7 00 FF FF FF FF EB 22 85 FF 75 48 53 E8 ?? ?? ?? ?? 5E 89 C2 8D 40 01 3D 01 04 00 00 76 10 E8 ?? ?? ?? ?? C7 00 03 00 00 00 83 C8 FF EB 7F 85 D2 74 5A 8D 72 FF 80 3C 33 2E 75 51 56 53 8D 5C 24 0B 53 E8 ?? ?? ?? ?? C6 44 34 0F 00 89 D8 83 C4 0C EB 3B 53 E8 ?? ?? ?? ?? 89 C6 89 3C 24 E8 ?? ?? ?? ?? 59 8D 44 06 02 3D 01 04 00 00 77 AF 57 53 68 ?? ?? ?? ?? 68 01 04 00 00 8D 5C 24 13 53 E8 ?? ?? ?? ?? 89 D8 83 C4 14 EB 02 89 D8 FF B4 24 2C 04 00 00 55 FF B4 24 2C 04 }
	condition:
		$pattern
}

rule ether_ntohost_c2c1be3feefc9d8cccd75d038f252296 {
	meta:
		aliases = "ether_ntohost"
		type = "func"
		size = "147"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 08 01 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 59 5B 83 CB FF 85 C0 74 62 EB 38 89 FA 89 E8 E8 ?? ?? ?? ?? 89 C3 85 C0 74 34 6A 06 57 FF B4 24 28 01 00 00 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 1E 53 FF B4 24 20 01 00 00 E8 ?? ?? ?? ?? 31 DB 58 5A EB 21 8D 6C 24 02 8D BC 24 02 01 00 00 56 68 00 01 00 00 55 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 AA 83 CB FF 56 E8 ?? ?? ?? ?? 58 89 D8 81 C4 08 01 00 00 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule clnt_sperror_1a9d60338ad0cbccafc4a1e0145463ad {
	meta:
		aliases = "__GI_clnt_sperror, clnt_sperror"
		type = "func"
		size = "357"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 0C 04 00 00 8B 9C 24 20 04 00 00 E8 ?? ?? ?? ?? 89 C5 31 C0 85 ED 0F 84 38 01 00 00 8B 53 04 8D 84 24 00 04 00 00 50 53 FF 52 08 FF B4 24 2C 04 00 00 68 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 8D 5C 05 00 FF B4 24 14 04 00 00 E8 ?? ?? ?? ?? 50 53 E8 ?? ?? ?? ?? 83 C4 20 53 E8 ?? ?? ?? ?? 5E 8D 34 03 83 BC 24 00 04 00 00 11 0F 87 BE 00 00 00 8B 84 24 00 04 00 00 FF 24 85 ?? ?? ?? ?? 68 00 04 00 00 8D 5C 24 04 53 FF B4 24 0C 04 00 00 E8 ?? ?? ?? ?? 53 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 01 C6 83 C4 18 E9 A2 00 00 00 8B 94 24 04 04 00 00 31 C0 EB 19 39 14 C5 ?? ?? ?? ?? 75 0F 8B 3C C5 ?? ?? }
	condition:
		$pattern
}

rule __getgrouplist_internal_520bf92d2c6190536ad72e48e2702b62 {
	meta:
		aliases = "__getgrouplist_internal"
		type = "func"
		size = "260"
		objfiles = "__getgrouplist_internal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 10 01 00 00 8B 84 24 2C 01 00 00 C7 00 01 00 00 00 6A 20 E8 ?? ?? ?? ?? 5D 31 ED 85 C0 0F 84 CE 00 00 00 89 C5 8B 84 24 28 01 00 00 89 45 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 5B 5F 85 C0 0F 84 A7 00 00 00 C7 40 34 01 00 00 00 BF 01 00 00 00 EB 61 8B 84 24 28 01 00 00 39 84 24 08 01 00 00 74 51 8B 9C 24 0C 01 00 00 EB 42 FF B4 24 24 01 00 00 50 E8 ?? ?? ?? ?? 5A 59 85 C0 75 2C F7 C7 07 00 00 00 75 16 8D 04 BD 20 00 00 00 50 55 E8 ?? ?? ?? ?? 5A 59 85 C0 74 41 89 C5 8B 84 24 08 01 00 00 89 44 BD 00 47 EB 09 83 C3 04 8B 03 85 C0 75 B8 56 68 00 01 00 00 8D 44 24 }
	condition:
		$pattern
}

rule clnt_broadcast_5df5237f651f1da73b2b4a1982fe1d10 {
	meta:
		aliases = "clnt_broadcast"
		type = "func"
		size = "1375"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 10 29 00 00 E8 ?? ?? ?? ?? 89 44 24 04 C7 84 24 08 29 00 00 01 00 00 00 6A 11 6A 02 6A 02 E8 ?? ?? ?? ?? 89 C5 83 C4 0C 85 C0 79 0A 68 ?? ?? ?? ?? E9 2B 03 00 00 6A 04 8D 84 24 0C 29 00 00 50 6A 06 6A 01 55 E8 ?? ?? ?? ?? 83 C4 14 85 C0 79 0A 68 ?? ?? ?? ?? E9 06 03 00 00 89 AC 24 FC 28 00 00 66 C7 84 24 00 29 00 00 01 00 C7 84 24 F4 28 00 00 60 22 00 00 8D 44 24 1C 89 84 24 F8 28 00 00 8D 84 24 F4 28 00 00 50 68 12 89 00 00 55 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 79 18 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 44 24 10 00 00 00 00 58 E9 DC 00 00 00 8B 9C 24 F8 28 00 00 8B BC 24 F4 28 00 00 }
	condition:
		$pattern
}

rule statvfs_df3c1346be5dc07be898b02e33405ccf {
	meta:
		aliases = "__GI_fstatvfs, __GI_statvfs, fstatvfs, statvfs"
		type = "func"
		size = "644"
		objfiles = "fstatvfs@libc.a, statvfs@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 14 05 00 00 8B B4 24 28 05 00 00 8B 9C 24 2C 05 00 00 8D 84 24 B8 04 00 00 50 56 E8 ?? ?? ?? ?? 5F 5D 83 CA FF 85 C0 0F 88 44 02 00 00 8B 84 24 BC 04 00 00 89 03 89 43 04 8B 84 24 C0 04 00 00 89 43 08 8B 84 24 C4 04 00 00 89 43 0C 8B 84 24 C8 04 00 00 89 43 10 8B 84 24 CC 04 00 00 89 43 14 8B 84 24 D0 04 00 00 89 43 18 8B 84 24 D4 04 00 00 89 43 20 C7 43 24 00 00 00 00 8B 84 24 DC 04 00 00 89 43 2C 31 C0 8D 7B 30 AB AB AB AB AB AB 8B 43 18 89 43 1C C7 43 28 00 00 00 00 8D 84 24 60 04 00 00 50 56 E8 ?? ?? ?? ?? 5A 59 31 D2 85 C0 0F 88 B9 01 00 00 E8 ?? ?? ?? ?? 89 04 24 8B 00 }
	condition:
		$pattern
}

rule realpath_27cdbd171e02679d79fa10418fdcb720 {
	meta:
		aliases = "__GI_realpath, realpath"
		type = "func"
		size = "572"
		objfiles = "realpath@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 1C 10 00 00 8B 9C 24 30 10 00 00 8B BC 24 34 10 00 00 85 DB 75 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 10 80 3B 00 75 12 E8 ?? ?? ?? ?? C7 00 02 00 00 00 31 FF E9 EF 01 00 00 53 E8 ?? ?? ?? ?? 5A 3D FD 0F 00 00 76 0D E8 ?? ?? ?? ?? C7 00 24 00 00 00 EB DE 8D AC 24 1B 10 00 00 29 C5 53 55 E8 ?? ?? ?? ?? 89 EB 5E 58 C7 44 24 08 00 00 00 00 85 FF 75 11 68 00 10 00 00 E8 ?? ?? ?? ?? 89 C7 89 44 24 0C 59 8D 87 FE 0F 00 00 89 44 24 04 80 7D 00 2F 74 40 68 FF 0F 00 00 57 E8 ?? ?? ?? ?? 5D 5A 85 C0 0F 84 94 00 00 00 57 E8 ?? ?? ?? ?? 5E 8D 34 07 80 7E FF 2F 74 04 C6 06 2F 46 C7 44 24 }
	condition:
		$pattern
}

rule vsyslog_0e15fa08caf63aca07cf937fb68b5ad7 {
	meta:
		aliases = "__GI_vsyslog, vsyslog"
		type = "func"
		size = "670"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 28 04 00 00 8B B4 24 3C 04 00 00 F7 C6 00 FC FF FF 0F 85 76 02 00 00 E8 ?? ?? ?? ?? 89 44 24 08 8B 28 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 84 24 1C 04 00 00 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 05 ?? ?? ?? ?? 89 F1 83 E1 07 D3 F8 83 C4 10 A8 01 0F 84 20 02 00 00 83 3D ?? ?? ?? ?? 00 78 09 80 3D ?? ?? ?? ?? 00 75 1D 0F B6 0D ?? ?? ?? ?? C1 E1 03 8A 15 ?? ?? ?? ?? 83 CA 08 0F B6 D2 31 C0 E8 ?? ?? ?? ?? F7 C6 F8 03 00 00 75 0C 0F B6 05 ?? ?? ?? ?? C1 E0 03 09 C6 8D 9C 24 24 04 00 00 53 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C0 04 50 56 68 ?? ?? ?? ?? 8D 5C 24 28 53 E8 }
	condition:
		$pattern
}

rule get_myaddress_1f5121a67b2368719ebea1d8bf30b26a {
	meta:
		aliases = "get_myaddress"
		type = "func"
		size = "280"
		objfiles = "get_myaddress@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 28 10 00 00 6A 00 6A 02 6A 02 E8 ?? ?? ?? ?? 89 C7 83 C4 0C 85 C0 79 07 68 ?? ?? ?? ?? EB 31 C7 84 24 20 10 00 00 00 10 00 00 89 A4 24 24 10 00 00 8D 84 24 20 10 00 00 50 68 12 89 00 00 57 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 79 11 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 01 E8 ?? ?? ?? ?? 31 ED 8B 9C 24 24 10 00 00 8B B4 24 20 10 00 00 EB 7D 6A 20 53 8D 84 24 08 10 00 00 50 E8 ?? ?? ?? ?? 8D 84 24 0C 10 00 00 50 68 13 89 00 00 57 E8 ?? ?? ?? ?? 83 C4 18 85 C0 79 07 68 ?? ?? ?? ?? EB B1 0F BF 84 24 10 10 00 00 A8 01 74 3A 66 83 7B 10 02 75 33 A8 08 74 05 83 FD 01 75 2A 8D 43 10 6A 10 50 FF }
	condition:
		$pattern
}

rule __get_myaddress_ae872986d626babea19698e7dd85d933 {
	meta:
		aliases = "__get_myaddress"
		type = "func"
		size = "286"
		objfiles = "pmap_clnt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 2C 10 00 00 89 04 24 6A 00 6A 02 6A 02 E8 ?? ?? ?? ?? 89 C7 83 C4 0C 85 C0 79 07 68 ?? ?? ?? ?? EB 3A C7 84 24 24 10 00 00 00 10 00 00 8D 44 24 04 89 84 24 28 10 00 00 8D 84 24 24 10 00 00 50 68 12 89 00 00 57 E8 ?? ?? ?? ?? 83 C4 0C BD 01 00 00 00 85 C0 79 11 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 01 E8 ?? ?? ?? ?? 8B 9C 24 28 10 00 00 8B B4 24 24 10 00 00 EB 7B 6A 20 53 8D 84 24 0C 10 00 00 50 E8 ?? ?? ?? ?? 8D 84 24 10 10 00 00 50 68 13 89 00 00 57 E8 ?? ?? ?? ?? 83 C4 18 85 C0 79 07 68 ?? ?? ?? ?? EB B3 0F BF 84 24 14 10 00 00 A8 01 74 38 66 83 7B 10 02 75 31 A8 08 75 04 85 ED }
	condition:
		$pattern
}

rule des_init_1e0a13c7761ad9d250d6bdaf67efebe8 {
	meta:
		aliases = "des_init"
		type = "func"
		size = "976"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 30 02 00 00 83 3D ?? ?? ?? ?? 01 0F 84 AE 03 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 31 DB EB 3E 31 C9 89 DE C1 E6 06 8D 84 24 30 02 00 00 8D 3C 06 89 CA 83 E2 01 C1 E2 04 89 C8 D1 F8 83 E0 0F 09 C2 89 C8 83 E0 20 09 C2 8A 84 32 ?? ?? ?? ?? 88 84 39 00 FE FF FF 41 83 F9 3F 7E D4 43 83 FB 07 7E BD 31 ED EB 45 89 F2 C1 E2 06 09 DA 89 E9 C1 E1 0C 89 4C 24 08 8B 4C 24 0C 0F B6 81 00 FE FF FF C1 E0 04 8B 4C 24 10 0A 84 0B 00 FE FF FF 8B 4C 24 08 88 84 0A ?? ?? ?? ?? 43 83 FB 3F 7E C6 46 83 FE 3F }
	condition:
		$pattern
}

rule _dl_load_elf_shared_library_d26689ddd98b5e43c116249eeb72bfe5 {
	meta:
		aliases = "_dl_load_elf_shared_library"
		type = "func"
		size = "2747"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 34 01 00 00 31 C9 31 D2 8B 84 24 50 01 00 00 53 89 C3 B8 05 00 00 00 CD 80 5B 89 44 24 30 3D 00 F0 FF FF 76 09 F7 D8 A3 ?? ?? ?? ?? EB 07 83 7C 24 30 00 79 0F C7 05 ?? ?? ?? ?? 01 00 00 00 E9 57 0A 00 00 8D 8C 24 F0 00 00 00 8B 54 24 30 87 D3 B8 6C 00 00 00 CD 80 87 D3 3D 00 F0 FF FF 76 09 F7 D8 A3 ?? ?? ?? ?? EB 04 85 C0 79 0F C7 05 ?? ?? ?? ?? 01 00 00 00 E9 FB 07 00 00 83 BC 24 48 01 00 00 00 74 0E F6 84 24 F9 00 00 00 08 0F 84 E3 07 00 00 8B 2D ?? ?? ?? ?? EB 42 8B 84 24 F0 00 00 00 83 BD E0 00 00 00 00 75 2F 39 85 DC 00 00 00 75 27 8B 85 E4 00 00 00 3B 84 24 F4 00 00 00 }
	condition:
		$pattern
}

rule statvfs64_21f0316f257d26668d182dc685b5d9cd {
	meta:
		aliases = "fstatvfs64, statvfs64"
		type = "func"
		size = "700"
		objfiles = "statvfs64@libc.a, fstatvfs64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 38 05 00 00 8B B4 24 4C 05 00 00 8B 9C 24 50 05 00 00 8D 84 24 C8 04 00 00 50 56 E8 ?? ?? ?? ?? 5F 5D 83 CA FF 85 C0 0F 88 7C 02 00 00 8B 84 24 CC 04 00 00 89 03 89 43 04 8B 84 24 D0 04 00 00 8B 94 24 D4 04 00 00 89 43 08 89 53 0C 8B 84 24 D8 04 00 00 8B 94 24 DC 04 00 00 89 43 10 89 53 14 8B 84 24 E0 04 00 00 8B 94 24 E4 04 00 00 89 43 18 89 53 1C 8B 84 24 E8 04 00 00 8B 94 24 EC 04 00 00 89 43 20 89 53 24 8B 84 24 F0 04 00 00 8B 94 24 F4 04 00 00 89 43 28 89 53 2C 8B 84 24 F8 04 00 00 89 43 38 C7 43 3C 00 00 00 00 8B 84 24 00 05 00 00 89 43 44 31 C0 8D 7B 48 AB AB AB AB AB }
	condition:
		$pattern
}

rule __kernel_rem_pio2_4d42c5c82eb6d25ca800e9d812a6b7ef {
	meta:
		aliases = "__kernel_rem_pio2"
		type = "func"
		size = "1476"
		objfiles = "k_rem_pio2@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 60 02 00 00 8B 8C 24 7C 02 00 00 8B 84 24 84 02 00 00 8B 04 85 ?? ?? ?? ?? 89 44 24 14 8B 9C 24 80 02 00 00 4B 89 5C 24 10 8D 51 FD BB 18 00 00 00 89 D0 99 F7 FB 89 44 24 1C F7 D0 C1 F8 1F 21 44 24 1C 8B 44 24 1C 40 6B C0 18 89 CE 29 C6 8B 44 24 1C 2B 44 24 10 8B 4C 24 14 03 4C 24 10 31 D2 EB 1B 85 C0 79 04 D9 EE EB 0A 8B 9C 24 88 02 00 00 DB 04 83 DD 9C D4 70 01 00 00 42 40 39 CA 7E E1 31 C9 EB 23 89 D8 29 D0 8B BC 24 74 02 00 00 DD 04 D7 DC 8C C4 70 01 00 00 DE C1 42 3B 54 24 10 7E E2 DD 5C CC 30 41 3B 4C 24 14 7F 0D 31 D2 D9 EE 8B 6C 24 10 8D 1C 29 EB E2 8B 5C 24 14 C7 44 }
	condition:
		$pattern
}

rule _vfprintf_internal_bc40063f6028f6eee04d0d0db9bb5980 {
	meta:
		aliases = "_vfprintf_internal"
		type = "func"
		size = "1545"
		objfiles = "_vfprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 68 01 00 00 8B 9C 24 80 01 00 00 53 8D 74 24 10 56 E8 ?? ?? ?? ?? 5F 5D 85 C0 79 38 8B 5C 24 0C 53 E8 ?? ?? ?? ?? 5E C7 04 24 FF FF FF FF 85 C0 0F 84 BF 05 00 00 FF B4 24 7C 01 00 00 50 53 E8 ?? ?? ?? ?? C7 44 24 0C FF FF FF FF 83 C4 0C E9 A1 05 00 00 FF B4 24 84 01 00 00 56 E8 ?? ?? ?? ?? 89 DA C7 44 24 08 00 00 00 00 58 59 EB 01 43 8A 03 84 C0 74 04 3C 25 75 F5 39 D3 74 26 89 DE 29 D6 31 C0 85 F6 7E 11 FF B4 24 7C 01 00 00 56 52 E8 ?? ?? ?? ?? 83 C4 0C 39 F0 0F 85 4D 05 00 00 01 04 24 80 3B 00 0F 84 48 05 00 00 8D 53 01 80 7B 01 25 0F 84 2C 05 00 00 89 54 24 0C C7 84 24 64 }
	condition:
		$pattern
}

rule universal_d8104b8a5bd92246061a858e7dca68ac {
	meta:
		aliases = "universal"
		type = "func"
		size = "313"
		objfiles = "svc_simple@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 68 22 00 00 8B 84 24 7C 22 00 00 8B B4 24 80 22 00 00 C7 84 24 64 22 00 00 00 00 00 00 8B 68 08 85 ED 75 2B 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 0F 85 EC 00 00 00 6A 04 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? E9 84 00 00 00 8B 38 E8 ?? ?? ?? ?? 8B 98 C0 00 00 00 E9 8C 00 00 00 39 7B 04 0F 85 80 00 00 00 39 6B 08 75 7B 31 C0 B9 98 08 00 00 8D 6C 24 04 89 EF F3 AB 8B 46 08 55 FF 73 0C 56 FF 50 08 83 C4 0C 85 C0 75 0C 56 E8 ?? ?? ?? ?? 5B E9 8C 00 00 00 55 FF 13 59 85 C0 75 09 81 7B 10 ?? ?? ?? ?? 75 7B 50 FF 73 10 56 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 1C FF 73 04 68 }
	condition:
		$pattern
}

rule rexec_af_38198af33aa5325c8c96972672a5cba4 {
	meta:
		aliases = "__GI_rexec_af, rexec_af"
		type = "func"
		size = "1058"
		objfiles = "rexec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 80 01 00 00 8B 84 24 98 01 00 00 0F B7 9C 24 AC 01 00 00 8B 94 24 9C 01 00 00 89 14 24 8B BC 24 A0 01 00 00 89 7C 24 04 66 C1 C8 08 0F B7 C0 50 68 ?? ?? ?? ?? 8D B4 24 38 01 00 00 56 E8 ?? ?? ?? ?? 31 C0 B9 08 00 00 00 8D 94 24 5C 01 00 00 89 D7 F3 AB 89 9C 24 60 01 00 00 C7 84 24 64 01 00 00 01 00 00 00 C7 84 24 5C 01 00 00 02 00 00 00 8D 84 24 84 01 00 00 50 52 56 8B 84 24 AC 01 00 00 FF 30 E8 ?? ?? ?? ?? 83 C4 1C 83 CF FF 85 C0 0F 85 78 03 00 00 8B 84 24 78 01 00 00 8B 40 18 85 C0 74 4D 68 01 04 00 00 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 00 8B 94 24 A0 01 00 }
	condition:
		$pattern
}

rule _vfwprintf_internal_1cfc8c0b4ec364c451b12e2c93da3183 {
	meta:
		aliases = "_vfwprintf_internal"
		type = "func"
		size = "1870"
		objfiles = "_vfwprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 80 02 00 00 8B B4 24 98 02 00 00 31 C0 B9 2F 00 00 00 8D BC 24 10 01 00 00 F3 AB FF 8C 24 28 01 00 00 89 B4 24 10 01 00 00 C7 84 24 20 01 00 00 80 00 00 00 C7 84 24 70 02 00 00 00 00 00 00 89 B4 24 7C 02 00 00 8D 84 24 70 02 00 00 50 6A FF 8D 84 24 84 02 00 00 50 6A 00 E8 ?? ?? ?? ?? 83 C4 10 40 75 0D C7 84 24 10 01 00 00 ?? ?? ?? ?? EB 7B BA 09 00 00 00 8D 84 24 38 01 00 00 C7 00 08 00 00 00 83 C0 04 4A 75 F4 89 F0 8D 9C 24 10 01 00 00 EB 2B 83 FA 25 75 23 83 C0 04 83 38 25 74 1B 89 84 24 10 01 00 00 53 E8 ?? ?? ?? ?? 59 85 C0 78 39 8B 84 24 10 01 00 00 EB 03 83 C0 04 8B 10 }
	condition:
		$pattern
}

rule rendezvous_request_561e60adf290d521cd23f2f1d061f1d4 {
	meta:
		aliases = "rendezvous_request"
		type = "func"
		size = "136"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 84 00 00 00 8B 9C 24 98 00 00 00 8B 6B 2C 8D BC 24 80 00 00 00 C7 84 24 80 00 00 00 6E 00 00 00 57 8D 44 24 06 50 FF 33 E8 ?? ?? ?? ?? 89 C6 83 C4 0C 85 C0 79 0C E8 ?? ?? ?? ?? 83 38 04 75 35 EB D3 31 C0 8D 5C 24 70 89 DF AB AB AB AB 66 C7 44 24 70 01 00 8B 4D 04 8B 55 00 89 F0 E8 ?? ?? ?? ?? 8D 78 10 89 DE A5 A5 A5 A5 8B 94 24 80 00 00 00 89 50 0C 31 C0 81 C4 84 00 00 00 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __gen_tempname_b5f14840040deb954a10642bf5ca8ddc {
	meta:
		aliases = "__gen_tempname"
		type = "func"
		size = "630"
		objfiles = "tempname@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 84 00 00 00 E8 ?? ?? ?? ?? 89 44 24 04 8B 00 89 44 24 10 FF B4 24 98 00 00 00 E8 ?? ?? ?? ?? 5B 83 F8 05 76 2D 8B 94 24 98 00 00 00 8D 44 10 FA 89 44 24 08 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 5A 59 85 C0 75 0D C7 44 24 0C 00 00 00 00 E9 F8 01 00 00 8B 4C 24 04 C7 01 16 00 00 00 E9 01 02 00 00 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C7 5E 5D 85 C0 79 17 68 00 08 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C7 59 5B 85 C0 78 24 6A 06 8D 9C 24 82 00 00 00 53 57 E8 ?? ?? ?? ?? 89 C3 57 E8 ?? ?? ?? ?? 83 C4 10 83 FB 06 0F 84 AE 00 00 00 6A 00 8D 44 24 78 50 E8 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getnameinfo_95d4679e246c7de2d597657e45fd4ac3 {
	meta:
		aliases = "__GI_getnameinfo, getnameinfo"
		type = "func"
		size = "843"
		objfiles = "getnameinfo@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 94 02 00 00 8B AC 24 A8 02 00 00 8B 9C 24 AC 02 00 00 E8 ?? ?? ?? ?? 89 04 24 8B 00 89 44 24 08 83 C8 FF F7 84 24 C0 02 00 00 E0 FF FF FF 0F 85 06 03 00 00 85 ED 0F 84 F9 02 00 00 83 FB 01 0F 86 F0 02 00 00 66 8B 45 00 66 83 F8 01 74 1E 66 83 F8 02 75 05 83 FB 0F EB 0D 66 83 F8 0A 0F 85 D1 02 00 00 83 FB 1B 0F 86 C8 02 00 00 83 BC 24 B0 02 00 00 00 0F 95 44 24 05 83 BC 24 B4 02 00 00 00 0F 95 44 24 06 80 7C 24 05 00 0F 84 A8 01 00 00 80 7C 24 06 00 0F 84 9D 01 00 00 66 83 F8 02 74 13 66 83 F8 0A 74 0D 66 48 0F 85 89 01 00 00 E9 25 01 00 00 F6 84 24 C0 02 00 00 01 0F 85 B9 00 }
	condition:
		$pattern
}

rule _time_tzset_8eeaff5fa502ad9473ac1880dbd84066 {
	meta:
		aliases = "_time_tzset"
		type = "func"
		size = "927"
		objfiles = "tzset@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 98 00 00 00 C7 84 24 94 00 00 00 00 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 84 24 8C 00 00 00 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 83 C4 14 85 C0 75 4E 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C7 58 5A 85 FF 78 32 6A 44 8D 5C 24 14 53 57 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 78 15 8D 04 03 39 D8 76 0E 80 78 FF 0A 75 08 C6 40 FF 00 89 DE EB 02 31 F6 57 E8 ?? ?? ?? ?? 58 85 F6 0F 84 87 02 00 00 8A 06 84 C0 0F 84 7D 02 00 00 3C 3A 0F 94 C0 0F B6 C0 01 C6 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 5F 5D 85 C0 0F 84 C5 02 00 00 6A 44 56 68 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule parse_printf_format_603974daf087f0d83effedff23c98f1b {
	meta:
		aliases = "parse_printf_format"
		type = "func"
		size = "226"
		objfiles = "parse_printf_format@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC BC 00 00 00 8B BC 24 D0 00 00 00 8B B4 24 D4 00 00 00 8B 9C 24 D8 00 00 00 57 8D 44 24 04 50 E8 ?? ?? ?? ?? 5A 59 31 ED 85 C0 0F 88 9F 00 00 00 8B 44 24 18 85 C0 0F 8E 8D 00 00 00 89 C5 89 F2 39 C6 76 02 89 C2 31 C9 EB 0A 8B 44 8C 28 89 03 83 C3 04 41 39 D1 72 F2 EB 75 3C 25 75 6A 47 80 3F 25 74 64 89 3C 24 8D 04 24 50 E8 ?? ?? ?? ?? 8B 7C 24 04 58 81 7C 24 08 00 00 00 80 75 0F 45 85 F6 74 0A C7 03 00 00 00 00 83 C3 04 4E 81 7C 24 04 00 00 00 80 75 0F 45 85 F6 74 0A C7 03 00 00 00 00 83 C3 04 4E 31 D2 EB 15 8B 44 94 28 83 F8 08 74 0B 45 85 F6 74 06 89 03 83 C3 04 4E 42 3B 54 }
	condition:
		$pattern
}

rule _fpmaxtostr_ba07eefe2ab592b20939abdd7b0e7102 {
	meta:
		aliases = "_fpmaxtostr"
		type = "func"
		size = "1479"
		objfiles = "_fpmaxtostr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC C4 00 00 00 DB AC 24 DC 00 00 00 8B 84 24 E8 00 00 00 8B 40 04 89 44 24 10 8B 94 24 E8 00 00 00 8B 2A 8A 4A 08 88 4C 24 1A C6 84 24 AE 00 00 00 65 88 C8 83 C8 20 3C 61 75 07 83 C1 06 88 4C 24 1A 85 ED 79 05 BD 06 00 00 00 C6 84 24 BE 00 00 00 00 8B BC 24 E8 00 00 00 8B 47 0C A8 02 74 0A C6 84 24 BE 00 00 00 2B EB 0C A8 01 74 08 C6 84 24 BE 00 00 00 20 C6 84 24 BF 00 00 00 00 C7 44 24 44 00 00 00 00 DD E0 DF E0 9E 7A 02 74 0C DD D8 C7 44 24 44 08 00 00 00 EB 61 D9 EE D9 C9 DD E1 DF E0 9E 75 2A 7A 28 D9 E8 D8 F1 D9 CA C7 44 24 0C FF FF FF FF DD EA DF E0 DD D9 9E 0F 86 08 01 00 }
	condition:
		$pattern
}

rule authunix_create_afba51aa8e9a1832bb13d64745718585 {
	meta:
		aliases = "__GI_authunix_create, authunix_create"
		type = "func"
		size = "358"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC C8 01 00 00 6A 28 E8 ?? ?? ?? ?? 89 C7 68 B0 01 00 00 E8 ?? ?? ?? ?? 89 C6 5B 5D 85 FF 74 04 85 C0 75 26 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 31 FF 83 C4 10 E9 0A 01 00 00 C7 47 20 ?? ?? ?? ?? 89 47 24 8D 58 0C 6A 0C 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8D 47 0C 6A 0C 53 50 E8 ?? ?? ?? ?? C7 46 18 00 00 00 00 6A 00 8D 84 24 DC 01 00 00 50 E8 ?? ?? ?? ?? 8B 84 24 E0 01 00 00 89 84 24 C8 01 00 00 8B 84 24 FC 01 00 00 89 84 24 CC 01 00 00 8B 84 24 00 02 00 00 89 84 24 D0 01 00 00 8B 84 24 04 02 00 00 89 84 24 D4 01 00 00 8B 84 24 08 02 }
	condition:
		$pattern
}

rule __psfs_do_numeric_abdcfb8c72d783f556850739b53757c8 {
	meta:
		aliases = "__psfs_do_numeric"
		type = "func"
		size = "1053"
		objfiles = "__psfs_do_numeric@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC CC 00 00 00 8B BC 24 E4 00 00 00 8B 84 24 E0 00 00 00 8B 40 3C 89 44 24 08 0F B6 A8 ?? ?? ?? ?? 48 75 5E BB ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 5A 85 C0 78 07 0F B6 03 3B 07 74 14 57 E8 ?? ?? ?? ?? 58 81 FB ?? ?? ?? ?? 76 38 E9 B5 03 00 00 43 80 3B 00 75 D4 8B 94 24 E0 00 00 00 80 7A 44 00 0F 84 A5 03 00 00 FF 42 34 6A 00 6A 00 FF 72 38 FF 72 2C E8 ?? ?? ?? ?? 31 C0 83 C4 10 E9 8B 03 00 00 57 E8 ?? ?? ?? ?? 8B 17 5E 83 C8 FF 85 D2 0F 88 77 03 00 00 83 FA 2B 74 09 8D 74 24 21 83 FA 2D 75 0F 88 54 24 21 57 E8 ?? ?? ?? ?? 8D 74 24 26 5B F7 C5 EF 00 00 00 75 59 83 3F 30 75 49 57 E8 ?? }
	condition:
		$pattern
}

rule ttyname_r_7614351c121abd997336fac0e16a3838 {
	meta:
		aliases = "__GI_ttyname_r, ttyname_r"
		type = "func"
		size = "353"
		objfiles = "ttyname@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC D4 00 00 00 8B 9C 24 E8 00 00 00 8D 44 24 5C 50 53 E8 ?? ?? ?? ?? 5E 5F 85 C0 79 0C E8 ?? ?? ?? ?? 8B 18 E9 26 01 00 00 53 E8 ?? ?? ?? ?? 59 BA ?? ?? ?? ?? 85 C0 0F 85 FC 00 00 00 E9 01 01 00 00 0F B6 D8 8D 7A 01 57 8D 84 24 B8 00 00 00 50 E8 ?? ?? ?? ?? 8D 84 24 BC 00 00 00 01 D8 89 44 24 08 BD 1E 00 00 00 29 DD 57 E8 ?? ?? ?? ?? 89 C6 83 C4 0C 85 C0 0F 85 9E 00 00 00 E9 AF 00 00 00 8D 58 0B 53 E8 ?? ?? ?? ?? 5A 39 E8 0F 87 87 00 00 00 53 FF 74 24 04 E8 ?? ?? ?? ?? 8D 44 24 0C 50 8D 84 24 C0 00 00 00 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 64 8B 44 24 14 25 00 F0 00 00 3D 00 20 }
	condition:
		$pattern
}

rule pow_b195aadcefdb096b8e2df0a7ae6a1be2 {
	meta:
		aliases = "__GI_pow, __ieee754_pow, pow"
		type = "func"
		size = "1903"
		objfiles = "e_pow@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC D4 00 00 00 DD 84 24 E8 00 00 00 DD 5C 24 18 DD 84 24 F0 00 00 00 DD 5C 24 10 DD 44 24 18 DD 9C 24 98 00 00 00 8B AC 24 9C 00 00 00 89 AC 24 B4 00 00 00 8B 8C 24 98 00 00 00 89 8C 24 B8 00 00 00 81 FD 00 00 F0 3F 75 08 85 C9 0F 84 09 07 00 00 DD 44 24 10 DD 9C 24 90 00 00 00 8B 84 24 94 00 00 00 89 84 24 A0 00 00 00 89 C7 8B 94 24 90 00 00 00 89 C3 81 E3 FF FF FF 7F 89 D9 09 D1 0F 84 CF 06 00 00 89 EE 81 E6 FF FF FF 7F 81 FE 00 00 F0 7F 7F 22 0F 94 84 24 A7 00 00 00 75 0A 83 BC 24 B8 00 00 00 00 75 0E 81 FB 00 00 F0 7F 7F 06 75 11 85 D2 74 0D DD 44 24 18 DC 44 24 10 E9 92 06 }
	condition:
		$pattern
}

rule __md5_crypt_c53653be4c4c8ee01a1391182fdc766a {
	meta:
		aliases = "__md5_crypt"
		type = "func"
		size = "695"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC D8 00 00 00 8B 9C 24 F0 00 00 00 6A 03 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 0C 89 5C 24 08 85 C0 75 07 83 C3 03 89 5C 24 08 8B 44 24 08 89 C1 83 C1 08 EB 01 40 8A 10 84 D2 74 09 80 FA 24 74 04 39 C8 72 F0 2B 44 24 08 89 44 24 0C 8D 5C 24 6C 89 D8 E8 ?? ?? ?? ?? FF B4 24 EC 00 00 00 E8 ?? ?? ?? ?? 5A 89 C5 89 C1 8B 94 24 EC 00 00 00 89 D8 E8 ?? ?? ?? ?? B9 03 00 00 00 BA ?? ?? ?? ?? 89 D8 E8 ?? ?? ?? ?? 8B 4C 24 0C 8B 54 24 08 89 D8 E8 ?? ?? ?? ?? 8D 74 24 14 89 F0 E8 ?? ?? ?? ?? 89 E9 8B 94 24 EC 00 00 00 89 F0 E8 ?? ?? ?? ?? 8B 4C 24 0C 8B 54 24 08 89 F0 E8 ?? ?? ?? ?? 89 }
	condition:
		$pattern
}

rule __dns_lookup_8ae3a4b6ce3be1e55f18ce90f3e51f39 {
	meta:
		aliases = "__dns_lookup"
		type = "func"
		size = "1812"
		objfiles = "dnslookup@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC E0 01 00 00 8B 9C 24 F4 01 00 00 68 00 02 00 00 E8 ?? ?? ?? ?? 89 C5 53 E8 ?? ?? ?? ?? 89 44 24 14 59 5E 3D 7E 03 00 00 76 15 C7 44 24 1C FF FF FF FF C7 44 24 2C 00 00 00 00 E9 8B 06 00 00 8B 44 24 0C 05 82 00 00 00 50 E8 ?? ?? ?? ?? 89 44 24 30 5A 85 ED 0F 84 67 06 00 00 85 C0 0F 84 5F 06 00 00 80 3B 00 0F 84 56 06 00 00 8B 44 24 0C 8A 44 18 FF 88 44 24 13 FF 74 24 0C 53 FF 74 24 34 E8 ?? ?? ?? ?? C7 44 24 28 FF FF FF FF C7 44 24 34 00 00 00 00 C7 44 24 3C FF FF FF FF C7 44 24 40 FF FF FF FF 83 C4 0C 8B 54 24 2C 8B 4C 24 0C 8D 54 0A 01 89 54 24 08 83 7C 24 1C FF 74 0A FF 74 }
	condition:
		$pattern
}

rule vfscanf_3858337cc4eb1d46438595b8c2b7f4ec {
	meta:
		aliases = "__GI_vfscanf, vfscanf"
		type = "func"
		size = "1585"
		objfiles = "vfscanf@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC E8 01 00 00 C7 84 24 2C 01 00 00 FF FF FF FF 31 C0 B9 09 00 00 00 8D BC 24 08 01 00 00 F3 AB 8B 84 24 FC 01 00 00 83 78 34 00 0F 94 C0 0F B6 C0 89 44 24 04 85 C0 74 26 8B 9C 24 FC 01 00 00 83 C3 38 53 68 ?? ?? ?? ?? 8D 84 24 DC 01 00 00 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 FF B4 24 FC 01 00 00 8D 9C 24 98 01 00 00 53 E8 ?? ?? ?? ?? C7 84 24 C8 01 00 00 ?? ?? ?? ?? 8B 84 24 A4 01 00 00 8A 40 03 88 84 24 B4 01 00 00 8B 84 24 CC 01 00 00 89 84 24 D8 01 00 00 C7 84 24 44 01 00 00 00 00 00 00 8B BC 24 08 02 00 00 C6 44 24 0B 01 5D 58 89 DD E9 D0 04 00 00 C6 84 24 4C 01 00 }
	condition:
		$pattern
}

rule vfwscanf_ef8d7f197212ffabbd6b52e3821544ba {
	meta:
		aliases = "__GI_vfwscanf, vfwscanf"
		type = "func"
		size = "1661"
		objfiles = "vfwscanf@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC FC 00 00 00 C7 44 24 38 FF FF FF FF 31 C0 B9 09 00 00 00 8D 7C 24 14 F3 AB 8B 84 24 10 01 00 00 83 78 34 00 0F 94 C0 0F B6 C0 89 44 24 0C 85 C0 74 26 8B 9C 24 10 01 00 00 83 C3 38 53 68 ?? ?? ?? ?? 8D 84 24 E8 00 00 00 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 FF B4 24 10 01 00 00 8D 9C 24 A4 00 00 00 53 E8 ?? ?? ?? ?? C7 84 24 D4 00 00 00 ?? ?? ?? ?? 8B 84 24 B0 00 00 00 8A 40 03 88 84 24 C0 00 00 00 C7 84 24 E4 00 00 00 ?? ?? ?? ?? C7 44 24 50 00 00 00 00 8B BC 24 1C 01 00 00 C6 44 24 13 01 58 5A E9 08 05 00 00 C6 44 24 58 01 C6 44 24 59 00 80 A4 24 B9 00 00 00 01 C7 44 }
	condition:
		$pattern
}

rule __open_nameservers_112104b0068f0f1b1c06f825d24bad94 {
	meta:
		aliases = "__open_nameservers"
		type = "func"
		size = "876"
		objfiles = "opennameservers@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC FC 01 00 00 83 3D ?? ?? ?? ?? 00 75 3C 8D 84 24 88 01 00 00 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 5D 85 C0 74 0B C7 84 24 C8 01 00 00 00 00 00 00 8B 84 24 C8 01 00 00 39 05 ?? ?? ?? ?? 74 0A A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 0F 85 FA 02 00 00 C6 05 ?? ?? ?? ?? 05 C6 05 ?? ?? ?? ?? 03 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 44 24 0C 5B 5E 85 C0 0F 85 F7 01 00 00 E9 27 02 00 00 8D 84 24 08 01 00 00 E8 ?? ?? ?? ?? 89 C6 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C5 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 5A 59 89 C3 85 C0 0F 85 B8 00 00 00 89 E8 E8 ?? ?? ?? ?? C6 00 00 B9 }
	condition:
		$pattern
}

rule byte_regex_compile_062cccba1e2cd0ee96e73accaf290215 {
	meta:
		aliases = "byte_regex_compile"
		type = "func"
		size = "8219"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC FC 01 00 00 89 44 24 1C 89 4C 24 18 8B BC 24 10 02 00 00 89 84 24 F4 01 00 00 01 C2 89 54 24 28 8B 47 14 89 44 24 2C 68 80 02 00 00 E8 ?? ?? ?? ?? 89 44 24 68 5D 85 C0 0F 84 B7 1F 00 00 8B 54 24 18 89 57 0C 80 67 1C 97 C7 47 08 00 00 00 00 C7 47 18 00 00 00 00 80 3D ?? ?? ?? ?? 00 75 42 68 00 01 00 00 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 D2 83 C4 0C EB 14 A1 ?? ?? ?? ?? F6 44 50 01 08 74 07 C6 82 ?? ?? ?? ?? 01 42 81 FA FF 00 00 00 7E E4 C6 05 ?? ?? ?? ?? 01 C6 05 ?? ?? ?? ?? 01 83 7F 04 00 75 3D 8B 07 85 C0 74 0E 6A 20 50 E8 ?? ?? ?? ?? 89 07 5B 5E EB 0A 6A 20 E8 ?? ?? ?? }
	condition:
		$pattern
}

rule fork_fdb6b782f0184581cdaeeb68511b8f25 {
	meta:
		aliases = "__fork, fork"
		type = "func"
		size = "218"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 2D ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C7 5E 58 85 FF 75 6D BE ?? ?? ?? ?? 85 F6 74 4C 89 E3 53 E8 ?? ?? ?? ?? 6A 01 53 E8 ?? ?? ?? ?? 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 18 85 F6 74 24 89 E3 53 E8 ?? ?? ?? ?? 6A 00 53 E8 ?? ?? ?? ?? 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 18 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 E8 E8 ?? ?? ?? ?? EB 22 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? }
	condition:
		$pattern
}

rule makefd_xprt_ddc96b1c6b9fd30d84d6f1080f271263 {
	meta:
		aliases = "makefd_xprt"
		type = "func"
		size = "170"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 89 04 24 89 D5 89 CF 68 34 01 00 00 E8 ?? ?? ?? ?? 89 C3 68 B0 01 00 00 E8 ?? ?? ?? ?? 89 C6 59 58 85 DB 74 04 85 F6 75 23 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 31 DB 83 C4 10 EB 4F C7 06 02 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 57 55 8D 46 08 50 E8 ?? ?? ?? ?? C7 43 30 00 00 00 00 89 73 2C 8D 46 20 89 43 24 C7 43 0C 00 00 00 00 C7 43 08 ?? ?? ?? ?? 66 C7 43 04 00 00 8B 44 24 18 89 03 53 E8 ?? ?? ?? ?? 83 C4 1C 89 D8 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule getoffset_a91c2b2a62dfbdd8b70a03753e398cbb {
	meta:
		aliases = "getoffset"
		type = "func"
		size = "108"
		objfiles = "tzset@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 89 C1 89 14 24 BD ?? ?? ?? ?? 31 FF 83 CE FF 45 8A 11 8D 42 D0 3C 09 77 07 0F B6 C2 8D 70 D0 41 8A 19 8D 43 D0 3C 09 77 0B 6B D6 0A 0F B6 C3 8D 74 02 D0 41 8A 55 00 0F B6 C2 39 C6 72 04 31 C9 EB 1B 0F AF C7 8D 3C 06 31 F6 80 39 3A 75 04 41 83 CE FF 80 FA 01 77 B7 8B 04 24 89 38 89 C8 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule inet_pton4_7642ec721fd52dd89dda1c16e64b0a8f {
	meta:
		aliases = "inet_pton4"
		type = "func"
		size = "119"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 89 C3 89 D5 C6 04 24 00 31 FF 31 D2 89 E6 EB 40 0F B6 C0 43 8D 48 D0 83 F9 09 77 20 0F B6 06 6B C0 0A 8D 04 01 3D FF 00 00 00 77 3C 88 06 85 D2 75 1E 47 83 FF 04 7F 30 B2 01 EB 14 83 F8 2E 75 27 85 D2 74 23 83 FF 04 74 1E 46 C6 06 00 31 D2 8A 03 84 C0 75 BA 83 FF 03 7E 0D 8B 04 24 89 45 00 B8 01 00 00 00 EB 02 31 C0 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule byte_common_op_match_null_stri_ff0361bc0a70f544d47f5c9e38822e94 {
	meta:
		aliases = "byte_common_op_match_null_string_p"
		type = "func"
		size = "234"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 89 C5 89 CF 8B 08 89 0C 24 8A 01 8D 71 01 89 34 24 3C 0C 77 21 3C 09 0F 83 B1 00 00 00 3C 06 74 32 3C 08 0F 84 9B 00 00 00 84 C0 0F 84 9D 00 00 00 E9 A5 00 00 00 3C 15 74 5D 77 0A 3C 0D 0F 85 97 00 00 00 EB 3C 83 E8 1A 3C 03 0F 87 8A 00 00 00 EB 7B 0F B6 59 01 89 E0 89 F9 E8 ?? ?? ?? ?? 89 C6 8D 0C 9F 8A 01 83 E0 03 3C 03 75 0E 89 F2 83 E2 03 8A 01 83 E0 FC 09 D0 88 01 89 F0 84 C0 EB 4A 0F B6 51 01 0F BE 46 01 C1 E0 08 01 D0 78 4A 8D 44 08 03 EB 28 8D 59 03 89 1C 24 0F BE 43 01 C1 E0 08 0F B6 51 03 01 D0 75 2F 89 34 24 0F B6 51 01 0F BE 46 01 C1 E0 08 01 D0 8D 04 03 89 04 }
	condition:
		$pattern
}

rule byte_group_match_null_string_p_c1011da63a6f73edd3e950bb5fcf1773 {
	meta:
		aliases = "byte_group_match_null_string_p"
		type = "func"
		size = "240"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 89 C5 89 D7 89 CE 8B 00 83 C0 02 89 04 24 E9 C3 00 00 00 8A 02 3C 07 0F 84 9D 00 00 00 3C 0F 0F 85 A2 00 00 00 8D 42 01 89 04 24 0F B6 4A 01 0F BE 40 01 C1 E0 08 83 C2 03 89 14 24 89 C3 01 CB 79 4A E9 8F 00 00 00 8D 54 18 FD 89 F1 E8 ?? ?? ?? ?? 84 C0 0F 84 87 00 00 00 89 D9 03 0C 24 89 0C 24 80 39 0F 75 2F 8D 41 01 89 04 24 0F B6 51 01 0F BE 40 01 C1 E0 08 8D 1C 10 8D 41 03 89 04 24 80 3C 19 0E 74 05 89 0C 24 EB 0A 8B 04 24 80 7C 18 FD 0E 74 B1 8B 04 24 0F B6 48 FE 0F BE 50 FF C1 E2 08 8D 1C 0A 8D 14 18 89 F1 E8 ?? ?? ?? ?? 84 C0 74 2C 01 1C 24 EB 1C 8D 42 02 89 45 00 B8 }
	condition:
		$pattern
}

rule __md5_Update_47d01d95957e76c1bc25be20b8352429 {
	meta:
		aliases = "__md5_Update"
		type = "func"
		size = "151"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 89 C6 89 14 24 89 CF 8B 40 10 89 C1 C1 E9 03 83 E1 3F 8D 14 FD 00 00 00 00 8D 04 02 89 46 10 39 D0 73 03 FF 46 14 89 F8 C1 E8 1D 01 46 14 BD 40 00 00 00 29 CD 31 DB 39 EF 72 39 55 FF 74 24 04 8D 5E 18 8D 04 0B 50 E8 ?? ?? ?? ?? 89 DA 89 F0 E8 ?? ?? ?? ?? 89 EB 83 C4 0C EB 0F 8B 14 24 01 DA 89 F0 E8 ?? ?? ?? ?? 83 C3 40 8D 43 3F 39 F8 72 EA 31 C9 29 DF 57 8B 44 24 04 01 D8 50 8D 44 31 18 50 E8 ?? ?? ?? ?? 83 C4 10 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _charpad_08eff7673841ed595932f53250678f9c {
	meta:
		aliases = "_charpad"
		type = "func"
		size = "53"
		objfiles = "_vfprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 89 C7 89 CE 88 54 24 03 89 CB 8D 6C 24 03 EB 01 4B 85 DB 74 0F 57 6A 01 55 E8 ?? ?? ?? ?? 83 C4 0C 48 74 EC 29 DE 89 F0 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _charpad_75b0dfb839f98c82488442c9c7d8ad8d {
	meta:
		aliases = "_charpad"
		type = "func"
		size = "50"
		objfiles = "_vfwprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 89 C7 89 CE 89 14 24 89 CB 89 E5 EB 01 4B 85 DB 74 0F 57 6A 01 55 E8 ?? ?? ?? ?? 83 C4 0C 48 74 EC 29 DE 89 F0 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __fake_pread_write_1e512b70b7f6daffde30b20cd8f05f49 {
	meta:
		aliases = "__fake_pread_write"
		type = "func"
		size = "128"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 89 C7 89 D6 89 CB 6A 01 6A 00 50 E8 ?? ?? ?? ?? 89 44 24 0C 83 C4 0C 40 74 54 6A 00 FF 74 24 1C 57 E8 ?? ?? ?? ?? 83 C4 0C 40 74 42 83 7C 24 1C 01 75 0A 53 56 57 E8 ?? ?? ?? ?? EB 08 53 56 57 E8 ?? ?? ?? ?? 89 C6 83 C4 0C E8 ?? ?? ?? ?? 89 C3 8B 28 6A 00 FF 74 24 04 57 E8 ?? ?? ?? ?? 83 C4 0C 40 75 05 83 FE FF 75 04 89 2B EB 03 83 CE FF 89 F0 5B 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __malloc_trim_cc9dd99024af8fa6d64ee00aab0c69e0 {
	meta:
		aliases = "__malloc_trim"
		type = "func"
		size = "125"
		objfiles = "free@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 89 D5 8B 8A 5C 03 00 00 8B 52 2C 8B 72 04 83 E6 FC 8D 5C 31 EF 29 C3 89 D8 31 D2 F7 F1 89 C3 4B 0F AF D9 85 DB 7E 47 6A 00 E8 ?? ?? ?? ?? 89 C7 89 F0 03 45 2C 5A 39 C7 75 34 F7 DB 53 E8 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? 59 5B 83 F8 FF 74 1E 89 F9 29 C1 74 18 29 8D 68 03 00 00 8B 45 2C 29 CE 83 CE 01 89 70 04 B8 01 00 00 00 EB 02 31 C0 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule inet_aton_6123089d71978e99f3fd102f30e385cd {
	meta:
		aliases = "__GI_inet_aton, inet_aton"
		type = "func"
		size = "148"
		objfiles = "inet_aton@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 4C 24 18 85 C9 74 7D 31 F6 C7 04 24 01 00 00 00 EB 51 8B 2D ?? ?? ?? ?? 0F B6 01 F6 44 45 00 08 74 62 31 FF EB 10 6B C7 0A 8D 7C 18 D0 81 FF FF 00 00 00 7F 4F 41 8A 11 0F B6 DA 0F B7 44 5D 00 A8 08 75 E2 83 3C 24 04 74 08 80 FA 2E 75 35 41 EB 09 41 84 D2 74 04 A8 20 74 29 C1 E6 08 09 FE FF 04 24 83 3C 24 04 7E A9 B8 01 00 00 00 83 7C 24 1C 00 74 11 0F CE 8B 44 24 1C 89 30 B8 01 00 00 00 EB 02 31 C0 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __getdents_1f63c3491d775b8864d0826d7d48f4da {
	meta:
		aliases = "__getdents"
		type = "func"
		size = "130"
		objfiles = "getdents@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 4C 24 1C 8B 54 24 20 8B 44 24 18 53 89 C3 B8 8D 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 CF FF EB 45 89 C7 83 F8 FF 74 3E 89 CE 8D 2C 01 EB 33 0F B7 46 08 8A 44 06 FF 88 44 24 03 8D 5E 0A 53 E8 ?? ?? ?? ?? 40 89 04 24 53 8D 46 0B 50 E8 ?? ?? ?? ?? 8A 44 24 0F 88 46 0A 0F B7 46 08 01 C6 83 C4 0C 39 EE 72 C9 89 F8 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _dl_fixup_589521c3fcb354f8b36c77c641d8ff49 {
	meta:
		aliases = "_dl_fixup"
		type = "func"
		size = "275"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 54 24 18 8B 42 10 85 C0 74 16 FF 74 24 1C 50 E8 ?? ?? ?? ?? 89 C6 5F 5D 85 C0 0F 85 E3 00 00 00 8B 44 24 18 8B 18 66 8B 43 22 BE 01 00 00 00 83 7B 5C 00 0F 85 CA 00 00 00 8B AB 88 00 00 00 8B B3 84 00 00 00 85 F6 74 4A A8 01 75 46 8B 8B C8 00 00 00 89 F0 85 C9 74 23 8D 14 CD 00 00 00 00 89 14 24 8B 3B 8D 56 F8 83 C2 08 89 F8 03 02 01 38 49 75 F4 2B 2C 24 8B 04 24 01 F0 55 50 FF 74 24 20 E8 ?? ?? ?? ?? 89 C6 66 83 4B 22 01 83 C4 0C EB 02 31 F6 83 BB A0 00 00 00 00 74 08 C7 44 24 1C 02 00 00 00 83 BB 9C 00 00 00 00 74 54 F6 43 22 02 74 10 83 7C 24 1C 00 74 47 8B 44 24 1C }
	condition:
		$pattern
}

rule mbsnrtowcs_2f4a8ef45ad0523ebf4a8e2a59591498 {
	meta:
		aliases = "__GI_mbsnrtowcs, mbsnrtowcs"
		type = "func"
		size = "147"
		objfiles = "mbsnrtowcs@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 54 24 18 8B 74 24 20 8B 5C 24 24 8B 44 24 28 85 C0 75 05 B8 ?? ?? ?? ?? 85 D2 74 0F B9 01 00 00 00 39 C2 75 0D 89 E2 30 C9 EB 07 89 E2 83 CB FF 31 C9 89 DF 39 F3 76 02 89 F7 8B 44 24 1C 8B 18 89 FE 8D 2C 8D 00 00 00 00 EB 28 8A 03 0F B6 C8 89 0A 84 C0 75 04 31 DB EB 1D 83 F9 7F 7E 10 E8 ?? ?? ?? ?? C7 00 54 00 00 00 83 C8 FF EB 16 43 01 EA 4E 85 F6 75 D4 39 E2 74 06 8B 44 24 1C 89 18 89 F8 29 F0 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __psfs_parse_spec_78f11b199ef2465f985515d1f6c8509f {
	meta:
		aliases = "__psfs_parse_spec"
		type = "func"
		size = "454"
		objfiles = "__psfs_parse_spec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 5C 24 18 8B 43 30 89 04 24 8A 00 83 E8 30 31 ED BF 01 00 00 00 3C 09 77 4B 81 FD CB CC CC 0C 7F 11 8B 43 30 0F B6 08 6B D5 0A 8D 6C 11 D0 40 89 43 30 8B 73 30 8A 0E 8D 41 D0 3C 09 76 DB 80 F9 24 74 19 83 7B 24 00 0F 89 5D 01 00 00 89 6B 40 C7 43 24 FE FF FF FF E9 99 00 00 00 8D 46 01 89 43 30 31 FF BE ?? ?? ?? ?? BA 10 00 00 00 8B 4B 30 8A 06 3A 01 75 0B 8D 41 01 89 43 30 08 53 45 EB E2 46 80 3E 00 74 04 01 D2 EB E2 F6 43 45 10 74 08 C6 43 44 00 31 D2 EB 4F 89 F8 84 C0 74 13 83 7B 24 00 0F 89 00 01 00 00 C7 43 24 FE FF FF FF EB E3 83 7B 24 FE 0F 84 ED 00 00 00 8D 45 FF }
	condition:
		$pattern
}

rule __parsepwent_888a5bcda7d552d44b9323290f85cd37 {
	meta:
		aliases = "__parsepwent"
		type = "func"
		size = "112"
		objfiles = "__parsepwent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 5C 24 1C 31 F6 89 E5 0F B6 86 ?? ?? ?? ?? 8B 7C 24 18 01 C7 89 F0 83 E0 06 83 F8 02 74 17 89 1F 83 FE 06 74 36 6A 3A 53 E8 ?? ?? ?? ?? 59 5B 85 C0 75 1F EB 2A 6A 0A 55 53 E8 ?? ?? ?? ?? 89 C2 8B 44 24 0C 83 C4 0C 39 D8 74 14 80 38 3A 75 0F 89 17 C6 00 00 8D 58 01 46 EB AC 31 C0 EB 03 83 C8 FF 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fread_unlocked_843501bd2ccb359faa555e3f57215150 {
	meta:
		aliases = "__GI_fread_unlocked, fread_unlocked"
		type = "func"
		size = "260"
		objfiles = "fread_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 5C 24 20 8B 6C 24 24 0F B7 45 00 25 83 00 00 00 3D 80 00 00 00 77 15 68 80 00 00 00 55 E8 ?? ?? ?? ?? 5E 5F 85 C0 0F 85 C8 00 00 00 83 7C 24 1C 00 0F 84 BD 00 00 00 85 DB 0F 84 B5 00 00 00 83 C8 FF 31 D2 F7 74 24 1C 39 C3 0F 87 94 00 00 00 8B 7C 24 18 0F AF 5C 24 1C 89 1C 24 89 DE EB 1B 83 E0 01 8B 44 85 24 88 07 8D 42 FF 66 89 45 00 C7 45 28 00 00 00 00 4E 74 5C 47 8B 55 00 0F B7 C2 A8 02 75 DB 8B 55 10 8B 45 14 29 D0 74 1C 89 F3 39 C6 76 02 89 C3 53 52 57 E8 ?? ?? ?? ?? 01 5D 10 83 C4 0C 29 DE 74 2D 01 DF 0F B7 45 00 F6 C4 03 74 13 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 EB }
	condition:
		$pattern
}

rule svc_unregister_d12f76dbae7c6bc6ffa0d970a721e4ef {
	meta:
		aliases = "__GI_svc_unregister, svc_unregister"
		type = "func"
		size = "84"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 6C 24 18 8B 7C 24 1C 89 E1 89 FA 89 E8 E8 ?? ?? ?? ?? 89 C3 85 C0 74 2E 8B 04 24 85 C0 8B 33 75 0D E8 ?? ?? ?? ?? 89 B0 B8 00 00 00 EB 02 89 30 C7 03 00 00 00 00 53 E8 ?? ?? ?? ?? 57 55 E8 ?? ?? ?? ?? 83 C4 0C 58 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule error_at_line_ed64e0cb05918d42eed96c252ab15275 {
	meta:
		aliases = "__error_at_line, error_at_line"
		type = "func"
		size = "284"
		objfiles = "error@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 6C 24 18 8B 7C 24 1C 8B 5C 24 20 8B 74 24 24 83 3D ?? ?? ?? ?? 00 74 32 39 35 ?? ?? ?? ?? 75 1E A1 ?? ?? ?? ?? 39 C3 0F 84 E1 00 00 00 53 50 E8 ?? ?? ?? ?? 59 5A 85 C0 0F 84 D0 00 00 00 89 1D ?? ?? ?? ?? 89 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 5A 85 C0 74 04 FF D0 EB 19 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 85 DB 74 15 56 53 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 8D 44 24 2C 89 04 24 50 FF 74 24 2C FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 05 ?? ?? ?? ?? 83 C4 0C 85 FF 74 1A 57 E8 ?? ?? ?? ?? 50 }
	condition:
		$pattern
}

rule _dl_linux_resolver_886eb86e79ad8c72d6a1e92ca652b4e5 {
	meta:
		aliases = "_dl_linux_resolver"
		type = "func"
		size = "139"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 74 24 18 8B 44 24 1C 03 86 9C 00 00 00 8B 50 04 C1 EA 08 8B 4E 58 C1 E2 04 8B 1C 0A 03 5E 54 8B 00 89 04 24 8B 2E 6A 00 6A 01 56 FF 76 1C 53 E8 ?? ?? ?? ?? 89 C7 83 C4 14 85 C0 75 37 FF 76 04 53 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? B9 01 00 00 00 87 CB B8 01 00 00 00 CD 80 87 CB 83 C4 14 3D 00 F0 FF FF 76 07 F7 D8 A3 ?? ?? ?? ?? 8B 04 24 89 7C 05 00 89 F8 5D 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule xdr_pmaplist_1c6145be0542b218c5878867925f76b2 {
	meta:
		aliases = "__GI_xdr_pmaplist, xdr_pmaplist"
		type = "func"
		size = "119"
		objfiles = "pmap_prot2@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 74 24 18 8B 5C 24 1C 83 3E 02 0F 94 C0 0F B6 F8 31 ED 31 C0 83 3B 00 0F 95 C0 89 04 24 8D 04 24 50 56 E8 ?? ?? ?? ?? 59 5A 85 C0 74 3A 83 3C 24 00 75 07 B8 01 00 00 00 EB 2F 85 FF 74 05 8B 2B 83 C5 10 68 ?? ?? ?? ?? 6A 14 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 0F 85 FF 74 04 89 EB EB B2 8B 1B 83 C3 10 EB AB 31 C0 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule regcomp_c826362e903209cf2b2acf262be3b277 {
	meta:
		aliases = "regcomp"
		type = "func"
		size = "298"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 74 24 18 8B 6C 24 20 89 E8 83 E0 01 83 F8 01 19 DB 81 E3 CA 4F FD 00 81 C3 FC B2 03 00 C7 06 00 00 00 00 C7 46 04 00 00 00 00 C7 46 08 00 00 00 00 68 00 01 00 00 E8 ?? ?? ?? ?? 89 46 10 59 F7 C5 02 00 00 00 74 4D 68 00 01 00 00 E8 ?? ?? ?? ?? 89 46 14 5A BF 0C 00 00 00 31 C9 85 C0 75 2A E9 B5 00 00 00 8B 46 14 89 04 24 8D 3C 09 88 CA A1 ?? ?? ?? ?? F6 04 38 01 74 08 A1 ?? ?? ?? ?? 8A 14 38 8B 04 24 88 14 08 41 81 F9 FF 00 00 00 76 D3 EB 07 C7 46 14 00 00 00 00 F7 C5 04 00 00 00 8A 46 1C 74 0B 83 E3 BF 80 CF 01 83 C8 80 EB 03 83 E0 7F 88 46 1C C1 ED 03 89 E8 83 E0 01 C1 }
	condition:
		$pattern
}

rule xdr_union_8ec4f68fd8621f2e9995a627566a440a {
	meta:
		aliases = "__GI_xdr_union, xdr_union"
		type = "func"
		size = "122"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 74 24 18 8B 7C 24 1C 8B 44 24 20 89 04 24 8B 5C 24 24 8B 6C 24 28 57 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 47 8B 07 EB 1C 39 03 75 15 C7 44 24 20 FF FF FF FF 8B 04 24 89 44 24 1C 89 74 24 18 EB 23 83 C3 08 8B 4B 04 85 C9 75 DD 85 ED 74 1C C7 44 24 20 FF FF FF FF 8B 0C 24 89 4C 24 1C 89 74 24 18 89 E9 5B 5B 5E 5F 5D FF E1 31 C0 59 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __parsespent_ce23bfc5f92464dc27588a149d81236f {
	meta:
		aliases = "__parsespent"
		type = "func"
		size = "120"
		objfiles = "__parsespent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 74 24 1C 31 FF 89 E5 0F B6 87 ?? ?? ?? ?? 8B 5C 24 18 01 C3 83 FF 01 7F 12 89 33 6A 3A 56 E8 ?? ?? ?? ?? 59 5B 85 C0 75 31 EB 38 6A 0A 55 56 E8 ?? ?? ?? ?? 89 03 83 C4 0C 39 34 24 75 06 C7 03 FF FF FF FF 8B 04 24 83 FF 08 75 09 31 D2 80 38 00 74 15 EB 0E 80 38 3A 75 09 C6 00 00 8D 70 01 47 EB A4 BA 16 00 00 00 89 D0 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule getmntent_r_7ecb474de368c6205634093d785bd778 {
	meta:
		aliases = "__GI_getmntent_r, getmntent_r"
		type = "func"
		size = "271"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 7C 24 18 8B 5C 24 1C 8B 74 24 20 8B 6C 24 24 85 FF 0F 84 E6 00 00 00 85 DB 0F 84 DE 00 00 00 85 F6 0F 84 D6 00 00 00 EB 0A 8A 06 3C 23 74 04 3C 0A 75 14 57 55 56 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 E7 E9 B6 00 00 00 C7 04 24 00 00 00 00 89 E7 57 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 89 03 83 C4 0C 85 C0 0F 84 94 00 00 00 57 68 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? 89 43 04 83 C4 0C 85 C0 74 7D 57 68 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? 89 43 08 83 C4 0C 85 C0 74 66 57 68 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? 89 43 0C 83 C4 0C 85 C0 75 07 C7 43 0C ?? ?? ?? ?? 57 68 ?? ?? ?? ?? 6A 00 E8 ?? ?? }
	condition:
		$pattern
}

rule strcasestr_e423ab6305e7e0b45dda86e461d450c3 {
	meta:
		aliases = "__GI_strcasestr, strcasestr"
		type = "func"
		size = "83"
		objfiles = "strcasestr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 7C 24 18 8B 6C 24 1C 89 FE 89 EB 8A 03 84 C0 75 04 89 F8 EB 30 8A 16 88 54 24 03 38 D0 74 16 8B 15 ?? ?? ?? ?? 0F B6 0B 0F B6 06 66 8B 04 42 66 3B 04 4A 75 04 43 46 EB D2 80 7C 24 03 00 74 03 47 EB C4 31 C0 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule vasprintf_5718aa84c9ba4727a31d2365b682977f {
	meta:
		aliases = "__GI_vasprintf, vasprintf"
		type = "func"
		size = "102"
		objfiles = "vasprintf@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 7C 24 18 8B 6C 24 1C 8B 74 24 20 89 34 24 56 55 6A 00 6A 00 E8 ?? ?? ?? ?? 89 C3 C7 07 00 00 00 00 83 C4 10 85 C0 78 2E 43 53 E8 ?? ?? ?? ?? 89 07 5A 85 C0 74 20 56 55 53 50 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 79 0E FF 37 E8 ?? ?? ?? ?? C7 07 00 00 00 00 59 89 D8 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule xdr_bytes_988e5afec88a2d0e8c1d0cbd5964fc20 {
	meta:
		aliases = "__GI_xdr_bytes, xdr_bytes"
		type = "func"
		size = "178"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 7C 24 18 8B 6C 24 1C 8B 74 24 20 8B 44 24 24 89 04 24 8B 5D 00 56 57 E8 ?? ?? ?? ?? 5A 59 85 C0 74 79 8B 36 3B 34 24 76 05 83 3F 02 75 6D 8B 07 83 F8 01 74 09 72 35 83 F8 02 75 5F EB 44 85 F6 74 5D 85 DB 75 26 56 E8 ?? ?? ?? ?? 89 C3 89 45 00 58 85 DB 75 16 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 5F 5D EB 38 89 74 24 20 89 5C 24 1C 89 7C 24 18 5E 5B 5E 5F 5D E9 ?? ?? ?? ?? 85 DB 74 19 53 E8 ?? ?? ?? ?? C7 45 00 00 00 00 00 B8 01 00 00 00 5B EB 09 31 C0 EB 05 B8 01 00 00 00 59 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __pthread_alt_timedlock_2c667f6aa05ee39b3c3b9f0bb589cd77 {
	meta:
		aliases = "__pthread_alt_timedlock"
		type = "func"
		size = "196"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 7C 24 18 8B 6C 24 1C B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 31 F6 85 C0 74 09 89 C6 8B 00 A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 85 F6 75 1E 6A 0C E8 ?? ?? ?? ?? 89 C6 58 85 F6 75 10 55 57 E8 ?? ?? ?? ?? BA 01 00 00 00 5D 58 EB 63 8B 1F BA 01 00 00 00 85 DB 74 10 85 ED 75 07 E8 ?? ?? ?? ?? 89 C5 89 6E 04 89 F2 C7 46 08 00 00 00 00 89 1E 89 D8 F0 0F B1 17 0F 94 C2 84 D2 74 CF 85 DB 74 22 FF 74 24 20 55 E8 ?? ?? ?? ?? 5B 5F 85 C0 75 12 B0 01 87 46 08 31 D2 85 C0 74 13 89 E8 E8 ?? ?? ?? ?? 89 F0 E8 ?? ?? ?? ?? BA 01 00 00 00 89 D0 59 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule registerrpc_93c93972a335333904b6e6030adba941 {
	meta:
		aliases = "registerrpc"
		type = "func"
		size = "257"
		objfiles = "svc_simple@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 7C 24 18 8B 74 24 1C 8B 6C 24 20 85 ED 75 19 6A 00 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 83 C4 0C E9 AD 00 00 00 E8 ?? ?? ?? ?? 89 C3 83 B8 C4 00 00 00 00 75 19 6A FF E8 ?? ?? ?? ?? 89 83 C4 00 00 00 5A 85 C0 75 07 68 ?? ?? ?? ?? EB 4B 56 57 E8 ?? ?? ?? ?? 6A 11 68 ?? ?? ?? ?? 56 57 FF B3 C4 00 00 00 E8 ?? ?? ?? ?? 83 C4 1C 85 C0 75 16 56 57 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 EB 4C 6A 18 E8 ?? ?? ?? ?? 89 C2 5E 85 C0 75 11 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 44 24 04 59 EB 2D 8B 44 24 24 89 02 89 7A 04 89 6A 08 8B 44 24 28 89 42 0C 8B 44 24 2C 89 }
	condition:
		$pattern
}

rule svc_register_cd5946b2894447ad99a25d357838654c {
	meta:
		aliases = "__GI_svc_register, svc_register"
		type = "func"
		size = "128"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 7C 24 1C 8B 74 24 20 8B 6C 24 24 89 E1 89 F2 89 F8 E8 ?? ?? ?? ?? 85 C0 74 07 39 68 0C 75 51 EB 2A 6A 10 E8 ?? ?? ?? ?? 89 C3 58 85 DB 74 41 89 7B 04 89 73 08 89 6B 0C E8 ?? ?? ?? ?? 8B 90 B8 00 00 00 89 13 89 98 B8 00 00 00 B8 01 00 00 00 83 7C 24 28 00 74 1B 8B 44 24 18 0F B7 40 04 50 FF 74 24 2C 56 57 E8 ?? ?? ?? ?? 83 C4 10 EB 02 31 C0 59 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule svc_run_5aa9450a47266991e398e6fb5976667d {
	meta:
		aliases = "svc_run"
		type = "func"
		size = "199"
		objfiles = "svc_run@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 E8 ?? ?? ?? ?? 89 04 24 8B 18 85 DB 75 0E E8 ?? ?? ?? ?? 83 38 00 0F 84 9E 00 00 00 8D 04 DD 00 00 00 00 50 E8 ?? ?? ?? ?? 89 C7 31 ED 58 EB 27 8D 1C ED 00 00 00 00 8D 34 1F E8 ?? ?? ?? ?? 8B 10 8B 14 1A 89 16 8B 00 8B 44 18 04 66 89 46 04 66 C7 46 06 00 00 45 8B 14 24 8B 02 39 C5 7C D0 6A FF 50 57 E8 ?? ?? ?? ?? 83 C4 0C 83 F8 FF 74 06 85 C0 74 24 EB 2E 57 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5E 83 38 04 0F 84 74 FF FF FF 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5B EB 21 57 E8 ?? ?? ?? ?? 59 E9 5B FF FF FF 50 57 E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 83 C4 0C E9 46 FF FF FF 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule svc_getreqset_dda7e3b21ba955277fe74d029e7be01d {
	meta:
		aliases = "__GI_svc_getreqset, svc_getreqset"
		type = "func"
		size = "79"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 E8 ?? ?? ?? ?? 89 04 24 8B 7C 24 18 31 ED EB 2D 8B 37 EB 18 8D 58 FF 8D 04 2B 50 E8 ?? ?? ?? ?? B8 01 00 00 00 88 D9 D3 E0 31 C6 58 56 E8 ?? ?? ?? ?? 5B 85 C0 75 DD 83 C7 04 83 C5 20 3B 2C 24 7C CE 59 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __prefix_array_340b214be79acfb0fe1836dd04d019ce {
	meta:
		aliases = "__prefix_array"
		type = "func"
		size = "160"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 FF 74 24 18 E8 ?? ?? ?? ?? 59 89 C5 83 F8 01 75 0D 8B 44 24 18 80 38 2F 0F 95 C0 0F B6 E8 31 FF EB 69 8B 54 24 1C 8D 34 BA FF 36 E8 ?? ?? ?? ?? 5A 8D 50 01 89 14 24 8D 44 05 02 50 E8 ?? ?? ?? ?? 89 C3 58 85 DB 75 1B EB 0E 4F 8B 44 24 1C FF 34 B8 E8 ?? ?? ?? ?? 5B 85 FF 75 EE B8 01 00 00 00 EB 30 55 FF 74 24 1C 53 E8 ?? ?? ?? ?? C6 00 2F FF 74 24 0C FF 36 40 50 E8 ?? ?? ?? ?? FF 36 E8 ?? ?? ?? ?? 89 1E 47 83 C4 1C 3B 7C 24 20 72 91 31 C0 59 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __fake_pread_write64_c9a1c674682b1f123471e50944e52bad {
	meta:
		aliases = "__fake_pread_write64"
		type = "func"
		size = "167"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 89 04 24 89 D5 89 CB 6A 01 6A 00 6A 00 50 E8 ?? ?? ?? ?? 89 C6 89 D7 83 C4 10 83 FA FF 75 05 83 F8 FF 74 70 6A 00 FF 74 24 24 FF 74 24 24 FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 10 42 75 03 40 74 54 83 7C 24 24 01 75 0D 53 55 FF 74 24 08 E8 ?? ?? ?? ?? EB 0B 53 55 FF 74 24 08 E8 ?? ?? ?? ?? 89 C5 83 C4 0C E8 ?? ?? ?? ?? 89 C3 8B 00 89 44 24 04 6A 00 57 56 FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 10 42 75 08 40 75 05 83 FD FF 75 08 8B 44 24 04 89 03 EB 03 83 CD FF 89 E8 5A 59 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __pthread_lock_9736bf1825f527e9bcb1f1cef842a83d {
	meta:
		aliases = "__pthread_lock"
		type = "func"
		size = "142"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 89 C3 89 D7 83 38 00 74 04 31 ED EB 16 B9 01 00 00 00 31 D2 89 D0 F0 0F B1 0B 0F 94 C2 84 D2 74 E8 EB 5D 8B 33 F7 C6 01 00 00 00 75 0C 89 F1 83 C9 01 BA 01 00 00 00 EB 12 85 FF 75 07 E8 ?? ?? ?? ?? 89 C7 89 F9 83 C9 01 31 D2 85 FF 74 03 89 77 0C 89 F0 F0 0F B1 0B 0F 94 C1 84 C9 74 C4 85 D2 75 17 89 F8 E8 ?? ?? ?? ?? 83 7F 0C 00 74 B3 45 EB F0 89 F8 E8 ?? ?? ?? ?? 4D 83 FD FF 75 F3 58 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule scan_getwc_ddb3cbbf53c6b40c0b02e9615d167ac2 {
	meta:
		aliases = "scan_getwc"
		type = "func"
		size = "148"
		objfiles = "vfscanf@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 89 C3 8B 78 10 4F 89 78 10 85 FF 79 09 80 48 19 02 83 C8 FF EB 70 C7 40 10 FF FF FF 7F BE FD FF FF FF 8D 68 1C EB 2E 8B 03 88 44 24 07 55 6A 01 8D 44 24 0F 50 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 C0 78 08 8B 04 24 89 43 24 EB 31 83 F8 FE 75 0B 53 E8 ?? ?? ?? ?? 5A 85 C0 79 C7 83 FE FD 75 0D C7 43 24 FF FF FF FF 66 BE FF FF EB 0F E8 ?? ?? ?? ?? C7 00 54 00 00 00 C6 43 1B 01 89 7B 10 89 F0 5A 59 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule do_dlclose_aa01db4894b0a66f9377734ba8f38e85 {
	meta:
		aliases = "do_dlclose"
		type = "func"
		size = "557"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 89 C5 89 14 24 3B 05 ?? ?? ?? ?? 0F 84 0C 02 00 00 A1 ?? ?? ?? ?? 31 D2 EB 09 39 E8 74 1A 89 C2 8B 40 04 85 C0 75 F3 C7 05 ?? ?? ?? ?? 0A 00 00 00 B0 01 E9 E7 01 00 00 85 D2 8B 45 04 74 05 89 42 04 EB 05 A3 ?? ?? ?? ?? 8B 55 00 8B 42 20 66 83 F8 01 75 12 C7 44 24 04 00 00 00 00 F6 42 25 10 0F 84 5D 01 00 00 48 66 89 42 20 55 E8 ?? ?? ?? ?? 31 C0 5F E9 A5 01 00 00 8B 45 08 8B 54 24 04 8B 3C 90 8B 47 20 48 66 89 47 20 66 85 C0 0F 85 2B 01 00 00 F6 47 25 10 0F 85 21 01 00 00 83 7F 74 00 75 09 83 BF A8 00 00 00 00 74 27 83 3C 24 00 74 21 66 8B 47 22 A8 08 75 19 83 C8 08 66 89 }
	condition:
		$pattern
}

rule strverscmp_4b10e48ee0d66d1ebe7e1b45a7805edc {
	meta:
		aliases = "__GI_strverscmp, strverscmp"
		type = "func"
		size = "245"
		objfiles = "strverscmp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 8B 44 24 1C 8B 54 24 20 C7 04 24 00 00 00 00 39 D0 0F 84 CD 00 00 00 8A 18 8D 68 01 8A 0A 8D 7A 01 0F B6 C3 83 E8 30 31 D2 83 F8 09 0F 96 C2 31 C0 80 FB 30 0F 94 C0 8D 34 02 EB 2F 0F B6 B6 ?? ?? ?? ?? 89 74 24 04 8A 5D 00 45 8A 0F 47 0F B6 C3 83 E8 30 31 D2 83 F8 09 0F 96 C2 31 C0 80 FB 30 0F 94 C0 8D 34 02 0B 74 24 04 0F B6 D1 0F B6 C3 29 D0 89 04 24 75 04 84 DB 75 C0 8D 42 D0 31 D2 83 F8 09 0F 96 C2 31 C0 80 F9 30 0F 94 C0 01 C2 8D 04 B5 00 00 00 00 09 C2 8A 82 ?? ?? ?? ?? 3C 02 74 40 3C 03 74 1D 0F BE C0 89 04 24 EB 34 0F B6 07 83 E8 30 83 F8 09 76 09 C7 04 24 01 00 00 }
	condition:
		$pattern
}

rule inet_network_0aaef1bbec9cbee1e6845d4e084b76f2 {
	meta:
		aliases = "__GI_inet_network, inet_network"
		type = "func"
		size = "220"
		objfiles = "inet_net@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 8B 4C 24 1C C7 04 24 00 00 00 00 C7 44 24 04 00 00 00 00 BD 0A 00 00 00 80 39 30 75 1D 41 8A 01 3C 78 74 10 3C 58 74 0C BD 08 00 00 00 BE 01 00 00 00 EB 08 41 BD 10 00 00 00 31 F6 31 FF EB 51 0F B6 DA A1 ?? ?? ?? ?? 0F B7 04 58 A8 08 74 15 83 FD 08 75 05 80 FA 37 77 68 89 F8 0F AF C5 8D 7C 03 D0 EB 1E 83 FD 10 75 2D A8 10 74 29 83 E0 02 83 F8 01 19 D2 83 E2 E0 89 F8 C1 E0 04 29 D0 8D 78 A9 81 FF FF 00 00 00 77 37 41 BE 01 00 00 00 8A 11 84 D2 75 A9 85 F6 74 27 83 3C 24 00 74 05 C1 64 24 04 08 09 7C 24 04 80 FA 2E 75 0F FF 04 24 83 3C 24 04 74 0A 41 E9 55 FF FF FF 84 D2 74 }
	condition:
		$pattern
}

rule strstr_a1771bb7ea1f350a8b12b56d5a4efff5 {
	meta:
		aliases = "__GI_strstr, strstr"
		type = "func"
		size = "197"
		objfiles = "strstr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 8B 54 24 20 8B 5C 24 1C 8A 02 0F B6 E8 84 C0 0F 84 9C 00 00 00 4B 43 8A 03 84 C0 0F 84 94 00 00 00 0F B6 C0 39 E8 75 EE 8D 42 01 89 44 24 04 8A 42 01 84 C0 74 7B 0F B6 C0 89 04 24 8D 53 01 0F B6 43 01 EB 27 8D 53 01 0F B6 43 01 EB 16 85 C0 74 63 42 8A 0A 0F B6 C1 39 E8 74 0C 84 C9 74 55 42 0F B6 02 39 E8 75 E6 42 0F B6 02 3B 04 24 75 F3 8B 7C 24 04 47 8D 72 01 8B 44 24 04 0F B6 48 01 8D 5A FF 0F B6 42 01 39 C8 75 21 85 C9 74 21 8A 47 01 0F B6 C8 38 46 01 75 12 84 C0 74 12 83 C6 02 83 C7 02 0F B6 0F 0F B6 06 EB DB 85 C9 75 94 89 D8 EB 02 31 C0 5A 59 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule getwc_unlocked_80ada2a6a62c22e17ec023ecf319c7dd {
	meta:
		aliases = "__GI_fgetwc_unlocked, fgetwc_unlocked, getwc_unlocked"
		type = "func"
		size = "271"
		objfiles = "fgetwc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 8B 5C 24 1C 0F B7 03 25 03 08 00 00 3D 00 08 00 00 77 18 68 00 08 00 00 53 E8 ?? ?? ?? ?? 5F 5D 83 CE FF 85 C0 0F 85 D4 00 00 00 0F B7 03 A8 02 74 31 A8 01 75 06 83 7B 28 00 74 06 C6 43 02 00 EB 06 8A 43 03 88 43 02 8B 03 89 C2 83 E2 01 8B 74 93 24 48 66 89 03 C7 43 28 00 00 00 00 E9 8A 00 00 00 83 7B 08 00 75 0E 8D 54 24 07 89 D8 E8 ?? ?? ?? ?? FF 43 0C 83 7B 2C 00 75 04 C6 43 02 00 8D 7B 2C 89 E5 8B 53 10 8B 43 14 89 C6 29 D6 74 30 57 56 52 55 E8 ?? ?? ?? ?? 83 C4 10 83 F8 00 7C 12 75 05 B8 01 00 00 00 01 43 10 00 43 02 8B 34 24 EB 38 83 F8 FE 75 2C 01 73 10 89 F0 00 43 }
	condition:
		$pattern
}

rule _obstack_newchunk_8156895a814099efaff25baa2c5895c7 {
	meta:
		aliases = "_obstack_newchunk"
		type = "func"
		size = "259"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 8B 5C 24 1C 8B 43 04 89 44 24 04 8B 6B 0C 2B 6B 08 8B 43 18 83 C0 64 01 E8 03 44 24 20 89 EA C1 FA 03 8B 0B 8D 3C 10 39 CF 7D 02 89 CF F6 43 28 01 8B 43 1C 74 0C 57 FF 73 24 FF D0 89 C6 58 5A EB 06 57 FF D0 89 C6 59 85 F6 75 05 E8 ?? ?? ?? ?? 89 73 04 8B 54 24 04 89 56 04 8D 04 3E 89 43 10 89 06 8B 53 18 8D 7C 32 08 89 D0 F7 D0 21 C7 31 C0 83 FA 02 7E 25 89 E9 C1 E9 02 89 0C 24 EB 10 8D 04 8D 00 00 00 00 8B 53 08 8B 14 02 89 14 07 49 85 C9 79 EB 8B 04 24 C1 E0 02 89 C2 EB 0A 8B 43 08 8A 04 10 88 04 17 42 39 EA 7C F2 F6 43 28 02 75 34 8B 43 18 8B 4C 24 04 8D 54 08 08 F7 D0 }
	condition:
		$pattern
}

rule xdr_rmtcall_args_8449496508876ae113a9be21674f9594 {
	meta:
		aliases = "__GI_xdr_rmtcall_args, xdr_rmtcall_args"
		type = "func"
		size = "196"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 8B 5C 24 1C 8B 74 24 20 56 53 E8 ?? ?? ?? ?? 5F 5D 85 C0 0F 84 9B 00 00 00 8D 46 04 50 53 E8 ?? ?? ?? ?? 5A 59 85 C0 0F 84 87 00 00 00 8D 46 08 50 53 E8 ?? ?? ?? ?? 5F 5D 85 C0 74 77 C7 44 24 04 00 00 00 00 8B 43 04 53 FF 50 10 89 44 24 04 8D 44 24 08 50 53 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 52 8B 43 04 53 FF 50 10 89 C5 FF 76 10 53 FF 56 14 83 C4 0C 85 C0 74 3B 8B 43 04 53 FF 50 10 89 C7 29 E8 89 46 0C 8B 43 04 FF 74 24 04 53 FF 50 14 8D 46 0C 50 53 E8 ?? ?? ?? ?? 83 C4 14 85 C0 74 11 8B 43 04 57 53 FF 50 14 B8 01 00 00 00 5B 5E EB 02 31 C0 5A 59 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule setstate_r_5b60b5b77a6d54d2705c94253dc0e45c {
	meta:
		aliases = "__GI_setstate_r, setstate_r"
		type = "func"
		size = "169"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 8B 5C 24 20 8B 74 24 1C 83 C6 04 8A 53 0C 8B 4B 08 84 D2 75 09 C7 41 FC 00 00 00 00 EB 13 8B 43 04 29 C8 C1 F8 02 8D 04 80 0F BE D2 01 D0 89 41 FC 8B 46 FC BF 05 00 00 00 99 F7 FF 83 FA 04 77 4C 8A 82 ?? ?? ?? ?? 0F BE C8 88 43 0D 8A 82 ?? ?? ?? ?? 88 44 24 07 88 43 0E 88 53 0C 85 D2 74 1F 8B 6E FC 89 E8 99 F7 FF 89 C7 8D 04 86 89 43 04 0F BE 44 24 07 01 F8 99 F7 F9 8D 14 96 89 13 89 73 08 8D 04 8E 89 43 10 31 C0 EB 0E E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 5A 59 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __parsegrent_93c1fbb235e2b90f7f8f5a660bea3af6 {
	meta:
		aliases = "__parsegrent"
		type = "func"
		size = "216"
		objfiles = "__parsegrent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 8B 6C 24 1C 8B 5C 24 20 8B 45 00 89 04 24 31 F6 0F B6 86 ?? ?? ?? ?? 8D 7C 05 00 83 FE 01 7F 1D 89 1F 6A 3A 53 E8 ?? ?? ?? ?? 5B 5F 85 C0 0F 84 93 00 00 00 C6 00 00 8D 58 01 46 EB D3 6A 0A 8D 44 24 08 50 53 E8 ?? ?? ?? ?? 89 07 8B 4C 24 10 83 C4 0C 39 D9 74 70 80 39 3A 75 6B BB 01 00 00 00 80 79 01 00 74 2B C6 01 2C 80 39 2C 75 1D C6 01 00 41 8A 01 84 C0 74 4E 3C 2C 74 4A 0F B6 D0 A1 ?? ?? ?? ?? F6 04 50 20 75 3C 43 41 80 39 00 75 D8 8D 51 04 83 E2 FC 8D 04 9A 3B 04 24 77 27 89 55 0C 89 D9 49 74 15 8B 44 24 04 40 89 02 83 C2 04 49 74 08 40 80 38 00 75 FA EB EF C7 02 00 00 }
	condition:
		$pattern
}

rule __stdio_fwrite_010a57b6683cc964693037704d86bc9a {
	meta:
		aliases = "__stdio_fwrite"
		type = "func"
		size = "232"
		objfiles = "_fwrite@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 8B 6C 24 1C 8B 74 24 20 8B 5C 24 24 F6 43 01 02 0F 85 AB 00 00 00 83 7B 04 FE 8B 53 10 8B 43 0C 75 1D 29 D0 89 F7 39 C6 76 02 89 C7 57 55 52 E8 ?? ?? ?? ?? 01 7B 10 83 C4 0C E9 99 00 00 00 29 D0 39 C6 77 68 56 55 52 E8 ?? ?? ?? ?? 01 73 10 83 C4 0C F6 43 01 01 74 7F 56 6A 0A 55 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 6F 53 E8 ?? ?? ?? ?? 89 C1 58 85 C9 74 62 89 0C 24 39 F1 76 03 89 34 24 89 F0 2B 04 24 01 C5 89 EF 8B 0C 24 E3 09 B0 0A F2 AE 8D 7F FF 74 02 31 FF 85 FF 74 3B 8B 0C 24 8D 44 0D 00 29 F8 29 C6 29 43 10 EB 2B 3B 53 08 74 0F 53 E8 ?? ?? ?? ?? 5F 85 C0 74 04 31 F6 EB 17 }
	condition:
		$pattern
}

rule _stdlib_wcsto_l_01212b3c5a4be01f5a3ea0f6f9dc2697 {
	meta:
		aliases = "_stdlib_wcsto_l"
		type = "func"
		size = "306"
		objfiles = "_stdlib_wcsto_l@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 8B 6C 24 1C 8B 74 24 24 89 EB EB 03 83 C3 04 FF 33 E8 ?? ?? ?? ?? 5F 85 C0 75 F1 8B 03 83 F8 2B 74 11 C6 44 24 06 00 83 F8 2D 75 0F C6 44 24 06 01 EB 05 C6 44 24 06 00 83 C3 04 89 EF F7 C6 EF FF FF FF 75 29 83 C6 0A 83 3B 30 75 17 83 C3 04 83 EE 02 8B 03 83 C8 20 89 DF 83 F8 78 75 05 01 F6 83 C3 04 83 FE 10 7E 05 BE 10 00 00 00 8D 46 FE 31 ED 83 F8 22 77 6F 83 C8 FF 31 D2 F7 F6 89 04 24 88 54 24 07 EB 02 89 DF 8B 0B 8D 41 D0 8D 51 D0 83 F8 09 76 14 89 C8 83 C8 20 B2 28 83 F8 60 76 08 88 C8 83 C8 20 8D 50 A9 0F B6 C2 39 F0 7D 35 83 C3 04 3B 2C 24 77 08 75 1E 3A 54 24 07 76 }
	condition:
		$pattern
}

rule __drand48_iterate_47411908d657a05cc25ffd78293de7b6 {
	meta:
		aliases = "__drand48_iterate"
		type = "func"
		size = "160"
		objfiles = "drand48_iter@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 8B 6C 24 1C 8B 7C 24 20 66 83 7F 0E 00 75 1A C7 47 10 6D E6 EC DE C7 47 14 05 00 00 00 66 C7 47 0C 0B 00 66 C7 47 0E 01 00 0F B7 45 04 31 D2 89 C2 B8 00 00 00 00 0F B7 4D 00 31 DB 09 C8 09 DA 0F B7 4D 02 C1 E1 10 89 C6 09 CE 89 34 24 89 54 24 04 89 D6 0F AF 77 10 8B 0C 24 0F AF 4F 14 01 CE 8B 04 24 F7 67 10 89 C1 8D 1C 16 0F B7 47 0C 31 D2 01 C8 11 DA 66 89 45 00 0F AC D0 10 C1 EA 10 66 89 45 02 0F AC D0 10 C1 EA 10 66 89 45 04 31 C0 5A 59 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule pmap_getmaps_4a196dcde4ac9e7aa88a83e6003877cc {
	meta:
		aliases = "pmap_getmaps"
		type = "func"
		size = "145"
		objfiles = "pm_getmaps@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 8B 6C 24 1C C7 44 24 04 00 00 00 00 C7 04 24 FF FF FF FF 66 C7 45 02 00 6F 68 F4 01 00 00 6A 32 8D 44 24 08 50 6A 02 68 A0 86 01 00 55 E8 ?? ?? ?? ?? 89 C3 83 C4 18 85 C0 74 3E 8B 50 04 8D 44 24 04 BE 3C 00 00 00 31 FF 57 56 50 68 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 6A 04 53 FF 12 83 C4 20 85 C0 74 0D 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 5E 5F 8B 43 04 53 FF 50 10 5B 66 C7 45 02 00 00 8B 44 24 04 5A 59 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule qsort_b8cdef38fcdabb15ffed29015421d2f4 {
	meta:
		aliases = "__GI_qsort, qsort"
		type = "func"
		size = "169"
		objfiles = "qsort@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 8B 74 24 20 83 FE 01 0F 86 8E 00 00 00 83 7C 24 24 00 0F 84 83 00 00 00 31 C9 8D 5E FF 8D 04 49 8D 48 01 BA 03 00 00 00 89 D8 89 D5 31 D2 F7 F5 39 C1 72 E9 8B 5C 24 24 0F AF D9 0F AF 74 24 24 89 74 24 04 89 1C 24 8B 2C 24 29 DD 8B 74 24 1C 01 EE 8D 3C 1E 57 56 FF 54 24 30 59 5A 85 C0 7E 15 8B 4C 24 24 8A 16 8A 07 88 06 46 88 17 47 49 75 F3 39 DD 73 D4 8B 44 24 24 01 04 24 8B 74 24 04 39 34 24 72 C1 29 C3 BA 03 00 00 00 89 D8 89 D6 31 D2 F7 F6 89 C3 85 C0 75 A9 58 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _stdlib_strto_l_560ea013b71efd946e6ef79923b36e63 {
	meta:
		aliases = "_stdlib_strto_l"
		type = "func"
		size = "276"
		objfiles = "_stdlib_strto_l@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 8B 7C 24 1C 8B 74 24 24 89 FB EB 01 43 8A 0B 0F B6 D1 A1 ?? ?? ?? ?? F6 04 50 20 75 EF 80 F9 2B 74 0E 31 ED 80 F9 2D 75 0A BD 01 00 00 00 EB 02 31 ED 43 89 F9 F7 C6 EF FF FF FF 75 24 83 C6 0A 80 3B 30 75 12 43 83 EE 02 8A 03 83 C8 20 89 D9 3C 78 75 03 01 F6 43 83 FE 10 7E 05 BE 10 00 00 00 8D 46 FE 31 FF 83 F8 22 77 60 83 C8 FF 31 D2 F7 F6 89 04 24 88 54 24 07 EB 02 89 D9 8A 03 8D 50 D0 80 FA 09 76 0C 83 C8 20 B2 28 3C 60 76 03 8D 50 A9 0F B6 C2 39 F0 7D 31 43 3B 3C 24 77 08 75 1C 3A 54 24 07 76 16 8A 44 24 28 21 C5 E8 ?? ?? ?? ?? C7 00 22 00 00 00 83 CF FF EB BD 0F B6 D2 }
	condition:
		$pattern
}

rule readahead_6cee4e3a181790c7abe600771d30c53a {
	meta:
		aliases = "readahead"
		type = "func"
		size = "86"
		objfiles = "readahead@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 8B 7C 24 20 8B 6C 24 24 8B 74 24 28 89 F8 89 EA 89 D0 89 C2 C1 FA 1F 89 04 24 89 54 24 04 8B 44 24 1C 8B 0C 24 89 FA 53 89 C3 B8 E1 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 59 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __pthread_destroy_specifics_88338a7995eff9685103c247506a1a20 {
	meta:
		aliases = "__pthread_destroy_specifics"
		type = "func"
		size = "192"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 E8 ?? ?? ?? ?? 89 C6 31 ED C7 44 24 04 01 00 00 00 EB 53 83 7C 9E 74 00 74 45 31 FF 89 D8 C1 E0 05 89 04 24 EB 34 8B 04 24 01 F8 8B 0C C5 ?? ?? ?? ?? 8D 04 BD 00 00 00 00 03 44 9E 74 8B 10 85 C9 74 16 85 D2 74 12 C7 00 00 00 00 00 52 FF D1 C7 44 24 08 01 00 00 00 5A 47 83 FF 1F 7E C7 43 83 FB 1F 7E AE 45 83 7C 24 04 00 74 11 83 FD 03 7F 0C 31 DB C7 44 24 04 00 00 00 00 EB E2 8B 46 1C 89 F2 E8 ?? ?? ?? ?? 31 DB EB 18 8B 44 9E 74 85 C0 74 0F 50 E8 ?? ?? ?? ?? C7 44 9E 74 00 00 00 00 58 43 83 FB 1F 7E E3 FF 76 1C E8 ?? ?? ?? ?? 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __copy_rpcent_dcc5add14dbb4bf2580837b847d2edec {
	meta:
		aliases = "__copy_rpcent"
		type = "func"
		size = "252"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 89 C6 89 D3 89 0C 24 8B 44 24 24 C7 00 00 00 00 00 B8 02 00 00 00 85 F6 0F 84 CF 00 00 00 30 C0 89 D7 AB AB AB FF 74 24 20 6A 00 51 E8 ?? ?? ?? ?? 8B 46 08 89 43 08 31 D2 83 C4 0C 8B 46 04 8B 04 90 42 85 C0 75 F5 8D 04 95 00 00 00 00 39 44 24 20 0F 82 90 00 00 00 8D 6A FF 8B 14 24 89 53 04 01 C2 89 54 24 04 8B 4C 24 20 29 C1 89 4C 24 08 EB 45 8D 3C AD 00 00 00 00 8B 46 04 FF 34 38 E8 ?? ?? ?? ?? 59 8D 50 01 39 54 24 08 72 59 8B 43 04 8B 4C 24 04 89 0C 38 01 D1 89 4C 24 04 29 54 24 08 52 8B 46 04 FF 34 38 8B 43 04 FF 34 38 E8 ?? ?? ?? ?? 83 C4 0C 4D 83 FD FF 75 B5 FF 36 E8 }
	condition:
		$pattern
}

rule getsubopt_6b98f2102b682507da4fba27d708498e {
	meta:
		aliases = "getsubopt"
		type = "func"
		size = "217"
		objfiles = "getsubopt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 44 24 20 8B 00 89 04 24 C7 44 24 08 FF FF FF FF 80 38 00 0F 84 AC 00 00 00 6A 2C 50 E8 ?? ?? ?? ?? 5A 59 89 C3 89 C1 2B 0C 24 8B 3C 24 E3 09 B0 3D F2 AE 8D 7F FF 74 02 31 FF 89 DD 85 FF 74 02 89 FD C7 44 24 08 00 00 00 00 89 E8 2B 04 24 89 44 24 04 EB 41 FF 74 24 04 56 FF 74 24 08 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 28 8B 54 24 04 80 3C 16 00 75 1E 39 DD 74 03 8D 45 01 8B 7C 24 28 89 07 80 3B 00 74 04 C6 03 00 43 8B 44 24 20 89 18 EB 33 FF 44 24 08 8B 54 24 08 8B 7C 24 24 8B 34 97 85 F6 75 B0 8B 14 24 8B 44 24 28 89 10 80 3B 00 74 04 C6 03 00 43 8B 7C 24 20 89 1F C7 44 24 }
	condition:
		$pattern
}

rule __ns_name_unpack_62c80aa01348ab92847092bb08fec35e {
	meta:
		aliases = "__GI___ns_name_unpack, __ns_name_unpack"
		type = "func"
		size = "263"
		objfiles = "ns_name@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 44 24 2C 8B 54 24 30 01 C2 89 54 24 04 8B 54 24 20 39 54 24 28 0F 82 A4 00 00 00 8B 54 24 24 39 54 24 28 0F 83 96 00 00 00 8B 7C 24 28 89 C3 31 ED C7 44 24 08 FF FF FF FF 2B 54 24 20 89 14 24 E9 8F 00 00 00 0F B6 F1 89 F0 25 C0 00 00 00 74 09 3D C0 00 00 00 75 67 EB 29 8D 44 1E 01 3B 44 24 04 73 5B 8D 3C 32 3B 7C 24 24 73 52 88 0B 43 56 52 53 E8 ?? ?? ?? ?? 8D 6C 35 01 01 F3 83 C4 0C EB 51 3B 54 24 24 73 36 83 7C 24 08 00 79 09 2B 54 24 28 42 89 54 24 08 83 E6 3F C1 E6 08 0F B6 47 01 09 C6 8B 7C 24 20 01 F7 3B 7C 24 20 72 0E 3B 7C 24 24 73 08 83 C5 02 3B 2C 24 7C 15 E8 }
	condition:
		$pattern
}

rule __pthread_unlock_b206eefc5b2273761e537d6635270b6b {
	meta:
		aliases = "__pthread_unlock"
		type = "func"
		size = "158"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 4C 24 20 EB 0F 31 DB 89 D0 F0 0F B1 19 0F 94 C2 84 D2 75 78 8B 11 83 FA 01 74 EA 89 D7 83 E7 FE 89 F8 89 CD 89 CE C7 04 24 00 00 00 00 EB 16 8B 58 18 3B 1C 24 7C 05 89 EE 89 1C 24 8D 68 0C 8B 40 0C 83 E0 FE 85 C0 75 E6 39 CE 75 15 8B 5F 0C 83 E3 FE 89 D0 F0 0F B1 19 0F 94 C2 84 D2 74 B4 EB 1C 8B 3E 83 E7 FE 8B 47 0C 89 06 8B 01 89 C2 83 E2 FE F0 0F B1 11 0F 94 C2 84 D2 74 EE C7 47 0C 00 00 00 00 89 F8 E8 ?? ?? ?? ?? 31 C0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __decode_dotted_82bb83c4485d31e97d70b2efb557a4df {
	meta:
		aliases = "__decode_dotted"
		type = "func"
		size = "259"
		objfiles = "decoded@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 54 24 24 83 7C 24 20 00 0F 84 E2 00 00 00 C6 44 24 07 01 31 ED C7 44 24 08 00 00 00 00 EB 04 89 7C 24 08 3B 54 24 28 0F 8D C3 00 00 00 8B 4C 24 20 8A 04 11 84 C0 0F 84 A8 00 00 00 80 7C 24 07 01 83 DD FF 0F B6 F0 8D 4A 01 89 F0 25 C0 00 00 00 3D C0 00 00 00 75 2F 3B 4C 24 28 0F 8D 8E 00 00 00 80 7C 24 07 01 83 DD FF 89 F2 83 E2 3F C1 E2 08 8B 5C 24 20 0F B6 04 0B 09 C2 8B 7C 24 08 C6 44 24 07 00 EB 98 8B 44 24 08 01 F0 89 04 24 89 C7 47 3B 7C 24 30 73 57 8D 1C 0E 3B 5C 24 28 73 4E 56 8B 44 24 24 01 C8 50 8B 44 24 34 03 44 24 10 50 E8 ?? ?? ?? ?? 89 DA 83 C4 0C 80 7C 24 }
	condition:
		$pattern
}

rule svcudp_reply_9431d10d0553bc59c9d90d42467eda3f {
	meta:
		aliases = "svcudp_reply"
		type = "func"
		size = "469"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 6C 24 20 8B 5C 24 24 8B 7D 30 8D 77 08 C7 47 08 00 00 00 00 8B 47 0C 6A 00 56 FF 50 14 8B 47 04 89 03 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 8F 01 00 00 8B 47 0C 56 FF 50 10 89 44 24 0C 8D 55 3C 5B 83 7A 0C 00 74 1D 8B 45 2C 89 45 34 8B 44 24 08 89 45 38 6A 00 52 FF 75 00 E8 ?? ?? ?? ?? 83 C4 0C EB 1B 8D 45 10 FF 75 0C 50 6A 00 FF 74 24 14 FF 75 2C FF 75 00 E8 ?? ?? ?? ?? 83 C4 18 3B 44 24 08 0F 85 38 01 00 00 83 BF B0 01 00 00 00 74 07 83 7C 24 08 00 79 0A B8 01 00 00 00 E9 20 01 00 00 8B 7D 30 8B B7 B0 01 00 00 8B 56 0C 8B 46 08 8B 1C 90 85 DB 74 3C 8B 06 8D 14 85 }
	condition:
		$pattern
}

rule _dl_find_hash_cedbedcaacd435320dd569f625d058cd {
	meta:
		aliases = "_dl_find_hash"
		type = "func"
		size = "290"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 6C 24 24 8B 44 24 30 85 C0 74 06 8B 10 85 D2 75 12 83 CF FF 8B 44 24 2C 83 E0 02 89 04 24 E9 C9 00 00 00 0F B6 42 0D 83 E0 03 83 F8 03 75 E2 E9 C2 00 00 00 8B 75 00 F6 46 25 01 75 26 83 7C 24 28 00 74 1F 39 74 24 28 74 19 8B 54 24 28 8B 42 34 EB 07 39 70 04 74 0B 8B 00 85 C0 75 F5 E9 86 00 00 00 83 3C 24 00 74 06 83 7E 18 01 74 7A 8B 5E 28 85 DB 74 73 8B 46 58 89 44 24 04 83 FF FF 75 27 8B 4C 24 20 31 FF EB 19 0F B6 D0 C1 E7 04 01 FA 41 89 D0 25 00 00 00 F0 89 C7 31 D7 C1 E8 18 31 C7 8A 01 84 C0 75 E1 8B 56 54 89 54 24 08 89 F8 31 D2 F7 F3 8B 46 2C 8B 1C 90 EB 27 89 D8 }
	condition:
		$pattern
}

rule __pthread_alt_unlock_d6086c324d0b458581ce3d646148afe9 {
	meta:
		aliases = "__pthread_alt_unlock"
		type = "func"
		size = "174"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 74 24 20 8B 16 83 FA 01 77 14 31 C9 89 D0 F0 0F B1 0E 0F 94 C2 84 D2 74 EA E9 80 00 00 00 89 D3 89 F5 89 D7 89 34 24 C7 44 24 04 00 00 00 80 EB 3A 83 7B 08 00 74 1B 89 D9 89 EA 89 F0 E8 ?? ?? ?? ?? 89 D8 E8 ?? ?? ?? ?? 8B 5D 00 39 F5 75 1B EB 19 8B 43 04 8B 40 18 3B 44 24 04 7C 09 89 DF 89 2C 24 89 44 24 04 89 DD 8B 1B 83 FB 01 75 C1 81 7C 24 04 00 00 00 80 74 89 89 D8 87 47 08 85 C0 75 80 89 F9 8B 14 24 89 F0 E8 ?? ?? ?? ?? 8B 47 04 83 C4 0C 5B 5E 5F 5D E9 ?? ?? ?? ?? 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule readtcp_412a757824dc44763d7b1b5636bedfe0 {
	meta:
		aliases = "readtcp"
		type = "func"
		size = "194"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 74 24 20 8B 6C 24 28 8B 4E 0C BB E8 03 00 00 89 C8 99 F7 FB 89 C1 69 46 08 E8 03 00 00 8D 3C 01 66 31 DB 85 ED 0F 84 85 00 00 00 8B 06 89 44 24 04 66 C7 44 24 08 01 00 8D 5C 24 04 57 6A 01 53 E8 ?? ?? ?? ?? 83 C4 0C 83 F8 FF 74 0D 85 C0 75 24 C7 46 24 05 00 00 00 EB 16 E8 ?? ?? ?? ?? 83 38 04 74 D8 C7 46 24 04 00 00 00 8B 00 89 46 28 83 CB FF EB 3B 55 FF 74 24 28 FF 36 E8 ?? ?? ?? ?? 89 C3 83 C4 0C 83 F8 FF 74 14 85 C0 75 21 C7 46 28 68 00 00 00 C7 46 24 04 00 00 00 EB D1 E8 ?? ?? ?? ?? 8B 00 89 46 28 C7 46 24 04 00 00 00 89 D8 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __read_etc_hosts_r_d21f546f22cc2dd8aceb1077c456d56a {
	meta:
		aliases = "__read_etc_hosts_r"
		type = "func"
		size = "446"
		objfiles = "read_etc_hosts_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 7C 24 20 8B 6C 24 30 8B 5C 24 38 8B 74 24 40 C7 44 24 08 00 00 00 00 C7 06 FF FF FF FF C7 44 24 04 22 00 00 00 81 FB 80 00 00 00 0F 86 79 01 00 00 85 FF 75 25 E8 ?? ?? ?? ?? 89 C7 85 C0 75 1A 8B 44 24 3C C7 00 00 00 00 00 E8 ?? ?? ?? ?? 8B 00 89 44 24 04 E9 50 01 00 00 8B 54 24 34 89 57 04 C7 47 08 30 00 00 00 8D 43 D0 89 47 10 C7 06 01 00 00 00 C7 44 24 04 01 00 00 00 83 C2 18 89 14 24 E9 E9 00 00 00 8B 74 24 08 83 C6 04 89 75 04 83 7C 24 2C 01 0F 84 0E 01 00 00 89 F3 83 7C 24 2C 02 75 2E 8B 44 24 08 FF 30 FF 74 24 28 E8 ?? ?? ?? ?? 5B 5A 85 C0 0F 85 B2 00 00 00 EB 1E }
	condition:
		$pattern
}

rule _dl_parse_a1b36803850d06dddd661c029a405dc0 {
	meta:
		aliases = "_dl_parse"
		type = "func"
		size = "219"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 89 C5 89 14 24 89 CE C1 6C 24 24 03 8B 40 58 89 44 24 0C 8B 55 54 89 54 24 08 C7 44 24 04 00 00 00 00 E9 93 00 00 00 8B 5E 04 FF 74 24 08 FF 74 24 10 56 FF 74 24 0C 55 FF 54 24 3C 89 C7 83 C4 14 85 C0 74 6E C1 EB 08 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? 83 C4 0C 85 DB 74 1E C1 E3 04 8B 44 24 08 8B 54 24 0C 03 04 13 50 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? 83 C4 0C 83 FF 00 7D 19 FF 75 04 0F B6 46 04 50 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? 83 C4 10 EB 2D 7E 14 FF 75 04 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? 83 C4 0C EB 17 FF 44 24 04 83 C6 08 8B 44 24 24 39 44 24 }
	condition:
		$pattern
}

rule xdrrec_create_ef55de97bb256a55e86c16813db6f8c1 {
	meta:
		aliases = "__GI_xdrrec_create, xdrrec_create"
		type = "func"
		size = "269"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 44 24 24 89 44 24 0C 8B 74 24 28 8B 7C 24 2C 8B 44 24 30 89 44 24 08 8B 44 24 34 89 44 24 04 8B 44 24 38 89 04 24 6A 44 E8 ?? ?? ?? ?? 89 C3 5D 83 FE 63 77 05 BE A0 0F 00 00 8D 6E 03 83 E5 FC 83 FF 63 77 05 BF A0 0F 00 00 83 C7 03 83 E7 FC 8D 44 3D 04 50 E8 ?? ?? ?? ?? 89 C6 59 85 DB 74 04 85 C0 75 26 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 89 74 24 30 83 C4 1C 5B 5E 5F 5D E9 ?? ?? ?? ?? 89 6B 3C 89 7B 40 89 43 04 89 C2 83 E0 03 74 05 29 C6 8D 56 04 89 53 0C 8D 04 2A 89 43 28 8B 44 24 0C C7 40 04 ?? ?? ?? ?? 89 58 0C 8B 44 24 08 89 03 8B 44 24 }
	condition:
		$pattern
}

rule _time_t2tm_d4d48b48602415ec28b2a0602494f5d5 {
	meta:
		aliases = "_time_t2tm"
		type = "func"
		size = "364"
		objfiles = "_time_t2tm@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 44 24 24 8B 18 8B 74 24 2C C7 46 1C 00 00 00 00 C7 44 24 0C ?? ?? ?? ?? 8B 44 24 28 05 76 0E 02 00 89 44 24 04 8B 54 24 0C 66 8B 2A 0F B7 CD 66 83 FD 07 75 27 89 D8 99 F7 F9 8D 42 0B B9 07 00 00 00 99 F7 F9 89 54 24 08 8B 54 24 0C 0F B7 42 02 8D 0C 85 01 00 00 00 03 5C 24 04 89 D8 99 F7 F9 89 C7 0F AF C1 29 C3 79 03 01 CB 4F 66 83 FD 07 75 0D 8D 41 FF 39 C3 75 06 8D 59 FE FF 46 10 83 F9 3C 8D 4E 04 7F 08 89 1E 89 CE 89 FB EB 04 89 3E 89 CE 83 44 24 0C 02 8B 54 24 0C 66 83 3A 00 75 82 83 79 FC 04 75 0C C7 41 FC 03 00 00 00 BB 6D 01 00 00 01 19 8D 59 F8 8B 51 FC 81 EA 2B }
	condition:
		$pattern
}

rule wcsnrtombs_97ea943256b4b2c862598e23a538e028 {
	meta:
		aliases = "__GI_wcsnrtombs, wcsnrtombs"
		type = "func"
		size = "127"
		objfiles = "wcsnrtombs@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 54 24 24 8B 6C 24 28 8B 4C 24 2C 8B 44 24 30 85 D2 74 10 BF 01 00 00 00 39 EA 75 0E 89 E2 66 31 FF EB 07 89 E2 83 C8 FF 31 FF 89 C6 39 C8 76 02 89 CE 8B 4D 00 89 F3 EB 27 8B 01 83 F8 7F 76 10 E8 ?? ?? ?? ?? C7 00 54 00 00 00 83 C8 FF EB 1F 88 02 84 C0 75 04 31 C9 EB 0A 83 C1 04 01 FA 4B 85 DB 75 D5 39 E2 74 03 89 4D 00 89 F0 29 D8 83 C4 10 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule srandom_r_7c19d8c8f71e7f45238ef7aa61bdecc2 {
	meta:
		aliases = "__GI_srandom_r, srandom_r"
		type = "func"
		size = "160"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 54 24 24 8B 74 24 28 8A 46 0C 88 44 24 0B 0F BE C0 83 C9 FF 83 F8 04 77 75 8B 5E 08 85 D2 75 02 B2 01 89 13 80 7C 24 0B 00 74 61 0F BE 6E 0D 89 2C 24 89 D9 BF 01 00 00 00 EB 2A 89 D0 BD 1D F3 01 00 99 F7 FD 89 44 24 04 69 D2 A7 41 00 00 69 C0 14 0B 00 00 29 C2 79 06 81 C2 FF FF FF 7F 83 C1 04 89 11 47 3B 3C 24 7C D1 0F BE 46 0E 8D 04 83 89 06 89 5E 04 6B 1C 24 0A 8D 7C 24 0C EB 09 57 56 E8 ?? ?? ?? ?? 5D 58 4B 79 F4 31 C9 89 C8 83 C4 10 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _dl_do_reloc_c47cbef6dee6d03c64c9a10da7741d61 {
	meta:
		aliases = "_dl_do_reloc"
		type = "func"
		size = "250"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 6C 24 24 8B 44 24 2C 8B 55 00 89 14 24 8B 10 89 54 24 04 8B 40 04 0F B6 D8 C1 E8 08 89 C6 C1 E6 04 03 74 24 30 89 74 24 08 C7 44 24 0C 00 00 00 00 8B 3E 85 C0 74 6D 83 FB 07 74 19 83 FB 23 74 14 83 FB 24 74 0F 83 FB 25 74 0A 31 C9 83 FB 0E 0F 94 C1 EB 05 B9 01 00 00 00 31 C0 83 FB 05 0F 94 C0 01 C0 8D 54 24 08 52 09 C8 50 55 FF 74 24 34 8B 44 24 44 01 F8 50 E8 ?? ?? ?? ?? 89 C1 83 C4 14 85 C0 75 1A 8A 56 0C 89 D0 83 E0 0F 83 F8 06 74 0D C0 EA 04 B8 01 00 00 00 80 FA 02 75 4A 89 C8 EB 03 8B 46 04 8B 54 24 04 03 14 24 83 FB 08 77 07 FF 24 9D ?? ?? ?? ?? 83 C8 FF EB 2B 29 }
	condition:
		$pattern
}

rule getprotobyname_r_9d4cfd852722360d517271ac1a4acfef {
	meta:
		aliases = "__GI_getprotobyname_r, getprotobyname_r"
		type = "func"
		size = "182"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 6C 24 24 8B 74 24 28 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F BE 05 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 14 EB 29 FF 36 55 E8 ?? ?? ?? ?? 5B 5A 85 C0 74 36 8B 5E 04 EB 10 50 55 E8 ?? ?? ?? ?? 5A 59 85 C0 74 24 83 C3 04 8B 03 85 C0 75 EA FF 74 24 34 FF 74 24 34 FF 74 24 34 56 E8 ?? ?? ?? ?? 89 C7 83 C4 10 85 C0 74 BC 80 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 8B 44 24 3C 83 38 00 0F 94 C0 0F B6 C0 F7 D8 21 F8 83 C4 18 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule getservbyname_r_d4bf4bbe5acea59e4c15179cc3bee0d4 {
	meta:
		aliases = "__GI_getservbyname_r, getservbyname_r"
		type = "func"
		size = "209"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 6C 24 28 8B 74 24 2C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F BE 05 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 14 EB 44 FF 36 FF 74 24 28 E8 ?? ?? ?? ?? 59 5B 85 C0 74 20 8B 5E 04 EB 13 50 FF 74 24 28 E8 ?? ?? ?? ?? 59 5A 85 C0 74 0B 83 C3 04 8B 03 85 C0 75 E7 EB 13 85 ED 74 2A 55 FF 76 0C E8 ?? ?? ?? ?? 5B 5A 85 C0 74 1B FF 74 24 38 FF 74 24 38 FF 74 24 38 56 E8 ?? ?? ?? ?? 89 C7 83 C4 10 85 C0 74 A1 80 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 8B 44 24 40 83 38 00 0F 94 C0 0F B6 C0 F7 D8 21 }
	condition:
		$pattern
}

rule fwide_b0b8c1deb75405275c4164881a557c61 {
	meta:
		aliases = "fwide"
		type = "func"
		size = "134"
		objfiles = "fwide@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 74 24 24 8B 6C 24 28 83 7E 34 00 0F 94 C0 0F B6 F8 85 FF 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 85 ED 74 1D 8B 16 F7 C2 80 08 00 00 75 13 B8 00 08 00 00 85 ED 7F 05 B8 80 00 00 00 09 D0 66 89 06 0F B7 1E 85 FF 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 D8 25 00 08 00 00 81 E3 80 00 00 00 29 D8 83 C4 10 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule readdir_r_baefc56fbac74ac58064e56c685b177d {
	meta:
		aliases = "__GI_readdir_r, readdir_r"
		type = "func"
		size = "187"
		objfiles = "readdir_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 74 24 24 8B 6C 24 2C 8D 5E 18 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 31 FF 83 C4 10 8B 46 08 3B 46 04 77 35 FF 76 14 FF 76 0C FF 36 E8 ?? ?? ?? ?? 83 C4 0C 83 F8 00 7F 16 C7 45 00 00 00 00 00 75 04 31 DB EB 43 E8 ?? ?? ?? ?? 8B 18 EB 3A 89 46 08 C7 46 04 00 00 00 00 8B 46 04 89 C7 03 7E 0C 0F B7 57 08 8D 04 02 89 46 04 8B 47 04 89 46 10 83 3F 00 74 A6 52 57 FF 74 24 30 E8 ?? ?? ?? ?? 89 45 00 31 DB 83 C4 0C 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 31 C0 85 FF 0F 94 C0 F7 D8 21 C3 89 D8 83 C4 18 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule readdir64_r_706f7c2291d5f808517dd52db5beead6 {
	meta:
		aliases = "__GI_readdir64_r, readdir64_r"
		type = "func"
		size = "189"
		objfiles = "readdir64_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 74 24 24 8B 6C 24 2C 8D 5E 18 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 31 FF 83 C4 10 8B 46 08 3B 46 04 77 35 FF 76 14 FF 76 0C FF 36 E8 ?? ?? ?? ?? 83 C4 0C 83 F8 00 7F 16 C7 45 00 00 00 00 00 75 04 31 DB EB 45 E8 ?? ?? ?? ?? 8B 18 EB 3C 89 46 08 C7 46 04 00 00 00 00 8B 46 04 89 C7 03 7E 0C 0F B7 57 10 8D 04 02 89 46 04 8B 47 08 89 46 10 8B 07 0B 47 04 74 A4 52 57 FF 74 24 30 E8 ?? ?? ?? ?? 89 45 00 31 DB 83 C4 0C 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 31 C0 85 FF 0F 94 C0 F7 D8 21 C3 89 D8 83 C4 18 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fgetpos_0805757290c8faa9db9e8c0d1d9649a7 {
	meta:
		aliases = "fgetpos"
		type = "func"
		size = "122"
		objfiles = "fgetpos@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 74 24 24 8B 7C 24 28 83 7E 34 00 0F 94 C0 0F B6 E8 85 ED 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 56 E8 ?? ?? ?? ?? 89 07 59 83 CB FF 85 C0 78 15 8B 46 2C 89 47 04 8B 46 30 89 47 08 0F B6 46 02 89 47 0C 31 DB 85 ED 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 10 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fgetpos64_76706c73f228c69a5491a74d05fb0d44 {
	meta:
		aliases = "fgetpos64"
		type = "func"
		size = "125"
		objfiles = "fgetpos64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 74 24 24 8B 7C 24 28 83 7E 34 00 0F 94 C0 0F B6 E8 85 ED 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 56 E8 ?? ?? ?? ?? 89 07 89 57 04 59 83 CB FF 85 D2 78 15 8B 46 2C 89 47 08 8B 46 30 89 47 0C 0F B6 46 02 89 47 10 31 DB 85 ED 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 10 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fsetpos_02f00e02a54bce692855c178656d4799 {
	meta:
		aliases = "fsetpos"
		type = "func"
		size = "122"
		objfiles = "fsetpos@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 74 24 24 8B 7C 24 28 83 7E 34 00 0F 94 C0 0F B6 E8 85 ED 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 6A 00 FF 37 56 E8 ?? ?? ?? ?? 89 C3 83 C4 0C 85 C0 75 12 8B 47 04 89 46 2C 8B 47 08 89 46 30 8B 47 0C 88 46 02 85 ED 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 10 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fsetpos64_20a49404510c7519ca6163cb58070361 {
	meta:
		aliases = "fsetpos64"
		type = "func"
		size = "125"
		objfiles = "fsetpos64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 74 24 24 8B 7C 24 28 83 7E 34 00 0F 94 C0 0F B6 E8 85 ED 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 6A 00 FF 77 04 FF 37 56 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 75 12 8B 47 08 89 46 2C 8B 47 0C 89 46 30 8B 47 10 88 46 02 85 ED 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 10 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule putgrent_29c596081f0a3df66dc78d538c8399a9 {
	meta:
		aliases = "putgrent"
		type = "func"
		size = "198"
		objfiles = "putgrent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 74 24 24 8B 7C 24 28 85 F6 74 04 85 FF 75 13 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CB FF E9 92 00 00 00 83 7F 34 00 0F 94 C0 0F B6 E8 85 ED 74 1C 8D 5F 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 FF 76 08 FF 76 04 FF 36 68 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 83 C4 14 85 C0 78 39 8B 5E 0C BA ?? ?? ?? ?? 8B 03 85 C0 75 12 57 6A 0A E8 ?? ?? ?? ?? 59 5B 31 DB 85 C0 79 1E EB 19 50 52 57 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 78 0A 83 C3 04 BA ?? ?? ?? ?? EB CF 83 CB FF 85 ED 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 10 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule getprotobynumber_r_4c9deb7056fc9a08bf290336a0b03123 {
	meta:
		aliases = "__GI_getprotobynumber_r, getprotobynumber_r"
		type = "func"
		size = "143"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 74 24 28 8B 6C 24 30 8B 7C 24 34 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F BE 05 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 14 EB 09 8B 44 24 24 3B 46 08 74 15 57 55 FF 74 24 34 56 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 74 E2 80 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 31 C0 83 3F 00 0F 94 C0 F7 D8 21 D8 83 C4 18 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _dl_load_shared_library_1f91c8c2591a22bef9ef0ecc4c74c392 {
	meta:
		aliases = "_dl_load_shared_library"
		type = "func"
		size = "474"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 74 24 2C 8B 5C 24 30 C7 05 ?? ?? ?? ?? 00 00 00 00 8D 43 FF 40 80 38 00 75 FA 29 D8 3D 00 04 00 00 0F 87 87 01 00 00 8D 43 FF 31 C9 EB 07 80 FA 2F 75 02 89 C1 40 8A 10 84 D2 75 F2 89 DF 85 C9 74 03 8D 79 01 39 DF 74 19 53 FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 0C 85 C0 0F 85 68 01 00 00 85 F6 74 22 8B 4E 7C 85 C9 74 1B 03 4E 54 FF 74 24 28 8B 54 24 28 89 F8 E8 ?? ?? ?? ?? 5B 85 C0 0F 85 42 01 00 00 8B 0D ?? ?? ?? ?? 85 C9 74 18 FF 74 24 28 8B 54 24 28 89 F8 E8 ?? ?? ?? ?? 59 85 C0 0F 85 20 01 00 00 85 F6 74 25 8B 8E B4 00 00 00 85 C9 74 1B 03 4E 54 FF 74 24 28 8B }
	condition:
		$pattern
}

rule rresvport_861bc12032b8c2ea393c0da4d66fa7f2 {
	meta:
		aliases = "__GI_rresvport, rresvport"
		type = "func"
		size = "137"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 7C 24 24 66 C7 04 24 02 00 C7 44 24 04 00 00 00 00 6A 00 6A 01 6A 02 E8 ?? ?? ?? ?? 89 C3 83 C4 0C 89 E5 85 C0 79 05 83 CB FF EB 4B 8B 07 66 C1 C8 08 66 89 44 24 02 6A 10 55 53 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 79 30 E8 ?? ?? ?? ?? 89 C6 83 38 62 74 08 53 E8 ?? ?? ?? ?? EB 18 8B 07 48 89 07 3D 00 02 00 00 75 C5 53 E8 ?? ?? ?? ?? C7 06 0B 00 00 00 83 CB FF 5E 89 D8 83 C4 10 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule unsetenv_639884a97fb7d3b9fcfa23ff02b3a088 {
	meta:
		aliases = "__GI_unsetenv, unsetenv"
		type = "func"
		size = "172"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 7C 24 24 85 FF 74 14 80 3F 00 74 0F 6A 3D 57 E8 ?? ?? ?? ?? 5B 5E 80 38 3D 75 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 71 89 C5 29 FD 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 83 C4 10 85 F6 75 2C EB 30 55 57 53 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 18 80 3C 2B 3D 75 12 89 F2 8D 4A 04 8B 42 04 89 02 85 C0 74 07 89 CA EB F0 83 C6 04 8B 1E 85 DB 75 D0 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 31 C0 5A 59 83 C4 10 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule ungetwc_2a584ddfa9c4c53d87f7347c70cd152f {
	meta:
		aliases = "__GI_ungetwc, ungetwc"
		type = "func"
		size = "168"
		objfiles = "ungetwc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 7C 24 24 8B 74 24 28 83 7E 34 00 0F 94 C0 0F B6 E8 85 ED 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 0F B7 06 25 03 08 00 00 3D 00 08 00 00 77 11 68 00 08 00 00 56 E8 ?? ?? ?? ?? 59 5B 85 C0 75 30 0F B7 06 A8 02 74 0A A8 01 75 25 83 7E 28 00 75 1F 83 FF FF 74 1A C7 46 28 01 00 00 00 8B 06 40 66 89 06 83 E0 01 89 7C 86 24 66 83 26 FB EB 03 83 CF FF 85 ED 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 F8 83 C4 10 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule ungetc_7ee0202ad94a1be3f2054a8cf1ced550 {
	meta:
		aliases = "__GI_ungetc, ungetc"
		type = "func"
		size = "205"
		objfiles = "ungetc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 7C 24 24 8B 74 24 28 83 7E 34 00 0F 94 C0 0F B6 E8 85 ED 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 8B 46 10 3B 46 18 73 17 83 FF FF 74 12 3B 46 08 76 0D 89 FA 38 50 FF 75 06 48 89 46 10 EB 50 0F B7 06 25 83 00 00 00 3D 80 00 00 00 77 11 68 80 00 00 00 56 E8 ?? ?? ?? ?? 59 5B 85 C0 75 36 0F B7 06 A8 02 74 0A A8 01 75 2B 83 7E 28 00 75 25 83 FF FF 74 20 8B 46 08 89 46 18 C7 46 28 01 00 00 00 8B 06 40 66 89 06 83 E0 01 89 7C 86 24 66 83 26 FB EB 03 83 CF FF 85 ED 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 F8 83 C4 10 }
	condition:
		$pattern
}

rule putspent_08089b5f37ce3242e6652bed4bf5e6fe {
	meta:
		aliases = "putspent"
		type = "func"
		size = "214"
		objfiles = "putspent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 7C 24 24 8B 74 24 28 83 7E 34 00 0F 94 C0 0F B6 E8 85 ED 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 8B 47 04 85 C0 75 05 B8 ?? ?? ?? ?? 50 FF 37 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 10 31 DB 85 C0 79 2B EB 59 0F B6 83 ?? ?? ?? ?? 8B 04 07 BA ?? ?? ?? ?? 83 F8 FF 74 05 BA ?? ?? ?? ?? 50 52 56 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 78 31 43 83 FB 05 76 D2 8B 47 20 83 F8 FF 74 13 50 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 78 10 56 6A 0A E8 ?? ?? ?? ?? 59 5B 31 DB 85 C0 7F 03 83 CB FF 85 ED 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? }
	condition:
		$pattern
}

rule getservbyport_r_17f3fab7b434eb5793e0a64b175c54cd {
	meta:
		aliases = "__GI_getservbyport_r, getservbyport_r"
		type = "func"
		size = "166"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 7C 24 28 8B 5C 24 2C 8B 6C 24 38 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F BE 05 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 14 EB 1C 8B 44 24 24 39 43 08 75 13 85 FF 74 27 57 FF 73 0C E8 ?? ?? ?? ?? 5A 59 85 C0 74 18 55 FF 74 24 38 FF 74 24 38 53 E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 C0 74 CC 80 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 31 C0 83 7D 00 00 0F 94 C0 F7 D8 21 F0 83 C4 18 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule ceil_8cf17b67713e9b6ced91b4da40060a8b {
	meta:
		aliases = "__GI_ceil, ceil"
		type = "func"
		size = "310"
		objfiles = "s_ceil@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 C7 04 24 00 00 00 00 C7 44 24 04 00 00 00 00 DD 44 24 24 DD 54 24 08 8B 54 24 0C 8B 6C 24 08 89 EE 89 D0 C1 F8 14 25 FF 07 00 00 8D 98 01 FC FF FF 83 FB 13 7F 7D 85 DB 79 38 DD 05 ?? ?? ?? ?? DE C1 D9 EE D9 C9 DA E9 DF E0 9E 0F 86 C4 00 00 00 85 D2 79 07 BA 00 00 00 80 EB 0F 89 E9 09 D1 0F 84 AF 00 00 00 BA 00 00 F0 3F 31 F6 E9 A3 00 00 00 DD D8 BF FF FF 0F 00 88 D9 D3 FF 89 F8 21 D0 09 E8 0F 84 9A 00 00 00 DD 44 24 24 DC 05 ?? ?? ?? ?? D9 EE D9 C9 DA E9 DF E0 9E 76 77 85 D2 7E 09 B8 00 00 10 00 D3 F8 01 C2 89 F8 F7 D0 21 C2 EB B8 DD D8 83 FB 33 7E 10 81 FB 00 04 00 00 75 }
	condition:
		$pattern
}

rule floor_ff0fd13464850e0ec082432a04d89236 {
	meta:
		aliases = "__GI_floor, floor"
		type = "func"
		size = "312"
		objfiles = "s_floor@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 C7 04 24 00 00 00 00 C7 44 24 04 00 00 00 00 DD 44 24 24 DD 54 24 08 8B 54 24 0C 8B 6C 24 08 89 EE 89 D0 C1 F8 14 25 FF 07 00 00 8D 98 01 FC FF FF 83 FB 13 7F 7F 85 DB 79 3A DD 05 ?? ?? ?? ?? DE C1 D9 EE D9 C9 DA E9 DF E0 9E 0F 86 C6 00 00 00 85 D2 78 04 31 D2 EB 14 89 D0 25 FF FF FF 7F 09 E8 0F 84 AF 00 00 00 BA 00 00 F0 BF 31 F6 E9 A3 00 00 00 DD D8 BF FF FF 0F 00 88 D9 D3 FF 89 F8 21 D0 09 E8 0F 84 9A 00 00 00 DD 44 24 24 DC 05 ?? ?? ?? ?? D9 EE D9 C9 DA E9 DF E0 9E 76 77 85 D2 79 09 B8 00 00 10 00 D3 F8 01 C2 89 F8 F7 D0 21 C2 EB B8 DD D8 83 FB 33 7E 10 81 FB 00 04 00 }
	condition:
		$pattern
}

rule lround_3095c0570d8623de324693f16e6ae11b {
	meta:
		aliases = "__GI_lround, lround"
		type = "func"
		size = "198"
		objfiles = "s_lround@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 DD 44 24 24 DD 1C 24 8B 44 24 04 8B 2C 24 89 C1 C1 E9 14 81 E1 FF 07 00 00 8D 99 01 FC FF FF 89 C7 C1 FF 1F 83 CF 01 89 C2 81 E2 FF FF 0F 00 81 CA 00 00 10 00 83 FB 13 7F 23 85 DB 79 09 89 F8 43 74 74 31 C0 EB 70 B8 00 00 08 00 88 D9 D3 F8 01 D0 B9 14 00 00 00 29 D9 D3 E8 EB 57 83 FB 1E 7F 2B 81 E9 13 04 00 00 B8 00 00 00 80 D3 E8 8D 34 28 39 EE 83 D2 00 89 D0 83 FB 14 74 36 D3 E0 B9 34 00 00 00 29 D9 D3 EE 09 F0 EB 27 D9 7C 24 0E 66 8B 44 24 0E 80 CC 0C 66 89 44 24 0C DD 44 24 24 D9 6C 24 0C DB 5C 24 08 D9 6C 24 0E 8B 44 24 08 EB 03 0F AF C7 83 C4 10 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule ptsname_r_3fb4cc3db051b3145e3923ee7676d260 {
	meta:
		aliases = "__GI_ptsname_r, ptsname_r"
		type = "func"
		size = "144"
		objfiles = "ptsname@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 E8 ?? ?? ?? ?? 89 C7 8B 28 8D 44 24 0C 50 68 30 54 04 80 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 53 6A 00 6A F6 8B 44 24 14 99 52 50 8D 5C 24 1B 53 E8 ?? ?? ?? ?? 89 C6 29 C3 83 C3 0A 83 C4 14 39 5C 24 2C 73 0D C7 07 22 00 00 00 B8 22 00 00 00 EB 2C 68 ?? ?? ?? ?? FF 74 24 2C E8 ?? ?? ?? ?? 56 FF 74 24 34 E8 ?? ?? ?? ?? 89 2F 31 C0 83 C4 10 EB 0B C7 07 19 00 00 00 B8 19 00 00 00 83 C4 10 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule scandir_d07680bbe90b88b00230c939acdaf6f6 {
	meta:
		aliases = "scandir"
		type = "func"
		size = "322"
		objfiles = "scandir@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 FF 74 24 24 E8 ?? ?? ?? ?? 89 44 24 04 59 83 C8 FF 83 3C 24 00 0F 84 18 01 00 00 E8 ?? ?? ?? ?? 89 C6 8B 00 89 44 24 0C C7 06 00 00 00 00 C7 44 24 04 00 00 00 00 C7 44 24 08 00 00 00 00 31 ED EB 76 83 7C 24 2C 00 74 12 57 FF 54 24 30 5A 85 C0 75 08 C7 06 00 00 00 00 EB 5D C7 06 00 00 00 00 3B 6C 24 08 75 2F C7 44 24 08 0A 00 00 00 85 ED 74 08 8D 54 2D 00 89 54 24 08 8B 44 24 08 C1 E0 02 50 FF 74 24 08 E8 ?? ?? ?? ?? 59 5B 85 C0 74 39 89 44 24 04 0F B7 5F 08 53 E8 ?? ?? ?? ?? 5A 85 C0 74 26 53 57 50 E8 ?? ?? ?? ?? 8B 54 24 10 89 04 AA 45 83 C4 0C FF 34 24 E8 ?? ?? ?? ?? 89 }
	condition:
		$pattern
}

rule scandir64_dc74a11de6acaf3f70a406937cd8c321 {
	meta:
		aliases = "scandir64"
		type = "func"
		size = "322"
		objfiles = "scandir64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 FF 74 24 24 E8 ?? ?? ?? ?? 89 44 24 04 59 83 C8 FF 83 3C 24 00 0F 84 18 01 00 00 E8 ?? ?? ?? ?? 89 C6 8B 00 89 44 24 0C C7 06 00 00 00 00 C7 44 24 04 00 00 00 00 C7 44 24 08 00 00 00 00 31 ED EB 76 83 7C 24 2C 00 74 12 57 FF 54 24 30 5A 85 C0 75 08 C7 06 00 00 00 00 EB 5D C7 06 00 00 00 00 3B 6C 24 08 75 2F C7 44 24 08 0A 00 00 00 85 ED 74 08 8D 54 2D 00 89 54 24 08 8B 44 24 08 C1 E0 02 50 FF 74 24 08 E8 ?? ?? ?? ?? 59 5B 85 C0 74 39 89 44 24 04 0F B7 5F 10 53 E8 ?? ?? ?? ?? 5A 85 C0 74 26 53 57 50 E8 ?? ?? ?? ?? 8B 54 24 10 89 04 AA 45 83 C4 0C FF 34 24 E8 ?? ?? ?? ?? 89 }
	condition:
		$pattern
}

rule fcloseall_1502db20f8b4638434b7a9d8a3be0941 {
	meta:
		aliases = "fcloseall"
		type = "func"
		size = "226"
		objfiles = "fcloseall@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 0C 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 40 A3 ?? ?? ?? ?? 6A 01 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 24 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 6A 01 53 E8 ?? ?? ?? ?? C7 44 24 0C 00 00 00 00 83 C4 0C EB 5E 8B 6E 20 83 7E 34 00 0F 94 C0 0F B6 F8 85 FF 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 0F B7 06 83 E0 30 83 F8 30 74 12 56 E8 ?? ?? ?? ?? 59 85 C0 74 07 C7 04 24 FF FF FF FF 85 FF 74 0E 6A 01 8D 44 24 08 50 E8 ?? ?? }
	condition:
		$pattern
}

rule fflush_unlocked_58dd84072b2612e2dcc74f9d67ebd29a {
	meta:
		aliases = "__GI_fflush_unlocked, fflush_unlocked"
		type = "func"
		size = "282"
		objfiles = "fflush_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 5C 24 28 66 C7 44 24 02 00 00 81 FB ?? ?? ?? ?? 74 0F 66 C7 44 24 02 00 01 85 DB 0F 85 C6 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 0C 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 40 A3 ?? ?? ?? ?? 6A 01 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 24 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 6A 01 53 E8 ?? ?? ?? ?? 31 FF 83 C4 0C 89 DD EB 56 F6 06 40 74 4E 8D 5E 38 53 68 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 66 8B 44 24 12 0B 06 66 35 40 01 83 C4 10 A9 40 03 00 00 75 1A 56 E8 ?? ?? ?? ?? 59 85 C0 74 05 }
	condition:
		$pattern
}

rule rendezvous_request_7b9505d294e0af476ed4e993e27b736b {
	meta:
		aliases = "rendezvous_request"
		type = "func"
		size = "90"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 5C 24 28 8B 7B 2C 89 E6 8D 6C 24 10 C7 44 24 10 10 00 00 00 55 56 FF 33 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 79 0C E8 ?? ?? ?? ?? 83 38 04 75 1A EB DC 8B 4F 04 8B 17 E8 ?? ?? ?? ?? 8D 78 10 A5 A5 A5 A5 8B 54 24 10 89 50 0C 31 C0 83 C4 14 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule sigaction_b89ecf605089a2ef606d1112e7ed1c09 {
	meta:
		aliases = "__GI_sigaction, sigaction"
		type = "func"
		size = "182"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 5C 24 28 8B 7C 24 2C 8B 6C 24 30 3B 1D ?? ?? ?? ?? 0F 84 84 00 00 00 3B 1D ?? ?? ?? ?? 74 7C 3B 1D ?? ?? ?? ?? 75 04 85 DB 7F 70 31 C0 85 FF 74 34 89 E6 6A 14 57 56 E8 ?? ?? ?? ?? 83 C4 0C 83 3F 01 76 1F 85 DB 7E 1B 83 FB 40 7F 16 F6 47 04 04 74 09 C7 04 24 ?? ?? ?? ?? EB 07 C7 04 24 ?? ?? ?? ?? 89 E0 55 50 53 E8 ?? ?? ?? ?? 83 C4 0C 83 CA FF 40 74 2E 8D 43 FF 83 F8 3F 77 24 85 ED 74 0A 8B 04 9D ?? ?? ?? ?? 89 45 00 85 FF 74 12 8B 07 89 04 9D ?? ?? ?? ?? EB 07 BA 16 00 00 00 EB 02 31 D2 89 D0 83 C4 14 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule svctcp_create_c6204fc8c88148b1ac016100c8713902 {
	meta:
		aliases = "svctcp_create"
		type = "func"
		size = "323"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 5C 24 28 C7 44 24 10 10 00 00 00 31 ED 83 FB FF 75 26 6A 06 6A 01 6A 02 E8 ?? ?? ?? ?? 89 C3 83 C4 0C 66 BD 01 00 85 C0 79 0E 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 F6 EB 6E 31 C0 89 E6 89 E7 AB AB AB AB 66 C7 04 24 02 00 56 53 E8 ?? ?? ?? ?? 5F 5A 85 C0 74 15 66 C7 44 24 02 00 00 FF 74 24 10 56 53 E8 ?? ?? ?? ?? 83 C4 0C 8D 44 24 10 50 56 53 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 0E 6A 02 53 E8 ?? ?? ?? ?? 5A 59 85 C0 74 21 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 31 F6 85 ED 0F 84 91 00 00 00 53 E8 ?? ?? ?? ?? 58 E9 85 00 00 00 6A 08 E8 ?? ?? ?? ?? 89 C7 68 34 01 00 00 E8 ?? ?? ?? ?? 89 }
	condition:
		$pattern
}

rule free_c9bd16e55846271df0cd3ec4500ed606 {
	meta:
		aliases = "free"
		type = "func"
		size = "399"
		objfiles = "free@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 6C 24 28 85 ED 0F 84 74 01 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4D F8 89 CF 8B 51 04 89 D3 83 E3 FC A1 ?? ?? ?? ?? 83 C4 10 39 C3 77 23 83 C8 03 A3 ?? ?? ?? ?? 89 DA C1 EA 03 8B 04 95 ?? ?? ?? ?? 89 41 08 89 0C 95 ?? ?? ?? ?? E9 0C 01 00 00 80 E2 02 0F 85 E6 00 00 00 83 C8 01 A3 ?? ?? ?? ?? 8D 34 19 8B 46 04 89 04 24 F6 41 04 01 75 21 8B 6D F8 89 C8 29 E8 8B 48 08 8B 50 0C 8B 79 0C 39 C7 75 39 39 7A 08 75 34 01 EB 89 51 0C 89 4A 08 8B 0C 24 83 E1 FC 3B 35 ?? ?? ?? ?? 74 50 8B 44 0E 04 83 E0 01 89 4E 04 85 C0 }
	condition:
		$pattern
}

rule bindresvport_69f433838b65feeccd745de58a45f740 {
	meta:
		aliases = "__GI_bindresvport, bindresvport"
		type = "func"
		size = "197"
		objfiles = "bindresvport@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 6C 24 28 8B 5C 24 2C 85 DB 75 17 8D 54 24 04 89 D7 89 D8 AB AB AB AB 66 C7 44 24 04 02 00 89 D3 EB 16 66 83 3B 02 74 10 E8 ?? ?? ?? ?? C7 00 60 00 00 00 83 C8 FF EB 7D 66 83 3D ?? ?? ?? ?? 00 75 1B E8 ?? ?? ?? ?? BA A8 01 00 00 89 D1 99 F7 F9 66 81 C2 58 02 66 89 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 C7 00 62 00 00 00 83 C8 FF 31 FF EB 33 66 A1 ?? ?? ?? ?? 89 C2 66 C1 CA 08 66 89 53 02 40 66 A3 ?? ?? ?? ?? 66 3D FF 03 7E 09 66 C7 05 ?? ?? ?? ?? 58 02 6A 10 53 55 E8 ?? ?? ?? ?? 47 83 C4 0C 81 FF A7 01 00 00 7F 09 85 C0 79 05 83 3E 62 74 BC 83 C4 14 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule re_search_2_37927055d100e14ef1ec9072d573a69f {
	meta:
		aliases = "__GI_re_search_2, re_search_2"
		type = "func"
		size = "530"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 6C 24 28 8B 5C 24 3C 8B 74 24 40 8B 45 10 89 44 24 10 8B 55 14 89 54 24 0C 8B 7C 24 38 03 7C 24 30 89 7C 24 08 85 DB 0F 88 BE 01 00 00 39 FB 0F 8F B6 01 00 00 89 F0 01 D8 79 06 89 DE F7 DE EB 0C 3B 44 24 08 7E 06 8B 74 24 08 29 DE 83 7D 08 00 74 24 85 F6 7E 20 8B 45 00 8A 00 3C 0B 74 0A 3C 09 75 13 80 7D 1C 00 78 0D 85 DB 0F 8F 79 01 00 00 BE 01 00 00 00 83 7C 24 10 00 0F 84 11 01 00 00 F6 45 1C 08 75 10 55 E8 ?? ?? ?? ?? 59 83 F8 FE 0F 84 58 01 00 00 83 7C 24 10 00 0F 84 F0 00 00 00 3B 5C 24 08 0F 8D E6 00 00 00 F6 45 1C 01 0F 85 DC 00 00 00 85 F6 0F 8E 90 00 00 00 3B }
	condition:
		$pattern
}

rule getnetbyname_r_5f98d677cb0812ab689eb6361d25c9b8 {
	meta:
		aliases = "__GI_getnetbyname_r, getnetbyname_r"
		type = "func"
		size = "187"
		objfiles = "getnet@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 6C 24 28 8B 74 24 2C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F BE 05 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 14 EB 29 FF 36 55 E8 ?? ?? ?? ?? 5B 5A 85 C0 74 3B 8B 5E 04 EB 10 50 55 E8 ?? ?? ?? ?? 5A 59 85 C0 74 29 83 C3 04 8B 03 85 C0 75 EA 8D 44 24 10 50 FF 74 24 3C FF 74 24 3C FF 74 24 3C 56 E8 ?? ?? ?? ?? 89 C7 83 C4 14 85 C0 74 B7 80 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 8B 44 24 40 83 38 00 0F 94 C0 0F B6 C0 F7 D8 21 F8 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule getdelim_28d1a8a4af9070c9631b7abcb8d3eb9b {
	meta:
		aliases = "__GI_getdelim, getdelim"
		type = "func"
		size = "241"
		objfiles = "getdelim@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 6C 24 2C 8B 7C 24 34 83 7C 24 28 00 74 08 85 ED 74 04 85 FF 75 13 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CF FF E9 B6 00 00 00 31 C0 83 7F 34 00 0F 94 C0 89 04 24 85 C0 74 1C 8D 5F 38 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 8B 44 24 28 8B 18 85 DB 75 07 C7 45 00 00 00 00 00 BE 01 00 00 00 8B 45 00 39 C6 72 21 83 C0 40 50 53 E8 ?? ?? ?? ?? 5B 5A 85 C0 75 05 83 CF FF EB 44 89 C3 83 45 00 40 8B 44 24 28 89 18 8B 47 10 3B 47 18 73 09 0F B6 10 40 89 47 10 EB 0E 57 E8 ?? ?? ?? ?? 89 C2 59 83 F8 FF 74 0B 46 88 54 1E FE 3B 54 24 30 75 AE 89 F7 83 }
	condition:
		$pattern
}

rule memalign_ec023f5f088ab6c19b9cb2fdfaca2160 {
	meta:
		aliases = "memalign"
		type = "func"
		size = "359"
		objfiles = "memalign@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 74 24 28 8B 5C 24 2C 83 FE 08 77 0E 53 E8 ?? ?? ?? ?? 89 C3 5D E9 3B 01 00 00 83 FE 0F 77 05 BE 10 00 00 00 8D 46 FF BA 10 00 00 00 85 C6 75 04 EB 08 01 D2 39 F2 72 FA 89 D6 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 FB DF 76 12 E8 ?? ?? ?? ?? C7 00 0C 00 00 00 31 DB E9 E3 00 00 00 8D 43 0B C7 04 24 10 00 00 00 83 F8 0F 76 06 83 E0 F8 89 04 24 8B 14 24 8D 44 32 10 50 E8 ?? ?? ?? ?? 89 C5 5F 31 DB 85 C0 0F 84 A6 00 00 00 8D 78 F8 31 D2 F7 F6 85 D2 74 5B 8D 44 35 FF 89 F2 F7 DA 21 D0 8D 58 F8 89 D8 29 F8 83 F8 0F }
	condition:
		$pattern
}

rule setvbuf_4722100226023b8ae72bba6802f44122 {
	meta:
		aliases = "__GI_setvbuf, setvbuf"
		type = "func"
		size = "247"
		objfiles = "setvbuf@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 74 24 28 8B 7C 24 2C 8B 6C 24 34 31 C0 83 7E 34 00 0F 94 C0 89 04 24 85 C0 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 83 7C 24 30 02 76 13 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CB FF E9 80 00 00 00 8B 16 83 CB FF F7 C2 CF 08 00 00 75 73 8B 44 24 30 C1 E0 08 80 E6 FC 09 C2 66 89 16 83 7C 24 30 02 74 04 85 ED 75 08 31 FF 31 ED 31 DB EB 21 31 DB 85 FF 75 1B 8B 46 0C 2B 46 08 39 E8 74 3F 55 E8 ?? ?? ?? ?? 5F 85 C0 74 34 89 C7 66 BB 00 40 8B 06 F6 C4 40 74 0F 80 E4 BF 66 89 06 FF 76 08 E8 ?? ?? ?? ?? 59 66 09 1E 89 7E 08 8D 04 2F }
	condition:
		$pattern
}

rule getprotoent_r_e13874cb9b63493b4e104812a30d9606 {
	meta:
		aliases = "__GI_getprotoent_r, getprotoent_r"
		type = "func"
		size = "239"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 74 24 28 8B 7C 24 30 8B 6C 24 34 C7 44 24 10 00 00 00 00 C7 45 00 00 00 00 00 BB 22 00 00 00 81 FF 2B 01 00 00 0F 86 AB 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 3D ?? ?? ?? ?? 00 75 0E 0F BE 05 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 5B 8B 15 ?? ?? ?? ?? 85 D2 74 56 8B 44 24 2C 89 42 04 C7 42 08 2C 00 00 00 8D 47 D4 89 42 10 68 ?? ?? ?? ?? 68 0A 02 07 00 8D 44 24 18 50 52 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 26 8B 5C 24 10 8B 03 89 06 8B 43 04 83 C3 08 89 5C 24 10 50 E8 ?? ?? ?? ?? 59 89 46 08 89 5E 04 89 75 00 31 }
	condition:
		$pattern
}

rule getservent_r_5d3b7b9fff548678e2c91baeaae919d3 {
	meta:
		aliases = "__GI_getservent_r, getservent_r"
		type = "func"
		size = "259"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 74 24 28 8B 7C 24 30 8B 6C 24 34 C7 44 24 10 00 00 00 00 C7 45 00 00 00 00 00 BB 22 00 00 00 81 FF 2F 01 00 00 0F 86 BF 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 3D ?? ?? ?? ?? 00 75 0E 0F BE 05 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 5B 8B 15 ?? ?? ?? ?? 85 D2 74 6A 8B 44 24 2C 89 42 04 C7 42 08 30 00 00 00 8D 47 D0 89 42 10 68 ?? ?? ?? ?? 68 0B 03 07 00 8D 44 24 18 50 52 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 3A 8B 5C 24 10 8B 03 89 06 8B 53 04 8D 43 08 89 44 24 10 52 E8 ?? ?? ?? ?? 59 66 C1 C8 08 0F B7 C0 89 46 08 }
	condition:
		$pattern
}

rule getnetbyaddr_r_9fbd1344cdbda43f916c1d190055190b {
	meta:
		aliases = "__GI_getnetbyaddr_r, getnetbyaddr_r"
		type = "func"
		size = "157"
		objfiles = "getnet@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 74 24 30 8B 6C 24 3C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F BE 05 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 14 8D 7C 24 10 EB 12 8B 44 24 28 3B 46 0C 75 09 8B 44 24 2C 3B 46 08 74 19 57 55 FF 74 24 40 FF 74 24 40 56 E8 ?? ?? ?? ?? 89 C3 83 C4 14 85 C0 74 D5 80 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 31 C0 83 7D 00 00 0F 94 C0 F7 D8 21 D8 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule exchange_ec4cca30209941bf8ba9a89be4d21a34 {
	meta:
		aliases = "exchange"
		type = "func"
		size = "219"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 89 44 24 04 89 D6 8B 42 14 89 44 24 08 8B 52 18 89 54 24 0C 8B 06 89 44 24 10 E9 87 00 00 00 8B 6C 24 10 2B 6C 24 0C 8B 7C 24 0C 2B 7C 24 08 C7 44 24 14 00 00 00 00 39 FD 7E 61 31 ED 8B 54 24 10 29 FA 89 14 24 EB 20 8B 44 24 08 8D 4C 05 00 8B 54 24 04 8D 0C 8A 8B 19 8B 04 24 01 E8 8D 04 82 8B 10 89 11 89 18 45 39 FD 7C DC 29 7C 24 10 EB 34 8B 4C 24 14 03 4C 24 08 8B 44 24 04 8D 0C 88 8B 19 8B 44 24 14 03 44 24 0C 8B 54 24 04 8D 04 82 8B 10 89 11 89 18 FF 44 24 14 39 6C 24 14 7C D0 01 6C 24 08 8B 44 24 0C 39 44 24 10 7E 0C 8B 54 24 08 39 D0 0F 8F 63 FF FF FF 8B 46 14 03 06 }
	condition:
		$pattern
}

rule authunix_validate_c3383eb93a54945204a74fc94325af7b {
	meta:
		aliases = "authunix_validate"
		type = "func"
		size = "148"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 8B 6C 24 2C 8B 44 24 30 83 38 02 75 73 8B 75 24 6A 01 FF 70 08 FF 70 04 8D 7C 24 0C 57 E8 ?? ?? ?? ?? 8B 46 10 83 C4 10 85 C0 74 0E 50 E8 ?? ?? ?? ?? C7 46 10 00 00 00 00 5B 8D 5E 0C 53 57 E8 ?? ?? ?? ?? 5A 59 85 C0 74 0E 6A 0C 53 55 E8 ?? ?? ?? ?? 83 C4 0C EB 21 C7 04 24 02 00 00 00 53 57 E8 ?? ?? ?? ?? C7 46 10 00 00 00 00 6A 0C 56 55 E8 ?? ?? ?? ?? 83 C4 14 89 E8 E8 ?? ?? ?? ?? B8 01 00 00 00 83 C4 18 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __malloc_consolidate_1ea5bb1fe7edfe63f1f0357023e287b7 {
	meta:
		aliases = "__malloc_consolidate"
		type = "func"
		size = "379"
		objfiles = "free@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 8B 6C 24 2C 8B 45 00 BA 01 00 00 00 85 C0 0F 84 F9 00 00 00 83 E0 FD 89 45 00 8D 55 34 89 54 24 10 C1 E8 03 8D 44 85 FC 89 44 24 08 8D 5D 04 89 5C 24 04 8B 44 24 04 8B 08 85 C9 0F 84 B8 00 00 00 C7 00 00 00 00 00 8B 51 08 89 54 24 0C 8B 41 04 89 C7 83 E7 FE 8D 14 39 8B 5A 04 89 1C 24 A8 01 75 28 8B 01 89 44 24 14 89 C8 2B 44 24 14 8B 70 08 8B 58 0C 8B 4E 0C 39 C1 75 38 39 4B 08 75 33 03 7C 24 14 89 5E 0C 89 73 08 8B 34 24 83 E6 FC 3B 55 2C 74 4B 8B 44 32 04 83 E0 01 89 72 04 85 C0 75 1D 8B 5A 08 8B 42 0C 39 53 0C 75 05 39 50 08 74 05 E8 ?? ?? ?? ?? 01 F7 89 43 0C 89 58 08 }
	condition:
		$pattern
}

rule _uintmaxtostr_735f0c02c075e29258d2db73de0edc73 {
	meta:
		aliases = "_uintmaxtostr"
		type = "func"
		size = "228"
		objfiles = "_uintmaxtostr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 8B 6C 24 2C 8B 4C 24 30 8B 5C 24 34 8B 7C 24 38 85 FF 79 17 F7 DF 85 DB 79 11 F7 D9 83 D3 00 F7 DB C7 44 24 08 01 00 00 00 EB 08 C7 44 24 08 00 00 00 00 C6 45 00 00 83 C8 FF 31 D2 F7 F7 89 44 24 0C 42 89 54 24 10 39 FA 75 0D 40 89 44 24 0C C7 44 24 10 00 00 00 00 89 CE 89 D9 31 DB 89 4C 24 14 83 7C 24 14 00 74 3B 8B 44 24 14 31 D2 F7 F7 89 54 24 04 89 44 24 14 8B 4C 24 10 0F AF CA 89 0C 24 89 F0 31 D2 F7 F7 89 C3 8B 04 24 01 D0 8B 4C 24 04 0F AF 4C 24 0C 01 CB 31 D2 F7 F7 8D 34 03 EB 08 89 F0 31 D2 F7 F7 89 C6 4D 8D 42 30 83 FA 09 76 07 8A 4C 24 3C 8D 04 0A 88 45 00 8B 44 }
	condition:
		$pattern
}

rule lockf64_6515790c518f87941165642e2a45d3d6 {
	meta:
		aliases = "__GI_lockf64, lockf64"
		type = "func"
		size = "253"
		objfiles = "lockf64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 8B 6C 24 2C 8B 74 24 30 8B 4C 24 34 8B 5C 24 38 89 C8 99 39 D3 75 04 39 C9 74 10 E8 ?? ?? ?? ?? C7 00 4B 00 00 00 E9 A9 00 00 00 31 C0 89 E2 89 E7 AB AB AB AB AB AB 66 C7 44 24 02 01 00 C7 44 24 04 00 00 00 00 C7 44 24 08 00 00 00 00 89 4C 24 0C 89 5C 24 10 83 FE 01 74 54 7F 06 85 F6 74 46 EB 66 83 FE 02 74 54 83 FE 03 75 5C 66 C7 04 24 00 00 52 6A 0C 55 E8 ?? ?? ?? ?? 83 C4 0C 83 CA FF 85 C0 78 66 66 83 3C 24 02 74 5D 8B 5C 24 14 E8 ?? ?? ?? ?? 39 C3 74 50 E8 ?? ?? ?? ?? C7 00 0D 00 00 00 EB 2D 66 C7 04 24 02 00 EB 13 66 C7 04 24 01 00 BA 07 00 00 00 EB 1D 66 C7 04 24 01 }
	condition:
		$pattern
}

rule svcudp_recv_e5325d275ab27ad3f6982fe5e09ebe42 {
	meta:
		aliases = "svcudp_recv"
		type = "func"
		size = "495"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 8B 6C 24 2C 8B 7D 30 8D 45 34 89 44 24 04 8D 5D 3C C7 44 24 14 10 00 00 00 8B 54 24 04 89 54 24 0C 89 DE 83 7B 0C 00 8D 55 10 74 4D 8B 45 2C 89 45 34 8B 07 8B 4C 24 0C 89 41 04 89 4B 08 C7 43 0C 01 00 00 00 89 55 3C C7 43 04 10 00 00 00 8D 45 58 89 43 10 C7 43 14 DC 00 00 00 6A 00 53 FF 75 00 E8 ?? ?? ?? ?? 89 C2 83 C4 0C 85 C0 78 23 8B 43 04 89 44 24 14 EB 1A 8D 44 24 14 50 52 6A 00 FF 37 FF 75 2C FF 75 00 E8 ?? ?? ?? ?? 89 C2 83 C4 18 8B 44 24 14 89 45 0C 83 FA FF 75 13 E8 ?? ?? ?? ?? 83 38 04 0F 85 31 01 00 00 E9 5F FF FF FF 83 FA 0F 0F 8E 23 01 00 00 8D 5F 08 C7 47 08 }
	condition:
		$pattern
}

rule __GI_config_read_4aab5a36eb42639ab81f0c0c79b4015c {
	meta:
		aliases = "__GI_config_read"
		type = "func"
		size = "615"
		objfiles = "parse_config@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 8B 74 24 2C 85 F6 0F 84 48 02 00 00 0F B6 44 24 34 89 44 24 10 8B 54 24 34 0F B6 D6 89 54 24 14 C1 E0 02 89 44 24 04 40 89 04 24 83 7E 04 00 75 35 83 7E 10 00 75 07 C7 46 10 51 00 00 00 83 7E 08 00 75 06 8B 04 24 89 46 08 8B 46 08 03 46 10 50 E8 ?? ?? ?? ?? 89 46 04 5F 85 C0 0F 84 F2 01 00 00 80 4E 14 01 8B 46 08 03 46 04 89 46 0C 31 FF FF 36 8B 46 10 29 F8 50 89 F8 03 46 0C 50 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 17 FF 76 10 6A 00 FF 76 0C E8 ?? ?? ?? ?? 31 ED 83 C4 0C E9 B4 01 00 00 8B 5E 0C 8D 04 3B 50 E8 ?? ?? ?? ?? 01 C7 C7 04 24 0A 00 00 00 53 E8 ?? ?? ?? ?? 59 5B 89 C2 }
	condition:
		$pattern
}

rule fseeko64_054c9aa62e71c0988f19961a425a5b32 {
	meta:
		aliases = "__GI_fseeko64, fseeko64"
		type = "func"
		size = "219"
		objfiles = "fseeko64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 8B 74 24 2C 8B 7C 24 38 8B 44 24 30 8B 54 24 34 89 44 24 10 89 54 24 14 83 FF 02 76 13 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CB FF E9 9A 00 00 00 83 7E 34 00 0F 94 C0 0F B6 E8 85 ED 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 F6 06 40 74 0B 56 E8 ?? ?? ?? ?? 5A 85 C0 75 4B 83 FF 01 75 11 8D 44 24 10 50 56 E8 ?? ?? ?? ?? 59 5B 85 C0 78 35 57 8D 44 24 14 50 56 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 78 22 66 83 26 B8 8B 46 08 89 46 10 89 46 14 89 46 18 89 46 1C C7 46 2C 00 00 00 00 C6 46 02 00 31 DB EB 03 83 CB FF 85 ED 74 0E 6A 01 8D 44 24 }
	condition:
		$pattern
}

rule __pgsreader_29539db4b160425b7142c3fb530443c8 {
	meta:
		aliases = "__pgsreader"
		type = "func"
		size = "271"
		objfiles = "__pgsreader@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 8B 74 24 34 8B 7C 24 38 8B 6C 24 3C 81 FF FF 00 00 00 77 15 E8 ?? ?? ?? ?? C7 00 22 00 00 00 BB 22 00 00 00 E9 D5 00 00 00 31 C0 83 7D 34 00 0F 94 C0 89 44 24 04 85 C0 75 0A 31 DB 8D 04 3E 89 04 24 EB 1E 8D 5D 38 53 68 ?? ?? ?? ?? 8D 44 24 10 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 EB D8 55 57 56 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 14 0F B7 45 00 83 E0 04 83 F8 01 19 DB 83 E3 20 83 C3 02 EB 64 56 E8 ?? ?? ?? ?? 59 8D 54 06 FF 80 3A 0A 75 05 C6 02 00 EB 08 40 39 F8 75 03 43 EB C0 85 DB 74 03 4B EB B9 8A 06 84 C0 74 B3 3C 23 74 AF 0F B6 D0 A1 ?? ?? ?? ?? F6 04 50 20 75 A1 }
	condition:
		$pattern
}

rule __wcstofpmax_49f5fa43e6539c2b1fb90fc4e5c5f543 {
	meta:
		aliases = "__wcstofpmax"
		type = "func"
		size = "502"
		objfiles = "__wcstofpmax@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 8B 7C 24 34 8B 5C 24 2C EB 03 83 C3 04 FF 33 E8 ?? ?? ?? ?? 5A 85 C0 75 F1 8B 03 83 F8 2B 74 0D 31 ED 83 F8 2D 75 0B 66 BD 01 00 EB 02 31 ED 83 C3 04 D9 EE 31 C9 83 CA FF EB 2B 81 FA 00 00 00 80 83 DA FF 85 D2 75 05 83 F8 30 74 16 42 83 FA 15 7F 10 D8 0D ?? ?? ?? ?? 83 E8 30 50 DA 04 24 83 C4 04 83 C3 04 A1 ?? ?? ?? ?? 89 44 24 14 8B 03 8B 74 24 14 F6 04 46 08 75 C0 83 F8 2E 75 0B 85 C9 75 07 83 C3 04 89 D9 EB DB 85 D2 79 66 85 C9 75 59 31 F6 31 C9 8D 7E 01 EB 2C 41 80 BC 39 ?? ?? ?? ?? 00 75 21 DD D8 D9 EE 56 DA 3C 24 83 C4 04 85 ED 74 02 D9 E0 0F B6 86 ?? ?? ?? ?? 8D 5C }
	condition:
		$pattern
}

rule __res_init_81ddffd74a8687213e3ff1b85e76eaf0 {
	meta:
		aliases = "__GI___res_init, __res_init"
		type = "func"
		size = "320"
		objfiles = "res_init@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 E8 ?? ?? ?? ?? 89 C3 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 10 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 31 C0 B9 19 00 00 00 89 DF F3 AB C7 03 01 00 00 00 C6 43 52 05 C6 43 53 03 C6 43 51 01 A1 ?? ?? ?? ?? 83 C4 10 B9 07 00 00 00 83 F8 07 77 02 89 C1 31 D2 EB 0D A1 ?? ?? ?? ?? 8B 04 90 89 44 93 34 42 39 CA 7C EF C7 44 24 04 00 00 00 00 C7 04 24 00 00 00 00 31 ED EB 70 6B 74 24 04 1C 89 F2 03 15 ?? ?? ?? ?? 66 83 3A 02 75 23 8B 04 24 C1 E0 04 8D 7C 03 04 6A 10 52 57 E8 ?? ?? ?? ?? 83 C4 0C 83 FD 02 77 05 89 }
	condition:
		$pattern
}

rule dladdr_2f5a2ab94cf93d9c869f1b360d94d1a8 {
	meta:
		aliases = "dladdr"
		type = "func"
		size = "337"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 31 F6 EB 17 8B 50 14 3B 54 24 2C 73 0B 85 F6 74 05 39 56 14 73 02 89 C6 8B 40 0C 85 C0 75 E5 85 F6 0F 84 11 01 00 00 8B 46 04 8B 54 24 30 89 02 8B 46 14 89 42 04 8B 46 58 89 44 24 04 8B 6E 54 C7 44 24 08 00 00 00 00 C7 44 24 0C 00 00 00 00 C7 44 24 10 00 00 00 00 C7 44 24 14 00 00 00 00 E9 88 00 00 00 8B 46 2C 8B 54 24 08 8B 1C 90 EB 74 8B 06 89 04 24 89 D8 C1 E0 04 8B 4C 24 04 01 C1 8B 51 04 66 8B 79 0E 66 85 FF 75 04 85 D2 74 4E 0F B6 41 0C 83 E0 0F 83 F8 06 74 42 03 14 24 39 54 24 2C 72 39 66 85 FF 74 06 83 79 08 00 75 06 39 54 24 2C 74 0B }
	condition:
		$pattern
}

rule hsearch_r_6c2906c6e75daeb18bc52a51a5cf36bf {
	meta:
		aliases = "__GI_hsearch_r, hsearch_r"
		type = "func"
		size = "371"
		objfiles = "hsearch_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 44 24 30 8B 54 24 34 89 54 24 14 89 44 24 10 50 E8 ?? ?? ?? ?? 5A 89 C1 EB 0F 89 C2 C1 E2 04 8B 5C 24 10 0F B6 04 0B 01 D0 49 83 F9 FF 75 EB 8B 54 24 40 8B 52 04 89 54 24 08 31 D2 F7 74 24 08 89 D7 85 D2 75 04 66 BF 01 00 8B 4C 24 40 8B 09 89 4C 24 0C 6B C7 0C 89 CB 01 C3 8B 03 85 C0 0F 84 8A 00 00 00 39 F8 75 1A FF 73 04 FF 74 24 14 E8 ?? ?? ?? ?? 5E 5D 85 C0 75 08 8D 43 04 E9 C1 00 00 00 8B 54 24 08 83 EA 02 89 F8 89 D1 31 D2 F7 F1 8D 6A 01 89 FB 8B 44 24 08 29 E8 89 44 24 04 39 EB 77 06 03 5C 24 04 EB 02 29 EB 39 FB 74 3E 6B C3 0C 8B 74 24 0C 01 C6 8B 16 89 54 24 18 }
	condition:
		$pattern
}

rule _svcauth_unix_7de8cfc0381539abcd8ad2b0ed6d32f0 {
	meta:
		aliases = "_svcauth_unix"
		type = "func"
		size = "383"
		objfiles = "svc_authux@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 44 24 30 8B 78 18 8D 47 18 89 47 04 8D 87 18 01 00 00 89 47 14 8B 54 24 34 8B 52 20 89 14 24 6A 01 52 8B 4C 24 3C FF 71 1C 8D 5C 24 10 53 E8 ?? ?? ?? ?? FF 74 24 10 53 8B 44 24 20 FF 50 18 89 C2 83 C4 18 85 C0 0F 84 92 00 00 00 8B 00 0F C8 89 07 8B 72 04 0F CE 81 FE FF 00 00 00 0F 87 F2 00 00 00 8D 5A 08 56 53 FF 77 04 E8 ?? ?? ?? ?? 8B 47 04 C6 04 30 00 8D 6E 03 83 E5 FC 8D 14 2B 8B 02 0F C8 89 47 08 8B 42 04 0F C8 89 47 0C 8B 4A 08 0F C9 83 C4 0C 83 F9 10 0F 87 B5 00 00 00 8D 5A 0C 89 4F 10 31 F6 EB 0E 8B 03 0F C8 83 C3 04 8B 57 14 89 04 B2 46 39 CE 72 EE 8D 44 8D 14 }
	condition:
		$pattern
}

rule realloc_604f325d1fbbd28bd1e0e9d6ef151268 {
	meta:
		aliases = "realloc"
		type = "func"
		size = "762"
		objfiles = "realloc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 5C 24 34 83 7C 24 30 00 75 0A 53 E8 ?? ?? ?? ?? 89 C3 EB 0D 85 DB 75 0F FF 74 24 30 E8 ?? ?? ?? ?? 58 E9 C1 02 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 14 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 FB DF 76 12 E8 ?? ?? ?? ?? C7 00 0C 00 00 00 31 DB E9 89 02 00 00 8D 43 0B C7 44 24 04 10 00 00 00 83 F8 0F 76 07 83 E0 F8 89 44 24 04 8B 7C 24 30 83 EF 08 8B 57 04 89 D5 83 E5 FC F6 C2 02 0F 85 83 01 00 00 89 EB 3B 6C 24 04 0F 83 23 01 00 00 8D 34 2F 3B 35 ?? ?? ?? ?? 75 3B 8B 46 04 83 E0 FC 8D 0C 28 8B 44 24 04 83 C0 10 39 C1 72 62 83 E2 01 0B 54 24 04 }
	condition:
		$pattern
}

rule svcudp_bufcreate_cbd28a2228f6098467680577ff1d57df {
	meta:
		aliases = "__GI_svcudp_bufcreate, svcudp_bufcreate"
		type = "func"
		size = "454"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 6C 24 30 C7 44 24 18 10 00 00 00 31 F6 83 FD FF 75 24 6A 11 6A 02 6A 02 E8 ?? ?? ?? ?? 89 C5 83 C4 0C 66 BE 01 00 85 C0 79 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 68 31 C0 8D 5C 24 04 89 DF AB AB AB AB 66 C7 44 24 04 02 00 53 55 E8 ?? ?? ?? ?? 5A 59 85 C0 74 15 66 C7 44 24 06 00 00 FF 74 24 18 53 55 E8 ?? ?? ?? ?? 83 C4 0C 8D 44 24 18 50 53 55 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 2E 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F C7 04 24 00 00 00 00 85 F6 0F 84 1B 01 00 00 55 E8 ?? ?? ?? ?? C7 44 24 04 00 00 00 00 5B E9 07 01 00 00 68 34 01 00 00 E8 ?? ?? ?? ?? 89 44 24 04 68 B4 01 00 00 E8 }
	condition:
		$pattern
}

rule __strtofpmax_393a7298f2dfa908bd4276b6411ad44a {
	meta:
		aliases = "__strtofpmax"
		type = "func"
		size = "511"
		objfiles = "__strtofpmax@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 7C 24 38 8B 5C 24 30 EB 01 43 A1 ?? ?? ?? ?? 89 44 24 18 8A 13 0F B6 C2 8B 4C 24 18 F6 04 41 20 75 E7 80 FA 2B 74 15 C7 04 24 00 00 00 00 80 FA 2D 75 11 C7 04 24 01 00 00 00 EB 07 C7 04 24 00 00 00 00 43 D9 EE 31 F6 83 C9 FF EB 2D 81 F9 00 00 00 80 83 D9 FF 85 C9 75 05 80 FA 30 74 1A 41 83 F9 15 7F 14 D8 0D ?? ?? ?? ?? 8B 44 24 08 83 E8 30 50 DA 04 24 83 C4 04 43 8A 13 0F B6 EA 89 6C 24 08 8B 44 24 18 F6 04 68 08 75 C0 80 FA 2E 75 09 85 F6 75 05 43 89 DE EB DF 85 C9 79 65 85 F6 75 58 31 C9 31 D2 8D 71 01 EB 2E 42 80 BC 32 ?? ?? ?? ?? 00 75 23 DD D8 D9 EE 51 DA 3C 24 83 }
	condition:
		$pattern
}

rule sqrt_8ab5a07ae7eb659de4346f0169c4a358 {
	meta:
		aliases = "__GI_sqrt, __ieee754_sqrt, sqrt"
		type = "func"
		size = "452"
		objfiles = "e_sqrt@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C C7 04 24 00 00 00 00 C7 44 24 04 00 00 00 00 DD 44 24 30 DD 54 24 08 8B 54 24 0C 8B 5C 24 08 89 D0 25 00 00 F0 7F 3D 00 00 F0 7F 75 0B D8 C8 DC 44 24 30 E9 75 01 00 00 DD D8 85 D2 7F 20 89 D0 25 FF FF FF 7F 09 D8 0F 84 64 01 00 00 85 D2 74 0D DD 44 24 30 D8 E0 D8 F0 E9 4F 01 00 00 31 C9 89 D7 C1 FF 14 74 0D EB 36 83 E9 15 89 DA C1 EA 0B C1 E3 15 85 D2 74 F1 31 F6 EB 03 01 D2 46 F7 C2 00 00 10 00 74 F5 8D 46 FF 89 CF 29 C7 B9 20 00 00 00 29 F1 89 D8 D3 E8 09 C2 89 F1 D3 E3 81 EF FF 03 00 00 89 7C 24 18 81 E2 FF FF 0F 00 81 CA 00 00 10 00 83 E7 01 74 0A 89 D8 C1 E8 1F 8D 14 }
	condition:
		$pattern
}

rule __add_to_environ_2c5c8e668116a4ed00657ba9e9385ea3 {
	meta:
		aliases = "__add_to_environ"
		type = "func"
		size = "331"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 89 C5 89 54 24 04 89 0C 24 6A 3D 50 E8 ?? ?? ?? ?? 59 5B 89 C7 29 EF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 83 C4 10 C7 44 24 08 00 00 00 00 85 F6 74 32 EB 2A 57 55 53 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 14 80 3C 3B 3D 75 0E 31 DB 83 3C 24 00 0F 84 C1 00 00 00 EB 5F FF 44 24 08 83 C6 04 8B 1E 85 DB 75 D0 8B 74 24 08 C1 E6 02 8D 46 08 50 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 58 5A 85 DB 74 5D A1 ?? ?? ?? ?? 3B 05 ?? ?? ?? ?? 74 0B 56 50 53 E8 ?? ?? ?? ?? 83 C4 0C 89 1D ?? ?? ?? ?? 89 1D ?? ?? ?? ?? 8D 34 33 }
	condition:
		$pattern
}

rule _getopt_internal_a9ce45766f2f49df4b3713fff22c511b {
	meta:
		aliases = "_getopt_internal"
		type = "func"
		size = "1747"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? A1 ?? ?? ?? ?? 89 44 24 0C A3 ?? ?? ?? ?? 8B 4C 24 3C 31 C0 80 39 3A 0F 95 C0 F7 D8 21 44 24 0C 83 7C 24 34 00 0F 8E 68 06 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 85 D2 74 0B 80 3D ?? ?? ?? ?? 00 75 74 EB 0A C7 05 ?? ?? ?? ?? 01 00 00 00 A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 85 C0 0F 95 C0 A2 ?? ?? ?? ?? 8B 4C 24 3C 8A 11 80 FA 2D 75 0E C6 05 ?? ?? ?? ?? 02 41 89 4C 24 3C EB 1A 80 FA 2B 75 0D C6 05 ?? ?? ?? ?? 00 FF 44 24 3C EB 08 83 F0 01 A2 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule inet_pton_38bf8e39c54f468650f4ddf5a0d6d0a7 {
	meta:
		aliases = "__GI_inet_pton, inet_pton"
		type = "func"
		size = "467"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 44 24 34 8B 74 24 38 83 F8 02 74 0B 83 F8 0A 0F 85 A0 01 00 00 EB 10 8B 54 24 3C 89 F0 E8 ?? ?? ?? ?? E9 9C 01 00 00 31 C0 8D 54 24 10 89 D7 AB AB AB AB 80 3E 3A 75 0A 46 80 3E 3A 0F 85 6F 01 00 00 89 74 24 0C 89 54 24 04 C7 04 24 00 00 00 00 31 ED C7 44 24 08 00 00 00 00 E9 CF 00 00 00 46 0F B6 C3 83 C8 20 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 5F 85 C0 74 1B C1 E5 04 2D ?? ?? ?? ?? 09 C5 81 FD FF FF 00 00 0F 86 9A 00 00 00 E9 1E 01 00 00 80 FB 3A 75 5E 83 3C 24 00 75 19 83 7C 24 08 00 0F 85 08 01 00 00 8B 44 24 04 89 44 24 08 89 74 24 0C EB 78 80 3E 00 0F 84 F1 00 00 00 }
	condition:
		$pattern
}

rule fnmatch_db83f20ef4f68d0bc90d3d4d911cb3c8 {
	meta:
		aliases = "__GI_fnmatch, fnmatch"
		type = "func"
		size = "1188"
		objfiles = "fnmatch_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 4C 24 34 8B 7C 24 38 8B 44 24 3C D1 E8 83 F0 01 89 04 24 E9 52 04 00 00 8B 5C 24 3C 83 E3 10 89 5C 24 0C 74 1D 0F B6 C2 A8 80 75 16 8D 1C 00 A1 ?? ?? ?? ?? F6 04 18 01 74 08 A1 ?? ?? ?? ?? 8A 14 18 41 80 FA 3F 74 24 77 0E 80 FA 2A 0F 85 E5 03 00 00 E9 C7 00 00 00 80 FA 5B 0F 84 C0 01 00 00 80 FA 5C 0F 85 CE 03 00 00 EB 49 8A 07 84 C0 0F 84 15 04 00 00 8A 54 24 3C 80 E2 01 74 08 3C 2F 0F 84 04 04 00 00 F6 44 24 3C 04 0F 84 D7 03 00 00 3C 2E 0F 85 CF 03 00 00 3B 7C 24 38 0F 84 E7 03 00 00 84 D2 0F 84 BD 03 00 00 80 7F FF 2F E9 4C 03 00 00 F6 44 24 3C 02 75 2F 8A 11 84 D2 }
	condition:
		$pattern
}

rule __ns_name_ntop_e76d24f74beae7b47923ddaa3d7f8c04 {
	meta:
		aliases = "__GI___ns_name_ntop, __ns_name_ntop"
		type = "func"
		size = "368"
		objfiles = "ns_name@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 4C 24 38 89 CF 03 7C 24 3C 8B 6C 24 34 89 CB E9 04 01 00 00 0F B6 C0 89 44 24 1C A8 C0 0F 85 12 01 00 00 39 CB 75 04 89 CB EB 0C 39 FB 0F 83 02 01 00 00 C6 03 2E 43 8B 54 24 1C 8D 04 13 39 F8 0F 83 EF 00 00 00 45 E9 C1 00 00 00 8A 55 00 80 FA 2E 74 1F 77 0A 80 FA 22 74 18 80 FA 24 EB 0D 80 FA 40 74 0E 80 FA 5C 74 09 80 FA 3B 0F 85 DC 00 00 00 8D 43 01 39 F8 0F 83 B7 00 00 00 C6 03 5C 88 53 01 83 C3 02 EB 7F 8D 43 03 39 F8 0F 83 A1 00 00 00 C6 03 5C 0F B6 D2 66 89 54 24 12 B2 64 66 8B 44 24 12 F6 F2 0F B6 C0 8A 80 ?? ?? ?? ?? 88 43 01 66 8B 44 24 12 31 D2 BE 64 00 00 00 }
	condition:
		$pattern
}

rule _dl_dprintf_30b7c33a4e97df8e77f734e890adc943 {
	meta:
		aliases = "_dl_dprintf"
		type = "func"
		size = "705"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 5C 24 38 85 DB 0F 84 A6 02 00 00 8B 0D ?? ?? ?? ?? C7 44 24 18 00 00 00 00 31 C0 BA 03 00 00 00 BE 22 00 00 00 83 CF FF 53 89 C3 55 8B 6C 24 18 B8 C0 00 00 00 CD 80 5D 5B 3D 00 F0 FF FF 76 0C F7 D8 A3 ?? ?? ?? ?? 83 CD FF EB 07 89 C5 83 F8 FF 75 48 B9 ?? ?? ?? ?? BA 1D 00 00 00 8B 44 24 34 53 89 C3 B8 04 00 00 00 CD 80 5B 89 C2 3D 00 F0 FF FF 76 08 F7 DA 89 15 ?? ?? ?? ?? B9 14 00 00 00 87 CB B8 01 00 00 00 CD 80 87 CB 3D 00 F0 FF FF 76 07 F7 D8 A3 ?? ?? ?? ?? 8D 73 FF 89 F2 42 80 3A 00 75 FA 29 DA A1 ?? ?? ?? ?? 48 39 C2 72 48 B9 ?? ?? ?? ?? BA 0B 00 00 00 8B 44 24 34 }
	condition:
		$pattern
}

rule fclose_d6265bda5517bef4c099e6de8d84d901 {
	meta:
		aliases = "__GI_fclose, fclose"
		type = "func"
		size = "244"
		objfiles = "fclose@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 74 24 34 83 7E 34 00 0F 94 C0 0F B6 E8 85 ED 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 31 FF F6 06 40 74 09 56 E8 ?? ?? ?? ?? 89 C7 58 FF 76 04 E8 ?? ?? ?? ?? 5B 85 C0 79 03 83 CF FF C7 46 04 FF FF FF FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 40 A3 ?? ?? ?? ?? 6A 01 53 E8 ?? ?? ?? ?? 8B 06 66 25 00 60 83 C8 30 66 89 06 83 C4 18 85 ED 74 0E 6A 01 8D 44 24 14 50 E8 ?? ?? ?? ?? 5A 59 F6 46 01 40 74 09 FF 76 08 E8 ?? ?? ?? ?? 58 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 }
	condition:
		$pattern
}

rule _stdio_fopen_ba2baedf2eaae029b9ea3dcf250d2e8d {
	meta:
		aliases = "_stdio_fopen"
		type = "func"
		size = "534"
		objfiles = "_fopen@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 74 24 34 8B 54 24 38 8B 7C 24 3C 8B 6C 24 40 8A 02 3C 72 74 3C BB 41 02 00 00 3C 77 74 35 66 BB 41 04 3C 61 74 2D E8 ?? ?? ?? ?? C7 00 16 00 00 00 85 FF 0F 84 C9 01 00 00 F6 47 01 20 0F 84 BF 01 00 00 57 E8 ?? ?? ?? ?? 31 FF 58 E9 B3 01 00 00 31 DB 8D 42 01 80 7A 01 62 74 02 89 D0 80 78 01 2B 75 08 89 D8 83 C8 01 8D 58 01 85 FF 75 28 6A 50 E8 ?? ?? ?? ?? 89 C7 58 85 FF 0F 84 82 01 00 00 66 C7 07 00 20 C7 47 08 00 00 00 00 8D 47 38 50 E8 ?? ?? ?? ?? 58 85 ED 78 48 89 6F 04 89 DA 81 E2 03 80 00 00 42 8D 46 01 21 D0 39 D0 0F 85 71 FF FF FF 89 F0 F7 D0 25 00 04 00 00 85 C3 }
	condition:
		$pattern
}

rule freopen64_47193ec7e9f53bea462badede795b469 {
	meta:
		aliases = "freopen64"
		type = "func"
		size = "243"
		objfiles = "freopen64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 74 24 3C 83 7E 34 00 0F 94 C0 0F B6 E8 85 ED 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 7C 24 08 57 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 40 A3 ?? ?? ?? ?? 6A 01 57 E8 ?? ?? ?? ?? 8B 1E 89 D8 80 E4 9F 66 89 06 83 E0 30 83 C4 18 83 F8 30 74 31 56 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 0D ?? ?? ?? ?? 6A 01 57 E8 ?? ?? ?? ?? 83 C4 1C 6A FE 56 FF 74 24 40 FF 74 24 40 E8 ?? ?? ?? ?? 89 C7 83 C4 10 85 C0 75 05 66 C7 06 }
	condition:
		$pattern
}

rule freopen_2188db867f818823355c2f315d6a4bb9 {
	meta:
		aliases = "freopen"
		type = "func"
		size = "243"
		objfiles = "freopen@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 74 24 3C 83 7E 34 00 0F 94 C0 0F B6 E8 85 ED 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 7C 24 08 57 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 40 A3 ?? ?? ?? ?? 6A 01 57 E8 ?? ?? ?? ?? 8B 1E 89 D8 80 E4 9F 66 89 06 83 E0 30 83 C4 18 83 F8 30 74 31 56 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 0D ?? ?? ?? ?? 6A 01 57 E8 ?? ?? ?? ?? 83 C4 1C 6A FF 56 FF 74 24 40 FF 74 24 40 E8 ?? ?? ?? ?? 89 C7 83 C4 10 85 C0 75 05 66 C7 06 }
	condition:
		$pattern
}

rule llround_d31f96c0a4bb9cbaa3d035debaffda5d {
	meta:
		aliases = "__GI_llround, llround"
		type = "func"
		size = "329"
		objfiles = "s_llround@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 DD 44 24 34 DD 5C 24 08 8B 44 24 0C 8B 7C 24 08 89 C5 C1 ED 14 81 E5 FF 07 00 00 8D 9D 01 FC FF FF 99 83 CA 01 89 54 24 10 89 C2 81 E2 FF FF 0F 00 81 CA 00 00 10 00 83 FB 13 7F 35 85 DB 79 19 31 F6 31 FF 43 0F 85 EB 00 00 00 8B 44 24 10 99 89 C6 89 D7 E9 DD 00 00 00 B8 00 00 08 00 88 D9 D3 F8 01 D0 B9 14 00 00 00 29 D9 D3 E8 89 C6 EB 4F 83 FB 3E 7F 73 83 FB 33 7E 29 89 D1 31 DB 89 CB B9 00 00 00 00 89 C8 09 F8 89 C6 89 DF 8D 8D CD FB FF FF 0F A5 F7 D3 E6 F6 C1 20 74 76 89 F7 31 F6 EB 70 8D 8D ED FB FF FF B8 00 00 00 80 D3 E8 8D 34 38 39 FE 83 D2 00 83 FB 14 75 06 89 D6 31 }
	condition:
		$pattern
}

rule __res_search_3f30bc2c2b38524db506b15937fe1f41 {
	meta:
		aliases = "__res_search"
		type = "func"
		size = "528"
		objfiles = "res_query@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 24 83 7C 24 38 00 74 0B 8D 5C 24 14 83 7C 24 44 00 75 10 E8 ?? ?? ?? ?? C7 00 FF FF FF FF E9 CC 01 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 44 24 10 8B 28 0F B6 40 51 89 44 24 1C 6A 01 53 E8 ?? ?? ?? ?? 83 C4 18 F7 C5 01 00 00 00 75 07 E8 ?? ?? ?? ?? EB B9 E8 ?? ?? ?? ?? 89 44 24 04 C7 00 00 00 00 00 E8 ?? ?? ?? ?? 89 C3 C7 00 01 00 00 00 8B 54 24 38 31 FF EB 0B 3C 2E 0F 94 C0 0F B6 C0 01 C7 42 8A 02 84 C0 75 EF 31 F6 3B 54 24 38 76 0A 80 7A FF 2E 0F 94 C0 0F B6 F0 C7 44 24 08 FF FF FF FF 3B 7C 24 0C 72 2F FF 74 24 }
	condition:
		$pattern
}

rule inet_ntop4_4039353bc94b72cd81d30b99110c128f {
	meta:
		aliases = "inet_ntop4"
		type = "func"
		size = "231"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 24 89 44 24 08 89 54 24 04 89 0C 24 C6 44 24 13 00 31 ED 31 F6 E9 86 00 00 00 8B 44 24 08 01 E8 89 44 24 0C 0F B6 10 B1 64 89 D0 F6 F1 88 C1 8D 41 30 88 44 34 13 8D 7E 01 89 F3 3C 30 75 23 B1 0A 89 D0 F6 F1 0F B6 C0 B9 0A 00 00 00 31 D2 66 F7 F1 83 C2 30 88 54 34 13 80 FA 30 74 21 89 FB EB 1D B1 0A 89 D0 F6 F1 0F B6 C0 B9 0A 00 00 00 31 D2 66 F7 F1 83 C2 30 88 54 3C 13 8D 5E 02 8B 54 24 0C 0F B6 02 B9 0A 00 00 00 31 D2 66 F7 F1 83 C2 30 88 54 1C 13 C6 44 1C 14 2E 8D 73 02 45 83 FD 03 0F 8E 71 FF FF FF C6 44 34 12 00 8D 5C 24 13 53 E8 ?? ?? ?? ?? 59 3B 04 24 76 0F E8 ?? ?? ?? }
	condition:
		$pattern
}

rule tcsetattr_e2367f4caa97d4b0af6457852e4f1f69 {
	meta:
		aliases = "__GI_tcsetattr, tcsetattr"
		type = "func"
		size = "248"
		objfiles = "tcsetattr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 24 8B 44 24 3C 8B 5C 24 40 83 F8 01 74 10 83 F8 02 74 22 BD 02 54 00 00 85 C0 74 1E EB 07 BD 03 54 00 00 EB 15 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 AC 00 00 00 BD 04 54 00 00 8B 03 25 FF FF FF 7F 89 04 24 8B 43 04 89 44 24 04 8B 43 08 89 44 24 08 8B 43 0C 89 44 24 0C 8A 43 10 88 44 24 10 8D 73 11 8D 7C 24 11 A5 A5 A5 A5 66 A5 A4 8D 04 24 50 55 FF 74 24 40 E8 ?? ?? ?? ?? 89 C6 83 C4 0C 85 C0 75 63 81 FD 02 54 00 00 75 5B E8 ?? ?? ?? ?? 89 C7 8B 28 8D 04 24 50 68 01 54 00 00 FF 74 24 40 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 04 89 2F EB 35 8B 4B 08 8B 74 24 08 89 CA 81 E2 80 01 00 00 }
	condition:
		$pattern
}

rule memcmp_a493628e52c272244c2cb8b5e245501b {
	meta:
		aliases = "__GI_memcmp, bcmp, memcmp"
		type = "func"
		size = "679"
		objfiles = "memcmp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 24 8B 5C 24 38 8B 44 24 3C 89 04 24 83 7C 24 40 0F 77 20 E9 78 02 00 00 0F B6 13 8B 0C 24 0F B6 01 29 C2 89 D0 0F 85 6E 02 00 00 43 FF 04 24 FF 4C 24 40 8B 04 24 89 44 24 04 A8 03 75 DA 89 5C 24 08 89 D8 83 E0 03 0F 85 AD 00 00 00 8B 7C 24 40 C1 EF 02 89 F8 83 E0 03 83 F8 01 74 33 72 28 83 F8 03 8B 03 8B 0C 24 8B 11 74 0E 83 EB 08 83 E9 08 89 0C 24 83 C7 02 EB 4D 89 C5 89 D6 83 EB 04 83 2C 24 04 47 EB 32 8B 03 8B 0C 24 8B 11 EB 1C 8B 2B 8B 04 24 8B 30 83 C3 04 83 C0 04 89 04 24 4F 8B 03 8B 0C 24 8B 11 39 F5 75 3F 8B 6B 04 8B 0C 24 8B 71 04 39 D0 75 36 8B 43 08 8B 0C 24 8B 51 }
	condition:
		$pattern
}

rule rtime_c007a86eb49b48f5e65a30629d6fc44d {
	meta:
		aliases = "__GI_rtime, rtime"
		type = "func"
		size = "346"
		objfiles = "rtime@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 24 8B 7C 24 38 8B 6C 24 40 83 FD 01 19 DB 83 C3 02 6A 00 53 6A 02 E8 ?? ?? ?? ?? 89 C6 83 C4 0C 85 C0 0F 88 21 01 00 00 66 C7 07 02 00 66 C7 47 02 00 25 83 FB 02 0F 85 A5 00 00 00 6A 10 57 6A 00 6A 04 8D 44 24 30 50 56 E8 ?? ?? ?? ?? 83 C4 18 85 C0 0F 88 98 00 00 00 8B 4D 04 BB E8 03 00 00 89 C8 31 D2 F7 F3 89 C1 69 45 00 E8 03 00 00 8D 3C 01 89 74 24 14 66 C7 44 24 18 01 00 8D 6C 24 14 57 6A 01 55 E8 ?? ?? ?? ?? 89 C3 83 C4 0C 85 C0 79 0A E8 ?? ?? ?? ?? 83 38 04 74 E4 83 FB 00 7F 0F 75 4C E8 ?? ?? ?? ?? C7 00 6E 00 00 00 EB 3F C7 44 24 1C 10 00 00 00 8D 44 24 04 8D 54 24 1C }
	condition:
		$pattern
}

rule _stdlib_strto_ll_bacfe8c9f42135c13230728d142f3dc9 {
	meta:
		aliases = "_stdlib_strto_ll"
		type = "func"
		size = "531"
		objfiles = "_stdlib_strto_ll@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 28 8B 5C 24 3C 8B 6C 24 44 89 DF EB 01 47 8A 0F 0F B6 D1 A1 ?? ?? ?? ?? F6 04 50 20 75 EF 80 F9 2B 74 11 C6 44 24 27 00 80 F9 2D 75 0D C6 44 24 27 01 EB 05 C6 44 24 27 00 47 89 D9 F7 C5 EF FF FF FF 75 24 83 C5 0A 80 3F 30 75 12 47 83 ED 02 8A 07 83 C8 20 89 F9 3C 78 75 03 01 ED 47 83 FD 10 7E 05 BD 10 00 00 00 8D 45 FE C7 44 24 18 00 00 00 00 C7 44 24 1C 00 00 00 00 83 F8 22 0F 87 1A 01 00 00 89 6C 24 10 89 E8 C1 F8 1F 89 44 24 14 EB 02 89 F9 8A 17 8D 42 D0 3C 09 76 0D 83 CA 20 B0 28 80 FA 60 76 03 8D 42 A9 0F B6 F0 39 EE 0F 8D E8 00 00 00 47 81 7C 24 1C FF FF FF 03 77 3C 89 }
	condition:
		$pattern
}

rule _stdlib_wcsto_ll_87fe45577b59944bcab05f332e4481fc {
	meta:
		aliases = "_stdlib_wcsto_ll"
		type = "func"
		size = "551"
		objfiles = "_stdlib_wcsto_ll@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 28 8B 5C 24 3C 8B 6C 24 44 89 DF EB 03 83 C7 04 FF 37 E8 ?? ?? ?? ?? 5A 85 C0 75 F1 8B 07 83 F8 2B 74 11 C6 44 24 27 00 83 F8 2D 75 0F C6 44 24 27 01 EB 05 C6 44 24 27 00 83 C7 04 89 DA F7 C5 EF FF FF FF 75 29 83 C5 0A 83 3F 30 75 17 83 C7 04 83 ED 02 8B 07 83 C8 20 89 FA 83 F8 78 75 05 01 ED 83 C7 04 83 FD 10 7E 05 BD 10 00 00 00 8D 45 FE C7 44 24 18 00 00 00 00 C7 44 24 1C 00 00 00 00 83 F8 22 0F 87 27 01 00 00 89 6C 24 10 89 E8 C1 F8 1F 89 44 24 14 EB 02 89 FA 8B 1F 8D 43 D0 8D 4B D0 83 F8 09 76 14 89 D8 83 C8 20 B1 28 83 F8 60 76 08 88 D8 83 C8 20 8D 48 A9 0F B6 F1 39 EE }
	condition:
		$pattern
}

rule mallinfo_75ec96a606a94ec3814f71e2390a6d49 {
	meta:
		aliases = "__GI_mallinfo, mallinfo"
		type = "func"
		size = "309"
		objfiles = "mallinfo@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 28 8B 7C 24 3C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 20 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 3D ?? ?? ?? ?? 00 75 0B 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 A1 ?? ?? ?? ?? 8B 40 04 89 04 24 31 C9 C7 44 24 04 00 00 00 00 C7 44 24 0C 00 00 00 00 EB 1F 8B 14 8D ?? ?? ?? ?? EB 11 FF 44 24 0C 8B 42 04 83 E0 FC 01 44 24 04 8B 52 08 85 D2 75 EB 41 83 F9 09 76 DC 8B 04 24 83 E0 FC 8B 6C 24 04 01 C5 BB 01 00 00 00 C7 44 24 08 01 00 00 00 EB 20 8D 0C DD ?? ?? ?? ?? 8B 51 0C EB 0F FF 44 24 08 8B 42 04 83 E0 FC 01 C5 8B 52 0C 39 CA 75 ED 43 83 FB 5F 76 DB 8B 1D ?? ?? ?? }
	condition:
		$pattern
}

rule nextafter_6a8187cabd4ac5229a4dd944cd260fad {
	meta:
		aliases = "__GI_nextafter, nextafter"
		type = "func"
		size = "378"
		objfiles = "s_nextafter@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 28 C7 44 24 10 00 00 00 00 C7 44 24 14 00 00 00 00 C7 44 24 08 00 00 00 00 C7 44 24 0C 00 00 00 00 C7 04 24 00 00 00 00 C7 44 24 04 00 00 00 00 DD 44 24 3C DD 5C 24 20 8B 54 24 24 8B 4C 24 20 DD 44 24 44 DD 5C 24 18 8B 6C 24 1C 8B 7C 24 18 89 D6 81 E6 FF FF FF 7F 81 FE FF FF EF 7F 7E 0A 8D 86 00 00 10 80 09 C8 75 1B 8B 5C 24 1C 89 D8 25 FF FF FF 7F 3D FF FF EF 7F 7E 16 2D 00 00 F0 7F 09 F8 74 0D DD 44 24 3C DC 44 24 44 E9 CE 00 00 00 DD 44 24 3C DD 44 24 44 D9 C9 DA E9 DF E0 9E 7A 06 0F 84 BF 00 00 00 09 CE 75 37 81 E5 00 00 00 80 89 6C 24 14 C7 44 24 10 01 00 00 00 DD 44 24 }
	condition:
		$pattern
}

rule lrint_0eb3a3397a28999c63cd454146012ac5 {
	meta:
		aliases = "__GI_lrint, lrint"
		type = "func"
		size = "270"
		objfiles = "s_lrint@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 28 DD 44 24 3C DD 5C 24 10 8B 44 24 14 C1 E8 14 89 C2 81 E2 FF 07 00 00 81 EA FF 03 00 00 89 C5 C1 ED 0B 83 FA 13 7F 4C 31 DB 42 0F 8C CD 00 00 00 DD 04 ED ?? ?? ?? ?? DD 44 24 3C D8 C1 DD 5C 24 20 DD 44 24 20 DE E1 DD 5C 24 08 8B 44 24 0C 89 C3 81 E3 FF FF 0F 00 81 CB 00 00 10 00 C1 E8 14 25 FF 07 00 00 B9 13 04 00 00 29 C1 D3 EB E9 84 00 00 00 83 FA 1E 7F 58 DD 04 ED ?? ?? ?? ?? DD 44 24 3C D8 C1 DD 5C 24 20 DD 44 24 20 DE E1 DD 1C 24 8B 44 24 04 8B 34 24 89 C2 C1 EA 14 81 E2 FF 07 00 00 8D BA 01 FC FF FF 25 FF FF 0F 00 0D 00 00 10 00 89 C3 83 FF 14 74 3C 8D 8A ED FB FF FF }
	condition:
		$pattern
}

rule des_setkey_6da3ee1e88ad8977e5075f853e3881fe {
	meta:
		aliases = "des_setkey"
		type = "func"
		size = "638"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 89 C3 E8 ?? ?? ?? ?? 8B 13 0F CA 8B 43 04 0F C8 89 C1 09 D1 74 14 3B 15 ?? ?? ?? ?? 75 0C 3B 05 ?? ?? ?? ?? 0F 84 45 02 00 00 89 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 89 D5 C1 ED 19 89 6C 24 04 89 D1 C1 E9 11 83 E1 7F 89 4C 24 08 89 D1 C1 E9 09 83 E1 7F 89 D6 D1 EE 83 E6 7F 89 C5 C1 ED 19 89 6C 24 0C 89 C3 C1 EB 11 83 E3 7F 89 C2 C1 EA 09 83 E2 7F D1 E8 83 E0 7F 8B 3C 8D ?? ?? ?? ?? 8B 6C 24 08 0B 3C AD ?? ?? ?? ?? 8B 6C 24 04 0B 3C AD ?? ?? ?? ?? 0B 3C B5 ?? ?? ?? ?? 8B 6C 24 0C 0B 3C AD ?? ?? ?? ?? 0B 3C 9D ?? ?? ?? ?? 0B 3C 95 ?? ?? ?? ?? 0B 3C 85 ?? ?? ?? ?? 8B 2C 8D ?? ?? ?? }
	condition:
		$pattern
}

rule remainder_9b7e963d6d8f0cd0936e1d4c9b1a8f40 {
	meta:
		aliases = "__GI_remainder, __ieee754_remainder, drem, remainder"
		type = "func"
		size = "343"
		objfiles = "e_remainder@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C DD 44 24 40 DD 5C 24 18 8B 44 24 1C 89 44 24 20 8B 6C 24 18 DD 44 24 48 DD 5C 24 10 8B 7C 24 10 8B 74 24 14 81 E6 FF FF FF 7F 89 F0 09 F8 74 24 8B 5C 24 20 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7F 12 81 FE FF FF EF 7F 7E 19 8D 86 00 00 10 80 09 F8 74 37 DD 44 24 40 DC 4C 24 48 D8 F0 E9 E5 00 00 00 81 FE FF FF DF 7F 7F 20 DD 44 24 48 D8 C0 83 EC 08 DD 1C 24 FF 74 24 4C FF 74 24 4C E8 ?? ?? ?? ?? DD 5C 24 50 83 C4 10 29 F3 29 FD 09 EB 75 0F DD 44 24 40 DC 0D ?? ?? ?? ?? E9 A6 00 00 00 FF 74 24 44 FF 74 24 44 E8 ?? ?? ?? ?? 59 5B DD 5C 24 24 FF 74 24 4C FF 74 24 4C E8 ?? ?? ?? }
	condition:
		$pattern
}

rule do_des_c08c16ff769b24d21b7c0f7373ccaee3 {
	meta:
		aliases = "do_des"
		type = "func"
		size = "777"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 30 89 D5 89 4C 24 04 BA 01 00 00 00 83 7C 24 48 00 0F 84 E2 02 00 00 7E 12 C7 44 24 24 ?? ?? ?? ?? C7 44 24 28 ?? ?? ?? ?? EB 14 F7 5C 24 48 C7 44 24 24 ?? ?? ?? ?? C7 44 24 28 ?? ?? ?? ?? 89 C2 C1 EA 18 89 54 24 08 89 C2 C1 EA 10 81 E2 FF 00 00 00 0F B6 CC 89 4C 24 0C 25 FF 00 00 00 89 44 24 10 89 EE C1 EE 18 89 E8 C1 E8 10 25 FF 00 00 00 89 04 24 89 EB 0F B6 FF 89 E9 81 E1 FF 00 00 00 8B 44 24 08 8B 2C 85 ?? ?? ?? ?? 8B 5C 24 10 0B 2C 9D ?? ?? ?? ?? 0B 2C 95 ?? ?? ?? ?? 8B 44 24 0C 0B 2C 85 ?? ?? ?? ?? 0B 2C B5 ?? ?? ?? ?? 0B 2C 8D ?? ?? ?? ?? 8B 1C 24 0B 2C 9D ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clnttcp_create_c8b367c2de8d8cd4921b46f3d9d833b9 {
	meta:
		aliases = "__GI_clnttcp_create, clnttcp_create"
		type = "func"
		size = "461"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 30 8B 5C 24 44 8B 6C 24 50 6A 0C E8 ?? ?? ?? ?? 89 C7 6A 64 E8 ?? ?? ?? ?? 89 C6 58 5A 85 FF 74 04 85 F6 75 2B E8 ?? ?? ?? ?? 89 C3 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 03 0C 00 00 00 C7 43 08 0C 00 00 00 5B 5D E9 5D 01 00 00 66 83 7B 02 00 75 24 6A 06 FF 74 24 50 FF 74 24 50 53 E8 ?? ?? ?? ?? 83 C4 10 66 85 C0 0F 84 3A 01 00 00 66 C1 C8 08 66 89 43 02 83 7D 00 00 79 61 6A 06 6A 01 6A 02 E8 ?? ?? ?? ?? 89 45 00 6A 00 50 E8 ?? ?? ?? ?? 8B 45 00 83 C4 14 85 C0 78 10 6A 10 53 50 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 79 28 E8 ?? ?? ?? ?? 89 C3 C7 00 0C 00 00 00 E8 ?? ?? ?? }
	condition:
		$pattern
}

rule clntunix_create_86ddb257ec44567192d38173f0fa4643 {
	meta:
		aliases = "__GI_clntunix_create, clntunix_create"
		type = "func"
		size = "450"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 30 8B 6C 24 44 68 C4 00 00 00 E8 ?? ?? ?? ?? 89 C6 6A 0C E8 ?? ?? ?? ?? 89 C7 58 5A 85 FF 74 04 85 F6 75 2B E8 ?? ?? ?? ?? 89 C3 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 03 0C 00 00 00 C7 43 08 0C 00 00 00 5B 5D E9 53 01 00 00 8B 44 24 50 83 38 00 79 6A 6A 00 6A 01 6A 01 E8 ?? ?? ?? ?? 89 C3 8B 54 24 5C 89 02 8D 45 02 50 E8 ?? ?? ?? ?? 83 C4 10 85 DB 78 12 83 C0 03 50 55 53 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 79 2C E8 ?? ?? ?? ?? 89 C3 C7 00 0C 00 00 00 E8 ?? ?? ?? ?? 8B 00 89 43 08 8B 54 24 50 8B 02 83 F8 FF 0F 84 EF 00 00 00 50 E9 90 00 00 00 C7 46 04 01 00 00 00 EB 07 }
	condition:
		$pattern
}

rule regexec_fa68e1eb47fa1019aedb6b86866c7304 {
	meta:
		aliases = "__GI_regexec, regexec"
		type = "func"
		size = "260"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 30 8B 74 24 44 8B 6C 24 4C 8B 5C 24 54 FF 74 24 48 E8 ?? ?? ?? ?? 5F 89 04 24 8A 46 1C 83 F0 10 C0 E8 04 85 ED 0F 95 C2 89 D7 21 C7 6A 20 56 8D 44 24 0C 50 E8 ?? ?? ?? ?? 88 DA 83 E2 01 C1 E2 05 8A 44 24 2C 83 E0 9F D1 EB 83 E3 01 C1 E3 06 09 D0 09 D8 83 E0 F9 83 C8 04 88 44 24 2C 83 C4 0C 31 C0 89 FA 84 D2 74 2A 89 6C 24 24 8D 04 ED 00 00 00 00 50 E8 ?? ?? ?? ?? 5E BA 01 00 00 00 85 C0 74 70 89 44 24 28 8D 04 A8 89 44 24 2C 8D 44 24 24 50 FF 74 24 04 6A 00 FF 74 24 0C FF 74 24 58 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 C6 83 C4 18 89 F8 84 C0 74 38 31 DB 85 F6 79 24 EB 26 8B 54 24 }
	condition:
		$pattern
}

rule fmod_249a1f99426ab1ef9f347dab3822962f {
	meta:
		aliases = "__GI_fmod, __ieee754_fmod, fmod"
		type = "func"
		size = "786"
		objfiles = "e_fmod@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 30 C7 44 24 08 00 00 00 00 C7 44 24 0C 00 00 00 00 C7 04 24 00 00 00 00 C7 44 24 04 00 00 00 00 DD 44 24 44 DD 5C 24 18 8B 7C 24 18 DD 44 24 4C DD 5C 24 10 8B 44 24 10 89 44 24 2C 8B 4C 24 1C 81 E1 00 00 00 80 89 4C 24 28 8B 54 24 1C 81 E2 FF FF FF 7F 8B 6C 24 14 81 E5 FF FF FF 7F 09 E8 74 1E 81 FA FF FF EF 7F 7F 16 8B 44 24 2C F7 D8 0B 44 24 2C C1 E8 1F 09 E8 3D 00 00 F0 7F 76 0F DD 44 24 44 DC 4C 24 4C D8 F0 E9 6D 02 00 00 39 EA 7F 27 0F 8C 67 02 00 00 3B 7C 24 2C 0F 82 5D 02 00 00 75 15 C1 6C 24 28 1F 8B 44 24 28 DD 04 C5 ?? ?? ?? ?? E9 42 02 00 00 81 FA FF FF 0F 00 7F 37 }
	condition:
		$pattern
}

rule malloc_980d1a717bb6136370528ff09cf7bed5 {
	meta:
		aliases = "malloc"
		type = "func"
		size = "1926"
		objfiles = "malloc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 34 8B 5C 24 48 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 2C 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 FB DF 76 12 E8 ?? ?? ?? ?? C7 00 0C 00 00 00 31 DB E9 39 07 00 00 8D 43 0B C7 44 24 08 10 00 00 00 83 F8 0F 76 07 83 E0 F8 89 44 24 08 8B 1D ?? ?? ?? ?? F6 C3 01 75 18 85 DB 0F 85 59 03 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5D E9 49 03 00 00 39 5C 24 08 77 1E 8B 4C 24 08 C1 E9 03 8B 14 8D ?? ?? ?? ?? 85 D2 74 0C 8B 42 08 89 04 8D ?? ?? ?? ?? EB 35 81 7C 24 08 FF 00 00 00 77 33 8B 6C 24 08 C1 ED 03 8D 0C ED ?? ?? ?? ?? 8B 51 0C 39 CA 0F 84 69 01 00 00 8B 42 0C 8B }
	condition:
		$pattern
}

rule llrint_34cb6bc48114a314dfeb0d4aa8cdc576 {
	meta:
		aliases = "__GI_llrint, llrint"
		type = "func"
		size = "401"
		objfiles = "s_llrint@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 34 DD 44 24 48 DD 5C 24 14 8B 44 24 18 8B 74 24 14 89 C2 C1 EA 14 81 E2 FF 07 00 00 89 14 24 81 EA FF 03 00 00 89 C1 C1 E9 1F 89 4C 24 1C 83 FA 13 7F 54 DD 04 CD ?? ?? ?? ?? DD 44 24 48 D8 C1 DD 5C 24 2C DD 44 24 2C DE E1 DD 5C 24 0C 8B 54 24 10 89 D0 C1 E8 14 25 FF 07 00 00 31 FF 31 ED 2D FF 03 00 00 0F 88 06 01 00 00 81 E2 FF FF 0F 00 81 CA 00 00 10 00 B9 14 00 00 00 29 C1 D3 EA 89 D7 E9 94 00 00 00 83 FA 3E 0F 8F B6 00 00 00 83 FA 33 7E 3D 25 FF FF 0F 00 0D 00 00 10 00 89 C1 31 DB 89 CB B9 00 00 00 00 89 C8 09 F0 89 C7 89 DD 8B 0C 24 81 E9 33 04 00 00 0F A5 FD D3 E7 F6 C1 }
	condition:
		$pattern
}

rule clntudp_bufcreate_71f28e9ae28fffa6840e75e9cc7a3f92 {
	meta:
		aliases = "__GI_clntudp_bufcreate, clntudp_bufcreate"
		type = "func"
		size = "517"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 38 6A 0C E8 ?? ?? ?? ?? 89 C5 8B 7C 24 68 83 C7 03 83 E7 FC 8B 5C 24 6C 83 C3 03 83 E3 FC 8D 44 1F 64 50 E8 ?? ?? ?? ?? 89 C6 58 5A 85 ED 74 04 85 F6 75 2B E8 ?? ?? ?? ?? 89 C3 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 03 0C 00 00 00 C7 43 08 0C 00 00 00 5B 5F E9 7E 01 00 00 8D 44 33 60 89 46 58 8B 44 24 4C 66 83 78 02 00 75 28 6A 11 FF 74 24 58 FF 74 24 58 50 E8 ?? ?? ?? ?? 83 C4 10 66 85 C0 0F 84 50 01 00 00 66 C1 C8 08 8B 54 24 4C 66 89 42 02 C7 45 04 ?? ?? ?? ?? 89 75 08 8D 46 08 6A 10 FF 74 24 50 50 E8 ?? ?? ?? ?? C7 46 18 10 00 00 00 8B 44 24 68 89 46 20 8B 54 }
	condition:
		$pattern
}

rule writeunix_141641d7504be12be5736ad2c310582e {
	meta:
		aliases = "writeunix"
		type = "func"
		size = "249"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 38 8B 6C 24 50 8B 5C 24 54 8D 44 24 24 89 04 24 E9 CA 00 00 00 8B 54 24 4C 8B 12 89 54 24 04 E8 ?? ?? ?? ?? 89 44 24 24 E8 ?? ?? ?? ?? 89 44 24 28 E8 ?? ?? ?? ?? 89 44 24 2C BF ?? ?? ?? ?? 8B 34 24 A5 A5 A5 C7 05 ?? ?? ?? ?? 01 00 00 00 C7 05 ?? ?? ?? ?? 02 00 00 00 C7 05 ?? ?? ?? ?? 18 00 00 00 89 6C 24 30 89 5C 24 34 8D 44 24 30 89 44 24 10 C7 44 24 14 01 00 00 00 C7 44 24 08 00 00 00 00 C7 44 24 0C 00 00 00 00 C7 44 24 18 ?? ?? ?? ?? C7 44 24 1C 18 00 00 00 C7 44 24 20 00 00 00 00 8D 74 24 08 6A 00 56 FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C 85 C0 79 21 E8 ?? ?? ?? ?? 83 38 04 }
	condition:
		$pattern
}

rule gethostbyname_r_41ee15139029d7e66e2989b91bc8807e {
	meta:
		aliases = "__GI_gethostbyname_r, gethostbyname_r"
		type = "func"
		size = "666"
		objfiles = "gethostbyname_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 38 8B 6C 24 58 8B 44 24 5C C7 00 00 00 00 00 BE 16 00 00 00 83 7C 24 4C 00 0F 84 6B 02 00 00 E8 ?? ?? ?? ?? 89 C3 8B 38 C7 00 00 00 00 00 FF 74 24 60 FF 74 24 60 55 FF 74 24 60 FF 74 24 60 6A 02 FF 74 24 64 E8 ?? ?? ?? ?? 89 C6 83 C4 1C 85 C0 75 07 89 3B E9 30 02 00 00 8B 54 24 60 8B 02 83 F8 01 74 0E 83 F8 04 74 1F 40 0F 85 19 02 00 00 EB 0D 31 C0 83 FE 02 0F 94 C0 89 04 24 EB 10 83 3B 02 0F 85 01 02 00 00 C7 04 24 00 00 00 00 89 3B 8B 4C 24 60 C7 01 FF FF FF FF FF 74 24 4C E8 ?? ?? ?? ?? 59 8D 58 01 39 DD 0F 8E D4 01 00 00 53 FF 74 24 50 FF 74 24 5C E8 ?? ?? ?? ?? 8B 54 24 }
	condition:
		$pattern
}

rule gethostbyaddr_r_252d1a1c395aca6c6dac2df84f0d3204 {
	meta:
		aliases = "__GI_gethostbyaddr_r, gethostbyaddr_r"
		type = "func"
		size = "648"
		objfiles = "gethostbyaddr_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 38 8B 74 24 5C 8B 5C 24 60 8B 44 24 64 C7 00 00 00 00 00 83 7C 24 4C 00 0F 84 50 02 00 00 83 7C 24 54 02 74 0D 83 7C 24 54 0A 0F 85 3E 02 00 00 EB 07 83 7C 24 50 04 EB 05 83 7C 24 50 10 0F 85 2A 02 00 00 FF 74 24 68 FF 74 24 68 53 56 FF 74 24 68 FF 74 24 68 FF 74 24 68 FF 74 24 68 E8 ?? ?? ?? ?? 83 C4 20 85 C0 0F 84 0C 02 00 00 8B 4C 24 68 8B 11 83 FA 01 74 09 83 FA 04 0F 85 F8 01 00 00 8B 7C 24 68 C7 07 FF FF FF FF 83 7C 24 50 10 0F 87 DE 01 00 00 89 F0 F7 D8 83 E0 03 29 C3 83 EB 18 89 5C 24 08 81 FB FF 00 00 00 0F 8E C2 01 00 00 8D 2C 06 8D 45 08 8D 75 18 89 75 00 C7 45 04 }
	condition:
		$pattern
}

rule authunix_refresh_3bc97097c7c4a8bf86ecde40ad5e7db7 {
	meta:
		aliases = "authunix_refresh"
		type = "func"
		size = "209"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 38 8B 7C 24 4C 8B 5F 24 8B 47 04 31 ED 3B 43 04 0F 84 AB 00 00 00 FF 43 18 C7 44 24 1C 00 00 00 00 C7 44 24 2C 00 00 00 00 6A 01 FF 73 08 FF 73 04 8D 74 24 0C 56 E8 ?? ?? ?? ?? 8D 44 24 28 50 56 E8 ?? ?? ?? ?? 83 C4 18 85 C0 74 4D 6A 00 8D 44 24 34 50 E8 ?? ?? ?? ?? 8B 44 24 38 89 44 24 20 C7 44 24 08 00 00 00 00 6A 00 56 8B 44 24 14 FF 50 14 8D 44 24 28 50 56 E8 ?? ?? ?? ?? 89 C5 83 C4 18 85 C0 74 13 6A 0C 53 57 E8 ?? ?? ?? ?? 89 F8 E8 ?? ?? ?? ?? 83 C4 0C C7 04 24 02 00 00 00 8D 44 24 18 50 8D 5C 24 04 53 E8 ?? ?? ?? ?? 8B 44 24 0C 8B 40 1C 5E 5F 85 C0 74 04 53 FF D0 5B 89 }
	condition:
		$pattern
}

rule rint_c33b757d88fac953ad50fae5e08e6958 {
	meta:
		aliases = "__GI_nearbyint, __GI_rint, nearbyint, rint"
		type = "func"
		size = "342"
		objfiles = "s_rint@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 38 C7 04 24 00 00 00 00 C7 44 24 04 00 00 00 00 DD 44 24 4C DD 54 24 20 8B 5C 24 20 8B 44 24 24 C1 E8 14 25 FF 07 00 00 8D B0 01 FC FF FF 83 FE 33 0F 8F 0B 01 00 00 8B 6C 24 24 89 EF C1 EF 1F 83 FE 13 0F 8F B0 00 00 00 85 F6 79 72 89 E8 25 FF FF FF 7F 09 D8 0F 84 E6 00 00 00 89 EA 81 E2 FF FF 0F 00 09 DA DD 5C 24 18 89 D0 F7 D8 09 D0 C1 E8 0C 25 00 00 08 00 81 E5 00 00 FE FF 09 E8 89 44 24 1C DD 04 FD ?? ?? ?? ?? DD 44 24 18 D8 C1 DD 5C 24 30 DD 44 24 30 DE E1 DD 54 24 28 DD 54 24 10 DD 5C 24 08 C1 E7 1F 8B 44 24 14 25 FF FF FF 7F 09 C7 89 7C 24 0C DD 44 24 08 EB 7D DD D8 BA }
	condition:
		$pattern
}

rule __ivaliduser2_debb61c55ab40344cce1045ee9b51839 {
	meta:
		aliases = "__ivaliduser2"
		type = "func"
		size = "685"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C 89 44 24 08 89 54 24 04 89 0C 24 C7 44 24 38 00 00 00 00 C7 44 24 34 00 00 00 00 E9 4E 02 00 00 8B 54 24 34 8B 44 24 38 C6 44 02 FF 00 8B 5C 24 38 89 DE EB 01 46 8A 0E 84 C9 0F 84 2E 02 00 00 0F B6 D1 A1 ?? ?? ?? ?? F6 04 50 20 75 E7 80 F9 23 0F 84 17 02 00 00 6A 0A 53 E8 ?? ?? ?? ?? 5E 5F 85 C0 75 42 8B 54 24 08 8B 42 10 3B 42 18 73 0D 0F B6 10 40 8B 4C 24 08 89 41 10 EB 0C FF 74 24 08 E8 ?? ?? ?? ?? 89 C2 59 83 FA 0A 0F 84 DB 01 00 00 42 75 CF E9 D3 01 00 00 A1 ?? ?? ?? ?? 0F BF 04 08 88 03 43 8A 13 84 D2 74 11 0F B6 C2 8D 0C 00 A1 ?? ?? ?? ?? F6 04 08 20 74 DD 80 FA 20 }
	condition:
		$pattern
}

rule strerror_r_f47c225702285995fff180a022a4c6cb {
	meta:
		aliases = "__GI___xpg_strerror_r, __xpg_strerror_r, strerror_r"
		type = "func"
		size = "190"
		objfiles = "__xpg_strerror_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C 8B 44 24 50 8B 5C 24 58 83 F8 7C 77 26 89 C1 C7 04 24 ?? ?? ?? ?? EB 0D 8B 14 24 80 3A 01 83 D9 00 42 89 14 24 85 C9 75 EF 31 ED 8B 3C 24 80 3F 00 75 2C 6A 00 6A F6 99 52 50 8D 44 24 4B 50 E8 ?? ?? ?? ?? 83 E8 0E 89 44 24 14 BE ?? ?? ?? ?? 89 C7 A5 A5 A5 66 A5 BD 16 00 00 00 83 C4 14 31 C0 83 7C 24 54 00 0F 95 C0 F7 D8 21 C3 FF 34 24 E8 ?? ?? ?? ?? 5A 40 89 C6 39 D8 76 07 89 DE BD 22 00 00 00 85 F6 74 1A 56 FF 74 24 04 FF 74 24 5C E8 ?? ?? ?? ?? 8B 44 24 60 C6 44 06 FF 00 83 C4 0C 85 ED 74 07 E8 ?? ?? ?? ?? 89 28 89 E8 83 C4 3C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule gethostbyname2_r_4ea94c52abd831282907c73a037ff7a4 {
	meta:
		aliases = "__GI_gethostbyname2_r, gethostbyname2_r"
		type = "func"
		size = "668"
		objfiles = "gethostbyname2_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C 8B 44 24 54 8B 7C 24 60 83 F8 02 75 22 FF 74 24 68 FF 74 24 68 57 FF 74 24 68 FF 74 24 68 FF 74 24 64 E8 ?? ?? ?? ?? 83 C4 18 E9 5E 02 00 00 8B 54 24 64 C7 02 00 00 00 00 83 F8 0A 0F 85 46 02 00 00 83 7C 24 50 00 0F 84 3B 02 00 00 E8 ?? ?? ?? ?? 89 C6 8B 28 C7 00 00 00 00 00 FF 74 24 68 FF 74 24 68 57 FF 74 24 68 FF 74 24 68 6A 0A FF 74 24 68 E8 ?? ?? ?? ?? 83 C4 1C 85 C0 75 07 89 2E E9 07 02 00 00 8B 4C 24 68 8B 11 83 FA 01 74 0E 83 FA 04 74 1C 42 0F 85 F0 01 00 00 EB 0A 31 DB 83 F8 02 0F 94 C3 EB 0B 83 3E 02 0F 85 DB 01 00 00 31 DB 89 2E 8B 44 24 68 C7 00 FF FF FF FF 8B }
	condition:
		$pattern
}

rule getnetent_r_f7d08230ea340523191c3780a2d5ec30 {
	meta:
		aliases = "__GI_getnetent_r, getnetent_r"
		type = "func"
		size = "322"
		objfiles = "getnet@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C 8B 5C 24 50 8B 74 24 58 8B 6C 24 5C C7 44 24 38 00 00 00 00 C7 45 00 00 00 00 00 BF 22 00 00 00 81 FE 2B 01 00 00 0F 86 FE 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 2C 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 3D ?? ?? ?? ?? 00 75 0E 0F BE 05 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 59 8B 15 ?? ?? ?? ?? 85 D2 0F 84 A5 00 00 00 8B 44 24 54 89 42 04 C7 42 08 2C 00 00 00 8D 46 D4 89 42 10 68 ?? ?? ?? ?? 68 0A 02 07 00 8D 44 24 40 50 52 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 75 8B 44 24 38 8B 10 89 13 83 C0 04 89 44 24 38 31 C0 B9 08 00 00 00 8D 74 24 04 89 F7 F3 AB C7 }
	condition:
		$pattern
}

rule __time_localtime_tzi_f8e3fbe8a9ab28caa3bdd06efba05bfe {
	meta:
		aliases = "__time_localtime_tzi"
		type = "func"
		size = "690"
		objfiles = "_time_localtime_tzi@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C C7 44 24 18 00 00 00 00 6B 44 24 18 18 8B 5C 24 58 01 C3 B8 80 3A 09 00 2B 03 8B 4C 24 50 8B 11 B9 F9 FF FF FF 81 FA 7F C5 F6 7F 7E 07 F7 D8 B9 07 00 00 00 01 D0 89 44 24 38 FF 74 24 54 51 8D 74 24 40 56 E8 ?? ?? ?? ?? 8B 44 24 24 8B 7C 24 60 89 47 20 8B 03 F7 D8 89 47 24 8D 7B 10 BE ?? ?? ?? ?? 83 C4 0C 57 8D 5E 04 53 E8 ?? ?? ?? ?? 59 5A 85 C0 75 04 89 D8 EB 45 8B 36 85 F6 75 E6 6A 07 57 E8 ?? ?? ?? ?? 5E 5A 83 F8 06 7F 2B 83 C0 08 50 E8 ?? ?? ?? ?? 89 C2 5B 85 C0 74 1B A1 ?? ?? ?? ?? 89 02 89 15 ?? ?? ?? ?? 57 8D 42 04 50 E8 ?? ?? ?? ?? 5A 59 EB 05 B8 ?? ?? ?? ?? 8B 54 }
	condition:
		$pattern
}

rule atan2_2d90a78732b78f753276456c8a03e6bd {
	meta:
		aliases = "__GI_atan2, __ieee754_atan2, atan2"
		type = "func"
		size = "580"
		objfiles = "e_atan2@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C DD 44 24 50 DD 5C 24 08 DD 44 24 58 DD 14 24 DD 5C 24 28 8B 44 24 2C 89 44 24 38 8B 4C 24 28 89 C7 81 E7 FF FF FF 7F DD 44 24 08 DD 5C 24 20 8B 54 24 20 89 C8 F7 D8 09 C8 C1 E8 1F 09 F8 3D 00 00 F0 7F 77 1E 8B 6C 24 24 89 EE 81 E6 FF FF FF 7F 89 D0 F7 D8 09 D0 C1 E8 1F 09 F0 3D 00 00 F0 7F 76 0C DD 44 24 08 DC 04 24 E9 BE 01 00 00 8B 44 24 38 2D 00 00 F0 3F 09 C8 75 14 DD 44 24 08 DD 5C 24 50 83 C4 3C 5B 5E 5F 5D E9 ?? ?? ?? ?? 8B 5C 24 38 C1 FB 1E 83 E3 02 89 E8 C1 E8 1F 09 C3 09 F2 75 18 83 FB 02 0F 84 8C 00 00 00 0F 8E 7D 01 00 00 83 FB 03 0F 84 88 00 00 00 09 F9 0F 84 }
	condition:
		$pattern
}

rule clnttcp_call_85b1dddee9cf33d402fe4a6e0969f0c4 {
	meta:
		aliases = "clnttcp_call"
		type = "func"
		size = "544"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 40 8B 44 24 6C 8B 54 24 70 8B 4C 24 54 8B 59 08 8D 73 4C 8D 4B 30 89 4C 24 04 83 7B 10 00 75 06 89 53 0C 89 43 08 83 7C 24 64 00 75 12 83 7B 08 00 75 0C 83 7B 0C 00 0F 95 C0 0F B6 F8 EB 05 BF 01 00 00 00 C7 44 24 08 02 00 00 00 8D 43 30 89 04 24 C7 43 4C 00 00 00 00 C7 43 24 00 00 00 00 8B 54 24 04 8B 02 48 89 02 0F C8 89 44 24 0C 8B 43 50 FF 73 48 FF 74 24 04 56 FF 50 0C 83 C4 0C 85 C0 74 35 8B 43 50 8D 4C 24 58 51 56 FF 50 04 5A 59 85 C0 74 23 8B 54 24 54 8B 02 8B 50 20 56 50 FF 52 04 59 5D 85 C0 74 0F FF 74 24 60 56 FF 54 24 64 5D 5A 85 C0 75 1F 83 7B 24 00 75 07 C7 43 24 }
	condition:
		$pattern
}

rule clntunix_call_b7999b412e9247062305b540086fcc8a {
	meta:
		aliases = "clntunix_call"
		type = "func"
		size = "613"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 40 8B 44 24 6C 8B 54 24 70 8B 4C 24 54 8B 59 08 8D B3 AC 00 00 00 8D 8B 90 00 00 00 89 4C 24 04 83 7B 10 00 75 06 89 53 0C 89 43 08 83 7C 24 64 00 75 12 83 7B 08 00 75 0C 83 7B 0C 00 0F 95 C0 0F B6 F8 EB 05 BF 01 00 00 00 C7 44 24 08 02 00 00 00 8D 83 90 00 00 00 89 04 24 C7 83 AC 00 00 00 00 00 00 00 C7 83 84 00 00 00 00 00 00 00 8B 54 24 04 8B 02 48 89 02 0F C8 89 44 24 0C 8B 83 B0 00 00 00 FF B3 A8 00 00 00 FF 74 24 04 56 FF 50 0C 83 C4 0C 85 C0 74 38 8B 83 B0 00 00 00 8D 4C 24 58 51 56 FF 50 04 5A 59 85 C0 74 23 8B 54 24 54 8B 02 8B 50 20 56 50 FF 52 04 59 5D 85 C0 74 0F }
	condition:
		$pattern
}

rule clntraw_call_88103a36b03e69a579c2b0b53d4b0d0b {
	meta:
		aliases = "clntraw_call"
		type = "func"
		size = "386"
		objfiles = "clnt_raw@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 40 E8 ?? ?? ?? ?? 8B 98 A0 00 00 00 8D 73 0C BF 10 00 00 00 85 DB 0F 84 56 01 00 00 8D 83 84 22 00 00 89 04 24 C7 43 0C 00 00 00 00 8B 43 10 6A 00 56 FF 50 14 8B 54 24 08 FF 02 8B 43 10 FF B3 9C 22 00 00 52 56 FF 50 0C 83 C4 14 85 C0 0F 84 FC 00 00 00 8B 43 10 8D 54 24 58 52 56 FF 50 04 59 5F 85 C0 0F 84 E6 00 00 00 8B 54 24 54 8B 02 8B 50 20 56 50 FF 52 04 5D 5A 85 C0 0F 84 CE 00 00 00 FF 74 24 60 56 FF 54 24 64 59 5F 85 C0 0F 84 BB 00 00 00 8B 43 10 56 FF 50 10 6A 01 E8 ?? ?? ?? ?? C7 43 0C 01 00 00 00 8B 43 10 6A 00 56 FF 50 14 8D 6C 24 20 6A 0C 68 ?? ?? ?? ?? 55 E8 ?? ?? }
	condition:
		$pattern
}

rule _dl_map_cache_90a13c53363a068608581bee540d419d {
	meta:
		aliases = "_dl_map_cache"
		type = "func"
		size = "505"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 44 8B 15 ?? ?? ?? ?? 83 C8 FF 83 FA FF 0F 84 D8 01 00 00 85 D2 0F 85 CE 01 00 00 BE ?? ?? ?? ?? 89 E1 89 F2 87 D3 B8 6A 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0D F7 DB 89 1D ?? ?? ?? ?? E9 95 01 00 00 85 C0 0F 85 8D 01 00 00 B9 00 00 08 00 31 D2 89 F0 53 89 C3 B8 05 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0D F7 DF 89 3D ?? ?? ?? ?? E9 63 01 00 00 85 C0 0F 88 5B 01 00 00 8B 4C 24 14 89 0D ?? ?? ?? ?? C7 44 24 40 00 00 00 00 BE 01 00 00 00 89 D8 89 F2 53 89 C3 55 8B 6C 24 40 B8 C0 00 00 00 CD 80 5D 5B 89 C1 89 C2 3D 00 F0 FF FF 76 0B F7 D9 89 0D ?? ?? ?? ?? 83 CA FF 89 }
	condition:
		$pattern
}

rule sigwait_7fee8f3df9a4ce835f38b767300e7d78 {
	meta:
		aliases = "sigwait"
		type = "func"
		size = "271"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 44 E8 ?? ?? ?? ?? 89 44 24 40 C7 44 24 38 FF FF FF FF C7 44 24 3C FF FF FF FF FF 35 ?? ?? ?? ?? 8D 5C 24 3C 53 E8 ?? ?? ?? ?? BE 01 00 00 00 5F 5D 89 DD 8D 5C 24 24 EB 59 56 FF 74 24 5C E8 ?? ?? ?? ?? 5A 59 85 C0 74 48 3B 35 ?? ?? ?? ?? 74 40 3B 35 ?? ?? ?? ?? 74 38 3B 35 ?? ?? ?? ?? 74 30 56 55 E8 ?? ?? ?? ?? 5F 58 83 3C B5 ?? ?? ?? ?? 01 77 1D 31 C0 89 DF AB AB AB AB AB C7 44 24 24 ?? ?? ?? ?? 6A 00 53 56 E8 ?? ?? ?? ?? 83 C4 0C 46 83 FE 41 7E A2 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 5A 59 85 C0 75 39 8B 44 24 40 89 60 28 8B 44 24 40 80 78 42 00 74 0A 8B 44 24 40 80 78 40 00 }
	condition:
		$pattern
}

rule __md5_Final_d1bd57e83f2379a7775aa82a9eb0276e {
	meta:
		aliases = "__md5_Final"
		type = "func"
		size = "113"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 48 89 C5 89 D3 31 C0 B9 10 00 00 00 89 E7 F3 AB C6 04 24 80 8D 72 10 8D 7C 24 40 A5 A5 8B 42 10 C1 E8 03 83 E0 3F B9 38 00 00 00 83 F8 37 76 05 B9 78 00 00 00 29 C1 89 E2 89 D8 E8 ?? ?? ?? ?? 8D 54 24 40 B9 08 00 00 00 89 D8 E8 ?? ?? ?? ?? 89 DE 89 EF A5 A5 A5 A5 31 C0 B9 16 00 00 00 89 DF F3 AB 83 C4 48 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _wstdio_fwrite_4ad6c37e57a77f9c8419a90edacda929 {
	meta:
		aliases = "_wstdio_fwrite"
		type = "func"
		size = "226"
		objfiles = "_wfwrite@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 48 8B 6C 24 60 8B 74 24 64 83 7E 04 FD 75 36 8B 46 10 8B 5E 0C 29 C3 C1 FB 02 39 EB 76 02 89 EB 85 DB 0F 84 AA 00 00 00 53 FF 74 24 60 50 E8 ?? ?? ?? ?? 8D 04 9D 00 00 00 00 01 46 10 83 C4 0C E9 8D 00 00 00 0F B7 06 25 40 08 00 00 3D 40 08 00 00 74 13 68 00 08 00 00 56 E8 ?? ?? ?? ?? 5A 59 31 FF 85 C0 75 69 8B 44 24 5C 89 44 24 44 31 FF 8D 56 2C 89 14 24 EB 53 FF 34 24 6A 40 89 E8 29 F8 50 8D 44 24 50 50 8D 54 24 14 52 E8 ?? ?? ?? ?? 89 C3 83 C4 14 83 F8 FF 74 34 85 C0 75 0E 8B 54 24 5C 8D 44 BA 04 89 44 24 44 B3 01 56 53 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 0C 39 D8 75 0F 8B }
	condition:
		$pattern
}

rule getaddrinfo_effd2e469507bc7e4840239162167e5e {
	meta:
		aliases = "__GI_getaddrinfo, getaddrinfo"
		type = "func"
		size = "625"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C 8B 54 24 64 8B 5C 24 68 83 7C 24 60 00 74 19 8B 44 24 60 80 38 2A 75 10 80 78 01 00 0F 95 C0 0F B6 C0 F7 D8 21 44 24 60 85 D2 74 12 80 3A 2A 75 0D 31 C0 80 7A 01 00 0F 95 C0 F7 D8 21 C2 8B 7C 24 60 09 D7 0F 84 0E 02 00 00 85 DB 75 11 B9 08 00 00 00 8D 74 24 1C 89 F7 89 D8 F3 AB 89 F3 8B 03 A9 C0 FB FF FF 0F 85 F3 01 00 00 A8 02 74 0B 83 7C 24 60 00 0F 84 E4 01 00 00 85 D2 74 61 80 3A 00 74 5C 89 54 24 3C 6A 0A 8D 44 24 48 50 52 E8 ?? ?? ?? ?? 89 44 24 4C 83 C4 0C 8B 44 24 44 80 38 00 74 1C F6 43 01 04 0F 85 A9 01 00 00 C7 44 24 40 FF FF FF FF 8D 44 24 3C 89 44 24 10 EB 27 }
	condition:
		$pattern
}

rule readunix_d9e010f03a28261b59b4ef36e2bd0feb {
	meta:
		aliases = "readunix"
		type = "func"
		size = "356"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C 8B 74 24 60 8B 6C 24 68 8B 4E 0C BB E8 03 00 00 89 C8 99 F7 FB 89 C1 69 46 08 E8 03 00 00 8D 3C 01 66 31 DB 85 ED 0F 84 27 01 00 00 8B 06 89 44 24 40 66 C7 44 24 44 01 00 8D 5C 24 40 57 6A 01 53 E8 ?? ?? ?? ?? 83 C4 0C 83 F8 FF 74 10 85 C0 75 30 C7 86 84 00 00 00 05 00 00 00 EB 1C E8 ?? ?? ?? ?? 83 38 04 74 D5 C7 86 84 00 00 00 04 00 00 00 8B 00 89 86 88 00 00 00 83 CB FF E9 D1 00 00 00 8B 3E 8B 44 24 64 89 44 24 38 89 6C 24 3C 8D 44 24 38 89 44 24 0C C7 44 24 10 01 00 00 00 C7 44 24 04 00 00 00 00 C7 44 24 08 00 00 00 00 8D 44 24 20 89 44 24 14 C7 44 24 18 18 00 00 00 C7 }
	condition:
		$pattern
}

rule strftime_0cd607c9f7efea62e578acd49966d03f {
	meta:
		aliases = "strftime"
		type = "func"
		size = "1266"
		objfiles = "strftime@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 50 6A 00 FF 74 24 74 E8 ?? ?? ?? ?? 3D FF 4E 98 45 0F 9E C0 0F B6 C0 50 E8 ?? ?? ?? ?? 8B 4C 24 78 8B 44 24 74 89 44 24 20 C7 44 24 28 00 00 00 00 83 C4 0C 8D 54 24 38 89 54 24 04 83 7C 24 14 00 0F 84 9B 04 00 00 8A 01 84 C0 75 29 83 7C 24 1C 00 75 14 8B 4C 24 64 C6 01 00 8B 44 24 68 2B 44 24 14 E9 7C 04 00 00 FF 4C 24 1C 8B 5C 24 1C 8B 4C 9C 28 EB C6 3C 25 74 06 89 4C 24 10 EB 0E 8D 79 01 89 7C 24 10 8A 41 01 3C 25 75 0F 89 CE C7 44 24 18 01 00 00 00 E9 0D 04 00 00 3C 4F 74 10 3C 45 74 10 C7 44 24 18 02 00 00 00 B3 3F EB 17 B0 40 EB 02 B0 80 88 C3 83 CB 3F FF 44 24 10 C7 44 }
	condition:
		$pattern
}

rule vwarn_work_a23374f98dfbd11de2b1bee1fdf8ba87 {
	meta:
		aliases = "vwarn_work"
		type = "func"
		size = "195"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 50 89 C7 89 D5 BB ?? ?? ?? ?? 85 C9 74 1B E8 ?? ?? ?? ?? 6A 40 8D 54 24 04 52 FF 30 E8 ?? ?? ?? ?? BB ?? ?? ?? ?? 83 C4 0C 8B 15 ?? ?? ?? ?? 83 7A 34 00 0F 94 C0 0F B6 F0 85 F6 74 24 8D 42 38 50 68 ?? ?? ?? ?? 8D 44 24 48 50 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C0 38 50 E8 ?? ?? ?? ?? 83 C4 10 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 85 FF 74 13 55 57 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EB 02 83 C4 0C 89 E0 50 53 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 85 F6 74 0E 6A 01 8D 44 24 44 50 E8 ?? ?? ?? ?? 58 5A 83 C4 50 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule inet_ntop_92d01706f9a6f94471131d9e394b7868 {
	meta:
		aliases = "__GI_inet_ntop, inet_ntop"
		type = "func"
		size = "430"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 54 8B 44 24 68 83 F8 02 74 0B 83 F8 0A 0F 85 7E 01 00 00 EB 18 8B 4C 24 74 8B 54 24 70 8B 44 24 6C E8 ?? ?? ?? ?? 89 C2 E9 71 01 00 00 31 C0 B9 08 00 00 00 8D 7C 24 34 F3 AB 31 C9 BA 02 00 00 00 89 C8 89 D6 99 F7 FE 89 C3 8B 54 24 6C 0F B6 04 0A C1 E0 08 0F B6 54 11 01 09 D0 89 44 9C 34 83 C1 02 83 F9 0F 7E D4 31 D2 83 CE FF 83 C8 FF EB 2E 83 7C 94 34 00 75 11 83 F8 FF 75 09 89 D0 B9 01 00 00 00 EB 18 41 EB 15 83 F8 FF 74 10 83 FE FF 74 04 39 E9 7E 04 89 CD 89 C6 83 C8 FF 42 83 FA 07 7E CD 83 F8 FF 74 0D 83 FE FF 74 04 39 E9 7E 04 89 CD 89 C6 83 FE FF 74 08 83 FD 01 7F 03 83 }
	condition:
		$pattern
}

rule iruserfopen_e2b598108e07672b88bc18457dcf6c1a {
	meta:
		aliases = "iruserfopen"
		type = "func"
		size = "132"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 58 89 C6 89 D5 89 E7 57 50 E8 ?? ?? ?? ?? 59 5B 31 DB 85 C0 75 5E 8B 44 24 10 25 00 F0 00 00 3D 00 80 00 00 75 4E 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 89 C3 58 5A 85 DB 74 3B 53 E8 ?? ?? ?? ?? 57 50 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 78 1A 8B 44 24 18 85 C0 74 04 39 E8 75 0E F6 44 24 10 12 75 07 83 7C 24 14 01 76 0D 85 DB 74 09 53 E8 ?? ?? ?? ?? 31 DB 5D 89 D8 83 C4 58 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _ppfs_parsespec_62aeeb3660cd04bb47ab50eb5842fa44 {
	meta:
		aliases = "_ppfs_parsespec"
		type = "func"
		size = "1036"
		objfiles = "_ppfs_parsespec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 58 C7 44 24 4C 00 00 00 00 C7 44 24 50 00 00 00 00 C7 44 24 30 08 00 00 00 C7 44 24 34 08 00 00 00 8B 44 24 6C 8B 40 18 89 44 24 08 8B 54 24 6C 8B 6A 10 81 E5 80 00 00 00 75 04 8B 12 EB 39 31 F6 8D 0C B5 00 00 00 00 8B 44 24 6C 8B 10 8B 44 11 FC 88 C3 88 44 34 10 0F B6 C0 3B 44 11 FC 0F 85 96 03 00 00 84 DB 74 06 46 83 FE 1F 76 D2 C6 44 24 2F 00 8D 54 24 11 C7 04 24 00 00 00 00 C7 44 24 04 00 00 00 00 EB 02 89 F2 89 D6 80 3A 2A 75 10 6B 44 24 04 FC C7 44 04 30 00 00 00 00 8D 72 01 31 FF EB 24 81 FF CB CC CC 0C 7E 0D 81 FF CC CC CC 0C 75 0E 83 F9 37 7F 09 6B C7 0A 8D 7C 08 D0 }
	condition:
		$pattern
}

rule lgamma_r_7de14a464c6bb1cd24db5656c0ab97c0 {
	meta:
		aliases = "__ieee754_lgamma_r, gamma_r, lgamma_r"
		type = "func"
		size = "1677"
		objfiles = "e_lgamma_r@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 5C 8B 6C 24 78 DD 44 24 70 DD 54 24 28 8B 44 24 2C 89 44 24 40 C7 45 00 01 00 00 00 89 C6 81 E6 FF FF FF 7F 81 FE FF FF EF 7F 7E 09 D9 C0 DE C9 E9 4A 06 00 00 DD D8 8B 7C 24 28 89 F0 09 F8 75 1C FF 74 24 74 FF 74 24 74 E8 ?? ?? ?? ?? 5E 5F 85 C0 74 61 C7 45 00 FF FF FF FF EB 58 81 FE FF FF 8F 3B 7F 36 83 7C 24 40 00 79 19 C7 45 00 FF FF FF FF DD 44 24 70 D9 E0 DD 54 24 70 83 EC 08 DD 1C 24 EB 08 FF 74 24 74 FF 74 24 74 E8 ?? ?? ?? ?? D9 E0 59 5B E9 E4 05 00 00 83 7C 24 40 00 78 0B D9 EE DD 5C 24 38 E9 E9 01 00 00 81 FE FF FF 2F 43 7E 07 D9 EE E9 88 01 00 00 DD 44 24 70 DD 5C }
	condition:
		$pattern
}

rule lckpwdf_d48eeb422838d710e8d71c796b5747ec {
	meta:
		aliases = "lckpwdf"
		type = "func"
		size = "308"
		objfiles = "lckpwdf@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 60 83 C8 FF 83 3D ?? ?? ?? ?? FF 0F 85 15 01 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 38 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 01 00 08 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 18 83 F8 FF 0F 84 C7 00 00 00 6A 01 6A 02 50 E8 ?? ?? ?? ?? 31 DB 8D 54 24 14 89 D7 89 D8 AB AB AB AB AB C7 44 24 14 ?? ?? ?? ?? C7 44 24 20 FF FF FF FF C7 44 24 24 FF FF FF FF 8D 6C 24 28 55 52 6A 0E E8 ?? ?? ?? ?? C7 44 24 6C 00 00 00 00 C7 44 24 68 00 20 00 00 8D 74 24 70 56 8D 44 24 6C 50 6A 01 E8 ?? ?? ?? ?? 83 C4 24 6A 0F E8 ?? ?? ?? ?? 8D 54 24 44 89 D7 89 D8 AB AB }
	condition:
		$pattern
}

rule __pthread_manager_635f4020ab1f042f92d8d5b1de03c3d7 {
	meta:
		aliases = "__pthread_manager"
		type = "func"
		size = "1565"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 60 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 44 24 50 FF FF FF FF C7 44 24 54 FF FF FF FF FF 35 ?? ?? ?? ?? 8D 5C 24 54 53 E8 ?? ?? ?? ?? 6A 05 53 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 12 A1 ?? ?? ?? ?? 85 C0 7E 09 50 53 E8 ?? ?? ?? ?? 58 5A 6A 00 8D 44 24 54 50 6A 02 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? FF 70 18 E8 ?? ?? ?? ?? 83 C4 10 8D 5C 24 34 6A 1C 53 FF 74 24 7C E8 ?? ?? ?? ?? 83 C4 0C 40 75 0A E8 ?? ?? ?? ?? 83 38 04 74 E4 8B 44 24 74 89 44 24 58 66 C7 44 24 5C 01 00 68 D0 07 00 00 6A 01 8D 54 24 60 52 E8 ?? ?? ?? ?? 89 C3 E8 ?? ?? ?? ?? 83 C4 }
	condition:
		$pattern
}

rule __md5_Transform_cbae4cbbeb7221868d444bd833ec7753 {
	meta:
		aliases = "__md5_Transform"
		type = "func"
		size = "312"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 64 89 C5 89 D6 B9 10 00 00 00 8D 7C 24 24 F3 A5 8B 00 89 44 24 20 8D 55 04 89 54 24 04 8B 5D 04 8D 45 08 89 44 24 08 8B 7D 08 8D 55 0C 89 54 24 0C 8B 75 0C C7 44 24 10 ?? ?? ?? ?? 8B 4C 24 20 C7 44 24 14 ?? ?? ?? ?? C7 44 24 18 ?? ?? ?? ?? C7 44 24 1C 00 00 00 00 E9 99 00 00 00 F6 44 24 1C 0F 75 05 83 44 24 10 04 8B 44 24 1C C1 F8 04 83 F8 01 74 1E 7F 06 85 C0 74 0E EB 37 83 F8 02 74 1F 83 F8 03 74 22 EB 2B 89 D8 F7 D0 21 F0 89 FA EB 08 89 F0 F7 D0 21 F8 89 F2 21 DA 09 D0 EB 10 89 F8 31 D8 31 F0 EB 08 89 F0 F7 D0 09 D8 31 F8 8D 0C 08 8B 44 24 18 0F B6 00 89 04 24 8B 54 24 14 }
	condition:
		$pattern
}

rule _time_mktime_tzi_848069244c03a68637a2fc16fe8f2f0b {
	meta:
		aliases = "_time_mktime_tzi"
		type = "func"
		size = "693"
		objfiles = "_time_mktime_tzi@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 68 8D 6C 24 38 B9 0B 00 00 00 8B 74 24 7C 89 EF F3 A5 8B 84 24 84 00 00 00 80 78 28 00 75 08 C7 44 24 58 00 00 00 00 C7 44 24 34 00 00 00 00 83 7C 24 58 00 74 16 0F 9F C0 0F B6 C0 8D 44 00 FF 89 44 24 58 C7 44 24 34 01 00 00 00 8D 55 14 89 54 24 24 8B 4D 14 8D 5D 18 89 5C 24 28 BF 90 01 00 00 89 C8 99 F7 FF 89 44 24 04 89 45 18 8D 75 1C 8D 55 10 89 54 24 2C 8B 5D 10 89 5C 24 14 89 D8 BB 0C 00 00 00 99 F7 FB 89 44 24 10 89 45 1C 01 C1 69 5C 24 04 90 01 00 00 29 D9 89 4D 14 6B C0 0C 8B 54 24 14 29 C2 89 D0 89 55 10 85 D2 79 0C 83 C0 0C 89 45 10 8B 4C 24 24 FF 09 8B 4D 14 81 C1 }
	condition:
		$pattern
}

rule strptime_61561809fea061c5b4a0d7f23d1d6a4d {
	meta:
		aliases = "strptime"
		type = "func"
		size = "947"
		objfiles = "strptime@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 6C 8B AC 24 80 00 00 00 31 C0 C7 44 84 20 00 00 00 80 40 83 F8 0C 7E F2 8B BC 24 84 00 00 00 C7 44 24 08 00 00 00 00 8A 07 84 C0 75 48 83 7C 24 08 00 75 33 83 7C 24 38 07 75 08 C7 44 24 38 00 00 00 00 31 D2 8B 44 94 20 3D 00 00 00 80 74 0A 8B 8C 24 88 00 00 00 89 04 91 42 83 FA 07 7E E5 89 E8 E9 3E 03 00 00 FF 4C 24 08 8B 5C 24 08 8B 7C 9C 54 EB B2 3C 25 0F 85 FA 02 00 00 47 8A 07 3C 25 0F 84 EF 02 00 00 3C 4F 74 08 B1 3F 3C 45 75 0E EB 04 B0 40 EB 02 B0 80 88 C1 83 C9 3F 47 8A 17 84 D2 0F 84 F9 02 00 00 88 D0 83 C8 20 83 E8 61 3C 19 0F 87 E9 02 00 00 0F B6 C2 8A 90 ?? ?? ?? }
	condition:
		$pattern
}

rule svcunix_create_313d111ef7b9eadf38ec0537af343e6f {
	meta:
		aliases = "svcunix_create"
		type = "func"
		size = "358"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 74 8B B4 24 88 00 00 00 8B BC 24 94 00 00 00 C7 44 24 70 10 00 00 00 31 ED 83 FE FF 75 29 6A 00 6A 01 6A 01 E8 ?? ?? ?? ?? 89 C6 83 C4 0C 66 BD 01 00 85 C0 79 11 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 FF E9 85 00 00 00 6A 6E 6A 00 8D 5C 24 0A 53 E8 ?? ?? ?? ?? 66 C7 44 24 0E 01 00 57 E8 ?? ?? ?? ?? 5A 40 89 44 24 7C 50 57 8D 44 24 18 50 E8 ?? ?? ?? ?? 8B 84 24 88 00 00 00 83 C0 02 89 84 24 88 00 00 00 50 53 56 E8 ?? ?? ?? ?? 83 C4 24 8D 44 24 70 50 53 56 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 0E 6A 02 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 21 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 31 FF 85 ED 0F 84 }
	condition:
		$pattern
}

rule getpass_c82af47fa997a908a260263c96473789 {
	meta:
		aliases = "getpass"
		type = "func"
		size = "316"
		objfiles = "getpass@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 78 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 5B 5F 89 C3 85 C0 75 0C 8B 35 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 8D 7C 24 04 57 50 E8 ?? ?? ?? ?? 83 C4 0C 31 ED 85 C0 75 43 8D 44 24 3C 6A 3C 57 50 E8 ?? ?? ?? ?? 83 64 24 18 F6 56 E8 ?? ?? ?? ?? 57 6A 02 50 E8 ?? ?? ?? ?? 83 C4 1C 85 C0 0F 94 C0 0F B6 E8 3B 35 ?? ?? ?? ?? 74 0F 6A 00 6A 02 6A 00 56 E8 ?? ?? ?? ?? 83 C4 10 53 FF B4 24 90 00 00 00 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 56 68 FF 00 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 1C 85 C0 79 09 C6 05 ?? ?? ?? ?? 00 EB 40 48 80 }
	condition:
		$pattern
}

rule _fp_out_wide_b62c976380cea9f1cb17cdd048fe98c6 {
	meta:
		aliases = "_fp_out_wide"
		type = "func"
		size = "135"
		objfiles = "_vfwprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 78 8B B4 24 90 00 00 00 8B 9C 24 94 00 00 00 31 ED 89 F0 84 C0 79 30 FF B4 24 98 00 00 00 E8 ?? ?? ?? ?? 5F 89 C7 29 C3 85 DB 7E 19 83 E6 7F 89 D9 89 F2 8B 84 24 8C 00 00 00 E8 ?? ?? ?? ?? 89 C5 39 D8 75 32 89 FB 85 DB 7E 2C 31 D2 8B 8C 24 98 00 00 00 0F B6 04 11 89 04 94 42 39 DA 7C ED FF B4 24 8C 00 00 00 53 8D 44 24 08 50 E8 ?? ?? ?? ?? 01 C5 83 C4 0C 89 E8 83 C4 78 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __uClibc_main_7c63a016acaa1af0b65454b3c01351d6 {
	meta:
		aliases = "__uClibc_main"
		type = "func"
		size = "480"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 7C 8B AC 24 98 00 00 00 8B 84 24 A8 00 00 00 A3 ?? ?? ?? ?? 8B 84 24 A4 00 00 00 A3 ?? ?? ?? ?? 8B 94 24 94 00 00 00 C1 E2 02 8D 44 2A 04 A3 ?? ?? ?? ?? 3B 45 00 75 09 8D 44 15 00 A3 ?? ?? ?? ?? 31 C0 B9 1E 00 00 00 8D 7C 24 04 F3 AB A1 ?? ?? ?? ?? EB 02 89 F0 83 38 00 8D 70 04 75 F6 89 F1 8D 54 24 04 EB 11 8B 01 83 F8 0E 77 07 8D 3C C2 89 CE A5 A5 83 C1 08 83 39 00 75 EA 8D 44 24 04 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 38 85 C0 75 04 66 B8 00 10 A3 ?? ?? ?? ?? 83 7C 24 60 FF 75 20 E8 ?? ?? ?? ?? 89 C3 E8 ?? ?? ?? ?? 39 C3 75 29 E8 ?? ?? ?? ?? 89 C3 E8 ?? ?? ?? ?? 39 C3 75 }
	condition:
		$pattern
}

rule byte_insert_op2_8918643c119c9f98b97afd2d26510542 {
	meta:
		aliases = "byte_insert_op2"
		type = "func"
		size = "54"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 89 C5 89 D3 89 CF 8B 74 24 14 8B 44 24 18 8D 48 05 89 C2 EB 06 49 4A 8A 02 88 01 39 DA 75 F6 89 74 24 14 89 F9 89 DA 89 E8 5B 5E 5F 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __getutid_8320b7874e6468c0cbb3eec34f396664 {
	meta:
		aliases = "__getutid"
		type = "func"
		size = "73"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 89 C7 0F BF 00 8D 70 FF C1 EE 02 8D 6F 28 EB 23 85 F6 75 07 8B 03 66 3B 07 EB 16 83 FE 01 75 13 6A 04 55 8D 43 28 50 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 0B E8 ?? ?? ?? ?? 89 C3 85 C0 75 D2 89 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule get_input_bytes_7e566ef3f459221da21de862682dc232 {
	meta:
		aliases = "get_input_bytes"
		type = "func"
		size = "75"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 89 C7 89 D5 89 CE EB 31 8B 57 2C 8B 47 30 29 D0 75 0D 89 F8 E8 ?? ?? ?? ?? 85 C0 75 1C EB 23 89 F3 39 C6 7E 02 89 C3 53 52 55 E8 ?? ?? ?? ?? 01 5F 2C 01 DD 29 DE 83 C4 0C 85 F6 7F CB B8 01 00 00 00 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule byte_compile_range_a594a8a9968584042e70a356ca279a6e {
	meta:
		aliases = "byte_compile_range"
		type = "func"
		size = "204"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 89 C7 89 D5 8B 5C 24 18 8B 12 BE 0B 00 00 00 39 CA 0F 84 AA 00 00 00 8D 42 01 89 45 00 81 E3 00 00 01 00 83 FB 01 19 F6 F7 D6 83 E6 0B 83 7C 24 14 00 74 16 89 F9 0F B6 C1 8B 4C 24 14 0F B6 3C 01 0F B6 02 0F B6 2C 01 EB 03 0F B6 2A 89 FB EB 6C 83 7C 24 14 00 74 1B 0F B6 C3 8B 7C 24 14 0F B6 04 07 BA 08 00 00 00 89 D1 99 F7 F9 89 C6 89 C1 EB 19 0F B6 D3 B9 08 00 00 00 89 D0 99 F7 F9 89 C6 0F B6 D3 89 D0 99 F7 F9 89 C1 8B 7C 24 1C 8A 14 0F 89 D9 83 7C 24 14 00 74 0B 0F B6 C3 8B 7C 24 14 0F B6 0C 07 83 E1 07 B8 01 00 00 00 D3 E0 09 D0 8B 54 24 1C 88 04 32 43 31 F6 39 EB 76 90 89 F0 5B }
	condition:
		$pattern
}

rule rwlock_have_already_9b6e4b6aed06db3fb507d5d8ae3a02a6 {
	meta:
		aliases = "rwlock_have_already"
		type = "func"
		size = "164"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 89 C7 89 D6 89 CD 8B 18 83 7A 18 01 74 06 31 D2 31 C9 EB 6F 85 DB 75 07 E8 ?? ?? ?? ?? 89 C3 8B 93 48 01 00 00 EB 07 39 72 04 74 08 8B 12 85 D2 75 F5 EB 04 85 D2 75 4F 83 BB 50 01 00 00 00 7F 46 8B 93 4C 01 00 00 85 D2 74 0A 8B 02 89 83 4C 01 00 00 EB 0A 6A 0C E8 ?? ?? ?? ?? 89 C2 58 85 D2 74 18 C7 42 08 01 00 00 00 89 72 04 8B 83 48 01 00 00 89 02 89 93 48 01 00 00 83 FA 01 19 C9 83 E1 01 31 F6 EB 07 31 C9 BE 01 00 00 00 8B 44 24 14 89 08 89 55 00 89 1F 89 F0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __syscall_mq_timedsend_ad25a9f98bdb2dd8f43e059e8817c8e4 {
	meta:
		aliases = "__syscall_mq_timedsend"
		type = "func"
		size = "56"
		objfiles = "mq_send@librt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 89 D3 89 CA 8B 74 24 14 8B 7C 24 18 89 D9 53 89 C3 B8 17 01 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __syscall_mq_timedreceive_84c5a7726501d10666e8747ee7c4a46e {
	meta:
		aliases = "__syscall_mq_timedreceive"
		type = "func"
		size = "56"
		objfiles = "mq_receive@librt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 89 D3 89 CA 8B 74 24 14 8B 7C 24 18 89 D9 53 89 C3 B8 18 01 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule openlog_intern_a0e5d88909e0c744d8b1093a389108cd {
	meta:
		aliases = "openlog_intern"
		type = "func"
		size = "205"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 89 D5 85 C0 74 05 A3 ?? ?? ?? ?? 89 E8 A2 ?? ?? ?? ?? F7 C1 07 FC FF FF 75 09 C1 E9 03 88 0D ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? BF 02 00 00 00 83 FB FF 75 4D BE 02 00 00 00 F7 C5 08 00 00 00 0F 84 80 00 00 00 6A 00 56 6A 01 E8 ?? ?? ?? ?? 89 C3 A3 ?? ?? ?? ?? 83 C4 0C 83 F8 FF 74 67 6A 01 6A 02 50 E8 ?? ?? ?? ?? 6A 03 53 E8 ?? ?? ?? ?? 80 CC 08 50 6A 04 53 E8 ?? ?? ?? ?? 89 F7 83 C4 20 80 3D ?? ?? ?? ?? 00 75 3B 6A 10 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 0C 40 74 09 C6 05 ?? ?? ?? ?? 01 EB 1F 53 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? FF FF FF FF BE 01 00 00 00 5A 83 FF 02 0F 84 74 FF FF FF }
	condition:
		$pattern
}

rule regerror_b9ee93e390567987e323f904e68ec90a {
	meta:
		aliases = "regerror"
		type = "func"
		size = "94"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 44 24 14 8B 6C 24 1C 8B 7C 24 20 83 F8 10 76 05 E8 ?? ?? ?? ?? 0F B7 84 00 ?? ?? ?? ?? 8D 98 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 5E 8D 70 01 85 FF 74 21 39 FE 76 12 8D 47 FF 50 53 55 E8 ?? ?? ?? ?? C6 44 3D FF 00 EB 08 56 53 55 E8 ?? ?? ?? ?? 83 C4 0C 89 F0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule memmem_e6b381a7c24936a57ee0c339c563035b {
	meta:
		aliases = "memmem"
		type = "func"
		size = "87"
		objfiles = "memmem@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 4C 24 18 8B 54 24 20 8B 5C 24 14 8D 34 0B 29 D6 89 D8 85 D2 74 37 39 D1 73 25 EB 2F 8A 03 8B 54 24 1C 3A 02 75 16 55 57 8D 43 01 50 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 04 89 D8 EB 11 43 EB 08 8D 6A FF 8B 7C 24 1C 47 39 F3 76 D1 31 C0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule mknodat_06ee2524aaf51ac4ff4326df5e45c20a {
	meta:
		aliases = "__GI_mknodat, mknodat"
		type = "func"
		size = "60"
		objfiles = "mknodat@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 4C 24 18 8B 7C 24 20 8B 44 24 14 8B 54 24 1C 89 FE 53 89 C3 B8 29 01 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _dl_parse_dynamic_info_b58a7e39600cfbf03929006d48e2cb9f {
	meta:
		aliases = "_dl_parse_dynamic_info"
		type = "func"
		size = "274"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 54 24 14 8B 5C 24 18 8B 6C 24 1C 8B 74 24 20 31 FF E9 9A 00 00 00 83 F9 21 7F 58 8B 42 04 89 04 8B 83 3A 15 75 03 89 6A 04 83 3A 18 75 07 C7 43 60 01 00 00 00 83 3A 1E 75 0D F6 42 04 08 74 07 C7 43 60 01 00 00 00 83 3A 16 75 07 C7 43 58 01 00 00 00 83 3A 1D 75 07 C7 43 3C 00 00 00 00 83 3A 0F 75 49 83 7B 74 00 74 43 C7 43 3C 00 00 00 00 EB 3A 81 F9 FF FF FF 6F 7F 32 81 F9 FA FF FF 6F 75 09 8B 42 04 89 83 88 00 00 00 81 3A FB FF FF 6F 75 19 F6 42 04 01 74 07 C7 43 60 01 00 00 00 F6 42 04 08 74 06 81 CF 00 10 00 00 83 C2 08 8B 0A 85 C9 0F 85 5C FF FF FF 85 F6 74 48 8B 43 10 85 C0 }
	condition:
		$pattern
}

rule __stdio_adjust_position_f337673bc5d61cb6714fdc0e2078693f {
	meta:
		aliases = "__stdio_adjust_position"
		type = "func"
		size = "153"
		objfiles = "_adjust_pos@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 5C 24 14 8B 33 0F B7 C6 31 D2 89 C1 83 E1 03 74 27 89 CA 4A 74 22 F6 C4 08 74 1D 83 FA 02 74 6A 83 7B 28 00 75 64 0F B6 53 03 F7 DA 83 7B 2C 00 7E 06 0F B6 43 02 29 C2 66 F7 C6 40 00 74 05 8B 43 08 EB 03 8B 43 14 2B 53 10 8D 34 02 8B 44 24 18 8B 08 8B 58 04 89 F0 99 89 CF 89 DD 29 F7 19 D5 89 EA 8B 6C 24 18 89 7D 00 89 55 04 39 DA 7C 08 7F 04 39 CF 76 02 F7 DE 85 F6 79 10 E8 ?? ?? ?? ?? C7 00 4B 00 00 00 EB 03 83 CE FF 89 F0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _obstack_begin_1_58c5c25c469df4eb832faf366d93872b {
	meta:
		aliases = "_obstack_begin_1"
		type = "func"
		size = "143"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 5C 24 14 8B 54 24 18 8B 74 24 1C 8B 4C 24 20 8B 6C 24 28 85 F6 75 04 66 BE 04 00 85 D2 75 04 66 BA E0 0F 89 4B 1C 8B 44 24 24 89 43 20 89 13 8D 7E FF 89 7B 18 89 6B 24 80 4B 28 01 F6 43 28 01 74 0A 52 55 FF D1 89 C2 58 59 EB 06 52 FF D1 89 C2 58 89 53 04 85 D2 75 05 E8 ?? ?? ?? ?? 8D 44 3A 08 F7 DE 21 F0 89 43 08 89 43 0C 89 D0 03 03 89 02 89 43 10 C7 42 04 00 00 00 00 80 63 28 F9 B8 01 00 00 00 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule random_r_6b6a63362071605ce2ab2cdaa5d33b23 {
	meta:
		aliases = "__GI_random_r, random_r"
		type = "func"
		size = "95"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 5C 24 14 8B 6C 24 18 8B 73 08 80 7B 0C 00 75 17 69 06 6D 4E C6 41 05 39 30 00 00 25 FF FF FF 7F 89 06 89 45 00 EB 2C 8B 03 8B 4B 04 8B 7B 10 8B 10 03 11 89 10 D1 EA 89 55 00 83 C0 04 39 F8 8D 51 04 72 04 89 F0 EB 06 39 FA 72 02 89 F2 89 03 89 53 04 31 C0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule sgetspent_r_637203732147f55787736c71f6fee03f {
	meta:
		aliases = "__GI_sgetspent_r, sgetspent_r"
		type = "func"
		size = "105"
		objfiles = "sgetspent_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 5C 24 14 8B 74 24 1C 8B 7C 24 20 8B 6C 24 24 C7 45 00 00 00 00 00 81 FF FF 00 00 00 77 12 E8 ?? ?? ?? ?? C7 00 22 00 00 00 B8 22 00 00 00 EB 2F 39 F3 74 14 53 E8 ?? ?? ?? ?? 5A 39 F8 73 DF 53 56 E8 ?? ?? ?? ?? 5B 5F 56 FF 74 24 1C E8 ?? ?? ?? ?? 5A 59 85 C0 75 07 8B 54 24 18 89 55 00 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule ether_aton_r_f72d467cc72f9be1d5713e96012d2b41 {
	meta:
		aliases = "__GI_ether_aton_r, ether_aton_r"
		type = "func"
		size = "140"
		objfiles = "ether_addr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 5C 24 14 8B 7C 24 18 31 ED EB 6C 8A 03 3C 1F 76 6D 88 C2 83 CA 20 8D 4A D0 80 F9 09 76 07 8D 42 9F 3C 05 77 59 89 CE 80 FA 39 76 03 8D 72 A9 8A 43 01 83 C3 02 83 FD 05 74 04 3C 3A EB 02 84 C0 74 2F 88 C2 83 CA 20 8D 4A D0 80 F9 09 76 07 8D 42 9F 3C 05 77 28 80 FA 39 76 03 8D 4A A9 89 F0 C1 E0 04 8D 34 01 83 FD 05 74 06 80 3B 3A 75 0E 43 89 F0 88 04 2F 45 83 FD 05 7E 8F EB 02 31 FF 89 F8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule getgrouplist_a2a3c9f8331c89424546a687b5d9a75c {
	meta:
		aliases = "getgrouplist"
		type = "func"
		size = "108"
		objfiles = "getgrouplist@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 5C 24 18 8B 6C 24 20 8B 75 00 55 53 FF 74 24 1C E8 ?? ?? ?? ?? 89 C7 83 C4 0C 85 C0 75 11 85 F6 74 3B 8B 44 24 1C 89 18 BB 01 00 00 00 EB 31 8B 5D 00 39 F3 7E 02 89 F3 85 DB 74 15 8D 04 9D 00 00 00 00 50 57 FF 74 24 24 E8 ?? ?? ?? ?? 83 C4 0C 57 E8 ?? ?? ?? ?? 58 3B 5D 00 7D 03 83 CB FF 89 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule lldiv_f333841d9a07cbf89331fe9c04214ea1 {
	meta:
		aliases = "imaxdiv, lldiv"
		type = "func"
		size = "98"
		objfiles = "lldiv@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 5C 24 18 8B 74 24 1C FF 74 24 24 FF 74 24 24 56 53 E8 ?? ?? ?? ?? 83 C4 10 89 C7 89 D5 FF 74 24 24 FF 74 24 24 56 53 E8 ?? ?? ?? ?? 83 C4 10 85 F6 78 12 85 D2 79 0E 83 C7 01 83 D5 00 2B 44 24 20 1B 54 24 24 8B 4C 24 14 89 41 08 89 51 0C 89 39 89 69 04 89 C8 5B 5E 5F 5D C2 04 00 }
	condition:
		$pattern
}

rule svc_getreq_poll_fe60ac6ea61ca03e23c39c550bf6ed3c {
	meta:
		aliases = "__GI_svc_getreq_poll, svc_getreq_poll"
		type = "func"
		size = "88"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 6C 24 14 31 F6 31 FF EB 36 8D 44 F5 00 8B 18 83 FB FF 74 2A 66 8B 40 06 66 85 C0 74 21 47 A8 20 74 15 E8 ?? ?? ?? ?? 8B 80 B4 00 00 00 FF 34 98 E8 ?? ?? ?? ?? EB 06 53 E8 ?? ?? ?? ?? 58 46 E8 ?? ?? ?? ?? 3B 30 7D 06 3B 7C 24 18 7C BB 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule getenv_ae81495e6123469fc8517786b2361132 {
	meta:
		aliases = "__GI_getenv, getenv"
		type = "func"
		size = "71"
		objfiles = "getenv@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 6C 24 14 8B 35 ?? ?? ?? ?? 85 F6 74 2E 55 E8 ?? ?? ?? ?? 5A 89 C7 EB 1D 57 53 55 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 0B 8D 04 3B 80 38 3D 75 03 40 EB 0B 83 C6 04 8B 1E 85 DB 75 DD 31 C0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule asctime_r_64798aad599e2560d05434ec201b33f9 {
	meta:
		aliases = "__GI_asctime_r, asctime_r"
		type = "func"
		size = "191"
		objfiles = "asctime_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 6C 24 14 8B 5C 24 18 6A 1A 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8B 45 18 83 C4 0C 83 F8 06 77 0E 8D 34 40 81 C6 ?? ?? ?? ?? 89 DF 66 A5 A4 8B 45 10 83 F8 0B 77 0F 8D 34 40 81 C6 ?? ?? ?? ?? 8D 7B 04 66 A5 A4 8D 4B 13 8B 55 14 81 C2 6C 07 00 00 81 FA 0F 27 00 00 77 1A 8D 4B 17 BB 0A 00 00 00 89 D0 99 F7 FB 83 C2 30 88 11 89 C2 49 80 39 3F 74 E9 8D 71 FF 0F B6 41 FF 8B 54 05 00 83 FA 63 76 0A C6 41 FF 3F C6 46 FF 3F EB 13 BB 0A 00 00 00 89 D0 99 F7 FB 83 C2 30 88 51 FF 00 41 FE 8D 4E FE 80 79 FE 30 74 CA 80 7E FF 30 75 04 C6 46 FF 20 8D 46 F7 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule writetcp_8ac93d29ab01bd1fdd4e942bd62849a3 {
	meta:
		aliases = "writetcp"
		type = "func"
		size = "66"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 6C 24 14 8B 74 24 18 8B 7C 24 1C 89 FB EB 23 53 56 FF 75 00 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 79 0E 8B 45 2C C7 00 00 00 00 00 83 CF FF EB 08 29 C3 01 C6 85 DB 7F D9 89 F8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule writetcp_02e5ad2c6c5d51561312b70f440bf0a4 {
	meta:
		aliases = "writetcp"
		type = "func"
		size = "75"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 6C 24 14 8B 74 24 18 8B 7C 24 1C 89 FB EB 2C 53 56 FF 75 00 E8 ?? ?? ?? ?? 83 C4 0C 83 F8 FF 75 16 E8 ?? ?? ?? ?? 8B 00 89 45 28 C7 45 24 03 00 00 00 83 CF FF EB 08 29 C3 01 C6 85 DB 7F D0 89 F8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule writeunix_6bf1579ff05e7dc331e173fbb4d1d5d1 {
	meta:
		aliases = "writeunix"
		type = "func"
		size = "80"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 6C 24 14 8B 74 24 18 8B 7C 24 1C 89 FB EB 31 89 D9 89 F2 8B 45 00 E8 ?? ?? ?? ?? 83 F8 FF 75 1C E8 ?? ?? ?? ?? 8B 00 89 85 88 00 00 00 C7 85 84 00 00 00 03 00 00 00 83 CF FF EB 08 29 C3 01 C6 85 DB 7F CB 89 F8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule initstate_r_0f8f6c975f6677ea4d3a0e636dc05f34 {
	meta:
		aliases = "__GI_initstate_r, initstate_r"
		type = "func"
		size = "165"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 6C 24 18 8B 44 24 1C 8B 7C 24 20 83 F8 7F 76 0C 3D 00 01 00 00 19 DB 83 C3 04 EB 16 83 F8 1F 77 09 31 DB 83 F8 07 77 0A EB 58 83 F8 40 19 DB 83 C3 02 0F BE 83 ?? ?? ?? ?? 8A 93 ?? ?? ?? ?? 88 5F 0C 88 57 0E 88 47 0D 8D 75 04 8D 04 86 89 47 10 89 77 08 57 FF 74 24 18 E8 ?? ?? ?? ?? C7 45 00 00 00 00 00 58 5A 31 C0 85 DB 74 2E 8B 47 04 29 F0 C1 F8 02 8D 04 80 8D 04 03 89 45 00 31 C0 EB 19 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule xdrrec_getbytes_64801c0b043022129aa5845d5f99bf9c {
	meta:
		aliases = "xdrrec_getbytes"
		type = "func"
		size = "95"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 6C 24 18 8B 7C 24 1C 8B 44 24 14 8B 70 0C EB 38 8B 46 34 85 C0 75 13 83 7E 38 00 75 36 89 F0 E8 ?? ?? ?? ?? 85 C0 75 20 EB 29 89 FB 39 C7 76 02 89 C3 89 D9 89 EA 89 F0 E8 ?? ?? ?? ?? 85 C0 74 12 01 DD 29 5E 34 29 DF 85 FF 75 C4 B8 01 00 00 00 EB 02 31 C0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule xdrrec_putbytes_19effbb6e895901b3b1b251b33de7131 {
	meta:
		aliases = "xdrrec_putbytes"
		type = "func"
		size = "103"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 6C 24 18 8B 7C 24 1C 8B 44 24 14 8B 70 0C EB 44 8B 56 10 8B 46 14 29 D0 89 FB 39 C7 76 02 89 C3 53 55 52 E8 ?? ?? ?? ?? 89 D8 03 46 10 89 46 10 01 DD 29 DF 83 C4 0C 3B 46 14 75 18 85 FF 74 18 C7 46 1C 01 00 00 00 31 D2 89 F0 E8 ?? ?? ?? ?? 85 C0 74 09 85 FF 75 B8 B8 01 00 00 00 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule syscall_fa970c4170346219d0a1ba116897c543 {
	meta:
		aliases = "syscall"
		type = "func"
		size = "50"
		objfiles = "syscall@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 6C 24 2C 8B 7C 24 28 8B 74 24 24 8B 54 24 20 8B 4C 24 1C 8B 5C 24 18 8B 44 24 14 CD 80 5B 5E 5F 5D 3D 01 F0 FF FF 0F 83 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule pthread_cancel_fd339c86b518ca8ad06a95e9a9d15884 {
	meta:
		aliases = "pthread_cancel"
		type = "func"
		size = "162"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 74 24 14 89 F0 25 FF 03 00 00 C1 E0 04 8D B8 ?? ?? ?? ?? 31 D2 89 F8 E8 ?? ?? ?? ?? 8B 5F 08 85 DB 74 05 39 73 10 74 5C 57 E8 ?? ?? ?? ?? B8 03 00 00 00 EB 3A 57 E8 ?? ?? ?? ?? EB 30 8B 83 44 01 00 00 8B 6B 14 31 F6 85 C0 74 10 53 FF 30 FF 50 04 89 C6 88 83 40 01 00 00 58 5A 57 E8 ?? ?? ?? ?? 58 85 F6 74 0B 53 E8 ?? ?? ?? ?? 31 C0 5F EB 26 FF 35 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 31 C0 5B 5E EB 14 0F B6 43 42 C6 43 42 01 80 7B 40 01 74 A3 85 C0 75 9F EB A5 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule xprt_register_e12e9d1edbf21891bc5c69b530c903ad {
	meta:
		aliases = "__GI_xprt_register, xprt_register"
		type = "func"
		size = "211"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 74 24 14 8B 2E E8 ?? ?? ?? ?? 89 C3 83 B8 B4 00 00 00 00 75 1D E8 ?? ?? ?? ?? C1 E0 02 50 E8 ?? ?? ?? ?? 89 83 B4 00 00 00 5F 85 C0 0F 84 97 00 00 00 E8 ?? ?? ?? ?? 39 C5 0F 8D 8A 00 00 00 8B 83 B4 00 00 00 89 34 A8 81 FD FF 03 00 00 7F 13 E8 ?? ?? ?? ?? 89 E9 C1 E9 05 89 EA 83 E2 1F 0F AB 14 88 31 DB EB 23 E8 ?? ?? ?? ?? 8D 0C DD 00 00 00 00 89 CA 03 10 83 3A FF 75 0D 89 2A 8B 00 66 C7 44 08 04 C3 00 EB 40 43 E8 ?? ?? ?? ?? 89 C7 8B 00 39 C3 7C D0 8D 58 01 89 1F E8 ?? ?? ?? ?? 89 C6 C1 E3 03 53 FF 30 E8 ?? ?? ?? ?? 89 C2 89 06 58 59 85 D2 74 11 8B 07 89 6C C2 F8 8B 17 8B 06 66 }
	condition:
		$pattern
}

rule getcwd_3b096e9205fbd87755a3a828137b0166 {
	meta:
		aliases = "__GI_getcwd, getcwd"
		type = "func"
		size = "163"
		objfiles = "getcwd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 74 24 14 8B 6C 24 18 85 ED 75 26 85 F6 74 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 79 E8 ?? ?? ?? ?? 89 C3 3D 00 10 00 00 7D 0F BB 00 10 00 00 EB 08 89 EB 89 F7 85 F6 75 0D 53 E8 ?? ?? ?? ?? 5F 85 C0 74 51 89 C7 89 FA 89 D9 87 D3 B8 B7 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0B E8 ?? ?? ?? ?? F7 DB 89 18 EB 1F 85 C0 78 1B 85 F6 75 26 85 ED 75 0F 50 57 E8 ?? ?? ?? ?? 89 C6 5A 59 85 C0 75 13 89 FE EB 0F 85 F6 75 09 57 E8 ?? ?? ?? ?? 58 EB 02 31 F6 89 F0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __encode_answer_1f64515239bf1ee7774728b266b91118 {
	meta:
		aliases = "__encode_answer"
		type = "func"
		size = "153"
		objfiles = "encodea@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 74 24 14 8B 6C 24 18 8B 5C 24 1C 53 55 FF 36 E8 ?? ?? ?? ?? 89 C7 83 C4 0C 85 C0 78 70 29 C3 8B 46 10 83 C0 0A 39 C3 7D 05 83 CF FF EB 5F 8D 54 3D 00 0F B6 46 05 88 02 8B 46 04 88 42 01 0F B6 46 09 88 42 02 8B 46 08 88 42 03 0F B6 46 0F 88 42 04 0F B6 46 0E 88 42 05 0F B6 46 0D 88 42 06 8B 46 0C 88 42 07 0F B6 46 11 88 42 08 8B 46 10 88 42 09 FF 76 10 FF 76 14 83 C2 0A 52 E8 ?? ?? ?? ?? 8B 46 10 83 C0 0A 01 C7 83 C4 0C 89 F8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule register_printf_function_0df16f4598be47b9896152daa99f65f9 {
	meta:
		aliases = "register_printf_function"
		type = "func"
		size = "106"
		objfiles = "register_printf_function@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 85 F6 74 4E 85 ED 74 4A 8B 0D ?? ?? ?? ?? 8D 51 0A 31 DB 4A 8A 02 84 C0 75 02 89 D3 0F B6 C0 39 F0 75 04 89 D3 89 CA 39 CA 77 E8 85 DB 74 23 85 FF 74 18 89 F0 88 03 89 D8 29 D0 89 3C 85 ?? ?? ?? ?? 89 2C 85 ?? ?? ?? ?? EB 03 C6 03 00 31 C0 EB 03 83 C8 FF 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule wcsncasecmp_f81dbf6be026e6d1c9d68b296f455965 {
	meta:
		aliases = "wcsncasecmp"
		type = "func"
		size = "95"
		objfiles = "wcsncasecmp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C EB 0C 83 3E 00 74 0B 83 C6 04 83 C7 04 4D 85 ED 75 04 31 C0 EB 34 8B 06 3B 07 74 E6 50 E8 ?? ?? ?? ?? 89 C3 FF 37 E8 ?? ?? ?? ?? 5A 59 39 C3 74 D1 FF 36 E8 ?? ?? ?? ?? 89 C3 FF 37 E8 ?? ?? ?? ?? 5A 59 39 C3 19 C0 83 C8 01 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _fp_out_narrow_0432d203b38d9f29042de977e9776548 {
	meta:
		aliases = "_fp_out_narrow"
		type = "func"
		size = "94"
		objfiles = "_vfprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 74 24 18 8B 5C 24 1C 31 ED 89 F0 84 C0 79 2A FF 74 24 20 E8 ?? ?? ?? ?? 59 89 C7 29 C3 85 DB 7E 16 83 E6 7F 89 D9 89 F2 8B 44 24 14 E8 ?? ?? ?? ?? 89 C5 39 D8 75 1B 89 FB 31 C0 85 DB 7E 11 FF 74 24 14 53 FF 74 24 28 E8 ?? ?? ?? ?? 83 C4 0C 01 C5 89 E8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule bsearch_3ce92aaeb04f93bb36f2fd0cac3a3637 {
	meta:
		aliases = "bsearch"
		type = "func"
		size = "81"
		objfiles = "bsearch@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 74 24 1C 31 ED 83 7C 24 20 00 75 35 EB 37 89 F0 29 E8 D1 E8 8D 1C 28 8B 44 24 20 0F AF C3 8B 7C 24 18 01 C7 57 FF 74 24 18 FF 54 24 2C 5A 59 83 F8 00 7E 05 8D 6B 01 EB 08 75 04 89 F8 EB 08 89 DE 39 F5 72 C9 31 C0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule xdr_array_8fab093fb016287995d6101e8639a4c7 {
	meta:
		aliases = "__GI_xdr_array, xdr_array"
		type = "func"
		size = "248"
		objfiles = "xdr_array@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 74 24 1C 8B 44 24 18 8B 18 56 FF 74 24 18 E8 ?? ?? ?? ?? 5A 59 85 C0 0F 84 C6 00 00 00 8B 3E 3B 7C 24 20 77 0D 83 C8 FF 31 D2 F7 74 24 24 39 C7 76 0D 8B 54 24 14 83 3A 02 0F 85 A4 00 00 00 85 DB 75 59 8B 54 24 14 8B 02 83 F8 01 74 0A 83 F8 02 75 49 E9 8F 00 00 00 85 FF 0F 84 87 00 00 00 8B 74 24 24 0F AF F7 56 E8 ?? ?? ?? ?? 89 C3 8B 44 24 1C 89 18 5D 85 DB 75 16 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 F6 5A 59 EB 5C 56 6A 00 53 E8 ?? ?? ?? ?? 83 C4 0C 31 ED BE 01 00 00 00 EB 15 6A FF 53 FF 74 24 1C FF 54 24 34 89 C6 03 5C 24 30 45 83 C4 0C 39 FD 73 04 85 F6 75 E3 8B }
	condition:
		$pattern
}

rule __encode_dotted_a88d343bdac8facdc0432018fc3614a6 {
	meta:
		aliases = "__encode_dotted"
		type = "func"
		size = "130"
		objfiles = "encoded@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 7C 24 14 31 DB EB 51 6A 2E 57 E8 ?? ?? ?? ?? 59 5E 89 C5 85 C0 74 06 89 C6 29 FE EB 09 57 E8 ?? ?? ?? ?? 5A 89 C6 85 F6 74 4B 8B 44 24 1C 29 D8 48 39 C6 73 40 89 F0 8B 54 24 18 88 04 1A 43 56 57 89 D0 01 D8 50 E8 ?? ?? ?? ?? 8D 1C 1E 83 C4 0C 85 ED 74 0C 8D 7D 01 85 FF 74 05 80 3F 00 75 A6 83 7C 24 1C 00 7E 0D 8B 44 24 18 C6 04 18 00 8D 43 01 EB 03 83 C8 FF 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __encode_header_536b7550d07ab7a997c8f09f24a5df68 {
	meta:
		aliases = "__encode_header"
		type = "func"
		size = "182"
		objfiles = "encodeh@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 7C 24 14 8B 6C 24 18 83 C8 FF 83 7C 24 1C 0B 0F 8E 97 00 00 00 0F B6 47 01 88 45 00 8B 07 88 45 01 83 7F 04 01 19 F6 F7 D6 83 E6 80 83 7F 0C 01 19 DB F7 D3 83 E3 04 83 7F 10 01 19 C9 F7 D1 83 E1 02 8B 57 08 83 E2 0F C1 E2 03 83 7F 14 00 0F 95 C0 09 D0 09 F0 09 D8 09 C8 88 45 02 83 7F 18 01 19 C0 F7 D0 83 E0 80 8A 57 1C 83 E2 0F 09 D0 88 45 03 0F B6 47 21 88 45 04 8B 47 20 88 45 05 0F B6 47 25 88 45 06 8B 47 24 88 45 07 0F B6 47 29 88 45 08 8B 47 28 88 45 09 0F B6 47 2D 88 45 0A 8B 47 2C 88 45 0B B8 0C 00 00 00 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule pthread_setschedparam_9ddc41bf18899d5af4701d98265e9e95 {
	meta:
		aliases = "__GI_pthread_setschedparam, pthread_setschedparam"
		type = "func"
		size = "149"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 7C 24 14 8B 6C 24 18 89 F8 25 FF 03 00 00 C1 E0 04 8D B0 ?? ?? ?? ?? 31 D2 89 F0 E8 ?? ?? ?? ?? 8B 5E 08 85 DB 74 05 39 7B 10 74 4A 56 E8 ?? ?? ?? ?? B8 03 00 00 00 EB 0D 56 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 00 5A EB 42 31 C0 85 ED 74 06 8B 54 24 1C 8B 02 89 43 18 56 E8 ?? ?? ?? ?? 58 31 C0 83 3D ?? ?? ?? ?? 00 78 21 FF 73 18 E8 ?? ?? ?? ?? 31 C0 EB D0 FF 74 24 1C 55 FF 73 14 E8 ?? ?? ?? ?? 83 C4 0C 40 75 C0 EB AE 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule lsearch_9814a1430a7e0bbb93ecbd58d0b9783f {
	meta:
		aliases = "lsearch"
		type = "func"
		size = "65"
		objfiles = "lsearch@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 7C 24 14 8B 6C 24 18 8B 74 24 1C 8B 5C 24 20 FF 74 24 24 53 56 55 57 E8 ?? ?? ?? ?? 83 C4 14 85 C0 75 14 53 57 0F AF 1E 8D 44 1D 00 50 E8 ?? ?? ?? ?? FF 06 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule xdr_reference_251d6b1dc109530ad9571bf40b5d80ee {
	meta:
		aliases = "__GI_xdr_reference, xdr_reference"
		type = "func"
		size = "131"
		objfiles = "xdr_reference@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 7C 24 14 8B 6C 24 18 8B 74 24 1C 8B 5D 00 85 DB 75 45 8B 07 83 F8 01 74 0C BE 01 00 00 00 83 F8 02 74 54 EB 32 56 E8 ?? ?? ?? ?? 89 C3 89 45 00 58 85 DB 75 16 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 F6 5A 59 EB 2C 56 6A 00 53 E8 ?? ?? ?? ?? 83 C4 0C 6A FF 53 57 FF 54 24 2C 89 C6 83 C4 0C 83 3F 02 75 0E 53 E8 ?? ?? ?? ?? C7 45 00 00 00 00 00 58 89 F0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __stdio_WRITE_56d6be3b6d61b7ee214ef9590c3b32d4 {
	meta:
		aliases = "__stdio_WRITE"
		type = "func"
		size = "117"
		objfiles = "_WRITE@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 7C 24 14 8B 74 24 18 8B 6C 24 1C 89 EB 83 FB 00 74 57 7D 07 B8 FF FF FF 7F EB 02 89 D8 50 56 FF 77 04 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 78 06 29 C3 01 C6 EB D9 66 83 0F 08 8B 57 08 8B 47 0C 89 C1 29 D1 74 23 39 D9 76 02 89 D9 8A 06 88 02 3C 0A 75 06 F6 47 01 01 75 07 42 49 74 03 46 EB EB 89 57 10 2B 57 08 29 D3 29 DD 89 E8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fgets_unlocked_180b4b978508fa29c98a6e5c2ff7cbd9 {
	meta:
		aliases = "__GI_fgets_unlocked, fgets_unlocked"
		type = "func"
		size = "94"
		objfiles = "fgets_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 7C 24 14 8B 74 24 18 8B 6C 24 1C 89 FB 85 F6 7F 33 EB 3D 8B 45 10 3B 45 18 73 0E 8A 10 88 13 43 40 89 45 10 80 FA 0A EB 19 55 E8 ?? ?? ?? ?? 5A 83 F8 FF 75 08 F6 45 00 08 74 0C EB 13 88 03 43 3C 0A 74 03 4E 75 CC 39 FB 76 05 C6 03 00 EB 02 31 FF 89 F8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fgetws_unlocked_f2cc12b65d9d458357c2508ca80503df {
	meta:
		aliases = "__GI_fgetws_unlocked, fgetws_unlocked"
		type = "func"
		size = "69"
		objfiles = "fgetws_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 7C 24 14 8B 74 24 18 8B 6C 24 1C 89 FB EB 01 4E 83 FE 01 7E 16 55 E8 ?? ?? ?? ?? 5A 83 F8 FF 74 0A 89 03 83 C3 04 83 F8 0A 75 E4 39 FB 75 04 31 FF EB 06 C7 03 00 00 00 00 89 F8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule svcudp_enablecache_b9c9c788bd90e9c10442d38a3208fcb1 {
	meta:
		aliases = "svcudp_enablecache"
		type = "func"
		size = "172"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 7C 24 18 8B 44 24 14 8B 68 30 83 BD B0 01 00 00 00 74 07 68 ?? ?? ?? ?? EB 5D 6A 2C E8 ?? ?? ?? ?? 89 C3 59 85 C0 75 07 68 ?? ?? ?? ?? EB 48 89 38 C7 40 0C 00 00 00 00 89 FE C1 E6 04 56 E8 ?? ?? ?? ?? 89 43 04 5A 85 C0 75 07 68 ?? ?? ?? ?? EB 25 56 6A 00 50 E8 ?? ?? ?? ?? 8D 34 BD 00 00 00 00 56 E8 ?? ?? ?? ?? 89 43 08 83 C4 10 85 C0 75 19 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 EB 14 56 6A 00 50 E8 ?? ?? ?? ?? 89 9D B0 01 00 00 B8 01 00 00 00 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule truncate64_131901292ffdb23441069b447edda8e0 {
	meta:
		aliases = "truncate64"
		type = "func"
		size = "69"
		objfiles = "truncate64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 7C 24 18 8B 6C 24 1C 89 FB 89 EE 89 F3 89 DE C1 FE 1F 8B 44 24 14 89 F9 89 DA 53 89 C3 B8 C1 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule ftruncate64_5d28d2bf23d17ad4c3f1a74bd4ce7449 {
	meta:
		aliases = "__GI_ftruncate64, ftruncate64"
		type = "func"
		size = "69"
		objfiles = "ftruncate64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 7C 24 18 8B 6C 24 1C 89 FB 89 EE 89 F3 89 DE C1 FE 1F 8B 44 24 14 89 F9 89 DA 53 89 C3 B8 C2 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule getpwuid_r_23a0aeab15032686cb04abc9bea484b7 {
	meta:
		aliases = "__GI_getgrgid_r, __GI_getpwuid_r, getgrgid_r, getpwuid_r"
		type = "func"
		size = "127"
		objfiles = "getgrgid_r@libc.a, getpwuid_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 7C 24 18 8B 6C 24 24 C7 45 00 00 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 5A 59 85 C0 75 09 E8 ?? ?? ?? ?? 8B 18 EB 45 C7 40 34 01 00 00 00 56 FF 74 24 24 FF 74 24 24 57 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 83 C4 14 85 C0 75 0E 8B 44 24 14 39 47 08 75 DA 89 7D 00 EB 0C 31 C0 83 FB 02 0F 95 C0 F7 D8 21 C3 56 E8 ?? ?? ?? ?? 58 89 D8 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule getspnam_r_e612ed03d06dd4fd4054bcb61abc8918 {
	meta:
		aliases = "__GI_getgrnam_r, __GI_getpwnam_r, __GI_getspnam_r, getgrnam_r, getpwnam_r, getspnam_r"
		type = "func"
		size = "135"
		objfiles = "getpwnam_r@libc.a, getgrnam_r@libc.a, getspnam_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 7C 24 18 8B 6C 24 24 C7 45 00 00 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 5B 58 85 F6 75 09 E8 ?? ?? ?? ?? 8B 18 EB 4D C7 46 34 01 00 00 00 56 FF 74 24 24 FF 74 24 24 57 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 83 C4 14 85 C0 75 16 FF 74 24 14 FF 37 E8 ?? ?? ?? ?? 5A 59 85 C0 75 D2 89 7D 00 EB 0C 31 C0 83 FB 02 0F 95 C0 F7 D8 21 C3 56 E8 ?? ?? ?? ?? 58 89 D8 5B 5E 5F 5D C3 }
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

rule __ctzsi2_430b2af1f308fe442df8d8ad794efb17 {
	meta:
		aliases = "__ctzsi2"
		type = "func"
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
		type = "func"
		size = "12"
		objfiles = "_clzsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 0F BD 45 08 83 F0 1F 5D C3 }
	condition:
		$pattern
}

rule __udiv_w_sdiv_140843736b3275eead73f559484bfef9 {
	meta:
		aliases = "__gthread_active_p, __udiv_w_sdiv"
		type = "func"
		size = "7"
		objfiles = "gthr_gnat@libgcc_eh.a, _udiv_w_sdiv@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 31 C0 5D C3 }
	condition:
		$pattern
}

rule __do_global_ctors_aux_792460ecaaa16973e03ae87a43f50c17 {
	meta:
		aliases = "__do_global_ctors_aux"
		type = "func"
		size = "52"
		objfiles = "crtend"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 A1 ?? ?? ?? ?? 83 F8 FF 74 1F 31 DB 8D B6 00 00 00 00 8D BC 27 00 00 00 00 FF D0 8B 83 ?? ?? ?? ?? 83 EB 04 83 F8 FF 75 F0 58 5B 5D C3 }
	condition:
		$pattern
}

rule base_from_object_3d34ec143573a63d75bfae9d5e1ae1b4 {
	meta:
		aliases = "base_from_object"
		type = "func"
		size = "90"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 3C FF 74 1D 83 E0 70 83 F8 20 74 21 7E 0F 83 F8 30 74 21 83 F8 50 74 09 E8 ?? ?? ?? ?? 85 C0 75 1C 31 C0 5A 5B 5D C3 8D B6 00 00 00 00 8B 42 04 5A 5B 5D C3 8B 42 08 5A 5B 5D C3 89 F6 83 F8 10 74 DF E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule base_of_encoded_value_ddd1eb31318c95544dbd3977ae9722fb {
	meta:
		aliases = "base_of_encoded_value"
		type = "func"
		size = "146"
		objfiles = "unwind_c@libgcc_eh.a, unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 3C FF 74 2D 83 E0 70 83 F8 20 74 51 7E 1F 83 F8 40 74 31 83 F8 50 74 19 83 F8 30 74 51 E8 ?? ?? ?? ?? 8D 74 26 00 8D BC 27 00 00 00 00 85 C0 75 0C 31 C0 8B 5D FC C9 C3 90 8D 74 26 00 83 F8 10 75 DB EB ED 83 EC 0C 52 E8 ?? ?? ?? ?? 83 C4 10 8B 5D FC C9 C3 90 8D B4 26 00 00 00 00 83 EC 0C 52 E8 ?? ?? ?? ?? 83 C4 10 8B 5D FC C9 C3 83 EC 0C 52 E8 ?? ?? ?? ?? 83 C4 10 8B 5D FC C9 C3 }
	condition:
		$pattern
}

rule size_of_encoded_value_03c678977cbe5b9160e4e1b05016f7b7 {
	meta:
		aliases = "size_of_encoded_value"
		type = "func"
		size = "93"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 3C FF 74 42 83 E0 07 83 F8 02 74 31 7E 0F 83 F8 03 74 0E 83 F8 04 74 12 E8 ?? ?? ?? ?? 85 C0 75 F7 B8 04 00 00 00 59 5B 5D C3 B8 08 00 00 00 59 5B 5D C3 8D 76 00 8D BC 27 00 00 00 00 B8 02 00 00 00 59 5B 5D C3 31 C0 EB DC }
	condition:
		$pattern
}

rule __register_frame_info_table_e980501d6f7808850243e5ed8c240a0e {
	meta:
		aliases = "__register_frame_info, __register_frame_info_table"
		type = "func"
		size = "44"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 6A 00 6A 00 8B 45 0C 50 8B 45 08 50 E8 ?? ?? ?? ?? 83 C4 10 8B 5D FC C9 C3 }
	condition:
		$pattern
}

rule __do_global_dtors_aux_d9af0062c8b44659da35c6870a9b4fb8 {
	meta:
		aliases = "__do_global_dtors_aux"
		type = "func"
		size = "222"
		objfiles = "crtbeginS"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 80 BB ?? ?? ?? ?? 00 75 5E 8B 8B ?? ?? ?? ?? 85 C9 74 25 83 EC 0C 8B 93 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 10 EB 11 8D B6 00 00 00 00 83 C0 04 89 83 ?? ?? ?? ?? FF D2 8B 83 ?? ?? ?? ?? 8B 10 85 D2 75 E9 8B 83 ?? ?? ?? ?? 85 C0 74 12 83 EC 0C 8D 83 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 10 C6 83 ?? ?? ?? ?? 01 8B 5D FC C9 C3 90 55 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 83 ?? ?? ?? ?? 85 C0 74 19 53 6A 00 8D 83 ?? ?? ?? ?? 50 8D 83 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 10 8B 83 ?? ?? ?? ?? 85 C0 74 19 8B 93 ?? ?? ?? ?? 85 D2 }
	condition:
		$pattern
}

rule __negvsi2_f0671ae39c28d963c620bb437d76e80f {
	meta:
		aliases = "__negvsi2"
		type = "func"
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
		type = "func"
		size = "53"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 45 08 8B 10 85 D2 74 14 83 EC 0C 50 E8 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 8B 5D FC C9 C3 }
	condition:
		$pattern
}

rule __subvsi3_55f81f12371ddc996daf53030de2fa02 {
	meta:
		aliases = "__subvsi3"
		type = "func"
		size = "60"
		objfiles = "_subvsi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 4D 08 8B 45 0C 89 CA 29 C2 85 C0 78 0F 39 CA 0F 9F C0 84 C0 75 0D 89 D0 5A 5B 5D C3 39 CA 0F 9C C0 EB EF E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __addvsi3_b444b906f73c3f57e410b3a961239344 {
	meta:
		aliases = "__addvsi3"
		type = "func"
		size = "60"
		objfiles = "_addvsi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 4D 08 8B 45 0C 8D 14 08 85 C0 78 10 39 CA 0F 9C C0 84 C0 75 0E 89 D0 5A 5B 5D C3 90 39 CA 0F 9F C0 EB EE E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _Unwind_SetGR_04013b80f7c6eefcf456caff9a1450b1 {
	meta:
		aliases = "_Unwind_SetGR"
		type = "func"
		size = "86"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 55 08 8B 45 0C 83 F8 11 7F 33 8A 8C 03 ?? ?? ?? ?? F6 42 63 40 75 15 8B 04 82 80 F9 04 75 1E 8B 55 10 89 10 58 5B 5D C3 8D 74 26 00 80 7C 02 6C 00 74 E4 8B 4D 10 89 0C 82 58 5B 5D C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule frame_dummy_5e416c84c4b4da90a8f0fc11d5fa6906 {
	meta:
		aliases = "frame_dummy"
		type = "func"
		size = "94"
		objfiles = "crtbeginS"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 83 ?? ?? ?? ?? 85 C0 74 19 53 6A 00 8D 83 ?? ?? ?? ?? 50 8D 83 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 10 8B 83 ?? ?? ?? ?? 85 C0 74 19 8B 93 ?? ?? ?? ?? 85 D2 74 0F 83 EC 0C 8D 83 ?? ?? ?? ?? 50 FF D2 83 C4 10 8B 5D FC C9 C3 }
	condition:
		$pattern
}

rule __fixsfdi_f475bde28f8a130bf0575112242f8186 {
	meta:
		aliases = "__fixsfdi"
		type = "func"
		size = "92"
		objfiles = "_fixsfdi@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? D9 45 08 D9 EE DD E9 DF E0 F6 C4 45 74 1F 83 EC 10 D9 1C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 5D FC C9 C3 8D B6 00 00 00 00 8D BF 00 00 00 00 83 EC 10 D9 E0 D9 1C 24 E8 ?? ?? ?? ?? F7 D8 83 D2 00 F7 DA 83 C4 10 8B 5D FC C9 C3 }
	condition:
		$pattern
}

rule __fixxfdi_a3a3280476dfdc8e12179356b9e382fe {
	meta:
		aliases = "__fixxfdi"
		type = "func"
		size = "92"
		objfiles = "_fixxfdi@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? DB 6D 08 D9 EE DD E9 DF E0 F6 C4 45 74 1F 83 EC 10 DB 3C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 5D FC C9 C3 8D B6 00 00 00 00 8D BF 00 00 00 00 83 EC 10 D9 E0 DB 3C 24 E8 ?? ?? ?? ?? F7 D8 83 D2 00 F7 DA 83 C4 10 8B 5D FC C9 C3 }
	condition:
		$pattern
}

rule __fixdfdi_8a3291ee6e23f4e851abce54769e768c {
	meta:
		aliases = "__fixdfdi"
		type = "func"
		size = "92"
		objfiles = "_fixdfdi@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? DD 45 08 D9 EE DD E9 DF E0 F6 C4 45 74 1F 83 EC 10 DD 1C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 5D FC C9 C3 8D B6 00 00 00 00 8D BF 00 00 00 00 83 EC 10 D9 E0 DD 1C 24 E8 ?? ?? ?? ?? F7 D8 83 D2 00 F7 DA 83 C4 10 8B 5D FC C9 C3 }
	condition:
		$pattern
}

rule __gthread_mutex_unlock_acb29e780f57b7c61233a2c86561aebb {
	meta:
		aliases = "__gthread_mutex_unlock"
		type = "func"
		size = "31"
		objfiles = "gthr_gnat@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? FF 93 ?? ?? ?? ?? 31 C0 59 5B 5D C3 }
	condition:
		$pattern
}

rule __gthread_mutex_lock_8faa12d58ab59dbf83e706fa12d1584e {
	meta:
		aliases = "__gthread_mutex_lock"
		type = "func"
		size = "31"
		objfiles = "gthr_gnat@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? FF 93 ?? ?? ?? ?? 31 C0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule __register_frame_table_0cb9895e154004523f1435bd51c242ff {
	meta:
		aliases = "__register_frame_table"
		type = "func"
		size = "46"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 10 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 6A 18 E8 ?? ?? ?? ?? 5A 59 50 8B 45 08 50 E8 ?? ?? ?? ?? 83 C4 10 8B 5D FC C9 C3 }
	condition:
		$pattern
}

rule __deregister_frame_info_efe255031bd14ecca230e024a47a0b2f {
	meta:
		aliases = "__deregister_frame_info"
		type = "func"
		size = "33"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 10 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 45 08 50 E8 ?? ?? ?? ?? 8B 5D FC C9 C3 }
	condition:
		$pattern
}

rule _Unwind_FindEnclosingFunction_64747024d11879f542780ebe16d28aec {
	meta:
		aliases = "_Unwind_FindEnclosingFunction"
		type = "func"
		size = "48"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 1C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8D 45 F0 50 8B 45 08 48 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 03 8B 45 F8 8B 5D FC C9 C3 }
	condition:
		$pattern
}

rule __register_frame_info_bases_c12c3dd625f78cd8edbd6a1417dfe2e4 {
	meta:
		aliases = "__register_frame_info_bases"
		type = "func"
		size = "84"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 45 08 8B 55 0C 85 C0 74 37 8B 08 85 C9 74 31 C7 02 FF FF FF FF 8B 4D 10 89 4A 04 8B 4D 14 89 4A 08 89 42 0C C7 42 10 00 00 00 00 66 81 4A 10 F8 07 8B 83 ?? ?? ?? ?? 89 42 14 89 93 ?? ?? ?? ?? 5B 5D C3 }
	condition:
		$pattern
}

rule pthread_handle_sigcancel_352792c1c1b67822cdf0e873c431d27a {
	meta:
		aliases = "pthread_handle_sigcancel"
		type = "func"
		size = "127"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 E8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 75 09 8B 5D FC C9 E9 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 28 3B 05 ?? ?? ?? ?? 75 15 68 00 00 00 80 6A 00 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 80 78 42 00 74 2A 80 78 40 00 75 24 80 78 41 01 75 08 55 6A FF E8 ?? ?? ?? ?? 8B 50 28 85 D2 74 0F C7 40 28 00 00 00 00 6A 01 52 E8 ?? ?? ?? ?? 8B 5D FC C9 C3 }
	condition:
		$pattern
}

rule _init_6378da484a4f365704364c2fc1aaf10f {
	meta:
		aliases = "_fini, _init"
		type = "func"
		size = "15"
		objfiles = "crti"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 E8 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_exit_af2d50f1b71cf886beb9fbaedaa8978d {
	meta:
		aliases = "__GI_pthread_exit, pthread_exit"
		type = "func"
		size = "12"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 55 FF 75 08 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule execlp_004def64f407b65fc7303d0c7e5ffc52 {
	meta:
		aliases = "__GI_execlp, execlp"
		type = "func"
		size = "95"
		objfiles = "execlp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 04 8D 45 10 89 45 F4 31 F6 46 8B 55 F4 8D 42 04 89 45 F4 83 3A 00 75 F1 8D 04 B5 14 00 00 00 29 C4 8D 5C 24 0F 83 E3 F0 8B 45 0C 89 03 8D 45 10 89 45 F4 89 D9 83 C1 04 8B 45 F4 8D 50 04 89 55 F4 8B 00 89 01 4E 75 ED 53 FF 75 08 E8 ?? ?? ?? ?? 8D 65 F8 5B 5E 5D C3 }
	condition:
		$pattern
}

rule execl_ffb2d5202edd9e8e0369bf2a5057ea38 {
	meta:
		aliases = "__GI_execl, execl"
		type = "func"
		size = "101"
		objfiles = "execl@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 04 8D 45 10 89 45 F4 31 F6 46 8B 55 F4 8D 42 04 89 45 F4 83 3A 00 75 F1 8D 04 B5 14 00 00 00 29 C4 8D 5C 24 0F 83 E3 F0 8B 45 0C 89 03 8D 45 10 89 45 F4 89 D9 83 C1 04 8B 45 F4 8D 50 04 89 55 F4 8B 00 89 01 4E 75 ED FF 35 ?? ?? ?? ?? 53 FF 75 08 E8 ?? ?? ?? ?? 8D 65 F8 5B 5E 5D C3 }
	condition:
		$pattern
}

rule __divsc3_037373cb4a12024714cf1483f95f50e6 {
	meta:
		aliases = "__divsc3"
		type = "func"
		size = "890"
		objfiles = "_divsc3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? D9 45 10 D9 E1 D9 45 14 D9 E1 DA E9 DF E0 F6 C4 45 75 49 D9 45 10 D8 75 14 D9 45 10 D8 C9 D8 45 14 D9 45 08 D8 CA D8 45 0C D8 F1 D9 45 0C DE CB D9 CA D8 65 08 DE F1 D9 C9 DD E0 DF E0 80 E4 45 80 FC 40 75 3F D9 5D F4 8B 45 F4 D9 5D F4 8B 55 F4 59 5B 5E 5D C3 8D B6 00 00 00 00 D9 45 14 D8 75 10 D9 45 14 D8 C9 D8 45 10 D9 45 0C D8 CA D8 45 08 D8 F1 D9 CA D8 4D 08 D9 45 0C DE E1 DE F1 D9 C9 EB B5 D9 C9 DD E0 DF E0 80 E4 45 80 FC 40 75 04 D9 C9 EB AF D9 EE D9 45 10 DD E9 DF E0 80 E4 45 80 F4 40 0F 85 76 02 00 00 D9 45 14 DA E9 DF E0 80 E4 }
	condition:
		$pattern
}

rule sem_wait_b95d29974a91fbe38866e019058a87ff {
	meta:
		aliases = "__new_sem_wait, sem_wait"
		type = "func"
		size = "241"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 0C 8B 75 08 E8 ?? ?? ?? ?? 89 45 F4 89 75 EC C7 45 F0 ?? ?? ?? ?? 8B 55 F4 89 F0 E8 ?? ?? ?? ?? 8B 46 08 85 C0 7E 10 48 89 46 08 56 E8 ?? ?? ?? ?? 5B E9 AA 00 00 00 8B 45 F4 C6 80 42 01 00 00 00 8B 45 F4 8D 55 EC E8 ?? ?? ?? ?? 8B 45 F4 80 78 42 00 74 0E 8B 45 F4 BB 01 00 00 00 80 78 40 00 74 0D 8B 55 F4 8D 46 0C E8 ?? ?? ?? ?? 31 DB 56 E8 ?? ?? ?? ?? 59 85 DB 74 0C 8B 45 F4 31 D2 E8 ?? ?? ?? ?? EB 52 8B 45 F4 E8 ?? ?? ?? ?? 8B 45 F4 80 B8 42 01 00 00 00 75 15 8B 45 F4 80 B8 40 01 00 00 00 74 E0 8B 45 F4 80 78 40 00 75 D7 8B 45 F4 31 D2 E8 ?? ?? ?? ?? 8B 45 F4 80 B8 40 01 }
	condition:
		$pattern
}

rule __old_sem_wait_445586b298b501499acaec8241a2ae35 {
	meta:
		aliases = "__old_sem_wait"
		type = "func"
		size = "281"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 14 8B 5D 08 89 EA B8 ?? ?? ?? ?? 3B 2D ?? ?? ?? ?? 73 31 3B 2D ?? ?? ?? ?? 72 0D B8 ?? ?? ?? ?? 3B 2D ?? ?? ?? ?? 72 1C 83 3D ?? ?? ?? ?? 00 74 07 E8 ?? ?? ?? ?? EB 0C 81 CA FF FF 1F 00 8D 82 A1 FE FF FF 89 45 F4 C7 45 EC 00 00 00 00 C7 45 F0 ?? ?? ?? ?? 8D 75 EC 8B 45 F4 89 F2 E8 ?? ?? ?? ?? 8B 0B F6 C1 01 74 08 8D 51 FE 83 F9 01 75 09 8B 55 F4 8B 45 F4 89 48 08 89 C8 F0 0F B1 13 0F 94 C1 84 C9 74 DB 80 E2 01 75 73 8B 45 F4 50 E8 ?? ?? ?? ?? 8B 45 F4 31 D2 E8 ?? ?? ?? ?? 8B 45 F4 5A 80 78 42 00 74 AF 8B 45 F4 80 78 40 00 75 A6 8B 13 8B 45 F4 39 C2 75 13 8B 45 F4 8B 48 08 }
	condition:
		$pattern
}

rule __mulsc3_4e2aa4e1213b843f63d10caa3095f718 {
	meta:
		aliases = "__mulsc3"
		type = "func"
		size = "1099"
		objfiles = "_mulsc3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 18 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? D9 45 08 D8 4D 10 D9 5D F4 D9 45 0C D8 4D 14 D9 5D F0 D9 45 08 D8 4D 14 D9 5D EC D9 45 0C D8 4D 10 D9 5D E8 D9 45 F4 D9 45 F0 D9 C1 D8 E1 D9 45 EC D9 45 E8 D9 C1 D8 C1 D9 55 E4 D9 CB DD E0 DF E0 80 E4 45 80 FC 40 75 1A DD DC DD D8 DD D8 DD D8 DD D9 D9 5D E0 8B 45 E0 8B 55 E4 83 C4 18 5B 5E 5D C3 D9 CB DD E8 DF E0 80 E4 45 80 FC 40 75 0A DD D8 DD D8 DD D9 DD D9 EB D8 D9 45 08 D8 E0 D9 45 08 DD E8 DF E0 80 E4 45 80 F4 40 0F 85 BE 01 00 00 DD E8 DF E0 80 E4 45 80 F4 40 0F 84 B0 01 00 00 B8 00 00 80 3F 8B 55 08 85 D2 79 05 B8 00 00 80 BF }
	condition:
		$pattern
}

rule pthread_start_thread_e6a2660ecf558dbfa5adc9c77dd2ad9c {
	meta:
		aliases = "pthread_start_thread"
		type = "func"
		size = "163"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 20 8B 75 08 E8 ?? ?? ?? ?? 89 46 14 8D 46 64 6A 00 50 6A 02 E8 ?? ?? ?? ?? 8B 56 6C 83 C4 0C 85 D2 78 07 8D 46 70 50 52 EB 16 83 3D ?? ?? ?? ?? 00 7E 18 C7 45 F4 00 00 00 00 8D 45 F4 50 6A 00 FF 76 14 E8 ?? ?? ?? ?? 83 C4 0C A1 ?? ?? ?? ?? 85 C0 74 3B 83 3D ?? ?? ?? ?? 00 7E 32 89 75 D8 C7 45 DC 05 00 00 00 8D 5D D8 6A 1C 53 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 40 75 0A E8 ?? ?? ?? ?? 83 38 04 74 E2 56 E8 ?? ?? ?? ?? 59 FF 76 60 FF 56 5C 55 50 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule daemon_85f84479bab55723ed2ff1b7bfe62a1a {
	meta:
		aliases = "daemon"
		type = "func"
		size = "263"
		objfiles = "daemon@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 60 E8 ?? ?? ?? ?? 83 F8 FF 0F 84 D3 00 00 00 85 C0 0F 84 D4 00 00 00 6A 00 E8 ?? ?? ?? ?? 83 7D 08 00 75 0B 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 83 7D 0C 00 0F 85 AE 00 00 00 BB ?? ?? ?? ?? B9 02 00 00 00 89 D8 8B 55 0C 53 89 C3 B8 05 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 CE FF EB 6B 89 C6 83 F8 FF 74 64 8D 45 98 50 53 E8 ?? ?? ?? ?? 59 5A 85 C0 75 54 8B 45 A8 25 00 F0 00 00 3D 00 20 00 00 75 2B 6A 00 53 E8 ?? ?? ?? ?? 6A 01 53 E8 ?? ?? ?? ?? 6A 02 53 E8 ?? ?? ?? ?? 83 C4 18 83 FB 02 7E 37 53 E8 ?? ?? ?? ?? 31 C0 5A EB 3E 89 D9 87 CB B8 06 }
	condition:
		$pattern
}

rule pthread_setcancelstate_b17f5eef4028722aff03a376567e7699 {
	meta:
		aliases = "__GI_pthread_setcancelstate, pthread_setcancelstate"
		type = "func"
		size = "72"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 8B 5D 08 8B 75 0C B8 16 00 00 00 83 FB 01 77 2C E8 ?? ?? ?? ?? 89 C2 85 F6 74 06 0F B6 40 40 89 06 88 5A 40 80 7A 42 00 74 10 66 81 7A 40 00 01 75 08 55 6A FF E8 ?? ?? ?? ?? 31 C0 8D 65 F8 5B 5E 5D C3 }
	condition:
		$pattern
}

rule pthread_setcanceltype_bc7f2b0553f5359939c53394bd7ff33d {
	meta:
		aliases = "__GI_pthread_setcanceltype, pthread_setcanceltype"
		type = "func"
		size = "72"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 8B 5D 08 8B 75 0C B8 16 00 00 00 83 FB 01 77 2C E8 ?? ?? ?? ?? 89 C2 85 F6 74 06 0F B6 40 41 89 06 88 5A 41 80 7A 42 00 74 10 66 81 7A 40 00 01 75 08 55 6A FF E8 ?? ?? ?? ?? 31 C0 8D 65 F8 5B 5E 5D C3 }
	condition:
		$pattern
}

rule _pthread_cleanup_pop_restore_2004df8f172439abb358435fba4b8280 {
	meta:
		aliases = "__pthread_cleanup_pop_restore, _pthread_cleanup_pop_restore"
		type = "func"
		size = "68"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 8B 5D 08 E8 ?? ?? ?? ?? 89 C6 83 7D 0C 00 74 06 FF 73 04 FF 13 59 8B 43 0C 89 46 3C 8B 43 08 88 46 41 80 7E 42 00 74 10 66 81 7E 40 00 01 75 08 55 6A FF E8 ?? ?? ?? ?? 8D 65 F8 5B 5E 5D C3 }
	condition:
		$pattern
}

rule _Unwind_GetGR_86d602794302837f07fe401cfa2584b7 {
	meta:
		aliases = "_Unwind_GetGR"
		type = "func"
		size = "82"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 4D 08 8B 55 0C 83 FA 11 7F 31 8A 84 13 ?? ?? ?? ?? 8B 34 91 F6 41 63 40 75 14 3C 04 75 1D 8B 06 5B 5E 5D C3 8D 76 00 8D BC 27 00 00 00 00 80 7C 11 6C 00 74 E5 89 F0 5B 5E 5D C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __deregister_frame_info_bases_0542ef47de0c8070665c32a8794ff3bd {
	meta:
		aliases = "__deregister_frame_info_bases"
		type = "func"
		size = "205"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 55 08 85 D2 75 18 31 C0 8D 65 F8 5B 5E 5D C3 EB 0D 90 90 90 90 90 90 90 90 90 90 90 90 90 8B 02 85 C0 74 E2 8B B3 ?? ?? ?? ?? 85 F6 74 2F 39 56 0C 75 20 8D 8B ?? ?? ?? ?? 8B 46 14 89 01 89 F0 8D 65 F8 5B 5E 5D C3 8D B4 26 00 00 00 00 39 56 0C 74 E6 8D 4E 14 8B 76 14 85 F6 75 F1 8B B3 ?? ?? ?? ?? 85 F6 74 4F 8D 8B ?? ?? ?? ?? EB 22 EB 0D 90 90 90 90 90 90 90 90 90 90 90 90 90 8B 46 0C 39 10 74 19 8B 46 14 85 C0 74 2A 8D 4E 14 89 C6 F6 46 10 01 75 E7 39 56 0C 75 E9 EB 9B 8B 46 14 89 01 83 EC 0C 8B 46 0C 50 E8 ?? ?? ?? ?? 83 C4 10 89 F0 EB 8A }
	condition:
		$pattern
}

rule __register_frame_052c3a53ad2430fd0eb97f87d54cea34 {
	meta:
		aliases = "__register_frame"
		type = "func"
		size = "55"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 75 08 8B 06 85 C0 74 16 83 EC 0C 6A 18 E8 ?? ?? ?? ?? 5A 59 50 56 E8 ?? ?? ?? ?? 83 C4 10 8D 65 F8 5B 5E 5D C3 }
	condition:
		$pattern
}

rule __do_global_ctors_aux_3a440adc5580cfa988aa466d2ec88575 {
	meta:
		aliases = "__do_global_ctors_aux"
		type = "func"
		size = "65"
		objfiles = "crtendS"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8D 83 ?? ?? ?? ?? 8D 50 FC 8B 40 FC 83 F8 FF 74 1B 89 D6 8D B6 00 00 00 00 8D BF 00 00 00 00 FF D0 8B 46 FC 83 EE 04 83 F8 FF 75 F3 5B 5E 5D C3 }
	condition:
		$pattern
}

rule _Unwind_Resume_or_Rethrow_e213c8b7e3eb46f606e01c61e3a1ae02 {
	meta:
		aliases = "_Unwind_Resume_or_Rethrow"
		type = "func"
		size = "207"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 52 50 81 EC 14 01 00 00 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 45 08 8B 40 0C 85 C0 74 5C 8B 4D 04 8D 85 6C FF FF FF 89 85 E8 FE FF FF 8D 55 08 E8 05 F9 FF FF 8D 85 EC FE FF FF 89 85 E4 FE FF FF 57 68 80 00 00 00 8B B5 E8 FE FF FF 56 50 E8 ?? ?? ?? ?? 83 C4 10 8B 95 E4 FE FF FF 8B 45 08 E8 A5 FE FF FF 83 F8 07 74 29 E8 ?? ?? ?? ?? 8D 74 26 00 8D BC 27 00 00 00 00 83 EC 0C 8B 4D 08 51 E8 ?? ?? ?? ?? 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 8B 95 E4 FE FF FF 8B 85 E8 FE FF FF E8 D6 F9 FF FF 89 C1 8B 85 38 FF FF FF 89 44 0D 04 8B 45 EC 8B 55 F0 8B 5D F4 8B 75 F8 8B 7D FC 8D 4C 0D }
	condition:
		$pattern
}

rule _Unwind_Resume_ab8a6f68410450f90b589dee5e5ed86c {
	meta:
		aliases = "_Unwind_Resume"
		type = "func"
		size = "198"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 52 50 81 EC 14 01 00 00 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 4D 04 8D 85 6C FF FF FF 89 85 E8 FE FF FF 8D 55 08 E8 3F F8 FF FF 8D 85 EC FE FF FF 89 85 E4 FE FF FF 56 68 80 00 00 00 8B 8D E8 FE FF FF 51 50 E8 ?? ?? ?? ?? 83 C4 10 8B 45 08 8B 50 0C 85 D2 75 23 8B 95 E4 FE FF FF E8 B8 FB FF FF 83 F8 07 74 23 E8 ?? ?? ?? ?? 8D B4 26 00 00 00 00 8D BC 27 00 00 00 00 8B 95 E4 FE FF FF 8B 45 08 E8 B2 FD FF FF EB D8 8B 95 E4 FE FF FF 8B 85 E8 FE FF FF E8 0F F9 FF FF 89 C1 8B 85 38 FF FF FF 89 44 0D 04 8B 45 EC 8B 55 F0 8B 5D F4 8B 75 F8 8B 7D FC 8D 4C 0D 04 8B 6D 00 89 CC C3 }
	condition:
		$pattern
}

rule _Unwind_ForcedUnwind_2fe179aeecfaf6fa5aa897bed42f0b74 {
	meta:
		aliases = "_Unwind_ForcedUnwind"
		type = "func"
		size = "184"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 52 50 81 EC 14 01 00 00 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 4D 04 8D 85 6C FF FF FF 89 85 E8 FE FF FF 8D 55 08 E8 6F F7 FF FF 8D 95 EC FE FF FF 89 95 E4 FE FF FF 50 68 80 00 00 00 8B BD E8 FE FF FF 57 52 E8 ?? ?? ?? ?? 8B 45 0C 8B 55 08 89 42 0C 8B 45 10 89 42 10 83 C4 10 8B 95 E4 FE FF FF 8B 45 08 E8 00 FD FF FF 83 F8 07 74 0D 8B 5D F4 8B 75 F8 8B 7D FC 89 EC 5D C3 8B 95 E4 FE FF FF 8B 85 E8 FE FF FF E8 4D F8 FF FF 89 C1 8B 85 38 FF FF FF 89 44 0D 04 8B 45 EC 8B 55 F0 8B 5D F4 8B 75 F8 8B 7D FC 8D 4C 0D 04 8B 6D 00 89 CC C3 }
	condition:
		$pattern
}

rule _Unwind_RaiseException_0e34fe0a5b3e8d11f2023c2cb3761e19 {
	meta:
		aliases = "_Unwind_RaiseException"
		type = "func"
		size = "358"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 52 50 81 EC D4 01 00 00 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 4D 04 8D 85 6C FF FF FF 89 85 24 FE FF FF 8D 55 08 E8 6F FB FF FF 8D 95 EC FE FF FF 89 95 28 FE FF FF 50 68 80 00 00 00 8B 85 24 FE FF FF 50 52 E8 ?? ?? ?? ?? 83 C4 10 8D 85 2C FE FF FF 89 85 20 FE FF FF EB 59 EB 0D 90 90 90 90 90 90 90 90 90 90 90 90 90 85 C0 75 67 8B 85 D4 FE FF FF 85 C0 74 2B 83 EC 08 8B BD 28 FE FF FF 57 8B 75 08 56 8B 55 08 8B 4A 04 51 8B 12 52 6A 01 6A 01 FF D0 83 C4 20 83 F8 06 74 47 83 F8 08 75 32 8B 95 20 FE FF FF 8B 85 28 FE FF FF E8 86 FD FF FF 8B 95 20 FE FF FF 8B 85 28 FE FF FF E8 E5 }
	condition:
		$pattern
}

rule glob64_713ac7bd3deec0b17d396987f1d9bf62 {
	meta:
		aliases = "__GI_glob64, glob64"
		type = "func"
		size = "1298"
		objfiles = "glob64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 0C 01 00 00 8B 7D 14 83 7D 08 00 74 0D 85 FF 74 09 F7 45 0C 00 81 FF FF 74 13 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CA FF E9 D3 04 00 00 8B 45 0C 83 E0 08 89 85 F0 FE FF FF 75 07 C7 47 08 00 00 00 00 6A 2F FF 75 08 E8 ?? ?? ?? ?? 5B 5E 89 C6 85 C0 75 38 F7 45 0C 00 50 00 00 0F 84 C9 00 00 00 8B 55 08 80 3A 7E 0F 85 BD 00 00 00 52 E8 ?? ?? ?? ?? 59 89 85 FC FE FF FF 8B 5D 08 C7 85 F8 FE FF FF 00 00 00 00 E9 B6 00 00 00 3B 45 08 75 1E 8B 4D 08 41 89 8D F8 FE FF FF BB ?? ?? ?? ?? C7 85 FC FE FF FF 01 00 00 00 E9 93 00 00 00 2B 45 08 89 85 FC FE FF FF 83 C0 13 83 E0 FC 29 C4 }
	condition:
		$pattern
}

rule ruserok_53bba4f6d48bee9b9db2fdfe579435e0 {
	meta:
		aliases = "ruserok"
		type = "func"
		size = "159"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 30 04 00 00 8D 44 24 0F 83 E0 F0 BB 00 04 00 00 8D 7D E8 8D 75 F0 EB 21 83 7D E8 FF 75 6E E8 ?? ?? ?? ?? 83 38 22 75 64 01 DB 8D 43 12 83 E0 FC 29 C4 8D 44 24 0F 83 E0 F0 57 56 53 50 8D 45 D4 50 FF 75 08 E8 ?? ?? ?? ?? 83 C4 18 85 C0 75 C8 8B 45 F0 85 C0 74 C1 8B 58 10 8D 75 EC EB 27 6A 04 50 56 E8 ?? ?? ?? ?? 8B 45 EC FF 75 08 FF 75 14 8B 4D 10 8B 55 0C E8 ?? ?? ?? ?? 83 C4 14 85 C0 74 0C 83 C3 04 8B 03 85 C0 75 D3 83 C8 FF 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule clntudp_call_9a58f78555341ccdd57e428ebb2a6aec {
	meta:
		aliases = "clntudp_call"
		type = "func"
		size = "1317"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 38 23 00 00 8B 45 08 8B 70 08 8B 4E 20 BB E8 03 00 00 89 C8 99 F7 FB 89 C1 69 46 1C E8 03 00 00 01 C1 89 8D D4 DC FF FF 83 7E 28 FF 75 0E 8B 45 24 89 85 E4 DC FF FF 8B 55 20 EB 0C 8B 46 28 89 85 E4 DC FF FF 8B 56 24 89 95 E8 DC FF FF C7 85 D0 DC FF FF 00 00 00 00 C7 85 D8 DC FF FF 02 00 00 00 C7 85 E0 DC FF FF 00 00 00 00 C7 85 EC DC FF FF 00 00 00 00 8D 46 38 89 85 C0 DC FF FF 8D 56 08 89 95 BC DC FF FF 8B 85 C0 DC FF FF 89 85 CC DC FF FF 83 7D 10 00 0F 84 D7 00 00 00 C7 46 38 00 00 00 00 8B 46 3C FF 76 50 FF B5 CC DC FF FF FF 50 14 8B 46 58 FF 00 8D 45 0C 8B 56 3C 50 }
	condition:
		$pattern
}

rule getrpcport_283b958a9e053c0843bec6841b60bf6d {
	meta:
		aliases = "getrpcport"
		type = "func"
		size = "160"
		objfiles = "getrpcport@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 3C 04 00 00 8D 44 24 0F 83 E0 F0 BB 00 04 00 00 8D 7D EC 8D 75 F0 EB 21 83 7D EC FF 75 70 E8 ?? ?? ?? ?? 83 38 22 75 66 01 DB 8D 43 12 83 E0 FC 29 C4 8D 44 24 0F 83 E0 F0 57 56 53 50 8D 45 C8 50 FF 75 08 E8 ?? ?? ?? ?? 83 C4 18 85 C0 75 C8 8B 45 F0 85 C0 74 C1 FF 70 0C 8B 40 10 FF 30 8D 5D DC 8D 45 E0 50 E8 ?? ?? ?? ?? 66 C7 45 DC 02 00 66 C7 45 DE 00 00 FF 75 14 FF 75 10 FF 75 0C 53 E8 ?? ?? ?? ?? 0F B7 C0 83 C4 1C EB 02 31 C0 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule execute_stack_op_df27f4a55462483d5d76086ada2c418d {
	meta:
		aliases = "execute_stack_op"
		type = "func"
		size = "1478"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 4C 01 00 00 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 89 C7 89 95 C4 FE FF FF 89 8D C0 FE FF FF 8B 45 08 89 85 E0 FE FF FF 39 D7 0F 83 88 05 00 00 C7 85 C8 FE FF FF 01 00 00 00 8D 45 E8 89 85 BC FE FF FF 8D B6 00 00 00 00 8A 17 88 D1 81 E1 FF 00 00 00 89 CE 47 8D 42 FD 3C 93 76 0C E8 ?? ?? ?? ?? 8D B4 26 00 00 00 00 25 FF 00 00 00 8B 84 83 ?? ?? ?? ?? 01 D8 FF E0 8B 07 89 45 F0 83 C7 04 90 8D B4 26 00 00 00 00 83 BD C8 FE FF FF 3F 77 CB 8B 45 F0 8B 8D C8 FE FF FF 89 84 8D E0 FE FF FF 41 89 8D C8 FE FF FF 39 BD C4 FE FF FF 77 98 8B BD C8 FE FF FF 85 FF 74 A2 8B 85 C8 FE FF FF }
	condition:
		$pattern
}

rule __frame_state_for_95e69dd1614ff9fd86c50e902d145102 {
	meta:
		aliases = "__frame_state_for"
		type = "func"
		size = "214"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 50 01 00 00 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 7D 0C 8D 85 74 FF FF FF 89 85 B0 FE FF FF 68 80 00 00 00 6A 00 50 E8 ?? ?? ?? ?? C7 45 D4 00 00 00 40 8B 45 08 40 89 45 C0 83 C4 10 8D B5 B4 FE FF FF 89 F2 8B 85 B0 FE FF FF E8 58 FC FF FF 85 C0 74 0C 31 FF 89 F8 8D 65 F4 5B 5E 5F 5D C3 83 BD 54 FF FF FF 02 74 EB B9 01 00 00 00 EB 1A 90 8D B4 26 00 00 00 00 3C 02 74 1A C7 44 8F 0C 00 00 00 00 41 83 F9 13 74 16 8B 44 CE FC 88 44 39 5B 3C 01 75 E2 8B 44 CE F8 89 44 8F 0C EB E4 8B 85 48 FF FF FF 89 47 08 8B 85 4C FF FF FF 66 89 47 58 8B 85 68 FF FF FF 66 89 47 5A 8B 45 DC }
	condition:
		$pattern
}

rule ruserpass_b0fcba2f41a631c66b773975b64c5c3b {
	meta:
		aliases = "ruserpass"
		type = "func"
		size = "789"
		objfiles = "ruserpass@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 5C 04 00 00 8B 7D 08 E8 ?? ?? ?? ?? 89 C3 E8 ?? ?? ?? ?? 39 C3 0F 85 E5 02 00 00 E8 ?? ?? ?? ?? 89 C3 E8 ?? ?? ?? ?? 39 C3 0F 85 D1 02 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 59 85 C0 0F 84 BC 02 00 00 50 E8 ?? ?? ?? ?? 5A 83 C0 1A 83 E0 FC 29 C4 8D 5C 24 0F 83 E3 F0 56 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 18 85 C0 75 24 E8 ?? ?? ?? ?? 31 D2 83 38 02 0F 84 70 02 00 00 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 D2 5B 5E E9 5C 02 00 00 6A 02 50 E8 ?? ?? ?? ?? 68 00 04 00 00 8D 9D 9C FB FF FF 53 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule gaih_inet_6e6404d874fad9a9aaef7588b48fe536 {
	meta:
		aliases = "gaih_inet"
		type = "func"
		size = "2324"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 88 00 00 00 8B 55 10 8B 42 04 85 C0 74 0F C7 85 74 FF FF FF 00 00 00 00 83 F8 0A 75 16 8B 4D 10 8B 19 83 F3 08 C1 EB 03 F7 D3 83 E3 01 89 9D 74 FF FF FF 31 C0 8D 7D D0 AB AB AB AB 8B 75 10 8B 5E 0C 85 DB 75 30 83 7E 08 00 75 2A EB 4A 8B 7D 10 8B 4F 08 85 C9 74 07 0F BE 02 39 C1 75 12 85 DB 74 3A 0F BE 42 01 39 C3 74 32 F6 42 02 02 75 2C 83 C2 07 EB 05 BA ?? ?? ?? ?? 80 7A 03 00 75 CD B8 07 01 00 00 8B 55 10 83 7A 08 00 0F 85 71 08 00 00 E9 55 08 00 00 BA ?? ?? ?? ?? 8D 45 D0 89 45 F0 83 7D 0C 00 0F 84 1C 01 00 00 F6 42 02 01 0F 85 36 08 00 00 8B 4D 0C 83 79 04 00 0F 89 }
	condition:
		$pattern
}

rule search_object_abfa17fc3cf0264e23a98f333ba24bb7 {
	meta:
		aliases = "search_object"
		type = "func"
		size = "1819"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 9C 00 00 00 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 89 85 7C FF FF FF 89 95 78 FF FF FF 8A 50 10 F6 C2 01 0F 85 05 02 00 00 8B 48 10 89 C8 C1 E8 0B 0F 84 37 03 00 00 89 45 80 8B 45 80 85 C0 0F 84 CD 01 00 00 8B 7D 80 8D 34 BD 08 00 00 00 83 EC 0C 56 E8 ?? ?? ?? ?? 89 85 68 FF FF FF 89 45 E4 83 C4 10 85 C0 0F 84 A6 01 00 00 C7 40 04 00 00 00 00 83 EC 0C 56 E8 ?? ?? ?? ?? 89 85 64 FF FF FF 89 45 E8 83 C4 10 85 C0 74 07 C7 40 04 00 00 00 00 8B 85 7C FF FF FF F6 40 10 02 0F 84 6C 03 00 00 8B 95 7C FF FF FF 8B 42 0C 8B 08 85 C9 74 1C 89 C6 8D 7D E4 89 FA 8B 85 7C FF FF FF E8 35 }
	condition:
		$pattern
}

rule clnt_create_43747fd181b50e0a745bf95cc6c9e1ab {
	meta:
		aliases = "clnt_create"
		type = "func"
		size = "490"
		objfiles = "clnt_generic@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC B0 00 00 00 68 ?? ?? ?? ?? FF 75 14 E8 ?? ?? ?? ?? 5A 59 85 C0 75 4B 6A 6E 6A 00 8D 9D 46 FF FF FF 53 E8 ?? ?? ?? ?? 66 C7 85 46 FF FF FF 01 00 FF 75 08 8D 85 48 FF FF FF 50 E8 ?? ?? ?? ?? C7 45 E8 FF FF FF FF 6A 00 6A 00 8D 45 E8 50 FF 75 10 FF 75 0C 53 E8 ?? ?? ?? ?? 83 C4 2C E9 78 01 00 00 81 EC 10 04 00 00 8D 44 24 0F 83 E0 F0 BB 00 04 00 00 EB 31 83 7D E4 FF 75 0A E8 ?? ?? ?? ?? 83 38 22 74 10 E8 ?? ?? ?? ?? C7 00 0D 00 00 00 E9 42 01 00 00 01 DB 8D 43 12 83 E0 FC 29 C4 8D 44 24 0F 83 E0 F0 8D 55 E4 52 8D 55 F0 52 53 50 8D 45 B4 50 FF 75 08 E8 ?? ?? ?? ?? 83 C4 18 }
	condition:
		$pattern
}

rule uw_update_context_1_5958c2501758c4a220f6020c551b3fe9 {
	meta:
		aliases = "uw_update_context_1"
		type = "func"
		size = "750"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC B0 00 00 00 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 89 C7 89 95 5C FF FF FF 8D 85 6C FF FF FF 89 85 58 FF FF FF 68 80 00 00 00 57 50 E8 ?? ?? ?? ?? 83 C4 10 F6 45 CF 40 74 06 80 7D DC 00 75 3A 8B 85 7C FF FF FF 85 C0 74 3A F6 47 63 40 74 04 C6 47 70 00 C7 47 10 00 00 00 00 8B 95 5C FF FF FF 8B 82 A0 00 00 00 83 F8 01 0F 84 12 02 00 00 83 F8 02 74 39 E8 ?? ?? ?? ?? 8D 85 7C FF FF FF 85 C0 75 C6 8B 47 48 80 BB ?? ?? ?? ?? 04 75 E5 89 45 F0 F6 45 CF 40 74 04 C6 45 DC 00 8D 55 F0 B8 04 00 00 00 89 94 85 6C FF FF FF EB 9C 8B 95 5C FF FF FF 8B 82 9C 00 00 00 8D 55 EC E8 F7 EB FF }
	condition:
		$pattern
}

rule link_exists_p_f0c7d55e9b51c06dae1aee467abbe771 {
	meta:
		aliases = "link_exists_p"
		type = "func"
		size = "139"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC B8 00 00 00 89 85 3C FF FF FF 89 D3 89 CE 51 E8 ?? ?? ?? ?? 5F 89 85 40 FF FF FF 8D 44 18 14 83 E0 FC 29 C4 8D 7C 24 0F 83 E7 F0 53 FF B5 3C FF FF FF 57 E8 ?? ?? ?? ?? C6 00 2F 8B 95 40 FF FF FF 42 52 56 40 50 E8 ?? ?? ?? ?? 83 C4 18 F7 45 0C 00 02 00 00 74 0D 8D 45 9C 50 57 8B 45 08 FF 50 20 EB 0D 8D 85 44 FF FF FF 50 57 E8 ?? ?? ?? ?? 5B 5E 85 C0 0F 94 C0 0F B6 C0 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule link_exists_p_89f5577abe67263476ea78728cadc59a {
	meta:
		aliases = "link_exists_p"
		type = "func"
		size = "139"
		objfiles = "glob64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC C8 00 00 00 89 85 2C FF FF FF 89 D3 89 CE 51 E8 ?? ?? ?? ?? 5F 89 85 30 FF FF FF 8D 44 18 14 83 E0 FC 29 C4 8D 7C 24 0F 83 E7 F0 53 FF B5 2C FF FF FF 57 E8 ?? ?? ?? ?? C6 00 2F 8B 95 30 FF FF FF 42 52 56 40 50 E8 ?? ?? ?? ?? 83 C4 18 F7 45 0C 00 02 00 00 74 0D 8D 45 94 50 57 8B 45 08 FF 50 20 EB 0D 8D 85 34 FF FF FF 50 57 E8 ?? ?? ?? ?? 59 5B 85 C0 0F 94 C0 0F B6 C0 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _Unwind_RaiseException_Phase2_6aef6324cd5d6cb50f540733f96bd261 {
	meta:
		aliases = "_Unwind_RaiseException_Phase2"
		type = "func"
		size = "170"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC CC 00 00 00 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 89 85 30 FF FF FF 89 D7 8D 85 34 FF FF FF 89 85 2C FF FF FF EB 3F 89 F6 8B 55 DC 85 D2 74 25 83 EC 08 57 51 89 C8 8B 49 04 51 8B 00 50 89 F0 83 C8 02 50 6A 01 FF D2 83 C4 20 83 F8 07 74 46 83 F8 08 75 3C 85 F6 75 45 8B 95 2C FF FF FF 89 F8 E8 83 FE FF FF 8B 95 2C FF FF FF 89 F8 E8 E6 EE FF FF 8B 57 4C 8B 8D 30 FF FF FF 3B 51 10 0F 94 C2 81 E2 FF 00 00 00 89 D6 C1 E6 02 85 C0 74 98 B8 02 00 00 00 8D 65 F4 5B 5E 5F 5D C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule uw_init_context_1_38d69a3207f9a33d4e626efeaa8c9fc5 {
	meta:
		aliases = "uw_init_context_1"
		type = "func"
		size = "314"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC E0 00 00 00 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 89 C7 89 95 20 FF FF FF 89 8D 1C FF FF FF 8B 75 04 68 80 00 00 00 6A 00 50 E8 ?? ?? ?? ?? 89 77 4C C7 47 60 00 00 00 40 83 C4 10 8D B5 30 FF FF FF 89 F2 89 F8 E8 BE F2 FF FF 85 C0 0F 85 DB 00 00 00 80 BB ?? ?? ?? ?? 00 74 5D 80 BB ?? ?? ?? ?? 04 0F 85 C5 00 00 00 8B 85 20 FF FF FF 89 45 F0 F6 47 63 40 74 04 C6 47 70 00 8D 55 F0 B8 04 00 00 00 89 14 87 C7 45 D0 01 00 00 00 C7 45 C8 04 00 00 00 C7 45 C4 00 00 00 00 89 F2 89 F8 E8 64 FC FF FF 8B 85 1C FF FF FF 89 47 4C 8D 65 F4 5B 5E 5F 5D C3 8D 76 00 C6 83 ?? ?? ?? ?? 04 C6 }
	condition:
		$pattern
}

rule glob_in_dir_662b5d2c77643b5779297070d9d7c65f {
	meta:
		aliases = "glob_in_dir"
		type = "func"
		size = "1184"
		objfiles = "glob64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC E8 00 00 00 89 85 1C FF FF FF 89 95 18 FF FF FF 89 8D 14 FF FF FF 8B 75 08 52 E8 ?? ?? ?? ?? 89 85 20 FF FF FF 8B 9D 14 FF FF FF 83 E3 40 0F 94 C0 0F B6 C0 89 04 24 FF B5 1C FF FF FF E8 ?? ?? ?? ?? 59 5F 85 C0 0F 85 B4 00 00 00 F7 85 14 FF FF FF 10 08 00 00 0F 85 98 00 00 00 85 DB 75 17 6A 5C FF B5 1C FF FF FF E8 ?? ?? ?? ?? 5F 5A 85 C0 0F 85 89 00 00 00 FF B5 1C FF FF FF E8 ?? ?? ?? ?? 5E 89 C6 8B 95 20 FF FF FF 8D 44 10 14 83 E0 FC 29 C4 8D 5C 24 0F 83 E3 F0 52 FF B5 18 FF FF FF 53 E8 ?? ?? ?? ?? C6 00 2F 8D 56 01 52 FF B5 1C FF FF FF 40 50 E8 ?? ?? ?? ?? 83 C4 18 F7 }
	condition:
		$pattern
}

rule glob_in_dir_3276258e72bc4d9e6336b226c84a0ae6 {
	meta:
		aliases = "glob_in_dir"
		type = "func"
		size = "1250"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC E8 01 00 00 89 85 18 FE FF FF 89 95 14 FE FF FF 89 8D 10 FE FF FF 8B 75 08 52 E8 ?? ?? ?? ?? 89 85 1C FE FF FF 8B 9D 10 FE FF FF 83 E3 40 0F 94 C0 0F B6 C0 89 04 24 FF B5 18 FE FF FF E8 ?? ?? ?? ?? 59 5F 85 C0 0F 85 B4 00 00 00 F7 85 10 FE FF FF 10 08 00 00 0F 85 98 00 00 00 85 DB 75 17 6A 5C FF B5 18 FE FF FF E8 ?? ?? ?? ?? 5F 5A 85 C0 0F 85 89 00 00 00 FF B5 18 FE FF FF E8 ?? ?? ?? ?? 5E 89 C6 8B 95 1C FE FF FF 8D 44 10 14 83 E0 FC 29 C4 8D 5C 24 0F 83 E3 F0 52 FF B5 14 FE FF FF 53 E8 ?? ?? ?? ?? C6 00 2F 8D 56 01 52 FF B5 18 FE FF FF 40 50 E8 ?? ?? ?? ?? 83 C4 18 F7 }
	condition:
		$pattern
}

rule byte_re_match_2_internal_85ea11e13951931add38443b24df3ca6 {
	meta:
		aliases = "byte_re_match_2_internal"
		type = "func"
		size = "6887"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC F4 00 00 00 89 85 58 FF FF FF 89 95 54 FF FF FF 89 8D 50 FF FF FF 8B 5D 18 8B 00 89 85 7C FF FF FF 8B 95 58 FF FF FF 03 42 08 89 45 80 8B 4A 14 89 4D 88 8B 72 18 46 89 75 8C 8D 7C 24 0F 83 E7 F0 89 7D D8 83 7A 18 00 75 41 C7 45 98 00 00 00 00 C7 45 9C 00 00 00 00 C7 45 A0 00 00 00 00 C7 45 A4 00 00 00 00 C7 45 A8 00 00 00 00 C7 45 B0 00 00 00 00 C7 45 B4 00 00 00 00 C7 45 C0 00 00 00 00 C7 45 C4 00 00 00 00 EB 76 8B 55 8C 8D 04 95 10 00 00 00 29 C4 8D 4C 24 0F 83 E1 F0 89 4D 98 29 C4 8D 74 24 0F 83 E6 F0 89 75 9C 29 C4 8D 7C 24 0F 83 E7 F0 89 7D A0 29 C4 8D 54 24 0F 83 }
	condition:
		$pattern
}

rule glob_a3946d83e9c1d00f59d69c05adc32c47 {
	meta:
		aliases = "__GI_glob, glob"
		type = "func"
		size = "1298"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC FC 00 00 00 8B 7D 14 83 7D 08 00 74 0D 85 FF 74 09 F7 45 0C 00 81 FF FF 74 13 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CA FF E9 D3 04 00 00 8B 45 0C 83 E0 08 89 85 00 FF FF FF 75 07 C7 47 08 00 00 00 00 6A 2F FF 75 08 E8 ?? ?? ?? ?? 5B 5E 89 C6 85 C0 75 38 F7 45 0C 00 50 00 00 0F 84 C9 00 00 00 8B 55 08 80 3A 7E 0F 85 BD 00 00 00 52 E8 ?? ?? ?? ?? 59 89 85 0C FF FF FF 8B 5D 08 C7 85 08 FF FF FF 00 00 00 00 E9 B6 00 00 00 3B 45 08 75 1E 8B 4D 08 41 89 8D 08 FF FF FF BB ?? ?? ?? ?? C7 85 0C FF FF FF 01 00 00 00 E9 93 00 00 00 2B 45 08 89 85 0C FF FF FF 83 C0 13 83 E0 FC 29 C4 }
	condition:
		$pattern
}

rule sched_setaffinity_ad004dbd80734216b26885ec803ced59 {
	meta:
		aliases = "sched_setaffinity"
		type = "func"
		size = "205"
		objfiles = "sched_setaffinity@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 3D ?? ?? ?? ?? 00 75 69 81 EC 90 00 00 00 8D 74 24 0F 83 E6 F0 BF 80 00 00 00 EB 21 8D 0C 3F 8D 41 12 83 E0 FC 29 C4 8D 54 24 0F 83 E2 F0 8D 04 0A 39 F0 74 04 89 CF EB 02 01 CF 89 D6 E8 ?? ?? ?? ?? 89 F9 89 F2 53 89 C3 B8 F2 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 05 83 F8 EA 74 BD 85 DB 74 4F 81 FB 00 F0 FF FF 77 47 89 1D ?? ?? ?? ?? A1 ?? ?? ?? ?? EB 17 8B 55 10 80 3C 02 00 74 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 2D 40 3B 45 0C 72 E4 8B 45 08 8B 4D 0C 8B 55 10 53 89 C3 B8 F1 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 8D 65 F4 }
	condition:
		$pattern
}

rule pthread_cleanup_upto_0f8513ead0550c6f3707450ed1e17b35 {
	meta:
		aliases = "pthread_cleanup_upto"
		type = "func"
		size = "141"
		objfiles = "ptlongjmp@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 04 89 C7 89 E8 BE ?? ?? ?? ?? 3B 2D ?? ?? ?? ?? 73 32 3B 2D ?? ?? ?? ?? 72 0D BE ?? ?? ?? ?? 3B 2D ?? ?? ?? ?? 72 1D 83 3D ?? ?? ?? ?? 00 74 09 E8 ?? ?? ?? ?? 89 C6 EB 0B 0D FF FF 1F 00 8D B0 A1 FE FF FF 89 6D F0 8B 5E 3C EB 12 3B 5D F0 77 04 31 DB EB 12 FF 73 04 FF 13 8B 5B 0C 58 85 DB 74 05 3B 5F 10 72 E5 89 5E 3C 8B 46 54 85 C0 74 0C 3B 47 10 73 07 C7 46 54 00 00 00 00 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule execle_195dc35c4c7ab4f31f679d8e882aecf8 {
	meta:
		aliases = "__GI_execle, execle"
		type = "func"
		size = "101"
		objfiles = "execle@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 04 8D 45 10 89 45 F0 31 F6 46 8B 55 F0 8D 42 04 89 45 F0 83 3A 00 75 F1 8B 7A 04 8D 04 B5 14 00 00 00 29 C4 8D 5C 24 0F 83 E3 F0 8B 45 0C 89 03 8D 45 10 89 45 F0 89 D9 83 C1 04 8B 45 F0 8D 50 04 89 55 F0 8B 00 89 01 4E 75 ED 57 53 FF 75 08 E8 ?? ?? ?? ?? 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __floatundisf_7e022a0b49b4d66bf1d658ce9b58b703 {
	meta:
		aliases = "__floatundisf"
		type = "func"
		size = "125"
		objfiles = "_floatundisf@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 75 08 8B 7D 0C 81 FF FF FF 1F 00 72 2D 76 2B 89 F0 25 FF 07 00 00 31 D2 89 D1 09 C1 74 1C 89 F0 25 00 F8 FF FF 89 C6 81 CE 00 08 00 00 8D B6 00 00 00 00 8D BC 27 00 00 00 00 89 F0 89 FA 89 D0 31 D2 52 50 DF 2C 24 83 C4 08 D8 8B ?? ?? ?? ?? 31 D2 52 56 DF 2C 24 DE C1 D9 5D F0 D9 45 F0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __floatdisf_9fad562284a9d980ca0854c6086a1f40 {
	meta:
		aliases = "__floatdisf"
		type = "func"
		size = "135"
		objfiles = "_floatdisf@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 75 08 8B 7D 0C 89 F0 89 FA 83 C0 FF 81 D2 FF FF 1F 00 81 FA FF FF 3F 00 72 20 76 4E 89 F0 25 FF 07 00 00 31 D2 89 D1 09 C1 74 0F 89 F0 25 00 F8 FF FF 89 C6 81 CE 00 08 00 00 89 F0 89 FA 89 D0 89 C2 C1 FA 1F D9 83 ?? ?? ?? ?? 50 DA 0C 24 31 D2 89 14 24 56 DF 2C 24 DE C1 D9 5D F0 D9 45 F0 83 C4 0C 5B 5E 5F 5D C3 89 F6 83 F8 FE 76 CB EB AB }
	condition:
		$pattern
}

rule pthread_cond_wait_55db0009b9597ba6be28cf9c9170cfbc {
	meta:
		aliases = "__GI_pthread_cond_wait, pthread_cond_wait"
		type = "func"
		size = "293"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 5D 08 8B 75 0C E8 ?? ?? ?? ?? 89 45 F0 8B 46 0C 83 F8 03 74 15 85 C0 74 11 8B 45 F0 BA 16 00 00 00 39 46 08 0F 85 E7 00 00 00 89 5D E8 C7 45 EC ?? ?? ?? ?? 8B 45 F0 C6 80 41 01 00 00 00 8B 45 F0 8D 55 E8 E8 ?? ?? ?? ?? 8B 55 F0 89 D8 E8 ?? ?? ?? ?? 8B 45 F0 80 78 42 00 74 0E 8B 45 F0 BF 01 00 00 00 80 78 40 00 74 0D 8B 55 F0 8D 43 08 E8 ?? ?? ?? ?? 31 FF 53 E8 ?? ?? ?? ?? 58 85 FF 74 0C 8B 45 F0 31 D2 E8 ?? ?? ?? ?? EB 64 56 E8 ?? ?? ?? ?? 31 DB 58 8B 45 F0 E8 ?? ?? ?? ?? 8B 45 F0 80 B8 41 01 00 00 00 75 18 8B 45 F0 80 B8 40 01 00 00 00 74 09 8B 45 F0 80 78 40 00 }
	condition:
		$pattern
}

rule sem_timedwait_2287bd4782f7223249baff998d5bcaaa {
	meta:
		aliases = "sem_timedwait"
		type = "func"
		size = "345"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 75 08 E8 ?? ?? ?? ?? 89 45 E8 89 C2 89 F0 E8 ?? ?? ?? ?? 8B 46 08 85 C0 7E 0E 48 89 46 08 56 E8 ?? ?? ?? ?? 31 C0 EB 20 8B 45 0C 81 78 04 FF C9 9A 3B 76 1A 56 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 5A E9 F9 00 00 00 89 75 EC C7 45 F0 ?? ?? ?? ?? 8B 45 E8 C6 80 42 01 00 00 00 8D 55 EC 8B 45 E8 E8 ?? ?? ?? ?? 8B 45 E8 80 78 42 00 74 0B BB 01 00 00 00 80 78 40 00 74 0D 8D 46 0C 8B 55 E8 E8 ?? ?? ?? ?? 31 DB 56 E8 ?? ?? ?? ?? 5F 8D 7E 0C 85 DB 74 0F 31 D2 8B 45 E8 E8 ?? ?? ?? ?? E9 92 00 00 00 FF 75 0C FF 75 E8 E8 ?? ?? ?? ?? 5A 59 85 C0 75 43 8B 55 }
	condition:
		$pattern
}

rule uw_update_context_eebeab844e57edc414b25e2359b347cd {
	meta:
		aliases = "uw_update_context"
		type = "func"
		size = "105"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 89 C7 89 D6 E8 52 FA FF FF 8B 86 B4 00 00 00 83 F8 11 7F 3B 8A 94 03 ?? ?? ?? ?? 8B 0C 87 F6 47 63 40 75 17 80 FA 04 75 26 8B 01 89 47 4C 83 C4 0C 5B 5E 5F 5D C3 90 8D 74 26 00 80 7C 38 6C 00 74 E2 89 C8 89 47 4C 83 C4 0C 5B 5E 5F 5D C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __popcountdi2_334b955d1658a4f11dc73b75fd9505bc {
	meta:
		aliases = "__popcountdi2"
		type = "func"
		size = "117"
		objfiles = "_popcountdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 45 08 8B 55 0C 89 45 E8 89 55 EC 8B BB ?? ?? ?? ?? 0F B6 45 E8 8A 04 07 25 FF 00 00 00 89 C6 B9 08 00 00 00 8D B6 00 00 00 00 8B 45 E8 8B 55 EC 0F AD D0 D3 EA F6 C1 20 74 04 89 D0 31 D2 25 FF 00 00 00 8A 04 07 25 FF 00 00 00 01 C6 83 C1 08 83 F9 40 75 D5 89 F0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __negvdi2_8bf6c2e5ae1732990183c5493be216a5 {
	meta:
		aliases = "__negvdi2"
		type = "func"
		size = "105"
		objfiles = "_negvdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 45 08 8B 55 0C 89 C6 89 D7 F7 DE 83 D7 00 F7 DF 85 D2 78 16 83 FF 00 7E 31 E8 ?? ?? ?? ?? 8D B6 00 00 00 00 8D BF 00 00 00 00 89 F8 C1 E8 1F 75 E8 89 F0 89 FA 83 C4 0C 5B 5E 5F 5D C3 8D B6 00 00 00 00 8D BC 27 00 00 00 00 7C E5 83 FE 00 77 C8 EB DE }
	condition:
		$pattern
}

rule __mulvsi3_b82708699c59ef2aac883802a22998d2 {
	meta:
		aliases = "__mulvsi3"
		type = "func"
		size = "60"
		objfiles = "_mulvsi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 45 0C F7 6D 08 89 C6 89 D0 89 C2 C1 FA 1F 89 F1 C1 F9 1F 39 C1 75 0A 89 F0 83 C4 0C 5B 5E 5F 5D C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __subvdi3_7ee541c8f241080c510856337bf09b5b {
	meta:
		aliases = "__subvdi3"
		type = "func"
		size = "110"
		objfiles = "_subvdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 75 08 8B 7D 0C 89 F0 89 FA 2B 45 10 1B 55 14 89 45 E8 89 55 EC 8B 4D 14 85 C9 78 1E 39 FA 7F 0A 7C 28 39 F0 76 24 8D 74 26 00 E8 ?? ?? ?? ?? 8D 74 26 00 8D BC 27 00 00 00 00 39 7D EC 7C EB 7F 09 39 75 E8 72 E4 8D 74 26 00 8B 45 E8 8B 55 EC 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __addvdi3_734fe699f9e671a461ddadc57850e601 {
	meta:
		aliases = "__addvdi3"
		type = "func"
		size = "110"
		objfiles = "_addvdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 75 08 8B 7D 0C 8B 45 10 8B 55 14 01 F0 11 FA 89 45 E8 89 55 EC 8B 4D 14 85 C9 78 1E 39 FA 7C 0A 7F 28 39 F0 73 24 8D 74 26 00 E8 ?? ?? ?? ?? 8D 74 26 00 8D BC 27 00 00 00 00 39 7D EC 7F EB 7C 09 39 75 E8 77 E4 8D 74 26 00 8B 45 E8 8B 55 EC 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __getdents64_5e66b1ce45e2e77ca663a6fd3e1badc7 {
	meta:
		aliases = "__getdents64"
		type = "func"
		size = "264"
		objfiles = "getdents64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 10 8B 55 10 8D 42 12 83 E0 FC 29 C4 8D 4C 24 0F 83 E1 F0 8B 45 08 53 89 C3 B8 DC 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0B E8 ?? ?? ?? ?? F7 DE 89 30 EB 64 83 C8 FF 83 FE FF 0F 84 B7 00 00 00 8B 7D 0C 89 CB C7 45 EC FF FF FF FF C7 45 F0 FF FF FF FF 8D 34 31 89 75 E8 01 FA 89 55 E4 E9 86 00 00 00 0F B7 43 10 8D 48 03 83 E1 FC 8D 34 0F 3B 75 E4 76 28 6A 00 FF 75 F0 FF 75 EC FF 75 08 E8 ?? ?? ?? ?? 83 C4 10 3B 7D 0C 75 65 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 5A 8B 43 08 8B 53 0C 89 45 EC 89 55 F0 8B 03 8B 53 04 89 07 89 57 04 8B 43 08 8B 53 0C 89 47 08 89 57 0C }
	condition:
		$pattern
}

rule execvp_89b6ed237a8ecee95d02c03d67a4cc3a {
	meta:
		aliases = "__GI_execvp, execvp"
		type = "func"
		size = "412"
		objfiles = "execvp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 10 8B 75 08 80 3E 00 75 10 E8 ?? ?? ?? ?? C7 00 02 00 00 00 E9 70 01 00 00 6A 2F 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 71 FF 35 ?? ?? ?? ?? FF 75 0C 56 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 83 38 08 0F 85 42 01 00 00 31 C0 EB 01 40 8D 14 85 00 00 00 00 8B 4D 0C 83 3C 11 00 75 EF 8D 42 18 29 C4 8D 5C 24 0F 83 E3 F0 8B 01 89 03 89 73 04 52 89 C8 83 C0 04 50 8D 43 08 50 E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 18 E9 F1 00 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C7 58 85 FF 75 07 BF ?? ?? ?? ?? EB 09 80 3F 00 0F 84 50 FF FF FF 56 E8 ?? ?? ?? ?? 5B }
	condition:
		$pattern
}

rule pthread_cond_timedwait_650834ba2f86f073567506b298e947e2 {
	meta:
		aliases = "__GI_pthread_cond_timedwait, pthread_cond_timedwait"
		type = "func"
		size = "389"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 10 8B 7D 0C E8 ?? ?? ?? ?? 89 45 F0 8B 47 0C 83 F8 03 74 15 85 C0 74 11 8B 45 F0 BA 16 00 00 00 39 47 08 0F 85 4A 01 00 00 8B 45 08 89 45 E8 C7 45 EC ?? ?? ?? ?? 8B 45 F0 C6 80 41 01 00 00 00 8B 45 F0 8D 55 E8 E8 ?? ?? ?? ?? 8B 55 F0 8B 45 08 E8 ?? ?? ?? ?? 8B 45 F0 80 78 42 00 74 0E 8B 45 F0 BB 01 00 00 00 80 78 40 00 74 10 8B 55 F0 8B 45 08 83 C0 08 E8 ?? ?? ?? ?? 31 DB FF 75 08 E8 ?? ?? ?? ?? 5E 85 DB 74 0F 8B 45 F0 31 D2 E8 ?? ?? ?? ?? E9 BB 00 00 00 57 E8 ?? ?? ?? ?? 31 F6 5B 8B 45 08 83 C0 08 89 45 E4 8B 45 F0 FF 75 10 50 E8 ?? ?? ?? ?? 5A 59 85 C0 75 44 8B 55 F0 }
	condition:
		$pattern
}

rule search_for_named_library_445562a8a45d060e61e54b8232bc53b0 {
	meta:
		aliases = "search_for_named_library"
		type = "func"
		size = "269"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 14 89 45 EC 89 55 E8 89 CA 85 C9 0F 84 EA 00 00 00 8D 41 FF 40 80 38 00 75 FA 29 D0 8D 70 01 8D 46 12 83 E0 FC 29 C4 8D 5C 24 0F 83 E3 F0 89 DF 81 EC 14 08 00 00 8D 44 24 0F 83 E0 F0 89 45 E4 8D 4B FF 4A EB 07 41 42 8A 02 88 01 4E 85 F6 75 F5 89 D8 C7 45 F0 00 00 00 00 8B 55 E4 8D 72 FF 8B 55 EC 4A 89 55 E0 80 3F 00 75 0A C6 07 3A C7 45 F0 01 00 00 00 80 3F 3A 75 74 C6 07 00 80 38 00 74 11 89 F1 8D 50 FF 41 42 8A 02 88 01 84 C0 74 13 EB F4 89 F2 B9 ?? ?? ?? ?? 42 41 8A 01 88 02 84 C0 75 F6 89 F3 89 F0 40 80 38 00 75 FA 8D 50 FF B9 ?? ?? ?? ?? 42 41 8A 01 88 02 84 C0 75 }
	condition:
		$pattern
}

rule if_nameindex_e8786b339ce0a653fb4c974ce66ba8b2 {
	meta:
		aliases = "__GI_if_nameindex, if_nameindex"
		type = "func"
		size = "397"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 18 E8 ?? ?? ?? ?? 89 C7 C7 45 E4 00 00 00 00 85 C0 0F 88 63 01 00 00 C7 45 F0 00 00 00 00 B9 80 00 00 00 8D 75 EC 8D 1C 09 8D 43 12 83 E0 FC 29 C4 8D 54 24 0F 83 E2 F0 8D 04 1A 3B 45 F0 75 02 01 CB 89 55 F0 89 5D EC 56 68 12 89 00 00 57 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 79 12 89 F9 87 CB B8 06 00 00 00 CD 80 87 CB E9 CD 00 00 00 8B 45 EC 39 D8 75 04 89 C1 EB AE C1 E8 05 89 45 DC 8D 04 C5 08 00 00 00 50 E8 ?? ?? ?? ?? 89 45 E4 5B C7 45 E0 00 00 00 00 85 C0 0F 85 AD 00 00 00 89 F9 87 CB B8 06 00 00 00 CD 80 87 CB E8 ?? ?? ?? ?? C7 00 69 00 00 00 E9 BF 00 00 00 8B 5D E0 C1 E3 }
	condition:
		$pattern
}

rule gaih_inet_serv_7f92835490936a50e7d0312db28ca1c5 {
	meta:
		aliases = "gaih_inet_serv"
		type = "func"
		size = "145"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C 89 45 DC 89 D3 89 4D D8 8B 7D 08 BE 00 04 00 00 8D 46 12 83 E0 FC 29 C4 8D 44 24 0F 83 E0 F0 8D 55 F0 52 56 50 8D 45 E0 50 8D 43 03 50 FF 75 DC E8 ?? ?? ?? ?? 83 C4 18 85 C0 75 08 83 7D F0 00 75 0B EB 37 83 F8 22 75 32 01 F6 EB C3 C7 07 00 00 00 00 0F BE 03 89 47 04 F6 43 02 02 74 08 8B 55 D8 8B 42 0C EB 04 0F BE 43 01 89 47 08 8B 45 F0 8B 40 08 89 47 0C 31 C0 EB 05 B8 08 01 00 00 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule read_encoded_value_with_base_363e37ef5dc06f5e27a541c76b789a3f {
	meta:
		aliases = "read_encoded_value_with_base"
		type = "func"
		size = "232"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 89 55 DC 89 CE 89 C7 3C 50 74 60 25 FF 00 00 00 89 45 E0 83 E0 0F 83 F8 0C 76 10 E8 ?? ?? ?? ?? 8D 74 26 00 8D BC 27 00 00 00 00 8B 84 83 ?? ?? ?? ?? 01 D8 FF E0 90 8D 74 26 00 8B 11 8D 41 04 85 D2 74 17 83 65 E0 70 83 7D E0 10 74 7D 03 55 DC 89 F9 84 C9 79 04 8B 12 89 F6 8B 4D 08 89 11 83 C4 1C 5B 5E 5F 5D C3 8D 76 00 8D 41 03 83 E0 FC 8B 10 83 C0 04 8B 4D 08 89 11 83 C4 1C 5B 5E 5F 5D C3 8B 11 8D 41 08 EB B6 8D 55 F0 89 C8 E8 97 FD FF FF 8B 55 F0 EB A7 0F BF 11 8D 41 02 EB 9F 66 8B 01 89 C2 81 E2 FF FF 00 00 8D 41 02 EB 8F 8D 55 }
	condition:
		$pattern
}

rule read_encoded_value_with_base_bcce2527dc36fc1f59e24a1a50b39df5 {
	meta:
		aliases = "read_encoded_value_with_base"
		type = "func"
		size = "232"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 89 55 DC 89 CE 89 C7 3C 50 74 60 25 FF 00 00 00 89 45 E0 83 E0 0F 83 F8 0C 76 10 E8 ?? ?? ?? ?? 8D 74 26 00 8D BC 27 00 00 00 00 8B 84 83 ?? ?? ?? ?? 01 D8 FF E0 90 8D 74 26 00 8B 11 8D 41 04 85 D2 74 17 83 65 E0 70 83 7D E0 10 74 7D 03 55 DC 89 F9 84 C9 79 04 8B 12 89 F6 8B 4D 08 89 11 83 C4 1C 5B 5E 5F 5D C3 8D 76 00 8D 41 03 83 E0 FC 8B 10 83 C0 04 8B 4D 08 89 11 83 C4 1C 5B 5E 5F 5D C3 8B 11 8D 41 08 EB B6 8D 55 F0 89 C8 E8 F7 FC FF FF 8B 55 F0 EB A7 0F BF 11 8D 41 02 EB 9F 66 8B 01 89 C2 81 E2 FF FF 00 00 8D 41 02 EB 8F 8D 55 }
	condition:
		$pattern
}

rule get_cie_encoding_9de7649a74b4fa511f9066f44f96cd8a {
	meta:
		aliases = "get_cie_encoding"
		type = "func"
		size = "186"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 89 C6 80 78 09 7A 74 0A 31 C0 8D 65 F4 5B 5E 5F 5D C3 8D 78 09 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 8D 44 07 01 8D 7D EC 89 FA E8 8C FB FF FF 8D 55 E8 E8 D4 FB FF FF 80 7E 08 01 74 65 89 FA E8 77 FB FF FF 89 FA E8 70 FB FF FF 8A 56 0A 80 FA 52 74 40 83 C6 0A 8D 7D F0 EB 0F 80 FA 4C 75 A8 40 8A 56 01 46 80 FA 52 74 29 80 FA 50 75 EC 83 EC 0C 8D 48 01 8A 00 25 FF 00 00 00 83 E0 7F 57 31 D2 E8 E4 FD FF FF 83 C4 10 8A 56 01 46 80 FA 52 75 D7 8A 00 25 FF 00 00 00 8D 65 F4 5B 5E 5F 5D C3 40 EB 9F }
	condition:
		$pattern
}

rule _Unwind_Find_FDE_8c2704e9227c9af4e3e0a5a9cc973aa9 {
	meta:
		aliases = "_Unwind_Find_FDE"
		type = "func"
		size = "313"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B BB ?? ?? ?? ?? 85 FF 74 23 8B 45 08 3B 07 72 15 E9 D7 00 00 00 90 8D 74 26 00 8B 55 08 39 17 0F 86 C7 00 00 00 8B 7F 14 85 FF 75 EE 31 F6 8D 83 ?? ?? ?? ?? 89 45 DC 8D 76 00 8B BB ?? ?? ?? ?? 85 FF 0F 84 9A 00 00 00 8B 47 14 89 83 ?? ?? ?? ?? 8B 55 08 89 F8 E8 6F F8 FF FF 89 C6 8B 83 ?? ?? ?? ?? 85 C0 0F 84 96 00 00 00 8B 0F 39 08 73 0D E9 8B 00 00 00 8D 74 26 00 39 08 72 0A 8D 50 14 8B 40 14 85 C0 75 F2 89 47 14 89 3A 85 F6 74 A9 8B 47 04 8B 55 0C 89 02 8B 47 08 89 42 04 8B 47 10 66 C1 E8 03 F6 47 10 04 75 6A 25 FF 00 00 00 31 }
	condition:
		$pattern
}

rule pthread_initialize_85c362dcd5d9290bbc62abbfe8d891b5 {
	meta:
		aliases = "pthread_initialize"
		type = "func"
		size = "364"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 24 83 3D ?? ?? ?? ?? 00 0F 85 4E 01 00 00 8D 85 00 00 C0 FF 25 00 00 E0 FF A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 8B 1D ?? ?? ?? ?? EB 10 83 7B 34 01 74 07 C7 43 34 00 00 00 00 8B 5B 20 85 DB 75 EC 8D 7D E4 57 6A 03 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 01 C0 BA 00 00 20 00 29 C2 59 5E 39 55 E4 76 0D 89 55 E4 57 6A 03 E8 ?? ?? ?? ?? 58 5A 8D 75 D0 89 F7 89 D8 AB AB AB AB AB C7 45 D0 ?? ?? ?? ?? 6A 00 56 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 45 D0 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 8D 45 DC }
	condition:
		$pattern
}

rule __divdc3_ad7b95c2f870cd21c787e0671c6668f5 {
	meta:
		aliases = "__divdc3"
		type = "func"
		size = "949"
		objfiles = "_divdc3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 24 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 4D 08 DD 45 0C DD 5D E8 DD 45 14 DD 5D E0 DD 45 1C DD 55 D8 DD 45 24 DD 55 D0 D9 C1 D9 E1 D9 C9 D9 E1 DA E9 DF E0 F6 C4 45 75 4F DD 45 D0 D8 F9 DC C9 D9 C9 DC 45 D0 DD 45 E8 D8 CA DC 45 E0 D8 F1 DD 45 E0 DE CB D9 CA DC 65 E8 DE F1 D9 C9 DD E0 DF E0 80 E4 45 80 FC 40 75 49 DD 19 DD 59 08 89 C8 83 C4 24 5B 5E 5F 5D C2 04 00 8D B4 26 00 00 00 00 8D BC 27 00 00 00 00 DD D8 DD 45 D0 DC 75 D8 DD 45 D0 D8 C9 DC 45 D8 DD 45 E0 D8 CA DC 45 E8 D8 F1 D9 CA DC 4D E8 DD 45 E0 DE E1 DE F1 D9 C9 EB AB D9 C9 DD E0 DF E0 80 E4 45 80 FC 40 75 04 }
	condition:
		$pattern
}

rule iruserok2_f69d5d868680e9cd94e0f44a3aa6b2a7 {
	meta:
		aliases = "iruserok2"
		type = "func"
		size = "300"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C 89 45 CC 89 D6 89 4D C8 85 D2 75 12 31 D2 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 85 C0 75 05 83 CF FF EB 24 FF 75 0C FF 75 C8 8B 4D 08 8B 55 CC E8 ?? ?? ?? ?? 89 C7 53 E8 ?? ?? ?? ?? 83 C4 0C 85 FF 0F 84 D2 00 00 00 0B 35 ?? ?? ?? ?? 0F 84 C3 00 00 00 6A 46 E8 ?? ?? ?? ?? 8D 50 12 83 E2 FC 59 29 D4 8D 4C 24 0F 83 E1 F0 8D 55 F0 52 50 51 8D 45 D4 50 FF 75 08 E8 ?? ?? ?? ?? 83 C4 14 85 C0 0F 85 8F 00 00 00 8B 45 F0 85 C0 0F 84 84 00 00 00 FF 70 14 E8 ?? ?? ?? ?? 83 C0 09 89 04 24 E8 ?? ?? ?? ?? 89 C3 8B 45 F0 FF 70 14 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? E8 }
	condition:
		$pattern
}

rule pthread_join_2cc61da7be54c96a3875872a5089e9a6 {
	meta:
		aliases = "pthread_join"
		type = "func"
		size = "377"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C 8B 7D 08 E8 ?? ?? ?? ?? 89 45 F0 89 F8 25 FF 03 00 00 C1 E0 04 8D 98 ?? ?? ?? ?? 89 5D E8 C7 45 EC ?? ?? ?? ?? 8B 55 F0 89 D8 E8 ?? ?? ?? ?? 8B 43 08 89 45 C8 85 C0 74 05 39 78 10 74 0D 53 E8 ?? ?? ?? ?? B8 03 00 00 00 EB 2F 8B 45 F0 39 45 C8 75 0D 53 E8 ?? ?? ?? ?? B8 23 00 00 00 EB 1A 8B 55 C8 80 7A 2D 00 75 06 83 7A 38 00 74 11 53 E8 ?? ?? ?? ?? B8 16 00 00 00 5A E9 E8 00 00 00 8B 45 C8 80 78 2C 00 0F 85 87 00 00 00 8B 45 F0 8D 55 E8 E8 ?? ?? ?? ?? 8B 45 F0 80 78 42 00 74 0E 8B 45 F0 BE 01 00 00 00 80 78 40 00 74 0B 8B 45 F0 8B 55 C8 89 42 38 31 F6 53 E8 ?? ?? ?? }
	condition:
		$pattern
}

rule uw_install_context_1_0150cc17f271206f8f996faea916ef27 {
	meta:
		aliases = "uw_install_context_1"
		type = "func"
		size = "344"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 89 45 E0 89 55 D4 F6 42 63 40 74 0A 80 7A 70 00 0F 85 E8 00 00 00 8B 55 D4 8B 42 10 85 C0 0F 84 E9 00 00 00 BE 01 00 00 00 8D BB ?? ?? ?? ?? 89 7D DC EB 24 8D B4 26 00 00 00 00 85 C9 74 3C 8B 7D DC 80 7C 3E FF 04 0F 85 BB 00 00 00 89 55 EC 89 11 46 83 FE 12 74 4A 8B 45 E0 8B 4C B0 FC 8B 7D D4 8B 54 B7 FC 80 7C 06 6B 00 0F 85 97 00 00 00 8B 45 D4 80 7C 06 6B 00 75 C0 85 D2 74 D3 85 C9 74 CF 39 CA 74 CB 8B 7D DC 31 C0 8A 44 3E FF 57 50 52 51 E8 ?? ?? ?? ?? 83 C4 10 46 83 FE 12 75 B6 8B 45 E0 F6 40 63 40 75 14 8B 55 E0 8B 42 10 85 C0 }
	condition:
		$pattern
}

rule read_encoded_value_with_base_fdd29a101d7bba839b8f650ac528beba {
	meta:
		aliases = "read_encoded_value_with_base"
		type = "func"
		size = "379"
		objfiles = "unwind_c@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 89 55 D0 89 CE 88 45 D7 3C 50 0F 84 9B 00 00 00 89 4D DC 8A 4D D7 81 E1 FF 00 00 00 89 4D D8 89 C8 83 E0 0F 83 F8 0C 76 12 E8 ?? ?? ?? ?? 8D B6 00 00 00 00 8D BC 27 00 00 00 00 8B 84 83 ?? ?? ?? ?? 01 D8 FF E0 90 8D 74 26 00 8B 06 89 45 CC 83 C6 04 8B 45 CC 85 C0 74 31 83 65 D8 70 83 7D D8 10 0F 84 F3 00 00 00 8B 45 D0 01 45 CC 80 7D D7 00 79 17 8B 55 CC 8B 12 89 55 CC EB 0D 90 90 90 90 90 90 90 90 90 90 90 90 90 8B 45 CC 8B 4D 08 89 01 89 F0 83 C4 2C 5B 5E 5F 5D C3 8D B4 26 00 00 00 00 8D BC 27 00 00 00 00 8D 41 03 83 E0 FC 8B 10 }
	condition:
		$pattern
}

rule execute_cfa_program_bd057534e65468478da4127ab24bad4c {
	meta:
		aliases = "execute_cfa_program"
		type = "func"
		size = "1348"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 89 C7 89 55 D8 89 4D D4 8B 45 08 C7 80 90 00 00 00 00 00 00 00 39 D7 0F 83 AC 00 00 00 8B B0 A4 00 00 00 8B 41 60 C1 E8 1F 03 41 4C 39 F0 0F 86 95 00 00 00 C7 45 E0 00 00 00 00 8D 55 F0 89 55 D0 8D 76 00 8D BC 27 00 00 00 00 8A 0F 47 31 C0 88 C8 89 C2 81 E2 C0 00 00 00 83 FA 40 74 2C 81 FA 80 00 00 00 0F 84 95 00 00 00 81 FA C0 00 00 00 74 78 80 F9 2F 76 63 E8 ?? ?? ?? ?? 8D B4 26 00 00 00 00 8D BC 27 00 00 00 00 83 E0 3F 8B 4D 08 0F AF 81 B0 00 00 00 8D 04 06 89 81 A4 00 00 00 8D 76 00 8D BC 27 00 00 00 00 39 7D D8 76 19 8B 45 08 }
	condition:
		$pattern
}

rule callrpc_40c4563aff5a2774474a02d40bacadc0 {
	meta:
		aliases = "callrpc"
		type = "func"
		size = "510"
		objfiles = "clnt_simple@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 3C C7 45 C0 00 00 00 00 C7 45 C4 00 00 00 00 C7 45 B8 00 00 00 00 C7 45 BC 00 00 00 00 E8 ?? ?? ?? ?? 89 C3 8B B0 A4 00 00 00 85 F6 75 1F 6A 18 6A 01 E8 ?? ?? ?? ?? 89 C2 5E 5F 31 C0 85 D2 0F 84 A9 01 00 00 89 D6 89 93 A4 00 00 00 83 7E 14 00 75 18 68 00 01 00 00 E8 ?? ?? ?? ?? 89 46 14 C6 00 00 C7 46 04 FF FF FF FF 59 83 7E 10 00 74 25 8B 45 0C 39 46 08 75 1D 8B 55 10 39 56 0C 75 15 FF 75 08 FF 76 14 E8 ?? ?? ?? ?? 5F 5A 85 C0 0F 84 18 01 00 00 C7 46 10 00 00 00 00 8B 46 04 83 F8 FF 74 0E 50 E8 ?? ?? ?? ?? C7 46 04 FF FF FF FF 5B 8B 16 85 D2 74 0E 8B 42 04 52 FF 50 10 }
	condition:
		$pattern
}

rule __gcc_personality_v0_572db3bc2cc61f0bcd5ac4676f3ab0ba {
	meta:
		aliases = "__gcc_personality_v0"
		type = "func"
		size = "592"
		objfiles = "unwind_c@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 3C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 83 7D 08 01 74 15 B8 03 00 00 00 8D 65 F4 5B 5E 5F 5D C3 90 8D B4 26 00 00 00 00 F6 45 0C 02 75 0D B8 08 00 00 00 8D 65 F4 5B 5E 5F 5D C3 C7 45 F0 00 00 00 00 83 EC 0C 8B 45 1C 50 E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 C0 74 D7 8B 45 1C 85 C0 0F 84 90 01 00 00 83 EC 0C 8B 7D 1C 57 E8 ?? ?? ?? ?? 83 C4 10 89 45 C8 8A 16 8D 7E 01 80 FA FF 0F 84 68 01 00 00 81 E2 FF 00 00 00 89 D6 8B 55 1C 89 F0 E8 C4 FE FF FF 83 EC 0C 8D 55 CC 52 89 F9 89 C2 89 F0 E8 32 FD FF FF 89 C7 83 C4 10 8A 07 88 45 DC 8D 4F 01 FE C0 0F 84 1D 01 00 00 8D 45 E0 89 45 }
	condition:
		$pattern
}

rule __mulvdi3_1d63f6ff4a3b6b759383d482641f6acf {
	meta:
		aliases = "__mulvdi3"
		type = "func"
		size = "406"
		objfiles = "_mulvdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 3C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 75 08 8B 7D 0C 8B 45 10 8B 55 14 89 45 C8 89 55 CC 89 F9 89 75 E8 89 F0 C1 F8 1F 39 C7 75 23 89 D1 8B 75 C8 89 F0 C1 F8 1F 39 C2 75 71 8B 45 E8 F7 EE 89 C6 89 D7 89 F0 89 FA 83 C4 3C 5B 5E 5F 5D C3 8B 55 CC 8B 45 C8 89 45 EC C1 F8 1F 39 C2 0F 85 A9 00 00 00 8B 45 E8 F7 65 EC 89 55 C0 89 45 D8 89 55 DC 8B 45 EC F7 E7 89 45 D0 89 55 D4 85 FF 78 74 8B 45 EC 85 C0 78 65 8B 55 C0 31 C9 03 55 D0 13 4D D4 89 D0 C1 F8 1F 39 C8 0F 85 8E 00 00 00 89 55 DC 8B 75 D8 8B 7D DC EB 98 8B 45 E8 F7 E6 89 55 C4 89 45 E0 89 55 E4 8B 45 E8 F7 E1 89 }
	condition:
		$pattern
}

rule dlopen_a2aeb1407a1fb81a1525c1caa4517053 {
	meta:
		aliases = "dlopen"
		type = "func"
		size = "1073"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 3C F6 45 0C 03 75 0F C7 05 ?? ?? ?? ?? 0A 00 00 00 E9 09 04 00 00 C7 45 F0 00 00 00 00 8B 7D 04 80 3D ?? ?? ?? ?? 00 75 1B C6 05 ?? ?? ?? ?? 01 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 83 7D 08 00 75 0A A1 ?? ?? ?? ?? E9 CD 03 00 00 E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 89 D8 31 F6 EB 17 8B 08 8B 51 14 39 FA 73 0B 85 F6 74 05 39 56 14 73 02 89 CE 8B 40 10 85 C0 75 E5 89 5D F0 EB 03 89 45 F0 8B 45 F0 89 45 CC 85 C0 74 07 8B 40 10 85 C0 75 EC 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F C7 45 DC 02 00 00 00 85 C0 75 09 8B 4D 0C 83 E1 02 89 4D DC 68 ?? ?? ?? ?? E8 ?? ?? }
	condition:
		$pattern
}

rule uw_frame_state_for_f17f40ccbd5c4e9d82c0bbb2c86209ff {
	meta:
		aliases = "uw_frame_state_for"
		type = "func"
		size = "837"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 40 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 89 45 C8 89 55 C4 68 C0 00 00 00 6A 00 52 E8 ?? ?? ?? ?? 8B 45 C8 C7 40 68 00 00 00 00 C7 40 50 00 00 00 00 8B 50 4C 83 C4 10 85 D2 0F 84 F7 02 00 00 83 EC 08 83 C0 54 50 8B 4D C8 8B 41 60 C1 E8 1F 8D 44 02 FF 50 E8 ?? ?? ?? ?? 89 45 D0 83 C4 10 85 C0 0F 84 CF 02 00 00 8B 55 C8 8B 42 5C 8B 4D C4 89 81 A4 00 00 00 8B 45 D0 83 C0 04 8B 55 D0 8B 52 04 29 D0 89 45 D4 89 C7 83 C7 09 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 8D 14 38 8D 42 01 8B 4D D4 80 79 09 65 0F 84 62 01 00 00 8B 55 C4 81 C2 B0 00 00 00 E8 FF F5 FF FF 8B 55 C4 81 C2 AC 00 }
	condition:
		$pattern
}

rule __muldc3_240d93b9e2379ad460be38f006a24b54 {
	meta:
		aliases = "__muldc3"
		type = "func"
		size = "1226"
		objfiles = "_muldc3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 44 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 55 08 DD 45 0C DD 55 C8 DD 45 14 DD 55 C0 DD 45 1C DD 55 B8 DD 45 24 DD 55 B0 D9 CB D8 C9 DD 5D E8 D9 C1 D8 CB DD 5D E0 DD 45 C8 DE CB D9 CA DD 5D D8 DE C9 DD 5D D0 DD 45 E8 DD 45 E0 D9 C1 D8 E1 DD 45 D8 DD 45 D0 D9 C1 D8 C1 D9 CB DD E0 DF E0 80 E4 45 80 FC 40 75 19 DD DC DD D8 DD D8 DD DA DD 1A DD 5A 08 89 D0 83 C4 44 5B 5E 5F 5D C2 04 00 D9 CB DD E0 DF E0 80 E4 45 80 FC 40 75 0A DD DD DD D8 DD D8 DD D9 EB D7 DD 45 C8 D8 E0 DD 45 C8 DD E8 DF E0 80 E4 45 80 F4 40 0F 85 DF 01 00 00 DD E8 DF E0 80 E4 45 80 F4 40 0F 84 D1 01 00 00 }
	condition:
		$pattern
}

rule byte_re_compile_fastmap_998600330fa26c6594a13e2f2e02c15e {
	meta:
		aliases = "byte_re_compile_fastmap"
		type = "func"
		size = "804"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 48 89 C6 8B 40 10 89 45 E0 8B 1E 8B 56 08 01 DA 89 55 E4 8D 4C 24 0F 83 E1 F0 89 4D F0 68 00 01 00 00 6A 00 50 E8 ?? ?? ?? ?? 8A 46 1C 83 C8 08 83 E0 FE 88 46 1C C6 45 EA 01 C6 45 EB 00 31 FF C7 45 EC 05 00 00 00 83 C4 0C 8B 45 E0 83 C0 0A 89 45 D8 3B 5D E4 74 06 8A 03 3C 01 75 29 85 FF 8A 56 1C 0F 84 90 02 00 00 88 D0 83 E0 01 08 45 EA 83 E2 FE 0A 55 EA 88 56 1C 4F 8B 55 F0 8B 1C BA C6 45 EA 01 EB CC 43 3C 1D 0F 87 58 02 00 00 0F B6 C0 FF 24 85 ?? ?? ?? ?? 31 D2 E9 CF 00 00 00 31 D2 E9 E9 00 00 00 80 4E 1C 01 E9 5A 02 00 00 0F B6 43 01 8B 4D E0 C6 04 01 01 E9 2C 02 00 }
	condition:
		$pattern
}

rule __msgwrite_ac735f34c122b49177987b3e26a30605 {
	meta:
		aliases = "__msgwrite"
		type = "func"
		size = "176"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 64 89 45 C0 89 55 BC 89 4D B8 8D 5C 24 0F 83 E3 F0 E8 ?? ?? ?? ?? 89 45 E0 E8 ?? ?? ?? ?? 89 45 E4 E8 ?? ?? ?? ?? 89 45 E8 8D 75 E0 8D 7B 0C A5 A5 A5 C7 43 04 01 00 00 00 C7 43 08 02 00 00 00 C7 03 18 00 00 00 8B 45 BC 89 45 EC 8B 45 B8 89 45 F0 8D 45 EC 89 45 CC C7 45 D0 01 00 00 00 C7 45 C4 00 00 00 00 C7 45 C8 00 00 00 00 89 5D D4 C7 45 D8 18 00 00 00 C7 45 DC 00 00 00 00 8D 5D C4 6A 00 53 FF 75 C0 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 79 0D E8 ?? ?? ?? ?? 83 38 04 74 E4 83 C8 FF 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule rcmd_943d707624ed2af73934caa86b9bf0b9 {
	meta:
		aliases = "rcmd"
		type = "func"
		size = "1108"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 70 8B 45 0C 66 89 45 86 E8 ?? ?? ?? ?? 89 45 90 81 EC 10 04 00 00 8D 44 24 0F 83 E0 F0 BE 00 04 00 00 8D 7D E8 EB 39 8B 5D EC 83 FB FF 75 0A E8 ?? ?? ?? ?? 83 38 22 74 16 E8 ?? ?? ?? ?? 89 18 8B 55 08 FF 32 E8 ?? ?? ?? ?? E9 9E 00 00 00 01 F6 8D 46 12 83 E0 FC 29 C4 8D 44 24 0F 83 E0 F0 8D 55 EC 52 57 56 50 8D 45 94 50 8B 45 08 FF 30 E8 ?? ?? ?? ?? 83 C4 18 85 C0 75 AB 83 7D E8 00 74 A5 66 C7 45 AC 01 00 66 C7 45 B4 01 00 8B 45 E8 8B 00 8B 55 08 89 02 68 00 00 40 00 E8 ?? ?? ?? ?? 89 45 8C C7 45 E4 FF 03 00 00 BF 01 00 00 00 5B 8D 45 E4 50 E8 ?? ?? ?? ?? 89 C6 59 85 C0 }
	condition:
		$pattern
}

rule pthread_sighandler_4828cc19a184b178a6f710da2ffc24f9 {
	meta:
		aliases = "pthread_sighandler"
		type = "func"
		size = "91"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 8B 5D 08 E8 ?? ?? ?? ?? 89 C7 80 78 58 00 74 09 C6 40 58 00 89 58 20 EB 34 8B 70 54 85 F6 75 03 89 68 54 83 EC 58 89 E2 8D 45 0C 6A 58 50 52 E8 ?? ?? ?? ?? 83 C4 0C 53 FF 14 9D ?? ?? ?? ?? 83 C4 5C 85 F6 75 07 C7 47 54 00 00 00 00 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule pthread_sighandler_rt_d7a765829bdabe45cfc09c4a615e2f9b {
	meta:
		aliases = "pthread_sighandler_rt"
		type = "func"
		size = "77"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 8B 75 08 E8 ?? ?? ?? ?? 89 C7 80 78 58 00 74 09 C6 40 58 00 89 70 20 EB 26 8B 58 54 85 DB 75 03 89 68 54 FF 75 10 FF 75 0C 56 FF 14 B5 ?? ?? ?? ?? 83 C4 0C 85 DB 75 07 C7 47 54 00 00 00 00 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule nan_9538f1961499397ad5bf685562440dcc {
	meta:
		aliases = "__GI_nan, nan"
		type = "func"
		size = "76"
		objfiles = "nan@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 8B 7D 08 80 3F 00 75 08 D9 05 ?? ?? ?? ?? EB 2E 89 E3 57 E8 ?? ?? ?? ?? 59 83 C0 18 83 E0 FC 29 C4 8D 74 24 0F 83 E6 F0 57 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 6A 00 56 E8 ?? ?? ?? ?? 89 DC 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule nanf_be95debb65daa58c7b4c180af5f92103 {
	meta:
		aliases = "__GI_nanf, nanf"
		type = "func"
		size = "76"
		objfiles = "nan@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 8B 7D 08 80 3F 00 75 08 D9 05 ?? ?? ?? ?? EB 2E 89 E3 57 E8 ?? ?? ?? ?? 5A 83 C0 18 83 E0 FC 29 C4 8D 74 24 0F 83 E6 F0 57 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 6A 00 56 E8 ?? ?? ?? ?? 89 DC 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __divxc3_db7832f06ce5951e1cc9efa87ffb6542 {
	meta:
		aliases = "__divxc3"
		type = "func"
		size = "951"
		objfiles = "_divxc3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 4D 08 DB 6D 24 D9 E1 DB 6D 30 D9 E1 DA E9 DF E0 F6 C4 45 75 58 DB 6D 24 DB 6D 30 DE F9 DB 6D 24 D8 C9 DB 6D 30 DE C1 DB 6D 0C D8 CA DB 6D 18 DC C1 D9 C9 D8 F2 D9 C9 DE CB DB 6D 0C DE EB D9 CA DE F1 D9 C9 DD E0 DF E0 80 E4 45 80 FC 40 75 4C DB 39 DB 79 0C 89 C8 5B 5E 5F 5D C2 04 00 EB 0D 90 90 90 90 90 90 90 90 90 90 90 90 90 DB 6D 30 DB 6D 24 DE F9 DB 6D 30 D8 C9 DB 6D 24 DE C1 DB 6D 18 D8 CA DB 6D 0C DC C1 D9 C9 D8 F2 D9 CB DE C9 DB 6D 18 DE E1 DE F1 D9 C9 EB A8 D9 C9 DD E0 DF E0 80 E4 45 80 FC 40 75 04 D9 C9 EB A2 D9 EE DB 6D 24 DD E9 }
	condition:
		$pattern
}

rule __mulxc3_e0875431e8a8f668a23266cf669b4cb5 {
	meta:
		aliases = "__mulxc3"
		type = "func"
		size = "1205"
		objfiles = "_mulxc3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 55 08 DB 6D 0C DB 6D 24 DC C9 DB 6D 18 DB 6D 30 DC C9 DB 6D 0C DE C9 DB 6D 18 DE CB D9 C3 D8 E2 D9 C1 D8 C4 D9 C9 DD E0 DF E0 80 E4 45 80 FC 40 75 16 DD DC DD DC DD D8 DD D8 DB 3A DB 7A 0C 89 D0 5B 5E 5F 5D C2 04 00 D9 C9 DD E0 DF E0 80 E4 45 80 FC 40 75 0A DD DD DD DB DD D8 DD D8 EB DA DB 6D 0C D8 E0 DB 6D 0C DD E8 DF E0 80 E4 45 80 F4 40 0F 85 EC 01 00 00 DD E8 DF E0 80 E4 45 80 F4 40 0F 84 DE 01 00 00 D9 83 ?? ?? ?? ?? F7 45 14 00 80 00 00 74 08 DD D8 D9 83 ?? ?? ?? ?? DB 7D 0C DB 6D 18 D8 E0 DB 6D 18 DD E8 DF E0 80 E4 45 80 F4 40 0F }
	condition:
		$pattern
}

rule __popcountsi2_cc3c2da17a1ecbb16b97bed77c267c48 {
	meta:
		aliases = "__popcountsi2"
		type = "func"
		size = "81"
		objfiles = "_popcountsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B BB ?? ?? ?? ?? 8B 75 08 31 C0 8A 45 0A 31 C9 8A 0C 07 89 F2 0F B6 C6 8A 04 07 25 FF 00 00 00 01 C1 89 F0 25 FF 00 00 00 31 D2 8A 14 07 01 CA C1 EE 18 31 C0 8A 04 37 01 D0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _Unwind_Backtrace_f6e65e1ea6d1e2730be3cd8996337b15 {
	meta:
		aliases = "_Unwind_Backtrace"
		type = "func"
		size = "153"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 81 EC 50 01 00 00 8B 4D 04 8D 85 78 FF FF FF 89 85 AC FE FF FF 8D 55 08 E8 CE FC FF FF 8D 85 B8 FE FF FF 89 85 B0 FE FF FF EB 1A 83 BD B4 FE FF FF 05 74 53 8B 95 B0 FE FF FF 8B 85 AC FE FF FF E8 46 FF FF FF 8B 95 B0 FE FF FF 8B 85 AC FE FF FF E8 A5 EF FF FF 89 85 B4 FE FF FF 85 C0 74 05 83 F8 05 75 18 83 EC 08 8B 45 0C 50 8B 85 AC FE FF FF 50 FF 55 08 83 C4 10 85 C0 74 AE C7 85 B4 FE FF FF 03 00 00 00 8B 85 B4 FE FF FF 8D 65 F8 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _Unwind_ForcedUnwind_Phase2_25ad725ae922457e3708f6a7d14da85f {
	meta:
		aliases = "_Unwind_ForcedUnwind_Phase2"
		type = "func"
		size = "240"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 81 EC D0 00 00 00 89 85 2C FF FF FF 89 D7 8B 40 0C 89 85 30 FF FF FF 8B 95 2C FF FF FF 8B 52 10 89 95 34 FF FF FF 8D 85 38 FF FF FF 89 85 28 FF FF FF E9 85 00 00 00 8D 74 26 00 83 F8 05 0F 85 99 00 00 00 B8 1A 00 00 00 52 8B 8D 34 FF FF FF 51 57 8B 95 2C FF FF FF 52 8B 95 2C FF FF FF 8B 4A 04 51 8B 12 52 50 6A 01 FF 95 30 FF FF FF 83 C4 20 85 C0 75 67 83 FE 05 74 67 8B 45 E0 85 C0 74 2D 83 EC 08 57 8B B5 2C FF FF FF 56 8B 95 2C FF FF FF 8B 4A 04 51 8B 12 52 6A 0A 6A 01 FF D0 89 C6 83 C4 20 83 F8 07 74 38 83 F8 08 75 2E 8B 95 28 FF FF FF 89 F8 E8 0F FC FF FF 8B 95 28 FF FF FF 89 }
	condition:
		$pattern
}

rule __negdi2_a994d8013174792deac2e3dd32c55b6a {
	meta:
		aliases = "__negdi2"
		type = "func"
		size = "50"
		objfiles = "_negdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 04 8B 75 08 8B 7D 0C 89 75 F4 89 FE F7 DE 8B 7D F4 85 FF 0F 95 C1 81 E1 FF 00 00 00 29 CE F7 5D F4 8B 45 F4 89 F2 59 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __gcc_bcmp_151164c759c47ea720e3eaa173a4d559 {
	meta:
		aliases = "__gcc_bcmp"
		type = "func"
		size = "96"
		objfiles = "__gcc_bcmp@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 04 8B 7D 08 8B 75 0C 8B 4D 10 85 C9 74 2F 8A 07 88 45 F7 8A 06 38 45 F7 75 2C 31 D2 EB 1C 8D 74 26 00 8D BC 27 00 00 00 00 8A 44 3A 01 88 45 F7 8A 44 32 01 42 38 45 F7 75 0C 49 75 EC 31 D2 89 D0 5A 5E 5F 5D C3 31 D2 8A 55 F7 25 FF 00 00 00 29 C2 89 D0 5A 5E 5F 5D C3 }
	condition:
		$pattern
}

rule read_uleb128_b1a4435e6c31d6d4a48f7b9a9e0bb451 {
	meta:
		aliases = "read_uleb128"
		type = "func"
		size = "74"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a, unwind_c@libgcc_eh.a, unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 08 89 45 F0 89 55 F4 31 F6 31 FF 8D B4 26 00 00 00 00 8D BC 27 00 00 00 00 8B 45 F0 8A 10 40 89 45 F0 89 D0 83 E0 7F 89 F1 D3 E0 09 C7 83 C6 07 84 D2 78 E5 8B 45 F4 89 38 8B 45 F0 83 C4 08 5E 5F 5D C3 }
	condition:
		$pattern
}

rule read_sleb128_54a44737cdb2c6847e93f2e6f8a436fc {
	meta:
		aliases = "read_sleb128"
		type = "func"
		size = "110"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a, unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 0C 89 45 EC 89 55 F0 31 FF C7 45 F4 00 00 00 00 89 F6 8D BC 27 00 00 00 00 8B 45 EC 8A 10 40 89 45 EC 88 D1 81 E1 FF 00 00 00 89 CE 89 C8 83 E0 7F 89 F9 D3 E0 09 45 F4 83 C7 07 84 D2 78 DA 83 FF 1F 77 11 83 E6 40 74 0C B8 FF FF FF FF 89 F9 D3 E0 09 45 F4 8B 55 F4 8B 45 F0 89 10 8B 45 EC 83 C4 0C 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __ashrdi3_80b9183ce4b23344791d23107ea789c8 {
	meta:
		aliases = "__ashrdi3"
		type = "func"
		size = "115"
		objfiles = "_ashrdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 10 8B 45 08 8B 55 0C 89 45 E8 89 55 EC 8B 55 10 85 D2 74 35 C7 45 F4 20 00 00 00 8B 55 10 29 55 F4 8B 45 F4 85 C0 7E 31 8B 45 EC 89 C7 8A 4D 10 D3 FF 8A 4D F4 D3 E0 8B 55 E8 8A 4D 10 D3 EA 89 C6 09 D6 89 75 E8 89 7D EC 8B 45 E8 8B 55 EC 83 C4 10 5E 5F 5D C3 8D 76 00 8B 45 EC 89 C7 C1 FF 1F 8B 4D F4 F7 D9 89 C6 D3 FE EB D7 }
	condition:
		$pattern
}

rule fde_single_encoding_compare_b1a4113c26ee13b90d20072544bdf5e8 {
	meta:
		aliases = "fde_single_encoding_compare"
		type = "func"
		size = "140"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 10 8B 75 08 8B 46 10 66 C1 E8 03 25 FF 00 00 00 89 F2 E8 92 FE FF FF 89 C7 83 EC 0C 8B 4D 0C 83 C1 08 8B 46 10 66 C1 E8 03 25 FF 00 00 00 8D 55 F4 52 89 FA E8 D0 FE FF FF 8B 4D 10 83 C1 08 8B 46 10 66 C1 E8 03 25 FF 00 00 00 8D 55 F0 89 14 24 89 FA E8 B1 FE FF FF 83 C4 10 8B 45 F0 39 45 F4 77 16 19 C0 8D 65 F8 5E 5F 5D C3 8D B6 00 00 00 00 8D BC 27 00 00 00 00 B8 01 00 00 00 8D 65 F8 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fde_mixed_encoding_compare_de19b56d09e0f264d3940eb382c654d4 {
	meta:
		aliases = "fde_mixed_encoding_compare"
		type = "func"
		size = "156"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 10 8B 7D 0C 8D 47 04 2B 47 04 E8 1A F8 FF FF 89 C6 81 E6 FF 00 00 00 8B 55 08 89 F0 E8 28 F6 FF FF 83 EC 0C 8D 4F 08 8D 55 F4 52 89 C2 89 F0 E8 75 F6 FF FF 8B 45 10 83 C0 04 8B 55 10 2B 42 04 E8 E4 F7 FF FF 89 C6 81 E6 FF 00 00 00 8B 55 08 89 F0 E8 F2 F5 FF FF 8B 4D 10 83 C1 08 8D 55 F0 89 14 24 89 C2 89 F0 E8 3D F6 FF FF 83 C4 10 8B 45 F0 39 45 F4 77 12 19 C0 8D 65 F8 5E 5F 5D C3 89 F6 8D BC 27 00 00 00 00 B8 01 00 00 00 8D 65 F8 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __muldi3_1f2559194d1553dbdec89c7a823aac71 {
	meta:
		aliases = "__muldi3"
		type = "func"
		size = "65"
		objfiles = "_muldi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 10 C7 45 E8 00 00 00 00 C7 45 EC 00 00 00 00 8B 4D 08 8B 75 10 89 C8 F7 E6 89 45 E8 89 55 EC 8B 45 E8 8B 55 EC 0F AF 4D 14 0F AF 75 0C 01 F1 01 D1 89 CA 83 C4 10 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __ashldi3_ea2cd4659fdb6a9a6a60f742c001ab8d {
	meta:
		aliases = "__ashldi3"
		type = "func"
		size = "114"
		objfiles = "_ashldi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 10 C7 45 F0 00 00 00 00 C7 45 F4 00 00 00 00 8B 75 08 8B 7D 0C 8B 45 10 85 C0 74 31 BA 20 00 00 00 2B 55 10 85 D2 7E 31 89 75 EC 89 F0 8A 4D 10 D3 E0 89 45 F0 88 D1 D3 6D EC 89 FA 8A 4D 10 D3 E2 0B 55 EC 89 55 F4 8B 75 F0 8B 7D F4 89 F0 89 FA 83 C4 10 5E 5F 5D C3 90 C7 45 F0 00 00 00 00 89 D1 F7 D9 D3 E6 89 75 F4 EB DC }
	condition:
		$pattern
}

rule __lshrdi3_30d68a8352b4c757238c585769b7d6b7 {
	meta:
		aliases = "__lshrdi3"
		type = "func"
		size = "116"
		objfiles = "_lshrdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 10 C7 45 F0 00 00 00 00 C7 45 F4 00 00 00 00 8B 75 08 8B 7D 0C 8B 45 10 85 C0 74 31 BA 20 00 00 00 2B 55 10 85 D2 7E 31 89 7D EC 89 F8 8A 4D 10 D3 E8 89 45 F4 88 D1 D3 65 EC 89 F2 8A 4D 10 D3 EA 0B 55 EC 89 55 F0 8B 75 F0 8B 7D F4 89 F0 89 FA 83 C4 10 5E 5F 5D C3 90 C7 45 F4 00 00 00 00 89 D1 F7 D9 89 F8 D3 E8 89 45 F0 EB DA }
	condition:
		$pattern
}

rule __fixunssfdi_78dc9414b9d12054f8c5beaf9c41896b {
	meta:
		aliases = "__fixunssfdi"
		type = "func"
		size = "103"
		objfiles = "_fixunssfdi@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 10 E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? D9 45 08 D9 81 ?? ?? ?? ?? D8 C9 D9 7D F6 66 8B 45 F6 B4 0C 66 89 45 F4 D9 6D F4 DF 7D E8 D9 6D F6 8B 45 E8 89 C6 31 FF 57 50 DF 2C 24 D8 89 ?? ?? ?? ?? DE C1 D9 6D F4 DF 7D E8 D9 6D F6 8B 45 E8 89 F7 BE 00 00 00 00 09 F0 89 FA 83 C4 18 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __fixunsxfdi_bba9a69fadface8b7a6d8010de7c0c11 {
	meta:
		aliases = "__fixunsxfdi"
		type = "func"
		size = "205"
		objfiles = "_fixunsxfdi@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 10 E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? DB 6D 08 D9 EE DD E9 DF E0 F6 C4 45 0F 84 9A 00 00 00 D9 C0 D8 89 ?? ?? ?? ?? D9 7D F6 66 8B 45 F6 B4 0C 66 89 45 F4 D9 6D F4 DF 7D E8 D9 6D F6 8B 45 E8 89 C6 31 FF 89 F7 BE 00 00 00 00 57 56 DF 2C 24 83 C4 08 85 FF 78 32 DE E9 D9 EE DD E9 DF E0 F6 C4 45 74 35 D9 6D F4 DF 7D E8 D9 6D F6 8B 45 E8 31 D2 01 F0 11 FA 83 C4 10 5E 5F 5D C3 8D B6 00 00 00 00 8D BF 00 00 00 00 D8 81 ?? ?? ?? ?? EB C6 90 8D B4 26 00 00 00 00 D9 E0 D9 6D F4 DF 7D E8 D9 6D F6 8B 45 E8 31 D2 29 C6 19 D7 89 F0 89 FA 83 C4 10 5E 5F 5D C3 90 DD D8 31 C0 31 D2 83 C4 }
	condition:
		$pattern
}

rule __fixunsdfdi_6f7a32f0049a6c88622c4c12d8ec15cc {
	meta:
		aliases = "__fixunsdfdi"
		type = "func"
		size = "103"
		objfiles = "_fixunsdfdi@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 10 E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? DD 45 08 D9 81 ?? ?? ?? ?? D8 C9 D9 7D F6 66 8B 45 F6 B4 0C 66 89 45 F4 D9 6D F4 DF 7D E8 D9 6D F6 8B 45 E8 89 C6 31 FF 57 50 DF 2C 24 D8 89 ?? ?? ?? ?? DE C1 D9 6D F4 DF 7D E8 D9 6D F6 8B 45 E8 89 F7 BE 00 00 00 00 09 F0 89 FA 83 C4 18 5E 5F 5D C3 }
	condition:
		$pattern
}

rule frame_heapsort_84325e4ab36d7dffcbbaf4602c5bea4b {
	meta:
		aliases = "frame_heapsort"
		type = "func"
		size = "152"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 20 89 45 EC 89 55 E8 89 4D E4 83 C1 08 89 4D F0 8B 45 E4 8B 40 04 89 45 F4 D1 E8 89 C6 4E 78 25 89 F6 8D BC 27 00 00 00 00 83 EC 08 8B 7D F4 57 56 8B 4D F0 8B 55 E8 8B 45 EC E8 FA FE FF FF 83 C4 10 4E 79 E4 8B 7D F4 4F 85 FF 7E 3D 8B 55 F4 8B 4D E4 8D 74 91 08 89 F6 8B 45 E4 8B 50 08 8B 46 FC 8B 4D E4 89 41 08 89 56 FC 83 EC 08 57 6A 00 8B 4D F0 8B 55 E8 8B 45 EC E8 BA FE FF FF 4F 83 EE 04 83 C4 10 85 FF 7F CF 8D 65 F8 5E 5F 5D C3 }
	condition:
		$pattern
}

rule frame_downheap_12283f760cb548f41e01fd8a373b3875 {
	meta:
		aliases = "frame_downheap"
		type = "func"
		size = "184"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 20 89 45 EC 89 55 E8 89 4D E4 8B 45 08 8D 7C 00 01 3B 7D 0C 0F 8D 90 00 00 00 89 45 F0 EB 4D 8D 76 00 8D BC 27 00 00 00 00 8B 45 E4 8D 04 B8 89 45 F4 8B 55 F0 8B 4D E4 8D 34 91 50 8B 45 F4 8B 08 51 8B 16 52 8B 45 EC 50 FF 55 E8 83 C4 10 85 C0 79 57 8B 16 8B 4D F4 8B 01 89 06 89 11 8D 44 3F 01 89 7D F0 39 45 0C 7E 40 89 C7 8D 77 01 39 75 0C 7E B5 8D 04 BD 00 00 00 00 8B 55 E4 01 C2 89 55 F4 51 8B 4D E4 8B 44 08 04 50 8B 02 50 8B 45 EC 50 FF 55 E8 83 C4 10 85 C0 79 95 8B 45 E4 8D 04 B0 89 45 F4 89 F7 EB 88 8D 65 F8 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __udivdi3_d86d80d20b049545d078a0a7b7c566fb {
	meta:
		aliases = "__udivdi3"
		type = "func"
		size = "331"
		objfiles = "_udivdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 20 C7 45 E0 00 00 00 00 C7 45 E4 00 00 00 00 8B 45 10 8B 55 14 89 45 F4 89 C1 89 D7 8B 45 08 89 45 EC 8B 75 0C 85 D2 75 30 39 F1 76 5C 89 F2 F7 F1 89 C1 31 C0 8D 74 26 00 89 4D E0 89 45 E4 8B 45 E0 8B 55 E4 83 C4 20 5E 5F 5D C3 8D B6 00 00 00 00 8D BC 27 00 00 00 00 39 F2 0F 87 B8 00 00 00 0F BD C2 83 F0 1F 89 45 E8 75 4D 39 F2 72 0C 8B 55 EC 39 55 F4 0F 87 9D 00 00 00 B9 01 00 00 00 31 C0 EB B4 8D 74 26 00 8B 45 F4 85 C0 75 0C B8 01 00 00 00 31 D2 F7 75 F4 89 C1 89 F0 89 FA F7 F1 89 C6 8B 45 EC F7 F1 89 C1 89 F0 EB 8A 8D 76 00 8D BC 27 00 00 00 00 B8 20 00 00 00 2B 45 E8 }
	condition:
		$pattern
}

rule classify_object_over_fdes_c8ae02d1f459dd80a0f37e32fb4bc893 {
	meta:
		aliases = "classify_object_over_fdes"
		type = "func"
		size = "352"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 30 89 45 CC 89 D7 8B 02 85 C0 0F 84 17 01 00 00 C7 45 D4 00 00 00 00 C7 45 D8 00 00 00 00 C7 45 DC 00 00 00 00 C7 45 E0 00 00 00 00 8D 45 F4 89 45 C8 EB 37 90 8D 74 26 00 B8 FF FF FF FF 8B 55 F4 85 C2 74 14 FF 45 D8 8B 45 CC 39 10 76 0A 89 10 90 8D B4 26 00 00 00 00 89 F8 03 07 8D 78 04 8B 40 04 85 C0 0F 84 C3 00 00 00 8B 47 04 85 C0 74 E7 8D 77 04 29 C6 39 75 D4 0F 84 99 00 00 00 89 F0 E8 C2 FB FF FF 89 45 DC 88 45 D3 88 C1 81 E1 FF 00 00 00 89 4D E4 8B 55 CC 89 C8 E8 C7 F9 FF FF 89 45 E0 8B 55 CC 8B 42 10 25 F8 07 00 00 66 3D F8 07 0F 84 7E 00 00 00 8B 55 CC 8B 42 10 66 }
	condition:
		$pattern
}

rule add_fdes_52acfc78bf9a20a7ed39a54c4bb4ed0c {
	meta:
		aliases = "add_fdes"
		type = "func"
		size = "312"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 30 89 45 D8 89 55 D4 89 CF 89 C2 8B 40 10 66 C1 E8 03 25 FF 00 00 00 89 45 E0 E8 8A FB FF FF 89 45 E4 8B 07 85 C0 0F 84 ED 00 00 00 C7 45 DC 00 00 00 00 8D 45 F4 89 45 D0 EB 40 8D B4 26 00 00 00 00 8D BC 27 00 00 00 00 8B 4F 08 85 C9 74 19 8B 45 D4 8B 10 85 D2 74 10 8B 42 04 89 7C 82 08 40 89 42 04 90 8D 74 26 00 89 F8 03 07 8D 78 04 8B 40 04 85 C0 0F 84 9E 00 00 00 8B 47 04 85 C0 74 E7 8B 55 D8 F6 42 10 04 74 2E 8D 77 04 29 C6 39 75 DC 74 24 89 F0 E8 ED FC FF FF 89 45 E0 31 C0 8A 45 E0 8B 55 D8 E8 FD FA FF FF 89 45 E4 89 75 DC 8D B4 26 00 00 00 00 8B 75 E0 85 F6 74 89 8A }
	condition:
		$pattern
}

rule linear_search_fdes_3da648691a3b70f2a0a643b122b6979b {
	meta:
		aliases = "linear_search_fdes"
		type = "func"
		size = "322"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 30 89 45 D8 89 D7 89 4D D4 89 C2 8B 40 10 66 C1 E8 03 25 FF 00 00 00 89 45 E0 E8 DA FC FF FF 89 45 E4 8B 37 85 F6 0F 84 F3 00 00 00 C7 45 DC 00 00 00 00 8D 45 F4 89 45 D0 EB 40 8D B4 26 00 00 00 00 8D BC 27 00 00 00 00 8B 57 08 89 55 F4 8B 47 0C 89 45 F0 85 D2 74 10 8B 45 D4 2B 45 F4 3B 45 F0 0F 82 B9 00 00 00 90 89 F8 03 07 8D 78 04 8B 70 04 85 F6 0F 84 A4 00 00 00 8B 47 04 85 C0 74 E7 8B 55 D8 F6 42 10 04 74 2E 8D 77 04 29 C6 39 75 DC 74 24 89 F0 E8 3D FE FF FF 89 45 E0 31 C0 8A 45 E0 8B 55 D8 E8 4D FC FF FF 89 45 E4 89 75 DC 8D B4 26 00 00 00 00 8B 4D E0 85 C9 74 89 8A }
	condition:
		$pattern
}

rule __umoddi3_44895f6b5748d01258d52742f3aaf7c8 {
	meta:
		aliases = "__umoddi3"
		type = "func"
		size = "367"
		objfiles = "_umoddi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 30 C7 45 D0 00 00 00 00 C7 45 D4 00 00 00 00 8B 75 08 8B 7D 0C 8B 45 10 8B 55 14 89 45 EC 89 C1 89 55 E8 89 75 E4 89 75 F0 89 7D E0 89 FA 8B 45 E8 85 C0 75 14 39 F9 76 70 89 F0 F7 F1 89 55 D0 C7 45 D4 00 00 00 00 EB 10 8B 4D E0 39 4D E8 76 18 89 75 D0 89 7D D4 89 F6 8B 45 D0 8B 55 D4 83 C4 30 5E 5F 5D C3 8D 76 00 0F BD 45 E8 83 F0 1F 89 45 D8 75 64 8B 45 E0 39 45 E8 72 08 8B 4D E4 39 4D EC 77 0F 8B 55 E0 8B 45 E4 2B 45 EC 1B 55 E8 89 45 F0 8B 4D F0 89 4D D0 89 55 D4 EB BA 8D 76 00 8D BC 27 00 00 00 00 8B 45 EC 85 C0 75 0C B8 01 00 00 00 31 D2 F7 75 EC 89 C1 8B 45 E0 8B 55 }
	condition:
		$pattern
}

rule __divdi3_29ff45a6325c49662755140b12a86964 {
	meta:
		aliases = "__divdi3"
		type = "func"
		size = "432"
		objfiles = "_divdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 30 C7 45 D0 00 00 00 00 C7 45 D4 00 00 00 00 8B 75 10 8B 7D 14 8B 45 08 8B 55 0C 89 45 D8 89 55 DC 89 F0 89 FA 8B 4D DC 85 C9 0F 88 C9 00 00 00 C7 45 E4 00 00 00 00 85 FF 0F 88 DA 00 00 00 89 C6 89 C1 89 D7 8B 55 D8 89 55 F0 8B 45 DC 89 45 EC 85 FF 75 14 39 C6 76 50 89 D0 8B 55 EC F7 F6 89 C1 31 C0 EB 13 8D 76 00 3B 7D EC 76 6B 31 C9 31 C0 8D B4 26 00 00 00 00 89 4D D0 89 45 D4 8B 45 D0 8B 55 D4 8B 4D E4 85 C9 74 07 F7 D8 83 D2 00 F7 DA 83 C4 30 5E 5F 5D C3 EB 0D 90 90 90 90 90 90 90 90 90 90 90 90 90 85 F6 75 0B B8 01 00 00 00 31 D2 F7 F6 89 C1 8B 45 EC 89 FA F7 F1 89 C6 }
	condition:
		$pattern
}

rule __udivmoddi4_c1ef75e5a39d229b28ddeac878900cfd {
	meta:
		aliases = "__udivmoddi4"
		type = "func"
		size = "550"
		objfiles = "_udivmoddi4@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 40 C7 45 C8 00 00 00 00 C7 45 CC 00 00 00 00 C7 45 C0 00 00 00 00 C7 45 C4 00 00 00 00 8B 75 08 8B 7D 0C 8B 45 10 8B 55 14 89 45 D0 89 45 E0 89 55 BC 89 75 D4 89 75 EC 89 7D D8 89 7D E4 85 D2 75 37 39 F8 0F 86 EF 00 00 00 89 F0 89 FA F7 75 D0 31 C9 8B 75 18 85 F6 74 18 89 55 C8 C7 45 CC 00 00 00 00 8B 75 C8 8B 7D CC 8B 55 18 89 32 89 7A 04 89 C2 89 C8 EB 31 90 8B 4D D8 39 4D BC 76 48 8B 45 18 85 C0 74 14 89 75 C8 89 7D CC 8B 75 C8 8B 7D CC 8B 45 18 89 30 89 78 04 31 D2 31 C0 89 F6 8D BC 27 00 00 00 00 89 55 C0 89 45 C4 8B 45 C0 8B 55 C4 83 C4 40 5E 5F 5D C3 8D B6 00 00 00 }
	condition:
		$pattern
}

rule __moddi3_634eabc8599492431481fb6b4b6e256c {
	meta:
		aliases = "__moddi3"
		type = "func"
		size = "530"
		objfiles = "_moddi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 50 C7 45 B0 00 00 00 00 C7 45 B4 00 00 00 00 8B 45 10 8B 55 14 89 45 A8 89 55 AC 8B 55 08 8B 4D 0C 8B 75 A8 8B 7D AC 85 C9 0F 88 2A 01 00 00 C7 45 BC 00 00 00 00 8B 45 AC 85 C0 0F 88 F8 00 00 00 8D 45 F0 89 45 C0 89 75 D8 89 75 CC 89 55 D4 89 55 DC 89 CE 89 4D C8 85 FF 75 2D 39 4D D8 0F 86 A4 00 00 00 89 D0 89 CA F7 75 D8 89 55 B0 C7 45 B4 00 00 00 00 8B 55 B0 8B 4D B4 8B 45 C0 89 10 89 48 04 EB 23 8D 76 00 39 CF 76 3C 89 55 B0 89 4D B4 8B 55 B0 8B 4D B4 89 55 F0 89 4D F4 8D 76 00 8D BC 27 00 00 00 00 8B 45 BC 85 C0 74 0A F7 5D F0 83 55 F4 00 F7 5D F4 8B 45 F0 8B 55 F4 83 }
	condition:
		$pattern
}

rule __ucmpdi2_633817d9196e1b47712cb1c922c6def8 {
	meta:
		aliases = "__ucmpdi2"
		type = "func"
		size = "61"
		objfiles = "_ucmpdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 8B 75 08 8B 7D 0C 8B 45 10 8B 55 14 39 D7 72 1B 77 06 39 C6 72 15 76 19 B8 02 00 00 00 5E 5F 5D C3 8D 76 00 8D BC 27 00 00 00 00 31 C0 5E 5F 5D C3 B8 01 00 00 00 EB E5 }
	condition:
		$pattern
}

rule __cmpdi2_187a465eb7c688c4a7ef119f7f7202f6 {
	meta:
		aliases = "__cmpdi2"
		type = "func"
		size = "61"
		objfiles = "_cmpdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 8B 75 08 8B 7D 0C 8B 45 10 8B 55 14 39 D7 7C 1B 7F 06 39 C6 72 15 76 19 B8 02 00 00 00 5E 5F 5D C3 8D 76 00 8D BC 27 00 00 00 00 31 C0 5E 5F 5D C3 B8 01 00 00 00 EB E5 }
	condition:
		$pattern
}

rule __gnat_default_unlock_939a034664c2b3234964a30decbd1f50 {
	meta:
		aliases = "__clear_cache, __enable_execute_stack, __gcov_flush, __gcov_init, __gcov_merge_add, __gcov_merge_delta, __gcov_merge_single, __gnat_default_lock, __gnat_default_unlock"
		type = "func"
		size = "5"
		objfiles = "_clear_cache@libgcc.a, _gcov_merge_delta@libgcov.a, _gcov_merge_single@libgcov.a, _enable_execute_stack@libgcc.a, gthr_gnat@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 5D C3 }
	condition:
		$pattern
}

rule __do_global_dtors_aux_7a7fa84751646e937248b5807aee71e0 {
	meta:
		aliases = "__do_global_dtors_aux"
		type = "func"
		size = "177"
		objfiles = "crtbegin, crtbeginT"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 80 3D ?? ?? ?? ?? 00 74 1B EB 44 EB 0D 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C0 04 A3 ?? ?? ?? ?? FF D2 A1 ?? ?? ?? ?? 8B 10 85 D2 75 EB B8 ?? ?? ?? ?? 85 C0 74 10 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 C6 05 ?? ?? ?? ?? 01 C9 C3 89 F6 8D BC 27 00 00 00 00 55 89 E5 83 EC 08 E8 00 00 00 00 5A 81 C2 ?? ?? ?? ?? B8 ?? ?? ?? ?? 85 C0 74 15 52 6A 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 A1 ?? ?? ?? ?? 85 C0 74 16 B8 ?? ?? ?? ?? 85 C0 74 0D 83 EC 0C 68 ?? ?? ?? ?? FF D0 83 C4 10 C9 C3 }
	condition:
		$pattern
}

rule _Unwind_DeleteException_5deb80c9e8d016e79db693fed2d1dd97 {
	meta:
		aliases = "_Unwind_DeleteException"
		type = "func"
		size = "29"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 8B 55 08 8B 42 08 85 C0 74 0B 83 EC 08 52 6A 01 FF D0 83 C4 10 C9 C3 }
	condition:
		$pattern
}

rule __fixunssfsi_861889b8bca661734b42669772a5a81a {
	meta:
		aliases = "__fixunssfsi"
		type = "func"
		size = "109"
		objfiles = "_fixunssfsi@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? D9 45 08 D9 81 ?? ?? ?? ?? D9 C9 DD E1 DF E0 F6 C4 01 75 2A DE E1 D9 7D FE 66 8B 45 FE B4 0C 66 89 45 FC D9 6D FC DB 5D F8 D9 6D FE 8B 45 F8 2D 00 00 00 80 C9 C3 90 8D B4 26 00 00 00 00 DD D9 D9 7D FE 66 8B 45 FE B4 0C 66 89 45 FC D9 6D FC DB 5D F8 D9 6D FE 8B 45 F8 C9 C3 }
	condition:
		$pattern
}

rule __fixunsxfsi_c36333dc57d7126b5808a1d4954ecac6 {
	meta:
		aliases = "__fixunsxfsi"
		type = "func"
		size = "109"
		objfiles = "_fixunsxfsi@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? DB 6D 08 D9 81 ?? ?? ?? ?? D9 C9 DD E1 DF E0 F6 C4 01 75 2A DE E1 D9 7D FE 66 8B 45 FE B4 0C 66 89 45 FC D9 6D FC DB 5D F8 D9 6D FE 8B 45 F8 2D 00 00 00 80 C9 C3 90 8D B4 26 00 00 00 00 DD D9 D9 7D FE 66 8B 45 FE B4 0C 66 89 45 FC D9 6D FC DB 5D F8 D9 6D FE 8B 45 F8 C9 C3 }
	condition:
		$pattern
}

rule __fixunsdfsi_94e24bbb978f1c6da487a50fde8a5e2d {
	meta:
		aliases = "__fixunsdfsi"
		type = "func"
		size = "109"
		objfiles = "_fixunsdfsi@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? DD 45 08 D9 81 ?? ?? ?? ?? D9 C9 DD E1 DF E0 F6 C4 01 75 2A DE E1 D9 7D FE 66 8B 45 FE B4 0C 66 89 45 FC D9 6D FC DB 5D F8 D9 6D FE 8B 45 F8 2D 00 00 00 80 C9 C3 90 8D B4 26 00 00 00 00 DD D9 D9 7D FE 66 8B 45 FE B4 0C 66 89 45 FC D9 6D FC DB 5D F8 D9 6D FE 8B 45 F8 C9 C3 }
	condition:
		$pattern
}

rule frame_dummy_6aee645838cda37bf5dafaf79e22f360 {
	meta:
		aliases = "frame_dummy"
		type = "func"
		size = "81"
		objfiles = "crtbegin, crtbeginT"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 E8 00 00 00 00 5A 81 C2 ?? ?? ?? ?? B8 ?? ?? ?? ?? 85 C0 74 15 52 6A 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 A1 ?? ?? ?? ?? 85 C0 74 16 B8 ?? ?? ?? ?? 85 C0 74 0D 83 EC 0C 68 ?? ?? ?? ?? FF D0 83 C4 10 C9 C3 }
	condition:
		$pattern
}

rule __pthread_find_self_70df40a9518defd62a9e6091637b26f4 {
	meta:
		aliases = "__pthread_find_self"
		type = "func"
		size = "29"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 89 E9 BA ?? ?? ?? ?? EB 03 83 C2 10 8B 42 08 39 C1 77 F6 3B 4A 0C 72 F1 5D C3 }
	condition:
		$pattern
}

rule thread_self_dd5dae98b7dbe953d0d7e291f00b93db {
	meta:
		aliases = "thread_self"
		type = "func"
		size = "68"
		objfiles = "specific@libpthread.a, cancel@libpthread.a, spinlock@libpthread.a, rwlock@libpthread.a, signals@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 89 EA B8 ?? ?? ?? ?? 3B 2D ?? ?? ?? ?? 73 30 3B 2D ?? ?? ?? ?? 72 0D B8 ?? ?? ?? ?? 3B 2D ?? ?? ?? ?? 72 1B 83 3D ?? ?? ?? ?? 00 74 06 5D E9 ?? ?? ?? ?? 81 CA FF FF 1F 00 8D 82 A1 FE FF FF 5D C3 }
	condition:
		$pattern
}

rule __ffssi2_75fcfda88b2463b982a19044acb25b46 {
	meta:
		aliases = "__ffssi2"
		type = "func"
		size = "16"
		objfiles = "_ffssi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 85 C0 74 04 0F BC C0 40 5D C3 }
	condition:
		$pattern
}

rule __absvsi2_b4878ccf8bb679402a7559a0c3e6e436 {
	meta:
		aliases = "__absvsi2"
		type = "func"
		size = "20"
		objfiles = "_absvsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 85 C0 78 06 5D C3 8D 74 26 00 F7 D8 5D C3 }
	condition:
		$pattern
}

rule _Unwind_GetCFA_f9ab0b8ebd026c2d38d834d7b5a50b85 {
	meta:
		aliases = "_Unwind_GetCFA"
		type = "func"
		size = "11"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 40 48 5D C3 }
	condition:
		$pattern
}

rule _Unwind_GetIP_73420b4264bef5944f1b6c2f52b5f2de {
	meta:
		aliases = "_Unwind_GetIP"
		type = "func"
		size = "11"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 40 4C 5D C3 }
	condition:
		$pattern
}

rule _Unwind_GetLanguageSpecificDat_dea818baee87db5fa4587c6a89861854 {
	meta:
		aliases = "_Unwind_GetLanguageSpecificData"
		type = "func"
		size = "11"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 40 50 5D C3 }
	condition:
		$pattern
}

rule _Unwind_GetTextRelBase_eb32dd4e9818a134f7deaba3075bc496 {
	meta:
		aliases = "_Unwind_GetTextRelBase"
		type = "func"
		size = "11"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 40 54 5D C3 }
	condition:
		$pattern
}

rule _Unwind_GetDataRelBase_c81c43b8b3d5d92ed4a133ac70eb305f {
	meta:
		aliases = "_Unwind_GetDataRelBase"
		type = "func"
		size = "11"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 40 58 5D C3 }
	condition:
		$pattern
}

rule _Unwind_GetRegionStart_e45cee8d3c23e8fe1560e6ca3b0b04d6 {
	meta:
		aliases = "_Unwind_GetRegionStart"
		type = "func"
		size = "11"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 40 5C 5D C3 }
	condition:
		$pattern
}

rule __paritydi2_6bf41cdaa8036e11216ed1947f710266 {
	meta:
		aliases = "__paritydi2"
		type = "func"
		size = "47"
		objfiles = "_paritydi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 55 0C 31 C2 89 D0 C1 E8 10 31 D0 89 C2 C1 EA 08 31 C2 89 D1 C1 E9 04 31 D1 83 E1 0F B8 96 69 00 00 D3 F8 83 E0 01 5D C3 }
	condition:
		$pattern
}

rule __ctzdi2_81c922a3ec996136ef12722438ec9c76 {
	meta:
		aliases = "__ctzdi2"
		type = "func"
		size = "41"
		objfiles = "_ctzdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 55 0C 85 C0 74 13 31 D2 0F BC C0 01 D0 5D C3 8D 76 00 8D BC 27 00 00 00 00 89 D0 BA 20 00 00 00 EB E6 }
	condition:
		$pattern
}

rule __ffsdi2_31aa9925af2fb50ddfc274dd5b5d243c {
	meta:
		aliases = "__ffsdi2"
		type = "func"
		size = "52"
		objfiles = "_ffsdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 55 0C 85 C0 74 13 31 D2 0F BC C0 8D 44 02 01 5D C3 90 8D B4 26 00 00 00 00 85 D2 74 0C 89 D0 BA 20 00 00 00 EB E2 8D 76 00 31 C0 5D C3 }
	condition:
		$pattern
}

rule __clzdi2_b7fa7ed85b9a2ce3eae68c66b0dcebc2 {
	meta:
		aliases = "__clzdi2"
		type = "func"
		size = "39"
		objfiles = "_clzdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 55 0C 85 D2 74 13 89 D0 31 D2 0F BD C0 83 F0 1F 01 D0 5D C3 90 8D 74 26 00 BA 20 00 00 00 EB EA }
	condition:
		$pattern
}

rule __absvdi2_42091a6b17486d38dfb59ac2ddefaae1 {
	meta:
		aliases = "__absvdi2"
		type = "func"
		size = "25"
		objfiles = "_absvdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 55 0C 85 D2 78 03 5D C3 90 F7 D8 83 D2 00 F7 DA 5D C3 }
	condition:
		$pattern
}

rule fde_unencoded_compare_181f33e525491d15f6affa4cc809cd75 {
	meta:
		aliases = "fde_unencoded_compare"
		type = "func"
		size = "39"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 10 8B 50 08 8B 45 0C 39 50 08 77 0F 19 C0 5D C3 8D 74 26 00 8D BC 27 00 00 00 00 B8 01 00 00 00 5D C3 }
	condition:
		$pattern
}

rule _Unwind_GetIPInfo_b98644c9d0edbd02c086e7a49b940b27 {
	meta:
		aliases = "_Unwind_GetIPInfo"
		type = "func"
		size = "22"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 4D 08 8B 41 60 C1 E8 1F 8B 55 0C 89 02 8B 41 4C 5D C3 }
	condition:
		$pattern
}

rule __paritysi2_8dce14b3f1c6de6e96832eecd10c45b2 {
	meta:
		aliases = "__paritysi2"
		type = "func"
		size = "42"
		objfiles = "_paritysi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 55 08 89 D0 C1 E8 10 31 D0 89 C2 C1 EA 08 31 C2 89 D1 C1 E9 04 31 D1 83 E1 0F B8 96 69 00 00 D3 F8 83 E0 01 5D C3 }
	condition:
		$pattern
}

rule _Unwind_SetIP_67fb3b63675db93d4c89fe8d872db7f1 {
	meta:
		aliases = "_Unwind_SetIP"
		type = "func"
		size = "14"
		objfiles = "unwind_dw2@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 55 0C 8B 45 08 89 50 4C 5D C3 }
	condition:
		$pattern
}

rule __gnat_install_locks_8b3b439c56705975420bae8114b1a69f {
	meta:
		aliases = "__gnat_install_locks"
		type = "func"
		size = "35"
		objfiles = "gthr_gnat@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? 8B 45 08 89 81 ?? ?? ?? ?? 8B 45 0C 89 81 ?? ?? ?? ?? 5D C3 }
	condition:
		$pattern
}

rule __floatundixf_7a575897b2cc0ade6d72ff041b51e8dc {
	meta:
		aliases = "__floatundidf, __floatundixf"
		type = "func"
		size = "51"
		objfiles = "_floatundixf@libgcc.a, _floatundidf@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? 8B 45 0C 31 D2 52 50 DF 2C 24 83 C4 08 D8 89 ?? ?? ?? ?? 8B 45 08 31 D2 52 50 DF 2C 24 83 C4 08 DE C1 5D C3 }
	condition:
		$pattern
}

rule __register_frame_info_table_ba_b9a7ee2c5ac01787265ef94c052d5770 {
	meta:
		aliases = "__register_frame_info_table_bases"
		type = "func"
		size = "76"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? 8B 45 0C C7 00 FF FF FF FF 8B 55 10 89 50 04 8B 55 14 89 50 08 8B 55 08 89 50 0C C7 40 10 00 00 00 00 80 48 10 02 66 81 48 10 F8 07 8B 91 ?? ?? ?? ?? 89 50 14 89 81 ?? ?? ?? ?? 5D C3 }
	condition:
		$pattern
}

rule __powisf2_589cd186365ee16d07aabb661867eb5b {
	meta:
		aliases = "__powisf2"
		type = "func"
		size = "108"
		objfiles = "_powisf2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? D9 45 08 8B 55 0C 89 D0 85 D2 78 4D A8 01 74 45 D9 C0 D1 E8 74 31 8D 74 26 00 8D BC 27 00 00 00 00 D9 C9 D8 C8 A8 01 74 18 DC C9 D1 E8 75 F4 DD D8 85 D2 78 18 5D C3 8D 76 00 8D BC 27 00 00 00 00 D9 C9 D1 E8 75 DA DD D9 85 D2 79 E8 D8 B9 ?? ?? ?? ?? 5D C3 D9 E8 EB B9 F7 D8 EB AF }
	condition:
		$pattern
}

rule __floatdixf_7e5b38da17692b5cd5a196f724e46232 {
	meta:
		aliases = "__floatdidf, __floatdixf"
		type = "func"
		size = "41"
		objfiles = "_floatdixf@libgcc.a, _floatdidf@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? D9 81 ?? ?? ?? ?? DA 4D 0C 8B 45 08 31 D2 52 50 DF 2C 24 83 C4 08 DE C1 5D C3 }
	condition:
		$pattern
}

rule __powixf2_9e50670ffcadf003ad55442dd2648738 {
	meta:
		aliases = "__powixf2"
		type = "func"
		size = "112"
		objfiles = "_powixf2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? DB 6D 08 8B 55 14 89 D0 85 D2 78 51 A8 01 74 45 D9 C0 D1 E8 74 31 8D 74 26 00 8D BC 27 00 00 00 00 D9 C9 D8 C8 A8 01 74 18 DC C9 D1 E8 75 F4 DD D8 85 D2 78 18 5D C3 8D 76 00 8D BC 27 00 00 00 00 D9 C9 D1 E8 75 DA DD D9 85 D2 79 E8 D8 B9 ?? ?? ?? ?? 5D C3 D9 81 ?? ?? ?? ?? EB B5 F7 D8 EB AB }
	condition:
		$pattern
}

rule __powidf2_8bac1335659c1396bbcdaa0081b7f0c7 {
	meta:
		aliases = "__powidf2"
		type = "func"
		size = "112"
		objfiles = "_powidf2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? DD 45 08 8B 55 10 89 D0 85 D2 78 51 A8 01 74 45 D9 C0 D1 E8 74 31 8D 74 26 00 8D BC 27 00 00 00 00 D9 C9 D8 C8 A8 01 74 18 DC C9 D1 E8 75 F4 DD D8 85 D2 78 18 5D C3 8D 76 00 8D BC 27 00 00 00 00 D9 C9 D1 E8 75 DA DD D9 85 D2 79 E8 D8 B9 ?? ?? ?? ?? 5D C3 D9 81 ?? ?? ?? ?? EB B5 F7 D8 EB AB }
	condition:
		$pattern
}

rule pthread_testcancel_44903354f39dbc10912fae0fe333afe7 {
	meta:
		aliases = "pthread_testcancel"
		type = "func"
		size = "30"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 E8 ?? ?? ?? ?? 80 78 42 00 74 0E 80 78 40 00 75 08 55 6A FF E8 ?? ?? ?? ?? C9 C3 }
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

rule _stdio_term_de1141eac9a3e89a33cdb8963f8c26b4 {
	meta:
		aliases = "_stdio_term"
		type = "func"
		size = "117"
		objfiles = "_stdio@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 59 5E EB 33 8D 73 38 56 E8 ?? ?? ?? ?? 5A 85 C0 74 14 66 C7 03 30 00 8B 43 08 89 43 18 89 43 1C 89 43 10 89 43 14 C7 43 34 01 00 00 00 56 E8 ?? ?? ?? ?? 8B 5B 20 58 85 DB 75 C9 8B 1D ?? ?? ?? ?? EB 0F F6 03 40 74 07 53 E8 ?? ?? ?? ?? 5E 8B 5B 20 85 DB 75 ED 5B 5E C3 }
	condition:
		$pattern
}

rule dlinfo_d9c78ff2c2caf651fdf01827d4fff805 {
	meta:
		aliases = "dlinfo"
		type = "func"
		size = "220"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 56 ) 53 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 5E 58 EB 2F FF 73 04 0F B7 43 20 50 8B 43 18 8D 04 85 ?? ?? ?? ?? 50 FF 73 1C 53 FF 33 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 5B 0C 83 C4 20 85 DB 75 CD FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 83 C4 0C EB 1C 8B 03 FF 70 04 50 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 5B 10 83 C4 10 85 DB 75 E0 8B 35 ?? ?? ?? ?? EB 3B 56 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 F3 83 C4 0C EB 1C 8B 03 FF 70 04 50 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 5B }
	condition:
		$pattern
}

rule __ns_name_uncompress_5e2bdcbf38ed01e81be5ca266898d9be {
	meta:
		aliases = "__GI___ns_name_uncompress, __ns_name_uncompress"
		type = "func"
		size = "94"
		objfiles = "ns_name@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 00 01 00 00 68 FF 00 00 00 8D 74 24 05 56 FF B4 24 1C 01 00 00 FF B4 24 1C 01 00 00 FF B4 24 1C 01 00 00 E8 ?? ?? ?? ?? 89 C3 83 C4 14 83 F8 FF 74 1A FF B4 24 1C 01 00 00 FF B4 24 1C 01 00 00 56 E8 ?? ?? ?? ?? 83 C4 0C 40 75 03 83 CB FF 89 D8 81 C4 00 01 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule tmpfile64_60c7f9183410a40e0ea70d26e676619c {
	meta:
		aliases = "tmpfile, tmpfile64"
		type = "func"
		size = "131"
		objfiles = "tmpfile@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 00 10 00 00 68 ?? ?? ?? ?? 6A 00 68 FF 0F 00 00 8D 74 24 0D 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 51 68 80 01 00 00 6A 00 56 E8 ?? ?? ?? ?? 89 C3 83 C4 0C 85 C0 78 3B 56 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 89 C6 83 C4 0C 85 C0 75 23 89 D9 87 CB B8 06 00 00 00 CD 80 87 CB 89 C3 3D 00 F0 FF FF 76 0D E8 ?? ?? ?? ?? F7 DB 89 18 EB 02 31 F6 89 F0 81 C4 00 10 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule vdprintf_9ac66d3e42641fbf3e35db76ae99e05b {
	meta:
		aliases = "__GI_vdprintf, vdprintf"
		type = "func"
		size = "155"
		objfiles = "vdprintf@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 90 00 00 00 8D 44 24 50 8D 94 24 90 00 00 00 89 54 24 0C 89 44 24 08 89 44 24 18 89 44 24 1C 89 44 24 10 89 44 24 14 8B 84 24 9C 00 00 00 89 44 24 04 66 C7 04 24 D0 00 C6 44 24 02 00 C7 44 24 2C 00 00 00 00 C7 44 24 34 01 00 00 00 89 E6 8D 44 24 38 50 E8 ?? ?? ?? ?? C7 44 24 24 00 00 00 00 FF B4 24 A8 00 00 00 FF B4 24 A8 00 00 00 56 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 7E 0E 56 E8 ?? ?? ?? ?? 5A 85 C0 74 03 83 CB FF 89 D8 81 C4 90 00 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule login_3a88dee028bd9f1e2ec9c5fb8de8e61c {
	meta:
		aliases = "login"
		type = "func"
		size = "213"
		objfiles = "login@libutil.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC A8 01 00 00 89 E0 68 80 01 00 00 FF B4 24 B8 01 00 00 50 E8 ?? ?? ?? ?? 66 C7 44 24 0C 07 00 E8 ?? ?? ?? ?? 89 44 24 10 31 DB 83 C4 0C 8D B4 24 82 01 00 00 EB 01 43 83 FB 03 74 12 6A 26 56 53 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 EA EB 66 6A 20 68 ?? ?? ?? ?? 8D 44 24 10 50 E8 ?? ?? ?? ?? 83 C4 0C EB 3A 6A 1F 8D 84 24 8B 01 00 00 EB 09 6A 1F 8D 84 24 86 01 00 00 50 8D 44 24 10 50 E8 ?? ?? ?? ?? 83 C4 0C C6 44 24 27 00 E8 ?? ?? ?? ?? 89 E0 50 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 89 E0 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 C4 B0 01 00 00 5B 5E C3 6A 05 68 ?? ?? ?? ?? 8D 84 24 8A 01 00 00 50 E8 }
	condition:
		$pattern
}

rule adjtime_854f5a683269afea4fba8a44a0c2aa83 {
	meta:
		aliases = "adjtime"
		type = "func"
		size = "182"
		objfiles = "adjtime@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 C4 80 8B 8C 24 8C 00 00 00 8B B4 24 90 00 00 00 85 C9 74 43 8B 41 04 BB 40 42 0F 00 99 F7 FB 89 D3 89 C2 03 11 8D 82 61 08 00 00 3D C2 10 00 00 76 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CA FF EB 69 69 C2 40 42 0F 00 01 D8 89 44 24 04 C7 04 24 01 80 00 00 EB 07 C7 04 24 00 00 00 00 89 E0 50 E8 ?? ?? ?? ?? 5A 83 CA FF 85 C0 78 3D 31 D2 85 F6 74 37 8B 4C 24 04 85 C9 79 1A 89 C8 F7 D8 BB 40 42 0F 00 99 F7 FB F7 DA 89 56 04 89 C8 99 F7 FB 89 C1 EB 11 BA 40 42 0F 00 89 C8 89 D3 99 F7 FB 89 C1 89 56 04 89 0E 31 D2 89 D0 83 EC 80 5B 5E C3 }
	condition:
		$pattern
}

rule lseek64_65b4d3bec69ed50873493d98cdc6f84d {
	meta:
		aliases = "lseek64"
		type = "func"
		size = "61"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 89 E0 50 6A 01 E8 ?? ?? ?? ?? FF 74 24 24 FF 74 24 24 FF 74 24 24 FF 74 24 24 E8 ?? ?? ?? ?? 89 C3 89 D6 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? 89 D8 89 F2 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule __fresetlockfiles_254e34a76fe4ecad96042015f1666f94 {
	meta:
		aliases = "__fresetlockfiles"
		type = "func"
		size = "64"
		objfiles = "lockfile@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 89 E3 53 E8 ?? ?? ?? ?? 6A 01 53 E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 83 C4 0C EB 0F 50 8D 46 38 50 E8 ?? ?? ?? ?? 8B 76 20 59 58 85 F6 89 D8 75 EB 53 E8 ?? ?? ?? ?? 58 5A 5B 5E C3 }
	condition:
		$pattern
}

rule wcsxfrm_e97ef870b7c7966b8f02f4ca69f4f7a0 {
	meta:
		aliases = "__wcslcpy, wcsxfrm"
		type = "func"
		size = "62"
		objfiles = "wcslcpy@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 4C 24 10 8B 74 24 14 8B 44 24 18 8D 58 FF 85 C0 75 04 31 DB 89 E1 89 F2 EB 0B 85 DB 74 04 4B 83 C1 04 83 C2 04 8B 02 89 01 85 C0 75 ED 29 F2 C1 FA 02 89 D0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule strxfrm_74a18f0f542c50646d96143445c1d718 {
	meta:
		aliases = "__GI_strlcpy, strlcpy, strxfrm"
		type = "func"
		size = "57"
		objfiles = "strlcpy@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 4C 24 10 8B 74 24 14 8B 44 24 18 8D 58 FF 85 C0 75 06 8D 4C 24 03 31 DB 89 F2 EB 07 85 DB 74 02 4B 41 42 8A 02 88 01 84 C0 75 F1 29 F2 89 D0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule strlcat_817ea6dbea9fde13c64419bd4f24d5a6 {
	meta:
		aliases = "__GI_strlcat, strlcat"
		type = "func"
		size = "59"
		objfiles = "strlcat@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 54 24 10 8B 5C 24 14 8B 74 24 18 31 C9 39 F1 72 06 8D 54 24 03 EB 10 80 3A 00 74 0B 42 41 EB ED 41 39 F1 83 D2 00 43 8A 03 88 02 84 C0 75 F1 89 C8 5A 5B 5E C3 }
	condition:
		$pattern
}

rule mq_open_a386e2b9969ffde1cd5e655c7f2fe1ab {
	meta:
		aliases = "mq_open"
		type = "func"
		size = "97"
		objfiles = "mq_open@librt.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 10 8B 4C 24 14 80 3B 2F 74 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 3B F6 C1 40 75 06 31 D2 31 F6 EB 0F 8B 54 24 18 8D 44 24 20 89 04 24 8B 74 24 1C 43 89 D8 53 89 C3 B8 15 01 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 5B 5E C3 }
	condition:
		$pattern
}

rule xdrrec_getint32_990e0bd94c9b7e26551ec3f1e1213fc5 {
	meta:
		aliases = "xdrrec_getint32"
		type = "func"
		size = "91"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 10 8B 74 24 14 8B 53 0C 8B 4A 2C 83 7A 34 03 7E 1F 8B 42 30 29 C8 83 F8 03 7E 15 8B 01 0F C8 89 06 83 6A 34 04 83 42 2C 04 BA 01 00 00 00 EB 1D 89 E0 6A 04 50 53 E8 ?? ?? ?? ?? 83 C4 0C 31 D2 85 C0 74 09 8B 04 24 0F C8 89 06 B2 01 89 D0 59 5B 5E C3 }
	condition:
		$pattern
}

rule join_extricate_func_1661bf8051b54041216588b1e589ee68 {
	meta:
		aliases = "join_extricate_func"
		type = "func"
		size = "60"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 10 E8 ?? ?? ?? ?? 89 04 24 8B 14 24 89 D8 E8 ?? ?? ?? ?? 8B 43 08 83 78 38 00 0F 95 C2 0F B6 F2 C7 40 38 00 00 00 00 53 E8 ?? ?? ?? ?? 89 F0 5A 59 5B 5E C3 }
	condition:
		$pattern
}

rule cond_extricate_func_4d6b879145d7aeef7a3e09f05366c567 {
	meta:
		aliases = "cond_extricate_func"
		type = "func"
		size = "54"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 10 E8 ?? ?? ?? ?? 89 04 24 8B 14 24 89 D8 E8 ?? ?? ?? ?? 8D 43 08 8B 54 24 14 E8 ?? ?? ?? ?? 89 C6 53 E8 ?? ?? ?? ?? 89 F0 5B 5E 5B 5E C3 }
	condition:
		$pattern
}

rule new_sem_extricate_func_7d70c728640edd48e01796d6d1052385 {
	meta:
		aliases = "new_sem_extricate_func"
		type = "func"
		size = "54"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 10 E8 ?? ?? ?? ?? 89 04 24 8B 14 24 89 D8 E8 ?? ?? ?? ?? 8D 43 0C 8B 54 24 14 E8 ?? ?? ?? ?? 89 C6 53 E8 ?? ?? ?? ?? 89 F0 59 5B 5B 5E C3 }
	condition:
		$pattern
}

rule memrchr_5342f1f56d7cc99524a57c3d479d15d7 {
	meta:
		aliases = "__GI_memrchr, memrchr"
		type = "func"
		size = "177"
		objfiles = "memrchr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 18 8A 44 24 14 88 44 24 03 8B 44 24 10 01 D8 EB 0E 48 8A 54 24 03 38 10 0F 84 87 00 00 00 4B 85 DB 74 04 A8 03 75 EA 89 C1 0F B6 54 24 03 89 D0 C1 E0 08 09 D0 89 C6 C1 E6 10 09 C6 EB 4D 83 E9 04 89 F0 33 01 89 C2 F7 D2 05 FF FE FE 7E 31 C2 81 E2 00 01 01 81 74 30 8D 41 03 8A 54 24 03 38 51 03 74 41 8D 41 02 8A 54 24 03 38 51 02 74 35 8D 41 01 8A 54 24 03 38 51 01 74 29 8A 44 24 03 38 01 75 04 89 C8 EB 1D 83 EB 04 83 FB 03 77 AE 89 C8 EB 09 48 8A 54 24 03 38 10 74 08 4B 83 FB FF 75 F1 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_pointer_4bca07c05a55418c7d1ac3b835cb0126 {
	meta:
		aliases = "xdr_pointer"
		type = "func"
		size = "83"
		objfiles = "xdr_reference@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 8B 5C 24 14 31 C0 83 3B 00 0F 95 C0 89 04 24 89 E0 50 56 E8 ?? ?? ?? ?? 59 5A 31 D2 85 C0 74 24 83 3C 24 00 75 0A C7 03 00 00 00 00 B2 01 EB 14 FF 74 24 1C FF 74 24 1C 53 56 E8 ?? ?? ?? ?? 89 C2 83 C4 10 89 D0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_rmtcallres_972909abe554c43e0d9a12ab3d2fd29b {
	meta:
		aliases = "__GI_xdr_rmtcallres, xdr_rmtcallres"
		type = "func"
		size = "81"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 8B 5C 24 14 8B 03 89 04 24 68 ?? ?? ?? ?? 6A 04 8D 44 24 08 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 20 8D 43 04 50 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 10 8B 04 24 89 03 FF 73 08 56 FF 53 0C 59 5B EB 02 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule putc_unlocked_b15a6f9755d891f780cb639030287476 {
	meta:
		aliases = "__GI___fputc_unlocked, __GI_fputc_unlocked, __GI_putc_unlocked, __fputc_unlocked, fputc_unlocked, putc_unlocked"
		type = "func"
		size = "181"
		objfiles = "fputc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 8B 5C 24 14 8B 43 10 3B 43 1C 73 0D 89 F2 88 10 40 89 43 10 E9 87 00 00 00 0F B7 03 25 C0 00 00 00 3D C0 00 00 00 74 11 68 80 00 00 00 53 E8 ?? ?? ?? ?? 59 5A 85 C0 75 6C 83 7B 04 FE 75 07 89 F1 0F B6 C1 EB 62 8B 43 0C 3B 43 08 74 36 3B 43 10 75 0B 53 E8 ?? ?? ?? ?? 5A 85 C0 75 47 8B 43 10 89 F2 88 10 40 89 43 10 F6 43 01 01 74 2F 80 FA 0A 75 2A 53 E8 ?? ?? ?? ?? 59 85 C0 74 1F FF 4B 10 EB 21 89 F0 88 44 24 03 6A 01 8D 44 24 07 50 53 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 07 89 F2 0F B6 C2 EB 03 83 C8 FF 5A 5B 5E C3 }
	condition:
		$pattern
}

rule error_6562e3650828767a138608a443490d5b {
	meta:
		aliases = "__error, error"
		type = "func"
		size = "188"
		objfiles = "error@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 8B 5C 24 14 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 5A 85 C0 74 04 FF D0 EB 19 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 8D 44 24 1C 89 04 24 50 FF 74 24 1C FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 05 ?? ?? ?? ?? 83 C4 0C 85 DB 74 1A 53 E8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 8B 15 ?? ?? ?? ?? 83 7A 34 00 74 1B 8B 42 10 3B 42 1C 73 09 C6 00 0A 40 89 42 10 EB 14 52 6A 0A E8 ?? ?? ?? ?? EB 08 52 6A 0A E8 ?? ?? ?? ?? 5B 58 85 F6 74 06 56 E8 ?? ?? ?? ?? 59 5B 5E C3 }
	condition:
		$pattern
}

rule initgroups_7db7917d0f7d96907ee5e97292d38fc6 {
	meta:
		aliases = "initgroups"
		type = "func"
		size = "67"
		objfiles = "initgroups@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 C7 04 24 FF FF FF 7F 89 E0 50 FF 74 24 18 FF 74 24 18 E8 ?? ?? ?? ?? 89 C3 83 C4 0C 83 CE FF 85 C0 74 15 50 FF 74 24 04 E8 ?? ?? ?? ?? 89 C6 53 E8 ?? ?? ?? ?? 83 C4 0C 89 F0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule unlockpt_5ea43c5fc4dc4e1f4c7f4a115bcba7a2 {
	meta:
		aliases = "unlockpt"
		type = "func"
		size = "65"
		objfiles = "unlockpt@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 E8 ?? ?? ?? ?? 89 C3 8B 30 C7 04 24 00 00 00 00 89 E0 50 68 31 54 04 40 FF 74 24 18 E8 ?? ?? ?? ?? 83 C4 0C 31 D2 85 C0 74 0C 83 CA FF 83 3B 16 75 04 89 33 31 D2 89 D0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_uint64_t_d540c95401be2eb9937fd4cbc6892ffa {
	meta:
		aliases = "xdr_uint64_t"
		type = "func"
		size = "163"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 5C 24 14 8B 74 24 18 8B 03 83 F8 01 74 43 72 0C BA 01 00 00 00 83 F8 02 74 7C EB 78 8B 46 04 89 44 24 04 8B 06 89 04 24 8D 44 24 04 8B 53 04 50 53 FF 52 24 5A 59 31 D2 85 C0 74 5A 89 E0 8B 53 04 50 53 FF 52 24 5B 5E 31 D2 85 C0 0F 95 C2 EB 45 8D 44 24 04 8B 53 04 50 53 FF 52 20 5A 59 85 C0 74 31 89 E0 8B 53 04 50 53 FF 52 20 5A 59 85 C0 74 21 8B 44 24 04 31 D2 89 C2 B8 00 00 00 00 89 06 89 56 04 8B 0C 24 89 0E 89 56 04 BA 01 00 00 00 EB 02 31 D2 89 D0 59 5B 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_int64_t_851faaa836b5202b8e54eada2be816d3 {
	meta:
		aliases = "xdr_int64_t"
		type = "func"
		size = "178"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 5C 24 14 8B 74 24 18 8B 03 83 F8 01 74 53 72 13 BA 01 00 00 00 83 F8 02 0F 84 87 00 00 00 E9 80 00 00 00 8B 06 8B 56 04 89 D0 89 C2 C1 FA 1F 89 44 24 04 8B 06 89 04 24 8B 53 04 8D 44 24 04 50 53 FF 52 24 5E 5A 31 D2 85 C0 74 59 89 E0 8B 53 04 50 53 FF 52 24 59 5B 31 D2 85 C0 0F 95 C2 EB 44 8B 43 04 8D 54 24 04 52 53 FF 50 20 59 5A 85 C0 74 30 89 E0 8B 53 04 50 53 FF 52 20 5B 5A 85 C0 74 20 8B 44 24 04 99 89 C2 B8 00 00 00 00 89 06 89 56 04 8B 0C 24 89 0E 89 56 04 BA 01 00 00 00 EB 02 31 D2 89 D0 5A 59 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_u_hyper_55a0c2d179cb9873044057b28c6ab0de {
	meta:
		aliases = "__GI_xdr_u_hyper, xdr_u_hyper"
		type = "func"
		size = "160"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 5C 24 14 8B 74 24 18 8B 03 85 C0 75 33 8B 46 04 89 44 24 04 8B 06 89 04 24 8D 44 24 04 8B 53 04 50 53 FF 52 04 5A 59 31 D2 85 C0 74 66 89 E0 8B 53 04 50 53 FF 52 04 5B 5E 85 C0 0F 95 C0 EB 4C 83 F8 01 75 41 8D 44 24 04 8B 53 04 50 53 FF 12 5A 59 85 C0 74 3B 89 E0 8B 53 04 50 53 FF 12 5A 59 85 C0 74 2C 8B 44 24 04 31 D2 89 C2 B8 00 00 00 00 89 06 89 56 04 8B 0C 24 89 0E 89 56 04 BA 01 00 00 00 EB 0D 83 F8 02 0F 94 C0 0F B6 D0 EB 02 31 D2 89 D0 5B 5E 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_hyper_422d1bce1f1eef0e369761750bc2dd7c {
	meta:
		aliases = "__GI_xdr_hyper, xdr_hyper"
		type = "func"
		size = "168"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 5C 24 14 8B 74 24 18 8B 03 85 C0 75 3C 8B 06 8B 56 04 89 D0 89 C2 C1 FA 1F 89 44 24 04 8B 06 89 04 24 8B 53 04 8D 44 24 04 50 53 FF 52 04 5A 59 31 D2 85 C0 74 65 89 E0 8B 53 04 50 53 FF 52 04 5B 5E 85 C0 0F 95 C0 EB 4B 83 F8 01 75 40 8B 43 04 8D 54 24 04 52 53 FF 10 5A 59 85 C0 74 3A 89 E0 8B 53 04 50 53 FF 12 5A 59 85 C0 74 2B 8B 44 24 04 99 89 C2 B8 00 00 00 00 89 06 89 56 04 8B 0C 24 89 0E 89 56 04 BA 01 00 00 00 EB 0D 83 F8 02 0F 94 C0 0F B6 D0 EB 02 31 D2 89 D0 5B 5E 5B 5E C3 }
	condition:
		$pattern
}

rule __sigpause_e67da14d73a48c09cb4e447845acde4d {
	meta:
		aliases = "__GI___sigpause, __sigpause"
		type = "func"
		size = "76"
		objfiles = "sigpause@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 74 24 14 83 7C 24 18 00 74 1F 89 E3 53 6A 00 6A 00 E8 ?? ?? ?? ?? 56 53 E8 ?? ?? ?? ?? 83 C4 14 83 CA FF 85 C0 78 18 EB 0B C7 44 24 04 00 00 00 00 89 34 24 89 E0 50 E8 ?? ?? ?? ?? 89 C2 5B 89 D0 5A 59 5B 5E C3 }
	condition:
		$pattern
}

rule __pthread_wait_for_restart_sig_8398d59951cd1dd8b344e8b0769f9042 {
	meta:
		aliases = "__pthread_wait_for_restart_signal"
		type = "func"
		size = "66"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 74 24 14 89 E3 53 6A 00 6A 02 E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? C7 46 20 00 00 00 00 83 C4 14 53 E8 ?? ?? ?? ?? 58 8B 46 20 3B 05 ?? ?? ?? ?? 75 EE 59 5B 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_sigmask_aee42d559961caeb2dbc755d058577de {
	meta:
		aliases = "pthread_sigmask"
		type = "func"
		size = "170"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 74 24 14 8B 44 24 18 85 C0 74 78 8B 10 8B 40 04 89 44 24 04 89 14 24 83 FE 01 74 4F 83 FE 02 74 06 85 F6 74 28 EB 5A FF 35 ?? ?? ?? ?? 8D 5C 24 04 53 E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 EB 17 FF 35 ?? ?? ?? ?? 8D 5C 24 04 53 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 59 5A 85 C0 7E 19 50 EB 0A FF 35 ?? ?? ?? ?? 8D 5C 24 04 53 E8 ?? ?? ?? ?? 89 D8 5B 5A EB 02 89 E0 FF 74 24 1C 50 56 E8 ?? ?? ?? ?? 83 C4 0C 31 D2 40 75 07 E8 ?? ?? ?? ?? 8B 10 89 D0 5A 59 5B 5E C3 }
	condition:
		$pattern
}

rule erand48_r_4d27f5db64943cd84b53c6f5f5368237 {
	meta:
		aliases = "__GI_erand48_r, erand48_r"
		type = "func"
		size = "131"
		objfiles = "erand48_r@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 C7 04 24 00 00 00 00 C7 44 24 04 00 00 00 00 8B 74 24 14 FF 74 24 18 56 E8 ?? ?? ?? ?? 5B 5A 83 CA FF 85 C0 78 51 8B 54 24 04 81 E2 FF FF 0F 00 81 CA 00 00 F0 3F 66 8B 5E 02 89 D9 66 C1 E9 0C 0F B7 C9 0F B7 46 04 C1 E0 04 09 C1 81 E2 00 00 F0 FF 09 CA 89 54 24 04 C1 E3 14 0F B7 06 C1 E0 04 09 C3 89 1C 24 DD 04 24 DC 25 ?? ?? ?? ?? 8B 44 24 1C DD 18 31 D2 89 D0 5A 59 5B 5E C3 }
	condition:
		$pattern
}

rule tgamma_9987bf4a7aecf5e7e353877f53989005 {
	meta:
		aliases = "__GI_tgamma, tgamma"
		type = "func"
		size = "161"
		objfiles = "e_lgamma_r@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C DD 44 24 18 DD 14 24 8B 34 24 8B 44 24 04 25 FF FF FF 7F 09 F0 75 08 DC 3D ?? ?? ?? ?? EB 77 DD D8 8B 5C 24 04 85 DB 79 30 81 FB FF FF EF FF 77 28 FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 58 5A DD 44 24 18 D9 C9 DD E9 DF E0 9E 75 0A 7A 08 D9 C0 DE E1 D8 F0 EB 3F DD D8 81 FB 00 00 F0 FF 75 0C 85 F6 75 08 DD 44 24 18 D8 E0 EB 29 8D 44 24 08 50 FF 74 24 20 FF 74 24 20 E8 ?? ?? ?? ?? 83 EC 08 DD 1C 24 E8 ?? ?? ?? ?? 83 C4 14 83 7C 24 08 00 79 02 D9 E0 83 C4 0C 5B 5E C3 }
	condition:
		$pattern
}

rule setlogmask_a1128f9d0ea916a068647f725f333f17 {
	meta:
		aliases = "setlogmask"
		type = "func"
		size = "80"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 0F B6 35 ?? ?? ?? ?? 83 7C 24 1C 00 74 32 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 44 24 2C A2 ?? ?? ?? ?? 6A 01 53 E8 ?? ?? ?? ?? 83 C4 18 89 F2 0F B6 C2 83 C4 10 5B 5E C3 }
	condition:
		$pattern
}

rule getutline_2d20c0ca2cdeb861f80b8bfbc394e6fa {
	meta:
		aliases = "__GI_getutline, getutline"
		type = "func"
		size = "108"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 8B 74 24 1C 83 C6 08 EB 1E 8B 03 83 E8 06 66 83 F8 01 77 13 6A 20 56 8D 43 08 50 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 0B E8 ?? ?? ?? ?? 89 C3 85 C0 75 D7 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 89 D8 83 C4 18 5B 5E C3 }
	condition:
		$pattern
}

rule setstate_dc5e208c793d3a1828bd49656d02c6be {
	meta:
		aliases = "setstate"
		type = "func"
		size = "87"
		objfiles = "random@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 30 E8 ?? ?? ?? ?? 83 C4 18 31 F6 85 C0 78 03 8D 73 FC 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 89 F0 83 C4 18 5B 5E C3 }
	condition:
		$pattern
}

rule initstate_62284cf37846cfb02f3bfa397d88e079 {
	meta:
		aliases = "initstate"
		type = "func"
		size = "85"
		objfiles = "random@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 83 EE 04 68 ?? ?? ?? ?? FF 74 24 38 FF 74 24 38 FF 74 24 38 E8 ?? ?? ?? ?? 83 C4 20 6A 01 53 E8 ?? ?? ?? ?? 89 F0 83 C4 18 5B 5E C3 }
	condition:
		$pattern
}

rule getrpcent_r_5b4a6a4b4d52114c83390ef1e05ce556 {
	meta:
		aliases = "getrpcent_r"
		type = "func"
		size = "79"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 74 24 38 FF 74 24 38 8B 4C 24 38 8B 54 24 34 E8 ?? ?? ?? ?? 89 C6 6A 01 53 E8 ?? ?? ?? ?? 89 F0 83 C4 30 5B 5E C3 }
	condition:
		$pattern
}

rule getrpcbynumber_r_b2e70190f74df4d60c42f28644af9501 {
	meta:
		aliases = "getrpcbyname_r, getrpcbynumber_r"
		type = "func"
		size = "83"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 74 24 2C E8 ?? ?? ?? ?? FF 74 24 40 FF 74 24 40 8B 4C 24 40 8B 54 24 3C E8 ?? ?? ?? ?? 89 C6 6A 01 53 E8 ?? ?? ?? ?? 89 F0 83 C4 34 5B 5E C3 }
	condition:
		$pattern
}

rule getutid_8130b8e244ff5d1e14286cdad7cf68d7 {
	meta:
		aliases = "getutid"
		type = "func"
		size = "62"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 74 24 08 56 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 2C E8 ?? ?? ?? ?? 89 C3 6A 01 56 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B 5E C3 }
	condition:
		$pattern
}

rule _time_mktime_10a3842d1b40dcbce7e7d4d2648ebede {
	meta:
		aliases = "_time_mktime"
		type = "func"
		size = "76"
		objfiles = "_time_mktime@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 74 24 08 56 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 34 FF 74 24 34 E8 ?? ?? ?? ?? 89 C3 6A 01 56 E8 ?? ?? ?? ?? 89 D8 83 C4 34 5B 5E C3 }
	condition:
		$pattern
}

rule getutent_fe55359de9b3bb93908029041a78b803 {
	meta:
		aliases = "__GI_getutent, getutent"
		type = "func"
		size = "58"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 74 24 08 56 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 6A 01 56 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B 5E C3 }
	condition:
		$pattern
}

rule ulckpwdf_b6949ede03a732a1ee33cce7b6535fd8 {
	meta:
		aliases = "ulckpwdf"
		type = "func"
		size = "89"
		objfiles = "lckpwdf@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 83 CE FF 83 3D ?? ?? ?? ?? FF 74 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 C7 05 ?? ?? ?? ?? FF FF FF FF 6A 01 53 E8 ?? ?? ?? ?? 83 C4 1C 89 F0 83 C4 10 5B 5E C3 }
	condition:
		$pattern
}

rule getchar_4a07c6d81b47d0fe5a1d2de28a037cb2 {
	meta:
		aliases = "getchar"
		type = "func"
		size = "121"
		objfiles = "getchar@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 35 ?? ?? ?? ?? 83 7E 34 00 74 1C 8B 46 10 3B 46 18 73 09 0F B6 18 40 89 46 10 EB 4F 56 E8 ?? ?? ?? ?? 89 C3 5E EB 44 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8B 46 10 83 C4 10 3B 46 18 73 09 0F B6 18 40 89 46 10 EB 09 56 E8 ?? ?? ?? ?? 89 C3 59 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 10 5B 5E C3 }
	condition:
		$pattern
}

rule pselect_a4efd7ed7cd9a93dcd096aa8769322a6 {
	meta:
		aliases = "pselect"
		type = "func"
		size = "124"
		objfiles = "pselect@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 5C 24 2C 8B 74 24 30 85 DB 74 17 8B 03 89 44 24 08 8B 43 04 BA E8 03 00 00 89 D1 99 F7 F9 89 44 24 0C 85 F6 74 0E 89 E0 50 56 6A 02 E8 ?? ?? ?? ?? 83 C4 0C 31 C0 85 DB 74 04 8D 44 24 08 50 FF 74 24 2C FF 74 24 2C FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 89 C3 83 C4 14 85 F6 74 11 6A 00 8D 44 24 04 50 6A 02 E8 ?? ?? ?? ?? 83 C4 0C 89 D8 83 C4 10 5B 5E C3 }
	condition:
		$pattern
}

rule exit_a73758aecd6a9080c88eac6b66d2d196 {
	meta:
		aliases = "__GI_exit, exit"
		type = "func"
		size = "90"
		objfiles = "exit@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 74 24 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 08 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 04 56 FF D0 59 6A 01 53 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 5A B8 ?? ?? ?? ?? 85 C0 74 05 E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_once_c7c3d4e6133fb21f94007973ed05313f {
	meta:
		aliases = "__pthread_once, pthread_once"
		type = "func"
		size = "198"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 74 24 1C 83 3E 02 75 05 E9 AB 00 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 16 89 D0 83 E0 03 59 48 75 24 83 E2 FC 3B 15 ?? ?? ?? ?? 74 19 C7 06 00 00 00 00 EB 11 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 5A 8B 16 89 D0 83 E0 03 48 74 E5 31 DB 85 D2 75 48 A1 ?? ?? ?? ?? 83 C8 01 89 06 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 68 ?? ?? ?? ?? 8D 5C 24 0C 53 E8 ?? ?? ?? ?? FF 54 24 30 6A 00 53 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 06 02 00 00 00 BB 01 00 00 00 83 C4 1C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 85 DB 74 0B 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 31 C0 83 C4 10 5B 5E C3 }
	condition:
		$pattern
}

rule getc_961aa6f62fbab4254bd782098cead616 {
	meta:
		aliases = "__GI_fgetc, fgetc, getc"
		type = "func"
		size = "119"
		objfiles = "fgetc@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 74 24 1C 83 7E 34 00 74 1C 8B 46 10 3B 46 18 73 09 0F B6 18 40 89 46 10 EB 4F 56 E8 ?? ?? ?? ?? 89 C3 5E EB 44 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8B 46 10 83 C4 10 3B 46 18 73 09 0F B6 18 40 89 46 10 EB 09 56 E8 ?? ?? ?? ?? 89 C3 59 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 10 5B 5E C3 }
	condition:
		$pattern
}

rule dl_iterate_phdr_f9d6fa4ad3c0990373ed4b131edc7528 {
	meta:
		aliases = "dl_iterate_phdr"
		type = "func"
		size = "84"
		objfiles = "dl_iterate_phdr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 74 24 1C 8B 5C 24 20 8B 15 ?? ?? ?? ?? 85 D2 74 2E C7 04 24 00 00 00 00 C7 44 24 04 ?? ?? ?? ?? A1 ?? ?? ?? ?? 89 44 24 08 66 89 54 24 0C 53 6A 10 8D 44 24 08 50 FF D6 83 C4 0C 85 C0 75 09 53 56 E8 ?? ?? ?? ?? 5A 59 83 C4 10 5B 5E C3 }
	condition:
		$pattern
}

rule readdir_3e5b31e83c42d247bb79689289b80e10 {
	meta:
		aliases = "__GI_readdir, readdir"
		type = "func"
		size = "127"
		objfiles = "readdir@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 74 24 1C 8D 5E 18 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 8B 46 08 3B 46 04 77 22 FF 76 14 FF 76 0C FF 36 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 7F 04 31 DB EB 26 89 46 08 C7 46 04 00 00 00 00 8B 46 04 89 C3 03 5E 0C 0F B7 53 08 01 C2 89 56 04 8B 43 04 89 46 10 83 3B 00 74 BA 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 89 D8 83 C4 18 5B 5E C3 }
	condition:
		$pattern
}

rule readdir64_0a916aaee655995627b75b8b217838a2 {
	meta:
		aliases = "__GI_readdir64, readdir64"
		type = "func"
		size = "129"
		objfiles = "readdir64@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 74 24 1C 8D 5E 18 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 8B 46 08 3B 46 04 77 22 FF 76 14 FF 76 0C FF 36 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 7F 04 31 DB EB 28 89 46 08 C7 46 04 00 00 00 00 8B 56 04 89 D3 03 5E 0C 0F B7 43 10 01 D0 89 46 04 8B 43 08 89 46 10 8B 03 0B 43 04 74 B8 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 89 D8 83 C4 18 5B 5E C3 }
	condition:
		$pattern
}

rule atan_e122777cdcb3ce1672d60ca8b2e05419 {
	meta:
		aliases = "__GI_atan, atan"
		type = "func"
		size = "449"
		objfiles = "s_atan@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 DD 44 24 1C DD 54 24 08 8B 74 24 0C 89 F3 81 E3 FF FF FF 7F 81 FB FF FF 0F 44 7E 39 DD 1C 24 8B 04 24 81 FB 00 00 F0 7F 7F 06 75 0F 85 C0 74 0B DD 44 24 1C D8 C0 E9 73 01 00 00 85 F6 7F 0B DD 05 ?? ?? ?? ?? E9 64 01 00 00 DD 05 ?? ?? ?? ?? E9 59 01 00 00 DD D8 81 FB FF FF DB 3F 7F 2A 81 FB FF FF 1F 3E 0F 8F B0 00 00 00 DD 44 24 1C DC 05 ?? ?? ?? ?? D9 E8 D9 C9 DA E9 DF E0 9E 0F 87 2E 01 00 00 E9 92 00 00 00 FF 74 24 20 FF 74 24 20 E8 ?? ?? ?? ?? 58 5A D9 C0 81 FB FF FF F2 3F 7F 3D 81 FB FF FF E5 3F 7F 1C DC C1 D9 C9 DC 25 ?? ?? ?? ?? D9 C9 D8 05 ?? ?? ?? ?? DE F9 DD 5C 24 1C 31 }
	condition:
		$pattern
}

rule log2_bb87ad3d58a27abdf099f8b3dcfaf93e {
	meta:
		aliases = "__ieee754_log2, log2"
		type = "func"
		size = "390"
		objfiles = "e_log2@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 DD 44 24 24 DD 54 24 10 8B 4C 24 14 8B 54 24 10 31 F6 81 F9 FF FF 0F 00 7F 4A 89 C8 25 FF FF FF 7F 09 D0 75 0F D9 C0 DE E1 D8 3D ?? ?? ?? ?? E9 47 01 00 00 DD D8 85 C9 79 0D DD 44 24 24 D8 E0 D8 F0 E9 34 01 00 00 DD 44 24 24 D8 0D ?? ?? ?? ?? DD 54 24 24 DD 5C 24 08 8B 4C 24 0C BE CA FF FF FF EB 02 DD D8 81 F9 FF FF EF 7F 7E 0B DD 44 24 24 D8 C0 E9 02 01 00 00 89 CB 81 E3 FF FF 0F 00 8D 93 64 5F 09 00 81 E2 00 00 10 00 DD 44 24 24 DD 1C 24 89 D0 35 00 00 F0 3F 09 D8 89 44 24 04 C1 F9 14 8D 84 0E 01 FC FF FF C1 FA 14 01 D0 50 DB 04 24 83 C4 04 DD 04 24 DC 25 ?? ?? ?? ?? 8D 43 02 }
	condition:
		$pattern
}

rule log_c6a025aea17bd7ca73846953b8d35a4b {
	meta:
		aliases = "__GI_log, __ieee754_log, log"
		type = "func"
		size = "523"
		objfiles = "e_log@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 DD 44 24 24 DD 5C 24 10 8B 4C 24 14 8B 54 24 10 31 F6 81 F9 FF FF 0F 00 7F 48 89 C8 25 FF FF FF 7F 09 D0 75 0D D9 EE D8 3D ?? ?? ?? ?? E9 CE 01 00 00 85 C9 79 11 DD 44 24 24 D8 E0 DC 35 ?? ?? ?? ?? E9 B9 01 00 00 DD 44 24 24 D8 0D ?? ?? ?? ?? DD 54 24 24 DD 5C 24 08 8B 4C 24 0C BE CA FF FF FF 81 F9 FF FF EF 7F 7E 0B DD 44 24 24 D8 C0 E9 8B 01 00 00 89 CB 81 E3 FF FF 0F 00 8D 93 64 5F 09 00 81 E2 00 00 10 00 DD 44 24 24 DD 1C 24 89 D0 35 00 00 F0 3F 09 D8 89 44 24 04 C1 F9 14 8D 84 0E 01 FC FF FF C1 FA 14 8D 0C 10 DD 04 24 DC 25 ?? ?? ?? ?? 8D 43 02 25 FF FF 0F 00 83 F8 02 7F 75 }
	condition:
		$pattern
}

rule pthread_onexit_process_8c0b8233e6dadcf5e437dd0024f378bd {
	meta:
		aliases = "pthread_onexit_process"
		type = "func"
		size = "134"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 1C 83 3D ?? ?? ?? ?? 00 78 72 E8 ?? ?? ?? ?? 89 C3 89 04 24 C7 44 24 04 02 00 00 00 8B 44 24 28 89 44 24 08 89 E6 6A 1C 56 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 40 75 0A E8 ?? ?? ?? ?? 83 38 04 74 E2 89 D8 E8 ?? ?? ?? ?? 3B 1D ?? ?? ?? ?? 75 29 68 00 00 00 80 6A 00 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 0C 83 C4 1C 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_create_7fda7e6e6c59a22ededd3da9bbff2c45 {
	meta:
		aliases = "pthread_create"
		type = "func"
		size = "152"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 1C 83 3D ?? ?? ?? ?? 00 79 0E E8 ?? ?? ?? ?? BA 0B 00 00 00 85 C0 78 74 E8 ?? ?? ?? ?? 89 C3 89 04 24 C7 44 24 04 00 00 00 00 8B 44 24 2C 89 44 24 08 8B 44 24 30 89 44 24 0C 8B 44 24 34 89 44 24 10 8D 44 24 14 50 6A 00 6A 02 E8 ?? ?? ?? ?? 83 C4 0C 89 E6 6A 1C 56 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 40 75 0A E8 ?? ?? ?? ?? 83 38 04 74 E2 89 D8 E8 ?? ?? ?? ?? 83 7B 34 00 75 09 8B 53 30 8B 44 24 28 89 10 8B 53 34 89 D0 83 C4 1C 5B 5E C3 }
	condition:
		$pattern
}

rule sem_post_b0a272ed3c9f9fd5644e909ad64516e5 {
	meta:
		aliases = "__new_sem_post, sem_post"
		type = "func"
		size = "213"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 1C 8B 74 24 28 E8 ?? ?? ?? ?? 83 78 54 00 75 6B 89 C2 89 F0 E8 ?? ?? ?? ?? 83 7E 0C 00 75 2F 8B 46 08 3D FF FF FF 7F 75 16 E8 ?? ?? ?? ?? C7 00 22 00 00 00 56 E8 ?? ?? ?? ?? 83 C8 FF EB 0C 40 89 46 08 56 E8 ?? ?? ?? ?? 31 C0 59 EB 7D 8B 5E 0C 85 DB 74 0D 8B 43 08 89 46 0C C7 43 08 00 00 00 00 56 E8 ?? ?? ?? ?? C6 83 42 01 00 00 01 53 E8 ?? ?? ?? ?? 31 C0 5E 5A EB 50 83 3D ?? ?? ?? ?? 00 79 19 E8 ?? ?? ?? ?? 85 C0 79 10 E8 ?? ?? ?? ?? C7 00 0B 00 00 00 83 C8 FF EB 2E C7 44 24 04 04 00 00 00 89 74 24 08 89 E3 6A 1C 53 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 40 75 0A E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_do_exit_aa422388bab48433c104ed7416e53876 {
	meta:
		aliases = "__pthread_do_exit"
		type = "func"
		size = "214"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 1C E8 ?? ?? ?? ?? 89 C3 C6 40 40 01 C6 40 41 00 FF 74 24 2C E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 43 1C 89 DA E8 ?? ?? ?? ?? 8B 44 24 2C 89 43 30 58 83 BB 24 01 00 00 00 74 2B A1 ?? ?? ?? ?? 0B 83 28 01 00 00 F6 C4 01 74 1B C7 83 30 01 00 00 09 00 00 00 89 9B 34 01 00 00 89 1D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 43 2C 01 8B 73 38 FF 73 1C E8 ?? ?? ?? ?? 58 85 F6 74 07 56 E8 ?? ?? ?? ?? 58 8B 35 ?? ?? ?? ?? 39 F3 75 42 83 3D ?? ?? ?? ?? 00 78 39 89 34 24 C7 44 24 04 03 00 00 00 89 E3 6A 1C 53 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 40 75 0A E8 ?? ?? ?? ?? 83 38 04 74 E2 89 F0 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _stdio_openlist_dec_use_4a5b8af23fac39cd7951dd810c7dadd5 {
	meta:
		aliases = "_stdio_openlist_dec_use"
		type = "func"
		size = "209"
		objfiles = "fflush_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 20 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 48 0F 85 82 00 00 00 83 3D ?? ?? ?? ?? 00 7E 79 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 31 F6 83 C4 10 EB 32 8B 5A 20 0F B7 02 25 30 80 00 00 83 F8 30 74 04 89 D6 EB 1C 85 F6 75 08 89 1D ?? ?? ?? ?? EB 03 89 5E 20 F6 42 01 20 74 07 52 E8 ?? ?? ?? ?? 59 89 DA 85 D2 75 CA 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 58 5A A1 ?? ?? ?? ?? 48 A3 ?? ?? ?? ?? 6A 01 8D 44 24 14 50 E8 ?? }
	condition:
		$pattern
}

rule if_indextoname_0d9b93f0c9d242ed9b0325dcba638c51 {
	meta:
		aliases = "if_indextoname"
		type = "func"
		size = "116"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 20 E8 ?? ?? ?? ?? 89 C3 31 C0 85 DB 78 5C 8B 44 24 2C 89 44 24 10 89 E6 56 68 10 89 00 00 53 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 79 23 E8 ?? ?? ?? ?? 89 C6 8B 10 89 D9 87 CB B8 06 00 00 00 CD 80 87 CB 83 FA 13 75 02 B2 06 89 16 31 C0 EB 1C 89 D9 87 CB B8 06 00 00 00 CD 80 87 CB 6A 10 56 FF 74 24 38 E8 ?? ?? ?? ?? 83 C4 0C 83 C4 20 5B 5E C3 }
	condition:
		$pattern
}

rule if_nametoindex_49c0b2fad86715a196861de744ae4f77 {
	meta:
		aliases = "__GI_if_nametoindex, if_nametoindex"
		type = "func"
		size = "93"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 20 E8 ?? ?? ?? ?? 89 C6 31 C0 85 F6 78 45 6A 10 FF 74 24 30 8D 5C 24 08 53 E8 ?? ?? ?? ?? 53 68 33 89 00 00 56 E8 ?? ?? ?? ?? 83 C4 18 85 C0 79 11 89 F1 87 CB B8 06 00 00 00 CD 80 87 CB 31 C0 EB 11 89 F1 87 CB B8 06 00 00 00 CD 80 87 CB 8B 44 24 10 83 C4 20 5B 5E C3 }
	condition:
		$pattern
}

rule pmap_set_6ed1422dbe7b50956aa54d8905d890b1 {
	meta:
		aliases = "__GI_pmap_set, pmap_set"
		type = "func"
		size = "203"
		objfiles = "pmap_clnt@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 28 8B 74 24 40 C7 44 24 24 FF FF FF FF 8D 5C 24 10 89 D8 E8 ?? ?? ?? ?? 85 C0 0F 84 9F 00 00 00 68 90 01 00 00 68 90 01 00 00 8D 44 24 2C 50 FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 6A 02 68 A0 86 01 00 53 E8 ?? ?? ?? ?? 89 C3 83 C4 20 85 C0 74 6E 8B 44 24 34 89 04 24 8B 44 24 38 89 44 24 04 8B 44 24 3C 89 44 24 08 0F B7 C6 89 44 24 0C 8D 44 24 20 89 E2 8B 4B 04 FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? 6A 01 53 FF 11 83 C4 20 85 C0 74 15 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? C7 44 24 28 00 00 00 00 5E 58 8B 43 04 53 FF 50 10 8B 44 24 24 5B EB 02 31 C0 83 C4 28 }
	condition:
		$pattern
}

rule remquo_37d668307a52abcd085a57d968f0842c {
	meta:
		aliases = "__GI_remquo, remquo"
		type = "func"
		size = "124"
		objfiles = "s_remquo@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 28 DD 44 24 34 DD 5C 24 10 DD 44 24 3C DD 5C 24 08 8B 74 24 44 DD 44 24 10 DD 5C 24 20 DD 44 24 08 DD 5C 24 18 8B 54 24 24 C1 EA 1F 8B 44 24 1C C1 E8 1F 31 DB 39 C2 0F 94 C3 8D 5C 1B FF DD 44 24 10 DC 74 24 08 DD 1C 24 E8 ?? ?? ?? ?? DD 1C 24 E8 ?? ?? ?? ?? 83 E0 7F 0F AF C3 89 06 DD 44 24 08 DD 5C 24 3C DD 44 24 10 DD 5C 24 34 83 C4 28 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule popen_b9a8a940cae18c5ed06238dcf4ea839a {
	meta:
		aliases = "popen"
		type = "func"
		size = "453"
		objfiles = "popen@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 2C 8B 5C 24 3C 8A 03 3C 77 74 23 C7 44 24 10 01 00 00 00 3C 72 74 1F E8 ?? ?? ?? ?? C7 00 16 00 00 00 C7 04 24 00 00 00 00 E9 8A 01 00 00 C7 44 24 10 00 00 00 00 6A 0C E8 ?? ?? ?? ?? 5A C7 04 24 00 00 00 00 85 C0 0F 84 6B 01 00 00 89 44 24 04 8D 44 24 24 50 E8 ?? ?? ?? ?? 5E 85 C0 0F 85 42 01 00 00 8B 44 24 10 8B 44 84 24 89 44 24 0C B8 01 00 00 00 2B 44 24 10 8B 44 84 24 89 44 24 08 53 50 E8 ?? ?? ?? ?? 89 44 24 08 59 5B 85 C0 75 19 FF 74 24 08 E8 ?? ?? ?? ?? FF 74 24 10 E8 ?? ?? ?? ?? 58 5A E9 FB 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 1C 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __get_hosts_byaddr_r_c6ed1df6f1087b1138def915d0a6dd0b {
	meta:
		aliases = "__get_hosts_byaddr_r"
		type = "func"
		size = "96"
		objfiles = "get_hosts_byaddr_r@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 30 8B 44 24 40 8B 74 24 44 83 FE 02 74 07 83 FE 0A 75 41 EB 05 83 F8 04 EB 03 83 F8 10 75 35 6A 2E 8D 5C 24 06 53 FF 74 24 44 56 E8 ?? ?? ?? ?? FF 74 24 68 FF 74 24 68 FF 74 24 68 FF 74 24 68 FF 74 24 68 6A 02 56 53 6A 00 E8 ?? ?? ?? ?? 83 C4 34 EB 02 31 C0 83 C4 30 5B 5E C3 }
	condition:
		$pattern
}

rule __pthread_timedsuspend_new_b9b1886d2b3671a2e08c2ea562041eb1 {
	meta:
		aliases = "__pthread_timedsuspend_new"
		type = "func"
		size = "223"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 44 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 5A 59 BA 01 00 00 00 85 C0 0F 85 AC 00 00 00 8B 54 24 50 89 62 24 C7 42 20 00 00 00 00 C7 44 24 3C 00 00 00 00 C7 44 24 40 00 00 00 00 FF 35 ?? ?? ?? ?? 8D 5C 24 40 53 E8 ?? ?? ?? ?? 8D 44 24 3C 50 53 6A 01 E8 ?? ?? ?? ?? 83 C4 14 8D 74 24 2C 8D 5C 24 24 6A 00 56 E8 ?? ?? ?? ?? 69 44 24 38 E8 03 00 00 8B 4C 24 5C 8B 51 04 29 C2 89 54 24 30 8B 09 2B 4C 24 34 89 4C 24 2C 58 58 85 D2 79 11 8D 82 00 CA 9A 3B 89 44 24 28 8D 41 FF 89 44 24 24 83 7C 24 24 00 78 0E 6A 00 53 E8 ?? ?? ?? ?? 5A 59 85 C0 75 AD 6A 00 8D 44 24 38 50 6A 02 E8 ?? ?? ?? ?? 31 }
	condition:
		$pattern
}

rule erf_a65de0a3c51d6e85867ab8f264cba430 {
	meta:
		aliases = "__GI_erf, erf"
		type = "func"
		size = "845"
		objfiles = "s_erf@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 44 DD 44 24 50 DD 54 24 2C 8B 74 24 30 89 F3 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 1F C1 EE 1F 8D 14 36 B8 01 00 00 00 29 D0 DC 3D ?? ?? ?? ?? 50 DA 04 24 83 C4 04 E9 07 03 00 00 DD D8 81 FB FF FF EA 3F 0F 8F A8 00 00 00 81 FB FF FF 2F 3E 7F 35 81 FB FF FF 7F 00 7F 21 DD 44 24 50 D8 0D ?? ?? ?? ?? DD 44 24 50 DC 0D ?? ?? ?? ?? DE C1 D8 0D ?? ?? ?? ?? E9 C8 02 00 00 DD 44 24 50 DC 0D ?? ?? ?? ?? EB 62 DD 44 24 50 D8 C8 DD 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? DD 05 ?? ?? ?? ?? D8 CA DC 05 ?? ?? ?? ?? D8 CA DC }
	condition:
		$pattern
}

rule asin_9d74f299d8479d4cae56f1700fea2ed2 {
	meta:
		aliases = "__GI_asin, __ieee754_asin, asin"
		type = "func"
		size = "541"
		objfiles = "e_asin@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 44 DD 44 24 50 DD 54 24 34 8B 74 24 38 89 F3 81 E3 FF FF FF 7F 81 FB FF FF EF 3F 7E 36 DD 54 24 2C 8D 83 00 00 10 C0 0B 44 24 2C 75 17 DC 0D ?? ?? ?? ?? DD 44 24 50 DC 0D ?? ?? ?? ?? DE C1 E9 C3 01 00 00 DD D8 DD 44 24 50 D8 E0 D8 F0 E9 B4 01 00 00 DD D8 81 FB FF FF DF 3F 0F 8F 90 00 00 00 81 FB FF FF 3F 3E 7F 1B DD 44 24 50 DC 05 ?? ?? ?? ?? D9 E8 D9 C9 DA E9 DF E0 9E 0F 87 8D 01 00 00 EB 6D DD 44 24 50 D8 C8 DD 05 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DD 05 ?? ?? ?? ?? D8 CA DC 25 }
	condition:
		$pattern
}

rule vsscanf_46a954b23af42684f0ea79be03c1bf3d {
	meta:
		aliases = "__GI_vsscanf, vsscanf"
		type = "func"
		size = "118"
		objfiles = "vsscanf@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 50 8B 5C 24 5C C7 44 24 04 FE FF FF FF 66 C7 04 24 A1 00 C6 44 24 02 00 C7 44 24 2C 00 00 00 00 C7 44 24 34 01 00 00 00 89 E6 8D 44 24 38 50 E8 ?? ?? ?? ?? C7 44 24 24 00 00 00 00 89 5C 24 14 89 5C 24 0C 53 E8 ?? ?? ?? ?? 5A 8D 04 03 89 44 24 10 89 44 24 18 89 44 24 1C 89 5C 24 20 FF 74 24 68 FF 74 24 68 56 E8 ?? ?? ?? ?? 83 C4 60 5B 5E C3 }
	condition:
		$pattern
}

rule opendir_81dda54ebbf1fced341cc3b98436b3e7 {
	meta:
		aliases = "__GI_opendir, opendir"
		type = "func"
		size = "145"
		objfiles = "opendir@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 58 8B 54 24 64 B9 00 08 09 00 87 D3 B8 05 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0D E8 ?? ?? ?? ?? F7 DB 89 18 31 F6 EB 5A 31 F6 85 C0 78 54 89 E0 50 53 E8 ?? ?? ?? ?? 5A 59 85 C0 79 0F 89 D9 87 CB B8 06 00 00 00 CD 80 87 CB EB 36 6A 01 6A 02 53 E8 ?? ?? ?? ?? 8B 54 24 3C 89 D8 E8 ?? ?? ?? ?? 89 C6 83 C4 0C 85 C0 75 18 89 D9 87 CB B8 06 00 00 00 CD 80 87 CB E8 ?? ?? ?? ?? C7 00 0C 00 00 00 89 F0 83 C4 58 5B 5E C3 }
	condition:
		$pattern
}

rule cbrt_8abe9979e3fd600886fbac1bc2072d44 {
	meta:
		aliases = "__GI_cbrt, cbrt"
		type = "func"
		size = "342"
		objfiles = "s_cbrt@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 68 C7 44 24 10 00 00 00 00 C7 44 24 14 00 00 00 00 DD 44 24 74 DD 54 24 50 8B 5C 24 54 81 E3 00 00 00 80 8B 4C 24 54 81 E1 FF FF FF 7F 81 F9 FF FF EF 7F 7E 07 D8 C0 E9 04 01 00 00 DD D8 DD 44 24 74 DD 54 24 48 8B 44 24 48 09 C8 0F 84 F4 00 00 00 DD 5C 24 40 89 4C 24 44 DD 44 24 40 81 F9 FF FF 0F 00 7F 3D D9 EE DD 5C 24 38 C7 44 24 3C 00 00 50 43 DD 44 24 38 D8 C9 DD 54 24 30 DD 5C 24 28 BA 03 00 00 00 8B 44 24 34 89 D6 31 D2 F7 F6 89 C1 81 C1 93 78 7F 29 89 4C 24 2C DD 44 24 28 EB 22 D9 EE DD 5C 24 20 BA 03 00 00 00 89 C8 89 D6 99 F7 FE 89 C1 81 C1 93 78 9F 2A 89 4C 24 24 DD 44 24 }
	condition:
		$pattern
}

rule skip_9bfa637d5ea37583a67f7b84a064592d {
	meta:
		aliases = "skip"
		type = "func"
		size = "133"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 89 C2 89 C3 31 F6 EB 6C 80 F9 22 75 05 83 F6 01 EB 61 83 FE 01 75 10 80 F9 5C 75 0B 8D 42 01 80 7A 01 22 75 02 89 C2 8A 02 88 03 43 83 FE 01 74 42 80 F9 23 75 0C C6 05 ?? ?? ?? ?? 23 C6 02 00 EB 38 0F B6 C1 83 F8 09 74 0A 83 F8 20 74 05 80 F9 0A 75 1F 88 0D ?? ?? ?? ?? C6 02 00 42 8A 02 0F B6 C8 3C 09 74 F6 83 F9 20 74 F1 83 F9 0A 75 09 EB EA 42 8A 0A 84 C9 75 8E C6 43 FF 00 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule firstwhite_c26a127f88b95d6ba9017592ac36c787 {
	meta:
		aliases = "firstwhite"
		type = "func"
		size = "45"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 89 C3 6A 20 50 E8 ?? ?? ?? ?? 59 5E 89 C6 6A 09 53 E8 ?? ?? ?? ?? 5B 5A 85 F6 74 08 85 C0 74 06 39 C6 76 02 89 C6 89 F0 5B 5E C3 }
	condition:
		$pattern
}

rule __ether_line_w_deb3b07db03699b6b19f94be1427ca0e {
	meta:
		aliases = "__ether_line_w"
		type = "func"
		size = "48"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 89 C3 89 D6 6A 23 50 E8 ?? ?? ?? ?? 5A 59 85 C0 75 0E 6A 0A 53 E8 ?? ?? ?? ?? 5A 59 85 C0 74 03 C6 00 00 89 F2 89 D8 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_set_own_extricate_if_875c0aa90c668ae0a95530ac793c1e9d {
	meta:
		aliases = "__pthread_set_own_extricate_if"
		type = "func"
		size = "50"
		objfiles = "join@libpthread.a, condvar@libpthread.a, semaphore@libpthread.a, oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 89 C3 89 D6 85 D2 74 08 80 78 40 00 75 1F EB 0A 8B 40 1C 89 DA E8 ?? ?? ?? ?? 89 B3 44 01 00 00 85 F6 75 09 FF 73 1C E8 ?? ?? ?? ?? 58 5B 5E C3 }
	condition:
		$pattern
}

rule tdestroy_recurse_719e07924d283b1f95a967b018d9843f {
	meta:
		aliases = "tdestroy_recurse"
		type = "func"
		size = "47"
		objfiles = "tdestroy@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 89 C3 89 D6 8B 40 04 85 C0 74 05 E8 EE FF FF FF 8B 43 08 85 C0 74 07 89 F2 E8 E0 FF FF FF FF 33 FF D6 53 E8 ?? ?? ?? ?? 58 5A 5B 5E C3 }
	condition:
		$pattern
}

rule fill_input_buf_61e3da8444b8ca16f2890c4b996ecd45 {
	meta:
		aliases = "fill_input_buf"
		type = "func"
		size = "53"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 89 C3 8B 50 30 83 E2 03 8B 70 28 01 D6 8B 40 24 29 D0 50 56 FF 33 FF 53 20 83 C4 0C 31 D2 83 F8 FF 74 0B 89 73 2C 8D 04 06 89 43 30 B2 01 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule check_match_be29f606fda2205209315a05cb4d58d7 {
	meta:
		aliases = "check_match"
		type = "func"
		size = "91"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 56 ) 53 89 C6 31 C0 66 83 7E 0E 00 0F 94 C0 85 44 24 0C 75 40 83 7E 04 00 74 3A 0F B6 46 0C 83 E0 0F 83 F8 02 7E 05 83 F8 05 75 29 03 16 8D 5A FF 8D 51 FF 43 8A 03 42 8A 0A 84 C0 75 07 0F B6 D1 F7 DA EB 0C 38 C8 74 EB 0F B6 D0 0F B6 C1 29 C2 85 D2 74 02 31 F6 89 F0 5B 5E C3 }
	condition:
		$pattern
}

rule flush_out_2c874a607dfc68ed2e4d169a9535d4e3 {
	meta:
		aliases = "flush_out"
		type = "func"
		size = "78"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 89 C6 4A 0F 95 C2 0F B6 D2 4A 81 E2 00 00 00 80 8B 48 18 8B 40 10 29 C8 83 E8 04 09 C2 0F CA 89 11 8B 46 0C 8B 5E 10 29 C3 53 50 FF 36 FF 56 08 83 C4 0C 31 D2 39 D8 75 0E 8B 46 0C 89 46 18 83 C0 04 89 46 10 B2 01 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule __check_one_fd_6d008162e19ad6b7dcf00b22e33aa3fa {
	meta:
		aliases = "__check_one_fd"
		type = "func"
		size = "44"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 89 C6 89 D3 6A 01 50 E8 ?? ?? ?? ?? 5A 59 40 75 16 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A 59 39 F0 74 05 E8 ?? ?? ?? ?? 5B 5E C3 }
	condition:
		$pattern
}

rule skip_input_bytes_ed671880274ef9e824b5f7346b8607b1 {
	meta:
		aliases = "skip_input_bytes"
		type = "func"
		size = "59"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 89 C6 89 D3 EB 27 8B 4E 2C 8B 46 30 29 C8 75 0D 89 F0 E8 ?? ?? ?? ?? 85 C0 75 12 EB 19 89 DA 39 C3 7E 02 89 C2 8D 04 11 89 46 2C 29 D3 85 DB 7F D5 B8 01 00 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_free_03b3685495116ef02d386ba12a59f009 {
	meta:
		aliases = "pthread_free"
		type = "func"
		size = "171"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 89 C6 8B 58 10 81 E3 FF 03 00 00 C1 E3 04 81 C3 ?? ?? ?? ?? 31 D2 89 D8 E8 ?? ?? ?? ?? C7 43 08 00 00 00 00 C7 43 0C FF FF FF FF 53 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 48 A3 ?? ?? ?? ?? 8B 86 48 01 00 00 EB 0A 8B 18 50 E8 ?? ?? ?? ?? 89 D8 5B 85 C0 75 F1 8B 86 4C 01 00 00 EB 0B 8B 18 50 E8 ?? ?? ?? ?? 89 D8 59 85 C0 75 F1 81 FE ?? ?? ?? ?? 74 34 83 BE 10 01 00 00 00 75 2B 8B 86 18 01 00 00 85 C0 74 0E 50 FF B6 14 01 00 00 E8 ?? ?? ?? ?? 58 5A 8D 86 60 01 E0 FF 68 00 00 20 00 50 E8 ?? ?? ?? ?? 5B 5E 5B 5E C3 }
	condition:
		$pattern
}

rule strspn_8d2bcbc72e010445c961d2d7abd7e9fd {
	meta:
		aliases = "__GI_strspn, strspn"
		type = "func"
		size = "42"
		objfiles = "strspn@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 44 24 0C 31 F6 EB 0F 38 CB 74 09 42 8A 0A 84 C9 75 F5 EB 0E 46 40 8A 18 84 DB 74 06 8B 54 24 10 EB EA 89 F0 5B 5E C3 }
	condition:
		$pattern
}

rule sysconf_8fd99dd17857dc9c5f52feb31bc5d998 {
	meta:
		aliases = "__GI_sysconf, sysconf"
		type = "func"
		size = "420"
		objfiles = "sysconf@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 44 24 0C 3D F0 00 00 00 77 11 FF 24 85 ?? ?? ?? ?? B8 01 00 00 00 E9 83 01 00 00 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 2A 01 00 00 B8 64 00 00 00 E9 69 01 00 00 B8 00 00 01 00 E9 5F 01 00 00 5B 5E E9 ?? ?? ?? ?? B8 06 00 00 00 E9 4E 01 00 00 5B 5E E9 ?? ?? ?? ?? B8 00 80 00 00 E9 3D 01 00 00 B8 E8 03 00 00 E9 33 01 00 00 B8 00 40 00 00 E9 29 01 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 59 31 F6 85 C0 75 28 EB 3A 66 81 78 12 04 63 75 1E 66 81 78 14 70 75 75 16 0F B6 50 16 A1 ?? ?? ?? ?? 0F B7 04 50 83 E0 08 83 F8 01 83 DE FF 53 E8 ?? ?? ?? ?? 5A 85 C0 75 CF 53 E8 ?? ?? ?? ?? 5B EB 07 E8 }
	condition:
		$pattern
}

rule dirname_cfcca6dc51260af020b3902d5305f20a {
	meta:
		aliases = "dirname"
		type = "func"
		size = "94"
		objfiles = "dirname@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 44 24 0C 85 C0 74 4C 89 C3 89 C6 EB 05 8D 53 01 89 D3 8A 13 84 D2 74 05 80 FA 2F 75 F0 89 DA EB 01 42 8A 0A 80 F9 2F 74 F8 84 C9 74 04 89 DE EB DF 39 C6 75 19 80 38 2F 75 19 8D 70 01 80 78 01 2F 75 0B 8D 50 02 80 78 02 00 75 02 89 D6 C6 06 00 EB 05 B8 ?? ?? ?? ?? 5B 5E C3 }
	condition:
		$pattern
}

rule pread64_5c22623e9d600939c2de16f66411f0fb {
	meta:
		aliases = "__libc_pread64, pread64"
		type = "func"
		size = "45"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 44 24 0C 8B 54 24 10 8B 4C 24 14 C7 44 24 14 00 00 00 00 8B 5C 24 18 8B 74 24 1C 89 5C 24 0C 89 74 24 10 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pwrite64_a8be20e122709c174249db17691b0073 {
	meta:
		aliases = "__libc_pwrite64, pwrite64"
		type = "func"
		size = "45"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 44 24 0C 8B 54 24 10 8B 4C 24 14 C7 44 24 14 01 00 00 00 8B 5C 24 18 8B 74 24 1C 89 5C 24 0C 89 74 24 10 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule re_match_72bd68ff2541fe340642c306275ab316 {
	meta:
		aliases = "re_match"
		type = "func"
		size = "53"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 44 24 0C 8B 74 24 10 8B 4C 24 14 8B 5C 24 18 8B 54 24 1C 89 4C 24 1C 89 54 24 18 89 5C 24 14 89 4C 24 10 89 74 24 0C 31 C9 31 D2 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdrrec_inline_deb966b94ca4d1b53047925a9ac1081d {
	meta:
		aliases = "xdrrec_inline"
		type = "func"
		size = "75"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 44 24 0C 8B 74 24 10 8B 50 0C 8B 00 85 C0 74 05 48 75 30 EB 10 8B 42 10 8D 0C 30 3B 4A 14 77 23 89 4A 10 EB 20 8B 4A 34 39 CE 77 17 8B 5A 2C 8D 04 33 3B 42 30 77 0C 89 D8 29 F1 89 4A 34 01 72 2C EB 02 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule a64l_a7ad4dd76fa82f635ea880d715d13a95 {
	meta:
		aliases = "a64l"
		type = "func"
		size = "58"
		objfiles = "a64l@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 44 24 0C 8D 70 06 89 C2 31 DB 31 C9 0F B6 02 83 E8 2E 83 F8 4C 77 1B 8A 80 ?? ?? ?? ?? 3C 40 74 11 42 0F B6 C0 D3 E0 09 C3 39 F2 74 05 83 C1 06 EB DA 89 D8 5B 5E C3 }
	condition:
		$pattern
}

rule shm_unlink_6d07f6e6504226018ed7cc4b397d90e9 {
	meta:
		aliases = "shm_unlink"
		type = "func"
		size = "41"
		objfiles = "shm@librt.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 44 24 0C E8 ?? ?? ?? ?? 89 C3 83 CE FF 85 C0 74 10 50 E8 ?? ?? ?? ?? 89 C6 53 E8 ?? ?? ?? ?? 59 5B 89 F0 5B 5E C3 }
	condition:
		$pattern
}

rule _ppfs_setargs_57c8ab7a6f649f26956cf905810b78ee {
	meta:
		aliases = "_ppfs_setargs"
		type = "func"
		size = "277"
		objfiles = "_ppfs_setargs@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 4C 24 0C 83 79 18 00 0F 85 B5 00 00 00 81 79 08 00 00 00 80 75 11 8B 41 4C 8D 50 04 89 51 4C 8B 00 89 41 50 89 41 08 8D 59 50 81 79 04 00 00 00 80 75 11 8B 41 4C 8D 50 04 89 51 4C 8B 00 89 41 50 89 41 04 31 F6 EB 73 8B 44 B1 28 46 83 F8 08 74 69 8B 51 4C 7F 0E 83 F8 02 74 52 7E 50 83 F8 07 75 4B EB 2B 3D 00 04 00 00 74 42 7E 40 3D 00 08 00 00 74 09 3D 07 08 00 00 75 32 EB 21 8D 42 08 89 41 4C 8B 02 8B 52 04 89 03 89 53 04 EB 28 8B 51 4C 8D 42 08 89 41 4C DD 02 DD 1B EB 19 8B 51 4C 8D 42 0C 89 41 4C DB 2A DB 3B EB 0A 8D 42 04 89 41 4C 8B 02 89 03 83 C3 0C 3B 71 1C 7C 88 EB 2E 81 79 08 }
	condition:
		$pattern
}

rule timer_settime_d9f786750c77f52d71af91ffc12da914 {
	meta:
		aliases = "timer_settime"
		type = "func"
		size = "59"
		objfiles = "timer_settime@librt.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 4C 24 10 8B 54 24 14 8B 74 24 18 8B 44 24 0C 8B 58 04 89 D8 53 89 C3 B8 04 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5B 5E C3 }
	condition:
		$pattern
}

rule mknod_1a929ccf484a7adad65f6ae8a013d772 {
	meta:
		aliases = "__GI_mknod, mknod"
		type = "func"
		size = "52"
		objfiles = "mknod@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 4C 24 10 8B 5C 24 14 8B 44 24 0C 89 DA 53 89 C3 B8 0E 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B 5E C3 }
	condition:
		$pattern
}

rule _dl_run_fini_array_edde0368faee5a330f8774206e6d9763 {
	meta:
		aliases = "_dl_run_fini_array"
		type = "func"
		size = "43"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 54 24 0C 8B 82 A8 00 00 00 85 C0 74 18 89 C6 03 32 8B 9A B0 00 00 00 C1 EB 02 EB 03 FF 14 9E 4B 83 FB FF 75 F7 5B 5E C3 }
	condition:
		$pattern
}

rule svcunix_reply_4f95bb640e086a37d62653507e822a24 {
	meta:
		aliases = "svctcp_reply, svcunix_reply"
		type = "func"
		size = "53"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 54 24 10 8B 44 24 0C 8B 40 2C 8D 70 08 C7 40 08 00 00 00 00 8B 40 04 89 02 52 56 E8 ?? ?? ?? ?? 89 C3 6A 01 56 E8 ?? ?? ?? ?? 83 C4 10 89 D8 5B 5E C3 }
	condition:
		$pattern
}

rule _dl_do_lazy_reloc_e6b2c0c567bc19f91d29ad5097f64451 {
	meta:
		aliases = "_dl_do_lazy_reloc"
		type = "func"
		size = "45"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 54 24 14 8B 44 24 0C 8B 00 8B 1A 31 C9 8B 72 04 81 E6 FF 00 00 00 74 0D 83 C9 FF 83 FE 07 75 05 01 04 03 31 C9 89 C8 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_rwlock_trywrlock_d85ec09e92b61bb3c511a8ea11579260 {
	meta:
		aliases = "pthread_rwlock_trywrlock"
		type = "func"
		size = "56"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C 31 D2 89 D8 E8 ?? ?? ?? ?? 83 7B 08 00 75 12 83 7B 0C 00 75 0C E8 ?? ?? ?? ?? 89 43 0C 31 F6 EB 05 BE 10 00 00 00 53 E8 ?? ?? ?? ?? 59 89 F0 5B 5E C3 }
	condition:
		$pattern
}

rule sem_trywait_a6f922629b79da2a10e603424c0a845e {
	meta:
		aliases = "__new_sem_trywait, sem_trywait"
		type = "func"
		size = "56"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C 31 D2 89 D8 E8 ?? ?? ?? ?? 8B 43 08 85 C0 75 10 E8 ?? ?? ?? ?? C7 00 0B 00 00 00 83 CE FF EB 06 48 89 43 08 31 F6 53 E8 ?? ?? ?? ?? 5A 89 F0 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_cond_broadcast_c28935e3317bd6f5b11ff00531d74b39 {
	meta:
		aliases = "__GI_pthread_cond_broadcast, pthread_cond_broadcast"
		type = "func"
		size = "69"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C 31 D2 89 D8 E8 ?? ?? ?? ?? 8B 73 08 C7 43 08 00 00 00 00 53 E8 ?? ?? ?? ?? 59 EB 1A 8B 5E 08 C7 46 08 00 00 00 00 C6 86 41 01 00 00 01 89 F0 E8 ?? ?? ?? ?? 89 DE 85 F6 75 E2 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule globfree64_0870b4fc6a52ef2349f3f72211a53a44 {
	meta:
		aliases = "__GI_globfree, __GI_globfree64, globfree, globfree64"
		type = "func"
		size = "62"
		objfiles = "glob64@libc.a, glob@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C 31 F6 83 7B 04 00 75 19 EB 2B 89 F2 03 53 08 8B 43 04 8B 04 90 85 C0 74 07 50 E8 ?? ?? ?? ?? 5A 46 3B 33 72 E5 FF 73 04 E8 ?? ?? ?? ?? C7 43 04 00 00 00 00 58 5B 5E C3 }
	condition:
		$pattern
}

rule fputws_unlocked_744844744fe0a8180a2fb361bd415a0d {
	meta:
		aliases = "__GI_fputws_unlocked, fputws_unlocked"
		type = "func"
		size = "41"
		objfiles = "fputws_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C 53 E8 ?? ?? ?? ?? 5A 89 C6 FF 74 24 10 50 53 E8 ?? ?? ?? ?? 83 C4 0C 39 F0 0F 94 C0 0F B6 C0 48 5B 5E C3 }
	condition:
		$pattern
}

rule fputs_unlocked_6c27d0b1c060474f29b51d07a62f636d {
	meta:
		aliases = "__GI_fputs_unlocked, fputs_unlocked"
		type = "func"
		size = "45"
		objfiles = "fputs_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C 53 E8 ?? ?? ?? ?? 5A 89 C6 FF 74 24 10 50 6A 01 53 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 39 F0 75 02 89 C2 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_key_delete_6e15ab713adbc41585596b9993ac7526 {
	meta:
		aliases = "pthread_key_delete"
		type = "func"
		size = "141"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 81 FB FF 03 00 00 77 0A 83 3C DD ?? ?? ?? ?? 00 75 11 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 16 00 00 00 EB 55 C7 04 DD ?? ?? ?? ?? 00 00 00 00 C7 04 DD ?? ?? ?? ?? 00 00 00 00 83 3D ?? ?? ?? ?? FF 74 2A E8 ?? ?? ?? ?? 89 DE C1 EE 05 83 E3 1F 89 C2 80 7A 2C 00 75 0F 8B 4C B2 74 85 C9 74 07 C7 04 99 00 00 00 00 8B 12 39 C2 75 E5 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule herror_adf09dbd1995843166ce74cf401706b6 {
	meta:
		aliases = "__GI_herror, herror"
		type = "func"
		size = "74"
		objfiles = "herror@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C 85 DB 74 0A BE ?? ?? ?? ?? 80 3B 00 75 05 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 00 BA ?? ?? ?? ?? 83 F8 04 77 07 8B 14 85 ?? ?? ?? ?? 52 56 53 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_kill_586491e03728a5a5e9e5ef948b19fb03 {
	meta:
		aliases = "pthread_kill"
		type = "func"
		size = "96"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C 89 D8 25 FF 03 00 00 C1 E0 04 8D B0 ?? ?? ?? ?? 31 D2 89 F0 E8 ?? ?? ?? ?? 8B 46 08 85 C0 74 05 39 58 10 74 17 56 E8 ?? ?? ?? ?? B8 03 00 00 00 5A EB 24 E8 ?? ?? ?? ?? 8B 00 EB 1B 8B 58 14 56 E8 ?? ?? ?? ?? FF 74 24 14 53 E8 ?? ?? ?? ?? 83 C4 0C 40 74 DE 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule _ppfs_prepargs_aef31d2726b6efc00e8b623391196bd3 {
	meta:
		aliases = "_ppfs_prepargs"
		type = "func"
		size = "57"
		objfiles = "_ppfs_prepargs@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C 8B 44 24 10 89 43 4C 8B 73 18 85 F6 7E 22 89 73 1C C7 43 18 00 00 00 00 C7 43 04 00 00 00 00 C7 43 08 00 00 00 00 53 E8 ?? ?? ?? ?? 89 73 18 58 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_opaque_1bfe02defa9ba03e4477727e6fa2e42a {
	meta:
		aliases = "__GI_xdr_opaque, xdr_opaque"
		type = "func"
		size = "151"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C 8B 4C 24 10 8B 54 24 14 85 D2 74 79 31 F6 89 D0 83 E0 03 74 06 66 BE 04 00 29 C6 8B 03 83 F8 01 74 09 72 33 83 F8 02 75 63 EB 5A 8B 43 04 52 51 53 FF 50 08 83 C4 0C 85 C0 74 51 85 F6 74 46 8B 43 04 89 74 24 14 C7 44 24 10 ?? ?? ?? ?? 89 5C 24 0C 8B 48 08 EB 2A 8B 43 04 52 51 53 FF 50 0C 83 C4 0C 85 C0 74 25 85 F6 74 1A 8B 43 04 89 74 24 14 C7 44 24 10 ?? ?? ?? ?? 89 5C 24 0C 8B 48 0C 5B 5E FF E1 B8 01 00 00 00 EB 02 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule svcunix_destroy_e35d14c0356c14b6fc27392a9786a731 {
	meta:
		aliases = "svctcp_destroy, svcunix_destroy"
		type = "func"
		size = "74"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C 8B 73 2C 53 E8 ?? ?? ?? ?? FF 33 E8 ?? ?? ?? ?? 58 5A 66 83 7B 04 00 74 08 66 C7 43 04 00 00 EB 11 8B 46 0C 8B 50 1C 85 D2 74 07 8D 46 08 50 FF D2 58 56 E8 ?? ?? ?? ?? 58 89 5C 24 0C 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svcudp_destroy_c8b72464d92c9bd83d5d4efa0e953e1a {
	meta:
		aliases = "svcudp_destroy"
		type = "func"
		size = "68"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C 8B 73 30 53 E8 ?? ?? ?? ?? FF 33 E8 ?? ?? ?? ?? 8B 46 0C 8B 50 1C 58 59 85 D2 74 07 8D 46 08 50 FF D2 58 FF 73 2C E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 5E 58 89 5C 24 0C 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule strcasecmp_fe7f9d571a581daedb70c7d500fc65dd {
	meta:
		aliases = "__GI_strcasecmp, strcasecmp"
		type = "func"
		size = "54"
		objfiles = "strcasecmp@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C 8B 74 24 10 31 C0 39 F3 74 1A 8B 0D ?? ?? ?? ?? 0F B6 03 0F BF 14 41 0F B6 06 0F BF 04 41 29 C2 89 D0 75 09 80 3B 00 74 04 46 43 EB D9 5B 5E C3 }
	condition:
		$pattern
}

rule significand_3dd9151dbf98e47475997888d4f328ee {
	meta:
		aliases = "significand"
		type = "func"
		size = "42"
		objfiles = "s_significand@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C 8B 74 24 10 56 53 E8 ?? ?? ?? ?? F7 D8 50 DB 04 24 83 EC 04 DD 1C 24 56 53 E8 ?? ?? ?? ?? 83 C4 18 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_double_57972a683c5cd1f0265aeb3a6c69144d {
	meta:
		aliases = "xdr_double"
		type = "func"
		size = "96"
		objfiles = "xdr_float@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C 8B 74 24 10 8B 03 83 F8 01 74 27 72 08 83 F8 02 0F 94 C0 EB 3D 8B 43 04 8D 56 04 52 53 FF 50 04 5A 59 31 D2 85 C0 74 2D 8B 43 04 56 53 FF 50 04 EB 19 8B 43 04 8D 56 04 52 53 FF 10 5A 59 31 D2 85 C0 74 11 8B 43 04 56 53 FF 10 5A 59 85 C0 0F 95 C0 0F B6 D0 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule _authenticate_0999279fae2b248ecd7c02fbbfa8ac3a {
	meta:
		aliases = "__GI__authenticate, _authenticate"
		type = "func"
		size = "84"
		objfiles = "svc_auth@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C 8B 74 24 10 8D 53 0C 8D 46 18 6A 0C 50 52 E8 ?? ?? ?? ?? 8B 53 1C A1 ?? ?? ?? ?? 89 42 20 8B 43 1C C7 40 28 00 00 00 00 8B 43 0C 83 C4 0C 83 F8 03 77 13 89 74 24 10 89 5C 24 0C 8B 0C 85 ?? ?? ?? ?? 5B 5E FF E1 B8 02 00 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule xdrmem_getbytes_d3971bc069c9b5062a0b940684463efb {
	meta:
		aliases = "xdrmem_getbytes"
		type = "func"
		size = "51"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C 8B 74 24 14 8B 53 14 31 C0 39 F2 72 1D 29 F2 89 53 14 56 FF 73 0C FF 74 24 18 E8 ?? ?? ?? ?? 01 73 0C B8 01 00 00 00 83 C4 0C 5B 5E C3 }
	condition:
		$pattern
}

rule xdrmem_putbytes_97078ee494985b3e0f071960e3d32eae {
	meta:
		aliases = "xdrmem_putbytes"
		type = "func"
		size = "51"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C 8B 74 24 14 8B 53 14 31 C0 39 F2 72 1D 29 F2 89 53 14 56 FF 74 24 14 FF 73 0C E8 ?? ?? ?? ?? 01 73 0C B8 01 00 00 00 83 C4 0C 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_attr_setguardsize_718c14e1ca8c45fd5d5f688b60051f9c {
	meta:
		aliases = "__pthread_attr_setguardsize, pthread_attr_setguardsize"
		type = "func"
		size = "50"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C E8 ?? ?? ?? ?? 89 C6 8B 54 24 10 8D 54 10 FF 89 D0 31 D2 F7 F6 89 C1 0F AF CE B8 16 00 00 00 3B 4B 20 73 05 89 4B 14 30 C0 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_attr_setschedparam_94f938311ef709a0464faae3dd09d489 {
	meta:
		aliases = "__GI_pthread_attr_setschedparam, pthread_attr_setschedparam"
		type = "func"
		size = "55"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C FF 73 04 E8 ?? ?? ?? ?? 89 C6 FF 73 04 E8 ?? ?? ?? ?? 8B 54 24 18 8B 12 59 59 39 C2 7C 0B 39 F2 7F 07 89 53 08 31 C0 EB 05 B8 16 00 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule psignal_174465d2fae6b4862d5707ca0d947fa9 {
	meta:
		aliases = "psignal"
		type = "func"
		size = "61"
		objfiles = "psignal@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 10 85 DB 74 0A BE ?? ?? ?? ?? 80 3B 00 75 07 BB ?? ?? ?? ?? 89 DE FF 74 24 0C E8 ?? ?? ?? ?? 50 56 53 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 18 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_cond_signal_5908d0ad0caa14e9f40a533ed712a889 {
	meta:
		aliases = "__GI_pthread_cond_signal, pthread_cond_signal"
		type = "func"
		size = "65"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 31 D2 89 F0 E8 ?? ?? ?? ?? 8B 5E 08 85 DB 74 0D 8B 43 08 89 46 08 C7 43 08 00 00 00 00 56 E8 ?? ?? ?? ?? 58 85 DB 74 0E C6 83 41 01 00 00 01 89 D8 E8 ?? ?? ?? ?? 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule sbrk_26c89f80a8071f4884c421b4ed1cd2d1 {
	meta:
		aliases = "__GI_sbrk, sbrk"
		type = "func"
		size = "64"
		objfiles = "sbrk@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 83 3D ?? ?? ?? ?? 00 75 0C 6A 00 E8 ?? ?? ?? ?? 59 85 C0 78 1D 85 F6 A1 ?? ?? ?? ?? 75 04 89 C3 EB 13 89 C3 8D 04 30 50 E8 ?? ?? ?? ?? 5A 85 C0 79 03 83 CB FF 89 D8 5B 5E C3 }
	condition:
		$pattern
}

rule seteuid_f9240865b21bb1c7aef5a0b5ec1eca9a {
	meta:
		aliases = "__GI_seteuid, setegid, seteuid"
		type = "func"
		size = "74"
		objfiles = "setegid@libc.a, seteuid@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 83 FE FF 75 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CB FF EB 2A 6A FF 56 6A FF E8 ?? ?? ?? ?? 89 C3 83 C4 0C 83 F8 FF 75 16 E8 ?? ?? ?? ?? 83 38 26 75 0C 56 6A FF E8 ?? ?? ?? ?? 89 C3 58 5A 89 D8 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_getschedparam_77ef64a2070db0bb78be7af5b8687a28 {
	meta:
		aliases = "__GI_pthread_getschedparam, pthread_getschedparam"
		type = "func"
		size = "120"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 89 F0 25 FF 03 00 00 C1 E0 04 8D 98 ?? ?? ?? ?? 31 D2 89 D8 E8 ?? ?? ?? ?? 8B 43 08 85 C0 74 05 39 70 10 74 30 53 E8 ?? ?? ?? ?? B8 03 00 00 00 5B EB 3C FF 74 24 14 56 E8 ?? ?? ?? ?? 5A 59 40 75 09 E8 ?? ?? ?? ?? 8B 00 EB 24 8B 44 24 10 89 18 31 C0 EB 1A 8B 70 14 53 E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 89 C3 59 58 83 FB FF 75 C6 EB D3 5B 5E C3 }
	condition:
		$pattern
}

rule wcscspn_18cfccc2e720d4a78a7ff85f7c00a973 {
	meta:
		aliases = "wcscspn"
		type = "func"
		size = "46"
		objfiles = "wcscspn@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 89 F0 EB 10 39 D9 74 18 83 C2 04 8B 0A 85 C9 75 F3 83 C0 04 8B 18 85 DB 74 06 8B 54 24 10 EB EB 29 F0 C1 F8 02 5B 5E C3 }
	condition:
		$pattern
}

rule if_freenameindex_3f7c2458a6eef477f57398b2e7cac097 {
	meta:
		aliases = "__GI_if_freenameindex, if_freenameindex"
		type = "func"
		size = "43"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 89 F3 EB 0A 50 E8 ?? ?? ?? ?? 83 C3 08 58 8B 43 04 85 C0 75 EF 83 3B 00 75 EA 89 74 24 0C 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _dl_protect_relro_db05301d10b322e231feb5a3b73bf118 {
	meta:
		aliases = "_dl_protect_relro"
		type = "func"
		size = "130"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 16 03 96 D4 00 00 00 A1 ?? ?? ?? ?? F7 D8 89 C3 21 D3 89 D1 03 8E D8 00 00 00 21 C1 39 CB 74 58 29 D9 BA 01 00 00 00 89 D8 53 89 C3 B8 7D 00 00 00 CD 80 5B 89 C2 3D 00 F0 FF FF 76 0A F7 DA 89 15 ?? ?? ?? ?? EB 04 85 C0 79 2D FF 76 04 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? 31 C9 87 CB B8 01 00 00 00 CD 80 87 CB 83 C4 0C 3D 00 F0 FF FF 76 07 F7 D8 A3 ?? ?? ?? ?? 5B 5E C3 }
	condition:
		$pattern
}

rule __cxa_finalize_5a4d64c5f764fa2f818d8d4e8ea6fbce {
	meta:
		aliases = "__cxa_finalize"
		type = "func"
		size = "65"
		objfiles = "__cxa_finalize@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 1D ?? ?? ?? ?? EB 2C 4B 89 D9 C1 E1 04 03 0D ?? ?? ?? ?? 85 F6 74 05 3B 71 0C 75 17 31 D2 B8 03 00 00 00 F0 0F B1 11 83 F8 03 75 07 FF 71 08 FF 51 04 58 85 DB 75 D0 5B 5E C3 }
	condition:
		$pattern
}

rule xprt_unregister_7aee672a8361b86caa465ae7386500a2 {
	meta:
		aliases = "__GI_xprt_unregister, xprt_unregister"
		type = "func"
		size = "117"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 1E E8 ?? ?? ?? ?? 39 C3 7D 61 E8 ?? ?? ?? ?? 8D 14 9D 00 00 00 00 8B 80 B4 00 00 00 39 34 10 75 4A C7 04 10 00 00 00 00 81 FB FF 03 00 00 7E 04 31 F6 EB 2E E8 ?? ?? ?? ?? 89 D9 C1 E9 05 89 DA 83 E2 1F 0F B3 14 88 EB E7 E8 ?? ?? ?? ?? 8D 14 F5 00 00 00 00 03 10 39 1A 75 06 C7 02 FF FF FF FF 46 E8 ?? ?? ?? ?? 3B 30 7C DE 5B 5E C3 }
	condition:
		$pattern
}

rule strsep_c8eb3e0cacb0f4db18a646e6d787add8 {
	meta:
		aliases = "__GI_strsep, strsep"
		type = "func"
		size = "87"
		objfiles = "strsep@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 44 24 10 8B 1E 85 DB 74 42 8A 10 84 D2 74 36 80 78 01 00 75 1B 8A 0B 89 D8 38 D1 74 1C 84 C9 74 24 0F B6 C2 50 8D 43 01 50 E8 ?? ?? ?? ?? EB 07 50 53 E8 ?? ?? ?? ?? 5A 59 85 C0 74 08 C6 00 00 40 89 06 EB 06 C7 06 00 00 00 00 89 D8 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_mutex_lock_0bfb688b1ffcfb5f8c76c85e2d7b4e0e {
	meta:
		aliases = "__pthread_mutex_lock, pthread_mutex_lock"
		type = "func"
		size = "142"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 46 0C 83 F8 01 74 25 7F 06 85 C0 74 13 EB 0A 83 F8 02 74 41 83 F8 03 74 5C B8 16 00 00 00 EB 64 8D 46 10 31 D2 E8 ?? ?? ?? ?? EB 0F E8 ?? ?? ?? ?? 89 C3 39 46 08 75 07 FF 46 04 31 C0 EB 45 8D 46 10 89 DA E8 ?? ?? ?? ?? 89 5E 08 C7 46 04 00 00 00 00 EB E6 E8 ?? ?? ?? ?? 89 C3 B8 23 00 00 00 39 5E 08 74 1E 53 8D 46 10 50 E8 ?? ?? ?? ?? 89 5E 08 EB 0B 6A 00 8D 46 10 50 E8 ?? ?? ?? ?? 31 C0 5A 59 5B 5E C3 }
	condition:
		$pattern
}

rule tsearch_38c1ed5e6dc9299a4be993c3274f2068 {
	meta:
		aliases = "__GI_tsearch, tsearch"
		type = "func"
		size = "89"
		objfiles = "tsearch@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 31 C0 85 DB 74 46 EB 20 FF 30 56 FF 54 24 1C 59 5A 83 F8 00 75 04 8B 03 EB 32 7D 07 8B 1B 83 C3 04 EB 05 8B 1B 83 C3 08 8B 03 85 C0 75 DA 6A 0C E8 ?? ?? ?? ?? 5A 85 C0 74 12 89 03 89 30 C7 40 08 00 00 00 00 C7 40 04 00 00 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule wcswidth_4386e160a7a08019b21460540373ae15 {
	meta:
		aliases = "__GI_wcswidth, wcswidth"
		type = "func"
		size = "86"
		objfiles = "wcswidth@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 31 C9 EB 0A 89 D0 83 E0 7F 39 C2 75 37 41 39 D9 73 24 8B 14 8E 85 D2 75 EB EB 1B 3D FF 00 00 00 7F 22 83 F8 1F 7E 1D 83 E8 7F 83 F8 20 76 15 83 C6 04 42 4B EB 02 31 D2 85 DB 74 0B 8B 06 85 C0 75 D9 EB 03 83 CA FF 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_opaque_auth_38d77b29fbd773ce78520bc9bd550e18 {
	meta:
		aliases = "__GI_xdr_opaque_auth, xdr_opaque_auth"
		type = "func"
		size = "54"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 53 56 E8 ?? ?? ?? ?? 5A 59 31 D2 85 C0 74 18 68 90 01 00 00 8D 43 08 50 8D 43 04 50 56 E8 ?? ?? ?? ?? 89 C2 83 C4 10 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_replymsg_ab31c401c99117ca3b8d2f8e0cbdfeb9 {
	meta:
		aliases = "__GI_xdr_replymsg, xdr_replymsg"
		type = "func"
		size = "76"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 53 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 30 8D 43 04 50 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 20 83 7B 04 01 75 1A 6A 00 68 ?? ?? ?? ?? 8D 43 0C 50 8D 43 08 50 56 E8 ?? ?? ?? ?? 83 C4 14 EB 02 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_pmap_6e62b5ab24950e2c481b22101c1cbcea {
	meta:
		aliases = "__GI_xdr_pmap, xdr_pmap"
		type = "func"
		size = "78"
		objfiles = "pmap_prot@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 53 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 32 8D 43 04 50 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 22 8D 43 08 50 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 12 8D 43 0C 89 44 24 10 89 74 24 0C 5B 5E E9 ?? ?? ?? ?? 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_rejected_reply_e1d2e2de088aab812bb43573391bf507 {
	meta:
		aliases = "__GI_xdr_rejected_reply, xdr_rejected_reply"
		type = "func"
		size = "91"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 53 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 3F 8B 03 85 C0 74 05 48 75 36 EB 22 8D 43 04 50 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 24 8D 43 08 89 44 24 10 89 74 24 0C 5B 5E E9 ?? ?? ?? ?? 8D 43 04 89 44 24 10 89 74 24 0C 5B 5E E9 ?? ?? ?? ?? 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_accepted_reply_43befff6bb1c504eeb8a53000b1ee403 {
	meta:
		aliases = "__GI_xdr_accepted_reply, xdr_accepted_reply"
		type = "func"
		size = "115"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 53 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 57 8D 43 0C 50 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 47 8B 53 0C 85 D2 74 0C B8 01 00 00 00 83 FA 02 75 38 EB 12 8B 43 10 89 44 24 10 89 74 24 0C 8B 4B 14 5B 5E FF E1 8D 43 10 50 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 12 8D 43 14 89 44 24 10 89 74 24 0C 5B 5E E9 ?? ?? ?? ?? 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_authunix_parms_006a85d4b008d211efc5e6a5547d2f23 {
	meta:
		aliases = "__GI_xdr_authunix_parms, xdr_authunix_parms"
		type = "func"
		size = "118"
		objfiles = "authunix_prot@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 53 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 5A 68 FF 00 00 00 8D 43 04 50 56 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 44 8D 43 08 50 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 34 8D 43 0C 50 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 24 68 ?? ?? ?? ?? 6A 04 6A 10 8D 43 10 50 8D 43 14 50 56 E8 ?? ?? ?? ?? 83 C4 18 85 C0 0F 95 C0 0F B6 C0 EB 02 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule getlogin_r_522127bc6a4fc43061ef1904d69244a7 {
	meta:
		aliases = "getlogin_r"
		type = "func"
		size = "51"
		objfiles = "getlogin@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A 83 CA FF 85 C0 74 12 53 50 56 E8 ?? ?? ?? ?? C6 44 1E FF 00 31 D2 83 C4 0C 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule addmntent_5710c9a537e97b0bf9330cfff85467f5 {
	meta:
		aliases = "addmntent"
		type = "func"
		size = "73"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 6A 02 6A 00 56 E8 ?? ?? ?? ?? 83 C4 0C BA 01 00 00 00 85 C0 78 24 FF 73 14 FF 73 10 FF 73 0C FF 73 08 FF 73 04 FF 33 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 89 C2 C1 EA 1F 83 C4 20 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_callmsg_6b87164d49e448a74396616023513710 {
	meta:
		aliases = "__GI_xdr_callmsg, xdr_callmsg"
		type = "func"
		size = "779"
		objfiles = "rpc_cmsg@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 83 3E 00 0F 85 DC 00 00 00 8B 53 20 81 FA 90 01 00 00 0F 87 DD 02 00 00 8B 43 2C 3D 90 01 00 00 0F 87 CF 02 00 00 8B 4E 04 83 C2 03 83 E2 FC 83 C0 03 83 E0 FC 8D 54 02 28 52 56 FF 51 18 89 C2 58 59 85 D2 0F 84 9B 00 00 00 8B 03 0F C8 89 02 8B 43 04 0F C8 89 42 04 83 7B 04 00 0F 85 93 02 00 00 8B 43 08 0F C8 89 42 08 83 7B 08 02 0F 85 81 02 00 00 8B 43 0C 0F C8 89 42 0C 8B 43 10 0F C8 89 42 10 8B 43 14 0F C8 89 42 14 8B 43 18 0F C8 89 42 18 8B 43 20 0F C8 89 42 1C 8D 72 20 8B 43 20 85 C0 74 18 50 FF 73 1C 56 E8 ?? ?? ?? ?? 8B 43 20 83 C0 03 83 E0 FC 01 C6 83 C4 0C }
	condition:
		$pattern
}

rule siglongjmp_80874c12c0923f06960ef9b6fc6b2db8 {
	meta:
		aliases = "__libc_longjmp, __libc_siglongjmp, _longjmp, longjmp, siglongjmp"
		type = "func"
		size = "45"
		objfiles = "longjmp@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 83 7E 18 00 74 10 6A 00 8D 46 1C 50 6A 02 E8 ?? ?? ?? ?? 83 C4 0C 85 DB 75 02 B3 01 53 56 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tfind_ed002546cc2b66f9dd6d5a38a03ab767 {
	meta:
		aliases = "__GI_tfind, tfind"
		type = "func"
		size = "59"
		objfiles = "tfind@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 85 DB 74 28 EB 20 FF 30 56 FF 54 24 1C 5A 59 83 F8 00 75 04 8B 03 EB 16 7D 07 8B 1B 83 C3 04 EB 05 8B 1B 83 C3 08 8B 03 85 C0 75 DA 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule wcsspn_d02d319ac747b2faa306e49fd1cf5d41 {
	meta:
		aliases = "__GI_wcsspn, wcsspn"
		type = "func"
		size = "42"
		objfiles = "wcsspn@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 89 F0 EB 0C 3B 08 74 05 83 C2 04 EB 05 83 C0 04 89 DA 8B 0A 85 C9 75 EC 29 F0 C1 F8 02 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_callhdr_2a7a767a147e68b858a85039ce01c7bd {
	meta:
		aliases = "__GI_xdr_callhdr, xdr_callhdr"
		type = "func"
		size = "113"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 C7 43 04 00 00 00 00 C7 43 08 02 00 00 00 83 3E 00 75 4F 53 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 42 8D 43 04 50 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 32 8D 43 08 50 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 22 8D 43 0C 50 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 12 8D 43 10 89 44 24 10 89 74 24 0C 5B 5E E9 ?? ?? ?? ?? 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule mempcpy_cf525f70562f4ed36011481b9d7740b4 {
	meta:
		aliases = "__GI_mempcpy, mempcpy"
		type = "func"
		size = "30"
		objfiles = "mempcpy@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 14 53 FF 74 24 14 56 E8 ?? ?? ?? ?? 8D 04 1E 83 C4 0C 5B 5E C3 }
	condition:
		$pattern
}

rule ldiv_26fbe5458e0b5feb7ea2bce0cd2705b4 {
	meta:
		aliases = "ldiv"
		type = "func"
		size = "45"
		objfiles = "ldiv@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 14 8B 44 24 10 99 F7 FB 89 C1 83 7C 24 10 00 78 07 85 D2 79 03 41 29 DA 89 56 04 89 0E 89 F0 5B 5E C2 04 00 }
	condition:
		$pattern
}

rule clntudp_destroy_08553100d344b9cc6fd2f5fcf68db579 {
	meta:
		aliases = "clntudp_destroy"
		type = "func"
		size = "58"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5E 08 83 7B 04 00 74 08 FF 33 E8 ?? ?? ?? ?? 58 8B 43 3C 8B 50 1C 85 D2 74 07 8D 43 38 50 FF D2 58 53 E8 ?? ?? ?? ?? 59 89 74 24 0C 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clnttcp_destroy_3358e0ec6f6c561b0fb510c00ce99763 {
	meta:
		aliases = "clnttcp_destroy"
		type = "func"
		size = "58"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5E 08 83 7B 04 00 74 08 FF 33 E8 ?? ?? ?? ?? 59 8B 43 50 8B 50 1C 85 D2 74 07 8D 43 4C 50 FF D2 5A 53 E8 ?? ?? ?? ?? 58 89 74 24 0C 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clntunix_destroy_13fd7547a8d13333848147b9dac4c2d3 {
	meta:
		aliases = "clntunix_destroy"
		type = "func"
		size = "64"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5E 08 83 7B 04 00 74 08 FF 33 E8 ?? ?? ?? ?? 59 8B 83 B0 00 00 00 8B 50 1C 85 D2 74 0A 8D 83 AC 00 00 00 50 FF D2 5A 53 E8 ?? ?? ?? ?? 58 89 74 24 0C 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdrrec_setpos_8d1e31219f15088653afb2026ca30936 {
	meta:
		aliases = "xdrrec_setpos"
		type = "func"
		size = "94"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5E 0C 56 E8 ?? ?? ?? ?? 5A 83 F8 FF 74 44 2B 44 24 10 8B 16 85 D2 74 05 4A 75 37 EB 14 8B 53 10 29 C2 3B 53 18 76 2B 3B 53 14 73 26 89 53 10 EB 1A 8B 53 2C 3B 43 34 7D 19 29 C2 3B 53 30 77 12 3B 53 28 72 0D 89 53 2C 29 43 34 B8 01 00 00 00 EB 02 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule xdrrec_getpos_ba42a33a38e5a46ca7eb2715c4d3b697 {
	meta:
		aliases = "xdrrec_getpos"
		type = "func"
		size = "65"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5E 0C 6A 01 6A 00 FF 33 E8 ?? ?? ?? ?? 89 C1 83 C4 0C 83 C8 FF 83 F9 FF 74 1D 8B 16 85 D2 74 05 4A 75 14 EB 0A 8B 43 10 2B 43 0C 01 C8 EB 08 89 C8 2B 43 30 03 43 2C 5B 5E C3 }
	condition:
		$pattern
}

rule authunix_destroy_c52216da1aaef54a4607e50834f40a4b {
	meta:
		aliases = "authunix_destroy"
		type = "func"
		size = "66"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5E 24 FF 73 04 E8 ?? ?? ?? ?? 8B 43 10 5B 85 C0 74 07 50 E8 ?? ?? ?? ?? 59 FF 76 24 E8 ?? ?? ?? ?? 8B 46 10 5A 85 C0 74 07 50 E8 ?? ?? ?? ?? 58 89 74 24 0C 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getrpcbynumber_70f454fccf82ce1c078a235d0b30189d {
	meta:
		aliases = "__GI_getrpcbynumber, getrpcbynumber"
		type = "func"
		size = "53"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C E8 ?? ?? ?? ?? 31 DB 85 C0 74 1F 6A 00 E8 ?? ?? ?? ?? 58 EB 05 39 73 08 74 0B E8 ?? ?? ?? ?? 89 C3 85 C0 75 F0 E8 ?? ?? ?? ?? 89 D8 5B 5E C3 }
	condition:
		$pattern
}

rule getttynam_eccc10c46b64ca75e7fac5677e566628 {
	meta:
		aliases = "getttynam"
		type = "func"
		size = "48"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C E8 ?? ?? ?? ?? EB 0E FF 33 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 0B E8 ?? ?? ?? ?? 89 C3 85 C0 75 E7 E8 ?? ?? ?? ?? 89 D8 5B 5E C3 }
	condition:
		$pattern
}

rule hcreate_r_846ac91b930756d157f41a79795c54d6 {
	meta:
		aliases = "__GI_hcreate_r, hcreate_r"
		type = "func"
		size = "120"
		objfiles = "hcreate_r@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 10 85 F6 75 0F E8 ?? ?? ?? ?? C7 00 16 00 00 00 31 C0 EB 5C 31 C0 83 3E 00 75 55 8B 4C 24 0C 83 C9 01 EB 03 83 C1 02 BB 03 00 00 00 EB 03 83 C3 02 89 D8 0F AF C3 39 C8 73 0A 89 C8 31 D2 F7 F3 85 D2 75 EA 89 C8 31 D2 F7 F3 85 D2 74 D6 89 4E 04 C7 46 08 00 00 00 00 6A 0C 8B 46 04 40 50 E8 ?? ?? ?? ?? 89 06 5A 59 85 C0 0F 95 C0 0F B6 C0 5B 5E C3 }
	condition:
		$pattern
}

rule sched_getaffinity_351bef3470d16f96925eec69689e40ef {
	meta:
		aliases = "sched_getaffinity"
		type = "func"
		size = "92"
		objfiles = "sched_getaffinity@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 10 89 F1 85 F6 79 05 B9 FF FF FF 7F 8B 44 24 0C 8B 54 24 14 53 89 C3 B8 F2 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF EB 1E 83 C8 FF 83 FB FF 74 16 29 DE 56 6A 00 8B 44 24 1C 01 D8 50 E8 ?? ?? ?? ?? 31 C0 83 C4 0C 5B 5E C3 }
	condition:
		$pattern
}

rule clntraw_freeres_4a14a3df411230ebb6449ba69be2ff22 {
	meta:
		aliases = "clntraw_freeres"
		type = "func"
		size = "57"
		objfiles = "clnt_raw@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 10 8B 5C 24 14 E8 ?? ?? ?? ?? 8B 80 A0 00 00 00 85 C0 74 18 C7 40 0C 02 00 00 00 89 5C 24 10 83 C0 0C 89 44 24 0C 89 F1 5B 5E FF E1 B8 10 00 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule svcraw_getargs_7b732bd212c6735a6d5feb3415216ddb {
	meta:
		aliases = "svcraw_getargs"
		type = "func"
		size = "49"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 10 8B 5C 24 14 E8 ?? ?? ?? ?? 8B 80 BC 00 00 00 85 C0 74 13 89 5C 24 10 05 94 23 00 00 89 44 24 0C 89 F1 5B 5E FF E1 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule svcraw_freeargs_d9aa58799832c7acb4ac0ce6ce7322ef {
	meta:
		aliases = "svcraw_freeargs"
		type = "func"
		size = "59"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 10 8B 5C 24 14 E8 ?? ?? ?? ?? 8B 80 BC 00 00 00 85 C0 74 1D C7 80 94 23 00 00 02 00 00 00 89 5C 24 10 05 94 23 00 00 89 44 24 0C 89 F1 5B 5E FF E1 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule fgetspent_r_e1f38611a4b1ad9d822de85e67acd783 {
	meta:
		aliases = "__GI_fgetgrent_r, __GI_fgetpwent_r, __GI_fgetspent_r, fgetgrent_r, fgetpwent_r, fgetspent_r"
		type = "func"
		size = "51"
		objfiles = "fgetgrent_r@libc.a, fgetspent_r@libc.a, fgetpwent_r@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 10 8B 5C 24 1C C7 03 00 00 00 00 FF 74 24 0C FF 74 24 1C FF 74 24 1C 56 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 14 85 C0 75 02 89 33 5B 5E C3 }
	condition:
		$pattern
}

rule ether_line_b00d12addcd7a1c31e5e273f3599fd4f {
	meta:
		aliases = "ether_line"
		type = "func"
		size = "67"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 14 8B 54 24 10 8B 44 24 0C E8 ?? ?? ?? ?? 89 C3 83 C8 FF 85 DB 74 24 EB 17 80 F9 23 74 18 0F B6 D1 A1 ?? ?? ?? ?? F6 04 50 20 75 0A 88 0E 46 43 8A 0B 84 C9 75 E3 C6 06 00 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule updwtmp_7050ff048dd2c76da25bf1e3c2011aa0 {
	meta:
		aliases = "__GI_updwtmp, updwtmp"
		type = "func"
		size = "134"
		objfiles = "wtent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 B9 01 04 00 00 31 D2 8B 44 24 0C 53 89 C3 B8 05 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0B E8 ?? ?? ?? ?? F7 DE 89 30 EB 57 85 C0 78 53 6A 00 6A 01 50 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 42 BA 80 01 00 00 89 F0 8B 4C 24 10 53 89 C3 B8 04 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 09 E8 ?? ?? ?? ?? F7 DB 89 18 6A 00 6A 00 56 E8 ?? ?? ?? ?? 89 F1 87 CB B8 06 00 00 00 CD 80 87 CB 83 C4 0C 5B 5E C3 }
	condition:
		$pattern
}

rule sethostid_31f9b3cc94d7271dbe08deb1e0626175 {
	meta:
		aliases = "sethostid"
		type = "func"
		size = "161"
		objfiles = "hostid@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 E8 ?? ?? ?? ?? 85 C0 75 09 E8 ?? ?? ?? ?? 85 C0 74 12 E8 ?? ?? ?? ?? C7 00 01 00 00 00 B8 01 00 00 00 EB 78 BB ?? ?? ?? ?? B9 41 00 00 00 BA A4 01 00 00 89 D8 53 89 C3 B8 05 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF EB 45 85 DB 78 41 BA 04 00 00 00 8D 4C 24 0C 53 89 C3 B8 04 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0B E8 ?? ?? ?? ?? F7 DE 89 30 EB 07 31 D2 83 F8 04 74 03 83 CA FF 89 D9 87 CB B8 06 00 00 00 CD 80 87 CB 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule _stdio_init_fb4162a88a7c525030b964234985c465 {
	meta:
		aliases = "_stdio_init"
		type = "func"
		size = "58"
		objfiles = "_stdio@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 E8 ?? ?? ?? ?? 89 C3 8B 30 6A 00 E8 ?? ?? ?? ?? 59 85 C0 75 09 66 81 35 ?? ?? ?? ?? 00 01 6A 01 E8 ?? ?? ?? ?? 5A 85 C0 75 09 66 81 35 ?? ?? ?? ?? 00 01 89 33 5B 5E C3 }
	condition:
		$pattern
}

rule res_sync_func_7d0e61adac9356b2d518526525345c59 {
	meta:
		aliases = "res_sync_func"
		type = "func"
		size = "104"
		objfiles = "res_init@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 E8 ?? ?? ?? ?? 89 C6 81 3D ?? ?? ?? ?? ?? ?? ?? ?? 74 34 0F B6 40 60 39 05 ?? ?? ?? ?? 76 05 A3 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? EB 18 6B C3 1C 03 05 ?? ?? ?? ?? 6A 1C FF 74 9E 54 50 E8 ?? ?? ?? ?? 83 C4 0C 4B 79 E5 8A 46 52 84 C0 75 02 B0 05 A2 ?? ?? ?? ?? 8A 46 53 84 C0 75 02 B0 03 A2 ?? ?? ?? ?? 5B 5E C3 }
	condition:
		$pattern
}

rule svcraw_reply_2dcb352ae89b3f6ff497eadc6deb9834 {
	meta:
		aliases = "svcraw_reply"
		type = "func"
		size = "85"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 E8 ?? ?? ?? ?? 8B 98 BC 00 00 00 85 DB 74 3F 8D B3 94 23 00 00 C7 83 94 23 00 00 00 00 00 00 8B 83 98 23 00 00 6A 00 56 FF 50 14 FF 74 24 18 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 12 8B 83 98 23 00 00 56 FF 50 10 B8 01 00 00 00 5B EB 02 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule ftello_824e97517a9adc96dee5b0400f95e7fa {
	meta:
		aliases = "__GI_ftell, ftell, ftello"
		type = "func"
		size = "48"
		objfiles = "ftello@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 FF 74 24 0C E8 ?? ?? ?? ?? 89 C6 89 C3 C1 FB 1F 83 C4 04 39 D3 75 04 39 C0 74 0E E8 ?? ?? ?? ?? C7 00 4B 00 00 00 83 CE FF 89 F0 5B 5E C3 }
	condition:
		$pattern
}

rule fstatat64_1cfe03b2bcbc63bf5fad360bd0afc77e {
	meta:
		aliases = "fstatat, fstatat64"
		type = "func"
		size = "75"
		objfiles = "fstatat@libc.a, fstatat64@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 83 EC 60 8B 4C 24 6C 8B 74 24 74 89 E2 8B 44 24 68 53 89 C3 B8 2C 01 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF EB 10 85 C0 75 0C FF 74 24 70 52 E8 ?? ?? ?? ?? 58 5A 89 F0 83 C4 60 5E C3 }
	condition:
		$pattern
}

rule sigwaitinfo_8e6b2ae5f1bec13f1e9e79104da68d2a {
	meta:
		aliases = "__GI_sigwaitinfo, __sigwaitinfo, sigwaitinfo"
		type = "func"
		size = "51"
		objfiles = "__rt_sigwaitinfo@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 31 D2 BE 08 00 00 00 8B 44 24 08 53 89 C3 B8 B1 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule epoll_wait_df17beacf0c6845a788be755f4e427ae {
	meta:
		aliases = "__libc_epoll_wait, epoll_wait"
		type = "func"
		size = "52"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 54 24 10 8B 74 24 14 8B 44 24 08 53 89 C3 B8 00 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule openat_030ca9b09b5ea7191da5c1cbc3acbeb9 {
	meta:
		aliases = "__GI_openat, openat"
		type = "func"
		size = "52"
		objfiles = "openat@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 54 24 10 8B 74 24 14 8B 44 24 08 53 89 C3 B8 27 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule renameat_008d80aebff1f332d6210a8b438ff03f {
	meta:
		aliases = "renameat"
		type = "func"
		size = "52"
		objfiles = "renameat@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 54 24 10 8B 74 24 14 8B 44 24 08 53 89 C3 B8 2E 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule readlinkat_f0be5fd666e3fcdd93c3b0b0d78bb704 {
	meta:
		aliases = "readlinkat"
		type = "func"
		size = "52"
		objfiles = "readlinkat@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 54 24 10 8B 74 24 14 8B 44 24 08 53 89 C3 B8 31 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule fchmodat_321c1c222c545f8ad521271dc88ea8f3 {
	meta:
		aliases = "fchmodat"
		type = "func"
		size = "52"
		objfiles = "fchmodat@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 54 24 10 8B 74 24 14 8B 44 24 08 53 89 C3 B8 32 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule faccessat_cd8d55b1924b7da9044a814e5170e1f3 {
	meta:
		aliases = "faccessat"
		type = "func"
		size = "52"
		objfiles = "faccessat@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 54 24 10 8B 74 24 14 8B 44 24 08 53 89 C3 B8 33 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule tee_b8899d5fb6535130047946bac92f5548 {
	meta:
		aliases = "tee"
		type = "func"
		size = "52"
		objfiles = "tee@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 54 24 10 8B 74 24 14 8B 44 24 08 53 89 C3 B8 3B 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule vmsplice_adc66e792dc5c2f01e33a88a462bf0de {
	meta:
		aliases = "vmsplice"
		type = "func"
		size = "52"
		objfiles = "vmsplice@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 54 24 10 8B 74 24 14 8B 44 24 08 53 89 C3 B8 3C 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule utimensat_93d0c1df6f50a326cc0dc75fead94208 {
	meta:
		aliases = "__GI_utimensat, utimensat"
		type = "func"
		size = "52"
		objfiles = "utimensat@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 54 24 10 8B 74 24 14 8B 44 24 08 53 89 C3 B8 40 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule timerfd_settime_6c8c84ef0cc73437255814143388f925 {
	meta:
		aliases = "timerfd_settime"
		type = "func"
		size = "52"
		objfiles = "timerfd@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 54 24 10 8B 74 24 14 8B 44 24 08 53 89 C3 B8 45 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule wait4_3b1bf2ca56e739f2e687abd620b45896 {
	meta:
		aliases = "__GI_wait4, wait4"
		type = "func"
		size = "52"
		objfiles = "wait4@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 54 24 10 8B 74 24 14 8B 44 24 08 53 89 C3 B8 72 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule quotactl_35b68c3b894fb2e907523247a4f6d5cb {
	meta:
		aliases = "quotactl"
		type = "func"
		size = "52"
		objfiles = "quotactl@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 54 24 10 8B 74 24 14 8B 44 24 08 53 89 C3 B8 83 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule __syscall_rt_sigaction_b0dc35abcf6f4ad7795e42ca7be24474 {
	meta:
		aliases = "__syscall_rt_sigaction"
		type = "func"
		size = "52"
		objfiles = "__syscall_rt_sigaction@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 54 24 10 8B 74 24 14 8B 44 24 08 53 89 C3 B8 AE 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule sendfile_f28b5a21bd27d0962bfd49f551273462 {
	meta:
		aliases = "sendfile"
		type = "func"
		size = "52"
		objfiles = "sendfile@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 54 24 10 8B 74 24 14 8B 44 24 08 53 89 C3 B8 BB 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule getxattr_424ae9a459397b6f0ef89ab99f93d22d {
	meta:
		aliases = "getxattr"
		type = "func"
		size = "52"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 54 24 10 8B 74 24 14 8B 44 24 08 53 89 C3 B8 E5 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule lgetxattr_5cdfd1f9228801c6397b6bde537aead1 {
	meta:
		aliases = "lgetxattr"
		type = "func"
		size = "52"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 54 24 10 8B 74 24 14 8B 44 24 08 53 89 C3 B8 E6 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule fgetxattr_5e0990683905559423c318826e9447bc {
	meta:
		aliases = "fgetxattr"
		type = "func"
		size = "52"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 54 24 10 8B 74 24 14 8B 44 24 08 53 89 C3 B8 E7 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule sendfile64_0d05f31cd691695cd7a93f0854bde4aa {
	meta:
		aliases = "sendfile64"
		type = "func"
		size = "52"
		objfiles = "sendfile64@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 54 24 10 8B 74 24 14 8B 44 24 08 53 89 C3 B8 EF 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule epoll_ctl_e123a4f2f1318da160787bb70678c148 {
	meta:
		aliases = "epoll_ctl"
		type = "func"
		size = "52"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 54 24 10 8B 74 24 14 8B 44 24 08 53 89 C3 B8 FF 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule sigprocmask_2767846e45001203848067aabe4bf38f {
	meta:
		aliases = "__GI_sigprocmask, sigprocmask"
		type = "func"
		size = "53"
		objfiles = "sigprocmask@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 54 24 10 BE 08 00 00 00 8B 44 24 08 53 89 C3 B8 AF 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule sigtimedwait_3df25fad57518790a128d406c949d4c2 {
	meta:
		aliases = "__GI_sigtimedwait, __sigtimedwait, sigtimedwait"
		type = "func"
		size = "53"
		objfiles = "__rt_sigtimedwait@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 54 24 10 BE 08 00 00 00 8B 44 24 08 53 89 C3 B8 B1 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule signalfd_e77fce19059f0ac0fdb586718a182257 {
	meta:
		aliases = "signalfd"
		type = "func"
		size = "53"
		objfiles = "signalfd@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 4C 24 0C 8B 74 24 10 BA 08 00 00 00 8B 44 24 08 53 89 C3 B8 47 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E C3 }
	condition:
		$pattern
}

rule strchrnul_700e8ef0aa7b572b154b22a5db8a53d0 {
	meta:
		aliases = "__GI_strchrnul, strchrnul"
		type = "func"
		size = "25"
		objfiles = "strchrnul@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 74 24 08 8B 44 24 0C 88 C4 AC 38 E0 74 04 84 C0 75 F7 8D 46 FF 5E C3 }
	condition:
		$pattern
}

rule strchr_a896babb1add290c02798b8a3eb170f5 {
	meta:
		aliases = "__GI_strchr, index, strchr"
		type = "func"
		size = "30"
		objfiles = "strchr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 74 24 08 8B 44 24 0C 88 C4 AC 38 E0 74 09 84 C0 75 F7 BE 01 00 00 00 8D 46 FF 5E C3 }
	condition:
		$pattern
}

rule logout_381c2b32d708f70d08bc7929f689144c {
	meta:
		aliases = "logout"
		type = "func"
		size = "134"
		objfiles = "logout@libutil.a"
	strings:
		$pattern = { ( CC | 57 ) 53 81 EC 80 01 00 00 E8 ?? ?? ?? ?? 66 C7 04 24 07 00 6A 20 FF B4 24 90 01 00 00 8D 5C 24 08 8D 44 24 10 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 74 3B 31 C0 B9 08 00 00 00 8D 7B 2C F3 AB B9 40 00 00 00 8D 7B 4C F3 AB 6A 00 8D 83 54 01 00 00 50 E8 ?? ?? ?? ?? 66 C7 03 08 00 53 E8 ?? ?? ?? ?? 83 C4 0C BB 01 00 00 00 85 C0 75 02 31 DB E8 ?? ?? ?? ?? 89 D8 81 C4 80 01 00 00 5B 5F C3 }
	condition:
		$pattern
}

rule sigqueue_ec8328be0ec285a4275d90dafe7fdf4c {
	meta:
		aliases = "sigqueue"
		type = "func"
		size = "129"
		objfiles = "sigqueue@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 53 81 EC 84 00 00 00 31 C0 B9 20 00 00 00 8D 5C 24 04 89 DF F3 AB 8B 84 24 94 00 00 00 89 44 24 04 C7 44 24 0C FF FF FF FF E8 ?? ?? ?? ?? 89 44 24 10 E8 ?? ?? ?? ?? 89 44 24 14 8B 84 24 98 00 00 00 89 44 24 18 8B 84 24 90 00 00 00 8B 8C 24 94 00 00 00 89 DA 53 89 C3 B8 B2 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 81 C4 84 00 00 00 5B 5F C3 }
	condition:
		$pattern
}

rule __xstat_conv_4223b3036512d3b8b9e884449e5720e6 {
	meta:
		aliases = "__xstat_conv"
		type = "func"
		size = "141"
		objfiles = "xstatconv@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 53 83 EC 04 8B 54 24 10 8B 5C 24 14 31 C0 B9 16 00 00 00 89 DF F3 AB 8B 02 89 03 C7 43 04 00 00 00 00 8B 42 04 89 43 0C 0F B7 42 08 89 43 10 0F B7 42 0A 89 43 14 0F B7 42 0C 89 43 18 0F B7 42 0E 89 43 1C 0F B7 42 10 89 43 20 C7 43 24 00 00 00 00 8B 42 14 89 43 2C 8B 42 18 89 43 30 8B 42 1C 89 43 34 8B 4A 20 8B 42 24 89 43 3C 89 4B 38 8B 4A 28 8B 42 2C 89 43 44 89 4B 40 8B 4A 30 8B 42 34 89 43 4C 89 4B 48 5A 5B 5F C3 }
	condition:
		$pattern
}

rule lockf_7b76ef6682cdc618299093ea1fdb4690 {
	meta:
		aliases = "__GI_lockf, lockf"
		type = "func"
		size = "204"
		objfiles = "lockf@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 53 83 EC 10 8B 5C 24 1C 8B 54 24 20 31 C0 89 E1 89 E7 AB AB AB AB 66 C7 44 24 02 01 00 C7 44 24 04 00 00 00 00 8B 44 24 24 89 44 24 08 83 FA 01 74 54 7F 06 85 D2 74 46 EB 66 83 FA 02 74 54 83 FA 03 75 5C 66 C7 04 24 00 00 51 6A 05 53 E8 ?? ?? ?? ?? 83 C4 0C 83 CA FF 85 C0 78 66 66 83 3C 24 02 74 5D 8B 5C 24 0C E8 ?? ?? ?? ?? 39 C3 74 50 E8 ?? ?? ?? ?? C7 00 0D 00 00 00 EB 2D 66 C7 04 24 02 00 EB 13 66 C7 04 24 01 00 BA 07 00 00 00 EB 1D 66 C7 04 24 01 00 BA 06 00 00 00 EB 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CA FF EB 13 89 E0 50 52 53 E8 ?? ?? ?? ?? 89 C2 83 C4 0C EB 02 31 D2 89 D0 83 C4 }
	condition:
		$pattern
}

rule pthread_kill_other_threads_np_106bf819f1184a994f013884441ec201 {
	meta:
		aliases = "__pthread_kill_other_threads_np, pthread_kill_other_threads_np"
		type = "func"
		size = "90"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 53 83 EC 18 6A 00 6A 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 8D 5C 24 0C 89 DF AB AB AB AB AB 6A 00 53 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 00 53 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 20 85 C0 7E 0C 6A 00 53 50 E8 ?? ?? ?? ?? 83 C4 0C 83 C4 18 5B 5F C3 }
	condition:
		$pattern
}

rule timegm_12cccdee6b81b208465bb3af047e8d0d {
	meta:
		aliases = "timegm"
		type = "func"
		size = "53"
		objfiles = "timegm@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 53 83 EC 34 31 C0 B9 0C 00 00 00 8D 5C 24 04 89 DF F3 AB 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 53 6A 01 FF 74 24 50 E8 ?? ?? ?? ?? 83 C4 48 5B 5F C3 }
	condition:
		$pattern
}

rule sigset_5e9f4450e85fa866dfec3a6617c53695 {
	meta:
		aliases = "sigset"
		type = "func"
		size = "186"
		objfiles = "sigset@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 53 83 EC 34 8B 5C 24 40 8B 54 24 44 83 FA FF 74 09 85 DB 7E 05 83 FB 40 7E 13 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CA FF E9 84 00 00 00 83 FA 02 75 2C C7 44 24 2C 00 00 00 00 C7 44 24 30 00 00 00 00 53 8D 5C 24 30 53 E8 ?? ?? ?? ?? 6A 00 53 6A 00 E8 ?? ?? ?? ?? BA 02 00 00 00 EB 50 31 C0 8D 4C 24 18 89 CF AB AB AB AB AB 89 54 24 18 8D 44 24 04 50 51 53 E8 ?? ?? ?? ?? 83 C4 0C 83 CA FF 85 C0 78 2C C7 44 24 2C 00 00 00 00 C7 44 24 30 00 00 00 00 53 8D 5C 24 30 53 E8 ?? ?? ?? ?? 6A 00 53 6A 01 E8 ?? ?? ?? ?? 8B 54 24 18 83 C4 14 89 D0 83 C4 34 5B 5F C3 }
	condition:
		$pattern
}

rule gethostid_d253d99b20cef197371d6915041e597f {
	meta:
		aliases = "gethostid"
		type = "func"
		size = "214"
		objfiles = "hostid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 53 83 EC 70 C7 44 24 6C 00 00 00 00 BA ?? ?? ?? ?? 31 C9 87 D3 B8 05 00 00 00 CD 80 87 D3 89 C7 3D 00 F0 FF FF 76 0B E8 ?? ?? ?? ?? F7 DF 89 38 EB 40 85 C0 78 3C 8D 4C 24 6C BA 04 00 00 00 53 89 C3 B8 03 00 00 00 CD 80 5B 89 C3 89 C2 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CA FF 89 F9 87 CB B8 06 00 00 00 CD 80 87 CB 85 D2 7F 59 6A 40 8D 5C 24 0B 53 E8 ?? ?? ?? ?? 5A 59 85 C0 78 47 80 7C 24 07 00 74 40 31 C0 B9 08 00 00 00 8D 54 24 48 89 D7 F3 AB 8D 44 24 68 50 52 6A 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 1C 8B 54 24 68 85 D2 74 0D 8B 42 14 8B 40 04 C1 C8 10 89 44 24 6C 52 E8 ?? }
	condition:
		$pattern
}

rule ether_hostton_fde9de7ee54db1bcb540be44c0194a9a {
	meta:
		aliases = "ether_hostton"
		type = "func"
		size = "122"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 81 EC 00 01 00 00 8B BC 24 10 01 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 5B 58 83 CB FF 85 F6 74 44 EB 23 8B 94 24 14 01 00 00 89 E0 E8 ?? ?? ?? ?? 85 C0 74 13 50 57 E8 ?? ?? ?? ?? 5A 59 85 C0 75 06 31 DB EB 18 89 E3 56 68 00 01 00 00 53 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 C8 83 CB FF 56 E8 ?? ?? ?? ?? 5E 89 D8 81 C4 00 01 00 00 5B 5E 5F C3 }
	condition:
		$pattern
}

rule logwtmp_c76dccbd3c07ff5195197962266d12ca {
	meta:
		aliases = "logwtmp"
		type = "func"
		size = "153"
		objfiles = "logwtmp@libutil.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 81 EC 80 01 00 00 8B B4 24 94 01 00 00 31 C0 B9 60 00 00 00 89 E7 F3 AB 85 F6 74 07 B0 07 80 3E 00 75 05 B8 08 00 00 00 66 89 04 24 E8 ?? ?? ?? ?? 89 44 24 04 6A 1F FF B4 24 94 01 00 00 8D 5C 24 08 8D 44 24 10 50 E8 ?? ?? ?? ?? 6A 1F 56 8D 44 24 40 50 E8 ?? ?? ?? ?? 68 FF 00 00 00 FF B4 24 B4 01 00 00 8D 44 24 6C 50 E8 ?? ?? ?? ?? 83 C4 24 6A 00 8D 84 24 58 01 00 00 50 E8 ?? ?? ?? ?? 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 C4 90 01 00 00 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pathconf_085c2de279541432b02cbd0fc53b8621 {
	meta:
		aliases = "pathconf"
		type = "func"
		size = "205"
		objfiles = "pathconf@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 81 EC 98 00 00 00 8B B4 24 A8 00 00 00 8B 84 24 AC 00 00 00 80 3E 00 75 10 E8 ?? ?? ?? ?? C7 00 02 00 00 00 E9 86 00 00 00 83 F8 13 77 11 FF 24 85 ?? ?? ?? ?? B8 20 00 00 00 E9 81 00 00 00 E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 63 B8 7F 00 00 00 EB 6D E8 ?? ?? ?? ?? 89 C3 8B 38 8D 44 24 58 50 56 E8 ?? ?? ?? ?? 5E 5A 85 C0 79 09 83 3B 26 75 3D 89 3B EB 32 8B 44 24 7C EB 44 31 C0 EB 40 89 E0 50 56 E8 ?? ?? ?? ?? 5A 59 85 C0 78 20 8B 44 24 10 25 00 F0 00 00 3D 00 80 00 00 74 1C 3D 00 60 00 00 75 09 EB 13 B8 FF 00 00 00 EB 11 83 C8 FF EB 0C B8 00 10 00 00 EB 05 B8 01 00 00 00 81 C4 98 00 00 }
	condition:
		$pattern
}

rule fpathconf_4c94ee0b3cda0ff2805103dbcf430180 {
	meta:
		aliases = "fpathconf"
		type = "func"
		size = "210"
		objfiles = "fpathconf@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 81 EC 98 00 00 00 8B B4 24 A8 00 00 00 8B 94 24 AC 00 00 00 85 F6 79 10 E8 ?? ?? ?? ?? C7 00 09 00 00 00 E9 8C 00 00 00 B8 7F 00 00 00 85 D2 0F 84 90 00 00 00 8D 42 FF 83 F8 12 77 0E FF 24 85 ?? ?? ?? ?? B8 20 00 00 00 EB 7A E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 5C E8 ?? ?? ?? ?? 89 C3 8B 38 8D 44 24 58 50 56 E8 ?? ?? ?? ?? 5E 5A 85 C0 79 09 83 3B 26 75 3D 89 3B EB 32 8B 44 24 7C EB 44 31 C0 EB 40 89 E0 50 56 E8 ?? ?? ?? ?? 5A 59 85 C0 78 20 8B 44 24 10 25 00 F0 00 00 3D 00 80 00 00 74 1C 3D 00 60 00 00 75 09 EB 13 B8 FF 00 00 00 EB 11 83 C8 FF EB 0C B8 00 10 00 00 EB 05 B8 01 00 00 00 }
	condition:
		$pattern
}

rule byte_alt_match_null_string_p_54638baf3d8ef63529ef2e9f4234744c {
	meta:
		aliases = "byte_alt_match_null_string_p"
		type = "func"
		size = "81"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 04 89 D3 89 CE EB 1C 80 39 0F 75 1C 8D 41 01 89 04 24 0F B6 51 01 0F BE 40 01 C1 E0 08 01 D0 8D 44 01 03 89 04 24 EB 13 89 F1 89 DA 89 E0 E8 ?? ?? ?? ?? 84 C0 75 04 31 C0 EB 0C 8B 0C 24 39 D9 72 C5 B8 01 00 00 00 59 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_reap_children_f48fdf93e30c1e935e845ee654a3e071 {
	meta:
		aliases = "pthread_reap_children"
		type = "func"
		size = "231"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 04 89 E7 E9 BD 00 00 00 8B 0D ?? ?? ?? ?? 8B 31 EB 6F 39 46 14 8B 16 75 66 8B 46 04 89 42 04 8B 46 04 89 10 8B 46 1C 31 D2 E8 ?? ?? ?? ?? C6 46 2E 01 83 BE 24 01 00 00 00 74 2B A1 ?? ?? ?? ?? 0B 86 28 01 00 00 F6 C4 08 74 1B C7 86 30 01 00 00 0C 00 00 00 89 B6 34 01 00 00 89 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 5E 2D FF 76 1C E8 ?? ?? ?? ?? 58 84 DB 74 0F 89 F0 E8 ?? ?? ?? ?? EB 06 89 D6 39 CE 75 8D 83 3D ?? ?? ?? ?? 00 74 12 A1 ?? ?? ?? ?? 8B 10 39 C2 75 07 89 D0 E8 ?? ?? ?? ?? 8B 0C 24 88 C8 83 E0 7F 40 D0 F8 84 C0 7E 16 83 E1 7F BA 01 00 00 00 89 C8 E8 ?? ?? ?? ?? 6A 00 E8 ?? ?? }
	condition:
		$pattern
}

rule __xstat32_conv_39a65a752314afbe8e023cdef2b49904 {
	meta:
		aliases = "__xstat32_conv"
		type = "func"
		size = "138"
		objfiles = "xstatconv@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 04 8B 5C 24 14 8B 74 24 18 31 C0 B9 16 00 00 00 89 F7 F3 AB 8B 03 8B 53 04 89 06 89 56 04 8B 43 58 89 46 0C 8B 43 10 89 46 10 8B 43 14 89 46 14 8B 43 18 89 46 18 8B 43 1C 89 46 1C 0F B7 43 20 89 46 20 C7 46 24 00 00 00 00 8B 43 2C 89 46 2C 8B 43 34 89 46 30 8B 43 38 89 46 34 8B 53 40 8B 43 44 89 46 3C 89 56 38 8B 53 48 8B 43 4C 89 46 44 89 56 40 8B 53 50 8B 43 54 89 46 4C 89 56 48 59 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __xstat64_conv_9f235f84f97af30831312325fc897ae1 {
	meta:
		aliases = "__xstat64_conv"
		type = "func"
		size = "163"
		objfiles = "xstatconv@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 04 8B 5C 24 14 8B 74 24 18 31 C0 B9 18 00 00 00 89 F7 F3 AB 8B 03 8B 53 04 89 06 89 56 04 8B 43 58 8B 53 5C 89 46 58 89 56 5C 8B 43 0C 89 46 0C 8B 43 10 89 46 10 8B 43 14 89 46 14 8B 43 18 89 46 18 8B 43 1C 89 46 1C 0F B7 43 20 89 46 20 C7 46 24 00 00 00 00 8B 43 2C 8B 53 30 89 46 2C 89 56 30 8B 43 34 89 46 34 8B 43 38 89 46 38 C7 46 3C 00 00 00 00 8B 53 40 8B 43 44 89 46 44 89 56 40 8B 53 48 8B 43 4C 89 46 4C 89 56 48 8B 53 50 8B 43 54 89 46 54 89 56 50 58 5B 5E 5F C3 }
	condition:
		$pattern
}

rule div_d123fbb4109543a12338cd635d11de8c {
	meta:
		aliases = "div"
		type = "func"
		size = "44"
		objfiles = "div@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 04 8B 74 24 14 8B 4C 24 18 8B 7C 24 1C 89 C8 99 F7 FF 89 FA 0F AF D0 29 D1 89 4E 04 89 06 89 F0 5A 5B 5E 5F C2 04 00 }
	condition:
		$pattern
}

rule _ppfs_init_258539d87a4b335e7dbf165f88c8f57c {
	meta:
		aliases = "_ppfs_init"
		type = "func"
		size = "103"
		objfiles = "_ppfs_init@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 04 8B 74 24 14 8B 5C 24 18 31 C0 B9 2F 00 00 00 89 F7 F3 AB FF 4E 18 89 1E 8D 46 28 BA 09 00 00 00 C7 00 08 00 00 00 83 C0 04 4A 75 F4 89 D8 EB 22 80 FA 25 75 1C 40 80 38 25 74 16 89 06 56 E8 ?? ?? ?? ?? 59 85 C0 79 05 83 C8 FF EB 0F 8B 06 EB 01 40 8A 10 84 D2 75 D8 89 1E 31 C0 5A 5B 5E 5F C3 }
	condition:
		$pattern
}

rule xdr_string_77f45c227253890d928cd47a6454b6ca {
	meta:
		aliases = "__GI_xdr_string, xdr_string"
		type = "func"
		size = "194"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 04 8B 74 24 14 8B 7C 24 18 8B 1F 8B 06 85 C0 74 0E 83 F8 02 75 1B 85 DB 75 0D E9 90 00 00 00 85 DB 0F 84 8F 00 00 00 53 E8 ?? ?? ?? ?? 5A 89 04 24 89 E0 50 56 E8 ?? ?? ?? ?? 5A 59 85 C0 74 76 8B 04 24 3B 44 24 1C 77 6D 8B 16 83 FA 01 74 09 72 3A 83 FA 02 75 5F EB 42 40 74 53 85 DB 75 25 50 E8 ?? ?? ?? ?? 89 C3 89 07 59 85 C0 75 16 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 5F 5A EB 33 8B 04 24 C6 04 03 00 FF 34 24 53 56 E8 ?? ?? ?? ?? 83 C4 0C EB 1D 53 E8 ?? ?? ?? ?? C7 07 00 00 00 00 B8 01 00 00 00 5E EB 09 B8 01 00 00 00 EB 02 31 C0 5B 5B 5E 5F C3 }
	condition:
		$pattern
}

rule tcgetsid_463119d628f4833172bcc6aee5499257 {
	meta:
		aliases = "tcgetsid"
		type = "func"
		size = "118"
		objfiles = "tcgetsid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 04 8B 7C 24 14 80 3D ?? ?? ?? ?? 00 75 2C E8 ?? ?? ?? ?? 89 C3 8B 30 89 E0 50 68 29 54 00 00 57 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 79 38 83 3B 16 75 38 C6 05 ?? ?? ?? ?? 01 89 33 57 E8 ?? ?? ?? ?? 5B 83 F8 FF 74 23 50 E8 ?? ?? ?? ?? 89 44 24 04 59 40 75 10 E8 ?? ?? ?? ?? 83 38 03 75 06 C7 00 19 00 00 00 8B 04 24 EB 03 83 C8 FF 5A 5B 5E 5F C3 }
	condition:
		$pattern
}

rule nprocessors_onln_7d7cd8be2f1115e937c6a52ec9187d2d {
	meta:
		aliases = "nprocessors_onln"
		type = "func"
		size = "196"
		objfiles = "sysconf@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 04 C7 04 24 00 00 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 5F 85 C0 74 4C 31 DB 89 E7 EB 2C 8B 04 24 8B 00 80 38 63 75 22 80 78 01 70 75 1C 80 78 02 75 75 16 0F B6 50 03 A1 ?? ?? ?? ?? 0F B7 04 50 83 E0 08 83 F8 01 83 DB FF 68 ?? ?? ?? ?? 68 02 01 00 00 57 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 BC EB 46 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 5B 31 DB 89 E7 85 C0 75 19 EB 2F 8B 04 24 FF 30 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A 59 83 F8 01 83 D3 00 68 ?? ?? ?? ?? 68 02 02 07 00 57 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 D1 56 E8 ?? ?? ?? ?? 59 85 DB 75 02 B3 01 89 D8 5A 5B 5E 5F C3 }
	condition:
		$pattern
}

rule setusershell_8e26db7c0e11808d828a73b5643c7e06 {
	meta:
		aliases = "setusershell"
		type = "func"
		size = "168"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 04 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 5E 85 C0 75 0C C7 05 ?? ?? ?? ?? ?? ?? ?? ?? EB 78 C7 04 24 00 00 00 00 31 F6 89 E7 EB 44 8D 1C B5 00 00 00 00 8D 43 08 50 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 8D 1C 18 89 1D ?? ?? ?? ?? 46 8B 44 24 08 FF 30 E8 ?? ?? ?? ?? 89 03 8D 43 04 A3 ?? ?? ?? ?? C7 43 04 00 00 00 00 83 C4 0C 68 ?? ?? ?? ?? 68 01 01 07 00 57 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 9F A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 5B 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __pthread_acquire_46143ddcdbffbe911cd5555686e4f2c4 {
	meta:
		aliases = "__pthread_acquire"
		type = "func"
		size = "71"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 08 89 C3 31 F6 89 E7 EB 28 83 FE 31 7F 08 E8 ?? ?? ?? ?? 46 EB 1B C7 04 24 00 00 00 00 C7 44 24 04 81 84 1E 00 6A 00 57 E8 ?? ?? ?? ?? 31 F6 58 5A B8 01 00 00 00 87 03 85 C0 75 CD 5A 59 5B 5E 5F C3 }
	condition:
		$pattern
}

rule dlsym_2ae1b385aff19350576ee5d2a2df254a {
	meta:
		aliases = "dlsym"
		type = "func"
		size = "176"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 08 8B 4C 24 18 C7 04 24 00 00 00 00 C7 44 24 04 00 00 00 00 85 C9 75 08 8B 15 ?? ?? ?? ?? EB 58 89 CA 83 F9 FF 74 26 3B 0D ?? ?? ?? ?? 74 49 A1 ?? ?? ?? ?? EB 07 39 C8 74 3E 8B 40 04 85 C0 75 F5 C7 05 ?? ?? ?? ?? 0A 00 00 00 EB 58 8B 7C 24 14 A1 ?? ?? ?? ?? 31 F6 EB 1A 8B 18 8B 4B 14 39 F9 73 0E 85 F6 74 05 39 4E 14 73 05 8B 50 10 89 DE 8B 40 10 85 C0 75 E2 31 C9 3B 15 ?? ?? ?? ?? 75 02 8B 0A 89 E0 50 6A 00 51 52 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 14 85 C0 75 0A C7 05 ?? ?? ?? ?? 0B 00 00 00 5A 59 5B 5E 5F C3 }
	condition:
		$pattern
}

rule setkey_42d9007a48dad6315231918849271218 {
	meta:
		aliases = "setkey"
		type = "func"
		size = "65"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 08 8B 5C 24 18 89 E7 31 F6 EB 1F 8D 14 37 C6 02 00 31 C9 EB 0F F6 03 01 74 08 8A 81 ?? ?? ?? ?? 08 02 43 41 83 F9 07 7E EC 46 83 FE 07 7E DC 89 F8 E8 ?? ?? ?? ?? 59 5B 5B 5E 5F C3 }
	condition:
		$pattern
}

rule readtcp_600545a9805f6b5748e6aae4cb3b79dd {
	meta:
		aliases = "readtcp"
		type = "func"
		size = "120"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 08 8B 7C 24 18 8B 1F 89 E6 89 1C 24 66 C7 44 24 04 01 00 68 B8 88 00 00 6A 01 56 E8 ?? ?? ?? ?? 83 C4 0C 83 F8 FF 74 06 85 C0 74 35 EB 0A E8 ?? ?? ?? ?? 83 38 04 EB 0B 0F BF 44 24 06 A8 18 75 20 A8 20 75 1C F6 44 24 06 01 74 BD FF 74 24 20 FF 74 24 20 53 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 7F 0C 8B 47 2C C7 00 00 00 00 00 83 C8 FF 5B 5E 5B 5E 5F C3 }
	condition:
		$pattern
}

rule ptrace_e8d93d2a5591cc3b3e516f954d5b7d60 {
	meta:
		aliases = "ptrace"
		type = "func"
		size = "113"
		objfiles = "ptrace@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 08 8B 7C 24 18 8B 5C 24 1C 8B 54 24 20 8D 44 24 28 89 04 24 8B 74 24 24 8D 47 FF 83 F8 02 77 04 8D 74 24 04 89 F8 89 D9 53 89 C3 B8 1A 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF EB 1C 85 C0 78 18 85 FF 74 14 83 FF 03 77 0F E8 ?? ?? ?? ?? C7 00 00 00 00 00 8B 44 24 04 5A 59 5B 5E 5F C3 }
	condition:
		$pattern
}

rule encrypt_b96ce333c1d29803beb1126b5294872f {
	meta:
		aliases = "encrypt"
		type = "func"
		size = "149"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 08 8B 7C 24 18 E8 ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? 89 F9 31 DB EB 22 C7 04 9C 00 00 00 00 31 D2 EB 11 F6 01 01 74 0A 8B 04 95 ?? ?? ?? ?? 09 04 9C 41 42 83 FA 1F 7E EA 43 83 FB 01 7E D9 83 7C 24 1C 01 19 DB 83 E3 02 4B 89 E1 8B 54 24 04 8B 04 24 53 8D 5C 24 08 53 E8 ?? ?? ?? ?? 31 DB 59 5E EB 19 89 CA 09 F2 8B 04 9C 85 04 8D ?? ?? ?? ?? 0F 95 04 17 41 83 F9 1F 7E E8 43 83 FB 01 7F 09 31 C9 89 DE C1 E6 05 EB D9 58 5A 5B 5E 5F C3 }
	condition:
		$pattern
}

rule lseek64_205810a655cfee9b1a5deaa827939798 {
	meta:
		aliases = "__GI_lseek64, __libc_lseek64, lseek64"
		type = "func"
		size = "89"
		objfiles = "llseek@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 08 8B 7C 24 24 8B 4C 24 1C 8B 5C 24 20 89 D9 89 CB C1 FB 1F 89 E6 8B 44 24 18 8B 54 24 1C 53 89 C3 B8 8C 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF EB 04 85 C0 74 03 99 EB 07 8B 04 24 8B 54 24 04 59 5B 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __old_sem_post_1acaf5625257a3a21076fdab94d12b17 {
	meta:
		aliases = "__old_sem_post"
		type = "func"
		size = "162"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 0C 8B 4C 24 1C 8B 11 89 D7 83 E7 01 75 07 BE 03 00 00 00 EB 1B 81 FA FF FF FF 7F 75 10 E8 ?? ?? ?? ?? C7 00 22 00 00 00 83 C8 FF EB 69 8D 72 02 89 D0 F0 0F B1 31 0F 94 C3 84 DB 74 C8 85 FF 75 53 89 D1 C7 44 24 08 00 00 00 00 8D 7C 24 08 EB 1F 8B 71 08 89 FB EB 03 8D 5A 08 8B 13 85 D2 74 08 8B 41 18 3B 42 18 7C EF 89 51 08 89 0B 89 F1 83 F9 01 75 DC EB 15 8B 42 08 89 44 24 08 C7 42 08 00 00 00 00 52 E8 ?? ?? ?? ?? 59 8B 54 24 08 85 D2 75 E3 31 C0 83 C4 0C 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_rwlock_rdlock_a835988c55bf142f770ddc5235000280 {
	meta:
		aliases = "pthread_rwlock_rdlock"
		type = "func"
		size = "163"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 0C 8B 5C 24 1C C7 44 24 08 00 00 00 00 8D 4C 24 04 8D 44 24 08 89 E2 52 89 DA E8 ?? ?? ?? ?? 89 C6 58 8D 7B 10 83 7C 24 08 00 75 09 E8 ?? ?? ?? ?? 89 44 24 08 8B 54 24 08 89 D8 E8 ?? ?? ?? ?? 89 F2 89 D8 E8 ?? ?? ?? ?? 85 C0 75 1D 8B 54 24 08 89 F8 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8B 44 24 0C E8 ?? ?? ?? ?? 58 EB BB FF 43 08 53 E8 ?? ?? ?? ?? 59 85 F6 75 06 83 3C 24 00 74 17 8B 44 24 04 85 C0 74 05 FF 40 08 EB 0A 8B 44 24 08 FF 80 50 01 00 00 31 C0 83 C4 0C 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_rwlock_tryrdlock_2a44d94c844c7f48af62f7ad7cb3bfd3 {
	meta:
		aliases = "pthread_rwlock_tryrdlock"
		type = "func"
		size = "128"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 0C 8B 5C 24 1C E8 ?? ?? ?? ?? 89 44 24 08 8D 4C 24 04 8D 44 24 08 89 E2 52 89 DA E8 ?? ?? ?? ?? 89 C7 8B 54 24 0C 89 D8 E8 ?? ?? ?? ?? 31 D2 89 D8 E8 ?? ?? ?? ?? 5A BE 10 00 00 00 85 C0 74 06 FF 43 08 66 31 F6 53 E8 ?? ?? ?? ?? 58 85 F6 75 21 85 FF 75 06 83 3C 24 00 74 17 8B 44 24 04 85 C0 74 05 FF 40 08 EB 0A 8B 44 24 08 FF 80 50 01 00 00 89 F0 83 C4 0C 5B 5E 5F C3 }
	condition:
		$pattern
}

rule puts_08714d0c9ff6428e1bf1dbc17d039f13 {
	meta:
		aliases = "puts"
		type = "func"
		size = "119"
		objfiles = "puts@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 35 ?? ?? ?? ?? 83 7E 34 00 0F 94 C0 0F B6 F8 85 FF 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 56 FF 74 24 24 E8 ?? ?? ?? ?? 89 C3 58 5A 83 FB FF 74 13 56 6A 0A E8 ?? ?? ?? ?? 59 5E 40 75 05 83 CB FF EB 01 43 85 FF 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule calloc_21d0e643dbcd495f99e9354f6fd22dff {
	meta:
		aliases = "calloc"
		type = "func"
		size = "235"
		objfiles = "calloc@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 54 24 20 8B 4C 24 24 89 CB 0F AF DA 85 D2 74 1E 89 D8 89 D7 31 D2 F7 F7 39 C1 74 12 E8 ?? ?? ?? ?? C7 00 0C 00 00 00 31 DB E9 AD 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 89 C3 83 C4 14 85 C0 74 72 8B 40 FC A8 02 75 6B 83 E0 FC 8D 50 FC 89 D0 C1 E8 02 83 F8 09 76 0E 52 6A 00 53 E8 ?? ?? ?? ?? 83 C4 0C EB 4D C7 03 00 00 00 00 C7 43 04 00 00 00 00 C7 43 08 00 00 00 00 83 F8 04 76 34 C7 43 0C 00 00 00 00 C7 43 10 00 00 00 00 83 F8 06 76 21 C7 43 14 00 00 00 00 C7 43 18 00 00 00 00 83 F8 09 75 0E C7 43 }
	condition:
		$pattern
}

rule localtime_r_5c7b0a30adfe1f970fc45a8963105aad {
	meta:
		aliases = "__GI_localtime_r, localtime_r"
		type = "func"
		size = "93"
		objfiles = "localtime_r@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 5C 24 20 8B 7C 24 24 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 74 24 08 56 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 81 3B FF 4E 98 45 0F 9E C0 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 53 E8 ?? ?? ?? ?? 83 C4 20 6A 01 56 E8 ?? ?? ?? ?? 89 F8 83 C4 18 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __des_crypt_4508abaa9ea35912170902ab883c1789 {
	meta:
		aliases = "__des_crypt"
		type = "func"
		size = "384"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 5C 24 20 8B 7C 24 24 E8 ?? ?? ?? ?? 89 E2 89 E1 EB 0E 8A 03 01 C0 88 02 42 80 7A FF 01 83 DB FF 89 D0 29 C8 83 F8 08 75 E9 89 E0 E8 ?? ?? ?? ?? 8A 57 01 0F B6 37 89 F0 A2 ?? ?? ?? ?? 8A 47 01 84 C0 75 02 89 F0 A2 ?? ?? ?? ?? 0F B6 C2 E8 ?? ?? ?? ?? 89 C3 C1 E3 06 89 F2 0F B6 C2 E8 ?? ?? ?? ?? 09 C3 89 D8 E8 ?? ?? ?? ?? 8D 4C 24 0C 6A 19 8D 44 24 0C 50 31 D2 31 C0 E8 ?? ?? ?? ?? 5F 5A 31 D2 85 C0 0F 85 E5 00 00 00 8B 4C 24 0C 89 CA C1 EA 08 89 C8 C1 E8 1A 8A 80 ?? ?? ?? ?? A2 ?? ?? ?? ?? 89 C8 C1 E8 14 83 E0 3F 8A 80 ?? ?? ?? ?? A2 ?? ?? ?? ?? 89 C8 C1 E8 0E 83 E0 3F 8A 80 }
	condition:
		$pattern
}

rule rewinddir_5b5b3df76151a016423129e9201169fa {
	meta:
		aliases = "rewinddir"
		type = "func"
		size = "82"
		objfiles = "rewinddir@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 5C 24 20 8D 73 18 56 68 ?? ?? ?? ?? 8D 7C 24 08 57 E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 6A 00 6A 00 FF 33 E8 ?? ?? ?? ?? C7 43 08 00 00 00 00 C7 43 04 00 00 00 00 C7 43 10 00 00 00 00 6A 01 57 E8 ?? ?? ?? ?? 83 C4 34 5B 5E 5F C3 }
	condition:
		$pattern
}

rule seekdir_aa97e0a3a1934e3fce0afe2f06f7ba68 {
	meta:
		aliases = "seekdir"
		type = "func"
		size = "80"
		objfiles = "seekdir@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 5C 24 20 8D 73 18 56 68 ?? ?? ?? ?? 8D 7C 24 08 57 E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 6A 00 FF 74 24 38 FF 33 E8 ?? ?? ?? ?? 89 43 10 C7 43 04 00 00 00 00 C7 43 08 00 00 00 00 6A 01 57 E8 ?? ?? ?? ?? 83 C4 34 5B 5E 5F C3 }
	condition:
		$pattern
}

rule vfwprintf_ae36769e02c39fcbe7bcfdabeb553a85 {
	meta:
		aliases = "__GI_vfwprintf, vfwprintf"
		type = "func"
		size = "133"
		objfiles = "vfwprintf@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 83 7E 34 00 0F 94 C0 0F B6 F8 85 FF 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 0F B7 06 25 40 08 00 00 3D 40 08 00 00 74 14 68 00 08 00 00 56 E8 ?? ?? ?? ?? 59 5B 83 CB FF 85 C0 75 13 FF 74 24 28 FF 74 24 28 56 E8 ?? ?? ?? ?? 89 C3 83 C4 0C 85 FF 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule vfprintf_e596a54f7e8a74fcff96a713d3fd1d7c {
	meta:
		aliases = "__GI_vfprintf, vfprintf"
		type = "func"
		size = "133"
		objfiles = "vfprintf@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 83 7E 34 00 0F 94 C0 0F B6 F8 85 FF 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 0F B7 06 25 C0 00 00 00 3D C0 00 00 00 74 14 68 80 00 00 00 56 E8 ?? ?? ?? ?? 59 5B 83 CB FF 85 C0 75 13 FF 74 24 28 FF 74 24 28 56 E8 ?? ?? ?? ?? 89 C3 83 C4 0C 85 FF 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule getwc_4ad83eeaa60553f98b832d8b316ee87f {
	meta:
		aliases = "__GI_fgetwc, __GI_fileno, fgetwc, fileno, getwc"
		type = "func"
		size = "88"
		objfiles = "fgetwc@libc.a, fileno@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 83 7E 34 00 0F 94 C0 0F B6 F8 85 FF 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 56 E8 ?? ?? ?? ?? 89 C3 59 85 FF 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule clearerr_255c80466cf9780681f73f82238e184d {
	meta:
		aliases = "clearerr"
		type = "func"
		size = "81"
		objfiles = "clearerr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 83 7E 34 00 0F 94 C0 0F B6 F8 85 FF 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 66 83 26 F3 85 FF 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule rewind_b3b64a9ac4c12b1df60e8532c2dd5150 {
	meta:
		aliases = "__GI_rewind, rewind"
		type = "func"
		size = "94"
		objfiles = "rewind@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 83 7E 34 00 0F 94 C0 0F B6 F8 85 FF 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 66 83 26 F7 6A 00 6A 00 56 E8 ?? ?? ?? ?? 83 C4 0C 85 FF 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule feof_4878801c08d9eb3131c51638f2971a7e {
	meta:
		aliases = "feof"
		type = "func"
		size = "84"
		objfiles = "feof@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 83 7E 34 00 0F 94 C0 0F B6 F8 85 FF 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 8B 1E 85 FF 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 D8 83 E0 04 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule ferror_ad7026dae6848939a484dce637103ce2 {
	meta:
		aliases = "ferror"
		type = "func"
		size = "84"
		objfiles = "ferror@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 83 7E 34 00 0F 94 C0 0F B6 F8 85 FF 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 8B 1E 85 FF 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 D8 83 E0 08 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule fflush_fe8671fcff3560954886f3b3711f00c9 {
	meta:
		aliases = "__GI_fflush, fflush"
		type = "func"
		size = "111"
		objfiles = "fflush@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 85 F6 74 4F 81 FE ?? ?? ?? ?? 74 47 83 7E 34 00 0F 94 C0 0F B6 F8 85 FF 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 56 E8 ?? ?? ?? ?? 89 C3 5E 85 FF 74 19 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 5A 59 EB 09 56 E8 ?? ?? ?? ?? 89 C3 58 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule gets_ef4b626c344dd66d79a3e2359e61e6fd {
	meta:
		aliases = "gets"
		type = "func"
		size = "127"
		objfiles = "gets@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 8B 15 ?? ?? ?? ?? 83 7A 34 00 0F 94 C0 0F B6 F8 85 FF 75 04 89 F3 EB 27 8D 42 38 50 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C0 38 50 E8 ?? ?? ?? ?? 83 C4 10 EB D6 43 E8 ?? ?? ?? ?? 83 F8 FF 74 0A 88 03 3C 0A 75 EF 39 DE 75 04 31 F6 EB 03 C6 03 00 85 FF 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 F0 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __pthread_alt_lock_514219b0bcd1b864e00829983cbd7cc0 {
	meta:
		aliases = "__pthread_alt_lock"
		type = "func"
		size = "89"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 8B 54 24 24 8D 7C 24 04 8B 1E B9 01 00 00 00 85 DB 74 11 85 D2 75 07 E8 ?? ?? ?? ?? 89 C2 89 54 24 08 89 F9 C7 44 24 0C 00 00 00 00 89 5C 24 04 89 D8 F0 0F B1 0E 0F 94 C1 84 C9 74 CB 85 DB 74 07 89 D0 E8 ?? ?? ?? ?? 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule putwc_2addd2dd28334c1098b0e5698a927b1e {
	meta:
		aliases = "__GI_fputs, __GI_fputws, fputs, fputwc, fputws, putwc"
		type = "func"
		size = "93"
		objfiles = "fputwc@libc.a, fputws@libc.a, fputs@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 24 83 7E 34 00 0F 94 C0 0F B6 F8 85 FF 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 56 FF 74 24 24 E8 ?? ?? ?? ?? 89 C3 59 5E 85 FF 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule fgetws_d10e34421d17195167bce077ef9a47f4 {
	meta:
		aliases = "__GI_fgets, fgets, fgetws"
		type = "func"
		size = "98"
		objfiles = "fgetws@libc.a, fgets@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 28 83 7E 34 00 0F 94 C0 0F B6 F8 85 FF 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 56 FF 74 24 28 FF 74 24 28 E8 ?? ?? ?? ?? 89 C3 83 C4 0C 85 FF 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule fwrite_c9c2a2239634423bb8634a5ba2d35183 {
	meta:
		aliases = "__GI_fread, __GI_fwrite, fread, fwrite"
		type = "func"
		size = "102"
		objfiles = "fread@libc.a, fwrite@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 2C 83 7E 34 00 0F 94 C0 0F B6 F8 85 FF 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 56 FF 74 24 2C FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 FF 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule closedir_d1f4d87f6ac77564842c6a6d983c3bc5 {
	meta:
		aliases = "__GI_closedir, closedir"
		type = "func"
		size = "128"
		objfiles = "closedir@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 7C 24 20 83 3F FF 75 0D E8 ?? ?? ?? ?? C7 00 09 00 00 00 EB 5A 8D 5F 18 53 68 ?? ?? ?? ?? 8D 74 24 08 56 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8B 1F C7 07 FF FF FF FF 6A 01 56 E8 ?? ?? ?? ?? FF 77 0C E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 89 D9 87 CB B8 06 00 00 00 CD 80 87 CB 89 C3 83 C4 20 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule putchar_a17b923a75a439c693da3afba2910afc {
	meta:
		aliases = "putchar"
		type = "func"
		size = "137"
		objfiles = "putchar@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 7C 24 20 8B 35 ?? ?? ?? ?? 83 7E 34 00 74 20 8B 46 10 3B 46 1C 73 0D 89 FA 88 10 0F B6 DA 40 89 46 10 EB 55 56 57 E8 ?? ?? ?? ?? 89 C3 EB 48 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8B 46 10 83 C4 10 3B 46 1C 73 0D 89 FA 88 10 0F B6 DA 40 89 46 10 EB 0B 56 57 E8 ?? ?? ?? ?? 89 C3 59 5E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule putc_616f35da021ce09db47b602dae5f627e {
	meta:
		aliases = "__GI_fputc, __GI_putc, fputc, putc"
		type = "func"
		size = "135"
		objfiles = "fputc@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 7C 24 20 8B 74 24 24 83 7E 34 00 74 20 8B 46 10 3B 46 1C 73 0D 89 FA 88 10 0F B6 DA 40 89 46 10 EB 55 56 57 E8 ?? ?? ?? ?? 89 C3 EB 48 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8B 46 10 83 C4 10 3B 46 1C 73 0D 89 FA 88 10 0F B6 DA 40 89 46 10 EB 0B 56 57 E8 ?? ?? ?? ?? 89 C3 59 5E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule getspent_r_7ee86d6829de12dd3af398a00bb65158 {
	meta:
		aliases = "__GI_getgrent_r, __GI_getpwent_r, __GI_getspent_r, getgrent_r, getpwent_r, getspent_r"
		type = "func"
		size = "161"
		objfiles = "getgrent_r@libc.a, getpwent_r@libc.a, getspent_r@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 7C 24 20 8B 74 24 2C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 06 00 00 00 00 83 C4 10 83 3D ?? ?? ?? ?? 00 75 2A 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 5A 59 85 C0 75 09 E8 ?? ?? ?? ?? 8B 18 EB 2B C7 40 34 01 00 00 00 FF 35 ?? ?? ?? ?? FF 74 24 2C FF 74 24 2C 57 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 83 C4 14 85 C0 75 02 89 3E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 89 D8 83 C4 18 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __dl_iterate_phdr_a088f63c6878d7d08c100c8b8920ddcf {
	meta:
		aliases = "__GI___dl_iterate_phdr, __dl_iterate_phdr"
		type = "func"
		size = "84"
		objfiles = "dl_iterate_phdr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 7C 24 24 8B 1D ?? ?? ?? ?? 31 C0 89 E6 EB 33 8B 03 89 04 24 8B 43 04 89 44 24 04 8B 83 D0 00 00 00 89 44 24 08 8B 83 CC 00 00 00 66 89 44 24 0C 57 6A 10 56 FF 54 24 2C 83 C4 0C 85 C0 75 07 8B 5B 0C 85 DB 75 C9 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule round_75f6e08d8d1bdff54aa7dccc2c14e7f8 {
	meta:
		aliases = "__GI_round, round"
		type = "func"
		size = "288"
		objfiles = "s_round@libm.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 C7 04 24 00 00 00 00 C7 44 24 04 00 00 00 00 DD 44 24 20 DD 54 24 08 8B 74 24 0C 8B 54 24 08 89 F0 C1 F8 14 25 FF 07 00 00 8D 98 01 FC FF FF 83 FB 13 7F 75 85 DB 79 31 DD 05 ?? ?? ?? ?? DE C1 D9 EE D9 C9 DA E9 DF E0 9E 0F 86 B2 00 00 00 81 E6 00 00 00 80 31 D2 43 0F 85 A3 00 00 00 81 CE 00 00 F0 3F E9 98 00 00 00 DD D8 BF FF FF 0F 00 88 D9 D3 FF 89 F8 21 F0 09 D0 0F 84 8F 00 00 00 DD 44 24 20 DC 05 ?? ?? ?? ?? D9 EE D9 C9 DA E9 DF E0 9E 76 6C 89 FA F7 D2 B8 00 00 08 00 D3 F8 8D 34 30 21 D6 31 D2 EB 58 DD D8 83 FB 33 7E 10 81 FB 00 04 00 00 75 57 DD 44 24 20 D8 C0 EB 4B 8D 88 }
	condition:
		$pattern
}

rule pclose_5517927795cc0a26b8d4658427d9ad8c {
	meta:
		aliases = "pclose"
		type = "func"
		size = "178"
		objfiles = "popen@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 14 8B 7C 24 24 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 83 C4 10 85 DB 74 2C 39 7B 04 75 09 8B 03 A3 ?? ?? ?? ?? EB 1E 89 DA 8B 1B 85 DB 75 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 09 39 7B 04 75 E6 8B 03 89 02 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 59 5E 85 DB 74 35 8B 73 08 53 E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 58 5A 8D 5C 24 10 6A 00 53 56 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 78 06 8B 44 24 10 EB 0D E8 ?? ?? ?? ?? 83 38 04 74 E0 83 C8 FF 83 C4 14 5B 5E 5F C3 }
	condition:
		$pattern
}

rule marshal_new_auth_3af7c0df8f1e18afeb9d9dba2ffec217 {
	meta:
		aliases = "marshal_new_auth"
		type = "func"
		size = "118"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 18 89 C3 8B 78 24 6A 00 68 90 01 00 00 8D 47 1C 50 8D 74 24 0C 56 E8 ?? ?? ?? ?? 53 56 E8 ?? ?? ?? ?? 83 C4 18 85 C0 74 10 8D 43 0C 50 56 E8 ?? ?? ?? ?? 5A 59 85 C0 75 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 0E 56 8B 44 24 08 FF 50 10 89 87 AC 01 00 00 5F 8B 44 24 04 8B 50 1C 85 D2 74 06 89 E0 50 FF D2 5E B8 01 00 00 00 83 C4 18 5B 5E 5F C3 }
	condition:
		$pattern
}

rule fd_to_DIR_2bc5c2dd5e8a8fcc03178a819803a002 {
	meta:
		aliases = "fd_to_DIR"
		type = "func"
		size = "136"
		objfiles = "opendir@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 18 89 C7 89 D3 6A 30 E8 ?? ?? ?? ?? 5E 31 F6 85 C0 74 67 89 C6 89 38 C7 40 10 00 00 00 00 C7 40 08 00 00 00 00 C7 40 04 00 00 00 00 89 58 14 81 FB FF 01 00 00 77 07 C7 40 14 00 02 00 00 FF 76 14 6A 01 E8 ?? ?? ?? ?? 89 46 0C 5A 59 85 C0 75 0B 56 E8 ?? ?? ?? ?? 31 F6 58 EB 1E 89 E3 6A 18 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8D 46 18 6A 18 53 50 E8 ?? ?? ?? ?? 83 C4 18 89 F0 83 C4 18 5B 5E 5F C3 }
	condition:
		$pattern
}

rule ftello64_e0cb90bef7249129641678e05ea255b6 {
	meta:
		aliases = "__GI_ftello64, ftello64"
		type = "func"
		size = "169"
		objfiles = "ftello64@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 18 8B 74 24 28 C7 44 24 10 00 00 00 00 C7 44 24 14 00 00 00 00 83 7E 34 00 0F 94 C0 0F B6 F8 85 FF 74 1C 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 0F B7 06 25 40 04 00 00 3D 40 04 00 00 0F 94 C0 0F B6 C0 40 50 8D 5C 24 14 53 56 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 78 0D 53 56 E8 ?? ?? ?? ?? 59 5B 85 C0 79 10 C7 44 24 10 FF FF FF FF C7 44 24 14 FF FF FF FF 85 FF 74 0E 6A 01 8D 44 24 04 50 E8 ?? ?? ?? ?? 58 5A 8B 44 24 10 8B 54 24 14 83 C4 18 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pmap_getport_20b24a7768ac42471fb589f801c3bcb1 {
	meta:
		aliases = "__GI_pmap_getport, pmap_getport"
		type = "func"
		size = "224"
		objfiles = "pm_getport@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 18 8B 7C 24 28 66 C7 44 24 16 00 00 C7 44 24 10 FF FF FF FF 66 C7 47 02 00 6F 68 90 01 00 00 68 90 01 00 00 8D 44 24 18 50 FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 6A 02 68 A0 86 01 00 57 E8 ?? ?? ?? ?? 89 C3 83 C4 20 85 C0 74 7E E8 ?? ?? ?? ?? 89 C6 8B 44 24 2C 89 04 24 8B 44 24 30 89 44 24 04 8B 44 24 34 89 44 24 08 C7 44 24 0C 00 00 00 00 8D 44 24 16 89 E2 8B 4B 04 FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? 6A 03 53 FF 11 83 C4 20 85 C0 74 15 C7 06 0E 00 00 00 8B 53 04 8D 46 04 50 53 FF 52 08 5A 59 EB 0E 66 83 7C 24 16 00 75 06 C7 06 0F 00 00 00 8B 43 }
	condition:
		$pattern
}

rule authnone_create_148e20ea4579f60f9a702b6c8f08ac5a {
	meta:
		aliases = "__GI_authnone_create, authnone_create"
		type = "func"
		size = "161"
		objfiles = "auth_none@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 18 E8 ?? ?? ?? ?? 89 C3 8B B0 98 00 00 00 85 F6 75 19 6A 40 6A 01 E8 ?? ?? ?? ?? 5A 59 31 D2 85 C0 74 70 89 C6 89 83 98 00 00 00 83 7E 3C 00 75 60 8D 5E 0C 6A 0C 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 6A 0C 53 56 E8 ?? ?? ?? ?? C7 46 20 ?? ?? ?? ?? 6A 00 6A 14 8D 46 28 50 8D 7C 24 24 57 E8 ?? ?? ?? ?? 83 C4 28 56 57 E8 ?? ?? ?? ?? 53 57 E8 ?? ?? ?? ?? 57 8B 44 24 18 FF 50 10 89 46 3C 8B 44 24 18 8B 40 1C 83 C4 14 85 C0 74 04 57 FF D0 58 89 F2 89 D0 83 C4 18 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_detach_802b85314afd2d58d0e2317354d8c693 {
	meta:
		aliases = "pthread_detach"
		type = "func"
		size = "184"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 1C 8B 7C 24 2C 89 F8 25 FF 03 00 00 C1 E0 04 8D B0 ?? ?? ?? ?? 31 D2 89 F0 E8 ?? ?? ?? ?? 8B 46 08 85 C0 74 05 39 78 10 74 0D 56 E8 ?? ?? ?? ?? B8 03 00 00 00 EB 21 80 78 2D 00 74 0D 56 E8 ?? ?? ?? ?? B8 16 00 00 00 EB 0E 83 78 38 00 74 0B 56 E8 ?? ?? ?? ?? 31 C0 5B EB 51 C6 40 2D 01 8A 58 2C 56 E8 ?? ?? ?? ?? 59 84 DB 74 3D 83 3D ?? ?? ?? ?? 00 78 34 E8 ?? ?? ?? ?? 89 04 24 C7 44 24 04 01 00 00 00 89 7C 24 08 89 E3 6A 1C 53 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 40 75 0A E8 ?? ?? ?? ?? 83 38 04 74 E2 31 C0 83 C4 1C 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pmap_rmtcall_92307b5cdf63cf1077f34101e73f80d3 {
	meta:
		aliases = "pmap_rmtcall"
		type = "func"
		size = "193"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 2C 8B 7C 24 3C C7 44 24 28 FF FF FF FF 66 C7 47 02 00 6F 8D 44 24 28 50 FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 6A 02 68 A0 86 01 00 57 E8 ?? ?? ?? ?? 89 C3 83 C4 18 BE 10 00 00 00 85 C0 74 6E 8B 44 24 40 89 04 24 8B 44 24 44 89 44 24 04 8B 44 24 48 89 44 24 08 8B 44 24 50 89 44 24 10 8B 44 24 4C 89 44 24 14 8B 44 24 64 89 44 24 18 8B 44 24 58 89 44 24 20 8B 44 24 54 89 44 24 24 8D 44 24 18 89 E2 8B 4B 04 FF 74 24 60 FF 74 24 60 50 68 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? 6A 05 53 FF 11 89 C6 83 C4 20 8B 43 04 53 FF 50 10 5B 66 C7 47 02 00 00 89 F0 83 C4 2C 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __res_query_59c1e0dbc797fb0f545c259d9d1225e2 {
	meta:
		aliases = "__GI___res_query, __res_query"
		type = "func"
		size = "169"
		objfiles = "res_query@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 30 8B 54 24 40 8B 5C 24 48 85 D2 74 07 83 7C 24 44 01 74 10 E8 ?? ?? ?? ?? C7 00 03 00 00 00 83 CF FF EB 77 C7 44 24 2C 00 00 00 00 31 C0 B9 0A 00 00 00 8D 74 24 04 89 F7 F3 AB 56 8D 44 24 30 50 53 52 E8 ?? ?? ?? ?? 89 C7 83 C4 10 85 C0 79 15 E8 ?? ?? ?? ?? 83 CF FF 83 38 00 75 3D C7 00 02 00 00 00 EB 35 FF 74 24 04 E8 ?? ?? ?? ?? 5A 39 5C 24 08 75 1B 3B 7C 24 50 7E 04 8B 7C 24 50 57 FF 74 24 30 FF 74 24 54 E8 ?? ?? ?? ?? 83 C4 0C FF 74 24 2C E8 ?? ?? ?? ?? 58 89 F8 83 C4 30 5B 5E 5F C3 }
	condition:
		$pattern
}

rule readunix_8d3968a972829a6d96b39dc01ab310ed {
	meta:
		aliases = "readunix"
		type = "func"
		size = "265"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 30 8B 7C 24 40 8B 1F 8D 74 24 24 89 5C 24 24 66 C7 44 24 28 01 00 68 B8 88 00 00 6A 01 56 E8 ?? ?? ?? ?? 83 C4 0C 83 F8 FF 74 0A 85 C0 0F 84 BE 00 00 00 EB 0A E8 ?? ?? ?? ?? 83 38 04 EB 0F 0F BF 44 24 2A A8 18 0F 85 A5 00 00 00 A8 20 0F 85 9D 00 00 00 F6 44 24 2A 01 74 B0 8B 44 24 44 89 44 24 1C 8B 44 24 48 89 44 24 20 8D 44 24 1C 89 44 24 08 C7 44 24 0C 01 00 00 00 C7 04 24 00 00 00 00 C7 44 24 04 00 00 00 00 C7 44 24 10 ?? ?? ?? ?? C7 44 24 14 1C 00 00 00 C7 44 24 18 00 00 00 00 C7 44 24 2C 01 00 00 00 6A 04 8D 44 24 30 50 6A 10 6A 01 53 E8 ?? ?? ?? ?? 83 C4 14 85 C0 75 2F 89 }
	condition:
		$pattern
}

rule clntraw_create_92c5f270fae1fc0bf0c95f10b37cb9fd {
	meta:
		aliases = "clntraw_create"
		type = "func"
		size = "211"
		objfiles = "clnt_raw@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 30 E8 ?? ?? ?? ?? 89 C6 8B 98 A0 00 00 00 89 DF 85 DB 75 20 68 A0 22 00 00 6A 01 E8 ?? ?? ?? ?? 5F 5A 31 D2 85 C0 0F 84 99 00 00 00 89 C7 89 86 A0 00 00 00 8D 73 0C C7 44 24 04 00 00 00 00 C7 44 24 08 02 00 00 00 8B 44 24 40 89 44 24 0C 8B 44 24 44 89 44 24 10 6A 00 6A 18 8D 87 84 22 00 00 50 56 E8 ?? ?? ?? ?? 8D 44 24 10 50 56 E8 ?? ?? ?? ?? 83 C4 18 85 C0 75 0B 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 8B 43 10 56 FF 50 10 89 87 9C 22 00 00 8B 43 10 8B 40 1C 5A 85 C0 74 04 56 FF D0 58 6A 02 68 60 22 00 00 8D 47 24 50 56 E8 ?? ?? ?? ?? C7 43 04 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 03 89 DA 83 }
	condition:
		$pattern
}

rule modf_fee44f4f1a28d1c67e795c5918e7baad {
	meta:
		aliases = "__GI_modf, modf"
		type = "func"
		size = "398"
		objfiles = "s_modf@libm.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 38 C7 44 24 28 00 00 00 00 C7 44 24 2C 00 00 00 00 C7 44 24 20 00 00 00 00 C7 44 24 24 00 00 00 00 C7 44 24 18 00 00 00 00 C7 44 24 1C 00 00 00 00 C7 44 24 10 00 00 00 00 C7 44 24 14 00 00 00 00 C7 44 24 08 00 00 00 00 C7 44 24 0C 00 00 00 00 C7 04 24 00 00 00 00 C7 44 24 04 00 00 00 00 8B 7C 24 50 DD 44 24 48 DD 5C 24 30 8B 54 24 34 8B 74 24 30 89 D0 C1 F8 14 25 FF 07 00 00 8D 88 01 FC FF FF 83 F9 13 7F 73 85 C9 79 1D 81 E2 00 00 00 80 89 54 24 2C C7 44 24 28 00 00 00 00 DD 44 24 28 DD 1F E9 D4 00 00 00 BB FF FF 0F 00 D3 FB 89 D8 21 D0 09 F0 75 21 DD 44 24 48 DD 1F 81 E2 00 00 }
	condition:
		$pattern
}

rule timer_create_4f9eea97f424e3e9c8c2496dc02d9111 {
	meta:
		aliases = "timer_create"
		type = "func"
		size = "145"
		objfiles = "timer_create@librt.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 44 8B 74 24 58 85 F6 75 12 C7 44 24 08 00 00 00 00 C7 44 24 04 0E 00 00 00 89 E6 83 7E 08 02 74 61 6A 08 E8 ?? ?? ?? ?? 89 C7 59 85 C0 74 53 89 04 24 8D 54 24 40 8B 44 24 54 89 F1 53 89 C3 B8 03 01 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0B E8 ?? ?? ?? ?? F7 DB 89 18 EB 1B 83 F8 FF 74 16 8B 46 08 89 07 8B 44 24 40 89 47 04 8B 44 24 5C 89 38 89 D8 EB 0F 57 E8 ?? ?? ?? ?? 83 C8 FF 5A EB 03 83 C8 FF 83 C4 44 5B 5E 5F C3 }
	condition:
		$pattern
}

rule erfc_f5db6f4e77f020c949eb11d1f956ebc7 {
	meta:
		aliases = "__GI_erfc, erfc"
		type = "func"
		size = "884"
		objfiles = "s_erf@libm.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 44 DD 44 24 54 DD 54 24 2C 8B 74 24 30 89 F7 89 F3 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 1D C1 EE 1F 8D 04 36 31 D2 52 50 DF 2C 24 D9 C9 83 C4 08 DC 3D ?? ?? ?? ?? E9 5A 01 00 00 DD D8 81 FB FF FF EA 3F 0F 8F A8 00 00 00 81 FB FF FF 6F 3C 7F 0F DD 44 24 54 DC 2D ?? ?? ?? ?? E9 07 03 00 00 DD 44 24 54 D8 C8 DD 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? DD 05 ?? ?? ?? ?? D8 CA DC 05 ?? ?? ?? ?? D8 CA DC 05 ?? ?? ?? ?? D8 CA DC 05 ?? ?? ?? ?? D8 CA DC 05 ?? ?? ?? ?? DE CA D9 E8 DC C2 D9 C9 DE F2 D9 C9 81 FE FF FF }
	condition:
		$pattern
}

rule vsnprintf_24e73b8a5c5b8bd486b0590a3333b5ad {
	meta:
		aliases = "__GI_vsnprintf, vsnprintf"
		type = "func"
		size = "161"
		objfiles = "vsnprintf@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 50 8B 74 24 60 C7 44 24 04 FE FF FF FF 66 C7 04 24 D0 00 C6 44 24 02 00 C7 44 24 2C 00 00 00 00 C7 44 24 34 01 00 00 00 89 E7 8D 44 24 38 50 E8 ?? ?? ?? ?? C7 44 24 24 00 00 00 00 89 F0 F7 D0 5A 8B 5C 24 64 39 C3 76 02 89 C3 89 74 24 08 8D 04 1E 89 44 24 0C 89 74 24 10 89 74 24 14 89 74 24 18 89 44 24 1C FF 74 24 6C FF 74 24 6C 57 E8 ?? ?? ?? ?? 89 C2 83 C4 0C 85 DB 74 16 8B 44 24 10 3B 44 24 0C 75 05 48 89 44 24 10 8B 44 24 10 C6 00 00 89 D0 83 C4 50 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __ieee754_rem_pio2_570dea5fd50d87dca5dcb193fe82d94d {
	meta:
		aliases = "__ieee754_rem_pio2"
		type = "func"
		size = "728"
		objfiles = "e_rem_pio2@libm.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 60 8B 74 24 78 DD 44 24 70 DD 54 24 28 8B 7C 24 2C 89 FB 81 E3 FF FF FF 7F 81 FB FB 21 E9 3F 7F 15 DD 1E C7 46 08 00 00 00 00 C7 46 0C 00 00 00 00 E9 C9 01 00 00 DD D8 81 FB 7B D9 02 40 0F 8F 80 00 00 00 85 FF 7E 3F DD 44 24 70 DC 25 ?? ?? ?? ?? 81 FB FB 21 F9 3F 74 08 DD 05 ?? ?? ?? ?? EB 0E DD 05 ?? ?? ?? ?? DE E9 DD 05 ?? ?? ?? ?? D9 C1 D8 E1 DD 16 DE EA DE E9 DD 5E 08 B9 01 00 00 00 E9 43 02 00 00 DD 44 24 70 DC 05 ?? ?? ?? ?? 81 FB FB 21 F9 3F 74 08 DD 05 ?? ?? ?? ?? EB 0E DD 05 ?? ?? ?? ?? DE C1 DD 05 ?? ?? ?? ?? D9 C1 D8 C1 DD 16 DE EA DE C1 DD 5E 08 83 C9 FF E9 06 02 00 }
	condition:
		$pattern
}

rule trecurse_7b0faf9e5774b481ac9946c62d55061c {
	meta:
		aliases = "trecurse"
		type = "func"
		size = "91"
		objfiles = "twalk@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 C3 89 D7 89 CE 83 78 04 00 75 0B 83 78 08 00 75 05 51 6A 03 EB 37 56 6A 00 53 FF D7 8B 43 04 83 C4 0C 85 C0 74 0A 8D 4E 01 89 FA E8 CC FF FF FF 56 6A 01 53 FF D7 8B 43 08 83 C4 0C 85 C0 74 0A 8D 4E 01 89 FA E8 B2 FF FF FF 56 6A 02 53 FF D7 83 C4 0C 5B 5E 5F C3 }
	condition:
		$pattern
}

rule do_close_af9e8d64bcc22ff9f9e9715716b437b9 {
	meta:
		aliases = "do_close"
		type = "func"
		size = "27"
		objfiles = "rtime@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 C3 E8 ?? ?? ?? ?? 89 C6 8B 38 53 E8 ?? ?? ?? ?? 89 3E 58 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_kill_all_threads_3e7dfb0aac85e3722dfd53995b7c9296 {
	meta:
		aliases = "pthread_kill_all_threads"
		type = "func"
		size = "56"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 C6 89 D7 A1 ?? ?? ?? ?? 8B 18 EB 0D 56 FF 73 14 E8 ?? ?? ?? ?? 8B 1B 58 5A 3B 1D ?? ?? ?? ?? 75 EB 85 FF 74 0B 56 FF 73 14 E8 ?? ?? ?? ?? 59 5B 5B 5E 5F C3 }
	condition:
		$pattern
}

rule byte_insert_op1_0c4b250f2f4eb8212fe922f4261aa4e2 {
	meta:
		aliases = "byte_insert_op1"
		type = "func"
		size = "44"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 C7 89 D3 89 CE 8B 44 24 10 8D 48 03 89 C2 EB 06 49 4A 8A 02 88 01 39 DA 75 F6 89 F1 89 DA 89 F8 5B 5E 5F E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svc_find_3ecf90b931e4e6697824f9e8a5bb5caf {
	meta:
		aliases = "svc_find"
		type = "func"
		size = "48"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 C7 89 D3 89 CE E8 ?? ?? ?? ?? 8B 80 B8 00 00 00 31 D2 EB 0E 39 78 04 75 05 39 58 08 74 08 89 C2 8B 00 85 C0 75 EE 89 16 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __get_next_rpcent_4333a1d4663c258585e9ccf11b8b5fe2 {
	meta:
		aliases = "__get_next_rpcent"
		type = "func"
		size = "239"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 C7 8D B0 A8 00 00 00 FF 37 68 00 10 00 00 56 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 0F 84 C8 00 00 00 56 E8 ?? ?? ?? ?? 5A C6 84 07 A7 00 00 00 0A 80 BF A8 00 00 00 23 74 D0 6A 23 56 E8 ?? ?? ?? ?? 5A 59 85 C0 75 0E 6A 0A 56 E8 ?? ?? ?? ?? 59 5B 85 C0 74 B4 C6 00 00 89 F0 E8 ?? ?? ?? ?? 85 C0 74 A6 C6 00 00 8D 58 01 89 B7 9C 00 00 00 EB 01 43 8A 03 3C 20 74 F9 3C 09 74 F5 53 E8 ?? ?? ?? ?? 5A 89 87 A4 00 00 00 8D 77 10 89 B7 A0 00 00 00 89 D8 E8 ?? ?? ?? ?? 31 C9 85 C0 74 2E C6 00 00 8D 48 01 EB 26 80 FA 20 74 1E 80 FA 09 74 19 39 DE 73 05 89 0E 83 C6 04 89 C8 E8 ?? ?? ?? ?? 89 C1 85 C0 74 }
	condition:
		$pattern
}

rule inet_ntoa_r_a29830775dfaa0b46ba1a690b2765a1b {
	meta:
		aliases = "__GI_inet_ntoa_r, inet_ntoa_r"
		type = "func"
		size = "76"
		objfiles = "inet_ntoa@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 44 24 10 0F C8 8B 4C 24 14 83 C1 0F 89 C3 31 FF 31 F6 EB 28 6A 00 6A F6 89 D8 25 FF 00 00 00 31 D2 52 50 51 E8 ?? ?? ?? ?? 8D 48 FF 83 C4 14 85 F6 74 03 C6 06 2E C1 EB 08 47 89 CE 83 FF 03 7E D3 8D 41 01 5B 5E 5F C3 }
	condition:
		$pattern
}

rule _dl_run_init_array_181b9e48904b5efcc5a657ff0ed68b3e {
	meta:
		aliases = "_dl_run_init_array"
		type = "func"
		size = "49"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 44 24 10 8B 08 8B 90 AC 00 00 00 8B 80 A4 00 00 00 85 C0 74 14 89 D7 C1 EF 02 8D 34 08 31 DB EB 04 FF 14 9E 43 39 FB 72 F8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule re_match_2_39d0234ca65b8ff573355b91e6ea2202 {
	meta:
		aliases = "re_match_2"
		type = "func"
		size = "63"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 44 24 10 8B 54 24 14 8B 4C 24 18 8B 7C 24 1C 8B 74 24 20 8B 5C 24 2C 89 5C 24 20 8B 5C 24 28 89 5C 24 1C 8B 5C 24 24 89 5C 24 18 89 74 24 14 89 7C 24 10 5B 5E 5F E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule confstr_4a97449c150b7d79bf9c00725fc2c6bb {
	meta:
		aliases = "confstr"
		type = "func"
		size = "110"
		objfiles = "confstr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 44 24 10 8B 7C 24 14 8B 74 24 18 85 C0 74 07 83 F8 03 75 0E EB 1B BA ?? ?? ?? ?? BB 0E 00 00 00 EB 19 E8 ?? ?? ?? ?? C7 00 16 00 00 00 31 DB EB 33 BA ?? ?? ?? ?? BB 12 00 00 00 85 F6 74 25 85 FF 74 21 39 F3 77 0A 53 52 57 E8 ?? ?? ?? ?? EB 10 8D 46 FF 50 52 57 E8 ?? ?? ?? ?? C6 44 37 FF 00 83 C4 0C 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_rwlock_destroy_bef2da9f0a4015c9c1913015af1d0846 {
	meta:
		aliases = "pthread_rwlock_destroy"
		type = "func"
		size = "48"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 31 D2 89 D8 E8 ?? ?? ?? ?? 8B 73 08 8B 7B 0C 53 E8 ?? ?? ?? ?? 58 85 F6 7F 06 31 C0 85 FF 74 05 B8 10 00 00 00 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_setspecific_d8a5a37886c17295a882062239530b40 {
	meta:
		aliases = "pthread_setspecific"
		type = "func"
		size = "97"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 81 FB FF 03 00 00 77 49 83 3C DD ?? ?? ?? ?? 00 74 3F E8 ?? ?? ?? ?? 89 C7 89 DE C1 EE 05 83 7C B0 74 00 75 1A 6A 04 6A 20 E8 ?? ?? ?? ?? 89 C2 59 58 B8 0C 00 00 00 85 D2 74 1B 89 54 B7 74 83 E3 1F 8B 54 B7 74 8B 44 24 14 89 04 9A 31 C0 EB 05 B8 16 00 00 00 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_mutex_trylock_82f5194e649fc66eadbf70fd605cbef4 {
	meta:
		aliases = "__pthread_mutex_trylock, pthread_mutex_trylock"
		type = "func"
		size = "137"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 8B 43 0C 83 F8 01 74 24 7F 06 85 C0 74 13 EB 0A 83 F8 02 74 44 83 F8 03 74 57 BE 16 00 00 00 EB 5B 8D 43 10 5B 5E 5F E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C7 39 43 08 75 07 FF 43 04 31 F6 EB 3D 8D 43 10 E8 ?? ?? ?? ?? 89 C6 85 C0 75 2F 89 7B 08 C7 43 04 00 00 00 00 EB 23 8D 43 10 E8 ?? ?? ?? ?? 89 C6 85 C0 75 15 E8 ?? ?? ?? ?? 89 43 08 EB 0B 8D 43 10 5B 5E 5F E9 ?? ?? ?? ?? 89 F0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule tdelete_2985328f2e1dcd4274b2ceb16ca033b9 {
	meta:
		aliases = "tdelete"
		type = "func"
		size = "141"
		objfiles = "tdelete@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 8B 44 24 14 85 C0 74 78 89 C6 8B 38 85 FF EB 0F 89 C7 7D 05 8D 70 04 EB 03 8D 70 08 83 3E 00 74 5F 8B 06 FF 30 53 FF 54 24 20 59 5A 83 F8 00 8B 06 75 DD 8B 48 08 8B 58 04 85 DB 74 0E 85 C9 74 31 8B 51 04 85 D2 75 0B 89 59 04 89 CB EB 23 89 C2 89 D9 8B 42 04 89 D3 85 C0 75 F3 8B 42 08 89 41 04 8B 06 8B 40 04 89 42 04 8B 06 8B 40 08 89 42 08 FF 36 E8 ?? ?? ?? ?? 89 1E 89 F8 5A EB 02 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule _obstack_begin_86df14ba20342de2ed4a9c14c598574d {
	meta:
		aliases = "_obstack_begin"
		type = "func"
		size = "135"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 8B 54 24 14 8B 74 24 18 8B 4C 24 1C 85 F6 75 04 66 BE 04 00 85 D2 75 04 66 BA E0 0F 89 4B 1C 8B 44 24 20 89 43 20 89 13 8D 7E FF 89 7B 18 80 63 28 FE F6 43 28 01 74 0B 52 FF 73 24 FF D1 89 C2 59 EB 05 52 FF D1 89 C2 58 89 53 04 85 D2 75 05 E8 ?? ?? ?? ?? 8D 44 3A 08 F7 DE 21 F0 89 43 08 89 43 0C 89 D0 03 03 89 02 89 43 10 C7 42 04 00 00 00 00 80 63 28 F9 B8 01 00 00 00 5B 5E 5F C3 }
	condition:
		$pattern
}

rule obstack_free_44ebb19f16ced37f919583219f2a4239 {
	meta:
		aliases = "obstack_free"
		type = "func"
		size = "93"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 8B 74 24 14 8B 53 04 EB 20 8B 7A 04 F6 43 28 01 8B 43 20 74 0A 52 FF 73 24 FF D0 58 5A EB 04 52 FF D0 59 80 4B 28 02 89 FA 85 D2 74 1C 39 F2 73 D8 39 32 72 D4 85 D2 74 10 89 73 0C 89 73 08 8B 02 89 43 10 89 53 04 EB 09 85 F6 74 05 E8 ?? ?? ?? ?? 5B 5E 5F C3 }
	condition:
		$pattern
}

rule strncasecmp_1ea34e287293d4b2e440283344e76eb0 {
	meta:
		aliases = "__GI_strncasecmp, strncasecmp"
		type = "func"
		size = "65"
		objfiles = "strncasecmp@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 8B 74 24 14 8B 7C 24 18 31 C0 85 FF 74 28 39 F3 74 1A 8B 0D ?? ?? ?? ?? 0F B6 03 0F BF 14 41 0F B6 06 0F BF 04 41 29 C2 89 D0 75 0A 80 3B 00 74 05 4F 46 43 EB D4 5B 5E 5F C3 }
	condition:
		$pattern
}

rule strcspn_28259d4bcb32e49be938f30092a7407a {
	meta:
		aliases = "__GI_strcspn, strcspn"
		type = "func"
		size = "45"
		objfiles = "strcspn@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 8B 7C 24 14 31 F6 EB 12 0F B6 C0 50 57 E8 ?? ?? ?? ?? 5A 59 85 C0 75 08 43 46 8A 03 84 C0 75 E8 89 F0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule strtok_r_4ac00f2890a2c65b7b9950d34fb7c621 {
	meta:
		aliases = "__GI_strtok_r, strtok_r"
		type = "func"
		size = "80"
		objfiles = "strtok_r@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 8B 7C 24 14 8B 74 24 18 85 DB 75 02 8B 1E 57 53 E8 ?? ?? ?? ?? 59 5A 01 C3 80 3B 00 75 06 89 1E 31 C0 EB 21 57 53 E8 ?? ?? ?? ?? 5F 5A 85 C0 75 0C 6A 00 53 E8 ?? ?? ?? ?? 5A 59 EB 04 C6 00 00 40 89 06 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_rwlock_wrlock_8e67796fdaa147dbab8ec590548be295 {
	meta:
		aliases = "pthread_rwlock_wrlock"
		type = "func"
		size = "79"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 E8 ?? ?? ?? ?? 89 C6 8D 7B 14 89 F2 89 D8 E8 ?? ?? ?? ?? 83 7B 08 00 75 06 83 7B 0C 00 74 19 89 F2 89 F8 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 89 F0 E8 ?? ?? ?? ?? 58 EB D2 89 73 0C 53 E8 ?? ?? ?? ?? 58 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule ___path_search_4a6dacf74146d14ccc73fd32bfea0bf5 {
	meta:
		aliases = "___path_search"
		type = "func"
		size = "188"
		objfiles = "tempname@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 18 8B 7C 24 1C 85 FF 74 1A 80 3F 00 74 15 57 E8 ?? ?? ?? ?? 59 89 C6 83 F8 05 7E 11 BE 05 00 00 00 EB 0A BF ?? ?? ?? ?? BE 04 00 00 00 85 DB 75 38 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? BB ?? ?? ?? ?? 85 C0 75 25 53 53 E8 ?? ?? ?? ?? 59 5A 85 C0 74 0B 89 D8 E8 ?? ?? ?? ?? 85 C0 75 0D E8 ?? ?? ?? ?? C7 00 02 00 00 00 EB 2D 53 E8 ?? ?? ?? ?? 5A 89 C2 EB 01 4A 83 FA 01 7E 07 80 7C 1A FF 2F 74 F3 8D 44 16 08 39 44 24 14 73 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 17 57 56 53 52 68 ?? ?? ?? ?? FF 74 24 24 E8 ?? ?? ?? ?? 31 C0 83 C4 18 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_mutex_timedlock_345cd006ce4219cbb695a3d7c19db545 {
	meta:
		aliases = "pthread_mutex_timedlock"
		type = "func"
		size = "191"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 10 8B 7C 24 14 81 7F 04 FF C9 9A 3B 0F 87 9C 00 00 00 8B 46 0C 83 F8 01 74 23 7F 09 85 C0 74 11 E9 89 00 00 00 83 F8 02 74 3C 83 F8 03 75 7F EB 64 8D 46 10 31 D2 E8 ?? ?? ?? ?? EB 25 E8 ?? ?? ?? ?? 89 C3 39 46 08 75 05 FF 46 04 EB 14 8D 46 10 89 DA E8 ?? ?? ?? ?? 89 5E 08 C7 46 04 00 00 00 00 31 D2 EB 4D E8 ?? ?? ?? ?? 89 C3 BA 23 00 00 00 39 46 08 74 3C 57 50 8D 46 10 50 E8 ?? ?? ?? ?? 83 C4 0C BA 6E 00 00 00 85 C0 74 25 89 5E 08 30 D2 EB 1E 57 6A 00 8D 46 10 50 E8 ?? ?? ?? ?? 83 C4 0C 83 F8 01 19 D2 83 E2 6E EB 05 BA 16 00 00 00 89 D0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule wcswcs_9887b12654a526cef72d07c3a00876e9 {
	meta:
		aliases = "wcsstr, wcswcs"
		type = "func"
		size = "54"
		objfiles = "wcsstr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 10 8B 7C 24 14 89 F0 89 FA 8B 1A 85 DB 75 04 89 F0 EB 19 8B 08 39 CB 75 08 83 C2 04 83 C0 04 EB E8 85 C9 74 05 83 C6 04 EB DB 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __encode_question_684993d5f90f555509cc981544bfa56c {
	meta:
		aliases = "__encode_question"
		type = "func"
		size = "82"
		objfiles = "encodeq@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 10 8B 7C 24 14 8B 5C 24 18 53 57 FF 36 E8 ?? ?? ?? ?? 89 C1 83 C4 0C 85 C0 78 2B 29 C3 83 FB 03 7F 05 83 C9 FF EB 1F 8D 14 07 0F B6 46 05 88 02 8B 46 04 88 42 01 0F B6 46 09 88 42 02 8B 46 08 88 42 03 83 C1 04 89 C8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule wcscasecmp_7f8e02106d74ff02a4255971e2f05ff3 {
	meta:
		aliases = "wcscasecmp"
		type = "func"
		size = "84"
		objfiles = "wcscasecmp@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 10 8B 7C 24 14 EB 0F 83 3E 00 75 04 31 C0 EB 3A 83 C6 04 83 C7 04 8B 06 3B 07 74 EB 50 E8 ?? ?? ?? ?? 89 C3 FF 37 E8 ?? ?? ?? ?? 5A 59 39 C3 74 D6 FF 36 E8 ?? ?? ?? ?? 89 C3 FF 37 E8 ?? ?? ?? ?? 5A 59 39 C3 19 C0 83 C8 01 5B 5E 5F C3 }
	condition:
		$pattern
}

rule remove_2364e6da4ad88f06e6e480342ee5c7c7 {
	meta:
		aliases = "__GI_remove, remove"
		type = "func"
		size = "50"
		objfiles = "remove@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 10 E8 ?? ?? ?? ?? 89 C3 8B 38 56 E8 ?? ?? ?? ?? 5A 85 C0 79 13 83 3B 14 75 0E 89 3B 89 74 24 10 5B 5E 5F E9 ?? ?? ?? ?? 5B 5E 5F C3 }
	condition:
		$pattern
}

rule shm_open_6c7c769c15e0b0a7b6bc279c217dca14 {
	meta:
		aliases = "shm_open"
		type = "func"
		size = "59"
		objfiles = "shm@librt.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 14 8B 44 24 10 E8 ?? ?? ?? ?? 89 C3 83 CF FF 85 C0 74 1C FF 74 24 18 81 CE 00 00 08 00 56 50 E8 ?? ?? ?? ?? 89 C7 53 E8 ?? ?? ?? ?? 83 C4 10 89 F8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule _dl_add_elf_hash_table_9a01d598a71c70db6e85a848cb7c7dbc {
	meta:
		aliases = "_dl_add_elf_hash_table"
		type = "func"
		size = "169"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 14 8B 7C 24 18 68 E8 00 00 00 E8 ?? ?? ?? ?? 89 C3 BA E8 00 00 00 59 EB 04 C6 00 00 40 4A 83 FA FF 75 F6 A1 ?? ?? ?? ?? 85 C0 75 0A 89 1D ?? ?? ?? ?? EB 0F 89 D0 8B 50 0C 85 D2 75 F7 89 58 0C 89 43 10 C7 43 0C 00 00 00 00 66 C7 43 22 00 00 FF 74 24 10 E8 ?? ?? ?? ?? 89 43 04 8B 44 24 20 89 43 08 C7 43 18 03 00 00 00 8B 4F 10 58 85 C9 74 17 8B 01 89 43 28 8B 51 04 89 53 38 8D 51 08 89 53 2C 8D 04 82 89 43 3C 89 33 89 73 14 31 D2 8B 04 97 89 44 93 40 42 83 FA 22 7E F3 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule wcstok_42542c116afdebdaa2b5dedb91b148ac {
	meta:
		aliases = "wcstok"
		type = "func"
		size = "78"
		objfiles = "wcstok@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 14 8B 7C 24 18 8B 5C 24 10 85 DB 75 06 8B 1F 85 DB 74 2F 56 53 E8 ?? ?? ?? ?? 5A 59 8D 1C 83 83 3B 00 75 06 31 DB 31 C0 EB 16 56 53 E8 ?? ?? ?? ?? 5A 59 85 C0 74 09 C7 00 00 00 00 00 83 C0 04 89 07 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_rwlock_unlock_c7e5c9e099dbcfc6c817780409762f04 {
	meta:
		aliases = "pthread_rwlock_unlock"
		type = "func"
		size = "303"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 31 D2 89 F8 E8 ?? ?? ?? ?? 8B 5F 0C 85 DB 74 6A E8 ?? ?? ?? ?? 39 C3 75 68 C7 47 0C 00 00 00 00 83 7F 18 00 74 25 8B 5F 14 85 DB 74 1E 8B 43 08 89 47 14 C7 43 08 00 00 00 00 57 E8 ?? ?? ?? ?? 89 D8 E8 ?? ?? ?? ?? 31 C0 EB 41 8B 77 10 C7 47 10 00 00 00 00 57 E8 ?? ?? ?? ?? 59 EB 13 8B 5E 08 C7 46 08 00 00 00 00 89 F0 E8 ?? ?? ?? ?? 89 DE 85 F6 75 E9 E9 A8 00 00 00 8B 47 08 85 C0 75 11 57 E8 ?? ?? ?? ?? B8 01 00 00 00 5A E9 92 00 00 00 48 89 47 08 31 DB 85 C0 75 14 8B 5F 14 85 DB 74 0D 8B 43 08 89 47 14 C7 43 08 00 00 00 00 57 E8 ?? ?? ?? ?? 58 85 DB 74 07 89 D8 E8 ?? ?? ?? }
	condition:
		$pattern
}

rule wcsdup_d4376828ae9478581c5c06392f1e561b {
	meta:
		aliases = "wcsdup"
		type = "func"
		size = "52"
		objfiles = "wcsdup@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 57 E8 ?? ?? ?? ?? 8D 34 85 04 00 00 00 89 34 24 E8 ?? ?? ?? ?? 89 C3 58 85 DB 74 0B 56 57 53 E8 ?? ?? ?? ?? 83 C4 0C 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule strdup_7588b256d955dafd8fb4e8c4edccc671 {
	meta:
		aliases = "__GI_strdup, strdup"
		type = "func"
		size = "48"
		objfiles = "strdup@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 57 E8 ?? ?? ?? ?? 8D 70 01 89 34 24 E8 ?? ?? ?? ?? 89 C3 58 85 DB 74 0B 56 57 53 E8 ?? ?? ?? ?? 83 C4 0C 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule getrpcbyname_7723508ecee49dda2e734822d4abfb07 {
	meta:
		aliases = "__GI_getrpcbyname, getrpcbyname"
		type = "func"
		size = "80"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 6A 00 E8 ?? ?? ?? ?? 5E EB 29 57 FF 36 E8 ?? ?? ?? ?? 59 5B 85 C0 74 2B 8B 5E 04 EB 10 57 50 E8 ?? ?? ?? ?? 59 5A 85 C0 74 19 83 C3 04 8B 03 85 C0 75 EA E8 ?? ?? ?? ?? 89 C6 85 C0 75 CC E8 ?? ?? ?? ?? 89 F0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule xdr_vector_d1c06bd67f56dbf6e5c984e247b0851c {
	meta:
		aliases = "xdr_vector"
		type = "func"
		size = "50"
		objfiles = "xdr_array@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 8B 5C 24 14 31 F6 EB 14 6A FF 53 57 FF 54 24 2C 83 C4 0C 85 C0 74 10 03 5C 24 1C 46 3B 74 24 18 72 E6 B8 01 00 00 00 5B 5E 5F C3 }
	condition:
		$pattern
}

rule cfsetspeed_8e2f67a9abcc2044b602aa8278d6b4b3 {
	meta:
		aliases = "cfsetspeed"
		type = "func"
		size = "90"
		objfiles = "cfsetspeed@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 8B 74 24 14 31 C0 EB 34 8B 1C C5 ?? ?? ?? ?? 39 DE 75 0A 56 57 E8 ?? ?? ?? ?? 56 EB 11 3B 34 C5 ?? ?? ?? ?? 75 15 53 57 E8 ?? ?? ?? ?? 53 57 E8 ?? ?? ?? ?? 31 C0 83 C4 10 EB 14 40 83 F8 1F 76 C7 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 5B 5E 5F C3 }
	condition:
		$pattern
}

rule lfind_e8a547293c19b88a736e3891c2dbd281 {
	meta:
		aliases = "__GI_lfind, lfind"
		type = "func"
		size = "51"
		objfiles = "lfind@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 8B 74 24 14 8B 44 24 18 8B 18 EB 14 56 57 FF 54 24 28 5A 59 85 C0 75 04 89 F0 EB 0C 03 74 24 1C 4B 83 FB FF 75 E6 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule wmemmove_6ccacb392b42bbdea2f680c1755cd396 {
	meta:
		aliases = "wmemmove"
		type = "func"
		size = "66"
		objfiles = "wmemmove@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 8B 74 24 14 8B 4C 24 18 39 FE 72 25 89 FB 89 F2 EB 0B 8B 02 89 03 83 C3 04 83 C2 04 49 85 C9 75 F1 EB 12 49 8D 14 8D 00 00 00 00 8B 04 16 89 04 17 85 C9 75 EE 89 F8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule stpncpy_56505f9cb9c1bb7f6e4d005b043edcff {
	meta:
		aliases = "stpncpy"
		type = "func"
		size = "45"
		objfiles = "stpncpy@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 8B 74 24 14 8B 5C 24 18 89 F2 89 F9 EB 0B 8A 02 88 01 3C 01 83 DA FF 41 4B 85 DB 75 F1 29 F2 8D 04 17 5B 5E 5F C3 }
	condition:
		$pattern
}

rule wcpncpy_0bf442d57a273ad0f8a92a41365e29bf {
	meta:
		aliases = "wcpncpy"
		type = "func"
		size = "49"
		objfiles = "wcpncpy@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 8B 74 24 14 8B 5C 24 18 89 F2 89 F9 EB 0F 8B 02 89 01 85 C0 74 03 83 C2 04 83 C1 04 4B 85 DB 75 ED 29 F2 8D 04 17 5B 5E 5F C3 }
	condition:
		$pattern
}

rule wctype_fb8a97cdc5747e98711eab6a457c943e {
	meta:
		aliases = "__GI_wctrans, __GI_wctype, wctrans, wctype"
		type = "func"
		size = "58"
		objfiles = "wctype@libc.a, wctrans@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 B8 ?? ?? ?? ?? BE 01 00 00 00 8D 58 01 53 57 E8 ?? ?? ?? ?? 5A 59 85 C0 75 04 89 F0 EB 11 0F B6 43 FF 8D 04 03 80 38 00 74 03 46 EB DD 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __pthread_perform_cleanup_e4966b77f2f01cb08dee2374849e053e {
	meta:
		aliases = "__pthread_perform_cleanup"
		type = "func"
		size = "57"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 E8 ?? ?? ?? ?? 89 C6 8B 58 3C EB 0D 39 FB 76 0D FF 73 04 FF 13 8B 5B 0C 58 85 DB 75 EF 83 BE FC 00 00 00 00 74 08 5B 5E 5F E9 ?? ?? ?? ?? 5B 5E 5F C3 }
	condition:
		$pattern
}

rule strndup_694d743242225696fd0150ec1e0f00ab {
	meta:
		aliases = "__GI_strndup, strndup"
		type = "func"
		size = "58"
		objfiles = "strndup@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 FF 74 24 14 57 E8 ?? ?? ?? ?? 5A 59 89 C6 8D 40 01 50 E8 ?? ?? ?? ?? 89 C3 58 85 DB 74 0F 56 57 53 E8 ?? ?? ?? ?? C6 04 33 00 83 C4 0C 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule svctcp_recv_adc352d151d56c515870ca31281f779a {
	meta:
		aliases = "svctcp_recv"
		type = "func"
		size = "68"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 14 8B 44 24 10 8B 70 2C 8D 5E 08 C7 46 08 01 00 00 00 53 E8 ?? ?? ?? ?? 57 53 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 0C 8B 07 89 46 04 B8 01 00 00 00 EB 08 C7 06 00 00 00 00 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule svcunix_recv_b94deb0f198382f7b410e912c57520f2 {
	meta:
		aliases = "svcunix_recv"
		type = "func"
		size = "89"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 14 8B 44 24 10 8B 70 2C 8D 5E 08 C7 46 08 01 00 00 00 53 E8 ?? ?? ?? ?? 57 53 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 21 8B 07 89 46 04 C7 47 24 01 00 00 00 C7 47 28 ?? ?? ?? ?? C7 47 2C 1C 00 00 00 B8 01 00 00 00 EB 08 C7 06 00 00 00 00 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule fwrite_unlocked_74f714be1b7cad710df9617e20a9e6de {
	meta:
		aliases = "__GI_fwrite_unlocked, fwrite_unlocked"
		type = "func"
		size = "110"
		objfiles = "fwrite_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 14 8B 5C 24 18 8B 74 24 1C 0F B7 06 25 C0 00 00 00 3D C0 00 00 00 74 11 68 80 00 00 00 56 E8 ?? ?? ?? ?? 5A 59 85 C0 75 39 85 FF 74 35 85 DB 74 31 83 C8 FF 31 D2 F7 F7 39 C3 77 17 56 0F AF DF 53 FF 74 24 18 E8 ?? ?? ?? ?? 31 D2 F7 F7 83 C4 0C EB 11 66 83 0E 08 E8 ?? ?? ?? ?? C7 00 16 00 00 00 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule strsignal_5d7e3043aa37b2804c239965b9f0a776 {
	meta:
		aliases = "__GI_strsignal, strsignal"
		type = "func"
		size = "81"
		objfiles = "strsignal@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 44 24 10 83 F8 1F 77 19 89 C1 BA ?? ?? ?? ?? EB 07 80 3A 01 83 D9 00 42 85 C9 75 F5 80 3A 00 75 24 6A 00 6A F6 99 52 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 50 F1 BE ?? ?? ?? ?? 89 D7 A5 A5 A5 66 A5 A4 83 C4 14 89 D0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule epoll_pwait_e53bdc1790003cd822166f828b19fcf1 {
	meta:
		aliases = "__libc_epoll_pwait, epoll_pwait"
		type = "func"
		size = "74"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 C7 04 24 08 00 00 00 8B 44 24 10 53 89 C3 55 8B 2C 24 B8 3F 01 00 00 CD 80 5D 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule seed48_r_c09d0a77d71dbcf7470907820ac5840a {
	meta:
		aliases = "__GI_seed48_r, seed48_r"
		type = "func"
		size = "75"
		objfiles = "seed48_r@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 54 24 10 8B 4C 24 14 8D 79 06 89 CE A5 66 A5 66 8B 42 04 66 89 41 04 66 8B 42 02 66 89 41 02 66 8B 02 66 89 01 C7 41 10 6D E6 EC DE C7 41 14 05 00 00 00 66 C7 41 0C 0B 00 66 C7 41 0E 01 00 31 C0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule strcat_fc39f2e68c3e2b9572ead413f87d6dfc {
	meta:
		aliases = "__GI_strcat, strcat"
		type = "func"
		size = "35"
		objfiles = "strcat@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 74 24 14 31 C0 83 C9 FF 8B 7C 24 10 F2 AE 4F AC AA 84 C0 75 FA 8B 44 24 10 5A 5E 5F C3 }
	condition:
		$pattern
}

rule memcpy_55b9f3edcc52a715897dab39ce8dbfc0 {
	meta:
		aliases = "__GI_memcpy, memcpy"
		type = "func"
		size = "41"
		objfiles = "memcpy@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 74 24 14 8B 44 24 18 89 C1 C1 E9 02 8B 7C 24 10 F3 A5 89 C1 83 E1 03 74 02 F3 A4 8B 44 24 10 5A 5E 5F C3 }
	condition:
		$pattern
}

rule strncpy_12f93b7b48580efa90eb9711781dc110 {
	meta:
		aliases = "__GI_strncpy, strncpy"
		type = "func"
		size = "38"
		objfiles = "strncpy@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 74 24 14 8B 4C 24 18 8B 7C 24 10 83 E9 01 72 08 AC AA 84 C0 75 F5 F3 AA 8B 44 24 10 5A 5E 5F C3 }
	condition:
		$pattern
}

rule strcpy_25e830002e76d977a2cf7c0f6516f752 {
	meta:
		aliases = "__GI_strcpy, strcpy"
		type = "func"
		size = "27"
		objfiles = "strcpy@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 74 24 14 8B 7C 24 10 AC AA 84 C0 75 FA 8B 44 24 10 5A 5E 5F C3 }
	condition:
		$pattern
}

rule ppoll_b20fb00bf62d9361ae8b54372ebca169 {
	meta:
		aliases = "__GI_ppoll, ppoll"
		type = "func"
		size = "82"
		objfiles = "ppoll@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 08 8B 54 24 1C 8B 74 24 20 85 D2 74 0E 8B 0A 8B 42 04 89 44 24 04 89 0C 24 89 E2 BF 08 00 00 00 8B 44 24 14 8B 4C 24 18 53 89 C3 B8 35 01 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5E 5F C3 }
	condition:
		$pattern
}

rule tmpnam_f6dc69c8583fe13bb8c302580b695cc8 {
	meta:
		aliases = "tmpnam"
		type = "func"
		size = "84"
		objfiles = "tmpnam@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 14 8B 7C 24 20 89 FE 85 FF 75 02 89 E6 6A 00 6A 00 6A 14 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 26 6A 00 6A 03 56 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 15 85 FF 75 13 BF ?? ?? ?? ?? A5 A5 A5 A5 A5 BF ?? ?? ?? ?? EB 02 31 FF 89 F8 83 C4 14 5E 5F C3 }
	condition:
		$pattern
}

rule sigaction_b944632e69a6593723094f3779dca7d7 {
	meta:
		aliases = "__GI_sigaction, __libc_sigaction, sigaction"
		type = "func"
		size = "80"
		objfiles = "sigaction@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 18 8B 54 24 28 31 C0 85 D2 74 2B 8D 7C 24 04 89 D6 A5 A5 A5 A5 A5 81 4C 24 08 00 00 00 04 B8 ?? ?? ?? ?? F6 42 04 04 75 05 B8 ?? ?? ?? ?? 89 44 24 0C 8D 44 24 04 6A 08 FF 74 24 30 50 FF 74 24 30 E8 ?? ?? ?? ?? 83 C4 28 5E 5F C3 }
	condition:
		$pattern
}

rule tcgetattr_d578d04f2e9caf9475ae7483b21ade1b {
	meta:
		aliases = "__GI_tcgetattr, tcgetattr"
		type = "func"
		size = "96"
		objfiles = "tcgetattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 24 8B 7C 24 34 89 E0 50 68 01 54 00 00 FF 74 24 38 E8 ?? ?? ?? ?? 89 C2 83 C4 0C 85 C0 75 35 8B 04 24 89 07 8B 44 24 04 89 47 04 8B 44 24 08 89 47 08 8B 44 24 0C 89 47 0C 8A 44 24 10 88 47 10 8D 74 24 11 83 C7 11 A5 A5 A5 A5 66 A5 A4 89 D0 AB AB AB AA 89 D0 83 C4 24 5E 5F C3 }
	condition:
		$pattern
}

rule statfs64_316153a3b656783bdb27ac0809d5483c {
	meta:
		aliases = "__GI_fstatfs64, __GI_statfs64, fstatfs64, statfs64"
		type = "func"
		size = "155"
		objfiles = "statfs64@libc.a, fstatfs64@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 40 8B 7C 24 50 89 E0 50 FF 74 24 50 E8 ?? ?? ?? ?? 5A 59 83 CA FF 85 C0 78 75 8B 04 24 89 07 8B 44 24 04 89 47 04 8B 44 24 08 89 47 08 C7 47 0C 00 00 00 00 8B 44 24 0C 89 47 10 C7 47 14 00 00 00 00 8B 44 24 10 89 47 18 C7 47 1C 00 00 00 00 8B 44 24 14 89 47 20 C7 47 24 00 00 00 00 8B 44 24 18 89 47 28 C7 47 2C 00 00 00 00 8B 44 24 20 89 47 34 8B 44 24 1C 89 47 30 8B 44 24 24 89 47 38 8D 74 24 2C 83 C7 40 A5 A5 A5 A5 A5 31 D2 89 D0 83 C4 40 5E 5F C3 }
	condition:
		$pattern
}

rule memmove_3ec67c3799d619c013ecbf61d1376eff {
	meta:
		aliases = "__GI_memmove, memmove"
		type = "func"
		size = "37"
		objfiles = "memmove@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 44 24 0C 8B 74 24 10 8B 4C 24 14 89 C7 39 F0 74 0E 72 09 8D 74 0E FF 8D 7C 08 FF FD F3 A4 FC 5E 5F C3 }
	condition:
		$pattern
}

rule waitid_54e7a55afcc65403577b6b9bf3e26738 {
	meta:
		aliases = "waitid"
		type = "func"
		size = "56"
		objfiles = "waitid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 4C 24 10 8B 54 24 14 8B 74 24 18 31 FF 8B 44 24 0C 53 89 C3 B8 1C 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E 5F C3 }
	condition:
		$pattern
}

rule splice_8a6a4eea9243a52333fe5091e3f87aa7 {
	meta:
		aliases = "splice"
		type = "func"
		size = "64"
		objfiles = "splice@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 4C 24 10 8B 54 24 14 8B 74 24 18 8B 7C 24 1C 8B 44 24 0C 53 89 C3 55 8B 6C 24 20 B8 39 01 00 00 CD 80 5D 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E 5F C3 }
	condition:
		$pattern
}

rule __syscall_ipc_a0f999106288ee305b1692e7d0db8d0b {
	meta:
		aliases = "__syscall_ipc"
		type = "func"
		size = "64"
		objfiles = "__syscall_ipc@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 4C 24 10 8B 54 24 14 8B 74 24 18 8B 7C 24 1C 8B 44 24 0C 53 89 C3 55 8B 6C 24 20 B8 75 00 00 00 CD 80 5D 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E 5F C3 }
	condition:
		$pattern
}

rule remap_file_pages_05a40a9f1db38c73c9dd905e366e5133 {
	meta:
		aliases = "remap_file_pages"
		type = "func"
		size = "58"
		objfiles = "remap_file_pages@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 4C 24 10 8B 54 24 14 8B 74 24 18 8B 7C 24 1C 8B 44 24 0C 53 89 C3 B8 01 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E 5F C3 }
	condition:
		$pattern
}

rule mount_1e19266ee7f7883836098dafb81dd88e {
	meta:
		aliases = "mount"
		type = "func"
		size = "58"
		objfiles = "mount@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 4C 24 10 8B 54 24 14 8B 74 24 18 8B 7C 24 1C 8B 44 24 0C 53 89 C3 B8 15 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E 5F C3 }
	condition:
		$pattern
}

rule fchownat_f9f8a55b02f7955c323d5a660c829681 {
	meta:
		aliases = "fchownat"
		type = "func"
		size = "58"
		objfiles = "fchownat@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 4C 24 10 8B 54 24 14 8B 74 24 18 8B 7C 24 1C 8B 44 24 0C 53 89 C3 B8 2A 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E 5F C3 }
	condition:
		$pattern
}

rule linkat_67388a89b1c5a13c00c97a53fead46df {
	meta:
		aliases = "linkat"
		type = "func"
		size = "58"
		objfiles = "linkat@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 4C 24 10 8B 54 24 14 8B 74 24 18 8B 7C 24 1C 8B 44 24 0C 53 89 C3 B8 2F 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E 5F C3 }
	condition:
		$pattern
}

rule init_module_5cd54189385b9cdf596c52a86e33957a {
	meta:
		aliases = "init_module"
		type = "func"
		size = "58"
		objfiles = "init_module@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 4C 24 10 8B 54 24 14 8B 74 24 18 8B 7C 24 1C 8B 44 24 0C 53 89 C3 B8 80 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E 5F C3 }
	condition:
		$pattern
}

rule select_e66bc1121c5404ac1a39196e83f9475a {
	meta:
		aliases = "__GI_select, __libc_select, select"
		type = "func"
		size = "58"
		objfiles = "select@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 4C 24 10 8B 54 24 14 8B 74 24 18 8B 7C 24 1C 8B 44 24 0C 53 89 C3 B8 8E 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E 5F C3 }
	condition:
		$pattern
}

rule mremap_75341ac600a7108141385d527a8ac03b {
	meta:
		aliases = "__GI_mremap, mremap"
		type = "func"
		size = "58"
		objfiles = "mremap@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 4C 24 10 8B 54 24 14 8B 74 24 18 8B 7C 24 1C 8B 44 24 0C 53 89 C3 B8 A3 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E 5F C3 }
	condition:
		$pattern
}

rule prctl_7a6affa8ab33e20db1d85dd911e8e77f {
	meta:
		aliases = "prctl"
		type = "func"
		size = "58"
		objfiles = "prctl@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 4C 24 10 8B 54 24 14 8B 74 24 18 8B 7C 24 1C 8B 44 24 0C 53 89 C3 B8 AC 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E 5F C3 }
	condition:
		$pattern
}

rule setxattr_c3c18b7b75207009df9711797f952db5 {
	meta:
		aliases = "setxattr"
		type = "func"
		size = "58"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 4C 24 10 8B 54 24 14 8B 74 24 18 8B 7C 24 1C 8B 44 24 0C 53 89 C3 B8 E2 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E 5F C3 }
	condition:
		$pattern
}

rule lsetxattr_96964afc2b79b110078c334291ccf5a5 {
	meta:
		aliases = "lsetxattr"
		type = "func"
		size = "58"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 4C 24 10 8B 54 24 14 8B 74 24 18 8B 7C 24 1C 8B 44 24 0C 53 89 C3 B8 E3 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E 5F C3 }
	condition:
		$pattern
}

rule fsetxattr_810bad39e65fbc5be0037685b8955f5a {
	meta:
		aliases = "fsetxattr"
		type = "func"
		size = "58"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 4C 24 10 8B 54 24 14 8B 74 24 18 8B 7C 24 1C 8B 44 24 0C 53 89 C3 B8 E4 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E 5F C3 }
	condition:
		$pattern
}

rule posix_fadvise_12ebf4bb0528bc7cd122ea2b7996b8a9 {
	meta:
		aliases = "posix_fadvise"
		type = "func"
		size = "50"
		objfiles = "posix_fadvise@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 4C 24 10 8B 74 24 14 8B 7C 24 18 89 C8 99 8B 44 24 0C 53 89 C3 B8 FA 00 00 00 CD 80 5B 31 D2 3D 00 F0 FF FF 76 04 89 C2 F7 DA 89 D0 5E 5F C3 }
	condition:
		$pattern
}

rule strncmp_aea55172a8fbe75e3f4316664e505052 {
	meta:
		aliases = "__GI_strncmp, strncmp"
		type = "func"
		size = "37"
		objfiles = "strncmp@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 74 24 0C 8B 7C 24 10 8B 4C 24 14 41 49 74 08 AC AE 75 08 84 C0 75 F5 31 C0 EB 04 19 C0 0C 01 5E 5F C3 }
	condition:
		$pattern
}

rule strcoll_124e63b6cd601cb0633c0125291d4f19 {
	meta:
		aliases = "__GI_strcmp, __GI_strcoll, strcmp, strcoll"
		type = "func"
		size = "29"
		objfiles = "strcmp@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 74 24 0C 8B 7C 24 10 AC AE 75 08 84 C0 75 F8 31 C0 EB 04 19 C0 0C 01 5E 5F C3 }
	condition:
		$pattern
}

rule strncat_6820425f2b92541a2ef04b74ca4e9877 {
	meta:
		aliases = "__GI_strncat, strncat"
		type = "func"
		size = "39"
		objfiles = "strncat@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 7C 24 0C 8B 74 24 10 8B 54 24 14 83 C9 FF 31 C0 42 57 F2 AE 4F 4A 89 D0 74 01 AC AA 84 C0 75 F5 58 5E 5F C3 }
	condition:
		$pattern
}

rule __stdio_init_mutex_2a09b92424104c9dbb6d0a07f863ba4e {
	meta:
		aliases = "__stdio_init_mutex"
		type = "func"
		size = "20"
		objfiles = "_stdio@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 7C 24 0C BE ?? ?? ?? ?? A5 A5 A5 A5 A5 A5 5E 5F C3 }
	condition:
		$pattern
}

rule svc_getreq_af6e18308dd96e0db0c79fd37df00397 {
	meta:
		aliases = "__GI_svc_getreq, svc_getreq"
		type = "func"
		size = "48"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 81 EC 84 00 00 00 31 C0 B9 20 00 00 00 8D 54 24 04 89 D7 FC F3 AB 8B 84 24 8C 00 00 00 89 44 24 04 52 E8 ?? ?? ?? ?? 81 C4 88 00 00 00 5F C3 }
	condition:
		$pattern
}

rule memset_cba3fdeaa73d59af8f17534fa8d5aa11 {
	meta:
		aliases = "__GI_memset, memset"
		type = "func"
		size = "50"
		objfiles = "memset@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 04 8B 44 24 10 8B 4C 24 14 8B 7C 24 0C 89 CA C1 E9 02 74 0B 0F B6 C0 69 C0 01 01 01 01 F3 AB 83 E2 03 74 04 AA 4A 75 FC 8B 44 24 0C 5A 5F C3 }
	condition:
		$pattern
}

rule sigignore_133608b7dd8f4d5c09adb6da8680926c {
	meta:
		aliases = "sigignore"
		type = "func"
		size = "42"
		objfiles = "sigignore@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 18 31 C0 8D 54 24 04 89 D7 AB AB AB AB AB C7 44 24 04 01 00 00 00 6A 00 52 FF 74 24 28 E8 ?? ?? ?? ?? 83 C4 24 5F C3 }
	condition:
		$pattern
}

rule abort_654f2f2597df0f5f61f042a4d764a66b {
	meta:
		aliases = "__GI_abort, abort"
		type = "func"
		size = "191"
		objfiles = "abort@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 20 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 44 24 20 00 00 00 00 C7 44 24 1C 20 00 00 00 6A 00 8D 44 24 20 50 6A 01 E8 ?? ?? ?? ?? 83 C4 10 80 3D ?? ?? ?? ?? 00 75 25 C6 05 ?? ?? ?? ?? 01 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 06 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C A0 ?? ?? ?? ?? 3C 01 75 33 C6 05 ?? ?? ?? ?? 02 31 C0 8D 54 24 04 89 D7 AB AB AB AB AB C7 44 24 10 FF FF FF FF C7 44 24 14 FF FF FF FF 6A 00 52 6A 06 E8 ?? ?? ?? ?? 83 C4 0C EB A6 3C 02 75 08 C6 05 ?? ?? ?? ?? 03 F4 80 3D ?? ?? ?? ?? 03 75 0E C6 05 ?? ?? ?? ?? 04 6A 7F E8 ?? ?? ?? ?? F4 EB FD }
	condition:
		$pattern
}

rule ctime_d075ea8487bd6855710a9e02889c5cb2 {
	meta:
		aliases = "__GI_ctime, ctime"
		type = "func"
		size = "40"
		objfiles = "ctime@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 30 31 C0 B9 0B 00 00 00 8D 54 24 04 89 D7 F3 AB 52 FF 74 24 3C E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 3C 5F C3 }
	condition:
		$pattern
}

rule strlen_ed3aca4bf76582b787a24165936a35da {
	meta:
		aliases = "__GI_strlen, strlen"
		type = "func"
		size = "19"
		objfiles = "strlen@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 8B 7C 24 08 83 C9 FF 31 C0 F2 AE F7 D1 8D 41 FF 5F C3 }
	condition:
		$pattern
}

rule rawmemchr_9d200d63dcd2b2c62fedc0d7c3c4cada {
	meta:
		aliases = "__GI_rawmemchr, rawmemchr"
		type = "func"
		size = "19"
		objfiles = "rawmemchr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 8B 7C 24 08 8B 44 24 0C 83 C9 FF F2 AE 8D 47 FF 5F C3 }
	condition:
		$pattern
}

rule memchr_4ce3ec3ba4f2bdd2149ded835055e6f1 {
	meta:
		aliases = "__GI_memchr, memchr"
		type = "func"
		size = "28"
		objfiles = "memchr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 8B 7C 24 08 8B 44 24 0C 8B 4C 24 10 E3 07 F2 AE 8D 7F FF 74 02 31 FF 89 F8 5F C3 }
	condition:
		$pattern
}

rule vfork_8837c96e046fb66dd5409ab00bac5407 {
	meta:
		aliases = "__GI_vfork, __vfork, vfork"
		type = "func"
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
		type = "func"
		size = "26"
		objfiles = "resolve@libdl.a"
	strings:
		$pattern = { ( CC | 60 ) 8D 44 24 20 FF 70 04 FF 30 E8 ?? ?? ?? ?? 89 44 24 28 83 C4 08 61 C2 04 00 }
	condition:
		$pattern
}

rule canonicalize_file_name_e60f4d60f282709f17914343408003c6 {
	meta:
		aliases = "canonicalize_file_name"
		type = "func"
		size = "37"
		objfiles = "canonicalize@libc.a"
	strings:
		$pattern = { ( CC | 68 ) 00 10 00 00 E8 ?? ?? ?? ?? 5A 31 D2 85 C0 74 11 C6 00 00 50 FF 74 24 08 E8 ?? ?? ?? ?? 89 C2 58 59 89 D0 C3 }
	condition:
		$pattern
}

rule svcudp_create_4d6cf988d3f7d4c5719a88e84b0ac0a6 {
	meta:
		aliases = "__GI_svcudp_create, svcudp_create"
		type = "func"
		size = "23"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 68 ) 60 22 00 00 68 60 22 00 00 FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule clntudp_create_671122b88df312813229260f98c39983 {
	meta:
		aliases = "__GI_clntudp_create, clntudp_create"
		type = "func"
		size = "43"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 68 ) 60 22 00 00 68 60 22 00 00 FF 74 24 20 FF 74 24 20 FF 74 24 20 FF 74 24 20 FF 74 24 20 FF 74 24 20 E8 ?? ?? ?? ?? 83 C4 20 C3 }
	condition:
		$pattern
}

rule mkstemp_9bdfcd0967460f4301ddb91cbab56c6b {
	meta:
		aliases = "mkstemp"
		type = "func"
		size = "20"
		objfiles = "mkstemp@libc.a"
	strings:
		$pattern = { ( CC | 68 ) 80 01 00 00 6A 00 FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule mkstemp64_b8d7b5e976ccd645eede99786004d8c1 {
	meta:
		aliases = "mkstemp64"
		type = "func"
		size = "20"
		objfiles = "mkstemp64@libc.a"
	strings:
		$pattern = { ( CC | 68 ) 80 01 00 00 6A 01 FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule print_and_abort_46e3c90fa919bb61b8b0dcf517a174d2 {
	meta:
		aliases = "print_and_abort"
		type = "func"
		size = "28"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 68 ) ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 01 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule gmtime_d467792ced3a79e4c8fe0b9ae14f7b9a {
	meta:
		aliases = "gmtime"
		type = "func"
		size = "25"
		objfiles = "gmtime@libc.a"
	strings:
		$pattern = { ( CC | 68 ) ?? ?? ?? ?? 6A 00 FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule hdestroy_c97d8f5517fef4824426922a1b3eb9e1 {
	meta:
		aliases = "__pthread_once_fork_parent, __pthread_once_fork_prepare, _flushlbf, hdestroy"
		type = "func"
		size = "12"
		objfiles = "_flushlbf@libc.a, hsearch@libc.a, mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 68 ) ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 C3 }
	condition:
		$pattern
}

rule getlogin_4b4b020f95e78d1c2d908fe427dc4a97 {
	meta:
		aliases = "__GI_getlogin, __open_etc_hosts, getlogin"
		type = "func"
		size = "12"
		objfiles = "read_etc_hosts_r@libc.a, getlogin@libc.a"
	strings:
		$pattern = { ( CC | 68 ) ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A C3 }
	condition:
		$pattern
}

rule seed48_7136705c105fe90cbbb2eabb88b6c03d {
	meta:
		aliases = "__GI_localtime, localtime, seed48"
		type = "func"
		size = "22"
		objfiles = "seed48@libc.a, localtime@libc.a"
	strings:
		$pattern = { ( CC | 68 ) ?? ?? ?? ?? FF 74 24 08 E8 ?? ?? ?? ?? 58 5A B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule srand48_e3da2e975ce2f1c9e82f62d722adb213 {
	meta:
		aliases = "srand48"
		type = "func"
		size = "17"
		objfiles = "srand48@libc.a"
	strings:
		$pattern = { ( CC | 68 ) ?? ?? ?? ?? FF 74 24 08 E8 ?? ?? ?? ?? 58 5A C3 }
	condition:
		$pattern
}

rule inet_ntoa_e214931d143cca1a32199edb31adc4a0 {
	meta:
		aliases = "__GI_asctime, __GI_inet_ntoa, asctime, ether_aton, ether_ntoa, hcreate, inet_ntoa"
		type = "func"
		size = "17"
		objfiles = "asctime@libc.a, inet_ntoa@libc.a, hsearch@libc.a, ether_addr@libc.a"
	strings:
		$pattern = { ( CC | 68 ) ?? ?? ?? ?? FF 74 24 08 E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule strtok_ce767ada53bd455cecd0660edb8a7c87 {
	meta:
		aliases = "__GI_lgamma, __GI_strtok, __ieee754_lgamma, gamma, lgamma, strtok"
		type = "func"
		size = "22"
		objfiles = "strtok@libc.a, e_lgamma_r@libm.a"
	strings:
		$pattern = { ( CC | 68 ) ?? ?? ?? ?? FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule __pthread_once_fork_child_7c30dae3699ee96b226c11f207655386 {
	meta:
		aliases = "__pthread_once_fork_child"
		type = "func"
		size = "59"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 6A ) 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 3D FB FF FF 7F 7F 09 83 C0 04 A3 ?? ?? ?? ?? C3 C7 05 ?? ?? ?? ?? 00 00 00 00 C3 }
	condition:
		$pattern
}

rule msgget_f86836f599d53b455316b5c44b5e9620 {
	meta:
		aliases = "msgget"
		type = "func"
		size = "25"
		objfiles = "msgget@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 6A 00 6A 00 FF 74 24 14 FF 74 24 14 6A 0D E8 ?? ?? ?? ?? 83 C4 18 C3 }
	condition:
		$pattern
}

rule getopt_16692ebea0a8b167125d20849f433e58 {
	meta:
		aliases = "__GI_getopt, getopt"
		type = "func"
		size = "27"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 6A 00 6A 00 FF 74 24 18 FF 74 24 18 FF 74 24 18 E8 ?? ?? ?? ?? 83 C4 18 C3 }
	condition:
		$pattern
}

rule mkfifo_00d6ed0cbb7fa94b02b0342c692a83e5 {
	meta:
		aliases = "mkfifo"
		type = "func"
		size = "25"
		objfiles = "mkfifo@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 6A 00 8B 44 24 10 80 CC 10 50 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule mkfifoat_92a6b67f380c132d42d924f11d4bda7e {
	meta:
		aliases = "mkfifoat"
		type = "func"
		size = "29"
		objfiles = "mkfifoat@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 6A 00 8B 44 24 14 80 CC 10 50 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? 83 C4 14 C3 }
	condition:
		$pattern
}

rule setpgrp_8539b2f936eb87e426dbf4541b8d402d {
	meta:
		aliases = "setpgrp"
		type = "func"
		size = "12"
		objfiles = "setpgrp@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 6A 00 E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule wait_e1443d85905223fdf5cfc41ace8141c5 {
	meta:
		aliases = "__libc_wait, wait"
		type = "func"
		size = "19"
		objfiles = "wait@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 6A 00 FF 74 24 0C 6A FF E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule semget_fea8f9c7124fa989238f23d27fb07a36 {
	meta:
		aliases = "semget"
		type = "func"
		size = "27"
		objfiles = "semget@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 6A 00 FF 74 24 14 FF 74 24 14 FF 74 24 14 6A 02 E8 ?? ?? ?? ?? 83 C4 18 C3 }
	condition:
		$pattern
}

rule shmget_0d2f78588b63745d3a12de642f7a98e2 {
	meta:
		aliases = "shmget"
		type = "func"
		size = "27"
		objfiles = "shmget@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 6A 00 FF 74 24 14 FF 74 24 14 FF 74 24 14 6A 17 E8 ?? ?? ?? ?? 83 C4 18 C3 }
	condition:
		$pattern
}

rule setlinebuf_e639e96ae02203674987e47c0dc2a4e6 {
	meta:
		aliases = "setlinebuf"
		type = "func"
		size = "19"
		objfiles = "setlinebuf@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 6A 01 6A 00 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule __opensock_83a2b38bf0e7dc235b98d073e1747e1a {
	meta:
		aliases = "__opensock"
		type = "func"
		size = "33"
		objfiles = "opensock@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 6A 02 6A 0A E8 ?? ?? ?? ?? 83 C4 0C 85 C0 79 0E 6A 00 6A 02 6A 02 E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule tzset_2e5dd0a140b50499694806fa7840c1be {
	meta:
		aliases = "__GI_tzset, tzset"
		type = "func"
		size = "27"
		objfiles = "tzset@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 E8 ?? ?? ?? ?? 3D FF 4E 98 45 0F 9E C0 0F B6 C0 50 E8 ?? ?? ?? ?? 59 58 C3 }
	condition:
		$pattern
}

rule siggetmask_1d077a490af2358564875b611eb29157 {
	meta:
		aliases = "siggetmask"
		type = "func"
		size = "9"
		objfiles = "siggetmask@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 E8 ?? ?? ?? ?? 5A C3 }
	condition:
		$pattern
}

rule __pthread_initialize_minimal_6d842a476989bd048d42d959fa49be28 {
	meta:
		aliases = "__pthread_initialize_minimal"
		type = "func"
		size = "14"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 6A ) 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 58 C3 }
	condition:
		$pattern
}

rule shmdt_cd087b0b50f42e4229d5ee728adb5356 {
	meta:
		aliases = "shmdt"
		type = "func"
		size = "23"
		objfiles = "shmdt@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 FF 74 24 08 6A 00 6A 00 6A 00 6A 16 E8 ?? ?? ?? ?? 83 C4 18 C3 }
	condition:
		$pattern
}

rule atof_8a7d29a2c350d5db5721be07ba7ff0b1 {
	meta:
		aliases = "atof"
		type = "func"
		size = "14"
		objfiles = "atof@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 FF 74 24 08 E8 ?? ?? ?? ?? 58 5A C3 }
	condition:
		$pattern
}

rule sigpause_0b2bdff5f5301a6617caee89402ffe9b {
	meta:
		aliases = "sigpause"
		type = "func"
		size = "14"
		objfiles = "sigpause@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 FF 74 24 08 E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule sigwait_aa226e82f9c3bfabde1418b3deccdfab {
	meta:
		aliases = "sigwait"
		type = "func"
		size = "34"
		objfiles = "sigwait@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 FF 74 24 08 E8 ?? ?? ?? ?? 89 C2 58 59 B8 01 00 00 00 83 FA FF 74 08 8B 44 24 08 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule futimens_fb0e8b1f7ce6209b272707bb0a07b325 {
	meta:
		aliases = "futimens"
		type = "func"
		size = "21"
		objfiles = "futimens@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 FF 74 24 0C 6A 00 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule semop_94e686792aa4ea5e3b92eb01966efa8c {
	meta:
		aliases = "semop"
		type = "func"
		size = "27"
		objfiles = "semop@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 FF 74 24 0C 6A 00 FF 74 24 18 FF 74 24 14 6A 01 E8 ?? ?? ?? ?? 83 C4 18 C3 }
	condition:
		$pattern
}

rule xdrstdio_setpos_b2a6af6f85e0a468cdf655f7ecbe4d9f {
	meta:
		aliases = "xdrstdio_setpos"
		type = "func"
		size = "27"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 FF 74 24 0C 8B 44 24 0C FF 70 0C E8 ?? ?? ?? ?? F7 D0 C1 E8 1F 83 C4 0C C3 }
	condition:
		$pattern
}

rule wcstold_218c186b4d9e0825b5f6d16570a16a45 {
	meta:
		aliases = "strtold, wcstold"
		type = "func"
		size = "19"
		objfiles = "wcstold@libc.a, strtold@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule msgsnd_d77dbfc0719009ff732c428244105b8f {
	meta:
		aliases = "msgsnd"
		type = "func"
		size = "29"
		objfiles = "msgsnd@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 FF 74 24 0C FF 74 24 18 FF 74 24 18 FF 74 24 14 6A 0B E8 ?? ?? ?? ?? 83 C4 18 C3 }
	condition:
		$pattern
}

rule msgctl_4b44e2435db7757cda2e1fd6d17cec2e {
	meta:
		aliases = "msgctl"
		type = "func"
		size = "31"
		objfiles = "msgctl@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 FF 74 24 10 6A 00 8B 44 24 14 80 CC 01 50 FF 74 24 14 6A 0E E8 ?? ?? ?? ?? 83 C4 18 C3 }
	condition:
		$pattern
}

rule shmctl_e4d61f7b59fa7250819d3bae50355b22 {
	meta:
		aliases = "shmctl"
		type = "func"
		size = "31"
		objfiles = "shmctl@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 FF 74 24 10 6A 00 8B 44 24 14 80 CC 01 50 FF 74 24 14 6A 18 E8 ?? ?? ?? ?? 83 C4 18 C3 }
	condition:
		$pattern
}

rule wcstouq_a324739ecc8f201fcb11afb9bebf3b72 {
	meta:
		aliases = "__GI_strtoul, __GI_waitpid, __libc_waitpid, strtoul, strtoull, strtoumax, strtouq, waitpid, wcstoul, wcstoull, wcstoumax, wcstouq"
		type = "func"
		size = "23"
		objfiles = "wcstoul@libc.a, strtoul@libc.a, waitpid@libc.a, wcstoull@libc.a, strtoull@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 FF 74 24 10 FF 74 24 10 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule getopt_long_95e7d86cfa273507eb54b98c07b53292 {
	meta:
		aliases = "getopt_long"
		type = "func"
		size = "31"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 00 FF 74 24 18 FF 74 24 18 FF 74 24 18 FF 74 24 18 FF 74 24 18 E8 ?? ?? ?? ?? 83 C4 18 C3 }
	condition:
		$pattern
}

rule tcdrain_7f31bfab83c7e80ac18eb675a76212c2 {
	meta:
		aliases = "__libc_tcdrain, tcdrain"
		type = "func"
		size = "20"
		objfiles = "tcdrain@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 01 68 09 54 00 00 FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule wcwidth_4946ca8913dc777e38eb9b08f4bb2f05 {
	meta:
		aliases = "wcwidth"
		type = "func"
		size = "15"
		objfiles = "wcwidth@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 01 8D 44 24 08 50 E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule timelocal_0410fd2bb80bbf0bc944c8d2d2133af7 {
	meta:
		aliases = "__GI_iswalnum, iswalnum, mktime, timelocal"
		type = "func"
		size = "14"
		objfiles = "mktime@libc.a, iswalnum@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 01 FF 74 24 08 E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule wcstoq_fe8e5520a3eef7a03748f1ff8e71080f {
	meta:
		aliases = "__GI_strtol, __GI_strtoll, strtoimax, strtol, strtoll, strtoq, wcstoimax, wcstol, wcstoll, wcstoq"
		type = "func"
		size = "23"
		objfiles = "wcstol@libc.a, strtol@libc.a, strtoll@libc.a, wcstoll@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 01 FF 74 24 10 FF 74 24 10 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule getopt_long_only_44282234019cc0796c935aee1ad799e8 {
	meta:
		aliases = "getopt_long_only"
		type = "func"
		size = "31"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 01 FF 74 24 18 FF 74 24 18 FF 74 24 18 FF 74 24 18 FF 74 24 18 E8 ?? ?? ?? ?? 83 C4 18 C3 }
	condition:
		$pattern
}

rule iswalpha_60617713272f358c39f6fe181a7829f8 {
	meta:
		aliases = "__GI_gethostbyname, gethostbyname, iswalpha"
		type = "func"
		size = "14"
		objfiles = "iswalpha@libc.a, gethostbyname@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 02 FF 74 24 08 E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule rexec_30e859e96bf867a90146b9e46c0f7222 {
	meta:
		aliases = "rexec"
		type = "func"
		size = "35"
		objfiles = "rexec@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 02 FF 74 24 1C FF 74 24 1C FF 74 24 1C FF 74 24 1C FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule iswblank_5e8107a5008a5c5d8fc947f09a04a251 {
	meta:
		aliases = "iswblank"
		type = "func"
		size = "14"
		objfiles = "iswblank@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 03 FF 74 24 08 E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule iswcntrl_7417603aa9a58514d7404e7a8944260e {
	meta:
		aliases = "iswcntrl"
		type = "func"
		size = "14"
		objfiles = "iswcntrl@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 04 FF 74 24 08 E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule svcerr_weakauth_de46a2c8f098f77645720e010a1c1777 {
	meta:
		aliases = "svcerr_weakauth"
		type = "func"
		size = "14"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 05 FF 74 24 08 E8 ?? ?? ?? ?? 58 5A C3 }
	condition:
		$pattern
}

rule iswdigit_e83006ca42bcd5f8a005429c5301f208 {
	meta:
		aliases = "iswdigit"
		type = "func"
		size = "14"
		objfiles = "iswdigit@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 05 FF 74 24 08 E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule iswgraph_5e486d95fe08fa0fdf2bb315f9ea1bad {
	meta:
		aliases = "iswgraph"
		type = "func"
		size = "14"
		objfiles = "iswgraph@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 06 FF 74 24 08 E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule iswlower_5052853c04925b0531827fed4fc59dcb {
	meta:
		aliases = "__GI_iswlower, iswlower"
		type = "func"
		size = "14"
		objfiles = "iswlower@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 07 FF 74 24 08 E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule iswprint_d38784d66d96bfdd9e465c741b60d9f4 {
	meta:
		aliases = "iswprint"
		type = "func"
		size = "14"
		objfiles = "iswprint@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 08 FF 74 24 08 E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule xdr_des_block_f194eb11f766ec3cf45e567062b3b314 {
	meta:
		aliases = "xdr_des_block"
		type = "func"
		size = "19"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 08 FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule iswpunct_4c94741985d0f0335dcc750379f8d214 {
	meta:
		aliases = "iswpunct"
		type = "func"
		size = "14"
		objfiles = "iswpunct@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 09 FF 74 24 08 E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule atoll_40657ce09f1f30b9225c7cb14e45ae11 {
	meta:
		aliases = "__GI_atoi, atoi, atol, atoll"
		type = "func"
		size = "17"
		objfiles = "atol@libc.a, atoll@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 0A 6A 00 FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule iswspace_81824578a70c402e97ec717242bf6047 {
	meta:
		aliases = "__GI_iswspace, iswspace"
		type = "func"
		size = "14"
		objfiles = "iswspace@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 0A FF 74 24 08 E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule iswupper_f03dd08dee06b701b3ac49e6f438e1bf {
	meta:
		aliases = "__GI_iswupper, iswupper"
		type = "func"
		size = "14"
		objfiles = "iswupper@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 0B FF 74 24 08 E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule iswxdigit_81d11b4b6d7bfacaf4d33683705c538b {
	meta:
		aliases = "iswxdigit"
		type = "func"
		size = "14"
		objfiles = "iswxdigit@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 0C FF 74 24 08 E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule ptsname_27a309606127563421877551f0e2f557 {
	meta:
		aliases = "ptsname"
		type = "func"
		size = "33"
		objfiles = "ptsname@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 1E 68 ?? ?? ?? ?? FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C BA ?? ?? ?? ?? 85 C0 74 02 31 D2 89 D0 C3 }
	condition:
		$pattern
}

rule ttyname_8010edb7d42b044a8b02f3e56a1db481 {
	meta:
		aliases = "ttyname"
		type = "func"
		size = "33"
		objfiles = "ttyname@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 20 68 ?? ?? ?? ?? FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C BA ?? ?? ?? ?? 85 C0 74 02 31 D2 89 D0 C3 }
	condition:
		$pattern
}

rule strerror_35abbc3d6542f68153afe4cd3042295f {
	meta:
		aliases = "__GI_strerror, strerror"
		type = "func"
		size = "25"
		objfiles = "strerror@libc.a"
	strings:
		$pattern = { ( CC | 6A ) 32 68 ?? ?? ?? ?? FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule fopen64_dba6fc56a335bccbc0657c0736a115c0 {
	meta:
		aliases = "__GI_fopen64, fopen64"
		type = "func"
		size = "21"
		objfiles = "fopen64@libc.a"
	strings:
		$pattern = { ( CC | 6A ) FE 6A 00 FF 74 24 10 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule fopen_b6bff45319aab59876e06d70684e978f {
	meta:
		aliases = "__GI_fopen, fopen"
		type = "func"
		size = "21"
		objfiles = "fopen@libc.a"
	strings:
		$pattern = { ( CC | 6A ) FF 6A 00 FF 74 24 10 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule xdr_wrapstring_29d319d7e6b435beeb597c27ccef5359 {
	meta:
		aliases = "xdr_wrapstring"
		type = "func"
		size = "27"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 6A ) FF FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C 85 C0 0F 95 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule endusershell_4c1414925b3bcf09f0c06aebecc9df20 {
	meta:
		aliases = "endusershell"
		type = "func"
		size = "106"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { ( CC | 83 ) 3D ?? ?? ?? ?? 00 74 40 A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? EB 0F 83 C0 04 A3 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 59 A1 ?? ?? ?? ?? 85 C0 74 06 8B 10 85 D2 75 E2 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 5A FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 58 C3 }
	condition:
		$pattern
}

rule getusershell_0d4be72d14c89a405cb60c9a7e7197df {
	meta:
		aliases = "getusershell"
		type = "func"
		size = "36"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { ( CC | 83 ) 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 10 85 D2 74 08 83 C0 04 A3 ?? ?? ?? ?? 89 D0 C3 }
	condition:
		$pattern
}

rule _rpc_dtablesize_85c2418f5ec722f9878718e2519e1865 {
	meta:
		aliases = "__GI__rpc_dtablesize, _rpc_dtablesize"
		type = "func"
		size = "25"
		objfiles = "rpc_dtablesize@libc.a"
	strings:
		$pattern = { ( CC | 83 ) 3D ?? ?? ?? ?? 00 75 0A E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule valloc_bee4afb9ecfda494ea3c205608b5dee8 {
	meta:
		aliases = "valloc"
		type = "func"
		size = "37"
		objfiles = "valloc@libc.a"
	strings:
		$pattern = { ( CC | 83 ) 3D ?? ?? ?? ?? 00 75 0A E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? FF 74 24 04 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule __initbuf_e76dd1a8918466fd412c20b664d5204e {
	meta:
		aliases = "__initbuf"
		type = "func"
		size = "40"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 83 ) 3D ?? ?? ?? ?? 00 75 10 68 30 01 00 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 58 83 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __initbuf_b76b1aa07c66029dfc284027b0d25277 {
	meta:
		aliases = "__initbuf"
		type = "func"
		size = "35"
		objfiles = "getnet@libc.a, getproto@libc.a"
	strings:
		$pattern = { ( CC | 83 ) 3D ?? ?? ?? ?? 00 75 19 68 2C 01 00 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 5A 85 C0 75 05 E8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __uClibc_init_57bd80c37f527c73ad3ba562800da4d5 {
	meta:
		aliases = "__GI___uClibc_init, __uClibc_init"
		type = "func"
		size = "48"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { ( CC | 83 ) 3D ?? ?? ?? ?? 00 75 26 C7 05 ?? ?? ?? ?? 00 10 00 00 B8 ?? ?? ?? ?? 85 C0 74 05 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 85 C0 74 05 E9 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule funlockfile_c8ec7981dc8c7ffca74d62d23a333721 {
	meta:
		aliases = "flockfile, ftrylockfile, funlockfile"
		type = "func"
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
		type = "func"
		size = "15"
		objfiles = "wctob@libc.a"
	strings:
		$pattern = { ( CC | 83 ) C8 FF 83 7C 24 04 7F 77 04 8B 44 24 04 C3 }
	condition:
		$pattern
}

rule hsearch_ddeb863da2516d9a01354a45706f3e8d {
	meta:
		aliases = "hsearch"
		type = "func"
		size = "38"
		objfiles = "hsearch@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 68 ?? ?? ?? ?? 8D 44 24 04 50 FF 74 24 18 FF 74 24 18 FF 74 24 18 E8 ?? ?? ?? ?? 8B 44 24 14 83 C4 18 C3 }
	condition:
		$pattern
}

rule getspent_b0755d037b60fb5500574f607e9b1509 {
	meta:
		aliases = "getgrent, getpwent, getspent"
		type = "func"
		size = "34"
		objfiles = "getgrent@libc.a, getpwent@libc.a, getspent@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 89 E0 50 68 00 01 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 10 83 C4 14 C3 }
	condition:
		$pattern
}

rule sgetspent_55f8a496d4b651e19d576b899468cf9d {
	meta:
		aliases = "fgetgrent, fgetpwent, fgetspent, getgrgid, getgrnam, getpwnam, getpwuid, getspnam, sgetspent"
		type = "func"
		size = "38"
		objfiles = "fgetgrent@libc.a, fgetpwent@libc.a, fgetspent@libc.a, getspnam@libc.a, getgrnam@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 89 E0 50 68 00 01 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 18 E8 ?? ?? ?? ?? 8B 44 24 14 83 C4 18 C3 }
	condition:
		$pattern
}

rule tcgetpgrp_b86f33337acd6e90812ac2b03e3cccc0 {
	meta:
		aliases = "__GI_tcgetpgrp, tcgetpgrp"
		type = "func"
		size = "37"
		objfiles = "tcgetpgrp@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 89 E0 50 68 0F 54 00 00 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 0C 83 CA FF 85 C0 78 03 8B 14 24 89 D0 5A C3 }
	condition:
		$pattern
}

rule mrand48_6681456c0ccebd79d735ae3c59217f78 {
	meta:
		aliases = "lrand48, mrand48"
		type = "func"
		size = "29"
		objfiles = "lrand48@libc.a, mrand48@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 89 E0 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 0C 83 C4 10 C3 }
	condition:
		$pattern
}

rule nrand48_df9bc9521ef7022b723480b842632cc1 {
	meta:
		aliases = "jrand48, nrand48"
		type = "func"
		size = "28"
		objfiles = "nrand48@libc.a, jrand48@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 89 E0 50 68 ?? ?? ?? ?? FF 74 24 10 E8 ?? ?? ?? ?? 8B 44 24 0C 83 C4 10 C3 }
	condition:
		$pattern
}

rule inet_addr_3226f4a9d5b8f99eb9dd5631f944505a {
	meta:
		aliases = "__GI_inet_addr, inet_addr"
		type = "func"
		size = "31"
		objfiles = "inet_makeaddr@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 89 E0 50 FF 74 24 0C E8 ?? ?? ?? ?? 59 5A 83 CA FF 85 C0 74 03 8B 14 24 89 D0 5A C3 }
	condition:
		$pattern
}

rule xdrstdio_getlong_3e21e910d07e70c6805182ed96b61bc1 {
	meta:
		aliases = "xdrstdio_getlong"
		type = "func"
		size = "52"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 8B 44 24 08 FF 70 0C 6A 01 6A 04 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 31 D2 48 75 10 8B 04 24 0F C8 8B 54 24 0C 89 02 BA 01 00 00 00 89 D0 59 C3 }
	condition:
		$pattern
}

rule xdrstdio_getint32_5b721bb6f41e7dee476d61fcac71ab1f {
	meta:
		aliases = "xdrstdio_getint32"
		type = "func"
		size = "52"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 8B 44 24 08 FF 70 0C 6A 01 6A 04 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 31 D2 48 75 10 8B 04 24 0F C8 8B 54 24 0C 89 02 BA 01 00 00 00 89 D0 5A C3 }
	condition:
		$pattern
}

rule wcstombs_9632e4c6bd03b576b9f2ccc34882c46b {
	meta:
		aliases = "wcstombs"
		type = "func"
		size = "34"
		objfiles = "wcstombs@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 8B 44 24 0C 89 04 24 6A 00 FF 74 24 14 8D 44 24 08 50 FF 74 24 14 E8 ?? ?? ?? ?? 83 C4 14 C3 }
	condition:
		$pattern
}

rule xdrstdio_putlong_ee168bdd943675c3e8c44169ac168060 {
	meta:
		aliases = "xdrstdio_putint32, xdrstdio_putlong"
		type = "func"
		size = "46"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 8B 44 24 0C 8B 00 0F C8 89 04 24 8B 44 24 08 FF 70 0C 6A 01 6A 04 8D 44 24 0C 50 E8 ?? ?? ?? ?? 48 0F 94 C0 0F B6 C0 83 C4 14 C3 }
	condition:
		$pattern
}

rule inet_makeaddr_e994c8a164485b4220c8c6b99e85e465 {
	meta:
		aliases = "__GI_inet_makeaddr, inet_makeaddr"
		type = "func"
		size = "80"
		objfiles = "inet_addr@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 8B 4C 24 08 8B 54 24 0C 8B 44 24 10 83 FA 7F 77 0A 25 FF FF FF 00 C1 E2 18 EB 22 81 FA FF FF 00 00 77 0A 25 FF FF 00 00 C1 E2 10 EB 10 81 FA FF FF FF 00 77 08 25 FF 00 00 00 C1 E2 08 09 D0 89 04 24 8B 04 24 89 01 89 C8 5A C2 04 00 }
	condition:
		$pattern
}

rule __compare_and_swap_46760c203f45a198cb933aa6404210bb {
	meta:
		aliases = "__compare_and_swap"
		type = "func"
		size = "27"
		objfiles = "pt_machine@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 8B 54 24 08 8B 4C 24 10 8B 44 24 0C F0 0F B1 0A 0F 94 C1 0F B6 C1 5A C3 }
	condition:
		$pattern
}

rule fesetround_2823fa310a8cda272369e88b42e452b5 {
	meta:
		aliases = "fesetround"
		type = "func"
		size = "47"
		objfiles = "fesetround@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 8B 54 24 08 B8 01 00 00 00 F7 C2 FF F3 FF FF 75 19 D9 7C 24 02 66 8B 44 24 02 80 E4 F3 09 D0 66 89 44 24 02 D9 6C 24 02 31 C0 5A C3 }
	condition:
		$pattern
}

rule open64_6e27fa1a3b0055d4fad61e0c8063a637 {
	meta:
		aliases = "__GI_open64, __libc_open64, open64"
		type = "func"
		size = "43"
		objfiles = "open64@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 8B 54 24 0C 31 C0 F6 C2 40 74 0B 8D 44 24 14 89 04 24 8B 44 24 10 50 80 CE 80 52 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule warnx_bad0905bf4c53056c9d6cb34f37f57de {
	meta:
		aliases = "warn, warnx"
		type = "func"
		size = "24"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 8D 44 24 0C 89 04 24 50 FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule wscanf_d49bdeb5a2c59b42a4876d324b1f6480 {
	meta:
		aliases = "__GI_printf, printf, scanf, wprintf, wscanf"
		type = "func"
		size = "30"
		objfiles = "wscanf@libc.a, scanf@libc.a, printf@libc.a, wprintf@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 8D 44 24 0C 89 04 24 50 FF 74 24 0C FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule sprintf_8f72134c6305447e47b2df080ad309d1 {
	meta:
		aliases = "__GI_sprintf, sprintf"
		type = "func"
		size = "30"
		objfiles = "sprintf@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 8D 44 24 10 89 04 24 50 FF 74 24 10 6A FF FF 74 24 14 E8 ?? ?? ?? ?? 83 C4 14 C3 }
	condition:
		$pattern
}

rule errx_9f143f07bfdb3664ba74449340512e6c {
	meta:
		aliases = "err, errx"
		type = "func"
		size = "24"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 8D 44 24 10 89 04 24 50 FF 74 24 10 FF 74 24 10 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule syslog_3674412569e427ab0f649983548971e5 {
	meta:
		aliases = "__GI_asprintf, __GI_fprintf, __GI_fscanf, __GI_sscanf, __GI_syslog, asprintf, dprintf, fprintf, fscanf, fwprintf, fwscanf, sscanf, swscanf, syslog"
		type = "func"
		size = "28"
		objfiles = "dprintf@libc.a, syslog@libc.a, asprintf@libc.a, fwprintf@libc.a, fscanf@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 8D 44 24 10 89 04 24 50 FF 74 24 10 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule swprintf_87fe0f1f1b89a8759ca150cbe5a78e1c {
	meta:
		aliases = "__GI_snprintf, snprintf, swprintf"
		type = "func"
		size = "32"
		objfiles = "swprintf@libc.a, snprintf@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 8D 44 24 14 89 04 24 50 FF 74 24 14 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? 83 C4 14 C3 }
	condition:
		$pattern
}

rule fegetexcept_0e02841e6d081987d2f75f258ea5ef9c {
	meta:
		aliases = "fegetexcept"
		type = "func"
		size = "20"
		objfiles = "fegetexcept@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 9B D9 7C 24 02 0F B7 44 24 02 F7 D0 83 E0 3D 5A C3 }
	condition:
		$pattern
}

rule fedisableexcept_7b998e710b991fb14b8993c79b447827 {
	meta:
		aliases = "fedisableexcept"
		type = "func"
		size = "38"
		objfiles = "fedisblxcpt@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 9B D9 7C 24 02 66 8B 44 24 02 8B 54 24 08 83 E2 3D 09 C2 66 89 54 24 02 D9 6C 24 02 F7 D0 83 E0 3D 5A C3 }
	condition:
		$pattern
}

rule feenableexcept_43c175b667aa44d8cbe6d11944fb30bb {
	meta:
		aliases = "feenableexcept"
		type = "func"
		size = "40"
		objfiles = "feenablxcpt@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 9B D9 7C 24 02 66 8B 44 24 02 8B 54 24 08 83 E2 3D F7 D2 21 C2 66 89 54 24 02 D9 6C 24 02 F7 D0 83 E0 3D 5A C3 }
	condition:
		$pattern
}

rule fegetround_51af1270e7dcd2b09db9242015e8ce94 {
	meta:
		aliases = "fegetround"
		type = "func"
		size = "16"
		objfiles = "fegetround@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 D9 3C 24 8B 04 24 25 00 0C 00 00 5A C3 }
	condition:
		$pattern
}

rule feupdateenv_da2c2b2787401c24376e8a9f5e8c63b9 {
	meta:
		aliases = "feupdateenv"
		type = "func"
		size = "39"
		objfiles = "feupdateenv@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 DD 7C 24 02 66 83 64 24 02 3D FF 74 24 08 E8 ?? ?? ?? ?? 0F B7 44 24 06 50 E8 ?? ?? ?? ?? 31 C0 83 C4 0C C3 }
	condition:
		$pattern
}

rule fegetexceptflag_6991f587c43e9021a20352eee86fbc6d {
	meta:
		aliases = "fegetexceptflag"
		type = "func"
		size = "30"
		objfiles = "fgetexcptflg@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 DD 7C 24 02 8B 44 24 0C 66 23 44 24 02 83 E0 3D 8B 54 24 08 66 89 02 31 C0 5A C3 }
	condition:
		$pattern
}

rule gethostbyname2_25199f8098a8a497dedf01ad89c0d5e9 {
	meta:
		aliases = "__GI_gethostbyname2, gethostbyname2"
		type = "func"
		size = "50"
		objfiles = "gethostbyname2@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 E8 ?? ?? ?? ?? 50 8D 44 24 04 50 68 B8 01 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 20 FF 74 24 20 E8 ?? ?? ?? ?? 8B 44 24 1C 83 C4 20 C3 }
	condition:
		$pattern
}

rule gethostbyaddr_c70efe559458915bc93f497802d925aa {
	meta:
		aliases = "__GI_gethostbyaddr, gethostbyaddr"
		type = "func"
		size = "54"
		objfiles = "gethostbyaddr@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 E8 ?? ?? ?? ?? 50 8D 44 24 04 50 68 B8 01 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 24 FF 74 24 24 FF 74 24 24 E8 ?? ?? ?? ?? 8B 44 24 20 83 C4 24 C3 }
	condition:
		$pattern
}

rule gethostent_3d6d6e8792c5931e5a29cdcc56c6ecd3 {
	meta:
		aliases = "gethostent"
		type = "func"
		size = "39"
		objfiles = "gethostent@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 E8 ?? ?? ?? ?? 50 8D 44 24 04 50 6A 6A 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 14 83 C4 18 C3 }
	condition:
		$pattern
}

rule getprotoent_f9a2eabd2910541c85872a3e2005f9e9 {
	meta:
		aliases = "getprotoent"
		type = "func"
		size = "40"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 E8 ?? ?? ?? ?? 89 E0 50 68 2C 01 00 00 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 10 83 C4 14 C3 }
	condition:
		$pattern
}

rule getprotobynumber_2bfff9c1b3a2263e20d37eabcd209d61 {
	meta:
		aliases = "getprotobyname, getprotobynumber"
		type = "func"
		size = "44"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 E8 ?? ?? ?? ?? 89 E0 50 68 2C 01 00 00 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 18 E8 ?? ?? ?? ?? 8B 44 24 14 83 C4 18 C3 }
	condition:
		$pattern
}

rule getservent_f49fcaf338c7bf0aefa6b263d47d92ea {
	meta:
		aliases = "getservent"
		type = "func"
		size = "40"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 E8 ?? ?? ?? ?? 89 E0 50 68 30 01 00 00 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 10 83 C4 14 C3 }
	condition:
		$pattern
}

rule getservbyport_61e69dcc205699b7325339cd4ed92986 {
	meta:
		aliases = "__GI_getservbyport, getservbyname, getservbyport"
		type = "func"
		size = "48"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 E8 ?? ?? ?? ?? 89 E0 50 68 30 01 00 00 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 8B 44 24 18 83 C4 1C C3 }
	condition:
		$pattern
}

rule get_shm_name_56c810385ff0d9ca4537014e06a7619e {
	meta:
		aliases = "get_shm_name"
		type = "func"
		size = "43"
		objfiles = "shm@librt.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 EB 01 40 80 38 2F 74 FA 50 68 ?? ?? ?? ?? 8D 44 24 08 50 E8 ?? ?? ?? ?? 83 C4 0C 31 D2 85 C0 78 03 8B 14 24 89 D0 5A C3 }
	condition:
		$pattern
}

rule dysize_15d48c80523ddb7caabef0239be11864 {
	meta:
		aliases = "dysize"
		type = "func"
		size = "59"
		objfiles = "dysize@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 F6 44 24 08 03 75 2A BA 64 00 00 00 8B 44 24 08 89 D1 99 F7 F9 85 D2 75 11 66 BA 90 01 8B 44 24 08 89 D1 99 F7 F9 85 D2 75 07 B8 6E 01 00 00 EB 05 B8 6D 01 00 00 5A C3 }
	condition:
		$pattern
}

rule getw_382e09729c1817d7ac1b5e08d0635ccd {
	meta:
		aliases = "getw"
		type = "func"
		size = "38"
		objfiles = "getw@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 FF 74 24 08 6A 01 6A 04 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 74 03 8B 14 24 89 D0 5A C3 }
	condition:
		$pattern
}

rule scalbnf_52f7a84bc3ab9460e167cd68ace97b53 {
	meta:
		aliases = "frexpf, ldexpf, scalbnf"
		type = "func"
		size = "34"
		objfiles = "frexpf@libm.a, scalbnf@libm.a, ldexpf@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 04 FF 74 24 0C D9 44 24 0C 83 EC 08 DD 1C 24 E8 ?? ?? ?? ?? D9 5C 24 0C D9 44 24 0C 83 C4 10 C3 }
	condition:
		$pattern
}

rule wcstof_8a2523e8a23a59f0c88500a8ca4cd794 {
	meta:
		aliases = "__GI_strtof, __GI_wcstof, strtof, wcstof"
		type = "func"
		size = "49"
		objfiles = "wcstof@libc.a, strtof@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 08 6A 00 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? D9 54 24 0C 83 EC 18 DB 7C 24 0C D9 44 24 24 DB 3C 24 E8 ?? ?? ?? ?? D9 44 24 24 83 C4 2C C3 }
	condition:
		$pattern
}

rule drand48_339febe4395e43be7a4d17d8d3664a2b {
	meta:
		aliases = "drand48"
		type = "func"
		size = "29"
		objfiles = "drand48@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 08 89 E0 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? DD 44 24 0C 83 C4 14 C3 }
	condition:
		$pattern
}

rule erand48_ab1c9cd73a2f5006ae51d2020c615116 {
	meta:
		aliases = "erand48"
		type = "func"
		size = "28"
		objfiles = "erand48@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 08 89 E0 50 68 ?? ?? ?? ?? FF 74 24 14 E8 ?? ?? ?? ?? DD 44 24 0C 83 C4 14 C3 }
	condition:
		$pattern
}

rule getdtablesize_90b2f2c2661b18b66f57c4157bd76f83 {
	meta:
		aliases = "__GI_getdtablesize, getdtablesize"
		type = "func"
		size = "32"
		objfiles = "getdtablesize@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 08 89 E0 50 6A 07 E8 ?? ?? ?? ?? 5A 59 BA 00 01 00 00 85 C0 78 03 8B 14 24 89 D0 5A 59 C3 }
	condition:
		$pattern
}

rule listen_e1486ac3ad13e0438cf99c5cdbd757f6 {
	meta:
		aliases = "__GI_listen, listen"
		type = "func"
		size = "32"
		objfiles = "listen@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 08 8B 44 24 0C 89 04 24 8B 44 24 10 89 44 24 04 89 E0 50 6A 04 E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule shutdown_217490100ffe3ee0246d28ddf553914c {
	meta:
		aliases = "shutdown"
		type = "func"
		size = "32"
		objfiles = "shutdown@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 08 8B 44 24 0C 89 04 24 8B 44 24 10 89 44 24 04 89 E0 50 6A 0D E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule usleep_7dce7a09dd287351a9919743cfa9b973 {
	meta:
		aliases = "usleep"
		type = "func"
		size = "47"
		objfiles = "usleep@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 08 8B 44 24 0C BA 40 42 0F 00 89 D1 31 D2 F7 F1 89 04 24 69 D2 E8 03 00 00 89 54 24 04 6A 00 8D 44 24 04 50 E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule msgrcv_7b97b02f1a3cff3c4c1732edb1915038 {
	meta:
		aliases = "msgrcv"
		type = "func"
		size = "48"
		objfiles = "msgrcv@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 08 8B 44 24 18 89 44 24 04 8B 44 24 10 89 04 24 6A 00 8D 44 24 04 50 FF 74 24 24 FF 74 24 20 FF 74 24 1C 6A 0C E8 ?? ?? ?? ?? 83 C4 20 C3 }
	condition:
		$pattern
}

rule setrlimit64_70033876ff8d9ee9f0fa63a7f9d80ae9 {
	meta:
		aliases = "setrlimit64"
		type = "func"
		size = "80"
		objfiles = "setrlimit64@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 08 8B 4C 24 10 8B 01 8B 51 04 83 FA 00 77 05 83 F8 FE 76 09 C7 04 24 FF FF FF FF EB 03 89 04 24 8B 41 08 8B 51 0C 83 FA 00 77 05 83 F8 FE 76 0A C7 44 24 04 FF FF FF FF EB 04 89 44 24 04 89 E0 50 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule semctl_a815ddd57198c178b355d2bc551d62bb {
	meta:
		aliases = "semctl"
		type = "func"
		size = "52"
		objfiles = "semctl@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 08 8D 44 24 1C 89 04 24 8B 44 24 18 89 44 24 04 6A 00 8D 44 24 08 50 8B 44 24 1C 80 CC 01 50 FF 74 24 1C FF 74 24 1C 6A 03 E8 ?? ?? ?? ?? 83 C4 20 C3 }
	condition:
		$pattern
}

rule logb_a3671bd408dde00a7113e2fcab16cd08 {
	meta:
		aliases = "__GI_logb, logb"
		type = "func"
		size = "92"
		objfiles = "s_logb@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 08 DD 44 24 0C DD 14 24 8B 44 24 04 25 FF FF FF 7F 8B 14 24 09 C2 75 15 83 EC 08 DD 1C 24 E8 ?? ?? ?? ?? 59 58 D8 3D ?? ?? ?? ?? EB 2A DD D8 3D FF FF EF 7F 7E 08 DD 44 24 0C D8 C8 EB 19 C1 F8 14 75 08 D9 05 ?? ?? ?? ?? EB 0C 2D FF 03 00 00 50 DB 04 24 83 C4 04 58 5A C3 }
	condition:
		$pattern
}

rule __isnan_5dbc52f56dac7dcce0f5c7447d891486 {
	meta:
		aliases = "__GI___isnan, __isnan"
		type = "func"
		size = "45"
		objfiles = "s_isnan@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 08 DD 44 24 0C DD 1C 24 8B 14 24 F7 DA 0B 14 24 C1 EA 1F 8B 44 24 04 25 FF FF FF 7F 09 C2 B8 00 00 F0 7F 29 D0 C1 E8 1F 5A 59 C3 }
	condition:
		$pattern
}

rule __finite_ce9eb944c626935fdb87885be0b5d84a {
	meta:
		aliases = "__GI___finite, __finite"
		type = "func"
		size = "29"
		objfiles = "s_finite@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 08 DD 44 24 0C DD 1C 24 8B 44 24 04 0D FF FF 0F 80 40 0F 95 C0 0F B6 C0 5A 59 C3 }
	condition:
		$pattern
}

rule __signbit_83d5f0e8f572d2ea1eb86ba5936ed863 {
	meta:
		aliases = "__GI___signbit, __signbit"
		type = "func"
		size = "22"
		objfiles = "s_signbit@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 08 DD 44 24 0C DD 1C 24 8B 44 24 04 25 00 00 00 80 5A 59 C3 }
	condition:
		$pattern
}

rule __isinf_386028e5e6e9fa89335cefe6eb3ee9ed {
	meta:
		aliases = "__GI___isinf, __isinf"
		type = "func"
		size = "50"
		objfiles = "s_isinf@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 08 DD 44 24 0C DD 1C 24 8B 4C 24 04 89 CA 81 E2 FF FF FF 7F 81 F2 00 00 F0 7F 0B 14 24 89 D0 F7 D8 09 D0 C1 F8 1F F7 D0 C1 F9 1E 21 C8 5A 59 C3 }
	condition:
		$pattern
}

rule getnetent_9585ddc1daca27edf79ae541eac498ed {
	meta:
		aliases = "getnetent"
		type = "func"
		size = "45"
		objfiles = "getnet@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 08 E8 ?? ?? ?? ?? 89 E0 50 8D 44 24 08 50 68 2C 01 00 00 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 18 83 C4 1C C3 }
	condition:
		$pattern
}

rule getnetbyname_c9fd7da86fdf4718b4168cc6e0621daf {
	meta:
		aliases = "getnetbyname"
		type = "func"
		size = "49"
		objfiles = "getnet@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 08 E8 ?? ?? ?? ?? 89 E0 50 8D 44 24 08 50 68 2C 01 00 00 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 20 E8 ?? ?? ?? ?? 8B 44 24 1C 83 C4 20 C3 }
	condition:
		$pattern
}

rule getnetbyaddr_3d475a0af2c18b60515bacfaf67d8627 {
	meta:
		aliases = "getnetbyaddr"
		type = "func"
		size = "53"
		objfiles = "getnet@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 08 E8 ?? ?? ?? ?? 89 E0 50 8D 44 24 08 50 68 2C 01 00 00 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 24 FF 74 24 24 E8 ?? ?? ?? ?? 8B 44 24 20 83 C4 24 C3 }
	condition:
		$pattern
}

rule socket_48d3f7eaed9089438bad450058349aa7 {
	meta:
		aliases = "__GI_socket, socket"
		type = "func"
		size = "40"
		objfiles = "socket@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 10 89 04 24 8B 44 24 14 89 44 24 04 8B 44 24 18 89 44 24 08 89 E0 50 6A 01 E8 ?? ?? ?? ?? 83 C4 14 C3 }
	condition:
		$pattern
}

rule bind_8d867ef4aadcd5f6ff4837defeaacbba {
	meta:
		aliases = "__GI_bind, bind"
		type = "func"
		size = "40"
		objfiles = "bind@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 10 89 04 24 8B 44 24 14 89 44 24 04 8B 44 24 18 89 44 24 08 89 E0 50 6A 02 E8 ?? ?? ?? ?? 83 C4 14 C3 }
	condition:
		$pattern
}

rule connect_391ad6447a9e0b5b8c769dfc035016cc {
	meta:
		aliases = "__GI_connect, __libc_connect, connect"
		type = "func"
		size = "40"
		objfiles = "connect@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 10 89 04 24 8B 44 24 14 89 44 24 04 8B 44 24 18 89 44 24 08 89 E0 50 6A 03 E8 ?? ?? ?? ?? 83 C4 14 C3 }
	condition:
		$pattern
}

rule accept_078c7229578416c75068cad7383ac69c {
	meta:
		aliases = "__GI_accept, __libc_accept, accept"
		type = "func"
		size = "40"
		objfiles = "accept@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 10 89 04 24 8B 44 24 14 89 44 24 04 8B 44 24 18 89 44 24 08 89 E0 50 6A 05 E8 ?? ?? ?? ?? 83 C4 14 C3 }
	condition:
		$pattern
}

rule getsockname_dca9f8ddea1e838d4cbecf34b117f453 {
	meta:
		aliases = "__GI_getsockname, getsockname"
		type = "func"
		size = "40"
		objfiles = "getsockname@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 10 89 04 24 8B 44 24 14 89 44 24 04 8B 44 24 18 89 44 24 08 89 E0 50 6A 06 E8 ?? ?? ?? ?? 83 C4 14 C3 }
	condition:
		$pattern
}

rule getpeername_a51a10ba9fa5b85e89d4311b558be934 {
	meta:
		aliases = "getpeername"
		type = "func"
		size = "40"
		objfiles = "getpeername@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 10 89 04 24 8B 44 24 14 89 44 24 04 8B 44 24 18 89 44 24 08 89 E0 50 6A 07 E8 ?? ?? ?? ?? 83 C4 14 C3 }
	condition:
		$pattern
}

rule sendmsg_33231d5410bb15145c0551f9d9f4c64b {
	meta:
		aliases = "__GI_sendmsg, __libc_sendmsg, sendmsg"
		type = "func"
		size = "40"
		objfiles = "sendmsg@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 10 89 04 24 8B 44 24 14 89 44 24 04 8B 44 24 18 89 44 24 08 89 E0 50 6A 10 E8 ?? ?? ?? ?? 83 C4 14 C3 }
	condition:
		$pattern
}

rule recvmsg_e0a90a0336eb1eecaa6c0087d3ce57b1 {
	meta:
		aliases = "__GI_recvmsg, __libc_recvmsg, recvmsg"
		type = "func"
		size = "40"
		objfiles = "recvmsg@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 10 89 04 24 8B 44 24 14 89 44 24 04 8B 44 24 18 89 44 24 08 89 E0 50 6A 11 E8 ?? ?? ?? ?? 83 C4 14 C3 }
	condition:
		$pattern
}

rule mbstowcs_6b23fe567f501d39235ab0842ad46ead {
	meta:
		aliases = "mbstowcs"
		type = "func"
		size = "43"
		objfiles = "mbstowcs@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 14 89 44 24 08 C7 04 24 00 00 00 00 89 E0 50 FF 74 24 1C 8D 44 24 10 50 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule modff_b5516a33441ce8ac3a5816a833db3ac8 {
	meta:
		aliases = "modff"
		type = "func"
		size = "45"
		objfiles = "modff@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8D 44 24 04 50 D9 44 24 14 83 EC 08 DD 1C 24 E8 ?? ?? ?? ?? 8B 44 24 20 DD 44 24 10 D9 18 D9 5C 24 0C D9 44 24 0C 83 C4 18 C3 }
	condition:
		$pattern
}

rule truncf_237deda38afdc1ba6e02b05f725d180f {
	meta:
		aliases = "acosf, acoshf, asinf, asinhf, atanf, atanhf, cbrtf, ceilf, cosf, coshf, erfcf, erff, exp2f, expf, expm1f, fabsf, floorf, gammaf, lgammaf, log10f, log1pf, log2f, logbf, logf, rintf, roundf, significandf, sinf, sinhf, sqrtf, tanf, tanhf, truncf"
		type = "func"
		size = "27"
		objfiles = "floorf@libm.a, sinf@libm.a, gammaf@libm.a, erff@libm.a, asinf@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C D9 44 24 10 DD 1C 24 E8 ?? ?? ?? ?? D9 5C 24 08 D9 44 24 08 83 C4 0C C3 }
	condition:
		$pattern
}

rule wcstod_dabd39a3a649dc519b1084bccffdb2ef {
	meta:
		aliases = "__GI_strtod, strtod, wcstod"
		type = "func"
		size = "49"
		objfiles = "wcstod@libc.a, strtod@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 6A 00 FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? DD 54 24 0C 83 EC 18 DB 7C 24 0C DD 44 24 24 DB 3C 24 E8 ?? ?? ?? ?? DD 44 24 24 83 C4 34 C3 }
	condition:
		$pattern
}

rule clock_bdbd77890402f3c6f39292b332f8e073 {
	meta:
		aliases = "clock"
		type = "func"
		size = "34"
		objfiles = "clock@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 89 E0 50 E8 ?? ?? ?? ?? 8B 44 24 04 03 44 24 08 69 C0 10 27 00 00 25 FF FF FF 7F 83 C4 14 C3 }
	condition:
		$pattern
}

rule socketpair_cc3ef70ae2de36d9cb6bb9267fa6e89f {
	meta:
		aliases = "socketpair"
		type = "func"
		size = "48"
		objfiles = "socketpair@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 8B 44 24 14 89 04 24 8B 44 24 18 89 44 24 04 8B 44 24 1C 89 44 24 08 8B 44 24 20 89 44 24 0C 89 E0 50 6A 08 E8 ?? ?? ?? ?? 83 C4 18 C3 }
	condition:
		$pattern
}

rule send_07dbfb200062873ba35d40d012be56c2 {
	meta:
		aliases = "__GI_send, __libc_send, send"
		type = "func"
		size = "48"
		objfiles = "send@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 8B 44 24 14 89 04 24 8B 44 24 18 89 44 24 04 8B 44 24 1C 89 44 24 08 8B 44 24 20 89 44 24 0C 89 E0 50 6A 09 E8 ?? ?? ?? ?? 83 C4 18 C3 }
	condition:
		$pattern
}

rule recv_64d8a44c13c950ea781c6cd180b4b6b9 {
	meta:
		aliases = "__GI_recv, __libc_recv, recv"
		type = "func"
		size = "48"
		objfiles = "recv@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 8B 44 24 14 89 04 24 8B 44 24 18 89 44 24 04 8B 44 24 1C 89 44 24 08 8B 44 24 20 89 44 24 0C 89 E0 50 6A 0A E8 ?? ?? ?? ?? 83 C4 18 C3 }
	condition:
		$pattern
}

rule accept4_b206a75db3148e9b2dea3fdbba7fa0b1 {
	meta:
		aliases = "accept4"
		type = "func"
		size = "48"
		objfiles = "accept4@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 8B 44 24 14 89 04 24 8B 44 24 18 89 44 24 04 8B 44 24 1C 89 44 24 08 8B 44 24 20 89 44 24 0C 89 E0 50 6A 12 E8 ?? ?? ?? ?? 83 C4 18 C3 }
	condition:
		$pattern
}

rule lutimes_a8c2ed503ea11309aa8c6c79084a5a6e {
	meta:
		aliases = "lutimes"
		type = "func"
		size = "114"
		objfiles = "lutimes@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 8B 4C 24 18 85 C9 74 4D 81 79 04 3F 42 0F 00 77 0F 8B 51 0C 85 D2 78 08 81 FA 3F 42 0F 00 7E 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 3B 8B 01 89 04 24 69 41 04 E8 03 00 00 89 44 24 04 8B 41 08 89 44 24 08 69 C2 E8 03 00 00 89 44 24 0C 89 E0 EB 02 31 C0 68 00 01 00 00 50 FF 74 24 1C 6A 9C E8 ?? ?? ?? ?? 83 C4 10 83 C4 10 C3 }
	condition:
		$pattern
}

rule sigblock_d231928d5e4b1454773d22f622fcb9fe {
	meta:
		aliases = "__GI_sigblock, sigblock"
		type = "func"
		size = "42"
		objfiles = "sigblock@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 C7 44 24 0C 00 00 00 00 8B 44 24 14 89 44 24 08 89 E0 50 8D 44 24 0C 50 6A 00 E8 ?? ?? ?? ?? 8B 44 24 0C 83 C4 1C C3 }
	condition:
		$pattern
}

rule sigsetmask_c82be1d4f89c26bd5e34abb4b62d4de6 {
	meta:
		aliases = "__GI_sigsetmask, sigsetmask"
		type = "func"
		size = "42"
		objfiles = "sigsetmask@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 C7 44 24 0C 00 00 00 00 8B 44 24 14 89 44 24 08 89 E0 50 8D 44 24 0C 50 6A 02 E8 ?? ?? ?? ?? 8B 44 24 0C 83 C4 1C C3 }
	condition:
		$pattern
}

rule __kernel_sin_e17f48c80fffe3d2087ad51781ae1b1d {
	meta:
		aliases = "__kernel_sin"
		type = "func"
		size = "192"
		objfiles = "k_sin@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 DD 44 24 14 DD 14 24 8B 44 24 04 25 FF FF FF 7F 3D FF FF 3F 3E 7F 27 D9 7C 24 0E 66 8B 44 24 0E 80 CC 0C 66 89 44 24 0C D9 6C 24 0C DB 5C 24 08 D9 6C 24 0E 8B 44 24 08 85 C0 74 79 EB 02 DD D8 DD 44 24 14 D8 C8 DD 44 24 14 D8 C9 DD 05 ?? ?? ?? ?? D8 CA DC 25 ?? ?? ?? ?? D8 CA DC 05 ?? ?? ?? ?? D8 CA DC 25 ?? ?? ?? ?? D8 CA DC 05 ?? ?? ?? ?? 83 7C 24 24 00 75 12 DE CA D9 C9 DC 25 ?? ?? ?? ?? DE C9 DC 44 24 14 EB 26 DD 44 24 1C D8 0D ?? ?? ?? ?? D9 C9 D8 CA DE E9 DE CA D9 C9 DC 64 24 1C D9 C9 DC 0D ?? ?? ?? ?? DE C1 DC 6C 24 14 DD 5C 24 14 DD 44 24 14 83 C4 10 C3 }
	condition:
		$pattern
}

rule fabs_67d4c36ed885bd2f48ec733bd7370a67 {
	meta:
		aliases = "__GI_fabs, fabs"
		type = "func"
		size = "34"
		objfiles = "s_fabs@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 DD 44 24 14 DD 54 24 08 DD 1C 24 8B 44 24 0C 25 FF FF FF 7F 89 44 24 04 DD 04 24 83 C4 10 C3 }
	condition:
		$pattern
}

rule copysign_b2b071703f26a313e88c9d6050f340df {
	meta:
		aliases = "__GI_copysign, copysign"
		type = "func"
		size = "46"
		objfiles = "s_copysign@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 DD 44 24 14 DD 54 24 08 DD 1C 24 8B 54 24 20 81 E2 00 00 00 80 8B 44 24 0C 25 FF FF FF 7F 09 C2 89 54 24 04 DD 04 24 83 C4 10 C3 }
	condition:
		$pattern
}

rule setsockopt_e3000f0a40016e70ff62149ef4f5194a {
	meta:
		aliases = "__GI_setsockopt, setsockopt"
		type = "func"
		size = "56"
		objfiles = "setsockopt@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 8B 44 24 18 89 04 24 8B 44 24 1C 89 44 24 04 8B 44 24 20 89 44 24 08 8B 44 24 24 89 44 24 0C 8B 44 24 28 89 44 24 10 89 E0 50 6A 0E E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule getsockopt_592bf63b30180e9d14a68d4b03b924e6 {
	meta:
		aliases = "getsockopt"
		type = "func"
		size = "56"
		objfiles = "getsockopt@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 8B 44 24 18 89 04 24 8B 44 24 1C 89 44 24 04 8B 44 24 20 89 44 24 08 8B 44 24 24 89 44 24 0C 8B 44 24 28 89 44 24 10 89 E0 50 6A 0F E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule cargf_6180aeab131b4aa2b8e9d449f81dd209 {
	meta:
		aliases = "cargf"
		type = "func"
		size = "35"
		objfiles = "cargf@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 D9 44 24 18 D9 44 24 1C DD 5C 24 08 DD 1C 24 E8 ?? ?? ?? ?? D9 5C 24 10 D9 44 24 10 83 C4 14 C3 }
	condition:
		$pattern
}

rule scalbf_d4f7c0b3360f99708eca867df6e90175 {
	meta:
		aliases = "atan2f, copysignf, fmodf, hypotf, powf, remainderf, scalbf"
		type = "func"
		size = "35"
		objfiles = "copysignf@libm.a, hypotf@libm.a, atan2f@libm.a, fmodf@libm.a, remainderf@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 D9 44 24 1C DD 5C 24 08 D9 44 24 18 DD 1C 24 E8 ?? ?? ?? ?? D9 5C 24 10 D9 44 24 10 83 C4 14 C3 }
	condition:
		$pattern
}

rule sendto_bfdff1979e67bfb60a49e18003972120 {
	meta:
		aliases = "__GI_sendto, __libc_sendto, sendto"
		type = "func"
		size = "64"
		objfiles = "sendto@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 8B 44 24 1C 89 04 24 8B 44 24 20 89 44 24 04 8B 44 24 24 89 44 24 08 8B 44 24 28 89 44 24 0C 8B 44 24 2C 89 44 24 10 8B 44 24 30 89 44 24 14 89 E0 50 6A 0B E8 ?? ?? ?? ?? 83 C4 20 C3 }
	condition:
		$pattern
}

rule recvfrom_1e269ffd214f9efcaee9dfdb8b996d42 {
	meta:
		aliases = "__GI_recvfrom, __libc_recvfrom, recvfrom"
		type = "func"
		size = "64"
		objfiles = "recvfrom@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 8B 44 24 1C 89 04 24 8B 44 24 20 89 44 24 04 8B 44 24 24 89 44 24 08 8B 44 24 28 89 44 24 0C 8B 44 24 2C 89 44 24 10 8B 44 24 30 89 44 24 14 89 E0 50 6A 0C E8 ?? ?? ?? ?? 83 C4 20 C3 }
	condition:
		$pattern
}

rule wcrtomb_eb0ee40fa19d3987fbf282b06a8ff151 {
	meta:
		aliases = "__GI_wcrtomb, wcrtomb"
		type = "func"
		size = "63"
		objfiles = "wcrtomb@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 8B 54 24 1C 8B 4C 24 20 85 D2 75 04 89 E2 31 C9 8D 44 24 14 89 44 24 10 89 4C 24 14 FF 74 24 24 6A 10 6A 01 8D 44 24 1C 50 52 E8 ?? ?? ?? ?? 83 C4 14 85 C0 75 02 B0 01 83 C4 18 C3 }
	condition:
		$pattern
}

rule __kernel_cos_56a02bb7829de470655099dcbf420f2b {
	meta:
		aliases = "__kernel_cos"
		type = "func"
		size = "254"
		objfiles = "k_cos@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 C7 04 24 00 00 00 00 C7 44 24 04 00 00 00 00 DD 44 24 1C DD 54 24 08 8B 54 24 0C 81 E2 FF FF FF 7F 81 FA FF FF 3F 3E 7F 2C D9 7C 24 16 66 8B 44 24 16 80 CC 0C 66 89 44 24 14 D9 6C 24 14 DB 5C 24 10 D9 6C 24 16 8B 44 24 10 85 C0 75 09 D9 E8 E9 A2 00 00 00 DD D8 DD 44 24 1C D8 C8 DD 05 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 81 FA 32 33 D3 3F 7F 1C D9 C1 D8 0D ?? ?? ?? ?? D9 CA DE C9 DD 44 24 1C DC 4C 24 24 DE E9 DE E9 D9 E8 EB 44 81 FA 00 00 E9 3F 7E 08 D9 05 ?? ?? ?? ?? EB 14 81 EA 00 00 }
	condition:
		$pattern
}

rule xdr_free_9c6aa7c22a5c3c58d0bf6cb6484d5a47 {
	meta:
		aliases = "xdr_free"
		type = "func"
		size = "27"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 C7 04 24 02 00 00 00 FF 74 24 20 8D 44 24 04 50 FF 54 24 24 83 C4 20 C3 }
	condition:
		$pattern
}

rule cos_f3f7494184c6322a4edfc75713bc53e1 {
	meta:
		aliases = "__GI_cos, cos"
		type = "func"
		size = "204"
		objfiles = "s_cos@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 DD 44 24 1C DD 1C 24 8B 44 24 04 25 FF FF FF 7F 3D FB 21 E9 3F 7F 0E 6A 00 6A 00 FF 74 24 28 FF 74 24 28 EB 48 3D FF FF EF 7F 7E 0B DD 44 24 1C D8 E0 E9 8E 00 00 00 8D 44 24 08 50 FF 74 24 24 FF 74 24 24 E8 ?? ?? ?? ?? 83 C4 0C 83 E0 03 83 F8 01 74 23 83 F8 02 74 39 85 C0 75 4E FF 74 24 14 FF 74 24 14 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? 83 C4 10 EB 4E 6A 01 FF 74 24 18 FF 74 24 18 FF 74 24 18 FF 74 24 18 E8 ?? ?? ?? ?? D9 E0 EB 30 FF 74 24 14 FF 74 24 14 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? D9 E0 EB C7 6A 01 FF 74 24 18 FF 74 24 18 FF 74 24 18 FF 74 24 18 E8 ?? ?? ?? ?? 83 C4 14 }
	condition:
		$pattern
}

rule sin_6b31e29a58e0c42c0df534d96ad32c11 {
	meta:
		aliases = "__GI_sin, sin"
		type = "func"
		size = "206"
		objfiles = "s_sin@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 DD 44 24 1C DD 1C 24 8B 44 24 04 25 FF FF FF 7F 3D FB 21 E9 3F 7F 10 6A 00 6A 00 6A 00 FF 74 24 2C FF 74 24 2C EB 4A 3D FF FF EF 7F 7E 0B DD 44 24 1C D8 E0 E9 8E 00 00 00 8D 44 24 08 50 FF 74 24 24 FF 74 24 24 E8 ?? ?? ?? ?? 83 C4 0C 83 E0 03 83 F8 01 74 25 83 F8 02 74 37 85 C0 75 4E 6A 01 FF 74 24 18 FF 74 24 18 FF 74 24 18 FF 74 24 18 E8 ?? ?? ?? ?? 83 C4 14 EB 4C FF 74 24 14 FF 74 24 14 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? EB 32 6A 01 FF 74 24 18 FF 74 24 18 FF 74 24 18 FF 74 24 18 E8 ?? ?? ?? ?? D9 E0 EB C9 FF 74 24 14 FF 74 24 14 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? D9 E0 83 }
	condition:
		$pattern
}

rule tan_951073aa1c1922cd218edaee463f6f7b {
	meta:
		aliases = "__GI_tan, tan"
		type = "func"
		size = "124"
		objfiles = "s_tan@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 DD 44 24 1C DD 1C 24 8B 44 24 04 25 FF FF FF 7F 3D FB 21 E9 3F 7F 18 6A 01 6A 00 6A 00 FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 14 EB 46 3D FF FF EF 7F 7E 08 DD 44 24 1C D8 E0 EB 37 8D 44 24 08 50 FF 74 24 24 FF 74 24 24 E8 ?? ?? ?? ?? 83 E0 01 01 C0 BA 01 00 00 00 29 C2 52 FF 74 24 24 FF 74 24 24 FF 74 24 24 FF 74 24 24 E8 ?? ?? ?? ?? 83 C4 20 83 C4 18 C3 }
	condition:
		$pattern
}

rule ilogb_f981f57ab5578ca886c1cf24dbac0f04 {
	meta:
		aliases = "__GI_ilogb, ilogb"
		type = "func"
		size = "128"
		objfiles = "s_ilogb@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 DD 44 24 1C DD 54 24 10 8B 54 24 14 81 E2 FF FF FF 7F 81 FA FF FF 0F 00 7F 2B DD 5C 24 08 8B 4C 24 08 89 D0 09 C8 74 4C B8 ED FB FF FF 85 D2 74 0E 89 D1 C1 E1 0B 66 B8 02 FC EB 03 48 01 C9 85 C9 7F F9 EB 34 DD D8 81 FA FF FF EF 7F 7F 0B C1 FA 14 8D 82 01 FC FF FF EB 1F DD 44 24 1C DD 1C 24 81 FA 00 00 F0 7F 75 0B B8 FF FF FF 7F 83 3C 24 00 74 05 B8 00 00 00 80 83 C4 18 C3 }
	condition:
		$pattern
}

rule feraiseexcept_fbb73d66c49dab17863fcac4f86762c5 {
	meta:
		aliases = "__GI_feraiseexcept, feraiseexcept"
		type = "func"
		size = "88"
		objfiles = "fraiseexcpt@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8B 44 24 20 A8 01 74 07 D9 EE D8 F0 9B DD D8 A8 04 74 09 D9 EE D9 E8 DE F1 9B DD D8 A8 08 74 0D D9 34 24 66 83 4C 24 04 08 D9 24 24 9B A8 10 74 0D D9 34 24 66 83 4C 24 04 10 D9 24 24 9B A8 20 74 0D D9 34 24 66 83 4C 24 04 20 D9 24 24 9B 31 C0 83 C4 1C C3 }
	condition:
		$pattern
}

rule feholdexcept_ac84656d58f34df529e8663c4d83876f {
	meta:
		aliases = "feholdexcept"
		type = "func"
		size = "42"
		objfiles = "feholdexcpt@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C D9 34 24 89 E0 6A 1C 50 FF 74 24 28 E8 ?? ?? ?? ?? 66 83 4C 24 0C 3F 66 83 64 24 10 C0 D9 64 24 0C 31 C0 83 C4 28 C3 }
	condition:
		$pattern
}

rule feclearexcept_c68c50b2cbd32bb98c6aa4ffd903067f {
	meta:
		aliases = "feclearexcept"
		type = "func"
		size = "30"
		objfiles = "fclrexcpt@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C D9 34 24 8B 44 24 20 83 E0 3D 83 F0 3D 66 21 44 24 04 D9 24 24 31 C0 83 C4 1C C3 }
	condition:
		$pattern
}

rule fesetexceptflag_92487357eab8d64a7c973098e39a90e1 {
	meta:
		aliases = "fesetexceptflag"
		type = "func"
		size = "47"
		objfiles = "fsetexcptflg@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C D9 34 24 8B 44 24 24 89 C2 83 E2 3D F7 D2 23 54 24 04 8B 4C 24 20 66 23 01 83 E0 3D 09 C2 66 89 54 24 04 D9 24 24 31 C0 83 C4 1C C3 }
	condition:
		$pattern
}

rule acosh_141a17fdb9e46e9b88155affcfed22a0 {
	meta:
		aliases = "__GI_acosh, __ieee754_acosh, acosh"
		type = "func"
		size = "233"
		objfiles = "e_acosh@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C DD 44 24 20 DD 54 24 0C DD 54 24 14 8B 54 24 18 8B 4C 24 14 81 FA FF FF EF 3F 7F 09 D8 E0 D8 F0 E9 BD 00 00 00 DD D8 81 FA FF FF AF 41 7E 2D 81 FA FF FF EF 7F 7E 0B DD 44 24 0C D8 C0 E9 A0 00 00 00 FF 74 24 10 FF 74 24 10 E8 ?? ?? ?? ?? DC 05 ?? ?? ?? ?? 58 5A E9 86 00 00 00 8D 82 00 00 10 C0 09 C8 75 04 D9 EE EB 78 81 FA 00 00 00 40 7E 3B DD 44 24 0C D8 C8 DC 25 ?? ?? ?? ?? 83 EC 08 DD 1C 24 E8 ?? ?? ?? ?? DD 44 24 14 D8 C0 D9 C9 DC 44 24 14 DD 54 24 14 D8 3D ?? ?? ?? ?? DE C1 DD 5C 24 28 83 C4 24 E9 ?? ?? ?? ?? DD 44 24 0C DC 25 ?? ?? ?? ?? D9 C0 D8 C1 D9 C1 D8 CA DE C1 83 EC 08 DD }
	condition:
		$pattern
}

rule scalb_9bb2c6fa55c4996f45929387cbc45906 {
	meta:
		aliases = "__ieee754_scalb, scalb"
		type = "func"
		size = "275"
		objfiles = "e_scalb@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C DD 44 24 20 DD 54 24 10 DD 44 24 28 DD 5C 24 08 DD 1C 24 E8 ?? ?? ?? ?? 59 5A 85 C0 75 13 FF 74 24 04 FF 74 24 04 E8 ?? ?? ?? ?? 59 5A 85 C0 74 0C DD 44 24 08 DC 0C 24 E9 CF 00 00 00 FF 74 24 04 FF 74 24 04 E8 ?? ?? ?? ?? 59 5A 85 C0 75 2F D9 EE DD 04 24 DD E1 DF E0 DD D9 9E 76 0B DD 44 24 08 DE C9 E9 A3 00 00 00 DD D8 DD 04 24 D9 E0 DD 1C 24 DD 44 24 08 DC 34 24 E9 8D 00 00 00 FF 74 24 04 FF 74 24 04 E8 ?? ?? ?? ?? 58 5A DD 04 24 D9 C9 DD E9 DF E0 9E 7A 02 74 08 D9 C0 DE E1 D8 F0 EB 68 DD D8 D9 05 ?? ?? ?? ?? DD 04 24 DA E9 DF E0 9E 76 0A C7 44 24 20 E8 FD 00 00 EB 3C D9 05 ?? ?? ?? }
	condition:
		$pattern
}

rule ualarm_994892080868a146ff2f8fa90bf21ded {
	meta:
		aliases = "ualarm"
		type = "func"
		size = "79"
		objfiles = "ualarm@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 C7 04 24 00 00 00 00 8B 44 24 28 89 44 24 04 C7 44 24 08 00 00 00 00 8B 44 24 24 89 44 24 0C 8D 44 24 10 50 8D 44 24 04 50 6A 00 E8 ?? ?? ?? ?? 83 C4 0C 83 CA FF 85 C0 78 0C 69 54 24 18 40 42 0F 00 03 54 24 1C 89 D0 83 C4 20 C3 }
	condition:
		$pattern
}

rule sysv_signal_b25eea1279522c03afbb328afe65df85 {
	meta:
		aliases = "__sysv_signal, sysv_signal"
		type = "func"
		size = "102"
		objfiles = "sysv_signal@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 28 8B 54 24 2C 8B 44 24 30 83 F8 FF 74 09 85 D2 7E 05 83 FA 40 7E 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CA FF EB 37 89 44 24 14 C7 44 24 20 00 00 00 00 C7 44 24 24 00 00 00 00 C7 44 24 18 00 00 00 E0 89 E0 50 8D 44 24 18 50 52 E8 ?? ?? ?? ?? 83 C4 0C 83 CA FF 85 C0 78 03 8B 14 24 89 D0 83 C4 28 C3 }
	condition:
		$pattern
}

rule ctime_r_035eeed776572eeb9766fe1c03cda3e1 {
	meta:
		aliases = "ctime_r"
		type = "func"
		size = "29"
		objfiles = "ctime_r@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 2C 89 E0 50 FF 74 24 34 E8 ?? ?? ?? ?? FF 74 24 3C 50 E8 ?? ?? ?? ?? 83 C4 3C C3 }
	condition:
		$pattern
}

rule acos_f665c4ad412800b071014f5c4dc4f365 {
	meta:
		aliases = "__GI_acos, __ieee754_acos, acos"
		type = "func"
		size = "550"
		objfiles = "e_acos@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 2C DD 44 24 30 DD 54 24 1C 8B 54 24 20 89 D0 25 FF FF FF 7F 3D FF FF EF 3F 7E 32 DD 5C 24 14 2D 00 00 F0 3F 0B 44 24 14 75 16 85 D2 7E 07 D9 EE E9 EB 01 00 00 DD 05 ?? ?? ?? ?? E9 E0 01 00 00 DD 44 24 30 D8 E0 D8 F0 E9 D3 01 00 00 DD D8 3D FF FF DF 3F 0F 8F 8B 00 00 00 3D 00 00 60 3C 7F 0B DD 05 ?? ?? ?? ?? E9 B4 01 00 00 DD 44 24 30 D8 C8 DD 05 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DD 05 ?? ?? ?? ?? D8 CA DC 25 ?? ?? ?? ?? D8 CA DC 05 ?? ?? ?? ?? D8 CA DC 25 ?? ?? ?? ?? DE CA D9 C9 DC 05 }
	condition:
		$pattern
}

rule svcerr_auth_95728fff2a3ddb48780e8f4fcb23a819 {
	meta:
		aliases = "__GI_svcerr_auth, svcerr_auth"
		type = "func"
		size = "53"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 30 8B 4C 24 34 C7 44 24 04 01 00 00 00 C7 44 24 08 01 00 00 00 C7 44 24 0C 01 00 00 00 8B 44 24 38 89 44 24 10 8B 51 08 89 E0 50 51 FF 52 0C 83 C4 38 C3 }
	condition:
		$pattern
}

rule log1p_519bd3c2d8515f0110a4f35332746da8 {
	meta:
		aliases = "__GI_log1p, log1p"
		type = "func"
		size = "675"
		objfiles = "s_log1p@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 30 DD 44 24 34 DD 5C 24 20 8B 54 24 24 81 FA 79 82 DA 3F 0F 8F 9C 00 00 00 89 D1 81 E1 FF FF FF 7F 81 F9 FF FF EF 3F 7E 2D D9 05 ?? ?? ?? ?? DD 44 24 34 DA E9 DF E0 9E 75 0F 7A 0D D9 EE D8 3D ?? ?? ?? ?? E9 48 02 00 00 DD 44 24 34 D8 E0 D8 F0 E9 3B 02 00 00 81 F9 FF FF 1F 3E 7F 36 DD 44 24 34 D8 05 ?? ?? ?? ?? D9 EE D9 C9 DA E9 DF E0 9E 76 0C 81 F9 FF FF 8F 3C 0F 8E 1A 02 00 00 DD 44 24 34 D8 C8 D8 0D ?? ?? ?? ?? DC 44 24 34 E9 FD 01 00 00 8D 82 3C 41 2D 40 3D 3C 41 2D 40 76 27 DD 44 24 34 BA 01 00 00 00 D9 EE D9 C9 31 C9 E9 C6 00 00 00 81 FA FF FF EF 7F 7E 0B DD 44 24 34 D8 C0 E9 C9 01 }
	condition:
		$pattern
}

rule isatty_c0d5cefd87942a2fcd3a963af3b5ee17 {
	meta:
		aliases = "__GI_isatty, isatty"
		type = "func"
		size = "27"
		objfiles = "isatty@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 3C 89 E0 50 FF 74 24 44 E8 ?? ?? ?? ?? 85 C0 0F 94 C0 0F B6 C0 83 C4 44 C3 }
	condition:
		$pattern
}

rule exp_459a202c0c58edc95c1005e621e038c9 {
	meta:
		aliases = "__GI_exp, __ieee754_exp, exp"
		type = "func"
		size = "505"
		objfiles = "e_exp@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 40 DD 44 24 44 DD 54 24 28 8B 54 24 2C 89 D1 C1 E9 1F 89 D0 25 FF FF FF 7F 3D 41 2E 86 40 76 64 3D FF FF EF 7F 76 23 DD 54 24 20 81 E2 FF FF 0F 00 0B 54 24 20 74 07 D8 C0 E9 AD 01 00 00 DD D8 85 C9 0F 84 A7 01 00 00 EB 33 DD D8 DD 05 ?? ?? ?? ?? DD 44 24 44 DA E9 DF E0 9E 76 0D DD 05 ?? ?? ?? ?? D8 C8 E9 81 01 00 00 DD 05 ?? ?? ?? ?? DD 44 24 44 D9 C9 DA E9 DF E0 9E 76 32 D9 EE E9 67 01 00 00 DD D8 3D 42 2E D6 3F 76 7D 3D B1 A2 F0 3F 77 1B DD 44 24 44 DC 24 CD ?? ?? ?? ?? DD 04 CD ?? ?? ?? ?? 89 C8 F7 D8 29 C8 40 EB 51 DD 44 24 44 DC 0D ?? ?? ?? ?? DC 04 CD ?? ?? ?? ?? D9 7C 24 3E 66 8B }
	condition:
		$pattern
}

rule direxists_da93630807bf962c54798b6f184addef {
	meta:
		aliases = "direxists"
		type = "func"
		size = "45"
		objfiles = "tempname@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 58 89 E2 52 50 E8 ?? ?? ?? ?? 5A 59 31 D2 85 C0 75 13 8B 44 24 10 25 00 F0 00 00 31 D2 3D 00 40 00 00 0F 94 C2 89 D0 83 C4 58 C3 }
	condition:
		$pattern
}

rule expm1_ab0b1207f9019936da7e43ba732c59dd {
	meta:
		aliases = "__GI_expm1, expm1"
		type = "func"
		size = "734"
		objfiles = "s_expm1@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 70 DD 44 24 74 DD 54 24 48 8B 54 24 4C 89 D1 81 E1 00 00 00 80 89 D0 25 FF FF FF 7F 3D 79 68 43 40 76 75 3D 41 2E 86 40 76 4A 3D FF FF EF 7F 76 23 DD 54 24 40 81 E2 FF FF 0F 00 0B 54 24 40 74 07 D8 C0 E9 88 02 00 00 DD D8 85 C9 0F 84 82 02 00 00 EB 39 DD D8 DD 05 ?? ?? ?? ?? DD 44 24 74 DA E9 DF E0 9E 76 0F DD 05 ?? ?? ?? ?? D8 C8 E9 5C 02 00 00 DD D8 85 C9 74 63 DD 44 24 74 DC 05 ?? ?? ?? ?? D9 EE DA E9 DF E0 9E 76 4C D9 05 ?? ?? ?? ?? E9 38 02 00 00 DD D8 3D 42 2E D6 3F 0F 86 9C 00 00 00 3D B1 A2 F0 3F 77 2D 85 C9 75 14 DD 44 24 74 DC 25 ?? ?? ?? ?? DD 05 ?? ?? ?? ?? B1 01 EB 6F DD 44 }
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

rule byte_store_op1_69576d775ef7097c116c18e3fe2ee608 {
	meta:
		aliases = "byte_store_op1"
		type = "func"
		size = "12"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 88 ) 02 88 4A 01 C1 F9 08 88 4A 02 C3 }
	condition:
		$pattern
}

rule munge_stream_a38f180d9720851a3896e95d852f3038 {
	meta:
		aliases = "munge_stream"
		type = "func"
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
		type = "func"
		size = "41"
		objfiles = "_ppfs_parsespec@libc.a"
	strings:
		$pattern = { ( CC | 89 ) C1 BA ?? ?? ?? ?? 83 EA 02 0F BF 02 39 C8 74 08 81 FA ?? ?? ?? ?? 77 EE 81 EA ?? ?? ?? ?? D1 FA 0F B6 82 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule mmap_4e79fd119af355899e568b048df9ce0b {
	meta:
		aliases = "__GI_mmap, mmap"
		type = "func"
		size = "27"
		objfiles = "mmap@libc.a"
	strings:
		$pattern = { ( CC | 89 ) DA B8 5A 00 00 00 8D 5C 24 04 CD 80 89 D3 3D 00 F0 FF FF 0F 87 ?? ?? ?? ?? C3 }
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

rule __libc_allocate_rtsig_4d74fe7039aa729ed7082aad0a469e82 {
	meta:
		aliases = "__libc_allocate_rtsig"
		type = "func"
		size = "56"
		objfiles = "pthread@libpthread.a, allocrtsig@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 0D ?? ?? ?? ?? 83 F9 FF 74 27 8B 15 ?? ?? ?? ?? 39 D1 7F 1D 83 7C 24 04 00 74 0A 8D 41 01 A3 ?? ?? ?? ?? EB 0F 8D 42 FF A3 ?? ?? ?? ?? 89 D1 EB 03 83 C9 FF 89 C8 C3 }
	condition:
		$pattern
}

rule dlerror_cc6ce66afae3e16b02286f75b476e629 {
	meta:
		aliases = "dlerror"
		type = "func"
		size = "30"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 8B ) 15 ?? ?? ?? ?? 31 C0 85 D2 74 11 8B 04 95 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 C3 }
	condition:
		$pattern
}

rule getchar_unlocked_75c47541a7d5c00c85b3d0ef8462b780 {
	meta:
		aliases = "__GI_getchar_unlocked, getchar_unlocked"
		type = "func"
		size = "35"
		objfiles = "getchar_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 15 ?? ?? ?? ?? 8B 42 10 3B 42 18 73 09 0F B6 08 40 89 42 10 EB 09 52 E8 ?? ?? ?? ?? 89 C1 58 89 C8 C3 }
	condition:
		$pattern
}

rule _dl_unmap_cache_dec1be4a29d44a0aa12de95486fefb4b {
	meta:
		aliases = "_dl_unmap_cache"
		type = "func"
		size = "63"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 8B ) 15 ?? ?? ?? ?? 8D 42 FF 83 C9 FF 83 F8 FD 77 2B 8B 0D ?? ?? ?? ?? 87 D3 B8 5B 00 00 00 CD 80 87 D3 3D 00 F0 FF FF 76 07 F7 D8 A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 31 C9 89 C8 C3 }
	condition:
		$pattern
}

rule endttyent_cfdf69f1557ffd5b30c45190c6a4399a {
	meta:
		aliases = "__GI_endttyent, endttyent"
		type = "func"
		size = "40"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 15 ?? ?? ?? ?? B8 01 00 00 00 85 D2 74 18 52 E8 ?? ?? ?? ?? 5A 40 0F 95 C0 0F B6 C0 C7 05 ?? ?? ?? ?? 00 00 00 00 C3 }
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

rule __get_pc_thunk_bx_37f86caa53dde6570f57a89c5dd1662f {
	meta:
		aliases = "__get_pc_thunk_bx"
		type = "func"
		size = "4"
		objfiles = "crti, crtn"
	strings:
		$pattern = { ( CC | 8B ) 1C 24 C3 }
	condition:
		$pattern
}

rule __finitef_2619605be797367fc3a3ac36f7b890d3 {
	meta:
		aliases = "__GI___finitef, __finitef"
		type = "func"
		size = "17"
		objfiles = "s_finitef@libm.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 0D FF FF 7F 80 40 0F 95 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule __flbf_cb729161db8025af83533ec7547101d2 {
	meta:
		aliases = "__flbf"
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "17"
		objfiles = "__fwritable@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 0F B7 00 C1 E8 05 83 F0 01 83 E0 01 C3 }
	condition:
		$pattern
}

rule ntohl_f0b2ac96b2a9c6535f6815b42030bed8 {
	meta:
		aliases = "__GI_htonl, __GI_ntohl, htonl, ntohl"
		type = "func"
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
		type = "func"
		size = "10"
		objfiles = "s_signbitf@libm.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 25 00 00 00 80 C3 }
	condition:
		$pattern
}

rule clearerr_unlocked_8c764c7d676ccffde1ff2f2dfe5720bc {
	meta:
		aliases = "clearerr_unlocked"
		type = "func"
		size = "9"
		objfiles = "clearerr_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 66 83 20 F3 C3 }
	condition:
		$pattern
}

rule ntohs_abb47f3111edd8b51bf0127264a91b58 {
	meta:
		aliases = "__GI_htons, __GI_ntohs, htons, ntohs"
		type = "func"
		size = "12"
		objfiles = "ntohl@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 66 C1 C8 08 0F B7 C0 C3 }
	condition:
		$pattern
}

rule cfmakeraw_32bbe373bdeabe2a2697e5fcce91485d {
	meta:
		aliases = "cfmakeraw"
		type = "func"
		size = "45"
		objfiles = "cfmakeraw@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 81 20 14 FA FF FF 83 60 04 FE 81 60 0C B4 7F FF FF 8B 50 08 81 E2 CF FE FF FF 83 CA 30 89 50 08 C6 40 17 01 C6 40 16 00 C3 }
	condition:
		$pattern
}

rule pthread_cond_destroy_bf15198941e2982ca6dd52c8956c1838 {
	meta:
		aliases = "__GI_pthread_cond_destroy, pthread_cond_destroy"
		type = "func"
		size = "16"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 83 78 08 01 19 C0 F7 D0 83 E0 10 C3 }
	condition:
		$pattern
}

rule toascii_2512460995700c0f5996e06f2a68a499 {
	meta:
		aliases = "toascii"
		type = "func"
		size = "8"
		objfiles = "toascii@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 83 E0 7F C3 }
	condition:
		$pattern
}

rule wcschrnul_442b63eb143177bcce8466cf95c95ef6 {
	meta:
		aliases = "wcschrnul"
		type = "func"
		size = "23"
		objfiles = "wcschrnul@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 83 E8 04 83 C0 04 8B 10 85 D2 74 06 3B 54 24 08 75 F1 C3 }
	condition:
		$pattern
}

rule isdigit_f03eb0c52d2f467b29a636eef12a35a2 {
	meta:
		aliases = "__GI_isdigit, isdigit"
		type = "func"
		size = "17"
		objfiles = "isdigit@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 83 E8 30 83 F8 09 0F 96 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule btowc_a1224ff3f0aa6828e1ce619685927b9d {
	meta:
		aliases = "__GI_btowc, btowc"
		type = "func"
		size = "13"
		objfiles = "btowc@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 83 F8 7F 76 03 83 C8 FF C3 }
	condition:
		$pattern
}

rule endmntent_2ea9569a9a5998a8a67ae1cd8ead3e44 {
	meta:
		aliases = "__GI_endmntent, endmntent"
		type = "func"
		size = "21"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 85 C0 74 07 50 E8 ?? ?? ?? ?? 58 B8 01 00 00 00 C3 }
	condition:
		$pattern
}

rule perror_3cb7defce9031aa5025a47110a3d5c64 {
	meta:
		aliases = "__GI_perror, perror"
		type = "func"
		size = "47"
		objfiles = "perror@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 85 C0 74 0A BA ?? ?? ?? ?? 80 38 00 75 07 B8 ?? ?? ?? ?? 89 C2 52 50 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule ctermid_ae8f972f7198a2cddb8e0365ddefe85b {
	meta:
		aliases = "ctermid"
		type = "func"
		size = "27"
		objfiles = "ctermid@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 85 C0 75 05 B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule killpg_44c903f178a1dc77798baf0bb2123fe7 {
	meta:
		aliases = "killpg"
		type = "func"
		size = "34"
		objfiles = "killpg@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 85 C0 78 0B F7 D8 89 44 24 04 E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF C3 }
	condition:
		$pattern
}

rule setjmp_99ce58d3572fa80f5c80bc78c67a778d {
	meta:
		aliases = "setjmp"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "23"
		objfiles = "basename@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 89 C2 EB 08 42 80 F9 2F 75 02 89 D0 8A 0A 84 C9 75 F2 C3 }
	condition:
		$pattern
}

rule wcschr_9ff3205df0b8267166b22fe796ca03bc {
	meta:
		aliases = "wcschr"
		type = "func"
		size = "24"
		objfiles = "wcschr@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 10 3B 54 24 08 74 0B 85 D2 74 05 83 C0 04 EB EF 31 C0 C3 }
	condition:
		$pattern
}

rule remque_10c0f8cd79236b847235a8439924eaf0 {
	meta:
		aliases = "remque"
		type = "func"
		size = "23"
		objfiles = "remque@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 10 8B 40 04 85 D2 74 03 89 42 04 85 C0 74 02 89 10 C3 }
	condition:
		$pattern
}

rule pthread_rwlockattr_getkind_np_f1910983a54cef9177564bec55e19797 {
	meta:
		aliases = "__GI_pthread_attr_getdetachstate, __pthread_mutexattr_getkind_np, __pthread_mutexattr_gettype, pthread_attr_getdetachstate, pthread_mutexattr_getkind_np, pthread_mutexattr_gettype, pthread_rwlockattr_getkind_np"
		type = "func"
		size = "15"
		objfiles = "rwlock@libpthread.a, attr@libpthread.a, mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 10 8B 44 24 08 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule __collated_compare_40053fa228c814b52197883d074f25da {
	meta:
		aliases = "__collated_compare"
		type = "func"
		size = "47"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 10 8B 44 24 08 8B 00 31 C9 39 C2 74 1A B1 01 85 D2 74 14 83 C9 FF 85 C0 74 0D 89 44 24 08 89 54 24 04 E9 ?? ?? ?? ?? 89 C8 C3 }
	condition:
		$pattern
}

rule fileno_unlocked_b056f780e5a10be1cbc3fd5644943ed3 {
	meta:
		aliases = "__GI_fileno_unlocked, fileno_unlocked"
		type = "func"
		size = "26"
		objfiles = "fileno_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 40 04 85 C0 79 0E E8 ?? ?? ?? ?? C7 00 09 00 00 00 83 C8 FF C3 }
	condition:
		$pattern
}

rule clntunix_geterr_2ccc3e6e148f337d0feff1e1a445a77b {
	meta:
		aliases = "clntunix_geterr"
		type = "func"
		size = "28"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 40 08 05 84 00 00 00 6A 0C 50 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule cfgetospeed_8b87194ff10627aae8fdf7766d049e05 {
	meta:
		aliases = "cfgetospeed"
		type = "func"
		size = "13"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 40 08 25 0F 10 00 00 C3 }
	condition:
		$pattern
}

rule clnttcp_geterr_261545509181638fc8246492ed6f824e {
	meta:
		aliases = "clnttcp_geterr"
		type = "func"
		size = "26"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 40 08 83 C0 24 6A 0C 50 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule clntudp_geterr_4056b512266e2e07ec15c678cb00937a {
	meta:
		aliases = "clntudp_geterr"
		type = "func"
		size = "26"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 40 08 83 C0 2C 6A 0C 50 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule sc_getc_f05a2db01e53054c5dfad9358c52ad9e {
	meta:
		aliases = "sc_getc"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "8"
		objfiles = "telldir@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 40 10 C3 }
	condition:
		$pattern
}

rule xdrrec_endofrecord_4f7a51b732df0b0df192d4ee7bb5842f {
	meta:
		aliases = "__GI_xdrrec_endofrecord, xdrrec_endofrecord"
		type = "func"
		size = "84"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 48 0C 83 7C 24 08 00 75 11 83 79 1C 00 75 0B 8B 51 10 8D 42 04 3B 41 14 72 13 C7 41 1C 00 00 00 00 BA 01 00 00 00 89 C8 E9 ?? ?? ?? ?? 8B 41 18 29 C2 83 EA 04 81 CA 00 00 00 80 0F CA 89 10 8B 41 10 89 41 18 83 41 10 04 B8 01 00 00 00 C3 }
	condition:
		$pattern
}

rule pthread_mutex_init_151653319236b154a45a8df961584873 {
	meta:
		aliases = "__pthread_mutex_init, pthread_mutex_init"
		type = "func"
		size = "53"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 4C 24 08 C7 40 10 00 00 00 00 C7 40 14 00 00 00 00 BA 03 00 00 00 85 C9 74 02 8B 11 89 50 0C C7 40 04 00 00 00 00 C7 40 08 00 00 00 00 31 C0 C3 }
	condition:
		$pattern
}

rule _obstack_memory_used_c084757aff7d113df29d11114fde2ed0 {
	meta:
		aliases = "_obstack_memory_used"
		type = "func"
		size = "23"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 50 04 31 C0 EB 07 03 02 29 D0 8B 52 04 85 D2 75 F5 C3 }
	condition:
		$pattern
}

rule pthread_rwlockattr_getpshared_cb3bf975196f4bf05554dd110bc96783 {
	meta:
		aliases = "__GI_pthread_attr_getschedpolicy, pthread_attr_getschedpolicy, pthread_rwlockattr_getpshared"
		type = "func"
		size = "16"
		objfiles = "rwlock@libpthread.a, attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 50 04 8B 44 24 08 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule __fpurge_fef2ad89de321ac412068bd12d2ea293 {
	meta:
		aliases = "__fpurge"
		type = "func"
		size = "42"
		objfiles = "__fpurge@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 50 08 89 50 18 89 50 1C 89 50 10 89 50 14 C7 40 28 00 00 00 00 C7 40 2C 00 00 00 00 C6 40 02 00 66 83 20 BC C3 }
	condition:
		$pattern
}

rule sem_getvalue_bf01487b64a973dd33d77632c300357d {
	meta:
		aliases = "__GI_pthread_attr_getschedparam, __new_sem_getvalue, pthread_attr_getschedparam, sem_getvalue"
		type = "func"
		size = "16"
		objfiles = "semaphore@libpthread.a, attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 50 08 8B 44 24 08 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_attr_getinheritsched_467a4efaa4ddb4792886d5ffa5b1df1c {
	meta:
		aliases = "__GI_pthread_attr_getinheritsched, pthread_attr_getinheritsched"
		type = "func"
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
		type = "func"
		size = "16"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 50 10 8B 44 24 08 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_attr_getguardsize_88a28a419baab63607b16b64b3aebbfe {
	meta:
		aliases = "__pthread_attr_getguardsize, pthread_attr_getguardsize"
		type = "func"
		size = "16"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 50 14 8B 44 24 08 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_attr_getstacksize_dc7a64c2315e36c9e6022584d127f7c4 {
	meta:
		aliases = "__pthread_attr_getstacksize, pthread_attr_getstacksize"
		type = "func"
		size = "16"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 50 20 8B 44 24 08 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule svcunix_stat_e188e5a4fc3e86f0fc217b04ccc0272d {
	meta:
		aliases = "svctcp_stat, svcunix_stat"
		type = "func"
		size = "33"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 50 2C 31 C0 83 3A 00 74 12 8D 42 08 50 E8 ?? ?? ?? ?? 59 83 F8 01 19 C0 83 C0 02 C3 }
	condition:
		$pattern
}

rule vwarnx_253a37e4f537ccc5659b79682313bd94 {
	meta:
		aliases = "__GI_vwarnx, vwarnx"
		type = "func"
		size = "15"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 08 31 C9 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule putpwent_35b35f41bfd23423704f49bc68a0cbb9 {
	meta:
		aliases = "putpwent"
		type = "func"
		size = "69"
		objfiles = "putpwent@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 08 85 C0 74 04 85 D2 75 0F E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF C3 FF 70 18 FF 70 14 FF 70 10 FF 70 0C FF 70 08 FF 70 04 FF 30 68 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 24 C1 F8 1F C3 }
	condition:
		$pattern
}

rule tdestroy_8964637c7b9ae7f838fe29aa782cfaa4 {
	meta:
		aliases = "__GI_tdestroy, tdestroy"
		type = "func"
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
		type = "func"
		size = "24"
		objfiles = "twalk@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 08 85 C0 74 0B 85 D2 74 07 31 C9 E9 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule _pthread_cleanup_push_defer_1613e1a713782c00a8cc8bb8fffe1151 {
	meta:
		aliases = "_pthread_cleanup_push_defer"
		type = "func"
		size = "18"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 08 89 10 8B 54 24 0C 89 50 04 C3 }
	condition:
		$pattern
}

rule __init_scan_cookie_0bf6f56b3545264c082624926bcccfbf {
	meta:
		aliases = "__init_scan_cookie"
		type = "func"
		size = "72"
		objfiles = "__scan_cookie@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 08 89 50 08 C7 40 0C 00 00 00 00 C6 40 19 00 31 C9 F6 02 02 74 03 8B 4A 28 89 48 14 C6 40 1A 00 C6 40 1B 00 C7 40 30 ?? ?? ?? ?? C7 40 3C ?? ?? ?? ?? C7 40 34 01 00 00 00 C7 40 38 2E 00 00 00 C3 }
	condition:
		$pattern
}

rule srand48_r_7e6e7a10a66336236e0a67fb1ae87d7f {
	meta:
		aliases = "__GI_srand48_r, srand48_r"
		type = "func"
		size = "55"
		objfiles = "srand48_r@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 08 89 C1 C1 F9 10 66 89 4A 04 66 89 42 02 66 C7 02 0E 33 C7 42 10 6D E6 EC DE C7 42 14 05 00 00 00 66 C7 42 0C 0B 00 66 C7 42 0E 01 00 31 C0 C3 }
	condition:
		$pattern
}

rule svcunixfd_create_e63fbd4454ec064dc8f9d0b775e2be85 {
	meta:
		aliases = "__GI_setenv, setenv, svcfd_create, svcunixfd_create"
		type = "func"
		size = "17"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a, setenv@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 08 8B 4C 24 0C E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule vwarn_43fd1032e1ca011a69b78fa05ca77933 {
	meta:
		aliases = "__GI_vwarn, vwarn"
		type = "func"
		size = "18"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 08 B9 01 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sem_init_d9a5d35f096e3b6f339c60eead2d3b9b {
	meta:
		aliases = "__new_sem_init, sem_init"
		type = "func"
		size = "73"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 0C 85 D2 79 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 12 83 7C 24 08 00 74 0F E8 ?? ?? ?? ?? C7 00 26 00 00 00 83 C8 FF C3 C7 00 00 00 00 00 C7 40 04 00 00 00 00 89 50 08 C7 40 0C 00 00 00 00 31 C0 C3 }
	condition:
		$pattern
}

rule xdrstdio_create_3292d2dc2e660b60c583d2a71577fbb3 {
	meta:
		aliases = "xdrstdio_create"
		type = "func"
		size = "39"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 0C 89 10 C7 40 04 ?? ?? ?? ?? 8B 54 24 08 89 50 0C C7 40 14 00 00 00 00 C7 40 10 00 00 00 00 C3 }
	condition:
		$pattern
}

rule labs_9206eec894c56790c6ede6426d1a11e1 {
	meta:
		aliases = "abs, labs"
		type = "func"
		size = "10"
		objfiles = "labs@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 99 31 D0 29 D0 C3 }
	condition:
		$pattern
}

rule pthread_setconcurrency_54cf6a653520c3791886f194f83332a1 {
	meta:
		aliases = "__pthread_setconcurrency, pthread_setconcurrency"
		type = "func"
		size = "12"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 A3 ?? ?? ?? ?? 31 C0 C3 }
	condition:
		$pattern
}

rule ffsl_fa76d4818df8af69962f2ee9af2c2efb {
	meta:
		aliases = "__GI_ffs, ffs, ffsl"
		type = "func"
		size = "65"
		objfiles = "ffs@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 B2 01 66 85 C0 75 05 C1 F8 10 B2 11 84 C0 75 06 83 C2 08 C1 F8 08 A8 0F 75 06 83 C2 04 C1 F8 04 A8 03 75 06 83 C2 02 C1 F8 02 31 C9 85 C0 74 0A 40 83 E0 01 0F B6 D2 8D 0C 10 89 C8 C3 }
	condition:
		$pattern
}

rule dlclose_750318a9e1ee858a81008fdcdc0707b9 {
	meta:
		aliases = "dlclose"
		type = "func"
		size = "14"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 BA 01 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sigemptyset_9cccfab68f4bd16a32525f638f9dcc39 {
	meta:
		aliases = "__GI_sigemptyset, pthread_rwlockattr_init, sigemptyset"
		type = "func"
		size = "20"
		objfiles = "sigempty@libc.a, rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 C7 00 00 00 00 00 C7 40 04 00 00 00 00 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_cond_init_057ef04232bf5edac022d3faadf51fdb {
	meta:
		aliases = "__GI_pthread_cond_init, pthread_cond_init"
		type = "func"
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
		type = "func"
		size = "13"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 C7 00 03 00 00 00 31 C0 C3 }
	condition:
		$pattern
}

rule sigfillset_ce701e6d5bd33234bcb7993186a8222b {
	meta:
		aliases = "__GI_sigfillset, sigfillset"
		type = "func"
		size = "20"
		objfiles = "sigfillset@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 C7 00 FF FF FF FF C7 40 04 FF FF FF FF 31 C0 C3 }
	condition:
		$pattern
}

rule fegetenv_ff9412d8c158f90eb25852371c6570eb {
	meta:
		aliases = "fegetenv"
		type = "func"
		size = "11"
		objfiles = "fegetenv@libm.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 D9 30 D9 20 31 C0 C3 }
	condition:
		$pattern
}

rule re_compile_fastmap_08954bb79c8aadcdb928571c8d2dfa6d {
	meta:
		aliases = "__GI_re_compile_fastmap, re_compile_fastmap"
		type = "func"
		size = "9"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mrand48_r_b3aacb3ccfb17d803b012961cc545010 {
	meta:
		aliases = "__GI_lrand48_r, drand48_r, lrand48_r, mrand48_r"
		type = "func"
		size = "19"
		objfiles = "drand48_r@libc.a, mrand48_r@libc.a, lrand48_r@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 FF 74 24 08 50 50 E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule pthread_equal_d0ba95a9976b90bd2839b9a76661bc0b {
	meta:
		aliases = "__GI_pthread_equal, pthread_equal"
		type = "func"
		size = "15"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 08 39 44 24 04 0F 94 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule xdr_netobj_9cb5bdcf463e101e4d8cccb9161b2311 {
	meta:
		aliases = "xdr_netobj"
		type = "func"
		size = "27"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 08 68 00 04 00 00 50 83 C0 04 50 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule pthread_attr_setscope_eab52c90b7ecc1eed445e196b254028e {
	meta:
		aliases = "__GI_pthread_attr_setscope, pthread_attr_setscope"
		type = "func"
		size = "37"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 08 85 C0 74 0F 48 0F 94 C0 0F B6 C0 48 83 E0 B7 83 C0 5F C3 8B 44 24 04 C7 40 10 00 00 00 00 31 C0 C3 }
	condition:
		$pattern
}

rule sigismember_016a84adaadaa75b24de597e41b23cce {
	meta:
		aliases = "__GI_sigaddset, __GI_sigdelset, sigaddset, sigdelset, sigismember"
		type = "func"
		size = "33"
		objfiles = "sigaddset@libc.a, sigismem@libc.a, sigdelset@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 08 85 C0 7E 0A 83 F8 40 7F 05 E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF C3 }
	condition:
		$pattern
}

rule versionsort_0b8952c11d0122f6e2461be9483226b1 {
	meta:
		aliases = "alphasort, versionsort"
		type = "func"
		size = "31"
		objfiles = "versionsort@libc.a, alphasort@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 08 8B 00 83 C0 0B 89 44 24 08 8B 44 24 04 8B 00 83 C0 0B 89 44 24 04 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule versionsort64_8e3845784a90450e364e6b0b22024a07 {
	meta:
		aliases = "alphasort64, versionsort64"
		type = "func"
		size = "31"
		objfiles = "alphasort64@libc.a, versionsort64@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 08 8B 00 83 C0 13 89 44 24 08 8B 44 24 04 8B 00 83 C0 13 89 44 24 04 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_mutexattr_getpshared_d162f5566ce13c5224d3d871a682088e {
	meta:
		aliases = "__pthread_mutexattr_getpshared, pthread_condattr_getpshared, pthread_mutexattr_getpshared"
		type = "func"
		size = "13"
		objfiles = "condvar@libpthread.a, mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 08 C7 00 00 00 00 00 31 C0 C3 }
	condition:
		$pattern
}

rule re_search_15f6b841c36ec054a90439289c77596d {
	meta:
		aliases = "__GI_re_search, re_search"
		type = "func"
		size = "39"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 0C 50 FF 74 24 1C FF 74 24 1C FF 74 24 1C 50 FF 74 24 1C 6A 00 6A 00 FF 74 24 24 E8 ?? ?? ?? ?? 83 C4 24 C3 }
	condition:
		$pattern
}

rule openat64_27fdaf8728193a1191e5f313db07dbf9 {
	meta:
		aliases = "__GI_openat64, openat64"
		type = "func"
		size = "16"
		objfiles = "openat64@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 0C 80 CC 80 89 44 24 0C E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mbrlen_5cc209285f01f7ee7f966172a725a111 {
	meta:
		aliases = "__GI_mbrlen, mbrlen"
		type = "func"
		size = "33"
		objfiles = "mbrlen@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 0C 85 C0 75 05 B8 ?? ?? ?? ?? 50 FF 74 24 0C FF 74 24 0C 6A 00 E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule __assert_c120ce0e52eb048154117785cf8a56f4 {
	meta:
		aliases = "__GI___assert, __assert"
		type = "func"
		size = "72"
		objfiles = "__assert@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 10 80 3D ?? ?? ?? ?? 00 75 36 C6 05 ?? ?? ?? ?? 01 85 C0 75 05 B8 ?? ?? ?? ?? FF 74 24 04 50 FF 74 24 14 FF 74 24 14 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 1C E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mbsrtowcs_601a5834988a3975eb20803d2fd39bbf {
	meta:
		aliases = "__GI_mbsrtowcs, mbsrtowcs"
		type = "func"
		size = "37"
		objfiles = "mbsrtowcs@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 10 85 C0 75 05 B8 ?? ?? ?? ?? 50 FF 74 24 10 6A FF FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? 83 C4 14 C3 }
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

rule time_a75c0269822a568fe8d440d967c5d852 {
	meta:
		aliases = "__GI_time, time"
		type = "func"
		size = "16"
		objfiles = "time@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 87 CB B8 0D 00 00 00 CD 80 87 CB C3 }
	condition:
		$pattern
}

rule times_c27ef60e06858f08745007bcafd5a7f1 {
	meta:
		aliases = "__GI_times, times"
		type = "func"
		size = "16"
		objfiles = "times@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 87 CB B8 2B 00 00 00 CD 80 87 CB C3 }
	condition:
		$pattern
}

rule __isinff_4badbf104b1929e81db8af33a081a1da {
	meta:
		aliases = "__GI___isinff, __isinff"
		type = "func"
		size = "35"
		objfiles = "s_isinff@libm.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 89 CA 81 E2 FF FF FF 7F 81 F2 00 00 80 7F 89 D0 F7 D8 09 D0 C1 F8 1F F7 D0 C1 F9 1E 21 C8 C3 }
	condition:
		$pattern
}

rule putwchar_ca980f27b44d23890bf1c6d6d3c5e905 {
	meta:
		aliases = "putwchar"
		type = "func"
		size = "58"
		objfiles = "putwchar@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 15 ?? ?? ?? ?? 83 7A 34 00 74 1C 8B 42 10 3B 42 1C 73 0B 88 08 0F B6 C9 40 89 42 10 EB 14 52 51 E8 ?? ?? ?? ?? EB 07 52 51 E8 ?? ?? ?? ?? 89 C1 58 5A 89 C8 C3 }
	condition:
		$pattern
}

rule putchar_unlocked_611bccc07d35400ec2c021b968f174f7 {
	meta:
		aliases = "putchar_unlocked"
		type = "func"
		size = "43"
		objfiles = "putchar_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 15 ?? ?? ?? ?? 8B 42 10 3B 42 1C 73 0B 88 08 0F B6 C9 40 89 42 10 EB 0B 52 51 E8 ?? ?? ?? ?? 89 C1 58 5A 89 C8 C3 }
	condition:
		$pattern
}

rule isctype_c53864b289c0bcecca036bb75ce522ba {
	meta:
		aliases = "isctype"
		type = "func"
		size = "22"
		objfiles = "isctype@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 15 ?? ?? ?? ?? 8B 44 24 08 66 23 04 4A 0F B7 C0 C3 }
	condition:
		$pattern
}

rule xdrmem_getlong_25d25932753fcc2fe75ccaef4f4e35de {
	meta:
		aliases = "xdrmem_getint32, xdrmem_getlong"
		type = "func"
		size = "45"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 41 14 31 D2 83 F8 03 76 1C 83 E8 04 89 41 14 8B 41 0C 8B 00 0F C8 8B 54 24 08 89 02 83 41 0C 04 BA 01 00 00 00 89 D0 C3 }
	condition:
		$pattern
}

rule xdrmem_putlong_aa5b511a42f19d4cfd6101fefbe8d32a {
	meta:
		aliases = "xdrmem_putint32, xdrmem_putlong"
		type = "func"
		size = "45"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 41 14 31 D2 83 F8 03 76 1C 83 E8 04 89 41 14 8B 44 24 08 8B 00 0F C8 8B 51 0C 89 02 83 41 0C 04 BA 01 00 00 00 89 D0 C3 }
	condition:
		$pattern
}

rule iswctype_fcd4cc5d484e7871917d7914951c8ea3 {
	meta:
		aliases = "__GI_iswctype, iswctype"
		type = "func"
		size = "43"
		objfiles = "iswctype@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 44 24 08 83 F9 7F 77 05 83 F8 0C 76 03 31 C0 C3 66 8B 84 00 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 66 23 04 4A 0F B7 C0 C3 }
	condition:
		$pattern
}

rule __longjmp_eb3a20b3fbb1ee7d783df9086f759789 {
	meta:
		aliases = "__GI___longjmp, __longjmp"
		type = "func"
		size = "27"
		objfiles = "__longjmp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 44 24 08 8B 51 14 8B 19 8B 71 04 8B 79 08 8B 69 0C 8B 61 10 FF E2 }
	condition:
		$pattern
}

rule strnlen_71a22aeeede3454368cf6cbeb0891e42 {
	meta:
		aliases = "__GI_strnlen, strnlen"
		type = "func"
		size = "24"
		objfiles = "strnlen@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 54 24 08 42 8D 41 FF 40 4A 74 05 80 38 00 75 F7 29 C8 C3 }
	condition:
		$pattern
}

rule wcsnlen_36302110b5f494905b96409ac1c860a2 {
	meta:
		aliases = "__GI_wcsnlen, wcsnlen"
		type = "func"
		size = "31"
		objfiles = "wcsnlen@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 54 24 08 89 C8 EB 04 83 C0 04 4A 85 D2 74 05 83 38 00 75 F3 29 C8 C1 F8 02 C3 }
	condition:
		$pattern
}

rule _seterr_reply_3164b676154a517da321918e069dd174 {
	meta:
		aliases = "__GI__seterr_reply, _seterr_reply"
		type = "func"
		size = "223"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 54 24 08 8B 41 08 85 C0 74 09 48 0F 85 8B 00 00 00 EB 59 8B 41 18 85 C0 75 07 C7 02 00 00 00 00 C3 83 F8 05 77 37 FF 24 85 ?? ?? ?? ?? C7 02 08 00 00 00 EB 73 C7 02 09 00 00 00 EB 6B C7 02 0A 00 00 00 EB 63 C7 02 0B 00 00 00 EB 5B C7 02 0C 00 00 00 EB 53 C7 02 00 00 00 00 EB 4B C7 02 10 00 00 00 C7 42 04 00 00 00 00 EB 2B 8B 41 0C 85 C0 74 07 83 F8 01 75 12 EB 08 C7 02 06 00 00 00 EB 26 C7 02 07 00 00 00 EB 1E C7 02 10 00 00 00 C7 42 04 01 00 00 00 89 42 08 EB 0C C7 02 10 00 00 00 8B 41 08 89 42 04 8B 02 83 F8 07 74 17 83 F8 09 74 19 83 F8 06 75 20 8B 41 10 89 42 04 8B 41 14 89 }
	condition:
		$pattern
}

rule cfsetispeed_36ab95136b839447e465e0cec37e6429 {
	meta:
		aliases = "__GI_cfsetispeed, cfsetispeed"
		type = "func"
		size = "77"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 54 24 08 F7 C2 F0 EF FF FF 74 1A 8D 82 FF EF FF FF 83 F8 0E 76 0F E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF C3 85 D2 75 09 81 09 00 00 00 80 31 C0 C3 81 21 FF FF FF 7F 8B 41 08 25 F0 EF FF FF 09 C2 89 51 08 31 C0 C3 }
	condition:
		$pattern
}

rule cfsetospeed_c9dee19717e8162947de03fa44ec1d3b {
	meta:
		aliases = "__GI_cfsetospeed, cfsetospeed"
		type = "func"
		size = "58"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 54 24 08 F7 C2 F0 EF FF FF 74 1A 8D 82 FF EF FF FF 83 F8 0E 76 0F E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF C3 8B 41 08 25 F0 EF FF FF 09 C2 89 51 08 31 C0 C3 }
	condition:
		$pattern
}

rule svcunix_getargs_5505a2426bca0e46df0666a9dde0cad6 {
	meta:
		aliases = "svctcp_getargs, svcunix_getargs"
		type = "func"
		size = "28"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 08 8B 44 24 0C 89 44 24 08 8B 44 24 04 8B 40 2C 83 C0 08 89 44 24 04 FF E1 }
	condition:
		$pattern
}

rule svcudp_getargs_a7eb8db7be0b76ee33a2c3f4b8e8f270 {
	meta:
		aliases = "svcudp_getargs"
		type = "func"
		size = "28"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 08 8B 44 24 0C 89 44 24 08 8B 44 24 04 8B 40 30 83 C0 08 89 44 24 04 FF E1 }
	condition:
		$pattern
}

rule wcscpy_66594f22f089e8ab8867bac27481e917 {
	meta:
		aliases = "wcscpy"
		type = "func"
		size = "27"
		objfiles = "wcscpy@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 08 8B 54 24 04 8B 01 89 02 83 C2 04 83 C1 04 85 C0 75 F2 8B 44 24 04 C3 }
	condition:
		$pattern
}

rule wcscat_ee20ad29a8fd751d79d67a920679f941 {
	meta:
		aliases = "__GI_wcscat, wcscat"
		type = "func"
		size = "39"
		objfiles = "wcscat@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 08 8B 54 24 04 8B 02 83 C2 04 85 C0 75 F7 83 EA 04 8B 01 89 02 83 C2 04 83 C1 04 85 C0 75 F2 8B 44 24 04 C3 }
	condition:
		$pattern
}

rule clntudp_freeres_d6a787d5244f9ec2abbbb5b700e09cec {
	meta:
		aliases = "clntudp_freeres"
		type = "func"
		size = "35"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 08 8B 54 24 0C 8B 44 24 04 8B 40 08 C7 40 38 02 00 00 00 89 54 24 08 83 C0 38 89 44 24 04 FF E1 }
	condition:
		$pattern
}

rule clnttcp_freeres_1121a5d33bde19ddd8249d171639269e {
	meta:
		aliases = "clnttcp_freeres"
		type = "func"
		size = "35"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 08 8B 54 24 0C 8B 44 24 04 8B 40 08 C7 40 4C 02 00 00 00 89 54 24 08 83 C0 4C 89 44 24 04 FF E1 }
	condition:
		$pattern
}

rule clntunix_freeres_d53f74c06e4bce31d9cc6660ad0cd896 {
	meta:
		aliases = "clntunix_freeres"
		type = "func"
		size = "40"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 08 8B 54 24 0C 8B 44 24 04 8B 40 08 C7 80 AC 00 00 00 02 00 00 00 89 54 24 08 05 AC 00 00 00 89 44 24 04 FF E1 }
	condition:
		$pattern
}

rule svcunix_freeargs_b00eac8f841dd8fed9c028bec12a6e98 {
	meta:
		aliases = "svctcp_freeargs, svcunix_freeargs"
		type = "func"
		size = "35"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 08 8B 54 24 0C 8B 44 24 04 8B 40 2C C7 40 08 02 00 00 00 89 54 24 08 83 C0 08 89 44 24 04 FF E1 }
	condition:
		$pattern
}

rule svcudp_freeargs_50d3657a0d3f9674bf70a80bd7e761ce {
	meta:
		aliases = "svcudp_freeargs"
		type = "func"
		size = "35"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 08 8B 54 24 0C 8B 44 24 04 8B 40 30 C7 40 08 02 00 00 00 89 54 24 08 83 C0 08 89 44 24 04 FF E1 }
	condition:
		$pattern
}

rule wmemchr_0f94b3815a389062d9126f0f515c4037 {
	meta:
		aliases = "__GI_wmemchr, wmemchr"
		type = "func"
		size = "29"
		objfiles = "wmemchr@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 08 8B 54 24 0C 8B 44 24 04 EB 08 39 08 74 0A 83 C0 04 4A 85 D2 75 F4 31 C0 C3 }
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

rule _dl_aux_init_6803dca08f46e8ec451227ae34f51b8a {
	meta:
		aliases = "_dl_aux_init"
		type = "func"
		size = "18"
		objfiles = "dl_support@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 50 1C 89 15 ?? ?? ?? ?? 8B 40 2C A3 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule inet_netof_96bd25f4808937f22b3fe0927e46091d {
	meta:
		aliases = "__GI_inet_netof, inet_netof"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "20"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 31 C0 83 3A 00 78 08 8B 42 08 25 0F 10 00 00 C3 }
	condition:
		$pattern
}

rule wctomb_3940ea59cbc7f2cf96e1f898f747f621 {
	meta:
		aliases = "wctomb"
		type = "func"
		size = "26"
		objfiles = "wctomb@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 31 C0 85 D2 74 0F 6A 00 FF 74 24 0C 52 E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule wcsrchr_ae16100322b3f4bc188f7eb2d345bec9 {
	meta:
		aliases = "wcsrchr"
		type = "func"
		size = "26"
		objfiles = "wcsrchr@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 31 C0 8B 0A 3B 4C 24 08 75 02 89 D0 85 C9 74 05 83 C2 04 EB ED C3 }
	condition:
		$pattern
}

rule gai_strerror_2b1419d789939a62d80d203c0658865e {
	meta:
		aliases = "gai_strerror"
		type = "func"
		size = "37"
		objfiles = "gai_strerror@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 31 C0 EB 12 39 14 C5 ?? ?? ?? ?? 75 08 8B 04 C5 ?? ?? ?? ?? C3 40 83 F8 0F 76 E9 B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule clnt_sperrno_4c713e0849366ed00a7e291dc9cc5efe {
	meta:
		aliases = "__GI_clnt_sperrno, clnt_sperrno"
		type = "func"
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
		type = "func"
		size = "18"
		objfiles = "__fpending@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 31 C0 F6 02 40 74 06 8B 42 10 2B 42 08 C3 }
	condition:
		$pattern
}

rule __isnanf_bae6dd348368f7427b80c7a876984d20 {
	meta:
		aliases = "__GI___isnanf, __isnanf"
		type = "func"
		size = "21"
		objfiles = "s_isnanf@libm.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 81 E2 FF FF FF 7F B8 00 00 80 7F 29 D0 C1 E8 1F C3 }
	condition:
		$pattern
}

rule _pthread_cleanup_pop_restore_2564663ad7acd44b1ca96e9ed1d9cfe6 {
	meta:
		aliases = "_pthread_cleanup_pop_restore"
		type = "func"
		size = "23"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 83 7C 24 08 00 74 0B 8B 42 04 89 44 24 04 8B 0A FF E1 C3 }
	condition:
		$pattern
}

rule towupper_48138e3d9f8c60c2c473cafe14662f16 {
	meta:
		aliases = "__GI_towlower, __GI_towupper, towlower, towupper"
		type = "func"
		size = "21"
		objfiles = "towupper@libc.a, towlower@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 83 FA 7F 77 09 A1 ?? ?? ?? ?? 0F BF 14 50 89 D0 C3 }
	condition:
		$pattern
}

rule mblen_635c99c5ac27627916f6612a1c79865f {
	meta:
		aliases = "mblen"
		type = "func"
		size = "64"
		objfiles = "mblen@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 85 D2 75 0D C7 05 ?? ?? ?? ?? 00 00 00 00 31 C0 C3 31 C0 80 3A 00 74 23 68 ?? ?? ?? ?? FF 74 24 0C 52 E8 ?? ?? ?? ?? 83 C4 0C 83 F8 FE 75 0C C7 05 ?? ?? ?? ?? FF FF 00 00 B0 FF C3 }
	condition:
		$pattern
}

rule wcslen_95bb5ca1b15db730fbdf52d886799988 {
	meta:
		aliases = "__GI_wcslen, wcslen"
		type = "func"
		size = "22"
		objfiles = "wcslen@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 89 D0 EB 03 83 C0 04 83 38 00 75 F8 29 D0 C1 F8 02 C3 }
	condition:
		$pattern
}

rule nl_langinfo_1348c04be901cd4fa7bec0c00882ae92 {
	meta:
		aliases = "__GI_nl_langinfo, nl_langinfo"
		type = "func"
		size = "65"
		objfiles = "nl_langinfo@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 89 D1 C1 F9 08 83 F9 05 77 2D 0F B6 81 ?? ?? ?? ?? 81 E2 FF 00 00 00 8D 14 10 0F B6 81 ?? ?? ?? ?? 39 C2 73 12 0F B6 82 ?? ?? ?? ?? 83 E2 40 8D 84 50 ?? ?? ?? ?? C3 B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule sigisemptyset_97e61411df5e6da88b2e94ef36cd11ab {
	meta:
		aliases = "sigisemptyset"
		type = "func"
		size = "16"
		objfiles = "sigisempty@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 02 0B 42 04 0F 94 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule __fbufsize_315ef90ae72c125d2e04bdec80b2ac72 {
	meta:
		aliases = "__fbufsize"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "48"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 42 0C 85 C0 78 0A 83 F8 01 7E 0B 83 F8 03 7E 0C B8 16 00 00 00 C3 F6 42 10 01 EB 04 83 7A 10 00 74 06 B8 10 00 00 00 C3 31 C0 C3 }
	condition:
		$pattern
}

rule crypt_38ed92938727a36a8915df8cc6033228 {
	meta:
		aliases = "crypt"
		type = "func"
		size = "43"
		objfiles = "crypt@libcrypt.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 44 24 08 80 38 24 75 11 80 78 01 31 75 0B 80 78 02 24 75 05 E9 ?? ?? ?? ?? 89 44 24 08 89 54 24 04 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _load_inttype_bc3edf1c98f1f7ed828c85bfe764838f {
	meta:
		aliases = "_load_inttype"
		type = "func"
		size = "86"
		objfiles = "_load_inttype@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 44 24 08 83 7C 24 0C 00 78 22 F6 C6 08 75 22 8B 00 81 FA 00 01 00 00 75 05 0F B6 C0 EB 0B 81 FA 00 02 00 00 75 03 0F B7 C0 31 D2 C3 F6 C6 08 74 06 8B 50 04 8B 00 C3 8B 00 81 FA 00 01 00 00 75 05 0F B6 C0 EB 09 81 FA 00 02 00 00 75 01 98 99 C3 }
	condition:
		$pattern
}

rule __old_sem_init_f25465429f1714040a685a3226b278da {
	meta:
		aliases = "__old_sem_init"
		type = "func"
		size = "63"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 44 24 0C 85 C0 79 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 12 83 7C 24 08 00 74 0F E8 ?? ?? ?? ?? C7 00 26 00 00 00 83 C8 FF C3 C7 42 04 00 00 00 00 8D 44 00 01 89 02 31 C0 C3 }
	condition:
		$pattern
}

rule strrchr_bcc34327154efdfb74e18a0ac6c906cc {
	meta:
		aliases = "__GI_strrchr, rindex, strrchr"
		type = "func"
		size = "26"
		objfiles = "strrchr@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 4C 24 08 31 C0 88 CD 8A 0A 38 CD 75 02 89 D0 42 84 C9 75 F3 C3 }
	condition:
		$pattern
}

rule stpcpy_e85acb712e464efe694ecc781bc67b25 {
	meta:
		aliases = "__GI_stpcpy, stpcpy"
		type = "func"
		size = "22"
		objfiles = "stpcpy@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 4C 24 08 8A 01 88 02 42 41 84 C0 75 F6 8D 42 FF C3 }
	condition:
		$pattern
}

rule wcpcpy_6836f305f3d0c96d6a0f41575d0425e5 {
	meta:
		aliases = "wcpcpy"
		type = "func"
		size = "26"
		objfiles = "wcpcpy@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 4C 24 08 8B 01 89 02 83 C2 04 83 C1 04 85 C0 75 F2 8D 42 FC C3 }
	condition:
		$pattern
}

rule insque_86acebd078734744c9698b14f296039d {
	meta:
		aliases = "insque"
		type = "func"
		size = "25"
		objfiles = "insque@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 4C 24 08 8B 01 89 11 85 C0 74 03 89 50 04 89 02 89 4A 04 C3 }
	condition:
		$pattern
}

rule xdr_float_4273dee23da4e5503e962141101bd8b8 {
	meta:
		aliases = "xdr_float"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "52"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 4C 24 08 8B 02 85 C0 75 08 8B 42 04 8B 48 04 EB 12 83 F8 01 75 0F 8B 42 04 89 4C 24 08 89 54 24 04 8B 08 FF E1 83 F8 02 0F 94 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule xdrmem_create_97696748e504083caad888c9e7749a71 {
	meta:
		aliases = "__GI_xdrmem_create, xdrmem_create"
		type = "func"
		size = "35"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 4C 24 08 8B 44 24 10 89 02 C7 42 04 ?? ?? ?? ?? 89 4A 10 89 4A 0C 8B 44 24 0C 89 42 14 C3 }
	condition:
		$pattern
}

rule pthread_rwlock_init_c0cc93c42530c6c06f9aaa1dacd03c9a {
	meta:
		aliases = "pthread_rwlock_init"
		type = "func"
		size = "83"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 4C 24 08 C7 02 00 00 00 00 C7 42 04 00 00 00 00 C7 42 08 00 00 00 00 C7 42 0C 00 00 00 00 C7 42 10 00 00 00 00 C7 42 14 00 00 00 00 85 C9 75 10 C7 42 18 01 00 00 00 C7 42 1C 00 00 00 00 EB 0B 8B 01 89 42 18 8B 41 04 89 42 1C 31 C0 C3 }
	condition:
		$pattern
}

rule wcscoll_e91a61111c295dab6c061b7848cdcf0d {
	meta:
		aliases = "__GI_wcscmp, __GI_wcscoll, wcscmp, wcscoll"
		type = "func"
		size = "36"
		objfiles = "wcscmp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 4C 24 08 EB 0E 83 3A 00 75 03 31 C0 C3 83 C2 04 83 C1 04 8B 01 39 02 74 EC 19 C0 83 C8 01 C3 }
	condition:
		$pattern
}

rule toupper_d7d4521aee6b4c2c35428947fe099a90 {
	meta:
		aliases = "__GI_tolower, __GI_toupper, tolower, toupper"
		type = "func"
		size = "29"
		objfiles = "tolower@libc.a, toupper@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8D 82 80 00 00 00 3D 7F 01 00 00 77 09 A1 ?? ?? ?? ?? 0F BF 14 50 89 D0 C3 }
	condition:
		$pattern
}

rule isblank_5417f1fb8e36c6e932252b09ead9d0c1 {
	meta:
		aliases = "__GI_isblank, isblank"
		type = "func"
		size = "19"
		objfiles = "isblank@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 25 00 01 00 00 C3 }
	condition:
		$pattern
}

rule iscntrl_2dc04f106681d2b774e1ee052ef468e0 {
	meta:
		aliases = "__GI_iscntrl, iscntrl"
		type = "func"
		size = "19"
		objfiles = "iscntrl@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 25 00 02 00 00 C3 }
	condition:
		$pattern
}

rule ispunct_c3c3c53a2845a213d1fc619013cac873 {
	meta:
		aliases = "__GI_ispunct, ispunct"
		type = "func"
		size = "19"
		objfiles = "ispunct@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 25 00 04 00 00 C3 }
	condition:
		$pattern
}

rule isalnum_175659f72d6ba97b50950d48352e9f19 {
	meta:
		aliases = "__GI_isalnum, isalnum"
		type = "func"
		size = "19"
		objfiles = "isalnum@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 25 00 08 00 00 C3 }
	condition:
		$pattern
}

rule isgraph_49a9f6fcd3b0abca144dbbfe94b15c05 {
	meta:
		aliases = "__GI_isgraph, isgraph"
		type = "func"
		size = "19"
		objfiles = "isgraph@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 25 80 00 00 00 C3 }
	condition:
		$pattern
}

rule isupper_77cef65e7bce598ddaaadae7de98a90e {
	meta:
		aliases = "__GI_isupper, isupper"
		type = "func"
		size = "17"
		objfiles = "isupper@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 83 E0 01 C3 }
	condition:
		$pattern
}

rule islower_2d1974ca068d02645740cc133ae551f7 {
	meta:
		aliases = "__GI_islower, islower"
		type = "func"
		size = "17"
		objfiles = "islower@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 83 E0 02 C3 }
	condition:
		$pattern
}

rule isalpha_ae2fe3c00f0d2b34d5515092d9ace8ee {
	meta:
		aliases = "__GI_isalpha, isalpha"
		type = "func"
		size = "17"
		objfiles = "isalpha@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 83 E0 04 C3 }
	condition:
		$pattern
}

rule isxdigit_e58c5ce5bf1ea730964dd0478cb4d0f7 {
	meta:
		aliases = "__GI_isxdigit, isxdigit"
		type = "func"
		size = "17"
		objfiles = "isxdigit@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 83 E0 10 C3 }
	condition:
		$pattern
}

rule isspace_3135b1d20b0674a3cfa314f46d0b2e18 {
	meta:
		aliases = "__GI_isspace, isspace"
		type = "func"
		size = "17"
		objfiles = "isspace@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 83 E0 20 C3 }
	condition:
		$pattern
}

rule isprint_b16ef400bdbcab1927214d045ea4d492 {
	meta:
		aliases = "__GI_isprint, isprint"
		type = "func"
		size = "17"
		objfiles = "isprint@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 A1 ?? ?? ?? ?? 0F B7 04 50 83 E0 40 C3 }
	condition:
		$pattern
}

rule mbsinit_5cd63a44de22623256fcbd89e65a7b8d {
	meta:
		aliases = "__GI_mbsinit, mbsinit"
		type = "func"
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
		type = "func"
		size = "12"
		objfiles = "pt_machine@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 B8 01 00 00 00 87 02 C3 }
	condition:
		$pattern
}

rule __libc_sa_len_3f006f24e4f97d8c120a2f84b0095d2f {
	meta:
		aliases = "__libc_sa_len"
		type = "func"
		size = "37"
		objfiles = "sa_len@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 B8 10 00 00 00 66 83 FA 02 74 15 B0 1C 66 83 FA 0A 74 0D 31 C0 66 83 FA 01 0F 95 C0 48 83 E0 6E C3 }
	condition:
		$pattern
}

rule brk_4eaa515d503f2c4553c9f7f3a1b19ea7 {
	meta:
		aliases = "__GI_brk, brk"
		type = "func"
		size = "43"
		objfiles = "brk@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 B8 2D 00 00 00 53 89 D3 CD 80 5B A3 ?? ?? ?? ?? 31 C9 39 D0 73 0E E8 ?? ?? ?? ?? C7 00 0C 00 00 00 83 C9 FF 89 C8 C3 }
	condition:
		$pattern
}

rule hstrerror_d9078c5439f7fc15dd1cf5d3b9b5bdc4 {
	meta:
		aliases = "hstrerror"
		type = "func"
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
		type = "func"
		size = "55"
		objfiles = "__xpg_basename@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 B8 ?? ?? ?? ?? 85 D2 74 29 80 3A 00 74 24 8D 4A FF 89 D0 80 3A 2F 74 09 41 39 CA 76 04 89 D0 89 D1 42 80 3A 00 75 EC 80 38 2F 75 02 89 C1 C6 41 01 00 C3 }
	condition:
		$pattern
}

rule l64a_3daae660c361fa32ecef4d908978e416 {
	meta:
		aliases = "l64a"
		type = "func"
		size = "41"
		objfiles = "l64a@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 B9 ?? ?? ?? ?? EB 11 89 D0 83 E0 3F 8A 80 ?? ?? ?? ?? 88 01 41 C1 EA 06 85 D2 75 EB C6 01 00 B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __scan_ungetc_11228ccd939619491824ece6f7d5f8a6 {
	meta:
		aliases = "__scan_ungetc"
		type = "func"
		size = "36"
		objfiles = "__scan_cookie@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 FF 42 10 8A 42 19 3C 02 75 0A C6 42 19 00 8B 42 04 89 02 C3 84 C0 75 07 C6 42 19 01 FF 4A 0C C3 }
	condition:
		$pattern
}

rule setlocale_73b41e9de22c06546e633ae9e406d0dd {
	meta:
		aliases = "setlocale"
		type = "func"
		size = "57"
		objfiles = "setlocale@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 83 7C 24 04 06 77 2B 85 D2 74 21 8A 02 84 C0 74 1B 3C 43 75 06 80 7A 01 00 74 11 68 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 5A 59 85 C0 75 06 B8 ?? ?? ?? ?? C3 31 C0 C3 }
	condition:
		$pattern
}

rule setbuf_5ff9ff37b9432e8d1d2b9437834bb356 {
	meta:
		aliases = "setbuf"
		type = "func"
		size = "32"
		objfiles = "setbuf@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 83 FA 01 19 C0 83 E0 02 68 00 10 00 00 50 52 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule setbuffer_def0c0a032e9fcac2a74607b896b2739 {
	meta:
		aliases = "setbuffer"
		type = "func"
		size = "31"
		objfiles = "setbuffer@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 83 FA 01 19 C0 83 E0 02 FF 74 24 0C 50 52 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule mbtowc_09bf99ff518287bc8463f6f34c0607f2 {
	meta:
		aliases = "mbtowc"
		type = "func"
		size = "68"
		objfiles = "mbtowc@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 85 D2 75 0D C7 05 ?? ?? ?? ?? 00 00 00 00 31 C0 C3 31 C0 80 3A 00 74 27 68 ?? ?? ?? ?? FF 74 24 10 52 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FE 75 0C C7 05 ?? ?? ?? ?? FF FF 00 00 B0 FF C3 }
	condition:
		$pattern
}

rule bcopy_e79a9bddcac1b665c852d06cb17f5513 {
	meta:
		aliases = "bcopy"
		type = "func"
		size = "21"
		objfiles = "bcopy@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 8B 44 24 04 89 44 24 08 89 54 24 04 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __old_sem_getvalue_015685ac5f7e150c3820945fc53a4e2c {
	meta:
		aliases = "__old_sem_getvalue"
		type = "func"
		size = "29"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 8B 44 24 04 8B 00 A8 01 74 06 D1 E8 89 02 EB 06 C7 02 00 00 00 00 31 C0 C3 }
	condition:
		$pattern
}

rule _obstack_allocated_p_5e50d0b9e479c150a51c2772def87ab6 {
	meta:
		aliases = "_obstack_allocated_p"
		type = "func"
		size = "32"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 8B 44 24 04 8B 40 04 85 C0 74 08 39 D0 73 F5 39 10 72 F1 85 C0 0F 95 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule authunix_marshal_4dc177672fb3f60cc0ea6652208441c7 {
	meta:
		aliases = "authunix_marshal"
		type = "func"
		size = "32"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 8B 44 24 04 8B 40 24 8B 4A 04 FF B0 AC 01 00 00 83 C0 1C 50 52 FF 51 0C 83 C4 0C C3 }
	condition:
		$pattern
}

rule pthread_attr_setstacksize_b6965425ae27b0150c591b7fc658a2d7 {
	meta:
		aliases = "__pthread_attr_setstacksize, pthread_attr_setstacksize"
		type = "func"
		size = "27"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 B8 16 00 00 00 81 FA FF 3F 00 00 76 09 8B 44 24 04 89 50 20 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_mutexattr_setpshared_e2e13198bfa7a09b07b01a90b52bdfa4 {
	meta:
		aliases = "__pthread_mutexattr_setpshared, pthread_condattr_setpshared, pthread_mutexattr_setpshared"
		type = "func"
		size = "22"
		objfiles = "condvar@libpthread.a, mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 B8 16 00 00 00 83 FA 01 77 07 19 C0 F7 D0 83 E0 26 C3 }
	condition:
		$pattern
}

rule pthread_rwlockattr_setkind_np_7d2bf4c3248c20b172c5bb9a6c21fd7c {
	meta:
		aliases = "__GI_pthread_attr_setdetachstate, pthread_attr_setdetachstate, pthread_rwlockattr_setkind_np"
		type = "func"
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
		type = "func"
		size = "24"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 B8 16 00 00 00 83 FA 01 77 09 8B 44 24 04 89 50 04 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_attr_setinheritsched_ef355c139453c5b28a7b300640a40178 {
	meta:
		aliases = "__GI_pthread_attr_setinheritsched, pthread_attr_setinheritsched"
		type = "func"
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
		type = "func"
		size = "24"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 B8 16 00 00 00 83 FA 02 77 09 8B 44 24 04 89 50 04 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_mutexattr_settype_c966b71060253b953a535d91cc13d1cf {
	meta:
		aliases = "__pthread_mutexattr_setkind_np, __pthread_mutexattr_settype, pthread_mutexattr_setkind_np, pthread_mutexattr_settype"
		type = "func"
		size = "23"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 B8 16 00 00 00 83 FA 03 77 08 8B 44 24 04 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule posix_memalign_a20f1cb8676d7b656886a6c5b2fb9ba9 {
	meta:
		aliases = "posix_memalign"
		type = "func"
		size = "41"
		objfiles = "posix_memalign@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 B8 16 00 00 00 F6 C2 03 75 1A FF 74 24 0C 52 E8 ?? ?? ?? ?? 8B 54 24 0C 89 02 5A 59 83 F8 01 19 C0 83 E0 0C C3 }
	condition:
		$pattern
}

rule re_compile_pattern_69a9b75e0e9d1a2b4713c5ea850b847f {
	meta:
		aliases = "re_compile_pattern"
		type = "func"
		size = "60"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 0C 8A 42 1C 83 E0 E9 83 C8 80 88 42 1C 52 8B 0D ?? ?? ?? ?? 8B 54 24 0C 8B 44 24 08 E8 ?? ?? ?? ?? 59 31 D2 85 C0 74 0E 0F B7 84 00 ?? ?? ?? ?? 8D 90 ?? ?? ?? ?? 89 D0 C3 }
	condition:
		$pattern
}

rule xdrstdio_putbytes_f6745f5acad771f00a8fe9bac2f3d64b {
	meta:
		aliases = "xdrstdio_getbytes, xdrstdio_putbytes"
		type = "func"
		size = "43"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 0C B8 01 00 00 00 85 D2 74 1D 8B 44 24 04 FF 70 0C 6A 01 52 FF 74 24 14 E8 ?? ?? ?? ?? 83 C4 10 48 0F 94 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule tcsetpgrp_68cd3486f1a272ae35ed1873da4b2a7d {
	meta:
		aliases = "tcsetpgrp"
		type = "func"
		size = "23"
		objfiles = "tcsetpgrp@libc.a"
	strings:
		$pattern = { ( CC | 8D ) 44 24 08 50 68 10 54 00 00 FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C C3 }
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

rule set_fast_math_9de9d4f7520d3b2a494d4675b382da4f {
	meta:
		aliases = "set_fast_math"
		type = "func"
		size = "214"
		objfiles = "crtfastmath"
	strings:
		$pattern = { ( CC | 8D ) 4C 24 04 83 E4 F0 FF 71 FC 55 89 E5 57 56 53 51 81 EC 18 02 00 00 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 9C 9C 5A 89 D0 81 F2 00 00 20 00 52 9D 9C 5A 9D 31 D0 A9 00 00 20 00 74 54 31 C0 87 DE 0F A2 87 DE 85 C0 74 48 B8 01 00 00 00 87 DF 0F A2 87 DF 89 D6 F7 C2 00 00 00 02 74 33 0F AE 9D E4 FD FF FF 8B BD E4 FD FF FF 89 F8 80 CC 80 89 85 E0 FD FF FF 81 E6 00 00 00 01 75 1F 8B 95 E0 FD FF FF 89 95 E4 FD FF FF 0F AE 95 E4 FD FF FF 8D 65 F0 59 5B 5E 5F 5D 8D 61 FC C3 8D 85 E8 FD FF FF 52 68 00 02 00 00 6A 00 50 E8 ?? ?? ?? ?? 0F AE 85 E8 FD FF FF 83 C4 10 81 CF 40 80 00 00 F6 85 04 FE FF FF 40 0F }
	condition:
		$pattern
}

rule __close_nameservers_5797126c71a4080a98d89322093b671e {
	meta:
		aliases = "__close_nameservers"
		type = "func"
		size = "96"
		objfiles = "closenameservers@libc.a"
	strings:
		$pattern = { ( CC | A1 ) ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 07 50 E8 ?? ?? ?? ?? 59 C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 EB 17 8D 50 FF 89 15 ?? ?? ?? ?? A1 ?? ?? ?? ?? FF 34 90 E8 ?? ?? ?? ?? 5A A1 ?? ?? ?? ?? 85 C0 75 E0 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 58 C3 }
	condition:
		$pattern
}

rule setttyent_82b66c6f26b823e923265f38525e206e {
	meta:
		aliases = "__GI_setttyent, setttyent"
		type = "func"
		size = "68"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | A1 ) ?? ?? ?? ?? 85 C0 74 0D 50 E8 ?? ?? ?? ?? BA 01 00 00 00 EB 2A 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 5A 59 31 D2 85 C0 74 0F 6A 02 50 E8 ?? ?? ?? ?? BA 01 00 00 00 59 58 89 D0 C3 }
	condition:
		$pattern
}

rule endhostent_unlocked_b912aacbc931323968534249c2ed6810 {
	meta:
		aliases = "endhostent_unlocked"
		type = "func"
		size = "34"
		objfiles = "gethostent_r@libc.a"
	strings:
		$pattern = { ( CC | A1 ) ?? ?? ?? ?? 85 C0 74 11 50 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 58 C6 05 ?? ?? ?? ?? 00 C3 }
	condition:
		$pattern
}

rule _rpcdata_2044c19614b8b8922c9e01f3c83cf44d {
	meta:
		aliases = "_rpcdata"
		type = "func"
		size = "29"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | A1 ) ?? ?? ?? ?? 85 C0 75 13 68 B0 10 00 00 6A 01 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule re_set_syntax_d334f8e170de709da20dbec8f104bb34 {
	meta:
		aliases = "re_set_syntax"
		type = "func"
		size = "16"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | A1 ) ?? ?? ?? ?? 8B 54 24 04 89 15 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule getpagesize_1aa5a313fb0e75d8095bb092c574fd16 {
	meta:
		aliases = "__GI_getpagesize, __getpagesize, getpagesize"
		type = "func"
		size = "19"
		objfiles = "getpagesize@libc.a"
	strings:
		$pattern = { ( CC | A1 ) ?? ?? ?? ?? BA 00 10 00 00 85 C0 74 02 89 C2 89 D0 C3 }
	condition:
		$pattern
}

rule pthread_getconcurrency_9306906a3a71020f26be39b72f98096c {
	meta:
		aliases = "__libc_current_sigrtmax, __libc_current_sigrtmin, __pthread_getconcurrency, pthread_getconcurrency"
		type = "func"
		size = "6"
		objfiles = "pthread@libpthread.a, allocrtsig@libc.a"
	strings:
		$pattern = { ( CC | A1 ) ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule xdr_void_62dea3be98d084788202ec199cbcebf6 {
	meta:
		aliases = "__GI__stdlib_mb_cur_max, __GI_xdr_void, _stdlib_mb_cur_max, authnone_validate, floatformat_always_valid, old_sem_extricate_func, xdr_void"
		type = "func"
		size = "6"
		objfiles = "_stdlib_mb_cur_max@libc.a, oldsemaphore@libpthread.a, auth_none@libc.a, xdr@libc.a, floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | B8 ) 01 00 00 00 C3 }
	condition:
		$pattern
}

rule __fpclassifyf_d0760ed233543fbe2ab9f26c5c4d0481 {
	meta:
		aliases = "__GI___fpclassifyf, __fpclassifyf"
		type = "func"
		size = "49"
		objfiles = "s_fpclassifyf@libm.a"
	strings:
		$pattern = { ( CC | B8 ) 02 00 00 00 8B 54 24 04 81 E2 FF FF FF 7F 74 1F B0 03 81 FA FF FF 7F 00 76 15 B0 04 81 FA FF FF 7F 7F 76 0B 31 C0 81 FA 00 00 80 7F 0F 96 C0 C3 }
	condition:
		$pattern
}

rule svcudp_stat_cca2f00a582595d7f5454d6d2948b3e3 {
	meta:
		aliases = "_svcauth_short, rendezvous_stat, svcraw_stat, svcudp_stat"
		type = "func"
		size = "6"
		objfiles = "svc_unix@libc.a, svc_raw@libc.a, svc_udp@libc.a, svc_tcp@libc.a, svc_authux@libc.a"
	strings:
		$pattern = { ( CC | B8 ) 02 00 00 00 C3 }
	condition:
		$pattern
}

rule getpid_6b6fa8f5f0d4712ebe271a71fbef04ab {
	meta:
		aliases = "__GI_getpid, getpid"
		type = "func"
		size = "8"
		objfiles = "getpid@libc.a"
	strings:
		$pattern = { ( CC | B8 ) 14 00 00 00 CD 80 C3 }
	condition:
		$pattern
}

rule getppid_9afd8400a7e7a0c3f1340e8ab7853688 {
	meta:
		aliases = "getppid"
		type = "func"
		size = "8"
		objfiles = "getppid@libc.a"
	strings:
		$pattern = { ( CC | B8 ) 40 00 00 00 CD 80 C3 }
	condition:
		$pattern
}

rule getpgrp_2061eb7462f5c59763f5671c95f5bd2c {
	meta:
		aliases = "getpgrp"
		type = "func"
		size = "8"
		objfiles = "getpgrp@libc.a"
	strings:
		$pattern = { ( CC | B8 ) 41 00 00 00 CD 80 C3 }
	condition:
		$pattern
}

rule rpc_thread_multi_bfe718f7103f42d15626385133c68630 {
	meta:
		aliases = "rpc_thread_multi"
		type = "func"
		size = "35"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | B8 ) ?? ?? ?? ?? 85 C0 74 0F 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? 58 5A C3 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __res_state_6df29da601a97e2ce0e822cd8a3c1c72 {
	meta:
		aliases = "__GI___errno_location, __GI___h_errno_location, __errno_location, __h_errno_location, __libc_pthread_init, __res_state"
		type = "func"
		size = "6"
		objfiles = "libc_pthread_init@libc.a, __errno_location@libc.a, __h_errno_location@libc.a, _res_state@libc.a"
	strings:
		$pattern = { ( CC | B8 ) ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule localeconv_3fd768a6d4d57dafe0ca2586f0809abb {
	meta:
		aliases = "__GI_localeconv, localeconv"
		type = "func"
		size = "53"
		objfiles = "localeconv@libc.a"
	strings:
		$pattern = { ( CC | B8 ) ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 83 C0 04 C7 00 ?? ?? ?? ?? 3D ?? ?? ?? ?? 72 F0 B8 ?? ?? ?? ?? C6 00 FF 40 3D ?? ?? ?? ?? 76 F5 B8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule getuid_7c2320996163a5a91a92182337ed4a1a {
	meta:
		aliases = "__GI_getuid, getuid"
		type = "func"
		size = "8"
		objfiles = "getuid@libc.a"
	strings:
		$pattern = { ( CC | B8 ) C7 00 00 00 CD 80 C3 }
	condition:
		$pattern
}

rule getgid_43841467502e2c11272083900f672688 {
	meta:
		aliases = "__GI_getgid, getgid"
		type = "func"
		size = "8"
		objfiles = "getgid@libc.a"
	strings:
		$pattern = { ( CC | B8 ) C8 00 00 00 CD 80 C3 }
	condition:
		$pattern
}

rule geteuid_a2ef930678bc3005b23805f6b8f57651 {
	meta:
		aliases = "__GI_geteuid, geteuid"
		type = "func"
		size = "8"
		objfiles = "geteuid@libc.a"
	strings:
		$pattern = { ( CC | B8 ) C9 00 00 00 CD 80 C3 }
	condition:
		$pattern
}

rule getegid_b99714489a7ddffc84a058ac1c8dc2d6 {
	meta:
		aliases = "__GI_getegid, getegid"
		type = "func"
		size = "8"
		objfiles = "getegid@libc.a"
	strings:
		$pattern = { ( CC | B8 ) CA 00 00 00 CD 80 C3 }
	condition:
		$pattern
}

rule clone_8ef3be04e211ed0fcf605010e196ea48 {
	meta:
		aliases = "__clone, clone"
		type = "func"
		size = "108"
		objfiles = "clone@libc.a"
	strings:
		$pattern = { ( CC | B8 ) EA FF FF FF 8B 4C 24 04 85 C9 74 5A 8B 4C 24 08 85 C9 74 52 83 E1 F0 83 E9 1C 8B 44 24 10 89 41 0C 8B 44 24 04 89 41 08 C7 41 04 00 00 00 00 C7 01 00 00 00 00 53 56 57 8B 74 24 24 8B 54 24 20 8B 5C 24 18 8B 7C 24 28 B8 78 00 00 00 CD 80 5F 5E 5B 85 C0 7C 10 74 01 C3 89 F5 FF D3 89 C3 B8 01 00 00 00 CD 80 E9 ?? ?? ?? ?? }
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

rule atexit_06b23437573b6455f1fb88fdf48ecd49 {
	meta:
		aliases = "atexit"
		type = "func"
		size = "31"
		objfiles = "atexit@libc.a"
	strings:
		$pattern = { ( CC | BA ) ?? ?? ?? ?? 85 D2 74 06 8B 15 ?? ?? ?? ?? 52 6A 00 FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C C3 }
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

rule xdrmem_destroy_2b6be1eb3c8d07c259f5da1535d26263 {
	meta:
		aliases = "__cyg_profile_func_enter, __cyg_profile_func_exit, __linuxthreads_create_event, __linuxthreads_death_event, __linuxthreads_reap_event, __stub1, __stub2, authnone_destroy, authnone_verf, authunix_nextverf, clntraw_abort, clntraw_destroy, clntraw_geterr, clnttcp_abort, clntudp_abort, clntunix_abort, noop_handler, pthread_handle_sigdebug, pthread_null_sighandler, svcraw_destroy, xdrmem_destroy"
		type = "func"
		size = "1"
		objfiles = "clnt_raw@libc.a, clnt_unix@libc.a, clnt_tcp@libc.a, auth_unix@libc.a, nsl@libnsl.a"
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

rule __md5_Init_8e121a7e9e17edad5669c991716c95fb {
	meta:
		aliases = "__md5_Init"
		type = "func"
		size = "42"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | C7 ) 40 14 00 00 00 00 C7 40 10 00 00 00 00 C7 00 01 23 45 67 C7 40 04 89 AB CD EF C7 40 08 FE DC BA 98 C7 40 0C 76 54 32 10 C3 }
	condition:
		$pattern
}

rule llroundf_50a91947cae998517b5cdd3fc44f02d3 {
	meta:
		aliases = "llrintf, llroundf"
		type = "func"
		size = "18"
		objfiles = "llrintf@libm.a, llroundf@libm.a"
	strings:
		$pattern = { ( CC | D9 ) 44 24 04 83 EC 08 DD 1C 24 E8 ?? ?? ?? ?? 59 59 C3 }
	condition:
		$pattern
}

rule lroundf_f5f2daa96b9e124cf33f93c469bdf2db {
	meta:
		aliases = "ilogbf, lrintf, lroundf"
		type = "func"
		size = "18"
		objfiles = "ilogbf@libm.a, lroundf@libm.a, lrintf@libm.a"
	strings:
		$pattern = { ( CC | D9 ) 44 24 04 83 EC 08 DD 1C 24 E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule difftime_9e4ea5c9e61e1d829edaa7983571f49a {
	meta:
		aliases = "difftime"
		type = "func"
		size = "9"
		objfiles = "difftime@libc.a"
	strings:
		$pattern = { ( CC | DB ) 44 24 08 DA 6C 24 04 C3 }
	condition:
		$pattern
}

rule __fp_range_check_d958905d0f7f9fa30e8ff257ad8a9fba {
	meta:
		aliases = "__fp_range_check"
		type = "func"
		size = "75"
		objfiles = "__fp_range_check@libc.a"
	strings:
		$pattern = { ( CC | DB ) 6C 24 04 D9 05 ?? ?? ?? ?? D9 C1 D8 C9 D9 CA DD E2 DF E0 DD DA 9E 75 2D 7A 2B D9 EE D9 CA DD EA DF E0 DD D9 9E 7A 02 74 1E DB 6C 24 10 DC C9 DA E9 DF E0 9E 7A 02 74 11 E8 ?? ?? ?? ?? C7 00 22 00 00 00 EB 04 DD D8 DD D8 C3 }
	condition:
		$pattern
}

rule fma_394493ef54a844d9006d78ae6390ed25 {
	meta:
		aliases = "__GI_fma, fma"
		type = "func"
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
		type = "func"
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
		type = "func"
		size = "10"
		objfiles = "ftestexcept@libm.a"
	strings:
		$pattern = { ( CC | DF ) E0 23 44 24 04 83 E0 3D C3 }
	condition:
		$pattern
}

rule svcunix_rendezvous_abort_ae5fed6b8dcb4a035c3321eab387f4a2 {
	meta:
		aliases = "svctcp_rendezvous_abort, svcunix_rendezvous_abort"
		type = "func"
		size = "5"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | E8 ) ?? ?? ?? ?? }
	condition:
		$pattern
}

rule on_exit_4837c50262956560f4c78fdbb1746958 {
	meta:
		aliases = "on_exit"
		type = "func"
		size = "37"
		objfiles = "on_exit@libc.a"
	strings:
		$pattern = { ( CC | E8 ) ?? ?? ?? ?? 89 C2 83 C8 FF 85 D2 74 16 8B 44 24 04 89 42 04 8B 44 24 08 89 42 08 C7 02 02 00 00 00 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_self_5daf75c711fb4c0b7a9c42ce329f9df7 {
	meta:
		aliases = "__GI_pthread_self, pthread_self"
		type = "func"
		size = "9"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | E8 ) ?? ?? ?? ?? 8B 40 10 C3 }
	condition:
		$pattern
}

rule __errno_location_924b36085dd349fc4839c1942a704bbd {
	meta:
		aliases = "__errno_location"
		type = "func"
		size = "9"
		objfiles = "errno@libpthread.a"
	strings:
		$pattern = { ( CC | E8 ) ?? ?? ?? ?? 8B 40 44 C3 }
	condition:
		$pattern
}

rule __h_errno_location_ea76e524f18a904ac01defd83813288c {
	meta:
		aliases = "__h_errno_location"
		type = "func"
		size = "9"
		objfiles = "errno@libpthread.a"
	strings:
		$pattern = { ( CC | E8 ) ?? ?? ?? ?? 8B 40 4C C3 }
	condition:
		$pattern
}

rule pthread_handle_sigrestart_0fdf48eb2ff8202fc073c71ff3223827 {
	meta:
		aliases = "pthread_handle_sigrestart"
		type = "func"
		size = "28"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | E8 ) ?? ?? ?? ?? 8B 54 24 04 89 50 20 8B 40 24 85 C0 74 08 6A 01 50 E8 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule __rpc_thread_svc_fdset_4da2cb06603d3f5bdf5f8c9dd8de006b {
	meta:
		aliases = "__GI___rpc_thread_svc_fdset, __rpc_thread_svc_fdset"
		type = "func"
		size = "22"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | E8 ) ?? ?? ?? ?? BA ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 02 89 C2 89 D0 C3 }
	condition:
		$pattern
}

rule __rpc_thread_createerr_024a094824dcfbecdf69afeb092da282 {
	meta:
		aliases = "__GI___rpc_thread_createerr, __rpc_thread_createerr"
		type = "func"
		size = "26"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | E8 ) ?? ?? ?? ?? BA ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 8D 90 80 00 00 00 89 D0 C3 }
	condition:
		$pattern
}

rule __rpc_thread_svc_pollfd_8d1b807f756056cf87e7019d67127eb1 {
	meta:
		aliases = "__GI___rpc_thread_svc_pollfd, __rpc_thread_svc_pollfd"
		type = "func"
		size = "26"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | E8 ) ?? ?? ?? ?? BA ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 8D 90 90 00 00 00 89 D0 C3 }
	condition:
		$pattern
}

rule __rpc_thread_svc_max_pollfd_f50b36dc9991fe51c11e183376565e86 {
	meta:
		aliases = "__GI___rpc_thread_svc_max_pollfd, __rpc_thread_svc_max_pollfd"
		type = "func"
		size = "26"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | E8 ) ?? ?? ?? ?? BA ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 8D 90 94 00 00 00 89 D0 C3 }
	condition:
		$pattern
}

rule sem_open_fc399c31667f08a6d600f6272ea61169 {
	meta:
		aliases = "sem_open"
		type = "func"
		size = "14"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | E8 ) ?? ?? ?? ?? C7 00 26 00 00 00 31 C0 C3 }
	condition:
		$pattern
}

rule sem_unlink_7cc9779505d1c64f89de4f58094c2c65 {
	meta:
		aliases = "sem_close, sem_unlink"
		type = "func"
		size = "15"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | E8 ) ?? ?? ?? ?? C7 00 26 00 00 00 83 C8 FF C3 }
	condition:
		$pattern
}

rule raise_fdf1f4eeabbc454044f76306b8595759 {
	meta:
		aliases = "__GI_raise, raise"
		type = "func"
		size = "18"
		objfiles = "raise@libc.a"
	strings:
		$pattern = { ( CC | E8 ) ?? ?? ?? ?? FF 74 24 04 50 E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule free_mem_ceffd0e1db5cad3a660ef7cac6dfc160 {
	meta:
		aliases = "free_mem"
		type = "func"
		size = "18"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | E8 ) ?? ?? ?? ?? FF B0 9C 00 00 00 E8 ?? ?? ?? ?? 58 C3 }
	condition:
		$pattern
}

rule xdr_u_longlong_t_22aa66de8a720f160758a4fe68aab955 {
	meta:
		aliases = "__GI_cabs, __GI_setmntent, __GI_xdr_enum, __GI_xdr_int, __GI_xdr_u_int, __pthread_initialize, cabs, mq_close, partition_delete, rand, setmntent, splay_tree_xmalloc_deallocate, vfork, xdr_enum, xdr_int, xdr_longlong_t, xdr_u_int, xdr_u_longlong_t"
		type = "func"
		size = "5"
		objfiles = "splay_tree@libiberty.a, partition@libiberty.a, ptfork@libpthread.a, mntent@libc.a, xdr@libc.a"
	strings:
		$pattern = { ( CC | E9 ) ?? ?? ?? ?? }
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

rule __rpc_thread_svc_cleanup_91bcec0bdcd27cbc66a7f3b88ed4bfe0 {
	meta:
		aliases = "__rpc_thread_svc_cleanup"
		type = "func"
		size = "31"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | EB ) 0D FF 70 08 FF 70 04 E8 ?? ?? ?? ?? 58 5A E8 ?? ?? ?? ?? 8B 80 B8 00 00 00 85 C0 75 E4 C3 }
	condition:
		$pattern
}

rule pex_unix_cleanup_32a093eff127b3eedaa06c147dc0694b {
	meta:
		aliases = "hex_init, pex_unix_cleanup"
		type = "func"
		size = "2"
		objfiles = "hex@libiberty.a, pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | F3 ) C3 }
	condition:
		$pattern
}

rule __pthread_restart_new_6c229a224a1621fedb64c49e28c884d1 {
	meta:
		aliases = "__pthread_restart_new"
		type = "func"
		size = "21"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | FF ) 35 ?? ?? ?? ?? 8B 44 24 08 FF 70 14 E8 ?? ?? ?? ?? 58 5A C3 }
	condition:
		$pattern
}

rule _dl_app_init_array_c7484a98753a42b2a2e738aa10bcf62f {
	meta:
		aliases = "_dl_app_init_array"
		type = "func"
		size = "13"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | FF ) 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 C3 }
	condition:
		$pattern
}

rule getwchar_unlocked_d0a919a1423a1611f85f059ef10ad627 {
	meta:
		aliases = "_dl_app_fini_array, getwchar, getwchar_unlocked"
		type = "func"
		size = "13"
		objfiles = "libdl@libdl.a, getwchar@libc.a, getwchar_unlocked@libc.a"
	strings:
		$pattern = { ( CC | FF ) 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A C3 }
	condition:
		$pattern
}

rule putwchar_unlocked_e678cb7e6e8f447d22bcf73b752cb439 {
	meta:
		aliases = "putwchar_unlocked"
		type = "func"
		size = "18"
		objfiles = "putwchar_unlocked@libc.a"
	strings:
		$pattern = { ( CC | FF ) 35 ?? ?? ?? ?? FF 74 24 08 E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule execv_82b716818f0867f9c21d2e5a6d1174c5 {
	meta:
		aliases = "__GI_execv, execv"
		type = "func"
		size = "23"
		objfiles = "execv@libc.a"
	strings:
		$pattern = { ( CC | FF ) 35 ?? ?? ?? ?? FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule posix_openpt_05f9c0da9eeeeab48b334150000bd3cf {
	meta:
		aliases = "__GI_posix_openpt, posix_openpt"
		type = "func"
		size = "17"
		objfiles = "getpt@libc.a"
	strings:
		$pattern = { ( CC | FF ) 74 24 04 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A 59 C3 }
	condition:
		$pattern
}

rule tcflow_22d752c2ea826f4ff68b2146b4a3740c {
	meta:
		aliases = "tcflow"
		type = "func"
		size = "22"
		objfiles = "tcflow@libc.a"
	strings:
		$pattern = { ( CC | FF ) 74 24 08 68 0A 54 00 00 FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule tcflush_226f3677d668421e610fe5b01d28a8e1 {
	meta:
		aliases = "tcflush"
		type = "func"
		size = "22"
		objfiles = "tcflush@libc.a"
	strings:
		$pattern = { ( CC | FF ) 74 24 08 68 0B 54 00 00 FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule creat64_33f68df9a733aceaf7f24bbe441fc19c {
	meta:
		aliases = "creat, creat64"
		type = "func"
		size = "22"
		objfiles = "creat@libc.a, creat64@libc.a"
	strings:
		$pattern = { ( CC | FF ) 74 24 08 68 41 02 00 00 FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule mq_getattr_4ffe811b206b5540a8cd0461ad5ed514 {
	meta:
		aliases = "bzero, gmtime_r, mq_getattr"
		type = "func"
		size = "19"
		objfiles = "bzero@libc.a, gmtime_r@libc.a, mq_getsetattr@librt.a"
	strings:
		$pattern = { ( CC | FF ) 74 24 08 6A 00 FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule putw_bf797320ca35956e2d8b475b8a6e71f7 {
	meta:
		aliases = "putw"
		type = "func"
		size = "23"
		objfiles = "putw@libc.a"
	strings:
		$pattern = { ( CC | FF ) 74 24 08 6A 01 6A 04 8D 44 24 10 50 E8 ?? ?? ?? ?? 48 83 C4 10 C3 }
	condition:
		$pattern
}

rule putwc_unlocked_b086346fe2fcd137f3c4f541ac2d12da {
	meta:
		aliases = "__GI_fputwc_unlocked, fputwc_unlocked, putwc_unlocked"
		type = "func"
		size = "33"
		objfiles = "fputwc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | FF ) 74 24 08 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 0C 83 CA FF 85 C0 74 04 8B 54 24 04 89 D0 C3 }
	condition:
		$pattern
}

rule exp2_2217aae7994b9c57ff98a046d856d477 {
	meta:
		aliases = "__GI_exp2, exp2"
		type = "func"
		size = "24"
		objfiles = "w_exp2@libm.a"
	strings:
		$pattern = { ( CC | FF ) 74 24 08 FF 74 24 08 68 00 00 00 40 6A 00 E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule fdim_9821af0f1e4609ab05c02d150961f2ec {
	meta:
		aliases = "__GI_fdim, fdim"
		type = "func"
		size = "56"
		objfiles = "s_fdim@libm.a"
	strings:
		$pattern = { ( CC | FF ) 74 24 08 FF 74 24 08 E8 ?? ?? ?? ?? 5A 59 83 F8 01 77 07 D9 05 ?? ?? ?? ?? C3 DD 44 24 04 DD 44 24 0C D9 C9 DA E9 DF E0 9E 77 03 D9 EE C3 DD 44 24 04 DC 64 24 0C C3 }
	condition:
		$pattern
}

rule fmax_089335b2787679981a1badfdfb4c3d8f {
	meta:
		aliases = "__GI_fmax, fmax"
		type = "func"
		size = "74"
		objfiles = "s_fmax@libm.a"
	strings:
		$pattern = { ( CC | FF ) 74 24 08 FF 74 24 08 E8 ?? ?? ?? ?? 5A 59 85 C0 74 32 FF 74 24 10 FF 74 24 10 E8 ?? ?? ?? ?? 5A 59 85 C0 75 06 DD 44 24 0C EB 11 DD 44 24 04 DD 44 24 0C D9 C9 DD E9 DF E0 9E 77 06 DD 5C 24 04 EB 02 DD D8 DD 44 24 04 C3 }
	condition:
		$pattern
}

rule fmin_659b7df0831594bc581b7ab5f5974ab9 {
	meta:
		aliases = "__GI_fmin, fmin"
		type = "func"
		size = "76"
		objfiles = "s_fmin@libm.a"
	strings:
		$pattern = { ( CC | FF ) 74 24 08 FF 74 24 08 E8 ?? ?? ?? ?? 5A 59 85 C0 74 34 FF 74 24 10 FF 74 24 10 E8 ?? ?? ?? ?? 5A 59 85 C0 75 06 DD 44 24 0C EB 13 DD 44 24 0C DD 44 24 04 D9 C9 DD E1 DF E0 DD D9 9E 77 06 DD 5C 24 04 EB 02 DD D8 DD 44 24 04 C3 }
	condition:
		$pattern
}

rule ldexp_b953d56f97e155fd314280048846f9b2 {
	meta:
		aliases = "__GI_ldexp, ldexp"
		type = "func"
		size = "108"
		objfiles = "s_ldexp@libm.a"
	strings:
		$pattern = { ( CC | FF ) 74 24 08 FF 74 24 08 E8 ?? ?? ?? ?? 5A 59 85 C0 74 54 DD 44 24 04 D9 EE D9 C9 DA E9 DF E0 9E 7A 02 74 43 FF 74 24 0C FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? DD 54 24 10 83 EC 08 DD 1C 24 E8 ?? ?? ?? ?? 83 C4 14 85 C0 74 11 DD 44 24 04 D9 EE D9 C9 DA E9 DF E0 9E 75 0D 7A 0B E8 ?? ?? ?? ?? C7 00 22 00 00 00 DD 44 24 04 C3 }
	condition:
		$pattern
}

rule vwscanf_8656ba417f55ecd54498627fc6f064b6 {
	meta:
		aliases = "vprintf, vscanf, vwprintf, vwscanf"
		type = "func"
		size = "23"
		objfiles = "vprintf@libc.a, vwprintf@libc.a, vscanf@libc.a, vwscanf@libc.a"
	strings:
		$pattern = { ( CC | FF ) 74 24 08 FF 74 24 08 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule getline_8af70975a3b7202da3f0924b6a67d0cb {
	meta:
		aliases = "__GI_getline, getline"
		type = "func"
		size = "23"
		objfiles = "getline@libc.a"
	strings:
		$pattern = { ( CC | FF ) 74 24 0C 6A 0A FF 74 24 10 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule fseeko_c988c3466338bd611a4c400ed6b310ad {
	meta:
		aliases = "__GI_fseek, fseek, fseeko"
		type = "func"
		size = "24"
		objfiles = "fseeko@libc.a"
	strings:
		$pattern = { ( CC | FF ) 74 24 0C 8B 44 24 0C 99 52 50 FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule vsprintf_d40288e0265d760686843db233be4be1 {
	meta:
		aliases = "vsprintf"
		type = "func"
		size = "23"
		objfiles = "vsprintf@libc.a"
	strings:
		$pattern = { ( CC | FF ) 74 24 0C FF 74 24 0C 6A FF FF 74 24 10 E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule verrx_e995d28d2bc805c6592260c44650cadd {
	meta:
		aliases = "__GI_verr, __GI_verrx, verr, verrx"
		type = "func"
		size = "22"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | FF ) 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? FF 74 24 0C E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wait3_b031f3b2d18ad88e9e7483de814f76f0 {
	meta:
		aliases = "wait3"
		type = "func"
		size = "23"
		objfiles = "wait3@libc.a"
	strings:
		$pattern = { ( CC | FF ) 74 24 0C FF 74 24 0C FF 74 24 0C 6A FF E8 ?? ?? ?? ?? 83 C4 10 C3 }
	condition:
		$pattern
}

rule semtimedop_9ee480999a287014a812f60e9f364171 {
	meta:
		aliases = "semtimedop"
		type = "func"
		size = "29"
		objfiles = "semtimedop@libc.a"
	strings:
		$pattern = { ( CC | FF ) 74 24 10 FF 74 24 0C 6A 00 FF 74 24 18 FF 74 24 14 6A 04 E8 ?? ?? ?? ?? 83 C4 18 C3 }
	condition:
		$pattern
}

rule wcsrtombs_16011af63c374c0fc46c99c13b47eb95 {
	meta:
		aliases = "__GI_wcsrtombs, wcsrtombs"
		type = "func"
		size = "27"
		objfiles = "wcsrtombs@libc.a"
	strings:
		$pattern = { ( CC | FF ) 74 24 10 FF 74 24 10 6A FF FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? 83 C4 14 C3 }
	condition:
		$pattern
}

rule __get_hosts_byname_r_d95a27034efdf49558ea5feb7638246d {
	meta:
		aliases = "__get_hosts_byname_r"
		type = "func"
		size = "41"
		objfiles = "get_hosts_byname_r@libc.a"
	strings:
		$pattern = { ( CC | FF ) 74 24 1C FF 74 24 1C FF 74 24 1C FF 74 24 1C FF 74 24 1C 6A 00 FF 74 24 20 FF 74 24 20 6A 00 E8 ?? ?? ?? ?? 83 C4 24 C3 }
	condition:
		$pattern
}

