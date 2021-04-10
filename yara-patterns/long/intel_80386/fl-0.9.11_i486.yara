// YARA rules, version 0.1.1_2020_04_26

rule lbasename_660b301d569d7b273277759b254d7a20 {
	meta:
		aliases = "lbasename"
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
		size = "46"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 31 ) C0 8B 56 04 39 57 04 74 06 C3 0F 1F 44 00 00 48 83 EC 08 48 8B 76 08 48 8B 7F 08 E8 ?? ?? ?? ?? 85 C0 0F 94 C0 48 83 C4 08 0F B6 C0 C3 }
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

rule sort_pointers_a56a7795ce18bfce7dd1b07cf61260b7 {
	meta:
		aliases = "sort_pointers"
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
		size = "17"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 31 ) D2 48 39 F7 B8 FF FF FF FF 0F 97 C2 0F 43 C2 C3 }
	condition:
		$pattern
}

rule _start_a74091ded31fe9341c86ffba27b8ff00 {
	meta:
		aliases = "_start"
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
		size = "49"
		objfiles = "Scrt1"
	strings:
		$pattern = { ( CC | 31 ) ED 5E 89 E1 83 E4 F0 50 54 52 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? FF B3 ?? ?? ?? ?? FF B3 ?? ?? ?? ?? 51 56 FF B3 ?? ?? ?? ?? E8 ?? ?? ?? ?? F4 }
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

rule iterative_hash_80b3e0acc0f889b7de26d2dfd9cb6752 {
	meta:
		aliases = "iterative_hash"
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
		size = "91"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 48 89 F5 53 8B 45 00 48 63 D0 48 8D 1C D5 F8 FF FF FF EB 20 66 0F 1F 44 00 00 49 8B 14 24 83 E8 01 48 8D 4B F8 89 45 00 48 8B 3C 1A 48 85 FF 75 11 48 89 CB 85 C0 7F E2 5B 5D 41 5C C3 0F 1F 44 00 00 E8 ?? ?? ?? ?? 49 8B 04 24 48 C7 04 18 00 00 00 00 EB AF }
	condition:
		$pattern
}

rule cplus_demangle_name_to_style_77eed69686d6577052d3314d0d1e5f26 {
	meta:
		aliases = "cplus_demangle_name_to_style"
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
		size = "179"
		objfiles = "concat@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 55 48 89 FD 53 48 89 F3 48 83 EC 58 48 85 F6 48 8D 84 24 80 00 00 00 48 89 54 24 30 48 89 4C 24 38 4C 89 44 24 40 4C 89 4C 24 48 48 89 44 24 10 48 8D 44 24 20 C7 44 24 08 10 00 00 00 48 89 44 24 18 75 1B EB 54 0F 1F 00 89 CA 48 03 54 24 18 83 C1 08 89 4C 24 08 48 8B 1A 48 85 DB 74 3B 48 89 DF E8 ?? ?? ?? ?? 48 89 EF 48 89 C2 48 89 DE 49 89 C4 E8 ?? ?? ?? ?? 8B 4C 24 08 4C 01 E5 83 F9 2F 76 C5 48 8B 54 24 10 48 8B 1A 48 8D 42 08 48 89 44 24 10 48 85 DB 75 C5 C6 45 00 00 48 83 C4 58 4C 89 E8 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule strtoerrno_5486667c55fc0be2449253edb2d6ad4f {
	meta:
		aliases = "strtosigno, strtoerrno"
		size = "111"
		objfiles = "strsignal@libiberty.a, strerror@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 55 53 48 83 EC 08 48 85 FF 74 47 48 83 3D ?? ?? ?? ?? 00 74 4C 44 8B 25 ?? ?? ?? ?? 41 83 FC 00 7E 30 48 8B 2D ?? ?? ?? ?? 31 DB 66 0F 1F 44 00 00 48 8B 75 00 48 85 F6 74 0C 4C 89 EF E8 ?? ?? ?? ?? 85 C0 74 0E 83 C3 01 48 83 C5 08 44 39 E3 75 DF 31 DB 48 83 C4 08 89 D8 5B 5D 41 5C 41 5D C3 E8 23 FE FF FF EB AD }
	condition:
		$pattern
}

rule C_alloca_4830e97f38c4b79c593201445aec2a23 {
	meta:
		aliases = "C_alloca"
		size = "229"
		objfiles = "alloca@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 55 53 48 83 EC 18 8B 05 ?? ?? ?? ?? 85 C0 0F 84 B5 00 00 00 48 8B 3D ?? ?? ?? ?? 44 8B 25 ?? ?? ?? ?? 48 8D 6C 24 0F 48 85 FF 74 7D 0F 1F 44 00 00 41 83 FC 00 7E 52 48 39 6F 08 77 54 4D 85 ED 48 89 3D ?? ?? ?? ?? 74 6E 49 8D 7D 10 E8 ?? ?? ?? ?? 48 85 C0 74 7C 48 8B 15 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 83 C0 10 48 89 50 F0 48 8D 54 24 0F 48 89 50 F8 48 83 C4 18 5B 5D 41 5C 41 5D C3 0F 1F 84 00 00 00 00 00 74 B2 48 39 6F 08 73 AC 48 8B 1F E8 ?? ?? ?? ?? 48 85 DB 74 0B 48 89 DF EB 8E 66 0F 1F 44 00 00 31 FF 4D 85 ED 48 89 3D ?? ?? ?? ?? 75 92 48 83 C4 18 31 C0 5B 5D 41 5C }
	condition:
		$pattern
}

rule fibheap_replace_key_data_04ebcb29e97bbffeb8afd81b748b2604 {
	meta:
		aliases = "fibheap_replace_key_data"
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
		size = "199"
		objfiles = "floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | 44 ) 01 C1 41 56 41 89 CA 41 C1 EA 03 85 F6 53 0F 85 93 00 00 00 C1 EA 03 83 E1 07 83 EA 01 41 89 C9 8D 49 F8 44 29 D2 89 D0 F7 D9 83 C2 01 0F B6 04 07 D3 F8 48 98 45 89 C2 BB 01 00 00 00 45 29 CA EB 36 0F 1F 44 00 00 44 89 D1 41 89 DE 41 D3 E6 44 89 F1 83 E9 01 41 21 CB 44 89 C9 41 D3 E3 4D 63 DB 4C 09 D8 8D 4A 01 41 83 C1 08 83 EA 01 85 F6 0F 44 D1 41 83 EA 08 45 39 C8 76 22 89 D1 41 83 FA 07 44 0F B6 1C 0F 76 BD 44 89 C9 41 D3 E3 4D 63 DB 4C 09 D8 EB CD 0F 1F 80 00 00 00 00 5B 41 5E C3 0F 1F 40 00 44 89 D0 83 E1 07 41 8D 52 FF 0F B6 04 07 41 89 C9 8D 49 F8 F7 D9 D3 F8 48 98 E9 6F FF FF FF }
	condition:
		$pattern
}

rule strncmp_c78e26b387d5b26da80132cd32588865 {
	meta:
		aliases = "strncmp"
		size = "51"
		objfiles = "strncmp@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 01 F2 EB 1B 0F 1F 00 48 83 C7 01 48 83 C6 01 0F B6 47 FF 0F B6 4E FF 38 C8 75 14 84 C0 74 05 48 39 D6 75 E3 31 C0 C3 0F 1F 84 00 00 00 00 00 29 C8 C3 }
	condition:
		$pattern
}

rule spaces_e6c11297328fa42476a1d332b372a286 {
	meta:
		aliases = "spaces"
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
		size = "139"
		objfiles = "partition@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 63 F6 48 83 C7 08 48 63 D2 48 8D 04 76 48 8D 0C C7 48 8D 04 52 48 8D 34 C7 4C 63 01 8B 06 44 39 C0 74 4C 8B 56 10 39 51 10 73 4C 48 63 D0 4F 8D 04 40 48 8D 14 52 46 8B 44 C7 10 44 01 44 D7 10 48 8B 79 08 89 01 48 39 CF 48 89 FA 74 0C 90 89 02 48 8B 52 08 48 39 CA 75 F5 48 8B 56 08 48 89 7E 08 48 89 51 08 C3 0F 1F 84 00 00 00 00 00 F3 C3 66 0F 1F 44 00 00 48 89 F2 48 89 CE 48 89 D1 89 C2 44 89 C0 4C 63 C2 EB A1 }
	condition:
		$pattern
}

rule get_run_time_b37d8e2b582df0b8d61895784c62861b {
	meta:
		aliases = "get_run_time"
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
		size = "35"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 41 89 C9 48 89 F1 89 54 24 08 4C 89 04 24 31 F6 41 89 D0 31 D2 E8 C2 AD FF FF 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule strerrno_733bef70a4b714cdd6ea1b69979a7ad7 {
	meta:
		aliases = "strsigno, strerrno"
		size = "127"
		objfiles = "strsignal@libiberty.a, strerror@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 83 3D ?? ?? ?? ?? 00 74 62 85 FF 78 4E 3B 3D ?? ?? ?? ?? 7D 46 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 1A 48 63 D7 48 8B 04 D0 48 85 C0 74 0E 48 83 C4 18 C3 66 0F 1F 84 00 00 00 00 00 89 FA BE ?? ?? ?? ?? BF ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 48 83 C4 18 C3 0F 1F 00 31 C0 48 83 C4 18 C3 66 0F 1F 84 00 00 00 00 00 89 7C 24 0C E8 97 FE FF FF 8B 7C 24 0C EB 8F }
	condition:
		$pattern
}

rule xexit_1e52182c4afcd86c9eaace9db223d8b3 {
	meta:
		aliases = "xexit"
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
		size = "67"
		objfiles = "alloca@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 20 48 8D 54 24 0F 48 39 D0 19 C0 83 E0 02 83 E8 01 89 05 ?? ?? ?? ?? 48 83 C4 18 C3 0F 1F 44 00 00 48 8D 44 24 0F 48 89 05 ?? ?? ?? ?? E8 BF FF FF FF EB E3 }
	condition:
		$pattern
}

rule cplus_demangle_v3_5d6692dcc868f22a850d052e9fd15c0a {
	meta:
		aliases = "cplus_demangle_v3"
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
		size = "20"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F7 BA B6 01 00 00 BE 41 02 00 00 31 C0 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule choose_tmpdir_6426190c5240271afa335c755bc42a86 {
	meta:
		aliases = "choose_tmpdir"
		size = "472"
		objfiles = "make_temp_file@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 48 85 C0 74 04 F3 C3 66 90 41 54 BF ?? ?? ?? ?? 55 53 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 62 BE 07 00 00 00 48 89 C7 E8 ?? ?? ?? ?? 85 C0 75 51 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 8D 78 02 44 8D 60 01 89 C5 E8 ?? ?? ?? ?? 48 89 DE 48 89 C7 E8 ?? ?? ?? ?? C6 04 28 2F 42 C6 04 20 00 5B 5D 48 89 05 ?? ?? ?? ?? 41 5C C3 0F 1F 80 00 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C3 48 85 DB 74 26 BE 07 00 00 00 48 89 DF E8 ?? ?? ?? ?? 85 C0 75 15 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 94 66 0F 1F 84 00 00 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? }
	condition:
		$pattern
}

rule d_number_DOT_isra_DOT_0_5d61a7753c642c24469af354e167e206 {
	meta:
		aliases = "d_number.isra.0"
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
		size = "43"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 18 48 8D 50 01 48 89 57 18 80 38 5F 75 17 48 8D 50 02 48 89 57 18 80 78 01 5A 75 09 E9 0C FC FF FF 0F 1F 40 00 31 C0 C3 }
	condition:
		$pattern
}

rule htab_elements_72e41c2da0cd9b70b565650a43a4741e {
	meta:
		aliases = "htab_elements"
		size = "9"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 28 48 2B 47 30 C3 }
	condition:
		$pattern
}

rule d_substitution_f38f6d2757660f642d8703e5fcf8103f {
	meta:
		aliases = "d_substitution"
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
		size = "64"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8D 04 17 48 89 39 89 71 10 48 89 79 18 C7 41 28 00 00 00 00 48 89 41 08 8D 04 12 89 51 3C C7 41 38 00 00 00 00 C7 41 40 00 00 00 00 89 41 2C 48 C7 41 48 00 00 00 00 C7 41 50 00 00 00 00 C3 }
	condition:
		$pattern
}

rule byte_compile_range_cd5be65ad11023e48f03fd4b382a5166 {
	meta:
		aliases = "byte_compile_range"
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
		size = "122"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 4C ) 8B 07 31 C0 41 0F BE 10 0F B6 CA F6 84 09 ?? ?? ?? ?? 04 74 53 49 8D 48 01 83 EA 30 B0 01 89 16 48 89 0F 45 0F BE 40 01 45 0F B6 C8 43 F6 84 09 ?? ?? ?? ?? 04 74 31 0F 1F 84 00 00 00 00 00 8D 04 92 48 83 C1 01 41 8D 54 40 D0 44 0F BE 01 41 0F B6 C0 F6 84 00 ?? ?? ?? ?? 04 75 E2 41 80 F8 5F B8 01 00 00 00 74 07 F3 C3 0F 1F 44 00 00 48 83 C1 01 48 89 0F 89 16 C3 }
	condition:
		$pattern
}

rule setup_salt_8e04848e213208cb33ee8f7da9e8e377 {
	meta:
		aliases = "setup_salt"
		size = "60"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 53 ) 3B 05 ?? ?? ?? ?? 74 31 A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 BB 00 00 80 00 B9 01 00 00 00 31 D2 EB 0F 85 C8 74 06 09 1D ?? ?? ?? ?? 01 C9 D1 EB 42 83 FA 17 7E EC 5B C3 }
	condition:
		$pattern
}

rule fibheap_delete_7c89741389a23317408280be8c75d21d {
	meta:
		aliases = "fibheap_delete"
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
		size = "23"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 8B 5F 08 48 C7 47 08 00 00 00 00 E8 ?? ?? ?? ?? 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule __GI_sync_file_range_3d06f6540ffb5ed30dae4106a5a12f4e {
	meta:
		aliases = "sync_file_range, __GI_sync_file_range"
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

rule abort_f8d9b0a14b257dfb2daf27f5190e7040 {
	meta:
		aliases = "__GI_abort, abort"
		size = "273"
		objfiles = "abort@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC 24 01 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 20 00 00 00 83 C4 10 EB 0B C7 84 84 98 00 00 00 00 00 00 00 48 79 F2 53 53 6A 06 8D 9C 24 A4 00 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 0E 51 6A 00 53 6A 01 E8 ?? ?? ?? ?? 83 C4 10 80 3D ?? ?? ?? ?? 00 75 2F C6 05 ?? ?? ?? ?? 01 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 06 00 00 00 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 A0 ?? ?? ?? ?? 3C 01 75 58 C6 05 ?? ?? ?? ?? 02 52 68 8C 00 00 00 6A 00 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 44 24 1C 00 00 00 00 B8 20 00 00 00 83 C4 10 EB 08 C7 44 84 10 FF FF FF FF 48 79 F5 C7 84 }
	condition:
		$pattern
}

rule signal_c70b3179c7cd2dd284382e7762499f69 {
	meta:
		aliases = "__bsd_signal, bsd_signal, __GI_signal, signal"
		size = "175"
		objfiles = "signal@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC 28 01 00 00 8B 9C 24 30 01 00 00 8B 84 24 34 01 00 00 83 F8 FF 74 09 85 DB 7E 05 83 FB 40 7E 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 74 89 84 24 9C 00 00 00 B8 20 00 00 00 EB 0B C7 84 84 A0 00 00 00 00 00 00 00 48 79 F2 52 52 53 8D 84 24 AC 00 00 00 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 41 50 50 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 83 F8 01 19 C0 25 00 00 00 10 89 84 24 24 01 00 00 8D 44 24 14 50 8D 84 24 A4 00 00 00 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 06 8B 44 24 10 EB 03 83 C8 FF 81 C4 28 01 00 00 5B C3 }
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

rule login_f0e5f0fded8f139bd85f5d7011a7a81b {
	meta:
		aliases = "login"
		size = "104"
		objfiles = "login@libutil.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC 88 01 00 00 8B 9C 24 90 01 00 00 8D 44 24 08 52 68 80 01 00 00 53 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 C7 44 24 18 07 00 E8 ?? ?? ?? ?? 89 44 24 1C 83 C4 0C 6A 20 8D 43 08 50 8D 44 24 1C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 C4 98 01 00 00 5B C3 }
	condition:
		$pattern
}

rule sigrelse_d063cca957229e0116569f85807e14b5 {
	meta:
		aliases = "sighold, sigrelse"
		size = "77"
		objfiles = "sighold@libc.a, sigrelse@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC 8C 00 00 00 8D 5C 24 0C 53 6A 00 6A 02 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 26 52 52 FF B4 24 98 00 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 10 50 6A 00 53 6A 02 E8 ?? ?? ?? ?? 83 C4 10 EB 03 83 C8 FF 81 C4 88 00 00 00 5B C3 }
	condition:
		$pattern
}

rule ntp_gettime_c650843bc0628b461d128181a57f9699 {
	meta:
		aliases = "ntp_gettime"
		size = "67"
		objfiles = "ntp_gettime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC 94 00 00 00 8B 9C 24 9C 00 00 00 C7 44 24 14 00 00 00 00 8D 44 24 14 50 E8 ?? ?? ?? ?? 8B 54 24 40 89 53 04 8B 54 24 3C 89 13 8B 54 24 24 89 53 08 8B 54 24 28 89 53 0C 81 C4 98 00 00 00 5B C3 }
	condition:
		$pattern
}

rule logout_836115a089e14a0f2686661ee8a55462 {
	meta:
		aliases = "logout"
		size = "173"
		objfiles = "logout@libutil.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC 94 01 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 31 DB 40 0F 84 86 00 00 00 E8 ?? ?? ?? ?? 66 C7 44 24 08 07 00 53 6A 20 FF B4 24 98 01 00 00 8D 5C 24 14 8D 44 24 1C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 74 4A 51 6A 20 6A 00 8D 40 2C 50 E8 ?? ?? ?? ?? 83 C4 0C 68 00 01 00 00 6A 00 8D 43 4C 50 E8 ?? ?? ?? ?? 58 5A 6A 00 8D 83 54 01 00 00 50 E8 ?? ?? ?? ?? 66 C7 03 08 00 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 BB 01 00 00 00 85 C0 75 02 31 DB E8 ?? ?? ?? ?? 89 D8 81 C4 88 01 00 00 5B C3 }
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

rule pthread_kill_other_threads_np_cf492863a57a18561a50be49fce3363f {
	meta:
		aliases = "__pthread_kill_other_threads_np, pthread_kill_other_threads_np"
		size = "122"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC A0 00 00 00 6A 00 6A 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 8D 5C 24 18 8D 44 24 1C 50 E8 ?? ?? ?? ?? C7 84 24 A0 00 00 00 00 00 00 00 C7 44 24 1C 00 00 00 00 83 C4 0C 6A 00 53 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 6A 00 53 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 7E 0D 52 6A 00 53 50 E8 ?? ?? ?? ?? 83 C4 10 81 C4 98 00 00 00 5B C3 }
	condition:
		$pattern
}

rule gethostname_26055035bb38fb1b5ac6786bbafed770 {
	meta:
		aliases = "__GI_gethostname, gethostname"
		size = "98"
		objfiles = "gethostname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC A4 01 00 00 8D 44 24 1E 50 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 40 74 3E 83 EC 0C 8D 5C 24 5F 53 E8 ?? ?? ?? ?? 83 C4 10 40 3B 84 24 A4 01 00 00 76 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CA FF EB 14 50 50 53 FF B4 24 AC 01 00 00 E8 ?? ?? ?? ?? 31 D2 83 C4 10 89 D0 81 C4 98 01 00 00 5B C3 }
	condition:
		$pattern
}

rule __GI___libc_getdomainname_dfc5d78b3ad798eb8be58989de887c2d {
	meta:
		aliases = "__libc_getdomainname, __GI_getdomainname, getdomainname, __GI___libc_getdomainname"
		size = "101"
		objfiles = "getdomainname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC A4 01 00 00 8D 44 24 1E 50 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 40 74 41 83 EC 0C 8D 9C 24 63 01 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 40 3B 84 24 A4 01 00 00 76 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CA FF EB 14 50 50 53 FF B4 24 AC 01 00 00 E8 ?? ?? ?? ?? 31 D2 83 C4 10 89 D0 81 C4 98 01 00 00 5B C3 }
	condition:
		$pattern
}

rule __pthread_manager_sighandler_0d5b9922af5f917f7bf9309c764f1143 {
	meta:
		aliases = "__pthread_manager_sighandler"
		size = "106"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC A8 00 00 00 A1 ?? ?? ?? ?? 31 D2 85 C0 75 0C 31 D2 83 3D ?? ?? ?? ?? 00 0F 95 C2 C7 05 ?? ?? ?? ?? 01 00 00 00 85 D2 74 36 C7 44 24 14 00 00 00 00 C7 44 24 18 06 00 00 00 8D 5C 24 14 50 68 94 00 00 00 53 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 40 75 0A E8 ?? ?? ?? ?? 83 38 04 74 DE 81 C4 A8 00 00 00 5B C3 }
	condition:
		$pattern
}

rule __pthread_initialize_manager_a7ea54fb62b66204b2c77fd875ac0de6 {
	meta:
		aliases = "__pthread_initialize_manager"
		size = "517"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC A8 00 00 00 A1 ?? ?? ?? ?? C7 00 01 00 00 00 83 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8D 44 00 E0 83 EC 0C 50 E8 ?? ?? ?? ?? 89 C2 A3 ?? ?? ?? ?? 83 C4 10 83 C8 FF 85 D2 0F 84 B6 01 00 00 A1 ?? ?? ?? ?? 8D 44 42 E0 A3 ?? ?? ?? ?? 83 EC 0C 8D 84 24 AC 00 00 00 50 E8 ?? ?? ?? ?? 83 C4 10 40 75 13 83 EC 0C FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 F1 00 00 00 A1 ?? ?? ?? ?? 85 C0 74 05 A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 0F 84 88 00 00 00 A1 ?? ?? ?? ?? 8A 15 ?? ?? ?? ?? 08 C2 79 79 A1 ?? ?? ?? ?? 31 D2 E8 ?? ?? ?? ?? FF B4 24 A0 00 00 00 68 00 0F 00 00 FF 35 ?? ?? ?? ?? 68 ?? }
	condition:
		$pattern
}

rule __ieee754_hypot_81196aca3c59c38d50ed7f86c229dde4 {
	meta:
		aliases = "__ieee754_hypot"
		size = "779"
		objfiles = "e_hypot@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC A8 00 00 00 DD 84 24 B0 00 00 00 DD 54 24 08 DD 84 24 B8 00 00 00 DD 14 24 D9 C9 DD 94 24 80 00 00 00 D9 C9 8B 8C 24 84 00 00 00 81 E1 FF FF FF 7F DD 54 24 78 8B 54 24 7C 81 E2 FF FF FF 7F 39 CA 7E 16 DD 9C 24 88 00 00 00 DD 9C 24 90 00 00 00 89 D0 89 CA 89 C1 EB 19 DD D8 DD D8 DD 44 24 08 DD 9C 24 88 00 00 00 DD 04 24 DD 9C 24 90 00 00 00 DD 84 24 88 00 00 00 DD 5C 24 70 89 4C 24 74 DD 44 24 70 DD 9C 24 98 00 00 00 DD 84 24 90 00 00 00 DD 5C 24 68 89 54 24 6C DD 44 24 68 DD 94 24 A0 00 00 00 89 C8 29 D0 3D 00 00 C0 03 7E 0E DD 84 24 98 00 00 00 DE C1 E9 41 02 00 00 DD D8 31 DB 81 F9 }
	condition:
		$pattern
}

rule sigset_8a1a06ab9eed12d33e0a38c2ece26ec9 {
	meta:
		aliases = "sigset"
		size = "283"
		objfiles = "sigset@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC A8 01 00 00 8B 9C 24 B0 01 00 00 8B 94 24 B4 01 00 00 B8 20 00 00 00 83 FA 02 74 0D EB 49 C7 84 84 28 01 00 00 00 00 00 00 48 79 F2 50 50 53 8D 9C 24 34 01 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 88 C4 00 00 00 50 6A 00 53 6A 00 E8 ?? ?? ?? ?? 83 C4 10 BA 02 00 00 00 85 C0 0F 89 AC 00 00 00 E9 A4 00 00 00 83 FA FF 74 09 85 DB 7E 05 83 FB 40 7E 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 86 00 00 00 89 94 24 9C 00 00 00 B8 20 00 00 00 EB 0B C7 84 84 A0 00 00 00 00 00 00 00 48 79 F2 C7 84 24 20 01 00 00 00 00 00 00 51 8D 44 24 14 50 8D 84 24 A4 00 00 00 50 53 E8 ?? ?? ?? ?? 83 C4 10 BA 20 }
	condition:
		$pattern
}

rule gethostid_fef81d41e6f2e1bae4b0b4b2ee104c7b {
	meta:
		aliases = "gethostid"
		size = "230"
		objfiles = "hostid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC D0 01 00 00 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 78 2E 50 6A 04 8D 84 24 CC 01 00 00 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 95 00 00 00 83 EC 0C 53 E8 ?? ?? ?? ?? 8B 84 24 D4 01 00 00 EB 7A 53 53 6A 40 8D 9C 24 6F 01 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 67 80 BC 24 63 01 00 00 00 74 5D 51 51 8D 84 24 C0 01 00 00 50 8D 84 24 CC 01 00 00 50 68 4C 01 00 00 8D 44 24 2B 50 8D 84 24 BC 01 00 00 50 53 E8 ?? ?? ?? ?? 8B 84 24 E0 01 00 00 83 C4 20 85 C0 74 25 52 FF 70 0C 8B 40 10 FF 30 8D 84 24 C8 01 00 00 50 E8 ?? ?? ?? ?? 8B 84 24 CC 01 00 00 C1 C8 10 83 C4 10 EB }
	condition:
		$pattern
}

rule get_current_dir_name_9a6d4112fb480078de4a633160b4f0ea {
	meta:
		aliases = "get_current_dir_name"
		size = "146"
		objfiles = "getdirname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 81 EC D4 00 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 74 65 51 51 8D 44 24 70 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 4D 52 52 8D 44 24 10 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 39 8B 44 24 08 8B 54 24 0C 3B 54 24 6C 75 2B 3B 44 24 68 75 25 8B 44 24 60 8B 54 24 64 3B 94 24 C4 00 00 00 75 14 3B 84 24 C0 00 00 00 75 0B 83 EC 0C 53 E8 ?? ?? ?? ?? EB 0B 50 50 6A 00 6A 00 E8 ?? ?? ?? ?? 81 C4 D8 00 00 00 5B C3 }
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

rule __pthread_alt_trylock_af5025bd1f1c2fe7c44d6ff060de24bd {
	meta:
		aliases = "__pthread_alt_trylock"
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
		size = "43"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 04 89 C1 83 39 00 74 07 B8 10 00 00 00 EB 16 BB 01 00 00 00 31 D2 89 D0 F0 0F B1 19 0F 94 C2 84 D2 74 E0 31 C0 5A 5B C3 }
	condition:
		$pattern
}

rule memcmp_bytes_14ed3635c44c0407e1232abf3828ce6a {
	meta:
		aliases = "memcmp_bytes"
		size = "35"
		objfiles = "memcmp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 89 44 24 04 89 14 24 8D 5C 24 04 89 E1 0F B6 03 0F B6 11 43 41 39 D0 74 F4 29 D0 5A 59 5B C3 }
	condition:
		$pattern
}

rule wait_node_free_2bd51f104f97d5c818c1e222832641c4 {
	meta:
		aliases = "wait_node_free"
		size = "43"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 89 C3 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 89 03 89 1D ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 59 5B 5B C3 }
	condition:
		$pattern
}

rule scan_getwc_31a643437ba84bbcfccd8ab2d48ad7c0 {
	meta:
		aliases = "scan_getwc"
		size = "128"
		objfiles = "vfwscanf@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 89 C3 C7 40 24 FF FF FF FF 8B 40 10 48 89 43 10 85 C0 78 3D 80 7B 19 00 75 4F 8B 53 08 83 7A 04 FD 75 1B 8B 42 10 3B 42 0C 73 0A 8B 08 83 C0 04 89 42 10 EB 22 C6 43 19 02 83 C8 FF EB 3A 83 EC 0C 52 E8 ?? ?? ?? ?? 89 C1 83 C4 10 83 F8 FF 75 06 80 4B 19 02 EB E2 C6 43 1A 01 89 4B 04 8B 43 08 8A 40 02 88 43 18 EB 04 C6 43 19 00 FF 43 0C 8B 43 04 89 43 24 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule __syscall_error_bc57c9214be4015e5c8422b875266bee {
	meta:
		aliases = "__syscall_error"
		size = "22"
		objfiles = "__syscall_error@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 89 C3 E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule pthread_call_handlers_1e59783a0355f5289346aa4a19dc0bd7 {
	meta:
		aliases = "pthread_call_handlers"
		size = "21"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 89 C3 EB 05 FF 13 8B 5B 04 85 DB 75 F7 58 5A 5B C3 }
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

rule strsignal_99ea55dc6ea0fc240487036cdcd4b2e2 {
	meta:
		aliases = "__GI_strsignal, strsignal"
		size = "86"
		objfiles = "strsignal@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 44 24 10 83 F8 1F 77 19 89 C1 BB ?? ?? ?? ?? EB 07 80 3B 01 83 D9 00 43 85 C9 75 F5 80 3B 00 75 2A 83 EC 0C 6A 00 6A F6 99 52 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 58 F1 83 C4 1C 6A 0F 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 89 D8 5A 59 5B C3 }
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

rule xdrrec_putint32_6093432087292aea73bdbf3b13ed4657 {
	meta:
		aliases = "xdrrec_putint32"
		size = "82"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 44 24 10 8B 58 0C 8B 53 10 8D 42 04 89 43 10 89 D1 3B 43 14 76 22 89 53 10 C7 43 1C 01 00 00 00 31 D2 89 D8 E8 ?? ?? ?? ?? 31 D2 85 C0 74 18 8B 4B 10 8D 41 04 89 43 10 8B 44 24 14 8B 00 0F C8 89 01 BA 01 00 00 00 89 D0 5A 59 5B C3 }
	condition:
		$pattern
}

rule xdrrec_putlong_15cc383a6e57a413a4c80f7d2b398e38 {
	meta:
		aliases = "xdrrec_putlong"
		size = "82"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 44 24 10 8B 58 0C 8B 53 10 8D 42 04 89 43 10 89 D1 3B 43 14 76 22 89 53 10 C7 43 1C 01 00 00 00 31 D2 89 D8 E8 ?? ?? ?? ?? 31 D2 85 C0 74 18 8B 4B 10 8D 41 04 89 43 10 8B 44 24 14 8B 00 0F C8 89 01 BA 01 00 00 00 89 D0 5B 5A 5B C3 }
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

rule xdrrec_skiprecord_8e662018dc71667fd08960ecc88070a8 {
	meta:
		aliases = "__GI_xdrrec_skiprecord, xdrrec_skiprecord"
		size = "81"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 44 24 10 8B 58 0C EB 23 89 D8 E8 ?? ?? ?? ?? 85 C0 74 33 C7 43 34 00 00 00 00 83 7B 38 00 75 0B 89 D8 E8 ?? ?? ?? ?? 85 C0 74 1B 8B 53 34 85 D2 7F D6 83 7B 38 00 74 D0 C7 43 38 00 00 00 00 B8 01 00 00 00 EB 02 31 C0 59 5B 5B C3 }
	condition:
		$pattern
}

rule __GI_freeaddrinfo_24d5026326742a6e550987ffb2d0dc27 {
	meta:
		aliases = "freeaddrinfo, __GI_freeaddrinfo"
		size = "35"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 44 24 10 EB 11 8B 58 1C 83 EC 0C 50 E8 ?? ?? ?? ?? 89 D8 83 C4 10 85 C0 75 EB 58 5A 5B C3 }
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

rule tcsendbreak_f8bac4627ae5361f9e5995a34ce5f356 {
	meta:
		aliases = "tcsendbreak"
		size = "57"
		objfiles = "tcsendbrk@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 4C 24 10 8B 44 24 14 85 C0 7F 0A 53 6A 00 68 09 54 00 00 EB 14 52 83 C0 63 BA 64 00 00 00 89 D3 99 F7 FB 50 68 25 54 00 00 51 E8 ?? ?? ?? ?? 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule timer_gettime_714967802013867da1e0cf9091ee20da {
	meta:
		aliases = "timer_gettime"
		size = "53"
		objfiles = "timer_gettime@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 4C 24 14 8B 44 24 10 8B 50 04 87 D3 B8 05 01 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule mq_notify_e504be8e74f0718bb7588cd89f6f9fba {
	meta:
		aliases = "mq_notify"
		size = "76"
		objfiles = "mq_notify@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 85 C9 74 16 83 79 08 02 75 10 E8 ?? ?? ?? ?? C7 00 26 00 00 00 83 C8 FF EB 22 87 D3 B8 19 01 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule clock_settime_cf07f0926daac38bdf720d447ed46542 {
	meta:
		aliases = "clock_settime"
		size = "49"
		objfiles = "clock_settime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 08 01 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule link_6270e98b330f066d30c7d86b8c30dcbd {
	meta:
		aliases = "link"
		size = "49"
		objfiles = "link@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 09 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule clock_gettime_78bff3bb3261f50ba8870cacd8b8ae56 {
	meta:
		aliases = "clock_gettime"
		size = "49"
		objfiles = "clock_gettime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 09 01 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule clock_getres_44957698d0d52a3e9b9aea87fd10c18f {
	meta:
		aliases = "__GI_clock_getres, clock_getres"
		size = "49"
		objfiles = "clock_getres@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 0A 01 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule chmod_c459c5c2f3f03d3d015aea9b040ba6d1 {
	meta:
		aliases = "__GI_chmod, chmod"
		size = "50"
		objfiles = "chmod@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 0F 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_utimes_c2d099e98969367c5b670b93d98fb57a {
	meta:
		aliases = "utimes, __GI_utimes"
		size = "49"
		objfiles = "utimes@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 0F 01 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_utime_5ce7af96eb641c9dc21ed92e86032aac {
	meta:
		aliases = "utime, __GI_utime"
		size = "49"
		objfiles = "utime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 1E 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule access_70349c376b61c409fde270313c23f9a6 {
	meta:
		aliases = "access"
		size = "49"
		objfiles = "access@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 21 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_kill_ebe48f5615c17b4824626480fef6dd04 {
	meta:
		aliases = "kill, __GI_kill"
		size = "50"
		objfiles = "kill@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 25 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule inotify_rm_watch_dbbc42fb78dbd7660ea7bc0f1da690df {
	meta:
		aliases = "inotify_rm_watch"
		size = "49"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 25 01 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
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

rule __GI_mkdir_9c55a766d2953462f6e2f9b4a4ade2b5 {
	meta:
		aliases = "mkdir, __GI_mkdir"
		size = "50"
		objfiles = "mkdir@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 27 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule umount2_dc2dce29568c9b01d17367a7fbb5ccce {
	meta:
		aliases = "umount2"
		size = "49"
		objfiles = "umount2@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 34 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_setpgid_00835177ffacf6bfc28038b7b32a1b7d {
	meta:
		aliases = "setpgid, __GI_setpgid"
		size = "50"
		objfiles = "setpgid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 39 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule ulimit_272d0efc979e8cb5543046bbc5d65a2f {
	meta:
		aliases = "ulimit"
		size = "49"
		objfiles = "ulimit@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 3A 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_dup2_b19e58d9c4e4c77d5b1d4e70af9ff6dd {
	meta:
		aliases = "dup2, __GI_dup2"
		size = "49"
		objfiles = "dup2@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 3F 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule sethostname_b492a7b8e645c0e5d12438280a2c9822 {
	meta:
		aliases = "sethostname"
		size = "49"
		objfiles = "sethostname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 4A 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_setrlimit_e4ea3e4c70aa896b97a0d5fd9170de33 {
	meta:
		aliases = "setrlimit, __GI_setrlimit"
		size = "49"
		objfiles = "setrlimit@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 4B 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule getrusage_e284ba4748d9986e96f7077a97658488 {
	meta:
		aliases = "getrusage"
		size = "49"
		objfiles = "getrusage@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 4D 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_gettimeofday_9e477695b96e7d53b640ce7d76dc3601 {
	meta:
		aliases = "gettimeofday, __GI_gettimeofday"
		size = "49"
		objfiles = "gettimeofday@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 4E 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_settimeofday_0f6b38e57741612861777803db3e21f2 {
	meta:
		aliases = "settimeofday, __GI_settimeofday"
		size = "49"
		objfiles = "settimeofday@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 4F 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule symlink_4a2a4a400effebca631e6b5421572768 {
	meta:
		aliases = "symlink"
		size = "49"
		objfiles = "symlink@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 53 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule swapon_7600334e918300da02b3b2c83181ff6f {
	meta:
		aliases = "swapon"
		size = "49"
		objfiles = "swapon@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 57 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule munmap_28cf1e76b6f2c6b2b89fef340f3c1986 {
	meta:
		aliases = "__GI_munmap, munmap"
		size = "49"
		objfiles = "munmap@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 5B 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule truncate_0d309aac4d93a14e8a9ce28de8e9b443 {
	meta:
		aliases = "__GI_truncate, truncate"
		size = "49"
		objfiles = "truncate@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 5C 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_ftruncate_ec076f8cbd705d104113901d4087f124 {
	meta:
		aliases = "ftruncate, __GI_ftruncate"
		size = "49"
		objfiles = "ftruncate@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 5D 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule fchmod_bd737a146bda5148bc0c6d9fc75eb7b9 {
	meta:
		aliases = "fchmod"
		size = "50"
		objfiles = "fchmod@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 5E 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule getpriority_f6703dfedbefe1439d247d02e8d6fb79 {
	meta:
		aliases = "__GI_getpriority, getpriority"
		size = "65"
		objfiles = "getpriority@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 60 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 DA 85 DB 78 09 B8 14 00 00 00 29 D8 89 C2 89 D0 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_statfs_66b9353b0907b20e9d3c17ba1263b522 {
	meta:
		aliases = "__GI___libc_statfs, statfs, __libc_statfs, __GI_statfs"
		size = "49"
		objfiles = "statfs@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 63 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule __libc_fstatfs_be68736929ed9e4e1a0623b90d5be2a4 {
	meta:
		aliases = "fstatfs, __GI___libc_fstatfs, __GI_fstatfs, __libc_fstatfs"
		size = "49"
		objfiles = "fstatfs@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 64 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule __socketcall_2a952e64e3bfa0d3f4c6f5d4495a5729 {
	meta:
		aliases = "__socketcall"
		size = "49"
		objfiles = "__socketcall@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 66 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule getitimer_1a6b70036289ee57b7e60da84ec4d1d0 {
	meta:
		aliases = "getitimer"
		size = "49"
		objfiles = "getitimer@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 69 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule setdomainname_6169833290a479b1e45bb2a9b721b3db {
	meta:
		aliases = "setdomainname"
		size = "49"
		objfiles = "setdomainname@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 79 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule delete_module_2dab061c789b6205a109a361cda373b9 {
	meta:
		aliases = "delete_module"
		size = "49"
		objfiles = "delete_module@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 81 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule bdflush_35e2b04e43399fd5db9d9b25bf8b6963 {
	meta:
		aliases = "bdflush"
		size = "49"
		objfiles = "bdflush@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 86 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
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

rule mlock_fb175d0a31bd15b2c8f690474fbb1a66 {
	meta:
		aliases = "mlock"
		size = "49"
		objfiles = "mlock@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 96 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule munlock_b74ed7b8f93a4326add11cf098415720 {
	meta:
		aliases = "munlock"
		size = "49"
		objfiles = "munlock@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 97 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
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

rule __libc_nanosleep_7003dabb70336a01d375fc682b704659 {
	meta:
		aliases = "nanosleep, __GI_nanosleep, __libc_nanosleep"
		size = "49"
		objfiles = "nanosleep@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 A2 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule capget_751b7236c82ad87b05556c491959a5f1 {
	meta:
		aliases = "capget"
		size = "49"
		objfiles = "capget@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 B8 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule capset_239d45046b183d784179f11bca4ee9e5 {
	meta:
		aliases = "capset"
		size = "49"
		objfiles = "capset@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 B9 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule sigaltstack_c340242c7b73417a2e1ec3691afa3105 {
	meta:
		aliases = "sigaltstack"
		size = "49"
		objfiles = "sigaltstack@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 BA 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
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

rule setreuid_4324ce69179cad151790729b86e19d9c {
	meta:
		aliases = "__GI_setreuid, setreuid"
		size = "49"
		objfiles = "setreuid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 CB 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_setregid_a2e8ee1f16cdb5a0b36e1a9ae13b615e {
	meta:
		aliases = "setregid, __GI_setregid"
		size = "49"
		objfiles = "setregid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 CC 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_getgroups_d6182f20590ad4f40db81c792688997c {
	meta:
		aliases = "getgroups, __GI_getgroups"
		size = "49"
		objfiles = "getgroups@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 CD 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule setgroups_70582308d265b3d643d0249472ec9496 {
	meta:
		aliases = "__GI_setgroups, setgroups"
		size = "49"
		objfiles = "setgroups@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 CE 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule pivot_root_d220ef06fe529e206efc23b251bd85e7 {
	meta:
		aliases = "pivot_root"
		size = "49"
		objfiles = "pivot_root@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 D9 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule removexattr_e82738b2b8dfe1be2e29c708ac48c72e {
	meta:
		aliases = "removexattr"
		size = "49"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 EB 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 59 5B 5B C3 }
	condition:
		$pattern
}

rule lremovexattr_b862d4e0eb098817e1ba92ac7f1c6037 {
	meta:
		aliases = "lremovexattr"
		size = "49"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 EC 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5B 5A 5B C3 }
	condition:
		$pattern
}

rule fremovexattr_878d23a2abf64d09d16958cb6dff6377 {
	meta:
		aliases = "fremovexattr"
		size = "49"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8B 4C 24 14 87 D3 B8 ED 00 00 00 CD 80 87 D3 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
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

rule _dl_strdup_946681091a82d5f73efddc7de45b3eee {
	meta:
		aliases = "_dl_strdup"
		size = "55"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 8D 5A FF 89 D8 40 80 38 00 75 FA 83 EC 0C 29 D0 40 50 E8 ?? ?? ?? ?? 89 C1 8D 50 FF 83 C4 10 42 43 8A 03 88 02 84 C0 75 F6 89 C8 59 5B 5B C3 }
	condition:
		$pattern
}

rule sigpending_2b66bfeeef1592828a23c4c6b2c5e98c {
	meta:
		aliases = "sigpending"
		size = "51"
		objfiles = "sigpending@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 B9 08 00 00 00 87 D3 B8 B0 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_sigsuspend_41e0009e75838844497132e9f4ac49be {
	meta:
		aliases = "sigsuspend, __libc_sigsuspend, __GI_sigsuspend"
		size = "51"
		objfiles = "sigsuspend@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 54 24 10 B9 08 00 00 00 87 D3 B8 B3 00 00 00 CD 80 87 D3 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __cxa_atexit_5f525a696d62e9469ab62a9d76cb429e {
	meta:
		aliases = "__GI___cxa_atexit, __cxa_atexit"
		size = "57"
		objfiles = "__cxa_atexit@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 31 C0 85 DB 74 27 E8 ?? ?? ?? ?? 89 C2 83 C8 FF 85 D2 74 19 89 5A 04 8B 44 24 14 89 42 08 8B 44 24 18 89 42 0C C7 02 03 00 00 00 31 C0 5A 59 5B C3 }
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

rule re_comp_4a2fde7f0908c19cb1deb5ae4fa8967c {
	meta:
		aliases = "re_comp"
		size = "182"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 85 DB 75 17 BA ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 0F 84 92 00 00 00 E9 8B 00 00 00 83 3D ?? ?? ?? ?? 00 75 46 83 EC 0C 68 C8 00 00 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 10 BA ?? ?? ?? ?? 85 C0 74 66 C7 05 ?? ?? ?? ?? C8 00 00 00 83 EC 0C 68 00 01 00 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 10 BA ?? ?? ?? ?? 85 C0 74 3E 80 0D ?? ?? ?? ?? 80 83 EC 0C 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 89 C2 89 D8 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 0F 8B 14 85 ?? ?? ?? ?? 81 C2 ?? ?? ?? ?? EB 02 31 D2 89 D0 5B 5A 5B C3 }
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

rule pthread_mutex_unlock_2e1ec6f4f16d6c83b5d7af13efb549f7 {
	meta:
		aliases = "__pthread_mutex_unlock, pthread_mutex_unlock"
		size = "138"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 8B 43 0C 83 F8 01 74 19 7F 06 85 C0 74 33 EB 0A 83 F8 02 74 3A 83 F8 03 74 4C B8 16 00 00 00 EB 5D E8 ?? ?? ?? ?? 39 43 08 75 4E 8B 43 04 85 C0 7E 08 48 89 43 04 31 C0 EB 44 C7 43 08 00 00 00 00 83 EC 0C 8D 43 10 50 E8 ?? ?? ?? ?? EB 23 E8 ?? ?? ?? ?? 39 43 08 75 20 83 7B 10 00 74 1A C7 43 08 00 00 00 00 83 EC 0C 8D 43 10 50 E8 ?? ?? ?? ?? 31 C0 83 C4 10 EB 05 B8 01 00 00 00 5B 5A 5B C3 }
	condition:
		$pattern
}

rule __stdio_trans2r_o_92814f5172201b8a405ba6b44d6c241a {
	meta:
		aliases = "__stdio_trans2r_o"
		size = "101"
		objfiles = "_trans2r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 8B 4C 24 14 8B 03 0F B7 D0 85 CA 75 0D 81 E2 80 08 00 00 75 0C 09 C8 66 89 03 0F B7 03 A8 10 74 14 E8 ?? ?? ?? ?? C7 00 09 00 00 00 66 83 0B 08 83 C8 FF EB 24 A8 40 74 1A 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 E3 8B 43 08 89 43 1C 66 83 23 BF 66 83 0B 01 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule __stdio_trans2w_o_2750b152ab83ab36e95abd9f284dc721 {
	meta:
		aliases = "__stdio_trans2w_o"
		size = "159"
		objfiles = "_trans2w@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 8B 4C 24 14 8B 03 0F B7 D0 85 CA 75 0D 81 E2 80 08 00 00 75 0D 09 C8 66 89 03 0F B7 13 F6 C2 20 74 14 E8 ?? ?? ?? ?? C7 00 09 00 00 00 66 83 0B 08 83 CA FF EB 5B F6 C2 03 74 41 F6 C2 04 75 2C 8B 43 14 3B 43 10 75 05 F6 C2 02 74 1F 81 E2 00 04 00 00 83 FA 01 19 C0 83 C0 02 52 50 6A 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 C1 66 83 23 FC 8B 43 08 89 43 18 89 43 10 89 43 14 8B 03 83 C8 40 66 89 03 31 D2 F6 C4 0B 75 06 8B 43 0C 89 43 1C 89 D0 5A 59 5B C3 }
	condition:
		$pattern
}

rule sc_getc_87d844c026d3cddf933dcfff8ba506c3 {
	meta:
		aliases = "sc_getc"
		size = "106"
		objfiles = "vfwscanf@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 8B 53 08 83 7A 04 FD 75 1B 8B 42 10 3B 42 0C 73 0A 8B 08 83 C0 04 89 42 10 EB 1F 66 83 0A 04 83 C8 FF EB 3A 83 EC 0C 52 E8 ?? ?? ?? ?? 89 C1 83 C4 10 83 C8 FF 83 F9 FF 74 24 C6 43 1A 01 89 4B 28 8B 43 08 8A 40 02 88 43 18 3B 4B 38 75 07 B9 2E 00 00 00 EB 06 89 4B 04 89 4B 24 89 C8 5B 5A 5B C3 }
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

rule __GI_towctrans_cdc116b82bd640bd6b8e1bbe90eb5f40 {
	meta:
		aliases = "towctrans, __GI_towctrans"
		size = "65"
		objfiles = "towctrans@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 8B 54 24 14 8D 42 FF 83 F8 01 77 1C 83 FB 7F 77 22 4A 75 08 58 5A 5B E9 ?? ?? ?? ?? 89 5C 24 10 5B 58 5B E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 16 00 00 00 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __stdio_READ_9df1bb39a004f6f7a789afbc482e79b2 {
	meta:
		aliases = "__stdio_READ"
		size = "68"
		objfiles = "_READ@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 8B 54 24 18 31 C0 F6 03 04 75 2D 85 D2 79 05 BA FF FF FF 7F 50 52 FF 74 24 1C FF 73 04 E8 ?? ?? ?? ?? 83 C4 10 83 F8 00 7F 0E 75 06 66 83 0B 04 EB 06 66 83 0B 08 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_brk_c71cc48e1ebb66833d806df1647dc754 {
	meta:
		aliases = "brk, __GI_brk"
		size = "54"
		objfiles = "brk@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 BA 2D 00 00 00 89 D0 89 D9 89 DB CD 80 89 CB A3 ?? ?? ?? ?? 31 C9 39 D8 73 0E E8 ?? ?? ?? ?? C7 00 0C 00 00 00 83 C9 FF 89 C8 5A 59 5B C3 }
	condition:
		$pattern
}

rule __scan_getc_9f6c7a70dfa6483e14776802ff0f3493 {
	meta:
		aliases = "__scan_getc"
		size = "82"
		objfiles = "__scan_cookie@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 C7 03 FF FF FF FF 8B 43 10 48 89 43 10 85 C0 79 09 80 4B 19 02 83 C8 FF EB 2C 80 7B 19 00 75 1A 83 EC 0C 53 FF 53 2C 83 C4 10 83 F8 FF 75 06 80 4B 19 02 EB 11 89 43 04 EB 04 C6 43 19 00 FF 43 0C 8B 43 04 89 03 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_login_tty_2be46a244ef31d4e1491d738acc6fb2f {
	meta:
		aliases = "login_tty, __GI_login_tty"
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

rule pthread_start_thread_event_82cb7c1fd31c0f04b1788eae8418c0da {
	meta:
		aliases = "pthread_start_thread_event"
		size = "45"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 E8 ?? ?? ?? ?? 89 43 14 8B 43 1C 31 D2 E8 ?? ?? ?? ?? 83 EC 0C FF 73 1C E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_cleanup_push_defer_af6ad6e58a912e690370ffd567826780 {
	meta:
		aliases = "_pthread_cleanup_push_defer, __pthread_cleanup_push_defer"
		size = "67"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 E8 ?? ?? ?? ?? 89 C2 8B 44 24 14 89 03 8B 44 24 18 89 43 04 0F BE 42 41 89 43 08 8B 42 3C 89 43 0C 85 C0 74 0B 39 C3 72 07 C7 43 0C 00 00 00 00 C6 42 41 00 89 5A 3C 58 5A 5B C3 }
	condition:
		$pattern
}

rule _pthread_cleanup_push_9daf5da20d57b53e0c04b38d8762500c {
	meta:
		aliases = "_pthread_cleanup_push"
		size = "56"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 E8 ?? ?? ?? ?? 89 C2 8B 44 24 14 89 03 8B 44 24 18 89 43 04 8B 42 3C 89 43 0C 85 C0 74 0B 39 C3 72 07 C7 43 0C 00 00 00 00 89 5A 3C 58 5A 5B C3 }
	condition:
		$pattern
}

rule __GI_pthread_attr_init_6c766544b51e58e5583224b8283cd472 {
	meta:
		aliases = "pthread_attr_init, __GI_pthread_attr_init"
		size = "80"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 E8 ?? ?? ?? ?? C7 03 00 00 00 00 C7 43 04 00 00 00 00 C7 43 08 00 00 00 00 C7 43 0C 01 00 00 00 C7 43 10 00 00 00 00 89 43 14 C7 43 1C 00 00 00 00 C7 43 18 00 00 00 00 BA 00 00 20 00 29 C2 89 53 20 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule __exit_handler_136e0fb00eb19afb0a463f8e9963f530 {
	meta:
		aliases = "__exit_handler"
		size = "96"
		objfiles = "__exit_handler@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 10 EB 3B 48 A3 ?? ?? ?? ?? C1 E0 04 8D 04 02 8B 10 83 FA 02 74 07 83 FA 03 75 23 EB 0F 8B 50 04 85 D2 74 1A 51 51 FF 70 08 53 EB 0D 8B 50 04 85 D2 74 0B 83 EC 0C FF 70 08 FF D2 83 C4 10 A1 ?? ?? ?? ?? 85 C0 8B 15 ?? ?? ?? ?? 75 B6 89 54 24 10 58 5A 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule authnone_marshal_510f5ef3986caeb40fe7c3d38fa57675 {
	meta:
		aliases = "authnone_marshal"
		size = "51"
		objfiles = "auth_none@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 14 E8 ?? ?? ?? ?? 8B 80 98 00 00 00 31 D2 85 C0 74 14 52 8B 53 04 FF 70 3C 83 C0 28 50 53 FF 52 0C 89 C2 83 C4 10 89 D0 5A 59 5B C3 }
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

rule clnttcp_control_c13a0d5809512ea47bef87b42d821d55 {
	meta:
		aliases = "clnttcp_control"
		size = "173"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 18 8B 44 24 10 8B 48 08 8B 44 24 14 48 83 F8 0E 77 07 FF 24 85 ?? ?? ?? ?? 31 C0 E9 82 00 00 00 C7 41 04 01 00 00 00 EB 74 C7 41 04 00 00 00 00 EB 6B 8B 13 8B 43 04 89 41 0C 89 51 08 C7 41 10 01 00 00 00 EB 57 8B 51 08 8B 41 0C 89 43 04 89 13 EB 4A 8D 41 14 52 6A 10 50 53 E8 ?? ?? ?? ?? B8 01 00 00 00 83 C4 10 EB 38 8B 01 EB 24 8B 41 30 0F C8 EB 1D 8B 03 48 0F C8 89 41 30 8B 41 40 0F C8 EB 0E 8B 03 0F C8 89 41 40 EB 10 8B 41 3C 0F C8 89 03 EB 07 8B 03 0F C8 89 41 3C B8 01 00 00 00 5A 59 5B C3 }
	condition:
		$pattern
}

rule clntunix_control_bfe8e17ae017d6c181f4871f197777ae {
	meta:
		aliases = "clntunix_control"
		size = "184"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 18 8B 44 24 10 8B 48 08 8B 44 24 14 48 83 F8 0E 77 07 FF 24 85 ?? ?? ?? ?? 31 C0 E9 8D 00 00 00 C7 41 04 01 00 00 00 EB 7F C7 41 04 00 00 00 00 EB 76 8B 13 8B 43 04 89 41 0C 89 51 08 EB 69 8B 51 08 8B 41 0C 89 43 04 89 13 EB 5C 8D 41 14 52 6A 6E 50 53 E8 ?? ?? ?? ?? B8 01 00 00 00 83 C4 10 EB 4A 8B 01 EB 33 8B 81 90 00 00 00 0F C8 EB 29 8B 03 48 0F C8 89 81 90 00 00 00 8B 81 A0 00 00 00 0F C8 EB 14 8B 03 0F C8 89 81 A0 00 00 00 EB 16 8B 81 9C 00 00 00 0F C8 89 03 EB 0A 8B 03 0F C8 89 81 9C 00 00 00 B8 01 00 00 00 5A 59 5B C3 }
	condition:
		$pattern
}

rule clntudp_control_4f29ba0bc5bbe6e945f1e61ac1d297ce {
	meta:
		aliases = "clntudp_control"
		size = "209"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 8B 5C 24 18 8B 44 24 10 8B 48 08 8B 44 24 14 48 83 F8 0E 77 07 FF 24 85 ?? ?? ?? ?? 31 C0 E9 A6 00 00 00 C7 41 04 01 00 00 00 E9 95 00 00 00 C7 41 04 00 00 00 00 E9 89 00 00 00 8B 13 8B 43 04 89 41 28 89 51 24 EB 7C 8B 51 24 8B 41 28 EB 13 8B 13 8B 43 04 89 41 20 89 51 1C EB 67 8B 51 1C 8B 41 20 89 43 04 89 13 EB 5A 8D 41 08 52 6A 10 50 53 E8 ?? ?? ?? ?? B8 01 00 00 00 83 C4 10 EB 48 8B 01 EB 31 8B 41 58 8B 00 0F C8 EB 28 8B 03 48 0F C8 8B 51 58 89 02 8B 41 58 8B 40 10 0F C8 EB 14 8B 03 0F C8 8B 51 58 89 42 10 EB 16 8B 41 58 8B 40 0C 0F C8 89 03 EB 0A 8B 03 0F C8 8B 51 58 89 42 0C }
	condition:
		$pattern
}

rule token_cd60ef35d1cddfcf2fac9fac0072a7ed {
	meta:
		aliases = "token"
		size = "386"
		objfiles = "ruserpass@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 A1 ?? ?? ?? ?? 0F B7 00 A8 0C 0F 85 68 01 00 00 8B 0D ?? ?? ?? ?? 8B 41 10 3B 41 18 73 09 0F B6 10 40 89 41 10 EB 17 83 EC 0C 51 E8 ?? ?? ?? ?? 89 C2 83 C4 10 83 F8 FF 0F 84 3A 01 00 00 8D 42 F7 83 F8 01 76 CA 83 FA 20 74 C5 83 FA 2C 74 C0 BB ?? ?? ?? ?? 83 FA 22 74 2F EB 5E 83 FA 5C 75 25 8B 0D ?? ?? ?? ?? 8B 41 10 3B 41 18 73 09 0F B6 10 40 89 41 10 EB 0E 83 EC 0C 51 E8 ?? ?? ?? ?? 89 C2 83 C4 10 88 13 43 8B 0D ?? ?? ?? ?? 8B 41 10 3B 41 18 73 09 0F B6 10 40 89 41 10 EB 13 83 EC 0C 51 E8 ?? ?? ?? ?? 89 C2 83 C4 10 83 F8 FF 74 7F 83 FA 22 75 A4 EB 78 88 15 ?? ?? ?? ?? BB ?? ?? ?? }
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

rule fork_2527c0759d3c9058972affd170efda8f {
	meta:
		aliases = "__GI_fork, __libc_fork, fork"
		size = "37"
		objfiles = "fork@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 02 00 00 00 CD 80 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_getpid_3a4771e029f93732bee14358f6609a4d {
	meta:
		aliases = "__libc_getpid, getpid, __GI_getpid"
		size = "37"
		objfiles = "getpid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 14 00 00 00 CD 80 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule pause_ccfd0bcf0b3bd53c36c223076c06fc38 {
	meta:
		aliases = "__libc_pause, pause"
		size = "37"
		objfiles = "pause@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 1D 00 00 00 CD 80 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule inotify_init_25b258db0cd204aed1640957d39631cc {
	meta:
		aliases = "inotify_init"
		size = "37"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 23 01 00 00 CD 80 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 59 5B 5B C3 }
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

rule getppid_393c28a2bd38c7ec69a0945d96577525 {
	meta:
		aliases = "getppid"
		size = "37"
		objfiles = "getppid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 40 00 00 00 CD 80 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule getpgrp_25e27bd152398c5ca374b2d7b02e6c05 {
	meta:
		aliases = "getpgrp"
		size = "37"
		objfiles = "getpgrp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 41 00 00 00 CD 80 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_setsid_732fdc1410fa0642b5086d296fc578c7 {
	meta:
		aliases = "setsid, __GI_setsid"
		size = "37"
		objfiles = "setsid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 42 00 00 00 CD 80 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule vhangup_02218afd1b9eca94987fcca34651090d {
	meta:
		aliases = "vhangup"
		size = "37"
		objfiles = "vhangup@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 6F 00 00 00 CD 80 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule munlockall_378490174edb112a92238864a269bc63 {
	meta:
		aliases = "munlockall"
		size = "37"
		objfiles = "munlockall@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 99 00 00 00 CD 80 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule sched_yield_d3a2005370c32663ce649385a4d0be03 {
	meta:
		aliases = "sched_yield"
		size = "37"
		objfiles = "sched_yield@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 9E 00 00 00 CD 80 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule __rpc_thread_variables_0be1c61e6064ddc892a96d75b3a30a6b {
	meta:
		aliases = "__rpc_thread_variables"
		size = "225"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 ?? ?? ?? ?? 85 C0 74 0F 83 EC 0C 6A 02 E8 ?? ?? ?? ?? 83 C4 10 EB 05 A1 ?? ?? ?? ?? 89 C3 85 C0 0F 85 B0 00 00 00 B8 ?? ?? ?? ?? 85 C0 74 16 50 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 EB 18 83 3D ?? ?? ?? ?? 00 75 0F E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 01 00 00 00 B8 ?? ?? ?? ?? 85 C0 74 0F 83 EC 0C 6A 02 E8 ?? ?? ?? ?? 83 C4 10 EB 05 A1 ?? ?? ?? ?? 89 C3 85 C0 75 56 50 50 68 C8 00 00 00 6A 01 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 22 89 C3 B8 ?? ?? ?? ?? 85 C0 74 0F 50 50 53 6A 02 E8 ?? ?? ?? ?? 83 C4 10 EB 27 89 1D ?? ?? ?? ?? EB 1F B8 ?? ?? ?? ?? 85 C0 74 0F 83 EC 0C }
	condition:
		$pattern
}

rule __rpc_thread_destroy_564ac138950cb0c3a361c0617c79b2d5 {
	meta:
		aliases = "__rpc_thread_destroy"
		size = "190"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 ?? ?? ?? ?? 85 C0 74 11 83 EC 0C 6A 02 E8 ?? ?? ?? ?? 89 C3 83 C4 10 EB 06 8B 1D ?? ?? ?? ?? 85 DB 0F 84 8E 00 00 00 81 FB ?? ?? ?? ?? 0F 84 82 00 00 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EC 0C FF B3 98 00 00 00 E8 ?? ?? ?? ?? 58 FF B3 9C 00 00 00 E8 ?? ?? ?? ?? 58 FF B3 A0 00 00 00 E8 ?? ?? ?? ?? 58 FF B3 BC 00 00 00 E8 ?? ?? ?? ?? 58 FF B3 AC 00 00 00 E8 ?? ?? ?? ?? 58 FF B3 B0 00 00 00 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 B8 ?? ?? ?? ?? 85 C0 74 10 51 51 6A 00 6A 02 E8 ?? ?? ?? ?? 83 C4 10 EB 0A C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 58 5A 5B C3 }
	condition:
		$pattern
}

rule getuid_0bf9570f91109d30c536183cf147fc21 {
	meta:
		aliases = "__GI_getuid, getuid"
		size = "37"
		objfiles = "getuid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 C7 00 00 00 CD 80 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_getgid_e2906f0f52ab265ac458686f85aa82cf {
	meta:
		aliases = "getgid, __GI_getgid"
		size = "37"
		objfiles = "getgid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 C8 00 00 00 CD 80 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule __GI_geteuid_bff1617a41ce70b7ea2ce6dbd6ecc3cf {
	meta:
		aliases = "geteuid, __GI_geteuid"
		size = "37"
		objfiles = "geteuid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 C9 00 00 00 CD 80 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule getegid_7b213b856c26c608706a82279dade323 {
	meta:
		aliases = "__GI_getegid, getegid"
		size = "37"
		objfiles = "getegid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 B8 CA 00 00 00 CD 80 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule __uClibc_fini_07a89d8ce45a0cae4ce9d83526fa8ce9 {
	meta:
		aliases = "__GI___uClibc_fini, __uClibc_fini"
		size = "63"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 BB ?? ?? ?? ?? 81 EB ?? ?? ?? ?? C1 FB 02 EB 07 FF 14 9D ?? ?? ?? ?? 4B 83 FB FF 75 F3 A1 ?? ?? ?? ?? 85 C0 74 02 FF D0 8B 0D ?? ?? ?? ?? 85 C9 74 05 5B 58 5B FF E1 58 5A 5B C3 }
	condition:
		$pattern
}

rule __fpclassify_e4a69a8c76f26553ec406da8d3337a33 {
	meta:
		aliases = "__GI___fpclassify, __fpclassify"
		size = "70"
		objfiles = "s_fpclassify@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 DD 44 24 10 DD 1C 24 8B 44 24 04 89 C2 81 E2 FF FF 0F 00 0B 14 24 25 00 00 F0 7F B9 02 00 00 00 89 D3 09 C3 74 16 B1 03 85 C0 74 10 B1 04 3D 00 00 F0 7F 75 07 31 C9 85 D2 0F 94 C1 89 C8 5A 59 5B C3 }
	condition:
		$pattern
}

rule atexit_31dc2a2a7a0afab7d2d63911ae3b2abc {
	meta:
		aliases = "atexit"
		size = "48"
		objfiles = "atexits@uclibc_nonshared.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 83 ?? ?? ?? ?? 31 D2 85 C0 74 02 8B 10 50 52 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule __GI_raise_39acc1f7927a4588da0ebe747ae56cef {
	meta:
		aliases = "raise, __GI_raise"
		size = "46"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 53 53 FF 74 24 18 50 E8 ?? ?? ?? ?? 89 C3 83 C4 10 31 C0 85 DB 74 0A E8 ?? ?? ?? ?? 89 18 83 C8 FF 5A 59 5B C3 }
	condition:
		$pattern
}

rule __pthread_reset_main_thread_2dfae9ed5238457bd66d7c9447a8d3f6 {
	meta:
		aliases = "__pthread_reset_main_thread"
		size = "138"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 89 C3 83 3D ?? ?? ?? ?? FF 74 51 83 EC 0C FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 58 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? FF FF FF FF C7 05 ?? ?? ?? ?? FF FF FF FF 83 C4 10 E8 ?? ?? ?? ?? 89 43 14 89 1D ?? ?? ?? ?? 89 1B 89 5B 04 C7 43 44 ?? ?? ?? ?? C7 43 4C ?? ?? ?? ?? 58 5A 5B C3 }
	condition:
		$pattern
}

rule _buf_fb2d16062e1cc8af340ef0605567a924 {
	meta:
		aliases = "_buf"
		size = "52"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 89 C3 83 B8 9C 00 00 00 00 75 16 83 EC 0C 68 00 01 00 00 E8 ?? ?? ?? ?? 89 83 9C 00 00 00 83 C4 10 8B 83 9C 00 00 00 59 5B 5B C3 }
	condition:
		$pattern
}

rule svc_exit_571360ef65882139a54771de1c4b630b {
	meta:
		aliases = "svc_exit"
		size = "43"
		objfiles = "svc_run@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 89 C3 83 EC 0C FF 30 E8 ?? ?? ?? ?? C7 03 00 00 00 00 E8 ?? ?? ?? ?? C7 00 00 00 00 00 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule getrpcent_b961f6821bfd2f3852478c381f67f205 {
	meta:
		aliases = "__GI_getrpcent, getrpcent"
		size = "62"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 89 C3 85 C0 74 29 83 38 00 75 1A 51 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 03 83 C4 10 85 C0 74 0A 89 D8 5B 5A 5B E9 ?? ?? ?? ?? 31 C0 5A 59 5B C3 }
	condition:
		$pattern
}

rule endrpcent_64d52b1b43cf32c3631ef021483c0b69 {
	meta:
		aliases = "__GI_endrpcent, endrpcent"
		size = "70"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 89 C3 85 C0 74 33 83 78 0C 00 75 2D 83 EC 0C FF 70 04 E8 ?? ?? ?? ?? C7 43 04 00 00 00 00 8B 03 83 C4 10 85 C0 74 12 83 EC 0C 50 E8 ?? ?? ?? ?? C7 03 00 00 00 00 83 C4 10 58 5A 5B C3 }
	condition:
		$pattern
}

rule setrpcent_441006847e7e51489a29b7dbb5423ebd {
	meta:
		aliases = "__GI_setrpcent, setrpcent"
		size = "81"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 89 C3 85 C0 74 3E 8B 00 85 C0 75 15 50 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 03 EB 09 83 EC 0C 50 E8 ?? ?? ?? ?? 59 FF 73 04 E8 ?? ?? ?? ?? C7 43 04 00 00 00 00 8B 44 24 20 09 43 0C 83 C4 10 58 5A 5B C3 }
	condition:
		$pattern
}

rule svcraw_recv_5eb96dd98ece8aa27589dfa24992857c {
	meta:
		aliases = "svcraw_recv"
		size = "78"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 8B 90 BC 00 00 00 31 C0 85 D2 74 35 8D 9A 94 23 00 00 C7 82 94 23 00 00 01 00 00 00 50 50 8B 82 98 23 00 00 6A 00 53 FF 50 14 59 58 FF 74 24 1C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 95 C0 0F B6 C0 5B 5A 5B C3 }
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

rule svcraw_create_c25e17eaefb4daf3b9291b10c8122ca8 {
	meta:
		aliases = "svcraw_create"
		size = "120"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 08 E8 ?? ?? ?? ?? 8B 98 BC 00 00 00 85 DB 75 19 53 53 68 3C 25 00 00 6A 01 E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 74 48 89 C3 C7 83 60 22 00 00 00 00 00 00 66 C7 83 64 22 00 00 00 00 C7 83 68 22 00 00 ?? ?? ?? ?? 8D 83 AC 23 00 00 89 83 84 22 00 00 6A 02 68 60 22 00 00 53 8D 83 94 23 00 00 50 E8 ?? ?? ?? ?? 8D 93 60 22 00 00 83 C4 10 89 D0 5A 59 5B C3 }
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

rule __glibc_strerror_r_2be96166dfc3e38afa56f176ba22bc43 {
	meta:
		aliases = "__GI___glibc_strerror_r, __glibc_strerror_r"
		size = "29"
		objfiles = "__glibc_strerror_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 0C 8B 5C 24 18 FF 74 24 1C 53 FF 74 24 1C E8 ?? ?? ?? ?? 89 D8 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule __ether_line_6702712b2d575df2b1efce2426888390 {
	meta:
		aliases = "__ether_line"
		size = "64"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 89 C3 52 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 03 EB 22 43 8A 03 84 C0 74 0B 3C 20 74 07 3C 09 75 F1 EB 01 43 8A 03 84 C0 74 0A 3C 20 74 F5 3C 09 75 04 EB EF 31 DB 89 D8 5A 59 5B C3 }
	condition:
		$pattern
}

rule clnt_perror_3939fb0d85d1d07b440da8e59a520875 {
	meta:
		aliases = "__GI_clnt_perror, clnt_perror"
		size = "40"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 8B 1D ?? ?? ?? ?? FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 89 5C 24 24 89 44 24 20 83 C4 18 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mkdtemp_5124d170ac467ee6d2d623bba7aa2a71 {
	meta:
		aliases = "mkdtemp"
		size = "35"
		objfiles = "mkdtemp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 8B 5C 24 18 6A 02 53 E8 ?? ?? ?? ?? 85 C0 0F 94 C0 0F B6 C0 F7 D8 21 C3 89 D8 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule fdopen_3fb29071dac2255241f3e3fdc8c03262 {
	meta:
		aliases = "__GI_fdopen, fdopen"
		size = "50"
		objfiles = "fdopen@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 8B 5C 24 18 6A 03 53 E8 ?? ?? ?? ?? 83 C4 10 31 D2 83 F8 FF 74 12 53 6A 00 FF 74 24 1C 50 E8 ?? ?? ?? ?? 89 C2 83 C4 10 89 D0 5A 59 5B C3 }
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

rule jrand48_r_11f3874b93b1169cbbf15b23c8825b7a {
	meta:
		aliases = "__GI_jrand48_r, jrand48_r"
		size = "55"
		objfiles = "jrand48_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 8B 5C 24 18 FF 74 24 1C 53 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 15 0F B7 43 04 C1 E0 10 0F B7 53 02 09 D0 8B 54 24 18 89 02 31 D2 89 D0 5A 59 5B C3 }
	condition:
		$pattern
}

rule nrand48_r_6465f36196702099ad69c85456c93e51 {
	meta:
		aliases = "__GI_nrand48_r, nrand48_r"
		size = "61"
		objfiles = "nrand48_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 10 8B 5C 24 18 FF 74 24 1C 53 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 1B 66 8B 43 02 66 D1 E8 0F B7 C0 0F B7 53 04 C1 E2 0F 09 D0 8B 54 24 18 89 02 31 D2 89 D0 5A 59 5B C3 }
	condition:
		$pattern
}

rule pthread_key_create_714ab9318b36b997bafb352c5302b632 {
	meta:
		aliases = "pthread_key_create"
		size = "108"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 14 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 DB 83 C4 10 EB 38 83 3C DD ?? ?? ?? ?? 00 75 2D C7 04 DD ?? ?? ?? ?? 01 00 00 00 8B 44 24 14 89 04 DD ?? ?? ?? ?? 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 20 89 18 31 C0 EB 1B 43 81 FB FF 03 00 00 7E C0 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 0B 00 00 00 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule pthread_atfork_44062a5c1cbe97e38afb4df9fe0d0a5d {
	meta:
		aliases = "pthread_atfork"
		size = "113"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 14 6A 18 E8 ?? ?? ?? ?? 89 C3 83 C4 10 B8 0C 00 00 00 85 DB 74 54 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 00 89 D9 8B 54 24 24 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4B 08 6A 01 8B 54 24 2C B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 4B 10 6A 01 8B 54 24 34 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 83 C4 20 59 5B 5B C3 }
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

rule re_exec_f8f175ce6955d37c57131d37ed5aa256 {
	meta:
		aliases = "re_exec"
		size = "43"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 14 8B 5C 24 1C 53 E8 ?? ?? ?? ?? 5A 59 6A 00 50 6A 00 50 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? F7 D0 C1 E8 1F 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule malloc_trim_eb36e5578d0a64e4a0f0e17f75ea34b0 {
	meta:
		aliases = "malloc_trim"
		size = "34"
		objfiles = "free@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 14 8B 5C 24 1C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 89 D8 83 C4 18 5B E9 ?? ?? ?? ?? }
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

rule getttyent_d7af2e7a6bdbc0caec80d0f600b1ed58 {
	meta:
		aliases = "__GI_getttyent, getttyent"
		size = "667"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 83 3D ?? ?? ?? ?? 00 75 0F E8 ?? ?? ?? ?? 31 DB 85 C0 0F 84 78 02 00 00 83 3D ?? ?? ?? ?? 00 75 1E 83 EC 0C 68 00 10 00 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 10 85 C0 75 05 E8 ?? ?? ?? ?? 50 A1 ?? ?? ?? ?? 83 C0 38 50 68 ?? ?? ?? ?? 8D 44 24 14 50 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C0 38 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 8B 1D ?? ?? ?? ?? 50 FF 35 ?? ?? ?? ?? 68 00 10 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 07 31 DB E9 EE 01 00 00 51 51 6A 0A 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 30 8B 15 ?? ?? ?? ?? 8B 42 10 3B 42 18 73 09 0F B6 08 40 89 42 10 EB 0E 83 EC 0C 52 E8 ?? ?? ?? ?? 89 C1 }
	condition:
		$pattern
}

rule set_input_fragment_0a59e2efb47102f55c797426d5c2348e {
	meta:
		aliases = "set_input_fragment"
		size = "69"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 89 C3 8D 54 24 14 B9 04 00 00 00 E8 ?? ?? ?? ?? 85 C0 74 26 8B 54 24 14 0F CA 89 54 24 14 89 D0 C1 E8 1F 89 43 38 85 D2 74 10 81 E2 FF FF FF 7F 89 53 34 B8 01 00 00 00 EB 02 31 C0 83 C4 18 5B C3 }
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

rule xdr_u_short_8bdef77fd140b4597e3c4dd58e827100 {
	meta:
		aliases = "__GI_xdr_u_short, xdr_u_short"
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

rule __GI_xdr_short_0ea138b62048424af272c7635a883ec1 {
	meta:
		aliases = "xdr_short, __GI_xdr_short"
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

rule getc_unlocked_92bdc4c8003915a3ddbe7d653a878939 {
	meta:
		aliases = "fgetc_unlocked, __GI_getc_unlocked, __GI_fgetc_unlocked, __fgetc_unlocked, __GI___fgetc_unlocked, getc_unlocked"
		size = "220"
		objfiles = "fgetc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 8B 5C 24 20 8B 43 10 3B 43 18 0F 82 99 00 00 00 0F B7 03 25 83 00 00 00 3D 80 00 00 00 77 18 52 52 68 80 00 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 97 00 00 00 8B 0B 0F B7 D1 F6 C2 02 74 19 83 E2 01 8A 54 93 24 8D 41 FF 66 89 03 C7 43 28 00 00 00 00 0F B6 D2 EB 77 8B 43 10 39 43 14 75 47 83 7B 04 FE 75 08 83 C9 04 66 89 0B EB 5E 80 E6 03 74 10 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 8B 43 08 39 43 0C 74 25 89 43 18 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 2E 8B 43 14 89 43 18 8B 43 10 0F B6 10 40 89 43 10 EB 1F 50 6A 01 8D 44 24 1F 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 }
	condition:
		$pattern
}

rule __GI_mbrtowc_9e0b17fe867a4931f2fd44d640660795 {
	meta:
		aliases = "mbrtowc, __GI_mbrtowc"
		size = "111"
		objfiles = "mbrtowc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 8B 5C 24 20 8B 44 24 24 8B 54 24 2C 85 D2 75 05 BA ?? ?? ?? ?? 85 C0 75 0D C6 44 24 17 00 31 DB 8D 44 24 17 EB 0C 80 38 00 74 37 83 7C 24 28 00 74 30 89 44 24 0C 83 EC 0C 52 6A 01 6A FF 8D 44 24 24 50 8D 44 24 2C 50 E8 ?? ?? ?? ?? 89 C2 83 C4 20 85 C0 78 0E 85 DB 74 0A 8B 44 24 10 89 03 EB 02 31 D2 89 D0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule shmat_ef24c0af2faf768ad9c62c4c2ad6fde4 {
	meta:
		aliases = "shmat"
		size = "61"
		objfiles = "shmat@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 8D 44 24 14 52 52 6A 00 FF 74 24 30 50 FF 74 24 3C FF 74 24 38 6A 15 E8 ?? ?? ?? ?? 89 C3 83 C4 20 E8 ?? ?? ?? ?? F7 D8 89 DA 39 C3 77 04 8B 54 24 14 89 D0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule ilogb_f761977931dddcba673a5b3b42b293c1 {
	meta:
		aliases = "__GI_ilogb, ilogb"
		size = "120"
		objfiles = "s_ilogb@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 DD 44 24 20 DD 14 24 DD 54 24 10 8B 54 24 14 81 E2 FF FF FF 7F 81 FA FF FF 0F 00 7F 3A DD 5C 24 08 8B 4C 24 08 B8 01 00 00 80 89 D3 09 CB 74 3F B8 ED FB FF FF 85 D2 74 05 EB 09 48 01 C9 85 C9 7F F9 EB 2B C1 E2 0B B8 02 FC FF FF EB 03 48 01 D2 85 D2 7F F9 EB 18 DD D8 B8 FF FF FF 7F 81 FA FF FF EF 7F 7F 09 C1 FA 14 8D 82 01 FC FF FF 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule __ieee754_cosh_bfe2867def31540173df94cd134da492 {
	meta:
		aliases = "__ieee754_cosh"
		size = "293"
		objfiles = "e_cosh@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 DD 44 24 20 DD 14 24 DD 54 24 10 8B 5C 24 14 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 0F 8F F3 00 00 00 DD D8 81 FB 42 2E D6 3F 7F 3D 50 50 FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? DD 1C 24 E8 ?? ?? ?? ?? D9 E8 D9 C1 D8 C1 83 C4 10 81 FB FF FF 7F 3C 0F 8E C1 00 00 00 D9 CA D8 C8 D9 CA D8 C0 DE FA DE C1 E9 B4 00 00 00 81 FB FF FF 35 40 7F 29 51 51 FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? DD 1C 24 E8 ?? ?? ?? ?? D9 05 ?? ?? ?? ?? D9 C1 D8 C9 D9 C9 DE F2 DE C1 EB 70 81 FB 41 2E 86 40 7F 1F 52 52 FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? DD 1C 24 E8 ?? ?? ?? ?? D8 0D ?? ?? ?? ?? EB 49 DD 04 24 DD }
	condition:
		$pattern
}

rule __ieee754_atanh_0112c6c2100394c6027a88091e97b462 {
	meta:
		aliases = "__ieee754_atanh"
		size = "206"
		objfiles = "e_atanh@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 DD 44 24 20 DD 14 24 DD 54 24 10 8B 5C 24 14 89 DA 81 E2 FF FF FF 7F 8B 44 24 10 F7 D8 0B 44 24 10 C1 E8 1F 09 D0 3D 00 00 F0 3F 76 09 D8 E0 D8 F0 E9 85 00 00 00 DD D8 81 FA 00 00 F0 3F 75 0B DD 04 24 DC 35 ?? ?? ?? ?? EB 70 81 FA FF FF 2F 3E 7F 14 DD 04 24 DC 05 ?? ?? ?? ?? D9 EE D9 C9 DA E9 DF E0 9E 77 5B DD 04 24 DD 5C 24 08 89 54 24 0C DD 44 24 08 81 FA FF FF DF 3F D9 C0 D8 C1 7F 14 52 52 D9 C0 D8 CA D9 CA DC 2D ?? ?? ?? ?? DE FA DE C1 EB 08 50 50 D9 E8 DE E2 DE F1 83 EC 08 DD 1C 24 E8 ?? ?? ?? ?? D8 0D ?? ?? ?? ?? 83 C4 10 DD 14 24 85 DB 79 07 D9 E0 DD 1C 24 EB 02 DD D8 DD 04 }
	condition:
		$pattern
}

rule __GI_tanh_73a1c2a4f43e53719c6a06d370eb2900 {
	meta:
		aliases = "tanh, __GI_tanh"
		size = "211"
		objfiles = "s_tanh@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 18 DD 44 24 20 DD 54 24 08 DD 5C 24 10 8B 5C 24 14 89 D8 25 FF FF FF 7F 3D FF FF EF 7F 7E 22 85 DB 78 0F D9 E8 DD 44 24 08 D8 F9 DE C1 E9 99 00 00 00 D9 E8 DD 44 24 08 D8 F9 DE E1 E9 8A 00 00 00 3D FF FF 35 40 7E 04 D9 E8 EB 79 3D FF FF 7F 3C 7F 10 DD 44 24 08 DC 05 ?? ?? ?? ?? DC 4C 24 08 EB 68 3D FF FF EF 3F 7E 2D 52 52 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? D8 C0 DD 1C 24 E8 ?? ?? ?? ?? D8 05 ?? ?? ?? ?? D8 3D ?? ?? ?? ?? DC 05 ?? ?? ?? ?? EB 2B 50 50 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? D8 0D ?? ?? ?? ?? DD 1C 24 E8 ?? ?? ?? ?? D9 C0 D9 E0 D9 C9 D8 05 ?? ?? ?? ?? DE F9 83 C4 10 }
	condition:
		$pattern
}

rule getmntent_2ed392b46c46e23c7e90dea6d05dfe4a {
	meta:
		aliases = "getmntent"
		size = "126"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 14 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 3D ?? ?? ?? ?? 00 75 1E 83 EC 0C 68 00 10 00 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 10 85 C0 75 05 E8 ?? ?? ?? ?? 68 00 10 00 00 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 2C E8 ?? ?? ?? ?? 89 C3 58 5A 6A 01 8D 44 24 14 50 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule __new_exitfn_793ce54cef4a7e22946b8c4dc8f70bd5 {
	meta:
		aliases = "__new_exitfn"
		size = "171"
		objfiles = "__exit_handler@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 14 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? A1 ?? ?? ?? ?? 40 83 C4 10 39 C2 7D 39 50 50 C1 E2 04 8D 82 40 01 00 00 50 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 75 0D E8 ?? ?? ?? ?? C7 00 0C 00 00 00 EB 32 A3 ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 14 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? A1 ?? ?? ?? ?? 89 C3 C1 E3 04 03 1D ?? ?? ?? ?? 40 A3 ?? ?? ?? ?? C7 03 01 00 00 00 50 50 6A 01 8D 44 24 14 50 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule srandom_5075175c64c996ac23d58ea27d247c13 {
	meta:
		aliases = "srand, srandom"
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

rule setspent_c8677bf57d351f58f68849252919efb4 {
	meta:
		aliases = "setgrent, setpwent, setspent"
		size = "75"
		objfiles = "getspent_r@libc.a, getpwent_r@libc.a, getgrent_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 14 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 0C 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 50 50 6A 01 53 E8 ?? ?? ?? ?? 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule endgrent_388f7d68c5e644cf15134cf29cd318ff {
	meta:
		aliases = "endpwent, endspent, endgrent"
		size = "85"
		objfiles = "getspent_r@libc.a, getpwent_r@libc.a, getgrent_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 14 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 16 83 EC 0C 50 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 10 51 51 6A 01 53 E8 ?? ?? ?? ?? 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule __GI_endprotoent_0d96bf4fc2561ebab2649fbb03aaf667 {
	meta:
		aliases = "__GI_endnetent, endnetent, endprotoent, __GI_endprotoent"
		size = "92"
		objfiles = "getproto@libc.a, getnetent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 14 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 16 83 EC 0C 50 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 10 C6 05 ?? ?? ?? ?? 00 50 50 6A 01 53 E8 ?? ?? ?? ?? 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule endservent_4534faf6da303f19be4e28c6b005a74d {
	meta:
		aliases = "__GI_endservent, endservent"
		size = "92"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 14 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 16 83 EC 0C 50 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 10 C6 05 ?? ?? ?? ?? 00 52 52 6A 01 53 E8 ?? ?? ?? ?? 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule endhostent_45cf5e0498c78dda5a6113e73cacd78d {
	meta:
		aliases = "endhostent"
		size = "92"
		objfiles = "gethostent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 14 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 00 A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 16 83 EC 0C 50 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 10 50 50 6A 01 53 E8 ?? ?? ?? ?? 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule __GI_closelog_6f8b191d7ca074aa37f3d8ba9e720d20 {
	meta:
		aliases = "closelog, __GI_closelog"
		size = "63"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 14 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 00 00 00 00 E8 ?? ?? ?? ?? 58 5A 6A 01 53 E8 ?? ?? ?? ?? 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule setutent_cd7c84a10d02e5b3ac34f2547c251a00 {
	meta:
		aliases = "__GI_setutent, setutent"
		size = "56"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 14 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 5A 6A 01 53 E8 ?? ?? ?? ?? 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule pututline_6a4a6d42322b1906fa0957970d28e7dc {
	meta:
		aliases = "pututline"
		size = "157"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 8B 5C 24 24 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 14 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 6A 01 68 80 FE FF FF FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 D8 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 0A 50 6A 01 68 80 FE FF FF EB 05 50 6A 02 6A 00 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 68 80 01 00 00 53 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A 59 3D 80 01 00 00 0F 94 C0 0F B6 C0 F7 D8 21 C3 6A 01 8D 44 24 14 50 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule utmpname_5320ed26cf50f540a4b2aa2f5480e4e0 {
	meta:
		aliases = "utmpname"
		size = "155"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 8B 5C 24 24 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 14 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 DB 74 37 A1 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 0C 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C 53 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 10 85 C0 75 0A C7 05 ?? ?? ?? ?? ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 F8 FF 74 0C 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 C7 05 ?? ?? ?? ?? FF FF FF FF 50 50 6A 01 8D 44 24 14 50 E8 ?? ?? ?? ?? 31 C0 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule mallopt_0f473c22e0221f42afee35ebd7d5640f {
	meta:
		aliases = "mallopt"
		size = "181"
		objfiles = "mallopt@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 8B 5C 24 28 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 14 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 8B 44 24 20 83 C0 04 83 F8 05 77 5B FF 24 85 ?? ?? ?? ?? 83 FB 50 77 4F BA 08 00 00 00 85 DB 74 0F 8D 43 0B B2 10 83 F8 0F 76 05 89 C2 83 E2 F8 A1 ?? ?? ?? ?? 83 E0 03 09 C2 89 15 ?? ?? ?? ?? EB 16 89 1D ?? ?? ?? ?? EB 0E 89 1D ?? ?? ?? ?? EB 06 89 1D ?? ?? ?? ?? BB 01 00 00 00 EB 0A 89 1D ?? ?? ?? ?? EB F1 31 DB 50 50 6A 01 8D 44 24 14 50 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule __GI_gethostent_r_01ed60433443aaaff4d30cd1bd153afb {
	meta:
		aliases = "gethostent_r, __GI_gethostent_r"
		size = "178"
		objfiles = "gethostent@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 1C 8B 5C 24 30 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 14 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 3D ?? ?? ?? ?? 00 75 1B E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 85 C0 75 0D C7 03 00 00 00 00 BB 02 00 00 00 EB 4E 83 EC 0C FF 74 24 3C 53 FF 74 24 3C FF 74 24 3C FF 74 24 3C 6A 01 6A 02 6A 00 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 83 C4 30 80 3D ?? ?? ?? ?? 00 75 1B 83 EC 0C FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 10 51 51 6A 01 8D 44 24 14 50 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule ftime_3f73c1f6a390bf2c9daeea0a73bf5227 {
	meta:
		aliases = "ftime"
		size = "87"
		objfiles = "ftime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8B 5C 24 28 8D 44 24 10 50 8D 44 24 1C 50 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 2F 8B 44 24 10 89 03 8B 44 24 14 05 E7 03 00 00 BA E8 03 00 00 89 D1 99 F7 F9 66 89 43 04 8B 44 24 08 66 89 43 06 8B 44 24 0C 66 89 43 08 31 D2 89 D0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule __GI_fesetenv_aec45f854fd7b981f53521f862fcd8aa {
	meta:
		aliases = "fesetenv, __GI_fesetenv"
		size = "230"
		objfiles = "fesetenv@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8B 5C 24 28 D9 74 24 04 83 FB FF 75 2D 8B 44 24 04 83 C8 3D 80 E4 F3 66 89 44 24 04 66 83 64 24 08 C2 C7 44 24 10 00 00 00 00 66 C7 44 24 14 00 00 66 81 64 24 16 00 F8 EB 30 83 FB FE 66 8B 4C 24 16 75 37 66 81 64 24 04 C2 F3 66 83 64 24 08 C2 C7 44 24 10 00 00 00 00 66 C7 44 24 14 00 00 66 81 E1 00 F8 66 89 4C 24 16 C7 44 24 18 00 00 00 00 66 C7 44 24 1C 00 00 EB 5C 8B 03 66 25 3D 0C 8B 54 24 04 66 81 E2 C2 F3 09 D0 66 89 44 24 04 8B 43 04 83 E0 3D 8B 54 24 08 83 E2 C2 09 D0 66 89 44 24 08 8B 43 0C 89 44 24 10 8B 43 10 66 89 44 24 14 66 8B 43 12 66 25 FF 07 66 81 E1 00 F8 09 C1 66 }
	condition:
		$pattern
}

rule xdr_u_char_70508bd3d2f6862273b825ad6a9babcf {
	meta:
		aliases = "xdr_u_char"
		size = "53"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8B 5C 24 2C 0F B6 03 89 44 24 1C 8D 44 24 1C 50 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 74 08 8B 44 24 14 88 03 B2 01 89 D0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule xdr_char_5cf7111a62ea4f1f02518f3877c825b0 {
	meta:
		aliases = "xdr_char"
		size = "53"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8B 5C 24 2C 0F BE 03 89 44 24 1C 8D 44 24 1C 50 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 74 08 8B 44 24 14 88 03 B2 01 89 D0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule getrlimit64_32dd0b382dae3a19dc88b8aed0954e87 {
	meta:
		aliases = "getrlimit64"
		size = "109"
		objfiles = "getrlimit64@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8B 5C 24 2C 8D 44 24 18 50 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 46 8B 44 24 10 83 F8 FF 75 0F C7 03 FF FF FF FF C7 43 04 FF FF FF FF EB 09 89 03 C7 43 04 00 00 00 00 8B 44 24 14 83 F8 FF 75 10 C7 43 08 FF FF FF FF C7 43 0C FF FF FF FF EB 0A 89 43 08 C7 43 0C 00 00 00 00 31 D2 89 D0 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule sendto_5d34b75e813349ecb66d4df8bca7ae28 {
	meta:
		aliases = "sendto"
		size = "70"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 1C 50 6A 01 E8 ?? ?? ?? ?? 58 5A FF 74 24 3C FF 74 24 3C FF 74 24 3C FF 74 24 3C FF 74 24 3C FF 74 24 3C E8 ?? ?? ?? ?? 89 C3 83 C4 18 6A 00 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule close_4199d8a1026b0f444ee59b22a6da387c {
	meta:
		aliases = "close"
		size = "48"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 1C 50 6A 01 E8 ?? ?? ?? ?? 58 FF 74 24 2C E8 ?? ?? ?? ?? 89 C3 59 58 6A 00 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
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

rule recvfrom_0912a916b01e8887eb41f8cefdf84523 {
	meta:
		aliases = "recvfrom"
		size = "70"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 1C 50 6A 01 E8 ?? ?? ?? ?? 59 5B FF 74 24 3C FF 74 24 3C FF 74 24 3C FF 74 24 3C FF 74 24 3C FF 74 24 3C E8 ?? ?? ?? ?? 89 C3 83 C4 18 6A 00 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule tcdrain_f62998a482170cde13f7c89dcfb26a0d {
	meta:
		aliases = "system, fsync, wait, tcdrain"
		size = "48"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 1C 50 6A 01 E8 ?? ?? ?? ?? 59 FF 74 24 2C E8 ?? ?? ?? ?? 89 C3 58 5A 6A 00 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule read_f76fa2a31d5e51010722d3c9bb015e20 {
	meta:
		aliases = "connect, recvmsg, write, msync, read"
		size = "58"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 1C 50 6A 01 E8 ?? ?? ?? ?? 83 C4 0C FF 74 24 2C FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 89 C3 58 5A 6A 00 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule waitpid_b5bba3555d24a798c0dcf18747bdb9a3 {
	meta:
		aliases = "accept, __GI_waitpid, sendmsg, lseek, waitpid"
		size = "58"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 1C 50 6A 01 E8 ?? ?? ?? ?? 83 C4 0C FF 74 24 2C FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 89 C3 59 58 6A 00 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule fcntl_766a79d83351659da9ab1ae56794f7b2 {
	meta:
		aliases = "open64, fcntl"
		size = "66"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 1C 50 6A 01 E8 ?? ?? ?? ?? 8D 44 24 3C 89 44 24 20 83 C4 0C FF 74 24 2C FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 89 C3 58 5A 6A 00 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule open_4ed2b1ecf978bb23b24e6e364f3a090b {
	meta:
		aliases = "open"
		size = "66"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 1C 50 6A 01 E8 ?? ?? ?? ?? 8D 44 24 3C 89 44 24 20 83 C4 0C FF 74 24 2C FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 89 C3 59 58 6A 00 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule pause_e9088ea6a936a261a48e42225ddf1aaa {
	meta:
		aliases = "pause"
		size = "43"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 1C 50 6A 01 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 59 58 6A 00 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule pread_946cdd75fa3bd3e1398ebb9f2ed58d91 {
	meta:
		aliases = "recv, pwrite, send, pread"
		size = "60"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 8D 44 24 1C 50 6A 01 E8 ?? ?? ?? ?? FF 74 24 3C FF 74 24 3C FF 74 24 3C FF 74 24 3C E8 ?? ?? ?? ?? 89 C3 83 C4 18 6A 00 FF 74 24 20 E8 ?? ?? ?? ?? 89 D8 83 C4 28 5B C3 }
	condition:
		$pattern
}

rule __GI_frexp_ea39b07edae2c98b7a8d7129cd9ebec9 {
	meta:
		aliases = "frexp, __GI_frexp"
		size = "152"
		objfiles = "s_frexp@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 20 DD 44 24 28 DD 14 24 8B 5C 24 30 DD 54 24 18 8B 4C 24 1C 8B 44 24 18 89 CA 81 E2 FF FF FF 7F C7 03 00 00 00 00 81 FA FF FF EF 7F 7F 5D 09 D0 74 59 81 FA FF FF 0F 00 7F 21 D8 0D ?? ?? ?? ?? DD 14 24 DD 5C 24 10 8B 4C 24 14 89 CA 81 E2 FF FF FF 7F C7 03 CA FF FF FF EB 02 DD D8 8B 03 2D FE 03 00 00 C1 FA 14 01 D0 89 03 DD 04 24 DD 5C 24 08 81 E1 FF FF 0F 80 81 C9 00 00 E0 3F 89 4C 24 0C DD 44 24 08 DD 1C 24 EB 02 DD D8 DD 04 24 83 C4 20 5B C3 }
	condition:
		$pattern
}

rule forkpty_0ad8d1aeb48da7dcded67483b5c332ab {
	meta:
		aliases = "forkpty"
		size = "129"
		objfiles = "forkpty@libutil.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 24 FF 74 24 38 FF 74 24 38 FF 74 24 38 8D 44 24 28 50 8D 44 24 30 50 E8 ?? ?? ?? ?? 83 C4 20 40 74 52 E8 ?? ?? ?? ?? 89 C3 83 F8 FF 74 46 85 C0 75 27 83 EC 0C FF 74 24 20 E8 ?? ?? ?? ?? 58 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 28 83 EC 0C 6A 01 E8 ?? ?? ?? ?? 8B 54 24 14 8B 44 24 20 89 10 83 EC 0C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 EB 03 83 CB FF 89 D8 83 C4 18 5B C3 }
	condition:
		$pattern
}

rule __libc_system_b7accab364ef0d2de1e9aaa47bc35210 {
	meta:
		aliases = "system, __libc_system"
		size = "305"
		objfiles = "system@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 28 B8 01 00 00 00 83 7C 24 30 00 0F 84 18 01 00 00 51 51 6A 01 6A 03 E8 ?? ?? ?? ?? 89 44 24 1C 58 5A 6A 01 6A 02 E8 ?? ?? ?? ?? 89 44 24 20 5B 58 6A 00 6A 11 E8 ?? ?? ?? ?? 89 44 24 24 E8 ?? ?? ?? ?? 89 C3 83 C4 10 83 F8 00 7D 2F 51 51 FF 74 24 14 6A 03 E8 ?? ?? ?? ?? 58 5A FF 74 24 18 6A 02 E8 ?? ?? ?? ?? 5B 58 FF 74 24 1C 6A 11 E8 ?? ?? ?? ?? 83 C8 FF E9 AA 00 00 00 75 4A 51 51 6A 00 6A 03 E8 ?? ?? ?? ?? 58 5A 6A 00 6A 02 E8 ?? ?? ?? ?? 5B 58 6A 00 6A 11 E8 ?? ?? ?? ?? C7 04 24 00 00 00 00 FF 74 24 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 14 6A 7F E8 ?? }
	condition:
		$pattern
}

rule trunc_a5a0070084f848b349adcb56af6830b6 {
	meta:
		aliases = "__GI_trunc, trunc"
		size = "215"
		objfiles = "s_trunc@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 28 C7 44 24 18 00 00 00 00 C7 44 24 1C 00 00 00 00 C7 44 24 10 00 00 00 00 C7 44 24 14 00 00 00 00 C7 44 24 08 00 00 00 00 C7 44 24 0C 00 00 00 00 DD 44 24 30 DD 14 24 DD 5C 24 20 8B 54 24 24 8B 5C 24 20 89 D0 C1 F8 14 25 FF 07 00 00 8D 88 01 FC FF FF 83 F9 13 7F 3D 89 D3 81 E3 00 00 00 80 85 C9 79 12 89 5C 24 1C C7 44 24 18 00 00 00 00 DD 44 24 18 EB 52 B8 FF FF 0F 00 D3 F8 F7 D0 21 D0 09 D8 89 44 24 14 C7 44 24 10 00 00 00 00 DD 44 24 10 EB 33 83 F9 33 7E 0F 81 F9 00 04 00 00 75 29 DD 04 24 D8 C0 EB 1F 8B 54 24 24 89 54 24 0C 8D 88 ED FB FF FF 83 C8 FF D3 E8 F7 D0 21 D8 89 44 24 08 }
	condition:
		$pattern
}

rule __GI_scalbln_034638c633fc896e7da10d5f36a250e5 {
	meta:
		aliases = "scalbln, __GI_scalbln"
		size = "293"
		objfiles = "s_scalbln@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 28 DD 44 24 30 DD 14 24 8B 5C 24 38 DD 54 24 20 8B 54 24 24 8B 4C 24 20 89 D0 25 00 00 F0 7F C1 F8 14 75 2E 81 E2 FF FF FF 7F 09 CA 0F 84 E6 00 00 00 D8 0D ?? ?? ?? ?? DD 14 24 DD 5C 24 18 8B 54 24 1C 89 D0 25 00 00 F0 7F C1 F8 14 83 E8 36 EB 02 DD D8 3D FF 07 00 00 75 0A DD 04 24 D8 C0 E9 AE 00 00 00 01 D8 81 FB 50 C3 00 00 7F 07 3D FE 07 00 00 7E 25 FF 74 24 04 FF 74 24 04 68 3C E4 37 7E 68 9C 75 00 88 E8 ?? ?? ?? ?? 83 C4 10 DD 1C 24 DD 05 ?? ?? ?? ?? EB 50 81 FB B0 3C FF FF 7C 25 85 C0 7E 1C DD 04 24 DD 5C 24 10 C1 E0 14 81 E2 FF FF 0F 80 09 D0 89 44 24 14 DD 44 24 10 EB 50 83 F8 }
	condition:
		$pattern
}

rule scalbn_8f16b061623fe4da6276702d185f3de3 {
	meta:
		aliases = "__GI_scalbn, scalbn"
		size = "307"
		objfiles = "s_scalbn@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 28 DD 44 24 30 DD 14 24 8B 5C 24 38 DD 54 24 20 8B 54 24 24 8B 4C 24 20 89 D0 25 00 00 F0 7F C1 F8 14 75 44 81 E2 FF FF FF 7F 09 CA 0F 84 F4 00 00 00 D8 0D ?? ?? ?? ?? DD 14 24 DD 5C 24 18 81 FB B0 3C FF FF 7C 13 8B 54 24 1C 89 D0 25 00 00 F0 7F C1 F8 14 83 E8 36 EB 10 DD 04 24 DC 0D ?? ?? ?? ?? E9 B9 00 00 00 DD D8 3D FF 07 00 00 75 0A DD 04 24 D8 C0 E9 A6 00 00 00 01 D8 3D FE 07 00 00 7F 2D 85 C0 7E 1C DD 04 24 DD 5C 24 10 C1 E0 14 81 E2 FF FF 0F 80 09 D0 89 44 24 14 DD 44 24 10 EB 7D 83 F8 CA 7F 55 81 FB 50 C3 00 00 7E 25 FF 74 24 04 FF 74 24 04 68 3C E4 37 7E 68 9C 75 00 88 E8 ?? }
	condition:
		$pattern
}

rule __ieee754_sinh_d7723e5ea5085f4e6650c8c6b5718672 {
	meta:
		aliases = "__ieee754_sinh"
		size = "334"
		objfiles = "e_sinh@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 28 DD 44 24 30 DD 54 24 08 DD 54 24 18 8B 44 24 1C 89 C3 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 07 D8 C0 E9 16 01 00 00 DD D8 85 C0 79 08 D9 05 ?? ?? ?? ?? EB 06 D9 05 ?? ?? ?? ?? DD 5C 24 20 81 FB FF FF 35 40 7F 76 81 FB FF FF 2F 3E 7F 19 DD 44 24 08 DC 05 ?? ?? ?? ?? D9 E8 D9 C9 DA E9 DF E0 9E 0F 87 D9 00 00 00 51 51 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? DD 1C 24 E8 ?? ?? ?? ?? D9 C0 83 C4 10 81 FB FF FF EF 3F 7F 1C DC C1 D9 C9 DD 5C 24 08 D9 C0 D8 C9 D9 C9 DC 05 ?? ?? ?? ?? DE F9 DC 6C 24 08 EB 0A DD D9 D9 E8 D8 C1 D8 F9 DE C1 DD 44 24 20 DE C9 E9 80 00 00 00 81 FB 41 2E 86 40 7F }
	condition:
		$pattern
}

rule _create_xid_108fc3d0ca2a0291bf3d14cd0611d923 {
	meta:
		aliases = "_create_xid"
		size = "129"
		objfiles = "create_xid@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 2C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 18 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 80 3D ?? ?? ?? ?? 00 75 2D 51 51 6A 00 8D 44 24 28 50 E8 ?? ?? ?? ?? 58 5A 68 ?? ?? ?? ?? 8B 44 24 28 33 44 24 2C 50 E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01 83 C4 10 8D 44 24 24 51 51 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 5A 6A 01 53 E8 ?? ?? ?? ?? 8B 44 24 34 83 C4 38 5B C3 }
	condition:
		$pattern
}

rule random_7c427e1235d31eff265f99d3e8c484d4 {
	meta:
		aliases = "__GI_random, random"
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

rule malloc_stats_0850721a5765aca6c43b0dfd2082edec {
	meta:
		aliases = "malloc_stats"
		size = "88"
		objfiles = "mallinfo@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 38 8B 5C 24 40 85 DB 75 06 8B 1D ?? ?? ?? ?? 8D 44 24 10 83 EC 0C 50 E8 ?? ?? ?? ?? 8B 44 24 38 8B 4C 24 2C 8B 54 24 1C 83 EC 08 FF 74 24 48 FF 74 24 48 FF 74 24 40 50 51 FF 74 24 44 52 8D 04 01 50 01 CA 52 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 78 5B C3 }
	condition:
		$pattern
}

rule svc_sendreply_06a5b40eb9279fcca529445df247d912 {
	meta:
		aliases = "__GI_svc_sendreply, svc_sendreply"
		size = "84"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 38 8B 5C 24 40 C7 44 24 0C 01 00 00 00 C7 44 24 10 00 00 00 00 8D 54 24 14 8D 43 20 51 6A 0C 50 52 E8 ?? ?? ?? ?? C7 44 24 30 00 00 00 00 8B 44 24 58 89 44 24 34 8B 44 24 54 89 44 24 38 58 5A 8B 53 08 8D 44 24 10 50 53 FF 52 0C 83 C4 48 5B C3 }
	condition:
		$pattern
}

rule svcerr_noprog_191164ee7de49f4a45e7d01102b34817 {
	meta:
		aliases = "__GI_svcerr_noprog, svcerr_noprog"
		size = "68"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 38 8B 5C 24 40 C7 44 24 0C 01 00 00 00 C7 44 24 10 00 00 00 00 8D 54 24 14 8D 43 20 51 6A 0C 50 52 E8 ?? ?? ?? ?? C7 44 24 30 01 00 00 00 58 5A 8B 53 08 8D 44 24 10 50 53 FF 52 0C 83 C4 48 5B C3 }
	condition:
		$pattern
}

rule __GI_svcerr_progvers_c0d86089f080a5e203734f7037a52413 {
	meta:
		aliases = "svcerr_progvers, __GI_svcerr_progvers"
		size = "84"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 38 8B 5C 24 40 C7 44 24 0C 01 00 00 00 C7 44 24 10 00 00 00 00 8D 54 24 14 8D 43 20 51 6A 0C 50 52 E8 ?? ?? ?? ?? C7 44 24 30 02 00 00 00 8B 44 24 54 89 44 24 34 8B 44 24 58 89 44 24 38 58 5A 8B 53 08 8D 44 24 10 50 53 FF 52 0C 83 C4 48 5B C3 }
	condition:
		$pattern
}

rule svcerr_noproc_01e8f59eacd8b5324d939121cf2735b3 {
	meta:
		aliases = "svcerr_noproc"
		size = "68"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 38 8B 5C 24 40 C7 44 24 0C 01 00 00 00 C7 44 24 10 00 00 00 00 8D 54 24 14 8D 43 20 51 6A 0C 50 52 E8 ?? ?? ?? ?? C7 44 24 30 03 00 00 00 58 5A 8B 53 08 8D 44 24 10 50 53 FF 52 0C 83 C4 48 5B C3 }
	condition:
		$pattern
}

rule svcerr_decode_ca7ac4c5eb126fa3bb878c333526d582 {
	meta:
		aliases = "__GI_svcerr_decode, svcerr_decode"
		size = "68"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 38 8B 5C 24 40 C7 44 24 0C 01 00 00 00 C7 44 24 10 00 00 00 00 8D 54 24 14 8D 43 20 51 6A 0C 50 52 E8 ?? ?? ?? ?? C7 44 24 30 04 00 00 00 58 5A 8B 53 08 8D 44 24 10 50 53 FF 52 0C 83 C4 48 5B C3 }
	condition:
		$pattern
}

rule svcerr_systemerr_bc01c1ae0a7859041ff58d1bdc9ffe8f {
	meta:
		aliases = "svcerr_systemerr"
		size = "68"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 38 8B 5C 24 40 C7 44 24 0C 01 00 00 00 C7 44 24 10 00 00 00 00 8D 54 24 14 8D 43 20 51 6A 0C 50 52 E8 ?? ?? ?? ?? C7 44 24 30 05 00 00 00 58 5A 8B 53 08 8D 44 24 10 50 53 FF 52 0C 83 C4 48 5B C3 }
	condition:
		$pattern
}

rule pmap_unset_13f9c3cb836029a24a7a5ebff632cd7d {
	meta:
		aliases = "__GI_pmap_unset, pmap_unset"
		size = "178"
		objfiles = "pmap_clnt@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 38 C7 44 24 34 FF FF FF FF 8D 5C 24 20 89 D8 E8 ?? ?? ?? ?? 85 C0 0F 84 8C 00 00 00 68 90 01 00 00 68 90 01 00 00 8D 44 24 3C 50 FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 6A 02 68 A0 86 01 00 53 E8 ?? ?? ?? ?? 89 C3 83 C4 20 85 C0 74 5B 8B 44 24 40 89 44 24 10 8B 44 24 44 89 44 24 14 C7 44 24 18 00 00 00 00 C7 44 24 1C 00 00 00 00 8D 44 24 30 8D 54 24 10 8B 4B 04 FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? 6A 02 53 FF 11 83 C4 14 8B 43 04 53 FF 50 10 8B 44 24 40 83 C4 10 EB 02 31 C0 83 C4 38 5B C3 }
	condition:
		$pattern
}

rule __ieee754_j0_4f7b4cc4fb3494fe735508926ad0c65c {
	meta:
		aliases = "__ieee754_j0"
		size = "524"
		objfiles = "e_j0@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 38 DD 44 24 40 DD 14 24 DD 54 24 08 8B 5C 24 0C 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 0D D8 C8 DC 3D ?? ?? ?? ?? E9 D9 01 00 00 DD D8 50 50 FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 10 DD 5C 24 30 81 FB FF FF FF 3F 0F 8E FC 00 00 00 51 51 FF 74 24 3C FF 74 24 3C E8 ?? ?? ?? ?? DD 5C 24 20 58 5A FF 74 24 3C FF 74 24 3C E8 ?? ?? ?? ?? DD 5C 24 28 DD 44 24 20 DC 44 24 28 DD 5C 24 38 83 C4 10 81 FB FF FF DF 7F 7F 4B 83 EC 10 DD 44 24 40 D8 C0 DD 1C 24 E8 ?? ?? ?? ?? D9 E0 DD 44 24 20 DC 4C 24 28 83 C4 10 D9 EE DA E9 DF E0 9E 76 14 DD 44 24 10 DC 64 24 18 DD 54 24 20 DE F9 DD 5C 24 28 }
	condition:
		$pattern
}

rule __ieee754_log10_270758a40971f56d12824c33795497b7 {
	meta:
		aliases = "__ieee754_log10"
		size = "234"
		objfiles = "e_log10@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 38 DD 44 24 40 DD 54 24 10 DD 5C 24 28 8B 4C 24 2C 8B 54 24 28 31 DB 81 F9 FF FF 0F 00 7F 48 89 C8 25 FF FF FF 7F 09 D0 75 0D D9 EE D8 3D ?? ?? ?? ?? E9 AB 00 00 00 85 C9 79 11 DD 44 24 10 D8 E0 DC 35 ?? ?? ?? ?? E9 96 00 00 00 DD 44 24 10 D8 0D ?? ?? ?? ?? DD 54 24 10 DD 5C 24 20 8B 4C 24 24 BB CA FF FF FF 81 F9 FF FF EF 7F 7E 08 DD 44 24 10 D8 C0 EB 6B 89 C8 C1 F8 14 8D 84 03 01 FC FF FF 89 C2 C1 EA 1F 8D 04 02 50 DB 04 24 83 EC 04 DD 44 24 18 DD 5C 24 20 B8 FF 03 00 00 29 D0 C1 E0 14 81 E1 FF FF 0F 00 09 C8 89 44 24 24 FF 74 24 24 FF 74 24 24 DD 5C 24 10 E8 ?? ?? ?? ?? DD 44 24 10 }
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

rule __GI_lstat_57b223931df8f8a60653acc308330bca {
	meta:
		aliases = "lstat, __GI_lstat"
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

rule __kernel_tan_d096e41cfa02e6ba0f4cb0cbbaacdacf {
	meta:
		aliases = "__kernel_tan"
		size = "538"
		objfiles = "k_tan@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 48 DD 44 24 50 DD 54 24 08 DD 44 24 58 D9 C9 8B 5C 24 60 DD 54 24 28 8B 54 24 2C 89 D1 81 E1 FF FF FF 7F 81 F9 FF FF 2F 3E 7F 6D D9 7C 24 46 66 8B 44 24 46 80 CC 0C 66 89 44 24 44 D9 6C 24 44 DB 54 24 40 D9 6C 24 46 8B 44 24 40 85 C0 0F 85 80 00 00 00 DD D9 DD 5C 24 20 0B 4C 24 20 8D 43 01 09 C1 75 1D 50 50 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? 83 C4 10 DC 3D ?? ?? ?? ?? E9 88 01 00 00 4B 0F 84 85 01 00 00 DD 44 24 08 D8 3D ?? ?? ?? ?? E9 72 01 00 00 DD D8 81 F9 27 94 E5 3F 7E 34 85 D2 79 0C DD 44 24 08 D9 E0 DD 5C 24 08 D9 E0 DD 44 24 08 DC 2D ?? ?? ?? ?? DD 5C 24 08 DD 05 ?? ?? ?? }
	condition:
		$pattern
}

rule asinh_777da67f0ca2c8fb28edd9bd0d420541 {
	meta:
		aliases = "__GI_asinh, asinh"
		size = "319"
		objfiles = "s_asinh@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 48 DD 44 24 50 DD 54 24 20 DD 54 24 28 8B 5C 24 2C 89 DA 81 E2 FF FF FF 7F 81 FA FF FF EF 7F 7E 07 D8 C0 E9 03 01 00 00 DD D8 81 FA FF FF 2F 3E 7F 19 DD 44 24 20 DC 05 ?? ?? ?? ?? D9 E8 D9 C9 DA E9 DF E0 9E 0F 87 E8 00 00 00 81 FA 00 00 B0 41 7E 22 50 50 FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? DD 1C 24 E8 ?? ?? ?? ?? DC 05 ?? ?? ?? ?? E9 A9 00 00 00 81 FA 00 00 00 40 DD 44 24 20 D8 C8 DD 5C 24 10 7E 49 51 51 FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? DD 5C 24 48 D9 E8 DD 44 24 20 D8 C1 DD 54 24 20 DD 1C 24 DD 5C 24 10 E8 ?? ?? ?? ?? DD 44 24 48 D8 C0 D9 C9 DC 44 24 48 DD 44 24 10 DE F1 DE }
	condition:
		$pattern
}

rule __GI_statfs64_c25a7badef268e98cf069c0408da137e {
	meta:
		aliases = "__GI_fstatfs64, fstatfs64, statfs64, __GI_statfs64"
		size = "165"
		objfiles = "statfs64@libc.a, fstatfs64@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 50 8B 5C 24 5C 8D 44 24 10 50 FF 74 24 5C E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 7E 8B 44 24 08 89 03 8B 44 24 0C 89 43 04 8B 44 24 10 89 43 08 C7 43 0C 00 00 00 00 8B 44 24 14 89 43 10 C7 43 14 00 00 00 00 8B 44 24 18 89 43 18 C7 43 1C 00 00 00 00 8B 44 24 1C 89 43 20 C7 43 24 00 00 00 00 8B 44 24 20 89 43 28 C7 43 2C 00 00 00 00 8B 44 24 28 89 43 34 8B 44 24 24 89 43 30 8B 44 24 2C 89 43 38 50 6A 14 8D 44 24 3C 50 8D 43 40 50 E8 ?? ?? ?? ?? 31 D2 83 C4 10 89 D0 83 C4 48 5B C3 }
	condition:
		$pattern
}

rule vswprintf_3a220671c71a78fd9c7c6b76c32c9347 {
	meta:
		aliases = "__GI_vswprintf, vswprintf"
		size = "157"
		objfiles = "vswprintf@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 58 8B 54 24 60 8B 44 24 64 C7 44 24 0C FD FF FF FF 66 C7 44 24 08 50 08 C6 44 24 0A 00 C7 44 24 34 00 00 00 00 C7 44 24 28 00 00 00 00 89 D3 F7 D3 C1 EB 02 39 C3 76 02 89 C3 89 54 24 10 8D 04 9A 89 44 24 14 89 54 24 18 89 54 24 1C 89 54 24 20 89 54 24 24 50 FF 74 24 70 FF 74 24 70 8D 44 24 14 50 E8 ?? ?? ?? ?? 89 C2 8B 44 24 28 83 C4 10 3B 44 24 14 75 0E 83 CA FF 85 DB 74 15 83 E8 04 89 44 24 18 85 DB 74 0A 8B 44 24 18 C7 00 00 00 00 00 89 D0 83 C4 58 5B C3 }
	condition:
		$pattern
}

rule __ieee754_y1_7d708d39904570df395d36371fab5384 {
	meta:
		aliases = "__ieee754_y1"
		size = "551"
		objfiles = "e_j1@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 58 DD 44 24 60 DD 54 24 20 DD 54 24 28 8B 54 24 2C 8B 44 24 28 89 D3 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 11 D8 C8 DC 44 24 20 DC 3D ?? ?? ?? ?? E9 E9 01 00 00 DD D8 09 D8 75 0D D9 EE D8 3D ?? ?? ?? ?? E9 D6 01 00 00 85 D2 79 09 D9 EE D8 F0 E9 C9 01 00 00 81 FB FF FF FF 3F 0F 8E FB 00 00 00 51 51 FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? DD 5C 24 40 58 5A FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? DD 5C 24 48 DD 44 24 40 D9 E0 DC 64 24 48 DD 5C 24 50 83 C4 10 81 FB FF FF DF 7F 7F 4B 83 EC 10 DD 44 24 30 D8 C0 DD 1C 24 E8 ?? ?? ?? ?? DD 44 24 40 DC 4C 24 48 83 C4 10 D9 EE D9 C9 DA E9 DF E0 }
	condition:
		$pattern
}

rule __ieee754_y0_9ca44e73384e45bd38be7474db163c91 {
	meta:
		aliases = "__ieee754_y0"
		size = "560"
		objfiles = "e_j0@libm.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 58 DD 44 24 60 DD 54 24 20 DD 54 24 28 8B 54 24 2C 8B 44 24 28 89 D3 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 11 D8 C8 DC 44 24 20 DC 3D ?? ?? ?? ?? E9 F2 01 00 00 DD D8 09 D8 75 0D D9 EE D8 3D ?? ?? ?? ?? E9 DF 01 00 00 85 D2 79 09 D9 EE D8 F0 E9 D2 01 00 00 81 FB FF FF FF 3F 0F 8E F9 00 00 00 51 51 FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? DD 5C 24 40 58 5A FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? DD 5C 24 48 DD 44 24 40 DC 64 24 48 DD 5C 24 50 83 C4 10 81 FB FF FF DF 7F 7F 4B 83 EC 10 DD 44 24 30 D8 C0 DD 1C 24 E8 ?? ?? ?? ?? D9 E0 DD 44 24 40 DC 4C 24 48 83 C4 10 D9 EE DA E9 DF E0 9E 76 }
	condition:
		$pattern
}

rule __GI_vswscanf_33138bef49c586304e6fce1bb151522c {
	meta:
		aliases = "vswscanf, __GI_vswscanf"
		size = "122"
		objfiles = "vswscanf@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 64 8B 5C 24 6C 89 5C 24 24 89 5C 24 1C 53 E8 ?? ?? ?? ?? 5A 8D 04 83 89 44 24 20 89 44 24 28 89 5C 24 2C 89 5C 24 30 C7 44 24 18 FD FF FF FF 66 C7 44 24 14 21 08 C6 44 24 16 00 C7 44 24 40 00 00 00 00 C7 44 24 48 01 00 00 00 8D 5C 24 14 8D 44 24 4C 50 E8 ?? ?? ?? ?? C7 44 24 38 00 00 00 00 83 C4 0C FF 74 24 6C FF 74 24 6C 53 E8 ?? ?? ?? ?? 83 C4 68 5B C3 }
	condition:
		$pattern
}

rule stat64_126c0c0d7ca05fdaa874caf75b60c026 {
	meta:
		aliases = "__GI_stat64, stat64"
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

rule fdopendir_6ef75619c937fb845f7e71ee3b027738 {
	meta:
		aliases = "fdopendir"
		size = "112"
		objfiles = "opendir@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 70 8B 5C 24 78 8D 44 24 18 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 4F 8B 44 24 20 25 00 F0 00 00 3D 00 40 00 00 74 0D E8 ?? ?? ?? ?? C7 00 14 00 00 00 EB 32 50 50 6A 03 53 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 74 20 83 E0 03 48 75 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 0D 8B 54 24 40 89 D8 E8 ?? ?? ?? ?? EB 02 31 C0 83 C4 68 5B C3 }
	condition:
		$pattern
}

rule ftok_7fc74bf9f4cf50286bb684552fd6c076 {
	meta:
		aliases = "ftok"
		size = "59"
		objfiles = "ftok@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 83 EC 70 8B 5C 24 7C 8D 44 24 18 50 FF 74 24 7C E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 14 0F B6 54 24 10 C1 E2 10 0F B7 44 24 1C 09 C2 C1 E3 18 09 DA 89 D0 83 C4 68 5B C3 }
	condition:
		$pattern
}

rule pthread_insert_list_b4f8e514296fa1de8e42a4baed3a7009 {
	meta:
		aliases = "pthread_insert_list"
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
		size = "38"
		objfiles = "malloc@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C3 89 C2 C1 EA 08 B8 5F 00 00 00 81 FA FF FF 00 00 77 0F 0F BD C2 8D 48 06 D3 EB 83 E3 03 8D 44 83 20 5B C3 }
	condition:
		$pattern
}

rule __md5_to64_49bcf00391895a547b877ac98b8de652 {
	meta:
		aliases = "__md5_to64"
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
		size = "41"
		objfiles = "semaphore@libpthread.a, condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 89 C3 EB 1A 39 D1 75 13 8B 41 08 89 03 C7 41 08 00 00 00 00 B8 01 00 00 00 EB 0B 8D 59 08 8B 0B 85 C9 75 E0 31 C0 5B C3 }
	condition:
		$pattern
}

rule string_append_template_idx_58c505adb424e9d4c3bc40a83051ff37 {
	meta:
		aliases = "string_append_template_idx"
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
		size = "59"
		objfiles = "strftime@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 14 82 8A 98 ?? ?? ?? ?? B9 6D 01 00 00 83 F8 07 74 13 0F B6 CB 83 F8 05 75 0B 81 C2 6C 07 00 00 B9 0F 27 00 00 39 CA 77 09 83 F8 03 75 07 85 D2 75 03 83 CA FF 89 D0 5B C3 }
	condition:
		$pattern
}

rule llabs_7e56ecd29126203efd64d0b46dd8d488 {
	meta:
		aliases = "imaxabs, llabs"
		size = "30"
		objfiles = "llabs@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 54 24 0C 89 C1 89 D3 89 DB C1 FB 1F 89 D9 31 C8 31 DA 29 C8 19 DA 5B C3 }
	condition:
		$pattern
}

rule mq_timedreceive_f62a30623161be2fd9fda3b5ffa0883f {
	meta:
		aliases = "mq_timedsend, mq_timedreceive"
		size = "35"
		objfiles = "mq_send@librt.a, mq_receive@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 54 24 0C 8B 4C 24 10 8B 5C 24 18 89 5C 24 0C 8B 5C 24 14 89 5C 24 08 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __libc_pread_8810fe4c8dbaf93db0b2807cdd400643 {
	meta:
		aliases = "mq_receive, mq_send, pread, __libc_pread"
		size = "35"
		objfiles = "mq_send@librt.a, pread_write@libc.a, mq_receive@librt.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 54 24 0C 8B 4C 24 10 C7 44 24 0C 00 00 00 00 8B 5C 24 14 89 5C 24 08 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __libc_pwrite_9e46946a9d5e5d4a028f8a7e5d42a695 {
	meta:
		aliases = "pwrite, __libc_pwrite"
		size = "35"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 54 24 0C 8B 4C 24 10 C7 44 24 0C 01 00 00 00 8B 5C 24 14 89 5C 24 08 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __ivaliduser_973f2be830416d2da8e15c406d16eec7 {
	meta:
		aliases = "iruserok, __ivaliduser"
		size = "35"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 8B 54 24 0C 8B 4C 24 10 C7 44 24 0C ?? ?? ?? ?? 8B 5C 24 14 89 5C 24 08 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wmemset_357bef8bdfa803522ea2431254217c2a {
	meta:
		aliases = "wmemset"
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
		size = "35"
		objfiles = "strpbrk@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 EB 0C 38 D9 74 16 42 8A 0A 84 C9 75 F5 40 8A 18 84 DB 74 06 8B 54 24 0C EB ED 31 C0 5B C3 }
	condition:
		$pattern
}

rule wcspbrk_cdd88d21c3f86c1ae4cbaac47f47a095 {
	meta:
		aliases = "__GI_wcspbrk, wcspbrk"
		size = "39"
		objfiles = "wcspbrk@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 44 24 08 EB 10 39 D9 74 1A 83 C2 04 8B 0A 85 C9 75 F3 83 C0 04 8B 18 85 DB 74 06 8B 54 24 0C EB EB 31 C0 5B C3 }
	condition:
		$pattern
}

rule xdrmem_setpos_72cb6fad845e965777219a083e18843a {
	meta:
		aliases = "xdrmem_setpos"
		size = "38"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 8B 54 24 0C 03 51 10 8B 41 14 03 41 0C 31 DB 39 C2 7F 0A 89 51 0C 29 D0 89 41 14 B3 01 89 D8 5B C3 }
	condition:
		$pattern
}

rule re_set_registers_7206b1d369dfabfdd87020020d1cae74 {
	meta:
		aliases = "__re_set_registers, re_set_registers"
		size = "75"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 8B 54 24 0C 8B 5C 24 10 85 DB 8A 41 1C 74 1B 83 E0 F9 83 C8 02 88 41 1C 89 1A 8B 44 24 14 89 42 04 8B 44 24 18 89 42 08 EB 1A 83 E0 F9 88 41 1C C7 02 00 00 00 00 C7 42 08 00 00 00 00 C7 42 04 00 00 00 00 5B C3 }
	condition:
		$pattern
}

rule __decode_header_d70812666783c291d83a01141c90061e {
	meta:
		aliases = "__decode_header"
		size = "171"
		objfiles = "decodeh@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 8B 5C 24 0C 0F B6 51 01 0F B6 01 C1 E0 08 09 C2 89 13 0F BE 41 02 C1 E8 1F 89 43 04 8A 41 02 C0 E8 03 83 E0 0F 89 43 08 0F B6 41 02 C1 E8 02 83 E0 01 89 43 0C 0F B6 41 02 D1 E8 83 E0 01 89 43 10 0F B6 41 02 83 E0 01 89 43 14 0F BE 41 03 C1 E8 1F 89 43 18 0F B6 41 03 83 E0 0F 89 43 1C 0F B6 41 04 C1 E0 08 0F B6 51 05 09 D0 89 43 20 0F B6 41 06 C1 E0 08 0F B6 51 07 09 D0 89 43 24 0F B6 41 08 C1 E0 08 0F B6 51 09 09 D0 89 43 28 0F B6 41 0A C1 E0 08 0F B6 51 0B 09 D0 89 43 2C B8 0C 00 00 00 5B C3 }
	condition:
		$pattern
}

rule xdrmem_inline_73f81dd4e3715ff18c72a7b5a0fcef2d {
	meta:
		aliases = "xdrmem_inline"
		size = "36"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 08 8B 5C 24 0C 8B 41 14 31 D2 39 D8 72 0E 29 D8 89 41 14 8B 51 0C 8D 04 1A 89 41 0C 89 D0 5B C3 }
	condition:
		$pattern
}

rule __sigismember_153421a36092b719bf7f04011c9e23e0 {
	meta:
		aliases = "__sigismember"
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
		size = "36"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 4C 24 0C 8B 44 24 08 8B 00 8B 50 1C C7 44 24 0C ?? ?? ?? ?? 8B 5C 24 10 89 5C 24 08 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule swab_f15ce667d1078cb383f3c759dd52a476 {
	meta:
		aliases = "swab"
		size = "43"
		objfiles = "swab@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 44 24 10 83 E0 FE 8D 1C 02 8B 4C 24 0C EB 10 66 8B 02 66 C1 C8 08 83 C2 02 66 89 01 83 C1 02 39 DA 72 EC 5B C3 }
	condition:
		$pattern
}

rule wcsncmp_90197f1ac46757f3d958e6677c9844a5 {
	meta:
		aliases = "wcsncmp"
		size = "45"
		objfiles = "wcsncmp@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 54 24 08 8B 4C 24 0C 8B 5C 24 10 EB 0C 83 3A 00 74 0B 83 C2 04 83 C1 04 4B 85 DB 75 04 31 C0 EB 08 8B 02 3B 01 74 E6 2B 01 5B C3 }
	condition:
		$pattern
}

rule register_Btype_d9724c301eb12563f95e6cf261c2f6e8 {
	meta:
		aliases = "register_Btype"
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
		size = "29"
		objfiles = "semaphore@libpthread.a, rwlock@libpthread.a, condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5A 18 EB 0D 3B 59 18 7E 05 89 4A 08 EB 09 8D 41 08 8B 08 85 C9 75 ED 89 10 5B C3 }
	condition:
		$pattern
}

rule rand_r_e282aa635e9217bca6e56dcfe9757397 {
	meta:
		aliases = "rand_r"
		size = "84"
		objfiles = "rand_r@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 69 0B 6D 4E C6 41 81 C1 39 30 00 00 89 C8 C1 E8 06 69 C9 6D 4E C6 41 81 C1 39 30 00 00 25 00 FC 1F 00 89 CA C1 EA 10 81 E2 FF 03 00 00 31 D0 69 C9 6D 4E C6 41 81 C1 39 30 00 00 C1 E0 0A 89 CA C1 EA 10 81 E2 FF 03 00 00 31 D0 89 0B 5B C3 }
	condition:
		$pattern
}

rule byte_store_op2_28dc7fb9fb9a091ae8f6833edf8f3317 {
	meta:
		aliases = "byte_store_op2"
		size = "27"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 88 02 88 4A 01 C1 F9 08 88 4A 02 88 5A 03 C1 FB 08 88 5A 04 5B C3 }
	condition:
		$pattern
}

rule __sigaddset_a0b2dce9ddf206cde67fd512ea066dce {
	meta:
		aliases = "__sigaddset"
		size = "32"
		objfiles = "sigsetops@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 4C 24 0C 49 89 CA C1 EA 05 83 E1 1F B8 01 00 00 00 D3 E0 09 04 93 31 C0 5B C3 }
	condition:
		$pattern
}

rule __sigdelset_4c865c2b04e52bce1aaab48e6401d397 {
	meta:
		aliases = "__sigdelset"
		size = "32"
		objfiles = "sigsetops@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 4C 24 0C 49 89 CA C1 EA 05 83 E1 1F B8 FE FF FF FF D3 C0 21 04 93 31 C0 5B C3 }
	condition:
		$pattern
}

rule __fsetlocking_4741a05d9e8a78091574276d70fc3a85 {
	meta:
		aliases = "__GI___fsetlocking, __fsetlocking"
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
		size = "61"
		objfiles = "_store_inttype@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 4C 24 0C 8B 44 24 10 8B 54 24 14 81 F9 00 01 00 00 75 04 88 03 EB 1E 81 F9 00 08 00 00 75 07 89 03 89 53 04 EB 0F 81 F9 00 02 00 00 75 05 66 89 03 EB 02 89 03 5B C3 }
	condition:
		$pattern
}

rule _dl_parse_lazy_relocation_info_6e12d6311756fde7ac4c9b2fe8272242 {
	meta:
		aliases = "_dl_parse_lazy_relocation_information"
		size = "35"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 4C 24 0C C7 44 24 0C ?? ?? ?? ?? 8B 44 24 10 89 44 24 08 31 D2 8B 03 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __cmsg_nxthdr_724519eda3349abcc503a059a1241534 {
	meta:
		aliases = "__GI___cmsg_nxthdr, __cmsg_nxthdr"
		size = "59"
		objfiles = "cmsg_nxthdr@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 08 8B 54 24 0C 8B 02 83 F8 0B 76 25 83 C0 03 83 E0 FC 8D 0C 02 8B 53 14 03 53 10 8D 41 0C 39 D0 77 0F 8B 01 83 C0 03 83 E0 FC 8D 04 01 39 D0 76 02 31 C9 89 C8 5B C3 }
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

rule __GI_glob_pattern_p_f9defe124f82dbc1b9c06812650033cd {
	meta:
		aliases = "glob_pattern_p, __GI_glob_pattern_p"
		size = "85"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 0C 8B 54 24 08 31 C9 EB 37 3C 5B 74 16 7F 0A 3C 2A 74 37 3C 3F 75 28 EB 31 3C 5C 74 0D 3C 5D 75 1E EB 18 B9 01 00 00 00 EB 15 85 DB 74 11 8D 42 01 80 7A 01 00 74 08 89 C2 EB 04 85 C9 75 0B 42 8A 02 84 C0 75 C3 31 C0 EB 05 B8 01 00 00 00 5B C3 }
	condition:
		$pattern
}

rule wmemcmp_2cf584a240ba0dc8c819bd8436b326ee {
	meta:
		aliases = "wmemcmp"
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
		size = "34"
		objfiles = "wmempcpy@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 10 8B 54 24 08 8B 4C 24 0C EB 0B 8B 01 89 02 83 C2 04 83 C1 04 4B 85 DB 75 F1 89 D0 5B C3 }
	condition:
		$pattern
}

rule __GI_memccpy_d0f1f8f8b136a54a7660e53e648ea303 {
	meta:
		aliases = "memccpy, __GI_memccpy"
		size = "41"
		objfiles = "memccpy@libc.a"
	strings:
		$pattern = { ( CC | 53 ) 8B 5C 24 14 8B 54 24 08 8B 4C 24 0C 4B 83 FB FF 75 04 31 C0 EB 10 8A 01 88 02 42 3A 44 24 10 74 03 41 EB E8 89 D0 5B C3 }
	condition:
		$pattern
}

rule objalloc_create_18395ee3377292c35453f6c52c26de1f {
	meta:
		aliases = "objalloc_create"
		size = "96"
		objfiles = "objalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) BF 18 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 3D BF E0 0F 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 43 10 74 2E 48 C7 00 00 00 00 00 48 C7 40 08 00 00 00 00 48 83 C0 10 48 89 03 C7 43 08 D0 0F 00 00 48 89 D8 5B C3 0F 1F 84 00 00 00 00 00 31 C0 5B C3 48 89 DF E8 ?? ?? ?? ?? 31 C0 5B C3 }
	condition:
		$pattern
}

rule fdopen_unlocked_4055eda460634cf049c59e12199515a6 {
	meta:
		aliases = "freopen_unlocked, fopen_unlocked, fdopen_unlocked"
		size = "32"
		objfiles = "fopen_unlocked@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 0D BE 02 00 00 00 48 89 C7 E8 ?? ?? ?? ?? 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule htab_remove_elt_with_hash_4e2074c58398dd26aa62eeccc3da40e4 {
	meta:
		aliases = "htab_remove_elt_with_hash"
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
		size = "88"
		objfiles = "mmap64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 56 57 8B 54 24 28 8B 4C 24 2C F7 C2 FF 0F 00 00 75 36 0F AC CA 0C C1 E9 0C 75 2D 89 D5 8B 5C 24 14 8B 4C 24 18 8B 54 24 1C 8B 74 24 20 8B 7C 24 24 B8 C0 00 00 00 CD 80 5F 5E 5B 5D 3D 01 F0 FF FF 0F 87 ?? ?? ?? ?? C3 5F 5E 5B 5D B8 EA FF FF FF E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __libc_posix_fadvise64_1511e449734dfa79da8f4d5a23eebe5a {
	meta:
		aliases = "posix_fadvise64, __GI___libc_posix_fadvise64, __libc_posix_fadvise64"
		size = "42"
		objfiles = "posix_fadvise64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 53 56 57 B8 10 01 00 00 8B 5C 24 14 8B 4C 24 18 8B 54 24 1C 8B 74 24 20 8B 7C 24 24 8B 6C 24 28 CD 80 5F 5E 5B 5D F7 D8 C3 }
	condition:
		$pattern
}

rule __decode_question_3084a8f79b7d0ec3223c139bfea484f8 {
	meta:
		aliases = "__decode_question"
		size = "130"
		objfiles = "decodeq@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 0C 01 00 00 8B B4 24 20 01 00 00 8B BC 24 28 01 00 00 68 00 01 00 00 8D 6C 24 10 55 FF B4 24 2C 01 00 00 56 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 78 3D 83 EC 0C 55 E8 ?? ?? ?? ?? 89 07 89 D9 03 8C 24 34 01 00 00 0F B6 04 0E C1 E0 08 0F B6 54 31 01 09 D0 89 47 04 0F B6 44 31 02 C1 E0 08 0F B6 54 31 03 09 D0 89 47 08 83 C3 04 83 C4 10 89 D8 81 C4 0C 01 00 00 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __decode_answer_1a834c1870838f41daa4e89d3e733199 {
	meta:
		aliases = "__decode_answer"
		size = "235"
		objfiles = "decodea@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 0C 01 00 00 8B B4 24 24 01 00 00 8B 9C 24 28 01 00 00 8B BC 24 2C 01 00 00 68 00 01 00 00 8D 44 24 10 50 56 FF B4 24 2C 01 00 00 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 88 9F 00 00 00 8D 68 0A 29 F3 29 EB 89 5C 24 08 79 07 89 D8 E9 8B 00 00 00 8D 34 30 8B 9C 24 20 01 00 00 01 F3 83 EC 0C 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 07 0F B6 53 01 0F B6 03 C1 E0 08 09 C2 89 57 04 0F B6 53 03 0F B6 43 02 C1 E0 08 09 C2 89 57 08 8D 4B 04 0F B6 51 03 0F B6 43 04 C1 E0 18 09 C2 0F B6 41 01 C1 E0 10 09 C2 0F B6 41 02 C1 E0 08 09 C2 89 57 0C 0F B6 53 09 0F B6 43 08 C1 E0 08 09 C2 89 57 10 83 C3 0A 89 }
	condition:
		$pattern
}

rule __GI_clnt_spcreateerror_39a61559a988d408ff47aba5c03cc9f0 {
	meta:
		aliases = "clnt_spcreateerror, __GI_clnt_spcreateerror"
		size = "242"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 0C 04 00 00 E8 ?? ?? ?? ?? 89 C5 85 C0 0F 84 CC 00 00 00 E8 ?? ?? ?? ?? 89 C7 53 FF B4 24 24 04 00 00 68 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 8D 5C 05 00 FF 37 E8 ?? ?? ?? ?? 83 C4 0C 50 53 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 01 C3 8B 07 83 F8 0C 74 3E 83 F8 0E 75 7D 51 51 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 01 C3 FF 77 04 E8 ?? ?? ?? ?? 52 50 53 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 01 C3 EB 44 50 50 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 0C 8D 34 03 68 00 04 00 00 8D 5C 24 14 53 FF 77 08 E8 ?? ?? ?? ?? 5F }
	condition:
		$pattern
}

rule svc_getreq_common_c59f2e3a499e23b5108e3b99f68810a5 {
	meta:
		aliases = "__GI_svc_getreq_common, svc_getreq_common"
		size = "420"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 0C 05 00 00 8D 44 24 0C 89 84 24 D8 04 00 00 8D 84 24 9C 01 00 00 89 84 24 E4 04 00 00 E8 ?? ?? ?? ?? 89 C5 8B 90 B4 00 00 00 8B 84 24 20 05 00 00 8B 1C 82 85 DB 0F 84 57 01 00 00 57 57 8B 43 08 8D 94 24 C4 04 00 00 52 53 FF 10 83 C4 10 85 C0 0F 84 15 01 00 00 8D 84 24 2C 03 00 00 89 84 24 04 05 00 00 89 9C 24 08 05 00 00 8B 84 24 C8 04 00 00 89 84 24 EC 04 00 00 8B 84 24 CC 04 00 00 89 84 24 F0 04 00 00 8B 84 24 D0 04 00 00 89 84 24 F4 04 00 00 8D 94 24 F8 04 00 00 8D 84 24 D4 04 00 00 56 6A 0C 50 52 E8 ?? ?? ?? ?? 83 C4 10 83 BC 24 D4 04 00 00 00 75 1F A1 ?? ?? ?? ?? 8B 94 }
	condition:
		$pattern
}

rule __GI_vfwscanf_6709068058dfe5f8d67501f2712730a8 {
	meta:
		aliases = "vfwscanf, __GI_vfwscanf"
		size = "1733"
		objfiles = "vfwscanf@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 10 01 00 00 C7 44 24 4C FF FF FF FF 6A 24 6A 00 8D 44 24 30 50 E8 ?? ?? ?? ?? 8B 84 24 30 01 00 00 8B 40 34 89 44 24 24 83 C4 10 85 C0 75 29 50 8B 9C 24 24 01 00 00 83 C3 38 53 68 ?? ?? ?? ?? 8D 84 24 FC 00 00 00 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 50 50 FF B4 24 28 01 00 00 8D 9C 24 BC 00 00 00 53 E8 ?? ?? ?? ?? C7 84 24 EC 00 00 00 ?? ?? ?? ?? 8B 84 24 C8 00 00 00 8A 40 03 88 84 24 D8 00 00 00 C7 84 24 FC 00 00 00 ?? ?? ?? ?? C7 44 24 68 00 00 00 00 8B B4 24 34 01 00 00 C6 44 24 23 01 83 C4 10 E9 47 05 00 00 C6 44 24 68 01 C6 44 24 69 00 80 A4 24 C9 00 00 00 }
	condition:
		$pattern
}

rule __GI_authunix_create_default_ccebe5a2a876d0b1794e50542c6265bc {
	meta:
		aliases = "authunix_create_default, __GI_authunix_create_default"
		size = "170"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 18 01 00 00 6A 03 E8 ?? ?? ?? ?? 89 C3 83 C4 10 31 F6 85 C0 74 19 83 EC 0C 8D 04 85 00 00 00 00 50 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 74 3D 50 50 68 FF 00 00 00 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 40 74 26 C6 84 24 0B 01 00 00 00 E8 ?? ?? ?? ?? 89 C5 E8 ?? ?? ?? ?? 89 C7 50 50 56 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 05 E8 ?? ?? ?? ?? 83 EC 0C 56 83 F8 10 7E 05 B8 10 00 00 00 50 57 55 8D 44 24 28 50 E8 ?? ?? ?? ?? 89 C3 83 C4 14 56 E8 ?? ?? ?? ?? 89 D8 81 C4 1C 01 00 00 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_openpty_b528617ca1876ac5539191845b63a915 {
	meta:
		aliases = "openpty, __GI_openpty"
		size = "252"
		objfiles = "openpty@libutil.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 18 10 00 00 8B AC 24 38 10 00 00 6A 02 E8 ?? ?? ?? ?? 89 C6 83 C4 10 83 C8 FF 83 FE FF 0F 84 C8 00 00 00 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 A5 00 00 00 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 91 00 00 00 57 68 00 10 00 00 8D 7C 24 14 57 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 79 53 53 68 02 01 00 00 57 E8 ?? ?? ?? ?? 89 C3 83 C4 10 83 F8 FF 74 62 85 ED 74 0D 51 55 6A 02 50 E8 ?? ?? ?? ?? 83 C4 10 83 BC 24 30 10 00 00 00 74 16 52 FF B4 24 34 10 00 00 68 14 54 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 8B 84 24 20 10 00 00 89 30 8B 84 24 24 10 00 00 89 18 31 C0 83 BC 24 }
	condition:
		$pattern
}

rule __GI_clnt_sperror_912a6e8105fe071d038c2510d148f2a4 {
	meta:
		aliases = "clnt_sperror, __GI_clnt_sperror"
		size = "371"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 1C 04 00 00 8B 9C 24 30 04 00 00 E8 ?? ?? ?? ?? 89 C5 31 C0 85 ED 0F 84 46 01 00 00 50 50 8B 53 04 8D 84 24 18 04 00 00 50 53 FF 52 08 83 C4 0C FF B4 24 38 04 00 00 68 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 8D 5C 05 00 FF B4 24 20 04 00 00 E8 ?? ?? ?? ?? 83 C4 0C 50 53 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 8D 34 03 83 BC 24 10 04 00 00 11 0F 87 C3 00 00 00 8B 84 24 10 04 00 00 FF 24 85 ?? ?? ?? ?? 50 68 00 04 00 00 8D 5C 24 18 53 FF B4 24 20 04 00 00 E8 ?? ?? ?? ?? 83 C4 0C 53 68 ?? ?? ?? ?? E9 A3 00 00 00 8B 94 24 14 04 00 00 31 C0 EB 19 39 14 C5 ?? ?? ?? ?? 75 0F 8B 3C C5 }
	condition:
		$pattern
}

rule realpath_60d4a4cdde7e611bcfb45159d1b8e0d0 {
	meta:
		aliases = "realpath"
		size = "605"
		objfiles = "realpath@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 1C 10 00 00 8B 9C 24 30 10 00 00 8B AC 24 34 10 00 00 85 DB 75 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 10 80 3B 00 75 12 E8 ?? ?? ?? ?? C7 00 02 00 00 00 31 ED E9 10 02 00 00 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 3D FD 0F 00 00 76 0D E8 ?? ?? ?? ?? C7 00 24 00 00 00 EB D9 8D BC 24 1B 10 00 00 29 C7 56 56 53 57 E8 ?? ?? ?? ?? 89 FB 83 C4 10 C7 44 24 08 00 00 00 00 85 ED 75 16 83 EC 0C 68 00 10 00 00 E8 ?? ?? ?? ?? 89 C5 89 44 24 18 83 C4 10 8D 85 FE 0F 00 00 89 44 24 04 80 3F 2F 74 49 51 51 68 FF 0F 00 00 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 9B 00 00 00 83 EC 0C 55 E8 ?? ?? ?? }
	condition:
		$pattern
}

rule clnt_broadcast_dd441ea36b51bcb89b7f38d78321e8b5 {
	meta:
		aliases = "clnt_broadcast"
		size = "1470"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 1C 29 00 00 E8 ?? ?? ?? ?? 89 44 24 04 C7 84 24 14 29 00 00 01 00 00 00 56 6A 11 6A 02 6A 02 E8 ?? ?? ?? ?? 89 C5 83 C4 10 85 C0 79 0D 83 EC 0C 68 ?? ?? ?? ?? E9 66 03 00 00 83 EC 0C 6A 04 8D 84 24 24 29 00 00 50 6A 06 6A 01 55 E8 ?? ?? ?? ?? 83 C4 20 85 C0 79 0D 83 EC 0C 68 ?? ?? ?? ?? E9 3B 03 00 00 89 AC 24 08 29 00 00 66 C7 84 24 0C 29 00 00 01 00 C7 84 24 00 29 00 00 60 22 00 00 8D 44 24 28 89 84 24 04 29 00 00 8D 84 24 00 29 00 00 53 50 68 12 89 00 00 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 1D 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 44 24 1C 00 00 00 00 83 C4 10 E9 EF 00 }
	condition:
		$pattern
}

rule ether_ntohost_57ce92e71cf3c28dd2bc7d638c019f50 {
	meta:
		aliases = "ether_ntohost"
		size = "158"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 24 01 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 83 C4 10 83 CB FF 85 C0 74 6C EB 3C 89 FA 89 E8 E8 ?? ?? ?? ?? 89 C3 85 C0 74 38 50 6A 06 57 FF B4 24 40 01 00 00 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 21 57 57 53 FF B4 24 3C 01 00 00 E8 ?? ?? ?? ?? 31 DB 83 C4 10 EB 22 8D 6C 24 16 8D BC 24 16 01 00 00 51 56 68 00 01 00 00 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 A5 83 CB FF 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 89 D8 81 C4 1C 01 00 00 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule statvfs_14a134c6ede9eda4bd056120bb9040a7 {
	meta:
		aliases = "fstatvfs, __GI_statvfs, statvfs"
		size = "697"
		objfiles = "fstatvfs@libc.a, statvfs@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 24 05 00 00 8B 9C 24 38 05 00 00 8B B4 24 3C 05 00 00 8D 84 24 C8 04 00 00 50 53 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 0F 88 78 02 00 00 8B 84 24 C4 04 00 00 89 06 89 46 04 8B 84 24 C8 04 00 00 89 46 08 8B 84 24 CC 04 00 00 89 46 0C 8B 84 24 D0 04 00 00 89 46 10 8B 84 24 D4 04 00 00 89 46 14 8B 84 24 D8 04 00 00 89 46 18 8B 84 24 DC 04 00 00 89 46 20 C7 46 24 00 00 00 00 8B 84 24 E4 04 00 00 89 46 2C 50 6A 18 6A 00 8D 46 30 50 E8 ?? ?? ?? ?? 8B 46 18 89 46 1C C7 46 28 00 00 00 00 5F 5D 8D 84 24 70 04 00 00 50 53 E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 0F 88 E7 01 00 00 E8 ?? ?? }
	condition:
		$pattern
}

rule __getgrouplist_internal_98aa229d53c759055fbe695600e68a27 {
	meta:
		aliases = "__getgrouplist_internal"
		size = "279"
		objfiles = "__getgrouplist_internal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 28 01 00 00 8B 84 24 44 01 00 00 C7 00 01 00 00 00 6A 20 E8 ?? ?? ?? ?? 83 C4 10 31 ED 85 C0 0F 84 DF 00 00 00 89 C5 8B 84 24 34 01 00 00 89 45 00 51 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 C0 0F 84 B5 00 00 00 C7 40 34 01 00 00 00 BF 01 00 00 00 EB 67 8B 84 24 34 01 00 00 39 84 24 14 01 00 00 74 57 8B 9C 24 18 01 00 00 EB 48 52 52 FF B4 24 38 01 00 00 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 2F F7 C7 07 00 00 00 75 19 50 50 8D 04 BD 20 00 00 00 50 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 44 89 C5 8B 84 24 14 01 00 00 89 44 BD 00 47 EB 09 83 C3 04 8B 03 85 C0 }
	condition:
		$pattern
}

rule _dl_load_elf_shared_library_b33784a6dc0d2af763653fbabce10b9a {
	meta:
		aliases = "_dl_load_elf_shared_library"
		size = "2778"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 2C 01 00 00 31 C9 31 D2 8B BC 24 48 01 00 00 53 89 FB B8 05 00 00 00 CD 80 5B 89 44 24 34 3D 00 F0 FF FF 76 09 F7 D8 A3 ?? ?? ?? ?? EB 07 83 7C 24 34 00 79 0F C7 05 ?? ?? ?? ?? 01 00 00 00 E9 72 0A 00 00 8D 8C 24 E8 00 00 00 8B 54 24 34 87 D3 B8 6C 00 00 00 CD 80 87 D3 3D 00 F0 FF FF 76 09 F7 D8 A3 ?? ?? ?? ?? EB 04 85 C0 79 0C C7 05 ?? ?? ?? ?? 01 00 00 00 EB 14 83 BC 24 40 01 00 00 00 74 1E F6 84 24 F1 00 00 00 08 75 14 8B 7C 24 34 53 89 FB B8 06 00 00 00 CD 80 5B E9 06 08 00 00 8B 2D ?? ?? ?? ?? EB 44 0F B7 84 24 E8 00 00 00 31 D2 39 95 E0 00 00 00 75 2F 39 85 DC 00 00 00 }
	condition:
		$pattern
}

rule des_init_1e0a13c7761ad9d250d6bdaf67efebe8 {
	meta:
		aliases = "des_init"
		size = "976"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 30 02 00 00 83 3D ?? ?? ?? ?? 01 0F 84 AE 03 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 31 DB EB 3E 31 C9 89 DE C1 E6 06 8D 84 24 30 02 00 00 8D 3C 06 89 CA 83 E2 01 C1 E2 04 89 C8 D1 F8 83 E0 0F 09 C2 89 C8 83 E0 20 09 C2 8A 84 32 ?? ?? ?? ?? 88 84 39 00 FE FF FF 41 83 F9 3F 7E D4 43 83 FB 07 7E BD 31 ED EB 45 89 F2 C1 E2 06 09 DA 89 E9 C1 E1 0C 89 4C 24 08 8B 4C 24 0C 0F B6 81 00 FE FF FF C1 E0 04 8B 4C 24 10 0A 84 0B 00 FE FF FF 8B 4C 24 08 88 84 0A ?? ?? ?? ?? 43 83 FB 3F 7E C6 46 83 FE 3F }
	condition:
		$pattern
}

rule __GI___res_querydomain_305585d0ff231b37504734233ea100b3 {
	meta:
		aliases = "__res_querydomain, __GI___res_querydomain"
		size = "321"
		objfiles = "res_query@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 30 04 00 00 8B BC 24 44 04 00 00 8B AC 24 48 04 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 9C 24 28 04 00 00 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 58 5A 6A 01 53 E8 ?? ?? ?? ?? 83 C4 10 85 FF 74 17 83 BC 24 50 04 00 00 00 74 0D 83 E6 01 75 15 E8 ?? ?? ?? ?? 40 75 0D E8 ?? ?? ?? ?? C7 00 FF FF FF FF EB 27 85 ED 75 51 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 89 C2 8D 40 01 3D 01 04 00 00 76 13 E8 ?? ?? ?? ?? C7 00 03 00 00 00 83 C8 FF E9 91 00 00 00 85 D2 74 63 8D 72 FF 80 3C 37 2E 75 5A 53 56 57 8D 5C 24 27 53 E8 ?? ?? ?? ?? C6 44 34 2B 00 89 D8 83 C4 }
	condition:
		$pattern
}

rule vsyslog_d4bf0bca7279115b443547548ee9879d {
	meta:
		aliases = "__GI_vsyslog, vsyslog"
		size = "750"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 40 05 00 00 8B B4 24 54 05 00 00 68 8C 00 00 00 6A 00 8D 9C 24 A8 04 00 00 53 E8 ?? ?? ?? ?? C7 84 24 AC 04 00 00 ?? ?? ?? ?? 5D 8D 84 24 AC 04 00 00 50 E8 ?? ?? ?? ?? 83 C4 0C 8D 84 24 14 04 00 00 50 53 6A 0D E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 44 24 18 8B 28 83 C4 0C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 84 24 34 05 00 00 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 05 ?? ?? ?? ?? 89 F1 83 E1 07 D3 F8 83 C4 10 A8 01 0F 84 23 02 00 00 F7 C6 00 FC FF FF 0F 85 17 02 00 00 83 3D ?? ?? ?? ?? 00 78 09 80 3D ?? ?? ?? ?? 00 75 1D 57 6A 00 A0 ?? ?? ?? ?? 83 C8 08 0F B6 C0 50 }
	condition:
		$pattern
}

rule get_myaddress_1df4cf4d3cc92e913619b1216892ec55 {
	meta:
		aliases = "get_myaddress"
		size = "298"
		objfiles = "get_myaddress@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 40 10 00 00 6A 00 6A 02 6A 02 E8 ?? ?? ?? ?? 89 C7 83 C4 10 85 C0 79 0A 83 EC 0C 68 ?? ?? ?? ?? EB 39 C7 84 24 34 10 00 00 00 10 00 00 8D 44 24 14 89 84 24 38 10 00 00 8D 84 24 34 10 00 00 53 50 68 12 89 00 00 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 19 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 01 00 00 00 E8 ?? ?? ?? ?? 31 ED 8B 9C 24 38 10 00 00 8B B4 24 34 10 00 00 EB 7D 51 6A 20 53 8D 84 24 20 10 00 00 50 E8 ?? ?? ?? ?? 83 C4 0C 8D 84 24 18 10 00 00 50 68 13 89 00 00 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 0A 83 EC 0C 68 ?? ?? ?? ?? EB A5 0F BF 84 24 24 10 00 00 A8 01 74 33 }
	condition:
		$pattern
}

rule __get_myaddress_b1abc7f27c44f1fb4550e547ce09558c {
	meta:
		aliases = "__get_myaddress"
		size = "315"
		objfiles = "pmap_clnt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 40 10 00 00 89 44 24 0C 6A 00 6A 02 6A 02 E8 ?? ?? ?? ?? 89 C7 83 C4 10 85 C0 79 0A 83 EC 0C 68 ?? ?? ?? ?? EB 3E C7 84 24 34 10 00 00 00 10 00 00 8D 44 24 14 89 84 24 38 10 00 00 8D 84 24 34 10 00 00 53 50 68 12 89 00 00 57 E8 ?? ?? ?? ?? 83 C4 10 BD 01 00 00 00 85 C0 79 19 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 01 00 00 00 E8 ?? ?? ?? ?? 8B 9C 24 38 10 00 00 8B B4 24 34 10 00 00 E9 82 00 00 00 51 6A 20 53 8D 84 24 20 10 00 00 50 E8 ?? ?? ?? ?? 83 C4 0C 8D 84 24 18 10 00 00 50 68 13 89 00 00 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 0A 83 EC 0C 68 ?? ?? ?? ?? EB A4 0F BF }
	condition:
		$pattern
}

rule statvfs64_7af65a222d76ec8b45079c7ce8b5ffc3 {
	meta:
		aliases = "fstatvfs64, statvfs64"
		size = "753"
		objfiles = "fstatvfs64@libc.a, statvfs64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 44 05 00 00 8B 9C 24 58 05 00 00 8B B4 24 5C 05 00 00 8D 84 24 D4 04 00 00 50 53 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 0F 88 B0 02 00 00 8B 84 24 D0 04 00 00 89 06 89 46 04 8B 84 24 D4 04 00 00 8B 94 24 D8 04 00 00 89 46 08 89 56 0C 8B 84 24 DC 04 00 00 8B 94 24 E0 04 00 00 89 46 10 89 56 14 8B 84 24 E4 04 00 00 8B 94 24 E8 04 00 00 89 46 18 89 56 1C 8B 84 24 EC 04 00 00 8B 94 24 F0 04 00 00 89 46 20 89 56 24 8B 84 24 F4 04 00 00 8B 94 24 F8 04 00 00 89 46 28 89 56 2C 8B 84 24 FC 04 00 00 89 46 38 C7 46 3C 00 00 00 00 8B 84 24 04 05 00 00 89 46 44 50 6A 18 6A 00 8D 46 48 50 }
	condition:
		$pattern
}

rule __pthread_manager_5253844ecef1a95c578af3987f1e000a {
	meta:
		aliases = "__pthread_manager"
		size = "1647"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 58 01 00 00 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8D 9C 24 D0 00 00 00 53 E8 ?? ?? ?? ?? 5F 5D FF 35 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 59 5E 6A 05 53 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 15 A1 ?? ?? ?? ?? 85 C0 7E 0C 52 52 50 53 E8 ?? ?? ?? ?? 83 C4 10 50 6A 00 8D 84 24 CC 00 00 00 50 6A 02 E8 ?? ?? ?? ?? 5D A1 ?? ?? ?? ?? FF 70 18 E8 ?? ?? ?? ?? 83 C4 10 8D 5C 24 30 57 68 94 00 00 00 53 FF B4 24 6C 01 00 00 E8 ?? ?? ?? ?? 83 C4 10 40 75 0A E8 ?? ?? ?? ?? 83 38 04 74 DD 8B 84 24 60 01 00 00 89 84 24 44 01 00 00 66 C7 84 24 48 01 00 00 01 00 56 68 }
	condition:
		$pattern
}

rule _vfprintf_internal_1f31d691b06c3af483657235370846a2 {
	meta:
		aliases = "_vfprintf_internal"
		size = "1520"
		objfiles = "_vfprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 74 01 00 00 8B 9C 24 8C 01 00 00 53 8D 74 24 1C 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 3E 8B 5C 24 10 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 C7 04 24 FF FF FF FF 85 C0 0F 84 A0 05 00 00 52 FF B4 24 84 01 00 00 50 53 E8 ?? ?? ?? ?? C7 44 24 10 FF FF FF FF 83 C4 10 E9 81 05 00 00 50 50 FF B4 24 90 01 00 00 56 E8 ?? ?? ?? ?? 89 DA C7 44 24 10 00 00 00 00 83 C4 10 EB 01 43 8A 03 84 C0 74 04 3C 25 75 F5 39 D3 74 27 89 DE 29 D6 31 C0 85 F6 7E 12 50 FF B4 24 84 01 00 00 56 52 E8 ?? ?? ?? ?? 83 C4 10 39 F0 0F 85 29 05 00 00 01 04 24 80 3B 00 0F 84 24 05 00 00 8D 53 01 80 7B 01 25 0F 84 08 }
	condition:
		$pattern
}

rule rexec_af_d3efd48bbe9fa3b26e9631bc995b0978 {
	meta:
		aliases = "__GI_rexec_af, rexec_af"
		size = "1150"
		objfiles = "rexec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 7C 01 00 00 8B 84 24 94 01 00 00 0F B7 9C 24 A8 01 00 00 8B 94 24 98 01 00 00 89 14 24 8B 94 24 9C 01 00 00 89 54 24 04 66 C1 C8 08 0F B7 C0 50 68 ?? ?? ?? ?? 6A 20 8D BC 24 38 01 00 00 57 E8 ?? ?? ?? ?? C6 84 24 5B 01 00 00 00 83 C4 0C 6A 20 6A 00 8D B4 24 58 01 00 00 56 E8 ?? ?? ?? ?? 89 9C 24 60 01 00 00 C7 84 24 64 01 00 00 01 00 00 00 C7 84 24 5C 01 00 00 02 00 00 00 8D 84 24 84 01 00 00 50 56 57 8B 84 24 AC 01 00 00 FF 30 E8 ?? ?? ?? ?? 83 C4 20 83 CF FF 85 C0 0F 85 C8 03 00 00 8B 84 24 74 01 00 00 8B 40 18 85 C0 74 4E 57 68 01 04 00 00 50 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __kernel_rem_pio2_83015d4745f8b73f4830a4e1235419ee {
	meta:
		aliases = "__kernel_rem_pio2"
		size = "1485"
		objfiles = "k_rem_pio2@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 7C 02 00 00 8B 8C 24 98 02 00 00 8B 84 24 A0 02 00 00 8B 04 85 ?? ?? ?? ?? 89 44 24 24 8B 9C 24 9C 02 00 00 4B 89 5C 24 20 8D 51 FD BB 18 00 00 00 89 D0 99 F7 FB 89 44 24 2C F7 D0 C1 F8 1F 21 44 24 2C 8B 44 24 2C 40 6B C0 18 89 CE 29 C6 8B 44 24 2C 2B 44 24 20 8B 4C 24 24 03 4C 24 20 31 D2 EB 1B 85 C0 79 04 D9 EE EB 0A 8B 9C 24 A4 02 00 00 DB 04 83 DD 9C D4 80 01 00 00 42 40 39 CA 7E E1 31 C9 EB 23 89 D8 29 D0 8B BC 24 90 02 00 00 DD 04 D7 DC 8C C4 80 01 00 00 DE C1 42 3B 54 24 20 7E E2 DD 5C CC 40 41 3B 4C 24 24 7F 0D 31 D2 D9 EE 8B 6C 24 20 8D 1C 29 EB E2 8B 5C 24 24 C7 44 }
	condition:
		$pattern
}

rule universal_fd10b353559ff665695b1e097e1dd54c {
	meta:
		aliases = "universal"
		size = "345"
		objfiles = "svc_simple@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 7C 22 00 00 8B 84 24 90 22 00 00 8B AC 24 94 22 00 00 C7 84 24 78 22 00 00 00 00 00 00 8B 78 08 85 FF 75 2D 56 6A 00 68 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 0B 01 00 00 53 6A 04 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? E9 98 00 00 00 8B 30 E8 ?? ?? ?? ?? 8B 98 C0 00 00 00 E9 A6 00 00 00 39 73 04 0F 85 9A 00 00 00 39 7B 08 0F 85 91 00 00 00 51 68 60 22 00 00 6A 00 8D 74 24 24 56 E8 ?? ?? ?? ?? 83 C4 0C 8B 45 08 56 FF 73 0C 55 FF 50 08 83 C4 10 85 C0 75 0B 83 EC 0C 55 E8 ?? ?? ?? ?? EB 5A 83 EC 0C 56 FF 13 83 C4 10 85 C0 75 0D 81 7B 10 ?? ?? ?? ?? 0F 85 87 00 00 00 52 }
	condition:
		$pattern
}

rule byte_regex_compile_724c61495ac6fd132b418a113f775ca6 {
	meta:
		aliases = "byte_regex_compile"
		size = "8304"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 88 01 00 00 89 44 24 24 89 4C 24 20 8B BC 24 9C 01 00 00 89 84 24 84 01 00 00 01 C2 89 54 24 30 8B 47 14 89 44 24 34 68 80 02 00 00 E8 ?? ?? ?? ?? 89 44 24 70 83 C4 10 85 C0 0F 84 0A 20 00 00 8B 54 24 14 89 57 0C 80 67 1C 97 C7 47 08 00 00 00 00 C7 47 18 00 00 00 00 83 3D ?? ?? ?? ?? 00 75 46 51 68 00 01 00 00 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 D2 83 C4 10 EB 14 A1 ?? ?? ?? ?? F6 44 50 01 08 74 07 C6 82 ?? ?? ?? ?? 01 42 81 FA FF 00 00 00 7E E4 C6 05 ?? ?? ?? ?? 01 C7 05 ?? ?? ?? ?? 01 00 00 00 83 7F 04 00 75 43 8B 07 85 C0 74 0C 52 52 6A 20 50 E8 ?? ?? ?? ?? EB 0A 83 EC }
	condition:
		$pattern
}

rule svcunix_create_ce89801a24f5dd63342490449467d137 {
	meta:
		aliases = "svcunix_create"
		size = "408"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 8C 00 00 00 8B B4 24 A0 00 00 00 8B BC 24 AC 00 00 00 C7 84 24 88 00 00 00 10 00 00 00 31 ED 83 FE FF 75 2B 50 6A 00 6A 01 6A 01 E8 ?? ?? ?? ?? 89 C6 83 C4 10 66 BD 01 00 85 C0 79 12 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 EA 00 00 00 50 6A 6E 6A 00 8D 5C 24 26 53 E8 ?? ?? ?? ?? 66 C7 44 24 2A 01 00 89 3C 24 E8 ?? ?? ?? ?? 83 C4 0C 40 89 84 24 8C 00 00 00 50 57 8D 44 24 28 50 E8 ?? ?? ?? ?? 8B 84 24 98 00 00 00 83 C0 02 89 84 24 98 00 00 00 83 C4 0C 50 53 56 E8 ?? ?? ?? ?? 83 C4 0C 8D 84 24 8C 00 00 00 50 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 11 53 53 6A 02 56 E8 ?? ?? ?? }
	condition:
		$pattern
}

rule _fp_out_wide_92c57f57f8e2ec86753d88054c99ea55 {
	meta:
		aliases = "_fp_out_wide"
		size = "148"
		objfiles = "_vfwprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 8C 00 00 00 8B B4 24 A4 00 00 00 8B 9C 24 A8 00 00 00 31 ED 89 F0 84 C0 79 35 83 EC 0C FF B4 24 B8 00 00 00 E8 ?? ?? ?? ?? 83 C4 10 89 C7 29 C3 85 DB 7E 19 83 E6 7F 89 D9 89 F2 8B 84 24 A0 00 00 00 E8 ?? ?? ?? ?? 89 C5 39 D8 75 34 89 FB 85 DB 7E 2E 31 D2 8B 8C 24 AC 00 00 00 0F BE 04 11 89 44 94 14 42 39 DA 7C EC 50 FF B4 24 A4 00 00 00 53 8D 44 24 20 50 E8 ?? ?? ?? ?? 01 C5 83 C4 10 89 E8 81 C4 8C 00 00 00 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __uClibc_main_16606d1b4f21f9acca0dc06c65b83429 {
	meta:
		aliases = "__uClibc_main"
		size = "447"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 8C 00 00 00 8B BC 24 A8 00 00 00 8B AC 24 AC 00 00 00 8B 84 24 B8 00 00 00 A3 ?? ?? ?? ?? 8B 84 24 B4 00 00 00 A3 ?? ?? ?? ?? 8B 94 24 A4 00 00 00 C1 E2 02 8D 44 3A 04 A3 ?? ?? ?? ?? 3B 07 75 08 8D 04 17 A3 ?? ?? ?? ?? 51 6A 78 6A 00 8D 44 24 20 50 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 83 38 00 8D 40 04 75 F8 89 C3 8D 74 24 14 EB 1A 8B 03 83 F8 0E 77 10 52 6A 08 53 8D 04 C6 50 E8 ?? ?? ?? ?? 83 C4 10 83 C3 08 83 3B 00 75 E1 8D 44 24 14 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 48 85 C0 75 04 66 B8 00 10 A3 ?? ?? ?? ?? 83 7C 24 70 FF 75 20 E8 ?? ?? ?? ?? 89 C3 E8 ?? ?? ?? ?? 39 }
	condition:
		$pattern
}

rule __gen_tempname_c179259d49077b05f64772d94fca5164 {
	meta:
		aliases = "__gen_tempname"
		size = "645"
		objfiles = "tempname@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 8C 00 00 00 E8 ?? ?? ?? ?? 89 44 24 10 8B 00 89 44 24 1C 83 EC 0C FF B4 24 AC 00 00 00 E8 ?? ?? ?? ?? 83 C4 10 83 F8 05 76 30 8B 94 24 A0 00 00 00 8D 44 10 FA 89 44 24 14 52 52 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 0D C7 44 24 18 00 00 00 00 E9 FF 01 00 00 8B 4C 24 10 C7 01 16 00 00 00 E9 08 02 00 00 50 50 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C7 83 C4 10 85 C0 79 1A 50 50 68 00 08 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C7 83 C4 10 85 C0 78 27 55 6A 06 8D 9C 24 8A 00 00 00 53 57 E8 ?? ?? ?? ?? 89 C3 89 3C 24 E8 ?? ?? ?? ?? 83 C4 10 83 FB 06 0F 84 B1 00 00 00 56 }
	condition:
		$pattern
}

rule _vfwprintf_internal_aeed882c939fccb32d6584a771c3f2ea {
	meta:
		aliases = "_vfwprintf_internal"
		size = "1887"
		objfiles = "_vfwprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 90 02 00 00 8B B4 24 A8 02 00 00 68 BC 00 00 00 6A 00 8D 84 24 2C 01 00 00 50 E8 ?? ?? ?? ?? FF 8C 24 48 01 00 00 89 B4 24 30 01 00 00 C7 84 24 40 01 00 00 80 00 00 00 C7 84 24 90 02 00 00 00 00 00 00 89 B4 24 98 02 00 00 8D 84 24 90 02 00 00 50 6A FF 8D 84 24 A0 02 00 00 50 6A 00 E8 ?? ?? ?? ?? 83 C4 20 40 75 10 C7 84 24 20 01 00 00 ?? ?? ?? ?? E9 80 00 00 00 8D 94 24 48 01 00 00 B8 09 00 00 00 C7 02 08 00 00 00 83 C2 04 48 75 F4 89 F0 8D 9C 24 20 01 00 00 EB 30 83 FA 25 75 28 83 C0 04 83 38 25 74 20 89 84 24 20 01 00 00 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 39 8B 84 }
	condition:
		$pattern
}

rule getpass_3d54af48253d082d271c47afab765400 {
	meta:
		aliases = "getpass"
		size = "359"
		objfiles = "getpass@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 94 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 83 C4 10 89 C3 85 C0 75 0C 8B 35 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 83 EC 0C 56 E8 ?? ?? ?? ?? 5A 59 8D 7C 24 1C 57 50 E8 ?? ?? ?? ?? 83 C4 10 31 ED 85 C0 75 49 8D 44 24 50 55 6A 3C 57 50 E8 ?? ?? ?? ?? 83 64 24 30 F6 89 34 24 E8 ?? ?? ?? ?? 83 C4 0C 57 6A 02 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 94 C0 0F B6 E8 3B 35 ?? ?? ?? ?? 74 0F 6A 00 6A 02 6A 00 56 E8 ?? ?? ?? ?? 83 C4 10 51 51 53 FF B4 24 AC 00 00 00 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 0C 56 68 FF 00 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_sigaction_00ee9b1fbd45d68bffc43c7c446d53a5 {
	meta:
		aliases = "sigaction, __GI_sigaction"
		size = "223"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 9C 00 00 00 8B 9C 24 B0 00 00 00 8B BC 24 B4 00 00 00 8B AC 24 B8 00 00 00 3B 1D ?? ?? ?? ?? 0F 84 9E 00 00 00 3B 1D ?? ?? ?? ?? 0F 84 92 00 00 00 3B 1D ?? ?? ?? ?? 75 08 85 DB 0F 8F 82 00 00 00 31 C0 85 FF 74 45 8D 74 24 10 50 68 8C 00 00 00 57 56 E8 ?? ?? ?? ?? 83 C4 10 83 3F 01 76 28 85 DB 7E 24 83 FB 40 7F 1F F6 87 84 00 00 00 04 74 0A C7 44 24 10 ?? ?? ?? ?? EB 08 C7 44 24 10 ?? ?? ?? ?? 89 F0 EB 04 8D 44 24 10 56 55 50 53 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 40 74 2E 8D 43 FF 83 F8 3F 77 24 85 ED 74 0A 8B 04 9D ?? ?? ?? ?? 89 45 00 85 FF 74 12 8B 07 89 04 9D ?? ?? ?? ?? EB }
	condition:
		$pattern
}

rule rendezvous_request_9697bda86d57f4ff40b50e134653307c {
	meta:
		aliases = "rendezvous_request"
		size = "156"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 9C 00 00 00 8B B4 24 B0 00 00 00 8B 7E 2C 8D AC 24 98 00 00 00 C7 84 24 98 00 00 00 6E 00 00 00 50 55 8D 44 24 22 50 FF 36 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 79 0C E8 ?? ?? ?? ?? 83 38 04 75 48 EB D2 50 6A 10 6A 00 8D B4 24 94 00 00 00 56 E8 ?? ?? ?? ?? 66 C7 84 24 98 00 00 00 01 00 8B 4F 04 8B 17 89 D8 E8 ?? ?? ?? ?? 89 C3 83 C4 0C 6A 10 56 8D 40 10 50 E8 ?? ?? ?? ?? 8B 84 24 A8 00 00 00 89 43 0C 83 C4 10 31 C0 81 C4 9C 00 00 00 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule getnameinfo_61701ad9443834551ec0fcb7cb784236 {
	meta:
		aliases = "__GI_getnameinfo, getnameinfo"
		size = "862"
		objfiles = "getnameinfo@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC 9C 02 00 00 8B AC 24 B0 02 00 00 8B 9C 24 B4 02 00 00 E8 ?? ?? ?? ?? 89 04 24 8B 00 89 44 24 08 83 C8 FF F7 84 24 C8 02 00 00 E0 FF FF FF 0F 85 19 03 00 00 85 ED 0F 84 0C 03 00 00 83 FB 01 0F 86 03 03 00 00 66 8B 45 00 66 83 F8 01 74 1E 66 83 F8 02 75 05 83 FB 0F EB 0D 66 83 F8 0A 0F 85 E4 02 00 00 83 FB 1B 0F 86 DB 02 00 00 83 BC 24 B8 02 00 00 00 0F 95 44 24 05 83 BC 24 BC 02 00 00 00 0F 95 44 24 06 80 7C 24 05 00 0F 84 B9 01 00 00 80 7C 24 06 00 0F 84 AE 01 00 00 66 83 F8 02 74 13 66 83 F8 0A 74 0D 66 48 0F 85 9A 01 00 00 E9 2F 01 00 00 F6 84 24 C8 02 00 00 01 0F 85 C3 00 }
	condition:
		$pattern
}

rule _time_tzset_9893bec2a509a1c39cfbeec8abb64fa1 {
	meta:
		aliases = "_time_tzset"
		size = "953"
		objfiles = "tzset@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC A0 00 00 00 C7 84 24 9C 00 00 00 00 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 84 24 94 00 00 00 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 75 61 50 50 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C7 83 C4 10 85 C0 78 46 BE 44 00 00 00 8D 5C 24 14 50 56 53 57 E8 ?? ?? ?? ?? 83 C4 10 83 F8 00 7C 1E 74 06 01 C3 29 C6 75 E7 8D 44 24 14 39 C3 76 0E 80 7B FF 0A 75 08 C6 43 FF 00 89 C3 EB 02 31 DB 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 85 DB 74 06 8A 03 84 C0 75 2C C6 05 ?? ?? ?? ?? 00 50 6A 30 6A 00 68 ?? ?? ?? ?? E8 ?? ?? }
	condition:
		$pattern
}

rule sleep_ae719f65eab24bdf0878363c319fd0c0 {
	meta:
		aliases = "__GI_sleep, sleep"
		size = "393"
		objfiles = "sleep@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC AC 01 00 00 8B 8C 24 C0 01 00 00 31 C0 BA 20 00 00 00 85 C9 75 10 E9 5D 01 00 00 C7 84 94 24 01 00 00 00 00 00 00 4A 79 F2 C7 84 24 A8 01 00 00 00 00 00 00 89 8C 24 A4 01 00 00 50 50 6A 11 8D 9C 24 30 01 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 88 1E 01 00 00 50 8D B4 24 A8 00 00 00 56 53 6A 00 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 02 01 00 00 50 50 6A 11 56 E8 ?? ?? ?? ?? 83 C4 10 BA 20 00 00 00 85 C0 74 10 E9 B3 00 00 00 C7 84 94 24 01 00 00 00 00 00 00 4A 79 F2 50 50 6A 11 8D 84 24 30 01 00 00 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 88 BD 00 00 00 50 8D 44 24 1C 50 6A 00 6A 11 }
	condition:
		$pattern
}

rule sigwait_ec69a34ea5c01550a0cd01da544e8ee5 {
	meta:
		aliases = "sigwait"
		size = "355"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC BC 01 00 00 8B AC 24 D0 01 00 00 E8 ?? ?? ?? ?? 89 84 24 B8 01 00 00 83 EC 0C 8D 9C 24 44 01 00 00 53 E8 ?? ?? ?? ?? 58 5A FF 35 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? BE 01 00 00 00 83 C4 10 89 DF 8D 9C 24 AC 00 00 00 EB 74 50 50 56 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 63 3B 35 ?? ?? ?? ?? 74 5B 3B 35 ?? ?? ?? ?? 74 53 3B 35 ?? ?? ?? ?? 74 4B 50 50 56 57 E8 ?? ?? ?? ?? 83 C4 10 83 3C B5 ?? ?? ?? ?? 01 77 35 C7 84 24 AC 00 00 00 ?? ?? ?? ?? 83 EC 0C 8D 84 24 BC 00 00 00 50 E8 ?? ?? ?? ?? C7 84 24 40 01 00 00 00 00 00 00 83 C4 0C 6A 00 53 56 E8 ?? ?? ?? ?? 83 C4 10 46 83 FE 41 7E 87 50 }
	condition:
		$pattern
}

rule __open_nameservers_d99add3ea4774ef3cbcb8505f181afb3 {
	meta:
		aliases = "__open_nameservers"
		size = "585"
		objfiles = "opennameservers@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC C0 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 84 24 B8 00 00 00 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 3D ?? ?? ?? ?? 00 0F 8F F0 01 00 00 55 55 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C5 83 C4 10 85 C0 0F 85 98 01 00 00 57 57 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C5 83 C4 10 85 C0 0F 85 7A 01 00 00 E9 A4 01 00 00 43 8A 0B 84 C9 0F 84 6A 01 00 00 0F BE D1 A1 ?? ?? ?? ?? F6 04 50 20 75 E7 80 F9 0A 0F 84 53 01 00 00 C7 44 24 08 00 00 00 00 80 F9 23 75 50 E9 41 01 00 00 8B 44 24 08 89 9C 84 98 00 00 00 40 89 44 24 08 EB 01 43 8A 0B 84 }
	condition:
		$pattern
}

rule parse_printf_format_334516b961d4d9f7591d827b9748c4e2 {
	meta:
		aliases = "parse_printf_format"
		size = "234"
		objfiles = "parse_printf_format@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC D4 00 00 00 8B BC 24 E8 00 00 00 8B B4 24 EC 00 00 00 8B 9C 24 F0 00 00 00 57 8D 44 24 1C 50 E8 ?? ?? ?? ?? 83 C4 10 31 ED 85 C0 0F 88 A6 00 00 00 8B 44 24 28 85 C0 0F 8E 94 00 00 00 89 C5 89 F2 39 C6 76 02 89 C2 31 C9 EB 0A 8B 44 8C 38 89 03 83 C3 04 41 39 D1 72 F2 EB 7C 3C 25 75 71 47 80 3F 25 74 6B 89 7C 24 10 83 EC 0C 8D 44 24 1C 50 E8 ?? ?? ?? ?? 8B 7C 24 20 83 C4 10 81 7C 24 18 00 00 00 80 75 0F 45 85 F6 74 0A C7 03 00 00 00 00 83 C3 04 4E 81 7C 24 14 00 00 00 80 75 0F 45 85 F6 74 0A C7 03 00 00 00 00 83 C3 04 4E 31 D2 EB 15 8B 44 94 38 83 F8 08 74 0B 45 85 F6 74 06 89 }
	condition:
		$pattern
}

rule __psfs_do_numeric_1b225ce9b447eeaee874e8d521d65bc2 {
	meta:
		aliases = "__psfs_do_numeric"
		size = "1163"
		objfiles = "__psfs_do_numeric@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC DC 00 00 00 8B BC 24 F4 00 00 00 8B 84 24 F0 00 00 00 8B 40 3C 89 44 24 10 0F B6 A8 ?? ?? ?? ?? 48 75 63 BB ?? ?? ?? ?? 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 07 0F B6 03 3B 07 74 19 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 81 FB ?? ?? ?? ?? 76 33 E9 19 04 00 00 43 80 3B 00 75 CA 8B 94 24 F0 00 00 00 80 7A 44 00 0F 84 09 04 00 00 FF 42 34 6A 00 6A 00 FF 72 38 FF 72 2C E8 ?? ?? ?? ?? E9 D4 03 00 00 83 EC 0C 57 E8 ?? ?? ?? ?? 8B 17 83 C4 10 83 C8 FF 85 D2 0F 88 DB 03 00 00 83 FA 2B 74 09 8D 74 24 2D 83 FA 2D 75 14 88 54 24 2D 83 EC 0C 57 E8 ?? ?? ?? ?? 8D 74 24 3E 83 C4 10 F7 }
	condition:
		$pattern
}

rule _fpmaxtostr_c09cc4b6ee1c78a151a94ea6fb3b022a {
	meta:
		aliases = "_fpmaxtostr"
		size = "1472"
		objfiles = "_fpmaxtostr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC DC 00 00 00 DB AC 24 F4 00 00 00 8B 84 24 00 01 00 00 8B 40 04 89 44 24 18 8B 94 24 00 01 00 00 8B 2A 8A 4A 08 88 4C 24 21 C6 84 24 C2 00 00 00 65 88 C8 83 C8 20 3C 61 75 07 83 C1 06 88 4C 24 21 85 ED 79 05 BD 06 00 00 00 C6 84 24 D2 00 00 00 00 8B 94 24 00 01 00 00 8B 42 0C A8 02 74 0A C6 84 24 D2 00 00 00 2B EB 0C A8 01 74 08 C6 84 24 D2 00 00 00 20 C6 84 24 D3 00 00 00 00 C7 44 24 58 00 00 00 00 DD E0 DF E0 9E 7A 02 74 0C DD D8 C7 44 24 58 08 00 00 00 EB 61 D9 EE D9 C9 DD E1 DF E0 9E 75 2A 7A 28 D9 E8 D8 F1 D9 CA C7 44 24 14 FF FF FF FF DD EA DF E0 DD D9 9E 0F 86 08 01 00 }
	condition:
		$pattern
}

rule ttyname_r_a273ff26e896b29af598b023e8b5a27b {
	meta:
		aliases = "__GI_ttyname_r, ttyname_r"
		size = "393"
		objfiles = "ttyname@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC E4 00 00 00 8B 9C 24 F8 00 00 00 8D 44 24 6C 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 0C E8 ?? ?? ?? ?? 8B 18 E9 4D 01 00 00 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 BA ?? ?? ?? ?? 85 C0 0F 85 1E 01 00 00 E9 23 01 00 00 0F BE D8 8D 7A 01 50 50 57 8D 84 24 C8 00 00 00 50 E8 ?? ?? ?? ?? 8D 84 24 CC 00 00 00 01 D8 89 44 24 18 BD 1E 00 00 00 29 DD 89 3C 24 E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 C0 0F 85 B2 00 00 00 E9 CD 00 00 00 83 EC 0C 8D 58 0B 53 E8 ?? ?? ?? ?? 83 C4 10 39 E8 0F 87 96 00 00 00 50 50 53 FF 74 24 14 E8 ?? ?? ?? ?? 59 5B 8D 44 24 14 50 8D 84 24 C8 00 00 00 50 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __dns_lookup_bda052aa72c40c8ca221997511f52efa {
	meta:
		aliases = "__dns_lookup"
		size = "1901"
		objfiles = "dnslookup@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC E8 00 00 00 8B BC 24 10 01 00 00 68 00 02 00 00 E8 ?? ?? ?? ?? 89 C5 C7 04 24 01 04 00 00 E8 ?? ?? ?? ?? 89 44 24 1C 83 C4 10 85 ED 0F 84 6B 06 00 00 85 C0 0F 84 63 06 00 00 83 BC 24 F8 00 00 00 00 0F 84 55 06 00 00 8B 84 24 F0 00 00 00 80 38 00 0F 84 45 06 00 00 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 0C 8B 94 24 F4 00 00 00 80 7C 02 FF 2E 0F 94 44 24 37 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 9C 24 C4 00 00 00 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 99 F7 BC 24 08 01 00 00 89 54 24 38 0F B7 05 ?? ?? ?? ?? 89 44 24 48 58 5A 6A 01 53 E8 ?? ?? ?? ?? C7 44 24 24 }
	condition:
		$pattern
}

rule __GI_authunix_create_e9645da4b9e043748169d2ba0cabc1da {
	meta:
		aliases = "authunix_create, __GI_authunix_create"
		size = "377"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC E8 01 00 00 6A 28 E8 ?? ?? ?? ?? 89 C7 C7 04 24 B0 01 00 00 E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 FF 74 04 85 C0 75 29 50 50 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 3C 24 E8 ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 31 FF E9 17 01 00 00 C7 47 20 ?? ?? ?? ?? 89 47 24 8D 58 0C 55 6A 0C 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8D 47 0C 83 C4 0C 6A 0C 53 50 E8 ?? ?? ?? ?? C7 46 18 00 00 00 00 59 5B 6A 00 8D 84 24 E0 01 00 00 50 E8 ?? ?? ?? ?? 8B 84 24 E4 01 00 00 89 84 24 CC 01 00 00 8B 84 24 00 02 00 00 89 84 24 D0 01 00 00 8B 84 24 04 02 00 00 89 84 24 D4 01 00 00 8B 84 24 08 02 00 00 }
	condition:
		$pattern
}

rule __md5_crypt_a79f444093f8260cc3f713c1b8f67a0a {
	meta:
		aliases = "__md5_crypt"
		size = "733"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC F0 00 00 00 8B 9C 24 08 01 00 00 6A 03 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 89 5C 24 18 85 C0 75 07 83 C3 03 89 5C 24 18 8B 74 24 18 89 F2 83 C2 08 EB 01 46 8A 06 84 C0 74 08 3C 24 74 04 39 D6 72 F1 8D 9C 24 80 00 00 00 89 D8 E8 ?? ?? ?? ?? 83 EC 0C FF B4 24 0C 01 00 00 E8 ?? ?? ?? ?? 83 C4 10 89 C5 89 C1 8B 94 24 00 01 00 00 89 D8 E8 ?? ?? ?? ?? B9 03 00 00 00 BA ?? ?? ?? ?? 89 D8 E8 ?? ?? ?? ?? 2B 74 24 18 89 74 24 10 89 F1 8B 54 24 18 89 D8 E8 ?? ?? ?? ?? 8D 74 24 28 89 F0 E8 ?? ?? ?? ?? 89 E9 8B 94 24 00 01 00 00 89 F0 E8 ?? ?? ?? ?? 8B 4C 24 10 8B 54 24 18 89 F0 E8 }
	condition:
		$pattern
}

rule vfscanf_2df58c7296e4374ff6f05f2c709c79f9 {
	meta:
		aliases = "__GI_vfscanf, vfscanf"
		size = "1653"
		objfiles = "vfscanf@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC F0 01 00 00 C7 84 24 34 01 00 00 FF FF FF FF 6A 24 6A 00 8D 84 24 18 01 00 00 50 E8 ?? ?? ?? ?? 8B 84 24 10 02 00 00 8B 40 34 89 44 24 18 83 C4 10 85 C0 75 29 57 8B 9C 24 04 02 00 00 83 C3 38 53 68 ?? ?? ?? ?? 8D 84 24 E4 01 00 00 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 56 56 FF B4 24 08 02 00 00 8D 9C 24 A4 01 00 00 53 E8 ?? ?? ?? ?? C7 84 24 D4 01 00 00 ?? ?? ?? ?? 8B 84 24 B0 01 00 00 8A 40 03 88 84 24 C0 01 00 00 8B 84 24 D8 01 00 00 89 84 24 E4 01 00 00 C7 84 24 50 01 00 00 00 00 00 00 8B B4 24 14 02 00 00 C6 44 24 17 01 83 C4 10 89 DD E9 0B 05 00 00 C6 84 24 }
	condition:
		$pattern
}

rule __ieee754_pow_f75ce0b57ec7a9d92c3de3e74b67be9a {
	meta:
		aliases = "__ieee754_pow"
		size = "1933"
		objfiles = "e_pow@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 81 EC FC 00 00 00 DD 84 24 10 01 00 00 DD 5C 24 30 DD 84 24 18 01 00 00 DD 5C 24 28 DD 44 24 30 DD 9C 24 B0 00 00 00 8B AC 24 B4 00 00 00 8B 84 24 B0 00 00 00 89 84 24 D4 00 00 00 DD 44 24 28 DD 9C 24 A8 00 00 00 8B 84 24 AC 00 00 00 89 84 24 B8 00 00 00 89 C7 8B 94 24 A8 00 00 00 89 C3 81 E3 FF FF FF 7F 89 D9 09 D1 75 07 D9 E8 E9 FF 06 00 00 8B 84 24 B4 00 00 00 89 84 24 D0 00 00 00 89 EE 81 E6 FF FF FF 7F 81 FE 00 00 F0 7F 7F 22 0F 94 84 24 BF 00 00 00 75 0A 83 BC 24 D4 00 00 00 00 75 0E 81 FB 00 00 F0 7F 7F 06 75 11 85 D2 74 0D DD 44 24 28 DC 44 24 30 E9 B2 06 00 00 83 BC 24 D0 }
	condition:
		$pattern
}

rule getoffset_2cb884c9d4aace9ad43be39595c2a5c5 {
	meta:
		aliases = "getoffset"
		size = "107"
		objfiles = "tzset@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 89 C1 89 14 24 BD ?? ?? ?? ?? 31 FF 83 CE FF 45 8A 11 8D 42 D0 3C 09 77 07 0F BE C2 8D 70 D0 41 8A 19 8D 43 D0 3C 09 77 0B 6B D6 0A 0F BE C3 8D 74 02 D0 41 8A 55 00 0F BE C2 39 C6 72 04 31 C9 EB 1A 0F AF C7 8D 3C 06 31 F6 80 39 3A 75 04 41 83 CE FF FE CA 7F B8 8B 04 24 89 38 89 C8 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule inet_aton_6720a484cd356159a78db2ca9532dc95 {
	meta:
		aliases = "__GI_inet_aton, inet_aton"
		size = "148"
		objfiles = "inet_aton@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 4C 24 18 85 C9 74 7D 31 F6 C7 04 24 01 00 00 00 EB 51 8B 2D ?? ?? ?? ?? 0F BE 01 F6 44 45 00 08 74 62 31 FF EB 10 6B C7 0A 8D 7C 18 D0 81 FF FF 00 00 00 7F 4F 41 8A 11 0F BE DA 0F B7 44 5D 00 A8 08 75 E2 83 3C 24 04 74 08 80 FA 2E 75 35 41 EB 09 41 84 D2 74 04 A8 20 74 29 C1 E6 08 09 FE FF 04 24 83 3C 24 04 7E A9 B8 01 00 00 00 83 7C 24 1C 00 74 11 0F CE 8B 44 24 1C 89 30 B8 01 00 00 00 EB 02 31 C0 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_ether_aton_r_56897db1c0ca7c1a5a638e55c21ecf45 {
	meta:
		aliases = "ether_aton_r, __GI_ether_aton_r"
		size = "214"
		objfiles = "ether_addr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 4C 24 18 C7 04 24 00 00 00 00 E9 A1 00 00 00 8B 2D ?? ?? ?? ?? 0F BE 01 8A 54 45 00 8D 42 D0 3C 09 76 0B 8D 42 9F 3C 05 0F 87 8E 00 00 00 8B 35 ?? ?? ?? ?? 0F BE C2 8D 78 D0 F6 04 46 08 75 03 8D 78 A9 8D 59 01 0F BE 41 01 8A 54 45 00 83 3C 24 04 0F 96 C1 77 05 80 FA 3A 75 13 83 3C 24 05 75 3C 84 D2 74 38 0F BE C2 F6 04 46 20 75 2F 8D 42 D0 3C 09 76 07 8D 42 9F 3C 05 77 3F 0F BE C2 8D 50 D0 F6 04 46 08 75 03 8D 50 A9 43 84 C9 74 05 80 3B 3A 75 26 89 F8 C1 E0 04 8D 3C 02 89 F8 8B 54 24 1C 8B 0C 24 88 04 0A 8D 4B 01 FF 04 24 83 3C 24 05 0F 86 55 FF FF FF EB 08 C7 44 24 1C }
	condition:
		$pattern
}

rule _dl_linux_resolver_7f5b0032e236fe2f4794b639605eb6a1 {
	meta:
		aliases = "_dl_linux_resolver"
		size = "137"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 5C 24 18 8B 44 24 1C 03 83 9C 00 00 00 8B 50 04 C1 EA 08 8B 4B 58 C1 E2 04 8B 3C 0A 03 7B 54 8B 00 89 04 24 8B 2B 6A 01 53 FF 73 1C 57 E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 C0 75 37 FF 73 04 57 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? BF 01 00 00 00 53 89 FB B8 01 00 00 00 CD 80 5B 83 C4 14 3D 00 F0 FF FF 76 07 F7 D8 A3 ?? ?? ?? ?? 8B 04 24 89 74 05 00 89 F0 5F 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule strcasestr_e423ab6305e7e0b45dda86e461d450c3 {
	meta:
		aliases = "__GI_strcasestr, strcasestr"
		size = "83"
		objfiles = "strcasestr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 04 8B 7C 24 18 8B 6C 24 1C 89 FE 89 EB 8A 03 84 C0 75 04 89 F8 EB 30 8A 16 88 54 24 03 38 D0 74 16 8B 15 ?? ?? ?? ?? 0F B6 0B 0F B6 06 66 8B 04 42 66 3B 04 4A 75 04 43 46 EB D2 80 7C 24 03 00 74 03 47 EB C4 31 C0 5A 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule inet_network_4a3e0802d21cba540a87bee663f3c332 {
	meta:
		aliases = "__GI_inet_network, inet_network"
		size = "224"
		objfiles = "inet_net@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 8B 4C 24 1C C7 04 24 00 00 00 00 C7 44 24 04 00 00 00 00 80 39 30 74 09 31 F6 BD 0A 00 00 00 EB 1F 41 8A 01 3C 78 74 10 3C 58 74 0C BE 01 00 00 00 BD 08 00 00 00 EB 08 41 31 F6 BD 10 00 00 00 31 FF EB 51 0F B6 DA A1 ?? ?? ?? ?? 0F B7 04 58 A8 08 74 15 83 FD 08 75 05 80 FA 37 77 68 89 F8 0F AF C5 8D 7C 03 D0 EB 1E 83 FD 10 75 2D A8 10 74 29 83 E0 02 83 F8 01 19 D2 83 E2 E0 89 F8 C1 E0 04 29 D0 8D 78 A9 81 FF FF 00 00 00 77 37 41 BE 01 00 00 00 8A 11 84 D2 75 A9 85 F6 74 27 83 3C 24 00 74 05 C1 64 24 04 08 09 7C 24 04 80 FA 2E 75 0F FF 04 24 83 3C 24 04 74 0A 41 E9 51 FF FF }
	condition:
		$pattern
}

rule __GI_strstr_a1771bb7ea1f350a8b12b56d5a4efff5 {
	meta:
		aliases = "strstr, __GI_strstr"
		size = "197"
		objfiles = "strstr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 8B 54 24 20 8B 5C 24 1C 8A 02 0F B6 E8 84 C0 0F 84 9C 00 00 00 4B 43 8A 03 84 C0 0F 84 94 00 00 00 0F B6 C0 39 E8 75 EE 8D 42 01 89 44 24 04 8A 42 01 84 C0 74 7B 0F B6 C0 89 04 24 8D 53 01 0F B6 43 01 EB 27 8D 53 01 0F B6 43 01 EB 16 85 C0 74 63 42 8A 0A 0F B6 C1 39 E8 74 0C 84 C9 74 55 42 0F B6 02 39 E8 75 E6 42 0F B6 02 3B 04 24 75 F3 8B 7C 24 04 47 8D 72 01 8B 44 24 04 0F B6 48 01 8D 5A FF 0F B6 42 01 39 C8 75 21 85 C9 74 21 8A 47 01 0F B6 C8 38 46 01 75 12 84 C0 74 12 83 C6 02 83 C7 02 0F B6 0F 0F B6 06 EB DB 85 C9 75 94 89 D8 EB 02 31 C0 5A 59 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _dl_do_reloc_64d9a97e7f44215175208a151224c9e7 {
	meta:
		aliases = "_dl_do_reloc"
		size = "193"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 08 8B 6C 24 1C 8B 44 24 24 8B 55 00 89 14 24 8B 10 89 54 24 04 8B 40 04 0F B6 F0 C1 E8 08 89 C3 C1 E3 04 03 5C 24 28 8B 3B 31 C9 85 C0 74 3E 31 C0 83 FE 05 0F 94 C0 01 C0 31 D2 83 FE 07 0F 94 C2 09 D0 50 55 FF 74 24 28 8B 44 24 38 01 F8 50 E8 ?? ?? ?? ?? 89 C1 83 C4 10 85 C0 75 0F 8A 43 0C C0 E8 04 BA 01 00 00 00 3C 02 75 45 8B 54 24 04 03 14 24 83 FE 08 77 07 FF 24 B5 ?? ?? ?? ?? 83 CA FF EB 2D 29 D1 01 0A EB 25 89 0A EB 21 8B 45 00 01 02 EB 1A 85 C9 74 16 8B 73 08 8D 5A FF 8D 51 FF EB 07 43 42 8A 02 88 03 4E 85 F6 75 F5 31 D2 89 D0 5E 5F 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __pthread_lock_cf17df7653b05787dd5f8f9623c7708e {
	meta:
		aliases = "__pthread_lock"
		size = "143"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 89 C3 89 D7 83 38 00 74 04 31 ED EB 16 B9 01 00 00 00 31 D2 89 D0 F0 0F B1 0B 0F 94 C2 84 D2 74 E8 EB 5D 8B 33 F7 C6 01 00 00 00 75 0C 89 F1 83 C9 01 BA 01 00 00 00 EB 12 85 FF 75 07 E8 ?? ?? ?? ?? 89 C7 89 F9 83 C9 01 31 D2 85 FF 74 03 89 77 0C 89 F0 F0 0F B1 0B 0F 94 C1 84 C9 74 C4 85 D2 75 17 89 F8 E8 ?? ?? ?? ?? 83 7F 0C 00 74 B3 45 EB F0 89 F8 E8 ?? ?? ?? ?? 4D 83 FD FF 75 F3 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule do_dlclose_1b55203a4bb447f7955fd4384972a617 {
	meta:
		aliases = "do_dlclose"
		size = "555"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 89 C5 89 54 24 04 3B 05 ?? ?? ?? ?? 0F 84 08 02 00 00 A1 ?? ?? ?? ?? 31 D2 EB 09 39 E8 74 1A 89 C2 8B 40 04 85 C0 75 F3 C7 05 ?? ?? ?? ?? 09 00 00 00 B0 01 E9 E3 01 00 00 85 D2 8B 45 04 74 05 89 42 04 EB 05 A3 ?? ?? ?? ?? 8B 55 00 8B 42 20 C7 44 24 08 00 00 00 00 66 83 F8 01 0F 84 6E 01 00 00 48 66 89 42 20 83 EC 0C 55 E8 ?? ?? ?? ?? 31 C0 83 C4 10 E9 A2 01 00 00 8B 45 08 8B 54 24 08 8B 3C 90 8B 47 20 48 66 89 47 20 66 85 C0 0F 85 37 01 00 00 83 7F 74 00 75 09 83 BF A8 00 00 00 00 74 2D 83 7C 24 04 00 74 26 66 8B 47 22 A8 08 75 1E 83 C8 08 66 89 47 22 83 EC 0C 57 E8 ?? ?? }
	condition:
		$pattern
}

rule __md5_Update_630ac5472f9ef9210081fef5e3eb8bda {
	meta:
		aliases = "__md5_Update"
		size = "155"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 89 C6 89 54 24 08 89 CF 8B 40 10 89 C1 C1 E9 03 83 E1 3F 8D 14 FD 00 00 00 00 8D 04 02 89 46 10 39 D0 73 03 FF 46 14 89 F8 C1 E8 1D 01 46 14 BD 40 00 00 00 29 CD 31 DB 39 EF 72 3B 53 55 FF 74 24 10 8D 5E 18 8D 04 0B 50 E8 ?? ?? ?? ?? 89 DA 89 F0 E8 ?? ?? ?? ?? 89 EB 83 C4 10 EB 10 8B 54 24 08 01 DA 89 F0 E8 ?? ?? ?? ?? 83 C3 40 8D 43 3F 39 F8 72 E9 31 C9 52 29 DF 57 8B 44 24 10 01 D8 50 8D 44 31 18 50 E8 ?? ?? ?? ?? 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __copy_rpcent_0c4a3ed681aa5230b97b85e4d4e4dd6e {
	meta:
		aliases = "__copy_rpcent"
		size = "267"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 89 C6 89 D7 89 CB 8B 44 24 24 C7 00 00 00 00 00 B8 02 00 00 00 85 F6 0F 84 DF 00 00 00 50 6A 0C 6A 00 52 E8 ?? ?? ?? ?? 83 C4 0C FF 74 24 24 6A 00 53 E8 ?? ?? ?? ?? 8B 46 08 89 47 08 31 D2 83 C4 10 8B 46 04 8B 04 90 42 85 C0 75 F5 8D 04 95 00 00 00 00 39 44 24 20 0F 82 99 00 00 00 8D 6A FF 89 5F 04 01 C3 89 5C 24 08 8B 54 24 20 29 C2 89 54 24 04 EB 4B 8D 1C AD 00 00 00 00 83 EC 0C 8B 46 04 FF 34 18 E8 ?? ?? ?? ?? 83 C4 10 8D 50 01 39 54 24 04 72 60 8B 47 04 8B 4C 24 08 89 0C 18 01 D1 89 4C 24 08 29 54 24 04 50 52 8B 46 04 FF 34 18 8B 47 04 FF 34 18 E8 ?? ?? ?? ?? 83 C4 10 }
	condition:
		$pattern
}

rule get_input_bytes_7b1a4b62ff47c8fb52c5dbb0143f7cc2 {
	meta:
		aliases = "get_input_bytes"
		size = "82"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 89 C7 89 D5 89 CE EB 32 8B 57 2C 8B 47 30 29 D0 75 0D 89 F8 E8 ?? ?? ?? ?? 85 C0 75 1D EB 24 89 F3 39 C6 7E 02 89 C3 51 53 52 55 E8 ?? ?? ?? ?? 01 5F 2C 01 DD 29 DE 83 C4 10 85 F6 7F CA B8 01 00 00 00 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule rwlock_have_already_e8470d0401319f933af047d6bd5326d1 {
	meta:
		aliases = "rwlock_have_already"
		size = "175"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 89 C7 89 D6 89 CD 8B 18 83 7A 18 01 74 06 31 D2 31 F6 EB 7D 85 DB 75 07 E8 ?? ?? ?? ?? 89 C3 8B 93 C0 01 00 00 EB 07 39 72 04 74 08 8B 12 85 D2 75 F5 EB 04 85 D2 75 54 83 BB C8 01 00 00 00 7F 4B 8B 93 C4 01 00 00 85 D2 74 0A 8B 02 89 83 C4 01 00 00 EB 0F 83 EC 0C 6A 0C E8 ?? ?? ?? ?? 89 C2 83 C4 10 85 D2 74 18 C7 42 08 01 00 00 00 89 72 04 8B 83 C0 01 00 00 89 02 89 93 C0 01 00 00 31 F6 83 FA 01 19 C9 83 E1 01 EB 07 BE 01 00 00 00 31 C9 8B 44 24 20 89 08 89 55 00 89 1F 89 F0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __syscall_mq_timedsend_7e3e0d588680492f22941b7a9f671abc {
	meta:
		aliases = "__syscall_mq_timedsend"
		size = "62"
		objfiles = "mq_send@librt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 89 D3 89 CA 8B 74 24 20 8B 7C 24 24 89 D9 53 89 C3 B8 17 01 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __syscall_mq_timedreceive_5929a3f7e0d76d7d338accb2d778582f {
	meta:
		aliases = "__syscall_mq_timedreceive"
		size = "62"
		objfiles = "mq_receive@librt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 89 D3 89 CA 8B 74 24 20 8B 7C 24 24 89 D9 53 89 C3 B8 18 01 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 C8 FF 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __malloc_trim_b97d9975c959500d4a956488bbd16d0c {
	meta:
		aliases = "__malloc_trim"
		size = "141"
		objfiles = "free@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 89 D5 8B 8A 5C 03 00 00 8B 52 2C 8B 72 04 83 E6 FC 8D 5C 31 EF 29 C3 89 D8 31 D2 F7 F1 89 C3 4B 0F AF D9 85 DB 7E 55 83 EC 0C 6A 00 E8 ?? ?? ?? ?? 89 C7 89 F0 03 45 2C 83 C4 10 39 C7 75 3D 83 EC 0C F7 DB 53 E8 ?? ?? ?? ?? C7 04 24 00 00 00 00 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 74 1E 89 F9 29 C1 74 18 29 8D 68 03 00 00 8B 45 2C 29 CE 83 CE 01 89 70 04 B8 01 00 00 00 EB 02 31 C0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule getsubopt_5478d37d0d3e1a310cb4d2c4ac96aea2 {
	meta:
		aliases = "getsubopt"
		size = "206"
		objfiles = "getsubopt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 44 24 20 8B 38 C7 44 24 08 FF FF FF FF 80 3F 00 0F 84 A4 00 00 00 52 52 6A 2C 57 E8 ?? ?? ?? ?? 83 C4 0C 89 C3 29 F8 50 6A 3D 57 E8 ?? ?? ?? ?? 83 C4 10 89 DD 85 C0 74 02 89 C5 C7 44 24 08 00 00 00 00 89 EA 29 FA 89 54 24 04 EB 41 50 FF 74 24 08 56 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 2A 8B 44 24 04 80 3C 06 00 75 20 31 C0 39 DD 74 03 8D 45 01 8B 54 24 28 89 02 80 3B 00 74 04 C6 03 00 43 8B 44 24 20 89 18 EB 30 FF 44 24 08 8B 54 24 08 8B 44 24 24 8B 34 90 85 F6 75 B0 8B 54 24 28 89 3A 80 3B 00 74 04 C6 03 00 43 8B 44 24 20 89 18 C7 44 24 08 FF FF FF FF 8B 44 24 08 83 C4 }
	condition:
		$pattern
}

rule __regerror_97663fd4b2b36f16cb545a9f5e35cf97 {
	meta:
		aliases = "regerror, __regerror"
		size = "104"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 44 24 20 8B 6C 24 28 8B 7C 24 2C 83 F8 10 76 05 E8 ?? ?? ?? ?? 8B 1C 85 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 8D 70 01 85 FF 74 21 39 FE 76 11 50 8D 47 FF 50 53 55 E8 ?? ?? ?? ?? C6 00 00 EB 09 51 56 53 55 E8 ?? ?? ?? ?? 83 C4 10 89 F0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule shm_unlink_f5eeba5de78056b20049a393a2495706 {
	meta:
		aliases = "shm_unlink"
		size = "68"
		objfiles = "shm@librt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 44 24 20 E8 ?? ?? ?? ?? 89 C7 83 CD FF 85 C0 74 21 83 EC 0C 50 E8 ?? ?? ?? ?? 89 C5 E8 ?? ?? ?? ?? 89 C3 8B 30 89 3C 24 E8 ?? ?? ?? ?? 89 33 83 C4 10 89 E8 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI___ns_name_unpack_3dcb77db3a90707f3e9ac8954733d302 {
	meta:
		aliases = "__ns_name_unpack, __GI___ns_name_unpack"
		size = "264"
		objfiles = "ns_name@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 44 24 2C 8B 54 24 30 01 C2 89 54 24 04 8B 54 24 20 39 54 24 28 0F 82 A5 00 00 00 8B 54 24 24 39 54 24 28 0F 83 97 00 00 00 8B 7C 24 28 89 C3 C7 44 24 08 FF FF FF FF 31 ED 2B 54 24 20 89 14 24 E9 90 00 00 00 0F B6 F1 89 F0 25 C0 00 00 00 74 09 3D C0 00 00 00 75 68 EB 2A 8D 44 1E 01 3B 44 24 04 73 5C 8D 3C 32 3B 7C 24 24 73 53 8D 6C 35 01 88 0B 43 50 56 52 53 E8 ?? ?? ?? ?? 01 F3 83 C4 10 EB 51 3B 54 24 24 73 36 83 7C 24 08 00 79 09 2B 54 24 28 42 89 54 24 08 83 E6 3F C1 E6 08 0F B6 47 01 09 C6 8B 7C 24 20 01 F7 3B 7C 24 20 72 0E 3B 7C 24 24 73 08 83 C5 02 3B 2C 24 7C 15 }
	condition:
		$pattern
}

rule __pthread_unlock_b206eefc5b2273761e537d6635270b6b {
	meta:
		aliases = "__pthread_unlock"
		size = "158"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 4C 24 20 EB 0F 31 DB 89 D0 F0 0F B1 19 0F 94 C2 84 D2 75 78 8B 11 83 FA 01 74 EA 89 D7 83 E7 FE 89 F8 89 CD 89 CE C7 04 24 00 00 00 00 EB 16 8B 58 18 3B 1C 24 7C 05 89 EE 89 1C 24 8D 68 0C 8B 40 0C 83 E0 FE 85 C0 75 E6 39 CE 75 15 8B 5F 0C 83 E3 FE 89 D0 F0 0F B1 19 0F 94 C2 84 D2 74 B4 EB 1C 8B 3E 83 E7 FE 8B 47 0C 89 06 8B 01 89 C2 83 E2 FE F0 0F B1 11 0F 94 C2 84 D2 74 EE C7 47 0C 00 00 00 00 89 F8 E8 ?? ?? ?? ?? 31 C0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_memmem_1e6e262232a8bd9317e1f98749d481f7 {
	meta:
		aliases = "memmem, __GI_memmem"
		size = "94"
		objfiles = "memmem@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 4C 24 24 8B 54 24 2C 8B 5C 24 20 8D 34 0B 29 D6 89 D8 85 D2 74 38 39 D1 73 26 EB 30 8A 03 8B 54 24 28 3A 02 75 17 50 55 57 8D 43 01 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 04 89 D8 EB 11 43 EB 08 8D 6A FF 8B 7C 24 28 47 39 F3 76 D0 31 C0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _dl_fixup_cfca402b8da8d1cfdad81812c1d96192 {
	meta:
		aliases = "_dl_fixup"
		size = "286"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 54 24 20 8B 42 10 85 C0 74 19 51 51 FF 74 24 2C 50 E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 C0 0F 85 E9 00 00 00 8B 44 24 20 8B 18 66 8B 43 22 BE 01 00 00 00 83 7B 5C 00 0F 85 D0 00 00 00 8B AB 88 00 00 00 8B B3 84 00 00 00 85 F6 74 4E A8 01 75 4A 8B 8B C8 00 00 00 89 F0 85 C9 74 26 8D 14 CD 00 00 00 00 89 54 24 08 8B 3B 8D 56 F8 83 C2 08 89 F8 03 02 01 38 49 75 F4 2B 6C 24 08 8B 44 24 08 01 F0 52 55 50 FF 74 24 2C E8 ?? ?? ?? ?? 89 C6 66 83 4B 22 01 83 C4 10 EB 02 31 F6 83 BB A0 00 00 00 00 74 08 C7 44 24 24 02 00 00 00 83 BB 9C 00 00 00 00 74 56 F6 43 22 02 74 10 83 7C 24 24 }
	condition:
		$pattern
}

rule __decode_dotted_a3d2549222a731fe978e11cf13993939 {
	meta:
		aliases = "__decode_dotted"
		size = "217"
		objfiles = "decoded@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 54 24 24 83 7C 24 20 00 0F 84 B8 00 00 00 C6 44 24 0B 01 31 ED 31 C9 E9 8F 00 00 00 80 7C 24 0B 01 83 DD FF 0F B6 D8 8D 72 01 89 D8 25 C0 00 00 00 3D C0 00 00 00 75 23 80 7C 24 0B 01 83 DD FF 89 DA 83 E2 3F C1 E2 08 8B 5C 24 20 0F B6 04 33 09 C2 89 CF C6 44 24 0B 00 EB 4E 8D 04 0B 89 44 24 04 89 C7 47 3B 7C 24 2C 73 5B 50 53 8B 44 24 28 01 F0 50 8B 44 24 34 01 C8 50 E8 ?? ?? ?? ?? 8D 14 33 83 C4 10 80 7C 24 0B 00 74 02 01 DD 8B 4C 24 20 80 3C 11 01 19 C0 F7 D0 83 E0 2E 8B 5C 24 28 8B 4C 24 04 88 04 0B 89 F9 8B 5C 24 20 8A 04 13 84 C0 0F 85 62 FF FF FF 80 7C 24 0B 01 89 }
	condition:
		$pattern
}

rule __stdio_adjust_position_5eefeb23331aa986eb6af96dc41f997d {
	meta:
		aliases = "__stdio_adjust_position"
		size = "159"
		objfiles = "_adjust_pos@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 5C 24 20 8B 33 0F B7 C6 31 D2 89 C1 83 E1 03 74 27 89 CA 4A 74 22 F6 C4 08 74 1D 83 FA 02 74 6A 83 7B 28 00 75 64 0F B6 53 03 F7 DA 83 7B 2C 00 7E 06 0F B6 43 02 29 C2 66 F7 C6 40 00 74 05 8B 43 08 EB 03 8B 43 14 2B 53 10 8D 34 02 8B 44 24 24 8B 08 8B 58 04 89 F0 99 89 CF 89 DD 29 F7 19 D5 89 EA 8B 6C 24 24 89 7D 00 89 55 04 39 DA 7C 08 7F 04 39 CF 76 02 F7 DE 85 F6 79 10 E8 ?? ?? ?? ?? C7 00 4B 00 00 00 EB 03 83 CE FF 89 F0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _obstack_begin_1_1dedcb78dc4e817c341ae276b89f2b82 {
	meta:
		aliases = "_obstack_begin_1"
		size = "150"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 5C 24 20 8B 54 24 24 8B 74 24 28 8B 4C 24 2C 8B 6C 24 34 85 F6 75 04 66 BE 04 00 85 D2 75 04 66 BA E0 0F 89 4B 1C 8B 44 24 30 89 43 20 89 13 8D 7E FF 89 7B 18 89 6B 24 80 4B 28 01 F6 43 28 01 74 06 50 50 52 55 EB 04 83 EC 0C 52 FF D1 89 C2 83 C4 10 89 43 04 85 C0 75 05 E8 ?? ?? ?? ?? 8D 44 38 08 F7 DE 21 F0 89 43 08 89 43 0C 89 D0 03 03 89 02 89 43 10 C7 42 04 00 00 00 00 80 63 28 F9 B8 01 00 00 00 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule sgetspent_r_e28c114c6f91c7dc0910a1a228c34307 {
	meta:
		aliases = "__GI_sgetspent_r, sgetspent_r"
		size = "122"
		objfiles = "sgetspent_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 5C 24 20 8B 74 24 28 8B 7C 24 2C 8B 6C 24 30 C7 45 00 00 00 00 00 81 FF FF 00 00 00 77 12 E8 ?? ?? ?? ?? C7 00 22 00 00 00 B8 22 00 00 00 EB 3A 39 F3 74 1C 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 39 F8 73 DA 52 52 53 56 E8 ?? ?? ?? ?? 83 C4 10 50 50 56 FF 74 24 30 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 07 8B 54 24 24 89 55 00 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule shm_open_032471a4fa72903bc5323cff6da54dd9 {
	meta:
		aliases = "shm_open"
		size = "81"
		objfiles = "shm@librt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 5C 24 24 8B 44 24 20 E8 ?? ?? ?? ?? 89 C7 83 CD FF 85 C0 74 2A 51 FF 74 24 2C 81 CB 00 00 08 00 53 50 E8 ?? ?? ?? ?? 89 C5 E8 ?? ?? ?? ?? 89 C3 8B 30 89 3C 24 E8 ?? ?? ?? ?? 89 33 83 C4 10 89 E8 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_setstate_r_7fe532f1fafe94a9f188bdc094d3a9b6 {
	meta:
		aliases = "setstate_r, __GI_setstate_r"
		size = "155"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 5C 24 24 8B 74 24 20 83 C6 04 8B 4B 0C 8B 53 08 85 C9 75 09 C7 42 FC 00 00 00 00 EB 10 8B 43 04 29 D0 C1 F8 02 8D 04 80 01 C8 89 42 FC 8B 46 FC BF 05 00 00 00 99 F7 FF 83 FA 04 77 40 8B 0C 95 ?? ?? ?? ?? 89 4B 10 8B 2C 95 ?? ?? ?? ?? 89 6B 14 89 53 0C 85 D2 74 18 8B 46 FC 99 F7 FF 8D 14 86 89 53 04 8D 44 05 00 99 F7 F9 8D 14 96 89 13 89 73 08 8D 04 8E 89 43 18 31 C0 EB 0E E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule lldiv_9298bd8bc0f445e766b29010be65a043 {
	meta:
		aliases = "imaxdiv, lldiv"
		size = "112"
		objfiles = "lldiv@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 5C 24 24 8B 74 24 28 8B 44 24 2C 8B 54 24 30 89 04 24 89 54 24 04 52 50 56 53 E8 ?? ?? ?? ?? 83 C4 10 89 C7 89 D5 FF 74 24 04 FF 74 24 04 56 53 E8 ?? ?? ?? ?? 83 C4 10 85 F6 78 11 85 D2 79 0D 83 C7 01 83 D5 00 2B 04 24 1B 54 24 04 8B 4C 24 20 89 41 08 89 51 0C 89 39 89 69 04 89 C8 83 C4 0C 5B 5E 5F 5D C2 04 00 }
	condition:
		$pattern
}

rule fread_unlocked_067617f7895c4c208ddd5471e54fd699 {
	meta:
		aliases = "__GI_fread_unlocked, fread_unlocked"
		size = "275"
		objfiles = "fread_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 5C 24 28 8B 6C 24 2C 0F B7 45 00 25 83 00 00 00 3D 80 00 00 00 77 18 56 56 68 80 00 00 00 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 D2 00 00 00 83 7C 24 24 00 0F 84 C7 00 00 00 85 DB 0F 84 BF 00 00 00 83 C8 FF 31 D2 F7 74 24 24 39 C3 0F 87 9E 00 00 00 8B 7C 24 20 0F AF 5C 24 24 89 5C 24 08 89 DE EB 1B 83 E0 01 8B 44 85 24 88 07 8D 42 FF 66 89 45 00 C7 45 28 00 00 00 00 4E 74 63 47 8B 55 00 0F B7 C2 A8 02 75 DB 8B 55 10 8B 45 14 29 D0 74 1D 89 F3 39 C6 76 02 89 C3 51 53 52 57 E8 ?? ?? ?? ?? 01 5D 10 83 C4 10 29 DE 74 33 01 DF 0F B7 45 00 F6 C4 03 74 18 83 EC 0C 68 ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_svc_getreq_poll_1e54a2a6bfea763f6285d8c20bc9e84c {
	meta:
		aliases = "svc_getreq_poll, __GI_svc_getreq_poll"
		size = "102"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 6C 24 20 31 F6 31 FF EB 3E 8D 44 F5 00 8B 18 83 FB FF 74 32 66 8B 40 06 66 85 C0 74 29 47 A8 20 74 18 E8 ?? ?? ?? ?? 83 EC 0C 8B 80 B4 00 00 00 FF 34 98 E8 ?? ?? ?? ?? EB 09 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 46 E8 ?? ?? ?? ?? 3B 30 7D 06 3B 7C 24 24 7C B3 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_getenv_5dcfd56dc7e5924bf2fc330b1a43d2e5 {
	meta:
		aliases = "getenv, __GI_getenv"
		size = "83"
		objfiles = "getenv@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 6C 24 20 8B 35 ?? ?? ?? ?? 85 F6 74 34 83 EC 0C 55 E8 ?? ?? ?? ?? 83 C4 10 89 C7 EB 1E 50 57 53 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 0B 8D 04 3B 80 38 3D 75 03 40 EB 0B 83 C6 04 8B 1E 85 DB 75 DC 31 C0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule writetcp_3b16e4ff97d63d75e92e8df4ccf1c25c {
	meta:
		aliases = "writetcp"
		size = "73"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 6C 24 20 8B 74 24 24 8B 7C 24 28 89 FB EB 24 50 53 56 FF 75 00 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 0E 8B 45 2C C7 00 00 00 00 00 83 CF FF EB 08 29 C3 01 C6 85 DB 7F D8 89 F8 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule writetcp_d07a9285b66a7869262320cacf063828 {
	meta:
		aliases = "writetcp"
		size = "82"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 6C 24 20 8B 74 24 24 8B 7C 24 28 89 FB EB 2D 50 53 56 FF 75 00 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 75 16 E8 ?? ?? ?? ?? 8B 00 89 45 28 C7 45 24 03 00 00 00 83 CF FF EB 08 29 C3 01 C6 85 DB 7F CF 89 F8 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule writeunix_b1fb4f53d2efecae9681f153ce169e7d {
	meta:
		aliases = "writeunix"
		size = "86"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 6C 24 20 8B 74 24 24 8B 7C 24 28 89 FB EB 31 89 D9 89 F2 8B 45 00 E8 ?? ?? ?? ?? 83 F8 FF 75 1C E8 ?? ?? ?? ?? 8B 00 89 85 88 00 00 00 C7 85 84 00 00 00 03 00 00 00 83 CF FF EB 08 29 C3 01 C6 85 DB 7F CB 89 F8 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _stdlib_wcsto_l_c72a02cecb7f944cde40dbb0f707f7c2 {
	meta:
		aliases = "_stdlib_wcsto_l"
		size = "314"
		objfiles = "_stdlib_wcsto_l@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 6C 24 20 8B 74 24 28 89 EB EB 03 83 C3 04 83 EC 0C FF 33 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 EC 8B 03 83 F8 2B 74 11 C6 44 24 0A 00 83 F8 2D 75 0F C6 44 24 0A 01 EB 05 C6 44 24 0A 00 83 C3 04 89 EF F7 C6 EF FF FF FF 75 29 83 C6 0A 83 3B 30 75 17 83 C3 04 83 EE 02 8B 03 83 C8 20 89 DF 83 F8 78 75 05 01 F6 83 C3 04 83 FE 10 7E 05 BE 10 00 00 00 8D 46 FE 31 ED 83 F8 22 77 71 83 C8 FF 31 D2 F7 F6 89 44 24 04 88 54 24 0B EB 02 89 DF 8B 0B 8D 41 D0 8D 51 D0 83 F8 09 76 14 89 C8 83 C8 20 B2 28 83 F8 60 76 08 88 C8 83 C8 20 8D 50 A9 0F B6 C2 39 F0 7D 36 83 C3 04 3B 6C 24 04 77 08 }
	condition:
		$pattern
}

rule __drand48_iterate_674ef8a61e40f38992df8e2cdf3391b3 {
	meta:
		aliases = "__drand48_iterate"
		size = "161"
		objfiles = "drand48_iter@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 6C 24 20 8B 7C 24 24 66 83 7F 0E 00 75 1A C7 47 10 6D E6 EC DE C7 47 14 05 00 00 00 66 C7 47 0C 0B 00 66 C7 47 0E 01 00 0F B7 45 04 31 D2 89 C2 B8 00 00 00 00 0F B7 4D 00 31 DB 09 C8 09 DA 0F B7 4D 02 C1 E1 10 89 C6 09 CE 89 34 24 89 54 24 04 89 D6 0F AF 77 10 8B 0C 24 0F AF 4F 14 01 CE 8B 04 24 F7 67 10 89 C1 8D 1C 16 0F B7 47 0C 31 D2 01 C8 11 DA 66 89 45 00 0F AC D0 10 C1 EA 10 66 89 45 02 0F AC D0 10 C1 EA 10 66 89 45 04 31 C0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __stdio_fwrite_93b9b1c72301bf1737a7286927333820 {
	meta:
		aliases = "__stdio_fwrite"
		size = "240"
		objfiles = "_fwrite@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 6C 24 20 8B 7C 24 24 8B 5C 24 28 F6 43 01 02 0F 85 B1 00 00 00 83 7B 04 FE 8B 53 10 8B 43 0C 75 1E 29 D0 89 FE 39 C7 76 02 89 C6 50 56 55 52 E8 ?? ?? ?? ?? 01 73 10 83 C4 10 E9 9F 00 00 00 29 D0 39 C7 77 68 51 57 55 52 E8 ?? ?? ?? ?? 01 7B 10 83 C4 10 F6 43 01 01 0F 84 80 00 00 00 52 57 6A 0A 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 6F 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 5F 89 C6 39 F8 76 02 89 FE 89 F8 29 F0 01 C5 50 56 6A 0A 55 E8 ?? ?? ?? ?? 83 C4 10 89 C2 85 C0 74 3E 8D 44 35 00 29 D0 29 C7 29 43 10 EB 31 3B 53 08 74 14 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 }
	condition:
		$pattern
}

rule _dl_lookup_hash_225ff099d8cb3e56f507a4985d002b57 {
	meta:
		aliases = "_dl_lookup_hash"
		size = "251"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 6C 24 24 83 CF FF 8B 44 24 2C 83 E0 02 89 04 24 E9 B8 00 00 00 8B 75 00 F6 46 25 01 75 26 83 7C 24 28 00 74 1F 39 74 24 28 74 19 8B 54 24 28 8B 42 34 EB 07 39 70 04 74 0B 8B 00 85 C0 75 F5 E9 86 00 00 00 83 3C 24 00 74 06 83 7E 18 01 74 7A 8B 5E 28 85 DB 74 73 8B 46 58 89 44 24 04 83 FF FF 75 27 8B 4C 24 20 31 FF EB 19 0F B6 D0 C1 E7 04 01 FA 41 89 D0 25 00 00 00 F0 89 C7 31 D7 C1 E8 18 31 C7 8A 01 84 C0 75 E1 8B 56 54 89 54 24 08 89 F8 31 D2 F7 F3 8B 46 2C 8B 1C 90 EB 27 89 D8 C1 E0 04 03 44 24 04 FF 74 24 2C 8B 4C 24 24 8B 54 24 0C E8 ?? ?? ?? ?? 89 C2 59 85 C0 75 17 }
	condition:
		$pattern
}

rule initstate_r_d5c15529cd3179840bd1704146fecc38 {
	meta:
		aliases = "__GI_initstate_r, initstate_r"
		size = "172"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 6C 24 24 8B 44 24 28 8B 7C 24 2C 83 F8 7F 76 0C 3D 00 01 00 00 19 DB 83 C3 04 EB 16 83 F8 1F 77 09 31 DB 83 F8 07 77 0A EB 59 83 F8 40 19 DB 83 C3 02 8B 04 9D ?? ?? ?? ?? 8B 14 9D ?? ?? ?? ?? 89 5F 0C 89 57 14 89 47 10 8D 75 04 8D 04 86 89 47 18 89 77 08 57 FF 74 24 24 E8 ?? ?? ?? ?? C7 45 00 00 00 00 00 59 58 31 C0 85 DB 74 2E 8B 47 04 29 F0 C1 F8 02 8D 04 80 8D 04 03 89 45 00 31 C0 EB 19 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule xdrrec_getbytes_ed661b89b3eb10604bbfe985210ec039 {
	meta:
		aliases = "xdrrec_getbytes"
		size = "101"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 6C 24 24 8B 7C 24 28 8B 44 24 20 8B 70 0C EB 38 8B 46 34 85 C0 75 13 83 7E 38 00 75 36 89 F0 E8 ?? ?? ?? ?? 85 C0 75 20 EB 29 89 FB 39 C7 76 02 89 C3 89 D9 89 EA 89 F0 E8 ?? ?? ?? ?? 85 C0 74 12 01 DD 29 5E 34 29 DF 85 FF 75 C4 B8 01 00 00 00 EB 02 31 C0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule xdrrec_putbytes_b7810e70de08776dc03b6f630fbd140b {
	meta:
		aliases = "xdrrec_putbytes"
		size = "110"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 6C 24 24 8B 7C 24 28 8B 44 24 20 8B 70 0C EB 45 8B 56 10 8B 46 14 29 D0 89 FB 39 C7 76 02 89 C3 50 53 55 52 E8 ?? ?? ?? ?? 89 D8 03 46 10 89 46 10 01 DD 29 DF 83 C4 10 3B 46 14 75 18 85 FF 74 18 C7 46 1C 01 00 00 00 31 D2 89 F0 E8 ?? ?? ?? ?? 85 C0 74 09 85 FF 75 B7 B8 01 00 00 00 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule pthread_cancel_722e154c7e9dc27934354b837cfab10a {
	meta:
		aliases = "pthread_cancel"
		size = "180"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 74 24 20 89 F0 25 FF 03 00 00 C1 E0 04 8D B8 ?? ?? ?? ?? 31 D2 89 F8 E8 ?? ?? ?? ?? 8B 5F 08 85 DB 74 05 39 73 10 74 70 83 EC 0C 57 E8 ?? ?? ?? ?? B8 03 00 00 00 EB 58 83 EC 0C 57 E8 ?? ?? ?? ?? EB 4B 8B 83 BC 01 00 00 8B 6B 14 31 F6 85 C0 74 13 52 52 53 FF 30 FF 50 04 89 C6 88 83 B8 01 00 00 83 C4 10 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 85 F6 74 0B 83 EC 0C 53 E8 ?? ?? ?? ?? EB 0E 50 50 FF 35 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 31 C0 83 C4 1C 5B 5E 5F 5D C3 0F BE 43 42 C6 43 42 01 80 7B 40 01 74 92 85 C0 75 8E EB 97 }
	condition:
		$pattern
}

rule __pthread_alt_unlock_bc2214c04fe3f26fcdf0ad6de0287e00 {
	meta:
		aliases = "__pthread_alt_unlock"
		size = "174"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 74 24 20 8B 16 83 FA 01 77 14 31 C9 89 D0 F0 0F B1 0E 0F 94 C2 84 D2 74 EA E9 80 00 00 00 89 D3 89 34 24 89 F5 89 D7 C7 44 24 04 00 00 00 80 EB 3A 83 7B 08 00 74 1B 89 D9 89 EA 89 F0 E8 ?? ?? ?? ?? 89 D8 E8 ?? ?? ?? ?? 8B 5D 00 39 F5 75 1B EB 19 8B 43 04 8B 40 18 3B 44 24 04 7C 09 89 2C 24 89 44 24 04 89 DF 89 DD 8B 1B 83 FB 01 75 C1 81 7C 24 04 00 00 00 80 74 89 89 D8 87 47 08 85 C0 75 80 89 F9 8B 14 24 89 F0 E8 ?? ?? ?? ?? 8B 47 04 83 C4 0C 5B 5E 5F 5D E9 ?? ?? ?? ?? 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_xprt_register_6592214a1f32102731fb429ef0b92af0 {
	meta:
		aliases = "xprt_register, __GI_xprt_register"
		size = "225"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 74 24 20 8B 2E E8 ?? ?? ?? ?? 89 C3 83 B8 B4 00 00 00 00 75 22 E8 ?? ?? ?? ?? 83 EC 0C C1 E0 02 50 E8 ?? ?? ?? ?? 89 83 B4 00 00 00 83 C4 10 85 C0 0F 84 9A 00 00 00 E8 ?? ?? ?? ?? 39 C5 0F 8D 8D 00 00 00 8B 83 B4 00 00 00 89 34 A8 81 FD FF 03 00 00 7F 13 E8 ?? ?? ?? ?? 89 E9 C1 E9 05 89 EA 83 E2 1F 0F AB 14 88 31 DB EB 23 E8 ?? ?? ?? ?? 8D 0C DD 00 00 00 00 89 CA 03 10 83 3A FF 75 0D 89 2A 8B 00 66 C7 44 08 04 C3 00 EB 43 43 E8 ?? ?? ?? ?? 89 C7 8B 00 39 C3 7C D0 8D 58 01 89 1F E8 ?? ?? ?? ?? 89 C6 50 50 C1 E3 03 53 FF 36 E8 ?? ?? ?? ?? 89 C2 89 06 83 C4 10 85 C0 74 11 }
	condition:
		$pattern
}

rule _obstack_newchunk_4b7b2ee9590c2c24fc0d5b3ce2a36067 {
	meta:
		aliases = "_obstack_newchunk"
		size = "266"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 74 24 20 8B 46 04 89 44 24 08 8B 6E 0C 2B 6E 08 8B 46 18 83 C0 64 01 E8 03 44 24 24 89 EA C1 FA 03 8B 0E 8D 3C 10 39 CF 7D 02 89 CF F6 46 28 01 8B 46 1C 74 08 51 51 57 FF 76 24 EB 04 83 EC 0C 57 FF D0 89 C3 83 C4 10 85 C0 75 05 E8 ?? ?? ?? ?? 89 46 04 8B 54 24 08 89 50 04 8D 04 38 89 46 10 89 03 8B 56 18 8D 7C 1A 08 89 D0 F7 D0 21 C7 31 C0 83 FA 02 7E 27 89 E9 C1 E9 02 89 4C 24 04 EB 10 8D 04 8D 00 00 00 00 8B 56 08 8B 14 02 89 14 07 49 85 C9 79 EB 8B 44 24 04 C1 E0 02 89 C2 EB 0A 8B 46 08 8A 04 10 88 04 17 42 39 EA 7C F2 F6 46 28 02 75 37 8B 46 18 8B 4C 24 08 8D 54 08 }
	condition:
		$pattern
}

rule __psfs_parse_spec_6d8e74d5f7e5b47e4cd3d8d29392b170 {
	meta:
		aliases = "__psfs_parse_spec"
		size = "444"
		objfiles = "__psfs_parse_spec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 74 24 20 8B 46 30 89 44 24 08 8A 00 83 E8 30 31 ED BF 01 00 00 00 3C 09 77 4B 81 FD CB CC CC 0C 7F 11 8B 46 30 0F B6 08 6B D5 0A 8D 6C 11 D0 40 89 46 30 8B 5E 30 8A 0B 8D 41 D0 3C 09 76 DB 80 F9 24 74 19 83 7E 24 00 0F 89 50 01 00 00 89 6E 40 C7 46 24 FE FF FF FF E9 99 00 00 00 8D 43 01 89 46 30 31 FF BB ?? ?? ?? ?? BA 10 00 00 00 8B 4E 30 8A 03 3A 01 75 0B 8D 41 01 89 46 30 08 56 45 EB E2 43 80 3B 00 74 04 01 D2 EB E2 F6 46 45 10 74 08 C6 46 44 00 31 D2 EB 4F 89 F8 84 C0 74 13 83 7E 24 00 0F 89 F3 00 00 00 C7 46 24 FE FF FF FF EB E3 83 7E 24 FE 0F 84 E0 00 00 00 8D 45 }
	condition:
		$pattern
}

rule getcwd_f00839558b75565af1b91f756c7a074d {
	meta:
		aliases = "__GI_getcwd, getcwd"
		size = "185"
		objfiles = "getcwd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 74 24 20 8B 6C 24 24 85 ED 75 29 85 F6 74 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 86 00 00 00 E8 ?? ?? ?? ?? 89 C3 3D 00 10 00 00 7D 0F BB 00 10 00 00 EB 08 89 EB 89 F7 85 F6 75 12 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 59 89 C7 89 F8 89 D9 53 89 C3 B8 B7 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0B E8 ?? ?? ?? ?? F7 DB 89 18 EB 22 85 C0 78 1E 85 F6 75 2E 85 ED 75 12 50 50 53 57 E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 C0 75 18 89 FE EB 14 85 F6 75 0E 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 EB 02 31 F6 89 F0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_wcsncasecmp_bd82365cf700823633454fc2c069f858 {
	meta:
		aliases = "wcsncasecmp, __GI_wcsncasecmp"
		size = "111"
		objfiles = "wcsncasecmp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 74 24 20 8B 7C 24 24 8B 6C 24 28 EB 0C 83 3E 00 74 0B 83 C6 04 83 C7 04 4D 85 ED 75 04 31 C0 EB 3E 8B 06 3B 07 74 E6 83 EC 0C 50 E8 ?? ?? ?? ?? 89 C3 5A FF 37 E8 ?? ?? ?? ?? 83 C4 10 39 C3 74 CC 83 EC 0C FF 36 E8 ?? ?? ?? ?? 89 C3 58 FF 37 E8 ?? ?? ?? ?? 83 C4 10 39 C3 19 C0 83 C8 01 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule qsort_bafae48377ebde27aabe139d7785f25b {
	meta:
		aliases = "__GI_qsort, qsort"
		size = "177"
		objfiles = "qsort@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 74 24 24 83 FE 01 0F 86 95 00 00 00 83 7C 24 28 00 0F 84 8A 00 00 00 31 C9 8D 5E FF 8D 04 49 8D 48 01 BA 03 00 00 00 89 D8 89 D5 31 D2 F7 F5 39 C1 72 E9 8B 5C 24 28 0F AF D9 0F AF 74 24 28 89 74 24 08 89 5C 24 04 8B 6C 24 04 29 DD 8B 74 24 20 01 EE 8D 3C 1E 50 50 57 56 FF 54 24 3C 83 C4 10 85 C0 7E 15 8B 4C 24 28 8A 16 8A 07 88 06 46 88 17 47 49 75 F3 39 DD 73 D1 8B 44 24 28 01 44 24 04 8B 74 24 08 39 74 24 04 72 BB 29 C3 BA 03 00 00 00 89 D8 89 D6 31 D2 F7 F6 89 C3 85 C0 75 A2 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _fp_out_narrow_2a2495f01e006b6a947d6258f9c74c52 {
	meta:
		aliases = "_fp_out_narrow"
		size = "106"
		objfiles = "_vfprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 74 24 24 8B 5C 24 28 31 ED 89 F0 84 C0 79 2F 83 EC 0C FF 74 24 38 E8 ?? ?? ?? ?? 83 C4 10 89 C7 29 C3 85 DB 7E 16 83 E6 7F 89 D9 89 F2 8B 44 24 20 E8 ?? ?? ?? ?? 89 C5 39 D8 75 1C 89 FB 31 C0 85 DB 7E 12 52 FF 74 24 24 53 FF 74 24 38 E8 ?? ?? ?? ?? 83 C4 10 01 C5 89 E8 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule bsearch_c6b69b97678cdb6a5649ddbecb00bde5 {
	meta:
		aliases = "bsearch"
		size = "90"
		objfiles = "bsearch@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 74 24 28 31 ED 83 7C 24 2C 00 75 38 EB 3A 89 F0 29 E8 D1 E8 8D 1C 28 8B 44 24 2C 0F AF C3 8B 7C 24 24 01 C7 50 50 57 FF 74 24 2C FF 54 24 40 83 C4 10 83 F8 00 7E 05 8D 6B 01 EB 08 75 04 89 F8 EB 08 89 DE 39 F5 72 C6 31 C0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __encode_dotted_f7f3043489fcf419dbaf67c9853ab6f1 {
	meta:
		aliases = "__encode_dotted"
		size = "145"
		objfiles = "encoded@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 7C 24 20 31 DB EB 5A 52 52 6A 2E 57 E8 ?? ?? ?? ?? 83 C4 10 89 C5 85 C0 74 06 89 C6 29 FE EB 0E 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 F6 74 4C 8B 44 24 28 29 D8 48 39 C6 73 41 89 F0 8B 54 24 24 88 04 1A 43 50 56 57 89 D0 01 D8 50 E8 ?? ?? ?? ?? 8D 1C 1E 83 C4 10 85 ED 74 0C 8D 7D 01 85 FF 74 05 80 3F 00 75 9D 83 7C 24 28 00 7E 0D 8B 44 24 24 C6 04 18 00 8D 43 01 EB 03 83 C8 FF 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __getdents_a53c125db245399631e82bb497eb8ccd {
	meta:
		aliases = "__getdents"
		size = "134"
		objfiles = "getdents@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 7C 24 20 8B 4C 24 24 8B 54 24 28 53 89 FB B8 8D 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF EB 47 83 F8 FF 74 42 89 CF 8D 2C 01 EB 37 0F B7 47 08 8A 44 07 FF 88 44 24 0B 83 EC 0C 8D 5F 0A 53 E8 ?? ?? ?? ?? 83 C4 0C 40 50 53 8D 47 0B 50 E8 ?? ?? ?? ?? 8A 44 24 1B 88 47 0A 0F B7 47 08 01 C7 83 C4 10 39 EF 72 C5 89 F0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_pthread_setschedparam_a049620420c968e09762111958489202 {
	meta:
		aliases = "pthread_setschedparam, __GI_pthread_setschedparam"
		size = "172"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 7C 24 20 8B 6C 24 24 89 F8 25 FF 03 00 00 C1 E0 04 8D B0 ?? ?? ?? ?? 31 D2 89 F0 E8 ?? ?? ?? ?? 8B 5E 08 85 DB 74 05 39 7B 10 74 5A 83 EC 0C 56 E8 ?? ?? ?? ?? B8 03 00 00 00 EB 10 83 EC 0C 56 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 00 83 C4 10 EB 4B 31 C0 85 ED 74 06 8B 54 24 28 8B 02 89 43 18 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 31 C0 83 3D ?? ?? ?? ?? 00 78 25 83 EC 0C FF 73 18 E8 ?? ?? ?? ?? 31 C0 EB C6 51 FF 74 24 2C 55 FF 73 14 E8 ?? ?? ?? ?? 83 C4 10 40 75 B7 EB A0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_xdr_reference_ea041564e8e0afd64acc4db6bceea6cc {
	meta:
		aliases = "xdr_reference, __GI_xdr_reference"
		size = "149"
		objfiles = "xdr_reference@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 7C 24 20 8B 6C 24 24 8B 74 24 28 8B 5D 00 85 DB 75 4B 8B 07 83 F8 01 74 0C BE 01 00 00 00 83 F8 02 74 60 EB 38 83 EC 0C 56 E8 ?? ?? ?? ?? 89 C3 89 45 00 83 C4 10 85 C0 75 16 51 51 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 F6 EB 30 52 56 6A 00 50 E8 ?? ?? ?? ?? 83 C4 10 50 6A FF 53 57 FF 54 24 3C 89 C6 83 C4 10 83 3F 02 75 13 83 EC 0C 53 E8 ?? ?? ?? ?? C7 45 00 00 00 00 00 83 C4 10 89 F0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __pthread_alt_timedlock_822d5bf637c587ff918fcf71cb9e5ac5 {
	meta:
		aliases = "__pthread_alt_timedlock"
		size = "209"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 7C 24 20 8B 6C 24 24 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 31 F6 85 C0 74 09 89 C6 8B 00 A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 85 F6 75 26 83 EC 0C 6A 0C E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 C0 75 13 50 50 55 57 E8 ?? ?? ?? ?? BA 01 00 00 00 83 C4 10 EB 66 8B 1F BA 01 00 00 00 85 DB 74 10 85 ED 75 07 E8 ?? ?? ?? ?? 89 C5 89 6E 04 89 F2 C7 46 08 00 00 00 00 89 1E 89 D8 F0 0F B1 17 0F 94 C2 84 D2 74 CF 85 DB 74 25 57 57 FF 74 24 30 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 12 B0 01 87 46 08 31 D2 85 C0 74 13 89 E8 E8 ?? ?? ?? ?? 89 F0 E8 ?? ?? ?? ?? BA 01 00 00 00 89 }
	condition:
		$pattern
}

rule __stdio_WRITE_13166b788453f8cd7808800f2d7541d5 {
	meta:
		aliases = "__stdio_WRITE"
		size = "124"
		objfiles = "_WRITE@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 7C 24 20 8B 74 24 24 8B 6C 24 28 89 EB 83 FB 00 74 58 7D 07 B8 FF FF FF 7F EB 02 89 D8 52 50 56 FF 77 04 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 06 29 C3 01 C6 EB D8 66 83 0F 08 8B 57 08 8B 47 0C 89 C1 29 D1 74 23 39 D9 76 02 89 D9 8A 06 88 02 3C 0A 75 06 F6 47 01 01 75 07 42 49 74 03 46 EB EB 89 57 10 2B 57 08 29 D3 29 DD 89 E8 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_fgets_unlocked_016e7db348ca673183b8ca57664751a9 {
	meta:
		aliases = "fgets_unlocked, __GI_fgets_unlocked"
		size = "105"
		objfiles = "fgets_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 7C 24 20 8B 74 24 24 8B 6C 24 28 89 FB 85 F6 7F 38 EB 42 8B 45 10 3B 45 18 73 0E 8A 10 88 13 43 40 89 45 10 80 FA 0A EB 1E 83 EC 0C 55 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 75 08 F6 45 00 08 74 0C EB 13 88 03 43 3C 0A 74 03 4E 75 C7 39 FB 76 05 C6 03 00 EB 02 31 FF 89 F8 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fgetws_unlocked_d99141f9a41d1ac2ef5dfb6ee2b3178f {
	meta:
		aliases = "__GI_fgetws_unlocked, fgetws_unlocked"
		size = "80"
		objfiles = "fgetws_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 7C 24 20 8B 74 24 24 8B 6C 24 28 89 FB EB 01 4E 83 FE 01 7E 1B 83 EC 0C 55 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 74 0A 89 03 83 C3 04 83 F8 0A 75 DF 39 FB 75 04 31 FF EB 06 C7 03 00 00 00 00 89 F8 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _stdlib_strto_l_348e6b6423a7d2adb332e10fe53d0d69 {
	meta:
		aliases = "_stdlib_strto_l"
		size = "279"
		objfiles = "_stdlib_strto_l@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 7C 24 20 8B 74 24 28 89 FB EB 01 43 8A 0B 0F BE D1 A1 ?? ?? ?? ?? F6 04 50 20 75 EF 80 F9 2B 74 0E 31 ED 80 F9 2D 75 0A BD 01 00 00 00 EB 02 31 ED 43 89 F9 F7 C6 EF FF FF FF 75 24 83 C6 0A 80 3B 30 75 12 43 83 EE 02 8A 03 83 C8 20 89 D9 3C 78 75 03 01 F6 43 83 FE 10 7E 05 BE 10 00 00 00 8D 46 FE 31 FF 83 F8 22 77 62 83 C8 FF 31 D2 F7 F6 89 44 24 04 88 54 24 0B EB 02 89 D9 8A 03 8D 50 D0 80 FA 09 76 0C 83 C8 20 B2 28 3C 60 76 03 8D 50 A9 0F B6 C2 39 F0 7D 32 43 3B 7C 24 04 77 08 75 1C 3A 54 24 0B 76 16 8A 44 24 2C 21 C5 E8 ?? ?? ?? ?? C7 00 22 00 00 00 83 CF FF EB BC 0F }
	condition:
		$pattern
}

rule svcudp_enablecache_b27384c6b19ffabb8b11fc28c10e49fe {
	meta:
		aliases = "svcudp_enablecache"
		size = "193"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C 8B 7C 24 24 8B 44 24 20 8B 68 30 83 BD B0 01 00 00 00 74 08 56 68 ?? ?? ?? ?? EB 6D 83 EC 0C 6A 2C E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 75 08 53 68 ?? ?? ?? ?? EB 52 89 38 C7 40 0C 00 00 00 00 89 FE C1 E6 04 83 EC 0C 56 E8 ?? ?? ?? ?? 89 43 04 83 C4 10 85 C0 75 08 51 68 ?? ?? ?? ?? EB 29 52 56 6A 00 50 E8 ?? ?? ?? ?? 8D 34 BD 00 00 00 00 89 34 24 E8 ?? ?? ?? ?? 89 43 08 83 C4 10 85 C0 75 1A 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 EB 15 52 56 6A 00 50 E8 ?? ?? ?? ?? 89 9D B0 01 00 00 B8 01 00 00 00 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule svc_run_17078f31495b927bf673db52b7a0e70e {
	meta:
		aliases = "svc_run"
		size = "215"
		objfiles = "svc_run@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C E8 ?? ?? ?? ?? 89 44 24 08 8B 18 85 DB 75 0E E8 ?? ?? ?? ?? 83 38 00 0F 84 AB 00 00 00 83 EC 0C 8D 04 DD 00 00 00 00 50 E8 ?? ?? ?? ?? 89 C7 31 ED 83 C4 10 EB 27 8D 1C ED 00 00 00 00 8D 34 1F E8 ?? ?? ?? ?? 8B 10 8B 14 1A 89 16 8B 00 8B 44 18 04 66 89 46 04 66 C7 46 06 00 00 45 8B 54 24 08 8B 02 39 C5 7C CF 51 6A FF 50 57 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 74 06 85 C0 74 2E EB 31 83 EC 0C 57 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 38 04 0F 84 67 FF FF FF 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 EB 1D 83 EC 0C EB 0A 52 52 50 57 E8 ?? ?? ?? ?? 58 57 E8 ?? ?? ?? ?? 83 }
	condition:
		$pattern
}

rule svc_getreqset_91e62f0926eb1599e1c85bb536593c41 {
	meta:
		aliases = "__GI_svc_getreqset, svc_getreqset"
		size = "93"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C E8 ?? ?? ?? ?? 89 44 24 08 8B 7C 24 20 31 ED EB 37 8B 37 EB 1D 83 EC 0C 8D 58 FF 8D 04 2B 50 E8 ?? ?? ?? ?? B8 01 00 00 00 88 D9 D3 E0 31 C6 83 C4 10 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 D3 83 C7 04 83 C5 20 3B 6C 24 08 7C C3 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __pthread_destroy_specifics_1172ab36e5a0711f2ddf109d32059efe {
	meta:
		aliases = "__pthread_destroy_specifics"
		size = "219"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C E8 ?? ?? ?? ?? 89 C6 31 ED C7 44 24 08 01 00 00 00 EB 60 83 BC 9E EC 00 00 00 00 74 4F 31 FF 89 D8 C1 E0 05 89 44 24 04 EB 3D 8B 44 24 04 01 F8 8B 0C C5 ?? ?? ?? ?? 8D 04 BD 00 00 00 00 03 84 9E EC 00 00 00 8B 10 85 C9 74 1B 85 D2 74 17 C7 00 00 00 00 00 83 EC 0C 52 FF D1 C7 44 24 18 01 00 00 00 83 C4 10 47 83 FF 1F 7E BE 43 83 FB 1F 7E A1 45 83 7C 24 08 00 74 11 83 FD 03 7F 0C 31 DB C7 44 24 08 00 00 00 00 EB E2 8B 46 1C 89 F2 E8 ?? ?? ?? ?? 31 DB EB 23 8B 84 9E EC 00 00 00 85 C0 74 17 83 EC 0C 50 E8 ?? ?? ?? ?? C7 84 9E EC 00 00 00 00 00 00 00 83 C4 10 43 83 FB 1F 7E D8 }
	condition:
		$pattern
}

rule _stdio_init_fdb438b1b16328502b36294794fde0cd {
	meta:
		aliases = "_stdio_init"
		size = "97"
		objfiles = "_stdio@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 0C E8 ?? ?? ?? ?? 89 C7 8B 28 8B 35 ?? ?? ?? ?? 83 EC 0C 6A 00 E8 ?? ?? ?? ?? BB 01 00 00 00 89 DA 29 C2 89 D0 C1 E0 08 31 C6 66 89 35 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? C7 04 24 01 00 00 00 E8 ?? ?? ?? ?? 29 C3 C1 E3 08 31 DE 66 89 35 ?? ?? ?? ?? 89 2F 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __fake_pread_write_5604f5bb002218067cad63eae1b1d0ac {
	meta:
		aliases = "__fake_pread_write"
		size = "138"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 89 C7 89 D6 89 CB 6A 01 6A 00 50 E8 ?? ?? ?? ?? 89 44 24 18 83 C4 10 83 7C 24 08 FF 74 58 50 6A 00 FF 74 24 28 57 E8 ?? ?? ?? ?? 83 C4 10 40 74 45 83 7C 24 24 01 75 0B 50 53 56 57 E8 ?? ?? ?? ?? EB 09 55 53 56 57 E8 ?? ?? ?? ?? 89 C6 83 C4 10 E8 ?? ?? ?? ?? 89 C3 8B 28 51 6A 00 FF 74 24 10 57 E8 ?? ?? ?? ?? 83 C4 10 40 75 05 83 FE FF 75 04 89 2B EB 03 83 CE FF 89 F0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _time_t2tm_d4d48b48602415ec28b2a0602494f5d5 {
	meta:
		aliases = "_time_t2tm"
		size = "368"
		objfiles = "_time_t2tm@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 44 24 24 8B 18 8B 74 24 2C C7 46 1C 00 00 00 00 C7 44 24 0C ?? ?? ?? ?? 8B 44 24 28 05 76 0E 02 00 89 44 24 04 8B 54 24 0C 66 8B 2A 0F B7 CD 66 83 FD 07 75 27 89 D8 99 F7 F9 8D 42 0B B9 07 00 00 00 99 F7 F9 89 54 24 08 8B 54 24 0C 0F B7 42 02 8D 0C 85 01 00 00 00 03 5C 24 04 89 D8 99 F7 F9 89 C7 0F AF C1 29 C3 79 03 01 CB 4F 66 83 FD 07 75 0D 8D 41 FF 39 C3 75 06 8D 59 FE FF 46 10 83 F9 3C 8D 4E 04 7F 08 89 1E 89 CE 89 FB EB 04 89 3E 89 CE 83 44 24 0C 02 8B 54 24 0C 66 83 3A 00 75 82 83 79 FC 04 75 0C C7 41 FC 03 00 00 00 BB 6D 01 00 00 01 19 8D 59 F8 8B 51 FC 81 EA 2B }
	condition:
		$pattern
}

rule __encode_answer_ccc99fdc54fc9f9220805b7429221fb4 {
	meta:
		aliases = "__encode_answer"
		size = "160"
		objfiles = "encodea@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 5C 24 24 8B 6C 24 28 8B 74 24 2C 56 55 FF 33 E8 ?? ?? ?? ?? 89 C7 83 C4 10 85 C0 78 71 29 C6 8B 43 10 83 C0 0A 39 C6 7D 05 83 CF FF EB 60 8D 54 3D 00 0F B6 43 05 88 02 8B 43 04 88 42 01 0F B6 43 09 88 42 02 8B 43 08 88 42 03 0F B6 43 0F 88 42 04 0F B6 43 0E 88 42 05 0F B6 43 0D 88 42 06 8B 43 0C 88 42 07 0F B6 43 11 88 42 08 8B 43 10 88 42 09 50 FF 73 10 FF 73 14 83 C2 0A 52 E8 ?? ?? ?? ?? 8B 43 10 83 C0 0A 01 C7 83 C4 10 89 F8 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule getgrouplist_5379255d7cd6ddc375c3c1a659011335 {
	meta:
		aliases = "getgrouplist"
		size = "120"
		objfiles = "getgrouplist@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 10 8B 5C 24 28 8B 6C 24 30 8B 75 00 55 53 FF 74 24 2C E8 ?? ?? ?? ?? 89 C7 83 C4 10 85 C0 75 11 85 F6 74 41 8B 44 24 28 89 18 BB 01 00 00 00 EB 37 8B 5D 00 39 F3 7E 02 89 F3 85 DB 74 16 50 8D 04 9D 00 00 00 00 50 57 FF 74 24 34 E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 3B 5D 00 7D 03 83 CB FF 89 D8 83 C4 0C 5B 5E 5F 5D C3 }
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

rule svcudp_reply_6bd68a49999d34d13cb5a045f694f423 {
	meta:
		aliases = "svcudp_reply"
		size = "490"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 6C 24 28 8B 5C 24 2C 8B 7D 30 8D 77 08 C7 47 08 00 00 00 00 8B 47 0C 6A 00 56 FF 50 14 8B 47 04 89 03 58 5A 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 A2 01 00 00 83 EC 0C 8B 47 0C 56 FF 50 10 89 44 24 18 8D 55 3C 83 C4 10 83 7A 0C 00 74 1E 8B 45 2C 89 45 34 8B 44 24 08 89 45 38 51 6A 00 52 FF 75 00 E8 ?? ?? ?? ?? 83 C4 10 EB 1D 8D 45 10 52 52 FF 75 0C 50 6A 00 FF 74 24 1C FF 75 2C FF 75 00 E8 ?? ?? ?? ?? 83 C4 20 3B 44 24 08 0F 85 43 01 00 00 83 BF B0 01 00 00 00 74 07 83 7C 24 08 00 79 0A B8 01 00 00 00 E9 2B 01 00 00 8B 7D 30 8B B7 B0 01 00 00 8B 56 0C 8B 46 08 8B 1C }
	condition:
		$pattern
}

rule xdr_union_b633bfe8b6f55fa8b69cb1a2daecd9a6 {
	meta:
		aliases = "__GI_xdr_union, xdr_union"
		size = "130"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 74 24 28 8B 7C 24 2C 8B 44 24 30 89 44 24 10 8B 5C 24 34 8B 6C 24 38 57 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 4B 8B 07 EB 1D 39 03 75 16 C7 44 24 28 FF FF FF FF 8B 44 24 08 89 44 24 24 89 74 24 20 EB 24 83 C3 08 8B 4B 04 85 C9 75 DC 85 ED 74 1F C7 44 24 28 FF FF FF FF 8B 4C 24 08 89 4C 24 24 89 74 24 20 89 E9 83 C4 0C 5B 5E 5F 5D FF E1 31 C0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_xdr_array_c270896efc404f0dcc84235b5e27658e {
	meta:
		aliases = "xdr_array, __GI_xdr_array"
		size = "267"
		objfiles = "xdr_array@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 74 24 30 8B 44 24 2C 8B 18 56 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 D2 00 00 00 8B 3E 3B 7C 24 2C 77 0D 83 C8 FF 31 D2 F7 74 24 30 39 C7 76 0D 8B 54 24 20 83 3A 02 0F 85 B0 00 00 00 85 DB 75 5F 8B 54 24 20 8B 02 83 F8 01 74 0A 83 F8 02 75 4F E9 9B 00 00 00 85 FF 0F 84 93 00 00 00 8B 74 24 30 0F AF F7 83 EC 0C 56 E8 ?? ?? ?? ?? 89 C3 8B 44 24 34 89 18 83 C4 10 85 DB 75 16 53 53 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 F6 EB 55 51 56 6A 00 53 E8 ?? ?? ?? ?? 83 C4 10 31 ED BE 01 00 00 00 EB 16 52 6A FF 53 FF 74 24 2C FF 54 24 44 89 C6 03 5C 24 40 45 83 }
	condition:
		$pattern
}

rule __GI_xdr_bytes_22acc711e442399613dffe1e339e974e {
	meta:
		aliases = "xdr_bytes, __GI_xdr_bytes"
		size = "199"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 7C 24 28 8B 6C 24 2C 8B 74 24 30 8B 44 24 34 89 44 24 10 8B 5D 00 56 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 86 00 00 00 8B 36 3B 74 24 08 76 05 83 3F 02 75 79 8B 07 83 F8 01 74 09 72 3A 83 F8 02 75 6B EB 4B 85 F6 74 69 85 DB 75 2B 83 EC 0C 56 E8 ?? ?? ?? ?? 89 C3 89 45 00 83 C4 10 85 C0 75 16 50 50 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 EB 31 89 74 24 28 89 5C 24 24 89 7C 24 20 83 C4 0C 5B 5E 5F 5D E9 ?? ?? ?? ?? 85 DB 74 1E 83 EC 0C 53 E8 ?? ?? ?? ?? C7 45 00 00 00 00 00 B8 01 00 00 00 83 C4 10 EB 09 31 C0 EB 05 B8 01 00 00 00 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_getgrgid_r_b6064fe98627534bbf7fad9a44387570 {
	meta:
		aliases = "__GI_getpwuid_r, getgrgid_r, getpwuid_r, __GI_getgrgid_r"
		size = "142"
		objfiles = "getpwuid_r@libc.a, getgrgid_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 7C 24 2C 8B 6C 24 38 C7 45 00 00 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 C0 75 09 E8 ?? ?? ?? ?? 8B 18 EB 4D C7 40 34 01 00 00 00 83 EC 0C 56 FF 74 24 3C FF 74 24 3C 57 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 83 C4 20 85 C0 75 0E 8B 44 24 20 39 47 08 75 D7 89 7D 00 EB 0C 31 C0 83 FB 02 0F 95 C0 F7 D8 21 C3 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule getspnam_r_520f0bca15a222178f21171c2fc55dbf {
	meta:
		aliases = "__GI_getpwnam_r, getpwnam_r, __GI_getgrnam_r, getgrnam_r, __GI_getspnam_r, getspnam_r"
		size = "153"
		objfiles = "getgrnam_r@libc.a, getspnam_r@libc.a, getpwnam_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 8B 7C 24 2C 8B 6C 24 38 C7 45 00 00 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 C0 75 09 E8 ?? ?? ?? ?? 8B 18 EB 58 C7 40 34 01 00 00 00 83 EC 0C 56 FF 74 24 3C FF 74 24 3C 57 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 83 C4 20 85 C0 75 19 50 50 FF 74 24 28 FF 37 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 CC 89 7D 00 EB 0C 31 C0 83 FB 02 0F 95 C0 F7 D8 21 C3 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule dladdr_d3e3127706f4b7df53a995556488ecfd {
	meta:
		aliases = "dladdr"
		size = "255"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 14 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 31 DB EB 17 8B 50 14 3B 54 24 28 73 0B 85 DB 74 05 39 53 14 73 02 89 C3 8B 40 0C 85 C0 75 E5 85 DB 0F 84 BF 00 00 00 8B 43 04 8B 54 24 2C 89 02 8B 43 14 89 42 04 8B 73 58 89 74 24 08 8B 43 54 89 04 24 31 FF C7 44 24 0C 00 00 00 00 31 ED C7 44 24 10 00 00 00 00 EB 47 8B 43 2C 8B 0C B8 EB 3A 89 CA C1 E2 04 89 54 24 04 8B 13 8B 74 24 04 8B 44 24 08 03 54 06 04 3B 54 24 28 77 17 85 ED 74 06 39 54 24 10 73 0D 89 4C 24 0C 89 54 24 10 BD 01 00 00 00 8B 43 3C 8B 0C 88 85 C9 75 C2 47 3B 7B 28 72 B4 85 ED 74 26 C1 64 24 0C 04 8B 54 24 0C 8B 74 24 08 8B }
	condition:
		$pattern
}

rule exchange_ec4cca30209941bf8ba9a89be4d21a34 {
	meta:
		aliases = "exchange"
		size = "219"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 89 44 24 04 89 D6 8B 42 14 89 44 24 08 8B 52 18 89 54 24 0C 8B 06 89 44 24 10 E9 87 00 00 00 8B 6C 24 10 2B 6C 24 0C 8B 7C 24 0C 2B 7C 24 08 C7 44 24 14 00 00 00 00 39 FD 7E 61 31 ED 8B 54 24 10 29 FA 89 14 24 EB 20 8B 44 24 08 8D 4C 05 00 8B 54 24 04 8D 0C 8A 8B 19 8B 04 24 01 E8 8D 04 82 8B 10 89 11 89 18 45 39 FD 7C DC 29 7C 24 10 EB 34 8B 4C 24 14 03 4C 24 08 8B 44 24 04 8D 0C 88 8B 19 8B 44 24 14 03 44 24 0C 8B 54 24 04 8D 04 82 8B 10 89 11 89 18 FF 44 24 14 39 6C 24 14 7C D0 01 6C 24 08 8B 44 24 0C 39 44 24 10 7E 0C 8B 54 24 08 39 D0 0F 8F 63 FF FF FF 8B 46 14 03 06 }
	condition:
		$pattern
}

rule makefd_xprt_cfa5da7a0432abd09830bbf514e2acd5 {
	meta:
		aliases = "makefd_xprt"
		size = "181"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 89 44 24 14 89 D5 89 CF 68 34 01 00 00 E8 ?? ?? ?? ?? 89 C3 C7 04 24 B0 01 00 00 E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 DB 74 04 85 C0 75 26 52 52 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 31 DB EB 51 C7 00 02 00 00 00 50 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 57 55 8D 46 08 50 E8 ?? ?? ?? ?? C7 43 30 00 00 00 00 89 73 2C 8D 46 20 89 43 24 C7 43 0C 00 00 00 00 C7 43 08 ?? ?? ?? ?? 66 C7 43 04 00 00 8B 44 24 28 89 03 83 C4 14 53 E8 ?? ?? ?? ?? 89 D8 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule srandom_r_e875de7fc38d3225b1ff6c034e8b687a {
	meta:
		aliases = "__GI_srandom_r, srandom_r"
		size = "150"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 8B 44 24 2C 8B 74 24 30 8B 56 0C 83 C9 FF 83 FA 04 77 72 8B 5E 08 85 C0 75 02 B0 01 89 03 85 D2 74 61 89 C2 8B 46 10 89 04 24 89 D9 BF 01 00 00 00 EB 2A 89 D0 BD 1D F3 01 00 99 F7 FD 89 44 24 04 69 D2 A7 41 00 00 69 C0 14 0B 00 00 29 C2 79 06 81 C2 FF FF FF 7F 83 C1 04 89 11 47 3B 3C 24 7C D1 8B 46 14 8D 04 83 89 06 89 5E 04 6B 1C 24 0A 8D 7C 24 14 EB 09 57 56 E8 ?? ?? ?? ?? 58 5A 4B 79 F4 31 C9 89 C8 83 C4 18 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_fnmatch_74482755c072c7d24bfdf7593e67af5b {
	meta:
		aliases = "fnmatch, __GI_fnmatch"
		size = "1196"
		objfiles = "fnmatch_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 8B 5C 24 2C 8B 7C 24 30 8B 44 24 34 D1 E8 83 F0 01 89 04 24 E9 5A 04 00 00 8B 4C 24 34 83 E1 10 89 4C 24 0C 74 1D 84 D2 78 19 0F BE C2 8D 0C 00 A1 ?? ?? ?? ?? F6 04 08 01 74 08 A1 ?? ?? ?? ?? 8A 14 08 43 80 FA 3F 74 24 7F 0E 80 FA 2A 0F 85 EB 03 00 00 E9 C9 00 00 00 80 FA 5B 0F 84 D3 01 00 00 80 FA 5C 0F 85 D4 03 00 00 EB 49 8A 07 84 C0 0F 84 1D 04 00 00 8A 54 24 34 80 E2 01 74 08 3C 2F 0F 84 0C 04 00 00 F6 44 24 34 04 0F 84 DF 03 00 00 3C 2E 0F 85 D7 03 00 00 3B 7C 24 30 0F 84 EF 03 00 00 84 D2 0F 84 C5 03 00 00 80 7F FF 2F E9 5E 03 00 00 F6 44 24 34 02 75 2F 8A 13 84 D2 }
	condition:
		$pattern
}

rule _uintmaxtostr_735f0c02c075e29258d2db73de0edc73 {
	meta:
		aliases = "_uintmaxtostr"
		size = "228"
		objfiles = "_uintmaxtostr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 8B 6C 24 2C 8B 4C 24 30 8B 5C 24 34 8B 7C 24 38 85 FF 79 17 F7 DF 85 DB 79 11 F7 D9 83 D3 00 F7 DB C7 44 24 08 01 00 00 00 EB 08 C7 44 24 08 00 00 00 00 C6 45 00 00 83 C8 FF 31 D2 F7 F7 89 44 24 0C 42 89 54 24 10 39 FA 75 0D 40 89 44 24 0C C7 44 24 10 00 00 00 00 89 CE 89 D9 31 DB 89 4C 24 14 83 7C 24 14 00 74 3B 8B 44 24 14 31 D2 F7 F7 89 54 24 04 89 44 24 14 8B 4C 24 10 0F AF CA 89 0C 24 89 F0 31 D2 F7 F7 89 C3 8B 04 24 01 D0 8B 4C 24 04 0F AF 4C 24 0C 01 CB 31 D2 F7 F7 8D 34 03 EB 08 89 F0 31 D2 F7 F7 89 C6 4D 8D 42 30 83 FA 09 76 07 8A 4C 24 3C 8D 04 0A 88 45 00 8B 44 }
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

rule regcomp_56d0ed520ba6c37e1119653f6ac9e5c2 {
	meta:
		aliases = "__regcomp, regcomp"
		size = "324"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 8B 7C 24 2C 8B 6C 24 34 89 E8 83 E0 01 83 F8 01 19 DB 81 E3 CA 4F FD 00 81 C3 FC B2 03 00 C7 07 00 00 00 00 C7 47 04 00 00 00 00 C7 47 08 00 00 00 00 68 00 01 00 00 E8 ?? ?? ?? ?? 89 47 10 83 C4 10 F7 C5 02 00 00 00 74 54 83 EC 0C 68 00 01 00 00 E8 ?? ?? ?? ?? 89 47 14 83 C4 10 BE 0C 00 00 00 31 C9 85 C0 75 2C E9 C6 00 00 00 8B 47 14 89 44 24 08 8D 34 09 88 CA A1 ?? ?? ?? ?? F6 04 30 01 74 08 A1 ?? ?? ?? ?? 8A 14 30 8B 44 24 08 88 14 08 41 81 F9 FF 00 00 00 76 D1 EB 07 C7 47 14 00 00 00 00 F7 C5 04 00 00 00 8A 47 1C 74 0B 83 E3 BF 80 CF 01 83 C8 80 EB 03 83 E0 7F 88 47 1C }
	condition:
		$pattern
}

rule __prefix_array_e84c21b032b0f52c3956297394629884 {
	meta:
		aliases = "__prefix_array"
		size = "180"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 18 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 89 C5 83 F8 01 75 0D 8B 44 24 20 80 38 2F 0F 95 C0 0F B6 E8 31 FF EB 79 8B 54 24 24 8D 34 BA 83 EC 0C FF 36 E8 ?? ?? ?? ?? 5B 8D 50 01 89 54 24 14 8D 44 05 02 50 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 75 20 EB 13 4F 83 EC 0C 8B 44 24 30 FF 34 B8 E8 ?? ?? ?? ?? 83 C4 10 85 FF 75 E9 B8 01 00 00 00 EB 35 51 55 FF 74 24 28 50 E8 ?? ?? ?? ?? C6 00 2F 83 C4 0C FF 74 24 0C FF 36 40 50 E8 ?? ?? ?? ?? 5A FF 36 E8 ?? ?? ?? ?? 89 1E 47 83 C4 10 3B 7C 24 28 72 81 31 C0 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __fake_pread_write64_bfb8fe2a4020a84403eab28b4bf49d19 {
	meta:
		aliases = "__fake_pread_write64"
		size = "198"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 89 44 24 10 89 D5 89 CB 8B 44 24 30 8B 54 24 34 89 44 24 08 89 54 24 0C 6A 01 6A 00 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? 89 C6 89 D7 83 C4 10 83 FA FF 75 05 83 F8 FF 74 7A 6A 00 FF 74 24 10 FF 74 24 10 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 42 75 03 40 74 5E 83 7C 24 38 01 75 0E 52 53 55 FF 74 24 1C E8 ?? ?? ?? ?? EB 0C 50 53 55 FF 74 24 1C E8 ?? ?? ?? ?? 89 C5 83 C4 10 E8 ?? ?? ?? ?? 89 C3 8B 10 89 54 24 14 6A 00 57 56 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 42 75 10 40 75 0D 83 FD FF 75 10 8B 44 24 14 89 03 EB 0B 8B 54 24 14 89 13 EB 03 83 CD FF 89 E8 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule inet_pton4_52eee4fbfa0cc8b1ac1f806e7aeb7b4b {
	meta:
		aliases = "inet_pton4"
		size = "133"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 89 C3 89 D5 C6 44 24 18 00 31 FF 8D 74 24 18 EB 3E 0F BE C0 43 8D 48 D0 83 F9 09 77 20 0F B6 06 6B C0 0A 8D 04 01 3D FF 00 00 00 77 47 88 06 85 D2 75 1E 47 83 FF 04 7F 3B B2 01 EB 14 83 F8 2E 75 32 85 D2 74 2E 83 FF 04 74 29 46 C6 06 00 31 D2 8A 03 84 C0 75 BA 83 FF 03 7E 18 50 6A 04 8D 44 24 20 50 55 E8 ?? ?? ?? ?? B8 01 00 00 00 83 C4 10 EB 02 31 C0 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule scan_getwc_de4708d4793dac1d88e70fa259a67c72 {
	meta:
		aliases = "scan_getwc"
		size = "155"
		objfiles = "vfscanf@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 89 C3 8B 78 10 4F 89 78 10 85 FF 79 09 80 48 19 02 83 C8 FF EB 76 C7 40 10 FF FF FF 7F BE FD FF FF FF 8D 68 1C EB 2F 8B 03 88 44 24 1B 55 6A 01 8D 44 24 23 50 8D 44 24 20 50 E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 C0 78 09 8B 44 24 14 89 43 24 EB 36 83 F8 FE 75 10 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 C1 83 FE FD 75 0D C7 43 24 FF FF FF FF 66 BE FF FF EB 0F E8 ?? ?? ?? ?? C7 00 54 00 00 00 C6 43 1B 01 89 7B 10 89 F0 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _dl_parse_eb21582050e0a332b6bdd0b40cfb0db7 {
	meta:
		aliases = "_dl_parse"
		size = "223"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 89 C5 89 54 24 0C 89 CE C1 6C 24 30 03 8B 40 58 89 44 24 18 8B 55 54 89 54 24 14 C7 44 24 10 00 00 00 00 E9 96 00 00 00 8B 5E 04 83 EC 0C FF 74 24 20 FF 74 24 28 56 FF 74 24 24 55 FF 54 24 54 89 C7 83 C4 20 85 C0 74 6E C1 EB 08 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? 83 C4 0C 85 DB 74 1E C1 E3 04 8B 44 24 14 8B 54 24 18 03 04 13 50 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? 83 C4 0C 83 FF 00 7D 19 FF 75 04 0F B6 46 04 50 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? 83 C4 10 EB 2D 7E 14 FF 75 04 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? 83 C4 0C EB 17 FF 44 24 10 83 C6 08 8B 44 24 }
	condition:
		$pattern
}

rule byte_common_op_match_null_stri_9c24429f197655d6b3f60a27e25fcae9 {
	meta:
		aliases = "byte_common_op_match_null_string_p"
		size = "247"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 89 C5 89 CF 8B 08 89 4C 24 18 8A 01 8D 71 01 89 74 24 18 3C 0C 77 21 3C 09 0F 83 B9 00 00 00 3C 06 74 35 3C 08 0F 84 A3 00 00 00 84 C0 0F 84 A5 00 00 00 E9 AE 00 00 00 3C 15 74 62 77 0A 3C 0D 0F 85 A0 00 00 00 EB 41 83 E8 1A 3C 03 0F 87 93 00 00 00 E9 80 00 00 00 0F B6 59 01 8D 44 24 18 89 F9 E8 ?? ?? ?? ?? 89 C6 8D 0C 9F 8A 01 83 E0 03 3C 03 75 0E 89 F2 83 E2 03 8A 01 83 E0 FC 09 D0 88 01 89 F0 84 C0 EB 4D 0F B6 51 01 0F BE 46 01 C1 E0 08 01 D0 78 4E 8D 44 08 03 EB 2A 8D 59 03 89 5C 24 18 0F BE 43 01 C1 E0 08 0F B6 51 03 01 D0 75 32 89 74 24 18 0F B6 51 01 0F BE 46 01 C1 }
	condition:
		$pattern
}

rule byte_group_match_null_string_p_9c61859f2eb3109aef4555541daf5322 {
	meta:
		aliases = "byte_group_match_null_string_p"
		size = "256"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 89 C5 89 D7 89 CE 8B 00 83 C0 02 89 44 24 18 E9 CF 00 00 00 8A 02 3C 07 0F 84 A7 00 00 00 3C 0F 0F 85 AC 00 00 00 8D 42 01 89 44 24 18 0F B6 4A 01 0F BE 40 01 C1 E0 08 83 C2 03 89 54 24 18 89 C3 01 CB 79 4F E9 99 00 00 00 8D 54 18 FD 89 F1 E8 ?? ?? ?? ?? 84 C0 0F 84 92 00 00 00 89 D9 03 4C 24 18 89 4C 24 18 80 39 0F 75 33 8D 41 01 89 44 24 18 0F B6 51 01 0F BE 40 01 C1 E0 08 8D 1C 10 8D 41 03 89 44 24 18 80 3C 19 0E 74 06 89 4C 24 18 EB 0B 8B 44 24 18 80 7C 18 FD 0E 74 AB 8B 44 24 18 0F B6 48 FE 0F BE 50 FF C1 E2 08 8D 1C 0A 8D 14 18 89 F1 E8 ?? ?? ?? ?? 84 C0 74 30 01 5C }
	condition:
		$pattern
}

rule _charpad_02d0ac32e4d09b1131798ff4270e8690 {
	meta:
		aliases = "_charpad"
		size = "56"
		objfiles = "_vfprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 89 C7 89 CE 88 54 24 1B 89 CB 8D 6C 24 1B EB 01 4B 85 DB 74 10 50 57 6A 01 55 E8 ?? ?? ?? ?? 83 C4 10 48 74 EB 29 DE 89 F0 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _charpad_881b220dcf5adcd51e84d7630dd5ccfc {
	meta:
		aliases = "_charpad"
		size = "56"
		objfiles = "_vfwprintf_internal@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 89 C7 89 CE 89 54 24 18 89 CB 8D 6C 24 18 EB 01 4B 85 DB 74 10 50 57 6A 01 55 E8 ?? ?? ?? ?? 83 C4 10 48 74 EB 29 DE 89 F0 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule wcsnrtombs_51a425b4e3cd6ba0a02492dd7fd0afec {
	meta:
		aliases = "__GI_wcsnrtombs, wcsnrtombs"
		size = "135"
		objfiles = "wcsnrtombs@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 54 24 30 8B 6C 24 34 8B 4C 24 38 8B 44 24 3C 85 D2 74 12 BF 01 00 00 00 39 EA 75 12 8D 54 24 0C 66 31 FF EB 09 8D 54 24 0C 83 C8 FF 31 FF 89 C6 39 C8 76 02 89 CE 8B 4D 00 89 F3 EB 27 8B 01 83 F8 7F 76 10 E8 ?? ?? ?? ?? C7 00 54 00 00 00 83 C8 FF EB 23 88 02 84 C0 75 04 31 C9 EB 0A 83 C1 04 01 FA 4B 85 DB 75 D5 8D 44 24 0C 39 C2 74 03 89 4D 00 89 F0 29 D8 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule mbsnrtowcs_85ad3122d2f3f7a6298010b15c90a819 {
	meta:
		aliases = "__GI_mbsnrtowcs, mbsnrtowcs"
		size = "157"
		objfiles = "mbsnrtowcs@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 54 24 30 8B 74 24 38 8B 5C 24 3C 8B 44 24 40 85 C0 75 05 B8 ?? ?? ?? ?? 85 D2 74 11 B9 01 00 00 00 39 C2 75 11 30 C9 8D 54 24 18 EB 09 31 C9 8D 54 24 18 83 CB FF 89 DF 39 F3 76 02 89 F7 8B 44 24 34 8B 18 89 FE 8D 2C 8D 00 00 00 00 EB 28 8A 03 0F B6 C8 89 0A 84 C0 75 04 31 DB EB 1D 83 F9 7F 7E 10 E8 ?? ?? ?? ?? C7 00 54 00 00 00 83 C8 FF EB 1A 43 01 EA 4E 85 F6 75 D4 8D 44 24 18 39 C2 74 06 8B 44 24 34 89 18 89 F8 29 F0 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fgetwc_unlocked_c23c63c63488ef714b1bad2d3155579c {
	meta:
		aliases = "__GI_fgetwc_unlocked, getwc_unlocked, fgetwc_unlocked"
		size = "283"
		objfiles = "fgetwc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 5C 24 30 0F B7 03 25 03 08 00 00 3D 00 08 00 00 77 1B 50 50 68 00 08 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 83 CE FF 85 C0 0F 85 DC 00 00 00 0F B7 03 A8 02 74 31 A8 01 75 06 83 7B 28 00 74 06 C6 43 02 00 EB 06 8A 43 03 88 43 02 8B 03 89 C2 83 E2 01 8B 74 93 24 48 66 89 03 C7 43 28 00 00 00 00 E9 92 00 00 00 83 7B 08 00 75 0E 8D 54 24 1B 89 D8 E8 ?? ?? ?? ?? FF 43 0C 83 7B 2C 00 75 04 C6 43 02 00 8D 7B 2C 8D 6C 24 14 8B 53 10 8B 43 14 89 C6 29 D6 74 31 57 56 52 55 E8 ?? ?? ?? ?? 83 C4 10 83 F8 00 7C 13 75 05 B8 01 00 00 00 01 43 10 00 43 02 8B 74 24 14 EB 3D 83 F8 FE 75 31 01 }
	condition:
		$pattern
}

rule __GI_fflush_unlocked_f6d86edeb3d9022c9610a995e35708b9 {
	meta:
		aliases = "fflush_unlocked, __GI_fflush_unlocked"
		size = "325"
		objfiles = "fflush_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 5C 24 30 66 C7 44 24 0A 00 00 81 FB ?? ?? ?? ?? 74 0F 66 C7 44 24 0A 00 01 85 DB 0F 85 EC 00 00 00 57 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 18 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 40 A3 ?? ?? ?? ?? 59 5E 6A 01 53 E8 ?? ?? ?? ?? 83 C4 0C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 58 5A 6A 01 53 E8 ?? ?? ?? ?? 31 FF 83 C4 10 89 DD EB 73 F6 06 40 74 6B 83 3D ?? ?? ?? ?? 02 74 1B 8D 5E 38 50 53 68 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 66 8B 44 24 0A 0B 06 66 }
	condition:
		$pattern
}

rule __parsepwent_ea99c5392898ffc67409f62a4fdac4bb {
	meta:
		aliases = "__parsepwent"
		size = "120"
		objfiles = "__parsepwent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 5C 24 34 31 F6 8D 6C 24 18 0F B6 86 ?? ?? ?? ?? 8B 7C 24 30 01 C7 89 F0 83 E0 06 83 F8 02 74 1A 89 1F 83 FE 06 74 3A 52 52 6A 3A 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 20 EB 2B 50 6A 0A 55 53 E8 ?? ?? ?? ?? 89 C2 8B 44 24 28 83 C4 10 39 D8 74 14 80 38 3A 75 0F 89 17 C6 00 00 8D 58 01 46 EB A8 31 C0 EB 03 83 C8 FF 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule realloc_e989579dac7d4f718589221fd8352615 {
	meta:
		aliases = "realloc"
		size = "805"
		objfiles = "realloc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 5C 24 34 83 7C 24 30 00 75 10 83 EC 0C 53 E8 ?? ?? ?? ?? 89 C3 E9 F6 02 00 00 85 DB 75 11 83 EC 0C FF 74 24 3C E8 ?? ?? ?? ?? E9 E1 02 00 00 57 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 FB DF 76 12 E8 ?? ?? ?? ?? C7 00 0C 00 00 00 31 DB E9 A9 02 00 00 8D 43 0B C7 04 24 10 00 00 00 83 F8 0F 76 06 83 E0 F8 89 04 24 8B 7C 24 30 83 EF 08 8B 57 04 89 D0 83 E0 FC 89 44 24 04 F6 C2 02 0F 85 95 01 00 00 89 C3 8B 0C 24 39 C8 0F 83 33 01 00 00 8D 34 07 3B 35 ?? ?? ?? ?? 75 38 8B 46 04 83 E0 FC 8D 0C 18 8B 04 24 83 }
	condition:
		$pattern
}

rule __read_etc_hosts_r_1750f19dd15533177434ec625453fc72 {
	meta:
		aliases = "__read_etc_hosts_r"
		size = "717"
		objfiles = "read_etc_hosts_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 5C 24 44 8B 54 24 48 89 D8 F7 D8 83 E0 03 74 0C 39 C2 0F 82 99 02 00 00 01 C3 29 C2 83 FA 1F 0F 86 8C 02 00 00 8D 43 20 89 44 24 18 8D 6A E0 83 7C 24 3C 01 0F 84 9D 00 00 00 8B 44 24 50 C7 00 FF FF FF FF 83 FD 03 0F 86 64 02 00 00 8D 42 DC 83 F8 07 0F 86 58 02 00 00 83 FD 0F 0F 86 4F 02 00 00 8D 42 D0 83 F8 07 0F 86 43 02 00 00 8D 7B 24 8D 6A D4 8D 43 30 89 44 24 14 8D 42 C8 8D 73 2C 39 E8 73 05 8D 73 38 89 C5 83 FD 4F 0F 86 1E 02 00 00 E8 ?? ?? ?? ?? 89 44 24 30 85 C0 74 1D 8B 54 24 18 89 14 24 89 7C 24 04 89 54 24 08 8B 44 24 14 89 44 24 0C 89 74 24 18 EB 39 8B 54 24 }
	condition:
		$pattern
}

rule free_e8c1f3dd6d7cddc825521fdbe67cd25b {
	meta:
		aliases = "free"
		size = "415"
		objfiles = "free@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 6C 24 30 85 ED 0F 84 84 01 00 00 53 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 5D F8 89 DF 8B 53 04 89 D1 83 E1 FC A1 ?? ?? ?? ?? 83 C4 10 39 C1 77 23 83 C8 03 A3 ?? ?? ?? ?? 89 CA C1 EA 03 8B 04 95 ?? ?? ?? ?? 89 43 08 89 1C 95 ?? ?? ?? ?? E9 16 01 00 00 80 E2 02 0F 85 ED 00 00 00 83 C8 01 A3 ?? ?? ?? ?? 8D 34 0B 8B 46 04 89 44 24 08 F6 43 04 01 75 21 8B 6D F8 89 D8 29 E8 8B 58 08 8B 50 0C 8B 7B 0C 39 C7 75 3A 39 7A 08 75 35 01 E9 89 53 0C 89 5A 08 8B 5C 24 08 83 E3 FC 3B 35 ?? ?? ?? ?? 74 50 8B 44 1E 04 83 E0 01 }
	condition:
		$pattern
}

rule __malloc_consolidate_e169476baf480436aead7559c4c6b1cf {
	meta:
		aliases = "__malloc_consolidate"
		size = "386"
		objfiles = "free@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 6C 24 30 8B 45 00 BA 01 00 00 00 85 C0 0F 84 FB 00 00 00 83 E0 FD 89 45 00 8D 55 34 89 54 24 14 C1 E8 03 8D 44 85 FC 89 44 24 0C 8D 5D 04 89 5C 24 08 8B 44 24 08 8B 08 85 C9 0F 84 BA 00 00 00 C7 00 00 00 00 00 8B 51 08 89 54 24 10 8B 41 04 89 C7 83 E7 FE 8D 14 39 8B 5A 04 89 5C 24 04 A8 01 75 28 8B 01 89 44 24 18 89 C8 2B 44 24 18 8B 70 08 8B 58 0C 8B 4E 0C 39 C1 75 39 39 4B 08 75 34 03 7C 24 18 89 5E 0C 89 73 08 8B 74 24 04 83 E6 FC 3B 55 2C 74 4B 8B 44 32 04 83 E0 01 89 72 04 85 C0 75 1D 8B 5A 08 8B 42 0C 39 53 0C 75 05 39 50 08 74 05 E8 ?? ?? ?? ?? 01 F7 89 43 0C 89 }
	condition:
		$pattern
}

rule bindresvport_b6adf81784a499a46a884f46475686d3 {
	meta:
		aliases = "__GI_bindresvport, bindresvport"
		size = "202"
		objfiles = "bindresvport@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 6C 24 30 8B 5C 24 34 85 DB 75 1B 52 6A 10 6A 00 8D 5C 24 18 53 E8 ?? ?? ?? ?? 66 C7 44 24 1C 02 00 83 C4 10 EB 16 66 83 3B 02 74 10 E8 ?? ?? ?? ?? C7 00 60 00 00 00 83 C8 FF EB 7E 66 83 3D ?? ?? ?? ?? 00 75 1B E8 ?? ?? ?? ?? BA A8 01 00 00 89 D1 99 F7 F9 66 81 C2 58 02 66 89 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C7 C7 00 62 00 00 00 83 C8 FF 31 F6 EB 34 66 A1 ?? ?? ?? ?? 89 C2 66 C1 CA 08 66 89 53 02 40 66 A3 ?? ?? ?? ?? 66 3D FF 03 7E 09 66 C7 05 ?? ?? ?? ?? 58 02 50 6A 10 53 55 E8 ?? ?? ?? ?? 46 83 C4 10 81 FE A7 01 00 00 7F 09 85 C0 79 05 83 3F 62 74 BB 83 C4 1C 5B 5E 5F }
	condition:
		$pattern
}

rule __parsegrent_874af477dd0b8056739be98ee98a5605 {
	meta:
		aliases = "__parsegrent"
		size = "223"
		objfiles = "__parsegrent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 6C 24 30 8B 5C 24 34 8B 45 00 89 44 24 08 31 F6 0F B6 86 ?? ?? ?? ?? 8D 7C 05 00 83 FE 01 7F 20 89 1F 52 52 6A 3A 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 95 00 00 00 C6 00 00 8D 58 01 46 EB D0 50 6A 0A 8D 44 24 20 50 53 E8 ?? ?? ?? ?? 89 07 8B 4C 24 28 83 C4 10 39 D9 74 71 80 39 3A 75 6C BB 01 00 00 00 80 79 01 00 74 2B C6 01 2C 80 39 2C 75 1D C6 01 00 41 8A 01 84 C0 74 4F 3C 2C 74 4B 0F BE D0 A1 ?? ?? ?? ?? F6 04 50 20 75 3D 43 41 80 39 00 75 D8 8D 51 04 83 E2 FC 8D 04 9A 3B 44 24 08 77 27 89 55 0C 89 D9 49 74 15 8B 44 24 18 40 89 02 83 C2 04 49 74 08 40 80 38 00 75 FA }
	condition:
		$pattern
}

rule __re_search_2_ca3bae1dd8862321961a2ddccd6ad3f3 {
	meta:
		aliases = "re_search_2, __re_search_2"
		size = "543"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 6C 24 30 8B 5C 24 44 8B 74 24 48 8B 45 10 89 44 24 18 8B 55 14 89 54 24 14 8B 7C 24 40 03 7C 24 38 89 7C 24 10 85 DB 0F 88 CB 01 00 00 39 FB 0F 8F C3 01 00 00 89 F0 01 D8 79 06 89 DE F7 DE EB 0C 3B 44 24 10 7E 06 8B 74 24 10 29 DE 83 7D 08 00 74 24 85 F6 7E 20 8B 45 00 8A 00 3C 0B 74 0A 3C 09 75 13 80 7D 1C 00 78 0D 85 DB 0F 8F 86 01 00 00 BE 01 00 00 00 83 7C 24 18 00 0F 84 1B 01 00 00 F6 45 1C 08 75 15 83 EC 0C 55 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FE 0F 84 60 01 00 00 83 7C 24 18 00 0F 84 F5 00 00 00 3B 5C 24 10 0F 8D EB 00 00 00 F6 45 1C 01 0F 85 E1 00 00 00 85 F6 0F 8E }
	condition:
		$pattern
}

rule getprotoent_r_0c64fccfe021b2898e9400423ab51b35 {
	meta:
		aliases = "__GI_getprotoent_r, getprotoent_r"
		size = "442"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 6C 24 30 8B 7C 24 34 8B 5C 24 38 8B 44 24 3C C7 00 00 00 00 00 81 FB 8B 00 00 00 77 15 E8 ?? ?? ?? ?? C7 00 22 00 00 00 BB 22 00 00 00 E9 76 01 00 00 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D B7 8C 00 00 00 8D 83 74 FF FF FF 83 C4 10 3D 00 10 00 00 77 15 E8 ?? ?? ?? ?? C7 00 22 00 00 00 BB 22 00 00 00 E9 19 01 00 00 83 3D ?? ?? ?? ?? 00 75 29 50 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 10 85 C0 75 0C E8 ?? ?? ?? ?? 8B 18 E9 E7 00 00 00 50 FF 35 ?? ?? ?? ?? 68 00 10 00 00 56 E8 ?? ?? }
	condition:
		$pattern
}

rule error_at_line_bdc9038382eff4f908555604df364805 {
	meta:
		aliases = "__error_at_line, error_at_line"
		size = "311"
		objfiles = "error@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 6C 24 30 8B 7C 24 34 8B 5C 24 38 8B 74 24 3C 83 3D ?? ?? ?? ?? 00 74 35 39 35 ?? ?? ?? ?? 75 21 A1 ?? ?? ?? ?? 39 C3 0F 84 FA 00 00 00 52 52 53 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 E6 00 00 00 89 1D ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 83 EC 0C FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 04 FF D0 EB 1A 50 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 DB 74 15 56 53 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 8D 44 24 44 89 44 24 18 53 50 FF 74 24 48 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 05 ?? ?? ?? ?? 83 C4 10 }
	condition:
		$pattern
}

rule __GI_svc_unregister_850d816d89c1e350a454c32bc837a6a7 {
	meta:
		aliases = "svc_unregister, __GI_svc_unregister"
		size = "94"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 6C 24 30 8B 7C 24 34 8D 4C 24 18 89 FA 89 E8 E8 ?? ?? ?? ?? 89 C3 85 C0 74 34 8B 44 24 18 85 C0 8B 33 75 0D E8 ?? ?? ?? ?? 89 B0 B8 00 00 00 EB 02 89 30 C7 03 00 00 00 00 83 EC 0C 53 E8 ?? ?? ?? ?? 58 5A 57 55 E8 ?? ?? ?? ?? 83 C4 10 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_getdelim_2bf86743842064a6c97e6e1d2715fad6 {
	meta:
		aliases = "getdelim, __GI_getdelim"
		size = "251"
		objfiles = "getdelim@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 6C 24 34 8B 7C 24 3C 83 7C 24 30 00 74 08 85 ED 74 04 85 FF 75 13 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CF FF E9 C0 00 00 00 8B 47 34 89 44 24 08 85 C0 75 1F 51 8D 5F 38 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 44 24 30 8B 18 85 DB 75 07 C7 45 00 00 00 00 00 BE 01 00 00 00 8B 45 00 39 C6 72 24 52 52 83 C0 40 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 05 83 CF FF EB 49 89 C3 83 45 00 40 8B 44 24 30 89 18 8B 47 10 3B 47 18 73 09 0F B6 10 40 89 47 10 EB 13 83 EC 0C 57 E8 ?? ?? ?? ?? 89 C2 83 C4 10 83 F8 FF 74 0B 46 88 54 1E FE 3B 54 24 }
	condition:
		$pattern
}

rule xdr_pmaplist_449c0d309a81f277b8a1094fda98e22b {
	meta:
		aliases = "__GI_xdr_pmaplist, xdr_pmaplist"
		size = "127"
		objfiles = "pmap_prot2@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 30 8B 5C 24 34 83 3E 02 0F 94 C0 0F B6 F8 31 ED 31 C0 83 3B 00 0F 95 C0 89 44 24 18 50 50 8D 44 24 20 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 3B 83 7C 24 18 00 75 07 B8 01 00 00 00 EB 2F 85 FF 74 05 8B 2B 83 C5 10 68 ?? ?? ?? ?? 6A 14 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 0F 85 FF 74 04 89 EB EB AC 8B 1B 83 C3 10 EB A5 31 C0 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fwide_4e29e4f369453e4155e104908813203a {
	meta:
		aliases = "fwide"
		size = "133"
		objfiles = "fwide@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 30 8B 6C 24 34 8B 7E 34 85 FF 75 1F 52 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 85 ED 74 1D 8B 16 F7 C2 80 08 00 00 75 13 B8 00 08 00 00 85 ED 7F 05 B8 80 00 00 00 09 D0 66 89 06 0F B7 1E 85 FF 75 11 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 25 00 08 00 00 81 E3 80 00 00 00 29 D8 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule readtcp_c181cfb0bc716e8389dff0661c82b2ec {
	meta:
		aliases = "readtcp"
		size = "196"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 30 8B 6C 24 38 8B 4E 0C BB E8 03 00 00 89 C8 99 F7 FB 89 C1 69 46 08 E8 03 00 00 8D 3C 01 66 31 DB 85 ED 0F 84 87 00 00 00 8B 06 89 44 24 14 66 C7 44 24 18 01 00 8D 5C 24 14 50 57 6A 01 53 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 74 0D 85 C0 75 24 C7 46 24 05 00 00 00 EB 16 E8 ?? ?? ?? ?? 83 38 04 74 D7 C7 46 24 04 00 00 00 8B 00 89 46 28 83 CB FF EB 3C 50 55 FF 74 24 3C FF 36 E8 ?? ?? ?? ?? 89 C3 83 C4 10 83 F8 FF 74 14 85 C0 75 21 C7 46 28 68 00 00 00 C7 46 24 04 00 00 00 EB D0 E8 ?? ?? ?? ?? 8B 00 89 46 28 C7 46 24 04 00 00 00 89 D8 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule putgrent_0cd5bd68fd89e774866e8a5a187c81a2 {
	meta:
		aliases = "putgrent"
		size = "204"
		objfiles = "putgrent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 30 8B 7C 24 34 85 F6 74 04 85 FF 75 13 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CB FF E9 98 00 00 00 8B 6F 34 85 ED 75 1F 50 8D 5F 38 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C FF 76 08 FF 76 04 FF 36 68 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 83 C4 20 85 C0 78 3D 8B 5E 0C BA ?? ?? ?? ?? 8B 03 85 C0 75 15 53 53 57 6A 0A E8 ?? ?? ?? ?? 83 C4 10 31 DB 85 C0 79 1F EB 1A 51 50 52 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 0A 83 C3 04 BA ?? ?? ?? ?? EB CB 83 CB FF 85 ED 75 11 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 1C 5B }
	condition:
		$pattern
}

rule fsetpos_9669d3e204f4cea5b42026fe61b742a0 {
	meta:
		aliases = "fsetpos"
		size = "122"
		objfiles = "fsetpos@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 30 8B 7C 24 34 8B 6E 34 85 ED 75 1F 51 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 52 6A 00 FF 37 56 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 75 12 8B 47 04 89 46 2C 8B 47 08 89 46 30 8B 47 0C 88 46 02 85 ED 75 11 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fsetpos64_6707c411719a55786875d729d581012a {
	meta:
		aliases = "fsetpos64"
		size = "124"
		objfiles = "fsetpos64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 30 8B 7C 24 34 8B 6E 34 85 ED 75 1F 52 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 6A 00 FF 77 04 FF 37 56 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 75 12 8B 47 08 89 46 2C 8B 47 0C 89 46 30 8B 47 10 88 46 02 85 ED 75 11 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fgetpos_2c87dad79cc23406654b1dcfed005545 {
	meta:
		aliases = "fgetpos"
		size = "126"
		objfiles = "fgetpos@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 30 8B 7C 24 34 8B 6E 34 85 ED 75 1F 52 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C 56 E8 ?? ?? ?? ?? 89 07 83 C4 10 83 CB FF 85 C0 78 15 8B 46 2C 89 47 04 8B 46 30 89 47 08 0F B6 46 02 89 47 0C 31 DB 85 ED 75 11 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fgetpos64_ea3dbf5f579bfeb8cdae3d8ca494eeaf {
	meta:
		aliases = "fgetpos64"
		size = "129"
		objfiles = "fgetpos64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 30 8B 7C 24 34 8B 6E 34 85 ED 75 1F 52 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C 56 E8 ?? ?? ?? ?? 89 07 89 57 04 83 C4 10 83 CB FF 85 D2 78 15 8B 46 2C 89 47 08 8B 46 30 89 47 0C 0F B6 46 02 89 47 10 31 DB 85 ED 75 11 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __parsespent_32eb0b63e3dd83bca99c324f2ef4c017 {
	meta:
		aliases = "__parsespent"
		size = "130"
		objfiles = "__parsespent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 34 31 FF 8D 6C 24 18 0F B6 87 ?? ?? ?? ?? 8B 5C 24 30 01 C3 83 FF 01 7F 15 89 33 52 52 6A 3A 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 34 EB 3B 50 6A 0A 55 56 E8 ?? ?? ?? ?? 89 03 83 C4 10 39 74 24 18 75 06 C7 03 FF FF FF FF 8B 44 24 18 83 FF 08 75 09 31 D2 80 38 00 74 15 EB 0E 80 38 3A 75 09 C6 00 00 8D 70 01 47 EB 9E BA 16 00 00 00 89 D0 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _dl_load_shared_library_47efe82116086eb8f415ddf7e5f775b8 {
	meta:
		aliases = "_dl_load_shared_library"
		size = "503"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 38 8B 5C 24 3C C7 05 ?? ?? ?? ?? 00 00 00 00 8D 43 FF 40 80 38 00 75 FA 29 D8 3D 00 04 00 00 0F 87 A4 01 00 00 8D 43 FF 31 C9 EB 07 80 FA 2F 75 02 89 C1 40 8A 10 84 D2 75 F2 89 DF 85 C9 74 03 8D 79 01 39 DF 74 1A 50 53 FF 74 24 3C FF 74 24 3C E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 84 01 00 00 85 F6 74 27 8B 4E 7C 85 C9 74 20 83 EC 0C 03 4E 54 FF 74 24 40 8B 54 24 40 89 F8 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 59 01 00 00 8B 0D ?? ?? ?? ?? 85 C9 74 1D 83 EC 0C FF 74 24 40 8B 54 24 40 89 F8 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 32 01 00 00 85 F6 74 2A 8B 8E B4 00 00 00 85 }
	condition:
		$pattern
}

rule __pgsreader_b71dd3f53dabc1de012c218a5335bcbd {
	meta:
		aliases = "__pgsreader"
		size = "282"
		objfiles = "__pgsreader@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 74 24 38 8B 7C 24 3C 8B 6C 24 40 81 FF FF 00 00 00 77 15 E8 ?? ?? ?? ?? C7 00 22 00 00 00 BB 22 00 00 00 E9 E0 00 00 00 8B 45 34 89 44 24 08 85 C0 74 0B 31 DB 8D 14 3E 89 54 24 04 EB 21 53 8D 5D 38 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 EB D4 51 55 57 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 14 0F B7 45 00 83 E0 04 83 F8 01 19 DB 83 E3 20 83 C3 02 EB 6D 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 8D 54 06 FF 80 3A 0A 75 05 C6 02 00 EB 08 40 39 F8 75 03 43 EB BA 85 DB 74 03 4B EB B3 8A 06 84 C0 74 AD 3C 23 74 A9 0F BE D0 A1 ?? ?? ?? ?? F6 04 }
	condition:
		$pattern
}

rule __GI_unsetenv_33d7c8dd8a24734cfdc2c0d1c4c73fe6 {
	meta:
		aliases = "unsetenv, __GI_unsetenv"
		size = "186"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 7C 24 30 85 FF 74 16 80 3F 00 74 11 53 53 6A 3D 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 7D 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 0C 89 C5 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 83 C4 10 EB 2B 51 55 57 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 18 80 3C 2B 3D 75 12 89 F2 8D 4A 04 8B 42 04 89 02 85 C0 74 07 89 CA EB F0 83 C6 04 8B 1E 85 DB 75 CF 52 52 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 31 C0 83 C4 10 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule memalign_703940e18304471b67a1d1217b15e742 {
	meta:
		aliases = "memalign"
		size = "389"
		objfiles = "memalign@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 7C 24 30 8B 5C 24 34 83 FF 08 77 10 83 EC 0C 53 E8 ?? ?? ?? ?? 89 C3 E9 54 01 00 00 83 FF 0F 77 05 BF 10 00 00 00 8D 47 FF BA 10 00 00 00 85 C7 75 04 EB 08 01 D2 39 FA 72 FA 89 D7 52 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 FB DF 76 12 E8 ?? ?? ?? ?? C7 00 0C 00 00 00 31 DB E9 FC 00 00 00 8D 43 0B C7 44 24 08 10 00 00 00 83 F8 0F 76 07 83 E0 F8 89 44 24 08 83 EC 0C 8B 54 24 14 8D 44 3A 10 50 E8 ?? ?? ?? ?? 89 C5 83 C4 10 31 DB 85 C0 0F 84 B4 00 00 00 8D 70 F8 31 D2 F7 F7 85 D2 74 60 8D 44 3D FF 89 FA F7 }
	condition:
		$pattern
}

rule getmntent_r_a5f6e7968601f97d9c04a9b853a83e11 {
	meta:
		aliases = "__GI_getmntent_r, getmntent_r"
		size = "299"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 7C 24 30 8B 5C 24 34 8B 74 24 38 8B 6C 24 3C 85 FF 0F 84 00 01 00 00 85 DB 0F 84 F8 00 00 00 85 F6 0F 84 F0 00 00 00 EB 0A 8A 06 3C 23 74 04 3C 0A 75 15 50 57 55 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 E6 E9 CF 00 00 00 C7 44 24 18 00 00 00 00 50 8D 7C 24 1C 57 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 89 03 83 C4 10 85 C0 0F 84 A9 00 00 00 50 57 68 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? 89 43 04 83 C4 10 85 C0 0F 84 8D 00 00 00 50 57 68 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? 89 43 08 83 C4 10 85 C0 74 75 55 57 68 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? 89 43 0C 83 C4 10 85 C0 75 07 C7 43 0C ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_getservent_r_41849462c09b8261b1d4cbef5b284d9d {
	meta:
		aliases = "getservent_r, __GI_getservent_r"
		size = "499"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 7C 24 30 8B 6C 24 34 8B 5C 24 38 8B 44 24 3C C7 00 00 00 00 00 81 FB 8B 00 00 00 77 15 E8 ?? ?? ?? ?? C7 00 22 00 00 00 BB 22 00 00 00 E9 AF 01 00 00 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 85 8C 00 00 00 89 44 24 18 8D 83 74 FF FF FF 83 C4 10 3D 00 10 00 00 77 15 E8 ?? ?? ?? ?? C7 00 22 00 00 00 BB 22 00 00 00 E9 4E 01 00 00 83 3D ?? ?? ?? ?? 00 75 32 50 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 10 85 C0 75 15 E8 ?? ?? ?? ?? C7 00 05 00 00 00 BB 05 00 00 00 E9 13 01 00 00 50 FF 35 }
	condition:
		$pattern
}

rule __GI_vasprintf_d1bd1fc660fb8ccb8dd47a2a9a10fd81 {
	meta:
		aliases = "vasprintf, __GI_vasprintf"
		size = "115"
		objfiles = "vasprintf@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 7C 24 30 8B 6C 24 34 8B 74 24 38 89 74 24 18 56 55 6A 00 6A 00 E8 ?? ?? ?? ?? 89 C3 C7 07 00 00 00 00 83 C4 10 85 C0 78 38 43 83 EC 0C 53 E8 ?? ?? ?? ?? 89 07 83 C4 10 85 C0 74 25 56 55 53 50 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 79 13 83 EC 0C FF 37 E8 ?? ?? ?? ?? C7 07 00 00 00 00 83 C4 10 89 D8 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule registerrpc_7c768a0145560a5189617053d3dc4e10 {
	meta:
		aliases = "registerrpc"
		size = "266"
		objfiles = "svc_simple@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 7C 24 30 8B 74 24 34 8B 6C 24 38 85 ED 75 0A 50 6A 00 68 ?? ?? ?? ?? EB 61 E8 ?? ?? ?? ?? 89 C3 83 B8 C4 00 00 00 00 75 21 83 EC 0C 6A FF E8 ?? ?? ?? ?? 89 83 C4 00 00 00 83 C4 10 85 C0 75 0A 83 EC 0C 68 ?? ?? ?? ?? EB 57 50 50 56 57 E8 ?? ?? ?? ?? C7 04 24 11 00 00 00 68 ?? ?? ?? ?? 56 57 FF B3 C4 00 00 00 E8 ?? ?? ?? ?? 83 C4 20 85 C0 75 13 56 57 68 ?? ?? ?? ?? 8D 44 24 24 50 E8 ?? ?? ?? ?? EB 53 83 EC 0C 6A 18 E8 ?? ?? ?? ?? 89 C2 83 C4 10 85 C0 75 13 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 44 24 28 EB 2D 8B 44 24 3C 89 02 89 7A 04 89 6A 08 8B 44 24 40 89 42 0C 8B }
	condition:
		$pattern
}

rule __GI_setvbuf_5379b6eee0c89f7fe8b6dc62b07fa7dc {
	meta:
		aliases = "setvbuf, __GI_setvbuf"
		size = "259"
		objfiles = "setvbuf@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 7C 24 30 8B 74 24 34 8B 6C 24 3C 8B 47 34 89 44 24 08 85 C0 75 1F 52 8D 5F 38 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 83 7C 24 38 02 76 13 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CB FF E9 8A 00 00 00 8B 17 83 CB FF F7 C2 CF 08 00 00 75 7D 8B 44 24 38 C1 E0 08 80 E6 FC 09 C2 66 89 17 83 7C 24 38 02 74 04 85 ED 75 08 31 F6 31 ED 31 DB EB 26 31 DB 85 F6 75 20 8B 47 0C 2B 47 08 39 E8 74 49 83 EC 0C 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 39 89 C6 66 BB 00 40 8B 07 F6 C4 40 74 14 80 E4 BF 66 89 07 83 EC 0C FF 77 08 E8 ?? ?? ?? ?? 83 C4 10 66 }
	condition:
		$pattern
}

rule ungetwc_e23ba96952b32f960b1573650cf57f7d {
	meta:
		aliases = "__GI_ungetwc, ungetwc"
		size = "170"
		objfiles = "ungetwc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 7C 24 30 8B 74 24 34 8B 6E 34 85 ED 75 1F 51 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 0F B7 06 25 03 08 00 00 3D 00 08 00 00 77 14 52 52 68 00 08 00 00 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 30 0F B7 06 A8 02 74 0A A8 01 75 25 83 7E 28 00 75 1F 83 FF FF 74 1A C7 46 28 01 00 00 00 8B 06 40 66 89 06 83 E0 01 89 7C 86 24 66 83 26 FB EB 03 83 CF FF 85 ED 75 11 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 89 F8 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_ungetc_382824eaa075fde4bf23ffe6daf89d3a {
	meta:
		aliases = "ungetc, __GI_ungetc"
		size = "207"
		objfiles = "ungetc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 7C 24 30 8B 74 24 34 8B 6E 34 85 ED 75 1F 51 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 46 10 3B 46 18 73 17 83 FF FF 74 12 3B 46 08 76 0D 89 FA 38 50 FF 75 06 48 89 46 10 EB 53 0F B7 06 25 83 00 00 00 3D 80 00 00 00 77 14 52 52 68 80 00 00 00 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 36 0F B7 06 A8 02 74 0A A8 01 75 2B 83 7E 28 00 75 25 83 FF FF 74 20 8B 46 08 89 46 18 C7 46 28 01 00 00 00 8B 06 40 66 89 06 83 E0 01 89 7C 86 24 66 83 26 FB EB 03 83 CF FF 85 ED 75 11 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 89 F8 83 }
	condition:
		$pattern
}

rule putspent_ffaf6fadbd375a68083ff1366762a62f {
	meta:
		aliases = "putspent"
		size = "218"
		objfiles = "putspent@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 7C 24 30 8B 74 24 34 8B 6E 34 85 ED 75 1F 53 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 47 04 85 C0 75 05 B8 ?? ?? ?? ?? 50 FF 37 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 10 31 DB 85 C0 79 2C EB 5E 0F B6 83 ?? ?? ?? ?? 8B 04 07 BA ?? ?? ?? ?? 83 F8 FF 74 05 BA ?? ?? ?? ?? 51 50 52 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 35 43 83 FB 05 76 D1 8B 47 20 83 F8 FF 74 14 51 50 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 13 52 52 56 6A 0A E8 ?? ?? ?? ?? 83 C4 10 31 DB 85 C0 7F 03 83 CB FF 85 ED 75 11 50 50 6A 01 8D 44 24 18 50 }
	condition:
		$pattern
}

rule __GI_svc_register_4472b2e5f1ee6e311462a224812f2c0e {
	meta:
		aliases = "svc_register, __GI_svc_register"
		size = "137"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C 8B 7C 24 34 8B 74 24 38 8B 6C 24 3C 8D 4C 24 18 89 F2 89 F8 E8 ?? ?? ?? ?? 85 C0 74 07 39 68 0C 75 56 EB 2F 83 EC 0C 6A 10 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 74 41 89 78 04 89 70 08 89 68 0C E8 ?? ?? ?? ?? 8B 90 B8 00 00 00 89 13 89 98 B8 00 00 00 B8 01 00 00 00 83 7C 24 40 00 74 1B 8B 44 24 30 0F B7 40 04 50 FF 74 24 44 56 57 E8 ?? ?? ?? ?? 83 C4 10 EB 02 31 C0 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule ceil_1c4cd84017937fb7a4478b6a1d25c5bd {
	meta:
		aliases = "__GI_ceil, ceil"
		size = "311"
		objfiles = "s_ceil@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C C7 44 24 08 00 00 00 00 C7 44 24 0C 00 00 00 00 DD 44 24 30 DD 14 24 DD 54 24 10 8B 54 24 14 8B 6C 24 10 89 EE 89 D0 C1 F8 14 25 FF 07 00 00 8D 98 01 FC FF FF 83 FB 13 7F 7C 85 DB 79 38 DD 05 ?? ?? ?? ?? DE C1 D9 EE D9 C9 DA E9 DF E0 9E 0F 86 C1 00 00 00 85 D2 79 07 BA 00 00 00 80 EB 0F 89 E9 09 D1 0F 84 AC 00 00 00 BA 00 00 F0 3F 31 F6 E9 A0 00 00 00 DD D8 BF FF FF 0F 00 88 D9 D3 FF 89 F8 21 D0 09 E8 0F 84 98 00 00 00 DD 04 24 DC 05 ?? ?? ?? ?? D9 EE D9 C9 DA E9 DF E0 9E 76 75 85 D2 7E 09 B8 00 00 10 00 D3 F8 01 C2 89 F8 F7 D0 21 C2 EB B9 DD D8 83 FB 33 7E 0F 81 FB 00 04 }
	condition:
		$pattern
}

rule __GI_floor_4c8b843aa43f9e2d56ee1c6a46fbb956 {
	meta:
		aliases = "floor, __GI_floor"
		size = "313"
		objfiles = "s_floor@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C C7 44 24 08 00 00 00 00 C7 44 24 0C 00 00 00 00 DD 44 24 30 DD 14 24 DD 54 24 10 8B 54 24 14 8B 6C 24 10 89 EE 89 D0 C1 F8 14 25 FF 07 00 00 8D 98 01 FC FF FF 83 FB 13 7F 7E 85 DB 79 3A DD 05 ?? ?? ?? ?? DE C1 D9 EE D9 C9 DA E9 DF E0 9E 0F 86 C3 00 00 00 85 D2 78 04 31 D2 EB 14 89 D0 25 FF FF FF 7F 09 E8 0F 84 AC 00 00 00 BA 00 00 F0 BF 31 F6 E9 A0 00 00 00 DD D8 BF FF FF 0F 00 88 D9 D3 FF 89 F8 21 D0 09 E8 0F 84 98 00 00 00 DD 04 24 DC 05 ?? ?? ?? ?? D9 EE D9 C9 DA E9 DF E0 9E 76 75 85 D2 79 09 B8 00 00 10 00 D3 F8 01 C2 89 F8 F7 D0 21 C2 EB B9 DD D8 83 FB 33 7E 0F 81 FB }
	condition:
		$pattern
}

rule __GI_lround_5672d9462ed409312c7918d4ecce6961 {
	meta:
		aliases = "lround, __GI_lround"
		size = "202"
		objfiles = "s_lround@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C DD 44 24 30 DD 14 24 DD 5C 24 08 8B 44 24 0C 8B 6C 24 08 89 C1 C1 E9 14 81 E1 FF 07 00 00 8D 99 01 FC FF FF 89 C7 C1 FF 1F 83 CF 01 89 C2 81 E2 FF FF 0F 00 81 CA 00 00 10 00 83 FB 13 7F 23 85 DB 79 09 89 F8 43 74 73 31 C0 EB 6F B8 00 00 08 00 88 D9 D3 F8 01 D0 B9 14 00 00 00 29 D9 D3 E8 EB 56 83 FB 1E 7F 2B 81 E9 13 04 00 00 B8 00 00 00 80 D3 E8 8D 34 28 39 EE 83 D2 00 89 D0 83 FB 14 74 35 D3 E0 B9 34 00 00 00 29 D9 D3 EE 09 F0 EB 26 D9 7C 24 16 66 8B 44 24 16 80 CC 0C 66 89 44 24 14 DD 04 24 D9 6C 24 14 DB 5C 24 10 D9 6C 24 16 8B 44 24 10 EB 03 0F AF C7 83 C4 1C 5B 5E 5F }
	condition:
		$pattern
}

rule __GI_ptsname_r_c93365cec3b5777bdc800dfd5a2b0997 {
	meta:
		aliases = "ptsname_r, __GI_ptsname_r"
		size = "152"
		objfiles = "ptsname@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 1C E8 ?? ?? ?? ?? 89 C6 8B 28 53 8D 44 24 1C 50 68 30 54 04 80 FF 74 24 3C E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 5A 83 EC 0C 6A 00 6A F6 8B 44 24 2C 99 52 50 8D 5C 24 33 53 E8 ?? ?? ?? ?? 89 C7 29 C3 83 C3 0A 83 C4 20 39 5C 24 38 73 0D C7 06 22 00 00 00 B8 22 00 00 00 EB 30 51 51 68 ?? ?? ?? ?? FF 74 24 40 E8 ?? ?? ?? ?? 58 5A 57 FF 74 24 40 E8 ?? ?? ?? ?? 89 2E 31 C0 83 C4 10 EB 0B C7 06 19 00 00 00 B8 19 00 00 00 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fcloseall_06ed1e68c6d0768abd0e97c0d5f4b5cc {
	meta:
		aliases = "fcloseall"
		size = "240"
		objfiles = "fcloseall@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 18 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 40 A3 ?? ?? ?? ?? 5D 58 6A 01 53 E8 ?? ?? ?? ?? 83 C4 0C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 59 5F 6A 01 53 E8 ?? ?? ?? ?? C7 44 24 18 00 00 00 00 83 C4 10 EB 63 8B 6E 20 8B 7E 34 85 FF 75 1F 8D 5E 38 52 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 0F B7 06 83 E0 30 83 F8 30 74 18 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 08 C7 44 24 08 FF FF FF FF 85 FF 75 11 }
	condition:
		$pattern
}

rule getprotobyname_r_763556cced7ac8564ae83910a4d9f0a2 {
	meta:
		aliases = "__GI_getprotobyname_r, getprotobyname_r"
		size = "194"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 6C 24 34 8B 74 24 38 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F BE 05 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 EB 2F 51 51 55 FF 36 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 39 8B 5E 04 EB 13 52 52 55 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 24 83 C3 04 8B 03 85 C0 75 E7 FF 74 24 40 FF 74 24 40 FF 74 24 40 56 E8 ?? ?? ?? ?? 89 C7 83 C4 10 85 C0 74 B6 80 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 55 55 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 8B 44 24 50 83 38 00 0F 94 C0 0F B6 C0 F7 D8 21 F8 83 C4 2C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _dl_dprintf_bbdfb1eee8aa6be6df7d96dd5102dc61 {
	meta:
		aliases = "_dl_dprintf"
		size = "700"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 6C 24 38 85 ED 0F 84 A1 02 00 00 8B 0D ?? ?? ?? ?? C7 44 24 18 00 00 00 00 31 C0 BA 03 00 00 00 BE 22 00 00 00 83 CF FF 53 89 C3 55 8B 6C 24 18 B8 C0 00 00 00 CD 80 5D 5B 3D 00 F0 FF FF 76 0A F7 D8 A3 ?? ?? ?? ?? 83 C8 FF A3 ?? ?? ?? ?? 40 75 45 B9 ?? ?? ?? ?? BA 1D 00 00 00 8B 7C 24 34 53 89 FB B8 04 00 00 00 CD 80 5B 3D 00 F0 FF FF 76 07 F7 D8 A3 ?? ?? ?? ?? BF 14 00 00 00 53 89 FB B8 01 00 00 00 CD 80 5B 3D 00 F0 FF FF 76 07 F7 D8 A3 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 8D 75 FF 89 F2 42 80 3A 00 75 FA 29 EA A1 ?? ?? ?? ?? 48 39 C2 72 45 B9 ?? ?? ?? ?? BA 0B 00 00 00 8B 7C }
	condition:
		$pattern
}

rule __GI_getservbyname_r_1b5d508b89b88494e3cbb44a094a36c4 {
	meta:
		aliases = "getservbyname_r, __GI_getservbyname_r"
		size = "224"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 6C 24 38 8B 74 24 3C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F BE 05 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 EB 4D 51 51 FF 36 FF 74 24 3C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 23 8B 5E 04 EB 16 52 52 50 FF 74 24 3C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 0B 83 C3 04 8B 03 85 C0 75 E4 EB 16 85 ED 74 2D 50 50 55 FF 76 0C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 1B FF 74 24 44 FF 74 24 44 FF 74 24 44 56 E8 ?? ?? ?? ?? 89 C7 83 C4 10 85 C0 74 98 80 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 8B }
	condition:
		$pattern
}

rule readdir_r_f1ecaf8d6f697d704fae642e176cb011 {
	meta:
		aliases = "__GI_readdir_r, readdir_r"
		size = "196"
		objfiles = "readdir_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 74 24 34 8B 6C 24 3C 8D 5E 18 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 31 FF 83 C4 10 8B 46 08 3B 46 04 77 36 51 FF 76 14 FF 76 0C FF 36 E8 ?? ?? ?? ?? 83 C4 10 83 F8 00 7F 16 C7 45 00 00 00 00 00 75 04 31 DB EB 47 E8 ?? ?? ?? ?? 8B 18 EB 3E 89 46 08 C7 46 04 00 00 00 00 8B 46 04 89 C7 03 7E 0C 0F B7 57 08 01 C2 89 56 04 8B 47 04 89 46 10 83 3F 00 74 A6 52 0F B7 47 08 50 57 FF 74 24 40 E8 ?? ?? ?? ?? 89 45 00 31 DB 83 C4 10 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 31 C0 85 FF 0F 94 C0 F7 D8 21 C3 89 D8 83 C4 2C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_readdir64_r_f6a34d6e063c54f05fa1df5ccb9337a4 {
	meta:
		aliases = "readdir64_r, __GI_readdir64_r"
		size = "198"
		objfiles = "readdir64_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 74 24 34 8B 6C 24 3C 8D 5E 18 53 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 31 FF 83 C4 10 8B 46 08 3B 46 04 77 36 51 FF 76 14 FF 76 0C FF 36 E8 ?? ?? ?? ?? 83 C4 10 83 F8 00 7F 16 C7 45 00 00 00 00 00 75 04 31 DB EB 49 E8 ?? ?? ?? ?? 8B 18 EB 40 89 46 08 C7 46 04 00 00 00 00 8B 56 04 89 D7 03 7E 0C 0F B7 47 10 01 D0 89 46 04 8B 47 08 89 46 10 8B 07 0B 47 04 74 A4 52 0F B7 47 10 50 57 FF 74 24 40 E8 ?? ?? ?? ?? 89 45 00 31 DB 83 C4 10 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 31 C0 85 FF 0F 94 C0 F7 D8 21 C3 89 D8 83 C4 2C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_getprotobynumber_r_4f2870bc4469de44e30b8ab021d37c92 {
	meta:
		aliases = "getprotobynumber_r, __GI_getprotobynumber_r"
		size = "149"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 74 24 38 8B 6C 24 40 8B 7C 24 44 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F BE 05 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 EB 09 8B 44 24 30 39 46 08 74 15 57 55 FF 74 24 40 56 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 74 E2 80 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 56 56 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 31 C0 83 3F 00 0F 94 C0 F7 D8 21 D8 83 C4 2C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule rresvport_e5a276433f63ce3304e5125b32083541 {
	meta:
		aliases = "__GI_rresvport, rresvport"
		size = "149"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 7C 24 34 66 C7 44 24 10 02 00 C7 44 24 14 00 00 00 00 6A 00 6A 01 6A 02 E8 ?? ?? ?? ?? 89 C3 83 C4 10 8D 6C 24 0C 85 C0 79 05 83 CB FF EB 54 8B 07 66 C1 C8 08 66 89 44 24 0E 51 6A 10 55 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 38 E8 ?? ?? ?? ?? 89 C6 83 38 62 74 0B 83 EC 0C 53 E8 ?? ?? ?? ?? EB 1B 8B 07 48 89 07 3D 00 02 00 00 75 C1 83 EC 0C 53 E8 ?? ?? ?? ?? C7 06 0B 00 00 00 83 CB FF 83 C4 10 89 D8 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule getservbyport_r_a01b36e521b85d75e8f44b1cf9e4961f {
	meta:
		aliases = "__GI_getservbyport_r, getservbyport_r"
		size = "175"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 20 8B 7C 24 38 8B 74 24 3C 8B 6C 24 48 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F BE 05 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 EB 1F 8B 44 24 30 39 46 08 75 16 85 FF 74 2A 50 50 57 FF 76 0C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 18 55 FF 74 24 44 FF 74 24 44 56 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 74 C9 80 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 31 C0 83 7D 00 00 0F 94 C0 F7 D8 21 D8 83 C4 2C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule bcmp_a493628e52c272244c2cb8b5e245501b {
	meta:
		aliases = "memcmp, __GI_memcmp, bcmp"
		size = "679"
		objfiles = "memcmp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 24 8B 5C 24 38 8B 44 24 3C 89 04 24 83 7C 24 40 0F 77 20 E9 78 02 00 00 0F B6 13 8B 0C 24 0F B6 01 29 C2 89 D0 0F 85 6E 02 00 00 43 FF 04 24 FF 4C 24 40 8B 04 24 89 44 24 04 A8 03 75 DA 89 5C 24 08 89 D8 83 E0 03 0F 85 AD 00 00 00 8B 7C 24 40 C1 EF 02 89 F8 83 E0 03 83 F8 01 74 33 72 28 83 F8 03 8B 03 8B 0C 24 8B 11 74 0E 83 EB 08 83 E9 08 89 0C 24 83 C7 02 EB 4D 89 C5 89 D6 83 EB 04 83 2C 24 04 47 EB 32 8B 03 8B 0C 24 8B 11 EB 1C 8B 2B 8B 04 24 8B 30 83 C3 04 83 C0 04 89 04 24 4F 8B 03 8B 0C 24 8B 11 39 F5 75 3F 8B 6B 04 8B 0C 24 8B 71 04 39 D0 75 36 8B 43 08 8B 0C 24 8B 51 }
	condition:
		$pattern
}

rule xdr_rmtcall_args_021c2adbd2a4d500e047d223f9190b02 {
	meta:
		aliases = "__GI_xdr_rmtcall_args, xdr_rmtcall_args"
		size = "228"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 24 8B 5C 24 38 8B 74 24 3C 56 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 B9 00 00 00 50 50 8D 46 04 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 A2 00 00 00 55 55 8D 46 08 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 8B 00 00 00 C7 44 24 18 00 00 00 00 83 EC 0C 8B 43 04 53 FF 50 10 89 44 24 18 59 5F 8D 44 24 20 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 61 83 EC 0C 8B 43 04 53 FF 50 10 89 C5 58 5A FF 76 10 53 FF 56 14 83 C4 10 85 C0 74 45 83 EC 0C 8B 43 04 53 FF 50 10 89 C7 29 E8 89 46 0C 5D 58 8B 43 04 FF 74 24 10 53 FF 50 14 5A 59 8D 46 0C 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 14 50 50 }
	condition:
		$pattern
}

rule pmap_getmaps_56b3fd86909793d598670d46ad2a9a83 {
	meta:
		aliases = "pmap_getmaps"
		size = "155"
		objfiles = "pm_getmaps@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 24 8B 6C 24 38 C7 44 24 20 00 00 00 00 C7 44 24 1C FF FF FF FF 66 C7 45 02 00 6F 68 F4 01 00 00 6A 32 8D 44 24 24 50 6A 02 68 A0 86 01 00 55 E8 ?? ?? ?? ?? 89 C3 83 C4 20 85 C0 74 46 8B 50 04 8D 44 24 18 BE 3C 00 00 00 31 FF 57 56 50 68 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 6A 04 53 FF 12 83 C4 20 85 C0 74 10 50 50 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C 8B 43 04 53 FF 50 10 83 C4 10 66 C7 45 02 00 00 8B 44 24 18 83 C4 1C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fork_706fa52a9bd6327f4ec7081defeb27d3 {
	meta:
		aliases = "__fork, fork"
		size = "255"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 28 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 2D ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C7 83 C4 10 85 C0 0F 85 83 00 00 00 BE ?? ?? ?? ?? 85 F6 74 62 83 EC 0C 8D 5C 24 24 53 E8 ?? ?? ?? ?? 58 5A 6A 01 53 E8 ?? ?? ?? ?? 59 58 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 85 F6 74 2F 83 EC 0C 8D 5C 24 24 53 E8 ?? ?? ?? ?? 58 5A 6A 00 53 E8 ?? ?? ?? ?? 59 5E 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 E8 E8 ?? }
	condition:
		$pattern
}

rule __GI_xdrrec_create_8772771b2ea7c0eaf61f376c71dbc918 {
	meta:
		aliases = "xdrrec_create, __GI_xdrrec_create"
		size = "282"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 28 8B 44 24 3C 89 44 24 24 8B 74 24 40 8B 7C 24 44 8B 44 24 48 89 44 24 20 8B 44 24 4C 89 44 24 1C 8B 44 24 50 89 44 24 18 6A 44 E8 ?? ?? ?? ?? 89 C3 83 C4 10 83 FE 63 77 05 BE A0 0F 00 00 8D 6E 03 83 E5 FC 83 FF 63 77 05 BF A0 0F 00 00 83 C7 03 83 E7 FC 83 EC 0C 8D 44 3D 04 50 E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 DB 74 04 85 C0 75 2A 57 57 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 89 74 24 40 83 C4 2C 5B 5E 5F 5D E9 ?? ?? ?? ?? 89 6B 3C 89 7B 40 89 43 04 89 C2 83 E0 03 74 05 29 C6 8D 56 04 89 53 0C 8D 04 2A 89 43 28 8B 44 24 18 C7 40 04 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule hsearch_r_c02f38adeae58976a823ba56011a4dee {
	meta:
		aliases = "__GI_hsearch_r, hsearch_r"
		size = "376"
		objfiles = "hsearch_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 28 8B 44 24 3C 8B 54 24 40 89 54 24 20 89 44 24 1C 50 E8 ?? ?? ?? ?? 83 C4 10 89 C1 EB 0F 89 C2 C1 E2 04 8B 5C 24 10 0F BE 04 0B 01 D0 49 83 F9 FF 75 EB 8B 54 24 40 8B 52 04 89 54 24 08 31 D2 F7 74 24 08 89 D6 85 D2 75 04 66 BE 01 00 8B 4C 24 40 8B 09 89 4C 24 0C 6B C6 0C 89 CB 01 C3 8B 03 85 C0 0F 84 93 00 00 00 39 F0 75 20 52 52 FF 73 04 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 0B 8D 43 04 8B 5C 24 3C 89 03 EB 5F 8B 54 24 08 83 EA 02 89 F0 89 D1 31 D2 F7 F1 8D 6A 01 89 F3 8B 44 24 08 29 E8 89 44 24 04 39 EB 77 06 03 5C 24 04 EB 02 29 EB 39 F3 74 41 6B C3 0C 8B 7C 24 0C }
	condition:
		$pattern
}

rule __add_to_environ_c14a00bd5bccefde0b9009e802008946 {
	meta:
		aliases = "__add_to_environ"
		size = "454"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 28 FF 74 24 3C E8 ?? ?? ?? ?? 83 C4 10 89 C7 C7 44 24 08 00 00 00 00 83 7C 24 34 00 74 14 83 EC 0C FF 74 24 40 E8 ?? ?? ?? ?? 83 C4 10 40 89 44 24 08 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 83 C4 10 31 ED 85 F6 74 32 EB 1D 50 57 FF 74 24 38 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 06 80 3C 3B 3D 74 0A 45 83 C6 04 8B 1E 85 DB 75 DD 85 F6 74 09 83 3E 00 0F 85 B8 00 00 00 C1 E5 02 53 53 8D 45 08 50 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 0F 84 F0 00 00 00 83 7C 24 38 00 74 09 8B 44 24 38 89 04 }
	condition:
		$pattern
}

rule scandir_0b94dba043cfd9133abff6731f2f5e25 {
	meta:
		aliases = "scandir"
		size = "368"
		objfiles = "scandir@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 28 FF 74 24 3C E8 ?? ?? ?? ?? 89 44 24 1C 83 C4 10 83 C8 FF 83 7C 24 0C 00 0F 84 43 01 00 00 E8 ?? ?? ?? ?? 89 C6 8B 00 89 44 24 18 C7 06 00 00 00 00 C7 44 24 10 00 00 00 00 C7 44 24 14 00 00 00 00 31 ED E9 84 00 00 00 83 7C 24 38 00 74 17 83 EC 0C 57 FF 54 24 48 83 C4 10 85 C0 75 08 C7 06 00 00 00 00 EB 66 C7 06 00 00 00 00 3B 6C 24 14 75 32 C7 44 24 14 0A 00 00 00 85 ED 74 08 8D 54 2D 00 89 54 24 14 51 51 8B 44 24 1C C1 E0 02 50 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 45 89 44 24 10 0F B7 5F 08 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 2D 52 53 57 50 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule scandir64_205cfa2b48f9dc10fddf0fe042e63c67 {
	meta:
		aliases = "scandir64"
		size = "368"
		objfiles = "scandir64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 28 FF 74 24 3C E8 ?? ?? ?? ?? 89 44 24 1C 83 C4 10 83 C8 FF 83 7C 24 0C 00 0F 84 43 01 00 00 E8 ?? ?? ?? ?? 89 C6 8B 00 89 44 24 18 C7 06 00 00 00 00 C7 44 24 10 00 00 00 00 C7 44 24 14 00 00 00 00 31 ED E9 84 00 00 00 83 7C 24 38 00 74 17 83 EC 0C 57 FF 54 24 48 83 C4 10 85 C0 75 08 C7 06 00 00 00 00 EB 66 C7 06 00 00 00 00 3B 6C 24 14 75 32 C7 44 24 14 0A 00 00 00 85 ED 74 08 8D 54 2D 00 89 54 24 14 51 51 8B 44 24 1C C1 E0 02 50 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 45 89 44 24 10 0F B7 5F 10 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 2D 52 53 57 50 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule des_setkey_6da3ee1e88ad8977e5075f853e3881fe {
	meta:
		aliases = "des_setkey"
		size = "638"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 89 C3 E8 ?? ?? ?? ?? 8B 13 0F CA 8B 43 04 0F C8 89 C1 09 D1 74 14 3B 15 ?? ?? ?? ?? 75 0C 3B 05 ?? ?? ?? ?? 0F 84 45 02 00 00 89 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 89 D5 C1 ED 19 89 6C 24 04 89 D1 C1 E9 11 83 E1 7F 89 4C 24 08 89 D1 C1 E9 09 83 E1 7F 89 D6 D1 EE 83 E6 7F 89 C5 C1 ED 19 89 6C 24 0C 89 C3 C1 EB 11 83 E3 7F 89 C2 C1 EA 09 83 E2 7F D1 E8 83 E0 7F 8B 3C 8D ?? ?? ?? ?? 8B 6C 24 08 0B 3C AD ?? ?? ?? ?? 8B 6C 24 04 0B 3C AD ?? ?? ?? ?? 0B 3C B5 ?? ?? ?? ?? 8B 6C 24 0C 0B 3C AD ?? ?? ?? ?? 0B 3C 9D ?? ?? ?? ?? 0B 3C 95 ?? ?? ?? ?? 0B 3C 85 ?? ?? ?? ?? 8B 2C 8D ?? ?? ?? }
	condition:
		$pattern
}

rule _getopt_internal_20d67a358665c0a35f7fc24f4bc1466e {
	meta:
		aliases = "_getopt_internal"
		size = "1799"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? A1 ?? ?? ?? ?? 89 44 24 18 A3 ?? ?? ?? ?? 8B 4C 24 48 31 C0 80 39 3A 0F 95 C0 F7 D8 21 44 24 18 83 7C 24 40 00 0F 8E 9C 06 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 85 D2 74 0B 80 3D ?? ?? ?? ?? 00 75 79 EB 0A C7 05 ?? ?? ?? ?? 01 00 00 00 A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 95 C0 A2 ?? ?? ?? ?? 8B 4C 24 48 8A 11 80 FA 2D 75 0E C6 05 ?? ?? ?? ?? 02 41 89 4C 24 48 EB 1A 80 FA 2B 75 0D C6 05 ?? ?? ?? ?? 00 FF 44 24 48 EB 08 83 F0 01 A2 ?? ?? ?? ?? C6 }
	condition:
		$pattern
}

rule __GI_inet_pton_f6f9b6efb2e94630b492a4553bf3340a {
	meta:
		aliases = "inet_pton, __GI_inet_pton"
		size = "458"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 44 24 40 8B 74 24 44 83 F8 02 74 0B 83 F8 0A 0F 85 97 01 00 00 EB 10 8B 54 24 48 89 F0 E8 ?? ?? ?? ?? E9 93 01 00 00 53 6A 10 6A 00 8D 44 24 28 50 E8 ?? ?? ?? ?? 89 C7 8D 40 10 89 44 24 24 83 C4 10 80 3E 3A 75 0A 46 80 3E 3A 0F 85 57 01 00 00 89 74 24 18 C7 44 24 10 00 00 00 00 EB 79 46 51 51 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 1B C1 E5 04 2D ?? ?? ?? ?? 09 C5 81 FD FF FF 00 00 0F 86 84 00 00 00 E9 19 01 00 00 83 FB 3A 75 50 83 7C 24 0C 00 75 15 83 7C 24 10 00 0F 85 02 01 00 00 89 7C 24 10 89 74 24 18 EB 66 80 3E 00 0F 84 EF 00 00 00 8D 57 02 3B 54 24 14 }
	condition:
		$pattern
}

rule _svcauth_unix_2e8e21b58a7483d8d19e503283978935 {
	meta:
		aliases = "_svcauth_unix"
		size = "392"
		objfiles = "svc_authux@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 44 24 40 8B 78 18 8D 47 18 89 47 04 8D 87 18 01 00 00 89 47 14 8B 54 24 44 8B 52 20 89 54 24 08 6A 01 52 8B 4C 24 4C FF 71 1C 8D 5C 24 20 53 E8 ?? ?? ?? ?? 5E 5D FF 74 24 10 53 8B 44 24 28 FF 50 18 89 C2 83 C4 10 85 C0 0F 84 8D 00 00 00 8B 00 0F C8 89 07 8B 72 04 0F CE 81 FE FF 00 00 00 0F 87 F3 00 00 00 8D 5A 08 51 56 53 FF 77 04 E8 ?? ?? ?? ?? 8B 47 04 C6 04 30 00 8D 6E 03 83 E5 FC 8D 14 2B 8B 02 0F C8 89 47 08 8B 42 04 0F C8 89 47 0C 8B 4A 08 0F C9 83 C4 10 83 F9 10 0F 87 B5 00 00 00 8D 5A 0C 89 4F 10 31 F6 EB 0E 8B 03 0F C8 83 C3 04 8B 57 14 89 04 B2 46 39 CE 72 EE }
	condition:
		$pattern
}

rule __ns_name_ntop_40bb87efc8921f4b166e5ca8fffa66c4 {
	meta:
		aliases = "__GI___ns_name_ntop, __ns_name_ntop"
		size = "368"
		objfiles = "ns_name@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 4C 24 44 89 CF 03 7C 24 48 8B 6C 24 40 89 CB E9 04 01 00 00 0F B6 C0 89 44 24 1C A8 C0 0F 85 12 01 00 00 39 CB 75 04 89 CB EB 0C 39 FB 0F 83 02 01 00 00 C6 03 2E 43 8B 54 24 1C 8D 04 13 39 F8 0F 83 EF 00 00 00 45 E9 C1 00 00 00 8A 55 00 80 FA 2E 74 1F 77 0A 80 FA 22 74 18 80 FA 24 EB 0D 80 FA 40 74 0E 80 FA 5C 74 09 80 FA 3B 0F 85 DC 00 00 00 8D 43 01 39 F8 0F 83 B7 00 00 00 C6 03 5C 88 53 01 83 C3 02 EB 7F 8D 43 03 39 F8 0F 83 A1 00 00 00 C6 03 5C 0F B6 D2 66 89 54 24 12 B2 64 66 8B 44 24 12 F6 F2 0F B6 C0 8A 80 ?? ?? ?? ?? 88 43 01 66 8B 44 24 12 31 D2 BE 64 00 00 00 }
	condition:
		$pattern
}

rule _stdio_fopen_60961d599672c42fbfc9d62465d8f83d {
	meta:
		aliases = "_stdio_fopen"
		size = "564"
		objfiles = "_fopen@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 5C 24 40 8B 54 24 44 8B 6C 24 48 8B 7C 24 4C 8A 02 3C 72 74 3E BE 41 02 00 00 3C 77 74 37 66 BE 41 04 3C 61 74 2F E8 ?? ?? ?? ?? C7 00 16 00 00 00 85 ED 0F 84 E7 01 00 00 F6 45 01 20 0F 84 DD 01 00 00 83 EC 0C 55 E8 ?? ?? ?? ?? 31 ED E9 C8 01 00 00 31 F6 8D 42 01 80 7A 01 62 74 02 89 D0 80 78 01 2B 75 08 89 F0 83 C8 01 8D 70 01 85 ED 75 32 83 EC 0C 6A 50 E8 ?? ?? ?? ?? 89 C5 83 C4 10 85 C0 0F 84 99 01 00 00 66 C7 00 00 20 C7 40 08 00 00 00 00 83 EC 0C 8D 40 38 50 E8 ?? ?? ?? ?? 83 C4 10 85 FF 78 49 89 7D 04 89 F2 81 E2 03 80 00 00 42 8D 43 01 21 D0 39 D0 0F 85 65 FF FF }
	condition:
		$pattern
}

rule _stdlib_strto_ll_8405528fefbc2f597cc325841709372e {
	meta:
		aliases = "_stdlib_strto_ll"
		size = "531"
		objfiles = "_stdlib_strto_ll@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 5C 24 40 8B 6C 24 48 89 DF EB 01 47 8A 0F 0F BE D1 A1 ?? ?? ?? ?? F6 04 50 20 75 EF 80 F9 2B 74 11 C6 44 24 27 00 80 F9 2D 75 0D C6 44 24 27 01 EB 05 C6 44 24 27 00 47 89 D9 F7 C5 EF FF FF FF 75 24 83 C5 0A 80 3F 30 75 12 47 83 ED 02 8A 07 83 C8 20 89 F9 3C 78 75 03 01 ED 47 83 FD 10 7E 05 BD 10 00 00 00 8D 45 FE C7 44 24 18 00 00 00 00 C7 44 24 1C 00 00 00 00 83 F8 22 0F 87 1A 01 00 00 89 6C 24 10 89 E8 C1 F8 1F 89 44 24 14 EB 02 89 F9 8A 17 8D 42 D0 3C 09 76 0D 83 CA 20 B0 28 80 FA 60 76 03 8D 42 A9 0F B6 F0 39 EE 0F 8D E8 00 00 00 47 81 7C 24 1C FF FF FF 03 77 3C 89 }
	condition:
		$pattern
}

rule _stdlib_wcsto_ll_65901d1461c58bf24eeb9cee2999986e {
	meta:
		aliases = "_stdlib_wcsto_ll"
		size = "556"
		objfiles = "_stdlib_wcsto_ll@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 5C 24 40 8B 6C 24 48 89 DF EB 03 83 C7 04 83 EC 0C FF 37 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 EC 8B 07 83 F8 2B 74 11 C6 44 24 27 00 83 F8 2D 75 0F C6 44 24 27 01 EB 05 C6 44 24 27 00 83 C7 04 89 DA F7 C5 EF FF FF FF 75 29 83 C5 0A 83 3F 30 75 17 83 C7 04 83 ED 02 8B 07 83 C8 20 89 FA 83 F8 78 75 05 01 ED 83 C7 04 83 FD 10 7E 05 BD 10 00 00 00 8D 45 FE C7 44 24 18 00 00 00 00 C7 44 24 1C 00 00 00 00 83 F8 22 0F 87 27 01 00 00 89 6C 24 10 89 E8 C1 F8 1F 89 44 24 14 EB 02 89 FA 8B 1F 8D 43 D0 8D 4B D0 83 F8 09 76 14 89 D8 83 C8 20 B1 28 83 F8 60 76 08 88 D8 83 C8 20 8D 48 A9 }
	condition:
		$pattern
}

rule authunix_validate_d5b046105a3785b5300a0bdf7f86792a {
	meta:
		aliases = "authunix_validate"
		size = "154"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 6C 24 40 8B 44 24 44 83 38 02 75 79 8B 75 24 6A 01 FF 70 08 FF 70 04 8D 7C 24 20 57 E8 ?? ?? ?? ?? 8B 46 10 83 C4 10 85 C0 74 13 83 EC 0C 50 E8 ?? ?? ?? ?? C7 46 10 00 00 00 00 83 C4 10 50 50 8D 5E 0C 53 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 06 56 6A 0C 53 EB 1E C7 44 24 14 02 00 00 00 51 51 53 57 E8 ?? ?? ?? ?? C7 46 10 00 00 00 00 83 C4 0C 6A 0C 56 55 E8 ?? ?? ?? ?? 83 C4 10 89 E8 E8 ?? ?? ?? ?? B8 01 00 00 00 83 C4 2C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule svcudp_recv_5984305a9f9628f8b0fb9a3eb0071577 {
	meta:
		aliases = "svcudp_recv"
		size = "507"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 6C 24 40 8B 75 30 8D 45 34 89 44 24 0C 8D 5D 3C C7 44 24 28 10 00 00 00 8B 54 24 0C 89 54 24 14 89 DF 83 7B 0C 00 8D 55 10 74 4E 8B 45 2C 89 45 34 8B 06 8B 4C 24 14 89 41 04 89 4B 08 C7 43 0C 01 00 00 00 89 55 3C C7 43 04 10 00 00 00 8D 45 58 89 43 10 C7 43 14 DC 00 00 00 50 6A 00 53 FF 75 00 E8 ?? ?? ?? ?? 89 C2 83 C4 10 85 C0 78 25 8B 43 04 89 44 24 28 EB 1C 50 50 8D 44 24 30 50 52 6A 00 FF 36 FF 75 2C FF 75 00 E8 ?? ?? ?? ?? 89 C2 83 C4 20 8B 44 24 28 89 45 0C 83 FA FF 75 13 E8 ?? ?? ?? ?? 83 38 04 0F 85 3A 01 00 00 E9 5C FF FF FF 83 FA 0F 0F 8E 2C 01 00 00 8D 5E 08 }
	condition:
		$pattern
}

rule svcudp_bufcreate_6721d87115e00db7b1d0b071b122de91 {
	meta:
		aliases = "__GI_svcudp_bufcreate, svcudp_bufcreate"
		size = "490"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 6C 24 40 8B 7C 24 44 C7 44 24 28 10 00 00 00 31 F6 83 FD FF 75 2B 53 6A 11 6A 02 6A 02 E8 ?? ?? ?? ?? 89 C5 83 C4 10 66 BE 01 00 85 C0 79 12 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 F6 00 00 00 51 6A 10 6A 00 8D 5C 24 20 53 E8 ?? ?? ?? ?? 66 C7 44 24 24 02 00 58 5A 53 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 16 66 C7 44 24 16 00 00 50 FF 74 24 2C 53 55 E8 ?? ?? ?? ?? 83 C4 10 50 8D 44 24 2C 50 53 55 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 2B 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 C7 44 24 08 00 00 00 00 85 F6 0F 84 25 01 00 00 83 EC 0C 55 E8 ?? ?? ?? ?? EB 7B 83 EC 0C 68 }
	condition:
		$pattern
}

rule rendezvous_request_8b4e28536fd017439f8f6aa3a85d742f {
	meta:
		aliases = "rendezvous_request"
		size = "104"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 74 24 40 8B 5E 2C 8D 6C 24 18 8D 7C 24 28 C7 44 24 28 10 00 00 00 50 57 55 FF 36 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 0C E8 ?? ?? ?? ?? 83 38 04 75 25 EB DB 8B 4B 04 8B 13 E8 ?? ?? ?? ?? 89 C3 56 6A 10 55 8D 40 10 50 E8 ?? ?? ?? ?? 8B 44 24 38 89 43 0C 83 C4 10 31 C0 83 C4 2C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule fclose_f1303fae229c1163f47188170d303891 {
	meta:
		aliases = "__GI_fclose, fclose"
		size = "268"
		objfiles = "fclose@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 74 24 40 8B 6E 34 85 ED 75 1F 8D 5E 38 57 53 68 ?? ?? ?? ?? 8D 44 24 28 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 31 FF F6 06 40 74 0E 83 EC 0C 56 E8 ?? ?? ?? ?? 89 C7 83 C4 10 83 EC 0C FF 76 04 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 03 83 CF FF C7 46 04 FF FF FF FF 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 18 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 40 A3 ?? ?? ?? ?? 58 5A 6A 01 53 E8 ?? ?? ?? ?? 8B 06 66 25 00 60 83 C8 30 66 89 06 83 C4 10 85 ED 75 11 55 55 6A 01 8D 44 24 28 50 E8 ?? ?? ?? ?? 83 C4 10 F6 46 01 40 74 0E 83 EC 0C FF 76 08 }
	condition:
		$pattern
}

rule __GI_fseeko64_ae67a260a890c07f6632c295a97f43d8 {
	meta:
		aliases = "fseeko64, __GI_fseeko64"
		size = "227"
		objfiles = "fseeko64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 74 24 40 8B 7C 24 4C 8B 44 24 44 8B 54 24 48 89 44 24 20 89 54 24 24 83 FF 02 76 13 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CB FF E9 A2 00 00 00 8B 6E 34 85 ED 75 1F 53 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 1C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 F6 06 40 74 10 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 4F 83 FF 01 75 14 51 51 8D 44 24 28 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 36 52 57 8D 44 24 28 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 22 66 83 26 B8 8B 46 08 89 46 10 89 46 14 89 46 18 89 46 1C C7 46 2C 00 00 00 00 C6 46 02 00 31 DB EB 03 83 CB FF 85 ED 75 11 }
	condition:
		$pattern
}

rule svctcp_create_9dfeec607d0adb4e5d57cda903af0fd5 {
	meta:
		aliases = "svctcp_create"
		size = "364"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 74 24 40 C7 44 24 28 10 00 00 00 31 ED 83 FE FF 75 2B 53 6A 06 6A 01 6A 02 E8 ?? ?? ?? ?? 89 C6 83 C4 10 66 BD 01 00 85 C0 79 12 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 D0 00 00 00 51 6A 10 6A 00 8D 5C 24 24 53 E8 ?? ?? ?? ?? 66 C7 44 24 28 02 00 58 5A 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 16 66 C7 44 24 1A 00 00 50 FF 74 24 2C 53 56 E8 ?? ?? ?? ?? 83 C4 10 57 8D 44 24 2C 50 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 11 53 53 6A 02 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 28 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 31 FF 85 ED 0F 84 A2 00 00 00 83 EC 0C 56 E8 ?? ?? ?? }
	condition:
		$pattern
}

rule freopen64_c3f2fa2e230bcabc75fbd1df64c0138e {
	meta:
		aliases = "freopen64"
		size = "257"
		objfiles = "freopen64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 74 24 48 8B 6E 34 85 ED 75 1F 8D 5E 38 50 53 68 ?? ?? ?? ?? 8D 44 24 28 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 7C 24 18 57 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 40 A3 ?? ?? ?? ?? 5B 58 6A 01 57 E8 ?? ?? ?? ?? 8B 1E 89 D8 80 E4 9F 66 89 06 83 E0 30 83 C4 10 83 F8 30 74 3B 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 0C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 0D ?? ?? ?? ?? 5A 59 6A 01 57 E8 ?? ?? ?? ?? 83 C4 10 6A FE 56 FF 74 24 4C FF 74 24 4C E8 ?? ?? ?? ?? 89 }
	condition:
		$pattern
}

rule freopen_fb8ba2531117013c2ae4ac1107023ab3 {
	meta:
		aliases = "freopen"
		size = "257"
		objfiles = "freopen@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 74 24 48 8B 6E 34 85 ED 75 1F 8D 5E 38 50 53 68 ?? ?? ?? ?? 8D 44 24 28 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 7C 24 18 57 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 40 A3 ?? ?? ?? ?? 5B 58 6A 01 57 E8 ?? ?? ?? ?? 8B 1E 89 D8 80 E4 9F 66 89 06 83 E0 30 83 C4 10 83 F8 30 74 3B 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 0C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 0D ?? ?? ?? ?? 5A 59 6A 01 57 E8 ?? ?? ?? ?? 83 C4 10 6A FF 56 FF 74 24 4C FF 74 24 4C E8 ?? ?? ?? ?? 89 }
	condition:
		$pattern
}

rule lockf64_a0ed670fc6cf6c337d50a9938b44cacf {
	meta:
		aliases = "__GI_lockf64, lockf64"
		size = "270"
		objfiles = "lockf64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C 8B 7C 24 44 8B 5C 24 48 8B 74 24 4C 89 D8 99 39 D6 75 04 39 DB 74 10 E8 ?? ?? ?? ?? C7 00 4B 00 00 00 E9 B8 00 00 00 51 6A 18 6A 00 8D 6C 24 20 55 E8 ?? ?? ?? ?? 66 C7 44 24 26 01 00 C7 44 24 28 00 00 00 00 C7 44 24 2C 00 00 00 00 89 5C 24 30 89 74 24 34 83 C4 10 83 FF 01 74 5B 7F 06 85 FF 74 4C EB 6F 83 FF 02 74 5C 83 FF 03 75 65 66 C7 44 24 14 00 00 52 55 6A 0C FF 74 24 4C E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 70 66 83 7C 24 14 02 74 66 8B 5C 24 28 E8 ?? ?? ?? ?? 39 C3 74 59 E8 ?? ?? ?? ?? C7 00 0D 00 00 00 EB 30 66 C7 44 24 14 02 00 EB 15 66 C7 44 24 14 01 00 BA 07 }
	condition:
		$pattern
}

rule __ieee754_sqrt_5eb7f8f85351d63682d3ee522de4ef5b {
	meta:
		aliases = "__ieee754_sqrt"
		size = "454"
		objfiles = "e_sqrt@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 2C C7 44 24 08 00 00 00 00 C7 44 24 0C 00 00 00 00 DD 44 24 40 DD 14 24 DD 54 24 10 8B 54 24 14 8B 5C 24 10 89 D0 25 00 00 F0 7F 3D 00 00 F0 7F 75 0A D8 C8 DC 04 24 E9 76 01 00 00 DD D8 85 D2 7F 1F 89 D0 25 FF FF FF 7F 09 D8 0F 84 64 01 00 00 85 D2 74 0C DD 04 24 D8 E0 D8 F0 E9 51 01 00 00 31 C9 89 D7 C1 FF 14 74 0D EB 36 83 E9 15 89 DA C1 EA 0B C1 E3 15 85 D2 74 F1 31 F6 EB 03 01 D2 46 F7 C2 00 00 10 00 74 F5 8D 46 FF 89 CF 29 C7 B9 20 00 00 00 29 F1 89 D8 D3 E8 09 C2 89 F1 D3 E3 81 EF FF 03 00 00 89 7C 24 24 81 E2 FF FF 0F 00 81 CA 00 00 10 00 83 E7 01 74 0A 89 D8 C1 E8 1F }
	condition:
		$pattern
}

rule __res_search_b7b0afd5f0d42ef42d457526a773253a {
	meta:
		aliases = "__res_search"
		size = "706"
		objfiles = "res_query@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 30 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 28 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 5F 5D 6A 01 53 E8 ?? ?? ?? ?? 83 C4 10 83 7C 24 40 00 74 14 83 7C 24 4C 00 74 0D 83 E6 01 75 18 E8 ?? ?? ?? ?? 40 75 10 E8 ?? ?? ?? ?? C7 00 FF FF FF FF E9 42 02 00 00 E8 ?? ?? ?? ?? 89 44 24 0C C7 00 00 00 00 00 E8 ?? ?? ?? ?? 89 C7 C7 00 01 00 00 00 8B 54 24 40 C7 44 24 14 00 00 00 00 EB 0D 3C 2E 0F 94 C0 0F B6 C0 01 44 24 14 42 8A 02 84 C0 75 ED 31 ED 3B 54 24 40 76 0A 80 7A FF 2E 0F 94 C0 0F B6 E8 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 74 24 28 56 E8 ?? ?? ?? }
	condition:
		$pattern
}

rule mallinfo_aedbcc58ca1d9270dc6f2d13a0a8dbcb {
	meta:
		aliases = "__GI_mallinfo, mallinfo"
		size = "320"
		objfiles = "mallinfo@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 30 8B 7C 24 44 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 28 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 3D ?? ?? ?? ?? 00 75 10 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 A1 ?? ?? ?? ?? 8B 40 04 89 44 24 04 31 C9 C7 44 24 08 00 00 00 00 C7 44 24 10 00 00 00 00 EB 1F 8B 14 8D ?? ?? ?? ?? EB 11 FF 44 24 10 8B 42 04 83 E0 FC 01 44 24 08 8B 52 08 85 D2 75 EB 41 83 F9 09 76 DC 8B 44 24 04 83 E0 FC 8B 6C 24 08 01 C5 BB 01 00 00 00 C7 44 24 0C 01 00 00 00 EB 20 8D 0C DD ?? ?? ?? ?? 8B 51 0C EB 0F FF 44 24 0C 8B 42 04 83 E0 FC 01 C5 8B 52 0C 39 CA 75 ED 43 83 }
	condition:
		$pattern
}

rule __GI_rtime_afa72f1acb3ee976e4f038655395a5a7 {
	meta:
		aliases = "rtime, __GI_rtime"
		size = "353"
		objfiles = "rtime@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 30 8B 7C 24 44 8B 6C 24 4C 83 FD 01 19 DB 83 C3 02 6A 00 53 6A 02 E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 C0 0F 88 28 01 00 00 66 C7 07 02 00 66 C7 47 02 00 25 83 FB 02 0F 85 AA 00 00 00 50 50 6A 10 57 6A 00 6A 04 8D 44 24 40 50 56 E8 ?? ?? ?? ?? 83 C4 20 85 C0 0F 88 9C 00 00 00 8B 4D 04 BB E8 03 00 00 89 C8 31 D2 F7 F3 89 C1 69 45 00 E8 03 00 00 8D 3C 01 89 74 24 1C 66 C7 44 24 20 01 00 8D 6C 24 1C 53 57 6A 01 55 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 79 0A E8 ?? ?? ?? ?? 83 38 04 74 E3 83 FB 00 7F 0F 75 4F E8 ?? ?? ?? ?? C7 00 6E 00 00 00 EB 42 C7 44 24 24 10 00 00 00 8D 44 24 0C 51 }
	condition:
		$pattern
}

rule do_des_d9dd1f5a41be298b56ff79f5c2e83602 {
	meta:
		aliases = "do_des"
		size = "795"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 34 89 D5 89 4C 24 04 BA 01 00 00 00 83 7C 24 4C 00 0F 84 F4 02 00 00 7E 12 C7 44 24 28 ?? ?? ?? ?? C7 44 24 2C ?? ?? ?? ?? EB 14 F7 5C 24 4C C7 44 24 28 ?? ?? ?? ?? C7 44 24 2C ?? ?? ?? ?? 89 C2 C1 EA 18 89 54 24 08 89 C2 C1 EA 10 81 E2 FF 00 00 00 0F B6 CC 89 4C 24 0C 25 FF 00 00 00 89 44 24 10 89 EE C1 EE 18 89 E8 C1 E8 10 25 FF 00 00 00 89 04 24 89 EB 0F B6 FF 89 E9 81 E1 FF 00 00 00 8B 6C 24 08 8B 1C AD ?? ?? ?? ?? 8B 44 24 10 0B 1C 85 ?? ?? ?? ?? 0B 1C 95 ?? ?? ?? ?? 8B 6C 24 0C 0B 1C AD ?? ?? ?? ?? 0B 1C B5 ?? ?? ?? ?? 0B 1C 8D ?? ?? ?? ?? 8B 04 24 0B 1C 85 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule llround_9e6d3d92229bf5edfe6e19810a4170a1 {
	meta:
		aliases = "__GI_llround, llround"
		size = "333"
		objfiles = "s_llround@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 34 DD 44 24 48 DD 54 24 08 DD 5C 24 10 8B 44 24 14 8B 7C 24 10 89 C5 C1 ED 14 81 E5 FF 07 00 00 8D 9D 01 FC FF FF 99 83 CA 01 89 54 24 1C 89 C2 81 E2 FF FF 0F 00 81 CA 00 00 10 00 83 FB 13 7F 35 85 DB 79 19 31 F6 31 FF 43 0F 85 EB 00 00 00 8B 44 24 1C 99 89 C6 89 D7 E9 DD 00 00 00 B8 00 00 08 00 88 D9 D3 F8 01 D0 B9 14 00 00 00 29 D9 D3 E8 89 C6 EB 4F 83 FB 3E 7F 73 83 FB 33 7E 29 89 D1 31 DB 89 CB B9 00 00 00 00 89 C8 09 F8 89 C6 89 DF 8D 8D CD FB FF FF 0F A5 F7 D3 E6 F6 C1 20 74 76 89 F7 31 F6 EB 70 8D 8D ED FB FF FF B8 00 00 00 80 D3 E8 8D 34 38 39 FE 83 D2 00 83 FB 14 75 }
	condition:
		$pattern
}

rule inet_ntop4_d4ca5bc7175e0bb90e40375189f7dc70 {
	meta:
		aliases = "inet_ntop4"
		size = "241"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C 89 44 24 14 89 54 24 10 89 4C 24 0C C6 44 24 2B 00 31 ED 31 F6 E9 86 00 00 00 8B 44 24 14 01 E8 89 44 24 18 0F B6 10 B1 64 89 D0 F6 F1 88 C1 8D 41 30 88 44 34 2B 8D 7E 01 89 F3 3C 30 75 23 B1 0A 89 D0 F6 F1 0F B6 C0 B9 0A 00 00 00 31 D2 66 F7 F1 83 C2 30 88 54 34 2B 80 FA 30 74 21 89 FB EB 1D B1 0A 89 D0 F6 F1 0F B6 C0 B9 0A 00 00 00 31 D2 66 F7 F1 83 C2 30 88 54 3C 2B 8D 5E 02 8B 54 24 18 0F B6 02 B9 0A 00 00 00 31 D2 66 F7 F1 83 C2 30 88 54 1C 2B C6 44 1C 2C 2E 8D 73 02 45 83 FD 03 0F 8E 71 FF FF FF C6 44 34 2A 00 83 EC 0C 8D 5C 24 37 53 E8 ?? ?? ?? ?? 83 C4 10 3B 44 24 }
	condition:
		$pattern
}

rule tcsetattr_6a7fc83854eccd4374849932d711ebde {
	meta:
		aliases = "__GI_tcsetattr, tcsetattr"
		size = "258"
		objfiles = "tcsetattr@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C 8B 44 24 54 8B 7C 24 58 83 F8 01 74 10 83 F8 02 74 22 BE 02 54 00 00 85 C0 74 1E EB 07 BE 03 54 00 00 EB 15 E8 ?? ?? ?? ?? C7 00 16 00 00 00 E9 B6 00 00 00 BE 04 54 00 00 8B 07 25 FF FF FF 7F 89 44 24 18 8B 47 04 89 44 24 1C 8B 47 08 89 44 24 20 8B 47 0C 89 44 24 24 8A 47 10 88 44 24 28 52 6A 13 8D 47 11 50 8D 44 24 35 50 E8 ?? ?? ?? ?? 83 C4 0C 8D 44 24 1C 50 56 FF 74 24 5C E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 75 65 81 FE 02 54 00 00 75 5D E8 ?? ?? ?? ?? 89 C6 8B 28 50 8D 44 24 1C 50 68 01 54 00 00 FF 74 24 5C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 04 89 2E EB 35 8B 4F 08 8B 5C }
	condition:
		$pattern
}

rule readunix_eb5fabec25bf6d125faa4645a93bf887 {
	meta:
		aliases = "readunix"
		size = "361"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C 8B 74 24 50 8B 6C 24 58 8B 4E 0C BB E8 03 00 00 89 C8 99 F7 FB 89 C1 69 46 08 E8 03 00 00 8D 3C 01 66 31 DB 85 ED 0F 84 2C 01 00 00 8B 06 89 44 24 30 66 C7 44 24 34 01 00 8D 5C 24 30 50 57 6A 01 53 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 74 10 85 C0 75 30 C7 86 84 00 00 00 05 00 00 00 EB 1C E8 ?? ?? ?? ?? 83 38 04 74 D4 C7 86 84 00 00 00 04 00 00 00 8B 00 89 86 88 00 00 00 83 CB FF E9 D5 00 00 00 8B 3E 8B 44 24 54 89 44 24 28 89 6C 24 2C 8D 44 24 28 89 44 24 14 C7 44 24 18 01 00 00 00 C7 44 24 0C 00 00 00 00 C7 44 24 10 00 00 00 00 C7 44 24 1C ?? ?? ?? ?? C7 44 24 20 18 00 00 00 }
	condition:
		$pattern
}

rule writeunix_caba3b82f8dd883c6eec41bb3093af2f {
	meta:
		aliases = "writeunix"
		size = "248"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C 8B 74 24 54 8B 7C 24 58 89 FB E9 D0 00 00 00 8B 44 24 50 8B 00 89 44 24 08 E8 ?? ?? ?? ?? 89 44 24 28 E8 ?? ?? ?? ?? 89 44 24 2C E8 ?? ?? ?? ?? 89 44 24 30 50 6A 0C 8D 54 24 30 52 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 01 00 00 00 C7 05 ?? ?? ?? ?? 02 00 00 00 C7 05 ?? ?? ?? ?? 18 00 00 00 89 74 24 44 89 5C 24 48 8D 44 24 44 89 44 24 24 C7 44 24 28 01 00 00 00 C7 44 24 1C 00 00 00 00 C7 44 24 20 00 00 00 00 C7 44 24 2C ?? ?? ?? ?? C7 44 24 30 18 00 00 00 C7 44 24 34 00 00 00 00 83 C4 10 8D 6C 24 0C 50 6A 00 55 FF 74 24 14 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 1C E8 ?? }
	condition:
		$pattern
}

rule nextafter_0b9c9322597d4f7cdb535d4a4acfb8eb {
	meta:
		aliases = "__GI_nextafter, nextafter"
		size = "388"
		objfiles = "s_nextafter@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C C7 44 24 20 00 00 00 00 C7 44 24 24 00 00 00 00 C7 44 24 18 00 00 00 00 C7 44 24 1C 00 00 00 00 C7 44 24 10 00 00 00 00 C7 44 24 14 00 00 00 00 DD 44 24 50 DD 54 24 08 DD 44 24 58 DD 14 24 D9 C9 DD 5C 24 30 8B 54 24 34 8B 4C 24 30 DD 5C 24 28 8B 6C 24 2C 8B 7C 24 28 89 D6 81 E6 FF FF FF 7F 81 FE FF FF EF 7F 7E 0A 8D 86 00 00 10 80 09 C8 75 1B 8B 5C 24 2C 89 D8 25 FF FF FF 7F 3D FF FF EF 7F 7E 15 2D 00 00 F0 7F 09 F8 74 0C DD 44 24 08 DC 04 24 E9 CF 00 00 00 DD 44 24 08 DD 04 24 D9 C9 DA E9 DF E0 9E 7A 06 0F 84 C1 00 00 00 09 CE 75 37 81 E5 00 00 00 80 89 6C 24 24 C7 44 24 }
	condition:
		$pattern
}

rule __GI_lrint_66b779f6f71fc3162e8590cb2a7c68a8 {
	meta:
		aliases = "lrint, __GI_lrint"
		size = "272"
		objfiles = "s_lrint@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 3C DD 44 24 50 DD 14 24 DD 5C 24 18 8B 44 24 1C C1 E8 14 89 C2 81 E2 FF 07 00 00 81 EA FF 03 00 00 89 C5 C1 ED 0B 83 FA 13 7F 4B 31 DB 42 0F 8C CC 00 00 00 DD 04 ED ?? ?? ?? ?? DD 04 24 D8 C1 DD 5C 24 30 DD 44 24 30 DE E1 DD 5C 24 10 8B 44 24 14 89 C3 81 E3 FF FF 0F 00 81 CB 00 00 10 00 C1 E8 14 25 FF 07 00 00 B9 13 04 00 00 29 C1 D3 EB E9 84 00 00 00 83 FA 1E 7F 59 DD 04 ED ?? ?? ?? ?? DD 04 24 D8 C1 DD 5C 24 30 DD 44 24 30 DE E1 DD 5C 24 08 8B 44 24 0C 8B 74 24 08 89 C2 C1 EA 14 81 E2 FF 07 00 00 8D BA 01 FC FF FF 25 FF FF 0F 00 0D 00 00 10 00 89 C3 83 FF 14 74 3B 8D 8A ED }
	condition:
		$pattern
}

rule malloc_c655758f4d8c5e960efdc94f2904ba4b {
	meta:
		aliases = "malloc"
		size = "1982"
		objfiles = "malloc@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 40 8B 5C 24 54 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 38 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 FB DF 76 12 E8 ?? ?? ?? ?? C7 00 0C 00 00 00 31 DB E9 6F 07 00 00 8D 43 0B C7 44 24 10 10 00 00 00 83 F8 0F 76 07 83 E0 F8 89 44 24 10 8B 1D ?? ?? ?? ?? F6 C3 01 75 1D 85 DB 0F 85 6C 03 00 00 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 E9 57 03 00 00 39 5C 24 10 77 1E 8B 4C 24 10 C1 E9 03 8B 14 8D ?? ?? ?? ?? 85 D2 74 0C 8B 42 08 89 04 8D ?? ?? ?? ?? EB 35 81 7C 24 10 FF 00 00 00 77 33 8B 6C 24 10 C1 ED 03 8D 0C ED ?? ?? ?? ?? 8B 51 0C 39 CA 0F 84 77 }
	condition:
		$pattern
}

rule __ieee754_fmod_baa6a793d85a717bf998e5b006ee6ae4 {
	meta:
		aliases = "__ieee754_fmod"
		size = "802"
		objfiles = "e_fmod@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 44 C7 44 24 18 00 00 00 00 C7 44 24 1C 00 00 00 00 C7 44 24 10 00 00 00 00 C7 44 24 14 00 00 00 00 DD 44 24 58 DD 5C 24 08 DD 44 24 60 DD 1C 24 DD 44 24 08 DD 5C 24 28 8B 7C 24 28 DD 04 24 DD 5C 24 20 8B 44 24 20 89 44 24 3C 8B 4C 24 2C 81 E1 00 00 00 80 89 4C 24 38 8B 54 24 2C 81 E2 FF FF FF 7F 8B 6C 24 24 81 E5 FF FF FF 7F 09 E8 74 1E 81 FA FF FF EF 7F 7F 16 8B 44 24 3C F7 D8 0B 44 24 3C C1 E8 1F 09 E8 3D 00 00 F0 7F 76 0E DD 44 24 08 DC 0C 24 D8 F0 E9 6F 02 00 00 39 EA 7F 27 0F 8C 69 02 00 00 3B 7C 24 3C 0F 82 5F 02 00 00 75 15 C1 6C 24 38 1F 8B 44 24 38 DD 04 C5 ?? ?? ?? }
	condition:
		$pattern
}

rule clnttcp_create_c2d5016723b6213c964636351eef9888 {
	meta:
		aliases = "__GI_clnttcp_create, clnttcp_create"
		size = "504"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 48 8B 5C 24 5C 8B 6C 24 68 6A 0C E8 ?? ?? ?? ?? 89 C7 C7 04 24 64 00 00 00 E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 FF 74 04 85 C0 75 2B E8 ?? ?? ?? ?? 89 C3 50 50 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 03 0C 00 00 00 C7 43 08 0C 00 00 00 E9 90 00 00 00 66 83 7B 02 00 75 24 6A 06 FF 74 24 5C FF 74 24 5C 53 E8 ?? ?? ?? ?? 83 C4 10 66 85 C0 0F 84 59 01 00 00 66 C1 C8 08 66 89 43 02 83 7D 00 00 79 70 50 6A 06 6A 01 6A 02 E8 ?? ?? ?? ?? 89 45 00 5A 59 6A 00 50 E8 ?? ?? ?? ?? 8B 45 00 83 C4 10 85 C0 78 11 51 6A 10 53 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 33 E8 ?? ?? ?? ?? 89 C3 }
	condition:
		$pattern
}

rule clntunix_create_f438a3a749d41e1e4e60787abec53e39 {
	meta:
		aliases = "__GI_clntunix_create, clntunix_create"
		size = "490"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 48 8B 6C 24 5C 68 C4 00 00 00 E8 ?? ?? ?? ?? 89 C6 C7 04 24 0C 00 00 00 E8 ?? ?? ?? ?? 89 C7 83 C4 10 85 C0 74 04 85 F6 75 28 E8 ?? ?? ?? ?? 89 C3 55 55 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 03 0C 00 00 00 C7 43 08 0C 00 00 00 EB 71 8B 44 24 5C 83 38 00 79 79 53 6A 00 6A 01 6A 01 E8 ?? ?? ?? ?? 89 C3 8B 54 24 6C 89 02 8D 45 02 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 85 DB 78 13 51 83 C0 03 50 55 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 37 E8 ?? ?? ?? ?? 89 C3 C7 00 0C 00 00 00 E8 ?? ?? ?? ?? 8B 00 89 43 08 8B 54 24 5C 8B 02 83 F8 FF 0F 84 0A 01 00 00 83 EC 0C 50 E8 ?? ?? ?? }
	condition:
		$pattern
}

rule regexec_e5eeb6cf68fd42a3d6c86540c22c8883 {
	meta:
		aliases = "__regexec, regexec"
		size = "275"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 48 8B 74 24 5C 8B 6C 24 64 8B 5C 24 6C FF 74 24 60 E8 ?? ?? ?? ?? 83 C4 0C 89 44 24 0C 8A 46 1C 83 F0 10 C0 E8 04 85 ED 0F 95 C2 89 D7 21 C7 6A 20 56 8D 44 24 1C 50 E8 ?? ?? ?? ?? 88 DA 83 E2 01 C1 E2 05 8A 44 24 3C 83 E0 9F D1 EB 83 E3 01 C1 E3 06 09 D0 09 D8 83 E0 F9 83 C8 04 88 44 24 3C 83 C4 10 31 C0 89 FA 84 D2 74 2F 89 6C 24 30 83 EC 0C 8D 04 ED 00 00 00 00 50 E8 ?? ?? ?? ?? 83 C4 10 BA 01 00 00 00 85 C0 74 77 89 44 24 34 8D 04 A8 89 44 24 38 8D 44 24 30 56 56 50 FF 74 24 14 6A 00 FF 74 24 1C FF 74 24 6C 8D 44 24 2C 50 E8 ?? ?? ?? ?? 89 C6 83 C4 20 89 F8 84 C0 74 3D 31 }
	condition:
		$pattern
}

rule __ivaliduser2_1e4304a48d3a5e99969ac7eec61af802 {
	meta:
		aliases = "__ivaliduser2"
		size = "734"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C 89 44 24 10 89 54 24 0C 89 4C 24 08 C7 44 24 48 00 00 00 00 C7 44 24 44 00 00 00 00 E9 7A 02 00 00 8B 54 24 44 8B 44 24 48 C6 44 02 FF 00 8B 5C 24 48 89 DE EB 01 46 8A 0E 84 C9 0F 84 5A 02 00 00 0F BE D1 A1 ?? ?? ?? ?? F6 04 50 20 75 E7 80 F9 23 0F 84 43 02 00 00 57 57 6A 0A 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 47 8B 54 24 10 8B 42 10 3B 42 18 73 0D 0F B6 10 40 8B 4C 24 10 89 41 10 EB 11 83 EC 0C FF 74 24 1C E8 ?? ?? ?? ?? 89 C2 83 C4 10 83 FA 0A 0F 84 FF 01 00 00 42 75 CA E9 F7 01 00 00 A1 ?? ?? ?? ?? 0F BF 04 08 88 03 43 8A 13 84 D2 74 11 0F BE C2 8D 0C 00 A1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI___xpg_strerror_r_8e0c3f2f52e10277a1d4327d8c27ca8f {
	meta:
		aliases = "strerror_r, __xpg_strerror_r, __GI___xpg_strerror_r"
		size = "183"
		objfiles = "__xpg_strerror_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C 8B 44 24 60 8B 7C 24 68 83 F8 7C 77 1B 89 C1 BE ?? ?? ?? ?? EB 07 80 3E 01 83 D9 00 46 85 C9 75 F5 31 ED 80 3E 00 75 2F 83 EC 0C 6A 00 6A F6 99 52 50 8D 44 24 67 50 E8 ?? ?? ?? ?? 8D 70 F2 83 C4 1C 6A 0E 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? BD 16 00 00 00 83 C4 10 31 C0 83 7C 24 64 00 0F 95 C0 F7 D8 21 C7 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 40 89 C3 39 F8 76 07 89 FB BD 22 00 00 00 85 DB 74 18 50 53 56 FF 74 24 70 E8 ?? ?? ?? ?? 8B 44 24 74 C6 44 03 FF 00 83 C4 10 85 ED 74 07 E8 ?? ?? ?? ?? 89 28 89 E8 83 C4 4C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_gethostbyname2_r_7a999590fbacee8a291a1062afaca670 {
	meta:
		aliases = "gethostbyname2_r, __GI_gethostbyname2_r"
		size = "765"
		objfiles = "gethostbyname2_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C 8B 44 24 64 8B 7C 24 68 8B 74 24 70 83 F8 02 75 2A 50 50 FF B4 24 80 00 00 00 FF B4 24 80 00 00 00 56 FF B4 24 80 00 00 00 57 FF 74 24 7C E8 ?? ?? ?? ?? 83 C4 20 E9 B3 02 00 00 83 F8 0A 0F 85 9E 02 00 00 E8 ?? ?? ?? ?? 8B 44 24 74 C7 00 00 00 00 00 83 7C 24 60 00 0F 84 84 02 00 00 E8 ?? ?? ?? ?? 89 C3 8B 28 C7 00 00 00 00 00 50 FF 74 24 7C FF 74 24 7C 56 FF 74 24 7C 57 6A 0A FF 74 24 7C E8 ?? ?? ?? ?? 83 C4 20 85 C0 0F 84 5C 02 00 00 8B 4C 24 78 8B 11 83 FA 01 74 0E 83 FA 04 74 21 42 0F 85 45 02 00 00 EB 0F 83 F8 02 0F 94 C0 0F B6 C0 89 44 24 04 EB 11 83 3B 02 0F 85 2B 02 }
	condition:
		$pattern
}

rule clnttcp_call_182c5baa6ae8725974de810dc953d494 {
	meta:
		aliases = "clnttcp_call"
		size = "587"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C 8B 44 24 78 8B 54 24 7C 8B 4C 24 60 8B 59 08 8D 73 4C 8D 4B 30 89 4C 24 10 83 7B 10 00 75 06 89 53 0C 89 43 08 83 7C 24 70 00 75 12 83 7B 08 00 75 0C 83 7B 0C 00 0F 95 C0 0F B6 F8 EB 05 BF 01 00 00 00 C7 44 24 14 02 00 00 00 8D 43 30 89 44 24 0C C7 43 4C 00 00 00 00 C7 43 24 00 00 00 00 8B 54 24 10 8B 02 48 89 02 0F C8 89 44 24 18 55 8B 43 50 FF 73 48 FF 74 24 14 56 FF 50 0C 83 C4 10 85 C0 74 3E 51 51 8B 43 50 8D 4C 24 6C 51 56 FF 50 04 83 C4 10 85 C0 74 29 8B 54 24 60 8B 02 52 52 8B 50 20 56 50 FF 52 04 83 C4 10 85 C0 74 12 50 50 FF 74 24 74 56 FF 54 24 78 83 C4 10 85 C0 }
	condition:
		$pattern
}

rule clntunix_call_99dc74bf13a04f6006b9276dd67822b5 {
	meta:
		aliases = "clntunix_call"
		size = "656"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C 8B 44 24 78 8B 54 24 7C 8B 4C 24 60 8B 59 08 8D B3 AC 00 00 00 8D 8B 90 00 00 00 89 4C 24 10 83 7B 10 00 75 06 89 53 0C 89 43 08 83 7C 24 70 00 75 12 83 7B 08 00 75 0C 83 7B 0C 00 0F 95 C0 0F B6 F8 EB 05 BF 01 00 00 00 C7 44 24 14 02 00 00 00 8D 83 90 00 00 00 89 44 24 0C C7 83 AC 00 00 00 00 00 00 00 C7 83 84 00 00 00 00 00 00 00 8B 54 24 10 8B 02 48 89 02 0F C8 89 44 24 18 55 8B 83 B0 00 00 00 FF B3 A8 00 00 00 FF 74 24 14 56 FF 50 0C 83 C4 10 85 C0 74 41 51 51 8B 83 B0 00 00 00 8D 4C 24 6C 51 56 FF 50 04 83 C4 10 85 C0 74 29 8B 54 24 60 8B 02 52 52 8B 50 20 56 50 FF 52 }
	condition:
		$pattern
}

rule __GI___res_query_008ee27441a6e5e47540efe78851e8e7 {
	meta:
		aliases = "__res_query, __GI___res_query"
		size = "244"
		objfiles = "res_query@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C 8B 6C 24 60 C7 44 24 48 00 00 00 00 85 ED 74 07 83 7C 24 64 01 74 0D E8 ?? ?? ?? ?? C7 00 03 00 00 00 EB 76 51 6A 28 6A 00 8D 7C 24 1C 57 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 44 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 58 5A 6A 01 53 E8 ?? ?? ?? ?? 5A 59 57 8D 44 24 54 50 68 ?? ?? ?? ?? 56 FF B4 24 80 00 00 00 55 E8 ?? ?? ?? ?? 89 C3 83 C4 20 85 C0 79 10 E8 ?? ?? ?? ?? C7 00 02 00 00 00 83 CB FF EB 44 83 EC 0C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 8B 44 24 68 39 44 24 14 75 1C 3B 5C 24 70 7E 04 8B 5C 24 }
	condition:
		$pattern
}

rule gethostbyname_r_577a4809eca1461f4f568cda7bdd4209 {
	meta:
		aliases = "__GI_gethostbyname_r, gethostbyname_r"
		size = "811"
		objfiles = "gethostbyname_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C 8B 6C 24 68 8B 5C 24 6C 8B 44 24 70 C7 00 00 00 00 00 B8 16 00 00 00 83 7C 24 60 00 0F 84 FA 02 00 00 E8 ?? ?? ?? ?? 89 C6 8B 38 C7 00 00 00 00 00 50 FF 74 24 78 FF 74 24 78 53 55 FF 74 24 78 6A 02 FF 74 24 7C E8 ?? ?? ?? ?? 83 C4 20 85 C0 0F 84 C6 02 00 00 8B 4C 24 74 8B 11 83 FA 01 74 15 83 FA 04 74 10 42 0F 85 AF 02 00 00 83 3E 02 0F 85 A6 02 00 00 89 3E 89 E8 F7 D8 83 E0 03 74 0C 39 C3 0F 82 8E 02 00 00 01 C5 29 C3 8B 44 24 74 C7 00 FF FF FF FF 83 FB 03 0F 86 77 02 00 00 8D 43 FC 83 F8 07 0F 86 6B 02 00 00 8D 55 04 89 14 24 8D 43 F4 89 6D 04 C7 42 04 00 00 00 00 83 F8 }
	condition:
		$pattern
}

rule __GI_getaddrinfo_8fbbf6e5d83c0d0e5b4ea4827d388ac7 {
	meta:
		aliases = "getaddrinfo, __GI_getaddrinfo"
		size = "643"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C 8B 74 24 64 8B 7C 24 68 C7 44 24 48 00 00 00 00 83 7C 24 60 00 74 19 8B 44 24 60 80 38 2A 75 10 80 78 01 00 0F 95 C0 0F B6 C0 F7 D8 21 44 24 60 85 F6 74 12 80 3E 2A 75 0D 31 C0 80 7E 01 00 0F 95 C0 F7 D8 21 C6 8B 54 24 60 09 F2 0F 84 18 02 00 00 85 FF 75 14 57 6A 20 6A 00 8D 5C 24 28 53 E8 ?? ?? ?? ?? 89 DF 83 C4 10 8B 07 A9 C0 FB FF FF 0F 85 FA 01 00 00 A8 02 74 0B 83 7C 24 60 00 0F 84 EB 01 00 00 85 F6 74 62 80 3E 00 74 5D 89 74 24 3C 53 6A 0A 8D 44 24 4C 50 56 E8 ?? ?? ?? ?? 89 44 24 50 83 C4 10 8B 44 24 44 80 38 00 74 1C F6 47 01 04 0F 85 AF 01 00 00 C7 44 24 40 FF FF }
	condition:
		$pattern
}

rule authunix_refresh_2da1876748b86582a8e0c54de10974f9 {
	meta:
		aliases = "authunix_refresh"
		size = "227"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C 8B 7C 24 60 8B 5F 24 8B 47 04 31 ED 3B 43 04 0F 84 BD 00 00 00 FF 43 18 C7 44 24 30 00 00 00 00 C7 44 24 40 00 00 00 00 6A 01 FF 73 08 FF 73 04 8D 74 24 20 56 E8 ?? ?? ?? ?? 58 5A 8D 44 24 34 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 54 50 50 6A 00 8D 44 24 50 50 E8 ?? ?? ?? ?? 8B 44 24 54 89 44 24 3C C7 44 24 24 00 00 00 00 59 5D 6A 00 56 8B 44 24 28 FF 50 14 58 5A 8D 44 24 34 50 56 E8 ?? ?? ?? ?? 89 C5 83 C4 10 85 C0 74 14 50 6A 0C 53 57 E8 ?? ?? ?? ?? 89 F8 E8 ?? ?? ?? ?? 83 C4 10 C7 44 24 14 02 00 00 00 50 50 8D 44 24 34 50 8D 5C 24 20 53 E8 ?? ?? ?? ?? 8B 44 24 28 8B 40 }
	condition:
		$pattern
}

rule __strtofpmax_1b7a843f738ba6849e0d4ea855929d67 {
	meta:
		aliases = "__strtofpmax"
		size = "522"
		objfiles = "__strtofpmax@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C 8B 7C 24 68 8B 5C 24 60 EB 01 43 A1 ?? ?? ?? ?? 89 44 24 38 8A 13 0F BE C2 8B 4C 24 38 F6 04 41 20 75 E7 80 FA 2B 74 17 C7 44 24 3C 00 00 00 00 80 FA 2D 75 13 C7 44 24 3C 01 00 00 00 EB 08 C7 44 24 3C 00 00 00 00 43 83 C9 FF D9 EE 31 F6 EB 29 81 F9 00 00 00 80 83 D9 FF 85 C9 75 05 80 FA 30 74 16 41 83 F9 15 7F 10 D8 0D ?? ?? ?? ?? 83 E8 30 50 DA 04 24 83 C4 04 43 8A 13 0F BE C2 8B 6C 24 38 F6 44 45 00 08 75 C7 80 FA 2E 75 09 85 F6 75 05 43 89 DE EB E2 85 C9 79 6F 85 F6 75 62 31 FF 31 F6 8D 6F 01 EB 2F 46 80 BC 2E ?? ?? ?? ?? 00 75 24 DD D8 D9 EE 57 DA 3C 24 83 C4 04 83 7C }
	condition:
		$pattern
}

rule __wcstofpmax_cee26b2b8b22d5cda2409ad782a58b73 {
	meta:
		aliases = "__wcstofpmax"
		size = "538"
		objfiles = "__wcstofpmax@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C 8B 7C 24 68 8B 5C 24 60 EB 03 83 C3 04 83 EC 0C FF 33 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 EC 8B 03 83 F8 2B 74 17 C7 44 24 3C 00 00 00 00 83 F8 2D 75 15 C7 44 24 3C 01 00 00 00 EB 08 C7 44 24 3C 00 00 00 00 83 C3 04 83 CA FF D9 EE 31 C9 EB 2B 81 FA 00 00 00 80 83 DA FF 85 D2 75 05 83 F8 30 74 16 42 83 FA 15 7F 10 D8 0D ?? ?? ?? ?? 83 E8 30 50 DA 04 24 83 C4 04 83 C3 04 A1 ?? ?? ?? ?? 89 44 24 38 8B 03 8B 74 24 38 F6 04 46 08 75 C0 83 F8 2E 75 0B 85 C9 75 07 83 C3 04 89 D9 EB DB 85 D2 79 6E 85 C9 75 61 31 FF 31 F6 8D 6F 01 EB 2F 46 80 BC 2E ?? ?? ?? ?? 00 75 24 DD D8 D9 EE 57 }
	condition:
		$pattern
}

rule __time_localtime_tzi_bba0918d0e4f81d640df3b8d1dcc8ccf {
	meta:
		aliases = "__time_localtime_tzi"
		size = "709"
		objfiles = "_time_localtime_tzi@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C C7 44 24 1C 00 00 00 00 6B 44 24 1C 18 8B 5C 24 68 01 C3 B8 80 3A 09 00 2B 03 8B 4C 24 60 8B 11 B9 F9 FF FF FF 81 FA 7F C5 F6 7F 7E 07 F7 D8 B9 07 00 00 00 01 D0 89 44 24 48 56 FF 74 24 68 51 8D 74 24 54 56 E8 ?? ?? ?? ?? 8B 44 24 2C 8B 7C 24 74 89 47 20 8B 03 F7 D8 89 47 24 8D 7B 10 BE ?? ?? ?? ?? 83 C4 10 EB 19 51 51 57 8D 5E 04 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 04 89 D8 EB 50 8B 36 85 F6 75 E3 52 52 6A 07 57 E8 ?? ?? ?? ?? 83 C4 10 83 F8 06 77 33 83 EC 0C 6A 0C E8 ?? ?? ?? ?? 89 C2 83 C4 10 85 C0 74 20 A1 ?? ?? ?? ?? 89 02 89 15 ?? ?? ?? ?? 50 50 57 8D 5A 04 53 E8 ?? }
	condition:
		$pattern
}

rule __ieee754_remainder_52c29ffe4eb910c4a60d831aa97a4540 {
	meta:
		aliases = "__ieee754_remainder"
		size = "368"
		objfiles = "e_remainder@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C DD 44 24 60 DD 54 24 10 DD 44 24 68 DD 54 24 08 D9 C9 DD 54 24 30 D9 C9 8B 44 24 34 89 44 24 3C 8B 6C 24 30 DD 54 24 28 8B 7C 24 28 8B 74 24 2C 81 E6 FF FF FF 7F 89 F0 09 F8 75 04 DE C9 EB 30 DD D8 DD D8 8B 5C 24 3C 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7F 12 81 FE FF FF EF 7F 7E 19 8D 86 00 00 10 80 09 F8 74 37 DD 44 24 10 DC 4C 24 08 D8 F0 E9 EA 00 00 00 81 FE FF FF DF 7F 7F 20 DD 44 24 08 D8 C0 83 EC 08 DD 1C 24 FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? DD 5C 24 20 83 C4 10 29 F3 29 FD 09 EB 75 0F DD 44 24 10 DC 0D ?? ?? ?? ?? E9 AB 00 00 00 51 51 FF 74 24 1C FF 74 24 1C E8 }
	condition:
		$pattern
}

rule __ieee754_atan2_26213d87333e9386f8ea0bf6c5dc96e2 {
	meta:
		aliases = "__ieee754_atan2"
		size = "584"
		objfiles = "e_atan2@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C DD 44 24 60 DD 5C 24 10 DD 44 24 68 DD 54 24 08 DD 5C 24 30 8B 44 24 34 89 44 24 44 8B 4C 24 30 89 C7 81 E7 FF FF FF 7F DD 44 24 10 DD 5C 24 28 8B 54 24 28 89 C8 F7 D8 09 C8 C1 E8 1F 09 F8 3D 00 00 F0 7F 77 1E 8B 6C 24 2C 89 EE 81 E6 FF FF FF 7F 89 D0 F7 D8 09 D0 C1 E8 1F 09 F0 3D 00 00 F0 7F 76 0D DD 44 24 10 DC 44 24 08 E9 C0 01 00 00 8B 44 24 44 2D 00 00 F0 3F 09 C8 75 14 DD 44 24 10 DD 5C 24 60 83 C4 4C 5B 5E 5F 5D E9 ?? ?? ?? ?? 8B 5C 24 44 C1 FB 1E 83 E3 02 89 E8 C1 E8 1F 09 C3 09 F2 75 18 83 FB 02 0F 84 8C 00 00 00 0F 8E 7F 01 00 00 83 FB 03 0F 84 88 00 00 00 09 F9 }
	condition:
		$pattern
}

rule clntraw_call_fd5402eb3fed8c19db90d1f189d57ff5 {
	meta:
		aliases = "clntraw_call"
		size = "436"
		objfiles = "clnt_raw@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 4C E8 ?? ?? ?? ?? 8B 98 A0 00 00 00 8D 73 0C BF 10 00 00 00 85 DB 0F 84 88 01 00 00 8D 83 84 22 00 00 89 44 24 08 C7 43 0C 00 00 00 00 57 57 8B 43 10 6A 00 56 FF 50 14 8B 54 24 18 FF 02 83 C4 0C 8B 43 10 FF B3 9C 22 00 00 52 56 FF 50 0C 83 C4 10 85 C0 0F 84 25 01 00 00 51 51 8B 43 10 8D 54 24 6C 52 56 FF 50 04 83 C4 10 85 C0 0F 84 0C 01 00 00 8B 54 24 60 8B 02 52 52 8B 50 20 56 50 FF 52 04 83 C4 10 85 C0 0F 84 F1 00 00 00 55 55 FF 74 24 74 56 FF 54 24 78 83 C4 10 85 C0 0F 84 DB 00 00 00 83 EC 0C 8B 43 10 56 FF 50 10 C7 04 24 01 00 00 00 E8 ?? ?? ?? ?? C7 43 0C 01 00 00 00 59 }
	condition:
		$pattern
}

rule _dl_map_cache_05fdee318270969493b8cae813d29c89 {
	meta:
		aliases = "_dl_map_cache"
		size = "497"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 50 8B 15 ?? ?? ?? ?? 83 C8 FF 83 FA FF 0F 84 D0 01 00 00 85 D2 0F 85 C6 01 00 00 BE ?? ?? ?? ?? 8D 4C 24 0C 89 F0 53 89 C3 B8 6A 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0D F7 DB 89 1D ?? ?? ?? ?? E9 8B 01 00 00 85 C0 0F 85 83 01 00 00 31 D2 89 C1 53 89 F3 B8 05 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0D F7 DF 89 3D ?? ?? ?? ?? E9 5E 01 00 00 85 C0 0F 88 56 01 00 00 8B 4C 24 20 89 0D ?? ?? ?? ?? C7 44 24 4C 00 00 00 00 BE 01 00 00 00 89 D8 89 F2 53 89 C3 55 8B 6C 24 4C B8 C0 00 00 00 CD 80 5D 5B 89 C1 3D 00 F0 FF FF 76 0B F7 D9 89 0D ?? ?? ?? ?? 83 C9 FF 89 0D ?? ?? ?? ?? }
	condition:
		$pattern
}

rule llrint_a2f7b3e7743b73e73fa80127f50e26a8 {
	meta:
		aliases = "__GI_llrint, llrint"
		size = "407"
		objfiles = "s_llrint@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 54 DD 44 24 68 DD 54 24 08 DD 5C 24 20 8B 44 24 24 8B 74 24 20 89 C2 C1 EA 14 81 E2 FF 07 00 00 89 54 24 04 81 EA FF 03 00 00 89 C1 C1 E9 1F 89 4C 24 2C 83 FA 13 7F 54 DD 04 CD ?? ?? ?? ?? DD 44 24 08 D8 C1 DD 5C 24 48 DD 44 24 48 DE E1 DD 5C 24 18 8B 54 24 1C 89 D0 C1 E8 14 25 FF 07 00 00 31 FF 31 ED 2D FF 03 00 00 0F 88 07 01 00 00 81 E2 FF FF 0F 00 81 CA 00 00 10 00 B9 14 00 00 00 29 C1 D3 EA 89 D7 E9 95 00 00 00 83 FA 3E 0F 8F B7 00 00 00 83 FA 33 7E 3E 25 FF FF 0F 00 0D 00 00 10 00 89 C1 31 DB 89 CB B9 00 00 00 00 89 C8 09 F0 89 C7 89 DD 8B 4C 24 04 81 E9 33 04 00 00 0F }
	condition:
		$pattern
}

rule clntudp_bufcreate_8c2d993965a8bacc11ba70933f5425ec {
	meta:
		aliases = "__GI_clntudp_bufcreate, clntudp_bufcreate"
		size = "568"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 58 6A 0C E8 ?? ?? ?? ?? 89 C5 8B BC 24 88 00 00 00 83 C7 03 83 E7 FC 8B 9C 24 8C 00 00 00 83 C3 03 83 E3 FC 8D 44 1F 64 89 04 24 E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 ED 74 04 85 C0 75 2E E8 ?? ?? ?? ?? 89 C3 51 51 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 03 0C 00 00 00 C7 43 08 0C 00 00 00 83 C4 10 E9 9B 01 00 00 8D 44 03 60 89 46 58 8B 44 24 60 66 83 78 02 00 75 28 6A 11 FF 74 24 6C FF 74 24 6C 50 E8 ?? ?? ?? ?? 83 C4 10 66 85 C0 0F 84 6D 01 00 00 66 C1 C8 08 8B 54 24 60 66 89 42 02 C7 45 04 ?? ?? ?? ?? 89 75 08 8D 46 08 52 6A 10 FF 74 24 68 50 E8 ?? ?? ?? ?? C7 46 18 }
	condition:
		$pattern
}

rule vwarn_work_dfaf7a6b4f07b14ed39c449492edd67b {
	meta:
		aliases = "vwarn_work"
		size = "199"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 5C 89 C7 89 D5 BB ?? ?? ?? ?? 85 C9 74 1C E8 ?? ?? ?? ?? 51 6A 40 8D 54 24 14 52 FF 30 E8 ?? ?? ?? ?? BB ?? ?? ?? ?? 83 C4 10 A1 ?? ?? ?? ?? 8B 70 34 85 F6 75 27 52 83 C0 38 50 68 ?? ?? ?? ?? 8D 44 24 58 50 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C0 38 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 50 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 FF 74 14 51 55 57 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 EB 02 83 C4 10 52 8D 44 24 10 50 53 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 F6 75 11 50 50 6A 01 8D 44 24 58 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 5C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule inet_ntop_641ab2341fabb1992b12af06db229bac {
	meta:
		aliases = "__GI_inet_ntop, inet_ntop"
		size = "460"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 5C 8B 44 24 70 83 F8 02 74 0B 83 F8 0A 0F 85 9C 01 00 00 EB 18 8B 4C 24 7C 8B 54 24 78 8B 44 24 74 E8 ?? ?? ?? ?? 89 C2 E9 8F 01 00 00 50 6A 20 6A 00 8D 44 24 48 50 E8 ?? ?? ?? ?? 31 C9 83 C4 10 BA 02 00 00 00 89 C8 89 D6 99 F7 FE 89 C3 8B 54 24 74 0F B6 04 0A C1 E0 08 0F B6 54 11 01 09 D0 89 44 9C 3C 83 C1 02 83 F9 0F 7E D4 31 D2 83 CF FF 83 C8 FF EB 2E 83 7C 94 3C 00 75 11 83 F8 FF 75 09 89 D0 BB 01 00 00 00 EB 18 43 EB 15 83 F8 FF 74 10 83 FF FF 74 04 39 EB 7E 04 89 DD 89 C7 83 C8 FF 42 83 FA 07 7E CD 83 F8 FF 74 0D 83 FF FF 74 04 39 EB 7E 04 89 DD 89 C7 83 FF FF 74 08 83 }
	condition:
		$pattern
}

rule timer_create_020e5dc3d558d4fd69a972790b9e3298 {
	meta:
		aliases = "timer_create"
		size = "158"
		objfiles = "timer_create@librt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 5C 8B 6C 24 74 85 ED 75 14 C7 44 24 20 00 00 00 00 C7 44 24 1C 0E 00 00 00 8D 6C 24 18 83 7D 08 02 74 68 83 EC 0C 6A 08 E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 C0 74 55 89 44 24 18 8D 54 24 58 8B 7C 24 70 89 E9 53 89 FB B8 03 01 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 83 FB FF 74 14 8B 45 08 89 06 8B 44 24 58 89 46 04 8B 44 24 78 89 30 EB 11 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 EB 03 83 CB FF 89 D8 83 C4 5C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _wstdio_fwrite_477e6a7d3a716c0e7d7e00ded87079b4 {
	meta:
		aliases = "_wstdio_fwrite"
		size = "236"
		objfiles = "_wfwrite@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 5C 8B 6C 24 74 8B 74 24 78 83 7E 04 FD 75 37 8B 46 10 8B 5E 0C 29 C3 C1 FB 02 39 EB 76 02 89 EB 85 DB 0F 84 B4 00 00 00 51 53 FF 74 24 78 50 E8 ?? ?? ?? ?? 8D 04 9D 00 00 00 00 01 46 10 83 C4 10 E9 96 00 00 00 0F B7 06 25 40 08 00 00 3D 40 08 00 00 74 16 52 52 68 00 08 00 00 56 E8 ?? ?? ?? ?? 83 C4 10 31 FF 85 C0 75 6F 8B 44 24 70 89 44 24 58 31 FF 8D 56 2C 89 54 24 08 EB 58 83 EC 0C FF 74 24 14 6A 40 89 E8 29 F8 50 8D 44 24 70 50 8D 54 24 34 52 E8 ?? ?? ?? ?? 89 C3 83 C4 20 83 F8 FF 74 35 85 C0 75 0E 8B 54 24 70 8D 44 BA 04 89 44 24 58 B3 01 50 56 53 8D 44 24 24 50 E8 ?? ?? }
	condition:
		$pattern
}

rule gethostbyaddr_r_06b247cdb23f20ecec32bc045987bd96 {
	meta:
		aliases = "__GI_gethostbyaddr_r, gethostbyaddr_r"
		size = "877"
		objfiles = "gethostbyaddr_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 5C 8B 74 24 70 8B AC 24 80 00 00 00 8B 9C 24 84 00 00 00 8B 84 24 88 00 00 00 C7 00 00 00 00 00 85 F6 0F 84 2B 03 00 00 57 6A 28 6A 00 8D 44 24 2C 50 E8 ?? ?? ?? ?? 83 C4 10 83 7C 24 78 02 74 0D 83 7C 24 78 0A 0F 85 07 03 00 00 EB 07 83 7C 24 74 04 EB 05 83 7C 24 74 10 0F 85 F3 02 00 00 FF B4 24 8C 00 00 00 FF B4 24 8C 00 00 00 53 55 FF B4 24 8C 00 00 00 FF B4 24 8C 00 00 00 FF B4 24 8C 00 00 00 56 E8 ?? ?? ?? ?? 83 C4 20 85 C0 0F 84 C9 02 00 00 8B 8C 24 8C 00 00 00 8B 11 83 FA 01 74 09 83 FA 04 0F 85 B2 02 00 00 E8 ?? ?? ?? ?? 8B 84 24 8C 00 00 00 C7 00 FF FF FF FF 83 FB 03 }
	condition:
		$pattern
}

rule __GI_strftime_59a9dacb29dece606ac3eee517f736d6 {
	meta:
		aliases = "strftime, __GI_strftime"
		size = "1296"
		objfiles = "strftime@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 64 6A 00 FF B4 24 88 00 00 00 E8 ?? ?? ?? ?? 3D FF 4E 98 45 0F 9E C0 0F B6 C0 89 04 24 E8 ?? ?? ?? ?? 8B 8C 24 88 00 00 00 8B 84 24 84 00 00 00 89 44 24 28 C7 44 24 30 00 00 00 00 83 C4 10 8D 54 24 44 89 54 24 08 83 7C 24 18 00 0F 84 AE 04 00 00 8A 01 84 C0 75 29 83 7C 24 20 00 75 14 8B 4C 24 70 C6 01 00 8B 44 24 74 2B 44 24 18 E9 8F 04 00 00 FF 4C 24 20 8B 5C 24 20 8B 4C 9C 34 EB C6 3C 25 74 06 89 4C 24 14 EB 0E 8D 79 01 89 7C 24 14 8A 41 01 3C 25 75 0F 89 CE C7 44 24 1C 01 00 00 00 E9 20 04 00 00 3C 4F 74 10 3C 45 74 10 C7 44 24 1C 02 00 00 00 B3 3F EB 17 B0 40 EB 02 B0 80 }
	condition:
		$pattern
}

rule __GI_strptime_a2aa17f4961902840714ba78a3d3e601 {
	meta:
		aliases = "strptime, __GI_strptime"
		size = "954"
		objfiles = "strptime@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 6C 8B AC 24 80 00 00 00 31 C0 C7 44 84 20 00 00 00 80 40 83 F8 0C 7E F2 8B BC 24 84 00 00 00 C7 44 24 08 00 00 00 00 8A 07 84 C0 75 48 83 7C 24 08 00 75 33 83 7C 24 38 07 75 08 C7 44 24 38 00 00 00 00 31 D2 8B 44 94 20 3D 00 00 00 80 74 0A 8B 8C 24 88 00 00 00 89 04 91 42 83 FA 07 7E E5 89 E8 E9 45 03 00 00 FF 4C 24 08 8B 5C 24 08 8B 7C 9C 54 EB B2 3C 25 0F 85 01 03 00 00 47 8A 07 3C 25 0F 84 F6 02 00 00 3C 4F 74 08 B1 3F 3C 45 75 0E EB 04 B0 40 EB 02 B0 80 88 C1 83 C9 3F 47 8A 17 84 D2 0F 84 00 03 00 00 88 D0 83 C8 20 83 E8 61 3C 19 0F 87 F0 02 00 00 0F BE C2 8A 90 ?? ?? ?? }
	condition:
		$pattern
}

rule _time_mktime_tzi_c3bc441d0b6d8cd882e6844748f7c55b {
	meta:
		aliases = "_time_mktime_tzi"
		size = "713"
		objfiles = "_time_mktime_tzi@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 6C 8D 6C 24 38 51 6A 2C FF B4 24 88 00 00 00 55 E8 ?? ?? ?? ?? 83 C4 10 8B 84 24 88 00 00 00 80 78 28 00 75 08 C7 44 24 58 00 00 00 00 C7 44 24 34 00 00 00 00 83 7C 24 58 00 74 16 0F 9F C0 0F B6 C0 8D 44 00 FF 89 44 24 58 C7 44 24 34 01 00 00 00 8D 55 14 89 54 24 24 8B 4D 14 8D 5D 18 89 5C 24 28 BF 90 01 00 00 89 C8 99 F7 FF 89 44 24 04 89 45 18 8D 75 1C 8D 55 10 89 54 24 2C 8B 5D 10 89 5C 24 14 89 D8 BB 0C 00 00 00 99 F7 FB 89 44 24 10 89 45 1C 01 C1 69 5C 24 04 90 01 00 00 29 D9 89 4D 14 6B 44 24 10 0C 8B 54 24 14 29 C2 89 D0 89 55 10 85 D2 79 0C 83 C0 0C 89 45 10 8B 4C 24 }
	condition:
		$pattern
}

rule _ppfs_parsespec_90888343574bd61d39808e2e8aa25816 {
	meta:
		aliases = "_ppfs_parsespec"
		size = "1077"
		objfiles = "_ppfs_parsespec@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 6C C7 44 24 60 00 00 00 00 C7 44 24 64 00 00 00 00 C7 44 24 44 08 00 00 00 C7 44 24 48 08 00 00 00 8B 84 24 80 00 00 00 8B 40 18 89 44 24 14 8B 94 24 80 00 00 00 8B 6A 10 81 E5 80 00 00 00 75 04 8B 12 EB 3C 31 F6 8D 0C B5 00 00 00 00 8B 84 24 80 00 00 00 8B 10 8B 44 11 FC 88 C3 88 44 34 24 0F BE C0 3B 44 11 FC 0F 85 B6 03 00 00 84 DB 74 06 46 83 FE 1F 76 CF C6 44 24 43 00 8D 54 24 25 C7 44 24 0C 00 00 00 00 C7 44 24 10 00 00 00 00 EB 02 89 F2 89 D6 80 3A 2A 75 10 6B 44 24 10 FC C7 44 04 44 00 00 00 00 8D 72 01 31 DB EB 10 81 FB FE 0F 00 00 7F 07 6B C3 0A 8D 5C 38 D0 46 8A 0E }
	condition:
		$pattern
}

rule initshells_add97229b42ae1977eb447ca58af7e48 {
	meta:
		aliases = "initshells"
		size = "319"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 6C E8 ?? ?? ?? ?? 50 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C7 83 C4 10 B8 ?? ?? ?? ?? 85 FF 0F 84 08 01 00 00 83 EC 0C 57 E8 ?? ?? ?? ?? 5E 5D 8D 54 24 1C 52 50 E8 ?? ?? ?? ?? 83 C4 10 40 0F 84 D2 00 00 00 83 EC 0C 8B 44 24 4C 40 50 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 B4 00 00 00 53 53 6A 04 8B 44 24 4C BA 03 00 00 00 89 D1 31 D2 F7 F1 50 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 8B 00 00 00 51 51 6A 02 57 E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 8B 6C 24 50 83 C4 10 EB 3A 43 8A 03 3C 23 74 33 3C 2F 74 06 84 C0 75 F1 EB 29 84 C0 }
	condition:
		$pattern
}

rule __md5_Transform_456c71694d26e7f0eb496fbdc9ab2380 {
	meta:
		aliases = "__md5_Transform"
		size = "320"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 70 89 C5 6A 40 52 8D 44 24 38 50 E8 ?? ?? ?? ?? 8B 45 00 89 44 24 38 8D 55 04 89 54 24 1C 8B 7D 04 8D 45 08 89 44 24 20 8B 75 08 8D 55 0C 89 54 24 24 8B 5D 0C C7 44 24 28 ?? ?? ?? ?? 8B 4C 24 38 C7 44 24 2C ?? ?? ?? ?? C7 44 24 30 ?? ?? ?? ?? C7 44 24 34 00 00 00 00 83 C4 10 E9 9B 00 00 00 F6 44 24 24 0F 75 05 83 44 24 18 04 8B 44 24 24 C1 F8 04 83 F8 01 74 1E 7F 06 85 C0 74 0E EB 37 83 F8 02 74 1F 83 F8 03 74 22 EB 2B 89 F8 F7 D0 21 D8 89 F2 EB 08 89 D8 F7 D0 21 F0 89 DA 21 FA 09 D0 EB 10 89 F0 31 F8 31 D8 EB 08 89 D8 F7 D0 09 F8 31 F0 8D 0C 08 8B 44 24 20 0F BE 00 89 44 24 }
	condition:
		$pattern
}

rule iruserfopen_6cce8b4406f9cd99ed2b3afae79d857b {
	meta:
		aliases = "iruserfopen"
		size = "148"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 74 89 C6 89 D5 8D 7C 24 1C 57 50 E8 ?? ?? ?? ?? 83 C4 10 31 DB 85 C0 75 6B 8B 44 24 24 25 00 F0 00 00 3D 00 80 00 00 75 5B 53 53 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 74 45 83 EC 0C 50 E8 ?? ?? ?? ?? 5A 59 57 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 1A 8B 44 24 2C 85 C0 74 04 39 E8 75 0E F6 44 24 24 12 75 07 83 7C 24 28 01 76 12 85 DB 74 0E 83 EC 0C 53 E8 ?? ?? ?? ?? 31 DB 83 C4 10 89 D8 83 C4 6C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __ieee754_lgamma_r_c2003f6f44a4b131e378559e2de1337e {
	meta:
		aliases = "__ieee754_lgamma_r"
		size = "1689"
		objfiles = "e_lgamma_r@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 83 EC 7C DD 84 24 90 00 00 00 DD 54 24 20 8B AC 24 98 00 00 00 DD 54 24 38 8B 44 24 3C 89 44 24 54 C7 45 00 01 00 00 00 89 C6 81 E6 FF FF FF 7F 81 FE FF FF EF 7F 7E 09 D9 C0 DE C9 E9 4C 06 00 00 DD D8 8B 7C 24 38 89 F0 09 F8 74 5B 81 FE FF FF 8F 3B 7F 39 83 7C 24 54 00 79 19 C7 45 00 FF FF FF FF 83 EC 10 DD 44 24 30 D9 E0 DD 54 24 30 DD 1C 24 EB 0A 56 56 FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? D9 E0 83 C4 10 E9 FF 05 00 00 83 7C 24 54 00 78 0B D9 EE DD 5C 24 48 E9 FC 01 00 00 81 FE FF FF 2F 43 7E 07 D9 EE E9 9A 01 00 00 DD 44 24 20 DD 5C 24 30 8B 5C 24 34 81 E3 FF FF FF 7F 81 FB FF }
	condition:
		$pattern
}

rule byte_insert_op2_8918643c119c9f98b97afd2d26510542 {
	meta:
		aliases = "byte_insert_op2"
		size = "54"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 89 C5 89 D3 89 CF 8B 74 24 14 8B 44 24 18 8D 48 05 89 C2 EB 06 49 4A 8A 02 88 01 39 DA 75 F6 89 74 24 14 89 F9 89 DA 89 E8 5B 5E 5F 5D E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule byte_compile_range_6c6742f10a22d77fb2b2bdc6409a6c2c {
	meta:
		aliases = "byte_compile_range"
		size = "204"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 89 C7 89 D5 8B 5C 24 18 8B 12 BE 0B 00 00 00 39 CA 0F 84 AA 00 00 00 8D 42 01 89 45 00 81 E3 00 00 01 00 83 FB 01 19 F6 F7 D6 83 E6 0B 83 7C 24 14 00 74 16 89 F9 0F B6 C1 8B 4C 24 14 0F BE 3C 01 0F B6 02 0F B6 2C 01 EB 03 0F B6 2A 89 FB EB 6C 83 7C 24 14 00 74 1B 0F B6 C3 8B 7C 24 14 0F B6 04 07 BA 08 00 00 00 89 D1 99 F7 F9 89 C6 89 C1 EB 19 0F B6 D3 B9 08 00 00 00 89 D0 99 F7 F9 89 C6 0F B6 D3 89 D0 99 F7 F9 89 C1 8B 7C 24 1C 8A 14 0F 89 D9 83 7C 24 14 00 74 0B 0F B6 C3 8B 7C 24 14 0F B6 0C 07 83 E1 07 B8 01 00 00 00 D3 E0 09 D0 8B 54 24 1C 88 04 32 43 31 F6 39 EB 76 90 89 F0 5B }
	condition:
		$pattern
}

rule __GI_random_r_f4380743c0cb10b41c9ed7bf8d26e5e0 {
	meta:
		aliases = "random_r, __GI_random_r"
		size = "95"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 5C 24 14 8B 6C 24 18 8B 73 08 83 7B 0C 00 75 17 69 06 6D 4E C6 41 05 39 30 00 00 25 FF FF FF 7F 89 06 89 45 00 EB 2C 8B 03 8B 4B 04 8B 7B 18 8B 10 03 11 89 10 D1 EA 89 55 00 83 C0 04 39 F8 8D 51 04 72 04 89 F0 EB 06 39 FA 72 02 89 F2 89 03 89 53 04 31 C0 5B 5E 5F 5D C3 }
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

rule register_printf_function_57820ce5205e6ca10801a657b2b28c36 {
	meta:
		aliases = "register_printf_function"
		size = "106"
		objfiles = "register_printf_function@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 85 F6 74 4E 85 ED 74 4A 8B 0D ?? ?? ?? ?? 8D 51 0A 31 DB 4A 8A 02 84 C0 75 02 89 D3 0F BE C0 39 F0 75 04 89 D3 89 CA 39 CA 77 E8 85 DB 74 23 85 FF 74 18 89 F0 88 03 89 D8 29 D0 89 3C 85 ?? ?? ?? ?? 89 2C 85 ?? ?? ?? ?? EB 03 C6 03 00 31 C0 EB 03 83 C8 FF 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __encode_header_536b7550d07ab7a997c8f09f24a5df68 {
	meta:
		aliases = "__encode_header"
		size = "182"
		objfiles = "encodeh@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 57 56 53 8B 7C 24 14 8B 6C 24 18 83 C8 FF 83 7C 24 1C 0B 0F 8E 97 00 00 00 0F B6 47 01 88 45 00 8B 07 88 45 01 83 7F 04 01 19 F6 F7 D6 83 E6 80 83 7F 0C 01 19 DB F7 D3 83 E3 04 83 7F 10 01 19 C9 F7 D1 83 E1 02 8B 57 08 83 E2 0F C1 E2 03 83 7F 14 00 0F 95 C0 09 D0 09 F0 09 D8 09 C8 88 45 02 83 7F 18 01 19 C0 F7 D0 83 E0 80 8A 57 1C 83 E2 0F 09 D0 88 45 03 0F B6 47 21 88 45 04 8B 47 20 88 45 05 0F B6 47 25 88 45 06 8B 47 24 88 45 07 0F B6 47 29 88 45 08 8B 47 28 88 45 09 0F B6 47 2D 88 45 0A 8B 47 2C 88 45 0B B8 0C 00 00 00 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule d_call_offset_a1810eaf0cb1f17cbedf05b7aef7b6e1 {
	meta:
		aliases = "d_call_offset"
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

rule __do_global_ctors_aux_792460ecaaa16973e03ae87a43f50c17 {
	meta:
		aliases = "__do_global_ctors_aux"
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
		size = "90"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 3C FF 74 1D 83 E0 70 83 F8 20 74 21 7E 0F 83 F8 30 74 21 83 F8 50 74 09 E8 ?? ?? ?? ?? 85 C0 75 1C 31 C0 5A 5B 5D C3 8D B6 00 00 00 00 8B 42 04 5A 5B 5D C3 8B 42 08 5A 5B 5D C3 89 F6 83 F8 10 74 DF E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule size_of_encoded_value_03c678977cbe5b9160e4e1b05016f7b7 {
	meta:
		aliases = "size_of_encoded_value"
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
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 45 08 8B 10 85 D2 74 14 83 EC 0C 50 E8 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 8B 5D FC C9 C3 }
	condition:
		$pattern
}

rule __subvsi3_55f81f12371ddc996daf53030de2fa02 {
	meta:
		aliases = "__subvsi3"
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
		size = "60"
		objfiles = "_addvsi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 4D 08 8B 45 0C 8D 14 08 85 C0 78 10 39 CA 0F 9C C0 84 C0 75 0E 89 D0 5A 5B 5D C3 90 39 CA 0F 9F C0 EB EE E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule frame_dummy_5e416c84c4b4da90a8f0fc11d5fa6906 {
	meta:
		aliases = "frame_dummy"
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
		size = "31"
		objfiles = "gthr_gnat@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? FF 93 ?? ?? ?? ?? 31 C0 5A 5B 5D C3 }
	condition:
		$pattern
}

rule pthread_handle_sigcancel_54a68a1da113f7b67ff80911483edfc0 {
	meta:
		aliases = "pthread_handle_sigcancel"
		size = "138"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 75 09 8B 5D FC C9 E9 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 2C 3B 05 ?? ?? ?? ?? 75 16 50 68 00 00 00 80 6A 00 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 80 78 42 00 74 2E 80 78 40 00 75 28 80 78 41 01 75 0A 50 50 55 6A FF E8 ?? ?? ?? ?? 8B 50 28 85 D2 74 11 C7 40 28 00 00 00 00 53 53 6A 01 52 E8 ?? ?? ?? ?? 8B 5D FC C9 C3 }
	condition:
		$pattern
}

rule daemon_a466feae30dc69af1241b1f9f7a5d3de {
	meta:
		aliases = "daemon"
		size = "162"
		objfiles = "daemon@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 04 E8 ?? ?? ?? ?? 83 F8 FF 74 79 85 C0 74 7E 83 EC 0C 6A 00 E8 ?? ?? ?? ?? 83 7D 08 00 75 10 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 7D 0C 00 75 54 50 6A 00 6A 02 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 83 C4 10 83 F8 FF 74 3B 50 50 6A 00 53 E8 ?? ?? ?? ?? 59 58 6A 01 53 E8 ?? ?? ?? ?? 58 5A 6A 02 53 E8 ?? ?? ?? ?? 83 C4 10 83 FB 02 7E 15 83 EC 0C 53 E8 ?? ?? ?? ?? 31 C0 83 C4 10 EB 13 83 C8 FF EB 0E 31 C0 EB 0A E8 ?? ?? ?? ?? 40 75 84 EB ED 8B 5D FC C9 C3 }
	condition:
		$pattern
}

rule __register_frame_table_0cb9895e154004523f1435bd51c242ff {
	meta:
		aliases = "__register_frame_table"
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
		size = "33"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 83 EC 10 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 45 08 50 E8 ?? ?? ?? ?? 8B 5D FC C9 C3 }
	condition:
		$pattern
}

rule uw_install_context_6a4924b7334ec7647a143b2c9925b67f {
	meta:
		aliases = "uw_install_context"
		size = "38"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 02 89 83 ?? ?? ?? ?? 8D 50 20 8B 4A 04 8B 68 20 8B 62 08 FF E1 }
	condition:
		$pattern
}

rule __register_frame_info_bases_c12c3dd625f78cd8edbd6a1417dfe2e4 {
	meta:
		aliases = "__register_frame_info_bases"
		size = "84"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 45 08 8B 55 0C 85 C0 74 37 8B 08 85 C9 74 31 C7 02 FF FF FF FF 8B 4D 10 89 4A 04 8B 4D 14 89 4A 08 89 42 0C C7 42 10 00 00 00 00 66 81 4A 10 F8 07 8B 83 ?? ?? ?? ?? 89 42 14 89 93 ?? ?? ?? ?? 5B 5D C3 }
	condition:
		$pattern
}

rule pthread_initialize_15d32805992cd1db627f01b9e13f9684 {
	meta:
		aliases = "pthread_initialize"
		size = "415"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 81 EC 20 01 00 00 83 3D ?? ?? ?? ?? 00 0F 85 80 01 00 00 8D 85 00 00 C0 FF 25 00 00 E0 FF A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 A1 ?? ?? ?? ?? EB 10 83 78 34 01 74 07 C7 40 34 00 00 00 00 8B 40 20 85 C0 75 EC 50 50 8D 5D F0 53 6A 03 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 01 C0 BA 00 00 20 00 29 C2 83 C4 10 39 55 F0 76 10 89 55 F0 50 50 53 6A 03 E8 ?? ?? ?? ?? 83 C4 10 C7 85 E4 FE FF FF ?? ?? ?? ?? 83 EC 0C 8D B5 E4 FE FF FF 8D 9D E8 FE FF FF 53 E8 ?? ?? ?? ?? C7 85 68 FF FF FF 00 00 00 00 83 }
	condition:
		$pattern
}

rule pthread_start_thread_ff2195701b4ce3e58f271f6fe9d6a291 {
	meta:
		aliases = "pthread_start_thread"
		size = "198"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 81 EC A0 00 00 00 8B 75 08 E8 ?? ?? ?? ?? 89 46 14 8D 46 64 53 6A 00 50 6A 02 E8 ?? ?? ?? ?? 8B 96 E4 00 00 00 83 C4 10 85 D2 78 0B 8D 86 E8 00 00 00 51 50 52 EB 17 83 3D ?? ?? ?? ?? 00 7E 19 C7 45 F4 00 00 00 00 50 8D 45 F4 50 6A 00 FF 76 14 E8 ?? ?? ?? ?? 83 C4 10 A1 ?? ?? ?? ?? 85 C0 74 4D 83 3D ?? ?? ?? ?? 00 7E 44 89 B5 60 FF FF FF C7 85 64 FF FF FF 05 00 00 00 8D 9D 60 FF FF FF 50 68 94 00 00 00 53 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 40 75 0A E8 ?? ?? ?? ?? 83 38 04 74 DE 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C FF 76 60 FF 56 5C 5B 5E 55 50 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __divsc3_037373cb4a12024714cf1483f95f50e6 {
	meta:
		aliases = "__divsc3"
		size = "890"
		objfiles = "_divsc3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? D9 45 10 D9 E1 D9 45 14 D9 E1 DA E9 DF E0 F6 C4 45 75 49 D9 45 10 D8 75 14 D9 45 10 D8 C9 D8 45 14 D9 45 08 D8 CA D8 45 0C D8 F1 D9 45 0C DE CB D9 CA D8 65 08 DE F1 D9 C9 DD E0 DF E0 80 E4 45 80 FC 40 75 3F D9 5D F4 8B 45 F4 D9 5D F4 8B 55 F4 59 5B 5E 5D C3 8D B6 00 00 00 00 D9 45 14 D8 75 10 D9 45 14 D8 C9 D8 45 10 D9 45 0C D8 CA D8 45 08 D8 F1 D9 CA D8 4D 08 D9 45 0C DE E1 DE F1 D9 C9 EB B5 D9 C9 DD E0 DF E0 80 E4 45 80 FC 40 75 04 D9 C9 EB AF D9 EE D9 45 10 DD E9 DF E0 80 E4 45 80 F4 40 0F 85 76 02 00 00 D9 45 14 DA E9 DF E0 80 E4 }
	condition:
		$pattern
}

rule __new_sem_wait_8f1b2aedc749f81acfeda2cb2ee5bdc5 {
	meta:
		aliases = "sem_wait, __new_sem_wait"
		size = "253"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 10 8B 75 08 E8 ?? ?? ?? ?? 89 45 F4 89 75 EC C7 45 F0 ?? ?? ?? ?? 8B 55 F4 89 F0 E8 ?? ?? ?? ?? 8B 46 08 85 C0 7E 15 48 89 46 08 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 E9 B1 00 00 00 8B 45 F4 C6 80 BA 01 00 00 00 8B 45 F4 8D 55 EC E8 ?? ?? ?? ?? 8B 45 F4 80 78 42 00 74 0E 8B 45 F4 BB 01 00 00 00 80 78 40 00 74 0D 8B 55 F4 8D 46 0C E8 ?? ?? ?? ?? 31 DB 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 85 DB 74 0C 8B 45 F4 31 D2 E8 ?? ?? ?? ?? EB 52 8B 45 F4 E8 ?? ?? ?? ?? 8B 45 F4 80 B8 BA 01 00 00 00 75 15 8B 45 F4 80 B8 B8 01 00 00 00 74 E0 8B 45 F4 80 78 40 00 75 D7 8B 45 F4 31 D2 E8 ?? }
	condition:
		$pattern
}

rule __GI_execlp_d95bb4a820fb6e471e9dfc02c6dd0de0 {
	meta:
		aliases = "execlp, __GI_execlp"
		size = "100"
		objfiles = "execlp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 10 8D 45 10 89 45 F4 31 F6 46 8B 55 F4 8D 42 04 89 45 F4 83 3A 00 75 F1 8D 04 B5 22 00 00 00 83 E0 F0 29 C4 8D 5C 24 0F 83 E3 F0 8B 45 0C 89 03 8D 45 10 89 45 F4 89 D9 83 C1 04 8B 45 F4 8D 50 04 89 55 F4 8B 00 89 01 4E 75 ED 50 50 53 FF 75 08 E8 ?? ?? ?? ?? 8D 65 F8 5B 5E 5D C3 }
	condition:
		$pattern
}

rule execl_d85114b43351d9d28e90782b79e15212 {
	meta:
		aliases = "__GI_execl, execl"
		size = "105"
		objfiles = "execl@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 10 8D 45 10 89 45 F4 31 F6 46 8B 55 F4 8D 42 04 89 45 F4 83 3A 00 75 F1 8D 04 B5 22 00 00 00 83 E0 F0 29 C4 8D 5C 24 0F 83 E3 F0 8B 45 0C 89 03 8D 45 10 89 45 F4 89 D9 83 C1 04 8B 45 F4 8D 50 04 89 55 F4 8B 00 89 01 4E 75 ED 50 FF 35 ?? ?? ?? ?? 53 FF 75 08 E8 ?? ?? ?? ?? 8D 65 F8 5B 5E 5D C3 }
	condition:
		$pattern
}

rule _Unwind_SjLj_ForcedUnwind_a1ddd0ad3cf4012d00e858c684b0775b {
	meta:
		aliases = "_Unwind_SjLj_ForcedUnwind"
		size = "79"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 10 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 45 08 8B 93 ?? ?? ?? ?? 89 55 F4 89 55 F0 8B 55 0C 89 50 0C 8B 55 10 89 50 10 8D 75 F0 89 F2 E8 A7 FD FF FF 83 F8 07 74 07 83 C4 10 5B 5E 5D C3 8D 45 F4 89 F2 E8 21 FF FF FF }
	condition:
		$pattern
}

rule _Unwind_SjLj_Resume_or_Rethrow_ef72d9b2dcc2cdd768368004faeef850 {
	meta:
		aliases = "_Unwind_SjLj_Resume_or_Rethrow"
		size = "90"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 10 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 4D 08 8B 71 0C 85 F6 74 22 8B 83 ?? ?? ?? ?? 89 45 F4 89 45 F0 8D 75 F0 89 F2 89 C8 E8 AA FC FF FF 83 F8 07 74 15 E8 ?? ?? ?? ?? 83 EC 0C 51 E8 ?? ?? ?? ?? 8D 65 F8 5B 5E 5D C3 8D 45 F4 89 F2 E8 16 FE FF FF }
	condition:
		$pattern
}

rule _Unwind_SjLj_Resume_f040361612a7bec9719a99a506d8b2f1 {
	meta:
		aliases = "_Unwind_SjLj_Resume"
		size = "88"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 10 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 4D 08 8B 83 ?? ?? ?? ?? 89 45 F4 89 45 F0 8B 41 0C 85 C0 75 16 8D 75 F0 89 F2 89 C8 E8 FA FE FF FF 83 F8 07 74 13 E8 ?? ?? ?? ?? 8D 75 F0 89 F2 89 C8 E8 F4 FD FF FF EB E8 8D 45 F4 89 F2 E8 78 FF FF FF }
	condition:
		$pattern
}

rule __mulsc3_4e2aa4e1213b843f63d10caa3095f718 {
	meta:
		aliases = "__mulsc3"
		size = "1099"
		objfiles = "_mulsc3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 18 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? D9 45 08 D8 4D 10 D9 5D F4 D9 45 0C D8 4D 14 D9 5D F0 D9 45 08 D8 4D 14 D9 5D EC D9 45 0C D8 4D 10 D9 5D E8 D9 45 F4 D9 45 F0 D9 C1 D8 E1 D9 45 EC D9 45 E8 D9 C1 D8 C1 D9 55 E4 D9 CB DD E0 DF E0 80 E4 45 80 FC 40 75 1A DD DC DD D8 DD D8 DD D8 DD D9 D9 5D E0 8B 45 E0 8B 55 E4 83 C4 18 5B 5E 5D C3 D9 CB DD E8 DF E0 80 E4 45 80 FC 40 75 0A DD D8 DD D8 DD D9 DD D9 EB D8 D9 45 08 D8 E0 D9 45 08 DD E8 DF E0 80 E4 45 80 F4 40 0F 85 BE 01 00 00 DD E8 DF E0 80 E4 45 80 F4 40 0F 84 B0 01 00 00 B8 00 00 80 3F 8B 55 08 85 D2 79 05 B8 00 00 80 BF }
	condition:
		$pattern
}

rule __old_sem_wait_f5fbd32257604b631ae58dcde03712f0 {
	meta:
		aliases = "__old_sem_wait"
		size = "288"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 83 EC 20 8B 5D 08 89 EA B8 ?? ?? ?? ?? 3B 2D ?? ?? ?? ?? 73 31 3B 2D ?? ?? ?? ?? 72 0D B8 ?? ?? ?? ?? 3B 2D ?? ?? ?? ?? 72 1C 83 3D ?? ?? ?? ?? 00 74 07 E8 ?? ?? ?? ?? EB 0C 81 CA FF FF 1F 00 8D 82 21 FE FF FF 89 45 F4 C7 45 EC 00 00 00 00 C7 45 F0 ?? ?? ?? ?? 8D 75 EC 8B 45 F4 89 F2 E8 ?? ?? ?? ?? 8B 0B F6 C1 01 74 08 8D 51 FE 83 F9 01 75 09 8B 55 F4 8B 45 F4 89 48 08 89 C8 F0 0F B1 13 0F 94 C1 84 C9 74 DB 80 E2 01 75 7A 8B 45 F4 83 EC 0C 50 E8 ?? ?? ?? ?? 8B 45 F4 31 D2 E8 ?? ?? ?? ?? 8B 45 F4 83 C4 10 80 78 42 00 74 AA 8B 45 F4 80 78 40 00 75 A1 8B 13 8B 45 F4 39 C2 75 13 8B }
	condition:
		$pattern
}

rule __GI_pthread_setcancelstate_9263c05e917c13e14b83247c9836bc89 {
	meta:
		aliases = "pthread_setcancelstate, __GI_pthread_setcancelstate"
		size = "74"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 8B 5D 08 8B 75 0C B8 16 00 00 00 83 FB 01 77 2E E8 ?? ?? ?? ?? 89 C2 85 F6 74 06 0F BE 40 40 89 06 88 5A 40 80 7A 42 00 74 12 66 81 7A 40 00 01 75 0A 50 50 55 6A FF E8 ?? ?? ?? ?? 31 C0 8D 65 F8 5B 5E 5D C3 }
	condition:
		$pattern
}

rule __GI_pthread_setcanceltype_bc90fe87ba1a1feab4753bd1954d843a {
	meta:
		aliases = "pthread_setcanceltype, __GI_pthread_setcanceltype"
		size = "74"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 8B 5D 08 8B 75 0C B8 16 00 00 00 83 FB 01 77 2E E8 ?? ?? ?? ?? 89 C2 85 F6 74 06 0F BE 40 41 89 06 88 5A 41 80 7A 42 00 74 12 66 81 7A 40 00 01 75 0A 50 50 55 6A FF E8 ?? ?? ?? ?? 31 C0 8D 65 F8 5B 5E 5D C3 }
	condition:
		$pattern
}

rule __pthread_cleanup_pop_restore_9900bb5930fd2b5c34ce3e9ed80bd196 {
	meta:
		aliases = "_pthread_cleanup_pop_restore, __pthread_cleanup_pop_restore"
		size = "75"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 8B 5D 08 E8 ?? ?? ?? ?? 89 C6 83 7D 0C 00 74 0B 83 EC 0C FF 73 04 FF 13 83 C4 10 8B 43 0C 89 46 3C 8B 43 08 88 46 41 80 7E 42 00 74 12 66 81 7E 40 00 01 75 0A 51 51 55 6A FF E8 ?? ?? ?? ?? 8D 65 F8 5B 5E 5D C3 }
	condition:
		$pattern
}

rule __deregister_frame_info_bases_0542ef47de0c8070665c32a8794ff3bd {
	meta:
		aliases = "__deregister_frame_info_bases"
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
		size = "65"
		objfiles = "crtendS"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 56 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8D 83 ?? ?? ?? ?? 8D 50 FC 8B 40 FC 83 F8 FF 74 1B 89 D6 8D B6 00 00 00 00 8D BF 00 00 00 00 FF D0 8B 46 FC 83 EE 04 83 F8 FF 75 F3 5B 5E 5D C3 }
	condition:
		$pattern
}

rule glob_in_dir_01a42c8d3ece8fdc55ea721f25336d8f {
	meta:
		aliases = "glob_in_dir"
		size = "1354"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 08 02 00 00 89 85 0C FE FF FF 89 95 08 FE FF FF 89 8D 04 FE FF FF 8B 75 08 52 E8 ?? ?? ?? ?? 83 C4 10 89 85 10 FE FF FF 8B 9D 04 FE FF FF 83 E3 40 0F 94 C0 0F B6 C0 50 FF B5 0C FE FF FF E8 ?? ?? ?? ?? 5A 59 85 C0 0F 85 D1 00 00 00 F7 85 04 FE FF FF 10 08 00 00 0F 85 B5 00 00 00 85 DB 75 1A 50 50 6A 5C FF B5 0C FE FF FF E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 A3 00 00 00 83 EC 0C FF B5 0C FE FF FF E8 ?? ?? ?? ?? 83 C4 10 89 C6 8B 95 10 FE FF FF 8D 44 10 20 83 E0 F0 29 C4 8D 5C 24 0F 83 E3 F0 57 52 FF B5 08 FE FF FF 53 E8 ?? ?? ?? ?? 83 C4 0C 6A 01 68 ?? ?? ?? ?? 50 E8 ?? ?? }
	condition:
		$pattern
}

rule byte_re_match_2_internal_062141c1cf1cabb38f505464ac187d1d {
	meta:
		aliases = "byte_re_match_2_internal"
		size = "6991"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 0C 01 00 00 89 85 4C FF FF FF 89 95 48 FF FF FF 89 8D 44 FF FF FF 8B 5D 18 8B 00 89 85 74 FF FF FF 8B 95 4C FF FF FF 03 42 08 89 85 78 FF FF FF 8B 4A 14 89 4D 80 8B 72 18 46 89 75 84 8D 7C 24 0F 83 E7 F0 89 7D D0 83 7A 18 00 75 41 C7 45 90 00 00 00 00 C7 45 94 00 00 00 00 C7 45 98 00 00 00 00 C7 45 9C 00 00 00 00 C7 45 A0 00 00 00 00 C7 45 A8 00 00 00 00 C7 45 AC 00 00 00 00 C7 45 B8 00 00 00 00 C7 45 BC 00 00 00 00 EB 79 8B 55 84 8D 04 95 1E 00 00 00 83 E0 F0 29 C4 8D 4C 24 0F 83 E1 F0 89 4D 90 29 C4 8D 74 24 0F 83 E6 F0 89 75 94 29 C4 8D 7C 24 0F 83 E7 F0 89 7D 98 29 }
	condition:
		$pattern
}

rule ruserok_8077a7660d72a964e08000189ec343b3 {
	meta:
		aliases = "ruserok"
		size = "164"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 3C 04 00 00 8D 44 24 0F 83 E0 F0 BB 00 04 00 00 8D 7D E8 8D 75 F0 EB 21 83 7D E8 FF 75 73 E8 ?? ?? ?? ?? 83 38 22 75 69 01 DB 8D 43 1E 83 E0 F0 29 C4 8D 44 24 0F 83 E0 F0 52 52 57 56 53 50 8D 45 D4 50 FF 75 08 E8 ?? ?? ?? ?? 83 C4 20 85 C0 75 C6 8B 45 F0 85 C0 74 BF 8B 58 10 8D 75 EC EB 2A 51 6A 04 50 56 E8 ?? ?? ?? ?? 58 5A 8B 45 EC FF 75 08 FF 75 14 8B 4D 10 8B 55 0C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 0C 83 C3 04 8B 03 85 C0 75 D0 83 C8 FF 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule getrpcport_eb99d78d4a63befb026b10c5aa5836ab {
	meta:
		aliases = "getrpcport"
		size = "163"
		objfiles = "getrpcport@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 4C 04 00 00 8D 44 24 0F 83 E0 F0 BB 00 04 00 00 8D 7D EC 8D 75 F0 EB 21 83 7D EC FF 75 73 E8 ?? ?? ?? ?? 83 38 22 75 69 01 DB 8D 43 1E 83 E0 F0 29 C4 8D 44 24 0F 83 E0 F0 51 51 57 56 53 50 8D 45 C8 50 FF 75 08 E8 ?? ?? ?? ?? 83 C4 20 85 C0 75 C6 8B 45 F0 85 C0 74 BF 52 FF 70 0C 8B 40 10 FF 30 8D 5D DC 8D 45 E0 50 E8 ?? ?? ?? ?? 66 C7 45 DC 02 00 66 C7 45 DE 00 00 FF 75 14 FF 75 10 FF 75 0C 53 E8 ?? ?? ?? ?? 0F B7 C0 83 C4 20 EB 02 31 C0 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule clntudp_call_3c4bd0862e9c7920d50b856a22073988 {
	meta:
		aliases = "clntudp_call"
		size = "1373"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 4C 23 00 00 8B 45 08 8B 70 08 8B 4E 20 BB E8 03 00 00 89 C8 99 F7 FB 89 C1 69 46 1C E8 03 00 00 01 C1 89 8D C8 DC FF FF 83 7E 28 FF 75 0E 8B 45 24 89 85 D8 DC FF FF 8B 55 20 EB 0C 8B 46 28 89 85 D8 DC FF FF 8B 56 24 89 95 DC DC FF FF C7 85 C4 DC FF FF 00 00 00 00 C7 85 CC DC FF FF 02 00 00 00 C7 85 D4 DC FF FF 00 00 00 00 C7 85 E0 DC FF FF 00 00 00 00 8D 46 38 89 85 B4 DC FF FF 8D 56 08 89 95 B0 DC FF FF 8B 85 B4 DC FF FF 89 85 C0 DC FF FF 83 7D 10 00 0F 84 E8 00 00 00 C7 46 38 00 00 00 00 57 57 8B 46 3C FF 76 50 FF B5 C0 DC FF FF FF 50 14 8B 46 58 FF 00 8D 45 0C 59 5B }
	condition:
		$pattern
}

rule ruserpass_3845da2a83c605b7434081301d20e4a9 {
	meta:
		aliases = "__GI_ruserpass, ruserpass"
		size = "862"
		objfiles = "ruserpass@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 6C 04 00 00 8B 7D 08 E8 ?? ?? ?? ?? 89 C3 E8 ?? ?? ?? ?? 39 C3 0F 85 2E 03 00 00 E8 ?? ?? ?? ?? 89 C3 E8 ?? ?? ?? ?? 39 C3 0F 85 1A 03 00 00 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 C0 0F 84 00 03 00 00 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 C0 26 83 E0 F0 29 C4 8D 5C 24 0F 83 E3 F0 50 50 56 53 E8 ?? ?? ?? ?? 59 5E 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 58 5A 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 10 85 C0 75 22 E8 ?? ?? ?? ?? 31 D2 83 38 02 0F 84 A9 02 00 00 56 56 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 8D 02 00 00 51 51 6A 02 50 E8 ?? ?? ?? ?? 58 }
	condition:
		$pattern
}

rule gaih_inet_5813933936c5879c03cc725fbc9df944 {
	meta:
		aliases = "gaih_inet"
		size = "2502"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 9C 00 00 00 8B 7D 0C 8D 45 D4 89 45 F0 C7 45 EC 00 00 00 00 8B 55 10 8B 42 04 85 C0 74 0F C7 85 6C FF FF FF 00 00 00 00 83 F8 0A 75 16 8B 4D 10 8B 19 83 F3 08 C1 EB 03 F7 D3 83 E3 01 89 9D 6C FF FF FF 56 6A 10 6A 00 8D 45 D4 50 E8 ?? ?? ?? ?? 8B 45 10 8B 48 0C 83 C4 10 85 C9 75 0D 83 78 08 00 75 07 EB 5A 83 C3 07 EB 05 BB ?? ?? ?? ?? 8A 53 03 88 95 6B FF FF FF 84 D2 74 2C 8B 45 10 8B 50 08 85 D2 74 07 0F BE 03 39 C2 75 D8 85 C9 74 0E F6 43 02 02 75 08 0F BE 43 01 39 C1 75 C6 80 BD 6B FF FF FF 00 75 1C B8 07 01 00 00 8B 55 10 83 7A 08 00 0F 85 FB 08 00 00 E9 DF 08 00 00 }
	condition:
		$pattern
}

rule search_object_abfa17fc3cf0264e23a98f333ba24bb7 {
	meta:
		aliases = "search_object"
		size = "1819"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC 9C 00 00 00 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 89 85 7C FF FF FF 89 95 78 FF FF FF 8A 50 10 F6 C2 01 0F 85 05 02 00 00 8B 48 10 89 C8 C1 E8 0B 0F 84 37 03 00 00 89 45 80 8B 45 80 85 C0 0F 84 CD 01 00 00 8B 7D 80 8D 34 BD 08 00 00 00 83 EC 0C 56 E8 ?? ?? ?? ?? 89 85 68 FF FF FF 89 45 E4 83 C4 10 85 C0 0F 84 A6 01 00 00 C7 40 04 00 00 00 00 83 EC 0C 56 E8 ?? ?? ?? ?? 89 85 64 FF FF FF 89 45 E8 83 C4 10 85 C0 74 07 C7 40 04 00 00 00 00 8B 85 7C FF FF FF F6 40 10 02 0F 84 6C 03 00 00 8B 95 7C FF FF FF 8B 42 0C 8B 08 85 C9 74 1C 89 C6 8D 7D E4 89 FA 8B 85 7C FF FF FF E8 35 }
	condition:
		$pattern
}

rule pthread_join_70a7955f5a6a6839d9b8c75d5c4a091f {
	meta:
		aliases = "pthread_join"
		size = "437"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC AC 00 00 00 8B 7D 08 E8 ?? ?? ?? ?? 89 45 F0 89 F8 25 FF 03 00 00 C1 E0 04 8D 98 ?? ?? ?? ?? 89 5D E8 C7 45 EC ?? ?? ?? ?? 8B 55 F0 89 D8 E8 ?? ?? ?? ?? 8B 43 08 89 85 50 FF FF FF 85 C0 74 05 39 78 10 74 10 83 EC 0C 53 E8 ?? ?? ?? ?? B8 03 00 00 00 EB 3B 8B 45 F0 39 85 50 FF FF FF 75 10 83 EC 0C 53 E8 ?? ?? ?? ?? B8 23 00 00 00 EB 20 8B 95 50 FF FF FF 80 7A 2D 00 75 06 83 7A 38 00 74 16 83 EC 0C 53 E8 ?? ?? ?? ?? B8 16 00 00 00 83 C4 10 E9 0D 01 00 00 8B 85 50 FF FF FF 80 78 2C 00 0F 85 91 00 00 00 8B 45 F0 8D 55 E8 E8 ?? ?? ?? ?? 8B 45 F0 80 78 42 00 74 0E 8B 45 F0 BE }
	condition:
		$pattern
}

rule clnt_create_34237f408713c05684c91440ff5232b6 {
	meta:
		aliases = "clnt_create"
		size = "509"
		objfiles = "clnt_generic@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC C4 00 00 00 68 ?? ?? ?? ?? FF 75 14 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 50 51 6A 6E 6A 00 8D 9D 46 FF FF FF 53 E8 ?? ?? ?? ?? 66 C7 85 46 FF FF FF 01 00 58 5A FF 75 08 8D 85 48 FF FF FF 50 E8 ?? ?? ?? ?? C7 45 E8 FF FF FF FF 5F 58 6A 00 6A 00 8D 45 E8 50 FF 75 10 FF 75 0C 53 E8 ?? ?? ?? ?? 83 C4 20 E9 85 01 00 00 81 EC 10 04 00 00 8D 44 24 0F 83 E0 F0 BB 00 04 00 00 EB 31 83 7D E4 FF 75 0A E8 ?? ?? ?? ?? 83 38 22 74 10 E8 ?? ?? ?? ?? C7 00 0D 00 00 00 E9 4F 01 00 00 01 DB 8D 43 1E 83 E0 F0 29 C4 8D 44 24 0F 83 E0 F0 56 56 8D 55 E4 52 8D 55 F0 52 53 50 8D 45 B4 50 FF 75 08 }
	condition:
		$pattern
}

rule link_exists_p_7f21d8f04fb062b3ae03f698d6cac5fd {
	meta:
		aliases = "link_exists_p"
		size = "162"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC C8 00 00 00 89 C6 89 D3 89 8D 3C FF FF FF 51 E8 ?? ?? ?? ?? 83 C4 10 89 85 40 FF FF FF 8D 44 18 20 83 E0 F0 29 C4 8D 7C 24 0F 83 E7 F0 50 53 56 57 E8 ?? ?? ?? ?? 83 C4 0C 6A 01 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 0C 8B 95 40 FF FF FF 42 52 FF B5 3C FF FF FF 50 E8 ?? ?? ?? ?? 83 C4 10 F7 45 0C 00 02 00 00 74 0F 50 50 8D 45 9C 50 57 8B 45 08 FF 50 20 EB 0F 56 56 8D 85 44 FF FF FF 50 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 94 C0 0F B6 C0 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule link_exists_p_924dc0b45ae71a979b58a6129199a970 {
	meta:
		aliases = "link_exists_p"
		size = "162"
		objfiles = "glob64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC D8 00 00 00 89 C6 89 D3 89 8D 2C FF FF FF 51 E8 ?? ?? ?? ?? 83 C4 10 89 85 30 FF FF FF 8D 44 18 20 83 E0 F0 29 C4 8D 7C 24 0F 83 E7 F0 50 53 56 57 E8 ?? ?? ?? ?? 83 C4 0C 6A 01 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 0C 8B 95 30 FF FF FF 42 52 FF B5 2C FF FF FF 50 E8 ?? ?? ?? ?? 83 C4 10 F7 45 0C 00 02 00 00 74 0F 51 51 8D 45 94 50 57 8B 45 08 FF 50 20 EB 0F 52 52 8D 85 34 FF FF FF 50 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 94 C0 0F B6 C0 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule glob_750feb8044843fc301152b97b5f181ec {
	meta:
		aliases = "__GI_glob, glob"
		size = "1351"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC DC 00 00 00 8B 7D 14 83 7D 08 00 74 0D 85 FF 74 09 F7 45 0C 00 81 FF FF 74 13 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CA FF E9 08 05 00 00 8B 45 0C 83 E0 08 89 85 24 FF FF FF 75 07 C7 47 08 00 00 00 00 50 50 6A 2F FF 75 08 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 75 3D F7 45 0C 00 50 00 00 0F 84 CF 00 00 00 8B 55 08 80 3A 7E 0F 85 C3 00 00 00 83 EC 0C 52 E8 ?? ?? ?? ?? 83 C4 10 89 85 30 FF FF FF 8B 5D 08 C7 85 2C FF FF FF 00 00 00 00 E9 B7 00 00 00 3B 45 08 75 1E 8B 4D 08 41 89 8D 2C FF FF FF BB ?? ?? ?? ?? C7 85 30 FF FF FF 01 00 00 00 E9 94 00 00 00 2B 45 08 89 85 30 FF FF FF }
	condition:
		$pattern
}

rule glob64_1ac817701171bb51e8699d874478758f {
	meta:
		aliases = "__GI_glob64, glob64"
		size = "1354"
		objfiles = "glob64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC EC 00 00 00 8B 7D 14 83 7D 08 00 74 0D 85 FF 74 09 F7 45 0C 00 81 FF FF 74 13 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CA FF E9 0B 05 00 00 8B 45 0C 83 E0 08 89 85 14 FF FF FF 75 07 C7 47 08 00 00 00 00 53 53 6A 2F FF 75 08 E8 ?? ?? ?? ?? 83 C4 10 89 C6 85 C0 75 3D F7 45 0C 00 50 00 00 0F 84 CF 00 00 00 8B 55 08 80 3A 7E 0F 85 C3 00 00 00 83 EC 0C 52 E8 ?? ?? ?? ?? 83 C4 10 89 85 20 FF FF FF 8B 5D 08 C7 85 1C FF FF FF 00 00 00 00 E9 B7 00 00 00 3B 45 08 75 1E 8B 4D 08 41 89 8D 1C FF FF FF BB ?? ?? ?? ?? C7 85 20 FF FF FF 01 00 00 00 E9 94 00 00 00 2B 45 08 89 85 20 FF FF FF }
	condition:
		$pattern
}

rule glob_in_dir_2552941b2e37c23461e67b9b497ea5e5 {
	meta:
		aliases = "glob_in_dir"
		size = "1281"
		objfiles = "glob64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 81 EC F8 00 00 00 89 85 1C FF FF FF 89 95 18 FF FF FF 89 8D 14 FF FF FF 8B 75 08 52 E8 ?? ?? ?? ?? 5A 59 89 85 20 FF FF FF 8B 9D 14 FF FF FF 83 E3 40 0F 94 C0 0F B6 C0 50 FF B5 1C FF FF FF E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 D1 00 00 00 F7 85 14 FF FF FF 10 08 00 00 0F 85 B5 00 00 00 85 DB 75 1A 50 50 6A 5C FF B5 1C FF FF FF E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 A3 00 00 00 83 EC 0C FF B5 1C FF FF FF E8 ?? ?? ?? ?? 83 C4 10 89 C6 8B 95 20 FF FF FF 8D 44 10 20 83 E0 F0 29 C4 8D 5C 24 0F 83 E3 F0 50 52 FF B5 18 FF FF FF 53 E8 ?? ?? ?? ?? 83 C4 0C 6A 01 68 ?? ?? ?? ?? 50 E8 ?? ?? }
	condition:
		$pattern
}

rule __floatundisf_7e022a0b49b4d66bf1d658ce9b58b703 {
	meta:
		aliases = "__floatundisf"
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
		size = "135"
		objfiles = "_floatdisf@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 04 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 75 08 8B 7D 0C 89 F0 89 FA 83 C0 FF 81 D2 FF FF 1F 00 81 FA FF FF 3F 00 72 20 76 4E 89 F0 25 FF 07 00 00 31 D2 89 D1 09 C1 74 0F 89 F0 25 00 F8 FF FF 89 C6 81 CE 00 08 00 00 89 F0 89 FA 89 D0 89 C2 C1 FA 1F D9 83 ?? ?? ?? ?? 50 DA 0C 24 31 D2 89 14 24 56 DF 2C 24 DE C1 D9 5D F0 D9 45 F0 83 C4 0C 5B 5E 5F 5D C3 89 F6 83 F8 FE 76 CB EB AB }
	condition:
		$pattern
}

rule sched_setaffinity_ded25f53ce541207841386f9058a766b {
	meta:
		aliases = "sched_setaffinity"
		size = "221"
		objfiles = "sched_setaffinity@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 83 3D ?? ?? ?? ?? 00 75 76 81 EC 90 00 00 00 8D 5C 24 0F 83 E3 F0 BE 80 00 00 00 EB 21 8D 0C 36 8D 41 1E 83 E0 F0 29 C4 8D 54 24 0F 83 E2 F0 8D 04 0A 39 D8 74 04 89 CE EB 02 01 CE 89 D3 E8 ?? ?? ?? ?? 89 C7 89 F1 89 DA 53 89 FB B8 F2 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 05 83 F8 EA 74 BB 85 FF 74 08 81 FF 00 F0 FF FF 76 0B E8 ?? ?? ?? ?? F7 DF 89 38 EB 50 89 3D ?? ?? ?? ?? A1 ?? ?? ?? ?? EB 17 8B 7D 10 80 3C 07 00 74 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 2D 40 3B 45 0C 72 E4 8B 7D 08 8B 4D 0C 8B 55 10 53 89 FB B8 F1 00 00 00 CD 80 5B 89 C3 81 FB 00 F0 FF FF 76 }
	condition:
		$pattern
}

rule pthread_cleanup_upto_877dbaeca41973fc9369702df23b0aba {
	meta:
		aliases = "pthread_cleanup_upto"
		size = "146"
		objfiles = "ptlongjmp@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 89 C7 89 E8 BE ?? ?? ?? ?? 3B 2D ?? ?? ?? ?? 73 32 3B 2D ?? ?? ?? ?? 72 0D BE ?? ?? ?? ?? 3B 2D ?? ?? ?? ?? 72 1D 83 3D ?? ?? ?? ?? 00 74 09 E8 ?? ?? ?? ?? 89 C6 EB 0B 0D FF FF 1F 00 8D B0 21 FE FF FF 89 6D F0 8B 5E 3C EB 17 3B 5D F0 77 04 31 DB EB 17 83 EC 0C FF 73 04 FF 13 8B 5B 0C 83 C4 10 85 DB 74 05 3B 5F 10 72 E0 89 5E 3C 8B 46 54 85 C0 74 0C 3B 47 10 73 07 C7 46 54 00 00 00 00 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule pthread_sighandler_443957d682fb29d7ccbb8b94b793f2ba {
	meta:
		aliases = "pthread_sighandler"
		size = "96"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 5D 08 E8 ?? ?? ?? ?? 89 C7 80 78 58 00 74 09 C6 40 58 00 89 58 20 EB 36 8B 70 54 85 F6 75 03 89 68 54 83 EC 5C 89 E2 8D 45 0C 51 51 6A 58 50 52 E8 ?? ?? ?? ?? 83 C4 14 53 FF 14 9D ?? ?? ?? ?? 83 C4 60 85 F6 75 07 C7 47 54 00 00 00 00 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule pthread_sighandler_rt_6355847e95b75a39d4660e59a58d7a0c {
	meta:
		aliases = "pthread_sighandler_rt"
		size = "81"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 75 08 E8 ?? ?? ?? ?? 89 C7 80 78 58 00 74 09 C6 40 58 00 89 70 20 EB 27 8B 58 54 85 DB 75 03 89 68 54 50 FF 75 10 FF 75 0C 56 FF 14 B5 ?? ?? ?? ?? 83 C4 10 85 DB 75 07 C7 47 54 00 00 00 00 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __GI_nan_9bc31f50cd8270123206ef2030dcf46b {
	meta:
		aliases = "nan, __GI_nan"
		size = "87"
		objfiles = "nan@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 7D 08 80 3F 00 75 08 D9 05 ?? ?? ?? ?? EB 36 89 E3 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 83 C0 24 83 E0 F0 29 C4 8D 74 24 0F 83 E6 F0 50 57 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 5F 58 6A 00 56 E8 ?? ?? ?? ?? 89 DC 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule nanf_454b8f9a43331570e81b9637d10a4347 {
	meta:
		aliases = "__GI_nanf, nanf"
		size = "87"
		objfiles = "nan@libm.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 7D 08 80 3F 00 75 08 D9 05 ?? ?? ?? ?? EB 36 89 E3 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 83 C0 24 83 E0 F0 29 C4 8D 74 24 0F 83 E6 F0 51 57 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 58 5A 6A 00 56 E8 ?? ?? ?? ?? 89 DC 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _Unwind_RaiseException_Phase2_20a98fa5da8e2fee043b1642f0189b6e {
	meta:
		aliases = "_Unwind_RaiseException_Phase2"
		size = "146"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 89 45 F0 89 D7 8B 02 EB 55 89 F6 8B 50 18 31 C9 8B 75 F0 3B 46 10 0F 94 C0 25 FF 00 00 00 89 C6 C1 E6 02 85 C9 75 44 85 D2 74 29 83 EC 08 57 8B 45 F0 50 8B 45 F0 8B 48 04 51 8B 08 51 89 F0 83 C8 02 50 6A 01 FF D2 83 C4 20 83 F8 07 74 21 83 F8 08 75 17 85 F6 75 20 8B 07 8B 00 89 07 85 C0 75 A9 B9 05 00 00 00 31 D2 EB A5 B8 02 00 00 00 8D 65 F4 5B 5E 5F 5D C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __popcountdi2_334b955d1658a4f11dc73b75fd9505bc {
	meta:
		aliases = "__popcountdi2"
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
		size = "110"
		objfiles = "_addvdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 75 08 8B 7D 0C 8B 45 10 8B 55 14 01 F0 11 FA 89 45 E8 89 55 EC 8B 4D 14 85 C9 78 1E 39 FA 7C 0A 7F 28 39 F0 73 24 8D 74 26 00 E8 ?? ?? ?? ?? 8D 74 26 00 8D BC 27 00 00 00 00 39 7D EC 7F EB 7C 09 39 75 E8 77 E4 8D 74 26 00 8B 45 E8 8B 55 EC 83 C4 0C 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule search_for_named_library_758c409baea66bda21cd20c47b861911 {
	meta:
		aliases = "search_for_named_library"
		size = "270"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C 89 45 EC 89 55 E8 89 CA 85 C9 0F 84 EB 00 00 00 8D 41 FF 40 80 38 00 75 FA 29 D0 8D 70 01 8D 46 1E 83 E0 F0 29 C4 8D 5C 24 0F 83 E3 F0 89 DF 81 EC 20 08 00 00 8D 44 24 0F 83 E0 F0 89 45 E4 8D 4B FF 4A EB 07 41 42 8A 02 88 01 4E 85 F6 75 F5 89 D8 C7 45 F0 00 00 00 00 8B 55 E4 8D 72 FF 8B 55 EC 4A 89 55 E0 80 3F 00 75 0A C6 07 3A C7 45 F0 01 00 00 00 80 3F 3A 75 75 C6 07 00 80 38 00 74 11 89 F1 8D 50 FF 41 42 8A 02 88 01 84 C0 74 13 EB F4 89 F2 B9 ?? ?? ?? ?? 42 41 8A 01 88 02 84 C0 75 F6 89 F3 89 F0 40 80 38 00 75 FA 8D 50 FF B9 ?? ?? ?? ?? 42 41 8A 01 88 02 84 C0 75 }
	condition:
		$pattern
}

rule __getdents64_1f159e54662c0d41fa1b68bd5eec9548 {
	meta:
		aliases = "__getdents64"
		size = "274"
		objfiles = "getdents64@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C 8B 55 10 8B 45 0C 89 45 DC 8D 42 1E 83 E0 F0 29 C4 8D 4C 24 0F 83 E1 F0 8B 7D 08 53 89 FB B8 DC 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0B E8 ?? ?? ?? ?? F7 DE 89 30 EB 60 83 F8 FF 74 5B 89 CB C7 45 E8 FF FF FF FF C7 45 EC FF FF FF FF 8D 34 01 89 75 E4 03 55 0C 89 55 E0 E9 92 00 00 00 0F B7 43 10 8D 48 03 83 E1 FC 8B 75 DC 01 CE 3B 75 E0 76 2B 6A 00 FF 75 EC FF 75 E8 FF 75 08 E8 ?? ?? ?? ?? 83 C4 10 8B 45 0C 39 45 DC 75 6C E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 62 8B 43 08 8B 53 0C 89 45 E8 89 55 EC 8B 03 8B 53 04 8B 7D DC 89 07 89 57 04 8B 43 08 8B 53 0C 89 }
	condition:
		$pattern
}

rule pthread_cond_wait_418fe441485ce6526cced6e63bc4a70c {
	meta:
		aliases = "__GI_pthread_cond_wait, pthread_cond_wait"
		size = "315"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C 8B 5D 08 8B 75 0C E8 ?? ?? ?? ?? 89 45 F0 8B 46 0C 83 F8 03 74 15 85 C0 74 11 8B 45 F0 BA 16 00 00 00 39 46 08 0F 85 FD 00 00 00 89 5D E8 C7 45 EC ?? ?? ?? ?? 8B 45 F0 C6 80 B9 01 00 00 00 8B 45 F0 8D 55 E8 E8 ?? ?? ?? ?? 8B 55 F0 89 D8 E8 ?? ?? ?? ?? 8B 45 F0 80 78 42 00 74 0E 8B 45 F0 BF 01 00 00 00 80 78 40 00 74 0D 8B 55 F0 8D 43 08 E8 ?? ?? ?? ?? 31 FF 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 FF 74 0E 8B 45 F0 31 D2 E8 ?? ?? ?? ?? 57 57 EB 6E 83 EC 0C 56 E8 ?? ?? ?? ?? 31 DB 83 C4 10 8B 45 F0 E8 ?? ?? ?? ?? 8B 45 F0 80 B8 B9 01 00 00 00 75 18 8B 45 F0 80 B8 B8 01 }
	condition:
		$pattern
}

rule execvp_a79d91337e93696f82147998c30784ea {
	meta:
		aliases = "__GI_execvp, execvp"
		size = "442"
		objfiles = "execvp@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C 8B 75 08 80 3E 00 75 10 E8 ?? ?? ?? ?? C7 00 02 00 00 00 E9 8E 01 00 00 50 50 6A 2F 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 79 57 FF 35 ?? ?? ?? ?? FF 75 0C 56 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 38 08 0F 85 5C 01 00 00 31 C0 EB 01 40 8D 14 85 00 00 00 00 8B 4D 0C 83 3C 11 00 75 EF 8D 42 26 83 E0 F0 29 C4 8D 5C 24 0F 83 E3 F0 8B 01 89 03 89 73 04 56 52 89 C8 83 C0 04 50 8D 43 08 50 E8 ?? ?? ?? ?? 83 C4 0C FF 35 ?? ?? ?? ?? 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 E9 04 01 00 00 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C7 83 C4 10 85 C0 75 07 BF ?? ?? ?? ?? EB 09 }
	condition:
		$pattern
}

rule sem_timedwait_52242e89bae466e5749099b05f3a718c {
	meta:
		aliases = "sem_timedwait"
		size = "368"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C 8B 75 08 E8 ?? ?? ?? ?? 89 45 E0 89 C2 89 F0 E8 ?? ?? ?? ?? 8B 46 08 85 C0 7E 11 48 89 46 08 83 EC 0C 56 E8 ?? ?? ?? ?? 31 C0 EB 23 8B 45 0C 81 78 04 FF C9 9A 3B 76 1F 83 EC 0C 56 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 83 C4 10 E9 08 01 00 00 89 75 EC C7 45 F0 ?? ?? ?? ?? 8B 45 E0 C6 80 BA 01 00 00 00 8D 55 EC 8B 45 E0 E8 ?? ?? ?? ?? 8B 45 E0 80 78 42 00 74 0B BB 01 00 00 00 80 78 40 00 74 0D 8D 46 0C 8B 55 E0 E8 ?? ?? ?? ?? 31 DB 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 8D 7E 0C 85 DB 74 0F 31 D2 8B 45 E0 E8 ?? ?? ?? ?? E9 9A 00 00 00 51 51 FF 75 0C FF }
	condition:
		$pattern
}

rule __GI_pthread_cond_timedwait_e9459ce0efcfd0102d071e8aa6ba5e57 {
	meta:
		aliases = "pthread_cond_timedwait, __GI_pthread_cond_timedwait"
		size = "428"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C 8B 7D 0C E8 ?? ?? ?? ?? 89 45 F0 8B 47 0C 83 F8 03 74 15 85 C0 74 11 8B 45 F0 BA 16 00 00 00 39 47 08 0F 85 71 01 00 00 8B 45 08 89 45 E8 C7 45 EC ?? ?? ?? ?? 8B 45 F0 C6 80 B9 01 00 00 00 8B 45 F0 8D 55 E8 E8 ?? ?? ?? ?? 8B 55 F0 8B 45 08 E8 ?? ?? ?? ?? 8B 45 F0 80 78 42 00 74 0E 8B 45 F0 BB 01 00 00 00 80 78 40 00 74 10 8B 55 F0 8B 45 08 83 C0 08 E8 ?? ?? ?? ?? 31 DB 83 EC 0C FF 75 08 E8 ?? ?? ?? ?? 83 C4 10 85 DB 74 11 8B 45 F0 31 D2 E8 ?? ?? ?? ?? 51 51 E9 D6 00 00 00 83 EC 0C 57 E8 ?? ?? ?? ?? 31 F6 83 C4 10 8B 45 08 83 C0 08 89 45 E0 8B 45 F0 52 52 FF 75 10 50 }
	condition:
		$pattern
}

rule execle_398160867dcf5e08b9e53f596d308a53 {
	meta:
		aliases = "__GI_execle, execle"
		size = "111"
		objfiles = "execle@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C 8D 45 10 89 45 F0 31 F6 46 8B 55 F0 8D 42 04 89 45 F0 83 3A 00 75 F1 8D 42 08 89 45 F0 8B 7A 04 8D 04 B5 22 00 00 00 83 E0 F0 29 C4 8D 5C 24 0F 83 E3 F0 8B 45 0C 89 03 8D 45 10 89 45 F0 89 D9 83 C1 04 8B 45 F0 8D 50 04 89 55 F0 8B 00 89 01 4E 75 ED 50 57 53 FF 75 08 E8 ?? ?? ?? ?? 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __gcc_personality_sj0_9f34bc712db133ae55fb9d9bc4926355 {
	meta:
		aliases = "__gcc_personality_sj0"
		size = "581"
		objfiles = "unwind_c@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 83 7D 08 01 74 15 B8 03 00 00 00 8D 65 F4 5B 5E 5F 5D C3 90 8D B4 26 00 00 00 00 F6 45 0C 02 75 1A B8 08 00 00 00 8D 65 F4 5B 5E 5F 5D C3 8D B6 00 00 00 00 8D BC 27 00 00 00 00 C7 45 F0 00 00 00 00 83 EC 0C 8B 45 1C 50 E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 C0 74 CA 8B 7D 1C 85 FF 74 0F 83 EC 0C 8B 4D 1C 51 E8 ?? ?? ?? ?? 83 C4 10 0F B6 3E 46 89 F8 3C FF 0F 84 90 00 00 00 89 FA 81 E2 FF 00 00 00 89 55 E0 89 D0 83 E0 70 83 F8 20 0F 84 74 01 00 00 0F 8E 26 01 00 00 83 F8 40 0F 84 79 01 00 00 83 F8 50 74 23 83 F8 30 0F 85 20 01 00 00 83 EC }
	condition:
		$pattern
}

rule _Unwind_ForcedUnwind_Phase2_1f93847fcb98d18f72effa5f32e91664 {
	meta:
		aliases = "_Unwind_ForcedUnwind_Phase2"
		size = "203"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 89 45 E4 89 D7 8B 40 0C 89 45 E8 8B 55 E4 8B 52 10 89 55 EC EB 7B 90 8D 74 26 00 8B 40 18 89 45 F0 B8 0A 00 00 00 31 F6 52 8B 4D EC 51 57 8B 55 E4 52 8B 55 E4 8B 4A 04 51 8B 12 52 50 6A 01 FF 55 E8 83 C4 20 85 C0 75 5E 83 FE 05 74 5E 8B 45 F0 85 C0 74 28 83 EC 08 57 8B 75 E4 56 8B 45 E4 8B 48 04 51 8B 10 52 6A 0A 6A 01 FF 55 F0 89 C6 83 C4 20 83 F8 07 74 34 83 F8 08 75 2A 83 EC 0C 8B 07 50 E8 ?? ?? ?? ?? 8B 07 8B 00 89 07 83 C4 10 8B 07 85 C0 75 84 B0 1A BE 05 00 00 00 C7 45 F0 00 00 00 00 EB 81 BE 02 00 00 00 89 F0 8D 65 F4 5B 5E }
	condition:
		$pattern
}

rule read_encoded_value_with_base_bcce2527dc36fc1f59e24a1a50b39df5 {
	meta:
		aliases = "read_encoded_value_with_base"
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
		size = "186"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 89 C6 80 78 09 7A 74 0A 31 C0 8D 65 F4 5B 5E 5F 5D C3 8D 78 09 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 8D 44 07 01 8D 7D EC 89 FA E8 8C FB FF FF 8D 55 E8 E8 D4 FB FF FF 80 7E 08 01 74 65 89 FA E8 77 FB FF FF 89 FA E8 70 FB FF FF 8A 56 0A 80 FA 52 74 40 83 C6 0A 8D 7D F0 EB 0F 80 FA 4C 75 A8 40 8A 56 01 46 80 FA 52 74 29 80 FA 50 75 EC 83 EC 0C 8D 48 01 8A 00 25 FF 00 00 00 83 E0 7F 57 31 D2 E8 E4 FD FF FF 83 C4 10 8A 56 01 46 80 FA 52 75 D7 8A 00 25 FF 00 00 00 8D 65 F4 5B 5E 5F 5D C3 40 EB 9F }
	condition:
		$pattern
}

rule _Unwind_SjLj_RaiseException_1da6a6ee605a5092fb3b06367f95d37b {
	meta:
		aliases = "_Unwind_SjLj_RaiseException"
		size = "173"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 75 08 8B 83 ?? ?? ?? ?? 89 45 F0 89 45 EC 85 C0 74 3A 8D 7D EC EB 06 8D 76 00 89 45 EC 8B 40 18 85 C0 74 1F 83 EC 08 57 56 8B 4E 04 51 8B 16 52 6A 01 6A 01 FF D0 83 C4 20 83 F8 06 74 1B 83 F8 08 75 47 8B 45 EC 8B 00 85 C0 75 CE B8 05 00 00 00 8D 65 F4 5B 5E 5F 5D C3 C7 46 0C 00 00 00 00 8B 45 EC 89 46 10 8B 45 F0 89 45 EC 89 FA 89 F0 E8 F5 FD FF FF 83 F8 07 75 D7 8D 45 F0 89 FA E8 86 FE FF FF 8D B6 00 00 00 00 B8 03 00 00 00 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _Unwind_Backtrace_9e66887d2a43f0678204ca91150f14b5 {
	meta:
		aliases = "_Unwind_Backtrace"
		size = "103"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 83 ?? ?? ?? ?? 89 45 F0 8D 7D F0 EB 1A 8D B6 00 00 00 00 8D BC 27 00 00 00 00 83 FE 05 74 28 8B 45 F0 8B 00 89 45 F0 83 7D F0 01 19 F6 83 E6 05 83 EC 08 8B 45 0C 50 57 FF 55 08 83 C4 10 85 C0 74 D8 BE 03 00 00 00 89 F0 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule _Unwind_Find_FDE_8c2704e9227c9af4e3e0a5a9cc973aa9 {
	meta:
		aliases = "_Unwind_Find_FDE"
		size = "313"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 1C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B BB ?? ?? ?? ?? 85 FF 74 23 8B 45 08 3B 07 72 15 E9 D7 00 00 00 90 8D 74 26 00 8B 55 08 39 17 0F 86 C7 00 00 00 8B 7F 14 85 FF 75 EE 31 F6 8D 83 ?? ?? ?? ?? 89 45 DC 8D 76 00 8B BB ?? ?? ?? ?? 85 FF 0F 84 9A 00 00 00 8B 47 14 89 83 ?? ?? ?? ?? 8B 55 08 89 F8 E8 6F F8 FF FF 89 C6 8B 83 ?? ?? ?? ?? 85 C0 0F 84 96 00 00 00 8B 0F 39 08 73 0D E9 8B 00 00 00 8D 74 26 00 39 08 72 0A 8D 50 14 8B 40 14 85 C0 75 F2 89 47 14 89 3A 85 F6 74 A9 8B 47 04 8B 55 0C 89 02 8B 47 08 89 42 04 8B 47 10 66 C1 E8 03 F6 47 10 04 75 6A 25 FF 00 00 00 31 }
	condition:
		$pattern
}

rule __divdc3_ad7b95c2f870cd21c787e0671c6668f5 {
	meta:
		aliases = "__divdc3"
		size = "949"
		objfiles = "_divdc3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 24 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 4D 08 DD 45 0C DD 5D E8 DD 45 14 DD 5D E0 DD 45 1C DD 55 D8 DD 45 24 DD 55 D0 D9 C1 D9 E1 D9 C9 D9 E1 DA E9 DF E0 F6 C4 45 75 4F DD 45 D0 D8 F9 DC C9 D9 C9 DC 45 D0 DD 45 E8 D8 CA DC 45 E0 D8 F1 DD 45 E0 DE CB D9 CA DC 65 E8 DE F1 D9 C9 DD E0 DF E0 80 E4 45 80 FC 40 75 49 DD 19 DD 59 08 89 C8 83 C4 24 5B 5E 5F 5D C2 04 00 8D B4 26 00 00 00 00 8D BC 27 00 00 00 00 DD D8 DD 45 D0 DC 75 D8 DD 45 D0 D8 C9 DC 45 D8 DD 45 E0 D8 CA DC 45 E8 D8 F1 D9 CA DC 4D E8 DD 45 E0 DE E1 DE F1 D9 C9 EB AB D9 C9 DD E0 DF E0 80 E4 45 80 FC 40 75 04 }
	condition:
		$pattern
}

rule iruserok2_a9e638e4b292cb2039f3422af59d1dd9 {
	meta:
		aliases = "iruserok2"
		size = "331"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C 89 45 CC 89 D6 89 4D C8 85 D2 75 12 31 D2 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 85 C0 75 05 83 CF FF EB 28 57 57 FF 75 0C FF 75 C8 8B 4D 08 8B 55 CC E8 ?? ?? ?? ?? 89 C7 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 85 FF 0F 84 ED 00 00 00 0B 35 ?? ?? ?? ?? 0F 84 DE 00 00 00 83 EC 0C 6A 46 E8 ?? ?? ?? ?? 8D 50 1E 83 E2 F0 83 C4 10 29 D4 8D 4C 24 0F 83 E1 F0 83 EC 0C 8D 55 F0 52 50 51 8D 45 D4 50 FF 75 08 E8 ?? ?? ?? ?? 83 C4 20 85 C0 0F 85 A2 00 00 00 8B 45 F0 85 C0 0F 84 97 00 00 00 83 EC 0C FF 70 14 E8 ?? ?? ?? ?? 83 C0 09 89 04 24 E8 ?? ?? ?? ?? 89 C3 59 5E 8B 45 F0 FF 70 14 53 }
	condition:
		$pattern
}

rule gaih_inet_serv_e95d8db75853a629a2027277ee691684 {
	meta:
		aliases = "gaih_inet_serv"
		size = "147"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C 89 45 D0 89 D3 89 4D CC 8B 7D 08 BE 00 04 00 00 8D 46 1E 83 E0 F0 29 C4 8D 44 24 0F 83 E0 F0 52 52 8D 55 F0 52 56 50 8D 45 E0 50 8D 43 03 50 FF 75 D0 E8 ?? ?? ?? ?? 83 C4 20 85 C0 75 08 83 7D F0 00 75 0B EB 37 83 F8 22 75 32 01 F6 EB C1 C7 07 00 00 00 00 0F BE 03 89 47 04 F6 43 02 02 74 08 8B 55 CC 8B 42 0C EB 04 0F BE 43 01 89 47 08 8B 45 F0 8B 40 08 89 47 0C 31 C0 EB 05 B8 08 01 00 00 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule if_nameindex_0f87366271a49e86f9f314443570be86 {
	meta:
		aliases = "__GI_if_nameindex, if_nameindex"
		size = "410"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 2C E8 ?? ?? ?? ?? 89 45 D4 C7 45 DC 00 00 00 00 85 C0 0F 88 6F 01 00 00 C7 45 F0 00 00 00 00 B9 80 00 00 00 8D 75 EC 8D 1C 09 8D 43 1E 83 E0 F0 29 C4 8D 54 24 0F 83 E2 F0 8D 04 1A 3B 45 F0 75 02 01 CB 89 55 F0 89 5D EC 50 56 68 12 89 00 00 FF 75 D4 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 17 83 EC 0C FF 75 D4 E8 ?? ?? ?? ?? C7 45 DC 00 00 00 00 E9 0E 01 00 00 8B 45 EC 39 D8 75 04 89 C1 EB A6 C1 E8 05 89 45 D8 83 EC 0C 8D 04 C5 08 00 00 00 50 E8 ?? ?? ?? ?? 89 45 DC 83 C4 10 31 FF 85 C0 0F 85 B6 00 00 00 83 EC 0C FF 75 D4 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 69 00 00 00 E9 C2 00 }
	condition:
		$pattern
}

rule __mulvdi3_1d63f6ff4a3b6b759383d482641f6acf {
	meta:
		aliases = "__mulvdi3"
		size = "406"
		objfiles = "_mulvdi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 3C E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 75 08 8B 7D 0C 8B 45 10 8B 55 14 89 45 C8 89 55 CC 89 F9 89 75 E8 89 F0 C1 F8 1F 39 C7 75 23 89 D1 8B 75 C8 89 F0 C1 F8 1F 39 C2 75 71 8B 45 E8 F7 EE 89 C6 89 D7 89 F0 89 FA 83 C4 3C 5B 5E 5F 5D C3 8B 55 CC 8B 45 C8 89 45 EC C1 F8 1F 39 C2 0F 85 A9 00 00 00 8B 45 E8 F7 65 EC 89 55 C0 89 45 D8 89 55 DC 8B 45 EC F7 E7 89 45 D0 89 55 D4 85 FF 78 74 8B 45 EC 85 C0 78 65 8B 55 C0 31 C9 03 55 D0 13 4D D4 89 D0 C1 F8 1F 39 C8 0F 85 8E 00 00 00 89 55 DC 8B 75 D8 8B 7D DC EB 98 8B 45 E8 F7 E6 89 55 C4 89 45 E0 89 55 E4 8B 45 E8 F7 E1 89 }
	condition:
		$pattern
}

rule __muldc3_240d93b9e2379ad460be38f006a24b54 {
	meta:
		aliases = "__muldc3"
		size = "1226"
		objfiles = "_muldc3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 44 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B 55 08 DD 45 0C DD 55 C8 DD 45 14 DD 55 C0 DD 45 1C DD 55 B8 DD 45 24 DD 55 B0 D9 CB D8 C9 DD 5D E8 D9 C1 D8 CB DD 5D E0 DD 45 C8 DE CB D9 CA DD 5D D8 DE C9 DD 5D D0 DD 45 E8 DD 45 E0 D9 C1 D8 E1 DD 45 D8 DD 45 D0 D9 C1 D8 C1 D9 CB DD E0 DF E0 80 E4 45 80 FC 40 75 19 DD DC DD D8 DD D8 DD DA DD 1A DD 5A 08 89 D0 83 C4 44 5B 5E 5F 5D C2 04 00 D9 CB DD E0 DF E0 80 E4 45 80 FC 40 75 0A DD DD DD D8 DD D8 DD D9 EB D7 DD 45 C8 D8 E0 DD 45 C8 DD E8 DF E0 80 E4 45 80 F4 40 0F 85 DF 01 00 00 DD E8 DF E0 80 E4 45 80 F4 40 0F 84 D1 01 00 00 }
	condition:
		$pattern
}

rule callrpc_97059a1d276f0237a6e0e9f248634f43 {
	meta:
		aliases = "callrpc"
		size = "537"
		objfiles = "clnt_simple@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 4C C7 45 B8 00 00 00 00 C7 45 BC 00 00 00 00 C7 45 B0 00 00 00 00 C7 45 B4 00 00 00 00 E8 ?? ?? ?? ?? 89 C3 8B B0 A4 00 00 00 85 F6 75 22 56 56 6A 18 6A 01 E8 ?? ?? ?? ?? 89 C2 83 C4 10 31 C0 85 D2 0F 84 C1 01 00 00 89 D6 89 93 A4 00 00 00 83 7E 14 00 75 1D 83 EC 0C 68 00 01 00 00 E8 ?? ?? ?? ?? 89 46 14 C6 00 00 C7 46 04 FF FF FF FF 83 C4 10 83 7E 10 00 74 28 8B 45 0C 39 46 08 75 20 8B 55 10 39 56 0C 75 18 53 53 FF 75 08 FF 76 14 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 28 01 00 00 C7 46 10 00 00 00 00 8B 46 04 83 F8 FF 74 13 83 EC 0C 50 E8 ?? ?? ?? ?? C7 46 04 FF FF FF FF }
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

rule byte_re_compile_fastmap_2b3c1e9c0b5076c739f6e136ca1c0fb6 {
	meta:
		aliases = "byte_re_compile_fastmap"
		size = "809"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 5C 89 C6 8B 40 10 89 45 E0 8B 1E 8B 56 08 01 DA 89 55 E4 8D 4C 24 0F 83 E1 F0 89 4D F0 57 68 00 01 00 00 6A 00 50 E8 ?? ?? ?? ?? 8A 46 1C 83 C8 08 83 E0 FE 88 46 1C C6 45 EA 01 C6 45 EB 00 31 FF C7 45 EC 05 00 00 00 83 C4 10 8B 45 E0 83 C0 0A 89 45 D8 3B 5D E4 74 06 8A 03 3C 01 75 29 85 FF 8A 56 1C 0F 84 94 02 00 00 88 D0 83 E0 01 08 45 EA 83 E2 FE 0A 55 EA 88 56 1C 4F 8B 55 F0 8B 1C BA C6 45 EA 01 EB CC 43 3C 1D 0F 87 5C 02 00 00 0F B6 C0 FF 24 85 ?? ?? ?? ?? 31 D2 E9 CF 00 00 00 31 D2 E9 E9 00 00 00 80 4E 1C 01 E9 5E 02 00 00 0F B6 43 01 8B 4D E0 C6 04 01 01 E9 30 02 }
	condition:
		$pattern
}

rule __msgwrite_c556913f53827f621e4235f5160bcfc6 {
	meta:
		aliases = "__msgwrite"
		size = "179"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 6C 89 45 C0 89 D6 89 CF 8D 5C 24 0F 83 E3 F0 E8 ?? ?? ?? ?? 89 45 E0 E8 ?? ?? ?? ?? 89 45 E4 E8 ?? ?? ?? ?? 89 45 E8 50 6A 0C 8D 45 E0 50 8D 43 0C 50 E8 ?? ?? ?? ?? C7 43 04 01 00 00 00 C7 43 08 02 00 00 00 C7 03 18 00 00 00 89 75 EC 89 7D F0 8D 45 EC 89 45 CC C7 45 D0 01 00 00 00 C7 45 C4 00 00 00 00 C7 45 C8 00 00 00 00 89 5D D4 C7 45 D8 18 00 00 00 C7 45 DC 00 00 00 00 83 C4 10 8D 5D C4 50 6A 00 53 FF 75 C0 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 0D E8 ?? ?? ?? ?? 83 38 04 74 E3 83 C8 FF 8D 65 F4 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule rcmd_c406e5134923be08670bb687d104fe83 {
	meta:
		aliases = "rcmd"
		size = "1179"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 7C 8B 45 0C 66 89 45 86 E8 ?? ?? ?? ?? 89 45 8C 81 EC 10 04 00 00 8D 44 24 0F 83 E0 F0 BE 00 04 00 00 8D 7D E8 EB 3C 8B 5D EC 83 FB FF 75 0A E8 ?? ?? ?? ?? 83 38 22 74 19 E8 ?? ?? ?? ?? 89 18 83 EC 0C 8B 55 08 FF 32 E8 ?? ?? ?? ?? E9 2C 04 00 00 01 F6 8D 46 1E 83 E0 F0 29 C4 8D 44 24 0F 83 E0 F0 52 52 8D 55 EC 52 57 56 50 8D 45 94 50 8B 45 08 FF 30 E8 ?? ?? ?? ?? 83 C4 20 85 C0 75 A6 83 7D E8 00 74 A0 66 C7 45 AC 01 00 66 C7 45 B4 01 00 8B 45 E8 8B 00 8B 55 08 89 02 83 EC 0C 68 00 00 40 00 E8 ?? ?? ?? ?? 89 45 88 C7 45 E4 FF 03 00 00 BF 01 00 00 00 83 C4 10 83 EC 0C 8D }
	condition:
		$pattern
}

rule __divxc3_db7832f06ce5951e1cc9efa87ffb6542 {
	meta:
		aliases = "__divxc3"
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
		size = "81"
		objfiles = "_popcountsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 8B BB ?? ?? ?? ?? 8B 75 08 31 C0 8A 45 0A 31 C9 8A 0C 07 89 F2 0F B6 C6 8A 04 07 25 FF 00 00 00 01 C1 89 F0 25 FF 00 00 00 31 D2 8A 14 07 01 CA C1 EE 18 31 C0 8A 04 37 01 D0 5B 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __negdi2_a994d8013174792deac2e3dd32c55b6a {
	meta:
		aliases = "__negdi2"
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
		size = "74"
		objfiles = "unwind_c@libgcc_eh.a, unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 08 89 45 F0 89 55 F4 31 F6 31 FF 8D B4 26 00 00 00 00 8D BC 27 00 00 00 00 8B 45 F0 8A 10 40 89 45 F0 89 D0 83 E0 7F 89 F1 D3 E0 09 C7 83 C6 07 84 D2 78 E5 8B 45 F4 89 38 8B 45 F0 83 C4 08 5E 5F 5D C3 }
	condition:
		$pattern
}

rule read_sleb128_54a44737cdb2c6847e93f2e6f8a436fc {
	meta:
		aliases = "read_sleb128"
		size = "110"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 0C 89 45 EC 89 55 F0 31 FF C7 45 F4 00 00 00 00 89 F6 8D BC 27 00 00 00 00 8B 45 EC 8A 10 40 89 45 EC 88 D1 81 E1 FF 00 00 00 89 CE 89 C8 83 E0 7F 89 F9 D3 E0 09 45 F4 83 C7 07 84 D2 78 DA 83 FF 1F 77 11 83 E6 40 74 0C B8 FF FF FF FF 89 F9 D3 E0 09 45 F4 8B 55 F4 8B 45 F0 89 10 8B 45 EC 83 C4 0C 5E 5F 5D C3 }
	condition:
		$pattern
}

rule __ashrdi3_80b9183ce4b23344791d23107ea789c8 {
	meta:
		aliases = "__ashrdi3"
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
		size = "322"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 30 89 45 D8 89 D7 89 4D D4 89 C2 8B 40 10 66 C1 E8 03 25 FF 00 00 00 89 45 E0 E8 DA FC FF FF 89 45 E4 8B 37 85 F6 0F 84 F3 00 00 00 C7 45 DC 00 00 00 00 8D 45 F4 89 45 D0 EB 40 8D B4 26 00 00 00 00 8D BC 27 00 00 00 00 8B 57 08 89 55 F4 8B 47 0C 89 45 F0 85 D2 74 10 8B 45 D4 2B 45 F4 3B 45 F0 0F 82 B9 00 00 00 90 89 F8 03 07 8D 78 04 8B 70 04 85 F6 0F 84 A4 00 00 00 8B 47 04 85 C0 74 E7 8B 55 D8 F6 42 10 04 74 2E 8D 77 04 29 C6 39 75 DC 74 24 89 F0 E8 3D FE FF FF 89 45 E0 31 C0 8A 45 E0 8B 55 D8 E8 4D FC FF FF 89 45 E4 89 75 DC 8D B4 26 00 00 00 00 8B 4D E0 85 C9 74 89 8A }
	condition:
		$pattern
}

rule __umoddi3_afb92777a249600fc0e5ecf07a5bdb51 {
	meta:
		aliases = "__umoddi3"
		size = "407"
		objfiles = "_umoddi3@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 83 EC 30 C7 45 D0 00 00 00 00 C7 45 D4 00 00 00 00 8B 75 08 8B 7D 0C 8B 45 10 8B 55 14 89 45 EC 89 C1 89 55 E8 89 75 E4 89 75 F0 89 7D E0 89 FA 8B 45 E8 85 C0 75 24 39 F9 0F 86 8C 00 00 00 89 F0 F7 F1 89 55 D0 C7 45 D4 00 00 00 00 8B 45 D0 8B 55 D4 83 C4 30 5E 5F 5D C3 90 8B 4D E0 39 4D E8 76 18 89 75 D0 89 7D D4 8B 45 D0 8B 55 D4 83 C4 30 5E 5F 5D C3 90 8D 74 26 00 0F BD 45 E8 83 F0 1F 89 45 D8 75 74 8B 45 E0 39 45 E8 72 08 8B 4D E4 39 4D EC 77 0F 8B 55 E0 8B 45 E4 2B 45 EC 1B 55 E8 89 45 F0 8B 4D F0 89 4D D0 89 55 D4 8B 45 D0 8B 55 D4 83 C4 30 5E 5F 5D C3 EB 0D 90 90 90 90 90 }
	condition:
		$pattern
}

rule __divdi3_29ff45a6325c49662755140b12a86964 {
	meta:
		aliases = "__divdi3"
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
		size = "61"
		objfiles = "_cmpdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 8B 75 08 8B 7D 0C 8B 45 10 8B 55 14 39 D7 7C 1B 7F 06 39 C6 72 15 76 19 B8 02 00 00 00 5E 5F 5D C3 8D 76 00 8D BC 27 00 00 00 00 31 C0 5E 5F 5D C3 B8 01 00 00 00 EB E5 }
	condition:
		$pattern
}

rule __do_global_dtors_aux_7a7fa84751646e937248b5807aee71e0 {
	meta:
		aliases = "__do_global_dtors_aux"
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
		size = "29"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 8B 55 08 8B 42 08 85 C0 74 0B 83 EC 08 52 6A 01 FF D0 83 C4 10 C9 C3 }
	condition:
		$pattern
}

rule __fixunssfsi_861889b8bca661734b42669772a5a81a {
	meta:
		aliases = "__fixunssfsi"
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
		size = "81"
		objfiles = "crtbegin, crtbeginT"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 E8 00 00 00 00 5A 81 C2 ?? ?? ?? ?? B8 ?? ?? ?? ?? 85 C0 74 15 52 6A 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 A1 ?? ?? ?? ?? 85 C0 74 16 B8 ?? ?? ?? ?? 85 C0 74 0D 83 EC 0C 68 ?? ?? ?? ?? FF D0 83 C4 10 C9 C3 }
	condition:
		$pattern
}

rule pthread_testcancel_5ce9f9bf0c84b4560d9bfdddb919f666 {
	meta:
		aliases = "pthread_testcancel"
		size = "35"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 08 E8 ?? ?? ?? ?? 80 78 42 00 74 10 80 78 40 00 75 0A 50 50 55 6A FF E8 ?? ?? ?? ?? C9 C3 }
	condition:
		$pattern
}

rule __GI_pthread_exit_83e56a658c13c6b420f924ab76774e5d {
	meta:
		aliases = "pthread_exit, __GI_pthread_exit"
		size = "15"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 83 EC 10 55 FF 75 08 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_find_self_70df40a9518defd62a9e6091637b26f4 {
	meta:
		aliases = "__pthread_find_self"
		size = "29"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 89 E9 BA ?? ?? ?? ?? EB 03 83 C2 10 8B 42 08 39 C1 77 F6 3B 4A 0C 72 F1 5D C3 }
	condition:
		$pattern
}

rule thread_self_d71c1c543da7010362c2339043c20f2c {
	meta:
		aliases = "thread_self"
		size = "68"
		objfiles = "spinlock@libpthread.a, cancel@libpthread.a, join@libpthread.a, mutex@libpthread.a, semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 89 EA B8 ?? ?? ?? ?? 3B 2D ?? ?? ?? ?? 73 30 3B 2D ?? ?? ?? ?? 72 0D B8 ?? ?? ?? ?? 3B 2D ?? ?? ?? ?? 72 1B 83 3D ?? ?? ?? ?? 00 74 06 5D E9 ?? ?? ?? ?? 81 CA FF FF 1F 00 8D 82 21 FE FF FF 5D C3 }
	condition:
		$pattern
}

rule __ffssi2_75fcfda88b2463b982a19044acb25b46 {
	meta:
		aliases = "__ffssi2"
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
		size = "20"
		objfiles = "_absvsi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 85 C0 78 06 5D C3 8D 74 26 00 F7 D8 5D C3 }
	condition:
		$pattern
}

rule _Unwind_GetCFA_d66b7f0ed7a6f653f8703bcca959b8ec {
	meta:
		aliases = "_Unwind_GetCFA"
		size = "17"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 00 85 C0 74 03 8B 40 28 5D C3 }
	condition:
		$pattern
}

rule _Unwind_GetIP_a7126c729d39df5fb2b09d48333dfd6a {
	meta:
		aliases = "_Unwind_GetIP"
		size = "14"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 00 8B 40 04 40 5D C3 }
	condition:
		$pattern
}

rule _Unwind_GetLanguageSpecificDat_03788f937622db0700293d7a71b17120 {
	meta:
		aliases = "_Unwind_GetLanguageSpecificData"
		size = "13"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 00 8B 40 1C 5D C3 }
	condition:
		$pattern
}

rule _Unwind_SetGR_c74249c3aec845f1d009059431a09b07 {
	meta:
		aliases = "_Unwind_SetGR"
		size = "20"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 08 8B 55 10 8B 45 0C 89 54 81 08 5D C3 }
	condition:
		$pattern
}

rule _Unwind_SetIP_b770eeb82fb02dcc792dfcdd24557910 {
	meta:
		aliases = "_Unwind_SetIP"
		size = "17"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 10 8B 45 0C 48 89 42 04 5D C3 }
	condition:
		$pattern
}

rule _Unwind_GetGR_fec1c3f00795c106a6e1e7f41810bedc {
	meta:
		aliases = "_Unwind_GetGR"
		size = "17"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 10 8B 45 0C 8B 44 82 08 5D C3 }
	condition:
		$pattern
}

rule __paritydi2_6bf41cdaa8036e11216ed1947f710266 {
	meta:
		aliases = "__paritydi2"
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
		size = "25"
		objfiles = "_absvdi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 08 8B 55 0C 85 D2 78 03 5D C3 90 F7 D8 83 D2 00 F7 DA 5D C3 }
	condition:
		$pattern
}

rule _Unwind_GetIPInfo_3c93d829c800f52ce3ec2fbbecd4d1fe {
	meta:
		aliases = "_Unwind_GetIPInfo"
		size = "23"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 0C C7 00 00 00 00 00 8B 45 08 8B 00 8B 40 04 40 5D C3 }
	condition:
		$pattern
}

rule fde_unencoded_compare_181f33e525491d15f6affa4cc809cd75 {
	meta:
		aliases = "fde_unencoded_compare"
		size = "39"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 45 10 8B 50 08 8B 45 0C 39 50 08 77 0F 19 C0 5D C3 8D 74 26 00 8D BC 27 00 00 00 00 B8 01 00 00 00 5D C3 }
	condition:
		$pattern
}

rule __paritysi2_8dce14b3f1c6de6e96832eecd10c45b2 {
	meta:
		aliases = "__paritysi2"
		size = "42"
		objfiles = "_paritysi2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 8B 55 08 89 D0 C1 E8 10 31 D0 89 C2 C1 EA 08 31 C2 89 D1 C1 E9 04 31 D1 83 E1 0F B8 96 69 00 00 D3 F8 83 E0 01 5D C3 }
	condition:
		$pattern
}

rule __gnat_install_locks_8b3b439c56705975420bae8114b1a69f {
	meta:
		aliases = "__gnat_install_locks"
		size = "35"
		objfiles = "gthr_gnat@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? 8B 45 08 89 81 ?? ?? ?? ?? 8B 45 0C 89 81 ?? ?? ?? ?? 5D C3 }
	condition:
		$pattern
}

rule _Unwind_SjLj_Unregister_dd0a7b846cc96730f8e468a98324f668 {
	meta:
		aliases = "_Unwind_SjLj_Unregister"
		size = "28"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? 8B 45 08 8B 00 89 81 ?? ?? ?? ?? 5D C3 }
	condition:
		$pattern
}

rule __floatundixf_7a575897b2cc0ade6d72ff041b51e8dc {
	meta:
		aliases = "__floatundidf, __floatundixf"
		size = "51"
		objfiles = "_floatundidf@libgcc.a, _floatundixf@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? 8B 45 0C 31 D2 52 50 DF 2C 24 83 C4 08 D8 89 ?? ?? ?? ?? 8B 45 08 31 D2 52 50 DF 2C 24 83 C4 08 DE C1 5D C3 }
	condition:
		$pattern
}

rule __register_frame_info_table_ba_b9a7ee2c5ac01787265ef94c052d5770 {
	meta:
		aliases = "__register_frame_info_table_bases"
		size = "76"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? 8B 45 0C C7 00 FF FF FF FF 8B 55 10 89 50 04 8B 55 14 89 50 08 8B 55 08 89 50 0C C7 40 10 00 00 00 00 80 48 10 02 66 81 48 10 F8 07 8B 91 ?? ?? ?? ?? 89 50 14 89 81 ?? ?? ?? ?? 5D C3 }
	condition:
		$pattern
}

rule _Unwind_SjLj_Register_cf2004594875d5e2dacc9ab6399ade93 {
	meta:
		aliases = "_Unwind_SjLj_Register"
		size = "34"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? 8B 55 08 8B 81 ?? ?? ?? ?? 89 02 89 91 ?? ?? ?? ?? 5D C3 }
	condition:
		$pattern
}

rule __powisf2_589cd186365ee16d07aabb661867eb5b {
	meta:
		aliases = "__powisf2"
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
		size = "112"
		objfiles = "_powidf2@libgcc.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 E8 00 00 00 00 59 81 C1 ?? ?? ?? ?? DD 45 08 8B 55 10 89 D0 85 D2 78 51 A8 01 74 45 D9 C0 D1 E8 74 31 8D 74 26 00 8D BC 27 00 00 00 00 D9 C9 D8 C8 A8 01 74 18 DC C9 D1 E8 75 F4 DD D8 85 D2 78 18 5D C3 8D 76 00 8D BC 27 00 00 00 00 D9 C9 D1 E8 75 DA DD D9 85 D2 79 E8 D8 B9 ?? ?? ?? ?? 5D C3 D9 81 ?? ?? ?? ?? EB B5 F7 D8 EB AB }
	condition:
		$pattern
}

rule dyn_string_init_93771ce539eb51ac72616b1dc1db84ca {
	meta:
		aliases = "dyn_string_init"
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
		size = "1144"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) BA 00 01 00 00 48 89 E5 41 57 41 56 41 55 41 54 49 89 FC 53 48 83 EC 38 48 8B 5F 20 4C 8B 2F 48 83 EC 40 48 8D 74 24 0F 4D 89 EE 4C 03 77 10 48 89 DF 48 83 E6 F0 F6 C3 01 0F 85 D8 00 00 00 40 F6 C7 02 0F 85 E6 00 00 00 40 F6 C7 04 0F 85 AC 00 00 00 89 D1 31 C0 C1 E9 03 F6 C2 04 F3 48 AB 74 0A C7 07 00 00 00 00 48 83 C7 04 F6 C2 02 74 0A 31 C0 48 83 C7 02 66 89 47 FE 83 E2 01 74 03 C6 07 00 41 0F B6 44 24 38 4C 8D 43 01 45 31 FF B9 01 00 00 00 83 C8 08 83 E0 FE 41 88 44 24 38 B8 05 00 00 00 4D 39 F5 74 25 41 0F B6 55 00 80 FA 01 74 1B 80 FA 1D 4D 8D 4D 01 0F 87 06 03 00 00 FF 24 D5 ?? ?? ?? }
	condition:
		$pattern
}

rule tmpfile_8d4d83ff62fa028a608515104a723b4c {
	meta:
		aliases = "tmpfile64, tmpfile"
		size = "114"
		objfiles = "tmpfile@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 04 10 00 00 68 ?? ?? ?? ?? 6A 00 68 FF 0F 00 00 8D 5C 24 11 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 40 51 51 6A 00 53 E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 C0 78 2D 83 EC 0C 53 E8 ?? ?? ?? ?? 58 5A 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 75 10 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 EB 02 31 DB 89 D8 81 C4 04 10 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule __ns_name_uncompress_d39721280fa88588f2bc4443e2114b47 {
	meta:
		aliases = "__GI___ns_name_uncompress, __ns_name_uncompress"
		size = "95"
		objfiles = "ns_name@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 10 01 00 00 68 FF 00 00 00 8D 74 24 15 56 FF B4 24 2C 01 00 00 FF B4 24 2C 01 00 00 FF B4 24 2C 01 00 00 E8 ?? ?? ?? ?? 89 C3 83 C4 20 83 F8 FF 74 1B 52 FF B4 24 24 01 00 00 FF B4 24 24 01 00 00 56 E8 ?? ?? ?? ?? 83 C4 10 40 75 03 83 CB FF 89 D8 81 C4 04 01 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_sigaction_7c4c0fb5708faab03709e6cd6f1ba20f {
	meta:
		aliases = "sigaction, __libc_sigaction, __GI_sigaction"
		size = "217"
		objfiles = "sigaction@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 24 01 00 00 8B 9C 24 34 01 00 00 8B B4 24 38 01 00 00 85 DB 74 4F 8B 03 89 84 24 98 00 00 00 52 68 80 00 00 00 8D 43 04 50 8D 84 24 B0 00 00 00 50 E8 ?? ?? ?? ?? 8B 83 84 00 00 00 0D 00 00 00 04 89 84 24 AC 00 00 00 83 C4 10 B8 ?? ?? ?? ?? F6 83 84 00 00 00 04 75 05 B8 ?? ?? ?? ?? 89 84 24 A0 00 00 00 31 D2 85 F6 74 04 8D 54 24 0C 31 C0 85 DB 74 07 8D 84 24 98 00 00 00 6A 08 52 50 FF B4 24 3C 01 00 00 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 F6 74 35 85 C0 78 31 8B 44 24 0C 89 06 50 68 80 00 00 00 8D 44 24 20 50 8D 46 04 50 E8 ?? ?? ?? ?? 8B 44 24 20 89 86 84 00 00 00 8B 44 24 24 89 86 88 }
	condition:
		$pattern
}

rule adjtime_7703632bbde2123db8869bb358655a2e {
	meta:
		aliases = "adjtime"
		size = "197"
		objfiles = "adjtime@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 84 00 00 00 8B 8C 24 90 00 00 00 8B B4 24 94 00 00 00 85 C9 74 44 8B 41 04 BB 40 42 0F 00 99 F7 FB 89 D3 89 C2 03 11 8D 82 61 08 00 00 3D C2 10 00 00 76 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CA FF EB 72 69 C2 40 42 0F 00 01 D8 89 44 24 08 C7 44 24 04 01 80 00 00 EB 08 C7 44 24 04 00 00 00 00 83 EC 0C 8D 44 24 10 50 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 3D 31 D2 85 F6 74 37 8B 4C 24 08 85 C9 79 1A 89 C8 F7 D8 BB 40 42 0F 00 99 F7 FB F7 DA 89 56 04 89 C8 99 F7 FB 89 C1 EB 11 BA 40 42 0F 00 89 C8 89 D3 99 F7 FB 89 C1 89 56 04 89 0E 31 D2 89 D0 81 C4 84 00 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule __GI___sigpause_e2d971c959694ecb430f15ce27ed77b4 {
	meta:
		aliases = "__sigpause, __GI___sigpause"
		size = "120"
		objfiles = "sigpause@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 84 00 00 00 8B B4 24 90 00 00 00 83 BC 24 94 00 00 00 00 74 28 52 8D 5C 24 08 53 6A 00 6A 00 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 3D 50 50 56 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 1B EB 2B 89 74 24 04 8D 54 24 08 B8 1E 00 00 00 C7 02 00 00 00 00 83 C2 04 48 79 F4 83 EC 0C 8D 44 24 10 50 E8 ?? ?? ?? ?? 83 C4 10 EB 03 83 C8 FF 81 C4 84 00 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_sigmask_909ac5a74a71e82e30849becafb79b8f {
	meta:
		aliases = "pthread_sigmask"
		size = "177"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 84 00 00 00 8B B4 24 90 00 00 00 8B 84 24 94 00 00 00 85 C0 74 6E 8D 5C 24 04 52 68 80 00 00 00 50 53 E8 ?? ?? ?? ?? 83 C4 10 83 FE 01 74 3C 83 FE 02 74 06 85 F6 74 14 EB 46 51 51 FF 35 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 58 5A EB 02 51 51 FF 35 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 7E 1A 52 52 50 EB 08 51 51 FF 35 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 89 D8 83 C4 10 EB 04 8D 44 24 04 52 FF B4 24 9C 00 00 00 50 56 E8 ?? ?? ?? ?? 83 C4 10 31 D2 40 75 07 E8 ?? ?? ?? ?? 8B 10 89 D0 81 C4 84 00 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule __pthread_wait_for_restart_sig_189712c2f577f570ada2ba859799e4f7 {
	meta:
		aliases = "__pthread_wait_for_restart_signal"
		size = "85"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 88 00 00 00 8B B4 24 94 00 00 00 8D 5C 24 08 53 6A 00 6A 02 E8 ?? ?? ?? ?? 58 5A FF 35 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? C7 46 20 00 00 00 00 83 C4 10 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 8B 46 20 3B 05 ?? ?? ?? ?? 75 E9 81 C4 84 00 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule logwtmp_506d7c7f77db052d98e4d9494a5e4a89 {
	meta:
		aliases = "logwtmp"
		size = "172"
		objfiles = "logwtmp@libutil.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 88 01 00 00 8B B4 24 98 01 00 00 68 80 01 00 00 6A 00 8D 44 24 10 50 E8 ?? ?? ?? ?? 83 C4 10 85 F6 74 0A B8 07 00 00 00 80 3E 00 75 05 B8 08 00 00 00 66 89 44 24 04 E8 ?? ?? ?? ?? 89 44 24 08 50 6A 1F FF B4 24 98 01 00 00 8D 5C 24 10 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 0C 6A 1F 56 8D 44 24 3C 50 E8 ?? ?? ?? ?? 83 C4 0C 68 FF 00 00 00 FF B4 24 A0 01 00 00 8D 44 24 5C 50 E8 ?? ?? ?? ?? 59 5E 6A 00 8D 84 24 64 01 00 00 50 E8 ?? ?? ?? ?? 58 5A 53 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 81 C4 94 01 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule __libc_pselect_2a7e9006fc95457173b012236eb8c4ed {
	meta:
		aliases = "pselect, __libc_pselect"
		size = "164"
		objfiles = "pselect@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 94 00 00 00 8B 9C 24 B0 00 00 00 8B B4 24 B4 00 00 00 85 DB 74 1D 8B 03 89 84 24 8C 00 00 00 8B 43 04 BA E8 03 00 00 89 D1 99 F7 F9 89 84 24 90 00 00 00 85 F6 74 11 52 8D 44 24 10 50 56 6A 02 E8 ?? ?? ?? ?? 83 C4 10 31 C0 85 DB 74 07 8D 84 24 8C 00 00 00 83 EC 0C 50 FF B4 24 BC 00 00 00 FF B4 24 BC 00 00 00 FF B4 24 BC 00 00 00 FF B4 24 BC 00 00 00 E8 ?? ?? ?? ?? 89 C3 83 C4 20 85 F6 74 12 50 6A 00 8D 44 24 14 50 6A 02 E8 ?? ?? ?? ?? 83 C4 10 89 D8 81 C4 94 00 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule vdprintf_fa74c07d3511b9c1162673e7e35b75a6 {
	meta:
		aliases = "__GI_vdprintf, vdprintf"
		size = "169"
		objfiles = "vdprintf@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC 94 00 00 00 8D 44 24 54 8D 94 24 94 00 00 00 89 54 24 10 89 44 24 0C 89 44 24 1C 89 44 24 20 89 44 24 14 89 44 24 18 8B 84 24 A0 00 00 00 89 44 24 08 66 C7 44 24 04 D0 00 C6 44 24 06 00 C7 44 24 30 00 00 00 00 C7 44 24 38 01 00 00 00 83 EC 0C 8D 74 24 10 8D 44 24 48 50 E8 ?? ?? ?? ?? C7 44 24 34 00 00 00 00 83 C4 0C FF B4 24 AC 00 00 00 FF B4 24 AC 00 00 00 56 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 7E 13 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 03 83 CB FF 89 D8 81 C4 94 00 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_onexit_process_4d0b25b94c270dc7467b5c4b3c387b29 {
	meta:
		aliases = "pthread_onexit_process"
		size = "151"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC A4 00 00 00 83 3D ?? ?? ?? ?? 00 78 7D E8 ?? ?? ?? ?? 89 C3 89 44 24 10 C7 44 24 14 02 00 00 00 8B 84 24 B0 00 00 00 89 44 24 18 8D 74 24 10 50 68 94 00 00 00 56 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 40 75 0A E8 ?? ?? ?? ?? 83 38 04 74 DE 89 D8 E8 ?? ?? ?? ?? 3B 1D ?? ?? ?? ?? 75 2A 51 68 00 00 00 80 6A 00 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 10 81 C4 A4 00 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_create_a140de1f28faa8d0b6448ae369f549de {
	meta:
		aliases = "pthread_create"
		size = "182"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC A4 00 00 00 83 3D ?? ?? ?? ?? 00 79 12 E8 ?? ?? ?? ?? BA 0B 00 00 00 85 C0 0F 88 88 00 00 00 E8 ?? ?? ?? ?? 89 C3 89 44 24 10 C7 44 24 14 00 00 00 00 8B 84 24 B4 00 00 00 89 44 24 18 8B 84 24 B8 00 00 00 89 44 24 1C 8B 84 24 BC 00 00 00 89 44 24 20 51 8D 44 24 28 50 6A 00 6A 02 E8 ?? ?? ?? ?? 83 C4 10 8D 74 24 10 52 68 94 00 00 00 56 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 40 75 0A E8 ?? ?? ?? ?? 83 38 04 74 DE 89 D8 E8 ?? ?? ?? ?? 83 7B 34 00 75 0C 8B 53 30 8B 84 24 B0 00 00 00 89 10 8B 53 34 89 D0 81 C4 A4 00 00 00 5B 5E C3 }
	condition:
		$pattern
}

rule __new_sem_post_def2f25588a40b228910d085fa1507da {
	meta:
		aliases = "sem_post, __new_sem_post"
		size = "237"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC A4 00 00 00 8B B4 24 B0 00 00 00 E8 ?? ?? ?? ?? 83 78 54 00 75 74 89 C2 89 F0 E8 ?? ?? ?? ?? 83 7E 0C 00 75 32 8B 46 08 3D FF FF FF 7F 75 19 E8 ?? ?? ?? ?? C7 00 22 00 00 00 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C8 FF EB 3D 40 89 46 08 83 EC 0C 56 E8 ?? ?? ?? ?? EB 2C 8B 5E 0C 85 DB 74 0D 8B 43 08 89 46 0C C7 43 08 00 00 00 00 83 EC 0C 56 E8 ?? ?? ?? ?? C6 83 BA 01 00 00 01 89 1C 24 E8 ?? ?? ?? ?? 31 C0 83 C4 10 EB 56 83 3D ?? ?? ?? ?? 00 79 19 E8 ?? ?? ?? ?? 85 C0 79 10 E8 ?? ?? ?? ?? C7 00 0B 00 00 00 83 C8 FF EB 34 C7 44 24 14 04 00 00 00 89 74 24 18 8D 5C 24 10 56 68 94 00 00 00 53 FF }
	condition:
		$pattern
}

rule __pthread_do_exit_6042ce17bb973577f37bf8d2d08e880b {
	meta:
		aliases = "__pthread_do_exit"
		size = "251"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC A4 00 00 00 E8 ?? ?? ?? ?? 89 C3 C6 40 40 01 C6 40 41 00 83 EC 0C FF B4 24 C0 00 00 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 43 1C 89 DA E8 ?? ?? ?? ?? 8B 84 24 C0 00 00 00 89 43 30 83 C4 10 83 BB 9C 01 00 00 00 74 2B A1 ?? ?? ?? ?? 0B 83 A0 01 00 00 F6 C4 01 74 1B C7 83 A8 01 00 00 09 00 00 00 89 9B AC 01 00 00 89 1D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 43 2C 01 8B 73 38 83 EC 0C FF 73 1C E8 ?? ?? ?? ?? 83 C4 10 85 F6 74 0C 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 8B 35 ?? ?? ?? ?? 39 F3 75 4C 83 3D ?? ?? ?? ?? 00 78 43 89 74 24 10 C7 44 24 14 03 00 00 00 8D 5C 24 10 52 68 94 00 00 00 53 FF 35 ?? }
	condition:
		$pattern
}

rule __pthread_timedsuspend_new_76944dc1811b14a33b733218c9f05a95 {
	meta:
		aliases = "__pthread_timedsuspend_new"
		size = "284"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 81 EC BC 01 00 00 6A 01 8D 44 24 14 50 E8 ?? ?? ?? ?? 83 C4 10 BA 01 00 00 00 85 C0 0F 85 DF 00 00 00 8D 44 24 08 8B 94 24 C0 01 00 00 89 42 24 C7 42 20 00 00 00 00 83 EC 0C 8D 9C 24 30 01 00 00 53 E8 ?? ?? ?? ?? 5E 58 FF 35 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 0C 8D 84 24 A8 00 00 00 50 53 6A 01 E8 ?? ?? ?? ?? 83 C4 10 8D B4 24 AC 01 00 00 8D 9C 24 A4 01 00 00 51 51 6A 00 56 E8 ?? ?? ?? ?? 69 84 24 C0 01 00 00 E8 03 00 00 8B 8C 24 D4 01 00 00 8B 51 04 29 C2 89 94 24 B8 01 00 00 8B 09 2B 8C 24 BC 01 00 00 89 8C 24 B4 01 00 00 83 C4 10 85 D2 79 17 8D 82 00 CA 9A 3B 89 84 24 A8 01 00 00 8D }
	condition:
		$pattern
}

rule __pthread_set_own_extricate_if_fb8c2424281d38480bc1208870dae02f {
	meta:
		aliases = "__pthread_set_own_extricate_if"
		size = "59"
		objfiles = "semaphore@libpthread.a, oldsemaphore@libpthread.a, condvar@libpthread.a, join@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 89 C3 89 D6 85 D2 74 08 80 78 40 00 75 24 EB 0A 8B 40 1C 89 DA E8 ?? ?? ?? ?? 89 B3 BC 01 00 00 85 F6 75 0E 83 EC 0C FF 73 1C E8 ?? ?? ?? ?? 83 C4 10 58 5B 5E C3 }
	condition:
		$pattern
}

rule tdestroy_recurse_3d72f6385b4cf76e272e2d0021eb4b9b {
	meta:
		aliases = "tdestroy_recurse"
		size = "56"
		objfiles = "tdestroy@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 89 C3 89 D6 8B 40 04 85 C0 74 05 E8 EB FF FF FF 8B 43 08 85 C0 74 07 89 F2 E8 DD FF FF FF 83 EC 0C FF 33 FF D6 89 1C 24 E8 ?? ?? ?? ?? 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule skip_input_bytes_033facd1c2716ad81dc38bbdc441b32a {
	meta:
		aliases = "skip_input_bytes"
		size = "63"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 89 C6 89 D3 EB 27 8B 4E 2C 8B 46 30 29 C8 75 0D 89 F0 E8 ?? ?? ?? ?? 85 C0 75 12 EB 19 89 DA 39 C3 7E 02 89 C2 8D 04 11 89 46 2C 29 D3 85 DB 7F D5 B8 01 00 00 00 59 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_free_330d4020647d846dbeb9daaec987e482 {
	meta:
		aliases = "pthread_free"
		size = "194"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 89 C6 8B 58 10 81 E3 FF 03 00 00 C1 E3 04 81 C3 ?? ?? ?? ?? 31 D2 89 D8 E8 ?? ?? ?? ?? C7 43 08 00 00 00 00 C7 43 0C FF FF FF FF 83 EC 0C 53 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 48 A3 ?? ?? ?? ?? 8B 86 C0 01 00 00 EB 0D 8B 18 83 EC 0C 50 E8 ?? ?? ?? ?? 89 D8 83 C4 10 85 C0 75 EC 8B 86 C4 01 00 00 EB 10 8B 18 83 EC 0C 50 E8 ?? ?? ?? ?? 89 D8 83 C4 10 85 C0 75 EC 81 FE ?? ?? ?? ?? 74 3A 83 BE 88 01 00 00 00 75 31 8B 86 90 01 00 00 85 C0 74 11 51 51 50 FF B6 8C 01 00 00 E8 ?? ?? ?? ?? 83 C4 10 8D 86 E0 01 E0 FF 52 52 68 00 00 20 00 50 E8 ?? ?? ?? ?? 83 C4 10 5E 5B 5E C3 }
	condition:
		$pattern
}

rule strchrnul_42bd722abdcbc5006c6980de65076f17 {
	meta:
		aliases = "__GI_strchrnul, strchrnul"
		size = "180"
		objfiles = "strchrnul@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8A 44 24 14 88 44 24 03 8B 44 24 10 EB 15 8A 10 3A 54 24 03 0F 84 91 00 00 00 84 D2 0F 84 89 00 00 00 40 A8 03 75 E7 89 C3 0F B6 54 24 03 89 D0 C1 E0 08 09 D0 89 C6 C1 E6 10 09 C6 8B 0B 83 C3 04 89 C8 F7 D0 8D 91 FF FE FE 7E 31 D0 A9 00 01 01 81 75 17 89 C8 31 F0 89 C2 F7 D2 05 FF FE FE 7E 31 C2 81 E2 00 01 01 81 74 D1 8D 43 FC 8A 53 FC 3A 54 24 03 74 34 84 D2 74 30 8D 43 FD 8A 53 FD 3A 54 24 03 74 24 84 D2 74 20 8D 43 FE 8A 53 FE 3A 54 24 03 74 14 84 D2 74 10 8D 43 FF 8A 53 FF 3A 54 24 03 74 04 84 D2 75 91 5A 5B 5E C3 }
	condition:
		$pattern
}

rule ustat_7cfc4fe9909f2162a2abbafd231e6de4 {
	meta:
		aliases = "ustat"
		size = "83"
		objfiles = "ustat@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 4C 24 10 8B 5C 24 14 89 C8 89 DA 0F AC D0 08 C1 EA 08 25 FF 0F 00 00 89 C6 C1 E6 08 0F B6 D1 09 D6 89 F0 8B 4C 24 18 53 89 C3 B8 3E 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 5A 5B 5E C3 }
	condition:
		$pattern
}

rule _dl_run_fini_array_3f9de57487dfb2ccc71ad7095184b053 {
	meta:
		aliases = "_dl_run_fini_array"
		size = "47"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 54 24 10 8B 82 A8 00 00 00 85 C0 74 18 89 C6 03 32 8B 9A B0 00 00 00 C1 EB 02 EB 03 FF 14 9E 4B 83 FB FF 75 F7 58 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_rwlock_trywrlock_42b4828bed00e3b89dac071ea3d83ba6 {
	meta:
		aliases = "pthread_rwlock_trywrlock"
		size = "64"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 10 31 D2 89 D8 E8 ?? ?? ?? ?? 83 7B 08 00 75 12 83 7B 0C 00 75 0C E8 ?? ?? ?? ?? 89 43 0C 31 F6 EB 05 BE 10 00 00 00 83 EC 0C 53 E8 ?? ?? ?? ?? 89 F0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule __new_sem_trywait_34c79f28f3b08916bb1cd9a9c2d60b26 {
	meta:
		aliases = "sem_trywait, __new_sem_trywait"
		size = "64"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 10 31 D2 89 D8 E8 ?? ?? ?? ?? 8B 43 08 85 C0 75 10 E8 ?? ?? ?? ?? C7 00 0B 00 00 00 83 CE FF EB 06 48 89 43 08 31 F6 83 EC 0C 53 E8 ?? ?? ?? ?? 89 F0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_pthread_cond_broadcast_cf20cc5bd91ece76ebc513c84b4ad47d {
	meta:
		aliases = "pthread_cond_broadcast, __GI_pthread_cond_broadcast"
		size = "78"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 10 31 D2 89 D8 E8 ?? ?? ?? ?? 8B 73 08 C7 43 08 00 00 00 00 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 EB 1A 8B 5E 08 C7 46 08 00 00 00 00 C6 86 B9 01 00 00 01 89 F0 E8 ?? ?? ?? ?? 89 DE 85 F6 75 E2 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule globfree_d18ea5f3312296e271736973f89b424e {
	meta:
		aliases = "__GI_globfree64, globfree64, __GI_globfree, globfree"
		size = "76"
		objfiles = "glob64@libc.a, glob@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 10 31 F6 83 7B 04 00 75 1E EB 35 89 F2 03 53 08 8B 43 04 8B 04 90 85 C0 74 0C 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 46 3B 33 72 E0 83 EC 0C FF 73 04 E8 ?? ?? ?? ?? C7 43 04 00 00 00 00 83 C4 10 58 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_herror_9a2f9c53979935e193f96d9b7ff8f33a {
	meta:
		aliases = "herror, __GI_herror"
		size = "80"
		objfiles = "herror@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 10 85 DB 74 0A BE ?? ?? ?? ?? 80 3B 00 75 05 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 00 BA ?? ?? ?? ?? 83 F8 04 77 07 8B 14 85 ?? ?? ?? ?? 83 EC 0C 52 56 53 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule pthread_kill_5c37743139a184a71ada0a8b6e79c298 {
	meta:
		aliases = "pthread_kill"
		size = "110"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 10 89 D8 25 FF 03 00 00 C1 E0 04 8D B0 ?? ?? ?? ?? 31 D2 89 F0 E8 ?? ?? ?? ?? 8B 46 08 85 C0 74 05 39 58 10 74 1C 83 EC 0C 56 E8 ?? ?? ?? ?? B8 03 00 00 00 83 C4 10 EB 29 E8 ?? ?? ?? ?? 8B 00 EB 20 8B 58 14 83 EC 0C 56 E8 ?? ?? ?? ?? 5E 58 FF 74 24 1C 53 E8 ?? ?? ?? ?? 83 C4 10 40 74 D9 31 C0 59 5B 5E C3 }
	condition:
		$pattern
}

rule _ppfs_prepargs_7ad9a21f8f1106a99993459627a0373a {
	meta:
		aliases = "_ppfs_prepargs"
		size = "66"
		objfiles = "_ppfs_prepargs@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 10 8B 44 24 14 89 43 4C 8B 73 18 85 F6 7E 27 89 73 1C C7 43 18 00 00 00 00 C7 43 04 00 00 00 00 C7 43 08 00 00 00 00 83 EC 0C 53 E8 ?? ?? ?? ?? 89 73 18 83 C4 10 58 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_opaque_56e75916fdb210864127fe97749b10bb {
	meta:
		aliases = "__GI_xdr_opaque, xdr_opaque"
		size = "158"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 10 8B 4C 24 14 8B 54 24 18 85 D2 74 7C 31 F6 89 D0 83 E0 03 74 06 66 BE 04 00 29 C6 8B 03 83 F8 01 74 09 72 34 83 F8 02 75 66 EB 5D 50 8B 43 04 52 51 53 FF 50 08 83 C4 10 85 C0 74 53 85 F6 74 48 8B 43 04 89 74 24 18 C7 44 24 14 ?? ?? ?? ?? 89 5C 24 10 8B 48 08 EB 2B 50 8B 43 04 52 51 53 FF 50 0C 83 C4 10 85 C0 74 26 85 F6 74 1B 8B 43 04 89 74 24 18 C7 44 24 14 ?? ?? ?? ?? 89 5C 24 10 8B 48 0C 5B 5B 5E FF E1 B8 01 00 00 00 EB 02 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_double_c121179c79fae6727ed22f02faec9726 {
	meta:
		aliases = "xdr_double"
		size = "111"
		objfiles = "xdr_float@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 10 8B 74 24 14 8B 03 83 F8 01 74 2C 72 08 83 F8 02 0F 94 C0 EB 48 50 50 8B 43 04 8D 56 04 52 53 FF 50 04 83 C4 10 31 D2 85 C0 74 35 50 50 8B 43 04 56 53 FF 50 04 EB 1E 50 50 8B 43 04 8D 56 04 52 53 FF 10 83 C4 10 31 D2 85 C0 74 14 51 51 8B 43 04 56 53 FF 10 83 C4 10 85 C0 0F 95 C0 0F B6 D0 89 D0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule xdrmem_getbytes_159ae1ce485d71bd934fc2cfa2c96841 {
	meta:
		aliases = "xdrmem_getbytes"
		size = "56"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 10 8B 74 24 18 8B 53 14 31 C0 39 F2 72 1E 29 F2 89 53 14 50 56 FF 73 0C FF 74 24 20 E8 ?? ?? ?? ?? 01 73 0C B8 01 00 00 00 83 C4 10 5B 5B 5E C3 }
	condition:
		$pattern
}

rule xdrmem_putbytes_6596a9516be08993798adc63850599ac {
	meta:
		aliases = "xdrmem_putbytes"
		size = "56"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 10 8B 74 24 18 8B 53 14 31 C0 39 F2 72 1E 29 F2 89 53 14 51 56 FF 74 24 1C FF 73 0C E8 ?? ?? ?? ?? 01 73 0C B8 01 00 00 00 83 C4 10 5A 5B 5E C3 }
	condition:
		$pattern
}

rule __pthread_attr_setguardsize_bb55cdebea2c7dec3a6981587089d857 {
	meta:
		aliases = "pthread_attr_setguardsize, __pthread_attr_setguardsize"
		size = "54"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 10 E8 ?? ?? ?? ?? 89 C6 8B 54 24 14 8D 54 10 FF 89 D0 31 D2 F7 F6 89 C1 0F AF CE B8 16 00 00 00 3B 4B 20 73 05 89 4B 14 30 C0 5B 5B 5E C3 }
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

rule memrchr_5342f1f56d7cc99524a57c3d479d15d7 {
	meta:
		aliases = "__GI_memrchr, memrchr"
		size = "177"
		objfiles = "memrchr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 5C 24 18 8A 44 24 14 88 44 24 03 8B 44 24 10 01 D8 EB 0E 48 8A 54 24 03 38 10 0F 84 87 00 00 00 4B 85 DB 74 04 A8 03 75 EA 89 C1 0F B6 54 24 03 89 D0 C1 E0 08 09 D0 89 C6 C1 E6 10 09 C6 EB 4D 83 E9 04 89 F0 33 01 89 C2 F7 D2 05 FF FE FE 7E 31 C2 81 E2 00 01 01 81 74 30 8D 41 03 8A 54 24 03 38 51 03 74 41 8D 41 02 8A 54 24 03 38 51 02 74 35 8D 41 01 8A 54 24 03 38 51 01 74 29 8A 44 24 03 38 01 75 04 89 C8 EB 1D 83 EB 04 83 FB 03 77 AE 89 C8 EB 09 48 8A 54 24 03 38 10 74 08 4B 83 FB FF 75 F1 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_pthread_cond_signal_6505f463b6c56b45fa1b102172ea72c3 {
	meta:
		aliases = "pthread_cond_signal, __GI_pthread_cond_signal"
		size = "74"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 31 D2 89 F0 E8 ?? ?? ?? ?? 8B 5E 08 85 DB 74 0D 8B 43 08 89 46 08 C7 43 08 00 00 00 00 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 85 DB 74 0E C6 83 B9 01 00 00 01 89 D8 E8 ?? ?? ?? ?? 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule sbrk_4216cbee0817b8642a640f8e6c88a5c4 {
	meta:
		aliases = "__GI_sbrk, sbrk"
		size = "78"
		objfiles = "sbrk@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 83 3D ?? ?? ?? ?? 00 75 11 83 EC 0C 6A 00 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 22 85 F6 A1 ?? ?? ?? ?? 75 04 89 C3 EB 18 89 C3 83 EC 0C 8D 04 30 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 03 83 CB FF 89 D8 5A 5B 5E C3 }
	condition:
		$pattern
}

rule seteuid_eac46212fcce22296a0f5f5d314593e6 {
	meta:
		aliases = "__GI_seteuid, setegid, seteuid"
		size = "82"
		objfiles = "setegid@libc.a, seteuid@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 83 FE FF 75 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CB FF EB 2E 53 6A FF 56 6A FF E8 ?? ?? ?? ?? 89 C3 83 C4 10 83 F8 FF 75 19 E8 ?? ?? ?? ?? 83 38 26 75 0F 51 51 56 6A FF E8 ?? ?? ?? ?? 89 C3 83 C4 10 89 D8 5A 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_pthread_getschedparam_12179f2b8ef08b60a3bcbcb1f5f1fd18 {
	meta:
		aliases = "pthread_getschedparam, __GI_pthread_getschedparam"
		size = "138"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 89 F0 25 FF 03 00 00 C1 E0 04 8D 98 ?? ?? ?? ?? 31 D2 89 D8 E8 ?? ?? ?? ?? 8B 43 08 85 C0 74 05 39 70 10 74 38 83 EC 0C 53 E8 ?? ?? ?? ?? B8 03 00 00 00 83 C4 10 EB 45 50 50 FF 74 24 20 56 E8 ?? ?? ?? ?? 83 C4 10 40 75 09 E8 ?? ?? ?? ?? 8B 00 EB 2A 8B 44 24 14 89 18 31 C0 EB 20 8B 70 14 83 EC 0C 53 E8 ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 89 C3 83 C4 10 83 F8 FF 75 BD EB CD 5B 5B 5E C3 }
	condition:
		$pattern
}

rule if_freenameindex_18846da9bd83c73585272ced0e147258 {
	meta:
		aliases = "__GI_if_freenameindex, if_freenameindex"
		size = "52"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 89 F3 EB 0F 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C3 08 83 C4 10 8B 43 04 85 C0 75 EA 83 3B 00 75 E5 89 74 24 10 58 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __cxa_finalize_c6b720814dd4d923e6926c63b4d3c16c {
	meta:
		aliases = "__cxa_finalize"
		size = "74"
		objfiles = "__cxa_finalize@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 8B 1D ?? ?? ?? ?? EB 31 4B 89 D9 C1 E1 04 03 0D ?? ?? ?? ?? 85 F6 74 05 3B 71 0C 75 1C 31 D2 B8 03 00 00 00 F0 0F B1 11 83 F8 03 75 0C 83 EC 0C FF 71 08 FF 51 04 83 C4 10 85 DB 75 CB 58 5B 5E C3 }
	condition:
		$pattern
}

rule xprt_unregister_9aa999b9f4f90fa5c74350ab71ca9879 {
	meta:
		aliases = "__GI_xprt_unregister, xprt_unregister"
		size = "121"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 8B 1E E8 ?? ?? ?? ?? 39 C3 7D 61 E8 ?? ?? ?? ?? 8D 14 9D 00 00 00 00 8B 80 B4 00 00 00 39 34 10 75 4A C7 04 10 00 00 00 00 81 FB FF 03 00 00 7E 04 31 F6 EB 2E E8 ?? ?? ?? ?? 89 D9 C1 E9 05 89 DA 83 E2 1F 0F B3 14 88 EB E7 E8 ?? ?? ?? ?? 8D 14 F5 00 00 00 00 03 10 39 1A 75 06 C7 02 FF FF FF FF 46 E8 ?? ?? ?? ?? 3B 30 7C DE 5B 5B 5E C3 }
	condition:
		$pattern
}

rule strsep_91a123daa9cb2a4f823ec92b7677e3b4 {
	meta:
		aliases = "__GI_strsep, strsep"
		size = "96"
		objfiles = "strsep@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 8B 44 24 14 8B 1E 85 DB 74 47 8A 10 84 D2 74 3B 80 78 01 00 75 1D 8A 0B 89 D8 38 D1 74 21 84 C9 74 29 50 50 0F BE C2 50 8D 43 01 50 E8 ?? ?? ?? ?? EB 09 51 51 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 08 C6 00 00 40 89 06 EB 06 C7 06 00 00 00 00 89 D8 5A 5B 5E C3 }
	condition:
		$pattern
}

rule __pthread_mutex_lock_75655bbff5601d11c5e54144771c4adb {
	meta:
		aliases = "pthread_mutex_lock, __pthread_mutex_lock"
		size = "151"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 8B 46 0C 83 F8 01 74 25 7F 06 85 C0 74 13 EB 0A 83 F8 02 74 41 83 F8 03 74 5E B8 16 00 00 00 EB 69 8D 46 10 31 D2 E8 ?? ?? ?? ?? EB 0F E8 ?? ?? ?? ?? 89 C3 39 46 08 75 07 FF 46 04 31 C0 EB 4A 8D 46 10 89 DA E8 ?? ?? ?? ?? 89 5E 08 C7 46 04 00 00 00 00 EB E6 E8 ?? ?? ?? ?? 89 C3 B8 23 00 00 00 39 5E 08 74 23 50 50 53 8D 46 10 50 E8 ?? ?? ?? ?? 89 5E 08 EB 0D 51 51 6A 00 8D 46 10 50 E8 ?? ?? ?? ?? 31 C0 83 C4 10 5A 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_tsearch_5720b721a5baf30c1446f2575b1e9335 {
	meta:
		aliases = "tsearch, __GI_tsearch"
		size = "101"
		objfiles = "tsearch@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 8B 5C 24 14 31 C0 85 DB 74 4E EB 23 51 51 FF 30 56 FF 54 24 28 83 C4 10 83 F8 00 75 04 8B 03 EB 37 7D 07 8B 1B 83 C3 04 EB 05 8B 1B 83 C3 08 8B 03 85 C0 75 D7 83 EC 0C 6A 0C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 12 89 03 89 30 C7 40 08 00 00 00 00 C7 40 04 00 00 00 00 5A 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_callmsg_b39d39b06ea14824a2e6aadbb5ee9df0 {
	meta:
		aliases = "__GI_xdr_callmsg, xdr_callmsg"
		size = "846"
		objfiles = "rpc_cmsg@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 8B 5C 24 14 83 3E 00 0F 85 E1 00 00 00 8B 53 20 81 FA 90 01 00 00 0F 87 1C 03 00 00 8B 43 2C 3D 90 01 00 00 0F 87 0E 03 00 00 51 51 8B 4E 04 83 C2 03 83 E2 FC 83 C0 03 83 E0 FC 8D 54 02 28 52 56 FF 51 18 89 C2 83 C4 10 85 C0 0F 84 9D 00 00 00 8B 03 0F C8 89 02 8B 43 04 0F C8 89 42 04 83 7B 04 00 0F 85 CF 02 00 00 8B 43 08 0F C8 89 42 08 83 7B 08 02 0F 85 BD 02 00 00 8B 43 0C 0F C8 89 42 0C 8B 43 10 0F C8 89 42 10 8B 43 14 0F C8 89 42 14 8B 43 18 0F C8 89 42 18 8B 43 20 0F C8 89 42 1C 8D 72 20 8B 43 20 85 C0 74 19 51 50 FF 73 1C 56 E8 ?? ?? ?? ?? 8B 43 20 83 C0 03 83 }
	condition:
		$pattern
}

rule longjmp_c6cf49351096c713c12b4029e4e28a99 {
	meta:
		aliases = "__libc_siglongjmp, siglongjmp, _longjmp, __libc_longjmp, longjmp"
		size = "51"
		objfiles = "longjmp@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 8B 5C 24 14 83 7E 18 00 74 11 52 6A 00 8D 46 1C 50 6A 02 E8 ?? ?? ?? ?? 83 C4 10 85 DB 75 02 B3 01 50 50 53 56 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_tfind_8ef44e36bbe4faca5acb8715d9aa0383 {
	meta:
		aliases = "tfind, __GI_tfind"
		size = "66"
		objfiles = "tfind@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 8B 5C 24 14 85 DB 74 2B EB 23 51 51 FF 30 56 FF 54 24 28 83 C4 10 83 F8 00 75 04 8B 03 EB 16 7D 07 8B 1B 83 C3 04 EB 05 8B 1B 83 C3 08 8B 03 85 C0 75 D7 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_xdr_callhdr_09295c3900c9bbfc91940914ec48f078 {
	meta:
		aliases = "xdr_callhdr, __GI_xdr_callhdr"
		size = "130"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 8B 5C 24 14 C7 43 04 00 00 00 00 C7 43 08 02 00 00 00 83 3E 00 75 5C 50 50 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 4C 50 50 8D 43 04 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 39 50 50 8D 43 08 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 26 50 50 8D 43 0C 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 13 8D 43 10 89 44 24 14 89 74 24 10 59 5B 5E E9 ?? ?? ?? ?? 31 C0 5A 5B 5E C3 }
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

rule __GI_getrpcbynumber_68532aa7461352a507e8da0beb3a6bce {
	meta:
		aliases = "getrpcbynumber, __GI_getrpcbynumber"
		size = "62"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 10 E8 ?? ?? ?? ?? 31 DB 85 C0 74 24 83 EC 0C 6A 00 E8 ?? ?? ?? ?? 83 C4 10 EB 05 39 73 08 74 0B E8 ?? ?? ?? ?? 89 C3 85 C0 75 F0 E8 ?? ?? ?? ?? 89 D8 5A 5B 5E C3 }
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

rule __GI_hcreate_r_d79cb6f3f330e9aa15d02369ce2067b8 {
	meta:
		aliases = "hcreate_r, __GI_hcreate_r"
		size = "127"
		objfiles = "hcreate_r@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 14 85 F6 75 0F E8 ?? ?? ?? ?? C7 00 16 00 00 00 31 C0 EB 5F 31 C0 83 3E 00 75 58 8B 4C 24 10 83 C9 01 EB 03 83 C1 02 BB 03 00 00 00 EB 03 83 C3 02 89 D8 0F AF C3 39 C8 73 0A 89 C8 31 D2 F7 F3 85 D2 75 EA 89 C8 31 D2 F7 F3 85 D2 74 D6 89 4E 04 C7 46 08 00 00 00 00 51 51 6A 0C 8B 46 04 40 50 E8 ?? ?? ?? ?? 89 06 83 C4 10 85 C0 0F 95 C0 0F B6 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule confstr_27a5e25bf88949f24ff239f3ca9f3876 {
	meta:
		aliases = "confstr"
		size = "104"
		objfiles = "confstr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 14 8B 5C 24 18 83 7C 24 10 00 75 0F 85 DB 74 04 85 F6 75 16 B8 0E 00 00 00 EB 41 E8 ?? ?? ?? ?? C7 00 16 00 00 00 31 C0 EB 32 83 FB 0D 76 10 53 6A 0E 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? EB 15 51 8D 43 FF 50 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? C6 44 1E FF 00 B8 0E 00 00 00 83 C4 10 5A 5B 5E C3 }
	condition:
		$pattern
}

rule clntraw_freeres_43023418abc8c2fcde9b7eabf47bb284 {
	meta:
		aliases = "clntraw_freeres"
		size = "62"
		objfiles = "clnt_raw@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 14 8B 5C 24 18 E8 ?? ?? ?? ?? 8B 80 A0 00 00 00 85 C0 74 19 C7 40 0C 02 00 00 00 89 5C 24 14 83 C0 0C 89 44 24 10 89 F1 5B 5B 5E FF E1 B8 10 00 00 00 5A 5B 5E C3 }
	condition:
		$pattern
}

rule svcraw_getargs_9bf0b99afb42e34f0f4f94d66812a47a {
	meta:
		aliases = "svcraw_getargs"
		size = "54"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 14 8B 5C 24 18 E8 ?? ?? ?? ?? 8B 80 BC 00 00 00 85 C0 74 14 89 5C 24 14 05 94 23 00 00 89 44 24 10 89 F1 58 5B 5E FF E1 31 C0 5E 5B 5E C3 }
	condition:
		$pattern
}

rule svcraw_freeargs_bb8ea7e800fe8d3a68f4a31786b93dbe {
	meta:
		aliases = "svcraw_freeargs"
		size = "64"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 14 8B 5C 24 18 E8 ?? ?? ?? ?? 8B 80 BC 00 00 00 85 C0 74 1E C7 80 94 23 00 00 02 00 00 00 89 5C 24 14 05 94 23 00 00 89 44 24 10 89 F1 5B 5B 5E FF E1 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule ether_line_88b53dca7ed01dfbc24bd4fdf970e87a {
	meta:
		aliases = "ether_line"
		size = "71"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 8B 74 24 18 8B 54 24 14 8B 44 24 10 E8 ?? ?? ?? ?? 89 C3 83 C8 FF 85 DB 74 24 EB 17 80 F9 23 74 18 0F BE D1 A1 ?? ?? ?? ?? F6 04 50 20 75 0A 88 0E 46 43 8A 0B 84 C9 75 E3 C6 06 00 31 C0 5B 5B 5E C3 }
	condition:
		$pattern
}

rule sethostid_41d281aade908de52f8a536f7adb0485 {
	meta:
		aliases = "sethostid"
		size = "111"
		objfiles = "hostid@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 E8 ?? ?? ?? ?? 85 C0 75 09 E8 ?? ?? ?? ?? 85 C0 74 12 E8 ?? ?? ?? ?? C7 00 01 00 00 00 BB 01 00 00 00 EB 40 53 68 A4 01 00 00 6A 41 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 83 C4 10 83 CB FF 85 C0 78 22 51 6A 04 8D 44 24 18 50 56 E8 ?? ?? ?? ?? 31 DB 83 F8 04 0F 94 C3 4B 89 34 24 E8 ?? ?? ?? ?? 83 C4 10 89 D8 5A 5B 5E C3 }
	condition:
		$pattern
}

rule svcraw_reply_1b46a4ae3582b22b976a59ab7c99751d {
	meta:
		aliases = "svcraw_reply"
		size = "98"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 04 E8 ?? ?? ?? ?? 8B 98 BC 00 00 00 85 DB 74 48 8D B3 94 23 00 00 C7 83 94 23 00 00 00 00 00 00 51 51 8B 83 98 23 00 00 6A 00 56 FF 50 14 58 5A FF 74 24 1C 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 17 83 EC 0C 8B 83 98 23 00 00 56 FF 50 10 B8 01 00 00 00 83 C4 10 EB 02 31 C0 5E 5B 5E C3 }
	condition:
		$pattern
}

rule fill_input_buf_2e632d762388a5f17c3b4871d8b1a70f {
	meta:
		aliases = "fill_input_buf"
		size = "57"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 89 C3 8B 50 30 83 E2 03 8B 70 28 01 D6 8B 40 24 29 D0 50 56 FF 33 FF 53 20 83 C4 10 31 D2 83 F8 FF 74 0B 89 73 2C 8D 04 06 89 43 30 B2 01 89 D0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule flush_out_f1e8a20c3dfa5c945b7ec7db9140bc84 {
	meta:
		aliases = "flush_out"
		size = "82"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 89 C6 4A 0F 95 C2 0F B6 D2 4A 81 E2 00 00 00 80 8B 48 18 8B 40 10 29 C8 83 E8 04 09 C2 0F CA 89 11 8B 46 0C 8B 5E 10 29 C3 53 50 FF 36 FF 56 08 83 C4 10 31 D2 39 D8 75 0E 8B 46 0C 89 46 18 83 C0 04 89 46 10 B2 01 89 D0 5B 5B 5E C3 }
	condition:
		$pattern
}

rule _ppfs_init_87fb16d45f5a3f07da7c14cc63ae5eec {
	meta:
		aliases = "_ppfs_init"
		size = "111"
		objfiles = "_ppfs_init@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 5C 24 14 8B 74 24 18 68 BC 00 00 00 6A 00 53 E8 ?? ?? ?? ?? FF 4B 18 89 33 8D 43 28 BA 09 00 00 00 83 C4 10 C7 00 08 00 00 00 83 C0 04 4A 75 F4 89 F0 EB 27 80 FA 25 75 21 40 80 38 25 74 1B 89 03 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 05 83 C8 FF EB 0F 8B 03 EB 01 40 8A 10 84 D2 75 D3 89 33 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule _authenticate_b3d31c3e29aaae712712f6a46218c4b6 {
	meta:
		aliases = "__GI__authenticate, _authenticate"
		size = "89"
		objfiles = "svc_auth@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 5C 24 14 8B 74 24 18 8D 53 0C 8D 46 18 6A 0C 50 52 E8 ?? ?? ?? ?? 8B 53 1C A1 ?? ?? ?? ?? 89 42 20 8B 43 1C C7 40 28 00 00 00 00 8B 43 0C 83 C4 10 83 F8 03 77 14 89 74 24 14 89 5C 24 10 8B 0C 85 ?? ?? ?? ?? 5B 5B 5E FF E1 B8 02 00 00 00 5A 5B 5E C3 }
	condition:
		$pattern
}

rule addmntent_b21d8c5a75ef9136ccdcf923251c871d {
	meta:
		aliases = "addmntent"
		size = "77"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 74 24 14 8B 5C 24 18 6A 02 6A 00 56 E8 ?? ?? ?? ?? 83 C4 10 BA 01 00 00 00 85 C0 78 24 FF 73 14 FF 73 10 FF 73 0C FF 73 08 FF 73 04 FF 33 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 89 C2 C1 EA 1F 83 C4 20 89 D0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule seed48_r_b86c866df4cd66b616f4280ce6ad18b8 {
	meta:
		aliases = "__GI_seed48_r, seed48_r"
		size = "81"
		objfiles = "seed48_r@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 74 24 14 8B 5C 24 18 6A 06 53 8D 43 06 50 E8 ?? ?? ?? ?? 66 8B 46 04 66 89 43 04 66 8B 46 02 66 89 43 02 66 8B 06 66 89 03 C7 43 10 6D E6 EC DE C7 43 14 05 00 00 00 66 C7 43 0C 0B 00 66 C7 43 0E 01 00 31 C0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule __xstat_conv_3271056362a0589ad762173b993b7890 {
	meta:
		aliases = "__xstat_conv"
		size = "143"
		objfiles = "xstatconv@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 74 24 14 8B 5C 24 18 6A 58 6A 00 53 E8 ?? ?? ?? ?? 0F B7 06 89 03 C7 43 04 00 00 00 00 8B 46 04 89 43 0C 0F B7 46 08 89 43 10 0F B7 46 0A 89 43 14 0F B7 46 0C 89 43 18 0F B7 46 0E 89 43 1C 0F B7 46 10 89 43 20 C7 43 24 00 00 00 00 8B 46 14 89 43 2C 8B 46 18 89 43 30 8B 46 1C 89 43 34 8B 56 20 8B 46 24 89 43 3C 89 53 38 8B 56 28 8B 46 2C 89 43 44 89 53 40 8B 56 30 8B 46 34 89 43 4C 89 53 48 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule __xstat32_conv_4c6e578ee89c37f23750781e7cf79116 {
	meta:
		aliases = "__xstat32_conv"
		size = "139"
		objfiles = "xstatconv@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 74 24 14 8B 5C 24 18 6A 58 6A 00 53 E8 ?? ?? ?? ?? 0F B7 06 89 03 C7 43 04 00 00 00 00 8B 46 58 89 43 0C 8B 46 10 89 43 10 8B 46 14 89 43 14 8B 46 18 89 43 18 8B 46 1C 89 43 1C 0F B7 46 20 89 43 20 C7 43 24 00 00 00 00 8B 46 2C 89 43 2C 8B 46 34 89 43 30 8B 46 38 89 43 34 8B 56 40 8B 46 44 89 43 3C 89 53 38 8B 56 48 8B 46 4C 89 43 44 89 53 40 8B 56 50 8B 46 54 89 43 4C 89 53 48 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule __xstat64_conv_838a26563a6458d0f04824aefc6e1073 {
	meta:
		aliases = "__xstat64_conv"
		size = "164"
		objfiles = "xstatconv@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 74 24 14 8B 5C 24 18 6A 60 6A 00 53 E8 ?? ?? ?? ?? 0F B7 06 89 03 C7 43 04 00 00 00 00 8B 46 58 8B 56 5C 89 43 58 89 53 5C 8B 46 0C 89 43 0C 8B 46 10 89 43 10 8B 46 14 89 43 14 8B 46 18 89 43 18 8B 46 1C 89 43 1C 0F B7 46 20 89 43 20 C7 43 24 00 00 00 00 8B 46 2C 8B 56 30 89 43 2C 89 53 30 8B 46 34 89 43 34 8B 46 38 89 43 38 C7 43 3C 00 00 00 00 8B 56 40 8B 46 44 89 43 44 89 53 40 8B 56 48 8B 46 4C 89 43 4C 89 53 48 8B 56 50 8B 46 54 89 43 54 89 53 50 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule mempcpy_fc1aa9b4268df2c2e5191bbb3a10dd56 {
	meta:
		aliases = "__GI_mempcpy, mempcpy"
		size = "33"
		objfiles = "mempcpy@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 74 24 14 8B 5C 24 1C 53 FF 74 24 1C 56 E8 ?? ?? ?? ?? 8D 04 1E 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule xdrrec_getpos_55f57f146630add6e6e4e673abe69764 {
	meta:
		aliases = "xdrrec_getpos"
		size = "69"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 74 24 14 8B 5E 0C 6A 01 6A 00 FF 33 E8 ?? ?? ?? ?? 89 C1 83 C4 10 83 C8 FF 83 F9 FF 74 1D 8B 16 85 D2 74 05 4A 75 14 EB 0A 8B 43 10 2B 43 0C 01 C8 EB 08 89 C8 2B 43 30 03 43 2C 5A 5B 5E C3 }
	condition:
		$pattern
}

rule updwtmp_f153def860133d8e2697388528a8bcd7 {
	meta:
		aliases = "updwtmp"
		size = "96"
		objfiles = "wtent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 08 8B 74 24 18 6A 00 68 01 04 00 00 FF 74 24 1C E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 78 3A 51 6A 00 6A 01 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 28 52 68 80 01 00 00 56 53 E8 ?? ?? ?? ?? 83 C4 0C 6A 00 6A 00 53 E8 ?? ?? ?? ?? 89 5C 24 20 83 C4 14 5B 5E E9 ?? ?? ?? ?? 58 5B 5E C3 }
	condition:
		$pattern
}

rule dlinfo_27f2024e92575dd278c2fa16627a9fd7 {
	meta:
		aliases = "dlinfo"
		size = "220"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 83 C4 10 EB 2E FF 73 04 0F B7 43 20 50 8B 43 18 FF 34 85 ?? ?? ?? ?? FF 73 1C 53 FF 33 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 5B 0C 83 C4 20 85 DB 75 CE 50 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? EB 19 8B 03 FF 70 04 50 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 5B 10 83 C4 10 85 DB 75 E0 8B 35 ?? ?? ?? ?? EB 39 50 56 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 F3 EB 19 8B 03 FF 70 04 50 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 5B 10 }
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

rule svctcp_reply_9132e91328c623d276b5b74e38fcf309 {
	meta:
		aliases = "svcunix_reply, svctcp_reply"
		size = "58"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 8B 54 24 1C 8B 44 24 18 8B 40 2C 8D 70 08 C7 40 08 00 00 00 00 8B 40 04 89 02 52 56 E8 ?? ?? ?? ?? 89 C3 58 5A 6A 01 56 E8 ?? ?? ?? ?? 89 D8 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule putenv_fd47f2574374d7e7b51cdbce402e773d {
	meta:
		aliases = "putenv"
		size = "80"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 8B 74 24 18 6A 3D 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 25 52 52 29 F0 50 56 E8 ?? ?? ?? ?? 89 C3 6A 01 56 6A 00 50 E8 ?? ?? ?? ?? 89 C6 83 C4 14 53 E8 ?? ?? ?? ?? EB 0B 83 EC 0C 56 E8 ?? ?? ?? ?? 31 F6 89 F0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_opaque_auth_5e1dff17a3ebe6b7a389979d4d335a66 {
	meta:
		aliases = "__GI_xdr_opaque_auth, xdr_opaque_auth"
		size = "59"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 8B 74 24 18 8B 5C 24 1C 53 56 E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 74 18 68 90 01 00 00 8D 43 08 50 8D 43 04 50 56 E8 ?? ?? ?? ?? 89 C2 83 C4 10 89 D0 5B 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_xdr_replymsg_aff4d942266a12f8e1fefb038e08bc3b {
	meta:
		aliases = "xdr_replymsg, __GI_xdr_replymsg"
		size = "87"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 8B 74 24 18 8B 5C 24 1C 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 36 51 51 8D 43 04 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 23 83 7B 04 01 75 1D 83 EC 0C 6A 00 68 ?? ?? ?? ?? 8D 43 0C 50 8D 43 08 50 56 E8 ?? ?? ?? ?? 83 C4 20 EB 02 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_pmap_3930e028a2172d646bcb096f2a84f718 {
	meta:
		aliases = "__GI_xdr_pmap, xdr_pmap"
		size = "90"
		objfiles = "pmap_prot@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 8B 74 24 18 8B 5C 24 1C 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 39 50 50 8D 43 04 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 26 50 50 8D 43 08 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 13 8D 43 0C 89 44 24 14 89 74 24 10 59 5B 5E E9 ?? ?? ?? ?? 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_rejected_reply_2cbaf901d271eadfeffc2ad2287bcfb5 {
	meta:
		aliases = "__GI_xdr_rejected_reply, xdr_rejected_reply"
		size = "101"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 8B 74 24 18 8B 5C 24 1C 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 44 8B 03 85 C0 74 05 48 75 3B EB 26 50 50 8D 43 04 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 26 8D 43 08 89 44 24 14 89 74 24 10 5B 5B 5E E9 ?? ?? ?? ?? 8D 43 04 89 44 24 14 89 74 24 10 59 5B 5E E9 ?? ?? ?? ?? 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_accepted_reply_084ba190918286d1026e34270f66e635 {
	meta:
		aliases = "__GI_xdr_accepted_reply, xdr_accepted_reply"
		size = "128"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 8B 74 24 18 8B 5C 24 1C 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 5F 50 50 8D 43 0C 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 4C 8B 53 0C 85 D2 74 0C B8 01 00 00 00 83 FA 02 75 3D EB 13 8B 43 10 89 44 24 14 89 74 24 10 8B 4B 14 58 5B 5E FF E1 50 50 8D 43 10 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 13 8D 43 14 89 44 24 14 89 74 24 10 58 5B 5E E9 ?? ?? ?? ?? 31 C0 5E 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_xdr_authunix_parms_3f4463dc51d054c821814c66bdc793ca {
	meta:
		aliases = "xdr_authunix_parms, __GI_xdr_authunix_parms"
		size = "132"
		objfiles = "authunix_prot@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 0C 8B 74 24 18 8B 5C 24 1C 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 63 50 68 FF 00 00 00 8D 43 04 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 4C 50 50 8D 43 08 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 39 50 50 8D 43 0C 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 26 51 51 68 ?? ?? ?? ?? 6A 04 6A 10 8D 43 10 50 8D 43 14 50 56 E8 ?? ?? ?? ?? 83 C4 20 85 C0 0F 95 C0 0F B6 C0 EB 02 31 C0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule _stdio_term_604ec11d9f13a3872b16486e137469f8 {
	meta:
		aliases = "_stdio_term"
		size = "136"
		objfiles = "_stdio@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? EB 3A 83 EC 0C 8D 73 38 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 14 66 C7 03 30 00 8B 43 08 89 43 18 89 43 1C 89 43 10 89 43 14 C7 43 34 01 00 00 00 83 EC 0C 56 E8 ?? ?? ?? ?? 8B 5B 20 83 C4 10 85 DB 75 BF 8B 1D ?? ?? ?? ?? EB 14 F6 03 40 74 0C 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 8B 5B 20 85 DB 75 E8 58 5B 5E C3 }
	condition:
		$pattern
}

rule __wcslcpy_2034c9bcc503ec9d6eddc65b874087f0 {
	meta:
		aliases = "wcsxfrm, __wcslcpy"
		size = "66"
		objfiles = "wcslcpy@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 4C 24 1C 8B 74 24 20 8B 44 24 24 8D 58 FF 85 C0 75 06 8D 4C 24 0C 31 DB 89 F2 EB 0B 85 DB 74 04 4B 83 C1 04 83 C2 04 8B 02 89 01 85 C0 75 ED 29 F2 C1 FA 02 89 D0 83 C4 10 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_strlcpy_b6e6d4cbaaace54afe0d9a66092e2a83 {
	meta:
		aliases = "__GI_strxfrm, strxfrm, strlcpy, __GI_strlcpy"
		size = "59"
		objfiles = "strlcpy@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 4C 24 1C 8B 74 24 20 8B 44 24 24 8D 58 FF 85 C0 75 06 8D 4C 24 0F 31 DB 89 F2 EB 07 85 DB 74 02 4B 41 42 8A 02 88 01 84 C0 75 F1 29 F2 89 D0 83 C4 10 5B 5E C3 }
	condition:
		$pattern
}

rule strlcat_ab7166dd77f222f791bb07f4c0071bb9 {
	meta:
		aliases = "__GI_strlcat, strlcat"
		size = "61"
		objfiles = "strlcat@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 54 24 1C 8B 5C 24 20 8B 74 24 24 31 C9 39 F1 72 06 8D 54 24 0F EB 10 80 3A 00 74 0B 42 41 EB ED 41 39 F1 83 D2 00 43 8A 03 88 02 84 C0 75 F1 89 C8 83 C4 10 5B 5E C3 }
	condition:
		$pattern
}

rule fputs_unlocked_d2c3621195138ba1673ab64555a59981 {
	meta:
		aliases = "__GI_fputs_unlocked, fputs_unlocked"
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

rule svcunix_destroy_8f1fb4e8db7b6491b1e0d492ba00bd8a {
	meta:
		aliases = "svctcp_destroy, svcunix_destroy"
		size = "89"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
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

rule __GI_fputws_unlocked_7b4a4750f701305da94cb5bc7e694e5c {
	meta:
		aliases = "fputws_unlocked, __GI_fputws_unlocked"
		size = "46"
		objfiles = "fputws_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 74 24 1C 56 E8 ?? ?? ?? ?? 83 C4 0C 89 C3 FF 74 24 18 50 56 E8 ?? ?? ?? ?? 39 D8 0F 94 C0 0F B6 C0 48 83 C4 14 5B 5E C3 }
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

rule xdrrec_setpos_18735796ee08a1257762d970871262c3 {
	meta:
		aliases = "xdrrec_setpos"
		size = "100"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 74 24 1C 8B 5E 0C 56 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 74 44 2B 44 24 14 8B 16 85 D2 74 05 4A 75 37 EB 14 8B 53 10 29 C2 3B 53 18 76 2B 3B 53 14 73 26 89 53 10 EB 1A 8B 53 2C 3B 43 34 7D 19 29 C2 3B 53 30 77 12 3B 53 28 72 0D 89 53 2C 29 43 34 B8 01 00 00 00 EB 02 31 C0 59 5B 5E C3 }
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

rule fgetspent_r_82a6a9c51768278cc2c69d0f50defec1 {
	meta:
		aliases = "fgetgrent_r, __GI_fgetpwent_r, __GI_fgetgrent_r, fgetpwent_r, __GI_fgetspent_r, fgetspent_r"
		size = "55"
		objfiles = "fgetspent_r@libc.a, fgetgrent_r@libc.a, fgetpwent_r@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 8B 74 24 20 8B 5C 24 2C C7 03 00 00 00 00 FF 74 24 1C FF 74 24 2C FF 74 24 2C 56 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 20 85 C0 75 02 89 33 5A 5B 5E C3 }
	condition:
		$pattern
}

rule ftello_1269a363713370ece21c4440adabd7d6 {
	meta:
		aliases = "__GI_ftell, ftell, ftello"
		size = "52"
		objfiles = "ftello@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 10 FF 74 24 1C E8 ?? ?? ?? ?? 89 C6 89 C3 C1 FB 1F 83 C4 10 39 D3 75 04 39 C0 74 0E E8 ?? ?? ?? ?? C7 00 4B 00 00 00 83 CE FF 89 F0 5A 5B 5E C3 }
	condition:
		$pattern
}

rule setlogmask_ad3bb1ebf2ee4d2bb2da82f690c53994 {
	meta:
		aliases = "setlogmask"
		size = "85"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 0F B6 35 ?? ?? ?? ?? 83 7C 24 20 00 74 37 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 10 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 44 24 30 A2 ?? ?? ?? ?? 58 5A 6A 01 53 E8 ?? ?? ?? ?? 83 C4 10 89 F2 0F B6 C2 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule ulckpwdf_fb1a44832a50ec619da344e06508415c {
	meta:
		aliases = "ulckpwdf"
		size = "95"
		objfiles = "lckpwdf@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 83 CE FF 83 3D ?? ?? ?? ?? FF 74 46 53 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 10 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 C7 05 ?? ?? ?? ?? FF FF FF FF 58 5A 6A 01 53 E8 ?? ?? ?? ?? 83 C4 10 89 F0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule getchar_115f1caab04df0ad0d6e64187ebb8a52 {
	meta:
		aliases = "getchar"
		size = "134"
		objfiles = "getchar@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 35 ?? ?? ?? ?? 83 7E 34 00 74 1E 8B 46 10 3B 46 18 73 09 0F B6 18 40 89 46 10 EB 5C 83 EC 0C 56 E8 ?? ?? ?? ?? 89 C3 EB 4C 52 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 10 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 46 10 83 C4 10 3B 46 18 73 09 0F B6 18 40 89 46 10 EB 0E 83 EC 0C 56 E8 ?? ?? ?? ?? 89 C3 83 C4 10 50 50 6A 01 8D 44 24 10 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_uint64_t_f8fa04af34e688c085b18649186f27ff {
	meta:
		aliases = "xdr_uint64_t"
		size = "189"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 20 8B 74 24 24 8B 03 83 F8 01 74 53 72 13 BA 01 00 00 00 83 F8 02 0F 84 91 00 00 00 E9 8A 00 00 00 8B 46 04 89 44 24 10 8B 06 89 44 24 0C 8D 44 24 10 52 52 8B 53 04 50 53 FF 52 24 83 C4 10 31 D2 85 C0 74 68 8D 44 24 0C 56 56 8B 53 04 50 53 FF 52 24 83 C4 10 31 D2 85 C0 0F 95 C2 EB 4E 8D 44 24 10 51 51 8B 53 04 50 53 FF 52 20 83 C4 10 85 C0 74 37 8D 44 24 0C 52 52 8B 53 04 50 53 FF 52 20 83 C4 10 85 C0 74 22 8B 44 24 10 31 D2 89 C2 B8 00 00 00 00 89 06 89 56 04 8B 4C 24 0C 89 0E 89 56 04 BA 01 00 00 00 EB 02 31 D2 89 D0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_int64_t_81bf4e6a91f95dceb0e039c2d8724e01 {
	meta:
		aliases = "xdr_int64_t"
		size = "197"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 20 8B 74 24 24 8B 03 83 F8 01 74 5C 72 13 BA 01 00 00 00 83 F8 02 0F 84 99 00 00 00 E9 92 00 00 00 8B 06 8B 56 04 89 D0 89 C2 C1 FA 1F 89 44 24 10 8B 06 89 44 24 0C 50 50 8B 53 04 8D 44 24 18 50 53 FF 52 24 83 C4 10 31 D2 85 C0 74 67 8D 44 24 0C 56 56 8B 53 04 50 53 FF 52 24 83 C4 10 31 D2 85 C0 0F 95 C2 EB 4D 51 51 8B 43 04 8D 54 24 18 52 53 FF 50 20 83 C4 10 85 C0 74 36 8D 44 24 0C 52 52 8B 53 04 50 53 FF 52 20 83 C4 10 85 C0 74 21 8B 44 24 10 99 89 C2 B8 00 00 00 00 89 06 89 56 04 8B 4C 24 0C 89 0E 89 56 04 BA 01 00 00 00 EB 02 31 D2 89 D0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_u_hyper_01ddd05be95913152bda660d92058467 {
	meta:
		aliases = "__GI_xdr_u_hyper, xdr_u_hyper"
		size = "179"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 20 8B 74 24 24 8B 03 85 C0 75 3C 8B 46 04 89 44 24 10 8B 06 89 44 24 0C 8D 44 24 10 52 52 8B 53 04 50 53 FF 52 04 83 C4 10 31 D2 85 C0 74 74 8D 44 24 0C 56 56 8B 53 04 50 53 FF 52 04 83 C4 10 85 C0 0F 95 C0 EB 55 83 F8 01 75 4A 8D 44 24 10 51 51 8B 53 04 50 53 FF 12 83 C4 10 85 C0 74 41 8D 44 24 0C 52 52 8B 53 04 50 53 FF 12 83 C4 10 85 C0 74 2D 8B 44 24 10 31 D2 89 C2 B8 00 00 00 00 89 06 89 56 04 8B 4C 24 0C 89 0E 89 56 04 BA 01 00 00 00 EB 0D 83 F8 02 0F 94 C0 0F B6 D0 EB 02 31 D2 89 D0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_hyper_7948ace8f0dcc89b58755902b996aa2b {
	meta:
		aliases = "__GI_xdr_hyper, xdr_hyper"
		size = "187"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 20 8B 74 24 24 8B 03 85 C0 75 45 8B 06 8B 56 04 89 D0 89 C2 C1 FA 1F 89 44 24 10 8B 06 89 44 24 0C 50 50 8B 53 04 8D 44 24 18 50 53 FF 52 04 83 C4 10 31 D2 85 C0 74 73 8D 44 24 0C 56 56 8B 53 04 50 53 FF 52 04 83 C4 10 85 C0 0F 95 C0 EB 54 83 F8 01 75 49 51 51 8B 43 04 8D 54 24 18 52 53 FF 10 83 C4 10 85 C0 74 40 8D 44 24 0C 52 52 8B 53 04 50 53 FF 12 83 C4 10 85 C0 74 2C 8B 44 24 10 99 89 C2 B8 00 00 00 00 89 06 89 56 04 8B 4C 24 0C 89 0E 89 56 04 BA 01 00 00 00 EB 0D 83 F8 02 0F 94 C0 0F B6 D0 EB 02 31 D2 89 D0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule xdrrec_getlong_3687cb89884e0f2c6c58667ee449875d {
	meta:
		aliases = "xdrrec_getlong"
		size = "97"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 20 8B 74 24 24 8B 53 0C 8B 4A 2C 83 7A 34 03 7E 1F 8B 42 30 29 C8 83 F8 03 7E 15 8B 01 0F C8 89 06 83 6A 34 04 83 42 2C 04 BA 01 00 00 00 EB 21 8D 44 24 10 51 6A 04 50 53 E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 74 0A 8B 44 24 10 0F C8 89 06 B2 01 89 D0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule xdrrec_getint32_a19930163c9f54e3fa3128aaa4a78c5e {
	meta:
		aliases = "xdrrec_getint32"
		size = "97"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 20 8B 74 24 24 8B 53 0C 8B 4A 2C 83 7A 34 03 7E 1F 8B 42 30 29 C8 83 F8 03 7E 15 8B 01 0F C8 89 06 83 6A 34 04 83 42 2C 04 BA 01 00 00 00 EB 21 8D 44 24 10 52 6A 04 50 53 E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 74 0A 8B 44 24 10 0F C8 89 06 B2 01 89 D0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule __des_crypt_9935319dc22c33c8a7fb805efb792281 {
	meta:
		aliases = "__des_crypt"
		size = "391"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 20 8B 74 24 24 E8 ?? ?? ?? ?? 8D 54 24 04 89 D1 EB 0E 8A 03 01 C0 88 02 42 80 7A FF 01 83 DB FF 89 D0 29 C8 83 F8 08 75 E9 89 C8 E8 ?? ?? ?? ?? 8A 46 01 8A 16 88 54 24 03 88 15 ?? ?? ?? ?? 8A 56 01 8A 4C 24 03 84 D2 74 02 88 D1 88 0D ?? ?? ?? ?? 0F BE C0 E8 ?? ?? ?? ?? 89 C3 C1 E3 06 0F BE 44 24 03 E8 ?? ?? ?? ?? 09 C3 89 D8 E8 ?? ?? ?? ?? 8D 4C 24 10 6A 19 8D 44 24 10 50 31 D2 31 C0 E8 ?? ?? ?? ?? 59 5B 31 D2 85 C0 0F 85 E5 00 00 00 8B 4C 24 10 89 CA C1 EA 08 89 C8 C1 E8 1A 8A 80 ?? ?? ?? ?? A2 ?? ?? ?? ?? 89 C8 C1 E8 14 83 E0 3F 8A 80 ?? ?? ?? ?? A2 ?? ?? ?? ?? 89 C8 }
	condition:
		$pattern
}

rule join_extricate_func_98fe06c9421499ece8ee54443f29964d {
	meta:
		aliases = "join_extricate_func"
		size = "66"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 20 E8 ?? ?? ?? ?? 89 44 24 10 8B 54 24 10 89 D8 E8 ?? ?? ?? ?? 8B 43 08 83 78 38 00 0F 95 C2 0F B6 F2 C7 40 38 00 00 00 00 83 EC 0C 53 E8 ?? ?? ?? ?? 89 F0 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule cond_extricate_func_72146daef84be2848cff228031cd9923 {
	meta:
		aliases = "cond_extricate_func"
		size = "60"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 20 E8 ?? ?? ?? ?? 89 44 24 10 8B 54 24 10 89 D8 E8 ?? ?? ?? ?? 8D 43 08 8B 54 24 24 E8 ?? ?? ?? ?? 89 C6 83 EC 0C 53 E8 ?? ?? ?? ?? 89 F0 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule new_sem_extricate_func_196fbf035d86bda53a63bfa52b80e9c7 {
	meta:
		aliases = "new_sem_extricate_func"
		size = "60"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 5C 24 20 E8 ?? ?? ?? ?? 89 44 24 10 8B 54 24 10 89 D8 E8 ?? ?? ?? ?? 8D 43 0C 8B 54 24 24 E8 ?? ?? ?? ?? 89 C6 83 EC 0C 53 E8 ?? ?? ?? ?? 89 F0 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule __pthread_once_b5eb6ff612f6e67fab6a0346a5f83cb7 {
	meta:
		aliases = "pthread_once, __pthread_once"
		size = "226"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 74 24 20 83 3E 02 75 05 E9 C7 00 00 00 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 16 89 D0 83 E0 03 83 C4 10 48 75 27 83 E2 FC 3B 15 ?? ?? ?? ?? 74 1C C7 06 00 00 00 00 EB 14 51 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 8B 16 89 D0 83 E0 03 48 74 E2 31 DB 85 D2 75 52 A1 ?? ?? ?? ?? 83 C8 01 89 06 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 56 68 ?? ?? ?? ?? 8D 5C 24 10 53 E8 ?? ?? ?? ?? FF 54 24 34 58 5A 6A 00 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 06 02 00 00 00 BB 01 00 00 00 83 C4 10 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 DB }
	condition:
		$pattern
}

rule __GI_fgetc_8b451145c5c85f5240f6ce41b4ff2173 {
	meta:
		aliases = "fgetc, getc, __GI_fgetc"
		size = "132"
		objfiles = "fgetc@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 74 24 20 83 7E 34 00 74 1E 8B 46 10 3B 46 18 73 09 0F B6 18 40 89 46 10 EB 5C 83 EC 0C 56 E8 ?? ?? ?? ?? 89 C3 EB 4C 52 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 10 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 46 10 83 C4 10 3B 46 18 73 09 0F B6 18 40 89 46 10 EB 0E 83 EC 0C 56 E8 ?? ?? ?? ?? 89 C3 83 C4 10 50 50 6A 01 8D 44 24 10 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_xdr_rmtcallres_aa68f664ef6d123b6b90d3d6b113361a {
	meta:
		aliases = "xdr_rmtcallres, __GI_xdr_rmtcallres"
		size = "91"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 74 24 20 8B 5C 24 24 8B 03 89 44 24 10 68 ?? ?? ?? ?? 6A 04 8D 44 24 18 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 27 50 50 8D 43 04 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 14 8B 44 24 10 89 03 50 50 FF 73 08 56 FF 53 0C 83 C4 10 EB 02 31 C0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule dl_iterate_phdr_3dc9acc5c7184e2cbb0db5c494e145a4 {
	meta:
		aliases = "dl_iterate_phdr"
		size = "89"
		objfiles = "dl_iterate_phdr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 74 24 20 8B 5C 24 24 8B 15 ?? ?? ?? ?? 85 D2 74 30 C7 44 24 04 00 00 00 00 C7 44 24 08 ?? ?? ?? ?? A1 ?? ?? ?? ?? 89 44 24 0C 66 89 54 24 10 51 53 6A 10 8D 44 24 10 50 FF D6 83 C4 10 85 C0 75 0C 52 52 53 56 E8 ?? ?? ?? ?? 83 C4 10 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule __GI___fputc_unlocked_7df26a995a8754f6c6a81fb5c94f89cf {
	meta:
		aliases = "putc_unlocked, fputc_unlocked, __GI_putc_unlocked, __fputc_unlocked, __GI___fputc_unlocked"
		size = "197"
		objfiles = "fputc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 8B 74 24 20 8B 5C 24 24 8B 43 10 3B 43 1C 73 0D 89 F2 88 10 40 89 43 10 E9 95 00 00 00 0F B7 03 25 C0 00 00 00 3D C0 00 00 00 74 14 52 52 68 80 00 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 77 83 7B 04 FE 75 07 89 F1 0F B6 C1 EB 6D 8B 43 0C 3B 43 08 74 40 3B 43 10 75 10 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 4D 8B 43 10 89 F2 88 10 40 89 43 10 F6 43 01 01 74 35 80 FA 0A 75 30 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 20 FF 4B 10 EB 22 89 F0 88 44 24 13 50 6A 01 8D 44 24 1B 50 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 07 89 F2 0F B6 C2 EB 03 83 C8 FF 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule unlockpt_d38a1f994be0bd54d87146e5d589a4f6 {
	meta:
		aliases = "unlockpt"
		size = "71"
		objfiles = "unlockpt@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 14 E8 ?? ?? ?? ?? 89 C3 8B 30 C7 44 24 10 00 00 00 00 50 8D 44 24 14 50 68 31 54 04 40 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 74 0C 83 CA FF 83 3B 16 75 04 89 33 31 D2 89 D0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule getnetent_bfa81095a271c8dc3f255fadeaf7db24 {
	meta:
		aliases = "__GI_getnetent, getnetent"
		size = "382"
		objfiles = "getnetent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 10 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 3D ?? ?? ?? ?? 00 75 21 51 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 14 01 00 00 83 3D ?? ?? ?? ?? 00 75 1E 83 EC 0C 68 01 10 00 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 10 85 C0 75 05 E8 ?? ?? ?? ?? 52 FF 35 ?? ?? ?? ?? 68 00 10 00 00 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 0F 84 C9 00 00 00 80 38 23 74 B0 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74 A2 C6 00 00 89 1D ?? ?? ?? ?? BA ?? ?? ?? ?? 89 D8 E8 ?? ?? ?? ?? 85 C0 74 }
	condition:
		$pattern
}

rule getutline_d8b012794a4a6638979bcb63464c3be9 {
	meta:
		aliases = "getutline"
		size = "117"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 10 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 8B 74 24 20 83 C6 08 EB 1E 8B 03 83 E8 06 66 83 F8 01 77 13 50 50 56 8D 43 08 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 10 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 85 C0 75 D2 51 51 6A 01 8D 44 24 10 50 E8 ?? ?? ?? ?? 89 D8 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule setstate_5e71f06304711b453d328f120c930167 {
	meta:
		aliases = "setstate"
		size = "93"
		objfiles = "random@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 10 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 58 5A 68 ?? ?? ?? ?? FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 10 31 F6 85 C0 78 03 8D 73 FC 50 50 6A 01 8D 44 24 10 50 E8 ?? ?? ?? ?? 89 F0 83 C4 24 5B 5E C3 }
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

rule getrpcbynumber_r_903966613e578702082f94174628b6e8 {
	meta:
		aliases = "getrpcbynumber_r"
		size = "90"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 10 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5E FF 74 24 2C E8 ?? ?? ?? ?? 5A 59 FF 74 24 38 FF 74 24 38 8B 4C 24 38 8B 54 24 34 E8 ?? ?? ?? ?? 89 C6 59 58 6A 01 53 E8 ?? ?? ?? ?? 89 F0 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule initstate_062e5ae25a550a3a940317241d69a458 {
	meta:
		aliases = "initstate"
		size = "87"
		objfiles = "random@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 10 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 83 EE 04 68 ?? ?? ?? ?? FF 74 24 3C FF 74 24 3C FF 74 24 3C E8 ?? ?? ?? ?? 83 C4 18 6A 01 53 E8 ?? ?? ?? ?? 89 F0 83 C4 24 5B 5E C3 }
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

rule getutent_11cfa29d58651cfc0703d95379d877fa {
	meta:
		aliases = "getutent"
		size = "67"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 74 24 10 56 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 59 58 6A 01 56 E8 ?? ?? ?? ?? 89 D8 83 C4 24 5B 5E C3 }
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

rule exit_855324f7e0abaabc08af47d2a72cd379 {
	meta:
		aliases = "__GI_exit, exit"
		size = "103"
		objfiles = "exit@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 8B 74 24 24 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 10 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 09 83 EC 0C 56 FF D0 83 C4 10 50 50 6A 01 53 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 B8 ?? ?? ?? ?? 85 C0 74 05 E8 ?? ?? ?? ?? 83 EC 0C 56 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule openlog_b9df32826e2ab5860b3ec9956d3b73de {
	meta:
		aliases = "__GI_openlog, openlog"
		size = "297"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 8B 74 24 24 8B 5C 24 2C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 10 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 F6 74 06 89 35 ?? ?? ?? ?? 8B 44 24 24 A2 ?? ?? ?? ?? 85 DB 74 0E F7 C3 07 FC FF FF 75 06 89 1D ?? ?? ?? ?? BB 02 00 00 00 83 3D ?? ?? ?? ?? FF 75 56 F6 05 ?? ?? ?? ?? 08 74 4D 56 6A 00 53 6A 01 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 10 83 F8 FF 0F 84 8D 00 00 00 51 6A 01 6A 02 50 E8 ?? ?? ?? ?? 58 5A 6A 03 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 80 CC 08 50 6A 04 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 A1 ?? ?? ?? ?? 83 F8 FF 74 52 80 3D ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_readdir_337b699b16135972b03ab4fd4b7e25d6 {
	meta:
		aliases = "readdir, __GI_readdir"
		size = "132"
		objfiles = "readdir@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 8B 74 24 24 8D 5E 18 53 68 ?? ?? ?? ?? 8D 44 24 10 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 46 08 3B 46 04 77 23 52 FF 76 14 FF 76 0C FF 36 E8 ?? ?? ?? ?? 83 C4 10 85 C0 7F 04 31 DB EB 26 89 46 08 C7 46 04 00 00 00 00 8B 46 04 89 C3 03 5E 0C 0F B7 53 08 01 C2 89 56 04 8B 43 04 89 46 10 83 3B 00 74 B9 50 50 6A 01 8D 44 24 10 50 E8 ?? ?? ?? ?? 89 D8 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule readdir64_bd90089c675a5cd4281c19dd7bb2ebfe {
	meta:
		aliases = "__GI_readdir64, readdir64"
		size = "134"
		objfiles = "readdir64@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 8B 74 24 24 8D 5E 18 53 68 ?? ?? ?? ?? 8D 44 24 10 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 46 08 3B 46 04 77 23 52 FF 76 14 FF 76 0C FF 36 E8 ?? ?? ?? ?? 83 C4 10 85 C0 7F 04 31 DB EB 28 89 46 08 C7 46 04 00 00 00 00 8B 56 04 89 D3 03 5E 0C 0F B7 43 10 01 D0 89 46 04 8B 43 08 89 46 10 8B 03 0B 43 04 74 B7 50 50 6A 01 8D 44 24 10 50 E8 ?? ?? ?? ?? 89 D8 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule initgroups_69cd6aa89cba741411bf6e9895f833e3 {
	meta:
		aliases = "initgroups"
		size = "76"
		objfiles = "initgroups@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 18 C7 44 24 14 FF FF FF 7F 8D 44 24 14 50 FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 89 C3 83 C4 10 83 CE FF 85 C0 74 19 50 50 53 FF 74 24 1C E8 ?? ?? ?? ?? 89 C6 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 89 F0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule lseek64_8ffe60d0f4557935179a2ddee10922c8 {
	meta:
		aliases = "lseek64"
		size = "68"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 1C 8B 5C 24 2C 8B 74 24 30 8D 44 24 18 50 6A 01 E8 ?? ?? ?? ?? FF 74 24 3C 56 53 FF 74 24 3C E8 ?? ?? ?? ?? 89 C3 89 D6 83 C4 18 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? 89 D8 89 F2 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule pread64_54247e9fd1d931cff9699d84ebe68e1d {
	meta:
		aliases = "pread64"
		size = "70"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 1C 8B 5C 24 34 8B 74 24 38 8D 44 24 18 50 6A 01 E8 ?? ?? ?? ?? 89 34 24 53 FF 74 24 3C FF 74 24 3C FF 74 24 3C E8 ?? ?? ?? ?? 89 C3 83 C4 18 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? 89 D8 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule xdr_pointer_d9e5db2b9cb21e1e1ca935812e5108f1 {
	meta:
		aliases = "xdr_pointer"
		size = "90"
		objfiles = "xdr_reference@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 1C 8B 74 24 28 8B 5C 24 2C 31 C0 83 3B 00 0F 95 C0 89 44 24 18 8D 44 24 18 50 56 E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 74 25 83 7C 24 10 00 75 0A C7 03 00 00 00 00 B2 01 EB 14 FF 74 24 2C FF 74 24 2C 53 56 E8 ?? ?? ?? ?? 89 C2 83 C4 10 89 D0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule erand48_r_9ed5c3ecbe5ad2fc4eebaa676062afe3 {
	meta:
		aliases = "__GI_erand48_r, erand48_r"
		size = "140"
		objfiles = "erand48_r@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 1C C7 44 24 10 00 00 00 00 C7 44 24 14 00 00 00 00 8B 74 24 28 FF 74 24 2C 56 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 57 8B 54 24 0C 81 E2 FF FF 0F 00 81 CA 00 00 F0 3F 89 54 24 0C 66 8B 5E 02 89 D9 66 C1 E9 0C 0F B7 C9 0F B7 46 04 C1 E0 04 09 C1 81 E2 00 00 F0 FF 09 CA 89 54 24 0C C1 E3 14 0F B7 06 C1 E0 04 09 C3 89 5C 24 08 DD 44 24 08 DC 25 ?? ?? ?? ?? 8B 44 24 28 DD 18 31 D2 89 D0 83 C4 14 5B 5E C3 }
	condition:
		$pattern
}

rule error_9402e2398908dcf63de459ddad3f2784 {
	meta:
		aliases = "__error, error"
		size = "209"
		objfiles = "error@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 20 8B 74 24 2C 8B 5C 24 30 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 74 04 FF D0 EB 1A 51 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 8D 44 24 2C 89 44 24 10 52 50 FF 74 24 30 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 05 ?? ?? ?? ?? 83 C4 10 85 DB 74 20 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 0C 50 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 8B 15 ?? ?? ?? ?? 83 7A 34 00 74 1D 8B 42 10 3B 42 1C 73 09 C6 00 0A 40 89 42 10 EB 19 53 53 52 6A 0A E8 ?? ?? ?? ?? EB 0A 51 51 52 6A 0A E8 ?? ?? ?? ?? 83 C4 10 85 F6 74 09 83 EC 0C 56 E8 ?? }
	condition:
		$pattern
}

rule __fresetlockfiles_d89fda1cdfe32532b84adddd7cfd2c2d {
	meta:
		aliases = "__fresetlockfiles"
		size = "72"
		objfiles = "lockfile@libpthread.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 20 8D 5C 24 1C 53 E8 ?? ?? ?? ?? 59 5E 6A 01 53 E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? EB 0F 52 52 50 8D 46 38 50 E8 ?? ?? ?? ?? 8B 76 20 83 C4 10 85 F6 89 D8 75 E8 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule tmpnam_9f345b9923980aff1fd34a213099ddeb {
	meta:
		aliases = "tmpnam"
		size = "90"
		objfiles = "tmpnam@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 24 8B 5C 24 30 89 DE 85 DB 75 04 8D 74 24 10 6A 00 6A 00 6A 14 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 2A 52 52 6A 03 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 19 85 DB 75 17 50 6A 14 56 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 83 C4 10 EB 02 31 DB 89 D8 83 C4 24 5B 5E C3 }
	condition:
		$pattern
}

rule __ieee754_log2_c6f5e2313c212abbf72fbddbb3356696 {
	meta:
		aliases = "__ieee754_log2"
		size = "390"
		objfiles = "e_log2@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 24 DD 44 24 30 DD 14 24 DD 54 24 18 8B 4C 24 1C 8B 54 24 18 31 F6 81 F9 FF FF 0F 00 7F 47 89 C8 25 FF FF FF 7F 09 D0 75 0F D9 C0 DE E1 D8 3D ?? ?? ?? ?? E9 44 01 00 00 DD D8 85 C9 79 0C DD 04 24 D8 E0 D8 F0 E9 32 01 00 00 DD 04 24 D8 0D ?? ?? ?? ?? DD 14 24 DD 5C 24 10 8B 4C 24 14 BE CA FF FF FF EB 02 DD D8 81 F9 FF FF EF 7F 7E 0A DD 04 24 D8 C0 E9 03 01 00 00 89 CB 81 E3 FF FF 0F 00 8D 93 64 5F 09 00 81 E2 00 00 10 00 DD 04 24 DD 5C 24 08 89 D0 35 00 00 F0 3F 09 D8 89 44 24 0C C1 F9 14 8D 84 0E 01 FC FF FF C1 FA 14 01 D0 50 DB 04 24 83 C4 04 DD 44 24 08 DC 25 ?? ?? ?? ?? 8D 43 02 }
	condition:
		$pattern
}

rule __ieee754_log_50db4fe9c1d50d885f9db52dced9f8d8 {
	meta:
		aliases = "__ieee754_log"
		size = "523"
		objfiles = "e_log@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 24 DD 44 24 30 DD 14 24 DD 5C 24 18 8B 4C 24 1C 8B 54 24 18 31 F6 81 F9 FF FF 0F 00 7F 45 89 C8 25 FF FF FF 7F 09 D0 75 0D D9 EE D8 3D ?? ?? ?? ?? E9 CB 01 00 00 85 C9 79 10 DD 04 24 D8 E0 DC 35 ?? ?? ?? ?? E9 B7 01 00 00 DD 04 24 D8 0D ?? ?? ?? ?? DD 14 24 DD 5C 24 10 8B 4C 24 14 BE CA FF FF FF 81 F9 FF FF EF 7F 7E 0A DD 04 24 D8 C0 E9 8C 01 00 00 89 CB 81 E3 FF FF 0F 00 8D 93 64 5F 09 00 81 E2 00 00 10 00 DD 04 24 DD 5C 24 08 89 D0 35 00 00 F0 3F 09 D8 89 44 24 0C C1 F9 14 8D 84 0E 01 FC FF FF C1 FA 14 8D 0C 10 DD 44 24 08 DC 25 ?? ?? ?? ?? 8D 43 02 25 FF FF 0F 00 83 F8 02 7F 75 }
	condition:
		$pattern
}

rule __GI_atan_878fd505d7697039251ab7e869d08a97 {
	meta:
		aliases = "atan, __GI_atan"
		size = "458"
		objfiles = "s_atan@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 24 DD 44 24 30 DD 54 24 08 DD 54 24 18 8B 74 24 1C 89 F3 81 E3 FF FF FF 7F 81 FB FF FF 0F 44 7E 3B DD 5C 24 10 8B 44 24 10 81 FB 00 00 F0 7F 7F 06 75 0F 85 C0 74 0B DD 44 24 08 D8 C0 E9 76 01 00 00 85 F6 7F 0B DD 05 ?? ?? ?? ?? E9 67 01 00 00 DD 05 ?? ?? ?? ?? E9 5C 01 00 00 DD D8 81 FB FF FF DB 3F 7F 2A 81 FB FF FF 1F 3E 0F 8F B3 00 00 00 DD 44 24 08 DC 05 ?? ?? ?? ?? D9 E8 D9 C9 DA E9 DF E0 9E 0F 87 31 01 00 00 E9 95 00 00 00 50 50 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? 83 C4 10 D9 C0 81 FB FF FF F2 3F 7F 3D 81 FB FF FF E5 3F 7F 1C DC C1 D9 C9 DC 25 ?? ?? ?? ?? D9 C9 D8 05 ?? ?? }
	condition:
		$pattern
}

rule __GI___res_init_20d957c70b420901d2d02ddf1f186338 {
	meta:
		aliases = "__res_init, __GI___res_init"
		size = "292"
		objfiles = "res_init@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 28 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 1C 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 05 00 00 00 C7 05 ?? ?? ?? ?? 04 00 00 00 C7 05 ?? ?? ?? ?? 01 00 00 00 E8 ?? ?? ?? ?? 66 A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 66 C7 05 ?? ?? ?? ?? 02 00 66 C7 05 ?? ?? ?? ?? 00 35 A0 ?? ?? ?? ?? 83 E0 F0 83 C8 01 A2 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? FF FF FF FF 8B 0D ?? ?? ?? ?? 83 C4 10 31 D2 85 C9 75 11 EB 13 8B 04 95 ?? ?? ?? ?? 89 04 95 ?? ?? ?? ?? 42 39 CA 7C ED 83 3D ?? ?? ?? ?? 00 74 49 31 DB 8D 74 24 20 EB 39 52 52 56 FF 34 }
	condition:
		$pattern
}

rule _stdio_openlist_dec_use_af9e6a8b7ed886773a9aa453a262b7d8 {
	meta:
		aliases = "_stdio_openlist_dec_use"
		size = "228"
		objfiles = "fflush_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 28 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 20 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 48 0F 85 91 00 00 00 83 3D ?? ?? ?? ?? 00 0F 8E 84 00 00 00 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 10 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 31 F6 83 C4 10 EB 37 8B 5A 20 0F B7 02 25 30 80 00 00 83 F8 30 74 04 89 D6 EB 21 85 F6 75 08 89 1D ?? ?? ?? ?? EB 03 89 5E 20 F6 42 01 20 74 0C 83 EC 0C 52 E8 ?? ?? ?? ?? 83 C4 10 89 DA 85 D2 75 C5 52 52 6A 01 8D 44 24 10 50 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 10 A1 ?? ?? }
	condition:
		$pattern
}

rule __get_hosts_byaddr_r_3a46d05b00aa4c6ee16b736279e5cc77 {
	meta:
		aliases = "__get_hosts_byaddr_r"
		size = "97"
		objfiles = "get_hosts_byaddr_r@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 34 8B 44 24 44 8B 74 24 48 83 FE 02 74 07 83 FE 0A 75 42 EB 05 83 F8 04 EB 03 83 F8 10 75 36 6A 2E 8D 5C 24 0A 53 FF 74 24 48 56 E8 ?? ?? ?? ?? 58 FF 74 24 68 FF 74 24 68 FF 74 24 68 FF 74 24 68 FF 74 24 68 6A 02 56 53 6A 00 E8 ?? ?? ?? ?? 83 C4 30 EB 02 31 C0 83 C4 34 5B 5E C3 }
	condition:
		$pattern
}

rule popen_10999fc83f809dc4d7b2dd88155c5e63 {
	meta:
		aliases = "popen"
		size = "506"
		objfiles = "popen@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 34 8B 5C 24 44 8A 03 3C 77 74 23 C7 44 24 10 01 00 00 00 3C 72 74 1F E8 ?? ?? ?? ?? C7 00 16 00 00 00 C7 04 24 00 00 00 00 E9 BF 01 00 00 C7 44 24 10 00 00 00 00 83 EC 0C 6A 0C E8 ?? ?? ?? ?? 83 C4 10 C7 04 24 00 00 00 00 85 C0 0F 84 9B 01 00 00 89 44 24 04 83 EC 0C 8D 44 24 38 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 85 68 01 00 00 8B 44 24 10 8B 44 84 2C 89 44 24 0C B8 01 00 00 00 2B 44 24 10 8B 44 84 2C 89 44 24 08 51 51 53 50 E8 ?? ?? ?? ?? 89 44 24 10 83 C4 10 85 C0 75 1B 83 EC 0C FF 74 24 14 E8 ?? ?? ?? ?? 5A FF 74 24 18 E8 ?? ?? ?? ?? E9 19 01 00 00 50 68 ?? ?? ?? ?? 68 ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_pmap_set_ab33fb6712437a4ca99bbda0fba4290e {
	meta:
		aliases = "pmap_set, __GI_pmap_set"
		size = "214"
		objfiles = "pmap_clnt@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 34 8B 74 24 4C C7 44 24 30 FF FF FF FF 8D 5C 24 1C 89 D8 E8 ?? ?? ?? ?? 85 C0 0F 84 AA 00 00 00 68 90 01 00 00 68 90 01 00 00 8D 44 24 38 50 FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 6A 02 68 A0 86 01 00 53 E8 ?? ?? ?? ?? 89 C3 83 C4 20 85 C0 74 79 8B 44 24 40 89 44 24 0C 8B 44 24 44 89 44 24 10 8B 44 24 48 89 44 24 14 0F B7 C6 89 44 24 18 8D 44 24 2C 8D 54 24 0C 8B 4B 04 FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? 6A 01 53 FF 11 83 C4 20 85 C0 74 18 56 56 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? C7 44 24 3C 00 00 00 00 83 C4 10 83 EC 0C 8B 43 04 53 FF 50 10 8B 44 24 }
	condition:
		$pattern
}

rule __GI_remquo_9f063c4de99c3de03ea6f1899a6c55da {
	meta:
		aliases = "remquo, __GI_remquo"
		size = "124"
		objfiles = "s_remquo@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 34 DD 44 24 40 DD 5C 24 18 DD 44 24 48 DD 5C 24 10 8B 74 24 50 DD 44 24 18 DD 5C 24 28 DD 44 24 10 DD 5C 24 20 8B 54 24 2C C1 EA 1F 8B 44 24 24 C1 E8 1F 31 DB 39 C2 0F 94 C3 8D 5C 1B FF DD 44 24 18 DC 74 24 10 DD 1C 24 E8 ?? ?? ?? ?? DD 1C 24 E8 ?? ?? ?? ?? 83 E0 7F 0F AF C3 89 06 DD 44 24 10 DD 5C 24 48 DD 44 24 18 DD 5C 24 40 83 C4 34 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tcgetattr_c89694447acf1925ab58d0d6ff8ad13d {
	meta:
		aliases = "__GI_tcgetattr, tcgetattr"
		size = "112"
		objfiles = "tcgetattr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 38 8B 5C 24 48 8D 44 24 14 50 68 01 54 00 00 FF 74 24 4C E8 ?? ?? ?? ?? 89 C6 83 C4 10 85 C0 75 43 8B 44 24 10 89 03 8B 44 24 14 89 43 04 8B 44 24 18 89 43 08 8B 44 24 1C 89 43 0C 8A 44 24 20 88 43 10 50 6A 13 8D 44 24 29 50 8D 43 11 50 E8 ?? ?? ?? ?? 83 C4 0C 6A 0D 6A 00 50 E8 ?? ?? ?? ?? 83 C4 10 89 F0 83 C4 34 5B 5E C3 }
	condition:
		$pattern
}

rule __ieee754_yn_c4822a7128aa91815eacae3b7d2075d8 {
	meta:
		aliases = "__ieee754_yn"
		size = "588"
		objfiles = "e_jn@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 44 8B 5C 24 50 DD 44 24 54 DD 14 24 DD 54 24 18 8B 74 24 1C 8B 54 24 18 89 F1 81 E1 FF FF FF 7F 89 D0 F7 D8 09 D0 C1 E8 1F 09 C8 3D 00 00 F0 7F 76 07 D8 C0 E9 01 02 00 00 DD D8 09 CA 75 0D D9 EE D8 3D ?? ?? ?? ?? E9 EE 01 00 00 85 F6 79 09 D9 EE D8 F0 E9 E1 01 00 00 83 FB 00 7D 12 F7 DB 89 D8 83 E0 01 01 C0 BE 01 00 00 00 29 C6 EB 18 75 11 DD 04 24 DD 5C 24 50 83 C4 44 5B 5E E9 ?? ?? ?? ?? BE 01 00 00 00 83 FB 01 75 23 50 50 FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? DD 54 24 38 56 DA 0C 24 DD 5C 24 3C 83 C4 14 E9 8E 01 00 00 81 F9 00 00 F0 7F 75 07 D9 EE E9 7B 01 00 00 81 F9 FF FF CF }
	condition:
		$pattern
}

rule __ieee754_j1_89d95a9ee163f4c27d4613a663d59301 {
	meta:
		aliases = "__ieee754_j1"
		size = "498"
		objfiles = "e_j1@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 44 DD 44 24 50 DD 54 24 08 DD 54 24 10 8B 74 24 14 89 F3 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 0B DC 3D ?? ?? ?? ?? E9 BC 01 00 00 DD D8 81 FB FF FF FF 3F 0F 8E 1B 01 00 00 50 50 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? 59 58 DD 5C 24 40 FF 74 24 44 FF 74 24 44 E8 ?? ?? ?? ?? DD 5C 24 28 58 5A FF 74 24 44 FF 74 24 44 E8 ?? ?? ?? ?? DD 5C 24 30 DD 44 24 28 DC 64 24 30 DD 5C 24 40 83 C4 10 81 FB FF FF DF 7F 7F 4D 83 EC 10 DD 44 24 48 D8 C0 DD 1C 24 E8 ?? ?? ?? ?? DD 44 24 28 DC 4C 24 30 83 C4 10 D9 EE D9 C9 DA E9 DF E0 9E 76 16 DD 44 24 18 D9 E0 DC 64 24 20 DD 54 24 28 DE F9 DD 5C 24 }
	condition:
		$pattern
}

rule __md5_Final_a8418feb1e73e6776d3805acaa439855 {
	meta:
		aliases = "__md5_Final"
		size = "132"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 58 89 C6 89 D3 6A 40 6A 00 8D 44 24 18 50 E8 ?? ?? ?? ?? C6 44 24 1C 80 83 C4 0C 6A 08 8D 43 10 50 8D 44 24 58 50 E8 ?? ?? ?? ?? 8B 43 10 C1 E8 03 83 E0 3F 83 C4 10 B9 38 00 00 00 83 F8 37 76 05 B9 78 00 00 00 29 C1 8D 54 24 0C 89 D8 E8 ?? ?? ?? ?? 8D 54 24 4C B9 08 00 00 00 89 D8 E8 ?? ?? ?? ?? 50 6A 10 53 56 E8 ?? ?? ?? ?? 83 C4 0C 6A 58 6A 00 53 E8 ?? ?? ?? ?? 83 C4 64 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_vsscanf_873aa25ae40454924486b36a3991c935 {
	meta:
		aliases = "vsscanf, __GI_vsscanf"
		size = "125"
		objfiles = "vsscanf@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 60 8B 5C 24 6C C7 44 24 14 FE FF FF FF 66 C7 44 24 10 A1 00 C6 44 24 12 00 C7 44 24 3C 00 00 00 00 C7 44 24 44 01 00 00 00 8D 74 24 10 8D 44 24 48 50 E8 ?? ?? ?? ?? C7 44 24 34 00 00 00 00 89 5C 24 24 89 5C 24 1C 89 1C 24 E8 ?? ?? ?? ?? 83 C4 0C 8D 04 03 89 44 24 14 89 44 24 1C 89 44 24 20 89 5C 24 24 FF 74 24 6C FF 74 24 6C 56 E8 ?? ?? ?? ?? 83 C4 64 5B 5E C3 }
	condition:
		$pattern
}

rule erf_2fb4c6e8e3689b0fcf2fecadabee9981 {
	meta:
		aliases = "__GI_erf, erf"
		size = "852"
		objfiles = "s_erf@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 64 DD 44 24 70 DD 54 24 38 DD 54 24 48 8B 74 24 4C 89 F3 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 1F C1 EE 1F 8D 14 36 B8 01 00 00 00 29 D0 DC 3D ?? ?? ?? ?? 50 DA 04 24 83 C4 04 E9 0A 03 00 00 DD D8 81 FB FF FF EA 3F 0F 8F A8 00 00 00 81 FB FF FF 2F 3E 7F 35 81 FB FF FF 7F 00 7F 21 DD 44 24 38 D8 0D ?? ?? ?? ?? DD 44 24 38 DC 0D ?? ?? ?? ?? DE C1 D8 0D ?? ?? ?? ?? E9 CB 02 00 00 DD 44 24 38 DC 0D ?? ?? ?? ?? EB 62 DD 44 24 38 D8 C8 DD 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? DD 05 ?? ?? ?? ?? D8 CA DC 05 ?? ?? ?? }
	condition:
		$pattern
}

rule __ieee754_asin_f788c53b2a8807fb67a0d93ac1438b33 {
	meta:
		aliases = "__ieee754_asin"
		size = "548"
		objfiles = "e_asin@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 64 DD 44 24 70 DD 54 24 38 DD 54 24 50 8B 74 24 54 89 F3 81 E3 FF FF FF 7F 81 FB FF FF EF 3F 7E 36 DD 54 24 48 8D 83 00 00 10 C0 0B 44 24 48 75 17 DC 0D ?? ?? ?? ?? DD 44 24 38 DC 0D ?? ?? ?? ?? DE C1 E9 C6 01 00 00 DD D8 DD 44 24 38 D8 E0 D8 F0 E9 B7 01 00 00 DD D8 81 FB FF FF DF 3F 0F 8F 90 00 00 00 81 FB FF FF 3F 3E 7F 1B DD 44 24 38 DC 05 ?? ?? ?? ?? D9 E8 D9 C9 DA E9 DF E0 9E 0F 87 90 01 00 00 EB 6D DD 44 24 38 D8 C8 DD 05 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DD 05 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule cbrt_2d20bb1ddff5e1f4de7d68067203f1c6 {
	meta:
		aliases = "__GI_cbrt, cbrt"
		size = "347"
		objfiles = "s_cbrt@libm.a"
	strings:
		$pattern = { ( CC | 56 ) 53 83 EC 74 C7 44 24 18 00 00 00 00 C7 44 24 1C 00 00 00 00 DD 84 24 80 00 00 00 DD 14 24 DD 54 24 58 8B 5C 24 5C 81 E3 00 00 00 80 8B 4C 24 5C 81 E1 FF FF FF 7F 81 F9 FF FF EF 7F 7E 07 D8 C0 E9 05 01 00 00 DD D8 DD 04 24 DD 54 24 50 8B 44 24 50 09 C8 0F 84 F5 00 00 00 DD 5C 24 48 89 4C 24 4C DD 44 24 48 81 F9 FF FF 0F 00 7F 3D D9 EE DD 5C 24 40 C7 44 24 44 00 00 50 43 DD 44 24 40 D8 C9 DD 54 24 38 DD 5C 24 30 BA 03 00 00 00 8B 44 24 3C 89 D6 31 D2 F7 F6 89 C1 81 C1 93 78 7F 29 89 4C 24 34 DD 44 24 30 EB 22 D9 EE DD 5C 24 28 BA 03 00 00 00 89 C8 89 D6 99 F7 FE 89 C1 81 C1 93 78 9F 2A 89 4C }
	condition:
		$pattern
}

rule skip_3d309c064f996f3fc6c0beb3b6a1fb63 {
	meta:
		aliases = "skip"
		size = "133"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 89 C2 89 C3 31 F6 EB 6C 80 F9 22 75 05 83 F6 01 EB 61 83 FE 01 75 10 80 F9 5C 75 0B 8D 42 01 80 7A 01 22 75 02 89 C2 8A 02 88 03 43 83 FE 01 74 42 80 F9 23 75 0C C6 05 ?? ?? ?? ?? 23 C6 02 00 EB 38 0F BE C1 83 F8 09 74 0A 83 F8 20 74 05 80 F9 0A 75 1F 88 0D ?? ?? ?? ?? C6 02 00 42 8A 02 0F BE C8 3C 09 74 F6 83 F9 20 74 F1 83 F9 0A 75 09 EB EA 42 8A 0A 84 C9 75 8E C6 43 FF 00 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule any_1eba76cdaf107cd6798d56e673b9ffcc {
	meta:
		aliases = "any"
		size = "37"
		objfiles = "getnetent@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 89 C3 89 D6 EB 0C 38 D0 74 14 41 8A 01 84 C0 75 F5 43 8A 13 84 D2 74 04 89 F1 EB EF 31 DB 89 D8 5B 5E C3 }
	condition:
		$pattern
}

rule check_match_be29f606fda2205209315a05cb4d58d7 {
	meta:
		aliases = "check_match"
		size = "91"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 56 ) 53 89 C6 31 C0 66 83 7E 0E 00 0F 94 C0 85 44 24 0C 75 40 83 7E 04 00 74 3A 0F B6 46 0C 83 E0 0F 83 F8 02 7E 05 83 F8 05 75 29 03 16 8D 5A FF 8D 51 FF 43 8A 03 42 8A 0A 84 C0 75 07 0F B6 D1 F7 DA EB 0C 38 C8 74 EB 0F B6 D0 0F B6 C1 29 C2 85 D2 74 02 31 F6 89 F0 5B 5E C3 }
	condition:
		$pattern
}

rule rawmemchr_8e7374812e9871c15d6da80f1bd73741 {
	meta:
		aliases = "__GI_rawmemchr, rawmemchr"
		size = "101"
		objfiles = "rawmemchr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8A 5C 24 10 8B 44 24 0C EB 05 38 18 74 52 40 A8 03 75 F7 89 C1 0F B6 D3 89 D0 C1 E0 08 09 D0 89 C6 C1 E6 10 09 C6 89 F2 33 11 83 C1 04 89 D0 F7 D0 81 C2 FF FE FE 7E 31 D0 A9 00 01 01 81 74 E6 8D 41 FC 38 59 FC 74 18 8D 41 FD 38 59 FD 74 10 8D 41 FE 38 59 FE 74 08 8D 41 FF 38 59 FF 75 C6 5B 5E C3 }
	condition:
		$pattern
}

rule strspn_8d2bcbc72e010445c961d2d7abd7e9fd {
	meta:
		aliases = "__GI_strspn, strspn"
		size = "42"
		objfiles = "strspn@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 44 24 0C 31 F6 EB 0F 38 CB 74 09 42 8A 0A 84 C9 75 F5 EB 0E 46 40 8A 18 84 DB 74 06 8B 54 24 10 EB EA 89 F0 5B 5E C3 }
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

rule pread64_5c22623e9d600939c2de16f66411f0fb {
	meta:
		aliases = "__libc_pread64, pread64"
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
		size = "45"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 44 24 0C 8B 54 24 10 8B 4C 24 14 C7 44 24 14 01 00 00 00 8B 5C 24 18 8B 74 24 1C 89 5C 24 0C 89 74 24 10 5B 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule re_match_72bd68ff2541fe340642c306275ab316 {
	meta:
		aliases = "__re_match, re_match"
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
		size = "75"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 44 24 0C 8B 74 24 10 8B 50 0C 8B 00 85 C0 74 05 48 75 30 EB 10 8B 42 10 8D 0C 30 3B 4A 14 77 23 89 4A 10 EB 20 8B 4A 34 39 CE 77 17 8B 5A 2C 8D 04 33 3B 42 30 77 0C 89 D8 29 F1 89 4A 34 01 72 2C EB 02 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule a64l_8ec46257a8ecf26014b45a7dcbfb264a {
	meta:
		aliases = "a64l"
		size = "58"
		objfiles = "a64l@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 44 24 0C 8D 70 06 89 C2 31 DB 31 C9 0F BE 02 83 E8 2E 83 F8 4C 77 1B 8A 80 ?? ?? ?? ?? 3C 40 74 11 42 0F BE C0 D3 E0 09 C3 39 F2 74 05 83 C1 06 EB DA 89 D8 5B 5E C3 }
	condition:
		$pattern
}

rule _ppfs_setargs_57c8ab7a6f649f26956cf905810b78ee {
	meta:
		aliases = "_ppfs_setargs"
		size = "277"
		objfiles = "_ppfs_setargs@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 4C 24 0C 83 79 18 00 0F 85 B5 00 00 00 81 79 08 00 00 00 80 75 11 8B 41 4C 8D 50 04 89 51 4C 8B 00 89 41 50 89 41 08 8D 59 50 81 79 04 00 00 00 80 75 11 8B 41 4C 8D 50 04 89 51 4C 8B 00 89 41 50 89 41 04 31 F6 EB 73 8B 44 B1 28 46 83 F8 08 74 69 8B 51 4C 7F 0E 83 F8 02 74 52 7E 50 83 F8 07 75 4B EB 2B 3D 00 04 00 00 74 42 7E 40 3D 00 08 00 00 74 09 3D 07 08 00 00 75 32 EB 21 8D 42 08 89 41 4C 8B 02 8B 52 04 89 03 89 53 04 EB 28 8B 51 4C 8D 42 08 89 41 4C DD 02 DD 1B EB 19 8B 51 4C 8D 42 0C 89 41 4C DB 2A DB 3B EB 0A 8D 42 04 89 41 4C 8B 02 89 03 83 C3 0C 3B 71 1C 7C 88 EB 2E 81 79 08 }
	condition:
		$pattern
}

rule _dl_do_lazy_reloc_e6b2c0c567bc19f91d29ad5097f64451 {
	meta:
		aliases = "_dl_do_lazy_reloc"
		size = "45"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 54 24 14 8B 44 24 0C 8B 00 8B 1A 31 C9 8B 72 04 81 E6 FF 00 00 00 74 0D 83 C9 FF 83 FE 07 75 05 01 04 03 31 C9 89 C8 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_strcasecmp_fe7f9d571a581daedb70c7d500fc65dd {
	meta:
		aliases = "strcasecmp, __GI_strcasecmp"
		size = "54"
		objfiles = "strcasecmp@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 5C 24 0C 8B 74 24 10 31 C0 39 F3 74 1A 8B 0D ?? ?? ?? ?? 0F B6 03 0F BF 14 41 0F B6 06 0F BF 04 41 29 C2 89 D0 75 09 80 3B 00 74 04 46 43 EB D9 5B 5E C3 }
	condition:
		$pattern
}

rule wcscspn_18cfccc2e720d4a78a7ff85f7c00a973 {
	meta:
		aliases = "wcscspn"
		size = "46"
		objfiles = "wcscspn@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 89 F0 EB 10 39 D9 74 18 83 C2 04 8B 0A 85 C9 75 F3 83 C0 04 8B 18 85 DB 74 06 8B 54 24 10 EB EB 29 F0 C1 F8 02 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_wcswidth_4386e160a7a08019b21460540373ae15 {
	meta:
		aliases = "wcswidth, __GI_wcswidth"
		size = "86"
		objfiles = "wcswidth@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 31 C9 EB 0A 89 D0 83 E0 7F 39 C2 75 37 41 39 D9 73 24 8B 14 8E 85 D2 75 EB EB 1B 3D FF 00 00 00 7F 22 83 F8 1F 7E 1D 83 E8 7F 83 F8 20 76 15 83 C6 04 42 4B EB 02 31 D2 85 DB 74 0B 8B 06 85 C0 75 D9 EB 03 83 CA FF 89 D0 5B 5E C3 }
	condition:
		$pattern
}

rule __GI_wcsspn_d02d319ac747b2faa306e49fd1cf5d41 {
	meta:
		aliases = "wcsspn, __GI_wcsspn"
		size = "42"
		objfiles = "wcsspn@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 89 F0 EB 0C 3B 08 74 05 83 C2 04 EB 05 83 C0 04 89 DA 8B 0A 85 C9 75 EC 29 F0 C1 F8 02 5B 5E C3 }
	condition:
		$pattern
}

rule sigorset_31d9aa62a2a1b3ef4f645551c2da30d3 {
	meta:
		aliases = "sigorset"
		size = "38"
		objfiles = "sigorset@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 8B 4C 24 14 BA 20 00 00 00 EB 09 8B 04 93 0B 04 91 89 04 96 4A 79 F4 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule sigandset_2e88eadd45cde9d9f8296119b7ead618 {
	meta:
		aliases = "sigandset"
		size = "38"
		objfiles = "sigandset@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 10 8B 4C 24 14 BA 20 00 00 00 EB 09 8B 04 93 23 04 91 89 04 96 4A 79 F4 31 C0 5B 5E C3 }
	condition:
		$pattern
}

rule ldiv_26fbe5458e0b5feb7ea2bce0cd2705b4 {
	meta:
		aliases = "ldiv"
		size = "45"
		objfiles = "ldiv@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 53 8B 74 24 0C 8B 5C 24 14 8B 44 24 10 99 F7 FB 89 C1 83 7C 24 10 00 78 07 85 D2 79 03 41 29 DA 89 56 04 89 0E 89 F0 5B 5E C2 04 00 }
	condition:
		$pattern
}

rule rindex_738aaa8a9844d021b20e0b9e74e6bb20 {
	meta:
		aliases = "__GI_strrchr, strrchr, rindex"
		size = "33"
		objfiles = "strrchr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 83 EC 04 8B 74 24 0C 31 C9 8B 44 24 10 88 C4 AC 38 E0 75 03 8D 4E FF 84 C0 75 F4 89 C8 5A 5E C3 }
	condition:
		$pattern
}

rule strchr_8a31351c1888fb1843961e913f53be1b {
	meta:
		aliases = "__GI_strchr, index, strchr"
		size = "30"
		objfiles = "strchr@libc.a"
	strings:
		$pattern = { ( CC | 56 ) 8B 74 24 08 8B 44 24 0C 88 C4 AC 38 E0 74 09 84 C0 75 F7 BE 01 00 00 00 89 F0 48 5E C3 }
	condition:
		$pattern
}

rule sigqueue_25a2de5c1e92a620d852385b77a09533 {
	meta:
		aliases = "sigqueue"
		size = "135"
		objfiles = "sigqueue@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 53 81 EC 88 00 00 00 8B BC 24 94 00 00 00 68 80 00 00 00 6A 00 8D 5C 24 10 53 E8 ?? ?? ?? ?? 8B 84 24 A4 00 00 00 89 44 24 14 C7 44 24 1C FF FF FF FF E8 ?? ?? ?? ?? 89 44 24 20 E8 ?? ?? ?? ?? 89 44 24 24 8B 84 24 A8 00 00 00 89 44 24 28 8B 8C 24 A4 00 00 00 89 DA 53 89 FB B8 B2 00 00 00 CD 80 5B 89 C3 83 C4 10 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 81 C4 84 00 00 00 5B 5F C3 }
	condition:
		$pattern
}

rule __GI__exit_d824590045fd5175581e5a4e7a65f434 {
	meta:
		aliases = "_Exit, _exit, __GI__exit"
		size = "40"
		objfiles = "_exit@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 53 83 EC 04 8B 7C 24 10 53 89 FB B8 01 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 EC E8 ?? ?? ?? ?? F7 DB 89 18 EB E1 }
	condition:
		$pattern
}

rule truncate64_a95737fa5de2ca129e9d311f9ea281f6 {
	meta:
		aliases = "truncate64"
		size = "79"
		objfiles = "truncate64@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 53 83 EC 14 8B 7C 24 20 8B 44 24 24 8B 54 24 28 89 D0 89 C2 C1 FA 1F 89 44 24 08 89 54 24 0C 8B 4C 24 24 8B 54 24 08 53 89 FB B8 C1 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 83 C4 14 5B 5F C3 }
	condition:
		$pattern
}

rule ftruncate64_2e202853950b6c205ef73b22caf2f0d0 {
	meta:
		aliases = "__GI_ftruncate64, ftruncate64"
		size = "79"
		objfiles = "ftruncate64@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 53 83 EC 14 8B 7C 24 20 8B 44 24 24 8B 54 24 28 89 D0 89 C2 C1 FA 1F 89 44 24 08 89 54 24 0C 8B 4C 24 24 8B 54 24 08 53 89 FB B8 C2 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 83 C4 14 5B 5F C3 }
	condition:
		$pattern
}

rule __GI___libc_open_9b664c97270d72c149d1365d6d26566d {
	meta:
		aliases = "open, __GI_open, __libc_open, __GI___libc_open"
		size = "72"
		objfiles = "open@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 53 83 EC 14 8B 7C 24 20 8B 4C 24 24 31 D2 F6 C1 40 74 0C 8D 44 24 2C 89 44 24 10 8B 54 24 28 53 89 FB B8 05 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 83 C4 14 5B 5F C3 }
	condition:
		$pattern
}

rule __libc_fcntl_502b397b50a1b3cf673f81ba1bbdca6d {
	meta:
		aliases = "__GI_fcntl, fcntl, __GI___libc_fcntl, __libc_fcntl"
		size = "87"
		objfiles = "__syscall_fcntl@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 53 83 EC 14 8B 7C 24 20 8B 4C 24 24 8D 44 24 2C 89 44 24 10 8B 54 24 28 8D 41 F4 83 F8 02 77 0E 50 52 51 57 E8 ?? ?? ?? ?? 83 C4 10 EB 22 53 89 FB B8 37 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF 89 D8 83 C4 14 5B 5F C3 }
	condition:
		$pattern
}

rule _dl_protect_relro_59b506bbb118b55a78ddaef3a5a9efd9 {
	meta:
		aliases = "_dl_protect_relro"
		size = "125"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 57 ) 53 8B 5C 24 0C 8B 13 03 93 D4 00 00 00 A1 ?? ?? ?? ?? F7 D8 89 C7 21 D7 89 D1 03 8B D8 00 00 00 21 C1 39 CF 74 53 29 F9 BA 01 00 00 00 53 89 FB B8 7D 00 00 00 CD 80 5B 3D 00 F0 FF FF 76 09 F7 D8 A3 ?? ?? ?? ?? EB 04 85 C0 79 2D FF 73 04 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? 31 FF 53 89 FB B8 01 00 00 00 CD 80 5B 83 C4 0C 3D 00 F0 FF FF 76 07 F7 D8 A3 ?? ?? ?? ?? 5B 5F C3 }
	condition:
		$pattern
}

rule ether_hostton_6c08fc67b592fd5b837f27a5fa5e5683 {
	meta:
		aliases = "ether_hostton"
		size = "132"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 81 EC 08 01 00 00 8B BC 24 18 01 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C6 83 C4 10 83 CB FF 85 C0 74 4D EB 26 8B 94 24 14 01 00 00 89 E0 E8 ?? ?? ?? ?? 85 C0 74 16 52 52 50 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 06 31 DB EB 19 89 E3 50 56 68 00 01 00 00 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 C4 83 CB FF 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 89 D8 81 C4 00 01 00 00 5B 5E 5F C3 }
	condition:
		$pattern
}

rule lckpwdf_e05cde855f6c74d82a4a381a383f0248 {
	meta:
		aliases = "lckpwdf"
		size = "482"
		objfiles = "lckpwdf@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 81 EC 40 02 00 00 83 C8 FF 83 3D ?? ?? ?? ?? FF 0F 85 BF 01 00 00 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 84 24 2C 02 00 00 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 5A 68 01 00 08 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 10 83 F8 FF 0F 84 63 01 00 00 57 6A 00 6A 01 50 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 0F 84 31 01 00 00 56 83 C8 01 50 6A 02 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 88 14 01 00 00 53 6A 01 6A 02 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 68 8C 00 00 00 6A 00 8D 5C 24 14 53 E8 ?? ?? ?? ?? C7 44 24 18 ?? ?? ?? ?? 59 8D 44 24 18 50 E8 ?? ?? }
	condition:
		$pattern
}

rule pthread_detach_7fe355a772ada0441794e91992dea323 {
	meta:
		aliases = "pthread_detach"
		size = "216"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 81 EC A0 00 00 00 8B BC 24 B0 00 00 00 89 F8 25 FF 03 00 00 C1 E0 04 8D B0 ?? ?? ?? ?? 31 D2 89 F0 E8 ?? ?? ?? ?? 8B 46 08 85 C0 74 05 39 78 10 74 10 83 EC 0C 56 E8 ?? ?? ?? ?? B8 03 00 00 00 EB 27 80 78 2D 00 74 10 83 EC 0C 56 E8 ?? ?? ?? ?? B8 16 00 00 00 EB 11 83 78 38 00 74 10 83 EC 0C 56 E8 ?? ?? ?? ?? 31 C0 83 C4 10 EB 5D C6 40 2D 01 8A 58 2C 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 84 DB 74 44 83 3D ?? ?? ?? ?? 00 78 3B E8 ?? ?? ?? ?? 89 44 24 0C C7 44 24 10 01 00 00 00 89 7C 24 14 8D 5C 24 0C 56 68 94 00 00 00 53 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 40 75 0A E8 ?? ?? ?? ?? 83 }
	condition:
		$pattern
}

rule div_d123fbb4109543a12338cd635d11de8c {
	meta:
		aliases = "div"
		size = "44"
		objfiles = "div@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 04 8B 74 24 14 8B 4C 24 18 8B 7C 24 1C 89 C8 99 F7 FF 89 FA 0F AF D0 29 D1 89 4E 04 89 06 89 F0 5A 5B 5E 5F C2 04 00 }
	condition:
		$pattern
}

rule __pthread_acquire_53268c3919fca017fdb05d0cda6d403d {
	meta:
		aliases = "__pthread_acquire"
		size = "78"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 89 C3 31 F6 8D 7C 24 08 EB 2C 83 FE 31 7F 08 E8 ?? ?? ?? ?? 46 EB 1F C7 44 24 08 00 00 00 00 C7 44 24 0C 81 84 1E 00 52 52 6A 00 57 E8 ?? ?? ?? ?? 31 F6 83 C4 10 B8 01 00 00 00 87 03 85 C0 75 C9 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule byte_alt_match_null_string_p_ac123d7d70b2293e39a7837943862c2c {
	meta:
		aliases = "byte_alt_match_null_string_p"
		size = "94"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 89 D3 89 CE 89 44 24 0C 8D 7C 24 0C EB 36 80 39 0F 75 1E 8D 41 01 89 44 24 0C 0F B6 51 01 0F BE 40 01 C1 E0 08 01 D0 8D 44 01 03 89 44 24 0C EB 13 89 F1 89 DA 89 F8 E8 ?? ?? ?? ?? 84 C0 75 04 31 C0 EB 0D 8B 4C 24 0C 39 D9 72 C2 B8 01 00 00 00 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule puts_452f089c9ee43df555156b5b310eb911 {
	meta:
		aliases = "puts"
		size = "124"
		objfiles = "puts@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 35 ?? ?? ?? ?? 8B 7E 34 85 FF 75 1F 53 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 51 51 56 FF 74 24 2C E8 ?? ?? ?? ?? 89 C3 83 C4 10 83 F8 FF 74 16 52 52 56 6A 0A E8 ?? ?? ?? ?? 83 C4 10 40 75 05 83 CB FF EB 01 43 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule calloc_20e5c87efd5899da40ae5fd2b550e5b9 {
	meta:
		aliases = "calloc"
		size = "244"
		objfiles = "calloc@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 54 24 20 8B 4C 24 24 89 CB 0F AF DA 85 D2 74 1E 89 D8 89 D7 31 D2 F7 F7 39 C1 74 12 E8 ?? ?? ?? ?? C7 00 0C 00 00 00 31 DB E9 B6 00 00 00 56 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 74 73 8B 40 FC A8 02 75 6C 83 E0 FC 8D 50 FC 89 D0 C1 E8 02 83 F8 09 76 0F 51 52 6A 00 53 E8 ?? ?? ?? ?? 83 C4 10 EB 4D C7 03 00 00 00 00 C7 43 04 00 00 00 00 C7 43 08 00 00 00 00 83 F8 04 76 34 C7 43 0C 00 00 00 00 C7 43 10 00 00 00 00 83 F8 06 76 21 C7 43 14 00 00 00 00 C7 43 18 00 00 00 00 83 }
	condition:
		$pattern
}

rule setkey_172589db858e01adbd1c9fd35a619fd5 {
	meta:
		aliases = "setkey"
		size = "68"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 5C 24 20 8D 7C 24 08 31 F6 EB 1F 8D 14 37 C6 02 00 31 C9 EB 0F F6 03 01 74 08 8A 81 ?? ?? ?? ?? 08 02 43 41 83 F9 07 7E EC 46 83 FE 07 7E DC 89 F8 E8 ?? ?? ?? ?? 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_rwlock_tryrdlock_d7c424aeb3cd8ccb8e3cb7f1fc48a415 {
	meta:
		aliases = "pthread_rwlock_tryrdlock"
		size = "141"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 5C 24 20 E8 ?? ?? ?? ?? 89 44 24 0C 83 EC 0C 8D 4C 24 14 8D 44 24 18 8D 54 24 10 52 89 DA E8 ?? ?? ?? ?? 89 C7 8B 54 24 1C 89 D8 E8 ?? ?? ?? ?? 31 D2 89 D8 E8 ?? ?? ?? ?? 83 C4 10 BE 10 00 00 00 85 C0 74 06 FF 43 08 66 31 F6 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 F6 75 22 85 FF 75 07 83 7C 24 04 00 74 17 8B 44 24 08 85 C0 74 05 FF 40 08 EB 0A 8B 44 24 0C FF 80 C8 01 00 00 89 F0 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_fflush_e8bf684822e9ecaf4552124b3fc960de {
	meta:
		aliases = "fflush, __GI_fflush"
		size = "117"
		objfiles = "fflush@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 85 F6 74 50 81 FE ?? ?? ?? ?? 74 48 8B 7E 34 85 FF 75 1F 52 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C 56 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 FF 75 1E 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? EB 0B 83 EC 0C 56 E8 ?? ?? ?? ?? 89 C3 83 C4 10 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule xdr_string_73b8dc22b6a5bf76d1e5f2dce7c594fe {
	meta:
		aliases = "__GI_xdr_string, xdr_string"
		size = "222"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 8B 7C 24 24 8B 1F 8B 06 85 C0 74 0E 83 F8 02 75 21 85 DB 75 0D E9 AA 00 00 00 85 DB 0F 84 A9 00 00 00 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 89 44 24 0C 50 50 8D 44 24 14 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 81 00 00 00 8B 44 24 0C 3B 44 24 28 77 77 8B 16 83 FA 01 74 09 72 40 83 FA 02 75 69 EB 47 40 74 5D 85 DB 75 2A 83 EC 0C 50 E8 ?? ?? ?? ?? 89 C3 89 07 83 C4 10 85 C0 75 16 50 50 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 EB 2A 8B 44 24 0C C6 04 03 00 50 FF 74 24 10 53 56 E8 ?? ?? ?? ?? EB 14 83 EC 0C 53 E8 ?? ?? ?? ?? C7 07 00 00 00 00 B8 01 00 00 }
	condition:
		$pattern
}

rule rewind_bcf51d35782f05a236935fd718c8f48f {
	meta:
		aliases = "__GI_rewind, rewind"
		size = "94"
		objfiles = "rewind@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 8B 7E 34 85 FF 75 1F 51 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 66 83 26 F7 52 6A 00 6A 00 56 E8 ?? ?? ?? ?? 83 C4 10 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule clearerr_1b9bd1538b34730b2275a81f9534cdea {
	meta:
		aliases = "clearerr"
		size = "80"
		objfiles = "clearerr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 8B 7E 34 85 FF 75 1F 52 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 66 83 26 F3 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule fileno_b689731659256f78e8cd210467d375a8 {
	meta:
		aliases = "fgetwc, __GI_fgetwc, __GI_fileno, getwc, fileno"
		size = "92"
		objfiles = "fgetwc@libc.a, fileno@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 8B 7E 34 85 FF 75 1F 52 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C 56 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule feof_5162c8ebde745d2f9470e3bc1d04d441 {
	meta:
		aliases = "feof"
		size = "83"
		objfiles = "feof@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 8B 7E 34 85 FF 75 1F 52 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 1E 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 E0 04 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule ferror_cd4b5f7132ab92d1cfbb75f71b00f091 {
	meta:
		aliases = "ferror"
		size = "83"
		objfiles = "ferror@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 8B 7E 34 85 FF 75 1F 52 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 8B 1E 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 E0 08 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule vfwprintf_f045abb3a8c393368500b7d3f8b20a3a {
	meta:
		aliases = "__GI_vfwprintf, vfwprintf"
		size = "136"
		objfiles = "vfwprintf@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 8B 7E 34 85 FF 75 1F 53 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 0F B7 06 25 40 08 00 00 3D 40 08 00 00 74 17 51 51 68 00 08 00 00 56 E8 ?? ?? ?? ?? 83 C4 10 83 CB FF 85 C0 75 14 52 FF 74 24 2C FF 74 24 2C 56 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_vfprintf_69b6451d9186158abeeac83e8130281f {
	meta:
		aliases = "vfprintf, __GI_vfprintf"
		size = "136"
		objfiles = "vfprintf@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 8B 7E 34 85 FF 75 1F 53 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 0F B7 06 25 C0 00 00 00 3D C0 00 00 00 74 17 51 51 68 80 00 00 00 56 E8 ?? ?? ?? ?? 83 C4 10 83 CB FF 85 C0 75 14 52 FF 74 24 2C FF 74 24 2C 56 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule gets_3c1939a1eb9f42aac25b3b2af4ea5ce7 {
	meta:
		aliases = "gets"
		size = "125"
		objfiles = "gets@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 20 A1 ?? ?? ?? ?? 8B 78 34 85 FF 74 04 89 F3 EB 2A 52 83 C0 38 50 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C0 38 89 04 24 E8 ?? ?? ?? ?? 83 C4 10 EB D3 43 E8 ?? ?? ?? ?? 83 F8 FF 74 0A 88 03 3C 0A 75 EF 39 DE 75 04 31 F6 EB 03 C6 03 00 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 89 F0 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule fputwc_eeac17f7362809bc8dda555980909188 {
	meta:
		aliases = "fputws, __GI_fputws, putwc, __GI_fputs, fputs, fputwc"
		size = "95"
		objfiles = "fputs@libc.a, fputws@libc.a, fputwc@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 24 8B 7E 34 85 FF 75 1F 51 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 52 52 56 FF 74 24 2C E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_fgets_7cb02aab089f718e67bb8de99cea1e29 {
	meta:
		aliases = "fgets, fgetws, __GI_fgets"
		size = "98"
		objfiles = "fgetws@libc.a, fgets@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 28 8B 7E 34 85 FF 75 1F 51 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 52 56 FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_fread_96f979affe6ac82a825dd73cb9bfe457 {
	meta:
		aliases = "fwrite, fread, __GI_fwrite, __GI_fread"
		size = "101"
		objfiles = "fread@libc.a, fwrite@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 74 24 2C 8B 7E 34 85 FF 75 1F 52 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 56 FF 74 24 2C FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 FF 75 11 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule tcgetsid_79db86e47c586167a40edd9bc8a4828a {
	meta:
		aliases = "tcgetsid"
		size = "134"
		objfiles = "tcgetsid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 7C 24 20 80 3D ?? ?? ?? ?? 00 75 2F E8 ?? ?? ?? ?? 89 C3 8B 30 50 8D 44 24 10 50 68 29 54 00 00 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 42 83 3B 16 75 43 C6 05 ?? ?? ?? ?? 01 89 33 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 74 29 83 EC 0C 50 E8 ?? ?? ?? ?? 89 44 24 1C 83 C4 10 40 75 10 E8 ?? ?? ?? ?? 83 38 03 75 06 C7 00 19 00 00 00 8B 44 24 0C EB 03 83 C8 FF 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_closedir_ce9e5257be66082dcb15c36cb8455275 {
	meta:
		aliases = "closedir, __GI_closedir"
		size = "112"
		objfiles = "closedir@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 7C 24 20 83 3F FF 75 10 E8 ?? ?? ?? ?? C7 00 09 00 00 00 83 C8 FF EB 4A 53 8D 5F 18 53 68 ?? ?? ?? ?? 8D 74 24 0C 56 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 1F C7 07 FF FF FF FF 5A 59 6A 01 56 E8 ?? ?? ?? ?? 58 FF 77 0C E8 ?? ?? ?? ?? 89 3C 24 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule readtcp_60e98d4678a39ba202ac871c2c819611 {
	meta:
		aliases = "readtcp"
		size = "126"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 7C 24 20 8B 1F 8D 74 24 08 89 5C 24 08 66 C7 44 24 0C 01 00 50 68 B8 88 00 00 6A 01 56 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 74 06 85 C0 74 36 EB 0A E8 ?? ?? ?? ?? 83 38 04 EB 0B 0F BF 44 24 0E A8 18 75 21 A8 20 75 1D F6 44 24 0E 01 74 BB 50 FF 74 24 2C FF 74 24 2C 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 7F 0C 8B 47 2C C7 00 00 00 00 00 83 C8 FF 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule putchar_40f6cb3d66d87488507d15235d2a5504 {
	meta:
		aliases = "putchar"
		size = "148"
		objfiles = "putchar@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 7C 24 20 8B 35 ?? ?? ?? ?? 83 7E 34 00 74 22 8B 46 10 3B 46 1C 73 0D 89 FA 88 10 0F B6 DA 40 89 46 10 EB 60 53 53 56 57 E8 ?? ?? ?? ?? 89 C3 EB 50 51 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 46 10 83 C4 10 3B 46 1C 73 0D 89 FA 88 10 0F B6 DA 40 89 46 10 EB 0E 52 52 56 57 E8 ?? ?? ?? ?? 89 C3 83 C4 10 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule ptrace_2f1cab921647817e4cd1b9c1ddab509d {
	meta:
		aliases = "ptrace"
		size = "115"
		objfiles = "ptrace@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 7C 24 20 8B 4C 24 24 8B 54 24 28 8D 44 24 30 89 44 24 08 8B 74 24 2C 8D 47 FF 83 F8 02 77 04 8D 74 24 0C 53 89 FB B8 1A 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DB 89 18 83 CB FF EB 1E 85 C0 78 1A 85 FF 74 16 83 FF 03 77 11 E8 ?? ?? ?? ?? C7 00 00 00 00 00 8B 44 24 0C EB 02 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule putc_82f0145acafa4972f0b86a77fbcaec6f {
	meta:
		aliases = "__GI_fputc, fputc, __GI_putc, putc"
		size = "146"
		objfiles = "fputc@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 7C 24 20 8B 74 24 24 83 7E 34 00 74 22 8B 46 10 3B 46 1C 73 0D 89 FA 88 10 0F B6 DA 40 89 46 10 EB 60 53 53 56 57 E8 ?? ?? ?? ?? 89 C3 EB 50 51 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 46 10 83 C4 10 3B 46 1C 73 0D 89 FA 88 10 0F B6 DA 40 89 46 10 EB 0E 52 52 56 57 E8 ?? ?? ?? ?? 89 C3 83 C4 10 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule readahead_77f7a041298f989075f4f2d7b4be9fc0 {
	meta:
		aliases = "readahead"
		size = "86"
		objfiles = "readahead@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 7C 24 20 8B 74 24 2C 8B 44 24 24 8B 54 24 28 89 D0 89 C2 C1 FA 1F 89 44 24 08 89 54 24 0C 8B 4C 24 08 8B 54 24 24 53 89 FB B8 E1 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule encrypt_d599bb08654b619850349d2318633ac5 {
	meta:
		aliases = "encrypt"
		size = "156"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 7C 24 20 E8 ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? 89 F9 31 DB EB 24 C7 44 9C 08 00 00 00 00 31 D2 EB 12 F6 01 01 74 0B 8B 04 95 ?? ?? ?? ?? 09 44 9C 08 41 42 83 FA 1F 7E E9 43 83 FB 01 7E D7 83 7C 24 24 01 19 DB 83 E3 02 4B 8D 4C 24 08 8B 54 24 0C 8B 44 24 08 53 8D 5C 24 10 53 E8 ?? ?? ?? ?? 31 DB 58 5A EB 1A 89 CA 09 F2 8B 44 9C 08 85 04 8D ?? ?? ?? ?? 0F 95 04 17 41 83 F9 1F 7E E7 43 83 FB 01 7F 09 31 C9 89 DE C1 E6 05 EB D8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __dl_iterate_phdr_d977e78ce6fa39deee2f96dfaadd9b2f {
	meta:
		aliases = "__GI___dl_iterate_phdr, __dl_iterate_phdr"
		size = "85"
		objfiles = "dl_iterate_phdr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 7C 24 24 8B 1D ?? ?? ?? ?? 31 C0 89 E6 EB 34 8B 03 89 04 24 8B 43 04 89 44 24 04 8B 83 D0 00 00 00 89 44 24 08 8B 83 CC 00 00 00 66 89 44 24 0C 50 57 6A 10 56 FF 54 24 30 83 C4 10 85 C0 75 07 8B 5B 0C 85 DB 75 C8 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __libc_lseek64_662286542f76d029e94223665fff5775 {
	meta:
		aliases = "lseek64, __GI_lseek64, __libc_lseek64"
		size = "93"
		objfiles = "llseek@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8B 7C 24 2C 8B 4C 24 24 8B 5C 24 28 89 D9 89 CB C1 FB 1F 8D 74 24 08 8B 44 24 20 8B 54 24 24 53 89 C3 B8 8C 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF EB 04 85 C0 74 03 99 EB 08 8B 44 24 08 8B 54 24 0C 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_reap_children_94dfdd26e9354e4aa88fe7c8d1a8f35c {
	meta:
		aliases = "pthread_reap_children"
		size = "245"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 10 8D 7C 24 0C E9 C6 00 00 00 8B 0D ?? ?? ?? ?? 8B 31 EB 74 39 46 14 8B 16 75 6B 8B 46 04 89 42 04 8B 46 04 89 10 8B 46 1C 31 D2 E8 ?? ?? ?? ?? C6 46 2E 01 83 BE 9C 01 00 00 00 74 2B A1 ?? ?? ?? ?? 0B 86 A0 01 00 00 F6 C4 08 74 1B C7 86 A8 01 00 00 0C 00 00 00 89 B6 AC 01 00 00 89 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 5E 2D 83 EC 0C FF 76 1C E8 ?? ?? ?? ?? 83 C4 10 84 DB 74 0F 89 F0 E8 ?? ?? ?? ?? EB 06 89 D6 39 CE 75 88 83 3D ?? ?? ?? ?? 00 74 12 A1 ?? ?? ?? ?? 8B 10 39 C2 75 07 89 D0 E8 ?? ?? ?? ?? 8B 4C 24 0C 88 C8 83 E0 7F 40 D0 F8 84 C0 7E 19 83 E1 7F BA 01 00 00 00 89 C8 E8 ?? }
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

rule seekdir_d2e9243c847e2c944326ab4eb2265bf9 {
	meta:
		aliases = "seekdir"
		size = "87"
		objfiles = "seekdir@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 14 8B 5C 24 24 8D 73 18 56 68 ?? ?? ?? ?? 8D 7C 24 0C 57 E8 ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 83 C4 0C 6A 00 FF 74 24 2C FF 33 E8 ?? ?? ?? ?? 89 43 10 C7 43 04 00 00 00 00 C7 43 08 00 00 00 00 58 5A 6A 01 57 E8 ?? ?? ?? ?? 83 C4 20 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_asctime_r_bfcbbfe8045804f5fa4e067aba6e3cf4 {
	meta:
		aliases = "asctime_r, __GI_asctime_r"
		size = "214"
		objfiles = "asctime_r@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 14 8B 74 24 24 8B 5C 24 28 6A 1A 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 8B 46 18 83 C4 10 83 F8 06 77 15 51 6A 03 8D 04 40 05 ?? ?? ?? ?? 50 53 E8 ?? ?? ?? ?? 83 C4 10 8B 46 10 83 F8 0B 77 18 52 6A 03 8D 04 40 05 ?? ?? ?? ?? 50 8D 43 04 50 E8 ?? ?? ?? ?? 83 C4 10 8D 4B 13 8B 56 14 81 C2 6C 07 00 00 81 FA 0F 27 00 00 77 1A 8D 4B 17 BB 0A 00 00 00 89 D0 99 F7 FB 83 C2 30 88 11 89 C2 49 80 39 3F 74 E9 8D 59 FF 0F BE 41 FF 8B 14 06 83 FA 63 76 0A C6 41 FF 3F C6 43 FF 3F EB 17 BF 0A 00 00 00 89 D0 99 F7 FF 89 44 24 0C 83 C2 30 88 51 FF 00 41 FE 8D 4B FE 80 79 FE 30 74 C7 80 7B FF 30 75 04 }
	condition:
		$pattern
}

rule localtime_r_dbc70031f9e99d21d84f741235ef5e46 {
	meta:
		aliases = "__GI_localtime_r, localtime_r"
		size = "99"
		objfiles = "localtime_r@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 14 8B 74 24 24 8B 7C 24 28 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 5C 24 0C 53 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 81 3E FF 4E 98 45 0F 9E C0 89 04 24 E8 ?? ?? ?? ?? 83 C4 0C 68 ?? ?? ?? ?? 57 56 E8 ?? ?? ?? ?? 58 5A 6A 01 53 E8 ?? ?? ?? ?? 89 F8 83 C4 20 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_lockf_d73305bbe3e9dc743efa74947051c424 {
	meta:
		aliases = "lockf, __GI_lockf"
		size = "217"
		objfiles = "lockf@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 14 8B 7C 24 24 8B 5C 24 28 6A 10 6A 00 8D 74 24 0C 56 E8 ?? ?? ?? ?? 66 C7 44 24 12 01 00 C7 44 24 14 00 00 00 00 8B 44 24 38 89 44 24 18 83 C4 10 83 FB 01 74 55 7F 06 85 DB 74 47 EB 67 83 FB 02 74 55 83 FB 03 75 5D 66 C7 04 24 00 00 52 56 6A 05 57 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 69 66 83 3C 24 02 74 60 8B 5C 24 0C E8 ?? ?? ?? ?? 39 C3 74 53 E8 ?? ?? ?? ?? C7 00 0D 00 00 00 EB 2D 66 C7 04 24 02 00 EB 13 66 C7 04 24 01 00 BA 07 00 00 00 EB 1D 66 C7 04 24 01 00 BA 06 00 00 00 EB 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CA FF EB 16 50 8D 44 24 04 50 52 57 E8 ?? ?? ?? ?? 89 }
	condition:
		$pattern
}

rule __GI_getpwent_r_55330fa262cb426b61ec2bf4b987d33f {
	meta:
		aliases = "__GI_getgrent_r, getspent_r, __GI_getspent_r, getgrent_r, getpwent_r, __GI_getpwent_r"
		size = "171"
		objfiles = "getspent_r@libc.a, getpwent_r@libc.a, getgrent_r@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 14 8B 7C 24 24 8B 74 24 30 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 0C 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 06 00 00 00 00 83 C4 10 83 3D ?? ?? ?? ?? 00 75 2D 52 52 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 10 85 C0 75 09 E8 ?? ?? ?? ?? 8B 18 EB 2E C7 40 34 01 00 00 00 83 EC 0C FF 35 ?? ?? ?? ?? FF 74 24 38 FF 74 24 38 57 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 83 C4 20 85 C0 75 02 89 3E 50 50 6A 01 8D 44 24 0C 50 E8 ?? ?? ?? ?? 89 D8 83 C4 20 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_round_19f188d9033b4f2d1bd37e025b756960 {
	meta:
		aliases = "round, __GI_round"
		size = "289"
		objfiles = "s_round@libm.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 18 C7 44 24 08 00 00 00 00 C7 44 24 0C 00 00 00 00 DD 44 24 28 DD 14 24 DD 54 24 10 8B 74 24 14 8B 54 24 10 89 F0 C1 F8 14 25 FF 07 00 00 8D 98 01 FC FF FF 83 FB 13 7F 74 85 DB 79 31 DD 05 ?? ?? ?? ?? DE C1 D9 EE D9 C9 DA E9 DF E0 9E 0F 86 AF 00 00 00 81 E6 00 00 00 80 31 D2 43 0F 85 A0 00 00 00 81 CE 00 00 F0 3F E9 95 00 00 00 DD D8 BF FF FF 0F 00 88 D9 D3 FF 89 F8 21 F0 09 D0 0F 84 8D 00 00 00 DD 04 24 DC 05 ?? ?? ?? ?? D9 EE D9 C9 DA E9 DF E0 9E 76 6A 89 FA F7 D2 B8 00 00 08 00 D3 F8 8D 34 30 21 D6 31 D2 EB 56 DD D8 83 FB 33 7E 0F 81 FB 00 04 00 00 75 56 DD 04 24 D8 C0 EB 4C }
	condition:
		$pattern
}

rule pthread_rwlock_rdlock_6323ac9ab993abf4d6def2cfbd5475c6 {
	meta:
		aliases = "pthread_rwlock_rdlock"
		size = "178"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 1C 8B 5C 24 2C C7 44 24 18 00 00 00 00 8D 4C 24 14 8D 44 24 18 8D 54 24 10 52 89 DA E8 ?? ?? ?? ?? 89 C6 83 C4 10 8D 7B 10 83 7C 24 0C 00 75 09 E8 ?? ?? ?? ?? 89 44 24 0C 8B 54 24 0C 89 D8 E8 ?? ?? ?? ?? 89 F2 89 D8 E8 ?? ?? ?? ?? 85 C0 75 22 8B 54 24 0C 89 F8 E8 ?? ?? ?? ?? 83 EC 0C 53 E8 ?? ?? ?? ?? 8B 44 24 1C E8 ?? ?? ?? ?? 83 C4 10 EB B6 FF 43 08 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 F6 75 07 83 7C 24 04 00 74 17 8B 44 24 08 85 C0 74 05 FF 40 08 EB 0A 8B 44 24 0C FF 80 C8 01 00 00 31 C0 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule marshal_new_auth_3d17000175eb69ec1ed12269b93a1122 {
	meta:
		aliases = "marshal_new_auth"
		size = "138"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 20 89 C3 8B 78 24 6A 00 68 90 01 00 00 8D 47 1C 50 8D 74 24 14 56 E8 ?? ?? ?? ?? 59 58 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 13 52 52 8D 43 0C 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 0F 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 11 83 EC 0C 56 8B 44 24 1C FF 50 10 89 87 AC 01 00 00 83 C4 10 8B 44 24 0C 8B 50 1C 85 D2 74 0D 83 EC 0C 8D 44 24 14 50 FF D2 83 C4 10 B8 01 00 00 00 83 C4 20 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __old_sem_post_ddeff629af11885164cba9c6a8cf66eb {
	meta:
		aliases = "__old_sem_post"
		size = "167"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 20 8B 4C 24 30 8B 11 89 D7 83 E7 01 75 07 BE 03 00 00 00 EB 1B 81 FA FF FF FF 7F 75 10 E8 ?? ?? ?? ?? C7 00 22 00 00 00 83 C8 FF EB 6E 8D 72 02 89 D0 F0 0F B1 31 0F 94 C3 84 DB 74 C8 85 FF 75 58 89 D1 C7 44 24 1C 00 00 00 00 8D 7C 24 1C EB 1F 8B 71 08 89 FB EB 03 8D 5A 08 8B 13 85 D2 74 08 8B 41 18 3B 42 18 7C EF 89 51 08 89 0B 89 F1 83 F9 01 75 DC EB 1A 8B 42 08 89 44 24 1C C7 42 08 00 00 00 00 83 EC 0C 52 E8 ?? ?? ?? ?? 83 C4 10 8B 54 24 1C 85 D2 75 DE 31 C0 83 C4 20 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __pthread_alt_lock_133079313320dbab7b171d98177ebcd3 {
	meta:
		aliases = "__pthread_alt_lock"
		size = "89"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 20 8B 74 24 30 8B 54 24 34 8D 7C 24 14 8B 1E B9 01 00 00 00 85 DB 74 11 85 D2 75 07 E8 ?? ?? ?? ?? 89 C2 89 54 24 18 89 F9 C7 44 24 1C 00 00 00 00 89 5C 24 14 89 D8 F0 0F B1 0E 0F 94 C1 84 C9 74 CB 85 DB 74 07 89 D0 E8 ?? ?? ?? ?? 83 C4 20 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_ftello64_d7fe2d2ca6607a4834f73ce1631ba010 {
	meta:
		aliases = "ftello64, __GI_ftello64"
		size = "172"
		objfiles = "ftello64@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 20 8B 74 24 30 C7 44 24 18 00 00 00 00 C7 44 24 1C 00 00 00 00 8B 7E 34 85 FF 75 1F 53 8D 5E 38 53 68 ?? ?? ?? ?? 8D 44 24 14 50 E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 83 C4 10 0F B7 06 25 40 04 00 00 3D 40 04 00 00 0F 94 C0 0F B6 C0 40 51 50 8D 5C 24 20 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 10 52 52 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 10 C7 44 24 18 FF FF FF FF C7 44 24 1C FF FF FF FF 85 FF 75 11 50 50 6A 01 8D 44 24 14 50 E8 ?? ?? ?? ?? 83 C4 10 8B 44 24 18 8B 54 24 1C 83 C4 20 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pmap_getport_58073625b7c9cc57895c66a7e43d5a48 {
	meta:
		aliases = "__GI_pmap_getport, pmap_getport"
		size = "239"
		objfiles = "pm_getport@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 20 8B 7C 24 30 66 C7 44 24 1E 00 00 C7 44 24 18 FF FF FF FF 66 C7 47 02 00 6F 68 90 01 00 00 68 90 01 00 00 8D 44 24 20 50 FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 6A 02 68 A0 86 01 00 57 E8 ?? ?? ?? ?? 89 C3 83 C4 20 85 C0 0F 84 89 00 00 00 E8 ?? ?? ?? ?? 89 C6 8B 44 24 34 89 44 24 08 8B 44 24 38 89 44 24 0C 8B 44 24 3C 89 44 24 10 C7 44 24 14 00 00 00 00 8D 44 24 1E 8D 54 24 08 8B 4B 04 FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? 6A 03 53 FF 11 83 C4 20 85 C0 74 18 C7 06 0E 00 00 00 50 50 8B 53 04 8D 46 04 50 53 FF 52 08 83 C4 10 EB 0E 66 83 7C 24 1E 00 }
	condition:
		$pattern
}

rule __GI_authnone_create_ffea37ecd0a4cb9f204c39c3dd3e05da {
	meta:
		aliases = "authnone_create, __GI_authnone_create"
		size = "177"
		objfiles = "auth_none@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 20 E8 ?? ?? ?? ?? 89 C3 8B B0 98 00 00 00 85 F6 75 1C 50 50 6A 40 6A 01 E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 74 7D 89 C6 89 83 98 00 00 00 83 7E 3C 00 75 6D 8D 5E 0C 50 6A 0C 68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 83 C4 0C 6A 0C 53 56 E8 ?? ?? ?? ?? C7 46 20 ?? ?? ?? ?? 6A 00 6A 14 8D 46 28 50 8D 7C 24 24 57 E8 ?? ?? ?? ?? 83 C4 18 56 57 E8 ?? ?? ?? ?? 59 58 53 57 E8 ?? ?? ?? ?? 89 3C 24 8B 44 24 1C FF 50 10 89 46 3C 8B 44 24 1C 8B 40 1C 83 C4 10 85 C0 74 09 83 EC 0C 57 FF D0 83 C4 10 89 F2 89 D0 83 C4 20 5B 5E 5F C3 }
	condition:
		$pattern
}

rule if_indextoname_a30a467d14504d7256a3f10f0378979b {
	meta:
		aliases = "if_indextoname"
		size = "119"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 20 E8 ?? ?? ?? ?? 89 C6 31 C0 85 F6 78 5D 8B 44 24 30 89 44 24 10 50 8D 5C 24 04 53 68 10 89 00 00 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 22 E8 ?? ?? ?? ?? 89 C7 8B 18 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 83 FB 13 75 02 B3 06 89 1F 31 C0 EB 1B 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 0C 6A 10 53 FF 74 24 40 E8 ?? ?? ?? ?? 83 C4 10 83 C4 20 5B 5E 5F C3 }
	condition:
		$pattern
}

rule if_nametoindex_ce164ff771686f826dabbea381a7b6d4 {
	meta:
		aliases = "__GI_if_nametoindex, if_nametoindex"
		size = "117"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 20 E8 ?? ?? ?? ?? 89 C6 85 C0 78 5B 52 6A 10 FF 74 24 38 8D 5C 24 0C 53 E8 ?? ?? ?? ?? 83 C4 0C 53 68 33 89 00 00 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 22 E8 ?? ?? ?? ?? 89 C7 8B 18 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 83 FB 16 75 1A C7 07 26 00 00 00 EB 12 83 EC 0C 56 E8 ?? ?? ?? ?? 8B 44 24 20 83 C4 10 EB 02 31 C0 83 C4 20 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pclose_460ff3dfa4557aa7d844a2bfcf1f0c21 {
	meta:
		aliases = "pclose"
		size = "190"
		objfiles = "popen@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 24 8B 7C 24 34 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 83 C4 10 85 DB 74 2C 39 7B 04 75 09 8B 03 A3 ?? ?? ?? ?? EB 1E 89 DA 8B 1B 85 DB 75 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 09 39 7B 04 75 E6 8B 03 89 02 52 52 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 10 85 DB 74 3C 8B 73 08 83 EC 0C 53 E8 ?? ?? ?? ?? 89 3C 24 E8 ?? ?? ?? ?? 83 C4 10 8D 5C 24 1C 50 6A 00 53 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 06 8B 44 24 1C EB 0D E8 ?? ?? ?? ?? 83 38 04 74 DF 83 C8 FF 83 C4 20 5B 5E 5F C3 }
	condition:
		$pattern
}

rule readunix_f2f5a59c16b464b5c2c19abc2fe18183 {
	meta:
		aliases = "readunix"
		size = "270"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 30 8B 7C 24 40 8B 1F 8D 74 24 24 89 5C 24 24 66 C7 44 24 28 01 00 50 68 B8 88 00 00 6A 01 56 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 74 0A 85 C0 0F 84 C2 00 00 00 EB 0A E8 ?? ?? ?? ?? 83 38 04 EB 0F 0F BF 44 24 2A A8 18 0F 85 A9 00 00 00 A8 20 0F 85 A1 00 00 00 F6 44 24 2A 01 74 AF 8B 44 24 44 89 44 24 1C 8B 44 24 48 89 44 24 20 8D 44 24 1C 89 44 24 08 C7 44 24 0C 01 00 00 00 C7 04 24 00 00 00 00 C7 44 24 04 00 00 00 00 C7 44 24 10 ?? ?? ?? ?? C7 44 24 14 1C 00 00 00 C7 44 24 18 00 00 00 00 C7 44 24 2C 01 00 00 00 83 EC 0C 6A 04 8D 44 24 3C 50 6A 10 6A 01 53 E8 ?? ?? ?? ?? 83 C4 20 85 }
	condition:
		$pattern
}

rule clntraw_create_d1b31628168fb7302960a817b2a8d580 {
	meta:
		aliases = "clntraw_create"
		size = "231"
		objfiles = "clnt_raw@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 30 E8 ?? ?? ?? ?? 89 C6 8B 98 A0 00 00 00 89 DF 85 DB 75 23 51 51 68 A0 22 00 00 6A 01 E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 0F 84 AA 00 00 00 89 C7 89 86 A0 00 00 00 8D 73 0C C7 44 24 04 00 00 00 00 C7 44 24 08 02 00 00 00 8B 44 24 40 89 44 24 0C 8B 44 24 44 89 44 24 10 6A 00 6A 18 8D 87 84 22 00 00 50 56 E8 ?? ?? ?? ?? 58 5A 8D 44 24 08 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 10 83 EC 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 EC 0C 8B 43 10 56 FF 50 10 89 87 9C 22 00 00 8B 43 10 8B 40 1C 83 C4 10 85 C0 74 09 83 EC 0C 56 FF D0 83 C4 10 6A 02 68 60 22 00 00 8D 47 24 50 56 E8 ?? }
	condition:
		$pattern
}

rule pmap_rmtcall_c2e8ce443e2d5b5e4c09dd75b051bfbe {
	meta:
		aliases = "pmap_rmtcall"
		size = "198"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 38 8B 7C 24 48 C7 44 24 34 FF FF FF FF 66 C7 47 02 00 6F 8D 44 24 34 50 FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 6A 02 68 A0 86 01 00 57 E8 ?? ?? ?? ?? 89 C3 83 C4 20 BE 10 00 00 00 85 C0 74 73 8B 44 24 44 89 44 24 04 8B 44 24 48 89 44 24 08 8B 44 24 4C 89 44 24 0C 8B 44 24 54 89 44 24 14 8B 44 24 50 89 44 24 18 8B 44 24 68 89 44 24 1C 8B 44 24 5C 89 44 24 24 8B 44 24 58 89 44 24 28 8D 44 24 1C 8D 54 24 04 8B 4B 04 FF 74 24 64 FF 74 24 64 50 68 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? 6A 05 53 FF 11 89 C6 83 C4 14 8B 43 04 53 FF 50 10 83 C4 10 66 C7 47 02 00 00 89 F0 83 C4 30 5B 5E 5F C3 }
	condition:
		$pattern
}

rule rint_a2c84a0b3529e2a514e6dce1ea67581a {
	meta:
		aliases = "__GI_rint, rint"
		size = "330"
		objfiles = "s_rint@libm.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 38 C7 44 24 08 00 00 00 00 C7 44 24 0C 00 00 00 00 DD 44 24 48 DD 14 24 DD 54 24 28 8B 5C 24 2C 8B 74 24 28 89 DF C1 EF 1F 89 D8 C1 F8 14 25 FF 07 00 00 8D 88 01 FC FF FF 83 F9 13 0F 8F A3 00 00 00 85 C9 79 69 89 D8 25 FF FF FF 7F 09 F0 0F 84 E4 00 00 00 89 DA 81 E2 FF FF 0F 00 09 F2 DD 5C 24 20 89 D0 F7 D8 09 D0 C1 E8 0C 25 00 00 08 00 81 E3 00 00 FE FF 09 D8 89 44 24 24 DD 04 FD ?? ?? ?? ?? DD 44 24 20 D8 C1 DE E1 DD 54 24 18 DD 5C 24 10 C1 E7 1F 8B 44 24 1C 25 FF FF FF 7F 09 C7 89 7C 24 14 DD 44 24 10 E9 85 00 00 00 DD D8 BA FF FF 0F 00 D3 FA 89 D0 21 D8 09 F0 74 7B D1 EA 89 }
	condition:
		$pattern
}

rule __form_query_96baadd8b95ddb027121b3aae7659198 {
	meta:
		aliases = "__form_query"
		size = "128"
		objfiles = "formquery@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 44 8B 7C 24 60 8B 74 24 64 6A 30 6A 00 8D 5C 24 10 53 E8 ?? ?? ?? ?? 8B 44 24 60 89 44 24 14 C7 44 24 34 01 00 00 00 8B 44 24 64 89 44 24 44 8B 44 24 68 89 44 24 48 C7 44 24 4C 01 00 00 00 83 C4 0C 56 57 53 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 78 1F 50 29 DE 56 8D 04 1F 50 8D 44 24 40 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 04 89 C3 EB 02 01 C3 89 D8 83 C4 40 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __ieee754_jn_de6774a195e28597980d8efb016aa9d4 {
	meta:
		aliases = "__ieee754_jn"
		size = "955"
		objfiles = "e_jn@libm.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 50 8B 74 24 60 DD 44 24 64 DD 54 24 18 DD 54 24 20 8B 7C 24 24 8B 54 24 20 89 FB 81 E3 FF FF FF 7F 89 D0 F7 D8 09 D0 C1 E8 1F 09 D8 3D 00 00 F0 7F 76 09 D9 C0 DE C1 E9 73 03 00 00 DD D8 83 FE 00 7D 14 F7 DE DD 44 24 18 D9 E0 DD 5C 24 18 81 EF 00 00 00 80 EB 15 75 13 DD 44 24 18 DD 5C 24 60 83 C4 50 5B 5E 5F E9 ?? ?? ?? ?? 83 FE 01 75 13 DD 44 24 18 DD 5C 24 60 83 C4 50 5B 5E 5F E9 ?? ?? ?? ?? 09 DA 0F 84 18 03 00 00 81 FB FF FF EF 7F 0F 8F 0C 03 00 00 50 50 FF 74 24 24 FF 74 24 24 E8 ?? ?? ?? ?? 83 C4 10 DD 5C 24 48 56 DB 04 24 83 C4 04 DD 54 24 28 DD 44 24 48 DA E9 DF E0 9E 0F }
	condition:
		$pattern
}

rule __GI_modf_a202645b8bfc1188ffe6a1e5544d854f {
	meta:
		aliases = "modf, __GI_modf"
		size = "400"
		objfiles = "s_modf@libm.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 58 C7 44 24 48 00 00 00 00 C7 44 24 4C 00 00 00 00 C7 44 24 38 00 00 00 00 C7 44 24 3C 00 00 00 00 C7 44 24 30 00 00 00 00 C7 44 24 34 00 00 00 00 C7 44 24 20 00 00 00 00 C7 44 24 24 00 00 00 00 C7 44 24 10 00 00 00 00 C7 44 24 14 00 00 00 00 C7 44 24 08 00 00 00 00 C7 44 24 0C 00 00 00 00 DD 44 24 68 DD 14 24 8B 7C 24 70 DD 5C 24 50 8B 5C 24 54 8B 74 24 50 89 D8 C1 F8 14 25 FF 07 00 00 8D 88 01 FC FF FF 83 F9 13 7F 78 85 C9 79 1D 81 E3 00 00 00 80 89 5C 24 4C C7 44 24 48 00 00 00 00 DD 44 24 48 DD 1F E9 D3 00 00 00 BA FF FF 0F 00 D3 FA 89 D0 21 D8 09 F0 75 27 DD 04 24 DD 17 DD }
	condition:
		$pattern
}

rule vsnprintf_f255c6ff5934a5d501527e392f3bbbca {
	meta:
		aliases = "__GI_vsnprintf, vsnprintf"
		size = "167"
		objfiles = "vsnprintf@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 5C 8B 74 24 6C C7 44 24 10 FE FF FF FF 66 C7 44 24 0C D0 00 C6 44 24 0E 00 C7 44 24 38 00 00 00 00 C7 44 24 40 01 00 00 00 8D 7C 24 0C 8D 44 24 44 50 E8 ?? ?? ?? ?? C7 44 24 30 00 00 00 00 89 F0 F7 D0 83 C4 10 8B 5C 24 64 39 C3 76 02 89 C3 89 74 24 08 8D 04 1E 89 44 24 0C 89 74 24 10 89 74 24 14 89 74 24 18 89 44 24 1C 50 FF 74 24 70 FF 74 24 70 57 E8 ?? ?? ?? ?? 89 C2 83 C4 10 85 DB 74 16 8B 44 24 10 3B 44 24 0C 75 05 48 89 44 24 10 8B 44 24 10 C6 00 00 89 D0 83 C4 50 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pathconf_f2e0ef9e84a731e89211e8d26fd4fcc4 {
	meta:
		aliases = "pathconf"
		size = "201"
		objfiles = "pathconf@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 60 8B 74 24 70 8B 44 24 74 80 3E 00 75 10 E8 ?? ?? ?? ?? C7 00 02 00 00 00 E9 8E 00 00 00 83 F8 13 77 11 FF 24 85 ?? ?? ?? ?? B8 20 00 00 00 E9 89 00 00 00 E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 6B B8 7F 00 00 00 EB 75 E8 ?? ?? ?? ?? 89 C3 8B 38 52 52 8D 44 24 10 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 09 83 3B 26 75 42 89 3B EB 37 8B 44 24 2C EB 49 31 C0 EB 45 50 50 8D 44 24 10 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 20 8B 44 24 18 25 00 F0 00 00 3D 00 80 00 00 74 1C 3D 00 60 00 00 75 09 EB 13 B8 FF 00 00 00 EB 11 83 C8 FF EB 0C B8 00 10 00 00 EB 05 B8 01 00 00 00 83 C4 60 5B 5E 5F }
	condition:
		$pattern
}

rule fpathconf_53ea0168d030790291fa6efc20275ee8 {
	meta:
		aliases = "fpathconf"
		size = "209"
		objfiles = "fpathconf@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 60 8B 74 24 70 8B 54 24 74 85 F6 79 10 E8 ?? ?? ?? ?? C7 00 09 00 00 00 E9 97 00 00 00 B8 7F 00 00 00 85 D2 0F 84 9B 00 00 00 8D 42 FF 83 F8 12 77 11 FF 24 85 ?? ?? ?? ?? B8 20 00 00 00 E9 82 00 00 00 E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 64 E8 ?? ?? ?? ?? 89 C3 8B 38 52 52 8D 44 24 10 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 09 83 3B 26 75 42 89 3B EB 37 8B 44 24 2C EB 49 31 C0 EB 45 50 50 8D 44 24 10 50 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 20 8B 44 24 18 25 00 F0 00 00 3D 00 80 00 00 74 1C 3D 00 60 00 00 75 09 EB 13 B8 FF 00 00 00 EB 11 83 C8 FF EB 0C B8 00 10 00 00 EB 05 B8 01 00 }
	condition:
		$pattern
}

rule erfc_1553515862e9baffdca632f2af0de998 {
	meta:
		aliases = "__GI_erfc, erfc"
		size = "891"
		objfiles = "s_erf@libm.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 60 DD 44 24 70 DD 54 24 38 DD 54 24 48 8B 74 24 4C 89 F7 89 F3 81 E3 FF FF FF 7F 81 FB FF FF EF 7F 7E 1D C1 EE 1F 8D 04 36 31 D2 52 50 DF 2C 24 D9 C9 83 C4 08 DC 3D ?? ?? ?? ?? E9 5D 01 00 00 DD D8 81 FB FF FF EA 3F 0F 8F A8 00 00 00 81 FB FF FF 6F 3C 7F 0F DD 44 24 38 DC 2D ?? ?? ?? ?? E9 0A 03 00 00 DD 44 24 38 D8 C8 DD 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? DD 05 ?? ?? ?? ?? D8 CA DC 05 ?? ?? ?? ?? D8 CA DC 05 ?? ?? ?? ?? D8 CA DC 05 ?? ?? ?? ?? D8 CA DC 05 ?? ?? ?? ?? DE CA D9 E8 DC C2 D9 C9 DE F2 D9 C9 }
	condition:
		$pattern
}

rule __GI_opendir_1b6ed033a8bbdec1190b95c18395bf28 {
	meta:
		aliases = "opendir, __GI_opendir"
		size = "142"
		objfiles = "opendir@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 68 68 00 08 01 00 FF 74 24 7C E8 ?? ?? ?? ?? 89 C7 83 C4 10 31 DB 85 C0 78 66 53 53 8D 44 24 10 50 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 12 51 6A 01 6A 02 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 18 E8 ?? ?? ?? ?? 89 C3 8B 30 83 EC 0C 57 E8 ?? ?? ?? ?? 89 33 31 DB EB 25 8B 54 24 38 89 F8 E8 ?? ?? ?? ?? 89 C3 85 C0 75 17 83 EC 0C 57 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 0C 00 00 00 83 C4 10 89 D8 83 C4 60 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __ieee754_rem_pio2_c8d87e7ceb8e7453f8103dee73930eff {
	meta:
		aliases = "__ieee754_rem_pio2"
		size = "736"
		objfiles = "e_rem_pio2@libm.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 83 EC 70 DD 84 24 80 00 00 00 DD 14 24 8B B4 24 88 00 00 00 DD 54 24 30 8B 7C 24 34 89 FB 81 E3 FF FF FF 7F 81 FB FB 21 E9 3F 7F 15 DD 1E C7 46 08 00 00 00 00 C7 46 0C 00 00 00 00 E9 C5 01 00 00 DD D8 81 FB 7B D9 02 40 7F 7E 85 FF 7E 3E DD 04 24 DC 25 ?? ?? ?? ?? 81 FB FB 21 F9 3F 74 08 DD 05 ?? ?? ?? ?? EB 0E DD 05 ?? ?? ?? ?? DE E9 DD 05 ?? ?? ?? ?? D9 C1 D8 E1 DD 16 DE EA DE E9 DD 5E 08 B9 01 00 00 00 E9 47 02 00 00 DD 04 24 DC 05 ?? ?? ?? ?? 81 FB FB 21 F9 3F 74 08 DD 05 ?? ?? ?? ?? EB 0E DD 05 ?? ?? ?? ?? DE C1 DD 05 ?? ?? ?? ?? D9 C1 D8 C1 DD 16 DE EA DE C1 DD 5E 08 83 C9 FF E9 }
	condition:
		$pattern
}

rule trecurse_9104e090ebcc25149b46e1a35e17f2a1 {
	meta:
		aliases = "trecurse"
		size = "95"
		objfiles = "twalk@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 C3 89 D7 89 CE 83 78 04 00 75 0C 83 78 08 00 75 06 50 51 6A 03 EB 3A 51 56 6A 00 53 FF D7 8B 43 04 83 C4 10 85 C0 74 0A 8D 4E 01 89 FA E8 CA FF FF FF 52 56 6A 01 53 FF D7 8B 43 08 83 C4 10 85 C0 74 0A 8D 4E 01 89 FA E8 AF FF FF FF 50 56 6A 02 53 FF D7 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule do_close_39755c09ba26fb1becc5b79ffe9ca18e {
	meta:
		aliases = "do_close"
		size = "32"
		objfiles = "rtime@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 C3 E8 ?? ?? ?? ?? 89 C6 8B 38 83 EC 0C 53 E8 ?? ?? ?? ?? 89 3E 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_kill_all_threads_612394b4d45bbf7922d18f4877c31e9b {
	meta:
		aliases = "pthread_kill_all_threads"
		size = "62"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 C6 89 D7 A1 ?? ?? ?? ?? 8B 18 EB 10 51 51 56 FF 73 14 E8 ?? ?? ?? ?? 8B 1B 83 C4 10 3B 1D ?? ?? ?? ?? 75 E8 85 FF 74 0E 52 52 56 FF 73 14 E8 ?? ?? ?? ?? 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __getutid_8ed3069b5eec795b03c6c022689343e1 {
	meta:
		aliases = "__getutid"
		size = "92"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 C6 8D 78 28 EB 3C 8B 16 8D 42 FF 66 83 F8 03 77 05 66 39 13 74 3C 66 83 FA 05 74 12 66 83 FA 08 74 0C 66 83 FA 06 74 06 66 83 FA 07 75 14 51 6A 04 57 8D 43 28 50 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 10 A1 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C3 85 C0 75 B4 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __rt_sigtimedwait_e4944706a54a98f9e63fd0a880038930 {
	meta:
		aliases = "__rt_sigtimedwait"
		size = "52"
		objfiles = "__rt_sigtimedwait@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 C7 89 D3 89 CA 8B 74 24 10 89 D9 53 89 FB B8 B1 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5B 5E 5F C3 }
	condition:
		$pattern
}

rule byte_insert_op1_0c4b250f2f4eb8212fe922f4261aa4e2 {
	meta:
		aliases = "byte_insert_op1"
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
		size = "48"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 C7 89 D3 89 CE E8 ?? ?? ?? ?? 8B 80 B8 00 00 00 31 D2 EB 0E 39 78 04 75 05 39 58 08 74 08 89 C2 8B 00 85 C0 75 EE 89 16 5B 5E 5F C3 }
	condition:
		$pattern
}

rule fd_to_DIR_29fb03f959452a7b646942b307bec3c4 {
	meta:
		aliases = "fd_to_DIR"
		size = "126"
		objfiles = "opendir@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 C7 89 D6 83 EC 0C 6A 30 E8 ?? ?? ?? ?? 83 C4 10 31 DB 85 C0 74 5E 89 C3 89 38 C7 40 10 00 00 00 00 C7 40 08 00 00 00 00 C7 40 04 00 00 00 00 89 70 14 81 FE FF 01 00 00 77 07 C7 40 14 00 02 00 00 52 52 FF 73 14 6A 01 E8 ?? ?? ?? ?? 89 43 0C 83 C4 10 85 C0 75 0D 83 EC 0C 53 E8 ?? ?? ?? ?? 31 DB EB 0D 50 50 6A 00 8D 43 18 50 E8 ?? ?? ?? ?? 83 C4 10 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __get_next_rpcent_bfc93ef39501e9ebf15a6f40e7715233 {
	meta:
		aliases = "__get_next_rpcent"
		size = "256"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 89 C7 8D B0 A8 00 00 00 50 FF 37 68 00 10 00 00 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 0F 84 D8 00 00 00 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 C6 84 07 A7 00 00 00 0A 80 BF A8 00 00 00 23 74 CA 50 50 6A 23 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 11 50 50 6A 0A 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 A8 C6 00 00 89 F0 E8 ?? ?? ?? ?? 85 C0 74 9A C6 00 00 8D 58 01 89 B7 9C 00 00 00 EB 01 43 8A 03 3C 20 74 F9 3C 09 74 F5 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 89 87 A4 00 00 00 8D 77 10 89 B7 A0 00 00 00 89 D8 E8 ?? ?? ?? ?? 31 C9 85 C0 74 2E C6 00 00 8D 48 01 EB 26 80 FA 20 74 1E 80 FA 09 74 19 39 DE 73 05 }
	condition:
		$pattern
}

rule __GI_inet_ntoa_r_66be6476971ad6d10f74f05fcbd35268 {
	meta:
		aliases = "inet_ntoa_r, __GI_inet_ntoa_r"
		size = "79"
		objfiles = "inet_ntoa@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 44 24 10 0F C8 8B 4C 24 14 83 C1 0F 89 C3 31 FF 31 F6 EB 2B 83 EC 0C 6A 00 6A F6 89 D8 25 FF 00 00 00 31 D2 52 50 51 E8 ?? ?? ?? ?? 8D 48 FF 83 C4 20 85 F6 74 03 C6 06 2E C1 EB 08 47 89 CE 83 FF 03 7E D0 8D 41 01 5B 5E 5F C3 }
	condition:
		$pattern
}

rule _dl_run_init_array_181b9e48904b5efcc5a657ff0ed68b3e {
	meta:
		aliases = "_dl_run_init_array"
		size = "49"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 44 24 10 8B 08 8B 90 AC 00 00 00 8B 80 A4 00 00 00 85 C0 74 14 89 D7 C1 EF 02 8D 34 08 31 DB EB 04 FF 14 9E 43 39 FB 72 F8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule re_match_2_39d0234ca65b8ff573355b91e6ea2202 {
	meta:
		aliases = "__re_match_2, re_match_2"
		size = "63"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 44 24 10 8B 54 24 14 8B 4C 24 18 8B 7C 24 1C 8B 74 24 20 8B 5C 24 2C 89 5C 24 20 8B 5C 24 28 89 5C 24 1C 8B 5C 24 24 89 5C 24 18 89 74 24 14 89 7C 24 10 5B 5E 5F E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule dlsym_e2ea7720cfeaa5921bfa2fa0b2dc2fab {
	meta:
		aliases = "dlsym"
		size = "156"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 4C 24 10 85 C9 75 08 8B 15 ?? ?? ?? ?? EB 58 89 CA 83 F9 FF 74 26 3B 0D ?? ?? ?? ?? 74 49 A1 ?? ?? ?? ?? EB 07 39 C8 74 3E 8B 40 04 85 C0 75 F5 C7 05 ?? ?? ?? ?? 09 00 00 00 EB 58 8B 7C 24 0C A1 ?? ?? ?? ?? 31 F6 EB 1A 8B 18 8B 4B 14 39 F9 73 0E 85 F6 74 05 39 4E 14 73 05 8B 50 10 89 DE 8B 40 10 85 C0 75 E2 31 C0 3B 15 ?? ?? ?? ?? 75 02 8B 02 68 00 00 00 80 50 52 FF 74 24 20 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 0A C7 05 ?? ?? ?? ?? 0A 00 00 00 5B 5E 5F C3 }
	condition:
		$pattern
}

rule _dl_parse_dynamic_info_f2e7d357f2093d71607015b26aa64efa {
	meta:
		aliases = "_dl_parse_dynamic_info"
		size = "252"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 54 24 10 8B 5C 24 14 8B 7C 24 18 8B 74 24 1C E9 8E 00 00 00 83 F9 21 7F 58 8B 42 04 89 04 8B 83 3A 15 75 03 89 7A 04 83 3A 18 75 07 C7 43 60 01 00 00 00 83 3A 1E 75 0D F6 42 04 08 74 07 C7 43 60 01 00 00 00 83 3A 16 75 07 C7 43 58 01 00 00 00 83 3A 1D 75 07 C7 43 3C 00 00 00 00 83 3A 0F 75 3D 83 7B 74 00 74 37 C7 43 3C 00 00 00 00 EB 2E 81 F9 FF FF FF 6F 7F 26 81 F9 FA FF FF 6F 75 09 8B 42 04 89 83 88 00 00 00 81 3A FB FF FF 6F 75 0D F6 42 04 01 74 07 C7 43 60 01 00 00 00 83 C2 08 8B 0A 85 C9 0F 85 68 FF FF FF 8B 43 10 85 C0 74 05 01 F0 89 43 10 8B 43 0C 85 C0 74 05 01 F0 89 43 0C }
	condition:
		$pattern
}

rule pthread_rwlock_destroy_4c18465ec0c36c7018cc2d7edbc8e663 {
	meta:
		aliases = "pthread_rwlock_destroy"
		size = "53"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 31 D2 89 D8 E8 ?? ?? ?? ?? 8B 73 08 8B 7B 0C 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 85 F6 7F 06 31 C0 85 FF 74 05 B8 10 00 00 00 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_setspecific_b01d39d2b279c76e65f9d0e49db91bd0 {
	meta:
		aliases = "pthread_setspecific"
		size = "109"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 81 FB FF 03 00 00 77 55 83 3C DD ?? ?? ?? ?? 00 74 4B E8 ?? ?? ?? ?? 89 C7 89 DE C1 EE 05 83 BC B0 EC 00 00 00 00 75 20 50 50 6A 04 6A 20 E8 ?? ?? ?? ?? 89 C2 83 C4 10 B8 0C 00 00 00 85 D2 74 21 89 94 B7 EC 00 00 00 83 E3 1F 8B 94 B7 EC 00 00 00 8B 44 24 14 89 04 9A 31 C0 EB 05 B8 16 00 00 00 5B 5E 5F C3 }
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

rule tdelete_fc9d9cbda7647f54833fe8eb91d076d0 {
	meta:
		aliases = "tdelete"
		size = "153"
		objfiles = "tdelete@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 8B 44 24 14 85 C0 0F 84 80 00 00 00 89 C6 8B 38 85 FF EB 0F 89 C7 7D 05 8D 70 04 EB 03 8D 70 08 83 3E 00 74 67 50 50 8B 06 FF 30 53 FF 54 24 28 83 C4 10 83 F8 00 8B 06 75 DA 8B 48 08 8B 58 04 85 DB 74 0E 85 C9 74 31 8B 51 04 85 D2 75 0B 89 59 04 89 CB EB 23 89 C2 89 D9 8B 42 04 89 D3 85 C0 75 F3 8B 42 08 89 41 04 8B 06 8B 40 04 89 42 04 8B 06 8B 40 08 89 42 08 83 EC 0C FF 36 E8 ?? ?? ?? ?? 89 1E 89 F8 83 C4 10 EB 02 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule _obstack_begin_82edc79dd230bc5c2cea4bfb3be3965c {
	meta:
		aliases = "_obstack_begin"
		size = "137"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 8B 54 24 14 8B 74 24 18 8B 4C 24 1C 85 F6 75 04 66 BE 04 00 85 D2 75 04 66 BA E0 0F 89 4B 1C 8B 44 24 20 89 43 20 89 13 8D 7E FF 89 7B 18 80 63 28 FE F6 43 28 01 74 08 50 50 52 FF 73 24 EB 04 83 EC 0C 52 FF D1 89 C2 83 C4 10 89 43 04 85 C0 75 05 E8 ?? ?? ?? ?? 8D 44 38 08 F7 DE 21 F0 89 43 08 89 43 0C 89 D0 03 03 89 02 89 43 10 C7 42 04 00 00 00 00 80 63 28 F9 B8 01 00 00 00 5B 5E 5F C3 }
	condition:
		$pattern
}

rule obstack_free_6f8cc95b48d5dc7460350b660e8a860c {
	meta:
		aliases = "obstack_free"
		size = "96"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 8B 74 24 14 8B 53 04 EB 23 8B 7A 04 F6 43 28 01 8B 43 20 74 08 51 51 52 FF 73 24 EB 04 83 EC 0C 52 FF D0 83 C4 10 80 4B 28 02 89 FA 85 D2 74 1C 39 F2 73 D5 39 32 72 D1 85 D2 74 10 89 73 0C 89 73 08 8B 02 89 43 10 89 53 04 EB 09 85 F6 74 05 E8 ?? ?? ?? ?? 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_strncasecmp_1ea34e287293d4b2e440283344e76eb0 {
	meta:
		aliases = "strncasecmp, __GI_strncasecmp"
		size = "65"
		objfiles = "strncasecmp@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 8B 74 24 14 8B 7C 24 18 31 C0 85 FF 74 28 39 F3 74 1A 8B 0D ?? ?? ?? ?? 0F B6 03 0F BF 14 41 0F B6 06 0F BF 04 41 29 C2 89 D0 75 0A 80 3B 00 74 05 4F 46 43 EB D4 5B 5E 5F C3 }
	condition:
		$pattern
}

rule strcspn_37d623e5da07b07b1fa0b97debb50c38 {
	meta:
		aliases = "__GI_strcspn, strcspn"
		size = "48"
		objfiles = "strcspn@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 8B 7C 24 14 31 F6 EB 15 52 52 0F BE C0 50 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 08 43 46 8A 03 84 C0 75 E5 89 F0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule strtok_r_d24ba90d00027a173b51b655d7cf7b01 {
	meta:
		aliases = "__GI_strtok_r, strtok_r"
		size = "89"
		objfiles = "strtok_r@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 10 8B 7C 24 14 8B 74 24 18 85 DB 75 02 8B 1E 51 51 57 53 E8 ?? ?? ?? ?? 83 C4 10 01 C3 80 3B 00 75 06 89 1E 31 C0 EB 27 52 52 57 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 0F 50 50 6A 00 53 E8 ?? ?? ?? ?? 83 C4 10 EB 04 C6 00 00 40 89 06 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule ___path_search_c336d91db5459777f2887629fe721964 {
	meta:
		aliases = "___path_search"
		size = "203"
		objfiles = "tempname@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 5C 24 18 8B 7C 24 1C 85 FF 74 1F 80 3F 00 74 1A 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 89 C6 83 F8 05 76 11 BE 05 00 00 00 EB 0A BF ?? ?? ?? ?? BE 04 00 00 00 85 DB 75 3B B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? BB ?? ?? ?? ?? 85 C0 75 28 50 50 53 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 0B 89 D8 E8 ?? ?? ?? ?? 85 C0 75 0D E8 ?? ?? ?? ?? C7 00 02 00 00 00 EB 32 83 EC 0C 53 E8 ?? ?? ?? ?? 83 C4 10 89 C2 EB 01 4A 83 FA 01 76 07 80 7C 1A FF 2F 74 F3 8D 44 16 08 39 44 24 14 73 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 19 51 51 57 56 53 52 68 ?? ?? ?? ?? FF 74 24 2C E8 ?? ?? ?? ?? 31 C0 83 C4 20 5B }
	condition:
		$pattern
}

rule pthread_mutex_timedlock_6bf5b095cf26a17fea6618fa9a70558a {
	meta:
		aliases = "pthread_mutex_timedlock"
		size = "197"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 10 8B 7C 24 14 81 7F 04 FF C9 9A 3B 0F 87 A2 00 00 00 8B 46 0C 83 F8 01 74 27 7F 09 85 C0 74 15 E9 8F 00 00 00 83 F8 02 74 40 83 F8 03 0F 85 81 00 00 00 EB 65 8D 46 10 31 D2 E8 ?? ?? ?? ?? EB 25 E8 ?? ?? ?? ?? 89 C3 39 46 08 75 05 FF 46 04 EB 14 8D 46 10 89 DA E8 ?? ?? ?? ?? 89 5E 08 C7 46 04 00 00 00 00 31 D2 EB 4F E8 ?? ?? ?? ?? 89 C3 BA 23 00 00 00 39 46 08 74 3E 50 57 53 8D 46 10 50 E8 ?? ?? ?? ?? 83 C4 10 BA 6E 00 00 00 85 C0 74 26 89 5E 08 30 D2 EB 1F 51 57 6A 00 8D 46 10 50 E8 ?? ?? ?? ?? 83 C4 10 83 F8 01 19 D2 83 E2 6E EB 05 BA 16 00 00 00 89 D0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __length_dotted_1eb874563e25b30ac931d713810f209b {
	meta:
		aliases = "__length_dotted"
		size = "65"
		objfiles = "lengthd@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 10 8B 7C 24 14 83 C8 FF 89 FA 85 F6 75 1B EB 27 0F B6 D8 89 D8 25 C0 00 00 00 3D C0 00 00 00 75 05 8D 4A 02 EB 0D 8D 14 0B 8A 04 16 8D 4A 01 84 C0 75 DD 89 C8 29 F8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_attr_setschedparam_228cce3559ede6a00d60e3cfb02627da {
	meta:
		aliases = "__GI_pthread_attr_setschedparam, pthread_attr_setschedparam"
		size = "75"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 10 8B 7C 24 14 83 EC 0C FF 76 04 E8 ?? ?? ?? ?? 89 C3 58 FF 76 04 E8 ?? ?? ?? ?? 8B 17 83 C4 10 39 C2 7C 18 39 DA 7F 14 50 6A 04 57 8D 46 08 50 E8 ?? ?? ?? ?? 31 C0 83 C4 10 EB 05 B8 16 00 00 00 5B 5E 5F C3 }
	condition:
		$pattern
}

rule wcswcs_9887b12654a526cef72d07c3a00876e9 {
	meta:
		aliases = "wcsstr, wcswcs"
		size = "54"
		objfiles = "wcsstr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 10 8B 7C 24 14 89 F0 89 FA 8B 1A 85 DB 75 04 89 F0 EB 19 8B 08 39 CB 75 08 83 C2 04 83 C0 04 EB E8 85 C9 74 05 83 C6 04 EB DB 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __encode_question_6787e6df2e07d4f717c1a2f6455f664d {
	meta:
		aliases = "__encode_question"
		size = "83"
		objfiles = "encodeq@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 10 8B 7C 24 14 8B 5C 24 18 50 53 57 FF 36 E8 ?? ?? ?? ?? 89 C1 83 C4 10 85 C0 78 2B 29 C3 83 FB 03 7F 05 83 C9 FF EB 1F 8D 14 07 0F B6 46 05 88 02 8B 46 04 88 42 01 0F B6 46 09 88 42 02 8B 46 08 88 42 03 83 C1 04 89 C8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule wcscasecmp_de2d730f70a4226a6c51668356e8ee62 {
	meta:
		aliases = "__GI_wcscasecmp, wcscasecmp"
		size = "94"
		objfiles = "wcscasecmp@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 10 8B 7C 24 14 EB 0F 83 3E 00 75 04 31 C0 EB 44 83 C6 04 83 C7 04 8B 06 3B 07 74 EB 83 EC 0C 50 E8 ?? ?? ?? ?? 89 C3 5A FF 37 E8 ?? ?? ?? ?? 83 C4 10 39 C3 74 D1 83 EC 0C FF 36 E8 ?? ?? ?? ?? 89 C3 58 FF 37 E8 ?? ?? ?? ?? 83 C4 10 39 C3 19 C0 83 C8 01 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_remove_6dc044afff9bcf5daa108a1ed133edd3 {
	meta:
		aliases = "remove, __GI_remove"
		size = "55"
		objfiles = "remove@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 10 E8 ?? ?? ?? ?? 89 C3 8B 38 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 13 83 3B 14 75 0E 89 3B 89 74 24 10 5B 5E 5F E9 ?? ?? ?? ?? 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_rwlock_wrlock_9f9ad7e0f2ebb9fed55ac31e39f5dcdb {
	meta:
		aliases = "pthread_rwlock_wrlock"
		size = "89"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 10 E8 ?? ?? ?? ?? 89 C3 8D 7E 14 89 DA 89 F0 E8 ?? ?? ?? ?? 83 7E 08 00 75 06 83 7E 0C 00 74 1E 89 DA 89 F8 E8 ?? ?? ?? ?? 83 EC 0C 56 E8 ?? ?? ?? ?? 89 D8 E8 ?? ?? ?? ?? 83 C4 10 EB CD 89 5E 0C 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule _dl_add_elf_hash_table_7b497e00fd59515b81952f46d9b0f306 {
	meta:
		aliases = "_dl_add_elf_hash_table"
		size = "217"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 14 8B 7C 24 18 8B 1D ?? ?? ?? ?? 85 DB 75 2C 83 EC 0C 68 E8 00 00 00 E8 ?? ?? ?? ?? 89 C3 A3 ?? ?? ?? ?? BA E8 00 00 00 83 C4 10 EB 04 C6 00 00 40 4A 83 FA FF 75 F6 EB 35 89 C3 8B 43 0C 85 C0 75 F7 83 EC 0C 68 E8 00 00 00 E8 ?? ?? ?? ?? 89 43 0C BA E8 00 00 00 83 C4 10 EB 04 C6 00 00 40 4A 83 FA FF 75 F6 8B 43 0C 89 58 10 89 C3 C7 43 0C 00 00 00 00 66 C7 43 22 00 00 83 EC 0C FF 74 24 1C E8 ?? ?? ?? ?? 89 43 04 8B 44 24 2C 89 43 08 C7 43 18 03 00 00 00 8B 4F 10 83 C4 10 85 C9 74 17 8B 01 89 43 28 8B 51 04 89 53 38 8D 51 08 89 53 2C 8D 04 82 89 43 3C 89 33 89 73 14 31 D2 8B 04 }
	condition:
		$pattern
}

rule wcstok_28aa4e48b4b7a16dc7c6994b70569fbc {
	meta:
		aliases = "wcstok"
		size = "84"
		objfiles = "wcstok@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 74 24 14 8B 7C 24 18 8B 5C 24 10 85 DB 75 06 8B 1F 85 DB 74 35 52 52 56 53 E8 ?? ?? ?? ?? 83 C4 10 8D 1C 83 83 3B 00 75 06 31 DB 31 C0 EB 19 50 50 56 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 09 C7 00 00 00 00 00 83 C0 04 89 07 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule pthread_rwlock_unlock_1ae17440c441568f94aacdb8a2f78f27 {
	meta:
		aliases = "pthread_rwlock_unlock"
		size = "321"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 31 D2 89 F8 E8 ?? ?? ?? ?? 8B 5F 0C 85 DB 74 72 E8 ?? ?? ?? ?? 39 C3 75 70 C7 47 0C 00 00 00 00 83 7F 18 00 74 28 8B 5F 14 85 DB 74 21 8B 43 08 89 47 14 C7 43 08 00 00 00 00 83 EC 0C 57 E8 ?? ?? ?? ?? 89 D8 E8 ?? ?? ?? ?? 31 C0 EB 49 8B 77 10 C7 47 10 00 00 00 00 83 EC 0C 57 E8 ?? ?? ?? ?? 83 C4 10 EB 13 8B 5E 08 C7 46 08 00 00 00 00 89 F0 E8 ?? ?? ?? ?? 89 DE 85 F6 75 E9 E9 B2 00 00 00 8B 47 08 85 C0 75 16 83 EC 0C 57 E8 ?? ?? ?? ?? B8 01 00 00 00 83 C4 10 E9 97 00 00 00 48 89 47 08 31 DB 85 C0 75 14 8B 5F 14 85 DB 74 0D 8B 43 08 89 47 14 C7 43 08 00 00 00 00 83 EC 0C 57 }
	condition:
		$pattern
}

rule __GI_strndup_f3499d35f179e80d3a367ff0caeb841e {
	meta:
		aliases = "strndup, __GI_strndup"
		size = "63"
		objfiles = "strndup@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 52 52 FF 74 24 1C 57 E8 ?? ?? ?? ?? 89 C6 8D 40 01 89 04 24 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 74 10 50 56 57 53 E8 ?? ?? ?? ?? C6 04 33 00 83 C4 10 89 D8 5B 5E 5F C3 }
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

rule wcsdup_f21635e4fe588ea8d303b4f993dc446e {
	meta:
		aliases = "wcsdup"
		size = "58"
		objfiles = "wcsdup@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 83 EC 0C 57 E8 ?? ?? ?? ?? 8D 34 85 04 00 00 00 89 34 24 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 74 0C 50 56 57 53 E8 ?? ?? ?? ?? 83 C4 10 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule strdup_8f030be86eee5afe9177a12a1330a4c2 {
	meta:
		aliases = "__GI_strdup, strdup"
		size = "54"
		objfiles = "strdup@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 83 EC 0C 57 E8 ?? ?? ?? ?? 8D 70 01 89 34 24 E8 ?? ?? ?? ?? 89 C3 83 C4 10 85 C0 74 0C 50 56 57 53 E8 ?? ?? ?? ?? 83 C4 10 89 D8 5B 5E 5F C3 }
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

rule __GI_mknod_9f26d16c708d150accf3e135728fda1a {
	meta:
		aliases = "mknod, __GI_mknod"
		size = "55"
		objfiles = "mknod@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 8B 4C 24 14 8B 5C 24 18 89 DA 53 89 FB B8 0E 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule xdr_vector_381a53d403b0900aba23392d11820bfe {
	meta:
		aliases = "xdr_vector"
		size = "51"
		objfiles = "xdr_array@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 8B 5C 24 14 31 F6 EB 15 50 6A FF 53 57 FF 54 24 30 83 C4 10 85 C0 74 10 03 5C 24 1C 46 3B 74 24 18 72 E5 B8 01 00 00 00 5B 5E 5F C3 }
	condition:
		$pattern
}

rule cfsetspeed_3cd979f1c29e358fe0fa9143c8db2cc0 {
	meta:
		aliases = "cfsetspeed"
		size = "98"
		objfiles = "cfsetspeed@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 8B 74 24 14 31 C0 EB 3C 8B 1C C5 ?? ?? ?? ?? 39 DE 75 0E 50 50 56 57 E8 ?? ?? ?? ?? 5B 58 56 EB 15 3B 34 C5 ?? ?? ?? ?? 75 19 51 51 53 57 E8 ?? ?? ?? ?? 58 5A 53 57 E8 ?? ?? ?? ?? 31 C0 83 C4 10 EB 14 40 83 F8 1F 76 BF E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 5B 5E 5F C3 }
	condition:
		$pattern
}

rule getnetbyaddr_48496ceb3bbaee7e6d346027451ebd28 {
	meta:
		aliases = "getnetbyaddr"
		size = "73"
		objfiles = "getnetbyad@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 8B 74 24 14 83 EC 0C 0F BE 05 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 10 EB 0A 39 73 08 75 05 39 7B 0C 74 0B E8 ?? ?? ?? ?? 89 C3 85 C0 75 EB 80 3D ?? ?? ?? ?? 00 75 05 E8 ?? ?? ?? ?? 89 D8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule lfind_94e8ae75adf229abede616435c5312b5 {
	meta:
		aliases = "__GI_lfind, lfind"
		size = "54"
		objfiles = "lfind@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 8B 74 24 14 8B 44 24 18 8B 18 EB 17 50 50 56 57 FF 54 24 30 83 C4 10 85 C0 75 04 89 F0 EB 0C 03 74 24 1C 4B 83 FB FF 75 E3 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule wmemmove_6ccacb392b42bbdea2f680c1755cd396 {
	meta:
		aliases = "wmemmove"
		size = "66"
		objfiles = "wmemmove@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 8B 74 24 14 8B 4C 24 18 39 FE 72 25 89 FB 89 F2 EB 0B 8B 02 89 03 83 C3 04 83 C2 04 49 85 C9 75 F1 EB 12 49 8D 14 8D 00 00 00 00 8B 04 16 89 04 17 85 C9 75 EE 89 F8 5B 5E 5F C3 }
	condition:
		$pattern
}

rule sched_getaffinity_dec44b6ce65a92ab1192fe893b4e8173 {
	meta:
		aliases = "sched_getaffinity"
		size = "91"
		objfiles = "sched_getaffinity@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 8B 74 24 14 8B 54 24 18 89 F1 85 F6 79 05 B9 FF FF FF 7F 53 89 FB B8 F2 00 00 00 CD 80 5B 89 C3 3D 00 F0 FF FF 76 0B E8 ?? ?? ?? ?? F7 DB 89 18 EB 05 83 F8 FF 75 05 83 C8 FF EB 14 50 29 DE 56 6A 00 8D 04 1A 50 E8 ?? ?? ?? ?? 31 C0 83 C4 10 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_stpncpy_56505f9cb9c1bb7f6e4d005b043edcff {
	meta:
		aliases = "stpncpy, __GI_stpncpy"
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
		size = "49"
		objfiles = "wcpncpy@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 8B 74 24 14 8B 5C 24 18 89 F2 89 F9 EB 0F 8B 02 89 01 85 C0 74 03 83 C2 04 83 C1 04 4B 85 DB 75 ED 29 F2 8D 04 17 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_wctype_8a4d087639cfab401aa2be368523356c {
	meta:
		aliases = "wctrans, __GI_wctrans, wctype, __GI_wctype"
		size = "61"
		objfiles = "wctrans@libc.a, wctype@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 B8 ?? ?? ?? ?? BE 01 00 00 00 8D 58 01 50 50 53 57 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 04 89 F0 EB 11 0F B6 43 FF 8D 04 03 80 38 00 74 03 46 EB DA 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __pthread_perform_cleanup_b241a486defc39527b0cc72528cf351a {
	meta:
		aliases = "__pthread_perform_cleanup"
		size = "62"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 10 E8 ?? ?? ?? ?? 89 C6 8B 58 3C EB 12 39 FB 76 12 83 EC 0C FF 73 04 FF 13 8B 5B 0C 83 C4 10 85 DB 75 EA 83 BE 74 01 00 00 00 74 08 5B 5E 5F E9 ?? ?? ?? ?? 5B 5E 5F C3 }
	condition:
		$pattern
}

rule svctcp_recv_92b11823f1f487a890eaa4369eba8cb3 {
	meta:
		aliases = "svctcp_recv"
		size = "73"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 14 8B 44 24 10 8B 70 2C 8D 5E 08 C7 46 08 01 00 00 00 83 EC 0C 53 E8 ?? ?? ?? ?? 59 58 57 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 0C 8B 07 89 46 04 B8 01 00 00 00 EB 08 C7 06 00 00 00 00 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule svcunix_recv_c600f3444f588989c47e779b0e4f7090 {
	meta:
		aliases = "svcunix_recv"
		size = "94"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 14 8B 44 24 10 8B 70 2C 8D 5E 08 C7 46 08 01 00 00 00 83 EC 0C 53 E8 ?? ?? ?? ?? 59 58 57 53 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 21 8B 07 89 46 04 C7 47 24 01 00 00 00 C7 47 28 ?? ?? ?? ?? C7 47 2C 1C 00 00 00 B8 01 00 00 00 EB 08 C7 06 00 00 00 00 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_fwrite_unlocked_50260af8ec1e77e13daa5360af19b798 {
	meta:
		aliases = "fwrite_unlocked, __GI_fwrite_unlocked"
		size = "114"
		objfiles = "fwrite_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 53 8B 7C 24 14 8B 5C 24 18 8B 74 24 1C 0F B7 06 25 C0 00 00 00 3D C0 00 00 00 74 14 52 52 68 80 00 00 00 56 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 3A 85 FF 74 36 85 DB 74 32 83 C8 FF 31 D2 F7 F7 39 C3 77 18 50 56 0F AF DF 53 FF 74 24 1C E8 ?? ?? ?? ?? 31 D2 F7 F7 83 C4 10 EB 11 66 83 0E 08 E8 ?? ?? ?? ?? C7 00 16 00 00 00 31 C0 5B 5E 5F C3 }
	condition:
		$pattern
}

rule waitid_ebaba468af1edda1c4b867477b389588 {
	meta:
		aliases = "waitid"
		size = "61"
		objfiles = "waitid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 31 FF 8B 44 24 10 53 89 C3 B8 1C 01 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule timer_settime_bc2e81f1d4fdd046bc1ea44cb3121d49 {
	meta:
		aliases = "timer_settime"
		size = "62"
		objfiles = "timer_settime@librt.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 44 24 10 8B 78 04 53 89 FB B8 04 01 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule splice_378d4600fd6c2fc04e6b3bace07da612 {
	meta:
		aliases = "__GI_splice, splice"
		size = "68"
		objfiles = "splice@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 55 8B 6C 24 24 B8 39 01 00 00 CD 80 5D 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule __syscall_ipc_d01ff4c24ace2d74dd83c98bde9dae0b {
	meta:
		aliases = "__syscall_ipc"
		size = "68"
		objfiles = "__syscall_ipc@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 55 8B 6C 24 24 B8 75 00 00 00 CD 80 5D 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule remap_file_pages_6383b7a736603502b51f2b19d4015f3d {
	meta:
		aliases = "remap_file_pages"
		size = "62"
		objfiles = "remap_file_pages@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 B8 01 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule mount_ece3b2dae1d9127cd89517984432b18d {
	meta:
		aliases = "mount"
		size = "62"
		objfiles = "mount@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 B8 15 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule fchownat_151a3706e4b0e8438533aac9cd165c18 {
	meta:
		aliases = "fchownat"
		size = "62"
		objfiles = "fchownat@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 B8 2A 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule linkat_83973700bcc0466d111198625b9a852f {
	meta:
		aliases = "linkat"
		size = "62"
		objfiles = "linkat@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 B8 2F 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule init_module_5197f937570c535229dec1edb064f071 {
	meta:
		aliases = "init_module"
		size = "62"
		objfiles = "init_module@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 B8 80 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_select_9c95bff044e4dd03cd5d0c52723e2c39 {
	meta:
		aliases = "select, __libc_select, __GI_select"
		size = "62"
		objfiles = "select@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 B8 8E 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule mremap_5b645fc8fb566e3b6118c2b6be2da347 {
	meta:
		aliases = "__GI_mremap, mremap"
		size = "62"
		objfiles = "mremap@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 B8 A3 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule prctl_40177fb115474eb10e2ee0095c5dca6d {
	meta:
		aliases = "prctl"
		size = "62"
		objfiles = "prctl@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 B8 AC 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule setxattr_97203c1769b24387d7b33a73b9446459 {
	meta:
		aliases = "setxattr"
		size = "62"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 B8 E2 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5F 5E 5F C3 }
	condition:
		$pattern
}

rule lsetxattr_bcbd9877867beed9db17454740a1069d {
	meta:
		aliases = "lsetxattr"
		size = "62"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 B8 E3 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E 5E 5F C3 }
	condition:
		$pattern
}

rule fsetxattr_5a93524aa9b494ed3f2fdd619e51924c {
	meta:
		aliases = "fsetxattr"
		size = "62"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 8B 7C 24 20 8B 44 24 10 53 89 C3 B8 E4 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 59 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_strncat_087bf8e3075fdca29d98967594d20f8f {
	meta:
		aliases = "strncat, __GI_strncat"
		size = "48"
		objfiles = "strncat@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 74 24 14 31 C0 83 C9 FF 8B 7C 24 10 F2 AE 4F 8B 4C 24 18 41 49 74 08 AC AA 84 C0 75 F7 EB 03 31 C0 AA 8B 44 24 10 5A 5E 5F C3 }
	condition:
		$pattern
}

rule strcat_fc39f2e68c3e2b9572ead413f87d6dfc {
	meta:
		aliases = "__GI_strcat, strcat"
		size = "35"
		objfiles = "strcat@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 74 24 14 31 C0 83 C9 FF 8B 7C 24 10 F2 AE 4F AC AA 84 C0 75 FA 8B 44 24 10 5A 5E 5F C3 }
	condition:
		$pattern
}

rule memcpy_f71bed6dea38d9b522e08b738554b3ff {
	meta:
		aliases = "__GI_memcpy, memcpy"
		size = "43"
		objfiles = "memcpy@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 74 24 14 8B 44 24 18 89 C1 C1 E9 02 8B 7C 24 10 F3 A5 A8 02 74 02 66 A5 A8 01 74 01 A4 8B 44 24 10 5A 5E 5F C3 }
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

rule __GI_strcpy_25e830002e76d977a2cf7c0f6516f752 {
	meta:
		aliases = "strcpy, __GI_strcpy"
		size = "27"
		objfiles = "strcpy@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 74 24 14 8B 7C 24 10 AC AA 84 C0 75 FA 8B 44 24 10 5A 5E 5F C3 }
	condition:
		$pattern
}

rule sigprocmask_c9246d449d20e85ecafe84f8fe06c3ee {
	meta:
		aliases = "__GI_sigprocmask, sigprocmask"
		size = "85"
		objfiles = "sigprocmask@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 85 C9 74 15 83 FF 02 76 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 27 BE 08 00 00 00 53 89 FB B8 AF 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule epoll_wait_a802b1ab1a028f71b5b08b5e254f5a60 {
	meta:
		aliases = "epoll_wait"
		size = "58"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 00 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_openat_66b15afa1c11d4132fd2950d13051c42 {
	meta:
		aliases = "openat, __GI_openat"
		size = "58"
		objfiles = "openat@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 27 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule renameat_f0261891ff2702a62aa89b82d508c143 {
	meta:
		aliases = "renameat"
		size = "58"
		objfiles = "renameat@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 2E 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule readlinkat_157e6efcb6b94985b0127d86b094f96c {
	meta:
		aliases = "readlinkat"
		size = "58"
		objfiles = "readlinkat@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 31 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule fchmodat_8be770efd3391959adbe7d6ebcc05be1 {
	meta:
		aliases = "fchmodat"
		size = "58"
		objfiles = "fchmodat@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 32 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule faccessat_8b268a9289d1c2f2909998c77698bcc3 {
	meta:
		aliases = "faccessat"
		size = "58"
		objfiles = "faccessat@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 33 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule tee_ef833b56c3d2cee094b12e32a068816d {
	meta:
		aliases = "tee"
		size = "58"
		objfiles = "tee@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 3B 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_vmsplice_2d425cb7f315a49508f5216c13042a9f {
	meta:
		aliases = "vmsplice, __GI_vmsplice"
		size = "58"
		objfiles = "vmsplice@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 3C 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule utimensat_f5fd7ea83de199d3b52614959c221c3f {
	meta:
		aliases = "__GI_utimensat, utimensat"
		size = "58"
		objfiles = "utimensat@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 40 01 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule wait4_f19cd2ea4158684f3d7d21cb20087386 {
	meta:
		aliases = "__GI_wait4, wait4"
		size = "59"
		objfiles = "wait4@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 72 00 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule quotactl_17193ed1623ecff1711c5d4448de420b {
	meta:
		aliases = "quotactl"
		size = "58"
		objfiles = "quotactl@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 83 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule __syscall_rt_sigaction_cfc374af905eb672cddbde063d738d32 {
	meta:
		aliases = "__syscall_rt_sigaction"
		size = "58"
		objfiles = "__syscall_rt_sigaction@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 AE 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule sendfile_30a20347a6ccbe91413b78c6e9305a1e {
	meta:
		aliases = "sendfile"
		size = "58"
		objfiles = "sendfile@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 BB 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule getxattr_edcc8407a7d6958f3e4796dc70547376 {
	meta:
		aliases = "getxattr"
		size = "58"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 E5 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule lgetxattr_843a9c12689289cb83b11985f2f097e9 {
	meta:
		aliases = "lgetxattr"
		size = "58"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 E6 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5F 5E 5F C3 }
	condition:
		$pattern
}

rule fgetxattr_164d39509003b0be7d8f1a8fd1943c6f {
	meta:
		aliases = "fgetxattr"
		size = "58"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 E7 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5E 5E 5F C3 }
	condition:
		$pattern
}

rule sendfile64_227ffa4aa715feeba5897bed85d0e404 {
	meta:
		aliases = "sendfile64"
		size = "58"
		objfiles = "sendfile64@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 EF 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 5A 5E 5F C3 }
	condition:
		$pattern
}

rule epoll_ctl_2b3331f6f28e691c403ff7008804820c {
	meta:
		aliases = "epoll_ctl"
		size = "58"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 8B 74 24 1C 53 89 FB B8 FF 00 00 00 CD 80 5B 89 C6 81 FE 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 C8 FF 59 5E 5F C3 }
	condition:
		$pattern
}

rule signalfd_657d5ea57a9b3d1f25712e1a216bddba {
	meta:
		aliases = "signalfd"
		size = "60"
		objfiles = "signalfd@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 04 8B 7C 24 10 8B 4C 24 14 8B 74 24 18 BA 08 00 00 00 53 89 FB B8 47 01 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF 89 F0 5A 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_ppoll_5a83ab0029d4acc709fb963715bdce3d {
	meta:
		aliases = "ppoll, __GI_ppoll"
		size = "87"
		objfiles = "ppoll@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 14 8B 54 24 28 8B 74 24 2C 85 D2 74 11 8B 0A 8B 42 04 89 44 24 10 89 4C 24 0C 8D 54 24 0C BF 08 00 00 00 8B 44 24 20 8B 4C 24 24 53 89 C3 B8 35 01 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 83 C4 14 5E 5F C3 }
	condition:
		$pattern
}

rule mq_open_d24c6bc9e1a0a9d6ed7e404c9181abc7 {
	meta:
		aliases = "mq_open"
		size = "102"
		objfiles = "mq_open@librt.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 14 8B 7C 24 20 8B 4C 24 24 80 3F 2F 74 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 3E F6 C1 40 75 06 31 D2 31 F6 EB 10 8B 54 24 28 8D 44 24 30 89 44 24 10 8B 74 24 2C 47 53 89 FB B8 15 01 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 83 C4 14 5E 5F C3 }
	condition:
		$pattern
}

rule mknodat_5c586dfe9d5516067f96897a1f0dbfd1 {
	meta:
		aliases = "__GI_mknodat, mknodat"
		size = "74"
		objfiles = "mknodat@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 14 8B 7C 24 20 8B 4C 24 24 8B 44 24 2C 89 44 24 08 C7 44 24 0C 00 00 00 00 8B 54 24 28 89 C6 53 89 FB B8 29 01 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 83 C4 14 5E 5F C3 }
	condition:
		$pattern
}

rule fstatat_eb03f6e223060678b7be8360f2e1ae14 {
	meta:
		aliases = "fstatat64, fstatat"
		size = "85"
		objfiles = "fstatat@libc.a, fstatat64@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 83 EC 64 8B 7C 24 70 8B 4C 24 74 8B 74 24 7C 8D 54 24 04 53 89 FB B8 2C 01 00 00 CD 80 5B 89 C6 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DE 89 30 83 CE FF EB 16 85 C0 75 12 50 50 FF B4 24 80 00 00 00 52 E8 ?? ?? ?? ?? 83 C4 10 89 F0 83 C4 64 5E 5F C3 }
	condition:
		$pattern
}

rule memmove_ad78593e4bf89b0547145e77f94ba18f {
	meta:
		aliases = "__GI_memmove, memmove"
		size = "39"
		objfiles = "memmove@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 44 24 0C 8B 74 24 10 8B 4C 24 14 39 F0 73 06 89 C7 F3 A4 EB 0C 8D 74 0E FF 8D 7C 08 FF FD F3 A4 FC 5E 5F C3 }
	condition:
		$pattern
}

rule posix_fadvise_12ebf4bb0528bc7cd122ea2b7996b8a9 {
	meta:
		aliases = "posix_fadvise"
		size = "50"
		objfiles = "posix_fadvise@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 4C 24 10 8B 74 24 14 8B 7C 24 18 89 C8 99 8B 44 24 0C 53 89 C3 B8 FA 00 00 00 CD 80 5B 31 D2 3D 00 F0 FF FF 76 04 89 C2 F7 DA 89 D0 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_strncmp_aea55172a8fbe75e3f4316664e505052 {
	meta:
		aliases = "strncmp, __GI_strncmp"
		size = "37"
		objfiles = "strncmp@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 74 24 0C 8B 7C 24 10 8B 4C 24 14 41 49 74 08 AC AE 75 08 84 C0 75 F5 31 C0 EB 04 19 C0 0C 01 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_strcmp_124e63b6cd601cb0633c0125291d4f19 {
	meta:
		aliases = "__GI_strcoll, strcoll, strcmp, __GI_strcmp"
		size = "29"
		objfiles = "strcmp@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 56 8B 74 24 0C 8B 7C 24 10 AC AE 75 08 84 C0 75 F8 31 C0 EB 04 19 C0 0C 01 5E 5F C3 }
	condition:
		$pattern
}

rule __GI_svc_getreq_fdbe930caa42267420bdbea5fb0560ff {
	meta:
		aliases = "svc_getreq, __GI_svc_getreq"
		size = "51"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 81 EC 88 00 00 00 31 C0 B9 20 00 00 00 8D 54 24 08 89 D7 FC F3 AB 8B 84 24 90 00 00 00 89 44 24 08 83 EC 0C 52 E8 ?? ?? ?? ?? 81 C4 98 00 00 00 5F C3 }
	condition:
		$pattern
}

rule memset_2cede61e9952e182d0194cb6dba884fd {
	meta:
		aliases = "__GI_memset, memset"
		size = "25"
		objfiles = "memset@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 04 8B 44 24 10 8B 4C 24 14 8B 7C 24 0C F3 AA 8B 44 24 0C 5A 5F C3 }
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

rule timer_delete_1360b40fc6d15815b1821588d29e96d1 {
	meta:
		aliases = "timer_delete"
		size = "70"
		objfiles = "timer_delete@librt.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 54 24 10 8B 7A 04 53 89 FB B8 07 01 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF EB 15 83 C8 FF 85 FF 75 0E 83 EC 0C 52 E8 ?? ?? ?? ?? 31 C0 83 C4 10 5A 59 5F C3 }
	condition:
		$pattern
}

rule reboot_4c86f047e5d2c7468fc4267f9616525e {
	meta:
		aliases = "reboot"
		size = "56"
		objfiles = "reboot@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 54 24 10 BF AD DE E1 FE B9 69 19 12 28 53 89 FB B8 58 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule __GI_close_2538c5f989c9cda6d429a23d4f923813 {
	meta:
		aliases = "close, __libc_close, __GI_close"
		size = "45"
		objfiles = "close@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 06 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule unlink_1b4c43d4a4f172d910e013afb1af848d {
	meta:
		aliases = "__GI_unlink, unlink"
		size = "45"
		objfiles = "unlink@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 0A 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
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

rule time_481dc1ed84bcad904fc40504754fe51c {
	meta:
		aliases = "__GI_time, time"
		size = "45"
		objfiles = "time@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 0D 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule umount_20c94dd4a3e84c791046760e6cd3e011 {
	meta:
		aliases = "umount"
		size = "45"
		objfiles = "umount@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 16 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule stime_725feb538e27f7a92160c5e995baffce {
	meta:
		aliases = "stime"
		size = "45"
		objfiles = "stime@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 19 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule alarm_cd2fccb347e68089b7ae9a1f5a62fc25 {
	meta:
		aliases = "__GI_alarm, alarm"
		size = "45"
		objfiles = "alarm@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 1B 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule nice_fc8ea9e82bc8a1becd932ada693b8aee {
	meta:
		aliases = "nice"
		size = "67"
		objfiles = "nice@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 22 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0E E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF EB 15 83 C8 FF 85 FF 75 0E 57 57 6A 00 6A 00 E8 ?? ?? ?? ?? 83 C4 10 5A 59 5F C3 }
	condition:
		$pattern
}

rule rmdir_9ba5eea834bd3a742eea3411166b4088 {
	meta:
		aliases = "__GI_rmdir, rmdir"
		size = "45"
		objfiles = "rmdir@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 28 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule dup_24f718f78fd62e9652e4b5c2eac08260 {
	meta:
		aliases = "dup"
		size = "45"
		objfiles = "dup@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 29 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule __GI_pipe_4db5cc4a100518f2b83167ca73f5df53 {
	meta:
		aliases = "pipe, __GI_pipe"
		size = "45"
		objfiles = "pipe@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 2A 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule times_d9989002e3bf57f4f0ab73aed2269fcb {
	meta:
		aliases = "__GI_times, times"
		size = "45"
		objfiles = "times@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 2B 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule acct_1e10855e152854ec22d5cf4a2bf41a8c {
	meta:
		aliases = "acct"
		size = "45"
		objfiles = "acct@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 33 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule umask_f342397061801d2aa3ae0975d8c21ea1 {
	meta:
		aliases = "umask"
		size = "47"
		objfiles = "umask@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 3C 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 0F B7 C7 5A 59 5F C3 }
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

rule iopl_f8399bdad791539a0552775f1ac96694 {
	meta:
		aliases = "iopl"
		size = "45"
		objfiles = "iopl@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 6E 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule swapoff_c47062d9e0d23889bffaaec9ab0b1544 {
	meta:
		aliases = "swapoff"
		size = "45"
		objfiles = "swapoff@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 73 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule sysinfo_6f966fcfdac99051f57b0e029e115cdf {
	meta:
		aliases = "sysinfo"
		size = "45"
		objfiles = "sysinfo@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 74 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule fsync_5ec2d0acc60340d78b0dabbbc3d6b4c8 {
	meta:
		aliases = "__libc_fsync, fsync"
		size = "45"
		objfiles = "fsync@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 76 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule __GI_uname_45744210c023f7e0355a7c20e1f582ec {
	meta:
		aliases = "uname, __GI_uname"
		size = "45"
		objfiles = "uname@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 7A 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule ntp_adjtime_8508e6930e40d6c25f60dddb8be3797e {
	meta:
		aliases = "__GI_adjtimex, adjtimex, ntp_adjtime"
		size = "45"
		objfiles = "adjtimex@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 7C 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
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

rule fchdir_0fb90e4aa8482d14b4d96ee5730b9e06 {
	meta:
		aliases = "__GI_fchdir, fchdir"
		size = "45"
		objfiles = "fchdir@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 85 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule personality_0252759f1378a383c58844d1946a9e5f {
	meta:
		aliases = "personality"
		size = "45"
		objfiles = "personality@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 88 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule getsid_2e9affb63995f7d667a0ec2e8fd43f6b {
	meta:
		aliases = "__GI_getsid, getsid"
		size = "46"
		objfiles = "getsid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 93 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule fdatasync_f897d361b4aa33ca92fa9ad662e23bf7 {
	meta:
		aliases = "fdatasync"
		size = "45"
		objfiles = "fdatasync@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 94 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule mlockall_f35f800d31c01fec4f464954a96ffcad {
	meta:
		aliases = "mlockall"
		size = "45"
		objfiles = "mlockall@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 98 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
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

rule sched_get_priority_max_8a722c53fe7a86c955fea14084dfe185 {
	meta:
		aliases = "sched_get_priority_max"
		size = "45"
		objfiles = "sched_get_priority_max@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 9F 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule sched_get_priority_min_66989fb75289606d9c7c35b71fde07ec {
	meta:
		aliases = "sched_get_priority_min"
		size = "45"
		objfiles = "sched_get_priority_min@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 A0 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule setuid_2c2fdf488710ba9ba7f9163ea30e88dc {
	meta:
		aliases = "setuid"
		size = "45"
		objfiles = "setuid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 D5 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule setgid_52d0e6e565fc67238d16439d6873bb85 {
	meta:
		aliases = "setgid"
		size = "45"
		objfiles = "setgid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 D6 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule setfsuid_badcd5f72fd5f12d12201f2caaa244a6 {
	meta:
		aliases = "setfsuid"
		size = "45"
		objfiles = "setfsuid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 D7 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule setfsgid_c69e4d5ec71dc2fc3ac76e94ba9e3e05 {
	meta:
		aliases = "setfsgid"
		size = "45"
		objfiles = "setfsgid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 D8 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule epoll_create_13fce070cf4305597d065931d928e0d6 {
	meta:
		aliases = "epoll_create"
		size = "45"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 53 89 FB B8 FE 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5F 5A 5F C3 }
	condition:
		$pattern
}

rule __GI_read_2be93fe5a4927a92aea2ff27d46d36a5 {
	meta:
		aliases = "read, __libc_read, __GI_read"
		size = "53"
		objfiles = "read@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 03 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule write_6a5564e27c1a91b1845d3b294792608c {
	meta:
		aliases = "__libc_write, __GI_write, write"
		size = "53"
		objfiles = "write@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 04 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule execve_1ac94fab1be5d9a2688ec562e81e020d {
	meta:
		aliases = "__GI_execve, execve"
		size = "53"
		objfiles = "execve@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 0B 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule __GI_lseek_8e5a565fe0a5b32af31233427caa96c0 {
	meta:
		aliases = "__GI___libc_lseek, __libc_lseek, lseek, __GI_lseek"
		size = "53"
		objfiles = "lseek@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 13 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule __GI_mq_setattr_032460859c946605f1509955db9e7e48 {
	meta:
		aliases = "mq_setattr, __GI_mq_setattr"
		size = "54"
		objfiles = "mq_getsetattr@librt.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 1A 01 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 5A 59 5F C3 }
	condition:
		$pattern
}

rule inotify_add_watch_117c495705c994f8ccd44adbb8192826 {
	meta:
		aliases = "inotify_add_watch"
		size = "53"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 24 01 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5F 5A 5F C3 }
	condition:
		$pattern
}

rule mkdirat_8d407142996e039fefc085a4d8f61dd9 {
	meta:
		aliases = "mkdirat"
		size = "53"
		objfiles = "mkdirat@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 28 01 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule futimesat_041964aa4d78e93fa3464ccc22bd38ca {
	meta:
		aliases = "futimesat"
		size = "53"
		objfiles = "futimesat@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 2B 01 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule unlinkat_6aaf252536ff790dac02261ee4278d43 {
	meta:
		aliases = "unlinkat"
		size = "53"
		objfiles = "unlinkat@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 2D 01 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule symlinkat_d2f9b3c52b2baff1f591903dac6ea993 {
	meta:
		aliases = "symlinkat"
		size = "53"
		objfiles = "symlinkat@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 30 01 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule __GI_readlink_3b312c5c16590ae5a1919976ff696374 {
	meta:
		aliases = "readlink, __GI_readlink"
		size = "53"
		objfiles = "readlink@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 55 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule __GI_setpriority_bdc7b4e920da4efe4a9c35e11b49ee09 {
	meta:
		aliases = "setpriority, __GI_setpriority"
		size = "53"
		objfiles = "setpriority@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 61 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule ioperm_c1143c52ee5c99b9de649ad7d0ecff55 {
	meta:
		aliases = "ioperm"
		size = "53"
		objfiles = "ioperm@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 65 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
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

rule __GI_setitimer_0ac70d275ff5c28611053d1b947ab63a {
	meta:
		aliases = "setitimer, __GI_setitimer"
		size = "53"
		objfiles = "setitimer@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 68 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule modify_ldt_06543221b1b239d96c6f9cf6e462bba2 {
	meta:
		aliases = "modify_ldt"
		size = "53"
		objfiles = "modify_ldt@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 7B 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule mprotect_3536923a9994e37f098dd1d97126e77d {
	meta:
		aliases = "mprotect"
		size = "53"
		objfiles = "mprotect@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 7D 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule __libc_msync_f6c711a117d1e89044f541412493e260 {
	meta:
		aliases = "msync, __libc_msync"
		size = "53"
		objfiles = "msync@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 90 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule readv_42d980f99c45cb4dc42e73f0acd98d16 {
	meta:
		aliases = "__libc_readv, readv"
		size = "53"
		objfiles = "readv@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 91 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule __libc_writev_aaf32191cfc12d485d2e1ac30a8d6b50 {
	meta:
		aliases = "writev, __libc_writev"
		size = "53"
		objfiles = "writev@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 92 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
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

rule __GI_poll_71bcd0cdbda71d3c792691e8f4d18539 {
	meta:
		aliases = "__libc_poll, poll, __GI_poll"
		size = "53"
		objfiles = "poll@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 A8 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule lchown_bb302e1a29835e76c23d65c10eff97ef {
	meta:
		aliases = "lchown"
		size = "53"
		objfiles = "lchown@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 C6 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule fchown_b2e885c2c8b1ce6ffb06171d152ccfc4 {
	meta:
		aliases = "fchown"
		size = "53"
		objfiles = "fchown@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 CF 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule __GI_setresuid_994d12a65c596360531036e02c5f639e {
	meta:
		aliases = "setresuid, __GI_setresuid"
		size = "53"
		objfiles = "setresuid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 D0 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule getresuid_4b3610267276c406397b8c1afe939e38 {
	meta:
		aliases = "getresuid"
		size = "53"
		objfiles = "getresuid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 D1 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule __GI_setresgid_854640f682e6b196db8c18e318a4ada3 {
	meta:
		aliases = "setresgid, __GI_setresgid"
		size = "53"
		objfiles = "setresgid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 D2 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule getresgid_e2287d5c8bd1e9036b8560553d401e35 {
	meta:
		aliases = "getresgid"
		size = "53"
		objfiles = "getresgid@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 D3 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule chown_51f9755c23bca5a24f419f4fda3bb6f3 {
	meta:
		aliases = "__GI_chown, chown"
		size = "53"
		objfiles = "chown@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 D4 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule mincore_0175c56c470eb9690e1730208ab6b7b0 {
	meta:
		aliases = "mincore"
		size = "53"
		objfiles = "mincore@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 DA 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule madvise_7c001bc33230c656b1fc1d0fa274d561 {
	meta:
		aliases = "madvise"
		size = "53"
		objfiles = "madvise@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 DB 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule listxattr_2f1877597177a931e86a7d1b09c9128a {
	meta:
		aliases = "listxattr"
		size = "53"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 E8 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5A 59 5F C3 }
	condition:
		$pattern
}

rule llistxattr_6c5a21fafbc7c39a7c355cd7933423bc {
	meta:
		aliases = "llistxattr"
		size = "53"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 E9 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 59 5F 5F C3 }
	condition:
		$pattern
}

rule flistxattr_81e2d8ab50a90511cde9ab31dfc6e804 {
	meta:
		aliases = "flistxattr"
		size = "53"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 08 8B 7C 24 10 8B 4C 24 14 8B 54 24 18 53 89 FB B8 EA 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 5F 5A 5F C3 }
	condition:
		$pattern
}

rule ioctl_014db8a7925058a6f77a73ba3b234ee1 {
	meta:
		aliases = "__GI_ioctl, ioctl"
		size = "63"
		objfiles = "ioctl@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 18 8B 7C 24 20 8B 4C 24 24 8D 44 24 2C 89 44 24 14 8B 54 24 28 53 89 FB B8 36 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 83 C4 18 5F C3 }
	condition:
		$pattern
}

rule __GI_fcntl64_9226c6c9fddd63826079fb38276bf98f {
	meta:
		aliases = "__libc_fcntl64, fcntl64, __GI___libc_fcntl64, __GI_fcntl64"
		size = "63"
		objfiles = "__syscall_fcntl64@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 18 8B 7C 24 20 8B 4C 24 24 8D 44 24 2C 89 44 24 14 8B 54 24 28 53 89 FB B8 DD 00 00 00 CD 80 5B 89 C7 3D 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 CF FF 89 F8 83 C4 18 5F C3 }
	condition:
		$pattern
}

rule sysctl_377ac7c009e26f429046677d6fafa4aa {
	meta:
		aliases = "sysctl"
		size = "94"
		objfiles = "sysctl@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 83 EC 38 8B 44 24 40 89 44 24 10 8B 44 24 44 89 44 24 14 8B 44 24 48 89 44 24 18 8B 44 24 4C 89 44 24 1C 8B 44 24 50 89 44 24 20 8B 44 24 54 89 44 24 24 8D 7C 24 10 53 89 FB B8 95 00 00 00 CD 80 5B 89 C7 81 FF 00 F0 FF FF 76 0C E8 ?? ?? ?? ?? F7 DF 89 38 83 C8 FF 83 C4 38 5F C3 }
	condition:
		$pattern
}

rule strlen_745f2b316e703ae50d36279ddd1d527e {
	meta:
		aliases = "__GI_strlen, strlen"
		size = "19"
		objfiles = "strlen@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 8B 7C 24 08 31 C0 83 C9 FF F2 AE F7 D1 49 89 C8 5F C3 }
	condition:
		$pattern
}

rule __GI_memchr_50218d1f8b9db094d126f8476b9eacd2 {
	meta:
		aliases = "memchr, __GI_memchr"
		size = "35"
		objfiles = "memchr@libc.a"
	strings:
		$pattern = { ( CC | 57 ) 8B 7C 24 08 8B 44 24 0C 8B 4C 24 10 31 D2 85 C9 74 0C F2 AE 74 05 BF 01 00 00 00 4F 89 FA 89 D0 5F C3 }
	condition:
		$pattern
}

rule vfork_8837c96e046fb66dd5409ab00bac5407 {
	meta:
		aliases = "__GI_vfork, __vfork, vfork"
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

rule sigblock_eb20bf8b993442b7533a4ff46b830953 {
	meta:
		aliases = "__GI_sigblock, sigblock"
		size = "88"
		objfiles = "sigblock@libc.a"
	strings:
		$pattern = { ( CC | 81 ) EC 0C 01 00 00 8B 84 24 10 01 00 00 89 84 24 8C 00 00 00 8D 94 24 90 00 00 00 B8 1E 00 00 00 C7 02 00 00 00 00 83 C2 04 48 79 F4 50 8D 44 24 10 50 8D 84 24 94 00 00 00 50 6A 00 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 04 8B 54 24 0C 89 D0 81 C4 0C 01 00 00 C3 }
	condition:
		$pattern
}

rule sigsetmask_4c8c9e34f1435221b9992a2e1ada46d5 {
	meta:
		aliases = "__GI_sigsetmask, sigsetmask"
		size = "88"
		objfiles = "sigsetmask@libc.a"
	strings:
		$pattern = { ( CC | 81 ) EC 0C 01 00 00 8B 84 24 10 01 00 00 89 84 24 8C 00 00 00 8D 94 24 90 00 00 00 B8 1E 00 00 00 C7 02 00 00 00 00 83 C2 04 48 79 F4 50 8D 44 24 10 50 8D 84 24 94 00 00 00 50 6A 02 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 04 8B 54 24 0C 89 D0 81 C4 0C 01 00 00 C3 }
	condition:
		$pattern
}

rule __sysv_signal_f22ca379987e5ce1652dcb37603a1974 {
	meta:
		aliases = "sysv_signal, __sysv_signal"
		size = "132"
		objfiles = "sysv_signal@libc.a"
	strings:
		$pattern = { ( CC | 81 ) EC 2C 01 00 00 8B 94 24 30 01 00 00 8B 84 24 34 01 00 00 83 F8 FF 74 09 85 D2 7E 05 83 FA 40 7E 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 CA FF EB 49 89 84 24 A0 00 00 00 B8 20 00 00 00 EB 0B C7 84 84 A4 00 00 00 00 00 00 00 48 79 F2 C7 84 24 24 01 00 00 00 00 00 E0 50 8D 44 24 18 50 8D 84 24 A8 00 00 00 50 52 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 04 8B 54 24 14 89 D0 81 C4 2C 01 00 00 C3 }
	condition:
		$pattern
}

rule sigignore_06b37ddcf67d21f5791a23d1e73679f7 {
	meta:
		aliases = "sigignore"
		size = "70"
		objfiles = "sigignore@libc.a"
	strings:
		$pattern = { ( CC | 81 ) EC 9C 00 00 00 C7 44 24 10 01 00 00 00 B8 20 00 00 00 EB 08 C7 44 84 14 00 00 00 00 48 79 F5 C7 84 24 94 00 00 00 00 00 00 00 50 6A 00 8D 44 24 18 50 FF B4 24 AC 00 00 00 E8 ?? ?? ?? ?? 81 C4 AC 00 00 00 C3 }
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

rule __new_sem_destroy_f4634403c8484c81d7ee3206a54f9016 {
	meta:
		aliases = "sem_destroy, __new_sem_destroy"
		size = "35"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 31 D2 8B 44 24 10 83 78 0C 00 74 0E E8 ?? ?? ?? ?? C7 00 10 00 00 00 83 CA FF 89 D0 83 C4 0C C3 }
	condition:
		$pattern
}

rule __old_sem_destroy_8cfcc3f13118715a6823d7bb8dadd6f6 {
	meta:
		aliases = "__old_sem_destroy"
		size = "34"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 31 D2 8B 44 24 10 F6 00 01 75 0E E8 ?? ?? ?? ?? C7 00 10 00 00 00 83 CA FF 89 D0 83 C4 0C C3 }
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

rule __libc_wait_848edee9a935c6ac0d34b0cf205e4666 {
	meta:
		aliases = "wait, __libc_wait"
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

rule futimens_29b9214fb8c31b37ef917b88b626cd22 {
	meta:
		aliases = "futimens"
		size = "24"
		objfiles = "futimens@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 6A 00 FF 74 24 18 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule waitpid_94d3925005c9f6c3778188d300b054a5 {
	meta:
		aliases = "wcstoumax, wcstoul, strtoull, wcstoull, strtoumax, strtoul, __GI_waitpid, __libc_waitpid, __GI_wcstoul, __GI_strtoul, __GI_wcstoull, __GI_strtoull, strtouq, wcstouq, waitpid"
		size = "26"
		objfiles = "strtoull@libc.a, strtoul@libc.a, wcstoul@libc.a, waitpid@libc.a, wcstoull@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 6A 00 FF 74 24 1C FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI_strtol_da26619b63cd9d4af4cd0f247526cc20 {
	meta:
		aliases = "strtoq, wcstol, strtoimax, strtol, wcstoq, strtoll, wcstoll, __GI_strtoll, __GI_wcstol, __GI_wcstoll, wcstoimax, __GI_strtol"
		size = "26"
		objfiles = "wcstoll@libc.a, strtol@libc.a, wcstol@libc.a, strtoll@libc.a"
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

rule fopen_f364830bff6399e8f176c673f485beb3 {
	meta:
		aliases = "__GI_fopen, fopen"
		size = "24"
		objfiles = "fopen@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 6A FF 6A 00 FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI___uClibc_init_5001d31a273157d71eaf93f09052d786 {
	meta:
		aliases = "__uClibc_init, __GI___uClibc_init"
		size = "64"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 80 3D ?? ?? ?? ?? 00 75 30 C6 05 ?? ?? ?? ?? 01 C7 05 ?? ?? ?? ?? 00 10 00 00 B8 ?? ?? ?? ?? 85 C0 74 05 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 85 C0 74 08 83 C4 0C E9 ?? ?? ?? ?? 83 C4 0C C3 }
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

rule __initbuf_becc142fae716f03f8c449af313538dc {
	meta:
		aliases = "__initbuf"
		size = "46"
		objfiles = "getproto@libc.a, getservice@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 83 3D ?? ?? ?? ?? 00 75 1E 83 EC 0C 68 8D 10 00 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 10 85 C0 75 05 E8 ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule __setutent_42093eefb2cfff09e7c9ea94d93d171f {
	meta:
		aliases = "__setutent"
		size = "156"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 83 3D ?? ?? ?? ?? FF 75 7C 50 50 6A 02 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 10 85 C0 79 1B 50 50 6A 00 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 10 85 C0 78 30 51 6A 00 6A 01 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 C0 78 19 52 83 C8 01 50 6A 02 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 85 C0 79 16 C7 05 ?? ?? ?? ?? FF FF FF FF 83 EC 0C 6A FF E8 ?? ?? ?? ?? EB 10 51 6A 00 6A 00 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __getutent_de9e4af31ba9e42ac333df63ad99b2bc {
	meta:
		aliases = "__getutent"
		size = "57"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 83 F8 FF 75 09 E8 ?? ?? ?? ?? 31 D2 EB 22 52 68 80 01 00 00 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 10 31 D2 3D 80 01 00 00 75 05 BA ?? ?? ?? ?? 89 D0 83 C4 0C C3 }
	condition:
		$pattern
}

rule getchar_unlocked_ba7c93b352215253e7885b79ebd7ebaa {
	meta:
		aliases = "__GI_getchar_unlocked, getchar_unlocked"
		size = "46"
		objfiles = "getchar_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 15 ?? ?? ?? ?? 8B 42 10 3B 42 18 73 09 0F B6 08 40 89 42 10 EB 0E 83 EC 0C 52 E8 ?? ?? ?? ?? 89 C1 83 C4 10 89 C8 83 C4 0C C3 }
	condition:
		$pattern
}

rule __GI_endttyent_44e509cc572e35e7eca102c617947e9d {
	meta:
		aliases = "endttyent, __GI_endttyent"
		size = "51"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 15 ?? ?? ?? ?? B8 01 00 00 00 85 D2 74 1D 83 EC 0C 52 E8 ?? ?? ?? ?? 83 C4 10 40 0F 95 C0 0F B6 C0 C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 0C C3 }
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

rule __GI_fileno_unlocked_70e7b53a80bf10ca8612118c41007002 {
	meta:
		aliases = "fileno_unlocked, __GI_fileno_unlocked"
		size = "32"
		objfiles = "fileno_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 10 8B 40 04 85 C0 79 0E E8 ?? ?? ?? ?? C7 00 09 00 00 00 83 C8 FF 83 C4 0C C3 }
	condition:
		$pattern
}

rule svctcp_stat_b9ef69e5544d5edda93fefab77863149 {
	meta:
		aliases = "svcunix_stat, svctcp_stat"
		size = "44"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
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

rule sem_init_0052d6831d9781447759e5cba0031051 {
	meta:
		aliases = "__new_sem_init, sem_init"
		size = "80"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 10 8B 54 24 18 85 D2 79 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 12 83 7C 24 14 00 74 10 E8 ?? ?? ?? ?? C7 00 26 00 00 00 83 C8 FF EB 19 C7 00 00 00 00 00 C7 40 04 00 00 00 00 89 50 08 C7 40 0C 00 00 00 00 31 C0 83 C4 0C C3 }
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

rule __GI_sigaddset_f657b9531bb3871fec8523f286c72564 {
	meta:
		aliases = "sigdelset, __GI_sigdelset, sigaddset, sigismember, __GI_sigaddset"
		size = "42"
		objfiles = "sigdelset@libc.a, sigaddset@libc.a, sigismem@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 14 85 C0 7E 0D 83 F8 40 7F 08 83 C4 0C E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF 83 C4 0C C3 }
	condition:
		$pattern
}

rule mbrlen_9ca82023638247df2c187a2369ce7e4c {
	meta:
		aliases = "__GI_mbrlen, mbrlen"
		size = "36"
		objfiles = "mbrlen@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 18 85 C0 75 05 B8 ?? ?? ?? ?? 50 FF 74 24 18 FF 74 24 18 6A 00 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI___assert_30d41f0669085af1fe903d6a469998de {
	meta:
		aliases = "__assert, __GI___assert"
		size = "76"
		objfiles = "__assert@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 1C 80 3D ?? ?? ?? ?? 00 75 37 C6 05 ?? ?? ?? ?? 01 85 C0 75 05 B8 ?? ?? ?? ?? 52 FF 74 24 14 50 FF 74 24 24 FF 74 24 24 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 20 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_mbsrtowcs_0bf1db9b392dda6e0e7333922ed6bef4 {
	meta:
		aliases = "mbsrtowcs, __GI_mbsrtowcs"
		size = "43"
		objfiles = "mbsrtowcs@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 44 24 1C 85 C0 75 05 B8 ?? ?? ?? ?? 83 EC 0C 50 FF 74 24 28 6A FF FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule putwchar_41958e078f50b6a515426cc0a2e67e1d {
	meta:
		aliases = "putwchar"
		size = "69"
		objfiles = "putwchar@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 4C 24 10 8B 15 ?? ?? ?? ?? 83 7A 34 00 74 1E 8B 42 10 3B 42 1C 73 0B 88 08 0F B6 C9 40 89 42 10 EB 19 50 50 52 51 E8 ?? ?? ?? ?? EB 09 50 50 52 51 E8 ?? ?? ?? ?? 89 C1 83 C4 10 89 C8 83 C4 0C C3 }
	condition:
		$pattern
}

rule putchar_unlocked_e9b595a77bcae6a5031e0876ad17db96 {
	meta:
		aliases = "putchar_unlocked"
		size = "52"
		objfiles = "putchar_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 4C 24 10 8B 15 ?? ?? ?? ?? 8B 42 10 3B 42 1C 73 0B 88 08 0F B6 C9 40 89 42 10 EB 0E 50 50 52 51 E8 ?? ?? ?? ?? 89 C1 83 C4 10 89 C8 83 C4 0C C3 }
	condition:
		$pattern
}

rule cfsetospeed_5df8d9ebecb9d856ede3bfbf86c057f4 {
	meta:
		aliases = "__GI_cfsetospeed, cfsetospeed"
		size = "65"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 4C 24 10 8B 54 24 14 F7 C2 F0 EF FF FF 74 1B 8D 82 FF EF FF FF 83 F8 0E 76 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 0F 8B 41 08 25 F0 EF FF FF 09 C2 89 51 08 31 C0 83 C4 0C C3 }
	condition:
		$pattern
}

rule __GI_cfsetispeed_248e3cbfaf9a4e35bc135582cb79d48b {
	meta:
		aliases = "cfsetispeed, __GI_cfsetispeed"
		size = "83"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 4C 24 10 8B 54 24 14 F7 C2 F0 EF FF FF 74 1B 8D 82 FF EF FF FF 83 F8 0E 76 10 E8 ?? ?? ?? ?? C7 00 16 00 00 00 83 C8 FF EB 21 85 D2 75 08 81 09 00 00 00 80 EB 13 81 21 FF FF FF 7F 8B 41 08 25 F0 EF FF FF 09 C2 89 51 08 31 C0 83 C4 0C C3 }
	condition:
		$pattern
}

rule wctomb_728221d6595d8adf0a454ccefa04f48e {
	meta:
		aliases = "wctomb"
		size = "33"
		objfiles = "wctomb@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 54 24 10 31 C0 85 D2 74 10 50 6A 00 FF 74 24 1C 52 E8 ?? ?? ?? ?? 83 C4 10 83 C4 0C C3 }
	condition:
		$pattern
}

rule mblen_cae35fa3a06e0c355694540ef9a4ef22 {
	meta:
		aliases = "mblen"
		size = "72"
		objfiles = "mblen@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 54 24 10 85 D2 75 0E C7 05 ?? ?? ?? ?? 00 00 00 00 31 C0 EB 2B 31 C0 80 3A 00 74 24 50 68 ?? ?? ?? ?? FF 74 24 1C 52 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FE 75 0C C7 05 ?? ?? ?? ?? FF FF 00 00 B0 FF 83 C4 0C C3 }
	condition:
		$pattern
}

rule __old_sem_init_c78677321b1cae5dfc5f0d96fbf97ef4 {
	meta:
		aliases = "__old_sem_init"
		size = "70"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 54 24 10 8B 44 24 18 85 C0 79 0D E8 ?? ?? ?? ?? C7 00 16 00 00 00 EB 12 83 7C 24 14 00 74 10 E8 ?? ?? ?? ?? C7 00 26 00 00 00 83 C8 FF EB 0F C7 42 04 00 00 00 00 8D 44 00 01 89 02 31 C0 83 C4 0C C3 }
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

rule setbuf_8b35136567c466748f5068f412da2f36 {
	meta:
		aliases = "setbuf"
		size = "35"
		objfiles = "setbuf@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 54 24 14 83 FA 01 19 C0 83 E0 02 68 00 10 00 00 50 52 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule setbuffer_f68a9979a8b699c17fb439828c13efab {
	meta:
		aliases = "setbuffer"
		size = "34"
		objfiles = "setbuffer@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 54 24 14 83 FA 01 19 C0 83 E0 02 FF 74 24 18 50 52 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule mbtowc_f9f45a1b2c1825ac1be7067513a23cd6 {
	meta:
		aliases = "mbtowc"
		size = "75"
		objfiles = "mbtowc@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 54 24 14 85 D2 75 0E C7 05 ?? ?? ?? ?? 00 00 00 00 31 C0 EB 2E 31 C0 80 3A 00 74 27 68 ?? ?? ?? ?? FF 74 24 1C 52 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 83 F8 FE 75 0C C7 05 ?? ?? ?? ?? FF FF 00 00 B0 FF 83 C4 0C C3 }
	condition:
		$pattern
}

rule posix_memalign_fac0a4f345fa73f1f05c4992db0eb886 {
	meta:
		aliases = "posix_memalign"
		size = "50"
		objfiles = "posix_memalign@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 54 24 14 B8 16 00 00 00 F6 C2 03 75 1D 50 50 FF 74 24 20 52 E8 ?? ?? ?? ?? 8B 54 24 20 89 02 83 C4 10 83 F8 01 19 C0 83 E0 0C 83 C4 0C C3 }
	condition:
		$pattern
}

rule xdrstdio_putbytes_6ef8ef1d7c0cb8d1ad5a3f42634d006b {
	meta:
		aliases = "xdrstdio_getbytes, xdrstdio_putbytes"
		size = "49"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C 8B 54 24 18 B8 01 00 00 00 85 D2 74 1D 8B 44 24 10 FF 70 0C 6A 01 52 FF 74 24 20 E8 ?? ?? ?? ?? 83 C4 10 48 0F 94 C0 0F B6 C0 83 C4 0C C3 }
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

rule setttyent_f54500d27b1369b7bf11860d736e6ac9 {
	meta:
		aliases = "__GI_setttyent, setttyent"
		size = "78"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C A1 ?? ?? ?? ?? 85 C0 74 0B 83 EC 0C 50 E8 ?? ?? ?? ?? EB 29 51 51 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 74 12 52 52 6A 02 50 E8 ?? ?? ?? ?? BA 01 00 00 00 83 C4 10 89 D0 83 C4 0C C3 }
	condition:
		$pattern
}

rule _rpcdata_506e15d3a43585cdb41c542e3f499ad6 {
	meta:
		aliases = "_rpcdata"
		size = "38"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C A1 ?? ?? ?? ?? 85 C0 75 16 50 50 68 B0 10 00 00 6A 01 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 C4 10 83 C4 0C C3 }
	condition:
		$pattern
}

rule rpc_thread_multi_6ec144fcc46a4c5f256fb495e1ae628c {
	meta:
		aliases = "rpc_thread_multi"
		size = "45"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C B8 ?? ?? ?? ?? 85 C0 74 13 50 50 68 ?? ?? ?? ?? 6A 02 E8 ?? ?? ?? ?? 83 C4 10 EB 0A C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 83 C4 0C C3 }
	condition:
		$pattern
}

rule atexit_65846a30059e19a6ee144761255a498e {
	meta:
		aliases = "atexit"
		size = "35"
		objfiles = "atexit@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C BA ?? ?? ?? ?? 85 D2 74 06 8B 15 ?? ?? ?? ?? 50 52 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __fp_range_check_7ea1dcac424f9f6f30d4f29dc78709f5 {
	meta:
		aliases = "__fp_range_check"
		size = "81"
		objfiles = "__fp_range_check@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C DB 6C 24 10 D9 05 ?? ?? ?? ?? D9 C1 D8 C9 D9 CA DD E2 DF E0 DD DA 9E 75 2D 7A 2B D9 EE D9 CA DD EA DF E0 DD D9 9E 7A 02 74 1E DB 6C 24 1C DC C9 DA E9 DF E0 9E 7A 02 74 11 E8 ?? ?? ?? ?? C7 00 22 00 00 00 EB 04 DD D8 DD D8 83 C4 0C C3 }
	condition:
		$pattern
}

rule __isnan_a6fcd1b1737635ad82f82d13290b7120 {
	meta:
		aliases = "__GI___isnan, __isnan"
		size = "46"
		objfiles = "s_isnan@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C DD 44 24 10 DD 1C 24 8B 14 24 F7 DA 0B 14 24 C1 EA 1F 8B 44 24 04 25 FF FF FF 7F 09 C2 B8 00 00 F0 7F 29 D0 C1 E8 1F 83 C4 0C C3 }
	condition:
		$pattern
}

rule __signbit_7aa6ca9e0f3b89018adfd25c9d98ca68 {
	meta:
		aliases = "__GI___signbit, __signbit"
		size = "23"
		objfiles = "s_signbit@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C DD 44 24 10 DD 1C 24 8B 44 24 04 25 00 00 00 80 83 C4 0C C3 }
	condition:
		$pattern
}

rule __GI___finite_0008bd168b8ffff7aeaad093f06f8bce {
	meta:
		aliases = "__finite, __GI___finite"
		size = "31"
		objfiles = "s_finite@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C DD 44 24 10 DD 1C 24 8B 44 24 04 25 FF FF FF 7F 2D 00 00 F0 7F C1 E8 1F 83 C4 0C C3 }
	condition:
		$pattern
}

rule __GI___isinf_e1fceb4644d854b85450d40707e6b5aa {
	meta:
		aliases = "__isinf, __GI___isinf"
		size = "51"
		objfiles = "s_isinf@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C DD 44 24 10 DD 1C 24 8B 4C 24 04 89 CA 81 E2 FF FF FF 7F 81 F2 00 00 F0 7F 0B 14 24 89 D0 F7 D8 09 D0 C1 F8 1F F7 D0 C1 F9 1E 21 C8 83 C4 0C C3 }
	condition:
		$pattern
}

rule __GI_raise_a9ef0b92c90e6c96f4b1888939a72f32 {
	meta:
		aliases = "raise, __raise, __GI_raise"
		size = "24"
		objfiles = "raise@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? 52 52 FF 74 24 18 50 E8 ?? ?? ?? ?? 83 C4 1C C3 }
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

rule on_exit_7ae71cfc075ba261245a88cb7f2e1a63 {
	meta:
		aliases = "on_exit"
		size = "43"
		objfiles = "on_exit@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? 89 C2 83 C8 FF 85 D2 74 16 8B 44 24 10 89 42 04 8B 44 24 14 89 42 08 C7 02 02 00 00 00 31 C0 83 C4 0C C3 }
	condition:
		$pattern
}

rule __pthread_internal_tsd_address_da84f9209c9cecc6220d08d8a948a5e5 {
	meta:
		aliases = "__pthread_internal_tsd_address"
		size = "25"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? 89 C2 8B 44 24 10 8D 84 82 6C 01 00 00 83 C4 0C C3 }
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

rule __pthread_internal_tsd_set_384a24dd9fe4e64d7f759934fa646192 {
	meta:
		aliases = "__pthread_internal_tsd_set"
		size = "29"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? 8B 4C 24 14 8B 54 24 10 89 8C 90 6C 01 00 00 31 C0 83 C4 0C C3 }
	condition:
		$pattern
}

rule pthread_handle_sigrestart_f5b2407126c2ea5a16a7fdbd26b20155 {
	meta:
		aliases = "pthread_handle_sigrestart"
		size = "36"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C E8 ?? ?? ?? ?? 8B 54 24 10 89 50 20 8B 40 24 85 C0 74 0A 52 52 6A 01 50 E8 ?? ?? ?? ?? 83 C4 0C C3 }
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

rule __GI___rpc_thread_svc_max_poll_3b6c04d5bbccaed47f19d67af3adf01d {
	meta:
		aliases = "__rpc_thread_svc_max_pollfd, __GI___rpc_thread_svc_max_pollfd"
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

rule sem_close_86bb2750c653e2882ee6698c514ddcbc {
	meta:
		aliases = "sem_unlink, sem_close"
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

rule putw_f067a416c2ada9b9963f73f6177aafb9 {
	meta:
		aliases = "putw"
		size = "26"
		objfiles = "putw@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 0C FF 74 24 14 6A 01 6A 04 8D 44 24 1C 50 E8 ?? ?? ?? ?? 48 83 C4 1C C3 }
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

rule fseek_7ba7d87fac272bbbbb6337a10e4d8ec0 {
	meta:
		aliases = "__GI_fseek, fseeko, fseek"
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

rule __ieee754_lgamma_6ef4550f4268b481d14e1b0dbb3bef41 {
	meta:
		aliases = "__GI_strtok, __ieee754_gamma, strtok, __GI_lgamma, gamma, lgamma, __ieee754_lgamma"
		size = "25"
		objfiles = "w_lgamma@libm.a, w_gamma@libm.a, e_gamma@libm.a, e_lgamma@libm.a, strtok@libc.a"
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

rule xdrstdio_setpos_8f0be7a08fd20ea1212c233a74c298fb {
	meta:
		aliases = "xdrstdio_setpos"
		size = "30"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 6A 00 FF 74 24 1C 8B 44 24 1C FF 70 0C E8 ?? ?? ?? ?? F7 D0 C1 E8 1F 83 C4 1C C3 }
	condition:
		$pattern
}

rule strtold_1da02766b2a304b7f969428fc4c15b06 {
	meta:
		aliases = "wcstold, __GI_wcstold, __GI_strtold, strtold"
		size = "22"
		objfiles = "strtold@libc.a, wcstold@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 6A 00 FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule wcstof_2ff06c8b56e3ed2678dab280e38803b5 {
	meta:
		aliases = "__GI_wcstof, strtof, __GI_strtof, wcstof"
		size = "49"
		objfiles = "wcstof@libc.a, strtof@libc.a"
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

rule pthread_attr_getschedparam_dfca650f122af66fec7183124e98e3ea {
	meta:
		aliases = "__GI_pthread_attr_getschedparam, pthread_attr_getschedparam"
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

rule atol_e6c5c8392e7b41865e74c28a5b36180c {
	meta:
		aliases = "atoll, __GI_atoi, __GI_atol, atoi, atol"
		size = "20"
		objfiles = "atol@libc.a, atoll@libc.a"
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

rule clntunix_geterr_6657bb1460053cd9e0565b8a646778d0 {
	meta:
		aliases = "clntunix_geterr"
		size = "31"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 8B 44 24 14 8B 40 08 05 84 00 00 00 6A 0C 50 FF 74 24 20 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule clnttcp_geterr_d1ff13d34eab77be9ad70d6ccd0a6747 {
	meta:
		aliases = "clnttcp_geterr"
		size = "29"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 8B 44 24 14 8B 40 08 83 C0 24 6A 0C 50 FF 74 24 20 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule clntudp_geterr_e1ec8a6d91a5bdadaf2f319e9c62aa74 {
	meta:
		aliases = "clntudp_geterr"
		size = "29"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 8B 44 24 14 8B 40 08 83 C0 2C 6A 0C 50 FF 74 24 20 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule mrand48_r_c7069002931132f2dfc08888133d95bf {
	meta:
		aliases = "drand48_r, __GI_lrand48_r, lrand48_r, mrand48_r"
		size = "22"
		objfiles = "lrand48_r@libc.a, drand48_r@libc.a, mrand48_r@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 8B 44 24 14 FF 74 24 18 50 50 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule inet_makeaddr_c803be0b62582a1a1a8b47f56d49a7fd {
	meta:
		aliases = "__GI_inet_makeaddr, inet_makeaddr"
		size = "86"
		objfiles = "inet_addr@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 8B 4C 24 14 8B 54 24 18 8B 44 24 1C 83 FA 7F 77 0A 25 FF FF FF 00 C1 E2 18 EB 22 81 FA FF FF 00 00 77 0A 25 FF FF 00 00 C1 E2 10 EB 10 81 FA FF FF FF 00 77 08 25 FF 00 00 00 C1 E2 08 09 D0 89 44 24 0C 8B 44 24 0C 0F C8 89 01 89 C8 83 C4 10 C2 04 00 }
	condition:
		$pattern
}

rule authunix_marshal_4021ada98bf8084ffa8d040deddf6c4e {
	meta:
		aliases = "authunix_marshal"
		size = "35"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 8B 4C 24 18 8B 44 24 14 8B 40 24 8B 51 04 FF B0 AC 01 00 00 83 C0 1C 50 51 FF 52 0C 83 C4 1C C3 }
	condition:
		$pattern
}

rule fesetround_93800070c0b3b9cd22ccb2d9b3835964 {
	meta:
		aliases = "fesetround"
		size = "49"
		objfiles = "fesetround@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 8B 54 24 14 B8 01 00 00 00 F7 C2 FF F3 FF FF 75 19 D9 7C 24 0E 66 8B 44 24 0E 80 E4 F3 09 D0 66 89 44 24 0E D9 6C 24 0E 31 C0 83 C4 10 C3 }
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

rule fedisableexcept_382e22bfd1e88f8736cc7d3180ee6378 {
	meta:
		aliases = "fedisableexcept"
		size = "40"
		objfiles = "fedisblxcpt@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 9B D9 7C 24 0E 66 8B 44 24 0E 8B 54 24 14 83 E2 3D 09 C2 66 89 54 24 0E D9 6C 24 0E F7 D0 83 E0 3D 83 C4 10 C3 }
	condition:
		$pattern
}

rule feenableexcept_d2116b9e95d7687331f15830cd917111 {
	meta:
		aliases = "feenableexcept"
		size = "42"
		objfiles = "feenablxcpt@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 9B D9 7C 24 0E 66 8B 44 24 0E 8B 54 24 14 83 E2 3D F7 D2 21 C2 66 89 54 24 0E D9 6C 24 0E F7 D0 83 E0 3D 83 C4 10 C3 }
	condition:
		$pattern
}

rule fegetround_a59e37f00a6504ccf9166d0b7fcb24bd {
	meta:
		aliases = "fegetround"
		size = "20"
		objfiles = "fegetround@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 D9 7C 24 0C 8B 44 24 0C 25 00 0C 00 00 83 C4 10 C3 }
	condition:
		$pattern
}

rule fegetexceptflag_bdb8900704f211a0bf03626ea2d20afb {
	meta:
		aliases = "fegetexceptflag"
		size = "32"
		objfiles = "fgetexcptflg@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 DD 7C 24 0E 8B 44 24 18 66 23 44 24 0E 83 E0 3D 8B 54 24 14 66 89 02 31 C0 83 C4 10 C3 }
	condition:
		$pattern
}

rule execv_92df585bcb680a694716f24b55d276c9 {
	meta:
		aliases = "__GI_execv, execv"
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
		aliases = "__libc_creat, __libc_creat64, creat, creat64"
		size = "25"
		objfiles = "creat64@libc.a, open@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 FF 74 24 18 68 41 02 00 00 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule bzero_1a2c0490f5b8cdeeb9221e9da900869e {
	meta:
		aliases = "mq_getattr, gmtime_r, bzero"
		size = "22"
		objfiles = "bzero@libc.a, gmtime_r@libc.a, mq_getsetattr@librt.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 FF 74 24 18 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI_fputwc_unlocked_173166608ee9ab184afff2d4ff75d1ae {
	meta:
		aliases = "putwc_unlocked, fputwc_unlocked, __GI_fputwc_unlocked"
		size = "39"
		objfiles = "fputwc_unlocked@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 FF 74 24 18 6A 01 8D 44 24 1C 50 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 74 04 8B 54 24 10 89 D0 83 C4 0C C3 }
	condition:
		$pattern
}

rule scalblnf_312f3131b70190222fba14e3c3defea1 {
	meta:
		aliases = "scalbnf, frexpf, ldexpf, scalblnf"
		size = "34"
		objfiles = "scalblnf@libm.a, frexpf@libm.a, ldexpf@libm.a, scalbnf@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 10 FF 74 24 18 D9 44 24 18 83 EC 08 DD 1C 24 E8 ?? ?? ?? ?? D9 5C 24 18 D9 44 24 18 83 C4 1C C3 }
	condition:
		$pattern
}

rule vwscanf_207313f1bf35dacd417d7e4d154f43e5 {
	meta:
		aliases = "vwprintf, vscanf, vprintf, __GI_vscanf, vwscanf"
		size = "26"
		objfiles = "vwscanf@libc.a, vscanf@libc.a, vwprintf@libc.a, vprintf@libc.a"
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

rule __GI_asctime_dec9bb6027f4362fd7a2fa48e394d09b {
	meta:
		aliases = "srand48, asctime, inet_ntoa, __GI_inet_ntoa, ether_ntoa, hcreate, __GI_asctime"
		size = "21"
		objfiles = "inet_ntoa@libc.a, srand48@libc.a, ether_addr@libc.a, hsearch@libc.a, asctime@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 68 ?? ?? ?? ?? FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule seed48_0ae95ce91e5b77a2d2152eeb67234a6c {
	meta:
		aliases = "localtime, __GI_localtime, seed48"
		size = "26"
		objfiles = "seed48@libc.a, localtime@libc.a"
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

rule __GI_getopt_73d9a2a92ea759c7f11861a497219353 {
	meta:
		aliases = "getopt, __GI_getopt"
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

rule mkstemp_6bf719c25f6fbaef08052b0889ae3660 {
	meta:
		aliases = "sigpause, atof, __GI_sigpause, mkstemp"
		size = "18"
		objfiles = "atof@libc.a, sigpause@libc.a, mkstemp@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI_sigwait_88a6c5f2fd06a28d10c1d6df0307f4a1 {
	meta:
		aliases = "__sigwait, sigwait, __GI_sigwait"
		size = "41"
		objfiles = "sigwait@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 00 FF 74 24 1C E8 ?? ?? ?? ?? 89 C2 83 C4 10 B8 01 00 00 00 83 FA FF 74 08 8B 44 24 14 89 10 31 C0 83 C4 0C C3 }
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

rule iswalnum_eaca46bf57de9d027c256de54e89e0bb {
	meta:
		aliases = "timelocal, __GI_iswalnum, mkstemp64, mktime, iswalnum"
		size = "18"
		objfiles = "iswalnum@libc.a, mkstemp64@libc.a, mktime@libc.a"
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

rule __GI_iswalpha_44c9108329ea01c01c96bfbe167c0d14 {
	meta:
		aliases = "iswalpha, __GI_iswalpha"
		size = "18"
		objfiles = "iswalpha@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 02 FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule iswblank_12c91398970349ed99af2a374a090970 {
	meta:
		aliases = "__GI_iswblank, iswblank"
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

rule svcerr_weakauth_7720675966c0239ac00d65240257cbfe {
	meta:
		aliases = "iswdigit, __GI_iswdigit, svcerr_weakauth"
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

rule __GI_iswpunct_f01b91b2f7168b88182a0c205db198e3 {
	meta:
		aliases = "iswpunct, __GI_iswpunct"
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

rule iswupper_2a94a97715b7d870b4e9aaefb774a9a4 {
	meta:
		aliases = "__GI_iswupper, iswupper"
		size = "18"
		objfiles = "iswupper@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 0B FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule iswxdigit_3a0e6c29b954679706b683ac4d0f3d31 {
	meta:
		aliases = "__GI_iswxdigit, iswxdigit"
		size = "18"
		objfiles = "iswxdigit@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 6A 0C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule pzero_4a5bbfcf7613b136b7891fc774fb20a7 {
	meta:
		aliases = "pone, pzero"
		size = "175"
		objfiles = "e_j1@libm.a, e_j0@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 DD 44 24 18 DD 14 24 DD 5C 24 08 8B 44 24 0C 25 FF FF FF 7F 3D FF FF 1F 40 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 3D 3D 8A 2E 12 40 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 2A 3D 6C DB 06 40 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 17 3D FF FF FF 3F 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 04 31 C0 31 D2 DD 04 24 D8 C8 D9 E8 DC F1 DD 40 28 D8 CA DC 40 20 D8 CA DC 40 18 D8 CA DC 40 10 D8 CA DC 40 08 D8 CA DC 00 DD 42 20 D8 CB DC 42 18 D8 CB DC 42 10 D8 CB DC 42 08 D8 CB DC 02 DE CB D9 CA D8 C1 DE FA DE C1 83 C4 14 C3 }
	condition:
		$pattern
}

rule qone_090faffb27a1a7ad9f7ca412895660d0 {
	meta:
		aliases = "qone"
		size = "187"
		objfiles = "e_j1@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 DD 44 24 18 DD 14 24 DD 5C 24 08 8B 44 24 0C 25 FF FF FF 7F 3D FF FF 1F 40 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 3D 3D 8A 2E 12 40 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 2A 3D 6C DB 06 40 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 17 3D FF FF FF 3F 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 04 31 C0 31 D2 DD 04 24 D8 C8 D9 E8 DC F1 DD 40 28 D8 CA DC 40 20 D8 CA DC 40 18 D8 CA DC 40 10 D8 CA DC 40 08 D8 CA DC 00 DD 42 28 D8 CB DC 42 20 D8 CB DC 42 18 D8 CB DC 42 10 D8 CB DC 42 08 D8 CB DC 02 DE CB D9 CA DE C1 DE F9 D8 05 ?? ?? ?? ?? DC 34 24 83 C4 14 C3 }
	condition:
		$pattern
}

rule qzero_71164b7aef2bf0d3c25e023ac791aa49 {
	meta:
		aliases = "qzero"
		size = "187"
		objfiles = "e_j0@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 DD 44 24 18 DD 14 24 DD 5C 24 08 8B 44 24 0C 25 FF FF FF 7F 3D FF FF 1F 40 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 3D 3D 8A 2E 12 40 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 2A 3D 6C DB 06 40 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 17 3D FF FF FF 3F 7E 0C B8 ?? ?? ?? ?? BA ?? ?? ?? ?? EB 04 31 C0 31 D2 DD 04 24 D8 C8 D9 E8 DC F1 DD 40 28 D8 CA DC 40 20 D8 CA DC 40 18 D8 CA DC 40 10 D8 CA DC 40 08 D8 CA DC 00 DD 42 28 D8 CB DC 42 20 D8 CB DC 42 18 D8 CB DC 42 10 D8 CB DC 42 08 D8 CB DC 02 DE CB D9 CA DE C1 DE F9 D8 25 ?? ?? ?? ?? DC 34 24 83 C4 14 C3 }
	condition:
		$pattern
}

rule fabs_05a32123bf082b052d4b26451d6753d1 {
	meta:
		aliases = "__GI_fabs, fabs"
		size = "34"
		objfiles = "s_fabs@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 DD 44 24 18 DD 54 24 08 DD 1C 24 8B 44 24 0C 25 FF FF FF 7F 89 44 24 04 DD 04 24 83 C4 14 C3 }
	condition:
		$pattern
}

rule __GI_copysign_f5db861c6e2894e7e6bf1de8b87282f6 {
	meta:
		aliases = "copysign, __GI_copysign"
		size = "46"
		objfiles = "s_copysign@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 DD 44 24 18 DD 54 24 08 DD 1C 24 8B 54 24 24 81 E2 00 00 00 80 8B 44 24 0C 25 FF FF FF 7F 09 C2 89 54 24 04 DD 04 24 83 C4 14 C3 }
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

rule significand_3741d875592b7099d703385e33496ccd {
	meta:
		aliases = "significand"
		size = "53"
		objfiles = "s_significand@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 14 DD 44 24 18 DD 5C 24 08 FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? F7 D8 50 DB 04 24 83 EC 04 DD 1C 24 FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 2C C3 }
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
		objfiles = "spinlock@libpthread.a, join@libpthread.a, semaphore@libpthread.a, pthread@libpthread.a, condvar@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 50 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule hdestroy_07f21806b50c232838a1f6ebf5d39e92 {
	meta:
		aliases = "__pthread_once_fork_parent, getlogin, __GI_getlogin, _flushlbf, __pthread_once_fork_prepare, hdestroy"
		size = "17"
		objfiles = "getlogin@libc.a, hsearch@libc.a, _flushlbf@libc.a, mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule mkfifoat_c072293d91800f7fc13795214e53bfac {
	meta:
		aliases = "mkfifoat"
		size = "32"
		objfiles = "mkfifoat@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 6A 00 6A 00 8B 44 24 2C 80 CC 10 50 FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __GI_tzset_bcd04f4458945647b09065086156a9cb {
	meta:
		aliases = "tzset, __GI_tzset"
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

rule __re_search_2183e4d8f03ca681e9ba33fafe22c649 {
	meta:
		aliases = "re_search, __re_search"
		size = "42"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 8B 44 24 24 50 FF 74 24 34 FF 74 24 34 FF 74 24 34 50 FF 74 24 34 6A 00 6A 00 FF 74 24 3C E8 ?? ?? ?? ?? 83 C4 3C C3 }
	condition:
		$pattern
}

rule re_compile_pattern_54bb38dd9a2c6ee34c76a6dcd3f3f6da {
	meta:
		aliases = "__re_compile_pattern, re_compile_pattern"
		size = "67"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 8B 54 24 24 8A 42 1C 83 E0 E9 83 C8 80 88 42 1C 52 8B 0D ?? ?? ?? ?? 8B 54 24 24 8B 44 24 20 E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 74 0D 8B 14 85 ?? ?? ?? ?? 81 C2 ?? ?? ?? ?? 89 D0 83 C4 0C C3 }
	condition:
		$pattern
}

rule getwchar_unlocked_8d2509fbeabb04bc47cf41d0b9e2530e {
	meta:
		aliases = "_dl_app_init_array, _dl_app_fini_array, getwchar, getwchar_unlocked"
		size = "18"
		objfiles = "getwchar@libc.a, getwchar_unlocked@libc.a, libdl@libdl.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule __free_initshell_memory_84f16f1d403dc995664bac68afe14687 {
	meta:
		aliases = "__free_initshell_memory"
		size = "50"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 58 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 1C C3 }
	condition:
		$pattern
}

rule ctime_24905b5dda7060cf4eb875e8c4bf40ce {
	meta:
		aliases = "__GI_ctime, ctime"
		size = "24"
		objfiles = "ctime@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 18 FF 74 24 1C E8 ?? ?? ?? ?? 89 44 24 20 83 C4 1C E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_wcsrtombs_ce57aba5bc61bf8cfdb2613bdce28092 {
	meta:
		aliases = "wcsrtombs, __GI_wcsrtombs"
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

rule xdrstdio_getlong_bcf753d65df04347dbad1b2cd0800d1b {
	meta:
		aliases = "xdrstdio_getint32, xdrstdio_getlong"
		size = "55"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8B 44 24 20 FF 70 0C 6A 01 6A 04 8D 44 24 24 50 E8 ?? ?? ?? ?? 83 C4 10 31 D2 48 75 11 8B 44 24 18 0F C8 8B 54 24 24 89 02 BA 01 00 00 00 89 D0 83 C4 1C C3 }
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

rule mbstowcs_575ec308ac3d6bb1ddbac925ba2945a0 {
	meta:
		aliases = "mbstowcs"
		size = "46"
		objfiles = "mbstowcs@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8B 44 24 24 89 44 24 18 C7 44 24 10 00 00 00 00 8D 44 24 10 50 FF 74 24 2C 8D 44 24 20 50 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule xdrstdio_putlong_7dc79e05c0a901da8f5fca95c692f5f8 {
	meta:
		aliases = "xdrstdio_putint32, xdrstdio_putlong"
		size = "47"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8B 44 24 24 8B 00 0F C8 89 44 24 18 8B 44 24 20 FF 70 0C 6A 01 6A 04 8D 44 24 24 50 E8 ?? ?? ?? ?? 48 0F 94 C0 0F B6 C0 83 C4 2C C3 }
	condition:
		$pattern
}

rule setrlimit64_ecb4ff5e15d93eac8ba268bb331ea07b {
	meta:
		aliases = "setrlimit64"
		size = "86"
		objfiles = "setrlimit64@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8B 4C 24 24 8B 01 8B 51 04 83 FA 00 77 05 83 F8 FE 76 0A C7 44 24 14 FF FF FF FF EB 04 89 44 24 14 8B 41 08 8B 51 0C 83 FA 00 77 05 83 F8 FE 76 0A C7 44 24 18 FF FF FF FF EB 04 89 44 24 18 50 50 8D 44 24 1C 50 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __libc_open64_065a259e65a14bc1252966bf022b8687 {
	meta:
		aliases = "open64, __GI___libc_open64, __GI_open64, __libc_open64"
		size = "45"
		objfiles = "open64@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8B 54 24 24 31 C0 F6 C2 40 74 0C 8D 44 24 2C 89 44 24 18 8B 44 24 28 51 50 80 CE 80 52 FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule getgrent_975d0e0bc0166ffe58a24e49d939ba0d {
	meta:
		aliases = "getspent, getpwent, getgrent"
		size = "36"
		objfiles = "getspent@libc.a, getgrent@libc.a, getpwent@libc.a"
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

rule printf_84203de9a76a1350b67c27a76abfb69a {
	meta:
		aliases = "wscanf, __GI_printf, wprintf, scanf, printf"
		size = "32"
		objfiles = "printf@libc.a, wprintf@libc.a, scanf@libc.a, wscanf@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8D 44 24 24 89 44 24 18 52 50 FF 74 24 28 FF 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule sprintf_41fec4642f4d9a0c14e4c2b512a44fe9 {
	meta:
		aliases = "__GI_sprintf, sprintf"
		size = "31"
		objfiles = "sprintf@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8D 44 24 28 89 44 24 18 50 FF 74 24 28 6A FF FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule errx_dcce67024a6ef6d0ef2d8cceb00297d8 {
	meta:
		aliases = "err, errx"
		size = "26"
		objfiles = "err@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8D 44 24 28 89 44 24 18 52 50 FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_sscanf_b8d2de1a3389a9ac7063fcf8ecd732a9 {
	meta:
		aliases = "__GI_asprintf, __GI_syslog, __GI_fscanf, fprintf, swscanf, fscanf, asprintf, fwprintf, fwscanf, __GI_fprintf, syslog, dprintf, sscanf, __GI_sscanf"
		size = "30"
		objfiles = "syslog@libc.a, dprintf@libc.a, sscanf@libc.a, fprintf@libc.a, swscanf@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C 8D 44 24 28 89 44 24 18 52 50 FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __GI_snprintf_8bd6d358af3d92600852784dc3535348 {
	meta:
		aliases = "snprintf, swprintf, __GI_snprintf"
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

rule cargf_d3e1ae86040152e59dc1221be9420e09 {
	meta:
		aliases = "cabsf, cargf"
		size = "35"
		objfiles = "cargf@libm.a, cabsf@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C D9 44 24 20 D9 44 24 24 DD 5C 24 08 DD 1C 24 E8 ?? ?? ?? ?? D9 5C 24 18 D9 44 24 18 83 C4 1C C3 }
	condition:
		$pattern
}

rule ilogbf_ae59cb3ea4cc505a336a4a795ec11feb {
	meta:
		aliases = "lrintf, llrintf, lroundf, llroundf, ilogbf"
		size = "19"
		objfiles = "llrintf@libm.a, llroundf@libm.a, lroundf@libm.a, ilogbf@libm.a, lrintf@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C D9 44 24 20 DD 1C 24 E8 ?? ?? ?? ?? 83 C4 1C C3 }
	condition:
		$pattern
}

rule log10f_a4ed7d1ef71bac89a28737c2f33b4283 {
	meta:
		aliases = "expf, sinhf, tanf, asinhf, exp2f, erff, log2f, logbf, atanf, fabsf, sqrtf, acosf, tanhf, floorf, cbrtf, erfcf, tgammaf, truncf, log1pf, lgammaf, coshf, cosf, roundf, atanhf, asinf, sinf, logf, acoshf, expm1f, rintf, ceilf, log10f"
		size = "27"
		objfiles = "log1pf@libm.a, atanf@libm.a, acosf@libm.a, exp2f@libm.a, truncf@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C D9 44 24 20 DD 1C 24 E8 ?? ?? ?? ?? D9 5C 24 18 D9 44 24 18 83 C4 1C C3 }
	condition:
		$pattern
}

rule fmodf_1e2978707d238f6fac2f7eea075fd954 {
	meta:
		aliases = "hypotf, copysignf, atan2f, remainderf, nextafterf, powf, fmodf"
		size = "35"
		objfiles = "fmodf@libm.a, hypotf@libm.a, copysignf@libm.a, atan2f@libm.a, powf@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C D9 44 24 24 DD 5C 24 08 D9 44 24 20 DD 1C 24 E8 ?? ?? ?? ?? D9 5C 24 18 D9 44 24 18 83 C4 1C C3 }
	condition:
		$pattern
}

rule __kernel_sin_f3d76a1a6359cef4b1e507ba527a37b6 {
	meta:
		aliases = "__kernel_sin"
		size = "200"
		objfiles = "k_sin@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C DD 44 24 20 DD 14 24 DD 44 24 28 D9 C9 DD 54 24 08 8B 44 24 0C 25 FF FF FF 7F 3D FF FF 3F 3E 7F 27 D9 7C 24 16 66 8B 44 24 16 80 CC 0C 66 89 44 24 14 D9 6C 24 14 DB 5C 24 10 D9 6C 24 16 8B 44 24 10 85 C0 74 76 EB 02 DD D8 DD 04 24 D8 C8 DD 04 24 D8 C9 DD 05 ?? ?? ?? ?? D8 CA DC 25 ?? ?? ?? ?? D8 CA DC 05 ?? ?? ?? ?? D8 CA DC 25 ?? ?? ?? ?? D8 CA DC 05 ?? ?? ?? ?? 83 7C 24 30 00 75 17 DD DB D9 C9 D9 CA DE CA D9 C9 DC 25 ?? ?? ?? ?? DE C9 DC 04 24 EB 1F D9 C3 D8 0D ?? ?? ?? ?? D9 C9 D8 CA DE E9 DE CA D9 C9 DE E2 DC 0D ?? ?? ?? ?? DE C1 DC 2C 24 DD 1C 24 EB 02 DD D8 DD 04 24 83 C4 1C C3 }
	condition:
		$pattern
}

rule logb_9354d172f2c0c737ea5a3e2746cc22d8 {
	meta:
		aliases = "__GI_logb, logb"
		size = "102"
		objfiles = "s_logb@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C DD 44 24 20 DD 54 24 08 DD 5C 24 10 8B 44 24 14 25 FF FF FF 7F 8B 54 24 10 09 C2 75 1A 50 50 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? 83 C4 10 D8 3D ?? ?? ?? ?? EB 28 3D FF FF EF 7F 7E 08 DD 44 24 08 D8 C8 EB 19 C1 F8 14 75 08 D9 05 ?? ?? ?? ?? EB 0C 2D FF 03 00 00 50 DB 04 24 83 C4 04 83 C4 1C C3 }
	condition:
		$pattern
}

rule getservbyport_16a31ef8f7e62de12459b2fda9de28d5 {
	meta:
		aliases = "getservbyname, __GI_getservbyport, getservbyport"
		size = "52"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C E8 ?? ?? ?? ?? 50 50 8D 44 24 20 50 68 8D 10 00 00 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 3C FF 74 24 3C E8 ?? ?? ?? ?? 8B 44 24 38 83 C4 3C C3 }
	condition:
		$pattern
}

rule __GI_gethostbyaddr_98bcb7b3b137c439cb8c40fcca6ee5ac {
	meta:
		aliases = "gethostbyaddr, __GI_gethostbyaddr"
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

rule gethostbyname_26e7684a2f16b0f611316a12fa264a9b {
	meta:
		aliases = "__GI_gethostbyname, gethostbyname"
		size = "48"
		objfiles = "gethostbyname@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C E8 ?? ?? ?? ?? 52 52 50 8D 44 24 24 50 68 CC 01 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 3C E8 ?? ?? ?? ?? 8B 44 24 38 83 C4 3C C3 }
	condition:
		$pattern
}

rule getprotobyname_cece215ae69e7eef8eca3b3b36f673a2 {
	meta:
		aliases = "getprotobynumber, getprotobyname"
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
		objfiles = "getproto@libc.a, getservice@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C E8 ?? ?? ?? ?? 8D 44 24 18 50 68 8D 10 00 00 FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 44 24 28 83 C4 2C C3 }
	condition:
		$pattern
}

rule get_shm_name_055e4b19a57fbd76bb91ef7035f93ce5 {
	meta:
		aliases = "get_shm_name"
		size = "47"
		objfiles = "shm@librt.a"
	strings:
		$pattern = { ( CC | 83 ) EC 1C EB 01 40 80 38 2F 74 FA 52 50 68 ?? ?? ?? ?? 8D 44 24 24 50 E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 78 04 8B 54 24 18 89 D0 83 C4 1C C3 }
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

rule clearenv_9daca505217589776bb4043ead2bfc59 {
	meta:
		aliases = "clearenv"
		size = "107"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 3B 05 ?? ?? ?? ?? 75 1A 85 C0 74 16 83 EC 0C 50 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 83 C4 10 C7 05 ?? ?? ?? ?? 00 00 00 00 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 31 C0 83 C4 2C C3 }
	condition:
		$pattern
}

rule __GI_setnetent_e8e33c0347b592015d837b52fa78f42e {
	meta:
		aliases = "setnetent, __GI_setnetent"
		size = "115"
		objfiles = "getnetent@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 75 18 50 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? EB 09 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 7C 24 20 00 74 07 C6 05 ?? ?? ?? ?? 01 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __GI_setservent_6625f43fda10d701a72533d551cd40b7 {
	meta:
		aliases = "setservent, __GI_setservent"
		size = "115"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C4 10 85 C0 75 18 50 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? EB 09 83 EC 0C 50 E8 ?? ?? ?? ?? 83 C4 10 83 7C 24 20 00 74 07 C6 05 ?? ?? ?? ?? 01 51 51 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 2C C3 }
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

rule __close_nameservers_9e95a013c65dc18cd2a61096da11d0e3 {
	meta:
		aliases = "__close_nameservers"
		size = "155"
		objfiles = "closenameservers@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 44 24 18 50 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 25 48 A3 ?? ?? ?? ?? 83 EC 0C FF 34 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 04 85 ?? ?? ?? ?? 00 00 00 00 83 C4 10 A1 ?? ?? ?? ?? 85 C0 7F CF EB 28 48 A3 ?? ?? ?? ?? 83 EC 0C FF 34 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? C7 04 85 ?? ?? ?? ?? 00 00 00 00 83 C4 10 A1 ?? ?? ?? ?? 85 C0 7F CF 50 50 6A 01 8D 44 24 18 50 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule strtod_933c5f43d5ab233ccdd1cdce8fe5644f {
	meta:
		aliases = "__GI_wcstod, __GI_strtod, wcstod, strtod"
		size = "49"
		objfiles = "strtod@libc.a, wcstod@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 6A 00 FF 74 24 2C FF 74 24 2C E8 ?? ?? ?? ?? DD 54 24 18 83 EC 10 DB 7C 24 0C DD 44 24 28 DB 3C 24 E8 ?? ?? ?? ?? DD 44 24 28 83 C4 3C C3 }
	condition:
		$pattern
}

rule feraiseexcept_b0ab73eac1b5a1fa77dec2ac00c3b2cd {
	meta:
		aliases = "__GI_feraiseexcept, feraiseexcept"
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

rule tcgetpgrp_f4401064c54adef256659aa6bcec0c6c {
	meta:
		aliases = "__GI_tcgetpgrp, tcgetpgrp"
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

rule jrand48_b4f49879994ad0f55ed666ca9d4a8004 {
	meta:
		aliases = "nrand48, jrand48"
		size = "30"
		objfiles = "nrand48@libc.a, jrand48@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 8D 44 24 1C 50 68 ?? ?? ?? ?? FF 74 24 2C E8 ?? ?? ?? ?? 8B 44 24 28 83 C4 2C C3 }
	condition:
		$pattern
}

rule __GI_tgamma_96393af6e1991ca57572368591bc9b16 {
	meta:
		aliases = "tgamma, __GI_tgamma"
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

rule fesetexceptflag_b4cacb89f02fd9e8f78bcb0eb13ec8a5 {
	meta:
		aliases = "fesetexceptflag"
		size = "49"
		objfiles = "fsetexcptflg@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 20 D9 74 24 04 8B 44 24 28 89 C2 83 E2 3D F7 D2 23 54 24 08 8B 4C 24 24 66 23 01 83 E0 3D 09 C2 66 89 54 24 08 D9 64 24 04 31 C0 83 C4 20 C3 }
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
		aliases = "__GI_send, send, __libc_send"
		size = "51"
		objfiles = "send@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8B 44 24 28 89 44 24 14 8B 44 24 2C 89 44 24 18 8B 44 24 30 89 44 24 1C 8B 44 24 34 89 44 24 20 8D 44 24 14 50 6A 09 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __GI_recv_6ec4911cea1b9f9222b30f8d859d44ff {
	meta:
		aliases = "__libc_recv, recv, __GI_recv"
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

rule bind_6d1ea7ec396d0f9c10cb256f24d761eb {
	meta:
		aliases = "__GI_bind, bind"
		size = "43"
		objfiles = "bind@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8B 44 24 28 89 44 24 18 8B 44 24 2C 89 44 24 1C 8B 44 24 30 89 44 24 20 8D 44 24 18 50 6A 02 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __GI_connect_ba8a3c3562e6535089bbd872abbc9301 {
	meta:
		aliases = "connect, __libc_connect, __GI_connect"
		size = "43"
		objfiles = "connect@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8B 44 24 28 89 44 24 18 8B 44 24 2C 89 44 24 1C 8B 44 24 30 89 44 24 20 8D 44 24 18 50 6A 03 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __GI_accept_681d082753dd4d5bc2087c0f365cb33f {
	meta:
		aliases = "accept, __libc_accept, __GI_accept"
		size = "43"
		objfiles = "accept@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8B 44 24 28 89 44 24 18 8B 44 24 2C 89 44 24 1C 8B 44 24 30 89 44 24 20 8D 44 24 18 50 6A 05 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule getsockname_398e5d068fd58918361146ef3e5cefdf {
	meta:
		aliases = "__GI_getsockname, getsockname"
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

rule sendmsg_1d8d12223f92a0aceb7b64f521572efc {
	meta:
		aliases = "__GI_sendmsg, __libc_sendmsg, sendmsg"
		size = "43"
		objfiles = "sendmsg@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8B 44 24 28 89 44 24 18 8B 44 24 2C 89 44 24 1C 8B 44 24 30 89 44 24 20 8D 44 24 18 50 6A 10 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __GI_recvmsg_7414edcbbe4d5a3ce30b60e65289406d {
	meta:
		aliases = "recvmsg, __libc_recvmsg, __GI_recvmsg"
		size = "43"
		objfiles = "recvmsg@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8B 44 24 28 89 44 24 18 8B 44 24 2C 89 44 24 1C 8B 44 24 30 89 44 24 20 8D 44 24 18 50 6A 11 E8 ?? ?? ?? ?? 83 C4 2C C3 }
	condition:
		$pattern
}

rule __GI_listen_52fed9462e0c70044d975ebc4e489814 {
	meta:
		aliases = "listen, __GI_listen"
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

rule usleep_6cd1b107f1a9065cff663f463b8824dd {
	meta:
		aliases = "usleep"
		size = "48"
		objfiles = "usleep@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 8B 44 24 28 BA 40 42 0F 00 89 D1 31 D2 F7 F1 89 44 24 1C 69 D2 E8 03 00 00 89 54 24 20 6A 00 8D 44 24 20 50 E8 ?? ?? ?? ?? 83 C4 2C C3 }
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

rule __kernel_cos_33049bb2fa56715c3a5106c21015d6ee {
	meta:
		aliases = "__kernel_cos"
		size = "265"
		objfiles = "k_cos@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 C7 44 24 08 00 00 00 00 C7 44 24 0C 00 00 00 00 DD 44 24 28 DD 14 24 DD 44 24 30 D9 C9 DD 54 24 10 8B 54 24 14 81 E2 FF FF FF 7F 81 FA FF FF 3F 3E 7F 2E D9 7C 24 1E 66 8B 44 24 1E 80 CC 0C 66 89 44 24 1C D9 6C 24 1C DB 5C 24 18 D9 6C 24 1E 8B 44 24 18 85 C0 75 0B DD D8 D9 E8 E9 A1 00 00 00 DD D8 DD 04 24 D8 C8 DD 05 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 81 FA 32 33 D3 3F 7F 1C D9 C1 D8 0D ?? ?? ?? ?? D9 CA DE C9 D9 CA DC 0C 24 DD 14 24 DE EA DE E1 D9 E8 EB 44 81 FA 00 00 E9 3F 7E 08 D9 }
	condition:
		$pattern
}

rule __ieee754_scalb_55a9a9ae6176e0543856cd325bb55194 {
	meta:
		aliases = "__ieee754_scalb"
		size = "290"
		objfiles = "e_scalb@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 DD 44 24 28 DD 5C 24 10 DD 44 24 30 DD 5C 24 08 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 16 51 51 FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 0C DD 44 24 08 DC 0C 24 E9 D5 00 00 00 52 52 FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 2F D9 EE DD 04 24 DD E1 DF E0 DD D9 9E 76 0B DD 44 24 08 DE C9 E9 A6 00 00 00 DD D8 DD 04 24 D9 E0 DD 1C 24 DD 44 24 08 DC 34 24 E9 90 00 00 00 50 50 FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? 83 C4 10 DD 04 24 D9 C9 DD E9 DF E0 9E 7A 02 74 08 D9 C0 DE E1 D8 F0 EB 68 DD D8 D9 05 ?? ?? ?? ?? DD 04 24 DA E9 DF E0 9E 76 0A }
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

rule __GI_fmax_da339a516288d0656508c5e16bde8960 {
	meta:
		aliases = "fmax, __GI_fmax"
		size = "100"
		objfiles = "s_fmax@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 DD 44 24 28 DD 5C 24 18 DD 44 24 30 DD 5C 24 10 FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 35 50 50 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 06 DD 44 24 08 EB 11 DD 44 24 10 DD 44 24 08 D9 C9 DD E9 DF E0 9E 77 06 DD 5C 24 10 EB 02 DD D8 DD 44 24 10 83 C4 1C C3 }
	condition:
		$pattern
}

rule __GI_fmin_5d7f195ff648c58407210264d6dde14c {
	meta:
		aliases = "fmin, __GI_fmin"
		size = "102"
		objfiles = "s_fmin@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 24 DD 44 24 28 DD 5C 24 18 DD 44 24 30 DD 5C 24 10 FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 37 50 50 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? 83 C4 10 85 C0 75 06 DD 44 24 08 EB 13 DD 44 24 08 DD 44 24 10 D9 C9 DD E1 DF E0 DD D9 9E 77 06 DD 5C 24 10 EB 02 DD D8 DD 44 24 10 83 C4 1C C3 }
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

rule clock_4f661d5b8256eeaca7f2c7396d935815 {
	meta:
		aliases = "clock"
		size = "36"
		objfiles = "clock@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 28 8D 44 24 18 50 E8 ?? ?? ?? ?? 8B 44 24 1C 03 44 24 20 69 C0 10 27 00 00 25 FF FF FF 7F 83 C4 2C C3 }
	condition:
		$pattern
}

rule fgetpwent_a7773e5d3145ef4863b1ee448a617097 {
	meta:
		aliases = "fgetgrent, sgetspent, fgetspent, getspnam, getpwnam, getgrgid, getpwuid, getgrnam, fgetpwent"
		size = "40"
		objfiles = "getgrnam@libc.a, getgrgid@libc.a, getpwuid@libc.a, getspnam@libc.a, fgetspent@libc.a"
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

rule __GI_wcrtomb_96bfa2933e3da723dc94e1de4e68ccb5 {
	meta:
		aliases = "wcrtomb, __GI_wcrtomb"
		size = "68"
		objfiles = "wcrtomb@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 2C 8B 54 24 30 8B 4C 24 34 85 D2 75 06 8D 54 24 14 31 C9 8D 44 24 28 89 44 24 24 89 4C 24 28 83 EC 0C FF 74 24 44 6A 10 6A 01 8D 44 24 3C 50 52 E8 ?? ?? ?? ?? 83 C4 20 85 C0 75 02 B0 01 83 C4 2C C3 }
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

rule cos_58d947ac4c8a595e79382ab8f32eef92 {
	meta:
		aliases = "__GI_cos, cos"
		size = "216"
		objfiles = "s_cos@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 2C DD 44 24 30 DD 54 24 08 DD 5C 24 10 8B 44 24 14 25 FF FF FF 7F 3D FB 21 E9 3F 7F 0E 6A 00 6A 00 FF 74 24 14 FF 74 24 14 EB 49 3D FF FF EF 7F 7E 0B DD 44 24 08 D8 E0 E9 95 00 00 00 50 8D 44 24 1C 50 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? 83 C4 10 83 E0 03 83 F8 01 74 23 83 F8 02 74 3C 85 C0 75 51 FF 74 24 24 FF 74 24 24 FF 74 24 24 FF 74 24 24 E8 ?? ?? ?? ?? 83 C4 10 EB 54 83 EC 0C 6A 01 FF 74 24 34 FF 74 24 34 FF 74 24 34 FF 74 24 34 E8 ?? ?? ?? ?? D9 E0 EB 33 FF 74 24 24 FF 74 24 24 FF 74 24 24 FF 74 24 24 E8 ?? ?? ?? ?? D9 E0 EB C4 83 EC 0C 6A 01 FF 74 24 34 FF 74 24 34 FF 74 24 34 }
	condition:
		$pattern
}

rule __GI_sin_19d6433546766aa714b264e94141a6fa {
	meta:
		aliases = "sin, __GI_sin"
		size = "221"
		objfiles = "s_sin@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 2C DD 44 24 30 DD 54 24 08 DD 5C 24 10 8B 44 24 14 25 FF FF FF 7F 3D FB 21 E9 3F 7F 13 83 EC 0C 6A 00 6A 00 6A 00 FF 74 24 24 FF 74 24 24 EB 4E 3D FF FF EF 7F 7E 0B DD 44 24 08 D8 E0 E9 95 00 00 00 50 8D 44 24 1C 50 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? 83 C4 10 83 E0 03 83 F8 01 74 28 83 F8 02 74 3A 85 C0 75 54 83 EC 0C 6A 01 FF 74 24 34 FF 74 24 34 FF 74 24 34 FF 74 24 34 E8 ?? ?? ?? ?? 83 C4 20 EB 4F FF 74 24 24 FF 74 24 24 FF 74 24 24 FF 74 24 24 E8 ?? ?? ?? ?? EB 35 83 EC 0C 6A 01 FF 74 24 34 FF 74 24 34 FF 74 24 34 FF 74 24 34 E8 ?? ?? ?? ?? D9 E0 EB C6 FF 74 24 24 FF 74 24 24 FF }
	condition:
		$pattern
}

rule tan_0ad56fb64ac93f7daccdb0e57e31c349 {
	meta:
		aliases = "__GI_tan, tan"
		size = "127"
		objfiles = "s_tan@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 2C DD 44 24 30 DD 54 24 08 DD 5C 24 10 8B 44 24 14 25 FF FF FF 7F 3D FB 21 E9 3F 7F 13 83 EC 0C 6A 01 6A 00 6A 00 FF 74 24 24 FF 74 24 24 EB 41 3D FF FF EF 7F 7E 08 DD 44 24 08 D8 E0 EB 3A 50 8D 44 24 1C 50 FF 74 24 14 FF 74 24 14 E8 ?? ?? ?? ?? 83 E0 01 01 C0 BA 01 00 00 00 29 C2 89 14 24 FF 74 24 34 FF 74 24 34 FF 74 24 34 FF 74 24 34 E8 ?? ?? ?? ?? 83 C4 20 83 C4 2C C3 }
	condition:
		$pattern
}

rule __ieee754_acosh_cfe9c0090d6ee13e51cdcd5e592b8001 {
	meta:
		aliases = "__ieee754_acosh"
		size = "236"
		objfiles = "e_acosh@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 2C DD 44 24 30 DD 54 24 10 DD 54 24 18 8B 54 24 1C 8B 4C 24 18 81 FA FF FF EF 3F 7F 09 D8 E0 D8 F0 E9 C0 00 00 00 DD D8 81 FA FF FF AF 41 7E 30 81 FA FF FF EF 7F 7E 0B DD 44 24 10 D8 C0 E9 A3 00 00 00 50 50 FF 74 24 1C FF 74 24 1C E8 ?? ?? ?? ?? DC 05 ?? ?? ?? ?? 83 C4 10 E9 86 00 00 00 8D 82 00 00 10 C0 09 C8 75 04 D9 EE EB 78 81 FA 00 00 00 40 7E 3B 83 EC 10 DD 44 24 20 D8 C8 DC 25 ?? ?? ?? ?? DD 1C 24 E8 ?? ?? ?? ?? DD 44 24 20 D8 C0 D9 C9 DC 44 24 20 DD 54 24 20 D8 3D ?? ?? ?? ?? DE C1 DD 5C 24 40 83 C4 3C E9 ?? ?? ?? ?? DD 44 24 10 DC 25 ?? ?? ?? ?? 83 EC 10 D9 C0 D8 C1 D9 C1 D8 CA }
	condition:
		$pattern
}

rule ualarm_ed94c7458d6d8bc97bd2954d73dc586d {
	meta:
		aliases = "ualarm"
		size = "80"
		objfiles = "ualarm@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 30 C7 44 24 10 00 00 00 00 8B 44 24 38 89 44 24 14 C7 44 24 18 00 00 00 00 8B 44 24 34 89 44 24 1C 8D 44 24 20 50 8D 44 24 14 50 6A 00 E8 ?? ?? ?? ?? 83 C4 10 83 CA FF 85 C0 78 0C 69 54 24 24 40 42 0F 00 03 54 24 28 89 D0 83 C4 2C C3 }
	condition:
		$pattern
}

rule sendto_410aaa21bf82c35acb5a8f5810fb2da5 {
	meta:
		aliases = "__libc_sendto, __GI_sendto, sendto"
		size = "67"
		objfiles = "sendto@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 34 8B 44 24 38 89 44 24 1C 8B 44 24 3C 89 44 24 20 8B 44 24 40 89 44 24 24 8B 44 24 44 89 44 24 28 8B 44 24 48 89 44 24 2C 8B 44 24 4C 89 44 24 30 8D 44 24 1C 50 6A 0B E8 ?? ?? ?? ?? 83 C4 3C C3 }
	condition:
		$pattern
}

rule __GI_recvfrom_8c80a4f60bdf4fd190baf2fce61d61bf {
	meta:
		aliases = "recvfrom, __libc_recvfrom, __GI_recvfrom"
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

rule __GI_log1p_2c824f54f48ec994c3420ed43b1de782 {
	meta:
		aliases = "log1p, __GI_log1p"
		size = "666"
		objfiles = "s_log1p@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 3C DD 44 24 40 DD 14 24 DD 5C 24 28 8B 54 24 2C 81 FA 79 82 DA 3F 0F 8F 96 00 00 00 89 D1 81 E1 FF FF FF 7F 81 F9 FF FF EF 3F 7E 2B D9 05 ?? ?? ?? ?? DD 04 24 DA E9 DF E0 9E 75 0F 7A 0D D9 EE D8 3D ?? ?? ?? ?? E9 3F 02 00 00 DD 04 24 D8 E0 D8 F0 E9 33 02 00 00 81 F9 FF FF 1F 3E 7F 33 DD 04 24 D8 05 ?? ?? ?? ?? D9 EE D9 C9 DA E9 DF E0 9E 76 0C 81 F9 FF FF 8F 3C 0F 8E 12 02 00 00 DD 04 24 D8 C8 D8 0D ?? ?? ?? ?? DC 04 24 E9 F8 01 00 00 8D 82 3C 41 2D 40 3D 3C 41 2D 40 76 25 DD 04 24 BA 01 00 00 00 D9 EE D9 C9 31 C9 E9 C3 00 00 00 81 FA FF FF EF 7F 7E 0A DD 04 24 D8 C0 E9 C6 01 00 00 81 FA }
	condition:
		$pattern
}

rule svcerr_auth_1a102be13820473ddc99b1d3cfc0b954 {
	meta:
		aliases = "__GI_svcerr_auth, svcerr_auth"
		size = "55"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 44 8B 4C 24 48 C7 44 24 18 01 00 00 00 C7 44 24 1C 01 00 00 00 C7 44 24 20 01 00 00 00 8B 44 24 4C 89 44 24 24 8B 51 08 8D 44 24 14 50 51 FF 52 0C 83 C4 4C C3 }
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

rule __ieee754_exp_c3b72dbf35df8bfa9a1f7ab80a8cead2 {
	meta:
		aliases = "__ieee754_exp"
		size = "496"
		objfiles = "e_exp@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 4C DD 44 24 50 DD 14 24 DD 54 24 30 8B 54 24 34 89 D1 C1 E9 1F 89 D0 25 FF FF FF 7F 3D 41 2E 86 40 76 62 3D FF FF EF 7F 76 23 DD 54 24 28 81 E2 FF FF 0F 00 0B 54 24 28 74 07 D8 C0 E9 A3 01 00 00 DD D8 85 C9 0F 84 9C 01 00 00 EB 31 DD D8 DD 05 ?? ?? ?? ?? DD 04 24 DA E9 DF E0 9E 76 0D DD 05 ?? ?? ?? ?? D8 C8 E9 78 01 00 00 DD 05 ?? ?? ?? ?? DD 04 24 D9 C9 DA E9 DF E0 9E 76 31 D9 EE E9 5F 01 00 00 DD D8 3D 42 2E D6 3F 76 79 3D B1 A2 F0 3F 77 1A DD 04 24 DC 24 CD ?? ?? ?? ?? DD 04 CD ?? ?? ?? ?? 89 C8 F7 D8 29 C8 40 EB 4F DD 04 24 DC 0D ?? ?? ?? ?? DC 04 CD ?? ?? ?? ?? D9 7C 24 46 66 8B 44 }
	condition:
		$pattern
}

rule __ieee754_acos_086701683039a127d4be196d1c178b5b {
	meta:
		aliases = "__ieee754_acos"
		size = "555"
		objfiles = "e_acos@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 4C DD 44 24 50 DD 54 24 18 DD 54 24 30 8B 54 24 34 89 D0 25 FF FF FF 7F 3D FF FF EF 3F 7E 32 DD 5C 24 28 2D 00 00 F0 3F 0B 44 24 28 75 16 85 D2 7E 07 D9 EE E9 EC 01 00 00 DD 05 ?? ?? ?? ?? E9 E1 01 00 00 DD 44 24 18 D8 E0 D8 F0 E9 D4 01 00 00 DD D8 3D FF FF DF 3F 0F 8F 8B 00 00 00 3D 00 00 60 3C 7F 0B DD 05 ?? ?? ?? ?? E9 B5 01 00 00 DD 44 24 18 D8 C8 DD 05 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DC 25 ?? ?? ?? ?? D8 C9 DC 05 ?? ?? ?? ?? D8 C9 DD 05 ?? ?? ?? ?? D8 CA DC 25 ?? ?? ?? ?? D8 CA DC 05 ?? ?? ?? ?? D8 CA DC 25 ?? ?? ?? ?? DE CA }
	condition:
		$pattern
}

rule __GI_isatty_e2010327c8c72c43d69a91e098ac602c {
	meta:
		aliases = "isatty, __GI_isatty"
		size = "29"
		objfiles = "isatty@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 54 8D 44 24 18 50 FF 74 24 5C E8 ?? ?? ?? ?? 85 C0 0F 94 C0 0F B6 C0 83 C4 5C C3 }
	condition:
		$pattern
}

rule direxists_410f7608a0239783125b60e6d57af8e7 {
	meta:
		aliases = "direxists"
		size = "48"
		objfiles = "tempname@libc.a"
	strings:
		$pattern = { ( CC | 83 ) EC 74 8D 54 24 1C 52 50 E8 ?? ?? ?? ?? 83 C4 10 31 D2 85 C0 75 13 8B 44 24 24 25 00 F0 00 00 31 D2 3D 00 40 00 00 0F 94 C2 89 D0 83 C4 6C C3 }
	condition:
		$pattern
}

rule expm1_d88154254719242540cfc0a6177173d1 {
	meta:
		aliases = "__GI_expm1, expm1"
		size = "719"
		objfiles = "s_expm1@libm.a"
	strings:
		$pattern = { ( CC | 83 ) EC 7C DD 84 24 80 00 00 00 DD 14 24 DD 54 24 50 8B 54 24 54 89 D1 81 E1 00 00 00 80 89 D0 25 FF FF FF 7F 3D 79 68 43 40 76 73 3D 41 2E 86 40 76 49 3D FF FF EF 7F 76 23 DD 54 24 48 81 E2 FF FF 0F 00 0B 54 24 48 74 07 D8 C0 E9 75 02 00 00 DD D8 85 C9 0F 84 6E 02 00 00 EB 37 DD D8 DD 05 ?? ?? ?? ?? DD 04 24 DA E9 DF E0 9E 76 0F DD 05 ?? ?? ?? ?? D8 C8 E9 4A 02 00 00 DD D8 85 C9 74 60 DD 04 24 DC 05 ?? ?? ?? ?? D9 EE DA E9 DF E0 9E 76 4A D9 05 ?? ?? ?? ?? E9 27 02 00 00 DD D8 3D 42 2E D6 3F 0F 86 97 00 00 00 3D B1 A2 F0 3F 77 2B 85 C9 75 13 DD 04 24 DC 25 ?? ?? ?? ?? DD 05 ?? ?? ?? ?? B1 01 EB }
	condition:
		$pattern
}

rule d_make_comp_5db324b0a41e386f7fb57c31fb0fee29 {
	meta:
		aliases = "d_make_comp"
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

rule init_error_tables_e50ef9f6720f8c97dd31a6d8a2acf7fd {
	meta:
		aliases = "init_signal_tables, init_error_tables"
		size = "163"
		objfiles = "strsignal@libiberty.a, strerror@libiberty.a"
	strings:
		$pattern = { ( CC | 8B ) 05 ?? ?? ?? ?? 85 C0 75 29 31 C0 BA ?? ?? ?? ?? 0F 1F 80 00 00 00 00 8B 0A 8D 71 01 39 C1 0F 4D C6 48 83 C2 10 48 83 7A 08 00 75 EB 89 05 ?? ?? ?? ?? 48 83 3D ?? ?? ?? ?? 00 74 03 C3 66 90 55 53 48 83 EC 08 8B 05 ?? ?? ?? ?? 8D 2C C5 00 00 00 00 48 63 ED 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 48 89 05 ?? ?? ?? ?? 74 2F 48 89 EA 31 F6 48 89 C7 E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 0F 1F 40 00 48 63 32 48 83 C2 10 48 89 0C F3 48 8B 4A 08 48 85 C9 75 EC 48 83 C4 08 5B 5D C3 }
	condition:
		$pattern
}

rule elem_compare_c4f4bfd59bfdc2921bec650d7161647a {
	meta:
		aliases = "elem_compare"
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
		size = "56"
		objfiles = "allocrtsig@libc.a, pthread@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 0D ?? ?? ?? ?? 83 F9 FF 74 27 8B 15 ?? ?? ?? ?? 39 D1 7F 1D 83 7C 24 04 00 74 0A 8D 41 01 A3 ?? ?? ?? ?? EB 0F 8D 42 FF A3 ?? ?? ?? ?? 89 D1 EB 03 83 C9 FF 89 C8 C3 }
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

rule _dl_unmap_cache_dec1be4a29d44a0aa12de95486fefb4b {
	meta:
		aliases = "_dl_unmap_cache"
		size = "63"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { ( CC | 8B ) 15 ?? ?? ?? ?? 8D 42 FF 83 C9 FF 83 F8 FD 77 2B 8B 0D ?? ?? ?? ?? 87 D3 B8 5B 00 00 00 CD 80 87 D3 3D 00 F0 FF FF 76 07 F7 D8 A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 31 C9 89 C8 C3 }
	condition:
		$pattern
}

rule md5_read_ctx_a04181dc7c20e88560d125749673b140 {
	meta:
		aliases = "md5_read_ctx"
		size = "26"
		objfiles = "md5@libiberty.a"
	strings:
		$pattern = { ( CC | 8B ) 17 48 89 F0 89 16 8B 57 04 89 56 04 8B 57 08 89 56 08 8B 57 0C 89 56 0C C3 }
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
		aliases = "__GI___finitef, __finitef"
		size = "18"
		objfiles = "s_finitef@libm.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 25 FF FF FF 7F 2D 00 00 80 7F C1 E8 1F C3 }
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

rule __libc_sa_len_638dd6e6dec621511e6198e75f05a097 {
	meta:
		aliases = "__libc_sa_len"
		size = "53"
		objfiles = "sa_len@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 66 83 F8 02 74 25 77 06 66 48 75 16 EB 0E 66 83 F8 04 74 17 66 83 F8 0A 75 08 EB 09 B8 6E 00 00 00 C3 31 C0 C3 B8 1C 00 00 00 C3 B8 10 00 00 00 C3 }
	condition:
		$pattern
}

rule htons_abb47f3111edd8b51bf0127264a91b58 {
	meta:
		aliases = "ntohs, htons"
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
		size = "8"
		objfiles = "toascii@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 83 E0 7F C3 }
	condition:
		$pattern
}

rule __GI_wcschrnul_442b63eb143177bcce8466cf95c95ef6 {
	meta:
		aliases = "wcschrnul, __GI_wcschrnul"
		size = "23"
		objfiles = "wcschrnul@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 83 E8 04 83 C0 04 8B 10 85 D2 74 06 3B 54 24 08 75 F1 C3 }
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

rule btowc_a1224ff3f0aa6828e1ce619685927b9d {
	meta:
		aliases = "__GI_btowc, btowc"
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

rule __GI_wcschr_9ff3205df0b8267166b22fe796ca03bc {
	meta:
		aliases = "wcschr, __GI_wcschr"
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
		size = "23"
		objfiles = "remque@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 10 8B 40 04 85 D2 74 03 89 42 04 85 C0 74 02 89 10 C3 }
	condition:
		$pattern
}

rule __pthread_mutexattr_getkind_np_f1910983a54cef9177564bec55e19797 {
	meta:
		aliases = "__GI_pthread_attr_getdetachstate, pthread_mutexattr_getkind_np, pthread_rwlockattr_getkind_np, pthread_mutexattr_gettype, pthread_attr_getdetachstate, __pthread_mutexattr_gettype, __pthread_mutexattr_getkind_np"
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
		size = "47"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 10 8B 44 24 08 8B 00 31 C9 39 C2 74 1A B1 01 85 D2 74 14 83 C9 FF 85 C0 74 0D 89 44 24 08 89 54 24 04 E9 ?? ?? ?? ?? 89 C8 C3 }
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

rule xdrstdio_destroy_dc8ca3cc6c0bf02202e93dd779d2d651 {
	meta:
		aliases = "xdrstdio_getpos, hasmntopt, xdrstdio_destroy"
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

rule __GI_xdrrec_endofrecord_4f7a51b732df0b0df192d4ee7bb5842f {
	meta:
		aliases = "xdrrec_endofrecord, __GI_xdrrec_endofrecord"
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
		size = "23"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 50 04 31 C0 EB 07 03 02 29 D0 8B 52 04 85 D2 75 F5 C3 }
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

rule __fpurge_fef2ad89de321ac412068bd12d2ea293 {
	meta:
		aliases = "__fpurge"
		size = "42"
		objfiles = "__fpurge@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 50 08 89 50 18 89 50 1C 89 50 10 89 50 14 C7 40 28 00 00 00 00 C7 40 2C 00 00 00 00 C6 40 02 00 66 83 20 BC C3 }
	condition:
		$pattern
}

rule __new_sem_getvalue_bf01487b64a973dd33d77632c300357d {
	meta:
		aliases = "sem_getvalue, __new_sem_getvalue"
		size = "16"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 50 08 8B 44 24 08 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule __GI_pthread_attr_getinheritsc_467a4efaa4ddb4792886d5ffa5b1df1c {
	meta:
		aliases = "pthread_attr_getinheritsched, __GI_pthread_attr_getinheritsched"
		size = "16"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 50 0C 8B 44 24 08 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule __GI_pthread_attr_getscope_017ad18cec422befc27664a9ac92e393 {
	meta:
		aliases = "pthread_attr_getscope, __GI_pthread_attr_getscope"
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
		size = "16"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 50 14 8B 44 24 08 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_attr_getstackaddr_c88e6caf6b9456cde7277674cbdadb30 {
	meta:
		aliases = "__pthread_attr_getstackaddr, pthread_attr_getstackaddr"
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

rule __init_scan_cookie_0bf6f56b3545264c082624926bcccfbf {
	meta:
		aliases = "__init_scan_cookie"
		size = "72"
		objfiles = "__scan_cookie@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 08 89 50 08 C7 40 0C 00 00 00 00 C6 40 19 00 31 C9 F6 02 02 74 03 8B 4A 28 89 48 14 C6 40 1A 00 C6 40 1B 00 C7 40 30 ?? ?? ?? ?? C7 40 3C ?? ?? ?? ?? C7 40 34 01 00 00 00 C7 40 38 2E 00 00 00 C3 }
	condition:
		$pattern
}

rule __GI_srand48_r_7e6e7a10a66336236e0a67fb1ae87d7f {
	meta:
		aliases = "srand48_r, __GI_srand48_r"
		size = "55"
		objfiles = "srand48_r@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 08 89 C1 C1 F9 10 66 89 4A 04 66 89 42 02 66 C7 02 0E 33 C7 42 10 6D E6 EC DE C7 42 14 05 00 00 00 66 C7 42 0C 0B 00 66 C7 42 0E 01 00 31 C0 C3 }
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

rule svcfd_create_e63fbd4454ec064dc8f9d0b775e2be85 {
	meta:
		aliases = "svcunixfd_create, svcfd_create"
		size = "17"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
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

rule __GI_sigwaitinfo_2aa34826b54f8b832f45f541b8504e96 {
	meta:
		aliases = "sigwaitinfo, __GI_sigwaitinfo"
		size = "23"
		objfiles = "__rt_sigtimedwait@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 08 C7 44 24 04 08 00 00 00 31 C9 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdrstdio_create_3292d2dc2e660b60c583d2a71577fbb3 {
	meta:
		aliases = "xdrstdio_create"
		size = "39"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 8B 54 24 0C 89 10 C7 40 04 ?? ?? ?? ?? 8B 54 24 08 89 50 0C C7 40 14 00 00 00 00 C7 40 10 00 00 00 00 C3 }
	condition:
		$pattern
}

rule abs_9206eec894c56790c6ede6426d1a11e1 {
	meta:
		aliases = "labs, abs"
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

rule __GI_ffs_2b5de0c83bb80eca92d688540d0592ff {
	meta:
		aliases = "ffs, __GI_ffs"
		size = "65"
		objfiles = "ffs@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 04 B2 01 66 85 C0 75 05 C1 F8 10 B2 11 84 C0 75 06 83 C2 08 C1 F8 08 A8 0F 75 06 83 C2 04 C1 F8 04 A8 03 75 06 83 C2 02 C1 F8 02 31 C9 85 C0 74 0A 40 83 E0 01 0F BE D2 8D 0C 10 89 C8 C3 }
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

rule __pthread_mutexattr_init_a8bcb8367c737460394990dca0e230b0 {
	meta:
		aliases = "pthread_mutexattr_init, __pthread_mutexattr_init"
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

rule openat64_27fdaf8728193a1191e5f313db07dbf9 {
	meta:
		aliases = "__GI_openat64, openat64"
		size = "16"
		objfiles = "openat64@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 44 24 0C 80 CC 80 89 44 24 0C E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule htab_collisions_efdb2a82d6506f1a578969f8336a37d9 {
	meta:
		aliases = "htab_collisions"
		size = "30"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 8B ) 47 38 66 0F 57 C0 85 C0 74 11 8B 57 3C F2 48 0F 2A C8 F2 48 0F 2A C2 F2 0F 5E C1 F3 C3 }
	condition:
		$pattern
}

rule __GI___isinff_4badbf104b1929e81db8af33a081a1da {
	meta:
		aliases = "__isinff, __GI___isinff"
		size = "35"
		objfiles = "s_isinff@libm.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 89 CA 81 E2 FF FF FF 7F 81 F2 00 00 80 7F 89 D0 F7 D8 09 D0 C1 F8 1F F7 D0 C1 F9 1E 21 C8 C3 }
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

rule xdrmem_getlong_25d25932753fcc2fe75ccaef4f4e35de {
	meta:
		aliases = "xdrmem_getint32, xdrmem_getlong"
		size = "45"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 41 14 31 D2 83 F8 03 76 1C 83 E8 04 89 41 14 8B 41 0C 8B 00 0F C8 8B 54 24 08 89 02 83 41 0C 04 BA 01 00 00 00 89 D0 C3 }
	condition:
		$pattern
}

rule xdrmem_putint32_aa5b511a42f19d4cfd6101fefbe8d32a {
	meta:
		aliases = "xdrmem_putlong, xdrmem_putint32"
		size = "45"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 41 14 31 D2 83 F8 03 76 1C 83 E8 04 89 41 14 8B 44 24 08 8B 00 0F C8 8B 51 0C 89 02 83 41 0C 04 BA 01 00 00 00 89 D0 C3 }
	condition:
		$pattern
}

rule sigisemptyset_c1404c6b076b7ee6786ea78a6701833a {
	meta:
		aliases = "sigisemptyset"
		size = "33"
		objfiles = "sigisempty@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 41 7C BA 1F 00 00 00 EB 03 8B 04 91 85 C0 75 03 4A 79 F6 85 C0 0F 94 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule __GI_iswctype_fcd4cc5d484e7871917d7914951c8ea3 {
	meta:
		aliases = "iswctype, __GI_iswctype"
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
		size = "27"
		objfiles = "__longjmp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 44 24 08 8B 51 14 8B 19 8B 71 04 8B 79 08 8B 69 0C 8B 61 10 FF E2 }
	condition:
		$pattern
}

rule strnlen_2627ae82c3a3a930f82b5500b21212d8 {
	meta:
		aliases = "__GI_strnlen, strnlen"
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

rule __GI__seterr_reply_3164b676154a517da321918e069dd174 {
	meta:
		aliases = "_seterr_reply, __GI__seterr_reply"
		size = "223"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 04 8B 54 24 08 8B 41 08 85 C0 74 09 48 0F 85 8B 00 00 00 EB 59 8B 41 18 85 C0 75 07 C7 02 00 00 00 00 C3 83 F8 05 77 37 FF 24 85 ?? ?? ?? ?? C7 02 08 00 00 00 EB 73 C7 02 09 00 00 00 EB 6B C7 02 0A 00 00 00 EB 63 C7 02 0B 00 00 00 EB 5B C7 02 0C 00 00 00 EB 53 C7 02 00 00 00 00 EB 4B C7 02 10 00 00 00 C7 42 04 00 00 00 00 EB 2B 8B 41 0C 85 C0 74 07 83 F8 01 75 12 EB 08 C7 02 06 00 00 00 EB 26 C7 02 07 00 00 00 EB 1E C7 02 10 00 00 00 C7 42 04 01 00 00 00 89 42 08 EB 0C C7 02 10 00 00 00 8B 41 08 89 42 04 8B 02 83 F8 07 74 17 83 F8 09 74 19 83 F8 06 75 20 8B 41 10 89 42 04 8B 41 14 89 }
	condition:
		$pattern
}

rule svcunix_getargs_5505a2426bca0e46df0666a9dde0cad6 {
	meta:
		aliases = "svctcp_getargs, svcunix_getargs"
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
		size = "28"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 08 8B 44 24 0C 89 44 24 08 8B 44 24 04 8B 40 30 83 C0 08 89 44 24 04 FF E1 }
	condition:
		$pattern
}

rule wcscpy_66594f22f089e8ab8867bac27481e917 {
	meta:
		aliases = "__GI_wcscpy, wcscpy"
		size = "27"
		objfiles = "wcscpy@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 08 8B 54 24 04 8B 01 89 02 83 C2 04 83 C1 04 85 C0 75 F2 8B 44 24 04 C3 }
	condition:
		$pattern
}

rule __GI_wcscat_ee20ad29a8fd751d79d67a920679f941 {
	meta:
		aliases = "wcscat, __GI_wcscat"
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
		size = "35"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 4C 24 08 8B 54 24 0C 8B 44 24 04 8B 40 30 C7 40 08 02 00 00 00 89 54 24 08 83 C0 08 89 44 24 04 FF E1 }
	condition:
		$pattern
}

rule __GI_wmemchr_0f94b3815a389062d9126f0f515c4037 {
	meta:
		aliases = "wmemchr, __GI_wmemchr"
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
		size = "18"
		objfiles = "dl_support@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 50 1C 89 15 ?? ?? ?? ?? 8B 40 2C A3 ?? ?? ?? ?? C3 }
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

rule wcsrchr_ae16100322b3f4bc188f7eb2d345bec9 {
	meta:
		aliases = "wcsrchr"
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

rule __GI___isnanf_bae6dd348368f7427b80c7a876984d20 {
	meta:
		aliases = "__isnanf, __GI___isnanf"
		size = "21"
		objfiles = "s_isnanf@libm.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 81 E2 FF FF FF 7F B8 00 00 80 7F 29 D0 C1 E8 1F C3 }
	condition:
		$pattern
}

rule towupper_48138e3d9f8c60c2c473cafe14662f16 {
	meta:
		aliases = "__GI_towupper, towlower, __GI_towlower, towupper"
		size = "21"
		objfiles = "towlower@libc.a, towupper@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 83 FA 7F 77 09 A1 ?? ?? ?? ?? 0F BF 14 50 89 D0 C3 }
	condition:
		$pattern
}

rule __GI_wcslen_95bb5ca1b15db730fbdf52d886799988 {
	meta:
		aliases = "wcslen, __GI_wcslen"
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

rule crypt_38ed92938727a36a8915df8cc6033228 {
	meta:
		aliases = "crypt"
		size = "43"
		objfiles = "crypt@libcrypt.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 44 24 08 80 38 24 75 11 80 78 01 31 75 0B 80 78 02 24 75 05 E9 ?? ?? ?? ?? 89 44 24 08 89 54 24 04 E9 ?? ?? ?? ?? }
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

rule pthread_attr_setstackaddr_a0613757e730bad6d782fdcbd86589ca {
	meta:
		aliases = "__pthread_attr_setstackaddr, pthread_attr_setstackaddr"
		size = "21"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 44 24 08 89 42 1C C7 42 18 01 00 00 00 31 C0 C3 }
	condition:
		$pattern
}

rule stpcpy_e85acb712e464efe694ecc781bc67b25 {
	meta:
		aliases = "__GI_stpcpy, stpcpy"
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
		size = "50"
		objfiles = "xdr_float@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 4C 24 08 8B 02 83 F8 01 74 0A 73 17 8B 42 04 8B 48 04 EB 0D 8B 42 04 89 4C 24 08 89 54 24 04 8B 08 FF E1 83 F8 02 0F 94 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule xdr_int32_t_b99c859feb793efa5ddaf9bf8c665f60 {
	meta:
		aliases = "xdr_uint32_t, xdr_int32_t"
		size = "51"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 4C 24 08 8B 02 83 F8 01 74 0A 73 18 8B 42 04 8B 48 24 EB 0E 8B 42 04 89 4C 24 08 89 54 24 04 8B 48 20 FF E1 83 F8 02 0F 94 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule __GI_xdr_long_f060e38d16e332385a915687f429ce46 {
	meta:
		aliases = "xdr_long, __GI_xdr_long"
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
		size = "83"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 4C 24 08 C7 02 00 00 00 00 C7 42 04 00 00 00 00 C7 42 08 00 00 00 00 C7 42 0C 00 00 00 00 C7 42 10 00 00 00 00 C7 42 14 00 00 00 00 85 C9 75 10 C7 42 18 01 00 00 00 C7 42 1C 00 00 00 00 EB 0B 8B 01 89 42 18 8B 41 04 89 42 1C 31 C0 C3 }
	condition:
		$pattern
}

rule __GI_wcscmp_e91a61111c295dab6c061b7848cdcf0d {
	meta:
		aliases = "wcscmp, __GI_wcscoll, wcscoll, __GI_wcscmp"
		size = "36"
		objfiles = "wcscmp@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 8B 4C 24 08 EB 0E 83 3A 00 75 03 31 C0 C3 83 C2 04 83 C1 04 8B 01 39 02 74 EC 19 C0 83 C8 01 C3 }
	condition:
		$pattern
}

rule toupper_d7d4521aee6b4c2c35428947fe099a90 {
	meta:
		aliases = "__GI_tolower, tolower, __GI_toupper, toupper"
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

rule l64a_29852ed5ad15658e6250b2f8dc4a7abd {
	meta:
		aliases = "l64a"
		size = "54"
		objfiles = "l64a@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 B8 ?? ?? ?? ?? 31 C9 85 D2 75 16 C3 89 D0 83 E0 3F 8A 80 ?? ?? ?? ?? 88 81 ?? ?? ?? ?? C1 EA 06 41 85 D2 75 E7 C6 81 ?? ?? ?? ?? 00 B8 ?? ?? ?? ?? C3 }
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

rule __scan_ungetc_11228ccd939619491824ece6f7d5f8a6 {
	meta:
		aliases = "__scan_ungetc"
		size = "36"
		objfiles = "__scan_cookie@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 04 FF 42 10 8A 42 19 3C 02 75 0A C6 42 19 00 8B 42 04 89 02 C3 84 C0 75 07 C6 42 19 01 FF 4A 0C C3 }
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

rule __old_sem_getvalue_015685ac5f7e150c3820945fc53a4e2c {
	meta:
		aliases = "__old_sem_getvalue"
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
		size = "32"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 8B 44 24 04 8B 40 04 85 C0 74 08 39 D0 73 F5 39 10 72 F1 85 C0 0F 95 C0 0F B6 C0 C3 }
	condition:
		$pattern
}

rule __pthread_attr_setstacksize_b6965425ae27b0150c591b7fc658a2d7 {
	meta:
		aliases = "pthread_attr_setstacksize, __pthread_attr_setstacksize"
		size = "27"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 B8 16 00 00 00 81 FA FF 3F 00 00 76 09 8B 44 24 04 89 50 20 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_condattr_setpshared_e2e13198bfa7a09b07b01a90b52bdfa4 {
	meta:
		aliases = "__pthread_mutexattr_setpshared, pthread_mutexattr_setpshared, pthread_condattr_setpshared"
		size = "22"
		objfiles = "condvar@libpthread.a, mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 B8 16 00 00 00 83 FA 01 77 07 19 C0 F7 D0 83 E0 26 C3 }
	condition:
		$pattern
}

rule __GI_pthread_attr_setdetachsta_7d2bf4c3248c20b172c5bb9a6c21fd7c {
	meta:
		aliases = "pthread_attr_setdetachstate, pthread_rwlockattr_setkind_np, __GI_pthread_attr_setdetachstate"
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

rule __GI_pthread_attr_setschedpoli_3f713cd82669e1afbef6384c0d61c4a9 {
	meta:
		aliases = "pthread_attr_setschedpolicy, __GI_pthread_attr_setschedpolicy"
		size = "24"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 B8 16 00 00 00 83 FA 02 77 09 8B 44 24 04 89 50 04 31 C0 C3 }
	condition:
		$pattern
}

rule pthread_mutexattr_setkind_np_c966b71060253b953a535d91cc13d1cf {
	meta:
		aliases = "pthread_mutexattr_settype, __pthread_mutexattr_settype, __pthread_mutexattr_setkind_np, pthread_mutexattr_setkind_np"
		size = "23"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { ( CC | 8B ) 54 24 08 B8 16 00 00 00 83 FA 03 77 08 8B 44 24 04 89 10 31 C0 C3 }
	condition:
		$pattern
}

rule partition_new_74244911927ee0c5f6f2cb7e90a76dc4 {
	meta:
		aliases = "partition_new"
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
		size = "214"
		objfiles = "crtfastmath"
	strings:
		$pattern = { ( CC | 8D ) 4C 24 04 83 E4 F0 FF 71 FC 55 89 E5 57 56 53 51 81 EC 18 02 00 00 E8 00 00 00 00 5B 81 C3 ?? ?? ?? ?? 9C 9C 5A 89 D0 81 F2 00 00 20 00 52 9D 9C 5A 9D 31 D0 A9 00 00 20 00 74 54 31 C0 87 DE 0F A2 87 DE 85 C0 74 48 B8 01 00 00 00 87 DF 0F A2 87 DF 89 D6 F7 C2 00 00 00 02 74 33 0F AE 9D E4 FD FF FF 8B BD E4 FD FF FF 89 F8 80 CC 80 89 85 E0 FD FF FF 81 E6 00 00 00 01 75 1F 8B 95 E0 FD FF FF 89 95 E4 FD FF FF 0F AE 95 E4 FD FF FF 8D 65 F0 59 5B 5E 5F 5D 8D 61 FC C3 8D 85 E8 FD FF FF 52 68 00 02 00 00 6A 00 50 E8 ?? ?? ?? ?? 0F AE 85 E8 FD FF FF 83 C4 10 81 CF 40 80 00 00 F6 85 04 FE FF FF 40 0F }
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

rule getpagesize_1aa5a313fb0e75d8095bb092c574fd16 {
	meta:
		aliases = "__getpagesize, __GI_getpagesize, getpagesize"
		size = "19"
		objfiles = "getpagesize@libc.a"
	strings:
		$pattern = { ( CC | A1 ) ?? ?? ?? ?? BA 00 10 00 00 85 C0 74 02 89 C2 89 D0 C3 }
	condition:
		$pattern
}

rule __GI___fpclassifyf_d0760ed233543fbe2ab9f26c5c4d0481 {
	meta:
		aliases = "__fpclassifyf, __GI___fpclassifyf"
		size = "49"
		objfiles = "s_fpclassifyf@libm.a"
	strings:
		$pattern = { ( CC | B8 ) 02 00 00 00 8B 54 24 04 81 E2 FF FF FF 7F 74 1F B0 03 81 FA FF FF 7F 00 76 15 B0 04 81 FA FF FF 7F 7F 76 0B 31 C0 81 FA 00 00 80 7F 0F 96 C0 C3 }
	condition:
		$pattern
}

rule __GI_localeconv_5103b042467f0d3949b3e064e2091f16 {
	meta:
		aliases = "localeconv, __GI_localeconv"
		size = "53"
		objfiles = "localeconv@libc.a"
	strings:
		$pattern = { ( CC | B8 ) ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 83 C0 04 C7 00 ?? ?? ?? ?? 3D ?? ?? ?? ?? 72 F0 B8 ?? ?? ?? ?? C6 00 7F 40 3D ?? ?? ?? ?? 76 F5 B8 ?? ?? ?? ?? C3 }
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

rule fibheap_new_a8e74c40b27797e9696ef9fe8016ef07 {
	meta:
		aliases = "fibheap_new"
		size = "15"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | BE ) 18 00 00 00 BF 01 00 00 00 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule md5_init_ctx_785a9f69cbb00f34f11c6385aac1fc08 {
	meta:
		aliases = "md5_init_ctx"
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
		size = "42"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { ( CC | C7 ) 40 14 00 00 00 00 C7 40 10 00 00 00 00 C7 00 01 23 45 67 C7 40 04 89 AB CD EF C7 40 08 FE DC BA 98 C7 40 0C 76 54 32 10 C3 }
	condition:
		$pattern
}

rule difftime_9e4ea5c9e61e1d829edaa7983571f49a {
	meta:
		aliases = "difftime"
		size = "9"
		objfiles = "difftime@libc.a"
	strings:
		$pattern = { ( CC | DB ) 44 24 08 DA 6C 24 04 C3 }
	condition:
		$pattern
}

rule fma_394493ef54a844d9006d78ae6390ed25 {
	meta:
		aliases = "__GI_fma, fma"
		size = "13"
		objfiles = "s_fma@libm.a"
	strings:
		$pattern = { ( CC | DD ) 44 24 0C DC 4C 24 04 DC 44 24 14 C3 }
	condition:
		$pattern
}

rule __GI_carg_4aef79cd6c2785d18b6a685d2b1fd7ee {
	meta:
		aliases = "carg, __GI_carg"
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

