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

rule htab_hash_string_a26de71712c83fd95de6abf1b3cdc165 {
	meta:
		aliases = "htab_hash_string"
		size = "43"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 0F ) B6 17 31 C0 48 83 C7 01 84 D2 74 1C 0F 1F 00 B9 43 00 00 00 0F AF C1 8D 44 10 8F 0F B6 17 48 83 C7 01 84 D2 75 E9 F3 C3 F3 C3 }
	condition:
		$pattern
}

rule ternary_search_43571c955d2cf8328e32fe01b12782d7 {
	meta:
		aliases = "ternary_search"
		size = "85"
		objfiles = "ternary@libiberty.a"
	strings:
		$pattern = { ( CC | 0F ) BE 06 0F 1F 44 00 00 48 85 FF 74 21 0F BE 17 89 C1 29 D1 83 F9 00 75 1F 85 C0 74 33 48 8B 7F 10 0F BE 46 01 48 83 C6 01 48 85 FF 75 DF 31 C0 C3 0F 1F 80 00 00 00 00 7C 0E 48 8B 7F 18 66 90 EB C6 66 0F 1F 44 00 00 48 8B 7F 08 EB BA 66 90 48 8B 47 10 C3 }
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

rule cplus_demangle_fill_name_10ea67276ed6aea9a1e416dfaf2c7c7d {
	meta:
		aliases = "cplus_demangle_fill_name"
		size = "34"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 31 ) C0 48 85 F6 74 19 48 85 FF 74 14 85 D2 74 10 C7 07 00 00 00 00 48 89 77 08 B0 01 89 57 10 C3 F3 C3 }
	condition:
		$pattern
}

rule dyn_string_eq_ab6c63ee0a2710a09c5d4a554e283704 {
	meta:
		aliases = "dyn_string_eq"
		size = "46"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 31 ) C0 8B 56 04 39 57 04 74 06 F3 C3 0F 1F 40 00 48 83 EC 08 48 8B 76 08 48 8B 7F 08 E8 ?? ?? ?? ?? 85 C0 0F 94 C0 48 83 C4 08 0F B6 C0 C3 }
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

rule iterative_hash_b8d955a6ac7ee15c2b8b479025e7b1e2 {
	meta:
		aliases = "iterative_hash"
		size = "746"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 40 ) F6 C7 03 0F 84 16 02 00 00 B9 B9 79 37 9E 83 FE 0B 41 89 F3 89 C8 0F 86 21 01 00 00 0F 1F 00 44 0F B6 4F 05 44 0F B6 47 06 44 0F B6 57 04 41 C1 E0 10 41 C1 E1 08 45 01 C1 44 0F B6 47 07 45 01 D1 44 0F B6 57 08 41 C1 E0 18 45 01 C8 44 0F B6 4F 09 44 01 C1 44 0F B6 47 0A 41 C1 E1 08 41 C1 E0 10 45 01 C1 44 0F B6 47 0B 45 01 D1 44 0F B6 17 41 C1 E0 18 45 01 C8 44 0F B6 4F 01 44 01 C2 44 0F B6 47 02 41 C1 E1 08 41 C1 E0 10 45 01 C8 44 0F B6 4F 03 45 01 D0 41 C1 E1 18 45 01 C8 41 29 C8 29 D1 41 29 D0 44 01 C0 41 89 D0 41 C1 E8 0D 44 31 C0 41 89 C2 29 C1 29 C2 41 C1 E2 08 41 31 CA 45 89 D0 44 29 }
	condition:
		$pattern
}

rule dyn_string_insert_char_438f8e5bdae115a0b2855b6aeb919f3a {
	meta:
		aliases = "dyn_string_insert_char"
		size = "103"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 41 89 D4 55 48 63 EE 53 8B 77 04 48 89 FB 83 C6 01 E8 ?? ?? ?? ?? 48 85 C0 74 43 8B 53 04 39 EA 7C 23 48 63 FA 29 EA 48 8D 47 01 48 29 D7 48 8B 4B 08 44 0F B6 44 01 FF 44 88 04 01 48 83 E8 01 48 39 F8 75 E9 48 8B 43 08 44 88 24 28 83 43 04 01 B8 01 00 00 00 5B 5D 41 5C C3 0F 1F 00 5B 5D 31 C0 41 5C C3 }
	condition:
		$pattern
}

rule d_cv_qualifiers_056951e2f7ffdcfac4806ce89adf94f9 {
	meta:
		aliases = "d_cv_qualifiers"
		size = "186"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 41 89 D4 55 48 89 F5 53 48 8B 47 18 48 89 FB 0F B6 08 EB 4C 66 2E 0F 1F 84 00 00 00 00 00 84 C0 75 4C 80 F9 4B 0F 85 85 00 00 00 48 83 43 18 01 41 83 FC 01 19 F6 83 43 50 06 83 E6 FD 83 C6 1B 31 C9 31 D2 48 89 DF E8 E2 FE FF FF 48 85 C0 48 89 45 00 74 59 48 8D 68 08 48 8B 43 18 0F B6 08 80 F9 72 0F 94 C0 80 F9 56 0F 94 C2 75 B0 48 83 43 18 01 84 C0 74 17 41 83 FC 01 19 F6 83 43 50 09 83 E6 FD 83 C6 19 EB B7 0F 1F 44 00 00 84 D2 74 9E 41 83 FC 01 19 F6 83 43 50 09 83 E6 FD 83 C6 1A EB 9C 66 2E 0F 1F 84 00 00 00 00 00 31 ED 5B 48 89 E8 5D 41 5C C3 }
	condition:
		$pattern
}

rule put_field_891f470ae35dbe685fb4373915efd089 {
	meta:
		aliases = "put_field"
		size = "197"
		objfiles = "floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 41 8D 04 08 55 41 89 C2 41 C1 EA 03 85 F6 53 75 0C C1 EA 03 83 EA 01 44 29 D2 41 89 D2 83 E0 07 BA 01 00 00 00 44 89 D5 44 8D 58 F8 89 C1 48 01 FD D3 E2 41 0F B6 D9 41 F7 DB 83 EA 01 44 89 D9 D3 E2 48 D3 E3 F7 D2 22 55 00 09 DA 88 55 00 41 8D 52 01 41 83 EA 01 85 F6 BD 01 00 00 00 41 0F 45 D2 45 89 C2 41 29 C2 EB 38 0F 1F 40 00 44 89 D1 89 D3 41 89 EB 48 01 FB 41 D3 E3 4D 89 CC 41 F7 DB 44 22 1B 89 C1 49 D3 EC 45 09 E3 44 88 1B 8D 4A 01 83 C0 08 83 EA 01 85 F6 0F 44 D1 41 83 EA 08 41 39 C0 76 17 41 83 FA 07 76 C1 4C 89 CB 89 C1 41 89 D3 48 D3 EB 42 88 1C 1F EB D2 5B 5D 41 5C C3 }
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

rule d_print_array_type_DOT_isra_DOT_4_12037eb8f30cae1618b5faf72ef2a944 {
	meta:
		aliases = "d_print_array_type.isra.4"
		size = "448"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 85 D2 49 89 F4 55 48 89 D5 53 48 89 FB 74 26 48 89 D0 0F 1F 00 8B 50 10 85 D2 0F 84 BD 00 00 00 48 8B 00 48 85 C0 75 ED 31 D2 48 89 EE 48 89 DF E8 38 FE FF FF 48 8B 53 08 48 85 D2 74 7F 0F 1F 80 00 00 00 00 48 8B 43 10 48 3B 43 18 73 6E C6 04 02 20 48 83 C0 01 48 89 43 10 48 8B 53 08 48 85 D2 74 69 48 8B 43 10 48 3B 43 18 73 5F C6 04 02 5B 48 83 C0 01 48 89 43 10 49 8B 34 24 48 85 F6 74 08 48 89 DF E8 A2 DD FF FF 48 8B 53 08 48 85 D2 74 0E 48 8B 43 10 48 3B 43 18 0F 82 DB 00 00 00 48 89 DF BE 5D 00 00 00 5B 5D 41 5C E9 4A DC FF FF 66 2E 0F 1F 84 00 00 00 00 00 BE 20 00 00 00 48 89 DF }
	condition:
		$pattern
}

rule delete_non_B_K_work_stuff_c5490684c6763c35f5154e2d0d651532 {
	meta:
		aliases = "delete_non_B_K_work_stuff"
		size = "169"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 48 8D 77 30 49 89 FC 48 8D 7F 08 55 53 E8 8C FF FF FF 49 8B 7C 24 08 48 85 FF 74 17 E8 ?? ?? ?? ?? 49 C7 44 24 08 00 00 00 00 41 C7 44 24 34 00 00 00 00 49 8B 44 24 50 48 85 C0 74 43 41 8B 54 24 58 85 D2 7E 29 31 ED 31 DB 0F 1F 40 00 48 8B 3C 28 48 85 FF 74 0A E8 ?? ?? ?? ?? 49 8B 44 24 50 83 C3 01 48 83 C5 08 41 39 5C 24 58 7F DF 48 89 C7 E8 ?? ?? ?? ?? 49 C7 44 24 50 00 00 00 00 49 8B 7C 24 60 48 85 FF 74 18 E8 EF FB FF FF 49 8B 7C 24 60 E8 ?? ?? ?? ?? 49 C7 44 24 60 00 00 00 00 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule ternary_insert_d0dbf6d246607c7a7a021a7eb2723f0d {
	meta:
		aliases = "ternary_insert"
		size = "204"
		objfiles = "ternary@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 D4 55 48 89 F5 53 48 89 FB 0F 1F 00 4C 8B 03 4D 85 C0 74 4C 0F B6 55 00 41 0F BE 30 0F BE C2 29 F0 75 23 48 83 C5 01 84 D2 74 79 49 8D 58 10 4C 8B 03 4D 85 C0 74 29 0F B6 55 00 41 0F BE 30 0F BE C2 29 F0 74 DD 49 8D 58 08 49 83 C0 18 85 C0 49 0F 49 D8 EB B6 66 0F 1F 44 00 00 48 8D 58 10 BF 20 00 00 00 E8 ?? ?? ?? ?? 48 89 03 0F B6 55 00 48 83 C5 01 48 C7 40 10 00 00 00 00 48 C7 40 18 00 00 00 00 48 C7 40 08 00 00 00 00 84 D2 88 10 75 C9 4C 89 60 10 4C 89 E0 5B 5D 41 5C C3 0F 1F 44 00 00 85 C9 74 14 4D 89 60 10 4C 89 E0 5B 5D 41 5C C3 0F 1F 84 00 00 00 00 00 4D 8B 60 10 5B 5D 4C 89 }
	condition:
		$pattern
}

rule forget_types_DOT_isra_DOT_3_606f9059f3173011a17fb16f94d55ef1 {
	meta:
		aliases = "forget_types.isra.3"
		size = "91"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 48 89 F5 53 8B 45 00 48 63 D0 48 8D 1C D5 F8 FF FF FF EB 20 66 0F 1F 44 00 00 49 8B 14 24 83 E8 01 48 8D 4B F8 89 45 00 48 8B 3C 1A 48 85 FF 75 11 48 89 CB 85 C0 7F E2 5B 5D 41 5C C3 0F 1F 44 00 00 E8 ?? ?? ?? ?? 49 8B 04 24 48 C7 04 18 00 00 00 00 EB AF }
	condition:
		$pattern
}

rule C_alloca_4dadffbdd627481abba716ed9673d2f5 {
	meta:
		aliases = "C_alloca"
		size = "160"
		objfiles = "alloca@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 49 89 FC 55 53 48 83 EC 10 48 8B 3D ?? ?? ?? ?? 48 85 FF 74 2F 48 8D 6C 24 0F 48 39 6F 08 48 89 FB 72 14 EB 21 66 0F 1F 84 00 00 00 00 00 48 39 6B 08 48 89 DF 73 0F 48 8B 1F E8 ?? ?? ?? ?? 48 85 DB 75 EA 31 DB 4D 85 E4 48 89 1D ?? ?? ?? ?? 74 3C 49 8D 7C 24 10 E8 ?? ?? ?? ?? 48 85 C0 74 38 48 8B 15 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 89 10 48 8D 54 24 0F 48 89 50 08 48 83 C4 10 48 83 C0 10 5B 5D 41 5C C3 66 0F 1F 44 00 00 48 83 C4 10 31 C0 5B 5D 41 5C C3 E8 ?? ?? ?? ?? }
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

rule d_print_resize_1ec71d04e38751047525506d6bf85e66 {
	meta:
		aliases = "d_print_resize"
		size = "101"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 8B 47 08 48 85 C0 74 50 49 89 F4 4C 03 67 10 48 8B 5F 18 49 39 DC 77 15 EB 3E 66 0F 1F 44 00 00 49 39 DC 48 89 45 08 48 89 5D 18 76 2B 48 01 DB 48 89 C7 48 89 DE E8 ?? ?? ?? ?? 48 85 C0 75 E0 48 8B 7D 08 E8 ?? ?? ?? ?? 48 C7 45 08 00 00 00 00 C7 45 30 01 00 00 00 5B 5D 41 5C C3 }
	condition:
		$pattern
}

rule d_encoding_58962a28a5754006733a4c01f86c4fe9 {
	meta:
		aliases = "d_encoding"
		size = "944"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 48 89 FD 53 48 8B 47 18 0F B6 10 80 FA 54 0F 84 91 00 00 00 80 FA 47 0F 84 88 00 00 00 41 89 F4 E8 78 FC FF FF 48 85 C0 48 89 C3 75 20 48 8B 45 18 0F B6 00 3C 45 0F 85 01 01 00 00 48 89 D8 5B 5D 41 5C C3 66 0F 1F 84 00 00 00 00 00 45 85 E4 74 DB F6 45 10 01 75 D5 8B 03 8D 50 E7 83 FA 02 77 11 0F 1F 00 48 8B 5B 08 8B 03 8D 50 E7 83 FA 02 76 F2 83 F8 02 75 C4 48 8B 43 10 8B 10 83 EA 19 83 FA 02 77 15 0F 1F 80 00 00 00 00 48 8B 40 08 8B 10 83 EA 19 83 FA 02 76 F2 48 89 43 10 EB 9B 0F 1F 40 00 8B 4D 50 48 8D 70 01 8D 51 14 89 55 50 0F B6 10 48 89 75 18 80 FA 54 0F 84 D3 00 00 00 80 FA 47 }
	condition:
		$pattern
}

rule d_template_args_6567118a5e48bbbefab07431d8d20a4f {
	meta:
		aliases = "d_template_args"
		size = "218"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 48 89 FB 48 83 EC 10 48 8B 47 18 4C 8B 67 48 0F B6 08 48 8D 50 01 48 89 57 18 80 F9 49 0F 85 8D 00 00 00 48 C7 44 24 08 00 00 00 00 0F B6 40 01 48 8D 6C 24 08 EB 40 0F 1F 44 00 00 3C 58 74 4C 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 74 63 31 C9 48 89 C2 BE 27 00 00 00 48 89 DF E8 9D C6 FF FF 48 85 C0 48 89 45 00 74 48 48 8B 53 18 48 8D 68 10 0F B6 02 3C 45 74 45 3C 4C 75 C1 48 89 DF E8 A9 07 00 00 EB C3 0F 1F 80 00 00 00 00 48 83 C2 01 48 89 DF 48 89 53 18 E8 F0 FC FF FF 48 8B 53 18 0F B6 0A 48 83 C2 01 48 89 53 18 80 F9 45 74 98 48 83 C4 10 31 C0 5B 5D 41 5C C3 90 48 83 C2 01 4C 89 63 48 }
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

rule d_expr_primary_c9322a175cebb29ed8aecb09a26dc840 {
	meta:
		aliases = "d_expr_primary"
		size = "273"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 54 55 53 48 8B 47 18 48 89 FB 0F B6 10 48 8D 48 01 48 89 4F 18 80 FA 4C 0F 85 91 00 00 00 80 78 01 5F 0F 84 97 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 74 7A 83 38 21 0F 84 B1 00 00 00 48 8B 73 18 41 BC 31 00 00 00 0F B6 0E 80 F9 6E 74 7F 80 F9 45 0F 84 B0 00 00 00 84 C9 74 52 48 8D 4E 01 EB 0D 0F 1F 40 00 48 83 C1 01 45 84 C0 74 3F 48 89 4B 18 44 0F B6 01 41 80 F8 45 75 E9 89 CA 29 F2 48 89 DF E8 C5 BE FF FF 48 89 EA 48 89 C1 44 89 E6 48 89 DF E8 34 BE FF FF 48 8B 53 18 0F B6 0A 48 83 C2 01 48 89 53 18 80 F9 45 74 02 31 C0 5B 5D 41 5C C3 66 0F 1F 84 00 00 00 00 00 31 F6 E8 ?? ?? ?? ?? EB }
	condition:
		$pattern
}

rule fibheap_consolidate_1cdb73d89fa4ecd8157f2d82306b4634 {
	meta:
		aliases = "fibheap_consolidate"
		size = "431"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 31 C0 49 89 FD B9 41 00 00 00 41 54 55 53 48 81 EC 18 02 00 00 48 89 E7 49 89 E4 F3 48 AB 49 8B 5D 10 48 85 DB 0F 84 7B 01 00 00 49 8D 6D 10 0F 1F 80 00 00 00 00 48 89 DE 48 89 EF E8 5D FF FF FF 8B 73 30 81 E6 FF FF FF 7F 4C 63 C6 4A 8B 04 C4 48 85 C0 75 5E E9 9B 00 00 00 0F 1F 00 48 8B 52 10 48 8B 4A 18 48 39 CA 74 73 48 89 48 18 48 8B 4A 18 48 89 42 18 48 89 41 10 48 89 50 10 48 89 18 8B 53 30 83 C6 01 8D 4A 01 81 E2 00 00 00 80 81 E1 FF FF FF 7F 09 CA 89 53 30 80 60 33 7F 4A C7 04 C4 00 00 00 00 4C 63 C6 4A 8B 04 C4 48 85 C0 74 42 48 8B 50 20 48 39 53 20 7C 0B 7E 09 48 89 C2 48 89 D8 }
	condition:
		$pattern
}

rule d_print_function_type_DOT_isra_DOT_5_0fa84c244bb8f0c2e507d25720d927de {
	meta:
		aliases = "d_print_function_type.isra.5"
		size = "629"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 D4 55 48 89 CD 53 48 89 FB 48 83 EC 08 48 85 C9 0F 84 46 02 00 00 8B 79 10 85 FF 0F 85 3B 02 00 00 48 89 C8 BE 01 00 00 00 48 BA 00 00 C0 91 21 00 00 00 0F 1F 80 00 00 00 00 4C 8B 40 08 41 83 38 25 0F 87 B2 00 00 00 49 63 08 48 89 F7 48 D3 E7 48 85 D7 0F 85 48 01 00 00 F7 C7 00 00 00 60 0F 84 94 00 00 00 48 8B 43 08 48 85 C0 0F 84 57 01 00 00 48 8B 53 10 48 85 D2 0F 84 3F 01 00 00 0F B6 4C 10 FF 83 E1 FD 80 F9 28 0F 85 23 01 00 00 48 3B 53 18 0F 83 53 01 00 00 0F 1F 80 00 00 00 00 C6 04 10 28 48 83 C2 01 48 89 53 10 31 D2 4C 8B 6B 28 48 89 EE 48 C7 43 28 00 00 00 00 48 89 DF }
	condition:
		$pattern
}

rule do_arg_33f29d2ac4ed51d8a2d2a2866ab7d2e7 {
	meta:
		aliases = "do_arg"
		size = "314"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 55 48 89 D5 53 48 89 F3 48 83 EC 08 4C 8B 2E 8B 47 68 0F 1F 80 00 00 00 00 85 C0 48 C7 45 10 00 00 00 00 48 C7 45 08 00 00 00 00 48 C7 45 00 00 00 00 00 7F 3D 48 8B 03 80 38 6E 75 6C 48 83 C0 01 48 89 DF 48 89 03 E8 5D C6 FF FF 85 C0 41 89 44 24 68 7E 77 83 F8 09 7F 7F 48 C7 45 10 00 00 00 00 48 C7 45 08 00 00 00 00 48 C7 45 00 00 00 00 00 49 8B 74 24 60 83 E8 01 41 89 44 24 68 48 85 F6 74 48 48 8B 56 08 48 89 EF E8 89 CC FF FF 48 83 C4 08 B8 01 00 00 00 5B 5D 41 5C 41 5D C3 66 0F 1F 84 00 00 00 00 00 49 8B 7C 24 60 48 85 FF 74 6C E8 21 C7 FF FF 49 8B 54 24 60 48 89 DE 4C }
	condition:
		$pattern
}

rule byte_group_match_null_string_p_7a0d16263153e85417f8ad305b57fd8d {
	meta:
		aliases = "byte_group_match_null_string_p"
		size = "344"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 55 48 89 F5 53 48 89 D3 48 83 EC 18 48 8B 3F 48 83 C7 02 48 89 7C 24 08 48 39 FD 76 2C 0F B6 17 80 FA 07 74 34 80 FA 0F 74 4F 48 8D 7C 24 08 48 89 DA 48 89 EE E8 FF FD FF FF 84 C0 74 0B 48 8B 7C 24 08 48 39 FD 77 D5 90 48 83 C4 18 31 C0 5B 5D 41 5C 41 5D C3 0F 1F 00 48 8D 47 02 49 89 04 24 48 83 C4 18 B8 01 00 00 00 5B 5D 41 5C 41 5D C3 0F 1F 84 00 00 00 00 00 48 8D 57 01 48 89 54 24 08 0F BE 57 02 44 0F B6 6F 01 48 83 C7 03 48 89 7C 24 08 C1 E2 08 41 01 D5 0F 88 78 FF FF FF 4D 63 ED 42 80 7C 2F FD 0E 4A 8D 74 2F FD 74 0E E9 97 00 00 00 0F 1F 40 00 4A 8D 74 2F FD 48 89 DA }
	condition:
		$pattern
}

rule htab_delete_e5c024ef7696b662b34222cfaac50d68 {
	meta:
		aliases = "htab_delete"
		size = "187"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 55 53 48 83 EC 08 48 83 7F 10 00 48 8B 6F 20 4C 8B 6F 18 74 3A 89 E8 83 E8 01 78 33 48 98 83 ED 02 49 8D 5C C5 00 EB 0E 90 48 83 EB 08 85 ED 8D 45 FF 78 1B 89 C5 48 8B 3B 48 83 FF 01 76 EA 41 FF 54 24 10 48 83 EB 08 85 ED 8D 45 FF 79 E5 49 8B 44 24 48 48 85 C0 74 20 4C 89 EF FF D0 49 8B 44 24 48 48 83 C4 08 4C 89 E7 5B 5D 41 5C 41 5D FF E0 0F 1F 80 00 00 00 00 49 8B 44 24 60 48 85 C0 74 26 49 8B 7C 24 50 4C 89 EE FF D0 49 8B 7C 24 50 49 8B 44 24 60 48 83 C4 08 5B 5D 4C 89 E6 41 5C 41 5D FF E0 0F 1F 00 48 83 C4 08 5B 5D 41 5C 41 5D C3 }
	condition:
		$pattern
}

rule splay_tree_delete_5d559c6c2b0c33fe2474b50579f7a2a2 {
	meta:
		aliases = "splay_tree_delete"
		size = "269"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 49 89 FC 55 53 48 83 EC 08 48 8B 1F 48 85 DB 0F 84 B7 00 00 00 48 8B 47 10 48 85 C0 74 05 48 8B 3B FF D0 49 8B 44 24 18 48 85 C0 74 06 48 8B 7B 08 FF D0 48 C7 03 00 00 00 00 66 90 48 89 DD 31 DB 4C 8B 6D 10 4D 85 ED 0F 84 9E 00 00 00 49 8B 44 24 10 48 85 C0 74 0A 49 8B 7D 00 FF D0 4C 8B 6D 10 49 8B 44 24 18 48 85 C0 74 0A 49 8B 7D 08 FF D0 4C 8B 6D 10 49 89 5D 00 48 8B 5D 18 48 85 DB 74 79 49 8B 44 24 10 48 85 C0 74 09 48 8B 3B FF D0 48 8B 5D 18 49 8B 44 24 18 48 85 C0 74 0A 48 8B 7B 08 FF D0 48 8B 5D 18 4C 89 2B 4C 8B 6D 00 49 8B 74 24 30 48 89 EF 41 FF 54 24 28 4D 85 ED 75 3E 48 }
	condition:
		$pattern
}

rule d_name_b82d9d1b6c7318e1d752482265105e1b {
	meta:
		aliases = "d_name"
		size = "851"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 48 89 FD 53 48 83 EC 18 48 8B 57 18 0F B6 02 3C 53 0F 84 E4 01 00 00 3C 5A 0F 84 6C 01 00 00 3C 4E 74 28 E8 D3 FA FF FF 48 89 C3 48 8B 45 18 80 38 49 0F 84 74 02 00 00 48 83 C4 18 48 89 D8 5B 5D 41 5C 41 5D C3 0F 1F 44 00 00 48 83 C2 01 48 8D 74 24 08 48 89 57 18 BA 01 00 00 00 E8 89 C6 FF FF 48 85 C0 49 89 C5 0F 84 BD 00 00 00 48 8B 45 18 45 31 E4 0F B6 18 84 DB 0F 84 A3 00 00 00 0F 1F 00 8D 53 9F 80 FA 19 0F 86 AC 00 00 00 8D 43 D0 3C 09 0F 86 A1 00 00 00 8D 43 BD 3C 01 0F 86 96 00 00 00 80 FB 53 0F 84 9D 01 00 00 80 FB 49 0F 84 B4 00 00 00 80 FB 54 90 0F 85 4C 02 00 00 48 89 }
	condition:
		$pattern
}

rule d_print_mod_list_6bb8c874f8b4c3ef8403a9c7efdea101 {
	meta:
		aliases = "d_print_mod_list"
		size = "398"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 53 48 89 F3 48 83 EC 08 48 85 F6 74 6D 48 83 7F 08 00 48 89 FD 41 89 D5 75 10 EB 5E 0F 1F 80 00 00 00 00 48 83 7D 08 00 74 50 8B 43 10 85 C0 75 41 48 8B 73 08 45 85 ED 8B 06 75 08 8D 50 E7 83 FA 02 76 2E 48 8B 53 18 83 F8 23 C7 43 10 01 00 00 00 4C 8B 65 20 48 89 55 20 74 29 83 F8 24 74 46 83 F8 02 74 5F 48 89 EF E8 6D F9 FF FF 4C 89 65 20 48 8B 1B 48 85 DB 75 A9 48 83 C4 08 5B 5D 41 5C 41 5D C3 48 8B 0B 48 8D 56 10 48 89 EF 48 83 C6 08 E8 E3 FC FF FF 4C 89 65 20 48 83 C4 08 5B 5D 41 5C 41 5D C3 48 8B 13 48 89 EF 48 83 C6 08 E8 D5 00 00 00 4C 89 65 20 48 83 C4 08 5B 5D 41 5C 41 }
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

rule d_bare_function_type_c3381993a938a7920350a33f469d1dca {
	meta:
		aliases = "d_bare_function_type"
		size = "251"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 54 55 89 F5 53 48 89 FB 48 83 EC 18 48 8B 57 18 80 3A 4A 0F 84 A4 00 00 00 48 C7 44 24 08 00 00 00 00 4C 8D 6C 24 08 45 31 E4 EB 1F 90 84 C0 74 21 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 74 47 85 ED 74 53 48 8B 53 18 31 ED 49 89 C4 0F B6 02 3C 45 75 DB 48 8B 4C 24 08 48 85 C9 74 29 48 83 79 10 00 74 6C 4C 89 E2 48 89 DF BE 23 00 00 00 E8 1A CD FF FF 48 83 C4 18 5B 5D 41 5C 41 5D C3 0F 1F 80 00 00 00 00 48 83 C4 18 31 C0 5B 5D 41 5C 41 5D C3 0F 1F 00 31 C9 48 89 C2 BE 26 00 00 00 48 89 DF E8 E6 CC FF FF 48 85 C0 49 89 45 00 74 D5 4C 8D 68 10 48 8B 53 18 EB 91 0F 1F 00 48 83 C2 01 BD 01 00 00 }
	condition:
		$pattern
}

rule dyn_string_substring_6044ec60de4b1b0091ed888307feff4f {
	meta:
		aliases = "dyn_string_substring"
		size = "178"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 41 89 D5 41 54 41 89 CC 41 29 D4 55 53 48 83 EC 08 39 D1 0F 8C 92 00 00 00 8B 46 04 48 89 F5 39 C2 0F 8F 84 00 00 00 39 C1 0F 8F 7C 00 00 00 44 89 E6 48 89 FB E8 ?? ?? ?? ?? 48 85 C0 74 5F 44 89 E2 83 EA 01 78 37 48 63 CA 89 D2 48 8D 41 FF 48 89 C7 48 29 D7 49 63 D5 EB 07 0F 1F 00 48 83 E8 01 4C 8B 45 08 49 01 C8 48 39 F8 45 0F B6 0C 10 4C 8B 43 08 45 88 0C 08 48 89 C1 75 E0 48 8B 53 08 49 63 C4 C6 04 02 00 44 89 63 04 48 83 C4 08 5B 5D 41 5C B8 01 00 00 00 41 5D C3 90 48 83 C4 08 31 C0 5B 5D 41 5C 41 5D C3 E8 ?? ?? ?? ?? }
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

rule demangle_args_0a862e9dc7066bc991645da0f42af16a {
	meta:
		aliases = "demangle_args"
		size = "662"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 49 89 D4 55 53 48 89 FB 48 83 EC 38 F6 07 01 0F 85 E4 01 00 00 49 8B 55 00 0F B6 02 31 ED 84 C0 0F 84 0B 01 00 00 3C 5F 0F 84 03 01 00 00 3C 65 0F 84 FB 00 00 00 3C 4E 0F 94 C1 3C 54 74 08 84 C9 0F 84 32 01 00 00 48 83 C2 01 84 C9 49 89 55 00 0F 85 63 01 00 00 C7 04 24 01 00 00 00 F7 03 00 38 00 00 74 0A 83 7B 30 09 0F 8F B9 01 00 00 48 8D 74 24 04 4C 89 EF E8 9C C5 FF FF 85 C0 0F 84 4C 01 00 00 8B 44 24 04 F7 03 00 3C 00 00 74 07 83 E8 01 89 44 24 04 85 C0 0F 88 31 01 00 00 39 43 30 7F 1B E9 27 01 00 00 0F 1F 80 00 00 00 00 48 8D 7C 24 10 BD 01 00 00 00 E8 D9 C5 FF FF 8B }
	condition:
		$pattern
}

rule md5_stream_8a62aadcc37776e12bcad992854d3bf0 {
	meta:
		aliases = "md5_stream"
		size = "288"
		objfiles = "md5@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 F5 41 54 49 89 FC 55 53 48 81 EC F8 10 00 00 64 48 8B 04 25 28 00 00 00 48 89 84 24 E8 10 00 00 31 C0 C7 04 24 01 23 45 67 C7 44 24 04 89 AB CD EF C7 44 24 08 FE DC BA 98 C7 44 24 0C 76 54 32 10 C7 44 24 14 00 00 00 00 C7 44 24 10 00 00 00 00 C7 44 24 18 00 00 00 00 0F 1F 00 31 DB BD 00 10 00 00 66 0F 1F 84 00 00 00 00 00 48 8D BC 24 A0 00 00 00 48 89 EA 4C 89 E1 48 29 DA BE 01 00 00 00 48 01 DF E8 ?? ?? ?? ?? 48 01 C3 48 81 FB FF 0F 00 00 77 05 48 85 C0 75 D1 48 85 C0 74 1C 48 8D BC 24 A0 00 00 00 48 89 E2 BE 00 10 00 00 E8 ?? ?? ?? ?? EB A5 0F 1F 44 00 00 4C 89 E7 E8 ?? ?? ?? ?? }
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

rule strtosigno_7be4f44d8ada69e012a7f54f980c4020 {
	meta:
		aliases = "strtoerrno, strtosigno"
		size = "111"
		objfiles = "strsignal@libiberty.a, strerror@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 55 49 89 FD 41 54 55 53 48 83 EC 08 48 85 FF 74 47 48 83 3D ?? ?? ?? ?? 00 74 4C 44 8B 25 ?? ?? ?? ?? 41 83 FC 00 7E 30 48 8B 2D ?? ?? ?? ?? 31 DB 66 0F 1F 44 00 00 48 8B 75 00 48 85 F6 74 0C 4C 89 EF E8 ?? ?? ?? ?? 85 C0 74 0E 83 C3 01 48 83 C5 08 44 39 E3 75 DF 31 DB 48 83 C4 08 89 D8 5B 5D 41 5C 41 5D C3 E8 13 FE FF FF EB AD }
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

rule xregexec_a0eee2d3486be1978941240ec1f51e48 {
	meta:
		aliases = "xregexec"
		size = "469"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 56 45 89 C6 41 55 49 89 F5 41 54 49 89 CC 55 48 89 D5 53 48 89 FB 48 89 F7 48 83 EC 70 E8 ?? ?? ?? ?? F6 43 38 10 48 89 C2 75 09 48 85 ED 0F 85 9B 00 00 00 48 8B 03 48 8B 4B 38 48 8D 7C 24 30 45 31 C9 41 89 D0 4C 89 EE 48 89 44 24 30 48 8B 43 08 48 89 4C 24 68 83 E1 DF 48 89 44 24 38 48 8B 43 10 48 89 44 24 40 48 8B 43 18 48 89 44 24 48 48 8B 43 20 48 89 44 24 50 48 8B 43 28 48 89 44 24 58 48 8B 43 30 48 89 44 24 60 44 89 F0 41 D1 EE 83 E0 01 41 83 E6 01 C1 E0 05 41 C1 E6 06 09 C1 83 E1 B9 44 09 F1 83 C9 04 88 4C 24 68 31 C9 E8 ?? ?? ?? ?? 89 C3 89 D8 C1 E8 1F 48 83 C4 70 5B 5D 41 5C 41 5D }
	condition:
		$pattern
}

rule cplus_demangle_fill_builtin_ty_0548887fb70bf699d8db30f11dd6aa0f {
	meta:
		aliases = "cplus_demangle_fill_builtin_type"
		size = "139"
		objfiles = "cp_demint@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 56 48 85 F6 41 55 49 89 F5 41 54 55 53 74 70 48 85 FF 49 89 FE 74 68 48 89 F7 31 DB E8 ?? ?? ?? ?? 89 C5 EB 14 66 2E 0F 1F 84 00 00 00 00 00 48 83 C3 01 48 83 FB 1A 74 46 48 89 DA 41 89 DC 48 C1 E2 05 39 AA ?? ?? ?? ?? 75 E4 48 8B B2 ?? ?? ?? ?? 4C 89 EF E8 ?? ?? ?? ?? 85 C0 75 D1 49 C1 E4 05 41 C7 06 21 00 00 00 B0 01 49 81 C4 ?? ?? ?? ?? 4D 89 66 08 5B 5D 41 5C 41 5D 41 5E C3 5B 5D 41 5C 41 5D 31 C0 41 5E C3 }
	condition:
		$pattern
}

rule splay_tree_splay_0b8824cb5f214e58c73f9eeb590d103f {
	meta:
		aliases = "splay_tree_splay"
		size = "467"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 F6 41 55 49 89 FD 41 54 55 53 48 8B 2F 48 85 ED 0F 84 AE 00 00 00 66 0F 1F 44 00 00 48 8B 75 00 4C 89 F7 41 FF 55 08 83 F8 00 41 89 C4 0F 84 91 00 00 00 7C 7F 48 8B 5D 18 48 85 DB 0F 84 82 00 00 00 48 8B 33 4C 89 F7 41 FF 55 08 83 F8 00 0F 84 37 01 00 00 7C 7D 48 83 7B 18 00 0F 84 2A 01 00 00 44 89 E1 31 D2 C1 E9 1F 45 85 E4 40 0F 9F C6 85 C0 0F 9F C0 0F 8E A0 00 00 00 40 84 F6 0F 84 97 00 00 00 48 8B 43 18 48 8B 50 10 48 89 58 10 48 89 53 18 48 89 45 18 48 8B 50 10 48 89 68 10 48 89 55 18 49 89 45 00 48 89 C5 E9 6B FF FF FF 0F 1F 00 48 8B 5D 10 48 85 DB 75 85 0F 1F 80 00 00 00 00 }
	condition:
		$pattern
}

rule htab_empty_ab67500f7785452f6041f631a1bfedd8 {
	meta:
		aliases = "htab_empty"
		size = "111"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 FE 41 55 41 54 55 53 48 83 7F 10 00 4C 8B 67 20 4C 8B 6F 18 74 3B 44 89 E0 83 E8 01 78 33 48 98 41 8D 6C 24 FE 49 8D 5C C5 00 EB 0D 48 83 EB 08 85 ED 8D 45 FF 78 1A 89 C5 48 8B 3B 48 83 FF 01 76 EA 41 FF 56 10 48 83 EB 08 85 ED 8D 45 FF 79 E6 5B 5D 4A 8D 14 E5 00 00 00 00 4C 89 EF 31 F6 41 5C 41 5D 41 5E E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule demangle_template_template_par_12dee4ba886e123abd7f2bcdab7d8553 {
	meta:
		aliases = "demangle_template_template_parm"
		size = "322"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 56 49 89 FE 48 89 D7 41 55 49 89 D5 41 54 41 BC 01 00 00 00 55 48 89 F5 BE ?? ?? ?? ?? 53 48 83 EC 30 E8 88 CF FF FF 48 8D 74 24 0C 48 89 EF E8 7B C8 FF FF 85 C0 74 49 8B 44 24 0C 31 DB 85 C0 7E 3F 48 8B 45 00 0F B6 08 80 F9 5A 0F 84 A0 00 00 00 0F 1F 44 00 00 80 F9 7A 74 53 48 8D 54 24 10 48 89 EE 4C 89 F7 E8 63 EA FF FF 85 C0 41 89 C4 0F 85 98 00 00 00 48 8D 7C 24 10 E8 AE C8 FF FF 49 8B 45 08 80 78 FF 3E 0F 84 A0 00 00 00 4C 89 EF BE ?? ?? ?? ?? E8 13 CF FF FF 48 83 C4 30 44 89 E0 5B 5D 41 5C 41 5D 41 5E C3 0F 1F 00 48 83 C0 01 4C 89 EA 48 89 EE 48 89 45 00 4C 89 F7 E8 3A FF FF FF 85 C0 }
	condition:
		$pattern
}

rule iterate_demangle_function_fc8c629dab059c67aa031896a85faeb3 {
	meta:
		aliases = "iterate_demangle_function"
		size = "406"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 31 C0 41 56 41 55 41 54 49 89 F4 55 48 89 CD 53 48 81 EC A8 00 00 00 80 79 02 00 4C 8B 3E 0F 84 46 01 00 00 F7 07 00 3C 00 00 49 89 FD 48 89 D3 0F 85 46 01 00 00 48 8D 79 02 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 0F 84 2F 01 00 00 48 8B 53 08 48 8D 7C 24 10 4C 8D 74 24 30 48 89 DE 48 C7 44 24 20 00 00 00 00 48 C7 44 24 18 00 00 00 00 48 C7 44 24 10 00 00 00 00 E8 20 B8 FF FF 31 C0 B9 0E 00 00 00 4C 89 F7 F3 48 AB 4C 89 EE 4C 89 F7 E8 08 BC FF FF 80 7D 02 00 0F 84 A6 00 00 00 48 89 E9 48 89 DA 4C 89 E6 4C 89 EF E8 ED F2 FF FF 48 89 DA 4C 89 E6 4C 89 EF E8 EF F6 FF FF 85 C0 0F 85 81 00 00 }
	condition:
		$pattern
}

rule demangle_qualified_29a3b19b76a85ba87d58f19dbbfd3cc2 {
	meta:
		aliases = "demangle_qualified"
		size = "1181"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 49 89 FC 55 48 89 F5 53 48 81 EC 88 00 00 00 89 4C 24 1C 48 89 54 24 20 44 89 44 24 2C E8 D6 E3 FF FF 8B 4C 24 1C 89 44 24 28 85 C9 74 19 48 B8 01 00 00 00 01 00 00 00 49 85 44 24 38 0F 95 C0 0F B6 C0 89 44 24 1C 48 8B 45 00 48 C7 44 24 50 00 00 00 00 48 C7 44 24 48 00 00 00 00 48 C7 44 24 40 00 00 00 00 48 C7 44 24 70 00 00 00 00 48 C7 44 24 68 00 00 00 00 48 C7 44 24 60 00 00 00 00 80 38 4B 0F 84 AF 03 00 00 0F B6 50 01 80 FA 31 7D 25 C7 44 24 18 00 00 00 00 8B 44 24 18 48 81 C4 88 00 00 00 5B 5D 41 5C 41 5D 41 5E 41 5F C3 0F 1F 80 00 00 00 00 80 FA 39 0F 8E 17 03 00 }
	condition:
		$pattern
}

rule htab_expand_7f657714c4f024e7757b0ef77d2268b1 {
	meta:
		aliases = "htab_expand"
		size = "544"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 49 89 FC 55 53 48 83 EC 18 48 8B 57 28 48 2B 57 30 4C 8B 6F 20 48 8B 6F 18 44 8B 77 68 48 8D 3C 12 4A 8D 5C ED 00 49 39 FD 0F 82 6A 01 00 00 48 C1 E2 03 49 39 D5 0F 87 53 01 00 00 49 8B 4C 24 58 48 85 C9 0F 84 72 01 00 00 49 8B 7C 24 50 BA 08 00 00 00 4C 89 EE FF D1 48 85 C0 0F 84 70 01 00 00 49 89 44 24 18 4D 89 6C 24 20 49 89 ED 49 8B 44 24 30 45 89 74 24 68 49 29 44 24 28 49 C7 44 24 30 00 00 00 00 EB 14 0F 1F 80 00 00 00 00 49 83 C5 08 4C 39 EB 0F 86 CF 00 00 00 4D 8B 75 00 49 83 FE 01 76 E9 4C 89 F7 41 FF 14 24 41 8B 54 24 68 41 89 C1 89 C6 4D 8B 54 24 18 48 C1 E2 }
	condition:
		$pattern
}

rule objalloc_free_block_8f88cd2cd8eaa797368f1cc9283bb226 {
	meta:
		aliases = "objalloc_free_block"
		size = "343"
		objfiles = "objalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 49 89 FC 55 53 48 83 EC 18 48 8B 7F 10 48 85 FF 74 46 49 89 F7 48 89 FB 45 31 F6 EB 14 0F 1F 00 48 8D 53 10 49 39 D7 74 37 48 8B 1B 48 85 DB 74 27 48 8B 6B 08 48 85 ED 75 E6 49 39 DF 76 0C 48 8D AB E0 0F 00 00 49 39 EF 72 69 49 89 DE 48 8B 1B 48 85 DB 75 DB 66 90 E8 ?? ?? ?? ?? 0F 1F 00 48 8B 1B 48 39 DF 74 10 4C 8B 2F E8 ?? ?? ?? ?? 4C 39 EB 4C 89 EF 75 F0 49 89 5C 24 10 48 83 7B 08 00 74 0E 0F 1F 40 00 48 8B 1B 48 83 7B 08 00 75 F6 48 81 C3 E0 0F 00 00 49 89 2C 24 48 29 EB 41 89 5C 24 08 48 83 C4 18 5B 5D 41 5C 41 5D 41 5E 41 5F C3 48 85 DB 74 9F 48 39 DF 48 C7 44 24 }
	condition:
		$pattern
}

rule work_stuff_copy_to_from_b8cf3e765d6f6c55a7e38c588ddc29e5 {
	meta:
		aliases = "work_stuff_copy_to_from"
		size = "822"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 48 89 FD 53 48 89 F3 48 83 EC 08 E8 27 FA FF FF 48 89 EF E8 CF F6 FF FF 48 8B 03 48 89 45 00 48 8B 43 08 48 89 45 08 48 8B 43 10 48 89 45 10 48 8B 43 18 48 89 45 18 48 8B 43 20 48 89 45 20 48 8B 43 28 48 89 45 28 48 8B 43 30 48 89 45 30 48 8B 43 38 48 89 45 38 48 8B 43 40 48 89 45 40 48 8B 43 48 48 89 45 48 48 8B 43 50 48 89 45 50 48 8B 43 58 48 89 45 58 48 8B 43 60 48 89 45 60 48 8B 43 68 48 89 45 68 48 63 43 34 85 C0 0F 85 A4 01 00 00 8B 73 30 45 31 E4 85 F6 7E 5C 66 2E 0F 1F 84 00 00 00 00 00 48 8B 43 08 4E 8D 2C E5 00 00 00 00 4A 8B 3C E0 E8 ?? ?? ?? ?? 4C 03 6D }
	condition:
		$pattern
}

rule demangle_expression_338fce478f0b78236663ca2d3711f565 {
	meta:
		aliases = "demangle_expression"
		size = "409"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 54 55 53 48 83 EC 38 48 89 54 24 18 48 89 7C 24 20 BA 01 00 00 00 48 8B 7C 24 18 48 89 74 24 10 BE ?? ?? ?? ?? 89 4C 24 2C E8 6B A9 FF FF 48 8B 44 24 10 48 8B 54 24 10 31 C9 48 8B 00 49 89 C5 B8 01 00 00 00 49 83 C5 01 4C 89 2A 41 0F B6 55 00 80 FA 57 0F 84 E4 00 00 00 0F 1F 80 00 00 00 00 84 D2 0F 84 18 01 00 00 85 C9 0F 84 96 00 00 00 4C 89 EF BD ?? ?? ?? ?? 31 DB E8 ?? ?? ?? ?? 49 89 C4 EB 16 0F 1F 40 00 48 83 C3 01 48 83 C5 18 48 83 FB 4F 0F 84 E6 00 00 00 4C 8B 75 00 4C 89 F7 E8 ?? ?? ?? ?? 49 39 C4 49 89 C7 72 DA 48 89 C2 4C 89 EE 4C 89 F7 E8 ?? ?? ?? ?? 85 C0 75 C8 }
	condition:
		$pattern
}

rule byte_re_search_2_587e37d27c02dd16f62b6833f04d35e3 {
	meta:
		aliases = "byte_re_search_2"
		size = "810"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 89 D5 45 01 C5 41 54 49 89 FC 55 53 44 89 CB 48 83 EC 48 45 39 E9 4C 8B 7F 20 8B AC 24 80 00 00 00 48 89 74 24 20 89 54 24 1C 48 89 4C 24 28 44 89 44 24 34 4C 8B 77 28 41 8D 04 29 0F 8F 97 02 00 00 44 89 CA C1 EA 1F 84 D2 0F 85 89 02 00 00 85 C0 0F 88 C1 02 00 00 44 89 EA 44 29 CA 41 39 C5 0F 4C EA 48 83 7F 10 00 0F 85 32 02 00 00 4D 85 FF 74 0C 41 F6 44 24 38 08 0F 84 99 01 00 00 48 63 44 24 1C 48 8B 54 24 28 4D 85 FF 0F 95 44 24 33 48 29 C2 48 89 54 24 38 0F 1F 80 00 00 00 00 44 39 EB 0F 8D 9F 00 00 00 80 7C 24 33 00 0F 84 94 00 00 00 41 F6 44 24 38 01 0F 85 88 00 00 00 }
	condition:
		$pattern
}

rule pex_get_status_and_time_f4c2a3c03868653734e2c4e61f6c25f6 {
	meta:
		aliases = "pex_get_status_and_time"
		size = "274"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 41 BD 01 00 00 00 41 54 55 53 48 89 FB 48 83 EC 28 89 74 24 14 48 63 77 2C 39 77 48 48 89 54 24 18 0F 84 AE 00 00 00 48 8B 7F 38 48 C1 E6 02 49 89 CF E8 ?? ?? ?? ?? F6 03 01 48 89 43 38 0F 85 A6 00 00 00 44 8B 63 48 44 3B 63 2C 0F 8D B2 00 00 00 49 63 EC 4C 89 F8 41 BD 01 00 00 00 49 89 EE 49 C1 E6 05 4D 89 F7 45 89 E6 49 89 C4 0F 1F 40 00 48 8B 53 40 48 8B 43 70 48 89 DF 48 8B 73 30 4C 8B 4C 24 18 44 8B 44 24 14 4A 8D 0C 3A 48 85 D2 BA 00 00 00 00 48 8B 34 EE 48 8B 40 20 48 0F 44 CA 48 8B 53 38 4C 89 24 24 48 8D 14 AA FF D0 85 C0 B8 00 00 00 00 44 0F 48 E8 41 83 C6 01 48 83 }
	condition:
		$pattern
}

rule floatformat_to_double_a7cd7deef24169e8c7c75c7a963e8a90 {
	meta:
		aliases = "floatformat_to_double"
		size = "659"
		objfiles = "floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 55 49 89 F5 41 54 55 53 48 89 FB 48 83 EC 28 44 8B 5F 04 44 8B 37 8B 4F 0C 44 8B 47 10 4C 89 EF 48 89 54 24 18 44 89 F6 44 89 DA 44 89 1C 24 E8 97 FD FF FF 8B 53 18 44 8B 1C 24 48 39 D0 0F 84 87 01 00 00 48 85 C0 49 89 C4 44 8B 7B 20 8B 6B 1C 0F 85 54 01 00 00 66 0F 57 C0 44 89 F6 F2 0F 11 44 24 10 EB 46 0F 1F 44 00 00 4D 85 E4 75 68 8B 53 1C 2B 53 14 8D 7A 01 29 EF 44 29 F7 48 85 C0 0F 88 84 00 00 00 F2 48 0F 2A C0 E8 ?? ?? ?? ?? F2 0F 58 44 24 10 45 31 E4 F2 0F 11 44 24 10 44 8B 5B 04 8B 33 44 01 F5 45 29 F7 45 85 FF 0F 8E 96 00 00 00 41 83 FF 20 41 BE 20 00 00 00 89 E9 45 0F }
	condition:
		$pattern
}

rule htab_find_slot_with_hash_c764b9bb753c76bff351d41615b3ce9f {
	meta:
		aliases = "htab_find_slot_with_hash"
		size = "493"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 41 89 D6 41 55 41 54 55 48 89 FD 53 48 83 EC 28 83 F9 01 4C 8B 67 20 48 89 74 24 10 89 4C 24 1C 0F 84 66 01 00 00 8B 75 68 45 89 F5 44 89 F1 44 89 F3 48 89 F7 48 C1 E7 04 8B 87 ?? ?? ?? ?? 49 0F AF C5 48 C1 E8 20 29 C1 D1 E9 01 C8 8B 8F ?? ?? ?? ?? D3 E8 0F AF 87 ?? ?? ?? ?? 83 45 38 01 29 C3 48 8B 45 18 89 D9 48 C1 E1 03 4C 8D 3C 08 49 8B 3F 48 85 FF 0F 84 4E 01 00 00 48 83 FF 01 74 24 48 89 4C 24 08 48 8B 74 24 10 FF 55 08 85 C0 48 8B 4C 24 08 0F 85 E0 00 00 00 8B 75 68 48 8B 45 18 45 31 FF 48 C1 E6 04 44 89 F2 8B 8E ?? ?? ?? ?? 49 0F AF CD 45 8D 6E 01 48 C1 E9 20 29 CA D1 EA 01 }
	condition:
		$pattern
}

rule demangle_template_c9abeb578346ddc0cc71589bf92f816a {
	meta:
		aliases = "demangle_template"
		size = "1585"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 45 89 C6 41 55 49 89 D5 41 54 49 89 FC 55 48 89 F5 53 48 83 EC 78 48 8B 06 45 85 C0 44 89 4C 24 18 48 8D 50 01 48 89 16 0F 84 3E 01 00 00 80 78 01 7A 48 89 CB 0F 84 C1 00 00 00 48 89 F7 E8 C9 E7 FF FF 85 C0 89 44 24 2C 0F 8E 95 02 00 00 4C 8B 7D 00 89 44 24 10 4C 89 FF E8 ?? ?? ?? ?? 48 63 54 24 10 39 C2 0F 8F 78 02 00 00 41 F6 04 24 04 74 15 BF ?? ?? ?? ?? B9 08 00 00 00 4C 89 FE F3 A6 0F 84 FD 04 00 00 4C 89 FE 4C 89 EF E8 C9 ED FF FF 48 63 54 24 2C 4C 8B 7D 00 31 C0 48 85 DB 74 1C 4C 89 FE 48 89 DF 89 44 24 10 E8 AA ED FF FF 48 63 54 24 2C 4C 8B 7D 00 8B 44 24 10 4D 8D 04 17 85 }
	condition:
		$pattern
}

rule dupargv_50b8d027dbfa96be12c0c2e5a29a89ac {
	meta:
		aliases = "dupargv"
		size = "219"
		objfiles = "argv@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 41 56 49 89 FE 41 55 41 54 55 53 48 83 EC 08 48 85 FF 0F 84 8D 00 00 00 4C 8B 3F 4D 85 FF 0F 84 96 00 00 00 48 8D 5F 08 31 D2 48 89 D8 90 48 83 C0 08 83 C2 01 48 83 78 F8 00 75 F2 8D 7A 01 48 63 FF 48 C1 E7 03 E8 ?? ?? ?? ?? 48 85 C0 49 89 C5 74 52 4D 89 F4 31 ED EB 26 0F 1F 40 00 49 8B 34 24 48 89 DD 48 89 C7 49 89 DC 48 83 C3 08 4C 29 F5 E8 ?? ?? ?? ?? 4C 8B 7B F8 4D 85 FF 74 4E 4C 89 FF E8 ?? ?? ?? ?? 8D 78 01 48 63 FF E8 ?? ?? ?? ?? 48 85 C0 49 89 44 2D 00 75 C1 4C 89 EF E8 ?? ?? ?? ?? 45 31 ED 48 83 C4 08 4C 89 E8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 BF 08 00 00 00 E8 ?? ?? ?? ?? 48 85 }
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

rule sort_pointers_286ae5c52a435263b1cb1945887b068e {
	meta:
		aliases = "sort_pointers"
		size = "326"
		objfiles = "sort@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 45 31 DB 45 31 FF 41 56 41 55 41 54 55 53 48 81 EC A0 03 00 00 66 0F 1F 84 00 00 00 00 00 49 C1 E7 08 4D 01 DF 49 83 C3 01 49 83 FB 08 75 EF 41 BD 08 00 00 00 31 C0 4C 8D 34 FD 00 00 00 00 4D 89 EA 4C 8D 24 FD F8 FF FF FF 48 8D 5C 24 98 4D 29 DA 45 84 FF BD 80 00 00 00 0F 85 BE 00 00 00 4C 89 5C 24 90 4D 89 DA 48 89 DF 48 89 E9 4F 8D 04 32 F3 48 AB 4A 8D 0C 16 49 01 F0 4C 39 C1 0F 83 B5 00 00 00 66 0F 1F 84 00 00 00 00 00 0F B6 39 48 83 C1 08 83 44 BC 98 01 49 39 C8 77 EF 44 8B 4C 24 9C 8B 4C 24 98 4C 8D 43 04 EB 07 45 8B 08 41 8B 48 FC 41 01 C9 48 8D 8C 24 98 03 00 00 45 89 08 49 83 C0 }
	condition:
		$pattern
}

rule demangle_arm_hp_template_e793a0f436c7a08f50971189c677dd93 {
	meta:
		aliases = "demangle_arm_hp_template"
		size = "1788"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 48 63 C2 49 89 C7 41 56 41 55 49 89 F5 41 54 49 89 FC 55 48 89 CD 53 48 83 EC 78 48 8B 1E 48 89 44 24 10 49 01 DF F7 07 00 10 00 00 74 0A 41 80 3F 58 0F 84 46 01 00 00 45 8B 34 24 41 F7 C6 00 18 00 00 74 5B BE ?? ?? ?? ?? 48 89 DF 89 54 24 08 E8 ?? ?? ?? ?? 48 85 C0 48 89 C1 8B 54 24 08 74 3E 4C 8D 74 24 28 48 8D 40 06 48 89 0C 24 4C 89 F7 48 89 44 24 28 E8 12 CF FF FF 83 F8 FF 8B 54 24 08 48 8B 0C 24 74 7B 48 8B 74 24 28 48 98 48 01 F0 49 39 C7 0F 84 9F 04 00 00 45 8B 34 24 41 81 E6 00 21 00 00 74 5B BE ?? ?? ?? ?? 48 89 DF 89 54 24 08 E8 ?? ?? ?? ?? 48 85 C0 48 89 C1 8B 54 24 08 0F 84 }
	condition:
		$pattern
}

rule md5_process_block_0664b1e0f5cbcce750efb3e3056068e8 {
	meta:
		aliases = "md5_process_block"
		size = "2149"
		objfiles = "md5@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 48 89 F0 48 83 E0 FC 41 56 48 01 F8 41 55 41 54 55 48 89 FD 53 8B 5A 04 48 89 54 24 F8 48 89 44 24 F0 8B 02 8B 52 08 89 54 24 C0 48 8B 54 24 F8 89 44 24 E8 8B 52 0C 89 54 24 C4 48 8B 54 24 F8 8B 42 10 01 F0 48 39 C6 89 42 10 76 04 83 42 14 01 48 3B 6C 24 F0 0F 83 E0 07 00 00 66 90 8B 44 24 C4 33 44 24 C0 44 8B 5D 00 8B 4C 24 E8 8B 75 04 8B 7C 24 C4 44 8B 45 08 44 8B 4C 24 C0 21 D8 33 44 24 C4 41 8D 94 0B 78 A4 6A D7 8D 8C 3E 56 B7 C7 E8 89 74 24 C8 44 8B 55 0C 43 8D B4 08 DB 70 20 24 44 8B 65 10 44 8B 6D 14 44 8B 75 18 44 8B 7D 24 01 D0 8B 54 24 C0 41 8D BC 1A EE CE BD C1 C1 C0 07 44 89 }
	condition:
		$pattern
}

rule split_directories_21452d5e5fdf72cfa4e9e0a0fcb344fe {
	meta:
		aliases = "split_directories"
		size = "370"
		objfiles = "make_relative_prefix@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 48 89 F8 31 C9 41 56 41 55 41 54 49 89 FC 55 53 48 83 EC 18 0F BE 17 48 89 74 24 08 EB 03 0F BE 10 48 83 C0 01 85 D2 74 25 83 FA 2F 75 F0 0F BE 10 83 C1 01 80 FA 2F 75 E8 48 83 C0 01 0F BE 10 80 FA 2F 74 F4 48 83 C0 01 85 D2 75 DC 90 8D 79 02 48 63 FF 48 C1 E7 03 E8 ?? ?? ?? ?? 48 85 C0 49 89 C6 0F 84 D3 00 00 00 45 31 ED 45 89 EF 4C 89 E2 0F 1F 40 00 0F BE 0A 48 8D 5A 01 85 C9 74 5D 83 F9 2F 48 89 DA 75 ED 80 3B 2F 75 09 48 83 C3 01 80 3B 2F 74 F7 48 89 DD 4C 29 E5 8D 7D 01 48 63 ED 48 63 FF E8 ?? ?? ?? ?? 48 89 EA 49 89 C7 4C 89 E6 48 89 C7 E8 ?? ?? ?? ?? 4F 89 3C EE 49 83 C5 01 41 C6 }
	condition:
		$pattern
}

rule demangle_signature_06403c6ed2ae489fa4d34131c59d703e {
	meta:
		aliases = "demangle_signature"
		size = "2115"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 48 8D 47 30 41 BF 01 00 00 00 41 56 49 89 D6 41 55 45 31 ED 41 54 45 31 E4 55 48 89 F5 53 48 89 FB 48 81 EC 88 00 00 00 4C 8B 4D 00 C7 44 24 1C 00 00 00 00 C7 44 24 18 00 00 00 00 48 89 44 24 10 41 0F BE 39 40 84 FF 0F 84 66 01 00 00 8D 47 D0 3C 45 76 29 F7 03 00 03 00 00 0F 85 A5 05 00 00 0F 1F 44 00 00 45 31 FF 48 81 C4 88 00 00 00 44 89 F8 5B 5D 41 5C 41 5D 41 5E 41 5F C3 0F B6 C0 FF 24 C5 ?? ?? ?? ?? 66 0F 1F 44 00 00 4D 85 E4 48 8D 4C 24 20 48 8D 54 24 40 4D 0F 44 E1 41 B8 01 00 00 00 41 B9 01 00 00 00 48 89 EE 48 89 DF 48 C7 44 24 30 00 00 00 00 48 C7 44 24 28 00 00 00 00 48 C7 44 }
	condition:
		$pattern
}

rule partition_print_76c8a85e1117c0161bb8eb634222f41a {
	meta:
		aliases = "partition_print"
		size = "443"
		objfiles = "partition@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 48 8D 57 08 41 56 41 55 41 54 49 89 FC 55 53 48 83 EC 38 8B 07 48 89 74 24 10 48 89 54 24 28 48 63 D8 89 44 24 1C 48 89 DF E8 ?? ?? ?? ?? 31 F6 48 89 DA 48 89 C7 48 89 C5 E8 ?? ?? ?? ?? 48 8D 3C 9D 00 00 00 00 E8 ?? ?? ?? ?? 48 8B 74 24 10 BF 5B 00 00 00 49 89 C5 E8 ?? ?? ?? ?? 8B 44 24 1C 48 C7 44 24 08 00 00 00 00 85 C0 0F 8E F4 00 00 00 0F 1F 40 00 48 8B 4C 24 08 8B 44 24 08 80 7C 0D 00 00 0F 85 C8 00 00 00 48 8D 14 49 49 63 54 D4 08 48 8D 14 52 41 8B 5C D4 18 85 DB 0F 8E EF 00 00 00 48 8B 4C 24 28 31 D2 0F 1F 00 41 89 44 95 00 48 98 48 83 C2 01 C6 44 05 00 01 48 8D 04 40 49 8B 44 C4 }
	condition:
		$pattern
}

rule byte_regex_compile_08419ef105c1934fe92084a596065ac8 {
	meta:
		aliases = "byte_regex_compile"
		size = "11312"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 CF 41 56 41 55 41 54 55 48 89 F5 53 48 81 EC 78 01 00 00 48 8B 49 28 48 89 7C 24 20 48 89 BC 24 D8 00 00 00 BF 00 05 00 00 64 48 8B 04 25 28 00 00 00 48 89 84 24 68 01 00 00 31 C0 48 89 54 24 18 48 89 4C 24 30 E8 ?? ?? ?? ?? 48 85 C0 48 89 44 24 28 0F 84 F3 00 00 00 48 8B 54 24 18 41 80 67 38 97 8B 1D ?? ?? ?? ?? 49 C7 47 10 00 00 00 00 49 C7 47 30 00 00 00 00 49 89 57 18 85 DB 0F 84 37 01 00 00 49 83 7F 08 00 0F 84 EC 00 00 00 49 8B 1F 48 8B 54 24 20 48 03 6C 24 20 48 8B 4C 24 18 45 31 D2 48 8B 74 24 18 48 8B 44 24 18 45 31 F6 48 89 5C 24 10 C7 44 24 48 00 00 00 00 45 31 ED 83 E1 }
	condition:
		$pattern
}

rule expandargv_9f0d7ec65413466a78c8ec51036a9d6d {
	meta:
		aliases = "expandargv"
		size = "601"
		objfiles = "argv@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 41 56 41 55 41 54 45 31 E4 55 53 48 83 EC 38 8B 17 48 89 7C 24 20 EB 06 0F 1F 00 41 89 DC 41 8D 5C 24 01 39 D3 0F 8D E8 01 00 00 49 8B 07 48 63 EB 4C 8D 2C ED 00 00 00 00 48 8B 04 E8 80 38 40 75 D9 48 8D 78 01 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 49 89 C6 0F 84 A7 01 00 00 31 F6 BA 02 00 00 00 48 89 C7 E8 ?? ?? ?? ?? 83 F8 FF 0F 84 87 01 00 00 4C 89 F7 E8 ?? ?? ?? ?? 48 83 F8 FF 0F 84 75 01 00 00 31 D2 31 F6 4C 89 F7 48 89 04 24 E8 ?? ?? ?? ?? 83 F8 FF 4C 8B 14 24 0F 84 58 01 00 00 49 8D 7A 01 E8 ?? ?? ?? ?? 4C 8B 14 24 4C 89 F1 BE 01 00 00 00 48 89 C7 48 89 44 24 28 4C 89 D2 }
	condition:
		$pattern
}

rule cplus_demangle_fill_operator_5a8631a3e10de408a4485d4b89b205f4 {
	meta:
		aliases = "cplus_demangle_fill_operator"
		size = "193"
		objfiles = "cp_demint@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 41 56 41 55 41 54 55 53 48 83 EC 08 48 85 F6 0F 84 96 00 00 00 48 85 FF 49 89 FC 0F 84 8A 00 00 00 48 89 F7 41 89 D6 E8 ?? ?? ?? ?? 48 8B 35 ?? ?? ?? ?? 41 89 C5 48 85 F6 74 70 31 DB 31 C9 EB 20 66 2E 0F 1F 84 00 00 00 00 00 83 C3 01 89 D9 4C 8D 04 49 4A 8B 34 C5 ?? ?? ?? ?? 48 85 F6 74 4A 48 8D 0C 49 44 39 2C CD ?? ?? ?? ?? 48 8D 2C CD 00 00 00 00 75 D4 44 39 B5 ?? ?? ?? ?? 75 CB 4C 89 FF E8 ?? ?? ?? ?? 85 C0 75 BF 48 81 C5 ?? ?? ?? ?? 41 C7 04 24 28 00 00 00 B0 01 49 89 6C 24 08 EB 09 0F 1F 80 00 00 00 00 31 C0 48 83 C4 08 5B 5D 41 5C 41 5D 41 5E 41 5F C3 }
	condition:
		$pattern
}

rule do_type_1f18ae5e6d2b786752e07321f61e9cea {
	meta:
		aliases = "do_type"
		size = "3474"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 41 56 41 55 49 89 D5 41 54 45 31 E4 55 BD 01 00 00 00 53 48 89 FB 48 81 EC 98 00 00 00 48 C7 42 10 00 00 00 00 48 C7 42 08 00 00 00 00 64 48 8B 04 25 28 00 00 00 48 89 84 24 88 00 00 00 31 C0 48 C7 44 24 40 00 00 00 00 48 C7 44 24 38 00 00 00 00 48 C7 44 24 30 00 00 00 00 48 C7 02 00 00 00 00 66 0F 1F 84 00 00 00 00 00 85 ED 40 0F 95 C6 31 D2 85 D2 0F 85 F0 03 00 00 40 84 F6 0F 84 E7 03 00 00 49 8B 07 BA 01 00 00 00 44 0F B6 30 41 8D 4E BF 80 F9 34 77 DA 0F B6 C9 FF 24 CD ?? ?? ?? ?? 0F 1F 84 00 00 00 00 00 F6 03 02 74 42 48 8B 54 24 38 48 39 54 24 30 74 16 48 8D 7C 24 30 BE ?? }
	condition:
		$pattern
}

rule htab_find_with_hash_ffd44af28776d1a0de95d2b3fc02c89a {
	meta:
		aliases = "htab_find_with_hash"
		size = "300"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 F7 89 D1 41 56 41 89 D6 41 55 41 54 49 89 FC 55 53 89 D3 48 83 EC 18 83 47 38 01 4C 8B 6F 20 8B 7F 68 48 89 FE 48 C1 E6 04 8B 86 ?? ?? ?? ?? 49 0F AF C6 48 C1 E8 20 29 C1 D1 E9 01 C8 8B 8E ?? ?? ?? ?? D3 E8 0F AF 86 ?? ?? ?? ?? 49 8B 74 24 18 29 C3 89 D8 48 8B 2C C6 48 85 ED 0F 84 B2 00 00 00 48 83 FD 01 74 25 89 54 24 08 4C 89 FE 48 89 EF 41 FF 54 24 08 85 C0 8B 54 24 08 0F 85 93 00 00 00 41 8B 7C 24 68 49 8B 74 24 18 48 C1 E7 04 8B 87 ?? ?? ?? ?? 8B 8F ?? ?? ?? ?? 49 0F AF C6 44 8D 72 01 48 C1 E8 20 29 C2 D1 EA 01 C2 8B 87 ?? ?? ?? ?? D3 EA 83 E8 02 0F AF D0 41 8B 44 24 3C 41 29 }
	condition:
		$pattern
}

rule md5_process_bytes_42514dd91a1aa9af0ffbb2d8348af393 {
	meta:
		aliases = "md5_process_bytes"
		size = "410"
		objfiles = "md5@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 49 89 FF 41 56 49 89 F6 41 55 49 89 D5 41 54 55 53 48 83 EC 18 8B 5A 18 85 DB 0F 85 D6 00 00 00 49 83 FE 40 0F 86 9E 00 00 00 41 F6 C7 03 0F 84 02 01 00 00 49 8D 6D 1C 4D 89 F4 4C 89 FB 48 8B 03 4C 89 EA BE 40 00 00 00 48 89 EF 49 83 EC 40 48 89 45 00 48 8B 43 08 48 89 45 08 48 8B 43 10 48 89 45 10 48 8B 43 18 48 89 45 18 48 8B 43 20 48 89 45 20 48 8B 43 28 48 89 45 28 48 8B 43 30 48 89 45 30 48 8B 43 38 48 83 C3 40 48 89 45 38 E8 ?? ?? ?? ?? 49 83 FC 40 77 A3 49 8D 46 BF 48 C1 E8 06 48 8D 50 01 48 F7 D8 48 C1 E0 06 48 C1 E2 06 4D 8D 74 06 C0 49 01 D7 4C 89 F0 41 83 E6 3F 48 83 E0 C0 49 }
	condition:
		$pattern
}

rule xregcomp_7c2c3c787f33dc14036e45f49437681f {
	meta:
		aliases = "xregcomp"
		size = "397"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) 57 89 D0 49 89 FF 83 E0 01 41 56 41 55 41 89 D5 41 54 55 53 48 83 EC 18 83 F8 01 48 C7 07 00 00 00 00 4D 19 E4 48 C7 47 08 00 00 00 00 48 C7 47 10 00 00 00 00 49 81 E4 CA 4F FD FF BF 00 01 00 00 48 89 74 24 08 49 81 C4 FC B2 03 00 E8 ?? ?? ?? ?? 41 F6 C5 02 49 89 47 20 0F 85 AF 00 00 00 49 C7 47 28 00 00 00 00 41 F6 C5 04 0F 85 7D 00 00 00 41 0F B6 47 38 83 E0 7F 41 88 47 38 41 C1 ED 03 48 8B 7C 24 08 83 E0 EF 41 83 E5 01 BB 08 00 00 00 41 C1 E5 04 44 09 E8 41 88 47 38 E8 ?? ?? ?? ?? 48 8B 7C 24 08 4C 89 F9 4C 89 E2 48 89 C6 E8 09 D1 FF FF 83 F8 10 74 20 85 C0 89 C3 75 1A 49 83 7F 20 00 74 }
	condition:
		$pattern
}

rule higher_prime_index_929c58eed7b2c7ea7e978d19c9f17109 {
	meta:
		aliases = "higher_prime_index"
		size = "143"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) B8 1E 00 00 00 31 C0 EB 0E 66 0F 1F 44 00 00 8D 42 01 44 39 C0 74 40 44 89 C2 29 C2 D1 EA 01 C2 89 D6 48 C1 E6 04 8B 8E ?? ?? ?? ?? 48 39 CF 77 DE 39 D0 41 89 D0 74 1F 29 C2 D1 EA 01 C2 89 D6 48 C1 E6 04 8B 8E ?? ?? ?? ?? 48 39 F9 73 E2 8D 42 01 44 39 C0 75 C0 89 C2 48 C1 E2 04 8B 92 ?? ?? ?? ?? 48 39 D7 77 02 F3 C3 48 83 EC 08 48 89 F9 48 8B 3D ?? ?? ?? ?? BA ?? ?? ?? ?? BE 01 00 00 00 31 C0 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule htab_create_362d4d7e4c3709ec96849403e7b4b580 {
	meta:
		aliases = "htab_create"
		size = "17"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) B9 ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? E9 0F FE FF FF }
	condition:
		$pattern
}

rule htab_try_create_fce5de4199b2af08604accb10ca02da6 {
	meta:
		aliases = "htab_try_create"
		size = "17"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 41 ) B9 ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? E9 EF FD FF FF }
	condition:
		$pattern
}

rule get_field_883b9996ff7455805a26a64ccc5fb1ba {
	meta:
		aliases = "get_field"
		size = "193"
		objfiles = "floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | 44 ) 01 C1 55 41 89 CA 41 C1 EA 03 85 F6 53 0F 85 8C 00 00 00 C1 EA 03 41 89 C9 83 EA 01 41 83 E1 07 44 29 D2 41 8D 49 F8 89 D0 83 C2 01 0F B6 04 07 F7 D9 D3 F8 48 98 45 89 C2 BB 01 00 00 00 45 29 CA EB 30 0F 1F 40 00 44 89 D1 89 DD D3 E5 8D 4D FF 41 21 CB 44 89 C9 41 D3 E3 4D 63 DB 4C 09 D8 8D 4A 01 41 83 C1 08 83 EA 01 85 F6 0F 44 D1 41 83 EA 08 45 39 C8 76 1F 89 D1 41 83 FA 07 44 0F B6 1C 0F 76 C2 44 89 C9 41 D3 E3 4D 63 DB 4C 09 D8 EB CD 0F 1F 40 00 5B 5D C3 0F 1F 44 00 00 41 89 C9 44 89 D0 41 8D 52 FF 41 83 E1 07 0F B6 04 07 41 8D 49 F8 F7 D9 D3 F8 48 98 E9 76 FF FF FF }
	condition:
		$pattern
}

rule string_prepends_DOT_isra_DOT_8_4aeea90df16631e978405e46c20520e8 {
	meta:
		aliases = "string_prepends.isra.8"
		size = "18"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 39 D6 74 0B 48 29 F2 E9 73 FF FF FF 0F 1F 00 F3 C3 }
	condition:
		$pattern
}

rule spaces_d3e19a8f4b773a1c73a3dda75c47b5c2 {
	meta:
		aliases = "spaces"
		size = "125"
		objfiles = "spaces@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 63 15 ?? ?? ?? ?? 53 48 63 DF 39 DA 7C 11 48 8B 05 ?? ?? ?? ?? 48 29 DA 48 01 D0 5B C3 66 90 48 8B 3D ?? ?? ?? ?? 48 85 FF 74 05 E8 ?? ?? ?? ?? 8D 7B 01 48 63 FF E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 74 31 48 63 CB 48 01 C1 48 39 C8 48 89 CA 74 16 66 2E 0F 1F 84 00 00 00 00 00 48 83 EA 01 48 39 C2 C6 02 20 75 F4 89 1D ?? ?? ?? ?? C6 01 00 31 D2 EB A0 31 C0 5B C3 }
	condition:
		$pattern
}

rule partition_union_6af0bc0b209e16d564368362d80010b8 {
	meta:
		aliases = "partition_union"
		size = "162"
		objfiles = "partition@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 63 F6 48 63 D2 48 8D 04 76 49 89 D2 48 8D 04 C7 8B 48 08 4C 8D 48 08 48 8D 04 52 48 8D 04 C7 4C 8D 40 08 8B 40 08 39 C8 74 65 45 8B 58 10 45 39 59 10 73 63 48 8D 14 52 4C 8D 44 D7 08 48 8D 14 76 48 63 F0 48 8D 34 76 48 8D 14 D7 4C 63 4A 08 48 8D 4A 08 89 42 08 4F 8D 0C 49 46 8B 4C CF 18 44 01 4C F7 18 48 8B 71 08 48 39 F1 48 89 F2 74 11 66 0F 1F 44 00 00 89 02 48 8B 52 08 48 39 D1 75 F5 49 8B 50 08 49 89 70 08 48 89 51 08 C3 F3 C3 66 0F 1F 44 00 00 48 89 F2 89 C8 4C 89 D6 EB 93 }
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

rule xmalloc_set_program_name_0d39caf13c69dc1a8aa242cbaacd582f {
	meta:
		aliases = "xmalloc_set_program_name"
		size = "47"
		objfiles = "xmalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 3D ?? ?? ?? ?? 00 48 89 3D ?? ?? ?? ?? 74 07 F3 C3 0F 1F 44 00 00 48 83 EC 08 31 FF E8 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 83 C4 08 C3 }
	condition:
		$pattern
}

rule xre_compile_pattern_766cf674befa74cc1de2c92048692d3a {
	meta:
		aliases = "xre_compile_pattern"
		size = "63"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 0F B6 42 38 48 89 D1 83 E0 E9 83 C8 80 88 42 38 48 8B 15 ?? ?? ?? ?? E8 D0 D2 FF FF 85 C0 74 14 48 98 48 8B 04 C5 ?? ?? ?? ?? 48 83 C4 08 C3 0F 1F 44 00 00 31 C0 48 83 C4 08 C3 }
	condition:
		$pattern
}

rule signo_max_930b68442deba289ec1f2ad8e8906899 {
	meta:
		aliases = "signo_max"
		size = "55"
		objfiles = "strsignal@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 83 3D ?? ?? ?? ?? 00 74 22 83 3D ?? ?? ?? ?? 41 B8 41 00 00 00 0F 4D 05 ?? ?? ?? ?? 48 83 C4 08 83 E8 01 C3 0F 1F 80 00 00 00 00 E8 2B FF FF FF EB D7 }
	condition:
		$pattern
}

rule errno_max_d95af998f3225d1b5927941c049a90ba {
	meta:
		aliases = "errno_max"
		size = "55"
		objfiles = "strerror@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 08 48 83 3D ?? ?? ?? ?? 00 74 22 8B 05 ?? ?? ?? ?? 39 05 ?? ?? ?? ?? 0F 4D 05 ?? ?? ?? ?? 48 83 C4 08 83 E8 01 C3 0F 1F 80 00 00 00 00 E8 2B FF FF FF EB D7 }
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

rule xre_match_6aacaffd9a0fcc15f3078b11e24d3694 {
	meta:
		aliases = "xre_match"
		size = "35"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 41 89 C9 48 89 F1 89 54 24 08 4C 89 04 24 31 F6 41 89 D0 31 D2 E8 B2 AE FF FF 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule strsigno_f4b75ac1107ed77e12feab40f10025d9 {
	meta:
		aliases = "strerrno, strsigno"
		size = "146"
		objfiles = "strsignal@libiberty.a, strerror@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 83 3D ?? ?? ?? ?? 00 74 72 85 FF 78 5E 3B 3D ?? ?? ?? ?? 7D 56 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 1A 48 63 D7 48 8B 04 D0 48 85 C0 74 0E 48 83 C4 18 C3 66 0F 1F 84 00 00 00 00 00 41 89 F8 B9 ?? ?? ?? ?? BA 20 00 00 00 BE 01 00 00 00 BF ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 48 83 C4 18 C3 0F 1F 84 00 00 00 00 00 31 C0 48 83 C4 18 C3 66 0F 1F 84 00 00 00 00 00 89 7C 24 08 E8 97 FE FF FF 8B 7C 24 08 E9 7C FF FF FF }
	condition:
		$pattern
}

rule xexit_a6d6487993028b735f41c2c6429724ee {
	meta:
		aliases = "xexit"
		size = "31"
		objfiles = "xexit@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 0A 89 7C 24 08 FF D0 8B 7C 24 08 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule cplus_demangle_v3_e7eadd3d95db7e4209b7a87dedcd6d0d {
	meta:
		aliases = "cplus_demangle_v3"
		size = "19"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 8D 54 24 08 E8 F2 FC FF FF 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule is_gnu_v3_mangled_ctor_b810f8503839fd12e5c70ff807d35a61 {
	meta:
		aliases = "is_gnu_v3_mangled_ctor"
		size = "35"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 8D 54 24 0C 48 8D 74 24 08 E8 1D FA FF FF 31 D2 85 C0 0F 45 54 24 08 48 83 C4 18 89 D0 C3 }
	condition:
		$pattern
}

rule is_gnu_v3_mangled_dtor_9a216bc917f593c8ec1ce24e1597f523 {
	meta:
		aliases = "is_gnu_v3_mangled_dtor"
		size = "35"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 48 8D 54 24 0C 48 8D 74 24 08 E8 ED F9 FF FF 31 D2 85 C0 0F 45 54 24 0C 48 83 C4 18 89 D0 C3 }
	condition:
		$pattern
}

rule java_demangle_v3_bc15f01b8aceecefdeed63b81fde6dbf {
	meta:
		aliases = "java_demangle_v3"
		size = "183"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 BE 25 00 00 00 48 8D 54 24 08 E8 CD FC FF FF 48 85 C0 74 44 48 89 C2 49 89 C0 45 31 D2 41 BB 07 00 00 00 66 0F 1F 84 00 00 00 00 00 45 0F B6 08 45 84 C9 74 20 BF ?? ?? ?? ?? 4C 89 C6 4C 89 D9 F3 A6 75 20 49 83 C0 07 41 83 C2 01 45 0F B6 08 45 84 C9 75 E0 C6 02 00 48 83 C4 18 C3 0F 1F 80 00 00 00 00 45 85 D2 74 06 41 80 F9 3E 74 0D 44 88 0A 49 83 C0 01 48 83 C2 01 EB B0 48 39 C2 77 14 EB 18 66 0F 1F 84 00 00 00 00 00 48 83 EA 01 48 39 C2 74 06 80 7A FF 20 74 F1 C6 02 5B C6 42 01 5D 41 83 EA 01 48 83 C2 02 49 83 C0 01 E9 79 FF FF FF }
	condition:
		$pattern
}

rule physmem_total_f0f7b786e63091cfbd4ccb5bc3854107 {
	meta:
		aliases = "physmem_total"
		size = "81"
		objfiles = "physmem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 BF 55 00 00 00 E8 ?? ?? ?? ?? F2 48 0F 2A C0 BF 1E 00 00 00 F2 0F 11 04 24 E8 ?? ?? ?? ?? 66 0F 57 C9 F2 0F 10 04 24 F2 48 0F 2A D0 66 0F 2E C1 72 12 66 0F 2E D1 72 0C F2 0F 59 C2 48 83 C4 18 C3 0F 1F 00 66 0F 28 C1 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule physmem_available_6af896dd0afed16158e176250002bac3 {
	meta:
		aliases = "physmem_available"
		size = "90"
		objfiles = "physmem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 18 BF 56 00 00 00 E8 ?? ?? ?? ?? F2 48 0F 2A C0 BF 1E 00 00 00 F2 0F 11 04 24 E8 ?? ?? ?? ?? 66 0F 57 C9 F2 0F 10 04 24 F2 48 0F 2A D0 66 0F 2E C1 72 12 66 0F 2E D1 72 0C F2 0F 59 C2 48 83 C4 18 C3 0F 1F 00 E8 ?? ?? ?? ?? F2 0F 59 05 ?? ?? ?? ?? 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule xre_search_3e662a32e895e835349a04fe2226ce28 {
	meta:
		aliases = "xre_search"
		size = "40"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 83 EC 28 89 54 24 10 4C 89 4C 24 08 41 89 C9 44 89 04 24 48 89 F1 41 89 D0 31 F6 31 D2 E8 1D D0 FF FF 48 83 C4 28 C3 }
	condition:
		$pattern
}

rule cplus_demangle_fill_ctor_b577b4380e11c0dad447fa846609c212 {
	meta:
		aliases = "cplus_demangle_fill_ctor"
		size = "35"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 85 D2 74 1B 48 85 FF 74 16 C7 07 06 00 00 00 89 77 08 B8 01 00 00 00 48 89 57 10 C3 0F 1F 00 31 C0 C3 }
	condition:
		$pattern
}

rule cplus_demangle_fill_dtor_9ec23be900f1131b4e3a8e15bbc8e56a {
	meta:
		aliases = "cplus_demangle_fill_dtor"
		size = "35"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 85 D2 74 1B 48 85 FF 74 16 C7 07 07 00 00 00 89 77 08 B8 01 00 00 00 48 89 57 10 C3 0F 1F 00 31 C0 C3 }
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

rule string_prepend_b2ce379bdc4fc3c29dfe6d17c730caa4 {
	meta:
		aliases = "string_prepend"
		size = "57"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 85 F6 74 05 80 3E 00 75 06 F3 C3 0F 1F 40 00 53 48 89 FB 48 89 F7 48 83 EC 10 48 89 74 24 08 E8 ?? ?? ?? ?? 48 8B 74 24 08 48 83 C4 10 48 89 DF 5B 89 C2 E9 27 FF FF FF }
	condition:
		$pattern
}

rule cplus_demangle_fill_component_a6ea535e2832dd5473709c11659b1b6a {
	meta:
		aliases = "cplus_demangle_fill_component"
		size = "89"
		objfiles = "cp_demint@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 49 89 C8 74 40 83 FE 32 77 3B 89 F1 B8 01 00 00 00 48 D3 E0 48 B9 00 FB CF EF 05 04 00 00 48 85 C8 75 2A 48 B9 1E 04 00 10 F8 F8 07 00 48 85 C8 74 13 89 37 48 89 57 08 B8 01 00 00 00 4C 89 47 10 C3 0F 1F 00 31 C0 C3 0F 1F 44 00 00 31 C0 4D 85 C0 74 DE F3 C3 }
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

rule xre_comp_435d01ea6c3617aa178732f87631326f {
	meta:
		aliases = "xre_comp"
		size = "180"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 85 FF 53 48 89 FB 74 47 48 83 3D ?? ?? ?? ?? 00 74 55 48 89 DF 80 0D ?? ?? ?? ?? 80 E8 ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? B9 ?? ?? ?? ?? 48 89 C6 48 89 DF E8 77 D2 FF FF 85 C0 74 73 48 98 48 8B 04 C5 ?? ?? ?? ?? 5B C3 0F 1F 80 00 00 00 00 48 83 3D ?? ?? ?? ?? 00 B8 ?? ?? ?? ?? 5B 48 0F 45 C7 C3 0F 1F 44 00 00 BF C8 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 74 25 BF 00 01 00 00 48 C7 05 ?? ?? ?? ?? C8 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 05 ?? ?? ?? ?? 0F 85 70 FF FF FF B8 ?? ?? ?? ?? 5B C3 66 0F 1F 44 00 00 31 C0 5B C3 }
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

rule splay_tree_new_with_allocator_b90025509aac096940c46d8e883b329c {
	meta:
		aliases = "splay_tree_new_with_allocator"
		size = "128"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 D0 48 89 6C 24 D8 48 89 CB 4C 89 64 24 E0 4C 89 6C 24 E8 49 89 F4 4C 89 74 24 F0 4C 89 7C 24 F8 49 89 FD 48 83 EC 38 49 89 D6 4D 89 C7 4C 89 CD 4C 89 CE BF 38 00 00 00 FF D1 4C 89 68 08 4C 89 60 10 4C 89 70 18 48 89 58 20 4C 89 78 28 48 89 68 30 48 C7 00 00 00 00 00 48 8B 5C 24 08 48 8B 6C 24 10 4C 8B 64 24 18 4C 8B 6C 24 20 4C 8B 74 24 28 4C 8B 7C 24 30 48 83 C4 38 C3 }
	condition:
		$pattern
}

rule demangle_function_name_f399b6524c4b9a4b2140b6347de1e0f9 {
	meta:
		aliases = "demangle_function_name"
		size = "1035"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 D0 48 89 6C 24 D8 48 89 D3 4C 89 64 24 E0 4C 89 6C 24 E8 49 89 F5 4C 89 74 24 F0 4C 89 7C 24 F8 48 83 EC 78 48 8B 36 48 89 CA 49 89 FC 48 89 DF 48 89 CD 48 29 F2 E8 A1 C4 FF FF BE 01 00 00 00 48 89 DF E8 A4 C3 FF FF 48 8B 43 08 C6 00 00 41 F7 04 24 00 10 00 00 48 8D 45 02 49 89 45 00 74 0A 80 7D 02 58 0F 84 21 01 00 00 41 F7 04 24 00 3C 00 00 48 8B 2B 74 39 BF ?? ?? ?? ?? B9 05 00 00 00 48 89 EE F3 A6 75 13 41 83 44 24 38 01 48 89 6B 08 E9 BA 00 00 00 0F 1F 40 00 BF ?? ?? ?? ?? B9 05 00 00 00 48 89 EE F3 A6 0F 84 CB 00 00 00 4C 8B 7B 08 49 29 EF 49 83 FF 02 0F 8E 8A 00 00 00 80 7D }
	condition:
		$pattern
}

rule gnu_special_02b3bfba37f7497b4f1eb1b4e6a151c4 {
	meta:
		aliases = "gnu_special"
		size = "1589"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 D0 48 89 6C 24 D8 48 89 F5 4C 89 64 24 E0 4C 89 6C 24 E8 49 89 D4 4C 89 74 24 F0 4C 89 7C 24 F8 48 81 EC 88 00 00 00 48 8B 1E 49 89 FD 64 48 8B 04 25 28 00 00 00 48 89 44 24 48 31 C0 80 3B 5F 0F 84 D6 00 00 00 BF ?? ?? ?? ?? B9 08 00 00 00 48 89 DE F3 A6 0F 84 D1 01 00 00 BF ?? ?? ?? ?? B9 03 00 00 00 48 89 DE F3 A6 75 68 0F B6 43 03 3C 69 0F 94 C2 3C 66 0F 85 4F 02 00 00 84 D2 0F 85 4F 02 00 00 41 BE ?? ?? ?? ?? 48 8D 43 04 48 89 45 00 0F B6 43 04 3C 51 0F 84 7D 03 00 00 3C 74 0F 84 95 03 00 00 3C 4B 0F 84 6D 03 00 00 4C 89 E2 48 89 EE 4C 89 EF E8 9F D2 FF FF 89 C3 85 DB 74 11 48 }
	condition:
		$pattern
}

rule htab_create_alloc_ex_2fc691574c4c792ba5b5fc29db40d166 {
	meta:
		aliases = "htab_create_alloc_ex"
		size = "234"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 D0 48 89 6C 24 D8 4C 89 C3 4C 89 64 24 E0 4C 89 6C 24 E8 4C 89 CD 4C 89 74 24 F0 4C 89 7C 24 F8 48 83 EC 48 49 89 F7 48 89 14 24 48 89 4C 24 08 E8 27 FC FF FF 41 89 C4 89 C0 BA 70 00 00 00 48 C1 E0 04 BE 01 00 00 00 48 89 DF 44 8B A8 ?? ?? ?? ?? FF D5 48 85 C0 49 89 C6 0F 84 81 00 00 00 BA 08 00 00 00 4C 89 EE 48 89 DF FF D5 48 85 C0 49 89 46 18 74 56 48 8B 04 24 4D 89 6E 20 45 89 66 68 4D 89 3E 49 89 5E 50 49 89 6E 58 49 89 46 08 48 8B 44 24 08 49 89 46 10 48 8B 44 24 50 49 89 46 60 4C 89 F0 48 8B 5C 24 18 48 8B 6C 24 20 4C 8B 64 24 28 4C 8B 6C 24 30 4C 8B 74 24 38 4C 8B 7C 24 40 }
	condition:
		$pattern
}

rule htab_create_alloc_ee0ab02ff8e09a0fab5e8ab6d9eac39b {
	meta:
		aliases = "htab_create_alloc"
		size = "208"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 D0 48 89 6C 24 D8 4C 89 C3 4C 89 64 24 E0 4C 89 6C 24 E8 4D 89 CD 4C 89 74 24 F0 4C 89 7C 24 F8 48 83 EC 48 49 89 F7 48 89 14 24 48 89 4C 24 08 E8 F7 FC FF FF 89 C5 89 C0 BE 70 00 00 00 48 C1 E0 04 BF 01 00 00 00 44 8B A0 ?? ?? ?? ?? FF D3 48 85 C0 49 89 C6 74 6F BE 08 00 00 00 4C 89 E7 FF D3 48 85 C0 49 89 46 18 74 51 48 8B 04 24 4D 89 66 20 41 89 6E 68 4D 89 3E 49 89 5E 40 4D 89 6E 48 49 89 46 08 48 8B 44 24 08 49 89 46 10 4C 89 F0 48 8B 5C 24 18 48 8B 6C 24 20 4C 8B 64 24 28 4C 8B 6C 24 30 4C 8B 74 24 38 4C 8B 7C 24 40 48 83 C4 48 C3 0F 1F 80 00 00 00 00 4D 85 ED 74 06 4C 89 F7 }
	condition:
		$pattern
}

rule cplus_demangle_opname_c5800177c14d401ca3104b49cbaac75a {
	meta:
		aliases = "cplus_demangle_opname"
		size = "1077"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 D0 48 89 6C 24 D8 89 D5 4C 89 6C 24 E8 4C 89 74 24 F0 49 89 F5 4C 89 7C 24 F8 4C 89 64 24 E0 48 81 EC E8 00 00 00 48 8D 5C 24 40 49 89 FE E8 ?? ?? ?? ?? B9 0E 00 00 00 49 89 C7 48 89 DF 31 C0 41 C6 45 00 00 F3 48 AB 89 6C 24 40 41 0F B6 06 3C 5F 0F 84 AC 00 00 00 41 83 FF 02 7E 5E 3C 6F 0F 84 06 01 00 00 41 83 FF 04 7E 50 BA 04 00 00 00 BE ?? ?? ?? ?? 4C 89 F7 E8 ?? ?? ?? ?? 85 C0 75 3A 41 0F BE 76 04 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 26 48 8D 54 24 20 48 8D 74 24 18 49 83 C6 05 48 89 DF 4C 89 74 24 18 E8 EB E4 FF FF 85 C0 75 67 0F 1F 80 00 00 00 00 31 ED 48 89 DF E8 66 C3 }
	condition:
		$pattern
}

rule internal_cplus_demangle_dc61794e092322111d2f94708b0d64d4 {
	meta:
		aliases = "internal_cplus_demangle"
		size = "1703"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 D0 4C 89 64 24 E0 48 89 FB 4C 89 6C 24 E8 4C 89 74 24 F0 49 89 F4 4C 89 7C 24 F8 48 89 6C 24 D8 48 81 EC 88 00 00 00 8B 47 38 48 85 F6 44 8B 6F 3C 44 8B 7F 48 48 89 74 24 18 44 8B 77 40 C7 47 3C 00 00 00 00 89 44 24 14 C7 47 38 00 00 00 00 C7 47 48 00 00 00 00 C7 47 4C 00 00 00 00 0F 84 F8 02 00 00 80 3E 00 0F 84 EF 02 00 00 48 C7 44 24 40 00 00 00 00 48 C7 44 24 38 00 00 00 00 48 C7 44 24 30 00 00 00 00 F7 07 00 03 00 00 0F 85 F0 00 00 00 4C 89 E7 E8 ?? ?? ?? ?? 48 83 F8 06 0F 86 8E 01 00 00 BF ?? ?? ?? ?? B9 06 00 00 00 4C 89 E6 F3 A6 0F 84 C1 01 00 00 BF ?? ?? ?? ?? B9 06 00 00 }
	condition:
		$pattern
}

rule pex_run_40c2b2bd33e9f8e1433b44f295f1b8e0 {
	meta:
		aliases = "pex_run"
		size = "1268"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 D0 4C 89 64 24 E0 89 F3 4C 89 6C 24 E8 4C 89 74 24 F0 49 89 FE 4C 89 7C 24 F8 48 89 6C 24 D8 48 81 EC 88 00 00 00 48 8B 7F 50 48 89 54 24 30 49 89 CF 4D 89 C4 4D 89 CD 48 85 FF 74 16 E8 ?? ?? ?? ?? 83 F8 FF 0F 84 91 02 00 00 49 C7 46 50 00 00 00 00 49 83 7E 20 00 74 52 48 8B 8C 24 90 00 00 00 48 8D 54 24 48 31 F6 4C 89 F7 E8 AB FC FF FF 85 C0 0F 85 63 01 00 00 48 8B 44 24 48 48 8B 5C 24 58 48 8B 6C 24 60 4C 8B 64 24 68 4C 8B 6C 24 70 4C 8B 74 24 78 4C 8B BC 24 80 00 00 00 48 81 C4 88 00 00 00 C3 0F 1F 44 00 00 41 8B 6E 18 85 ED 0F 88 04 02 00 00 F6 C3 01 0F 84 57 01 00 00 4D 85 E4 }
	condition:
		$pattern
}

rule demangle_template_value_parm_9f28b64f079ab951a95cd3a3ac565893 {
	meta:
		aliases = "demangle_template_value_parm"
		size = "1329"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 D8 48 89 6C 24 E0 48 89 F3 4C 89 64 24 E8 4C 89 6C 24 F0 49 89 FC 4C 89 74 24 F8 48 83 EC 78 48 8B 36 64 48 8B 04 25 28 00 00 00 48 89 44 24 48 31 C0 48 89 D5 44 0F B6 06 41 80 F8 59 0F 84 09 01 00 00 83 F9 03 0F 84 68 01 00 00 83 F9 05 74 5B 83 F9 04 0F 84 BA 00 00 00 83 F9 06 0F 84 A9 02 00 00 8D 51 FF B8 01 00 00 00 83 FA 01 0F 86 F8 01 00 00 48 8B 54 24 48 64 48 33 14 25 28 00 00 00 0F 85 A0 04 00 00 48 8B 5C 24 50 48 8B 6C 24 58 4C 8B 64 24 60 4C 8B 6C 24 68 4C 8B 74 24 70 48 83 C4 78 C3 66 0F 1F 44 00 00 41 80 F8 6D 0F 84 06 03 00 00 BA 01 00 00 00 BE ?? ?? ?? ?? 48 89 EF E8 }
	condition:
		$pattern
}

rule floatformat_i387_ext_is_valid_6a1874d6fc539f38d14bc838bb6f4f2c {
	meta:
		aliases = "floatformat_i387_ext_is_valid"
		size = "135"
		objfiles = "floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 D8 48 89 6C 24 E0 48 89 F5 4C 89 64 24 E8 4C 89 6C 24 F0 48 89 FB 4C 89 74 24 F8 48 83 EC 28 44 8B 6F 04 44 8B 27 8B 4F 0C 44 8B 47 10 48 89 EF 44 89 EA 44 89 E6 E8 F1 FE FF FF 8B 4B 1C 44 89 EA 44 89 E6 48 89 EF 41 B8 01 00 00 00 49 89 C6 E8 D7 FE FF FF 48 85 C0 48 8B 1C 24 48 8B 6C 24 08 0F 94 C2 4D 85 F6 4C 8B 64 24 10 0F 95 C0 4C 8B 6C 24 18 4C 8B 74 24 20 31 D0 48 83 C4 28 0F B6 C0 C3 }
	condition:
		$pattern
}

rule d_print_comp_4f742f7d55634b02821d8880ec3a224d {
	meta:
		aliases = "d_print_comp"
		size = "6674"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 D8 48 89 6C 24 E0 48 89 FB 4C 89 64 24 E8 4C 89 6C 24 F0 48 89 F5 4C 89 74 24 F8 48 81 EC B8 00 00 00 48 85 F6 74 10 48 8B 4F 08 48 85 C9 74 14 8B 06 83 F8 32 76 45 48 8D 7B 08 E8 EC FE FF FF 0F 1F 40 00 48 8B 9C 24 90 00 00 00 48 8B AC 24 98 00 00 00 4C 8B A4 24 A0 00 00 00 4C 8B AC 24 A8 00 00 00 4C 8B B4 24 B0 00 00 00 48 81 C4 B8 00 00 00 C3 0F 1F 84 00 00 00 00 00 89 C2 FF 24 D5 ?? ?? ?? ?? 0F 1F 80 00 00 00 00 48 8B 47 10 48 8D 50 0B 48 3B 57 18 0F 86 B9 12 00 00 BA 0B 00 00 00 BE ?? ?? ?? ?? E8 AF FD FF FF 0F 1F 80 00 00 00 00 48 8B 75 08 48 89 DF E8 3C FF FF FF EB 82 66 2E }
	condition:
		$pattern
}

rule pexecute_f2dbf13a8f2f2ffcd266dd5d9823239c {
	meta:
		aliases = "pexecute"
		size = "291"
		objfiles = "pexecute@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 D8 48 89 6C 24 E0 4C 89 CD 4C 89 64 24 E8 4C 89 6C 24 F0 4D 89 C4 4C 89 74 24 F8 48 83 EC 48 49 89 FD 8B 5C 24 50 49 89 F6 F6 C3 01 0F 84 9A 00 00 00 48 83 3D ?? ?? ?? ?? 00 0F 85 B4 00 00 00 48 89 D6 BF 02 00 00 00 48 89 CA E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 48 89 C7 48 89 05 ?? ?? ?? ?? 41 89 DB 89 DE 48 8D 54 24 1C 41 D1 EB D1 EE 45 31 C9 41 83 E3 01 83 E6 02 48 89 14 24 44 09 DE 45 31 C0 4C 89 F1 4C 89 EA E8 ?? ?? ?? ?? 48 85 C0 75 75 8B 05 ?? ?? ?? ?? 83 C0 01 89 05 ?? ?? ?? ?? 48 8B 5C 24 20 48 8B 6C 24 28 4C 8B 64 24 30 4C 8B 6C 24 38 4C 8B 74 24 40 48 83 C4 48 C3 }
	condition:
		$pattern
}

rule pex_one_e9a89d31e0a66cf4858c1bb1229f1365 {
	meta:
		aliases = "pex_one"
		size = "189"
		objfiles = "pex_one@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 D8 48 89 6C 24 E0 89 FD 4C 89 64 24 E8 4C 89 6C 24 F0 31 FF 4C 89 74 24 F8 48 83 EC 48 49 89 F5 49 89 D6 48 89 CE 31 D2 4C 8B 64 24 58 4C 89 44 24 18 4C 89 4C 24 10 E8 ?? ?? ?? ?? 4C 8B 4C 24 10 4C 8B 44 24 18 89 EE 4C 89 24 24 4C 89 F1 4C 89 EA 48 89 C7 48 89 C3 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 74 2F 48 89 DF E8 ?? ?? ?? ?? 48 89 E8 48 8B 5C 24 20 48 8B 6C 24 28 4C 8B 64 24 30 4C 8B 6C 24 38 4C 8B 74 24 40 48 83 C4 48 C3 66 0F 1F 44 00 00 48 8B 54 24 50 BE 01 00 00 00 48 89 DF E8 ?? ?? ?? ?? 85 C0 75 BB 41 C7 04 24 00 00 00 00 BD ?? ?? ?? ?? EB AC }
	condition:
		$pattern
}

rule fibheap_replace_key_data_6516abc6be23369aedf2ba382d6070c8 {
	meta:
		aliases = "fibheap_replace_key_data"
		size = "294"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 D8 4C 89 6C 24 F0 48 89 F3 48 89 6C 24 E0 4C 89 64 24 E8 49 89 FD 4C 89 74 24 F8 48 83 EC 28 48 8B 46 20 48 39 C2 7C 34 41 BC 00 00 00 00 0F 8E C8 00 00 00 4C 89 E0 48 8B 1C 24 48 8B 6C 24 08 4C 8B 64 24 10 4C 8B 6C 24 18 4C 8B 74 24 20 48 83 C4 28 C3 0F 1F 84 00 00 00 00 00 48 8B 2E 4C 8B 66 28 48 89 56 20 48 89 4E 28 48 85 ED 74 5C 48 3B 55 20 7D 76 48 89 EA 48 89 DE 4C 89 EF E8 E8 F9 FF FF 4C 8B 75 00 4D 85 F6 0F 84 8B 00 00 00 0F B6 45 33 84 C0 79 29 4C 89 F2 48 89 EE 4C 89 EF E8 C5 F9 FF FF 49 8B 06 48 85 C0 74 6D 41 0F B6 56 33 4C 89 F5 84 D2 79 05 49 89 C6 EB D9 89 D0 83 C8 }
	condition:
		$pattern
}

rule demangle_class_name_23f27497951211f562e3655de8ff0e58 {
	meta:
		aliases = "demangle_class_name"
		size = "132"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E0 48 89 6C 24 E8 48 89 F3 4C 89 64 24 F0 4C 89 6C 24 F8 49 89 FC 48 83 EC 28 48 89 F7 49 89 D5 E8 67 C8 FF FF 83 F8 FF 89 C5 74 50 48 8B 3B E8 ?? ?? ?? ?? 31 F6 39 C5 7E 22 89 F0 48 8B 5C 24 08 48 8B 6C 24 10 4C 8B 64 24 18 4C 8B 6C 24 20 48 83 C4 28 C3 0F 1F 80 00 00 00 00 48 89 DE 4C 89 E9 89 EA 4C 89 E7 E8 90 F8 FF FF BE 01 00 00 00 EB C7 66 0F 1F 84 00 00 00 00 00 31 F6 EB BA }
	condition:
		$pattern
}

rule pex_unix_wait_5d868465d477017880fc07fbb992b3c2 {
	meta:
		aliases = "pex_unix_wait"
		size = "224"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E0 48 89 6C 24 E8 48 89 F7 4C 89 64 24 F0 4C 89 6C 24 F8 48 81 EC B8 00 00 00 45 85 C0 48 89 D5 48 89 CB 4D 89 CD 41 89 F4 75 69 48 85 DB 74 73 31 D2 48 89 E1 48 89 EE 44 89 E7 E8 ?? ?? ?? ?? 48 8B 14 24 48 89 13 48 8B 54 24 08 48 89 53 08 48 8B 54 24 10 48 89 53 10 48 8B 54 24 18 48 89 53 18 85 C0 78 56 31 C0 48 8B 9C 24 98 00 00 00 48 8B AC 24 A0 00 00 00 4C 8B A4 24 A8 00 00 00 4C 8B AC 24 B0 00 00 00 48 81 C4 B8 00 00 00 C3 0F 1F 40 00 BE 0F 00 00 00 E8 ?? ?? ?? ?? 48 85 DB 75 8D 31 D2 48 89 EE 44 89 E7 E8 ?? ?? ?? ?? EB B0 66 2E 0F 1F 84 00 00 00 00 00 E8 ?? ?? ?? ?? 8B 10 48 }
	condition:
		$pattern
}

rule cplus_demangle_v3_components_c7fd6b48233f6f3a2577611871b53b9b {
	meta:
		aliases = "cplus_demangle_v3_components"
		size = "367"
		objfiles = "cp_demint@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E0 48 89 6C 24 E8 48 89 FB 4C 89 64 24 F0 4C 89 6C 24 F8 48 81 EC 98 00 00 00 89 F5 49 89 D4 E8 ?? ?? ?? ?? 80 3B 5F 0F 84 E7 00 00 00 40 F6 C5 10 41 BD 01 00 00 00 0F 84 FC 00 00 00 48 8D 4C 24 10 48 89 C2 89 EE 48 89 DF E8 ?? ?? ?? ?? 48 63 44 24 3C 48 8D 3C 40 48 C1 E7 03 E8 ?? ?? ?? ?? 48 63 7C 24 4C 48 89 C3 48 89 44 24 30 48 C1 E7 03 E8 ?? ?? ?? ?? 48 85 DB 48 89 44 24 40 0F 84 A7 00 00 00 48 85 C0 0F 84 CE 00 00 00 45 85 ED 74 69 48 8D 7C 24 10 E8 ?? ?? ?? ?? 83 E5 01 48 8B 7C 24 40 74 0E 48 8B 54 24 28 80 3A 00 0F 85 8F 00 00 00 48 89 44 24 08 E8 ?? ?? ?? ?? 48 8B 44 24 08 }
	condition:
		$pattern
}

rule d_expression_036b85732411b9c63d02d768f90053d0 {
	meta:
		aliases = "d_expression"
		size = "619"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E0 48 89 6C 24 E8 48 89 FB 4C 89 64 24 F0 4C 89 6C 24 F8 48 83 EC 28 48 8B 57 18 0F B6 02 3C 4C 0F 84 AE 01 00 00 3C 54 0F 84 C6 01 00 00 3C 73 74 52 48 89 DF E8 A2 FC FF FF 48 85 C0 48 89 C5 74 22 8B 00 83 F8 28 74 7B 83 F8 29 0F 84 EA 00 00 00 83 F8 2A 0F 84 A5 00 00 00 83 F8 28 0F 84 B0 01 00 00 31 C0 48 8B 5C 24 08 48 8B 6C 24 10 4C 8B 64 24 18 4C 8B 6C 24 20 48 83 C4 28 C3 0F 1F 44 00 00 80 7A 01 72 75 A8 48 83 C2 02 48 89 57 18 E8 ?? ?? ?? ?? 48 89 DF 48 89 C5 E8 AA FD FF FF 48 8B 73 18 49 89 C4 80 3E 49 0F 84 8A 01 00 00 48 89 C1 48 89 EA BE 01 00 00 00 EB 54 0F 1F 44 00 00 }
	condition:
		$pattern
}

rule md5_finish_ctx_15f684a55efa52472a36cbd6e540c967 {
	meta:
		aliases = "md5_finish_ctx"
		size = "206"
		objfiles = "md5@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E0 48 89 6C 24 E8 48 89 FB 4C 89 64 24 F0 4C 89 6C 24 F8 48 83 EC 28 8B 47 18 8B 57 10 48 89 F5 01 C2 39 D0 89 57 10 76 04 83 47 14 01 83 F8 37 0F 87 86 00 00 00 41 BD 38 00 00 00 41 29 C5 41 89 C4 4C 89 EA BE ?? ?? ?? ?? 4A 8D 7C 23 1C E8 ?? ?? ?? ?? 8B 43 10 4B 8D 74 25 00 48 8D 7B 1C C1 E0 03 89 44 33 1C 8B 43 10 8B 53 14 C1 E8 1D C1 E2 03 09 D0 48 89 DA 89 44 33 20 48 83 C6 08 E8 ?? ?? ?? ?? 8B 03 4C 8B 64 24 18 4C 8B 6C 24 20 89 45 00 8B 43 04 89 45 04 8B 43 08 89 45 08 8B 43 0C 48 8B 5C 24 08 89 45 0C 48 89 E8 48 8B 6C 24 10 48 83 C4 28 C3 0F 1F 40 00 41 BD 78 00 00 00 41 29 }
	condition:
		$pattern
}

rule pex_input_file_0365a25dedc2423e684b3e0b1a7fa951 {
	meta:
		aliases = "pex_input_file"
		size = "196"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E0 48 89 6C 24 E8 48 89 FB 4C 89 64 24 F0 4C 89 6C 24 F8 48 83 EC 38 8B 4F 2C 85 C9 75 0E 8B 47 18 85 C0 7F 07 48 83 7F 20 00 74 30 E8 ?? ?? ?? ?? C7 00 16 00 00 00 31 C0 48 8B 5C 24 18 48 8B 6C 24 20 4C 8B 64 24 28 4C 8B 6C 24 30 48 83 C4 38 C3 66 2E 0F 1F 84 00 00 00 00 00 48 8D 7F 10 89 F5 49 89 D4 E8 D2 F8 FF FF 48 85 C0 49 89 C5 74 33 83 E5 20 B8 ?? ?? ?? ?? BE ?? ?? ?? ?? 48 0F 44 F0 4C 89 EF E8 ?? ?? ?? ?? 48 85 C0 74 19 31 D2 4D 39 E5 48 89 43 50 0F 95 C2 4C 89 6B 20 89 53 28 EB 94 31 C0 EB 90 4C 89 EF 48 89 44 24 08 E8 ?? ?? ?? ?? 48 8B 44 24 08 E9 79 FF FF FF }
	condition:
		$pattern
}

rule pex_input_pipe_5d0c625df0cf420d6a54c6612021fa49 {
	meta:
		aliases = "pex_input_pipe"
		size = "211"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E0 48 89 6C 24 E8 48 89 FB 4C 89 64 24 F0 4C 89 6C 24 F8 48 83 EC 38 8B 57 2C 85 D2 7F 13 F6 07 02 74 0E 8B 47 18 85 C0 7F 07 48 83 7F 20 00 74 2B E8 ?? ?? ?? ?? 31 ED C7 00 16 00 00 00 48 89 E8 48 8B 5C 24 18 48 8B 6C 24 20 4C 8B 64 24 28 4C 8B 6C 24 30 48 83 C4 38 C3 66 90 48 8B 47 70 31 ED 85 F6 40 0F 95 C5 48 89 E6 89 EA FF 50 28 85 C0 78 28 48 8B 43 70 89 EA 8B 74 24 04 48 89 DF FF 50 38 48 85 C0 48 89 C5 74 14 8B 04 24 89 43 18 EB AA 0F 1F 84 00 00 00 00 00 31 ED EB 9E E8 ?? ?? ?? ?? 44 8B 28 49 89 C4 48 8B 43 70 8B 34 24 48 89 DF FF 50 18 48 8B 43 70 8B 74 24 04 48 89 DF FF }
	condition:
		$pattern
}

rule splay_tree_insert_b3cae23f0db6a82520c021787bdd9ab6 {
	meta:
		aliases = "splay_tree_insert"
		size = "262"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E0 48 89 6C 24 E8 48 89 FB 4C 89 6C 24 F8 4C 89 64 24 F0 48 83 EC 28 48 89 F5 49 89 D5 E8 6A FB FF FF 48 8B 03 48 85 C0 0F 84 87 00 00 00 48 89 EE 48 8B 38 FF 53 08 41 89 C4 48 8B 03 48 85 C0 74 3A 45 85 E4 75 35 48 8B 53 18 48 85 D2 74 09 48 8B 78 08 FF D2 48 8B 03 4C 89 68 08 48 8B 5C 24 08 48 8B 6C 24 10 4C 8B 64 24 18 4C 8B 6C 24 20 48 83 C4 28 C3 66 0F 1F 44 00 00 48 8B 73 30 BF 20 00 00 00 FF 53 20 48 8B 13 48 89 28 4C 89 68 08 48 85 D2 74 3D 45 85 E4 78 50 48 8B 4A 10 48 89 50 18 48 89 48 10 48 C7 42 10 00 00 00 00 48 89 03 EB A8 48 8B 73 30 BF 20 00 00 00 FF 53 20 48 8B 13 }
	condition:
		$pattern
}

rule choose_tmpdir_c79d2418d8f645146c6dc79b94d763c4 {
	meta:
		aliases = "choose_tmpdir"
		size = "484"
		objfiles = "make_temp_file@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E0 48 89 6C 24 E8 4C 89 64 24 F0 4C 89 6C 24 F8 48 83 EC 28 48 8B 1D ?? ?? ?? ?? 48 85 DB 74 1C 48 89 D8 48 8B 6C 24 10 48 8B 5C 24 08 4C 8B 64 24 18 4C 8B 6C 24 20 48 83 C4 28 C3 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 74 60 BE 07 00 00 00 48 89 C7 E8 ?? ?? ?? ?? 85 C0 75 4F BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 8D 78 02 44 8D 68 01 41 89 C4 E8 ?? ?? ?? ?? 48 89 EE 48 89 C3 48 89 C7 E8 ?? ?? ?? ?? 42 C6 04 23 2F 48 89 1D ?? ?? ?? ?? 42 C6 04 2B 00 E9 72 FF FF FF BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C5 48 85 ED 74 1D BE 07 00 00 }
	condition:
		$pattern
}

rule xregerror_3411f17a73da06b446eda5a77efea709 {
	meta:
		aliases = "xregerror"
		size = "137"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E0 48 89 6C 24 E8 4C 89 64 24 F0 4C 89 6C 24 F8 48 83 EC 28 83 FF 10 77 67 48 63 FF 48 89 CD 49 89 D5 4C 8B 24 FD ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? 48 85 ED 48 8D 58 01 74 13 48 39 EB 77 2C 48 89 DA 4C 89 E6 4C 89 EF E8 ?? ?? ?? ?? 48 89 D8 48 8B 6C 24 10 48 8B 5C 24 08 4C 8B 64 24 18 4C 8B 6C 24 20 48 83 C4 28 C3 66 90 48 8D 55 FF 4C 89 E6 4C 89 EF E8 ?? ?? ?? ?? C6 00 00 EB CE E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pex_init_common_f07c47e9589100df978f5b3cf59294a4 {
	meta:
		aliases = "pex_init_common"
		size = "183"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E0 48 89 6C 24 E8 89 FB 4C 89 64 24 F0 4C 89 6C 24 F8 48 89 F5 48 83 EC 28 49 89 D4 49 89 CD BF 80 00 00 00 E8 ?? ?? ?? ?? 89 18 48 89 68 08 4C 89 60 10 4C 89 68 70 C7 40 18 00 00 00 00 48 C7 40 20 00 00 00 00 C7 40 28 00 00 00 00 C7 40 2C 00 00 00 00 48 C7 40 30 00 00 00 00 48 C7 40 38 00 00 00 00 48 C7 40 40 00 00 00 00 C7 40 48 00 00 00 00 48 C7 40 50 00 00 00 00 48 C7 40 58 00 00 00 00 C7 40 60 00 00 00 00 48 C7 40 68 00 00 00 00 48 C7 40 78 00 00 00 00 48 8B 5C 24 08 48 8B 6C 24 10 4C 8B 64 24 18 4C 8B 6C 24 20 48 83 C4 28 C3 }
	condition:
		$pattern
}

rule pwait_6fcd67cdf99389a399257ba15a16a9b3 {
	meta:
		aliases = "pwait"
		size = "259"
		objfiles = "pexecute@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E0 48 89 6C 24 E8 8D 5F FF 4C 89 64 24 F0 4C 89 6C 24 F8 89 FD 48 83 EC 28 48 8B 3D ?? ?? ?? ?? 48 85 FF 0F 84 BB 00 00 00 85 DB 0F 88 B3 00 00 00 48 63 05 ?? ?? ?? ?? 39 C3 0F 8D A4 00 00 00 85 DB 49 89 F5 75 09 83 F8 01 0F 84 9C 00 00 00 48 8D 3C 85 00 00 00 00 E8 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 48 89 C2 49 89 C4 E8 ?? ?? ?? ?? 85 C0 74 63 48 63 DB 4C 89 E7 41 8B 04 9C 41 89 45 00 E8 ?? ?? ?? ?? 3B 2D ?? ?? ?? ?? 74 20 89 E8 48 8B 5C 24 08 48 8B 6C 24 10 4C 8B 64 24 18 4C 8B 6C 24 20 48 83 C4 28 C3 0F 1F 44 00 00 48 8B 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 C7 05 ?? }
	condition:
		$pattern
}

rule remember_type_3a130f168c1e00f9d10481567cfbd9f7 {
	meta:
		aliases = "remember_type"
		size = "201"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E0 4C 89 64 24 F0 48 89 FB 48 89 6C 24 E8 4C 89 6C 24 F8 48 83 EC 28 8B 47 5C 4C 63 E2 85 C0 75 43 8B 47 34 39 47 30 49 89 F5 7D 58 41 8D 7C 24 01 48 63 FF E8 ?? ?? ?? ?? 4C 89 E2 48 89 C5 4C 89 EE 48 89 C7 E8 ?? ?? ?? ?? 42 C6 44 25 00 00 8B 43 30 48 8B 53 08 48 63 C8 83 C0 01 48 89 2C CA 89 43 30 48 8B 5C 24 08 48 8B 6C 24 10 4C 8B 64 24 18 4C 8B 6C 24 20 48 83 C4 28 C3 0F 1F 80 00 00 00 00 85 C0 75 1C C7 47 34 03 00 00 00 BF 18 00 00 00 E8 ?? ?? ?? ?? 48 89 43 08 EB 8D 0F 1F 44 00 00 01 C0 89 47 34 48 98 48 8B 7F 08 48 8D 34 C5 00 00 00 00 E8 ?? ?? ?? ?? 48 89 43 08 E9 67 FF FF }
	condition:
		$pattern
}

rule remember_Ktype_2e7d8ce52366a98ddc4579e4dcea7902 {
	meta:
		aliases = "remember_Ktype"
		size = "183"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E0 4C 89 64 24 F0 48 89 FB 4C 89 6C 24 F8 48 89 6C 24 E8 48 83 EC 28 8B 47 28 39 47 20 49 89 F5 4C 63 E2 7C 20 85 C0 74 73 01 C0 89 47 28 48 98 48 8B 7F 10 48 8D 34 C5 00 00 00 00 E8 ?? ?? ?? ?? 48 89 43 10 41 8D 7C 24 01 48 63 FF E8 ?? ?? ?? ?? 4C 89 E2 48 89 C5 4C 89 EE 48 89 C7 E8 ?? ?? ?? ?? 42 C6 44 25 00 00 8B 43 20 48 8B 53 10 4C 8B 64 24 18 4C 8B 6C 24 20 48 63 C8 83 C0 01 48 89 2C CA 89 43 20 48 8B 6C 24 10 48 8B 5C 24 08 48 83 C4 28 C3 66 0F 1F 44 00 00 C7 47 28 05 00 00 00 BF 28 00 00 00 E8 ?? ?? ?? ?? 48 89 43 10 EB 92 }
	condition:
		$pattern
}

rule string_append_32dcbc322fc65a74ac844d6bd1dd09ec {
	meta:
		aliases = "string_append"
		size = "97"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E8 48 89 6C 24 F0 48 89 F3 4C 89 64 24 F8 48 83 EC 18 48 85 F6 74 33 80 3E 00 74 2E 48 89 FD 48 89 F7 E8 ?? ?? ?? ?? 48 89 EF 89 C6 49 89 C4 E8 78 FD FF FF 48 8B 7D 08 4D 63 E4 48 89 DE 4C 89 E2 E8 ?? ?? ?? ?? 4C 01 65 08 48 8B 1C 24 48 8B 6C 24 08 4C 8B 64 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule d_print_cast_DOT_isra_DOT_6_f12fe41669966ccd78624569c2d9ec5c {
	meta:
		aliases = "d_print_cast.isra.6"
		size = "399"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E8 48 89 6C 24 F0 48 89 F5 4C 89 64 24 F8 48 83 EC 28 48 8B 36 48 89 FB 83 3E 04 74 1F E8 4A DC FF FF 48 8B 5C 24 10 48 8B 6C 24 18 4C 8B 64 24 20 48 83 C4 28 C3 66 0F 1F 44 00 00 48 8D 04 24 48 8B 57 20 4C 8B 67 28 48 89 74 24 08 48 C7 47 28 00 00 00 00 48 89 47 20 48 8B 76 08 48 89 14 24 E8 06 DC FF FF 48 8B 53 08 48 8B 04 24 48 85 D2 48 89 43 20 74 1A 48 8B 43 10 48 85 C0 74 0B 80 7C 02 FF 3C 0F 84 81 00 00 00 48 39 43 18 77 6B BE 3C 00 00 00 48 89 DF E8 9E DA FF FF 48 8B 45 00 48 89 DF 48 8B 70 10 E8 BE DB FF FF 48 8B 53 08 48 85 D2 74 16 48 8B 43 10 48 85 C0 74 07 80 7C 02 FF }
	condition:
		$pattern
}

rule string_need_8bb1218a736cafa909abc3f6848d17f0 {
	meta:
		aliases = "string_need"
		size = "151"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E8 48 89 6C 24 F0 48 89 FB 4C 89 64 24 F8 48 83 EC 18 48 8B 3F 48 85 FF 74 52 48 8B 53 08 48 8B 43 10 48 63 CE 48 29 D0 48 39 C8 7D 2B 49 89 D4 49 29 FC 42 8D 2C 26 4D 63 E4 01 ED 48 63 ED 48 89 EE E8 ?? ?? ?? ?? 49 01 C4 48 89 03 48 01 E8 4C 89 63 08 48 89 43 10 48 8B 1C 24 48 8B 6C 24 08 4C 8B 64 24 10 48 83 C4 18 C3 90 83 FE 20 48 63 C6 BD 20 00 00 00 48 0F 4D E8 48 89 EF E8 ?? ?? ?? ?? 48 01 C5 48 89 03 48 89 43 08 48 89 6B 10 EB C5 }
	condition:
		$pattern
}

rule d_print_append_buffer_f7a9cee2902868d94a85a171b021feac {
	meta:
		aliases = "d_print_append_buffer"
		size = "112"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E8 48 89 6C 24 F0 48 89 FB 4C 89 64 24 F8 48 83 EC 18 48 8B 47 08 48 85 C0 74 3E 48 8B 7F 10 48 89 D5 49 89 F4 48 8D 14 3A 48 3B 53 18 76 18 48 89 EE 48 89 DF E8 52 FF FF FF 48 8B 43 08 48 85 C0 74 16 48 8B 7B 10 48 01 C7 48 89 EA 4C 89 E6 E8 ?? ?? ?? ?? 48 01 6B 10 48 8B 1C 24 48 8B 6C 24 08 4C 8B 64 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule pex_get_status_6f3fbc72536dd49bcfae4662b326f9a9 {
	meta:
		aliases = "pex_get_status"
		size = "151"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E8 48 89 6C 24 F0 48 89 FB 4C 89 64 24 F8 48 83 EC 28 48 83 7F 38 00 48 63 EE 49 89 D4 74 5D 48 63 43 2C 39 E8 7C 35 48 8B 73 38 48 8D 14 AD 00 00 00 00 4C 89 E7 E8 ?? ?? ?? ?? B8 01 00 00 00 48 8B 5C 24 10 48 8B 6C 24 18 4C 8B 64 24 20 48 83 C4 28 C3 0F 1F 84 00 00 00 00 00 29 C5 49 8D 3C 84 31 F6 48 63 D5 48 C1 E2 02 E8 ?? ?? ?? ?? 48 63 6B 2C EB B1 66 0F 1F 44 00 00 48 8D 4C 24 04 48 8D 54 24 08 31 F6 E8 1F F5 FF FF 85 C0 75 8E EB AD }
	condition:
		$pattern
}

rule pex_get_times_f7cfa65ecd9d515cdfe93ddfb4a6e0ef {
	meta:
		aliases = "pex_get_times"
		size = "171"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E8 48 89 6C 24 F0 48 89 FB 4C 89 64 24 F8 48 83 EC 28 48 83 7F 38 00 89 F5 49 89 D4 74 6E 48 8B 73 40 48 85 F6 74 5D 48 63 4B 2C 39 E9 7C 2D 48 63 D5 4C 89 E7 48 C1 E2 05 E8 ?? ?? ?? ?? B8 01 00 00 00 48 8B 5C 24 10 48 8B 6C 24 18 4C 8B 64 24 20 48 83 C4 28 C3 0F 1F 44 00 00 29 CD 48 C1 E1 05 31 F6 48 63 D5 49 8D 3C 0C 48 C1 E2 05 E8 ?? ?? ?? ?? 8B 6B 2C 48 8B 73 40 EB B2 0F 1F 80 00 00 00 00 31 C0 EB BB 0F 1F 40 00 48 8D 4C 24 04 48 8D 54 24 08 31 F6 E8 6F F4 FF FF 85 C0 0F 85 79 FF FF FF EB 9C }
	condition:
		$pattern
}

rule byte_common_op_match_null_stri_8866035a0090a81c04c6a33ba62fa21c {
	meta:
		aliases = "byte_common_op_match_null_string_p"
		size = "294"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E8 48 89 6C 24 F0 48 89 FB 4C 89 64 24 F8 48 83 EC 28 48 8B 07 48 89 44 24 08 0F B6 38 48 8D 48 01 48 89 4C 24 08 40 80 FF 1D 76 08 31 C0 EB 54 0F 1F 40 00 48 89 D5 49 89 C8 FF 24 FD ?? ?? ?? ?? 0F 1F 00 44 0F B6 60 01 48 8D 7C 24 08 E8 69 01 00 00 BE 03 00 00 00 4A 8D 54 E5 00 0F B6 0A 21 CE 40 80 FE 03 0F 84 A8 00 00 00 84 C0 74 BC 4C 8B 44 24 08 0F 1F 80 00 00 00 00 4C 89 03 B8 01 00 00 00 48 8B 5C 24 10 48 8B 6C 24 18 4C 8B 64 24 20 48 83 C4 28 C3 0F 1F 40 00 48 8D 70 03 48 89 74 24 08 0F BE 50 04 0F B6 78 03 C1 E2 08 01 FA 0F 85 74 FF FF FF 48 89 4C 24 08 44 0F B6 40 01 0F BE }
	condition:
		$pattern
}

rule cplus_demangle_type_d36caf85a37b48ea4f039e9a80209934 {
	meta:
		aliases = "cplus_demangle_type"
		size = "1146"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E8 48 89 6C 24 F0 48 89 FB 4C 89 64 24 F8 48 83 EC 28 48 8B 57 18 0F BE 02 3C 56 74 3F 3C 72 74 3B 3C 4B 74 37 8D 48 D0 80 F9 4A 76 1F 31 C0 48 8B 5C 24 10 48 8B 6C 24 18 4C 8B 64 24 20 48 83 C4 28 C3 66 0F 1F 84 00 00 00 00 00 0F B6 C9 FF 24 CD ?? ?? ?? ?? 66 0F 1F 44 00 00 48 8D 74 24 08 31 D2 48 89 DF E8 71 D2 FF FF 48 85 C0 48 89 C5 74 BA 48 89 DF E8 ?? ?? ?? ?? 48 89 45 00 48 8B 54 24 08 48 85 D2 74 A4 8B 43 38 3B 43 3C 7D 9C 48 8B 4B 30 48 63 F0 83 C0 01 48 89 14 F1 89 43 38 48 8B 44 24 08 EB 86 48 83 C2 01 48 89 57 18 E8 B6 D5 FF FF 31 C9 48 89 C2 BE 22 00 00 00 48 89 DF E8 }
	condition:
		$pattern
}

rule htab_find_slot_7f4613aa45ad600ad147ead05aa69075 {
	meta:
		aliases = "htab_find_slot"
		size = "67"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E8 48 89 6C 24 F0 48 89 FB 4C 89 64 24 F8 48 89 F5 48 83 EC 18 41 89 D4 48 89 F7 FF 13 44 89 E1 48 89 EE 48 89 DF 48 8B 6C 24 08 48 8B 1C 24 89 C2 4C 8B 64 24 10 48 83 C4 18 E9 CD FD FF FF }
	condition:
		$pattern
}

rule splay_tree_new_0604e46216cd196e17e2e17da4590098 {
	meta:
		aliases = "splay_tree_new"
		size = "100"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E8 48 89 6C 24 F0 48 89 FB 4C 89 64 24 F8 48 89 F5 48 83 EC 18 49 89 D4 BF 38 00 00 00 E8 ?? ?? ?? ?? 48 89 58 08 48 89 68 10 4C 89 60 18 48 C7 00 00 00 00 00 48 C7 40 20 ?? ?? ?? ?? 48 C7 40 28 ?? ?? ?? ?? 48 C7 40 30 00 00 00 00 48 8B 1C 24 48 8B 6C 24 08 4C 8B 64 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule fibheap_insert_7e4f04d3cf9444a2aa6007816fc67932 {
	meta:
		aliases = "fibheap_insert"
		size = "178"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E8 48 89 6C 24 F0 48 89 FB 4C 89 64 24 F8 48 89 F5 49 89 D4 48 83 EC 18 BE 38 00 00 00 BF 01 00 00 00 E8 ?? ?? ?? ?? 48 89 40 10 48 89 40 18 4C 89 60 28 48 8B 53 10 48 89 68 20 48 85 D2 74 4C 48 8B 4A 18 48 39 CA 74 53 48 89 48 18 48 8B 4A 18 48 89 42 18 48 89 41 10 48 89 50 10 48 8B 53 08 48 85 D2 74 0A 48 8B 4A 20 48 39 48 20 7D 04 48 89 43 08 48 83 03 01 48 8B 6C 24 08 48 8B 1C 24 4C 8B 64 24 10 48 83 C4 18 C3 90 48 89 43 10 48 89 40 10 48 89 40 18 EB C3 66 90 48 89 42 18 48 89 42 10 48 89 50 18 48 89 50 10 EB AF }
	condition:
		$pattern
}

rule dyn_string_copy_cstr_0254eb3ac749e75b602db9d7a97b0bd0 {
	meta:
		aliases = "dyn_string_copy_cstr"
		size = "94"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E8 48 89 6C 24 F0 48 89 FB 4C 89 64 24 F8 48 89 F7 48 83 EC 18 49 89 F4 E8 ?? ?? ?? ?? 48 89 DF 89 C6 48 89 C5 E8 ?? ?? ?? ?? 31 D2 48 85 C0 74 14 48 8B 7B 08 4C 89 E6 E8 ?? ?? ?? ?? 89 6B 04 BA 01 00 00 00 89 D0 48 8B 1C 24 48 8B 6C 24 08 4C 8B 64 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule dyn_string_append_cstr_4a419dfd7a885cbaa2c9bdbc6060aebf {
	meta:
		aliases = "dyn_string_append_cstr"
		size = "101"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E8 48 89 6C 24 F0 48 89 FB 4C 89 64 24 F8 48 89 F7 48 83 EC 18 49 89 F4 E8 ?? ?? ?? ?? 8B 73 04 48 89 DF 48 89 C5 01 C6 E8 ?? ?? ?? ?? 31 D2 48 85 C0 74 18 48 63 7B 04 4C 89 E6 48 03 7B 08 E8 ?? ?? ?? ?? 01 6B 04 BA 01 00 00 00 89 D0 48 8B 1C 24 48 8B 6C 24 08 4C 8B 64 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule splay_tree_remove_179667ff69e52256445dd88f8b0d6027 {
	meta:
		aliases = "splay_tree_remove"
		size = "158"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E8 48 89 6C 24 F0 48 89 FD 4C 89 64 24 F8 48 83 EC 18 48 89 F3 E8 62 FA FF FF 48 8B 45 00 48 85 C0 74 59 48 89 DE 48 8B 38 FF 55 08 85 C0 75 4C 48 8B 45 18 48 8B 7D 00 48 85 C0 48 8B 5F 10 4C 8B 67 18 74 0A 48 8B 7F 08 FF D0 48 8B 7D 00 48 8B 75 30 FF 55 28 48 85 DB 74 39 4D 85 E4 48 89 5D 00 75 0B EB 16 66 0F 1F 44 00 00 48 89 C3 48 8B 43 18 48 85 C0 75 F4 4C 89 63 18 48 8B 1C 24 48 8B 6C 24 08 4C 8B 64 24 10 48 83 C4 18 C3 0F 1F 44 00 00 4C 89 65 00 EB E2 }
	condition:
		$pattern
}

rule choose_temp_base_7cbaaebb690bfc05ceb0bcbad889c5b2 {
	meta:
		aliases = "choose_temp_base"
		size = "122"
		objfiles = "choose_temp@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E8 48 89 6C 24 F0 4C 89 64 24 F8 48 83 EC 18 E8 ?? ?? ?? ?? 48 89 C7 49 89 C4 E8 ?? ?? ?? ?? 48 63 E8 48 8D 7D 09 E8 ?? ?? ?? ?? 4C 89 E6 48 89 C3 48 89 C7 E8 ?? ?? ?? ?? 48 01 DD 48 B8 63 63 58 58 58 58 58 58 48 89 DF 48 89 45 00 C6 45 08 00 E8 ?? ?? ?? ?? 80 3B 00 74 16 48 89 D8 48 8B 6C 24 08 48 8B 1C 24 4C 8B 64 24 10 48 83 C4 18 C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule d_source_name_00fd7138e0007761342a3a15fda3875d {
	meta:
		aliases = "d_source_name"
		size = "236"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 E8 48 89 FB 48 8D 7F 18 48 89 6C 24 F0 4C 89 64 24 F8 48 83 EC 18 E8 A1 FE FF FF 48 85 C0 48 89 C5 0F 8E B5 00 00 00 4C 8B 63 18 48 8B 43 08 48 63 D5 4C 29 E0 48 39 D0 0F 8C A6 00 00 00 4C 01 E2 F6 43 10 04 48 89 53 18 75 41 83 FD 09 7E 16 BA 08 00 00 00 BE ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 74 36 89 EA 4C 89 E6 48 89 DF E8 A9 FB FF FF 48 89 43 48 48 8B 1C 24 48 8B 6C 24 08 4C 8B 64 24 10 48 83 C4 18 C3 66 90 80 3A 24 75 BA 48 83 C2 01 48 89 53 18 EB B0 90 41 0F B6 44 24 08 3C 5F 74 0E 3C 2E 74 0A 3C 24 75 B8 66 0F 1F 44 00 00 41 80 7C 24 09 4E 75 AA 8B 43 50 BA 15 00 00 00 }
	condition:
		$pattern
}

rule htab_remove_elt_with_hash_e807df973348f450a140e58e4ebf52b4 {
	meta:
		aliases = "htab_remove_elt_with_hash"
		size = "74"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 F0 48 89 6C 24 F8 31 C9 48 83 EC 18 48 89 FB E8 ?? ?? ?? ?? 48 8B 38 48 89 C5 48 85 FF 74 18 48 8B 43 10 48 85 C0 74 02 FF D0 48 C7 45 00 01 00 00 00 48 83 43 30 01 48 8B 5C 24 08 48 8B 6C 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule d_call_offset_ad98bdcd154fe29dc5881e2bc454428d {
	meta:
		aliases = "d_call_offset"
		size = "158"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 F0 48 89 6C 24 F8 48 83 EC 10 85 F6 48 89 FB 75 0F 48 8B 47 18 0F BE 30 48 83 C0 01 48 89 47 18 83 FE 68 74 47 83 FE 76 74 12 31 C0 48 8B 1C 24 48 8B 6C 24 08 48 83 C4 10 C3 66 90 48 8D 6B 18 48 89 EF E8 84 FD FF FF 48 8B 43 18 0F B6 10 48 83 C0 01 48 89 43 18 80 FA 5F 75 CE 48 89 EF E8 68 FD FF FF EB 0F 66 0F 1F 44 00 00 48 8D 7B 18 E8 57 FD FF FF 48 8B 43 18 48 8B 6C 24 08 0F B6 10 48 83 C0 01 48 89 43 18 31 C0 48 8B 1C 24 80 FA 5F 0F 94 C0 48 83 C4 10 C3 }
	condition:
		$pattern
}

rule temp_file_DOT_isra_DOT_2_aedc4de89927ec0d7a4bccaef4053704 {
	meta:
		aliases = "temp_file.isra.2"
		size = "255"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 F0 48 89 6C 24 F8 48 83 EC 18 48 85 D2 48 89 D3 74 32 83 E6 04 0F 84 83 00 00 00 48 8B 3F 48 85 FF 0F 84 8D 00 00 00 48 89 DE 48 8B 6C 24 10 48 8B 5C 24 08 31 D2 31 C0 48 83 C4 18 E9 ?? ?? ?? ?? 0F 1F 00 48 8B 2F 48 85 ED 0F 84 8C 00 00 00 48 89 EF E8 ?? ?? ?? ?? 83 F8 05 7E 15 48 98 BF ?? ?? ?? ?? B9 07 00 00 00 48 8D 74 05 FA F3 A6 74 5A 48 89 EF 31 D2 BE ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? 48 89 C5 31 F6 48 89 EF E8 ?? ?? ?? ?? 85 C0 78 5D 89 C7 48 89 EB E8 ?? ?? ?? ?? 48 89 D8 48 8B 6C 24 10 48 8B 5C 24 08 48 83 C4 18 C3 0F 1F 40 00 48 8B 5C 24 08 48 8B 6C 24 10 48 89 D7 48 83 C4 }
	condition:
		$pattern
}

rule xcalloc_0198486f4f9ea987827de2537f09f04f {
	meta:
		aliases = "xcalloc"
		size = "88"
		objfiles = "xmalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 F0 48 89 6C 24 F8 48 83 EC 18 48 85 F6 48 89 F3 74 2A 48 85 FF 48 89 FD 74 22 48 89 DE 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 74 1E 48 8B 5C 24 08 48 8B 6C 24 10 48 83 C4 18 C3 0F 1F 00 BB 01 00 00 00 BD 01 00 00 00 EB D2 48 89 DF 48 0F AF FD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xstrdup_a42ef19fa3d08fc1a889e03084ef7a9d {
	meta:
		aliases = "xstrdup"
		size = "62"
		objfiles = "xstrdup@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 F0 48 89 6C 24 F8 48 83 EC 18 48 89 FB E8 ?? ?? ?? ?? 48 8D 68 01 48 89 EF E8 ?? ?? ?? ?? 48 89 EA 48 89 DE 48 8B 6C 24 10 48 8B 5C 24 08 48 89 C7 48 83 C4 18 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule d_print_append_char_82e661d817cea392d6b84b27ee0bec53 {
	meta:
		aliases = "d_print_append_char"
		size = "89"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 F0 48 89 6C 24 F8 48 83 EC 18 48 8B 47 08 48 89 FB 48 85 C0 74 15 48 8B 57 10 48 3B 57 18 89 F5 73 1A 40 88 2C 10 48 83 43 10 01 48 8B 5C 24 08 48 8B 6C 24 10 48 83 C4 18 C3 66 90 BE 01 00 00 00 E8 D6 FE FF FF 48 8B 43 08 48 85 C0 74 DC 48 8B 53 10 EB CD }
	condition:
		$pattern
}

rule fibheap_delete_node_72990ea111362b00493cf752261524d1 {
	meta:
		aliases = "fibheap_delete_node"
		size = "62"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 F0 48 89 6C 24 F8 48 83 EC 18 48 8B 6E 28 48 89 FB 48 BA 00 00 00 00 00 00 00 80 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 E8 48 8B 5C 24 08 48 8B 6C 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule d_print_expr_op_0e481306668f9f9f91bfe6cc7ec887b1 {
	meta:
		aliases = "d_print_expr_op"
		size = "170"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 F0 48 89 6C 24 F8 48 83 EC 18 83 3E 28 48 89 FB 48 89 F5 74 17 48 8B 5C 24 08 48 8B 6C 24 10 48 83 C4 18 E9 84 00 00 00 0F 1F 40 00 48 8B 4F 08 48 85 C9 74 67 48 8B 46 08 48 8B 7F 10 48 63 50 10 48 8D 34 3A 48 3B 73 18 76 21 48 8B 70 08 48 89 DF 48 8B 6C 24 10 48 8B 5C 24 08 48 83 C4 18 E9 A7 FE FF FF 0F 1F 80 00 00 00 00 48 8B 70 08 48 01 CF E8 ?? ?? ?? ?? 48 8B 45 08 48 8B 6C 24 10 48 63 40 10 48 01 43 10 48 8B 5C 24 08 48 83 C4 18 C3 66 0F 1F 84 00 00 00 00 00 48 8B 46 08 48 63 50 10 EB A5 }
	condition:
		$pattern
}

rule dyn_string_init_a1e0f983bbdd3b888b9e3b35d9f8c10a {
	meta:
		aliases = "dyn_string_init"
		size = "77"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 F0 48 89 6C 24 F8 48 83 EC 18 85 F6 48 89 FB 89 F5 48 63 FE 75 0A BF 01 00 00 00 BD 01 00 00 00 E8 ?? ?? ?? ?? 89 2B 48 89 43 08 C7 43 04 00 00 00 00 C6 00 00 B8 01 00 00 00 48 8B 5C 24 08 48 8B 6C 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule dyn_string_new_24be670364a778e74bce23978d86ae61 {
	meta:
		aliases = "dyn_string_new"
		size = "57"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 F0 48 89 6C 24 F8 48 83 EC 18 89 FD BF 10 00 00 00 E8 ?? ?? ?? ?? 89 EE 48 89 C3 48 89 C7 E8 ?? ?? ?? ?? 48 89 D8 48 8B 6C 24 10 48 8B 5C 24 08 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule d_print_mod_c17a1c5971de7c00ac881ddccf8ec330 {
	meta:
		aliases = "d_print_mod"
		size = "928"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 F0 48 89 6C 24 F8 48 83 EC 18 8B 06 48 89 FB 48 89 F5 83 E8 03 83 F8 22 76 22 48 89 EE 48 89 DF 48 8B 6C 24 10 48 8B 5C 24 08 48 83 C4 18 E9 A9 E5 FF FF 66 0F 1F 84 00 00 00 00 00 FF 24 C5 ?? ?? ?? ?? 66 0F 1F 84 00 00 00 00 00 48 8B 57 08 48 85 D2 0F 84 53 02 00 00 48 8B 47 10 48 85 C0 0F 84 FE 01 00 00 80 7C 02 FF 28 0F 85 F3 01 00 00 0F 1F 00 48 8B 75 08 48 89 DF E8 5C E5 FF FF 48 8B 43 08 48 85 C0 74 12 48 8B 53 10 48 8D 4A 03 48 3B 4B 18 0F 86 C1 02 00 00 BA 03 00 00 00 BE ?? ?? ?? ?? EB 3D 0F 1F 44 00 00 48 8B 76 08 E9 68 FF FF FF 0F 1F 80 00 00 00 00 48 8B 47 08 48 85 C0 74 }
	condition:
		$pattern
}

rule xstrndup_2fc39e48ce49353d30a5f5f1eaad8939 {
	meta:
		aliases = "xstrndup"
		size = "73"
		objfiles = "xstrndup@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 F0 48 89 6C 24 F8 48 89 F3 48 83 EC 18 48 89 FD E8 ?? ?? ?? ?? 48 39 D8 48 0F 46 D8 48 8D 7B 01 E8 ?? ?? ?? ?? 48 89 DA C6 04 18 00 48 89 EE 48 8B 5C 24 08 48 8B 6C 24 10 48 89 C7 48 83 C4 18 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule htab_remove_elt_bb640aca333c6eaaa86d6bb32db5f9a1 {
	meta:
		aliases = "htab_remove_elt"
		size = "52"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 F0 48 89 6C 24 F8 48 89 FB 48 83 EC 18 48 89 F5 48 89 F7 FF 13 48 89 EE 48 89 DF 48 8B 6C 24 10 48 8B 5C 24 08 89 C2 48 83 C4 18 E9 7C FF FF FF }
	condition:
		$pattern
}

rule htab_find_3f74b610fb323053ed240d041cddb860 {
	meta:
		aliases = "htab_find"
		size = "52"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 F0 48 89 6C 24 F8 48 89 FB 48 83 EC 18 48 89 F5 48 89 F7 FF 13 48 89 EE 48 89 DF 48 8B 6C 24 10 48 8B 5C 24 08 89 C2 48 83 C4 18 E9 9C FE FF FF }
	condition:
		$pattern
}

rule xmemdup_6981b877d9e423bd304f62b38b2896d4 {
	meta:
		aliases = "xmemdup"
		size = "61"
		objfiles = "xmemdup@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 F0 48 89 6C 24 F8 48 89 FB 48 83 EC 18 48 89 F5 BF 01 00 00 00 48 89 D6 E8 ?? ?? ?? ?? 48 89 EA 48 89 DE 48 8B 6C 24 10 48 8B 5C 24 08 48 89 C7 48 83 C4 18 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule splay_tree_lookup_38dc066e8e3310cc8e3bc1f29f9bad5b {
	meta:
		aliases = "splay_tree_lookup"
		size = "81"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 5C 24 F0 48 89 6C 24 F8 48 89 FB 48 83 EC 18 48 89 F5 E8 C7 F9 FF FF 48 8B 03 48 85 C0 74 1F 48 89 EE 48 8B 38 FF 53 08 85 C0 75 12 48 8B 03 48 8B 6C 24 10 48 8B 5C 24 08 48 83 C4 18 C3 31 C0 48 8B 5C 24 08 48 8B 6C 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule floatformat_from_double_c1adbd5d46ef26094174d1d3d2d964f0 {
	meta:
		aliases = "floatformat_from_double"
		size = "740"
		objfiles = "floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 6C 24 D8 4C 89 6C 24 E8 49 89 D5 48 89 5C 24 D0 4C 89 64 24 E0 48 89 FD 4C 89 74 24 F0 4C 89 7C 24 F8 48 83 EC 68 8B 57 04 F2 0F 10 06 4C 89 EF 31 F6 F2 0F 11 04 24 C1 EA 03 E8 ?? ?? ?? ?? 66 0F 57 C9 F2 0F 10 04 24 66 0F 2E C8 0F 87 14 02 00 00 66 0F 2E C1 7A 26 75 24 48 8B 5C 24 38 48 8B 6C 24 40 4C 8B 64 24 48 4C 8B 6C 24 50 4C 8B 74 24 58 4C 8B 7C 24 60 48 83 C4 68 C3 90 66 0F 2E C0 0F 8A AE 01 00 00 66 0F 28 C8 F2 0F 58 C8 66 0F 2E C8 0F 8B 54 01 00 00 48 8D 7C 24 2C E8 ?? ?? ?? ?? 8B 5C 24 2C 8B 45 14 01 D8 83 F8 01 0F 8E F8 01 00 00 44 8D 48 FF 8B 4D 0C 8B 55 04 44 8B 45 10 8B 75 }
	condition:
		$pattern
}

rule remember_Btype_DOT_isra_DOT_13_f5d76a5b33ab59ddfc87d2c58df7acc8 {
	meta:
		aliases = "remember_Btype.isra.13"
		size = "109"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 6C 24 E0 48 63 EA 4C 89 74 24 F8 49 89 FE 8D 7D 01 48 89 5C 24 D8 4C 89 64 24 E8 4C 89 6C 24 F0 48 83 EC 28 49 89 F5 48 63 FF 4C 63 E1 E8 ?? ?? ?? ?? 48 89 EA 4C 89 EE 48 89 C7 48 89 C3 E8 ?? ?? ?? ?? 49 8B 06 C6 04 2B 00 4C 8B 6C 24 18 48 8B 6C 24 08 4C 8B 74 24 20 4A 89 1C E0 48 8B 1C 24 4C 8B 64 24 10 48 83 C4 28 C3 }
	condition:
		$pattern
}

rule cplus_demangle_7e75a1d7068f94bede4999fa764b1d40 {
	meta:
		aliases = "cplus_demangle"
		size = "973"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 6C 24 E0 48 89 5C 24 D8 48 89 FD 4C 89 64 24 E8 4C 89 6C 24 F0 4C 89 74 24 F8 48 81 EC 98 00 00 00 8B 15 ?? ?? ?? ?? 83 FA FF 0F 84 CE 00 00 00 31 C0 B9 0E 00 00 00 48 89 E7 F7 C6 04 FF 00 00 F3 48 AB 74 69 89 34 24 F7 04 24 00 41 00 00 75 71 40 F6 C6 04 0F 85 8B 00 00 00 81 E6 00 80 00 00 0F 85 A7 00 00 00 48 89 E7 48 89 EE E8 5C 46 00 00 48 89 E7 48 89 C3 E8 01 F2 FF FF 48 89 D8 48 8B 6C 24 78 48 8B 5C 24 70 4C 8B A4 24 80 00 00 00 4C 8B AC 24 88 00 00 00 4C 8B B4 24 90 00 00 00 48 81 C4 98 00 00 00 C3 0F 1F 40 00 81 E2 04 FF 00 00 09 D6 89 34 24 F7 04 24 00 41 00 00 74 8F 48 89 EF E8 }
	condition:
		$pattern
}

rule make_temp_file_36c50021c825e02045c08bfde66d336d {
	meta:
		aliases = "make_temp_file"
		size = "212"
		objfiles = "make_temp_file@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 6C 24 E0 4C 89 6C 24 F0 48 89 FD 48 89 5C 24 D8 4C 89 64 24 E8 4C 89 74 24 F8 48 83 EC 28 E8 ?? ?? ?? ?? 48 85 ED 49 89 C5 0F 84 8F 00 00 00 48 89 EF E8 ?? ?? ?? ?? 41 89 C6 48 63 D8 4C 89 EF E8 ?? ?? ?? ?? 4C 63 E0 49 8D 7C 1C 09 E8 ?? ?? ?? ?? 4C 89 EE 48 89 C3 48 89 C7 E8 ?? ?? ?? ?? 4A 8D 04 23 48 BA 63 63 58 58 58 58 58 58 4A 8D 7C 23 08 48 89 EE 48 89 10 C6 40 08 00 E8 ?? ?? ?? ?? 44 89 F6 48 89 DF E8 ?? ?? ?? ?? 83 F8 FF 74 3B 89 C7 E8 ?? ?? ?? ?? 85 C0 75 30 48 89 D8 48 8B 6C 24 08 48 8B 1C 24 4C 8B 64 24 10 4C 8B 6C 24 18 4C 8B 74 24 20 48 83 C4 28 C3 90 31 DB 45 31 F6 BD ?? ?? }
	condition:
		$pattern
}

rule getpwd_5a75abb98ed5754856db69c6827d266d {
	meta:
		aliases = "getpwd"
		size = "313"
		objfiles = "getpwd@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 6C 24 E8 48 89 5C 24 E0 4C 89 64 24 F0 4C 89 6C 24 F8 48 81 EC 48 01 00 00 48 8B 2D ?? ?? ?? ?? 48 85 ED 74 31 48 89 E8 48 8B 9C 24 28 01 00 00 48 8B AC 24 30 01 00 00 4C 8B A4 24 38 01 00 00 4C 8B AC 24 40 01 00 00 48 81 C4 48 01 00 00 C3 66 0F 1F 44 00 00 E8 ?? ?? ?? ?? 49 89 C5 8B 05 ?? ?? ?? ?? 85 C0 41 89 45 00 75 B9 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 74 05 80 38 2F 74 5A BB 01 10 00 00 EB 19 0F 1F 40 00 45 8B 65 00 48 89 EF E8 ?? ?? ?? ?? 41 83 FC 22 75 2E 48 01 DB 48 89 DF E8 ?? ?? ?? ?? 48 89 DE 48 89 C7 48 89 C5 E8 ?? ?? ?? ?? 48 85 C0 74 D0 48 89 2D ?? ?? ?? ?? E9 }
	condition:
		$pattern
}

rule string_prependn_f005da28b098eba4bc85cc38ab446e58 {
	meta:
		aliases = "string_prependn"
		size = "115"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 6C 24 F0 48 63 EA 48 89 5C 24 E8 4C 89 64 24 F8 48 83 EC 18 85 ED 75 16 48 8B 1C 24 48 8B 6C 24 08 4C 8B 64 24 10 48 83 C4 18 C3 0F 1F 00 48 89 FB 49 89 F4 89 EE E8 53 FE FF FF 48 8B 43 08 48 8B 3B 48 83 E8 01 48 39 F8 72 15 0F 1F 00 0F B6 08 88 0C 28 48 8B 3B 48 83 E8 01 48 39 F8 73 EE 48 89 EA 4C 89 E6 E8 ?? ?? ?? ?? 48 01 6B 08 EB A7 }
	condition:
		$pattern
}

rule string_appendn_DOT_part_DOT_5_28449b968b0f88f8e35a7dd3633354ca {
	meta:
		aliases = "string_appendn.part.5"
		size = "73"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 6C 24 F0 48 63 EA 48 89 5C 24 E8 4C 89 64 24 F8 48 89 FB 48 83 EC 18 49 89 F4 89 EE E8 3D FF FF FF 48 8B 7B 08 48 89 EA 4C 89 E6 E8 ?? ?? ?? ?? 48 01 6B 08 4C 8B 64 24 10 48 8B 1C 24 48 8B 6C 24 08 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule string_appends_DOT_isra_DOT_6_b79f33518217607a042baeac1046150a {
	meta:
		aliases = "string_appends.isra.6"
		size = "89"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 6C 24 F0 48 89 5C 24 E8 48 89 F5 4C 89 64 24 F8 48 83 EC 18 48 8B 06 48 39 D0 74 28 49 89 D4 48 89 FB 49 29 C4 44 89 E6 4D 63 E4 E8 BE FE FF FF 48 8B 7B 08 48 8B 75 00 4C 89 E2 E8 ?? ?? ?? ?? 4C 01 63 08 48 8B 1C 24 48 8B 6C 24 08 4C 8B 64 24 10 48 83 C4 18 C3 }
	condition:
		$pattern
}

rule xatexit_5c603e77a136ec7faf3d488f146e390d {
	meta:
		aliases = "xatexit"
		size = "148"
		objfiles = "xatexit@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 6C 24 F8 48 89 5C 24 F0 48 83 EC 18 48 83 3D ?? ?? ?? ?? 00 48 89 FD 74 65 48 8B 1D ?? ?? ?? ?? 48 63 43 08 83 F8 1F 8D 50 01 7F 22 48 89 6C C3 10 89 53 08 31 C0 48 8B 5C 24 08 48 8B 6C 24 10 48 83 C4 18 C3 66 0F 1F 84 00 00 00 00 00 BF 10 01 00 00 E8 ?? ?? ?? ?? 48 85 C0 74 2E 48 89 18 C7 40 08 00 00 00 00 48 89 C3 48 89 05 ?? ?? ?? ?? BA 01 00 00 00 31 C0 EB B2 0F 1F 40 00 48 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? EB 8E B8 FF FF FF FF EB A4 }
	condition:
		$pattern
}

rule splay_tree_foreach_2dd4515fbdac62b5e1f069ed90b6d4fa {
	meta:
		aliases = "splay_tree_foreach"
		size = "14"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 D1 48 89 F2 48 8B 37 E9 42 FA FF FF }
	condition:
		$pattern
}

rule fibheap_replace_data_51f90f17a9e7c914aab6a093dd2cf032 {
	meta:
		aliases = "fibheap_replace_data"
		size = "12"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 D1 48 8B 56 20 E9 C4 FE FF FF }
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

rule xre_set_syntax_26e7b8d8a92ed76c586f2e06d4795b45 {
	meta:
		aliases = "xre_set_syntax"
		size = "15"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 05 ?? ?? ?? ?? 48 89 3D ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule d_number_DOT_isra_DOT_0_62a921a6239df229651205bd17644e22 {
	meta:
		aliases = "d_number.isra.0"
		size = "101"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 07 45 31 C0 48 0F BE 08 80 F9 6E 74 41 8D 41 D0 3C 09 77 4B 48 8B 17 31 C0 48 83 C2 01 90 48 8D 04 80 48 89 17 48 8D 44 41 D0 48 0F BE 0A 48 83 C2 01 8D 71 D0 40 80 FE 09 76 E3 48 89 C2 48 F7 DA 45 85 C0 48 0F 45 C2 C3 0F 1F 44 00 00 48 8D 50 01 41 B0 01 48 89 17 48 0F BE 48 01 EB AE 31 C0 EB D8 }
	condition:
		$pattern
}

rule splay_tree_min_0e310f9e2f7fd4fd8f92fff1759c81f8 {
	meta:
		aliases = "splay_tree_min"
		size = "32"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 07 48 85 C0 75 0B EB 14 66 0F 1F 44 00 00 48 89 D0 48 8B 50 10 48 85 D2 75 F4 F3 C3 F3 C3 }
	condition:
		$pattern
}

rule splay_tree_max_9d01bd8c9c462e714996509799da2439 {
	meta:
		aliases = "splay_tree_max"
		size = "32"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 07 48 85 C0 75 0B EB 14 66 0F 1F 44 00 00 48 89 D0 48 8B 50 18 48 85 D2 75 F4 F3 C3 F3 C3 }
	condition:
		$pattern
}

rule get_count_b43625d717ab26419f01f5afb7735214 {
	meta:
		aliases = "get_count"
		size = "122"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 17 31 C0 0F BE 0A 44 0F B6 C1 43 F6 84 00 ?? ?? ?? ?? 04 74 4F 4C 8D 42 01 83 E9 30 B0 01 89 0E 4C 89 07 0F BE 52 01 44 0F B6 CA 43 F6 84 09 ?? ?? ?? ?? 04 74 2E 0F 1F 84 00 00 00 00 00 8D 04 89 49 83 C0 01 8D 4C 42 D0 41 0F BE 10 0F B6 C2 F6 84 00 ?? ?? ?? ?? 04 75 E4 80 FA 5F B8 01 00 00 00 74 0A F3 C3 0F 1F 84 00 00 00 00 00 49 83 C0 01 4C 89 07 89 0E C3 }
	condition:
		$pattern
}

rule consume_count_98497034646c431574deed6bec7cde22 {
	meta:
		aliases = "consume_count"
		size = "78"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 17 31 C0 0F BE 0A 48 83 C2 01 0F B6 F1 F6 84 36 ?? ?? ?? ?? 04 74 2F 0F 1F 80 00 00 00 00 8D 04 80 48 89 17 8D 44 41 D0 0F BE 0A 48 83 C2 01 0F B6 F1 F6 84 36 ?? ?? ?? ?? 04 75 E2 85 C0 78 06 F3 C3 0F 1F 40 00 B8 FF FF FF FF C3 }
	condition:
		$pattern
}

rule consume_count_with_underscores_f5af4d99c6f3aedfafd6a54a908ac91b {
	meta:
		aliases = "consume_count_with_underscores"
		size = "81"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 17 53 48 89 FB 0F BE 02 3C 5F 74 1A 8D 48 D0 80 F9 09 77 34 83 E8 30 48 83 C2 01 48 89 13 5B C3 66 0F 1F 44 00 00 48 8D 42 01 48 89 07 0F B6 42 01 F6 84 00 ?? ?? ?? ?? 04 74 0D E8 6E FF FF FF 48 8B 13 80 3A 5F 74 CF B8 FF FF FF FF 5B C3 }
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

rule fibheap_rem_root_DOT_isra_DOT_4_77073ad7cc111bf8554d45776ae3e7ca {
	meta:
		aliases = "fibheap_rem_root.isra.4"
		size = "88"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 46 10 48 39 C6 74 47 48 8B 16 48 85 D2 74 06 48 3B 72 08 74 29 48 8B 56 18 48 C7 06 00 00 00 00 48 89 42 10 48 8B 4E 10 48 89 76 10 48 89 51 18 48 89 76 18 48 89 07 C3 66 0F 1F 44 00 00 48 89 42 08 EB D1 66 2E 0F 1F 84 00 00 00 00 00 48 C7 07 00 00 00 00 C3 }
	condition:
		$pattern
}

rule fibheap_cut_fcfee6f50318633f7d3de94e781f44e8 {
	meta:
		aliases = "fibheap_cut"
		size = "194"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 46 10 4C 8B 06 31 C9 48 39 C6 48 0F 45 C8 4D 85 C0 74 06 49 3B 70 08 74 6D 48 8B 4E 18 48 C7 06 00 00 00 00 48 89 41 10 48 8B 46 10 48 89 76 10 48 89 48 18 48 89 76 18 8B 42 30 8D 88 FF FF FF 7F 25 00 00 00 80 81 E1 FF FF FF 7F 09 C8 89 42 30 48 8B 47 10 48 85 C0 74 34 48 8B 50 18 48 39 D0 74 4B 48 89 56 18 48 8B 50 18 48 89 70 18 48 89 72 10 48 89 46 10 48 C7 06 00 00 00 00 80 66 33 7F C3 0F 1F 00 49 89 48 08 EB 8D 66 90 48 89 77 10 48 89 76 10 48 89 76 18 48 C7 06 00 00 00 00 80 66 33 7F C3 0F 1F 84 00 00 00 00 00 48 89 70 18 48 89 70 10 48 89 46 18 48 89 46 10 EB B7 }
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

rule cplus_demangle_mangled_name_2b0b0d7c37bc5368e8643562b1ee48a1 {
	meta:
		aliases = "cplus_demangle_mangled_name"
		size = "51"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 18 0F B6 10 48 8D 48 01 48 89 4F 18 80 FA 5F 75 1C 0F B6 50 01 48 83 C0 02 48 89 47 18 80 FA 5A 75 0B E9 26 FC FF FF 66 0F 1F 44 00 00 31 C0 C3 }
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

rule d_substitution_45814cf1aa1e1a395f92a19a43427231 {
	meta:
		aliases = "d_substitution"
		size = "400"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 57 18 0F B6 02 48 8D 4A 01 48 89 4F 18 3C 53 0F 85 AA 00 00 00 0F BE 42 01 48 8D 4A 02 48 89 4F 18 8D 48 D0 80 F9 09 77 4D 31 D2 3C 5F 75 29 E9 95 00 00 00 66 2E 0F 1F 84 00 00 00 00 00 8D 14 D2 8D 54 90 D0 48 8B 4F 18 0F BE 01 48 83 C1 01 48 89 4F 18 3C 5F 74 6E 8D 48 D0 80 F9 09 76 DE 8D 48 BF 80 F9 19 77 57 8D 14 D2 8D 54 90 C9 EB D4 0F 1F 44 00 00 3C 5F 74 AF 8D 48 BF 80 F9 19 76 5C 8B 4F 10 C1 E9 03 83 E1 01 85 F6 74 11 84 C9 75 0D 0F B6 52 02 83 EA 43 80 FA 01 0F 96 C1 0F B6 C9 BA ?? ?? ?? ?? 66 0F 1F 44 00 00 38 02 74 3C 48 83 C2 38 48 81 FA ?? ?? ?? ?? 75 EF 31 C0 C3 0F 1F 40 00 }
	condition:
		$pattern
}

rule d_discriminator_2e6307e0d3d52bffefe5585d463a0553 {
	meta:
		aliases = "d_discriminator"
		size = "41"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 57 18 B8 01 00 00 00 80 3A 5F 74 02 F3 C3 48 83 C2 01 48 89 57 18 48 83 C7 18 E8 CF FE FF FF 48 F7 D0 48 C1 E8 3F C3 }
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

rule hash_pointer_e271763c71d1ddf82a3be3c9b48dbbd1 {
	meta:
		aliases = "hash_pointer"
		size = "7"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) C1 FF 03 89 F8 C3 }
	condition:
		$pattern
}

rule byte_compile_range_a279d05068ba2dad2fbbd979c41bf384 {
	meta:
		aliases = "byte_compile_range"
		size = "197"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 49 ) 89 CA 48 8B 0E B8 0B 00 00 00 48 39 D1 0F 84 9F 00 00 00 48 8D 41 01 48 89 06 44 89 C0 C1 E0 0F C1 F8 1F 83 E0 0B 4D 85 D2 0F 84 88 00 00 00 0F B6 09 40 0F B6 FF 41 0F BE 14 3A 45 0F B6 04 0A 41 39 D0 72 6D 53 41 BB 01 00 00 00 EB 31 90 89 D0 44 89 DB 83 C2 01 41 0F B6 34 02 48 89 F0 89 F1 48 C1 E8 03 83 E1 07 83 E0 1F D3 E3 4C 01 C8 89 DE 0F B6 38 09 FE 41 39 D0 40 88 30 72 30 4D 85 D2 75 CB 89 D0 89 D1 44 89 DB C1 F8 03 83 E1 07 83 C2 01 48 98 D3 E3 4C 01 C8 89 DE 0F B6 38 09 FE 41 39 D0 40 88 30 73 D5 0F 1F 44 00 00 5B 31 C0 F3 C3 0F 1F 00 40 0F BE D7 44 0F B6 01 E9 7C FF FF FF }
	condition:
		$pattern
}

rule string_append_template_idx_d8ce14b9236eefea5079625f085d2d11 {
	meta:
		aliases = "string_append_template_idx"
		size = "88"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 41 89 F0 48 89 FB B9 ?? ?? ?? ?? BA 21 00 00 00 BE 01 00 00 00 48 83 EC 30 64 48 8B 04 25 28 00 00 00 48 89 44 24 28 31 C0 48 89 E7 E8 ?? ?? ?? ?? 48 89 E6 48 89 DF E8 53 FF FF FF 48 8B 44 24 28 64 48 33 04 25 28 00 00 00 75 06 48 83 C4 30 5B C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fibheap_delete_6ca25b3bf6c84e898e1574ddbf105fce {
	meta:
		aliases = "fibheap_delete"
		size = "48"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 7F 08 00 48 89 FB 74 1C 0F 1F 44 00 00 48 89 DF E8 98 FB FF FF 48 89 C7 E8 ?? ?? ?? ?? 48 83 7B 08 00 75 E9 48 89 DF 5B E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fibheap_extract_min_ee2fc4b0e3c41ae606e6f3e6968b6ac9 {
	meta:
		aliases = "fibheap_extract_min"
		size = "36"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 7F 08 00 74 18 E8 73 FD FF FF 48 89 C7 48 8B 58 28 E8 ?? ?? ?? ?? 48 89 D8 5B C3 66 90 31 DB EB F5 }
	condition:
		$pattern
}

rule pex_unix_exec_child_e6d2efdbc68e55a03356b810748eec5c {
	meta:
		aliases = "pex_unix_exec_child"
		size = "631"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 83 EC 40 C7 44 24 38 01 00 00 00 C7 44 24 3C 00 00 00 00 8B 44 24 3C 48 89 7C 24 20 89 74 24 1C 48 89 54 24 10 48 89 4C 24 28 44 89 44 24 18 83 F8 03 44 89 4C 24 0C 7E 2C E9 38 01 00 00 8B 7C 24 38 E8 ?? ?? ?? ?? 8B 44 24 38 01 C0 89 44 24 38 8B 44 24 3C 83 C0 01 89 44 24 3C 8B 44 24 3C 83 F8 03 7F 0B E8 ?? ?? ?? ?? 85 C0 89 C3 78 CE 83 FB FF 0F 84 FD 00 00 00 85 DB 0F 85 AD 00 00 00 8B 54 24 18 85 D2 0F 85 71 01 00 00 83 7C 24 0C 01 74 27 8B 7C 24 0C BE 01 00 00 00 E8 ?? ?? ?? ?? 85 C0 0F 88 2F 01 00 00 8B 7C 24 0C E8 ?? ?? ?? ?? 85 C0 0F 88 63 01 00 00 83 7C 24 50 02 74 27 8B 7C 24 50 }
	condition:
		$pattern
}

rule md5_buffer_cdcf9a635f2b3cecb24c4ff49eb3b8d1 {
	meta:
		aliases = "md5_buffer"
		size = "137"
		objfiles = "md5@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 D3 48 81 EC B0 00 00 00 48 89 E2 C7 04 24 01 23 45 67 C7 44 24 04 89 AB CD EF 64 48 8B 04 25 28 00 00 00 48 89 84 24 A8 00 00 00 31 C0 C7 44 24 08 FE DC BA 98 C7 44 24 0C 76 54 32 10 C7 44 24 14 00 00 00 00 C7 44 24 10 00 00 00 00 C7 44 24 18 00 00 00 00 E8 ?? ?? ?? ?? 48 89 DE 48 89 E7 E8 ?? ?? ?? ?? 48 8B 94 24 A8 00 00 00 64 48 33 14 25 28 00 00 00 75 09 48 81 C4 B0 00 00 00 5B C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fibheap_union_c39f3fcc85996b54734b20b90779eeee {
	meta:
		aliases = "fibheap_union"
		size = "129"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 F0 48 89 FB 48 83 EC 10 48 8B 57 10 48 85 D2 74 5C 48 8B 4E 10 48 85 C9 74 30 48 8B 72 10 48 8B 79 10 48 89 4E 18 48 89 7A 10 48 89 57 18 48 89 71 10 48 8B 10 48 8B 4B 08 48 01 13 48 8B 50 08 48 8B 71 20 48 39 72 20 7C 13 48 89 C7 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 10 5B C3 66 90 48 89 53 08 EB E7 66 2E 0F 1F 84 00 00 00 00 00 48 89 74 24 08 E8 ?? ?? ?? ?? 48 8B 44 24 08 EB D7 }
	condition:
		$pattern
}

rule htab_traverse_4505e0f0d295c97f092179c6ecbaa34b {
	meta:
		aliases = "htab_traverse"
		size = "62"
		objfiles = "hashtab@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 83 EC 10 48 8B 47 28 48 2B 47 30 48 C1 E0 03 48 3B 47 20 73 17 48 89 14 24 48 89 74 24 08 E8 58 F5 FF FF 48 8B 74 24 08 48 8B 14 24 48 83 C4 10 48 89 DF 5B E9 72 FF FF FF }
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

rule string_delete_9164dd95a303b5f03e5bf1922f2643fb {
	meta:
		aliases = "string_delete"
		size = "42"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 8B 3F 48 85 FF 74 1C E8 ?? ?? ?? ?? 48 C7 43 08 00 00 00 00 48 C7 43 10 00 00 00 00 48 C7 03 00 00 00 00 5B C3 }
	condition:
		$pattern
}

rule d_print_error_DOT_isra_DOT_3_c252a1ccfecdef82ee65fea6cf3430bf {
	meta:
		aliases = "d_print_error.isra.3"
		size = "21"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB 48 8B 3F E8 ?? ?? ?? ?? 48 C7 03 00 00 00 00 5B C3 }
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

rule xre_exec_98ae18492f77caac6d1fb79387fa2924 {
	meta:
		aliases = "xre_exec"
		size = "39"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 89 FB E8 ?? ?? ?? ?? 48 89 DE 45 31 C9 41 89 C0 31 C9 89 C2 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? F7 D0 C1 E8 1F 5B C3 }
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

rule d_template_param_7fde83a1ec8a3a652dbd76d66edc21de {
	meta:
		aliases = "d_template_param"
		size = "148"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 8B 47 18 48 89 FB 0F B6 10 48 8D 48 01 48 89 4F 18 80 FA 54 75 68 80 78 01 5F 74 6A 48 8D 7F 18 E8 69 FF FF FF 48 85 C0 78 54 48 8D 48 01 48 8B 43 18 0F B6 10 48 83 C0 01 48 89 43 18 80 FA 5F 75 3C 83 43 40 01 8B 53 28 3B 53 2C 7D 30 48 63 C2 83 C2 01 48 8D 34 40 48 8B 43 20 89 53 28 48 8D 04 F0 48 85 C0 74 16 C7 00 05 00 00 00 48 89 48 08 5B C3 66 2E 0F 1F 84 00 00 00 00 00 31 C0 5B C3 0F 1F 40 00 48 83 C0 02 31 C9 48 89 47 18 EB B0 }
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

rule d_unqualified_name_81bc5107e32522f5e4d89d8272fd9054 {
	meta:
		aliases = "d_unqualified_name"
		size = "426"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 48 8B 4F 18 48 89 FB 0F B6 11 8D 42 D0 3C 09 76 76 8D 42 9F 3C 19 76 47 8D 72 BD 31 C0 40 80 FE 01 77 30 48 8B 77 48 48 85 F6 74 0F 8B 06 85 C0 75 5D 8B 46 10 01 43 50 0F B6 11 48 8D 41 01 80 FA 43 48 89 43 18 0F 84 BB 00 00 00 80 FA 44 74 4E 31 C0 5B C3 66 2E 0F 1F 84 00 00 00 00 00 E8 2B FE FF FF 48 85 C0 74 EA 83 38 28 75 E5 48 8B 48 08 8B 53 50 03 51 10 83 C2 07 89 53 50 5B C3 0F 1F 80 00 00 00 00 5B E9 F2 CE FF FF 66 90 83 F8 15 75 A7 EB 9C 66 0F 1F 84 00 00 00 00 00 0F B6 41 01 48 83 C1 02 48 89 4B 18 3C 31 0F 84 EC 00 00 00 3C 32 0F 84 D4 00 00 00 3C 30 B9 01 00 00 00 75 8D 8B 53 28 }
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

rule xstrerror_042a56c5bd84c6ed443635c98cbbf0fa {
	meta:
		aliases = "xstrerror"
		size = "51"
		objfiles = "xstrerror@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) 89 FB E8 ?? ?? ?? ?? 48 85 C0 74 03 5B C3 90 41 89 D8 B9 ?? ?? ?? ?? BA 2B 00 00 00 BE 01 00 00 00 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 5B C3 }
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

rule lrealpath_5fb34f3c6c89e007a3efa333e41a12c2 {
	meta:
		aliases = "lrealpath"
		size = "91"
		objfiles = "lrealpath@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) BA 00 10 00 00 48 89 FB 48 81 EC 10 10 00 00 48 89 E6 64 48 8B 04 25 28 00 00 00 48 89 84 24 08 10 00 00 31 C0 E8 ?? ?? ?? ?? 48 85 C0 48 0F 44 C3 48 89 C7 E8 ?? ?? ?? ?? 48 8B 94 24 08 10 00 00 64 48 33 14 25 28 00 00 00 75 09 48 81 C4 10 10 00 00 5B C3 E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule objalloc_create_67ca0dbfb398a1520731a328f8230475 {
	meta:
		aliases = "objalloc_create"
		size = "84"
		objfiles = "objalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) BF 18 00 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 30 BF E0 0F 00 00 E8 ?? ?? ?? ?? 48 85 C0 48 89 43 10 74 22 48 C7 00 00 00 00 00 48 C7 40 08 00 00 00 00 48 83 C0 10 48 89 03 C7 43 08 D0 0F 00 00 48 89 D8 5B C3 48 89 DF 31 DB E8 ?? ?? ?? ?? EB EF }
	condition:
		$pattern
}

rule fopen_unlocked_4055eda460634cf049c59e12199515a6 {
	meta:
		aliases = "freopen_unlocked, fdopen_unlocked, fopen_unlocked"
		size = "32"
		objfiles = "fopen_unlocked@libiberty.a"
	strings:
		$pattern = { ( CC | 53 ) E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 74 0D BE 02 00 00 00 48 89 C7 E8 ?? ?? ?? ?? 48 89 D8 5B C3 }
	condition:
		$pattern
}

rule fibheap_extr_min_node_af2e7e7c4d4a52a0f051076c7a248c57 {
	meta:
		aliases = "fibheap_extr_min_node"
		size = "210"
		objfiles = "fibheap@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 45 31 C0 53 48 89 FB 48 83 EC 08 48 8B 6F 08 48 8B 55 08 EB 2A 66 2E 0F 1F 84 00 00 00 00 00 4C 8B 49 18 4C 39 C9 74 4F 4C 89 4A 18 48 8B 79 18 48 89 51 18 48 89 57 10 48 89 4A 10 4C 89 D2 48 85 D2 74 4B 4C 39 C2 74 46 48 C7 02 00 00 00 00 48 8B 4B 10 4D 85 C0 4C 0F 44 C2 4C 8B 52 18 48 85 C9 75 BB 48 89 53 10 48 89 52 10 48 89 52 18 EB CA 0F 1F 44 00 00 48 89 51 18 48 89 51 10 48 89 4A 18 48 89 4A 10 EB B3 66 0F 1F 44 00 00 48 8D 7B 10 48 89 EE E8 54 FD FF FF 48 83 2B 01 75 16 48 C7 43 08 00 00 00 00 48 83 C4 08 48 89 E8 5B 5D C3 0F 1F 40 00 48 8B 45 18 48 89 DF 48 89 43 08 E8 88 FD FF FF }
	condition:
		$pattern
}

rule is_ctor_or_dtor_112fcc956aa5ac981e7cb0b36c0cbd7b {
	meta:
		aliases = "is_ctor_or_dtor"
		size = "278"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 55 49 89 FD 41 54 49 89 D4 53 48 89 F3 48 83 EC 68 C7 06 00 00 00 00 C7 02 00 00 00 00 E8 ?? ?? ?? ?? 49 8D 54 05 00 89 45 BC 48 8D 7D 80 BE 01 00 00 00 4C 89 6D 80 C7 45 90 00 40 00 00 48 89 55 88 8D 14 00 48 98 48 8D 04 C5 16 00 00 00 4C 89 6D 98 C7 45 A8 00 00 00 00 89 55 AC 48 63 D2 C7 45 B8 00 00 00 00 48 8D 14 52 48 83 E0 F0 C7 45 C0 00 00 00 00 48 C7 45 C8 00 00 00 00 C7 45 D0 00 00 00 00 48 8D 14 D5 10 00 00 00 48 29 D4 48 89 E2 48 29 C4 48 89 55 A0 48 89 65 B0 E8 ?? ?? ?? ?? 48 89 C1 31 C0 0F 1F 00 48 85 C9 74 05 83 39 1B 76 0E 48 8D 65 E8 5B 41 5C 41 5D 5D C3 0F 1F 00 }
	condition:
		$pattern
}

rule byte_re_match_2_internal_63de4c4ccc6e729aa4b31667250ac2e3 {
	meta:
		aliases = "byte_re_match_2_internal"
		size = "8484"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 41 55 41 54 53 48 81 EC 58 01 00 00 4C 8B 37 4C 8B 67 10 48 83 EC 40 48 8B 5D 10 48 89 75 A8 64 48 8B 34 25 28 00 00 00 48 89 75 C8 31 F6 4D 01 F4 48 89 4D B0 44 89 8D 60 FF FF FF 4C 89 65 B8 4C 8B 67 30 B9 10 00 00 00 48 89 9D 48 FF FF FF 48 8B 5F 28 48 89 BD 78 FF FF FF 89 55 88 4C 89 A5 68 FF FF FF 49 83 C4 01 44 89 85 64 FF FF FF 4C 89 A5 50 FF FF FF 4C 8D 64 24 0F 44 8B 4D 18 48 89 9D 20 FF FF FF 49 83 E4 F0 48 83 BD 68 FF FF FF 00 0F 85 5C 13 00 00 48 C7 85 E8 FE FF FF 00 00 00 00 48 C7 85 F0 FE FF FF 00 00 00 00 45 31 C0 48 C7 85 08 FF FF FF 00 00 00 00 48 C7 85 }
	condition:
		$pattern
}

rule buildargv_ead13848656bc6a8f508ee62b166cbb3 {
	meta:
		aliases = "buildargv"
		size = "678"
		objfiles = "argv@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 41 55 41 54 53 48 89 FB 48 83 EC 38 64 48 8B 04 25 28 00 00 00 48 89 45 C8 31 C0 48 85 FF 0F 84 5D 02 00 00 E8 ?? ?? ?? ?? 48 83 C0 1F 45 31 F6 C7 45 B8 00 00 00 00 48 83 E0 F0 C7 45 BC 00 00 00 00 45 31 E4 48 29 C4 45 31 ED 45 31 FF 48 8D 54 24 0F 48 83 E2 F0 48 89 55 B0 0F 1F 44 00 00 0F B6 13 0F B6 C2 F6 84 00 ?? ?? ?? ?? 01 0F 85 74 01 00 00 8B 45 B8 85 C0 0F 84 79 01 00 00 8B 45 B8 83 E8 01 39 45 BC 0F 8D 6A 01 00 00 48 63 45 BC 4D 8D 14 C6 84 D2 48 8B 45 B0 75 1E EB 70 0F 1F 84 00 00 00 00 00 88 10 45 31 E4 48 83 C0 01 48 83 C3 01 0F B6 13 84 D2 74 54 0F B6 F2 F6 }
	condition:
		$pattern
}

rule make_relative_prefix_415eb8813e09d3eaf7965fa44bf9d290 {
	meta:
		aliases = "make_relative_prefix"
		size = "1132"
		objfiles = "make_relative_prefix@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 41 57 41 56 41 55 49 89 F5 41 54 53 48 83 EC 48 48 89 55 A8 64 48 8B 04 25 28 00 00 00 48 89 45 C8 31 C0 48 85 F6 0F 84 28 03 00 00 48 85 FF 49 89 FE 0F 84 1C 03 00 00 48 83 7D A8 00 0F 84 11 03 00 00 E8 ?? ?? ?? ?? 4C 39 F0 49 89 C7 0F 84 08 03 00 00 4C 89 F7 E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 0F 84 EC 02 00 00 48 8D 75 BC 48 89 C7 E8 08 FE FF FF 48 8D 75 C0 4C 89 EF 48 89 45 A0 E8 F8 FD FF FF 48 89 DF 49 89 C5 E8 ?? ?? ?? ?? 48 83 7D A0 00 0F 84 BA 02 00 00 4D 85 ED 0F 84 B1 02 00 00 44 8B 65 BC 41 83 EC 01 44 3B 65 C0 44 89 65 BC 0F 84 2B 02 00 00 48 8B 7D A8 48 8D 75 C4 E8 B6 FD }
	condition:
		$pattern
}

rule d_demangle_af168bfcd0378775899fb68174117ab2 {
	meta:
		aliases = "d_demangle"
		size = "689"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 E5 48 89 5D D8 4C 89 65 E0 48 89 FB 4C 89 6D E8 4C 89 75 F0 41 89 F5 4C 89 7D F8 48 81 EC A0 00 00 00 48 C7 02 00 00 00 00 49 89 D6 E8 ?? ?? ?? ?? 80 3B 5F 49 89 C4 0F 84 F8 01 00 00 BF ?? ?? ?? ?? B9 08 00 00 00 48 89 DE F3 A6 0F 84 0B 01 00 00 41 F6 C5 10 0F 84 F1 01 00 00 BA 01 00 00 00 4A 8D 04 23 48 89 9D 70 FF FF FF 48 89 5D 88 48 89 E3 44 89 6D 80 C7 45 98 00 00 00 00 48 89 85 78 FF FF FF 43 8D 04 24 44 89 65 AC C7 45 A8 00 00 00 00 C7 45 B0 00 00 00 00 89 45 9C 48 98 48 C7 45 B8 00 00 00 00 48 8D 04 40 C7 45 C0 00 00 00 00 48 8D 04 C5 10 00 00 00 48 29 C4 49 63 C4 48 8D 04 C5 }
	condition:
		$pattern
}

rule cplus_demangle_print_8521d135cf1b6b3e72a5c5c42a94184c {
	meta:
		aliases = "cplus_demangle_print"
		size = "193"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 CB 48 83 EC 48 89 3C 24 8D 7A 01 48 63 FF 48 89 7C 24 18 E8 ?? ?? ?? ?? 48 85 C0 48 89 44 24 08 0F 84 8B 00 00 00 48 89 EE 48 89 E7 48 C7 44 24 10 00 00 00 00 48 C7 44 24 20 00 00 00 00 48 C7 44 24 28 00 00 00 00 C7 44 24 30 00 00 00 00 E8 35 C4 FF FF 48 8B 44 24 08 48 85 C0 74 0C 48 8B 54 24 10 48 3B 54 24 18 72 27 31 F6 48 89 E7 E8 E5 C2 FF FF 48 8B 44 24 08 48 85 C0 74 21 48 8B 54 24 18 48 89 13 48 83 C4 48 5B 5D C3 0F 1F 40 00 C6 04 10 00 48 8B 44 24 08 48 85 C0 75 DF 48 63 54 24 30 48 89 13 48 83 C4 48 5B 5D C3 0F 1F 00 48 C7 03 01 00 00 00 EB CC }
	condition:
		$pattern
}

rule byte_alt_match_null_string_p_888afbcebe76cd1ca1c4b6cc08ce22e7 {
	meta:
		aliases = "byte_alt_match_null_string_p"
		size = "129"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 D3 48 83 EC 18 48 89 7C 24 08 0F 1F 80 00 00 00 00 48 39 FD 76 23 80 3F 0F 74 2E 48 8D 7C 24 08 48 89 DA 48 89 EE E8 9E FE FF FF 84 C0 74 42 48 8B 7C 24 08 48 39 FD 77 DD 48 83 C4 18 B8 01 00 00 00 5B 5D C3 0F 1F 40 00 48 8D 47 01 48 89 44 24 08 0F BE 47 02 0F B6 4F 01 C1 E0 08 01 C8 48 98 48 8D 7C 07 03 48 89 7C 24 08 EB A4 0F 1F 40 00 48 83 C4 18 31 C0 5B 5D C3 }
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

rule snarf_numeric_literal_1a52ec534405ac5182c10057792b4f81 {
	meta:
		aliases = "snarf_numeric_literal"
		size = "167"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 F5 53 48 89 FB 48 83 EC 08 48 8B 07 0F B6 10 80 FA 2D 74 69 80 FA 2B 74 54 0F B6 CA 31 C0 F6 84 09 ?? ?? ?? ?? 04 74 38 0F 1F 44 00 00 BE ?? ?? ?? ?? 48 89 EF 88 15 ?? ?? ?? ?? E8 ED FE FF FF 48 8B 03 48 8D 50 01 48 89 13 0F B6 50 01 0F B6 C2 F6 84 00 ?? ?? ?? ?? 04 75 D2 B8 01 00 00 00 48 83 C4 08 5B 5D C3 66 0F 1F 44 00 00 48 8D 50 01 48 89 17 0F B6 50 01 EB 9F 0F 1F 00 BE ?? ?? ?? ?? 48 89 EF C6 05 ?? ?? ?? ?? 2D E8 9C FE FF FF 48 8B 03 48 8D 50 01 48 89 13 0F B6 50 01 E9 75 FF FF FF }
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

rule xmalloc_failed_5166d7e0551593955ff7aef935280bba {
	meta:
		aliases = "xmalloc_failed"
		size = "110"
		objfiles = "xmalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 31 FF 53 48 83 EC 18 48 8B 1D ?? ?? ?? ?? 48 85 DB 74 4A E8 ?? ?? ?? ?? 48 29 D8 48 8B 0D ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? 49 89 E9 BA ?? ?? ?? ?? BE 01 00 00 00 80 39 00 48 89 04 24 B8 ?? ?? ?? ?? 4C 0F 45 C0 31 C0 E8 ?? ?? ?? ?? BF 01 00 00 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 2D ?? ?? ?? ?? EB B1 }
	condition:
		$pattern
}

rule _objalloc_alloc_aed94e2af3a6c56b2ba120d8e8e754c9 {
	meta:
		aliases = "_objalloc_alloc"
		size = "217"
		objfiles = "objalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 83 EC 08 48 85 F6 75 32 8B 57 08 BB 08 00 00 00 83 FA 07 76 40 0F 1F 44 00 00 48 8B 45 00 29 DA 89 55 08 48 01 D8 48 89 45 00 48 83 C4 08 48 29 D8 5B 5D C3 66 0F 1F 44 00 00 8B 57 08 48 8D 5E 07 48 83 E3 F8 89 D0 48 39 C3 76 CE 48 81 FB FF 01 00 00 77 45 BF E0 0F 00 00 E8 ?? ?? ?? ?? 48 85 C0 74 66 48 8B 55 10 48 C7 40 08 00 00 00 00 48 89 10 48 89 45 10 BA D0 0F 00 00 48 8D 44 18 10 29 DA 89 55 08 48 89 45 00 48 83 C4 08 48 29 D8 5B 5D C3 66 0F 1F 44 00 00 48 8D 7B 10 E8 ?? ?? ?? ?? 48 85 C0 74 22 48 8B 55 10 48 89 10 48 8B 55 00 48 89 50 08 48 89 45 10 48 83 C4 08 5B 48 83 }
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

rule objalloc_free_b8cb5842b081e1e93c79f4c9af8ad39c {
	meta:
		aliases = "objalloc_free"
		size = "54"
		objfiles = "objalloc@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 48 89 FD 53 48 83 EC 08 48 8B 7F 10 48 85 FF 74 16 66 0F 1F 44 00 00 48 8B 1F E8 ?? ?? ?? ?? 48 85 DB 48 89 DF 75 F0 48 83 C4 08 48 89 EF 5B 5D E9 ?? ?? ?? ?? }
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

rule concat_length_84b754ae7cb737cf19b1c996bf6f58b0 {
	meta:
		aliases = "concat_length"
		size = "153"
		objfiles = "concat@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 83 EC 58 48 85 FF 48 8D 44 24 70 48 89 74 24 28 48 89 54 24 30 48 89 4C 24 38 4C 89 44 24 40 48 89 44 24 10 48 8D 44 24 20 4C 89 4C 24 48 C7 44 24 08 08 00 00 00 48 89 44 24 18 74 55 48 89 C5 31 DB EB 1D 66 0F 1F 84 00 00 00 00 00 89 D1 83 C2 08 48 01 E9 89 54 24 08 48 8B 39 48 85 FF 74 27 E8 ?? ?? ?? ?? 8B 54 24 08 48 01 C3 83 FA 2F 76 DB 48 8B 4C 24 10 48 8B 39 48 8D 41 08 48 89 44 24 10 48 85 FF 75 D9 48 83 C4 58 48 89 D8 5B 5D C3 31 DB EB F2 }
	condition:
		$pattern
}

rule splay_tree_predecessor_e3e9d4d4d70a13fab64ce3712b2baae0 {
	meta:
		aliases = "splay_tree_predecessor"
		size = "89"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 48 83 3F 00 74 41 48 89 F5 E8 29 F9 FF FF 48 8B 03 48 89 EE 48 8B 38 FF 53 08 85 C0 48 8B 03 78 1A 48 8B 40 10 48 85 C0 75 08 EB 1B 0F 1F 00 48 89 D0 48 8B 50 18 48 85 D2 75 F4 48 83 C4 08 5B 5D C3 0F 1F 44 00 00 48 83 C4 08 31 C0 5B 5D C3 }
	condition:
		$pattern
}

rule splay_tree_successor_54ad4a88debbcff000eb71702036befe {
	meta:
		aliases = "splay_tree_successor"
		size = "100"
		objfiles = "splay_tree@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 48 83 3F 00 74 51 48 89 F5 E8 C9 F8 FF FF 48 8B 03 48 89 EE 48 8B 38 FF 53 08 85 C0 48 8B 03 7E 0E 48 83 C4 08 5B 5D C3 0F 1F 80 00 00 00 00 48 8B 40 18 48 85 C0 75 0A EB 1D 0F 1F 44 00 00 48 89 D0 48 8B 50 10 48 85 D2 75 F4 48 83 C4 08 5B 5D C3 0F 1F 44 00 00 31 C0 EB C6 }
	condition:
		$pattern
}

rule d_operator_name_c20fa3ba0b2105adba0e5bf0f1458851 {
	meta:
		aliases = "d_operator_name"
		size = "361"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 48 8B 47 18 0F B6 38 48 8D 50 01 48 89 53 18 0F B6 68 01 48 83 C0 02 48 89 43 18 40 80 FF 76 74 76 40 80 FD 76 0F 84 CC 00 00 00 BE 31 00 00 00 31 D2 0F 1F 44 00 00 89 F0 29 D0 89 C1 C1 E9 1F 01 C8 D1 F8 01 D0 48 63 C8 48 8D 0C 49 4C 8B 04 CD ?? ?? ?? ?? 4C 8D 0C CD ?? ?? ?? ?? 41 0F B6 08 40 38 F9 74 19 40 38 CF 7D 27 89 C6 39 F2 75 C6 31 C0 48 83 C4 08 5B 5D C3 0F 1F 44 00 00 41 0F B6 48 01 40 38 E9 0F 84 9A 00 00 00 40 38 CD 7C D9 8D 50 01 EB D6 8D 45 D0 31 D2 BE 31 00 00 00 3C 09 77 92 48 89 DF E8 3A D0 FF FF 8B 53 28 3B 53 2C 48 89 C1 7D B9 48 63 C2 83 C2 01 48 }
	condition:
		$pattern
}

rule squangle_mop_up_6b3b5bd27f6b3c535f57a4a5a5256b9e {
	meta:
		aliases = "squangle_mop_up"
		size = "200"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 53 48 89 FB 48 83 EC 08 8B 43 20 48 63 D0 48 8D 2C D5 F8 FF FF FF EB 0A 0F 1F 80 00 00 00 00 48 89 D5 85 C0 7E 3B 48 8B 53 10 83 E8 01 89 43 20 48 8B 3C 2A 48 8D 55 F8 48 85 FF 74 E2 E8 ?? ?? ?? ?? 48 8B 43 10 48 C7 04 28 00 00 00 00 EB B8 E8 ?? ?? ?? ?? 48 8B 43 18 48 C7 04 28 00 00 00 00 8B 43 24 48 8B 4B 18 48 63 D0 48 8D 2C D5 F8 FF FF FF EB 0D 66 2E 0F 1F 84 00 00 00 00 00 48 89 D5 85 C0 7E 19 48 8D 55 F8 83 E8 01 89 43 24 48 8B 7C 11 08 48 85 FF 74 E5 EB B4 0F 1F 00 48 85 C9 74 08 48 89 CF E8 ?? ?? ?? ?? 48 8B 7B 10 48 85 FF 74 0B 48 83 C4 08 5B 5D E9 ?? ?? ?? ?? 48 83 C4 08 5B 5D C3 }
	condition:
		$pattern
}

rule dyn_string_append_char_e1714ee3480c190e20b509b421e22179 {
	meta:
		aliases = "dyn_string_append_char"
		size = "81"
		objfiles = "dyn_string@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 F5 53 48 89 FB 48 83 EC 08 8B 77 04 83 C6 01 E8 ?? ?? ?? ?? 48 85 C0 74 2D 48 63 43 04 48 8B 53 08 40 88 2C 02 48 63 43 04 48 8B 53 08 C6 44 02 01 00 83 43 04 01 48 83 C4 08 5B B8 01 00 00 00 5D C3 0F 1F 40 00 48 83 C4 08 31 C0 5B 5D C3 }
	condition:
		$pattern
}

rule pex_read_output_5d00f8a2d41d09b0ceda124d6a7605c1 {
	meta:
		aliases = "pex_read_output"
		size = "180"
		objfiles = "pex_common@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 F5 53 48 89 FB 48 83 EC 18 48 83 7F 20 00 74 4E 48 8D 4C 24 04 48 8D 54 24 08 31 F6 E8 4D F6 FF FF 85 C0 74 79 48 8B 7B 20 85 ED BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 0F 44 F2 E8 ?? ?? ?? ?? 8B 53 28 48 89 43 58 85 D2 75 3D 48 C7 43 20 00 00 00 00 48 83 C4 18 5B 5D C3 66 0F 1F 44 00 00 8B 77 18 85 F6 7E 49 48 8B 47 70 89 EA FF 50 30 48 89 43 58 C7 43 18 FF FF FF FF 48 83 C4 18 5B 5D C3 66 0F 1F 44 00 00 48 8B 7B 20 E8 ?? ?? ?? ?? C7 43 28 00 00 00 00 48 8B 43 58 EB AD 66 90 E8 ?? ?? ?? ?? 8B 54 24 04 89 10 31 C0 EB A4 90 31 C0 EB 9F }
	condition:
		$pattern
}

rule byte_re_compile_fastmap_3b41fbca129be6ed3d824418961a4f5f {
	meta:
		aliases = "byte_re_compile_fastmap"
		size = "1182"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) BA 00 01 00 00 48 89 E5 41 57 41 56 41 55 49 89 FD 41 54 53 48 83 EC 58 48 8B 5F 20 4C 8B 27 48 83 EC 40 48 8D 74 24 0F 64 48 8B 04 25 28 00 00 00 48 89 45 C8 31 C0 4D 89 E6 48 83 E6 F0 4C 03 77 10 F6 C3 01 48 89 DF 0F 85 9D 03 00 00 40 F6 C7 02 0F 85 A8 03 00 00 40 F6 C7 04 0F 85 77 03 00 00 89 D1 31 C0 C1 E9 03 F6 C2 04 F3 48 AB 74 0A C7 07 00 00 00 00 48 83 C7 04 F6 C2 02 74 09 66 C7 07 00 00 48 83 C7 02 83 E2 01 74 03 C6 07 00 41 0F B6 45 38 4C 8D 43 01 45 31 FF 41 B9 05 00 00 00 B9 01 00 00 00 83 C8 08 83 E0 FE 41 88 45 38 4D 39 F4 74 18 41 0F B6 04 24 3C 01 74 0F 3C 1D 76 3B E8 ?? ?? }
	condition:
		$pattern
}

rule d_make_comp_0ea0bb7ab353fe1a51e60c99348222c9 {
	meta:
		aliases = "d_make_comp"
		size = "113"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 83 ) FE 32 77 53 89 F0 FF 24 C5 ?? ?? ?? ?? 66 90 48 85 C9 74 43 44 8B 47 28 44 3B 47 2C 7D 39 49 63 C0 41 83 C0 01 4C 8D 0C 40 48 8B 47 20 44 89 47 28 4A 8D 04 C8 48 85 C0 74 1D 89 30 48 89 50 08 48 89 48 10 C3 66 2E 0F 1F 84 00 00 00 00 00 48 85 C9 75 0B 0F 1F 00 31 C0 C3 0F 1F 44 00 00 48 85 D2 74 F3 44 8B 47 28 44 3B 47 2C 7D E9 EB AE }
	condition:
		$pattern
}

rule qualifier_string_e9993b76cebf6f1d9aa70f4fa4212b70 {
	meta:
		aliases = "qualifier_string"
		size = "150"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 83 ) FF 07 76 0B 48 83 EC 08 E8 ?? ?? ?? ?? 66 90 89 FF FF 24 FD ?? ?? ?? ?? 0F 1F 80 00 00 00 00 B8 ?? ?? ?? ?? C3 66 2E 0F 1F 84 00 00 00 00 00 B8 ?? ?? ?? ?? C3 66 2E 0F 1F 84 00 00 00 00 00 B8 ?? ?? ?? ?? C3 66 2E 0F 1F 84 00 00 00 00 00 B8 ?? ?? ?? ?? C3 66 2E 0F 1F 84 00 00 00 00 00 B8 ?? ?? ?? ?? C3 66 2E 0F 1F 84 00 00 00 00 00 B8 ?? ?? ?? ?? C3 66 2E 0F 1F 84 00 00 00 00 00 B8 ?? ?? ?? ?? C3 66 2E 0F 1F 84 00 00 00 00 00 B8 ?? ?? ?? ?? C3 }
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

rule cplus_demangle_set_style_c423b59f5a1ed5b55da0359a27425279 {
	meta:
		aliases = "cplus_demangle_set_style"
		size = "47"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 83 ) FF FF 89 F8 74 21 BA ?? ?? ?? ?? EB 06 66 90 39 C1 74 14 48 83 C2 18 8B 4A 08 85 C9 75 F1 31 C0 C3 66 0F 1F 44 00 00 89 05 ?? ?? ?? ?? C3 }
	condition:
		$pattern
}

rule string_appendn_87ed257e870a10e1cb7c94d45017dd4f {
	meta:
		aliases = "string_appendn"
		size = "18"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 85 ) D2 75 0C F3 C3 66 2E 0F 1F 84 00 00 00 00 00 EB 9E }
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

rule cplus_demangle_fill_extended_o_3981501c2554fbe0e42969d7a9de536e {
	meta:
		aliases = "cplus_demangle_fill_extended_operator"
		size = "51"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 89 ) F0 C1 E8 1F 84 C0 75 27 48 85 FF 74 22 48 85 D2 74 1D C7 07 29 00 00 00 89 77 08 B8 01 00 00 00 48 89 57 10 C3 66 2E 0F 1F 84 00 00 00 00 00 31 C0 C3 }
	condition:
		$pattern
}

rule init_error_tables_cf2ff99833398275645d2c370c9d213d {
	meta:
		aliases = "init_signal_tables, init_error_tables"
		size = "155"
		objfiles = "strsignal@libiberty.a, strerror@libiberty.a"
	strings:
		$pattern = { ( CC | 8B ) 05 ?? ?? ?? ?? 85 C0 75 29 31 D2 B8 ?? ?? ?? ?? 0F 1F 80 00 00 00 00 8B 08 8D 71 01 39 D1 0F 4D D6 48 83 C0 10 48 83 78 08 00 75 EB 89 15 ?? ?? ?? ?? 48 83 3D ?? ?? ?? ?? 00 74 03 C3 66 90 55 53 48 83 EC 08 8B 2D ?? ?? ?? ?? C1 E5 03 48 63 ED 48 89 EF E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 48 89 05 ?? ?? ?? ?? 74 2B 48 89 EA 31 F6 48 89 C7 E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 63 32 48 83 C2 10 48 89 0C F3 48 8B 4A 08 48 85 C9 75 EC 48 83 C4 08 5B 5D C3 }
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

rule d_make_name_b7996384a5bd8262784a2fce775cf9cb {
	meta:
		aliases = "d_make_name"
		size = "70"
		objfiles = "cp_demangle@libiberty.a"
	strings:
		$pattern = { ( CC | 8B ) 4F 28 3B 4F 2C 7D 23 48 63 C1 83 C1 01 48 85 F6 4C 8D 04 40 48 8B 47 20 89 4F 28 4A 8D 04 C0 74 09 48 85 C0 74 04 85 D2 75 0D 31 C0 0F 1F 00 C3 0F 1F 80 00 00 00 00 C7 00 00 00 00 00 48 89 70 08 89 50 10 C3 }
	condition:
		$pattern
}

rule partition_new_4f939e9f60e495974bf33c7b8789552f {
	meta:
		aliases = "partition_new"
		size = "79"
		objfiles = "partition@libiberty.a"
	strings:
		$pattern = { ( CC | 8D ) 47 FF 53 89 FB 48 98 48 8D 04 40 48 8D 3C C5 20 00 00 00 E8 ?? ?? ?? ?? 31 D2 85 DB 89 18 48 89 C1 7E 29 0F 1F 40 00 48 63 F2 89 51 08 83 C2 01 48 8D 34 76 C7 41 18 01 00 00 00 48 8D 74 F0 08 48 89 71 10 48 83 C1 18 39 DA 75 DB 5B C3 }
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

rule bcopy_90ded62a508cf2957583f85777cb2c39 {
	meta:
		aliases = "bcopy"
		size = "16"
		objfiles = "bcopy@libc.a"
	strings:
		$pattern = { 00 00 21 E0 01 10 20 E0 00 00 21 E0 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __aeabi_ui2d_23521c865a6d18d29fa87845da30c18d {
	meta:
		aliases = "__floatunsidf, __aeabi_ui2d"
		size = "40"
		objfiles = "_addsubdf3@libgcc.a"
	strings:
		$pattern = { 00 00 30 E3 00 10 A0 03 0E F0 A0 01 30 40 2D E9 01 4B A0 E3 32 40 84 E2 00 50 A0 E3 00 10 A0 E1 00 00 A0 E3 8F FF FF EA }
	condition:
		$pattern
}

rule __aeabi_i2d_886c702c19c479260a77a11c5a2b3496 {
	meta:
		aliases = "__floatsidf, __aeabi_i2d"
		size = "44"
		objfiles = "_addsubdf3@libgcc.a"
	strings:
		$pattern = { 00 00 30 E3 00 10 A0 03 0E F0 A0 01 30 40 2D E9 01 4B A0 E3 32 40 84 E2 02 51 10 E2 00 00 60 42 00 10 A0 E1 00 00 A0 E3 84 FF FF EA }
	condition:
		$pattern
}

rule twalk_35a47b89184e0cb075147fc1cd666b5d {
	meta:
		aliases = "twalk"
		size = "20"
		objfiles = "twalk@libc.a"
	strings:
		$pattern = { 00 00 50 E3 00 00 51 13 0E F0 A0 01 00 20 A0 E3 D5 FF FF EA }
	condition:
		$pattern
}

rule clone_f4a298be9cf5cc72cec19b7727994a2a {
	meta:
		aliases = "clone"
		size = "68"
		objfiles = "clone@libc.a"
	strings:
		$pattern = { 00 00 50 E3 00 00 51 13 15 00 E0 03 0B 00 00 0A 08 10 41 E2 04 30 81 E5 00 00 81 E5 02 00 A0 E1 78 00 90 EF 00 00 B0 E1 04 00 00 BA 0E F0 A0 11 04 00 9D E5 0F E0 A0 E1 00 F0 9D E5 ?? ?? ?? EA ?? ?? ?? EA }
	condition:
		$pattern
}

rule register_printf_function_e24abb1d01bc3885021f635a80566b20 {
	meta:
		aliases = "register_printf_function"
		size = "144"
		objfiles = "register_printf_function@libc.a"
	strings:
		$pattern = { 00 00 50 E3 00 00 52 13 10 40 2D E9 02 40 A0 E1 18 00 00 0A 68 30 9F E5 00 C0 93 E5 00 E0 A0 E3 0A 20 8C E2 01 30 72 E5 00 00 53 E3 02 E0 A0 01 00 00 53 E1 02 E0 A0 01 0C 20 A0 01 0C 00 52 E1 F7 FF FF 8A 00 00 5E E3 0A 00 00 0A 00 00 51 E3 0E 30 62 10 2C 20 9F 15 00 00 CE 15 03 41 82 17 24 20 9F 15 00 C0 A0 13 01 C0 A0 01 03 11 82 17 00 10 CE 05 00 00 00 EA 00 C0 E0 E3 0C 00 A0 E1 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule abs_982289527251259ce2e4944925414d59 {
	meta:
		aliases = "__absvsi2, labs, abs"
		size = "12"
		objfiles = "_absvsi2@libgcc.a, labs@libc.a"
	strings:
		$pattern = { 00 00 50 E3 00 00 60 B2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __negvsi2_00a5371883091f4df7557b172b848318 {
	meta:
		aliases = "__negvsi2"
		size = "44"
		objfiles = "_negvsi2@libgcc.a"
	strings:
		$pattern = { 00 00 50 E3 00 00 60 E2 04 E0 2D E5 A0 3F A0 B1 02 00 00 BA 00 00 50 E3 00 30 A0 D3 01 30 A0 C3 00 00 53 E3 04 F0 9D 04 ?? ?? ?? EB }
	condition:
		$pattern
}

rule dirname_a173de55b21fe45f9d3c387f3fc5c53d {
	meta:
		aliases = "dirname"
		size = "152"
		objfiles = "dirname@libc.a"
	strings:
		$pattern = { 00 00 50 E3 00 C0 A0 11 00 20 A0 11 02 00 00 1A 1D 00 00 EA 01 30 8C E2 03 C0 A0 E1 00 30 DC E5 00 00 53 E3 2F 00 53 13 0C 30 A0 01 01 00 00 0A F7 FF FF EA 01 30 83 E2 00 10 D3 E5 2F 00 51 E3 FB FF FF 0A 00 00 51 E3 0C 20 A0 11 F1 FF FF 1A 00 00 52 E1 09 00 00 1A 00 30 D0 E5 2F 00 53 E3 09 00 00 1A 01 30 D0 E5 2F 00 53 E3 01 20 80 E2 02 00 00 1A 01 30 D2 E5 00 00 53 E3 01 20 82 02 00 30 A0 E3 00 30 C2 E5 0E F0 A0 E1 00 00 9F E5 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __ffsdi2_8f397c4fd1bcbc3892040f84c5cc0713 {
	meta:
		aliases = "__ffsdi2"
		size = "136"
		objfiles = "_ffsdi2@libgcc.a"
	strings:
		$pattern = { 00 00 50 E3 00 C0 A0 13 04 00 00 1A 00 00 51 E3 01 00 A0 01 0E F0 A0 01 01 00 A0 E1 20 C0 A0 E3 00 30 60 E2 00 00 03 E0 01 08 50 E3 0A 00 00 3A FF 34 E0 E3 03 00 50 E1 18 20 A0 83 10 20 A0 93 02 10 A0 E1 30 11 A0 E1 34 30 9F E5 01 00 D3 E7 0C 20 82 E0 00 00 82 E0 0E F0 A0 E1 FF 00 50 E3 08 20 A0 83 00 20 A0 93 02 10 A0 E1 30 11 A0 E1 0C 30 9F E5 01 00 D3 E7 0C 20 82 E0 00 00 82 E0 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __ctzdi2_16096cc7e3563489a7c64a74054c7817 {
	meta:
		aliases = "__ctzdi2"
		size = "128"
		objfiles = "_ctzdi2@libgcc.a"
	strings:
		$pattern = { 00 00 50 E3 01 00 A0 01 00 30 60 E2 00 00 03 E0 00 C0 A0 13 20 C0 A0 03 01 08 50 E3 0A 00 00 2A FF 00 50 E3 08 20 A0 83 00 20 A0 93 30 22 A0 E1 44 30 9F E5 02 00 D3 E7 07 10 A0 83 00 10 E0 93 01 00 80 E0 0C 00 80 E0 0E F0 A0 E1 FF 34 E0 E3 03 00 50 E1 18 20 A0 83 10 20 A0 93 30 22 A0 E1 14 30 9F E5 02 00 D3 E7 17 10 A0 83 0F 10 A0 93 01 00 80 E0 0C 00 80 E0 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_mbsinit_22404d3b0cae3b99b04a4837eac19514 {
	meta:
		aliases = "mbsinit, __GI_mbsinit"
		size = "28"
		objfiles = "mbsinit@libc.a"
	strings:
		$pattern = { 00 00 50 E3 01 00 A0 03 0E F0 A0 01 00 30 90 E5 01 00 73 E2 00 00 A0 33 0E F0 A0 E1 }
	condition:
		$pattern
}

rule perror_64b0f4823a1c1ce33ff44b2e6dd45b0b {
	meta:
		aliases = "__GI_perror, perror"
		size = "72"
		objfiles = "perror@libc.a"
	strings:
		$pattern = { 00 00 50 E3 03 00 00 0A 00 30 D0 E5 00 00 53 E3 20 10 9F 15 01 00 00 1A 1C 10 9F E5 01 00 A0 E1 18 30 9F E5 00 20 A0 E1 00 00 93 E5 01 30 A0 E1 0C 10 9F E5 ?? ?? ?? EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __xpg_basename_cb95ab8449bf3d8a6ee04c8a6bdb79ae {
	meta:
		aliases = "__xpg_basename"
		size = "104"
		objfiles = "__xpg_basename@libc.a"
	strings:
		$pattern = { 00 00 50 E3 04 00 00 0A 00 30 D0 E5 00 00 53 E3 01 20 40 12 00 C0 A0 11 01 00 00 1A 40 C0 9F E5 0D 00 00 EA 00 30 D0 E5 2F 00 53 E3 03 00 00 0A 01 20 82 E2 02 00 50 E1 00 C0 A0 81 0C 20 A0 81 01 10 F0 E5 00 00 51 E3 F5 FF FF 1A 00 30 DC E5 2F 00 53 E3 0C 20 A0 01 01 10 C2 E5 0C 00 A0 E1 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule killpg_ed707dc8ae9b731bebbd196698e78a7e {
	meta:
		aliases = "killpg"
		size = "44"
		objfiles = "killpg@libc.a"
	strings:
		$pattern = { 00 00 50 E3 04 E0 2D E5 02 00 00 BA 00 00 60 E2 04 E0 9D E4 ?? ?? ?? EA ?? ?? ?? EB 16 30 A0 E3 00 30 80 E5 00 00 E0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule endmntent_97124c49c617aedb0ecf25df58fc465d {
	meta:
		aliases = "__GI_endmntent, endmntent"
		size = "20"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { 00 00 50 E3 04 E0 2D E5 ?? ?? ?? 1B 01 00 A0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule wctomb_c9a2023d3980e3dbc1ed951e7a98fb9a {
	meta:
		aliases = "wctomb"
		size = "16"
		objfiles = "wctomb@libc.a"
	strings:
		$pattern = { 00 00 50 E3 0E F0 A0 01 00 20 A0 E3 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __ffssi2_882e285f605a0c8f39cacdd05969e0ca {
	meta:
		aliases = "__ffssi2"
		size = "104"
		objfiles = "_ffssi2@libgcc.a"
	strings:
		$pattern = { 00 00 50 E3 0E F0 A0 01 00 30 60 E2 00 00 03 E0 01 08 50 E3 09 00 00 3A FF 34 E0 E3 03 00 50 E1 18 10 A0 83 10 10 A0 93 30 31 A0 E1 30 20 9F E5 01 C0 A0 E1 03 10 D2 E7 0C 00 81 E0 0E F0 A0 E1 FF 00 50 E3 08 10 A0 83 00 10 A0 93 30 31 A0 E1 0C 20 9F E5 01 C0 A0 E1 03 10 D2 E7 0C 00 81 E0 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_tdestroy_90c012372675865c8273e6c230cedf13 {
	meta:
		aliases = "tdestroy, __GI_tdestroy"
		size = "12"
		objfiles = "tdestroy@libc.a"
	strings:
		$pattern = { 00 00 50 E3 0E F0 A0 01 EC FF FF EA }
	condition:
		$pattern
}

rule __deregister_frame_info_bases_0032790a2a1e2dc64dab0ff0db18359b {
	meta:
		aliases = "__deregister_frame_info_bases"
		size = "224"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { 00 00 50 E3 10 40 2D E9 01 00 00 1A 00 00 A0 E3 10 80 BD E8 00 30 90 E5 00 00 53 E3 FA FF FF 0A B0 20 9F E5 00 40 92 E5 00 00 54 E3 04 00 00 1A 0A 00 00 EA 14 20 84 E2 14 40 94 E5 00 00 54 E3 06 00 00 0A 0C 30 94 E5 00 00 53 E1 F8 FF FF 1A 14 30 94 E5 00 30 82 E5 04 00 A0 E1 10 80 BD E8 74 30 9F E5 00 40 93 E5 00 00 54 E3 18 00 00 0A 03 10 A0 E1 08 00 00 EA 0C 30 94 E5 00 20 93 E5 00 00 52 E1 0D 00 00 0A 14 30 94 E5 00 00 53 E3 0F 00 00 0A 14 10 84 E2 03 40 A0 E1 10 30 D4 E5 01 00 13 E3 F3 FF FF 1A 0C 30 94 E5 00 00 53 E1 F4 FF FF 1A 14 30 94 E5 00 30 81 E5 E5 FF FF EA 14 30 94 E5 00 30 81 E5 }
	condition:
		$pattern
}

rule __register_frame_info_bases_e4bb39309d5f5ab8bd449eb3eb74f7cc {
	meta:
		aliases = "__register_frame_info_bases"
		size = "108"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { 00 00 50 E3 10 40 2D E9 01 C0 A0 E1 02 E0 A0 E1 03 40 A0 E1 10 80 BD 08 00 30 90 E5 00 00 53 E3 10 80 BD 08 00 20 A0 E3 7F 3E A0 E3 10 20 81 E5 08 30 83 E2 07 20 82 E2 10 30 C1 E5 11 20 C1 E5 20 10 9F E5 00 30 91 E5 14 30 8C E5 00 30 E0 E3 0C 00 8C E5 00 30 8C E5 00 C0 81 E5 04 E0 8C E5 08 40 8C E5 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wcstok_3e637b054225157744d6f1f755cc666b {
	meta:
		aliases = "wcstok"
		size = "108"
		objfiles = "wcstok@libc.a"
	strings:
		$pattern = { 00 00 50 E3 70 40 2D E9 01 50 A0 E1 02 60 A0 E1 00 40 A0 11 02 00 00 1A 00 40 92 E5 00 00 54 E3 0F 00 00 0A 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 41 84 E0 00 30 94 E5 00 00 53 E3 03 40 A0 01 04 00 A0 01 05 00 00 0A 05 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 30 A0 13 04 30 80 14 00 00 86 E5 04 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule dlsym_5a4c63e0fa1044777f8103f96353497c {
	meta:
		aliases = "dlsym"
		size = "224"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 00 00 50 E3 C8 30 9F 05 30 40 2D E9 01 50 A0 E1 0E 40 A0 E1 00 10 93 05 24 00 00 0A 01 00 70 E3 00 10 A0 E1 A8 30 9F E5 0F 00 00 0A 00 30 93 E5 03 00 50 E1 9C 30 9F 15 00 30 93 15 03 00 00 1A 1A 00 00 EA 00 00 53 E1 18 00 00 0A 04 30 93 E5 00 00 53 E3 FA FF FF 1A 7C 30 9F E5 0A 20 A0 E3 00 00 A0 E3 00 20 83 E5 30 80 BD E8 00 20 93 E5 00 E0 A0 E3 0B 00 00 EA 00 00 92 E5 14 C0 90 E5 04 00 5C E1 06 00 00 2A 00 00 5E E3 02 00 00 0A 14 30 9E E5 0C 00 53 E1 01 00 00 2A 10 10 92 E5 00 E0 A0 E1 10 20 92 E5 00 00 52 E3 F1 FF FF 1A 00 20 A0 E3 02 30 A0 E1 05 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 10 30 9F 05 }
	condition:
		$pattern
}

rule openlog_intern_1736ea77ac512ee0c08a17116e1f589d {
	meta:
		aliases = "openlog_intern"
		size = "264"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { 00 00 50 E3 E4 30 9F 15 00 00 83 15 FE 3F D2 E3 DC 30 9F E5 00 10 83 E5 D8 30 9F 05 A2 21 A0 01 00 20 83 05 D0 30 9F E5 F0 41 2D E9 00 40 93 E5 01 00 74 E3 01 80 A0 E1 02 60 A0 13 16 00 00 1A 02 50 A0 E3 08 00 18 E3 F0 81 BD 08 01 00 A0 E3 05 10 A0 E1 00 20 A0 E3 ?? ?? ?? EB 98 30 9F E5 01 00 70 E3 00 40 A0 E1 00 00 83 E5 F0 81 BD 08 01 20 A0 E3 02 10 A0 E3 ?? ?? ?? EB 03 10 A0 E3 04 00 A0 E1 ?? ?? ?? EB 04 10 A0 E3 02 2B 80 E3 04 00 A0 E1 ?? ?? ?? EB 05 60 A0 E1 5C 70 9F E5 00 30 97 E5 00 00 53 E3 F0 81 BD 18 04 00 A0 E1 4C 10 9F E5 10 20 A0 E3 ?? ?? ?? EB 01 00 70 E3 01 30 A0 13 00 50 A0 E1 }
	condition:
		$pattern
}

rule inet_aton_f969b0dfabe50b8d338e340a5e4bae8d {
	meta:
		aliases = "__GI_inet_aton, inet_aton"
		size = "240"
		objfiles = "inet_aton@libc.a"
	strings:
		$pattern = { 00 00 50 E3 F0 47 2D E9 01 70 A0 E1 34 00 00 0A 00 50 A0 E3 D0 90 9F E5 01 60 A0 E3 05 A0 A0 E1 0A 80 A0 E3 21 00 00 EA 00 E0 99 E5 00 30 D0 E5 83 30 DE E7 08 00 13 E3 29 00 00 0A 0A 40 A0 E1 05 00 00 EA 94 08 03 E0 30 30 43 E2 0C 40 83 E0 FF 00 54 E3 22 00 00 CA 01 00 80 E2 00 C0 D0 E5 8C 30 A0 E1 0E 20 83 E0 0E 10 D3 E7 01 30 D2 E5 03 34 81 E1 08 00 13 E3 F1 FF FF 1A 04 00 56 E3 03 00 00 0A 2E 00 5C E3 15 00 00 1A 01 00 80 E2 04 00 00 EA 00 00 5C E3 01 00 80 E2 01 00 00 0A 20 00 13 E3 0E 00 00 0A 05 54 84 E1 01 60 86 E2 04 00 56 E3 DB FF FF DA 00 00 57 E3 25 2C A0 11 FF 38 05 12 23 24 82 11 }
	condition:
		$pattern
}

rule wmemmove_699d5a2fab0a6cf2356dfec66addaf8a {
	meta:
		aliases = "wmemmove"
		size = "68"
		objfiles = "wmemmove@libc.a"
	strings:
		$pattern = { 00 00 51 E1 00 C0 A0 21 02 00 00 2A 07 00 00 EA 04 30 91 E4 04 30 8C E4 00 00 52 E3 01 20 42 E2 FA FF FF 1A 0E F0 A0 E1 0C 30 91 E7 0C 30 80 E7 00 00 52 E3 01 20 42 E2 02 C1 A0 E1 F9 FF FF 1A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule _memcpy_9c0fa403499e290516f81a99917ad67a {
	meta:
		aliases = "_memcpy"
		size = "1168"
		objfiles = "_memcpy@libc.a"
	strings:
		$pattern = { 00 00 51 E1 90 00 00 3A 0E F0 A0 01 01 40 2D E9 04 20 52 E2 20 00 00 BA 03 C0 10 E2 28 00 00 1A 03 C0 11 E2 32 00 00 1A 08 20 52 E2 12 00 00 BA 14 20 52 E2 0B 00 00 BA 04 40 2D E5 18 50 B1 E8 18 50 A0 E8 18 50 B1 E8 18 50 A0 E8 20 20 52 E2 F9 FF FF AA 10 00 72 E3 18 50 B1 A8 18 50 A0 A8 10 20 42 A2 04 40 9D E4 14 20 92 E2 08 50 B1 A8 08 50 A0 A8 0C 20 52 A2 FB FF FF AA 08 20 92 E2 05 00 00 BA 04 20 52 E2 04 30 91 B4 04 30 80 B4 08 10 B1 A8 08 10 A0 A8 04 20 42 A2 04 20 92 E2 01 80 BD 08 02 00 52 E3 01 30 D1 E4 01 30 C0 E4 01 30 D1 A4 01 30 C0 A4 01 30 D1 C4 01 30 C0 C4 01 80 BD E8 04 C0 6C E2 }
	condition:
		$pattern
}

rule __clzdi2_51b83d6a971669809d8c386ddf5a844a {
	meta:
		aliases = "__clzdi2"
		size = "120"
		objfiles = "_clzdi2@libgcc.a"
	strings:
		$pattern = { 00 00 51 E3 01 00 A0 11 00 C0 A0 13 20 C0 A0 03 01 08 50 E3 0A 00 00 2A FF 00 50 E3 08 20 A0 83 00 20 A0 93 30 22 A0 E1 44 30 9F E5 02 00 D3 E7 18 10 A0 83 20 10 A0 93 01 00 60 E0 0C 00 80 E0 0E F0 A0 E1 FF 34 E0 E3 03 00 50 E1 18 20 A0 83 10 20 A0 93 30 22 A0 E1 14 30 9F E5 02 00 D3 E7 08 10 A0 83 10 10 A0 93 01 00 60 E0 0C 00 80 E0 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __divsi3_688779cadb25f6de125153fb601756e2 {
	meta:
		aliases = "__aeabi_idiv, __divsi3"
		size = "296"
		objfiles = "_divsi3@libgcc.a"
	strings:
		$pattern = { 00 00 51 E3 01 C0 20 E0 42 00 00 0A 00 10 61 42 01 20 51 E2 27 00 00 0A 00 30 B0 E1 00 30 60 42 01 00 53 E1 26 00 00 9A 02 00 11 E1 28 00 00 0A 0E 02 11 E3 81 11 A0 01 08 20 A0 03 01 20 A0 13 01 02 51 E3 03 00 51 31 01 12 A0 31 02 22 A0 31 FA FF FF 3A 02 01 51 E3 03 00 51 31 81 10 A0 31 82 20 A0 31 FA FF FF 3A 00 00 A0 E3 01 00 53 E1 01 30 43 20 02 00 80 21 A1 00 53 E1 A1 30 43 20 A2 00 80 21 21 01 53 E1 21 31 43 20 22 01 80 21 A1 01 53 E1 A1 31 43 20 A2 01 80 21 00 00 53 E3 22 22 B0 11 21 12 A0 11 EF FF FF 1A 00 00 5C E3 00 00 60 42 0E F0 A0 E1 00 00 3C E1 00 00 60 42 0E F0 A0 E1 00 00 A0 33 }
	condition:
		$pattern
}

rule sigprocmask_89c6d4c5cfe34808d056038e80748878 {
	meta:
		aliases = "__GI_sigprocmask, sigprocmask"
		size = "84"
		objfiles = "sigprocmask@libc.a"
	strings:
		$pattern = { 00 00 51 E3 02 00 50 13 10 40 2D E9 04 00 00 9A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 09 00 00 EA 08 30 A0 E3 AF 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 20 A0 E1 02 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule setbuf_f770fe33d425fde756069ca8ae15686a {
	meta:
		aliases = "setbuf"
		size = "20"
		objfiles = "setbuf@libc.a"
	strings:
		$pattern = { 00 00 51 E3 02 20 A0 03 00 20 A0 13 01 3A A0 E3 ?? ?? ?? EA }
	condition:
		$pattern
}

rule setbuffer_7fc3dfe76355dae3347601cacf0f1a3f {
	meta:
		aliases = "setbuffer"
		size = "20"
		objfiles = "setbuffer@libc.a"
	strings:
		$pattern = { 00 00 51 E3 02 30 A0 E1 02 20 A0 03 00 20 A0 13 ?? ?? ?? EA }
	condition:
		$pattern
}

rule pthread_attr_setscope_2ecf6aa4300b95bc5f180bc7c8d83298 {
	meta:
		aliases = "__GI_pthread_attr_setscope, pthread_attr_setscope"
		size = "36"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 00 00 51 E3 03 00 00 0A 01 00 51 E3 16 00 A0 13 5F 00 A0 03 0E F0 A0 E1 10 10 80 E5 01 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __addvsi3_44295d8fa5ab3682849f451e46ede131 {
	meta:
		aliases = "__addvsi3"
		size = "64"
		objfiles = "_addvsi3@libgcc.a"
	strings:
		$pattern = { 00 00 51 E3 04 E0 2D E5 00 10 81 E0 06 00 00 BA 00 00 51 E1 00 00 A0 A3 01 00 A0 B3 00 00 50 E3 05 00 00 1A 01 00 A0 E1 04 F0 9D E4 00 00 51 E1 00 00 A0 D3 01 00 A0 C3 F7 FF FF EA ?? ?? ?? EB }
	condition:
		$pattern
}

rule __subvsi3_2b6d19333e3a535ebb289af29f6fb4ba {
	meta:
		aliases = "__subvsi3"
		size = "64"
		objfiles = "_subvsi3@libgcc.a"
	strings:
		$pattern = { 00 00 51 E3 04 E0 2D E5 00 30 61 E0 06 00 00 BA 00 00 53 E1 00 00 A0 D3 01 00 A0 C3 00 00 50 E3 05 00 00 1A 03 00 A0 E1 04 F0 9D E4 00 00 53 E1 00 00 A0 A3 01 00 A0 B3 F7 FF FF EA ?? ?? ?? EB }
	condition:
		$pattern
}

rule xdrrec_endofrecord_27be5ee1f052b4002c99129e090a5d71 {
	meta:
		aliases = "__GI_xdrrec_endofrecord, xdrrec_endofrecord"
		size = "132"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 00 00 51 E3 0C C0 90 E5 07 00 00 1A 1C 30 9C E5 00 00 53 E3 04 00 00 1A 10 10 8C E2 06 00 91 E8 04 30 81 E2 02 00 53 E1 04 00 00 3A 00 30 A0 E3 0C 00 A0 E1 01 10 A0 E3 1C 30 8C E5 CF FF FF EA 18 00 9C E5 01 20 60 E0 04 20 42 E2 02 21 82 E3 FF 18 02 E2 22 3C A0 E1 21 34 83 E1 FF 1C 02 E2 01 34 83 E1 02 3C 83 E1 00 30 80 E5 10 20 9C E5 01 00 A0 E3 04 30 82 E2 10 30 8C E5 18 20 8C E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_insert_list_51ebefd6f43c918abd8fb28b34aec50d {
	meta:
		aliases = "pthread_insert_list"
		size = "52"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { 00 00 51 E3 0E F0 A0 01 00 00 53 E3 01 00 00 1A 03 00 00 EA 04 00 83 E2 00 30 90 E5 00 00 53 E3 FB FF FF 1A 00 30 90 E5 0A 00 82 E8 00 20 80 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_strnlen_3a16e42e1b25afa75566a45c10cab1e8 {
	meta:
		aliases = "strnlen, __GI_strnlen"
		size = "216"
		objfiles = "strnlen@libc.a"
	strings:
		$pattern = { 00 00 51 E3 10 40 2D E9 00 40 A0 E1 01 00 A0 01 10 80 BD 08 01 10 94 E0 00 10 E0 23 04 00 A0 E1 07 00 00 EA 00 30 D0 E5 00 00 53 E3 03 00 00 1A 00 00 51 E1 01 00 64 90 00 00 64 80 10 80 BD E8 01 00 80 E2 03 00 10 E3 F5 FF FF 1A 00 E0 A0 E1 16 00 00 EA 04 30 9E E4 02 20 83 E0 0C C0 02 E0 00 00 5C E3 10 00 00 0A 04 30 5E E5 00 00 53 E3 04 20 4E E2 02 00 A0 01 10 00 00 0A 03 30 5E E5 00 00 53 E3 01 00 82 E2 0C 00 00 0A 02 30 5E E5 00 00 53 E3 02 00 82 E2 08 00 00 0A 01 30 5E E5 00 00 53 E3 03 00 82 E2 04 00 00 0A 01 00 A0 E1 01 00 5E E1 14 20 9F E5 14 C0 9F E5 E4 FF FF 3A 00 00 51 E1 01 00 64 90 }
	condition:
		$pattern
}

rule _pthread_cleanup_pop_d21223bbbd6fdea25a36ba02cc40ddf0 {
	meta:
		aliases = "_pthread_cleanup_pop"
		size = "40"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { 00 00 51 E3 10 40 2D E9 00 40 A0 E1 04 00 90 15 0F E0 A0 11 00 F0 94 15 B3 FF FF EB 0C 30 94 E5 3C 30 80 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule __sigjmp_save_34c5193221591ddc6dd1145e70103baf {
	meta:
		aliases = "__sigjmp_save"
		size = "60"
		objfiles = "sigjmp@libc.a"
	strings:
		$pattern = { 00 00 51 E3 10 40 2D E9 00 40 A0 E1 06 00 00 0A 00 00 A0 E3 00 10 A0 E1 5C 20 84 E2 ?? ?? ?? EB 00 00 50 E3 01 30 A0 03 00 00 00 0A 00 30 A0 E3 00 00 A0 E3 58 30 84 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule mq_notify_9a450b236ec923a19c5d83ad77705d7b {
	meta:
		aliases = "mq_notify"
		size = "88"
		objfiles = "mq_notify@librt.a"
	strings:
		$pattern = { 00 00 51 E3 10 40 2D E9 07 00 00 0A 08 30 91 E5 02 00 53 E3 04 00 00 1A ?? ?? ?? EB 26 30 A0 E3 00 20 E0 E3 00 30 80 E5 08 00 00 EA 16 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 20 A0 E1 02 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule tcsendbreak_bbcf97c4493b712877317fe881f36444 {
	meta:
		aliases = "tcsendbreak"
		size = "64"
		objfiles = "tcsendbrk@libc.a"
	strings:
		$pattern = { 00 00 51 E3 10 40 2D E9 28 10 9F D5 00 40 A0 E1 00 20 A0 D3 05 00 00 DA 63 00 81 E2 64 10 A0 E3 ?? ?? ?? EB 10 10 9F E5 00 20 A0 E1 04 00 A0 E1 10 40 BD E8 ?? ?? ?? EA 09 54 00 00 25 54 00 00 }
	condition:
		$pattern
}

rule start_fde_sort_a2ea0b0a9d1b14a5029dfe5cffcee0ab {
	meta:
		aliases = "start_fde_sort"
		size = "104"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { 00 00 51 E3 30 40 2D E9 00 50 A0 E1 02 00 00 1A 00 30 A0 E3 03 00 A0 E1 30 80 BD E8 01 31 A0 E1 08 40 83 E2 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 30 A0 E1 00 00 85 E5 F4 FF FF 0A 04 00 A0 E1 00 40 A0 E3 04 40 83 E5 ?? ?? ?? EB 04 00 50 E1 01 30 A0 03 01 30 A0 13 04 00 85 E5 04 40 80 15 03 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule __modsi3_47e15a0d494d7fa05d3b13cf5e9baf51 {
	meta:
		aliases = "__modsi3"
		size = "228"
		objfiles = "_modsi3@libgcc.a"
	strings:
		$pattern = { 00 00 51 E3 32 00 00 0A 00 10 61 42 00 C0 B0 E1 00 00 60 42 01 20 51 E2 01 00 50 11 00 00 A0 03 02 00 11 81 02 00 00 00 26 00 00 9A 00 20 A0 E3 01 02 51 E3 00 00 51 31 01 12 A0 31 04 20 82 32 FA FF FF 3A 02 01 51 E3 00 00 51 31 81 10 A0 31 01 20 82 32 FA FF FF 3A 03 20 52 E2 0E 00 00 BA 01 00 50 E1 01 00 40 20 A1 00 50 E1 A1 00 40 20 21 01 50 E1 21 01 40 20 A1 01 50 E1 A1 01 40 20 01 00 50 E3 21 12 A0 E1 04 20 52 A2 F3 FF FF AA 03 00 12 E3 00 00 30 13 0A 00 00 0A 02 00 72 E3 06 00 00 BA 02 00 00 0A 01 00 50 E1 01 00 40 20 A1 10 A0 E1 01 00 50 E1 01 00 40 20 A1 10 A0 E1 01 00 50 E1 01 00 40 20 }
	condition:
		$pattern
}

rule __fsetlocking_e3c13499a8ba90c2c333a5d3dc6f1e63 {
	meta:
		aliases = "__GI___fsetlocking, __fsetlocking"
		size = "48"
		objfiles = "__fsetlocking@libc.a"
	strings:
		$pattern = { 00 00 51 E3 34 20 90 E5 04 00 00 0A 02 00 51 E3 14 30 9F 15 00 30 93 15 01 30 A0 03 34 30 80 E5 01 00 02 E2 01 00 80 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tdelete_18553bba5708858f4b4960e38d0b7abb {
	meta:
		aliases = "tdelete"
		size = "228"
		objfiles = "tdelete@libc.a"
	strings:
		$pattern = { 00 00 51 E3 F0 40 2D E9 00 70 A0 E1 02 40 A0 E1 31 00 00 0A 00 60 91 E5 01 50 A0 E1 00 00 56 E3 04 00 00 EA 04 50 83 B2 08 50 83 A2 03 60 A0 E1 00 30 95 E5 00 00 53 E3 27 00 00 0A 00 30 95 E5 07 00 A0 E1 00 10 93 E5 0F E0 A0 E1 04 F0 A0 E1 00 00 50 E3 00 30 95 E5 F1 FF FF 1A 04 40 93 E5 00 00 54 E3 08 10 93 E5 05 00 00 0A 00 00 51 E3 14 00 00 0A 04 20 91 E5 00 00 52 E3 04 00 00 1A 04 40 81 E5 01 40 A0 E1 0E 00 00 EA 03 20 A0 E1 00 10 A0 E1 04 30 92 E5 00 00 53 E3 02 00 A0 E1 F9 FF FF 1A 08 30 92 E5 04 30 81 E5 00 30 95 E5 04 30 93 E5 04 30 82 E5 00 30 95 E5 08 30 93 E5 08 30 82 E5 02 40 A0 E1 }
	condition:
		$pattern
}

rule _load_inttype_a970421fc4e33dfe9ac75d8dcb02e625 {
	meta:
		aliases = "_load_inttype"
		size = "112"
		objfiles = "_load_inttype@libc.a"
	strings:
		$pattern = { 00 00 52 E3 00 30 A0 E1 02 2B 00 E2 0A 00 00 BA 00 00 52 E3 0A 00 00 1A 01 0C 50 E3 00 00 91 E5 FF 00 00 02 02 00 00 0A 02 0C 53 E3 00 38 A0 01 23 08 A0 01 00 10 A0 E3 0E F0 A0 E1 00 00 52 E3 01 00 00 0A 03 00 91 E8 0E F0 A0 E1 01 0C 50 E3 00 00 91 E5 FF 00 00 02 02 00 00 0A 02 0C 53 E3 00 38 A0 01 43 08 A0 01 C0 1F A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule xdrstdio_getbytes_26f44c67f0f768d3737b069f6d38412f {
	meta:
		aliases = "xdrstdio_putbytes, xdrstdio_getbytes"
		size = "56"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { 00 00 52 E3 00 30 A0 E1 04 E0 2D E5 01 00 A0 E1 01 00 A0 03 04 F0 9D 04 02 10 A0 E1 0C 30 93 E5 01 20 A0 E3 ?? ?? ?? EB 01 00 50 E3 00 00 A0 13 01 00 A0 03 04 F0 9D E4 }
	condition:
		$pattern
}

rule __gcc_bcmp_9859ca10db0aa29fc4b21ef48375325e {
	meta:
		aliases = "__gcc_bcmp"
		size = "72"
		objfiles = "__gcc_bcmp@libgcc.a"
	strings:
		$pattern = { 00 00 52 E3 00 C0 A0 E1 0A 00 00 0A 00 30 D0 E5 00 00 D1 E5 00 00 53 E1 04 00 00 0A 07 00 00 EA 01 30 FC E5 01 00 F1 E5 00 00 53 E1 03 00 00 1A 01 20 52 E2 F9 FF FF 1A 00 00 A0 E3 0E F0 A0 E1 03 00 60 E0 0E F0 A0 E1 }
	condition:
		$pattern
}

rule re_set_registers_78a52c8468d38fd610d23d781e1a131a {
	meta:
		aliases = "re_set_registers"
		size = "72"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 00 00 52 E3 03 C0 A0 E1 1C 30 D0 E5 07 00 00 0A 04 30 C3 E3 02 30 83 E3 1C 30 C0 E5 00 30 9D E5 00 20 81 E5 08 30 81 E5 04 C0 81 E5 0E F0 A0 E1 06 30 C3 E3 1C 30 C0 E5 04 20 81 E5 00 20 81 E5 08 20 81 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_strxfrm_5d445bc672e3f71d5e5815df3d7e3390 {
	meta:
		aliases = "__GI_strlcpy, strxfrm, strlcpy, __GI_strxfrm"
		size = "72"
		objfiles = "strlcpy@libc.a"
	strings:
		$pattern = { 00 00 52 E3 04 D0 4D E2 00 C0 A0 E1 01 20 42 12 03 C0 8D 02 01 00 A0 E1 03 00 00 EA 00 00 52 E3 01 20 42 12 01 C0 8C 12 01 00 80 E2 00 30 D0 E5 00 00 53 E3 00 30 CC E5 F7 FF FF 1A 00 00 61 E0 04 D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __wcslcpy_6bfd2276420604edc2ccbdaa243f7350 {
	meta:
		aliases = "wcsxfrm, __GI_wcsxfrm, __wcslcpy"
		size = "76"
		objfiles = "wcslcpy@libc.a"
	strings:
		$pattern = { 00 00 52 E3 04 D0 4D E2 00 C0 A0 E1 01 20 42 12 0D C0 A0 01 01 00 A0 E1 03 00 00 EA 00 00 52 E3 01 20 42 12 04 C0 8C 12 04 00 80 E2 00 30 90 E5 00 00 53 E3 00 30 8C E5 F7 FF FF 1A 00 00 61 E0 40 01 A0 E1 04 D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __new_sem_init_10af9c11183921c48c4bf715f33c08fa {
	meta:
		aliases = "sem_init, __new_sem_init"
		size = "84"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { 00 00 52 E3 04 E0 2D E5 00 30 A0 E1 03 00 00 AA ?? ?? ?? EB 00 10 E0 E3 16 30 A0 E3 04 00 00 EA 00 00 51 E3 04 00 00 0A ?? ?? ?? EB 00 10 E0 E3 26 30 A0 E3 00 30 80 E5 03 00 00 EA 08 20 83 E5 0C 10 83 E5 00 10 83 E5 04 10 83 E5 01 00 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule __old_sem_init_f460b25234ecb78b50828229347eb771 {
	meta:
		aliases = "__old_sem_init"
		size = "84"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { 00 00 52 E3 04 E0 2D E5 00 C0 A0 E1 03 00 00 AA ?? ?? ?? EB 00 10 E0 E3 16 30 A0 E3 04 00 00 EA 00 00 51 E3 04 00 00 0A ?? ?? ?? EB 00 10 E0 E3 26 30 A0 E3 00 30 80 E5 03 00 00 EA 82 30 A0 E1 01 30 83 E2 00 30 8C E5 04 10 8C E5 01 00 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule mbrlen_82aa21b7c2c0be9efdcb24aa6a8a3284 {
	meta:
		aliases = "__GI_mbrlen, mbrlen"
		size = "32"
		objfiles = "mbrlen@libc.a"
	strings:
		$pattern = { 00 00 52 E3 10 30 9F E5 02 30 A0 11 01 20 A0 E1 00 10 A0 E1 00 00 A0 E3 ?? ?? ?? EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fde_insert_164b571ad04f447660282f8e0e399579 {
	meta:
		aliases = "fde_insert"
		size = "40"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { 00 00 90 E5 00 00 50 E3 0E F0 A0 01 04 20 90 E5 02 31 A0 E1 00 30 83 E0 01 20 82 E2 08 10 83 E5 04 20 80 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule uw_frame_state_for_b1469de00c6490b4c43cfe8179ba362b {
	meta:
		aliases = "uw_frame_state_for"
		size = "36"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { 00 00 90 E5 00 00 50 E3 18 30 90 15 05 30 A0 03 00 30 81 15 00 30 A0 13 00 00 81 05 03 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule _Unwind_GetCFA_59b23f58345c4b02c717ab8c852052c0 {
	meta:
		aliases = "_Unwind_GetCFA"
		size = "16"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { 00 00 90 E5 00 00 50 E3 28 00 90 15 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __collated_compare_4d106d8c9edae9636e2db2ec8abc5ba4 {
	meta:
		aliases = "__collated_compare"
		size = "48"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { 00 00 90 E5 00 10 91 E5 01 00 50 E1 00 00 A0 03 0E F0 A0 01 00 00 50 E3 01 00 80 02 0E F0 A0 01 00 00 51 E3 00 00 E0 03 0E F0 A0 01 ?? ?? ?? EA }
	condition:
		$pattern
}

rule alphasort_83d05895d963825cf6af6500a45ff860 {
	meta:
		aliases = "versionsort, alphasort"
		size = "20"
		objfiles = "versionsort@libc.a, alphasort@libc.a"
	strings:
		$pattern = { 00 00 90 E5 00 10 91 E5 0B 00 80 E2 0B 10 81 E2 ?? ?? ?? EA }
	condition:
		$pattern
}

rule alphasort64_e2b0c6410971199a5d896458bd818c1e {
	meta:
		aliases = "versionsort64, alphasort64"
		size = "20"
		objfiles = "alphasort64@libc.a, versionsort64@libc.a"
	strings:
		$pattern = { 00 00 90 E5 00 10 91 E5 13 00 80 E2 13 10 81 E2 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __old_sem_getvalue_8c38fa2680a2b155e8a9f85efb264912 {
	meta:
		aliases = "__old_sem_getvalue"
		size = "24"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { 00 00 90 E5 01 30 10 E2 A0 30 A0 11 00 00 A0 E3 00 30 81 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule uw_identify_context_26e210e3a566ab2cbc6ef52b759ff955 {
	meta:
		aliases = "uw_identify_context"
		size = "8"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { 00 00 90 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule _Unwind_SjLj_Unregister_dd8fb2be0bd7eb75d0ce06a710995fd0 {
	meta:
		aliases = "_Unwind_SjLj_Unregister"
		size = "8"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { 00 00 90 E5 F9 FF FF EA }
	condition:
		$pattern
}

rule last_fde_e30947c7171c69f1bf3ce25aa10e8f1f {
	meta:
		aliases = "last_fde"
		size = "16"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { 00 00 91 E5 01 00 70 E2 00 00 A0 33 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __errno_location_e58b6c68de6f2c99d5beb6298a089abb {
	meta:
		aliases = "__GI___h_errno_location, __libc_pthread_init, __res_state, __h_errno_location, __GI___errno_location, __errno_location"
		size = "12"
		objfiles = "__errno_location@libc.a, _res_state@libc.a, __h_errno_location@libc.a, libc_pthread_init@libc.a"
	strings:
		$pattern = { 00 00 9F E5 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_mutexattr_getpshared_ce822670167e714100ef5d7d1cf95d8f {
	meta:
		aliases = "pthread_condattr_getpshared, pthread_mutexattr_getpshared, __pthread_mutexattr_getpshared"
		size = "12"
		objfiles = "condvar@libpthread.a, mutex@libpthread.a"
	strings:
		$pattern = { 00 00 A0 E3 00 00 81 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule setpgrp_1d8cc3ce28789b0c82443963c9c374e7 {
	meta:
		aliases = "setpgrp"
		size = "12"
		objfiles = "setpgrp@libc.a"
	strings:
		$pattern = { 00 00 A0 E3 00 10 A0 E1 ?? ?? ?? EA }
	condition:
		$pattern
}

rule xdrstdio_inline_6784a51311637d8b420ae445bb38bfaa {
	meta:
		aliases = "wcsftime, __gthread_active_p, __GI_wcsftime, authnone_refresh, clntraw_control, __udiv_w_sdiv, _Unwind_GetRegionStart, pthread_rwlockattr_destroy, _Unwind_GetTextRelBase, __pthread_mutexattr_destroy, pthread_mutexattr_destroy, __pthread_mutex_lock, __GI_pthread_attr_destroy, __GI_pthread_condattr_init, pthread_condattr_destroy, _Unwind_GetDataRelBase, __gthread_mutex_unlock, _Unwind_FindEnclosingFunction, pthread_attr_destroy, __pthread_mutex_trylock, __pthread_mutex_init, __pthread_return_0, _svcauth_null, grantpt, __pthread_mutex_unlock, __GI_pthread_condattr_destroy, pthread_condattr_init, __gthread_mutex_lock, xdrstdio_inline"
		size = "8"
		objfiles = "mutex@libpthread.a, condvar@libpthread.a, rwlock@libpthread.a, auth_none@libc.a, _udiv_w_sdiv@libgcc.a"
	strings:
		$pattern = { 00 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule feof_unlocked_cff4238c928096c2e89b094a80678bda {
	meta:
		aliases = "feof_unlocked"
		size = "12"
		objfiles = "feof_unlocked@libc.a"
	strings:
		$pattern = { 00 00 D0 E5 04 00 00 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule ferror_unlocked_a6882a24eefef269698fca3e96969fa0 {
	meta:
		aliases = "ferror_unlocked"
		size = "12"
		objfiles = "ferror_unlocked@libc.a"
	strings:
		$pattern = { 00 00 D0 E5 08 00 00 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __freading_45ce153e86646947c1541a88c463649c {
	meta:
		aliases = "__freading"
		size = "12"
		objfiles = "__freading@libc.a"
	strings:
		$pattern = { 00 00 D0 E5 23 00 00 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __fwriting_c9c8c6c5a7c1186f84a9bd0179d7f737 {
	meta:
		aliases = "__fwriting"
		size = "12"
		objfiles = "__fwriting@libc.a"
	strings:
		$pattern = { 00 00 D0 E5 50 00 00 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule umask_1ce06b0f75172a81a86adaa37bde1ac4 {
	meta:
		aliases = "umask"
		size = "56"
		objfiles = "umask@libc.a"
	strings:
		$pattern = { 00 08 A0 E1 10 40 2D E9 20 08 A0 E1 3C 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 08 A0 E1 20 08 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __libc_sa_len_17207c9ba3857dd6c2f8355cf7db5cdc {
	meta:
		aliases = "__libc_sa_len"
		size = "96"
		objfiles = "sa_len@libc.a"
	strings:
		$pattern = { 00 08 A0 E1 20 08 A0 E1 01 00 40 E2 09 00 50 E3 00 F1 9F 97 0B 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 70 00 A0 E3 0E F0 A0 E1 00 00 A0 E3 0E F0 A0 E1 1C 00 A0 E3 0E F0 A0 E1 10 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __paritydi2_245b8e3c24a486106ff2f5745ce96026 {
	meta:
		aliases = "__paritydi2"
		size = "40"
		objfiles = "_paritydi2@libgcc.a"
	strings:
		$pattern = { 00 10 21 E0 21 18 21 E0 21 14 21 E0 21 12 21 E0 69 0C A0 E3 0F 10 01 E2 96 00 80 E2 50 01 A0 E1 01 00 00 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule _dl_protect_relro_61d6fd9a456b63d58aa21af2d00f788d {
	meta:
		aliases = "_dl_protect_relro"
		size = "144"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 00 10 90 E5 D4 30 90 E5 D8 20 90 E5 01 30 83 E0 02 20 83 E0 00 C0 A0 E1 FF 1E C2 E3 FF 0E C3 E3 0F 00 C0 E3 0F 10 C1 E3 01 00 50 E1 04 E0 2D E5 04 F0 9D 04 01 10 60 E0 01 20 A0 E3 7D 00 90 EF 01 0A 70 E3 3C 30 9F 85 00 20 60 82 00 20 83 85 01 00 00 8A 00 00 50 E3 04 F0 9D A4 04 20 9C E5 02 00 A0 E3 20 10 9F E5 ?? ?? ?? EB 00 00 A0 E3 01 00 90 EF 01 0A 70 E3 08 30 9F 85 00 20 60 82 00 20 83 85 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_posix_openpt_99e48e6a3894911c4e8e20424e2b342d {
	meta:
		aliases = "posix_openpt, __GI_posix_openpt"
		size = "16"
		objfiles = "getpt@libc.a"
	strings:
		$pattern = { 00 10 A0 E1 00 00 9F E5 ?? ?? ?? EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule setlinebuf_16b465632732a95f3127fc4e9dc392ad {
	meta:
		aliases = "setlinebuf"
		size = "16"
		objfiles = "setlinebuf@libc.a"
	strings:
		$pattern = { 00 10 A0 E3 01 20 A0 E3 01 30 A0 E1 ?? ?? ?? EA }
	condition:
		$pattern
}

rule atol_deef6c6063aa04a17c5a206f19cbcf02 {
	meta:
		aliases = "atoll, atoi, __GI_atol, __GI_atoi, atol"
		size = "12"
		objfiles = "atoll@libc.a, atol@libc.a"
	strings:
		$pattern = { 00 10 A0 E3 0A 20 A0 E3 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __GI_pthread_cond_broadcast_08952126cd41324e86caf0a4a8024c20 {
	meta:
		aliases = "pthread_cond_broadcast, __GI_pthread_cond_broadcast"
		size = "88"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { 00 10 A0 E3 F0 40 2D E9 01 50 A0 E1 00 40 A0 E1 ?? ?? ?? EB 08 60 94 E5 04 00 A0 E1 08 50 84 E5 ?? ?? ?? EB 05 70 A0 E1 01 50 85 E2 05 00 00 EA 08 40 96 E5 41 51 C6 E5 08 70 86 E5 06 00 A0 E1 ED FF FF EB 04 60 A0 E1 00 00 56 E3 F7 FF FF 1A 06 00 A0 E1 F0 80 BD E8 }
	condition:
		$pattern
}

rule mblen_21c1806717cd7a600665024838d49384 {
	meta:
		aliases = "mblen"
		size = "84"
		objfiles = "mblen@libc.a"
	strings:
		$pattern = { 00 20 50 E2 10 40 2D E9 03 00 00 1A 38 30 9F E5 02 00 A0 E1 00 20 83 E5 10 80 BD E8 00 30 D2 E5 00 00 53 E3 03 00 A0 01 10 80 BD 08 18 40 9F E5 04 20 A0 E1 ?? ?? ?? EB 02 00 70 E3 0C 30 9F 05 01 00 80 02 04 30 84 05 10 80 BD E8 ?? ?? ?? ?? FF FF 00 00 }
	condition:
		$pattern
}

rule __GI_atanh_e76d0f990370587ee08428e61f26bf21 {
	meta:
		aliases = "__ieee754_atanh, atanh, __GI_atanh"
		size = "408"
		objfiles = "e_atanh@libm.a"
	strings:
		$pattern = { 00 20 61 E2 F0 47 2D E9 01 20 82 E1 02 61 C0 E3 68 31 9F E5 A2 2F 86 E1 03 00 52 E1 00 80 A0 E1 01 90 A0 E1 01 40 A0 E1 00 A0 A0 E1 05 00 00 9A 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 03 00 00 EA 03 00 56 E1 03 00 00 1A 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? EB 42 00 00 EA 1C 31 9F E5 03 00 56 E1 07 00 00 CA 14 21 9F E5 14 31 9F E5 ?? ?? ?? EB 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? EB 00 00 50 E3 39 00 00 CA FC 20 9F E5 02 00 56 E1 06 80 A0 E1 1B 00 00 CA 06 20 A0 E1 09 30 A0 E1 06 00 A0 E1 09 10 A0 E1 ?? ?? ?? EB 08 20 A0 E1 09 30 A0 E1 00 60 A0 E1 01 70 A0 E1 ?? ?? ?? EB 08 20 A0 E1 }
	condition:
		$pattern
}

rule __GI_wcsnlen_3210d24187de1efb9bd3e9b821d67e96 {
	meta:
		aliases = "wcsnlen, __GI_wcsnlen"
		size = "48"
		objfiles = "wcsnlen@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 00 00 00 EA 04 00 80 E2 00 00 51 E3 01 10 41 E2 02 00 00 0A 00 30 90 E5 00 00 53 E3 F8 FF FF 1A 00 00 62 E0 40 01 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule wcslen_e93167656d8b830e0911230b22cf29ec {
	meta:
		aliases = "__GI_wcslen, wcslen"
		size = "36"
		objfiles = "wcslen@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 00 00 00 EA 04 00 80 E2 00 30 90 E5 00 00 53 E3 FB FF FF 1A 00 00 62 E0 40 01 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule wcscmp_a3b541edbf35adc36810dbf35431bc47 {
	meta:
		aliases = "__GI_wcscmp, wcscoll, __GI_wcscoll, wcscmp"
		size = "52"
		objfiles = "wcscmp@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 01 00 00 EA 00 00 50 E3 0E F0 A0 01 00 00 92 E5 00 30 91 E5 03 00 50 E1 04 20 82 E2 04 10 81 E2 F7 FF FF 0A 00 00 E0 33 01 00 A0 23 0E F0 A0 E1 }
	condition:
		$pattern
}

rule strcpy_add200a8cd676cf7c447f2cceddef1da {
	meta:
		aliases = "__GI_strcpy, strcpy"
		size = "36"
		objfiles = "strcpy@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 01 00 00 EA 01 10 81 E2 01 20 82 E2 00 30 D1 E5 00 00 53 E3 00 30 C2 E5 F9 FF FF 1A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_exp2_3a1cca57f723b7c96aea9aacaf2b9ce9 {
	meta:
		aliases = "exp2, __GI_exp2"
		size = "20"
		objfiles = "w_exp2@libm.a"
	strings:
		$pattern = { 00 20 A0 E1 01 30 A0 E1 01 01 A0 E3 00 10 A0 E3 ?? ?? ?? EA }
	condition:
		$pattern
}

rule strcat_b63f573c56518f74126d0772da1ace16 {
	meta:
		aliases = "__GI_strcat, strcat"
		size = "40"
		objfiles = "strcat@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 01 30 D2 E4 00 00 53 E3 FC FF FF 1A 02 20 42 E2 01 30 D1 E4 00 00 53 E3 01 30 E2 E5 FB FF FF 1A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule wcscpy_60b1f0d2c1c9e9c2f1ebb68525f00d5a {
	meta:
		aliases = "wcscpy"
		size = "24"
		objfiles = "wcscpy@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 04 30 91 E4 00 00 53 E3 04 30 82 E4 FB FF FF 1A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule wcscat_85260f4a56dae149f3ebc845e5e338c9 {
	meta:
		aliases = "__GI_wcscat, wcscat"
		size = "40"
		objfiles = "wcscat@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 04 30 92 E4 00 00 53 E3 FC FF FF 1A 04 20 42 E2 04 30 91 E4 00 00 53 E3 04 30 82 E4 FB FF FF 1A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_wcspbrk_060c54492cfae5f406bc497e2cb4a9cb {
	meta:
		aliases = "wcspbrk, __GI_wcspbrk"
		size = "64"
		objfiles = "wcspbrk@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 08 00 00 EA 00 00 5C E1 01 00 00 1A 02 00 A0 E1 0E F0 A0 E1 00 C0 93 E5 00 00 5C E3 04 30 83 E2 F7 FF FF 1A 04 20 82 E2 00 00 92 E5 00 00 50 E3 0E F0 A0 01 01 30 A0 E1 F5 FF FF EA }
	condition:
		$pattern
}

rule strpbrk_7cef120fdbb5f26a5322dd28e6c78540 {
	meta:
		aliases = "__GI_strpbrk, strpbrk"
		size = "64"
		objfiles = "strpbrk@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 08 00 00 EA 00 00 5C E1 01 00 00 1A 02 00 A0 E1 0E F0 A0 E1 00 C0 D3 E5 00 00 5C E3 01 30 83 E2 F7 FF FF 1A 01 20 82 E2 00 00 D2 E5 00 00 50 E3 0E F0 A0 01 01 30 A0 E1 F5 FF FF EA }
	condition:
		$pattern
}

rule reboot_602ed1ac94032b250d8c325bf86724d6 {
	meta:
		aliases = "reboot"
		size = "64"
		objfiles = "reboot@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 10 40 2D E9 28 00 9F E5 28 10 9F E5 58 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 AD DE E1 FE 69 19 12 28 }
	condition:
		$pattern
}

rule __mulvsi3_1a0b9e2acad18ba4ad7ce1c98a4e9f5a {
	meta:
		aliases = "__mulvsi3"
		size = "44"
		objfiles = "_mulvsi3@libgcc.a"
	strings:
		$pattern = { 00 20 A0 E1 C2 3F A0 E1 10 40 2D E9 01 00 A0 E1 C0 1F A0 E1 ?? ?? ?? EB C0 2F A0 E1 01 00 52 E1 C1 4F A0 E1 10 80 BD 08 ?? ?? ?? EB }
	condition:
		$pattern
}

rule ntohl_f0439868045060aec9db8c8f877016ab {
	meta:
		aliases = "__GI_ntohl, __GI_htonl, htonl, ntohl"
		size = "32"
		objfiles = "ntohl@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 FF 38 00 E2 20 0C A0 E1 23 04 80 E1 FF 3C 02 E2 03 04 80 E1 02 0C 80 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule wait_db69692a147d487f1320fb8548949b2b {
	meta:
		aliases = "__libc_wait, wait"
		size = "20"
		objfiles = "wait@libc.a"
	strings:
		$pattern = { 00 20 A0 E3 00 10 A0 E1 02 30 A0 E1 00 00 E0 E3 ?? ?? ?? EA }
	condition:
		$pattern
}

rule wcsrchr_1a3407bde646679fbfeb7a2b6b1838ca {
	meta:
		aliases = "wcsrchr"
		size = "36"
		objfiles = "wcsrchr@libc.a"
	strings:
		$pattern = { 00 20 A0 E3 00 30 90 E5 01 00 53 E1 00 20 A0 01 00 00 53 E3 04 00 80 E2 F9 FF FF 1A 02 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_fopen_4ce1a249bb60e6f00ba2676db9d4be65 {
	meta:
		aliases = "fopen, __GI_fopen"
		size = "12"
		objfiles = "fopen@libc.a"
	strings:
		$pattern = { 00 20 A0 E3 00 30 E0 E3 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __GI_fopen64_d73e744ca7841fca2d43bd74ed252036 {
	meta:
		aliases = "fopen64, __GI_fopen64"
		size = "12"
		objfiles = "fopen64@libc.a"
	strings:
		$pattern = { 00 20 A0 E3 01 30 E0 E3 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __clear_cache_d143ac68a659d80e86fffabc368102e6 {
	meta:
		aliases = "__clear_cache"
		size = "12"
		objfiles = "_clear_cache@libgcc.a"
	strings:
		$pattern = { 00 20 A0 E3 02 00 9F EF 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __register_frame_info_42a437b0df72df8e349f8fa90b1035e6 {
	meta:
		aliases = "__register_frame_info_table, __register_frame_info"
		size = "12"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { 00 20 A0 E3 02 30 A0 E1 ?? ?? ?? EA }
	condition:
		$pattern
}

rule sigwaitinfo_0b77e5f70c250670cebdfc40eedc30a9 {
	meta:
		aliases = "__GI_sigwaitinfo, sigwaitinfo"
		size = "12"
		objfiles = "__rt_sigtimedwait@libc.a"
	strings:
		$pattern = { 00 20 A0 E3 08 30 A0 E3 EF FF FF EA }
	condition:
		$pattern
}

rule vwarnx_cef0584fafe4a59a3080816a940a5713 {
	meta:
		aliases = "__GI_vwarnx, vwarnx"
		size = "8"
		objfiles = "err@libc.a"
	strings:
		$pattern = { 00 20 A0 E3 BF FF FF EA }
	condition:
		$pattern
}

rule __decode_header_42fdbcbf76e07558ba9b3191853d6046 {
	meta:
		aliases = "__decode_header"
		size = "180"
		objfiles = "decodeh@libc.a"
	strings:
		$pattern = { 00 20 D0 E5 01 30 D0 E5 02 34 83 E1 00 30 81 E5 02 30 D0 E5 A3 33 A0 E1 04 30 81 E5 02 30 D0 E5 A3 31 A0 E1 0F 30 03 E2 08 30 81 E5 02 30 D0 E5 23 31 A0 E1 01 30 03 E2 0C 30 81 E5 02 30 D0 E5 A3 30 A0 E1 01 30 03 E2 10 30 81 E5 02 30 D0 E5 01 30 03 E2 14 30 81 E5 03 30 D0 E5 A3 33 A0 E1 18 30 81 E5 03 30 D0 E5 0F 30 03 E2 1C 30 81 E5 04 20 D0 E5 05 30 D0 E5 02 34 83 E1 20 30 81 E5 06 20 D0 E5 07 30 D0 E5 02 34 83 E1 24 30 81 E5 08 20 D0 E5 09 30 D0 E5 02 34 83 E1 28 30 81 E5 0B 30 D0 E5 0A 20 D0 E5 02 34 83 E1 2C 30 81 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule sigismember_fd9ce6819bfc06c14eb42fa50fbc768c {
	meta:
		aliases = "sigdelset, __GI_sigaddset, __GI_sigdelset, sigaddset, sigismember"
		size = "48"
		objfiles = "sigismem@libc.a, sigaddset@libc.a, sigdelset@libc.a"
	strings:
		$pattern = { 00 30 51 E2 04 E0 2D E5 03 00 00 DA 40 00 53 E3 01 00 00 CA 04 E0 9D E4 ?? ?? ?? EA ?? ?? ?? EB 16 30 A0 E3 00 30 80 E5 00 00 E0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule sched_getaffinity_07c4548773fc431ff2e3a8874dc58f2c {
	meta:
		aliases = "sched_getaffinity"
		size = "96"
		objfiles = "sched_getaffinity@libc.a"
	strings:
		$pattern = { 00 30 51 E2 10 40 2D E9 03 10 A0 A1 02 11 E0 B3 02 C0 A0 E1 F2 00 90 EF 01 0A 70 E3 00 40 A0 E1 04 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 40 E0 E3 00 30 80 E5 01 00 00 EA 01 00 70 E3 01 00 00 1A 04 00 A0 E1 10 80 BD E8 03 20 60 E0 00 10 A0 E3 00 00 8C E0 ?? ?? ?? EB 00 00 A0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __ctzsi2_b9eae1bcd95396befabfbfbc8381348e {
	meta:
		aliases = "__ctzsi2"
		size = "104"
		objfiles = "_ctzsi2@libgcc.a"
	strings:
		$pattern = { 00 30 60 E2 00 20 03 E0 01 08 52 E3 09 00 00 2A FF 00 52 E3 08 30 A0 83 00 30 A0 93 32 33 A0 E1 3C 20 9F E5 03 00 D2 E7 07 10 A0 83 00 10 E0 93 01 00 80 E0 0E F0 A0 E1 FF 34 E0 E3 03 00 52 E1 18 30 A0 83 10 30 A0 93 32 33 A0 E1 10 20 9F E5 03 00 D2 E7 17 10 A0 83 0F 10 A0 93 01 00 80 E0 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __isnan_ceddce4d7f6c178fd2a81f23e2807caf {
	meta:
		aliases = "__GI___isnan, __isnan"
		size = "32"
		objfiles = "s_isnan@libm.a"
	strings:
		$pattern = { 00 30 61 E2 01 30 83 E1 02 01 C0 E3 A3 0F 80 E1 7F 04 60 E2 0F 06 80 E2 A0 0F A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule xdrmem_create_37ac29726ffac9c17b31bbf448e9ac26 {
	meta:
		aliases = "__GI_xdrmem_create, xdrmem_create"
		size = "32"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { 00 30 80 E5 10 30 9F E5 14 20 80 E5 04 30 80 E5 0C 10 80 E5 10 10 80 E5 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __deregister_frame_11f0f5c0f161c79073a307772e860016 {
	meta:
		aliases = "__deregister_frame"
		size = "28"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { 00 30 90 E5 00 00 53 E3 04 E0 2D E5 04 F0 9D 04 ?? ?? ?? EB 04 E0 9D E4 ?? ?? ?? EA }
	condition:
		$pattern
}

rule cfgetispeed_3a42fb4ca6ca5dae9ddc05c5a4b61608 {
	meta:
		aliases = "cfgetispeed"
		size = "32"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { 00 30 90 E5 00 00 53 E3 08 30 90 A5 08 00 9F A5 00 00 A0 B3 00 00 03 A0 0E F0 A0 E1 0F 10 00 00 }
	condition:
		$pattern
}

rule __register_frame_638b84ede3c8599a477931931c48c68f {
	meta:
		aliases = "__register_frame"
		size = "44"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { 00 30 90 E5 00 00 53 E3 10 40 2D E9 00 40 A0 E1 10 80 BD 08 18 00 A0 E3 ?? ?? ?? EB 00 10 A0 E1 04 00 A0 E1 10 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __malloc_consolidate_ca3c7d45ca7cb1a5c793535170c28520 {
	meta:
		aliases = "__malloc_consolidate"
		size = "424"
		objfiles = "free@libc.a"
	strings:
		$pattern = { 00 30 90 E5 00 00 53 E3 F0 4F 2D E9 01 20 A0 03 00 40 A0 E1 48 00 00 0A 02 30 C3 E3 A3 21 A0 E1 00 30 80 E5 04 30 40 E2 02 91 83 E0 34 70 80 E2 04 60 80 E2 00 B0 A0 E3 00 10 96 E5 00 00 51 E3 39 00 00 0A 00 B0 86 E5 04 30 91 E5 01 E0 C3 E3 0E 00 81 E0 01 00 13 E3 08 A0 91 E5 04 80 90 E5 0C 00 00 1A 00 50 91 E5 01 30 65 E0 08 C0 93 E5 0C 10 9C E5 03 00 51 E1 0C 20 93 E5 16 00 00 1A 08 30 92 E5 01 00 53 E1 13 00 00 1A 08 C0 82 E5 0C 20 8C E5 05 E0 8E E0 2C 30 94 E5 03 00 50 E1 03 50 C8 E3 19 00 00 0A 05 30 80 E0 04 30 93 E5 01 00 13 E3 04 50 80 E5 0B 00 00 1A 08 C0 90 E5 0C 30 9C E5 00 00 53 E1 }
	condition:
		$pattern
}

rule __GI_pthread_attr_getdetachsta_0b416f364d729a7dc563889c583f0308 {
	meta:
		aliases = "__pthread_mutexattr_gettype, pthread_mutexattr_gettype, pthread_rwlockattr_getkind_np, pthread_mutexattr_getkind_np, __pthread_mutexattr_getkind_np, pthread_attr_getdetachstate, __GI_pthread_attr_getdetachstate"
		size = "16"
		objfiles = "attr@libpthread.a, mutex@libpthread.a, rwlock@libpthread.a"
	strings:
		$pattern = { 00 30 90 E5 00 00 A0 E3 00 30 81 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule uw_update_context_dda1628ae176658f9a59a09417a908a8 {
	meta:
		aliases = "uw_update_context"
		size = "16"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { 00 30 90 E5 00 20 93 E5 00 20 80 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __old_sem_destroy_21806e720edf9685a54093b7f5907dc2 {
	meta:
		aliases = "__old_sem_destroy"
		size = "40"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { 00 30 90 E5 01 00 13 E3 04 E0 2D E5 00 00 A0 13 04 F0 9D 14 ?? ?? ?? EB 10 30 A0 E3 00 30 80 E5 00 00 E0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule _Unwind_SetIP_39c401ad514acf6b3badef9bf4d81e7a {
	meta:
		aliases = "_Unwind_SetIP"
		size = "16"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { 00 30 90 E5 01 10 41 E2 04 10 83 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule _Unwind_GetGR_21bd919f8185f4dceee4c1a78d855417 {
	meta:
		aliases = "_Unwind_GetGR"
		size = "20"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { 00 30 90 E5 01 11 A0 E1 03 10 81 E0 08 00 91 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule _Unwind_SetGR_1f5004d588e688dbd2aeaa09f17b8cb7 {
	meta:
		aliases = "_Unwind_SetGR"
		size = "20"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { 00 30 90 E5 01 11 A0 E1 03 10 81 E0 08 20 81 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule next_fde_3fd3e7f7d53743d2b0175d45d9ecf956 {
	meta:
		aliases = "next_fde"
		size = "16"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { 00 30 90 E5 03 00 80 E0 04 00 80 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule _Unwind_GetIP_ef0e0b7ba0ac0f6748f3518e0d3fec34 {
	meta:
		aliases = "_Unwind_GetIP"
		size = "16"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { 00 30 90 E5 04 00 93 E5 01 00 80 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule clearerr_unlocked_7534914d58871fcead28a1623e10ecb9 {
	meta:
		aliases = "clearerr_unlocked"
		size = "24"
		objfiles = "clearerr_unlocked@libc.a"
	strings:
		$pattern = { 00 30 90 E5 0C 30 C3 E3 43 24 A0 E1 01 20 C0 E5 00 30 C0 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule _Unwind_GetLanguageSpecificDat_9e043d4db733426f631d3fc3ac25a9e1 {
	meta:
		aliases = "_Unwind_GetLanguageSpecificData"
		size = "12"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { 00 30 90 E5 1C 00 93 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule insque_5d633a27a9b3c35568edf14a0cbc8f30 {
	meta:
		aliases = "insque"
		size = "28"
		objfiles = "insque@libc.a"
	strings:
		$pattern = { 00 30 91 E5 00 00 53 E3 00 00 81 E5 04 00 83 15 04 10 80 E5 00 30 80 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI___cmsg_nxthdr_14dbef565c49e62ddfeaf9ff2dd4382e {
	meta:
		aliases = "__cmsg_nxthdr, __GI___cmsg_nxthdr"
		size = "80"
		objfiles = "cmsg_nxthdr@libc.a"
	strings:
		$pattern = { 00 30 91 E5 0B 00 53 E3 0E 00 00 9A 03 30 83 E2 03 20 C3 E3 10 30 80 E2 08 10 93 E8 0C C0 83 E0 02 00 81 E0 0C 30 80 E2 0C 00 53 E1 05 00 00 8A 02 30 91 E7 03 30 83 E2 03 30 C3 E3 03 30 80 E0 0C 00 53 E1 0E F0 A0 91 00 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule sigandset_2653ee75bc08d4f8df25f2fc7ef7cd0b {
	meta:
		aliases = "sigandset"
		size = "40"
		objfiles = "sigandset@libc.a"
	strings:
		$pattern = { 00 30 92 E5 00 C0 91 E5 0C 30 03 E0 00 30 80 E5 04 30 92 E5 04 20 91 E5 02 30 03 E0 04 30 80 E5 00 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule sigorset_457f4c2ed749566ce2169fbae321d8f4 {
	meta:
		aliases = "sigorset"
		size = "40"
		objfiles = "sigorset@libc.a"
	strings:
		$pattern = { 00 30 92 E5 00 C0 91 E5 0C 30 83 E1 00 30 80 E5 04 30 92 E5 04 20 91 E5 02 30 83 E1 04 30 80 E5 00 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule wmemset_a8d9869701210366ad883fee87e1631d {
	meta:
		aliases = "wmemset"
		size = "28"
		objfiles = "wmemset@libc.a"
	strings:
		$pattern = { 00 30 A0 E1 00 00 00 EA 04 10 83 E4 00 00 52 E3 01 20 42 E2 FB FF FF 1A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule wcschr_e0cc41bce344a692a5589cd22d4b9944 {
	meta:
		aliases = "__GI_wcschr, wcschr"
		size = "40"
		objfiles = "wcschr@libc.a"
	strings:
		$pattern = { 00 30 A0 E1 00 00 93 E5 01 00 50 E1 01 00 00 1A 03 00 A0 E1 0E F0 A0 E1 00 00 50 E3 04 30 83 E2 F7 FF FF 1A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule sigemptyset_9439624d8943723f7245d918097c6c83 {
	meta:
		aliases = "pthread_rwlockattr_init, __GI_sigemptyset, sigemptyset"
		size = "20"
		objfiles = "sigempty@libc.a, rwlock@libpthread.a"
	strings:
		$pattern = { 00 30 A0 E1 00 00 A0 E3 04 00 83 E5 00 00 83 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_pthread_cond_init_1298c2975efe4d6b34adc1cbd7b4bb65 {
	meta:
		aliases = "pthread_cond_init, __GI_pthread_cond_init"
		size = "24"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { 00 30 A0 E1 00 00 A0 E3 08 00 83 E5 00 00 83 E5 04 00 83 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule wcsncmp_5b17c2318d296822cab8f0f852e711ef {
	meta:
		aliases = "wcsncmp"
		size = "68"
		objfiles = "wcsncmp@libc.a"
	strings:
		$pattern = { 00 30 A0 E1 01 00 00 EA 00 00 50 E3 0E F0 A0 01 00 00 52 E3 01 00 00 1A 02 00 A0 E1 0E F0 A0 E1 00 00 93 E5 00 C0 91 E5 0C 00 50 E1 04 30 83 E2 04 10 81 E2 01 20 42 E2 F2 FF FF 0A 00 00 6C E0 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_basename_c7fc359c5fb109855bedf5da890bbcdb {
	meta:
		aliases = "basename, __GI_basename"
		size = "36"
		objfiles = "basename@libc.a"
	strings:
		$pattern = { 00 30 A0 E1 01 00 00 EA 2F 00 52 E3 03 00 A0 01 00 20 D3 E5 00 00 52 E3 01 30 83 E2 F9 FF FF 1A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule memset_d4150aabf3383fe094ac3522ab7afc96 {
	meta:
		aliases = "__GI_memset, memset"
		size = "156"
		objfiles = "memset@libc.a"
	strings:
		$pattern = { 00 30 A0 E1 08 00 52 E3 16 00 00 BA 01 14 81 E1 01 18 81 E1 03 00 13 E3 01 10 C3 14 01 20 42 12 FB FF FF 1A 01 C0 A0 E1 08 00 52 E3 0D 00 00 BA 02 10 A3 E8 08 20 42 E2 08 00 52 E3 09 00 00 BA 02 10 A3 E8 08 20 42 E2 08 00 52 E3 05 00 00 BA 02 10 A3 E8 08 20 42 E2 08 00 52 E3 02 10 A3 A8 08 20 42 A2 EF FF FF AA 02 20 B0 E1 0E F0 A0 01 07 20 62 E2 02 F1 8F E0 00 00 A0 E1 01 10 C3 E4 01 10 C3 E4 01 10 C3 E4 01 10 C3 E4 01 10 C3 E4 01 10 C3 E4 01 10 C3 E4 0E F0 A0 E1 }
	condition:
		$pattern
}

rule timer_delete_00535ba9b86cb122be7bae3c4347f067 {
	meta:
		aliases = "timer_delete"
		size = "80"
		objfiles = "timer_delete@librt.a"
	strings:
		$pattern = { 00 30 A0 E1 10 40 2D E9 04 00 90 E5 05 01 90 EF 01 0A 70 E3 00 40 A0 E1 04 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 20 E0 E3 00 30 80 E5 05 00 00 EA 00 00 50 E3 00 20 E0 13 02 00 00 1A 03 00 A0 E1 ?? ?? ?? EB 04 20 A0 E1 02 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule _Unwind_GetIPInfo_cf14e707d912f1c77fbb43a4c3f3ad55 {
	meta:
		aliases = "_Unwind_GetIPInfo"
		size = "24"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { 00 30 A0 E3 00 30 81 E5 00 20 90 E5 04 00 92 E5 01 00 80 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __floatunsisf_8bdab7fc7baffea2941b8641de057444 {
	meta:
		aliases = "__aeabi_ui2f, __floatunsisf"
		size = "40"
		objfiles = "_addsubsf3@libgcc.a"
	strings:
		$pattern = { 00 30 A0 E3 01 00 00 EA 02 31 10 E2 00 00 60 42 00 C0 B0 E1 0E F0 A0 01 4B 34 83 E3 00 10 A0 E1 00 00 A0 E3 0F 00 00 EA }
	condition:
		$pattern
}

rule __pthread_unlock_05b09f32ebc85964349f671f0138a1b9 {
	meta:
		aliases = "__pthread_unlock"
		size = "16"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { 00 30 A0 E3 04 30 80 E5 03 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_rwlock_init_1622592b34c8071bb94f9ae90df2692d {
	meta:
		aliases = "pthread_rwlock_init"
		size = "68"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { 00 30 A0 E3 04 30 80 E5 08 30 80 E5 00 00 51 E3 14 30 80 E5 00 30 80 E5 0C 30 80 E5 10 30 80 E5 00 30 91 15 18 30 80 15 04 30 91 15 01 30 83 02 1C 10 80 05 18 30 80 05 1C 30 80 15 00 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __pthread_mutex_init_f51f2006628a104d31f0c341d4792e9e {
	meta:
		aliases = "pthread_mutex_init, __pthread_mutex_init"
		size = "48"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { 00 30 A0 E3 14 30 80 E5 00 00 51 E3 00 10 91 15 00 20 A0 E1 10 30 80 E5 03 10 A0 03 00 00 A0 E3 0C 10 82 E5 08 00 82 E5 04 00 82 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __init_scan_cookie_f2a9be1f07f0e3348b100a785fc8e0c3 {
	meta:
		aliases = "__init_scan_cookie"
		size = "84"
		objfiles = "__scan_cookie@libc.a"
	strings:
		$pattern = { 00 30 A0 E3 19 30 C0 E5 08 10 80 E5 0C 30 80 E5 00 30 D1 E5 02 30 13 E2 28 C0 91 15 03 C0 A0 01 28 10 9F E5 2E 30 A0 E3 00 20 A0 E3 38 30 80 E5 01 30 A0 E3 14 C0 80 E5 1B 20 C0 E5 3C 10 80 E5 34 30 80 E5 1A 20 C0 E5 30 10 80 E5 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __fpending_d6f8bd4727e067720d97f3afeee8686b {
	meta:
		aliases = "__fpending"
		size = "28"
		objfiles = "__fpending@libc.a"
	strings:
		$pattern = { 00 30 D0 E5 40 30 13 E2 08 20 90 15 10 30 90 15 03 00 A0 01 03 00 62 10 0E F0 A0 E1 }
	condition:
		$pattern
}

rule crypt_c551b1cc7c92945a7a0b940112d2bfd7 {
	meta:
		aliases = "crypt"
		size = "60"
		objfiles = "crypt@libcrypt.a"
	strings:
		$pattern = { 00 30 D1 E5 24 00 53 E3 01 20 A0 E1 00 C0 A0 E1 06 00 00 1A 01 30 D1 E5 31 00 53 E3 03 00 00 1A 02 30 D1 E5 24 00 53 E3 00 00 00 1A ?? ?? ?? EA 0C 00 A0 E1 02 10 A0 E1 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __GI_sigfillset_74f67f0944c9b2a683489503e59fffd2 {
	meta:
		aliases = "sigfillset, __GI_sigfillset"
		size = "20"
		objfiles = "sigfillset@libc.a"
	strings:
		$pattern = { 00 30 E0 E3 04 30 80 E5 00 30 80 E5 00 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_htons_558f6a9dc3f01601f002ce7596af1acf {
	meta:
		aliases = "ntohs, __GI_ntohs, htons, __GI_htons"
		size = "20"
		objfiles = "ntohl@libc.a"
	strings:
		$pattern = { 00 38 A0 E1 23 04 A0 E1 FF 0C 00 E2 23 0C 80 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_ffs_8918bf46bc0226922438e003d2d934e0 {
	meta:
		aliases = "ffs, __GI_ffs"
		size = "92"
		objfiles = "ffs@libc.a"
	strings:
		$pattern = { 00 38 A0 E1 23 38 A0 E1 00 00 53 E3 40 08 A0 01 01 20 A0 13 11 20 A0 03 FF 00 10 E3 08 30 82 02 40 04 A0 01 FF 20 03 02 0F 00 10 E3 04 30 82 02 40 02 A0 01 FF 20 03 02 03 00 10 E3 02 30 82 02 40 01 A0 01 FF 20 03 02 00 00 50 E3 01 30 80 12 01 30 03 12 02 00 83 10 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_cancel_a2c14988801e29b7e0259d63fc2cf0c2 {
	meta:
		aliases = "pthread_cancel"
		size = "240"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { 00 3B A0 E1 DC 20 9F E5 23 3B A0 E1 F0 40 2D E9 03 62 82 E0 00 50 A0 E1 00 10 A0 E3 06 00 A0 E1 ?? ?? ?? EB 08 40 96 E5 00 00 54 E3 02 00 00 0A 10 30 94 E5 05 00 53 E1 1F 00 00 0A 06 00 A0 E1 ?? ?? ?? EB 03 00 A0 E3 F0 80 BD E8 06 00 A0 E1 ?? ?? ?? EB 10 00 00 EA 44 31 94 E5 00 00 53 E3 14 70 94 E5 03 50 A0 01 05 00 00 0A 00 00 93 E5 04 10 A0 E1 0F E0 A0 E1 04 F0 93 E5 40 01 C4 E5 00 50 A0 E1 06 00 A0 E1 ?? ?? ?? EB 00 00 55 E3 03 00 00 0A 04 00 A0 E1 ?? ?? ?? EB 00 00 A0 E3 F0 80 BD E8 40 30 9F E5 07 00 A0 E1 00 10 93 E5 ?? ?? ?? EB 05 00 A0 E1 F0 80 BD E8 42 30 D4 E5 40 20 D4 E5 00 30 53 E2 }
	condition:
		$pattern
}

rule __GI_verr_861c9e3ef51d49fd16dd2857e7a2f968 {
	meta:
		aliases = "__GI_verrx, verrx, verr, __GI_verr"
		size = "24"
		objfiles = "err@libc.a"
	strings:
		$pattern = { 00 40 A0 E1 01 00 A0 E1 02 10 A0 E1 ?? ?? ?? EB 04 00 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule pthread_start_thread_event_58ff076ad19116079601b73d38d32217 {
	meta:
		aliases = "pthread_start_thread_event"
		size = "40"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { 00 40 A0 E1 ?? ?? ?? EB 00 10 A0 E3 14 00 84 E5 1C 00 94 E5 ?? ?? ?? EB 1C 00 94 E5 ?? ?? ?? EB 04 00 A0 E1 BE FF FF EB }
	condition:
		$pattern
}

rule __GI__exit_9b20eaf9fd17ab39a318799c6d286209 {
	meta:
		aliases = "_Exit, _exit, __GI__exit"
		size = "40"
		objfiles = "_exit@libc.a"
	strings:
		$pattern = { 00 50 A0 E1 05 00 A0 E1 01 00 90 EF 01 0A 70 E3 00 40 A0 E1 FA FF FF 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 F6 FF FF EA }
	condition:
		$pattern
}

rule _start_6e6e18ae42c1856a6c3448205f001dd1 {
	meta:
		aliases = "_start"
		size = "60"
		objfiles = "crt1"
	strings:
		$pattern = { 00 B0 A0 E3 00 E0 A0 E3 04 10 9D E4 0D 20 A0 E1 04 20 2D E5 04 00 2D E5 10 C0 9F E5 04 C0 2D E5 0C 00 9F E5 0C 30 9F E5 ?? ?? ?? EA ?? ?? ?? EB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _start_3a400b12bcb868b3ded6fd3bbdd60fbd {
	meta:
		aliases = "_start"
		size = "84"
		objfiles = "Scrt1"
	strings:
		$pattern = { 00 B0 A0 E3 00 E0 A0 E3 04 10 9D E4 0D 20 A0 E1 04 20 2D E5 04 00 2D E5 24 A0 9F E5 0A A0 8F E0 20 C0 9F E5 0C 00 9A E7 04 00 2D E5 18 C0 9F E5 0C 30 9A E7 14 C0 9F E5 0C 00 9A E7 ?? ?? ?? ?? ?? ?? ?? EB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mbtowc_e50add70aff8dd88f173b454f08462d2 {
	meta:
		aliases = "mbtowc"
		size = "84"
		objfiles = "mbtowc@libc.a"
	strings:
		$pattern = { 00 C0 51 E2 10 40 2D E9 03 00 00 1A 38 30 9F E5 0C 00 A0 E1 00 C0 83 E5 10 80 BD E8 00 30 DC E5 00 00 53 E3 03 00 A0 01 10 80 BD 08 18 40 9F E5 04 30 A0 E1 ?? ?? ?? EB 02 00 70 E3 0C 30 9F 05 01 00 80 02 04 30 84 05 10 80 BD E8 ?? ?? ?? ?? FF FF 00 00 }
	condition:
		$pattern
}

rule xdr_opaque_dcaddd92dcf01ba682b7f2f60dd9d332 {
	meta:
		aliases = "__GI_xdr_opaque, xdr_opaque"
		size = "200"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { 00 C0 52 E2 30 40 2D E9 00 40 A0 E1 27 00 00 0A 00 30 90 E5 03 20 1C E2 02 50 A0 01 04 50 62 12 01 00 53 E3 03 00 00 0A 11 00 00 3A 02 00 53 E3 20 00 00 1A 1D 00 00 EA 0C 20 A0 E1 04 30 90 E5 0F E0 A0 E1 08 F0 93 E5 00 00 50 E3 19 00 00 0A 00 00 55 E3 15 00 00 0A 04 00 A0 E1 05 20 A0 E1 04 30 94 E5 54 10 9F E5 0F E0 A0 E1 08 F0 93 E5 30 80 BD E8 0C 20 A0 E1 04 30 90 E5 0F E0 A0 E1 0C F0 93 E5 00 00 50 E3 0A 00 00 0A 00 00 55 E3 06 00 00 0A 04 00 A0 E1 05 20 A0 E1 04 30 94 E5 1C 10 9F E5 0F E0 A0 E1 0C F0 93 E5 30 80 BD E8 01 00 A0 E3 30 80 BD E8 00 00 A0 E3 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule end_fde_sort_a2acf7e5f8718cfc5a7bbef74af2c8c1 {
	meta:
		aliases = "end_fde_sort"
		size = "240"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { 00 C0 91 E5 00 00 5C E3 F0 40 2D E9 01 40 A0 E1 00 50 A0 E1 02 70 A0 E1 02 00 00 0A 04 30 9C E5 02 00 53 E1 2D 00 00 1A 10 30 D5 E5 04 00 13 E3 AC 60 9F 15 18 00 00 0A 04 30 94 E5 00 00 53 E3 21 00 00 0A 0C 20 A0 E1 05 00 A0 E1 06 10 A0 E1 5B FC FF EB 04 00 94 E5 00 30 94 E5 04 20 90 E5 04 10 93 E5 01 20 82 E0 07 00 52 E1 1B 00 00 1A 00 20 A0 E1 06 10 A0 E1 05 00 A0 E1 D5 FC FF EB 05 00 A0 E1 06 10 A0 E1 0C 00 94 E8 F8 FC FF EB 04 00 94 E5 F0 40 BD E8 ?? ?? ?? EA 10 30 95 E5 07 30 C3 E3 83 3A A0 E1 A3 3A A0 E1 00 00 53 E3 30 10 9F E5 30 20 9F E5 04 30 94 E5 01 60 A0 11 02 60 A0 01 00 00 53 E3 }
	condition:
		$pattern
}

rule byte_compile_range_0a4024fc6daace9967c33d93285e9774 {
	meta:
		aliases = "byte_compile_range"
		size = "188"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 00 C0 91 E5 F0 40 2D E9 02 00 5C E1 14 E0 9D E5 03 20 A0 E1 18 60 9D E5 0B E0 A0 03 24 00 00 0A 01 30 8C E2 00 30 81 E5 01 E8 1E E2 00 10 DC E5 0B E0 A0 13 00 00 52 E3 FF 30 00 12 03 00 D2 17 01 40 D2 17 01 40 A0 01 01 50 A0 E3 00 70 A0 E3 15 00 00 EA FF 30 00 E2 00 00 52 E3 03 30 D2 17 A3 C1 A0 01 C3 C1 A0 11 FF 30 00 E2 00 00 52 E3 03 30 D2 17 A3 31 A0 01 C3 31 A0 11 00 00 52 E3 03 10 D6 E7 FF 30 00 12 03 30 D2 17 07 30 00 02 07 30 03 12 15 33 A0 E1 FF 30 03 E2 01 30 83 E1 0C 30 C6 E7 01 00 80 E2 07 E0 A0 E1 04 00 50 E1 E7 FF FF 9A 0E 00 A0 E1 F0 80 BD E8 }
	condition:
		$pattern
}

rule skip_af03b27d080030f7ddb5e0d8951bf44f {
	meta:
		aliases = "skip"
		size = "196"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { 00 C0 A0 E1 00 10 A0 E3 26 00 00 EA 22 00 52 E3 01 10 21 02 22 00 00 0A 01 00 51 E3 04 00 00 1A 5C 00 52 E3 02 00 00 1A 01 30 D0 E5 22 00 53 E3 01 00 80 02 00 30 D0 E5 01 00 51 E3 01 30 CC E4 17 00 00 0A 23 00 52 E3 70 30 9F 05 00 20 C3 05 00 30 A0 03 00 30 C0 05 15 00 00 0A 20 00 52 E3 09 00 52 13 01 00 00 0A 0A 00 52 E3 0C 00 00 1A 48 30 9F E5 00 20 C3 E5 00 30 A0 E3 01 30 C0 E4 00 00 00 EA 01 00 80 E2 00 30 D0 E5 09 00 53 E3 FB FF FF 0A 0A 00 53 E3 20 00 53 13 F8 FF FF 0A 03 00 00 EA 01 00 80 E2 00 20 D0 E5 00 00 52 E3 D5 FF FF 1A 00 30 A0 E3 01 30 4C E5 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_wmemcpy_05e1fc694e6e983a9914aa6330c39d8e {
	meta:
		aliases = "wmemcpy, __GI_wmemcpy"
		size = "32"
		objfiles = "wmemcpy@libc.a"
	strings:
		$pattern = { 00 C0 A0 E1 01 00 00 EA 04 30 91 E4 04 30 8C E4 00 00 52 E3 01 20 42 E2 FA FF FF 1A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __aeabi_cfrcmple_68e11b29bca5218f6bdb59a1dc5fa473 {
	meta:
		aliases = "__aeabi_cfrcmple"
		size = "36"
		objfiles = "_cmpsf2@libgcc.a"
	strings:
		$pattern = { 00 C0 A0 E1 01 00 A0 E1 0C 10 A0 E1 FF FF FF EA 0F 40 2D E9 ?? ?? ?? EB 00 00 50 E3 00 00 70 43 0F 80 BD E8 }
	condition:
		$pattern
}

rule __longjmp_d9cf44339c3a121503c7af975c3175b2 {
	meta:
		aliases = "__GI___longjmp, __longjmp"
		size = "20"
		objfiles = "__longjmp@libc.a"
	strings:
		$pattern = { 00 C0 A0 E1 01 00 B0 E1 01 00 A0 03 F0 6F BC E8 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __aeabi_cdrcmple_53792a536d321deb0dc7d1e5f2f7c611 {
	meta:
		aliases = "__aeabi_cdrcmple"
		size = "48"
		objfiles = "_cmpdf2@libgcc.a"
	strings:
		$pattern = { 00 C0 A0 E1 02 00 A0 E1 0C 20 A0 E1 01 C0 A0 E1 03 10 A0 E1 0C 30 A0 E1 FF FF FF EA 01 40 2D E9 ?? ?? ?? EB 00 00 50 E3 00 00 70 43 01 80 BD E8 }
	condition:
		$pattern
}

rule wcsncpy_12676295ea2e44ec9b636bc9660bf7e6 {
	meta:
		aliases = "wcsncpy"
		size = "44"
		objfiles = "wcsncpy@libc.a"
	strings:
		$pattern = { 00 C0 A0 E1 04 00 00 EA 00 30 91 E5 00 00 53 E3 00 30 8C E5 04 10 81 12 04 C0 8C E2 00 00 52 E3 01 20 42 E2 F7 FF FF 1A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule wcsncat_85243040e33251b7e80db9a4fefb0943 {
	meta:
		aliases = "wcsncat"
		size = "72"
		objfiles = "wcsncat@libc.a"
	strings:
		$pattern = { 00 C0 A0 E1 04 30 9C E4 00 00 53 E3 FC FF FF 1A 04 C0 4C E2 01 00 00 EA 04 10 81 E2 04 C0 8C E2 00 00 52 E3 01 20 42 E2 03 00 00 0A 00 30 91 E5 00 00 53 E3 00 30 8C E5 F6 FF FF 1A 00 30 A0 E3 00 30 8C E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule xdrmem_setpos_ca6d063d148413a5bc4862452e5fc18b {
	meta:
		aliases = "xdrmem_setpos"
		size = "52"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { 00 C0 A0 E1 10 30 90 E5 14 20 9C E5 0C 00 90 E5 03 10 81 E0 02 00 80 E0 00 00 51 E1 00 30 61 D0 00 00 A0 C3 01 00 A0 D3 14 30 8C D5 0C 10 8C D5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __sigsetjmp_21dd68f27d79f86ce0eec13a05a25cd8 {
	meta:
		aliases = "__sigsetjmp"
		size = "12"
		objfiles = "setjmp@libc.a"
	strings:
		$pattern = { 00 C0 A0 E1 F0 6F AC E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __fpurge_be79f18aa8ac563290f8cf2152ab8773 {
	meta:
		aliases = "__fpurge"
		size = "60"
		objfiles = "__fpurge@libc.a"
	strings:
		$pattern = { 00 C0 A0 E3 02 C0 C0 E5 00 10 90 E5 08 20 90 E5 43 10 C1 E3 41 34 A0 E1 01 30 C0 E5 14 20 80 E5 18 20 80 E5 1C 20 80 E5 10 20 80 E5 28 C0 80 E5 2C C0 80 E5 00 10 C0 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule read_uleb128_b76a2a73396711c17efdec92bf6dc6cf {
	meta:
		aliases = "read_uleb128"
		size = "40"
		objfiles = "unwind_c@libgcc_eh.a, unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { 00 C0 A0 E3 0C 20 A0 E1 01 30 D0 E4 80 00 13 E3 7F 30 03 E2 13 C2 8C E1 07 20 82 E2 F9 FF FF 1A 00 C0 81 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __gesf2_ad422eb2775c203273756adcef1e7b43 {
	meta:
		aliases = "__gtsf2, __gesf2"
		size = "112"
		objfiles = "_cmpsf2@libgcc.a"
	strings:
		$pattern = { 00 C0 E0 E3 02 00 00 EA 01 C0 A0 E3 00 00 00 EA 01 C0 A0 E3 04 C0 0D E5 80 20 A0 E1 81 30 A0 E1 42 CC F0 E1 43 CC F0 11 06 00 00 0A A3 C0 92 E1 01 00 30 11 03 00 52 50 C1 0F A0 81 C1 0F E0 31 01 00 80 13 0E F0 A0 E1 42 CC F0 E1 01 00 00 1A 80 C4 B0 E1 03 00 00 1A 43 CC F0 E1 F2 FF FF 1A 81 C4 B0 E1 F0 FF FF 0A 04 00 1D E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __gedf2_a8d5193e8d8006a54a086450fcbe7256 {
	meta:
		aliases = "__gtdf2, __gedf2"
		size = "148"
		objfiles = "_cmpdf2@libgcc.a"
	strings:
		$pattern = { 00 C0 E0 E3 02 00 00 EA 01 C0 A0 E3 00 00 00 EA 01 C0 A0 E3 04 C0 0D E5 80 C0 A0 E1 CC CA F0 E1 82 C0 A0 E1 CC CA F0 11 0D 00 00 0A 80 C0 91 E1 82 C0 93 01 02 00 30 11 03 00 31 01 00 00 A0 03 0E F0 A0 01 00 00 70 E3 02 00 30 E1 02 00 50 51 03 00 51 01 C2 0F A0 21 C2 0F E0 31 01 00 80 E3 0E F0 A0 E1 80 C0 A0 E1 CC CA F0 E1 01 00 00 1A 00 C6 91 E1 04 00 00 1A 82 C0 A0 E1 CC CA F0 E1 E9 FF FF 1A 02 C6 93 E1 E7 FF FF 0A 04 00 1D E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule wmempcpy_0335f1bcd611eebda2ac3349c7ce1742 {
	meta:
		aliases = "__GI_wmempcpy, wmempcpy"
		size = "28"
		objfiles = "wmempcpy@libc.a"
	strings:
		$pattern = { 01 00 00 EA 04 30 91 E4 04 30 80 E4 00 00 52 E3 01 20 42 E2 FA FF FF 1A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_pthread_equal_f6fdbfcb4403a684069caac8d4c4200c {
	meta:
		aliases = "pthread_equal, __GI_pthread_equal"
		size = "16"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { 01 00 50 E1 00 00 A0 13 01 00 A0 03 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_strverscmp_a2cf6695fa3a940ca1768f33857d13eb {
	meta:
		aliases = "__GI_strverscmp"
		size = "256"
		objfiles = "strverscmp@libc.a"
	strings:
		$pattern = { 01 00 50 E1 70 40 2D E9 00 10 A0 03 37 00 00 0A 01 C0 D0 E4 01 E0 D1 E4 30 00 5C E3 00 20 A0 13 01 20 A0 03 30 30 4C E2 C8 60 9F E5 00 50 A0 E1 09 00 53 E3 02 40 A0 81 01 40 82 92 01 00 A0 E1 09 00 00 EA 01 C0 D5 E4 04 30 D6 E7 30 00 5C E3 00 20 A0 13 01 20 A0 03 30 10 4C E2 09 00 51 E3 01 20 82 92 01 E0 D0 E4 03 40 82 E1 0E 10 5C E0 01 00 00 1A 00 00 5C E3 F1 FF FF 1A 30 00 5E E3 00 30 A0 13 01 30 A0 03 30 20 4E E2 09 00 52 E3 01 30 83 92 60 20 9F E5 04 31 83 E1 03 30 D2 E7 03 3C A0 E1 43 2C A0 E1 02 00 52 E3 0F 00 00 0A 03 00 52 E3 02 10 A0 11 0C 00 00 1A 02 00 00 EA 09 00 52 E3 01 10 A0 83 }
	condition:
		$pattern
}

rule __GI_pthread_setcancelstate_98c0cd4fd826219594b6d064cf62a64d {
	meta:
		aliases = "pthread_setcancelstate, __GI_pthread_setcancelstate"
		size = "92"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { 01 00 50 E3 30 40 2D E9 00 50 A0 E1 01 40 A0 E1 16 00 A0 83 30 80 BD 88 60 FF FF EB 00 00 54 E3 40 30 D0 15 00 30 84 15 42 30 D0 E5 00 00 53 E3 40 50 C0 E5 06 00 00 0A 41 20 D0 E5 40 30 D0 E5 02 34 83 E1 01 0C 53 E3 00 00 E0 03 0D 10 A0 01 ?? ?? ?? 0B 00 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_pthread_setcanceltype_a10d1ab35b100a36d1f0a42daeb8a0b7 {
	meta:
		aliases = "pthread_setcanceltype, __GI_pthread_setcanceltype"
		size = "92"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { 01 00 50 E3 30 40 2D E9 00 50 A0 E1 01 40 A0 E1 16 00 A0 83 30 80 BD 88 77 FF FF EB 00 00 54 E3 41 30 D0 15 00 30 84 15 42 30 D0 E5 00 00 53 E3 41 50 C0 E5 06 00 00 0A 41 20 D0 E5 40 30 D0 E5 02 34 83 E1 01 0C 53 E3 00 00 E0 03 0D 10 A0 01 ?? ?? ?? 0B 00 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule pthread_attr_setdetachstate_7bcc34872ff84de30e032d1df0c50b3f {
	meta:
		aliases = "__GI_pthread_attr_setdetachstate, pthread_rwlockattr_setkind_np, pthread_attr_setdetachstate"
		size = "20"
		objfiles = "attr@libpthread.a, rwlock@libpthread.a"
	strings:
		$pattern = { 01 00 51 E3 00 10 80 95 16 00 A0 83 00 00 A0 93 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_rwlockattr_setpshared_4c4803b85666f355d6f3e2cd2af89ee1 {
	meta:
		aliases = "pthread_rwlockattr_setpshared"
		size = "20"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { 01 00 51 E3 04 10 80 95 16 00 A0 83 00 00 A0 93 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_pthread_attr_setinheritsc_c9dfd86fe3074e75abe54f04069c35e7 {
	meta:
		aliases = "pthread_attr_setinheritsched, __GI_pthread_attr_setinheritsched"
		size = "20"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 01 00 51 E3 0C 10 80 95 16 00 A0 83 00 00 A0 93 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __pthread_mutexattr_setpshared_fe029dee1c86b07e98c7bc55f938804d {
	meta:
		aliases = "pthread_condattr_setpshared, pthread_mutexattr_setpshared, __pthread_mutexattr_setpshared"
		size = "28"
		objfiles = "condvar@libpthread.a, mutex@libpthread.a"
	strings:
		$pattern = { 01 00 51 E3 16 00 A0 83 0E F0 A0 81 00 00 51 E3 26 00 A0 13 00 00 A0 03 0E F0 A0 E1 }
	condition:
		$pattern
}

rule setegid_6a9f10f29cd6a8b190eb4840a9cb8159 {
	meta:
		aliases = "__GI_seteuid, seteuid, setegid"
		size = "104"
		objfiles = "seteuid@libc.a, setegid@libc.a"
	strings:
		$pattern = { 01 00 70 E3 30 40 2D E9 00 40 A0 E1 04 00 00 1A ?? ?? ?? EB 04 50 A0 E1 16 30 A0 E3 00 30 80 E5 0E 00 00 EA 00 00 E0 E3 04 10 A0 E1 00 20 A0 E1 ?? ?? ?? EB 01 00 70 E3 00 50 A0 E1 07 00 00 1A ?? ?? ?? EB 00 30 90 E5 26 00 53 E3 03 00 00 1A 05 00 A0 E1 04 10 A0 E1 30 40 BD E8 ?? ?? ?? EA 05 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_void_1ce4a30a252936ca418941b102aaafc1 {
	meta:
		aliases = "authnone_validate, __GI_xdr_void, __GI__stdlib_mb_cur_max, old_sem_extricate_func, _stdlib_mb_cur_max, xdr_void"
		size = "8"
		objfiles = "auth_none@libc.a, _stdlib_mb_cur_max@libc.a, xdr@libc.a, oldsemaphore@libpthread.a"
	strings:
		$pattern = { 01 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __flbf_58386131fdee5041c570737b8e23262d {
	meta:
		aliases = "__flbf"
		size = "16"
		objfiles = "__flbf@libc.a"
	strings:
		$pattern = { 01 00 D0 E5 00 04 A0 E1 01 0C 00 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule log10_494ce340f3c17c2f1cdb437a6090a2d6 {
	meta:
		aliases = "__ieee754_log10, __GI_log10, log10"
		size = "384"
		objfiles = "e_log10@libm.a"
	strings:
		$pattern = { 01 06 50 E3 F0 4F 2D E9 00 A0 A0 E1 00 60 A0 E1 01 B0 A0 E1 01 40 A0 E1 00 00 A0 A3 15 00 00 AA 02 31 CA E3 01 30 93 E1 2C 01 9F 05 00 10 A0 03 04 00 00 0A 00 00 5A E3 06 00 00 AA 0A 20 A0 E1 0B 30 A0 E1 ?? ?? ?? EB 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? EB F0 8F BD E8 00 21 9F E5 00 30 A0 E3 ?? ?? ?? EB 00 A0 A0 E1 00 60 A0 E1 01 B0 A0 E1 01 40 A0 E1 35 00 E0 E3 E4 30 9F E5 03 00 56 E1 05 00 00 DA 0A 00 A0 E1 0B 10 A0 E1 0A 20 A0 E1 0B 30 A0 E1 ?? ?? ?? EB F0 8F BD E8 FF 0F 40 E2 03 00 40 E2 46 0A 80 E0 A0 5F A0 E1 00 00 85 E0 ?? ?? ?? EB FF 5F 65 E2 FF 24 C6 E3 0F 26 C2 E3 03 50 85 E2 05 3A 82 E1 }
	condition:
		$pattern
}

rule __clzsi2_dd138589df3ff810bd40a66faf9fb2c7 {
	meta:
		aliases = "__clzsi2"
		size = "96"
		objfiles = "_clzsi2@libgcc.a"
	strings:
		$pattern = { 01 08 50 E3 09 00 00 2A FF 00 50 E3 08 30 A0 83 00 30 A0 93 30 33 A0 E1 3C 20 9F E5 03 00 D2 E7 18 10 A0 83 20 10 A0 93 01 00 60 E0 0E F0 A0 E1 FF 34 E0 E3 03 00 50 E1 18 30 A0 83 10 30 A0 93 30 33 A0 E1 10 20 9F E5 03 00 D2 E7 08 10 A0 83 10 10 A0 93 01 00 60 E0 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_attr_setstacksize_627cef3b789ebda3dab77f28e01b501e {
	meta:
		aliases = "__pthread_attr_setstacksize, pthread_attr_setstacksize"
		size = "20"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 01 09 51 E3 20 10 80 25 16 00 A0 33 00 00 A0 23 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_getspecific_a4828b901ebee4a01aaaa2ce7c96afdd {
	meta:
		aliases = "pthread_getspecific"
		size = "76"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { 01 0B 50 E3 10 40 2D E9 00 40 A0 E1 0B 00 00 2A 9C FF FF EB A4 32 A0 E1 03 01 80 E0 74 00 90 E5 00 00 50 E3 05 00 00 0A 18 30 9F E5 84 31 93 E7 00 00 53 E3 1F 30 04 12 03 01 90 17 10 80 BD 18 00 00 A0 E3 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_setspecific_24245f8669cc603aa0a6553fc8db5bf6 {
	meta:
		aliases = "pthread_setspecific"
		size = "132"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { 01 0B 50 E3 F0 41 2D E9 00 40 A0 E1 01 80 A0 E1 18 00 00 2A 64 30 9F E5 80 31 93 E7 00 00 53 E3 14 00 00 0A 84 FF FF EB A4 62 A0 E1 06 31 80 E0 60 50 83 E2 14 30 95 E5 00 00 53 E3 00 70 A0 E1 06 00 00 1A 20 00 A0 E3 04 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 0C 00 A0 03 F0 81 BD 08 14 00 85 E5 06 31 87 E0 74 20 93 E5 00 00 A0 E3 1F 30 04 E2 03 81 82 E7 F0 81 BD E8 16 00 A0 E3 F0 81 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _store_inttype_4ee76f97215949a02f47a0bf157da908 {
	meta:
		aliases = "_store_inttype"
		size = "64"
		objfiles = "_store_inttype@libc.a"
	strings:
		$pattern = { 01 0C 51 E3 01 C0 A0 E1 02 10 A0 E1 03 20 A0 E1 08 00 00 0A 02 0B 5C E3 01 00 00 1A 06 00 80 E8 0E F0 A0 E1 02 0C 5C E3 00 10 80 15 0E F0 A0 11 41 34 A0 E1 01 30 C0 E5 00 10 C0 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __sigismember_cd47bd13fa76ee3371e06c499250e6bc {
	meta:
		aliases = "__GI___sigismember, __sigismember"
		size = "36"
		objfiles = "sigsetops@libc.a"
	strings:
		$pattern = { 01 10 41 E2 A1 32 A0 E1 03 21 90 E7 1F 10 01 E2 01 30 A0 E3 13 31 12 E0 00 00 A0 03 01 00 A0 13 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __sigaddset_c34af2b02df82895665c9ec02529b6aa {
	meta:
		aliases = "__GI___sigaddset, __sigaddset"
		size = "36"
		objfiles = "sigsetops@libc.a"
	strings:
		$pattern = { 01 10 41 E2 A1 C2 A0 E1 0C 31 90 E7 1F 10 01 E2 01 20 A0 E3 12 31 83 E1 0C 31 80 E7 00 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI___sigdelset_72d374db4bb099eec68b3c50b166af99 {
	meta:
		aliases = "__sigdelset, __GI___sigdelset"
		size = "36"
		objfiles = "sigsetops@libc.a"
	strings:
		$pattern = { 01 10 41 E2 A1 C2 A0 E1 0C 31 90 E7 1F 10 01 E2 01 20 A0 E3 12 31 C3 E1 0C 31 80 E7 00 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule dlclose_7f50039806c7d76471f5837461f829be {
	meta:
		aliases = "dlclose"
		size = "8"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 01 10 A0 E3 3D FF FF EA }
	condition:
		$pattern
}

rule __GI_chmod_7571c1b2105f14b9715fa234ecace5a2 {
	meta:
		aliases = "chmod, __GI_chmod"
		size = "52"
		objfiles = "chmod@libc.a"
	strings:
		$pattern = { 01 18 A0 E1 10 40 2D E9 21 18 A0 E1 0F 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_mkdir_6d5cf74a16250c4a1a020a07d7e03ce4 {
	meta:
		aliases = "mkdir, __GI_mkdir"
		size = "52"
		objfiles = "mkdir@libc.a"
	strings:
		$pattern = { 01 18 A0 E1 10 40 2D E9 21 18 A0 E1 27 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule fchmod_f2a6c6ac1501e59364961db853208789 {
	meta:
		aliases = "fchmod"
		size = "52"
		objfiles = "fchmod@libc.a"
	strings:
		$pattern = { 01 18 A0 E1 10 40 2D E9 21 18 A0 E1 5E 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule mkfifo_109fec92792af639fbb5145a93eb69d9 {
	meta:
		aliases = "mkfifo"
		size = "16"
		objfiles = "mkfifo@libc.a"
	strings:
		$pattern = { 01 1A 81 E3 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __aeabi_uidiv_d1c9bc83f74de32950c43b311311f773 {
	meta:
		aliases = "__udivsi3, __aeabi_uidiv"
		size = "248"
		objfiles = "_udivsi3@libgcc.a"
	strings:
		$pattern = { 01 20 51 E2 0E F0 A0 01 36 00 00 3A 01 00 50 E1 22 00 00 9A 02 00 11 E1 23 00 00 0A 0E 02 11 E3 81 11 A0 01 08 30 A0 03 01 30 A0 13 01 02 51 E3 00 00 51 31 01 12 A0 31 03 32 A0 31 FA FF FF 3A 02 01 51 E3 00 00 51 31 81 10 A0 31 83 30 A0 31 FA FF FF 3A 00 20 A0 E3 01 00 50 E1 01 00 40 20 03 20 82 21 A1 00 50 E1 A1 00 40 20 A3 20 82 21 21 01 50 E1 21 01 40 20 23 21 82 21 A1 01 50 E1 A1 01 40 20 A3 21 82 21 00 00 50 E3 23 32 B0 11 21 12 A0 11 EF FF FF 1A 02 00 A0 E1 0E F0 A0 E1 01 00 A0 03 00 00 A0 13 0E F0 A0 E1 01 08 51 E3 21 18 A0 21 10 20 A0 23 00 20 A0 33 01 0C 51 E3 21 14 A0 21 08 20 82 22 }
	condition:
		$pattern
}

rule __umodsi3_719519ad91a99cc222098ad4a9841e75 {
	meta:
		aliases = "__umodsi3"
		size = "204"
		objfiles = "_umodsi3@libgcc.a"
	strings:
		$pattern = { 01 20 51 E2 2C 00 00 3A 01 00 50 11 00 00 A0 03 02 00 11 81 02 00 00 00 0E F0 A0 91 00 20 A0 E3 01 02 51 E3 00 00 51 31 01 12 A0 31 04 20 82 32 FA FF FF 3A 02 01 51 E3 00 00 51 31 81 10 A0 31 01 20 82 32 FA FF FF 3A 03 20 52 E2 0E 00 00 BA 01 00 50 E1 01 00 40 20 A1 00 50 E1 A1 00 40 20 21 01 50 E1 21 01 40 20 A1 01 50 E1 A1 01 40 20 01 00 50 E3 21 12 A0 E1 04 20 52 A2 F3 FF FF AA 03 00 12 E3 00 00 30 13 0A 00 00 0A 02 00 72 E3 06 00 00 BA 02 00 00 0A 01 00 50 E1 01 00 40 20 A1 10 A0 E1 01 00 50 E1 01 00 40 20 A1 10 A0 E1 01 00 50 E1 01 00 40 20 0E F0 A0 E1 08 E0 2D E5 ?? ?? ?? ?? 00 00 A0 E3 }
	condition:
		$pattern
}

rule bcmp_53b538cb10b98e19970157fe279f25da {
	meta:
		aliases = "memcmp, __GI_memcmp, bcmp"
		size = "44"
		objfiles = "memcmp@libc.a"
	strings:
		$pattern = { 01 20 52 E2 00 00 A0 43 0E F0 A0 41 02 C0 80 E0 01 20 D0 E4 01 30 D1 E4 00 00 5C E1 03 00 52 21 FA FF FF 0A 03 00 42 E0 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __aeabi_ul2f_1dad0a4ba6bae6e64bc334c9810cc219 {
	meta:
		aliases = "__floatundisf, __aeabi_ul2f"
		size = "188"
		objfiles = "_addsubsf3@libgcc.a"
	strings:
		$pattern = { 01 20 90 E1 0E F0 A0 01 00 30 A0 E3 05 00 00 EA 01 20 90 E1 0E F0 A0 01 02 31 11 E2 01 00 00 5A 00 00 70 E2 00 10 E1 E2 01 C0 B0 E1 00 C0 A0 01 00 10 A0 01 00 00 A0 03 5B 34 83 E3 01 32 43 02 02 35 43 E2 17 20 A0 E3 01 08 5C E3 2C C8 A0 21 10 20 42 22 01 0C 5C E3 2C C4 A0 21 08 20 42 22 10 00 5C E3 2C C2 A0 21 04 20 42 22 04 00 5C E3 02 20 42 22 AC 20 42 30 AC 21 52 E0 82 3B 43 E0 06 00 00 BA 11 32 83 E0 10 C2 A0 E1 20 20 62 E2 02 01 5C E3 30 02 A3 E0 01 00 C0 03 0E F0 A0 E1 20 20 82 E2 11 C2 A0 E1 20 20 62 E2 8C 00 90 E1 31 02 A3 E0 AC 0F C0 01 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __floatdisf_527956a4cba54ded633c5b77f9b19377 {
	meta:
		aliases = "__aeabi_l2f, __floatdisf"
		size = "172"
		objfiles = "_addsubsf3@libgcc.a"
	strings:
		$pattern = { 01 20 90 E1 0E F0 A0 01 02 31 11 E2 01 00 00 5A 00 00 70 E2 00 10 E1 E2 01 C0 B0 E1 00 C0 A0 01 00 10 A0 01 00 00 A0 03 5B 34 83 E3 01 32 43 02 02 35 43 E2 17 20 A0 E3 01 08 5C E3 2C C8 A0 21 10 20 42 22 01 0C 5C E3 2C C4 A0 21 08 20 42 22 10 00 5C E3 2C C2 A0 21 04 20 42 22 04 00 5C E3 02 20 42 22 AC 20 42 30 AC 21 52 E0 82 3B 43 E0 06 00 00 BA 11 32 83 E0 10 C2 A0 E1 20 20 62 E2 02 01 5C E3 30 02 A3 E0 01 00 C0 03 0E F0 A0 E1 20 20 82 E2 11 C2 A0 E1 20 20 62 E2 8C 00 90 E1 31 02 A3 E0 AC 0F C0 01 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __aeabi_ul2d_eab34c3c5ffc718a52c525c301522271 {
	meta:
		aliases = "__floatundidf, __aeabi_ul2d"
		size = "128"
		objfiles = "_addsubdf3@libgcc.a"
	strings:
		$pattern = { 01 20 90 E1 0E F0 A0 01 30 40 2D E9 00 50 A0 E3 06 00 00 EA 01 20 90 E1 0E F0 A0 01 30 40 2D E9 02 51 11 E2 01 00 00 5A 00 00 70 E2 00 10 E1 E2 01 4B A0 E3 32 40 84 E2 00 C0 A0 E1 01 00 A0 E1 0C 10 A0 E1 20 CB B0 E1 4A FF FF 0A 03 20 A0 E3 AC C1 B0 E1 03 20 82 12 AC C1 B0 E1 03 20 82 12 AC 21 82 E0 20 30 62 E2 11 C3 A0 E1 31 12 A0 E1 10 13 81 E1 30 02 A0 E1 02 40 84 E0 3D FF FF EA }
	condition:
		$pattern
}

rule __floatdidf_59a44d4aa9b2a12b1a3fb3a810efccf0 {
	meta:
		aliases = "__aeabi_l2d, __floatdidf"
		size = "108"
		objfiles = "_addsubdf3@libgcc.a"
	strings:
		$pattern = { 01 20 90 E1 0E F0 A0 01 30 40 2D E9 02 51 11 E2 01 00 00 5A 00 00 70 E2 00 10 E1 E2 01 4B A0 E3 32 40 84 E2 00 C0 A0 E1 01 00 A0 E1 0C 10 A0 E1 20 CB B0 E1 4A FF FF 0A 03 20 A0 E3 AC C1 B0 E1 03 20 82 12 AC C1 B0 E1 03 20 82 12 AC 21 82 E0 20 30 62 E2 11 C3 A0 E1 31 12 A0 E1 10 13 81 E1 30 02 A0 E1 02 40 84 E0 3D FF FF EA }
	condition:
		$pattern
}

rule tcflow_ef3ed2424499b3eeeda71bb99932f3ae {
	meta:
		aliases = "tcflow"
		size = "16"
		objfiles = "tcflow@libc.a"
	strings:
		$pattern = { 01 20 A0 E1 00 10 9F E5 ?? ?? ?? EA 0A 54 00 00 }
	condition:
		$pattern
}

rule tcflush_3e598688048ef11b4e4ed18afbf3146c {
	meta:
		aliases = "tcflush"
		size = "16"
		objfiles = "tcflush@libc.a"
	strings:
		$pattern = { 01 20 A0 E1 00 10 9F E5 ?? ?? ?? EA 0B 54 00 00 }
	condition:
		$pattern
}

rule creat64_e4e7b589e2583f0c6c103523c2dd83b2 {
	meta:
		aliases = "creat, creat64"
		size = "16"
		objfiles = "creat64@libc.a, creat@libc.a"
	strings:
		$pattern = { 01 20 A0 E1 00 10 9F E5 ?? ?? ?? EA 41 02 00 00 }
	condition:
		$pattern
}

rule drand48_r_2145ca4e0ef4524858602e20f56948c7 {
	meta:
		aliases = "__GI_lrand48_r, mrand48_r, lrand48_r, drand48_r"
		size = "12"
		objfiles = "drand48_r@libc.a, lrand48_r@libc.a, mrand48_r@libc.a"
	strings:
		$pattern = { 01 20 A0 E1 00 10 A0 E1 ?? ?? ?? EA }
	condition:
		$pattern
}

rule futimens_efbca4da4e6804ec651fd18cfce8f82e {
	meta:
		aliases = "futimens"
		size = "16"
		objfiles = "futimens@libc.a"
	strings:
		$pattern = { 01 20 A0 E1 00 10 A0 E3 01 30 A0 E1 ?? ?? ?? EA }
	condition:
		$pattern
}

rule mq_getattr_0efc9bd82418dead8553fc2005f25bf4 {
	meta:
		aliases = "bzero, gmtime_r, mq_getattr"
		size = "12"
		objfiles = "mq_getsetattr@librt.a, gmtime_r@libc.a, bzero@libc.a"
	strings:
		$pattern = { 01 20 A0 E1 00 10 A0 E3 ?? ?? ?? EA }
	condition:
		$pattern
}

rule xdr_netobj_8faf88506fc3c25bca7e6ab6608b1f3e {
	meta:
		aliases = "xdr_netobj"
		size = "16"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { 01 20 A0 E1 01 3B A0 E3 04 10 81 E2 ?? ?? ?? EA }
	condition:
		$pattern
}

rule vprintf_f2068c4f7ded18dcf76a6cb2fc8fc546 {
	meta:
		aliases = "__GI_vscanf, vwprintf, vwscanf, vscanf, vprintf"
		size = "28"
		objfiles = "vscanf@libc.a, vwscanf@libc.a, vwprintf@libc.a, vprintf@libc.a"
	strings:
		$pattern = { 01 20 A0 E1 0C 10 9F E5 00 30 A0 E1 00 00 91 E5 03 10 A0 E1 ?? ?? ?? EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_alt_trylock_b60491968acc28c66fa246c1530f2d2e {
	meta:
		aliases = "__pthread_alt_trylock"
		size = "68"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { 01 20 A0 E3 04 30 80 E2 02 10 A0 E1 91 10 03 E1 00 00 51 E3 0F 20 82 12 07 00 00 1A 00 30 90 E5 00 00 53 E3 10 20 A0 13 01 00 00 1A 00 20 80 E5 03 20 A0 E1 00 30 A0 E3 04 30 80 E5 02 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_vwarn_39baab3184766f99eb7531efaebce3a5 {
	meta:
		aliases = "vwarn, __GI_vwarn"
		size = "8"
		objfiles = "err@libc.a"
	strings:
		$pattern = { 01 20 A0 E3 A4 FF FF EA }
	condition:
		$pattern
}

rule swab_52deb5a32b4b731855d518a2d8391b87 {
	meta:
		aliases = "swab"
		size = "64"
		objfiles = "swab@libc.a"
	strings:
		$pattern = { 01 20 C2 E3 02 C0 80 E0 09 00 00 EA 00 30 D0 E5 01 20 D0 E5 02 24 83 E1 22 24 A0 E1 03 24 82 E1 42 34 A0 E1 01 30 C1 E5 00 20 C1 E5 02 00 80 E2 02 10 81 E2 0C 00 50 E1 F3 FF FF 3A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule strcoll_5d8be841fab43937f1ba9f42fd8c1db7 {
	meta:
		aliases = "__GI_strcmp, strcmp, __GI_strcoll, strcoll"
		size = "28"
		objfiles = "strcmp@libc.a"
	strings:
		$pattern = { 01 20 D0 E4 01 30 D1 E4 01 00 52 E3 03 00 52 21 FA FF FF 0A 03 00 42 E0 0E F0 A0 E1 }
	condition:
		$pattern
}

rule towctrans_450ecab93a5e8136563391a08aa397a5 {
	meta:
		aliases = "__GI_towctrans, towctrans"
		size = "72"
		objfiles = "towctrans@libc.a"
	strings:
		$pattern = { 01 30 41 E2 01 00 53 E3 10 40 2D E9 00 40 A0 E1 07 00 00 8A 20 00 80 E3 61 30 40 E2 19 00 53 E3 04 00 A0 81 10 80 BD 88 02 00 51 E3 20 00 C0 03 10 80 BD E8 ?? ?? ?? EB 16 30 A0 E3 00 30 80 E5 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule testandset_93fb27a41f3a21ff4b36e58f971afbd1 {
	meta:
		aliases = "testandset"
		size = "16"
		objfiles = "pt_machine@libpthread.a"
	strings:
		$pattern = { 01 30 A0 E3 93 30 00 E1 03 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __freadable_0979c884479a0faa6bf6431e145daf6b {
	meta:
		aliases = "__freadable"
		size = "28"
		objfiles = "__freadable@libc.a"
	strings:
		$pattern = { 01 30 D0 E5 00 00 D0 E5 03 04 80 E1 20 02 A0 E1 01 00 20 E2 01 00 00 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __fwritable_216ca2954d781664667d6e5647724ac0 {
	meta:
		aliases = "__fwritable"
		size = "28"
		objfiles = "__fwritable@libc.a"
	strings:
		$pattern = { 01 30 D0 E5 00 00 D0 E5 03 04 80 E1 A0 02 A0 E1 01 00 20 E2 01 00 00 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule stpcpy_21474836729eada4ac8ab0f1000af6f8 {
	meta:
		aliases = "__GI_stpcpy, stpcpy"
		size = "24"
		objfiles = "stpcpy@libc.a"
	strings:
		$pattern = { 01 30 D1 E4 00 00 53 E3 01 30 C0 E4 FB FF FF 1A 01 00 40 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_cfsetispeed_5057c194bfc983a7399d967529dfe19a {
	meta:
		aliases = "cfsetispeed, __GI_cfsetispeed"
		size = "116"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { 01 3A C1 E3 0F 30 C3 E3 00 00 53 E3 04 E0 2D E5 07 00 00 0A 01 3A 41 E2 01 30 43 E2 0E 00 53 E3 03 00 00 9A ?? ?? ?? EB 00 10 E0 E3 16 30 A0 E3 03 00 00 EA 00 00 51 E3 00 20 90 E5 02 00 00 1A 02 31 82 E3 00 30 80 E5 07 00 00 EA 08 30 90 E5 01 3A C3 E3 0F 30 C3 E3 03 30 81 E1 02 21 C2 E3 08 30 80 E5 00 20 80 E5 00 10 A0 E3 01 00 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule cfsetospeed_e54ffa9fca4a97f266df10f2497e5546 {
	meta:
		aliases = "__GI_cfsetospeed, cfsetospeed"
		size = "88"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { 01 3A C1 E3 0F 30 C3 E3 00 00 53 E3 04 E0 2D E5 08 00 00 0A 01 3A 41 E2 01 30 43 E2 0E 00 53 E3 04 00 00 9A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 05 00 00 EA 08 30 90 E5 01 3A C3 E3 0F 30 C3 E3 03 30 81 E1 08 30 80 E5 00 20 A0 E3 02 00 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule __aeabi_cdcmpeq_62f18cfc09e7783ed06b46fb9fae0856 {
	meta:
		aliases = "__aeabi_cdcmple, __aeabi_cdcmpeq"
		size = "20"
		objfiles = "_cmpdf2@libgcc.a"
	strings:
		$pattern = { 01 40 2D E9 ?? ?? ?? EB 00 00 50 E3 00 00 70 43 01 80 BD E8 }
	condition:
		$pattern
}

rule siglongjmp_26448045ed4a82a559a4f1989d62f052 {
	meta:
		aliases = "siglongjmp"
		size = "24"
		objfiles = "ptlongjmp@libpthread.a"
	strings:
		$pattern = { 01 50 A0 E1 00 40 A0 E1 BD FF FF EB 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule longjmp_0cd9a193784944985f77ac5cb9388f7b {
	meta:
		aliases = "longjmp"
		size = "24"
		objfiles = "ptlongjmp@libpthread.a"
	strings:
		$pattern = { 01 50 A0 E1 00 40 A0 E1 C3 FF FF EB 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule wait3_ae5673c95afdc7c6be05dc9acdbb2359 {
	meta:
		aliases = "wait3"
		size = "24"
		objfiles = "wait3@libc.a"
	strings:
		$pattern = { 01 C0 A0 E1 02 30 A0 E1 00 10 A0 E1 0C 20 A0 E1 00 00 E0 E3 ?? ?? ?? EA }
	condition:
		$pattern
}

rule posix_fadvise_46225ecd6ed57161003d5610d01f8651 {
	meta:
		aliases = "posix_fadvise"
		size = "48"
		objfiles = "posix_fadvise@libc.a"
	strings:
		$pattern = { 01 C0 A0 E1 03 10 A0 E1 00 30 A0 E3 30 40 2D E9 02 40 A0 E1 03 50 A0 E1 0C 20 A0 E1 0E 01 90 EF 01 0A 70 E3 03 00 A0 91 00 00 60 82 30 80 BD E8 }
	condition:
		$pattern
}

rule __lesf2_3a855a9a3e166c4422d2040e24f2c5ac {
	meta:
		aliases = "__ltsf2, __lesf2"
		size = "104"
		objfiles = "_cmpsf2@libgcc.a"
	strings:
		$pattern = { 01 C0 A0 E3 00 00 00 EA 01 C0 A0 E3 04 C0 0D E5 80 20 A0 E1 81 30 A0 E1 42 CC F0 E1 43 CC F0 11 06 00 00 0A A3 C0 92 E1 01 00 30 11 03 00 52 50 C1 0F A0 81 C1 0F E0 31 01 00 80 13 0E F0 A0 E1 42 CC F0 E1 01 00 00 1A 80 C4 B0 E1 03 00 00 1A 43 CC F0 E1 F2 FF FF 1A 81 C4 B0 E1 F0 FF FF 0A 04 00 1D E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __ltdf2_d98ca0327e40efd721b0bf8ce68f781f {
	meta:
		aliases = "__ledf2, __ltdf2"
		size = "140"
		objfiles = "_cmpdf2@libgcc.a"
	strings:
		$pattern = { 01 C0 A0 E3 00 00 00 EA 01 C0 A0 E3 04 C0 0D E5 80 C0 A0 E1 CC CA F0 E1 82 C0 A0 E1 CC CA F0 11 0D 00 00 0A 80 C0 91 E1 82 C0 93 01 02 00 30 11 03 00 31 01 00 00 A0 03 0E F0 A0 01 00 00 70 E3 02 00 30 E1 02 00 50 51 03 00 51 01 C2 0F A0 21 C2 0F E0 31 01 00 80 E3 0E F0 A0 E1 80 C0 A0 E1 CC CA F0 E1 01 00 00 1A 00 C6 91 E1 04 00 00 1A 82 C0 A0 E1 CC CA F0 E1 E9 FF FF 1A 02 C6 93 E1 E7 FF FF 0A 04 00 1D E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __cmpsf2_20190a500a376de588b255af7f06cddf {
	meta:
		aliases = "__eqsf2, __nesf2, __cmpsf2"
		size = "96"
		objfiles = "_cmpsf2@libgcc.a"
	strings:
		$pattern = { 01 C0 A0 E3 04 C0 0D E5 80 20 A0 E1 81 30 A0 E1 42 CC F0 E1 43 CC F0 11 06 00 00 0A A3 C0 92 E1 01 00 30 11 03 00 52 50 C1 0F A0 81 C1 0F E0 31 01 00 80 13 0E F0 A0 E1 42 CC F0 E1 01 00 00 1A 80 C4 B0 E1 03 00 00 1A 43 CC F0 E1 F2 FF FF 1A 81 C4 B0 E1 F0 FF FF 0A 04 00 1D E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __cmpdf2_8d2cd9eee0fdc8c659f057219ecbfdad {
	meta:
		aliases = "__nedf2, __eqdf2, __cmpdf2"
		size = "132"
		objfiles = "_cmpdf2@libgcc.a"
	strings:
		$pattern = { 01 C0 A0 E3 04 C0 0D E5 80 C0 A0 E1 CC CA F0 E1 82 C0 A0 E1 CC CA F0 11 0D 00 00 0A 80 C0 91 E1 82 C0 93 01 02 00 30 11 03 00 31 01 00 00 A0 03 0E F0 A0 01 00 00 70 E3 02 00 30 E1 02 00 50 51 03 00 51 01 C2 0F A0 21 C2 0F E0 31 01 00 80 E3 0E F0 A0 E1 80 C0 A0 E1 CC CA F0 E1 01 00 00 1A 00 C6 91 E1 04 00 00 1A 82 C0 A0 E1 CC CA F0 E1 E9 FF FF 1A 02 C6 93 E1 E7 FF FF 0A 04 00 1D E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_pthread_attr_setschedpoli_5e65d41a68945d7a14b6d638fe2d90aa {
	meta:
		aliases = "pthread_attr_setschedpolicy, __GI_pthread_attr_setschedpolicy"
		size = "20"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 02 00 51 E3 04 10 80 95 16 00 A0 83 00 00 A0 93 0E F0 A0 E1 }
	condition:
		$pattern
}

rule svcudp_stat_ae78ace192a33af724e3cae5712c1237 {
	meta:
		aliases = "svcraw_stat, rendezvous_stat, _svcauth_short, svcudp_stat"
		size = "8"
		objfiles = "svc_udp@libc.a, svc_raw@libc.a, svc_unix@libc.a, svc_authux@libc.a, svc_tcp@libc.a"
	strings:
		$pattern = { 02 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI___signbitf_4b8f21fb04c77b43d51bc2a86522ce44 {
	meta:
		aliases = "__GI___signbit, __signbit, __signbitf, __GI___signbitf"
		size = "8"
		objfiles = "s_signbit@libm.a, s_signbitf@libm.a"
	strings:
		$pattern = { 02 01 00 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __aeabi_frsub_af6a0a28a2e50ea7406d3ffd142bde6d {
	meta:
		aliases = "__aeabi_frsub"
		size = "456"
		objfiles = "_addsubsf3@libgcc.a"
	strings:
		$pattern = { 02 01 20 E2 00 00 00 EA 02 11 21 E2 80 20 B0 E1 81 30 B0 11 03 00 32 11 42 CC F0 11 43 CC F0 11 47 00 00 0A 22 2C A0 E1 23 3C 72 E0 03 20 82 C0 01 10 20 C0 00 00 21 C0 01 10 20 C0 00 30 63 B2 19 00 53 E3 0E F0 A0 81 02 01 10 E3 02 05 80 E3 FF 04 C0 E3 00 00 60 12 02 01 11 E3 02 15 81 E3 FF 14 C1 E3 00 10 61 12 03 00 32 E1 2E 00 00 0A 01 20 42 E2 51 03 90 E0 20 30 63 E2 11 13 A0 E1 02 31 00 E2 01 00 00 5A 00 10 71 E2 00 00 E0 E2 02 05 50 E3 0B 00 00 3A 01 04 50 E3 04 00 00 3A A0 00 B0 E1 61 10 A0 E1 01 20 82 E2 FE 00 52 E3 38 00 00 2A 02 01 51 E3 82 0B A0 E0 01 00 C0 03 03 00 80 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __aeabi_drsub_854d5b0f1c85e2a1fc4798266a31f49a {
	meta:
		aliases = "__aeabi_drsub"
		size = "1024"
		objfiles = "_addsubdf3@libgcc.a"
	strings:
		$pattern = { 02 01 20 E2 00 00 00 EA 02 21 22 E2 30 40 2D E9 80 40 A0 E1 82 50 A0 E1 05 00 34 E1 03 00 31 01 01 C0 94 11 03 C0 95 11 C4 CA F0 11 C5 CA F0 11 86 00 00 0A A4 4A A0 E1 A5 5A 74 E0 00 50 65 B2 06 00 00 DA 05 40 84 E0 03 30 21 E0 02 20 20 E0 01 10 23 E0 00 00 22 E0 03 30 21 E0 02 20 20 E0 36 00 55 E3 30 80 BD 88 02 01 10 E3 00 06 A0 E1 01 C6 A0 E3 20 06 8C E1 01 00 00 0A 00 10 71 E2 00 00 E0 E2 02 01 12 E3 02 26 A0 E1 22 26 8C E1 01 00 00 0A 00 30 73 E2 00 20 E2 E2 05 00 34 E1 64 00 00 0A 01 40 44 E2 20 E0 75 E2 05 00 00 BA 13 CE A0 E1 33 15 91 E0 00 00 A0 E2 12 1E 91 E0 52 05 B0 E0 06 00 00 EA }
	condition:
		$pattern
}

rule __negsf2_91f9f13c92a8ce442cf9c1dcc6a7dfff {
	meta:
		aliases = "__negdf2, __aeabi_dneg, __aeabi_fneg, __negsf2"
		size = "8"
		objfiles = "_negsf2@libgcc.a, _negdf2@libgcc.a"
	strings:
		$pattern = { 02 01 20 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __isnanf_ae70b5bcd3313d6bee64d8873ca3e151 {
	meta:
		aliases = "__GI___isnanf, __isnanf"
		size = "20"
		objfiles = "s_isnanf@libm.a"
	strings:
		$pattern = { 02 01 C0 E3 7F 04 60 E2 02 05 80 E2 A0 0F A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __fpclassifyf_df80abb91a958035961cc0bffe92aab1 {
	meta:
		aliases = "__GI___fpclassifyf, __fpclassifyf"
		size = "68"
		objfiles = "s_fpclassifyf@libm.a"
	strings:
		$pattern = { 02 01 D0 E3 02 00 A0 03 0E F0 A0 01 02 05 50 E3 03 00 A0 33 0E F0 A0 31 1C 30 9F E5 03 00 50 E1 04 00 A0 93 0E F0 A0 91 10 30 9F E5 03 00 50 E1 00 00 A0 83 01 00 A0 93 0E F0 A0 E1 FF FF 7F 7F 00 00 80 7F }
	condition:
		$pattern
}

rule __aeabi_fsub_b34ada2c1daace1c8e4bc2bc2cb95841 {
	meta:
		aliases = "__subsf3, __aeabi_fsub"
		size = "448"
		objfiles = "_addsubsf3@libgcc.a"
	strings:
		$pattern = { 02 11 21 E2 80 20 B0 E1 81 30 B0 11 03 00 32 11 42 CC F0 11 43 CC F0 11 47 00 00 0A 22 2C A0 E1 23 3C 72 E0 03 20 82 C0 01 10 20 C0 00 00 21 C0 01 10 20 C0 00 30 63 B2 19 00 53 E3 0E F0 A0 81 02 01 10 E3 02 05 80 E3 FF 04 C0 E3 00 00 60 12 02 01 11 E3 02 15 81 E3 FF 14 C1 E3 00 10 61 12 03 00 32 E1 2E 00 00 0A 01 20 42 E2 51 03 90 E0 20 30 63 E2 11 13 A0 E1 02 31 00 E2 01 00 00 5A 00 10 71 E2 00 00 E0 E2 02 05 50 E3 0B 00 00 3A 01 04 50 E3 04 00 00 3A A0 00 B0 E1 61 10 A0 E1 01 20 82 E2 FE 00 52 E3 38 00 00 2A 02 01 51 E3 82 0B A0 E0 01 00 C0 03 03 00 80 E1 0E F0 A0 E1 81 10 B0 E1 00 00 A0 E0 }
	condition:
		$pattern
}

rule __aeabi_dsub_7e00cb5cbd4c014f146f2e99671140ca {
	meta:
		aliases = "__subdf3, __aeabi_dsub"
		size = "740"
		objfiles = "_addsubdf3@libgcc.a"
	strings:
		$pattern = { 02 21 22 E2 30 40 2D E9 80 40 A0 E1 82 50 A0 E1 05 00 34 E1 03 00 31 01 01 C0 94 11 03 C0 95 11 C4 CA F0 11 C5 CA F0 11 86 00 00 0A A4 4A A0 E1 A5 5A 74 E0 00 50 65 B2 06 00 00 DA 05 40 84 E0 03 30 21 E0 02 20 20 E0 01 10 23 E0 00 00 22 E0 03 30 21 E0 02 20 20 E0 36 00 55 E3 30 80 BD 88 02 01 10 E3 00 06 A0 E1 01 C6 A0 E3 20 06 8C E1 01 00 00 0A 00 10 71 E2 00 00 E0 E2 02 01 12 E3 02 26 A0 E1 22 26 8C E1 01 00 00 0A 00 30 73 E2 00 20 E2 E2 05 00 34 E1 64 00 00 0A 01 40 44 E2 20 E0 75 E2 05 00 00 BA 13 CE A0 E1 33 15 91 E0 00 00 A0 E2 12 1E 91 E0 52 05 B0 E0 06 00 00 EA 20 50 45 E2 20 E0 8E E2 }
	condition:
		$pattern
}

rule __GI_ilogb_ea4753f97924cad0541081a091de9547 {
	meta:
		aliases = "ilogb, __GI_ilogb"
		size = "144"
		objfiles = "s_ilogb@libm.a"
	strings:
		$pattern = { 02 21 C0 E3 01 06 52 E3 10 40 2D E9 01 40 A0 E1 14 00 00 AA 01 30 A0 E1 04 10 92 E1 06 01 A0 03 10 80 BD 08 00 00 52 E3 54 00 9F 05 02 00 00 0A 04 00 00 EA 01 00 40 E2 83 30 A0 E1 00 00 53 E3 FB FF FF CA 10 80 BD E8 38 00 9F E5 82 35 A0 E1 01 00 00 EA 01 00 40 E2 83 30 A0 E1 00 00 53 E3 FB FF FF CA 10 80 BD E8 1C 30 9F E5 03 00 52 E1 42 3A A0 D1 FF 0F 43 D2 02 01 E0 C3 03 00 40 D2 10 80 BD E8 ED FB FF FF 02 FC FF FF FF FF EF 7F }
	condition:
		$pattern
}

rule vsprintf_ba46a640a09064dc4ae5a4ddd4653d61 {
	meta:
		aliases = "vsprintf"
		size = "16"
		objfiles = "vsprintf@libc.a"
	strings:
		$pattern = { 02 30 A0 E1 01 20 A0 E1 00 10 E0 E3 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __GI_getline_74e87f63788bd739b15d97089f480aa5 {
	meta:
		aliases = "getline, __GI_getline"
		size = "12"
		objfiles = "getline@libc.a"
	strings:
		$pattern = { 02 30 A0 E1 0A 20 A0 E3 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __stdio_seek_0cdc93777837384b0ed1ae7829ff6cd2 {
	meta:
		aliases = "__stdio_seek"
		size = "48"
		objfiles = "_cs_funcs@libc.a"
	strings:
		$pattern = { 02 30 A0 E1 10 40 2D E9 04 00 90 E5 01 40 A0 E1 06 00 91 E8 ?? ?? ?? EB 00 00 51 E3 00 30 A0 B1 03 00 84 A8 00 30 A0 A3 03 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule signalfd_c066271c5bc65cd3662dddded86ae1c6 {
	meta:
		aliases = "signalfd"
		size = "52"
		objfiles = "signalfd@libc.a"
	strings:
		$pattern = { 02 30 A0 E1 10 40 2D E9 08 20 A0 E3 63 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_fseek_383b7bec52d509eb219b77b3119cabc4 {
	meta:
		aliases = "fseek, fseeko, __GI_fseek"
		size = "12"
		objfiles = "fseeko@libc.a"
	strings:
		$pattern = { 02 30 A0 E1 C1 2F A0 E1 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __aeabi_i2f_fa7be2f3021c58b4ff47704126dc81bd {
	meta:
		aliases = "__floatsisf, __aeabi_i2f"
		size = "32"
		objfiles = "_addsubsf3@libgcc.a"
	strings:
		$pattern = { 02 31 10 E2 00 00 60 42 00 C0 B0 E1 0E F0 A0 01 4B 34 83 E3 00 10 A0 E1 00 00 A0 E3 0F 00 00 EA }
	condition:
		$pattern
}

rule __uClibc_main_f508cfb51d8fea75a81d8f6828d90136 {
	meta:
		aliases = "__uClibc_main"
		size = "664"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { 02 60 A0 E1 04 C0 82 E2 00 20 92 E5 01 E1 A0 E1 78 D0 4D E2 0E C0 8C E0 02 00 5C E1 01 A0 A0 E1 34 22 9F E5 80 10 9D E5 30 42 9F E5 00 10 82 E5 7C 10 9D E5 28 22 9F E5 03 80 A0 E1 0E 30 86 00 00 10 82 E5 00 C0 84 E5 78 20 A0 E3 00 90 A0 E1 00 30 84 05 0D 00 A0 E1 00 10 A0 E3 ?? ?? ?? EB 00 20 94 E5 00 00 00 EA 01 20 A0 E1 04 30 92 E4 00 00 53 E3 02 10 A0 E1 FA FF FF 1A 02 40 A0 E1 0D 50 A0 E1 05 00 00 EA 0E 00 53 E3 83 01 85 90 04 10 A0 91 08 20 A0 93 ?? ?? ?? 9B 08 40 84 E2 00 30 94 E5 00 00 53 E3 F6 FF FF 1A 0D 00 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 34 30 9D E5 5C 20 9D E5 00 00 53 E3 01 3A A0 03 }
	condition:
		$pattern
}

rule wmemcmp_70d7c8cb251753d359dc60ae554173d5 {
	meta:
		aliases = "wmemcmp"
		size = "64"
		objfiles = "wmemcmp@libc.a"
	strings:
		$pattern = { 02 C0 A0 E1 02 00 00 EA 04 00 80 E2 04 10 81 E2 01 C0 4C E2 00 00 5C E3 01 00 00 1A 0C 00 A0 E1 0E F0 A0 E1 00 20 90 E5 00 30 91 E5 03 00 52 E1 F4 FF FF 0A 00 00 E0 33 01 00 A0 23 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_logb_d346714b7be1310995a6eccd5ae0df7e {
	meta:
		aliases = "logb, __GI_logb"
		size = "128"
		objfiles = "s_logb@libm.a"
	strings:
		$pattern = { 02 C1 C0 E3 01 30 9C E1 70 40 2D E9 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 06 00 00 1A ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 44 00 9F E5 00 10 A0 E3 ?? ?? ?? EB 70 80 BD E8 38 30 9F E5 03 00 5C E1 03 00 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 70 80 BD E8 4C 0A B0 E1 1C 00 9F 05 00 10 A0 03 70 80 BD 08 FF 0F 40 E2 03 00 40 E2 ?? ?? ?? EB 70 80 BD E8 00 00 F0 BF FF FF EF 7F 00 F0 8F C0 }
	condition:
		$pattern
}

rule dysize_a67414899ed0b22dc2726ceb8d304d07 {
	meta:
		aliases = "dysize"
		size = "76"
		objfiles = "dysize@libc.a"
	strings:
		$pattern = { 03 00 10 E3 10 40 2D E9 00 40 A0 E1 0A 00 00 1A 64 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 04 00 00 1A 04 00 A0 E1 19 1E A0 E3 ?? ?? ?? EB 00 00 50 E3 01 00 00 1A 08 00 9F E5 10 80 BD E8 04 00 9F E5 10 80 BD E8 6E 01 00 00 6D 01 00 00 }
	condition:
		$pattern
}

rule posix_memalign_d35d058b6042b5219f6e876caa40c870 {
	meta:
		aliases = "posix_memalign"
		size = "52"
		objfiles = "posix_memalign@libc.a"
	strings:
		$pattern = { 03 00 11 E3 10 40 2D E9 00 40 A0 E1 16 00 A0 13 10 80 BD 18 01 00 A0 E1 02 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 84 E5 0C 00 A0 03 00 00 A0 13 10 80 BD E8 }
	condition:
		$pattern
}

rule iopl_6a6865dc5c38866d89e4aee1799bdd47 {
	meta:
		aliases = "iopl"
		size = "72"
		objfiles = "iopl@libc.a"
	strings:
		$pattern = { 03 00 50 E3 04 E0 2D E5 04 00 00 DA ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 07 00 00 EA 00 00 50 E3 00 20 A0 01 04 00 00 0A 00 00 A0 E3 01 18 A0 E3 01 20 A0 E3 04 E0 9D E4 ?? ?? ?? EA 02 00 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule __ucmpdi2_5c487e0776c9835e170886576e0ca094 {
	meta:
		aliases = "__ucmpdi2"
		size = "44"
		objfiles = "_ucmpdi2@libgcc.a"
	strings:
		$pattern = { 03 00 51 E1 06 00 00 3A 03 00 00 8A 02 00 50 E1 03 00 00 3A 01 00 A0 93 0E F0 A0 91 02 00 A0 E3 0E F0 A0 E1 00 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __cmpdi2_27a1c44b56f6e6e2902093e9bbd8d2d5 {
	meta:
		aliases = "__cmpdi2"
		size = "44"
		objfiles = "_cmpdi2@libgcc.a"
	strings:
		$pattern = { 03 00 51 E1 06 00 00 BA 03 00 00 CA 02 00 50 E1 03 00 00 3A 01 00 A0 93 0E F0 A0 91 02 00 A0 E3 0E F0 A0 E1 00 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_mutexattr_settype_bfe2e818c796d7dd38f1a0656161489e {
	meta:
		aliases = "__pthread_mutexattr_settype, pthread_mutexattr_setkind_np, __pthread_mutexattr_setkind_np, pthread_mutexattr_settype"
		size = "20"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { 03 00 51 E3 00 10 80 95 16 00 A0 83 00 00 A0 93 0E F0 A0 E1 }
	condition:
		$pattern
}

rule strncmp_dbc80067a362acf831f643db6038e355 {
	meta:
		aliases = "__GI_strncmp, strncmp"
		size = "280"
		objfiles = "strncmp@libc.a"
	strings:
		$pattern = { 03 00 52 E3 00 C0 A0 E1 00 00 A0 93 70 40 2D E9 00 E0 A0 91 3A 00 00 9A 22 61 A0 E1 00 00 DC E5 00 E0 D1 E5 0E 30 50 E0 01 30 A0 13 00 00 50 E3 01 30 83 03 00 00 53 E3 2D 00 00 1A 01 00 DC E5 01 E0 D1 E5 0E 30 50 E0 01 30 A0 13 00 00 50 E3 01 30 83 03 00 00 53 E3 01 40 8C E2 01 50 81 E2 23 00 00 1A 01 00 D4 E5 01 C0 D5 E5 0C 30 50 E0 01 30 A0 13 00 00 50 E3 01 30 83 03 00 00 53 E3 01 10 84 E2 01 40 85 E2 01 00 00 0A 00 00 6C E0 70 80 BD E8 01 00 D1 E5 01 E0 D4 E5 0E 30 50 E0 01 30 A0 13 00 00 50 E3 01 30 83 03 00 00 53 E3 01 30 81 E2 01 C0 83 E2 01 30 84 E2 01 10 83 E2 0B 00 00 1A 01 60 56 E2 }
	condition:
		$pattern
}

rule strncpy_79ca62f8da926e4bc17e66c18effc261 {
	meta:
		aliases = "__GI_strncpy, strncpy"
		size = "184"
		objfiles = "strncpy@libc.a"
	strings:
		$pattern = { 03 00 52 E3 04 E0 2D E5 01 C0 40 E2 1C 00 00 9A 22 E1 A0 E1 00 30 D1 E5 00 00 53 E3 01 30 EC E5 12 00 00 0A 01 30 D1 E5 00 00 53 E3 01 30 EC E5 01 10 81 E2 0D 00 00 0A 01 30 D1 E5 00 00 53 E3 01 30 EC E5 01 10 81 E2 08 00 00 0A 01 30 D1 E5 00 00 53 E3 01 30 EC E5 01 10 81 E2 03 00 00 0A 01 E0 5E E2 01 10 81 E2 05 00 00 0A E8 FF FF EA 0C 30 60 E0 02 30 63 E0 01 30 53 E2 04 F0 9D 04 07 00 00 EA 03 30 12 E2 04 F0 9D 04 01 20 D1 E4 01 30 53 E2 01 20 EC E5 04 F0 9D 04 00 00 52 E3 F9 FF FF 1A 00 20 A0 E3 01 30 53 E2 01 20 EC E5 FC FF FF 1A 04 F0 9D E4 }
	condition:
		$pattern
}

rule strlen_cebb5d24777319d078a11b9205b5cbd9 {
	meta:
		aliases = "__GI_strlen, strlen"
		size = "96"
		objfiles = "strlen@libc.a"
	strings:
		$pattern = { 03 10 C0 E3 04 20 91 E4 03 30 10 E2 00 00 63 E2 04 00 00 0A FF 20 82 E3 01 30 53 E2 FF 2C 82 C3 01 30 53 E2 FF 28 82 C3 FF 00 12 E3 FF 0C 12 13 FF 08 12 13 FF 04 12 13 04 00 80 12 04 20 91 14 F8 FF FF 1A FF 00 12 E3 01 00 80 12 FF 0C 12 13 01 00 80 12 FF 08 12 13 01 00 80 12 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_mutexattr_init_07a2b4878aa47260ada39f96e63e4140 {
	meta:
		aliases = "__pthread_mutexattr_init, pthread_mutexattr_init"
		size = "16"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { 03 30 A0 E3 00 30 80 E5 00 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __aeabi_idivmod_bed41a5928bd8d6776aa3ebccbfb418a {
	meta:
		aliases = "__aeabi_uidivmod, __aeabi_idivmod"
		size = "24"
		objfiles = "_divsi3@libgcc.a, _udivsi3@libgcc.a"
	strings:
		$pattern = { 03 40 2D E9 ?? ?? ?? EB 06 40 BD E8 92 00 03 E0 03 10 41 E0 0E F0 A0 E1 }
	condition:
		$pattern
}

rule memmem_6a74601d1223ce64dfe78507f2503aa8 {
	meta:
		aliases = "__GI_memmem, memmem"
		size = "120"
		objfiles = "memmem@libc.a"
	strings:
		$pattern = { 03 C0 A0 E1 00 00 53 E3 01 30 80 E0 F0 41 2D E9 00 40 A0 E1 02 50 A0 E1 03 80 6C E0 0E 00 00 0A 0C 00 51 E1 01 70 4C 22 01 60 82 22 0D 00 00 2A 0E 00 00 EA 00 20 D4 E5 00 30 D5 E5 03 00 52 E1 07 00 00 1A 01 00 84 E2 06 10 A0 E1 07 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 01 00 00 1A 04 00 A0 E1 F0 81 BD E8 01 40 84 E2 08 00 54 E1 F0 FF FF 9A 00 00 A0 E3 F0 81 BD E8 }
	condition:
		$pattern
}

rule memccpy_9adac26429eaccd5e879255b3bd3971c {
	meta:
		aliases = "__GI_memccpy, memccpy"
		size = "48"
		objfiles = "memccpy@libc.a"
	strings:
		$pattern = { 03 C0 A0 E1 FF 20 02 E2 01 C0 5C E2 01 00 00 2A 00 00 A0 E3 0E F0 A0 E1 00 30 D1 E5 02 00 53 E1 01 10 81 E2 01 30 C0 E4 F6 FF FF 1A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule wmemchr_e5a99abfcfa2665b580f750f784b1920 {
	meta:
		aliases = "__GI_wmemchr, wmemchr"
		size = "40"
		objfiles = "wmemchr@libc.a"
	strings:
		$pattern = { 04 00 00 EA 00 30 90 E5 01 00 53 E1 0E F0 A0 01 04 00 80 E2 01 20 42 E2 00 00 52 E3 F8 FF FF 1A 02 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_wcschrnul_d0ee039838254623384258d214df3d2d {
	meta:
		aliases = "wcschrnul, __GI_wcschrnul"
		size = "28"
		objfiles = "wcschrnul@libc.a"
	strings:
		$pattern = { 04 00 40 E2 04 30 B0 E5 00 00 53 E3 0E F0 A0 01 01 00 53 E1 FA FF FF 1A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule hstrerror_d2dcc9734dbf6e96e9675451fef007b1 {
	meta:
		aliases = "hstrerror"
		size = "28"
		objfiles = "herror@libc.a"
	strings:
		$pattern = { 04 00 50 E3 08 30 9F 95 08 00 9F 85 00 01 93 97 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_lock_06dd4d9577787e5f65e76491298a0952 {
	meta:
		aliases = "__pthread_lock"
		size = "8"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { 04 00 80 E2 D5 FF FF EA }
	condition:
		$pattern
}

rule _obstack_allocated_p_b7d1c4af255ae7c641162e3187f4f316 {
	meta:
		aliases = "_obstack_allocated_p"
		size = "44"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { 04 00 90 E5 00 00 50 E3 04 00 00 0A 01 00 50 E1 FA FF FF 2A 00 30 90 E5 01 00 53 E1 F7 FF FF 3A 00 00 50 E2 01 00 A0 13 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_fileno_unlocked_48692e10d5095bd6ca6baf01d63acc50 {
	meta:
		aliases = "fileno_unlocked, __GI_fileno_unlocked"
		size = "36"
		objfiles = "fileno_unlocked@libc.a"
	strings:
		$pattern = { 04 00 90 E5 00 00 50 E3 04 E0 2D E5 04 F0 9D A4 ?? ?? ?? EB 09 30 A0 E3 00 30 80 E5 00 00 E0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule __open_etc_hosts_7a22fecb716df5f21b01f4696c911f97 {
	meta:
		aliases = "__open_etc_hosts"
		size = "20"
		objfiles = "read_etc_hosts_r@libc.a"
	strings:
		$pattern = { 04 00 9F E5 04 10 9F E5 ?? ?? ?? EA ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svcudp_create_f8f9b8227ad35f4bc4d3729a86a7fbfd {
	meta:
		aliases = "__GI_svcudp_create, svcudp_create"
		size = "16"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { 04 10 9F E5 01 20 A0 E1 ?? ?? ?? EA 60 22 00 00 }
	condition:
		$pattern
}

rule tcdrain_da0e9556d0f25e7a5916446a9c84b251 {
	meta:
		aliases = "__libc_tcdrain, tcdrain"
		size = "16"
		objfiles = "tcdrain@libc.a"
	strings:
		$pattern = { 04 10 9F E5 01 20 A0 E3 ?? ?? ?? EA 09 54 00 00 }
	condition:
		$pattern
}

rule __stdio_init_mutex_5d9df10d8a6b93efc69db0c7a4b2bf1a {
	meta:
		aliases = "__stdio_init_mutex"
		size = "16"
		objfiles = "_stdio@libc.a"
	strings:
		$pattern = { 04 10 9F E5 18 20 A0 E3 ?? ?? ?? EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _obstack_memory_used_4d9090383d0762fcfc85109b99eda840 {
	meta:
		aliases = "_obstack_memory_used"
		size = "40"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { 04 20 90 E5 00 00 A0 E3 03 00 00 EA 00 30 92 E5 03 30 80 E0 03 00 62 E0 04 20 92 E5 00 00 52 E3 F9 FF FF 1A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_mutex_timedlock_fa18815b331602a4da7d28f204e0bbd2 {
	meta:
		aliases = "pthread_mutex_timedlock"
		size = "248"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { 04 20 91 E5 E8 30 9F E5 03 00 52 E1 70 40 2D E9 01 60 A0 E1 00 40 A0 E1 33 00 00 8A 0C 30 90 E5 03 00 53 E3 03 F1 9F 97 2F 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 10 00 80 E2 00 10 A0 E3 ?? ?? ?? EB 00 00 A0 E3 70 80 BD E8 96 FF FF EB 08 30 94 E5 00 00 53 E1 04 30 94 05 00 50 A0 E1 01 30 83 02 00 00 A0 03 05 00 00 0A 10 00 84 E2 05 10 A0 E1 ?? ?? ?? EB 00 30 A0 E3 08 50 84 E5 03 00 A0 E1 04 30 84 E5 70 80 BD E8 86 FF FF EB 08 30 94 E5 00 00 53 E1 00 50 A0 E1 23 00 A0 03 70 80 BD 08 06 20 A0 E1 10 00 84 E2 05 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 6E 00 80 02 00 00 A0 13 08 50 84 15 }
	condition:
		$pattern
}

rule globfree_160075541114568eaf84686c5688c956 {
	meta:
		aliases = "__GI_globfree, __GI_globfree64, globfree64, globfree"
		size = "84"
		objfiles = "glob64@libc.a, glob@libc.a"
	strings:
		$pattern = { 04 30 90 E5 00 00 53 E3 30 40 2D E9 00 40 A0 E1 00 50 A0 13 30 80 BD 08 05 00 00 EA 0C 00 94 E9 03 30 85 E0 03 31 92 E7 00 00 53 E2 01 50 85 E2 ?? ?? ?? 1B 00 30 94 E5 03 00 55 E1 F6 FF FF 3A 04 00 94 E5 ?? ?? ?? EB 00 30 A0 E3 04 30 84 E5 30 80 BD E8 }
	condition:
		$pattern
}

rule trecurse_00f7376cfc4be6552fd8684f02cea972 {
	meta:
		aliases = "trecurse"
		size = "148"
		objfiles = "twalk@libc.a"
	strings:
		$pattern = { 04 30 90 E5 00 00 53 E3 70 40 2D E9 00 40 A0 E1 01 60 A0 E1 02 50 A0 E1 03 00 00 1A 08 30 90 E5 00 00 53 E3 03 10 A0 03 16 00 00 0A 04 00 A0 E1 00 10 A0 E3 05 20 A0 E1 0F E0 A0 E1 06 F0 A0 E1 04 00 94 E5 00 00 50 E3 06 10 A0 11 01 20 85 12 EA FF FF 1B 04 00 A0 E1 01 10 A0 E3 05 20 A0 E1 0F E0 A0 E1 06 F0 A0 E1 08 00 94 E5 00 00 50 E3 06 10 A0 11 01 20 85 12 E0 FF FF 1B 04 00 A0 E1 05 20 A0 E1 02 10 A0 E3 0F E0 A0 E1 06 F0 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule pthread_rwlockattr_getpshared_b1929ea2af7ddfbad2e7cee3aaf5d5bb {
	meta:
		aliases = "pthread_attr_getschedpolicy, __GI_pthread_attr_getschedpolicy, pthread_rwlockattr_getpshared"
		size = "16"
		objfiles = "attr@libpthread.a, rwlock@libpthread.a"
	strings:
		$pattern = { 04 30 90 E5 00 00 A0 E3 00 30 81 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule get_cie_cafe7272f04a798ce866e6562d8f6a08 {
	meta:
		aliases = "get_cie"
		size = "16"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { 04 30 90 E5 04 00 80 E2 00 00 63 E0 0E F0 A0 E1 }
	condition:
		$pattern
}

rule wcpcpy_a5663bbf3b251e1b7f0104c7f752b406 {
	meta:
		aliases = "wcpcpy"
		size = "24"
		objfiles = "wcpcpy@libc.a"
	strings:
		$pattern = { 04 30 91 E4 00 00 53 E3 04 30 80 E4 FB FF FF 1A 04 00 40 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule _Unwind_SjLj_SetContext_0ff2ef98c5068cd8f437f3a75361a871 {
	meta:
		aliases = "_Unwind_SjLj_SetContext"
		size = "16"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { 04 30 9F E5 00 00 83 E5 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __libc_current_sigrtmin_5762a499c2b87f8f0b5af31c6e1fff14 {
	meta:
		aliases = "_Unwind_SjLj_GetContext, __libc_current_sigrtmax, __pthread_getconcurrency, pthread_getconcurrency, __libc_current_sigrtmin"
		size = "16"
		objfiles = "pthread@libpthread.a, unwind_sjlj@libgcc_eh.a, allocrtsig@libc.a"
	strings:
		$pattern = { 04 30 9F E5 00 00 93 E5 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _dl_app_fini_array_050e28cf6bc58150f630cc4dc9018b17 {
	meta:
		aliases = "_dl_app_init_array, getwchar_unlocked, getwchar, _dl_app_fini_array"
		size = "16"
		objfiles = "getwchar_unlocked@libc.a, libdl@libdl.a, getwchar@libc.a"
	strings:
		$pattern = { 04 30 9F E5 00 00 93 E5 ?? ?? ?? EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule putwchar_unlocked_4df5f60b2784cde730adc77cd4da8efb {
	meta:
		aliases = "putwchar_unlocked"
		size = "16"
		objfiles = "putwchar_unlocked@libc.a"
	strings:
		$pattern = { 04 30 9F E5 00 10 93 E5 ?? ?? ?? EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_execv_b1a59bedbd6958509ecb5f54b8dcbab4 {
	meta:
		aliases = "execv, __GI_execv"
		size = "16"
		objfiles = "execv@libc.a"
	strings:
		$pattern = { 04 30 9F E5 00 20 93 E5 ?? ?? ?? EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _dl_do_lazy_reloc_0f5f1faca28d4e20357979faa5c4e75f {
	meta:
		aliases = "_dl_do_lazy_reloc"
		size = "52"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 04 30 D2 E5 00 00 53 E3 00 00 90 E5 00 20 92 E5 03 00 A0 01 0E F0 A0 01 16 00 53 E3 00 30 92 07 00 30 83 00 00 30 82 07 00 00 E0 13 00 00 A0 03 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __negdi2_8aa9580306de287671f2c303c5d26929 {
	meta:
		aliases = "__negdi2"
		size = "40"
		objfiles = "_negdi2@libgcc.a"
	strings:
		$pattern = { 04 40 2D E5 00 30 A0 E1 00 20 61 E2 01 40 A0 E1 00 00 60 E2 00 00 53 E3 02 10 A0 01 01 10 42 12 10 00 BD E8 0E F0 A0 E1 }
	condition:
		$pattern
}

rule _dl_do_reloc_8dfad039b6b73ac73d3cf280d1847170 {
	meta:
		aliases = "_dl_do_reloc"
		size = "364"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 04 C0 92 E5 F0 4F 2D E9 2C B4 B0 E1 00 A0 A0 E1 03 50 A0 E1 00 80 90 E5 00 70 92 E5 FF 40 0C E2 04 60 93 05 1C 00 00 0A 0B 32 A0 E1 11 00 54 E3 16 00 54 13 03 C0 95 E7 03 90 85 E0 01 20 A0 03 03 00 00 0A 13 00 54 E3 12 00 54 13 00 20 A0 13 01 20 A0 03 14 00 54 E3 24 00 9D E5 02 30 A0 03 00 30 A0 13 02 30 83 E1 0C 00 80 E0 0A 20 A0 E1 ?? ?? ?? EB 00 60 50 E2 07 00 00 1A 0C 20 D9 E5 0F 30 02 E2 06 00 53 E3 03 00 00 0A 22 32 A0 E1 02 00 53 E3 01 00 80 12 F0 8F BD 18 14 00 54 E3 08 90 87 E0 22 00 00 0A 06 00 00 CA 01 00 54 E3 0D 00 00 0A 02 00 54 E3 08 00 00 0A 00 00 54 E3 25 00 00 0A 03 00 00 EA }
	condition:
		$pattern
}

rule inet_makeaddr_d04e68bac40850946c8110574aafc900 {
	meta:
		aliases = "__GI_inet_makeaddr, inet_makeaddr"
		size = "16"
		objfiles = "inet_addr@libc.a"
	strings:
		$pattern = { 04 D0 4D E2 00 00 9D E5 04 D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule strlcat_cd64962b53d3b8e402ed5618343b8078 {
	meta:
		aliases = "__GI_strlcat, strlcat"
		size = "88"
		objfiles = "strlcat@libc.a"
	strings:
		$pattern = { 04 D0 4D E2 00 C0 A0 E3 02 00 5C E1 03 00 8D 22 08 00 00 2A 00 30 D0 E5 00 00 53 E3 05 00 00 0A 01 00 80 E2 01 C0 8C E2 F6 FF FF EA 01 C0 8C E2 02 00 5C E1 01 00 80 32 00 30 D1 E5 00 00 53 E3 01 10 81 E2 00 30 C0 E5 F7 FF FF 1A 0C 00 A0 E1 04 D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule mknodat_a7d4d68355b066a1d7cb90adefb0a014 {
	meta:
		aliases = "__GI_mknodat, mknodat"
		size = "60"
		objfiles = "mknodat@libc.a"
	strings:
		$pattern = { 04 D0 4D E2 10 40 2D E9 08 30 8D E5 44 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 40 BD E8 04 D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pread64_e4189c72e0ead9c2a873ca010d1261bc {
	meta:
		aliases = "__libc_pread64, pread64"
		size = "56"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { 04 D0 4D E2 30 40 2D E9 08 D0 4D E2 14 30 8D E5 14 40 8D E2 30 00 94 E8 00 C0 A0 E3 04 30 A0 E1 20 10 8D E8 AC FF FF EB 08 D0 8D E2 30 40 BD E8 04 D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pwrite64_90e1a1947b60fe955e4e71a5d34b128e {
	meta:
		aliases = "__libc_pwrite64, pwrite64"
		size = "56"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { 04 D0 4D E2 30 40 2D E9 08 D0 4D E2 14 30 8D E5 14 40 8D E2 30 00 94 E8 01 C0 A0 E3 04 30 A0 E1 20 10 8D E8 BA FF FF EB 08 D0 8D E2 30 40 BD E8 04 D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule clntudp_create_a2173c75b3b2544054146bf439b99156 {
	meta:
		aliases = "__GI_clntudp_create, clntudp_create"
		size = "76"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { 04 D0 4D E2 30 40 2D E9 10 D0 4D E2 1C 30 8D E5 1C 40 8D E2 30 00 94 E8 28 E0 9F E5 24 C0 9D E5 04 30 A0 E1 04 C0 8D E5 0C E0 8D E5 08 E0 8D E5 00 50 8D E5 ?? ?? ?? EB 10 D0 8D E2 30 40 BD E8 04 D0 8D E2 0E F0 A0 E1 60 22 00 00 }
	condition:
		$pattern
}

rule __fake_pread_write64_539ed63f1da57176fc25436eca65f2ef {
	meta:
		aliases = "__fake_pread_write64"
		size = "236"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { 04 D0 4D E2 F0 41 2D E9 01 60 A0 E1 18 30 8D E5 02 70 A0 E1 01 30 A0 E3 00 10 A0 E3 00 20 A0 E3 00 80 A0 E1 ?? ?? ?? EB 01 00 70 E3 00 40 A0 E1 01 50 A0 E1 01 00 00 1A 01 00 71 E3 25 00 00 0A 18 10 8D E2 06 00 91 E8 08 00 A0 E1 00 30 A0 E3 ?? ?? ?? EB 01 00 70 E3 01 00 00 1A 01 00 71 E3 1C 00 00 0A 20 30 9D E5 01 00 53 E3 04 00 00 1A 06 10 A0 E1 07 20 A0 E1 08 00 A0 E1 ?? ?? ?? EB 03 00 00 EA 06 10 A0 E1 07 20 A0 E1 08 00 A0 E1 ?? ?? ?? EB 00 70 A0 E1 ?? ?? ?? EB 04 10 A0 E1 00 60 A0 E1 05 20 A0 E1 08 00 A0 E1 00 30 A0 E3 00 40 96 E5 ?? ?? ?? EB 01 00 70 E3 03 00 00 1A 01 00 71 E3 01 00 00 1A }
	condition:
		$pattern
}

rule pread64_55991f877ac975ef683892279da19ffd {
	meta:
		aliases = "pread64"
		size = "108"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { 04 D0 4D E2 F0 41 2D E9 08 D0 4D E2 20 30 8D E5 20 40 8D E2 30 00 94 E8 00 80 A0 E1 01 60 A0 E1 02 70 A0 E1 04 10 8D E2 01 00 A0 E3 ?? ?? ?? EB 04 30 A0 E1 06 10 A0 E1 07 20 A0 E1 08 00 A0 E1 00 50 8D E5 ?? ?? ?? EB 00 10 A0 E3 00 40 A0 E1 04 00 9D E5 ?? ?? ?? EB 04 00 A0 E1 08 D0 8D E2 F0 41 BD E8 04 D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule lldiv_98e21203c2dc0b9bca110029690ad847 {
	meta:
		aliases = "imaxdiv, lldiv"
		size = "148"
		objfiles = "lldiv@libc.a"
	strings:
		$pattern = { 04 D0 4D E2 F0 47 2D E9 20 30 8D E5 20 80 8D E2 00 03 98 E8 02 50 A0 E1 01 40 A0 E1 08 20 A0 E1 09 30 A0 E1 00 A0 A0 E1 01 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 08 20 A0 E1 00 60 A0 E1 01 70 A0 E1 04 00 A0 E1 05 10 A0 E1 09 30 A0 E1 ?? ?? ?? EB 00 00 55 E3 07 00 00 BA 00 00 51 E3 05 00 00 AA 01 30 A0 E3 03 60 96 E0 00 40 A0 E3 04 70 A7 E0 08 00 50 E0 09 10 C1 E0 08 00 8A E5 0C 10 8A E5 0A 00 A0 E1 C0 00 8A E8 F0 47 BD E8 04 D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule posix_fadvise64_cb5e967ba243bcee71c900c6a696df16 {
	meta:
		aliases = "posix_fadvise64"
		size = "92"
		objfiles = "posix_fadvise64@libc.a"
	strings:
		$pattern = { 04 D0 4D E2 F0 47 2D E9 20 30 8D E5 20 90 8D E2 00 06 99 E8 01 70 A0 E1 02 80 A0 E1 02 30 A0 E1 0A 50 A0 E1 CA 6F A0 E1 28 10 9D E5 07 20 A0 E1 09 40 A0 E1 0E 01 90 EF 01 0A 70 E3 02 00 00 9A 26 00 70 E3 00 00 60 12 00 00 00 1A 00 00 A0 E3 F0 47 BD E8 04 D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_clntudp_bufcreate_66013c6eaf6e1fe011c250f8838540bf {
	meta:
		aliases = "clntudp_bufcreate, __GI_clntudp_bufcreate"
		size = "620"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { 04 D0 4D E2 F0 4F 2D E9 00 40 A0 E1 40 D0 4D E2 0C 00 A0 E3 64 30 8D E5 01 B0 A0 E1 04 20 8D E5 6C 90 9D E5 ?? ?? ?? EB 70 30 9D E5 03 30 83 E2 03 80 C3 E3 74 30 9D E5 03 30 83 E2 00 60 A0 E1 03 70 C3 E3 64 00 88 E2 07 00 80 E0 ?? ?? ?? EB 00 00 50 E3 00 00 56 13 00 50 A0 E1 00 A0 A0 13 01 A0 A0 03 09 00 00 1A ?? ?? ?? EB E8 31 9F E5 00 40 A0 E1 00 10 93 E5 E0 01 9F E5 ?? ?? ?? EB 0C 30 A0 E3 08 30 84 E5 00 30 84 E5 65 00 00 EA 60 30 80 E2 07 30 83 E0 58 30 80 E5 02 20 D4 E5 03 30 D4 E5 03 34 92 E1 0D 00 00 1A 04 00 A0 E1 0B 10 A0 E1 04 20 9D E5 11 30 A0 E3 ?? ?? ?? EB 00 00 50 E3 57 00 00 0A }
	condition:
		$pattern
}

rule __pthread_initialize_minimal_c025254fa575624c5fbf6d3f8df32792 {
	meta:
		aliases = "__pthread_initialize_minimal"
		size = "28"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { 04 E0 2D E5 00 00 A0 E3 ?? ?? ?? EB 04 30 9F E5 00 00 83 E5 04 F0 9D E4 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_tzset_b3e2f75e3c6167be2ae1cefdae939e37 {
	meta:
		aliases = "tzset, __GI_tzset"
		size = "40"
		objfiles = "tzset@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 00 A0 E3 ?? ?? ?? EB 10 30 9F E5 03 00 50 E1 00 00 A0 C3 01 00 A0 D3 04 E0 9D E4 ?? ?? ?? EA FF 4E 98 45 }
	condition:
		$pattern
}

rule xdrstdio_putint32_354e427dddce3db9b91234379c0d5a09 {
	meta:
		aliases = "xdrstdio_putlong, xdrstdio_putint32"
		size = "84"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 10 91 E5 FF 28 01 E2 21 3C A0 E1 22 34 83 E1 FF 2C 01 E2 04 D0 4D E2 02 34 83 E1 01 3C 83 E1 04 20 8D E2 04 30 22 E5 04 10 A0 E3 0C 30 90 E5 01 20 A0 E3 0D 00 A0 E1 ?? ?? ?? EB 01 00 50 E3 00 00 A0 13 01 00 A0 03 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule xdr_float_fd43c97ebaf5e15684269d9117fe8779 {
	meta:
		aliases = "xdr_float"
		size = "68"
		objfiles = "xdr_float@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 20 90 E5 01 00 52 E3 08 00 00 0A 03 00 00 3A 02 00 52 E3 00 00 A0 13 01 00 A0 03 04 F0 9D E4 04 30 90 E5 0F E0 A0 E1 04 F0 93 E5 04 F0 9D E4 04 30 90 E5 0F E0 A0 E1 00 F0 93 E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule xdr_int32_t_99a596ac58c319eb3aff5ae9585822fc {
	meta:
		aliases = "xdr_uint32_t, xdr_int32_t"
		size = "68"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 20 90 E5 01 00 52 E3 08 00 00 0A 03 00 00 3A 02 00 52 E3 00 00 A0 13 01 00 A0 03 04 F0 9D E4 04 30 90 E5 0F E0 A0 E1 24 F0 93 E5 04 F0 9D E4 04 30 90 E5 0F E0 A0 E1 20 F0 93 E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule cfmakeraw_7389be8de53e2ae78c780d7d724dfa1e {
	meta:
		aliases = "cfmakeraw"
		size = "80"
		objfiles = "cfmakeraw@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 20 90 E5 0C 10 90 E5 08 C0 90 E5 04 E0 90 E5 00 30 A0 E3 5E 2E C2 E3 02 19 C1 E3 13 CE CC E3 0B 20 C2 E3 01 E0 CE E3 4B 10 C1 E3 30 C0 8C E3 16 30 C0 E5 01 30 83 E2 04 40 80 E8 0C 10 80 E5 08 C0 80 E5 17 30 C0 E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule putpwent_26188f99fc55636ae8898c7ff18f2cf3 {
	meta:
		aliases = "putpwent"
		size = "128"
		objfiles = "putpwent@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 20 A0 E1 00 00 51 E3 00 00 52 13 14 D0 4D E2 01 00 A0 E1 04 00 00 1A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 0F 00 00 EA 08 30 92 E5 00 30 8D E5 0C 30 92 E5 04 30 8D E5 10 30 92 E5 08 30 8D E5 14 30 92 E5 0C 30 8D E5 18 30 92 E5 10 30 8D E5 1C 10 9F E5 0C 00 92 E8 ?? ?? ?? EB 00 00 50 E3 00 20 E0 B3 00 20 A0 A3 02 00 A0 E1 14 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule glob_pattern_p_d8e6cf8ed5f22edef07aa0dab1d0410b {
	meta:
		aliases = "__GI_glob_pattern_p, glob_pattern_p"
		size = "144"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 20 A0 E1 00 C0 A0 E3 01 E0 A0 E3 18 00 00 EA 5B 00 50 E3 0A 00 00 0A 04 00 00 8A 2A 00 50 E3 17 00 00 0A 3F 00 50 E3 10 00 00 1A 14 00 00 EA 5C 00 50 E3 04 00 00 0A 5D 00 50 E3 0B 00 00 1A 08 00 00 EA 0E C0 A0 E1 08 00 00 EA 00 00 51 E3 06 00 00 0A 01 30 D2 E5 00 00 53 E3 01 30 82 E2 03 20 A0 11 01 00 00 EA 00 00 5C E3 04 00 00 1A 01 20 82 E2 00 00 D2 E5 00 00 50 E3 E3 FF FF 1A 04 F0 9D E4 01 00 A0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule __GI_svc_getreq_a5523e5f377c1a4d487a9bc2366fc462 {
	meta:
		aliases = "svc_getreq, __GI_svc_getreq"
		size = "64"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 20 A0 E3 00 10 A0 E1 80 D0 4D E2 02 00 A0 E1 80 C0 8D E2 02 31 8C E0 01 20 82 E2 1F 00 52 E3 80 00 03 E5 F9 FF FF 9A 0D 00 A0 E1 00 10 8D E5 ?? ?? ?? EB 80 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule wcswidth_20bb2272596b9cd4e80a3647909c3400 {
	meta:
		aliases = "__GI_wcswidth, wcswidth"
		size = "148"
		objfiles = "wcswidth@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 20 A0 E3 00 E0 A0 E1 01 00 00 EA 0C 00 53 E1 1C 00 00 1A 01 00 52 E1 10 00 00 2A 02 31 9E E7 00 00 53 E3 7F C0 03 E2 01 20 82 E2 F6 FF FF 1A 0A 00 00 EA FF 00 52 E3 01 00 80 E2 11 00 00 CA 20 00 53 E3 00 30 A0 83 01 30 A0 93 1F 00 52 E3 01 30 83 D3 00 00 53 E3 0A 00 00 1A 00 00 00 EA 00 00 A0 E3 00 00 51 E3 01 10 41 E2 04 F0 9D 04 00 20 9E E5 00 00 52 E3 7F 30 42 E2 04 E0 8E E2 EB FF FF 1A 04 F0 9D E4 00 00 E0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule xdrstdio_setpos_90a11197d95ac245c9ae537f0825f209 {
	meta:
		aliases = "xdrstdio_setpos"
		size = "28"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 20 A0 E3 0C 00 90 E5 ?? ?? ?? EB 00 00 E0 E1 A0 0F A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule xdr_wrapstring_26970f400783ec1068363a60740854f1 {
	meta:
		aliases = "xdr_wrapstring"
		size = "24"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 20 E0 E3 ?? ?? ?? EB 00 00 50 E2 01 00 A0 13 04 F0 9D E4 }
	condition:
		$pattern
}

rule xdr_long_a7dfb98fbe1353d807e7b2a7ce0f51c5 {
	meta:
		aliases = "__GI_xdr_long, xdr_long"
		size = "72"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 30 90 E5 00 00 53 E3 03 00 00 1A 04 30 90 E5 0F E0 A0 E1 04 F0 93 E5 04 F0 9D E4 01 00 53 E3 03 00 00 1A 04 30 90 E5 0F E0 A0 E1 00 F0 93 E5 04 F0 9D E4 02 00 53 E3 00 00 A0 13 01 00 A0 03 04 F0 9D E4 }
	condition:
		$pattern
}

rule xdrrec_inline_4f3789a942b2fba8e46779e99a6f2062 {
	meta:
		aliases = "xdrrec_inline"
		size = "112"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 30 90 E5 00 00 53 E3 0C 20 90 E5 02 00 00 0A 01 00 53 E3 12 00 00 1A 06 00 00 EA 10 00 82 E2 09 00 90 E8 01 10 80 E0 03 00 51 E1 10 10 82 95 04 F0 9D 94 0A 00 00 EA 34 E0 92 E5 0E 00 51 E1 07 00 00 8A 2C 00 82 E2 09 00 90 E8 01 C0 80 E0 03 00 5C E1 0E 30 61 90 2C C0 82 95 34 30 82 95 04 F0 9D 94 00 00 A0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule brk_2051d3115b995997700bb9d99c44224f {
	meta:
		aliases = "__GI_brk, brk"
		size = "56"
		objfiles = "brk@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 30 A0 E1 2D 00 90 EF 03 00 50 E1 1C 30 9F E5 00 00 83 E5 00 00 A0 23 04 F0 9D 24 ?? ?? ?? EB 0C 30 A0 E3 00 30 80 E5 00 00 E0 E3 04 F0 9D E4 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_sigblock_4c924cf95e5d1288a7fc528df0e1a408 {
	meta:
		aliases = "sigblock, __GI_sigblock"
		size = "48"
		objfiles = "sigblock@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 30 A0 E3 10 D0 4D E2 08 00 8D E5 08 10 8D E2 03 00 A0 E1 0D 20 A0 E1 0C 30 8D E5 ?? ?? ?? EB 00 00 9D E5 10 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule ualarm_6da659f59c67df33a9b06f705cda1beb {
	meta:
		aliases = "ualarm"
		size = "80"
		objfiles = "ualarm@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 30 A0 E3 20 D0 4D E2 10 20 8D E2 04 10 8D E5 0C 00 8D E5 0D 10 A0 E1 03 00 A0 E1 00 30 8D E5 08 30 8D E5 ?? ?? ?? EB 00 00 50 E3 18 10 9D A5 10 20 9F A5 1C 30 9D A5 91 32 20 A0 00 00 E0 B3 20 D0 8D E2 00 80 BD E8 40 42 0F 00 }
	condition:
		$pattern
}

rule wcswcs_c24dc77fdb81feebfd647206e579a11d {
	meta:
		aliases = "wcsstr, wcswcs"
		size = "80"
		objfiles = "wcsstr@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 C0 A0 E1 00 20 A0 E1 01 30 A0 E1 00 E0 93 E5 00 00 5E E3 04 30 83 E2 01 00 00 1A 0C 00 A0 E1 04 F0 9D E4 00 00 92 E5 00 00 5E E1 04 20 82 E2 F5 FF FF 0A 04 C0 8C E2 00 00 50 E3 0C 20 A0 E1 01 30 A0 E1 F0 FF FF 1A 04 F0 9D E4 }
	condition:
		$pattern
}

rule __GI_stpncpy_d8caebb526cb423242b15226d414e77a {
	meta:
		aliases = "stpncpy, __GI_stpncpy"
		size = "64"
		objfiles = "stpncpy@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 C0 A0 E1 00 E0 A0 E1 01 00 A0 E1 04 00 00 EA 00 30 D0 E5 00 00 53 E3 00 30 CC E5 01 00 80 12 01 C0 8C E2 00 00 52 E3 01 20 42 E2 F7 FF FF 1A 00 00 61 E0 00 00 8E E0 04 F0 9D E4 }
	condition:
		$pattern
}

rule __get_hosts_byname_r_d2837574211a5d24948e667ba4e6e1b9 {
	meta:
		aliases = "__get_hosts_byname_r"
		size = "72"
		objfiles = "get_hosts_byname_r@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 C0 A0 E1 14 D0 4D E2 01 E0 A0 E1 0C 10 A0 E1 18 C0 9D E5 08 C0 8D E5 1C C0 9D E5 00 00 A0 E3 0C C0 8D E5 20 C0 9D E5 0C 00 8D E8 0E 20 A0 E1 00 30 A0 E1 10 C0 8D E5 ?? ?? ?? EB 14 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __libc_pread_26f83caaec103a020907a680b9b7f228 {
	meta:
		aliases = "pread, __libc_pread"
		size = "28"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 C0 A0 E3 04 D0 4D E2 00 C0 8D E5 C5 FF FF EB 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule mq_send_34983e4a6eddf636c1210e403db40ad6 {
	meta:
		aliases = "mq_receive, mq_send"
		size = "28"
		objfiles = "mq_send@librt.a, mq_receive@librt.a"
	strings:
		$pattern = { 04 E0 2D E5 00 C0 A0 E3 04 D0 4D E2 00 C0 8D E5 EE FF FF EB 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule mkfifoat_3a955b7ca863869d4cfd906031db6f81 {
	meta:
		aliases = "mkfifoat"
		size = "36"
		objfiles = "mkfifoat@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 C0 A0 E3 04 D0 4D E2 0C 30 A0 E1 01 2A 82 E3 00 C0 8D E5 ?? ?? ?? EB 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __GI_getopt_427c5a3de4a2b9d3a5f1e7f43531ff05 {
	meta:
		aliases = "getopt, __GI_getopt"
		size = "36"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 C0 A0 E3 08 D0 4D E2 0C 30 A0 E1 00 C0 8D E5 04 C0 8D E5 ?? ?? ?? EB 08 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule a64l_ef47a3f83dc5d645bd0745128399644d {
	meta:
		aliases = "a64l"
		size = "84"
		objfiles = "a64l@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 C0 A0 E3 40 E0 9F E5 00 20 A0 E1 0C 10 A0 E1 06 00 80 E2 00 30 D2 E5 2E 30 43 E2 4C 00 53 E3 01 20 82 E2 06 00 00 8A 03 30 DE E7 40 00 53 E3 03 00 00 0A 00 00 52 E1 13 C1 8C E1 06 10 81 E2 F3 FF FF 1A 0C 00 A0 E1 04 F0 9D E4 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wcsspn_34fc412af6f95f977ecc2a41a86f2114 {
	meta:
		aliases = "__GI_wcsspn, wcsspn"
		size = "60"
		objfiles = "wcsspn@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 E0 A0 E1 03 00 00 EA 00 30 90 E5 03 00 5C E1 01 00 00 1A 04 00 80 E2 01 20 A0 E1 00 C0 92 E5 00 00 5C E3 04 20 82 E2 F6 FF FF 1A 00 00 6E E0 40 01 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule wcscspn_887e7fdd1ab60f64e1a76b1c43340c69 {
	meta:
		aliases = "wcscspn"
		size = "68"
		objfiles = "wcscspn@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 E0 A0 E1 06 00 00 EA 0C 00 52 E1 08 00 00 0A 00 20 93 E5 00 00 52 E3 04 30 83 E2 F9 FF FF 1A 04 00 80 E2 00 C0 90 E5 00 00 5C E3 01 30 A0 11 F6 FF FF 1A 00 00 6E E0 40 01 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule wcpncpy_98f1b757a68cbf0c0463587e0eeb5ce3 {
	meta:
		aliases = "wcpncpy"
		size = "64"
		objfiles = "wcpncpy@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 E0 A0 E1 0E C0 A0 E1 01 00 A0 E1 04 00 00 EA 00 30 90 E5 00 00 53 E3 00 30 8C E5 04 00 80 12 04 C0 8C E2 00 00 52 E3 01 20 42 E2 F7 FF FF 1A 00 00 61 E0 00 00 8E E0 04 F0 9D E4 }
	condition:
		$pattern
}

rule check_match_8333436203fdac31511c0ea515c22eee {
	meta:
		aliases = "check_match"
		size = "136"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 04 E0 2D E5 00 E0 A0 E1 0F C0 DE E5 0E 00 D0 E5 0C C4 90 E1 00 30 A0 13 01 30 03 02 00 00 53 E3 15 00 00 1A 04 30 9E E5 00 00 53 E3 12 00 00 0A 0C 30 DE E5 0F 30 03 E2 05 00 53 E3 02 00 53 13 0D 00 00 CA 00 30 9E E5 03 30 81 E0 01 10 43 E2 01 20 42 E2 01 C0 F1 E5 00 00 5C E3 01 00 F2 E5 00 30 60 02 02 00 00 0A 00 00 5C E1 F8 FF FF 0A 0C 30 60 E0 00 00 53 E3 00 00 00 0A 00 E0 A0 E3 0E 00 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule strspn_96986ac56104a55f0095f0874fdc550c {
	meta:
		aliases = "__GI_strspn, strspn"
		size = "72"
		objfiles = "strspn@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 E0 A0 E3 08 00 00 EA 02 00 5C E1 04 00 00 0A 00 20 D3 E5 00 00 52 E3 01 30 83 E2 F9 FF FF 1A 05 00 00 EA 01 E0 8E E2 01 00 80 E2 00 C0 D0 E5 00 00 5C E3 01 30 A0 11 F4 FF FF 1A 0E 00 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule read_sleb128_12b5f4ea8b9edcb09e9e5efd10d71575 {
	meta:
		aliases = "read_sleb128"
		size = "72"
		objfiles = "unwind_c@libgcc_eh.a, unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { 04 E0 2D E5 00 E0 A0 E3 0E C0 A0 E1 01 20 D0 E4 7F 30 02 E2 80 00 12 E3 13 EC 8E E1 07 C0 8C E2 F9 FF FF 1A 1F 00 5C E3 04 00 00 8A 40 00 12 E3 01 30 A0 13 13 3C A0 11 00 30 63 12 0E E0 83 11 00 E0 81 E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule __rpc_thread_svc_cleanup_3ba2838890ab11de0551c4feb090e943 {
	meta:
		aliases = "__rpc_thread_svc_cleanup"
		size = "36"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 00 00 EA 03 00 93 E9 ?? ?? ?? EB ?? ?? ?? EB B8 30 90 E5 00 00 53 E3 F9 FF FF 1A 04 F0 9D E4 }
	condition:
		$pattern
}

rule __sysv_signal_eb40e7ddfdabd3ec7f2f937a7b4e192a {
	meta:
		aliases = "sysv_signal, __sysv_signal"
		size = "116"
		objfiles = "sysv_signal@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 00 71 E3 00 00 50 13 28 D0 4D E2 01 30 A0 E1 00 C0 A0 C3 01 C0 A0 D3 01 00 00 DA 40 00 50 E3 04 00 00 DA ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 0A 00 00 EA 0D 20 A0 E1 14 30 8D E5 14 10 8D E2 0E 32 A0 E3 24 C0 8D E5 18 30 8D E5 20 C0 8D E5 ?? ?? ?? EB 00 00 50 E3 00 20 9D A5 00 20 E0 B3 02 00 A0 E1 28 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule clnttcp_control_5fc512e79f9e968856e6076341545ed3 {
	meta:
		aliases = "clnttcp_control"
		size = "380"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 10 41 E2 02 C0 A0 E1 08 00 90 E5 0E 00 51 E3 01 F1 9F 97 0E 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 E0 A0 E3 44 00 00 EA 01 30 A0 E3 03 E0 A0 E1 01 00 00 EA 01 E0 A0 E3 00 30 A0 E3 04 30 80 E5 3D 00 00 EA 0A 00 92 E8 01 20 A0 E3 02 E0 A0 E1 0C 30 80 E5 08 10 80 E5 10 20 80 E5 36 00 00 EA 0C 20 90 E5 08 30 90 E5 01 E0 A0 E3 00 30 8C E5 04 20 8C E5 30 00 00 EA 14 30 80 E2 0F 00 93 E8 01 E0 A0 E3 0F 00 8C E8 2B 00 00 EA 00 30 90 E5 }
	condition:
		$pattern
}

rule clntudp_control_de112724e679a6c08259dc82f59aa1ad {
	meta:
		aliases = "clntudp_control"
		size = "436"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 10 41 E2 02 C0 A0 E1 08 00 90 E5 0E 00 51 E3 01 F1 9F 97 0E 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 E0 A0 E3 52 00 00 EA 01 30 A0 E3 03 E0 A0 E1 01 00 00 EA 01 E0 A0 E3 00 30 A0 E3 04 30 80 E5 4B 00 00 EA 04 20 92 E5 00 30 9C E5 01 E0 A0 E3 24 30 80 E5 28 20 80 E5 45 00 00 EA 28 20 90 E5 24 30 90 E5 07 00 00 EA 04 20 92 E5 00 30 9C E5 01 E0 A0 E3 1C 30 80 E5 20 20 80 E5 3C 00 00 EA 20 20 90 E5 1C 30 90 E5 01 E0 A0 E3 00 30 8C E5 }
	condition:
		$pattern
}

rule clntunix_control_aa81cf50da7ba43cc0a981a349cbb49f {
	meta:
		aliases = "clntunix_control"
		size = "376"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 10 41 E2 02 E0 A0 E1 08 C0 90 E5 0E 00 51 E3 01 F1 9F 97 0E 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 A0 E3 04 F0 9D E4 01 30 A0 E3 03 00 A0 E1 01 00 00 EA 01 00 A0 E3 00 30 A0 E3 04 30 8C E5 04 F0 9D E4 04 20 92 E5 00 30 9E E5 01 00 A0 E3 08 30 8C E5 0C 20 8C E5 04 F0 9D E4 0C 20 9C E5 08 30 9C E5 01 00 A0 E3 00 30 8E E5 04 20 8E E5 04 F0 9D E4 02 00 A0 E1 14 10 8C E2 70 20 A0 E3 ?? ?? ?? EB 01 00 A0 E3 04 F0 9D E4 00 30 9C E5 }
	condition:
		$pattern
}

rule __GI_svcerr_auth_291f45ce3c28f458eb2510a1a7c5e094 {
	meta:
		aliases = "svcerr_auth, __GI_svcerr_auth"
		size = "52"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 30 A0 E3 30 D0 4D E2 10 10 8D E5 0C 30 8D E5 04 30 8D E5 08 30 8D E5 0D 10 A0 E1 08 30 90 E5 0F E0 A0 E1 0C F0 93 E5 30 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule re_match_f3d34dc768ba35fabb07d173e9ffd9ad {
	meta:
		aliases = "re_match"
		size = "60"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 C0 A0 E1 10 D0 4D E2 00 10 A0 E3 04 30 8D E5 0C 30 A0 E1 14 C0 9D E5 02 E0 A0 E1 01 20 A0 E1 08 C0 8D E5 0C E0 8D E5 00 E0 8D E5 9D F8 FF EB 10 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule re_search_de99b3bc9eb29b2ed745888652e52299 {
	meta:
		aliases = "__GI_re_search, re_search"
		size = "68"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 C0 A0 E1 14 D0 4D E2 04 30 8D E5 0C 30 A0 E1 18 C0 9D E5 00 10 A0 E3 08 C0 8D E5 1C C0 9D E5 02 E0 A0 E1 01 20 A0 E1 0C C0 8D E5 10 E0 8D E5 00 E0 8D E5 ?? ?? ?? EB 14 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule pwrite_c204c8400d1e1461096a5e652e43bd48 {
	meta:
		aliases = "__libc_pwrite, pwrite"
		size = "28"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 C0 A0 E3 04 D0 4D E2 00 C0 8D E5 CC FF FF EB 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule re_compile_pattern_dfd341d8aac0e4177eddd0a95a501e87 {
	meta:
		aliases = "re_compile_pattern"
		size = "112"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 02 30 A0 E1 1C 20 D2 E5 06 20 C2 E3 1C 20 C3 E5 1C 20 D3 E5 10 20 C2 E3 1C 20 C3 E5 1C 20 D3 E5 80 20 82 E3 1C 20 C3 E5 30 20 9F E5 00 20 92 E5 A2 F6 FF EB 00 00 50 E3 04 F0 9D 04 20 20 9F E5 80 30 A0 E1 02 10 83 E0 02 30 D3 E7 01 20 D1 E5 02 34 83 E1 0C 20 9F E5 02 00 83 E0 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdr_free_81651331693e27fcabde4da201a082a4 {
	meta:
		aliases = "xdr_free"
		size = "40"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 02 30 A0 E3 18 D0 4D E2 00 20 A0 E1 00 30 8D E5 0D 00 A0 E1 0F E0 A0 E1 02 F0 A0 E1 18 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule byte_insert_op1_31a252922707c965a7e52797c44a2e3a {
	meta:
		aliases = "byte_insert_op1"
		size = "40"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 03 C0 A0 E1 03 E0 83 E2 01 00 00 EA 01 30 7C E5 01 30 6E E5 01 00 5C E1 FB FF FF 1A 04 E0 9D E4 E7 FF FF EA }
	condition:
		$pattern
}

rule get_shm_name_176d83281fe2819e4c90ebc8415ef60d {
	meta:
		aliases = "get_shm_name"
		size = "68"
		objfiles = "shm@librt.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 00 00 00 EA 01 00 80 E2 00 30 D0 E5 2F 00 53 E3 FB FF FF 0A 00 20 A0 E1 18 10 9F E5 0D 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 9D A5 00 00 A0 B3 04 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wcsrtombs_bf53f3b73ff890a3d97f7f3c4b853e0c {
	meta:
		aliases = "__GI_wcsrtombs, wcsrtombs"
		size = "32"
		objfiles = "wcsrtombs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 00 30 8D E5 02 30 A0 E1 00 20 E0 E3 ?? ?? ?? EB 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule getw_f3cabe46ebc157e519ac4ac36d2b1272 {
	meta:
		aliases = "getw"
		size = "48"
		objfiles = "getw@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 00 30 A0 E1 04 10 A0 E3 0D 00 A0 E1 01 20 A0 E3 ?? ?? ?? EB 00 00 50 E3 00 00 9D 15 00 00 E0 03 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule putw_75674ae7279d352da248f33ebc2f5a23 {
	meta:
		aliases = "putw"
		size = "48"
		objfiles = "putw@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 04 20 8D E2 04 00 22 E5 01 30 A0 E1 0D 00 A0 E1 04 10 A0 E3 01 20 A0 E3 ?? ?? ?? EB 01 00 40 E2 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule tcsetpgrp_f455fe420e2bbd87dc63af0d79c2a534 {
	meta:
		aliases = "tcsetpgrp"
		size = "40"
		objfiles = "tcsetpgrp@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 04 20 8D E2 04 10 22 E5 0D 20 A0 E1 08 10 9F E5 ?? ?? ?? EB 04 D0 8D E2 00 80 BD E8 10 54 00 00 }
	condition:
		$pattern
}

rule wcwidth_17c0d28adb59757386ed5185cab4089a {
	meta:
		aliases = "wcwidth"
		size = "36"
		objfiles = "wcwidth@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 04 30 8D E2 04 00 23 E5 01 10 A0 E3 0D 00 A0 E1 ?? ?? ?? EB 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __GI_fputwc_unlocked_7caa6be5d6b3a9130f4263d980dd8a3c {
	meta:
		aliases = "fputwc_unlocked, putwc_unlocked, __GI_fputwc_unlocked"
		size = "52"
		objfiles = "fputwc_unlocked@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 04 30 8D E2 04 00 23 E5 01 20 A0 E1 0D 00 A0 E1 01 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 00 00 9D 15 00 00 E0 03 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule wcstombs_080aca4bd2c7ad3b67c6f34872f563a6 {
	meta:
		aliases = "wcstombs"
		size = "36"
		objfiles = "wcstombs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 04 30 8D E2 04 10 23 E5 0D 10 A0 E1 00 30 A0 E3 ?? ?? ?? EB 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __GI_inet_addr_7fdd0658971bb539d45b78cafcda374f {
	meta:
		aliases = "inet_addr, __GI_inet_addr"
		size = "36"
		objfiles = "inet_makeaddr@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 0D 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 9D 15 00 00 E0 03 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule nrand48_ecd7978fb77bf0d3de708665c907813c {
	meta:
		aliases = "jrand48, nrand48"
		size = "36"
		objfiles = "jrand48@libc.a, nrand48@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 10 10 9F E5 0D 20 A0 E1 ?? ?? ?? EB 00 00 9D E5 04 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getpwent_1130adb5b3a29e916cfe3279f1af88f3 {
	meta:
		aliases = "getspent, getgrent, getpwent"
		size = "48"
		objfiles = "getgrent@libc.a, getpwent@libc.a, getspent@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 18 10 9F E5 01 2C A0 E3 0D 30 A0 E1 10 00 9F E5 ?? ?? ?? EB 00 00 9D E5 04 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tcgetpgrp_6df4fc4afad056198489592ff1c09cbe {
	meta:
		aliases = "__GI_tcgetpgrp, tcgetpgrp"
		size = "44"
		objfiles = "tcgetpgrp@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 18 10 9F E5 0D 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 9D A5 00 00 E0 B3 04 D0 8D E2 00 80 BD E8 0F 54 00 00 }
	condition:
		$pattern
}

rule getservent_74633c979fb7ddddae811dd3f3c46d83 {
	meta:
		aliases = "getservent"
		size = "60"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 5D FF FF EB 1C 30 9F E5 1C 20 9F E5 00 10 93 E5 18 00 9F E5 0D 30 A0 E1 ?? ?? ?? EB 00 00 9D E5 04 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? 8D 10 00 00 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getprotoent_dc0cfd389162bba61098ba235f692fad {
	meta:
		aliases = "getprotoent"
		size = "60"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 66 FF FF EB 1C 30 9F E5 1C 20 9F E5 00 10 93 E5 18 00 9F E5 0D 30 A0 E1 ?? ?? ?? EB 00 00 9D E5 04 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? 8D 10 00 00 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule call_frame_dummy_997de91c60dfeaa7966cf399b0caa4a3 {
	meta:
		aliases = "call___do_global_ctors_aux, call_frame_dummy"
		size = "8"
		objfiles = "crtbeginS, crtbeginT, crtend, crtbegin, crtendS"
	strings:
		$pattern = { 04 E0 2D E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule call___do_global_dtors_aux_5d697322d488efe51efcff4b754af832 {
	meta:
		aliases = "call___do_global_dtors_aux"
		size = "140"
		objfiles = "crtbeginS"
	strings:
		$pattern = { 04 E0 2D E5 04 F0 9D E4 10 40 2D E9 58 40 9F E5 58 30 9F E5 04 40 8F E0 03 30 94 E7 00 00 53 E3 05 00 00 0A 48 00 9F E5 48 10 9F E5 00 00 84 E0 01 10 84 E0 0F E0 A0 E1 03 F0 A0 E1 38 20 9F E5 02 30 94 E7 00 00 53 E3 02 00 84 E0 10 80 BD 08 28 30 9F E5 03 10 94 E7 00 00 51 E3 10 80 BD 08 0F E0 A0 E1 01 F0 A0 E1 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 E0 2D E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule call___do_global_dtors_aux_02b40f05b3da84d0132fa6c9fa3d96d2 {
	meta:
		aliases = "call___do_global_dtors_aux"
		size = "104"
		objfiles = "crtbegin, crtbeginT"
	strings:
		$pattern = { 04 E0 2D E5 04 F0 9D E4 3C 30 9F E5 00 00 53 E3 04 E0 2D E5 34 00 9F 15 34 10 9F 15 0F E0 A0 11 03 F0 A0 11 2C 00 9F E5 00 30 90 E5 00 00 53 E3 04 F0 9D 04 20 30 9F E5 00 00 53 E3 04 F0 9D 04 0F E0 A0 E1 03 F0 A0 E1 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 E0 2D E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule clntudp_freeres_e32521f7e234e1c5e6fb5032faf24d43 {
	meta:
		aliases = "clntudp_freeres"
		size = "36"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 08 00 90 E5 02 30 A0 E3 38 30 A0 E5 01 30 A0 E1 02 10 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule clnttcp_freeres_bbe454e01d17ead139d8f506d2090f68 {
	meta:
		aliases = "clnttcp_freeres"
		size = "36"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 08 00 90 E5 02 30 A0 E3 4C 30 A0 E5 01 30 A0 E1 02 10 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule clntunix_freeres_44bc27ad01720c1dc9d8bc75f6c50187 {
	meta:
		aliases = "clntunix_freeres"
		size = "36"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 08 00 90 E5 02 30 A0 E3 AC 30 A0 E5 01 30 A0 E1 02 10 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule getspnam_782ead4dc851d14a304b763550b392bd {
	meta:
		aliases = "fgetgrent, getgrnam, getpwnam, getgrgid, fgetspent, sgetspent, getpwuid, fgetpwent, getspnam"
		size = "52"
		objfiles = "fgetpwent@libc.a, fgetspent@libc.a, fgetgrent@libc.a, getgrgid@libc.a, getspnam@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 08 D0 4D E2 04 C0 8D E2 18 10 9F E5 18 20 9F E5 01 3C A0 E3 00 C0 8D E5 ?? ?? ?? EB 04 00 9D E5 08 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getopt_long_d38bf0b6e9b9183d73259d861eace776 {
	meta:
		aliases = "getopt_long"
		size = "36"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 08 D0 4D E2 0C C0 9D E5 00 C0 8D E5 00 C0 A0 E3 04 C0 8D E5 ?? ?? ?? EB 08 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule getopt_long_only_38a9d032ec497764ae5be9cd75556e22 {
	meta:
		aliases = "getopt_long_only"
		size = "36"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 08 D0 4D E2 0C C0 9D E5 00 C0 8D E5 01 C0 A0 E3 04 C0 8D E5 ?? ?? ?? EB 08 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __GI_getdtablesize_4afae0664d18865adaff58386ce86a79 {
	meta:
		aliases = "getdtablesize, __GI_getdtablesize"
		size = "40"
		objfiles = "getdtablesize@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 08 D0 4D E2 0D 10 A0 E1 07 00 A0 E3 ?? ?? ?? EB 00 00 50 E3 00 00 9D A5 01 0C A0 B3 08 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule erand48_04367cf366455c19d8d73c4548bbfbe4 {
	meta:
		aliases = "erand48"
		size = "36"
		objfiles = "erand48@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 08 D0 4D E2 10 10 9F E5 0D 20 A0 E1 ?? ?? ?? EB 03 00 9D E8 08 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule gethostent_42758989f111945a73cfb4868cbedd74 {
	meta:
		aliases = "gethostent"
		size = "56"
		objfiles = "gethostent@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 08 D0 4D E2 ?? ?? ?? EB 1C 10 9F E5 00 00 8D E5 8A 20 A0 E3 04 30 8D E2 10 00 9F E5 ?? ?? ?? EB 04 00 9D E5 08 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __opensock_ce5476bdb8f54e36bfbab9333e588a10 {
	meta:
		aliases = "__opensock"
		size = "48"
		objfiles = "opensock@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 0A 00 A0 E3 02 10 A0 E3 00 20 A0 E3 ?? ?? ?? EB 00 00 50 E3 04 F0 9D A4 02 00 A0 E3 00 10 A0 E1 00 20 A0 E3 04 E0 9D E4 ?? ?? ?? EA }
	condition:
		$pattern
}

rule setrlimit64_95b3f008fb2d1ba85a4aace37709873a {
	meta:
		aliases = "setrlimit64"
		size = "108"
		objfiles = "setrlimit64@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 0C 00 91 E8 00 00 53 E3 08 D0 4D E2 02 00 00 8A 04 00 00 1A 02 00 72 E3 02 00 00 9A 00 30 E0 E3 00 30 8D E5 00 00 00 EA 00 20 8D E5 08 10 81 E2 06 00 91 E8 00 00 52 E3 02 00 00 8A 04 00 00 1A 02 00 71 E3 02 00 00 9A 00 30 E0 E3 04 30 8D E5 00 00 00 EA 04 10 8D E5 0D 10 A0 E1 ?? ?? ?? EB 08 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __gthread_mutex_unlock_6de4a177e5599d1717ee99c55f58ac5a {
	meta:
		aliases = "__gthread_mutex_lock, __gthread_mutex_unlock"
		size = "28"
		objfiles = "gthr_gnat@libgcc_eh.a"
	strings:
		$pattern = { 04 E0 2D E5 0C 30 9F E5 0F E0 A0 E1 00 F0 93 E5 00 00 A0 E3 04 F0 9D E4 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mbstowcs_c3e2307a05e79e376249f3bce0076917 {
	meta:
		aliases = "mbstowcs"
		size = "40"
		objfiles = "mbstowcs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 0C D0 4D E2 08 10 8D E5 00 C0 A0 E3 08 10 8D E2 0D 30 A0 E1 00 C0 8D E5 ?? ?? ?? EB 0C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule rexec_3fa6f8ff0f5d2ab4ce093d38b16c4c69 {
	meta:
		aliases = "rexec"
		size = "44"
		objfiles = "rexec@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 0C D0 4D E2 10 C0 9D E5 00 C0 8D E5 14 C0 9D E5 04 C0 8D E5 02 C0 A0 E3 08 C0 8D E5 ?? ?? ?? EB 0C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __ivaliduser_62f506ae5f20951599d7a66ca48a31d6 {
	meta:
		aliases = "__ivaliduser"
		size = "32"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 10 C0 9F E5 04 D0 4D E2 00 C0 8D E5 2D FF FF EB 04 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule iruserok_93568486ea013ef08f82f5385519c4a5 {
	meta:
		aliases = "iruserok"
		size = "32"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 10 C0 9F E5 04 D0 4D E2 00 C0 8D E5 9E FF FF EB 04 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_sigsetmask_4ea223288341908e6ba5aacb9e20032a {
	meta:
		aliases = "sigsetmask, __GI_sigsetmask"
		size = "48"
		objfiles = "sigsetmask@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 10 D0 4D E2 08 00 8D E5 00 30 A0 E3 08 10 8D E2 0D 20 A0 E1 02 00 A0 E3 0C 30 8D E5 ?? ?? ?? EB 00 00 9D E5 10 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule clock_dcd23ec0036239d0607cbce0f0d31ea4 {
	meta:
		aliases = "clock"
		size = "48"
		objfiles = "clock@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 10 D0 4D E2 0D 00 A0 E1 ?? ?? ?? EB 0C 00 9D E8 02 30 83 E0 0C 20 9F E5 93 02 00 E0 3E 01 C0 E3 10 D0 8D E2 00 80 BD E8 10 27 00 00 }
	condition:
		$pattern
}

rule mrand48_86fdf4ee84ebc235f19e8e735c9d8875 {
	meta:
		aliases = "lrand48, mrand48"
		size = "40"
		objfiles = "mrand48@libc.a, lrand48@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 18 00 9F E5 04 D0 4D E2 00 10 A0 E1 0D 20 A0 E1 ?? ?? ?? EB 00 00 9D E5 04 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule drand48_4e1497ff0ffd39d4b7a374652bb452f3 {
	meta:
		aliases = "drand48"
		size = "40"
		objfiles = "drand48@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 18 00 9F E5 08 D0 4D E2 00 10 A0 E1 0D 20 A0 E1 ?? ?? ?? EB 03 00 9D E8 08 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ptsname_78b8866959beb177db3ee802e53dd52c {
	meta:
		aliases = "ptsname"
		size = "40"
		objfiles = "ptsname@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 18 10 9F E5 1E 20 A0 E3 ?? ?? ?? EB 0C 30 9F E5 00 00 50 E3 03 00 A0 01 00 00 A0 13 04 F0 9D E4 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ttyname_498223812526174f0849146fe7ae0228 {
	meta:
		aliases = "ttyname"
		size = "40"
		objfiles = "ttyname@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 18 10 9F E5 20 20 A0 E3 ?? ?? ?? EB 0C 30 9F E5 00 00 50 E3 03 00 A0 01 00 00 A0 13 04 F0 9D E4 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule hsearch_440ab745acb47241b2223eda615ece30 {
	meta:
		aliases = "hsearch"
		size = "40"
		objfiles = "hsearch@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 18 C0 9F E5 08 D0 4D E2 04 30 8D E2 00 C0 8D E5 ?? ?? ?? EB 04 00 9D E5 08 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svcerr_noproc_d05c34ff7f44869d599148163d4a41d3 {
	meta:
		aliases = "svcerr_noproc"
		size = "80"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 20 30 80 E2 30 D0 4D E2 00 C0 A0 E1 07 00 93 E8 0C 30 8D E2 07 00 83 E8 01 30 A0 E3 04 30 8D E5 00 30 A0 E3 08 30 8D E5 03 30 83 E2 18 30 8D E5 0C 00 A0 E1 08 30 9C E5 0D 10 A0 E1 0F E0 A0 E1 0C F0 93 E5 30 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __GI_svcerr_decode_6576fbe8d99769bcd2ff8685395aefd0 {
	meta:
		aliases = "svcerr_decode, __GI_svcerr_decode"
		size = "80"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 20 30 80 E2 30 D0 4D E2 00 C0 A0 E1 07 00 93 E8 0C 30 8D E2 07 00 83 E8 01 30 A0 E3 04 30 8D E5 00 30 A0 E3 08 30 8D E5 04 30 83 E2 18 30 8D E5 0C 00 A0 E1 08 30 9C E5 0D 10 A0 E1 0F E0 A0 E1 0C F0 93 E5 30 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule svcerr_systemerr_c0a83281166899f9691216ea5a013e2c {
	meta:
		aliases = "svcerr_systemerr"
		size = "80"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 20 30 80 E2 30 D0 4D E2 00 C0 A0 E1 07 00 93 E8 0C 30 8D E2 07 00 83 E8 01 30 A0 E3 04 30 8D E5 00 30 A0 E3 08 30 8D E5 05 30 83 E2 18 30 8D E5 0C 00 A0 E1 08 30 9C E5 0D 10 A0 E1 0F E0 A0 E1 0C F0 93 E5 30 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __GI_svcerr_noprog_020638c92f7867b5021d37b61fd85b54 {
	meta:
		aliases = "svcerr_noprog, __GI_svcerr_noprog"
		size = "76"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 20 30 80 E2 30 D0 4D E2 00 C0 A0 E1 07 00 93 E8 0C 30 8D E2 07 00 83 E8 01 E0 A0 E3 00 30 A0 E3 08 30 8D E5 18 E0 8D E5 04 E0 8D E5 0C 00 A0 E1 08 30 9C E5 0D 10 A0 E1 0F E0 A0 E1 0C F0 93 E5 30 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule _dl_parse_relocation_informati_ca0e5dc87b17b86430ced4cead375040 {
	meta:
		aliases = "_dl_parse_relocation_information"
		size = "48"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 04 E0 2D E5 20 30 9F E5 04 D0 4D E2 00 00 90 E5 00 30 8D E5 02 30 A0 E1 01 20 A0 E1 1C 10 90 E5 B4 FF FF EB 04 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _dl_parse_lazy_relocation_info_fa2bfa6ed38de21cd20496338ddc472e {
	meta:
		aliases = "_dl_parse_lazy_relocation_information"
		size = "48"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 04 E0 2D E5 20 30 9F E5 04 D0 4D E2 00 30 8D E5 02 30 A0 E1 00 00 90 E5 01 20 A0 E1 00 10 A0 E3 A8 FF FF EB 04 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_mbsrtowcs_28de1271b1e0490e91295bb0136fecbe {
	meta:
		aliases = "mbsrtowcs, __GI_mbsrtowcs"
		size = "48"
		objfiles = "mbsrtowcs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 20 C0 9F E5 00 00 53 E3 03 C0 A0 11 04 D0 4D E2 02 30 A0 E1 00 20 E0 E3 00 C0 8D E5 ?? ?? ?? EB 04 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule authunix_marshal_5ef7c27e3763fe1455fdbffb86c4197c {
	meta:
		aliases = "authunix_marshal"
		size = "36"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 24 30 90 E5 04 C0 91 E5 01 00 A0 E1 AC 21 93 E5 1C 10 83 E2 0F E0 A0 E1 0C F0 9C E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule svctcp_getargs_b60dd4967cbb6d2198d3edf17ee5b0d0 {
	meta:
		aliases = "svcunix_getargs, svctcp_getargs"
		size = "32"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 2C 00 90 E5 01 30 A0 E1 08 00 80 E2 02 10 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule svcunix_freeargs_7120ad789ffdfb9055ed0f24d6c0811c {
	meta:
		aliases = "svctcp_freeargs, svcunix_freeargs"
		size = "36"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 2C 00 90 E5 02 30 A0 E3 08 30 A0 E5 01 30 A0 E1 02 10 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule svcunix_stat_528219036dcb20e6c9ace897fd810347 {
	meta:
		aliases = "svctcp_stat, svcunix_stat"
		size = "44"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 2C 30 90 E5 00 00 93 E5 00 00 50 E3 04 F0 9D 04 08 00 83 E2 ?? ?? ?? EB 00 00 50 E3 02 00 A0 13 01 00 A0 03 04 F0 9D E4 }
	condition:
		$pattern
}

rule ctime_8af7f1199bf6029224583f7ce52db37c {
	meta:
		aliases = "__GI_ctime, ctime"
		size = "28"
		objfiles = "ctime@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 2C D0 4D E2 0D 10 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 2C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule svcudp_getargs_2bdae41319547e4bb01b2e1331626f97 {
	meta:
		aliases = "svcudp_getargs"
		size = "32"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 30 00 90 E5 01 30 A0 E1 08 00 80 E2 02 10 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule svcudp_freeargs_8b9b838726994ec5b5ae34f1c1dead6c {
	meta:
		aliases = "svcudp_freeargs"
		size = "36"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 30 00 90 E5 02 30 A0 E3 08 30 A0 E5 01 30 A0 E1 02 10 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule __GI_isatty_801c6a7883f0db4852f8793486b982e2 {
	meta:
		aliases = "isatty, __GI_isatty"
		size = "32"
		objfiles = "isatty@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 3C D0 4D E2 0D 10 A0 E1 ?? ?? ?? EB 01 00 70 E2 00 00 A0 33 3C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule byte_store_op2_def8a03c60ce94fac59b659c5a055dbe {
	meta:
		aliases = "byte_store_op2"
		size = "36"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 43 C4 A0 E1 42 E4 A0 E1 04 C0 C1 E5 00 00 C1 E5 02 E0 C1 E5 01 20 C1 E5 03 30 C1 E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule direxists_b333af83068b4b2baf17b7c1eca2afb6 {
	meta:
		aliases = "direxists"
		size = "56"
		objfiles = "tempname@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 58 D0 4D E2 0D 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 A0 13 04 00 00 1A 10 30 9D E5 0F 3A 03 E2 01 09 53 E3 00 00 A0 13 01 00 A0 03 58 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule endusershell_dba24b3323119a513bd9580641831f25 {
	meta:
		aliases = "endusershell"
		size = "28"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 83 FF FF EB 08 30 9F E5 00 20 A0 E3 00 20 83 E5 04 F0 9D E4 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_testcancel_15d266fc5bac0616a74a8ba8e4cb57d9 {
	meta:
		aliases = "pthread_testcancel"
		size = "44"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { 04 E0 2D E5 87 FF FF EB 42 30 D0 E5 00 00 53 E3 04 F0 9D 04 40 30 D0 E5 00 00 53 E3 04 F0 9D 14 00 00 E0 E3 0D 10 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule get_fde_encoding_0d2cc12daf69fe65807d932337fd92be {
	meta:
		aliases = "get_fde_encoding"
		size = "16"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { 04 E0 2D E5 9E FD FF EB 04 E0 9D E4 C8 FF FF EA }
	condition:
		$pattern
}

rule __GI_ftell_bf951bc17031556e0a73a0c404c867fd {
	meta:
		aliases = "ftell, ftello, __GI_ftell"
		size = "60"
		objfiles = "ftello@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 ?? ?? ?? EB 00 20 A0 E1 C2 3F A0 E1 00 00 52 E1 00 C0 A0 E1 01 00 00 1A 01 00 53 E1 03 00 00 0A ?? ?? ?? EB 4B 30 A0 E3 00 30 80 E5 00 C0 E0 E3 0C 00 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule llrintf_c4ff7ef54e5728e438def535189f6899 {
	meta:
		aliases = "ilogbf, lrintf, llroundf, lroundf, llrintf"
		size = "16"
		objfiles = "ilogbf@libm.a, lroundf@libm.a, lrintf@libm.a, llrintf@libm.a, llroundf@libm.a"
	strings:
		$pattern = { 04 E0 2D E5 ?? ?? ?? EB 04 E0 9D E4 ?? ?? ?? EA }
	condition:
		$pattern
}

rule clnt_pcreateerror_8213424d9423719eb0f7c5bff68b7e51 {
	meta:
		aliases = "clnt_perror, clnt_perrno, __GI_clnt_perror, clnt_pcreateerror"
		size = "28"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 ?? ?? ?? EB 08 30 9F E5 00 10 93 E5 04 E0 9D E4 ?? ?? ?? EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_fma_517cfc5984266b95dc7cd77d9881a267 {
	meta:
		aliases = "fma, __GI_fma"
		size = "20"
		objfiles = "s_fma@libm.a"
	strings:
		$pattern = { 04 E0 2D E5 ?? ?? ?? EB 0C 00 9D E9 ?? ?? ?? EB 04 F0 9D E4 }
	condition:
		$pattern
}

rule __GI___rpc_thread_svc_fdset_16e928c05aa6209f961f36421e8c5e2d {
	meta:
		aliases = "__rpc_thread_svc_fdset, __GI___rpc_thread_svc_fdset"
		size = "36"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 ?? ?? ?? EB 0C 20 9F E5 0C 30 9F E5 02 00 50 E1 03 00 A0 01 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __rpc_thread_createerr_693f3e5be885430a5b954a82986b0ff1 {
	meta:
		aliases = "__GI___rpc_thread_createerr, __rpc_thread_createerr"
		size = "36"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 ?? ?? ?? EB 0C 30 9F E5 03 00 50 E1 08 00 9F 05 80 00 80 12 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __rpc_thread_svc_pollfd_7943d65cbf1030d8c94cdc3be4616c49 {
	meta:
		aliases = "__GI___rpc_thread_svc_pollfd, __rpc_thread_svc_pollfd"
		size = "36"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 ?? ?? ?? EB 0C 30 9F E5 03 00 50 E1 08 00 9F 05 90 00 80 12 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI___rpc_thread_svc_max_poll_0b9056522680c6961eb801651d1ea121 {
	meta:
		aliases = "__rpc_thread_svc_max_pollfd, __GI___rpc_thread_svc_max_pollfd"
		size = "36"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 ?? ?? ?? EB 0C 30 9F E5 03 00 50 E1 08 00 9F 05 94 00 80 12 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sem_unlink_a40f80df3b43c7c733efb6877e131639 {
	meta:
		aliases = "sem_close, sem_unlink"
		size = "24"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { 04 E0 2D E5 ?? ?? ?? EB 26 30 A0 E3 00 30 80 E5 00 00 E0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule free_mem_6bfb37d7658bd73aff91514559987a78 {
	meta:
		aliases = "free_mem"
		size = "20"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 ?? ?? ?? EB 9C 00 90 E5 04 E0 9D E4 ?? ?? ?? EA }
	condition:
		$pattern
}

rule floorf_3a1a777b192db480491cbf217784f1e6 {
	meta:
		aliases = "logf, atanhf, atanf, acosf, expm1f, asinhf, log10f, cosf, significandf, truncf, logbf, expf, sinf, lgammaf, fabsf, erfcf, ceilf, gammaf, coshf, roundf, sqrtf, tanf, erff, cbrtf, acoshf, log1pf, log2f, exp2f, asinf, sinhf, rintf, tanhf, floorf"
		size = "20"
		objfiles = "exp2f@libm.a, sinf@libm.a, log2f@libm.a, significandf@libm.a, floorf@libm.a"
	strings:
		$pattern = { 04 E0 2D E5 ?? ?? ?? EB ?? ?? ?? EB ?? ?? ?? EB 04 F0 9D E4 }
	condition:
		$pattern
}

rule setusershell_1732a8471db573133ff8a0a12c54bc64 {
	meta:
		aliases = "setusershell"
		size = "24"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 A4 FF FF EB 04 30 9F E5 00 00 83 E5 04 F0 9D E4 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __errno_location_dda5695e6b20c41ec09e7be04637ed95 {
	meta:
		aliases = "__errno_location"
		size = "16"
		objfiles = "errno@libpthread.a"
	strings:
		$pattern = { 04 E0 2D E5 DA FF FF EB 44 00 90 E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule __GI_pthread_self_8f367ed3219e3d5fd0c0bc2376ef7b6d {
	meta:
		aliases = "pthread_self, __GI_pthread_self"
		size = "16"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { 04 E0 2D E5 DE FF FF EB 10 00 90 E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule __h_errno_location_524926fb50bafbcf8ba188b8542055fb {
	meta:
		aliases = "__h_errno_location"
		size = "16"
		objfiles = "errno@libpthread.a"
	strings:
		$pattern = { 04 E0 2D E5 DE FF FF EB 4C 00 90 E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule __GI_sysconf_d68c4fac3ebbb08894178e5cfcaf52d9 {
	meta:
		aliases = "sysconf, __GI_sysconf"
		size = "1308"
		objfiles = "sysconf@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 F0 00 50 E3 00 F1 9F 97 F2 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule any_4f4af857fe2c056bef2d63179f6e0dcb {
	meta:
		aliases = "any"
		size = "56"
		objfiles = "getnetent@libc.a"
	strings:
		$pattern = { 06 00 00 EA 02 00 5C E1 0E F0 A0 01 00 C0 D3 E5 00 00 5C E3 01 30 83 E2 F9 FF FF 1A 01 00 80 E2 00 20 D0 E5 00 00 52 E3 01 30 A0 11 F6 FF FF 1A 02 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule setlocale_957ded19ab1a8145482d5c3a7ba1aeef {
	meta:
		aliases = "setlocale"
		size = "96"
		objfiles = "setlocale@libc.a"
	strings:
		$pattern = { 06 00 50 E3 04 E0 2D E5 01 00 A0 E1 0F 00 00 8A 00 00 51 E3 0B 00 00 0A 00 30 D1 E5 00 00 53 E3 08 00 00 0A 43 00 53 E3 02 00 00 1A 01 30 D1 E5 00 00 53 E3 03 00 00 0A 18 10 9F E5 ?? ?? ?? EB 00 00 50 E3 01 00 00 1A 0C 00 9F E5 04 F0 9D E4 00 00 A0 E3 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule seed48_r_78212806420671a2131ed40ed08a0873 {
	meta:
		aliases = "__GI_seed48_r, seed48_r"
		size = "148"
		objfiles = "seed48_r@libc.a"
	strings:
		$pattern = { 06 20 A0 E3 30 40 2D E9 00 40 A0 E1 02 00 81 E0 01 50 A0 E1 ?? ?? ?? EB 05 20 D4 E5 04 30 D4 E5 02 34 83 E1 43 24 A0 E1 05 20 C5 E5 04 30 C5 E5 03 20 D4 E5 02 30 D4 E5 02 34 83 E1 43 24 A0 E1 03 20 C5 E5 02 30 C5 E5 01 30 D4 E5 00 20 D4 E5 03 24 82 E1 42 34 A0 E1 01 30 C5 E5 2C 30 9F E5 05 40 A0 E3 10 30 85 E5 14 40 85 E5 0B 30 A0 E3 00 00 A0 E3 0C 30 C5 E5 01 30 A0 E3 0E 30 C5 E5 0F 00 C5 E5 00 20 C5 E5 0D 00 C5 E5 30 80 BD E8 6D E6 EC DE }
	condition:
		$pattern
}

rule remove_from_queue_6a13bfc867faea2a2df61d0f141fd8e4 {
	meta:
		aliases = "remove_from_queue"
		size = "64"
		objfiles = "condvar@libpthread.a, semaphore@libpthread.a"
	strings:
		$pattern = { 08 00 00 EA 01 00 52 E1 05 00 00 1A 08 30 92 E5 01 10 A0 E3 00 30 80 E5 00 30 A0 E3 08 30 82 E5 04 00 00 EA 08 00 82 E2 00 20 90 E5 00 00 52 E3 F3 FF FF 1A 02 10 A0 E1 01 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_pthread_cond_destroy_c8d0b13dfce94003942f5d7c734678d1 {
	meta:
		aliases = "pthread_cond_destroy, __GI_pthread_cond_destroy"
		size = "20"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { 08 00 90 E5 00 00 50 E3 10 00 A0 13 00 00 A0 03 0E F0 A0 E1 }
	condition:
		$pattern
}

rule fde_unencoded_compare_4818f2de2e5998d41e3de4279a7d84c1 {
	meta:
		aliases = "fde_unencoded_compare"
		size = "32"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { 08 00 91 E5 08 30 92 E5 03 00 50 E1 01 00 A0 83 0E F0 A0 81 00 00 E0 33 00 00 A0 23 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_pthread_attr_getschedpara_c256e41d96cdd7cf60e33b1238f854a6 {
	meta:
		aliases = "pthread_attr_getschedparam, __GI_pthread_attr_getschedparam"
		size = "32"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 08 30 80 E2 04 E0 2D E5 01 00 A0 E1 04 20 A0 E3 03 10 A0 E1 ?? ?? ?? EB 00 00 A0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule _seterr_reply_b67822f835aa555dbf8fc6982da248bf {
	meta:
		aliases = "__GI__seterr_reply, _seterr_reply"
		size = "296"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { 08 30 90 E5 00 00 53 E3 02 00 00 0A 01 00 53 E3 2E 00 00 1A 1C 00 00 EA 18 20 90 E5 00 00 52 E3 00 20 81 05 0E F0 A0 01 05 00 52 E3 02 F1 9F 97 11 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 08 30 A0 E3 17 00 00 EA 09 30 A0 E3 15 00 00 EA 0A 30 A0 E3 13 00 00 EA 0B 30 A0 E3 11 00 00 EA 0C 30 A0 E3 0F 00 00 EA 00 30 A0 E3 0D 00 00 EA 10 30 A0 E3 00 30 81 E5 00 30 A0 E3 0D 00 00 EA 0C 20 90 E5 00 00 52 E3 06 30 A0 03 05 00 00 0A 01 00 52 E3 10 30 A0 13 00 30 81 15 01 30 A0 13 04 00 00 1A 01 00 00 EA 00 30 81 E5 08 00 00 EA 07 30 A0 E3 FB FF FF EA 04 30 81 E5 }
	condition:
		$pattern
}

rule _Unwind_DeleteException_3b1109f2775deb13c2f4bcdf1b8febe3 {
	meta:
		aliases = "_Unwind_DeleteException"
		size = "36"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { 08 30 90 E5 00 00 53 E3 04 E0 2D E5 04 F0 9D 04 00 10 A0 E1 01 00 A0 E3 0F E0 A0 E1 03 F0 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule sem_getvalue_3b8d4ddfd08b2a67e22760c2fb830277 {
	meta:
		aliases = "__new_sem_getvalue, sem_getvalue"
		size = "16"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { 08 30 90 E5 00 00 A0 E3 00 30 81 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule cfgetospeed_807731a5bba6a65b9597a235386f786b {
	meta:
		aliases = "cfgetospeed"
		size = "20"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { 08 30 90 E5 04 00 9F E5 00 00 03 E0 0E F0 A0 E1 0F 10 00 00 }
	condition:
		$pattern
}

rule clnttcp_geterr_745551b8930bc614a6166bf2c30d43b6 {
	meta:
		aliases = "clnttcp_geterr"
		size = "24"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { 08 30 90 E5 24 30 83 E2 01 C0 A0 E1 07 00 93 E8 07 00 8C E8 0E F0 A0 E1 }
	condition:
		$pattern
}

rule clntudp_geterr_df0f87012cbf6eb24c04c354f255f3e1 {
	meta:
		aliases = "clntudp_geterr"
		size = "24"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { 08 30 90 E5 2C 30 83 E2 01 C0 A0 E1 07 00 93 E8 07 00 8C E8 0E F0 A0 E1 }
	condition:
		$pattern
}

rule clntunix_geterr_31324b1d6b0abb2895dff9eac5449b91 {
	meta:
		aliases = "clntunix_geterr"
		size = "24"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { 08 30 90 E5 84 30 83 E2 01 C0 A0 E1 07 00 93 E8 07 00 8C E8 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __pthread_setconcurrency_38989b46bbf008e08282e08a554b3101 {
	meta:
		aliases = "pthread_setconcurrency, __pthread_setconcurrency"
		size = "20"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { 08 30 9F E5 00 00 83 E5 00 00 A0 E3 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_restart_new_0821034b232c85a34c74c6ee244061f6 {
	meta:
		aliases = "__pthread_restart_new"
		size = "20"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { 08 30 9F E5 14 00 90 E5 00 10 93 E5 ?? ?? ?? EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_sigtimedwait_244e3cd8f60de8eebe219a8ca68c4f65 {
	meta:
		aliases = "sigtimedwait, __GI_sigtimedwait"
		size = "8"
		objfiles = "__rt_sigtimedwait@libc.a"
	strings:
		$pattern = { 08 30 A0 E3 F2 FF FF EA }
	condition:
		$pattern
}

rule __aeabi_dcmpeq_bd6f3c16879cf32c44ab973db8ff5c12 {
	meta:
		aliases = "__aeabi_fcmpeq, __aeabi_dcmpeq"
		size = "20"
		objfiles = "_cmpdf2@libgcc.a, _cmpsf2@libgcc.a"
	strings:
		$pattern = { 08 E0 2D E5 ?? ?? ?? EB 01 00 A0 03 00 00 A0 13 08 F0 9D E4 }
	condition:
		$pattern
}

rule __aeabi_dcmpgt_f52cbcbfa58e06c8588cd1fb7e67afd3 {
	meta:
		aliases = "__aeabi_fcmplt, __aeabi_dcmplt, __aeabi_fcmpgt, __aeabi_dcmpgt"
		size = "20"
		objfiles = "_cmpdf2@libgcc.a, _cmpsf2@libgcc.a"
	strings:
		$pattern = { 08 E0 2D E5 ?? ?? ?? EB 01 00 A0 33 00 00 A0 23 08 F0 9D E4 }
	condition:
		$pattern
}

rule __aeabi_dcmple_ff7f5d7fa2e5dc60f94d507ce6a3303e {
	meta:
		aliases = "__aeabi_dcmpge, __aeabi_fcmple, __aeabi_fcmpge, __aeabi_dcmple"
		size = "20"
		objfiles = "_cmpdf2@libgcc.a, _cmpsf2@libgcc.a"
	strings:
		$pattern = { 08 E0 2D E5 ?? ?? ?? EB 01 00 A0 93 00 00 A0 83 08 F0 9D E4 }
	condition:
		$pattern
}

rule sigisemptyset_722dc576fed1dff38708c5b8c37ef2e4 {
	meta:
		aliases = "sigisemptyset"
		size = "20"
		objfiles = "sigisempty@libc.a"
	strings:
		$pattern = { 09 00 90 E8 00 00 83 E1 01 00 70 E2 00 00 A0 33 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __encode_header_170b2deee6b9f1f65bece348fbf11e04 {
	meta:
		aliases = "__encode_header"
		size = "232"
		objfiles = "encodeh@libc.a"
	strings:
		$pattern = { 0B 00 52 E3 04 E0 2D E5 00 C0 A0 E1 01 E0 A0 E1 00 00 E0 D3 04 F0 9D D4 01 30 DC E5 00 30 C1 E5 00 30 9C E5 01 30 C1 E5 08 20 9C E5 14 30 9C E5 04 00 9C E5 0C 10 9C E5 00 30 53 E2 01 30 A0 13 0F 20 02 E2 00 00 50 E3 82 31 83 E1 10 20 9C E5 80 00 A0 13 00 00 A0 03 00 00 51 E3 04 10 A0 13 00 10 A0 03 00 30 83 E1 00 00 52 E3 02 20 A0 13 00 20 A0 03 01 30 83 E1 02 30 83 E1 02 30 CE E5 18 20 8C E2 0C 00 92 E8 00 00 52 E3 80 20 A0 13 00 20 A0 03 0F 30 03 E2 03 20 82 E1 03 20 CE E5 21 30 DC E5 04 30 CE E5 20 30 9C E5 05 30 CE E5 25 30 DC E5 06 30 CE E5 24 30 9C E5 07 30 CE E5 29 30 DC E5 08 30 CE E5 }
	condition:
		$pattern
}

rule swprintf_4a999803dcd64297aad8387dd2b093cb {
	meta:
		aliases = "__GI_snprintf, snprintf, swprintf"
		size = "48"
		objfiles = "swprintf@libc.a, snprintf@libc.a"
	strings:
		$pattern = { 0C 00 2D E9 04 E0 2D E5 04 D0 4D E2 0C C0 8D E2 0C 30 A0 E1 08 20 9D E5 00 C0 8D E5 ?? ?? ?? EB 04 D0 8D E2 04 E0 9D E4 08 D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule semctl_522bf31142ea6be600444166ab8cd65b {
	meta:
		aliases = "semctl"
		size = "84"
		objfiles = "semctl@libc.a"
	strings:
		$pattern = { 0C 00 2D E9 10 40 2D E9 04 D0 4D E2 0C 20 9D E5 14 30 8D E2 00 30 8D E5 01 2C 82 E3 10 30 9D E5 2C 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 04 D0 8D E2 10 40 BD E8 08 D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __error_03cd2cc123bc8b72a0794f34fe3dc316 {
	meta:
		aliases = "error, __error"
		size = "284"
		objfiles = "error@libc.a"
	strings:
		$pattern = { 0C 00 2D E9 70 40 2D E9 F0 30 9F E5 04 D0 4D E2 00 60 A0 E1 00 00 93 E5 01 40 A0 E1 ?? ?? ?? EB DC 30 9F E5 00 30 93 E5 00 00 53 E3 02 00 00 0A 0F E0 A0 E1 03 F0 A0 E1 05 00 00 EA C4 30 9F E5 00 00 93 E5 C0 30 9F E5 C0 10 9F E5 00 20 93 E5 ?? ?? ?? EB AC 50 9F E5 18 30 8D E2 03 20 A0 E1 14 10 9D E5 00 00 95 E5 00 30 8D E5 ?? ?? ?? EB 9C 20 9F E5 00 30 92 E5 00 00 54 E3 01 30 83 E2 00 30 82 E5 06 00 00 0A 04 00 A0 E1 00 40 95 E5 ?? ?? ?? EB 7C 10 9F E5 00 20 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 10 95 E5 34 30 91 E5 00 00 53 E3 09 00 00 0A 10 20 91 E5 1C 30 91 E5 03 00 52 E1 0A 30 A0 33 01 30 C2 34 }
	condition:
		$pattern
}

rule __new_sem_destroy_6e201bb76263977e147e0bd5072f6407 {
	meta:
		aliases = "sem_destroy, __new_sem_destroy"
		size = "36"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { 0C 00 90 E5 00 00 50 E3 04 E0 2D E5 04 F0 9D 04 ?? ?? ?? EB 10 30 A0 E3 00 30 80 E5 00 00 E0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule remque_9957db2e8dfd287484e07f782192ecab {
	meta:
		aliases = "remque"
		size = "24"
		objfiles = "remque@libc.a"
	strings:
		$pattern = { 0C 00 90 E8 00 00 52 E3 04 30 82 15 00 00 53 E3 00 20 83 15 0E F0 A0 E1 }
	condition:
		$pattern
}

rule atexit_8e3a6a6fc75e36063122efdd24e46a63 {
	meta:
		aliases = "atexit"
		size = "24"
		objfiles = "atexit@libc.a"
	strings:
		$pattern = { 0C 20 9F E5 00 00 52 E3 00 20 92 15 00 10 A0 E3 ?? ?? ?? EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _Unwind_SjLj_Register_e9ba7229f5754868413277256518745e {
	meta:
		aliases = "_Unwind_SjLj_Register"
		size = "24"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { 0C 20 9F E5 00 30 92 E5 00 30 80 E5 00 00 82 E5 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __fbufsize_66a02f2b0f61afe443dd884d974b64af {
	meta:
		aliases = "__fbufsize"
		size = "16"
		objfiles = "__fbufsize@libc.a"
	strings:
		$pattern = { 0C 30 80 E2 09 00 13 E8 00 00 43 E0 0E F0 A0 E1 }
	condition:
		$pattern
}

rule xdrmem_getpos_e0e23d72cb67ccd6339366d9c91cf48a {
	meta:
		aliases = "xdrmem_getpos"
		size = "16"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { 0C 30 80 E2 09 00 93 E8 03 00 40 E0 0E F0 A0 E1 }
	condition:
		$pattern
}

rule rwlock_can_rdlock_34e312699451dd517f1a2bb2997a8e3e {
	meta:
		aliases = "rwlock_can_rdlock"
		size = "60"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { 0C 30 90 E5 00 00 53 E3 00 00 A0 13 0E F0 A0 11 18 30 90 E5 00 00 53 E3 05 00 00 0A 14 30 90 E5 00 00 53 E3 02 00 00 0A 00 00 51 E2 01 00 A0 13 0E F0 A0 E1 01 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_attr_getinheritsched_f4a72c6b38cc3b35220d755255df89ec {
	meta:
		aliases = "__GI_pthread_attr_getinheritsched, pthread_attr_getinheritsched"
		size = "16"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 0C 30 90 E5 00 00 A0 E3 00 30 81 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_mutex_destroy_590da0063cbada5f9cfa6538a4d01e66 {
	meta:
		aliases = "__pthread_mutex_destroy, pthread_mutex_destroy"
		size = "84"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { 0C 30 90 E5 03 00 53 E3 03 F1 9F 97 03 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 16 00 A0 E3 0E F0 A0 E1 10 30 90 E5 01 00 13 E3 03 00 00 1A 04 00 00 EA 10 30 90 E5 00 00 53 E3 01 00 00 0A 10 00 A0 E3 0E F0 A0 E1 00 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __pthread_mutex_lock_a0d3c67d33f7068d4a0bdcf1436ed2b0 {
	meta:
		aliases = "pthread_mutex_lock, __pthread_mutex_lock"
		size = "200"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { 0C 30 90 E5 30 40 2D E9 00 40 A0 E1 03 00 53 E3 03 F1 9F 97 03 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 16 00 A0 E3 30 80 BD E8 10 00 80 E2 00 10 A0 E3 ?? ?? ?? EB 00 00 A0 E3 30 80 BD E8 5B FF FF EB 08 30 94 E5 00 00 53 E1 04 30 94 05 00 50 A0 E1 01 30 83 02 00 00 A0 03 05 00 00 0A 10 00 84 E2 05 10 A0 E1 ?? ?? ?? EB 00 30 A0 E3 08 50 84 E5 03 00 A0 E1 04 30 84 E5 30 80 BD E8 4B FF FF EB 08 30 94 E5 00 00 53 E1 00 50 A0 E1 23 00 A0 03 30 80 BD 08 10 00 84 E2 05 10 A0 E1 ?? ?? ?? EB 00 00 A0 E3 08 50 84 E5 30 80 BD E8 10 00 80 E2 00 10 A0 E3 ?? ?? ?? EB 00 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule pthread_mutex_trylock_1eed71c640b5c1ecd7469944cd03519a {
	meta:
		aliases = "__pthread_mutex_trylock, pthread_mutex_trylock"
		size = "196"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { 0C 30 90 E5 30 40 2D E9 00 40 A0 E1 03 00 53 E3 03 F1 9F 97 03 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 16 50 A0 E3 22 00 00 EA 14 20 80 E2 01 30 A0 E3 93 30 02 E1 00 00 53 E3 10 50 A0 13 00 50 A0 03 1B 00 00 EA C1 FE FF EB 08 30 94 E5 00 00 53 E1 00 20 A0 E1 04 30 94 05 00 50 A0 03 01 30 83 02 04 30 84 05 12 00 00 0A 01 00 A0 E3 14 30 84 E2 90 00 03 E1 00 00 50 E3 10 50 A0 13 0C 00 00 1A 09 00 00 EA 10 00 80 E2 51 FE FF EB 00 50 50 E2 07 00 00 1A AD FE FF EB 08 00 84 E5 04 00 00 EA 10 00 80 E2 30 40 BD E8 49 FE FF EA 05 00 84 E9 00 50 A0 E1 05 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_mutex_unlock_7a4cebe44604351029f47bde258f57b5 {
	meta:
		aliases = "pthread_mutex_unlock, __pthread_mutex_unlock"
		size = "200"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { 0C 30 90 E5 30 40 2D E9 00 50 A0 E1 03 00 53 E3 03 F1 9F 97 03 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 16 00 A0 E3 30 80 BD E8 10 00 80 E2 ?? ?? ?? EB 1E 00 00 EA D0 FF FF EB 08 30 95 E5 00 00 53 E1 1C 00 00 1A 04 30 95 E5 00 00 53 E3 03 00 00 DA 01 30 43 E2 00 00 A0 E3 04 30 85 E5 30 80 BD E8 00 40 A0 E3 08 40 85 E5 10 00 85 E2 ?? ?? ?? EB 0A 00 00 EA C0 FF FF EB 08 30 95 E5 00 00 53 E1 0C 00 00 1A 10 30 95 E5 00 00 53 E3 09 00 00 0A 00 40 A0 E3 08 40 85 E5 10 00 85 E2 ?? ?? ?? EB 04 00 A0 E1 30 80 BD E8 10 00 80 E2 ?? ?? ?? EB 00 00 A0 E3 30 80 BD E8 01 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule ctermid_1a6c9e1eac143127c186d56eab6f4f1a {
	meta:
		aliases = "ctermid"
		size = "28"
		objfiles = "ctermid@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 00 00 50 E3 08 10 9F E5 03 00 A0 01 ?? ?? ?? EA ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_getpagesize_6aca7dca1f2b24957f3bf3e4e87ab272 {
	meta:
		aliases = "__getpagesize, getpagesize, __GI_getpagesize"
		size = "24"
		objfiles = "getpagesize@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 00 00 93 E5 00 00 50 E3 01 0A A0 03 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule re_set_syntax_bb868efe73ff5e9c3feb73348674049b {
	meta:
		aliases = "re_set_syntax"
		size = "24"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 00 20 93 E5 00 00 83 E5 02 00 A0 E1 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_isupper_55d3e10101725d0f8e3754dd946fdbb1 {
	meta:
		aliases = "isupper, __GI_isupper"
		size = "24"
		objfiles = "isupper@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 00 30 93 E5 80 00 D3 E7 01 00 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule islower_4cca9653e96fce3420dad4e9dc705337 {
	meta:
		aliases = "__GI_islower, islower"
		size = "24"
		objfiles = "islower@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 00 30 93 E5 80 00 D3 E7 02 00 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isalpha_1625fb5837213fc7fc0e3bb1c9975dfc {
	meta:
		aliases = "__GI_isalpha, isalpha"
		size = "24"
		objfiles = "isalpha@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 00 30 93 E5 80 00 D3 E7 04 00 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isxdigit_2719db6323c80447fb8186dbc35afa8b {
	meta:
		aliases = "__GI_isxdigit, isxdigit"
		size = "24"
		objfiles = "isxdigit@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 00 30 93 E5 80 00 D3 E7 10 00 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_isspace_4b5281112b120638e1ba531ff1df3449 {
	meta:
		aliases = "isspace, __GI_isspace"
		size = "24"
		objfiles = "isspace@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 00 30 93 E5 80 00 D3 E7 20 00 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isprint_8eb09ba1bc257f133a43bacdfa86e2e1 {
	meta:
		aliases = "__GI_isprint, isprint"
		size = "24"
		objfiles = "isprint@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 00 30 93 E5 80 00 D3 E7 40 00 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_isgraph_8a62f0844d0d95c797dd1f702db436df {
	meta:
		aliases = "isgraph, __GI_isgraph"
		size = "24"
		objfiles = "isgraph@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 00 30 93 E5 80 00 D3 E7 80 00 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __finite_3075b6565865386272c8000be88223da {
	meta:
		aliases = "__GI___finite, __finite"
		size = "24"
		objfiles = "s_finite@libm.a"
	strings:
		$pattern = { 0C 30 9F E5 03 30 80 E1 01 00 93 E2 01 00 A0 13 0E F0 A0 E1 FF FF 0F 80 }
	condition:
		$pattern
}

rule __finitef_fb9993c43e1ca113a8f021d93f3c45a8 {
	meta:
		aliases = "__GI___finitef, __finitef"
		size = "24"
		objfiles = "s_finitef@libm.a"
	strings:
		$pattern = { 0C 30 9F E5 03 30 80 E1 01 00 93 E2 01 00 A0 13 0E F0 A0 E1 FF FF 7F 80 }
	condition:
		$pattern
}

rule __gnat_install_locks_1ef71ec01ce244c73bfb0568abb96d1f {
	meta:
		aliases = "__gnat_install_locks"
		size = "28"
		objfiles = "gthr_gnat@libgcc_eh.a"
	strings:
		$pattern = { 0C 30 9F E5 0C 20 9F E5 00 00 83 E5 00 10 82 E5 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule time_70dee9cf10a09cac3c91b6a1e656bd49 {
	meta:
		aliases = "__GI_time, time"
		size = "8"
		objfiles = "time@libc.a"
	strings:
		$pattern = { 0D 00 90 EF 0E F0 A0 E1 }
	condition:
		$pattern
}

rule search_for_named_library_017b86baca7c3cbc55ddf49dadf76f63 {
	meta:
		aliases = "search_for_named_library"
		size = "372"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 0D C0 A0 E1 00 00 52 E3 F0 DF 2D E9 04 B0 4C E2 01 90 A0 E1 03 A0 A0 E1 50 00 00 0A 01 10 42 E2 01 30 F1 E5 00 00 53 E3 FC FF FF 1A 01 30 62 E2 01 10 83 E0 06 30 81 E2 03 30 C3 E3 0D D0 63 E0 0D 40 A0 E1 02 DB 4D E2 08 D0 4D E2 01 20 42 E2 0D 70 A0 E1 01 C0 44 E2 02 00 00 EA 01 30 F2 E5 01 30 EC E5 01 10 41 E2 00 00 51 E3 FA FF FF 1A 01 60 A0 E1 01 80 40 E2 04 20 A0 E1 01 50 47 E2 00 30 D4 E5 00 00 53 E3 3A 30 A0 03 00 30 C4 05 00 30 D4 E5 01 60 A0 03 3A 00 53 E3 2C 00 00 1A 00 30 A0 E3 00 30 C4 E5 00 30 D2 E5 00 00 53 E3 05 10 A0 01 B0 20 9F 05 06 00 00 0A 01 10 42 E2 05 20 A0 E1 01 30 F1 E5 }
	condition:
		$pattern
}

rule uw_install_context_b4fcddd0704632ea855bd1f5e24c9d04 {
	meta:
		aliases = "uw_install_context"
		size = "48"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { 0D C0 A0 E1 00 D8 2D E9 00 00 91 E5 04 B0 4C E2 01 40 A0 E1 2C FF FF EB 00 30 94 E5 20 20 83 E2 04 10 92 E5 20 B0 93 E5 08 D0 92 E5 01 F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_execl_c3641a48629ee725461f4159cd1146ac {
	meta:
		aliases = "execl, __GI_execl"
		size = "148"
		objfiles = "execl@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 0E 00 2D E9 00 D8 2D E9 10 B0 4C E2 04 D0 4D E2 08 30 8B E2 10 30 0B E5 00 E0 A0 E3 10 30 1B E5 00 20 93 E5 04 30 83 E2 00 00 52 E3 10 30 0B E5 01 E0 8E E2 F8 FF FF 1A 0E 31 A0 E1 08 30 83 E2 0D D0 63 E0 04 30 9B E5 00 30 8D E5 08 30 8B E2 10 30 0B E5 0D 10 A0 E1 0D C0 A0 E1 10 30 1B E5 00 20 93 E5 01 E0 5E E2 04 30 83 E2 10 30 0B E5 04 20 AC E5 F8 FF FF 1A 0C 30 9F E5 00 20 93 E5 ?? ?? ?? EB 0C D0 4B E2 00 A8 9D E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule execlp_e9723d351a9153daf2f5bd3b322cb126 {
	meta:
		aliases = "__GI_execlp, execlp"
		size = "136"
		objfiles = "execlp@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 0E 00 2D E9 00 D8 2D E9 10 B0 4C E2 04 D0 4D E2 08 30 8B E2 10 30 0B E5 00 E0 A0 E3 10 30 1B E5 00 20 93 E5 04 30 83 E2 00 00 52 E3 10 30 0B E5 01 E0 8E E2 F8 FF FF 1A 0E 31 A0 E1 08 30 83 E2 0D D0 63 E0 04 30 9B E5 00 30 8D E5 08 30 8B E2 10 30 0B E5 0D 10 A0 E1 0D C0 A0 E1 10 30 1B E5 00 20 93 E5 01 E0 5E E2 04 30 83 E2 10 30 0B E5 04 20 AC E5 F8 FF FF 1A ?? ?? ?? EB 0C D0 4B E2 00 A8 9D E8 }
	condition:
		$pattern
}

rule execle_e40bcf0191feef55cc4c67f378ada946 {
	meta:
		aliases = "__GI_execle, execle"
		size = "144"
		objfiles = "execle@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 0E 00 2D E9 10 D8 2D E9 10 B0 4C E2 04 D0 4D E2 08 30 8B E2 14 30 0B E5 00 E0 A0 E3 14 20 1B E5 00 30 92 E5 00 00 53 E3 04 30 82 E2 14 30 0B E5 01 E0 8E E2 F8 FF FF 1A 0E 31 A0 E1 08 30 83 E2 0D D0 63 E0 04 30 9B E5 00 30 8D E5 08 30 8B E2 14 30 0B E5 04 40 92 E5 0D 10 A0 E1 0D C0 A0 E1 14 30 1B E5 00 20 93 E5 01 E0 5E E2 04 30 83 E2 14 30 0B E5 04 20 AC E5 F8 FF FF 1A 04 20 A0 E1 ?? ?? ?? EB 10 D0 4B E2 10 A8 9D E8 }
	condition:
		$pattern
}

rule nanf_a8a3d1de9b0d64d661bce7f4ac83552b {
	meta:
		aliases = "__GI_nanf, nanf"
		size = "104"
		objfiles = "nan@libm.a"
	strings:
		$pattern = { 0D C0 A0 E1 70 D8 2D E9 00 30 D0 E5 00 00 53 E3 00 60 A0 E1 04 B0 4C E2 40 00 9F 05 0D 00 00 0A ?? ?? ?? EB 0C 00 80 E2 03 00 C0 E3 0D 50 A0 E1 0D D0 60 E0 06 20 A0 E1 24 10 9F E5 0D 00 A0 E1 ?? ?? ?? EB 0D 00 A0 E1 00 10 A0 E3 ?? ?? ?? EB 0D 40 A0 E1 05 D0 A0 E1 18 D0 4B E2 70 A8 9D E8 00 00 C0 7F ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_nan_a39d345c67ca09ce0e9ece32b1021de2 {
	meta:
		aliases = "nan, __GI_nan"
		size = "108"
		objfiles = "nan@libm.a"
	strings:
		$pattern = { 0D C0 A0 E1 70 D8 2D E9 00 30 D0 E5 00 00 53 E3 00 60 A0 E1 04 B0 4C E2 44 00 9F 05 00 10 A0 03 0D 00 00 0A ?? ?? ?? EB 0C 00 80 E2 03 00 C0 E3 0D 50 A0 E1 0D D0 60 E0 06 20 A0 E1 24 10 9F E5 0D 00 A0 E1 ?? ?? ?? EB 0D 00 A0 E1 00 10 A0 E3 ?? ?? ?? EB 0D 40 A0 E1 05 D0 A0 E1 18 D0 4B E2 70 A8 9D E8 00 00 F8 7F ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __msgwrite_c320dc4a1406047c15e65f81b2623084 {
	meta:
		aliases = "__msgwrite"
		size = "192"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 D8 2D E9 04 B0 4C E2 30 D0 4D E2 1C D0 4D E2 01 50 A0 E1 02 60 A0 E1 00 70 A0 E1 ?? ?? ?? EB 30 00 0B E5 ?? ?? ?? EB 2C 00 0B E5 ?? ?? ?? EB 30 10 4B E2 28 00 0B E5 0C 20 A0 E3 0C 00 8D E2 ?? ?? ?? EB 02 30 A0 E3 00 20 A0 E3 01 10 A0 E3 18 00 A0 E3 08 30 8D E5 24 30 4B E2 24 50 0B E5 20 60 0B E5 44 30 0B E5 40 10 0B E5 3C D0 0B E5 38 00 0B E5 34 20 0B E5 03 00 8D E8 4C 20 0B E5 48 20 0B E5 4C 40 4B E2 04 10 A0 E1 00 20 A0 E3 07 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 04 00 00 AA ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 F5 FF FF 0A 00 00 E0 E3 1C D0 4B E2 F0 A8 9D E8 }
	condition:
		$pattern
}

rule link_exists_p_2d8718f471734bf283a810e1c2952e85 {
	meta:
		aliases = "link_exists_p"
		size = "168"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DD 2D E9 04 B0 4C E2 B0 D0 4D E2 00 60 A0 E1 02 00 A0 E1 01 40 A0 E1 02 70 A0 E1 03 A0 A0 E1 ?? ?? ?? EB 04 30 80 E0 08 30 83 E2 03 30 C3 E3 0D D0 63 E0 00 50 A0 E1 06 10 A0 E1 04 20 A0 E1 0D 00 A0 E1 ?? ?? ?? EB 01 20 A0 E3 4C 10 9F E5 ?? ?? ?? EB 07 10 A0 E1 01 20 85 E2 ?? ?? ?? EB 04 30 9B E5 02 0C 13 E3 0D 80 A0 E1 04 00 00 0A 0D 00 A0 E1 7C 10 4B E2 0F E0 A0 E1 20 F0 9A E5 02 00 00 EA 0D 00 A0 E1 D4 10 4B E2 ?? ?? ?? EB 01 00 70 E2 00 00 A0 33 24 D0 4B E2 F0 AD 9D E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule link_exists_p_d784661fa626210fb431d6c42fad1276 {
	meta:
		aliases = "link_exists_p"
		size = "168"
		objfiles = "glob64@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DD 2D E9 04 B0 4C E2 C0 D0 4D E2 00 60 A0 E1 02 00 A0 E1 01 40 A0 E1 02 70 A0 E1 03 A0 A0 E1 ?? ?? ?? EB 04 30 80 E0 08 30 83 E2 03 30 C3 E3 0D D0 63 E0 00 50 A0 E1 06 10 A0 E1 04 20 A0 E1 0D 00 A0 E1 ?? ?? ?? EB 01 20 A0 E3 4C 10 9F E5 ?? ?? ?? EB 07 10 A0 E1 01 20 85 E2 ?? ?? ?? EB 04 30 9B E5 02 0C 13 E3 0D 80 A0 E1 04 00 00 0A 0D 00 A0 E1 84 10 4B E2 0F E0 A0 E1 20 F0 9A E5 02 00 00 EA 0D 00 A0 E1 E4 10 4B E2 ?? ?? ?? EB 01 00 70 E2 00 00 A0 33 24 D0 4B E2 F0 AD 9D E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule glob_9f4738c76ad8f02cef784ad4581e8465 {
	meta:
		aliases = "__GI_glob, glob"
		size = "1328"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 00 00 53 E3 00 00 50 13 04 B0 4C E2 EC D0 4D E2 03 50 A0 E1 01 A0 A0 E1 0C 21 0B E5 00 90 A0 E1 03 00 00 0A 7E 7C C1 E3 FF 70 C7 E3 00 00 57 E3 04 00 00 0A ?? ?? ?? EB 16 30 A0 E3 00 10 E0 E3 00 30 80 E5 30 01 00 EA 08 20 11 E2 08 20 83 05 08 21 0B E5 2F 10 A0 E3 ?? ?? ?? EB 00 60 50 E2 0A 00 00 1A 05 0A 1A E3 2D 00 00 0A 00 30 D9 E5 7E 00 53 E3 2A 00 00 1A 09 00 A0 E1 ?? ?? ?? EB 09 40 A0 E1 00 80 A0 E1 04 61 0B E5 27 00 00 EA 09 00 56 E1 7C 44 9F 05 01 30 89 02 01 80 A0 03 04 31 0B 05 21 00 00 0A 06 80 69 E0 07 30 88 E2 03 30 C3 E3 0D D0 63 E0 04 40 8D E2 04 00 A0 E1 }
	condition:
		$pattern
}

rule __GI_glob64_0e8f35ea345e69137e9dbc269364d0d8 {
	meta:
		aliases = "glob64, __GI_glob64"
		size = "1328"
		objfiles = "glob64@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 00 00 53 E3 00 00 50 13 04 B0 4C E2 FC D0 4D E2 03 50 A0 E1 01 A0 A0 E1 1C 21 0B E5 00 90 A0 E1 03 00 00 0A 7E 7C C1 E3 FF 70 C7 E3 00 00 57 E3 04 00 00 0A ?? ?? ?? EB 16 30 A0 E3 00 10 E0 E3 00 30 80 E5 30 01 00 EA 08 20 11 E2 08 20 83 05 18 21 0B E5 2F 10 A0 E3 ?? ?? ?? EB 00 60 50 E2 0A 00 00 1A 05 0A 1A E3 2D 00 00 0A 00 30 D9 E5 7E 00 53 E3 2A 00 00 1A 09 00 A0 E1 ?? ?? ?? EB 09 40 A0 E1 00 80 A0 E1 14 61 0B E5 27 00 00 EA 09 00 56 E1 7C 44 9F 05 01 30 89 02 01 80 A0 03 14 31 0B 05 21 00 00 0A 06 80 69 E0 07 30 88 E2 03 30 C3 E3 0D D0 63 E0 04 40 8D E2 04 00 A0 E1 }
	condition:
		$pattern
}

rule execvp_ff37fb5c349e756eb8ef056f1d02d0fc {
	meta:
		aliases = "__GI_execvp, execvp"
		size = "468"
		objfiles = "execvp@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 00 30 D0 E5 00 00 53 E3 04 B0 4C E2 00 50 A0 E1 01 90 A0 E1 02 00 00 1A ?? ?? ?? EB 02 30 A0 E3 30 00 00 EA 2F 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 1D 00 00 0A 7C 31 9F E5 09 10 A0 E1 00 20 93 E5 05 00 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 00 30 90 E5 08 00 53 E3 54 00 00 1A 00 10 A0 E3 00 00 00 EA 01 10 81 E2 01 21 A0 E1 02 30 99 E7 00 00 53 E3 FA FF FF 1A 0C 30 82 E2 0D D0 63 E0 04 30 99 E4 08 00 8D E2 09 10 A0 E1 28 00 8D E8 ?? ?? ?? EB 20 31 9F E5 0D 10 A0 E1 00 20 93 E5 18 01 9F E5 0D 40 A0 E1 ?? ?? ?? EB 3F 00 00 EA 0C 01 9F E5 ?? ?? ?? EB 00 60 50 E2 04 61 9F 05 02 00 00 0A }
	condition:
		$pattern
}

rule rcmd_f9db375cf01615901c5056447f4346a0 {
	meta:
		aliases = "rcmd"
		size = "1408"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 01 18 A0 E1 04 B0 4C E2 84 D0 4D E2 21 18 A0 E1 98 20 0B E5 00 90 A0 E1 9C 30 0B E5 94 10 0B E5 ?? ?? ?? EB 01 DB 4D E2 04 D0 4D E2 08 20 8D E2 01 5B A0 E3 88 80 4B E2 34 70 4B E2 30 60 4B E2 8C 00 0B E5 0F 00 00 EA 30 40 1B E5 01 00 74 E3 03 00 00 1A ?? ?? ?? EB 00 30 90 E5 22 00 53 E3 04 00 00 0A ?? ?? ?? EB 00 40 80 E5 00 00 99 E5 ?? ?? ?? EB 2C 01 00 EA 06 30 85 E2 03 30 C3 E3 0D D0 63 E0 08 20 8D E2 00 00 99 E5 05 30 A0 E1 08 10 A0 E1 00 70 8D E5 04 60 8D E5 ?? ?? ?? EB 00 00 50 E3 85 50 A0 E1 E6 FF FF 1A 34 30 1B E5 00 00 53 E3 E3 FF FF 0A 01 40 A0 E3 67 00 4B E5 }
	condition:
		$pattern
}

rule dlopen_10fdd25e18624a539c2d047373a58396 {
	meta:
		aliases = "dlopen"
		size = "1508"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 03 30 11 E2 04 B0 4C E2 1C D0 4D E2 01 70 A0 E1 0E 60 A0 E1 00 80 A0 E1 03 00 A0 01 88 35 9F 05 0A 20 A0 03 00 20 83 05 5D 01 00 0A 7C 25 9F E5 00 30 D2 E5 00 50 A0 E3 00 00 53 E3 2C 50 0B E5 07 00 00 1A 01 30 83 E2 00 30 C2 E5 60 25 9F E5 60 35 9F E5 00 20 83 E5 5C 25 9F E5 5C 35 9F E5 00 20 83 E5 58 45 9F E5 00 00 58 E3 00 00 94 05 4B 01 00 0A ?? ?? ?? EB 00 00 94 E5 05 40 A0 E1 00 20 A0 E1 0A 00 00 EA 00 C0 92 E5 14 10 9C E5 06 00 51 E1 05 00 00 2A 00 00 54 E3 02 00 00 0A 14 30 94 E5 01 00 53 E1 00 00 00 2A 0C 40 A0 E1 10 20 92 E5 00 00 52 E3 F2 FF FF 1A 2C 00 0B E5 }
	condition:
		$pattern
}

rule _fini_1b12b5978c44c8d8d2da164f12ca0466 {
	meta:
		aliases = "_init, _fini"
		size = "12"
		objfiles = "crti"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 }
	condition:
		$pattern
}

rule __GI_if_nameindex_b7ddcebf5468f414b2996a77199776e4 {
	meta:
		aliases = "if_nameindex, __GI_if_nameindex"
		size = "408"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 08 D0 4D E2 ?? ?? ?? EB 00 70 50 E2 15 00 00 BA 00 30 A0 E3 2C 30 0B E5 80 50 A0 E3 30 60 4B E2 85 40 A0 E1 06 30 84 E2 03 30 C3 E3 0D D0 63 E0 2C 30 1B E5 04 C0 8D E0 03 00 5C E1 05 40 84 00 07 00 A0 E1 38 11 9F E5 06 20 A0 E1 2C D0 0B E5 30 40 0B E5 ?? ?? ?? EB 00 00 50 E3 03 00 00 AA 07 00 A0 E1 ?? ?? ?? EB 00 A0 A0 E3 41 00 00 EA 30 00 1B E5 04 00 50 E1 00 50 A0 E1 E7 FF FF 0A A0 92 A0 E1 01 00 89 E2 80 01 A0 E1 ?? ?? ?? EB 00 A0 50 E2 00 60 A0 13 2D 00 00 1A 07 00 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 69 30 A0 E3 00 30 80 E5 30 00 00 EA 2C 30 1B E5 86 42 83 E0 }
	condition:
		$pattern
}

rule byte_re_compile_fastmap_3fb8c13997f072065a509f4279394597 {
	meta:
		aliases = "byte_re_compile_fastmap"
		size = "1072"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 0C D0 4D E2 10 70 90 E5 00 40 90 E5 08 30 90 E5 00 50 A0 E1 03 30 84 E0 18 D0 4D E2 00 10 A0 E3 01 2C A0 E3 07 00 A0 E1 30 30 0B E5 ?? ?? ?? EB 1C 30 D5 E5 08 30 83 E3 1C 30 C5 E5 1C 30 D5 E5 00 60 A0 E3 01 30 C3 E3 0A 20 87 E2 1C 30 C5 E5 01 90 A0 E3 2C 60 0B E5 34 20 0B E5 0D 00 A0 E1 05 10 A0 E3 09 A0 A0 E1 30 30 1B E5 03 00 54 E1 02 00 00 0A 00 30 D4 E5 01 00 53 E3 0B 00 00 1A 00 00 56 E3 1C 20 D5 E5 D9 00 00 0A 01 30 02 E2 03 30 89 E1 01 20 C2 E3 02 30 83 E1 1C 30 C5 E5 01 60 46 E2 06 41 90 E7 0A 90 A0 E1 ED FF FF EA 01 40 84 E2 1D 00 53 E3 03 F1 9F 97 }
	condition:
		$pattern
}

rule gaih_inet_serv_e8da3d23c88c6187caad2f6bffdb6873 {
	meta:
		aliases = "gaih_inet_serv"
		size = "200"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 1C D0 4D E2 01 40 A0 E1 00 80 A0 E1 02 A0 A0 E1 03 60 A0 E1 01 5B A0 E3 03 70 81 E2 2C 90 4B E2 06 30 85 E2 03 30 C3 E3 0D D0 63 E0 08 00 A0 E1 07 10 A0 E1 3C 20 4B E2 08 30 8D E2 20 02 8D E8 ?? ?? ?? EB 00 00 50 E3 85 50 A0 E1 03 00 00 1A 2C 30 1B E5 00 00 53 E3 03 00 00 1A 13 00 00 EA 22 00 50 E3 11 00 00 1A EC FF FF EA 00 00 86 E5 00 30 D4 E5 03 3C A0 E1 43 3C A0 E1 04 30 86 E5 02 30 D4 E5 02 00 13 E3 01 30 D4 05 0C 10 9A 15 03 3C A0 01 43 1C A0 01 08 10 86 E5 2C 30 1B E5 08 30 93 E5 00 00 A0 E3 0C 30 86 E5 00 00 00 EA 42 0F A0 E3 28 D0 4B E2 F0 AF 9D E8 }
	condition:
		$pattern
}

rule iruserok2_fc78019583de5b8e8ff0ade9aea0962c {
	meta:
		aliases = "iruserok2"
		size = "368"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 24 D0 4D E2 00 50 51 E2 00 A0 A0 E1 02 90 A0 E1 03 60 A0 E1 03 00 00 1A 38 01 9F E5 C8 FF FF EB 00 40 50 E2 01 00 00 1A 00 70 E0 E3 0A 00 00 EA 04 C0 9B E5 0A 10 A0 E1 06 20 A0 E1 09 30 A0 E1 00 C0 8D E5 E9 FE FF EB 00 70 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 00 57 E3 3B 00 00 0A F8 30 9F E5 00 30 93 E5 03 50 95 E1 36 00 00 0A 46 00 A0 E3 ?? ?? ?? EB 06 20 80 E2 03 20 C2 E3 0D D0 62 E0 00 30 A0 E1 2C C0 4B E2 06 00 A0 E1 48 10 4B E2 04 20 8D E2 00 C0 8D E5 ?? ?? ?? EB 00 00 50 E3 28 00 00 1A 2C 30 1B E5 00 00 53 E3 25 00 00 0A 14 00 93 E5 ?? ?? ?? EB 09 00 80 E2 }
	condition:
		$pattern
}

rule ruserok_7b0c57469db59b45bb775b043633c607 {
	meta:
		aliases = "ruserok"
		size = "236"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 28 D0 4D E2 01 DB 4D E2 04 D0 4D E2 02 80 A0 E1 00 50 A0 E1 01 A0 A0 E1 03 70 A0 E1 08 20 8D E2 01 4B A0 E3 2C 90 4B E2 34 60 4B E2 0A 00 00 EA 34 30 1B E5 01 00 73 E3 25 00 00 1A ?? ?? ?? EB 00 30 90 E5 22 00 53 E3 21 00 00 1A 06 30 84 E2 03 30 C3 E3 0D D0 63 E0 08 20 8D E2 04 30 A0 E1 48 10 4B E2 05 00 A0 E1 00 90 8D E5 04 60 8D E5 ?? ?? ?? EB 00 00 50 E3 84 40 A0 E1 EB FF FF 1A 2C 30 1B E5 00 00 53 E3 E8 FF FF 0A 10 40 93 E5 30 60 4B E2 08 00 00 EA ?? ?? ?? EB 30 00 1B E5 0A 10 A0 E1 08 20 A0 E1 07 30 A0 E1 00 50 8D E5 6B FF FF EB 00 00 50 E3 06 00 00 0A }
	condition:
		$pattern
}

rule getrpcport_b219c6731aa4a412759ecb16fc469acb {
	meta:
		aliases = "getrpcport"
		size = "232"
		objfiles = "getrpcport@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 34 D0 4D E2 01 DB 4D E2 04 D0 4D E2 02 80 A0 E1 00 60 A0 E1 01 70 A0 E1 03 A0 A0 E1 08 20 8D E2 01 4B A0 E3 30 90 4B E2 0A 00 00 EA 30 30 1B E5 01 00 73 E3 25 00 00 1A ?? ?? ?? EB 00 30 90 E5 22 00 53 E3 21 00 00 1A 06 30 84 E2 03 30 C3 E3 0D D0 63 E0 08 20 8D E2 04 30 A0 E1 2C C0 4B E2 54 10 4B E2 06 00 A0 E1 00 C0 8D E5 04 90 8D E5 ?? ?? ?? EB 00 50 50 E2 84 40 A0 E1 EA FF FF 1A 2C 20 1B E5 00 00 52 E3 E7 FF FF 0A 10 30 92 E5 40 40 4B E2 00 10 93 E5 0C 20 92 E5 04 00 84 E2 ?? ?? ?? EB 02 C0 A0 E3 04 00 A0 E1 07 10 A0 E1 08 20 A0 E1 0A 30 A0 E1 40 C0 4B E5 }
	condition:
		$pattern
}

rule callrpc_d36feefb5c09598460468e360f90a828 {
	meta:
		aliases = "callrpc"
		size = "624"
		objfiles = "clnt_simple@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 4C D0 4D E2 58 00 0B E5 5C 10 0B E5 60 20 0B E5 64 30 0B E5 ?? ?? ?? EB A4 50 90 E5 00 70 A0 E3 00 80 A0 E3 00 00 55 E3 00 40 A0 E1 07 90 A0 E1 08 A0 A0 E1 07 00 00 1A 01 00 A0 E3 18 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 05 00 A0 01 82 00 00 0A A4 00 84 E5 00 50 A0 E1 14 40 95 E5 00 00 54 E3 05 00 00 1A 01 0C A0 E3 ?? ?? ?? EB 00 30 E0 E3 14 00 85 E5 00 40 C0 E5 04 30 85 E5 10 30 95 E5 00 00 53 E3 0C 00 00 0A 08 30 95 E5 5C 20 1B E5 02 00 53 E1 08 00 00 1A 0C 30 95 E5 60 C0 1B E5 0C 00 53 E1 04 00 00 1A 14 00 95 E5 58 10 1B E5 ?? ?? ?? EB 00 00 50 E3 54 00 00 0A }
	condition:
		$pattern
}

rule glob_in_dir_31e52d79424eb145495c01660b2255f9 {
	meta:
		aliases = "glob_in_dir"
		size = "1220"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 7B DF 4D E2 00 A0 A0 E1 04 12 0B E5 01 00 A0 E1 02 70 A0 E1 03 60 A0 E1 ?? ?? ?? EB 40 50 17 E2 FC 01 0B E5 00 10 A0 13 01 10 A0 03 0A 00 A0 E1 04 90 9B E5 ?? ?? ?? EB 00 00 50 E3 2B 00 00 1A 81 0E 17 E3 27 00 00 1A 00 00 55 E3 04 00 00 1A 0A 00 A0 E1 5C 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 22 00 00 1A 0A 00 A0 E1 ?? ?? ?? EB FC 11 1B E5 00 30 81 E0 08 30 83 E2 03 30 C3 E3 0D D0 63 E0 04 50 8D E2 00 40 A0 E1 04 12 1B E5 FC 21 1B E5 05 00 A0 E1 ?? ?? ?? EB 01 20 A0 E3 10 14 9F E5 ?? ?? ?? EB 0A 10 A0 E1 01 20 84 E2 ?? ?? ?? EB 02 0C 17 E3 04 00 00 0A 05 00 A0 E1 }
	condition:
		$pattern
}

rule byte_re_match_2_internal_93d9c3a42e9f4ee1f4436ecac8eaac0d {
	meta:
		aliases = "byte_re_match_2_internal"
		size = "7504"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 80 D0 4D E2 18 C0 90 E5 9C 00 0B E5 00 50 90 E5 08 00 90 E5 00 00 85 E0 80 00 0B E5 9C 00 1B E5 14 00 90 E5 18 D0 4D E2 A0 10 0B E5 00 00 5C E3 01 10 8C E2 A4 20 0B E5 03 90 A0 E1 10 E0 9B E5 78 00 0B E5 74 10 0B E5 0D A0 A0 E1 09 00 00 1A 68 C0 0B E5 64 C0 0B E5 60 C0 0B E5 5C C0 0B E5 58 C0 0B E5 50 C0 0B E5 4C C0 0B E5 40 C0 0B E5 3C C0 0B E5 14 00 00 EA 74 20 1B E5 02 31 A0 E1 04 30 83 E2 0D D0 63 E0 68 D0 0B E5 0D D0 63 E0 64 D0 0B E5 0D D0 63 E0 60 D0 0B E5 0D D0 63 E0 5C D0 0B E5 0D D0 63 E0 50 D0 0B E5 0D D0 63 E0 4C D0 0B E5 0D D0 63 E0 58 D0 0B E5 }
	condition:
		$pattern
}

rule clntudp_call_0df020a33e0f7874483479d8b7ced5cb {
	meta:
		aliases = "clntudp_call"
		size = "1836"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 8D DD 4D E2 08 D0 4D E2 02 CA 4B E2 54 03 0C E5 EC 06 9F E5 28 C0 4B E2 00 10 8C E7 02 0A 4B E2 54 03 10 E5 08 60 90 E5 02 CA 4B E2 20 00 96 E5 FA 1F A0 E3 58 23 0C E5 5C 33 0C E5 ?? ?? ?? EB 1C 20 96 E5 FA 3F A0 E3 92 03 23 E0 28 10 96 E5 02 CA 4B E2 48 33 0C E5 01 00 71 E3 0C 30 8B E2 18 00 93 E8 24 30 96 15 0C 00 A0 01 02 2A 4B 12 38 33 00 05 38 33 02 15 00 10 A0 01 02 C0 A0 11 23 3C 4B E2 3C 13 0C 15 3C 43 01 05 02 0A 4B E2 28 30 43 E2 00 10 A0 E3 60 33 00 E5 4C 13 00 E5 00 20 A0 E1 08 00 43 E2 60 03 02 E5 02 C0 A0 E1 02 20 A0 E3 44 23 0C E5 0C 10 A0 E1 }
	condition:
		$pattern
}

rule gaih_inet_44815c9b39c6fbeb518d3f12e9c7ae1b {
	meta:
		aliases = "gaih_inet"
		size = "2808"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 94 D0 4D E2 02 80 A0 E1 04 20 92 E5 0A 00 52 E3 00 00 52 13 A0 30 0B E5 00 30 98 05 4C 20 4B E2 A3 31 A0 01 2C 20 0B E5 00 20 A0 E3 00 C0 A0 13 01 C0 A0 03 01 30 03 02 30 20 0B E5 00 70 A0 E1 01 60 A0 E1 4C 00 4B E2 00 10 A0 E3 10 20 A0 E3 9C C0 0B 15 9C 30 0B 05 ?? ?? ?? EB 0C 00 98 E5 00 00 50 E3 05 00 00 1A 08 30 98 E5 00 00 53 E3 02 00 00 1A 1C 00 00 EA 08 10 81 E2 00 00 00 EA 3C 1A 9F E5 03 C0 D1 E5 00 00 5C E3 11 00 00 0A 08 20 98 E5 00 00 52 E3 03 00 00 0A 00 30 D1 E5 03 3C A0 E1 43 0C 52 E1 F2 FF FF 1A 00 00 50 E3 06 00 00 0A 02 30 D1 E5 02 00 13 E3 }
	condition:
		$pattern
}

rule clnt_create_c21dda185081a16088d23694be0e11cc {
	meta:
		aliases = "clnt_create"
		size = "652"
		objfiles = "clnt_generic@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 BC D0 4D E2 00 90 A0 E1 DC 30 0B E5 01 80 A0 E1 03 00 A0 E1 60 12 9F E5 02 A0 A0 E1 ?? ?? ?? EB 00 50 50 E2 00 60 A0 E3 00 70 A0 E3 15 00 00 1A D8 40 4B E2 70 20 A0 E3 05 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 01 30 A0 E3 09 10 A0 E1 02 00 84 E2 D8 30 4B E5 D7 50 4B E5 ?? ?? ?? EB 08 10 A0 E1 00 C0 E0 E3 04 00 A0 E1 0A 20 A0 E1 34 30 4B E2 34 C0 0B E5 04 50 8D E5 00 50 8D E5 ?? ?? ?? EB 00 10 A0 E1 79 00 00 EA 01 DB 4D E2 04 D0 4D E2 08 20 8D E2 01 4B A0 E3 0E 00 00 EA 38 30 1B E5 01 00 73 E3 03 00 00 1A ?? ?? ?? EB 00 30 90 E5 22 00 53 E3 03 00 00 0A ?? ?? ?? EB }
	condition:
		$pattern
}

rule glob_in_dir_ca85445234849a0cca34f0289cf658ad {
	meta:
		aliases = "glob_in_dir"
		size = "1144"
		objfiles = "glob64@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 E4 D0 4D E2 00 A0 A0 E1 00 11 0B E5 01 00 A0 E1 02 60 A0 E1 03 70 A0 E1 ?? ?? ?? EB 40 50 16 E2 F8 00 0B E5 00 10 A0 13 01 10 A0 03 0A 00 A0 E1 04 90 9B E5 ?? ?? ?? EB 00 00 50 E3 2B 00 00 1A 81 0E 16 E3 27 00 00 1A 00 00 55 E3 04 00 00 1A 0A 00 A0 E1 5C 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 22 00 00 1A 0A 00 A0 E1 ?? ?? ?? EB F8 10 1B E5 00 30 81 E0 08 30 83 E2 03 30 C3 E3 0D D0 63 E0 04 50 8D E2 00 40 A0 E1 00 11 1B E5 F8 20 1B E5 05 00 A0 E1 ?? ?? ?? EB 01 20 A0 E3 C4 13 9F E5 ?? ?? ?? EB 0A 10 A0 E1 01 20 84 E2 ?? ?? ?? EB 02 0C 16 E3 04 00 00 0A 05 00 A0 E1 }
	condition:
		$pattern
}

rule __getdents64_241b96b66c50cd839faa9a8ddb85f477 {
	meta:
		aliases = "__getdents64"
		size = "352"
		objfiles = "getdents64@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 06 30 82 E2 04 B0 4C E2 10 D0 4D E2 03 30 C3 E3 0D D0 63 E0 01 80 A0 E1 01 60 A0 E1 34 00 0B E5 0D 10 A0 E1 D9 00 90 EF 01 0A 70 E3 00 40 A0 E1 04 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 40 E0 E3 00 30 80 E5 01 00 00 EA 01 00 70 E3 01 00 00 1A 04 10 A0 E1 3C 00 00 EA 00 40 8D E0 38 40 0B E5 00 30 E0 E3 00 40 E0 E3 0D 50 A0 E1 02 90 88 E0 30 30 0B E5 2C 40 0B E5 2C 00 00 EA 01 20 D7 E5 10 30 D5 E5 02 34 83 E1 03 30 83 E2 03 20 C3 E3 02 A0 86 E0 09 00 5A E1 42 C4 A0 E1 0B 00 00 9A 34 00 1B E5 30 10 4B E2 06 00 91 E8 00 30 A0 E3 ?? ?? ?? EB 08 00 56 E1 22 00 00 1A ?? ?? ?? EB }
	condition:
		$pattern
}

rule __GI_ruserpass_f0cfe6b390974686bc2b43bc64d46788 {
	meta:
		aliases = "ruserpass, __GI_ruserpass"
		size = "836"
		objfiles = "ruserpass@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 45 DE 4D E2 04 B0 4C E2 08 D0 4D E2 01 70 A0 E1 02 A0 A0 E1 00 60 A0 E1 ?? ?? ?? EB 00 40 A0 E1 ?? ?? ?? EB 00 00 54 E1 B5 00 00 1A ?? ?? ?? EB 00 40 A0 E1 ?? ?? ?? EB 00 00 54 E1 B0 00 00 1A C8 02 9F E5 ?? ?? ?? EB 00 40 50 E2 AC 00 00 0A ?? ?? ?? EB 0E 00 80 E2 03 00 C0 E3 0D D0 60 E0 04 10 A0 E1 0D 00 A0 E1 ?? ?? ?? EB A0 12 9F E5 0D 00 A0 E1 ?? ?? ?? EB 0D 00 A0 E1 94 12 9F E5 ?? ?? ?? EB 90 32 9F E5 00 00 50 E3 0D 50 A0 E1 00 40 A0 E1 00 00 83 E5 07 00 00 1A ?? ?? ?? EB 00 30 90 E5 02 00 53 E3 0D 10 A0 11 6C 02 9F 15 ?? ?? ?? 1B 04 00 A0 E1 92 00 00 EA 47 4E 4B E2 }
	condition:
		$pattern
}

rule _fini_522dd4955bdec9b323151dc7dcd03dcd {
	meta:
		aliases = "_init, _fini"
		size = "12"
		objfiles = "crti"
	strings:
		$pattern = { 0D C0 A0 E1 F8 DF 2D E9 04 B0 4C E2 }
	condition:
		$pattern
}

rule errx_c8f1b022fb02968909268fe66e08fb7f {
	meta:
		aliases = "err, errx"
		size = "28"
		objfiles = "err@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 04 D0 4D E2 08 30 8D E2 03 20 A0 E1 04 10 9D E5 00 30 8D E5 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __libc_open64_514b27a82d8ef887189958fd0549252f {
	meta:
		aliases = "__GI_open64, open64, __libc_open64"
		size = "56"
		objfiles = "open64@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 04 E0 2D E5 04 D0 4D E2 08 10 9D E5 40 20 11 E2 10 30 8D 12 0C 20 9D 15 02 18 81 E3 00 30 8D 15 ?? ?? ?? EB 04 D0 8D E2 04 E0 9D E4 0C D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_asprintf_b894f9a4909b4c2528ee0248ddf88a00 {
	meta:
		aliases = "fscanf, fwscanf, __GI_fwprintf, __GI_fprintf, asprintf, __GI_syslog, fwprintf, fprintf, __GI_fscanf, __GI_sscanf, sscanf, syslog, dprintf, swscanf, __GI_asprintf"
		size = "48"
		objfiles = "dprintf@libc.a, syslog@libc.a, swscanf@libc.a, fscanf@libc.a, fprintf@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 04 E0 2D E5 04 D0 4D E2 0C 30 8D E2 03 20 A0 E1 08 10 9D E5 00 30 8D E5 ?? ?? ?? EB 04 D0 8D E2 04 E0 9D E4 0C D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_sprintf_efcf0e00d2547f3073643f3d2cdf15ae {
	meta:
		aliases = "sprintf, __GI_sprintf"
		size = "52"
		objfiles = "sprintf@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 04 E0 2D E5 04 D0 4D E2 0C C0 8D E2 0C 30 A0 E1 00 10 E0 E3 08 20 9D E5 00 C0 8D E5 ?? ?? ?? EB 04 D0 8D E2 04 E0 9D E4 0C D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule sem_open_8f0ea4070981b315061d579eebc59fe3 {
	meta:
		aliases = "sem_open"
		size = "36"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { 0E 00 2D E9 04 E0 2D E5 ?? ?? ?? EB 26 30 A0 E3 00 30 80 E5 00 00 A0 E3 04 E0 9D E4 0C D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule mq_open_a3f1438459bdf4b9760752d757e4dfd4 {
	meta:
		aliases = "mq_open"
		size = "140"
		objfiles = "mq_open@librt.a"
	strings:
		$pattern = { 0E 00 2D E9 10 40 2D E9 00 30 D0 E5 04 D0 4D E2 2F 00 53 E3 0C 10 9D E5 04 00 00 0A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 11 00 00 EA 40 30 11 E2 10 20 9D 15 03 20 A0 01 18 30 8D 12 02 28 A0 E1 00 30 8D 15 01 00 80 E2 14 30 9D 15 22 28 A0 E1 12 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 20 A0 E1 02 00 A0 E1 04 D0 8D E2 10 40 BD E8 0C D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_fcntl_e11235c302c78487c0691882cb8b2dbd {
	meta:
		aliases = "fcntl, __libc_fcntl, __GI_fcntl"
		size = "100"
		objfiles = "__syscall_fcntl@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 10 40 2D E9 04 D0 4D E2 0C 10 9D E5 0C 30 41 E2 02 00 53 E3 14 30 8D E2 00 30 8D E5 10 20 9D E5 01 00 00 8A ?? ?? ?? EB 08 00 00 EA 37 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 04 D0 8D E2 10 40 BD E8 0C D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_open_6386fddfbd0437a794e8de24796d33bc {
	meta:
		aliases = "__libc_open, open, __GI_open"
		size = "92"
		objfiles = "open@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 10 40 2D E9 04 D0 4D E2 0C 10 9D E5 40 20 11 E2 10 20 9D 15 14 30 8D 12 02 28 A0 E1 00 30 8D 15 22 28 A0 E1 05 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 04 D0 8D E2 10 40 BD E8 0C D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule ioctl_ddb6a003763def04a11e78bcf4b29e6a {
	meta:
		aliases = "__GI_ioctl, ioctl"
		size = "80"
		objfiles = "ioctl@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 10 40 2D E9 04 D0 4D E2 14 30 8D E2 00 30 8D E5 0C 10 8D E2 06 00 91 E8 36 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 04 D0 8D E2 10 40 BD E8 0C D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_fcntl64_ea772faf4a859bf12c55c86e5c62dd83 {
	meta:
		aliases = "fcntl64, __GI_fcntl64"
		size = "80"
		objfiles = "__syscall_fcntl64@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 10 40 2D E9 04 D0 4D E2 14 30 8D E2 00 30 8D E5 0C 10 8D E2 06 00 91 E8 DD 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 04 D0 8D E2 10 40 BD E8 0C D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule open_cab87d0901014a7f96b83a750d00f80a {
	meta:
		aliases = "fcntl, open64, open"
		size = "88"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { 0E 00 2D E9 10 40 2D E9 08 D0 4D E2 00 40 A0 E1 04 10 8D E2 01 00 A0 E3 ?? ?? ?? EB 18 30 8D E2 10 10 8D E2 06 00 91 E8 04 00 A0 E1 00 30 8D E5 ?? ?? ?? EB 00 10 A0 E3 00 40 A0 E1 04 00 9D E5 ?? ?? ?? EB 04 00 A0 E1 08 D0 8D E2 10 40 BD E8 0C D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule _dl_dprintf_80562c3c78ed6e2e9369397370755b35 {
	meta:
		aliases = "_dl_dprintf"
		size = "960"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 0E 00 2D E9 F0 4F 2D E9 1C D0 4D E2 40 E0 9D E5 00 00 5E E3 00 60 A0 E1 DE 00 00 0A 84 33 9F E5 00 00 A0 E3 00 10 93 E5 03 20 A0 E3 22 30 A0 E3 00 40 E0 E3 00 50 A0 E1 C0 00 90 EF 01 0A 70 E3 00 50 A0 E1 60 33 9F 85 00 20 60 82 04 50 A0 81 00 20 83 85 01 00 00 8A 01 00 70 E3 0D 00 00 1A 06 00 A0 E1 44 13 9F E5 1D 20 A0 E3 04 00 90 EF 01 0A 70 E3 30 33 9F 85 00 20 60 82 00 20 83 85 14 00 A0 E3 01 00 90 EF 01 0A 70 E3 18 33 9F 85 00 20 60 82 00 20 83 85 01 C0 4E E2 0C 20 A0 E1 01 30 F2 E5 00 00 53 E3 FC FF FF 1A F4 32 9F E5 00 30 93 E5 02 20 6E E0 01 30 43 E2 03 00 52 E1 0D 00 00 3A 06 00 A0 E1 }
	condition:
		$pattern
}

rule warn_dd60735d76fdb5bc201ac5322c5bc580 {
	meta:
		aliases = "warnx, warn"
		size = "48"
		objfiles = "err@libc.a"
	strings:
		$pattern = { 0F 00 2D E9 04 E0 2D E5 04 D0 4D E2 0C 30 8D E2 03 10 A0 E1 08 00 9D E5 00 30 8D E5 ?? ?? ?? EB 04 D0 8D E2 04 E0 9D E4 10 D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule ulimit_958ff6806a2d2a04b80eae5d39aa7db9 {
	meta:
		aliases = "ulimit"
		size = "164"
		objfiles = "ulimit@libc.a"
	strings:
		$pattern = { 0F 00 2D E9 04 E0 2D E5 0C D0 4D E2 10 00 9D E5 14 20 8D E2 02 00 50 E3 08 20 8D E5 0A 00 00 0A 04 00 50 E3 14 00 00 0A 01 00 50 E3 14 00 00 1A 0D 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 30 9D 05 A3 04 A0 01 12 00 00 0A 10 00 00 EA 14 30 9D E5 02 05 53 E3 00 30 E0 23 83 34 A0 31 04 30 8D E5 00 30 8D E5 0D 10 A0 E1 04 30 82 E2 01 00 A0 E3 08 30 8D E5 ?? ?? ?? EB 05 00 00 EA ?? ?? ?? EB 03 00 00 EA ?? ?? ?? EB 16 30 A0 E3 00 30 80 E5 00 00 E0 E3 0C D0 8D E2 04 E0 9D E4 10 D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule scanf_0304853a5bbd79b71a43422fdd25bd20 {
	meta:
		aliases = "wscanf, __GI_printf, wprintf, printf, scanf"
		size = "60"
		objfiles = "wscanf@libc.a, scanf@libc.a, wprintf@libc.a, printf@libc.a"
	strings:
		$pattern = { 0F 00 2D E9 04 E0 2D E5 28 30 9F E5 04 D0 4D E2 0C C0 8D E2 00 00 93 E5 0C 20 A0 E1 08 10 9D E5 00 C0 8D E5 ?? ?? ?? EB 04 D0 8D E2 04 E0 9D E4 10 D0 8D E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ptrace_4bc55ed4e410761644c262a4b3b03e87 {
	meta:
		aliases = "ptrace"
		size = "156"
		objfiles = "ptrace@libc.a"
	strings:
		$pattern = { 0F 00 2D E9 30 40 2D E9 08 D0 4D E2 14 50 9D E5 01 30 45 E2 02 00 53 E3 24 30 8D E2 00 30 8D E5 18 10 8D E2 0E 00 91 E8 04 30 8D 92 05 00 A0 E1 1A 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 30 E0 E1 A3 3F A0 E1 00 00 55 E3 00 30 A0 03 00 00 53 E3 06 00 00 0A 03 00 55 E3 04 00 00 8A ?? ?? ?? EB 04 20 9D E5 00 30 A0 E3 00 30 80 E5 00 00 00 EA 04 20 A0 E1 02 00 A0 E1 08 D0 8D E2 30 40 BD E8 10 D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __aeabi_cfcmpeq_f6fc4a5fad48d06726d9d4590901cd50 {
	meta:
		aliases = "__aeabi_cfcmple, __aeabi_cfcmpeq"
		size = "20"
		objfiles = "_cmpsf2@libgcc.a"
	strings:
		$pattern = { 0F 40 2D E9 ?? ?? ?? EB 00 00 50 E3 00 00 70 43 0F 80 BD E8 }
	condition:
		$pattern
}

rule regerror_ffd30daeeac6590d2d0f87f153f770e8 {
	meta:
		aliases = "regerror"
		size = "144"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 10 00 50 E3 F0 40 2D E9 02 70 A0 E1 03 60 A0 E1 ?? ?? ?? 8B 6C 20 9F E5 80 30 A0 E1 02 10 83 E0 02 30 D3 E7 01 20 D1 E5 02 34 83 E1 58 20 9F E5 02 40 83 E0 04 00 A0 E1 ?? ?? ?? EB 00 00 56 E3 01 50 80 E2 0D 00 00 0A 06 00 55 E1 07 00 00 9A 01 20 46 E2 04 10 A0 E1 07 00 A0 E1 ?? ?? ?? EB 06 20 87 E0 00 30 A0 E3 01 30 42 E5 03 00 00 EA 07 00 A0 E1 04 10 A0 E1 05 20 A0 E1 ?? ?? ?? EB 05 00 A0 E1 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule telldir_7889e5a1a83058136a874ca7324bcb0b {
	meta:
		aliases = "telldir"
		size = "8"
		objfiles = "telldir@libc.a"
	strings:
		$pattern = { 10 00 90 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule inl_97116d512a18a5bcf424e3ede82b5460 {
	meta:
		aliases = "inl"
		size = "28"
		objfiles = "ioperm@libc.a"
	strings:
		$pattern = { 10 20 9F E5 08 30 92 E5 10 03 A0 E1 00 30 92 E5 03 00 90 E7 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule inb_abe71e7dd7afb477c8a3f9930a18b003 {
	meta:
		aliases = "inb"
		size = "28"
		objfiles = "ioperm@libc.a"
	strings:
		$pattern = { 10 20 9F E5 08 30 92 E5 10 03 A0 E1 00 30 92 E5 03 00 D0 E7 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule outl_048b2d57d0c84a48501784a5752e9b3d {
	meta:
		aliases = "outl"
		size = "28"
		objfiles = "ioperm@libc.a"
	strings:
		$pattern = { 10 20 9F E5 08 30 92 E5 11 13 A0 E1 00 30 92 E5 03 00 81 E7 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_attr_getscope_ef5b01ac6d4509787670ac91c03a07b4 {
	meta:
		aliases = "__GI_pthread_attr_getscope, pthread_attr_getscope"
		size = "16"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 10 30 90 E5 00 00 A0 E3 00 30 81 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __scan_ungetc_5e22462b269067f1d2a6f2a0f5dbf70e {
	meta:
		aliases = "__scan_ungetc"
		size = "68"
		objfiles = "__scan_cookie@libc.a"
	strings:
		$pattern = { 10 30 90 E5 19 20 D0 E5 01 30 83 E2 02 00 52 E3 10 30 80 E5 04 30 90 05 00 30 80 05 00 30 A0 03 05 00 00 0A 00 00 52 E3 0E F0 A0 11 0C 30 90 E5 01 30 43 E2 0C 30 80 E5 01 30 A0 E3 19 30 C0 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_free_e61c14fbe9c1008ea96e5ceb916de1b5 {
	meta:
		aliases = "pthread_free"
		size = "204"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { 10 30 90 E5 30 40 2D E9 03 3B A0 E1 A8 40 9F E5 23 3B A0 E1 03 42 84 E0 00 50 A0 E1 00 10 A0 E3 04 00 A0 E1 ?? ?? ?? EB 00 30 A0 E3 08 30 84 E5 00 30 E0 E3 0C 30 84 E5 04 00 A0 E1 ?? ?? ?? EB 78 20 9F E5 00 30 92 E5 48 41 95 E5 01 30 43 E2 00 30 82 E5 01 00 00 EA 00 40 94 E5 ?? ?? ?? EB 00 00 54 E2 FB FF FF 1A 4C 41 95 E5 01 00 00 EA 00 40 94 E5 ?? ?? ?? EB 00 00 54 E2 FB FF FF 1A 3C 30 9F E5 03 00 55 E1 30 80 BD 08 10 31 95 E5 00 00 53 E3 30 80 BD 18 18 11 95 E5 00 00 51 E3 14 01 95 15 ?? ?? ?? 1B 18 00 9F E5 02 16 A0 E3 00 00 85 E0 30 40 BD E8 ?? ?? ?? EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __md5_Update_9b0cb4ef88a30781b57e0235def52dd5 {
	meta:
		aliases = "__md5_Update"
		size = "176"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { 10 30 90 E5 F0 41 2D E9 02 70 A0 E1 82 21 A0 E1 00 50 A0 E1 03 00 82 E0 02 00 50 E1 A3 31 A0 E1 3F 20 03 E2 14 30 95 35 01 30 83 32 14 30 85 35 14 30 95 E5 40 60 62 E2 A7 3E 83 E0 06 00 57 E1 10 00 85 E5 01 80 A0 E1 14 30 85 E5 00 40 A0 33 10 00 00 3A 18 40 85 E2 02 00 84 E0 06 20 A0 E1 ?? ?? ?? EB 04 10 A0 E1 05 00 A0 E1 7D FF FF EB 06 40 A0 E1 01 00 00 EA 7A FF FF EB 40 40 84 E2 3F 30 84 E2 07 00 53 E1 04 10 88 E0 05 00 A0 E1 F8 FF FF 3A 00 20 A0 E3 18 00 85 E2 02 00 80 E0 04 10 88 E0 07 20 64 E0 F0 41 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __GI___isinff_666c1aab445e9825e268f6860b79b830 {
	meta:
		aliases = "__isinff, __GI___isinff"
		size = "28"
		objfiles = "s_isinff@libm.a"
	strings:
		$pattern = { 10 30 9F E5 02 21 C0 E3 03 00 52 E1 40 0F A0 01 00 00 A0 13 0E F0 A0 E1 00 00 80 7F }
	condition:
		$pattern
}

rule system_db7a1251c6f64182bc97303843acefc2 {
	meta:
		aliases = "__libc_system, system"
		size = "312"
		objfiles = "system@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 00 50 E3 18 D0 4D E2 04 00 8D E5 01 00 A0 03 42 00 00 0A 01 10 A0 E3 03 00 A0 E3 ?? ?? ?? EB 01 10 A0 E3 08 00 8D E5 02 00 A0 E3 ?? ?? ?? EB 00 10 A0 E3 0C 00 8D E5 11 00 A0 E3 ?? ?? ?? EB 10 00 8D E5 ?? ?? ?? EB 00 40 50 E2 0A 00 00 AA 08 10 9D E5 03 00 A0 E3 ?? ?? ?? EB 0C 10 9D E5 02 00 A0 E3 ?? ?? ?? EB 10 10 9D E5 11 00 A0 E3 ?? ?? ?? EB 00 00 E0 E3 28 00 00 EA 10 00 00 1A 04 10 A0 E1 03 00 A0 E3 ?? ?? ?? EB 04 10 A0 E1 02 00 A0 E3 ?? ?? ?? EB 04 10 A0 E1 11 00 A0 E3 ?? ?? ?? EB 04 30 9D E5 78 00 9F E5 78 10 9F E5 78 20 9F E5 00 40 8D E5 ?? ?? ?? EB 7F 00 A0 E3 ?? ?? ?? EB }
	condition:
		$pattern
}

rule pthread_kill_other_threads_np_500ce6a5a728fa826815334fe85fbcf5 {
	meta:
		aliases = "__pthread_kill_other_threads_np, pthread_kill_other_threads_np"
		size = "128"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 00 00 A0 E3 00 10 A0 E1 14 D0 4D E2 A5 FF FF EB 0D 40 A0 E1 ?? ?? ?? EB 00 10 A0 E3 14 20 A0 E3 0D 00 A0 E1 ?? ?? ?? EB 40 30 9F E5 0D 10 A0 E1 00 00 93 E5 00 20 A0 E3 ?? ?? ?? EB 30 30 9F E5 0D 10 A0 E1 00 00 93 E5 00 20 A0 E3 ?? ?? ?? EB 20 30 9F E5 00 00 93 E5 00 00 50 E3 0D 10 A0 C1 00 20 A0 C3 ?? ?? ?? CB 14 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __fixsfdi_3d15d5d84b32f8bdf3d27d77481a0c01 {
	meta:
		aliases = "__fixsfdi"
		size = "56"
		objfiles = "_fixsfdi@libgcc.a"
	strings:
		$pattern = { 10 40 2D E9 00 10 A0 E3 00 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 02 00 00 BA 04 00 A0 E1 10 40 BD E8 ?? ?? ?? EA 02 01 84 E2 ?? ?? ?? EB 00 00 70 E2 00 10 E1 E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __stdio_trans2w_o_4487beb4878a63cd812a2934845b4705 {
	meta:
		aliases = "__stdio_trans2w_o"
		size = "260"
		objfiles = "_trans2w@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 20 D0 E5 01 30 D0 E5 03 24 82 E1 02 00 11 E1 00 40 A0 E1 05 00 00 1A 22 0D 12 E3 08 00 00 1A 02 20 81 E1 42 34 A0 E1 01 30 C0 E5 00 20 C0 E5 00 20 D4 E5 01 30 D4 E5 03 C4 82 E1 20 00 1C E3 09 00 00 0A ?? ?? ?? EB 09 30 A0 E3 00 30 80 E5 00 30 94 E5 08 30 83 E3 43 24 A0 E1 00 00 E0 E3 01 20 C4 E5 00 30 C4 E5 10 80 BD E8 03 00 1C E3 16 00 00 0A 04 10 1C E2 0B 00 00 1A 14 20 94 E5 10 30 94 E5 03 00 52 E1 01 00 00 1A 02 00 1C E3 05 00 00 0A 01 0B 1C E3 01 20 A0 03 02 20 A0 13 ?? ?? ?? EB 00 00 50 E3 E8 FF FF 1A 00 30 94 E5 08 10 94 E5 03 30 C3 E3 43 24 A0 E1 01 20 C4 E5 14 10 84 E5 }
	condition:
		$pattern
}

rule __GI_wcrtomb_7e8e101d1b6e1ba29cc0c1db789c0891 {
	meta:
		aliases = "wcrtomb, __GI_wcrtomb"
		size = "80"
		objfiles = "wcrtomb@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 30 50 E2 1C D0 4D E2 04 30 8D 02 01 E0 A0 E1 02 40 A0 E1 00 E0 A0 01 18 C0 8D E2 03 00 A0 E1 14 10 8D E2 01 20 A0 E3 10 30 A0 E3 14 C0 8D E5 18 E0 8D E5 00 40 8D E5 ?? ?? ?? EB 00 00 50 E3 01 00 A0 03 1C D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_strncat_da1c482222e8b67a04686fb16253c07d {
	meta:
		aliases = "strncat, __GI_strncat"
		size = "200"
		objfiles = "strncat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 30 A0 E1 00 40 A0 E1 01 C0 D3 E4 00 00 5C E3 FC FF FF 1A 03 00 52 E3 02 E0 43 E2 22 00 00 9A 22 01 A0 E1 00 30 D1 E5 00 00 53 E3 01 30 CE E5 01 C0 8E E2 20 00 00 0A 01 30 D1 E5 00 00 53 E3 01 30 CC E5 01 10 81 E2 01 C0 8C E2 1A 00 00 0A 01 30 D1 E5 00 00 53 E3 01 30 CC E5 01 10 81 E2 01 E0 8C E2 14 00 00 0A 01 C0 D1 E5 01 30 81 E2 00 00 5C E3 01 C0 CE E5 01 10 83 E2 01 E0 8E E2 0D 00 00 0A 01 00 50 E2 E5 FF FF 1A 03 20 02 E2 05 00 00 EA 00 C0 D1 E5 00 00 5C E3 01 C0 EE E5 05 00 00 0A 01 10 81 E2 01 20 42 E2 00 00 52 E3 F7 FF FF 1A 00 00 5C E3 01 20 CE 15 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule mq_unlink_e3ed23049f56ea413632c93008c8a7ed {
	meta:
		aliases = "mq_unlink"
		size = "112"
		objfiles = "mq_unlink@librt.a"
	strings:
		$pattern = { 10 40 2D E9 00 30 D0 E5 2F 00 53 E3 04 00 00 0A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 10 00 00 EA 01 00 80 E2 13 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 00 20 54 E2 05 00 00 AA ?? ?? ?? EB 00 30 90 E5 01 00 53 E3 0D 30 A0 03 00 30 80 E5 00 20 E0 E3 02 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule xdr_char_5773e5e1d2a9ab8e40f6b58889eb5081 {
	meta:
		aliases = "xdr_u_char, xdr_char"
		size = "56"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 30 D1 E5 04 D0 4D E2 01 40 A0 E1 04 10 8D E2 04 30 21 E5 0D 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 30 9D 15 01 00 A0 13 00 30 C4 15 04 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule hdestroy_r_3dc0eaf4579ccd6c547fa55158b6cdb9 {
	meta:
		aliases = "__GI_hdestroy_r, hdestroy_r"
		size = "48"
		objfiles = "hdestroy_r@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 50 E2 03 00 00 1A ?? ?? ?? EB 16 30 A0 E3 00 30 80 E5 10 80 BD E8 00 00 94 E5 ?? ?? ?? EB 00 30 A0 E3 00 30 84 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule tmpnam_r_bf30018d7fa0383e678f63e83b168030 {
	meta:
		aliases = "tmpnam_r"
		size = "68"
		objfiles = "tmpnam_r@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 50 E2 0A 00 00 0A 00 20 A0 E3 14 10 A0 E3 02 30 A0 E1 ?? ?? ?? EB 00 00 50 E3 04 00 00 1A 04 00 A0 E1 03 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 00 00 00 0A 00 40 A0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule dirfd_72deeb3556701f754638cf3f571c21c8 {
	meta:
		aliases = "__GI_dirfd, dirfd"
		size = "36"
		objfiles = "dirfd@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 90 E5 01 00 74 E3 02 00 00 1A ?? ?? ?? EB 09 30 A0 E3 00 30 80 E5 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_freeaddrinfo_44f800c99271ba1b2621309a7dc8bec2 {
	meta:
		aliases = "freeaddrinfo, __GI_freeaddrinfo"
		size = "32"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 01 00 00 EA 1C 40 94 E5 ?? ?? ?? EB 00 00 54 E2 FB FF FF 1A 10 80 BD E8 }
	condition:
		$pattern
}

rule pthread_call_handlers_fbb9f0a732fdb5ce4e84b39dd5a26ed6 {
	meta:
		aliases = "pthread_call_handlers"
		size = "36"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 02 00 00 EA 0F E0 A0 E1 00 F0 94 E5 04 40 94 E5 00 00 54 E3 FA FF FF 1A 10 80 BD E8 }
	condition:
		$pattern
}

rule sc_getc_1598aec63064902ef269693433ce6223 {
	meta:
		aliases = "sc_getc"
		size = "144"
		objfiles = "vfwscanf@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 08 00 90 E5 04 30 90 E5 03 00 73 E3 0C 00 00 1A 10 20 90 E5 0C 30 90 E5 03 00 52 E1 04 10 92 34 10 20 80 35 0A 00 00 3A 00 30 90 E5 04 30 83 E3 43 24 A0 E1 00 10 E0 E3 01 20 C0 E5 00 30 C0 E5 0E 00 00 EA ?? ?? ?? EB 01 00 70 E3 00 10 A0 E1 0A 00 00 0A 01 30 A0 E3 1A 30 C4 E5 28 10 84 E5 08 30 94 E5 38 20 94 E5 02 30 D3 E5 02 00 51 E1 18 30 C4 E5 24 10 84 15 04 10 84 15 2E 10 A0 03 01 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __register_frame_table_b734490cf8caa6f405a401125c57e0d8 {
	meta:
		aliases = "__register_frame_table"
		size = "32"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 18 00 A0 E3 ?? ?? ?? EB 00 10 A0 E1 04 00 A0 E1 10 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule pthread_handle_sigrestart_fa83fb9d3b2f2b612ef7f4d3274f3280 {
	meta:
		aliases = "pthread_handle_sigrestart"
		size = "40"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 99 FD FF EB 24 30 90 E5 00 00 53 E3 20 40 80 E5 10 80 BD 08 03 00 A0 E1 01 10 A0 E3 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __ether_line_7ae4d53b78c9336c1fdbc86686fedf01 {
	meta:
		aliases = "__ether_line"
		size = "104"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 40 A0 01 11 00 00 0A 00 00 00 EA 01 40 84 E2 00 30 D4 E5 00 00 53 E3 20 00 53 13 03 00 00 0A 09 00 53 E3 F8 FF FF 1A 00 00 00 EA 01 40 84 E2 00 30 D4 E5 00 00 53 E3 03 00 00 0A 09 00 53 E3 20 00 53 13 F8 FF FF 0A 00 00 00 EA 03 40 A0 E1 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule cuserid_10a32b4c8db4fe83dd88850d7e82babb {
	meta:
		aliases = "cuserid"
		size = "48"
		objfiles = "getlogin@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 ?? ?? ?? EB 00 00 54 E3 10 80 BD 08 00 00 50 E3 0C 10 9F E5 00 10 A0 11 04 00 A0 E1 10 40 BD E8 ?? ?? ?? EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __syscall_error_1e931aa92c1e17bb52500521e95eb8ec {
	meta:
		aliases = "__syscall_error"
		size = "28"
		objfiles = "__syscall_error@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 ?? ?? ?? EB 00 40 64 E2 00 40 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __set_h_errno_faae2fde72e819b99a2a60a0e14e719b {
	meta:
		aliases = "__set_h_errno"
		size = "24"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 ?? ?? ?? EB 00 40 80 E5 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_pthread_attr_init_31c15af14bd5cb148f34d1aeb60c8ab1 {
	meta:
		aliases = "pthread_attr_init, __GI_pthread_attr_init"
		size = "68"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 ?? ?? ?? EB 02 36 60 E2 00 20 A0 E1 20 30 84 E5 00 00 A0 E3 01 30 A0 E3 0C 30 84 E5 00 00 84 E5 04 00 84 E5 08 00 84 E5 10 00 84 E5 14 20 84 E5 1C 00 84 E5 18 00 84 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule login_tty_854a04f11b9b9fbe0f37c366af1aa6ef {
	meta:
		aliases = "__GI_login_tty, login_tty"
		size = "104"
		objfiles = "login_tty@libutil.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 ?? ?? ?? EB 04 00 A0 E1 4C 10 9F E5 00 20 A0 E3 ?? ?? ?? EB 01 00 70 E3 10 80 BD 08 00 10 A0 E3 04 00 A0 E1 ?? ?? ?? EB 01 10 A0 E3 04 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 02 10 A0 E3 ?? ?? ?? EB 02 00 54 E3 00 00 A0 D3 10 80 BD D8 04 00 A0 E1 ?? ?? ?? EB 00 00 A0 E3 10 80 BD E8 0E 54 00 00 }
	condition:
		$pattern
}

rule __GI_raise_95d5c8be653a1bd4a1826b148e18757e {
	meta:
		aliases = "raise, __GI_raise"
		size = "24"
		objfiles = "raise@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 ?? ?? ?? EB 04 10 A0 E1 10 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __GI_raise_df0ba4b637da733d0113c35855deb6cc {
	meta:
		aliases = "raise, __GI_raise"
		size = "48"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 ?? ?? ?? EB 04 10 A0 E1 ?? ?? ?? EB 00 40 50 E2 04 00 A0 01 10 80 BD 08 ?? ?? ?? EB 00 40 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule uw_init_context_869bfee89f3af3072267f3b1ee7b4cb6 {
	meta:
		aliases = "uw_init_context"
		size = "20"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 B5 FF FF EB 00 00 84 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule pthread_handle_sigcancel_d64cc5102ef2f2a16ddf2850f6128dc6 {
	meta:
		aliases = "pthread_handle_sigcancel"
		size = "180"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 C6 FD FF EB 90 20 9F E5 02 00 50 E1 02 00 00 1A 04 00 A0 E1 10 40 BD E8 ?? ?? ?? EA 7C 30 9F E5 00 30 93 E5 00 00 53 E3 09 00 00 0A 70 30 9F E5 00 30 93 E5 03 00 50 E1 14 00 92 05 00 10 A0 03 02 21 A0 03 ?? ?? ?? 0B 58 30 9F E5 00 00 93 E5 ?? ?? ?? EB 42 30 D0 E5 00 00 53 E3 10 80 BD 08 40 20 D0 E5 00 00 52 E3 10 80 BD 18 41 30 D0 E5 01 00 53 E3 00 00 E0 03 0D 10 A0 01 ?? ?? ?? 0B 28 30 90 E5 00 00 53 E3 10 80 BD 08 28 20 80 E5 01 10 A0 E3 03 00 A0 E1 ?? ?? ?? EB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule waitid_c22ac4e69a965b43a23619378e9c82c6 {
	meta:
		aliases = "waitid"
		size = "48"
		objfiles = "waitid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E3 18 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule ppoll_6cf217a123d64a6d95b8569e0ba4cf32 {
	meta:
		aliases = "__GI_ppoll, ppoll"
		size = "84"
		objfiles = "ppoll@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 C0 52 E2 04 20 9C 15 00 C0 9C 15 08 D0 4D E2 00 C0 8D 15 0D C0 A0 11 04 20 8D 15 08 40 A0 E3 0C 20 A0 E1 50 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 08 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __register_frame_info_table_ba_2bd16ea7b10ee076b407d783c1840899 {
	meta:
		aliases = "__register_frame_info_table_bases"
		size = "88"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { 10 40 2D E9 00 E0 A0 E3 10 E0 81 E5 10 C0 D1 E5 02 C0 8C E3 10 C0 C1 E5 10 E0 91 E5 7F EE 8E E3 08 E0 8E E3 4E C4 A0 E1 11 C0 C1 E5 10 E0 C1 E5 1C 40 9F E5 00 C0 94 E5 0C 00 81 E5 00 00 E0 E3 14 C0 81 E5 00 00 81 E5 00 10 84 E5 0C 00 81 E9 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule msgctl_76eef0b581c7f80be96dbe54c3ae7bed {
	meta:
		aliases = "msgctl"
		size = "48"
		objfiles = "msgctl@libc.a"
	strings:
		$pattern = { 10 40 2D E9 01 1C 81 E3 30 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule shmctl_c731144fbe2bfbd862d6d24ac82a4cc5 {
	meta:
		aliases = "shmctl"
		size = "48"
		objfiles = "shmctl@libc.a"
	strings:
		$pattern = { 10 40 2D E9 01 1C 81 E3 34 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule _dl_strdup_a02f99a6203aaa1746385cfa34f7e4a6 {
	meta:
		aliases = "_dl_strdup"
		size = "60"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 10 40 2D E9 01 40 40 E2 04 20 A0 E1 01 30 F2 E5 00 00 53 E3 FC FF FF 1A 01 00 60 E2 02 00 80 E0 ?? ?? ?? EB 01 20 40 E2 01 30 F4 E5 00 00 53 E3 01 30 E2 E5 FB FF FF 1A 10 80 BD E8 }
	condition:
		$pattern
}

rule ether_aton_r_9b32db914ae9049c83c511933cacc645 {
	meta:
		aliases = "__GI_ether_aton_r, ether_aton_r"
		size = "220"
		objfiles = "ether_addr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 01 40 A0 E1 00 10 A0 E3 2C 00 00 EA 00 30 D0 E5 20 20 83 E3 30 30 42 E2 FF C0 03 E2 61 30 42 E2 09 00 5C E3 05 00 53 83 27 00 00 8A 39 00 52 E3 57 30 42 82 01 20 D0 E5 0C E0 A0 91 FF E0 03 82 05 00 51 E3 3A 00 52 13 02 00 80 E2 06 00 00 1A 05 00 51 E3 00 30 A0 13 01 30 A0 03 00 00 52 E3 00 30 A0 03 00 00 53 E3 12 00 00 0A 20 20 82 E3 30 30 42 E2 FF C0 03 E2 61 30 42 E2 09 00 5C E3 05 00 53 83 10 00 00 8A 39 00 52 E3 57 30 42 82 0C 30 A0 91 FF 30 03 82 0E 32 83 E0 05 00 51 E3 FF E0 03 E2 03 00 00 0A 00 30 D0 E5 3A 00 53 E3 05 00 00 1A 01 00 80 E2 01 E0 C4 E7 01 10 81 E2 05 00 51 E3 }
	condition:
		$pattern
}

rule sigwait_b8477292c188e15723b6e8247c31ecbd {
	meta:
		aliases = "sigwait"
		size = "36"
		objfiles = "sigwait@libc.a"
	strings:
		$pattern = { 10 40 2D E9 01 40 A0 E1 00 10 A0 E3 ?? ?? ?? EB 01 00 70 E3 00 00 84 15 02 00 80 02 00 00 A0 13 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI___glibc_strerror_r_39fcdb7ab7c7e46042b5ec6bf9cc4344 {
	meta:
		aliases = "__glibc_strerror_r, __GI___glibc_strerror_r"
		size = "20"
		objfiles = "__glibc_strerror_r@libc.a"
	strings:
		$pattern = { 10 40 2D E9 01 40 A0 E1 ?? ?? ?? EB 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule scalbnf_c8dbe55e46fc4c058d4ac1e5f9bc8e6a {
	meta:
		aliases = "frexpf, ldexpf, scalbnf"
		size = "28"
		objfiles = "frexpf@libm.a, ldexpf@libm.a, scalbnf@libm.a"
	strings:
		$pattern = { 10 40 2D E9 01 40 A0 E1 ?? ?? ?? EB 04 20 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 10 80 BD E8 }
	condition:
		$pattern
}

rule authnone_marshal_e2ea20495f0d7543de5e5e64edddc67b {
	meta:
		aliases = "authnone_marshal"
		size = "56"
		objfiles = "auth_none@libc.a"
	strings:
		$pattern = { 10 40 2D E9 01 40 A0 E1 ?? ?? ?? EB 98 10 90 E5 00 00 51 E3 01 00 A0 01 10 80 BD 08 3C 20 91 E5 04 00 A0 E1 04 30 94 E5 28 10 81 E2 0F E0 A0 E1 0C F0 93 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule tempnam_0d949b9bfcb02dd203e19f3e1c661987 {
	meta:
		aliases = "tempnam"
		size = "92"
		objfiles = "tempnam@libc.a"
	strings:
		$pattern = { 10 40 2D E9 01 DA 4D E2 10 40 8D E2 0F 40 44 E2 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 34 10 9F E5 ?? ?? ?? EB 00 00 50 E3 07 00 00 1A 04 00 A0 E1 03 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 02 00 00 1A 04 00 A0 E1 ?? ?? ?? EB 00 00 00 EA 00 00 A0 E3 01 DA 8D E2 10 80 BD E8 FF 0F 00 00 }
	condition:
		$pattern
}

rule fork_d4efd04ef7802809f64b53fefe9497ea {
	meta:
		aliases = "__libc_fork, __GI_fork, fork"
		size = "44"
		objfiles = "fork@libc.a"
	strings:
		$pattern = { 10 40 2D E9 02 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule ustat_3f7fefcd44d78af565da60b45ae948d6 {
	meta:
		aliases = "ustat"
		size = "48"
		objfiles = "ustat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 02 10 A0 E1 3E 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule mkdtemp_b5ca9676b7d635502edba85f2755a436 {
	meta:
		aliases = "mkdtemp"
		size = "32"
		objfiles = "mkdtemp@libc.a"
	strings:
		$pattern = { 10 40 2D E9 02 10 A0 E3 00 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 04 00 A0 01 00 00 A0 13 10 80 BD E8 }
	condition:
		$pattern
}

rule copysign_204b36bcfc565cd75b4bfcf9b6470a5f {
	meta:
		aliases = "__GI_copysign, copysign"
		size = "24"
		objfiles = "s_copysign@libm.a"
	strings:
		$pattern = { 10 40 2D E9 02 21 02 E2 02 31 C0 E3 01 40 A0 E1 03 00 82 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_fabs_cdbe71ab2a32c575f93390b1f19b6f4f {
	meta:
		aliases = "fabs, __GI_fabs"
		size = "24"
		objfiles = "s_fabs@libm.a"
	strings:
		$pattern = { 10 40 2D E9 02 31 C0 E3 01 40 A0 E1 03 00 A0 E1 04 10 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule ether_line_180c0770e1be7cf2378375349f9aa194 {
	meta:
		aliases = "ether_line"
		size = "100"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { 10 40 2D E9 02 40 A0 E1 E2 FF FF EB 00 00 50 E3 00 00 E0 03 10 80 BD 08 07 00 00 EA 23 00 52 E3 0A 00 00 0A 00 30 91 E5 82 30 D3 E7 20 00 13 E3 06 00 00 1A 01 20 C4 E4 00 00 00 EA 1C 10 9F E5 00 20 D0 E5 00 00 52 E3 01 00 80 E2 F2 FF FF 1A 00 30 A0 E3 03 00 A0 E1 00 30 C4 E5 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __libc_read_15ab80214717f47323dfb0c723a0d284 {
	meta:
		aliases = "__GI_read, read, __libc_read"
		size = "44"
		objfiles = "read@libc.a"
	strings:
		$pattern = { 10 40 2D E9 03 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule mktemp_37b9b0674b244bae16c4f8f40b85bb06 {
	meta:
		aliases = "mktemp"
		size = "36"
		objfiles = "mktemp@libc.a"
	strings:
		$pattern = { 10 40 2D E9 03 10 A0 E3 00 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 30 A0 B3 04 00 A0 E1 00 30 C4 B5 10 80 BD E8 }
	condition:
		$pattern
}

rule gcvt_012fb7853b70a68c365e23a593b78a6b {
	meta:
		aliases = "gcvt"
		size = "60"
		objfiles = "gcvt@libc.a"
	strings:
		$pattern = { 10 40 2D E9 03 40 A0 E1 01 C0 A0 E1 04 D0 4D E2 00 30 A0 E1 11 00 52 E3 11 20 A0 A3 04 00 A0 E1 10 10 9F E5 00 C0 8D E5 ?? ?? ?? EB 04 00 A0 E1 04 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule timer_settime_fe138e6db5fc0ec8830603470b41378b {
	meta:
		aliases = "timer_settime"
		size = "48"
		objfiles = "timer_settime@librt.a"
	strings:
		$pattern = { 10 40 2D E9 04 00 90 E5 02 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule timer_gettime_8aad887e73aed005a8a8d1a2795fe55d {
	meta:
		aliases = "timer_gettime"
		size = "48"
		objfiles = "timer_gettime@librt.a"
	strings:
		$pattern = { 10 40 2D E9 04 00 90 E5 03 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule timer_getoverrun_53d2d33d0ed978e092cd3ad18f5f6afc {
	meta:
		aliases = "timer_getoverrun"
		size = "48"
		objfiles = "timer_getoverr@librt.a"
	strings:
		$pattern = { 10 40 2D E9 04 00 90 E5 04 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __libc_write_2c7b76ca9ac99e9009774a69de22914c {
	meta:
		aliases = "__GI_write, write, __libc_write"
		size = "44"
		objfiles = "write@libc.a"
	strings:
		$pattern = { 10 40 2D E9 04 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule sethostid_5a825c8ea0442127f4144f142cce70e9 {
	meta:
		aliases = "sethostid"
		size = "128"
		objfiles = "hostid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 04 D0 4D E2 00 00 8D E5 ?? ?? ?? EB 00 00 50 E3 02 00 00 1A ?? ?? ?? EB 00 00 50 E3 04 00 00 0A ?? ?? ?? EB 01 30 A0 E3 03 40 A0 E1 00 30 80 E5 0D 00 00 EA 3C 00 9F E5 41 10 A0 E3 69 2F A0 E3 ?? ?? ?? EB 00 40 50 E2 07 00 00 BA 0D 10 A0 E1 04 20 A0 E3 ?? ?? ?? EB 04 00 50 E3 04 00 A0 E1 00 40 E0 13 00 40 A0 03 ?? ?? ?? EB 04 00 A0 E1 04 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdrstdio_getint32_0e4f154178cf39a2dee3bc608068e7b4 {
	meta:
		aliases = "xdrstdio_getlong, xdrstdio_getint32"
		size = "80"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { 10 40 2D E9 04 D0 4D E2 0C 30 90 E5 01 20 A0 E3 01 40 A0 E1 0D 00 A0 E1 04 10 A0 E3 ?? ?? ?? EB 01 00 50 E3 00 10 9D 05 21 3C A0 01 FF 28 01 02 22 34 83 01 FF 2C 01 02 02 34 83 01 01 3C 83 01 00 00 A0 13 00 30 84 05 04 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __dn_expand_f58e7368a658da21df71ba973e4e4b4e {
	meta:
		aliases = "__dn_expand"
		size = "56"
		objfiles = "res_comp@libc.a"
	strings:
		$pattern = { 10 40 2D E9 04 D0 4D E2 0C C0 9D E5 03 40 A0 E1 00 C0 8D E5 ?? ?? ?? EB 00 00 50 E3 03 00 00 DA 00 30 D4 E5 2E 00 53 E3 00 30 A0 03 00 30 C4 05 04 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule mbsnrtowcs_2704be0b1151ed83e6e3664d6b5301d4 {
	meta:
		aliases = "__GI_mbsnrtowcs, mbsnrtowcs"
		size = "192"
		objfiles = "mbsnrtowcs@libc.a"
	strings:
		$pattern = { 10 40 2D E9 04 D0 4D E2 0C C0 9D E5 A8 E0 9F E5 00 00 5C E3 0E C0 A0 01 0C 00 50 E1 00 00 50 13 00 E0 A0 E1 01 40 A0 E1 01 00 A0 13 04 00 00 1A 00 00 5E E3 0D E0 A0 11 00 00 A0 13 0D E0 A0 01 00 30 E0 03 02 00 53 E1 03 10 A0 31 02 10 A0 21 00 C0 94 E5 00 21 A0 E1 01 00 A0 E1 0E 00 00 EA 00 30 DC E5 00 00 53 E3 01 C0 8C E2 00 30 8E E5 03 C0 A0 01 0A 00 00 0A 7F 00 53 E3 04 00 00 DA ?? ?? ?? EB 54 30 A0 E3 00 20 E0 E3 00 30 80 E5 06 00 00 EA 02 E0 8E E0 01 00 40 E2 00 00 50 E3 EE FF FF 1A 0D 00 5E E1 00 C0 84 15 01 20 60 E0 02 00 A0 E1 04 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wait_06e8dc28926387eeb84f9d2d16b42772 {
	meta:
		aliases = "tcdrain, fsync, close, system, wait"
		size = "60"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 04 D0 4D E2 0D 10 A0 E1 00 40 A0 E1 01 00 A0 E3 ?? ?? ?? EB 04 00 A0 E1 ?? ?? ?? EB 00 10 A0 E3 00 40 A0 E1 00 00 9D E5 ?? ?? ?? EB 04 00 A0 E1 04 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule pause_05996144de2bc3592558895f1ac89767 {
	meta:
		aliases = "pause"
		size = "52"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 04 D0 4D E2 0D 10 A0 E1 01 00 A0 E3 ?? ?? ?? EB ?? ?? ?? EB 00 10 A0 E3 00 40 A0 E1 00 00 9D E5 ?? ?? ?? EB 04 00 A0 E1 04 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule set_input_fragment_5d84b604fe4882db305261187981b34f {
	meta:
		aliases = "set_input_fragment"
		size = "104"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 10 40 2D E9 04 D0 4D E2 0D 10 A0 E1 04 20 A0 E3 00 40 A0 E1 DB FF FF EB 00 00 50 E3 0E 00 00 0A 00 10 9D E5 FF 28 01 E2 21 3C A0 E1 22 34 83 E1 FF 2C 01 E2 02 34 83 E1 01 2C 83 E1 00 00 52 E3 A2 3F A0 E1 38 30 84 E5 02 31 C2 13 00 20 8D E5 01 00 A0 13 34 30 84 15 00 00 00 1A 00 00 A0 E3 04 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_tgamma_68d018117446c2a0ba245d5dd4863220 {
	meta:
		aliases = "tgamma, __GI_tgamma"
		size = "48"
		objfiles = "e_lgamma_r@libm.a"
	strings:
		$pattern = { 10 40 2D E9 04 D0 4D E2 0D 20 A0 E1 ?? ?? ?? EB 00 30 9D E5 00 00 53 E3 02 31 80 B2 01 40 A0 B1 03 00 A0 B1 04 10 A0 B1 04 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_close_390c52ad9010a56a027efa6f5f6013ed {
	meta:
		aliases = "close, __libc_close, __GI_close"
		size = "44"
		objfiles = "close@libc.a"
	strings:
		$pattern = { 10 40 2D E9 06 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule clock_settime_1c458aba7f36856d7776de086b438fcd {
	meta:
		aliases = "clock_settime"
		size = "44"
		objfiles = "clock_settime@libc.a"
	strings:
		$pattern = { 10 40 2D E9 06 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule login_8b0fa002775cf1f663ffa438f6286ccc {
	meta:
		aliases = "login"
		size = "104"
		objfiles = "login@libutil.a"
	strings:
		$pattern = { 10 40 2D E9 06 DD 4D E2 00 10 A0 E1 06 2D A0 E3 00 40 A0 E1 0D 00 A0 E1 ?? ?? ?? EB 40 00 9F E5 ?? ?? ?? EB ?? ?? ?? EB 07 30 A0 E3 00 30 CD E5 00 30 A0 E3 01 30 CD E5 ?? ?? ?? EB 08 10 84 E2 04 00 8D E5 20 20 A0 E3 08 00 8D E2 ?? ?? ?? EB 04 00 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 06 DD 8D E2 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clock_gettime_0cf9a9e530901ffd1316372945c46940 {
	meta:
		aliases = "clock_gettime"
		size = "44"
		objfiles = "clock_gettime@libc.a"
	strings:
		$pattern = { 10 40 2D E9 07 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_clock_getres_5045f4d5bf8b7ef5098ada957daacdbc {
	meta:
		aliases = "clock_getres, __GI_clock_getres"
		size = "44"
		objfiles = "clock_getres@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __stdio_rfill_558a5e7e12060fde6c8a7d9f33624ee3 {
	meta:
		aliases = "__stdio_rfill"
		size = "44"
		objfiles = "_rfill@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 10 80 E2 06 00 91 E8 02 20 61 E0 00 40 A0 E1 ?? ?? ?? EB 08 20 94 E5 00 30 82 E0 14 30 84 E5 10 20 84 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule __stdio_wcommit_fab909eb18bf38e3e7b04a8812ea974d {
	meta:
		aliases = "__stdio_wcommit"
		size = "44"
		objfiles = "_wcommit@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 10 90 E5 10 30 90 E5 01 20 53 E0 00 40 A0 E1 10 10 80 15 ?? ?? ?? 1B 08 30 94 E5 10 00 94 E5 00 00 63 E0 10 80 BD E8 }
	condition:
		$pattern
}

rule sigpending_9afbc76642b766b17da197bec2c3af40 {
	meta:
		aliases = "sigpending"
		size = "48"
		objfiles = "sigpending@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 10 A0 E3 B0 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule sigsuspend_d912cdcac22736d5130c4f477a585453 {
	meta:
		aliases = "__libc_sigsuspend, __GI_sigsuspend, sigsuspend"
		size = "48"
		objfiles = "sigsuspend@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 10 A0 E3 B3 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __syscall_mq_timedsend_e45cefc8f197c806ac3bdd782ec9884c {
	meta:
		aliases = "__syscall_mq_timedsend"
		size = "48"
		objfiles = "mq_send@librt.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 14 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule mount_1ae6326505c83cda1bf140eff8a5ee95 {
	meta:
		aliases = "mount"
		size = "48"
		objfiles = "mount@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 15 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __syscall_mq_timedreceive_e3646899753adec42077ba6e08d138aa {
	meta:
		aliases = "__syscall_mq_timedreceive"
		size = "48"
		objfiles = "mq_receive@librt.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 15 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_setsockopt_214ee73e08f08d91d0812ff33f372caf {
	meta:
		aliases = "setsockopt, __GI_setsockopt"
		size = "48"
		objfiles = "setsockopt@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 26 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule getsockopt_edac835281eb123fefb79e625ce3ae74 {
	meta:
		aliases = "getsockopt"
		size = "48"
		objfiles = "getsockopt@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 27 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule msgrcv_a06ddf949b9208eb88e71a1c73967fcb {
	meta:
		aliases = "msgrcv"
		size = "48"
		objfiles = "msgrcv@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 2E 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule fchownat_80115b1f784b112f84816b11ec9f2352 {
	meta:
		aliases = "fchownat"
		size = "48"
		objfiles = "fchownat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 45 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule linkat_920142e3614184a6786ec618ed6851c7 {
	meta:
		aliases = "linkat"
		size = "48"
		objfiles = "linkat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 4A 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule init_module_a47343723eb2bd6d3e5fc61517ee4236 {
	meta:
		aliases = "init_module"
		size = "48"
		objfiles = "init_module@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 80 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_select_931dd4e935e9a371839bfa86760e9a9d {
	meta:
		aliases = "select, __libc_select, __GI_select"
		size = "48"
		objfiles = "select@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 8E 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_mremap_60370ce4f7f7ad23f605cf29079010ad {
	meta:
		aliases = "mremap, __GI_mremap"
		size = "48"
		objfiles = "mremap@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 A3 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule prctl_bcba0421db1d0bbf3a8e2819c99841b5 {
	meta:
		aliases = "prctl"
		size = "48"
		objfiles = "prctl@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 AC 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule setxattr_180f491bda42b84bc93a9a22d36b1cdc {
	meta:
		aliases = "setxattr"
		size = "48"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 E2 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule lsetxattr_2c918d5fbd9181658c897ece7d89a986 {
	meta:
		aliases = "lsetxattr"
		size = "48"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 E3 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule fsetxattr_1cb80403109da039f02ee8cf839594fb {
	meta:
		aliases = "fsetxattr"
		size = "48"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 E4 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule remap_file_pages_ff0393c26047630689300239168f6321 {
	meta:
		aliases = "remap_file_pages"
		size = "48"
		objfiles = "remap_file_pages@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 FD 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule byte_insert_op2_cfef0b5ca1b62ec4748f3ed5d064ba47 {
	meta:
		aliases = "byte_insert_op2"
		size = "52"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 C0 9D E5 03 40 A0 E1 0C E0 A0 E1 05 C0 8C E2 01 00 00 EA 01 30 7E E5 01 30 6C E5 01 00 5E E1 FB FF FF 1A 04 30 A0 E1 10 40 BD E8 DF FF FF EA }
	condition:
		$pattern
}

rule getprotobyname_1b115da870b4c01d13f49876ca27502f {
	meta:
		aliases = "getprotobyname"
		size = "72"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 D0 4D E2 00 40 A0 E1 80 FE FF EB 24 30 9F E5 04 C0 8D E2 00 20 93 E5 04 00 A0 E1 18 10 9F E5 18 30 9F E5 00 C0 8D E5 ?? ?? ?? EB 04 00 9D E5 08 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? 8D 10 00 00 }
	condition:
		$pattern
}

rule re_exec_d89fa2dc839e54ea8dd364b2c56beee7 {
	meta:
		aliases = "re_exec"
		size = "68"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 D0 4D E2 00 40 A0 E1 ?? ?? ?? EB 00 E0 A0 E3 00 C0 A0 E1 00 20 A0 E1 04 10 A0 E1 0E 30 A0 E1 14 00 9F E5 00 50 8D E8 ?? ?? ?? EB 00 00 E0 E1 A0 0F A0 E1 08 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getprotobynumber_9ac13b5cd97656554489c0745fd7bca0 {
	meta:
		aliases = "getprotobynumber"
		size = "72"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 D0 4D E2 00 40 A0 E1 D2 FE FF EB 24 30 9F E5 04 C0 8D E2 00 20 93 E5 04 00 A0 E1 18 10 9F E5 18 30 9F E5 00 C0 8D E5 ?? ?? ?? EB 04 00 9D E5 08 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? 8D 10 00 00 }
	condition:
		$pattern
}

rule link_15011c8328b3c67e5820973f952c97ba {
	meta:
		aliases = "link"
		size = "44"
		objfiles = "link@libc.a"
	strings:
		$pattern = { 10 40 2D E9 09 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule unlink_f27f77f8c56553005b6b2fda48231bde {
	meta:
		aliases = "__GI_unlink, unlink"
		size = "44"
		objfiles = "unlink@libc.a"
	strings:
		$pattern = { 10 40 2D E9 0A 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule execve_034c7d56ecda8e98d8d0da7a9a931cb8 {
	meta:
		aliases = "__GI_execve, execve"
		size = "44"
		objfiles = "execve@libc.a"
	strings:
		$pattern = { 10 40 2D E9 0B 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule chdir_371cd2f0a7f01d355b452bc409c9a820 {
	meta:
		aliases = "__GI_chdir, chdir"
		size = "44"
		objfiles = "chdir@libc.a"
	strings:
		$pattern = { 10 40 2D E9 0C 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule random_r_4434b90b8fcb7cd68ab4d5ceb49d9a77 {
	meta:
		aliases = "__GI_random_r, random_r"
		size = "140"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { 10 40 2D E9 0C 30 D0 E5 00 00 53 E3 00 C0 A0 E1 01 40 A0 E1 08 E0 90 E5 08 00 00 1A 00 20 9E E5 60 30 9F E5 92 03 03 E0 03 3A 83 E2 39 30 83 E2 02 31 C3 E3 00 30 8E E5 00 30 81 E5 0F 00 00 EA 00 20 90 E5 04 00 90 E5 00 10 92 E5 04 30 90 E4 01 30 83 E0 04 30 82 E4 10 10 9C E5 A3 30 A0 E1 01 00 52 E1 00 30 84 E5 0E 20 A0 21 01 00 00 2A 01 00 50 E1 0E 00 A0 21 04 00 8C E5 00 20 8C E5 00 00 A0 E3 10 80 BD E8 6D 4E C6 41 }
	condition:
		$pattern
}

rule xdrrec_destroy_2794cfa23050d7f4d5cae215bf1afd3a {
	meta:
		aliases = "xdrrec_destroy"
		size = "28"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 10 40 2D E9 0C 40 90 E5 04 00 94 E5 ?? ?? ?? EB 04 00 A0 E1 10 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule localtime_6446048565b3ab2258d4e2ff685dc75d {
	meta:
		aliases = "__GI_localtime, localtime"
		size = "28"
		objfiles = "localtime@libc.a"
	strings:
		$pattern = { 10 40 2D E9 0C 40 9F E5 04 10 A0 E1 ?? ?? ?? EB 04 00 A0 E1 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule seed48_5de5f68db9ddebfb22521bfe4b344c21 {
	meta:
		aliases = "seed48"
		size = "28"
		objfiles = "seed48@libc.a"
	strings:
		$pattern = { 10 40 2D E9 0C 40 9F E5 04 10 A0 E1 ?? ?? ?? EB 06 00 84 E2 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdrrec_getint32_c1e76bcd5aef4cbef0cf7a4803c0244a {
	meta:
		aliases = "xdrrec_getint32"
		size = "176"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 10 40 2D E9 0C C0 90 E5 34 30 9C E5 03 00 53 E3 01 40 A0 E1 04 D0 4D E2 2C 10 9C E5 13 00 00 DA 30 30 9C E5 03 30 61 E0 03 00 53 E3 0F 00 00 DA 00 10 91 E5 FF 28 01 E2 21 3C A0 E1 22 34 83 E1 FF 2C 01 E2 02 34 83 E1 01 3C 83 E1 00 30 84 E5 34 20 9C E5 2C 30 9C E5 04 20 42 E2 04 30 83 E2 01 00 A0 E3 2C 30 8C E5 34 20 8C E5 0D 00 00 EA 0D 10 A0 E1 04 20 A0 E3 BC FF FF EB 00 00 50 E3 08 00 00 0A 00 10 9D E5 FF 28 01 E2 21 3C A0 E1 22 34 83 E1 FF 2C 01 E2 02 34 83 E1 01 3C 83 E1 00 30 84 E5 01 00 A0 E3 04 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_utimes_f9f9817bcf82666dec0de0e7a6edac61 {
	meta:
		aliases = "utimes, __GI_utimes"
		size = "44"
		objfiles = "utimes@libc.a"
	strings:
		$pattern = { 10 40 2D E9 0D 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule mknod_7b2cdfa7dc52819e8d1d4fd683dcccf1 {
	meta:
		aliases = "__GI_mknod, mknod"
		size = "44"
		objfiles = "mknod@libc.a"
	strings:
		$pattern = { 10 40 2D E9 0E 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI___fgetc_unlocked_ba13e73ea0c557d155bb10f1906ac51b {
	meta:
		aliases = "__fgetc_unlocked, __GI_getc_unlocked, fgetc_unlocked, getc_unlocked, __GI_fgetc_unlocked, __GI___fgetc_unlocked"
		size = "304"
		objfiles = "fgetc_unlocked@libc.a"
	strings:
		$pattern = { 10 40 2D E9 10 20 90 E5 18 30 90 E5 03 00 52 E1 00 40 A0 E1 01 00 D2 34 04 D0 4D E2 10 20 84 35 3F 00 00 3A 00 30 D4 E5 83 30 03 E2 80 00 53 E3 03 00 00 8A 80 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 36 00 00 1A 00 20 D4 E5 01 30 D4 E5 03 24 82 E1 02 00 12 E3 09 00 00 0A 01 30 02 E2 03 31 84 E0 24 30 D3 E5 01 20 42 E2 42 14 A0 E1 03 00 A0 E1 00 30 A0 E3 28 30 84 E5 01 10 C4 E5 0C 00 00 EA 10 10 84 E2 0A 00 91 E8 01 00 53 E1 01 00 D1 14 10 10 84 15 22 00 00 1A 04 30 94 E5 02 00 73 E3 05 00 00 1A 04 20 82 E3 42 34 A0 E1 01 30 C4 E5 00 00 E0 E3 00 20 C4 E5 19 00 00 EA 03 0C 12 E3 64 00 9F 15 ?? ?? ?? 1B }
	condition:
		$pattern
}

rule scan_getwc_5baa2161546070624b1272abf0e35c3b {
	meta:
		aliases = "scan_getwc"
		size = "200"
		objfiles = "vfwscanf@libc.a"
	strings:
		$pattern = { 10 40 2D E9 10 30 90 E5 01 30 43 E2 00 00 53 E3 10 30 80 E5 19 30 D0 E5 00 10 E0 E3 00 40 A0 E1 24 10 80 E5 02 30 83 B3 01 00 A0 B1 16 00 00 BA 00 00 53 E3 00 30 A0 13 19 30 C4 15 1A 00 00 1A 08 00 94 E5 04 30 90 E5 03 00 73 E3 08 00 00 1A 10 20 90 E5 0C 30 90 E5 03 00 52 E1 04 10 92 34 01 00 A0 21 10 20 80 35 02 30 A0 23 06 00 00 2A 07 00 00 EA ?? ?? ?? EB 01 00 70 E3 00 10 A0 E1 03 00 00 1A 19 30 D4 E5 02 30 83 E3 19 30 C4 E5 10 80 BD E8 01 30 A0 E3 1A 30 C4 E5 04 10 84 E5 08 30 94 E5 02 30 D3 E5 18 30 C4 E5 0C 30 94 E5 04 20 94 E5 01 30 83 E2 00 00 A0 E3 24 20 84 E5 0C 30 84 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule __scan_getc_96614a0cfc55f49d0c20456fe1c0e9ff {
	meta:
		aliases = "__scan_getc"
		size = "124"
		objfiles = "__scan_cookie@libc.a"
	strings:
		$pattern = { 10 40 2D E9 10 30 90 E5 01 30 43 E2 00 00 53 E3 10 30 80 E5 19 30 D0 E5 00 20 E0 E3 00 40 A0 E1 00 20 80 E5 02 30 83 B3 02 00 A0 B1 0A 00 00 BA 00 00 53 E3 00 30 A0 13 19 30 C4 15 08 00 00 1A 0F E0 A0 E1 2C F0 94 E5 01 00 70 E3 04 00 84 15 03 00 00 1A 19 30 D4 E5 02 30 83 E3 19 30 C4 E5 10 80 BD E8 0C 30 94 E5 04 00 94 E5 01 30 83 E2 0C 30 84 E5 00 00 84 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule gmtime_5a446ba4976ed55bae0f684720ac2885 {
	meta:
		aliases = "gmtime"
		size = "32"
		objfiles = "gmtime@libc.a"
	strings:
		$pattern = { 10 40 2D E9 10 40 9F E5 00 10 A0 E3 04 20 A0 E1 ?? ?? ?? EB 04 00 A0 E1 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule strerror_6d98a07df18711ff2205836706791ec9 {
	meta:
		aliases = "__GI_strerror, strerror"
		size = "32"
		objfiles = "strerror@libc.a"
	strings:
		$pattern = { 10 40 2D E9 10 40 9F E5 32 20 A0 E3 04 10 A0 E1 ?? ?? ?? EB 04 00 A0 E1 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ftime_eab14aa06e991ab63ecbc3ae47856932 {
	meta:
		aliases = "ftime"
		size = "104"
		objfiles = "ftime@libc.a"
	strings:
		$pattern = { 10 40 2D E9 10 D0 4D E2 00 40 A0 E1 0D 10 A0 E1 08 00 8D E2 ?? ?? ?? EB 0C 00 9D E5 08 30 9D E5 F9 0F 80 E2 00 30 84 E5 FA 1F A0 E3 03 00 80 E2 ?? ?? ?? EB 00 50 9D E8 40 24 A0 E1 4C 14 A0 E1 4E 34 A0 E1 04 00 C4 E5 00 00 A0 E3 09 30 C4 E5 05 20 C4 E5 07 10 C4 E5 06 C0 C4 E5 08 E0 C4 E5 10 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule setgrent_bc2a1861fc6600e47eca4f25d514c5e3 {
	meta:
		aliases = "setpwent, setspent, setgrent"
		size = "120"
		objfiles = "getgrent_r@libc.a, getspent_r@libc.a, getpwent_r@libc.a"
	strings:
		$pattern = { 10 40 2D E9 10 D0 4D E2 0D 00 A0 E1 4C 10 9F E5 4C 20 9F E5 4C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 44 30 9F E5 38 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 38 30 9F E5 00 00 93 E5 00 00 50 E3 0D 40 A0 E1 ?? ?? ?? 1B 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule setstate_136c56dc5e3eec75629fbd0faeade8af {
	meta:
		aliases = "setstate"
		size = "140"
		objfiles = "random@libc.a"
	strings:
		$pattern = { 10 40 2D E9 10 D0 4D E2 64 20 9F E5 00 40 A0 E1 60 10 9F E5 0D 00 A0 E1 5C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 54 30 9F E5 44 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 48 30 9F E5 04 00 A0 E1 03 10 A0 E1 08 40 93 E5 ?? ?? ?? EB 01 10 A0 E3 00 00 50 E3 30 30 9F E5 0D 00 A0 E1 00 40 A0 B3 04 40 44 A2 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 10 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __libc_lseek_907e4dd8519212da476d92911d86f5c8 {
	meta:
		aliases = "__GI_lseek, lseek, __libc_lseek"
		size = "44"
		objfiles = "lseek@libc.a"
	strings:
		$pattern = { 10 40 2D E9 13 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule getpid_b756ed38d47092e6de99d7c88c3f8677 {
	meta:
		aliases = "__GI_getpid, __libc_getpid, getpid"
		size = "44"
		objfiles = "getpid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 14 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule umount_67925073e6cc62017f13f2a24d99b146 {
	meta:
		aliases = "umount"
		size = "44"
		objfiles = "umount@libc.a"
	strings:
		$pattern = { 10 40 2D E9 16 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_mq_setattr_1fff7fa629e94ffb6e1a84b9b8ba7cb4 {
	meta:
		aliases = "mq_setattr, __GI_mq_setattr"
		size = "44"
		objfiles = "mq_getsetattr@librt.a"
	strings:
		$pattern = { 10 40 2D E9 17 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule _authenticate_92c76f6593b83aa1cb682bc53c14c1db {
	meta:
		aliases = "__GI__authenticate, _authenticate"
		size = "104"
		objfiles = "svc_auth@libc.a"
	strings:
		$pattern = { 10 40 2D E9 18 30 81 E2 00 C0 A0 E1 01 E0 A0 E1 07 00 93 E8 0C 30 8C E2 07 00 83 E8 3C 30 9F E5 00 20 93 E5 1C 30 9C E5 20 20 83 E5 0C 40 9C E5 1C 20 9C E5 03 00 54 E3 00 30 A0 E3 28 30 82 E5 02 00 A0 83 10 80 BD 88 0C 00 A0 E1 0E 10 A0 E1 0C 30 9F E5 0F E0 A0 E1 04 F1 93 E7 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI__rpc_dtablesize_6446cf8f42a30dc173625819f1c099fe {
	meta:
		aliases = "_rpc_dtablesize, __GI__rpc_dtablesize"
		size = "40"
		objfiles = "rpc_dtablesize@libc.a"
	strings:
		$pattern = { 10 40 2D E9 18 40 9F E5 00 30 94 E5 00 00 53 E3 01 00 00 1A ?? ?? ?? EB 00 00 84 E5 00 00 94 E5 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule stime_922e44e39209d4131fcb933f7dba81d4 {
	meta:
		aliases = "stime"
		size = "44"
		objfiles = "stime@libc.a"
	strings:
		$pattern = { 10 40 2D E9 19 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_socket_bbed504a677cdf7aa866e4c24580cc39 {
	meta:
		aliases = "socket, __GI_socket"
		size = "44"
		objfiles = "socket@libc.a"
	strings:
		$pattern = { 10 40 2D E9 19 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_bind_56ef8fd264a624b1d66dda8a128b4017 {
	meta:
		aliases = "bind, __GI_bind"
		size = "44"
		objfiles = "bind@libc.a"
	strings:
		$pattern = { 10 40 2D E9 1A 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_alarm_97bbb26a0889a56cb05906a9a63e787b {
	meta:
		aliases = "alarm, __GI_alarm"
		size = "44"
		objfiles = "alarm@libc.a"
	strings:
		$pattern = { 10 40 2D E9 1B 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_connect_c7e422bce6f558bc36d513f71d02064a {
	meta:
		aliases = "connect, __libc_connect, __GI_connect"
		size = "44"
		objfiles = "connect@libc.a"
	strings:
		$pattern = { 10 40 2D E9 1B 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule listen_fa87a4bc4f118e808afd7edf1a08400a {
	meta:
		aliases = "__GI_listen, listen"
		size = "44"
		objfiles = "listen@libc.a"
	strings:
		$pattern = { 10 40 2D E9 1C 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule _rpcdata_5d5310dccae26101f699d96953728f00 {
	meta:
		aliases = "_rpcdata"
		size = "48"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { 10 40 2D E9 1C 40 9F E5 00 00 94 E5 00 00 50 E3 10 80 BD 18 10 10 9F E5 01 00 80 E2 ?? ?? ?? EB 00 00 84 E5 10 80 BD E8 ?? ?? ?? ?? B0 10 00 00 }
	condition:
		$pattern
}

rule __libc_pause_df08d50df298ca9cd4866601a46e7d8d {
	meta:
		aliases = "pause, __libc_pause"
		size = "44"
		objfiles = "pause@libc.a"
	strings:
		$pattern = { 10 40 2D E9 1D 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule accept_74d504d25242b01999387e060b16bf64 {
	meta:
		aliases = "__GI_accept, __libc_accept, accept"
		size = "44"
		objfiles = "accept@libc.a"
	strings:
		$pattern = { 10 40 2D E9 1D 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule utime_07a34cf10b4353b7f622aa273a356f70 {
	meta:
		aliases = "__GI_utime, utime"
		size = "44"
		objfiles = "utime@libc.a"
	strings:
		$pattern = { 10 40 2D E9 1E 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule getsockname_0d171e6fa69aca801f16096aeb0950a4 {
	meta:
		aliases = "__GI_getsockname, getsockname"
		size = "44"
		objfiles = "getsockname@libc.a"
	strings:
		$pattern = { 10 40 2D E9 1E 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_strsignal_e4947ba7f5fdea78235f2b87198a4913 {
	meta:
		aliases = "strsignal, __GI_strsignal"
		size = "132"
		objfiles = "strsignal@libc.a"
	strings:
		$pattern = { 10 40 2D E9 1F 00 50 E3 04 D0 4D E2 64 40 9F 95 00 30 A0 91 03 00 00 9A 07 00 00 EA 00 00 5C E3 01 30 43 02 01 40 84 E2 00 00 53 E3 00 C0 D4 E5 F9 FF FF 1A 00 00 5C E3 0B 00 00 1A 00 10 A0 E1 C1 2F A0 E1 00 C0 A0 E3 2C 00 9F E5 09 30 E0 E3 00 C0 8D E5 ?? ?? ?? EB 0F 40 40 E2 04 00 A0 E1 18 10 9F E5 0F 20 A0 E3 ?? ?? ?? EB 04 00 A0 E1 04 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getpeername_20b6d047388b08cc9509b671bc609713 {
	meta:
		aliases = "getpeername"
		size = "44"
		objfiles = "getpeername@libc.a"
	strings:
		$pattern = { 10 40 2D E9 1F 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule socketpair_6ad0c614246fe9e0afa25b07f954017f {
	meta:
		aliases = "socketpair"
		size = "44"
		objfiles = "socketpair@libc.a"
	strings:
		$pattern = { 10 40 2D E9 20 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_svcerr_progvers_022641fccd6cc0f23cd37c6f5e7f75ee {
	meta:
		aliases = "svcerr_progvers, __GI_svcerr_progvers"
		size = "96"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { 10 40 2D E9 20 30 80 E2 30 D0 4D E2 00 C0 A0 E1 01 E0 A0 E1 02 40 A0 E1 07 00 93 E8 0C 30 8D E2 07 00 83 E8 01 30 A0 E3 04 30 8D E5 00 30 A0 E3 08 30 8D E5 02 30 83 E2 18 30 8D E5 1C E0 8D E5 20 40 8D E5 0C 00 A0 E1 08 30 9C E5 0D 10 A0 E1 0F E0 A0 E1 0C F0 93 E5 30 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule dl_cleanup_d79cc8fa4e326acd403aa6d7598697c7 {
	meta:
		aliases = "dl_cleanup"
		size = "48"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 10 40 2D E9 20 30 9F E5 00 40 93 E5 01 00 00 EA 04 40 94 E5 37 FF FF EB 00 00 54 E3 04 00 A0 E1 01 10 A0 E3 F9 FF FF 1A 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __initbuf_729b9d91907565989b4f690d08d0549a {
	meta:
		aliases = "__initbuf"
		size = "52"
		objfiles = "getproto@libc.a, getservice@libc.a"
	strings:
		$pattern = { 10 40 2D E9 20 40 9F E5 00 30 94 E5 00 00 53 E3 10 80 BD 18 14 00 9F E5 ?? ?? ?? EB 00 00 50 E3 00 00 84 E5 10 80 BD 18 ?? ?? ?? EB ?? ?? ?? ?? 8D 10 00 00 }
	condition:
		$pattern
}

rule access_b7a9812728a132b4dc21dce46f24696a {
	meta:
		aliases = "access"
		size = "44"
		objfiles = "access@libc.a"
	strings:
		$pattern = { 10 40 2D E9 21 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule send_41b527ce5555580abc5a4597ab739997 {
	meta:
		aliases = "__GI_send, __libc_send, send"
		size = "44"
		objfiles = "send@libc.a"
	strings:
		$pattern = { 10 40 2D E9 21 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule nice_64417b240bcc1d19621aad139d52ff34 {
	meta:
		aliases = "nice"
		size = "64"
		objfiles = "nice@libc.a"
	strings:
		$pattern = { 10 40 2D E9 22 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 04 00 00 EA 00 00 50 E3 02 00 00 1A 00 10 A0 E1 10 40 BD E8 ?? ?? ?? EA 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule recv_d8ce7f1eeb317cc2ea1494f89b2164ee {
	meta:
		aliases = "__libc_recv, __GI_recv, recv"
		size = "44"
		objfiles = "recv@libc.a"
	strings:
		$pattern = { 10 40 2D E9 23 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule sync_f428dec53fd719e9ef9798156c161ad1 {
	meta:
		aliases = "sync"
		size = "36"
		objfiles = "sync@libc.a"
	strings:
		$pattern = { 10 40 2D E9 24 00 90 EF 01 0A 70 E3 00 40 A0 E1 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule endttyent_51df05e6d3407d2144fdb344e81d1c9e {
	meta:
		aliases = "__GI_endttyent, endttyent"
		size = "52"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { 10 40 2D E9 24 40 9F E5 00 00 94 E5 00 00 50 E3 01 00 80 02 10 80 BD 08 ?? ?? ?? EB 00 30 A0 E3 01 00 90 E2 01 00 A0 13 00 30 84 E5 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule kill_1fdc68a74bcc0d5f71a0ceb8b96ff2ad {
	meta:
		aliases = "__GI_kill, kill"
		size = "44"
		objfiles = "kill@libc.a"
	strings:
		$pattern = { 10 40 2D E9 25 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule shutdown_54c03ea54f011ded62fa220116c61ff9 {
	meta:
		aliases = "shutdown"
		size = "44"
		objfiles = "shutdown@libc.a"
	strings:
		$pattern = { 10 40 2D E9 25 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule rename_e5700ce5dca971d35a3a7efe560b85ab {
	meta:
		aliases = "rename"
		size = "44"
		objfiles = "rename@libc.a"
	strings:
		$pattern = { 10 40 2D E9 26 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule rmdir_4c3468b66e8e960536c5b426c7e27431 {
	meta:
		aliases = "__GI_rmdir, rmdir"
		size = "44"
		objfiles = "rmdir@libc.a"
	strings:
		$pattern = { 10 40 2D E9 28 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_sendmsg_ce59f0d876b135736b8eeef4794499db {
	meta:
		aliases = "sendmsg, __libc_sendmsg, __GI_sendmsg"
		size = "44"
		objfiles = "sendmsg@libc.a"
	strings:
		$pattern = { 10 40 2D E9 28 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule getusershell_ed3f8d07ddf76dea93cc429de7b2ed37 {
	meta:
		aliases = "getusershell"
		size = "56"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { 10 40 2D E9 28 40 9F E5 00 30 94 E5 00 00 53 E3 01 00 00 1A 9A FF FF EB 00 00 84 E5 00 30 94 E5 00 00 93 E5 00 00 50 E3 04 30 83 12 00 30 84 15 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sysctl_fbacc843369c8de34c36b84929615e1e {
	meta:
		aliases = "sysctl"
		size = "80"
		objfiles = "sysctl@libc.a"
	strings:
		$pattern = { 10 40 2D E9 28 D0 4D E2 0C 30 8D E5 30 30 9D E5 10 30 8D E5 34 30 9D E5 07 00 8D E8 14 30 8D E5 0D 00 A0 E1 95 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 28 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule dup_d5ef486cf208db3f02b010ce1bb59476 {
	meta:
		aliases = "dup"
		size = "44"
		objfiles = "dup@libc.a"
	strings:
		$pattern = { 10 40 2D E9 29 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_recvmsg_d88b8a07bfeca37d4f71c32ddfb7ab6c {
	meta:
		aliases = "recvmsg, __libc_recvmsg, __GI_recvmsg"
		size = "44"
		objfiles = "recvmsg@libc.a"
	strings:
		$pattern = { 10 40 2D E9 29 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_pipe_0ef786d962381efc5077e1a95c46a6e2 {
	meta:
		aliases = "pipe, __GI_pipe"
		size = "44"
		objfiles = "pipe@libc.a"
	strings:
		$pattern = { 10 40 2D E9 2A 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule semop_69baaa2ceed6399de6d89f785f613b66 {
	meta:
		aliases = "semop"
		size = "44"
		objfiles = "semop@libc.a"
	strings:
		$pattern = { 10 40 2D E9 2A 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule semget_4a652a56bb22863f101214706658f9f1 {
	meta:
		aliases = "semget"
		size = "44"
		objfiles = "semget@libc.a"
	strings:
		$pattern = { 10 40 2D E9 2B 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule ctime_r_271f71c68fa42d88f8ce449fb13f5044 {
	meta:
		aliases = "ctime_r"
		size = "36"
		objfiles = "ctime_r@libc.a"
	strings:
		$pattern = { 10 40 2D E9 2C D0 4D E2 01 40 A0 E1 0D 10 A0 E1 ?? ?? ?? EB 04 10 A0 E1 ?? ?? ?? EB 2C D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule msgsnd_ad7fbea897fb13829413976284b41b02 {
	meta:
		aliases = "msgsnd"
		size = "44"
		objfiles = "msgsnd@libc.a"
	strings:
		$pattern = { 10 40 2D E9 2D 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule msgget_1a1690cd0beb14b94739c38c0a0c0a03 {
	meta:
		aliases = "msgget"
		size = "44"
		objfiles = "msgget@libc.a"
	strings:
		$pattern = { 10 40 2D E9 2F 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule shmat_272d2d20fd9942482b0f35cd5f3db2c2 {
	meta:
		aliases = "shmat"
		size = "44"
		objfiles = "shmat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 31 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule shmdt_bd1d860a27836aa5a1542b4b7b2b6fc8 {
	meta:
		aliases = "shmdt"
		size = "44"
		objfiles = "shmdt@libc.a"
	strings:
		$pattern = { 10 40 2D E9 32 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule acct_b8c1ca9cfad18032203fc05cacb4b1ef {
	meta:
		aliases = "acct"
		size = "44"
		objfiles = "acct@libc.a"
	strings:
		$pattern = { 10 40 2D E9 33 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule shmget_119f9371ebe83fbc9777b90d5c4a7d70 {
	meta:
		aliases = "shmget"
		size = "44"
		objfiles = "shmget@libc.a"
	strings:
		$pattern = { 10 40 2D E9 33 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule umount2_b134f5b9d1d717fdc1a38828dc0a6348 {
	meta:
		aliases = "umount2"
		size = "44"
		objfiles = "umount2@libc.a"
	strings:
		$pattern = { 10 40 2D E9 34 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule semtimedop_f6195fc6fcd091befb70c65ccdf081db {
	meta:
		aliases = "semtimedop"
		size = "44"
		objfiles = "semtimedop@libc.a"
	strings:
		$pattern = { 10 40 2D E9 38 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_setpgid_059d1baaddd61cc27f69341f35e582bb {
	meta:
		aliases = "setpgid, __GI_setpgid"
		size = "44"
		objfiles = "setpgid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 39 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule inotify_init_119438cbd431c74d888b49800090a82d {
	meta:
		aliases = "inotify_init"
		size = "44"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { 10 40 2D E9 3C 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule chroot_775636aa8ca01e8ec2acbe97ca656df0 {
	meta:
		aliases = "chroot"
		size = "44"
		objfiles = "chroot@libc.a"
	strings:
		$pattern = { 10 40 2D E9 3D 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule inotify_add_watch_03acf0d6c8e34a3ddfcc9307564d21ac {
	meta:
		aliases = "inotify_add_watch"
		size = "44"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { 10 40 2D E9 3D 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule putenv_835a392fcb9e389c6520af6301b6e965 {
	meta:
		aliases = "putenv"
		size = "56"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { 10 40 2D E9 3D 10 A0 E3 00 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 04 00 00 0A 04 00 A0 E1 00 10 A0 E3 01 20 A0 E3 10 40 BD E8 8B FF FF EA 04 00 A0 E1 10 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule inotify_rm_watch_f4c775547fd348783d7a7d53e87d2884 {
	meta:
		aliases = "inotify_rm_watch"
		size = "44"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { 10 40 2D E9 3E 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule dup2_c4a7f5356f0505f6096055cbb87e6faa {
	meta:
		aliases = "__GI_dup2, dup2"
		size = "44"
		objfiles = "dup2@libc.a"
	strings:
		$pattern = { 10 40 2D E9 3F 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule getppid_416dc9f1f2efffe1eaac8367f0a234ab {
	meta:
		aliases = "getppid"
		size = "44"
		objfiles = "getppid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 40 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_setttyent_c9efe52693bac3a8ec719987bd165781 {
	meta:
		aliases = "setttyent, __GI_setttyent"
		size = "88"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { 10 40 2D E9 40 40 9F E5 00 00 94 E5 00 00 50 E3 02 00 00 0A ?? ?? ?? EB 01 00 A0 E3 10 80 BD E8 28 00 9F E5 28 10 9F E5 ?? ?? ?? EB 00 00 50 E3 00 00 84 E5 00 00 A0 01 10 80 BD 08 02 10 A0 E3 ?? ?? ?? EB 01 00 A0 E3 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule stat_ea62d3122079fd2ee49b15bf3d365e57 {
	meta:
		aliases = "__GI_stat, stat"
		size = "80"
		objfiles = "stat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 40 D0 4D E2 01 30 A0 E1 0D 10 A0 E1 6A 00 90 EF 01 0A 70 E3 00 40 A0 E1 04 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 40 E0 E3 00 30 80 E5 03 00 00 EA 00 00 50 E3 0D 00 A0 01 03 10 A0 01 ?? ?? ?? 0B 04 00 A0 E1 40 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule lstat_1711b2b52ebf6040ea2fb0f5d5ee9705 {
	meta:
		aliases = "__GI_lstat, lstat"
		size = "80"
		objfiles = "lstat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 40 D0 4D E2 01 30 A0 E1 0D 10 A0 E1 6B 00 90 EF 01 0A 70 E3 00 40 A0 E1 04 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 40 E0 E3 00 30 80 E5 03 00 00 EA 00 00 50 E3 0D 00 A0 01 03 10 A0 01 ?? ?? ?? 0B 04 00 A0 E1 40 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule fstat_831e9d4595c6289896f8d2a3cdf6fe06 {
	meta:
		aliases = "__GI_fstat, fstat"
		size = "80"
		objfiles = "fstat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 40 D0 4D E2 01 30 A0 E1 0D 10 A0 E1 6C 00 90 EF 01 0A 70 E3 00 40 A0 E1 04 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 40 E0 E3 00 30 80 E5 03 00 00 EA 00 00 50 E3 0D 00 A0 01 03 10 A0 01 ?? ?? ?? 0B 04 00 A0 E1 40 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule getpgrp_d2eec07171dc538edb06b22c44d7ae8e {
	meta:
		aliases = "getpgrp"
		size = "44"
		objfiles = "getpgrp@libc.a"
	strings:
		$pattern = { 10 40 2D E9 41 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule setsid_db1cc7edabfa5a77f1b5e690141308b5 {
	meta:
		aliases = "__GI_setsid, setsid"
		size = "44"
		objfiles = "setsid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 42 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule openat_9b33a172f411e4a7b1c518e6c9e64017 {
	meta:
		aliases = "__GI_openat, openat"
		size = "44"
		objfiles = "openat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 42 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule mkdirat_2a01dc0b22ee70234308d965de746709 {
	meta:
		aliases = "mkdirat"
		size = "44"
		objfiles = "mkdirat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 43 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __getutent_35c3efe9cd63a1cc545a7c5af382c96c {
	meta:
		aliases = "__getutent"
		size = "88"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { 10 40 2D E9 44 40 9F E5 00 30 94 E5 00 00 53 E3 04 00 00 AA DB FF FF EB 00 30 94 E5 00 00 53 E3 00 00 A0 B3 10 80 BD B8 20 30 9F E5 20 10 9F E5 00 00 93 E5 06 2D A0 E3 ?? ?? ?? EB 10 30 9F E5 06 0D 50 E3 03 00 A0 01 00 00 A0 13 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule futimesat_8885bf116c8151c00564278b6b20e8af {
	meta:
		aliases = "futimesat"
		size = "44"
		objfiles = "futimesat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 46 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule unlinkat_80379e1a9ce4267c320de9332ae01bca {
	meta:
		aliases = "unlinkat"
		size = "44"
		objfiles = "unlinkat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 48 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule renameat_35ccc2dc9af4cb044c78f9c91ca50c2d {
	meta:
		aliases = "renameat"
		size = "44"
		objfiles = "renameat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 49 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule sethostname_0d5fa8cddba662a49df325e646f8dae7 {
	meta:
		aliases = "sethostname"
		size = "44"
		objfiles = "sethostname@libc.a"
	strings:
		$pattern = { 10 40 2D E9 4A 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_setrlimit_f95b90e824f800aaaba2a0be70f4ff81 {
	meta:
		aliases = "setrlimit, __GI_setrlimit"
		size = "44"
		objfiles = "setrlimit@libc.a"
	strings:
		$pattern = { 10 40 2D E9 4B 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule symlinkat_ad7c6323287e496dd7197c649e3fe978 {
	meta:
		aliases = "symlinkat"
		size = "44"
		objfiles = "symlinkat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 4B 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule readlinkat_a74b61a8f61f51f7678b91a60f73e642 {
	meta:
		aliases = "readlinkat"
		size = "44"
		objfiles = "readlinkat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 4C 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule getrusage_917694082a323aa90da98f7ddda5a6f7 {
	meta:
		aliases = "getrusage"
		size = "44"
		objfiles = "getrusage@libc.a"
	strings:
		$pattern = { 10 40 2D E9 4D 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule fchmodat_87c1eb8e72e4d1551fffe97f815baeba {
	meta:
		aliases = "fchmodat"
		size = "44"
		objfiles = "fchmodat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 4D 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule gettimeofday_f1de21df0d522d1bb1fd80312c14b0df {
	meta:
		aliases = "__GI_gettimeofday, gettimeofday"
		size = "44"
		objfiles = "gettimeofday@libc.a"
	strings:
		$pattern = { 10 40 2D E9 4E 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule faccessat_6f720a75ce9443b4dada6f89fe5854cf {
	meta:
		aliases = "faccessat"
		size = "44"
		objfiles = "faccessat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 4E 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule settimeofday_e906ee848442568a6ad73276e1a4e5fe {
	meta:
		aliases = "__GI_settimeofday, settimeofday"
		size = "44"
		objfiles = "settimeofday@libc.a"
	strings:
		$pattern = { 10 40 2D E9 4F 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule symlink_ee45c90c812d7d64145b2e4d1e1a39ba {
	meta:
		aliases = "symlink"
		size = "44"
		objfiles = "symlink@libc.a"
	strings:
		$pattern = { 10 40 2D E9 53 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule readlink_a09ae056a9f3cbf29a6a05b4e05e9dbb {
	meta:
		aliases = "__GI_readlink, readlink"
		size = "44"
		objfiles = "readlink@libc.a"
	strings:
		$pattern = { 10 40 2D E9 55 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule tee_621bf5f1ab7f9dabad4f7b5b4424f28c {
	meta:
		aliases = "tee"
		size = "44"
		objfiles = "tee@libc.a"
	strings:
		$pattern = { 10 40 2D E9 56 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule swapon_a3dce10774312656599a2602fa72c27c {
	meta:
		aliases = "swapon"
		size = "44"
		objfiles = "swapon@libc.a"
	strings:
		$pattern = { 10 40 2D E9 57 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule vmsplice_91066cdd804ba9819dd7d689027518fe {
	meta:
		aliases = "vmsplice"
		size = "44"
		objfiles = "vmsplice@libc.a"
	strings:
		$pattern = { 10 40 2D E9 57 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule frame_dummy_c1f0101a45eb1f6ee57078bffbec5606 {
	meta:
		aliases = "frame_dummy"
		size = "132"
		objfiles = "crtbeginS"
	strings:
		$pattern = { 10 40 2D E9 58 40 9F E5 58 30 9F E5 04 40 8F E0 03 30 94 E7 00 00 53 E3 05 00 00 0A 48 00 9F E5 48 10 9F E5 00 00 84 E0 01 10 84 E0 0F E0 A0 E1 03 F0 A0 E1 38 20 9F E5 02 30 94 E7 00 00 53 E3 02 00 84 E0 10 80 BD 08 28 30 9F E5 03 10 94 E7 00 00 51 E3 10 80 BD 08 0F E0 A0 E1 01 F0 A0 E1 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 E0 2D E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule ftok_e79cc82e5debf369b11f0f6f668f156a {
	meta:
		aliases = "ftok"
		size = "60"
		objfiles = "ftok@libc.a"
	strings:
		$pattern = { 10 40 2D E9 58 D0 4D E2 01 40 A0 E1 0D 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 0C 30 9D A5 00 20 DD A5 03 38 A0 A1 23 38 A0 A1 02 38 83 A1 00 00 E0 B3 04 0C 83 A1 58 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_munmap_7b823e0a342d46186cd8467de7ca9f8f {
	meta:
		aliases = "munmap, __GI_munmap"
		size = "44"
		objfiles = "munmap@libc.a"
	strings:
		$pattern = { 10 40 2D E9 5B 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_truncate_88ef88fe7f4738b8b07119b4a2729aba {
	meta:
		aliases = "truncate, __GI_truncate"
		size = "44"
		objfiles = "truncate@libc.a"
	strings:
		$pattern = { 10 40 2D E9 5C 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule utimensat_b05cbabc3f4a37e3cfe03e4177c61a98 {
	meta:
		aliases = "__GI_utimensat, utimensat"
		size = "44"
		objfiles = "utimensat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 5C 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_ftruncate_3a549f9e99df78ef08deb44153798bc4 {
	meta:
		aliases = "ftruncate, __GI_ftruncate"
		size = "44"
		objfiles = "ftruncate@libc.a"
	strings:
		$pattern = { 10 40 2D E9 5D 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule timerfd_create_e08395bf913ca19005f475ab324dc253 {
	meta:
		aliases = "timerfd_create"
		size = "44"
		objfiles = "timerfd@libc.a"
	strings:
		$pattern = { 10 40 2D E9 5E 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule getpriority_00ac421a175ba03658acf5b8b914d6a0 {
	meta:
		aliases = "__GI_getpriority, getpriority"
		size = "48"
		objfiles = "getpriority@libc.a"
	strings:
		$pattern = { 10 40 2D E9 60 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 00 00 54 E2 14 00 60 A2 10 80 BD E8 }
	condition:
		$pattern
}

rule stat64_1bdab6e18981ce75d0f207f1281a6b00 {
	meta:
		aliases = "__GI_stat64, stat64"
		size = "80"
		objfiles = "stat64@libc.a"
	strings:
		$pattern = { 10 40 2D E9 60 D0 4D E2 01 30 A0 E1 0D 10 A0 E1 C3 00 90 EF 01 0A 70 E3 00 40 A0 E1 04 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 40 E0 E3 00 30 80 E5 03 00 00 EA 00 00 50 E3 0D 00 A0 01 03 10 A0 01 ?? ?? ?? 0B 04 00 A0 E1 60 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_lstat64_9611e09cbf1e7cad790ab7b06058ff3c {
	meta:
		aliases = "lstat64, __GI_lstat64"
		size = "80"
		objfiles = "lstat64@libc.a"
	strings:
		$pattern = { 10 40 2D E9 60 D0 4D E2 01 30 A0 E1 0D 10 A0 E1 C4 00 90 EF 01 0A 70 E3 00 40 A0 E1 04 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 40 E0 E3 00 30 80 E5 03 00 00 EA 00 00 50 E3 0D 00 A0 01 03 10 A0 01 ?? ?? ?? 0B 04 00 A0 E1 60 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule fstat64_4017b769b5a27961b0a1361693234282 {
	meta:
		aliases = "__GI_fstat64, fstat64"
		size = "80"
		objfiles = "fstat64@libc.a"
	strings:
		$pattern = { 10 40 2D E9 60 D0 4D E2 01 30 A0 E1 0D 10 A0 E1 C5 00 90 EF 01 0A 70 E3 00 40 A0 E1 04 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 40 E0 E3 00 30 80 E5 03 00 00 EA 00 00 50 E3 0D 00 A0 01 03 10 A0 01 ?? ?? ?? 0B 04 00 A0 E1 60 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule fstatat64_cd14db599d3167c8bf9853ab202f0caa {
	meta:
		aliases = "fstatat, fstatat64"
		size = "84"
		objfiles = "fstatat@libc.a, fstatat64@libc.a"
	strings:
		$pattern = { 10 40 2D E9 60 D0 4D E2 02 C0 A0 E1 0D E0 A0 E1 0D 20 A0 E1 47 01 90 EF 01 0A 70 E3 00 40 A0 E1 04 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 40 E0 E3 00 30 80 E5 03 00 00 EA 00 00 54 E3 0D 00 A0 01 0C 10 A0 01 ?? ?? ?? 0B 04 00 A0 E1 60 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule setpriority_f6ef6e89f68de90b0976b95d2dd7ad76 {
	meta:
		aliases = "__GI_setpriority, setpriority"
		size = "44"
		objfiles = "setpriority@libc.a"
	strings:
		$pattern = { 10 40 2D E9 61 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule timerfd_settime_e68d97c7e81292140d56c84494e0596f {
	meta:
		aliases = "timerfd_settime"
		size = "44"
		objfiles = "timerfd@libc.a"
	strings:
		$pattern = { 10 40 2D E9 61 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule timerfd_gettime_563891d266231c56412c56860478f561 {
	meta:
		aliases = "timerfd_gettime"
		size = "44"
		objfiles = "timerfd@libc.a"
	strings:
		$pattern = { 10 40 2D E9 62 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule statfs_9355947002b7c6df6de989bd3965d1c6 {
	meta:
		aliases = "__libc_statfs, statfs"
		size = "44"
		objfiles = "statfs@libc.a"
	strings:
		$pattern = { 10 40 2D E9 63 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule fstatfs_3901152236d21195c12b59f64b62114d {
	meta:
		aliases = "__libc_fstatfs, fstatfs"
		size = "44"
		objfiles = "fstatfs@libc.a"
	strings:
		$pattern = { 10 40 2D E9 64 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __socketcall_c3363b35b83d5207ca2cd8ebb6d2dcc8 {
	meta:
		aliases = "__socketcall"
		size = "44"
		objfiles = "__socketcall@libc.a"
	strings:
		$pattern = { 10 40 2D E9 66 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule klogctl_709066e1bdfe7a263d1b2d4180551edd {
	meta:
		aliases = "klogctl"
		size = "44"
		objfiles = "klogctl@libc.a"
	strings:
		$pattern = { 10 40 2D E9 67 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule setitimer_f7ad9da154ce29b988aa5e9b33e284e6 {
	meta:
		aliases = "__GI_setitimer, setitimer"
		size = "44"
		objfiles = "setitimer@libc.a"
	strings:
		$pattern = { 10 40 2D E9 68 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule getitimer_54b9df965380d50f828d635dabb3e4ed {
	meta:
		aliases = "getitimer"
		size = "44"
		objfiles = "getitimer@libc.a"
	strings:
		$pattern = { 10 40 2D E9 69 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule vhangup_dc4e27e4e168182d9be1bab43f22a22a {
	meta:
		aliases = "vhangup"
		size = "44"
		objfiles = "vhangup@libc.a"
	strings:
		$pattern = { 10 40 2D E9 6F 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule wait4_34df717d0a5d741d02f77e5b7ec895fb {
	meta:
		aliases = "__GI_wait4, wait4"
		size = "44"
		objfiles = "wait4@libc.a"
	strings:
		$pattern = { 10 40 2D E9 72 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule swapoff_a051656fe4d4a36241f74b451463f5d4 {
	meta:
		aliases = "swapoff"
		size = "44"
		objfiles = "swapoff@libc.a"
	strings:
		$pattern = { 10 40 2D E9 73 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule sysinfo_a88c04ecc9f8a7fedaa62a0fa8a0d7d1 {
	meta:
		aliases = "sysinfo"
		size = "44"
		objfiles = "sysinfo@libc.a"
	strings:
		$pattern = { 10 40 2D E9 74 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __libc_fsync_541587bbd6b19f9263035adca9478cff {
	meta:
		aliases = "fsync, __libc_fsync"
		size = "44"
		objfiles = "fsync@libc.a"
	strings:
		$pattern = { 10 40 2D E9 76 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule mbrtowc_b932182b4a0b904bf0ff19a304875127 {
	meta:
		aliases = "__GI_mbrtowc, mbrtowc"
		size = "136"
		objfiles = "mbrtowc@libc.a"
	strings:
		$pattern = { 10 40 2D E9 78 C0 9F E5 00 00 53 E3 10 D0 4D E2 03 E0 A0 11 0C E0 A0 01 00 C0 51 E2 00 40 A0 E1 0F C0 CD 05 0C 40 A0 01 0F C0 8D 02 04 00 00 0A 00 30 DC E5 00 00 53 E3 0E 00 00 0A 00 00 52 E3 0C 00 00 0A 08 00 8D E2 04 10 8D E2 00 20 E0 E3 01 30 A0 E3 04 C0 8D E5 00 E0 8D E5 ?? ?? ?? EB 00 00 50 E3 04 00 00 BA 00 00 54 E3 08 30 9D 15 00 30 84 15 00 00 00 EA 00 00 A0 E3 10 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule setdomainname_d863a6d7489fdcb684abf2f4c4770ac3 {
	meta:
		aliases = "setdomainname"
		size = "44"
		objfiles = "setdomainname@libc.a"
	strings:
		$pattern = { 10 40 2D E9 79 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_uname_4b7eb3f733c87452c29515043f261165 {
	meta:
		aliases = "uname, __GI_uname"
		size = "44"
		objfiles = "uname@libc.a"
	strings:
		$pattern = { 10 40 2D E9 7A 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule ntp_adjtime_b1a233073507c5b51f83a01b78f58152 {
	meta:
		aliases = "__GI_adjtimex, adjtimex, ntp_adjtime"
		size = "44"
		objfiles = "adjtimex@libc.a"
	strings:
		$pattern = { 10 40 2D E9 7C 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule mprotect_1c66b002d17bc821c796a46b53eba41c {
	meta:
		aliases = "mprotect"
		size = "44"
		objfiles = "mprotect@libc.a"
	strings:
		$pattern = { 10 40 2D E9 7D 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule ntp_gettime_2f95b44ac8cc1e44437f55435c5f3e14 {
	meta:
		aliases = "ntp_gettime"
		size = "68"
		objfiles = "ntp_gettime@libc.a"
	strings:
		$pattern = { 10 40 2D E9 80 D0 4D E2 00 40 A0 E1 00 30 A0 E3 0D 00 A0 E1 00 30 8D E5 ?? ?? ?? EB 0C 10 8D E2 0A 00 91 E8 24 C0 9D E5 28 20 9D E5 00 C0 84 E5 0C 30 84 E5 04 20 84 E5 08 10 84 E5 80 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule delete_module_5025089706c97ed154cbf9f26b9f758a {
	meta:
		aliases = "delete_module"
		size = "44"
		objfiles = "delete_module@libc.a"
	strings:
		$pattern = { 10 40 2D E9 81 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule quotactl_44cdd3bef7a30360a6dd10e204ee8364 {
	meta:
		aliases = "quotactl"
		size = "44"
		objfiles = "quotactl@libc.a"
	strings:
		$pattern = { 10 40 2D E9 83 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule getpgid_0ed16f478fb9c3cb14e85b8a390f6707 {
	meta:
		aliases = "getpgid"
		size = "44"
		objfiles = "getpgid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 84 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule fchdir_137e5acc80587a4d8ce6765d462cdad1 {
	meta:
		aliases = "__GI_fchdir, fchdir"
		size = "44"
		objfiles = "fchdir@libc.a"
	strings:
		$pattern = { 10 40 2D E9 85 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule bdflush_1f279a01ca4020143c2bcb70bd028440 {
	meta:
		aliases = "bdflush"
		size = "44"
		objfiles = "bdflush@libc.a"
	strings:
		$pattern = { 10 40 2D E9 86 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule personality_9c12622d8b8218b41db75576e54c2819 {
	meta:
		aliases = "personality"
		size = "44"
		objfiles = "personality@libc.a"
	strings:
		$pattern = { 10 40 2D E9 88 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule flock_938eb8b7fe44e708ce4d5d329785c289 {
	meta:
		aliases = "flock"
		size = "44"
		objfiles = "flock@libc.a"
	strings:
		$pattern = { 10 40 2D E9 8F 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule msync_23af1cbbb7d750f5fdd16e50d91db127 {
	meta:
		aliases = "__libc_msync, msync"
		size = "44"
		objfiles = "msync@libc.a"
	strings:
		$pattern = { 10 40 2D E9 90 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_getrpcent_33044997b988bd6dd7d50efe3a68bb0b {
	meta:
		aliases = "getrpcent, __GI_getrpcent"
		size = "80"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { 10 40 2D E9 90 FF FF EB 00 40 50 E2 0B 00 00 0A 00 30 94 E5 00 00 53 E3 05 00 00 1A 24 00 9F E5 24 10 9F E5 ?? ?? ?? EB 00 00 50 E3 00 00 84 E5 02 00 00 0A 04 00 A0 E1 10 40 BD E8 9F FF FF EA 00 00 A0 E3 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule readv_676b61248e53def1a8d6bc7c79482206 {
	meta:
		aliases = "readv"
		size = "44"
		objfiles = "readv@libc.a"
	strings:
		$pattern = { 10 40 2D E9 91 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule writev_a90d3e38e869d8857eb01bdc636d0204 {
	meta:
		aliases = "writev"
		size = "44"
		objfiles = "writev@libc.a"
	strings:
		$pattern = { 10 40 2D E9 92 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_getsid_4cd137dcc1858d250908ca429cf46558 {
	meta:
		aliases = "getsid, __GI_getsid"
		size = "44"
		objfiles = "getsid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 93 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule fdatasync_baaf6714351585ed21e6e2cd964ab54c {
	meta:
		aliases = "fdatasync"
		size = "44"
		objfiles = "fdatasync@libc.a"
	strings:
		$pattern = { 10 40 2D E9 94 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule get_current_dir_name_8f6b1758d8805f83e1dd1c57f4d1a9a7 {
	meta:
		aliases = "get_current_dir_name"
		size = "168"
		objfiles = "getdirname@libc.a"
	strings:
		$pattern = { 10 40 2D E9 94 00 9F E5 C0 D0 4D E2 ?? ?? ?? EB 00 40 50 E2 1C 00 00 0A 84 00 9F E5 60 10 8D E2 ?? ?? ?? EB 00 00 50 E3 17 00 00 1A 04 00 A0 E1 0D 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 12 00 00 1A 00 20 9D E5 60 30 9D E5 03 00 52 E1 0E 00 00 1A 04 20 9D E5 64 30 9D E5 03 00 52 E1 0A 00 00 1A 58 20 9D E5 B8 30 9D E5 03 00 52 E1 06 00 00 1A 5C 20 9D E5 BC 30 9D E5 03 00 52 E1 02 00 00 1A 04 00 A0 E1 ?? ?? ?? EB 02 00 00 EA 00 00 A0 E3 00 10 A0 E1 ?? ?? ?? EB C0 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mlock_7a0d998679ff4e5c497f37b57e47311b {
	meta:
		aliases = "mlock"
		size = "44"
		objfiles = "mlock@libc.a"
	strings:
		$pattern = { 10 40 2D E9 96 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule munlock_c61f28792da3d8fb24aafd95715d89b1 {
	meta:
		aliases = "munlock"
		size = "44"
		objfiles = "munlock@libc.a"
	strings:
		$pattern = { 10 40 2D E9 97 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule mlockall_557a42a566e13b5f5cf99505f45084e5 {
	meta:
		aliases = "mlockall"
		size = "44"
		objfiles = "mlockall@libc.a"
	strings:
		$pattern = { 10 40 2D E9 98 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule munlockall_0f78633f8dc98016b84e232643fe46b6 {
	meta:
		aliases = "munlockall"
		size = "44"
		objfiles = "munlockall@libc.a"
	strings:
		$pattern = { 10 40 2D E9 99 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule sched_setparam_b996c160021c065f930392954e687709 {
	meta:
		aliases = "sched_setparam"
		size = "44"
		objfiles = "sched_setparam@libc.a"
	strings:
		$pattern = { 10 40 2D E9 9A 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule sched_getparam_ccee937c9153682154cb0435aa8a54ab {
	meta:
		aliases = "sched_getparam"
		size = "44"
		objfiles = "sched_getparam@libc.a"
	strings:
		$pattern = { 10 40 2D E9 9B 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule sched_setscheduler_cf95c5c36dd801d90326d37a4970bfd3 {
	meta:
		aliases = "sched_setscheduler"
		size = "44"
		objfiles = "sched_setscheduler@libc.a"
	strings:
		$pattern = { 10 40 2D E9 9C 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule sched_getscheduler_44180ead11dd1ffb13a8b5db67d7db6e {
	meta:
		aliases = "sched_getscheduler"
		size = "44"
		objfiles = "sched_getscheduler@libc.a"
	strings:
		$pattern = { 10 40 2D E9 9D 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule sched_yield_0249ac78e4d22bf588926ad72c348294 {
	meta:
		aliases = "sched_yield"
		size = "44"
		objfiles = "sched_yield@libc.a"
	strings:
		$pattern = { 10 40 2D E9 9E 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule sched_get_priority_max_3d8c7fdd67ea18acc81bed6bd87435c9 {
	meta:
		aliases = "sched_get_priority_max"
		size = "44"
		objfiles = "sched_get_priority_max@libc.a"
	strings:
		$pattern = { 10 40 2D E9 9F 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule _buf_5bac25fb540a2958b766d0b30c75c9e8 {
	meta:
		aliases = "_buf"
		size = "44"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { 10 40 2D E9 ?? ?? ?? EB 9C 30 90 E5 00 00 53 E3 00 40 A0 E1 02 00 00 1A 01 0C A0 E3 ?? ?? ?? EB 9C 00 84 E5 9C 00 94 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule __rpc_thread_clnt_cleanup_6cb8a9bb38e14682ff19cd1477cc1f56 {
	meta:
		aliases = "__rpc_thread_clnt_cleanup"
		size = "56"
		objfiles = "clnt_simple@libc.a"
	strings:
		$pattern = { 10 40 2D E9 ?? ?? ?? EB A4 40 90 E5 00 00 54 E3 10 80 BD 08 00 30 94 E5 00 00 53 E3 03 00 A0 11 04 30 93 15 0F E0 A0 11 10 F0 93 15 04 00 A0 E1 10 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule sched_get_priority_min_d79e726456d96476318cde0af6a04783 {
	meta:
		aliases = "sched_get_priority_min"
		size = "44"
		objfiles = "sched_get_priority_min@libc.a"
	strings:
		$pattern = { 10 40 2D E9 A0 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule sched_rr_get_interval_14aef5dad437feb6e7b4bf94b176f967 {
	meta:
		aliases = "sched_rr_get_interval"
		size = "44"
		objfiles = "sched_rr_get_interval@libc.a"
	strings:
		$pattern = { 10 40 2D E9 A1 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_nanosleep_a14c692c82c0930d820e3f36cd51c687 {
	meta:
		aliases = "nanosleep, __libc_nanosleep, __GI_nanosleep"
		size = "44"
		objfiles = "nanosleep@libc.a"
	strings:
		$pattern = { 10 40 2D E9 A2 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __libc_poll_2bd42a77426b787f5c0acabd477524c7 {
	meta:
		aliases = "poll, __GI_poll, __libc_poll"
		size = "44"
		objfiles = "poll@libc.a"
	strings:
		$pattern = { 10 40 2D E9 A8 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __syscall_rt_sigaction_0520bd7e29634b5bc5488d1f0897a2cb {
	meta:
		aliases = "__syscall_rt_sigaction"
		size = "44"
		objfiles = "__syscall_rt_sigaction@libc.a"
	strings:
		$pattern = { 10 40 2D E9 AE 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule pthread_key_delete_433791c6b635af53889107c7f45383e9 {
	meta:
		aliases = "pthread_key_delete"
		size = "208"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 B0 30 9F E5 00 40 A0 E1 AC 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 01 0B 54 E3 03 00 00 2A 9C 10 9F E5 84 31 91 E7 00 00 53 E3 05 00 00 1A 88 00 9F E5 8C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 16 00 A0 E3 10 80 BD E8 7C 30 9F E5 00 30 93 E5 84 21 81 E0 01 00 73 E3 00 30 A0 E3 04 30 82 E5 84 31 81 E7 0E 00 00 0A 52 FF FF EB A4 32 A0 E1 1F E0 04 E2 03 31 A0 E1 00 20 A0 E1 2C C0 D2 E5 00 00 5C E3 02 10 83 E0 02 00 00 1A 74 10 91 E5 00 00 51 E3 0E C1 81 17 00 20 92 E5 00 00 52 E1 F5 FF FF 1A 1C 30 9F E5 10 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 A0 E3 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __rt_sigtimedwait_bde9758ea6941a52469af44edcf5b617 {
	meta:
		aliases = "__rt_sigtimedwait"
		size = "44"
		objfiles = "__rt_sigtimedwait@libc.a"
	strings:
		$pattern = { 10 40 2D E9 B1 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule capget_5675574c7d79939cca6e08470027fb19 {
	meta:
		aliases = "capget"
		size = "44"
		objfiles = "capget@libc.a"
	strings:
		$pattern = { 10 40 2D E9 B8 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule capset_633630494c7e097c5fb6317bfb672e2b {
	meta:
		aliases = "capset"
		size = "44"
		objfiles = "capset@libc.a"
	strings:
		$pattern = { 10 40 2D E9 B9 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule sigaltstack_f75a9b12a0decb2369056b4fc332f81b {
	meta:
		aliases = "sigaltstack"
		size = "44"
		objfiles = "sigaltstack@libc.a"
	strings:
		$pattern = { 10 40 2D E9 BA 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule sendfile_94248496b5b391a59f7bde0ed318e5d4 {
	meta:
		aliases = "sendfile"
		size = "44"
		objfiles = "sendfile@libc.a"
	strings:
		$pattern = { 10 40 2D E9 BB 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule getrlimit_d89fa881e01c47c064d79fe5c1e2b52e {
	meta:
		aliases = "__GI_getrlimit, getrlimit"
		size = "44"
		objfiles = "getrlimit@libc.a"
	strings:
		$pattern = { 10 40 2D E9 BF 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule lchown_3b0b5c9a826cbdf140a27af9ac6a379a {
	meta:
		aliases = "lchown"
		size = "44"
		objfiles = "lchown@libc.a"
	strings:
		$pattern = { 10 40 2D E9 C6 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_getuid_a2afc5bbec862a9c24a2aef61991a3c4 {
	meta:
		aliases = "getuid, __GI_getuid"
		size = "44"
		objfiles = "getuid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 C7 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_getgid_d6e3fe4e539a1852bdb5e5d236b27488 {
	meta:
		aliases = "getgid, __GI_getgid"
		size = "44"
		objfiles = "getgid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 C8 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_geteuid_ddfa9e0aadca818cea003099b7ae1af3 {
	meta:
		aliases = "geteuid, __GI_geteuid"
		size = "44"
		objfiles = "geteuid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 C9 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule getegid_9a35cfc8d97ecfa6e4317b1f470e40b2 {
	meta:
		aliases = "__GI_getegid, getegid"
		size = "44"
		objfiles = "getegid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 CA 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule setreuid_0715b86bf24564eb84acc9a8eacffd02 {
	meta:
		aliases = "__GI_setreuid, setreuid"
		size = "44"
		objfiles = "setreuid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 CB 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule setregid_4cf7ea8a3ed6da8c9d0f0a08dfacc873 {
	meta:
		aliases = "__GI_setregid, setregid"
		size = "44"
		objfiles = "setregid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 CC 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_getgroups_2ebdf83eaf6d77760c02fca7aad4325b {
	meta:
		aliases = "getgroups, __GI_getgroups"
		size = "44"
		objfiles = "getgroups@libc.a"
	strings:
		$pattern = { 10 40 2D E9 CD 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule setgroups_71e93f8cd7d7821a337ee0c3fea5c607 {
	meta:
		aliases = "__GI_setgroups, setgroups"
		size = "44"
		objfiles = "setgroups@libc.a"
	strings:
		$pattern = { 10 40 2D E9 CE 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule fchown_1343a3d717eb6e96a3e8edfa1afcd220 {
	meta:
		aliases = "fchown"
		size = "44"
		objfiles = "fchown@libc.a"
	strings:
		$pattern = { 10 40 2D E9 CF 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_setresuid_dbe79c7fa53896743acc87e2a96897ca {
	meta:
		aliases = "setresuid, __GI_setresuid"
		size = "44"
		objfiles = "setresuid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 D0 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule getresuid_15f07ca285676ca959d3e8299b1f2392 {
	meta:
		aliases = "getresuid"
		size = "44"
		objfiles = "getresuid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 D1 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule setresgid_4f1101a680c54e44de622cf34265340e {
	meta:
		aliases = "__GI_setresgid, setresgid"
		size = "44"
		objfiles = "setresgid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 D2 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule getresgid_b28a9367230ef9618fd5d14396b41e37 {
	meta:
		aliases = "getresgid"
		size = "44"
		objfiles = "getresgid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 D3 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule chown_da8527f5aefc711cf6684ef3bf2ae04f {
	meta:
		aliases = "__GI_chown, chown"
		size = "44"
		objfiles = "chown@libc.a"
	strings:
		$pattern = { 10 40 2D E9 D4 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule setuid_9fb283e421658af8e070dd7ac3a161ba {
	meta:
		aliases = "setuid"
		size = "44"
		objfiles = "setuid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 D5 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule setgid_34adc8c94345ae5201b96cb454007475 {
	meta:
		aliases = "setgid"
		size = "44"
		objfiles = "setgid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 D6 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule setfsuid_72103bdf0e6faaa6907e6263cbf13be5 {
	meta:
		aliases = "setfsuid"
		size = "44"
		objfiles = "setfsuid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 D7 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule setfsgid_6965b06dad390508dbc3a83df07b644d {
	meta:
		aliases = "setfsgid"
		size = "44"
		objfiles = "setfsgid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 D8 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule pivot_root_479537103a86be29f634f79fb17fce66 {
	meta:
		aliases = "pivot_root"
		size = "44"
		objfiles = "pivot_root@libc.a"
	strings:
		$pattern = { 10 40 2D E9 DA 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule mincore_95f962de8c716cf6170309957ba3817f {
	meta:
		aliases = "mincore"
		size = "44"
		objfiles = "mincore@libc.a"
	strings:
		$pattern = { 10 40 2D E9 DB 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule madvise_932ee1e68c440570b3d2b088583967cf {
	meta:
		aliases = "madvise"
		size = "44"
		objfiles = "madvise@libc.a"
	strings:
		$pattern = { 10 40 2D E9 DC 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule getxattr_20570a44bc2517901133e328e12de7be {
	meta:
		aliases = "getxattr"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 E5 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule lgetxattr_add0f88ec0ec171dece118826f4bbcd3 {
	meta:
		aliases = "lgetxattr"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 E6 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule fgetxattr_1e9ba1eed09b9ebf32fe3980b47ececc {
	meta:
		aliases = "fgetxattr"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 E7 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule listxattr_56c75f3a43bc20fe995a7f6d7bc56863 {
	meta:
		aliases = "listxattr"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 E8 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule llistxattr_ccfea69e8e16546469f4e25fbe766ea6 {
	meta:
		aliases = "llistxattr"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 E9 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule flistxattr_381eed894b52b996da6a6711f63e30df {
	meta:
		aliases = "flistxattr"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 EA 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule removexattr_8ecc3d0806fd722fa36e86a328a8af0f {
	meta:
		aliases = "removexattr"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 EB 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule lremovexattr_2ec867c1d0a60aa3b99023f187d49b8a {
	meta:
		aliases = "lremovexattr"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 EC 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule fremovexattr_266de7b6732ffb2b5287327f1baa7124 {
	meta:
		aliases = "fremovexattr"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 ED 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule sendfile64_53c3dcabd33c8809205e8e646f1de075 {
	meta:
		aliases = "sendfile64"
		size = "44"
		objfiles = "sendfile64@libc.a"
	strings:
		$pattern = { 10 40 2D E9 EF 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule epoll_create_20d8cbce000cd9fb49ed2d4b1cee874e {
	meta:
		aliases = "epoll_create"
		size = "44"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { 10 40 2D E9 FA 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule epoll_ctl_471054f3df3407fbe5e7147d250cc714 {
	meta:
		aliases = "epoll_ctl"
		size = "44"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { 10 40 2D E9 FB 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule epoll_wait_53a9fcfb563cd713f19c5a593c1affa1 {
	meta:
		aliases = "epoll_wait"
		size = "44"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { 10 40 2D E9 FC 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 10 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_memrchr_cc6da8dfc8b4243d10185c29be27a762 {
	meta:
		aliases = "memrchr, __GI_memrchr"
		size = "220"
		objfiles = "memrchr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 FF 10 01 E2 02 00 80 E0 03 00 00 EA 01 30 70 E5 01 00 53 E1 10 80 BD 08 01 20 42 E2 00 00 52 E3 01 00 00 0A 03 00 10 E3 F7 FF FF 1A 01 34 81 E1 03 48 83 E1 19 00 00 EA 04 30 30 E5 03 30 24 E0 0C C0 83 E0 03 30 E0 E1 0C 30 23 E0 0E E0 03 E0 00 00 5E E3 04 20 42 E2 10 00 00 0A 03 30 D0 E5 01 00 53 E1 03 30 80 E2 07 00 00 0A 02 30 D0 E5 01 00 53 E1 02 30 80 E2 03 00 00 0A 01 30 D0 E5 01 00 53 E1 01 30 80 E2 01 00 00 1A 03 00 A0 E1 10 80 BD E8 00 30 D0 E5 01 00 53 E1 10 80 BD 08 03 00 52 E3 24 C0 9F E5 24 E0 9F E5 E1 FF FF 8A 02 00 00 EA 01 30 70 E5 01 00 53 E1 10 80 BD 08 01 20 52 E2 }
	condition:
		$pattern
}

rule memchr_8c1436d3c755d0d7459fe2b92a7c4809 {
	meta:
		aliases = "__GI_memchr, memchr"
		size = "244"
		objfiles = "memchr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 FF 10 01 E2 04 00 00 EA 00 30 D0 E5 01 00 53 E1 10 80 BD 08 01 20 42 E2 01 00 80 E2 00 00 52 E3 01 00 00 0A 03 00 10 E3 F6 FF FF 1A 01 34 81 E1 00 E0 A0 E1 03 48 83 E1 1C 00 00 EA 04 30 9E E4 03 30 24 E0 0C C0 83 E0 03 30 E0 E1 0C 30 23 E0 00 00 03 E0 00 00 50 E3 04 20 42 E2 13 00 00 0A 04 30 5E E5 04 00 4E E2 01 00 53 E1 03 C0 80 E2 10 80 BD 08 03 30 5E E5 01 00 53 E1 01 30 80 E2 01 00 00 1A 03 00 A0 E1 10 80 BD E8 02 30 5E E5 01 00 53 E1 02 00 80 E2 10 80 BD 08 01 30 5E E5 01 00 53 E1 01 00 00 1A 0C 00 A0 E1 10 80 BD E8 03 00 52 E3 2C C0 9F E5 2C 00 9F E5 DE FF FF 8A 0E 00 A0 E1 }
	condition:
		$pattern
}

rule __GI_rawmemchr_8c449240d3231ed329e2d0679bec07dc {
	meta:
		aliases = "rawmemchr, __GI_rawmemchr"
		size = "176"
		objfiles = "rawmemchr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 FF E0 01 E2 03 00 00 EA 00 30 D0 E5 0E 00 53 E1 10 80 BD 08 01 00 80 E2 03 00 10 E3 F9 FF FF 1A 0E 34 8E E1 00 C0 A0 E1 03 48 83 E1 04 30 9C E4 6C 10 9F E5 03 30 24 E0 01 10 83 E0 64 20 9F E5 03 30 E0 E1 01 30 23 E0 02 20 03 E0 00 00 52 E3 F5 FF FF 0A 04 30 5C E5 04 00 4C E2 0E 00 53 E1 03 20 80 E2 10 80 BD 08 03 30 5C E5 0E 00 53 E1 01 30 80 E2 01 00 00 1A 03 00 A0 E1 10 80 BD E8 02 30 5C E5 0E 00 53 E1 02 00 80 E2 10 80 BD 08 01 30 5C E5 0E 00 53 E1 E3 FF FF 1A 02 00 A0 E1 10 80 BD E8 FF FE FE 7E 00 01 01 81 }
	condition:
		$pattern
}

rule exit_c699065025a9271dbd3f3b1fe556f9a4 {
	meta:
		aliases = "__GI_exit, exit"
		size = "148"
		objfiles = "exit@libc.a"
	strings:
		$pattern = { 10 D0 4D E2 6C 10 9F E5 6C 20 9F E5 6C 30 9F E5 00 40 A0 E1 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 5C 30 9F E5 50 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 50 30 9F E5 00 30 93 E5 00 00 53 E3 04 00 A0 11 0F E0 A0 11 03 F0 A0 11 3C 30 9F E5 0D 00 A0 E1 01 10 A0 E3 0F E0 A0 E1 03 F0 A0 E1 ?? ?? ?? EB 28 30 9F E5 00 00 53 E3 0F E0 A0 11 03 F0 A0 11 04 00 A0 E1 ?? ?? ?? EB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdrmem_inline_fdce170850d61b7de90ffa8cf87d27dd {
	meta:
		aliases = "xdrmem_inline"
		size = "40"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { 14 20 90 E5 01 00 52 E1 0C C0 90 25 00 C0 A0 33 02 20 61 20 01 30 8C 20 0C 30 80 25 14 20 80 25 0C 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule outb_5dec0c8d7b2a3c2afdbb76cfc5fcb069 {
	meta:
		aliases = "outb"
		size = "32"
		objfiles = "ioperm@libc.a"
	strings:
		$pattern = { 14 20 9F E5 08 30 92 E5 11 13 A0 E1 00 30 92 E5 FF 00 00 E2 03 00 C1 E7 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_attr_getguardsize_71c31f4be323be3dc0c32d4c0e971b33 {
	meta:
		aliases = "pthread_attr_getguardsize, __pthread_attr_getguardsize"
		size = "16"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 14 30 90 E5 00 00 A0 E3 00 30 81 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule xdrmem_putlong_4fe1e45cb26d363dfedfdf2f7271fc5d {
	meta:
		aliases = "xdrmem_putint32, xdrmem_putlong"
		size = "80"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { 14 30 90 E5 03 00 53 E3 00 00 A0 93 0E F0 A0 91 04 30 43 E2 14 30 80 E5 00 10 91 E5 FF 28 01 E2 21 3C A0 E1 22 34 83 E1 FF 2C 01 E2 02 34 83 E1 0C 20 90 E5 01 3C 83 E1 00 30 82 E5 0C 30 90 E5 04 30 83 E2 0C 30 80 E5 01 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule xdrmem_getint32_37701a71b68e33d1a85de117e55e5d34 {
	meta:
		aliases = "xdrmem_getlong, xdrmem_getint32"
		size = "84"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { 14 30 90 E5 03 00 53 E3 01 C0 A0 E1 00 00 A0 93 0E F0 A0 91 04 30 43 E2 14 30 80 E5 0C 30 90 E5 00 10 93 E5 FF 28 01 E2 21 3C A0 E1 22 34 83 E1 FF 2C 01 E2 02 34 83 E1 01 3C 83 E1 00 30 8C E5 0C 30 90 E5 04 30 83 E2 0C 30 80 E5 01 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule xdrstdio_create_c57f553388b82d807d7072dc11f20a2f {
	meta:
		aliases = "xdrstdio_create"
		size = "32"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { 14 30 9F E5 00 C0 A0 E3 10 C0 80 E5 0C 00 80 E8 0C 10 80 E5 14 C0 80 E5 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule print_and_abort_13c116ae12bd354b0c87ed1a2306873d {
	meta:
		aliases = "print_and_abort"
		size = "40"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { 14 30 9F E5 14 10 9F E5 00 00 93 E5 10 20 9F E5 ?? ?? ?? EB 01 00 A0 E3 ?? ?? ?? EB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _ppfs_setargs_6a2da19e668c100dd12953e838c63750 {
	meta:
		aliases = "_ppfs_setargs"
		size = "412"
		objfiles = "_ppfs_setargs@libc.a"
	strings:
		$pattern = { 18 10 90 E5 00 00 51 E3 30 40 2D E9 08 30 90 E5 49 00 00 1A 02 01 53 E3 05 00 00 1A 4C 30 90 E5 00 20 93 E5 04 30 83 E2 4C 30 80 E5 08 20 80 E5 50 20 80 E5 04 30 90 E5 02 01 53 E3 50 E0 80 E2 05 00 00 1A 4C 30 90 E5 00 20 93 E5 04 30 83 E2 4C 30 80 E5 04 20 80 E5 50 20 80 E5 34 51 9F E5 01 40 A0 E1 30 00 00 EA 04 31 80 E0 28 30 93 E5 08 00 53 E3 01 40 84 E2 2B 00 00 0A 4C C0 90 E5 07 00 00 CA 02 00 53 E3 17 00 00 0A 02 00 00 CA 00 00 53 E3 14 00 00 AA 1E 00 00 EA 07 00 53 E3 0A 00 00 EA 01 0B 53 E3 0F 00 00 0A 04 00 00 CA 01 0C 53 E3 0C 00 00 0A 02 0C 53 E3 15 00 00 1A 09 00 00 EA 02 0B 53 E3 }
	condition:
		$pattern
}

rule rpc_thread_multi_4e76abfe52a8e6ef0c4205a097787c96 {
	meta:
		aliases = "rpc_thread_multi"
		size = "44"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { 18 30 9F E5 00 00 53 E3 14 10 9F E5 14 30 9F 05 00 10 83 05 0E F0 A0 01 02 00 A0 E3 ?? ?? ?? EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ispunct_34453b9b72ac3592e35d276b4bfedf24 {
	meta:
		aliases = "__GI_ispunct, ispunct"
		size = "36"
		objfiles = "ispunct@libc.a"
	strings:
		$pattern = { 18 30 9F E5 00 30 93 E5 80 00 A0 E1 03 00 80 E0 01 00 D0 E5 00 04 A0 E1 01 0B 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_isblank_04676f99c4c22d0c0ab44abf28ccb085 {
	meta:
		aliases = "isblank, __GI_isblank"
		size = "36"
		objfiles = "isblank@libc.a"
	strings:
		$pattern = { 18 30 9F E5 00 30 93 E5 80 00 A0 E1 03 00 80 E0 01 00 D0 E5 00 04 A0 E1 01 0C 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isalnum_03e245c133ace13950a353a77a7905ec {
	meta:
		aliases = "__GI_isalnum, isalnum"
		size = "36"
		objfiles = "isalnum@libc.a"
	strings:
		$pattern = { 18 30 9F E5 00 30 93 E5 80 00 A0 E1 03 00 80 E0 01 00 D0 E5 00 04 A0 E1 02 0B 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule iscntrl_3410e46c7f1eacf3e49ac2c45d56a297 {
	meta:
		aliases = "__GI_iscntrl, iscntrl"
		size = "36"
		objfiles = "iscntrl@libc.a"
	strings:
		$pattern = { 18 30 9F E5 00 30 93 E5 80 00 A0 E1 03 00 80 E0 01 00 D0 E5 00 04 A0 E1 02 0C 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule atexit_ec24d1d5a8d7be5861871fee2cb65048 {
	meta:
		aliases = "atexit"
		size = "40"
		objfiles = "atexits@uclibc_nonshared.a"
	strings:
		$pattern = { 18 30 9F E5 18 20 9F E5 03 30 8F E0 02 20 93 E7 00 00 52 E3 00 20 92 15 00 10 A0 E3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule enqueue_87f857d09940efef44b7a93828aa85f2 {
	meta:
		aliases = "enqueue"
		size = "48"
		objfiles = "condvar@libpthread.a, semaphore@libpthread.a, rwlock@libpthread.a"
	strings:
		$pattern = { 18 C0 91 E5 04 00 00 EA 18 30 92 E5 03 00 5C E1 08 20 81 C5 03 00 00 CA 08 00 82 E2 00 20 90 E5 00 00 52 E3 F7 FF FF 1A 00 10 80 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule munge_stream_4fb300da73fb4c35d6bce1e25e1767b2 {
	meta:
		aliases = "munge_stream"
		size = "28"
		objfiles = "fgetwc_unlocked@libc.a"
	strings:
		$pattern = { 1C 10 80 E5 08 10 80 E5 0C 10 80 E5 10 10 80 E5 14 10 80 E5 18 10 80 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule _dl_aux_init_87cb184bea8b779c9000e532b12eda0f {
	meta:
		aliases = "_dl_aux_init"
		size = "36"
		objfiles = "dl_support@libc.a"
	strings:
		$pattern = { 1C 20 90 E5 10 30 9F E5 2C 10 90 E5 00 20 83 E5 08 30 9F E5 00 10 83 E5 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule inw_1cb56a6dcc09af366d7984cc3df92454 {
	meta:
		aliases = "inw"
		size = "40"
		objfiles = "ioperm@libc.a"
	strings:
		$pattern = { 1C 20 9F E5 08 30 92 E5 10 03 A0 E1 00 30 92 E5 03 20 80 E0 03 30 D0 E7 01 00 D2 E5 00 04 83 E1 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isctype_3b7e99730b79bc56ff6f5aecd3684f9c {
	meta:
		aliases = "isctype"
		size = "40"
		objfiles = "isctype@libc.a"
	strings:
		$pattern = { 1C 30 9F E5 00 30 93 E5 80 00 A0 E1 03 20 80 E0 03 00 D0 E7 01 30 D2 E5 03 04 80 E1 01 00 00 E0 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_manager_event_abdc0a9ff4b25adb7b436aaf07090c22 {
	meta:
		aliases = "__pthread_manager_event"
		size = "40"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { 1C 40 9F E5 00 50 A0 E1 00 10 A0 E3 1C 00 94 E5 ?? ?? ?? EB 1C 00 94 E5 ?? ?? ?? EB 05 00 A0 E1 ?? ?? ?? EB ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __md5_to64_97cb3249c9003f670a8042185a518368 {
	meta:
		aliases = "__md5_to64"
		size = "40"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { 1C C0 9F E5 01 00 00 EA 03 30 DC E7 01 30 C0 E4 01 20 52 E2 3F 30 01 E2 21 13 A0 E1 F9 FF FF 5A 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_do_exit_24c2d282471d919f7f7e5062e268320c {
	meta:
		aliases = "__pthread_do_exit"
		size = "284"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { 1C D0 4D E2 01 40 A0 E1 00 50 A0 E1 C8 FF FF EB 01 30 A0 E3 40 30 C0 E5 00 30 A0 E3 00 60 A0 E1 41 30 C0 E5 04 00 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 1C 00 96 E5 06 10 A0 E1 ?? ?? ?? EB 24 31 96 E5 00 00 53 E3 30 50 86 E5 0B 00 00 0A B8 30 9F E5 28 21 96 E5 00 30 93 E5 02 30 83 E1 01 0C 13 E3 05 00 00 0A 09 30 A0 E3 30 31 86 E5 9C 30 9F E5 34 61 86 E5 00 60 83 E5 ?? ?? ?? EB 38 40 96 E5 01 30 A0 E3 2C 30 C6 E5 1C 00 96 E5 ?? ?? ?? EB 00 00 54 E3 04 00 A0 11 ?? ?? ?? 1B 70 30 9F E5 00 40 93 E5 04 00 56 E1 15 00 00 1A 64 00 9F E5 00 30 90 E5 00 00 53 E3 11 00 00 BA 03 30 A0 E3 04 30 8D E5 00 40 8D E5 }
	condition:
		$pattern
}

rule __GI_abort_89715f2c882e51511bd5d9bb05f10e9d {
	meta:
		aliases = "abort, __GI_abort"
		size = "268"
		objfiles = "abort@libc.a"
	strings:
		$pattern = { 1C D0 4D E2 F0 30 9F E5 14 50 8D E2 EC 00 9F E5 00 40 A0 E3 0F E0 A0 E1 03 F0 A0 E1 06 10 A0 E3 05 00 A0 E1 14 40 8D E5 18 40 8D E5 ?? ?? ?? EB 04 20 A0 E1 05 10 A0 E1 01 00 A0 E3 ?? ?? ?? EB BC 20 9F E5 00 30 92 E5 04 00 53 E1 0B 00 00 1A 01 30 A0 E3 00 30 82 E5 A8 30 9F E5 9C 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 06 00 A0 E3 ?? ?? ?? EB 88 00 9F E5 80 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 7C C0 9F E5 00 30 9C E5 01 00 53 E3 0D 00 00 1A 01 30 83 E2 0D 00 A0 E1 00 10 A0 E3 14 20 A0 E3 00 30 8C E5 ?? ?? ?? EB 00 30 E0 E3 0D 10 A0 E1 00 20 A0 E3 06 00 A0 E3 10 30 8D E5 0C 30 8D E5 ?? ?? ?? EB E3 FF FF EA }
	condition:
		$pattern
}

rule _dl_linux_resolve_51224eed06ca5afb1111e7f3807eb401 {
	meta:
		aliases = "_dl_linux_resolve"
		size = "32"
		objfiles = "resolve@libdl.a"
	strings:
		$pattern = { 1F 00 2D E9 04 00 1E E5 0C 10 4E E0 41 11 E0 E1 ?? ?? ?? EB 00 C0 A0 E1 1F 40 BD E8 0C F0 A0 E1 }
	condition:
		$pattern
}

rule __paritysi2_6fcc3139510411c5a3f5d946d00ac7f6 {
	meta:
		aliases = "__paritysi2"
		size = "36"
		objfiles = "_paritysi2@libgcc.a"
	strings:
		$pattern = { 20 08 20 E0 20 04 20 E0 20 02 20 E0 69 3C A0 E3 0F 00 00 E2 96 30 83 E2 53 30 A0 E1 01 00 03 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule dlerror_dc3445d67dc50daace9b54b3cbc36fab {
	meta:
		aliases = "dlerror"
		size = "48"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 20 10 9F E5 00 00 91 E5 00 00 50 E3 0E F0 A0 01 14 30 9F E5 00 21 93 E7 00 30 A0 E3 02 00 A0 E1 00 30 81 E5 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __malloc_largebin_index_ebb502ab1ed9b7c37b28e1505e504508 {
	meta:
		aliases = "__malloc_largebin_index"
		size = "120"
		objfiles = "malloc@libc.a"
	strings:
		$pattern = { 20 14 A0 E1 01 08 51 E3 00 C0 A0 E1 5F 00 A0 23 0E F0 A0 21 01 3C 41 E2 23 38 A0 E1 08 30 03 E2 11 13 A0 E1 01 2A 41 E2 22 28 A0 E1 04 20 02 E2 11 12 A0 E1 01 09 41 E2 20 08 A0 E1 02 00 00 E2 11 10 A0 E1 0D 30 63 E2 03 30 62 E0 A1 27 E0 E1 21 27 02 E0 03 30 60 E0 02 30 83 E0 06 20 83 E2 3C 22 A0 E1 03 31 A0 E1 20 30 83 E2 03 20 02 E2 02 00 83 E0 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __ashldi3_887a760ccd40f339c0b687063b63c0fc {
	meta:
		aliases = "__aeabi_llsl, __ashldi3"
		size = "28"
		objfiles = "_ashldi3@libgcc.a"
	strings:
		$pattern = { 20 30 52 E2 20 C0 62 E2 11 12 A0 41 10 13 A0 51 30 1C 81 41 10 02 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __aeabi_llsr_dc8d41a1bb89f16fc4a2c36d7e776e70 {
	meta:
		aliases = "__lshrdi3, __aeabi_llsr"
		size = "28"
		objfiles = "_lshrdi3@libgcc.a"
	strings:
		$pattern = { 20 30 52 E2 20 C0 62 E2 30 02 A0 41 31 03 A0 51 11 0C 80 41 31 12 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __ashrdi3_bbd82ffebddc7de5630c025bd359f1aa {
	meta:
		aliases = "__aeabi_lasr, __ashrdi3"
		size = "28"
		objfiles = "_ashrdi3@libgcc.a"
	strings:
		$pattern = { 20 30 52 E2 20 C0 62 E2 30 02 A0 41 51 03 A0 51 11 0C 80 41 51 12 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_attr_getstacksize_6c5d6331f482f886c8d9ebd865b140ac {
	meta:
		aliases = "__pthread_attr_getstacksize, pthread_attr_getstacksize"
		size = "16"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 20 30 90 E5 00 00 A0 E3 00 30 81 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule llround_9b89ce865160df82b75b166842321940 {
	meta:
		aliases = "__GI_llround, llround"
		size = "260"
		objfiles = "s_llround@libm.a"
	strings:
		$pattern = { 20 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 F0 40 2D E9 FF 6F 43 E2 00 00 50 E3 03 60 46 E2 FF 24 C0 E3 01 70 A0 A3 00 70 E0 B3 0F 26 C2 E3 13 00 56 E3 00 40 A0 E1 01 50 A0 E1 01 26 82 E3 0E 00 00 CA 00 00 56 E3 05 00 00 AA 01 00 76 E3 00 00 A0 13 00 10 A0 13 07 00 A0 01 C0 1F A0 01 F0 80 BD E8 02 37 A0 E3 53 36 82 E0 14 20 66 E2 33 32 A0 E1 03 00 A0 E1 00 10 A0 E3 1D 00 00 EA 3E 00 56 E3 19 00 00 CA 33 00 56 E3 08 00 00 DA 02 30 A0 E1 00 40 A0 E3 03 40 A0 E1 00 30 A0 E3 01 00 83 E1 34 20 46 E2 04 10 A0 E1 ?? ?? ?? EB 10 00 00 EA 14 E0 46 E2 02 31 A0 E3 33 4E 81 E0 01 00 54 E1 01 20 82 32 14 00 56 E3 }
	condition:
		$pattern
}

rule lround_8c0e608a6512757a5da467e3b390a9c1 {
	meta:
		aliases = "__GI_lround, lround"
		size = "176"
		objfiles = "s_lround@libm.a"
	strings:
		$pattern = { 20 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF CF 43 E2 00 00 50 E3 03 C0 4C E2 FF 24 C0 E3 30 40 2D E9 0F 26 C2 E3 01 E0 A0 A3 00 E0 E0 B3 13 00 5C E3 01 50 A0 E1 01 40 A0 E1 01 26 82 E3 0A 00 00 CA 00 00 5C E3 03 00 00 AA 01 00 7C E3 0E 00 A0 01 00 00 A0 13 30 80 BD E8 02 37 A0 E3 53 3C 82 E0 14 20 6C E2 33 02 A0 E1 0E 00 00 EA 1E 00 5C E3 0A 00 00 CA 02 31 A0 E3 14 00 4C E2 33 10 81 E0 05 00 51 E1 01 20 82 32 14 00 5C E3 34 30 6C 12 31 33 A0 11 12 00 83 11 02 00 A0 01 01 00 00 EA ?? ?? ?? EB 30 80 BD E8 9E 00 00 E0 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_lrint_1a2f6a6ca602a3ccb447655f514f23aa {
	meta:
		aliases = "lrint, __GI_lrint"
		size = "304"
		objfiles = "s_lrint@libm.a"
	strings:
		$pattern = { 20 3A A0 E1 F0 41 2D E9 83 3A A0 E1 A3 3A A0 E1 FF 3F 43 E2 03 30 43 E2 13 00 53 E3 08 D0 4D E2 00 60 A0 E1 01 70 A0 E1 00 40 A0 E1 01 50 A0 E1 A0 8F A0 E1 19 00 00 CA 01 00 73 E3 00 00 A0 B3 37 00 00 BA E0 30 9F E5 88 31 83 E0 30 00 93 E8 06 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 03 00 8D E8 05 30 A0 E1 04 20 A0 E1 03 00 9D E8 ?? ?? ?? EB 20 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF 04 C0 E3 0F 06 C0 E3 41 3E 63 E2 01 06 80 E3 03 30 83 E2 30 03 A0 E1 1E 00 00 EA 1E 00 53 E3 1A 00 00 CA 7C 30 9F E5 88 31 83 E0 30 00 93 E8 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __GI_llrint_8c69e0ed2430d1453c96585da66c3bb6 {
	meta:
		aliases = "llrint, __GI_llrint"
		size = "404"
		objfiles = "s_llrint@libm.a"
	strings:
		$pattern = { 20 3A A0 E1 F0 41 2D E9 83 3A A0 E1 A3 3A A0 E1 FF CF 43 E2 03 C0 4C E2 13 00 5C E3 08 D0 4D E2 00 60 A0 E1 01 70 A0 E1 00 40 A0 E1 01 50 A0 E1 A0 8F A0 E1 1C 00 00 CA 50 31 9F E5 88 31 83 E0 30 00 93 E8 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 03 00 8D E8 04 20 A0 E1 05 30 A0 E1 03 00 9D E8 ?? ?? ?? EB 20 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF 2F 43 E2 03 20 42 E2 00 00 52 E3 FF 34 C0 A3 0F 36 C3 A3 01 36 83 A3 14 20 62 A2 33 32 A0 A1 00 00 A0 B3 00 10 A0 B3 03 00 A0 A1 00 10 A0 A3 32 00 00 EA 3E 00 5C E3 2E 00 00 CA 33 00 5C E3 0A 00 00 DA FF 34 C0 E3 0F 36 C3 E3 01 36 83 E3 }
	condition:
		$pattern
}

rule pthread_start_thread_82fe5ee4a8d7f506fafb555f8838c97d {
	meta:
		aliases = "pthread_start_thread"
		size = "220"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { 20 D0 4D E2 00 40 A0 E1 ?? ?? ?? EB 64 10 84 E2 14 00 84 E5 00 20 A0 E3 02 00 A0 E3 ?? ?? ?? EB 6C 10 94 E5 00 00 51 E3 14 00 94 A5 70 20 84 A2 07 00 00 AA 90 30 9F E5 18 30 93 E5 00 00 53 E3 04 00 00 DA 00 10 A0 E3 20 20 8D E2 04 10 22 E5 14 00 94 E5 ?? ?? ?? EB 70 30 9F E5 00 30 93 E5 00 00 53 E3 13 00 00 0A 64 30 9F E5 00 30 93 E5 00 00 53 E3 0F 00 00 DA 05 30 A0 E3 04 30 8D E5 00 40 8D E5 4C 60 9F E5 00 00 96 E5 0D 10 A0 E1 1C 20 A0 E3 ?? ?? ?? EB 01 00 70 E3 03 00 00 1A ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 F5 FF FF 0A 04 00 A0 E1 ?? ?? ?? EB 60 00 94 E5 0F E0 A0 E1 5C F0 94 E5 0D 10 A0 E1 }
	condition:
		$pattern
}

rule __GI___isinf_7160d4c12946ee8b3c58a69ec4309068 {
	meta:
		aliases = "__isinf, __GI___isinf"
		size = "48"
		objfiles = "s_isinf@libm.a"
	strings:
		$pattern = { 24 20 9F E5 02 31 C0 E3 02 30 23 E0 01 30 83 E1 00 C0 A0 E1 00 00 63 E2 03 00 80 E1 00 00 50 E3 4C 0F A0 A1 00 00 A0 B3 0E F0 A0 E1 00 00 F0 7F }
	condition:
		$pattern
}

rule outw_159632572b2937b69f898dc327eb3f67 {
	meta:
		aliases = "outw"
		size = "48"
		objfiles = "ioperm@libc.a"
	strings:
		$pattern = { 24 20 9F E5 08 30 92 E5 11 13 A0 E1 00 C0 92 E5 00 08 A0 E1 20 08 A0 E1 40 24 A0 E1 0C 30 81 E0 0C 00 C1 E7 01 20 C3 E5 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_find_self_770bfa96c53517f1ab1107b588559a17 {
	meta:
		aliases = "__pthread_find_self"
		size = "48"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { 24 20 9F E5 0D 10 A0 E1 00 00 00 EA 10 20 82 E2 08 00 92 E5 00 00 51 E1 FB FF FF 8A 0C 30 92 E5 03 00 51 E1 F8 FF FF 3A 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_getchar_unlocked_c3accbb26318d256e4363dc2acda3fba {
	meta:
		aliases = "getchar_unlocked, __GI_getchar_unlocked"
		size = "48"
		objfiles = "getchar_unlocked@libc.a"
	strings:
		$pattern = { 24 30 9F E5 00 10 93 E5 10 20 91 E5 18 30 91 E5 03 00 52 E1 01 00 00 3A 01 00 A0 E1 ?? ?? ?? EA 01 00 D2 E4 10 20 81 E5 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule putchar_unlocked_124516770b8b39af892eebe7c339e66f {
	meta:
		aliases = "putchar_unlocked"
		size = "48"
		objfiles = "putchar_unlocked@libc.a"
	strings:
		$pattern = { 24 30 9F E5 00 10 93 E5 10 20 91 E5 1C 30 91 E5 03 00 52 E1 00 00 00 3A ?? ?? ?? EA FF 00 00 E2 01 00 C2 E4 10 20 81 E5 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __do_global_ctors_aux_ff0de06c35db23c16df936b9c880e676 {
	meta:
		aliases = "__do_global_ctors_aux"
		size = "60"
		objfiles = "crtend"
	strings:
		$pattern = { 28 20 9F E5 04 30 12 E5 01 00 73 E3 10 40 2D E9 10 80 BD 08 04 40 42 E2 0F E0 A0 E1 03 F0 A0 E1 04 30 34 E5 01 00 73 E3 FA FF FF 1A 10 80 BD E8 ?? ?? ?? ?? 04 E0 2D E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule l64a_22272196a685208e981521cb507797ca {
	meta:
		aliases = "l64a"
		size = "56"
		objfiles = "l64a@libc.a"
	strings:
		$pattern = { 28 20 9F E5 28 10 9F E5 02 00 00 EA 03 30 D1 E7 01 30 C2 E4 20 03 A0 E1 00 00 50 E3 3F 30 00 E2 F9 FF FF 1A 00 00 C2 E5 00 00 9F E5 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sqrt_407f785407bd66ae3b911b0999e66719 {
	meta:
		aliases = "__GI_sqrt, __ieee754_sqrt, sqrt"
		size = "564"
		objfiles = "e_sqrt@libm.a"
	strings:
		$pattern = { 28 22 9F E5 24 C2 9F E5 02 20 00 E0 0C 00 52 E1 F0 43 2D E9 01 C0 A0 E1 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 00 E0 A0 E1 00 80 A0 E3 00 90 A0 E3 08 00 00 1A 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 05 00 A0 E1 06 10 A0 E1 ?? ?? ?? EB 0C 00 00 EA 00 00 50 E3 0D 00 00 CA 02 31 C0 E3 01 30 93 E1 6D 00 00 0A 00 00 50 E3 08 00 00 0A 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 00 50 A0 E1 01 60 A0 E1 62 00 00 EA 4E 3A B0 E1 03 10 A0 01 03 00 00 0A 0F 00 00 EA AC E5 A0 E1 15 10 41 E2 8C CA A0 E1 00 00 5E E3 FA FF FF 0A 00 20 A0 E3 01 00 00 EA 8E E0 A0 E1 }
	condition:
		$pattern
}

rule __md5_Init_82ae3088ea2427dc6d702bcc3bb13c77 {
	meta:
		aliases = "__md5_Init"
		size = "64"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { 28 30 9F E5 0C 30 80 E5 24 30 9F E5 00 30 80 E5 20 30 9F E5 04 30 80 E5 1C 30 9F E5 00 20 A0 E3 10 20 80 E5 08 30 80 E5 14 20 80 E5 0E F0 A0 E1 76 54 32 10 01 23 45 67 89 AB CD EF FE DC BA 98 }
	condition:
		$pattern
}

rule __GI_times_91afd189d10619a7bc4085fbd562a3d3 {
	meta:
		aliases = "times, __GI_times"
		size = "8"
		objfiles = "times@libc.a"
	strings:
		$pattern = { 2B 00 90 EF 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __malloc_trim_3065ba803c844b57e804b79111a8d395 {
	meta:
		aliases = "__malloc_trim"
		size = "164"
		objfiles = "free@libc.a"
	strings:
		$pattern = { 2C 30 91 E5 F0 40 2D E9 04 30 93 E5 5C 43 91 E5 03 60 C3 E3 11 30 44 E2 06 30 83 E0 01 50 A0 E1 03 00 60 E0 04 10 A0 E1 ?? ?? ?? EB 01 00 40 E2 94 00 07 E0 00 00 57 E3 17 00 00 DA 00 00 A0 E3 ?? ?? ?? EB 2C 30 95 E5 03 30 86 E0 03 00 50 E1 00 40 A0 E1 10 00 00 1A 00 00 67 E2 ?? ?? ?? EB 00 00 A0 E3 ?? ?? ?? EB 01 00 70 E3 0A 00 00 0A 00 00 54 E0 08 00 00 0A 68 33 95 E5 06 20 60 E0 2C 10 95 E5 03 30 60 E0 01 20 82 E3 01 00 A0 E3 68 33 85 E5 04 20 81 E5 F0 80 BD E8 00 00 A0 E3 F0 80 BD E8 }
	condition:
		$pattern
}

rule _dl_load_shared_library_01c856ec8cc552befdcc8ce6d805c631 {
	meta:
		aliases = "_dl_load_shared_library"
		size = "588"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 2C C2 9F E5 F0 4F 2D E9 00 E0 A0 E3 00 E0 8C E5 00 70 A0 E1 03 C0 A0 E1 01 80 A0 E1 02 50 A0 E1 01 30 43 E2 01 20 F3 E5 00 00 52 E3 FC FF FF 1A 03 30 6C E0 01 0B 53 E3 02 00 A0 91 01 30 4C 92 02 00 00 9A 70 00 00 EA 2F 00 52 E3 03 00 A0 01 01 20 F3 E5 00 00 52 E3 FA FF FF 1A 00 00 50 E3 0C 40 A0 01 01 40 80 12 0C 00 54 E1 05 00 00 0A 0C 20 A0 E1 07 00 A0 E1 08 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 F0 8F BD 18 00 00 55 E3 0A 00 00 0A 7C 30 95 E5 00 00 53 E3 07 00 00 0A 54 20 95 E5 04 00 A0 E1 02 20 83 E0 07 10 A0 E1 08 30 A0 E1 75 FF FF EB 00 00 50 E3 F0 8F BD 18 74 31 9F E5 00 20 93 E5 00 00 52 E3 }
	condition:
		$pattern
}

rule __GI_isdigit_2cc7b1353f57f0929448a034aadb83c8 {
	meta:
		aliases = "isdigit, __GI_isdigit"
		size = "20"
		objfiles = "isdigit@libc.a"
	strings:
		$pattern = { 30 00 40 E2 09 00 50 E3 00 00 A0 83 01 00 A0 93 0E F0 A0 E1 }
	condition:
		$pattern
}

rule gai_strerror_968101a0a1f86c65c4eb978ed6b0a816 {
	meta:
		aliases = "gai_strerror"
		size = "64"
		objfiles = "gai_strerror@libc.a"
	strings:
		$pattern = { 30 10 9F E5 00 20 A0 E3 06 00 00 EA 82 31 91 E7 00 00 53 E1 02 00 00 1A 82 31 81 E0 04 00 93 E5 0E F0 A0 E1 01 20 82 E2 0F 00 52 E3 F6 FF FF 9A 04 00 9F E5 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sched_setaffinity_4d42c4c814df710200e293941bd350e6 {
	meta:
		aliases = "sched_setaffinity"
		size = "316"
		objfiles = "sched_setaffinity@libc.a"
	strings:
		$pattern = { 30 31 9F E5 00 30 93 E5 0D C0 A0 E1 00 00 53 E3 F0 DD 2D E9 04 B0 4C E2 00 A0 A0 E1 01 70 A0 E1 02 80 A0 E1 25 00 00 1A 84 D0 4D E2 0D 50 A0 E1 80 60 A0 E3 05 00 00 EA 0D D0 61 E0 02 30 8D E0 05 00 53 E1 02 60 A0 11 02 60 86 00 0D 50 A0 E1 ?? ?? ?? EB 06 10 A0 E1 05 20 A0 E1 F2 00 90 EF 86 20 A0 E1 06 30 82 E2 03 10 C3 E3 16 00 70 E3 00 30 A0 13 01 30 A0 03 01 0A 70 E3 00 30 A0 93 00 00 53 E3 00 40 A0 E1 EA FF FF 1A 01 0A 70 E3 00 30 A0 93 01 30 A0 83 00 00 50 E3 01 30 83 03 00 00 53 E3 8C 30 9F 05 00 00 83 05 03 00 00 0A ?? ?? ?? EB 00 30 64 E2 00 20 E0 E3 08 00 00 EA 70 30 9F E5 00 20 93 E5 }
	condition:
		$pattern
}

rule calloc_a76b95ba3676e3b3ffba7100108234dc {
	meta:
		aliases = "calloc"
		size = "268"
		objfiles = "calloc@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 00 50 E3 10 D0 4D E2 01 40 A0 E1 90 01 05 E0 09 00 00 0A 00 10 A0 E1 05 00 A0 E1 ?? ?? ?? EB 00 00 54 E1 04 00 00 0A ?? ?? ?? EB 00 40 A0 E3 0C 30 A0 E3 00 30 80 E5 2A 00 00 EA B0 10 9F E5 B0 20 9F E5 0D 00 A0 E1 AC 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 A4 30 9F E5 98 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 ?? ?? ?? EB 00 40 50 E2 17 00 00 0A 04 30 14 E5 02 10 13 E2 14 00 00 1A 03 30 C3 E3 04 20 43 E2 22 C1 A0 E1 09 00 5C E3 01 00 00 9A ?? ?? ?? EB 0D 00 00 EA 04 00 5C E3 00 10 84 E5 04 10 84 E5 08 10 84 E5 08 00 00 9A 06 00 5C E3 0C 10 84 E5 10 10 84 E5 04 00 00 9A 09 00 5C E3 }
	condition:
		$pattern
}

rule __sigpause_a7c78ed7711995dd155ad95ea63c4aab {
	meta:
		aliases = "__GI___sigpause, __sigpause"
		size = "88"
		objfiles = "sigpause@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 00 51 E3 08 D0 4D E2 00 50 A0 E1 04 10 8D 05 00 00 8D 05 0A 00 00 0A 00 00 A0 E3 0D 20 A0 E1 00 10 A0 E1 ?? ?? ?? EB 0D 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 0D 40 A0 E1 00 00 E0 B3 01 00 00 BA 0D 00 A0 E1 ?? ?? ?? EB 08 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule sem_trywait_8713be2ef33932a12107ee9b8bfbe38f {
	meta:
		aliases = "__new_sem_trywait, sem_trywait"
		size = "76"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 00 10 A0 E3 00 40 A0 E1 ?? ?? ?? EB 08 30 94 E5 00 00 53 E3 04 00 00 1A ?? ?? ?? EB 00 50 E0 E3 0B 30 A0 E3 00 30 80 E5 02 00 00 EA 01 30 43 E2 08 30 84 E5 00 50 A0 E3 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule pthread_rwlock_trywrlock_68c9296bb64f8de8270435c9940315bc {
	meta:
		aliases = "pthread_rwlock_trywrlock"
		size = "72"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 00 10 A0 E3 00 40 A0 E1 ?? ?? ?? EB 08 30 94 E5 00 00 53 E3 05 00 00 1A 0C 50 94 E5 00 00 55 E3 02 00 00 1A D5 FF FF EB 0C 00 84 E5 00 00 00 EA 10 50 A0 E3 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_pthread_cond_signal_559c3e5e5f2e537064fab14252f1acc9 {
	meta:
		aliases = "pthread_cond_signal, __GI_pthread_cond_signal"
		size = "80"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 00 10 A0 E3 00 50 A0 E1 ?? ?? ?? EB 08 40 95 E5 00 00 54 E3 08 30 94 15 08 30 85 15 00 30 A0 13 08 30 84 15 05 00 A0 E1 ?? ?? ?? EB 00 00 54 E3 03 00 00 0A 01 30 A0 E3 41 31 C4 E5 04 00 A0 E1 BC FE FF EB 00 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule __fixdfdi_56639e562c1be4be40aae6d506ccf893 {
	meta:
		aliases = "__fixdfdi"
		size = "72"
		objfiles = "_fixdfdi@libgcc.a"
	strings:
		$pattern = { 30 40 2D E9 00 20 A0 E3 00 30 A0 E3 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? EB 00 00 50 E3 03 00 00 BA 04 00 A0 E1 05 10 A0 E1 30 40 BD E8 ?? ?? ?? EA 02 01 84 E2 05 10 A0 E1 ?? ?? ?? EB 00 00 70 E2 00 10 E1 E2 30 80 BD E8 }
	condition:
		$pattern
}

rule strtod_4007dc262a6002cff4be8e25166dae44 {
	meta:
		aliases = "__GI_strtod, __GI_wcstod, wcstod, strtod"
		size = "44"
		objfiles = "wcstod@libc.a, strtod@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 20 A0 E3 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? EB 04 00 A0 E1 05 10 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule __stdio_trans2r_o_2e548ea84828ecd76518d609c5389540 {
	meta:
		aliases = "__stdio_trans2r_o"
		size = "188"
		objfiles = "_trans2r@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 20 D0 E5 01 30 D0 E5 03 24 82 E1 02 00 11 E1 00 40 A0 E1 05 00 00 1A 22 0D 12 E3 08 00 00 1A 02 20 81 E1 42 34 A0 E1 01 30 C0 E5 00 20 C0 E5 00 20 D4 E5 01 30 D4 E5 03 34 82 E1 10 50 13 E2 09 00 00 0A ?? ?? ?? EB 09 30 A0 E3 00 30 80 E5 00 30 94 E5 08 30 83 E3 43 24 A0 E1 00 00 E0 E3 01 20 C4 E5 00 30 C4 E5 30 80 BD E8 40 00 13 E3 09 00 00 0A ?? ?? ?? EB 00 00 50 E3 F3 FF FF 1A 00 30 94 E5 08 20 94 E5 40 30 C3 E3 43 14 A0 E1 1C 20 84 E5 01 10 C4 E5 00 30 C4 E5 00 30 94 E5 01 30 83 E3 43 24 A0 E1 05 00 A0 E1 01 20 C4 E5 00 30 C4 E5 30 80 BD E8 }
	condition:
		$pattern
}

rule __stdio_adjust_position_ff789e812ed8fafdb8bbe27a19095d1b {
	meta:
		aliases = "__stdio_adjust_position"
		size = "192"
		objfiles = "_adjust_pos@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 20 D0 E5 01 30 D0 E5 03 C4 82 E1 03 20 1C E2 01 50 A0 E1 02 E0 A0 01 0E 00 00 0A 01 E0 52 E2 0C 00 00 0A 02 0B 1C E3 0A 00 00 0A 02 00 5E E3 1E 00 00 0A 28 30 90 E5 00 00 53 E3 1B 00 00 1A 2C 30 90 E5 03 20 D0 E5 00 00 53 E3 02 30 D0 C5 00 E0 62 E2 0E E0 63 C0 40 00 1C E3 10 30 90 E5 08 20 90 15 14 20 90 05 0E 30 63 E0 03 00 95 E8 02 40 83 E0 04 20 50 E0 C4 3F C1 E0 01 00 53 E1 0C 00 85 E8 02 00 00 CA 02 00 00 1A 00 00 52 E1 00 00 00 9A 00 40 64 E2 00 00 54 E3 04 00 00 AA ?? ?? ?? EB 4B 30 A0 E3 00 30 80 E5 00 00 00 EA 00 40 E0 E3 04 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_callmsg_2063b167ed6bcc8fd56c7f1f45f9a113 {
	meta:
		aliases = "__GI_xdr_callmsg, xdr_callmsg"
		size = "1440"
		objfiles = "rpc_cmsg@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 30 90 E5 00 00 53 E3 00 50 A0 E1 01 40 A0 E1 7E 00 00 1A 20 10 91 E5 19 0E 51 E3 5A 01 00 8A 2C 30 94 E5 19 0E 53 E3 57 01 00 8A 03 10 81 E2 03 30 83 E2 03 30 C3 E3 03 10 C1 E3 03 10 81 E0 28 10 81 E2 04 30 90 E5 0F E0 A0 E1 18 F0 93 E5 00 C0 50 E2 6D 00 00 0A 00 10 94 E5 FF 28 01 E2 21 3C A0 E1 22 34 83 E1 FF 2C 01 E2 02 34 83 E1 01 3C 83 E1 0C 00 A0 E1 04 30 80 E4 04 10 94 E5 FF 28 01 E2 21 3C A0 E1 22 34 83 E1 FF 2C 01 E2 02 34 83 E1 01 3C 83 E1 04 30 8C E5 04 30 94 E5 00 00 53 E3 38 01 00 1A 08 10 94 E5 FF 28 01 E2 21 3C A0 E1 22 34 83 E1 FF 2C 01 E2 02 34 83 E1 01 3C 83 E1 }
	condition:
		$pattern
}

rule xdr_double_3258c86dc914444ce0cb0c869fb821b5 {
	meta:
		aliases = "xdr_double"
		size = "148"
		objfiles = "xdr_float@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 30 90 E5 01 00 53 E3 00 40 A0 E1 01 50 A0 E1 11 00 00 0A 03 00 00 3A 02 00 53 E3 00 00 A0 13 01 00 A0 03 30 80 BD E8 04 30 90 E5 0F E0 A0 E1 04 F0 93 E5 00 00 50 E3 30 80 BD 08 04 00 A0 E1 04 10 85 E2 04 30 94 E5 0F E0 A0 E1 04 F0 93 E5 00 00 50 E2 01 00 A0 13 30 80 BD E8 04 30 90 E5 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 30 80 BD 08 04 00 A0 E1 04 10 85 E2 04 30 94 E5 0F E0 A0 E1 00 F0 93 E5 00 00 50 E2 01 00 A0 13 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_rmtcallres_bfb687d948aed5023f30a25054a7e697 {
	meta:
		aliases = "__GI_xdr_rmtcallres, xdr_rmtcallres"
		size = "116"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 30 91 E5 04 D0 4D E2 01 40 A0 E1 04 10 8D E2 04 30 21 E5 04 20 A0 E3 0D 10 A0 E1 48 30 9F E5 00 50 A0 E1 ?? ?? ?? EB 00 00 50 E3 0B 00 00 0A 05 00 A0 E1 04 10 84 E2 ?? ?? ?? EB 00 00 50 E3 06 00 00 0A 00 30 9D E5 05 00 A0 E1 00 30 84 E5 08 10 94 E5 0F E0 A0 E1 0C F0 94 E5 00 00 00 EA 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_xdr_callhdr_f0f6e5ace29920ca70681a931750b245 {
	meta:
		aliases = "xdr_callhdr, __GI_xdr_callhdr"
		size = "136"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 30 A0 E3 04 30 81 E5 02 30 83 E2 08 30 81 E5 00 30 90 E5 00 00 53 E3 01 50 A0 E1 00 40 A0 E1 15 00 00 1A ?? ?? ?? EB 00 00 50 E3 12 00 00 0A 04 00 A0 E1 04 10 85 E2 ?? ?? ?? EB 00 00 50 E3 0D 00 00 0A 04 00 A0 E1 08 10 85 E2 ?? ?? ?? EB 00 00 50 E3 08 00 00 0A 04 00 A0 E1 0C 10 85 E2 ?? ?? ?? EB 00 00 50 E3 03 00 00 0A 04 00 A0 E1 10 10 85 E2 30 40 BD E8 ?? ?? ?? EA 00 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule gethostid_974c02d205b2c7c6fa1c5325aad4c8f6 {
	meta:
		aliases = "gethostid"
		size = "196"
		objfiles = "hostid@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 30 A0 E3 6C D0 4D E2 03 10 A0 E1 A8 00 9F E5 68 30 8D E5 ?? ?? ?? EB 00 50 50 E2 07 00 00 BA 68 10 8D E2 04 20 A0 E3 ?? ?? ?? EB 00 40 A0 E1 05 00 A0 E1 ?? ?? ?? EB 00 00 54 E3 1B 00 00 CA 03 50 8D E2 05 00 A0 E1 40 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 15 00 00 BA 03 30 DD E5 00 00 53 E3 12 00 00 0A 44 40 8D E2 00 10 A0 E3 20 20 A0 E3 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 04 20 A0 E1 00 10 A0 E3 64 30 8D E2 ?? ?? ?? EB 00 00 50 E3 06 00 00 1A 64 00 9D E5 00 00 50 E3 14 30 90 15 04 30 93 15 63 38 A0 11 68 30 8D 15 ?? ?? ?? EB 68 00 9D E5 6C D0 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pathconf_2905c0e71ed892572df104c5d2a639c0 {
	meta:
		aliases = "pathconf"
		size = "316"
		objfiles = "pathconf@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 30 D0 E5 00 00 53 E3 98 D0 4D E2 00 40 A0 E1 03 00 00 1A ?? ?? ?? EB 00 20 E0 E3 02 30 A0 E3 1B 00 00 EA 13 00 51 E3 01 F1 9F 97 15 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 20 A0 E3 28 00 00 EA ?? ?? ?? EB 00 20 E0 E3 16 30 A0 E3 00 30 80 E5 23 00 00 EA 7F 20 A0 E3 21 00 00 EA ?? ?? ?? EB 58 10 8D E2 00 50 A0 E1 04 00 A0 E1 00 40 95 E5 ?? ?? ?? EB 00 00 50 E3 7C 20 9D A5 }
	condition:
		$pattern
}

rule __stdio_READ_4ead8be3268b8f22ebb705c24b648aec {
	meta:
		aliases = "__stdio_READ"
		size = "92"
		objfiles = "_READ@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 30 D0 E5 04 50 13 E2 00 40 A0 E1 00 00 A0 13 30 80 BD 18 00 00 52 E3 02 21 E0 B3 04 00 94 E5 ?? ?? ?? EB 00 00 50 E3 30 80 BD C8 00 20 94 E5 04 20 82 03 08 20 82 13 42 34 A0 01 42 34 A0 11 05 00 A0 11 01 30 C4 05 00 20 C4 05 01 30 C4 15 00 20 C4 15 30 80 BD E8 }
	condition:
		$pattern
}

rule herror_913b88f85c0df5df1897b8bf9fe30358 {
	meta:
		aliases = "__GI_herror, herror"
		size = "120"
		objfiles = "herror@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 50 E2 04 D0 4D E2 03 00 00 0A 00 30 D4 E5 00 00 53 E3 40 50 9F 15 00 00 00 1A 3C 50 9F E5 ?? ?? ?? EB 00 00 90 E5 04 00 50 E3 30 30 9F 95 00 C1 93 97 2C 30 9F E5 2C C0 9F 85 00 00 93 E5 04 20 A0 E1 05 30 A0 E1 20 10 9F E5 00 C0 8D E5 ?? ?? ?? EB 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getpw_2f97cad94975470ed71cca5ed1da59f5 {
	meta:
		aliases = "getpw"
		size = "160"
		objfiles = "getpw@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 51 E2 4D DF 4D E2 04 00 00 1A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 1A 00 00 EA 13 CE 8D E2 45 1F 8D E2 14 20 8D E2 01 3C A0 E3 00 C0 8D E5 ?? ?? ?? EB 00 50 50 E2 11 00 00 1A 1C C1 9D E5 00 C0 8D E5 20 C1 9D E5 04 C0 8D E5 24 C1 9D E5 08 C0 8D E5 28 C1 9D E5 0C C0 8D E5 2C C1 9D E5 14 21 9D E5 04 00 A0 E1 24 10 9F E5 18 31 9D E5 10 C0 8D E5 ?? ?? ?? EB 00 00 50 E3 05 20 A0 A1 00 00 00 AA 00 20 E0 E3 02 00 A0 E1 4D DF 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __negvdi2_4da1150504337ac913def490752e32d1 {
	meta:
		aliases = "__negvdi2"
		size = "84"
		objfiles = "_negvdi2@libgcc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 70 E2 00 50 E1 E2 00 00 51 E3 A5 3F A0 B1 03 00 00 BA 00 00 55 E3 00 30 A0 E3 06 00 00 DA 01 30 A0 E3 FF 30 03 E2 00 00 53 E3 06 00 00 1A 04 00 A0 E1 05 10 A0 E1 30 80 BD E8 F8 FF FF 1A 00 00 54 E3 F6 FF FF 9A F4 FF FF EA ?? ?? ?? EB }
	condition:
		$pattern
}

rule strsep_756e267d856f032968ca1cb0b84659e7 {
	meta:
		aliases = "__GI_strsep, strsep"
		size = "128"
		objfiles = "strsep@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 00 00 54 E3 00 50 A0 E1 18 00 00 0A 00 20 D1 E5 00 00 52 E3 0F 00 00 0A 01 30 D1 E5 00 00 53 E3 09 00 00 1A 00 30 D4 E5 02 00 53 E1 04 00 A0 01 0A 00 00 0A 00 00 53 E3 06 00 00 0A 02 10 A0 E1 01 00 84 E2 ?? ?? ?? EB 04 00 00 EA 04 00 A0 E1 ?? ?? ?? EB 01 00 00 EA 00 00 A0 E3 02 00 00 EA 00 00 50 E3 00 30 A0 13 01 30 C0 14 00 00 85 E5 04 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_u_long_a4de5514a4b53840d67ea5cb6ead75b3 {
	meta:
		aliases = "__GI_xdr_u_long, xdr_u_long"
		size = "112"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 01 00 54 E3 04 D0 4D E2 01 50 A0 E1 04 00 00 0A 0D 00 00 3A 02 00 54 E3 01 00 A0 03 0F 00 00 0A 0D 00 00 EA 04 30 90 E5 0D 10 A0 E1 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 00 30 9D 15 04 00 A0 11 00 30 85 15 05 00 00 1A 03 00 00 EA 04 30 90 E5 0F E0 A0 E1 04 F0 93 E5 00 00 00 EA 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_uint8_t_659695889c89347c38f2c4746e94a5c8 {
	meta:
		aliases = "xdr_uint8_t"
		size = "124"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 01 00 54 E3 04 D0 4D E2 01 50 A0 E1 0C 00 00 0A 03 00 00 3A 02 00 54 E3 01 00 A0 03 12 00 00 0A 10 00 00 EA 00 30 D1 E5 04 10 8D E2 04 30 21 E5 0D 10 A0 E1 04 30 90 E5 0F E0 A0 E1 24 F0 93 E5 09 00 00 EA 04 30 90 E5 0D 10 A0 E1 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 00 30 9D 15 04 00 A0 11 00 30 C5 15 00 00 00 1A 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_int8_t_625c76ebab89e822db918be30af514a1 {
	meta:
		aliases = "xdr_int8_t"
		size = "132"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 01 00 54 E3 04 D0 4D E2 01 50 A0 E1 0E 00 00 0A 03 00 00 3A 02 00 54 E3 01 00 A0 03 14 00 00 0A 12 00 00 EA 00 30 D1 E5 03 3C A0 E1 04 10 8D E2 43 3C A0 E1 04 30 21 E5 0D 10 A0 E1 04 30 90 E5 0F E0 A0 E1 24 F0 93 E5 09 00 00 EA 04 30 90 E5 0D 10 A0 E1 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 00 30 9D 15 04 00 A0 11 00 30 C5 15 00 00 00 1A 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_xdr_bool_a51798d9980192c7d59144822f736572 {
	meta:
		aliases = "xdr_bool, __GI_xdr_bool"
		size = "144"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 01 00 54 E3 04 D0 4D E2 01 50 A0 E1 0E 00 00 0A 03 00 00 3A 02 00 54 E3 01 00 A0 03 17 00 00 0A 15 00 00 EA 00 30 91 E5 04 10 8D E2 00 30 53 E2 01 30 A0 13 04 30 21 E5 0D 10 A0 E1 04 30 90 E5 0F E0 A0 E1 04 F0 93 E5 0C 00 00 EA 04 30 90 E5 0D 10 A0 E1 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 05 00 00 0A 00 30 9D E5 04 00 A0 E1 00 30 53 E2 01 30 A0 13 00 30 85 E5 00 00 00 EA 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __addvdi3_ea5d362a3c56c0e72ffcfacb498b0742 {
	meta:
		aliases = "__addvdi3"
		size = "108"
		objfiles = "_addvdi3@libgcc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 92 E0 01 50 A3 E0 00 00 53 E3 0D 00 00 BA 05 00 51 E1 00 30 A0 E3 06 00 00 DA 01 30 A0 E3 FF 30 03 E2 00 00 53 E3 0D 00 00 1A 04 00 A0 E1 05 10 A0 E1 30 80 BD E8 F8 FF FF 1A 04 00 50 E1 F6 FF FF 9A F4 FF FF EA 01 00 55 E1 00 30 A0 E3 F1 FF FF CA F1 FF FF 1A 00 00 54 E1 EF FF FF 9A ED FF FF EA ?? ?? ?? EB }
	condition:
		$pattern
}

rule uw_advance_context_a079703732f85c6cf9ad203b77f7fc81 {
	meta:
		aliases = "uw_advance_context"
		size = "36"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 00 00 90 E5 01 50 A0 E1 ?? ?? ?? EB 04 00 A0 E1 05 10 A0 E1 30 40 BD E8 F2 FF FF EA }
	condition:
		$pattern
}

rule __GI_regfree_c451c3775b2f258fd2c2862acef7cbcc {
	meta:
		aliases = "regfree, __GI_regfree"
		size = "72"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 00 50 A0 E3 00 00 90 E5 ?? ?? ?? EB 10 00 94 E5 00 50 84 E5 04 50 84 E5 08 50 84 E5 ?? ?? ?? EB 1C 30 D4 E5 08 30 C3 E3 1C 30 C4 E5 10 50 84 E5 14 00 94 E5 ?? ?? ?? EB 14 50 84 E5 30 80 BD E8 }
	condition:
		$pattern
}

rule carg_029674173c670bcb66c0b453e170d6d0 {
	meta:
		aliases = "__GI_carg, carg"
		size = "36"
		objfiles = "carg@libm.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 01 50 A0 E1 02 00 A0 E1 03 10 A0 E1 04 20 A0 E1 05 30 A0 E1 30 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __ieee754_scalb_24cf0dfa2d0ef12f2e9a0c7b74b798b1 {
	meta:
		aliases = "scalb, __ieee754_scalb"
		size = "44"
		objfiles = "e_scalb@libm.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 01 50 A0 E1 02 00 A0 E1 03 10 A0 E1 ?? ?? ?? EB 05 10 A0 E1 00 20 A0 E1 04 00 A0 E1 30 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __subvdi3_28d81423b523131cf18c1658182e2958 {
	meta:
		aliases = "__subvdi3"
		size = "116"
		objfiles = "_subvdi3@libgcc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 01 50 A0 E1 02 40 54 E0 03 50 C5 E0 00 00 53 E3 0D 00 00 BA 01 00 55 E1 00 30 A0 E3 06 00 00 DA 01 30 A0 E3 FF 30 03 E2 00 00 53 E3 0D 00 00 1A 04 00 A0 E1 05 10 A0 E1 30 80 BD E8 F8 FF FF 1A 00 00 54 E1 F6 FF FF 9A F4 FF FF EA 05 00 51 E1 00 30 A0 E3 F1 FF FF CA F1 FF FF 1A 04 00 50 E1 EF FF FF 9A ED FF FF EA ?? ?? ?? EB }
	condition:
		$pattern
}

rule skip_input_bytes_59ef905b464d145dedce5eca338f3fec {
	meta:
		aliases = "skip_input_bytes"
		size = "92"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 01 50 A0 E1 0E 00 00 EA 2C 10 84 E2 0A 00 91 E8 01 30 53 E0 04 00 00 1A 04 00 A0 E1 E2 FF FF EB 00 00 50 E3 06 00 00 1A 30 80 BD E8 03 00 55 E1 05 20 A0 B1 03 20 A0 A1 02 30 81 E0 2C 30 84 E5 05 50 62 E0 00 00 55 E3 EE FF FF CA 01 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule on_exit_3d1e7deadbbaa105dc4c2cfd98ddb9a3 {
	meta:
		aliases = "on_exit"
		size = "48"
		objfiles = "on_exit@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? EB 00 00 50 E3 02 30 A0 13 00 30 80 15 04 40 80 15 08 50 80 15 00 00 E0 03 00 00 A0 13 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_pmap_481f6d833e18cfff8d0eeb193e1619ac {
	meta:
		aliases = "__GI_xdr_pmap, xdr_pmap"
		size = "88"
		objfiles = "pmap_prot@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? EB 00 00 50 E3 0D 00 00 0A 04 00 A0 E1 04 10 85 E2 ?? ?? ?? EB 00 00 50 E3 08 00 00 0A 04 00 A0 E1 08 10 85 E2 ?? ?? ?? EB 00 00 50 E3 03 00 00 0A 04 00 A0 E1 0C 10 85 E2 30 40 BD E8 ?? ?? ?? EA 00 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule daemon_b8712717b4b674003236c48907a3ec46 {
	meta:
		aliases = "daemon"
		size = "180"
		objfiles = "daemon@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? EB 01 00 70 E3 1C 00 00 0A 00 00 50 E3 1E 00 00 0A 00 00 A0 E3 ?? ?? ?? EB 00 00 54 E3 78 00 9F 05 ?? ?? ?? 0B 00 00 55 E3 15 00 00 1A 6C 00 9F E5 02 10 A0 E3 ?? ?? ?? EB 01 00 70 E3 00 40 A0 E1 0F 00 00 0A 05 10 A0 E1 ?? ?? ?? EB 01 10 A0 E3 04 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 02 10 A0 E3 ?? ?? ?? EB 02 00 54 E3 05 00 00 DA 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 30 80 BD E8 00 00 E0 E3 30 80 BD E8 00 00 A0 E3 30 80 BD E8 ?? ?? ?? EB 01 00 70 E3 DF FF FF 1A F7 FF FF EA ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tdestroy_recurse_906340a1d1c1085276def5e4ed3b51c8 {
	meta:
		aliases = "tdestroy_recurse"
		size = "64"
		objfiles = "tdestroy@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 04 00 90 E5 00 00 50 E3 01 50 A0 E1 F9 FF FF 1B 08 00 94 E5 00 00 50 E3 05 10 A0 11 F5 FF FF 1B 00 00 94 E5 0F E0 A0 E1 05 F0 A0 E1 04 00 A0 E1 30 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule logout_c274311fb0fd7d0d3691f6f4ef7141ea {
	meta:
		aliases = "logout"
		size = "184"
		objfiles = "logout@libutil.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 06 DD 4D E2 A0 00 9F E5 ?? ?? ?? EB 01 00 70 E3 00 40 A0 03 21 00 00 0A ?? ?? ?? EB 00 50 A0 E3 04 10 A0 E1 07 30 A0 E3 20 20 A0 E3 08 00 8D E2 00 30 CD E5 01 50 CD E5 ?? ?? ?? EB 0D 00 A0 E1 ?? ?? ?? EB 00 40 50 E2 12 00 00 0A 05 10 A0 E1 20 20 A0 E3 2C 00 84 E2 ?? ?? ?? EB 01 2C A0 E3 05 10 A0 E1 4C 00 84 E2 ?? ?? ?? EB 05 10 A0 E1 55 0F 84 E2 ?? ?? ?? EB 08 30 A0 E3 00 30 C4 E5 01 50 C4 E5 04 00 A0 E1 ?? ?? ?? EB 05 00 50 E1 01 40 A0 13 00 00 00 1A 00 40 A0 E3 ?? ?? ?? EB 04 00 A0 E1 06 DD 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svcudp_destroy_5934d8bc9e8ae327c20a275e37c40114 {
	meta:
		aliases = "svcudp_destroy"
		size = "76"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 30 50 90 E5 ?? ?? ?? EB 00 00 94 E5 ?? ?? ?? EB 0C 30 95 E5 1C 30 93 E5 00 00 53 E3 08 00 85 12 0F E0 A0 11 03 F0 A0 11 2C 00 94 E5 ?? ?? ?? EB 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 30 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __md5_Encode_8606f141d5348c80e1139e684ded1903 {
	meta:
		aliases = "__md5_Encode"
		size = "92"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E3 02 50 A0 E1 04 20 A0 E1 0B 00 00 EA 0C 30 91 E7 04 30 C0 E7 0C 30 91 E7 23 34 A0 E1 01 30 CE E5 0C 30 91 E7 23 38 A0 E1 02 30 CE E5 0C 30 91 E7 23 3C A0 E1 03 30 CE E5 04 40 84 E2 05 00 54 E1 02 C1 A0 E1 00 E0 84 E0 01 20 82 E2 EE FF FF 3A 30 80 BD E8 }
	condition:
		$pattern
}

rule tmpnam_8a6783131948adb0af92489777d87bb3 {
	meta:
		aliases = "tmpnam"
		size = "120"
		objfiles = "tmpnam@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 50 E2 14 D0 4D E2 05 40 A0 11 0D 40 A0 01 00 20 A0 E3 04 00 A0 E1 14 10 A0 E3 02 30 A0 E1 ?? ?? ?? EB 00 00 50 E3 0C 00 00 1A 04 00 A0 E1 03 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 07 00 00 1A 00 00 55 E3 06 00 00 1A 04 10 A0 E1 1C 00 9F E5 14 20 A0 E3 ?? ?? ?? EB 00 50 A0 E1 00 00 00 EA 00 50 A0 E3 05 00 A0 E1 14 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fpathconf_9cf8dc0d7aaa6ee79ec508a4808bdcec {
	meta:
		aliases = "fpathconf"
		size = "316"
		objfiles = "fpathconf@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 50 E2 98 D0 4D E2 03 00 00 AA ?? ?? ?? EB 00 20 E0 E3 09 30 A0 E3 1E 00 00 EA 00 00 51 E3 7F 20 A0 03 40 00 00 0A 01 30 41 E2 12 00 53 E3 03 F1 9F 97 14 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 20 A0 E3 27 00 00 EA ?? ?? ?? EB 00 20 E0 E3 16 30 A0 E3 00 30 80 E5 22 00 00 EA ?? ?? ?? EB 58 10 8D E2 00 40 A0 E1 05 00 A0 E1 00 50 94 E5 ?? ?? ?? EB 00 00 50 E3 7C 20 9D A5 19 00 00 AA }
	condition:
		$pattern
}

rule __pthread_set_own_extricate_if_6c53f5f7d911f8425ea67d96c83575ba {
	meta:
		aliases = "__pthread_set_own_extricate_if"
		size = "68"
		objfiles = "condvar@libpthread.a, oldsemaphore@libpthread.a, semaphore@libpthread.a, join@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 51 E2 00 40 A0 E1 03 00 00 0A 40 30 D0 E5 00 00 53 E3 30 80 BD 18 02 00 00 EA 1C 00 90 E5 04 10 A0 E1 ?? ?? ?? EB 00 00 55 E3 44 51 84 E5 30 80 BD 18 1C 00 94 E5 30 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __GI_xdr_u_short_7e94a2ec36a214087cbfbe13fbd17c15 {
	meta:
		aliases = "xdr_u_short, __GI_xdr_u_short"
		size = "144"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 90 E5 01 00 55 E3 04 D0 4D E2 01 40 A0 E1 0E 00 00 0A 03 00 00 3A 02 00 55 E3 01 00 A0 03 17 00 00 0A 15 00 00 EA 01 20 D1 E5 00 30 D1 E5 04 10 8D E2 02 34 83 E1 04 30 21 E5 0D 10 A0 E1 04 30 90 E5 0F E0 A0 E1 04 F0 93 E5 0C 00 00 EA 04 30 90 E5 0D 10 A0 E1 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 05 00 00 0A 00 20 9D E5 05 00 A0 E1 42 34 A0 E1 01 30 C4 E5 00 20 C4 E5 00 00 00 EA 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_uint16_t_fb213af640c8d1eed7bae8c4a6573590 {
	meta:
		aliases = "xdr_uint16_t"
		size = "144"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 90 E5 01 00 55 E3 04 D0 4D E2 01 40 A0 E1 0E 00 00 0A 03 00 00 3A 02 00 55 E3 01 00 A0 03 17 00 00 0A 15 00 00 EA 01 20 D1 E5 00 30 D1 E5 04 10 8D E2 02 34 83 E1 04 30 21 E5 0D 10 A0 E1 04 30 90 E5 0F E0 A0 E1 24 F0 93 E5 0C 00 00 EA 04 30 90 E5 0D 10 A0 E1 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 05 00 00 0A 00 20 9D E5 05 00 A0 E1 42 34 A0 E1 01 30 C4 E5 00 20 C4 E5 00 00 00 EA 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_xdr_short_aeba2c897fb0c40087a7a52ab4543721 {
	meta:
		aliases = "xdr_short, __GI_xdr_short"
		size = "148"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 90 E5 01 00 55 E3 04 D0 4D E2 01 40 A0 E1 0F 00 00 0A 03 00 00 3A 02 00 55 E3 01 00 A0 03 18 00 00 0A 16 00 00 EA 01 30 D1 E5 00 20 D1 E5 03 3C A0 E1 43 28 82 E1 04 10 8D E2 04 20 21 E5 0D 10 A0 E1 04 30 90 E5 0F E0 A0 E1 04 F0 93 E5 0C 00 00 EA 04 30 90 E5 0D 10 A0 E1 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 05 00 00 0A 00 20 9D E5 05 00 A0 E1 42 34 A0 E1 01 30 C4 E5 00 20 C4 E5 00 00 00 EA 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_int16_t_d4a3065e443000985c54be8e353eff3f {
	meta:
		aliases = "xdr_int16_t"
		size = "148"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 90 E5 01 00 55 E3 04 D0 4D E2 01 40 A0 E1 0F 00 00 0A 03 00 00 3A 02 00 55 E3 01 00 A0 03 18 00 00 0A 16 00 00 EA 01 30 D1 E5 00 20 D1 E5 03 3C A0 E1 43 28 82 E1 04 10 8D E2 04 20 21 E5 0D 10 A0 E1 04 30 90 E5 0F E0 A0 E1 24 F0 93 E5 0C 00 00 EA 04 30 90 E5 0D 10 A0 E1 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 05 00 00 0A 00 20 9D E5 05 00 A0 E1 42 34 A0 E1 01 30 C4 E5 00 20 C4 E5 00 00 00 EA 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_if_freenameindex_e582b144e4be2421604a95f25b75a871 {
	meta:
		aliases = "if_freenameindex, __GI_if_freenameindex"
		size = "60"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 A0 E1 00 40 A0 E1 01 00 00 EA ?? ?? ?? EB 08 40 84 E2 04 30 94 E5 00 00 53 E2 FA FF FF 1A 00 30 94 E5 00 00 53 E3 F7 FF FF 1A 05 00 A0 E1 30 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __old_sem_trywait_dfafe3d759685a4ac6b1e1a292b435f1 {
	meta:
		aliases = "__old_sem_trywait"
		size = "96"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 A0 E1 00 C0 95 E5 01 30 2C E2 01 30 03 E2 01 00 5C E3 03 40 A0 11 01 40 83 03 00 00 54 E3 05 00 A0 E1 0C 10 A0 E1 02 20 4C E2 04 00 00 0A ?? ?? ?? EB 0B 30 A0 E3 00 20 E0 E3 00 30 80 E5 03 00 00 EA EA FF FF EB 00 00 50 E3 EC FF FF 0A 04 20 A0 E1 02 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_rejected_reply_adc36e17bd22f653300b2e7d59f568eb {
	meta:
		aliases = "__GI_xdr_rejected_reply, xdr_rejected_reply"
		size = "108"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 A0 E1 01 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 12 00 00 0A 00 30 94 E5 00 00 53 E3 02 00 00 0A 01 00 53 E3 0D 00 00 1A 08 00 00 EA 05 00 A0 E1 04 10 84 E2 ?? ?? ?? EB 00 00 50 E3 07 00 00 0A 05 00 A0 E1 08 10 84 E2 30 40 BD E8 ?? ?? ?? EA 05 00 A0 E1 04 10 84 E2 30 40 BD E8 ?? ?? ?? EA 00 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_xdr_accepted_reply_a66191477dce273164cdeddaf1581af8 {
	meta:
		aliases = "xdr_accepted_reply, __GI_xdr_accepted_reply"
		size = "136"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 A0 E1 01 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 19 00 00 0A 05 00 A0 E1 0C 10 84 E2 ?? ?? ?? EB 00 00 50 E3 14 00 00 0A 0C 30 94 E5 00 00 53 E3 03 00 00 0A 02 00 53 E3 01 00 A0 13 30 80 BD 18 04 00 00 EA 05 00 A0 E1 10 10 94 E5 0F E0 A0 E1 14 F0 94 E5 30 80 BD E8 05 00 A0 E1 10 10 84 E2 ?? ?? ?? EB 00 00 50 E3 03 00 00 0A 05 00 A0 E1 14 10 84 E2 30 40 BD E8 ?? ?? ?? EA 00 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_opaque_auth_62dfdfd8627a85d888b26643ae2d458e {
	meta:
		aliases = "__GI_xdr_opaque_auth, xdr_opaque_auth"
		size = "48"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 A0 E1 01 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 30 80 BD 08 05 00 A0 E1 08 20 84 E2 04 10 84 E2 19 3E A0 E3 30 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule mempcpy_5bfbebcf423b35f283059b773f8245b5 {
	meta:
		aliases = "__GI_mempcpy, mempcpy"
		size = "24"
		objfiles = "mempcpy@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 A0 E1 02 40 A0 E1 ?? ?? ?? EB 04 00 85 E0 30 80 BD E8 }
	condition:
		$pattern
}

rule flush_out_26a2818497a0b24d0f9133400346b8a7 {
	meta:
		aliases = "flush_out"
		size = "128"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 A0 E1 10 30 95 E5 18 00 90 E5 01 00 51 E3 03 30 60 E0 02 11 A0 03 00 10 A0 13 04 30 43 E2 03 10 81 E1 FF 28 01 E2 21 3C A0 E1 22 34 83 E1 FF 2C 01 E2 02 34 83 E1 01 3C 83 E1 00 30 80 E5 0C 10 85 E2 12 00 91 E8 04 40 61 E0 04 20 A0 E1 00 00 95 E5 0F E0 A0 E1 08 F0 95 E5 04 00 50 E1 0C 20 95 05 00 00 A0 13 04 30 82 02 01 00 A0 03 10 30 85 05 18 20 85 05 30 80 BD E8 }
	condition:
		$pattern
}

rule getlogin_r_a2d1d8f200ab4c52a46d3c5df6672dac {
	meta:
		aliases = "getlogin_r"
		size = "72"
		objfiles = "getlogin@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 A0 E1 34 00 9F E5 01 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 E0 03 30 80 BD 08 00 10 A0 E1 04 20 A0 E1 05 00 A0 E1 ?? ?? ?? EB 00 30 A0 E3 04 20 85 E0 03 00 A0 E1 01 30 42 E5 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_setrpcent_9b957710ef19a63cb6153f1eb06cb80e {
	meta:
		aliases = "setrpcent, __GI_setrpcent"
		size = "96"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 A0 E1 55 FF FF EB 00 40 50 E2 30 80 BD 08 00 00 94 E5 00 00 50 E3 04 00 00 1A 30 00 9F E5 30 10 9F E5 ?? ?? ?? EB 00 00 84 E5 00 00 00 EA ?? ?? ?? EB 04 00 94 E5 ?? ?? ?? EB 0C 30 94 E5 05 30 83 E1 0C 30 84 E5 00 30 A0 E3 04 30 84 E5 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getttynam_1e8ee83e3dc71b9992aed7e7d083ad9a {
	meta:
		aliases = "getttynam"
		size = "60"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 A0 E1 ?? ?? ?? EB 03 00 00 EA 00 10 94 E5 ?? ?? ?? EB 00 00 50 E3 03 00 00 0A ?? ?? ?? EB 00 40 50 E2 05 00 A0 E1 F7 FF FF 1A ?? ?? ?? EB 04 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule getrpcbynumber_e5c7d3be89534491df02d2f5adce206d {
	meta:
		aliases = "__GI_getrpcbynumber, getrpcbynumber"
		size = "72"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 A0 E1 EB FE FF EB 00 00 50 E3 00 40 A0 01 09 00 00 0A 00 00 A0 E3 ?? ?? ?? EB 02 00 00 EA 08 30 94 E5 05 00 53 E1 02 00 00 0A ?? ?? ?? EB 00 40 50 E2 F9 FF FF 1A ?? ?? ?? EB 04 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_vswprintf_aeb34b33fb0c088f86901263f0e11723 {
	meta:
		aliases = "vswprintf, __GI_vswprintf"
		size = "176"
		objfiles = "vswprintf@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 C0 A0 E1 00 00 E0 E1 20 51 A0 E1 50 D0 4D E2 01 00 55 E1 01 50 A0 21 02 10 A0 E1 03 20 A0 E1 02 30 E0 E3 04 30 8D E5 53 30 83 E2 00 E0 A0 E3 05 41 8C E0 00 30 CD E5 0D 00 A0 E1 08 30 A0 E3 01 30 CD E5 20 E0 8D E5 0C 40 8D E5 1C C0 8D E5 02 E0 CD E5 2C E0 8D E5 08 C0 8D E5 10 C0 8D E5 14 C0 8D E5 18 C0 8D E5 ?? ?? ?? EB 10 20 9D E5 0C 30 9D E5 03 00 52 E1 05 00 00 1A 00 00 55 E3 00 00 E0 03 06 00 00 0A 04 30 42 E2 10 30 8D E5 00 00 E0 E3 00 00 55 E3 10 30 9D 15 00 20 A0 13 00 20 83 15 50 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule wcsnrtombs_4e90e15625c4cda09043838c2b2b11a4 {
	meta:
		aliases = "__GI_wcsnrtombs, wcsnrtombs"
		size = "172"
		objfiles = "wcsnrtombs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 00 50 E1 00 00 50 13 10 D0 4D E2 00 E0 A0 E1 01 40 A0 13 05 00 00 1A 00 00 50 E3 0D E0 A0 11 00 40 A0 13 0D E0 A0 01 00 40 A0 01 00 30 E0 03 02 00 53 E1 03 50 A0 31 02 50 A0 21 00 20 91 E5 05 00 A0 E1 0F 00 00 EA 00 30 92 E5 7F 00 53 E3 FF C0 03 E2 04 20 82 E2 04 00 00 9A ?? ?? ?? EB 54 30 A0 E3 00 20 E0 E3 00 30 80 E5 0A 00 00 EA 00 00 5C E3 00 C0 CE E5 0C 20 A0 01 03 00 00 0A 04 E0 8E E0 01 00 40 E2 00 00 50 E3 ED FF FF 1A 0D 00 5E E1 00 20 81 15 05 20 60 E0 02 00 A0 E1 10 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule bsd_signal_8eb5da6d0c80e6548fa23bc1737be9a2 {
	meta:
		aliases = "__GI_signal, signal, bsd_signal"
		size = "164"
		objfiles = "signal@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 00 71 E3 00 00 50 13 28 D0 4D E2 01 30 A0 E1 00 50 A0 E1 00 20 A0 C3 01 20 A0 D3 01 00 00 DA 40 00 50 E3 04 00 00 DA ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 14 00 00 EA 14 40 8D E2 00 10 A0 E1 0C 00 84 E2 14 30 8D E5 24 20 8D E5 20 20 8D E5 ?? ?? ?? EB 05 10 A0 E1 38 00 9F E5 ?? ?? ?? EB 00 00 50 E3 01 32 A0 03 00 30 A0 13 0D 20 A0 E1 04 10 A0 E1 05 00 A0 E1 18 30 8D E5 ?? ?? ?? EB 00 00 50 E3 00 20 9D A5 00 20 E0 B3 02 00 A0 E1 28 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __check_one_fd_e024b12593517c491a6ba3aa4420be42 {
	meta:
		aliases = "__check_one_fd"
		size = "56"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 40 A0 E1 01 10 A0 E3 00 50 A0 E1 ?? ?? ?? EB 01 00 70 E3 30 80 BD 18 04 10 A0 E1 0C 00 9F E5 ?? ?? ?? EB 05 00 50 E1 30 80 BD 08 ?? ?? ?? EB ?? ?? ?? ?? }
	condition:
		$pattern
}

rule readahead_023ddf9ecfd26fdfed3811263c4358f9 {
	meta:
		aliases = "readahead"
		size = "60"
		objfiles = "readahead@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 40 A0 E1 02 50 A0 E1 02 10 A0 E1 04 20 A0 E1 E1 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule lseek64_340e70387a80abeb5e832e91760d7ff8 {
	meta:
		aliases = "__libc_lseek64, __GI_lseek64, lseek64"
		size = "100"
		objfiles = "llseek@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 40 A0 E1 08 D0 4D E2 02 50 A0 E1 02 10 A0 E1 04 20 A0 E1 03 40 A0 E1 0D 30 A0 E1 8C 00 90 EF 01 0A 70 E3 00 40 A0 E1 04 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 20 E0 E3 00 30 80 E5 01 00 00 EA 00 20 50 E2 02 00 00 0A 02 00 A0 E1 C0 1F A0 E1 00 00 00 EA 03 00 9D E8 08 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule significand_af2e204b43b6f898731bc097b196afd1 {
	meta:
		aliases = "significand"
		size = "48"
		objfiles = "s_significand@libm.a"
	strings:
		$pattern = { 30 40 2D E9 01 50 A0 E1 00 40 A0 E1 ?? ?? ?? EB 00 00 60 E2 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 30 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule clntraw_freeres_5dd96a7ce0535761b44bd05c3d88b9ae {
	meta:
		aliases = "clntraw_freeres"
		size = "56"
		objfiles = "clnt_raw@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 50 A0 E1 02 40 A0 E1 ?? ?? ?? EB A0 00 90 E5 00 00 50 E3 10 00 80 02 30 80 BD 08 02 30 A0 E3 0C 30 A0 E5 04 10 A0 E1 0F E0 A0 E1 05 F0 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule svcraw_getargs_fb206f51495a0e828ea9e83225fb9b09 {
	meta:
		aliases = "svcraw_getargs"
		size = "52"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 50 A0 E1 02 40 A0 E1 ?? ?? ?? EB BC 00 90 E5 00 00 50 E3 30 80 BD 08 8E 0D 80 E2 04 10 A0 E1 14 00 80 E2 0F E0 A0 E1 05 F0 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule svcraw_freeargs_13d4e51dd5f9cfeb673e553dc291a357 {
	meta:
		aliases = "svcraw_freeargs"
		size = "72"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 50 A0 E1 02 40 A0 E1 ?? ?? ?? EB BC 10 90 E5 00 00 51 E3 01 00 A0 01 30 80 BD 08 1C 30 9F E5 8E 0D 81 E2 02 20 A0 E3 03 20 81 E7 14 00 80 E2 04 10 A0 E1 0F E0 A0 E1 05 F0 A0 E1 30 80 BD E8 94 23 00 00 }
	condition:
		$pattern
}

rule __GI_fdopen_0ae4fea337a3c0a79fc0a87daaafc7d0 {
	meta:
		aliases = "fdopen, __GI_fdopen"
		size = "56"
		objfiles = "fdopen@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 50 A0 E1 03 10 A0 E3 00 40 A0 E1 ?? ?? ?? EB 01 00 70 E3 04 00 00 0A 05 10 A0 E1 04 30 A0 E1 00 20 A0 E3 30 40 BD E8 ?? ?? ?? EA 00 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule __ether_line_w_9f43788988563ab92a9c175357b9601b {
	meta:
		aliases = "__ether_line_w"
		size = "72"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 50 A0 E1 23 10 A0 E3 00 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 04 00 00 1A 04 00 A0 E1 0A 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 01 00 00 0A 00 30 A0 E3 00 30 C0 E5 04 00 A0 E1 05 10 A0 E1 30 40 BD E8 BA FF FF EA }
	condition:
		$pattern
}

rule svcraw_recv_6c2f8b73c1f2252174b69954408df07e {
	meta:
		aliases = "svcraw_recv"
		size = "96"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 50 A0 E1 ?? ?? ?? EB BC 00 90 E5 00 00 50 E3 30 80 BD 08 3C 30 9F E5 01 20 A0 E3 8E 4D 80 E2 03 20 80 E7 14 40 84 E2 04 30 83 E2 03 30 90 E7 00 10 A0 E3 04 00 A0 E1 0F E0 A0 E1 14 F0 93 E5 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 00 50 E2 01 00 A0 13 30 80 BD E8 94 23 00 00 }
	condition:
		$pattern
}

rule tmpfile_86ca4dc8062f63df82bbbc08d7526f1d {
	meta:
		aliases = "tmpfile64, tmpfile"
		size = "132"
		objfiles = "tmpfile@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 DA 4D E2 10 40 8D E2 0F 40 44 E2 04 00 A0 E1 5C 10 9F E5 00 20 A0 E3 58 30 9F E5 ?? ?? ?? EB 00 00 50 E3 0E 00 00 1A 00 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 50 50 E2 09 00 00 BA 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 2C 10 9F E5 ?? ?? ?? EB 00 40 50 E2 03 00 00 1A 05 00 A0 E1 ?? ?? ?? EB 00 00 00 EA 00 40 A0 E3 04 00 A0 E1 01 DA 8D E2 30 80 BD E8 FF 0F 00 00 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _dl_parse_dynamic_info_805bd45f37fb58db077412f9ab91459c {
	meta:
		aliases = "_dl_parse_dynamic_info"
		size = "296"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 30 40 2D E9 02 40 A0 E1 03 E0 A0 E1 01 20 A0 E3 00 50 A0 E3 27 00 00 EA 21 00 5C E3 19 00 00 CA 04 30 90 E5 0C 31 81 E7 00 30 90 E5 15 00 5C E3 04 40 80 05 18 00 53 E3 00 30 90 E5 60 20 81 05 1E 00 53 E3 02 00 00 1A 04 30 90 E5 08 00 13 E3 60 20 81 15 00 30 90 E5 16 00 53 E3 00 30 90 E5 58 20 81 05 1D 00 53 E3 00 30 90 E5 3C 50 81 05 0F 00 53 E3 0E 00 00 1A 74 30 91 E5 00 00 53 E3 3C 50 81 15 0A 00 00 EA 19 02 7C E3 08 00 00 CA 69 02 7C E3 04 30 90 05 88 30 81 05 00 30 90 E5 59 02 73 E3 02 00 00 1A 04 30 90 E5 01 00 13 E3 60 20 81 15 08 00 80 E2 00 C0 90 E5 00 00 5C E3 D4 FF FF 1A 10 30 91 E5 }
	condition:
		$pattern
}

rule jrand48_r_60a3f9a5c31e465d6f6770a3495a7cb5 {
	meta:
		aliases = "__GI_jrand48_r, jrand48_r"
		size = "68"
		objfiles = "jrand48_r@libc.a"
	strings:
		$pattern = { 30 40 2D E9 02 50 A0 E1 00 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 E0 B3 30 80 BD B8 03 00 D4 E5 04 20 D4 E5 05 10 D4 E5 02 30 D4 E5 01 24 82 E1 00 34 83 E1 02 38 83 E1 00 00 A0 E3 00 30 85 E5 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_nrand48_r_5674055970afc089584ad9e838ba469e {
	meta:
		aliases = "nrand48_r, __GI_nrand48_r"
		size = "72"
		objfiles = "nrand48_r@libc.a"
	strings:
		$pattern = { 30 40 2D E9 02 50 A0 E1 00 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 E0 B3 30 80 BD B8 05 00 D4 E5 04 30 D4 E5 02 20 D4 E5 03 10 D4 E5 00 34 83 E1 01 24 82 E1 83 37 A0 E1 A2 30 83 E1 00 00 A0 E3 00 30 85 E5 30 80 BD E8 }
	condition:
		$pattern
}

rule truncate64_dc3ff77bce79110ed4097a3010ca8e9c {
	meta:
		aliases = "truncate64"
		size = "48"
		objfiles = "truncate64@libc.a"
	strings:
		$pattern = { 30 40 2D E9 02 50 A0 E1 C1 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 30 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_ftruncate64_a2e7b83dad9ddfd7424572c617378cd9 {
	meta:
		aliases = "ftruncate64, __GI_ftruncate64"
		size = "48"
		objfiles = "ftruncate64@libc.a"
	strings:
		$pattern = { 30 40 2D E9 02 50 A0 E1 C2 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 30 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule forkpty_0ac2769a8bb2f4268a42298d5ca7ca4d {
	meta:
		aliases = "forkpty"
		size = "140"
		objfiles = "forkpty@libutil.a"
	strings:
		$pattern = { 30 40 2D E9 02 C0 A0 E1 0C D0 4D E2 00 30 8D E5 01 20 A0 E1 00 50 A0 E1 0C 30 A0 E1 08 00 8D E2 04 10 8D E2 ?? ?? ?? EB 01 00 70 E3 12 00 00 0A ?? ?? ?? EB 01 00 70 E3 00 40 A0 E1 0E 00 00 0A 00 00 50 E3 07 00 00 1A 08 00 9D E5 ?? ?? ?? EB 04 00 9D E5 ?? ?? ?? EB 00 00 50 E3 07 00 00 0A 01 00 A0 E3 ?? ?? ?? EB 08 30 9D E5 00 30 85 E5 04 00 9D E5 ?? ?? ?? EB 00 00 00 EA 00 40 E0 E3 04 00 A0 E1 0C D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_nanosleep_84a9844dcfac7fc79dfc2ed874cb5c15 {
	meta:
		aliases = "nanosleep, __GI_nanosleep"
		size = "68"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 00 40 A0 E1 01 50 A0 E1 01 00 A0 E3 0D 10 A0 E1 ?? ?? ?? EB 05 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 10 A0 E3 00 40 A0 E1 00 00 9D E5 ?? ?? ?? EB 04 00 A0 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_replymsg_b597f0d32228ff0bf6eabf83784f3a8e {
	meta:
		aliases = "__GI_xdr_replymsg, xdr_replymsg"
		size = "108"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 00 50 A0 E1 01 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 0F 00 00 0A 05 00 A0 E1 04 10 84 E2 ?? ?? ?? EB 00 00 50 E3 0A 00 00 0A 04 30 94 E5 01 00 53 E3 07 00 00 1A 00 C0 A0 E3 05 00 A0 E1 0C 20 84 E2 08 10 84 E2 14 30 9F E5 00 C0 8D E5 ?? ?? ?? EB 00 00 00 EA 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule cond_extricate_func_c8345c6f121e2c25dddebe2846f62148 {
	meta:
		aliases = "cond_extricate_func"
		size = "72"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 00 50 A0 E1 01 40 A0 E1 DB FF FF EB 00 00 8D E5 00 10 9D E5 05 00 A0 E1 ?? ?? ?? EB 04 10 A0 E1 08 00 85 E2 83 FF FF EB 00 40 A0 E1 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule new_sem_extricate_func_3ac1df508a939c4a390088bfe5707a0d {
	meta:
		aliases = "new_sem_extricate_func"
		size = "72"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 00 50 A0 E1 01 40 A0 E1 DB FF FF EB 00 00 8D E5 00 10 9D E5 05 00 A0 E1 ?? ?? ?? EB 04 10 A0 E1 0C 00 85 E2 69 FF FF EB 00 40 A0 E1 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule join_extricate_func_597be8529419301e39930629996287d6 {
	meta:
		aliases = "join_extricate_func"
		size = "76"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 00 50 A0 E1 DC FF FF EB 00 00 8D E5 00 10 9D E5 05 00 A0 E1 ?? ?? ?? EB 08 20 95 E5 00 30 A0 E3 38 40 92 E5 05 00 A0 E1 38 30 82 E5 03 40 54 E0 01 40 A0 13 ?? ?? ?? EB 04 00 A0 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule initgroups_f0fa6b742f4d9aa415a308e82294c092 {
	meta:
		aliases = "initgroups"
		size = "76"
		objfiles = "initgroups@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 04 20 8D E2 02 31 E0 E3 04 30 22 E5 0D 20 A0 E1 ?? ?? ?? EB 00 40 50 E2 00 50 E0 03 05 00 00 0A 00 00 9D E5 04 10 A0 E1 ?? ?? ?? EB 00 50 A0 E1 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_fgetgrent_r_e8080a1c2fc51c486b5e54e9e6df8922 {
	meta:
		aliases = "__GI_fgetspent_r, fgetgrent_r, __GI_fgetpwent_r, fgetpwent_r, fgetspent_r, __GI_fgetgrent_r"
		size = "56"
		objfiles = "fgetspent_r@libc.a, fgetpwent_r@libc.a, fgetgrent_r@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 10 50 9D E5 00 00 8D E5 00 00 A0 E3 00 00 85 E5 14 00 9F E5 01 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 40 85 05 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clntudp_destroy_f09dca5ad61f5b2c4599611757602562 {
	meta:
		aliases = "clntudp_destroy"
		size = "72"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { 30 40 2D E9 08 40 90 E5 04 30 94 E5 00 00 53 E3 00 50 A0 E1 00 00 94 15 ?? ?? ?? 1B 3C 30 94 E5 1C 30 93 E5 00 00 53 E3 38 00 84 12 0F E0 A0 11 03 F0 A0 11 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 30 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule clnttcp_destroy_202a9a5ca6e3b0205a59f4296cadf862 {
	meta:
		aliases = "clnttcp_destroy"
		size = "72"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { 30 40 2D E9 08 40 90 E5 04 30 94 E5 00 00 53 E3 00 50 A0 E1 00 00 94 15 ?? ?? ?? 1B 50 30 94 E5 1C 30 93 E5 00 00 53 E3 4C 00 84 12 0F E0 A0 11 03 F0 A0 11 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 30 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule clntunix_destroy_6ed4035c89a768b5aee9e5c8429590d2 {
	meta:
		aliases = "clntunix_destroy"
		size = "72"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { 30 40 2D E9 08 40 90 E5 04 30 94 E5 00 00 53 E3 00 50 A0 E1 00 00 94 15 ?? ?? ?? 1B B0 30 94 E5 1C 30 93 E5 00 00 53 E3 AC 00 84 12 0F E0 A0 11 03 F0 A0 11 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 30 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule sighold_4beeacb0914a6da24b8b06b3291fbcdb {
	meta:
		aliases = "sigrelse, sighold"
		size = "76"
		objfiles = "sighold@libc.a, sigrelse@libc.a"
	strings:
		$pattern = { 30 40 2D E9 08 D0 4D E2 00 40 A0 E1 0D 20 A0 E1 00 10 A0 E3 02 00 A0 E3 ?? ?? ?? EB 0D 00 A0 E1 04 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 0D 50 A0 E1 00 00 E0 B3 0D 10 A0 A1 02 00 A0 A3 00 20 A0 A3 ?? ?? ?? AB 08 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_xdr_authunix_parms_2c81db2f08943685f20edb6d848e8cb0 {
	meta:
		aliases = "xdr_authunix_parms, __GI_xdr_authunix_parms"
		size = "156"
		objfiles = "authunix_prot@libc.a"
	strings:
		$pattern = { 30 40 2D E9 08 D0 4D E2 00 50 A0 E1 01 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 1B 00 00 0A 05 00 A0 E1 04 10 84 E2 FF 20 A0 E3 ?? ?? ?? EB 00 00 50 E3 15 00 00 0A 05 00 A0 E1 08 10 84 E2 ?? ?? ?? EB 00 00 50 E3 10 00 00 0A 05 00 A0 E1 0C 10 84 E2 ?? ?? ?? EB 00 00 50 E3 0B 00 00 0A 04 C0 A0 E3 00 C0 8D E5 2C C0 9F E5 05 00 A0 E1 10 20 84 E2 14 10 84 E2 10 30 A0 E3 04 C0 8D E5 ?? ?? ?? EB 00 00 50 E2 01 00 A0 13 00 00 00 EA 00 00 A0 E3 08 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getrlimit64_4f5d639063fb99c0f7037edd0e5a246e {
	meta:
		aliases = "getrlimit64"
		size = "108"
		objfiles = "getrlimit64@libc.a"
	strings:
		$pattern = { 30 40 2D E9 08 D0 4D E2 01 50 A0 E1 0D 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 E0 B3 10 00 00 BA 00 30 9D E5 01 00 73 E3 00 30 E0 03 00 40 A0 13 00 40 E0 03 18 00 85 E8 04 30 9D E5 01 00 73 E3 00 30 E0 03 00 40 E0 03 00 00 A0 03 08 30 85 05 0C 40 85 05 00 40 A0 13 08 30 85 15 0C 40 85 15 00 00 A0 13 08 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule get_cie_encoding_7d79e25450e40d1f6e9650fae3d645b3 {
	meta:
		aliases = "get_cie_encoding"
		size = "204"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { 30 40 2D E9 09 30 D0 E5 7A 00 53 E3 0C D0 4D E2 00 50 A0 E1 02 00 00 0A 00 00 A0 E3 0C D0 8D E2 30 80 BD E8 09 40 80 E2 04 00 A0 E1 ?? ?? ?? EB 04 00 80 E0 04 40 8D E2 04 10 A0 E1 01 00 80 E2 A6 FD FF EB 0D 10 A0 E1 AE FD FF EB 08 30 D5 E5 01 00 53 E3 01 00 80 02 04 10 A0 11 9F FD FF 1B 04 10 A0 E1 9D FD FF EB 0A 30 D5 E5 52 00 53 E3 00 20 A0 E1 0A 40 85 12 06 00 00 1A 10 00 00 EA 4C 00 53 E3 E3 FF FF 1A 01 30 F4 E5 52 00 53 E3 01 20 82 E2 0A 00 00 0A 50 00 53 E3 F7 FF FF 1A 01 00 D2 E4 08 30 8D E2 7F 00 00 E2 00 10 A0 E3 1D FF FF EB 01 30 F4 E5 52 00 53 E3 00 20 A0 E1 F4 FF FF 1A 00 00 D2 E5 }
	condition:
		$pattern
}

rule sendto_e053056c3c5d6506b1d81dc8dfa56fba {
	meta:
		aliases = "__libc_sendto, __GI_sendto, sendto"
		size = "52"
		objfiles = "sendto@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C 40 8D E2 30 00 94 E8 22 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 30 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule recvfrom_ad0d3dd18cca54fa722ba12b8faff003 {
	meta:
		aliases = "__GI_recvfrom, __libc_recvfrom, recvfrom"
		size = "52"
		objfiles = "recvfrom@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C 40 8D E2 30 00 94 E8 24 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 30 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule splice_c25fd5ded04ca549e120ed7fb5b0d8fb {
	meta:
		aliases = "splice"
		size = "52"
		objfiles = "splice@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C 40 8D E2 30 00 94 E8 54 01 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 30 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule __syscall_ipc_1761a53874dab6f14aa55cdaec2ff389 {
	meta:
		aliases = "__syscall_ipc"
		size = "52"
		objfiles = "__syscall_ipc@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C 40 8D E2 30 00 94 E8 75 00 90 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 30 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule xdrrec_getpos_84044d050cac72398e13749091146d64 {
	meta:
		aliases = "xdrrec_getpos"
		size = "104"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C 40 90 E5 00 50 A0 E1 00 10 A0 E3 00 00 94 E5 01 20 A0 E3 ?? ?? ?? EB 01 00 70 E3 30 80 BD 08 00 30 95 E5 00 00 53 E3 03 00 00 0A 01 00 53 E3 00 00 E0 13 30 80 BD 18 04 00 00 EA 10 20 84 E2 0C 00 12 E8 02 30 43 E0 00 00 83 E0 30 80 BD E8 30 20 84 E2 0C 00 12 E8 02 30 43 E0 00 00 63 E0 30 80 BD E8 }
	condition:
		$pattern
}

rule xdrrec_skiprecord_8b65d79471847b92df57cd40e02af64e {
	meta:
		aliases = "__GI_xdrrec_skiprecord, xdrrec_skiprecord"
		size = "112"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C 40 90 E5 00 50 A0 E3 0A 00 00 EA 2E FF FF EB 00 00 50 E3 12 00 00 0A 38 30 94 E5 00 00 53 E3 34 50 84 E5 03 00 00 1A 04 00 A0 E1 BA FF FF EB 00 00 50 E3 0A 00 00 0A 34 30 94 E5 00 10 53 E2 04 00 A0 E1 F0 FF FF CA 38 30 94 E5 00 00 53 E3 ED FF FF 0A 00 30 A0 E3 01 00 A0 E3 38 30 84 E5 30 80 BD E8 00 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_xdrrec_eof_4024b23a0a0bf52f5fe8f269f18d0557 {
	meta:
		aliases = "xdrrec_eof, __GI_xdrrec_eof"
		size = "120"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C 40 90 E5 00 50 A0 E3 0A 00 00 EA 4C FF FF EB 00 00 50 E3 14 00 00 0A 38 30 94 E5 00 00 53 E3 34 50 84 E5 03 00 00 1A 04 00 A0 E1 D8 FF FF EB 00 00 50 E3 0C 00 00 0A 34 30 94 E5 00 10 53 E2 04 00 A0 E1 F0 FF FF CA 38 30 94 E5 00 00 53 E3 ED FF FF 0A 30 20 94 E5 2C 30 94 E5 02 00 53 E1 00 00 A0 13 01 00 A0 03 30 80 BD E8 01 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule xdrrec_putint32_1e9ee12bb1a1f9f75516f3a75057d7c7 {
	meta:
		aliases = "xdrrec_putint32"
		size = "120"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C 40 90 E5 10 00 84 E2 09 00 90 E8 04 20 80 E2 03 00 52 E1 01 50 A0 E1 10 20 84 E5 0A 00 00 9A 01 30 A0 E3 10 00 84 E5 1C 30 84 E5 04 00 A0 E1 00 10 A0 E3 AF FF FF EB 00 00 50 E3 30 80 BD 08 10 00 94 E5 04 30 80 E2 10 30 84 E5 00 10 95 E5 FF 28 01 E2 21 3C A0 E1 22 34 83 E1 FF 2C 01 E2 02 34 83 E1 01 3C 83 E1 00 30 80 E5 01 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule binary_search_unencoded_fdes_8c1a991548ce91a5d5e1491fae2bda77 {
	meta:
		aliases = "binary_search_unencoded_fdes"
		size = "100"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { 30 40 2D E9 0C 50 90 E5 04 E0 95 E5 00 00 5E E3 01 40 A0 E1 10 00 00 0A 00 10 A0 E3 0E 20 81 E0 A2 C0 A0 E1 0C 31 A0 E1 05 30 83 E0 08 00 93 E5 08 20 80 E2 0C 00 92 E8 04 00 52 E1 0C E0 A0 81 03 20 82 E0 02 00 00 8A 02 00 54 E1 30 80 BD 38 01 10 8C E2 0E 00 51 E1 EF FF FF 3A 00 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule getservbyname_1e5adfa518ca1dce96d2b403ca3d3f24 {
	meta:
		aliases = "getservbyname"
		size = "84"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C D0 4D E2 00 40 A0 E1 01 50 A0 E1 63 FE FF EB 2C C0 9F E5 2C 30 9F E5 04 00 A0 E1 00 30 93 E5 05 10 A0 E1 00 C0 8D E5 1C 20 9F E5 08 C0 8D E2 04 C0 8D E5 ?? ?? ?? EB 08 00 9D E5 0C D0 8D E2 30 80 BD E8 8D 10 00 00 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_getservbyport_eeb9756b126cd751cf15777f2f4a0edd {
	meta:
		aliases = "getservbyport, __GI_getservbyport"
		size = "84"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C D0 4D E2 00 40 A0 E1 01 50 A0 E1 C1 FE FF EB 2C C0 9F E5 2C 30 9F E5 04 00 A0 E1 00 30 93 E5 05 10 A0 E1 00 C0 8D E5 1C 20 9F E5 08 C0 8D E2 04 C0 8D E5 ?? ?? ?? EB 08 00 9D E5 0C D0 8D E2 30 80 BD E8 8D 10 00 00 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __new_sem_wait_cf39f27643025fb8e82eed39944b0666 {
	meta:
		aliases = "sem_wait, __new_sem_wait"
		size = "320"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 0C D0 4D E2 00 40 A0 E1 5C FF FF EB 24 31 9F E5 08 00 8D E5 08 10 9D E5 04 00 A0 E1 04 30 8D E5 00 40 8D E5 ?? ?? ?? EB 08 30 94 E5 00 00 53 E3 04 00 00 DA 01 30 43 E2 08 30 84 E5 04 00 A0 E1 ?? ?? ?? EB 38 00 00 EA 08 20 9D E5 00 30 A0 E3 42 31 C2 E5 08 00 9D E5 0D 10 A0 E1 F0 FE FF EB 08 30 9D E5 42 30 D3 E5 00 00 53 E3 04 00 00 0A 08 30 9D E5 40 30 D3 E5 00 00 53 E3 01 50 A0 03 03 00 00 0A 08 10 9D E5 0C 00 84 E2 C4 FE FF EB 00 50 A0 E3 04 00 A0 E1 ?? ?? ?? EB 00 00 55 E3 03 00 00 0A 08 00 9D E5 00 10 A0 E3 DC FE FF EB 1A 00 00 EA 08 00 9D E5 61 FF FF EB 08 30 9D E5 42 31 D3 E5 }
	condition:
		$pattern
}

rule __GI_putc_unlocked_5e36d1201230a94a099b0e739248355a {
	meta:
		aliases = "putc_unlocked, __GI___fputc_unlocked, __fputc_unlocked, __GI_fputc_unlocked, fputc_unlocked, __GI_putc_unlocked"
		size = "260"
		objfiles = "fputc_unlocked@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 20 91 E5 1C 30 91 E5 03 00 52 E1 04 D0 4D E2 01 40 A0 E1 00 50 A0 E1 FF 30 00 32 01 30 C2 34 03 00 A0 31 10 20 81 35 32 00 00 3A 00 30 D1 E5 C0 30 03 E2 C0 00 53 E3 04 00 00 0A 01 00 A0 E1 80 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 28 00 00 1A 04 30 94 E5 02 00 73 E3 23 00 00 0A 0C 20 94 E5 08 30 94 E5 03 00 52 E1 18 00 00 0A 10 30 94 E5 03 00 52 E1 03 00 00 1A 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 1A 00 00 1A 10 20 94 E5 FF 10 05 E2 01 10 C2 E4 01 30 D4 E5 01 00 13 E3 10 20 84 E5 11 00 00 0A 0A 00 51 E3 0F 00 00 1A 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 0B 00 00 0A 10 30 94 E5 00 00 E0 E3 }
	condition:
		$pattern
}

rule mmap_90990db10d5110ca04d4a68bb831bcc9 {
	meta:
		aliases = "__GI_mmap, mmap"
		size = "96"
		objfiles = "mmap@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 50 9D E5 05 CA A0 E1 2C CA A0 E1 00 00 5C E3 04 00 00 0A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 0A 00 00 EA 0C 40 9D E5 25 56 A0 E1 C0 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 20 A0 E1 02 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule mmap64_fb1af78aaf5ca9b3df157b71e1b0090b {
	meta:
		aliases = "mmap64"
		size = "104"
		objfiles = "mmap64@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 50 9D E5 0C 40 9D E5 05 CA B0 E1 10 00 00 1A 14 C0 9D E5 25 56 A0 E1 0C 5A 85 E1 2C C6 B0 E1 0B 00 00 1A 00 C0 A0 E1 C0 00 90 EF 01 0A 70 E3 30 80 BD 38 26 00 70 E3 30 40 BD 18 07 00 00 1A 14 50 9D E5 0C 00 A0 E1 00 00 35 E3 30 40 BD 08 ?? ?? ?? 0A 15 00 E0 E3 30 40 BD E8 FF FF FF EA ?? ?? ?? EA }
	condition:
		$pattern
}

rule getutline_171dd9d3299f9b8c7c752d7b44a51947 {
	meta:
		aliases = "getutline"
		size = "164"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 D0 4D E2 00 40 A0 E1 7C 10 9F E5 0D 00 A0 E1 78 20 9F E5 78 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 68 00 9F E5 6C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 08 50 84 E2 09 00 00 EA 00 30 94 E5 06 30 43 E2 03 38 A0 E1 01 08 53 E3 04 00 00 8A 08 00 84 E2 05 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 02 00 00 0A 21 FF FF EB 00 40 50 E2 F2 FF FF 1A 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pututline_62ff22f8a8fb084eb16c0ad23d828cda {
	meta:
		aliases = "pututline"
		size = "196"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 D0 4D E2 00 40 A0 E1 94 50 9F E5 94 10 9F E5 94 20 9F E5 0D 00 A0 E1 90 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 88 30 9F E5 7C 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 01 20 A0 E3 78 10 9F E5 00 00 95 E5 ?? ?? ?? EB 04 00 A0 E1 C5 FF FF EB 00 10 50 E2 60 10 9F 15 01 20 A0 13 02 20 A0 03 00 00 95 15 00 00 95 05 ?? ?? ?? EB 34 30 9F E5 04 10 A0 E1 06 2D A0 E3 00 00 93 E5 ?? ?? ?? EB 01 10 A0 E3 06 0D 50 E3 30 30 9F E5 0D 00 A0 E1 00 40 A0 13 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 FE FF FF ?? ?? ?? ?? }
	condition:
		$pattern
}

rule gethostbyname2_160ec223c9c4d79064784e46f5ba03a9 {
	meta:
		aliases = "__GI_gethostbyname2, gethostbyname2"
		size = "80"
		objfiles = "gethostbyname2@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 D0 4D E2 00 50 A0 E1 01 40 A0 E1 ?? ?? ?? EB 76 CF A0 E3 08 00 8D E5 00 C0 8D E5 04 10 A0 E1 0C C0 8D E2 05 00 A0 E1 14 20 9F E5 14 30 9F E5 04 C0 8D E5 ?? ?? ?? EB 0C 00 9D E5 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule endutent_e96c1de88d76a3f83141eb069c13ecd4 {
	meta:
		aliases = "endutent"
		size = "128"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 D0 4D E2 0D 00 A0 E1 54 10 9F E5 54 20 9F E5 54 30 9F E5 54 40 9F E5 0F E0 A0 E1 03 F0 A0 E1 40 00 9F E5 48 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 94 E5 00 00 50 E3 0D 50 A0 E1 ?? ?? ?? AB 00 30 E0 E3 00 30 84 E5 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule endgrent_0fda5d4abe92cf31284053aff3167d76 {
	meta:
		aliases = "endpwent, endspent, endgrent"
		size = "132"
		objfiles = "getgrent_r@libc.a, getspent_r@libc.a, getpwent_r@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 D0 4D E2 0D 00 A0 E1 58 10 9F E5 58 20 9F E5 58 30 9F E5 58 40 9F E5 0F E0 A0 E1 03 F0 A0 E1 44 00 9F E5 4C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 94 E5 00 00 50 E3 0D 50 A0 E1 02 00 00 0A ?? ?? ?? EB 00 30 A0 E3 00 30 84 E5 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_endprotoent_c3462f56f9929520ab241c1eb9066968 {
	meta:
		aliases = "endnetent, __GI_endnetent, endservent, __GI_endservent, endprotoent, __GI_endprotoent"
		size = "148"
		objfiles = "getnetent@libc.a, getproto@libc.a, getservice@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 D0 4D E2 0D 00 A0 E1 64 10 9F E5 64 20 9F E5 64 30 9F E5 64 40 9F E5 0F E0 A0 E1 03 F0 A0 E1 50 00 9F E5 58 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 94 E5 00 00 50 E3 0D 50 A0 E1 02 00 00 0A ?? ?? ?? EB 00 30 A0 E3 00 30 84 E5 34 20 9F E5 00 30 A0 E3 00 30 82 E5 0D 00 A0 E1 01 10 A0 E3 24 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule setprotoent_4fac06ced0537d7c958ab606f1f198e7 {
	meta:
		aliases = "__GI_setservent, setservent, __GI_setnetent, setnetent, __GI_setprotoent, setprotoent"
		size = "172"
		objfiles = "getnetent@libc.a, getproto@libc.a, getservice@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 D0 4D E2 78 10 9F E5 78 20 9F E5 78 30 9F E5 00 50 A0 E1 74 40 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 5C 00 9F E5 64 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 94 E5 00 00 50 E3 04 00 00 1A 50 00 9F E5 50 10 9F E5 ?? ?? ?? EB 00 00 84 E5 00 00 00 EA ?? ?? ?? EB 00 00 55 E3 3C 30 9F 15 01 20 A0 13 00 20 83 15 0D 00 A0 E1 01 10 A0 E3 2C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getmntent_5d1bdfda1524d5b1f4c2262d8098015e {
	meta:
		aliases = "getmntent"
		size = "176"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 D0 4D E2 84 10 9F E5 84 20 9F E5 84 30 9F E5 00 50 A0 E1 80 40 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 74 30 9F E5 64 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 94 E5 00 00 53 E3 04 00 00 1A 01 0A A0 E3 ?? ?? ?? EB 00 00 50 E3 00 00 84 E5 ?? ?? ?? 0B 40 30 9F E5 05 00 A0 E1 00 20 93 E5 3C 10 9F E5 01 3A A0 E3 ?? ?? ?? EB 01 10 A0 E3 00 40 A0 E1 2C 30 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mallopt_3a057a030782cd7c34fd0aa4a86b67af {
	meta:
		aliases = "mallopt"
		size = "292"
		objfiles = "mallopt@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 D0 4D E2 FC 20 9F E5 00 40 A0 E1 F8 30 9F E5 0D 00 A0 E1 01 50 A0 E1 F0 10 9F E5 0F E0 A0 E1 03 F0 A0 E1 E8 30 9F E5 D8 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 40 84 E2 D8 00 9F E5 ?? ?? ?? EB 05 00 54 E3 04 F1 9F 97 25 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 00 55 E3 1D 00 00 8A 00 00 55 E3 08 10 A0 03 03 00 00 0A 0B 10 85 E2 0F 00 51 E3 10 10 A0 93 07 10 C1 83 88 20 9F E5 00 30 92 E5 03 30 03 E2 03 30 81 E1 01 40 A0 E3 00 30 82 E5 10 00 00 EA 6C 30 9F E5 01 40 A0 E3 44 53 83 E5 0C 00 00 EA 5C 30 9F E5 01 40 A0 E3 48 53 83 E5 08 00 00 EA }
	condition:
		$pattern
}

rule xdrmem_putbytes_0e822c62bd49fdec854526521b030dc9 {
	meta:
		aliases = "xdrmem_putbytes"
		size = "64"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { 30 40 2D E9 14 30 90 E5 02 00 53 E1 00 40 A0 E1 02 50 A0 E1 00 00 A0 33 30 80 BD 38 03 30 62 E0 14 30 84 E5 0C 00 94 E5 ?? ?? ?? EB 0C 30 94 E5 01 00 A0 E3 05 30 83 E0 0C 30 84 E5 30 80 BD E8 }
	condition:
		$pattern
}

rule xdrmem_getbytes_0739ae53bb67deffcd73e5764050b2a3 {
	meta:
		aliases = "xdrmem_getbytes"
		size = "68"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { 30 40 2D E9 14 30 90 E5 02 00 53 E1 00 40 A0 E1 02 50 A0 E1 01 00 A0 E1 00 00 A0 33 30 80 BD 38 03 30 62 E0 14 30 84 E5 0C 10 94 E5 ?? ?? ?? EB 0C 30 94 E5 01 00 A0 E3 05 30 83 E0 0C 30 84 E5 30 80 BD E8 }
	condition:
		$pattern
}

rule sigignore_06d5a5b431cb002ac90a317da4c8aa35 {
	meta:
		aliases = "sigignore"
		size = "64"
		objfiles = "sigignore@libc.a"
	strings:
		$pattern = { 30 40 2D E9 14 D0 4D E2 00 50 A0 E1 00 10 A0 E3 14 20 A0 E3 0D 00 A0 E1 ?? ?? ?? EB 01 30 A0 E3 05 00 A0 E1 0D 10 A0 E1 00 20 A0 E3 0D 40 A0 E1 00 30 8D E5 ?? ?? ?? EB 14 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule siginterrupt_0f8ceffb939a664bab193a91f7c928d8 {
	meta:
		aliases = "siginterrupt"
		size = "124"
		objfiles = "sigintr@libc.a"
	strings:
		$pattern = { 30 40 2D E9 14 D0 4D E2 01 50 A0 E1 0D 20 A0 E1 00 10 A0 E3 00 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 E0 B3 11 00 00 BA 00 00 55 E3 05 00 00 0A 40 00 9F E5 04 10 A0 E1 ?? ?? ?? EB 04 30 9D E5 01 32 C3 E3 04 00 00 EA 28 00 9F E5 04 10 A0 E1 ?? ?? ?? EB 04 30 9D E5 01 32 83 E3 04 00 A0 E1 0D 10 A0 E1 00 20 A0 E3 04 30 8D E5 ?? ?? ?? EB 14 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pclose_6399b72e97e832340448ea672e588d66 {
	meta:
		aliases = "pclose"
		size = "252"
		objfiles = "popen@libc.a"
	strings:
		$pattern = { 30 40 2D E9 14 D0 4D E2 D4 20 9F E5 D4 10 9F E5 D4 30 9F E5 00 50 A0 E1 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 B8 00 9F E5 C0 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 B8 20 9F E5 00 40 92 E5 00 00 54 E3 0C 00 00 0A 04 30 94 E5 05 00 53 E1 07 00 00 0A 04 20 A0 E1 00 40 94 E5 00 00 54 E3 F8 FF FF 1A ?? ?? ?? EB 16 30 A0 E3 00 30 80 E5 01 00 00 EA 00 30 94 E5 00 30 82 E5 0D 00 A0 E1 01 10 A0 E3 70 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 54 E3 10 00 00 0A 04 00 A0 E1 08 40 94 E5 ?? ?? ?? EB 05 00 A0 E1 ?? ?? ?? EB 10 50 8D E2 05 10 A0 E1 00 20 A0 E3 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 10 00 9D A5 04 00 00 AA }
	condition:
		$pattern
}

rule _ppfs_prepargs_5c98cf9ead0f6ef0cea54f649a9fe64d {
	meta:
		aliases = "_ppfs_prepargs"
		size = "56"
		objfiles = "_ppfs_prepargs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 18 50 90 E5 00 00 55 E3 00 40 A0 E1 4C 10 80 E5 30 80 BD D8 00 30 A0 E3 08 30 80 E5 1C 50 80 E5 18 30 80 E5 04 30 80 E5 ?? ?? ?? EB 18 50 84 E5 30 80 BD E8 }
	condition:
		$pattern
}

rule malloc_trim_5e993a4b138d93cac96b2be39fb8de95 {
	meta:
		aliases = "malloc_trim"
		size = "40"
		objfiles = "free@libc.a"
	strings:
		$pattern = { 30 40 2D E9 18 50 9F E5 00 40 A0 E1 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 05 10 A0 E1 30 40 BD E8 E1 FE FF EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _create_xid_15e15170f8e704afbf394cf31e19f8fb {
	meta:
		aliases = "_create_xid"
		size = "176"
		objfiles = "create_xid@libc.a"
	strings:
		$pattern = { 30 40 2D E9 1C D0 4D E2 84 10 9F E5 0D 00 A0 E1 80 20 9F E5 80 30 9F E5 80 40 9F E5 0F E0 A0 E1 03 F0 A0 E1 6C 00 9F E5 74 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 10 94 E5 00 00 51 E3 0D 50 A0 E1 08 00 00 1A 10 00 8D E2 ?? ?? ?? EB 10 00 8D E2 09 00 90 E8 4C 10 9F E5 00 00 23 E0 ?? ?? ?? EB 01 30 A0 E3 00 30 84 E5 18 10 8D E2 34 00 9F E5 ?? ?? ?? EB 0D 00 A0 E1 01 10 A0 E3 28 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 18 00 9D E5 1C D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule firstwhite_c756f922bdbe84cce05461bdca30f0f7 {
	meta:
		aliases = "firstwhite"
		size = "68"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 20 10 A0 E3 00 40 A0 E1 ?? ?? ?? EB 09 10 A0 E3 00 50 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 00 55 E3 00 50 A0 01 03 00 00 0A 00 00 50 E3 01 00 00 0A 00 00 55 E1 00 50 A0 21 05 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule svc_sendreply_6b38662d8c38e1751cf68f4dbb2659a3 {
	meta:
		aliases = "__GI_svc_sendreply, svc_sendreply"
		size = "92"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { 30 40 2D E9 20 30 80 E2 30 D0 4D E2 00 C0 A0 E1 01 50 A0 E1 02 40 A0 E1 07 00 93 E8 0C 30 8D E2 07 00 83 E8 00 E0 A0 E3 01 30 A0 E3 04 30 8D E5 18 E0 8D E5 1C 40 8D E5 20 50 8D E5 08 E0 8D E5 0C 00 A0 E1 08 30 9C E5 0D 10 A0 E1 0F E0 A0 E1 0C F0 93 E5 30 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule authunix_destroy_1527aba37eb669652a75a48875283730 {
	meta:
		aliases = "authunix_destroy"
		size = "64"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { 30 40 2D E9 24 40 90 E5 00 50 A0 E1 04 00 94 E5 ?? ?? ?? EB 10 00 94 E5 00 00 50 E3 ?? ?? ?? 1B 24 00 95 E5 ?? ?? ?? EB 10 00 95 E5 00 00 50 E3 ?? ?? ?? 1B 05 00 A0 E1 30 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule valloc_8f4e9e4e0b4a2e5698446910ce03ffb1 {
	meta:
		aliases = "valloc"
		size = "52"
		objfiles = "valloc@libc.a"
	strings:
		$pattern = { 30 40 2D E9 24 40 9F E5 00 30 94 E5 00 00 53 E3 00 50 A0 E1 01 00 00 1A ?? ?? ?? EB 00 00 84 E5 00 00 94 E5 05 10 A0 E1 30 40 BD E8 ?? ?? ?? EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wait_node_free_2cb37cbd3a68996d7ae7b91e3906d15f {
	meta:
		aliases = "wait_node_free"
		size = "56"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 24 40 9F E5 00 50 A0 E1 04 00 A0 E1 E0 FF FF EB 18 30 9F E5 00 20 93 E5 00 50 83 E5 00 20 85 E5 00 30 A0 E3 00 30 84 E5 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svcunix_reply_b4dfbb35217dd35e9cc6627a5f2cb9e2 {
	meta:
		aliases = "svctcp_reply, svcunix_reply"
		size = "60"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { 30 40 2D E9 2C 30 90 E5 04 00 93 E5 08 50 83 E2 00 20 A0 E3 08 20 83 E5 00 00 81 E5 05 00 A0 E1 ?? ?? ?? EB 01 10 A0 E3 00 40 A0 E1 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule fill_input_buf_00d9d2aebc4a68f08cd1b074c8429c48 {
	meta:
		aliases = "fill_input_buf"
		size = "76"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 30 40 2D E9 30 20 90 E5 28 10 90 E5 24 30 90 E5 03 20 02 E2 02 50 81 E0 00 40 A0 E1 03 20 62 E0 05 10 A0 E1 00 00 90 E5 0F E0 A0 E1 20 F0 94 E5 01 00 70 E3 00 30 85 10 01 00 80 02 01 00 A0 13 30 30 84 15 2C 50 84 15 30 80 BD E8 }
	condition:
		$pattern
}

rule timegm_f4cbb9cf7a4f28a9817e190a23d48e2d {
	meta:
		aliases = "timegm"
		size = "72"
		objfiles = "timegm@libc.a"
	strings:
		$pattern = { 30 40 2D E9 30 D0 4D E2 00 50 A0 E1 30 20 A0 E3 00 10 A0 E3 0D 00 A0 E1 ?? ?? ?? EB 20 10 9F E5 10 00 8D E2 ?? ?? ?? EB 05 00 A0 E1 0D 20 A0 E1 01 10 A0 E3 0D 40 A0 E1 ?? ?? ?? EB 30 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getc_9fcc99d35dfa90724fd2f7a2296cbe78 {
	meta:
		aliases = "fgetc, __GI_fgetc, getc"
		size = "188"
		objfiles = "fgetc@libc.a"
	strings:
		$pattern = { 30 40 2D E9 34 30 90 E5 00 00 53 E3 10 D0 4D E2 00 50 A0 E1 08 00 00 0A 10 20 90 E5 18 30 90 E5 03 00 52 E1 01 40 D2 34 10 20 80 35 1B 00 00 3A ?? ?? ?? EB 00 40 A0 E1 18 00 00 EA 38 40 80 E2 04 20 A0 E1 60 10 9F E5 0D 00 A0 E1 5C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 50 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 10 20 95 E5 18 30 95 E5 03 00 52 E1 01 40 D2 34 10 20 85 35 02 00 00 3A 05 00 A0 E1 ?? ?? ?? EB 00 40 A0 E1 0D 00 A0 E1 01 10 A0 E3 1C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_once_cancelhandler_211171878760a7212989c90f1398bfb8 {
	meta:
		aliases = "pthread_once_cancelhandler"
		size = "80"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 34 40 9F E5 00 50 A0 E1 30 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 00 30 A0 E3 00 30 85 E5 04 00 A0 E1 18 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 10 00 9F E5 30 40 BD E8 ?? ?? ?? EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule usleep_0e52698ff42da7fbaab0d4263d7b34b6 {
	meta:
		aliases = "usleep"
		size = "76"
		objfiles = "usleep@libc.a"
	strings:
		$pattern = { 30 40 2D E9 3C 40 9F E5 08 D0 4D E2 04 10 A0 E1 00 50 A0 E1 ?? ?? ?? EB 04 10 A0 E1 00 00 8D E5 05 00 A0 E1 ?? ?? ?? EB FA 3F A0 E3 90 03 03 E0 00 10 A0 E3 0D 00 A0 E1 04 30 8D E5 ?? ?? ?? EB 08 D0 8D E2 30 80 BD E8 40 42 0F 00 }
	condition:
		$pattern
}

rule __GI_endrpcent_f154f94cc9e53ef5fab24d949804ebdb {
	meta:
		aliases = "endrpcent, __GI_endrpcent"
		size = "64"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 3E FF FF EB 00 40 50 E2 30 80 BD 08 0C 50 94 E5 00 00 55 E3 30 80 BD 18 04 00 94 E5 ?? ?? ?? EB 00 00 94 E5 00 00 50 E3 04 50 84 E5 30 80 BD 08 ?? ?? ?? EB 00 50 84 E5 30 80 BD E8 }
	condition:
		$pattern
}

rule __uc_malloc_25b99c5494c264f094686c7752d8b410 {
	meta:
		aliases = "__GI___uc_malloc, __uc_malloc"
		size = "80"
		objfiles = "__uc_malloc@libc.a"
	strings:
		$pattern = { 30 40 2D E9 40 50 9F E5 00 40 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 30 50 E2 01 30 A0 13 00 00 54 E3 01 30 83 03 00 00 53 E3 30 80 BD 18 00 30 95 E5 00 00 53 E3 01 00 A0 03 ?? ?? ?? 0B 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 EF FF FF EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sbrk_2b121848a5ad4dd61e0892184f20528d {
	meta:
		aliases = "__GI_sbrk, sbrk"
		size = "88"
		objfiles = "sbrk@libc.a"
	strings:
		$pattern = { 30 40 2D E9 48 40 9F E5 00 30 94 E5 00 00 53 E3 00 50 A0 E1 03 00 00 1A 03 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 07 00 00 BA 00 00 55 E3 00 40 94 05 05 00 00 0A 00 40 94 E5 05 00 84 E0 ?? ?? ?? EB 00 00 50 E3 00 00 00 AA 00 40 E0 E3 04 00 A0 E1 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __md5_Final_55090f6b0fc3bd7ca5acbbb3c82b0f6b {
	meta:
		aliases = "__md5_Final"
		size = "148"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { 30 40 2D E9 48 D0 4D E2 01 40 A0 E1 00 50 A0 E1 00 10 A0 E3 40 20 A0 E3 0D 00 A0 E1 ?? ?? ?? EB 40 00 8D E2 10 10 84 E2 7F 30 E0 E3 08 20 A0 E3 00 30 CD E5 2E FF FF EB 10 30 94 E5 A3 31 A0 E1 3F 20 03 E2 37 00 52 E3 38 20 62 92 78 20 62 82 0D 10 A0 E1 04 00 A0 E1 BC FF FF EB 04 00 A0 E1 40 10 8D E2 08 20 A0 E3 B8 FF FF EB 05 00 A0 E1 04 10 A0 E1 10 20 A0 E3 1D FF FF EB 04 00 A0 E1 00 10 A0 E3 58 20 A0 E3 ?? ?? ?? EB 48 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_manager_adjust_prio_e5d0c37ab438ad109c31400f737a1533 {
	meta:
		aliases = "__pthread_manager_adjust_prio"
		size = "92"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 4C 30 9F E5 18 30 93 E5 03 00 50 E1 04 D0 4D E2 00 50 A0 E1 0C 00 00 DA 01 00 A0 E3 ?? ?? ?? EB 2C 40 9F E5 00 00 55 E1 04 20 8D E2 05 30 A0 A1 01 30 85 B2 04 30 22 E5 14 00 94 E5 0D 20 A0 E1 01 10 A0 E3 ?? ?? ?? EB 18 50 84 E5 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_setutent_f453c9aa07ef1c2622ef5e8c186e98f6 {
	meta:
		aliases = "setutent, __GI_setutent"
		size = "108"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 4C 40 9F E5 10 D0 4D E2 48 10 9F E5 04 20 A0 E1 0D 00 A0 E1 40 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 38 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 2A FF FF EB 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0D 50 A0 E1 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI___uClibc_fini_fc677e0b664445127f8776a960eae419 {
	meta:
		aliases = "__uClibc_fini, __GI___uClibc_fini"
		size = "108"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { 30 40 2D E9 50 20 9F E5 50 30 9F E5 03 30 62 E0 43 41 A0 E1 02 50 A0 E1 01 00 00 EA 0F E0 A0 E1 04 F1 95 E7 01 40 54 E2 FB FF FF 2A 30 30 9F E5 00 30 93 E5 00 00 53 E3 0F E0 A0 11 03 F0 A0 11 20 30 9F E5 00 30 93 E5 00 00 53 E3 30 80 BD 08 0F E0 A0 E1 03 F0 A0 E1 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule closelog_47bc18d84ca104e57170c3d48d92de28 {
	meta:
		aliases = "__GI_closelog, closelog"
		size = "112"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { 30 40 2D E9 50 40 9F E5 10 D0 4D E2 4C 10 9F E5 04 20 A0 E1 0D 00 A0 E1 44 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 3C 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 00 00 A0 E3 CF FF FF EB 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0D 50 A0 E1 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule setup_salt_3b62750e58bcd313d66c4a3545051a4e {
	meta:
		aliases = "setup_salt"
		size = "104"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { 30 40 2D E9 54 40 9F E5 00 30 94 E5 03 00 50 E1 30 80 BD 08 48 20 9F E5 00 30 A0 E3 03 E0 A0 E1 02 50 A0 E1 02 C5 A0 E3 01 10 A0 E3 00 00 84 E5 00 30 82 E5 05 00 00 EA 00 00 11 E1 00 30 95 15 03 30 8C 11 00 30 85 15 81 10 A0 E1 AC C0 A0 E1 17 00 5E E3 01 E0 8E E2 F6 FF FF DA 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getutent_41e96454c24d7e9c50e6f8a66586099b {
	meta:
		aliases = "getutent"
		size = "116"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 54 40 9F E5 10 D0 4D E2 04 20 A0 E1 4C 10 9F E5 0D 00 A0 E1 48 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 40 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 65 FF FF EB 01 10 A0 E3 00 40 A0 E1 28 30 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 0D 50 A0 E1 04 00 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_random_386ff274759e728d0326dedeb7bfde2e {
	meta:
		aliases = "random, __GI_random"
		size = "124"
		objfiles = "random@libc.a"
	strings:
		$pattern = { 30 40 2D E9 58 40 9F E5 14 D0 4D E2 04 20 A0 E1 50 10 9F E5 0D 00 A0 E1 4C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 44 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 10 10 8D E2 34 00 9F E5 ?? ?? ?? EB 0D 00 A0 E1 01 10 A0 E3 28 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 10 00 9D E5 0D 50 A0 E1 14 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fdopendir_69f45a4891afe97e8db9fa0c5a3e45f8 {
	meta:
		aliases = "fdopendir"
		size = "148"
		objfiles = "opendir@libc.a"
	strings:
		$pattern = { 30 40 2D E9 58 D0 4D E2 0D 10 A0 E1 00 40 A0 E1 ?? ?? ?? EB 00 50 50 E2 19 00 00 1A 10 30 9D E5 0F 3A 03 E2 01 09 53 E3 03 00 00 0A ?? ?? ?? EB 05 20 A0 E1 14 30 A0 E3 0A 00 00 EA 04 00 A0 E1 03 10 A0 E3 ?? ?? ?? EB 01 00 70 E3 0C 00 00 0A 03 30 00 E2 01 00 53 E3 04 00 00 1A ?? ?? ?? EB 05 20 A0 E1 16 30 A0 E3 00 30 80 E5 05 00 00 EA 04 00 A0 E1 30 10 9D E5 9B FF FF EB 00 20 A0 E1 00 00 00 EA 00 20 A0 E3 02 00 A0 E1 58 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule closelog_intern_c2505240425efbc889e1f1008d215fd0 {
	meta:
		aliases = "closelog_intern"
		size = "132"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { 30 40 2D E9 5C 50 9F E5 00 30 95 E5 01 00 73 E3 00 40 A0 E1 03 00 A0 11 ?? ?? ?? 1B 00 30 E0 E3 00 30 85 E5 40 30 9F E5 00 20 A0 E3 00 00 54 E3 00 20 83 E5 30 80 BD 18 30 30 9F E5 30 20 9F E5 00 40 83 E5 2C 30 9F E5 00 20 83 E5 28 30 9F E5 01 20 A0 E3 00 20 83 E5 20 30 9F E5 FE 20 82 E2 00 20 83 E5 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __do_global_dtors_aux_1dde3a26ce48932f556d0dc6162bc5ca {
	meta:
		aliases = "__do_global_dtors_aux"
		size = "224"
		objfiles = "crtbegin, crtbeginT"
	strings:
		$pattern = { 30 40 2D E9 5C 50 9F E5 00 30 D5 E5 00 00 53 E3 30 80 BD 18 50 40 9F E5 00 30 94 E5 00 20 93 E5 00 00 52 E3 07 00 00 0A 04 30 83 E2 00 30 84 E5 0F E0 A0 E1 02 F0 A0 E1 00 30 94 E5 00 20 93 E5 00 00 52 E3 F7 FF FF 1A 20 30 9F E5 00 00 53 E3 1C 00 9F 15 0F E0 A0 11 03 F0 A0 11 01 30 A0 E3 00 30 C5 E5 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 E0 2D E5 04 F0 9D E4 3C 30 9F E5 00 00 53 E3 04 E0 2D E5 34 00 9F 15 34 10 9F 15 0F E0 A0 11 03 F0 A0 11 2C 00 9F E5 00 30 90 E5 00 00 53 E3 04 F0 9D 04 20 30 9F E5 00 00 53 E3 04 F0 9D 04 0F E0 A0 E1 03 F0 A0 E1 04 F0 9D E4 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __setutent_aa22f192dba8d7af20b9a0a1184940a5 {
	meta:
		aliases = "__setutent"
		size = "120"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 60 40 9F E5 00 00 94 E5 00 00 50 E3 11 00 00 AA 54 50 9F E5 54 10 9F E5 00 00 95 E5 ?? ?? ?? EB 00 00 50 E3 00 00 84 E5 05 00 00 AA 00 00 95 E5 02 17 A0 E3 ?? ?? ?? EB 00 00 50 E3 00 00 84 E5 30 80 BD B8 00 00 94 E5 02 10 A0 E3 01 20 A0 E3 30 40 BD E8 ?? ?? ?? EA 00 10 A0 E3 01 20 A0 E1 30 40 BD E8 ?? ?? ?? EA ?? ?? ?? ?? ?? ?? ?? ?? 02 00 08 00 }
	condition:
		$pattern
}

rule opendir_e70a562a7d6a622de33e7a6c1806f619 {
	meta:
		aliases = "__GI_opendir, opendir"
		size = "128"
		objfiles = "opendir@libc.a"
	strings:
		$pattern = { 30 40 2D E9 70 10 9F E5 58 D0 4D E2 ?? ?? ?? EB 00 40 50 E2 05 00 00 BA 0D 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 03 00 00 AA 04 00 A0 E1 ?? ?? ?? EB 00 50 A0 E3 0D 00 00 EA 02 10 A0 E3 01 20 A0 E3 04 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 30 10 9D E5 C5 FF FF EB 00 50 50 E2 04 00 00 1A 04 00 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 0C 30 A0 E3 00 30 80 E5 05 00 A0 E1 58 D0 8D E2 30 80 BD E8 00 48 08 00 }
	condition:
		$pattern
}

rule __pthread_manager_sighandler_4120f04d33f96e627f0fee7f926e8837 {
	meta:
		aliases = "__pthread_manager_sighandler"
		size = "148"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 7C 30 9F E5 00 30 93 E5 00 00 53 E3 1C D0 4D E2 00 30 A0 13 03 00 00 1A 68 30 9F E5 00 30 93 E5 00 30 53 E2 01 30 A0 13 00 00 53 E3 50 30 9F E5 01 20 A0 E3 00 20 83 E5 0F 00 00 0A 00 30 A0 E3 00 30 8D E5 06 30 83 E2 04 30 8D E5 38 50 9F E5 0D 40 A0 E1 0D 10 A0 E1 1C 20 A0 E3 00 00 95 E5 ?? ?? ?? EB 01 00 70 E3 03 00 00 1A ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 F5 FF FF 0A 1C D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __adddf3_671e43d5e63a2998e9d475ae5d300b68 {
	meta:
		aliases = "__aeabi_dadd, __adddf3"
		size = "736"
		objfiles = "_addsubdf3@libgcc.a"
	strings:
		$pattern = { 30 40 2D E9 80 40 A0 E1 82 50 A0 E1 05 00 34 E1 03 00 31 01 01 C0 94 11 03 C0 95 11 C4 CA F0 11 C5 CA F0 11 86 00 00 0A A4 4A A0 E1 A5 5A 74 E0 00 50 65 B2 06 00 00 DA 05 40 84 E0 03 30 21 E0 02 20 20 E0 01 10 23 E0 00 00 22 E0 03 30 21 E0 02 20 20 E0 36 00 55 E3 30 80 BD 88 02 01 10 E3 00 06 A0 E1 01 C6 A0 E3 20 06 8C E1 01 00 00 0A 00 10 71 E2 00 00 E0 E2 02 01 12 E3 02 26 A0 E1 22 26 8C E1 01 00 00 0A 00 30 73 E2 00 20 E2 E2 05 00 34 E1 64 00 00 0A 01 40 44 E2 20 E0 75 E2 05 00 00 BA 13 CE A0 E1 33 15 91 E0 00 00 A0 E2 12 1E 91 E0 52 05 B0 E0 06 00 00 EA 20 50 45 E2 20 E0 8E E2 01 00 53 E3 }
	condition:
		$pattern
}

rule _ppfs_init_0233c46357aaf2a365962b58d14fe8dc {
	meta:
		aliases = "_ppfs_init"
		size = "152"
		objfiles = "_ppfs_init@libc.a"
	strings:
		$pattern = { 30 40 2D E9 98 20 A0 E3 00 40 A0 E1 01 50 A0 E1 00 10 A0 E3 ?? ?? ?? EB 18 30 94 E5 00 50 84 E5 01 30 43 E2 18 30 84 E5 28 20 84 E2 09 30 A0 E3 08 10 A0 E3 01 30 53 E2 04 10 82 E4 FC FF FF 1A 05 20 A0 E1 0E 00 00 EA 25 00 50 E3 0B 00 00 1A 01 30 F2 E5 25 00 53 E3 08 00 00 0A 00 20 84 E5 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 01 00 00 AA 00 00 E0 E3 30 80 BD E8 00 20 94 E5 00 00 00 EA 01 20 82 E2 00 00 D2 E5 00 00 50 E3 ED FF FF 1A 00 50 84 E5 30 80 BD E8 }
	condition:
		$pattern
}

rule _stdio_init_9bcc896ee80acc3221b60d732a6ac9bd {
	meta:
		aliases = "_stdio_init"
		size = "124"
		objfiles = "_stdio@libc.a"
	strings:
		$pattern = { 30 40 2D E9 ?? ?? ?? EB 00 40 A0 E1 00 00 A0 E3 00 50 94 E5 ?? ?? ?? EB 00 00 50 E3 07 00 00 1A 50 10 9F E5 01 20 D1 E5 00 30 D1 E5 02 34 83 E1 01 3C 23 E2 43 24 A0 E1 01 20 C1 E5 00 30 C1 E5 01 00 A0 E3 ?? ?? ?? EB 00 00 50 E3 07 00 00 1A 20 10 9F E5 51 20 D1 E5 50 30 D1 E5 02 34 83 E1 01 3C 23 E2 43 24 A0 E1 51 20 C1 E5 50 30 C1 E5 00 50 84 E5 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svc_exit_b133f06996feff5e0cef31611d73f24e {
	meta:
		aliases = "svc_exit"
		size = "40"
		objfiles = "svc_run@libc.a"
	strings:
		$pattern = { 30 40 2D E9 ?? ?? ?? EB 00 50 A0 E3 00 40 A0 E1 00 00 90 E5 ?? ?? ?? EB 00 50 84 E5 ?? ?? ?? EB 00 50 80 E5 30 80 BD E8 }
	condition:
		$pattern
}

rule svcraw_create_6612688819ca2842db39f57d4a486e94 {
	meta:
		aliases = "svcraw_create"
		size = "156"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { 30 40 2D E9 ?? ?? ?? EB BC 50 90 E5 00 00 55 E3 06 00 00 1A 01 00 A0 E3 6C 10 9F E5 ?? ?? ?? EB 00 00 50 E3 05 00 A0 01 30 80 BD 08 00 50 A0 E1 58 10 9F E5 58 30 9F E5 8E CD 85 E2 03 10 85 E7 50 20 9F E5 2C C0 8C E2 89 4D 85 E2 1C 30 83 E2 00 E0 A0 E3 03 C0 85 E7 24 40 84 E2 8E 0D 85 E2 20 30 43 E2 03 E0 C5 E7 02 E0 85 E7 01 E0 C4 E5 14 00 80 E2 05 10 A0 E1 02 30 A0 E3 ?? ?? ?? EB 89 0D 85 E2 20 00 80 E2 30 80 BD E8 3C 25 00 00 ?? ?? ?? ?? 68 22 00 00 60 22 00 00 }
	condition:
		$pattern
}

rule shm_unlink_8b5f12b07ad38f4c58cfd895f3e63b99 {
	meta:
		aliases = "shm_unlink"
		size = "44"
		objfiles = "shm@librt.a"
	strings:
		$pattern = { 30 40 2D E9 EC FF FF EB 00 40 50 E2 00 50 E0 03 03 00 00 0A ?? ?? ?? EB 00 50 A0 E1 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule rindex_994a0f7b446ea6782fe4d5c2d1e735d6 {
	meta:
		aliases = "strrchr, __GI_strrchr, rindex"
		size = "68"
		objfiles = "strrchr@libc.a"
	strings:
		$pattern = { 30 40 2D E9 FF 40 11 E2 00 30 A0 E1 00 50 A0 13 04 00 00 1A 04 10 A0 E1 30 40 BD E8 ?? ?? ?? EA 00 50 A0 E1 01 30 80 E2 03 00 A0 E1 04 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 F8 FF FF 1A 05 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule skip_nospace_e09a0cfb9ef19dae2c413d5203bc1751 {
	meta:
		aliases = "skip_nospace"
		size = "64"
		objfiles = "opennameservers@libc.a"
	strings:
		$pattern = { 34 10 9F E5 04 00 00 EA 0A 00 52 E3 01 00 00 1A 00 30 C0 E5 0E F0 A0 E1 01 00 80 E2 00 20 D0 E5 00 00 52 E3 0E F0 A0 01 00 30 91 E5 82 30 D3 E7 20 30 13 E2 F3 FF FF 0A 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule putwchar_5789187e7fb18f55a228e3188f2c2211 {
	meta:
		aliases = "putwchar"
		size = "64"
		objfiles = "putwchar@libc.a"
	strings:
		$pattern = { 34 30 9F E5 00 10 93 E5 34 30 91 E5 00 00 53 E3 04 00 00 0A 10 20 91 E5 1C 30 91 E5 03 00 52 E1 01 00 00 3A ?? ?? ?? EA ?? ?? ?? EA FF 00 00 E2 01 00 C2 E4 10 20 81 E5 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule skip_and_NUL_space_3142e8744bdb9c67306d0a866b8b74ed {
	meta:
		aliases = "skip_and_NUL_space"
		size = "64"
		objfiles = "opennameservers@libc.a"
	strings:
		$pattern = { 34 C0 9F E5 00 10 A0 E3 00 20 D0 E5 00 00 52 E3 0E F0 A0 01 00 30 9C E5 82 30 D3 E7 20 00 13 E3 0E F0 A0 01 23 00 52 E3 0A 00 52 13 00 10 C0 E5 0E F0 A0 01 01 00 80 E2 F2 FF FF EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clnt_sperrno_3286f2069befdb204fd85c0af9c3328a {
	meta:
		aliases = "__GI_clnt_sperrno, clnt_sperrno"
		size = "76"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { 38 10 9F E5 00 20 A0 E3 08 00 00 EA 82 31 91 E7 00 00 53 E1 04 00 00 1A 82 31 81 E0 04 20 93 E5 1C 30 9F E5 03 00 82 E0 0E F0 A0 E1 01 20 82 E2 11 00 52 E3 F4 FF FF 9A 08 00 9F E5 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI___uClibc_init_ea5a8ffad957b2c0ca7d659db8c6f7fb {
	meta:
		aliases = "__uClibc_init, __GI___uClibc_init"
		size = "76"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { 38 10 9F E5 00 30 91 E5 00 00 53 E3 04 E0 2D E5 04 F0 9D 14 28 20 9F E5 01 3A 83 E2 00 00 52 E3 00 30 81 E5 0F E0 A0 11 02 F0 A0 11 14 30 9F E5 00 00 53 E3 04 F0 9D 04 04 E0 9D E4 ?? ?? ?? EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _promoted_size_ee49341f7cd32d19d04e22ab386f5114 {
	meta:
		aliases = "_promoted_size"
		size = "76"
		objfiles = "_ppfs_parsespec@libc.a"
	strings:
		$pattern = { 38 10 9F E5 38 C0 9F E5 02 10 41 E2 01 30 D1 E5 00 20 D1 E5 03 3C A0 E1 43 28 82 E1 00 00 52 E1 01 00 00 0A 0C 00 51 E1 F6 FF FF 8A 10 30 9F E5 10 20 9F E5 01 30 63 E0 C3 00 D2 E7 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule localeconv_5eedfe9e00a039d80b9e7b14c726823c {
	meta:
		aliases = "__GI_localeconv, localeconv"
		size = "76"
		objfiles = "localeconv@libc.a"
	strings:
		$pattern = { 38 20 9F E5 38 30 9F E5 00 30 82 E5 24 10 82 E2 01 30 83 E2 04 30 A2 E5 01 00 52 E1 FC FF FF 3A 20 30 9F E5 00 10 E0 E3 0D 20 83 E2 01 10 C3 E4 02 00 53 E1 FC FF FF 9A 00 00 9F E5 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_once_fork_child_36f1973d155d2153fc75efc847922463 {
	meta:
		aliases = "__pthread_once_fork_child"
		size = "80"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { 38 30 9F E5 04 E0 2D E5 00 10 A0 E3 30 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 28 00 9F E5 00 10 A0 E3 ?? ?? ?? EB 20 20 9F E5 00 30 92 E5 16 01 73 E3 04 30 83 D2 00 30 A0 C3 00 30 82 E5 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __do_global_ctors_aux_bc4b8b763d2ef85f0b63e1ce57f66ce7 {
	meta:
		aliases = "__do_global_ctors_aux"
		size = "80"
		objfiles = "crtendS"
	strings:
		$pattern = { 38 30 9F E5 38 20 9F E5 03 30 8F E0 02 20 83 E0 04 10 12 E5 01 00 71 E3 10 40 2D E9 04 20 42 E2 10 80 BD 08 02 40 A0 E1 0F E0 A0 E1 01 F0 A0 E1 04 10 34 E5 01 00 71 E3 FA FF FF 1A 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? 04 E0 2D E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule __GI_atan_c8771cac0583a34a1ad2a5af294d60b8 {
	meta:
		aliases = "atan, __GI_atan"
		size = "1236"
		objfiles = "s_atan@libm.a"
	strings:
		$pattern = { 38 34 9F E5 F0 4F 2D E9 02 41 C0 E3 03 00 54 E1 00 80 A0 E1 01 90 A0 E1 00 B0 A0 E1 13 00 00 DA 1C 34 9F E5 03 00 54 E1 01 40 A0 E1 06 00 00 CA 00 30 A0 13 01 30 A0 03 00 00 51 E3 00 30 A0 03 01 30 03 12 00 00 53 E3 03 00 00 0A 08 20 A0 E1 09 30 A0 E1 ?? ?? ?? EB F3 00 00 EA 00 00 50 E3 E0 83 9F D5 E0 83 9F C5 E0 93 9F E5 F0 00 00 EA DC 33 9F E5 03 00 54 E1 0B 00 00 CA 6F 37 43 E2 03 00 54 E1 5C 00 00 CA C8 23 9F E5 C8 33 9F E5 ?? ?? ?? EB C4 23 9F E5 00 30 A0 E3 ?? ?? ?? EB 00 00 50 E3 E2 00 00 CA 53 00 00 EA ?? ?? ?? EB AC 33 9F E5 03 00 54 E1 00 80 A0 E1 01 90 A0 E1 2B 00 00 CA 0D 38 43 E2 }
	condition:
		$pattern
}

rule __popcountsi2_c835de348e872894af4e122bb0669e05 {
	meta:
		aliases = "__popcountsi2"
		size = "68"
		objfiles = "_popcountsi2@libgcc.a"
	strings:
		$pattern = { 38 C0 9F E5 20 38 A0 E1 20 24 A0 E1 FF 30 03 E2 FF 20 02 E2 10 40 2D E9 03 10 DC E7 02 40 DC E7 FF 30 00 E2 00 E0 A0 E1 03 00 DC E7 04 10 81 E0 2E 3C DC E7 01 00 80 E0 00 00 83 E0 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule frame_dummy_358df2ac6b39d5bc0e6fb5821cab1e37 {
	meta:
		aliases = "frame_dummy"
		size = "96"
		objfiles = "crtbegin, crtbeginT"
	strings:
		$pattern = { 3C 30 9F E5 00 00 53 E3 04 E0 2D E5 34 00 9F 15 34 10 9F 15 0F E0 A0 11 03 F0 A0 11 2C 00 9F E5 00 30 90 E5 00 00 53 E3 04 F0 9D 04 20 30 9F E5 00 00 53 E3 04 F0 9D 04 0F E0 A0 E1 03 F0 A0 E1 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 E0 2D E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule _dl_unmap_cache_4a56936bcd05ecc02f2a2b6f85d9c4fb {
	meta:
		aliases = "_dl_unmap_cache"
		size = "80"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 3C C0 9F E5 00 00 9C E5 01 30 40 E2 03 00 73 E3 00 00 E0 83 0E F0 A0 81 28 30 9F E5 00 10 93 E5 5B 00 90 EF 01 0A 70 E3 1C 30 9F 85 00 20 60 82 00 20 83 85 00 30 A0 E3 03 00 A0 E1 00 30 8C E5 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_nl_langinfo_016de9d33e146d3a7b35c451e264ea7f {
	meta:
		aliases = "nl_langinfo, __GI_nl_langinfo"
		size = "84"
		objfiles = "nl_langinfo@libc.a"
	strings:
		$pattern = { 40 14 A0 E1 05 00 51 E3 0E 00 00 8A 3C C0 9F E5 0C 20 81 E0 01 10 DC E7 FF 30 00 E2 01 20 D2 E5 03 00 81 E0 02 00 50 E1 06 00 00 2A 0C 30 80 E0 07 30 D3 E5 61 20 8C E2 02 30 83 E0 40 20 00 E2 82 00 83 E0 0E F0 A0 E1 00 00 9F E5 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule rand_r_460dc636bee4516cb1f7d3831e5ab11b {
	meta:
		aliases = "rand_r"
		size = "88"
		objfiles = "rand_r@libc.a"
	strings:
		$pattern = { 40 30 9F E5 00 20 90 E5 3C 10 9F E5 91 32 22 E0 92 31 2C E0 9C 31 21 E0 04 E0 2D E5 2C 30 9F E5 00 E0 A0 E1 28 00 9F E5 22 23 A0 E1 2C C8 03 E0 00 00 02 E0 0C 00 20 E0 21 38 03 E0 00 05 83 E1 00 10 8E E5 04 F0 9D E4 39 30 00 00 6D 4E C6 41 FF 03 00 00 00 FC 1F 00 }
	condition:
		$pattern
}

rule __GI_srand48_r_f5ecc680d3d8b004af94ce15c68d4c63 {
	meta:
		aliases = "srand48_r, __GI_srand48_r"
		size = "104"
		objfiles = "srand48_r@libc.a"
	strings:
		$pattern = { 40 38 A0 E1 04 30 C1 E5 0E 30 A0 E3 10 40 2D E9 00 30 C1 E5 25 30 83 E2 01 30 C1 E5 40 30 9F E5 05 40 A0 E3 00 C0 A0 E3 10 30 81 E5 14 40 81 E5 0B 30 A0 E3 40 E4 A0 E1 40 2C A0 E1 0C 30 C1 E5 02 00 C1 E5 01 30 A0 E3 0C 00 A0 E1 05 20 C1 E5 03 E0 C1 E5 0E 30 C1 E5 0F C0 C1 E5 0D C0 C1 E5 10 80 BD E8 6D E6 EC DE }
	condition:
		$pattern
}

rule __GI_nearbyint_6c7ce7972e6f1df89dbae5a3da36aef9 {
	meta:
		aliases = "rint, nearbyint, __GI_rint, __GI_nearbyint"
		size = "408"
		objfiles = "s_rint@libm.a"
	strings:
		$pattern = { 40 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF CF 43 E2 03 C0 4C E2 13 00 5C E3 F0 4F 2D E9 00 60 A0 E1 01 70 A0 E1 00 40 A0 E1 01 50 A0 E1 00 80 A0 E1 01 E0 A0 E1 00 A0 A0 E3 00 B0 A0 E3 A0 9F A0 E1 2E 00 00 CA 00 00 5C E3 1D 00 00 AA 02 31 C0 E3 01 30 93 E1 4A 00 00 0A FF 34 C0 E3 0F 36 C3 E3 01 30 83 E1 00 20 63 E2 20 11 9F E5 03 20 82 E1 89 11 81 E0 22 26 A0 E1 A0 08 A0 E1 60 00 91 E8 02 27 02 E2 80 08 A0 E1 00 30 82 E1 03 20 A0 E1 06 10 A0 E1 07 30 A0 E1 05 00 A0 E1 ?? ?? ?? EB 06 30 A0 E1 05 20 A0 E1 ?? ?? ?? EB 02 31 C0 E3 01 40 A0 E1 89 1F 83 E1 01 60 A0 E1 04 70 A0 E1 2F 00 00 EA C8 30 9F E5 }
	condition:
		$pattern
}

rule __libc_allocate_rtsig_27d4fc5826d000b7ad03b76e9d1df6d9 {
	meta:
		aliases = "__libc_allocate_rtsig"
		size = "80"
		objfiles = "pthread@libpthread.a, allocrtsig@libc.a"
	strings:
		$pattern = { 40 C0 9F E5 00 20 9C E5 01 00 72 E3 0A 00 00 0A 34 10 9F E5 00 30 91 E5 03 00 52 E1 06 00 00 CA 00 00 50 E3 01 30 82 12 03 20 A0 01 01 30 43 02 00 30 8C 15 00 30 81 05 00 00 00 EA 00 20 E0 E3 02 00 A0 E1 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule byte_store_op1_8be34835b2b51a5b614ae6fece335667 {
	meta:
		aliases = "byte_store_op1"
		size = "20"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 42 34 A0 E1 02 30 C1 E5 00 00 C1 E5 01 20 C1 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_wctype_b6e1aa4997f51081955c25d2f6a49a1e {
	meta:
		aliases = "wctype, wctrans, __GI_wctrans, __GI_wctype"
		size = "80"
		objfiles = "wctype@libc.a, wctrans@libc.a"
	strings:
		$pattern = { 44 10 9F E5 70 40 2D E9 00 60 A0 E1 01 50 A0 E3 01 40 81 E2 06 00 A0 E1 04 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 01 00 00 1A 05 00 A0 E1 70 80 BD E8 01 30 54 E5 03 00 D4 E7 00 00 50 E3 01 50 85 E2 03 10 84 E0 F1 FF FF 1A 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule load_field_2268c917fd7d3b63d94a2f946ee8373f {
	meta:
		aliases = "load_field"
		size = "88"
		objfiles = "strftime@libc.a"
	strings:
		$pattern = { 44 30 9F E5 07 00 50 E3 03 30 80 E0 00 20 A0 E1 3A 30 D3 E5 00 01 91 E7 30 30 9F 05 03 00 00 0A 05 00 52 E3 76 0E 80 02 24 30 9F 05 0C 00 80 02 03 00 50 E1 02 00 00 8A 03 00 52 E3 00 00 50 03 0E F0 A0 11 00 00 E0 E3 0E F0 A0 E1 ?? ?? ?? ?? 6D 01 00 00 0F 27 00 00 }
	condition:
		$pattern
}

rule pthread_kill_all_threads_878045d42b1baecb6a9933050ffbf6de {
	meta:
		aliases = "pthread_kill_all_threads"
		size = "84"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { 48 20 9F E5 F0 40 2D E9 00 30 92 E5 00 40 93 E5 00 50 A0 E1 01 60 A0 E1 02 70 A0 E1 02 00 00 EA 14 00 94 E5 ?? ?? ?? EB 00 40 94 E5 00 30 97 E5 03 00 54 E1 05 10 A0 E1 F8 FF FF 1A 00 00 56 E3 F0 80 BD 08 14 00 94 E5 F0 40 BD E8 ?? ?? ?? EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule scalbn_950b39ad041b433a13436117bbb2c6ef {
	meta:
		aliases = "scalbln, __GI_scalbln, __GI_scalbn, scalbn"
		size = "380"
		objfiles = "s_scalbn@libm.a"
	strings:
		$pattern = { 48 31 9F E5 03 30 00 E0 43 CA B0 E1 F0 41 2D E9 00 60 A0 E1 01 70 A0 E1 01 50 A0 E1 00 E0 A0 E1 02 80 A0 E1 01 40 A0 E1 0C 00 00 1A 02 31 C0 E3 01 30 93 E1 42 00 00 0A 00 30 A0 E3 10 21 9F E5 ?? ?? ?? EB 04 31 9F E5 03 30 00 E0 43 3A A0 E1 00 60 A0 E1 01 70 A0 E1 00 E0 A0 E1 36 C0 43 E2 F0 30 9F E5 03 00 5C E1 05 00 00 1A 06 00 A0 E1 07 10 A0 E1 06 20 A0 E1 07 30 A0 E1 ?? ?? ?? EB 2D 00 00 EA D0 30 9F E5 08 10 8C E0 03 00 51 E1 0F 00 00 CA C4 30 9F E5 03 00 58 E1 14 00 00 BA 00 00 51 E3 05 00 00 DA 7F 24 CE E3 0F 26 C2 E3 01 3A 82 E1 07 40 A0 E1 03 60 A0 E1 20 00 00 EA 36 00 71 E3 12 00 00 CA }
	condition:
		$pattern
}

rule getnetbyaddr_233d99eaf6b818523ad5165c2a8d9a63 {
	meta:
		aliases = "getnetbyaddr"
		size = "92"
		objfiles = "getnetbyad@libc.a"
	strings:
		$pattern = { 50 30 9F E5 70 40 2D E9 00 60 A0 E1 00 00 93 E5 01 50 A0 E1 ?? ?? ?? EB 05 00 00 EA 08 30 94 E5 05 00 53 E1 02 00 00 1A 0C 30 94 E5 06 00 53 E1 02 00 00 0A ?? ?? ?? EB 00 40 50 E2 F6 FF FF 1A 10 30 9F E5 00 30 93 E5 00 00 53 E3 ?? ?? ?? 0B 04 00 A0 E1 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_tanh_a1e7afc3b6bd79f1c95fefc346191441 {
	meta:
		aliases = "tanh, __GI_tanh"
		size = "360"
		objfiles = "s_tanh@libm.a"
	strings:
		$pattern = { 50 31 9F E5 02 21 C0 E3 03 00 52 E1 F0 40 2D E9 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 00 70 A0 E1 13 00 00 DA 00 00 50 E3 08 00 00 BA 00 20 A0 E1 01 30 A0 E1 20 01 9F E5 00 10 A0 E3 ?? ?? ?? EB 14 21 9F E5 00 30 A0 E3 ?? ?? ?? EB F0 80 BD E8 00 20 A0 E1 01 30 A0 E1 FC 00 9F E5 00 10 A0 E3 ?? ?? ?? EB F0 20 9F E5 00 30 A0 E3 ?? ?? ?? EB F0 80 BD E8 E4 30 9F E5 03 00 52 E1 D8 00 9F C5 00 10 A0 C3 2D 00 00 CA F2 05 52 E3 08 00 00 AA C4 20 9F E5 00 30 A0 E3 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 05 00 A0 E1 06 10 A0 E1 ?? ?? ?? EB F0 80 BD E8 A8 30 9F E5 03 00 52 E1 10 00 00 DA ?? ?? ?? EB 00 20 A0 E1 }
	condition:
		$pattern
}

rule __GI___assert_b33cfb80ab1785e0cd114a021f9768d5 {
	meta:
		aliases = "__assert, __GI___assert"
		size = "112"
		objfiles = "__assert@libc.a"
	strings:
		$pattern = { 54 60 9F E5 00 C0 96 E5 00 00 5C E3 0C D0 4D E2 00 50 A0 E1 02 40 A0 E1 03 E0 A0 E1 0D 00 00 1A 38 30 9F E5 00 00 93 E5 34 30 9F E5 00 20 93 E5 30 30 9F E5 00 00 5E E3 03 E0 A0 01 01 C0 8C E2 01 30 A0 E1 20 10 9F E5 00 C0 86 E5 10 40 8D E8 08 50 8D E5 ?? ?? ?? EB ?? ?? ?? EB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _longjmp_789ce6fea0e89014516e8152aa1f9b75 {
	meta:
		aliases = "longjmp, __libc_longjmp, siglongjmp, __libc_siglongjmp, _longjmp"
		size = "52"
		objfiles = "longjmp@libc.a"
	strings:
		$pattern = { 58 30 90 E5 00 00 53 E3 00 40 A0 E1 01 50 A0 E1 02 00 A0 13 5C 10 84 12 00 20 A0 13 ?? ?? ?? 1B 00 00 55 E3 05 10 A0 11 01 10 A0 03 04 00 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule thread_self_64a341d9e80005fa919d065998c3f9b0 {
	meta:
		aliases = "thread_self"
		size = "124"
		objfiles = "pthread@libpthread.a, spinlock@libpthread.a, mutex@libpthread.a, rwlock@libpthread.a, errno@libpthread.a"
	strings:
		$pattern = { 5C 30 9F E5 00 30 93 E5 03 00 5D E1 0D 20 A0 E1 50 00 9F 25 0E F0 A0 21 4C 30 9F E5 00 30 93 E5 03 00 5D E1 04 00 00 3A 40 30 9F E5 00 30 93 E5 03 00 5D E1 38 00 9F 35 0E F0 A0 31 34 30 9F E5 00 30 93 E5 00 00 53 E3 00 00 00 0A ?? ?? ?? EA A2 3A E0 E1 83 3A E0 E1 57 0F 43 E2 03 00 40 E2 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getenv_bfc81d5c345e09c6f15d96c465c9bf43 {
	meta:
		aliases = "__GI_getenv, getenv"
		size = "108"
		objfiles = "getenv@libc.a"
	strings:
		$pattern = { 60 30 9F E5 F0 40 2D E9 00 60 93 E5 00 00 56 E3 00 70 A0 E1 11 00 00 0A ?? ?? ?? EB 00 50 A0 E1 08 00 00 EA ?? ?? ?? EB 00 00 50 E3 05 20 84 E0 04 00 00 1A 05 30 D4 E7 3D 00 53 E3 01 00 00 1A 01 00 82 E2 F0 80 BD E8 00 40 96 E5 00 10 54 E2 07 00 A0 E1 05 20 A0 E1 04 60 86 E2 F0 FF FF 1A 00 00 A0 E3 F0 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_xdrrec_create_c6ba4af85aa3850660026b37be90718e {
	meta:
		aliases = "xdrrec_create, __GI_xdrrec_create"
		size = "268"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 63 00 51 E3 F0 4F 2D E9 01 40 A0 E1 00 80 A0 E1 FA 4E A0 93 44 00 A0 E3 63 00 52 E3 02 50 A0 E1 03 A0 A0 E1 FA 5E A0 93 24 90 8D E2 00 0A 99 E8 ?? ?? ?? EB 03 40 84 E2 03 70 C4 E3 03 50 85 E2 00 60 A0 E1 03 50 C5 E3 04 00 87 E2 05 00 80 E0 ?? ?? ?? EB 00 00 50 E3 00 00 56 13 00 40 A0 E1 08 00 00 1A 94 30 9F E5 94 00 9F E5 00 10 93 E5 ?? ?? ?? EB 06 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 F0 4F BD E8 ?? ?? ?? EA 03 30 10 E2 04 30 63 12 03 E0 80 10 00 E0 A0 01 01 30 A0 E3 07 20 8E E0 38 30 86 E5 5C 30 9F E5 04 00 86 E5 02 C0 85 E0 00 00 A0 E3 04 10 8E E2 3C 70 86 E5 40 50 86 E5 04 30 88 E5 0C 60 88 E5 }
	condition:
		$pattern
}

rule __absvdi2_8e049f90875ced01626f53cdd9411294 {
	meta:
		aliases = "__absvdi2"
		size = "44"
		objfiles = "_absvdi2@libgcc.a"
	strings:
		$pattern = { 70 00 2D E9 C1 3F A0 E1 C1 4F A0 E1 00 50 23 E0 01 60 24 E0 05 00 A0 E1 06 10 A0 E1 03 00 50 E0 04 10 C1 E0 70 00 BD E8 0E F0 A0 E1 }
	condition:
		$pattern
}

rule getnetbyname_f5b21c5cca971c484fa958b69ed09f41 {
	meta:
		aliases = "getnetbyname"
		size = "124"
		objfiles = "getnetbynm@libc.a"
	strings:
		$pattern = { 70 30 9F E5 70 40 2D E9 00 60 A0 E1 00 00 93 E5 ?? ?? ?? EB 0E 00 00 EA 00 00 95 E5 06 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 0C 00 00 0A 04 40 95 E5 04 00 00 EA 06 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 06 00 00 0A 04 40 84 E2 00 00 94 E5 00 00 50 E3 F7 FF FF 1A ?? ?? ?? EB 00 50 50 E2 ED FF FF 1A 10 30 9F E5 00 30 93 E5 00 00 53 E3 ?? ?? ?? 0B 05 00 A0 E1 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_sigmask_6cecf97cfaa1e524e45e41dea1958136 {
	meta:
		aliases = "pthread_sigmask"
		size = "196"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 00 51 E3 08 D0 4D E2 00 50 A0 E1 02 60 A0 E1 1D 00 00 0A 0C 00 91 E8 01 00 50 E3 0C 00 8D E8 13 00 00 0A 02 00 50 E3 03 00 00 0A 00 00 50 E3 0D 40 A0 01 05 00 00 0A 12 00 00 EA 70 30 9F E5 0D 00 A0 E1 00 10 93 E5 0D 40 A0 E1 ?? ?? ?? EB 60 30 9F E5 0D 00 A0 E1 00 10 93 E5 ?? ?? ?? EB 54 30 9F E5 00 10 93 E5 00 00 51 E3 05 00 00 DA 02 00 00 EA 38 30 9F E5 00 10 93 E5 0D 40 A0 E1 0D 00 A0 E1 ?? ?? ?? EB 0D 10 A0 E1 05 00 A0 E1 06 20 A0 E1 ?? ?? ?? EB 01 00 70 E3 00 00 A0 13 01 00 00 1A ?? ?? ?? EB 00 00 90 E5 08 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_rwlock_destroy_6543549aaf229f3e2d710ef6e3ccc808 {
	meta:
		aliases = "pthread_rwlock_destroy"
		size = "56"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 10 A0 E3 00 40 A0 E1 ?? ?? ?? EB 04 00 A0 E1 08 60 94 E5 0C 50 94 E5 ?? ?? ?? EB 00 00 56 E3 00 00 55 D3 00 00 A0 03 01 00 A0 13 10 00 A0 13 70 80 BD E8 }
	condition:
		$pattern
}

rule pthread_rwlock_unlock_ac7457e7ccb8bd71137d39c516ccdae8 {
	meta:
		aliases = "pthread_rwlock_unlock"
		size = "404"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 10 A0 E3 00 50 A0 E1 ?? ?? ?? EB 0C 40 95 E5 00 00 54 E3 21 00 00 0A 0D FF FF EB 00 00 54 E1 21 00 00 1A 18 30 95 E5 00 60 A0 E3 00 00 53 E3 0C 60 85 E5 0B 00 00 0A 14 40 95 E5 06 00 54 E1 08 00 00 0A 08 30 94 E5 05 00 A0 E1 14 30 85 E5 08 60 84 E5 ?? ?? ?? EB 04 00 A0 E1 FB FE FF EB 06 00 A0 E1 70 80 BD E8 00 40 A0 E3 10 60 95 E5 05 00 A0 E1 10 40 85 E5 ?? ?? ?? EB 04 50 A0 E1 03 00 00 EA 08 40 96 E5 08 50 86 E5 EF FE FF EB 04 60 A0 E1 00 00 56 E2 F9 FF FF 1A 39 00 00 EA 08 30 95 E5 00 00 53 E3 03 00 00 1A 05 00 A0 E1 ?? ?? ?? EB 01 00 A0 E3 70 80 BD E8 01 20 43 E2 00 00 52 E3 }
	condition:
		$pattern
}

rule wcstof_c5421df7119fbd0b4ad58db4de7788f6 {
	meta:
		aliases = "__GI_wcstof, __GI_strtof, strtof, wcstof"
		size = "52"
		objfiles = "wcstof@libc.a, strtof@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 20 A0 E3 ?? ?? ?? EB 01 50 A0 E1 00 40 A0 E1 ?? ?? ?? EB 00 60 A0 E1 ?? ?? ?? EB 04 20 A0 E1 05 30 A0 E1 ?? ?? ?? EB 06 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule __GI_strtok_r_eb3f11a72dc13cbd9f4b674f6707d3d3 {
	meta:
		aliases = "strtok_r, __GI_strtok_r"
		size = "116"
		objfiles = "strtok_r@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 50 E2 00 40 92 05 04 00 A0 E1 02 50 A0 E1 01 60 A0 E1 ?? ?? ?? EB 00 30 D4 E7 00 40 84 E0 00 00 53 E3 00 40 85 05 0E 00 00 0A 06 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 05 00 00 1A 00 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 04 30 A0 E1 00 00 85 E5 03 00 00 EA 00 30 A0 E3 01 30 C0 E4 00 00 85 E5 04 30 A0 E1 03 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule __GI___cxa_atexit_89a10552de47821c1b2c7109b986ed1b {
	meta:
		aliases = "__cxa_atexit, __GI___cxa_atexit"
		size = "64"
		objfiles = "__cxa_atexit@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 50 E2 01 50 A0 E1 02 60 A0 E1 04 00 A0 01 70 80 BD 08 ?? ?? ?? EB 00 00 50 E3 03 30 A0 13 00 30 80 15 04 40 80 15 08 50 80 15 0C 60 80 15 00 00 E0 03 00 00 A0 13 70 80 BD E8 }
	condition:
		$pattern
}

rule tfind_09570e4c929b12e4f4598d87f8146de9 {
	meta:
		aliases = "__GI_tfind, tfind"
		size = "88"
		objfiles = "tfind@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 51 E2 00 60 A0 E1 02 50 A0 E1 0E 00 00 0A 09 00 00 EA 00 10 91 E5 0F E0 A0 E1 05 F0 A0 E1 00 00 50 E3 01 00 00 1A 00 00 94 E5 70 80 BD E8 00 30 94 E5 08 40 83 E2 04 40 83 B2 00 10 94 E5 00 00 51 E3 06 00 A0 E1 F1 FF FF 1A 00 00 A0 E3 70 80 BD E8 }
	condition:
		$pattern
}

rule __libc_sigaction_e7839bf1813679c3e2f7e89a54a85652 {
	meta:
		aliases = "sigaction, __GI_sigaction, __libc_sigaction"
		size = "116"
		objfiles = "sigaction@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 51 E2 14 D0 4D E2 00 50 A0 E1 02 60 A0 E1 0D 00 00 0A 04 30 94 E5 01 03 13 E3 0A 00 00 1A 14 20 A0 E3 0D 00 A0 E1 ?? ?? ?? EB 04 10 9D E5 30 30 9F E5 30 20 9F E5 04 00 11 E3 02 30 A0 11 01 13 81 E3 0A 00 8D E9 0D 40 A0 E1 05 00 A0 E1 04 10 A0 E1 06 20 A0 E1 08 30 A0 E3 ?? ?? ?? EB 14 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule closedir_8e3c94723cadb293d233ad7878d984e0 {
	meta:
		aliases = "__GI_closedir, closedir"
		size = "180"
		objfiles = "closedir@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 90 E5 01 00 74 E3 10 D0 4D E2 00 60 A0 E1 04 00 00 1A ?? ?? ?? EB 09 30 A0 E3 04 20 A0 E1 00 30 80 E5 1A 00 00 EA 18 40 80 E2 04 20 A0 E1 68 10 9F E5 0D 00 A0 E1 64 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 58 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 E0 E3 01 10 A0 E3 00 40 96 E5 0D 00 A0 E1 00 30 86 E5 3C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 0C 00 96 E5 ?? ?? ?? EB 06 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 ?? ?? ?? EB 0D 50 A0 E1 00 20 A0 E1 02 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __encode_question_7f4cfbd46ed9da8d175b8642817a7996 {
	meta:
		aliases = "__encode_question"
		size = "92"
		objfiles = "encodeq@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 A0 E1 00 00 90 E5 01 60 A0 E1 02 50 A0 E1 ?? ?? ?? EB 00 00 50 E3 70 80 BD B8 05 30 60 E0 03 00 53 E3 00 00 E0 D3 70 80 BD D8 05 30 D4 E5 00 30 C6 E7 04 30 94 E5 00 20 86 E0 01 30 C2 E5 09 30 D4 E5 02 30 C2 E5 08 30 94 E5 04 00 80 E2 03 30 C2 E5 70 80 BD E8 }
	condition:
		$pattern
}

rule __GI_xprt_unregister_408965919ca3f2748e5163d9ba0cb8ac {
	meta:
		aliases = "xprt_unregister, __GI_xprt_unregister"
		size = "152"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 A0 E1 00 50 90 E5 ?? ?? ?? EB 00 00 55 E1 70 80 BD A8 ?? ?? ?? EB B4 10 90 E5 05 21 A0 E1 02 30 91 E7 04 00 53 E1 70 80 BD 18 00 30 A0 E3 01 0B 55 E3 02 30 81 E7 02 00 00 BA 00 40 A0 E3 00 60 E0 E3 0D 00 00 EA ?? ?? ?? EB A5 C2 A0 E1 0C 31 90 E7 1F 10 05 E2 01 20 A0 E3 12 31 C3 E1 0C 31 80 E7 F4 FF FF EA ?? ?? ?? EB 00 00 90 E5 84 31 90 E7 05 00 53 E1 84 61 80 07 01 40 84 E2 ?? ?? ?? EB 00 30 90 E5 03 00 54 E1 F5 FF FF BA 70 80 BD E8 }
	condition:
		$pattern
}

rule svcunix_destroy_2fce79638867afdc3b2b470d775a2acc {
	meta:
		aliases = "svctcp_destroy, svcunix_destroy"
		size = "100"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 A0 E1 00 50 A0 E1 2C 60 90 E5 ?? ?? ?? EB 04 00 94 E4 ?? ?? ?? EB 04 30 D5 E5 01 20 D4 E5 02 24 93 E1 00 30 A0 13 05 30 C5 15 04 30 C5 15 05 00 00 1A 0C 30 96 E5 1C 30 93 E5 00 00 53 E3 08 00 86 12 0F E0 A0 11 03 F0 A0 11 06 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 70 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule strcspn_8183c189ad02d0b8c80e538a6a5317ae {
	meta:
		aliases = "__GI_strcspn, strcspn"
		size = "64"
		objfiles = "strcspn@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 A0 E1 01 60 A0 E1 00 50 A0 E3 03 00 00 EA ?? ?? ?? EB 00 00 50 E3 05 00 00 1A 01 50 85 E2 00 30 D4 E5 00 10 53 E2 06 00 A0 E1 01 40 84 E2 F6 FF FF 1A 05 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule obstack_free_00f1adef68173621008481896fdb5769 {
	meta:
		aliases = "obstack_free"
		size = "156"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 A0 E1 04 00 90 E5 01 50 A0 E1 0F 00 00 EA 28 30 D4 E5 01 00 13 E3 04 60 90 E5 20 30 94 E5 04 00 00 0A 00 10 A0 E1 24 00 94 E5 0F E0 A0 E1 03 F0 A0 E1 01 00 00 EA 0F E0 A0 E1 03 F0 A0 E1 28 30 D4 E5 02 30 83 E3 28 30 C4 E5 06 00 A0 E1 00 00 50 E3 0C 00 00 0A 05 00 50 E1 EB FF FF 2A 00 30 90 E5 05 00 53 E1 E8 FF FF 3A 00 00 50 E3 05 00 00 0A 08 50 84 E5 0C 50 84 E5 00 30 90 E5 04 00 84 E5 10 30 84 E5 70 80 BD E8 00 00 55 E3 70 80 BD 08 ?? ?? ?? EB }
	condition:
		$pattern
}

rule pthread_attr_setschedparam_7bd2c1294432a6f6f658d37ff0243f26 {
	meta:
		aliases = "__GI_pthread_attr_setschedparam, pthread_attr_setschedparam"
		size = "84"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 A0 E1 04 00 90 E5 01 60 A0 E1 ?? ?? ?? EB 00 50 A0 E1 04 00 94 E5 ?? ?? ?? EB 00 30 96 E5 00 00 53 E1 07 00 00 BA 05 00 53 E1 05 00 00 CA 08 00 84 E2 06 10 A0 E1 04 20 A0 E3 ?? ?? ?? EB 00 00 A0 E3 70 80 BD E8 16 00 A0 E3 70 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_alt_lock_32193f08a76320fd0aa056157c748c7c {
	meta:
		aliases = "__pthread_alt_lock"
		size = "116"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 A0 E1 0C D0 4D E2 04 00 80 E2 01 60 A0 E1 AF FF FF EB 00 50 94 E5 00 00 55 E3 01 30 A0 03 05 20 A0 01 00 30 84 05 09 00 00 0A 00 00 56 E3 01 00 00 1A D0 FF FF EB 00 60 A0 E1 00 30 A0 E3 08 30 8D E5 00 50 8D E5 00 D0 84 E5 04 60 8D E5 01 20 A0 E3 00 30 A0 E3 04 30 84 E5 03 00 52 E1 06 00 A0 11 E3 FF FF 1B 0C D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule _obstack_begin_1_1fd31bf30c20e6b0d8f174d9729184ff {
	meta:
		aliases = "_obstack_begin_1"
		size = "216"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 A0 E1 28 00 D0 E5 01 00 80 E3 00 00 52 E3 28 00 C4 E5 02 60 A0 11 B0 20 9F E5 04 60 A0 03 28 00 D4 E5 00 00 51 E3 02 10 A0 01 14 C0 9D E5 03 20 A0 E1 10 30 9D E5 01 50 46 E2 01 00 10 E3 20 30 84 E5 1C 20 84 E5 00 10 84 E5 18 50 84 E5 24 C0 84 E5 03 00 00 0A 0C 00 A0 E1 0F E0 A0 E1 02 F0 A0 E1 02 00 00 EA 01 00 A0 E1 0F E0 A0 E1 02 F0 A0 E1 00 00 50 E3 04 00 84 E5 84 00 00 0B 08 20 80 E2 00 10 94 E5 00 30 66 E2 02 20 85 E0 03 20 02 E0 01 10 80 E0 00 30 A0 E3 04 30 80 E5 0C 20 84 E5 08 20 84 E5 00 10 80 E5 28 30 D4 E5 02 30 C3 E3 28 30 C4 E5 28 30 D4 E5 01 00 A0 E3 04 30 C3 E3 }
	condition:
		$pattern
}

rule _obstack_begin_38f3a7985d2997e6dff6ac887270a8ab {
	meta:
		aliases = "_obstack_begin"
		size = "208"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 A0 E1 28 00 D0 E5 01 00 C0 E3 00 00 52 E3 28 00 C4 E5 02 60 A0 11 A8 20 9F E5 04 60 A0 03 28 00 D4 E5 00 00 51 E3 02 10 A0 01 03 20 A0 E1 10 30 9D E5 01 50 46 E2 01 00 10 E3 20 30 84 E5 1C 20 84 E5 00 10 84 E5 18 50 84 E5 03 00 00 0A 24 00 94 E5 0F E0 A0 E1 02 F0 A0 E1 02 00 00 EA 01 00 A0 E1 0F E0 A0 E1 02 F0 A0 E1 00 00 50 E3 04 00 84 E5 BA 00 00 0B 08 20 80 E2 00 10 94 E5 00 30 66 E2 02 20 85 E0 03 20 02 E0 01 10 80 E0 00 30 A0 E3 04 30 80 E5 0C 20 84 E5 08 20 84 E5 00 10 80 E5 28 30 D4 E5 02 30 C3 E3 28 30 C4 E5 28 30 D4 E5 01 00 A0 E3 04 30 C3 E3 28 30 C4 E5 10 10 84 E5 }
	condition:
		$pattern
}

rule do_close_6e7b5ffd6b7496a2ece97e4a3d709133 {
	meta:
		aliases = "do_close"
		size = "36"
		objfiles = "rtime@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 A0 E1 ?? ?? ?? EB 00 60 90 E5 00 50 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 60 85 E5 70 80 BD E8 }
	condition:
		$pattern
}

rule __GI_strstr_db109421f9fdc76e6903d9d3e6c53718 {
	meta:
		aliases = "strstr, __GI_strstr"
		size = "248"
		objfiles = "strstr@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 D1 E5 00 00 54 E3 70 80 BD 08 01 00 40 E2 01 30 F0 E5 00 00 53 E3 33 00 00 0A 04 00 53 E1 FA FF FF 1A 01 50 D1 E5 00 00 55 E3 01 60 81 E2 70 80 BD 08 01 30 D0 E5 01 00 80 E2 05 00 53 E1 0E 00 00 EA 01 30 D0 E5 01 00 80 E2 07 00 00 EA 00 00 53 E3 24 00 00 0A 01 30 F0 E5 04 00 53 E1 04 00 00 0A 00 00 53 E3 1F 00 00 0A 01 30 F0 E5 04 00 53 E1 F5 FF FF 1A 01 30 F0 E5 05 00 53 E1 FA FF FF 1A 01 30 D0 E5 01 20 D6 E5 01 C0 80 E2 02 00 53 E1 01 E0 86 E2 01 00 40 E2 0F 00 00 1A 00 00 52 E3 70 80 BD 08 01 30 DC E5 01 20 DE E5 01 10 8C E2 02 00 53 E1 01 30 8E E2 01 C0 81 E2 01 E0 83 E2 }
	condition:
		$pattern
}

rule __GI_fflush_948fa1fcbd688714d3b3a9a07424d35b {
	meta:
		aliases = "fflush, __GI_fflush"
		size = "172"
		objfiles = "fflush@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 50 50 E2 10 D0 4D E2 1B 00 00 0A 80 30 9F E5 03 00 55 E1 18 00 00 0A 34 60 95 E5 00 00 56 E3 0A 00 00 1A 38 40 85 E2 0D 00 A0 E1 64 30 9F E5 64 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 54 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 ?? ?? ?? EB 00 00 56 E3 00 40 A0 E1 08 00 00 1A 0D 00 A0 E1 01 10 A0 E3 30 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 02 00 00 EA 05 00 A0 E1 ?? ?? ?? EB 00 40 A0 E1 04 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule psignal_ea1f3b81fd091dbf64ca06af3cb392d9 {
	meta:
		aliases = "psignal"
		size = "100"
		objfiles = "psignal@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 50 51 E2 04 D0 4D E2 03 00 00 0A 00 30 D5 E5 00 00 53 E3 34 60 9F 15 01 00 00 1A 30 60 9F E5 06 50 A0 E1 2C 30 9F E5 00 40 93 E5 ?? ?? ?? EB 05 20 A0 E1 00 00 8D E5 06 30 A0 E1 04 00 A0 E1 14 10 9F E5 ?? ?? ?? EB 04 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdr_u_hyper_f765ea3d163cb6505a5349e6fba3a69d {
	meta:
		aliases = "__GI_xdr_u_hyper, xdr_u_hyper"
		size = "224"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 50 90 E5 00 00 55 E3 08 D0 4D E2 00 40 A0 E1 01 60 A0 E1 12 00 00 1A 00 30 91 E5 04 10 91 E5 00 30 8D E5 04 10 8D E5 04 10 8D E2 04 30 90 E5 0F E0 A0 E1 04 F0 93 E5 00 00 50 E3 05 00 A0 01 23 00 00 0A 04 00 A0 E1 04 30 94 E5 0D 10 A0 E1 0F E0 A0 E1 04 F0 93 E5 00 00 50 E2 01 00 A0 13 1B 00 00 EA 01 00 55 E3 14 00 00 1A 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 12 00 00 0A 04 00 A0 E1 04 30 94 E5 0D 10 A0 E1 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 0B 00 00 0A 0C 00 9D E8 00 40 A0 E3 03 40 A0 E1 00 30 A0 E3 02 30 83 E1 05 00 A0 E1 18 00 86 E8 04 00 00 EA 02 00 55 E3 }
	condition:
		$pattern
}

rule xdr_uint64_t_d2d5fda093f9037fc711cc4b4ef85b1f {
	meta:
		aliases = "xdr_uint64_t"
		size = "216"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 50 90 E5 01 00 55 E3 08 D0 4D E2 00 40 A0 E1 01 60 A0 E1 16 00 00 0A 03 00 00 3A 02 00 55 E3 01 00 A0 03 28 00 00 0A 26 00 00 EA 00 30 91 E5 04 10 91 E5 00 30 8D E5 04 10 8D E5 04 10 8D E2 04 30 90 E5 0F E0 A0 E1 24 F0 93 E5 00 00 50 E3 1D 00 00 0A 04 00 A0 E1 04 30 94 E5 0D 10 A0 E1 0F E0 A0 E1 24 F0 93 E5 00 00 50 E2 01 00 A0 13 15 00 00 EA 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 0E 00 00 0A 04 00 A0 E1 04 30 94 E5 0D 10 A0 E1 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 07 00 00 0A 0C 00 9D E8 00 40 A0 E3 03 40 A0 E1 00 30 A0 E3 02 30 83 E1 05 00 A0 E1 18 00 86 E8 }
	condition:
		$pattern
}

rule wcscasecmp_d9aa0f77c542f096edd7a16acd9739db {
	meta:
		aliases = "__GI_wcscasecmp, wcscasecmp"
		size = "116"
		objfiles = "wcscasecmp@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 50 A0 E1 01 60 A0 E1 04 00 00 EA 00 00 95 E5 00 00 50 E3 70 80 BD 08 04 50 85 E2 04 60 86 E2 00 20 95 E5 00 30 96 E5 03 00 52 E1 02 00 A0 E1 F5 FF FF 0A ?? ?? ?? EB 00 40 A0 E1 00 00 96 E5 ?? ?? ?? EB 00 00 54 E1 EF FF FF 0A 00 00 95 E5 ?? ?? ?? EB 00 40 A0 E1 00 00 96 E5 ?? ?? ?? EB 00 00 54 E1 01 00 A0 23 00 00 E0 33 70 80 BD E8 }
	condition:
		$pattern
}

rule xdrrec_setpos_0538d3eb135a30651bbf0aae73b4ae7a {
	meta:
		aliases = "xdrrec_setpos"
		size = "176"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 50 A0 E1 01 60 A0 E1 0C 40 90 E5 E0 FF FF EB 01 00 70 E3 00 30 A0 E1 20 00 00 0A 00 00 95 E5 00 00 50 E3 03 10 66 E0 02 00 00 0A 01 00 50 E3 1A 00 00 1A 0A 00 00 EA 10 30 94 E5 18 20 94 E5 03 00 61 E0 02 00 50 E1 14 00 00 9A 14 30 94 E5 03 00 50 E1 01 10 A0 33 10 00 84 35 10 00 00 3A 0E 00 00 EA 34 00 94 E5 00 00 51 E1 2C 20 94 E5 0A 00 00 AA 30 30 94 E5 02 20 61 E0 03 00 52 E1 06 00 00 8A 28 30 94 E5 03 00 52 E1 00 30 61 20 01 10 A0 23 34 30 84 25 2C 20 84 25 00 00 00 2A 00 10 A0 E3 01 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule confstr_911ff19059f8ed5c7c1eecb65d27e343 {
	meta:
		aliases = "confstr"
		size = "124"
		objfiles = "confstr@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 50 E2 01 50 A0 E1 02 40 A0 E1 03 00 00 1A 00 00 52 E3 00 00 51 13 05 00 00 1A 11 00 00 EA ?? ?? ?? EB 16 30 A0 E3 00 20 A0 E3 00 30 80 E5 0D 00 00 EA 0D 00 52 E3 04 00 00 9A 01 00 A0 E1 0E 20 A0 E3 28 10 9F E5 ?? ?? ?? EB 05 00 00 EA 01 00 A0 E1 01 20 42 E2 14 10 9F E5 ?? ?? ?? EB 04 30 85 E0 01 60 43 E5 0E 20 A0 E3 02 00 A0 E1 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule parse_lsda_header_97f29f14b7d3c5556ff6bbea7507f08b {
	meta:
		aliases = "parse_lsda_header"
		size = "160"
		objfiles = "unwind_c@libgcc_eh.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 50 E2 04 D0 4D E2 01 40 A0 E1 02 50 A0 E1 06 00 A0 01 ?? ?? ?? 1B 00 00 85 E5 01 10 D4 E4 FF 00 51 E3 04 20 A0 E1 04 00 85 05 03 00 00 0A 06 00 A0 E1 04 30 85 E2 E1 FF FF EB 00 20 A0 E1 01 30 D2 E4 FF 00 53 E3 14 30 C5 E5 00 30 A0 03 02 00 A0 E1 0C 30 85 05 0D 40 A0 01 05 00 00 0A 0D 10 A0 E1 42 FF FF EB 00 30 9D E5 03 30 80 E0 0C 30 85 E5 0D 40 A0 E1 01 30 D0 E4 0D 10 A0 E1 15 30 C5 E5 3A FF FF EB 00 30 9D E5 03 20 80 E0 10 20 85 E5 04 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule malloc_stats_83d40d48e7412fd803fe33c3c7ca95c1 {
	meta:
		aliases = "malloc_stats"
		size = "120"
		objfiles = "mallinfo@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 50 E2 44 D0 4D E2 5C 30 9F 05 1C 00 8D E2 00 60 93 05 ?? ?? ?? EB 28 C0 9D E5 04 C0 8D E5 30 C0 9D E5 10 C0 8D E5 3C C0 9D E5 2C E0 9D E5 1C 40 9D E5 38 50 9D E5 14 C0 8D E5 40 C0 9D E5 0E 30 85 E0 06 00 A0 E1 04 20 8E E0 1C 10 9F E5 18 C0 8D E5 00 40 8D E5 08 E0 8D E5 0C 50 8D E5 ?? ?? ?? EB 44 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule re_comp_284b44d37ed5db3ccb896972e08ba1c9 {
	meta:
		aliases = "re_comp"
		size = "232"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 50 E2 C0 40 9F E5 04 00 00 1A 00 30 94 E5 00 00 53 E3 B4 00 9F 05 70 80 BD 08 28 00 00 EA 00 30 94 E5 00 00 53 E3 04 50 A0 E1 0D 00 00 1A C8 00 A0 E3 ?? ?? ?? EB 00 00 50 E3 00 00 84 E5 06 00 00 0A C8 30 A0 E3 01 0C A0 E3 04 30 84 E5 ?? ?? ?? EB 00 00 50 E3 10 00 84 E5 01 00 00 1A 6C 00 9F E5 70 80 BD E8 5C 40 9F E5 1C 30 D4 E5 80 30 83 E3 1C 30 C4 E5 06 00 A0 E1 ?? ?? ?? EB 50 30 9F E5 00 10 A0 E1 00 20 93 E5 06 00 A0 E1 04 30 A0 E1 C3 F6 FF EB 00 00 50 E3 08 00 00 0A 34 20 9F E5 80 30 A0 E1 02 10 83 E0 02 30 D3 E7 01 20 D1 E5 02 34 83 E1 20 20 9F E5 02 00 83 E0 70 80 BD E8 }
	condition:
		$pattern
}

rule byte_common_op_match_null_stri_0dc1f51ab99678b99f11598d0edef132 {
	meta:
		aliases = "byte_common_op_match_null_string_p"
		size = "320"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 00 00 90 E5 04 D0 4D E2 00 00 8D E5 00 C0 A0 E1 01 30 DC E4 0C 00 53 E3 00 C0 8D E5 02 50 A0 E1 08 00 00 8A 09 00 53 E3 3B 00 00 2A 06 00 53 E3 0E 00 00 0A 08 00 53 E3 33 00 00 0A 00 00 53 E3 35 00 00 0A 38 00 00 EA 15 00 53 E3 1E 00 00 0A 02 00 00 8A 0D 00 53 E3 33 00 00 1A 12 00 00 EA 1A 30 43 E2 03 00 53 E3 2F 00 00 8A 2A 00 00 EA 01 40 D0 E5 0D 00 A0 E1 4E 00 00 EB 04 41 A0 E1 04 30 D5 E7 03 30 03 E2 03 00 53 E3 04 20 95 07 03 30 00 02 03 20 C2 03 02 20 83 01 04 20 85 07 00 00 50 E3 1C 00 00 1A 1F 00 00 EA 01 30 DC E5 01 20 D0 E5 03 3C A0 E1 43 28 92 E0 03 30 80 52 }
	condition:
		$pattern
}

rule __GI_getrpcbyname_b4753be57184238a7cc672ca006ff647 {
	meta:
		aliases = "getrpcbyname, __GI_getrpcbyname"
		size = "104"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 00 00 A0 E3 ?? ?? ?? EB 0E 00 00 EA 00 00 95 E5 06 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 0D 00 00 0A 04 40 95 E5 04 00 00 EA 06 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 07 00 00 0A 04 40 84 E2 00 00 94 E5 00 00 50 E3 F7 FF FF 1A ?? ?? ?? EB 00 50 50 E2 ED FF FF 1A ?? ?? ?? EB 05 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule _pthread_cleanup_push_b4a02c28be6cf809bfc1200b33bcdc55 {
	meta:
		aliases = "_pthread_cleanup_push"
		size = "60"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 01 40 A0 E1 02 50 A0 E1 AB FF FF EB 3C 30 90 E5 00 00 53 E3 30 00 86 E8 0C 30 86 E5 02 00 00 0A 03 00 56 E1 00 30 A0 23 0C 30 86 25 3C 60 80 E5 70 80 BD E8 }
	condition:
		$pattern
}

rule _pthread_cleanup_push_defer_80c9bd9ce4fe1f1677c151cdfc1804c4 {
	meta:
		aliases = "__pthread_cleanup_push_defer, _pthread_cleanup_push_defer"
		size = "76"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 02 50 A0 E1 01 40 A0 E1 C8 FF FF EB 30 00 86 E8 3C 20 90 E5 41 30 D0 E5 00 00 52 E3 08 30 86 E5 0C 20 86 E5 02 00 00 0A 02 00 56 E1 00 30 A0 23 0C 30 86 25 00 30 A0 E3 3C 60 80 E5 41 30 C0 E5 70 80 BD E8 }
	condition:
		$pattern
}

rule strndup_f06fd0b48888fa24232c848400bda320 {
	meta:
		aliases = "__GI_strndup, strndup"
		size = "60"
		objfiles = "strndup@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 ?? ?? ?? EB 00 40 A0 E1 01 00 80 E2 ?? ?? ?? EB 00 50 50 E2 04 00 00 0A 06 10 A0 E1 04 20 A0 E1 ?? ?? ?? EB 00 30 A0 E3 04 30 C5 E7 05 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule __GI_remove_eb133b81e5f8a90d58f1fce908ce3dc5 {
	meta:
		aliases = "remove, __GI_remove"
		size = "64"
		objfiles = "remove@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 ?? ?? ?? EB 00 40 A0 E1 06 00 A0 E1 00 50 94 E5 ?? ?? ?? EB 00 00 50 E3 70 80 BD A8 00 30 94 E5 14 00 53 E3 70 80 BD 18 06 00 A0 E1 00 50 84 E5 70 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule wcsdup_f9f4ae3f66f8fa1ca1866e7fb88a3faa {
	meta:
		aliases = "wcsdup"
		size = "52"
		objfiles = "wcsdup@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 ?? ?? ?? EB 01 00 80 E2 00 41 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 50 50 E2 06 10 A0 11 04 20 A0 11 ?? ?? ?? 1B 05 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule __GI_strdup_4454023922d5b5b1f9744e3ea9bfa567 {
	meta:
		aliases = "strdup, __GI_strdup"
		size = "48"
		objfiles = "strdup@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 ?? ?? ?? EB 01 40 80 E2 04 00 A0 E1 ?? ?? ?? EB 00 50 50 E2 06 10 A0 11 04 20 A0 11 ?? ?? ?? 1B 05 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_perform_cleanup_71155a6f45949bc936879d51f406dbd9 {
	meta:
		aliases = "__pthread_perform_cleanup"
		size = "76"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 DD FF FF EB 3C 40 90 E5 00 50 A0 E1 05 00 00 EA 06 00 54 E1 05 00 00 9A 04 00 94 E5 0F E0 A0 E1 00 F0 94 E5 0C 40 94 E5 00 00 54 E3 F7 FF FF 1A FC 30 95 E5 00 00 53 E3 70 80 BD 08 70 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule setkey_594e24828693bf562c1d8ca06d20a013 {
	meta:
		aliases = "setkey"
		size = "116"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { 70 40 2D E9 00 C0 A0 E3 08 D0 4D E2 5C 60 9F E5 0D 40 A0 E1 0C 50 A0 E1 0E 00 00 EA 0C E0 84 E0 05 10 A0 E1 0C 50 C4 E7 07 00 00 EA 00 30 D0 E5 01 00 13 E3 00 30 DE 15 01 20 D6 17 02 30 83 11 00 30 CE 15 01 00 80 E2 01 10 81 E2 07 00 51 E3 F5 FF FF DA 01 C0 8C E2 07 00 5C E3 EE FF FF DA 04 00 A0 E1 BD FE FF EB 08 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule div_eb82b5d26b5b9e158a3a0c3c0b08f507 {
	meta:
		aliases = "div"
		size = "52"
		objfiles = "div@libc.a"
	strings:
		$pattern = { 70 40 2D E9 01 40 A0 E1 00 50 A0 E1 02 10 A0 E1 04 00 A0 E1 02 60 A0 E1 ?? ?? ?? EB 96 00 03 E0 00 00 85 E5 04 40 63 E0 05 00 A0 E1 04 40 85 E5 70 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_cleanup_pop_restore_112760ba84f37950a7efa1dd633ac0c7 {
	meta:
		aliases = "_pthread_cleanup_pop_restore, __pthread_cleanup_pop_restore"
		size = "96"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 01 40 A0 E1 00 50 A0 E1 9D FF FF EB 00 00 54 E3 00 60 A0 E1 04 00 95 15 0F E0 A0 11 00 F0 95 15 42 30 D6 E5 08 10 85 E2 06 00 91 E8 00 00 53 E3 3C 20 86 E5 41 10 C6 E5 70 80 BD 08 41 20 D6 E5 40 30 D6 E5 02 34 83 E1 01 0C 53 E3 70 80 BD 18 00 00 E0 E3 0D 10 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __GI_fputws_unlocked_0c812d83ea9d970f7192c147d9775ccb {
	meta:
		aliases = "fputws_unlocked, __GI_fputws_unlocked"
		size = "52"
		objfiles = "fputws_unlocked@libc.a"
	strings:
		$pattern = { 70 40 2D E9 01 40 A0 E1 00 50 A0 E1 ?? ?? ?? EB 00 60 A0 E1 06 10 A0 E1 05 00 A0 E1 04 20 A0 E1 ?? ?? ?? EB 06 00 50 E1 00 00 E0 13 00 00 A0 03 70 80 BD E8 }
	condition:
		$pattern
}

rule shm_open_e92f6b22c7f05979fe0df1eeca43a61e {
	meta:
		aliases = "shm_open"
		size = "60"
		objfiles = "shm@librt.a"
	strings:
		$pattern = { 70 40 2D E9 01 40 A0 E1 02 50 A0 E1 DF FF FF EB 00 60 50 E2 00 40 E0 03 05 00 00 0A 02 17 84 E3 05 20 A0 E1 ?? ?? ?? EB 00 40 A0 E1 06 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule read_encoded_value_0c6d02878350871bc572f23ae37809a7 {
	meta:
		aliases = "read_encoded_value"
		size = "56"
		objfiles = "unwind_c@libgcc_eh.a"
	strings:
		$pattern = { 70 40 2D E9 01 40 A0 E1 FF 40 04 E2 00 10 A0 E1 04 00 A0 E1 02 50 A0 E1 03 60 A0 E1 D8 FF FF EB 05 20 A0 E1 00 10 A0 E1 06 30 A0 E1 04 00 A0 E1 70 40 BD E8 79 FF FF EA }
	condition:
		$pattern
}

rule __GI_fputs_unlocked_48e3905df4b4856817f022f6fcec5473 {
	meta:
		aliases = "fputs_unlocked, __GI_fputs_unlocked"
		size = "52"
		objfiles = "fputs_unlocked@libc.a"
	strings:
		$pattern = { 70 40 2D E9 01 50 A0 E1 00 40 A0 E1 ?? ?? ?? EB 00 60 A0 E1 05 30 A0 E1 04 00 A0 E1 01 10 A0 E3 06 20 A0 E1 ?? ?? ?? EB 06 00 50 E1 00 00 E0 13 70 80 BD E8 }
	condition:
		$pattern
}

rule pthread_attr_setguardsize_a6855025b438a014e9ab67ee075a2925 {
	meta:
		aliases = "__pthread_attr_setguardsize, pthread_attr_setguardsize"
		size = "64"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 01 50 A0 E1 00 60 A0 E1 ?? ?? ?? EB 00 40 A0 E1 01 00 40 E2 04 10 A0 E1 05 00 80 E0 ?? ?? ?? EB 90 04 04 E0 20 30 96 E5 03 00 54 E1 16 00 A0 23 00 00 A0 33 14 40 86 35 70 80 BD E8 }
	condition:
		$pattern
}

rule __xstat_conv_c5ad3ba03798859911027d0886550d15 {
	meta:
		aliases = "__xstat_conv"
		size = "204"
		objfiles = "xstatconv@libc.a"
	strings:
		$pattern = { 70 40 2D E9 01 60 A0 E1 00 50 A0 E1 00 10 A0 E3 58 20 A0 E3 06 00 A0 E1 ?? ?? ?? EB 00 30 95 E5 04 20 95 E5 00 40 A0 E3 18 00 86 E8 0C 20 86 E5 09 20 D5 E5 08 30 D5 E5 02 34 83 E1 10 30 86 E5 0B 20 D5 E5 0A 30 D5 E5 02 34 83 E1 14 30 86 E5 0D 20 D5 E5 0C 30 D5 E5 02 34 83 E1 18 30 86 E5 14 30 95 E5 0E C0 D5 E5 0F E0 D5 E5 10 00 95 E5 2C 30 86 E5 18 30 95 E5 30 30 86 E5 1C 30 95 E5 34 30 86 E5 20 30 95 E5 24 20 95 E5 38 30 86 E5 3C 20 86 E5 28 30 95 E5 2C 20 95 E5 40 30 86 E5 44 20 86 E5 30 20 85 E2 0C 00 92 E8 0E C4 8C E1 00 10 A0 E3 1C C0 86 E5 20 00 86 E5 24 10 86 E5 4C 30 86 E5 48 20 86 E5 }
	condition:
		$pattern
}

rule updwtmp_96fd1d35fbbaaeeced0599854d865138 {
	meta:
		aliases = "updwtmp"
		size = "92"
		objfiles = "wtent@libc.a"
	strings:
		$pattern = { 70 40 2D E9 01 60 A0 E1 48 10 9F E5 ?? ?? ?? EB 00 40 50 E2 70 80 BD B8 01 10 A0 E3 00 20 A0 E3 ?? ?? ?? EB 00 50 50 E2 70 80 BD 18 06 10 A0 E1 04 00 A0 E1 06 2D A0 E3 ?? ?? ?? EB 04 00 A0 E1 05 10 A0 E1 05 20 A0 E1 ?? ?? ?? EB 04 00 A0 E1 70 40 BD E8 ?? ?? ?? EA 01 04 00 00 }
	condition:
		$pattern
}

rule difftime_bb721b70ab87165fd6b94f0587ca196d {
	meta:
		aliases = "difftime"
		size = "52"
		objfiles = "difftime@libc.a"
	strings:
		$pattern = { 70 40 2D E9 01 60 A0 E1 ?? ?? ?? EB 00 40 A0 E1 06 00 A0 E1 01 50 A0 E1 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 70 80 BD E8 }
	condition:
		$pattern
}

rule scalbf_4a44cd37ef35a0b922cd1ed5d81e2ab8 {
	meta:
		aliases = "remainderf, hypotf, fmodf, powf, copysignf, atan2f, scalbf"
		size = "56"
		objfiles = "powf@libm.a, copysignf@libm.a, fmodf@libm.a, atan2f@libm.a, scalbf@libm.a"
	strings:
		$pattern = { 70 40 2D E9 01 60 A0 E1 ?? ?? ?? EB 00 40 A0 E1 06 00 A0 E1 01 50 A0 E1 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 70 80 BD E8 }
	condition:
		$pattern
}

rule __get_hosts_byaddr_r_6dd96e3e79e37a6dd076f996fa93970d {
	meta:
		aliases = "__get_hosts_byaddr_r"
		size = "148"
		objfiles = "get_hosts_byaddr_r@libc.a"
	strings:
		$pattern = { 70 40 2D E9 02 00 52 E3 44 D0 4D E2 02 50 A0 E1 03 60 A0 E1 02 00 00 0A 0A 00 52 E3 19 00 00 1A 01 00 00 EA 04 00 51 E3 00 00 00 EA 10 00 51 E3 14 00 00 1A 16 40 8D E2 00 10 A0 E1 04 20 A0 E1 2E 30 A0 E3 05 00 A0 E1 ?? ?? ?? EB 54 C0 9D E5 04 C0 8D E5 58 C0 9D E5 08 C0 8D E5 5C C0 9D E5 0C C0 8D E5 60 C0 9D E5 04 10 A0 E1 05 20 A0 E1 02 30 A0 E3 00 00 A0 E3 00 60 8D E5 10 C0 8D E5 ?? ?? ?? EB 00 00 00 EA 00 00 A0 E3 44 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule svc_find_a2132f35ec5c1f6bbe8eff7e2b314979 {
	meta:
		aliases = "svc_find"
		size = "80"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { 70 40 2D E9 02 50 A0 E1 00 60 A0 E1 01 40 A0 E1 ?? ?? ?? EB B8 00 90 E5 00 20 A0 E3 07 00 00 EA 04 30 90 E5 06 00 53 E1 02 00 00 1A 08 30 90 E5 04 00 53 E1 03 00 00 0A 00 20 A0 E1 00 00 90 E5 00 00 50 E3 F5 FF FF 1A 00 20 85 E5 70 80 BD E8 }
	condition:
		$pattern
}

rule ldexp_56e903529f3d2514160cc428c0acd184 {
	meta:
		aliases = "__GI_ldexp, ldexp"
		size = "144"
		objfiles = "s_ldexp@libm.a"
	strings:
		$pattern = { 70 40 2D E9 02 60 A0 E1 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? EB 00 00 50 E3 19 00 00 0A 04 00 A0 E1 05 10 A0 E1 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? EB 00 00 50 E3 12 00 00 0A 06 20 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? EB 00 00 50 E3 06 00 00 0A 04 00 A0 E1 05 10 A0 E1 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? EB 00 00 50 E3 02 00 00 1A ?? ?? ?? EB 22 30 A0 E3 00 30 80 E5 04 00 A0 E1 05 10 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule msync_1823f96336634c69108f5ddfbc5d7589 {
	meta:
		aliases = "write, connect, __GI_waitpid, lseek, recvmsg, sendmsg, read, waitpid, accept, msync"
		size = "76"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 04 D0 4D E2 00 40 A0 E1 01 50 A0 E1 02 60 A0 E1 0D 10 A0 E1 01 00 A0 E3 ?? ?? ?? EB 05 10 A0 E1 06 20 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 10 A0 E3 00 40 A0 E1 00 00 9D E5 ?? ?? ?? EB 04 00 A0 E1 04 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule byte_alt_match_null_string_p_54ce1e8d0426987801b81a35a7d64483 {
	meta:
		aliases = "byte_alt_match_null_string_p"
		size = "128"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 70 40 2D E9 04 D0 4D E2 04 40 8D E2 04 00 24 E5 01 50 A0 E1 02 60 A0 E1 0F 00 00 EA 00 30 DC E5 0F 00 53 E3 09 00 00 1A 01 30 8C E2 00 30 8D E5 01 30 D3 E5 01 20 DC E5 03 3C A0 E1 43 28 82 E0 03 30 8C E2 02 30 83 E0 00 30 8D E5 02 00 00 EA 9A FF FF EB 00 00 50 E3 06 00 00 0A 00 C0 9D E5 05 00 5C E1 0D 00 A0 E1 05 10 A0 E1 06 20 A0 E1 E9 FF FF 3A 01 00 A0 E3 04 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule __fresetlockfiles_736d46f00632f181a9f7824a5dd0e8b8 {
	meta:
		aliases = "__fresetlockfiles"
		size = "100"
		objfiles = "lockfile@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 04 D0 4D E2 0D 00 A0 E1 ?? ?? ?? EB 0D 00 A0 E1 01 10 A0 E3 ?? ?? ?? EB 38 30 9F E5 38 60 9F E5 00 50 93 E5 0D 40 A0 E1 02 00 00 EA 0F E0 A0 E1 06 F0 A0 E1 20 50 95 E5 00 00 55 E3 38 00 85 E2 0D 10 A0 E1 F8 FF FF 1A 0D 00 A0 E1 ?? ?? ?? EB 04 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ether_ntoa_r_8600950ba51f116eb718aecac334bf80 {
	meta:
		aliases = "__GI_ether_ntoa_r, ether_ntoa_r"
		size = "76"
		objfiles = "ether_addr@libc.a"
	strings:
		$pattern = { 70 40 2D E9 05 60 D0 E5 02 C0 D0 E5 03 E0 D0 E5 04 40 D0 E5 00 20 D0 E5 01 30 D0 E5 10 D0 4D E2 01 50 A0 E1 01 00 A0 E1 18 10 9F E5 00 50 8D E8 08 40 8D E5 0C 60 8D E5 ?? ?? ?? EB 05 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule logwtmp_6af930ca05410258a64a042f2684721c {
	meta:
		aliases = "logwtmp"
		size = "172"
		objfiles = "logwtmp@libutil.a"
	strings:
		$pattern = { 70 40 2D E9 06 DD 4D E2 01 40 A0 E1 00 50 A0 E1 02 60 A0 E1 0D 00 A0 E1 00 10 A0 E3 06 2D A0 E3 ?? ?? ?? EB 00 00 54 E3 03 00 00 0A 00 30 D4 E5 00 00 53 E3 07 20 A0 13 00 00 00 1A 08 20 A0 E3 42 34 A0 E1 01 30 CD E5 00 20 CD E5 ?? ?? ?? EB 05 10 A0 E1 04 00 8D E5 1F 20 A0 E3 08 00 8D E2 ?? ?? ?? EB 04 10 A0 E1 1F 20 A0 E3 2C 00 8D E2 ?? ?? ?? EB 06 10 A0 E1 FF 20 A0 E3 4C 00 8D E2 ?? ?? ?? EB 00 10 A0 E3 55 0F 8D E2 ?? ?? ?? EB 0D 10 A0 E1 0C 00 9F E5 0D 40 A0 E1 ?? ?? ?? EB 06 DD 8D E2 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sigaction_ebbc66a8c8953c3e70405c3aae45121a {
	meta:
		aliases = "__GI_sigaction, sigaction"
		size = "300"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 08 31 9F E5 00 30 93 E5 03 00 50 E1 14 D0 4D E2 00 50 A0 E1 01 40 A0 E1 02 60 A0 E1 36 00 00 0A EC 30 9F E5 00 30 93 E5 03 00 50 E1 32 00 00 0A E0 30 9F E5 00 30 93 E5 03 00 50 E1 01 00 00 1A 00 00 50 E3 2C 00 00 CA 00 00 54 E3 04 10 A0 01 16 00 00 0A 04 C0 A0 E1 0F 00 BC E8 0D C0 A0 E1 0F 00 AC E8 01 00 50 E3 00 30 A0 93 01 30 A0 83 00 00 55 E3 00 30 A0 D3 10 20 94 E5 00 00 53 E3 00 20 8C E5 08 00 00 0A 40 00 55 E3 06 00 00 CA 04 00 11 E3 80 30 9F 15 80 30 9F 05 0D 10 A0 E1 0D 10 A0 01 00 30 8D E5 00 00 00 EA 0D 10 A0 E1 05 00 A0 E1 06 20 A0 E1 ?? ?? ?? EB 01 00 70 E3 10 00 00 0A }
	condition:
		$pattern
}

rule __pthread_wait_for_restart_sig_fd4b5c8a6e82a9daae97f0240f0bb041 {
	meta:
		aliases = "__pthread_wait_for_restart_signal"
		size = "92"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 08 D0 4D E2 00 60 A0 E1 00 10 A0 E3 0D 20 A0 E1 02 00 A0 E3 0D 40 A0 E1 ?? ?? ?? EB 30 50 9F E5 0D 00 A0 E1 00 10 95 E5 ?? ?? ?? EB 00 30 A0 E3 20 30 86 E5 0D 00 A0 E1 ?? ?? ?? EB 20 20 96 E5 00 30 95 E5 03 00 52 E1 F9 FF FF 1A 08 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule modff_059986036bea64ad3f6de2cee2894a70 {
	meta:
		aliases = "modff"
		size = "64"
		objfiles = "modff@libm.a"
	strings:
		$pattern = { 70 40 2D E9 08 D0 4D E2 01 60 A0 E1 ?? ?? ?? EB 0D 20 A0 E1 ?? ?? ?? EB 00 40 A0 E1 01 50 A0 E1 03 00 9D E8 ?? ?? ?? EB 05 10 A0 E1 00 00 86 E5 04 00 A0 E1 ?? ?? ?? EB 08 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule _Unwind_SjLj_Resume_a32ab5e2664aae7f6eaf57b440d3b65e {
	meta:
		aliases = "_Unwind_SjLj_Resume"
		size = "96"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { 70 40 2D E9 08 D0 4D E2 04 60 8D E2 00 40 A0 E1 06 00 A0 E1 63 FF FF EB 0C 30 94 E5 04 20 9D E5 00 00 53 E3 00 20 8D E5 05 00 00 1A 04 00 A0 E1 0D 10 A0 E1 BC FF FF EB 07 00 50 E3 04 00 00 0A ?? ?? ?? EB 04 00 A0 E1 0D 10 A0 E1 5C FF FF EB F8 FF FF EA 06 00 A0 E1 0D 10 A0 E1 DB FF FF EB }
	condition:
		$pattern
}

rule _Unwind_SjLj_Resume_or_Rethrow_8d9b17bdc610654b0c52b8c47e8ee09d {
	meta:
		aliases = "_Unwind_SjLj_Resume_or_Rethrow"
		size = "92"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { 70 40 2D E9 0C 30 90 E5 00 00 53 E3 08 D0 4D E2 00 40 A0 E1 0A 00 00 0A 04 60 8D E2 06 00 A0 E1 FA FE FF EB 04 30 9D E5 04 00 A0 E1 0D 10 A0 E1 00 30 8D E5 FC FE FF EB 07 00 50 E3 03 00 00 0A ?? ?? ?? EB ?? ?? ?? EB 08 D0 8D E2 70 80 BD E8 06 00 A0 E1 0D 10 A0 E1 76 FF FF EB }
	condition:
		$pattern
}

rule pthread_rwlock_tryrdlock_d4907b01a3666bfc9ca7ba8437e75ace {
	meta:
		aliases = "pthread_rwlock_tryrdlock"
		size = "180"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 0C D0 4D E2 00 40 A0 E1 76 FF FF EB 0C 30 8D E2 04 00 23 E5 04 20 8D E2 03 00 A0 E1 04 10 A0 E1 0D 30 A0 E1 BC FF FF EB 08 10 9D E5 00 60 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 10 A0 E3 04 00 A0 E1 20 FF FF EB 00 00 50 E3 08 30 94 15 01 30 83 12 10 50 A0 03 08 30 84 15 00 50 A0 13 04 00 A0 E1 ?? ?? ?? EB 00 00 55 E3 0D 00 00 1A 00 00 56 E3 02 00 00 1A 00 30 9D E5 00 00 53 E3 08 00 00 0A 04 20 9D E5 00 00 52 E3 08 20 9D 05 08 30 92 15 50 31 92 05 01 30 83 12 01 30 83 02 08 30 82 15 50 31 82 05 05 00 A0 E1 0C D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule __GI_pthread_cond_wait_c3e2722b2d0d13d027e742356da550a0 {
	meta:
		aliases = "pthread_cond_wait, __GI_pthread_cond_wait"
		size = "408"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 0C D0 4D E2 01 60 A0 E1 00 50 A0 E1 46 FF FF EB 0C 30 96 E5 03 00 53 E3 00 00 53 13 08 00 8D E5 04 00 00 0A 08 20 9D E5 08 30 96 E5 02 00 53 E1 16 00 A0 13 51 00 00 1A 48 31 9F E5 08 20 9D E5 04 30 8D E5 00 30 A0 E3 00 50 8D E5 41 31 C2 E5 08 00 9D E5 0D 10 A0 E1 0B FF FF EB 05 00 A0 E1 08 10 9D E5 ?? ?? ?? EB 08 30 9D E5 42 30 D3 E5 00 00 53 E3 04 00 00 0A 08 30 9D E5 40 30 D3 E5 00 00 53 E3 01 40 A0 03 03 00 00 0A 08 10 9D E5 08 00 85 E2 C7 FE FF EB 00 40 A0 E3 05 00 A0 E1 ?? ?? ?? EB 00 00 54 E3 03 00 00 0A 08 00 9D E5 00 10 A0 E3 F4 FE FF EB 24 00 00 EA 06 00 A0 E1 C4 30 9F E5 }
	condition:
		$pattern
}

rule pthread_rwlock_rdlock_cf009b54a8accc4a24e313fb94dbe85b {
	meta:
		aliases = "pthread_rwlock_rdlock"
		size = "224"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 0C D0 4D E2 0C 30 8D E2 00 20 A0 E3 04 20 23 E5 00 40 A0 E1 04 10 A0 E1 03 00 A0 E1 04 20 8D E2 0D 30 A0 E1 8F FF FF EB 10 60 84 E2 00 50 A0 E1 08 30 9D E5 00 00 53 E3 01 00 00 1A 3C FF FF EB 08 00 8D E5 04 00 A0 E1 08 10 9D E5 ?? ?? ?? EB 04 00 A0 E1 05 10 A0 E1 ED FE FF EB 00 00 50 E3 06 00 A0 E1 06 00 00 1A 08 10 9D E5 DC FE FF EB 04 00 A0 E1 ?? ?? ?? EB 08 00 9D E5 5D FF FF EB EA FF FF EA 08 30 94 E5 01 30 83 E2 08 30 84 E5 04 00 A0 E1 ?? ?? ?? EB 00 00 55 E3 02 00 00 1A 00 30 9D E5 00 00 53 E3 08 00 00 0A 04 20 9D E5 00 00 52 E3 08 20 9D 05 08 30 92 15 50 31 92 05 01 30 83 12 }
	condition:
		$pattern
}

rule search_object_f629ff68edc56855bbcec2cdb4335206 {
	meta:
		aliases = "search_object"
		size = "224"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { 70 40 2D E9 10 30 D0 E5 01 00 13 E3 00 40 A0 E1 01 50 A0 E1 13 00 00 0A 04 00 13 E3 0D 00 00 1A 10 30 94 E5 07 30 C3 E3 83 3A A0 E1 A3 3A A0 E1 00 00 53 E3 03 00 00 1A 04 00 A0 E1 05 10 A0 E1 70 40 BD E8 C2 FC FF EA 04 00 A0 E1 05 10 A0 E1 70 40 BD E8 46 FD FF EA 04 00 A0 E1 05 10 A0 E1 70 40 BD E8 D5 FD FF EA 95 FF FF EB 00 30 94 E5 05 00 53 E1 09 00 00 8A 10 30 D4 E5 01 00 13 E3 E4 FF FF 1A 02 00 13 E3 06 00 00 1A 0C 10 94 E5 04 00 A0 E1 05 20 A0 E1 70 40 BD E8 2F FE FF EA 00 00 A0 E3 70 80 BD E8 0C 30 94 E5 00 10 93 E5 00 00 51 E3 F9 FF FF 0A 03 60 A0 E1 04 00 A0 E1 05 20 A0 E1 25 FE FF EB }
	condition:
		$pattern
}

rule syscall_c4d0f5e9829eac31e3eac02d1e472124 {
	meta:
		aliases = "syscall"
		size = "48"
		objfiles = "syscall@libc.a"
	strings:
		$pattern = { 70 40 2D E9 10 40 8D E2 70 00 94 E8 71 00 90 EF 01 0A 70 E3 00 40 A0 E1 70 80 BD 98 ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 00 E0 E3 70 80 BD E8 }
	condition:
		$pattern
}

rule utmpname_1960753e33da4e9721b1d4902b0e639b {
	meta:
		aliases = "utmpname"
		size = "192"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { 70 40 2D E9 10 D0 4D E2 00 50 A0 E1 8C 10 9F E5 0D 00 A0 E1 88 20 9F E5 88 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 78 00 9F E5 7C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 55 E3 09 00 00 0A 6C 60 9F E5 6C 40 9F E5 00 00 96 E5 04 00 50 E1 ?? ?? ?? 1B 05 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 04 00 A0 01 00 00 86 E5 4C 40 9F E5 00 00 94 E5 00 00 50 E3 02 00 00 BA ?? ?? ?? EB 00 30 E0 E3 00 30 84 E5 0D 00 A0 E1 01 10 A0 E3 2C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 A0 E3 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_lockf_2f82b575a4f404d2c6a40a6d8778b6e1 {
	meta:
		aliases = "lockf, __GI_lockf"
		size = "276"
		objfiles = "lockf@libc.a"
	strings:
		$pattern = { 70 40 2D E9 10 D0 4D E2 02 50 A0 E1 00 60 A0 E1 10 20 A0 E3 01 40 A0 E1 0D 00 A0 E1 00 10 A0 E3 ?? ?? ?? EB 00 20 A0 E3 01 30 A0 E3 02 30 CD E5 24 00 8D E9 03 20 CD E5 03 00 54 E3 04 F1 9F 97 2A 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 30 A0 E3 0D 20 A0 E1 06 00 A0 E1 05 10 A0 E3 01 30 CD E5 00 30 CD E5 ?? ?? ?? EB 00 00 50 E3 00 20 E0 B3 22 00 00 BA 01 30 DD E5 00 20 DD E5 03 3C A0 E1 43 28 82 E1 02 00 52 E3 1B 00 00 0A 0C 40 9D E5 ?? ?? ?? EB 00 00 54 E1 17 00 00 0A ?? ?? ?? EB 00 20 E0 E3 0D 30 A0 E3 11 00 00 EA 06 10 A0 E3 02 30 A0 E3 03 00 00 EA 07 10 A0 E3 00 00 00 EA }
	condition:
		$pattern
}

rule endhostent_289172910d9a547bb95915acf718dc05 {
	meta:
		aliases = "endhostent"
		size = "144"
		objfiles = "gethostent_r@libc.a"
	strings:
		$pattern = { 70 40 2D E9 10 D0 4D E2 0D 00 A0 E1 60 10 9F E5 60 20 9F E5 60 30 9F E5 60 50 9F E5 0F E0 A0 E1 03 F0 A0 E1 58 30 9F E5 48 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 95 E5 48 30 9F E5 00 40 A0 E3 00 00 50 E3 0D 60 A0 E1 00 40 83 E5 01 00 00 0A ?? ?? ?? EB 00 40 85 E5 0D 00 A0 E1 01 10 A0 E3 24 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __new_exitfn_e543cc7d2deef7584778c0d5123a2e49 {
	meta:
		aliases = "__new_exitfn"
		size = "260"
		objfiles = "__exit_handler@libc.a"
	strings:
		$pattern = { 70 40 2D E9 10 D0 4D E2 CC 10 9F E5 0D 00 A0 E1 C8 20 9F E5 C8 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 C0 30 9F E5 B4 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 B4 30 9F E5 B4 50 9F E5 00 30 93 E5 00 10 95 E5 01 30 83 E2 03 00 51 E1 0E 00 00 AA A0 60 9F E5 01 12 A0 E1 05 1D 81 E2 00 00 96 E5 ?? ?? ?? EB 00 40 50 E2 03 00 00 1A ?? ?? ?? EB 0C 30 A0 E3 00 30 80 E5 10 00 00 EA 00 30 95 E5 14 30 83 E2 00 40 86 E5 00 30 85 E5 5C E0 9F E5 60 30 9F E5 00 20 9E E5 00 00 93 E5 01 C0 82 E2 01 30 A0 E3 02 22 A0 E1 00 30 82 E7 48 10 9F E5 48 30 9F E5 00 C0 8E E5 00 10 83 E5 00 40 82 E0 0D 00 A0 E1 01 10 A0 E3 34 30 9F E5 }
	condition:
		$pattern
}

rule gethostbyaddr_21f16a76c958d8f1d4e978dde3c0e6a6 {
	meta:
		aliases = "__GI_gethostbyaddr, gethostbyaddr"
		size = "92"
		objfiles = "gethostbyaddr@libc.a"
	strings:
		$pattern = { 70 40 2D E9 14 D0 4D E2 00 60 A0 E1 01 40 A0 E1 02 50 A0 E1 ?? ?? ?? EB 34 C0 9F E5 00 C0 8D E5 76 CF A0 E3 0C 00 8D E5 04 C0 8D E5 04 10 A0 E1 10 C0 8D E2 06 00 A0 E1 05 20 A0 E1 14 30 9F E5 08 C0 8D E5 ?? ?? ?? EB 10 00 9D E5 14 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule readdir_a65d6ed1c981fd66e66981e9452202db {
	meta:
		aliases = "__GI_readdir, readdir"
		size = "208"
		objfiles = "readdir@libc.a"
	strings:
		$pattern = { 70 40 2D E9 18 40 80 E2 10 D0 4D E2 AC 10 9F E5 04 20 A0 E1 A8 30 9F E5 00 50 A0 E1 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 94 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 60 A0 E3 0C 00 95 E9 02 00 53 E1 08 00 00 8A 00 00 95 E5 0C 10 95 E5 14 20 95 E5 ?? ?? ?? EB 00 00 50 E3 00 40 A0 D3 0E 00 00 DA 08 00 85 E5 04 60 85 E5 04 10 95 E5 0C C0 95 E5 0C 40 81 E0 04 20 94 E5 08 30 D4 E5 09 00 D4 E5 10 20 85 E5 0C 20 91 E7 00 34 83 E1 01 30 83 E0 00 00 52 E3 04 30 85 E5 E6 FF FF 0A 0D 00 A0 E1 01 10 A0 E3 1C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule readdir64_246436ef8a6b03b04399d3899d019660 {
	meta:
		aliases = "__GI_readdir64, readdir64"
		size = "212"
		objfiles = "readdir64@libc.a"
	strings:
		$pattern = { 70 40 2D E9 18 40 80 E2 10 D0 4D E2 B0 10 9F E5 04 20 A0 E1 AC 30 9F E5 00 50 A0 E1 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 98 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 60 A0 E3 0C 00 95 E9 02 00 53 E1 08 00 00 8A 00 00 95 E5 0C 10 95 E5 14 20 95 E5 ?? ?? ?? EB 00 00 50 E3 00 40 A0 D3 0F 00 00 DA 08 00 85 E5 04 60 85 E5 04 20 95 E5 0C 00 95 E5 00 40 82 E0 11 10 D4 E5 10 30 D4 E5 00 C0 92 E7 04 00 94 E5 01 34 83 E1 08 10 94 E5 02 30 83 E0 00 C0 9C E1 04 30 85 E5 10 10 85 E5 E5 FF FF 0A 0D 00 A0 E1 01 10 A0 E3 1C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule rewinddir_99f208f67edd93295add277db8a22154 {
	meta:
		aliases = "rewinddir"
		size = "136"
		objfiles = "rewinddir@libc.a"
	strings:
		$pattern = { 70 40 2D E9 18 50 80 E2 10 D0 4D E2 00 40 A0 E1 05 20 A0 E1 5C 10 9F E5 0D 00 A0 E1 58 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 50 30 9F E5 05 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 00 10 A0 E3 01 20 A0 E1 00 00 94 E5 ?? ?? ?? EB 00 30 A0 E3 10 30 84 E5 08 30 84 E5 04 30 84 E5 0D 00 A0 E1 01 10 A0 E3 1C 30 9F E5 0D 60 A0 E1 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_authnone_create_bd2039786a18c8a016861156802b08f3 {
	meta:
		aliases = "authnone_create, __GI_authnone_create"
		size = "208"
		objfiles = "auth_none@libc.a"
	strings:
		$pattern = { 70 40 2D E9 18 D0 4D E2 ?? ?? ?? EB 98 50 90 E5 00 00 55 E3 00 40 A0 E1 06 00 00 1A 01 00 A0 E3 40 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 22 00 00 0A 98 00 84 E5 00 50 A0 E1 3C C0 95 E5 00 00 5C E3 1D 00 00 1A 7C 30 9F E5 07 00 93 E8 78 30 9F E5 0C 40 85 E2 07 00 84 E8 07 00 85 E8 20 30 85 E5 14 20 A0 E3 0C 30 A0 E1 0D 00 A0 E1 28 10 85 E2 ?? ?? ?? EB 05 10 A0 E1 0D 00 A0 E1 ?? ?? ?? EB 04 10 A0 E1 0D 00 A0 E1 ?? ?? ?? EB 04 30 9D E5 0D 00 A0 E1 0F E0 A0 E1 10 F0 93 E5 3C 00 85 E5 04 30 9D E5 1C 30 93 E5 00 00 53 E3 0D 60 A0 E1 0D 00 A0 11 0F E0 A0 11 03 F0 A0 11 05 00 A0 E1 18 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule __new_sem_post_8b680821c41502fccfa7a84b5dd7902f {
	meta:
		aliases = "sem_post, __new_sem_post"
		size = "288"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 1C D0 4D E2 00 40 A0 E1 0C FF FF EB 54 60 90 E5 00 00 56 E3 20 00 00 1A 00 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 0C 50 94 E5 00 00 55 E3 0F 00 00 1A 08 30 94 E5 06 01 73 E3 06 00 00 1A ?? ?? ?? EB 22 30 A0 E3 00 30 80 E5 04 00 A0 E1 ?? ?? ?? EB 00 20 E0 E3 2C 00 00 EA 01 30 83 E2 08 30 84 E5 04 00 A0 E1 ?? ?? ?? EB 05 20 A0 E1 26 00 00 EA 08 30 95 E5 04 00 A0 E1 0C 30 84 E5 08 60 85 E5 ?? ?? ?? EB 01 30 A0 E3 42 31 C5 E5 05 00 A0 E1 ?? ?? ?? EB 06 20 A0 E1 1B 00 00 EA 74 30 9F E5 00 30 93 E5 00 00 53 E3 07 00 00 AA ?? ?? ?? EB 00 00 50 E3 04 00 00 AA ?? ?? ?? EB 0B 30 A0 E3 00 20 E0 E3 }
	condition:
		$pattern
}

rule __free_initshell_memory_7965d9501befdc2dd1bb3d621fc33225 {
	meta:
		aliases = "__free_initshell_memory"
		size = "52"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { 70 40 2D E9 20 40 9F E5 20 60 9F E5 00 00 94 E5 ?? ?? ?? EB 00 50 A0 E3 00 00 96 E5 00 50 84 E5 ?? ?? ?? EB 00 50 86 E5 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_if_nametoindex_38926585ef650227ec998ec15f7e7580 {
	meta:
		aliases = "if_nametoindex, __GI_if_nametoindex"
		size = "108"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { 70 40 2D E9 20 D0 4D E2 00 60 A0 E1 ?? ?? ?? EB 00 50 50 E2 0C 00 00 BA 06 10 A0 E1 10 20 A0 E3 0D 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 0D 20 A0 E1 30 10 9F E5 ?? ?? ?? EB 00 00 50 E3 0D 40 A0 E1 03 00 00 AA 05 00 A0 E1 ?? ?? ?? EB 00 00 A0 E3 02 00 00 EA 05 00 A0 E1 ?? ?? ?? EB 10 00 9D E5 20 D0 8D E2 70 80 BD E8 33 89 00 00 }
	condition:
		$pattern
}

rule marshal_new_auth_4bf81f019957a5b63fec6a26ba7ea0e8 {
	meta:
		aliases = "marshal_new_auth"
		size = "152"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { 70 40 2D E9 24 60 90 E5 18 D0 4D E2 00 40 A0 E1 19 2E A0 E3 00 30 A0 E3 0D 00 A0 E1 1C 10 86 E2 ?? ?? ?? EB 0D 00 A0 E1 04 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 0D 50 A0 E1 04 00 00 0A 0C 10 84 E2 0D 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 02 00 00 1A 3C 00 9F E5 ?? ?? ?? EB 04 00 00 EA 0D 00 A0 E1 04 30 9D E5 0F E0 A0 E1 10 F0 93 E5 AC 01 86 E5 04 30 9D E5 1C 30 93 E5 00 00 53 E3 0D 00 A0 11 0F E0 A0 11 03 F0 A0 11 01 00 A0 E3 18 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tcgetattr_ae3e1438d0feb83a09970f7d37ec5b96 {
	meta:
		aliases = "__GI_tcgetattr, tcgetattr"
		size = "120"
		objfiles = "tcgetattr@libc.a"
	strings:
		$pattern = { 70 40 2D E9 24 D0 4D E2 01 40 A0 E1 0D 20 A0 E1 5C 10 9F E5 ?? ?? ?? EB 00 50 50 E2 0D 60 A0 E1 10 00 00 1A 04 20 9D E5 08 10 9D E5 0C 00 9D E5 10 C0 DD E5 00 30 9D E5 04 20 84 E5 08 10 84 E5 0C 00 84 E5 11 10 8D E2 13 20 A0 E3 00 30 84 E5 10 C0 C4 E5 11 00 84 E2 ?? ?? ?? EB 05 10 A0 E1 0D 20 A0 E3 ?? ?? ?? EB 05 00 A0 E1 24 D0 8D E2 70 80 BD E8 01 54 00 00 }
	condition:
		$pattern
}

rule putc_60ed37c17c0065234bf7a07494647792 {
	meta:
		aliases = "__GI_putc, fputc, __GI_fputc, putc"
		size = "212"
		objfiles = "fputc@libc.a"
	strings:
		$pattern = { 70 40 2D E9 34 30 91 E5 00 00 53 E3 10 D0 4D E2 01 50 A0 E1 00 60 A0 E1 0A 00 00 0A 10 20 91 E5 1C 30 91 E5 03 00 52 E1 FF 30 00 32 01 30 C2 34 03 40 A0 31 10 20 81 35 1E 00 00 3A ?? ?? ?? EB 00 40 A0 E1 1B 00 00 EA 38 40 81 E2 04 20 A0 E1 6C 10 9F E5 0D 00 A0 E1 68 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 60 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 10 20 95 E5 1C 30 95 E5 03 00 52 E1 FF 30 06 32 01 30 C2 34 03 40 A0 31 10 20 85 35 03 00 00 3A 06 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 40 A0 E1 0D 00 A0 E1 01 10 A0 E3 1C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule feof_ef2e4a7999bb287c3dc51a95c0fb104a {
	meta:
		aliases = "feof"
		size = "132"
		objfiles = "feof@libc.a"
	strings:
		$pattern = { 70 40 2D E9 34 60 90 E5 00 00 56 E3 10 D0 4D E2 00 50 A0 E1 0A 00 00 1A 38 40 80 E2 50 30 9F E5 0D 00 A0 E1 4C 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 3C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 01 20 D5 E5 00 30 D5 E5 00 00 56 E3 02 44 83 E1 0D 00 A0 01 01 10 A0 03 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 04 00 04 E2 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ferror_6484dd219411a92732fbc4ae7ccf178e {
	meta:
		aliases = "ferror"
		size = "132"
		objfiles = "ferror@libc.a"
	strings:
		$pattern = { 70 40 2D E9 34 60 90 E5 00 00 56 E3 10 D0 4D E2 00 50 A0 E1 0A 00 00 1A 38 40 80 E2 50 30 9F E5 0D 00 A0 E1 4C 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 3C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 01 20 D5 E5 00 30 D5 E5 00 00 56 E3 02 44 83 E1 0D 00 A0 01 01 10 A0 03 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 08 00 04 E2 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fgetwc_f330e9cb98e8883cb9149cfdf83c99af {
	meta:
		aliases = "__GI_fgetwc, fileno, getwc, __GI_fileno, fgetwc"
		size = "132"
		objfiles = "fileno@libc.a, fgetwc@libc.a"
	strings:
		$pattern = { 70 40 2D E9 34 60 90 E5 00 00 56 E3 10 D0 4D E2 00 50 A0 E1 0A 00 00 1A 38 40 80 E2 50 30 9F E5 0D 00 A0 E1 4C 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 3C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 ?? ?? ?? EB 00 00 56 E3 00 40 A0 E1 0D 00 A0 01 01 10 A0 03 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 04 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clearerr_33a587dd9a3a926eb9d3d631ca3bf71f {
	meta:
		aliases = "clearerr"
		size = "136"
		objfiles = "clearerr@libc.a"
	strings:
		$pattern = { 70 40 2D E9 34 60 90 E5 00 00 56 E3 10 D0 4D E2 00 50 A0 E1 0A 00 00 1A 38 40 80 E2 54 30 9F E5 0D 00 A0 E1 50 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 40 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 95 E5 0C 30 C3 E3 43 24 A0 E1 00 00 56 E3 01 20 C5 E5 00 30 C5 E5 0D 00 A0 01 01 10 A0 03 18 30 9F 05 0F E0 A0 01 03 F0 A0 01 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule rewind_0ef2f45b6c716eb132bc67c01df48b66 {
	meta:
		aliases = "__GI_rewind, rewind"
		size = "152"
		objfiles = "rewind@libc.a"
	strings:
		$pattern = { 70 40 2D E9 34 60 90 E5 00 00 56 E3 10 D0 4D E2 00 50 A0 E1 0A 00 00 1A 38 40 80 E2 64 30 9F E5 0D 00 A0 E1 60 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 50 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 95 E5 08 30 C3 E3 43 24 A0 E1 00 10 A0 E3 01 20 C5 E5 00 30 C5 E5 05 00 A0 E1 01 20 A0 E1 ?? ?? ?? EB 00 00 56 E3 0D 00 A0 01 01 10 A0 03 18 30 9F 05 0F E0 A0 01 03 F0 A0 01 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ftello64_715fa52e2b89757d676239d6dbdd9dc8 {
	meta:
		aliases = "__GI_ftello64, ftello64"
		size = "228"
		objfiles = "ftello64@libc.a"
	strings:
		$pattern = { 70 40 2D E9 34 60 90 E5 18 D0 4D E2 00 30 A0 E3 00 40 A0 E3 00 00 56 E3 00 50 A0 E1 10 30 8D E5 14 40 8D E5 0A 00 00 1A 38 40 80 E2 A0 30 9F E5 0D 00 A0 E1 9C 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 8C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 20 D5 E5 01 30 D5 E5 03 24 82 E1 11 2D 02 E2 11 0D 52 E3 10 40 8D E2 01 20 A0 13 02 20 A0 03 05 00 A0 E1 04 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 04 00 00 BA 05 00 A0 E1 04 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 03 00 00 AA 00 30 E0 E3 00 40 E0 E3 10 30 8D E5 14 40 8D E5 00 00 56 E3 0D 00 A0 01 01 10 A0 03 20 30 9F 05 0F E0 A0 01 03 F0 A0 01 10 00 8D E2 }
	condition:
		$pattern
}

rule __GI___ns_name_uncompress_cd777b96e7823f66de90030b1d9e1ad9 {
	meta:
		aliases = "__ns_name_uncompress, __GI___ns_name_uncompress"
		size = "84"
		objfiles = "ns_name@libc.a"
	strings:
		$pattern = { 70 40 2D E9 41 DF 4D E2 05 60 8D E2 FF C0 A0 E3 03 50 A0 E1 06 30 A0 E1 00 C0 8D E5 ?? ?? ?? EB 01 00 70 E3 00 40 A0 E1 05 00 00 0A 06 00 A0 E1 05 10 A0 E1 14 21 9D E5 ?? ?? ?? EB 01 00 70 E3 00 00 00 1A 00 40 E0 E3 04 00 A0 E1 41 DF 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule __popcountdi2_186e5f51e7e0e4907dce70ef4787bcba {
	meta:
		aliases = "__popcountdi2"
		size = "84"
		objfiles = "_popcountdi2@libgcc.a"
	strings:
		$pattern = { 70 40 2D E9 44 E0 9F E5 FF 30 00 E2 00 50 A0 E1 03 00 DE E7 01 60 A0 E1 08 C0 A0 E3 35 3C A0 E1 20 20 6C E2 16 32 83 E1 20 10 5C E2 36 31 A0 51 FF 30 03 E2 36 4C A0 E1 03 20 DE E7 08 C0 8C E2 40 00 5C E3 02 00 80 E0 F3 FF FF 1A 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule srandom_bc90e476496ce4e3f2c23b5f49d6b9d9 {
	meta:
		aliases = "srand, srandom"
		size = "124"
		objfiles = "random@libc.a"
	strings:
		$pattern = { 70 40 2D E9 58 40 9F E5 10 D0 4D E2 04 20 A0 E1 00 60 A0 E1 4C 10 9F E5 0D 00 A0 E1 48 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 40 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 06 00 A0 E1 30 10 9F E5 ?? ?? ?? EB 0D 00 A0 E1 01 10 A0 E3 24 30 9F E5 0D 50 A0 E1 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule iruserfopen_0936cfec1241c460e786a114b3ffdfdb {
	meta:
		aliases = "iruserfopen"
		size = "176"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { 70 40 2D E9 58 D0 4D E2 01 50 A0 E1 0D 10 A0 E1 00 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 0D 60 A0 E1 1D 00 00 1A 10 30 9D E5 0F 3A 03 E2 02 09 53 E3 00 40 A0 11 19 00 00 1A 04 00 A0 E1 68 10 9F E5 ?? ?? ?? EB 00 40 50 E2 14 00 00 0A ?? ?? ?? EB 0D 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 0A 00 00 BA 18 30 9D E5 00 00 53 E3 01 00 00 0A 05 00 53 E1 05 00 00 1A 10 30 9D E5 12 00 13 E3 02 00 00 1A 14 30 9D E5 01 00 53 E3 04 00 00 9A 00 00 54 E3 02 00 00 0A 04 00 A0 E1 ?? ?? ?? EB 00 40 A0 E3 04 00 A0 E1 58 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getutid_4d4d4bb5c779abbb787cb9b46ccfd5d6 {
	meta:
		aliases = "__GI_getutid, getutid"
		size = "124"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { 70 40 2D E9 5C 40 9F E5 10 D0 4D E2 04 20 A0 E1 54 10 9F E5 00 60 A0 E1 50 30 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 44 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 06 00 A0 E1 98 FF FF EB 01 10 A0 E3 00 40 A0 E1 28 30 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 0D 50 A0 E1 04 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __close_nameservers_1659170f9c12b5a3b8ba9b8b449adb95 {
	meta:
		aliases = "__close_nameservers"
		size = "124"
		objfiles = "closenameservers@libc.a"
	strings:
		$pattern = { 70 40 2D E9 5C 40 9F E5 5C 30 9F E5 00 00 94 E5 03 00 50 E1 ?? ?? ?? 1B 50 30 9F E5 50 60 9F E5 50 50 9F E5 00 20 A0 E3 00 20 83 E5 00 20 84 E5 03 00 00 EA 00 30 93 E5 02 01 93 E7 00 20 86 E5 ?? ?? ?? EB 00 40 96 E5 00 00 54 E3 01 20 44 E2 05 30 A0 E1 F6 FF FF 1A 00 00 95 E5 ?? ?? ?? EB 00 40 85 E5 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sethostent_fc5e7da197fe5f2dedb2b9f0e5bf268d {
	meta:
		aliases = "sethostent"
		size = "128"
		objfiles = "gethostent_r@libc.a"
	strings:
		$pattern = { 70 40 2D E9 5C 50 9F E5 10 D0 4D E2 58 10 9F E5 05 20 A0 E1 00 40 A0 E1 50 30 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 40 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 38 30 9F E5 00 40 54 E2 01 40 A0 13 00 40 83 E5 0D 00 A0 E1 01 10 A0 E3 24 30 9F E5 0D 60 A0 E1 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getdomainname_a536411d8281989efcf80a4b1a855393 {
	meta:
		aliases = "__GI_getdomainname, getdomainname"
		size = "112"
		objfiles = "getdomainname@libc.a"
	strings:
		$pattern = { 70 40 2D E9 62 DF 4D E2 00 60 A0 E1 0D 00 A0 E1 01 40 A0 E1 ?? ?? ?? EB 01 00 70 E3 00 20 A0 01 0F 00 00 0A 51 5F 8D E2 01 50 85 E2 05 00 A0 E1 ?? ?? ?? EB 01 00 80 E2 04 00 50 E1 04 00 00 9A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 03 00 00 EA 06 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 20 A0 E3 02 00 A0 E1 62 DF 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule __GI_gethostname_fc8e345a0f5b42315d7d42b353956e69 {
	meta:
		aliases = "gethostname, __GI_gethostname"
		size = "112"
		objfiles = "gethostname@libc.a"
	strings:
		$pattern = { 70 40 2D E9 62 DF 4D E2 00 60 A0 E1 0D 00 A0 E1 01 50 A0 E1 ?? ?? ?? EB 01 00 70 E3 0D 40 A0 E1 00 20 A0 01 0E 00 00 0A 41 40 8D E2 04 00 A0 E1 ?? ?? ?? EB 01 00 80 E2 05 00 50 E1 04 00 00 9A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 03 00 00 EA 06 00 A0 E1 04 10 A0 E1 ?? ?? ?? EB 00 20 A0 E3 02 00 A0 E1 62 DF 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule dl_iterate_phdr_60640020b95ba55ffe08bbe60cd253b2 {
	meta:
		aliases = "dl_iterate_phdr"
		size = "128"
		objfiles = "dl_iterate_phdr@libc.a"
	strings:
		$pattern = { 70 40 2D E9 68 30 9F E5 00 40 93 E5 00 00 54 E3 10 D0 4D E2 00 50 A0 E1 01 60 A0 E1 0F 00 00 0A 50 30 9F E5 00 C0 93 E5 00 30 A0 E3 00 30 8D E5 44 30 9F E5 44 E4 A0 E1 0D 00 A0 E1 10 10 A0 E3 06 20 A0 E1 08 10 8D E9 0D E0 CD E5 0C 40 CD E5 0F E0 A0 E1 05 F0 A0 E1 00 00 50 E3 02 00 00 1A 05 00 A0 E1 06 10 A0 E1 ?? ?? ?? EB 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clearenv_c79bf37b97efc442cefaf8ee0c33071b {
	meta:
		aliases = "clearenv"
		size = "144"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { 70 40 2D E9 68 40 9F E5 10 D0 4D E2 04 20 A0 E1 60 10 9F E5 60 60 9F E5 0D 00 A0 E1 5C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 54 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 00 00 96 E5 ?? ?? ?? EB 40 30 9F E5 00 40 A0 E3 0D 00 A0 E1 00 40 83 E5 01 10 A0 E3 00 40 86 E5 2C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 0D 50 A0 E1 04 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_strcasecmp_9c4dd0ad3945145242450bfe68b1aa68 {
	meta:
		aliases = "strcasecmp, __GI_strcasecmp"
		size = "124"
		objfiles = "strcasecmp@libc.a"
	strings:
		$pattern = { 70 40 2D E9 6C 60 9F E5 00 40 A0 E1 01 50 A0 E1 00 00 A0 E3 05 00 54 E1 10 00 00 0A 00 E0 D4 E5 00 30 D5 E5 00 C0 96 E5 83 30 A0 E1 8E E0 A0 E1 0C 20 8E E0 0C 00 83 E0 01 10 D2 E5 01 00 D0 E5 0C 20 D3 E7 0C 30 DE E7 00 0C A0 E1 01 1C A0 E1 41 38 83 E1 40 28 82 E1 02 00 53 E0 70 80 BD 18 00 30 D4 E5 00 00 53 E3 01 50 85 E2 01 40 84 E2 E7 FF FF 1A 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pmap_getmaps_1ccc9ec452169d84e1b059832b0a1587 {
	meta:
		aliases = "pmap_getmaps"
		size = "212"
		objfiles = "pm_getmaps@libc.a"
	strings:
		$pattern = { 70 40 2D E9 6F 30 A0 E3 18 D0 4D E2 00 60 A0 E3 00 C0 E0 E3 03 30 C0 E5 02 60 C0 E5 10 C0 8D E5 33 C0 8C E2 00 C0 8D E5 94 10 9F E5 7D CF A0 E3 02 20 A0 E3 10 30 8D E2 00 50 A0 E1 04 C0 8D E5 14 60 8D E5 ?? ?? ?? EB 00 40 50 E2 16 00 00 0A 04 30 94 E5 00 C0 93 E5 68 30 9F E5 3C 10 A0 E3 06 20 A0 E1 00 30 8D E5 14 30 8D E2 08 10 8D E5 0C 20 8D E5 04 30 8D E5 04 10 A0 E3 06 30 A0 E1 44 20 9F E5 0F E0 A0 E1 0C F0 A0 E1 06 00 50 E1 04 00 A0 11 34 10 9F 15 ?? ?? ?? 1B 04 00 A0 E1 04 30 94 E5 0F E0 A0 E1 10 F0 93 E5 00 30 A0 E3 03 30 C5 E5 02 30 C5 E5 14 00 9D E5 18 D0 8D E2 70 80 BD E8 A0 86 01 00 }
	condition:
		$pattern
}

rule tan_96cfc2433269e88cd28f35e1b477876c {
	meta:
		aliases = "__GI_tan, tan"
		size = "132"
		objfiles = "s_tan@libm.a"
	strings:
		$pattern = { 70 40 2D E9 70 30 9F E5 02 C1 C0 E3 03 00 5C E1 14 D0 4D E2 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 00 20 A0 D3 00 30 A0 D3 01 C0 A0 D3 0E 00 00 DA 48 30 9F E5 03 00 5C E1 03 00 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 09 00 00 EA 04 20 8D E2 ?? ?? ?? EB 01 C0 00 E2 8C C0 A0 E1 03 00 9D E9 0C 20 8D E2 0C 00 92 E8 01 C0 6C E2 00 C0 8D E5 ?? ?? ?? EB 14 D0 8D E2 70 80 BD E8 FB 21 E9 3F FF FF EF 7F }
	condition:
		$pattern
}

rule ulckpwdf_d74d8dcdce4e7e73c7742d375ba9538a {
	meta:
		aliases = "ulckpwdf"
		size = "148"
		objfiles = "lckpwdf@libc.a"
	strings:
		$pattern = { 70 40 2D E9 70 50 9F E5 00 00 95 E5 01 00 70 E3 10 D0 4D E2 00 60 A0 01 14 00 00 0A 5C 10 9F E5 5C 20 9F E5 0D 00 A0 E1 58 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 50 30 9F E5 44 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 95 E5 ?? ?? ?? EB 00 30 E0 E3 00 60 A0 E1 00 30 85 E5 0D 00 A0 E1 01 10 A0 E3 28 30 9F E5 0D 40 A0 E1 0F E0 A0 E1 03 F0 A0 E1 06 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule cfsetspeed_e93ba95e4d5b91ff6658b7d81c8d074a {
	meta:
		aliases = "cfsetspeed"
		size = "144"
		objfiles = "cfsetspeed@libc.a"
	strings:
		$pattern = { 70 40 2D E9 80 C0 9F E5 00 60 A0 E1 01 50 A0 E1 00 20 A0 E3 14 00 00 EA 04 40 91 E5 04 00 55 E1 05 00 00 1A 05 10 A0 E1 06 00 A0 E1 ?? ?? ?? EB 06 00 A0 E1 05 10 A0 E1 07 00 00 EA 82 31 9C E7 03 00 55 E1 07 00 00 1A 04 10 A0 E1 06 00 A0 E1 ?? ?? ?? EB 06 00 A0 E1 04 10 A0 E1 ?? ?? ?? EB 00 00 A0 E3 70 80 BD E8 01 20 82 E2 1F 00 52 E3 82 11 8C E0 E7 FF FF 9A ?? ?? ?? EB 16 30 A0 E3 00 30 80 E5 00 00 E0 E3 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __exit_handler_99d8aa5ea7c2adce90c9d58e9580cdfa {
	meta:
		aliases = "__exit_handler"
		size = "152"
		objfiles = "__exit_handler@libc.a"
	strings:
		$pattern = { 70 40 2D E9 84 50 9F E5 84 60 9F E5 00 40 A0 E1 15 00 00 EA 00 30 93 E5 00 20 93 E7 02 00 52 E3 00 10 85 E5 00 30 83 E0 02 00 00 0A 03 00 52 E3 0D 00 00 1A 07 00 00 EA 04 20 93 E5 00 00 52 E3 04 00 A0 E1 08 00 00 0A 08 10 93 E5 0F E0 A0 E1 02 F0 A0 E1 04 00 00 EA 04 20 93 E5 00 00 52 E3 08 00 93 15 0F E0 A0 11 02 F0 A0 11 00 30 95 E5 01 10 43 E2 00 00 53 E3 01 02 A0 E1 06 30 A0 E1 E3 FF FF 1A 00 00 96 E5 70 40 BD E8 ?? ?? ?? EA ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __do_global_dtors_aux_ea117dfd965ad88c61a947b95cf01c78 {
	meta:
		aliases = "__do_global_dtors_aux"
		size = "316"
		objfiles = "crtbeginS"
	strings:
		$pattern = { 70 40 2D E9 88 50 9F E5 88 60 9F E5 05 50 8F E0 06 30 D5 E7 00 00 53 E3 70 80 BD 18 78 30 9F E5 03 20 95 E7 00 00 52 E3 70 30 9F 15 03 00 95 17 0F E0 A0 11 02 F0 A0 11 64 40 9F E5 04 30 95 E7 00 20 93 E5 00 00 52 E3 07 00 00 0A 04 30 83 E2 04 30 85 E7 0F E0 A0 E1 02 F0 A0 E1 04 30 95 E7 00 20 93 E5 00 00 52 E3 F7 FF FF 1A 34 30 9F E5 03 30 95 E7 00 00 53 E3 2C 00 9F 15 00 00 85 10 0F E0 A0 11 03 F0 A0 11 01 30 A0 E3 06 30 C5 E7 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 E0 2D E5 04 F0 9D E4 10 40 2D E9 58 40 9F E5 58 30 9F E5 04 40 8F E0 }
	condition:
		$pattern
}

rule __old_sem_wait_8f4557b4fd1c84dbe05b5f4d81afb9bd {
	meta:
		aliases = "__old_sem_wait"
		size = "440"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 90 31 9F E5 00 30 93 E5 0C D0 4D E2 03 00 5D E1 00 50 A0 E1 0D 20 A0 E1 7C 01 9F 25 12 00 00 2A 78 31 9F E5 00 30 93 E5 03 00 5D E1 04 00 00 3A 6C 31 9F E5 00 30 93 E5 03 00 5D E1 64 01 9F 35 09 00 00 3A 60 31 9F E5 00 30 93 E5 00 00 53 E3 01 00 00 0A ?? ?? ?? EB 03 00 00 EA A2 3A E0 E1 83 3A E0 E1 57 0F 43 E2 03 00 40 E2 00 30 A0 E3 00 30 8D E5 34 31 9F E5 08 00 8D E5 04 30 8D E5 0D 60 A0 E1 08 00 9D E5 0D 10 A0 E1 C9 FF FF EB 00 10 95 E5 01 00 51 E3 00 30 A0 03 01 30 01 12 00 00 53 E3 08 40 9D 05 08 30 9D 05 02 40 41 12 08 10 83 05 05 00 A0 E1 04 20 A0 E1 6B FF FF EB 00 00 50 E3 }
	condition:
		$pattern
}

rule pthread_onexit_process_371d8e2818d289aa10a119fe698b182a {
	meta:
		aliases = "pthread_onexit_process"
		size = "180"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 94 60 9F E5 00 30 96 E5 00 00 53 E3 1C D0 4D E2 00 50 A0 E1 1E 00 00 BA 69 FF FF EB 02 30 A0 E3 29 00 8D E8 00 40 A0 E1 0D 50 A0 E1 0D 10 A0 E1 1C 20 A0 E3 00 00 96 E5 ?? ?? ?? EB 01 00 70 E3 03 00 00 1A ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 F5 FF FF 0A 04 00 A0 E1 E6 FF FF EB 3C 30 9F E5 00 30 93 E5 03 00 54 E1 09 00 00 1A 30 30 9F E5 02 21 A0 E3 14 00 93 E5 00 10 A0 E3 ?? ?? ?? EB 20 30 9F E5 00 20 A0 E3 00 20 83 E5 18 30 9F E5 00 20 83 E5 1C D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule gets_8b77787f47e09edb9be56cd2c7b2ecf3 {
	meta:
		aliases = "gets"
		size = "200"
		objfiles = "gets@libc.a"
	strings:
		$pattern = { 70 40 2D E9 A8 40 9F E5 00 20 94 E5 34 60 92 E5 00 00 56 E3 10 D0 4D E2 00 50 A0 E1 01 00 00 0A 05 40 A0 E1 0C 00 00 EA 0D 00 A0 E1 38 20 82 E2 80 10 9F E5 80 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 94 E5 74 30 9F E5 38 00 80 E2 0F E0 A0 E1 03 F0 A0 E1 F1 FF FF EA 01 40 84 E2 ?? ?? ?? EB 01 00 70 E3 FF 30 00 E2 02 00 00 0A 0A 00 53 E3 00 30 C4 E5 F7 FF FF 1A 01 00 70 E3 04 00 55 11 00 30 A0 13 01 30 A0 03 00 50 A0 03 00 30 C4 15 00 00 56 E3 0D 00 A0 01 01 10 A0 03 20 30 9F 05 0F E0 A0 01 03 F0 A0 01 05 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule token_1f3ba1649c02a5f9cb0481de26f990ca {
	meta:
		aliases = "token"
		size = "468"
		objfiles = "ruserpass@libc.a"
	strings:
		$pattern = { 70 40 2D E9 B8 21 9F E5 00 30 92 E5 00 30 D3 E5 0C 00 13 E3 02 40 A0 01 67 00 00 1A 00 10 94 E5 10 20 91 E5 18 30 91 E5 03 00 52 E1 01 00 D2 34 10 20 81 35 03 00 00 3A 01 00 A0 E1 ?? ?? ?? EB 01 00 70 E3 5C 00 00 0A 09 30 40 E2 20 00 50 E3 01 00 53 13 F0 FF FF 9A 2C 00 50 E3 EE FF FF 0A 60 31 9F E5 22 00 50 E3 54 51 9F 05 03 40 A0 01 0B 00 00 0A 18 00 00 EA 5C 00 50 E3 07 00 00 1A 00 10 95 E5 10 20 91 E5 18 30 91 E5 03 00 52 E1 01 00 D2 34 10 20 81 35 01 00 A0 21 ?? ?? ?? 2B 01 00 C4 E4 00 10 95 E5 10 20 91 E5 18 30 91 E5 03 00 52 E1 01 00 D2 34 10 20 81 35 03 00 00 3A 01 00 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __GI_cos_1599077e396e0671e7a82dd9578c0a04 {
	meta:
		aliases = "cos, __GI_cos"
		size = "212"
		objfiles = "s_cos@libm.a"
	strings:
		$pattern = { 70 40 2D E9 C0 30 9F E5 02 C1 C0 E3 03 00 5C E1 14 D0 4D E2 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 00 20 A0 D3 00 30 A0 D3 12 00 00 DA 9C 30 9F E5 03 00 5C E1 03 00 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 1C 00 00 EA 04 20 8D E2 ?? ?? ?? EB 03 C0 00 E2 01 00 5C E3 08 00 00 0A 02 00 5C E3 0C 00 00 0A 00 00 5C E3 03 00 9D E9 0C 20 8D E2 0C 00 92 E8 0D 00 00 1A ?? ?? ?? EB 0E 00 00 EA 03 00 9D E9 0C 20 8D E2 0C 00 92 E8 00 C0 8D E5 ?? ?? ?? EB 03 00 00 EA 03 00 9D E9 0C 20 8D E2 0C 00 92 E8 ?? ?? ?? EB 02 21 80 E2 03 00 00 EA 01 C0 A0 E3 00 C0 8D E5 ?? ?? ?? EB 00 20 A0 E1 02 00 A0 E1 14 D0 8D E2 }
	condition:
		$pattern
}

rule imaxabs_9e60e6755f51fc2f2cad304c792b98f3 {
	meta:
		aliases = "llabs, imaxabs"
		size = "40"
		objfiles = "llabs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 C1 3F A0 E1 00 50 23 E0 01 60 23 E0 03 40 A0 E1 05 00 A0 E1 06 10 A0 E1 03 00 50 E0 04 10 C1 E0 70 80 BD E8 }
	condition:
		$pattern
}

rule __GI_sin_6f66f0f5d1bf043b356aaceabfbb1566 {
	meta:
		aliases = "sin, __GI_sin"
		size = "220"
		objfiles = "s_sin@libm.a"
	strings:
		$pattern = { 70 40 2D E9 C8 30 9F E5 02 C1 C0 E3 03 00 5C E1 14 D0 4D E2 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 00 20 A0 D3 00 30 A0 D3 00 C0 A0 D3 13 00 00 DA A0 30 9F E5 03 00 5C E1 03 00 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 13 00 00 EA 04 20 8D E2 ?? ?? ?? EB 03 00 00 E2 01 00 50 E3 0A 00 00 0A 02 00 50 E3 0E 00 00 0A 00 00 50 E3 0C 20 8D E2 0C 00 92 E8 03 00 9D E9 10 00 00 1A 01 C0 A0 E3 00 C0 8D E5 ?? ?? ?? EB 03 00 00 EA 03 00 9D E9 0C 20 8D E2 0C 00 92 E8 ?? ?? ?? EB 00 20 A0 E1 08 00 00 EA 01 C0 A0 E3 03 00 9D E9 0C 20 8D E2 0C 00 92 E8 00 C0 8D E5 ?? ?? ?? EB 00 00 00 EA ?? ?? ?? EB 02 21 80 E2 }
	condition:
		$pattern
}

rule strchr_751ee7706823363fd76afffeb48237e6 {
	meta:
		aliases = "index, __GI_strchr, strchr"
		size = "236"
		objfiles = "strchr@libc.a"
	strings:
		$pattern = { 70 40 2D E9 FF 40 01 E2 05 00 00 EA 00 30 D0 E5 04 00 53 E1 70 80 BD 08 00 00 53 E3 2E 00 00 0A 01 00 80 E2 03 00 10 E3 F7 FF FF 1A 04 34 84 E1 00 50 A0 E1 03 68 83 E1 04 30 95 E4 A0 00 9F E5 06 20 23 E0 00 C0 82 E0 98 10 9F E5 00 00 83 E0 03 30 E0 E1 00 30 23 E0 01 E0 A0 E1 02 20 E0 E1 01 10 03 E0 0C 20 22 E0 00 00 51 E3 0E E0 02 E0 01 00 00 1A 00 00 5E E3 EE FF FF 0A 04 30 55 E5 04 00 53 E1 04 00 45 E2 70 80 BD 08 00 00 53 E3 11 00 00 0A 03 30 55 E5 04 00 53 E1 01 00 80 E2 70 80 BD 08 00 00 53 E3 0B 00 00 0A 01 30 D0 E5 04 00 53 E1 01 00 80 E2 70 80 BD 08 00 00 53 E3 05 00 00 0A 01 30 D0 E5 }
	condition:
		$pattern
}

rule strchrnul_71ca457be5e9ee1b69f67a88f9eb4d76 {
	meta:
		aliases = "__GI_strchrnul, strchrnul"
		size = "232"
		objfiles = "strchrnul@libc.a"
	strings:
		$pattern = { 70 40 2D E9 FF 40 01 E2 05 00 00 EA 00 30 D0 E5 04 00 53 E1 70 80 BD 08 00 00 53 E3 70 80 BD 08 01 00 80 E2 03 00 10 E3 F7 FF FF 1A 04 34 84 E1 00 50 A0 E1 03 68 83 E1 04 30 95 E4 9C 00 9F E5 06 20 23 E0 00 C0 82 E0 94 10 9F E5 00 00 83 E0 03 30 E0 E1 00 30 23 E0 01 E0 A0 E1 02 20 E0 E1 01 10 03 E0 0C 20 22 E0 00 00 51 E3 0E E0 02 E0 01 00 00 1A 00 00 5E E3 EE FF FF 0A 04 30 55 E5 04 00 53 E1 04 00 45 E2 70 80 BD 08 00 00 53 E3 70 80 BD 08 03 30 55 E5 04 00 53 E1 01 00 80 E2 70 80 BD 08 00 00 53 E3 70 80 BD 08 01 30 D0 E5 04 00 53 E1 01 00 80 E2 70 80 BD 08 00 00 53 E3 70 80 BD 08 01 30 D0 E5 }
	condition:
		$pattern
}

rule __divdf3_a296c0cec0c21243732534f34b82e29f {
	meta:
		aliases = "__aeabi_ddiv, __divdf3"
		size = "516"
		objfiles = "_muldivdf3@libgcc.a"
	strings:
		$pattern = { 70 40 2D E9 FF C0 A0 E3 07 CC 8C E3 20 4A 1C E0 22 5A 1C 10 0C 00 34 11 0C 00 35 11 5C 00 00 0B 05 40 44 E0 02 E0 20 E0 02 56 93 E1 00 06 A0 E1 4B 00 00 0A 02 26 A0 E1 01 52 A0 E3 22 22 85 E1 23 2C 82 E1 03 34 A0 E1 20 52 85 E1 21 5C 85 E1 01 64 A0 E1 02 01 0E E2 02 00 55 E1 03 00 56 01 FD 40 A4 E2 03 4C 84 E2 01 00 00 2A A2 20 B0 E1 63 30 A0 E1 03 60 56 E0 02 50 C5 E0 A2 20 B0 E1 63 30 A0 E1 01 16 A0 E3 02 C7 A0 E3 03 E0 56 E0 02 E0 D5 E0 03 60 46 20 0E 50 A0 21 0C 10 81 21 A2 20 B0 E1 63 30 A0 E1 03 E0 56 E0 02 E0 D5 E0 03 60 46 20 0E 50 A0 21 AC 10 81 21 A2 20 B0 E1 63 30 A0 E1 03 E0 56 E0 }
	condition:
		$pattern
}

rule __muldf3_2cb7c38d4df5dd0cd4a3cdc0c533ee6b {
	meta:
		aliases = "__aeabi_dmul, __muldf3"
		size = "808"
		objfiles = "_muldivdf3@libgcc.a"
	strings:
		$pattern = { 70 40 2D E9 FF C0 A0 E3 07 CC 8C E3 20 4A 1C E0 22 5A 1C 10 0C 00 34 11 0C 00 35 11 9E 00 00 0B 05 40 84 E0 02 60 20 E0 8C 0A C0 E1 8C 2A C2 E1 00 56 91 E1 02 56 93 11 01 06 80 E3 01 26 82 E3 4B 00 00 0A 02 61 06 E2 C0 0F 2D E9 21 78 A0 E1 23 88 A0 E1 20 98 A0 E1 22 A8 A0 E1 07 18 C1 E1 08 38 C3 E1 09 08 C0 E1 0A 28 C2 E1 91 03 0C E0 91 08 0B E0 00 E0 A0 E3 0B C8 9C E0 2B E8 AE E0 97 03 0B E0 0B C8 9C E0 2B E8 AE E0 91 0A 0B E0 00 50 A0 E3 0B E8 9E E0 2B 58 A5 E0 97 02 0B E0 0B E8 9E E0 2B 58 A5 E0 90 08 0B E0 0B E8 9E E0 2B 58 A5 E0 99 03 0B E0 0B E8 9E E0 2B 58 A5 E0 90 0A 0B E0 99 0A 06 E0 }
	condition:
		$pattern
}

rule __default_sa_restorer_c2ab957ad672471588429fd99098ba23 {
	meta:
		aliases = "__default_sa_restorer"
		size = "8"
		objfiles = "sigrestorer@libc.a"
	strings:
		$pattern = { 77 00 90 EF AD 00 90 EF }
	condition:
		$pattern
}

rule pthread_kill_34c0241aa0dc55e7152738b212744e17 {
	meta:
		aliases = "pthread_kill"
		size = "136"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { 7C 20 9F E5 00 3B A0 E1 23 3B A0 E1 70 40 2D E9 03 52 82 E0 00 40 A0 E1 01 60 A0 E1 05 00 A0 E1 00 10 A0 E3 ?? ?? ?? EB 08 20 95 E5 00 00 52 E3 02 00 00 0A 10 30 92 E5 04 00 53 E1 06 00 00 0A 05 00 A0 E1 ?? ?? ?? EB 03 00 A0 E3 70 80 BD E8 ?? ?? ?? EB 00 00 90 E5 70 80 BD E8 14 40 92 E5 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 06 10 A0 E1 ?? ?? ?? EB 01 00 70 E3 F4 FF FF 0A 00 00 A0 E3 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_acosh_8f60c50ec334453da5b4d31e7e51fac2 {
	meta:
		aliases = "__ieee754_acosh, acosh, __GI_acosh"
		size = "412"
		objfiles = "e_acosh@libm.a"
	strings:
		$pattern = { 7C 31 9F E5 03 00 50 E1 F0 43 2D E9 00 80 A0 E1 01 90 A0 E1 01 50 A0 E1 01 40 A0 E1 06 00 00 CA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB F0 83 BD E8 44 31 9F E5 03 00 50 E1 09 00 00 DA F9 35 83 E2 03 00 50 E1 00 20 A0 C1 01 30 A0 C1 02 00 00 CA ?? ?? ?? EB 24 21 9F E5 24 31 9F E5 ?? ?? ?? EB F0 83 BD E8 03 31 80 E2 01 36 83 E2 01 30 93 E1 00 00 A0 03 00 10 A0 03 F0 83 BD 08 01 01 58 E3 20 00 00 DA 08 20 A0 E1 09 30 A0 E1 ?? ?? ?? EB F0 20 9F E5 00 30 A0 E3 ?? ?? ?? EB ?? ?? ?? EB 08 20 A0 E1 00 40 A0 E1 01 50 A0 E1 09 30 A0 E1 08 00 A0 E1 09 10 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule toascii_46ee7e8d78995988ce323a0a232db103 {
	meta:
		aliases = "toascii"
		size = "8"
		objfiles = "toascii@libc.a"
	strings:
		$pattern = { 7F 00 00 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_iswctype_1fe478345b4c5df53b4dbcdaa7e627e1 {
	meta:
		aliases = "iswctype, __GI_iswctype"
		size = "96"
		objfiles = "iswctype@libc.a"
	strings:
		$pattern = { 7F 00 50 E3 0C 00 51 93 00 C0 A0 E1 04 E0 2D E5 00 00 A0 83 01 00 A0 93 04 F0 9D 84 34 30 9F E5 34 00 9F E5 00 20 93 E5 81 10 A0 E1 8C 30 A0 E1 02 C0 83 E0 00 E0 81 E0 02 20 D3 E7 00 30 D1 E7 01 00 DE E5 01 10 DC E5 00 34 83 E1 01 24 82 E1 03 00 02 E0 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_towupper_f7cd71ed709ec94d5000e2fd1a8c0960 {
	meta:
		aliases = "towupper, __GI_towlower, towlower, __GI_towupper"
		size = "48"
		objfiles = "towlower@libc.a, towupper@libc.a"
	strings:
		$pattern = { 7F 00 50 E3 0E F0 A0 81 1C 30 9F E5 00 10 93 E5 80 20 A0 E1 01 30 82 E0 01 30 D3 E5 01 20 D2 E7 03 3C A0 E1 43 08 82 E1 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule initstate_r_8e60a771d280b682589029af425ae361 {
	meta:
		aliases = "__GI_initstate_r, initstate_r"
		size = "200"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { 7F 00 52 E3 F0 40 2D E9 01 70 A0 E1 03 50 A0 E1 03 00 00 9A FF 00 52 E3 04 40 A0 83 03 40 A0 93 08 00 00 EA 1F 00 52 E3 03 00 00 8A 07 00 52 E3 00 40 A0 83 03 00 00 8A 1A 00 00 EA 3F 00 52 E3 02 40 A0 83 01 40 A0 93 74 20 9F E5 04 31 82 E0 14 10 93 E5 04 21 92 E7 04 60 87 E2 01 31 86 E0 10 30 85 E5 0E 20 C5 E5 0D 10 C5 E5 0C 40 C5 E5 08 60 85 E5 05 10 A0 E1 ?? ?? ?? EB 00 00 54 E3 04 30 95 15 03 30 66 10 43 31 A0 11 05 20 A0 13 92 43 23 10 00 00 A0 E3 00 00 87 E5 04 00 A0 01 00 30 87 15 F0 80 BD E8 ?? ?? ?? EB 16 40 A0 E3 00 40 80 E5 ?? ?? ?? EB 00 40 80 E5 00 00 E0 E3 F0 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_isascii_98be199b4bc40b36ca693293cff31851 {
	meta:
		aliases = "isascii, __GI_isascii"
		size = "16"
		objfiles = "isascii@libc.a"
	strings:
		$pattern = { 7F 30 D0 E3 00 00 A0 13 01 00 A0 03 0E F0 A0 E1 }
	condition:
		$pattern
}

rule btowc_af3dfcf50b4a136e32fd17666457bac4 {
	meta:
		aliases = "__GI_btowc, wctob, btowc"
		size = "12"
		objfiles = "wctob@libc.a, btowc@libc.a"
	strings:
		$pattern = { 80 00 50 E3 00 00 E0 23 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __fixdfsi_15db5a2f3614d1823cc4148afe67ce86 {
	meta:
		aliases = "__aeabi_d2iz, __fixdfsi"
		size = "92"
		objfiles = "_fixdfsi@libgcc.a"
	strings:
		$pattern = { 80 20 A0 E1 02 26 92 E2 0C 00 00 2A 09 00 00 5A 3E 3E E0 E3 C2 2A 53 E0 0A 00 00 9A 80 35 A0 E1 02 31 83 E3 A1 3A 83 E1 02 01 10 E3 33 02 A0 E1 00 00 60 12 0E F0 A0 E1 00 00 A0 E3 0E F0 A0 E1 00 16 91 E1 02 00 00 1A 02 01 10 E2 02 01 E0 03 0E F0 A0 E1 00 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __truncdfsf2_5cb6735ce343b5da996d663553bc0bcf {
	meta:
		aliases = "__aeabi_d2f, __truncdfsf2"
		size = "160"
		objfiles = "_truncdfsf2@libgcc.a"
	strings:
		$pattern = { 80 20 A0 E1 07 32 52 E2 02 C6 53 22 7F C5 7C 22 06 00 00 9A 02 C1 00 E2 81 21 A0 E1 A1 1E 8C E1 02 01 52 E3 03 01 A1 E0 01 00 C0 03 0E F0 A0 E1 01 01 10 E3 0F 00 00 1A 2E 26 93 E2 02 01 00 B2 0E F0 A0 B1 01 06 80 E3 A2 2A A0 E1 18 20 62 E2 20 C0 62 E2 11 3C B0 E1 31 12 A0 E1 01 10 81 13 80 35 A0 E1 A3 35 A0 E1 13 1C 81 E1 33 32 A0 E1 83 30 A0 E1 E6 FF FF EA C2 3A F0 E1 03 00 00 1A 00 36 91 E1 7F 04 A0 13 03 05 80 13 0E F0 A0 11 02 01 00 E2 7F 04 80 E3 02 05 80 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __aeabi_f2iz_3f2b814bd4e7e5e8841801021a6d3ff9 {
	meta:
		aliases = "__fixsfsi, __aeabi_f2iz"
		size = "92"
		objfiles = "_fixsfsi@libgcc.a"
	strings:
		$pattern = { 80 20 A0 E1 7F 04 52 E3 08 00 00 3A 9E 30 A0 E3 22 2C 53 E0 07 00 00 9A 00 34 A0 E1 02 31 83 E3 02 01 10 E3 33 02 A0 E1 00 00 60 12 0E F0 A0 E1 00 00 A0 E3 0E F0 A0 E1 61 00 72 E3 01 00 00 1A 80 24 B0 E1 02 00 00 1A 02 01 10 E2 02 01 E0 03 0E F0 A0 E1 00 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __unordsf2_d0e4f2507b6e98524d135d82d4b78104 {
	meta:
		aliases = "__aeabi_fcmpun, __unordsf2"
		size = "56"
		objfiles = "_unordsf2@libgcc.a"
	strings:
		$pattern = { 80 20 A0 E1 81 30 A0 E1 42 CC F0 E1 01 00 00 1A 80 C4 B0 E1 05 00 00 1A 43 CC F0 E1 01 00 00 1A 81 C4 B0 E1 01 00 00 1A 00 00 A0 E3 0E F0 A0 E1 01 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __aeabi_f2uiz_c609666c0d7d4b84305a36e14bdee41d {
	meta:
		aliases = "__fixunssfsi, __aeabi_f2uiz"
		size = "84"
		objfiles = "_fixunssfsi@libgcc.a"
	strings:
		$pattern = { 80 20 B0 E1 08 00 00 2A 7F 04 52 E3 06 00 00 3A 9E 30 A0 E3 22 2C 53 E0 05 00 00 4A 00 34 A0 E1 02 31 83 E3 33 02 A0 E1 0E F0 A0 E1 00 00 A0 E3 0E F0 A0 E1 61 00 72 E3 01 00 00 1A 80 24 B0 E1 01 00 00 1A 00 00 E0 E3 0E F0 A0 E1 00 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __aeabi_d2uiz_0b11c0b82088c8df9ab9bfcfd468f975 {
	meta:
		aliases = "__fixunsdfsi, __aeabi_d2uiz"
		size = "84"
		objfiles = "_fixunsdfsi@libgcc.a"
	strings:
		$pattern = { 80 20 B0 E1 0A 00 00 2A 02 26 92 E2 0A 00 00 2A 07 00 00 5A 3E 3E E0 E3 C2 2A 53 E0 08 00 00 4A 80 35 A0 E1 02 31 83 E3 A1 3A 83 E1 33 02 A0 E1 0E F0 A0 E1 00 00 A0 E3 0E F0 A0 E1 00 16 91 E1 01 00 00 1A 00 00 E0 E3 0E F0 A0 E1 00 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __addsf3_7bfbc46a1abc3596775dc142025ed59d {
	meta:
		aliases = "__aeabi_fadd, __addsf3"
		size = "444"
		objfiles = "_addsubsf3@libgcc.a"
	strings:
		$pattern = { 80 20 B0 E1 81 30 B0 11 03 00 32 11 42 CC F0 11 43 CC F0 11 47 00 00 0A 22 2C A0 E1 23 3C 72 E0 03 20 82 C0 01 10 20 C0 00 00 21 C0 01 10 20 C0 00 30 63 B2 19 00 53 E3 0E F0 A0 81 02 01 10 E3 02 05 80 E3 FF 04 C0 E3 00 00 60 12 02 01 11 E3 02 15 81 E3 FF 14 C1 E3 00 10 61 12 03 00 32 E1 2E 00 00 0A 01 20 42 E2 51 03 90 E0 20 30 63 E2 11 13 A0 E1 02 31 00 E2 01 00 00 5A 00 10 71 E2 00 00 E0 E2 02 05 50 E3 0B 00 00 3A 01 04 50 E3 04 00 00 3A A0 00 B0 E1 61 10 A0 E1 01 20 82 E2 FE 00 52 E3 38 00 00 2A 02 01 51 E3 82 0B A0 E0 01 00 C0 03 03 00 80 E1 0E F0 A0 E1 81 10 B0 E1 00 00 A0 E0 02 05 10 E3 }
	condition:
		$pattern
}

rule __extendsfdf2_e1cb4a3e7a7ed85e5cfa29041680ff4c {
	meta:
		aliases = "__aeabi_f2d, __extendsfdf2"
		size = "64"
		objfiles = "_addsubdf3@libgcc.a"
	strings:
		$pattern = { 80 20 B0 E1 C2 01 A0 E1 60 00 A0 E1 02 1E A0 E1 FF 34 12 12 FF 04 33 13 0E 03 20 12 0E F0 A0 11 00 00 32 E3 FF 04 33 13 0E F0 A0 01 30 40 2D E9 0E 4D A0 E3 02 51 00 E2 02 01 C0 E3 74 FF FF EA }
	condition:
		$pattern
}

rule __GI_tolower_c7c2da1e9dd8d42a29407c7a7cc35a23 {
	meta:
		aliases = "__GI_toupper, tolower, toupper, __GI_tolower"
		size = "52"
		objfiles = "tolower@libc.a, toupper@libc.a"
	strings:
		$pattern = { 80 30 80 E2 06 0D 53 E3 0E F0 A0 21 1C 30 9F E5 00 10 93 E5 80 20 A0 E1 01 30 82 E0 01 30 D3 E5 01 20 D2 E7 03 3C A0 E1 43 08 82 E1 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __unorddf2_bffa2f105a05b3342d7139066f6bb49f {
	meta:
		aliases = "__aeabi_dcmpun, __unorddf2"
		size = "56"
		objfiles = "_unorddf2@libgcc.a"
	strings:
		$pattern = { 80 C0 A0 E1 CC CA F0 E1 01 00 00 1A 00 C6 91 E1 06 00 00 1A 82 C0 A0 E1 CC CA F0 E1 01 00 00 1A 02 C6 93 E1 01 00 00 1A 00 00 A0 E3 0E F0 A0 E1 01 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule frexp_fa2278ee8e4df06e955ca082d608ea2e {
	meta:
		aliases = "__GI_frexp, frexp"
		size = "160"
		objfiles = "s_frexp@libm.a"
	strings:
		$pattern = { 90 C0 9F E5 F0 41 2D E9 02 E1 C0 E3 02 80 A0 E1 0C 00 5E E1 00 20 A0 E3 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 00 70 A0 E1 00 20 88 E5 01 30 A0 E1 15 00 00 CA 03 30 9E E1 13 00 00 0A 01 06 5E E3 07 00 00 AA 00 30 A0 E3 4C 20 9F E5 ?? ?? ?? EB 35 30 E0 E3 00 30 88 E5 01 60 A0 E1 00 70 A0 E1 02 E1 C0 E3 00 30 98 E5 7F 04 C7 E3 FF 3F 43 E2 02 30 43 E2 0F 06 C0 E3 2E 3A 83 E0 FF 15 80 E3 02 16 81 E3 00 30 88 E5 01 50 A0 E1 05 00 A0 E1 06 10 A0 E1 F0 81 BD E8 FF FF EF 7F 00 00 50 43 }
	condition:
		$pattern
}

rule __rpc_thread_destroy_877dab6d10c655ee0348f310e0a9b16c {
	meta:
		aliases = "__rpc_thread_destroy"
		size = "176"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { 98 30 9F E5 10 40 2D E9 00 00 53 E3 90 30 9F 05 00 40 93 05 03 00 00 0A 02 00 A0 E3 0F E0 A0 E1 03 F0 A0 E1 00 40 A0 E1 00 00 54 E3 10 80 BD 08 70 30 9F E5 03 00 54 E1 10 80 BD 08 ?? ?? ?? EB ?? ?? ?? EB 98 00 94 E5 ?? ?? ?? EB 9C 00 94 E5 ?? ?? ?? EB A0 00 94 E5 ?? ?? ?? EB BC 00 94 E5 ?? ?? ?? EB AC 00 94 E5 ?? ?? ?? EB B0 00 94 E5 ?? ?? ?? EB 04 00 A0 E1 ?? ?? ?? EB 28 20 9F E5 00 00 52 E3 18 30 9F 05 00 20 83 05 10 80 BD 08 02 00 A0 E3 00 10 A0 E3 10 40 BD E8 ?? ?? ?? EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule puts_68b35f2948677fa77a766472d12d35a1 {
	meta:
		aliases = "puts"
		size = "180"
		objfiles = "puts@libc.a"
	strings:
		$pattern = { 98 30 9F E5 F0 40 2D E9 00 50 93 E5 34 70 95 E5 00 00 57 E3 10 D0 4D E2 00 60 A0 E1 0A 00 00 1A 38 40 85 E2 0D 00 A0 E1 74 30 9F E5 74 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 64 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 06 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 01 00 70 E3 00 40 A0 E1 05 00 00 0A 05 10 A0 E1 0A 00 A0 E3 ?? ?? ?? EB 01 00 70 E3 00 40 A0 01 01 40 84 12 00 00 57 E3 0D 00 A0 01 01 10 A0 03 20 30 9F 05 0F E0 A0 01 03 F0 A0 01 04 00 A0 E1 10 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_cosh_bd5b83259f8a815fa51de0ace60efce6 {
	meta:
		aliases = "__ieee754_cosh, cosh, __GI_cosh"
		size = "464"
		objfiles = "e_cosh@libm.a"
	strings:
		$pattern = { 9C 31 9F E5 F0 43 2D E9 02 51 C0 E3 03 00 55 E1 01 40 A0 E1 00 20 A0 C1 01 30 A0 C1 5A 00 00 CA 80 31 9F E5 03 00 55 E1 1E 00 00 CA ?? ?? ?? EB ?? ?? ?? EB 70 21 9F E5 00 30 A0 E3 00 80 A0 E1 01 90 A0 E1 ?? ?? ?? EB F2 05 55 E3 00 60 A0 E1 01 70 A0 E1 4F 00 00 BA 08 20 A0 E1 09 30 A0 E1 08 00 A0 E1 09 10 A0 E1 ?? ?? ?? EB 06 20 A0 E1 00 40 A0 E1 01 50 A0 E1 07 30 A0 E1 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 08 21 9F E5 00 30 A0 E3 14 00 00 EA 00 31 9F E5 03 00 55 E1 13 00 00 CA ?? ?? ?? EB ?? ?? ?? EB F0 20 9F E5 00 30 A0 E3 00 40 A0 E1 }
	condition:
		$pattern
}

rule _dl_run_init_array_a1524f63dbf8209d098894d8eba67166 {
	meta:
		aliases = "_dl_run_init_array"
		size = "64"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { A4 30 90 E5 00 10 90 E5 AC 20 90 E5 00 00 53 E3 70 40 2D E9 03 60 81 10 22 51 A0 11 00 40 A0 13 70 80 BD 08 02 00 00 EA 0F E0 A0 E1 04 F1 96 E7 01 40 84 E2 05 00 54 E1 FA FF FF 3A 70 80 BD E8 }
	condition:
		$pattern
}

rule _dl_run_fini_array_d583672c104e192bd668b59a30fcab99 {
	meta:
		aliases = "_dl_run_fini_array"
		size = "56"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { A8 10 90 E5 00 00 51 E3 30 40 2D E9 30 80 BD 08 B0 20 90 E5 00 30 90 E5 22 41 A0 E1 03 50 81 E0 01 00 00 EA 0F E0 A0 E1 04 F1 95 E7 01 40 54 E2 FB FF FF 2A 30 80 BD E8 }
	condition:
		$pattern
}

rule getchar_5abb08d0caeca2adeb92a47bf5389982 {
	meta:
		aliases = "getchar"
		size = "200"
		objfiles = "getchar@libc.a"
	strings:
		$pattern = { AC 30 9F E5 30 40 2D E9 00 50 93 E5 34 30 95 E5 00 00 53 E3 10 D0 4D E2 09 00 00 0A 10 20 95 E5 18 30 95 E5 03 00 52 E1 01 40 D2 34 10 20 85 35 1C 00 00 3A 05 00 A0 E1 ?? ?? ?? EB 00 40 A0 E1 18 00 00 EA 38 40 85 E2 04 20 A0 E1 64 10 9F E5 0D 00 A0 E1 60 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 54 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 10 20 95 E5 18 30 95 E5 03 00 52 E1 01 40 D2 34 10 20 85 35 02 00 00 3A 05 00 A0 E1 ?? ?? ?? EB 00 40 A0 E1 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __vfork_704a65e4313fd53c8769931b1a84edbd {
	meta:
		aliases = "__GI_vfork, vfork, __vfork"
		size = "40"
		objfiles = "vfork@libc.a"
	strings:
		$pattern = { BE 00 90 EF 01 0A 70 E3 0E F0 A0 31 25 10 E0 E3 01 00 30 E1 02 00 00 1A 02 00 90 EF 01 0A 70 E3 0E F0 A0 31 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __powisf2_e901eaf6d3fff45a933e7b59cc416faf {
	meta:
		aliases = "__powisf2"
		size = "136"
		objfiles = "_powisf2@libgcc.a"
	strings:
		$pattern = { C1 2F 21 E0 C1 2F 42 E0 F0 40 2D E9 01 00 12 E3 FE 35 A0 E3 00 60 A0 E1 01 70 A0 E1 00 50 A0 E1 03 60 A0 01 02 40 A0 E1 A4 40 B0 E1 05 00 A0 E1 05 10 A0 E1 0B 00 00 0A ?? ?? ?? EB 01 00 14 E3 00 50 A0 E1 05 10 A0 E1 06 00 A0 E1 F5 FF FF 0A ?? ?? ?? EB A4 40 B0 E1 00 60 A0 E1 05 10 A0 E1 05 00 A0 E1 F3 FF FF 1A 00 00 57 E3 03 00 00 AA 06 10 A0 E1 FE 05 A0 E3 ?? ?? ?? EB 00 60 A0 E1 06 00 A0 E1 F0 80 BD E8 }
	condition:
		$pattern
}

rule __powidf2_3d091dfaa80b7c50d2799fc8ccf36813 {
	meta:
		aliases = "__powidf2"
		size = "200"
		objfiles = "_powidf2@libgcc.a"
	strings:
		$pattern = { C2 3F 22 E0 C2 3F 43 E0 01 00 13 E3 F0 45 2D E9 FF 75 A0 03 02 A0 A0 E1 00 40 A0 E1 01 50 A0 E1 00 70 A0 11 01 80 A0 11 03 76 87 02 00 80 A0 03 03 60 A0 E1 A6 60 B0 E1 04 00 A0 E1 05 10 A0 E1 04 20 A0 E1 05 30 A0 E1 11 00 00 0A ?? ?? ?? EB 01 00 16 E3 00 40 A0 E1 01 50 A0 E1 07 00 A0 E1 08 10 A0 E1 04 20 A0 E1 05 30 A0 E1 F0 FF FF 0A ?? ?? ?? EB A6 60 B0 E1 00 70 A0 E1 01 80 A0 E1 04 00 A0 E1 05 10 A0 E1 04 20 A0 E1 05 30 A0 E1 ED FF FF 1A 00 00 5A E3 07 00 00 AA FF 05 A0 E3 07 20 A0 E1 08 30 A0 E1 03 06 80 E2 00 10 A0 E3 ?? ?? ?? EB 00 70 A0 E1 01 80 A0 E1 07 00 A0 E1 08 10 A0 E1 F0 85 BD E8 }
	condition:
		$pattern
}

rule putchar_becfecd5d6e5811ca776fbab860fc5ff {
	meta:
		aliases = "putchar"
		size = "224"
		objfiles = "putchar@libc.a"
	strings:
		$pattern = { C4 30 9F E5 70 40 2D E9 00 50 93 E5 34 30 95 E5 00 00 53 E3 10 D0 4D E2 00 60 A0 E1 0B 00 00 0A 10 20 95 E5 1C 30 95 E5 03 00 52 E1 FF 30 00 32 01 30 C2 34 03 40 A0 31 10 20 85 35 1F 00 00 3A 05 10 A0 E1 ?? ?? ?? EB 00 40 A0 E1 1B 00 00 EA 38 40 85 E2 04 20 A0 E1 70 10 9F E5 0D 00 A0 E1 6C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 64 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 10 20 95 E5 1C 30 95 E5 03 00 52 E1 FF 30 06 32 01 30 C2 34 03 40 A0 31 10 20 85 35 03 00 00 3A 06 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 40 A0 E1 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 10 D0 8D E2 }
	condition:
		$pattern
}

rule asinh_950a2d088a9587c4704d41d73af3c2ec {
	meta:
		aliases = "__GI_asinh, asinh"
		size = "504"
		objfiles = "s_asinh@libm.a"
	strings:
		$pattern = { D0 31 9F E5 F0 47 2D E9 02 41 C0 E3 03 00 54 E1 00 80 A0 E1 01 90 A0 E1 00 A0 A0 E1 03 00 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 64 00 00 EA A4 31 9F E5 03 00 54 E1 07 00 00 CA 9C 21 9F E5 9C 31 9F E5 ?? ?? ?? EB 98 21 9F E5 00 30 A0 E3 ?? ?? ?? EB 00 00 50 E3 5B 00 00 CA 88 31 9F E5 03 00 54 E1 07 00 00 DA 08 00 A0 E1 09 10 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 70 21 9F E5 70 31 9F E5 ?? ?? ?? EB 4B 00 00 EA 01 01 54 E3 27 00 00 DA 08 00 A0 E1 09 10 A0 E1 ?? ?? ?? EB 08 20 A0 E1 00 40 A0 E1 01 50 A0 E1 09 30 A0 E1 08 00 A0 E1 09 10 A0 E1 ?? ?? ?? EB 28 21 9F E5 00 30 A0 E3 ?? ?? ?? EB ?? ?? ?? EB }
	condition:
		$pattern
}

rule do_dlclose_1b9a5b8c5db57e1e702356e6ecdd65e9 {
	meta:
		aliases = "do_dlclose"
		size = "768"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { E0 32 9F E5 00 30 93 E5 03 00 50 E1 F0 4F 2D E9 00 70 A0 E1 01 90 A0 E1 B0 00 00 0A C8 32 9F E5 00 30 93 E5 00 10 A0 E3 03 00 00 EA 07 00 53 E1 08 00 00 0A 03 10 A0 E1 04 30 93 E5 00 00 53 E3 F9 FF FF 1A A4 32 9F E5 0A 20 A0 E3 01 00 A0 E3 00 20 83 E5 F0 8F BD E8 00 00 51 E3 04 20 97 E5 84 32 9F 05 04 20 81 15 00 20 83 05 00 10 97 E5 20 20 D1 E5 21 30 D1 E5 03 24 82 E1 01 00 52 E3 00 80 A0 03 5C B2 9F 05 08 A0 A0 01 7A 00 00 0A 01 20 42 E2 42 34 A0 E1 07 00 A0 E1 21 30 C1 E5 20 20 C1 E5 ?? ?? ?? EB 00 00 A0 E3 F0 8F BD E8 08 30 97 E5 08 61 93 E7 20 30 96 E5 01 30 43 E2 03 38 A0 E1 23 38 A0 E1 }
	condition:
		$pattern
}

rule __rpc_thread_variables_f16e7ed206f73eb3b8be438ca97a0bb7 {
	meta:
		aliases = "__rpc_thread_variables"
		size = "272"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { F0 30 9F E5 10 40 2D E9 00 00 53 E3 E8 30 9F 05 00 00 93 05 02 00 A0 13 0F E0 A0 11 03 F0 A0 11 00 00 50 E3 17 00 00 1A D0 30 9F E5 00 00 53 E3 CC 40 9F E5 04 00 00 0A 04 00 A0 E1 C4 10 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 00 EA 00 30 94 E5 00 00 53 E3 02 00 00 1A DD FF FF EB 01 30 A0 E3 00 30 84 E5 8C 30 9F E5 00 00 53 E3 88 30 9F 05 00 00 93 05 02 00 A0 13 0F E0 A0 11 03 F0 A0 11 00 00 50 E3 01 00 00 0A 00 40 A0 E1 17 00 00 EA 01 00 A0 E3 C8 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 0A 00 00 0A 60 30 9F E5 00 00 53 E3 48 30 9F 05 00 40 A0 E1 00 00 83 05 0C 00 00 0A 00 10 A0 E1 02 00 A0 E3 0F E0 A0 E1 }
	condition:
		$pattern
}

rule __ieee754_sinh_fc03e68850bb6d633e928562cffe364b {
	meta:
		aliases = "__GI_sinh, sinh, __ieee754_sinh"
		size = "556"
		objfiles = "e_sinh@libm.a"
	strings:
		$pattern = { F0 31 9F E5 F0 4F 2D E9 02 71 C0 E3 03 00 57 E1 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 03 00 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 6C 00 00 EA C4 31 9F E5 00 00 50 E3 C0 A1 9F B5 C0 A1 9F A5 03 00 57 E1 00 B0 A0 E3 41 00 00 CA B4 31 9F E5 03 00 57 E1 07 00 00 CA AC 21 9F E5 AC 31 9F E5 ?? ?? ?? EB A8 21 9F E5 00 30 A0 E3 ?? ?? ?? EB 00 00 50 E3 5C 00 00 CA 05 00 A0 E1 06 10 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 88 31 9F E5 03 00 57 E1 00 80 A0 E1 01 90 A0 E1 1B 00 00 CA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 08 20 A0 E1 00 60 A0 E1 01 70 A0 E1 09 30 A0 E1 08 00 A0 E1 09 10 A0 E1 ?? ?? ?? EB 48 21 9F E5 }
	condition:
		$pattern
}

rule __GI_sleep_026e3c4f3c2630fafeee9c94b94c1b65 {
	meta:
		aliases = "sleep, __GI_sleep"
		size = "284"
		objfiles = "sleep@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 30 50 E2 2C D0 4D E2 03 00 A0 01 3E 00 00 0A 1C 50 8D E2 00 40 A0 E3 11 10 A0 E3 14 70 8D E2 05 00 A0 E1 24 30 8D E5 1C 40 8D E5 20 40 8D E5 28 40 8D E5 ?? ?? ?? EB 04 00 A0 E1 05 10 A0 E1 07 20 A0 E1 ?? ?? ?? EB 07 00 A0 E1 11 10 A0 E3 ?? ?? ?? EB 00 40 50 E2 24 00 8D 12 1E 00 00 1A 05 00 A0 E1 11 10 A0 E3 1C 40 8D E5 20 40 8D E5 ?? ?? ?? EB 11 00 A0 E3 04 10 A0 E1 0D 20 A0 E1 ?? ?? ?? EB 00 30 9D E5 01 00 53 E3 24 50 8D E2 0C 00 00 1A 05 10 A0 E1 05 00 A0 E1 ?? ?? ?? EB 00 60 A0 E1 ?? ?? ?? EB 04 20 A0 E1 00 50 A0 E1 07 10 A0 E1 02 00 A0 E3 00 40 95 E5 ?? ?? ?? EB 00 40 85 E5 }
	condition:
		$pattern
}

rule xdr_string_44eff910b3455951a5e993d3bf195ac9 {
	meta:
		aliases = "__GI_xdr_string, xdr_string"
		size = "280"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 30 90 E5 00 00 53 E3 04 D0 4D E2 00 50 A0 E1 01 60 A0 E1 02 70 A0 E1 00 40 91 E5 04 00 00 0A 02 00 53 E3 07 00 00 1A 00 00 54 E3 02 00 00 1A 30 00 00 EA 00 00 54 E3 30 00 00 0A 04 00 A0 E1 ?? ?? ?? EB 00 00 8D E5 05 00 A0 E1 0D 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 28 00 00 0A 00 30 9D E5 07 00 53 E1 25 00 00 8A 00 20 95 E5 01 00 52 E3 03 00 00 0A 14 00 00 3A 02 00 52 E3 1F 00 00 1A 16 00 00 EA 01 00 93 E2 1A 00 00 0A 00 00 54 E3 0A 00 00 1A ?? ?? ?? EB 00 00 50 E3 00 40 A0 E1 00 00 86 E5 05 00 00 1A 5C 30 9F E5 5C 00 9F E5 00 10 93 E5 ?? ?? ?? EB 04 00 A0 E1 10 00 00 EA 00 30 9D E5 }
	condition:
		$pattern
}

rule __pthread_once_1d895936d5cddc5572777ff2e55a7641 {
	meta:
		aliases = "pthread_once, __pthread_once"
		size = "316"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 00 30 90 E5 02 00 53 E3 10 D0 4D E2 00 50 A0 E1 01 70 A0 E1 00 00 00 1A 3B 00 00 EA F4 30 9F E5 F4 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 10 95 E5 03 30 01 E2 01 00 53 E3 07 00 00 1A DC 30 9F E5 00 20 93 E5 03 30 C1 E3 02 00 53 E1 00 30 A0 13 00 30 85 15 00 00 00 EA ?? ?? ?? EB 00 60 95 E5 03 30 06 E2 01 00 53 E3 B4 00 9F E5 A8 10 9F E5 F8 FF FF 0A 00 00 56 E3 00 40 A0 13 1B 00 00 1A 98 30 9F E5 00 30 93 E5 01 30 83 E3 00 30 85 E5 84 00 9F E5 8C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 20 A0 E1 0D 00 A0 E1 7C 10 9F E5 7C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 0F E0 A0 E1 07 F0 A0 E1 06 10 A0 E1 }
	condition:
		$pattern
}

rule __GI_rresvport_23660062f29f55a56239770e4b4305de {
	meta:
		aliases = "rresvport, __GI_rresvport"
		size = "200"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 30 A0 E3 02 C0 A0 E3 10 D0 4D E2 00 60 A0 E1 03 20 A0 E1 0C 00 A0 E1 01 10 A0 E3 00 C0 CD E5 01 30 CD E5 04 30 8D E5 ?? ?? ?? EB 00 40 50 E2 1F 00 00 BA 0D 70 A0 E1 00 30 96 E5 03 38 A0 E1 23 C4 A0 E1 FF CC 0C E2 23 CC 8C E1 4C 34 A0 E1 0D 10 A0 E1 10 20 A0 E3 04 00 A0 E1 03 30 CD E5 02 C0 CD E5 ?? ?? ?? EB 00 00 50 E3 11 00 00 AA ?? ?? ?? EB 00 30 90 E5 62 00 53 E3 00 50 A0 E1 02 00 00 0A 04 00 A0 E1 ?? ?? ?? EB 08 00 00 EA 00 30 96 E5 01 30 43 E2 02 0C 53 E3 00 30 86 E5 E4 FF FF 1A 04 00 A0 E1 ?? ?? ?? EB 0B 30 A0 E3 00 30 85 E5 00 40 E0 E3 04 00 A0 E1 10 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule inet_pton4_f10bf0a2247f6e7bad426b6a4f178915 {
	meta:
		aliases = "inet_pton4"
		size = "204"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 30 A0 E3 04 D0 4D E2 01 40 A0 E1 03 C0 A0 E1 03 E0 A0 E1 0D 10 A0 E1 03 50 A0 E1 0A 70 A0 E3 01 60 A0 E3 00 30 CD E5 17 00 00 EA 09 00 52 E3 01 00 80 E2 0B 00 00 8A 00 30 D1 E5 97 23 23 E0 FF 00 53 E3 1C 00 00 8A 00 00 5E E3 00 30 C1 E5 0D 00 00 1A 01 C0 8C E2 04 00 5C E3 06 E0 A0 E1 15 00 00 CA 08 00 00 EA 2E 00 53 E3 00 30 A0 13 01 30 0E 02 00 00 53 E3 05 E0 A0 E1 0E 00 00 0A 04 00 5C E3 0C 00 00 0A 01 50 E1 E5 00 30 D0 E5 00 00 53 E3 30 20 43 E2 E3 FF FF 1A 03 00 5C E3 05 00 00 DA 04 00 A0 E1 0D 10 A0 E1 04 20 A0 E3 ?? ?? ?? EB 01 00 A0 E3 00 00 00 EA 00 00 A0 E3 04 D0 8D E2 }
	condition:
		$pattern
}

rule getwc_unlocked_fab2ef58a648e230d1536677e5ca902f {
	meta:
		aliases = "__GI_fgetwc_unlocked, fgetwc_unlocked, getwc_unlocked"
		size = "448"
		objfiles = "fgetwc_unlocked@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 30 D0 E5 01 10 D0 E5 A8 21 9F E5 01 34 83 E1 02 20 03 E0 02 0B 52 E3 08 D0 4D E2 00 40 A0 E1 04 00 00 8A 02 1B A0 E3 ?? ?? ?? EB 00 00 50 E3 00 50 E0 13 5C 00 00 1A 00 20 D4 E5 01 30 D4 E5 03 34 82 E1 02 00 13 E3 14 00 00 0A 01 00 13 E3 03 00 00 1A 28 30 94 E5 00 00 53 E3 03 30 D4 05 00 00 00 0A 00 30 A0 E3 00 20 D4 E5 02 30 C4 E5 01 30 D4 E5 03 24 82 E1 01 30 02 E2 03 31 84 E0 01 20 42 E2 24 50 93 E5 42 34 A0 E1 01 30 C4 E5 00 30 A0 E3 28 30 84 E5 00 20 C4 E5 3C 00 00 EA 08 30 94 E5 00 00 53 E3 05 00 00 1A 04 00 A0 E1 07 10 8D E2 C9 FF FF EB 0C 30 94 E5 01 30 83 E2 0C 30 84 E5 }
	condition:
		$pattern
}

rule popen_e89f442f042b0510168d6834727d4305 {
	meta:
		aliases = "popen"
		size = "584"
		objfiles = "popen@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 30 D1 E5 34 D0 4D E2 77 00 53 E3 01 40 A0 E1 04 00 8D E5 09 00 00 0A 72 00 53 E3 01 00 A0 03 18 00 8D 05 07 00 00 0A ?? ?? ?? EB 00 10 A0 E3 16 30 A0 E3 08 10 8D E5 00 30 80 E5 74 00 00 EA 00 20 A0 E3 18 20 8D E5 0C 00 A0 E3 ?? ?? ?? EB 00 30 50 E2 08 30 8D 05 6D 00 00 0A 2C 00 8D E2 0C 30 8D E5 ?? ?? ?? EB 00 00 50 E3 64 00 00 1A 18 C0 9D E5 34 00 8D E2 01 30 6C E2 07 20 E0 E3 03 31 80 E0 02 30 93 E7 10 30 8D E5 0C 31 80 E0 02 30 93 E7 04 10 A0 E1 10 00 9D E5 14 30 8D E5 ?? ?? ?? EB 00 00 50 E3 08 00 8D E5 04 00 00 1A 10 00 9D E5 ?? ?? ?? EB 14 00 9D E5 ?? ?? ?? EB 4F 00 00 EA }
	condition:
		$pattern
}

rule pthread_getschedparam_bbc40c7e933aa70dc99435248814878c {
	meta:
		aliases = "__GI_pthread_getschedparam, pthread_getschedparam"
		size = "164"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 00 3B A0 E1 00 50 A0 E1 8C 00 9F E5 23 3B A0 E1 03 42 80 E0 04 00 A0 E1 01 70 A0 E1 00 10 A0 E3 02 60 A0 E1 ?? ?? ?? EB 08 00 94 E5 00 00 50 E3 02 00 00 0A 10 30 90 E5 05 00 53 E1 0D 00 00 0A 04 00 A0 E1 ?? ?? ?? EB 03 00 A0 E3 F0 80 BD E8 05 00 A0 E1 06 10 A0 E1 ?? ?? ?? EB 01 00 70 E3 00 00 A0 13 00 40 87 15 F0 80 BD 18 ?? ?? ?? EB 00 00 90 E5 F0 80 BD E8 14 50 90 E5 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 ?? ?? ?? EB 01 00 70 E3 00 40 A0 E1 ED FF FF 1A F3 FF FF EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule adjtime_a89133155ef21bc04d07de52aa9919d4 {
	meta:
		aliases = "adjtime"
		size = "272"
		objfiles = "adjtime@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 40 50 E2 80 D0 4D E2 01 60 A0 E1 18 00 00 0A 04 70 94 E5 E4 50 9F E5 07 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 30 94 E5 03 40 80 E0 86 3E 84 E2 CC 20 9F E5 01 30 83 E2 02 00 53 E1 04 00 00 9A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 27 00 00 EA 07 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 95 04 04 E0 9C 30 9F E5 00 40 84 E0 18 00 8D E8 00 00 00 EA 00 40 8D E5 0D 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 20 E0 B3 19 00 00 BA 00 00 56 E3 06 20 A0 01 16 00 00 0A 04 40 9D E5 00 00 54 E3 0A 00 00 AA 54 10 9F E5 00 00 64 E2 ?? ?? ?? EB 00 00 60 E2 04 00 86 E5 40 10 9F E5 04 00 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __GI_tsearch_45c2e5d14b6b171fc139109e18af8ca0 {
	meta:
		aliases = "tsearch, __GI_tsearch"
		size = "116"
		objfiles = "tsearch@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 40 51 E2 00 60 A0 E1 02 70 A0 E1 04 00 A0 01 F0 80 BD 08 09 00 00 EA 00 10 95 E5 0F E0 A0 E1 07 F0 A0 E1 00 00 50 E3 01 00 00 1A 00 00 94 E5 F0 80 BD E8 00 30 94 E5 08 40 83 E2 04 40 83 B2 00 50 94 E5 00 00 55 E3 06 00 A0 E1 F1 FF FF 1A 0C 00 A0 E3 ?? ?? ?? EB 00 00 50 E3 00 00 84 15 00 60 80 15 04 50 80 15 08 50 80 15 F0 80 BD E8 }
	condition:
		$pattern
}

rule __encode_answer_3402741ade72dc7edb61a0056efe64ce {
	meta:
		aliases = "__encode_answer"
		size = "208"
		objfiles = "encodea@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 40 A0 E1 00 00 90 E5 01 70 A0 E1 02 60 A0 E1 ?? ?? ?? EB 00 50 50 E2 29 00 00 BA 10 30 94 E5 06 20 65 E0 0A 30 83 E2 03 00 52 E1 00 50 E0 B3 23 00 00 BA 05 30 D4 E5 05 30 C7 E7 04 30 94 E5 05 00 87 E0 01 30 C0 E5 09 30 D4 E5 01 00 80 E2 01 30 C0 E5 08 30 94 E5 01 00 80 E2 01 30 C0 E5 0F 30 D4 E5 01 00 80 E2 01 30 C0 E5 0E 30 D4 E5 01 00 80 E2 01 30 C0 E5 0D 30 D4 E5 01 00 80 E2 01 30 C0 E5 0C 30 94 E5 01 00 80 E2 01 30 C0 E5 11 30 D4 E5 01 00 80 E2 01 30 C0 E5 10 30 94 E5 01 00 80 E2 01 30 C0 E5 02 00 80 E2 14 10 94 E5 10 20 94 E5 ?? ?? ?? EB 10 30 94 E5 0A 30 83 E2 03 50 85 E0 }
	condition:
		$pattern
}

rule pthread_rwlock_wrlock_2869bd1061b2db71684fb497b05db1eb {
	meta:
		aliases = "pthread_rwlock_wrlock"
		size = "108"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 00 40 A0 E1 14 70 80 E2 C9 FF FF EB 00 50 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 08 30 94 E5 00 00 53 E3 05 10 A0 E1 07 00 A0 E1 02 00 00 1A 0C 60 94 E5 00 00 56 E3 05 00 00 0A 68 FF FF EB 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 E9 FF FF EB EE FF FF EA 0C 50 84 E5 04 00 A0 E1 ?? ?? ?? EB 06 00 A0 E1 F0 80 BD E8 }
	condition:
		$pattern
}

rule __GI_wcsncasecmp_e408ad5e71607b1d669763b18492d343 {
	meta:
		aliases = "wcsncasecmp, __GI_wcsncasecmp"
		size = "140"
		objfiles = "wcsncasecmp@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 50 A0 E1 01 70 A0 E1 02 60 A0 E1 04 00 00 EA 00 00 95 E5 00 00 50 E3 F0 80 BD 08 04 50 85 E2 04 70 87 E2 00 00 56 E3 01 00 00 1A 06 00 A0 E1 F0 80 BD E8 00 20 95 E5 00 30 97 E5 03 00 52 E1 02 00 A0 E1 01 60 46 E2 F0 FF FF 0A ?? ?? ?? EB 00 40 A0 E1 00 00 97 E5 ?? ?? ?? EB 00 00 54 E1 EA FF FF 0A 00 00 95 E5 ?? ?? ?? EB 00 40 A0 E1 00 00 97 E5 ?? ?? ?? EB 00 00 54 E1 00 00 E0 33 01 00 A0 23 F0 80 BD E8 }
	condition:
		$pattern
}

rule get_input_bytes_a495989bf890a186990f3c1b0d60ed66 {
	meta:
		aliases = "get_input_bytes"
		size = "120"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 50 A0 E1 01 70 A0 E1 02 60 A0 E1 13 00 00 EA 2C 20 85 E2 0C 00 92 E8 02 30 53 E0 02 10 A0 E1 03 00 00 1A 6B FF FF EB 00 00 50 E3 0B 00 00 1A F0 80 BD E8 03 00 56 E1 06 40 A0 B1 03 40 A0 A1 07 00 A0 E1 04 20 A0 E1 ?? ?? ?? EB 2C 30 95 E5 04 30 83 E0 2C 30 85 E5 06 60 64 E0 04 70 87 E0 00 00 56 E3 05 00 A0 E1 E8 FF FF CA 01 00 A0 E3 F0 80 BD E8 }
	condition:
		$pattern
}

rule __old_sem_post_a42c55e8b95e2955ba6a8352df17e7f9 {
	meta:
		aliases = "__old_sem_post"
		size = "224"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 00 50 A0 E1 04 D0 4D E2 03 70 A0 E3 00 40 95 E5 01 60 14 E2 07 20 A0 01 07 00 00 0A 06 01 74 E3 04 00 00 1A ?? ?? ?? EB 22 30 A0 E3 00 20 E0 E3 00 30 80 E5 25 00 00 EA 02 20 84 E2 05 00 A0 E1 04 10 A0 E1 D2 FF FF EB 00 00 50 E3 EE FF FF 0A 00 00 56 E3 04 E0 8D 02 04 60 2E 05 0D 00 00 0A 19 00 00 EA 08 40 91 E5 0E C0 A0 E1 00 00 00 EA 08 C0 80 E2 00 00 9C E5 00 00 50 E3 03 00 00 0A 18 20 91 E5 18 30 90 E5 03 00 52 E1 F7 FF FF BA 08 00 81 E5 00 10 8C E5 01 00 54 E3 04 10 A0 E1 EF FF FF 1A 04 00 00 EA 08 30 92 E5 00 30 8D E5 08 40 82 E5 ?? ?? ?? EB 00 00 00 EA 00 40 A0 E3 00 20 9D E5 }
	condition:
		$pattern
}

rule pthread_atfork_b3b17b881b9eb82d88e89e09c38fa232 {
	meta:
		aliases = "pthread_atfork"
		size = "160"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 00 50 A0 E1 18 00 A0 E3 01 60 A0 E1 02 70 A0 E1 ?? ?? ?? EB 00 40 50 E2 0C 00 80 02 F0 80 BD 08 5C 30 9F E5 5C 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 10 A0 E1 04 20 A0 E1 4C 00 9F E5 00 30 A0 E3 7C FF FF EB 06 10 A0 E1 08 20 84 E2 3C 00 9F E5 01 30 A0 E3 77 FF FF EB 07 10 A0 E1 10 20 84 E2 2C 00 9F E5 01 30 A0 E3 72 FF FF EB 24 30 9F E5 10 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 A0 E3 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xprt_register_6f5bceb1a0e21abfc70efe6257ba7f33 {
	meta:
		aliases = "__GI_xprt_register, xprt_register"
		size = "288"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 50 A0 E1 ?? ?? ?? EB B4 30 90 E5 00 00 53 E3 00 40 A0 E1 00 70 95 E5 05 00 00 1A ?? ?? ?? EB 00 01 A0 E1 ?? ?? ?? EB 00 00 50 E3 B4 00 84 E5 F0 80 BD 08 ?? ?? ?? EB 00 00 57 E1 F0 80 BD A8 B4 30 94 E5 01 0B 57 E3 07 51 83 E7 06 00 00 AA ?? ?? ?? EB A7 C2 A0 E1 0C 31 90 E7 1F 10 07 E2 01 20 A0 E3 12 31 83 E1 0C 31 80 E7 00 50 A0 E3 0F 00 00 EA ?? ?? ?? EB 00 20 90 E5 85 31 92 E7 01 00 73 E3 00 10 A0 E1 85 01 A0 E1 07 00 00 1A 85 71 82 E7 00 30 91 E5 00 20 A0 E3 00 30 83 E0 05 20 C3 E5 C3 20 82 E2 04 20 C3 E5 F0 80 BD E8 01 50 85 E2 ?? ?? ?? EB 00 40 90 E5 04 00 55 E1 00 60 A0 E1 }
	condition:
		$pattern
}

rule __GI_unsetenv_ebfbfefb774793f02c6e1c5b9c433f64 {
	meta:
		aliases = "unsetenv, __GI_unsetenv"
		size = "280"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 50 E2 10 D0 4D E2 08 00 00 0A 00 30 D6 E5 00 00 53 E3 05 00 00 0A 3D 10 A0 E3 ?? ?? ?? EB 00 30 D0 E5 3D 00 53 E3 00 C0 A0 E1 04 00 00 1A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 2A 00 00 EA 0D 00 A0 E1 AC 10 9F E5 AC 20 9F E5 AC 30 9F E5 0C 70 66 E0 0F E0 A0 E1 03 F0 A0 E1 A0 30 9F E5 94 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 94 30 9F E5 00 50 93 E5 00 00 55 E3 12 00 00 1A 14 00 00 EA 04 00 A0 E1 06 10 A0 E1 07 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 0A 00 00 1A 07 30 D4 E7 3D 00 53 E3 07 00 00 1A 05 20 A0 E1 04 30 92 E5 00 30 82 E5 00 00 53 E3 04 30 82 E2 03 20 A0 E1 01 00 00 0A }
	condition:
		$pattern
}

rule free_4912ae436253296246600ffc47a46ad0 {
	meta:
		aliases = "free"
		size = "520"
		objfiles = "free@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 50 E2 10 D0 4D E2 73 00 00 0A D0 21 9F E5 0D 00 A0 E1 CC 11 9F E5 CC 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 C4 51 9F E5 C4 31 9F E5 B0 01 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 20 16 E5 00 30 95 E5 03 C0 C2 E3 08 40 46 E2 03 00 5C E1 04 E0 A0 E1 07 00 00 8A 9C 01 9F E5 AC 11 A0 E1 01 21 90 E7 03 30 83 E3 08 20 84 E5 00 30 85 E5 01 41 80 E7 54 00 00 EA 02 00 12 E3 48 00 00 1A 01 30 83 E3 00 30 85 E5 04 30 16 E5 0C 10 84 E0 01 00 13 E3 04 70 91 E5 0C 00 00 1A 08 50 16 E5 04 30 65 E0 08 20 93 E5 0C E0 92 E5 03 00 5E E1 0C 00 93 E5 17 00 00 1A 08 30 90 E5 0E 00 53 E1 14 00 00 1A 08 20 80 E5 }
	condition:
		$pattern
}

rule fgets_unlocked_fe9f9edcd867da158960b3b9d0ff3094 {
	meta:
		aliases = "__GI_fgets_unlocked, fgets_unlocked"
		size = "148"
		objfiles = "fgets_unlocked@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 51 E2 00 70 A0 E1 02 40 A0 E1 00 50 A0 C1 15 00 00 CA 1A 00 00 EA 10 20 94 E5 18 30 94 E5 03 00 52 E1 04 00 00 2A 01 30 D2 E4 01 30 C5 E4 0A 00 53 E3 10 20 84 E5 0A 00 00 EA 04 00 A0 E1 ?? ?? ?? EB 01 00 70 E3 FF 30 00 E2 03 00 00 1A 00 30 D4 E5 08 00 13 E3 05 00 00 0A 08 00 00 EA 01 30 C5 E4 0A 00 53 E3 01 00 00 0A 01 60 56 E2 E8 FF FF 1A 07 00 55 E1 00 30 A0 83 00 30 C5 85 00 00 00 8A 00 70 A0 E3 07 00 A0 E1 F0 80 BD E8 }
	condition:
		$pattern
}

rule __GI_hcreate_r_02a7558551caefa3f5e57987e43c2875 {
	meta:
		aliases = "hcreate_r, __GI_hcreate_r"
		size = "172"
		objfiles = "hcreate_r@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 51 E2 04 00 00 1A ?? ?? ?? EB 16 30 A0 E3 06 10 A0 E1 00 30 80 E5 20 00 00 EA 00 30 96 E5 00 00 53 E3 00 10 A0 13 01 50 80 03 03 70 A0 03 01 00 00 0A 19 00 00 EA 02 50 85 E2 07 40 A0 E1 00 00 00 EA 02 40 84 E2 94 04 03 E0 05 00 53 E1 04 10 A0 E1 05 00 A0 E1 02 00 00 2A ?? ?? ?? EB 00 00 50 E3 F6 FF FF 1A 04 10 A0 E1 05 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 EE FF FF 0A 00 30 A0 E3 0C 10 A0 E3 08 30 86 E5 04 50 86 E5 01 00 85 E2 ?? ?? ?? EB 00 00 86 E5 00 10 50 E2 01 10 A0 13 01 00 A0 E1 F0 80 BD E8 }
	condition:
		$pattern
}

rule timer_create_1398f940ec126ffb72f176579dd73f44 {
	meta:
		aliases = "timer_create"
		size = "172"
		objfiles = "timer_create@librt.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 51 E2 44 D0 4D E2 08 60 8D 05 0E 30 A0 03 0D 60 A0 01 04 30 8D 05 08 30 96 E5 02 00 53 E3 00 40 A0 E1 02 70 A0 E1 1A 00 00 0A 08 00 A0 E3 ?? ?? ?? EB 00 50 50 E2 16 00 00 0A 00 50 8D E5 04 00 A0 E1 06 10 A0 E1 40 20 8D E2 01 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 01 00 74 E3 05 00 00 0A 08 30 96 E5 00 30 85 E5 40 30 9D E5 00 50 87 E5 04 30 85 E5 03 00 00 EA 05 00 A0 E1 ?? ?? ?? EB 00 00 00 EA 00 40 E0 E3 04 00 A0 E1 44 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule fgetws_unlocked_2d307553a3ebd45996f0415abf64f020 {
	meta:
		aliases = "__GI_fgetws_unlocked, fgetws_unlocked"
		size = "84"
		objfiles = "fgetws_unlocked@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 A0 E1 01 50 A0 E1 02 70 A0 E1 00 40 A0 E1 01 00 55 E3 07 00 A0 E1 01 50 45 E2 05 00 00 DA ?? ?? ?? EB 01 00 70 E3 02 00 00 0A 0A 00 50 E3 04 00 84 E4 F5 FF FF 1A 06 00 54 E1 00 60 A0 03 00 30 A0 13 06 00 A0 E1 00 30 84 15 F0 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_compare_and_swap_19216319c4ca5912f0468e43abef4180 {
	meta:
		aliases = "__pthread_compare_and_swap"
		size = "60"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 A0 E1 03 00 A0 E1 03 50 A0 E1 01 40 A0 E1 02 70 A0 E1 4B FF FF EB 00 30 96 E5 04 00 53 E1 00 00 A0 13 00 70 86 05 01 00 A0 03 00 30 A0 E3 00 30 85 E5 F0 80 BD E8 }
	condition:
		$pattern
}

rule fde_mixed_encoding_compare_02875c393eb91edf71b0a50368094753 {
	meta:
		aliases = "fde_mixed_encoding_compare"
		size = "144"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 A0 E1 08 D0 4D E2 01 00 A0 E1 02 70 A0 E1 01 50 A0 E1 C6 FF FF EB FF 40 00 E2 04 00 A0 E1 06 10 A0 E1 C4 FE FF EB 08 20 85 E2 00 10 A0 E1 04 30 8D E2 04 00 A0 E1 D5 FE FF EB 07 00 A0 E1 BB FF FF EB FF 40 00 E2 06 10 A0 E1 04 00 A0 E1 B9 FE FF EB 08 20 87 E2 00 10 A0 E1 0D 30 A0 E1 04 00 A0 E1 CA FE FF EB 04 20 9D E5 00 30 9D E5 03 00 52 E1 01 00 A0 83 01 00 00 8A 00 00 E0 33 00 00 A0 23 08 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule __getutid_111cb63883bc67da900bc191e0911d97 {
	meta:
		aliases = "__getutid"
		size = "152"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 A0 E1 28 70 80 E2 19 00 00 EA 01 30 D6 E5 00 C0 D6 E5 03 C4 8C E1 01 30 4C E2 03 38 A0 E1 0C E8 A0 E1 03 08 53 E3 4E E8 A0 E1 0C 58 A0 E1 05 00 00 8A 01 30 D4 E5 00 C0 D4 E5 03 3C A0 E1 43 C8 8C E1 45 08 5C E1 0F 00 00 0A 08 00 5E E3 05 00 5E 13 03 00 00 0A 06 00 5E E3 01 00 00 0A 07 00 5E E3 02 00 00 1A ?? ?? ?? EB 00 00 50 E3 05 00 00 0A CA FF FF EB 00 40 50 E2 07 10 A0 E1 04 20 A0 E3 28 00 84 E2 DF FF FF 1A 04 00 A0 E1 F0 80 BD E8 }
	condition:
		$pattern
}

rule __GI_getcwd_2ee8af58a7267e0ede9f35647912b22a {
	meta:
		aliases = "getcwd, __GI_getcwd"
		size = "220"
		objfiles = "getcwd@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 70 51 E2 00 50 A0 E1 0B 00 00 1A 00 00 50 E3 04 00 00 0A ?? ?? ?? EB 07 50 A0 E1 16 30 A0 E3 00 30 80 E5 29 00 00 EA ?? ?? ?? EB 01 0A 50 E3 00 40 A0 A1 01 4A A0 B3 03 00 00 EA 00 00 50 E3 07 40 A0 E1 00 60 A0 11 04 00 00 1A 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 1B 00 00 0A 00 60 A0 E1 04 10 A0 E1 06 00 A0 E1 B7 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 0B 00 00 EA 00 00 50 E3 09 00 00 BA 00 00 55 E3 00 00 57 03 03 00 00 1A 00 10 A0 E1 06 00 A0 E1 ?? ?? ?? EB 00 50 A0 E1 00 00 55 E3 06 50 A0 01 05 00 00 EA 00 00 55 E3 02 00 00 1A 06 00 A0 E1 }
	condition:
		$pattern
}

rule __GI_xdr_hyper_dc1f8afd10f8f0f8d59d8c75e305c4e2 {
	meta:
		aliases = "xdr_hyper, __GI_xdr_hyper"
		size = "224"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 70 90 E5 00 00 57 E3 08 D0 4D E2 00 50 A0 E1 01 60 A0 E1 12 00 00 1A 00 10 91 E5 04 20 96 E5 06 00 8D E8 04 10 8D E2 04 30 90 E5 C2 4F A0 E1 0F E0 A0 E1 04 F0 93 E5 00 00 50 E3 07 00 A0 01 23 00 00 0A 05 00 A0 E1 04 30 95 E5 0D 10 A0 E1 0F E0 A0 E1 04 F0 93 E5 00 00 50 E2 01 00 A0 13 1B 00 00 EA 01 00 57 E3 14 00 00 1A 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 12 00 00 0A 05 00 A0 E1 04 30 95 E5 0D 10 A0 E1 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 0B 00 00 0A 0C 00 9D E8 C3 4F A0 E1 03 40 A0 E1 00 30 A0 E3 02 30 83 E1 07 00 A0 E1 18 00 86 E8 04 00 00 EA 02 00 57 E3 }
	condition:
		$pattern
}

rule xdr_int64_t_530ff8abfd312312a9b5c5f857848c13 {
	meta:
		aliases = "xdr_int64_t"
		size = "216"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 70 90 E5 01 00 57 E3 08 D0 4D E2 00 50 A0 E1 01 60 A0 E1 16 00 00 0A 03 00 00 3A 02 00 57 E3 01 00 A0 03 28 00 00 0A 26 00 00 EA 00 10 91 E5 04 20 96 E5 06 00 8D E8 04 10 8D E2 04 30 90 E5 C2 4F A0 E1 0F E0 A0 E1 24 F0 93 E5 00 00 50 E3 1D 00 00 0A 05 00 A0 E1 04 30 95 E5 0D 10 A0 E1 0F E0 A0 E1 24 F0 93 E5 00 00 50 E2 01 00 A0 13 15 00 00 EA 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 0E 00 00 0A 05 00 A0 E1 04 30 95 E5 0D 10 A0 E1 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 07 00 00 0A 0C 00 9D E8 C3 4F A0 E1 03 40 A0 E1 00 30 A0 E3 02 30 83 E1 07 00 A0 E1 18 00 86 E8 }
	condition:
		$pattern
}

rule ether_hostton_37df54d78b7f7f1f16ff7cd500000fc6 {
	meta:
		aliases = "ether_hostton"
		size = "140"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 70 A0 E1 01 DC 4D E2 01 60 A0 E1 6C 00 9F E5 6C 10 9F E5 ?? ?? ?? EB 00 50 50 E2 00 40 E0 03 13 00 00 0A 07 00 00 EA E1 FF FF EB 00 10 50 E2 07 00 A0 E1 03 00 00 0A ?? ?? ?? EB 00 00 50 E3 00 40 A0 01 08 00 00 0A 01 1C A0 E3 05 20 A0 E1 0D 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 06 10 A0 E1 0D 00 A0 E1 EF FF FF 1A 00 40 E0 E3 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 01 DC 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fd_to_DIR_4fd696627511a566c21c8e867a8c49a7 {
	meta:
		aliases = "fd_to_DIR"
		size = "148"
		objfiles = "opendir@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 70 A0 E1 30 00 A0 E3 01 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 50 A0 01 19 00 00 0A 02 0C 54 E3 02 3C A0 33 14 40 80 E5 14 30 80 35 00 50 A0 E1 00 60 A0 E3 00 70 80 E5 10 60 80 E5 08 60 80 E5 04 60 80 E5 14 10 95 E5 01 00 A0 E3 ?? ?? ?? EB 00 00 50 E3 00 40 A0 E1 0C 00 85 E5 03 00 00 1A 05 00 A0 E1 ?? ?? ?? EB 04 50 A0 E1 04 00 00 EA 06 10 A0 E1 18 00 85 E2 0C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 F0 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdr_pointer_a859c8bf04e990f6a1a6a25084de74ed {
	meta:
		aliases = "xdr_pointer"
		size = "104"
		objfiles = "xdr_reference@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 C0 91 E5 04 D0 4D E2 00 C0 5C E2 01 C0 A0 13 01 40 A0 E1 04 10 8D E2 04 C0 21 E5 0D 10 A0 E1 02 60 A0 E1 03 70 A0 E1 00 50 A0 E1 ?? ?? ?? EB 00 00 50 E3 08 00 00 0A 00 30 9D E5 00 00 53 E3 01 00 A0 03 00 30 84 05 05 00 A0 11 04 10 A0 11 06 20 A0 11 07 30 A0 11 ?? ?? ?? 1B 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule getoffset_80765645440c38b6e7e876646d0965dd {
	meta:
		aliases = "getoffset"
		size = "148"
		objfiles = "tzset@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 C0 E0 E3 00 E0 A0 E3 7C 40 9F E5 0A 70 A0 E3 0C 60 A0 E1 0E 50 A0 E1 00 30 D0 E5 30 20 43 E2 FF 30 02 E2 09 00 53 E3 01 00 80 92 02 C0 A0 91 00 20 D0 E5 30 30 42 E2 09 00 53 E3 9C 07 03 90 01 40 84 E2 30 30 43 92 02 C0 83 90 00 20 D4 E5 01 00 80 92 02 00 5C E1 01 00 00 3A 00 00 A0 E3 F0 80 BD E8 00 30 D0 E5 3A 00 53 E3 92 CE 2E E0 01 00 80 02 05 C0 A0 E1 06 C0 A0 01 01 00 52 E3 E4 FF FF 8A 00 E0 81 E5 F0 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __gcc_personality_sj0_e0cc55dfeff814ccd86f1f7f3e0bbf51 {
	meta:
		aliases = "__gcc_personality_sj0"
		size = "228"
		objfiles = "unwind_c@libgcc_eh.a"
	strings:
		$pattern = { F0 40 2D E9 01 00 50 E3 24 D0 4D E2 03 00 A0 13 01 00 00 0A 24 D0 8D E2 F0 80 BD E8 02 00 11 E3 01 00 00 1A 08 00 A0 E3 F9 FF FF EA 00 30 A0 E3 3C 00 9D E5 20 30 8D E5 ?? ?? ?? EB 00 00 50 E3 F7 FF FF 0A 00 10 A0 E1 0D 20 A0 E1 3C 00 9D E5 C2 FF FF EB 20 10 8D E2 00 50 A0 E1 3C 00 9D E5 ?? ?? ?? EB 20 30 9D E5 00 00 53 E3 00 40 A0 E1 01 40 40 02 00 00 54 E3 E9 FF FF DA 1C 70 8D E2 18 60 8D E2 05 00 A0 E1 07 10 A0 E1 11 FF FF EB 06 10 A0 E1 0F FF FF EB 01 40 54 E2 00 50 A0 E1 F7 FF FF 1A 1C 30 9D E5 01 50 93 E2 DC FF FF 0A 38 20 9D E5 04 10 A0 E1 3C 00 9D E5 ?? ?? ?? EB 3C 00 9D E5 04 20 A0 E1 }
	condition:
		$pattern
}

rule sigset_50be3bb9a4ae1c2a52b550e3b11ed463 {
	meta:
		aliases = "sigset"
		size = "228"
		objfiles = "sigset@libc.a"
	strings:
		$pattern = { F0 40 2D E9 01 00 71 E3 00 00 50 13 30 D0 4D E2 01 70 A0 E1 00 60 A0 E1 00 50 A0 C3 01 50 A0 D3 01 00 00 DA 40 00 50 E3 04 00 00 DA ?? ?? ?? EB 16 30 A0 E3 00 10 E0 E3 00 30 80 E5 25 00 00 EA 02 00 51 E3 0B 00 00 1A 28 40 8D E2 00 10 A0 E1 04 00 A0 E1 28 50 8D E5 2C 50 8D E5 ?? ?? ?? EB 04 10 A0 E1 05 00 A0 E1 05 20 A0 E1 ?? ?? ?? EB 07 10 A0 E1 17 00 00 EA 14 40 8D E2 05 10 A0 E1 14 20 A0 E3 04 00 A0 E1 ?? ?? ?? EB 04 10 A0 E1 06 00 A0 E1 0D 20 A0 E1 14 70 8D E5 ?? ?? ?? EB 00 00 50 E3 00 10 E0 B3 0A 00 00 BA 28 40 8D E2 06 10 A0 E1 04 00 A0 E1 28 50 8D E5 2C 50 8D E5 ?? ?? ?? EB 04 10 A0 E1 }
	condition:
		$pattern
}

rule __GI___res_query_95fab8c3d7cfe678206f83ff0fc1a2cc {
	meta:
		aliases = "__res_query, __GI___res_query"
		size = "220"
		objfiles = "res_query@libc.a"
	strings:
		$pattern = { F0 40 2D E9 01 10 51 E2 01 10 A0 13 00 50 A0 E1 00 00 50 E3 01 00 A0 11 01 00 81 03 2C D0 4D E2 00 10 A0 E3 00 00 50 E3 28 10 8D E5 02 60 A0 E1 03 70 A0 E1 03 00 00 0A ?? ?? ?? EB 00 40 E0 E3 03 30 A0 E3 11 00 00 EA 00 10 A0 E1 28 20 A0 E3 0D 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 06 10 A0 E1 0D 30 A0 E1 28 20 8D E2 ?? ?? ?? EB 00 40 50 E2 08 00 00 AA ?? ?? ?? EB 00 30 90 E5 00 00 53 E3 00 40 E0 13 11 00 00 1A 00 40 E0 E3 02 30 A0 E3 00 30 80 E5 0D 00 00 EA 00 00 9D E5 ?? ?? ?? EB 04 30 9D E5 06 00 53 E1 06 00 00 1A 40 30 9D E5 03 00 54 E1 03 40 A0 A1 07 00 A0 E1 28 10 9D E5 04 20 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __stdio_fwrite_66270f7c00d084b3e28d9eb8c57ecb6f {
	meta:
		aliases = "__stdio_fwrite"
		size = "312"
		objfiles = "_fwrite@libc.a"
	strings:
		$pattern = { F0 40 2D E9 01 30 D2 E5 03 34 A0 E1 02 4C 13 E2 02 50 A0 E1 00 70 A0 E1 01 60 A0 E1 3E 00 00 1A 04 30 92 E5 02 00 73 E3 10 00 92 E5 0C 30 92 E5 09 00 00 1A 03 40 60 E0 04 00 51 E1 01 40 A0 31 04 20 A0 E1 07 10 A0 E1 ?? ?? ?? EB 10 30 95 E5 04 30 83 E0 10 30 85 E5 34 00 00 EA 03 30 60 E0 03 00 51 E1 24 00 00 8A 06 20 A0 E1 07 10 A0 E1 ?? ?? ?? EB 10 30 95 E5 01 20 D5 E5 06 30 83 E0 01 00 12 E3 10 30 85 E5 28 00 00 0A 07 00 A0 E1 0A 10 A0 E3 06 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 22 00 00 0A 05 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 1E 00 00 0A 06 00 50 E1 00 40 A0 31 06 40 A0 21 06 30 64 E0 03 70 87 E0 }
	condition:
		$pattern
}

rule ldiv_1f18dcf26b8cb7b8f97fdc9a6ae11761 {
	meta:
		aliases = "ldiv"
		size = "80"
		objfiles = "ldiv@libc.a"
	strings:
		$pattern = { F0 40 2D E9 01 40 A0 E1 00 70 A0 E1 02 10 A0 E1 04 00 A0 E1 02 60 A0 E1 ?? ?? ?? EB 06 10 A0 E1 00 50 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 00 54 E3 02 00 00 BA 00 00 50 E3 00 00 66 B0 01 50 85 B2 04 00 87 E5 07 00 A0 E1 00 50 87 E5 F0 80 BD E8 }
	condition:
		$pattern
}

rule setstate_r_fb3d3c7066c9f0bb747f708268595f8d {
	meta:
		aliases = "__GI_setstate_r, setstate_r"
		size = "200"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { F0 40 2D E9 01 40 A0 E1 0C 10 D1 E5 00 00 51 E3 04 30 94 15 04 60 80 E2 08 00 94 E5 01 1C A0 11 03 30 60 10 43 31 A0 11 41 1C A0 11 05 20 A0 13 92 13 23 10 04 10 00 05 04 30 00 15 05 10 A0 E3 04 00 16 E5 ?? ?? ?? EB 04 00 50 E3 17 00 00 8A 6C 20 9F E5 00 31 82 E0 14 50 93 E5 00 71 92 E7 00 00 50 E3 0D 50 C4 E5 0E 70 C4 E5 0C 00 C4 E5 09 00 00 0A 05 10 A0 E3 04 00 16 E5 ?? ?? ?? EB 00 31 86 E0 04 30 84 E5 00 00 87 E0 05 10 A0 E1 ?? ?? ?? EB 00 01 86 E0 00 00 84 E5 05 31 86 E0 00 00 A0 E3 10 30 84 E5 08 60 84 E5 F0 80 BD E8 ?? ?? ?? EB 16 30 A0 E3 00 30 80 E5 00 00 E0 E3 F0 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule cargf_459666b6e5c366097adb268169965fad {
	meta:
		aliases = "cargf"
		size = "64"
		objfiles = "cargf@libm.a"
	strings:
		$pattern = { F0 40 2D E9 01 40 A0 E1 ?? ?? ?? EB 00 60 A0 E1 04 00 A0 E1 01 70 A0 E1 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 00 40 A0 E1 01 50 A0 E1 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? EB ?? ?? ?? EB F0 80 BD E8 }
	condition:
		$pattern
}

rule svcraw_reply_22073f93a4dc5d554c52b6aebd23f7c6 {
	meta:
		aliases = "svcraw_reply"
		size = "124"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { F0 40 2D E9 01 60 A0 E1 ?? ?? ?? EB BC 50 90 E5 00 00 55 E3 14 00 00 0A 54 30 9F E5 8E 4D 85 E2 50 70 9F E5 00 10 A0 E3 14 40 84 E2 03 10 85 E7 04 00 A0 E1 07 30 95 E7 0F E0 A0 E1 14 F0 93 E5 04 00 A0 E1 06 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 05 00 00 0A 07 30 95 E7 04 00 A0 E1 0F E0 A0 E1 10 F0 93 E5 01 00 A0 E3 F0 80 BD E8 00 00 A0 E3 F0 80 BD E8 94 23 00 00 98 23 00 00 }
	condition:
		$pattern
}

rule clnt_spcreateerror_2fbdd55efec76ece4ec15e29a5e4837a {
	meta:
		aliases = "__GI_clnt_spcreateerror, clnt_spcreateerror"
		size = "264"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { F0 40 2D E9 01 DB 4D E2 00 40 A0 E1 F0 FF FF EB 00 70 50 E2 36 00 00 0A ?? ?? ?? EB 04 20 A0 E1 00 60 A0 E1 D4 10 9F E5 07 00 A0 E1 ?? ?? ?? EB 00 40 87 E0 00 00 96 E5 ?? ?? ?? EB 00 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 ?? ?? ?? EB 00 30 96 E5 0C 00 53 E3 00 40 84 E0 0F 00 00 0A 0E 00 53 E3 1E 00 00 1A 94 10 9F E5 04 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 ?? ?? ?? EB 00 40 84 E0 04 00 96 E5 ?? ?? ?? EB 00 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 ?? ?? ?? EB 0F 00 00 EA 5C 10 9F E5 04 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 ?? ?? ?? EB 01 2B A0 E3 00 40 84 E0 0D 10 A0 E1 08 00 96 E5 ?? ?? ?? EB }
	condition:
		$pattern
}

rule clnt_sperror_d82f279187edad2f26e86575dd83340f {
	meta:
		aliases = "__GI_clnt_sperror, clnt_sperror"
		size = "476"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { F0 40 2D E9 01 DB 4D E2 0C D0 4D E2 00 40 A0 E1 01 50 A0 E1 A5 FF FF EB 00 70 50 E2 62 00 00 0A 04 30 94 E5 04 00 A0 E1 01 1B 8D E2 0F E0 A0 E1 08 F0 93 E5 05 20 A0 E1 7C 11 9F E5 07 00 A0 E1 ?? ?? ?? EB 00 40 87 E0 00 04 9D E5 ?? ?? ?? EB 00 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 ?? ?? ?? EB 00 34 9D E5 00 50 84 E0 11 00 53 E3 03 F1 9F 97 42 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0D 10 A0 E1 01 2B A0 E3 }
	condition:
		$pattern
}

rule __GI_fseeko64_bf70414258ba19f219e8bc9a26fccd37 {
	meta:
		aliases = "fseeko64, __GI_fseeko64"
		size = "304"
		objfiles = "fseeko64@libc.a"
	strings:
		$pattern = { F0 40 2D E9 02 00 53 E3 18 D0 4D E2 03 60 A0 E1 10 10 8D E5 14 20 8D E5 00 50 A0 E1 04 00 00 9A ?? ?? ?? EB 00 40 E0 E3 16 30 A0 E3 00 30 80 E5 37 00 00 EA 34 70 90 E5 00 00 57 E3 0A 00 00 1A 38 40 80 E2 D4 30 9F E5 0D 00 A0 E1 D0 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 C0 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 D5 E5 40 00 13 E3 03 00 00 0A 05 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 1B 00 00 1A 01 00 56 E3 04 00 00 1A 05 00 A0 E1 10 10 8D E2 ?? ?? ?? EB 00 00 50 E3 14 00 00 BA 06 20 A0 E1 05 00 A0 E1 10 10 8D E2 ?? ?? ?? EB 00 00 50 E3 0E 00 00 BA 00 30 95 E5 08 20 95 E5 00 00 A0 E3 }
	condition:
		$pattern
}

rule addmntent_0999352773cce4e7c091c64b8203e2cd {
	meta:
		aliases = "addmntent"
		size = "100"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { F0 40 2D E9 02 20 A0 E3 10 D0 4D E2 01 60 A0 E1 00 10 A0 E3 00 70 A0 E1 ?? ?? ?? EB 00 00 50 E3 01 00 A0 B3 0B 00 00 BA 08 C0 86 E2 00 50 9C E8 10 40 86 E2 30 00 94 E8 0C 00 96 E8 07 00 A0 E1 18 10 9F E5 00 50 8D E8 08 40 8D E5 0C 50 8D E5 ?? ?? ?? EB A0 0F A0 E1 10 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fmin_ee6e46a63bd9c2985d65018922760db5 {
	meta:
		aliases = "__GI_fmin, fmin"
		size = "100"
		objfiles = "s_fmin@libm.a"
	strings:
		$pattern = { F0 40 2D E9 02 40 A0 E1 03 50 A0 E1 00 60 A0 E1 01 70 A0 E1 ?? ?? ?? EB 00 00 50 E3 0D 00 00 0A 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 06 00 00 0A 06 00 A0 E1 07 10 A0 E1 04 20 A0 E1 05 30 A0 E1 ?? ?? ?? EB 00 00 50 E3 01 00 00 BA 04 60 A0 E1 05 70 A0 E1 06 00 A0 E1 07 10 A0 E1 F0 80 BD E8 }
	condition:
		$pattern
}

rule fmax_64cb3e26b4c0fa32c6e3d5a8012fc7be {
	meta:
		aliases = "__GI_fmax, fmax"
		size = "100"
		objfiles = "s_fmax@libm.a"
	strings:
		$pattern = { F0 40 2D E9 02 40 A0 E1 03 50 A0 E1 00 60 A0 E1 01 70 A0 E1 ?? ?? ?? EB 00 00 50 E3 0D 00 00 0A 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 06 00 00 0A 06 00 A0 E1 07 10 A0 E1 04 20 A0 E1 05 30 A0 E1 ?? ?? ?? EB 00 00 50 E3 01 00 00 CA 04 60 A0 E1 05 70 A0 E1 06 00 A0 E1 07 10 A0 E1 F0 80 BD E8 }
	condition:
		$pattern
}

rule writetcp_23295e4869529c88dbdeba3f92307d9e {
	meta:
		aliases = "writetcp"
		size = "84"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { F0 40 2D E9 02 60 A0 E1 00 70 A0 E1 01 50 A0 E1 02 40 A0 E1 09 00 00 EA 00 00 97 E5 ?? ?? ?? EB 00 00 50 E3 2C 20 97 B5 00 30 A0 B3 00 60 E0 B3 00 30 82 B5 04 00 00 BA 00 50 85 E0 04 40 60 E0 00 20 54 E2 05 10 A0 E1 F2 FF FF CA 06 00 A0 E1 F0 80 BD E8 }
	condition:
		$pattern
}

rule __GI_fdim_311d47d2f667a37b68d5f0576d69623c {
	meta:
		aliases = "fdim, __GI_fdim"
		size = "104"
		objfiles = "s_fdim@libm.a"
	strings:
		$pattern = { F0 40 2D E9 02 60 A0 E1 03 70 A0 E1 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? EB 01 00 50 E3 40 00 9F 95 07 00 00 9A 04 00 A0 E1 05 10 A0 E1 06 20 A0 E1 07 30 A0 E1 ?? ?? ?? EB 00 00 50 E3 02 00 00 CA 00 00 A0 E3 00 10 A0 E3 F0 80 BD E8 04 00 A0 E1 05 10 A0 E1 06 20 A0 E1 07 30 A0 E1 ?? ?? ?? EB F0 80 BD E8 00 00 F0 7F }
	condition:
		$pattern
}

rule __fp_range_check_9713f87350619e4f7c154e89a21f062b {
	meta:
		aliases = "__fp_range_check"
		size = "156"
		objfiles = "__fp_range_check@libc.a"
	strings:
		$pattern = { F0 40 2D E9 02 60 A0 E1 03 70 A0 E1 84 20 9F E5 00 30 A0 E3 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 F0 80 BD 18 04 00 A0 E1 05 10 A0 E1 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? EB 00 00 50 E3 F0 80 BD 08 38 20 9F E5 00 30 A0 E3 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 F0 80 BD 08 ?? ?? ?? EB 22 30 A0 E3 00 30 80 E5 F0 80 BD E8 00 00 D0 3F }
	condition:
		$pattern
}

rule __GI_erand48_r_448dcf41b7831c0bf2dc4cd3a3811638 {
	meta:
		aliases = "erand48_r, __GI_erand48_r"
		size = "152"
		objfiles = "erand48_r@libc.a"
	strings:
		$pattern = { F0 40 2D E9 02 70 A0 E1 00 60 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 40 A0 E3 00 50 A0 E3 00 00 E0 B3 F0 80 BD B8 05 C0 D6 E5 03 10 D6 E5 02 41 C4 E3 04 20 D6 E5 02 00 D6 E5 01 31 C4 E3 01 04 80 E1 0C 24 82 E1 FF 35 83 E3 01 C0 D6 E5 00 10 D6 E5 03 46 83 E3 02 22 A0 E1 20 26 82 E1 0C 14 81 E1 24 3A A0 E1 02 36 83 E1 01 12 A0 E1 63 46 A0 E1 00 5A 81 E1 05 10 A0 E1 04 00 A0 E1 10 20 9F E5 00 30 A0 E3 ?? ?? ?? EB 03 00 87 E8 00 00 A0 E3 F0 80 BD E8 00 00 F0 3F }
	condition:
		$pattern
}

rule __GI_fwrite_unlocked_89144879274f98bf09b6ddb026d92c18 {
	meta:
		aliases = "fwrite_unlocked, __GI_fwrite_unlocked"
		size = "172"
		objfiles = "fwrite_unlocked@libc.a"
	strings:
		$pattern = { F0 40 2D E9 03 40 A0 E1 00 30 D3 E5 C0 30 03 E2 C0 00 53 E3 00 70 A0 E1 01 50 A0 E1 02 60 A0 E1 04 00 00 0A 04 00 A0 E1 80 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 19 00 00 1A 00 00 55 E3 00 00 56 13 16 00 00 0A 00 00 E0 E3 05 10 A0 E1 ?? ?? ?? EB 00 00 56 E1 07 00 00 8A 04 20 A0 E1 95 06 01 E0 07 00 A0 E1 ?? ?? ?? EB 05 10 A0 E1 ?? ?? ?? EB 00 20 A0 E1 0A 00 00 EA 00 30 94 E5 08 30 83 E3 43 24 A0 E1 01 20 C4 E5 00 30 C4 E5 ?? ?? ?? EB 16 30 A0 E3 00 20 A0 E3 00 30 80 E5 00 00 00 EA 00 20 A0 E3 02 00 A0 E1 F0 80 BD E8 }
	condition:
		$pattern
}

rule pwrite_9f456afe647f211a108d8f577808cae8 {
	meta:
		aliases = "pread, recv, send, pwrite"
		size = "84"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 04 D0 4D E2 00 40 A0 E1 01 50 A0 E1 02 60 A0 E1 03 70 A0 E1 0D 10 A0 E1 01 00 A0 E3 ?? ?? ?? EB 05 10 A0 E1 06 20 A0 E1 07 30 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 10 A0 E3 00 40 A0 E1 00 00 9D E5 ?? ?? ?? EB 04 00 A0 E1 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule unlockpt_b3eb29c0a2c6e6ba0d071e9daff2d1e3 {
	meta:
		aliases = "unlockpt"
		size = "92"
		objfiles = "unlockpt@libc.a"
	strings:
		$pattern = { F0 40 2D E9 04 D0 4D E2 00 40 A0 E1 ?? ?? ?? EB 00 70 A0 E3 04 20 8D E2 00 60 90 E5 00 50 A0 E1 04 70 22 E5 04 00 A0 E1 0D 20 A0 E1 24 10 9F E5 ?? ?? ?? EB 00 00 50 E3 04 00 00 0A 00 30 95 E5 16 00 53 E3 00 60 85 05 00 00 E0 13 07 00 A0 01 04 D0 8D E2 F0 80 BD E8 31 54 04 40 }
	condition:
		$pattern
}

rule lseek64_ab186285bdae77d75d368f2f237c223e {
	meta:
		aliases = "lseek64"
		size = "92"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 04 D0 4D E2 00 60 A0 E1 01 40 A0 E1 02 50 A0 E1 03 70 A0 E1 0D 10 A0 E1 01 00 A0 E3 ?? ?? ?? EB 05 20 A0 E1 07 30 A0 E1 06 00 A0 E1 04 10 A0 E1 ?? ?? ?? EB 00 40 A0 E1 01 50 A0 E1 00 00 9D E5 00 10 A0 E3 ?? ?? ?? EB 04 00 A0 E1 05 10 A0 E1 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule _charpad_62a96c7d27912441e7558c25adc61503 {
	meta:
		aliases = "_charpad"
		size = "80"
		objfiles = "_vfprintf_internal@libc.a"
	strings:
		$pattern = { F0 40 2D E9 04 D0 4D E2 04 50 8D E2 01 10 65 E5 02 60 A0 E1 00 70 A0 E1 02 40 A0 E1 00 00 00 EA 01 40 44 E2 00 00 54 E3 05 00 A0 E1 01 10 A0 E3 07 20 A0 E1 02 00 00 0A ?? ?? ?? EB 01 00 50 E3 F6 FF FF 0A 06 00 64 E0 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule _charpad_a37a935b1c0d096e3c0ef38febac448b {
	meta:
		aliases = "_charpad"
		size = "80"
		objfiles = "_vfwprintf_internal@libc.a"
	strings:
		$pattern = { F0 40 2D E9 04 D0 4D E2 04 50 8D E2 04 10 25 E5 02 60 A0 E1 00 70 A0 E1 02 40 A0 E1 00 00 00 EA 01 40 44 E2 00 00 54 E3 0D 00 A0 E1 01 10 A0 E3 07 20 A0 E1 02 00 00 0A ?? ?? ?? EB 01 00 50 E3 F6 FF FF 0A 06 00 64 E0 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule svc_unregister_e6bc97ea5006768f462e3dc79899210a {
	meta:
		aliases = "__GI_svc_unregister, svc_unregister"
		size = "96"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { F0 40 2D E9 04 D0 4D E2 0D 20 A0 E1 00 60 A0 E1 01 70 A0 E1 53 FF FF EB 00 40 50 E2 0D 00 00 0A 00 30 9D E5 00 50 94 E5 00 00 53 E3 00 50 83 15 01 00 00 1A ?? ?? ?? EB B8 50 80 E5 00 30 A0 E3 04 00 A0 E1 00 30 84 E5 ?? ?? ?? EB 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? EB 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule lsearch_465d5b4b215242af3615d93fb78e31e6 {
	meta:
		aliases = "lsearch"
		size = "84"
		objfiles = "lsearch@libc.a"
	strings:
		$pattern = { F0 40 2D E9 04 D0 4D E2 18 C0 9D E5 00 70 A0 E1 00 C0 8D E5 01 60 A0 E1 02 40 A0 E1 03 50 A0 E1 ?? ?? ?? EB 00 00 50 E3 07 00 00 1A 00 30 94 E5 07 10 A0 E1 93 65 20 E0 05 20 A0 E1 ?? ?? ?? EB 00 30 94 E5 01 30 83 E2 00 30 84 E5 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule xdrrec_getbytes_986e2ee64c6e493b7d8baf6b73f3146a {
	meta:
		aliases = "xdrrec_getbytes"
		size = "144"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { F0 40 2D E9 0C 50 90 E5 01 70 A0 E1 02 60 A0 E1 17 00 00 EA 34 20 95 E5 00 00 52 E3 06 00 00 1A 38 30 95 E5 00 00 53 E3 16 00 00 1A 9F FF FF EB 00 00 50 E3 0E 00 00 1A 12 00 00 EA 02 00 56 E1 06 40 A0 31 02 40 A0 21 07 10 A0 E1 05 00 A0 E1 04 20 A0 E1 77 FF FF EB 00 00 50 E3 06 60 64 E0 04 70 87 E0 07 00 00 0A 34 30 95 E5 03 30 64 E0 34 30 85 E5 00 00 56 E3 05 00 A0 E1 E4 FF FF 1A 01 00 A0 E3 F0 80 BD E8 00 00 A0 E3 F0 80 BD E8 }
	condition:
		$pattern
}

rule encrypt_5273da7c875ff16cf139972c76452a75 {
	meta:
		aliases = "encrypt"
		size = "252"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { F0 40 2D E9 0C D0 4D E2 00 60 A0 E1 01 50 A0 E1 9C FD FF EB 00 00 A0 E3 DE FE FF EB D4 70 9F E5 00 C0 A0 E3 06 10 A0 E1 0C 40 A0 E1 10 00 00 EA 0C 20 8D E2 0C 31 82 E0 03 E0 A0 E1 04 00 A0 E1 08 40 03 E5 07 00 00 EA 00 30 D1 E5 01 00 13 E3 00 31 97 17 08 20 1E 15 02 30 83 11 08 30 0E 15 01 10 81 E2 01 00 80 E2 1F 00 50 E3 F5 FF FF DA 01 C0 8C E2 01 00 5C E3 EC FF FF DA 00 00 55 E3 04 20 8D E2 01 C0 A0 03 00 C0 E0 13 03 00 9D E9 04 30 82 E2 00 C0 8D E5 D8 FE FF EB 54 50 9F E5 00 00 A0 E3 00 40 A0 E1 0A 00 00 EA 01 21 95 E7 08 30 1C E5 03 00 12 E1 0E 20 81 E1 01 10 81 E2 00 30 A0 03 01 30 A0 13 }
	condition:
		$pattern
}

rule recvfrom_772dc59a2a283d2b973f08b7b8fd7337 {
	meta:
		aliases = "sendto, recvfrom"
		size = "100"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 0C D0 4D E2 00 70 A0 E1 01 40 A0 E1 01 00 A0 E3 08 10 8D E2 02 50 A0 E1 03 60 A0 E1 ?? ?? ?? EB 20 C0 9D E5 00 C0 8D E5 24 C0 9D E5 04 10 A0 E1 05 20 A0 E1 06 30 A0 E1 07 00 A0 E1 04 C0 8D E5 ?? ?? ?? EB 00 10 A0 E3 00 40 A0 E1 08 00 9D E5 ?? ?? ?? EB 04 00 A0 E1 0C D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule dlinfo_cddd90ff9a972d69791253afebccbae4 {
	meta:
		aliases = "dlinfo"
		size = "324"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { F0 40 2D E9 10 41 9F E5 10 D0 4D E2 0C 11 9F E5 00 00 94 E5 ?? ?? ?? EB 04 31 9F E5 04 71 9F E5 00 50 93 E5 04 60 A0 E1 0E 00 00 EA 1C 20 95 E5 00 20 8D E5 18 20 95 E5 02 21 87 E0 04 20 8D E5 21 00 D5 E5 20 20 D5 E5 00 24 82 E1 08 20 8D E5 04 20 95 E5 0C 20 8D E5 00 20 95 E5 00 00 9C E5 ?? ?? ?? EB 0C 50 95 E5 00 00 55 E3 05 30 A0 E1 B4 10 9F E5 06 C0 A0 E1 EB FF FF 1A AC 40 9F E5 00 00 96 E5 00 20 94 E5 A4 10 9F E5 ?? ?? ?? EB 84 50 9F E5 00 40 94 E5 04 00 00 EA 00 20 94 E5 00 00 95 E5 04 30 92 E5 ?? ?? ?? EB 10 40 94 E5 00 00 54 E3 7C 10 9F E5 F7 FF FF 1A 78 30 9F E5 54 60 9F E5 00 50 93 E5 }
	condition:
		$pattern
}

rule init_object_18b7aae8532a4db2533c47af35f261d0 {
	meta:
		aliases = "init_object"
		size = "316"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { F0 40 2D E9 10 C0 90 E5 AC 25 B0 E1 08 D0 4D E2 00 50 A0 E1 02 60 A0 11 1D 00 00 1A 10 30 D0 E5 02 00 13 E3 40 00 00 0A 0C 30 90 E5 00 10 93 E5 00 00 51 E3 8C 3A A0 01 A3 3A A0 01 01 60 A0 01 10 30 80 05 12 00 00 0A 03 40 A0 E1 02 60 A0 E1 05 00 A0 E1 2F FF FF EB 04 10 B4 E5 00 00 51 E3 00 60 86 E0 F9 FF FF 1A 10 30 95 E5 FF 24 C6 E3 83 3A A0 E1 0E 26 C2 E3 A3 3A A0 E1 82 35 83 E1 02 00 56 E1 10 30 85 E5 83 3A A0 11 A3 3A A0 11 10 30 85 15 0D 00 A0 E1 06 10 A0 E1 6E FF FF EB 00 00 50 E3 0D 70 A0 E1 18 00 00 0A 10 30 D5 E5 02 00 13 E3 17 00 00 0A 0C 30 95 E5 00 20 93 E5 00 00 52 E3 06 00 00 0A }
	condition:
		$pattern
}

rule _obstack_newchunk_bef626bdcdccd9f8d6bbd41516171d20 {
	meta:
		aliases = "_obstack_newchunk"
		size = "364"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { F0 40 2D E9 18 30 90 E5 0C 20 80 E2 84 00 12 E8 02 70 47 E0 64 30 83 E2 07 30 83 E0 01 30 83 E0 00 20 90 E5 28 10 D0 E5 C7 31 83 E0 02 00 53 E1 03 50 A0 A1 02 50 A0 B1 01 00 11 E3 00 40 A0 E1 04 60 90 E5 1C 30 90 E5 04 00 00 0A 05 10 A0 E1 24 00 90 E5 0F E0 A0 E1 03 F0 A0 E1 02 00 00 EA 05 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 00 00 50 E3 52 00 00 0B 18 30 94 E5 08 20 80 E2 02 00 53 E3 05 10 80 E0 03 20 82 E0 27 C1 A0 C1 10 10 84 E5 04 00 84 E5 00 10 80 E5 03 50 C2 E1 04 60 80 E5 00 30 A0 D3 01 10 4C C2 05 00 00 CA 07 00 00 EA 08 30 94 E5 01 21 A0 E1 02 30 93 E7 02 30 85 E7 01 10 41 E2 00 00 51 E3 }
	condition:
		$pattern
}

rule seekdir_57c50a7357ca9b07e334b6a13e6ceea4 {
	meta:
		aliases = "seekdir"
		size = "140"
		objfiles = "seekdir@libc.a"
	strings:
		$pattern = { F0 40 2D E9 18 50 80 E2 10 D0 4D E2 00 40 A0 E1 05 20 A0 E1 01 60 A0 E1 0D 00 A0 E1 58 10 9F E5 58 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 50 30 9F E5 05 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 06 10 A0 E1 00 00 94 E5 00 20 A0 E3 ?? ?? ?? EB 00 30 A0 E3 08 30 84 E5 10 00 84 E5 04 30 84 E5 0D 00 A0 E1 01 10 A0 E3 1C 30 9F E5 0D 70 A0 E1 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule if_indextoname_75654ca3f45449f44faf6fb69d835453 {
	meta:
		aliases = "if_indextoname"
		size = "136"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { F0 40 2D E9 20 D0 4D E2 00 50 A0 E1 01 60 A0 E1 ?? ?? ?? EB 00 40 50 E2 00 00 A0 B3 16 00 00 BA 5C 10 9F E5 0D 20 A0 E1 10 50 8D E5 ?? ?? ?? EB 00 00 50 E3 0D 70 A0 E1 09 00 00 AA ?? ?? ?? EB 00 50 A0 E1 04 00 A0 E1 00 40 95 E5 ?? ?? ?? EB 13 00 54 E3 06 40 A0 03 00 00 A0 E3 00 40 85 E5 05 00 00 EA 04 00 A0 E1 ?? ?? ?? EB 06 00 A0 E1 0D 10 A0 E1 10 20 A0 E3 ?? ?? ?? EB 20 D0 8D E2 F0 80 BD E8 10 89 00 00 }
	condition:
		$pattern
}

rule _stdio_openlist_dec_use_4aa20ff78fb408c03c660d5672f15bb0 {
	meta:
		aliases = "_stdio_openlist_dec_use"
		size = "320"
		objfiles = "fflush_unlocked@libc.a"
	strings:
		$pattern = { F0 40 2D E9 20 D0 4D E2 10 00 8D E2 04 11 9F E5 04 21 9F E5 04 41 9F E5 0F E0 A0 E1 04 F0 A0 E1 FC 50 9F E5 F0 00 9F E5 0F E0 A0 E1 05 F0 A0 E1 F0 30 9F E5 00 30 93 E5 01 00 53 E3 2A 00 00 1A E4 30 9F E5 00 30 93 E5 00 00 53 E3 26 00 00 DA 0D 00 A0 E1 BC 10 9F E5 D0 20 9F E5 0F E0 A0 E1 04 F0 A0 E1 C4 00 9F E5 0F E0 A0 E1 05 F0 A0 E1 BC 30 9F E5 00 40 93 E5 03 70 A0 E1 00 60 A0 E3 0F 00 00 EA 00 30 D4 E5 01 20 D4 E5 02 34 83 E1 01 10 03 E0 30 00 51 E3 20 50 94 E5 04 60 A0 11 06 00 00 1A 00 00 56 E3 00 50 87 05 20 50 86 15 01 30 D4 E5 20 00 13 E3 04 00 A0 11 ?? ?? ?? 1B 05 40 A0 E1 00 00 54 E3 }
	condition:
		$pattern
}

rule svctcp_recv_72a5e9feeeea813ca993844353163a30 {
	meta:
		aliases = "svctcp_recv"
		size = "68"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { F0 40 2D E9 2C 50 90 E5 01 70 A0 E3 08 40 85 E2 01 60 A0 E1 08 70 85 E5 04 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 06 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 30 96 15 07 00 A0 11 04 30 85 15 00 00 85 05 F0 80 BD E8 }
	condition:
		$pattern
}

rule svcunix_recv_a94e363bbc2dae98d28c2036e7c6758e {
	meta:
		aliases = "svcunix_recv"
		size = "92"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { F0 40 2D E9 2C 60 90 E5 01 70 A0 E3 08 40 86 E2 01 50 A0 E1 08 70 86 E5 04 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 30 95 15 04 30 86 15 1C 30 A0 13 2C 30 85 15 10 30 9F 15 07 00 A0 11 28 30 85 15 24 70 85 15 00 00 86 05 F0 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __fork_ca1cf6a5e7cdf85b0c02bef6e3e48b51 {
	meta:
		aliases = "fork, __fork"
		size = "360"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 30 01 9F E5 30 41 9F E5 04 D0 4D E2 0F E0 A0 E1 04 F0 A0 E1 24 31 9F E5 00 00 93 E5 20 31 9F E5 00 70 93 E5 1C 31 9F E5 00 50 93 E5 E9 FF FF EB ?? ?? ?? EB 10 01 9F E5 0F E0 A0 E1 04 F0 A0 E1 ?? ?? ?? EB 00 60 50 E2 2D 00 00 1A FC 50 9F E5 00 00 55 E3 25 00 00 0A F4 30 9F E5 0D 00 A0 E1 0D 40 A0 E1 0F E0 A0 E1 03 F0 A0 E1 E4 30 9F E5 01 10 A0 E3 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 C4 00 9F E5 0D 10 A0 E1 0F E0 A0 E1 05 F0 A0 E1 C4 30 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 00 00 55 E3 11 00 00 0A A4 30 9F E5 0D 00 A0 E1 0D 40 A0 E1 0F E0 A0 E1 03 F0 A0 E1 94 30 9F E5 06 10 A0 E1 }
	condition:
		$pattern
}

rule _dl_map_cache_5d0a8e9189970f3b95237adb7ec34499 {
	meta:
		aliases = "_dl_map_cache"
		size = "608"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { F0 40 2D E9 30 E2 9F E5 00 00 9E E5 01 00 70 E3 44 D0 4D E2 86 00 00 0A 00 00 50 E3 83 00 00 1A 18 62 9F E5 04 10 8D E2 06 00 A0 E1 6A 00 90 EF 01 0A 70 E3 00 30 A0 E1 00 20 60 82 09 00 00 8A 00 00 50 E3 0C 00 00 1A 06 00 A0 E1 02 17 A0 E3 03 20 A0 E1 05 00 90 EF 01 0A 70 E3 00 C0 A0 E1 03 00 00 9A 00 20 60 E2 D4 31 9F E5 00 20 83 E5 01 00 00 EA 00 00 50 E3 04 00 00 AA 00 20 E0 E3 B4 31 9F E5 02 00 A0 E1 00 20 83 E5 68 00 00 EA 18 10 9D E5 AC 71 9F E5 03 00 A0 E1 01 20 A0 E3 00 10 87 E5 02 30 A0 E1 0C 40 A0 E1 00 50 A0 E1 C0 00 90 EF 01 0A 70 E3 84 31 9F 85 00 20 60 82 00 00 E0 83 00 00 8E E5 }
	condition:
		$pattern
}

rule __GI_fputws_4d4fcca9f185327cd7eba12530eff5d8 {
	meta:
		aliases = "fputwc, putwc, __GI_fputs, fputs, fputws, __GI_fputws"
		size = "140"
		objfiles = "fputws@libc.a, fputwc@libc.a, fputs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 60 91 E5 00 00 56 E3 10 D0 4D E2 01 50 A0 E1 00 70 A0 E1 0A 00 00 1A 38 40 81 E2 0D 00 A0 E1 50 30 9F E5 50 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 40 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 07 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 00 56 E3 00 40 A0 E1 0D 00 A0 01 01 10 A0 03 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 04 00 A0 E1 10 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fsetpos_bdd3eb167fff940ad255c02d03f0aaa5 {
	meta:
		aliases = "fsetpos"
		size = "172"
		objfiles = "fsetpos@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 70 90 E5 00 00 57 E3 10 D0 4D E2 00 50 A0 E1 01 60 A0 E1 0A 00 00 1A 38 40 80 E2 74 30 9F E5 0D 00 A0 E1 70 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 60 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 00 10 96 E5 00 20 A0 E3 ?? ?? ?? EB 00 40 50 E2 05 00 00 1A 04 20 96 E5 08 10 86 E2 0A 00 91 E8 2C 20 85 E5 02 30 C5 E5 30 10 85 E5 00 00 57 E3 0D 00 A0 01 01 10 A0 03 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 04 00 A0 E1 10 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fsetpos64_92f84d04b3096e31616272086ad47793 {
	meta:
		aliases = "fsetpos64"
		size = "172"
		objfiles = "fsetpos64@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 70 90 E5 00 00 57 E3 10 D0 4D E2 00 50 A0 E1 01 60 A0 E1 0A 00 00 1A 38 40 80 E2 74 30 9F E5 0D 00 A0 E1 70 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 60 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 06 00 96 E8 00 30 A0 E3 ?? ?? ?? EB 00 40 50 E2 05 00 00 1A 08 20 96 E5 0C 10 86 E2 0A 00 91 E8 2C 20 85 E5 02 30 C5 E5 30 10 85 E5 00 00 57 E3 0D 00 A0 01 01 10 A0 03 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 04 00 A0 E1 10 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fgetpos_b56d25281ce7ca0767bd4bdc742d4a48 {
	meta:
		aliases = "fgetpos"
		size = "172"
		objfiles = "fgetpos@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 70 90 E5 00 00 57 E3 10 D0 4D E2 00 50 A0 E1 01 60 A0 E1 0A 00 00 1A 38 40 80 E2 74 30 9F E5 0D 00 A0 E1 70 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 60 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 ?? ?? ?? EB 00 00 86 E5 00 00 50 E3 2C 30 95 A5 30 20 95 A5 04 30 86 A5 08 20 86 A5 02 30 D5 A5 00 40 E0 B3 0C 30 86 A5 00 40 A0 A3 00 00 57 E3 0D 00 A0 01 01 10 A0 03 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 04 00 A0 E1 10 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fgetpos64_0a38eb59be283b0ab89193550b66e4e6 {
	meta:
		aliases = "fgetpos64"
		size = "172"
		objfiles = "fgetpos64@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 70 90 E5 00 00 57 E3 10 D0 4D E2 00 50 A0 E1 01 60 A0 E1 0A 00 00 1A 38 40 80 E2 74 30 9F E5 0D 00 A0 E1 70 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 60 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 ?? ?? ?? EB 03 00 86 E8 00 00 51 E3 2C 30 95 A5 30 20 95 A5 08 30 86 A5 0C 20 86 A5 02 30 D5 A5 00 40 E0 B3 10 30 86 A5 00 40 A0 A3 00 00 57 E3 0D 00 A0 01 01 10 A0 03 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 04 00 A0 E1 10 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fwide_5d8564e4224f8eb57a6bcdeae0dc5eee {
	meta:
		aliases = "fwide"
		size = "200"
		objfiles = "fwide@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 70 90 E5 00 00 57 E3 10 D0 4D E2 00 50 A0 E1 01 60 A0 E1 0A 00 00 1A 38 40 80 E2 90 30 9F E5 0D 00 A0 E1 8C 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 7C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 56 E3 0B 00 00 0A 00 20 D5 E5 01 30 D5 E5 03 14 82 E1 22 0D 11 E3 06 00 00 1A 00 00 56 E3 80 30 A0 D3 02 3B A0 C3 01 30 83 E1 43 24 A0 E1 01 20 C5 E5 00 30 C5 E5 01 20 D5 E5 00 30 D5 E5 00 00 57 E3 02 44 83 E1 0D 00 A0 01 01 10 A0 03 24 30 9F 05 0F E0 A0 01 03 F0 A0 01 80 30 04 E2 02 0B 04 E2 00 00 63 E0 10 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ungetc_95ace9b2c4c1f9e869cd4da120a3ec01 {
	meta:
		aliases = "__GI_ungetc, ungetc"
		size = "372"
		objfiles = "ungetc@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 70 91 E5 00 00 57 E3 10 D0 4D E2 01 50 A0 E1 00 60 A0 E1 0A 00 00 1A 38 40 81 E2 0D 00 A0 E1 38 31 9F E5 38 11 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 28 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 10 10 95 E5 18 30 95 E5 01 00 76 E3 03 00 51 11 0E 00 00 2A 08 30 95 E5 03 00 51 E1 0B 00 00 9A 01 20 51 E5 FF 30 06 E2 03 00 52 E1 07 00 00 1A 00 30 95 E5 04 30 C3 E3 01 10 41 E2 43 24 A0 E1 01 20 C5 E5 10 10 85 E5 00 30 C5 E5 29 00 00 EA 00 30 D5 E5 83 30 03 E2 80 00 53 E3 04 00 00 8A 05 00 A0 E1 80 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 1F 00 00 1A 00 20 D5 E5 01 30 D5 E5 03 34 82 E1 }
	condition:
		$pattern
}

rule ungetwc_6a6005d57ecd46c5a3e6226c2cc902bb {
	meta:
		aliases = "__GI_ungetwc, ungetwc"
		size = "300"
		objfiles = "ungetwc@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 70 91 E5 00 00 57 E3 10 D0 4D E2 01 50 A0 E1 00 60 A0 E1 0A 00 00 1A 38 40 81 E2 0D 00 A0 E1 EC 30 9F E5 EC 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 DC 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 D5 E5 01 10 D5 E5 CC 20 9F E5 01 34 83 E1 02 20 03 E0 02 0B 52 E3 04 00 00 8A 05 00 A0 E1 02 1B A0 E3 ?? ?? ?? EB 00 00 50 E3 1D 00 00 1A 00 20 D5 E5 01 30 D5 E5 03 34 82 E1 02 00 13 E3 04 00 00 0A 01 00 13 E3 16 00 00 1A 28 30 95 E5 00 00 53 E3 13 00 00 1A 01 00 76 E3 11 00 00 0A 00 30 95 E5 01 30 83 E2 03 38 A0 E1 23 38 A0 E1 43 24 A0 E1 01 10 03 E2 01 20 C5 E5 01 11 85 E0 }
	condition:
		$pattern
}

rule __GI_pmap_unset_35bc4b84a9ad146a998226734f93442b {
	meta:
		aliases = "pmap_unset, __GI_pmap_unset"
		size = "232"
		objfiles = "pmap_clnt@libc.a"
	strings:
		$pattern = { F0 40 2D E9 38 D0 4D E2 20 50 8D E2 00 30 E0 E3 00 70 A0 E1 05 00 A0 E1 34 30 8D E5 01 60 A0 E1 9B FF FF EB 00 00 50 E3 26 00 00 0A A0 30 9F E5 04 40 93 E5 19 EE A0 E3 34 C0 8D E2 00 30 93 E5 05 00 A0 E1 8C 10 9F E5 02 20 A0 E3 10 10 8D E8 0C E0 8D E5 08 E0 8D E5 ?? ?? ?? EB 00 40 50 E2 18 00 00 0A 00 30 A0 E3 1C 30 8D E5 18 30 8D E5 64 30 9F E5 10 70 8D E5 06 00 93 E8 14 60 8D E5 58 30 9F E5 04 C0 94 E5 00 30 8D E5 30 30 8D E2 08 10 8D E5 0C 20 8D E5 04 30 8D E5 02 10 A0 E3 3C 20 9F E5 10 30 8D E2 0F E0 A0 E1 00 F0 9C E5 04 00 A0 E1 04 30 94 E5 0F E0 A0 E1 10 F0 93 E5 30 00 9D E5 00 00 00 EA }
	condition:
		$pattern
}

rule __pthread_reset_main_thread_629c86841c6790559bfe9e710497fb82 {
	meta:
		aliases = "__pthread_reset_main_thread"
		size = "160"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 42 FF FF EB 74 70 9F E5 00 30 97 E5 01 00 73 E3 00 60 A0 E1 0E 00 00 0A 64 40 9F E5 00 00 94 E5 ?? ?? ?? EB 5C 30 9F E5 00 20 A0 E3 58 50 9F E5 00 20 83 E5 00 00 97 E5 00 20 84 E5 ?? ?? ?? EB 00 00 95 E5 ?? ?? ?? EB 00 30 E0 E3 00 30 87 E5 00 30 85 E5 ?? ?? ?? EB 30 30 9F E5 4C 30 86 E5 2C 30 9F E5 00 60 83 E5 28 30 9F E5 14 00 86 E5 44 30 86 E5 00 60 86 E5 04 60 86 E5 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __cxa_finalize_8b1dcf9ee061bce985d05b3b8066dd4f {
	meta:
		aliases = "__cxa_finalize"
		size = "108"
		objfiles = "__cxa_finalize@libc.a"
	strings:
		$pattern = { F0 40 2D E9 58 30 9F E5 58 70 9F E5 00 40 93 E5 00 50 A0 E1 00 60 A0 E3 0C 00 00 EA 00 10 97 E5 00 00 55 E3 01 20 80 E0 02 00 00 0A 0C 30 92 E5 03 00 55 E1 05 00 00 1A 01 30 90 E7 03 00 53 E3 01 60 80 07 08 00 92 05 0F E0 A0 01 04 F0 92 05 00 00 54 E3 01 40 44 E2 04 02 A0 E1 EE FF FF 1A F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule setlogmask_1aee9619ab84be12a81d280aa37131ac {
	meta:
		aliases = "setlogmask"
		size = "128"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { F0 40 2D E9 5C 70 9F E5 00 50 50 E2 10 D0 4D E2 00 60 97 E5 10 00 00 0A 4C 10 9F E5 0D 00 A0 E1 48 20 9F E5 48 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 40 30 9F E5 34 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 0D 00 A0 E1 01 10 A0 E3 00 50 87 E5 28 30 9F E5 0D 40 A0 E1 0F E0 A0 E1 03 F0 A0 E1 06 00 A0 E1 10 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _time_mktime_c28fa311bd1e16d6644df23b1b4ab098 {
	meta:
		aliases = "_time_mktime"
		size = "144"
		objfiles = "_time_mktime@libc.a"
	strings:
		$pattern = { F0 40 2D E9 6C 40 9F E5 10 D0 4D E2 04 20 A0 E1 00 50 A0 E1 01 60 A0 E1 0D 00 A0 E1 58 10 9F E5 58 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 50 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 ?? ?? ?? EB 06 10 A0 E1 3C 20 9F E5 05 00 A0 E1 ?? ?? ?? EB 01 10 A0 E3 00 40 A0 E1 2C 30 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 0D 70 A0 E1 04 00 A0 E1 10 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule strerror_r_dec5e9c33145504e227fc8f6f8fc0710 {
	meta:
		aliases = "__xpg_strerror_r, __GI___xpg_strerror_r, strerror_r"
		size = "232"
		objfiles = "__xpg_strerror_r@libc.a"
	strings:
		$pattern = { F0 40 2D E9 7C 00 50 E3 00 C0 A0 E1 38 D0 4D E2 01 70 A0 E1 02 40 A0 E1 C0 50 9F 95 00 00 A0 91 03 00 00 9A 08 00 00 EA 00 00 53 E3 01 00 40 02 01 50 85 E2 00 00 50 E3 00 30 D5 E5 F9 FF FF 1A 00 00 53 E3 00 60 A0 11 0C 00 00 1A 0C 10 A0 E1 C1 2F A0 E1 09 30 E0 E3 00 C0 A0 E3 37 00 8D E2 00 C0 8D E5 ?? ?? ?? EB 0E 50 40 E2 05 00 A0 E1 6C 10 9F E5 0E 20 A0 E3 ?? ?? ?? EB 16 60 A0 E3 05 00 A0 E1 ?? ?? ?? EB 00 00 57 E3 00 40 A0 03 01 20 80 E2 04 00 52 E1 02 40 A0 91 22 60 A0 83 00 00 54 E3 06 00 00 0A 04 20 A0 E1 05 10 A0 E1 07 00 A0 E1 ?? ?? ?? EB 07 20 84 E0 00 30 A0 E3 01 30 42 E5 00 00 56 E3 }
	condition:
		$pattern
}

rule pthread_key_create_c683b6533fc6bf6e586086c067f229b1 {
	meta:
		aliases = "pthread_key_create"
		size = "156"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 7C 30 9F E5 00 70 A0 E1 78 00 9F E5 01 60 A0 E1 0F E0 A0 E1 03 F0 A0 E1 6C 30 9F E5 6C 20 9F E5 00 40 A0 E3 0E 00 00 EA 84 51 92 E7 00 00 55 E3 0A 00 00 1A 84 31 82 E0 04 60 83 E5 01 30 A0 E3 84 31 82 E7 3C 00 9F E5 44 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 00 40 87 E5 F0 80 BD E8 01 40 84 E2 03 00 54 E1 EE FF FF DA 20 30 9F E5 10 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 0B 00 A0 E3 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? FF 03 00 00 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule localtime_r_d365aeeb663f7bab53e9e98b3d2ece11 {
	meta:
		aliases = "__GI_localtime_r, localtime_r"
		size = "164"
		objfiles = "localtime_r@libc.a"
	strings:
		$pattern = { F0 40 2D E9 7C 40 9F E5 10 D0 4D E2 04 20 A0 E1 00 50 A0 E1 01 70 A0 E1 0D 00 A0 E1 68 10 9F E5 68 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 5C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 95 E5 50 00 9F E5 00 00 53 E1 00 00 A0 C3 01 00 A0 D3 ?? ?? ?? EB 07 10 A0 E1 3C 20 9F E5 05 00 A0 E1 ?? ?? ?? EB 0D 00 A0 E1 01 10 A0 E3 2C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 0D 60 A0 E1 07 00 A0 E1 10 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF 4E 98 45 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule strncasecmp_d1a051945027a14319f4f3b11a5d8717 {
	meta:
		aliases = "__GI_strncasecmp, strncasecmp"
		size = "140"
		objfiles = "strncasecmp@libc.a"
	strings:
		$pattern = { F0 40 2D E9 7C 70 9F E5 00 40 A0 E1 01 50 A0 E1 02 60 A0 E1 00 00 A0 E3 00 00 56 E3 01 60 46 E2 F0 80 BD 08 05 00 54 E1 10 00 00 0A 00 E0 D4 E5 00 30 D5 E5 00 C0 97 E5 83 30 A0 E1 8E E0 A0 E1 0C 20 8E E0 0C 00 83 E0 01 10 D2 E5 01 00 D0 E5 0C 20 D3 E7 0C 30 DE E7 00 0C A0 E1 01 1C A0 E1 41 38 83 E1 40 28 82 E1 02 00 53 E0 F0 80 BD 18 00 30 D4 E5 00 00 53 E3 01 50 85 E2 01 40 84 E2 E4 FF FF 1A F0 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_initialize_29b2214610a2f878cf000e9a36204cf9 {
	meta:
		aliases = "pthread_initialize"
		size = "448"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 80 21 9F E5 00 40 92 E5 00 00 54 E3 24 D0 4D E2 5A 00 00 1A 01 35 4D E2 A3 3A A0 E1 83 3A A0 E1 00 30 82 E5 ?? ?? ?? EB 5C 31 9F E5 5C 21 9F E5 00 50 93 E5 58 31 9F E5 4C 30 82 E5 54 31 9F E5 44 30 82 E5 50 31 9F E5 04 10 A0 E1 14 00 82 E5 00 40 83 E5 03 00 00 EA 34 30 95 E5 01 00 53 E3 34 10 85 15 20 50 95 E5 00 00 55 E3 F9 FF FF 1A 14 40 8D E2 04 10 A0 E1 03 00 A0 E3 ?? ?? ?? EB ?? ?? ?? EB 80 00 A0 E1 14 30 9D E5 02 26 60 E2 02 00 53 E1 04 10 A0 81 03 00 A0 83 14 20 8D 85 ?? ?? ?? 8B 05 10 A0 E1 14 20 A0 E3 0D 00 A0 E1 ?? ?? ?? EB E4 60 9F E5 E4 30 9F E5 05 20 A0 E1 0D 10 A0 E1 }
	condition:
		$pattern
}

rule universal_16270a214a7128167e929f54ec2bcfa9 {
	meta:
		aliases = "universal"
		size = "412"
		objfiles = "svc_simple@libc.a"
	strings:
		$pattern = { F0 40 2D E9 89 DD 4D E2 08 60 90 E5 24 D0 4D E2 00 30 A0 E3 02 2A 8D E2 00 00 56 E3 60 32 82 E5 01 50 A0 E1 0A 00 00 1A 01 00 A0 E1 06 20 A0 E1 4C 11 9F E5 ?? ?? ?? EB 00 00 50 E3 4D 00 00 1A 40 11 9F E5 04 20 A0 E3 02 00 80 E2 ?? ?? ?? EB 2E 00 00 EA 00 70 90 E5 ?? ?? ?? EB C0 40 90 E5 34 00 00 EA 04 30 94 E5 07 00 53 E1 30 00 00 1A 08 30 94 E5 06 00 53 E1 2D 00 00 1A 00 10 A0 E3 04 21 9F E5 0D 00 A0 E1 ?? ?? ?? EB 08 30 95 E5 05 00 A0 E1 0C 10 94 E5 0D 20 A0 E1 0F E0 A0 E1 08 F0 93 E5 24 60 8D E2 00 00 50 E3 24 60 46 E2 02 00 00 1A 05 00 A0 E1 ?? ?? ?? EB 2D 00 00 EA 0D 00 A0 E1 0F E0 A0 E1 }
	condition:
		$pattern
}

rule __pthread_timedsuspend_new_7c41852b3fd7951eac4511f89eb2d333 {
	meta:
		aliases = "__pthread_timedsuspend_new"
		size = "272"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 8C D0 4D E2 04 00 8D E5 00 10 8D E5 08 00 8D E2 01 10 A0 E3 ?? ?? ?? EB 00 20 50 E2 01 00 A0 13 32 00 00 1A 04 10 9D E5 08 30 8D E2 24 30 81 E5 CC 30 9F E5 00 10 93 E5 04 30 9D E5 84 40 8D E2 20 20 83 E5 04 00 A0 E1 88 20 8D E5 84 20 8D E5 ?? ?? ?? EB 04 10 A0 E1 01 00 A0 E3 7C 20 8D E2 ?? ?? ?? EB 9C 70 9F E5 74 60 8D E2 FA 5F A0 E3 6C 40 8D E2 00 10 A0 E3 06 00 A0 E1 ?? ?? ?? EB 78 30 9D E5 93 05 02 E0 00 C0 9D E5 04 30 9C E5 00 C0 9C E5 03 20 62 E0 74 30 9D E5 00 10 A0 E3 01 00 52 E1 0C 30 63 E0 6C 30 8D E5 01 30 43 B2 6C 30 8D B5 6C 30 9D E5 70 20 8D E5 07 20 82 B0 70 20 8D B5 }
	condition:
		$pattern
}

rule __muldi3_3e946762cf432c31595665c777908eb0 {
	meta:
		aliases = "__muldi3"
		size = "72"
		objfiles = "_muldi3@libgcc.a"
	strings:
		$pattern = { F0 40 2D E9 92 01 0E E0 90 E3 25 E0 20 78 A0 E1 22 48 A0 E1 07 68 C0 E1 04 E8 C2 E1 96 0E 02 E0 97 0E 0E E0 94 06 06 E0 97 04 04 E0 06 60 9E E0 01 48 84 22 06 28 92 E0 26 48 A4 E0 02 00 A0 E1 04 10 85 E0 F0 80 BD E8 }
	condition:
		$pattern
}

rule tcgetsid_0a1a7fbd643098b1ba952870d1d462ce {
	meta:
		aliases = "tcgetsid"
		size = "168"
		objfiles = "tcgetsid@libc.a"
	strings:
		$pattern = { F0 40 2D E9 94 70 9F E5 00 30 97 E5 00 00 53 E3 04 D0 4D E2 00 60 A0 E1 0E 00 00 1A ?? ?? ?? EB 7C 10 9F E5 00 40 A0 E1 0D 20 A0 E1 06 00 A0 E1 00 50 94 E5 ?? ?? ?? EB 00 00 50 E3 12 00 00 AA 00 30 94 E5 16 00 53 E3 11 00 00 1A 01 30 A0 E3 00 30 87 E5 00 50 84 E5 06 00 A0 E1 ?? ?? ?? EB 01 00 70 E3 0A 00 00 0A ?? ?? ?? EB 01 00 70 E3 00 00 8D E5 04 00 00 1A ?? ?? ?? EB 00 30 90 E5 03 00 53 E3 16 30 83 02 00 30 80 05 00 00 9D E5 00 00 00 EA 00 00 E0 E3 04 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? 29 54 00 00 }
	condition:
		$pattern
}

rule _dl_linux_resolver_a0ab01712e28d8a489cb6946721f95f4 {
	meta:
		aliases = "_dl_linux_resolver"
		size = "152"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { F0 40 2D E9 9C 40 90 E5 81 E1 A0 E1 04 30 8E E0 04 30 93 E5 58 20 90 E5 23 34 A0 E1 03 22 92 E7 54 30 90 E5 00 C0 A0 E1 02 50 83 E0 1C 10 9C E5 00 20 A0 E1 01 30 A0 E3 05 00 A0 E1 04 70 9E E7 00 60 9C E5 ?? ?? ?? EB 00 40 50 E2 0B 00 00 1A 34 20 9F E5 05 30 A0 E1 00 20 92 E5 02 00 80 E2 28 10 9F E5 ?? ?? ?? EB 01 00 A0 E3 01 00 90 EF 01 0A 70 E3 18 30 9F 85 00 20 60 82 00 20 83 85 04 00 A0 E1 07 40 86 E7 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule res_sync_func_da2d68e88a48e83cec748067d5af441e {
	meta:
		aliases = "res_sync_func"
		size = "160"
		objfiles = "res_init@libc.a"
	strings:
		$pattern = { F0 40 2D E9 ?? ?? ?? EB 00 50 A0 E1 78 00 9F E5 78 30 9F E5 00 20 90 E5 03 00 52 E1 13 00 00 0A 6C 10 9F E5 60 20 D5 E5 00 30 91 E5 02 00 53 E1 00 20 81 85 00 40 91 E5 00 70 A0 E1 1C 60 A0 E3 07 00 00 EA 00 30 97 E5 94 36 2E E0 54 30 92 E5 03 C0 A0 E1 0F 00 BC E8 0F 00 AE E8 07 00 9C E8 07 00 8E E8 01 40 54 E2 04 21 85 E0 F4 FF FF 5A 52 20 D5 E5 1C 30 9F E5 00 20 C3 E5 18 30 9F E5 53 20 D5 E5 00 20 C3 E5 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __fixunssfdi_a563a03f241f249a4be833e235094e31 {
	meta:
		aliases = "__fixunssfdi"
		size = "104"
		objfiles = "_fixunssfdi@libgcc.a"
	strings:
		$pattern = { F0 40 2D E9 ?? ?? ?? EB F7 25 A0 E3 03 26 82 E2 00 30 A0 E3 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 00 60 A0 E1 ?? ?? ?? EB C1 24 A0 E3 0F 26 82 E2 00 30 A0 E3 ?? ?? ?? EB 04 20 A0 E1 05 30 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 00 70 A0 E3 06 70 A0 E1 00 10 A0 E3 00 60 A0 E3 06 00 80 E1 07 10 81 E1 F0 80 BD E8 }
	condition:
		$pattern
}

rule pthread_cleanup_upto_ee9201b4bb52539520c3f55a4bcb2c4b {
	meta:
		aliases = "pthread_cleanup_upto"
		size = "228"
		objfiles = "ptlongjmp@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 C0 30 9F E5 00 30 93 E5 03 00 5D E1 0D 60 A0 E1 00 70 A0 E1 B0 50 9F 25 13 00 00 2A AC 30 9F E5 00 30 93 E5 03 00 5D E1 04 00 00 3A A0 30 9F E5 00 30 93 E5 03 00 5D E1 98 50 9F 35 0A 00 00 3A 94 30 9F E5 00 30 93 E5 00 00 53 E3 02 00 00 0A ?? ?? ?? EB 00 50 A0 E1 03 00 00 EA A6 3A E0 E1 83 3A E0 E1 57 5F 43 E2 03 50 45 E2 3C 40 95 E5 06 00 00 EA 06 00 54 E1 00 40 A0 93 08 00 00 9A 04 00 94 E5 0F E0 A0 E1 00 F0 94 E5 0C 40 94 E5 00 00 54 E3 02 00 00 0A 20 30 97 E5 03 00 54 E1 F3 FF FF 3A 54 20 95 E5 00 00 52 E3 3C 40 85 E5 F0 80 BD 08 20 30 97 E5 03 00 52 E1 00 30 A0 33 54 30 85 35 }
	condition:
		$pattern
}

rule vdprintf_0a726833e0b62f0d42a2e96595b1e4b7 {
	meta:
		aliases = "__GI_vdprintf, vdprintf"
		size = "152"
		objfiles = "vdprintf@libc.a"
	strings:
		$pattern = { F0 40 2D E9 D0 30 A0 E3 90 D0 4D E2 00 30 CD E5 01 30 A0 E3 00 40 A0 E3 04 00 8D E5 01 50 A0 E1 02 60 A0 E1 38 00 8D E2 50 20 8D E2 34 30 8D E5 90 30 8D E2 14 20 8D E5 0C 30 8D E5 08 20 8D E5 18 20 8D E5 1C 20 8D E5 10 20 8D E5 01 40 CD E5 02 40 CD E5 2C 40 8D E5 ?? ?? ?? EB 05 10 A0 E1 06 20 A0 E1 0D 00 A0 E1 20 40 8D E5 ?? ?? ?? EB 00 40 50 E2 0D 70 A0 E1 03 00 00 DA 0D 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 40 E0 13 04 00 A0 E1 90 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule pthread_detach_04efa5f4c150b2b7543e40285656e266 {
	meta:
		aliases = "pthread_detach"
		size = "260"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 F0 20 9F E5 00 3B A0 E1 23 3B A0 E1 03 52 82 E0 1C D0 4D E2 00 40 A0 E1 00 10 A0 E3 05 00 A0 E1 ?? ?? ?? EB 08 20 95 E5 00 00 52 E3 02 00 00 0A 10 60 92 E5 04 00 56 E1 03 00 00 0A 05 00 A0 E1 ?? ?? ?? EB 03 00 A0 E3 28 00 00 EA 2D 40 D2 E5 00 00 54 E3 03 00 00 0A 05 00 A0 E1 ?? ?? ?? EB 16 00 A0 E3 21 00 00 EA 38 30 92 E5 00 00 53 E3 03 00 00 0A 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 1A 00 00 EA 2C 40 D2 E5 01 70 A0 E3 2D 70 C2 E5 05 00 A0 E1 ?? ?? ?? EB 00 00 54 E3 12 00 00 0A 54 40 9F E5 00 30 94 E5 00 00 53 E3 0E 00 00 BA DC FE FF EB 81 00 8D E8 08 60 8D E5 04 50 A0 E1 0D 40 A0 E1 }
	condition:
		$pattern
}

rule getttyent_86b717d6db2a840367e09c93fdb7e016 {
	meta:
		aliases = "__GI_getttyent, getttyent"
		size = "820"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { F0 40 2D E9 F4 32 9F E5 00 30 93 E5 00 00 53 E3 10 D0 4D E2 03 00 00 1A ?? ?? ?? EB 00 00 50 E3 00 40 A0 01 B2 00 00 0A D4 42 9F E5 00 30 94 E5 00 00 53 E3 04 00 00 1A 01 0A A0 E3 ?? ?? ?? EB 00 00 50 E3 00 00 84 E5 ?? ?? ?? 0B AC 42 9F E5 00 20 94 E5 0D 00 A0 E1 38 20 82 E2 A4 12 9F E5 A4 32 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 94 E5 98 32 9F E5 38 00 80 E2 0F E0 A0 E1 03 F0 A0 E1 7C 72 9F E5 88 62 9F E5 04 50 A0 E1 00 40 97 E5 01 1A A0 E3 04 00 A0 E1 00 20 95 E5 ?? ?? ?? EB 00 00 50 E3 00 40 A0 01 8C 00 00 0A 04 00 A0 E1 0A 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 0E 00 00 1A 00 00 95 E5 10 20 90 E5 }
	condition:
		$pattern
}

rule getmntent_r_88fb9f4ac3d192262a816c1a595cdb26 {
	meta:
		aliases = "__GI_getmntent_r, getmntent_r"
		size = "316"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 00 51 E3 00 00 50 13 04 D0 4D E2 00 70 A0 E1 01 50 A0 E1 02 40 A0 E1 03 80 A0 E1 3F 00 00 0A 00 00 52 E3 3D 00 00 0A 05 00 00 EA 00 30 D4 E5 0A 00 53 E3 23 00 53 13 00 60 A0 13 01 60 A0 03 06 00 00 1A 04 00 A0 E1 08 10 A0 E1 07 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 F3 FF FF 1A 2F 00 00 EA 04 70 8D E2 04 60 27 E5 04 00 A0 E1 BC 10 9F E5 0D 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 85 E5 26 00 00 0A 06 00 A0 E1 A0 10 9F E5 0D 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 04 00 85 E5 1F 00 00 0A 06 00 A0 E1 84 10 9F E5 0D 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 08 00 85 E5 18 00 00 0A 6C 10 9F E5 0D 20 A0 E1 }
	condition:
		$pattern
}

rule putgrent_572ab069eddb370f925cfe1d3ac757a3 {
	meta:
		aliases = "putgrent"
		size = "280"
		objfiles = "putgrent@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 00 51 E3 00 00 50 13 14 D0 4D E2 00 50 A0 E1 01 60 A0 E1 04 00 00 1A ?? ?? ?? EB 00 40 E0 E3 16 30 A0 E3 00 30 80 E5 2F 00 00 EA 34 80 91 E5 00 00 58 E3 0A 00 00 1A 38 40 81 E2 04 00 8D E2 B0 30 9F E5 B0 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 A0 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 08 30 95 E5 00 30 8D E5 06 00 A0 E1 8C 10 9F E5 0C 00 95 E8 ?? ?? ?? EB 00 00 50 E3 12 00 00 BA 0C 50 95 E5 78 10 9F E5 78 70 9F E5 00 40 95 E5 00 00 54 E3 06 00 A0 E1 04 20 A0 E1 04 50 85 E2 05 00 00 1A 06 10 A0 E1 0A 00 A0 E3 ?? ?? ?? EB 00 00 50 E3 04 00 00 BA 04 00 00 EA ?? ?? ?? EB }
	condition:
		$pattern
}

rule __GI_rtime_c4f9087c69c958bdf13adf8f99e6fc21 {
	meta:
		aliases = "rtime, __GI_rtime"
		size = "460"
		objfiles = "rtime@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 00 52 E3 01 60 A0 03 02 60 A0 13 28 D0 4D E2 02 70 A0 E1 00 40 A0 E1 01 80 A0 E1 02 00 A0 E3 06 10 A0 E1 00 20 A0 E3 ?? ?? ?? EB 00 50 50 E2 5F 00 00 BA 02 30 A0 E3 02 00 56 E3 00 30 C4 E5 00 60 A0 E3 23 30 83 E2 03 30 C4 E5 01 60 C4 E5 02 60 C4 E5 2F 00 00 1A 10 C0 A0 E3 24 10 8D E2 04 20 A0 E3 06 30 A0 E1 10 10 8D E8 ?? ?? ?? EB 06 00 50 E1 2C 00 00 BA 04 00 97 E5 FA 1F A0 E3 ?? ?? ?? EB 00 30 97 E5 FA 2F A0 E3 93 02 27 E0 01 30 A0 E3 1C 30 CD E5 18 50 8D E5 1D 60 CD E5 18 60 8D E2 01 10 A0 E3 07 20 A0 E1 06 00 A0 E1 ?? ?? ?? EB 00 40 50 E2 03 00 00 AA ?? ?? ?? EB 00 30 90 E5 }
	condition:
		$pattern
}

rule vwarn_work_f6b1467ef7b4a09f4614c139324201cf {
	meta:
		aliases = "vwarn_work"
		size = "248"
		objfiles = "err@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 00 52 E3 50 D0 4D E2 00 70 A0 E1 01 80 A0 E1 B8 50 9F 05 05 00 00 0A ?? ?? ?? EB 0D 10 A0 E1 00 00 90 E5 40 20 A0 E3 ?? ?? ?? EB A0 50 9F E5 A0 40 9F E5 00 20 94 E5 34 60 92 E5 00 00 56 E3 0A 00 00 1A 40 00 8D E2 8C 30 9F E5 38 20 82 E2 88 10 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 94 E5 7C 30 9F E5 38 00 80 E2 0F E0 A0 E1 03 F0 A0 E1 70 30 9F E5 00 00 94 E5 00 20 93 E5 68 10 9F E5 ?? ?? ?? EB 00 00 57 E3 04 00 00 0A 07 10 A0 E1 08 20 A0 E1 00 00 94 E5 ?? ?? ?? EB 02 50 45 E2 00 00 94 E5 05 10 A0 E1 0D 20 A0 E1 ?? ?? ?? EB 00 00 56 E3 40 00 8D 02 01 10 A0 03 2C 30 9F 05 0F E0 A0 01 }
	condition:
		$pattern
}

rule __GI_xdr_pmaplist_8bb6801dd4a503893b5e620c97211b9d {
	meta:
		aliases = "xdr_pmaplist, __GI_xdr_pmaplist"
		size = "168"
		objfiles = "pmap_prot2@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 30 90 E5 04 D0 4D E2 00 50 A0 E1 02 00 53 E3 00 60 A0 13 01 60 A0 03 01 40 A0 E1 00 70 A0 E3 0D 80 A0 E1 00 30 94 E5 0D 10 A0 E1 00 30 53 E2 01 30 A0 13 05 00 A0 E1 00 30 8D E5 ?? ?? ?? EB 00 00 50 E3 04 10 A0 E1 14 20 A0 E3 4C 30 9F E5 05 00 A0 E1 0E 00 00 0A 00 C0 9D E5 00 00 5C E3 01 00 A0 03 0B 00 00 0A 00 00 56 E3 00 C0 94 15 10 70 8C 12 ?? ?? ?? EB 00 00 50 E3 04 00 00 0A 00 00 56 E3 00 30 94 05 07 40 A0 11 10 40 83 02 E3 FF FF EA 00 00 A0 E3 04 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule byte_group_match_null_string_p_1b3b11979bef14135116f3a72da07f30 {
	meta:
		aliases = "byte_group_match_null_string_p"
		size = "336"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 30 90 E5 04 D0 4D E2 02 30 83 E2 04 60 8D E2 04 30 26 E5 00 80 A0 E1 01 70 A0 E1 02 50 A0 E1 43 00 00 EA 00 30 D1 E5 07 00 53 E3 36 00 00 0A 0F 00 53 E3 38 00 00 1A 01 30 81 E2 00 30 8D E5 01 30 D3 E5 01 20 D1 E5 03 3C A0 E1 43 48 92 E0 03 30 81 E2 00 30 8D E5 15 00 00 5A 34 00 00 EA C5 FF FF EB 00 00 50 E3 34 00 00 0A 00 30 9D E5 03 10 84 E0 00 10 8D E5 03 30 D4 E7 0F 00 53 E3 01 20 81 E2 03 00 81 E2 11 00 00 1A 00 20 8D E5 01 30 D2 E5 01 20 D1 E5 03 3C A0 E1 00 00 8D E5 43 48 82 E0 04 30 D1 E7 0E 00 53 E3 00 10 8D 15 07 00 00 1A 00 30 9D E5 03 00 A0 E1 04 30 83 E0 03 10 43 E2 }
	condition:
		$pattern
}

rule pthread_setschedparam_706249afa1043cc2ab117de980016e73 {
	meta:
		aliases = "__GI_pthread_setschedparam, pthread_setschedparam"
		size = "192"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { F0 41 2D E9 00 3B A0 E1 00 70 A0 E1 A4 00 9F E5 23 3B A0 E1 03 52 80 E0 01 60 A0 E1 05 00 A0 E1 00 10 A0 E3 02 80 A0 E1 ?? ?? ?? EB 08 40 95 E5 00 00 54 E3 02 00 00 0A 10 30 94 E5 07 00 53 E1 15 00 00 0A 05 00 A0 E1 ?? ?? ?? EB 03 00 A0 E3 F0 81 BD E8 05 00 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 00 00 90 E5 F0 81 BD E8 00 00 56 E3 00 10 98 15 06 10 A0 01 18 10 84 E5 05 00 A0 E1 ?? ?? ?? EB 34 30 9F E5 00 30 93 E5 00 00 53 E3 18 00 94 A5 ?? ?? ?? AB 00 00 A0 E3 F0 81 BD E8 14 00 94 E5 06 10 A0 E1 08 20 A0 E1 ?? ?? ?? EB 01 00 70 E3 EC FF FF 1A E6 FF FF EA ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_xdr_reference_f8e7396350acc32136b7c1712d24ec7a {
	meta:
		aliases = "xdr_reference, __GI_xdr_reference"
		size = "188"
		objfiles = "xdr_reference@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 40 91 E5 00 00 54 E3 01 70 A0 E1 00 50 A0 E1 02 60 A0 E1 03 80 A0 E1 15 00 00 1A 00 30 90 E5 01 00 53 E3 03 00 00 0A 02 00 53 E3 01 60 A0 03 1C 00 00 0A 0E 00 00 EA 02 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 40 A0 E1 00 00 87 E5 05 00 00 1A 58 30 9F E5 58 00 9F E5 00 10 93 E5 ?? ?? ?? EB 04 60 A0 E1 0F 00 00 EA 06 20 A0 E1 00 10 A0 E3 ?? ?? ?? EB 05 00 A0 E1 04 10 A0 E1 00 20 E0 E3 0F E0 A0 E1 08 F0 A0 E1 00 30 95 E5 02 00 53 E3 00 60 A0 E1 03 00 00 1A 04 00 A0 E1 ?? ?? ?? EB 00 30 A0 E3 00 30 87 E5 06 00 A0 E1 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __get_next_rpcent_0b16fdf02ac0cb8bb5b46a2e9dd2dc90 {
	meta:
		aliases = "__get_next_rpcent"
		size = "320"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 50 A0 E1 A8 60 80 E2 0A 70 A0 E3 00 80 A0 E3 00 20 95 E5 01 1A A0 E3 06 00 A0 E1 ?? ?? ?? EB 00 30 50 E2 06 40 A0 E1 06 00 A0 E1 01 00 00 1A 03 00 A0 E1 F0 81 BD E8 ?? ?? ?? EB 00 30 85 E0 A7 70 C3 E5 A8 30 D5 E5 23 10 A0 E3 01 00 53 E1 06 00 A0 E1 ED FF FF 0A ?? ?? ?? EB 00 00 50 E3 04 00 00 1A 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 E5 FF FF 0A 00 80 C0 E5 06 00 A0 E1 CC FF FF EB 00 00 50 E3 E0 FF FF 0A 01 80 C0 E4 00 40 A0 E1 9C 60 85 E5 00 00 00 EA 01 40 84 E2 00 30 D4 E5 09 00 53 E3 20 00 53 13 00 70 A0 13 01 70 A0 03 F8 FF FF 0A 04 00 A0 E1 ?? ?? ?? EB 10 60 85 E2 }
	condition:
		$pattern
}

rule _dl_add_elf_hash_table_a1292f46294d087324cb0a34b00093b6 {
	meta:
		aliases = "_dl_add_elf_hash_table"
		size = "240"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { F0 41 2D E9 00 50 A0 E1 E8 00 A0 E3 01 60 A0 E1 02 80 A0 E1 03 70 A0 E1 ?? ?? ?? EB E8 30 A0 E3 00 40 A0 E1 00 20 A0 E1 00 10 A0 E3 00 00 00 EA 01 10 C2 E4 01 30 53 E2 FC FF FF 2A A8 20 9F E5 00 30 92 E5 00 00 53 E3 00 40 82 05 06 00 00 0A 00 00 00 EA 02 30 A0 E1 0C 20 93 E5 00 00 52 E3 FB FF FF 1A 10 30 84 E5 0C 40 83 E5 05 00 A0 E1 00 50 A0 E3 0C 50 84 E5 22 50 C4 E5 23 50 C4 E5 ?? ?? ?? EB 10 10 98 E5 03 30 A0 E3 05 00 51 E1 81 00 84 E9 18 30 84 E5 08 00 00 0A 01 30 A0 E1 04 20 93 E4 28 20 84 E5 04 30 83 E2 04 10 91 E5 02 21 83 E0 38 10 84 E5 3C 20 84 E5 2C 30 84 E5 14 60 84 E5 00 60 84 E5 }
	condition:
		$pattern
}

rule __pthread_alt_timedlock_1ae9e4dfb11423f872250dd6fa090c61 {
	meta:
		aliases = "__pthread_alt_timedlock"
		size = "264"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { F0 41 2D E9 00 50 A0 E1 F0 00 9F E5 02 80 A0 E1 01 70 A0 E1 92 FF FF EB E4 20 9F E5 00 00 92 E5 00 00 50 E3 00 60 A0 11 00 30 96 15 00 60 A0 01 00 30 82 15 C4 30 9F E5 00 20 A0 E3 00 20 83 E5 02 00 56 E1 08 00 00 1A 0C 00 A0 E3 ?? ?? ?? EB 00 60 50 E2 04 00 00 1A 05 00 A0 E1 07 10 A0 E1 ?? ?? ?? EB 01 00 A0 E3 F0 81 BD E8 04 00 85 E2 7B FF FF EB 00 40 95 E5 00 00 54 E3 01 30 A0 03 04 20 A0 01 00 30 85 05 08 00 00 0A 00 00 57 E3 01 00 00 1A 9C FF FF EB 00 70 A0 E1 00 30 A0 E3 08 30 86 E5 90 00 86 E8 00 60 85 E5 01 20 A0 E3 00 30 A0 E3 04 30 85 E5 03 00 52 E1 0B 00 00 0A 08 10 A0 E1 07 00 A0 E1 }
	condition:
		$pattern
}

rule ___path_search_4ddabb2fefbd4122aa72f3a9035ee1ee {
	meta:
		aliases = "___path_search"
		size = "280"
		objfiles = "tempname@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 60 53 E2 08 D0 4D E2 00 80 A0 E1 01 70 A0 E1 02 40 A0 E1 08 00 00 0A 00 30 D6 E5 00 00 53 E3 05 00 00 0A 06 00 A0 E1 ?? ?? ?? EB 05 00 50 E3 00 50 A0 E1 05 50 A0 83 01 00 00 EA C4 60 9F E5 04 50 A0 E3 00 00 54 E3 11 00 00 1A B8 00 9F E5 2B FF FF EB 00 00 50 E3 0C 00 00 1A A8 00 9F E5 00 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 03 00 00 0A 94 00 9F E5 22 FF FF EB 00 00 50 E3 03 00 00 1A ?? ?? ?? EB 00 20 E0 E3 02 30 A0 E3 12 00 00 EA 74 40 9F E5 04 00 A0 E1 ?? ?? ?? EB 00 20 A0 E1 00 00 00 EA 01 20 42 E2 01 00 52 E3 04 30 82 E0 02 00 00 9A 01 30 53 E5 2F 00 53 E3 F8 FF FF 0A 08 30 85 E2 }
	condition:
		$pattern
}

rule pthread_sighandler_rt_1f2b108ed9f67d59519a4e9a18a31edd {
	meta:
		aliases = "pthread_sighandler_rt"
		size = "100"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { F0 41 2D E9 00 60 A0 E1 01 70 A0 E1 02 80 A0 E1 DB FF FF EB 58 30 D0 E5 00 00 53 E3 00 30 A0 13 00 40 A0 E1 20 60 80 15 58 30 C0 15 F0 81 BD 18 54 50 90 E5 00 00 55 E3 54 D0 80 05 07 10 A0 E1 08 20 A0 E1 06 00 A0 E1 10 30 9F E5 0F E0 A0 E1 06 F1 93 E7 00 00 55 E3 54 50 84 05 F0 81 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_svc_getreq_poll_500c99eb5c0d7cd7b56f77b74a2e1aa6 {
	meta:
		aliases = "svc_getreq_poll, __GI_svc_getreq_poll"
		size = "128"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 60 A0 E3 00 70 A0 E1 01 80 A0 E1 06 50 A0 E1 12 00 00 EA 02 40 97 E7 01 00 74 E3 02 30 87 E0 0D 00 00 0A 07 20 D3 E5 06 30 D3 E5 02 34 93 E1 09 00 00 0A 20 00 13 E3 04 00 A0 E1 01 60 86 E2 04 00 00 0A ?? ?? ?? EB B4 30 90 E5 04 01 93 E7 ?? ?? ?? EB 00 00 00 EA ?? ?? ?? EB 01 50 85 E2 ?? ?? ?? EB 00 30 90 E5 03 00 55 E1 08 00 56 B1 85 21 A0 E1 E6 FF FF BA F0 81 BD E8 }
	condition:
		$pattern
}

rule registerrpc_de9e753c61feaa6c6312487d37b83117 {
	meta:
		aliases = "registerrpc"
		size = "300"
		objfiles = "svc_simple@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 80 52 E2 08 D0 4D E2 00 50 A0 E1 01 60 A0 E1 03 70 A0 E1 03 00 00 1A 04 00 8D E2 EC 10 9F E5 ?? ?? ?? EB 2F 00 00 EA ?? ?? ?? EB C4 30 90 E5 00 00 53 E3 00 40 A0 E1 05 00 00 1A 00 00 E0 E3 ?? ?? ?? EB 00 00 50 E3 C4 00 84 E5 C0 00 9F 05 16 00 00 0A 06 10 A0 E1 05 00 A0 E1 ?? ?? ?? EB 11 30 A0 E3 00 30 8D E5 05 10 A0 E1 C4 00 94 E5 06 20 A0 E1 9C 30 9F E5 ?? ?? ?? EB 00 00 50 E3 05 00 00 1A 05 20 A0 E1 06 30 A0 E1 04 00 8D E2 84 10 9F E5 ?? ?? ?? EB 12 00 00 EA 18 00 A0 E3 ?? ?? ?? EB 00 00 50 E3 03 00 00 1A 6C 00 9F E5 ?? ?? ?? EB 04 00 8D E5 0A 00 00 EA 00 70 80 E5 20 01 80 E9 }
	condition:
		$pattern
}

rule _dl_fixup_8c9deae988f391f9877be29f35d98c60 {
	meta:
		aliases = "_dl_fixup"
		size = "340"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { F0 41 2D E9 00 80 A0 E1 10 00 90 E5 00 00 50 E3 01 70 A0 E1 02 00 00 0A ?? ?? ?? EB 00 50 50 E2 49 00 00 1A 00 40 98 E5 5C 30 94 E5 22 10 D4 E5 23 20 D4 E5 00 00 53 E3 01 50 A0 13 02 34 81 E1 41 00 00 1A 84 10 94 E5 00 00 51 E3 88 50 94 E5 1B 00 00 0A 01 00 13 E3 19 00 00 1A C8 C0 94 E5 00 00 5C E3 0B 00 00 0A 00 E0 94 E5 8C 61 A0 E1 08 00 41 E2 08 00 80 E2 00 20 90 E5 02 30 9E E7 01 C0 5C E2 0E 30 83 E0 02 30 8E E7 F8 FF FF 1A 01 10 86 E0 05 50 66 E0 05 20 A0 E1 08 00 A0 E1 ?? ?? ?? EB 20 30 94 E5 23 38 A0 E1 01 30 83 E3 43 24 A0 E1 00 50 A0 E1 23 20 C4 E5 22 30 C4 E5 00 00 00 EA 00 50 A0 E3 }
	condition:
		$pattern
}

rule _stdio_fopen_290e1d9b44b7e09da5c0ebfc524044bc {
	meta:
		aliases = "_stdio_fopen"
		size = "748"
		objfiles = "_fopen@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 C0 D1 E5 72 00 5C E3 20 D0 4D E2 00 60 A0 E1 02 80 A0 E1 03 50 A0 E1 10 00 00 0A 77 00 5C E3 90 42 9F 05 0E 00 00 0A 61 00 5C E3 88 42 9F 05 0B 00 00 0A ?? ?? ?? EB 16 30 A0 E3 00 00 58 E3 00 30 80 E5 97 00 00 0A 01 30 D8 E5 20 00 13 E3 94 00 00 0A 08 00 A0 E1 ?? ?? ?? EB 91 00 00 EA 00 40 A0 E3 01 30 D1 E5 62 00 53 E3 01 30 A0 11 01 30 81 02 01 30 D3 E5 2B 00 53 E3 01 30 84 03 01 40 83 02 00 00 58 E3 0A 00 00 1A 50 00 A0 E3 ?? ?? ?? EB 00 80 50 E2 83 00 00 0A 00 20 A0 E3 20 30 A0 E3 01 30 C8 E5 08 20 88 E5 00 20 C8 E5 38 00 88 E2 ?? ?? ?? EB 00 00 55 E3 13 00 00 BA F8 21 9F E5 }
	condition:
		$pattern
}

rule regcomp_da45b1d993b5838073b6d2eacd2e1520 {
	meta:
		aliases = "regcomp"
		size = "340"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { F0 41 2D E9 01 00 12 E3 00 60 A0 E3 30 31 9F E5 02 50 A0 E1 2C 21 9F E5 00 40 A0 E1 00 60 80 E5 04 60 80 E5 08 60 80 E5 01 0C A0 E3 02 70 A0 01 03 70 A0 11 01 80 A0 E1 ?? ?? ?? EB 02 30 15 E2 10 00 84 E5 16 00 00 0A 01 0C A0 E3 ?? ?? ?? EB 06 00 50 E1 14 00 84 E5 0C 50 A0 03 36 00 00 0A E4 E0 9F E5 E4 C0 9F E5 06 20 A0 E1 08 00 00 EA 00 30 9E E5 01 30 D3 E7 01 00 13 E3 00 30 9C 15 14 00 94 E5 01 30 D3 17 FF 30 02 02 02 30 C0 E7 01 20 82 E2 FF 00 52 E3 82 10 A0 E1 F3 FF FF 9A 00 00 00 EA 14 30 84 E5 1C 20 D4 E5 04 00 15 E3 80 30 C2 03 80 20 82 13 1C 20 C4 15 1C 30 C4 05 40 30 C7 13 01 7C 83 13 }
	condition:
		$pattern
}

rule vsscanf_4f186c8986816f2ff73b35018495efb8 {
	meta:
		aliases = "__GI_vsscanf, vsscanf"
		size = "136"
		objfiles = "vsscanf@libc.a"
	strings:
		$pattern = { F0 41 2D E9 01 30 E0 E3 50 D0 4D E2 04 30 8D E5 A3 30 83 E2 00 50 A0 E1 00 40 A0 E3 38 00 8D E2 00 30 CD E5 01 30 A0 E3 34 30 8D E5 01 60 A0 E1 02 70 A0 E1 01 40 CD E5 02 40 CD E5 2C 40 8D E5 ?? ?? ?? EB 20 40 8D E5 10 50 8D E5 08 50 8D E5 05 00 A0 E1 ?? ?? ?? EB 06 10 A0 E1 00 30 85 E0 07 20 A0 E1 0D 00 A0 E1 0D 80 A0 E1 18 30 8D E5 1C 50 8D E5 0C 30 8D E5 14 30 8D E5 ?? ?? ?? EB 50 D0 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule __fake_pread_write_7bdff9846ef86da433680c868c705ff9 {
	meta:
		aliases = "__fake_pread_write"
		size = "184"
		objfiles = "pread_write@libc.a"
	strings:
		$pattern = { F0 41 2D E9 01 50 A0 E1 02 70 A0 E1 00 10 A0 E3 01 20 A0 E3 03 40 A0 E1 00 60 A0 E1 ?? ?? ?? EB 01 00 70 E3 00 80 A0 E1 1F 00 00 0A 04 10 A0 E1 06 00 A0 E1 00 20 A0 E3 ?? ?? ?? EB 01 00 70 E3 19 00 00 0A 18 30 9D E5 01 00 53 E3 04 00 00 1A 05 10 A0 E1 07 20 A0 E1 06 00 A0 E1 ?? ?? ?? EB 03 00 00 EA 05 10 A0 E1 07 20 A0 E1 06 00 A0 E1 ?? ?? ?? EB 00 50 A0 E1 ?? ?? ?? EB 08 10 A0 E1 00 40 A0 E1 00 20 A0 E3 06 00 A0 E1 00 60 94 E5 ?? ?? ?? EB 01 00 70 E3 01 00 00 1A 01 00 75 E3 01 00 00 1A 00 60 84 E5 00 00 00 EA 00 50 E0 E3 05 00 A0 E1 F0 81 BD E8 }
	condition:
		$pattern
}

rule rwlock_have_already_6748586c2a4e0f163daeb767987ed1b5 {
	meta:
		aliases = "rwlock_have_already"
		size = "224"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { F0 41 2D E9 01 50 A0 E1 18 10 91 E5 01 00 51 E3 00 60 A0 E1 00 40 90 E5 00 00 A0 13 02 80 A0 E1 03 70 A0 E1 00 20 A0 11 00 30 A0 11 26 00 00 1A 00 00 54 E3 01 00 00 1A A3 FF FF EB 00 40 A0 E1 48 01 94 E5 03 00 00 EA 04 30 90 E5 05 00 53 E1 03 00 00 0A 00 00 90 E5 00 00 50 E3 F9 FF FF 1A 01 00 00 EA 00 00 50 E3 15 00 00 1A 50 31 94 E5 00 00 53 E3 12 00 00 CA 4C 01 94 E5 00 00 50 E3 00 30 90 15 4C 31 84 15 0C 00 A0 03 ?? ?? ?? 0B 00 00 50 E3 05 00 00 0A 48 31 94 E5 00 30 80 E5 01 30 A0 E3 08 30 80 E5 04 50 80 E5 48 01 84 E5 00 20 A0 01 00 20 A0 13 00 30 A0 13 01 30 A0 03 01 00 00 EA 00 30 A0 E3 }
	condition:
		$pattern
}

rule _fp_out_narrow_51d8cfc154212fd8ec2d26446288009b {
	meta:
		aliases = "_fp_out_narrow"
		size = "128"
		objfiles = "_vfprintf_internal@libc.a"
	strings:
		$pattern = { F0 41 2D E9 01 50 A0 E1 80 10 11 E2 00 80 A0 E1 02 40 A0 E1 03 70 A0 E1 01 50 A0 01 0E 00 00 0A 03 00 A0 E1 ?? ?? ?? EB 04 40 60 E0 00 00 54 E3 00 60 A0 E1 00 50 A0 D3 06 00 00 DA 7F 10 05 E2 08 00 A0 E1 04 20 A0 E1 D8 FF FF EB 04 00 50 E1 00 50 A0 E1 07 00 00 1A 06 40 A0 E1 00 00 54 E3 00 00 A0 D3 07 00 A0 C1 04 10 A0 C1 08 20 A0 C1 ?? ?? ?? CB 00 50 85 E0 05 00 A0 E1 F0 81 BD E8 }
	condition:
		$pattern
}

rule _fp_out_wide_ee27285a852c386cb77a2add89a0d966 {
	meta:
		aliases = "_fp_out_wide"
		size = "168"
		objfiles = "_vfwprintf_internal@libc.a"
	strings:
		$pattern = { F0 41 2D E9 01 50 A0 E1 80 10 11 E2 54 D0 4D E2 00 80 A0 E1 02 40 A0 E1 03 70 A0 E1 01 50 A0 01 0E 00 00 0A 03 00 A0 E1 ?? ?? ?? EB 04 40 60 E0 00 00 54 E3 00 60 A0 E1 00 50 A0 D3 06 00 00 DA 7F 10 05 E2 08 00 A0 E1 04 20 A0 E1 10 FE FF EB 04 00 50 E1 00 50 A0 E1 0F 00 00 1A 06 40 A0 E1 00 00 54 E3 0C 00 00 DA 00 10 A0 E3 54 30 8D E2 01 21 83 E0 01 30 D7 E7 01 10 81 E2 04 00 51 E1 54 30 02 E5 F8 FF FF BA 04 10 A0 E1 08 20 A0 E1 0D 00 A0 E1 ?? ?? ?? EB 00 50 85 E0 05 00 A0 E1 54 D0 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule __GI_asctime_r_38cb552a8ddfec57f6ff69286c4b07b5 {
	meta:
		aliases = "asctime_r, __GI_asctime_r"
		size = "296"
		objfiles = "asctime_r@libc.a"
	strings:
		$pattern = { F0 41 2D E9 01 60 A0 E1 00 70 A0 E1 04 11 9F E5 06 00 A0 E1 1A 20 A0 E3 ?? ?? ?? EB 18 10 97 E5 06 00 51 E3 F0 30 9F 95 03 20 A0 93 92 31 21 90 06 00 A0 91 ?? ?? ?? 9B 10 10 97 E5 0B 00 51 E3 D8 30 9F 95 03 20 A0 93 92 31 21 90 04 00 86 92 ?? ?? ?? 9B 14 30 97 E5 76 5E 83 E2 C0 30 9F E5 0C 50 85 E2 03 00 55 E1 13 40 86 E2 0C 00 00 8A 17 40 86 E2 05 00 A0 E1 0A 10 A0 E3 ?? ?? ?? EB 30 00 80 E2 00 00 C4 E5 0A 10 A0 E3 05 00 A0 E1 ?? ?? ?? EB 01 30 74 E5 3F 00 53 E3 00 50 A0 E1 F3 FF FF 0A 3F 80 A0 E3 01 30 54 E5 03 60 97 E7 01 50 44 E2 63 00 56 E3 01 80 44 85 0A 10 A0 E3 06 00 A0 E1 01 80 45 85 }
	condition:
		$pattern
}

rule __GI_xdr_bytes_43947a1e4ab9e22e1316e0cf109228d3 {
	meta:
		aliases = "xdr_bytes, __GI_xdr_bytes"
		size = "232"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { F0 41 2D E9 01 80 A0 E1 02 10 A0 E1 02 50 A0 E1 03 70 A0 E1 00 60 A0 E1 00 40 98 E5 ?? ?? ?? EB 00 00 50 E3 29 00 00 0A 00 50 95 E5 07 00 55 E1 02 00 00 9A 00 30 96 E5 02 00 53 E3 23 00 00 1A 00 30 96 E5 01 00 53 E3 03 00 00 0A 12 00 00 3A 02 00 53 E3 1D 00 00 1A 14 00 00 EA 00 00 55 E3 1C 00 00 0A 00 00 54 E3 0B 00 00 1A 05 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 40 A0 E1 00 00 88 E5 05 00 00 1A 54 30 9F E5 54 00 9F E5 00 10 93 E5 ?? ?? ?? EB 04 00 A0 E1 F0 81 BD E8 06 00 A0 E1 04 10 A0 E1 05 20 A0 E1 F0 41 BD E8 ?? ?? ?? EA 00 00 54 E3 07 00 00 0A 04 00 A0 E1 ?? ?? ?? EB 00 30 A0 E3 01 00 A0 E3 }
	condition:
		$pattern
}

rule __GI_vasprintf_1b5110e58fe9c08b9f1b747ce35facbb {
	meta:
		aliases = "vasprintf, __GI_vasprintf"
		size = "132"
		objfiles = "vasprintf@libc.a"
	strings:
		$pattern = { F0 41 2D E9 02 60 A0 E1 00 50 A0 E1 01 70 A0 E1 00 00 A0 E3 04 D0 4D E2 00 10 A0 E1 07 20 A0 E1 06 30 A0 E1 00 60 8D E5 ?? ?? ?? EB 00 80 A0 E3 00 40 50 E2 00 80 85 E5 0E 00 00 BA 01 40 84 E2 04 00 A0 E1 ?? ?? ?? EB 08 00 50 E1 00 00 85 E5 08 00 00 0A 04 10 A0 E1 07 20 A0 E1 06 30 A0 E1 ?? ?? ?? EB 00 40 50 E2 02 00 00 AA 00 00 95 E5 ?? ?? ?? EB 00 80 85 E5 04 00 A0 E1 04 D0 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule __stdio_WRITE_f8c121dc568c64c413be02b6f78c6f34 {
	meta:
		aliases = "__stdio_WRITE"
		size = "184"
		objfiles = "_WRITE@libc.a"
	strings:
		$pattern = { F0 41 2D E9 02 70 A0 E1 00 40 A0 E1 01 60 A0 E1 02 50 A0 E1 02 81 E0 E3 00 00 55 E3 23 00 00 0A 08 20 A0 B1 05 20 A0 A1 06 10 A0 E1 04 00 94 E5 ?? ?? ?? EB 00 00 50 E3 00 60 86 A0 05 50 60 A0 F4 FF FF AA 00 30 94 E5 08 00 84 E2 05 00 90 E8 08 30 83 E3 43 14 A0 E1 00 20 52 E0 01 10 C4 E5 00 30 C4 E5 10 00 00 0A 05 00 52 E1 05 20 A0 21 00 30 D6 E5 0A 00 53 E3 01 60 86 E2 00 30 C0 E5 02 00 00 1A 01 30 D4 E5 01 00 13 E3 02 00 00 1A 01 20 52 E2 01 00 80 E2 F4 FF FF 1A 08 30 94 E5 10 00 84 E5 00 30 63 E0 05 50 63 E0 07 70 65 E0 07 00 A0 E1 F0 81 BD E8 }
	condition:
		$pattern
}

rule writetcp_99643780a03b34649dbe4cf018672b6a {
	meta:
		aliases = "writetcp"
		size = "100"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { F0 41 2D E9 02 80 A0 E1 00 70 A0 E1 01 60 A0 E1 02 50 A0 E1 0D 00 00 EA 00 00 97 E5 ?? ?? ?? EB 01 00 70 E3 00 40 A0 E1 06 00 00 1A ?? ?? ?? EB 00 20 90 E5 03 30 A0 E3 04 80 A0 E1 24 30 87 E5 28 20 87 E5 04 00 00 EA 00 60 86 E0 05 50 60 E0 00 20 55 E2 06 10 A0 E1 EE FF FF CA 08 00 A0 E1 F0 81 BD E8 }
	condition:
		$pattern
}

rule writeunix_cbc05106facfeef1f44538ae7acf8e64 {
	meta:
		aliases = "writeunix"
		size = "100"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { F0 41 2D E9 02 80 A0 E1 00 70 A0 E1 01 60 A0 E1 02 50 A0 E1 0D 00 00 EA 00 00 97 E5 C7 FF FF EB 01 00 70 E3 00 40 A0 E1 06 00 00 1A ?? ?? ?? EB 00 20 90 E5 03 30 A0 E3 04 80 A0 E1 84 30 87 E5 88 20 87 E5 04 00 00 EA 00 60 86 E0 05 50 60 E0 00 20 55 E2 06 10 A0 E1 EE FF FF CA 08 00 A0 E1 F0 81 BD E8 }
	condition:
		$pattern
}

rule getgrouplist_5a1ed38bebb7dc51ef0f091cc6cbf0d6 {
	meta:
		aliases = "getgrouplist"
		size = "120"
		objfiles = "getgrouplist@libc.a"
	strings:
		$pattern = { F0 41 2D E9 02 80 A0 E1 03 20 A0 E1 03 40 A0 E1 01 70 A0 E1 00 50 93 E5 ?? ?? ?? EB 00 60 50 E2 04 00 00 1A 00 00 55 E3 01 50 A0 13 00 70 88 15 0E 00 00 1A 0C 00 00 EA 00 30 94 E5 03 00 55 E1 03 50 A0 A1 00 00 55 E3 08 00 A0 11 06 10 A0 11 05 21 A0 11 ?? ?? ?? 1B 06 00 A0 E1 ?? ?? ?? EB 00 30 94 E5 03 00 55 E1 00 00 00 AA 00 50 E0 E3 05 00 A0 E1 F0 81 BD E8 }
	condition:
		$pattern
}

rule authunix_create_default_c00a2fdc93ee4260ce6a99874bab3cbf {
	meta:
		aliases = "__GI_authunix_create_default, authunix_create_default"
		size = "176"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { F0 41 2D E9 03 00 A0 E3 41 DF 4D E2 ?? ?? ?? EB 00 40 50 E2 04 50 A0 01 04 00 00 0A 04 01 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 50 A0 11 10 00 00 0A 04 80 8D E2 08 00 A0 E1 FF 10 A0 E3 ?? ?? ?? EB 01 00 70 E3 0A 00 00 0A 00 30 A0 E3 03 31 CD E5 ?? ?? ?? EB 00 70 A0 E1 ?? ?? ?? EB 05 10 A0 E1 00 60 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 00 AA ?? ?? ?? EB 10 00 50 E3 00 30 A0 B1 10 30 A0 A3 07 10 A0 E1 06 20 A0 E1 08 00 A0 E1 00 50 8D E5 ?? ?? ?? EB 00 40 A0 E1 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 41 DF 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule lockf64_f5340e95f98e23286a2d9e5965c0286a {
	meta:
		aliases = "__GI_lockf64, lockf64"
		size = "328"
		objfiles = "lockf64@libc.a"
	strings:
		$pattern = { F0 41 2D E9 03 60 A0 E1 02 30 A0 E1 C3 4F A0 E1 04 00 56 E1 18 D0 4D E2 02 50 A0 E1 00 80 A0 E1 01 70 A0 E1 03 00 00 0A ?? ?? ?? EB 00 20 E0 E3 4B 30 A0 E3 3D 00 00 EA 0D 00 A0 E1 00 10 A0 E3 18 20 A0 E3 ?? ?? ?? EB 01 30 A0 E3 02 30 CD E5 00 30 A0 E3 03 30 CD E5 00 40 A0 E3 00 30 A0 E3 18 00 8D E9 0C 50 8D E5 10 60 8D E5 03 00 57 E3 07 F1 9F 97 2A 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 30 A0 E3 0D 20 A0 E1 08 00 A0 E1 0C 10 A0 E3 01 30 CD E5 00 30 CD E5 ?? ?? ?? EB 00 00 50 E3 00 20 E0 B3 22 00 00 BA 01 30 DD E5 00 20 DD E5 03 3C A0 E1 43 28 82 E1 02 00 52 E3 1B 00 00 0A }
	condition:
		$pattern
}

rule __GI_xdr_rmtcall_args_47ad1d165afaa0d7d32fbf91ddb6ec0d {
	meta:
		aliases = "xdr_rmtcall_args, __GI_xdr_rmtcall_args"
		size = "272"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { F0 41 2D E9 04 D0 4D E2 00 50 A0 E1 01 60 A0 E1 ?? ?? ?? EB 00 00 50 E3 39 00 00 0A 05 00 A0 E1 04 10 86 E2 ?? ?? ?? EB 00 00 50 E3 34 00 00 0A 05 00 A0 E1 08 10 86 E2 ?? ?? ?? EB 00 00 50 E3 2F 00 00 0A 00 30 A0 E3 04 40 8D E2 04 30 24 E5 05 00 A0 E1 04 30 95 E5 0F E0 A0 E1 10 F0 93 E5 0D 10 A0 E1 00 80 A0 E1 05 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 22 00 00 0A 04 30 95 E5 05 00 A0 E1 0F E0 A0 E1 10 F0 93 E5 10 10 96 E5 00 70 A0 E1 05 00 A0 E1 0F E0 A0 E1 14 F0 96 E5 00 00 50 E3 17 00 00 0A 04 30 95 E5 05 00 A0 E1 0F E0 A0 E1 10 F0 93 E5 00 30 67 E0 0C 30 A6 E5 08 10 A0 E1 04 30 95 E5 00 40 A0 E1 }
	condition:
		$pattern
}

rule memalign_d307f7762d20eb48da46a281d68a0ab1 {
	meta:
		aliases = "memalign"
		size = "472"
		objfiles = "memalign@libc.a"
	strings:
		$pattern = { F0 41 2D E9 08 00 50 E3 10 D0 4D E2 00 50 A0 E1 01 40 A0 E1 03 00 00 8A 01 00 A0 E1 ?? ?? ?? EB 00 50 A0 E1 63 00 00 EA 0F 00 50 E3 10 50 A0 93 01 30 45 E2 05 00 13 E1 10 30 A0 13 01 00 00 1A 03 00 00 EA 83 30 A0 E1 05 00 53 E1 FC FF FF 3A 03 50 A0 E1 0D 00 A0 E1 64 11 9F E5 64 21 9F E5 64 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 54 01 9F E5 58 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 21 00 74 E3 04 00 00 9A ?? ?? ?? EB 00 50 A0 E3 0C 30 A0 E3 00 30 80 E5 47 00 00 EA 0B 00 84 E2 0F 00 50 E3 07 80 C0 83 10 80 A0 93 10 00 85 E2 08 00 80 E0 ?? ?? ?? EB 00 70 50 E2 07 50 A0 01 38 00 00 0A 05 10 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule _Unwind_Backtrace_b0580f5b1183edf2acb4861bdf6e96bc {
	meta:
		aliases = "_Unwind_Backtrace"
		size = "124"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { F0 41 2D E9 08 D0 4D E2 04 50 8D E2 00 80 A0 E1 05 00 A0 E1 01 70 A0 E1 B6 FF FF EB 0D 60 A0 E1 08 00 00 EA 0F E0 A0 E1 08 F0 A0 E1 00 00 50 E3 0D 10 A0 E1 05 00 A0 E1 0B 00 00 1A 05 00 54 E3 0A 00 00 0A 9E FF FF EB 0D 10 A0 E1 05 00 A0 E1 92 FF FF EB 00 00 50 E3 05 00 50 13 00 40 A0 E1 07 10 A0 E1 05 00 A0 E1 ED FF FF 0A 03 40 A0 E3 04 00 A0 E1 08 D0 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule _Unwind_SjLj_ForcedUnwind_86f3092eda065b34910ffa609358a9a3 {
	meta:
		aliases = "_Unwind_SjLj_ForcedUnwind"
		size = "92"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { F0 41 2D E9 08 D0 4D E2 04 80 8D E2 00 40 A0 E1 08 00 A0 E1 01 50 A0 E1 02 60 A0 E1 49 FF FF EB 04 30 9D E5 0C 50 84 E5 10 60 84 E5 04 00 A0 E1 0D 10 A0 E1 00 30 8D E5 49 FF FF EB 07 00 50 E3 0D 70 A0 E1 01 00 00 0A 08 D0 8D E2 F0 81 BD E8 08 00 A0 E1 0D 10 A0 E1 C4 FF FF EB }
	condition:
		$pattern
}

rule xdrrec_putbytes_6c4bbbecf549405da624543028b06901 {
	meta:
		aliases = "xdrrec_putbytes"
		size = "148"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { F0 41 2D E9 0C 50 90 E5 01 70 A0 E1 02 60 A0 E1 01 80 A0 E3 19 00 00 EA 10 00 85 E2 11 00 90 E8 04 40 60 E0 04 00 56 E1 06 40 A0 31 04 20 A0 E1 ?? ?? ?? EB 10 20 95 E5 04 60 56 E0 14 10 95 E5 02 20 84 E0 00 30 A0 03 01 30 A0 13 01 00 52 E1 00 30 A0 13 01 30 03 02 00 00 53 E3 10 20 85 E5 04 70 87 E0 05 00 00 0A 1C 80 85 E5 05 00 A0 E1 00 10 A0 E3 C0 FE FF EB 00 00 50 E3 F0 81 BD 08 00 00 56 E3 07 10 A0 E1 E2 FF FF 1A 01 00 A0 E3 F0 81 BD E8 }
	condition:
		$pattern
}

rule _Unwind_RaiseException_Phase2_de9741c81e3423777066615519202983 {
	meta:
		aliases = "_Unwind_RaiseException_Phase2"
		size = "164"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { F0 41 2D E9 0C D0 4D E2 00 60 A0 E1 01 50 A0 E1 08 80 8D E2 12 00 00 EA 08 C0 9D E5 00 00 5C E3 0A 00 00 0A 0C 00 96 E8 01 00 A0 E3 00 60 8D E5 04 50 8D E5 02 10 87 E3 0F E0 A0 E1 0C F0 A0 E1 07 00 50 E3 13 00 00 0A 08 00 50 E3 10 00 00 1A 00 00 57 E3 11 00 00 1A 05 00 A0 E1 08 10 A0 E1 78 FF FF EB 08 10 A0 E1 05 00 A0 E1 6C FF FF EB 00 40 A0 E1 05 00 A0 E1 84 FF FF EB 10 30 96 E5 03 00 50 E1 04 70 A0 03 00 70 A0 13 00 00 54 E3 E0 FF FF 0A 02 00 A0 E3 0C D0 8D E2 F0 81 BD E8 ?? ?? ?? EB }
	condition:
		$pattern
}

rule fde_single_encoding_compare_19ec22644e43f0dde43d0651f1b518ec {
	meta:
		aliases = "fde_single_encoding_compare"
		size = "164"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { F0 41 2D E9 10 50 80 E2 00 40 A0 E1 01 30 D5 E5 10 00 D0 E5 03 04 80 E1 A0 01 A0 E1 08 D0 4D E2 01 60 A0 E1 FF 00 00 E2 04 10 A0 E1 02 80 A0 E1 50 FF FF EB 01 30 D5 E5 00 70 A0 E1 10 00 D4 E5 03 04 80 E1 A0 01 A0 E1 08 20 86 E2 07 10 A0 E1 04 30 8D E2 FF 00 00 E2 5C FF FF EB 01 30 D5 E5 10 00 D4 E5 03 04 80 E1 A0 01 A0 E1 08 20 88 E2 0D 30 A0 E1 FF 00 00 E2 07 10 A0 E1 53 FF FF EB 04 20 9D E5 00 30 9D E5 03 00 52 E1 01 00 A0 83 01 00 00 8A 00 00 E0 33 00 00 A0 23 08 D0 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule rendezvous_request_dc0542866a9a30c02f8e94861ba46137 {
	meta:
		aliases = "rendezvous_request"
		size = "124"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { F0 41 2D E9 10 80 A0 E3 14 D0 4D E2 2C 50 90 E5 00 40 A0 E1 0D 60 A0 E1 08 70 8D E0 00 00 94 E5 06 10 A0 E1 07 20 A0 E1 10 80 8D E5 ?? ?? ?? EB 00 00 50 E3 04 00 00 AA ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 09 00 00 1A F3 FF FF EA 06 00 95 E8 B6 FE FF EB 0D 10 A0 E1 00 40 A0 E1 08 20 A0 E1 10 00 80 E2 ?? ?? ?? EB 10 30 9D E5 0C 30 84 E5 00 00 A0 E3 14 D0 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule getnetent_2d155d189e4ddb560d2d8cabaaba1155 {
	meta:
		aliases = "__GI_getnetent, getnetent"
		size = "508"
		objfiles = "getnetent@libc.a"
	strings:
		$pattern = { F0 41 2D E9 10 D0 4D E2 0D 00 A0 E1 B0 11 9F E5 B0 21 9F E5 B0 31 9F E5 B0 41 9F E5 0F E0 A0 E1 03 F0 A0 E1 A8 31 9F E5 98 01 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 94 E5 00 00 53 E3 05 00 00 1A 90 01 9F E5 90 11 9F E5 ?? ?? ?? EB 00 00 50 E3 00 00 84 E5 51 00 00 0A 80 51 9F E5 80 81 9F E5 04 70 A0 E1 00 60 A0 E3 00 30 95 E5 00 00 53 E3 04 00 00 1A 6C 01 9F E5 ?? ?? ?? EB 00 00 50 E3 00 00 85 E5 ?? ?? ?? 0B 00 00 95 E5 01 1A A0 E3 00 20 97 E5 ?? ?? ?? EB 00 40 50 E2 3F 00 00 0A 00 30 D4 E5 23 00 53 E3 EE FF FF 0A 38 11 9F E5 C4 FF FF EB 00 00 50 E3 EA FF FF 0A 00 60 C0 E5 28 11 9F E5 04 00 A0 E1 }
	condition:
		$pattern
}

rule getgrent_r_99821bf27485a6a4b744561d515384a2 {
	meta:
		aliases = "getpwent_r, __GI_getgrent_r, getspent_r, __GI_getpwent_r, __GI_getspent_r, getgrent_r"
		size = "240"
		objfiles = "getgrent_r@libc.a, getspent_r@libc.a, getpwent_r@libc.a"
	strings:
		$pattern = { F0 41 2D E9 14 D0 4D E2 03 50 A0 E1 00 60 A0 E1 B4 30 9F E5 04 00 8D E2 01 70 A0 E1 02 80 A0 E1 A8 10 9F E5 A8 20 9F E5 A8 40 9F E5 0F E0 A0 E1 03 F0 A0 E1 A0 30 9F E5 94 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 94 E5 00 00 53 E3 00 30 A0 E3 00 30 85 E5 0A 00 00 1A 80 00 9F E5 80 10 9F E5 ?? ?? ?? EB 00 00 50 E3 01 30 A0 13 00 00 84 E5 34 30 80 15 02 00 00 1A ?? ?? ?? EB 00 40 90 E5 09 00 00 EA 4C 30 9F E5 00 C0 93 E5 07 20 A0 E1 08 30 A0 E1 4C 00 9F E5 06 10 A0 E1 00 C0 8D E5 ?? ?? ?? EB 00 40 50 E2 00 60 85 05 04 00 8D E2 01 10 A0 E3 30 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 14 D0 8D E2 }
	condition:
		$pattern
}

rule _Unwind_SjLj_RaiseException_a9315bf0e5f96d092633f9fa6fa5db2f {
	meta:
		aliases = "_Unwind_SjLj_RaiseException"
		size = "220"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { F0 41 2D E9 14 D0 4D E2 10 80 8D E2 00 50 A0 E1 08 00 A0 E1 34 FF FF EB 10 30 9D E5 0C 60 8D E2 08 70 8D E2 0C 30 8D E5 11 00 00 EA 00 00 50 E3 18 00 00 1A 08 C0 9D E5 00 00 5C E3 09 00 00 0A 01 00 A0 E3 0C 00 95 E8 00 10 A0 E1 60 00 8D E8 0F E0 A0 E1 0C F0 A0 E1 06 00 50 E3 0F 00 00 0A 08 00 50 E3 0B 00 00 1A 06 00 A0 E1 07 10 A0 E1 10 FF FF EB 06 00 A0 E1 07 10 A0 E1 04 FF FF EB 05 00 50 E3 00 40 A0 E1 E7 FF FF 1A 04 00 A0 E1 14 D0 8D E2 F0 81 BD E8 03 40 A0 E3 FA FF FF EA 0C 40 85 E5 06 00 A0 E1 14 FF FF EB 10 30 9D E5 10 00 85 E5 06 10 A0 E1 05 00 A0 E1 0C 30 8D E5 6A FF FF EB 07 00 50 E3 }
	condition:
		$pattern
}

rule readdir64_r_4b83e2eec1f224046f595443a5335e86 {
	meta:
		aliases = "__GI_readdir64_r, readdir64_r"
		size = "292"
		objfiles = "readdir64_r@libc.a"
	strings:
		$pattern = { F0 41 2D E9 18 40 80 E2 10 D0 4D E2 00 31 9F E5 00 50 A0 E1 01 80 A0 E1 0D 00 A0 E1 F4 10 9F E5 02 70 A0 E1 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 E0 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 60 A0 E3 06 40 A0 E1 0C 00 95 E9 02 00 53 E1 0E 00 00 8A 00 00 95 E5 0C 10 95 E5 14 20 95 E5 ?? ?? ?? EB 00 00 50 E3 06 00 00 CA 00 30 A0 E3 00 30 87 E5 00 40 A0 01 1B 00 00 0A ?? ?? ?? EB 00 40 90 E5 18 00 00 EA 08 00 85 E5 04 40 85 E5 04 20 95 E5 0C 00 95 E5 00 60 82 E0 10 E0 86 E2 01 10 DE E5 10 30 D6 E5 00 C0 92 E7 04 00 96 E5 01 34 83 E1 08 10 96 E5 02 30 83 E0 00 C0 9C E1 04 30 85 E5 10 10 85 E5 }
	condition:
		$pattern
}

rule readdir_r_f5162547dc741dd2bb71cf1db790f9c4 {
	meta:
		aliases = "__GI_readdir_r, readdir_r"
		size = "288"
		objfiles = "readdir_r@libc.a"
	strings:
		$pattern = { F0 41 2D E9 18 40 80 E2 10 D0 4D E2 FC 30 9F E5 00 50 A0 E1 01 80 A0 E1 0D 00 A0 E1 F0 10 9F E5 02 70 A0 E1 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 DC 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 60 A0 E3 06 40 A0 E1 0C 00 95 E9 02 00 53 E1 0E 00 00 8A 00 00 95 E5 0C 10 95 E5 14 20 95 E5 ?? ?? ?? EB 00 00 50 E3 06 00 00 CA 00 30 A0 E3 00 30 87 E5 00 40 A0 01 1A 00 00 0A ?? ?? ?? EB 00 40 90 E5 17 00 00 EA 08 00 85 E5 04 40 85 E5 04 10 95 E5 0C C0 95 E5 0C 60 81 E0 04 20 96 E5 08 E0 86 E2 08 30 D6 E5 01 00 DE E5 10 20 85 E5 0C 20 91 E7 00 34 83 E1 01 30 83 E0 00 00 52 E3 04 30 85 E5 DF FF FF 0A }
	condition:
		$pattern
}

rule __GI_xdr_union_3a0d819d52ec105a179fd2f390016870 {
	meta:
		aliases = "xdr_union, __GI_xdr_union"
		size = "132"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { F0 41 2D E9 18 60 9D E5 01 50 A0 E1 02 80 A0 E1 03 40 A0 E1 00 70 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 10 95 15 F0 81 BD 08 09 00 00 EA 00 30 94 E5 01 00 53 E1 05 00 00 1A 07 00 A0 E1 08 10 A0 E1 00 20 E0 E3 0F E0 A0 E1 0C F0 A0 E1 F0 81 BD E8 08 40 84 E2 04 C0 94 E5 00 00 5C E3 F2 FF FF 1A 00 00 56 E3 06 00 A0 01 F0 81 BD 08 07 00 A0 E1 08 10 A0 E1 00 20 E0 E3 0F E0 A0 E1 06 F0 A0 E1 F0 81 BD E8 }
	condition:
		$pattern
}

rule __GI_lfind_c6ce82c7da8bbafa483129ec4fb27072 {
	meta:
		aliases = "lfind, __GI_lfind"
		size = "80"
		objfiles = "lfind@libc.a"
	strings:
		$pattern = { F0 41 2D E9 18 80 9D E5 00 50 92 E5 00 70 A0 E1 01 40 A0 E1 03 60 A0 E1 06 00 00 EA 0F E0 A0 E1 08 F0 A0 E1 00 00 50 E3 01 00 00 1A 04 00 A0 E1 F0 81 BD E8 06 40 84 E0 01 50 55 E2 04 10 A0 E1 07 00 A0 E1 F4 FF FF 2A 00 00 A0 E3 F0 81 BD E8 }
	condition:
		$pattern
}

rule __GI_sgetspent_r_37970a154259239cca5ce30de96566cb {
	meta:
		aliases = "sgetspent_r, __GI_sgetspent_r"
		size = "120"
		objfiles = "sgetspent_r@libc.a"
	strings:
		$pattern = { F0 41 2D E9 18 80 9D E5 03 60 A0 E1 FF 00 53 E3 00 30 A0 E3 00 30 88 E5 01 70 A0 E1 02 40 A0 E1 00 50 A0 E1 04 00 00 8A ?? ?? ?? EB 22 30 A0 E3 03 20 A0 E1 00 30 80 E5 0C 00 00 EA 02 00 50 E1 05 00 00 0A ?? ?? ?? EB 06 00 50 E1 F5 FF FF 2A 05 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 04 10 A0 E1 07 00 A0 E1 ?? ?? ?? EB 00 20 50 E2 00 70 88 05 02 00 A0 E1 F0 81 BD E8 }
	condition:
		$pattern
}

rule authunix_refresh_c00553c94cfbdf4996b7f3fa16196072 {
	meta:
		aliases = "authunix_refresh"
		size = "240"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { F0 41 2D E9 24 40 90 E5 04 20 90 E5 04 30 94 E5 03 00 52 E1 38 D0 4D E2 00 50 A0 E1 00 60 A0 03 2F 00 00 0A 18 30 94 E5 00 60 A0 E3 01 30 83 E2 18 30 84 E5 1C 60 8D E5 2C 60 8D E5 0D 00 A0 E1 06 00 94 E9 01 30 A0 E3 18 80 8D E2 ?? ?? ?? EB 0D 00 A0 E1 08 10 A0 E1 ?? ?? ?? EB 06 00 50 E1 0D 70 A0 E1 12 00 00 0A 06 10 A0 E1 30 00 8D E2 ?? ?? ?? EB 30 30 9D E5 06 10 A0 E1 18 30 8D E5 00 60 8D E5 04 30 9D E5 0D 00 A0 E1 0F E0 A0 E1 14 F0 93 E5 0D 00 A0 E1 08 10 A0 E1 ?? ?? ?? EB 00 60 50 E2 07 00 94 18 07 00 85 18 05 00 A0 11 AC FF FF 1B 02 30 A0 E3 0D 00 A0 E1 18 10 8D E2 00 30 8D E5 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __GI_gethostent_r_a1317e1ce234dd5155a8c093379a0c45 {
	meta:
		aliases = "gethostent_r, __GI_gethostent_r"
		size = "240"
		objfiles = "gethostent_r@libc.a"
	strings:
		$pattern = { F0 41 2D E9 24 D0 4D E2 00 60 A0 E1 01 70 A0 E1 14 00 8D E2 B8 10 9F E5 02 80 A0 E1 B4 50 9F E5 B4 20 9F E5 03 40 A0 E1 B0 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 A8 30 9F E5 9C 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 95 E5 00 00 53 E3 05 00 00 1A ?? ?? ?? EB 00 00 50 E3 00 00 85 E5 02 60 A0 03 00 00 84 05 12 00 00 0A 68 50 9F E5 3C C0 9D E5 01 30 A0 E3 00 10 A0 E3 00 00 95 E5 02 20 A0 E3 00 60 8D E5 0C 40 8D E5 80 01 8D E9 10 C0 8D E5 ?? ?? ?? EB 4C 30 9F E5 00 40 93 E5 00 00 54 E3 00 60 A0 E1 02 00 00 1A 00 00 95 E5 ?? ?? ?? EB 00 40 85 E5 14 00 8D E2 01 10 A0 E3 28 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_join_166ccd534b8ca19049c00278864a92f7 {
	meta:
		aliases = "pthread_join"
		size = "484"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { F0 41 2D E9 28 D0 4D E2 00 70 A0 E1 01 80 A0 E1 7E FF FF EB BC 21 9F E5 07 3B A0 E1 23 3B A0 E1 03 52 82 E0 24 00 8D E5 AC 31 9F E5 24 10 9D E5 05 00 A0 E1 20 30 8D E5 1C 50 8D E5 ?? ?? ?? EB 08 40 95 E5 00 00 54 E3 02 00 00 0A 10 30 94 E5 07 00 53 E1 03 00 00 0A 05 00 A0 E1 ?? ?? ?? EB 03 00 A0 E3 59 00 00 EA 24 30 9D E5 03 00 54 E1 03 00 00 1A 05 00 A0 E1 ?? ?? ?? EB 23 00 A0 E3 52 00 00 EA 2D 30 D4 E5 00 00 53 E3 02 00 00 1A 38 30 94 E5 00 00 53 E3 03 00 00 0A 05 00 A0 E1 ?? ?? ?? EB 16 00 A0 E3 48 00 00 EA 2C 30 D4 E5 00 00 53 E3 2B 00 00 1A 24 00 9D E5 1C 10 8D E2 41 FF FF EB 24 30 9D E5 }
	condition:
		$pattern
}

rule __psfs_parse_spec_5ec83c3e6c805ff87eca82f8d6387815 {
	meta:
		aliases = "__psfs_parse_spec"
		size = "644"
		objfiles = "__psfs_parse_spec@libc.a"
	strings:
		$pattern = { F0 41 2D E9 30 80 90 E5 00 30 D8 E5 30 30 43 E2 09 00 53 E3 00 40 A0 83 01 50 A0 83 19 00 00 8A 44 E2 9F E5 00 40 A0 E3 0A C0 A0 E3 0E 00 54 E1 30 20 90 D5 01 30 D2 D4 30 20 80 D5 30 10 90 E5 00 20 D1 E5 30 30 43 D2 9C 34 24 D0 30 30 42 E2 09 00 53 E3 F4 FF FF 9A 24 00 52 E3 06 00 00 0A 24 30 90 E5 00 00 53 E3 01 30 E0 B3 40 40 80 B5 24 30 80 B5 38 00 00 BA 75 00 00 EA 01 30 81 E2 30 30 80 E5 00 50 A0 E3 E0 71 9F E5 10 60 A0 E3 07 10 A0 E1 06 C0 A0 E1 30 E0 90 E5 00 20 D1 E5 00 30 DE E5 03 00 52 E1 05 00 00 1A 45 30 D0 E5 01 20 8E E2 0C 30 83 E1 30 20 80 E5 45 30 C0 E5 F2 FF FF EA 01 20 F1 E5 }
	condition:
		$pattern
}

rule vfprintf_382a3d0c5d8e8ed3d0dbee7f4d3aafbe {
	meta:
		aliases = "__GI_vfprintf, vfprintf"
		size = "188"
		objfiles = "vfprintf@libc.a"
	strings:
		$pattern = { F0 41 2D E9 34 60 90 E5 00 00 56 E3 10 D0 4D E2 00 50 A0 E1 01 70 A0 E1 02 80 A0 E1 0A 00 00 1A 38 40 80 E2 80 30 9F E5 0D 00 A0 E1 7C 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 6C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 D5 E5 C0 30 03 E2 C0 00 53 E3 05 00 00 0A 05 00 A0 E1 80 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 00 40 E0 13 04 00 00 1A 05 00 A0 E1 07 10 A0 E1 08 20 A0 E1 ?? ?? ?? EB 00 40 A0 E1 00 00 56 E3 0D 00 A0 01 01 10 A0 03 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 04 00 A0 E1 10 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule vfwprintf_03fa53d58b564be89d7049ef87d687f6 {
	meta:
		aliases = "__GI_vfwprintf, vfwprintf"
		size = "196"
		objfiles = "vfwprintf@libc.a"
	strings:
		$pattern = { F0 41 2D E9 34 60 90 E5 00 00 56 E3 10 D0 4D E2 00 50 A0 E1 01 70 A0 E1 02 80 A0 E1 0A 00 00 1A 38 40 80 E2 88 30 9F E5 0D 00 A0 E1 84 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 74 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 D5 E5 01 20 D5 E5 02 34 83 E1 21 3D 03 E2 21 0D 53 E3 05 00 00 0A 05 00 A0 E1 02 1B A0 E3 ?? ?? ?? EB 00 00 50 E3 00 40 E0 13 04 00 00 1A 05 00 A0 E1 07 10 A0 E1 08 20 A0 E1 ?? ?? ?? EB 00 40 A0 E1 00 00 56 E3 0D 00 A0 01 01 10 A0 03 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 04 00 A0 E1 10 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fgets_1c22a52eabcbd370417e7f9e11ed3242 {
	meta:
		aliases = "__GI_fgets, fgetws, fgets"
		size = "148"
		objfiles = "fgetws@libc.a, fgets@libc.a"
	strings:
		$pattern = { F0 41 2D E9 34 80 92 E5 00 00 58 E3 10 D0 4D E2 02 50 A0 E1 00 60 A0 E1 01 70 A0 E1 0A 00 00 1A 38 40 82 E2 0D 00 A0 E1 54 30 9F E5 54 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 44 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 06 00 A0 E1 07 10 A0 E1 05 20 A0 E1 ?? ?? ?? EB 00 00 58 E3 00 40 A0 E1 0D 00 A0 01 01 10 A0 03 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 04 00 A0 E1 10 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule vswscanf_d2998cc2ddaf30b840a6e72aafe61628 {
	meta:
		aliases = "__GI_vswscanf, vswscanf"
		size = "136"
		objfiles = "vswscanf@libc.a"
	strings:
		$pattern = { F0 41 2D E9 50 D0 4D E2 10 00 8D E5 08 00 8D E5 00 40 A0 E1 01 70 A0 E1 02 80 A0 E1 ?? ?? ?? EB 02 30 E0 E3 04 30 8D E5 24 30 83 E2 00 30 CD E5 08 30 A0 E3 00 21 84 E0 00 50 A0 E3 38 00 8D E2 01 30 CD E5 01 30 A0 E3 14 20 8D E5 0C 20 8D E5 1C 40 8D E5 34 30 8D E5 18 40 8D E5 02 50 CD E5 2C 50 8D E5 ?? ?? ?? EB 0D 00 A0 E1 07 10 A0 E1 08 20 A0 E1 0D 60 A0 E1 20 50 8D E5 ?? ?? ?? EB 50 D0 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule error_at_line_24ebdbb40ff72b535feeb82c3544dbb1 {
	meta:
		aliases = "__error_at_line, error_at_line"
		size = "404"
		objfiles = "error@libc.a"
	strings:
		$pattern = { F0 41 2D E9 5C C1 9F E5 00 C0 9C E5 00 00 5C E3 04 D0 4D E2 00 80 A0 E1 01 70 A0 E1 02 40 A0 E1 03 50 A0 E1 0E 00 00 0A 3C 61 9F E5 00 30 96 E5 05 00 53 E1 07 00 00 1A 30 31 9F E5 00 00 93 E5 00 00 52 E1 45 00 00 0A 02 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 41 00 00 0A 10 31 9F E5 00 50 86 E5 00 40 83 E5 08 31 9F E5 00 00 93 E5 ?? ?? ?? EB 00 31 9F E5 00 30 93 E5 00 00 53 E3 02 00 00 0A 0F E0 A0 E1 03 F0 A0 E1 05 00 00 EA E8 30 9F E5 00 00 93 E5 E4 30 9F E5 E4 10 9F E5 00 20 93 E5 ?? ?? ?? EB 00 00 54 E3 05 00 00 0A C8 30 9F E5 04 20 A0 E1 00 00 93 E5 C8 10 9F E5 05 30 A0 E1 ?? ?? ?? EB B0 50 9F E5 }
	condition:
		$pattern
}

rule openlog_fe818f4fe7fb34aff197c79a40f70441 {
	meta:
		aliases = "__GI_openlog, openlog"
		size = "132"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { F0 41 2D E9 64 40 9F E5 10 D0 4D E2 00 60 A0 E1 01 70 A0 E1 02 80 A0 E1 54 10 9F E5 04 20 A0 E1 0D 00 A0 E1 4C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 44 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 06 00 A0 E1 07 10 A0 E1 08 20 A0 E1 BF FE FF EB 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0D 50 A0 E1 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule initstate_6c441ea5a4feb2d2f9916b2ea641cf7e {
	meta:
		aliases = "initstate"
		size = "152"
		objfiles = "random@libc.a"
	strings:
		$pattern = { F0 41 2D E9 74 40 9F E5 10 D0 4D E2 00 80 A0 E1 01 50 A0 E1 02 60 A0 E1 64 10 9F E5 04 20 A0 E1 0D 00 A0 E1 5C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 50 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 48 30 9F E5 05 10 A0 E1 06 20 A0 E1 08 00 A0 E1 08 40 93 E5 ?? ?? ?? EB 0D 00 A0 E1 01 10 A0 E3 2C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 40 44 E2 0D 70 A0 E1 04 00 A0 E1 10 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sigqueue_28589769c60c27339c63cdc65ad9b620 {
	meta:
		aliases = "sigqueue"
		size = "128"
		objfiles = "sigqueue@libc.a"
	strings:
		$pattern = { F0 41 2D E9 80 D0 4D E2 01 40 A0 E1 00 70 A0 E1 00 10 A0 E3 02 50 A0 E1 0D 00 A0 E1 80 20 A0 E3 00 80 E0 E3 ?? ?? ?? EB 00 40 8D E5 08 80 8D E5 ?? ?? ?? EB 0C 00 8D E5 ?? ?? ?? EB 0D 60 A0 E1 10 00 8D E5 14 50 8D E5 04 10 A0 E1 07 00 A0 E1 0D 20 A0 E1 B2 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 08 40 A0 E1 04 00 A0 E1 80 D0 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule __GI_strcasestr_5173c64790cccfc78380696e2beb0819 {
	meta:
		aliases = "strcasestr, __GI_strcasestr"
		size = "156"
		objfiles = "strcasestr@libc.a"
	strings:
		$pattern = { F0 41 2D E9 8C 80 9F E5 00 40 A0 E1 01 70 A0 E1 00 50 A0 E1 01 E0 A0 E1 00 30 DE E5 00 00 53 E3 83 60 A0 E1 01 E0 8E E2 01 00 00 1A 04 00 A0 E1 F0 81 BD E8 00 C0 D5 E5 0C 00 53 E1 8C 00 A0 E1 01 50 85 E2 F3 FF FF 0A 00 30 98 E5 03 10 80 E0 03 20 86 E0 01 20 D2 E5 01 10 D1 E5 03 00 D0 E7 03 30 D6 E7 02 2C A0 E1 01 1C A0 E1 42 38 83 E1 41 08 80 E1 00 00 53 E1 E6 FF FF 0A 01 40 84 E2 00 00 5C E3 04 50 A0 E1 07 E0 A0 E1 E1 FF FF 1A 0C 00 A0 E1 F0 81 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule nextafterf_8f2165c0236bc5429ab30dd798895d96 {
	meta:
		aliases = "nextafterf"
		size = "212"
		objfiles = "s_nextafterf@libm.a"
	strings:
		$pattern = { F0 41 2D E9 C4 20 9F E5 02 71 C0 E3 02 31 C1 E3 00 80 A0 E1 02 00 53 E1 02 00 57 D1 01 50 A0 E1 00 40 A0 E1 01 60 A0 E1 01 00 A0 C1 04 D0 4D E2 08 10 A0 C1 18 00 00 CA ?? ?? ?? EB 00 00 50 E3 1F 00 00 0A 00 00 57 E3 02 31 05 02 01 50 83 03 1B 00 00 0A 00 00 58 E3 02 00 00 BA 06 00 58 E1 03 00 00 CA 04 00 00 EA 06 00 58 E1 00 00 56 D3 01 00 00 BA 01 40 44 E2 00 00 00 EA 01 40 84 E2 48 20 9F E5 44 30 9F E5 02 20 04 E0 03 00 52 E1 04 00 00 1A 08 00 A0 E1 08 10 A0 E1 ?? ?? ?? EB 00 50 A0 E1 06 00 00 EA 02 05 52 E3 03 00 00 AA 08 00 A0 E1 08 10 A0 E1 ?? ?? ?? EB 00 00 8D E5 04 50 A0 E1 05 00 A0 E1 }
	condition:
		$pattern
}

rule __pthread_alt_unlock_2b4b69974e47779f978d45bfcd7da93f {
	meta:
		aliases = "__pthread_alt_unlock"
		size = "192"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { F0 45 2D E9 00 40 A0 E1 04 00 80 E2 3F FF FF EB 02 A1 A0 E3 00 00 94 E5 01 00 50 E3 00 30 A0 93 00 30 84 95 22 00 00 9A 04 50 A0 E1 00 70 A0 E1 04 80 A0 E1 0A 60 A0 E1 11 00 00 EA 08 30 90 E5 00 00 53 E3 06 00 00 0A 00 30 90 E5 00 30 85 E5 48 FF FF EB 04 00 55 E1 00 00 95 E5 08 00 00 1A 07 00 00 EA 04 30 90 E5 18 30 93 E5 06 00 53 E1 05 80 A0 A1 00 70 A0 A1 00 50 A0 E1 00 00 90 E5 03 60 A0 A1 01 00 50 E3 EB FF FF 1A 02 01 56 E3 DF FF FF 0A 08 30 87 E2 90 00 03 E1 00 00 50 E3 DB FF FF 1A 00 30 97 E5 04 00 97 E5 00 30 88 E5 ?? ?? ?? EB 00 30 A0 E3 04 30 84 E5 F0 85 BD E8 }
	condition:
		$pattern
}

rule regexec_60852ddf7844e8b9db3412f69df7b0d5 {
	meta:
		aliases = "__GI_regexec, regexec"
		size = "312"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { F0 45 2D E9 00 40 A0 E1 34 D0 4D E2 01 00 A0 E1 02 60 A0 E1 01 80 A0 E1 03 A0 A0 E1 ?? ?? ?? EB 1C 30 D4 E5 23 32 A0 E1 01 30 23 E2 04 10 A0 E1 20 20 A0 E3 00 70 A0 E1 08 00 8D E2 00 00 56 E3 00 50 A0 03 01 50 03 12 50 40 9D E5 ?? ?? ?? EB 24 30 DD E5 01 20 04 E2 20 30 C3 E3 82 32 83 E1 24 30 CD E5 24 30 DD E5 84 42 A0 E1 40 30 C3 E3 40 40 04 E2 03 40 84 E1 24 40 CD E5 24 30 DD E5 02 30 C3 E3 04 30 83 E3 00 00 55 E3 24 30 CD E5 05 C0 A0 01 09 00 00 0A 86 01 A0 E1 28 60 8D E5 ?? ?? ?? EB 00 00 50 E3 01 00 A0 03 1F 00 00 0A 06 31 80 E0 30 30 8D E5 2C 00 8D E5 28 C0 8D E2 08 10 A0 E1 07 20 A0 E1 }
	condition:
		$pattern
}

rule svc_getreqset_a00d7b48bcb4925aff59cf55eab0eead {
	meta:
		aliases = "__GI_svc_getreqset, svc_getreqset"
		size = "92"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { F0 45 2D E9 00 40 A0 E1 ?? ?? ?? EB 04 60 A0 E1 00 80 A0 E1 00 70 A0 E3 01 A0 A0 E3 0B 00 00 EA 00 40 96 E5 01 00 00 EA ?? ?? ?? EB 1A 45 24 E0 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 01 50 40 E2 07 00 85 E0 F7 FF FF 1A 04 60 86 E2 20 70 87 E2 08 00 57 E1 F1 FF FF BA F0 85 BD E8 }
	condition:
		$pattern
}

rule readtcp_167957eec8c52f41bf0831e2a61d0bd5 {
	meta:
		aliases = "readtcp"
		size = "260"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { F0 45 2D E9 00 50 A0 E1 08 D0 4D E2 01 A0 A0 E1 0C 00 90 E5 FA 1F A0 E3 02 60 A0 E1 ?? ?? ?? EB 08 20 95 E5 00 00 56 E3 FA 3F A0 E3 92 03 27 E0 06 40 A0 01 2F 00 00 0A 00 30 95 E5 00 30 8D E5 01 30 A0 E3 04 30 CD E5 00 30 A0 E3 05 30 CD E5 0D 80 A0 E1 01 10 A0 E3 07 20 A0 E1 0D 00 A0 E1 ?? ?? ?? EB 01 00 70 E3 00 40 A0 E1 05 00 00 0A 00 00 50 E3 05 30 A0 03 00 40 E0 03 24 30 85 05 1C 00 00 0A 07 00 00 EA ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 EE FF FF 0A 04 30 A0 E3 24 30 85 E5 00 30 90 E5 0C 00 00 EA 0A 10 A0 E1 06 20 A0 E1 00 00 95 E5 ?? ?? ?? EB 01 00 70 E3 00 40 A0 E1 07 00 00 0A 00 00 50 E3 }
	condition:
		$pattern
}

rule readunix_485e7613d606daa5d6633a20ca74f0f4 {
	meta:
		aliases = "readunix"
		size = "420"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { F0 45 2D E9 00 50 A0 E1 4C D0 4D E2 01 A0 A0 E1 0C 00 90 E5 FA 1F A0 E3 02 60 A0 E1 ?? ?? ?? EB 08 20 95 E5 00 00 56 E3 FA 3F A0 E3 92 03 27 E0 06 40 A0 01 57 00 00 0A 00 30 95 E5 40 30 8D E5 01 30 A0 E3 44 30 CD E5 00 30 A0 E3 45 30 CD E5 40 80 8D E2 01 10 A0 E3 07 20 A0 E1 08 00 A0 E1 ?? ?? ?? EB 01 00 70 E3 00 40 A0 E1 05 00 00 0A 00 00 50 E3 05 30 A0 03 00 40 E0 03 84 30 85 05 44 00 00 0A 07 00 00 EA ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 EE FF FF 0A 04 30 A0 E3 84 30 85 E5 00 30 90 E5 34 00 00 EA 01 40 A0 E3 4C 30 8D E2 04 40 23 E5 38 C0 8D E2 00 70 95 E5 0C C0 8D E5 20 C0 8D E2 14 C0 8D E5 }
	condition:
		$pattern
}

rule parse_printf_format_aa52c1316c30563a6bc30adf36d78ce0 {
	meta:
		aliases = "parse_printf_format"
		size = "312"
		objfiles = "parse_printf_format@libc.a"
	strings:
		$pattern = { F0 45 2D E9 00 50 A0 E1 98 D0 4D E2 01 40 A0 E1 0D 00 A0 E1 05 10 A0 E1 02 60 A0 E1 ?? ?? ?? EB 00 00 50 E3 0D 80 A0 E1 00 70 A0 B3 3E 00 00 BA 18 00 9D E5 00 00 50 E3 00 70 A0 D3 0D A0 A0 D1 07 80 A0 D1 35 00 00 DA 00 70 A0 E1 00 00 54 E1 04 10 A0 31 00 10 A0 21 00 20 A0 E3 01 00 00 EA 70 30 13 E5 04 30 86 E4 98 00 8D E2 01 00 52 E1 02 31 80 E0 01 20 82 E2 F8 FF FF 3A 2A 00 00 EA 25 00 53 E3 24 00 00 1A 01 30 F5 E5 25 00 53 E3 21 00 00 0A 0D 00 A0 E1 00 50 8D E5 ?? ?? ?? EB 08 30 9D E5 02 01 53 E3 00 50 9D E5 03 00 00 1A 00 00 54 E3 04 80 86 14 01 70 87 E2 01 40 44 12 04 30 9D E5 02 01 53 E3 }
	condition:
		$pattern
}

rule __pthread_acquire_14a2e7d7af90a05fd32019dbebdb7e64 {
	meta:
		aliases = "__pthread_acquire"
		size = "104"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { F0 45 2D E9 00 60 A0 E1 08 D0 4D E2 00 40 A0 E3 4C A0 9F E5 01 70 A0 E3 04 50 A0 E1 0D 80 A0 E1 07 00 00 EA 31 00 54 E3 01 40 84 E2 01 00 00 CA ?? ?? ?? EB 02 00 00 EA 20 04 8D E8 ?? ?? ?? EB 05 40 A0 E1 07 30 A0 E1 93 30 06 E1 00 00 53 E3 0D 00 A0 E1 05 10 A0 E1 F1 FF FF 1A 08 D0 8D E2 F0 85 BD E8 81 84 1E 00 }
	condition:
		$pattern
}

rule authunix_validate_180b18c47fb15d25efc00334738abf0d {
	meta:
		aliases = "authunix_validate"
		size = "152"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { F0 45 2D E9 00 A0 91 E5 02 00 5A E3 18 D0 4D E2 00 60 A0 E1 1C 00 00 1A 24 50 90 E5 08 20 91 E5 0D 00 A0 E1 04 10 91 E5 01 30 A0 E3 ?? ?? ?? EB 10 00 95 E5 00 00 50 E3 0D 80 A0 E1 02 00 00 0A ?? ?? ?? EB 00 30 A0 E3 10 30 85 E5 0C 40 85 E2 0D 00 A0 E1 04 10 A0 E1 ?? ?? ?? EB 00 70 50 E2 07 00 94 18 05 00 00 1A 04 10 A0 E1 0D 00 A0 E1 00 A0 8D E5 ?? ?? ?? EB 07 00 95 E8 10 70 85 E5 07 00 86 E8 06 00 A0 E1 7A FF FF EB 01 00 A0 E3 18 D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule dladdr_bcfc52a4643d64320a39fbc76ad3a3c6 {
	meta:
		aliases = "dladdr"
		size = "280"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { F0 45 2D E9 00 A0 A0 E1 01 40 A0 E1 ?? ?? ?? EB FC 30 9F E5 00 20 93 E5 00 00 A0 E3 09 00 00 EA 14 10 92 E5 0A 00 51 E1 05 00 00 2A 00 00 50 E3 02 00 00 0A 14 30 90 E5 01 00 53 E1 00 00 00 2A 02 00 A0 E1 0C 20 92 E5 00 00 52 E3 F3 FF FF 1A 00 00 50 E3 F0 85 BD 08 02 50 A0 E1 04 30 90 E5 14 20 90 E5 58 70 90 E5 54 80 90 E5 05 C0 A0 E1 05 E0 A0 E1 05 60 A0 E1 00 30 84 E5 04 20 84 E5 16 00 00 EA 2C 30 90 E5 0E 11 93 E7 0F 00 00 EA 04 20 93 E5 00 30 90 E5 03 20 82 E0 0A 00 52 E1 08 00 00 8A 02 00 56 E1 00 30 A0 23 01 30 A0 33 00 00 5C E3 01 30 83 03 00 00 53 E3 02 60 A0 11 01 C0 A0 13 01 50 A0 11 }
	condition:
		$pattern
}

rule makefd_xprt_ccd20259474b62e005fccb33c80b7a90 {
	meta:
		aliases = "makefd_xprt"
		size = "228"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { F0 45 2D E9 00 A0 A0 E1 08 D0 4D E2 4D 0F A0 E3 01 70 A0 E1 02 80 A0 E1 ?? ?? ?? EB 00 40 A0 E1 1B 0E A0 E3 ?? ?? ?? EB 00 00 50 E3 00 00 54 13 00 50 A0 E1 00 60 A0 13 01 60 A0 03 09 00 00 1A 88 30 9F E5 88 00 9F E5 00 10 93 E5 ?? ?? ?? EB 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 ?? ?? ?? EB 00 40 A0 E3 16 00 00 EA 68 C0 9F E5 02 30 A0 E3 00 30 80 E5 00 C0 8D E5 5C C0 9F E5 08 00 80 E2 04 30 A0 E1 07 10 A0 E1 08 20 A0 E1 04 C0 8D E5 ?? ?? ?? EB 20 30 85 E2 24 30 84 E5 3C 30 9F E5 05 60 C4 E5 08 30 84 E5 00 A0 84 E5 30 60 84 E5 2C 50 84 E5 0C 60 84 E5 04 60 C4 E5 04 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 }
	condition:
		$pattern
}

rule svc_run_28048b56e6df2de7fdb45015f8a83376 {
	meta:
		aliases = "svc_run"
		size = "240"
		objfiles = "svc_run@libc.a"
	strings:
		$pattern = { F0 45 2D E9 00 A0 A0 E3 ?? ?? ?? EB 00 40 90 E5 00 00 54 E3 00 80 A0 E1 03 00 00 1A ?? ?? ?? EB 00 30 90 E5 00 00 53 E3 F0 85 BD 08 84 01 A0 E1 ?? ?? ?? EB 0A 70 A0 E1 00 50 A0 E1 0D 00 00 EA ?? ?? ?? EB 00 30 90 E5 04 30 93 E7 04 30 85 E7 00 30 90 E5 04 30 83 E0 05 20 D3 E5 04 30 D3 E5 02 34 83 E1 43 24 A0 E1 05 20 C6 E5 07 A0 C6 E5 04 30 C6 E5 06 A0 C6 E5 00 10 98 E5 87 41 A0 E1 01 00 57 E1 04 60 85 E0 01 70 87 E2 EB FF FF BA 05 00 A0 E1 00 20 E0 E3 ?? ?? ?? EB 01 00 70 E3 02 00 00 0A 00 00 50 E3 0C 00 00 0A 08 00 00 EA 05 00 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 CF FF FF 0A }
	condition:
		$pattern
}

rule __GI_tcsetattr_e11e9c1c2c89f9fb2b0d6817f9d6e3d1 {
	meta:
		aliases = "tcsetattr, __GI_tcsetattr"
		size = "300"
		objfiles = "tcsetattr@libc.a"
	strings:
		$pattern = { F0 45 2D E9 01 00 51 E3 24 D0 4D E2 00 A0 A0 E1 02 60 A0 E1 05 00 00 0A 02 00 51 E3 0A 00 00 0A 00 00 51 E3 F0 80 9F 05 08 00 00 0A 01 00 00 EA E8 80 9F E5 05 00 00 EA ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 30 00 00 EA D0 80 9F E5 08 50 96 E8 0C 40 96 E5 10 50 D6 E5 02 31 C3 E3 11 10 86 E2 13 20 A0 E3 11 00 8D E2 08 50 8D E8 0C 40 8D E5 10 50 CD E5 ?? ?? ?? EB 0D 20 A0 E1 0A 00 A0 E1 08 10 A0 E1 ?? ?? ?? EB 88 30 9F E5 00 00 50 E3 03 00 58 01 0D 70 A0 E1 00 20 A0 E1 1A 00 00 1A ?? ?? ?? EB 0D 20 A0 E1 00 40 A0 E1 70 10 9F E5 0A 00 A0 E1 00 50 94 E5 ?? ?? ?? EB 00 00 50 E3 00 20 A0 13 }
	condition:
		$pattern
}

rule svc_register_33d9e72e67fda01996018d82114b18c1 {
	meta:
		aliases = "__GI_svc_register, svc_register"
		size = "164"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { F0 45 2D E9 01 60 A0 E1 04 D0 4D E2 02 10 A0 E1 02 70 A0 E1 00 80 A0 E1 0D 20 A0 E1 06 00 A0 E1 03 50 A0 E1 20 A0 9D E5 2D FF FF EB 00 00 50 E3 03 00 00 0A 0C 30 90 E5 05 00 53 E1 15 00 00 1A 09 00 00 EA 10 00 A0 E3 ?? ?? ?? EB 00 40 50 E2 10 00 00 0A 0C 50 84 E5 C0 00 84 E9 ?? ?? ?? EB B8 30 90 E5 00 30 84 E5 B8 40 80 E5 00 00 5A E3 01 00 A0 03 08 00 00 0A 05 20 D8 E5 04 30 D8 E5 06 00 A0 E1 02 34 83 E1 07 10 A0 E1 0A 20 A0 E1 ?? ?? ?? EB 00 00 00 EA 00 00 A0 E3 04 D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule vsnprintf_d05124eb9617d85201ae4438ff34197d {
	meta:
		aliases = "__GI_vsnprintf, vsnprintf"
		size = "180"
		objfiles = "vsnprintf@libc.a"
	strings:
		$pattern = { F0 45 2D E9 01 C0 E0 E3 50 D0 4D E2 04 C0 8D E5 D2 C0 8C E2 00 40 A0 E1 00 A0 A0 E3 38 00 8D E2 00 C0 CD E5 01 C0 A0 E3 01 50 A0 E1 02 60 A0 E1 03 70 A0 E1 34 C0 8D E5 01 A0 CD E5 02 A0 CD E5 2C A0 8D E5 ?? ?? ?? EB 04 30 E0 E1 03 00 55 E1 03 50 A0 21 05 30 84 E0 0D 00 A0 E1 06 10 A0 E1 07 20 A0 E1 18 40 8D E5 1C 30 8D E5 20 A0 8D E5 08 40 8D E5 0C 30 8D E5 10 40 8D E5 14 40 8D E5 ?? ?? ?? EB 0A 00 55 E1 0D 80 A0 E1 06 00 00 0A 0C 30 9D E5 10 20 9D E5 03 00 52 E1 01 30 42 02 10 30 8D 05 10 30 9D E5 00 A0 C3 E5 50 D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule __GI_fread_unlocked_4134e071cdeaef0607b563407762baa3 {
	meta:
		aliases = "fread_unlocked, __GI_fread_unlocked"
		size = "380"
		objfiles = "fread_unlocked@libc.a"
	strings:
		$pattern = { F0 45 2D E9 03 50 A0 E1 00 30 D3 E5 83 30 03 E2 80 00 53 E3 00 60 A0 E1 01 80 A0 E1 02 40 A0 E1 04 00 00 8A 05 00 A0 E1 80 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 4C 00 00 1A 00 00 58 E3 00 00 54 13 49 00 00 0A 00 00 E0 E3 08 10 A0 E1 ?? ?? ?? EB 00 00 54 E1 3A 00 00 8A 98 04 0A E0 06 70 A0 E1 00 C0 A0 E3 0A 60 A0 E1 07 00 00 EA 24 30 92 E5 01 60 56 E2 00 30 C7 E5 01 00 C5 E5 00 10 C5 E5 28 C0 85 E5 29 00 00 0A 01 70 87 E2 01 20 D5 E5 00 30 D5 E5 02 34 83 E1 01 20 03 E2 01 10 43 E2 02 00 13 E3 02 21 85 E0 41 04 A0 E1 EE FF FF 1A 10 10 85 E2 0A 00 91 E8 01 20 53 E0 0B 00 00 0A 02 00 56 E1 06 40 A0 31 }
	condition:
		$pattern
}

rule frame_heapsort_9dd76872770caccc4d91bee2209d32eb {
	meta:
		aliases = "frame_heapsort"
		size = "156"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { F0 45 2D E9 04 50 92 E5 A5 30 A0 E1 01 40 53 E2 04 D0 4D E2 02 60 A0 E1 00 A0 A0 E1 01 80 A0 E1 08 70 82 E2 07 00 00 4A 04 30 A0 E1 0A 00 A0 E1 08 10 A0 E1 07 20 A0 E1 00 50 8D E5 C0 FF FF EB 01 40 54 E2 F7 FF FF 5A 01 40 45 E2 00 00 54 E3 0F 00 00 DA 05 31 A0 E1 08 30 83 E2 03 50 86 E0 04 30 15 E5 08 20 96 E5 0A 00 A0 E1 08 30 86 E5 08 10 A0 E1 04 20 25 E5 00 30 A0 E3 00 40 8D E5 07 20 A0 E1 01 40 44 E2 AD FF FF EB 00 00 54 E3 F2 FF FF CA 04 D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule sem_timedwait_cf2759362c928022d387311131e624c0 {
	meta:
		aliases = "sem_timedwait"
		size = "436"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { F0 45 2D E9 08 D0 4D E2 00 60 A0 E1 01 A0 A0 E1 C8 FF FF EB 00 50 A0 E1 05 10 A0 E1 06 00 A0 E1 ?? ?? ?? EB 08 30 96 E5 00 00 53 E3 04 00 00 DA 01 30 43 E2 08 30 86 E5 06 00 A0 E1 ?? ?? ?? EB 55 00 00 EA 04 20 9A E5 5C 31 9F E5 03 00 52 E1 05 00 00 9A 06 00 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 00 20 E0 E3 16 30 A0 E3 31 00 00 EA 3C 31 9F E5 04 30 8D E5 00 30 A0 E3 00 60 8D E5 05 00 A0 E1 42 31 C5 E5 0D 10 A0 E1 53 FF FF EB 42 30 D5 E5 00 00 53 E3 03 00 00 0A 40 30 D5 E5 00 00 53 E3 01 40 A0 03 03 00 00 0A 0C 00 86 E2 05 10 A0 E1 29 FF FF EB 00 40 A0 E3 06 00 A0 E1 ?? ?? ?? EB 00 00 54 E3 0C 80 86 02 }
	condition:
		$pattern
}

rule _Unwind_ForcedUnwind_Phase2_5bccabaf94d9725722e9853b09a72388 {
	meta:
		aliases = "_Unwind_ForcedUnwind_Phase2"
		size = "200"
		objfiles = "unwind_sjlj@libgcc_eh.a"
	strings:
		$pattern = { F0 45 2D E9 0C A0 90 E5 10 D0 4D E2 10 70 90 E5 00 60 A0 E1 01 50 A0 E1 0C 80 8D E2 1D 00 00 EA 05 00 54 E3 0C 00 96 E8 0A 10 A0 13 1A 10 A0 03 00 60 8D E5 A0 00 8D E9 0F E0 A0 E1 0A F0 A0 E1 00 00 50 E3 0A 10 A0 E3 01 00 A0 E3 19 00 00 1A 05 00 54 E3 18 00 00 0A 0C C0 9D E5 00 00 5C E3 09 00 00 0A 0C 00 96 E8 00 60 8D E5 04 50 8D E5 0F E0 A0 E1 0C F0 A0 E1 07 00 50 E3 00 40 A0 E1 0D 00 00 0A 08 00 50 E3 0A 00 00 1A 05 00 A0 E1 08 10 A0 E1 C9 FF FF EB 08 10 A0 E1 05 00 A0 E1 B9 FF FF EB 00 00 50 E3 05 00 50 13 00 40 A0 E1 01 00 A0 E3 D9 FF FF 0A 02 40 A0 E3 04 00 A0 E1 10 D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule scan_getwc_699829f97bf24b597d94f4c6fa9a032e {
	meta:
		aliases = "scan_getwc"
		size = "200"
		objfiles = "vfscanf@libc.a"
	strings:
		$pattern = { F0 45 2D E9 10 30 90 E5 01 50 43 E2 00 00 55 E3 08 D0 4D E2 00 40 A0 E1 10 50 80 E5 19 30 D0 B5 00 00 E0 B3 02 30 83 B3 19 30 C4 B5 23 00 00 BA 02 31 E0 E3 02 60 E0 E3 0D A0 A0 E1 07 80 8D E2 1C 70 80 E2 10 30 80 E5 07 00 00 EA 00 C0 94 E5 07 C0 CD E5 ?? ?? ?? EB 00 60 50 E2 00 30 9D A5 0D 00 00 AA 02 00 76 E3 07 00 00 1A 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 08 10 A0 E1 01 20 A0 E3 07 30 A0 E1 0D 00 A0 E1 EF FF FF AA 03 00 76 E3 03 00 00 1A 00 30 E0 E3 03 60 A0 E1 24 30 84 E5 04 00 00 EA ?? ?? ?? EB 54 30 A0 E3 00 30 80 E5 01 30 A0 E3 1B 30 C4 E5 10 50 84 E5 06 00 A0 E1 08 D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule getprotobynumber_r_1980fe30e38d3196c4e02682cb035a4b {
	meta:
		aliases = "__GI_getprotobynumber_r, getprotobynumber_r"
		size = "208"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { F0 45 2D E9 10 D0 4D E2 00 80 A0 E1 01 50 A0 E1 0D 00 A0 E1 9C 10 9F E5 02 70 A0 E1 03 60 A0 E1 94 20 9F E5 94 30 9F E5 2C A0 9D E5 0F E0 A0 E1 03 F0 A0 E1 88 30 9F E5 7C 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 7C 30 9F E5 00 00 93 E5 ?? ?? ?? EB 02 00 00 EA 08 30 95 E5 08 00 53 E1 06 00 00 0A 05 00 A0 E1 07 10 A0 E1 06 20 A0 E1 0A 30 A0 E1 ?? ?? ?? EB 00 40 50 E2 F5 FF FF 0A 44 30 9F E5 00 30 93 E5 00 00 53 E3 ?? ?? ?? 0B 0D 00 A0 E1 01 10 A0 E3 30 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 9A E5 00 00 50 E3 04 00 A0 01 00 00 A0 13 10 D0 8D E2 F0 85 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pselect_f42bf01eba5b0eac1bd821c10f71a120 {
	meta:
		aliases = "__libc_pselect, pselect"
		size = "156"
		objfiles = "pselect@libc.a"
	strings:
		$pattern = { F0 45 2D E9 14 D0 4D E2 30 40 9D E5 00 00 54 E3 00 60 A0 E1 01 70 A0 E1 02 80 A0 E1 03 A0 A0 E1 34 50 9D E5 05 00 00 0A 00 30 94 E5 04 00 94 E5 FA 1F A0 E3 0C 30 8D E5 ?? ?? ?? EB 10 00 8D E5 00 00 55 E3 02 00 A0 13 05 10 A0 11 04 20 8D 12 ?? ?? ?? 1B 00 00 54 E3 04 C0 A0 01 0C C0 8D 12 06 00 A0 E1 07 10 A0 E1 08 20 A0 E1 0A 30 A0 E1 00 C0 8D E5 ?? ?? ?? EB 00 00 55 E3 00 40 A0 E1 02 00 A0 13 04 10 8D 12 00 20 A0 13 ?? ?? ?? 1B 04 00 A0 E1 14 D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule _svcauth_unix_a4a40266215e9eb6d536fbd4c9a7b577 {
	meta:
		aliases = "_svcauth_unix"
		size = "560"
		objfiles = "svc_authux@libc.a"
	strings:
		$pattern = { F0 45 2D E9 18 60 90 E5 18 30 86 E2 46 2F 86 E2 04 30 86 E5 14 20 86 E5 20 80 91 E5 18 D0 4D E2 08 20 A0 E1 01 30 A0 E3 00 A0 A0 E1 01 70 A0 E1 0D 00 A0 E1 1C 10 91 E5 ?? ?? ?? EB 0D 00 A0 E1 08 10 A0 E1 04 30 9D E5 0F E0 A0 E1 18 F0 93 E5 00 00 50 E3 50 00 00 0A 00 40 A0 E1 04 10 94 E4 FF 28 01 E2 21 3C A0 E1 22 34 83 E1 FF 2C 01 E2 02 34 83 E1 01 3C 83 E1 00 30 86 E5 04 10 90 E5 FF 28 01 E2 21 3C A0 E1 22 34 83 E1 FF 2C 01 E2 02 34 83 E1 01 5C 83 E1 FF 00 55 E3 58 00 00 8A 04 40 84 E2 04 10 A0 E1 05 20 A0 E1 04 00 96 E5 ?? ?? ?? EB 04 30 96 E5 00 E0 A0 E3 05 E0 C3 E7 03 30 85 E2 03 00 C3 E3 }
	condition:
		$pattern
}

rule xdr_vector_079369b9164eef4a8f0ac9097fe4f29a {
	meta:
		aliases = "xdr_vector"
		size = "84"
		objfiles = "xdr_array@libc.a"
	strings:
		$pattern = { F0 45 2D E9 1C A0 9D E5 00 80 A0 E1 02 70 A0 E1 03 60 A0 E1 01 40 A0 E1 00 50 A0 E3 03 00 00 EA 0F E0 A0 E1 0A F0 A0 E1 00 00 50 E3 F0 85 BD 08 07 00 55 E1 04 10 A0 E1 08 00 A0 E1 00 20 E0 E3 06 40 84 E0 01 50 85 E2 F4 FF FF 3A 01 00 A0 E3 F0 85 BD E8 }
	condition:
		$pattern
}

rule exchange_6747a7d0530177a5f106af72818d8aef {
	meta:
		aliases = "exchange"
		size = "200"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { F0 45 2D E9 20 70 81 E2 80 01 97 E8 00 60 91 E5 01 C0 A0 E1 00 A0 A0 E3 1F 00 00 EA 06 40 68 E0 08 E0 67 E0 0E 00 54 E1 0A 10 A0 D1 06 60 6E C0 0A 10 A0 C1 04 00 00 CA 0F 00 00 EA 05 20 90 E7 04 30 90 E7 05 30 80 E7 04 20 80 E7 07 30 81 E0 03 51 A0 E1 0E 00 51 E1 01 30 86 E0 03 41 A0 E1 01 10 81 E2 F4 FF FF BA 0B 00 00 EA 0E 20 90 E7 05 30 90 E7 0E 30 80 E7 05 20 80 E7 07 30 81 E0 08 20 81 E0 04 00 51 E1 03 E1 A0 E1 02 51 A0 E1 01 10 81 E2 F4 FF FF BA 04 70 87 E0 08 00 56 E1 07 00 58 C1 DC FF FF CA 00 30 9C E5 20 20 9C E5 24 10 9C E5 02 20 83 E0 02 20 61 E0 24 30 8C E5 20 20 8C E5 F0 85 BD E8 }
	condition:
		$pattern
}

rule svcudp_reply_5be730a357d8bd390f8cdd2523d642b6 {
	meta:
		aliases = "svcudp_reply"
		size = "612"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { F0 45 2D E9 30 70 90 E5 00 A0 A0 E3 08 50 87 E2 01 40 A0 E1 08 D0 4D E2 0A 10 A0 E1 0C 30 97 E5 00 60 A0 E1 08 A0 87 E5 05 00 A0 E1 0F E0 A0 E1 14 F0 93 E5 04 30 97 E5 04 10 A0 E1 00 30 84 E5 05 00 A0 E1 ?? ?? ?? EB 0A 00 50 E1 7B 00 00 0A 0C 30 97 E5 05 00 A0 E1 0F E0 A0 E1 10 F0 93 E5 3C 20 86 E2 0C 30 92 E5 0A 00 53 E1 00 80 A0 E1 2C 10 96 E5 06 00 00 0A 34 10 86 E5 38 00 86 E5 02 10 A0 E1 00 00 96 E5 0A 20 A0 E1 ?? ?? ?? EB 05 00 00 EA 0C E0 96 E5 00 00 96 E5 10 C0 86 E2 08 20 A0 E1 00 50 8D E8 ?? ?? ?? EB 08 00 50 E1 62 00 00 1A B0 31 97 E5 00 30 53 E2 01 30 A0 13 00 00 58 E3 00 30 A0 B3 }
	condition:
		$pattern
}

rule svcudp_enablecache_82b9957d9d50e694f81a38e5d021898b {
	meta:
		aliases = "svcudp_enablecache"
		size = "264"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { F0 45 2D E9 30 A0 90 E5 B0 71 9A E5 00 00 57 E3 01 50 A0 E1 06 00 00 0A D0 30 9F E5 D0 10 9F E5 00 00 93 E5 CC 20 9F E5 ?? ?? ?? EB 00 00 A0 E3 F0 85 BD E8 2C 00 A0 E3 ?? ?? ?? EB 00 60 50 E2 06 00 00 1A A4 30 9F E5 A4 10 9F E5 00 00 93 E5 A4 20 9F E5 ?? ?? ?? EB 06 00 A0 E1 F0 85 BD E8 05 82 A0 E1 00 50 86 E5 0C 70 86 E5 08 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 40 A0 E1 04 00 86 E5 68 30 9F 05 68 10 9F 05 00 00 93 05 6C 20 9F 05 0D 00 00 0A 08 20 A0 E1 07 10 A0 E1 05 51 A0 E1 ?? ?? ?? EB 05 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 40 A0 E1 08 00 86 E5 06 00 00 1A 2C 30 9F E5 2C 10 9F E5 00 00 93 E5 }
	condition:
		$pattern
}

rule clntraw_create_255c8df344e60bf107e5b85a7d98bb35 {
	meta:
		aliases = "clntraw_create"
		size = "260"
		objfiles = "clnt_raw@libc.a"
	strings:
		$pattern = { F0 45 2D E9 30 D0 4D E2 00 70 A0 E1 01 80 A0 E1 ?? ?? ?? EB A0 40 90 E5 00 00 54 E3 00 50 A0 E1 04 60 A0 11 06 00 00 1A 01 00 A0 E3 BC 10 9F E5 ?? ?? ?? EB 00 00 50 E3 29 00 00 0A A0 00 85 E5 00 60 A0 E1 00 C0 A0 E3 0C 50 84 E2 8A 1D 86 E2 04 10 81 E2 0C 30 A0 E1 18 20 A0 E3 05 00 A0 E1 02 A0 A0 E3 04 C0 8D E5 0C 70 8D E5 10 80 8D E5 08 A0 8D E5 ?? ?? ?? EB 05 00 A0 E1 0D 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 64 00 9F 05 ?? ?? ?? 0B 10 30 94 E5 05 00 A0 E1 0F E0 A0 E1 10 F0 93 E5 50 30 9F E5 03 00 86 E7 10 30 94 E5 1C 30 93 E5 00 00 53 E3 05 00 A0 11 0F E0 A0 11 03 F0 A0 11 05 00 A0 E1 24 10 86 E2 }
	condition:
		$pattern
}

rule setvbuf_5bf8f74cfa9ec6130345f08fead3cc1f {
	meta:
		aliases = "__GI_setvbuf, setvbuf"
		size = "408"
		objfiles = "setvbuf@libc.a"
	strings:
		$pattern = { F0 45 2D E9 34 A0 90 E5 00 00 5A E3 10 D0 4D E2 00 50 A0 E1 01 60 A0 E1 02 70 A0 E1 03 80 A0 E1 0A 00 00 1A 38 40 80 E2 54 31 9F E5 0D 00 A0 E1 50 11 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 40 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 02 00 57 E3 04 00 00 9A ?? ?? ?? EB 00 40 E0 E3 16 30 A0 E3 00 30 80 E5 3C 00 00 EA 00 20 D5 E5 01 30 D5 E5 14 11 9F E5 03 34 82 E1 01 10 03 E0 00 00 51 E3 00 40 E0 13 34 00 00 1A 03 3C C3 E3 00 00 58 E3 02 00 57 13 07 34 83 E1 01 60 A0 01 43 24 A0 E1 00 00 A0 13 01 00 A0 03 01 20 C5 E5 00 30 C5 E5 06 80 A0 01 06 40 A0 01 0D 00 00 0A 00 00 56 E3 00 40 A0 11 }
	condition:
		$pattern
}

rule fwrite_510fa6aabf0cdb63b100e153964ea7c0 {
	meta:
		aliases = "__GI_fwrite, __GI_fread, fread, fwrite"
		size = "156"
		objfiles = "fread@libc.a, fwrite@libc.a"
	strings:
		$pattern = { F0 45 2D E9 34 A0 93 E5 00 00 5A E3 10 D0 4D E2 03 50 A0 E1 00 60 A0 E1 01 70 A0 E1 02 80 A0 E1 0A 00 00 1A 38 40 83 E2 0D 00 A0 E1 58 30 9F E5 58 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 48 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 06 00 A0 E1 07 10 A0 E1 08 20 A0 E1 05 30 A0 E1 ?? ?? ?? EB 00 00 5A E3 00 40 A0 E1 0D 00 A0 01 01 10 A0 03 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 04 00 A0 E1 10 D0 8D E2 F0 85 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pmap_set_178eaf08229019da2744e39917154e13 {
	meta:
		aliases = "__GI_pmap_set, pmap_set"
		size = "272"
		objfiles = "pmap_clnt@libc.a"
	strings:
		$pattern = { F0 45 2D E9 38 D0 4D E2 20 50 8D E2 03 38 A0 E1 00 C0 E0 E3 00 A0 A0 E1 05 00 A0 E1 34 C0 8D E5 01 60 A0 E1 02 70 A0 E1 23 88 A0 E1 5E FF FF EB 00 00 50 E3 2C 00 00 0A B8 30 9F E5 04 40 93 E5 19 EE A0 E3 34 C0 8D E2 00 30 93 E5 05 00 A0 E1 A4 10 9F E5 02 20 A0 E3 10 10 8D E8 0C E0 8D E5 08 E0 8D E5 ?? ?? ?? EB 00 40 50 E2 1E 00 00 0A 88 30 9F E5 10 A0 8D E5 06 00 93 E8 14 60 8D E5 18 70 8D E5 1C 80 8D E5 74 30 9F E5 04 C0 94 E5 00 30 8D E5 30 30 8D E2 08 10 8D E5 0C 20 8D E5 04 30 8D E5 01 10 A0 E3 58 20 9F E5 10 30 8D E2 0F E0 A0 E1 00 F0 9C E5 00 00 50 E3 04 00 00 0A 04 00 A0 E1 40 10 9F E5 }
	condition:
		$pattern
}

rule pmap_rmtcall_5dcccb8a641521179821efb94ebe893c {
	meta:
		aliases = "pmap_rmtcall"
		size = "264"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { F0 45 2D E9 3C D0 4D E2 E8 40 9F E5 3C E0 8D E2 00 C0 E0 E3 04 C0 2E E5 01 C0 8C E2 04 50 94 E5 02 C0 C0 E5 6F C0 8C E2 03 C0 C0 E5 01 70 A0 E1 02 80 A0 E1 03 A0 A0 E1 BC 10 9F E5 00 30 94 E5 02 20 A0 E3 00 50 8D E5 00 60 A0 E1 04 E0 8D E5 ?? ?? ?? EB 00 50 50 E2 10 40 A0 03 1F 00 00 0A 5C 30 9D E5 20 30 8D E5 58 30 9D E5 24 30 8D E5 70 30 9D E5 28 30 8D E5 64 30 9D E5 30 30 8D E5 60 30 9D E5 10 70 8D E5 34 30 8D E5 14 80 8D E5 18 A0 8D E5 64 30 9F E5 04 C0 95 E5 00 30 8D E5 28 30 8D E2 04 30 8D E5 68 30 8D E2 18 00 93 E8 05 10 A0 E3 08 30 8D E5 0C 40 8D E5 40 20 9F E5 10 30 8D E2 0F E0 A0 E1 }
	condition:
		$pattern
}

rule __GI_round_5e41ddf7ef8450c1bafa8b5ee39d29f7 {
	meta:
		aliases = "round, __GI_round"
		size = "360"
		objfiles = "s_round@libm.a"
	strings:
		$pattern = { F0 45 2D E9 40 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF 6F 43 E2 03 60 46 E2 08 D0 4D E2 00 20 A0 E3 00 30 A0 E3 13 00 56 E3 00 70 A0 E1 01 80 A0 E1 01 50 A0 E1 00 A0 A0 E1 01 40 A0 E1 0C 00 8D E8 20 00 00 CA 00 00 56 E3 0D 00 00 AA 08 21 9F E5 08 31 9F E5 ?? ?? ?? EB 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? EB 00 00 50 E3 34 00 00 DA 01 00 76 E3 02 A1 07 E2 FF A5 8A 03 03 A6 8A 03 00 40 A0 E3 2E 00 00 EA D8 30 9F E5 53 56 A0 E1 00 30 05 E0 01 30 93 E1 2C 00 00 0A BC 20 9F E5 BC 30 9F E5 ?? ?? ?? EB 00 30 A0 E3 00 20 A0 E3 ?? ?? ?? EB 00 00 50 E3 02 37 A0 C3 53 36 87 C0 05 A0 C3 C1 ED FF FF CA 1D 00 00 EA }
	condition:
		$pattern
}

rule _Unwind_Find_FDE_fcbd1bd6f2a9694dd8beb29c70996cca {
	meta:
		aliases = "_Unwind_Find_FDE"
		size = "364"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { F0 45 2D E9 58 A1 9F E5 00 50 9A E5 00 00 55 E3 04 D0 4D E2 00 40 A0 E1 01 70 A0 E1 09 00 00 0A 00 30 95 E5 03 00 50 E1 03 00 00 3A 3D 00 00 EA 00 30 95 E5 04 00 53 E1 3A 00 00 9A 14 50 95 E5 00 00 55 E3 F9 FF FF 1A 18 81 9F E5 00 60 A0 E3 00 50 98 E5 00 00 55 E3 2F 00 00 0A 14 20 95 E5 00 31 9F E5 05 00 A0 E1 00 20 83 E5 04 10 A0 E1 AA FF FF EB 00 20 9A E5 00 00 52 E3 00 60 A0 E1 2E 00 00 0A 00 10 95 E5 00 30 92 E5 01 00 53 E1 03 00 00 2A 29 00 00 EA 00 30 92 E5 01 00 53 E1 03 00 00 3A 14 00 82 E2 14 20 92 E5 00 00 52 E3 F8 FF FF 1A 00 00 56 E3 14 20 85 E5 00 50 80 E5 E2 FF FF 0A 04 30 95 E5 }
	condition:
		$pattern
}

rule lckpwdf_5410b86777def96f03cfddbb508fe877 {
	meta:
		aliases = "lckpwdf"
		size = "392"
		objfiles = "lckpwdf@libc.a"
	strings:
		$pattern = { F0 45 2D E9 58 A1 9F E5 00 80 9A E5 01 00 78 E3 58 D0 4D E2 00 00 E0 13 4F 00 00 1A 44 11 9F E5 44 21 9F E5 28 00 8D E2 40 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 38 31 9F E5 2C 01 9F E5 0F E0 A0 E1 03 F0 A0 E1 2C 01 9F E5 2C 11 9F E5 ?? ?? ?? EB 01 00 70 E3 00 00 8A E5 39 00 00 0A 02 10 A0 E3 01 20 A0 E3 ?? ?? ?? EB 00 10 A0 E3 14 20 A0 E3 0D 00 A0 E1 ?? ?? ?? EB 14 70 8D E2 FC 30 9F E5 07 20 A0 E1 48 50 8D E2 0D 10 A0 E1 0E 00 A0 E3 00 40 A0 E3 00 30 8D E5 50 60 8D E2 0C 80 8D E5 10 80 8D E5 ?? ?? ?? EB 0E 10 A0 E3 05 00 A0 E1 48 40 8D E5 4C 40 8D E5 ?? ?? ?? EB 05 10 A0 E1 06 20 A0 E1 01 00 A0 E3 }
	condition:
		$pattern
}

rule pthread_sighandler_6b9db6ea4bc6b86def4f061f1693b270 {
	meta:
		aliases = "pthread_sighandler"
		size = "132"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { F0 45 2D E9 58 D0 4D E2 00 60 A0 E1 03 A0 A0 E1 01 70 A0 E1 02 80 A0 E1 C0 FF FF EB 58 30 D0 E5 00 00 53 E3 00 30 A0 13 00 40 A0 E1 20 60 80 15 58 30 C0 15 0F 00 00 1A 54 50 90 E5 00 00 55 E3 54 D0 80 05 74 10 8D E2 58 20 A0 E3 0D 00 A0 E1 ?? ?? ?? EB 06 00 A0 E1 07 10 A0 E1 08 20 A0 E1 0A 30 A0 E1 14 C0 9F E5 0F E0 A0 E1 06 F1 9C E7 00 00 55 E3 54 50 84 05 58 D0 8D E2 F0 85 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __dl_iterate_phdr_1e90469de7ece537ba7bebf87f1ab702 {
	meta:
		aliases = "__GI___dl_iterate_phdr, __dl_iterate_phdr"
		size = "120"
		objfiles = "dl_iterate_phdr@libc.a"
	strings:
		$pattern = { F0 45 2D E9 68 30 9F E5 10 D0 4D E2 00 60 93 E5 00 80 A0 E1 01 70 A0 E1 00 30 A0 E3 0D A0 A0 E1 0B 00 00 EA CC 50 96 E5 08 10 96 E8 D0 E0 96 E5 45 44 A0 E1 08 50 8D E8 0D 40 CD E5 0C 50 CD E5 0F E0 A0 E1 08 F0 A0 E1 00 30 50 E2 05 00 00 1A 0C 60 96 E5 00 00 56 E3 0D 00 A0 E1 10 10 A0 E3 07 20 A0 E1 EE FF FF 1A 03 00 A0 E1 10 D0 8D E2 F0 85 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getrpcent_r_80cf06cf0dceb8730dc9b9ab0f39021a {
	meta:
		aliases = "getrpcent_r"
		size = "152"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { F0 45 2D E9 78 40 9F E5 14 D0 4D E2 04 A0 8D E2 00 60 A0 E1 01 70 A0 E1 02 80 A0 E1 64 10 9F E5 04 20 A0 E1 0A 00 A0 E1 03 50 A0 E1 58 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 50 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 ?? ?? ?? EB 06 10 A0 E1 07 20 A0 E1 08 30 A0 E1 00 50 8D E5 22 FF FF EB 01 10 A0 E3 00 40 A0 E1 24 30 9F E5 0A 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 14 D0 8D E2 F0 85 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getrpcbynumber_r_510ebb13029247f097784388b156e093 {
	meta:
		aliases = "getrpcbynumber_r"
		size = "160"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { F0 45 2D E9 80 40 9F E5 14 D0 4D E2 04 A0 8D E2 00 60 A0 E1 01 70 A0 E1 02 80 A0 E1 6C 10 9F E5 04 20 A0 E1 0A 00 A0 E1 03 50 A0 E1 60 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 58 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 06 00 A0 E1 ?? ?? ?? EB 30 C0 9D E5 07 10 A0 E1 08 20 A0 E1 05 30 A0 E1 00 C0 8D E5 7E FE FF EB 01 10 A0 E3 00 40 A0 E1 24 30 9F E5 0A 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 14 D0 8D E2 F0 85 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getrpcbyname_r_80aa95075bba815aadebbc23c1f056f1 {
	meta:
		aliases = "getrpcbyname_r"
		size = "160"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { F0 45 2D E9 80 40 9F E5 14 D0 4D E2 04 A0 8D E2 00 60 A0 E1 01 70 A0 E1 02 80 A0 E1 6C 10 9F E5 04 20 A0 E1 0A 00 A0 E1 03 50 A0 E1 60 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 58 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 06 00 A0 E1 ?? ?? ?? EB 30 C0 9D E5 07 10 A0 E1 08 20 A0 E1 05 30 A0 E1 00 C0 8D E5 B8 FE FF EB 01 10 A0 E3 00 40 A0 E1 24 30 9F E5 0A 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 14 D0 8D E2 F0 85 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getpass_f90e23cf346a89a00591cf4e01cbe055 {
	meta:
		aliases = "getpass"
		size = "420"
		objfiles = "getpass@libc.a"
	strings:
		$pattern = { F0 45 2D E9 84 11 9F E5 78 D0 4D E2 00 A0 A0 E1 7C 01 9F E5 ?? ?? ?? EB 00 60 50 E2 74 31 9F 05 00 60 93 05 70 31 9F 05 06 00 A0 E1 06 50 A0 11 00 50 93 05 ?? ?? ?? EB 0D 10 A0 E1 ?? ?? ?? EB 00 70 50 E2 00 80 A0 13 1B 00 00 1A 0D E0 A0 E1 0F 00 BE E8 3C C0 8D E2 0F 00 AC E8 0F 00 BE E8 0F 00 AC E8 0F 00 BE E8 0F 00 AC E8 07 00 9E E8 0C 30 9D E5 07 00 8C E8 09 30 C3 E3 06 00 A0 E1 0C 30 8D E5 ?? ?? ?? EB 0D 20 A0 E1 02 10 A0 E3 ?? ?? ?? EB FC 30 9F E5 00 30 93 E5 01 80 70 E2 00 80 A0 33 03 00 56 E1 07 10 A0 11 06 00 A0 11 02 20 A0 13 07 30 A0 11 ?? ?? ?? 1B 05 10 A0 E1 D8 40 9F E5 0A 00 A0 E1 }
	condition:
		$pattern
}

rule rendezvous_request_56cbc48271a3e1cf20621b8e90dfb7f2 {
	meta:
		aliases = "rendezvous_request"
		size = "164"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { F0 45 2D E9 84 D0 4D E2 2C 70 90 E5 00 40 A0 E1 70 A0 A0 E3 0D 80 A0 E1 80 50 8D E2 00 00 94 E5 0D 10 A0 E1 05 20 A0 E1 80 A0 8D E5 ?? ?? ?? EB 00 60 50 E2 04 00 00 AA ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 13 00 00 1A F3 FF FF EA 70 50 8D E2 00 10 A0 E3 10 20 A0 E3 05 00 A0 E1 ?? ?? ?? EB 01 30 A0 E3 70 30 CD E5 00 30 A0 E3 71 30 CD E5 06 00 A0 E1 06 00 97 E8 55 FE FF EB 05 10 A0 E1 00 40 A0 E1 10 20 A0 E3 10 00 80 E2 ?? ?? ?? EB 80 30 9D E5 0C 30 84 E5 00 00 A0 E3 84 D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule _stdio_term_727dd05d4e1ea6422ce5ae426b18ce39 {
	meta:
		aliases = "_stdio_term"
		size = "184"
		objfiles = "_stdio@libc.a"
	strings:
		$pattern = { F0 45 2D E9 9C 00 9F E5 ?? ?? ?? EB 98 00 9F E5 ?? ?? ?? EB 94 30 9F E5 94 A0 9F E5 00 40 93 E5 30 80 A0 E3 00 70 A0 E3 01 60 A0 E3 0E 00 00 EA 0F E0 A0 E1 0A F0 A0 E1 00 00 50 E3 05 00 A0 E1 06 00 00 0A 08 30 94 E5 00 80 C4 E5 14 30 84 E5 01 70 C4 E5 18 30 84 E5 1C 30 84 E5 10 30 84 E5 34 60 84 E5 ?? ?? ?? EB 20 40 94 E5 38 50 84 E2 00 00 54 E3 05 00 A0 E1 EC FF FF 1A 2C 30 9F E5 00 40 93 E5 04 00 00 EA 00 30 D4 E5 40 00 13 E3 04 00 A0 11 ?? ?? ?? 1B 20 40 94 E5 00 00 54 E3 F8 FF FF 1A F0 85 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_create_2f3827f4b3ca6add2d5c958384d57659 {
	meta:
		aliases = "pthread_create"
		size = "192"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { F0 45 2D E9 B0 C0 9F E5 00 C0 9C E5 00 00 5C E3 1C D0 4D E2 00 A0 A0 E1 01 60 A0 E1 02 70 A0 E1 03 80 A0 E1 03 00 00 AA ?? ?? ?? EB 00 00 50 E3 0B 00 A0 B3 1E 00 00 BA EB FD FF EB 00 30 A0 E3 00 50 A0 E1 03 10 A0 E1 02 00 A0 E3 14 20 8D E2 08 60 8D E5 0D 40 A0 E1 0C 70 8D E5 10 80 8D E5 00 50 8D E5 04 30 8D E5 ?? ?? ?? EB 48 60 9F E5 0D 10 A0 E1 1C 20 A0 E3 00 00 96 E5 ?? ?? ?? EB 01 00 70 E3 03 00 00 1A ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 F5 FF FF 0A 05 00 A0 E1 5F FE FF EB 34 30 95 E5 00 00 53 E3 30 30 95 05 34 00 95 E5 00 30 8A 05 1C D0 8D E2 F0 85 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getdelim_b4837ce40ce8275638f345095532fc08 {
	meta:
		aliases = "__GI_getdelim, getdelim"
		size = "320"
		objfiles = "getdelim@libc.a"
	strings:
		$pattern = { F0 47 2D E9 00 00 51 E3 00 00 50 13 10 D0 4D E2 00 80 A0 E1 01 60 A0 E1 02 90 A0 E1 03 50 A0 E1 01 00 00 0A 00 00 53 E3 04 00 00 1A ?? ?? ?? EB 00 50 E0 E3 16 30 A0 E3 00 30 80 E5 38 00 00 EA 34 A0 93 E5 00 00 5A E3 0A 00 00 1A 38 40 83 E2 0D 00 A0 E1 D4 30 9F E5 D4 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 C4 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 40 98 E5 00 00 54 E3 00 40 86 05 01 70 A0 E3 00 10 96 E5 01 00 57 E1 0A 00 00 3A 04 00 A0 E1 40 10 81 E2 ?? ?? ?? EB 00 00 50 E3 00 40 A0 E1 00 50 E0 03 16 00 00 0A 00 30 96 E5 40 30 83 E2 00 30 86 E5 00 00 88 E5 10 20 95 E5 18 30 95 E5 }
	condition:
		$pattern
}

rule __encode_dotted_baf445c8563656078a0293862e54d39b {
	meta:
		aliases = "__encode_dotted"
		size = "168"
		objfiles = "encoded@libc.a"
	strings:
		$pattern = { F0 47 2D E9 00 40 A0 E1 01 80 A0 E1 02 90 A0 E1 00 A0 A0 E3 16 00 00 EA ?? ?? ?? EB 00 60 50 E2 06 50 64 E0 02 00 00 1A 04 00 A0 E1 ?? ?? ?? EB 00 50 A0 E1 01 70 8A E2 09 30 6A E0 00 00 55 E3 04 10 A0 E1 07 00 88 E0 05 20 A0 E1 01 30 43 E2 01 40 86 E2 11 00 00 0A 03 00 55 E1 0F 00 00 2A 0A 50 C8 E7 ?? ?? ?? EB 00 00 56 E3 07 A0 85 E0 05 00 00 0A 00 00 54 E2 2E 10 A0 E3 02 00 00 0A 00 30 D4 E5 00 00 53 E3 E2 FF FF 1A 00 00 59 E3 00 30 A0 C3 01 00 8A C2 0A 30 C8 C7 F0 87 BD C8 00 00 E0 E3 F0 87 BD E8 }
	condition:
		$pattern
}

rule __parsegrent_0127a9c9f6cb293b8fddf0805d33032a {
	meta:
		aliases = "__parsegrent"
		size = "336"
		objfiles = "__parsegrent@libc.a"
	strings:
		$pattern = { F0 47 2D E9 00 50 A0 E3 00 90 90 E5 34 A1 9F E5 04 D0 4D E2 00 70 A0 E1 01 40 A0 E1 05 80 A0 E1 01 00 55 E3 05 60 DA E7 04 00 A0 E1 3A 10 A0 E3 01 50 85 E2 06 00 00 CA 06 40 87 E7 ?? ?? ?? EB 00 00 50 E3 3C 00 00 0A 01 80 C0 E4 00 40 A0 E1 F2 FF FF EA 0D 10 A0 E1 04 00 A0 E1 0A 20 A0 E3 ?? ?? ?? EB 00 10 9D E5 04 00 51 E1 06 00 87 E7 31 00 00 0A 00 30 D1 E5 3A 00 53 E3 2E 00 00 1A 01 30 D1 E5 00 00 53 E3 01 00 A0 03 15 00 00 0A 2C 30 A0 E3 00 30 C1 E5 AC E0 9F E5 01 00 A0 E3 00 C0 A0 E3 00 30 D1 E5 2C 00 53 E3 0A 00 00 1A 00 C0 C1 E5 01 20 F1 E5 00 00 52 E3 01 00 80 E2 1D 00 00 0A 2C 00 52 E3 }
	condition:
		$pattern
}

rule __parsepwent_6d199328b2c4fd995bcfbbe7c06ffdfc {
	meta:
		aliases = "__parsepwent"
		size = "172"
		objfiles = "__parsepwent@libc.a"
	strings:
		$pattern = { F0 47 2D E9 00 50 A0 E3 04 D0 4D E2 94 90 9F E5 00 70 A0 E1 01 40 A0 E1 0D A0 A0 E1 05 80 A0 E1 06 30 05 E2 02 00 53 E3 04 00 A0 E1 3A 10 A0 E3 05 60 D9 E7 06 00 00 0A 06 00 55 E3 06 40 87 E7 13 00 00 0A ?? ?? ?? EB 00 00 50 E3 0C 00 00 1A 11 00 00 EA 0A 20 A0 E3 04 00 A0 E1 0D 10 A0 E1 ?? ?? ?? EB 00 20 A0 E1 00 00 9D E5 04 00 50 E1 09 00 00 0A 00 30 D0 E5 3A 00 53 E3 06 00 00 1A 06 20 87 E7 01 80 C0 E4 01 50 85 E2 00 40 A0 E1 E2 FF FF EA 00 00 A0 E3 00 00 00 EA 00 00 E0 E3 04 D0 8D E2 F0 87 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule add_fdes_99c23c26e44d2bc465f31c81cb8f8995 {
	meta:
		aliases = "add_fdes"
		size = "288"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { F0 47 2D E9 00 60 A0 E1 10 30 D0 E5 11 00 D0 E5 00 34 83 E1 A3 31 A0 E1 FF 70 03 E2 04 D0 4D E2 01 A0 A0 E1 07 00 A0 E1 06 10 A0 E1 02 50 A0 E1 31 FE FF EB 00 90 A0 E3 00 80 A0 E1 0A 00 00 EA 00 00 57 E3 21 00 00 1A 08 30 95 E5 00 00 53 E3 02 00 00 0A 0A 00 A0 E1 05 10 A0 E1 14 FD FF EB 05 00 A0 E1 C7 FC FF EB 00 50 A0 E1 06 00 A0 E1 05 10 A0 E1 C7 FC FF EB 00 00 50 E3 25 00 00 1A 04 30 95 E5 00 00 53 E3 F4 FF FF 0A 10 30 D6 E5 04 00 13 E3 E9 FF FF 0A 05 00 A0 E1 B5 FC FF EB 00 00 59 E1 00 40 A0 E1 E4 FF FF 0A DD FE FF EB 06 10 A0 E1 00 70 A0 E1 FF 00 00 E2 0E FE FF EB 00 00 57 E3 00 80 A0 E1 }
	condition:
		$pattern
}

rule linear_search_fdes_091029292acedc2c8e722f2f987fd9e7 {
	meta:
		aliases = "linear_search_fdes"
		size = "348"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { F0 47 2D E9 00 60 A0 E1 10 30 D0 E5 11 00 D0 E5 00 34 83 E1 A3 31 A0 E1 FF 70 03 E2 08 D0 4D E2 01 50 A0 E1 07 00 A0 E1 06 10 A0 E1 02 A0 A0 E1 88 FE FF EB 00 90 A0 E3 00 80 A0 E1 0E 00 00 EA 00 00 57 E3 25 00 00 1A 08 10 95 E5 04 10 8D E5 0C 30 95 E5 00 00 51 E3 00 30 8D E5 03 00 00 0A 00 30 9D E5 0A 20 61 E0 03 00 52 E1 35 00 00 3A 05 00 A0 E1 1A FD FF EB 00 50 A0 E1 06 00 A0 E1 05 10 A0 E1 1A FD FF EB 00 00 50 E3 30 00 00 1A 04 30 95 E5 00 00 53 E3 F4 FF FF 0A 10 30 D6 E5 04 00 13 E3 E5 FF FF 0A 05 00 A0 E1 08 FD FF EB 00 00 59 E1 00 40 A0 E1 E0 FF FF 0A 30 FF FF EB 06 10 A0 E1 00 70 A0 E1 }
	condition:
		$pattern
}

rule __GI_clnttcp_create_d3e367022e6de1d1fa048729df934130 {
	meta:
		aliases = "clnttcp_create, __GI_clnttcp_create"
		size = "604"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { F0 47 2D E9 00 60 A0 E1 38 D0 4D E2 0C 00 A0 E3 01 A0 A0 E1 02 90 A0 E1 03 80 A0 E1 ?? ?? ?? EB 00 70 A0 E1 64 00 A0 E3 ?? ?? ?? EB 00 00 50 E3 00 00 57 13 00 50 A0 E1 09 00 00 1A ?? ?? ?? EB 00 32 9F E5 00 40 A0 E1 00 10 93 E5 F8 01 9F E5 ?? ?? ?? EB 0C 30 A0 E3 08 30 84 E5 00 30 84 E5 70 00 00 EA 02 20 D6 E5 03 30 D6 E5 03 34 92 E1 13 00 00 1A 06 00 A0 E1 0A 10 A0 E1 09 20 A0 E1 06 30 A0 E3 ?? ?? ?? EB 00 40 50 E2 05 00 00 1A 05 00 A0 E1 ?? ?? ?? EB 07 00 A0 E1 ?? ?? ?? EB 04 70 A0 E1 64 00 00 EA 24 34 A0 E1 FF 20 04 E2 FF 30 03 E2 02 34 83 E1 43 24 A0 E1 03 20 C6 E5 02 30 C6 E5 00 30 98 E5 }
	condition:
		$pattern
}

rule clntunix_create_fc69efe74c36fe04c3483640c4127d37 {
	meta:
		aliases = "__GI_clntunix_create, clntunix_create"
		size = "524"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { F0 47 2D E9 00 60 A0 E1 38 D0 4D E2 C4 00 A0 E3 02 90 A0 E1 01 A0 A0 E1 03 80 A0 E1 ?? ?? ?? EB 00 50 A0 E1 0C 00 A0 E3 ?? ?? ?? EB 00 00 55 E3 00 00 50 13 00 70 A0 E1 00 20 A0 13 01 20 A0 03 09 00 00 1A ?? ?? ?? EB A8 31 9F E5 00 40 A0 E1 00 10 93 E5 A0 01 9F E5 ?? ?? ?? EB 0C 30 A0 E3 08 30 84 E5 00 30 84 E5 5A 00 00 EA 00 30 98 E5 00 00 53 E3 04 20 85 A5 1C 00 00 AA 01 00 A0 E3 00 10 A0 E1 ?? ?? ?? EB 00 40 A0 E1 00 00 88 E5 02 00 86 E2 ?? ?? ?? EB 00 00 54 E3 00 20 A0 E1 07 00 00 BA 04 00 A0 E1 03 20 82 E2 06 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 01 30 A0 A3 04 30 85 A5 0A 00 00 AA ?? ?? ?? EB }
	condition:
		$pattern
}

rule ether_ntohost_2e85b9e678a0a7edc1c2a57bd5c6c91a {
	meta:
		aliases = "ether_ntohost"
		size = "176"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { F0 47 2D E9 00 90 A0 E1 42 DF 4D E2 01 A0 A0 E1 90 00 9F E5 90 10 9F E5 ?? ?? ?? EB 00 70 50 E2 00 40 E0 03 1C 00 00 0A 0C 00 00 EA BE FF FF EB 00 50 50 E2 08 10 A0 E1 06 20 A0 E3 0A 00 A0 E1 0A 00 00 0A ?? ?? ?? EB 00 40 50 E2 07 00 00 1A 09 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 0C 00 00 EA 04 60 8D E2 01 8C 8D E2 02 60 46 E2 02 80 88 E2 01 1C A0 E3 07 20 A0 E1 06 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 08 10 A0 E1 06 00 A0 E1 E6 FF FF 1A 00 40 E0 E3 07 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 42 DF 8D E2 F0 87 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svctcp_create_b5790c8687167f36127d96988b018d5a {
	meta:
		aliases = "svctcp_create"
		size = "436"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { F0 47 2D E9 01 00 70 E3 14 D0 4D E2 10 30 A0 E3 00 50 A0 E1 10 30 8D E5 01 A0 A0 E1 02 90 A0 E1 00 80 A0 13 0A 00 00 1A 02 00 A0 E3 01 10 A0 E3 06 20 A0 E3 ?? ?? ?? EB 00 50 50 E2 01 80 A0 A3 03 00 00 AA 50 01 9F E5 ?? ?? ?? EB 00 60 A0 E3 4E 00 00 EA 00 10 A0 E3 10 20 A0 E3 0D 00 A0 E1 ?? ?? ?? EB 00 60 A0 E3 02 70 A0 E3 05 00 A0 E1 0D 10 A0 E1 00 70 CD E5 01 60 CD E5 ?? ?? ?? EB 06 00 50 E1 0D 40 A0 E1 05 00 00 0A 05 00 A0 E1 0D 10 A0 E1 10 20 9D E5 02 60 CD E5 03 60 CD E5 ?? ?? ?? EB 0D 10 A0 E1 05 00 A0 E1 10 20 8D E2 ?? ?? ?? EB 00 00 50 E3 04 00 00 1A 07 10 A0 E1 05 00 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __xstat32_conv_d9d816623f4ebe4ccbc3276612167657 {
	meta:
		aliases = "__xstat32_conv"
		size = "728"
		objfiles = "xstatconv@libc.a"
	strings:
		$pattern = { F0 47 2D E9 01 70 A0 E1 00 40 A0 E1 18 D0 4D E2 00 10 A0 E3 58 20 A0 E3 07 00 A0 E1 ?? ?? ?? EB 01 C0 D4 E5 05 E0 D4 E5 00 00 D4 E5 04 10 D4 E5 02 90 D4 E5 06 A0 D4 E5 03 80 D4 E5 0C 04 80 E1 0E 14 81 E1 07 C0 D4 E5 09 08 80 E1 0A 18 81 E1 08 2C 80 E1 0C 3C 81 E1 0C 00 87 E8 59 10 D4 E5 58 20 D4 E5 5A 80 D4 E5 5B C0 D4 E5 01 24 82 E1 5D 00 D4 E5 5C 30 D4 E5 08 28 82 E1 5E E0 D4 E5 0C 5C 82 E1 5F 10 D4 E5 00 34 83 E1 0C 50 87 E5 0E 38 83 E1 11 20 D4 E5 01 6C 83 E1 10 30 D4 E5 12 10 D4 E5 02 34 83 E1 13 20 D4 E5 01 38 83 E1 02 3C 83 E1 10 30 87 E5 15 20 D4 E5 14 30 D4 E5 16 10 D4 E5 02 34 83 E1 }
	condition:
		$pattern
}

rule __xstat64_conv_1e2558eff678359151518898612f95af {
	meta:
		aliases = "__xstat64_conv"
		size = "784"
		objfiles = "xstatconv@libc.a"
	strings:
		$pattern = { F0 47 2D E9 01 70 A0 E1 00 40 A0 E1 18 D0 4D E2 00 10 A0 E3 60 20 A0 E3 07 00 A0 E1 ?? ?? ?? EB 01 C0 D4 E5 05 E0 D4 E5 00 00 D4 E5 04 10 D4 E5 02 90 D4 E5 06 A0 D4 E5 03 80 D4 E5 0C 04 80 E1 0E 14 81 E1 07 C0 D4 E5 09 08 80 E1 0A 18 81 E1 08 2C 80 E1 0C 3C 81 E1 0C 00 87 E8 59 10 D4 E5 5D 00 D4 E5 58 20 D4 E5 5C 30 D4 E5 5E E0 D4 E5 5A 80 D4 E5 5B C0 D4 E5 01 24 82 E1 00 34 83 E1 5F 10 D4 E5 0E 38 83 E1 08 28 82 E1 0C 5C 82 E1 01 6C 83 E1 58 50 87 E5 5C 60 87 E5 0D 20 D4 E5 0C 30 D4 E5 0E 10 D4 E5 02 34 83 E1 0F 20 D4 E5 01 38 83 E1 02 3C 83 E1 0C 30 87 E5 11 20 D4 E5 10 30 D4 E5 12 10 D4 E5 }
	condition:
		$pattern
}

rule __res_querydomain_c5de41b46cfd7bd1dc68136c62c45191 {
	meta:
		aliases = "__GI___res_querydomain, __res_querydomain"
		size = "308"
		objfiles = "res_query@libc.a"
	strings:
		$pattern = { F0 47 2D E9 01 DB 4D E2 08 D0 4D E2 28 94 9D E5 00 00 59 E3 00 00 50 13 01 70 A0 E1 02 80 A0 E1 03 A0 A0 E1 00 60 A0 E1 03 00 00 1A ?? ?? ?? EB 00 30 E0 E3 03 20 A0 E1 09 00 00 EA 00 00 51 E3 1B 00 00 1A ?? ?? ?? EB DC 30 9F E5 01 20 80 E2 03 00 52 E1 04 00 00 9A ?? ?? ?? EB 00 20 E0 E3 03 30 A0 E3 00 30 80 E5 2B 00 00 EA 00 00 50 E3 21 00 00 0A 01 50 40 E2 05 30 D6 E7 2E 00 53 E3 1D 00 00 1A 08 40 8D E2 01 40 44 E2 05 20 A0 E1 06 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 01 2B 8D E2 08 20 82 E2 05 30 82 E0 04 00 A0 E1 01 74 43 E5 12 00 00 EA ?? ?? ?? EB 00 40 A0 E1 07 00 A0 E1 ?? ?? ?? EB 60 10 9F E5 }
	condition:
		$pattern
}

rule __GI_getpwuid_r_d059c4ebfab1936be1f69c7e7258a6bc {
	meta:
		aliases = "__GI_getgrgid_r, getgrgid_r, getpwuid_r, __GI_getpwuid_r"
		size = "168"
		objfiles = "getpwuid_r@libc.a, getgrgid_r@libc.a"
	strings:
		$pattern = { F0 47 2D E9 04 D0 4D E2 24 90 9D E5 00 C0 A0 E3 00 C0 89 E5 00 A0 A0 E1 01 60 A0 E1 78 00 9F E5 78 10 9F E5 03 70 A0 E1 02 80 A0 E1 ?? ?? ?? EB 00 50 50 E2 01 30 A0 13 34 30 85 15 02 00 00 1A ?? ?? ?? EB 00 40 90 E5 10 00 00 EA 50 00 9F E5 06 10 A0 E1 08 20 A0 E1 07 30 A0 E1 00 50 8D E5 ?? ?? ?? EB 00 40 50 E2 04 00 00 1A 08 30 96 E5 0A 00 53 E1 F4 FF FF 1A 00 60 89 E5 01 00 00 EA 02 00 54 E3 00 40 A0 03 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 04 D0 8D E2 F0 87 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_getspnam_r_f0f9c54b72d68aa234b440f56dbd90cc {
	meta:
		aliases = "getspnam_r, getpwnam_r, __GI_getgrnam_r, __GI_getpwnam_r, getgrnam_r, __GI_getspnam_r"
		size = "176"
		objfiles = "getspnam_r@libc.a, getgrnam_r@libc.a, getpwnam_r@libc.a"
	strings:
		$pattern = { F0 47 2D E9 04 D0 4D E2 24 90 9D E5 00 C0 A0 E3 00 C0 89 E5 00 A0 A0 E1 01 60 A0 E1 80 00 9F E5 80 10 9F E5 03 70 A0 E1 02 80 A0 E1 ?? ?? ?? EB 00 50 50 E2 01 30 A0 13 34 30 85 15 02 00 00 1A ?? ?? ?? EB 00 40 90 E5 12 00 00 EA 06 10 A0 E1 08 20 A0 E1 07 30 A0 E1 4C 00 9F E5 00 50 8D E5 ?? ?? ?? EB 00 40 50 E2 0A 10 A0 E1 05 00 00 1A 00 00 96 E5 ?? ?? ?? EB 00 00 50 E3 F2 FF FF 1A 00 60 89 E5 01 00 00 EA 02 00 54 E3 00 40 A0 03 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 04 D0 8D E2 F0 87 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule statvfs_c7d4199ebe188ea37beeacba8b6667db {
	meta:
		aliases = "__GI_fstatvfs, __GI_statvfs, fstatvfs, statvfs"
		size = "668"
		objfiles = "fstatvfs@libc.a, statvfs@libc.a"
	strings:
		$pattern = { F0 47 2D E9 05 DC 4D E2 0C D0 4D E2 01 40 A0 E1 4B 1E 8D E2 00 60 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 E0 B3 8D 00 00 BA B8 34 9D E5 BC 24 9D E5 C0 14 9D E5 C4 04 9D E5 C8 C4 9D E5 08 30 84 E5 CC 34 9D E5 B4 E4 9D E5 20 30 84 E5 D4 34 9D E5 00 50 A0 E3 04 E0 84 E5 0C 20 84 E5 10 10 84 E5 14 00 84 E5 18 C0 84 E5 2C 30 84 E5 00 E0 84 E5 05 10 A0 E1 18 20 A0 E3 24 50 84 E5 30 00 84 E2 ?? ?? ?? EB 18 30 94 E5 45 1E 8D E2 1C 30 84 E5 28 50 84 E5 06 00 A0 E1 08 10 81 E2 ?? ?? ?? EB 05 00 50 E1 05 00 A0 B1 6C 00 00 BA ?? ?? ?? EB B4 11 9F E5 00 A0 A0 E1 B0 01 9F E5 00 90 9A E5 ?? ?? ?? EB 00 60 50 E2 }
	condition:
		$pattern
}

rule readtcp_50587b51c4928300745e08c3cf0ae997 {
	meta:
		aliases = "readtcp"
		size = "204"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { F0 47 2D E9 08 D0 4D E2 00 40 90 E5 00 50 A0 E1 01 60 A0 E1 02 70 A0 E1 01 80 A0 E3 00 90 A0 E3 0D A0 A0 E1 08 10 A0 E1 98 20 9F E5 0D 00 A0 E1 00 40 8D E5 04 80 CD E5 05 90 CD E5 ?? ?? ?? EB 01 00 70 E3 02 00 00 0A 00 00 50 E3 17 00 00 0A 04 00 00 EA ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 09 00 00 0A 11 00 00 EA 06 30 DD E5 07 20 DD E5 02 34 83 E1 03 38 A0 E1 43 38 A0 E1 18 00 13 E3 0A 00 00 1A 20 00 13 E3 08 00 00 1A 06 30 DD E5 01 00 13 E3 E2 FF FF 0A 04 00 A0 E1 06 10 A0 E1 07 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 03 00 00 CA 2C 20 95 E5 00 30 A0 E3 00 30 82 E5 00 00 E0 E3 08 D0 8D E2 F0 87 BD E8 }
	condition:
		$pattern
}

rule __GI_pthread_cond_timedwait_c7b6a67247de97ca0ba5d43977772852 {
	meta:
		aliases = "pthread_cond_timedwait, __GI_pthread_cond_timedwait"
		size = "520"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { F0 47 2D E9 0C D0 4D E2 01 60 A0 E1 00 50 A0 E1 02 90 A0 E1 C7 FF FF EB 0C 30 96 E5 03 00 53 E3 00 00 53 13 08 00 8D E5 04 00 00 0A 08 20 9D E5 08 30 96 E5 02 00 53 E1 16 00 A0 13 6C 00 00 1A B4 31 9F E5 08 20 9D E5 04 30 8D E5 00 30 A0 E3 00 50 8D E5 41 31 C2 E5 08 00 9D E5 0D 10 A0 E1 8C FF FF EB 05 00 A0 E1 08 10 9D E5 ?? ?? ?? EB 08 30 9D E5 42 30 D3 E5 00 00 53 E3 04 00 00 0A 08 30 9D E5 40 30 D3 E5 00 00 53 E3 01 40 A0 03 03 00 00 0A 08 10 9D E5 08 00 85 E2 48 FF FF EB 00 40 A0 E3 05 00 A0 E1 ?? ?? ?? EB 00 00 54 E3 03 00 00 0A 08 00 9D E5 00 10 A0 E3 75 FF FF EB 3F 00 00 EA 06 00 A0 E1 }
	condition:
		$pattern
}

rule __GI_getprotobyname_r_a5123283d26368b61e43a758cc532501 {
	meta:
		aliases = "getprotobyname_r, __GI_getprotobyname_r"
		size = "256"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { F0 47 2D E9 10 D0 4D E2 00 60 A0 E1 01 50 A0 E1 0D 00 A0 E1 CC 10 9F E5 02 A0 A0 E1 03 80 A0 E1 C4 20 9F E5 C4 30 9F E5 30 90 9D E5 0F E0 A0 E1 03 F0 A0 E1 B8 30 9F E5 AC 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 AC 30 9F E5 00 00 93 E5 ?? ?? ?? EB 0E 00 00 EA 00 00 95 E5 06 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 10 00 00 0A 04 40 95 E5 04 00 00 EA 06 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 0A 00 00 0A 04 40 84 E2 00 00 94 E5 00 00 50 E3 F7 FF FF 1A 05 00 A0 E1 0A 10 A0 E1 08 20 A0 E1 09 30 A0 E1 ?? ?? ?? EB 00 70 50 E2 E9 FF FF 0A 44 30 9F E5 00 30 93 E5 00 00 53 E3 ?? ?? ?? 0B 0D 00 A0 E1 01 10 A0 E3 30 30 9F E5 }
	condition:
		$pattern
}

rule getservbyport_r_0efbbf6e0cd2ca66e29c71df8f5d69f0 {
	meta:
		aliases = "__GI_getservbyport_r, getservbyport_r"
		size = "236"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { F0 47 2D E9 10 D0 4D E2 00 80 A0 E1 01 50 A0 E1 0D 00 A0 E1 B8 10 9F E5 02 40 A0 E1 03 70 A0 E1 B0 20 9F E5 B0 30 9F E5 30 90 8D E2 00 06 99 E8 0F E0 A0 E1 03 F0 A0 E1 A0 30 9F E5 94 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 94 30 9F E5 00 00 93 E5 ?? ?? ?? EB 08 00 00 EA 08 30 94 E5 08 00 53 E1 05 00 00 1A 00 10 55 E2 0A 00 00 0A 0C 00 94 E5 ?? ?? ?? EB 00 00 50 E3 06 00 00 0A 07 10 A0 E1 09 20 A0 E1 0A 30 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 60 50 E2 EF FF FF 0A 44 30 9F E5 00 30 93 E5 00 00 53 E3 ?? ?? ?? 0B 0D 00 A0 E1 01 10 A0 E3 30 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 9A E5 00 00 50 E3 06 00 A0 01 }
	condition:
		$pattern
}

rule ptsname_r_56de14a4e6442f08b7397a476215ab79 {
	meta:
		aliases = "__GI_ptsname_r, ptsname_r"
		size = "176"
		objfiles = "ptsname@libc.a"
	strings:
		$pattern = { F0 47 2D E9 14 D0 4D E2 00 40 A0 E1 01 80 A0 E1 02 A0 A0 E1 ?? ?? ?? EB 88 10 9F E5 00 50 A0 E1 10 20 8D E2 04 00 A0 E1 00 90 95 E5 ?? ?? ?? EB 00 70 50 E2 19 30 A0 13 00 30 85 15 03 00 A0 11 16 00 00 1A 10 10 9D E5 0F 40 8D E2 09 30 E0 E3 04 00 A0 E1 C1 2F A0 E1 00 70 8D E5 ?? ?? ?? EB 04 40 60 E0 0A 40 84 E2 04 00 5A E1 22 30 A0 33 00 60 A0 E1 00 30 85 35 03 00 A0 31 07 00 00 3A 24 10 9F E5 08 00 A0 E1 ?? ?? ?? EB 08 00 A0 E1 06 10 A0 E1 ?? ?? ?? EB 00 90 85 E5 07 00 A0 E1 14 D0 8D E2 F0 87 BD E8 30 54 04 80 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pmap_getport_92797642e0c9cab354081e0186a2774d {
	meta:
		aliases = "__GI_pmap_getport, pmap_getport"
		size = "324"
		objfiles = "pm_getport@libc.a"
	strings:
		$pattern = { F0 47 2D E9 24 E1 9F E5 6F C0 A0 E3 28 D0 4D E2 03 C0 C0 E5 04 40 9E E5 00 60 A0 E3 00 C0 E0 E3 02 60 C0 E5 01 80 A0 E1 20 C0 8D E5 02 A0 A0 E1 20 C0 8D E2 03 90 A0 E1 F4 10 9F E5 00 30 9E E5 02 20 A0 E3 19 EE A0 E3 00 40 8D E5 00 70 A0 E1 04 C0 8D E5 0C E0 8D E5 26 60 CD E5 27 60 CD E5 08 E0 8D E5 ?? ?? ?? EB 00 40 50 E2 27 00 00 0A ?? ?? ?? EB BC 30 9F E5 10 80 8D E5 06 00 93 E8 14 A0 8D E5 18 90 8D E5 1C 60 8D E5 A8 30 9F E5 04 C0 94 E5 00 30 8D E5 26 30 8D E2 08 10 8D E5 0C 20 8D E5 04 30 8D E5 00 50 A0 E1 03 10 A0 E3 04 00 A0 E1 84 20 9F E5 10 30 8D E2 0F E0 A0 E1 00 F0 9C E5 06 00 50 E1 }
	condition:
		$pattern
}

rule fclose_fb010ccb69c513b0d7d639ebfa9910b3 {
	meta:
		aliases = "__GI_fclose, fclose"
		size = "360"
		objfiles = "fclose@libc.a"
	strings:
		$pattern = { F0 47 2D E9 34 80 90 E5 00 00 58 E3 20 D0 4D E2 00 50 A0 E1 0A 00 00 1A 38 40 80 E2 28 31 9F E5 10 00 8D E2 24 11 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 14 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 D5 E5 40 00 13 E2 05 00 A0 11 ?? ?? ?? 1B 00 70 A0 E1 04 00 95 E5 ?? ?? ?? EB 00 30 E0 E3 00 00 50 E3 04 30 85 E5 DC 10 9F E5 E0 20 9F E5 0D 00 A0 E1 CC 90 9F E5 03 70 A0 B1 CC A0 9F E5 0F E0 A0 E1 09 F0 A0 E1 C4 00 9F E5 0F E0 A0 E1 0A F0 A0 E1 BC 20 9F E5 00 30 92 E5 01 30 83 E2 00 30 82 E5 0D 00 A0 E1 01 10 A0 E3 A8 40 9F E5 0F E0 A0 E1 04 F0 A0 E1 00 30 95 E5 06 3A 03 E2 30 30 83 E3 }
	condition:
		$pattern
}

rule putspent_35e49837b8c343c87738da6dae98a60b {
	meta:
		aliases = "putspent"
		size = "308"
		objfiles = "putspent@libc.a"
	strings:
		$pattern = { F0 47 2D E9 34 90 91 E5 00 00 59 E3 10 D0 4D E2 01 50 A0 E1 00 60 A0 E1 0A 00 00 1A 38 40 81 E2 0D 00 A0 E1 E4 30 9F E5 E4 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 D4 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 20 96 E5 00 00 52 E3 C4 30 9F E5 05 00 A0 E1 02 30 A0 11 BC 10 9F E5 00 20 96 E5 ?? ?? ?? EB 00 00 50 E3 1D 00 00 BA AC 70 9F E5 AC A0 9F E5 00 40 A0 E3 03 80 87 E2 08 00 00 EA 04 30 DA E7 03 20 96 E7 01 00 72 E3 07 10 A0 11 08 10 A0 01 ?? ?? ?? EB 00 00 50 E3 10 00 00 BA 01 40 84 E2 05 00 54 E3 05 00 A0 E1 F3 FF FF 9A 20 20 96 E5 01 00 72 E3 03 00 00 0A 64 10 9F E5 ?? ?? ?? EB }
	condition:
		$pattern
}

rule readunix_d9249d980d9258d766de3f6d297228f7 {
	meta:
		aliases = "readunix"
		size = "364"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { F0 47 2D E9 34 D0 4D E2 00 50 90 E5 00 80 A0 E1 01 60 A0 E1 02 70 A0 E1 01 40 A0 E3 00 90 A0 E3 28 A0 8D E2 04 10 A0 E1 34 21 9F E5 0A 00 A0 E1 28 50 8D E5 2C 40 CD E5 2D 90 CD E5 ?? ?? ?? EB 01 00 70 E3 02 00 00 0A 00 00 50 E3 3E 00 00 0A 04 00 00 EA ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 09 00 00 0A 38 00 00 EA 2E 30 DD E5 2F 20 DD E5 02 34 83 E1 03 38 A0 E1 43 38 A0 E1 18 00 13 E3 31 00 00 1A 20 00 13 E3 2F 00 00 1A 2E 30 DD E5 01 00 13 E3 E2 FF FF 0A 20 C0 8D E2 0C C0 8D E5 C0 C0 9F E5 01 40 A0 E3 34 30 8D E2 14 C0 8D E5 1C C0 A0 E3 00 E0 A0 E3 04 40 23 E5 18 C0 8D E5 04 10 A0 E1 04 C0 A0 E3 }
	condition:
		$pattern
}

rule __GI_ceil_db55914f28e05790574b80007114621a {
	meta:
		aliases = "ceil, __GI_ceil"
		size = "392"
		objfiles = "s_ceil@libm.a"
	strings:
		$pattern = { F0 47 2D E9 40 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF 7F 43 E2 03 70 47 E2 08 D0 4D E2 00 20 A0 E3 00 30 A0 E3 13 00 57 E3 00 80 A0 E1 01 90 A0 E1 00 40 A0 E1 01 50 A0 E1 00 60 A0 E1 01 A0 A0 E1 0C 00 8D E8 23 00 00 CA 00 00 57 E3 0F 00 00 AA 20 21 9F E5 20 31 9F E5 ?? ?? ?? EB 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? EB 00 00 50 E3 3B 00 00 DA 00 00 58 E3 02 61 A0 B3 02 00 00 BA 06 30 99 E1 36 00 00 0A F4 60 9F E5 00 A0 A0 E3 33 00 00 EA EC 30 9F E5 53 47 A0 E1 00 30 04 E0 01 30 93 E1 30 00 00 0A CC 20 9F E5 CC 30 9F E5 ?? ?? ?? EB 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? EB 00 00 50 E3 26 00 00 DA 00 00 58 E3 }
	condition:
		$pattern
}

rule floor_909cc92b486a14f79bd0241fbc734b85 {
	meta:
		aliases = "__GI_floor, floor"
		size = "400"
		objfiles = "s_floor@libm.a"
	strings:
		$pattern = { F0 47 2D E9 40 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF 7F 43 E2 03 70 47 E2 08 D0 4D E2 00 20 A0 E3 00 30 A0 E3 13 00 57 E3 00 80 A0 E1 01 90 A0 E1 00 40 A0 E1 01 50 A0 E1 00 60 A0 E1 01 A0 A0 E1 0C 00 8D E8 25 00 00 CA 00 00 57 E3 10 00 00 AA 28 21 9F E5 28 31 9F E5 ?? ?? ?? EB 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? EB 00 00 50 E3 3D 00 00 DA 00 00 58 E3 00 A0 A0 A3 0A 60 A0 A1 39 00 00 AA 02 31 C6 E3 0A 30 93 E1 F8 60 9F 15 11 00 00 1A 34 00 00 EA F0 30 9F E5 53 47 A0 E1 00 30 04 E0 01 30 93 E1 31 00 00 0A D0 20 9F E5 D0 30 9F E5 ?? ?? ?? EB 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? EB 00 00 50 E3 27 00 00 DA }
	condition:
		$pattern
}

rule initshells_415c5d8f34a62b499e5b7fee7ddd99cd {
	meta:
		aliases = "initshells"
		size = "356"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { F0 47 2D E9 58 D0 4D E2 EF FF FF EB 38 01 9F E5 38 11 9F E5 ?? ?? ?? EB 00 70 50 E2 47 00 00 0A ?? ?? ?? EB 0D 10 A0 E1 ?? ?? ?? EB 01 00 70 E3 3F 00 00 0A 2C 00 9D E5 01 00 80 E2 ?? ?? ?? EB 0C 61 9F E5 00 00 50 E3 00 00 86 E5 38 00 00 0A 2C 00 9D E5 03 10 A0 E3 ?? ?? ?? EB 04 10 A0 E3 ?? ?? ?? EB EC 40 9F E5 00 00 50 E3 00 00 84 E5 2F 00 00 0A 07 00 A0 E1 02 10 A0 E3 ?? ?? ?? EB D4 90 9F E5 00 50 94 E5 2C 80 9D E5 00 40 96 E5 06 A0 A0 E1 00 60 A0 E3 17 00 00 EA 01 40 84 E2 00 30 D4 E5 23 00 53 E3 2F 00 53 13 01 00 00 0A 00 00 53 E3 F8 FF FF 1A 00 00 53 E3 23 00 53 13 00 40 85 15 01 00 00 1A }
	condition:
		$pattern
}

rule getprotoent_r_142d737aa5e100bd6a3a04f2750fea4e {
	meta:
		aliases = "__GI_getprotoent_r, getprotoent_r"
		size = "548"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { F0 47 2D E9 8B 00 52 E3 03 90 A0 E1 00 30 A0 E3 10 D0 4D E2 02 40 A0 E1 00 30 89 E5 00 80 A0 E1 01 70 A0 E1 04 00 00 8A ?? ?? ?? EB 22 30 A0 E3 03 40 A0 E1 00 30 80 E5 6C 00 00 EA 0D 00 A0 E1 B4 11 9F E5 B4 21 9F E5 B4 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 AC 31 9F E5 A0 01 9F E5 0F E0 A0 E1 03 F0 A0 E1 8C 30 44 E2 01 0A 53 E3 8C 60 87 E2 04 00 00 8A ?? ?? ?? EB 22 30 A0 E3 03 40 A0 E1 00 30 80 E5 54 00 00 EA 7C 41 9F E5 00 30 94 E5 00 00 53 E3 08 00 00 1A 70 01 9F E5 70 11 9F E5 ?? ?? ?? EB 00 00 50 E3 00 00 84 E5 02 00 00 1A ?? ?? ?? EB 00 40 90 E5 47 00 00 EA 48 A1 9F E5 00 50 A0 E3 01 1A A0 E3 }
	condition:
		$pattern
}

rule __getdents_130c000a779e49e55942bf7fb665bef3 {
	meta:
		aliases = "__getdents"
		size = "152"
		objfiles = "getdents@libc.a"
	strings:
		$pattern = { F0 47 2D E9 8D 00 90 EF 01 0A 70 E3 00 60 A0 E1 04 00 00 9A ?? ?? ?? EB 00 30 66 E2 00 60 E0 E3 00 30 80 E5 19 00 00 EA 01 00 70 E3 01 50 A0 11 00 90 85 10 0F 00 00 1A 14 00 00 EA 01 20 DA E5 08 30 D5 E5 02 34 83 E1 03 30 85 E0 01 40 53 E5 ?? ?? ?? EB 07 10 A0 E1 01 20 80 E2 08 00 A0 E1 ?? ?? ?? EB 0A 40 C5 E5 08 30 D5 E5 01 20 DA E5 02 34 83 E1 03 50 85 E0 0A 70 85 E2 09 00 55 E1 08 A0 85 E2 07 00 A0 E1 0B 80 85 E2 EA FF FF 3A 06 00 A0 E1 F0 87 BD E8 }
	condition:
		$pattern
}

rule inet_ntoa_r_4840c0b98dd9553f4806e6e3014f1efc {
	meta:
		aliases = "__GI_inet_ntoa_r, inet_ntoa_r"
		size = "132"
		objfiles = "inet_ntoa@libc.a"
	strings:
		$pattern = { F0 47 2D E9 FF 28 00 E2 20 3C A0 E1 22 34 83 E1 FF 2C 00 E2 00 50 A0 E3 02 34 83 E1 04 D0 4D E2 00 4C 83 E1 0F C0 81 E2 05 60 A0 E1 FF 70 A0 E3 00 80 A0 E3 05 90 A0 E1 2E A0 A0 E3 05 00 00 EA 00 90 8D E5 ?? ?? ?? EB 00 00 56 E3 01 C0 40 E2 00 A0 C6 15 0C 60 A0 E1 03 00 55 E3 04 10 07 E0 0C 00 A0 E1 00 20 A0 E3 09 30 E0 E3 24 44 A0 E1 01 50 85 E2 F1 FF FF DA 01 00 8C E2 04 D0 8D E2 F0 87 BD E8 }
	condition:
		$pattern
}

rule read_encoded_value_with_base_d73a98cb50f1db025f6d94dd1030a793 {
	meta:
		aliases = "read_encoded_value_with_base"
		size = "356"
		objfiles = "unwind_c@libgcc_eh.a, unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { F0 47 2D E9 FF 80 00 E2 50 00 58 E3 04 D0 4D E2 01 A0 A0 E1 02 70 A0 E1 03 90 A0 E1 23 00 00 0A 0F 30 00 E2 0C 00 53 E3 03 F1 9F 97 41 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 30 D2 E5 01 20 D2 E5 02 00 D7 E5 02 34 83 E1 03 10 D7 E5 00 38 83 E1 01 1C 83 E1 04 00 87 E2 00 00 51 E3 05 00 00 0A 70 30 08 E2 10 00 53 E3 07 A0 A0 01 0A 10 81 E0 80 00 18 E3 00 10 91 15 00 10 89 E5 04 D0 8D E2 F0 87 BD E8 03 30 82 E2 03 30 C3 E3 04 10 93 E4 03 00 A0 E1 F7 FF FF EA 01 00 D2 E5 }
	condition:
		$pattern
}

rule statvfs64_8a7ef27f4272120623f6abfb9774f8b3 {
	meta:
		aliases = "fstatvfs64, statvfs64"
		size = "728"
		objfiles = "fstatvfs64@libc.a, statvfs64@libc.a"
	strings:
		$pattern = { F0 4B 2D E9 53 DE 4D E2 0C D0 4D E2 01 B0 A0 E1 13 1D 8D E2 0C 10 81 E2 08 00 8D E5 ?? ?? ?? EB 00 00 50 E3 00 00 E0 B3 9B 00 00 BA F4 34 9D E5 F8 44 9D E5 18 00 8D E8 D4 34 9D E5 D8 44 9D E5 DC 14 9D E5 E0 24 9D E5 E4 54 9D E5 E8 64 9D E5 EC 74 9D E5 F0 84 9D E5 08 30 8B E5 0C 40 8B E5 18 00 9D E8 28 30 8B E5 2C 40 8B E5 FC 34 9D E5 D0 04 9D E5 38 30 8B E5 04 35 9D E5 00 90 A0 E3 10 10 8B E5 14 20 8B E5 04 00 8B E5 44 30 8B E5 00 00 8B E5 09 10 A0 E1 18 20 A0 E3 18 50 8B E5 1C 60 8B E5 20 70 8B E5 24 80 8B E5 3C 90 8B E5 48 00 8B E2 ?? ?? ?? EB 28 30 8B E2 18 00 93 E8 46 1E 8D E2 30 30 8B E5 }
	condition:
		$pattern
}

rule __divdi3_639efc7939fda424f83e3133f04ee9d8 {
	meta:
		aliases = "__divdi3"
		size = "1408"
		objfiles = "_divdi3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 00 51 E3 18 D0 4D E2 00 40 A0 E3 00 50 A0 E3 00 C0 A0 A3 30 00 8D E8 08 C0 8D A5 02 40 A0 E1 03 50 A0 E1 D3 00 00 BA 00 00 53 E3 D7 00 00 BA 00 00 55 E3 01 70 A0 E1 04 60 A0 E1 00 90 A0 E1 3C 00 00 1A 01 00 54 E1 49 00 00 9A 01 08 54 E3 30 01 00 2A FF 00 54 E3 18 00 A0 83 20 00 A0 93 00 30 A0 93 08 30 A0 83 36 13 A0 E1 04 25 9F E5 01 30 D2 E7 03 10 50 E0 17 21 A0 11 20 30 61 12 16 61 A0 11 39 73 82 11 26 88 A0 E1 19 91 A0 11 07 00 A0 E1 08 10 A0 E1 ?? ?? ?? EB 08 10 A0 E1 00 A0 A0 E1 07 00 A0 E1 ?? ?? ?? EB 06 78 A0 E1 27 78 A0 E1 97 0A 02 E0 29 38 A0 E1 00 48 83 E1 04 00 52 E1 }
	condition:
		$pattern
}

rule __moddi3_eb8fa956a4e0d0390f52dc5eec4a65c0 {
	meta:
		aliases = "__moddi3"
		size = "1424"
		objfiles = "_moddi3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 00 51 E3 24 D0 4D E2 00 40 A0 E3 00 50 A0 E3 00 C0 A0 A3 30 00 8D E8 08 C0 8D A5 02 40 A0 E1 03 50 A0 E1 D3 00 00 BA 00 00 53 E3 CE 00 00 BA 00 00 55 E3 04 60 A0 E1 00 90 A0 E1 01 70 A0 E1 45 00 00 1A 01 00 54 E1 6F 00 00 9A 01 08 54 E3 D3 00 00 3A FF 34 E0 E3 03 00 54 E1 18 30 A0 83 10 30 A0 93 08 00 A0 83 10 00 A0 93 36 13 A0 E1 10 25 9F E5 01 30 D2 E7 03 30 50 E0 03 B0 A0 11 17 2B A0 11 20 30 6B 12 16 6B A0 11 39 73 82 11 26 A8 A0 E1 0A 10 A0 E1 07 00 A0 E1 03 B0 A0 01 19 9B A0 11 ?? ?? ?? EB 06 58 A0 E1 25 58 A0 E1 95 00 08 E0 0A 10 A0 E1 07 00 A0 E1 ?? ?? ?? EB 29 38 A0 E1 }
	condition:
		$pattern
}

rule qsort_6745dfad242f05073776e842260044dd {
	meta:
		aliases = "__GI_qsort, qsort"
		size = "208"
		objfiles = "qsort@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 00 52 E3 01 00 51 13 04 D0 4D E2 01 50 A0 E1 02 A0 A0 E1 00 00 8D E5 03 B0 A0 E1 28 00 00 9A 00 40 A0 E3 03 70 A0 E3 01 60 41 E2 94 07 03 E0 06 00 A0 E1 07 10 A0 E1 01 40 83 E2 ?? ?? ?? EB 00 00 54 E1 F8 FF FF 3A 9A 04 07 E0 95 0A 09 E0 07 80 A0 E1 08 60 A0 E1 00 30 9D E5 06 60 67 E0 06 40 83 E0 07 50 84 E0 04 00 A0 E1 05 10 A0 E1 0F E0 A0 E1 0B F0 A0 E1 00 00 50 E3 08 00 00 DA 0A 10 A0 E1 00 20 D4 E5 00 30 D5 E5 01 10 51 E2 01 30 C4 E4 01 20 C5 E4 F9 FF FF 1A 07 00 56 E1 EC FF FF 2A 0A 80 88 E0 09 00 58 E1 E8 FF FF 3A 07 00 6A E0 03 10 A0 E3 ?? ?? ?? EB 00 70 50 E2 E2 FF FF 1A }
	condition:
		$pattern
}

rule __res_search_0088b238a8be7567acb8079d47c7775e {
	meta:
		aliases = "__res_search"
		size = "628"
		objfiles = "res_query@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 00 53 E3 00 00 50 13 24 D0 4D E2 00 A0 A0 E1 03 90 A0 E1 0C 10 8D E5 08 20 8D E5 04 00 00 1A ?? ?? ?? EB 00 30 E0 E3 03 20 A0 E1 00 30 80 E5 86 00 00 EA 20 62 9F E5 20 52 9F E5 14 40 8D E2 1C 22 9F E5 1C 12 9F E5 1C 32 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 02 9F E5 0F E0 A0 E1 06 F0 A0 E1 ?? ?? ?? EB 00 70 90 E5 00 80 A0 E1 01 10 A0 E3 04 00 A0 E1 51 B0 D8 E5 0F E0 A0 E1 05 F0 A0 E1 01 00 17 E3 01 00 00 1A ?? ?? ?? EB EA FF FF EA ?? ?? ?? EB 00 40 A0 E3 00 40 80 E5 10 00 8D E5 ?? ?? ?? EB 04 60 A0 E1 01 30 A0 E3 00 50 A0 E1 0A 20 A0 E1 00 30 80 E5 02 00 00 EA 2E 00 53 E3 }
	condition:
		$pattern
}

rule __udivdi3_81352010651b1652180df2aba0ea9a86 {
	meta:
		aliases = "__udivdi3"
		size = "1300"
		objfiles = "_udivdi3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 00 53 E3 00 50 A0 E3 14 D0 4D E2 00 40 A0 E3 30 00 8D E8 01 60 A0 E1 02 50 A0 E1 00 90 A0 E1 3D 00 00 1A 01 00 52 E1 56 00 00 9A 01 08 52 E3 1E 01 00 3A FF 34 E0 E3 03 00 52 E1 18 30 A0 83 10 30 A0 93 08 00 A0 83 10 00 A0 93 35 13 A0 E1 B4 24 9F E5 01 30 D2 E7 03 C0 50 E0 16 2C A0 11 20 30 6C 12 15 5C A0 11 39 63 82 11 25 88 A0 E1 08 10 A0 E1 06 00 A0 E1 19 9C A0 11 ?? ?? ?? EB 08 10 A0 E1 00 A0 A0 E1 06 00 A0 E1 ?? ?? ?? EB 05 78 A0 E1 27 78 A0 E1 97 0A 02 E0 29 38 A0 E1 00 48 83 E1 04 00 52 E1 05 00 00 9A 05 40 94 E0 01 A0 4A E2 02 00 00 2A 04 00 52 E1 01 A0 4A 82 05 40 84 80 }
	condition:
		$pattern
}

rule __umoddi3_b90429ef9916d795f2a7b8eee1956967 {
	meta:
		aliases = "__umoddi3"
		size = "1260"
		objfiles = "_umoddi3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 00 53 E3 00 50 A0 E3 18 D0 4D E2 00 40 A0 E3 30 00 8D E8 00 90 A0 E1 02 50 A0 E1 01 60 A0 E1 3D 00 00 1A 01 00 52 E1 59 00 00 9A 01 08 52 E3 B5 00 00 3A FF 34 E0 E3 03 00 52 E1 18 30 A0 83 10 30 A0 93 08 00 A0 83 10 00 A0 93 35 13 A0 E1 8C 24 9F E5 01 30 D2 E7 03 30 50 E0 03 B0 A0 11 16 2B A0 11 20 30 6B 12 15 5B A0 11 39 63 82 11 25 A8 A0 E1 0A 10 A0 E1 06 00 A0 E1 03 B0 A0 01 19 9B A0 11 ?? ?? ?? EB 05 78 A0 E1 27 78 A0 E1 97 00 08 E0 0A 10 A0 E1 06 00 A0 E1 ?? ?? ?? EB 29 38 A0 E1 00 48 83 E1 04 00 58 E1 03 00 00 9A 05 40 94 E0 01 00 00 2A 04 00 58 E1 05 40 84 80 04 40 68 E0 }
	condition:
		$pattern
}

rule __udivmoddi4_6d8f2dc2dc61194421c2da621082d260 {
	meta:
		aliases = "__udivmoddi4"
		size = "1616"
		objfiles = "_udivmoddi4@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 00 53 E3 34 D0 4D E2 00 A0 A0 E3 00 B0 A0 E3 00 0C 8D E8 02 60 A0 E1 00 90 A0 E1 01 50 A0 E1 50 00 00 1A 01 00 52 E1 7E 00 00 9A 01 08 52 E3 FF 00 00 3A FF 34 E0 E3 03 00 52 E1 18 30 A0 83 10 30 A0 93 08 00 A0 83 10 00 A0 93 36 13 A0 E1 F0 25 9F E5 01 30 D2 E7 03 00 50 E0 15 20 A0 11 20 30 60 12 16 60 A0 11 39 53 82 11 26 88 A0 E1 19 90 A0 11 0C 00 8D E5 08 10 A0 E1 05 00 A0 E1 ?? ?? ?? EB 08 10 A0 E1 10 00 8D E5 05 00 A0 E1 ?? ?? ?? EB 06 78 A0 E1 10 20 9D E5 27 78 A0 E1 97 02 02 E0 29 38 A0 E1 00 48 83 E1 04 00 52 E1 08 00 00 9A 10 10 9D E5 06 40 94 E0 01 10 41 E2 10 10 8D E5 }
	condition:
		$pattern
}

rule __GI_modf_56804936c5e6e22afeb8d38cb5a589aa {
	meta:
		aliases = "modf, __GI_modf"
		size = "372"
		objfiles = "s_modf@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 00 30 A0 E1 24 D0 4D E2 01 40 A0 E1 1C 30 8D E5 20 40 8D E5 1C 90 9D E5 49 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF CF 43 E2 00 40 A0 E3 00 30 A0 E3 03 C0 4C E2 03 70 A0 E1 04 80 A0 E1 13 00 5C E3 00 50 A0 E1 01 60 A0 E1 00 20 8D E5 14 30 8D E5 18 40 8D E5 0C 30 8D E5 10 40 8D E5 80 01 8D E9 03 A0 A0 E1 04 B0 A0 E1 20 E0 9D E5 1A 00 00 CA 00 00 5C E3 02 31 09 B2 00 40 A0 B3 18 00 82 B8 35 00 00 BA E0 30 9F E5 53 2C A0 E1 09 30 02 E0 0E C0 93 E1 07 00 00 1A 02 31 00 E2 00 40 9D E5 14 30 8D E5 18 C0 8D E5 60 00 84 E8 14 50 8D E2 60 00 95 E8 28 00 00 EA 02 20 C9 E1 00 70 A0 E3 0C 20 8D E5 }
	condition:
		$pattern
}

rule inet_ntop4_5d7567b91f1c363dded098215ffe787c {
	meta:
		aliases = "inet_ntop4"
		size = "320"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 30 A0 E3 1C D0 4D E2 03 60 A0 E1 00 B0 A0 E1 03 A0 A0 E1 04 10 8D E5 00 20 8D E5 0B 30 CD E5 2B 00 00 EA 0A 40 DB E7 04 00 A0 E1 ?? ?? ?? EB 30 30 80 E2 11 30 45 E5 11 30 55 E5 01 60 86 E2 1C 20 8D E2 30 00 53 E3 0A 10 A0 E3 04 00 A0 E1 06 80 82 E0 0A 90 8B E0 09 00 00 1A ?? ?? ?? EB 0A 10 A0 E3 FF 00 00 E2 ?? ?? ?? EB 30 00 80 E2 FF 00 00 E2 30 00 50 E3 06 70 A0 11 11 00 45 E5 06 00 00 EA ?? ?? ?? EB 0A 10 A0 E3 FF 00 00 E2 ?? ?? ?? EB 30 00 80 E2 11 00 48 E5 01 70 86 E2 00 00 D9 E5 0A 10 A0 E3 ?? ?? ?? EB 1C C0 8D E2 01 10 87 E2 07 30 8C E0 30 00 80 E2 11 00 43 E5 01 20 8C E0 }
	condition:
		$pattern
}

rule _time_tzset_d20af58a6a1e51d33b817986bd169e99 {
	meta:
		aliases = "_time_tzset"
		size = "1240"
		objfiles = "tzset@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 30 A0 E3 88 D0 4D E2 6C 14 9F E5 6C 24 9F E5 84 30 8D E5 00 90 A0 E1 64 34 9F E5 74 00 8D E2 0F E0 A0 E1 03 F0 A0 E1 58 34 9F E5 4C 04 9F E5 0F E0 A0 E1 03 F0 A0 E1 4C 04 9F E5 ?? ?? ?? EB 00 40 50 E2 17 00 00 1A 40 04 9F E5 04 10 A0 E1 ?? ?? ?? EB 00 60 50 E2 04 50 A0 B1 0F 00 00 BA 0D 10 A0 E1 44 20 A0 E3 ?? ?? ?? EB 00 00 50 E3 07 00 00 BA 00 00 8D E0 0D 00 50 E1 04 00 00 9A 01 30 50 E5 0A 00 53 E3 0D 50 A0 01 01 40 40 05 00 00 00 0A 00 50 A0 E3 06 00 A0 E1 ?? ?? ?? EB 00 40 55 E2 02 00 00 0A 00 30 D4 E5 00 00 53 E3 0A 00 00 1A D8 33 9F E5 00 C0 A0 E3 0C 10 A0 E1 30 20 A0 E3 }
	condition:
		$pattern
}

rule _time_t2tm_b73b0a543655e03e61efd11a089d4cf1 {
	meta:
		aliases = "_time_t2tm"
		size = "480"
		objfiles = "_time_t2tm@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 30 A0 E3 B8 91 9F E5 1C 30 82 E5 00 50 90 E5 B0 71 9F E5 02 80 A0 E1 09 90 81 E0 02 60 A0 E1 00 20 D7 E5 01 30 D7 E5 03 44 82 E1 07 00 54 E3 04 A0 A0 E1 0C 00 00 1A 04 10 A0 E1 05 00 A0 E1 ?? ?? ?? EB 04 10 A0 E1 0B 00 80 E2 ?? ?? ?? EB 02 30 D7 E5 03 20 D7 E5 02 34 83 E1 03 31 A0 E1 00 B0 A0 E1 01 40 83 E2 09 50 85 E0 05 00 A0 E1 04 10 A0 E1 ?? ?? ?? EB 94 00 03 E0 03 50 55 E0 04 50 85 40 01 00 40 42 07 00 5A E3 05 00 00 1A 01 30 44 E2 03 00 55 E1 10 30 96 05 01 30 83 02 10 30 86 05 01 50 45 02 02 70 87 E2 00 20 D7 E5 01 30 D7 E5 3C 00 54 E3 00 50 86 D5 00 00 86 C5 04 C0 86 E2 }
	condition:
		$pattern
}

rule _stdlib_wcsto_ll_c9e664fa5bb5623ac33e1c020f70360d {
	meta:
		aliases = "_stdlib_wcsto_ll"
		size = "572"
		objfiles = "_stdlib_wcsto_ll@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 40 A0 E1 10 D0 4D E2 02 70 A0 E1 00 60 A0 E1 0C 10 8D E5 08 30 8D E5 00 00 00 EA 04 60 86 E2 00 00 96 E5 ?? ?? ?? EB 00 00 50 E3 FA FF FF 1A 00 20 96 E5 2B 00 52 E3 04 00 00 0A 2D 00 52 E3 00 90 A0 11 01 90 A0 03 01 00 00 0A 01 00 00 EA 00 90 A0 E1 04 60 86 E2 10 10 D7 E3 04 00 A0 11 0E 00 00 1A 00 30 96 E5 30 00 53 E3 0A 70 87 E2 04 00 A0 11 07 00 00 1A 04 30 B6 E5 20 30 83 E3 78 00 53 E3 02 70 47 E2 06 00 A0 01 06 00 A0 11 87 70 A0 01 04 60 86 02 10 00 57 E3 10 70 A0 A3 02 30 47 E2 22 00 53 E3 00 40 A0 93 00 50 A0 93 07 A0 A0 91 CA BF A0 91 01 00 00 9A 39 00 00 EA 06 00 A0 E1 }
	condition:
		$pattern
}

rule des_setkey_d908e707c9d07d5fa116b0a92502c5f8 {
	meta:
		aliases = "des_setkey"
		size = "800"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { F0 4F 2D E9 00 40 A0 E1 14 D0 4D E2 5E FD FF EB 00 50 94 E8 FF 08 0E E2 FF 18 0C E2 2C 3C A0 E1 2E 2C A0 E1 21 34 83 E1 20 24 82 E1 FF 1C 0C E2 FF 0C 0E E2 00 24 82 E1 01 34 83 E1 0C 9C 83 E1 0E BC 82 E1 09 00 9B E1 07 00 00 0A A0 32 9F E5 00 30 93 E5 03 00 59 E1 03 00 00 1A 94 32 9F E5 00 30 93 E5 03 00 5B E1 9F 00 00 0A 88 52 9F E5 88 42 9F E5 A9 37 A0 E1 A9 23 A0 E1 7F 3F 03 E2 7F 2F 02 E2 04 C0 83 E0 04 E0 82 E0 05 20 82 E0 00 84 92 E5 00 22 9C E5 A9 CC A0 E1 0C 61 94 E7 89 00 A0 E1 05 30 83 E0 7F 0F 00 E2 00 12 93 E5 04 60 8D E5 04 60 80 E0 AB 3C A0 E1 0C C1 95 E7 00 66 96 E5 00 74 9E E5 }
	condition:
		$pattern
}

rule __dns_lookup_e726d1836d2b2d4c147244505241fe87 {
	meta:
		aliases = "__dns_lookup"
		size = "1892"
		objfiles = "dnslookup@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 40 A0 E1 1E DE 4D E2 02 0C A0 E3 03 B0 A0 E1 10 10 8D E5 0C 20 8D E5 ?? ?? ?? EB 00 A0 A0 E1 04 00 A0 E1 ?? ?? ?? EB F8 36 9F E5 03 00 50 E1 14 00 8D E5 00 00 E0 83 00 10 A0 83 20 00 8D 85 30 10 8D 85 A6 01 00 8A 14 20 9D E5 82 00 82 E2 ?? ?? ?? EB 00 00 50 E3 00 00 5A 13 30 00 8D E5 00 50 A0 13 01 50 A0 03 9B 01 00 0A 00 30 D4 E5 00 00 53 E3 98 01 00 0A 14 C0 9D E5 04 30 8C E0 01 30 53 E5 04 10 A0 E1 0C 20 A0 E1 18 30 8D E5 ?? ?? ?? EB 30 10 9D E5 14 20 9D E5 01 30 81 E2 00 00 E0 E3 02 30 83 E0 20 00 8D E5 2C 50 8D E5 04 30 8D E5 34 00 8D E5 00 90 A0 E1 20 30 9D E5 01 00 73 E3 }
	condition:
		$pattern
}

rule realpath_0c1598add535aa7d79844f4a76c4365d {
	meta:
		aliases = "realpath"
		size = "708"
		objfiles = "realpath@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 50 50 E2 01 DA 4D E2 0C D0 4D E2 01 70 A0 E1 03 00 00 1A ?? ?? ?? EB 05 70 A0 E1 16 30 A0 E3 05 00 00 EA 00 40 D5 E5 00 00 54 E3 04 00 00 1A ?? ?? ?? EB 04 70 A0 E1 02 30 A0 E3 00 30 80 E5 98 00 00 EA ?? ?? ?? EB 68 32 9F E5 03 00 50 E1 03 00 00 9A ?? ?? ?? EB 00 70 A0 E3 24 30 A0 E3 F5 FF FF EA 01 3A 8D E2 0B 30 83 E2 03 40 60 E0 05 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 00 57 E3 00 20 A0 13 04 60 A0 E1 08 20 8D 15 03 00 00 1A 01 0A A0 E3 ?? ?? ?? EB 08 00 8D E5 00 70 A0 E1 00 30 D4 E5 FF 9E 87 E2 2F 00 53 E3 0E 90 89 E2 13 00 00 0A 07 00 A0 E1 FC 11 9F E5 ?? ?? ?? EB 00 00 50 E3 }
	condition:
		$pattern
}

rule realloc_f62123fea5d38f84a9c718e221baa796 {
	meta:
		aliases = "realloc"
		size = "872"
		objfiles = "realloc@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 50 50 E2 10 D0 4D E2 01 40 A0 E1 03 00 00 1A 01 00 A0 E1 ?? ?? ?? EB 00 40 A0 E1 C7 00 00 EA 00 00 51 E3 01 00 00 1A ?? ?? ?? EB C3 00 00 EA 0D 00 A0 E1 10 13 9F E5 10 23 9F E5 10 33 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 03 9F E5 04 33 9F E5 0F E0 A0 E1 03 F0 A0 E1 21 00 74 E3 04 00 00 9A ?? ?? ?? EB 00 40 A0 E3 0C 30 A0 E3 00 30 80 E5 B2 00 00 EA 0B 00 84 E2 04 20 15 E5 0F 00 50 E3 10 90 A0 93 07 90 C0 83 02 00 12 E3 08 A0 45 E2 03 60 C2 E3 73 00 00 1A 09 00 56 E1 06 00 A0 21 56 00 00 2A B0 02 9F E5 2C 30 90 E5 06 40 8A E0 03 00 54 E1 04 10 94 E5 0E 00 00 1A 03 30 C1 E3 06 10 83 E0 }
	condition:
		$pattern
}

rule bindresvport_728b4779945bb7c23ea1b4a25f041ef3 {
	meta:
		aliases = "__GI_bindresvport, bindresvport"
		size = "356"
		objfiles = "bindresvport@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 50 51 E2 10 D0 4D E2 00 90 A0 E1 07 00 00 1A 0D 00 A0 E1 10 20 A0 E3 ?? ?? ?? EB 01 50 CD E5 02 30 A0 E3 0D 50 A0 E1 00 30 CD E5 09 00 00 EA 00 30 D5 E5 01 20 D5 E5 02 34 83 E1 02 00 53 E3 04 00 00 0A ?? ?? ?? EB 60 30 A0 E3 00 C0 E0 E3 00 30 80 E5 3B 00 00 EA F4 40 9F E5 01 30 D4 E5 00 20 D4 E5 03 3C A0 E1 43 38 92 E1 06 00 00 1A ?? ?? ?? EB 6A 1F A0 E3 ?? ?? ?? EB 96 0F 80 E2 40 34 A0 E1 01 30 C4 E5 00 00 C4 E5 ?? ?? ?? EB 04 60 A0 E1 62 30 A0 E3 00 80 A0 E1 00 70 A0 E3 00 C0 E0 E3 58 B0 A0 E3 02 A0 A0 E3 00 30 80 E5 16 00 00 EA 01 C0 D6 E5 00 30 D6 E5 0C 34 83 E1 01 C0 83 E2 }
	condition:
		$pattern
}

rule getsubopt_26faa3927999ecc27bf3b7c3e9c2ee20 {
	meta:
		aliases = "getsubopt"
		size = "216"
		objfiles = "getsubopt@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 60 90 E5 00 30 D6 E5 04 D0 4D E2 00 00 53 E3 00 90 A0 E1 00 10 8D E5 02 B0 A0 E1 28 00 00 0A 2C 10 A0 E3 06 00 A0 E1 ?? ?? ?? EB 00 40 A0 E1 3D 10 A0 E3 06 00 A0 E1 04 20 66 E0 ?? ?? ?? EB 00 00 50 E3 00 70 A0 11 04 70 A0 01 00 80 A0 E3 07 A0 66 E0 0F 00 00 EA ?? ?? ?? EB 00 00 50 E3 0B 00 00 1A 0A 10 D5 E7 00 00 51 E3 08 00 00 1A 04 00 57 E1 01 10 87 12 00 10 8B E5 00 30 D4 E5 00 00 53 E3 00 30 A0 13 01 30 C4 14 00 40 89 E5 0C 00 00 EA 01 80 88 E2 00 30 9D E5 08 51 93 E7 00 10 55 E2 06 00 A0 E1 0A 20 A0 E1 E9 FF FF 1A 00 60 8B E5 00 30 D4 E5 00 00 53 E3 01 50 C4 14 00 40 89 E5 }
	condition:
		$pattern
}

rule _stdlib_wcsto_l_ed189fa6f98614ac6faba7d6447b87b7 {
	meta:
		aliases = "_stdlib_wcsto_l"
		size = "400"
		objfiles = "_stdlib_wcsto_l@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 60 A0 E1 01 90 A0 E1 02 50 A0 E1 03 B0 A0 E1 00 40 A0 E1 00 00 00 EA 04 40 84 E2 00 00 94 E5 ?? ?? ?? EB 00 00 50 E3 FA FF FF 1A 00 20 94 E5 2B 00 52 E3 04 00 00 0A 2D 00 52 E3 00 70 A0 11 01 70 A0 03 01 00 00 0A 01 00 00 EA 00 70 A0 E1 04 40 84 E2 10 30 D5 E3 0D 00 00 1A 00 30 94 E5 30 00 53 E3 0A 50 85 E2 07 00 00 1A 04 30 B4 E5 20 30 83 E3 78 00 53 E3 02 50 45 E2 04 60 A0 01 04 60 A0 11 85 50 A0 01 04 40 84 02 10 00 55 E3 10 50 A0 A3 02 30 45 E2 22 00 53 E3 00 10 A0 83 29 00 00 8A 05 10 A0 E1 00 00 E0 E3 ?? ?? ?? EB 05 10 A0 E1 00 30 A0 E1 00 00 E0 E3 FF A0 03 E2 ?? ?? ?? EB }
	condition:
		$pattern
}

rule svcudp_recv_a7ef6222c11162d1444ed303fbf68401 {
	meta:
		aliases = "svcudp_recv"
		size = "564"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 60 A0 E1 30 50 90 E5 10 D0 4D E2 34 00 80 E2 08 00 8D E5 01 A0 A0 E1 3C B0 86 E2 10 40 86 E2 58 90 86 E2 0C 30 9B E5 10 C0 A0 E3 00 20 A0 E3 0C C0 8D E5 02 00 53 E1 0B 70 A0 E1 0B 10 A0 E1 2C C0 96 E5 08 80 9D E5 10 00 00 0A 34 C0 86 E5 00 30 95 E5 01 00 A0 E3 04 30 88 E5 DC C0 A0 E3 10 30 A0 E3 08 01 8B E9 0C 00 8B E5 10 90 8B E5 14 C0 8B E5 3C 40 86 E5 00 00 96 E5 ?? ?? ?? EB 00 00 50 E3 04 30 9B A5 0C 30 8D A5 05 00 00 EA 00 20 95 E5 00 00 96 E5 0C 10 A0 E1 0C C0 8D E2 10 10 8D E8 ?? ?? ?? EB 0C 30 9D E5 01 00 70 E3 0C 30 86 E5 04 00 00 1A ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 }
	condition:
		$pattern
}

rule inet_network_df6a668c4d7b53111c618e973ba9a301 {
	meta:
		aliases = "__GI_inet_network, inet_network"
		size = "304"
		objfiles = "inet_net@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 60 A0 E3 01 A0 A0 E3 06 70 A0 E1 06 80 A0 E1 0A B0 A0 E3 0A 90 A0 E1 00 30 D0 E5 30 00 53 E3 08 E0 A0 11 0B 50 A0 11 07 00 00 1A 01 30 F0 E5 58 00 53 E3 78 00 53 13 0A E0 A0 11 08 50 A0 13 01 00 80 02 08 E0 A0 01 10 50 A0 03 08 40 A0 E1 1F 00 00 EA CC 20 9F E5 00 30 92 E5 03 20 81 E0 03 10 D1 E7 01 30 D2 E5 03 24 81 E1 08 00 12 E3 0A 00 00 0A 08 00 55 E3 00 30 A0 13 01 30 A0 03 37 00 5C E3 00 30 A0 93 00 00 53 E3 22 00 00 1A 95 04 03 E0 30 30 43 E2 0C 40 83 E0 08 00 00 EA 10 00 55 E3 0E 00 00 1A 10 00 12 E3 0C 00 00 0A 02 00 12 E3 41 30 A0 03 61 30 A0 13 04 32 63 E0 0A 40 83 E2 }
	condition:
		$pattern
}

rule _uintmaxtostr_ff219620d4d13489111ba0b6d462a9ca {
	meta:
		aliases = "_uintmaxtostr"
		size = "340"
		objfiles = "_uintmaxtostr@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 70 53 E2 04 D0 4D E2 00 80 A0 E1 01 50 A0 E1 02 60 A0 E1 07 00 00 AA 00 00 52 E3 00 70 67 E2 04 00 00 AA 01 20 A0 E3 00 50 75 E2 00 60 E6 E2 00 20 8D E5 01 00 00 EA 00 30 A0 E3 00 30 8D E5 00 A0 A0 E3 00 A0 C8 E5 07 10 A0 E1 00 00 E0 E3 ?? ?? ?? EB 07 10 A0 E1 00 B0 A0 E1 00 00 E0 E3 ?? ?? ?? EB 01 90 80 E2 07 00 59 E1 0A 90 A0 01 01 B0 8B 02 06 A0 A0 E1 05 60 A0 E1 00 00 5A E3 06 00 A0 E1 07 10 A0 E1 19 00 00 0A 0A 00 A0 E1 ?? ?? ?? EB 07 10 A0 E1 00 40 A0 E1 0A 00 A0 E1 ?? ?? ?? EB 07 10 A0 E1 00 A0 A0 E1 06 00 A0 E1 ?? ?? ?? EB 99 04 05 E0 07 10 A0 E1 00 50 85 E0 06 00 A0 E1 }
	condition:
		$pattern
}

rule get_myaddress_57038de43a93fd56bb60fbcf2d1b740d {
	meta:
		aliases = "get_myaddress"
		size = "348"
		objfiles = "get_myaddress@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 70 A0 E1 01 DA 4D E2 02 00 A0 E3 28 D0 4D E2 00 10 A0 E1 00 20 A0 E3 ?? ?? ?? EB 00 A0 50 E2 1C 01 9F B5 0F 00 00 BA 01 3A A0 E3 28 C0 8D E2 03 E0 8D E0 28 C0 4C E2 01 2A 8D E2 04 11 9F E5 20 20 82 E2 20 30 8E E5 24 C0 8E E5 ?? ?? ?? EB 00 00 50 E3 00 90 A0 A3 01 8A 8D A2 01 B0 A0 A3 03 00 00 AA E0 00 9F E5 ?? ?? ?? EB 01 00 A0 E3 ?? ?? ?? EB 01 1A 8D E2 24 50 91 E5 20 60 91 E5 25 00 00 EA 05 40 A0 E1 0F 00 B4 E8 08 C0 A0 E1 0F 00 AC E8 0F 00 94 E8 0F 00 8C E8 0A 00 A0 E1 A8 10 9F E5 08 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 9C 00 9F B5 EB FF FF BA 01 2A 8D E2 11 30 D2 E5 10 20 D2 E5 }
	condition:
		$pattern
}

rule __get_myaddress_07b8b83d818729ba861a811bdb90d4d8 {
	meta:
		aliases = "__get_myaddress"
		size = "364"
		objfiles = "pmap_clnt@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 70 A0 E1 01 DA 4D E2 02 00 A0 E3 28 D0 4D E2 00 10 A0 E1 00 20 A0 E3 ?? ?? ?? EB 00 A0 50 E2 2C 01 9F B5 0F 00 00 BA 01 3A A0 E3 28 C0 8D E2 03 E0 8D E0 28 C0 4C E2 01 2A 8D E2 14 11 9F E5 20 20 82 E2 20 30 8E E5 24 C0 8E E5 ?? ?? ?? EB 00 00 50 E3 01 90 A0 A3 01 8A 8D A2 00 B0 A0 A3 03 00 00 AA F0 00 9F E5 ?? ?? ?? EB 01 00 A0 E3 ?? ?? ?? EB 01 1A 8D E2 24 50 91 E5 20 60 91 E5 28 00 00 EA 05 40 A0 E1 0F 00 B4 E8 08 C0 A0 E1 0F 00 AC E8 0F 00 94 E8 0F 00 8C E8 0A 00 A0 E1 B8 10 9F E5 08 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 AC 00 9F B5 EB FF FF BA 01 2A 8D E2 11 30 D2 E5 10 20 D2 E5 }
	condition:
		$pattern
}

rule __parsespent_eeff81e8666c4d15f8a533d41670a317 {
	meta:
		aliases = "__parsespent"
		size = "172"
		objfiles = "__parsespent@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 70 A0 E3 04 D0 4D E2 94 B0 9F E5 00 60 A0 E1 01 40 A0 E1 0D 90 A0 E1 00 A0 E0 E3 07 80 A0 E1 01 00 57 E3 04 00 A0 E1 3A 10 A0 E3 07 50 DB E7 04 00 00 CA 05 40 86 E7 ?? ?? ?? EB 00 20 50 E2 10 00 00 1A 13 00 00 EA 0A 20 A0 E3 04 00 A0 E1 0D 10 A0 E1 ?? ?? ?? EB 00 20 9D E5 04 00 52 E1 05 00 86 E7 05 A0 86 07 08 00 57 E3 00 00 D2 E5 02 00 00 1A 00 00 50 E3 07 00 00 0A 05 00 00 EA 3A 00 50 E3 03 00 00 1A 01 80 C2 E4 01 70 87 E2 02 40 A0 E1 E1 FF FF EA 16 00 A0 E3 04 D0 8D E2 F0 8F BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_getaddrinfo_20020f8392201172c41de0346ff7818b {
	meta:
		aliases = "getaddrinfo, __GI_getaddrinfo"
		size = "764"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 80 50 E2 40 D0 4D E2 00 00 A0 E3 3C 00 8D E5 01 50 A0 E1 02 60 A0 E1 00 30 8D E5 05 00 00 0A 00 30 D8 E5 2A 00 53 E3 02 00 00 1A 01 30 D8 E5 00 00 53 E1 00 80 A0 01 00 00 55 E3 05 00 00 0A 00 30 D5 E5 2A 00 53 E3 02 00 00 1A 01 30 D5 E5 00 00 53 E3 00 50 A0 03 05 20 98 E1 9F 00 00 0A 00 00 56 E3 05 00 00 1A 10 40 8D E2 06 10 A0 E1 04 00 A0 E1 20 20 A0 E3 ?? ?? ?? EB 04 60 A0 E1 00 20 96 E5 43 3E C2 E3 0F 30 C3 E3 00 00 53 E3 94 00 00 1A 01 30 78 E2 00 30 A0 33 A2 20 13 E0 90 00 00 1A 00 00 55 E3 1E 00 00 0A 00 30 D5 E5 00 00 53 E3 1B 00 00 0A 05 00 A0 E1 38 10 8D E2 0A 20 A0 E3 }
	condition:
		$pattern
}

rule _dl_parse_2661cfda3cef8a62ba7848346b13aefd {
	meta:
		aliases = "_dl_parse"
		size = "264"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { F0 4F 2D E9 00 80 A0 E3 54 90 80 E2 00 0A 99 E8 0C D0 4D E2 A3 31 A0 E1 00 70 A0 E1 02 60 A0 E1 08 A0 A0 E1 0A 00 8D E9 26 00 00 EA 04 40 96 E5 30 C0 9D E5 00 90 8D E5 0F E0 A0 E1 0C F0 A0 E1 00 50 50 E2 1D 00 00 0A A0 00 9F E5 24 44 A0 E1 00 20 90 E5 98 10 9F E5 02 00 A0 E3 ?? ?? ?? EB 00 00 54 E3 04 22 9B 17 02 00 A0 13 02 20 89 10 80 10 9F 15 ?? ?? ?? 1B 00 00 55 E3 09 00 00 AA 02 00 A0 E3 70 10 9F E5 04 20 D6 E5 ?? ?? ?? EB 00 00 65 E2 01 00 90 EF 01 0A 70 E3 5C 20 9F 85 00 30 60 82 00 30 82 85 00 00 55 E3 03 00 00 DA 02 00 A0 E3 48 10 9F E5 ?? ?? ?? EB 05 80 88 E0 01 A0 8A E2 08 60 86 E2 }
	condition:
		$pattern
}

rule bsearch_50639882ed029c084b7a1b4c4646b609 {
	meta:
		aliases = "bsearch"
		size = "108"
		objfiles = "bsearch@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 90 53 E2 00 A0 A0 E1 01 80 A0 E1 02 50 A0 E1 24 B0 9D E5 00 70 A0 13 0B 00 00 1A 0F 00 00 EA 99 84 26 E0 06 10 A0 E1 0F E0 A0 E1 0B F0 A0 E1 00 00 50 E3 01 70 84 C2 03 00 00 CA 01 00 00 1A 06 00 A0 E1 F0 8F BD E8 04 50 A0 E1 05 30 67 E0 05 00 57 E1 A3 40 87 E0 0A 00 A0 E1 EF FF FF 3A 00 00 A0 E3 F0 8F BD E8 }
	condition:
		$pattern
}

rule __decode_dotted_dba7d09fed0ba10f9fdd7b94fb4ea27c {
	meta:
		aliases = "__decode_dotted"
		size = "248"
		objfiles = "decoded@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 A0 50 E2 00 80 A0 13 04 D0 4D E2 02 B0 A0 E1 03 90 A0 E1 01 C0 A0 13 08 00 A0 11 01 00 00 1A 30 00 00 EA 07 00 A0 E1 0B 00 51 E1 2D 00 00 AA 01 40 DA E7 00 00 54 E3 26 00 00 0A 00 00 5C E3 C0 30 04 E2 01 80 88 12 C0 00 53 E3 01 10 81 E2 09 00 00 1A 0B 00 51 E1 22 00 00 AA 01 20 DA E7 00 00 5C E3 3F 30 04 E2 01 80 88 12 03 14 82 E1 00 70 A0 E1 00 C0 A0 E3 E9 FF FF EA 00 60 84 E0 28 30 9D E5 01 70 86 E2 03 00 57 E1 15 00 00 2A 01 50 84 E0 01 30 85 E2 0B 00 53 E1 11 00 00 2A 01 10 8A E0 00 00 89 E0 04 20 A0 E1 00 C0 8D E5 ?? ?? ?? EB 00 C0 9D E5 05 30 DA E7 00 00 5C E3 04 80 88 10 }
	condition:
		$pattern
}

rule classify_object_over_fdes_44aad21e8666295c5af46a0c5f28eba1 {
	meta:
		aliases = "classify_object_over_fdes"
		size = "324"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { F0 4F 2D E9 00 A0 A0 E3 04 D0 4D E2 00 50 A0 E1 01 40 A0 E1 0A 80 A0 E1 0A 90 A0 E1 0A B0 A0 E1 02 00 00 EA 04 00 A0 E1 8E FC FF EB 00 40 A0 E1 05 00 A0 E1 04 10 A0 E1 8E FC FF EB 00 00 50 E3 35 00 00 1A 04 30 94 E5 00 00 53 E3 F4 FF FF 0A 04 00 A0 E1 7F FC FF EB 00 00 58 E1 00 70 A0 E1 FF 60 09 02 17 00 00 0A A6 FE FF EB FF 60 00 E2 05 10 A0 E1 00 90 A0 E1 06 00 A0 E1 D6 FD FF EB 10 10 95 E5 07 20 C1 E3 82 2A A0 E1 7F 3E A0 E3 08 30 83 E2 A2 2A A0 E1 03 00 52 E1 00 B0 A0 E1 20 00 00 0A 10 20 D5 E5 11 30 D5 E5 03 34 82 E1 A3 31 A0 E1 FF 30 03 E2 03 00 59 E1 04 30 82 13 10 30 C5 15 07 80 A0 E1 }
	condition:
		$pattern
}

rule __GI_openpty_479cc0bd02b6b260eeefefcefa74ab25 {
	meta:
		aliases = "openpty, __GI_openpty"
		size = "236"
		objfiles = "openpty@libutil.a"
	strings:
		$pattern = { F0 4F 2D E9 00 B0 A0 E1 01 DA 4D E2 02 00 A0 E3 01 90 A0 E1 02 60 A0 E1 03 80 A0 E1 ?? ?? ?? EB 01 00 70 E3 00 50 A0 E1 00 00 A0 01 2A 00 00 0A ?? ?? ?? EB 00 00 50 E3 24 00 00 1A 05 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 20 00 00 1A 05 00 A0 E1 0D 10 A0 E1 01 2A A0 E3 ?? ?? ?? EB 00 A0 50 E2 0D 70 A0 E1 19 00 00 1A 0D 00 A0 E1 70 10 9F E5 ?? ?? ?? EB 01 00 70 E3 00 40 A0 E1 13 00 00 0A 00 00 58 E3 08 20 A0 11 02 10 A0 13 ?? ?? ?? 1B 01 2A 8D E2 24 20 92 E5 00 00 52 E3 04 00 A0 11 40 10 9F 15 ?? ?? ?? 1B 00 00 56 E3 00 50 8B E5 06 00 A0 01 00 40 89 E5 07 00 00 0A 06 00 A0 E1 0D 10 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule authunix_create_9fbd3fbcd7648ffd32dde440528782c6 {
	meta:
		aliases = "__GI_authunix_create, authunix_create"
		size = "340"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 B0 A0 E1 72 DF 4D E2 28 00 A0 E3 01 80 A0 E1 02 A0 A0 E1 03 90 A0 E1 ?? ?? ?? EB 00 50 A0 E1 1B 0E A0 E3 ?? ?? ?? EB 00 00 50 E3 00 00 55 13 00 40 A0 E1 00 60 A0 13 01 60 A0 03 09 00 00 1A F8 30 9F E5 F8 00 9F E5 00 10 93 E5 ?? ?? ?? EB 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 ?? ?? ?? EB 00 50 A0 E3 32 00 00 EA D8 30 9F E5 24 00 85 E5 20 30 85 E5 D0 30 9F E5 07 00 93 E8 0C 30 84 E2 07 00 83 E8 0C 30 85 E2 07 00 83 E8 06 10 A0 E1 18 60 84 E5 07 0D 8D E2 ?? ?? ?? EB C0 C1 9D E5 19 7E 8D E2 A8 C1 8D E5 EC C1 9D E5 06 30 A0 E1 0D 10 A0 E1 19 2E A0 E3 07 00 A0 E1 BC C1 8D E5 AC B1 8D E5 }
	condition:
		$pattern
}

rule __GI_atan2_9ab475f1b7ede2c192fcf2b05a3bb6e1 {
	meta:
		aliases = "atan2, __ieee754_atan2, __GI_atan2"
		size = "628"
		objfiles = "e_atan2@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 00 C0 63 E2 30 62 9F E5 03 C0 8C E1 02 91 C2 E3 AC CF 89 E1 08 D0 4D E2 06 00 5C E1 0C 00 8D E8 03 80 A0 E1 02 B0 A0 E1 00 40 A0 E1 01 50 A0 E1 00 60 A0 E1 01 70 A0 E1 01 E0 A0 E1 07 00 00 8A 00 C0 61 E2 01 C0 8C E1 02 71 C0 E3 E8 61 9F E5 AC CF 87 E1 06 00 5C E1 00 A0 A0 E1 01 00 00 9A ?? ?? ?? EB 6E 00 00 EA 03 31 82 E2 01 36 83 E2 08 30 93 E1 02 00 00 1A 08 D0 8D E2 F0 4F BD E8 ?? ?? ?? EA 42 3F A0 E1 02 30 03 E2 0E E0 97 E1 A0 6F 83 E1 06 00 00 1A 03 00 56 E3 06 F1 9F 97 03 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 08 80 99 E1 04 00 00 1A 00 00 5A E3 78 41 9F A5 }
	condition:
		$pattern
}

rule __ivaliduser2_7644dd9c282890119748a8def7b302cf {
	meta:
		aliases = "__ivaliduser2"
		size = "820"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 C0 A0 E3 14 93 9F E5 3C D0 4D E2 00 80 A0 E1 0C B0 A0 E1 10 10 8D E5 0C 20 8D E5 08 30 8D E5 38 C0 8D E5 34 C0 8D E5 AE 00 00 EA 34 30 9D E5 38 20 9D E5 02 30 83 E0 01 B0 43 E5 38 40 9D E5 04 10 A0 E1 00 20 D1 E5 00 00 52 E3 01 10 81 E2 03 00 00 0A 00 30 99 E5 82 30 D3 E7 20 00 13 E3 F7 FF FF 1A 23 00 52 E3 00 00 52 13 9D 00 00 0A 04 00 A0 E1 0A 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 0E 00 00 1A 10 20 98 E5 18 30 98 E5 03 00 52 E1 01 00 D2 34 10 20 88 35 08 00 A0 21 ?? ?? ?? 2B 0A 00 50 E3 01 00 70 13 F5 FF FF 1A 8D 00 00 EA 6C 22 9F E5 00 30 92 E5 01 30 D3 E7 01 30 C4 E4 00 20 D4 E5 }
	condition:
		$pattern
}

rule __md5_Transform_855a021b76e8062507f28ea2fa523668 {
	meta:
		aliases = "__md5_Transform"
		size = "408"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { F0 4F 2D E9 00 C0 A0 E3 4C D0 4D E2 00 50 A0 E1 01 40 A0 E1 0C E0 A0 E1 0C 60 8D E2 04 20 8C E0 02 30 D2 E5 01 10 D2 E5 0C 00 D4 E7 03 38 A0 E1 03 20 D2 E5 01 34 83 E1 00 30 83 E1 04 C0 8C E2 02 3C 83 E1 3F 00 5C E3 0E 31 86 E7 01 E0 8E E2 F1 FF FF 9A 05 60 A0 E1 04 A0 96 E4 28 21 9F E5 28 31 9F E5 00 50 95 E9 0C 40 95 E5 20 81 9F E5 08 90 85 E2 0C B0 85 E2 0A 00 A0 E1 00 70 A0 E3 0C 00 8D E9 2C 00 00 EA 0F 00 17 E3 04 80 88 02 03 00 53 E3 03 F1 9F 97 11 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0C 30 C4 E1 0C 20 0E E0 01 00 00 EA 04 30 CE E1 0C 20 04 E0 02 30 83 E1 05 00 00 EA }
	condition:
		$pattern
}

rule __GI_svcudp_bufcreate_f824f82e443cd50addbd34708778e993 {
	meta:
		aliases = "svcudp_bufcreate, __GI_svcudp_bufcreate"
		size = "544"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 00 70 E3 1C D0 4D E2 10 30 A0 E3 00 70 A0 E1 18 30 8D E5 01 B0 A0 E1 02 80 A0 E1 00 60 A0 13 0A 00 00 1A 02 00 A0 E3 00 10 A0 E1 11 20 A0 E3 ?? ?? ?? EB 00 70 50 E2 01 60 A0 A3 03 00 00 AA C0 01 9F E5 ?? ?? ?? EB 00 A0 A0 E3 6A 00 00 EA 04 40 8D E2 00 10 A0 E3 10 20 A0 E3 04 00 A0 E1 ?? ?? ?? EB 00 50 A0 E3 02 30 A0 E3 07 00 A0 E1 04 10 A0 E1 04 30 CD E5 05 50 CD E5 ?? ?? ?? EB 05 00 50 E1 05 00 00 0A 07 00 A0 E1 04 10 A0 E1 18 20 9D E5 06 50 CD E5 07 50 CD E5 ?? ?? ?? EB 04 10 A0 E1 07 00 A0 E1 18 20 8D E2 ?? ?? ?? EB 00 90 50 E2 08 00 00 0A 4C 01 9F E5 ?? ?? ?? EB 00 00 56 E3 }
	condition:
		$pattern
}

rule svcunix_create_efd36198f9cf39b4a1b63b072cb5fe09 {
	meta:
		aliases = "svcunix_create"
		size = "440"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 00 70 E3 74 D0 4D E2 00 60 A0 E1 10 00 A0 E3 70 00 8D E5 01 90 A0 E1 02 B0 A0 E1 03 40 A0 E1 00 80 A0 13 0A 00 00 1A 01 00 A0 E3 00 10 A0 E1 00 20 A0 E3 ?? ?? ?? EB 00 60 50 E2 01 80 A0 A3 03 00 00 AA 50 01 9F E5 ?? ?? ?? EB 00 50 A0 E3 4E 00 00 EA 00 10 A0 E3 70 20 A0 E3 0D 00 A0 E1 ?? ?? ?? EB 00 A0 A0 E3 01 30 A0 E3 00 30 CD E5 04 00 A0 E1 01 A0 CD E5 ?? ?? ?? EB 01 30 80 E2 03 20 A0 E1 04 10 A0 E1 02 00 8D E2 70 30 8D E5 ?? ?? ?? EB 70 20 9D E5 74 40 8D E2 02 20 82 E2 04 20 24 E5 0D 10 A0 E1 06 00 A0 E1 ?? ?? ?? EB 06 00 A0 E1 0D 10 A0 E1 04 20 A0 E1 ?? ?? ?? EB 0A 00 50 E1 }
	condition:
		$pattern
}

rule __ieee754_log2_decea9f3f0884a7c64a6276e65147b8d {
	meta:
		aliases = "log2, __ieee754_log2"
		size = "1032"
		objfiles = "e_log2@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 01 06 50 E3 00 50 A0 E1 00 C0 A0 E1 0C D0 4D E2 01 60 A0 E1 01 40 A0 E1 00 00 A0 A3 1B 00 00 AA 02 31 C5 E3 01 30 93 E1 07 00 00 1A 05 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 00 20 A0 E1 58 03 9F E5 01 30 A0 E1 00 10 A0 E3 06 00 00 EA 00 00 55 E3 06 00 00 AA 05 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB C4 00 00 EA 28 23 9F E5 00 30 A0 E3 ?? ?? ?? EB 00 50 A0 E1 00 C0 A0 E1 01 60 A0 E1 01 40 A0 E1 35 00 E0 E3 0C 33 9F E5 03 00 5C E1 05 00 A0 C1 06 10 A0 C1 05 20 A0 C1 06 30 A0 C1 B4 00 00 CA FF 14 CC E3 F0 22 9F E5 0F 16 C1 E3 FF 0F 40 E2 02 20 81 E0 03 00 40 E2 }
	condition:
		$pattern
}

rule __GI_log_4996a36e159142cf3e9064acdcf5f7c6 {
	meta:
		aliases = "__ieee754_log, log, __GI_log"
		size = "1492"
		objfiles = "e_log@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 01 06 50 E3 14 D0 4D E2 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 00 70 A0 E1 00 C0 A0 A3 15 00 00 AA 02 31 C0 E3 01 30 93 E1 2C 05 9F 05 00 10 A0 03 04 00 00 0A 00 00 55 E3 06 00 00 AA 05 20 A0 E1 06 30 A0 E1 ?? ?? ?? EB 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? EB 3E 01 00 EA 00 25 9F E5 00 30 A0 E3 ?? ?? ?? EB 35 C0 E0 E3 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 00 70 A0 E1 E4 34 9F E5 03 00 57 E1 05 00 A0 C1 06 10 A0 C1 05 20 A0 C1 06 30 A0 C1 34 00 00 CA FF A4 C7 E3 C8 E4 9F E5 0F A6 CA E3 0E E0 8A E0 C0 34 9F E5 01 E6 0E E2 FF CF 4C E2 03 30 2E E0 03 C0 4C E2 0A 10 83 E1 47 CA 8C E0 01 00 A0 E1 }
	condition:
		$pattern
}

rule rexec_af_4fe9ff713ba123e0a031dc3867137cdd {
	meta:
		aliases = "__GI_rexec_af, rexec_af"
		size = "1048"
		objfiles = "rexec@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 18 A0 E1 63 DF 4D E2 21 C4 A0 E1 FF CC 0C E2 4F 6F 8D E2 B8 41 9D E5 57 5F 8D E2 00 A0 A0 E1 18 20 8D E5 0C 20 8D E5 06 00 A0 E1 21 2C 8C E1 BC 13 9F E5 14 30 8D E5 10 30 8D E5 04 48 A0 E1 B4 B1 9D E5 ?? ?? ?? EB 00 10 A0 E3 20 20 A0 E3 05 00 A0 E1 ?? ?? ?? EB 24 48 A0 E1 00 00 9A E5 06 10 A0 E1 05 20 A0 E1 01 60 A0 E3 02 70 A0 E3 61 3F 8D E2 60 41 8D E5 64 61 8D E5 5C 71 8D E5 ?? ?? ?? EB 00 50 50 E2 D5 00 00 1A 84 31 9D E5 18 10 93 E5 00 00 51 E3 0C 00 00 0A 54 43 9F E5 54 23 9F E5 04 00 A0 E1 ?? ?? ?? EB 00 54 C4 E5 00 40 8A E5 84 31 9D E5 18 10 8D E2 18 00 93 E5 14 20 8D E2 }
	condition:
		$pattern
}

rule __kernel_rem_pio2_fa9957f90510895c58a72242216edb33 {
	meta:
		aliases = "__kernel_rem_pio2"
		size = "2728"
		objfiles = "k_rem_pio2@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 01 30 43 E2 9A DF 4D E2 02 40 A0 E1 18 00 8D E5 1C 30 8D E5 03 00 42 E2 64 3A 9F E5 8C 22 9D E5 02 31 93 E7 14 10 8D E5 18 10 A0 E3 20 30 8D E5 ?? ?? ?? EB C0 0F C0 E1 01 20 80 E2 18 30 A0 E3 92 03 03 E0 20 C0 9D E5 04 B0 63 E0 1C 30 9D E5 00 50 A0 E3 00 40 63 E0 03 80 8C E0 00 60 A0 E3 00 70 A0 E3 2C 00 8D E5 0B 00 00 EA 00 00 54 E3 06 00 A0 B1 07 10 A0 B1 90 12 9D A5 04 01 91 A7 ?? ?? ?? AB 9A 2F 8D E2 85 31 82 E0 F0 00 03 E5 EC 10 03 E5 01 50 85 E2 01 40 84 E2 08 00 55 E1 F1 FF FF DA 00 70 A0 E3 00 90 A0 E3 00 A0 A0 E3 17 00 00 EA F0 20 43 E2 0C 00 92 E8 03 00 90 E8 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __md5_crypt_eb227d79720b72e65b0bb788ce683e87 {
	meta:
		aliases = "__md5_crypt"
		size = "716"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { F0 4F 2D E9 01 40 A0 E1 03 20 A0 E3 A8 12 9F E5 C4 D0 4D E2 00 A0 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 04 80 A0 11 03 80 84 02 08 20 A0 E1 08 10 88 E2 00 00 00 EA 01 20 82 E2 00 30 D2 E5 00 00 53 E3 24 00 53 13 01 00 00 0A 01 00 52 E1 F8 FF FF 3A 58 40 8D E2 04 00 A0 E1 02 90 68 E0 15 FF FF EB 0A 00 A0 E1 ?? ?? ?? EB 00 70 A0 E1 0A 10 A0 E1 04 00 A0 E1 07 20 A0 E1 8E FF FF EB 04 00 A0 E1 30 12 9F E5 03 20 A0 E3 8A FF FF EB 08 10 A0 E1 09 20 A0 E1 04 00 A0 E1 86 FF FF EB 0D 00 A0 E1 04 FF FF EB 0D 00 A0 E1 0A 10 A0 E1 07 20 A0 E1 80 FF FF EB 0D 00 A0 E1 08 10 A0 E1 09 20 A0 E1 7C FF FF EB }
	condition:
		$pattern
}

rule __getgrouplist_internal_3e1a90cff55690a4cb91997aebcaef30 {
	meta:
		aliases = "__getgrouplist_internal"
		size = "264"
		objfiles = "__getgrouplist_internal@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 40 A0 E3 45 DF 4D E2 00 90 A0 E1 00 40 82 E5 20 00 A0 E3 02 A0 A0 E1 01 80 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 70 A0 01 2F 00 00 0A 00 80 80 E5 00 70 A0 E1 BC 10 9F E5 BC 00 9F E5 ?? ?? ?? EB 00 50 50 E2 04 60 A0 11 04 B0 8D 12 34 40 85 15 1A 00 00 1A 24 00 00 EA 0C 31 9D E5 08 00 53 E1 10 41 9D 15 10 00 00 1A 14 00 00 EA ?? ?? ?? EB 00 00 50 E3 0C 00 00 1A 07 00 16 E3 06 00 00 1A 06 11 A0 E1 20 10 81 E2 07 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 11 00 00 0A 00 70 A0 E1 0C 31 9D E5 06 31 87 E7 01 60 86 E2 04 00 00 EA 00 30 94 E5 00 00 53 E2 09 10 A0 E1 04 40 84 E2 EA FF FF 1A 38 00 9F E5 }
	condition:
		$pattern
}

rule __mulsc3_b635d888093e4da6e3dc62ea2a0b7e68 {
	meta:
		aliases = "__mulsc3"
		size = "1492"
		objfiles = "_mulsc3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 60 A0 E1 3C D0 4D E2 02 10 A0 E1 03 70 A0 E1 02 80 A0 E1 00 90 A0 E1 ?? ?? ?? EB 07 10 A0 E1 00 B0 A0 E1 06 00 A0 E1 ?? ?? ?? EB 07 10 A0 E1 00 50 A0 E1 09 00 A0 E1 ?? ?? ?? EB 08 10 A0 E1 00 40 A0 E1 06 00 A0 E1 ?? ?? ?? EB 05 10 A0 E1 2C 00 8D E5 0B 00 A0 E1 ?? ?? ?? EB 2C 10 9D E5 00 A0 A0 E1 04 00 A0 E1 ?? ?? ?? EB 0A 10 A0 E1 30 00 8D E5 0A 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 03 00 00 1A 30 10 9D E5 0A 00 A0 E1 3C D0 8D E2 F0 8F BD E8 30 00 9D E5 00 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 F6 FF FF 0A 09 10 A0 E1 09 00 A0 E1 ?? ?? ?? EB 09 10 A0 E1 0C 00 8D E5 09 00 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __prefix_array_e6fc057725d5ed155ad7d99d617b6267 {
	meta:
		aliases = "__prefix_array"
		size = "184"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 70 A0 E1 02 B0 A0 E1 00 90 A0 E1 ?? ?? ?? EB 01 00 50 E3 00 60 A0 E1 02 00 00 1A 00 30 D9 E5 2F 60 53 E2 01 60 A0 13 00 50 A0 E3 1B 00 00 EA 04 00 97 E7 ?? ?? ?? EB 01 80 80 E2 01 00 88 E2 06 00 80 E0 ?? ?? ?? EB 00 A0 50 E2 09 10 A0 E1 06 20 A0 E1 07 00 00 1A 01 00 00 EA 05 01 97 E7 ?? ?? ?? EB 00 00 55 E3 01 50 45 E2 FA FF FF 1A 01 00 A0 E3 F0 8F BD E8 ?? ?? ?? EB 2F 30 A0 E3 01 30 C0 E4 08 20 A0 E1 04 10 97 E7 ?? ?? ?? EB 04 00 97 E7 ?? ?? ?? EB 04 A0 87 E7 01 50 85 E2 0B 00 55 E1 05 41 A0 E1 E0 FF FF 3A 00 00 A0 E3 F0 8F BD E8 }
	condition:
		$pattern
}

rule xdr_array_af70490755c7ca97d779e05b81f4fac3 {
	meta:
		aliases = "__GI_xdr_array, xdr_array"
		size = "316"
		objfiles = "xdr_array@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 90 A0 E1 02 10 A0 E1 02 50 A0 E1 03 60 A0 E1 00 A0 A0 E1 24 B0 9D E5 00 40 99 E5 ?? ?? ?? EB 00 00 50 E3 3C 00 00 0A 00 70 95 E5 06 00 57 E1 04 00 00 8A 00 00 E0 E3 0B 10 A0 E1 ?? ?? ?? EB 00 00 57 E1 02 00 00 9A 00 30 9A E5 02 00 53 E3 31 00 00 1A 00 00 54 E3 17 00 00 1A 00 30 9A E5 01 00 53 E3 02 00 00 0A 02 00 53 E3 12 00 00 1A 2B 00 00 EA 00 00 57 E3 29 00 00 0A 97 0B 05 E0 05 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 40 A0 E1 00 00 89 E5 05 00 00 1A 90 30 9F E5 90 00 9F E5 00 10 93 E5 ?? ?? ?? EB 04 50 A0 E1 1D 00 00 EA 05 20 A0 E1 00 10 A0 E3 ?? ?? ?? EB 00 60 A0 E3 01 50 A0 E3 }
	condition:
		$pattern
}

rule __add_to_environ_af4cb659764d825cce6c376359179e45 {
	meta:
		aliases = "__add_to_environ"
		size = "420"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 B0 A0 E1 10 D0 4D E2 3D 10 A0 E3 02 70 A0 E1 00 A0 A0 E1 ?? ?? ?? EB 64 11 9F E5 64 21 9F E5 64 31 9F E5 00 80 6A E0 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 54 31 9F E5 48 01 9F E5 0F E0 A0 E1 03 F0 A0 E1 48 31 9F E5 00 60 93 E5 00 00 56 E3 06 50 A0 01 00 50 A0 13 0C 00 00 1A 10 00 00 EA ?? ?? ?? EB 00 00 50 E3 01 50 85 E2 06 00 00 1A 08 30 D4 E7 3D 00 53 E3 03 00 00 1A 00 00 57 E3 07 40 A0 01 36 00 00 0A 18 00 00 EA 04 60 86 E2 00 40 96 E5 00 00 54 E2 0A 10 A0 E1 08 20 A0 E1 EE FF FF 1A EC 70 9F E5 05 51 A0 E1 00 00 97 E5 08 10 85 E2 ?? ?? ?? EB 00 40 50 E2 16 00 00 0A CC 90 9F E5 }
	condition:
		$pattern
}

rule __GI_vfwscanf_b46a1d7ff394e5501571038eee40cc67 {
	meta:
		aliases = "vfwscanf, __GI_vfwscanf"
		size = "1744"
		objfiles = "vfwscanf@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 DC 4D E2 18 60 8D E2 0C 00 8D E5 08 20 8D E5 00 30 E0 E3 01 50 A0 E1 06 00 A0 E1 00 10 A0 E3 24 20 A0 E3 3C 30 8D E5 ?? ?? ?? EB 0C 00 9D E5 34 00 90 E5 00 00 50 E3 10 00 8D E5 0B 00 00 1A 0C 10 9D E5 38 40 81 E2 E4 00 8D E2 5C 36 9F E5 5C 16 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 4C 36 9F E5 0F E0 A0 E1 03 F0 A0 E1 A4 40 8D E2 04 00 A0 E1 0C 10 9D E5 ?? ?? ?? EB 34 36 9F E5 D0 30 8D E5 AC 30 9D E5 03 30 D3 E5 00 20 A0 E3 61 00 8D E2 BC 30 CD E5 1C 36 9F E5 42 10 80 E2 01 70 A0 E3 02 90 A0 E1 04 A0 A0 E1 03 00 8D E8 E0 30 8D E5 4C 20 8D E5 46 01 00 EA BD 30 DD E5 }
	condition:
		$pattern
}

rule inet_pton_be2ed8018e908c3155dca4044cc901bc {
	meta:
		aliases = "__GI_inet_pton, inet_pton"
		size = "512"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 02 00 50 E3 14 D0 4D E2 01 50 A0 E1 00 20 8D E5 02 00 00 0A 0A 00 50 E3 6F 00 00 1A 03 00 00 EA 01 00 A0 E1 00 10 9D E5 C0 FF FF EB 6E 00 00 EA 04 00 8D E2 00 10 A0 E3 10 20 A0 E3 ?? ?? ?? EB 00 30 D5 E5 3A 00 53 E3 00 60 A0 E1 10 80 80 E2 02 00 00 1A 01 30 F5 E5 3A 00 53 E3 5C 00 00 1A 00 B0 A0 E3 05 A0 A0 E1 0B 90 A0 E1 0B 70 A0 E1 30 00 00 EA 78 01 9F E5 20 10 84 E3 ?? ?? ?? EB 00 00 50 E3 01 50 85 E2 06 00 00 0A 60 21 9F E5 00 30 62 E0 07 72 83 E1 58 31 9F E5 03 00 57 E1 23 00 00 9A 4A 00 00 EA 3A 00 54 E3 15 00 00 1A 00 00 59 E3 04 00 00 1A 00 00 5B E3 44 00 00 1A 06 B0 A0 E1 }
	condition:
		$pattern
}

rule __GI_inet_ntop_44072a6b8890f89165b7e4233d1069a5 {
	meta:
		aliases = "inet_ntop, __GI_inet_ntop"
		size = "620"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 02 00 50 E3 58 D0 4D E2 01 80 A0 E1 04 20 8D E5 00 30 8D E5 02 00 00 0A 0A 00 50 E3 88 00 00 1A 04 00 00 EA 01 00 A0 E1 00 20 9D E5 04 10 9D E5 A1 FF FF EB 80 00 00 EA 38 00 8D E2 00 10 A0 E3 20 20 A0 E3 ?? ?? ?? EB 00 00 A0 E3 08 30 80 E0 00 10 D8 E7 01 20 D3 E5 A0 3F 80 E0 01 24 82 E1 C3 30 A0 E1 02 00 80 E2 58 10 8D E2 03 31 81 E0 0F 00 50 E3 20 20 03 E5 F3 FF FF DA 00 60 E0 E3 00 10 A0 E3 06 20 A0 E1 06 C0 A0 E1 01 00 A0 E3 13 00 00 EA 58 E0 8D E2 01 31 8E E0 20 30 13 E5 00 00 53 E3 04 00 00 1A 01 00 72 E3 01 20 A0 01 00 40 A0 01 01 40 84 12 08 00 00 EA 01 00 72 E3 06 00 00 0A }
	condition:
		$pattern
}

rule gethostbyname2_r_07459232b7678e96c23fbb7b884aa851 {
	meta:
		aliases = "__GI_gethostbyname2_r, gethostbyname2_r"
		size = "664"
		objfiles = "gethostbyname2_r@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 02 00 51 E3 3C D0 4D E2 01 40 A0 E1 02 60 A0 E1 03 80 A0 E1 00 90 A0 E1 60 A0 9D E5 68 B0 9D E5 07 00 00 1A 64 C0 9D E5 02 10 A0 E1 03 20 A0 E1 0A 30 A0 E1 00 C0 8D E5 04 B0 8D E5 ?? ?? ?? EB 91 00 00 EA 64 20 9D E5 00 70 A0 E3 0A 00 51 E3 00 70 82 E5 8B 00 00 1A 07 00 50 E1 89 00 00 0A ?? ?? ?? EB 64 C0 9D E5 00 50 A0 E1 04 10 A0 E1 06 20 A0 E1 00 40 90 E5 08 30 A0 E1 00 70 80 E5 09 00 A0 E1 00 14 8D E8 08 B0 8D E5 ?? ?? ?? EB 00 00 50 E3 00 40 85 05 7B 00 00 0A 00 30 9B E5 01 00 53 E3 04 00 00 0A 04 00 53 E3 09 00 00 0A 01 00 73 E3 74 00 00 1A 03 00 00 EA 02 00 50 E3 00 70 A0 13 }
	condition:
		$pattern
}

rule __kernel_sin_04a01b3c9229a60b7accae63a0ad82b7 {
	meta:
		aliases = "__kernel_sin"
		size = "556"
		objfiles = "k_sin@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 02 41 C0 E3 10 D0 4D E2 F9 05 54 E3 00 80 A0 E1 01 90 A0 E1 01 50 A0 E1 0C 00 8D E8 02 00 00 AA ?? ?? ?? EB 00 00 50 E3 6D 00 00 0A 08 20 A0 E1 09 30 A0 E1 08 00 A0 E1 09 10 A0 E1 ?? ?? ?? EB 08 20 A0 E1 09 30 A0 E1 00 60 A0 E1 01 70 A0 E1 ?? ?? ?? EB 98 21 9F E5 08 00 8D E5 0C 10 8D E5 90 31 9F E5 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? EB 84 21 9F E5 84 31 9F E5 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? EB 6C 21 9F E5 6C 31 9F E5 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? EB 54 21 9F E5 54 31 9F E5 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 }
	condition:
		$pattern
}

rule fde_split_8ac0f448f7356a71665cfac8eaac081b {
	meta:
		aliases = "fde_split"
		size = "344"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { F0 4F 2D E9 02 60 A0 E1 04 20 92 E5 00 00 52 E3 10 D0 4D E2 02 E0 A0 01 00 90 A0 E1 04 20 8D E5 01 A0 A0 E1 03 70 A0 E1 0E 00 A0 01 44 00 00 0A 03 B0 A0 E1 18 81 9F E5 0C 30 8D E5 04 20 9D E5 00 30 A0 E3 01 10 83 E2 08 40 A0 E1 02 00 51 E1 06 C0 A0 E1 06 50 A0 E1 08 10 8D E5 08 40 8B E5 1F 00 00 0A 03 31 A0 E1 08 30 83 E2 03 40 86 E0 08 00 54 E1 05 00 00 1A 11 00 00 EA 08 40 92 E5 00 30 A0 E3 08 00 54 E1 08 30 82 E5 0C 00 00 0A 00 20 94 E5 00 C0 8D E5 09 00 A0 E1 0C 10 95 E5 0F E0 A0 E1 0A F0 A0 E1 08 30 86 E2 04 30 63 E0 03 30 C3 E3 00 00 50 E3 07 20 83 E0 00 C0 9D E5 ED FF FF BA 0C 00 9D E9 }
	condition:
		$pattern
}

rule __GI_hypot_a52c9145ea0c8b9aa1faad5c1e296e7c {
	meta:
		aliases = "hypot, __ieee754_hypot, __GI_hypot"
		size = "1008"
		objfiles = "e_hypot@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 02 71 C0 E3 01 B0 A0 E1 02 11 C2 E3 07 00 51 E1 20 D0 4D E2 14 10 8D E5 14 70 8D C5 03 60 A0 E1 14 C0 9D E5 01 30 A0 C1 03 70 A0 C1 0B 10 A0 C1 0B 90 A0 D1 06 90 A0 C1 00 80 A0 D1 06 10 A0 D1 07 00 6C E0 02 80 A0 C1 02 50 A0 E1 09 40 A0 E1 01 20 A0 E1 07 30 A0 E1 0F 05 50 E3 18 30 8D E5 1C 40 8D E5 0C A0 A0 E1 02 B0 A0 E1 05 00 00 DA 07 00 A0 E1 09 10 A0 E1 0C 20 A0 E1 0B 30 A0 E1 ?? ?? ?? EB D1 00 00 EA 48 33 9F E5 03 00 57 E1 00 00 A0 D3 22 00 00 DA 3C 33 9F E5 03 00 57 E1 13 00 00 DA 18 30 8D E2 18 00 93 E8 FF 24 C7 E3 0F 26 C2 E3 04 20 92 E1 03 00 A0 01 04 10 A0 01 18 00 8D 12 }
	condition:
		$pattern
}

rule __kernel_cos_ae6315e118960ff1846a1c6b468a6bbf {
	meta:
		aliases = "__kernel_cos"
		size = "688"
		objfiles = "k_cos@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 02 81 C0 E3 10 D0 4D E2 F9 05 58 E3 00 A0 A0 E1 01 B0 A0 E1 00 40 A0 E1 01 50 A0 E1 0C 00 8D E8 00 60 A0 E3 00 70 A0 E3 04 00 00 AA ?? ?? ?? EB 00 00 50 E3 2C 02 9F 05 00 10 A0 03 87 00 00 0A 0A 20 A0 E1 0B 30 A0 E1 0A 00 A0 E1 0B 10 A0 E1 ?? ?? ?? EB 10 22 9F E5 10 32 9F E5 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? EB 04 22 9F E5 04 32 9F E5 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB EC 21 9F E5 EC 31 9F E5 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB D4 21 9F E5 D4 31 9F E5 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 }
	condition:
		$pattern
}

rule __GI_remainder_f10a09247b6aea03a880dc86e2889bdb {
	meta:
		aliases = "__ieee754_remainder, remainder, drem, __GI_remainder"
		size = "520"
		objfiles = "e_remainder@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 02 91 C2 E3 08 D0 4D E2 03 C0 99 E1 02 A0 A0 E1 03 B0 A0 E1 00 60 A0 E1 01 70 A0 E1 03 80 A0 E1 00 40 A0 E1 01 50 A0 E1 03 00 8D E8 0A 00 00 0A 00 E0 9D E5 BC C1 9F E5 02 41 CE E3 0C 00 54 E1 05 00 00 CA 0C 00 59 E1 08 00 00 DA 02 C1 89 E2 01 C6 8C E2 03 C0 9C E1 11 00 00 0A ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 5F 00 00 EA 84 11 9F E5 01 00 59 E1 09 00 00 CA 02 00 A0 E1 03 10 A0 E1 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? EB 00 60 A0 E1 01 70 A0 E1 04 30 9D E5 03 20 68 E0 04 30 69 E0 02 30 93 E1 05 00 00 1A 06 00 A0 E1 07 10 A0 E1 00 20 A0 E3 }
	condition:
		$pattern
}

rule __wcstofpmax_fe32b19ce837fd54eba38350e1c98f4b {
	meta:
		aliases = "__wcstofpmax"
		size = "872"
		objfiles = "__wcstofpmax@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 02 B0 A0 E1 10 D0 4D E2 00 60 A0 E1 04 00 8D E5 00 10 8D E5 00 00 00 EA 04 60 86 E2 00 00 96 E5 ?? ?? ?? EB 00 00 50 E3 FA FF FF 1A 00 30 96 E5 2B 00 53 E3 05 00 00 0A 2D 00 53 E3 01 20 A0 03 0C 00 8D 15 0C 20 8D 05 01 00 00 0A 01 00 00 EA 0C 00 8D E5 04 60 86 E2 00 30 A0 E3 00 70 A0 E3 00 80 A0 E3 00 A0 E0 E3 08 30 8D E5 19 00 00 EA 00 00 5A E3 01 A0 8A B2 00 00 5A E3 07 00 A0 E1 08 10 A0 E1 C8 22 9F E5 00 30 A0 E3 04 60 86 E2 01 00 00 1A 30 00 59 E3 0E 00 00 0A 01 A0 8A E2 11 00 5A E3 0B 00 00 CA ?? ?? ?? EB 00 40 A0 E1 30 00 49 E2 01 50 A0 E1 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 }
	condition:
		$pattern
}

rule fmod_10b9ebfa70a9daf3597b26e6d6a8e33f {
	meta:
		aliases = "__GI_fmod, __ieee754_fmod, fmod"
		size = "852"
		objfiles = "e_fmod@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 02 B1 C2 E3 18 D0 4D E2 03 40 9B E1 01 50 A0 E1 00 40 A0 E1 30 00 8D E8 00 50 9D E5 18 E3 9F E5 00 C0 A0 13 01 C0 A0 03 02 91 C5 E3 0E 00 59 E1 01 C0 8C C3 00 00 5C E3 00 C0 9D E5 00 50 A0 E3 00 40 A0 E3 10 40 8D E5 14 50 8D E5 08 40 8D E5 0C 50 8D E5 00 60 A0 E1 01 70 A0 E1 03 A0 A0 E1 04 80 9D E5 02 51 0C E2 05 00 00 1A 00 C0 63 E2 03 C0 8C E1 AC CF 8B E1 01 E0 8E E2 0E 00 5C E1 06 00 00 9A ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 00 60 A0 E1 01 70 A0 E1 A2 00 00 EA 0B 00 59 E1 07 00 00 CA 00 30 A0 A3 01 30 A0 B3 0A 00 58 E1 01 30 83 33 00 00 53 E3 9A 00 00 1A 0A 00 58 E1 }
	condition:
		$pattern
}

rule __kernel_tan_22f466b601dfacdf5a2e43d4f7a2203a {
	meta:
		aliases = "__kernel_tan"
		size = "1508"
		objfiles = "k_tan@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 02 C1 C0 E3 28 D0 4D E2 18 C0 8D E5 18 E0 9D E5 40 C5 9F E5 0C 00 5E E1 10 00 8D E5 14 10 8D E5 01 50 A0 E1 1C 00 8D E5 02 A0 A0 E1 03 B0 A0 E1 1A 00 00 CA ?? ?? ?? EB 00 00 50 E3 3B 00 00 1A 10 30 8D E2 18 00 93 E8 18 00 9D E5 4C 10 9D E5 04 20 80 E1 01 30 81 E2 03 20 92 E1 06 00 00 1A 10 00 8D E2 03 00 90 E8 ?? ?? ?? EB 00 20 A0 E1 E4 04 9F E5 01 30 A0 E1 05 00 00 EA 4C 20 9D E5 01 00 52 E3 2F 01 00 0A 10 20 8D E2 0C 00 92 E8 C8 04 9F E5 00 10 A0 E3 ?? ?? ?? EB 27 01 00 EA BC 34 9F E5 18 C0 9D E5 03 00 5C E1 1F 00 00 DA 1C E0 9D E5 00 00 5E E3 07 00 00 AA 10 00 8D E2 01 10 90 E8 }
	condition:
		$pattern
}

rule __ieee754_pow_035083d4d1431c4a906437573a0c5ddd {
	meta:
		aliases = "pow, __GI_pow, __ieee754_pow"
		size = "4084"
		objfiles = "e_pow@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 03 40 A0 E1 02 71 C2 E3 78 D0 4D E2 3C 20 8D E5 40 30 8D E5 00 50 A0 E1 02 30 A0 E1 01 60 A0 E1 04 10 97 E1 02 80 A0 E1 04 00 A0 E1 05 90 A0 E1 06 A0 A0 E1 03 E0 A0 E1 B8 2E 9F 05 C7 00 00 0A B4 CE 9F E5 02 41 C5 E3 0C 00 54 E1 64 50 8D E5 0F 00 00 CA 00 B0 A0 13 01 B0 A0 03 00 00 56 E3 00 30 A0 03 01 30 0B 12 00 00 53 E3 08 00 00 1A 0C 00 57 E1 06 00 00 CA 00 30 A0 13 01 30 A0 03 00 00 50 E3 00 30 A0 03 01 30 03 12 00 00 53 E3 05 00 00 0A 3C 00 8D E2 03 00 90 E8 05 20 A0 E1 06 30 A0 E1 ?? ?? ?? EB 8C 03 00 EA 00 00 55 E3 1C 00 00 AA 44 3E 9F E5 03 00 57 E1 02 30 A0 C3 0D 00 00 CA }
	condition:
		$pattern
}

rule __divsc3_e8236474605a87936bebbf717237348e {
	meta:
		aliases = "__divsc3"
		size = "1380"
		objfiles = "_divsc3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 03 B0 A0 E1 02 A0 A0 E1 02 31 C2 E3 02 21 CB E3 10 D0 4D E2 00 80 A0 E1 01 70 A0 E1 03 00 A0 E1 02 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 22 00 00 AA 0B 10 A0 E1 0A 00 A0 E1 ?? ?? ?? EB 00 40 A0 E1 04 10 A0 E1 0A 00 A0 E1 ?? ?? ?? EB 0B 10 A0 E1 ?? ?? ?? EB 04 10 A0 E1 00 50 A0 E1 08 00 A0 E1 ?? ?? ?? EB 07 10 A0 E1 ?? ?? ?? EB 05 10 A0 E1 ?? ?? ?? EB 04 10 A0 E1 00 90 A0 E1 07 00 A0 E1 ?? ?? ?? EB 08 10 A0 E1 ?? ?? ?? EB 05 10 A0 E1 ?? ?? ?? EB 00 60 A0 E1 09 00 A0 E1 09 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 1F 00 00 1A 09 00 A0 E1 06 10 A0 E1 10 D0 8D E2 F0 8F BD E8 0A 10 A0 E1 0B 00 A0 E1 }
	condition:
		$pattern
}

rule frame_downheap_b0803ca79b1f2d29c9ff57c11114954b {
	meta:
		aliases = "frame_downheap"
		size = "188"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { F0 4F 2D E9 03 C0 A0 E1 24 A0 9D E5 83 30 A0 E1 01 40 83 E2 0A 00 54 E1 00 B0 A0 E1 01 90 A0 E1 02 50 A0 E1 F0 8F BD A8 0C 80 A0 E1 10 00 00 EA 08 11 95 E7 0B 00 A0 E1 00 20 96 E5 0F E0 A0 E1 09 F0 A0 E1 84 30 A0 E1 00 00 50 E3 01 10 83 E2 F0 8F BD A8 08 21 95 E7 00 30 96 E5 01 00 5A E1 08 31 85 E7 04 80 A0 E1 00 20 86 E5 01 40 A0 E1 10 00 00 DA 01 70 84 E2 04 31 A0 E1 07 00 5A E1 03 60 85 E0 E9 FF FF DA 04 31 A0 E1 05 60 83 E0 05 10 93 E7 04 20 96 E5 0B 00 A0 E1 0F E0 A0 E1 09 F0 A0 E1 00 00 50 E3 07 31 A0 B1 03 60 85 B0 07 40 A0 B1 DD FF FF EA F0 8F BD E8 }
	condition:
		$pattern
}

rule _wstdio_fwrite_de5bee4d35d6a21d1521f9dd1b00c5fb {
	meta:
		aliases = "_wstdio_fwrite"
		size = "284"
		objfiles = "_wfwrite@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 04 30 92 E5 03 00 73 E3 48 D0 4D E2 02 50 A0 E1 00 70 A0 E1 01 60 A0 E1 0F 00 00 1A 10 00 92 E5 0C 30 92 E5 03 30 60 E0 43 31 A0 E1 01 00 53 E1 03 40 A0 31 01 40 A0 21 00 00 54 E3 32 00 00 0A 07 10 A0 E1 04 20 A0 E1 ?? ?? ?? EB 10 30 95 E5 04 31 83 E0 10 30 85 E5 2B 00 00 EA 00 30 D2 E5 01 20 D2 E5 02 34 83 E1 21 3D 03 E2 21 0D 53 E3 05 00 00 0A 05 00 A0 E1 02 1B A0 E3 ?? ?? ?? EB 00 00 50 E3 00 80 A0 13 1E 00 00 1A 00 80 A0 E3 04 90 8D E2 2C A0 85 E2 01 B0 A0 E3 44 70 8D E5 12 00 00 EA 00 A0 8D E5 ?? ?? ?? EB 00 40 A0 E1 01 30 88 E2 01 00 74 E3 05 20 A0 E1 09 00 A0 E1 03 31 87 E0 }
	condition:
		$pattern
}

rule fde_merge_f00eec47a9a91af9ceecdb9298050c0d {
	meta:
		aliases = "fde_merge"
		size = "268"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { F0 4F 2D E9 04 C0 93 E5 08 D0 4D E2 00 00 5C E3 00 30 8D E5 00 90 A0 E1 01 80 A0 E1 04 20 8D E5 37 00 00 0A 0C 31 A0 E1 00 10 9D E5 08 30 83 E2 04 50 92 E5 03 B0 81 E0 00 00 55 E3 01 A0 4C E2 04 70 1B E5 15 00 00 0A 05 20 8C E0 04 10 9D E5 02 21 A0 E1 05 31 A0 E1 08 30 83 E2 08 20 82 E2 03 40 81 E0 02 60 81 E0 04 00 00 EA 04 30 34 E5 00 00 52 E3 04 30 26 E5 12 00 00 0A 02 50 A0 E1 07 20 A0 E1 04 10 14 E5 09 00 A0 E1 0F E0 A0 E1 08 F0 A0 E1 00 00 50 E3 01 20 45 E2 F2 FF FF CA 0A 30 85 E0 04 20 9D E5 03 31 A0 E1 02 30 83 E0 00 00 5A E3 08 70 83 E5 04 B0 4B E2 0A 00 00 0A 0A C0 A0 E1 DB FF FF EA }
	condition:
		$pattern
}

rule svc_getreq_common_da26280470e25ef8d6fa3a9f56eedde3 {
	meta:
		aliases = "__GI_svc_getreq_common, svc_getreq_common"
		size = "428"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 05 DC 4D E2 19 3E 8D E2 D8 34 8D E5 00 40 A0 E1 CC D4 8D E5 ?? ?? ?? EB B4 30 90 E5 04 41 93 E7 00 00 54 E3 00 70 A0 E1 5B 00 00 0A 4E 6E 8D E2 13 5D 8D E2 4B 9E 8D E2 0C 60 86 E2 08 50 85 E2 00 B0 A0 E3 01 A0 A0 E3 4E 8E 8D E2 08 30 94 E5 04 00 A0 E1 09 10 A0 E1 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 3F 00 00 0A BC 34 9D E5 E0 34 8D E5 C0 34 9D E5 07 00 95 E8 C8 C4 9D E5 E4 34 8D E5 C4 34 9D E5 07 00 86 E8 00 00 5C E3 32 2E 8D E2 E8 34 8D E5 F8 24 8D E5 FC 44 8D E5 05 00 00 1A FC 20 9F E5 00 30 92 E5 20 30 84 E5 FC 34 9D E5 28 C0 83 E5 08 00 00 EA 08 00 A0 E1 09 10 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule _fpmaxtostr_d86865ed882053182834cf94080edb69 {
	meta:
		aliases = "_fpmaxtostr"
		size = "1952"
		objfiles = "_fpmaxtostr@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 08 A0 D3 E5 A0 D0 4D E2 04 30 8D E5 20 30 8A E3 61 00 53 E3 65 30 A0 E3 8A 30 CD E5 01 50 A0 E1 06 30 8A 02 04 10 9D E5 FF A0 03 02 04 30 9D E5 00 B0 91 E5 08 00 8D E5 04 00 9D E5 02 60 A0 E1 0C 20 93 E5 04 00 90 E5 00 00 5B E3 00 30 A0 E3 06 B0 A0 B3 02 00 12 E3 9A 30 CD E5 10 00 8D E5 2B 30 83 12 02 00 00 1A 01 00 12 E3 01 00 00 0A 20 30 A0 E3 9A 30 CD E5 00 C0 A0 E3 06 30 A0 E1 05 00 A0 E1 06 10 A0 E1 05 20 A0 E1 28 C0 8D E5 9B C0 CD E5 ?? ?? ?? EB 00 00 50 E3 08 30 A0 13 28 30 8D 15 2D 00 00 1A 05 00 A0 E1 06 10 A0 E1 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? EB 00 00 50 E3 0F 00 00 1A }
	condition:
		$pattern
}

rule _dl_lookup_hash_29459dcc06197179d765d1c67881d678 {
	meta:
		aliases = "_dl_lookup_hash"
		size = "440"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { F0 4F 2D E9 08 D0 4D E2 04 30 8D E5 00 B0 A0 E1 02 30 03 E2 01 70 A0 E1 02 80 A0 E1 00 A0 E0 E3 00 30 8D E5 55 00 00 EA 00 50 97 E5 24 30 95 E5 23 34 A0 E1 01 30 23 E2 00 00 58 E3 00 30 A0 03 01 30 03 12 00 00 53 E3 0A 00 00 0A 05 00 58 E1 34 20 98 15 04 00 00 1A 06 00 00 EA 04 30 92 E5 05 00 53 E1 03 00 00 0A 00 20 92 E5 00 00 52 E3 F9 FF FF 1A 40 00 00 EA 00 30 9D E5 00 00 53 E3 02 00 00 0A 18 30 95 E5 01 00 53 E3 3A 00 00 0A 28 00 95 E5 00 00 50 E3 37 00 00 0A 01 00 7A E3 58 90 95 E5 0B 10 A0 01 01 A0 8A 02 05 00 00 0A 07 00 00 EA 0A 32 83 E0 0F 22 03 E2 03 30 22 E0 22 AC 23 E0 01 10 81 E2 }
	condition:
		$pattern
}

rule srandom_r_8ff63182c114958736670f69803f07aa {
	meta:
		aliases = "__GI_srandom_r, srandom_r"
		size = "224"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 0C 20 D1 E5 02 3C A0 E1 01 03 53 E3 04 D0 4D E2 01 60 A0 E1 00 00 E0 83 2A 00 00 8A 00 00 50 E3 08 70 91 E5 01 00 A0 03 00 00 52 E3 00 00 87 E5 23 00 00 0A 0D 30 D1 E5 90 B0 9F E5 03 3C A0 E1 00 50 A0 E1 43 9C A0 E1 07 A0 A0 E1 01 80 A0 E3 09 00 00 EA ?? ?? ?? EB 74 40 9F E5 74 10 9F E5 90 04 04 E0 05 00 A0 E1 ?? ?? ?? EB 90 0B 03 E0 03 50 54 E0 06 51 45 42 04 50 AA E5 09 00 58 E1 05 00 A0 E1 4C 10 9F E5 01 80 88 E2 F0 FF FF BA 0A 30 A0 E3 99 03 04 E0 0E 30 D6 E5 03 3C A0 E1 43 3B 87 E0 0D 50 A0 E1 88 00 86 E8 00 00 00 EA ?? ?? ?? EB 01 40 54 E2 06 00 A0 E1 0D 10 A0 E1 FA FF FF 5A }
	condition:
		$pattern
}

rule binary_search_mixed_encoding_f_4093cd715e97f495ba43b5411e2d7275 {
	meta:
		aliases = "binary_search_mixed_encoding_fdes"
		size = "184"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { F0 4F 2D E9 0C D0 4D E2 00 00 8D E5 0C B0 90 E5 04 80 9B E5 00 00 58 E3 01 90 A0 E1 21 00 00 0A 00 A0 A0 E3 0A 20 88 E0 A2 70 A0 E1 07 31 A0 E1 0B 30 83 E0 08 60 93 E5 06 00 A0 E1 EB FF FF EB FF 40 00 E2 00 50 A0 E1 00 10 9D E5 04 00 A0 E1 E8 FE FF EB 08 20 86 E2 00 10 A0 E1 08 30 8D E2 04 00 A0 E1 F9 FE FF EB 00 10 A0 E3 00 20 A0 E1 04 30 8D E2 0F 00 05 E2 F4 FE FF EB 08 20 9D E5 09 00 52 E1 07 80 A0 81 04 00 00 8A 04 30 9D E5 03 30 82 E0 09 00 53 E1 03 00 00 8A 01 A0 87 E2 0A 00 58 E1 DE FF FF 8A 00 60 A0 E3 06 00 A0 E1 0C D0 8D E2 F0 8F BD E8 }
	condition:
		$pattern
}

rule __ns_name_unpack_a52265ee39b2c76f826fc3a2dafe7e08 {
	meta:
		aliases = "__GI___ns_name_unpack, __ns_name_unpack"
		size = "316"
		objfiles = "ns_name@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 0C D0 4D E2 02 A0 A0 E1 03 40 A0 E1 01 00 52 E1 00 20 A0 33 01 20 A0 23 30 30 9D E5 00 00 5A E1 01 20 82 33 03 30 84 E0 00 00 52 E3 01 80 A0 E1 00 70 A0 E1 08 30 8D E5 2F 00 00 1A 02 90 A0 E1 0A 60 A0 E1 01 20 60 E0 00 C0 E0 E3 01 B0 6A E2 04 20 8D E5 2D 00 00 EA C0 30 15 E2 02 00 00 0A C0 00 53 E3 24 00 00 1A 11 00 00 EA 05 30 84 E0 08 20 9D E5 01 30 83 E2 02 00 53 E1 1E 00 00 2A 05 60 81 E0 08 00 56 E1 1B 00 00 2A 01 50 C4 E4 01 30 89 E2 04 00 A0 E1 05 20 A0 E1 00 C0 8D E5 05 90 83 E0 ?? ?? ?? EB 00 C0 9D E5 05 40 84 E0 16 00 00 EA 08 00 51 E1 0F 00 00 2A 01 30 D6 E5 3F 20 05 E2 }
	condition:
		$pattern
}

rule scandir_edadde364d133e1ead9efb6ca2329a24 {
	meta:
		aliases = "scandir"
		size = "348"
		objfiles = "scandir@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 0C D0 4D E2 04 10 8D E5 02 B0 A0 E1 00 30 8D E5 ?? ?? ?? EB 00 A0 50 E2 00 00 E0 03 4B 00 00 0A ?? ?? ?? EB 00 30 A0 E3 00 20 90 E5 00 50 A0 E1 03 80 A0 E1 03 60 A0 E1 03 90 A0 E1 08 20 8D E5 00 30 80 E5 1F 00 00 EA 00 00 5B E3 04 00 00 0A 0F E0 A0 E1 0B F0 A0 E1 00 00 50 E3 00 00 85 05 18 00 00 0A 00 30 A0 E3 09 00 56 E1 00 30 85 E5 08 00 00 1A 03 00 56 E1 0A 90 A0 03 86 90 A0 11 08 00 A0 E1 09 11 A0 E1 ?? ?? ?? EB 00 00 50 E3 10 00 00 0A 00 80 A0 E1 08 20 D7 E5 09 30 D7 E5 03 44 82 E1 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 08 00 00 0A 07 10 A0 E1 04 20 A0 E1 ?? ?? ?? EB 06 01 88 E7 }
	condition:
		$pattern
}

rule scandir64_f6d0825ab27721b08c883fe1c8d5a1e0 {
	meta:
		aliases = "scandir64"
		size = "348"
		objfiles = "scandir64@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 0C D0 4D E2 04 10 8D E5 02 B0 A0 E1 00 30 8D E5 ?? ?? ?? EB 00 A0 50 E2 00 00 E0 03 4B 00 00 0A ?? ?? ?? EB 00 30 A0 E3 00 20 90 E5 00 50 A0 E1 03 80 A0 E1 03 60 A0 E1 03 90 A0 E1 08 20 8D E5 00 30 80 E5 1F 00 00 EA 00 00 5B E3 04 00 00 0A 0F E0 A0 E1 0B F0 A0 E1 00 00 50 E3 00 00 85 05 18 00 00 0A 00 30 A0 E3 09 00 56 E1 00 30 85 E5 08 00 00 1A 03 00 56 E1 0A 90 A0 03 86 90 A0 11 08 00 A0 E1 09 11 A0 E1 ?? ?? ?? EB 00 00 50 E3 10 00 00 0A 00 80 A0 E1 10 20 D7 E5 11 30 D7 E5 03 44 82 E1 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 08 00 00 0A 07 10 A0 E1 04 20 A0 E1 ?? ?? ?? EB 06 01 88 E7 }
	condition:
		$pattern
}

rule __GI_nextafter_412ac0e1e0974c2b005c17b90c32d3af {
	meta:
		aliases = "nextafter, __GI_nextafter"
		size = "544"
		objfiles = "s_nextafter@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 0C E2 9F E5 02 91 C0 E3 20 D0 4D E2 02 B0 A0 E1 03 C0 A0 E1 02 60 A0 E1 03 70 A0 E1 00 20 A0 E3 00 30 A0 E3 0E 00 59 E1 00 40 A0 E1 01 50 A0 E1 00 80 A0 E1 01 A0 A0 E1 10 20 8D E5 14 30 8D E5 08 20 8D E5 0C 30 8D E5 0C 00 8D E8 18 B0 8D E5 1C C0 8D E5 03 00 00 DA 02 31 89 E2 01 36 83 E2 01 30 93 E1 07 00 00 1A 02 31 C6 E3 0E 00 53 E1 09 00 00 DA 02 31 83 E2 1C 20 9D E5 01 36 83 E2 02 20 93 E1 04 00 00 0A 04 00 A0 E1 05 10 A0 E1 0B 20 A0 E1 0C 30 A0 E1 42 00 00 EA 0B 20 A0 E1 0C 30 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 52 00 00 0A 0A 90 99 E1 14 00 00 1A 18 30 9D E5 }
	condition:
		$pattern
}

rule __drand48_iterate_e688c7c3590e3ec389d0ca296e5aa9eb {
	meta:
		aliases = "__drand48_iterate"
		size = "236"
		objfiles = "drand48_iter@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 0E 20 D1 E5 0F 30 D1 E5 03 24 92 E1 01 90 A0 E1 00 B0 A0 E1 09 00 00 1A C4 30 9F E5 05 40 A0 E3 10 30 81 E5 14 40 81 E5 0B 30 A0 E3 0C 30 C1 E5 01 30 A0 E3 0E 30 C1 E5 0F 20 C1 E5 0D 20 C1 E5 04 A0 8B E2 01 70 DA E5 04 50 DB E5 02 80 8B E2 01 60 D8 E5 00 E0 DB E5 01 C0 DB E5 02 20 DB E5 07 34 85 E1 00 40 A0 E3 0C 04 8E E1 03 40 A0 E1 06 24 82 E1 00 30 A0 E3 00 30 83 E1 02 28 A0 E1 02 00 83 E1 04 10 A0 E1 10 20 89 E2 0C 00 92 E8 ?? ?? ?? EB 0D C0 D9 E5 0C 20 D9 E5 0C 34 82 E1 03 50 90 E0 00 60 A1 E2 25 38 A0 E1 06 38 83 E1 45 04 A0 E1 00 20 A0 E3 01 00 CB E5 43 C4 A0 E1 46 E4 A0 E1 }
	condition:
		$pattern
}

rule _ppfs_parsespec_f0e1cbb3475ac8753f4e66a131af19c3 {
	meta:
		aliases = "_ppfs_parsespec"
		size = "1344"
		objfiles = "_ppfs_parsespec@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 10 30 90 E5 48 D0 4D E2 80 50 13 E2 00 20 A0 E3 08 30 A0 E3 24 30 8D E5 3C 20 8D E5 40 20 8D E5 20 30 8D E5 00 70 A0 E1 18 B0 90 E5 00 10 90 05 11 00 00 0A 02 00 A0 E1 00 30 97 E5 00 31 83 E0 04 10 53 E5 48 C0 8D E2 00 20 8C E0 48 10 42 E5 04 30 13 E5 03 00 51 E1 01 00 80 E2 27 01 00 1A 00 00 51 E3 01 00 00 0A 1F 00 50 E3 F1 FF FF 9A 00 30 A0 E3 1F 30 CD E5 01 10 8D E2 00 A0 A0 E3 0A 40 A0 E1 03 80 E0 E3 0A E0 A0 E1 02 91 E0 E3 00 00 00 EA 06 10 A0 E1 00 30 D1 E5 2A 00 53 E3 48 30 8D 02 94 38 23 00 01 60 A0 11 01 60 81 02 0E 20 A0 E1 28 E0 03 05 0E 00 00 EA 48 34 9F E5 03 00 52 E1 }
	condition:
		$pattern
}

rule binary_search_single_encoding__d34c03c2b15be55c8d1444d5a1167d59 {
	meta:
		aliases = "binary_search_single_encoding_fdes"
		size = "204"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { F0 4F 2D E9 10 30 D0 E5 11 20 D0 E5 02 34 83 E1 A3 41 A0 E1 FF B0 04 E2 0C 30 90 E5 0C D0 4D E2 01 80 A0 E1 00 10 A0 E1 0B 00 A0 E1 00 30 8D E5 83 FF FF EB 00 30 9D E5 04 60 93 E5 00 00 56 E3 00 90 A0 E1 1C 00 00 0A 0F A0 04 E2 00 70 A0 E3 07 30 86 E0 A3 40 A0 E1 00 30 9D E5 04 21 A0 E1 03 20 82 E0 08 50 92 E5 09 10 A0 E1 08 20 85 E2 08 30 8D E2 0B 00 A0 E1 87 FF FF EB 00 10 A0 E3 00 20 A0 E1 04 30 8D E2 0A 00 A0 E1 82 FF FF EB 08 20 9D E5 08 00 52 E1 04 60 A0 81 04 00 00 8A 04 30 9D E5 03 30 82 E0 08 00 53 E1 03 00 00 8A 01 70 84 E2 06 00 57 E1 E4 FF FF 3A 00 50 A0 E3 05 00 A0 E1 0C D0 8D E2 }
	condition:
		$pattern
}

rule getservbyname_r_49219ffb0ce229dfef0dfbd274cde822 {
	meta:
		aliases = "__GI_getservbyname_r, getservbyname_r"
		size = "292"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 10 D0 4D E2 00 70 A0 E1 01 60 A0 E1 0D 00 A0 E1 F0 10 9F E5 02 50 A0 E1 03 A0 A0 E1 E8 20 9F E5 E8 30 9F E5 34 B0 9D E5 38 90 9D E5 0F E0 A0 E1 03 F0 A0 E1 D8 30 9F E5 CC 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 CC 30 9F E5 00 00 93 E5 ?? ?? ?? EB 16 00 00 EA 07 00 A0 E1 00 10 95 E5 ?? ?? ?? EB 00 00 50 E3 04 40 95 15 03 00 00 1A 08 00 00 EA ?? ?? ?? EB 00 00 50 E3 05 00 00 0A 00 30 94 E5 00 10 53 E2 07 00 A0 E1 04 40 84 E2 F7 FF FF 1A 06 00 00 EA 00 00 56 E3 0B 00 00 0A 0C 00 95 E5 06 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 06 00 00 0A 05 00 A0 E1 0A 10 A0 E1 0B 20 A0 E1 09 30 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule hsearch_r_b816ff14cf77adabd90b725825e21897 {
	meta:
		aliases = "__GI_hsearch_r, hsearch_r"
		size = "448"
		objfiles = "hsearch_r@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 10 D0 4D E2 08 20 8D E5 04 30 8D E5 0C 10 8D E5 00 40 A0 E1 ?? ?? ?? EB 04 B0 A0 E1 00 20 A0 E1 01 00 00 EA 02 30 DB E7 00 02 83 E0 01 20 52 E2 FB FF FF 2A 34 10 9D E5 04 90 91 E5 09 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 50 A0 11 01 50 A0 03 0C 30 A0 E3 95 03 03 E0 34 20 9D E5 00 A0 92 E5 03 20 9A E7 00 00 52 E3 03 60 8A E0 26 00 00 0A 05 00 52 E1 04 00 00 1A 0B 00 A0 E1 04 10 96 E5 ?? ?? ?? EB 00 00 50 E3 17 00 00 0A 05 00 A0 E1 02 10 49 E2 ?? ?? ?? EB 01 70 80 E2 09 20 67 E0 00 20 8D E5 05 40 A0 E1 07 00 54 E1 00 30 9D 95 04 40 67 80 03 40 84 90 05 00 54 E1 12 00 00 0A 0C 30 A0 E3 }
	condition:
		$pattern
}

rule fcloseall_acebc8de379406fa3232dc038567e1ce {
	meta:
		aliases = "fcloseall"
		size = "332"
		objfiles = "fcloseall@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 10 D0 4D E2 1C 21 9F E5 1C 11 9F E5 1C 71 9F E5 0D 00 A0 E1 0F E0 A0 E1 07 F0 A0 E1 10 61 9F E5 00 01 9F E5 0F E0 A0 E1 06 F0 A0 E1 04 21 9F E5 00 30 92 E5 01 30 83 E2 00 30 82 E5 F8 50 9F E5 01 10 A0 E3 0D 00 A0 E1 0F E0 A0 E1 05 F0 A0 E1 D4 10 9F E5 E4 20 9F E5 0D 00 A0 E1 0F E0 A0 E1 07 F0 A0 E1 D4 00 9F E5 0F E0 A0 E1 06 F0 A0 E1 CC 30 9F E5 0D 00 A0 E1 01 10 A0 E3 00 80 93 E5 0F E0 A0 E1 05 F0 A0 E1 0D 40 A0 E1 0D A0 A0 E1 06 B0 A0 E1 05 90 A0 E1 00 70 A0 E3 1B 00 00 EA 34 50 98 E5 00 00 55 E3 20 60 98 E5 09 00 00 1A 38 40 88 E2 0D 00 A0 E1 6C 10 9F E5 04 20 A0 E1 68 30 9F E5 }
	condition:
		$pattern
}

rule __res_init_897022d8a2931533e988a8a0b11e077b {
	meta:
		aliases = "__GI___res_init, __res_init"
		size = "488"
		objfiles = "res_init@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 10 D0 4D E2 ?? ?? ?? EB A8 11 9F E5 00 40 A0 E1 A4 21 9F E5 0D 00 A0 E1 A0 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 98 31 9F E5 8C 01 9F E5 0F E0 A0 E1 03 F0 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 84 C1 9F E5 84 31 9F E5 00 10 A0 E3 00 C0 83 E5 64 20 A0 E3 04 00 A0 E1 ?? ?? ?? EB 05 30 A0 E3 01 20 A0 E3 52 30 C4 E5 03 30 A0 E3 53 30 C4 E5 51 20 C4 E5 58 31 9F E5 00 30 93 E5 54 C1 9F E5 07 00 53 E3 03 00 A0 31 07 00 A0 23 00 10 A0 E3 00 20 84 E5 03 00 00 EA 00 30 9C E5 01 31 93 E7 34 30 82 E5 01 10 81 E2 00 00 51 E1 01 21 84 E0 F8 FF FF BA 00 80 A0 E3 08 90 A0 E1 08 70 A0 E1 2D 00 00 EA 1C 60 A0 E3 }
	condition:
		$pattern
}

rule getservent_r_735b2247886bc6616fd716ba68576355 {
	meta:
		aliases = "__GI_getservent_r, getservent_r"
		size = "584"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 14 D0 4D E2 00 30 8D E5 02 40 A0 E1 8B 00 52 E3 00 20 9D E5 00 30 A0 E3 00 30 82 E5 00 70 A0 E1 01 80 A0 E1 04 00 00 8A ?? ?? ?? EB 22 30 A0 E3 03 40 A0 E1 00 30 80 E5 73 00 00 EA 04 00 8D E2 D0 11 9F E5 D0 21 9F E5 D0 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 C8 31 9F E5 BC 01 9F E5 0F E0 A0 E1 03 F0 A0 E1 8C 30 44 E2 01 0A 53 E3 8C 90 88 E2 02 00 00 8A ?? ?? ?? EB 22 30 A0 E3 0B 00 00 EA A0 41 9F E5 00 30 94 E5 00 00 53 E3 0A 00 00 1A 94 01 9F E5 94 11 9F E5 ?? ?? ?? EB 00 00 50 E3 00 00 84 E5 04 00 00 1A ?? ?? ?? EB 05 30 A0 E3 03 40 A0 E1 00 30 80 E5 4E 00 00 EA 64 B1 9F E5 00 A0 A0 E3 }
	condition:
		$pattern
}

rule __strtofpmax_b5419dcc3a8c61962f1871af02ff6d05 {
	meta:
		aliases = "__strtofpmax"
		size = "884"
		objfiles = "__strtofpmax@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 14 D0 4D E2 04 00 8D E5 04 80 9D E5 4C 03 9F E5 02 B0 A0 E1 00 10 8D E5 00 00 00 EA 01 80 88 E2 00 20 D8 E5 00 10 90 E5 82 30 D1 E7 20 30 13 E2 08 10 8D E5 F8 FF FF 1A 2B 00 52 E3 05 00 00 0A 2D 00 52 E3 01 20 A0 03 10 30 8D 15 10 20 8D 05 01 00 00 0A 01 00 00 EA 10 30 8D E5 01 80 88 E2 00 30 A0 E3 00 60 A0 E3 00 70 A0 E3 00 A0 E0 E3 0C 30 8D E5 19 00 00 EA 00 00 5A E3 01 A0 8A B2 00 00 5A E3 06 00 A0 E1 07 10 A0 E1 D0 22 9F E5 00 30 A0 E3 01 80 88 E2 01 00 00 1A 30 00 59 E3 0E 00 00 0A 01 A0 8A E2 11 00 5A E3 0B 00 00 CA ?? ?? ?? EB 00 40 A0 E1 30 00 49 E2 01 50 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __read_etc_hosts_r_da2e5f5b60fc6fcd0e378ecf1a635720 {
	meta:
		aliases = "__read_etc_hosts_r"
		size = "660"
		objfiles = "read_etc_hosts_r@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 14 D0 4D E2 3C 40 8D E2 10 10 94 E8 00 E0 64 E2 03 E0 0E E2 0C 50 6E E0 20 60 55 E2 10 60 8D E5 48 60 9D E5 00 C0 E0 E3 00 C0 86 E5 04 00 8D E5 00 10 8D E5 02 90 A0 E1 03 B0 A0 E1 0E 60 84 E0 38 80 9D E5 8C 00 00 4A 01 00 53 E3 01 C0 8C 02 20 A0 86 E2 08 C0 8D 05 0C C0 8D 05 13 00 00 0A 38 50 45 E2 4F 00 55 E3 10 50 8D E5 82 00 00 DA ?? ?? ?? EB 00 00 50 E3 04 00 8D E5 04 00 00 1A 44 20 9D E5 00 00 82 E5 ?? ?? ?? EB 00 70 90 E5 7A 00 00 EA 28 30 86 E2 20 30 86 E5 0C 30 8D E5 00 30 A0 E3 08 A0 8D E5 04 30 8A E5 38 A0 86 E2 01 30 A0 E3 48 00 9D E5 03 70 A0 E1 00 30 80 E5 62 00 00 EA }
	condition:
		$pattern
}

rule pthread_reap_children_2406ce9d9468c4d8ffb4588a21810b50 {
	meta:
		aliases = "pthread_reap_children"
		size = "308"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { F0 4F 2D E9 18 61 9F E5 04 D0 4D E2 14 B1 9F E5 14 91 9F E5 0D A0 A0 E1 01 80 A0 E3 0C 70 A0 E3 37 00 00 EA 00 10 96 E5 00 50 91 E5 20 00 00 EA 14 30 95 E5 00 00 53 E1 00 20 95 E5 1B 00 00 1A 04 30 95 E5 04 30 82 E5 04 30 95 E5 1C 00 95 E5 00 20 83 E5 00 10 A0 E3 ?? ?? ?? EB 24 31 95 E5 00 00 53 E3 2E 80 C5 E5 08 00 00 0A BC 20 9F E5 00 30 92 E5 28 21 95 E5 02 30 83 E1 02 0B 13 E3 30 71 85 15 34 51 85 15 00 50 8B 15 ?? ?? ?? 1B 2D 40 D5 E5 1C 00 95 E5 ?? ?? ?? EB 00 00 54 E3 05 00 00 0A 05 00 A0 E1 A0 FF FF EB 02 00 00 EA 02 50 A0 E1 01 00 55 E1 DC FF FF 1A 00 30 99 E5 00 00 53 E3 03 00 00 0A }
	condition:
		$pattern
}

rule __des_crypt_1f3dda31a8c99562563d3d265ec24807 {
	meta:
		aliases = "__des_crypt"
		size = "384"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { F0 4F 2D E9 18 D0 4D E2 00 40 A0 E1 01 50 A0 E1 95 FC FF EB 08 20 8D E2 02 00 A0 E1 05 00 00 EA 00 30 D4 E5 83 30 A0 E1 00 30 C2 E5 01 30 D2 E4 00 00 53 E3 01 40 84 12 02 30 60 E0 08 00 53 E3 F6 FF FF 1A 25 FF FF EB 28 B1 9F E5 00 40 D5 E5 01 00 D5 E5 00 40 CB E5 01 30 D5 E5 00 00 53 E3 04 30 A0 01 01 30 CB E5 6D FC FF EB 00 53 A0 E1 04 00 A0 E1 6A FC FF EB 00 00 85 E1 BE FD FF EB 00 00 A0 E3 19 C0 A0 E3 00 10 A0 E1 14 20 8D E2 10 30 8D E2 00 C0 8D E5 D1 FD FF EB 00 00 50 E3 04 00 8D E5 00 00 A0 13 30 00 00 1A 10 20 8D E2 04 04 92 E8 0A 18 A0 E1 22 18 81 E1 02 21 A0 E1 B4 30 9F E5 21 E9 A0 E1 }
	condition:
		$pattern
}

rule re_search_2_e96e6a941277190fe00b3f981bfe3092 {
	meta:
		aliases = "__GI_re_search_2, re_search_2"
		size = "588"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 18 D0 4D E2 02 70 A0 E1 3C 20 8D E2 14 00 92 E8 07 A0 82 E0 0A 00 54 E1 00 20 A0 D3 01 20 A0 C3 A4 2F 92 E1 00 60 A0 E1 14 10 8D E5 03 B0 A0 E1 44 50 9D E5 10 80 80 E2 00 03 98 E8 77 00 00 1A 04 30 95 E0 00 50 64 42 01 00 00 4A 0A 00 53 E1 0A 50 64 C0 08 30 96 E5 00 00 53 E3 00 00 55 13 0B 00 00 DA 00 30 96 E5 00 30 D3 E5 0B 00 53 E3 04 00 00 0A 09 00 53 E3 05 00 00 1A 1C 30 D6 E5 80 00 13 E3 02 00 00 1A 00 00 54 E3 63 00 00 CA 01 50 A0 E3 00 00 58 E3 06 00 00 0A 1C 30 D6 E5 08 00 13 E3 03 00 00 1A 06 00 A0 E1 ?? ?? ?? EB 02 00 70 E3 5B 00 00 0A 0B 30 67 E0 10 30 8D E5 00 00 58 E3 }
	condition:
		$pattern
}

rule __GI_mallinfo_efaab0189ca271bb37bbdd442f2d90a6 {
	meta:
		aliases = "mallinfo, __GI_mallinfo"
		size = "380"
		objfiles = "mallinfo@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 18 D0 4D E2 50 11 9F E5 50 21 9F E5 50 31 9F E5 00 80 A0 E1 4C 41 9F E5 08 00 8D E2 0F E0 A0 E1 03 F0 A0 E1 40 31 9F E5 30 01 9F E5 0F E0 A0 E1 03 F0 A0 E1 2C 30 94 E5 00 00 53 E3 04 00 A0 01 ?? ?? ?? 0B 2C 30 94 E5 00 90 A0 E3 04 30 93 E5 04 00 A0 E1 09 10 A0 E1 08 02 8D E8 0C 00 00 EA 01 30 81 E2 03 21 90 E7 06 00 00 EA 04 30 92 E5 03 30 C3 E3 03 90 89 E0 04 30 9D E5 01 30 83 E2 08 20 92 E5 04 30 8D E5 00 00 52 E3 F6 FF FF 1A 01 10 81 E2 09 00 51 E3 F0 FF FF 9A 00 20 9D E5 01 B0 A0 E3 03 30 C2 E3 C0 C0 9F E5 03 A0 89 E0 0B 00 A0 E1 0B 00 00 EA 80 31 8C E0 08 10 43 E2 0C 20 91 E5 }
	condition:
		$pattern
}

rule __GI_erf_63681eedaa10f72a851997d6d58d69a9 {
	meta:
		aliases = "erf, __GI_erf"
		size = "2820"
		objfiles = "s_erf@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 1C 39 9F E5 02 61 C0 E3 14 D0 4D E2 03 00 56 E1 00 80 A0 E1 01 90 A0 E1 01 40 A0 E1 00 00 8D E5 10 00 00 DA 00 30 9D E5 A3 0F A0 E1 80 00 A0 E1 01 00 60 E2 ?? ?? ?? EB 08 20 A0 E1 00 40 A0 E1 01 50 A0 E1 09 30 A0 E1 D8 08 9F E5 00 10 A0 E3 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 21 00 00 EA BC 38 9F E5 03 00 56 E1 77 00 00 CA B4 38 9F E5 03 00 56 E1 1D 00 00 CA 02 05 56 E3 12 00 00 AA A4 28 9F E5 00 30 A0 E3 ?? ?? ?? EB 9C 28 9F E5 00 40 A0 E1 01 50 A0 E1 08 00 A0 E1 09 10 A0 E1 8C 38 9F E5 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __time_localtime_tzi_55bd4e4e2bccc36e57b353a74a466242 {
	meta:
		aliases = "__time_localtime_tzi"
		size = "844"
		objfiles = "_time_localtime_tzi@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 1C D0 4D E2 04 00 8D E5 00 00 A0 E3 00 20 8D E5 08 00 8D E5 01 80 A0 E1 08 10 9D E5 18 20 A0 E3 91 02 02 E0 03 00 9D E8 02 30 90 E7 00 00 91 E5 F8 12 9F E5 93 3A 63 E2 01 00 50 E1 2A 3D 83 E2 00 10 9D E5 00 30 63 C2 02 40 81 E0 00 30 83 E0 08 20 A0 E1 06 10 E0 D3 07 10 A0 C3 18 00 8D E2 18 30 8D E5 ?? ?? ?? EB 08 20 9D E5 20 20 88 E5 10 30 94 E4 00 30 63 E2 04 60 A0 E1 24 30 88 E5 AC 42 9F E5 04 50 84 E2 05 00 A0 E1 06 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 05 00 A0 01 15 00 00 0A 00 40 94 E5 00 00 54 E3 F5 FF FF 1A 06 00 A0 E1 07 10 A0 E3 ?? ?? ?? EB 06 00 50 E3 0C 00 00 CA 08 00 80 E2 }
	condition:
		$pattern
}

rule __divdc3_a4d399cc097d9502a3884fe7b64bd38a {
	meta:
		aliases = "__divdc3"
		size = "1968"
		objfiles = "_divdc3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 1C D0 4D E2 40 40 8D E2 30 10 94 E8 02 61 C4 E3 02 41 CC E3 4C C0 9D E5 05 70 A0 E1 0C 00 8D E8 00 A0 A0 E1 01 B0 A0 E1 06 00 A0 E1 07 10 A0 E1 04 20 A0 E1 0C 30 A0 E1 ?? ?? ?? EB 00 00 50 E3 35 00 00 AA 48 20 8D E2 0C 00 92 E8 40 00 8D E2 03 00 90 E8 ?? ?? ?? EB 00 40 A0 E1 01 50 A0 E1 04 20 A0 E1 05 30 A0 E1 40 00 8D E2 03 00 90 E8 ?? ?? ?? EB 48 20 8D E2 0C 00 92 E8 ?? ?? ?? EB 04 20 A0 E1 00 60 A0 E1 01 70 A0 E1 05 30 A0 E1 0A 00 A0 E1 0B 10 A0 E1 ?? ?? ?? EB 0C 00 9D E8 ?? ?? ?? EB 06 20 A0 E1 07 30 A0 E1 ?? ?? ?? EB 04 20 A0 E1 05 30 A0 E1 00 80 A0 E1 01 90 A0 E1 03 00 9D E8 }
	condition:
		$pattern
}

rule malloc_bf70e9e8e3c8cbc60de0f8458f2c9d4d {
	meta:
		aliases = "malloc"
		size = "2116"
		objfiles = "malloc@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 20 D0 4D E2 00 40 A0 E1 10 18 9F E5 10 00 8D E2 0C 28 9F E5 0C 38 9F E5 0F E0 A0 E1 03 F0 A0 E1 FC 07 9F E5 00 38 9F E5 0F E0 A0 E1 03 F0 A0 E1 21 00 74 E3 04 00 00 9A ?? ?? ?? EB 00 40 A0 E3 0C 30 A0 E3 00 30 80 E5 F1 01 00 EA 0B 00 84 E2 0F 00 50 E3 07 A0 C0 83 D0 07 9F E5 00 40 90 E5 10 A0 A0 93 01 00 14 E3 03 00 00 1A 00 00 54 E3 E2 00 00 1A ?? ?? ?? EB E0 00 00 EA 04 00 5A E1 07 00 00 8A A8 17 9F E5 AA 21 A0 E1 02 01 91 E7 00 00 50 E3 08 30 B0 15 00 40 A0 11 02 31 81 17 D6 01 00 1A FF 00 5A E3 0F 00 00 8A 84 37 9F E5 AA 81 A0 E1 88 31 83 E0 08 C0 43 E2 0C 00 9C E5 0C 00 50 E1 }
	condition:
		$pattern
}

rule do_des_c5e7cee1e5abddd71ecd36196bb6ebfb {
	meta:
		aliases = "do_des"
		size = "1024"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { F0 4F 2D E9 20 D0 4D E2 44 70 9D E5 00 00 57 E3 01 B0 A0 E1 10 20 8D E5 0C 30 8D E5 01 00 A0 03 E9 00 00 0A A8 83 9F C5 A8 C3 9F C5 18 80 8D C5 1C C0 8D C5 06 00 00 CA 44 30 9D E5 98 13 9F E5 98 23 9F E5 00 30 63 E2 18 10 8D E5 1C 20 8D E5 44 30 8D E5 88 63 9F E5 88 43 9F E5 FF 30 00 E2 03 31 A0 E1 20 17 A0 E1 04 C0 83 E0 FF 1F 01 E2 06 30 83 E0 20 7C A0 E1 20 53 A0 E1 00 0C 93 E5 04 30 81 E0 06 10 81 E0 00 14 91 E5 07 81 96 E7 00 34 93 E5 FF 5F 05 E2 08 10 8D E5 2B 2C A0 E1 00 30 8D E5 08 00 80 E1 04 30 85 E0 08 80 9D E5 06 50 85 E0 07 A1 94 E7 02 21 A0 E1 00 58 95 E5 00 CC 9C E5 04 70 82 E0 }
	condition:
		$pattern
}

rule __copy_rpcent_ee134246e5e4a1591187f74dce738042 {
	meta:
		aliases = "__copy_rpcent"
		size = "272"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 24 B0 9D E5 00 90 50 E2 00 50 A0 E3 01 60 A0 E1 02 A0 A0 E1 03 40 A0 E1 00 50 8B E5 02 00 80 02 F0 8F BD 08 01 00 A0 E1 0C 20 A0 E3 05 10 A0 E1 ?? ?? ?? EB 05 10 A0 E1 0A 00 A0 E1 04 20 A0 E1 ?? ?? ?? EB 08 30 99 E5 08 30 86 E5 05 10 A0 E1 04 30 99 E5 01 31 93 E7 00 00 53 E3 01 10 81 E2 FA FF FF 1A 01 01 A0 E1 00 00 54 E1 24 00 00 3A 04 80 60 E0 01 50 41 E2 00 70 8A E0 04 A0 86 E5 0F 00 00 EA 04 30 99 E5 04 00 93 E7 ?? ?? ?? EB 01 C0 80 E2 0C 00 58 E1 0C 20 A0 E1 08 80 6C E0 17 00 00 3A 04 30 96 E5 04 70 83 E7 04 00 96 E5 04 30 99 E5 04 00 90 E7 04 10 93 E7 0C 70 87 E0 ?? ?? ?? EB }
	condition:
		$pattern
}

rule _stdlib_strto_ll_4e0835b706f0483f32580beb28a94046 {
	meta:
		aliases = "_stdlib_strto_ll"
		size = "564"
		objfiles = "_stdlib_strto_ll@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 24 C2 9F E5 10 D0 4D E2 02 70 A0 E1 00 60 A0 E1 0C 10 8D E5 08 30 8D E5 00 00 00 EA 01 60 86 E2 00 20 D6 E5 00 30 9C E5 82 30 D3 E7 20 30 13 E2 F9 FF FF 1A 2B 00 52 E3 04 00 00 0A 2D 00 52 E3 03 90 A0 11 01 90 A0 03 01 00 00 0A 01 00 00 EA 03 90 A0 E1 01 60 86 E2 10 10 D7 E3 0D 00 00 1A 00 30 D6 E5 30 00 53 E3 0A 70 87 E2 07 00 00 1A 01 30 F6 E5 20 30 83 E3 78 00 53 E3 02 70 47 E2 06 00 A0 01 06 00 A0 11 87 70 A0 01 01 60 86 02 10 00 57 E3 10 70 A0 A3 02 30 47 E2 22 00 53 E3 00 40 A0 93 00 50 A0 93 07 A0 A0 91 CA BF A0 91 01 00 00 9A 38 00 00 EA 06 00 A0 E1 00 20 D6 E5 30 30 42 E2 }
	condition:
		$pattern
}

rule clnt_broadcast_8a32f4a0ae96f4bb468337f44f563750 {
	meta:
		aliases = "clnt_broadcast"
		size = "1560"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 29 DC 4D E2 1C D0 4D E2 10 10 8D E5 0C 20 8D E5 08 30 8D E5 14 00 8D E5 ?? ?? ?? EB 01 50 A0 E3 02 3A 8D E2 00 A0 A0 E1 02 00 A0 E3 00 10 A0 E1 11 20 A0 E3 14 59 83 E5 ?? ?? ?? EB 00 80 50 E2 8C 05 9F B5 C4 00 00 BA 29 3C 8D E2 04 C0 A0 E3 05 10 A0 E1 06 20 A0 E3 14 30 83 E2 00 C0 8D E5 ?? ?? ?? EB 00 00 50 E3 68 05 9F B5 BA 00 00 BA 64 35 9F E5 5C C0 8D E2 02 EA 8D E2 34 C0 4C E2 00 40 A0 E3 08 00 A0 E1 50 15 9F E5 29 2C 8D E2 0C 59 CE E5 00 39 8E E5 04 C9 8E E5 08 89 8E E5 0D 49 CE E5 ?? ?? ?? EB 04 00 50 E1 03 00 00 AA 2C 05 9F E5 ?? ?? ?? EB 1C 40 8D E5 37 00 00 EA 02 1A 8D E2 }
	condition:
		$pattern
}

rule __GI_acos_2a4a1cdf2fce00aef47edf2a58ed7c8e {
	meta:
		aliases = "__ieee754_acos, acos, __GI_acos"
		size = "1712"
		objfiles = "e_acos@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 2C 36 9F E5 02 21 C0 E3 03 00 52 E1 08 D0 4D E2 00 80 A0 E1 01 90 A0 E1 01 40 A0 E1 11 00 00 DA 03 21 82 E2 01 26 82 E2 01 20 92 E1 01 40 A0 E1 05 00 00 1A 00 00 50 E3 00 00 A0 C3 00 10 A0 C3 F0 05 9F D5 0E 00 00 DA 77 01 00 EA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 70 01 00 EA CC 35 9F E5 03 00 52 E1 71 00 00 CA C4 35 9F E5 03 00 52 E1 02 00 00 CA BC 05 9F E5 BC 15 9F E5 67 01 00 EA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB AC 25 9F E5 AC 35 9F E5 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? EB A0 25 9F E5 A0 35 9F E5 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 }
	condition:
		$pattern
}

rule __GI_log1p_e5b43336060a1f716d4771565a2f8381 {
	meta:
		aliases = "log1p, __GI_log1p"
		size = "1732"
		objfiles = "s_log1p@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 30 36 9F E5 03 00 50 E1 1C D0 4D E2 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 00 C0 A0 E1 43 00 00 CA 14 36 9F E5 02 41 C0 E3 03 00 54 E1 11 00 00 DA 08 26 9F E5 00 30 A0 E3 ?? ?? ?? EB 00 00 50 E3 FC 05 9F 05 00 10 A0 03 00 20 A0 03 00 30 A0 03 06 00 00 0A 05 20 A0 E1 06 30 A0 E1 05 00 A0 E1 06 10 A0 E1 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 69 01 00 EA C8 35 9F E5 03 00 54 E1 1B 00 00 CA C0 25 9F E5 00 30 A0 E3 ?? ?? ?? EB 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? EB AC 35 9F E5 00 00 50 E3 00 20 A0 E3 01 20 A0 C3 03 00 54 E1 00 30 A0 C3 01 30 02 D2 00 00 53 E3 59 01 00 1A 05 20 A0 E1 }
	condition:
		$pattern
}

rule freopen64_363347caee720536f0d7d85d81f0cd84 {
	meta:
		aliases = "freopen, freopen64"
		size = "404"
		objfiles = "freopen@libc.a, freopen64@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 34 90 92 E5 24 D0 4D E2 00 00 59 E3 02 50 A0 E1 00 B0 A0 E1 00 10 8D E5 0A 00 00 1A 38 40 82 E2 14 00 8D E2 44 31 9F E5 44 11 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 34 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 60 8D E2 20 11 9F E5 24 21 9F E5 06 00 A0 E1 10 81 9F E5 0F E0 A0 E1 08 F0 A0 E1 0C A1 9F E5 0C 01 9F E5 0F E0 A0 E1 0A F0 A0 E1 04 21 9F E5 00 30 92 E5 01 30 83 E2 00 30 82 E5 01 10 A0 E3 06 00 A0 E1 F0 70 9F E5 0F E0 A0 E1 07 F0 A0 E1 01 30 D5 E5 00 10 D5 E5 E0 20 9F E5 03 44 81 E1 02 20 04 E0 30 30 04 E2 30 00 53 E3 42 34 A0 E1 01 30 C5 E5 00 20 C5 E5 11 00 00 0A }
	condition:
		$pattern
}

rule trunc_9afc2e27e2383196c7bd7a900fda10d4 {
	meta:
		aliases = "__GI_trunc, trunc"
		size = "220"
		objfiles = "s_trunc@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 40 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF 2F 43 E2 03 20 42 E2 00 A0 A0 E3 00 B0 A0 E3 08 D0 4D E2 13 00 52 E3 00 40 A0 E1 01 50 A0 E1 00 60 A0 E1 01 70 A0 E1 00 0C 8D E8 0A 80 A0 E1 0B 90 A0 E1 01 E0 A0 E1 0E 00 00 CA 00 00 52 E3 02 11 00 E2 00 B0 A0 B3 01 A0 A0 B1 01 40 A0 B1 0B 50 A0 B1 17 00 00 BA 68 30 9F E5 53 32 C0 E1 01 30 83 E1 00 30 8D E5 00 30 A0 E3 04 30 8D E5 30 00 9D E8 0F 00 00 EA 33 00 52 E3 07 00 00 DA 01 0B 52 E3 0B 00 00 1A 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 00 40 A0 E1 01 50 A0 E1 05 00 00 EA 14 20 42 E2 00 30 E0 E3 33 92 C1 E1 00 80 A0 E1 00 40 A0 E1 09 50 A0 E1 }
	condition:
		$pattern
}

rule fstatfs64_85a6d178126e4d2a8a8106a6ffe186e2 {
	meta:
		aliases = "__GI_fstatfs64, __GI_statfs64, statfs64, fstatfs64"
		size = "188"
		objfiles = "fstatfs64@libc.a, statfs64@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 40 D0 4D E2 01 B0 A0 E1 0D 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 E0 B3 24 00 00 BA 08 30 9D E5 14 40 9D E5 03 10 A0 E1 00 20 A0 E3 08 10 8B E5 0C 20 8B E5 04 20 A0 E1 00 30 A0 E3 20 20 8B E5 24 30 8B E5 0C 80 9D E5 00 30 9D E5 10 60 9D E5 18 10 9D E5 04 00 9D E5 1C A0 8D E2 00 54 9A E8 00 20 A0 E3 00 30 8B E5 00 90 A0 E3 00 30 8D E2 00 70 A0 E3 28 10 8B E5 2C 20 8B E5 04 00 8B E5 10 80 8B E5 14 90 8B E5 18 60 8B E5 1C 70 8B E5 34 C0 8B E5 30 A0 8B E5 38 E0 8B E5 40 00 8B E2 2C 10 83 E2 14 20 A0 E3 ?? ?? ?? EB 00 00 A0 E3 40 D0 8D E2 F0 8F BD E8 }
	condition:
		$pattern
}

rule _time_mktime_tzi_91d6c7d7d5c1e60fd28bb4b46b515c00 {
	meta:
		aliases = "_time_mktime_tzi"
		size = "784"
		objfiles = "_time_mktime_tzi@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 40 D0 4D E2 08 00 8D E5 10 80 8D E2 02 90 A0 E1 04 10 8D E5 2C 20 A0 E3 08 00 A0 E1 08 10 9D E5 ?? ?? ?? EB 28 30 D9 E5 00 00 53 E3 30 30 8D 05 30 C0 9D E5 00 00 5C E3 20 20 88 E2 0C C0 8D 05 04 00 00 0A 01 30 A0 C3 00 30 E0 D3 00 30 82 E5 01 20 A0 E3 0C 20 8D E5 14 40 98 E5 19 1E A0 E3 04 00 A0 E1 ?? ?? ?? EB 10 60 98 E5 00 50 A0 E1 0C 10 A0 E3 06 00 A0 E1 18 50 88 E5 ?? ?? ?? EB 0C 30 A0 E3 90 03 03 E0 19 7E A0 E3 95 07 02 E0 06 30 63 E0 04 40 80 E0 00 00 53 E3 04 20 62 E0 14 20 88 E5 01 20 42 B2 14 20 88 B5 10 30 88 E5 0C 30 83 B2 10 30 88 B5 14 30 98 E5 76 4E 83 E2 0C 40 84 E2 }
	condition:
		$pattern
}

rule __GI_gethostbyname_r_9aa566837ddedc840077f07b017c86ed {
	meta:
		aliases = "gethostbyname_r, __GI_gethostbyname_r"
		size = "756"
		objfiles = "gethostbyname_r@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 40 D0 4D E2 0C 20 8D E5 64 20 9D E5 00 50 A0 E3 00 A0 50 E2 00 50 82 E5 01 70 A0 E1 03 60 A0 E1 16 50 85 02 AE 00 00 0A ?? ?? ?? EB 64 C0 9D E5 00 80 90 E5 00 50 80 E5 04 C0 8D E5 68 C0 9D E5 00 40 A0 E1 02 10 A0 E3 0A 00 A0 E1 07 20 A0 E1 0C 30 9D E5 00 60 8D E5 08 C0 8D E5 ?? ?? ?? EB 00 50 50 E2 00 80 84 05 9D 00 00 0A 68 20 9D E5 00 30 92 E5 01 00 53 E3 04 00 00 0A 04 00 53 E3 0A 00 00 0A 01 00 73 E3 95 00 00 1A 04 00 00 EA 02 00 55 E3 00 50 A0 13 01 50 A0 03 10 50 8D E5 04 00 00 EA 00 30 94 E5 02 00 53 E3 8C 00 00 1A 00 30 A0 E3 10 30 8D E5 68 C0 9D E5 00 30 E0 E3 00 80 84 E5 }
	condition:
		$pattern
}

rule clntraw_call_5c601813da9e6550d1713048000056dc {
	meta:
		aliases = "clntraw_call"
		size = "524"
		objfiles = "clnt_raw@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 48 D0 4D E2 08 10 8D E5 00 80 A0 E1 04 20 8D E5 00 30 8D E5 ?? ?? ?? EB A0 40 90 E5 00 00 54 E3 0C 60 84 E2 10 70 A0 03 70 00 00 0A 8A 5D 84 E2 04 50 85 E2 00 B0 A0 E3 18 A0 8D E2 0C 90 8D E2 0B 10 A0 E1 10 30 94 E5 0C B0 84 E5 06 00 A0 E1 0F E0 A0 E1 14 F0 93 E5 00 30 95 E5 98 21 9F E5 01 30 83 E2 02 30 84 E7 90 31 9F E5 05 10 A0 E1 03 20 94 E7 06 00 A0 E1 10 30 94 E5 0F E0 A0 E1 0C F0 93 E5 00 00 50 E3 08 10 8D E2 06 00 A0 E1 55 00 00 0A 10 30 94 E5 0F E0 A0 E1 04 F0 93 E5 00 00 50 E3 06 10 A0 E1 4F 00 00 0A 00 30 98 E5 03 00 A0 E1 20 30 93 E5 0F E0 A0 E1 04 F0 93 E5 00 00 50 E3 }
	condition:
		$pattern
}

rule strftime_bb1dbc75f39fb3c68e88cd9eb349eb04 {
	meta:
		aliases = "__GI_strftime, strftime"
		size = "1484"
		objfiles = "strftime@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 48 D0 4D E2 10 10 8D E5 14 00 8D E5 00 10 A0 E3 03 00 A0 E1 02 40 A0 E1 0C 30 8D E5 ?? ?? ?? EB 8C 35 9F E5 30 10 8D E2 03 00 50 E1 00 00 A0 C3 01 00 A0 D3 04 10 8D E5 ?? ?? ?? EB 30 30 8D E2 00 20 A0 E3 0B 30 83 E2 10 B0 9D E5 1C 20 8D E5 08 30 8D E5 04 00 A0 E1 00 00 5B E3 51 01 00 0A 00 30 D0 E5 00 00 53 E3 0D 00 00 1A 1C C0 9D E5 00 00 5C E3 10 E0 9D 05 14 10 9D 05 0E 00 6B 00 00 C0 C1 05 48 01 00 0A 1C 20 9D E5 48 C0 8D E2 01 20 42 E2 02 31 8C E0 28 00 13 E5 1C 20 8D E5 EC FF FF EA 25 00 53 E3 00 90 A0 11 09 40 A0 11 44 00 00 1A 01 30 D0 E5 25 00 53 E3 01 90 80 E2 00 40 A0 01 }
	condition:
		$pattern
}

rule __GI_erfc_b811df69013b6421e7eb1155132ea760 {
	meta:
		aliases = "erfc, __GI_erfc"
		size = "2864"
		objfiles = "s_erf@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 4C 39 9F E5 02 61 C0 E3 14 D0 4D E2 03 00 56 E1 00 80 A0 E1 01 90 A0 E1 00 40 A0 E1 01 50 A0 E1 00 A0 A0 E1 00 00 8D E5 0E 00 00 DA A0 0F A0 E1 80 00 A0 E1 ?? ?? ?? EB 08 20 A0 E1 00 40 A0 E1 01 50 A0 E1 09 30 A0 E1 08 09 9F E5 00 10 A0 E3 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 FE 00 00 EA EC 38 9F E5 03 00 56 E1 7C 00 00 CA E4 38 9F E5 03 00 56 E1 00 20 A0 D1 01 30 A0 D1 60 00 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB C8 28 9F E5 C8 38 9F E5 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? EB BC 28 9F E5 BC 38 9F E5 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 }
	condition:
		$pattern
}

rule __GI_gethostbyaddr_r_f3623effe835020fd0c806be4efb6949 {
	meta:
		aliases = "gethostbyaddr_r, __GI_gethostbyaddr_r"
		size = "724"
		objfiles = "gethostbyaddr_r@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 4C D0 4D E2 78 C0 9D E5 00 60 50 E2 00 00 A0 E3 00 00 8C E5 14 10 8D E5 10 20 8D E5 03 A0 A0 E1 70 40 8D E2 30 00 94 E8 A2 00 00 0A 02 00 52 E3 02 00 00 0A 0A 00 52 E3 9E 00 00 1A 02 00 00 EA 14 10 9D E5 04 00 51 E3 01 00 00 EA 14 20 9D E5 10 00 52 E3 97 00 00 1A 78 C0 9D E5 08 C0 8D E5 7C C0 9D E5 06 00 A0 E1 14 10 9D E5 10 20 9D E5 0A 30 A0 E1 30 00 8D E8 0C C0 8D E5 ?? ?? ?? EB 00 00 50 E3 8C 00 00 0A 7C 10 9D E5 00 30 91 E5 01 00 53 E3 01 00 00 0A 04 00 53 E3 86 00 00 1A 00 30 64 E2 03 80 03 E2 05 30 68 E0 38 B0 43 E2 7C 20 9D E5 FF 00 5B E3 00 30 E0 E3 00 30 82 E5 22 00 A0 D3 }
	condition:
		$pattern
}

rule strptime_37496062e79f235e6bd1d405bca690b0 {
	meta:
		aliases = "__GI_strptime, strptime"
		size = "1096"
		objfiles = "strptime@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 50 D0 4D E2 00 70 A0 E1 00 20 8D E5 01 00 A0 E1 00 20 A0 E3 02 C1 A0 E3 50 10 8D E2 02 31 81 E0 01 20 82 E2 0C 00 52 E3 4C C0 03 E5 F9 FF FF DA 00 60 A0 E1 00 90 A0 E3 00 30 D6 E5 00 00 53 E3 15 00 00 1A 00 00 59 E3 0E 00 00 1A 1C 30 9D E5 07 00 53 E3 1C 90 8D 05 09 20 A0 E1 50 00 8D E2 02 31 80 E0 4C 30 13 E5 02 01 53 E3 00 10 9D 15 02 31 81 17 01 20 82 E2 07 00 52 E3 F6 FF FF DA 07 00 A0 E1 E6 00 00 EA 01 90 49 E2 50 20 8D E2 09 31 82 E0 18 60 13 E5 E6 FF FF EA 25 00 53 E3 CB 00 00 1A 01 30 F6 E5 25 00 53 E3 C8 00 00 0A 45 00 53 E3 4F 00 53 13 3F 10 A0 13 03 00 00 1A 4F 00 53 E3 }
	condition:
		$pattern
}

rule clnttcp_call_cfe021549881fa6468335d3e2d4181ef {
	meta:
		aliases = "clnttcp_call"
		size = "740"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 50 D0 4D E2 1C 10 8D E5 08 50 90 E5 10 10 95 E5 08 30 8D E5 7C 30 8D E2 18 00 93 E8 00 00 51 E3 0C 20 8D E5 30 20 85 E2 10 20 8D E5 08 30 85 05 0C 40 85 05 74 30 9D E5 00 00 53 E3 00 70 A0 E1 4C 60 85 E2 06 00 00 1A 08 30 95 E5 00 00 53 E3 03 00 00 1A 0C 30 95 E5 00 80 53 E2 01 80 A0 13 00 00 00 EA 01 80 A0 E3 02 20 A0 E3 14 20 8D E5 30 30 85 E2 24 20 85 E2 0C 00 8D E8 00 A0 A0 E3 2C 90 8D E2 20 B0 8D E2 4C A0 85 E5 24 A0 85 E5 10 20 9D E5 00 30 92 E5 01 30 43 E2 00 30 82 E5 23 CC A0 E1 FF 28 03 E2 22 C4 8C E1 FF 2C 03 E2 02 C4 8C E1 03 3C 8C E1 50 40 95 E5 48 20 95 E5 06 00 A0 E1 }
	condition:
		$pattern
}

rule clntunix_call_7e900b5b0807c0064a167620c3ec0cee {
	meta:
		aliases = "clntunix_call"
		size = "740"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 50 D0 4D E2 1C 10 8D E5 08 50 90 E5 10 10 95 E5 08 30 8D E5 7C 30 8D E2 18 00 93 E8 00 00 51 E3 0C 20 8D E5 90 20 85 E2 10 20 8D E5 08 30 85 05 0C 40 85 05 74 30 9D E5 00 00 53 E3 00 70 A0 E1 AC 60 85 E2 06 00 00 1A 08 30 95 E5 00 00 53 E3 03 00 00 1A 0C 30 95 E5 00 80 53 E2 01 80 A0 13 00 00 00 EA 01 80 A0 E3 02 20 A0 E3 14 20 8D E5 90 30 85 E2 84 20 85 E2 0C 00 8D E8 00 A0 A0 E3 2C 90 8D E2 20 B0 8D E2 AC A0 85 E5 84 A0 85 E5 10 20 9D E5 00 30 92 E5 01 30 43 E2 00 30 82 E5 23 CC A0 E1 FF 28 03 E2 22 C4 8C E1 FF 2C 03 E2 02 C4 8C E1 03 3C 8C E1 B0 40 95 E5 A8 20 95 E5 06 00 A0 E1 }
	condition:
		$pattern
}

rule _vfprintf_internal_bf00f5b718876a6f016a0f8cc829a5b6 {
	meta:
		aliases = "_vfprintf_internal"
		size = "1608"
		objfiles = "_vfprintf_internal@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 51 DF 4D E2 0C 60 8D E2 00 90 A0 E1 06 00 A0 E1 02 50 A0 E1 01 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 0A 00 00 AA 0C 40 9D E5 04 00 A0 E1 ?? ?? ?? EB 00 10 50 E2 00 20 E0 03 08 20 8D 05 76 01 00 0A 04 00 A0 E1 09 20 A0 E1 ?? ?? ?? EB 70 01 00 EA 06 00 A0 E1 05 10 A0 E1 A4 B0 8D E2 ?? ?? ?? EB 00 C0 A0 E3 7F 30 8B E2 08 10 8D E9 04 20 A0 E1 00 30 D4 E5 00 00 53 E3 25 00 53 13 00 00 A0 03 01 00 A0 13 01 40 84 12 F8 FF FF 1A 02 00 54 E1 0A 00 00 0A 04 50 62 E0 00 00 55 E3 02 00 A0 C1 05 10 A0 C1 09 20 A0 C1 ?? ?? ?? CB 05 00 50 E1 57 01 00 1A 08 C0 9D E5 00 C0 8C E0 08 C0 8D E5 00 30 D4 E5 }
	condition:
		$pattern
}

rule __GI_cbrt_9a24abdce87612197b39e8ba65d05489 {
	meta:
		aliases = "cbrt, __GI_cbrt"
		size = "656"
		objfiles = "s_cbrt@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 54 32 9F E5 02 21 C0 E3 0C D0 4D E2 00 80 A0 E3 00 90 A0 E3 02 41 00 E2 03 00 52 E1 00 60 A0 E1 01 70 A0 E1 01 50 A0 E1 00 03 8D E8 08 40 8D E5 05 00 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 00 60 A0 E1 01 70 A0 E1 7F 00 00 EA 01 30 92 E1 01 40 A0 E1 7C 00 00 0A 01 06 52 E3 02 A0 A0 E1 01 B0 A0 E1 10 00 00 AA F0 31 9F E5 00 40 A0 E3 03 00 A0 E1 04 10 A0 E1 07 30 A0 E1 ?? ?? ?? EB 01 40 A0 E1 03 10 A0 E3 ?? ?? ?? EB 04 50 A0 E1 2A 44 80 E2 02 45 44 E2 87 4C 44 E2 6D 40 44 E2 04 80 A0 E1 05 90 A0 E1 09 00 00 EA 02 00 A0 E1 03 10 A0 E3 ?? ?? ?? EB 2B 34 80 E2 06 36 43 E2 87 3C 43 E2 }
	condition:
		$pattern
}

rule __muldc3_36df0c4ae4ec54ac9094342194f05f99 {
	meta:
		aliases = "__muldc3"
		size = "2024"
		objfiles = "_muldc3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 54 D0 4D E2 78 A0 8D E2 00 0C 9A E8 0C 00 8D E8 0A 20 A0 E1 0B 30 A0 E1 08 00 8D E5 0C 10 8D E5 ?? ?? ?? EB 80 70 8D E2 80 01 97 E8 24 00 8D E5 28 10 8D E5 07 20 A0 E1 08 30 A0 E1 03 00 9D E8 ?? ?? ?? EB 07 20 A0 E1 2C 00 8D E5 30 10 8D E5 08 30 A0 E1 08 00 8D E2 03 00 90 E8 ?? ?? ?? EB 0A 20 A0 E1 34 00 8D E5 38 10 8D E5 0B 30 A0 E1 03 00 9D E8 ?? ?? ?? EB 2C 20 8D E2 0C 00 92 E8 3C 00 8D E5 40 10 8D E5 24 00 8D E2 03 00 90 E8 ?? ?? ?? EB 3C 20 8D E2 0C 00 92 E8 44 00 8D E5 48 10 8D E5 34 00 8D E2 03 00 90 E8 ?? ?? ?? EB 4C 00 8D E5 50 10 8D E5 44 00 8D E2 03 00 90 E8 00 20 A0 E1 }
	condition:
		$pattern
}

rule ioperm_e5fcef059dcbc506a7730068d9847ca0 {
	meta:
		aliases = "__GI_ioperm, ioperm"
		size = "676"
		objfiles = "ioperm@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 60 52 9F E5 0C C0 95 E5 00 00 5C E3 43 DF 4D E2 00 A0 A0 E1 01 90 A0 E1 02 B0 A0 E1 67 00 00 1A 04 30 A0 E3 43 4F 8D E2 04 30 24 E5 03 20 85 E0 34 02 9F E5 03 10 A0 E3 04 30 A0 E1 04 C0 8D E5 00 C0 8D E5 ?? ?? ?? EB 00 C0 50 E2 0A 00 00 1A 04 30 A0 E1 14 02 9F E5 03 10 A0 E3 08 20 85 E2 04 C0 8D E5 00 C0 8D E5 ?? ?? ?? EB 00 00 50 E3 01 30 A0 03 0C 30 85 05 50 00 00 0A 08 40 8D E2 EC 01 9F E5 04 10 A0 E1 FF 20 A0 E3 ?? ?? ?? EB 00 00 50 E3 14 00 00 DA 43 3F 8D E2 00 20 83 E0 00 30 A0 E3 04 31 42 E5 C8 31 9F E5 00 20 93 E5 08 30 DD E5 83 30 D2 E7 08 00 13 E3 2A 00 00 0A B4 21 9F E5 }
	condition:
		$pattern
}

rule __ieee754_asin_52f9985f442c6f716739db5a4500916d {
	meta:
		aliases = "asin, __GI_asin, __ieee754_asin"
		size = "1536"
		objfiles = "e_asin@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 74 35 9F E5 02 41 C0 E3 14 D0 4D E2 03 00 54 E1 00 80 A0 E1 01 90 A0 E1 08 00 8D E5 1A 00 00 DA 03 21 84 E2 01 26 82 E2 01 20 92 E1 01 40 A0 E1 0E 00 00 1A 44 25 9F E5 44 35 9F E5 ?? ?? ?? EB 40 25 9F E5 00 40 A0 E1 01 50 A0 E1 38 35 9F E5 08 00 A0 E1 09 10 A0 E1 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 74 00 00 EA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB 35 01 00 EA FC 34 9F E5 03 00 54 E1 6C 00 00 CA F9 05 54 E3 08 00 00 AA EC 24 9F E5 EC 34 9F E5 ?? ?? ?? EB E8 24 9F E5 00 30 A0 E3 ?? ?? ?? EB 00 00 50 E3 2A 01 00 CA 61 00 00 EA }
	condition:
		$pattern
}

rule __gen_tempname_5a62f3e4b75e30f432d2a45af315ca05 {
	meta:
		aliases = "__gen_tempname"
		size = "704"
		objfiles = "tempname@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 78 D0 4D E2 00 10 8D E5 00 A0 A0 E1 ?? ?? ?? EB 00 B0 A0 E1 0A 00 A0 E1 ?? ?? ?? EB 00 10 9B E5 05 00 50 E3 0C 10 8D E5 08 00 00 9A 00 30 8A E0 06 30 43 E2 04 30 8D E5 03 00 A0 E1 5C 12 9F E5 ?? ?? ?? EB 00 00 50 E3 08 00 8D 05 88 00 00 0A 00 00 E0 E3 16 30 A0 E3 8B 00 00 EA 40 02 9F E5 00 10 A0 E3 ?? ?? ?? EB 00 50 50 E2 04 00 00 AA 30 02 9F E5 02 1B A0 E3 ?? ?? ?? EB 00 50 50 E2 08 00 00 BA 72 10 8D E2 06 20 A0 E3 05 00 A0 E1 ?? ?? ?? EB 00 40 A0 E1 05 00 A0 E1 ?? ?? ?? EB 06 00 54 E3 39 00 00 0A 00 10 A0 E3 68 00 8D E2 ?? ?? ?? EB F0 21 9F E5 6C 40 9D E5 00 03 92 E8 68 60 9D E5 }
	condition:
		$pattern
}

rule __GI_vfscanf_da1a928a883a1998858176d28830fbd2 {
	meta:
		aliases = "vfscanf, __GI_vfscanf"
		size = "1672"
		objfiles = "vfscanf@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 7B DF 4D E2 43 6F 8D E2 00 00 8D E5 00 30 E0 E3 01 50 A0 E1 02 B0 A0 E1 06 00 A0 E1 00 10 A0 E3 24 20 A0 E3 30 31 8D E5 ?? ?? ?? EB 00 00 9D E5 34 00 90 E5 00 00 50 E3 08 00 8D E5 0B 00 00 1A 00 10 9D E5 38 40 81 E2 76 0F 8D E2 14 36 9F E5 14 16 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 04 36 9F E5 0F E0 A0 E1 03 F0 A0 E1 66 4F 8D E2 04 00 A0 E1 00 10 9D E5 ?? ?? ?? EB EC 35 9F E5 C4 31 8D E5 A0 31 9D E5 03 30 D3 E5 00 20 A0 E3 01 70 A0 E3 B0 31 CD E5 C8 31 9D E5 02 A0 A0 E1 04 80 A0 E1 07 90 A0 E1 D4 31 8D E5 40 21 8D E5 44 01 00 EA B1 31 DD E5 02 21 E0 E3 01 30 03 E2 }
	condition:
		$pattern
}

rule byte_regex_compile_6a9b2e93834e70bb80ebdfac89abfe02 {
	meta:
		aliases = "byte_regex_compile"
		size = "9300"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 82 DF 4D E2 34 00 8D E5 30 20 8D E5 34 20 9D E5 00 22 8D E5 03 50 A0 E1 14 30 93 E5 01 10 82 E0 0A 0D A0 E3 40 10 8D E5 44 30 8D E5 ?? ?? ?? EB 00 00 50 E3 60 00 8D E5 FB 08 00 0A 1C 30 D5 E5 08 30 C3 E3 1C 30 C5 E5 1C 30 D5 E5 40 30 C3 E3 1C 30 C5 E5 1C 30 D5 E5 20 30 C3 E3 1C 30 C5 E5 B0 3F 9F E5 00 40 93 E5 30 C0 9D E5 00 30 A0 E3 00 00 54 E3 18 30 85 E5 0C C0 85 E5 08 30 85 E5 16 00 00 1A 04 10 A0 E1 8C 0F 9F E5 01 2C A0 E3 ?? ?? ?? EB 84 EF 9F E5 7C CF 9F E5 04 10 A0 E1 01 00 A0 E3 05 00 00 EA 00 30 9E E5 03 30 82 E0 01 30 D3 E5 08 00 13 E3 01 00 CC 17 01 10 81 E2 FF 00 51 E3 }
	condition:
		$pattern
}

rule _stdlib_strto_l_befc8f353bb25057eba7ac5f6dbf7565 {
	meta:
		aliases = "_stdlib_strto_l"
		size = "408"
		objfiles = "_stdlib_strto_l@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 88 C1 9F E5 01 90 A0 E1 02 50 A0 E1 03 B0 A0 E1 00 40 A0 E1 00 00 00 EA 01 40 84 E2 00 20 D4 E5 00 30 9C E5 82 30 D3 E7 20 30 13 E2 F9 FF FF 1A 2B 00 52 E3 04 00 00 0A 2D 00 52 E3 03 70 A0 11 01 70 A0 03 01 00 00 0A 01 00 00 EA 03 70 A0 E1 01 40 84 E2 10 30 D5 E3 00 60 A0 11 0E 00 00 1A 00 30 D4 E5 30 00 53 E3 0A 50 85 E2 00 60 A0 11 07 00 00 1A 01 30 F4 E5 20 30 83 E3 78 00 53 E3 02 50 45 E2 04 60 A0 01 04 60 A0 11 85 50 A0 01 01 40 84 02 10 00 55 E3 10 50 A0 A3 02 30 45 E2 22 00 53 E3 00 C0 A0 83 28 00 00 8A 05 10 A0 E1 00 00 E0 E3 ?? ?? ?? EB 05 10 A0 E1 00 30 A0 E1 00 00 E0 E3 }
	condition:
		$pattern
}

rule sigwait_7d48e06e2d0b595d650c52900c6d4e5e {
	meta:
		aliases = "sigwait"
		size = "380"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { F0 4F 2D E9 88 D0 4D E2 7C 50 8D E2 00 10 8D E5 00 60 A0 E1 55 FF FF EB 48 41 9F E5 00 20 A0 E1 00 30 E0 E3 05 00 A0 E1 00 10 94 E5 84 20 8D E5 80 30 8D E5 7C 30 8D E5 ?? ?? ?? EB 28 B1 9F E5 28 91 9F E5 28 A1 9F E5 04 80 A0 E1 05 70 A0 E1 01 40 A0 E3 68 50 8D E2 1C 00 00 EA ?? ?? ?? EB 00 00 50 E3 18 00 00 0A 08 21 9F E5 00 30 92 E5 03 00 54 E1 14 00 00 0A 00 30 98 E5 03 00 54 E1 11 00 00 0A 00 30 9B E5 03 00 54 E1 04 10 A0 E1 07 00 A0 E1 0C 00 00 0A ?? ?? ?? EB 04 31 99 E7 01 00 53 E3 08 00 00 8A 00 10 A0 E3 14 20 A0 E3 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 05 10 A0 E1 00 20 A0 E3 68 A0 8D E5 }
	condition:
		$pattern
}

rule des_init_8a232f0c882ea544f0c2f2ae6b948da5 {
	meta:
		aliases = "des_init"
		size = "1296"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { F0 4F 2D E9 8C 34 9F E5 00 30 93 E5 01 00 53 E3 02 DC 4D E2 1D 01 00 0A 7C 34 9F E5 00 20 A0 E3 00 20 83 E5 74 34 9F E5 00 20 83 E5 70 34 9F E5 70 54 9F E5 00 20 83 E5 6C 34 9F E5 02 00 A0 E1 02 40 A0 E1 00 20 83 E5 11 00 00 EA 00 C3 A0 E1 02 2C 8D E2 04 10 A0 E1 02 E0 8C E0 C1 30 A0 E1 01 20 01 E2 0F 30 03 E2 02 32 83 E1 20 20 01 E2 02 30 83 E1 03 30 8C E0 05 20 D3 E7 01 30 8E E0 01 10 81 E2 3F 00 51 E3 00 22 43 E5 F2 FF FF DA 01 00 80 E2 07 00 50 E3 EB FF FF DA 00 60 A0 E3 08 94 9F E5 06 E0 A0 E1 0D 00 00 EA 00 30 8A E0 00 22 53 E5 00 12 54 E5 05 30 80 E1 01 00 80 E2 01 22 82 E1 03 30 88 E0 }
	condition:
		$pattern
}

rule _vfwprintf_internal_2ed6158cea90d6a2d8d7371ddcf436e7 {
	meta:
		aliases = "_vfwprintf_internal"
		size = "1820"
		objfiles = "_vfwprintf_internal@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 96 DF 4D E2 01 50 A0 E1 00 B0 A0 E1 00 10 A0 E3 02 60 A0 E1 43 0F 8D E2 98 20 A0 E3 ?? ?? ?? EB 24 C1 9D E5 00 E0 A0 E3 96 1F 8D E2 01 C0 4C E2 92 3F 8D E2 24 C1 8D E5 04 50 21 E5 80 C0 A0 E3 0E 00 A0 E1 00 20 E0 E3 1C C1 8D E5 0C 51 8D E5 48 E2 8D E5 ?? ?? ?? EB 01 00 70 E3 94 36 9F 05 0C 31 8D 05 23 00 00 0A 09 30 A0 E3 4D 2F 8D E2 08 10 A0 E3 01 30 53 E2 04 10 82 E4 FC FF FF 1A 05 20 A0 E1 43 4F 8D E2 0C 00 00 EA 25 00 53 E3 09 00 00 1A 04 30 B2 E5 25 00 53 E3 04 00 A0 E1 05 00 00 0A 0C 21 8D E5 ?? ?? ?? EB 00 00 50 E3 10 00 00 BA 0C 21 9D E5 00 00 00 EA 04 20 82 E2 00 30 92 E5 }
	condition:
		$pattern
}

rule __GI_fnmatch_9a1d770ba226c419db7bcee7aa79abf4 {
	meta:
		aliases = "fnmatch, __GI_fnmatch"
		size = "1564"
		objfiles = "fnmatch_old@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 A2 30 A0 E1 01 30 23 E2 20 D0 4D E2 02 70 A0 E1 01 30 03 E2 F4 95 9F E5 F4 A5 9F E5 04 30 8D E5 10 60 02 E2 01 B0 02 E2 02 30 07 E2 04 20 02 E2 01 50 A0 E1 10 10 8D E5 08 20 8D E5 00 30 8D E5 62 01 00 EA 00 00 56 E3 14 60 8D E5 07 00 00 0A 80 00 1E E3 05 00 00 1A 00 30 99 E5 8E 20 A0 E1 02 30 D3 E7 01 00 13 E3 00 30 9A 15 02 E0 D3 17 3F 00 5E E3 01 00 80 E2 08 00 00 0A 02 00 00 8A 2A 00 5E E3 3C 01 00 1A 3D 00 00 EA 5B 00 5E E3 97 00 00 0A 5C 00 5E E3 37 01 00 1A 13 00 00 EA 00 30 D5 E5 00 00 53 E3 53 01 00 0A 00 00 5B E3 01 00 00 0A 2F 00 53 E3 4F 01 00 0A 08 20 9D E5 00 00 52 E3 }
	condition:
		$pattern
}

rule __GI_remquo_c2365d9790d608d63cb1d961d526f983 {
	meta:
		aliases = "remquo, __GI_remquo"
		size = "96"
		objfiles = "s_remquo@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 A2 4F A0 E1 A0 0F 54 E1 03 B0 A0 E1 02 A0 A0 E1 01 50 A0 03 00 50 E0 13 00 80 A0 E1 01 90 A0 E1 00 60 A0 E1 01 70 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 24 40 9D E5 ?? ?? ?? EB 7F 00 00 E2 95 00 03 E0 09 10 A0 E1 00 30 84 E5 08 00 A0 E1 0A 20 A0 E1 0B 30 A0 E1 F0 4F BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __ns_name_ntop_6293d4ac1c70ed5ec92c6ec599a7f9e4 {
	meta:
		aliases = "__GI___ns_name_ntop, __ns_name_ntop"
		size = "436"
		objfiles = "ns_name@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 A4 B1 9F E5 01 70 A0 E1 02 80 81 E0 00 A0 A0 E1 01 50 A0 E1 4A 00 00 EA C0 00 13 E3 03 90 A0 E1 56 00 00 1A 07 00 55 E1 07 50 A0 01 03 00 00 0A 08 00 55 E1 51 00 00 2A 2E 20 A0 E3 01 20 C5 E4 03 30 85 E0 08 00 53 E1 4C 00 00 2A 01 A0 8A E2 39 00 00 EA 00 60 DA E5 2E 00 56 E3 0A 00 00 0A 03 00 00 8A 22 00 56 E3 07 00 00 0A 24 00 56 E3 04 00 00 EA 40 00 56 E3 03 00 00 0A 5C 00 56 E3 01 00 00 0A 3B 00 56 E3 41 00 00 1A 01 30 85 E2 08 00 53 E1 39 00 00 2A 5C 20 A0 E3 01 60 C5 E5 00 20 C5 E5 01 50 83 E2 21 00 00 EA 03 30 85 E2 08 00 53 E1 31 00 00 2A 05 40 A0 E1 5C 30 A0 E3 01 30 C4 E4 }
	condition:
		$pattern
}

rule getnameinfo_4b1a8d921058b2a2c52672d68f1c1060 {
	meta:
		aliases = "__GI_getnameinfo, getnameinfo"
		size = "772"
		objfiles = "getnameinfo@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 A6 DF 4D E2 01 40 A0 E1 02 A0 A0 E1 00 50 A0 E1 03 80 A0 E1 ?? ?? ?? EB C4 92 9D E5 00 20 90 E5 1F 10 D9 E3 00 00 8D E5 0C 20 8D E5 00 00 E0 13 AC 00 00 1A 00 00 55 E3 01 00 54 13 A8 00 00 9A 00 20 D5 E5 01 30 D5 E5 03 24 82 E1 01 00 52 E3 07 00 00 0A 02 00 52 E3 01 00 00 1A 0F 00 54 E3 02 00 00 EA 0A 00 52 E3 9D 00 00 1A 1B 00 54 E3 9B 00 00 9A 00 30 5A E2 01 30 A0 13 00 10 58 E2 01 10 A0 13 01 00 13 E1 04 30 8D E5 08 10 8D E5 5D 00 00 0A 02 00 52 E3 04 00 00 0A 0A 00 52 E3 02 00 00 0A 01 00 52 E3 57 00 00 1A 42 00 00 EA 01 00 19 E3 2C 00 00 1A 0A 00 52 E3 08 00 85 02 10 10 A0 03 }
	condition:
		$pattern
}

rule __ieee754_lgamma_r_400362d0c62bd1f64b601146dca42ed0 {
	meta:
		aliases = "lgamma_r, gamma_r, __ieee754_lgamma_r"
		size = "4604"
		objfiles = "e_lgamma_r@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 B4 3F 9F E5 02 91 C0 E3 28 D0 4D E2 03 00 59 E1 01 30 A0 E3 00 A0 A0 E1 01 B0 A0 E1 00 40 A0 E1 01 50 A0 E1 18 00 8D E5 04 20 8D E5 00 30 82 E5 03 00 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? EB D7 03 00 EA 01 40 A0 E1 04 40 99 E1 1C 10 8D E5 A6 00 00 0A 64 3F 9F E5 03 00 59 E1 0F 00 00 CA 18 20 9D E5 00 00 52 E3 07 00 00 AA 04 40 9D E5 00 30 E0 E3 02 01 80 E2 00 30 84 E5 ?? ?? ?? EB 02 21 80 E2 10 20 8D E5 02 00 00 EA ?? ?? ?? EB 02 31 80 E2 10 30 8D E5 14 10 8D E5 C2 03 00 EA 18 40 9D E5 00 00 54 E3 00 20 A0 A3 00 30 A0 A3 08 20 8D A5 0C 30 8D A5 AC 00 00 AA 00 3F 9F E5 03 00 59 E1 }
	condition:
		$pattern
}

rule __GI_fflush_unlocked_dde9cecc298dd68af6a97dc8e2dc90f9 {
	meta:
		aliases = "fflush_unlocked, __GI_fflush_unlocked"
		size = "488"
		objfiles = "fflush_unlocked@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 B8 31 9F E5 03 00 50 E1 00 A0 A0 E1 14 D0 4D E2 00 A0 A0 03 00 A0 8D 05 03 00 00 0A 01 2C A0 E3 00 00 5A E3 00 20 8D E5 52 00 00 1A 04 50 8D E2 8C 71 9F E5 8C 21 9F E5 8C 11 9F E5 05 00 A0 E1 0F E0 A0 E1 07 F0 A0 E1 80 61 9F E5 74 01 9F E5 0F E0 A0 E1 06 F0 A0 E1 74 21 9F E5 00 30 92 E5 01 30 83 E2 00 30 82 E5 68 41 9F E5 01 10 A0 E3 05 00 A0 E1 0F E0 A0 E1 04 F0 A0 E1 48 11 9F E5 54 21 9F E5 05 00 A0 E1 0F E0 A0 E1 07 F0 A0 E1 44 01 9F E5 0F E0 A0 E1 06 F0 A0 E1 1C 31 9F E5 05 00 A0 E1 01 10 A0 E3 00 80 93 E5 0F E0 A0 E1 04 F0 A0 E1 24 91 9F E5 07 B0 A0 E1 06 70 A0 E1 00 60 E0 E3 }
	condition:
		$pattern
}

rule __mulvdi3_c967d262a224e1902efae64caad04716 {
	meta:
		aliases = "__mulvdi3"
		size = "600"
		objfiles = "_mulvdi3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 C0 0F 51 E1 0C D0 4D E2 00 80 A0 E1 01 90 A0 E1 01 A0 A0 E1 00 B0 A0 E1 02 60 A0 E1 03 70 A0 E1 09 00 00 1A C2 0F 53 E1 03 80 A0 E1 27 00 00 1A 02 00 A0 E1 C0 1F A0 E1 0B 20 A0 E1 C2 3F A0 E1 ?? ?? ?? EB 0C D0 8D E2 F0 8F BD E8 C6 0F 57 E1 08 20 8D E5 40 00 00 1A 06 40 A0 E1 00 50 A0 E3 00 20 A0 E1 00 30 A0 E3 05 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 04 20 A0 E1 03 00 8D E8 05 30 A0 E1 09 00 A0 E1 00 10 A0 E3 ?? ?? ?? EB 00 00 59 E3 08 C0 9D B5 08 20 9D E5 01 10 6C B0 00 00 52 E3 2A 00 00 BA 04 30 9D E5 03 60 A0 E1 00 70 A0 E3 00 60 96 E0 01 70 A7 E0 C6 3F A0 E1 07 00 53 E1 1E 00 00 1A }
	condition:
		$pattern
}

rule __open_nameservers_17a2c9d5e083383b10ec492d110f93a1 {
	meta:
		aliases = "__open_nameservers"
		size = "1044"
		objfiles = "opennameservers@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 C4 33 9F E5 00 40 93 E5 00 00 54 E3 7E DF 4D E2 0A 00 00 1A 61 1F 8D E2 B0 03 9F E5 ?? ?? ?? EB 00 00 50 E3 C4 41 8D 15 A4 13 9F E5 C4 21 9D E5 00 30 91 E5 02 00 53 E1 00 20 81 15 ?? ?? ?? 1B 90 43 9F E5 00 30 94 E5 00 00 53 E3 D7 00 00 1A 84 63 9F E5 05 30 83 E2 80 53 9F E5 00 30 C6 E5 03 30 A0 E3 64 03 9F E5 74 13 9F E5 00 30 C5 E5 ?? ?? ?? EB 00 B0 50 E2 89 00 00 1A 96 00 00 EA 41 0F 8D E2 CC FF FF EB 00 40 A0 E1 BA FF FF EB C9 FF FF EB 4C 13 9F E5 00 60 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 50 50 E2 31 00 00 1A 06 00 A0 E1 B1 FF FF EB 05 10 A0 E1 00 50 C0 E5 1C 20 A0 E3 07 00 A0 E1 }
	condition:
		$pattern
}

rule __GI_ttyname_r_b7f4f8a3795678439d5036a296ea8707 {
	meta:
		aliases = "ttyname_r, __GI_ttyname_r"
		size = "340"
		objfiles = "ttyname@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 D0 D0 4D E2 01 B0 A0 E1 58 10 8D E2 02 90 A0 E1 00 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 02 00 00 AA ?? ?? ?? EB 00 40 90 E5 44 00 00 EA 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 0C 01 9F 15 B0 70 8D 12 38 00 00 1A 3A 00 00 EA 01 60 80 E2 06 10 A0 E1 07 00 A0 E1 ?? ?? ?? EB 06 00 A0 E1 ?? ?? ?? EB 00 50 50 E2 1E A0 64 E2 04 80 87 E0 22 00 00 1A 29 00 00 EA ?? ?? ?? EB 0A 00 50 E1 1E 00 00 8A 04 10 A0 E1 08 00 A0 E1 ?? ?? ?? EB 07 00 A0 E1 0D 10 A0 E1 ?? ?? ?? EB 00 40 50 E2 16 00 00 1A 10 30 9D E5 0F 3A 03 E2 02 0A 53 E3 12 00 00 1A 78 20 9D E5 20 30 9D E5 03 00 52 E1 0E 00 00 1A 7C 20 9D E5 }
	condition:
		$pattern
}

rule __pthread_destroy_specifics_e67604e277c2d948aa6258103e531b65 {
	meta:
		aliases = "__pthread_destroy_specifics"
		size = "252"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { F0 4F 2D E9 DE FF FF EB 00 80 A0 E3 01 10 A0 E3 00 60 A0 E1 08 70 A0 E1 01 B0 A0 E1 1C 00 00 EA 05 31 86 E0 60 20 83 E2 14 30 92 E5 00 00 53 E3 02 90 A0 11 07 40 A0 11 85 A2 A0 11 0B 00 00 1A 0F 00 00 EA 14 30 99 E5 04 20 92 E5 04 01 93 E7 00 00 52 E3 00 00 50 13 03 00 00 0A 04 71 83 E7 0F E0 A0 E1 02 F0 A0 E1 0B 10 A0 E1 01 40 84 E2 80 00 9F E5 04 30 8A E0 1F 00 54 E3 83 21 80 E0 EF FF FF DA 01 50 85 E2 1F 00 55 E3 E3 FF FF DA 01 80 88 E2 03 00 58 E3 00 40 A0 C3 01 40 01 D2 00 00 54 E3 07 50 A0 11 07 10 A0 11 F5 FF FF 1A 1C 00 96 E5 06 10 A0 E1 ?? ?? ?? EB 04 70 A0 E1 04 00 00 EA 14 30 95 E5 }
	condition:
		$pattern
}

rule writeunix_5cc7b5702b4e4c4288dbd84827c81ff2 {
	meta:
		aliases = "writeunix"
		size = "244"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 E0 80 9F E5 30 D0 4D E2 02 60 A0 E1 00 A0 A0 E1 01 50 A0 E1 02 40 A0 E1 18 B0 A0 E3 00 70 A0 E3 2B 00 00 EA 00 90 9A E5 ?? ?? ?? EB 1C 00 8D E5 ?? ?? ?? EB 20 00 8D E5 ?? ?? ?? EB 1C 10 8D E2 24 00 8D E5 0C 20 A0 E3 9C 00 9F E5 ?? ?? ?? EB 01 30 A0 E3 04 30 88 E5 03 30 83 E0 08 30 88 E5 28 30 8D E2 08 30 8D E5 01 30 A0 E3 00 B0 88 E5 28 50 8D E5 2C 40 8D E5 0C 30 8D E5 00 70 8D E5 04 70 8D E5 10 80 8D E5 14 B0 8D E5 18 70 8D E5 0D 10 A0 E1 07 20 A0 E1 09 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 08 00 00 AA ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 F5 FF FF 0A 2C 20 9A E5 00 30 A0 E3 00 60 E0 E3 }
	condition:
		$pattern
}

rule _getopt_internal_bdc880fa1b3e80f6ee2b7ee849779bad {
	meta:
		aliases = "_getopt_internal"
		size = "2108"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 E8 C7 9F E5 00 E0 9C E5 E4 C7 9F E5 00 C0 9C E5 24 D0 4D E2 14 C0 8D E5 14 40 9D E5 D4 C7 9F E5 04 40 8C E5 00 E0 8C E5 02 90 A0 E1 00 20 D2 E5 3A 00 52 E3 00 40 A0 03 00 00 50 E3 14 40 8D E5 08 00 8D E5 01 70 A0 E1 03 A0 A0 E1 D9 01 00 DA 00 30 A0 E3 00 00 5E E3 08 30 8C E5 01 30 A0 03 00 30 8C 05 02 00 00 0A 10 30 9C E5 00 00 53 E3 1B 00 00 1A 7C 47 9F E5 00 30 94 E5 00 50 A0 E3 20 30 84 E5 24 30 84 E5 6C 07 9F E5 1C 50 84 E5 ?? ?? ?? EB 05 00 50 E0 01 00 A0 13 18 00 84 E5 00 30 D9 E5 2D 00 53 E3 01 90 89 02 02 30 A0 03 07 00 00 0A 2B 00 53 E3 01 90 89 02 02 00 00 0A 00 00 50 E3 }
	condition:
		$pattern
}

rule __ieee754_rem_pio2_8bf88214bee7c45d3b70dad1e680557a {
	meta:
		aliases = "__ieee754_rem_pio2"
		size = "1608"
		objfiles = "e_rem_pio2@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 EC 35 9F E5 02 A1 C0 E3 38 D0 4D E2 03 00 5A E1 00 60 A0 E1 01 70 A0 E1 01 40 A0 E1 1C 00 8D E5 08 20 8D E5 07 00 00 CA 00 10 A0 E3 00 30 A0 E3 00 40 A0 E3 18 10 8D E5 08 30 82 E5 0C 40 82 E5 C0 00 82 E8 67 01 00 EA A8 35 9F E5 03 00 5A E1 58 00 00 CA 1C 20 9D E5 00 00 52 E3 28 00 00 DA 94 35 9F E5 94 25 9F E5 ?? ?? ?? EB 8C 35 9F E5 03 00 5A E1 00 60 A0 E1 01 70 A0 E1 0C 00 00 0A 7C 25 9F E5 7C 35 9F E5 ?? ?? ?? EB 08 C0 9D E5 00 20 A0 E1 01 30 A0 E1 03 00 8C E8 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? EB 54 25 9F E5 54 35 9F E5 10 00 00 EA 48 25 9F E5 4C 35 9F E5 ?? ?? ?? EB 48 25 9F E5 }
	condition:
		$pattern
}

rule __GI_exp_1540522ab97876c25dd8b5100e794f9b {
	meta:
		aliases = "__ieee754_exp, exp, __GI_exp"
		size = "1144"
		objfiles = "e_exp@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 F0 33 9F E5 02 C1 C0 E3 03 00 5C E1 0C D0 4D E2 00 80 A0 E1 01 90 A0 E1 01 40 A0 E1 A0 6F A0 E1 1F 00 00 9A D0 33 9F E5 03 00 5C E1 09 00 00 9A FF 24 C0 E3 0F 26 C2 E3 01 20 92 E1 01 40 A0 E1 00 20 A0 11 01 30 A0 11 5D 00 00 1A 00 00 56 E3 E4 00 00 0A 0F 00 00 EA A0 23 9F E5 A0 33 9F E5 ?? ?? ?? EB 00 00 50 E3 98 03 9F C5 98 13 9F C5 00 20 A0 C1 01 30 A0 C1 D7 00 00 CA 08 00 A0 E1 09 10 A0 E1 84 23 9F E5 84 33 9F E5 ?? ?? ?? EB 00 00 50 E3 16 00 00 AA 00 80 A0 E3 00 90 A0 E3 D0 00 00 EA 6C 33 9F E5 03 00 5C E1 35 00 00 9A 64 33 9F E5 03 00 5C E1 0D 00 00 8A 5C 33 9F E5 86 41 A0 E1 }
	condition:
		$pattern
}

rule __GI_expm1_d07c47fb66bedfb0906ee900e67721db {
	meta:
		aliases = "expm1, __GI_expm1"
		size = "1680"
		objfiles = "s_expm1@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 F0 35 9F E5 02 C1 C0 E3 03 00 5C E1 0C D0 4D E2 00 80 A0 E1 01 90 A0 E1 01 40 A0 E1 02 61 00 E2 27 00 00 9A D0 35 9F E5 03 00 5C E1 15 00 00 9A C8 35 9F E5 03 00 5C E1 09 00 00 9A FF 24 C0 E3 0F 26 C2 E3 01 20 92 E1 01 40 A0 E1 00 20 A0 11 01 30 A0 11 20 01 00 1A 00 00 56 E3 61 01 00 0A 14 00 00 EA 98 25 9F E5 98 35 9F E5 ?? ?? ?? EB 00 00 50 E3 90 05 9F C5 90 15 9F C5 00 20 A0 C1 01 30 A0 C1 08 01 00 CA 00 00 56 E3 2B 00 00 0A 7C 25 9F E5 7C 35 9F E5 08 00 A0 E1 09 10 A0 E1 ?? ?? ?? EB 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? EB 00 00 50 E3 1E 00 00 AA 5C 85 9F E5 00 90 A0 E3 48 01 00 EA }
	condition:
		$pattern
}

rule __psfs_do_numeric_bfce38c2eb813ef2ab05c276bccabfa0 {
	meta:
		aliases = "__psfs_do_numeric"
		size = "1308"
		objfiles = "__psfs_do_numeric@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 F8 34 9F E5 3C B0 90 E5 03 30 8B E0 01 00 5B E3 B4 D0 4D E2 00 80 A0 E1 01 40 A0 E1 01 70 53 E5 1E 00 00 1A D8 54 9F E5 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 03 00 00 BA 00 20 D5 E5 00 30 94 E5 03 00 52 E1 05 00 00 0A 04 00 A0 E1 ?? ?? ?? EB AC 34 9F E5 03 00 55 E1 10 00 00 9A 22 01 00 EA 01 60 F5 E5 00 00 56 E3 EE FF FF 1A 44 30 D8 E5 00 00 53 E3 1E 01 00 0A 34 30 98 E5 01 30 83 E2 34 30 88 E5 2C 00 98 E5 38 10 98 E5 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? EB 06 00 A0 E1 15 01 00 EA 04 00 A0 E1 ?? ?? ?? EB 00 30 94 E5 00 00 53 E3 00 00 E0 B3 0F 01 00 BA 2D 00 53 E3 2B 00 53 13 09 50 8D E2 }
	condition:
		$pattern
}

rule _dl_load_elf_shared_library_3de6bb1c45cde474396baa8b0898bb20 {
	meta:
		aliases = "_dl_load_elf_shared_library"
		size = "2936"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { F0 4F 2D E9 FC D0 4D E2 08 20 8D E5 0C 10 8D E5 00 10 A0 E3 00 30 A0 E1 01 20 A0 E1 08 00 9D E5 05 00 90 EF 01 0A 70 E3 00 A0 A0 E1 F0 3A 9F 85 00 20 60 82 00 20 83 85 01 00 00 8A 00 00 50 E3 03 00 00 AA DC 3A 9F E5 01 60 A0 E1 01 20 A0 E3 AA 02 00 EA BC 10 8D E2 6C 00 90 EF 01 0A 70 E3 BC 3A 9F 85 00 10 60 82 00 10 83 85 01 00 00 8A 00 00 50 E3 0B 00 00 AA A8 3A 9F E5 01 10 A0 E3 00 10 83 E5 0A 00 A0 E1 06 00 90 EF 01 0A 70 E3 9C 02 00 9A 88 3A 9F E5 00 10 60 E2 02 60 A0 E1 00 10 83 E5 9B 02 00 EA 00 00 53 E3 0A 00 00 0A C5 30 DD E5 03 34 A0 E1 02 1B 13 E2 06 00 00 1A 0A 00 A0 E1 06 00 90 EF }
	condition:
		$pattern
}

rule __pgsreader_7178875d917bd25e367f768a981117d4 {
	meta:
		aliases = "__pgsreader"
		size = "368"
		objfiles = "__pgsreader@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 FF 00 53 E3 10 D0 4D E2 03 60 A0 E1 00 A0 A0 E1 01 80 A0 E1 02 50 A0 E1 34 70 9D E5 04 00 00 8A ?? ?? ?? EB 22 30 A0 E3 03 40 A0 E1 00 30 80 E5 44 00 00 EA 34 B0 97 E5 00 00 5B E3 02 00 00 0A 00 40 A0 E3 06 90 85 E0 0B 00 00 EA 38 40 87 E2 0D 00 A0 E1 F8 10 9F E5 04 20 A0 E1 F4 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 E8 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 F0 FF FF EA 05 00 A0 E1 06 10 A0 E1 07 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 04 00 00 1A 00 30 D7 E5 04 00 13 E3 22 40 A0 03 02 40 A0 13 21 00 00 EA 05 00 A0 E1 ?? ?? ?? EB 01 20 40 E2 02 30 D5 E7 0A 00 53 E3 00 10 A0 03 02 10 C5 07 }
	condition:
		$pattern
}

rule vsyslog_04b6b4bec366f47a46240e78d94c0e77 {
	meta:
		aliases = "__GI_vsyslog, vsyslog"
		size = "888"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 FF 4F C0 E3 41 DE 4D E2 03 40 C4 E3 0C D0 4D E2 00 00 54 E3 00 50 A0 E1 04 10 8D E5 00 20 8D E5 BE 00 00 1A ?? ?? ?? EB 00 90 A0 E1 01 0B 8D E2 F4 12 9F E5 F4 22 9F E5 08 00 80 E2 F0 32 9F E5 00 B0 99 E5 0F E0 A0 E1 03 F0 A0 E1 E4 32 9F E5 D8 02 9F E5 0F E0 A0 E1 03 F0 A0 E1 D8 32 9F E5 00 10 93 E5 07 20 05 E2 01 30 A0 E3 13 32 11 E0 A4 00 00 0A C4 32 9F E5 00 30 93 E5 00 00 53 E3 03 00 00 BA B8 32 9F E5 00 30 93 E5 00 00 53 E3 05 00 00 1A AC 32 9F E5 00 10 93 E5 04 00 A0 E1 08 10 81 E3 08 20 A0 E3 91 FF FF EB FE 0F 15 E3 94 32 9F 05 41 4E 8D E2 00 30 93 05 08 40 84 E2 04 00 A0 E1 }
	condition:
		$pattern
}

rule __fixunsdfdi_11e6aae4d6ca833a2c99cc276fcb5031 {
	meta:
		aliases = "__fixunsdfdi"
		size = "100"
		objfiles = "_fixunsdfdi@libgcc.a"
	strings:
		$pattern = { F7 25 A0 E3 F0 40 2D E9 03 26 82 E2 00 30 A0 E3 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 00 60 A0 E1 ?? ?? ?? EB C1 24 A0 E3 0F 26 82 E2 00 30 A0 E3 ?? ?? ?? EB 04 20 A0 E1 05 30 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 00 70 A0 E3 06 70 A0 E1 00 10 A0 E3 00 60 A0 E3 06 00 80 E1 07 10 81 E1 F0 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_manager_8ceca9cacd83fdec391f9a24a33b5e06 {
	meta:
		aliases = "__pthread_manager"
		size = "1876"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { F8 26 9F E5 F8 36 9F E5 50 D0 4D E2 40 40 8D E2 00 10 93 E5 50 30 82 E2 48 E0 82 E2 00 C0 E0 E3 4C 30 82 E5 0C 00 8D E5 44 E0 82 E5 04 00 A0 E1 44 C0 8D E5 40 C0 8D E5 ?? ?? ?? EB 04 00 A0 E1 05 10 A0 E3 ?? ?? ?? EB B8 36 9F E5 00 30 93 E5 00 00 53 E3 04 00 00 0A AC 36 9F E5 00 10 93 E5 00 00 51 E3 04 00 A0 C1 ?? ?? ?? CB 40 10 8D E2 00 20 A0 E3 02 00 A0 E3 ?? ?? ?? EB 8C 36 9F E5 00 30 93 E5 18 00 93 E5 ?? ?? ?? EB 24 40 8D E2 0C 00 9D E5 04 10 A0 E1 1C 20 A0 E3 ?? ?? ?? EB 01 00 70 E3 03 00 00 1A ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 F5 FF FF 0A 01 30 A0 E3 0C 10 9D E5 4C 30 CD E5 00 30 A0 E3 }
	condition:
		$pattern
}

rule __pthread_initialize_manager_e18fa181cb23d908ab311262b94bceb8 {
	meta:
		aliases = "__pthread_initialize_manager"
		size = "584"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { FC 31 9F E5 70 40 2D E9 00 20 93 E5 F4 31 9F E5 00 10 93 E5 00 00 52 E3 01 30 A0 E3 24 D0 4D E2 00 30 81 E5 85 FF FF 0B DC 41 9F E5 00 00 94 E5 80 00 A0 E1 20 00 40 E2 ?? ?? ?? EB CC 51 9F E5 00 00 50 E3 00 00 85 E5 00 00 E0 03 6A 00 00 0A 00 20 94 E5 20 30 40 E2 B4 61 9F E5 82 30 83 E0 1C 00 8D E2 00 30 86 E5 ?? ?? ?? EB 01 00 70 E3 00 40 A0 E1 02 00 00 1A 00 00 95 E5 ?? ?? ?? EB 37 00 00 EA 8C 31 9F E5 00 20 93 E5 00 00 52 E3 84 31 9F 15 24 21 83 15 7C 21 9F E5 24 31 92 E5 00 00 53 E3 1E 00 00 0A 70 31 9F E5 28 21 92 E5 00 30 93 E5 02 30 83 E1 80 00 13 E3 18 00 00 0A 5C 51 9F E5 00 10 A0 E3 }
	condition:
		$pattern
}

rule ascii_to_bin_79ab3c66356dee8a411014aadca07393 {
	meta:
		aliases = "ascii_to_bin"
		size = "72"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { FF 00 00 E2 7A 00 50 E3 0C 00 00 8A 60 00 50 E3 3B 00 40 82 0E F0 A0 81 5A 00 50 E3 07 00 00 8A 40 00 50 E3 35 00 40 82 0E F0 A0 81 39 00 50 E3 02 00 00 8A 2D 00 50 E3 2E 00 40 82 0E F0 A0 81 00 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI___fpclassify_3a2976b0c607dffebcf93d076634edcc {
	meta:
		aliases = "__fpclassify, __GI___fpclassify"
		size = "88"
		objfiles = "s_fpclassify@libm.a"
	strings:
		$pattern = { FF 24 C0 E3 48 C0 9F E5 00 30 A0 E1 10 40 2D E9 0F 26 C2 E3 01 40 A0 E1 04 00 82 E1 0C C0 03 E0 0C 30 90 E1 02 00 A0 03 10 80 BD 08 00 00 5C E3 03 00 A0 03 10 80 BD 08 14 30 9F E5 03 00 5C E1 04 00 A0 13 10 80 BD 18 01 00 70 E2 00 00 A0 33 10 80 BD E8 00 00 F0 7F }
	condition:
		$pattern
}

rule __GI_inet_netof_d62a29c0fe2de6cc70be1e5f56a1fbe6 {
	meta:
		aliases = "inet_netof, __GI_inet_netof"
		size = "52"
		objfiles = "inet_netof@libc.a"
	strings:
		$pattern = { FF 28 00 E2 20 3C A0 E1 22 34 83 E1 FF 2C 00 E2 02 34 83 E1 00 0C 93 E1 20 0C A0 51 0E F0 A0 51 03 31 00 E2 02 01 53 E3 20 08 A0 01 20 04 A0 11 0E F0 A0 E1 }
	condition:
		$pattern
}

rule inet_lnaof_1db8bafad32bb3d2aa96341aaa77c4af {
	meta:
		aliases = "inet_lnaof"
		size = "56"
		objfiles = "inet_lnaof@libc.a"
	strings:
		$pattern = { FF 28 00 E2 20 3C A0 E1 22 34 83 E1 FF 2C 00 E2 02 34 83 E1 00 0C 93 E1 FF 04 C0 53 0E F0 A0 51 03 31 00 E2 02 01 53 E3 00 08 A0 01 20 08 A0 01 FF 00 00 12 0E F0 A0 E1 }
	condition:
		$pattern
}

rule base_from_object_5eaa9111861cb2cec1376dd1f76ae6ed {
	meta:
		aliases = "base_from_object"
		size = "88"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { FF 30 00 E2 FF 00 53 E3 04 E0 2D E5 0C 00 00 0A 70 00 00 E2 20 00 50 E3 04 00 91 05 04 F0 9D 04 05 00 00 DA 30 00 50 E3 08 00 91 05 04 F0 9D 04 50 00 50 E3 02 00 00 0A ?? ?? ?? EB 00 00 50 E3 01 00 00 1A 00 00 A0 E3 04 F0 9D E4 10 00 50 E3 FB FF FF 0A ?? ?? ?? EB }
	condition:
		$pattern
}

rule base_of_encoded_value_61845f3af9b53e3627f35c27fda66f41 {
	meta:
		aliases = "base_of_encoded_value"
		size = "124"
		objfiles = "unwind_c@libgcc_eh.a"
	strings:
		$pattern = { FF 30 00 E2 FF 00 53 E3 04 E0 2D E5 0C 00 00 0A 70 00 00 E2 20 00 50 E3 14 00 00 0A 06 00 00 DA 40 00 50 E3 0E 00 00 0A 50 00 50 E3 04 00 00 0A 30 00 50 E3 07 00 00 0A ?? ?? ?? EB 00 00 50 E3 01 00 00 1A 00 00 A0 E3 04 F0 9D E4 10 00 50 E3 FB FF FF 0A ?? ?? ?? EB 01 00 A0 E1 04 E0 9D E4 ?? ?? ?? EA 01 00 A0 E1 04 E0 9D E4 ?? ?? ?? EA 01 00 A0 E1 04 E0 9D E4 ?? ?? ?? EA }
	condition:
		$pattern
}

rule size_of_encoded_value_b33c245977b340c1f728c03b342ee47d {
	meta:
		aliases = "size_of_encoded_value"
		size = "88"
		objfiles = "unwind_dw2_fde_glibc@libgcc_eh.a"
	strings:
		$pattern = { FF 30 00 E2 FF 00 53 E3 04 E0 2D E5 0F 00 00 0A 07 30 00 E2 04 00 53 E3 03 F1 9F 97 0A 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 00 A0 E3 04 F0 9D E4 02 00 A0 E3 04 F0 9D E4 08 00 A0 E3 04 F0 9D E4 ?? ?? ?? EB 00 00 A0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule __aeabi_fdiv_e4310a7c63851085d2eb7182590a33a7 {
	meta:
		aliases = "__divsf3, __aeabi_fdiv"
		size = "352"
		objfiles = "_muldivsf3@libgcc.a"
	strings:
		$pattern = { FF C0 A0 E3 A0 2B 1C E0 A1 3B 1C 10 0C 00 32 11 0C 00 33 11 3A 00 00 0A 03 20 42 E0 01 C0 20 E0 81 14 B0 E1 80 04 A0 E1 1C 00 00 0A 01 32 A0 E3 21 12 83 E1 20 32 83 E1 02 01 0C E2 01 00 53 E1 83 30 A0 31 7D 20 A2 E2 02 C5 A0 E3 01 00 53 E1 01 30 43 20 0C 00 80 21 A1 00 53 E1 A1 30 43 20 AC 00 80 21 21 01 53 E1 21 31 43 20 2C 01 80 21 A1 01 53 E1 A1 31 43 20 AC 01 80 21 03 32 B0 E1 2C C2 B0 11 F0 FF FF 1A FD 00 52 E3 9D FF FF 8A 01 00 53 E1 82 0B A0 E0 01 00 C0 03 0E F0 A0 E1 02 C1 0C E2 A0 04 8C E1 7F 20 92 E2 FF 30 72 C2 82 0B 80 C1 0E F0 A0 C1 02 05 80 E3 00 30 A0 E3 01 20 52 E2 8F FF FF EA }
	condition:
		$pattern
}

rule __mulsf3_992766485331301338b85bebc046c184 {
	meta:
		aliases = "__aeabi_fmul, __mulsf3"
		size = "452"
		objfiles = "_muldivsf3@libgcc.a"
	strings:
		$pattern = { FF C0 A0 E3 A0 2B 1C E0 A1 3B 1C 10 0C 00 32 11 0C 00 33 11 49 00 00 0A 03 20 82 E0 01 C0 20 E0 80 04 B0 E1 81 14 B0 11 1B 00 00 0A 02 33 A0 E3 A0 02 83 E1 A1 12 83 E1 02 31 0C E2 38 00 2D E9 20 48 A0 E1 21 58 A0 E1 04 08 C0 E1 05 18 C1 E1 94 05 0C E0 90 01 03 E0 95 00 00 E0 94 01 20 E0 00 38 93 E0 20 18 AC E0 31 00 BD E8 02 05 51 E3 81 10 A0 31 A3 1F 81 31 83 30 A0 31 01 00 80 E1 7F 20 C2 E2 FD 00 52 E3 0F 00 00 8A 02 01 53 E3 82 0B A0 E0 01 00 C0 03 0E F0 A0 E1 00 00 30 E3 02 C1 0C E2 81 14 A0 01 A0 04 8C E1 A1 04 80 E1 7F 20 52 E2 FF 30 72 C2 82 0B 80 C1 0E F0 A0 C1 02 05 80 E3 00 30 A0 E3 }
	condition:
		$pattern
}

