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

rule set_cplus_marker_for_demanglin_67d7ceddbaa67f7a334ebbf697772e19 {
	meta:
		aliases = "set_cplus_marker_for_demangling"
		size = "8"
		objfiles = "cplus_dem@libiberty.a"
	strings:
		$pattern = { ( CC | 40 ) 88 3D ?? ?? ?? ?? C3 }
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
		objfiles = "strerror@libiberty.a, strsignal@libiberty.a"
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

rule splay_tree_xmalloc_allocate_99822f6becf3ab817549c8a4836c0ad2 {
	meta:
		aliases = "splay_tree_xmalloc_allocate"
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

rule strerrno_f4b75ac1107ed77e12feab40f10025d9 {
	meta:
		aliases = "strsigno, strerrno"
		size = "146"
		objfiles = "strerror@libiberty.a, strsignal@libiberty.a"
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

rule pex_unix_pipe_3d96b09e629cae87daecfec89870a4e5 {
	meta:
		aliases = "pex_unix_pipe"
		size = "8"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 89 F7 E9 ?? ?? ?? ?? }
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

rule htab_size_7a346892aa6f48c113696b74d69cab29 {
	meta:
		aliases = "htab_size"
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
		size = "6"
		objfiles = "floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | 48 ) 8B 47 30 FF E0 }
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
		aliases = "fdopen_unlocked, freopen_unlocked, fopen_unlocked"
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

rule pex_unix_fdopenr_175adfb56eb622058af8f007c8d1d34f {
	meta:
		aliases = "pex_unix_fdopenr"
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
		size = "7"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | 89 ) F7 E9 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule init_error_tables_cf2ff99833398275645d2c370c9d213d {
	meta:
		aliases = "init_signal_tables, init_error_tables"
		size = "155"
		objfiles = "strerror@libiberty.a, strsignal@libiberty.a"
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

rule floatformat_always_valid_62dea3be98d084788202ec199cbcebf6 {
	meta:
		aliases = "floatformat_always_valid"
		size = "6"
		objfiles = "floatformat@libiberty.a"
	strings:
		$pattern = { ( CC | B8 ) 01 00 00 00 C3 }
	condition:
		$pattern
}

rule pex_init_10696b7984a423ede6965fc7ac958e24 {
	meta:
		aliases = "pex_init"
		size = "10"
		objfiles = "pex_unix@libiberty.a"
	strings:
		$pattern = { ( CC | B9 ) ?? ?? ?? ?? E9 ?? ?? ?? ?? }
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

rule xre_search_2_b7b76ce6c5ad5d48da2aa7cc3881361a {
	meta:
		aliases = "xre_search_2"
		size = "5"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | E9 ) 0B D0 FF FF }
	condition:
		$pattern
}

rule xre_match_2_d096b21f6528ea904c2bd82c310f2079 {
	meta:
		aliases = "xre_match_2"
		size = "5"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | E9 ) 9B AE FF FF }
	condition:
		$pattern
}

rule partition_delete_22aa66de8a720f160758a4fe68aab955 {
	meta:
		aliases = "splay_tree_xmalloc_deallocate, partition_delete"
		size = "5"
		objfiles = "splay_tree@libiberty.a, partition@libiberty.a"
	strings:
		$pattern = { ( CC | E9 ) ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xre_compile_fastmap_4803f602058da3f627f67cdd5057f662 {
	meta:
		aliases = "xre_compile_fastmap"
		size = "5"
		objfiles = "regex@libiberty.a"
	strings:
		$pattern = { ( CC | E9 ) BB AA FF FF }
	condition:
		$pattern
}

rule hex_init_32a093eff127b3eedaa06c147dc0694b {
	meta:
		aliases = "pex_unix_cleanup, hex_init"
		size = "2"
		objfiles = "pex_unix@libiberty.a, hex@libiberty.a"
	strings:
		$pattern = { ( CC | F3 ) C3 }
	condition:
		$pattern
}

rule bcopy_90ded62a508cf2957583f85777cb2c39 {
	meta:
		aliases = "bcopy"
		size = "16"
		objfiles = "bcopys@libc.a"
	strings:
		$pattern = { 00 00 21 E0 01 10 20 E0 00 00 21 E0 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __aeabi_ui2d_1f1ba37c4d489ae615dc887e74515ecf {
	meta:
		aliases = "__floatunsidf, __aeabi_ui2d"
		size = "36"
		objfiles = "_addsubdf3@libgcc.a"
	strings:
		$pattern = { 00 00 30 E3 00 10 A0 03 1E FF 2F 01 30 40 2D E9 01 4B A0 E3 32 40 84 E2 00 50 A0 E3 00 10 A0 E3 9D FF FF EA }
	condition:
		$pattern
}

rule __floatsidf_1579553a544daf533786ef2dccc020a2 {
	meta:
		aliases = "__aeabi_i2d, __floatsidf"
		size = "40"
		objfiles = "_addsubdf3@libgcc.a"
	strings:
		$pattern = { 00 00 30 E3 00 10 A0 03 1E FF 2F 01 30 40 2D E9 01 4B A0 E3 32 40 84 E2 02 51 10 E2 00 00 60 42 00 10 A0 E3 93 FF FF EA }
	condition:
		$pattern
}

rule clone_67f0bc218c16c3df275473789b175b29 {
	meta:
		aliases = "clone"
		size = "80"
		objfiles = "clones@libc.a"
	strings:
		$pattern = { 00 00 50 E3 00 00 51 13 15 00 E0 03 0E 00 00 0A 08 10 41 E2 04 30 81 E5 00 00 81 E5 02 00 A0 E1 07 C0 A0 E1 78 70 A0 E3 00 00 00 EF 0C 70 A0 E1 00 00 B0 E1 04 00 00 BA 0E F0 A0 11 04 00 9D E5 0F E0 A0 E1 00 F0 9D E5 ?? ?? ?? EA ?? ?? ?? EA }
	condition:
		$pattern
}

rule twalk_11835f160a3808bf26e731e2d231a3c8 {
	meta:
		aliases = "twalk"
		size = "20"
		objfiles = "twalks@libc.a"
	strings:
		$pattern = { 00 00 50 E3 00 00 51 13 1E FF 2F 01 00 20 A0 E3 D6 FF FF EA }
	condition:
		$pattern
}

rule __absvsi2_c4b3dddcd45642a986492cd67886f6da {
	meta:
		aliases = "abs, labs, __absvsi2"
		size = "12"
		objfiles = "labss@libc.a, _absvsi2@libgcc.a"
	strings:
		$pattern = { 00 00 50 E3 00 00 60 B2 1E FF 2F E1 }
	condition:
		$pattern
}

rule __ctzdi2_268faf8333469ae9bbb8feda3fe747b7 {
	meta:
		aliases = "__ctzdi2"
		size = "128"
		objfiles = "_ctzdi2@libgcc.a"
	strings:
		$pattern = { 00 00 50 E3 01 00 A0 01 00 30 60 E2 64 20 9F E5 00 00 03 E0 04 E0 2D E5 00 E0 A0 13 20 E0 A0 03 01 08 50 E3 02 20 8F E0 0B 00 00 2A FF 00 50 E3 07 C0 A0 83 00 C0 E0 93 08 10 A0 83 00 10 A0 93 30 11 A0 E1 30 30 9F E5 03 20 92 E7 01 00 D2 E7 0C 00 80 E0 0E 00 80 E0 04 F0 9D E4 FF 34 E0 E3 03 00 50 E1 17 C0 A0 83 0F C0 A0 93 18 10 A0 83 10 10 A0 93 F1 FF FF EA ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mbsinit_ffa66b5b06ce79d6e42fd0c087e26589 {
	meta:
		aliases = "__GI_mbsinit, mbsinit"
		size = "28"
		objfiles = "mbsinits@libc.a"
	strings:
		$pattern = { 00 00 50 E3 01 00 A0 03 1E FF 2F 01 00 30 90 E5 01 00 73 E2 00 00 A0 33 1E FF 2F E1 }
	condition:
		$pattern
}

rule wctomb_9b731e951cb27791a49818fff6727a96 {
	meta:
		aliases = "wctomb"
		size = "16"
		objfiles = "wctombs@libc.a"
	strings:
		$pattern = { 00 00 50 E3 1E FF 2F 01 00 20 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tdestroy_bfd712e605708a09e4d2faef0bd5abc0 {
	meta:
		aliases = "__GI_tdestroy, tdestroy"
		size = "12"
		objfiles = "tdestroys@libc.a"
	strings:
		$pattern = { 00 00 50 E3 1E FF 2F 01 E9 FF FF EA }
	condition:
		$pattern
}

rule wcstok_02a84b1830e76ec1ac7fa94137c2fe0e {
	meta:
		aliases = "wcstok"
		size = "108"
		objfiles = "wcstoks@libc.a"
	strings:
		$pattern = { 00 00 50 E3 70 40 2D E9 01 50 A0 E1 02 60 A0 E1 00 40 A0 11 02 00 00 1A 00 40 92 E5 00 00 54 E3 0F 00 00 0A 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 00 41 84 E0 00 30 94 E5 00 00 53 E3 03 40 A0 01 04 00 A0 01 05 00 00 0A 05 10 A0 E1 04 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 30 A0 13 04 30 80 14 00 00 86 E5 04 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule wmemmove_8a2e57bde8109f1eba966594d02ccb30 {
	meta:
		aliases = "wmemmove"
		size = "68"
		objfiles = "wmemmoves@libc.a"
	strings:
		$pattern = { 00 00 51 E1 00 C0 A0 21 02 00 00 2A 07 00 00 EA 04 30 91 E4 04 30 8C E4 00 00 52 E3 01 20 42 E2 FA FF FF 1A 1E FF 2F E1 0C 30 91 E7 0C 30 80 E7 00 00 52 E3 01 20 42 E2 02 C1 A0 E1 F9 FF FF 1A 1E FF 2F E1 }
	condition:
		$pattern
}

rule _memcpy_9c0fa403499e290516f81a99917ad67a {
	meta:
		aliases = "_memcpy"
		size = "1168"
		objfiles = "_memcpys@libc.a"
	strings:
		$pattern = { 00 00 51 E1 90 00 00 3A 0E F0 A0 01 01 40 2D E9 04 20 52 E2 20 00 00 BA 03 C0 10 E2 28 00 00 1A 03 C0 11 E2 32 00 00 1A 08 20 52 E2 12 00 00 BA 14 20 52 E2 0B 00 00 BA 04 40 2D E5 18 50 B1 E8 18 50 A0 E8 18 50 B1 E8 18 50 A0 E8 20 20 52 E2 F9 FF FF AA 10 00 72 E3 18 50 B1 A8 18 50 A0 A8 10 20 42 A2 04 40 9D E4 14 20 92 E2 08 50 B1 A8 08 50 A0 A8 0C 20 52 A2 FB FF FF AA 08 20 92 E2 05 00 00 BA 04 20 52 E2 04 30 91 B4 04 30 80 B4 08 10 B1 A8 08 10 A0 A8 04 20 42 A2 04 20 92 E2 01 80 BD 08 02 00 52 E3 01 30 D1 E4 01 30 C0 E4 01 30 D1 A4 01 30 C0 A4 01 30 D1 C4 01 30 C0 C4 01 80 BD E8 04 C0 6C E2 }
	condition:
		$pattern
}

rule __divsi3_ac44d6a02e8c783b664329b86c253ddd {
	meta:
		aliases = "__aeabi_idiv, __divsi3"
		size = "544"
		objfiles = "_divsi3@libgcc.a"
	strings:
		$pattern = { 00 00 51 E3 01 C0 20 E0 80 00 00 0A 00 10 61 42 01 20 51 E2 70 00 00 0A 00 30 B0 E1 00 30 60 42 01 00 53 E1 6F 00 00 9A 02 00 11 E1 71 00 00 0A 13 2F 6F E1 11 0F 6F E1 02 20 40 E0 1F 20 72 E2 82 20 82 10 00 00 A0 E3 02 F1 8F 10 00 00 A0 E1 81 0F 53 E1 00 00 A0 E0 81 3F 43 20 01 0F 53 E1 00 00 A0 E0 01 3F 43 20 81 0E 53 E1 00 00 A0 E0 81 3E 43 20 01 0E 53 E1 00 00 A0 E0 01 3E 43 20 81 0D 53 E1 00 00 A0 E0 81 3D 43 20 01 0D 53 E1 00 00 A0 E0 01 3D 43 20 81 0C 53 E1 00 00 A0 E0 81 3C 43 20 01 0C 53 E1 00 00 A0 E0 01 3C 43 20 81 0B 53 E1 00 00 A0 E0 81 3B 43 20 01 0B 53 E1 00 00 A0 E0 01 3B 43 20 }
	condition:
		$pattern
}

rule __GI_sigprocmask_c6a852e14ad63293b7f29a084ddde2b8 {
	meta:
		aliases = "sigprocmask, __GI_sigprocmask"
		size = "88"
		objfiles = "sigprocmasks@libc.a"
	strings:
		$pattern = { 00 00 51 E3 02 00 50 13 80 40 2D E9 04 00 00 9A ?? ?? ?? ?? 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 0A 00 00 EA 08 30 A0 E3 AF 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 20 A0 E1 02 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule setbuf_738d1108e403cd9b4eda4d6f9eab8859 {
	meta:
		aliases = "setbuf"
		size = "20"
		objfiles = "setbufs@libc.a"
	strings:
		$pattern = { 00 00 51 E3 02 20 A0 03 00 20 A0 13 01 3A A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule setbuffer_e48f9ddd9470720fafb1c885494317f5 {
	meta:
		aliases = "setbuffer"
		size = "20"
		objfiles = "setbuffers@libc.a"
	strings:
		$pattern = { 00 00 51 E3 02 30 A0 E1 02 20 A0 03 00 20 A0 13 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_attr_setscope_19e76c922b02a0162186825fbc2e4408 {
	meta:
		aliases = "__GI_pthread_attr_setscope, pthread_attr_setscope"
		size = "36"
		objfiles = "attrs@libpthread.a"
	strings:
		$pattern = { 00 00 51 E3 03 00 00 0A 01 00 51 E3 16 00 A0 13 5F 00 A0 03 1E FF 2F E1 10 10 80 E5 01 00 A0 E1 1E FF 2F E1 }
	condition:
		$pattern
}

rule _Unwind_VRS_Set_77e7f9d1b1fafce107473a302e62c7f7 {
	meta:
		aliases = "_Unwind_VRS_Set"
		size = "76"
		objfiles = "unwind_arm@libgcc.a"
	strings:
		$pattern = { 00 00 51 E3 0B 00 00 1A 0F 00 52 E3 00 00 53 93 00 10 A0 03 01 10 A0 13 09 00 00 1A 00 C0 9D E5 02 31 A0 E1 00 20 9C E5 00 30 83 E0 01 00 A0 E1 04 20 83 E5 1E FF 2F E1 04 00 51 E3 01 00 A0 93 1E FF 2F 91 02 00 A0 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule _Unwind_VRS_Get_07498e5fb0da9dfd8865a6aa14c3f333 {
	meta:
		aliases = "_Unwind_VRS_Get"
		size = "76"
		objfiles = "unwind_arm@libgcc.a"
	strings:
		$pattern = { 00 00 51 E3 0B 00 00 1A 0F 00 52 E3 00 00 53 93 00 10 A0 03 01 10 A0 13 09 00 00 1A 02 31 A0 E1 00 30 83 E0 04 20 93 E5 00 30 9D E5 01 00 A0 E1 00 20 83 E5 1E FF 2F E1 04 00 51 E3 01 00 A0 93 1E FF 2F 91 02 00 A0 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule strnlen_7f840ea24b3f5e1430ebe4c90480439c {
	meta:
		aliases = "__GI_strnlen, strnlen"
		size = "216"
		objfiles = "strnlens@libc.a"
	strings:
		$pattern = { 00 00 51 E3 10 40 2D E9 00 40 A0 E1 01 00 A0 01 10 80 BD 08 01 10 94 E0 00 10 E0 23 04 00 A0 E1 07 00 00 EA 00 30 D0 E5 00 00 53 E3 03 00 00 1A 00 00 51 E1 01 00 64 90 00 00 64 80 10 80 BD E8 01 00 80 E2 03 00 10 E3 F5 FF FF 1A 00 E0 A0 E1 16 00 00 EA 04 30 9E E4 02 20 83 E0 0C C0 02 E0 00 00 5C E3 10 00 00 0A 04 30 5E E5 04 20 4E E2 00 00 53 E3 02 00 A0 01 10 00 00 0A 03 30 5E E5 01 00 82 E2 00 00 53 E3 0C 00 00 0A 02 30 5E E5 02 00 82 E2 00 00 53 E3 08 00 00 0A 01 30 5E E5 03 00 82 E2 00 00 53 E3 04 00 00 0A 01 00 A0 E1 01 00 5E E1 14 20 9F E5 14 C0 9F E5 E4 FF FF 3A 00 00 51 E1 01 00 64 90 }
	condition:
		$pattern
}

rule _pthread_cleanup_pop_a0126962ce2ff9be2974d6bbd1b86d61 {
	meta:
		aliases = "_pthread_cleanup_pop"
		size = "44"
		objfiles = "cancels@libpthread.a"
	strings:
		$pattern = { 00 00 51 E3 10 40 2D E9 00 40 A0 E1 02 00 00 0A 04 00 90 E5 0F E0 A0 E1 00 F0 94 E5 A8 FF FF EB 0C 30 94 E5 3C 30 80 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule __sigjmp_save_62c81651f08f54829e4e90ddfa9bb9b4 {
	meta:
		aliases = "__sigjmp_save"
		size = "60"
		objfiles = "sigjmps@libc.a"
	strings:
		$pattern = { 00 00 51 E3 10 40 2D E9 00 40 A0 E1 06 00 00 0A 00 00 A0 E3 00 10 A0 E1 41 2F 84 E2 ?? ?? ?? ?? 00 00 50 E3 01 30 A0 03 00 00 00 0A 00 30 A0 E3 00 00 A0 E3 00 31 84 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule tcsendbreak_78631a7f4669ea33d106757b64a7b71a {
	meta:
		aliases = "tcsendbreak"
		size = "64"
		objfiles = "tcsendbrks@libc.a"
	strings:
		$pattern = { 00 00 51 E3 10 40 2D E9 28 10 9F D5 00 40 A0 E1 00 20 A0 D3 05 00 00 DA 63 00 81 E2 64 10 A0 E3 ?? ?? ?? ?? 10 10 9F E5 00 20 A0 E1 04 00 A0 E1 10 40 BD E8 ?? ?? ?? ?? 09 54 00 00 25 54 00 00 }
	condition:
		$pattern
}

rule __modsi3_471fa64c83eb70493a88c841e5e0b37d {
	meta:
		aliases = "__modsi3"
		size = "352"
		objfiles = "_modsi3@libgcc.a"
	strings:
		$pattern = { 00 00 51 E3 51 00 00 0A 00 10 61 42 00 C0 B0 E1 00 00 60 42 01 20 51 E2 01 00 50 11 00 00 A0 03 02 00 11 81 02 00 00 00 45 00 00 9A 11 2F 6F E1 10 3F 6F E1 03 20 42 E0 1F 20 72 E2 82 F1 8F 10 00 00 A0 E1 81 0F 50 E1 81 0F 40 20 01 0F 50 E1 01 0F 40 20 81 0E 50 E1 81 0E 40 20 01 0E 50 E1 01 0E 40 20 81 0D 50 E1 81 0D 40 20 01 0D 50 E1 01 0D 40 20 81 0C 50 E1 81 0C 40 20 01 0C 50 E1 01 0C 40 20 81 0B 50 E1 81 0B 40 20 01 0B 50 E1 01 0B 40 20 81 0A 50 E1 81 0A 40 20 01 0A 50 E1 01 0A 40 20 81 09 50 E1 81 09 40 20 01 09 50 E1 01 09 40 20 81 08 50 E1 81 08 40 20 01 08 50 E1 01 08 40 20 81 07 50 E1 }
	condition:
		$pattern
}

rule __clzdi2_15134e12e3e60daf3497f5db603f7594 {
	meta:
		aliases = "__clzdi2"
		size = "120"
		objfiles = "_clzdi2@libgcc.a"
	strings:
		$pattern = { 00 00 51 E3 64 20 9F E5 01 00 A0 11 04 E0 2D E5 00 E0 A0 13 20 E0 A0 03 01 08 50 E3 02 20 8F E0 0B 00 00 2A FF 00 50 E3 18 C0 A0 83 20 C0 A0 93 08 10 A0 83 00 10 A0 93 30 11 A0 E1 30 30 9F E5 03 20 92 E7 01 00 D2 E7 0C 00 60 E0 0E 00 80 E0 04 F0 9D E4 FF 34 E0 E3 03 00 50 E1 18 10 A0 83 10 10 A0 93 08 C0 A0 83 10 C0 A0 93 F1 FF FF EA ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mq_notify_c135de9aeaf7ac2924bca3dd9b40ac10 {
	meta:
		aliases = "mq_notify"
		size = "96"
		objfiles = "mq_notifys@librt.a"
	strings:
		$pattern = { 00 00 51 E3 80 40 2D E9 07 00 00 0A 08 30 91 E5 02 00 53 E3 04 00 00 1A ?? ?? ?? ?? 26 30 A0 E3 00 20 E0 E3 00 30 80 E5 09 00 00 EA 28 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 20 A0 E1 02 00 A0 E1 80 80 BD E8 16 01 00 00 }
	condition:
		$pattern
}

rule _load_inttype_003f21aa27d60c413416659157911ff2 {
	meta:
		aliases = "_load_inttype"
		size = "112"
		objfiles = "_load_inttypes@libc.a"
	strings:
		$pattern = { 00 00 52 E3 00 30 A0 E1 02 2B 00 E2 0A 00 00 BA 00 00 52 E3 0A 00 00 1A 01 0C 50 E3 00 00 91 E5 FF 00 00 02 02 00 00 0A 02 0C 53 E3 00 38 A0 01 23 08 A0 01 00 10 A0 E3 1E FF 2F E1 00 00 52 E3 01 00 00 0A 03 00 91 E8 1E FF 2F E1 01 0C 50 E3 00 00 91 E5 FF 00 00 02 02 00 00 0A 02 0C 53 E3 00 38 A0 01 43 08 A0 01 C0 1F A0 E1 1E FF 2F E1 }
	condition:
		$pattern
}

rule __gcc_bcmp_e093cdd914ca45206cb8537b4d8c71e9 {
	meta:
		aliases = "__gcc_bcmp"
		size = "72"
		objfiles = "__gcc_bcmp@libgcc.a"
	strings:
		$pattern = { 00 00 52 E3 00 C0 A0 E1 0A 00 00 0A 00 30 D0 E5 00 00 D1 E5 00 00 53 E1 04 00 00 0A 07 00 00 EA 01 30 FC E5 01 00 F1 E5 00 00 53 E1 03 00 00 1A 01 20 52 E2 F9 FF FF 1A 00 00 A0 E3 1E FF 2F E1 03 00 60 E0 1E FF 2F E1 }
	condition:
		$pattern
}

rule re_set_registers_c9d52da1e615907fb59c0379865d4d66 {
	meta:
		aliases = "__re_set_registers, re_set_registers"
		size = "72"
		objfiles = "regex_olds@libc.a"
	strings:
		$pattern = { 00 00 52 E3 03 C0 A0 E1 1C 30 D0 E5 07 00 00 0A 04 30 C3 E3 02 30 83 E3 1C 30 C0 E5 00 30 9D E5 00 20 81 E5 08 30 81 E5 04 C0 81 E5 1E FF 2F E1 06 30 C3 E3 1C 30 C0 E5 04 20 81 E5 00 20 81 E5 08 20 81 E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule wcsxfrm_3dde33d9329ed03e483abef2473529d9 {
	meta:
		aliases = "__wcslcpy, wcsxfrm"
		size = "76"
		objfiles = "wcslcpys@libc.a"
	strings:
		$pattern = { 00 00 52 E3 08 D0 4D E2 00 C0 A0 E1 01 20 42 12 04 C0 8D 02 01 00 A0 E1 03 00 00 EA 00 00 52 E3 01 20 42 12 04 C0 8C 12 04 00 80 E2 00 30 90 E5 00 00 53 E3 00 30 8C E5 F7 FF FF 1A 00 00 61 E0 40 01 A0 E1 08 D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI_strxfrm_6890a3b16f57ee4692d0a7e29896d8e9 {
	meta:
		aliases = "strlcpy, __GI_strlcpy, strxfrm, __GI_strxfrm"
		size = "72"
		objfiles = "strlcpys@libc.a"
	strings:
		$pattern = { 00 00 52 E3 08 D0 4D E2 00 C0 A0 E1 01 20 42 12 07 C0 8D 02 01 00 A0 E1 03 00 00 EA 00 00 52 E3 01 20 42 12 01 C0 8C 12 01 00 80 E2 00 30 D0 E5 00 00 53 E3 00 30 CC E5 F7 FF FF 1A 00 00 61 E0 08 D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule __collated_compare_91758ae0e49f946321eae123c4722c32 {
	meta:
		aliases = "__collated_compare"
		size = "48"
		objfiles = "globs@libc.a"
	strings:
		$pattern = { 00 00 90 E5 00 10 91 E5 01 00 50 E1 00 00 A0 03 1E FF 2F 01 00 00 50 E3 01 00 80 02 1E FF 2F 01 00 00 51 E3 00 00 E0 03 1E FF 2F 01 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule alphasort_6a46915530b2af5315a72aaace9ccde0 {
	meta:
		aliases = "alphasort"
		size = "20"
		objfiles = "alphasorts@libc.a"
	strings:
		$pattern = { 00 00 90 E5 00 10 91 E5 0B 00 80 E2 0B 10 81 E2 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule alphasort64_84e13e7cc59419990a6697386058cc67 {
	meta:
		aliases = "alphasort64"
		size = "20"
		objfiles = "alphasort64s@libc.a"
	strings:
		$pattern = { 00 00 90 E5 00 10 91 E5 13 00 80 E2 13 10 81 E2 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __old_sem_getvalue_22cb04aad072e053abff474f98078b63 {
	meta:
		aliases = "__old_sem_getvalue"
		size = "24"
		objfiles = "oldsemaphores@libpthread.a"
	strings:
		$pattern = { 00 00 90 E5 01 30 10 E2 A0 30 A0 11 00 00 A0 E3 00 30 81 E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule pthread_mutexattr_getpshared_948adb0af1153ac4f43e29297a009bc2 {
	meta:
		aliases = "pthread_condattr_getpshared, __pthread_mutexattr_getpshared, pthread_mutexattr_getpshared"
		size = "12"
		objfiles = "condvars@libpthread.a, mutexs@libpthread.a"
	strings:
		$pattern = { 00 00 A0 E3 00 00 81 E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule setpgrp_f74a68b9821b334df542b94e7a7230e6 {
	meta:
		aliases = "setpgrp"
		size = "12"
		objfiles = "setpgrps@libc.a"
	strings:
		$pattern = { 00 00 A0 E3 00 10 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_mutex_unlock_281ea062d6e8fd2b1443a4711a7fce4e {
	meta:
		aliases = "__udiv_w_sdiv, __pthread_mutex_lock, __GI_wcsftime, __pthread_mutex_init, __pthread_mutexattr_destroy, __GI_pthread_condattr_init, pthread_condattr_init, __GI_pthread_condattr_destroy, wcsftime, pthread_attr_destroy, pthread_rwlockattr_destroy, grantpt, pthread_condattr_destroy, pthread_mutexattr_destroy, __GI_pthread_attr_destroy, __pthread_mutex_trylock, __pthread_mutex_unlock"
		size = "8"
		objfiles = "mutexs@libpthread.a, grantpts@libc.a, __uClibc_mains@libc.a, attrs@libpthread.a, _udiv_w_sdiv@libgcc.a"
	strings:
		$pattern = { 00 00 A0 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule siggetmask_dbde277b57be3767e4c30d5cae8cc7c4 {
	meta:
		aliases = "siggetmask"
		size = "8"
		objfiles = "siggetmasks@libc.a"
	strings:
		$pattern = { 00 00 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule umask_718af0f640e69c4141539597ff93e405 {
	meta:
		aliases = "umask"
		size = "60"
		objfiles = "umasks@libc.a"
	strings:
		$pattern = { 00 08 A0 E1 80 40 2D E9 20 08 A0 E1 3C 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 08 A0 E1 20 08 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule __paritydi2_2dbb84b2177823c530672b875b5fe7f6 {
	meta:
		aliases = "__paritydi2"
		size = "40"
		objfiles = "_paritydi2@libgcc.a"
	strings:
		$pattern = { 00 10 21 E0 21 18 21 E0 21 14 21 E0 21 12 21 E0 0C 00 9F E5 0F 10 01 E2 50 01 A0 E1 01 00 00 E2 1E FF 2F E1 96 69 00 00 }
	condition:
		$pattern
}

rule setlinebuf_ef6be85ecfd024a91cb0ef8b124a6eea {
	meta:
		aliases = "setlinebuf"
		size = "16"
		objfiles = "setlinebufs@libc.a"
	strings:
		$pattern = { 00 10 A0 E3 01 20 A0 E3 01 30 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_atoi_ab8a27fe8b5f3a96308a96ed58cab29b {
	meta:
		aliases = "atoll, atoi, atol, __GI_atol, __GI_atoi"
		size = "12"
		objfiles = "atols@libc.a, atolls@libc.a"
	strings:
		$pattern = { 00 10 A0 E3 0A 20 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule atof_0bbbd5e8b7ed6644e4aa24fbaa861c5d {
	meta:
		aliases = "sigpause, _setjmp, __GI_sigpause, mkstemp, atof"
		size = "8"
		objfiles = "mkstemps@libc.a, atofs@libc.a, bsd__setjmps@libc.a, sigpauses@libc.a"
	strings:
		$pattern = { 00 10 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __isnan_4465184e0e832a7691ca6c29a4d2f357 {
	meta:
		aliases = "__GI___isnan, __isnan"
		size = "40"
		objfiles = "s_isnans@libm.a"
	strings:
		$pattern = { 00 20 60 E2 00 20 82 E1 10 40 2D E9 02 01 C1 E3 A2 0F 80 E1 7F 04 60 E2 0F 06 80 E2 01 40 A0 E1 A0 0F A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __ieee754_atanh_c79ed0ec852ffad48d6ecabde49634e4 {
	meta:
		aliases = "__ieee754_atanh"
		size = "416"
		objfiles = "e_atanhs@libm.a"
	strings:
		$pattern = { 00 20 60 E2 F0 47 2D E9 00 20 82 E1 02 61 C1 E3 70 31 9F E5 A2 2F 86 E1 03 00 52 E1 00 80 A0 E1 01 90 A0 E1 01 40 A0 E1 01 A0 A0 E1 05 00 00 9A 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 03 00 00 EA 03 00 56 E1 05 00 00 1A 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? ?? 00 80 A0 E1 01 90 A0 E1 44 00 00 EA 1C 31 9F E5 03 00 56 E1 07 00 00 CA 14 21 9F E5 14 31 9F E5 ?? ?? ?? ?? 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? ?? 00 00 50 E3 39 00 00 1A FC 20 9F E5 06 40 A0 E1 02 00 56 E1 06 90 A0 E1 1B 00 00 CA 08 20 A0 E1 06 30 A0 E1 08 00 A0 E1 06 10 A0 E1 ?? ?? ?? ?? 08 20 A0 E1 04 30 A0 E1 00 60 A0 E1 }
	condition:
		$pattern
}

rule __GI_wcsnlen_3195fe81343aab330d22e3b287cf490e {
	meta:
		aliases = "wcsnlen, __GI_wcsnlen"
		size = "48"
		objfiles = "wcsnlens@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 00 00 00 EA 04 00 80 E2 00 00 51 E3 01 10 41 E2 02 00 00 0A 00 30 90 E5 00 00 53 E3 F8 FF FF 1A 00 00 62 E0 40 01 A0 E1 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI_wcslen_83f8bb85611f46bdc437e208e55eda3b {
	meta:
		aliases = "wcslen, __GI_wcslen"
		size = "36"
		objfiles = "wcslens@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 00 00 00 EA 04 00 80 E2 00 30 90 E5 00 00 53 E3 FB FF FF 1A 00 00 62 E0 40 01 A0 E1 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI_wcscmp_71b6ff4b7769eb8fabfa086695f8f6a9 {
	meta:
		aliases = "wcscmp, __GI_wcscoll, wcscoll, __GI_wcscmp"
		size = "52"
		objfiles = "wcscmps@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 01 00 00 EA 00 00 50 E3 1E FF 2F 01 00 00 92 E5 00 30 91 E5 04 20 82 E2 03 00 50 E1 04 10 81 E2 F7 FF FF 0A 00 00 E0 33 01 00 A0 23 1E FF 2F E1 }
	condition:
		$pattern
}

rule exp2_013f500d445bb2449045c26fb3d192fe {
	meta:
		aliases = "__GI_exp2, exp2"
		size = "20"
		objfiles = "w_exp2s@libm.a"
	strings:
		$pattern = { 00 20 A0 E1 01 30 A0 E1 00 00 A0 E3 01 11 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __decode_header_916ab7c96f5d9892a33bfef59ec57998 {
	meta:
		aliases = "__decode_header"
		size = "188"
		objfiles = "decodehs@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 01 30 D0 E5 00 00 D0 E5 00 34 83 E1 00 30 81 E5 D2 30 D2 E1 0C 00 A0 E3 A3 3F A0 E1 04 30 81 E5 02 30 D2 E5 A3 31 A0 E1 0F 30 03 E2 08 30 81 E5 02 30 D2 E5 23 31 A0 E1 01 30 03 E2 0C 30 81 E5 02 30 D2 E5 A3 30 A0 E1 01 30 03 E2 10 30 81 E5 02 30 D2 E5 01 30 03 E2 14 30 81 E5 D3 30 D2 E1 A3 3F A0 E1 18 30 81 E5 03 30 D2 E5 0F 30 03 E2 1C 30 81 E5 04 C0 D2 E5 05 30 D2 E5 0C 34 83 E1 20 30 81 E5 06 C0 D2 E5 07 30 D2 E5 0C 34 83 E1 24 30 81 E5 08 C0 D2 E5 09 30 D2 E5 0C 34 83 E1 28 30 81 E5 0B 30 D2 E5 0A 20 D2 E5 02 34 83 E1 2C 30 81 E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI_strcat_f1939fa8790176582400b33a66f15bc6 {
	meta:
		aliases = "strcat, __GI_strcat"
		size = "40"
		objfiles = "strcats@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 01 30 D2 E4 00 00 53 E3 FC FF FF 1A 02 20 42 E2 01 30 D1 E4 00 00 53 E3 01 30 E2 E5 FB FF FF 1A 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI_wcscpy_72a7f097aebd7eb369cc92f2651c406f {
	meta:
		aliases = "wcscpy, __GI_wcscpy"
		size = "24"
		objfiles = "wcscpys@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 04 30 91 E4 00 00 53 E3 04 30 82 E4 FB FF FF 1A 1E FF 2F E1 }
	condition:
		$pattern
}

rule wcscat_ce822917b4846debfaad4d606f7eaa7b {
	meta:
		aliases = "__GI_wcscat, wcscat"
		size = "40"
		objfiles = "wcscats@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 04 30 92 E4 00 00 53 E3 FC FF FF 1A 04 20 42 E2 04 30 91 E4 00 00 53 E3 04 30 82 E4 FB FF FF 1A 1E FF 2F E1 }
	condition:
		$pattern
}

rule wcspbrk_a6796ff4ca06937429518c2ebdb4c6e8 {
	meta:
		aliases = "__GI_wcspbrk, wcspbrk"
		size = "64"
		objfiles = "wcspbrks@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 08 00 00 EA 00 00 5C E1 01 00 00 1A 02 00 A0 E1 1E FF 2F E1 00 C0 93 E5 04 30 83 E2 00 00 5C E3 F7 FF FF 1A 04 20 82 E2 00 00 92 E5 00 00 50 E3 1E FF 2F 01 01 30 A0 E1 F5 FF FF EA }
	condition:
		$pattern
}

rule strpbrk_9e09ed053de78a7140627873dddf0de6 {
	meta:
		aliases = "__GI_strpbrk, strpbrk"
		size = "64"
		objfiles = "strpbrks@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 08 00 00 EA 00 00 5C E1 01 00 00 1A 02 00 A0 E1 1E FF 2F E1 00 C0 D3 E5 01 30 83 E2 00 00 5C E3 F7 FF FF 1A 01 20 82 E2 00 00 D2 E5 00 00 50 E3 1E FF 2F 01 01 30 A0 E1 F5 FF FF EA }
	condition:
		$pattern
}

rule hstrerror_05f5c02302a708077bc0c229443d830a {
	meta:
		aliases = "hstrerror"
		size = "60"
		objfiles = "herrors@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 24 00 9F E5 04 00 52 E3 00 00 8F E0 02 00 00 9A 18 30 9F E5 03 00 80 E0 1E FF 2F E1 10 30 9F E5 03 30 80 E0 02 01 93 E7 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sigisemptyset_09afa9769c2244ebe566b222be149c05 {
	meta:
		aliases = "sigisemptyset"
		size = "48"
		objfiles = "sigisemptys@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 7C 00 90 E5 1F 30 A0 E3 00 00 00 EA 03 01 92 E7 00 00 50 E3 01 00 00 1A 01 30 53 E2 FA FF FF 5A 01 00 70 E2 00 00 A0 33 1E FF 2F E1 }
	condition:
		$pattern
}

rule ntohl_94e3e7ef15be980979ed5a854a63090d {
	meta:
		aliases = "htonl, ntohl"
		size = "32"
		objfiles = "ntohls@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 FF 38 00 E2 20 0C A0 E1 23 04 80 E1 FF 3C 02 E2 03 04 80 E1 02 0C 80 E1 1E FF 2F E1 }
	condition:
		$pattern
}

rule wait_864ac745e063a9318b5097a856064e02 {
	meta:
		aliases = "__libc_wait, wait"
		size = "20"
		objfiles = "waits@libc.a"
	strings:
		$pattern = { 00 20 A0 E3 00 10 A0 E1 02 30 A0 E1 00 00 E0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wcsrchr_65132d6173a4c5cbaf70d99d5ea0e1ee {
	meta:
		aliases = "wcsrchr"
		size = "36"
		objfiles = "wcsrchrs@libc.a"
	strings:
		$pattern = { 00 20 A0 E3 00 30 90 E5 01 00 53 E1 00 20 A0 01 00 00 53 E3 04 00 80 E2 F9 FF FF 1A 02 00 A0 E1 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI_fopen_09351c1ab743219292cdadce4caf6a9f {
	meta:
		aliases = "fopen, __GI_fopen"
		size = "12"
		objfiles = "fopens@libc.a"
	strings:
		$pattern = { 00 20 A0 E3 00 30 E0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fopen64_70ce7f0f6430c5ff9dcf8b71b56cf22d {
	meta:
		aliases = "__GI_fopen64, fopen64"
		size = "12"
		objfiles = "fopen64s@libc.a"
	strings:
		$pattern = { 00 20 A0 E3 01 30 E0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_sigwaitinfo_1872c120642f00e628190dc1186e8f8e {
	meta:
		aliases = "sigwaitinfo, __GI_sigwaitinfo"
		size = "12"
		objfiles = "__rt_sigtimedwaits@libc.a"
	strings:
		$pattern = { 00 20 A0 E3 08 30 A0 E3 EE FF FF EA }
	condition:
		$pattern
}

rule __init_scan_cookie_ee1f4a776e9ede9b742ad03e52f1ea9d {
	meta:
		aliases = "__init_scan_cookie"
		size = "104"
		objfiles = "__scan_cookies@libc.a"
	strings:
		$pattern = { 00 20 A0 E3 19 20 C0 E5 B0 30 D1 E1 04 E0 2D E5 48 C0 9F E5 02 30 13 E2 0C 20 80 E5 40 20 9F E5 28 E0 91 15 0C C0 8F E0 03 E0 A0 01 2E 30 A0 E3 02 20 8C E0 08 10 80 E5 38 30 80 E5 00 10 A0 E3 01 30 A0 E3 14 E0 80 E5 1B 10 C0 E5 3C 20 80 E5 34 30 80 E5 1A 10 C0 E5 30 20 80 E5 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wcstold_3ded5e6bd630b9ee17870b8a0d99f528 {
	meta:
		aliases = "__GI_wcstold, __GI_strtold, strtold, wcstold"
		size = "8"
		objfiles = "wcstolds@libc.a, strtolds@libc.a"
	strings:
		$pattern = { 00 20 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_vwarnx_93715e4cb61cec5f4dc2dfa0833d30a2 {
	meta:
		aliases = "vwarnx, __GI_vwarnx"
		size = "8"
		objfiles = "errs@libc.a"
	strings:
		$pattern = { 00 20 A0 E3 B7 FF FF EA }
	condition:
		$pattern
}

rule sched_getaffinity_169b5729ee23160d56b9a0cb63f80537 {
	meta:
		aliases = "sched_getaffinity"
		size = "100"
		objfiles = "sched_getaffinitys@libc.a"
	strings:
		$pattern = { 00 30 51 E2 80 40 2D E9 03 10 A0 A1 02 11 E0 B3 02 C0 A0 E1 F2 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 04 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 70 E0 E3 00 30 80 E5 01 00 00 EA 01 00 70 E3 01 00 00 1A 07 00 A0 E1 80 80 BD E8 03 20 60 E0 00 10 A0 E3 00 00 8C E0 ?? ?? ?? ?? 00 00 A0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __ctzsi2_d4bf655c267718c30458cdb3b68afa9c {
	meta:
		aliases = "__ctzsi2"
		size = "124"
		objfiles = "_ctzsi2@libgcc.a"
	strings:
		$pattern = { 00 30 60 E2 00 10 03 E0 64 20 9F E5 01 08 51 E3 02 20 8F E0 0A 00 00 2A FF 00 51 E3 08 30 A0 83 00 30 A0 93 31 13 A0 E1 48 30 9F E5 07 C0 A0 83 00 C0 E0 93 03 20 92 E7 01 00 D2 E7 0C 00 80 E0 1E FF 2F E1 FF 34 E0 E3 03 00 51 E1 18 30 A0 83 10 30 A0 93 31 13 A0 E1 18 30 9F E5 17 C0 A0 83 0F C0 A0 93 03 20 92 E7 01 00 D2 E7 0C 00 80 E0 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_strcpy_4121208faa0498c79bdc795b38e60e58 {
	meta:
		aliases = "strcpy, __GI_strcpy"
		size = "28"
		objfiles = "strcpys@libc.a"
	strings:
		$pattern = { 00 30 61 E0 01 20 43 E2 01 30 D1 E4 00 00 53 E3 02 30 C1 E7 FB FF FF 1A 1E FF 2F E1 }
	condition:
		$pattern
}

rule cfgetispeed_7a2c3397b9870cd5768a5dd1cf2acbde {
	meta:
		aliases = "cfgetispeed"
		size = "32"
		objfiles = "speeds@libc.a"
	strings:
		$pattern = { 00 30 90 E5 00 00 53 E3 08 30 90 A5 08 00 9F A5 00 00 A0 B3 00 00 03 A0 1E FF 2F E1 0F 10 00 00 }
	condition:
		$pattern
}

rule pthread_rwlockattr_getkind_np_57e79cd282e28b24e2966b926ae0eba1 {
	meta:
		aliases = "__pthread_mutexattr_getkind_np, pthread_mutexattr_gettype, pthread_mutexattr_getkind_np, __pthread_mutexattr_gettype, __GI_pthread_attr_getdetachstate, pthread_attr_getdetachstate, pthread_rwlockattr_getkind_np"
		size = "16"
		objfiles = "rwlocks@libpthread.a, mutexs@libpthread.a, attrs@libpthread.a"
	strings:
		$pattern = { 00 30 90 E5 00 00 A0 E3 00 30 81 E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule insque_70bfcf76e3d2701fa42cf6b547efebb4 {
	meta:
		aliases = "insque"
		size = "28"
		objfiles = "insques@libc.a"
	strings:
		$pattern = { 00 30 91 E5 00 00 53 E3 00 00 81 E5 04 00 83 15 00 30 80 E5 04 10 80 E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule __heap_alloc_25525b96515f5a9895de283c67f9dba8 {
	meta:
		aliases = "__heap_alloc"
		size = "136"
		objfiles = "heap_allocs@libc.a"
	strings:
		$pattern = { 00 30 91 E5 04 E0 2D E5 03 30 83 E2 03 20 C3 E3 00 E0 A0 E1 0B 00 52 E3 00 00 90 E5 0C 20 A0 93 15 00 00 EA 00 C0 90 E5 02 00 5C E1 11 00 00 3A 2C 30 82 E2 03 00 5C E1 0C 30 62 20 00 30 80 25 08 00 00 2A 04 20 90 E5 00 00 52 E3 08 30 90 15 08 30 82 15 0C 00 90 E9 00 00 53 E3 04 20 83 15 00 20 8E 05 0C 20 A0 E1 0C 30 80 E2 03 00 6C E0 00 20 81 E5 04 F0 9D E4 04 00 90 E5 00 00 50 E3 E7 FF FF 1A 04 F0 9D E4 }
	condition:
		$pattern
}

rule __GI___cmsg_nxthdr_b67cf410bcaad3ad35b15d39cf3d19de {
	meta:
		aliases = "__cmsg_nxthdr, __GI___cmsg_nxthdr"
		size = "80"
		objfiles = "cmsg_nxthdrs@libc.a"
	strings:
		$pattern = { 00 30 91 E5 0B 00 53 E3 0E 00 00 9A 03 30 83 E2 03 C0 C3 E3 14 20 90 E5 10 30 90 E5 0C 00 81 E0 02 20 83 E0 0C 30 80 E2 02 00 53 E1 05 00 00 8A 0C 30 91 E7 03 30 83 E2 03 30 C3 E3 03 30 80 E0 02 00 53 E1 1E FF 2F 91 00 00 A0 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule wmemset_46bf70ea2ae579b120c6658546cd3492 {
	meta:
		aliases = "wmemset"
		size = "28"
		objfiles = "wmemsets@libc.a"
	strings:
		$pattern = { 00 30 A0 E1 00 00 00 EA 04 10 83 E4 00 00 52 E3 01 20 42 E2 FB FF FF 1A 1E FF 2F E1 }
	condition:
		$pattern
}

rule wcschr_682e8b77efd0ba96e07b391c67fb385b {
	meta:
		aliases = "__GI_wcschr, wcschr"
		size = "40"
		objfiles = "wcschrs@libc.a"
	strings:
		$pattern = { 00 30 A0 E1 00 00 93 E5 01 00 50 E1 01 00 00 1A 03 00 A0 E1 1E FF 2F E1 00 00 50 E3 04 30 83 E2 F7 FF FF 1A 1E FF 2F E1 }
	condition:
		$pattern
}

rule pthread_rwlockattr_init_ac020afaccb8bd1bc45515d0141bc5ba {
	meta:
		aliases = "pthread_rwlockattr_init"
		size = "20"
		objfiles = "rwlocks@libpthread.a"
	strings:
		$pattern = { 00 30 A0 E1 00 00 A0 E3 04 00 83 E5 00 00 83 E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI_pthread_cond_init_ca6d28b6672371abc4c8e0ec57f2e957 {
	meta:
		aliases = "pthread_cond_init, __GI_pthread_cond_init"
		size = "24"
		objfiles = "condvars@libpthread.a"
	strings:
		$pattern = { 00 30 A0 E1 00 00 A0 E3 08 00 83 E5 00 00 83 E5 04 00 83 E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule wcsncmp_6ce6d2d363bbcda51003675eb4ad77ba {
	meta:
		aliases = "wcsncmp"
		size = "68"
		objfiles = "wcsncmps@libc.a"
	strings:
		$pattern = { 00 30 A0 E1 01 00 00 EA 00 00 50 E3 1E FF 2F 01 00 00 52 E3 01 00 00 1A 02 00 A0 E1 1E FF 2F E1 00 00 93 E5 00 C0 91 E5 04 30 83 E2 0C 00 50 E1 04 10 81 E2 01 20 42 E2 F2 FF FF 0A 00 00 6C E0 1E FF 2F E1 }
	condition:
		$pattern
}

rule basename_0ec686d54baa2ebf76c2d21cc8a67236 {
	meta:
		aliases = "__GI_basename, basename"
		size = "36"
		objfiles = "basenames@libc.a"
	strings:
		$pattern = { 00 30 A0 E1 01 00 00 EA 2F 00 52 E3 03 00 A0 01 00 20 D3 E5 01 30 83 E2 00 00 52 E3 F9 FF FF 1A 1E FF 2F E1 }
	condition:
		$pattern
}

rule __aeabi_atexit_e8b0c22b3c5d5c6851b91f0dfbefccc8 {
	meta:
		aliases = "__aeabi_atexit"
		size = "16"
		objfiles = "aeabi_atexits@libc.a"
	strings:
		$pattern = { 00 30 A0 E1 01 00 A0 E1 03 10 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule logb_d7ad93ef88d258c816c52788967f757a {
	meta:
		aliases = "__GI_logb, logb"
		size = "132"
		objfiles = "s_logbs@libm.a"
	strings:
		$pattern = { 00 30 A0 E1 02 C1 C1 E3 03 30 9C E1 70 40 2D E9 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 06 00 00 1A ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 00 00 A0 E3 40 10 9F E5 ?? ?? ?? ?? 70 80 BD E8 38 30 9F E5 03 00 5C E1 03 00 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 70 80 BD E8 4C 0A B0 E1 00 00 A0 03 18 10 9F 05 70 80 BD 08 FF 0F 40 E2 03 00 40 E2 ?? ?? ?? ?? 70 80 BD E8 00 00 F0 BF FF FF EF 7F 00 F0 8F C0 }
	condition:
		$pattern
}

rule memset_d4150aabf3383fe094ac3522ab7afc96 {
	meta:
		aliases = "__GI_memset, memset"
		size = "156"
		objfiles = "memsets@libc.a"
	strings:
		$pattern = { 00 30 A0 E1 08 00 52 E3 16 00 00 BA 01 14 81 E1 01 18 81 E1 03 00 13 E3 01 10 C3 14 01 20 42 12 FB FF FF 1A 01 C0 A0 E1 08 00 52 E3 0D 00 00 BA 02 10 A3 E8 08 20 42 E2 08 00 52 E3 09 00 00 BA 02 10 A3 E8 08 20 42 E2 08 00 52 E3 05 00 00 BA 02 10 A3 E8 08 20 42 E2 08 00 52 E3 02 10 A3 A8 08 20 42 A2 EF FF FF AA 02 20 B0 E1 0E F0 A0 01 07 20 62 E2 02 F1 8F E0 00 00 A0 E1 01 10 C3 E4 01 10 C3 E4 01 10 C3 E4 01 10 C3 E4 01 10 C3 E4 01 10 C3 E4 01 10 C3 E4 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_rwlock_init_afbfa1353db08d0f77f511bda6dd7ced {
	meta:
		aliases = "pthread_rwlock_init"
		size = "68"
		objfiles = "rwlocks@libpthread.a"
	strings:
		$pattern = { 00 30 A0 E3 00 00 51 E3 04 30 80 E5 08 30 80 E5 14 30 80 E5 00 30 80 E5 0C 30 80 E5 10 30 80 E5 00 30 91 15 01 30 83 02 18 30 80 15 04 30 91 15 1C 10 80 05 18 30 80 05 1C 30 80 15 00 00 A0 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule pthread_mutex_init_c2d74847cb24c050a85994aee049dd9f {
	meta:
		aliases = "__pthread_mutex_init, pthread_mutex_init"
		size = "48"
		objfiles = "mutexs@libpthread.a"
	strings:
		$pattern = { 00 30 A0 E3 00 00 51 E3 14 30 80 E5 00 10 91 15 00 20 A0 E1 10 30 80 E5 03 10 A0 03 00 00 A0 E3 0C 10 82 E5 08 00 82 E5 04 00 82 E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule __floatunsisf_bb6048f6139fa6b32cc5947f87aa1360 {
	meta:
		aliases = "__aeabi_ui2f, __floatunsisf"
		size = "40"
		objfiles = "_addsubsf3@libgcc.a"
	strings:
		$pattern = { 00 30 A0 E3 01 00 00 EA 02 31 10 E2 00 00 60 42 00 C0 B0 E1 1E FF 2F 01 4B 34 83 E3 00 10 A0 E1 00 00 A0 E3 0F 00 00 EA }
	condition:
		$pattern
}

rule __pthread_unlock_2520523824fa03309155dfd8020210b6 {
	meta:
		aliases = "__pthread_unlock"
		size = "16"
		objfiles = "spinlocks@libpthread.a"
	strings:
		$pattern = { 00 30 A0 E3 04 30 80 E5 03 00 A0 E1 1E FF 2F E1 }
	condition:
		$pattern
}

rule strtoull_d17f3cff524b39318c52e8631321d422 {
	meta:
		aliases = "__GI_wcstoul, __GI_strtoull, __libc_waitpid, wcstoumax, __GI_waitpid, __GI_strtoul, waitpid, strtoul, wcstouq, wcstoull, strtoumax, wcstoul, __GI_wcstoull, __aeabi_assert, strtouq, strtoull"
		size = "8"
		objfiles = "wcstouls@libc.a, strtoulls@libc.a, aeabi_asserts@libc.a, wcstoulls@libc.a, strtouls@libc.a"
	strings:
		$pattern = { 00 30 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __aeabi_unwind_cpp_pr0_6faf1997a20a015de858253c6a1df739 {
	meta:
		aliases = "__aeabi_unwind_cpp_pr0"
		size = "8"
		objfiles = "unwind_arm@libgcc.a"
	strings:
		$pattern = { 00 30 A0 E3 AB FE FF EA }
	condition:
		$pattern
}

rule __aeabi_uread4_da81fd1e1bf204fafd6b82a8703e5283 {
	meta:
		aliases = "__aeabi_uread4"
		size = "32"
		objfiles = "unaligned_funcs@libgcc.a"
	strings:
		$pattern = { 00 30 D0 E5 01 20 D0 E5 02 10 D0 E5 02 34 83 E1 03 00 D0 E5 01 38 83 E1 00 0C 83 E1 1E FF 2F E1 }
	condition:
		$pattern
}

rule crypt_84387bc161f02e264561bc8e6d85cc59 {
	meta:
		aliases = "crypt"
		size = "60"
		objfiles = "crypts@libcrypt.a"
	strings:
		$pattern = { 00 30 D1 E5 24 00 53 E3 01 20 A0 E1 00 C0 A0 E1 06 00 00 1A 01 30 D1 E5 31 00 53 E3 03 00 00 1A 02 30 D1 E5 24 00 53 E3 00 00 00 1A ?? ?? ?? ?? 0C 00 A0 E1 02 10 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule siglongjmp_f8139e342af8f70999c4eadbcfdf2639 {
	meta:
		aliases = "__libc_siglongjmp, _longjmp, __libc_longjmp, longjmp, siglongjmp"
		size = "56"
		objfiles = "longjmps@libc.a"
	strings:
		$pattern = { 00 31 90 E5 00 00 53 E3 00 40 A0 E1 01 50 A0 E1 03 00 00 0A 02 00 A0 E3 41 1F 84 E2 00 20 A0 E3 ?? ?? ?? ?? 00 00 55 E3 05 10 A0 11 01 10 A0 03 04 00 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_ffs_ae89586a06d7d9e54392df2b0114e451 {
	meta:
		aliases = "ffs, __GI_ffs"
		size = "92"
		objfiles = "ffss@libc.a"
	strings:
		$pattern = { 00 38 A0 E1 23 38 A0 E1 00 00 53 E3 40 08 A0 01 01 20 A0 13 11 20 A0 03 FF 00 10 E3 08 30 82 02 40 04 A0 01 FF 20 03 02 0F 00 10 E3 04 30 82 02 40 02 A0 01 FF 20 03 02 03 00 10 E3 02 30 82 02 40 01 A0 01 FF 20 03 02 00 00 50 E3 01 30 80 12 01 30 03 12 02 00 83 10 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI_verr_c1b475570accd185990fa60a655bb1c9 {
	meta:
		aliases = "verrx, verr, __GI_verrx, __GI_verr"
		size = "24"
		objfiles = "errs@libc.a"
	strings:
		$pattern = { 00 40 A0 E1 01 00 A0 E1 02 10 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _exit_f5e8b45438b2ba8f7d06f094f20336f1 {
	meta:
		aliases = "__GI__exit, _exit"
		size = "44"
		objfiles = "_exits@libc.a"
	strings:
		$pattern = { 00 40 A0 E1 04 00 A0 E1 01 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 F9 FF FF 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 F5 FF FF EA }
	condition:
		$pattern
}

rule pthread_start_thread_event_e4cd2a319c850c917e51f98c0e6c9624 {
	meta:
		aliases = "pthread_start_thread_event"
		size = "40"
		objfiles = "managers@libpthread.a"
	strings:
		$pattern = { 00 40 A0 E1 ?? ?? ?? ?? 00 10 A0 E3 14 00 84 E5 1C 00 94 E5 ?? ?? ?? ?? 1C 00 94 E5 ?? ?? ?? ?? 04 00 A0 E1 B7 FF FF EB }
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

rule __GI_wmemcpy_fc07af9a3423eb7797edd1a3c344943c {
	meta:
		aliases = "wmemcpy, __GI_wmemcpy"
		size = "32"
		objfiles = "wmemcpys@libc.a"
	strings:
		$pattern = { 00 C0 A0 E1 01 00 00 EA 04 30 91 E4 04 30 8C E4 00 00 52 E3 01 20 42 E2 FA FF FF 1A 1E FF 2F E1 }
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
		objfiles = "__longjmps@libc.a"
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

rule wcsncpy_b810487c4d381d0f53f9e018ba5331b9 {
	meta:
		aliases = "wcsncpy"
		size = "44"
		objfiles = "wcsncpys@libc.a"
	strings:
		$pattern = { 00 C0 A0 E1 04 00 00 EA 00 30 91 E5 00 00 53 E3 00 30 8C E5 04 10 81 12 04 C0 8C E2 00 00 52 E3 01 20 42 E2 F7 FF FF 1A 1E FF 2F E1 }
	condition:
		$pattern
}

rule wcsncat_019d9f5438ff492e52a625604fd200f8 {
	meta:
		aliases = "wcsncat"
		size = "72"
		objfiles = "wcsncats@libc.a"
	strings:
		$pattern = { 00 C0 A0 E1 04 30 9C E4 00 00 53 E3 FC FF FF 1A 04 C0 4C E2 00 00 00 EA 04 C0 8C E2 00 00 52 E3 01 20 42 E2 04 00 00 0A 00 30 91 E5 04 10 81 E2 00 00 53 E3 00 30 8C E5 F6 FF FF 1A 00 30 A0 E3 00 30 8C E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule __sigsetjmp_3a6521cb280ba33aa115e7b2333d80a8 {
	meta:
		aliases = "__sigsetjmp"
		size = "12"
		objfiles = "setjmps@libc.a"
	strings:
		$pattern = { 00 C0 A0 E1 F0 6F AC E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule read_uleb128_9ad09bd7bfc6574ecde1594b2e5f9565 {
	meta:
		aliases = "read_uleb128"
		size = "40"
		objfiles = "unwind_c@libgcc.a"
	strings:
		$pattern = { 00 C0 A0 E3 0C 20 A0 E1 01 30 D0 E4 80 00 13 E3 7F 30 03 E2 13 C2 8C E1 07 20 82 E2 F9 FF FF 1A 00 C0 81 E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule __gesf2_690bec0c1b8f96963814b21cee1e835e {
	meta:
		aliases = "__gtsf2, __gesf2"
		size = "112"
		objfiles = "_cmpsf2@libgcc.a"
	strings:
		$pattern = { 00 C0 E0 E3 02 00 00 EA 01 C0 A0 E3 00 00 00 EA 01 C0 A0 E3 04 C0 0D E5 80 20 A0 E1 81 30 A0 E1 42 CC F0 E1 43 CC F0 11 06 00 00 0A A3 C0 92 E1 01 00 30 11 03 00 52 50 C1 0F A0 81 C1 0F E0 31 01 00 80 13 1E FF 2F E1 42 CC F0 E1 01 00 00 1A 80 C4 B0 E1 03 00 00 1A 43 CC F0 E1 F2 FF FF 1A 81 C4 B0 E1 F0 FF FF 0A 04 00 1D E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule __gedf2_b2c08053c27994afa3ba11b03888d288 {
	meta:
		aliases = "__gtdf2, __gedf2"
		size = "148"
		objfiles = "_cmpdf2@libgcc.a"
	strings:
		$pattern = { 00 C0 E0 E3 02 00 00 EA 01 C0 A0 E3 00 00 00 EA 01 C0 A0 E3 04 C0 0D E5 81 C0 A0 E1 CC CA F0 E1 83 C0 A0 E1 CC CA F0 11 0D 00 00 0A 81 C0 90 E1 83 C0 92 01 03 00 31 11 02 00 30 01 00 00 A0 03 1E FF 2F 01 00 00 70 E3 03 00 31 E1 03 00 51 51 02 00 50 01 C3 0F A0 21 C3 0F E0 31 01 00 80 E3 1E FF 2F E1 81 C0 A0 E1 CC CA F0 E1 01 00 00 1A 01 C6 90 E1 04 00 00 1A 83 C0 A0 E1 CC CA F0 E1 E9 FF FF 1A 03 C6 92 E1 E7 FF FF 0A 04 00 1D E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule _Unwind_RaiseException_77b07bc7a3f012f4411d8232a360ba67 {
	meta:
		aliases = "___Unwind_Resume_or_Rethrow, ___Unwind_RaiseException, _Unwind_Resume_or_Rethrow, _Unwind_Resume, ___Unwind_Resume, _Unwind_RaiseException"
		size = "36"
		objfiles = "libunwind@libgcc.a"
	strings:
		$pattern = { 00 E0 2D E9 FF 1F 2D E9 00 30 A0 E3 0C 00 2D E9 04 10 8D E2 ?? ?? ?? ?? 40 E0 9D E5 48 D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule _Unwind_ForcedUnwind_d297b731937bfa2068cfeb67f90068e1 {
	meta:
		aliases = "___Unwind_ForcedUnwind, _Unwind_ForcedUnwind"
		size = "36"
		objfiles = "libunwind@libgcc.a"
	strings:
		$pattern = { 00 E0 2D E9 FF 1F 2D E9 00 30 A0 E3 0C 00 2D E9 04 30 8D E2 ?? ?? ?? ?? 40 E0 9D E5 48 D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule wmempcpy_58ced995d6c5ab1e068910b410c6c233 {
	meta:
		aliases = "__GI_wmempcpy, wmempcpy"
		size = "28"
		objfiles = "wmempcpys@libc.a"
	strings:
		$pattern = { 01 00 00 EA 04 30 91 E4 04 30 80 E4 00 00 52 E3 01 20 42 E2 FA FF FF 1A 1E FF 2F E1 }
	condition:
		$pattern
}

rule __libc_sa_len_1a3225700188c92ceeac575ecd0c2b16 {
	meta:
		aliases = "__libc_sa_len"
		size = "88"
		objfiles = "sa_lens@libc.a"
	strings:
		$pattern = { 01 00 40 E2 09 00 50 E3 00 F1 8F 90 0B 00 00 EA 08 00 00 EA 0D 00 00 EA 08 00 00 EA 0B 00 00 EA 06 00 00 EA 05 00 00 EA 04 00 00 EA 03 00 00 EA 02 00 00 EA 03 00 00 EA 6E 00 A0 E3 1E FF 2F E1 00 00 A0 E3 1E FF 2F E1 1C 00 A0 E3 1E FF 2F E1 10 00 A0 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI_pthread_equal_933d16d4bb93d89ae99300aee1361569 {
	meta:
		aliases = "pthread_equal, __GI_pthread_equal"
		size = "16"
		objfiles = "pthreads@libpthread.a"
	strings:
		$pattern = { 01 00 50 E1 00 00 A0 13 01 00 A0 03 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI_pthread_attr_setdetachsta_f16f890431117d4272b7ecbd47929bd7 {
	meta:
		aliases = "pthread_rwlockattr_setkind_np, pthread_attr_setdetachstate, __GI_pthread_attr_setdetachstate"
		size = "20"
		objfiles = "rwlocks@libpthread.a, attrs@libpthread.a"
	strings:
		$pattern = { 01 00 51 E3 00 10 80 95 16 00 A0 83 00 00 A0 93 1E FF 2F E1 }
	condition:
		$pattern
}

rule pthread_rwlockattr_setpshared_08dfbf9d485eff685e0a877ac1a5caad {
	meta:
		aliases = "pthread_rwlockattr_setpshared"
		size = "20"
		objfiles = "rwlocks@libpthread.a"
	strings:
		$pattern = { 01 00 51 E3 04 10 80 95 16 00 A0 83 00 00 A0 93 1E FF 2F E1 }
	condition:
		$pattern
}

rule pthread_attr_setinheritsched_3631945a5c9e6aa23f8db0ecfc6a63b7 {
	meta:
		aliases = "__GI_pthread_attr_setinheritsched, pthread_attr_setinheritsched"
		size = "20"
		objfiles = "attrs@libpthread.a"
	strings:
		$pattern = { 01 00 51 E3 0C 10 80 95 16 00 A0 83 00 00 A0 93 1E FF 2F E1 }
	condition:
		$pattern
}

rule pthread_condattr_setpshared_d15d2401a89b721a992ab22e29f06f42 {
	meta:
		aliases = "__pthread_mutexattr_setpshared, pthread_mutexattr_setpshared, pthread_condattr_setpshared"
		size = "28"
		objfiles = "condvars@libpthread.a, mutexs@libpthread.a"
	strings:
		$pattern = { 01 00 51 E3 16 00 A0 83 1E FF 2F 81 00 00 51 E3 26 00 A0 13 00 00 A0 03 1E FF 2F E1 }
	condition:
		$pattern
}

rule _stdlib_mb_cur_max_dab03afea34cb473448f5f70e3c6b952 {
	meta:
		aliases = "old_sem_extricate_func, __GI_xdr_void, __GI__stdlib_mb_cur_max, xdr_void, _stdlib_mb_cur_max"
		size = "8"
		objfiles = "xdrs@libc.a, _stdlib_mb_cur_maxs@libc.a, oldsemaphores@libpthread.a"
	strings:
		$pattern = { 01 00 A0 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule __pthread_attr_setstacksize_4514bdcb7eab826dae299431b2704f37 {
	meta:
		aliases = "pthread_attr_setstacksize, __pthread_attr_setstacksize"
		size = "20"
		objfiles = "attrs@libpthread.a"
	strings:
		$pattern = { 01 09 51 E3 20 10 80 25 16 00 A0 33 00 00 A0 23 1E FF 2F E1 }
	condition:
		$pattern
}

rule _store_inttype_609473efd425038466fe70c9b2fe357b {
	meta:
		aliases = "_store_inttype"
		size = "44"
		objfiles = "_store_inttypes@libc.a"
	strings:
		$pattern = { 01 0C 51 E3 00 20 C0 05 1E FF 2F 01 02 0B 51 E3 01 00 00 1A 0C 00 80 E8 1E FF 2F E1 02 0C 51 E3 B0 20 C0 01 00 20 80 15 1E FF 2F E1 }
	condition:
		$pattern
}

rule __sigismember_a594e6bf04222e65c636e51e46a0e3a0 {
	meta:
		aliases = "__sigismember"
		size = "36"
		objfiles = "sigsetopss@libc.a"
	strings:
		$pattern = { 01 10 41 E2 A1 32 A0 E1 03 21 90 E7 1F 10 01 E2 01 30 A0 E3 13 31 12 E0 00 00 A0 03 01 00 A0 13 1E FF 2F E1 }
	condition:
		$pattern
}

rule __sigaddset_def2a84d1faf51caf49b6d72dac73325 {
	meta:
		aliases = "__sigaddset"
		size = "36"
		objfiles = "sigsetopss@libc.a"
	strings:
		$pattern = { 01 10 41 E2 A1 C2 A0 E1 0C 31 90 E7 1F 10 01 E2 01 20 A0 E3 12 31 83 E1 0C 31 80 E7 00 00 A0 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule __sigdelset_fc27983c4b00e010ab68650cbf688da3 {
	meta:
		aliases = "__sigdelset"
		size = "36"
		objfiles = "sigsetopss@libc.a"
	strings:
		$pattern = { 01 10 41 E2 A1 C2 A0 E1 0C 31 90 E7 1F 10 01 E2 01 20 A0 E3 12 31 C3 E1 0C 31 80 E7 00 00 A0 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule dlclose_80427568328fb69de67e3560dac86357 {
	meta:
		aliases = "dlclose"
		size = "8"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { 01 10 A0 E3 36 FF FF EA }
	condition:
		$pattern
}

rule setjmp_dff1374097697900181e6e2b83b634f3 {
	meta:
		aliases = "mkstemp64, mktime, __GI_iswalnum, timelocal, iswalnum, setjmp"
		size = "8"
		objfiles = "mktimes@libc.a, iswalnums@libc.a, bsd_setjmps@libc.a, mkstemp64s@libc.a"
	strings:
		$pattern = { 01 10 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule chmod_ef105e2832524ba073018f6aa306b502 {
	meta:
		aliases = "__GI_chmod, chmod"
		size = "56"
		objfiles = "chmods@libc.a"
	strings:
		$pattern = { 01 18 A0 E1 80 40 2D E9 21 18 A0 E1 0F 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_mkdir_e27cdd3694c6ea1a50cc15171388320e {
	meta:
		aliases = "mkdir, __GI_mkdir"
		size = "56"
		objfiles = "mkdirs@libc.a"
	strings:
		$pattern = { 01 18 A0 E1 80 40 2D E9 21 18 A0 E1 27 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule fchmod_36ecc37aeed3998b0ef433286946a253 {
	meta:
		aliases = "fchmod"
		size = "56"
		objfiles = "fchmods@libc.a"
	strings:
		$pattern = { 01 18 A0 E1 80 40 2D E9 21 18 A0 E1 5E 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule mkfifo_1df665c44b9ee6c7007cf12d04721223 {
	meta:
		aliases = "mkfifo"
		size = "16"
		objfiles = "mkfifos@libc.a"
	strings:
		$pattern = { 01 1A 81 E3 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __udivsi3_dbbdc5a74837d558cc953f8cceff20ca {
	meta:
		aliases = "__aeabi_uidiv, __udivsi3"
		size = "496"
		objfiles = "_udivsi3@libgcc.a"
	strings:
		$pattern = { 01 20 51 E2 1E FF 2F 01 74 00 00 3A 01 00 50 E1 6B 00 00 9A 02 00 11 E1 6C 00 00 0A 10 3F 6F E1 11 2F 6F E1 03 30 42 E0 1F 30 73 E2 83 30 83 10 00 20 A0 E3 03 F1 8F 10 00 00 A0 E1 81 0F 50 E1 02 20 A2 E0 81 0F 40 20 01 0F 50 E1 02 20 A2 E0 01 0F 40 20 81 0E 50 E1 02 20 A2 E0 81 0E 40 20 01 0E 50 E1 02 20 A2 E0 01 0E 40 20 81 0D 50 E1 02 20 A2 E0 81 0D 40 20 01 0D 50 E1 02 20 A2 E0 01 0D 40 20 81 0C 50 E1 02 20 A2 E0 81 0C 40 20 01 0C 50 E1 02 20 A2 E0 01 0C 40 20 81 0B 50 E1 02 20 A2 E0 81 0B 40 20 01 0B 50 E1 02 20 A2 E0 01 0B 40 20 81 0A 50 E1 02 20 A2 E0 81 0A 40 20 01 0A 50 E1 02 20 A2 E0 }
	condition:
		$pattern
}

rule __umodsi3_b757651edfa3201279a016d84dee351b {
	meta:
		aliases = "__umodsi3"
		size = "328"
		objfiles = "_umodsi3@libgcc.a"
	strings:
		$pattern = { 01 20 51 E2 4B 00 00 3A 01 00 50 11 00 00 A0 03 02 00 11 81 02 00 00 00 1E FF 2F 91 11 2F 6F E1 10 3F 6F E1 03 20 42 E0 1F 20 72 E2 82 F1 8F 10 00 00 A0 E1 81 0F 50 E1 81 0F 40 20 01 0F 50 E1 01 0F 40 20 81 0E 50 E1 81 0E 40 20 01 0E 50 E1 01 0E 40 20 81 0D 50 E1 81 0D 40 20 01 0D 50 E1 01 0D 40 20 81 0C 50 E1 81 0C 40 20 01 0C 50 E1 01 0C 40 20 81 0B 50 E1 81 0B 40 20 01 0B 50 E1 01 0B 40 20 81 0A 50 E1 81 0A 40 20 01 0A 50 E1 01 0A 40 20 81 09 50 E1 81 09 40 20 01 09 50 E1 01 09 40 20 81 08 50 E1 81 08 40 20 01 08 50 E1 01 08 40 20 81 07 50 E1 81 07 40 20 01 07 50 E1 01 07 40 20 81 06 50 E1 }
	condition:
		$pattern
}

rule bcmp_53b538cb10b98e19970157fe279f25da {
	meta:
		aliases = "__GI_memcmp, memcmp, bcmp"
		size = "44"
		objfiles = "memcmps@libc.a"
	strings:
		$pattern = { 01 20 52 E2 00 00 A0 43 0E F0 A0 41 02 C0 80 E0 01 20 D0 E4 01 30 D1 E4 00 00 5C E1 03 00 52 21 FA FF FF 0A 03 00 42 E0 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __aeabi_ul2f_e9c3aec81875d0f46f6c7fe1415d9b53 {
	meta:
		aliases = "__floatundisf, __aeabi_ul2f"
		size = "140"
		objfiles = "_addsubsf3@libgcc.a"
	strings:
		$pattern = { 01 20 90 E1 1E FF 2F 01 00 30 A0 E3 05 00 00 EA 01 20 90 E1 1E FF 2F 01 02 31 11 E2 01 00 00 5A 00 00 70 E2 00 10 E1 E2 01 C0 B0 E1 00 C0 A0 01 00 10 A0 01 00 00 A0 03 5B 34 83 E3 01 32 43 02 02 35 43 E2 1C 2F 6F E1 08 20 52 E2 82 3B 43 E0 06 00 00 BA 11 32 83 E0 10 C2 A0 E1 20 20 62 E2 02 01 5C E3 30 02 A3 E0 01 00 C0 03 1E FF 2F E1 20 20 82 E2 11 C2 A0 E1 20 20 62 E2 8C 00 90 E1 31 02 A3 E0 AC 0F C0 01 1E FF 2F E1 }
	condition:
		$pattern
}

rule __aeabi_l2f_2227d951da9f2e4df3e17fd45b72acf6 {
	meta:
		aliases = "__floatdisf, __aeabi_l2f"
		size = "124"
		objfiles = "_addsubsf3@libgcc.a"
	strings:
		$pattern = { 01 20 90 E1 1E FF 2F 01 02 31 11 E2 01 00 00 5A 00 00 70 E2 00 10 E1 E2 01 C0 B0 E1 00 C0 A0 01 00 10 A0 01 00 00 A0 03 5B 34 83 E3 01 32 43 02 02 35 43 E2 1C 2F 6F E1 08 20 52 E2 82 3B 43 E0 06 00 00 BA 11 32 83 E0 10 C2 A0 E1 20 20 62 E2 02 01 5C E3 30 02 A3 E0 01 00 C0 03 1E FF 2F E1 20 20 82 E2 11 C2 A0 E1 20 20 62 E2 8C 00 90 E1 31 02 A3 E0 AC 0F C0 01 1E FF 2F E1 }
	condition:
		$pattern
}

rule __floatundidf_5f8a2e560aee5c1db5a7b19daaf440fd {
	meta:
		aliases = "__aeabi_ul2d, __floatundidf"
		size = "116"
		objfiles = "_addsubdf3@libgcc.a"
	strings:
		$pattern = { 01 20 90 E1 1E FF 2F 01 30 40 2D E9 00 50 A0 E3 06 00 00 EA 01 20 90 E1 1E FF 2F 01 30 40 2D E9 02 51 11 E2 01 00 00 5A 00 00 70 E2 00 10 E1 E2 01 4B A0 E3 32 40 84 E2 21 CB B0 E1 5C FF FF 0A 03 20 A0 E3 AC C1 B0 E1 03 20 82 12 AC C1 B0 E1 03 20 82 12 AC 21 82 E0 20 30 62 E2 10 C3 A0 E1 30 02 A0 E1 11 03 80 E1 31 12 A0 E1 02 40 84 E0 4F FF FF EA }
	condition:
		$pattern
}

rule __aeabi_l2d_43d4d166ab157c3340ade98d50680aa5 {
	meta:
		aliases = "__floatdidf, __aeabi_l2d"
		size = "96"
		objfiles = "_addsubdf3@libgcc.a"
	strings:
		$pattern = { 01 20 90 E1 1E FF 2F 01 30 40 2D E9 02 51 11 E2 01 00 00 5A 00 00 70 E2 00 10 E1 E2 01 4B A0 E3 32 40 84 E2 21 CB B0 E1 5C FF FF 0A 03 20 A0 E3 AC C1 B0 E1 03 20 82 12 AC C1 B0 E1 03 20 82 12 AC 21 82 E0 20 30 62 E2 10 C3 A0 E1 30 02 A0 E1 11 03 80 E1 31 12 A0 E1 02 40 84 E0 4F FF FF EA }
	condition:
		$pattern
}

rule tcflow_31b4cb6eec270029f89cdee4b999263a {
	meta:
		aliases = "tcflow"
		size = "16"
		objfiles = "tcflows@libc.a"
	strings:
		$pattern = { 01 20 A0 E1 00 10 9F E5 ?? ?? ?? ?? 0A 54 00 00 }
	condition:
		$pattern
}

rule tcflush_d6971a05e01f971759791f4f6c3e1773 {
	meta:
		aliases = "tcflush"
		size = "16"
		objfiles = "tcflushs@libc.a"
	strings:
		$pattern = { 01 20 A0 E1 00 10 9F E5 ?? ?? ?? ?? 0B 54 00 00 }
	condition:
		$pattern
}

rule creat_c91cbddcf48e050919bd38fe461d8b81 {
	meta:
		aliases = "__libc_creat64, __libc_creat, creat64, creat"
		size = "16"
		objfiles = "creat64s@libc.a, opens@libc.a"
	strings:
		$pattern = { 01 20 A0 E1 00 10 9F E5 ?? ?? ?? ?? 41 02 00 00 }
	condition:
		$pattern
}

rule __GI_lrand48_r_84d5fc662cd176cf6a22464756e3399e {
	meta:
		aliases = "mrand48_r, lrand48_r, drand48_r, __GI_lrand48_r"
		size = "12"
		objfiles = "mrand48_rs@libc.a, drand48_rs@libc.a, lrand48_rs@libc.a"
	strings:
		$pattern = { 01 20 A0 E1 00 10 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mq_getattr_a464cd798fa96649246ccd82670132fa {
	meta:
		aliases = "gmtime_r, __aeabi_memclr8, __aeabi_memclr4, __aeabi_memclr, mq_getattr"
		size = "12"
		objfiles = "mq_getsetattrs@librt.a, gmtime_rs@libc.a, aeabi_memclrs@libc.a"
	strings:
		$pattern = { 01 20 A0 E1 00 10 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule bzero_0efc9bd82418dead8553fc2005f25bf4 {
	meta:
		aliases = "bzero"
		size = "12"
		objfiles = "bzeros@libc.a"
	strings:
		$pattern = { 01 20 A0 E1 00 10 A0 E3 ?? ?? ?? EA }
	condition:
		$pattern
}

rule xdr_netobj_5c60deddee2888a85e14877715f45e9a {
	meta:
		aliases = "xdr_netobj"
		size = "16"
		objfiles = "xdrs@libc.a"
	strings:
		$pattern = { 01 20 A0 E1 01 3B A0 E3 04 10 81 E2 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_vwarn_9a38596a919a3e117c37051b1f5029dd {
	meta:
		aliases = "vwarn, __GI_vwarn"
		size = "8"
		objfiles = "errs@libc.a"
	strings:
		$pattern = { 01 20 A0 E3 9C FF FF EA }
	condition:
		$pattern
}

rule swab_017ddc9b6a58ec91a6367ed0afe263ff {
	meta:
		aliases = "swab"
		size = "44"
		objfiles = "swabs@libc.a"
	strings:
		$pattern = { 01 20 C2 E3 02 C0 80 E0 04 00 00 EA B2 30 D0 E0 23 24 A0 E1 FF 30 03 E2 03 24 82 E1 B2 20 C1 E0 0C 00 50 E1 F8 FF FF 3A 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI_strcoll_5d8be841fab43937f1ba9f42fd8c1db7 {
	meta:
		aliases = "strcoll, strcmp, __GI_strcmp, __GI_strcoll"
		size = "28"
		objfiles = "strcmps@libc.a"
	strings:
		$pattern = { 01 20 D0 E4 01 30 D1 E4 01 00 52 E3 03 00 52 21 FA FF FF 0A 03 00 42 E0 0E F0 A0 E1 }
	condition:
		$pattern
}

rule towctrans_c1a91a83387a9d8f713eba9ac4e86ceb {
	meta:
		aliases = "__GI_towctrans, towctrans"
		size = "72"
		objfiles = "towctranss@libc.a"
	strings:
		$pattern = { 01 30 41 E2 01 00 53 E3 10 40 2D E9 00 40 A0 E1 07 00 00 8A 7F 00 50 E3 08 00 00 8A 01 00 51 E3 01 00 00 1A 10 40 BD E8 ?? ?? ?? ?? 10 40 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? 16 30 A0 E3 00 30 80 E5 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __aeabi_memset8_88a5bc2f1ccd01117c53c9610064cb34 {
	meta:
		aliases = "__aeabi_memset4, __aeabi_memset, __aeabi_memset8"
		size = "16"
		objfiles = "aeabi_memsets@libc.a"
	strings:
		$pattern = { 01 30 A0 E1 02 10 A0 E1 03 20 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_attr_setstackaddr_1d26a60e482e0ef74851109685f67fbd {
	meta:
		aliases = "pthread_attr_setstackaddr, __pthread_attr_setstackaddr"
		size = "20"
		objfiles = "attrs@libpthread.a"
	strings:
		$pattern = { 01 30 A0 E3 18 30 80 E5 1C 10 80 E5 00 00 A0 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule testandset_6ccfa1c38bbfcb0ab1363c00ebeab04a {
	meta:
		aliases = "testandset"
		size = "16"
		objfiles = "pt_machines@libpthread.a"
	strings:
		$pattern = { 01 30 A0 E3 93 30 00 E1 03 00 A0 E1 1E FF 2F E1 }
	condition:
		$pattern
}

rule strtoll_c01422cd02f2d83cb67ee1fe31d56cf7 {
	meta:
		aliases = "wcstoll, __GI_strtoll, wcstoimax, __GI_strtol, wcstoq, wcstol, strtoq, strtoimax, __GI_wcstol, strtol, __GI_wcstoll, strtoll"
		size = "8"
		objfiles = "strtols@libc.a, wcstols@libc.a, strtolls@libc.a, wcstolls@libc.a"
	strings:
		$pattern = { 01 30 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __aeabi_unwind_cpp_pr1_9d44a1be42707bbeb70e6efb061195b7 {
	meta:
		aliases = "__aeabi_unwind_cpp_pr1"
		size = "8"
		objfiles = "unwind_arm@libgcc.a"
	strings:
		$pattern = { 01 30 A0 E3 AD FE FF EA }
	condition:
		$pattern
}

rule stpcpy_c3ef4cb1307428838ffbde2ded564f36 {
	meta:
		aliases = "__GI_stpcpy, stpcpy"
		size = "24"
		objfiles = "stpcpys@libc.a"
	strings:
		$pattern = { 01 30 D1 E4 00 00 53 E3 01 30 C0 E4 FB FF FF 1A 01 00 40 E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule __aeabi_cdcmple_62f18cfc09e7783ed06b46fb9fae0856 {
	meta:
		aliases = "__aeabi_cdcmpeq, __aeabi_cdcmple"
		size = "20"
		objfiles = "_cmpdf2@libgcc.a"
	strings:
		$pattern = { 01 40 2D E9 ?? ?? ?? EB 00 00 50 E3 00 00 70 43 01 80 BD E8 }
	condition:
		$pattern
}

rule siglongjmp_0cc9d39680107282259cb27900414f04 {
	meta:
		aliases = "siglongjmp"
		size = "24"
		objfiles = "ptlongjmps@libpthread.a"
	strings:
		$pattern = { 01 50 A0 E1 00 40 A0 E1 B2 FF FF EB 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule longjmp_0822299301aedc7c252a4ed18fcefddb {
	meta:
		aliases = "longjmp"
		size = "24"
		objfiles = "ptlongjmps@libpthread.a"
	strings:
		$pattern = { 01 50 A0 E1 00 40 A0 E1 B8 FF FF EB 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wait3_6dd02c8ccd21a87df2c19360a317bd10 {
	meta:
		aliases = "wait3"
		size = "24"
		objfiles = "wait3s@libc.a"
	strings:
		$pattern = { 01 C0 A0 E1 02 30 A0 E1 00 10 A0 E1 0C 20 A0 E1 00 00 E0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __lesf2_f5e71b54f559735c480163db469deb54 {
	meta:
		aliases = "__ltsf2, __lesf2"
		size = "104"
		objfiles = "_cmpsf2@libgcc.a"
	strings:
		$pattern = { 01 C0 A0 E3 00 00 00 EA 01 C0 A0 E3 04 C0 0D E5 80 20 A0 E1 81 30 A0 E1 42 CC F0 E1 43 CC F0 11 06 00 00 0A A3 C0 92 E1 01 00 30 11 03 00 52 50 C1 0F A0 81 C1 0F E0 31 01 00 80 13 1E FF 2F E1 42 CC F0 E1 01 00 00 1A 80 C4 B0 E1 03 00 00 1A 43 CC F0 E1 F2 FF FF 1A 81 C4 B0 E1 F0 FF FF 0A 04 00 1D E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule __ledf2_a03d04001c0233255ccaa19a4f479f87 {
	meta:
		aliases = "__ltdf2, __ledf2"
		size = "140"
		objfiles = "_cmpdf2@libgcc.a"
	strings:
		$pattern = { 01 C0 A0 E3 00 00 00 EA 01 C0 A0 E3 04 C0 0D E5 81 C0 A0 E1 CC CA F0 E1 83 C0 A0 E1 CC CA F0 11 0D 00 00 0A 81 C0 90 E1 83 C0 92 01 03 00 31 11 02 00 30 01 00 00 A0 03 1E FF 2F 01 00 00 70 E3 03 00 31 E1 03 00 51 51 02 00 50 01 C3 0F A0 21 C3 0F E0 31 01 00 80 E3 1E FF 2F E1 81 C0 A0 E1 CC CA F0 E1 01 00 00 1A 01 C6 90 E1 04 00 00 1A 83 C0 A0 E1 CC CA F0 E1 E9 FF FF 1A 03 C6 92 E1 E7 FF FF 0A 04 00 1D E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule __eqsf2_f2199772768fe23525c4c89ff441fcf3 {
	meta:
		aliases = "__cmpsf2, __nesf2, __eqsf2"
		size = "96"
		objfiles = "_cmpsf2@libgcc.a"
	strings:
		$pattern = { 01 C0 A0 E3 04 C0 0D E5 80 20 A0 E1 81 30 A0 E1 42 CC F0 E1 43 CC F0 11 06 00 00 0A A3 C0 92 E1 01 00 30 11 03 00 52 50 C1 0F A0 81 C1 0F E0 31 01 00 80 13 1E FF 2F E1 42 CC F0 E1 01 00 00 1A 80 C4 B0 E1 03 00 00 1A 43 CC F0 E1 F2 FF FF 1A 81 C4 B0 E1 F0 FF FF 0A 04 00 1D E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule __nedf2_bac0753564ab7962d530cf4a7a62735a {
	meta:
		aliases = "__cmpdf2, __eqdf2, __nedf2"
		size = "132"
		objfiles = "_cmpdf2@libgcc.a"
	strings:
		$pattern = { 01 C0 A0 E3 04 C0 0D E5 81 C0 A0 E1 CC CA F0 E1 83 C0 A0 E1 CC CA F0 11 0D 00 00 0A 81 C0 90 E1 83 C0 92 01 03 00 31 11 02 00 30 01 00 00 A0 03 1E FF 2F 01 00 00 70 E3 03 00 31 E1 03 00 51 51 02 00 50 01 C3 0F A0 21 C3 0F E0 31 01 00 80 E3 1E FF 2F E1 81 C0 A0 E1 CC CA F0 E1 01 00 00 1A 01 C6 90 E1 04 00 00 1A 83 C0 A0 E1 CC CA F0 E1 E9 FF FF 1A 03 C6 92 E1 E7 FF FF 0A 04 00 1D E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule pthread_attr_setschedpolicy_393b7b81e8aa847925702806dd80da23 {
	meta:
		aliases = "__GI_pthread_attr_setschedpolicy, pthread_attr_setschedpolicy"
		size = "20"
		objfiles = "attrs@libpthread.a"
	strings:
		$pattern = { 02 00 51 E3 04 10 80 95 16 00 A0 83 00 00 A0 93 1E FF 2F E1 }
	condition:
		$pattern
}

rule _svcauth_short_da9d79174ce56606107713155a05cbbe {
	meta:
		aliases = "_svcauth_short"
		size = "8"
		objfiles = "svc_authuxs@libc.a"
	strings:
		$pattern = { 02 00 A0 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule __signbitf_cc49b4ef0ad92b3a63ea96f0203f180b {
	meta:
		aliases = "__GI___signbitf, __signbitf"
		size = "8"
		objfiles = "s_signbitfs@libm.a"
	strings:
		$pattern = { 02 01 00 E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI___signbit_75372f1cc782c5403a965b934f6fe465 {
	meta:
		aliases = "__signbit, __GI___signbit"
		size = "8"
		objfiles = "s_signbits@libm.a"
	strings:
		$pattern = { 02 01 01 E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule __aeabi_frsub_5a81b5d736392fadf689e025ac0460a7 {
	meta:
		aliases = "__aeabi_frsub"
		size = "412"
		objfiles = "_addsubsf3@libgcc.a"
	strings:
		$pattern = { 02 01 20 E2 00 00 00 EA 02 11 21 E2 80 20 B0 E1 81 30 B0 11 03 00 32 11 42 CC F0 11 43 CC F0 11 3C 00 00 0A 22 2C A0 E1 23 3C 72 E0 03 20 82 C0 01 10 20 C0 00 00 21 C0 01 10 20 C0 00 30 63 B2 19 00 53 E3 1E FF 2F 81 02 01 10 E3 02 05 80 E3 FF 04 C0 E3 00 00 60 12 02 01 11 E3 02 15 81 E3 FF 14 C1 E3 00 10 61 12 03 00 32 E1 23 00 00 0A 01 20 42 E2 51 03 90 E0 20 30 63 E2 11 13 A0 E1 02 31 00 E2 01 00 00 5A 00 10 71 E2 00 00 E0 E2 02 05 50 E3 0B 00 00 3A 01 04 50 E3 04 00 00 3A A0 00 B0 E1 61 10 A0 E1 01 20 82 E2 FE 00 52 E3 2D 00 00 2A 02 01 51 E3 82 0B A0 E0 01 00 C0 03 03 00 80 E1 1E FF 2F E1 }
	condition:
		$pattern
}

rule __aeabi_fneg_d0e50dd2e66e20e257d30a4d5d663bda {
	meta:
		aliases = "__negsf2, __aeabi_fneg"
		size = "8"
		objfiles = "_negsf2@libgcc.a"
	strings:
		$pattern = { 02 01 20 E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule __finitef_c6a9c4de45551889ffbfde6585c0470f {
	meta:
		aliases = "__GI___finitef, __finitef"
		size = "20"
		objfiles = "s_finitefs@libm.a"
	strings:
		$pattern = { 02 01 C0 E3 02 01 80 E2 02 05 80 E2 A0 0F A0 E1 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI___isnanf_b3f32007cc3227de0e2dadc2fa162c6a {
	meta:
		aliases = "__isnanf, __GI___isnanf"
		size = "20"
		objfiles = "s_isnanfs@libm.a"
	strings:
		$pattern = { 02 01 C0 E3 7F 04 60 E2 02 05 80 E2 A0 0F A0 E1 1E FF 2F E1 }
	condition:
		$pattern
}

rule __fpclassifyf_518d0c4ea39a1bb9f5c971ca48c4432e {
	meta:
		aliases = "__GI___fpclassifyf, __fpclassifyf"
		size = "68"
		objfiles = "s_fpclassifyfs@libm.a"
	strings:
		$pattern = { 02 01 D0 E3 02 00 A0 03 1E FF 2F 01 02 05 50 E3 03 00 A0 33 1E FF 2F 31 1C 30 9F E5 03 00 50 E1 04 00 A0 93 1E FF 2F 91 10 30 9F E5 03 00 50 E1 00 00 A0 83 01 00 A0 93 1E FF 2F E1 FF FF 7F 7F 00 00 80 7F }
	condition:
		$pattern
}

rule iswalpha_b4c86ed496878f11403ee5011a20a0e5 {
	meta:
		aliases = "__GI_iswalpha, iswalpha"
		size = "8"
		objfiles = "iswalphas@libc.a"
	strings:
		$pattern = { 02 10 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __aeabi_drsub_02ac9438b003dcb72d9a6893fb0e88ff {
	meta:
		aliases = "__aeabi_drsub"
		size = "952"
		objfiles = "_addsubdf3@libgcc.a"
	strings:
		$pattern = { 02 11 21 E2 00 00 00 EA 02 31 23 E2 30 40 2D E9 81 40 A0 E1 83 50 A0 E1 05 00 34 E1 02 00 30 01 00 C0 94 11 02 C0 95 11 C4 CA F0 11 C5 CA F0 11 79 00 00 0A A4 4A A0 E1 A5 5A 74 E0 00 50 65 B2 06 00 00 DA 05 40 84 E0 02 20 20 E0 03 30 21 E0 00 00 22 E0 01 10 23 E0 02 20 20 E0 03 30 21 E0 36 00 55 E3 30 80 BD 88 02 01 11 E3 01 16 A0 E1 01 C6 A0 E3 21 16 8C E1 01 00 00 0A 00 00 70 E2 00 10 E1 E2 02 01 13 E3 03 36 A0 E1 23 36 8C E1 01 00 00 0A 00 20 72 E2 00 30 E3 E2 05 00 34 E1 57 00 00 0A 01 40 44 E2 20 E0 75 E2 05 00 00 BA 12 CE A0 E1 32 05 90 E0 00 10 A1 E2 13 0E 90 E0 53 15 B1 E0 06 00 00 EA }
	condition:
		$pattern
}

rule __aeabi_dneg_2842341dadf15f712d107071cbcaac4b {
	meta:
		aliases = "__negdf2, __aeabi_dneg"
		size = "8"
		objfiles = "_negdf2@libgcc.a"
	strings:
		$pattern = { 02 11 21 E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule __aeabi_fsub_7c9b04926bf303609877e053cbe7969b {
	meta:
		aliases = "__subsf3, __aeabi_fsub"
		size = "404"
		objfiles = "_addsubsf3@libgcc.a"
	strings:
		$pattern = { 02 11 21 E2 80 20 B0 E1 81 30 B0 11 03 00 32 11 42 CC F0 11 43 CC F0 11 3C 00 00 0A 22 2C A0 E1 23 3C 72 E0 03 20 82 C0 01 10 20 C0 00 00 21 C0 01 10 20 C0 00 30 63 B2 19 00 53 E3 1E FF 2F 81 02 01 10 E3 02 05 80 E3 FF 04 C0 E3 00 00 60 12 02 01 11 E3 02 15 81 E3 FF 14 C1 E3 00 10 61 12 03 00 32 E1 23 00 00 0A 01 20 42 E2 51 03 90 E0 20 30 63 E2 11 13 A0 E1 02 31 00 E2 01 00 00 5A 00 10 71 E2 00 00 E0 E2 02 05 50 E3 0B 00 00 3A 01 04 50 E3 04 00 00 3A A0 00 B0 E1 61 10 A0 E1 01 20 82 E2 FE 00 52 E3 2D 00 00 2A 02 01 51 E3 82 0B A0 E0 01 00 C0 03 03 00 80 E1 1E FF 2F E1 81 10 B0 E1 00 00 A0 E0 }
	condition:
		$pattern
}

rule __GI___finite_7e0c5cae8508da6bb78b56b33650a1e3 {
	meta:
		aliases = "__finite, __GI___finite"
		size = "20"
		objfiles = "s_finites@libm.a"
	strings:
		$pattern = { 02 11 C1 E3 02 11 81 E2 01 16 81 E2 A1 0F A0 E1 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI_ilogb_76798331a455465e76a8e774213ad933 {
	meta:
		aliases = "ilogb, __GI_ilogb"
		size = "144"
		objfiles = "s_ilogbs@libm.a"
	strings:
		$pattern = { 02 21 C1 E3 01 06 52 E3 10 40 2D E9 00 30 A0 E1 01 40 A0 E1 13 00 00 AA 00 10 92 E1 06 01 A0 03 10 80 BD 08 00 00 52 E3 54 00 9F 05 02 00 00 0A 04 00 00 EA 01 00 40 E2 83 30 A0 E1 00 00 53 E3 FB FF FF CA 10 80 BD E8 38 00 9F E5 82 35 A0 E1 01 00 00 EA 01 00 40 E2 83 30 A0 E1 00 00 53 E3 FB FF FF CA 10 80 BD E8 1C 30 9F E5 03 00 52 E1 42 3A A0 D1 FF 0F 43 D2 02 01 E0 C3 03 00 40 D2 10 80 BD E8 ED FB FF FF 02 FC FF FF FF FF EF 7F }
	condition:
		$pattern
}

rule setenv_03c17d970a358c795ac18216235fb8cf {
	meta:
		aliases = "__GI_setenv, setenv"
		size = "12"
		objfiles = "setenvs@libc.a"
	strings:
		$pattern = { 02 30 A0 E1 00 20 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule vsprintf_0b0a06a3a22fb6e257f4aaea5dbd9dea {
	meta:
		aliases = "vsprintf"
		size = "16"
		objfiles = "vsprintfs@libc.a"
	strings:
		$pattern = { 02 30 A0 E1 01 20 A0 E1 00 10 E0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_getline_bbff622b5e4f585913ce99e23bd5159e {
	meta:
		aliases = "getline, __GI_getline"
		size = "12"
		objfiles = "getlines@libc.a"
	strings:
		$pattern = { 02 30 A0 E1 0A 20 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __aeabi_unwind_cpp_pr2_bde85f88f7c201799f52eb16c18fdb8d {
	meta:
		aliases = "__aeabi_unwind_cpp_pr2"
		size = "8"
		objfiles = "unwind_arm@libgcc.a"
	strings:
		$pattern = { 02 30 A0 E3 AF FE FF EA }
	condition:
		$pattern
}

rule __aeabi_i2f_06184ac45414c3f57fbcc57f94e86765 {
	meta:
		aliases = "__floatsisf, __aeabi_i2f"
		size = "32"
		objfiles = "_addsubsf3@libgcc.a"
	strings:
		$pattern = { 02 31 10 E2 00 00 60 42 00 C0 B0 E1 1E FF 2F 01 4B 34 83 E3 00 10 A0 E1 00 00 A0 E3 0F 00 00 EA }
	condition:
		$pattern
}

rule __subdf3_9f8fe820435f1d9a0765fba6174c3be2 {
	meta:
		aliases = "__aeabi_dsub, __subdf3"
		size = "688"
		objfiles = "_addsubdf3@libgcc.a"
	strings:
		$pattern = { 02 31 23 E2 30 40 2D E9 81 40 A0 E1 83 50 A0 E1 05 00 34 E1 02 00 30 01 00 C0 94 11 02 C0 95 11 C4 CA F0 11 C5 CA F0 11 79 00 00 0A A4 4A A0 E1 A5 5A 74 E0 00 50 65 B2 06 00 00 DA 05 40 84 E0 02 20 20 E0 03 30 21 E0 00 00 22 E0 01 10 23 E0 02 20 20 E0 03 30 21 E0 36 00 55 E3 30 80 BD 88 02 01 11 E3 01 16 A0 E1 01 C6 A0 E3 21 16 8C E1 01 00 00 0A 00 00 70 E2 00 10 E1 E2 02 01 13 E3 03 36 A0 E1 23 36 8C E1 01 00 00 0A 00 20 72 E2 00 30 E3 E2 05 00 34 E1 57 00 00 0A 01 40 44 E2 20 E0 75 E2 05 00 00 BA 12 CE A0 E1 32 05 90 E0 00 10 A1 E2 13 0E 90 E0 53 15 B1 E0 06 00 00 EA 20 50 45 E2 20 E0 8E E2 }
	condition:
		$pattern
}

rule __div0_951758d64c96433ee0178f9e192fb604 {
	meta:
		aliases = "__div0"
		size = "16"
		objfiles = "_dvmd_lnx@libgcc.a"
	strings:
		$pattern = { 02 40 2D E9 08 00 A0 E3 ?? ?? ?? ?? 02 80 BD E8 }
	condition:
		$pattern
}

rule __aeabi_lcmp_fa1efff14264542350e57e65830be738 {
	meta:
		aliases = "__aeabi_lcmp"
		size = "20"
		objfiles = "_aeabi_lcmp@libgcc.a"
	strings:
		$pattern = { 02 C0 50 E0 03 C0 D1 E0 02 C0 50 00 0C 00 A0 E1 1E FF 2F E1 }
	condition:
		$pattern
}

rule wmemcmp_f5bfb1d3aae9a42fc4a7d1b02d1af443 {
	meta:
		aliases = "wmemcmp"
		size = "64"
		objfiles = "wmemcmps@libc.a"
	strings:
		$pattern = { 02 C0 A0 E1 01 00 00 EA 04 10 81 E2 01 C0 4C E2 00 00 5C E3 01 00 00 1A 0C 00 A0 E1 1E FF 2F E1 00 20 90 E5 00 30 91 E5 04 00 80 E2 03 00 52 E1 F4 FF FF 0A 00 00 E0 33 01 00 A0 23 1E FF 2F E1 }
	condition:
		$pattern
}

rule dysize_4e505de58db37ad993f96dbc7b066c9a {
	meta:
		aliases = "dysize"
		size = "76"
		objfiles = "dysizes@libc.a"
	strings:
		$pattern = { 03 00 10 E3 10 40 2D E9 00 40 A0 E1 0A 00 00 1A 64 10 A0 E3 ?? ?? ?? ?? 00 00 51 E3 04 00 00 1A 04 00 A0 E1 19 1E 81 E2 ?? ?? ?? ?? 00 00 51 E3 01 00 00 1A 08 00 9F E5 10 80 BD E8 04 00 9F E5 10 80 BD E8 6E 01 00 00 6D 01 00 00 }
	condition:
		$pattern
}

rule posix_memalign_1a52a13720c74434b1382f89d21b88d8 {
	meta:
		aliases = "posix_memalign"
		size = "52"
		objfiles = "posix_memaligns@libc.a"
	strings:
		$pattern = { 03 00 11 E3 10 40 2D E9 00 40 A0 E1 16 00 A0 13 10 80 BD 18 01 00 A0 E1 02 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 00 84 E5 0C 00 A0 03 00 00 A0 13 10 80 BD E8 }
	condition:
		$pattern
}

rule __aeabi_ulcmp_6d2adfcafaf121b49594e6ad14e7fa8c {
	meta:
		aliases = "__aeabi_ulcmp"
		size = "36"
		objfiles = "_aeabi_ulcmp@libgcc.a"
	strings:
		$pattern = { 03 00 51 E1 00 00 E0 33 01 00 A0 83 1E FF 2F 11 02 00 50 E1 00 00 E0 33 01 00 A0 83 00 00 A0 03 1E FF 2F E1 }
	condition:
		$pattern
}

rule __ucmpdi2_022b5ea2983aee5f28117cf1d9fc88ed {
	meta:
		aliases = "__ucmpdi2"
		size = "44"
		objfiles = "_ucmpdi2@libgcc.a"
	strings:
		$pattern = { 03 00 51 E1 06 00 00 3A 03 00 00 8A 02 00 50 E1 03 00 00 3A 01 00 A0 93 1E FF 2F 91 02 00 A0 E3 1E FF 2F E1 00 00 A0 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule __cmpdi2_042254d0fb6c24d1bbcc98988c45a70e {
	meta:
		aliases = "__cmpdi2"
		size = "44"
		objfiles = "_cmpdi2@libgcc.a"
	strings:
		$pattern = { 03 00 51 E1 06 00 00 BA 03 00 00 CA 02 00 50 E1 03 00 00 3A 01 00 A0 93 1E FF 2F 91 02 00 A0 E3 1E FF 2F E1 00 00 A0 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule pthread_mutexattr_settype_dd51b77abc3acfa5d6b8a16107bb6db1 {
	meta:
		aliases = "__pthread_mutexattr_setkind_np, pthread_mutexattr_setkind_np, __pthread_mutexattr_settype, pthread_mutexattr_settype"
		size = "20"
		objfiles = "mutexs@libpthread.a"
	strings:
		$pattern = { 03 00 51 E3 00 10 80 95 16 00 A0 83 00 00 A0 93 1E FF 2F E1 }
	condition:
		$pattern
}

rule strncmp_a7c84389fcca25658056028c78fca22a {
	meta:
		aliases = "__GI_strncmp, strncmp"
		size = "280"
		objfiles = "strncmps@libc.a"
	strings:
		$pattern = { 03 00 52 E3 00 C0 A0 E1 00 00 A0 93 30 40 2D E9 00 E0 A0 91 3A 00 00 9A 22 51 A0 E1 00 00 DC E5 00 E0 D1 E5 01 40 8C E2 0E 30 50 E0 01 30 A0 13 00 00 50 E3 01 30 83 03 00 00 53 E3 2D 00 00 1A 01 00 DC E5 01 C0 D1 E5 01 E0 81 E2 0C 30 50 E0 01 30 A0 13 00 00 50 E3 01 30 83 03 00 00 53 E3 09 00 00 1A 01 00 D4 E5 01 C0 DE E5 01 10 84 E2 0C 30 50 E0 01 30 A0 13 00 00 50 E3 01 30 83 03 00 00 53 E3 01 40 8E E2 01 00 00 0A 00 00 6C E0 30 80 BD E8 01 00 D1 E5 01 E0 D4 E5 01 30 81 E2 01 C0 83 E2 0E 30 50 E0 01 30 A0 13 00 00 50 E3 01 30 83 03 00 00 53 E3 01 30 84 E2 01 10 83 E2 0C 00 00 1A 01 50 55 E2 }
	condition:
		$pattern
}

rule __GI_strncpy_eaf74f59e393968552fa6a369e6f4fff {
	meta:
		aliases = "strncpy, __GI_strncpy"
		size = "192"
		objfiles = "strncpys@libc.a"
	strings:
		$pattern = { 03 00 52 E3 30 40 2D E9 01 C0 40 E2 00 50 A0 E1 1C 00 00 9A 22 E1 A0 E1 00 30 D1 E5 01 40 81 E2 00 00 53 E3 01 30 EC E5 11 00 00 0A 01 30 D1 E5 01 00 84 E2 00 00 53 E3 01 30 EC E5 0C 00 00 0A 01 30 D4 E5 01 10 80 E2 00 00 53 E3 01 30 EC E5 07 00 00 0A 01 30 D0 E5 01 10 81 E2 00 00 53 E3 01 30 EC E5 02 00 00 0A 01 E0 5E E2 05 00 00 0A E8 FF FF EA 0C 30 65 E0 02 30 63 E0 01 30 53 E2 08 00 00 1A 0B 00 00 EA 03 30 12 E2 09 00 00 0A 01 20 D1 E4 01 30 53 E2 01 20 EC E5 05 00 00 0A 00 00 52 E3 F9 FF FF 1A 00 20 A0 E3 01 30 53 E2 01 20 EC E5 FC FF FF 1A 05 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_iswblank_3391c49eb95f9446ce34dd51dddfca12 {
	meta:
		aliases = "iswblank, __GI_iswblank"
		size = "8"
		objfiles = "iswblanks@libc.a"
	strings:
		$pattern = { 03 10 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_strlen_cebb5d24777319d078a11b9205b5cbd9 {
	meta:
		aliases = "strlen, __GI_strlen"
		size = "96"
		objfiles = "strlens@libc.a"
	strings:
		$pattern = { 03 10 C0 E3 04 20 91 E4 03 30 10 E2 00 00 63 E2 04 00 00 0A FF 20 82 E3 01 30 53 E2 FF 2C 82 C3 01 30 53 E2 FF 28 82 C3 FF 00 12 E3 FF 0C 12 13 FF 08 12 13 FF 04 12 13 04 00 80 12 04 20 91 14 F8 FF FF 1A FF 00 12 E3 01 00 80 12 FF 0C 12 13 01 00 80 12 FF 08 12 13 01 00 80 12 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_mutexattr_init_7c17adeb7432d5dedabdbab093eeabaf {
	meta:
		aliases = "__pthread_mutexattr_init, pthread_mutexattr_init"
		size = "16"
		objfiles = "mutexs@libpthread.a"
	strings:
		$pattern = { 03 30 A0 E3 00 30 80 E5 00 00 A0 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule __aeabi_uidivmod_4ab965911a7b4113d66eef0f270ae392 {
	meta:
		aliases = "__aeabi_idivmod, __aeabi_uidivmod"
		size = "24"
		objfiles = "_udivsi3@libgcc.a, _divsi3@libgcc.a"
	strings:
		$pattern = { 03 40 2D E9 ?? ?? ?? EB 06 40 BD E8 92 00 03 E0 03 10 41 E0 1E FF 2F E1 }
	condition:
		$pattern
}

rule memmem_22b76e40a92a210dce02ff6c229fd8c4 {
	meta:
		aliases = "__GI_memmem, memmem"
		size = "120"
		objfiles = "memmems@libc.a"
	strings:
		$pattern = { 03 C0 A0 E1 00 00 53 E3 01 30 80 E0 F0 41 2D E9 00 40 A0 E1 02 50 A0 E1 03 80 6C E0 0E 00 00 0A 0C 00 51 E1 01 70 4C 22 01 60 82 22 0D 00 00 2A 0E 00 00 EA 00 20 D4 E5 00 30 D5 E5 03 00 52 E1 07 00 00 1A 01 00 84 E2 06 10 A0 E1 07 20 A0 E1 ?? ?? ?? ?? 00 00 50 E3 01 00 00 1A 04 00 A0 E1 F0 81 BD E8 01 40 84 E2 08 00 54 E1 F0 FF FF 9A 00 00 A0 E3 F0 81 BD E8 }
	condition:
		$pattern
}

rule __GI_memccpy_06de593252e42457352f115c0215be91 {
	meta:
		aliases = "memccpy, __GI_memccpy"
		size = "48"
		objfiles = "memccpys@libc.a"
	strings:
		$pattern = { 03 C0 A0 E1 FF 20 02 E2 01 C0 5C E2 01 00 00 2A 00 00 A0 E3 1E FF 2F E1 00 30 D1 E5 01 10 81 E2 02 00 53 E1 01 30 C0 E4 F6 FF FF 1A 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI_wmemchr_791551bcdbaccaf4020a633de02fe7ca {
	meta:
		aliases = "wmemchr, __GI_wmemchr"
		size = "40"
		objfiles = "wmemchrs@libc.a"
	strings:
		$pattern = { 04 00 00 EA 00 30 90 E5 01 20 42 E2 01 00 53 E1 1E FF 2F 01 04 00 80 E2 00 00 52 E3 F8 FF FF 1A 02 00 A0 E1 1E FF 2F E1 }
	condition:
		$pattern
}

rule wcschrnul_819767789da2b1d9357ea383a3a432d7 {
	meta:
		aliases = "__GI_wcschrnul, wcschrnul"
		size = "28"
		objfiles = "wcschrnuls@libc.a"
	strings:
		$pattern = { 04 00 40 E2 04 30 B0 E5 00 00 53 E3 1E FF 2F 01 01 00 53 E1 FA FF FF 1A 1E FF 2F E1 }
	condition:
		$pattern
}

rule __pthread_lock_f4f264ef5350325c678ab1f9119c1696 {
	meta:
		aliases = "__pthread_lock"
		size = "8"
		objfiles = "spinlocks@libpthread.a"
	strings:
		$pattern = { 04 00 80 E2 D2 FF FF EA }
	condition:
		$pattern
}

rule _obstack_allocated_p_534240a55e2338f18fe639a0b55cac38 {
	meta:
		aliases = "_obstack_allocated_p"
		size = "44"
		objfiles = "obstacks@libc.a"
	strings:
		$pattern = { 04 00 90 E5 00 00 50 E3 04 00 00 0A 01 00 50 E1 FA FF FF 2A 00 30 90 E5 01 00 53 E1 F7 FF FF 3A 00 00 50 E2 01 00 A0 13 1E FF 2F E1 }
	condition:
		$pattern
}

rule svcudp_create_e51e8494506117e82db1d25eab4eabd4 {
	meta:
		aliases = "__GI_svcudp_create, svcudp_create"
		size = "16"
		objfiles = "svc_udps@libc.a"
	strings:
		$pattern = { 04 10 9F E5 01 20 A0 E1 ?? ?? ?? ?? 60 22 00 00 }
	condition:
		$pattern
}

rule __libc_tcdrain_af5447627100feed840bc78696d20c35 {
	meta:
		aliases = "tcdrain, __libc_tcdrain"
		size = "16"
		objfiles = "tcdrains@libc.a"
	strings:
		$pattern = { 04 10 9F E5 01 20 A0 E3 ?? ?? ?? ?? 09 54 00 00 }
	condition:
		$pattern
}

rule __GI_iswcntrl_f5a7a46beea641e92965c6d344a3a83c {
	meta:
		aliases = "iswcntrl, __GI_iswcntrl"
		size = "8"
		objfiles = "iswcntrls@libc.a"
	strings:
		$pattern = { 04 10 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _obstack_memory_used_78f95896e22f4d789492b35cfb276729 {
	meta:
		aliases = "_obstack_memory_used"
		size = "40"
		objfiles = "obstacks@libc.a"
	strings:
		$pattern = { 04 20 90 E5 00 00 A0 E3 03 00 00 EA 00 30 92 E5 03 30 80 E0 03 00 62 E0 04 20 92 E5 00 00 52 E3 F9 FF FF 1A 1E FF 2F E1 }
	condition:
		$pattern
}

rule pthread_mutex_timedlock_2dae78ce42dc43ce90927172d5771ac1 {
	meta:
		aliases = "pthread_mutex_timedlock"
		size = "248"
		objfiles = "mutexs@libpthread.a"
	strings:
		$pattern = { 04 20 91 E5 E8 30 9F E5 70 40 2D E9 03 00 52 E1 01 60 A0 E1 00 40 A0 E1 33 00 00 8A 0C 30 90 E5 03 00 53 E3 03 F1 8F 90 2F 00 00 EA 02 00 00 EA 06 00 00 EA 15 00 00 EA 23 00 00 EA 10 00 80 E2 00 10 A0 E3 ?? ?? ?? ?? 00 00 A0 E3 70 80 BD E8 88 FF FF EB 08 30 94 E5 00 50 A0 E1 00 00 53 E1 04 30 94 05 00 00 A0 03 01 30 83 02 05 00 00 0A 10 00 84 E2 05 10 A0 E1 ?? ?? ?? ?? 00 30 A0 E3 03 00 A0 E1 08 50 84 E5 04 30 84 E5 70 80 BD E8 78 FF FF EB 08 30 94 E5 00 50 A0 E1 00 00 53 E1 23 00 A0 03 70 80 BD 08 06 20 A0 E1 10 00 84 E2 05 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 6E 00 80 02 00 00 A0 13 08 50 84 15 }
	condition:
		$pattern
}

rule __GI_pthread_attr_getschedpoli_8b493cbb8fc566f00e7b45bdaf93e609 {
	meta:
		aliases = "pthread_rwlockattr_getpshared, pthread_attr_getschedpolicy, __GI_pthread_attr_getschedpolicy"
		size = "16"
		objfiles = "rwlocks@libpthread.a, attrs@libpthread.a"
	strings:
		$pattern = { 04 30 90 E5 00 00 A0 E3 00 30 81 E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule wcpcpy_c6d0bfa78b8ed6d02159c149d4d4ad3b {
	meta:
		aliases = "wcpcpy"
		size = "24"
		objfiles = "wcpcpys@libc.a"
	strings:
		$pattern = { 04 30 91 E4 00 00 53 E3 04 30 80 E4 FB FF FF 1A 04 00 40 E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule _dl_do_lazy_reloc_c2bd0b3c9cf45f87c389233c3cf3b976 {
	meta:
		aliases = "_dl_do_lazy_reloc"
		size = "56"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { 04 30 D2 E5 00 00 53 E3 00 00 90 E5 00 20 92 E5 03 10 A0 01 05 00 00 0A 16 00 53 E3 00 30 92 07 00 10 E0 13 00 30 83 00 00 10 A0 03 00 30 82 07 01 00 A0 E1 1E FF 2F E1 }
	condition:
		$pattern
}

rule __negdi2_1d5ec190e4c90d2670174192b388a23e {
	meta:
		aliases = "__negdi2"
		size = "40"
		objfiles = "_negdi2@libgcc.a"
	strings:
		$pattern = { 04 40 2D E5 00 30 A0 E1 00 20 61 E2 01 40 A0 E1 00 00 60 E2 00 00 53 E3 02 10 A0 01 01 10 42 12 10 00 BD E8 1E FF 2F E1 }
	condition:
		$pattern
}

rule __clear_cache_984740f76ea16696513918dafb877dca {
	meta:
		aliases = "__clear_cache"
		size = "28"
		objfiles = "_clear_cache@libgcc.a"
	strings:
		$pattern = { 04 70 2D E5 00 20 A0 E3 08 70 9F E5 02 00 9F EF 80 00 BD E8 1E FF 2F E1 02 00 0F 00 }
	condition:
		$pattern
}

rule __negvsi2_996dc1dce724688e84320f9aa3990e78 {
	meta:
		aliases = "__negvsi2"
		size = "56"
		objfiles = "_negvsi2@libgcc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 00 50 E3 00 00 60 E2 04 D0 4D E2 A0 3F A0 B1 02 00 00 BA 00 00 50 E3 00 30 A0 D3 01 30 A0 C3 00 00 53 E3 01 00 00 1A 04 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_endmntent_a197a528cfc7722f8df261d426a61633 {
	meta:
		aliases = "endmntent, __GI_endmntent"
		size = "32"
		objfiles = "mntents@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 00 50 E3 04 D0 4D E2 00 00 00 0A ?? ?? ?? ?? 01 00 A0 E3 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule killpg_49cdfd87a2766bd45a1ad479126d705c {
	meta:
		aliases = "killpg"
		size = "56"
		objfiles = "killpgs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 00 50 E3 04 D0 4D E2 03 00 00 BA 00 00 60 E2 04 D0 8D E2 04 E0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? 16 30 A0 E3 00 30 80 E5 00 00 E0 E3 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule stime_3d39b0768cf7b4e353b565118da59660 {
	meta:
		aliases = "stime"
		size = "76"
		objfiles = "stimes@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 00 50 E3 0C D0 4D E2 04 00 00 1A ?? ?? ?? ?? 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 06 00 00 EA 00 20 90 E5 00 30 A0 E3 03 10 A0 E1 0D 00 A0 E1 0C 00 8D E8 ?? ?? ?? ?? 00 20 A0 E1 02 00 A0 E1 0C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule utime_4153b2a7cc33007b32845b816ff706f3 {
	meta:
		aliases = "__GI_utime, utime"
		size = "64"
		objfiles = "utimes@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 00 51 E3 00 30 A0 13 14 D0 4D E2 0C 30 8D 15 04 30 8D 15 00 30 91 15 0D 20 A0 11 00 30 8D 15 04 30 91 15 01 20 A0 01 02 10 A0 E1 08 30 8D 15 ?? ?? ?? ?? 14 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __addvsi3_eafac0e957c229da9c326c0b4f3a1bad {
	meta:
		aliases = "__addvsi3"
		size = "72"
		objfiles = "_addvsi3@libgcc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 00 51 E3 04 D0 4D E2 00 10 81 E0 07 00 00 BA 00 00 51 E1 00 00 A0 A3 01 00 A0 B3 00 00 50 E3 06 00 00 1A 01 00 A0 E1 04 D0 8D E2 00 80 BD E8 00 00 51 E1 00 00 A0 D3 01 00 A0 C3 F6 FF FF EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __subvsi3_abd619d1a1c5dc866dffddf4e2f8f7bc {
	meta:
		aliases = "__subvsi3"
		size = "72"
		objfiles = "_subvsi3@libgcc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 00 51 E3 04 D0 4D E2 00 30 61 E0 07 00 00 BA 00 00 53 E1 00 00 A0 D3 01 00 A0 C3 00 00 50 E3 06 00 00 1A 03 00 A0 E1 04 D0 8D E2 00 80 BD E8 00 00 53 E1 00 00 A0 A3 01 00 A0 B3 F6 FF FF EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdrrec_endofrecord_e79878e2d81f12b0e41af4bd76cef8c7 {
	meta:
		aliases = "__GI_xdrrec_endofrecord, xdrrec_endofrecord"
		size = "140"
		objfiles = "xdr_recs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 00 51 E3 0C E0 90 E5 07 00 00 1A 1C 30 9E E5 00 00 53 E3 04 00 00 1A 10 10 9E E5 14 20 9E E5 04 30 81 E2 02 00 53 E1 05 00 00 3A 00 30 A0 E3 0E 00 A0 E1 01 10 A0 E3 1C 30 8E E5 04 E0 9D E4 CA FF FF EA 18 C0 9E E5 01 00 A0 E3 01 20 6C E0 04 20 42 E2 02 21 82 E3 FF 18 02 E2 22 3C A0 E1 21 34 83 E1 FF 1C 02 E2 01 34 83 E1 02 3C 83 E1 00 30 8C E5 10 20 9E E5 04 30 82 E2 10 30 8E E5 18 20 8E E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule sem_init_4aef9da5037081ccf74d91adec8f1731 {
	meta:
		aliases = "__new_sem_init, sem_init"
		size = "92"
		objfiles = "semaphores@libpthread.a"
	strings:
		$pattern = { 04 E0 2D E5 00 00 52 E3 04 D0 4D E2 00 30 A0 E1 03 00 00 AA ?? ?? ?? ?? 00 10 E0 E3 16 30 A0 E3 04 00 00 EA 00 00 51 E3 04 00 00 0A ?? ?? ?? ?? 00 10 E0 E3 26 30 A0 E3 00 30 80 E5 03 00 00 EA 08 20 83 E5 0C 10 83 E5 00 10 83 E5 04 10 83 E5 01 00 A0 E1 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __old_sem_init_82659cc715703873a496302083334a34 {
	meta:
		aliases = "__old_sem_init"
		size = "92"
		objfiles = "oldsemaphores@libpthread.a"
	strings:
		$pattern = { 04 E0 2D E5 00 00 52 E3 04 D0 4D E2 00 C0 A0 E1 03 00 00 AA ?? ?? ?? ?? 00 10 E0 E3 16 30 A0 E3 04 00 00 EA 00 00 51 E3 04 00 00 0A ?? ?? ?? ?? 00 10 E0 E3 26 30 A0 E3 00 30 80 E5 03 00 00 EA 82 30 A0 E1 01 30 83 E2 00 30 8C E5 04 10 8C E5 01 00 A0 E1 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_initialize_minimal_3595c82f869821b0d501d792dc484ea7 {
	meta:
		aliases = "__pthread_initialize_minimal"
		size = "48"
		objfiles = "pthreads@libpthread.a"
	strings:
		$pattern = { 04 E0 2D E5 00 00 A0 E3 04 D0 4D E2 ?? ?? ?? ?? 10 30 9F E5 10 20 9F E5 03 30 8F E0 02 00 83 E7 04 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tzset_94fbd258b0a3eadc50cd6c30f7efdf3f {
	meta:
		aliases = "__GI_tzset, tzset"
		size = "48"
		objfiles = "tzsets@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 00 A0 E3 04 D0 4D E2 ?? ?? ?? ?? 14 30 9F E5 03 00 50 E1 00 00 A0 C3 01 00 A0 D3 04 D0 8D E2 04 E0 9D E4 ?? ?? ?? ?? FF 4E 98 45 }
	condition:
		$pattern
}

rule sigemptyset_d90897aee907e49d8060d0d83944b567 {
	meta:
		aliases = "__GI_sigemptyset, sigemptyset"
		size = "32"
		objfiles = "sigemptys@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 10 A0 E3 04 D0 4D E2 80 20 A0 E3 ?? ?? ?? ?? 00 00 A0 E3 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule _Unwind_GetRegionStart_9f9d052aacaab3511f6cfd909d4a4cba {
	meta:
		aliases = "_Unwind_GetRegionStart"
		size = "48"
		objfiles = "pr_support@libgcc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 10 A0 E3 14 D0 4D E2 0C 20 A0 E3 01 30 A0 E1 02 C0 8D E0 00 C0 8D E5 ?? ?? ?? ?? 0C 30 9D E5 48 00 93 E5 14 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule _Unwind_GetLanguageSpecificDat_dfdb937f715a5568205867d453f67ed1 {
	meta:
		aliases = "_Unwind_GetLanguageSpecificData"
		size = "64"
		objfiles = "pr_support@libgcc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 10 A0 E3 14 D0 4D E2 0C 20 A0 E3 02 C0 8D E0 01 30 A0 E1 00 C0 8D E5 ?? ?? ?? ?? 0C 20 9D E5 4C 30 92 E5 07 00 D3 E5 08 30 83 E2 00 01 A0 E1 00 00 83 E0 14 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule xdr_float_6317d6dd7c19aa1598bfcf4b7fb85a99 {
	meta:
		aliases = "xdr_float"
		size = "76"
		objfiles = "xdr_floats@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 20 90 E5 04 D0 4D E2 01 00 52 E3 08 00 00 0A 03 00 00 3A 02 00 52 E3 00 00 A0 13 01 00 A0 03 06 00 00 EA 04 30 90 E5 0F E0 A0 E1 04 F0 93 E5 02 00 00 EA 04 30 90 E5 0F E0 A0 E1 00 F0 93 E5 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule xdr_int32_t_d43ccafbae6e319aa042d769ee6320c6 {
	meta:
		aliases = "xdr_uint32_t, xdr_int32_t"
		size = "76"
		objfiles = "xdr_intXX_ts@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 20 90 E5 04 D0 4D E2 01 00 52 E3 08 00 00 0A 03 00 00 3A 02 00 52 E3 00 00 A0 13 01 00 A0 03 06 00 00 EA 04 30 90 E5 0F E0 A0 E1 24 F0 93 E5 02 00 00 EA 04 30 90 E5 0F E0 A0 E1 20 F0 93 E5 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule cfmakeraw_7389be8de53e2ae78c780d7d724dfa1e {
	meta:
		aliases = "cfmakeraw"
		size = "80"
		objfiles = "cfmakeraws@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 20 90 E5 0C 10 90 E5 08 C0 90 E5 04 E0 90 E5 00 30 A0 E3 5E 2E C2 E3 02 19 C1 E3 13 CE CC E3 0B 20 C2 E3 01 E0 CE E3 4B 10 C1 E3 30 C0 8C E3 16 30 C0 E5 01 30 83 E2 04 40 80 E8 0C 10 80 E5 08 C0 80 E5 17 30 C0 E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule putpwent_7f6ec0d4c0b6b63b751c85197fb8e9a0 {
	meta:
		aliases = "putpwent"
		size = "144"
		objfiles = "putpwents@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 20 A0 E1 78 C0 9F E5 00 00 51 E3 00 00 52 13 1C D0 4D E2 01 00 A0 E1 0C C0 8F E0 04 00 00 1A ?? ?? ?? ?? 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 10 00 00 EA 08 30 92 E5 48 10 9F E5 00 30 8D E5 0C 30 92 E5 01 10 8C E0 04 30 8D E5 10 30 92 E5 08 30 8D E5 14 30 92 E5 0C 30 8D E5 18 30 92 E5 10 30 8D E5 0C 00 92 E8 ?? ?? ?? ?? 00 00 50 E3 00 20 E0 B3 00 20 A0 A3 02 00 A0 E1 1C D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svc_getreq_29da16934d329db79c7238b6dc38d972 {
	meta:
		aliases = "__GI_svc_getreq, svc_getreq"
		size = "64"
		objfiles = "svcs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 20 A0 E3 00 10 A0 E1 84 D0 4D E2 02 00 A0 E1 80 C0 8D E2 02 31 8C E0 01 20 82 E2 1F 00 52 E3 80 00 03 E5 F9 FF FF 9A 0D 00 A0 E1 00 10 8D E5 ?? ?? ?? ?? 84 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule xdr_wrapstring_8f0c2b63cef0c2203cb35d096ba2bba2 {
	meta:
		aliases = "xdr_wrapstring"
		size = "32"
		objfiles = "xdrs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 20 E0 E3 04 D0 4D E2 ?? ?? ?? ?? 00 00 50 E2 01 00 A0 13 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule sigdelset_27cd0cce02c093edda70078d789b754d {
	meta:
		aliases = "sigaddset, __GI_sigaddset, sigismember, __GI_sigdelset, sigdelset"
		size = "60"
		objfiles = "sigdelsets@libc.a, sigaddsets@libc.a, sigismems@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 30 51 E2 04 D0 4D E2 04 00 00 DA 40 00 53 E3 02 00 00 CA 04 D0 8D E2 04 E0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? 16 30 A0 E3 00 30 80 E5 00 00 E0 E3 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule xdr_long_9c3fd1723a4b13f6f1028bf2958de387 {
	meta:
		aliases = "__GI_xdr_long, xdr_long"
		size = "80"
		objfiles = "xdrs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 30 90 E5 04 D0 4D E2 00 00 53 E3 03 00 00 1A 04 30 90 E5 0F E0 A0 E1 04 F0 93 E5 08 00 00 EA 01 00 53 E3 03 00 00 1A 04 30 90 E5 0F E0 A0 E1 00 F0 93 E5 02 00 00 EA 02 00 53 E3 00 00 A0 13 01 00 A0 03 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __old_sem_destroy_8624caef4bc8a46dafd8265e11f1b121 {
	meta:
		aliases = "__old_sem_destroy"
		size = "48"
		objfiles = "oldsemaphores@libpthread.a"
	strings:
		$pattern = { 04 E0 2D E5 00 30 90 E5 04 D0 4D E2 01 00 13 E3 00 00 A0 13 03 00 00 1A ?? ?? ?? ?? 10 30 A0 E3 00 30 80 E5 00 00 E0 E3 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule ualarm_9d6a3c5865a8094bd38a4ec8f3474e53 {
	meta:
		aliases = "ualarm"
		size = "80"
		objfiles = "ualarms@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 30 A0 E3 24 D0 4D E2 10 20 8D E2 04 10 8D E5 0C 00 8D E5 0D 10 A0 E1 03 00 A0 E1 00 30 8D E5 08 30 8D E5 ?? ?? ?? ?? 00 00 50 E3 18 10 9D A5 10 20 9F A5 1C 30 9D A5 00 00 E0 B3 91 32 20 A0 24 D0 8D E2 00 80 BD E8 40 42 0F 00 }
	condition:
		$pattern
}

rule __heap_alloc_at_80ae0ece11e34910d36b032157f760ec {
	meta:
		aliases = "__heap_alloc_at"
		size = "136"
		objfiles = "heap_alloc_ats@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 C0 90 E5 00 E0 A0 E1 18 00 00 EA 00 00 9C E5 03 30 60 E0 01 00 53 E1 13 00 00 8A 16 00 00 1A 03 30 82 E2 03 20 C3 E3 02 00 50 E1 12 00 00 3A 2C 30 82 E2 03 00 50 E1 00 30 62 20 00 30 8C 25 02 00 A0 21 04 F0 9D 24 04 20 9C E5 00 00 52 E3 08 30 9C 15 08 30 82 15 0C 00 9C E9 00 00 53 E3 04 20 83 15 00 20 8E 05 04 F0 9D E4 04 C0 9C E5 00 00 5C E3 0C 30 8C E2 E3 FF FF 1A 00 00 A0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule wcsstr_7aa0aab11a63b7523f19b93c15466c3d {
	meta:
		aliases = "wcswcs, wcsstr"
		size = "80"
		objfiles = "wcsstrs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 C0 A0 E1 00 20 A0 E1 01 30 A0 E1 00 E0 93 E5 04 30 83 E2 00 00 5E E3 01 00 00 1A 0C 00 A0 E1 04 F0 9D E4 00 00 92 E5 04 20 82 E2 00 00 5E E1 F5 FF FF 0A 04 C0 8C E2 00 00 50 E3 0C 20 A0 E1 01 30 A0 E1 F0 FF FF 1A 04 F0 9D E4 }
	condition:
		$pattern
}

rule __get_hosts_byname_r_c1f753d5edc51538e7d6d9d755cf9d31 {
	meta:
		aliases = "__get_hosts_byname_r"
		size = "76"
		objfiles = "get_hosts_byname_rs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 C0 A0 E1 1C D0 4D E2 01 E0 A0 E1 0C 10 A0 E1 20 C0 9D E5 00 00 A0 E3 08 C0 8D E5 24 C0 9D E5 00 20 8D E5 0C C0 8D E5 28 C0 9D E5 04 30 8D E5 0E 20 A0 E1 00 30 A0 E1 10 C0 8D E5 ?? ?? ?? ?? 1C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule wcswidth_9bf4ebb9ce1b7be56e39545301a11bac {
	meta:
		aliases = "__GI_wcswidth, wcswidth"
		size = "132"
		objfiles = "wcswidths@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 C0 A0 E3 00 E0 A0 E1 01 00 00 EA 02 00 53 E1 18 00 00 1A 01 00 5C E1 0C 00 00 2A 0C 31 9E E7 01 C0 8C E2 00 00 53 E3 7F 20 03 E2 F6 FF FF 1A 06 00 00 EA FF 00 53 E3 01 00 80 E2 0D 00 00 8A 20 00 52 E3 1F 00 53 83 0A 00 00 9A 00 00 00 EA 00 00 A0 E3 00 00 51 E3 01 10 41 E2 04 F0 9D 04 00 30 9E E5 04 E0 8E E2 00 00 53 E3 7F 20 43 E2 EF FF FF 1A 04 F0 9D E4 00 00 E0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule pread_3c60ef09cf825aeaf146f6e2fdeeed08 {
	meta:
		aliases = "__libc_pread, pread"
		size = "28"
		objfiles = "pread_writes@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 C0 A0 E3 0C D0 4D E2 00 C0 8D E5 C5 FF FF EB 0C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule mq_receive_74276016e2232383e5d673824349f07c {
	meta:
		aliases = "mq_receive"
		size = "28"
		objfiles = "mq_receives@librt.a"
	strings:
		$pattern = { 04 E0 2D E5 00 C0 A0 E3 0C D0 4D E2 00 C0 8D E5 EA FF FF EB 0C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule mq_send_3312d1327477576ad12d75bd929b8704 {
	meta:
		aliases = "mq_send"
		size = "28"
		objfiles = "mq_sends@librt.a"
	strings:
		$pattern = { 04 E0 2D E5 00 C0 A0 E3 0C D0 4D E2 00 C0 8D E5 EB FF FF EB 0C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule getopt_63349c44dc538f74a05c4602c3f0783b {
	meta:
		aliases = "getopt"
		size = "36"
		objfiles = "getopts@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 C0 A0 E3 0C D0 4D E2 0C 30 A0 E1 00 C0 8D E5 04 C0 8D E5 ?? ?? ?? ?? 0C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __length_dotted_1f555f5c294baab57d43b3166ac62a30 {
	meta:
		aliases = "__length_dotted"
		size = "68"
		objfiles = "lengthds@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 E0 50 E2 00 00 E0 03 01 20 A0 11 04 F0 9D 04 02 00 00 EA C0 00 5C E3 01 00 80 02 05 00 00 0A 02 30 DE E7 01 00 82 E2 00 00 53 E3 C0 C0 03 E2 00 20 83 E0 F6 FF FF 1A 00 00 61 E0 04 F0 9D E4 }
	condition:
		$pattern
}

rule __GI_wcsspn_c48bfa3371af6354f4bf7f9d7a82abc4 {
	meta:
		aliases = "wcsspn, __GI_wcsspn"
		size = "60"
		objfiles = "wcsspns@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 E0 A0 E1 03 00 00 EA 00 30 90 E5 03 00 5C E1 01 00 00 1A 04 00 80 E2 01 20 A0 E1 00 C0 92 E5 04 20 82 E2 00 00 5C E3 F6 FF FF 1A 00 00 6E E0 40 01 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule wcscspn_e6488574851964251b0adde6ec6c10f1 {
	meta:
		aliases = "wcscspn"
		size = "68"
		objfiles = "wcscspns@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 E0 A0 E1 06 00 00 EA 0C 00 52 E1 08 00 00 0A 00 20 93 E5 04 30 83 E2 00 00 52 E3 F9 FF FF 1A 04 00 80 E2 00 C0 90 E5 00 00 5C E3 01 30 A0 11 F6 FF FF 1A 00 00 6E E0 40 01 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule wcpncpy_98f1b757a68cbf0c0463587e0eeb5ce3 {
	meta:
		aliases = "wcpncpy"
		size = "64"
		objfiles = "wcpncpys@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 E0 A0 E1 0E C0 A0 E1 01 00 A0 E1 04 00 00 EA 00 30 90 E5 00 00 53 E3 00 30 8C E5 04 00 80 12 04 C0 8C E2 00 00 52 E3 01 20 42 E2 F7 FF FF 1A 00 00 61 E0 00 00 8E E0 04 F0 9D E4 }
	condition:
		$pattern
}

rule __GI_stpncpy_76a2ba016b6b34db1dd119263d36c626 {
	meta:
		aliases = "stpncpy, __GI_stpncpy"
		size = "64"
		objfiles = "stpncpys@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 E0 A0 E1 0E C0 A0 E1 01 00 A0 E1 04 00 00 EA 00 30 D0 E5 00 00 53 E3 00 30 CC E5 01 00 80 12 01 C0 8C E2 00 00 52 E3 01 20 42 E2 F7 FF FF 1A 00 00 61 E0 00 00 8E E0 04 F0 9D E4 }
	condition:
		$pattern
}

rule rand_r_d340b98d62e44cd05d1f0020d9a0ba06 {
	meta:
		aliases = "rand_r"
		size = "88"
		objfiles = "rand_rs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 E0 A0 E1 38 10 9F E5 38 00 9F E5 00 30 9E E5 34 C0 9F E5 90 13 23 E0 93 10 22 E0 92 10 21 E0 28 00 9F E5 23 33 A0 E1 22 28 0C E0 00 00 03 E0 02 00 20 E0 21 C8 0C E0 00 05 8C E1 00 10 8E E5 04 F0 9D E4 39 30 00 00 6D 4E C6 41 FF 03 00 00 00 FC 1F 00 }
	condition:
		$pattern
}

rule strspn_36e18e7acedf4fe07576b4ccbda0bb95 {
	meta:
		aliases = "__GI_strspn, strspn"
		size = "72"
		objfiles = "strspns@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 E0 A0 E3 08 00 00 EA 02 00 5C E1 04 00 00 0A 00 20 D3 E5 01 30 83 E2 00 00 52 E3 F9 FF FF 1A 05 00 00 EA 01 E0 8E E2 01 00 80 E2 00 C0 D0 E5 00 00 5C E3 01 30 A0 11 F4 FF FF 1A 0E 00 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule sysv_signal_dba53f0fcb55408208bce51e9c003fcc {
	meta:
		aliases = "__sysv_signal, sysv_signal"
		size = "132"
		objfiles = "sysv_signals@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 00 71 E3 00 00 50 13 47 DF 4D E2 00 30 A0 C3 01 30 A0 D3 04 00 00 DA 40 00 50 E3 03 C0 A0 D1 20 20 A0 D3 8C 10 8D D5 05 00 00 DA ?? ?? ?? ?? 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 0C 00 00 EA 88 C0 03 E5 01 20 52 E2 46 1F 8D E2 02 31 81 E0 FA FF FF 5A 0D 20 A0 E1 0E 32 A0 E3 8C 10 8D E2 10 31 8D E5 ?? ?? ?? ?? 00 00 50 E3 00 20 9D A5 00 20 E0 B3 02 00 A0 E1 47 DF 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule svcerr_noprog_7392814a5c31b77fc485705ddcfe1b96 {
	meta:
		aliases = "__GI_svcerr_noprog, svcerr_noprog"
		size = "76"
		objfiles = "svcs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 10 A0 E3 34 D0 4D E2 00 30 A0 E3 00 E0 A0 E1 08 30 8D E5 18 10 8D E5 04 10 8D E5 0C C0 8D E2 20 20 80 E2 08 30 90 E5 07 00 92 E8 07 00 8C E8 0E 00 A0 E1 0D 10 A0 E1 0F E0 A0 E1 0C F0 93 E5 34 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __GI_svcerr_progvers_954ad724bc28137ce46ac5de44d322df {
	meta:
		aliases = "svcerr_progvers, __GI_svcerr_progvers"
		size = "88"
		objfiles = "svcs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 30 A0 E3 34 D0 4D E2 04 30 8D E5 00 30 A0 E3 08 30 8D E5 02 30 83 E2 00 E0 A0 E1 18 30 8D E5 1C 10 8D E5 20 20 8D E5 0C C0 8D E2 20 00 80 E2 07 00 90 E8 08 30 9E E5 07 00 8C E8 0E 00 A0 E1 0D 10 A0 E1 0F E0 A0 E1 0C F0 93 E5 34 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule svcerr_noproc_8f8e5629f1d45a6d2799023da89b9497 {
	meta:
		aliases = "svcerr_noproc"
		size = "80"
		objfiles = "svcs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 30 A0 E3 34 D0 4D E2 04 30 8D E5 00 30 A0 E3 08 30 8D E5 03 30 83 E2 00 E0 A0 E1 18 30 8D E5 0C C0 8D E2 20 20 80 E2 08 30 90 E5 07 00 92 E8 07 00 8C E8 0E 00 A0 E1 0D 10 A0 E1 0F E0 A0 E1 0C F0 93 E5 34 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __GI_svcerr_decode_f246dd257d4a5dd5ac9a98b8b6fc5cce {
	meta:
		aliases = "svcerr_decode, __GI_svcerr_decode"
		size = "80"
		objfiles = "svcs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 30 A0 E3 34 D0 4D E2 04 30 8D E5 00 30 A0 E3 08 30 8D E5 04 30 83 E2 00 E0 A0 E1 18 30 8D E5 0C C0 8D E2 20 20 80 E2 08 30 90 E5 07 00 92 E8 07 00 8C E8 0E 00 A0 E1 0D 10 A0 E1 0F E0 A0 E1 0C F0 93 E5 34 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule svcerr_systemerr_eb5529ce7d61a5c68d5c197b48c9015e {
	meta:
		aliases = "svcerr_systemerr"
		size = "80"
		objfiles = "svcs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 30 A0 E3 34 D0 4D E2 04 30 8D E5 00 30 A0 E3 08 30 8D E5 05 30 83 E2 00 E0 A0 E1 18 30 8D E5 0C C0 8D E2 20 20 80 E2 08 30 90 E5 07 00 92 E8 07 00 8C E8 0E 00 A0 E1 0D 10 A0 E1 0F E0 A0 E1 0C F0 93 E5 34 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule svcerr_auth_8b71a50088e49b5eb9ffab5cfd04a161 {
	meta:
		aliases = "__GI_svcerr_auth, svcerr_auth"
		size = "52"
		objfiles = "svcs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 30 A0 E3 34 D0 4D E2 10 10 8D E5 0C 30 8D E5 04 30 8D E5 08 30 8D E5 08 30 90 E5 0D 10 A0 E1 0F E0 A0 E1 0C F0 93 E5 34 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule sigignore_30492e8587406dab812885f64722a131 {
	meta:
		aliases = "sigignore"
		size = "76"
		objfiles = "sigignores@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 30 A0 E3 94 D0 4D E2 20 20 A0 E3 00 10 A0 E3 04 30 8D E5 00 00 00 EA 88 10 03 E5 01 20 52 E2 90 C0 8D E2 02 31 8C E0 FA FF FF 5A 00 30 A0 E3 03 20 A0 E1 04 10 8D E2 88 30 8D E5 ?? ?? ?? ?? 94 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __GI_cfsetispeed_6ca65fa6c2264f2a0182609fb03e8a7b {
	meta:
		aliases = "cfsetispeed, __GI_cfsetispeed"
		size = "124"
		objfiles = "speeds@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 3A C1 E3 0F 30 C3 E3 00 00 53 E3 04 D0 4D E2 07 00 00 0A 01 3A 41 E2 01 30 43 E2 0E 00 53 E3 03 00 00 9A ?? ?? ?? ?? 00 10 E0 E3 16 30 A0 E3 03 00 00 EA 00 00 51 E3 00 20 90 E5 02 00 00 1A 02 31 82 E3 00 30 80 E5 07 00 00 EA 08 30 90 E5 02 21 C2 E3 01 3A C3 E3 0F 30 C3 E3 03 30 81 E1 08 30 80 E5 00 20 80 E5 00 10 A0 E3 01 00 A0 E1 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __GI_cfsetospeed_6da8e9ec39a313b18f1177b6db847d00 {
	meta:
		aliases = "cfsetospeed, __GI_cfsetospeed"
		size = "96"
		objfiles = "speeds@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 3A C1 E3 0F 30 C3 E3 00 00 53 E3 04 D0 4D E2 08 00 00 0A 01 3A 41 E2 01 30 43 E2 0E 00 53 E3 04 00 00 9A ?? ?? ?? ?? 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 05 00 00 EA 08 30 90 E5 00 20 A0 E3 01 3A C3 E3 0F 30 C3 E3 03 30 81 E1 08 30 80 E5 02 00 A0 E1 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __re_match_b9b5b7e9ae8bc4d6a050dbbd72fc9f2b {
	meta:
		aliases = "re_match, __re_match"
		size = "60"
		objfiles = "regex_olds@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 C0 A0 E1 14 D0 4D E2 00 10 A0 E3 04 30 8D E5 0C 30 A0 E1 18 C0 9D E5 02 E0 A0 E1 01 20 A0 E1 08 C0 8D E5 0C E0 8D E5 00 E0 8D E5 84 F8 FF EB 14 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule re_search_7eccca93b02bf4009ef5374d81a8a37e {
	meta:
		aliases = "__re_search, re_search"
		size = "68"
		objfiles = "regex_olds@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 C0 A0 E1 1C D0 4D E2 04 30 8D E5 0C 30 A0 E1 20 C0 9D E5 00 10 A0 E3 08 C0 8D E5 24 C0 9D E5 02 E0 A0 E1 01 20 A0 E1 0C C0 8D E5 10 E0 8D E5 00 E0 8D E5 ?? ?? ?? ?? 1C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule pwrite_746cc36840deb236ea64b050db959e9a {
	meta:
		aliases = "__libc_pwrite, pwrite"
		size = "28"
		objfiles = "pread_writes@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 C0 A0 E3 0C D0 4D E2 00 C0 8D E5 CC FF FF EB 0C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule xdr_free_6f5e859341a4c2bf961086f2e63def18 {
	meta:
		aliases = "xdr_free"
		size = "36"
		objfiles = "xdrs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 02 30 A0 E3 1C D0 4D E2 00 20 A0 E1 00 30 8D E5 0D 00 A0 E1 32 FF 2F E1 1C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule iopl_b46c3690b8548ac36754aeae6ba5b408 {
	meta:
		aliases = "iopl"
		size = "84"
		objfiles = "iopls@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 03 00 50 E3 04 D0 4D E2 04 00 00 DA ?? ?? ?? ?? 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 08 00 00 EA 00 00 50 E3 00 20 A0 01 05 00 00 0A 00 00 A0 E3 01 18 A0 E3 01 20 A0 E3 04 D0 8D E2 04 E0 9D E4 ?? ?? ?? ?? 02 00 A0 E1 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __GI_fileno_unlocked_c577e8f4045017995b691366c791cc9e {
	meta:
		aliases = "fileno_unlocked, __GI_fileno_unlocked"
		size = "44"
		objfiles = "fileno_unlockeds@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 00 90 E5 04 D0 4D E2 00 00 50 E3 03 00 00 AA ?? ?? ?? ?? 09 30 A0 E3 00 30 80 E5 00 00 E0 E3 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __rpc_thread_svc_cleanup_7643b7e03d9da63523229b69eeca0b94 {
	meta:
		aliases = "__rpc_thread_svc_cleanup"
		size = "44"
		objfiles = "svcs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 01 00 00 EA 03 00 93 E9 ?? ?? ?? ?? ?? ?? ?? ?? B8 30 90 E5 00 00 53 E3 F9 FF FF 1A 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule pthread_testcancel_c8d7899b2235243907fac18e15626280 {
	meta:
		aliases = "pthread_testcancel"
		size = "56"
		objfiles = "cancels@libpthread.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 7B FF FF EB 42 30 D0 E5 00 00 53 E3 05 00 00 0A 40 30 D0 E5 00 00 53 E3 02 00 00 1A 00 00 E0 E3 0D 10 A0 E1 ?? ?? ?? ?? 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __GI_sysconf_53121237abfa551280a9e58ea47247ad {
	meta:
		aliases = "sysconf, __GI_sysconf"
		size = "960"
		objfiles = "sysconfs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 95 00 50 E3 00 F1 8F 90 97 00 00 EA 9B 00 00 EA D8 00 00 EA 9B 00 00 EA 9C 00 00 EA 9D 00 00 EA C6 00 00 EA 9E 00 00 EA 8D 00 00 EA 8C 00 00 EA 8B 00 00 EA 8A 00 00 EA 89 00 00 EA 88 00 00 EA 87 00 00 EA 86 00 00 EA 85 00 00 EA 84 00 00 EA 83 00 00 EA 82 00 00 EA 81 00 00 EA 80 00 00 EA 7F 00 00 EA 7E 00 00 EA C2 00 00 EA C1 00 00 EA C2 00 00 EA B5 00 00 EA BE 00 00 EA 8D 00 00 EA B0 00 00 EA 88 00 00 EA B4 00 00 EA B9 00 00 EA B8 00 00 EA B7 00 00 EA AE 00 00 EA B9 00 00 EA BA 00 00 EA B7 00 00 EA 84 00 00 EA A1 00 00 EA B0 00 00 EA A9 00 00 EA B4 00 00 EA B5 00 00 EA }
	condition:
		$pattern
}

rule setusershell_bba5d40648c87b67a0112edc658dce3f {
	meta:
		aliases = "setusershell"
		size = "44"
		objfiles = "usershells@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 9D FF FF EB 10 30 9F E5 10 20 9F E5 03 30 8F E0 02 00 83 E7 04 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _Unwind_GetDataRelBase_bfd9fe9fa033bb489f6516a753ce415a {
	meta:
		aliases = "_Unwind_GetTextRelBase, _Unwind_GetDataRelBase"
		size = "12"
		objfiles = "unwind_arm@libgcc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __length_question_a2aac4796fba25a762e6b91fc8d5935d {
	meta:
		aliases = "__length_question"
		size = "28"
		objfiles = "lengthqs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 ?? ?? ?? ?? 00 00 50 E3 04 00 80 A2 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule ftell_c78c930e3e19e5fec54fd6b2a1e0dbac {
	meta:
		aliases = "__GI_ftell, ftello, ftell"
		size = "68"
		objfiles = "ftellos@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 ?? ?? ?? ?? 00 20 A0 E1 C2 3F A0 E1 00 00 52 E1 00 C0 A0 E1 01 00 00 1A 01 00 53 E1 03 00 00 0A ?? ?? ?? ?? 4B 30 A0 E3 00 30 80 E5 00 C0 E0 E3 0C 00 A0 E1 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule lroundf_22f4b4cfffab37f84900b1c551af1237 {
	meta:
		aliases = "lrintf, __GI_ctime, llroundf, ilogbf, llrintf, ctime, lroundf"
		size = "24"
		objfiles = "ilogbfs@libm.a, lrintfs@libm.a, llrintfs@libm.a, lroundfs@libm.a, ctimes@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 ?? ?? ?? ?? 04 D0 8D E2 04 E0 9D E4 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fma_23fa29e78a2ae6f3c3dc4fd20ab04fe7 {
	meta:
		aliases = "__GI_fma, fma"
		size = "32"
		objfiles = "s_fmas@libm.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 ?? ?? ?? ?? 08 20 8D E2 0C 00 92 E8 ?? ?? ?? ?? 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule get_kernel_syms_8ac920ec79b0e17db50fbc9c42f50051 {
	meta:
		aliases = "sem_unlink, create_module, sem_close, get_kernel_syms"
		size = "32"
		objfiles = "create_modules@libc.a, semaphores@libpthread.a, get_kernel_symss@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 ?? ?? ?? ?? 26 30 A0 E3 00 30 80 E5 00 00 E0 E3 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule logbf_9f485ee764a3d09c30432ab8e871f85c {
	meta:
		aliases = "tanhf, coshf, cosf, floorf, rintf, atanf, truncf, tanf, sinhf, log10f, ceilf, roundf, fabsf, expm1f, lgammaf, atanhf, asinhf, tgammaf, cbrtf, erff, log1pf, asinf, erfcf, sinf, acosf, sqrtf, logf, expf, acoshf, logbf"
		size = "28"
		objfiles = "expm1fs@libm.a, asinhfs@libm.a, sinhfs@libm.a, tanfs@libm.a, fabsfs@libm.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __errno_location_50204d57ee5ae15c476a81c89701cdaa {
	meta:
		aliases = "__errno_location"
		size = "24"
		objfiles = "errnos@libpthread.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 CE FF FF EB 44 00 90 E5 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule pthread_self_baf317dd38a15c77313d182809522071 {
	meta:
		aliases = "__GI_pthread_self, pthread_self"
		size = "24"
		objfiles = "pthreads@libpthread.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 D4 FF FF EB 10 00 90 E5 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __h_errno_location_f197420526aac55c0d91756c79db2cb8 {
	meta:
		aliases = "__h_errno_location"
		size = "24"
		objfiles = "errnos@libpthread.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 D4 FF FF EB 4C 00 90 E5 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __GI_pthread_attr_getschedpara_a6b8abd73bd696454b7c26968b9f6672 {
	meta:
		aliases = "pthread_attr_getschedparam, __GI_pthread_attr_getschedparam"
		size = "40"
		objfiles = "attrs@libpthread.a"
	strings:
		$pattern = { 04 E0 2D E5 08 30 80 E2 04 20 A0 E3 01 00 A0 E1 04 D0 4D E2 03 10 A0 E1 ?? ?? ?? ?? 00 00 A0 E3 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule _Unwind_DeleteException_865fcdabf33ee4afbb7c0c973c379169 {
	meta:
		aliases = "_Unwind_DeleteException"
		size = "40"
		objfiles = "unwind_arm@libgcc.a"
	strings:
		$pattern = { 04 E0 2D E5 08 30 90 E5 04 D0 4D E2 00 00 53 E3 02 00 00 0A 00 10 A0 E1 01 00 A0 E3 33 FF 2F E1 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __opensock_6bc903f68777f054d508ccef78c615ed {
	meta:
		aliases = "__opensock"
		size = "64"
		objfiles = "opensocks@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 0A 00 A0 E3 04 D0 4D E2 02 10 A0 E3 00 20 A0 E3 ?? ?? ?? ?? 00 00 50 E3 05 00 00 AA 02 00 A0 E3 00 10 A0 E1 00 20 A0 E3 04 D0 8D E2 04 E0 9D E4 ?? ?? ?? ?? 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule sem_destroy_00f82ca8c35b699f0c0ea237037e6187 {
	meta:
		aliases = "__new_sem_destroy, sem_destroy"
		size = "44"
		objfiles = "semaphores@libpthread.a"
	strings:
		$pattern = { 04 E0 2D E5 0C 00 90 E5 04 D0 4D E2 00 00 50 E3 03 00 00 0A ?? ?? ?? ?? 10 30 A0 E3 00 30 80 E5 00 00 E0 E3 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule setrlimit64_9c53780c508b6777ef364dfe8b5369d5 {
	meta:
		aliases = "setrlimit64"
		size = "108"
		objfiles = "setrlimit64s@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 0C 00 91 E8 00 00 53 E3 0C D0 4D E2 02 00 00 8A 04 00 00 1A 02 00 72 E3 02 00 00 9A 00 30 E0 E3 00 30 8D E5 00 00 00 EA 00 20 8D E5 08 10 81 E2 06 00 91 E8 00 00 52 E3 02 00 00 8A 04 00 00 1A 02 00 71 E3 02 00 00 9A 00 30 E0 E3 04 30 8D E5 00 00 00 EA 04 10 8D E5 0D 10 A0 E1 ?? ?? ?? ?? 0C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __GI_fseek_dd2fd8b0e075e3fd20669b87b7af36bb {
	meta:
		aliases = "fseek, fseeko, __GI_fseek"
		size = "32"
		objfiles = "fseekos@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 0C D0 4D E2 00 20 8D E5 01 20 A0 E1 C2 3F A0 E1 ?? ?? ?? ?? 0C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule wcsrtombs_f954aba344daab9be62fd450fad4692b {
	meta:
		aliases = "__GI_wcsrtombs, wcsrtombs"
		size = "32"
		objfiles = "wcsrtombss@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 0C D0 4D E2 00 30 8D E5 02 30 A0 E1 00 20 E0 E3 ?? ?? ?? ?? 0C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule getw_00db190451895f5757c4535594e66a27 {
	meta:
		aliases = "getw"
		size = "48"
		objfiles = "getws@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 0C D0 4D E2 00 30 A0 E1 04 10 A0 E3 04 00 8D E2 01 20 A0 E3 ?? ?? ?? ?? 00 00 50 E3 04 00 9D 15 00 00 E0 03 0C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule inet_addr_cce514b1fd003944bacf44cbcf169a57 {
	meta:
		aliases = "__GI_inet_addr, inet_addr"
		size = "36"
		objfiles = "inet_makeaddrs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 0C D0 4D E2 04 10 8D E2 ?? ?? ?? ?? 00 00 50 E3 04 00 9D 15 00 00 E0 03 0C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule putw_0207c5a587b7b3dc0b1a9410a0c88bf2 {
	meta:
		aliases = "putw"
		size = "48"
		objfiles = "putws@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 0C D0 4D E2 08 20 8D E2 04 00 22 E5 01 30 A0 E1 02 00 A0 E1 04 10 A0 E3 01 20 A0 E3 ?? ?? ?? ?? 01 00 40 E2 0C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule tcsetpgrp_fee1cd5bc6341c7e52f392b43654ba66 {
	meta:
		aliases = "tcsetpgrp"
		size = "36"
		objfiles = "tcsetpgrps@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 0C D0 4D E2 08 20 8D E2 04 10 22 E5 08 10 9F E5 ?? ?? ?? ?? 0C D0 8D E2 00 80 BD E8 10 54 00 00 }
	condition:
		$pattern
}

rule __GI_fputwc_unlocked_b31defe2d0168e331d09cdbc8674bc52 {
	meta:
		aliases = "putwc_unlocked, fputwc_unlocked, __GI_fputwc_unlocked"
		size = "52"
		objfiles = "fputwc_unlockeds@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 0C D0 4D E2 08 30 8D E2 04 00 23 E5 01 20 A0 E1 03 00 A0 E1 01 10 A0 E3 ?? ?? ?? ?? 00 00 50 E3 04 00 9D 15 00 00 E0 03 0C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule wcwidth_8fef14792c4e7fb6f5b0ba8e35d2c5aa {
	meta:
		aliases = "wcwidth"
		size = "36"
		objfiles = "wcwidths@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 0C D0 4D E2 08 30 8D E2 04 00 23 E5 03 00 A0 E1 01 10 A0 E3 ?? ?? ?? ?? 0C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule wcstombs_87623ef5c81d2363647db9114e34783a {
	meta:
		aliases = "wcstombs"
		size = "36"
		objfiles = "wcstombss@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 0C D0 4D E2 08 30 8D E2 04 10 23 E5 03 10 A0 E1 00 30 A0 E3 ?? ?? ?? ?? 0C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule getdtablesize_7ac7a77041c33876611cbc2d55138b56 {
	meta:
		aliases = "__GI_getdtablesize, getdtablesize"
		size = "40"
		objfiles = "getdtablesizes@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 0C D0 4D E2 0D 10 A0 E1 07 00 A0 E3 ?? ?? ?? ?? 00 00 50 E3 00 00 9D A5 01 0C A0 B3 0C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule getopt_long_9c4cd90828146108a82fa46170371e7d {
	meta:
		aliases = "getopt_long"
		size = "36"
		objfiles = "getopts@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 0C D0 4D E2 10 C0 9D E5 00 C0 8D E5 00 C0 A0 E3 04 C0 8D E5 ?? ?? ?? ?? 0C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule getopt_long_only_e519a54ac0452f426e8b916e2e361eef {
	meta:
		aliases = "getopt_long_only"
		size = "36"
		objfiles = "getopts@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 0C D0 4D E2 10 C0 9D E5 00 C0 8D E5 01 C0 A0 E3 04 C0 8D E5 ?? ?? ?? ?? 0C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __GI_tcgetpgrp_0da020dba2480b72f1992b9f7717bf80 {
	meta:
		aliases = "tcgetpgrp, __GI_tcgetpgrp"
		size = "44"
		objfiles = "tcgetpgrps@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 0C D0 4D E2 18 10 9F E5 04 20 8D E2 ?? ?? ?? ?? 00 00 50 E3 04 00 9D A5 00 00 E0 B3 0C D0 8D E2 00 80 BD E8 0F 54 00 00 }
	condition:
		$pattern
}

rule mbstowcs_f679b562d3f0517253b87cc62f790ab1 {
	meta:
		aliases = "mbstowcs"
		size = "40"
		objfiles = "mbstowcss@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 14 D0 4D E2 0C 10 8D E5 00 C0 A0 E3 0C 10 8D E2 04 30 8D E2 04 C0 8D E5 ?? ?? ?? ?? 14 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule clock_1d928d757f734c58ff79199569e74fcf {
	meta:
		aliases = "clock"
		size = "48"
		objfiles = "clocks@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 14 D0 4D E2 0D 00 A0 E1 ?? ?? ?? ?? 0C 00 9D E8 02 30 83 E0 0C 20 9F E5 93 02 00 E0 3E 01 C0 E3 14 D0 8D E2 00 80 BD E8 10 27 00 00 }
	condition:
		$pattern
}

rule rexec_5cd15b6f4de22e16b6d658d98382abac {
	meta:
		aliases = "rexec"
		size = "44"
		objfiles = "rexecs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 14 D0 4D E2 18 C0 9D E5 00 C0 8D E5 1C C0 9D E5 04 C0 8D E5 02 C0 A0 E3 08 C0 8D E5 ?? ?? ?? ?? 14 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule hsearch_71817f1ce8b1525d2adeec1fb0af8332 {
	meta:
		aliases = "hsearch"
		size = "68"
		objfiles = "hsearchs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 1C D0 4D E2 08 30 8D E2 03 00 83 E8 24 E0 9F E5 24 C0 9F E5 0E E0 8F E0 03 00 93 E8 0C C0 8E E0 14 30 8D E2 00 C0 8D E5 ?? ?? ?? ?? 14 00 9D E5 1C D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdrmem_create_ffda9605bfd005b331bb188d79887c00 {
	meta:
		aliases = "__GI_xdrmem_create, xdrmem_create"
		size = "48"
		objfiles = "xdr_mems@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 1C E0 9F E5 1C C0 9F E5 0E E0 8F E0 0C C0 8E E0 14 20 80 E5 08 10 80 E8 0C 10 80 E5 10 10 80 E5 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __ivaliduser_96b413af09c830c595e26113e68d33a6 {
	meta:
		aliases = "__ivaliduser"
		size = "48"
		objfiles = "rcmds@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 1C E0 9F E5 1C C0 9F E5 0E E0 8F E0 0C D0 4D E2 0C C0 8E E0 00 C0 8D E5 11 FF FF EB 0C D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule iruserok_6016a56188053dd0dc7bc3b74141725f {
	meta:
		aliases = "iruserok"
		size = "48"
		objfiles = "rcmds@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 1C E0 9F E5 1C C0 9F E5 0E E0 8F E0 0C D0 4D E2 0C C0 8E E0 00 C0 8D E5 95 FF FF EB 0C D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __aeabi_uwrite4_282c5e8dc202bd59e982851a3e9f2acd {
	meta:
		aliases = "__aeabi_uwrite4"
		size = "36"
		objfiles = "unaligned_funcs@libgcc.a"
	strings:
		$pattern = { 04 E0 2D E5 20 2C A0 E1 20 C4 A0 E1 20 E8 A0 E1 03 20 C1 E5 01 C0 C1 E5 02 E0 C1 E5 00 00 C1 E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule jrand48_7656ffc8e4fe08d1a0d6d660b6b075e9 {
	meta:
		aliases = "nrand48, jrand48"
		size = "52"
		objfiles = "nrand48s@libc.a, jrand48s@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 20 30 9F E5 20 10 9F E5 0C D0 4D E2 03 30 8F E0 01 10 83 E0 04 20 8D E2 ?? ?? ?? ?? 04 00 9D E5 0C D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule erand48_b82c07202a1995a195dd78816d034380 {
	meta:
		aliases = "erand48"
		size = "52"
		objfiles = "erand48s@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 20 30 9F E5 20 10 9F E5 0C D0 4D E2 03 30 8F E0 01 10 83 E0 0D 20 A0 E1 ?? ?? ?? ?? 03 00 9D E8 0C D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdrstdio_create_afc0bea1e31f880fdf717e6d620864b5 {
	meta:
		aliases = "xdrstdio_create"
		size = "52"
		objfiles = "xdr_stdios@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 20 C0 9F E5 20 30 9F E5 0C C0 8F E0 00 E0 A0 E3 03 30 8C E0 10 E0 80 E5 0C 00 80 E8 0C 10 80 E5 14 E0 80 E5 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sigandset_1bad30a9b236491c3bac55c5ba39d76a {
	meta:
		aliases = "sigandset"
		size = "48"
		objfiles = "sigandsets@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 20 C0 A0 E3 02 E0 A0 E1 03 00 00 EA 0C 31 9E E7 0C 21 91 E7 02 30 03 E0 0C 31 80 E7 01 C0 5C E2 F9 FF FF 5A 00 00 A0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule sigorset_f84a5464cf1eb3cad52dbd337f93e384 {
	meta:
		aliases = "sigorset"
		size = "48"
		objfiles = "sigorsets@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 20 C0 A0 E3 02 E0 A0 E1 03 00 00 EA 0C 31 9E E7 0C 21 91 E7 02 30 83 E1 0C 31 80 E7 01 C0 5C E2 F9 FF FF 5A 00 00 A0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule mrand48_f628cddeb448625715b9eadeb3342188 {
	meta:
		aliases = "lrand48, mrand48"
		size = "56"
		objfiles = "mrand48s@libc.a, lrand48s@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 24 30 9F E5 24 00 9F E5 03 30 8F E0 0C D0 4D E2 00 00 83 E0 00 10 A0 E1 04 20 8D E2 ?? ?? ?? ?? 04 00 9D E5 0C D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule drand48_3140490c8937bafac6b55df5f9ab00cc {
	meta:
		aliases = "drand48"
		size = "56"
		objfiles = "drand48s@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 24 30 9F E5 24 00 9F E5 03 30 8F E0 0C D0 4D E2 00 00 83 E0 00 10 A0 E1 0D 20 A0 E1 ?? ?? ?? ?? 03 00 9D E8 0C D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mbsrtowcs_2369512cb4e1a32ee450fec7fd874a19 {
	meta:
		aliases = "__GI_mbsrtowcs, mbsrtowcs"
		size = "60"
		objfiles = "mbsrtowcss@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 28 C0 9F E5 00 E0 53 E2 0C D0 4D E2 0C C0 8F E0 1C 30 9F 05 03 E0 8C 00 02 30 A0 E1 00 20 E0 E3 00 E0 8D E5 ?? ?? ?? ?? 0C D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getspent_59692cbb7b24748a72af1d7a5e94baf4 {
	meta:
		aliases = "getpwent, getgrent, getspent"
		size = "68"
		objfiles = "getpwents@libc.a, getgrents@libc.a, getspents@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 2C C0 9F E5 2C 10 9F E5 2C 00 9F E5 0C C0 8F E0 0C D0 4D E2 01 10 8C E0 00 00 8C E0 01 2C A0 E3 04 30 8D E2 ?? ?? ?? ?? 04 00 9D E5 0C D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _dl_parse_relocation_informati_c6a2acd2a0c474336864f34b2a7be7eb {
	meta:
		aliases = "_dl_parse_relocation_information"
		size = "64"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { 04 E0 2D E5 2C C0 9F E5 2C 30 9F E5 0C C0 8F E0 03 30 8C E0 0C D0 4D E2 00 00 90 E5 00 30 8D E5 02 30 A0 E1 01 20 A0 E1 1C 10 90 E5 9A FF FF EB 0C D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _dl_parse_lazy_relocation_info_aa06f484d1409be29eefd300c2fc66e7 {
	meta:
		aliases = "_dl_parse_lazy_relocation_information"
		size = "64"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { 04 E0 2D E5 2C C0 9F E5 2C 30 9F E5 0C C0 8F E0 03 30 8C E0 0C D0 4D E2 00 30 8D E5 00 00 90 E5 02 30 A0 E1 01 20 A0 E1 00 10 A0 E3 8A FF FF EB 0C D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getpwnam_0068ad859bb5016a5793f4c416fe233c {
	meta:
		aliases = "sgetspent, getspnam, getgrgid, fgetpwent, getgrnam, fgetspent, getpwuid, fgetgrent, getpwnam"
		size = "72"
		objfiles = "getpwnams@libc.a, getgrgids@libc.a, getspnams@libc.a, getpwuids@libc.a, fgetspents@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 30 E0 9F E5 30 20 9F E5 30 10 9F E5 14 D0 4D E2 0E E0 8F E0 0C C0 8D E2 02 20 8E E0 01 10 8E E0 01 3C A0 E3 00 C0 8D E5 ?? ?? ?? ?? 0C 00 9D E5 14 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule frame_dummy_9e1efbc86bfe9a1ff6298ac3414ffab4 {
	meta:
		aliases = "frame_dummy"
		size = "92"
		objfiles = "crtbegin, crtbeginT"
	strings:
		$pattern = { 04 E0 2D E5 3C 30 9F E5 04 D0 4D E2 00 00 53 E3 02 00 00 0A 30 00 9F E5 30 10 9F E5 33 FF 2F E1 2C 00 9F E5 00 30 90 E5 00 00 53 E3 03 00 00 0A 20 30 9F E5 00 00 53 E3 00 00 00 0A 33 FF 2F E1 04 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_nl_langinfo_071288a47936301c37bc96001bd210ae {
	meta:
		aliases = "nl_langinfo, __GI_nl_langinfo"
		size = "108"
		objfiles = "nl_langinfos@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 40 24 A0 E1 54 E0 9F E5 05 00 52 E3 0E E0 8F E0 0F 00 00 8A 48 30 9F E5 FF 10 00 E2 03 C0 8E E0 0C 30 82 E0 02 20 DC E7 01 30 D3 E5 01 00 82 E0 03 00 50 E1 06 00 00 2A 0C 30 80 E0 07 30 D3 E5 61 20 8C E2 02 30 83 E0 40 20 00 E2 82 00 83 E0 04 F0 9D E4 08 30 9F E5 03 00 8E E0 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_sigsetmask_de85ccbd2b4f013527d1d1ef70c6974f {
	meta:
		aliases = "sigsetmask, __GI_sigsetmask"
		size = "72"
		objfiles = "sigsetmasks@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 41 DF 4D E2 80 00 8D E5 84 10 8D E2 1E 30 A0 E3 00 20 A0 E3 01 30 53 E2 04 20 81 E4 FC FF FF 5A 80 10 8D E2 0D 20 A0 E1 02 00 A0 E3 ?? ?? ?? ?? 00 00 50 E3 00 00 9D A5 00 00 E0 B3 41 DF 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule sigblock_2c8ac0ff3ebffedc0a3d98bf6ef2d787 {
	meta:
		aliases = "__GI_sigblock, sigblock"
		size = "68"
		objfiles = "sigblocks@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 41 DF 4D E2 80 00 8D E5 84 20 8D E2 1E 30 A0 E3 00 00 A0 E3 01 30 53 E2 04 00 82 E4 FC FF FF 5A 80 10 8D E2 0D 20 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 00 9D A5 00 00 E0 B3 41 DF 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule isatty_ab024be50f95b9c2ec59e4237a98fb8d {
	meta:
		aliases = "__GI_isatty, isatty"
		size = "32"
		objfiles = "isattys@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 44 D0 4D E2 04 10 8D E2 ?? ?? ?? ?? 01 00 70 E2 00 00 A0 33 44 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __gnu_unwind_frame_f037e3ada76a0bcf12e053a6b3ee8d62 {
	meta:
		aliases = "__gnu_unwind_frame"
		size = "68"
		objfiles = "pr_support@libgcc.a"
	strings:
		$pattern = { 04 E0 2D E5 4C C0 90 E5 14 D0 4D E2 04 30 9C E5 03 20 A0 E3 03 34 A0 E1 0C 20 CD E5 04 30 8D E5 07 20 DC E5 01 00 A0 E1 08 C0 8C E2 04 10 8D E2 08 C0 8D E5 0D 20 CD E5 ?? ?? ?? ?? 14 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule dirname_7959a8650c637541bbd374abb437ec22 {
	meta:
		aliases = "dirname"
		size = "172"
		objfiles = "dirnames@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 98 E0 9F E5 00 00 50 E3 0E E0 8F E0 00 C0 A0 11 00 20 A0 11 02 00 00 1A 1D 00 00 EA 01 30 8C E2 03 C0 A0 E1 00 30 DC E5 00 00 53 E3 2F 00 53 13 0C 30 A0 01 01 00 00 0A F7 FF FF EA 01 30 83 E2 00 10 D3 E5 2F 00 51 E3 FB FF FF 0A 00 00 51 E3 0C 20 A0 11 F1 FF FF 1A 00 00 52 E1 09 00 00 1A 00 30 D0 E5 2F 00 53 E3 09 00 00 1A 01 30 D0 E5 01 20 80 E2 2F 00 53 E3 02 00 00 1A 01 30 D2 E5 00 00 53 E3 01 20 82 02 00 30 A0 E3 00 30 C2 E5 04 F0 9D E4 08 30 9F E5 03 00 8E E0 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule base_of_encoded_value_f7c1b0ae1d511eb8b39b04bfeb14c6b9 {
	meta:
		aliases = "base_of_encoded_value"
		size = "140"
		objfiles = "unwind_c@libgcc.a"
	strings:
		$pattern = { 04 E0 2D E5 FF 00 50 E3 04 D0 4D E2 0C 00 00 0A 70 00 00 E2 20 00 50 E3 17 00 00 0A 06 00 00 DA 40 00 50 E3 10 00 00 0A 50 00 50 E3 04 00 00 0A 30 00 50 E3 08 00 00 0A ?? ?? ?? ?? 00 00 50 E3 02 00 00 1A 00 00 A0 E3 04 D0 8D E2 00 80 BD E8 10 00 50 E3 FA FF FF 0A ?? ?? ?? ?? 01 00 A0 E1 04 D0 8D E2 04 E0 9D E4 ?? ?? ?? ?? 01 00 A0 E1 04 D0 8D E2 04 E0 9D E4 ?? ?? ?? ?? 01 00 A0 E1 04 D0 8D E2 04 E0 9D E4 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_sigfillset_5140c290b87dcdea71e53f870ad41e86 {
	meta:
		aliases = "sigfillset, __GI_sigfillset"
		size = "32"
		objfiles = "sigfillsets@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 FF 10 A0 E3 04 D0 4D E2 80 20 A0 E3 ?? ?? ?? ?? 00 00 A0 E3 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __GI_iswdigit_6ca6d31206258467cec0e2506a7770ba {
	meta:
		aliases = "iswdigit, svcerr_weakauth, __GI_iswdigit"
		size = "8"
		objfiles = "svcs@libc.a, iswdigits@libc.a"
	strings:
		$pattern = { 05 10 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule iswgraph_8f331adb624588eaf80e9edee9f52dba {
	meta:
		aliases = "__GI_iswgraph, iswgraph"
		size = "8"
		objfiles = "iswgraphs@libc.a"
	strings:
		$pattern = { 06 10 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_iswlower_4e56629bc630bef6afa309708f26db55 {
	meta:
		aliases = "iswlower, __GI_iswlower"
		size = "8"
		objfiles = "iswlowers@libc.a"
	strings:
		$pattern = { 07 10 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __vfork_2aa73ea851410f400b8e07dd0abe7a1d {
	meta:
		aliases = "__GI_vfork, vfork, __vfork"
		size = "64"
		objfiles = "vforks@libc.a"
	strings:
		$pattern = { 07 C0 A0 E1 BE 70 A0 E3 00 00 00 EF 0C 70 A0 E1 01 0A 70 E3 0E F0 A0 31 25 10 E0 E3 01 00 30 E1 05 00 00 1A 07 C0 A0 E1 02 70 A0 E3 00 00 00 EF 0C 70 A0 E1 01 0A 70 E3 0E F0 A0 31 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __GI_pthread_cond_destroy_908ee3401f5825a7d85ca0be0d205a94 {
	meta:
		aliases = "pthread_cond_destroy, __GI_pthread_cond_destroy"
		size = "20"
		objfiles = "condvars@libpthread.a"
	strings:
		$pattern = { 08 00 90 E5 00 00 50 E3 10 00 A0 13 00 00 A0 03 1E FF 2F E1 }
	condition:
		$pattern
}

rule sc_getc_fad66e760fcf1d11a0afea2e1fb59d86 {
	meta:
		aliases = "sc_getc"
		size = "8"
		objfiles = "vfscanfs@libc.a"
	strings:
		$pattern = { 08 00 90 E5 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule iswprint_406c53c30230e904d192d3b3ed07e2f1 {
	meta:
		aliases = "__GI_iswprint, iswprint"
		size = "8"
		objfiles = "iswprints@libc.a"
	strings:
		$pattern = { 08 10 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdr_des_block_b205f5f6e9fb3f6578207e6e2b5affcd {
	meta:
		aliases = "xdr_des_block"
		size = "8"
		objfiles = "rpc_prots@libc.a"
	strings:
		$pattern = { 08 20 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sem_getvalue_1c257d8007290718a36d1c2dc3702155 {
	meta:
		aliases = "__new_sem_getvalue, sem_getvalue"
		size = "16"
		objfiles = "semaphores@libpthread.a"
	strings:
		$pattern = { 08 30 90 E5 00 00 A0 E3 00 30 81 E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule cfgetospeed_862c50e8c84243841b8ffc95531ca400 {
	meta:
		aliases = "cfgetospeed"
		size = "20"
		objfiles = "speeds@libc.a"
	strings:
		$pattern = { 08 30 90 E5 04 00 9F E5 00 00 03 E0 1E FF 2F E1 0F 10 00 00 }
	condition:
		$pattern
}

rule __fbufsize_f891956fb198f2e67e2592faed36a293 {
	meta:
		aliases = "__fbufsize"
		size = "16"
		objfiles = "__fbufsizes@libc.a"
	strings:
		$pattern = { 08 30 90 E5 0C 00 90 E5 00 00 63 E0 1E FF 2F E1 }
	condition:
		$pattern
}

rule sigtimedwait_60f459936364523b9fff1d5c087d098e {
	meta:
		aliases = "__GI_sigtimedwait, sigtimedwait"
		size = "8"
		objfiles = "__rt_sigtimedwaits@libc.a"
	strings:
		$pattern = { 08 30 A0 E3 F1 FF FF EA }
	condition:
		$pattern
}

rule __GI__seterr_reply_b44df0d69b33725cb0aad6c55d4483ec {
	meta:
		aliases = "_seterr_reply, __GI__seterr_reply"
		size = "288"
		objfiles = "rpc_prots@libc.a"
	strings:
		$pattern = { 08 C0 90 E5 00 00 5C E3 02 00 00 0A 01 00 5C E3 2C 00 00 1A 1D 00 00 EA 18 20 90 E5 00 00 52 E3 00 C0 81 05 1E FF 2F 01 05 00 52 E3 02 F1 8F 90 11 00 00 EA 0E 00 00 EA 03 00 00 EA 04 00 00 EA 05 00 00 EA 06 00 00 EA 07 00 00 EA 08 30 A0 E3 16 00 00 EA 09 30 A0 E3 14 00 00 EA 0A 30 A0 E3 12 00 00 EA 0B 30 A0 E3 10 00 00 EA 0C 30 A0 E3 0E 00 00 EA 00 30 A0 E3 0C 00 00 EA 10 30 A0 E3 00 30 81 E5 00 30 A0 E3 04 30 81 E5 0B 00 00 EA 0C 20 90 E5 01 00 52 E3 03 00 00 0A 06 00 52 E3 00 20 81 05 0B 00 00 0A 02 00 00 EA 07 30 A0 E3 00 30 81 E5 07 00 00 EA 10 30 A0 E3 08 10 81 E8 08 20 81 E5 03 00 00 EA }
	condition:
		$pattern
}

rule mmap64_ed4cbb6737fd552d127f4fea0d950dd6 {
	meta:
		aliases = "mmap64"
		size = "84"
		objfiles = "mmap64s@libc.a"
	strings:
		$pattern = { 08 C0 9D E5 04 50 2D E5 10 50 9D E5 04 40 2D E5 0C 4A B0 E1 2C C6 A0 E1 25 46 B0 01 09 00 00 1A 08 40 9D E5 05 5A 8C E1 07 C0 A0 E1 C0 70 A0 E3 00 00 00 EF 0C 70 A0 E1 01 0A 70 E3 30 00 BD E8 0E F0 A0 31 ?? ?? ?? EA 15 00 E0 E3 30 00 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __aeabi_uldivmod_4de0691030d40d1b434c1736e6ac29d6 {
	meta:
		aliases = "__aeabi_ldivmod, __aeabi_uldivmod"
		size = "28"
		objfiles = "_aeabi_ldivmod@libgcc.a, _aeabi_uldivmod@libgcc.a"
	strings:
		$pattern = { 08 D0 4D E2 00 60 2D E9 ?? ?? ?? ?? 04 E0 9D E5 08 D0 8D E2 0C 00 BD E8 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI_strlcat_22f648db5ed56dfccaedfe9d2e8b5666 {
	meta:
		aliases = "strlcat, __GI_strlcat"
		size = "88"
		objfiles = "strlcats@libc.a"
	strings:
		$pattern = { 08 D0 4D E2 00 C0 A0 E3 02 00 5C E1 07 00 8D 22 08 00 00 2A 00 30 D0 E5 00 00 53 E3 05 00 00 0A 01 00 80 E2 01 C0 8C E2 F6 FF FF EA 01 C0 8C E2 02 00 5C E1 01 00 80 32 00 30 D1 E5 01 10 81 E2 00 00 53 E3 00 30 C0 E5 F7 FF FF 1A 0C 00 A0 E1 08 D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule inet_makeaddr_3a79643af1a5b8eb935390b94e062b5d {
	meta:
		aliases = "__GI_inet_makeaddr, inet_makeaddr"
		size = "16"
		objfiles = "inet_addrs@libc.a"
	strings:
		$pattern = { 08 D0 4D E2 04 00 9D E5 08 D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI_clntudp_create_9e6f65ca3c1b1ff27b52c56a7d3de318 {
	meta:
		aliases = "clntudp_create, __GI_clntudp_create"
		size = "68"
		objfiles = "clnt_udps@libc.a"
	strings:
		$pattern = { 08 D0 4D E2 04 E0 2D E5 14 D0 4D E2 24 E0 9D E5 28 C0 9F E5 04 E0 8D E5 20 E0 9D E5 0C C0 8D E5 00 E0 8D E5 1C 30 8D E5 08 C0 8D E5 ?? ?? ?? ?? 14 D0 8D E2 04 E0 9D E4 08 D0 8D E2 1E FF 2F E1 60 22 00 00 }
	condition:
		$pattern
}

rule clntudp_bufcreate_aed05fafc6d74a739225d157314a2bd9 {
	meta:
		aliases = "__GI_clntudp_bufcreate, clntudp_bufcreate"
		size = "656"
		objfiles = "clnt_udps@libc.a"
	strings:
		$pattern = { 08 D0 4D E2 F0 4F 2D E9 54 D0 4D E2 7C 30 8D E5 10 30 8D E5 80 30 9D E5 00 40 A0 E1 0C 00 A0 E3 0C 10 8D E5 08 20 8D E5 14 30 8D E5 84 B0 9D E5 ?? ?? ?? ?? 88 30 9D E5 00 60 A0 E1 03 30 83 E2 03 90 C3 E3 8C 30 9D E5 64 00 89 E2 03 30 83 E2 03 80 C3 E3 08 00 80 E0 ?? ?? ?? ?? 18 72 9F E5 00 00 50 E3 00 00 56 13 00 50 A0 E1 00 A0 A0 13 01 A0 A0 03 07 70 8F E0 0B 00 00 1A ?? ?? ?? ?? F8 31 9F E5 00 40 A0 E1 03 30 97 E7 F0 01 9F E5 00 10 93 E5 00 00 87 E0 ?? ?? ?? ?? 0C 30 A0 E3 08 30 84 E5 00 30 84 E5 65 00 00 EA 60 30 80 E2 08 30 83 E0 58 30 80 E5 B2 30 D4 E1 00 00 53 E3 0B 00 00 1A 04 00 A0 E1 }
	condition:
		$pattern
}

rule __aeabi_fcmpeq_bd6f3c16879cf32c44ab973db8ff5c12 {
	meta:
		aliases = "__aeabi_dcmpeq, __aeabi_fcmpeq"
		size = "20"
		objfiles = "_cmpsf2@libgcc.a, _cmpdf2@libgcc.a"
	strings:
		$pattern = { 08 E0 2D E5 ?? ?? ?? EB 01 00 A0 03 00 00 A0 13 08 F0 9D E4 }
	condition:
		$pattern
}

rule __aeabi_dcmpgt_f52cbcbfa58e06c8588cd1fb7e67afd3 {
	meta:
		aliases = "__aeabi_dcmplt, __aeabi_fcmpgt, __aeabi_fcmplt, __aeabi_dcmpgt"
		size = "20"
		objfiles = "_cmpsf2@libgcc.a, _cmpdf2@libgcc.a"
	strings:
		$pattern = { 08 E0 2D E5 ?? ?? ?? EB 01 00 A0 33 00 00 A0 23 08 F0 9D E4 }
	condition:
		$pattern
}

rule __aeabi_fcmpge_ff7f5d7fa2e5dc60f94d507ce6a3303e {
	meta:
		aliases = "__aeabi_dcmple, __aeabi_dcmpge, __aeabi_fcmple, __aeabi_fcmpge"
		size = "20"
		objfiles = "_cmpsf2@libgcc.a, _cmpdf2@libgcc.a"
	strings:
		$pattern = { 08 E0 2D E5 ?? ?? ?? EB 01 00 A0 93 00 00 A0 83 08 F0 9D E4 }
	condition:
		$pattern
}

rule iswpunct_36840f7c1b38b2d05a8c16cb630d5496 {
	meta:
		aliases = "__GI_iswpunct, iswpunct"
		size = "8"
		objfiles = "iswpuncts@libc.a"
	strings:
		$pattern = { 09 10 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule iswspace_117d41feceaea8ddcd349334edfc6337 {
	meta:
		aliases = "__GI_iswspace, iswspace"
		size = "8"
		objfiles = "iswspaces@libc.a"
	strings:
		$pattern = { 0A 10 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __encode_header_9d26c74a0cc8da6628a4b988a4e406b5 {
	meta:
		aliases = "__encode_header"
		size = "236"
		objfiles = "encodehs@libc.a"
	strings:
		$pattern = { 0B 00 52 E3 10 40 2D E9 00 C0 A0 E1 01 E0 A0 E1 00 40 E0 D3 32 00 00 DA 01 30 D0 E5 0C 40 A0 E3 00 30 C1 E5 00 30 90 E5 01 30 C1 E5 08 20 90 E5 14 30 90 E5 04 00 90 E5 0C 10 9C E5 00 30 53 E2 01 30 A0 13 0F 20 02 E2 00 00 50 E3 82 31 83 E1 10 20 9C E5 80 00 A0 13 00 00 A0 03 00 00 51 E3 04 10 A0 13 00 10 A0 03 00 30 83 E1 00 00 52 E3 02 20 A0 13 00 20 A0 03 01 30 83 E1 02 30 83 E1 02 30 CE E5 18 20 9C E5 1C 30 9C E5 00 00 52 E3 0F 30 03 E2 80 20 A0 13 00 20 A0 03 03 20 82 E1 03 20 CE E5 21 30 DC E5 04 30 CE E5 20 30 9C E5 05 30 CE E5 25 30 DC E5 06 30 CE E5 24 30 9C E5 07 30 CE E5 29 30 DC E5 }
	condition:
		$pattern
}

rule __GI_iswupper_e56478209d9198c6aba15b9f593bce97 {
	meta:
		aliases = "iswupper, __GI_iswupper"
		size = "8"
		objfiles = "iswuppers@libc.a"
	strings:
		$pattern = { 0B 10 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_snprintf_570c035b4d37752c3bacb69841d6553c {
	meta:
		aliases = "snprintf, swprintf, __GI_snprintf"
		size = "48"
		objfiles = "snprintfs@libc.a, swprintfs@libc.a"
	strings:
		$pattern = { 0C 00 2D E9 04 E0 2D E5 0C D0 4D E2 14 C0 8D E2 0C 30 A0 E1 10 20 9D E5 04 C0 8D E5 ?? ?? ?? ?? 0C D0 8D E2 04 E0 9D E4 08 D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule semctl_19980eabf98010ab6297fe8faeac6ed7 {
	meta:
		aliases = "semctl"
		size = "88"
		objfiles = "semctls@libc.a"
	strings:
		$pattern = { 0C 00 2D E9 80 40 2D E9 08 D0 4D E2 10 20 9D E5 18 30 8D E2 04 30 8D E5 01 2C 82 E3 14 30 9D E5 4B 7F A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 08 D0 8D E2 80 40 BD E8 08 D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule error_998196680360af3b36a3061e522ae460 {
	meta:
		aliases = "__error, error"
		size = "324"
		objfiles = "errors@libc.a"
	strings:
		$pattern = { 0C 00 2D E9 F0 40 2D E9 14 51 9F E5 14 31 9F E5 05 50 8F E0 03 30 95 E7 0C D0 4D E2 00 70 A0 E1 00 00 93 E5 01 40 A0 E1 ?? ?? ?? ?? F8 30 9F E5 03 30 95 E7 00 30 93 E5 00 00 53 E3 01 00 00 0A 33 FF 2F E1 07 00 00 EA E0 30 9F E5 E0 10 9F E5 03 30 95 E7 01 10 85 E0 00 00 93 E5 D4 30 9F E5 03 20 95 E7 ?? ?? ?? ?? C0 30 9F E5 24 C0 8D E2 03 60 95 E7 0C 20 A0 E1 20 10 9D E5 00 00 96 E5 04 C0 8D E5 ?? ?? ?? ?? AC 30 9F E5 00 00 54 E3 03 20 95 E7 00 30 92 E5 01 30 83 E2 00 30 82 E5 07 00 00 0A 04 00 A0 E1 00 40 96 E5 ?? ?? ?? ?? 88 10 9F E5 00 20 A0 E1 01 10 85 E0 04 00 A0 E1 ?? ?? ?? ?? 00 10 96 E5 }
	condition:
		$pattern
}

rule hasmntopt_9e35c7e2abc6fd0b5f6da0849e917113 {
	meta:
		aliases = "hasmntopt"
		size = "8"
		objfiles = "mntents@libc.a"
	strings:
		$pattern = { 0C 00 90 E5 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule remque_2547e7c7eec500806885bfdf03584870 {
	meta:
		aliases = "remque"
		size = "24"
		objfiles = "remques@libc.a"
	strings:
		$pattern = { 0C 00 90 E8 00 00 52 E3 04 30 82 15 00 00 53 E3 00 20 83 15 1E FF 2F E1 }
	condition:
		$pattern
}

rule __gnu_Unwind_ForcedUnwind_4e7da855e49c43ed9eba98789528cee3 {
	meta:
		aliases = "__gnu_Unwind_ForcedUnwind"
		size = "28"
		objfiles = "unwind_arm@libgcc.a"
	strings:
		$pattern = { 0C 10 80 E5 18 20 80 E5 3C 20 93 E5 03 10 A0 E1 40 20 83 E5 00 20 A0 E3 A7 FF FF EA }
	condition:
		$pattern
}

rule iswxdigit_384981fd20efe21248e7a4e32e3d8b10 {
	meta:
		aliases = "__GI_iswxdigit, iswxdigit"
		size = "8"
		objfiles = "iswxdigits@libc.a"
	strings:
		$pattern = { 0C 10 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __gnu_Unwind_Resume_or_Rethrow_ec5fac3b5b2c74684dc26c0334ec8ece {
	meta:
		aliases = "__gnu_Unwind_Resume_or_Rethrow"
		size = "32"
		objfiles = "unwind_arm@libgcc.a"
	strings:
		$pattern = { 0C 30 90 E5 00 00 53 E3 00 00 00 1A ?? ?? ?? ?? 3C 30 91 E5 00 20 A0 E3 40 30 81 E5 41 FF FF EA }
	condition:
		$pattern
}

rule __GI_pthread_attr_getinheritsc_130c69d59b5da6f2e85a523b52795090 {
	meta:
		aliases = "pthread_attr_getinheritsched, __GI_pthread_attr_getinheritsched"
		size = "16"
		objfiles = "attrs@libpthread.a"
	strings:
		$pattern = { 0C 30 90 E5 00 00 A0 E3 00 30 81 E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule pthread_mutex_destroy_792f32af45825983470d2652e0be805b {
	meta:
		aliases = "__pthread_mutex_destroy, pthread_mutex_destroy"
		size = "84"
		objfiles = "mutexs@libpthread.a"
	strings:
		$pattern = { 0C 30 90 E5 03 00 53 E3 03 F1 8F 90 03 00 00 EA 04 00 00 EA 03 00 00 EA 06 00 00 EA 05 00 00 EA 16 00 A0 E3 1E FF 2F E1 10 30 90 E5 01 00 13 E3 03 00 00 1A 04 00 00 EA 10 30 90 E5 00 00 53 E3 01 00 00 0A 10 00 A0 E3 1E FF 2F E1 00 00 A0 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule random_r_83c815eca7ef10e693bb8ba60545fc85 {
	meta:
		aliases = "__GI_random_r, random_r"
		size = "140"
		objfiles = "random_rs@libc.a"
	strings:
		$pattern = { 0C 30 90 E5 30 40 2D E9 00 00 53 E3 00 C0 A0 E1 01 50 A0 E1 08 E0 90 E5 08 00 00 1A 00 20 9E E5 60 30 9F E5 92 03 03 E0 03 3A 83 E2 39 30 83 E2 02 31 C3 E3 00 30 8E E5 00 30 81 E5 0F 00 00 EA 00 20 90 E5 04 10 90 E5 00 00 92 E5 04 30 91 E4 18 40 9C E5 00 30 83 E0 04 30 82 E4 04 00 52 E1 A3 30 A0 E1 00 30 85 E5 0E 20 A0 21 01 00 00 2A 04 00 51 E1 0E 10 A0 21 04 10 8C E5 00 20 8C E5 00 00 A0 E3 30 80 BD E8 6D 4E C6 41 }
	condition:
		$pattern
}

rule __GI___h_errno_location_3e2dda803357704f489feb552671b3fe {
	meta:
		aliases = "__h_errno_location, __GI___errno_location, __errno_location, __libc_pthread_init, __GI___h_errno_location"
		size = "28"
		objfiles = "__errno_locations@libc.a, libc_pthread_inits@libc.a, __h_errno_locations@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 0C 00 9F E5 03 30 8F E0 00 00 83 E0 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_once_fork_parent_28bbae1cd081ef1d23e37cf50ac009eb {
	meta:
		aliases = "getlogin, hdestroy, __GI_getlogin, __pthread_once_fork_prepare, __pthread_once_fork_parent"
		size = "28"
		objfiles = "hsearchs@libc.a, mutexs@libpthread.a, getlogins@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 0C 00 9F E5 03 30 8F E0 00 00 83 E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule hcreate_a78a57c6f832433eca2c6b30cd7c1b24 {
	meta:
		aliases = "ether_ntoa, __GI_asctime, inet_ntoa, asctime, srand48, __GI_inet_ntoa, ether_aton, hcreate"
		size = "28"
		objfiles = "asctimes@libc.a, srand48s@libc.a, hsearchs@libc.a, ether_addrs@libc.a, inet_ntoas@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 0C 10 9F E5 03 30 8F E0 01 10 83 E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __libc_current_sigrtmax_85e650ffb17b03629851bbf5dbbf199f {
	meta:
		aliases = "__pthread_getconcurrency, pthread_getconcurrency, __libc_current_sigrtmin, __libc_current_sigrtmax"
		size = "28"
		objfiles = "pthreads@libpthread.a, allocrtsigs@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 0C 20 9F E5 03 30 8F E0 02 00 93 E7 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _flushlbf_4713760b2a08c5fab956dc75ade1e13e {
	meta:
		aliases = "_flushlbf"
		size = "28"
		objfiles = "_flushlbfs@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 0C 20 9F E5 03 30 8F E0 02 00 93 E7 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __ieee754_lgamma_d921c01341529dad451f1d9567c16244 {
	meta:
		aliases = "__GI_lgamma, lgamma, __ieee754_gamma, strtok, gamma, __GI_strtok, __ieee754_lgamma"
		size = "28"
		objfiles = "w_lgammas@libm.a, e_lgammas@libm.a, w_gammas@libm.a, e_gammas@libm.a, strtoks@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 0C 20 9F E5 03 30 8F E0 02 20 83 E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule setstate_r_28cb13d3810c120dc513bf18646f98a9 {
	meta:
		aliases = "__GI_setstate_r, setstate_r"
		size = "216"
		objfiles = "random_rs@libc.a"
	strings:
		$pattern = { 0C C0 91 E5 F0 40 2D E9 00 00 5C E3 01 40 A0 E1 04 30 94 15 08 10 91 E5 05 20 A0 13 03 30 61 10 43 31 A0 11 92 C3 23 10 04 C0 01 05 04 30 01 15 04 60 80 E2 04 D0 4D E2 04 00 16 E5 05 10 A0 E3 ?? ?? ?? ?? 84 50 9F E5 04 00 51 E3 05 50 8F E0 18 00 00 8A 78 30 9F E5 00 00 51 E3 03 30 85 E0 01 21 83 E0 14 50 92 E5 01 71 93 E7 10 50 84 E5 14 70 84 E5 0C 10 84 E5 09 00 00 0A 05 10 A0 E3 04 00 16 E5 ?? ?? ?? ?? 00 31 86 E0 04 30 84 E5 00 00 87 E0 05 10 A0 E1 ?? ?? ?? ?? 01 11 86 E0 00 10 84 E5 05 31 86 E0 00 00 A0 E3 18 30 84 E5 08 60 84 E5 03 00 00 EA ?? ?? ?? ?? 16 30 A0 E3 00 30 80 E5 00 00 E0 E3 }
	condition:
		$pattern
}

rule pthread_exit_1726dddee54b136555266b763fff55c4 {
	meta:
		aliases = "__GI_pthread_exit, pthread_exit"
		size = "8"
		objfiles = "joins@libpthread.a"
	strings:
		$pattern = { 0D 10 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule execlp_eeeded56a7a1073cedd094041ffcce26 {
	meta:
		aliases = "__GI_execlp, execlp"
		size = "140"
		objfiles = "execlps@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 0E 00 2D E9 00 D8 2D E9 10 B0 4C E2 0C D0 4D E2 08 30 8B E2 00 E0 A0 E3 14 30 0B E5 14 30 1B E5 01 E0 8E E2 00 20 93 E5 04 30 83 E2 00 00 52 E3 14 30 0B E5 F8 FF FF 1A 0E 31 A0 E1 12 30 83 E2 07 30 C3 E3 0D D0 63 E0 04 30 9B E5 0D 10 A0 E1 00 30 8D E5 08 30 8B E2 14 30 0B E5 0D C0 A0 E1 14 30 1B E5 01 E0 5E E2 00 20 93 E5 04 30 83 E2 14 30 0B E5 04 20 AC E5 F8 FF FF 1A ?? ?? ?? ?? 0C D0 4B E2 00 A8 9D E8 }
	condition:
		$pattern
}

rule __GI_execle_983e083c96dea365265de4b3e6e488bc {
	meta:
		aliases = "execle, __GI_execle"
		size = "148"
		objfiles = "execles@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 0E 00 2D E9 10 D8 2D E9 10 B0 4C E2 08 D0 4D E2 08 30 8B E2 00 E0 A0 E3 14 30 0B E5 14 10 1B E5 01 E0 8E E2 00 30 91 E5 04 20 81 E2 00 00 53 E3 14 20 0B E5 F8 FF FF 1A 0E 31 A0 E1 12 30 83 E2 07 30 C3 E3 0D D0 63 E0 04 30 9B E5 04 40 91 E5 00 30 8D E5 08 30 8B E2 0D 10 A0 E1 14 30 0B E5 0D C0 A0 E1 14 30 1B E5 01 E0 5E E2 00 20 93 E5 04 30 83 E2 14 30 0B E5 04 20 AC E5 F8 FF FF 1A 04 20 A0 E1 ?? ?? ?? ?? 10 D0 4B E2 10 A8 9D E8 }
	condition:
		$pattern
}

rule execl_e66ae442b486b133bf5980c1ef0f314e {
	meta:
		aliases = "__GI_execl, execl"
		size = "168"
		objfiles = "execls@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 0E 00 2D E9 10 D8 2D E9 10 B0 4C E2 88 40 9F E5 08 D0 4D E2 08 30 8B E2 00 E0 A0 E3 14 30 0B E5 04 40 8F E0 14 30 1B E5 01 E0 8E E2 00 20 93 E5 04 30 83 E2 00 00 52 E3 14 30 0B E5 F8 FF FF 1A 0E 31 A0 E1 12 30 83 E2 07 30 C3 E3 0D D0 63 E0 04 30 9B E5 0D 10 A0 E1 00 30 8D E5 08 30 8B E2 14 30 0B E5 0D C0 A0 E1 14 30 1B E5 01 E0 5E E2 00 20 93 E5 04 30 83 E2 14 30 0B E5 04 20 AC E5 F8 FF FF 1A 14 30 9F E5 03 30 94 E7 00 20 93 E5 ?? ?? ?? ?? 10 D0 4B E2 10 A8 9D E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule syscall_2ea454931619be772daa71d35c663213 {
	meta:
		aliases = "syscall"
		size = "48"
		objfiles = "syscall_eabis@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 00 2D E9 00 70 A0 E1 01 00 A0 E1 02 10 A0 E1 03 20 A0 E1 78 00 9C E8 00 00 00 EF F0 00 BD E8 01 0A 70 E3 0E F0 A0 31 ?? ?? ?? EA }
	condition:
		$pattern
}

rule nanf_165f571641dea9a26c770ade43fb819a {
	meta:
		aliases = "__GI_nanf, nanf"
		size = "120"
		objfiles = "nans@libm.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 D8 2D E9 00 30 D0 E5 58 60 9F E5 00 00 53 E3 00 70 A0 E1 06 60 8F E0 04 B0 4C E2 48 00 9F 05 0E 00 00 0A ?? ?? ?? ?? 14 00 80 E2 07 00 C0 E3 38 10 9F E5 0D 50 A0 E1 0D D0 60 E0 01 10 86 E0 07 20 A0 E1 0D 00 A0 E1 ?? ?? ?? ?? 0D 00 A0 E1 00 10 A0 E3 ?? ?? ?? ?? 0D 40 A0 E1 05 D0 A0 E1 1C D0 4B E2 F0 A8 9D E8 ?? ?? ?? ?? 00 00 C0 7F ?? ?? ?? ?? }
	condition:
		$pattern
}

rule nan_bce4689b9068e6fa653328b4fafa493a {
	meta:
		aliases = "__GI_nan, nan"
		size = "124"
		objfiles = "nans@libm.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 D8 2D E9 00 30 D0 E5 5C 60 9F E5 00 00 53 E3 00 70 A0 E1 06 60 8F E0 04 B0 4C E2 00 00 A0 03 48 10 9F 05 0E 00 00 0A ?? ?? ?? ?? 14 00 80 E2 07 00 C0 E3 38 10 9F E5 0D 50 A0 E1 0D D0 60 E0 01 10 86 E0 07 20 A0 E1 0D 00 A0 E1 ?? ?? ?? ?? 0D 00 A0 E1 00 10 A0 E3 ?? ?? ?? ?? 0D 40 A0 E1 05 D0 A0 E1 1C D0 4B E2 F0 A8 9D E8 ?? ?? ?? ?? 00 00 F8 7F ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_glob_40ac5acfd9fd4cd8a88e4694a2bcd0de {
	meta:
		aliases = "glob, __GI_glob"
		size = "1384"
		objfiles = "globs@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 03 50 A0 E1 40 35 9F E5 04 B0 4C E2 43 DF 4D E2 03 30 8F E0 00 00 55 E3 00 00 50 13 01 A0 A0 E1 18 31 0B E5 14 21 0B E5 00 90 A0 E1 03 00 00 0A 7E 7C C1 E3 FF 70 C7 E3 00 00 57 E3 04 00 00 0A ?? ?? ?? ?? 16 30 A0 E3 00 10 E0 E3 00 30 80 E5 3A 01 00 EA 08 20 11 E2 08 20 85 05 10 21 0B E5 2F 10 A0 E3 ?? ?? ?? ?? 00 60 50 E2 0A 00 00 1A 05 0A 1A E3 30 00 00 0A 00 30 D9 E5 7E 00 53 E3 2D 00 00 1A 09 00 A0 E1 ?? ?? ?? ?? 09 40 A0 E1 00 80 A0 E1 0C 61 0B E5 2C 00 00 EA 09 00 56 E1 06 00 00 1A 01 30 89 E2 0C 31 0B E5 18 21 1B E5 98 34 9F E5 01 80 A0 E3 03 40 82 E0 23 00 00 EA }
	condition:
		$pattern
}

rule glob64_99a02e11ac7905c1ffd4ae0d02d5bce9 {
	meta:
		aliases = "__GI_glob64, glob64"
		size = "1384"
		objfiles = "glob64s@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 03 50 A0 E1 40 35 9F E5 04 B0 4C E2 4B DF 4D E2 03 30 8F E0 00 00 55 E3 00 00 50 13 01 A0 A0 E1 38 31 0B E5 34 21 0B E5 00 90 A0 E1 03 00 00 0A 7E 7C C1 E3 FF 70 C7 E3 00 00 57 E3 04 00 00 0A ?? ?? ?? ?? 16 30 A0 E3 00 10 E0 E3 00 30 80 E5 3A 01 00 EA 08 20 11 E2 08 20 85 05 30 21 0B E5 2F 10 A0 E3 ?? ?? ?? ?? 00 60 50 E2 0A 00 00 1A 05 0A 1A E3 30 00 00 0A 00 30 D9 E5 7E 00 53 E3 2D 00 00 1A 09 00 A0 E1 ?? ?? ?? ?? 09 40 A0 E1 00 80 A0 E1 2C 61 0B E5 2C 00 00 EA 09 00 56 E1 06 00 00 1A 01 30 89 E2 2C 31 0B E5 38 21 1B E5 98 34 9F E5 01 80 A0 E3 03 40 82 E0 23 00 00 EA }
	condition:
		$pattern
}

rule _init_1b12b5978c44c8d8d2da164f12ca0466 {
	meta:
		aliases = "_fini, _init"
		size = "12"
		objfiles = "crti"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 }
	condition:
		$pattern
}

rule __GI_if_nameindex_9859d7e83e8efbb24234523024856c69 {
	meta:
		aliases = "if_nameindex, __GI_if_nameindex"
		size = "408"
		objfiles = "if_indexs@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 0C D0 4D E2 ?? ?? ?? ?? 00 70 50 E2 15 00 00 BA 00 30 A0 E3 30 30 0B E5 80 50 A0 E3 34 60 4B E2 85 40 A0 E1 0E 30 84 E2 07 30 C3 E3 0D D0 63 E0 30 30 1B E5 04 C0 8D E0 03 00 5C E1 05 40 84 00 07 00 A0 E1 38 11 9F E5 06 20 A0 E1 30 D0 0B E5 34 40 0B E5 ?? ?? ?? ?? 00 00 50 E3 03 00 00 AA 07 00 A0 E1 ?? ?? ?? ?? 00 A0 A0 E3 41 00 00 EA 34 00 1B E5 04 00 50 E1 00 50 A0 E1 E7 FF FF 0A A0 92 A0 E1 01 00 89 E2 80 01 A0 E1 ?? ?? ?? ?? 00 A0 50 E2 00 60 A0 13 2D 00 00 1A 07 00 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? 69 30 A0 E3 00 30 80 E5 30 00 00 EA 30 30 1B E5 86 42 83 E0 }
	condition:
		$pattern
}

rule __GI_execvp_885b8c97532cab46db0ed906df978f86 {
	meta:
		aliases = "execvp, __GI_execvp"
		size = "552"
		objfiles = "execvps@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 14 D0 4D E2 00 30 D0 E5 F4 21 9F E5 00 00 53 E3 02 20 8F E0 34 20 0B E5 00 50 A0 E1 01 90 A0 E1 02 00 00 1A ?? ?? ?? ?? 02 30 A0 E3 39 00 00 EA 2F 10 A0 E3 ?? ?? ?? ?? 00 00 50 E3 22 00 00 0A 34 20 1B E5 BC 31 9F E5 09 10 A0 E1 03 30 92 E7 05 00 A0 E1 00 20 93 E5 ?? ?? ?? ?? ?? ?? ?? ?? 00 30 90 E5 08 00 53 E3 62 00 00 1A 00 10 A0 E3 01 21 A0 E1 02 30 99 E7 01 10 81 E2 00 00 53 E3 FA FF FF 1A 16 30 82 E2 07 30 C3 E3 0D D0 63 E0 04 30 99 E4 08 00 8D E2 09 10 A0 E1 28 00 8D E8 ?? ?? ?? ?? 34 10 1B E5 58 31 9F E5 58 01 9F E5 03 30 91 E7 00 00 81 E0 00 20 93 E5 }
	condition:
		$pattern
}

rule ruserok_5ed26f3dd7c85ffff64b980d68f312da {
	meta:
		aliases = "ruserok"
		size = "244"
		objfiles = "rcmds@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 34 D0 4D E2 01 DB 4D E2 08 D0 4D E2 02 80 A0 E1 03 70 A0 E1 00 50 A0 E1 4C 30 4B E2 01 A0 A0 E1 08 20 8D E2 01 4B A0 E3 30 90 4B E2 38 60 4B E2 50 30 0B E5 0A 00 00 EA 38 30 1B E5 01 00 73 E3 25 00 00 1A ?? ?? ?? ?? 00 30 90 E5 0E 20 84 E2 22 00 53 E3 20 00 00 1A 07 30 C2 E3 0D D0 63 E0 08 20 8D E2 04 30 A0 E1 50 10 1B E5 05 00 A0 E1 00 90 8D E5 04 60 8D E5 ?? ?? ?? ?? 00 00 50 E3 84 40 A0 E1 EB FF FF 1A 30 30 1B E5 00 00 53 E3 E8 FF FF 0A 10 40 93 E5 34 60 4B E2 08 00 00 EA ?? ?? ?? ?? 34 00 1B E5 0A 10 A0 E1 08 20 A0 E1 07 30 A0 E1 00 50 8D E5 5F FF FF EB }
	condition:
		$pattern
}

rule getrpcport_afce5d9e902e6aac6a079b2e7c59a691 {
	meta:
		aliases = "getrpcport"
		size = "240"
		objfiles = "getrpcports@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 44 D0 4D E2 01 DB 4D E2 08 D0 4D E2 02 80 A0 E1 03 A0 A0 E1 30 C0 4B E2 58 30 4B E2 00 60 A0 E1 01 70 A0 E1 08 20 8D E2 01 4B A0 E3 34 90 4B E2 60 30 0B E5 64 C0 0B E5 0A 00 00 EA 34 30 1B E5 01 00 73 E3 23 00 00 1A ?? ?? ?? ?? 00 30 90 E5 0E 20 84 E2 22 00 53 E3 1E 00 00 1A 07 30 C2 E3 0D D0 63 E0 08 20 8D E2 64 C0 1B E5 04 30 A0 E1 60 10 1B E5 06 00 A0 E1 00 C0 8D E5 04 90 8D E5 ?? ?? ?? ?? 00 50 50 E2 84 40 A0 E1 EA FF FF 1A 30 20 1B E5 00 00 52 E3 E7 FF FF 0A 10 30 92 E5 44 40 4B E2 00 10 93 E5 0C 20 92 E5 04 00 84 E2 ?? ?? ?? ?? 02 C0 A0 E3 04 00 A0 E1 }
	condition:
		$pattern
}

rule callrpc_a0d4ccf2d1d980aa64ce4ecd68c38b7c {
	meta:
		aliases = "callrpc"
		size = "628"
		objfiles = "clnt_simples@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 64 D0 4D E2 00 A0 A0 E1 01 70 A0 E1 02 80 A0 E1 70 30 0B E5 ?? ?? ?? ?? A4 50 90 E5 00 40 A0 E1 00 00 55 E3 07 00 00 1A 01 00 A0 E3 18 10 A0 E3 ?? ?? ?? ?? 00 00 50 E3 05 00 A0 01 87 00 00 0A 00 50 A0 E1 A4 00 84 E5 14 40 95 E5 00 00 54 E3 05 00 00 1A 01 0C A0 E3 ?? ?? ?? ?? 00 30 E0 E3 14 00 85 E5 00 40 C0 E5 04 30 85 E5 10 30 95 E5 00 00 53 E3 0A 00 00 0A 08 30 95 E5 07 00 53 E1 07 00 00 1A 0C 30 95 E5 08 00 53 E1 04 00 00 1A 14 00 95 E5 0A 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 57 00 00 0A 04 00 95 E5 00 40 A0 E3 01 00 70 E3 10 40 85 E5 02 00 00 0A ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clnt_create_3015945d757ba0dd77bfbb162d63a6e2 {
	meta:
		aliases = "clnt_create"
		size = "660"
		objfiles = "clnt_generics@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 78 C2 9F E5 01 70 A0 E1 74 12 9F E5 0C C0 8F E0 CC D0 4D E2 00 80 A0 E1 E8 30 0B E5 01 10 8C E0 03 00 A0 E1 02 60 A0 E1 ?? ?? ?? ?? 00 50 50 E2 14 00 00 1A E2 40 4B E2 6E 20 A0 E3 05 10 A0 E1 04 00 A0 E1 ?? ?? ?? ?? 01 30 A0 E3 08 10 A0 E1 02 00 84 E2 B2 3E 4B E1 ?? ?? ?? ?? 07 10 A0 E1 00 C0 E0 E3 04 00 A0 E1 06 20 A0 E1 38 30 4B E2 38 C0 0B E5 04 50 8D E5 00 50 8D E5 ?? ?? ?? ?? 00 10 A0 E1 7A 00 00 EA 01 DB 4D E2 08 D0 4D E2 74 30 4B E2 08 20 8D E2 01 4B A0 E3 30 90 4B E2 3C A0 4B E2 EC 30 0B E5 0E 00 00 EA 3C 30 1B E5 01 00 73 E3 04 00 00 1A ?? ?? ?? ?? }
	condition:
		$pattern
}

rule rcmd_1c179cffc2ac29a06a58c4ca8e8f20e3 {
	meta:
		aliases = "rcmd"
		size = "1504"
		objfiles = "rcmds@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 9C D0 4D E2 A0 20 0B E5 98 00 0B E5 9C 10 0B E5 A4 30 0B E5 ?? ?? ?? ?? 74 75 9F E5 01 DB 4D E2 08 D0 4D E2 08 20 8D E2 07 70 8F E0 01 5B A0 E3 8C A0 4B E2 38 80 4B E2 34 60 4B E2 90 00 0B E5 10 00 00 EA 34 40 1B E5 01 00 74 E3 04 00 00 1A ?? ?? ?? ?? 00 30 90 E5 0E 20 85 E2 22 00 53 E3 05 00 00 0A ?? ?? ?? ?? 00 40 80 E5 98 20 1B E5 00 00 92 E5 ?? ?? ?? ?? 41 01 00 EA 07 30 C2 E3 0D D0 63 E0 08 20 8D E2 98 C0 1B E5 05 30 A0 E1 00 00 9C E5 0A 10 A0 E1 00 80 8D E5 04 60 8D E5 ?? ?? ?? ?? 00 00 50 E3 85 50 A0 E1 E4 FF FF 1A 38 30 1B E5 00 00 53 E3 E1 FF FF 0A }
	condition:
		$pattern
}

rule __getdents64_9ce7005a18d825bb01149e63dba8d207 {
	meta:
		aliases = "__getdents64"
		size = "312"
		objfiles = "getdents64s@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 0E 30 82 E2 04 B0 4C E2 14 D0 4D E2 07 30 C3 E3 0D D0 63 E0 08 30 8D E2 01 60 A0 E1 01 50 A0 E1 30 00 0B E5 03 10 A0 E1 D9 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 04 00 00 9A ?? ?? ?? ?? 00 30 64 E2 00 40 E0 E3 00 30 80 E5 01 00 00 EA 01 00 70 E3 01 00 00 1A 04 10 A0 E1 30 00 00 EA 00 40 83 E0 03 70 A0 E1 02 A0 86 E0 00 80 E0 E3 00 90 E0 E3 34 40 0B E5 23 00 00 EA B0 31 D7 E1 07 30 83 E2 07 20 C3 E3 02 C0 85 E0 0A 00 5C E1 0C 00 00 9A 00 10 A0 E3 30 00 1B E5 08 20 A0 E1 09 30 A0 E1 00 10 8D E5 ?? ?? ?? ?? 06 00 55 E1 1A 00 00 1A ?? ?? ?? ?? 16 30 A0 E3 00 10 E0 E3 }
	condition:
		$pattern
}

rule sched_setaffinity_7c53e765a102f9d2d5dde3fb0067e0e5 {
	meta:
		aliases = "sched_setaffinity"
		size = "332"
		objfiles = "sched_setaffinitys@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 34 61 9F E5 04 B0 4C E2 04 D0 4D E2 2C 31 9F E5 06 60 8F E0 03 30 96 E7 00 90 A0 E1 00 00 53 E3 01 A0 A0 E1 02 80 A0 E1 24 00 00 1A 88 D0 4D E2 0D 50 A0 E1 80 40 A0 E3 05 00 00 EA 0D D0 61 E0 02 30 8D E0 05 00 53 E1 02 40 A0 11 02 40 84 00 0D 50 A0 E1 ?? ?? ?? ?? F2 70 A0 E3 00 00 00 EF 84 20 A0 E1 0E 30 82 E2 07 10 C3 E3 16 00 70 E3 00 30 A0 13 01 30 A0 03 01 0A 70 E3 00 30 A0 93 00 00 53 E3 00 70 A0 E1 EB FF FF 1A 01 0A 70 E3 00 30 A0 93 01 30 A0 83 00 00 50 E3 01 30 83 03 00 00 53 E3 03 00 00 0A ?? ?? ?? ?? 00 30 67 E2 00 20 E0 E3 0B 00 00 EA 80 30 9F E5 03 00 86 E7 }
	condition:
		$pattern
}

rule ruserpass_a8e569c9a850d1090de72a26569a4f1d {
	meta:
		aliases = "__GI_ruserpass, ruserpass"
		size = "928"
		objfiles = "ruserpasss@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 47 DE 4D E2 04 B0 4C E2 04 D0 4D E2 01 80 A0 E1 02 90 A0 E1 00 70 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 ?? ?? ?? ?? 3C 63 9F E5 00 00 54 E1 06 60 8F E0 C9 00 00 1A ?? ?? ?? ?? 00 40 A0 E1 ?? ?? ?? ?? 00 00 54 E1 C4 00 00 1A 1C 03 9F E5 00 00 86 E0 ?? ?? ?? ?? 00 40 50 E2 BF 00 00 0A ?? ?? ?? ?? 16 00 80 E2 07 00 C0 E3 0D D0 60 E0 04 10 A0 E1 0D 00 A0 E1 ?? ?? ?? ?? F0 12 9F E5 0D 00 A0 E1 01 10 86 E0 ?? ?? ?? ?? E4 12 9F E5 0D 00 A0 E1 01 10 86 E0 ?? ?? ?? ?? D8 32 9F E5 00 00 50 E3 0D 50 A0 E1 00 40 A0 E1 03 00 86 E7 09 00 00 1A ?? ?? ?? ?? 00 30 90 E5 02 00 53 E3 03 00 00 0A }
	condition:
		$pattern
}

rule dlopen_c60be01f7d6f08a7950f06fd317e8bf9 {
	meta:
		aliases = "dlopen"
		size = "1540"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 C0 95 9F E5 04 B0 4C E2 2C D0 4D E2 03 30 11 E2 09 90 8F E0 01 70 A0 E1 0E 60 A0 E1 00 80 A0 E1 05 00 00 1A 03 00 A0 E1 9C 35 9F E5 03 20 99 E7 09 30 A0 E3 00 30 82 E5 60 01 00 EA 8C E5 9F E5 00 50 A0 E3 0E 30 D9 E7 30 50 0B E5 05 00 53 E1 0B 00 00 1A 78 35 9F E5 03 C0 99 E7 74 35 9F E5 03 00 99 E7 70 35 9F E5 00 00 8C E5 03 10 99 E7 68 35 9F E5 03 20 99 E7 01 30 A0 E3 0E 30 C9 E7 00 20 81 E5 58 45 9F E5 00 00 58 E3 04 30 99 07 00 00 93 05 49 01 00 0A ?? ?? ?? ?? 04 30 99 E7 05 40 A0 E1 00 00 93 E5 00 20 A0 E1 0A 00 00 EA 00 C0 92 E5 14 10 9C E5 06 00 51 E1 05 00 00 2A }
	condition:
		$pattern
}

rule __GI___libc_open64_2dbe61a5707505b24593ea09e43bc6bf {
	meta:
		aliases = "__GI_open64, __libc_open64, open64, __GI___libc_open64"
		size = "56"
		objfiles = "open64s@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 04 E0 2D E5 08 D0 4D E2 0C 10 9D E5 40 20 11 E2 14 30 8D 12 10 20 9D 15 02 18 81 E3 04 30 8D 15 ?? ?? ?? ?? 08 D0 8D E2 04 E0 9D E4 0C D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule sscanf_62c52eee2fbe23f15fa2cbf514acdc8e {
	meta:
		aliases = "fwprintf, asprintf, __GI_asprintf, __GI_syslog, fscanf, __GI_fscanf, fwscanf, swscanf, dprintf, __GI_sscanf, __GI_fprintf, fprintf, syslog, sscanf"
		size = "48"
		objfiles = "sscanfs@libc.a, swscanfs@libc.a, dprintfs@libc.a, fwprintfs@libc.a, fwscanfs@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 04 E0 2D E5 08 D0 4D E2 10 30 8D E2 03 20 A0 E1 0C 10 9D E5 04 30 8D E5 ?? ?? ?? ?? 08 D0 8D E2 04 E0 9D E4 0C D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule sprintf_7e76ad5ac6f27d948f7d72a084d5deec {
	meta:
		aliases = "__GI_sprintf, sprintf"
		size = "52"
		objfiles = "sprintfs@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 04 E0 2D E5 08 D0 4D E2 10 C0 8D E2 0C 30 A0 E1 00 10 E0 E3 0C 20 9D E5 04 C0 8D E5 ?? ?? ?? ?? 08 D0 8D E2 04 E0 9D E4 0C D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule sem_open_6beaf84297cf8e7f963f3e119d66c027 {
	meta:
		aliases = "sem_open"
		size = "36"
		objfiles = "semaphores@libpthread.a"
	strings:
		$pattern = { 0E 00 2D E9 04 E0 2D E5 ?? ?? ?? ?? 26 30 A0 E3 00 30 80 E5 00 00 A0 E3 04 E0 9D E4 0C D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule errx_814c18ce5d627294b1bbdd2784b1acce {
	meta:
		aliases = "err, errx"
		size = "28"
		objfiles = "errs@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 0C D0 4D E2 10 30 8D E2 03 20 A0 E1 0C 10 9D E5 04 30 8D E5 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule open_ce9a746e13c437a82b866c6078d21e61 {
	meta:
		aliases = "open64, fcntl, open"
		size = "88"
		objfiles = "wrapsyscalls@libpthread.a"
	strings:
		$pattern = { 0E 00 2D E9 10 40 2D E9 0C D0 4D E2 00 40 A0 E1 04 10 8D E2 01 00 A0 E3 ?? ?? ?? ?? 1C 30 8D E2 14 10 9D E5 18 20 9D E5 04 00 A0 E1 00 30 8D E5 ?? ?? ?? ?? 00 10 A0 E3 00 40 A0 E1 04 00 9D E5 ?? ?? ?? ?? 04 00 A0 E1 0C D0 8D E2 10 40 BD E8 0C D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule mq_open_2174e21f2a78640b82ad817dc3858a3d {
	meta:
		aliases = "mq_open"
		size = "152"
		objfiles = "mq_opens@librt.a"
	strings:
		$pattern = { 0E 00 2D E9 80 40 2D E9 00 30 D0 E5 0C D0 4D E2 2F 00 53 E3 14 10 9D E5 04 00 00 0A ?? ?? ?? ?? 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 13 00 00 EA 40 20 11 E2 18 20 9D 15 1C C0 9D 15 02 C0 A0 01 20 30 8D 12 02 28 A0 E1 04 30 8D 15 22 28 A0 E1 0C 30 A0 E1 01 00 80 E2 34 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 20 A0 E1 02 00 A0 E1 0C D0 8D E2 80 40 BD E8 0C D0 8D E2 1E FF 2F E1 12 01 00 00 }
	condition:
		$pattern
}

rule open_92e4ce417be077c15e99c240d7d0c203 {
	meta:
		aliases = "__GI_open, __libc_open, __GI___libc_open, open"
		size = "96"
		objfiles = "opens@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 80 40 2D E9 0C D0 4D E2 14 10 9D E5 05 70 A0 E3 40 20 11 E2 18 20 9D 15 1C 30 8D 12 02 28 A0 E1 04 30 8D 15 22 28 A0 E1 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 0C D0 8D E2 80 40 BD E8 0C D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI___libc_fcntl_c1a0ab95e5c78a1eec989ca445be1737 {
	meta:
		aliases = "__libc_fcntl, __GI_fcntl, fcntl, __GI___libc_fcntl"
		size = "104"
		objfiles = "__syscall_fcntls@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 80 40 2D E9 0C D0 4D E2 14 10 9D E5 18 20 9D E5 0C 30 41 E2 02 00 53 E3 1C 30 8D E2 04 30 8D E5 01 00 00 8A ?? ?? ?? ?? 09 00 00 EA 37 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 0C D0 8D E2 80 40 BD E8 0C D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI_ioctl_31d7defb2e84c2d46c10f621d7ae82db {
	meta:
		aliases = "ioctl, __GI_ioctl"
		size = "84"
		objfiles = "ioctls@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 80 40 2D E9 0C D0 4D E2 1C 30 8D E2 04 30 8D E5 18 20 9D E5 14 10 9D E5 36 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 0C D0 8D E2 80 40 BD E8 0C D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI_fcntl64_aae151bded391b863e98d1e0da382f49 {
	meta:
		aliases = "fcntl64, __libc_fcntl64, __GI___libc_fcntl64, __GI_fcntl64"
		size = "84"
		objfiles = "__syscall_fcntl64s@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 80 40 2D E9 0C D0 4D E2 1C 30 8D E2 04 30 8D E5 18 20 9D E5 14 10 9D E5 DD 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 0C D0 8D E2 80 40 BD E8 0C D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule _dl_dprintf_d2782f21cf8a9afd3bfab9028465993c {
	meta:
		aliases = "_dl_dprintf"
		size = "1016"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { 0E 00 2D E9 F0 4F 2D E9 28 D0 4D E2 4C E0 9D E5 C0 63 9F E5 00 00 5E E3 06 60 8F E0 00 A0 A0 E1 E8 00 00 0A B0 33 9F E5 00 50 A0 E3 03 30 96 E7 00 40 E0 E3 00 10 93 E5 03 20 A0 E3 22 30 A0 E3 05 00 A0 E1 C0 70 A0 E3 00 00 00 EF 01 0A 70 E3 88 23 9F 85 00 30 60 82 02 20 96 87 04 00 A0 81 00 30 82 85 78 33 9F E5 01 00 70 E3 03 00 86 E7 12 00 00 1A 6C 13 9F E5 1D 20 A0 E3 01 10 86 E0 0A 00 A0 E1 04 70 A0 E3 00 00 00 EF 01 0A 70 E3 48 23 9F 85 00 30 60 82 02 20 96 87 00 30 82 85 14 00 A0 E3 01 70 A0 E3 00 00 00 EF 01 0A 70 E3 28 23 9F 85 00 30 60 82 02 20 96 87 00 30 82 85 1C 33 9F E5 01 C0 4E E2 }
	condition:
		$pattern
}

rule warn_c86d5ca3b83eaee978e9f04c1131f7a4 {
	meta:
		aliases = "warnx, warn"
		size = "48"
		objfiles = "errs@libc.a"
	strings:
		$pattern = { 0F 00 2D E9 04 E0 2D E5 0C D0 4D E2 14 30 8D E2 03 10 A0 E1 10 00 9D E5 04 30 8D E5 ?? ?? ?? ?? 0C D0 8D E2 04 E0 9D E4 10 D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule ulimit_acc6e661de64602b04b5909677bdba57 {
	meta:
		aliases = "ulimit"
		size = "164"
		objfiles = "ulimits@libc.a"
	strings:
		$pattern = { 0F 00 2D E9 04 E0 2D E5 14 D0 4D E2 18 00 9D E5 1C 20 8D E2 02 00 50 E3 0C 20 8D E5 0A 00 00 0A 04 00 50 E3 14 00 00 0A 01 00 50 E3 14 00 00 1A 04 10 8D E2 ?? ?? ?? ?? 00 00 50 E3 04 30 9D 05 A3 04 A0 01 12 00 00 0A 10 00 00 EA 1C 30 9D E5 04 10 8D E2 02 05 53 E3 00 30 E0 23 83 34 A0 31 08 30 8D E5 04 30 8D E5 01 00 A0 E3 04 30 82 E2 0C 30 8D E5 ?? ?? ?? ?? 05 00 00 EA ?? ?? ?? ?? 03 00 00 EA ?? ?? ?? ?? 16 30 A0 E3 00 30 80 E5 00 00 E0 E3 14 D0 8D E2 04 E0 9D E4 10 D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule printf_fb45d20b5d646e2da1eda3faf2f5c67c {
	meta:
		aliases = "scanf, wprintf, __GI_printf, wscanf, printf"
		size = "76"
		objfiles = "scanfs@libc.a, printfs@libc.a, wprintfs@libc.a, wscanfs@libc.a"
	strings:
		$pattern = { 0F 00 2D E9 04 E0 2D E5 34 C0 9F E5 34 30 9F E5 0C C0 8F E0 0C D0 4D E2 03 30 9C E7 14 E0 8D E2 00 00 93 E5 0E 20 A0 E1 10 10 9D E5 04 E0 8D E5 ?? ?? ?? ?? 0C D0 8D E2 04 E0 9D E4 10 D0 8D E2 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ptrace_2e35d267d634e94b5fa755934dfd219a {
	meta:
		aliases = "ptrace"
		size = "164"
		objfiles = "ptraces@libc.a"
	strings:
		$pattern = { 0F 00 2D E9 90 40 2D E9 0C D0 4D E2 18 40 9D E5 1C 10 9D E5 01 30 44 E2 02 00 53 E3 28 30 8D E2 00 30 8D E5 20 20 9D E5 24 30 9D E5 04 00 A0 E1 04 30 8D 92 1A 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 30 E0 E1 A3 3F A0 E1 00 00 54 E3 00 30 A0 03 00 00 53 E3 06 00 00 0A 03 00 54 E3 04 00 00 8A ?? ?? ?? ?? 04 20 9D E5 00 30 A0 E3 00 30 80 E5 00 00 00 EA 07 20 A0 E1 02 00 A0 E1 0C D0 8D E2 90 40 BD E8 10 D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule __aeabi_cfcmple_f6fc4a5fad48d06726d9d4590901cd50 {
	meta:
		aliases = "__aeabi_cfcmpeq, __aeabi_cfcmple"
		size = "20"
		objfiles = "_cmpsf2@libgcc.a"
	strings:
		$pattern = { 0F 40 2D E9 ?? ?? ?? EB 00 00 50 E3 00 00 70 43 0F 80 BD E8 }
	condition:
		$pattern
}

rule telldir_fbbc0dfb8f408d13bd9d97de97cfd607 {
	meta:
		aliases = "telldir"
		size = "8"
		objfiles = "telldirs@libc.a"
	strings:
		$pattern = { 10 00 90 E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI_pthread_attr_getscope_3772e93db8188a51eba069aa964ced32 {
	meta:
		aliases = "pthread_attr_getscope, __GI_pthread_attr_getscope"
		size = "16"
		objfiles = "attrs@libpthread.a"
	strings:
		$pattern = { 10 30 90 E5 00 00 A0 E3 00 30 81 E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule __scan_ungetc_b1098efbc80c32b001bb439b2bb4251c {
	meta:
		aliases = "__scan_ungetc"
		size = "68"
		objfiles = "__scan_cookies@libc.a"
	strings:
		$pattern = { 10 30 90 E5 19 20 D0 E5 01 30 83 E2 02 00 52 E3 10 30 80 E5 04 30 90 05 00 30 80 05 00 30 A0 03 05 00 00 0A 00 00 52 E3 1E FF 2F 11 0C 30 90 E5 01 30 43 E2 0C 30 80 E5 01 30 A0 E3 19 30 C0 E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI_posix_openpt_4cd50ac07dbfa4c17dbc3578014d2e22 {
	meta:
		aliases = "posix_openpt, __GI_posix_openpt"
		size = "32"
		objfiles = "getpts@libc.a"
	strings:
		$pattern = { 10 30 9F E5 00 10 A0 E1 0C 00 9F E5 03 30 8F E0 00 00 83 E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __isinff_5a5af6e0ad74c7cefa7caee03a3b5a98 {
	meta:
		aliases = "__GI___isinff, __isinff"
		size = "28"
		objfiles = "s_isinffs@libm.a"
	strings:
		$pattern = { 10 30 9F E5 02 21 C0 E3 03 00 52 E1 40 0F A0 01 00 00 A0 13 1E FF 2F E1 00 00 80 7F }
	condition:
		$pattern
}

rule __stdio_init_mutex_a779d70b0c86ddb98330f0c926895e2b {
	meta:
		aliases = "__stdio_init_mutex"
		size = "32"
		objfiles = "_stdios@libc.a"
	strings:
		$pattern = { 10 30 9F E5 10 10 9F E5 03 30 8F E0 01 10 83 E0 18 20 A0 E3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_setconcurrency_f9302197f5c397801122be7e24522130 {
	meta:
		aliases = "pthread_setconcurrency, __pthread_setconcurrency"
		size = "32"
		objfiles = "pthreads@libpthread.a"
	strings:
		$pattern = { 10 30 9F E5 10 20 9F E5 03 30 8F E0 02 00 83 E7 00 00 A0 E3 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getwchar_unlocked_2d06acce506d2c2884e169aa827d5ff9 {
	meta:
		aliases = "getwchar, _dl_app_init_array, _dl_app_fini_array, getwchar_unlocked"
		size = "32"
		objfiles = "getwchar_unlockeds@libc.a, libdls@libdl.a, getwchars@libc.a"
	strings:
		$pattern = { 10 30 9F E5 10 20 9F E5 03 30 8F E0 02 20 93 E7 00 00 92 E5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule putwchar_unlocked_d3e0f94f503d60c13ff6d3a27824f9e1 {
	meta:
		aliases = "putwchar_unlocked"
		size = "32"
		objfiles = "putwchar_unlockeds@libc.a"
	strings:
		$pattern = { 10 30 9F E5 10 20 9F E5 03 30 8F E0 02 20 93 E7 00 10 92 E5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule execv_7f98b4460e95e829bf29a75b3c754db6 {
	meta:
		aliases = "__GI_execv, execv"
		size = "32"
		objfiles = "execvs@libc.a"
	strings:
		$pattern = { 10 30 9F E5 10 20 9F E5 03 30 8F E0 02 20 93 E7 00 20 92 E5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __fixsfdi_7f223e9e6b2db7ab058395834d46da37 {
	meta:
		aliases = "__aeabi_f2lz, __fixsfdi"
		size = "56"
		objfiles = "_fixsfdi@libgcc.a"
	strings:
		$pattern = { 10 40 2D E9 00 10 A0 E3 00 40 A0 E1 ?? ?? ?? ?? 00 00 50 E3 02 00 00 1A 04 00 A0 E1 10 40 BD E8 ?? ?? ?? ?? 02 01 84 E2 ?? ?? ?? ?? 00 00 70 E2 00 10 E1 E2 10 80 BD E8 }
	condition:
		$pattern
}

rule wcrtomb_a1b944d0bb9ba8065a3fe5b9f6c5c3f9 {
	meta:
		aliases = "__GI_wcrtomb, wcrtomb"
		size = "80"
		objfiles = "wcrtombs@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 30 50 E2 20 D0 4D E2 08 30 8D 02 01 E0 A0 E1 02 40 A0 E1 00 E0 A0 01 1C C0 8D E2 03 00 A0 E1 18 10 8D E2 01 20 A0 E3 10 30 A0 E3 18 C0 8D E5 1C E0 8D E5 00 40 8D E5 ?? ?? ?? ?? 00 00 50 E3 01 00 A0 03 20 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule strncat_6839497487f8d83ba8f882227837f581 {
	meta:
		aliases = "__GI_strncat, strncat"
		size = "200"
		objfiles = "strncats@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 30 A0 E1 00 40 A0 E1 01 C0 D3 E4 00 00 5C E3 FC FF FF 1A 03 00 52 E3 02 E0 43 E2 22 00 00 9A 22 01 A0 E1 00 30 D1 E5 01 C0 8E E2 00 00 53 E3 01 30 CE E5 20 00 00 0A 01 30 D1 E5 01 10 81 E2 00 00 53 E3 01 30 CC E5 01 C0 8C E2 1A 00 00 0A 01 30 D1 E5 01 E0 8C E2 00 00 53 E3 01 10 81 E2 01 30 CC E5 14 00 00 0A 01 C0 D1 E5 01 30 81 E2 00 00 5C E3 01 C0 CE E5 01 10 83 E2 01 E0 8E E2 0D 00 00 0A 01 00 50 E2 E5 FF FF 1A 03 20 02 E2 05 00 00 EA 00 C0 D1 E5 01 20 42 E2 00 00 5C E3 01 C0 EE E5 04 00 00 0A 01 10 81 E2 00 00 52 E3 F7 FF FF 1A 00 00 5C E3 01 20 CE 15 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __libc_pread64_ebf5364f632bef0affeab671dd48e866 {
	meta:
		aliases = "pread64, __libc_pread64"
		size = "40"
		objfiles = "pread_writes@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 30 A0 E3 10 D0 4D E2 08 30 8D E5 18 30 8D E2 18 00 93 E8 18 00 8D E8 B1 FF FF EB 10 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule xdr_char_2e5a1bca8323d708362efbcd5cb696ff {
	meta:
		aliases = "xdr_u_char, xdr_char"
		size = "52"
		objfiles = "xdrs@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 30 D1 E5 08 D0 4D E2 01 40 A0 E1 08 10 8D E2 04 30 21 E5 ?? ?? ?? ?? 00 00 50 E3 04 30 9D 15 01 00 A0 13 00 30 C4 15 08 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule hdestroy_r_7b14d6caa4d3b8dc1755330e4374c38b {
	meta:
		aliases = "__GI_hdestroy_r, hdestroy_r"
		size = "48"
		objfiles = "hdestroy_rs@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 50 E2 03 00 00 1A ?? ?? ?? ?? 16 30 A0 E3 00 30 80 E5 10 80 BD E8 00 00 94 E5 ?? ?? ?? ?? 00 30 A0 E3 00 30 84 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule tmpnam_r_aedf7462835a001c8f7d7db70ff1c927 {
	meta:
		aliases = "tmpnam_r"
		size = "68"
		objfiles = "tmpnam_rs@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 50 E2 0A 00 00 0A 00 20 A0 E3 14 10 A0 E3 02 30 A0 E1 ?? ?? ?? ?? 00 00 50 E3 04 00 00 1A 04 00 A0 E1 03 10 A0 E3 ?? ?? ?? ?? 00 00 50 E3 00 00 00 0A 00 40 A0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule dirfd_e5e91cdd1327baa20be59ddb65f913a9 {
	meta:
		aliases = "__GI_dirfd, dirfd"
		size = "36"
		objfiles = "dirfds@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 90 E5 01 00 74 E3 02 00 00 1A ?? ?? ?? ?? 09 30 A0 E3 00 30 80 E5 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_freeaddrinfo_2faa2e05347acfe27db0de876beb73cf {
	meta:
		aliases = "freeaddrinfo, __GI_freeaddrinfo"
		size = "32"
		objfiles = "getaddrinfos@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 01 00 00 EA 1C 40 94 E5 ?? ?? ?? ?? 00 00 54 E2 FB FF FF 1A 10 80 BD E8 }
	condition:
		$pattern
}

rule sc_getc_2e8d7698ed8c5fed24e953660adf9999 {
	meta:
		aliases = "sc_getc"
		size = "140"
		objfiles = "vfwscanfs@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 08 00 90 E5 04 30 90 E5 03 00 73 E3 0A 00 00 1A 10 20 90 E5 0C 30 90 E5 03 00 52 E1 04 10 92 34 10 20 80 35 08 00 00 3A B0 30 D0 E1 00 20 E0 E3 04 30 83 E3 B0 30 C0 E1 0F 00 00 EA ?? ?? ?? ?? 01 00 70 E3 00 10 A0 E1 0A 00 00 0A 01 30 A0 E3 08 20 94 E5 1A 30 C4 E5 28 10 84 E5 38 30 94 E5 02 20 D2 E5 03 00 51 E1 18 20 C4 E5 2E 10 A0 03 24 10 84 15 04 10 84 15 01 20 A0 E1 02 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule pthread_handle_sigrestart_2b7e2c3e693b55eeb9c1889c88d64993 {
	meta:
		aliases = "pthread_handle_sigrestart"
		size = "40"
		objfiles = "pthreads@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 1E FD FF EB 24 30 90 E5 20 40 80 E5 00 00 53 E3 10 80 BD 08 03 00 A0 E1 01 10 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __syscall_error_c7f90c2fa182a3650477c00ff5b62095 {
	meta:
		aliases = "__syscall_error"
		size = "28"
		objfiles = "__syscall_errors@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 ?? ?? ?? ?? 00 40 64 E2 00 40 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_pthread_attr_init_7ab37e3286e88dcb76a049926af7df9a {
	meta:
		aliases = "pthread_attr_init, __GI_pthread_attr_init"
		size = "68"
		objfiles = "attrs@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 ?? ?? ?? ?? 02 36 60 E2 00 20 A0 E1 20 30 84 E5 00 00 A0 E3 01 30 A0 E3 0C 30 84 E5 00 00 84 E5 04 00 84 E5 08 00 84 E5 10 00 84 E5 14 20 84 E5 1C 00 84 E5 18 00 84 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule login_tty_fcb24868a996a64ad8ea9e1c274d494c {
	meta:
		aliases = "__GI_login_tty, login_tty"
		size = "104"
		objfiles = "login_ttys@libutil.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 4C 10 9F E5 00 20 A0 E3 ?? ?? ?? ?? 01 00 70 E3 10 80 BD 08 00 10 A0 E3 04 00 A0 E1 ?? ?? ?? ?? 01 10 A0 E3 04 00 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 02 10 A0 E3 ?? ?? ?? ?? 02 00 54 E3 00 00 A0 D3 10 80 BD D8 04 00 A0 E1 ?? ?? ?? ?? 00 00 A0 E3 10 80 BD E8 0E 54 00 00 }
	condition:
		$pattern
}

rule raise_a0a78f7eff04580b8beac097a68a6107 {
	meta:
		aliases = "__GI_raise, __raise, raise"
		size = "24"
		objfiles = "raises@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 ?? ?? ?? ?? 04 10 A0 E1 10 40 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule raise_4a0feaea19206ae6265b6fa6d050e4d5 {
	meta:
		aliases = "__GI_raise, raise"
		size = "48"
		objfiles = "signalss@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 ?? ?? ?? ?? 04 10 A0 E1 ?? ?? ?? ?? 00 40 50 E2 04 00 A0 01 10 80 BD 08 ?? ?? ?? ?? 00 40 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_internal_tsd_get_115ff02e7ab962c867631138a6daa528 {
	meta:
		aliases = "__pthread_internal_tsd_get"
		size = "24"
		objfiles = "specifics@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 CE FF FF EB 04 01 80 E0 6C 01 90 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_internal_tsd_address_c05ff4ae61ace611e1bd59680aac0647 {
	meta:
		aliases = "__pthread_internal_tsd_address"
		size = "24"
		objfiles = "specifics@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 D4 FF FF EB 04 01 80 E0 5B 0F 80 E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_alarm_69e000c575552643fb4dc4aa72969a3f {
	meta:
		aliases = "alarm, __GI_alarm"
		size = "80"
		objfiles = "alarms@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E3 20 D0 4D E2 08 00 8D E5 0D 10 A0 E1 04 00 A0 E1 10 20 8D E2 0C 40 8D E5 00 40 8D E5 04 40 8D E5 ?? ?? ?? ?? 04 00 50 E1 04 00 A0 B1 03 00 00 BA 1C 30 9D E5 18 00 9D E5 00 00 53 E3 01 00 80 12 20 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_glob_pattern_p_b7cb24add75f90b1356f04d81b4f44fa {
	meta:
		aliases = "glob_pattern_p, __GI_glob_pattern_p"
		size = "144"
		objfiles = "globs@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 C0 A0 E1 00 E0 A0 E3 01 40 A0 E3 18 00 00 EA 5B 00 50 E3 0A 00 00 0A 04 00 00 8A 2A 00 50 E3 17 00 00 0A 3F 00 50 E3 10 00 00 1A 14 00 00 EA 5C 00 50 E3 04 00 00 0A 5D 00 50 E3 0B 00 00 1A 08 00 00 EA 04 E0 A0 E1 08 00 00 EA 00 00 51 E3 06 00 00 0A 01 30 DC E5 01 20 8C E2 00 00 53 E3 02 C0 A0 11 01 00 00 EA 00 00 5E E3 04 00 00 1A 01 C0 8C E2 00 00 DC E5 00 00 50 E3 E3 FF FF 1A 10 80 BD E8 01 00 A0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule pwrite64_3bc14d477672db17b36608035b88e0ff {
	meta:
		aliases = "__libc_pwrite64, pwrite64"
		size = "40"
		objfiles = "pread_writes@libc.a"
	strings:
		$pattern = { 10 40 2D E9 01 30 A0 E3 10 D0 4D E2 08 30 8D E5 18 30 8D E2 18 00 93 E8 18 00 8D E8 BB FF FF EB 10 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_svc_sendreply_0d3cbfc49c15b1f76edf8117ba08897c {
	meta:
		aliases = "svc_sendreply, __GI_svc_sendreply"
		size = "84"
		objfiles = "svcs@libc.a"
	strings:
		$pattern = { 10 40 2D E9 01 30 A0 E3 30 D0 4D E2 00 40 A0 E3 00 E0 A0 E1 04 30 8D E5 18 40 8D E5 1C 20 8D E5 20 10 8D E5 08 40 8D E5 0C C0 8D E2 20 00 80 E2 07 00 90 E8 08 30 9E E5 07 00 8C E8 0E 00 A0 E1 0D 10 A0 E1 0F E0 A0 E1 0C F0 93 E5 30 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule _dl_strdup_ef063e80db8950faeff9d89959ccf7f8 {
	meta:
		aliases = "_dl_strdup"
		size = "60"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { 10 40 2D E9 01 40 40 E2 04 20 A0 E1 01 30 F2 E5 00 00 53 E3 FC FF FF 1A 01 00 60 E2 02 00 80 E0 ?? ?? ?? ?? 01 20 40 E2 01 30 F4 E5 00 00 53 E3 01 30 E2 E5 FB FF FF 1A 10 80 BD E8 }
	condition:
		$pattern
}

rule sigwait_bbfcaeb6e5faf00f8c530a0b14e58202 {
	meta:
		aliases = "__GI_sigwait, __sigwait, sigwait"
		size = "36"
		objfiles = "sigwaits@libc.a"
	strings:
		$pattern = { 10 40 2D E9 01 40 A0 E1 00 10 A0 E3 ?? ?? ?? ?? 01 00 70 E3 00 00 84 15 02 00 80 02 00 00 A0 13 10 80 BD E8 }
	condition:
		$pattern
}

rule __glibc_strerror_r_47a30569692ffe6564af13472fb0c65d {
	meta:
		aliases = "__GI___glibc_strerror_r, __glibc_strerror_r"
		size = "20"
		objfiles = "__glibc_strerror_rs@libc.a"
	strings:
		$pattern = { 10 40 2D E9 01 40 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule ldexpf_86d053fd1938dc83cbcbf8ecffa8e762 {
	meta:
		aliases = "scalblnf, scalbnf, frexpf, ldexpf"
		size = "28"
		objfiles = "frexpfs@libm.a, ldexpfs@libm.a, scalbnfs@libm.a, scalblnfs@libm.a"
	strings:
		$pattern = { 10 40 2D E9 01 40 A0 E1 ?? ?? ?? ?? 04 20 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? 10 80 BD E8 }
	condition:
		$pattern
}

rule tempnam_832ba81df5e9e9abd50129a763a15850 {
	meta:
		aliases = "tempnam"
		size = "92"
		objfiles = "tempnams@libc.a"
	strings:
		$pattern = { 10 40 2D E9 01 DA 4D E2 10 40 8D E2 0F 40 44 E2 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 34 10 9F E5 ?? ?? ?? ?? 00 00 50 E3 07 00 00 1A 04 00 A0 E1 03 10 A0 E3 ?? ?? ?? ?? 00 00 50 E3 02 00 00 1A 04 00 A0 E1 ?? ?? ?? ?? 00 00 00 EA 00 00 A0 E3 01 DA 8D E2 10 80 BD E8 FF 0F 00 00 }
	condition:
		$pattern
}

rule mkdtemp_38508f725f90585480f0c78ff93a4516 {
	meta:
		aliases = "mkdtemp"
		size = "32"
		objfiles = "mkdtemps@libc.a"
	strings:
		$pattern = { 10 40 2D E9 02 10 A0 E3 00 40 A0 E1 ?? ?? ?? ?? 00 00 50 E3 04 00 A0 01 00 00 A0 13 10 80 BD E8 }
	condition:
		$pattern
}

rule __re_compile_pattern_18fd6b8fef4b173d4494f05e354e602d {
	meta:
		aliases = "re_compile_pattern, __re_compile_pattern"
		size = "120"
		objfiles = "regex_olds@libc.a"
	strings:
		$pattern = { 10 40 2D E9 02 30 A0 E1 1C 20 D2 E5 54 40 9F E5 06 20 C2 E3 1C 20 C3 E5 1C 20 D3 E5 04 40 8F E0 10 20 C2 E3 1C 20 C3 E5 1C C0 D3 E5 38 20 9F E5 80 C0 8C E3 02 20 94 E7 1C C0 C3 E5 00 20 92 E5 86 F6 FF EB 00 00 50 E3 10 80 BD 08 1C 30 9F E5 03 30 84 E0 00 21 93 E7 14 30 9F E5 03 30 84 E0 03 00 82 E0 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ether_line_538b04c3f81b2e4194d5defe5abad447 {
	meta:
		aliases = "ether_line"
		size = "120"
		objfiles = "etherss@libc.a"
	strings:
		$pattern = { 10 40 2D E9 02 40 A0 E1 E2 FF FF EB 5C C0 9F E5 00 00 50 E3 0C C0 8F E0 00 00 E0 03 10 80 BD 08 08 00 00 EA 23 00 52 E3 0C 00 00 0A 0E 30 9C E7 00 30 93 E5 B3 30 91 E1 20 00 13 E3 07 00 00 1A 01 20 C4 E4 00 00 00 EA 24 E0 9F E5 00 20 D0 E5 01 00 80 E2 00 00 52 E3 82 10 A0 E1 F0 FF FF 1A 00 30 A0 E3 03 00 A0 E1 00 30 C4 E5 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fabs_5cab04383d8e1978faeaaa266ab45337 {
	meta:
		aliases = "__GI_fabs, fabs"
		size = "16"
		objfiles = "s_fabss@libm.a"
	strings:
		$pattern = { 10 40 2D E9 02 41 C1 E3 04 10 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule mktemp_37f981e0a8053c014c46e680b6f47aec {
	meta:
		aliases = "mktemp"
		size = "36"
		objfiles = "mktemps@libc.a"
	strings:
		$pattern = { 10 40 2D E9 03 10 A0 E3 00 40 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 30 A0 B3 04 00 A0 E1 00 30 C4 B5 10 80 BD E8 }
	condition:
		$pattern
}

rule __stdio_rfill_f58f241d80cbcbd3e64e0a329db7915f {
	meta:
		aliases = "__stdio_rfill"
		size = "44"
		objfiles = "_rfills@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 10 90 E5 0C 20 90 E5 00 40 A0 E1 02 20 61 E0 ?? ?? ?? ?? 08 20 94 E5 00 30 82 E0 14 30 84 E5 10 20 84 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule __stdio_wcommit_4e5378b09f29cfe675d31da929a1d048 {
	meta:
		aliases = "__stdio_wcommit"
		size = "48"
		objfiles = "_wcommits@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 10 90 E5 10 30 90 E5 00 40 A0 E1 01 20 53 E0 01 00 00 0A 10 10 80 E5 ?? ?? ?? ?? 08 30 94 E5 10 00 94 E5 00 00 63 E0 10 80 BD E8 }
	condition:
		$pattern
}

rule __stdio_seek_a710263d3efd2fd304604944176ff0ea {
	meta:
		aliases = "__stdio_seek"
		size = "56"
		objfiles = "_cs_funcss@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 D0 4D E2 00 20 8D E5 0C 00 91 E8 04 00 90 E5 01 40 A0 E1 ?? ?? ?? ?? 00 00 51 E3 00 30 A0 B1 03 00 84 A8 00 30 A0 A3 03 00 A0 E1 08 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_time_1b7e2786ffdedfce8f9515140f22e9bc {
	meta:
		aliases = "time, __GI_time"
		size = "52"
		objfiles = "times@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 D0 4D E2 00 40 A0 E1 00 10 A0 E3 0D 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 00 9D 05 00 00 E0 13 00 00 54 E3 00 00 84 15 08 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule sethostid_92f8dd792b037e0e7ebee25e578fcd4e {
	meta:
		aliases = "sethostid"
		size = "148"
		objfiles = "hostids@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 D0 4D E2 04 00 8D E5 ?? ?? ?? ?? 74 40 9F E5 00 00 50 E3 04 40 8F E0 02 00 00 1A ?? ?? ?? ?? 00 00 50 E3 04 00 00 0A ?? ?? ?? ?? 01 30 A0 E3 03 40 A0 E1 00 30 80 E5 0F 00 00 EA 48 00 9F E5 41 10 A0 E3 00 00 84 E0 69 2F A0 E3 ?? ?? ?? ?? 00 40 50 E2 00 40 E0 B3 07 00 00 BA 04 10 8D E2 04 20 A0 E3 ?? ?? ?? ?? 04 00 50 E3 04 00 A0 E1 00 40 E0 13 00 40 A0 03 ?? ?? ?? ?? 04 00 A0 E1 08 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wait_5ea326d991ac2680059a00428d3c9b3c {
	meta:
		aliases = "tcdrain, fsync, close, system, wait"
		size = "60"
		objfiles = "wrapsyscalls@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 08 D0 4D E2 04 10 8D E2 00 40 A0 E1 01 00 A0 E3 ?? ?? ?? ?? 04 00 A0 E1 ?? ?? ?? ?? 00 10 A0 E3 00 40 A0 E1 04 00 9D E5 ?? ?? ?? ?? 04 00 A0 E1 08 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule pause_ce18840225e54ed004a32b43b45c3c3c {
	meta:
		aliases = "pause"
		size = "52"
		objfiles = "wrapsyscalls@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 08 D0 4D E2 04 10 8D E2 01 00 A0 E3 ?? ?? ?? ?? ?? ?? ?? ?? 00 10 A0 E3 00 40 A0 E1 04 00 9D E5 ?? ?? ?? ?? 04 00 A0 E1 08 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_tgamma_662851c014e62d5787348a63d8500151 {
	meta:
		aliases = "tgamma, __GI_tgamma"
		size = "48"
		objfiles = "w_tgammas@libm.a"
	strings:
		$pattern = { 10 40 2D E9 08 D0 4D E2 04 20 8D E2 ?? ?? ?? ?? 04 30 9D E5 00 00 53 E3 00 30 A0 B1 02 41 81 B2 03 00 A0 B1 04 10 A0 B1 08 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __dn_expand_1152d48b33f01a6f772ba791edf07fc2 {
	meta:
		aliases = "__dn_expand"
		size = "56"
		objfiles = "res_comps@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 D0 4D E2 10 C0 9D E5 03 40 A0 E1 00 C0 8D E5 ?? ?? ?? ?? 00 00 50 E3 03 00 00 DA 00 30 D4 E5 2E 00 53 E3 00 30 A0 03 00 30 C4 05 08 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __scan_getc_9fb3a975be1eae6e5a475889ddf5e491 {
	meta:
		aliases = "__scan_getc"
		size = "124"
		objfiles = "__scan_cookies@libc.a"
	strings:
		$pattern = { 10 40 2D E9 10 30 90 E5 00 20 E0 E3 02 30 83 E0 00 00 53 E3 10 30 80 E5 19 30 D0 E5 00 40 A0 E1 00 20 80 E5 02 30 83 B3 02 00 A0 B1 0A 00 00 BA 00 00 53 E3 00 30 A0 13 19 30 C4 15 08 00 00 1A 0F E0 A0 E1 2C F0 94 E5 01 00 70 E3 04 00 84 15 03 00 00 1A 19 30 D4 E5 02 30 83 E3 19 30 C4 E5 10 80 BD E8 0C 30 94 E5 04 00 94 E5 01 30 83 E2 0C 30 84 E5 00 00 84 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule ftime_e3c4387218e7eed0ca24e4f75e78cdb1 {
	meta:
		aliases = "ftime"
		size = "96"
		objfiles = "ftimes@libc.a"
	strings:
		$pattern = { 10 40 2D E9 10 D0 4D E2 00 40 A0 E1 0D 10 A0 E1 08 00 8D E2 ?? ?? ?? ?? 00 00 50 E3 00 00 E0 B3 0C 00 00 BA 0C 00 9D E5 08 30 9D E5 F9 0F 80 E2 00 30 84 E5 03 00 80 E2 FA 1F A0 E3 ?? ?? ?? ?? B4 30 DD E1 B4 00 C4 E1 B8 30 C4 E1 B0 30 DD E1 00 00 A0 E3 B6 30 C4 E1 10 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __do_global_dtors_aux_e7e9b0efca8b87a307984111253d6b75 {
	meta:
		aliases = "__do_global_dtors_aux"
		size = "156"
		objfiles = "crtbegin, crtbeginT"
	strings:
		$pattern = { 10 40 2D E9 28 40 9F E5 00 30 D4 E5 00 00 53 E3 10 80 BD 18 1C 30 9F E5 00 00 53 E3 01 00 00 0A 14 00 9F E5 33 FF 2F E1 01 30 A0 E3 00 30 C4 E5 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 E0 2D E5 3C 30 9F E5 04 D0 4D E2 00 00 53 E3 02 00 00 0A 30 00 9F E5 30 10 9F E5 33 FF 2F E1 2C 00 9F E5 00 30 90 E5 00 00 53 E3 03 00 00 0A 20 30 9F E5 00 00 53 E3 00 00 00 0A 33 FF 2F E1 04 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getservent_a370985a5a63358328490aa99ee122c3 {
	meta:
		aliases = "getservent"
		size = "76"
		objfiles = "getservices@libc.a"
	strings:
		$pattern = { 10 40 2D E9 30 40 9F E5 08 D0 4D E2 40 FF FF EB 28 30 9F E5 28 00 9F E5 04 40 8F E0 03 10 94 E7 00 00 84 E0 1C 20 9F E5 04 30 8D E2 ?? ?? ?? ?? 04 00 9D E5 08 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D 10 00 00 }
	condition:
		$pattern
}

rule getprotoent_bf27933d82924f05e32578e9ca047a33 {
	meta:
		aliases = "getprotoent"
		size = "76"
		objfiles = "getprotos@libc.a"
	strings:
		$pattern = { 10 40 2D E9 30 40 9F E5 08 D0 4D E2 4C FF FF EB 28 30 9F E5 28 00 9F E5 04 40 8F E0 03 10 94 E7 00 00 84 E0 1C 20 9F E5 04 30 8D E2 ?? ?? ?? ?? 04 00 9D E5 08 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D 10 00 00 }
	condition:
		$pattern
}

rule gcvt_dcffe02ff5040f8177f52223d7f8abc1 {
	meta:
		aliases = "gcvt"
		size = "68"
		objfiles = "gcvts@libc.a"
	strings:
		$pattern = { 10 40 2D E9 30 C0 9F E5 08 D0 4D E2 03 00 8D E8 28 10 9F E5 0C C0 8F E0 01 10 8C E0 11 00 52 E3 11 20 A0 A3 03 00 A0 E1 03 40 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 08 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ctime_r_5f3c4c4ea918245b6bfd10bd206808d7 {
	meta:
		aliases = "ctime_r"
		size = "36"
		objfiles = "ctime_rs@libc.a"
	strings:
		$pattern = { 10 40 2D E9 30 D0 4D E2 01 40 A0 E1 04 10 8D E2 ?? ?? ?? ?? 04 10 A0 E1 ?? ?? ?? ?? 30 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule system_d0052eafcf0aebdfdfe5325f6185bd6b {
	meta:
		aliases = "__libc_system, system"
		size = "344"
		objfiles = "systems@libc.a"
	strings:
		$pattern = { 10 40 2D E9 3C 31 9F E5 28 D0 4D E2 00 00 50 E3 03 30 8F E0 10 00 8D E5 0C 30 8D E5 01 00 A0 03 46 00 00 0A 01 10 A0 E3 03 00 A0 E3 ?? ?? ?? ?? 01 10 A0 E3 14 00 8D E5 02 00 A0 E3 ?? ?? ?? ?? 00 10 A0 E3 18 00 8D E5 11 00 A0 E3 ?? ?? ?? ?? 1C 00 8D E5 ?? ?? ?? ?? 00 40 50 E2 0A 00 00 AA 14 10 9D E5 03 00 A0 E3 ?? ?? ?? ?? 18 10 9D E5 02 00 A0 E3 ?? ?? ?? ?? 1C 10 9D E5 11 00 A0 E3 ?? ?? ?? ?? 00 00 E0 E3 2C 00 00 EA 14 00 00 1A 04 10 A0 E1 03 00 A0 E3 ?? ?? ?? ?? 04 10 A0 E1 02 00 A0 E3 ?? ?? ?? ?? 04 10 A0 E1 11 00 A0 E3 ?? ?? ?? ?? 0C 30 9D E5 8C 00 9F E5 8C 20 9F E5 8C 10 9F E5 00 00 83 E0 }
	condition:
		$pattern
}

rule __pthread_once_fork_child_dac61c699f43e8deaf9bb625c6d928f2 {
	meta:
		aliases = "__pthread_once_fork_child"
		size = "100"
		objfiles = "mutexs@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 44 40 9F E5 44 00 9F E5 44 30 9F E5 04 40 8F E0 03 30 84 E0 00 10 A0 E3 00 00 84 E0 33 FF 2F E1 30 00 9F E5 00 10 A0 E3 00 00 84 E0 ?? ?? ?? ?? 24 20 9F E5 02 30 94 E7 16 01 73 E3 04 30 83 D2 00 30 A0 C3 02 30 84 E7 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mbtowc_f9ea8df0adaf0b68264ee84953fda8d6 {
	meta:
		aliases = "mbtowc"
		size = "100"
		objfiles = "mbtowcs@libc.a"
	strings:
		$pattern = { 10 40 2D E9 4C E0 9F E5 00 C0 51 E2 0E E0 8F E0 03 00 00 1A 40 30 9F E5 0C 00 A0 E1 03 C0 8E E7 10 80 BD E8 00 30 DC E5 00 00 53 E3 03 00 A0 01 10 80 BD 08 20 30 9F E5 03 40 8E E0 04 30 A0 E1 ?? ?? ?? ?? 02 00 70 E3 10 30 9F 05 01 00 80 02 04 30 84 05 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? FF FF 00 00 }
	condition:
		$pattern
}

rule frame_dummy_98457952ea57e1161059a79ff12687ad {
	meta:
		aliases = "frame_dummy"
		size = "116"
		objfiles = "crtbeginS"
	strings:
		$pattern = { 10 40 2D E9 50 40 9F E5 50 30 9F E5 04 40 8F E0 03 30 94 E7 00 00 53 E3 04 00 00 0A 40 00 9F E5 40 10 9F E5 00 00 84 E0 01 10 84 E0 33 FF 2F E1 34 30 9F E5 03 20 94 E7 03 00 84 E0 00 00 52 E3 10 80 BD 08 24 30 9F E5 03 10 94 E7 00 00 51 E3 10 80 BD 08 31 FF 2F E1 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI___uClibc_init_16277d552c9883145a63fa7487cec848 {
	meta:
		aliases = "__uClibc_init, __GI___uClibc_init"
		size = "116"
		objfiles = "__uClibc_mains@libc.a"
	strings:
		$pattern = { 10 40 2D E9 54 40 9F E5 54 00 9F E5 04 40 8F E0 00 30 94 E7 00 00 53 E3 10 80 BD 18 44 30 9F E5 03 10 94 E7 40 30 9F E5 00 00 51 E3 03 20 94 E7 01 30 A0 E3 00 30 84 E7 01 3A A0 E3 00 30 82 E5 00 00 00 0A 31 FF 2F E1 20 30 9F E5 03 30 84 E0 00 00 53 E3 10 80 BD 08 10 40 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ftok_c60aed33f81d476f0c3c7e01aa09c881 {
	meta:
		aliases = "ftok"
		size = "52"
		objfiles = "ftoks@libc.a"
	strings:
		$pattern = { 10 40 2D E9 58 D0 4D E2 01 40 A0 E1 0D 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 BC 30 DD A1 00 20 DD A5 00 00 E0 B3 02 38 83 A1 04 0C 83 A1 58 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule setlocale_fb5201f5917203ef612df2bae23c50d9 {
	meta:
		aliases = "setlocale"
		size = "116"
		objfiles = "setlocales@libc.a"
	strings:
		$pattern = { 10 40 2D E9 5C 40 9F E5 06 00 50 E3 04 40 8F E0 01 00 A0 E1 11 00 00 8A 00 00 51 E3 0C 00 00 0A 00 30 D1 E5 00 00 53 E3 09 00 00 0A 43 00 53 E3 02 00 00 1A 01 30 D1 E5 00 00 53 E3 04 00 00 0A 24 10 9F E5 01 10 84 E0 ?? ?? ?? ?? 00 00 50 E3 02 00 00 1A 14 30 9F E5 03 00 84 E0 10 80 BD E8 00 00 A0 E3 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule endusershell_d7a1330b12369f05903904d1e3fadf27 {
	meta:
		aliases = "endusershell"
		size = "40"
		objfiles = "usershells@libc.a"
	strings:
		$pattern = { 10 40 2D E9 6E FF FF EB 10 40 9F E5 10 30 9F E5 04 40 8F E0 00 20 A0 E3 03 20 84 E7 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ntp_gettime_dd7c988fac7743250f45454a4f5180af {
	meta:
		aliases = "ntp_gettime"
		size = "72"
		objfiles = "ntp_gettimes@libc.a"
	strings:
		$pattern = { 10 40 2D E9 80 D0 4D E2 00 40 A0 E1 00 30 A0 E3 0D 00 A0 E1 00 30 8D E5 ?? ?? ?? ?? 0C 10 9D E5 10 30 9D E5 00 C0 A0 E1 24 20 8D E2 0C 30 84 E5 08 10 84 E5 03 00 92 E8 03 00 84 E8 0C 00 A0 E1 80 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_getrpcent_cc1779a39ec41de85fc6cd339c4307f2 {
	meta:
		aliases = "getrpcent, __GI_getrpcent"
		size = "100"
		objfiles = "getrpcents@libc.a"
	strings:
		$pattern = { 10 40 2D E9 89 FF FF EB 48 20 9F E5 00 40 50 E2 02 20 8F E0 0D 00 00 0A 00 30 94 E5 00 00 53 E3 07 00 00 1A 30 00 9F E5 30 10 9F E5 00 00 82 E0 01 10 82 E0 ?? ?? ?? ?? 00 00 50 E3 00 00 84 E5 02 00 00 0A 04 00 A0 E1 10 40 BD E8 9B FF FF EA 00 00 A0 E3 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __mulvsi3_a20c1e0d45e8c74cd89b1a7164aeabb5 {
	meta:
		aliases = "__mulvsi3"
		size = "36"
		objfiles = "_mulvsi3@libgcc.a"
	strings:
		$pattern = { 10 40 2D E9 91 30 C4 E0 03 00 A0 E1 04 10 A0 E1 C0 2F A0 E1 01 00 52 E1 C4 4F A0 E1 10 80 BD 08 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clnt_pcreateerror_7e149b4feabb3bb56e29aed280a188ab {
	meta:
		aliases = "__GI_clnt_perror, clnt_perror, clnt_perrno, clnt_pcreateerror"
		size = "44"
		objfiles = "clnt_perrors@libc.a"
	strings:
		$pattern = { 10 40 2D E9 ?? ?? ?? ?? 14 40 9F E5 14 30 9F E5 04 40 8F E0 03 30 94 E7 00 10 93 E5 10 40 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI___rpc_thread_svc_fdset_6cf21382bcf474bfa2070fb11e47050a {
	meta:
		aliases = "__rpc_thread_svc_fdset, __GI___rpc_thread_svc_fdset"
		size = "56"
		objfiles = "rpc_threads@libc.a"
	strings:
		$pattern = { 10 40 2D E9 ?? ?? ?? ?? 1C 40 9F E5 1C 30 9F E5 04 40 8F E0 03 30 84 E0 03 00 50 E1 10 80 BD 18 0C 30 9F E5 03 00 94 E7 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI___rpc_thread_createerr_a912bcf04092b7751374277081f49feb {
	meta:
		aliases = "__rpc_thread_createerr, __GI___rpc_thread_createerr"
		size = "64"
		objfiles = "rpc_threads@libc.a"
	strings:
		$pattern = { 10 40 2D E9 ?? ?? ?? ?? 24 40 9F E5 24 30 9F E5 04 40 8F E0 03 30 84 E0 03 00 50 E1 02 00 00 1A 14 30 9F E5 03 00 94 E7 10 80 BD E8 80 00 80 E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI___rpc_thread_svc_pollfd_0b3ba3d3840ef8e038dc5b9f8afcc3c7 {
	meta:
		aliases = "__rpc_thread_svc_pollfd, __GI___rpc_thread_svc_pollfd"
		size = "64"
		objfiles = "rpc_threads@libc.a"
	strings:
		$pattern = { 10 40 2D E9 ?? ?? ?? ?? 24 40 9F E5 24 30 9F E5 04 40 8F E0 03 30 84 E0 03 00 50 E1 02 00 00 1A 14 30 9F E5 03 00 94 E7 10 80 BD E8 90 00 80 E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __rpc_thread_svc_max_pollfd_0577d79f480efe9d305a174025f6ad30 {
	meta:
		aliases = "__GI___rpc_thread_svc_max_pollfd, __rpc_thread_svc_max_pollfd"
		size = "64"
		objfiles = "rpc_threads@libc.a"
	strings:
		$pattern = { 10 40 2D E9 ?? ?? ?? ?? 24 40 9F E5 24 30 9F E5 04 40 8F E0 03 30 84 E0 03 00 50 E1 02 00 00 1A 14 30 9F E5 03 00 94 E7 10 80 BD E8 94 00 80 E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __rpc_thread_clnt_cleanup_13bd2f8ad27a335f35d2c3f4d46ed72a {
	meta:
		aliases = "__rpc_thread_clnt_cleanup"
		size = "60"
		objfiles = "clnt_simples@libc.a"
	strings:
		$pattern = { 10 40 2D E9 ?? ?? ?? ?? A4 40 90 E5 00 00 54 E3 10 80 BD 08 00 30 94 E5 00 00 53 E3 03 00 00 0A 03 00 A0 E1 04 30 93 E5 0F E0 A0 E1 10 F0 93 E5 04 00 A0 E1 10 40 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule logout_d3580650a25c6972446a98ee021ecd5f {
	meta:
		aliases = "logout"
		size = "200"
		objfiles = "logouts@libutil.a"
	strings:
		$pattern = { 10 40 2D E9 B0 30 9F E5 00 40 A0 E1 AC 00 9F E5 03 30 8F E0 06 DD 4D E2 00 00 83 E0 ?? ?? ?? ?? 01 00 70 E3 00 40 A0 03 20 00 00 0A ?? ?? ?? ?? 8C 30 9F E5 04 10 A0 E1 07 E0 A0 E3 06 CD 8D E2 20 20 A0 E3 08 00 8D E2 B3 E0 8C E1 ?? ?? ?? ?? 0D 00 A0 E1 ?? ?? ?? ?? 00 40 50 E2 11 00 00 0A 00 10 A0 E3 20 20 A0 E3 2C 00 84 E2 ?? ?? ?? ?? 01 2C A0 E3 00 10 A0 E3 4C 00 84 E2 ?? ?? ?? ?? 00 10 A0 E3 55 0F 84 E2 ?? ?? ?? ?? 08 30 A0 E3 B0 30 C4 E1 04 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 01 40 A0 13 00 00 00 1A 00 40 A0 E3 ?? ?? ?? ?? 04 00 A0 E1 06 DD 8D E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? 80 FE FF FF }
	condition:
		$pattern
}

rule __stdio_trans2w_o_93d67a9458a5fd0bc07720cf675f6802 {
	meta:
		aliases = "__stdio_trans2w_o"
		size = "204"
		objfiles = "_trans2ws@libc.a"
	strings:
		$pattern = { 10 40 2D E9 B0 30 D0 E1 00 40 A0 E1 03 00 11 E1 03 00 00 1A 22 0D 13 E3 04 00 00 1A 03 30 81 E1 B0 30 C0 E1 B0 C0 D4 E1 20 00 1C E3 07 00 00 0A ?? ?? ?? ?? 09 30 A0 E3 00 30 80 E5 B0 30 D4 E1 00 00 E0 E3 08 30 83 E3 B0 30 C4 E1 10 80 BD E8 03 00 1C E3 14 00 00 0A 04 10 1C E2 0B 00 00 1A 14 20 94 E5 10 30 94 E5 03 00 52 E1 01 00 00 1A 02 00 1C E3 05 00 00 0A 01 0B 1C E3 01 20 A0 03 02 20 A0 13 ?? ?? ?? ?? 00 00 50 E3 EA FF FF 1A B0 30 D4 E1 08 20 94 E5 03 30 C3 E3 B0 30 C4 E1 14 20 84 E5 18 20 84 E5 10 20 84 E5 B0 30 D4 E1 40 30 83 E3 0B 0C 13 E2 B0 30 C4 E1 0C 30 94 05 00 00 A0 13 1C 30 84 05 }
	condition:
		$pattern
}

rule gethostid_7785dd685281fc924a228f34775047ad {
	meta:
		aliases = "gethostid"
		size = "236"
		objfiles = "hostids@libc.a"
	strings:
		$pattern = { 10 40 2D E9 D8 30 9F E5 D8 00 9F E5 03 30 8F E0 07 DD 4D E2 00 00 83 E0 00 10 A0 E3 ?? ?? ?? ?? 00 40 50 E2 08 00 00 BA 6F 1F 8D E2 04 20 A0 E3 ?? ?? ?? ?? 00 00 50 E3 24 00 00 0A 04 00 A0 E1 ?? ?? ?? ?? BC 01 9D E5 23 00 00 EA 56 4F 8D E2 03 40 84 E2 04 00 A0 E1 40 10 A0 E3 ?? ?? ?? ?? 00 00 50 E3 17 00 00 BA 5B 31 DD E5 00 00 53 E3 14 00 00 0A 6E CF 8D E2 10 20 8D E2 01 20 42 E2 00 C0 8D E5 04 00 A0 E1 1B CE 8D E2 67 1F 8D E2 53 3F A0 E3 04 C0 8D E5 ?? ?? ?? ?? B8 21 9D E5 00 00 52 E3 07 00 00 0A 10 30 92 E5 6D 0F 8D E2 00 10 93 E5 0C 20 92 E5 ?? ?? ?? ?? B4 31 9D E5 63 08 A0 E1 04 00 00 EA }
	condition:
		$pattern
}

rule __GI_memrchr_48eacd099d9453d026b7f33bd073318e {
	meta:
		aliases = "memrchr, __GI_memrchr"
		size = "220"
		objfiles = "memrchrs@libc.a"
	strings:
		$pattern = { 10 40 2D E9 FF 10 01 E2 02 00 80 E0 03 00 00 EA 01 30 70 E5 01 20 42 E2 01 00 53 E1 10 80 BD 08 00 00 52 E3 01 00 00 0A 03 00 10 E3 F7 FF FF 1A 01 34 81 E1 03 48 83 E1 19 00 00 EA 04 30 30 E5 04 20 42 E2 03 30 24 E0 0C C0 83 E0 03 30 E0 E1 0C 30 23 E0 0E E0 03 E0 00 00 5E E3 10 00 00 0A 03 30 D0 E5 03 C0 80 E2 01 00 53 E1 07 00 00 0A 02 30 D0 E5 02 C0 80 E2 01 00 53 E1 03 00 00 0A 01 30 D0 E5 01 C0 80 E2 01 00 53 E1 01 00 00 1A 0C 00 A0 E1 10 80 BD E8 00 30 D0 E5 01 00 53 E1 10 80 BD 08 03 00 52 E3 24 C0 9F E5 24 E0 9F E5 E1 FF FF 8A 02 00 00 EA 01 30 70 E5 01 00 53 E1 10 80 BD 08 01 20 52 E2 }
	condition:
		$pattern
}

rule rawmemchr_0fcb66caa5d910516fa1026f7dbe6076 {
	meta:
		aliases = "__GI_rawmemchr, rawmemchr"
		size = "176"
		objfiles = "rawmemchrs@libc.a"
	strings:
		$pattern = { 10 40 2D E9 FF E0 01 E2 03 00 00 EA 00 30 D0 E5 0E 00 53 E1 10 80 BD 08 01 00 80 E2 03 00 10 E3 F9 FF FF 1A 0E 34 8E E1 00 C0 A0 E1 03 48 83 E1 04 30 9C E4 6C 10 9F E5 03 30 24 E0 01 10 83 E0 64 20 9F E5 03 30 E0 E1 01 30 23 E0 02 20 03 E0 00 00 52 E3 F5 FF FF 0A 04 30 5C E5 04 00 4C E2 0E 00 53 E1 03 10 80 E2 10 80 BD 08 03 30 5C E5 01 20 80 E2 0E 00 53 E1 01 00 00 1A 02 00 A0 E1 10 80 BD E8 02 30 5C E5 02 00 80 E2 0E 00 53 E1 10 80 BD 08 01 30 5C E5 0E 00 53 E1 E3 FF FF 1A 01 00 A0 E1 10 80 BD E8 FF FE FE 7E 00 01 01 81 }
	condition:
		$pattern
}

rule __gnu_Unwind_Resume_50e6a95b3054d636e5a2b476b4195176 {
	meta:
		aliases = "__gnu_Unwind_Resume"
		size = "108"
		objfiles = "unwind_arm@libgcc.a"
	strings:
		$pattern = { 14 20 90 E5 30 40 2D E9 40 20 81 E5 0C 30 90 E5 04 D0 4D E2 00 00 53 E3 00 40 A0 E1 01 50 A0 E1 0E 00 00 1A 02 00 A0 E3 04 10 A0 E1 05 20 A0 E1 0F E0 A0 E1 10 F0 94 E5 07 00 50 E3 05 00 00 0A 08 00 50 E3 00 00 00 0A ?? ?? ?? ?? 04 00 A0 E1 05 10 A0 E1 D2 FF FF EB 04 00 85 E2 ?? ?? ?? ?? 01 20 A0 E3 76 FF FF EB ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_restart_new_83e64436e0f50979fcbee434587a9d01 {
	meta:
		aliases = "__pthread_restart_new"
		size = "36"
		objfiles = "pthreads@libpthread.a"
	strings:
		$pattern = { 14 20 9F E5 02 20 8F E0 10 30 9F E5 14 00 90 E5 03 30 92 E7 00 10 93 E5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_attr_getguardsize_dfbf41ce558b8a36338130e0b8b30317 {
	meta:
		aliases = "pthread_attr_getguardsize, __pthread_attr_getguardsize"
		size = "16"
		objfiles = "attrs@libpthread.a"
	strings:
		$pattern = { 14 30 90 E5 00 00 A0 E3 00 30 81 E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule _ppfs_setargs_496c2b4742c5b045bac6492ae60b070b {
	meta:
		aliases = "_ppfs_setargs"
		size = "428"
		objfiles = "_ppfs_setargss@libc.a"
	strings:
		$pattern = { 18 10 90 E5 30 40 2D E9 00 00 51 E3 08 30 90 E5 4D 00 00 1A 02 01 53 E3 05 00 00 1A 4C 30 90 E5 00 20 93 E5 04 30 83 E2 4C 30 80 E5 08 20 80 E5 50 20 80 E5 04 30 90 E5 50 C0 80 E2 02 01 53 E3 05 00 00 1A 4C 30 90 E5 00 20 93 E5 04 30 83 E2 4C 30 80 E5 04 20 80 E5 50 20 80 E5 44 51 9F E5 01 E0 A0 E1 34 00 00 EA 0E 31 80 E0 28 30 93 E5 01 E0 8E E2 08 00 53 E3 2F 00 00 0A 4C 10 90 E5 07 00 00 CA 02 00 53 E3 19 00 00 0A 02 00 00 CA 00 00 53 E3 16 00 00 AA 22 00 00 EA 07 00 53 E3 0A 00 00 EA 01 0B 53 E3 11 00 00 0A 04 00 00 CA 01 0C 53 E3 0E 00 00 0A 02 0C 53 E3 19 00 00 1A 0B 00 00 EA 02 0B 53 E3 }
	condition:
		$pattern
}

rule ctermid_51707976aa552739d420020d9a04a0ad {
	meta:
		aliases = "ctermid"
		size = "44"
		objfiles = "ctermids@libc.a"
	strings:
		$pattern = { 18 20 9F E5 00 00 50 E3 02 20 8F E0 10 30 9F 05 03 00 82 00 0C 10 9F E5 01 10 82 E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isctype_0f49af0f05e6dec09d385bb7c437ae43 {
	meta:
		aliases = "isctype"
		size = "40"
		objfiles = "isctypes@libc.a"
	strings:
		$pattern = { 18 20 9F E5 18 30 9F E5 02 20 8F E0 03 30 92 E7 80 00 A0 E1 B3 00 90 E1 01 00 00 E0 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isupper_0d76a5c09799dd0ec69b4adeacb08556 {
	meta:
		aliases = "isupper"
		size = "40"
		objfiles = "isuppers@libc.a"
	strings:
		$pattern = { 18 20 9F E5 18 30 9F E5 02 20 8F E0 03 30 92 E7 80 00 A0 E1 B3 00 90 E1 01 00 00 E2 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ispunct_008a7c6748a49402d04ecf8c54b7d72d {
	meta:
		aliases = "ispunct"
		size = "40"
		objfiles = "ispuncts@libc.a"
	strings:
		$pattern = { 18 20 9F E5 18 30 9F E5 02 20 8F E0 03 30 92 E7 80 00 A0 E1 B3 00 90 E1 01 0B 00 E2 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isblank_d7f2f5671613a26d4179d9c0e7fc0878 {
	meta:
		aliases = "isblank"
		size = "40"
		objfiles = "isblanks@libc.a"
	strings:
		$pattern = { 18 20 9F E5 18 30 9F E5 02 20 8F E0 03 30 92 E7 80 00 A0 E1 B3 00 90 E1 01 0C 00 E2 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule islower_499815d802c5af0101be8ff1d9c758aa {
	meta:
		aliases = "islower"
		size = "40"
		objfiles = "islowers@libc.a"
	strings:
		$pattern = { 18 20 9F E5 18 30 9F E5 02 20 8F E0 03 30 92 E7 80 00 A0 E1 B3 00 90 E1 02 00 00 E2 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isalnum_4a33f385f78fa744af876ad67c4f69e3 {
	meta:
		aliases = "isalnum"
		size = "40"
		objfiles = "isalnums@libc.a"
	strings:
		$pattern = { 18 20 9F E5 18 30 9F E5 02 20 8F E0 03 30 92 E7 80 00 A0 E1 B3 00 90 E1 02 0B 00 E2 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule iscntrl_8089223ffe7486e042036f876da4f1ae {
	meta:
		aliases = "iscntrl"
		size = "40"
		objfiles = "iscntrls@libc.a"
	strings:
		$pattern = { 18 20 9F E5 18 30 9F E5 02 20 8F E0 03 30 92 E7 80 00 A0 E1 B3 00 90 E1 02 0C 00 E2 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isalpha_98c5938fbb2229b8e866165612ac2eff {
	meta:
		aliases = "isalpha"
		size = "40"
		objfiles = "isalphas@libc.a"
	strings:
		$pattern = { 18 20 9F E5 18 30 9F E5 02 20 8F E0 03 30 92 E7 80 00 A0 E1 B3 00 90 E1 04 00 00 E2 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isxdigit_2173bb8942ff27c613195d27ed0a525f {
	meta:
		aliases = "isxdigit"
		size = "40"
		objfiles = "isxdigits@libc.a"
	strings:
		$pattern = { 18 20 9F E5 18 30 9F E5 02 20 8F E0 03 30 92 E7 80 00 A0 E1 B3 00 90 E1 10 00 00 E2 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isspace_722e6129ff0ac13a96b64a513a172c19 {
	meta:
		aliases = "isspace"
		size = "40"
		objfiles = "isspaces@libc.a"
	strings:
		$pattern = { 18 20 9F E5 18 30 9F E5 02 20 8F E0 03 30 92 E7 80 00 A0 E1 B3 00 90 E1 20 00 00 E2 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isprint_00d8fb09aa4aa0746831dd858ef6e854 {
	meta:
		aliases = "isprint"
		size = "40"
		objfiles = "isprints@libc.a"
	strings:
		$pattern = { 18 20 9F E5 18 30 9F E5 02 20 8F E0 03 30 92 E7 80 00 A0 E1 B3 00 90 E1 40 00 00 E2 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isgraph_08a74e1b86e5b59799a63b118a59e888 {
	meta:
		aliases = "isgraph"
		size = "40"
		objfiles = "isgraphs@libc.a"
	strings:
		$pattern = { 18 20 9F E5 18 30 9F E5 02 20 8F E0 03 30 92 E7 80 00 A0 E1 B3 00 90 E1 80 00 00 E2 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_getpagesize_c5499503477b351d203b817cca132fab {
	meta:
		aliases = "getpagesize, __getpagesize, __GI_getpagesize"
		size = "40"
		objfiles = "getpagesizes@libc.a"
	strings:
		$pattern = { 18 30 9F E5 18 20 9F E5 03 30 8F E0 02 20 93 E7 00 00 92 E5 00 00 50 E3 01 0A A0 03 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule atexit_287ba3e1847c1321c3da23d25f449738 {
	meta:
		aliases = "atexit"
		size = "40"
		objfiles = "atexits@uclibc_nonshared.a, atexits@libc.a"
	strings:
		$pattern = { 18 30 9F E5 18 20 9F E5 03 30 8F E0 02 20 93 E7 00 10 A0 E3 00 00 52 E3 00 20 92 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __re_set_syntax_4d2efd05f2d0e99c7a9f81c549642de9 {
	meta:
		aliases = "re_set_syntax, __re_set_syntax"
		size = "40"
		objfiles = "regex_olds@libc.a"
	strings:
		$pattern = { 18 30 9F E5 18 20 9F E5 03 30 8F E0 02 20 93 E7 00 30 92 E5 00 00 82 E5 03 00 A0 E1 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _dl_add_elf_hash_table_85b2db73dd8a29182ccb04073b01a9c1 {
	meta:
		aliases = "_dl_add_elf_hash_table"
		size = "296"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { 18 C1 9F E5 F0 47 2D E9 14 E1 9F E5 0C C0 8F E0 0E 60 9C E7 00 80 A0 E1 00 50 96 E5 01 70 A0 E1 00 00 55 E3 02 A0 A0 E1 03 90 A0 E1 0C 00 00 1A F0 00 A0 E3 ?? ?? ?? ?? 05 10 A0 E1 00 40 A0 E1 00 20 A0 E1 F0 30 A0 E3 00 00 86 E5 00 00 00 EA 01 10 C2 E4 01 30 53 E2 FC FF FF 2A 10 00 00 EA 04 50 A0 E1 0C 40 95 E5 00 00 54 E3 FB FF FF 1A F0 00 A0 E3 ?? ?? ?? ?? 04 10 A0 E1 00 20 A0 E1 F0 30 A0 E3 0C 00 85 E5 00 00 00 EA 01 10 C2 E4 01 30 53 E2 FC FF FF 2A 0C 30 95 E5 10 50 83 E5 03 40 A0 E1 00 50 A0 E3 0C 50 84 E5 B2 52 C4 E1 08 00 A0 E1 ?? ?? ?? ?? 10 10 9A E5 03 30 A0 E3 05 00 51 E1 01 02 84 E9 }
	condition:
		$pattern
}

rule towupper_34745ea6bc6d54b68adf6c8062c47f88 {
	meta:
		aliases = "__GI_towlower, __GI_towupper, towlower, towupper"
		size = "44"
		objfiles = "towlowers@libc.a, towuppers@libc.a"
	strings:
		$pattern = { 1C 10 9F E5 7F 00 50 E3 01 10 8F E0 1E FF 2F 81 10 20 9F E5 80 30 A0 E1 02 20 91 E7 F2 00 93 E1 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule inl_a1e4c2bbdf4b7de2a870df95bad7e927 {
	meta:
		aliases = "inl"
		size = "44"
		objfiles = "ioperms@libc.a"
	strings:
		$pattern = { 1C 20 9F E5 1C 10 9F E5 02 20 8F E0 01 30 82 E0 08 30 93 E5 01 10 92 E7 10 03 A0 E1 01 00 90 E7 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule inb_205c47211573e08e081306d259907336 {
	meta:
		aliases = "inb"
		size = "44"
		objfiles = "ioperms@libc.a"
	strings:
		$pattern = { 1C 20 9F E5 1C 10 9F E5 02 20 8F E0 01 30 82 E0 08 30 93 E5 01 10 92 E7 10 03 A0 E1 01 00 D0 E7 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule inw_71b8fe72b57e30312d6d2b4ac5681bbe {
	meta:
		aliases = "inw"
		size = "44"
		objfiles = "ioperms@libc.a"
	strings:
		$pattern = { 1C 20 9F E5 1C 10 9F E5 02 20 8F E0 01 30 82 E0 08 30 93 E5 01 10 92 E7 10 03 A0 E1 B1 00 90 E1 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule outl_cfa685f6c778a879f9afab06ba9d9729 {
	meta:
		aliases = "outl"
		size = "44"
		objfiles = "ioperms@libc.a"
	strings:
		$pattern = { 1C 20 9F E5 1C C0 9F E5 02 20 8F E0 0C 30 82 E0 08 30 93 E5 0C C0 92 E7 11 13 A0 E1 0C 00 81 E7 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule outb_19513d4062bdc59fceff3d77e4c4414f {
	meta:
		aliases = "outb"
		size = "44"
		objfiles = "ioperms@libc.a"
	strings:
		$pattern = { 1C 20 9F E5 1C C0 9F E5 02 20 8F E0 0C 30 82 E0 08 30 93 E5 0C C0 92 E7 11 13 A0 E1 0C 00 C1 E7 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule outw_1c0201da65049543d0285ada99414637 {
	meta:
		aliases = "outw"
		size = "44"
		objfiles = "ioperms@libc.a"
	strings:
		$pattern = { 1C 20 9F E5 1C C0 9F E5 02 20 8F E0 0C 30 82 E0 08 30 93 E5 0C C0 92 E7 11 13 A0 E1 BC 00 81 E1 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_attr_getstackaddr_79f4c062d4c3c90096e0e1a82d93ebce {
	meta:
		aliases = "pthread_attr_getstackaddr, __pthread_attr_getstackaddr"
		size = "16"
		objfiles = "attrs@libpthread.a"
	strings:
		$pattern = { 1C 30 90 E5 00 00 A0 E3 00 30 81 E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI_localtime_55b9519280441b97281c0d5db7102ee8 {
	meta:
		aliases = "localtime, __GI_localtime"
		size = "44"
		objfiles = "localtimes@libc.a"
	strings:
		$pattern = { 1C 30 9F E5 10 40 2D E9 18 40 9F E5 03 30 8F E0 04 40 83 E0 04 10 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule seed48_25b6cfbf269a432f88f86fef0923b95e {
	meta:
		aliases = "seed48"
		size = "44"
		objfiles = "seed48s@libc.a"
	strings:
		$pattern = { 1C 30 9F E5 10 40 2D E9 18 40 9F E5 03 30 8F E0 04 40 83 E0 04 10 A0 E1 ?? ?? ?? ?? 06 00 84 E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_mbrlen_6d9d784b48d08cb680ed77d9c9306937 {
	meta:
		aliases = "mbrlen, __GI_mbrlen"
		size = "44"
		objfiles = "mbrlens@libc.a"
	strings:
		$pattern = { 1C C0 9F E5 00 30 52 E2 0C C0 8F E0 01 20 A0 E1 10 30 9F 05 03 30 8C 00 00 10 A0 E1 00 00 A0 E3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __aeabi_unwind_cpp_pr1_f894b471d53671c59fc795612bc9e45b {
	meta:
		aliases = "_pthread_cleanup_push_defer, pthread_handle_sigdebug, _pthread_cleanup_pop_restore, noop_handler, __linuxthreads_death_event, __aeabi_unwind_cpp_pr2, __gcov_merge_delta, __linuxthreads_create_event, __enable_execute_stack, __cyg_profile_func_enter, __stub2, __gcov_flush, __cyg_profile_func_exit, __stub1, pthread_null_sighandler, __gcov_merge_add, __gcov_merge_single, __linuxthreads_reap_event, __aeabi_unwind_cpp_pr0, __gcov_init, _Unwind_Complete, __aeabi_unwind_cpp_pr1"
		size = "4"
		objfiles = "eventss@libpthread.a, _gcov_merge_add@libgcov.a, lckpwdfs@libc.a, signalss@libpthread.a, noophookss@libc.a"
	strings:
		$pattern = { 1E FF 2F E1 }
	condition:
		$pattern
}

rule _dl_linux_resolve_51224eed06ca5afb1111e7f3807eb401 {
	meta:
		aliases = "_dl_linux_resolve"
		size = "32"
		objfiles = "resolves@libdl.a"
	strings:
		$pattern = { 1F 00 2D E9 04 00 1E E5 0C 10 4E E0 41 11 E0 E1 ?? ?? ?? EB 00 C0 A0 E1 1F 40 BD E8 0C F0 A0 E1 }
	condition:
		$pattern
}

rule __paritysi2_308fe0c72921a61bdaa9ae1cd8c7b526 {
	meta:
		aliases = "__paritysi2"
		size = "36"
		objfiles = "_paritysi2@libgcc.a"
	strings:
		$pattern = { 20 08 20 E0 20 04 20 E0 20 02 20 E0 0C 30 9F E5 0F 00 00 E2 53 30 A0 E1 01 00 03 E2 1E FF 2F E1 96 69 00 00 }
	condition:
		$pattern
}

rule toupper_fa4c34b2a67db126f87daa1c917f135f {
	meta:
		aliases = "__GI_toupper, tolower, __GI_tolower, toupper"
		size = "48"
		objfiles = "tolowers@libc.a, touppers@libc.a"
	strings:
		$pattern = { 20 10 9F E5 80 30 80 E2 06 0D 53 E3 01 10 8F E0 1E FF 2F 21 10 20 9F E5 80 30 A0 E1 02 20 91 E7 F2 00 93 E1 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __isinf_54667d13a95ff952bc2e160433485480 {
	meta:
		aliases = "__GI___isinf, __isinf"
		size = "44"
		objfiles = "s_isinfs@libm.a"
	strings:
		$pattern = { 20 20 9F E5 02 31 C1 E3 02 30 23 E0 00 30 83 E1 00 00 63 E2 03 00 80 E1 00 00 50 E3 41 0F A0 A1 00 00 A0 B3 1E FF 2F E1 00 00 F0 7F }
	condition:
		$pattern
}

rule __aeabi_llsl_6b2da880df3defda3552db3a50620b12 {
	meta:
		aliases = "__ashldi3, __aeabi_llsl"
		size = "28"
		objfiles = "_ashldi3@libgcc.a"
	strings:
		$pattern = { 20 30 52 E2 20 C0 62 E2 11 12 A0 41 10 13 A0 51 30 1C 81 41 10 02 A0 E1 1E FF 2F E1 }
	condition:
		$pattern
}

rule __aeabi_llsr_f299e482b0a717dd0bf2a0839e8c6a53 {
	meta:
		aliases = "__lshrdi3, __aeabi_llsr"
		size = "28"
		objfiles = "_lshrdi3@libgcc.a"
	strings:
		$pattern = { 20 30 52 E2 20 C0 62 E2 30 02 A0 41 31 03 A0 51 11 0C 80 41 31 12 A0 E1 1E FF 2F E1 }
	condition:
		$pattern
}

rule __aeabi_lasr_0649f2c135987b66d3c93860637be431 {
	meta:
		aliases = "__ashrdi3, __aeabi_lasr"
		size = "28"
		objfiles = "_ashrdi3@libgcc.a"
	strings:
		$pattern = { 20 30 52 E2 20 C0 62 E2 30 02 A0 41 51 03 A0 51 11 0C 80 41 51 12 A0 E1 1E FF 2F E1 }
	condition:
		$pattern
}

rule pthread_attr_getstacksize_792976c8ac96644d4cde912f814c9246 {
	meta:
		aliases = "__pthread_attr_getstacksize, pthread_attr_getstacksize"
		size = "16"
		objfiles = "attrs@libpthread.a"
	strings:
		$pattern = { 20 30 90 E5 00 00 A0 E3 00 30 81 E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule gmtime_90c06a52dc373fe071d633744b551a90 {
	meta:
		aliases = "gmtime"
		size = "48"
		objfiles = "gmtimes@libc.a"
	strings:
		$pattern = { 20 30 9F E5 10 40 2D E9 1C 40 9F E5 03 30 8F E0 04 40 83 E0 00 10 A0 E3 04 20 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule strerror_0e23d29233fb50431b84fbb235025484 {
	meta:
		aliases = "__GI_strerror, strerror"
		size = "48"
		objfiles = "strerrors@libc.a"
	strings:
		$pattern = { 20 30 9F E5 10 40 2D E9 1C 40 9F E5 03 30 8F E0 04 40 83 E0 04 10 A0 E1 32 20 A0 E3 ?? ?? ?? ?? 04 00 A0 E1 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule htons_e0d98f6cf1c4e4ce519d087070283b98 {
	meta:
		aliases = "ntohs, htons"
		size = "16"
		objfiles = "ntohls@libc.a"
	strings:
		$pattern = { 20 34 A0 E1 FF 00 00 E2 00 04 83 E1 1E FF 2F E1 }
	condition:
		$pattern
}

rule __gnu_Unwind_Save_VFP_47ceeb1ba844f0ed4f3c8e104f79e873 {
	meta:
		aliases = "__gnu_Unwind_Save_VFP"
		size = "152"
		objfiles = "libunwind@libgcc.a"
	strings:
		$pattern = { 21 0B 80 EC 1E FF 2F E1 00 E0 2D E9 FF 1F 2D E9 00 30 A0 E3 0C 00 2D E9 04 10 8D E2 ?? ?? ?? ?? 40 E0 9D E5 48 D0 8D E2 1E FF 2F E1 00 E0 2D E9 FF 1F 2D E9 00 30 A0 E3 0C 00 2D E9 04 10 8D E2 ?? ?? ?? ?? 40 E0 9D E5 48 D0 8D E2 1E FF 2F E1 00 E0 2D E9 FF 1F 2D E9 00 30 A0 E3 0C 00 2D E9 04 10 8D E2 ?? ?? ?? ?? 40 E0 9D E5 48 D0 8D E2 1E FF 2F E1 00 E0 2D E9 FF 1F 2D E9 00 30 A0 E3 0C 00 2D E9 04 30 8D E2 ?? ?? ?? ?? 40 E0 9D E5 48 D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule __gnu_Unwind_Restore_VFP_090cbb07b63eba252ff7a5d182f2c774 {
	meta:
		aliases = "__gnu_Unwind_Restore_VFP"
		size = "160"
		objfiles = "libunwind@libgcc.a"
	strings:
		$pattern = { 21 0B 90 EC 1E FF 2F E1 21 0B 80 EC 1E FF 2F E1 00 E0 2D E9 FF 1F 2D E9 00 30 A0 E3 0C 00 2D E9 04 10 8D E2 ?? ?? ?? ?? 40 E0 9D E5 48 D0 8D E2 1E FF 2F E1 00 E0 2D E9 FF 1F 2D E9 00 30 A0 E3 0C 00 2D E9 04 10 8D E2 ?? ?? ?? ?? 40 E0 9D E5 48 D0 8D E2 1E FF 2F E1 00 E0 2D E9 FF 1F 2D E9 00 30 A0 E3 0C 00 2D E9 04 10 8D E2 ?? ?? ?? ?? 40 E0 9D E5 48 D0 8D E2 1E FF 2F E1 00 E0 2D E9 FF 1F 2D E9 00 30 A0 E3 0C 00 2D E9 04 30 8D E2 ?? ?? ?? ?? 40 E0 9D E5 48 D0 8D E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule lround_bfd4238515339577c76b256028955def {
	meta:
		aliases = "__GI_lround, lround"
		size = "184"
		objfiles = "s_lrounds@libm.a"
	strings:
		$pattern = { 21 3A A0 E1 30 40 2D E9 83 3A A0 E1 A3 3A A0 E1 FF CF 43 E2 00 00 51 E3 03 C0 4C E2 FF 24 C1 E3 01 E0 A0 A3 00 E0 E0 B3 0F 26 C2 E3 13 00 5C E3 04 D0 4D E2 00 40 A0 E1 01 50 A0 E1 01 26 82 E3 0A 00 00 CA 00 00 5C E3 03 00 00 AA 01 00 7C E3 0E 00 A0 01 00 00 A0 13 14 00 00 EA 02 37 A0 E3 53 3C 82 E0 14 20 6C E2 33 02 A0 E1 0E 00 00 EA 1E 00 5C E3 0A 00 00 CA 02 31 A0 E3 14 00 4C E2 33 10 84 E0 04 00 51 E1 01 20 82 32 14 00 5C E3 34 30 6C 12 31 33 A0 11 12 00 83 11 02 00 A0 01 01 00 00 EA ?? ?? ?? ?? 00 00 00 EA 9E 00 00 E0 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule lrint_7749f5c63a92422a86d753e048dc605b {
	meta:
		aliases = "__GI_lrint, lrint"
		size = "324"
		objfiles = "s_lrints@libm.a"
	strings:
		$pattern = { 21 3A A0 E1 F0 40 2D E9 83 3A A0 E1 A3 3A A0 E1 FF 3F 43 E2 03 30 43 E2 1C C1 9F E5 13 00 53 E3 0C D0 4D E2 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 0C C0 8F E0 A1 7F A0 E1 1A 00 00 CA 01 00 73 E3 00 00 A0 B3 3A 00 00 BA 01 30 A0 E1 EC 10 9F E5 05 20 A0 E1 01 10 8C E0 87 11 81 E0 30 00 91 E8 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 03 00 8D E8 03 00 9D E8 05 30 A0 E1 04 20 A0 E1 ?? ?? ?? ?? 21 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF 14 C1 E3 0F 16 C1 E3 41 3E 63 E2 01 16 81 E3 03 30 83 E2 31 03 A0 E1 20 00 00 EA 1E 00 53 E3 1C 00 00 CA 01 30 A0 E1 84 10 9F E5 00 20 A0 E1 01 10 8C E0 87 11 81 E0 30 00 91 E8 }
	condition:
		$pattern
}

rule llround_04c75a28ba38dda5a1dc70c529bc7b7f {
	meta:
		aliases = "__GI_llround, llround"
		size = "292"
		objfiles = "s_llrounds@libm.a"
	strings:
		$pattern = { 21 3A A0 E1 F0 40 2D E9 83 3A A0 E1 A3 3A A0 E1 FF 6F 43 E2 00 00 51 E3 03 60 46 E2 FF 24 C1 E3 01 70 A0 A3 00 70 E0 B3 0F 26 C2 E3 13 00 56 E3 04 D0 4D E2 00 40 A0 E1 01 26 82 E3 0E 00 00 CA 00 00 56 E3 05 00 00 AA 01 00 76 E3 00 50 A0 13 00 60 A0 13 07 50 A0 01 C5 6F A0 01 2C 00 00 EA 02 37 A0 E3 53 36 82 E0 14 20 66 E2 33 32 A0 E1 03 00 A0 E1 00 10 A0 E3 1F 00 00 EA 3E 00 56 E3 19 00 00 CA 33 00 56 E3 08 00 00 DA 02 30 A0 E1 00 40 A0 E3 03 40 A0 E1 00 30 A0 E3 00 00 83 E1 04 10 A0 E1 34 20 46 E2 ?? ?? ?? ?? 12 00 00 EA 14 E0 46 E2 02 31 A0 E3 33 4E 80 E0 00 00 54 E1 01 20 82 32 14 00 56 E3 }
	condition:
		$pattern
}

rule __GI_llrint_602317215aaf51c6b7f2291b1403c9fa {
	meta:
		aliases = "llrint, __GI_llrint"
		size = "424"
		objfiles = "s_llrints@libm.a"
	strings:
		$pattern = { 21 3A A0 E1 F0 41 2D E9 83 3A A0 E1 A3 3A A0 E1 FF 2F 43 E2 03 20 42 E2 80 E1 9F E5 13 00 52 E3 0E E0 8F E0 08 D0 4D E2 00 60 A0 E1 01 70 A0 E1 00 40 A0 E1 00 50 A0 E1 A1 8F A0 E1 1D 00 00 CA 01 30 A0 E1 58 11 9F E5 00 20 A0 E1 01 10 8E E0 88 11 81 E0 30 00 91 E8 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 03 00 8D E8 03 00 9D E8 04 20 A0 E1 05 30 A0 E1 ?? ?? ?? ?? 21 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF 2F 43 E2 03 20 42 E2 00 00 52 E3 FF 34 C1 A3 0F 36 C3 A3 01 36 83 A3 14 20 62 A2 33 32 A0 A1 00 00 A0 B3 00 10 A0 B3 03 00 A0 A1 00 10 A0 A3 33 00 00 EA 3E 00 52 E3 2F 00 00 CA 33 00 52 E3 0A 00 00 DA }
	condition:
		$pattern
}

rule __GI_asctime_r_090a5735bca2e9add4e189634c1c0937 {
	meta:
		aliases = "asctime_r, __GI_asctime_r"
		size = "312"
		objfiles = "asctime_rs@libc.a"
	strings:
		$pattern = { 24 31 9F E5 F0 41 2D E9 20 41 9F E5 03 30 8F E0 04 40 83 E0 01 60 A0 E1 00 70 A0 E1 39 10 84 E2 06 00 A0 E1 1A 20 A0 E3 ?? ?? ?? ?? 18 30 97 E5 06 00 53 E3 03 00 00 8A 03 20 A0 E3 93 42 21 E0 06 00 A0 E1 ?? ?? ?? ?? 10 00 97 E5 0B 00 50 E3 04 00 00 8A 15 30 84 E2 03 20 A0 E3 90 32 21 E0 04 00 86 E2 ?? ?? ?? ?? 14 30 97 E5 13 40 86 E2 76 5E 83 E2 B8 30 9F E5 0C 50 85 E2 03 00 55 E1 0C 00 00 8A 17 40 86 E2 05 00 A0 E1 0A 10 A0 E3 ?? ?? ?? ?? 30 10 81 E2 00 10 C4 E5 05 00 A0 E1 0A 10 A0 E3 ?? ?? ?? ?? 01 30 74 E5 00 50 A0 E1 3F 00 53 E3 F3 FF FF 0A 3F 80 A0 E3 01 30 54 E5 01 60 44 E2 03 50 97 E7 }
	condition:
		$pattern
}

rule vscanf_d6c4aa99fbab787f55c74867e467105f {
	meta:
		aliases = "vprintf, vwprintf, vwscanf, __GI_vscanf, vscanf"
		size = "52"
		objfiles = "vscanfs@libc.a, vprintfs@libc.a, vwscanfs@libc.a, vwprintfs@libc.a"
	strings:
		$pattern = { 24 C0 9F E5 24 30 9F E5 0C C0 8F E0 04 E0 2D E5 03 30 9C E7 00 E0 A0 E1 00 00 93 E5 01 20 A0 E1 0E 10 A0 E1 04 E0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _dl_aux_init_6755c619e85357091b2cc90f9e33f5cc {
	meta:
		aliases = "_dl_aux_init"
		size = "60"
		objfiles = "dl_supports@libc.a"
	strings:
		$pattern = { 28 20 9F E5 28 30 9F E5 02 20 8F E0 04 E0 2D E5 03 E0 92 E7 1C 30 9F E5 1C 10 90 E5 03 C0 92 E7 2C 30 90 E5 00 10 8C E5 00 30 8E E5 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ptsname_69242ed4f4771ad4c341f850daedcd6c {
	meta:
		aliases = "ptsname"
		size = "56"
		objfiles = "ptsnames@libc.a"
	strings:
		$pattern = { 28 30 9F E5 10 40 2D E9 24 40 9F E5 03 30 8F E0 04 40 83 E0 04 10 A0 E1 1E 20 A0 E3 ?? ?? ?? ?? 00 00 50 E3 04 00 A0 01 00 00 A0 13 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ttyname_68222b6af257bf8f12c80bdae4d52560 {
	meta:
		aliases = "ttyname"
		size = "56"
		objfiles = "ttynames@libc.a"
	strings:
		$pattern = { 28 30 9F E5 10 40 2D E9 24 40 9F E5 03 30 8F E0 04 40 83 E0 04 10 A0 E1 20 20 A0 E3 ?? ?? ?? ?? 00 00 50 E3 04 00 A0 01 00 00 A0 13 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isdigit_f7ff7822cbed587442ecdfcc78f775bf {
	meta:
		aliases = "isdigit"
		size = "20"
		objfiles = "isdigits@libc.a"
	strings:
		$pattern = { 30 00 40 E2 09 00 50 E3 00 00 A0 83 01 00 A0 93 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI___fsetlocking_36d750d801b184c43c95c6fae7b035f2 {
	meta:
		aliases = "__fsetlocking, __GI___fsetlocking"
		size = "64"
		objfiles = "__fsetlockings@libc.a"
	strings:
		$pattern = { 30 20 9F E5 00 00 51 E3 02 20 8F E0 34 C0 90 E5 05 00 00 0A 02 00 51 E3 01 30 A0 03 18 30 9F 15 03 30 92 17 00 30 93 15 34 30 80 E5 01 00 0C E2 01 00 80 E2 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule dlerror_99f5ecd1626c6d65f8d442a911e4d6c9 {
	meta:
		aliases = "dlerror"
		size = "68"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { 30 20 9F E5 30 30 9F E5 02 20 8F E0 03 10 92 E7 00 00 91 E5 00 00 50 E3 1E FF 2F 01 1C 30 9F E5 03 30 82 E0 00 21 93 E7 00 30 A0 E3 02 00 A0 E1 00 30 81 E5 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_getchar_unlocked_4bf5393a51ba2812a67df466eeccd015 {
	meta:
		aliases = "getchar_unlocked, __GI_getchar_unlocked"
		size = "64"
		objfiles = "getchar_unlockeds@libc.a"
	strings:
		$pattern = { 30 30 9F E5 30 20 9F E5 03 30 8F E0 02 20 93 E7 00 20 92 E5 10 10 92 E5 18 30 92 E5 03 00 51 E1 01 00 00 3A 02 00 A0 E1 ?? ?? ?? ?? 01 00 D1 E4 10 10 82 E5 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule dl_cleanup_b774e79414536cef5c047afb9010386a {
	meta:
		aliases = "dl_cleanup"
		size = "64"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { 30 30 9F E5 30 20 9F E5 03 30 8F E0 10 40 2D E9 02 20 93 E7 00 40 92 E5 01 00 00 EA 04 40 94 E5 2D FF FF EB 00 00 54 E3 04 00 A0 E1 01 10 A0 E3 F9 FF FF 1A 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule calloc_448c01ef00078a94f43bc6d5b8ffb925 {
	meta:
		aliases = "calloc"
		size = "104"
		objfiles = "callocs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 00 50 E3 04 D0 4D E2 01 50 A0 E1 90 01 04 E0 09 00 00 0A 00 10 A0 E1 04 00 A0 E1 ?? ?? ?? ?? 00 00 55 E1 04 00 00 0A ?? ?? ?? ?? 00 50 A0 E3 0C 30 A0 E3 00 30 80 E5 06 00 00 EA 04 00 A0 E1 ?? ?? ?? ?? 00 50 50 E2 02 00 00 0A 04 20 A0 E1 00 10 A0 E3 ?? ?? ?? ?? 05 00 A0 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __sigpause_6f34244aa483e2d33a2fa983eeef892e {
	meta:
		aliases = "__GI___sigpause, __sigpause"
		size = "120"
		objfiles = "sigpauses@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 00 51 E3 84 D0 4D E2 00 50 A0 E1 00 00 8D 05 0D 40 A0 E1 04 00 8D 02 1E 30 A0 03 0B 00 00 0A 00 00 A0 E3 00 10 A0 E1 0D 20 A0 E1 ?? ?? ?? ?? 00 00 50 E3 0B 00 00 BA 0D 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 03 00 00 AA 05 00 00 EA 01 30 53 E2 04 10 80 E4 FC FF FF 5A 0D 00 A0 E1 ?? ?? ?? ?? 00 00 00 EA 00 00 E0 E3 84 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule sem_trywait_70c4392b38686a0d56d24e40eacb7035 {
	meta:
		aliases = "__new_sem_trywait, sem_trywait"
		size = "84"
		objfiles = "semaphores@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 00 10 A0 E3 00 40 A0 E1 04 D0 4D E2 ?? ?? ?? ?? 08 30 94 E5 00 00 53 E3 04 00 00 1A ?? ?? ?? ?? 00 50 E0 E3 0B 30 A0 E3 00 30 80 E5 02 00 00 EA 01 30 43 E2 08 30 84 E5 00 50 A0 E3 04 00 A0 E1 ?? ?? ?? ?? 05 00 A0 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule pthread_rwlock_trywrlock_86402d78940bd6cfe97b5a916da05ce5 {
	meta:
		aliases = "pthread_rwlock_trywrlock"
		size = "80"
		objfiles = "rwlocks@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 00 10 A0 E3 00 40 A0 E1 04 D0 4D E2 ?? ?? ?? ?? 08 30 94 E5 00 00 53 E3 05 00 00 1A 0C 50 94 E5 00 00 55 E3 02 00 00 1A CB FF FF EB 0C 00 84 E5 00 00 00 EA 10 50 A0 E3 04 00 A0 E1 ?? ?? ?? ?? 05 00 A0 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule pthread_cond_signal_209b4df9366305a9c8066a1f38de8fed {
	meta:
		aliases = "__GI_pthread_cond_signal, pthread_cond_signal"
		size = "88"
		objfiles = "condvars@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 00 10 A0 E3 04 D0 4D E2 00 50 A0 E1 ?? ?? ?? ?? 08 40 95 E5 05 00 A0 E1 00 00 54 E3 08 30 94 15 08 30 85 15 00 30 A0 13 08 30 84 15 ?? ?? ?? ?? 00 00 54 E3 03 00 00 0A 01 30 A0 E3 B9 31 C4 E5 04 00 A0 E1 A8 FE FF EB 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __fixdfdi_e622ab6d03e81e53d2cccb0b7936853b {
	meta:
		aliases = "__aeabi_d2lz, __fixdfdi"
		size = "84"
		objfiles = "_fixdfdi@libgcc.a"
	strings:
		$pattern = { 30 40 2D E9 00 20 A0 E3 04 D0 4D E2 00 30 A0 E3 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? ?? 00 00 50 E3 04 00 00 1A 04 00 A0 E1 05 10 A0 E1 04 D0 8D E2 30 40 BD E8 ?? ?? ?? ?? 04 00 A0 E1 02 11 85 E2 ?? ?? ?? ?? 00 00 70 E2 00 10 E1 E2 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_wcstod_bff6a271e00d7d58930895c6d28e0c11 {
	meta:
		aliases = "strtod, wcstod, __GI_strtod, __GI_wcstod"
		size = "52"
		objfiles = "wcstods@libc.a, strtods@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 20 A0 E3 04 D0 4D E2 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 05 10 A0 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_callmsg_4fc8d93f9895ab5b9511ef34900dec09 {
	meta:
		aliases = "__GI_xdr_callmsg, xdr_callmsg"
		size = "1448"
		objfiles = "rpc_cmsgs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 30 90 E5 04 D0 4D E2 00 00 53 E3 00 50 A0 E1 01 40 A0 E1 7E 00 00 1A 20 10 91 E5 19 0E 51 E3 5A 01 00 8A 2C 30 94 E5 19 0E 53 E3 57 01 00 8A 03 10 81 E2 03 30 83 E2 03 30 C3 E3 03 10 C1 E3 03 10 81 E0 28 10 81 E2 04 30 90 E5 0F E0 A0 E1 18 F0 93 E5 00 00 50 E3 6D 00 00 0A 00 10 94 E5 00 C0 A0 E1 FF 28 01 E2 21 3C A0 E1 22 34 83 E1 FF 2C 01 E2 02 34 83 E1 01 3C 83 E1 04 30 8C E4 04 10 94 E5 FF 28 01 E2 21 3C A0 E1 22 34 83 E1 FF 2C 01 E2 02 34 83 E1 01 3C 83 E1 04 30 80 E5 04 30 94 E5 00 00 53 E3 38 01 00 1A 08 10 94 E5 04 E0 8C E2 FF 28 01 E2 21 3C A0 E1 22 34 83 E1 FF 2C 01 E2 }
	condition:
		$pattern
}

rule xdr_double_0bfcbf86146ef962e37b04231d89fb25 {
	meta:
		aliases = "xdr_double"
		size = "156"
		objfiles = "xdr_floats@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 30 90 E5 04 D0 4D E2 01 00 53 E3 00 40 A0 E1 01 50 A0 E1 10 00 00 0A 03 00 00 3A 02 00 53 E3 00 00 A0 13 01 00 A0 03 18 00 00 EA 04 30 90 E5 04 10 81 E2 0F E0 A0 E1 04 F0 93 E5 00 00 50 E3 12 00 00 0A 04 00 A0 E1 05 10 A0 E1 04 30 94 E5 0F E0 A0 E1 04 F0 93 E5 0A 00 00 EA 04 30 90 E5 04 10 81 E2 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 06 00 00 0A 04 00 A0 E1 05 10 A0 E1 04 30 94 E5 0F E0 A0 E1 00 F0 93 E5 00 00 50 E2 01 00 A0 13 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_xdr_rmtcallres_1bf9bb3c4cfed6e3207def575130a015 {
	meta:
		aliases = "xdr_rmtcallres, __GI_xdr_rmtcallres"
		size = "128"
		objfiles = "pmap_rmts@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 30 91 E5 0C D0 4D E2 01 40 A0 E1 60 C0 9F E5 08 10 8D E2 04 30 21 E5 58 30 9F E5 0C C0 8F E0 03 30 8C E0 04 20 A0 E3 00 50 A0 E1 ?? ?? ?? ?? 00 00 50 E3 0B 00 00 0A 05 00 A0 E1 04 10 84 E2 ?? ?? ?? ?? 00 00 50 E3 06 00 00 0A 04 30 9D E5 05 00 A0 E1 00 30 84 E5 08 10 94 E5 0F E0 A0 E1 0C F0 94 E5 00 00 00 EA 00 00 A0 E3 0C D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_xdr_callhdr_9406a87b251fea1b584d54ecc17434a7 {
	meta:
		aliases = "xdr_callhdr, __GI_xdr_callhdr"
		size = "148"
		objfiles = "rpc_prots@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 30 A0 E3 04 30 81 E5 02 30 83 E2 08 30 81 E5 00 30 90 E5 04 D0 4D E2 00 00 53 E3 01 50 A0 E1 00 40 A0 E1 16 00 00 1A ?? ?? ?? ?? 00 00 50 E3 13 00 00 0A 04 00 A0 E1 04 10 85 E2 ?? ?? ?? ?? 00 00 50 E3 0E 00 00 0A 04 00 A0 E1 08 10 85 E2 ?? ?? ?? ?? 00 00 50 E3 09 00 00 0A 04 00 A0 E1 0C 10 85 E2 ?? ?? ?? ?? 00 00 50 E3 04 00 00 0A 04 00 A0 E1 10 10 85 E2 04 D0 8D E2 30 40 BD E8 ?? ?? ?? ?? 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule pathconf_b1acde9d1c5030620de656f858e7e782 {
	meta:
		aliases = "pathconf"
		size = "316"
		objfiles = "pathconfs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 30 D0 E5 9C D0 4D E2 00 00 53 E3 00 40 A0 E1 03 00 00 1A ?? ?? ?? ?? 00 20 E0 E3 02 30 A0 E3 1B 00 00 EA 13 00 51 E3 01 F1 8F 90 15 00 00 EA 19 00 00 EA 35 00 00 EA 34 00 00 EA 18 00 00 EA 36 00 00 EA 35 00 00 EA 36 00 00 EA 35 00 00 EA 22 00 00 EA 2F 00 00 EA 22 00 00 EA 2D 00 00 EA 2C 00 00 EA 05 00 00 EA 2A 00 00 EA 29 00 00 EA 28 00 00 EA 27 00 00 EA 26 00 00 EA 25 00 00 EA 20 20 A0 E3 28 00 00 EA ?? ?? ?? ?? 00 20 E0 E3 16 30 A0 E3 00 30 80 E5 23 00 00 EA 7F 20 A0 E3 21 00 00 EA ?? ?? ?? ?? 58 10 8D E2 00 50 A0 E1 04 00 A0 E1 00 40 95 E5 ?? ?? ?? ?? 00 00 50 E3 7C 20 9D A5 }
	condition:
		$pattern
}

rule __negvdi2_4d7169de8c7209d6e73fe99a84da3dcb {
	meta:
		aliases = "__negvdi2"
		size = "92"
		objfiles = "_negvdi2@libgcc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 70 E2 00 50 E1 E2 00 00 51 E3 04 D0 4D E2 A5 3F A0 B1 03 00 00 BA 00 00 55 E3 00 30 A0 E3 07 00 00 DA 01 30 A0 E3 FF 30 03 E2 00 00 53 E3 07 00 00 1A 04 00 A0 E1 05 10 A0 E1 04 D0 8D E2 30 80 BD E8 F7 FF FF 1A 00 00 54 E3 F5 FF FF 9A F3 FF FF EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_strsep_e00f1c920fc1a17e503b2ebde1915719 {
	meta:
		aliases = "strsep, __GI_strsep"
		size = "136"
		objfiles = "strseps@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 04 D0 4D E2 00 00 54 E3 00 50 A0 E1 18 00 00 0A 00 20 D1 E5 00 00 52 E3 0F 00 00 0A 01 30 D1 E5 00 00 53 E3 09 00 00 1A 00 30 D4 E5 02 00 53 E1 04 00 A0 01 0A 00 00 0A 00 00 53 E3 06 00 00 0A 02 10 A0 E1 01 00 84 E2 ?? ?? ?? ?? 04 00 00 EA 04 00 A0 E1 ?? ?? ?? ?? 01 00 00 EA 00 00 A0 E3 02 00 00 EA 00 00 50 E3 00 30 A0 13 01 30 C0 14 00 00 85 E5 04 00 A0 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_u_long_e3e0b9d77f615aeb6b56bf1e27bd9e18 {
	meta:
		aliases = "__GI_xdr_u_long, xdr_u_long"
		size = "112"
		objfiles = "xdrs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 0C D0 4D E2 01 00 54 E3 01 50 A0 E1 04 00 00 0A 0D 00 00 3A 02 00 54 E3 01 00 A0 03 0F 00 00 0A 0D 00 00 EA 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 04 30 9D 15 04 00 A0 11 00 30 85 15 05 00 00 1A 03 00 00 EA 04 30 90 E5 0F E0 A0 E1 04 F0 93 E5 00 00 00 EA 00 00 A0 E3 0C D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_uint8_t_9676eac65e0b1ba9563a67218da44cf2 {
	meta:
		aliases = "xdr_uint8_t"
		size = "120"
		objfiles = "xdr_intXX_ts@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 0C D0 4D E2 01 00 54 E3 01 50 A0 E1 0B 00 00 0A 03 00 00 3A 02 00 54 E3 01 00 A0 03 11 00 00 0A 0F 00 00 EA 00 30 D1 E5 08 10 8D E2 04 30 21 E5 04 30 90 E5 0F E0 A0 E1 24 F0 93 E5 09 00 00 EA 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 04 30 9D 15 04 00 A0 11 00 30 C5 15 00 00 00 1A 00 00 A0 E3 0C D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_u_short_50bda2283b4fbcc325f6c1a111c524da {
	meta:
		aliases = "__GI_xdr_u_short, xdr_u_short"
		size = "120"
		objfiles = "xdrs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 0C D0 4D E2 01 00 54 E3 01 50 A0 E1 0B 00 00 0A 03 00 00 3A 02 00 54 E3 01 00 A0 03 11 00 00 0A 0F 00 00 EA B0 30 D1 E1 08 10 8D E2 04 30 21 E5 04 30 90 E5 0F E0 A0 E1 04 F0 93 E5 09 00 00 EA 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 B4 30 DD 11 04 00 A0 11 B0 30 C5 11 00 00 00 1A 00 00 A0 E3 0C D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_uint16_t_b9493b909f1a062dd63782007cd706bf {
	meta:
		aliases = "xdr_uint16_t"
		size = "120"
		objfiles = "xdr_intXX_ts@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 0C D0 4D E2 01 00 54 E3 01 50 A0 E1 0B 00 00 0A 03 00 00 3A 02 00 54 E3 01 00 A0 03 11 00 00 0A 0F 00 00 EA B0 30 D1 E1 08 10 8D E2 04 30 21 E5 04 30 90 E5 0F E0 A0 E1 24 F0 93 E5 09 00 00 EA 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 B4 30 DD 11 04 00 A0 11 B0 30 C5 11 00 00 00 1A 00 00 A0 E3 0C D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_int8_t_f001582a55108ff158e74c7c0d051cca {
	meta:
		aliases = "xdr_int8_t"
		size = "120"
		objfiles = "xdr_intXX_ts@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 0C D0 4D E2 01 00 54 E3 01 50 A0 E1 0B 00 00 0A 03 00 00 3A 02 00 54 E3 01 00 A0 03 11 00 00 0A 0F 00 00 EA D0 30 D1 E1 08 10 8D E2 04 30 21 E5 04 30 90 E5 0F E0 A0 E1 24 F0 93 E5 09 00 00 EA 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 04 30 9D 15 04 00 A0 11 00 30 C5 15 00 00 00 1A 00 00 A0 E3 0C D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_xdr_short_51e9a9dad9bacb96ca30c5ae3b480abb {
	meta:
		aliases = "xdr_short, __GI_xdr_short"
		size = "120"
		objfiles = "xdrs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 0C D0 4D E2 01 00 54 E3 01 50 A0 E1 0B 00 00 0A 03 00 00 3A 02 00 54 E3 01 00 A0 03 11 00 00 0A 0F 00 00 EA F0 30 D1 E1 08 10 8D E2 04 30 21 E5 04 30 90 E5 0F E0 A0 E1 04 F0 93 E5 09 00 00 EA 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 B4 30 DD 11 04 00 A0 11 B0 30 C5 11 00 00 00 1A 00 00 A0 E3 0C D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_int16_t_19667baea59c657a5fa86ed8f357ea9f {
	meta:
		aliases = "xdr_int16_t"
		size = "120"
		objfiles = "xdr_intXX_ts@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 0C D0 4D E2 01 00 54 E3 01 50 A0 E1 0B 00 00 0A 03 00 00 3A 02 00 54 E3 01 00 A0 03 11 00 00 0A 0F 00 00 EA F0 30 D1 E1 08 10 8D E2 04 30 21 E5 04 30 90 E5 0F E0 A0 E1 24 F0 93 E5 09 00 00 EA 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 B4 30 DD 11 04 00 A0 11 B0 30 C5 11 00 00 00 1A 00 00 A0 E3 0C D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_bool_1e10e80f8f2304e73f3a7fa06d6bd10e {
	meta:
		aliases = "__GI_xdr_bool, xdr_bool"
		size = "140"
		objfiles = "xdrs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 0C D0 4D E2 01 00 54 E3 01 50 A0 E1 0D 00 00 0A 03 00 00 3A 02 00 54 E3 01 00 A0 03 16 00 00 0A 14 00 00 EA 00 30 91 E5 08 10 8D E2 00 30 53 E2 01 30 A0 13 04 30 21 E5 04 30 90 E5 0F E0 A0 E1 04 F0 93 E5 0C 00 00 EA 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 05 00 00 0A 04 30 9D E5 04 00 A0 E1 00 30 53 E2 01 30 A0 13 00 30 85 E5 00 00 00 EA 00 00 A0 E3 0C D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __addvdi3_69cb4cba54cb0f1d139ab389751cd126 {
	meta:
		aliases = "__addvdi3"
		size = "116"
		objfiles = "_addvdi3@libgcc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 92 E0 01 50 A3 E0 00 00 53 E3 04 D0 4D E2 0E 00 00 BA 05 00 51 E1 00 30 A0 E3 07 00 00 DA 01 30 A0 E3 FF 30 03 E2 00 00 53 E3 0E 00 00 1A 04 00 A0 E1 05 10 A0 E1 04 D0 8D E2 30 80 BD E8 F7 FF FF 1A 04 00 50 E1 F5 FF FF 9A F3 FF FF EA 01 00 55 E1 00 30 A0 E3 F0 FF FF CA F0 FF FF 1A 00 00 54 E1 EE FF FF 9A EC FF FF EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __regfree_8e547197413bad078da9a2f2355196bc {
	meta:
		aliases = "regfree, __regfree"
		size = "80"
		objfiles = "regex_olds@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 00 50 A0 E3 04 D0 4D E2 00 00 90 E5 ?? ?? ?? ?? 10 00 94 E5 00 50 84 E5 04 50 84 E5 08 50 84 E5 ?? ?? ?? ?? 1C 30 D4 E5 10 50 84 E5 08 30 C3 E3 1C 30 C4 E5 14 00 94 E5 ?? ?? ?? ?? 14 50 84 E5 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule carg_d57a02b4c20085648c7ead8bea6d4c4c {
	meta:
		aliases = "__GI_carg, carg"
		size = "36"
		objfiles = "cargs@libm.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 01 50 A0 E1 02 00 A0 E1 03 10 A0 E1 04 20 A0 E1 05 30 A0 E1 30 40 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __subvdi3_774084db54b62711aa423d151ea43170 {
	meta:
		aliases = "__subvdi3"
		size = "124"
		objfiles = "_subvdi3@libgcc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 01 50 A0 E1 02 40 54 E0 03 50 C5 E0 00 00 53 E3 04 D0 4D E2 0E 00 00 BA 01 00 55 E1 00 30 A0 E3 07 00 00 DA 01 30 A0 E3 FF 30 03 E2 00 00 53 E3 0E 00 00 1A 04 00 A0 E1 05 10 A0 E1 04 D0 8D E2 30 80 BD E8 F7 FF FF 1A 00 00 54 E1 F5 FF FF 9A F3 FF FF EA 05 00 51 E1 00 30 A0 E3 F0 FF FF CA F0 FF FF 1A 04 00 50 E1 EE FF FF 9A EC FF FF EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule unwind_phase2_745343c66bfe73fca0213e19f820cc4a {
	meta:
		aliases = "unwind_phase2"
		size = "92"
		objfiles = "unwind_arm@libgcc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 04 D0 4D E2 01 50 A0 E1 04 00 A0 E1 40 10 95 E5 1A FF FF EB 00 00 50 E3 0A 00 00 1A 40 30 95 E5 01 00 A0 E3 14 30 84 E5 04 10 A0 E1 05 20 A0 E1 0F E0 A0 E1 10 F0 94 E5 08 00 50 E3 F1 FF FF 0A 07 00 50 E3 00 00 00 0A ?? ?? ?? ?? 04 00 85 E2 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fpathconf_e9d517c582cb0c358f8bec435796064e {
	meta:
		aliases = "fpathconf"
		size = "316"
		objfiles = "fpathconfs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 50 E2 9C D0 4D E2 03 00 00 AA ?? ?? ?? ?? 00 20 E0 E3 09 30 A0 E3 1E 00 00 EA 00 00 51 E3 7F 20 A0 03 40 00 00 0A 01 30 41 E2 12 00 53 E3 03 F1 8F 90 14 00 00 EA 34 00 00 EA 33 00 00 EA 16 00 00 EA 35 00 00 EA 34 00 00 EA 35 00 00 EA 34 00 00 EA 20 00 00 EA 2E 00 00 EA 20 00 00 EA 2C 00 00 EA 2B 00 00 EA 05 00 00 EA 29 00 00 EA 28 00 00 EA 27 00 00 EA 26 00 00 EA 25 00 00 EA 24 00 00 EA 20 20 A0 E3 27 00 00 EA ?? ?? ?? ?? 00 20 E0 E3 16 30 A0 E3 00 30 80 E5 22 00 00 EA ?? ?? ?? ?? 58 10 8D E2 00 40 A0 E1 05 00 A0 E1 00 50 94 E5 ?? ?? ?? ?? 00 00 50 E3 7C 20 9D A5 19 00 00 AA }
	condition:
		$pattern
}

rule __GI_if_freenameindex_06281365554df444293e7415f901bc7b {
	meta:
		aliases = "if_freenameindex, __GI_if_freenameindex"
		size = "68"
		objfiles = "if_indexs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 A0 E1 04 D0 4D E2 00 40 A0 E1 01 00 00 EA ?? ?? ?? ?? 08 40 84 E2 04 30 94 E5 00 00 53 E2 FA FF FF 1A 00 30 94 E5 00 00 53 E3 F7 FF FF 1A 05 00 A0 E1 04 D0 8D E2 30 40 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __old_sem_trywait_f844927815bc2fcacc05648b59319385 {
	meta:
		aliases = "__old_sem_trywait"
		size = "104"
		objfiles = "oldsemaphores@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 A0 E1 04 D0 4D E2 00 C0 95 E5 05 00 A0 E1 01 30 2C E2 01 30 03 E2 01 00 5C E3 03 40 A0 11 01 40 83 03 00 00 54 E3 0C 10 A0 E1 02 20 4C E2 04 00 00 0A ?? ?? ?? ?? 0B 30 A0 E3 00 20 E0 E3 00 30 80 E5 03 00 00 EA E9 FF FF EB 00 00 50 E3 EC FF FF 0A 04 20 A0 E1 02 00 A0 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule vswprintf_a800caeb8460d7a5c595ad494977155e {
	meta:
		aliases = "__GI_vswprintf, vswprintf"
		size = "168"
		objfiles = "vswprintfs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 C0 A0 E1 00 00 E0 E1 20 51 A0 E1 54 D0 4D E2 01 00 55 E1 01 50 A0 21 02 10 A0 E1 03 20 A0 E1 02 30 E0 E3 00 E0 A0 E3 05 41 8C E0 04 30 8D E5 0D 00 A0 E1 85 3E A0 E3 B0 30 CD E1 20 E0 8D E5 0C 40 8D E5 1C C0 8D E5 02 E0 CD E5 2C E0 8D E5 08 C0 8D E5 10 C0 8D E5 14 C0 8D E5 18 C0 8D E5 ?? ?? ?? ?? 10 20 9D E5 0C 30 9D E5 03 00 52 E1 05 00 00 1A 00 00 55 E3 00 00 E0 03 06 00 00 0A 04 30 42 E2 10 30 8D E5 00 00 E0 E3 00 00 55 E3 10 30 9D 15 00 20 A0 13 00 20 83 15 54 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_wcsnrtombs_7ff0d9730c156d77876de060d62e20ac {
	meta:
		aliases = "wcsnrtombs, __GI_wcsnrtombs"
		size = "172"
		objfiles = "wcsnrtombss@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 00 50 E1 00 00 50 13 14 D0 4D E2 00 E0 A0 E1 01 40 A0 13 05 00 00 1A 00 00 50 E3 0E 40 A0 01 0D E0 A0 11 00 40 A0 13 0D E0 A0 01 00 30 E0 03 02 00 53 E1 03 50 A0 31 02 50 A0 21 00 20 91 E5 05 00 A0 E1 0F 00 00 EA 00 30 92 E5 04 20 82 E2 7F 00 53 E3 FF C0 03 E2 04 00 00 9A ?? ?? ?? ?? 54 30 A0 E3 00 20 E0 E3 00 30 80 E5 0A 00 00 EA 00 00 5C E3 00 C0 CE E5 0C 20 A0 01 03 00 00 0A 04 E0 8E E0 01 00 40 E2 00 00 50 E3 ED FF FF 1A 0D 00 5E E1 00 20 81 15 05 20 60 E0 02 00 A0 E1 14 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule pthread_setcancelstate_bd75506cbc90e7d2fe68478e441f0960 {
	meta:
		aliases = "__GI_pthread_setcancelstate, pthread_setcancelstate"
		size = "96"
		objfiles = "cancels@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 01 00 50 E3 00 50 A0 E1 04 D0 4D E2 01 40 A0 E1 16 00 A0 83 0E 00 00 8A 50 FF FF EB 00 00 54 E3 40 30 D0 15 00 30 84 15 42 30 D0 E5 40 50 C0 E5 00 00 53 E3 05 00 00 0A B0 34 D0 E1 01 0C 53 E3 02 00 00 1A 00 00 E0 E3 0D 10 A0 E1 ?? ?? ?? ?? 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_pthread_setcanceltype_62fe76ec0582381981135a28f4ff3539 {
	meta:
		aliases = "pthread_setcanceltype, __GI_pthread_setcanceltype"
		size = "96"
		objfiles = "cancels@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 01 00 50 E3 00 50 A0 E1 04 D0 4D E2 01 40 A0 E1 16 00 A0 83 0E 00 00 8A 68 FF FF EB 00 00 54 E3 41 30 D0 15 00 30 84 15 42 30 D0 E5 41 50 C0 E5 00 00 53 E3 05 00 00 0A B0 34 D0 E1 01 0C 53 E3 02 00 00 1A 00 00 E0 E3 0D 10 A0 E1 ?? ?? ?? ?? 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule setegid_a42763d99881c6b380466ead19039267 {
	meta:
		aliases = "__GI_seteuid, seteuid, setegid"
		size = "116"
		objfiles = "setegids@libc.a, seteuids@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 00 70 E3 04 D0 4D E2 00 40 A0 E1 04 00 00 1A ?? ?? ?? ?? 04 50 A0 E1 16 30 A0 E3 00 30 80 E5 0F 00 00 EA 00 00 E0 E3 04 10 A0 E1 00 20 A0 E1 ?? ?? ?? ?? 01 00 70 E3 00 50 A0 E1 08 00 00 1A ?? ?? ?? ?? 00 30 90 E5 26 00 53 E3 04 00 00 1A 05 00 A0 E1 04 10 A0 E1 04 D0 8D E2 30 40 BD E8 ?? ?? ?? ?? 05 00 A0 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __aeabi_uread8_746dc05ae0d53354b0744e7e38dc6fc5 {
	meta:
		aliases = "__aeabi_uread8"
		size = "64"
		objfiles = "unaligned_funcs@libgcc.a"
	strings:
		$pattern = { 30 40 2D E9 01 10 D0 E5 00 20 D0 E5 02 E0 D0 E5 04 30 D0 E5 05 40 D0 E5 06 C0 D0 E5 01 24 82 E1 0E 28 82 E1 03 50 D0 E5 07 E0 D0 E5 04 34 83 E1 0C 38 83 E1 05 0C 82 E1 0E 1C 83 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule __xstat_conv_cab4ae78a8421ad2b37a0cd6dd1d0a3a {
	meta:
		aliases = "__xstat_conv"
		size = "180"
		objfiles = "xstatconvs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 50 A0 E1 00 40 A0 E1 00 10 A0 E3 58 20 A0 E3 04 D0 4D E2 05 00 A0 E1 ?? ?? ?? ?? 04 10 94 E5 00 20 94 E5 0C 10 85 E5 14 C0 94 E5 10 00 94 E5 2C C0 85 E5 18 C0 94 E5 00 30 A0 E3 30 C0 85 E5 1C C0 94 E5 0C 00 85 E8 34 C0 85 E5 20 C0 94 E5 00 10 A0 E3 38 C0 85 E5 28 30 94 E5 20 00 85 E5 24 10 85 E5 40 30 85 E5 30 30 94 E5 B8 C0 D4 E1 48 30 85 E5 24 30 94 E5 BA 00 D4 E1 3C 30 85 E5 2C 30 94 E5 BC 10 D4 E1 44 30 85 E5 34 30 94 E5 BE 20 D4 E1 4C 30 85 E5 10 C0 85 E5 14 00 85 E5 18 10 85 E5 1C 20 85 E5 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_copysign_68d41e05e5978f1da1a7b5aa33e8e5c0 {
	meta:
		aliases = "copysign, __GI_copysign"
		size = "36"
		objfiles = "s_copysigns@libm.a"
	strings:
		$pattern = { 30 40 2D E9 01 50 A0 E1 00 40 A0 E1 02 31 03 E2 02 01 C5 E3 00 20 83 E1 02 10 A0 E1 04 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule fdopen_9e3e5c217bc0cdcdc542af74ccf2fb5a {
	meta:
		aliases = "__GI_fdopen, fdopen"
		size = "68"
		objfiles = "fdopens@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 50 A0 E1 04 D0 4D E2 03 10 A0 E3 00 40 A0 E1 ?? ?? ?? ?? 01 00 70 E3 05 00 00 0A 05 10 A0 E1 04 30 A0 E1 00 20 A0 E3 04 D0 8D E2 30 40 BD E8 ?? ?? ?? ?? 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule sigset_66f696f8d8f3cae90092e6f4c247d5f0 {
	meta:
		aliases = "sigset"
		size = "320"
		objfiles = "sigsets@libc.a"
	strings:
		$pattern = { 30 40 2D E9 02 00 51 E3 67 DF 4D E2 00 40 A0 E1 20 20 A0 03 00 10 A0 03 01 00 00 0A 12 00 00 EA 80 10 03 E5 01 20 52 E2 66 0F 8D E2 02 31 80 E0 FA FF FF 5A 46 5F 8D E2 04 10 A0 E1 05 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 38 00 00 BA 00 00 A0 E3 00 20 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 02 20 A0 A3 32 00 00 AA 30 00 00 EA 01 00 71 E3 00 00 50 13 00 30 A0 C3 01 30 A0 D3 04 00 00 DA 40 00 50 E3 03 00 A0 D1 20 20 A0 D3 8C 10 8D D5 05 00 00 DA ?? ?? ?? ?? 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 22 00 00 EA 08 01 03 E5 01 20 52 E2 66 1F 8D E2 02 31 81 E0 FA FF FF 5A 00 50 A0 E3 8C 10 8D E2 04 00 A0 E1 }
	condition:
		$pattern
}

rule _dl_parse_dynamic_info_3c488e3a7e8b3ab5a64f43f52fcd70cc {
	meta:
		aliases = "_dl_parse_dynamic_info"
		size = "296"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { 30 40 2D E9 02 40 A0 E1 03 E0 A0 E1 01 20 A0 E3 00 50 A0 E3 27 00 00 EA 21 00 5C E3 19 00 00 CA 04 30 90 E5 15 00 5C E3 0C 31 81 E7 00 30 90 E5 04 40 80 05 18 00 53 E3 00 30 90 E5 60 20 81 05 1E 00 53 E3 02 00 00 1A 04 30 90 E5 08 00 13 E3 60 20 81 15 00 30 90 E5 16 00 53 E3 00 30 90 E5 58 20 81 05 1D 00 53 E3 00 30 90 E5 3C 50 81 05 0F 00 53 E3 0E 00 00 1A 74 30 91 E5 00 00 53 E3 3C 50 81 15 0A 00 00 EA 19 02 7C E3 08 00 00 CA 69 02 7C E3 04 30 90 05 88 30 81 05 00 30 90 E5 59 02 73 E3 02 00 00 1A 04 30 90 E5 01 00 13 E3 60 20 81 15 08 00 80 E2 00 C0 90 E5 00 00 5C E3 D4 FF FF 1A 10 30 91 E5 }
	condition:
		$pattern
}

rule forkpty_49b95cd0b3540f460907e7a706308b92 {
	meta:
		aliases = "forkpty"
		size = "140"
		objfiles = "forkptys@libutil.a"
	strings:
		$pattern = { 30 40 2D E9 02 C0 A0 E1 14 D0 4D E2 00 30 8D E5 01 20 A0 E1 00 50 A0 E1 0C 30 A0 E1 0C 00 8D E2 08 10 8D E2 ?? ?? ?? ?? 01 00 70 E3 12 00 00 0A ?? ?? ?? ?? 01 00 70 E3 00 40 A0 E1 0E 00 00 0A 00 00 50 E3 07 00 00 1A 0C 00 9D E5 ?? ?? ?? ?? 08 00 9D E5 ?? ?? ?? ?? 00 00 50 E3 07 00 00 0A 01 00 A0 E3 ?? ?? ?? ?? 0C 30 9D E5 08 00 9D E5 00 30 85 E5 ?? ?? ?? ?? 00 00 00 EA 00 40 E0 E3 04 00 A0 E1 14 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_globfree64_e8573727fe06fe7ed60f112a78b4ad75 {
	meta:
		aliases = "globfree64, __GI_globfree, globfree, __GI_globfree64"
		size = "96"
		objfiles = "glob64s@libc.a, globs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 30 90 E5 04 D0 4D E2 00 00 53 E3 00 40 A0 E1 00 50 A0 13 07 00 00 1A 0D 00 00 EA 0C 00 94 E9 03 30 85 E0 03 31 92 E7 01 50 85 E2 00 00 53 E2 00 00 00 0A ?? ?? ?? ?? 00 30 94 E5 03 00 55 E1 F5 FF FF 3A 04 00 94 E5 ?? ?? ?? ?? 00 30 A0 E3 04 30 84 E5 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule on_exit_90f856a94503847ed90c81b6ade24119 {
	meta:
		aliases = "on_exit"
		size = "56"
		objfiles = "on_exits@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? ?? 00 00 50 E3 02 30 A0 13 00 30 80 15 04 40 80 15 08 50 80 15 00 00 E0 03 00 00 A0 13 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_xdr_pmap_54f3b8c1bbfa4b240beaf5d345c7c885 {
	meta:
		aliases = "xdr_pmap, __GI_xdr_pmap"
		size = "100"
		objfiles = "pmap_prots@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? ?? 00 00 50 E3 0E 00 00 0A 04 00 A0 E1 04 10 85 E2 ?? ?? ?? ?? 00 00 50 E3 09 00 00 0A 04 00 A0 E1 08 10 85 E2 ?? ?? ?? ?? 00 00 50 E3 04 00 00 0A 04 00 A0 E1 0C 10 85 E2 04 D0 8D E2 30 40 BD E8 ?? ?? ?? ?? 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_internal_tsd_set_837843fedd2021b6e5b57df4235bad08 {
	meta:
		aliases = "__pthread_internal_tsd_set"
		size = "40"
		objfiles = "specifics@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 00 40 A0 E1 01 50 A0 E1 C6 FF FF EB 04 01 80 E0 6C 51 80 E5 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_opaque_auth_de56573b9865ad127eac60226043f8ac {
	meta:
		aliases = "__GI_xdr_opaque_auth, xdr_opaque_auth"
		size = "64"
		objfiles = "rpc_prots@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 00 50 A0 E1 01 40 A0 E1 ?? ?? ?? ?? 00 00 50 E3 06 00 00 0A 05 00 A0 E1 08 20 84 E2 04 10 84 E2 19 3E A0 E3 04 D0 8D E2 30 40 BD E8 ?? ?? ?? ?? 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_rejected_reply_99101da29e3f3166f9ce6aee5442ca37 {
	meta:
		aliases = "__GI_xdr_rejected_reply, xdr_rejected_reply"
		size = "124"
		objfiles = "rpc_prots@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 00 50 A0 E1 01 40 A0 E1 ?? ?? ?? ?? 00 00 50 E3 14 00 00 0A 00 30 94 E5 00 00 53 E3 02 00 00 0A 01 00 53 E3 0F 00 00 1A 09 00 00 EA 05 00 A0 E1 04 10 84 E2 ?? ?? ?? ?? 00 00 50 E3 09 00 00 0A 05 00 A0 E1 08 10 84 E2 04 D0 8D E2 30 40 BD E8 ?? ?? ?? ?? 05 00 A0 E1 04 10 84 E2 04 D0 8D E2 30 40 BD E8 ?? ?? ?? ?? 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_xdr_accepted_reply_34fcee677929027ed6e54bd7b3280571 {
	meta:
		aliases = "xdr_accepted_reply, __GI_xdr_accepted_reply"
		size = "148"
		objfiles = "rpc_prots@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 00 50 A0 E1 01 40 A0 E1 ?? ?? ?? ?? 00 00 50 E3 1A 00 00 0A 05 00 A0 E1 0C 10 84 E2 ?? ?? ?? ?? 00 00 50 E3 15 00 00 0A 0C 30 94 E5 00 00 53 E3 03 00 00 0A 02 00 53 E3 01 00 A0 13 10 00 00 1A 04 00 00 EA 05 00 A0 E1 10 10 94 E5 0F E0 A0 E1 14 F0 94 E5 0A 00 00 EA 05 00 A0 E1 10 10 84 E2 ?? ?? ?? ?? 00 00 50 E3 04 00 00 0A 05 00 A0 E1 14 10 84 E2 04 D0 8D E2 30 40 BD E8 ?? ?? ?? ?? 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_mempcpy_3e2609694c060d11e346d49086ab2613 {
	meta:
		aliases = "mempcpy, __GI_mempcpy"
		size = "32"
		objfiles = "mempcpys@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 00 50 A0 E1 02 40 A0 E1 ?? ?? ?? ?? 04 00 85 E0 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_setrpcent_cec957d2a632829bf58b2a10941ad383 {
	meta:
		aliases = "setrpcent, __GI_setrpcent"
		size = "124"
		objfiles = "getrpcents@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 00 50 A0 E1 43 FF FF EB 58 30 9F E5 00 40 50 E2 03 30 8F E0 11 00 00 0A 00 00 94 E5 00 00 50 E3 06 00 00 1A 40 00 9F E5 40 10 9F E5 00 00 83 E0 01 10 83 E0 ?? ?? ?? ?? 00 00 84 E5 00 00 00 EA ?? ?? ?? ?? 04 00 94 E5 ?? ?? ?? ?? 0C 30 94 E5 05 30 83 E1 0C 30 84 E5 00 30 A0 E3 04 30 84 E5 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_handle_sigcancel_56e5a898f66ff92065ad5f97c4b629fd {
	meta:
		aliases = "pthread_handle_sigcancel"
		size = "232"
		objfiles = "pthreads@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 00 50 A0 E1 57 FD FF EB BC 40 9F E5 BC 30 9F E5 04 40 8F E0 03 20 94 E7 02 00 50 E1 03 00 00 1A 05 00 A0 E1 04 D0 8D E2 30 40 BD E8 ?? ?? ?? ?? 9C 30 9F E5 03 30 94 E7 00 30 93 E5 00 00 53 E3 0C 00 00 0A 8C 30 9F E5 03 30 94 E7 00 30 93 E5 03 00 50 E1 03 00 00 1A 14 00 92 E5 00 10 A0 E3 02 21 A0 E3 ?? ?? ?? ?? 6C 30 9F E5 03 30 94 E7 00 00 93 E5 ?? ?? ?? ?? 42 30 D0 E5 00 00 53 E3 0F 00 00 0A 40 20 D0 E5 00 00 52 E3 0C 00 00 1A 41 30 D0 E5 01 00 53 E3 02 00 00 1A 00 00 E0 E3 0D 10 A0 E1 ?? ?? ?? ?? 28 30 90 E5 00 00 53 E3 03 00 00 0A 28 20 80 E5 01 10 A0 E3 03 00 A0 E1 }
	condition:
		$pattern
}

rule getttynam_f00692d441c217a443dcd8eb795c3ae2 {
	meta:
		aliases = "getttynam"
		size = "68"
		objfiles = "getttyents@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 00 50 A0 E1 ?? ?? ?? ?? 03 00 00 EA 00 10 94 E5 ?? ?? ?? ?? 00 00 50 E3 03 00 00 0A ?? ?? ?? ?? 00 40 50 E2 05 00 A0 E1 F7 FF FF 1A ?? ?? ?? ?? 04 00 A0 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule cuserid_04733c7fff8ee980a258d8abebcb21b8 {
	meta:
		aliases = "cuserid"
		size = "80"
		objfiles = "getlogins@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 00 50 A0 E1 ?? ?? ?? ?? 30 40 9F E5 00 00 55 E3 00 10 A0 E1 04 40 8F E0 06 00 00 0A 00 00 50 E3 1C 30 9F 05 03 10 84 00 05 00 A0 E1 04 D0 8D E2 30 40 BD E8 ?? ?? ?? ?? 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_getrpcbynumber_456af6f1603ca687f2fa4b2562ca2d3a {
	meta:
		aliases = "getrpcbynumber, __GI_getrpcbynumber"
		size = "80"
		objfiles = "getrpcents@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 00 50 A0 E1 CB FE FF EB 00 00 50 E3 00 40 A0 01 09 00 00 0A 00 00 A0 E3 ?? ?? ?? ?? 02 00 00 EA 08 30 94 E5 05 00 53 E1 02 00 00 0A ?? ?? ?? ?? 00 40 50 E2 F9 FF FF 1A ?? ?? ?? ?? 04 00 A0 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule significand_43e2c57dd3b716b56df3a634c175e3e4 {
	meta:
		aliases = "significand"
		size = "56"
		objfiles = "s_significands@libm.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 01 50 A0 E1 00 40 A0 E1 ?? ?? ?? ?? 00 00 60 E2 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 04 D0 8D E2 30 40 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule jrand48_r_1f39f54815182cf4de2dfaa76d19eb08 {
	meta:
		aliases = "__GI_jrand48_r, jrand48_r"
		size = "56"
		objfiles = "jrand48_rs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 02 50 A0 E1 00 40 A0 E1 ?? ?? ?? ?? 00 00 50 E3 B2 30 D4 A1 B4 20 D4 A1 00 00 E0 B3 02 38 83 A1 00 00 A0 A3 00 30 85 A5 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_nrand48_r_30af65e094db49e48fdc21583a791520 {
	meta:
		aliases = "nrand48_r, __GI_nrand48_r"
		size = "60"
		objfiles = "nrand48_rs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 02 50 A0 E1 00 40 A0 E1 ?? ?? ?? ?? 00 00 50 E3 B4 30 D4 A1 B2 20 D4 A1 83 37 A0 A1 A2 30 83 A1 00 00 E0 B3 00 00 A0 A3 00 30 85 A5 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_endrpcent_1900c37a9d28d7c68d09b30e6af77835 {
	meta:
		aliases = "endrpcent, __GI_endrpcent"
		size = "72"
		objfiles = "getrpcents@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 25 FF FF EB 00 40 50 E2 0A 00 00 0A 0C 50 94 E5 00 00 55 E3 07 00 00 1A 04 00 94 E5 ?? ?? ?? ?? 00 00 94 E5 04 50 84 E5 00 00 50 E3 01 00 00 0A ?? ?? ?? ?? 00 50 84 E5 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule svc_exit_3d00e087380bc1b67e78a5dd675e2d25 {
	meta:
		aliases = "svc_exit"
		size = "48"
		objfiles = "svc_runs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 ?? ?? ?? ?? 00 50 A0 E3 00 40 A0 E1 00 00 90 E5 ?? ?? ?? ?? 00 50 84 E5 ?? ?? ?? ?? 00 50 80 E5 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule svcraw_create_adb16a8b40eee7d8d486751234b9f4c6 {
	meta:
		aliases = "svcraw_create"
		size = "168"
		objfiles = "svc_raws@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 ?? ?? ?? ?? BC 40 90 E5 7C 50 9F E5 00 00 54 E3 05 50 8F E0 06 00 00 1A 01 00 A0 E3 6C 10 9F E5 ?? ?? ?? ?? 00 00 50 E3 04 00 A0 01 14 00 00 0A 00 40 A0 E1 58 30 9F E5 58 10 9F E5 00 E0 A0 E3 54 20 9F E5 01 10 85 E0 B3 E0 84 E1 8E CD 84 E2 04 30 83 E2 03 10 84 E7 2C C0 8C E2 1C 30 83 E2 8E 0D 84 E2 03 C0 84 E7 14 00 80 E2 02 E0 84 E7 04 10 A0 E1 02 30 A0 E3 ?? ?? ?? ?? 89 0D 84 E2 20 00 80 E2 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? 3C 25 00 00 64 22 00 00 ?? ?? ?? ?? 60 22 00 00 }
	condition:
		$pattern
}

rule __GI_seed48_r_9e9ab8c4d6a5ae09606f95c0f875c9bb {
	meta:
		aliases = "seed48_r, __GI_seed48_r"
		size = "100"
		objfiles = "seed48_rs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 06 20 A0 E3 00 50 A0 E1 04 D0 4D E2 02 00 81 E0 01 40 A0 E1 ?? ?? ?? ?? B4 30 D5 E1 38 20 9F E5 B4 30 C4 E1 B2 30 D5 E1 00 00 A0 E3 B2 30 C4 E1 05 30 A0 E3 B0 50 D5 E1 10 20 84 E5 14 30 84 E5 01 30 A0 E3 BE 30 C4 E1 0B 30 A0 E3 B0 50 C4 E1 BC 30 C4 E1 04 D0 8D E2 30 80 BD E8 6D E6 EC DE }
	condition:
		$pattern
}

rule pthread_mutex_lock_8d41be199b68b8290627197718357468 {
	meta:
		aliases = "__pthread_mutex_lock, pthread_mutex_lock"
		size = "204"
		objfiles = "mutexs@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 0C 30 90 E5 04 D0 4D E2 00 40 A0 E1 03 00 53 E3 03 F1 8F 90 03 00 00 EA 04 00 00 EA 07 00 00 EA 16 00 00 EA 21 00 00 EA 16 00 A0 E3 23 00 00 EA 10 00 80 E2 00 10 A0 E3 ?? ?? ?? ?? 1E 00 00 EA 4D FF FF EB 08 30 94 E5 00 50 A0 E1 00 00 53 E1 04 30 94 05 00 00 A0 03 01 30 83 02 05 00 00 0A 10 00 84 E2 05 10 A0 E1 ?? ?? ?? ?? 00 30 A0 E3 03 00 A0 E1 08 50 84 E5 04 30 84 E5 0F 00 00 EA 3D FF FF EB 08 30 94 E5 00 50 A0 E1 00 00 53 E1 23 00 A0 03 09 00 00 0A 10 00 84 E2 05 10 A0 E1 ?? ?? ?? ?? 00 00 A0 E3 08 50 84 E5 03 00 00 EA 10 00 80 E2 00 10 A0 E3 ?? ?? ?? ?? 00 00 A0 E3 04 D0 8D E2 }
	condition:
		$pattern
}

rule pthread_mutex_trylock_14598586806747ce452b7442b4d66051 {
	meta:
		aliases = "__pthread_mutex_trylock, pthread_mutex_trylock"
		size = "208"
		objfiles = "mutexs@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 0C 30 90 E5 04 D0 4D E2 00 40 A0 E1 03 00 53 E3 03 F1 8F 90 03 00 00 EA 04 00 00 EA 0A 00 00 EA 19 00 00 EA 1F 00 00 EA 16 50 A0 E3 23 00 00 EA 14 20 80 E2 01 30 A0 E3 93 30 02 E1 00 00 53 E3 10 50 A0 13 00 50 A0 03 1C 00 00 EA 99 FE FF EB 08 30 94 E5 00 20 A0 E1 00 00 53 E1 04 30 94 05 00 50 A0 03 01 30 83 02 04 30 84 05 13 00 00 0A 01 00 A0 E3 14 30 84 E2 90 00 03 E1 00 00 50 E3 10 50 A0 13 0D 00 00 1A 0A 00 00 EA 10 00 80 E2 24 FE FF EB 00 50 50 E2 08 00 00 1A 85 FE FF EB 08 00 84 E5 05 00 00 EA 10 00 80 E2 04 D0 8D E2 30 40 BD E8 1B FE FF EA 00 50 A0 E1 05 00 84 E9 05 00 A0 E1 }
	condition:
		$pattern
}

rule __pthread_mutex_unlock_9d8fe7979ad86a556b8dcc7555e36ce7 {
	meta:
		aliases = "pthread_mutex_unlock, __pthread_mutex_unlock"
		size = "204"
		objfiles = "mutexs@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 0C 30 90 E5 04 D0 4D E2 00 50 A0 E1 03 00 53 E3 03 F1 8F 90 03 00 00 EA 04 00 00 EA 06 00 00 EA 14 00 00 EA 20 00 00 EA 16 00 A0 E3 23 00 00 EA 10 00 80 E2 ?? ?? ?? ?? 1D 00 00 EA C6 FF FF EB 08 30 95 E5 00 00 53 E1 1B 00 00 1A 04 30 95 E5 00 00 53 E3 01 30 43 C2 00 00 A0 C3 04 30 85 C5 16 00 00 CA 00 40 A0 E3 08 40 85 E5 10 00 85 E2 ?? ?? ?? ?? 0A 00 00 EA B7 FF FF EB 08 30 95 E5 00 00 53 E1 0C 00 00 1A 10 30 95 E5 00 00 53 E3 09 00 00 0A 00 40 A0 E3 08 40 85 E5 10 00 85 E2 ?? ?? ?? ?? 04 00 A0 E1 04 00 00 EA 10 00 80 E2 ?? ?? ?? ?? 00 00 A0 E3 00 00 00 EA 01 00 A0 E3 04 D0 8D E2 }
	condition:
		$pattern
}

rule __GI_xdrrec_skiprecord_d8de570bf82d8bf408d9e8c3e4572f8b {
	meta:
		aliases = "xdrrec_skiprecord, __GI_xdrrec_skiprecord"
		size = "120"
		objfiles = "xdr_recs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C 40 90 E5 04 D0 4D E2 00 50 A0 E3 0A 00 00 EA 86 FF FF EB 00 00 50 E3 12 00 00 0A 38 30 94 E5 34 50 84 E5 00 00 53 E3 03 00 00 1A 04 00 A0 E1 B7 FF FF EB 00 00 50 E3 0A 00 00 0A 34 30 94 E5 04 00 A0 E1 00 10 53 E2 F0 FF FF CA 38 30 94 E5 00 00 53 E3 ED FF FF 0A 00 30 A0 E3 01 00 A0 E3 38 30 84 E5 00 00 00 EA 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_xdrrec_eof_25c550e5e50254e5ec05461dd7edb063 {
	meta:
		aliases = "xdrrec_eof, __GI_xdrrec_eof"
		size = "128"
		objfiles = "xdr_recs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C 40 90 E5 04 D0 4D E2 00 50 A0 E3 0A 00 00 EA A6 FF FF EB 00 00 50 E3 14 00 00 0A 38 30 94 E5 34 50 84 E5 00 00 53 E3 03 00 00 1A 04 00 A0 E1 D7 FF FF EB 00 00 50 E3 0C 00 00 0A 34 30 94 E5 04 00 A0 E1 00 10 53 E2 F0 FF FF CA 38 30 94 E5 00 00 53 E3 ED FF FF 0A 30 20 94 E5 2C 30 94 E5 02 00 53 E1 00 00 A0 13 01 00 A0 03 00 00 00 EA 01 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule _authenticate_5b21a2669db2a5ac4542619c27a340a3 {
	meta:
		aliases = "__GI__authenticate, _authenticate"
		size = "132"
		objfiles = "svc_auths@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C C0 80 E2 18 30 81 E2 64 40 9F E5 00 E0 A0 E1 01 50 A0 E1 07 00 93 E8 58 30 9F E5 07 00 8C E8 04 40 8F E0 03 30 94 E7 1C 20 9E E5 00 30 93 E5 04 D0 4D E2 20 30 82 E5 0C C0 9E E5 1C 20 9E E5 03 00 5C E3 00 30 A0 E3 28 30 82 E5 02 00 A0 83 05 00 00 8A 20 30 9F E5 0E 00 A0 E1 03 30 84 E0 05 10 A0 E1 0F E0 A0 E1 0C F1 93 E7 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule nanosleep_7a5eb85ad41bf87c1d96f6b810d176c8 {
	meta:
		aliases = "__GI_nanosleep, nanosleep"
		size = "68"
		objfiles = "wrapsyscalls@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 0C D0 4D E2 00 40 A0 E1 01 50 A0 E1 01 00 A0 E3 04 10 8D E2 ?? ?? ?? ?? 05 10 A0 E1 04 00 A0 E1 ?? ?? ?? ?? 00 10 A0 E3 00 40 A0 E1 04 00 9D E5 ?? ?? ?? ?? 04 00 A0 E1 0C D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule cond_extricate_func_52c9d81e8feae740a66a314e108e0422 {
	meta:
		aliases = "cond_extricate_func"
		size = "72"
		objfiles = "condvars@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 0C D0 4D E2 00 50 A0 E1 01 40 A0 E1 D2 FF FF EB 04 00 8D E5 04 10 9D E5 05 00 A0 E1 ?? ?? ?? ?? 04 10 A0 E1 08 00 85 E2 74 FF FF EB 00 40 A0 E1 05 00 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 0C D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule new_sem_extricate_func_d8b0caeab49fd6dea38af531d485660e {
	meta:
		aliases = "new_sem_extricate_func"
		size = "72"
		objfiles = "semaphores@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 0C D0 4D E2 00 50 A0 E1 01 40 A0 E1 D2 FF FF EB 04 00 8D E5 04 10 9D E5 05 00 A0 E1 ?? ?? ?? ?? 04 10 A0 E1 0C 00 85 E2 52 FF FF EB 00 40 A0 E1 05 00 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 0C D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule re_exec_cdbc98f9ec5b275a52dbbb32e64e289c {
	meta:
		aliases = "re_exec"
		size = "88"
		objfiles = "regex_olds@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C D0 4D E2 00 50 A0 E1 ?? ?? ?? ?? 38 40 9F E5 00 E0 A0 E1 34 00 9F E5 00 C0 A0 E3 04 40 8F E0 00 00 84 E0 05 10 A0 E1 0E 20 A0 E1 0C 30 A0 E1 00 E0 8D E5 04 C0 8D E5 ?? ?? ?? ?? 00 00 E0 E1 A0 0F A0 E1 0C D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule join_extricate_func_a58784bbda7fec700a0de7b8e04841fa {
	meta:
		aliases = "join_extricate_func"
		size = "76"
		objfiles = "joins@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 0C D0 4D E2 00 50 A0 E1 D3 FF FF EB 04 00 8D E5 04 10 9D E5 05 00 A0 E1 ?? ?? ?? ?? 08 20 95 E5 00 30 A0 E3 38 40 92 E5 05 00 A0 E1 38 30 82 E5 03 40 54 E0 01 40 A0 13 ?? ?? ?? ?? 04 00 A0 E1 0C D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule getrlimit64_ff7ffa65020e6cf9b5ce91960a685df3 {
	meta:
		aliases = "getrlimit64"
		size = "108"
		objfiles = "getrlimit64s@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C D0 4D E2 01 50 A0 E1 0D 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 00 E0 B3 10 00 00 BA 00 30 9D E5 01 00 73 E3 00 30 E0 03 00 40 A0 13 00 40 E0 03 18 00 85 E8 04 30 9D E5 01 00 73 E3 00 30 E0 03 00 40 E0 03 00 00 A0 03 08 30 85 05 0C 40 85 05 00 40 A0 13 08 30 85 15 0C 40 85 15 00 00 A0 13 0C D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule initgroups_c209b45c79c763b7b4bc2f81ffe8729c {
	meta:
		aliases = "initgroups"
		size = "72"
		objfiles = "initgroupss@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C D0 4D E2 08 20 8D E2 02 31 E0 E3 04 30 22 E5 ?? ?? ?? ?? 00 40 50 E2 00 50 E0 03 05 00 00 0A 04 00 9D E5 04 10 A0 E1 ?? ?? ?? ?? 00 50 A0 E1 04 00 A0 E1 ?? ?? ?? ?? 05 00 A0 E1 0C D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_fgetpwent_r_9fa88fa5d830423a6a58c038fb524758 {
	meta:
		aliases = "fgetpwent_r, __GI_fgetspent_r, __GI_fgetgrent_r, fgetspent_r, fgetgrent_r, __GI_fgetpwent_r"
		size = "72"
		objfiles = "fgetpwent_rs@libc.a, fgetspent_rs@libc.a, fgetgrent_rs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C D0 4D E2 18 50 9D E5 00 00 8D E5 28 C0 9F E5 00 00 A0 E3 00 00 85 E5 20 00 9F E5 0C C0 8F E0 00 00 8C E0 01 40 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 40 85 05 0C D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mbsnrtowcs_12b75da684549ace3e4cee7aae9cb90a {
	meta:
		aliases = "__GI_mbsnrtowcs, mbsnrtowcs"
		size = "216"
		objfiles = "mbsnrtowcss@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C D0 4D E2 18 E0 9D E5 BC 40 9F E5 00 00 5E E3 04 40 8F E0 01 50 A0 E1 02 10 A0 E1 00 C0 A0 E1 03 20 A0 E1 A4 30 9F 05 03 E0 84 00 0E 00 5C E1 00 00 5C 13 01 00 A0 13 05 00 00 1A 00 00 5C E3 04 30 8D E2 03 C0 A0 11 00 00 A0 13 03 C0 A0 01 00 20 E0 03 01 00 52 E1 01 20 A0 21 00 E0 95 E5 00 41 A0 E1 02 00 A0 E1 0E 00 00 EA 00 30 DE E5 01 E0 8E E2 00 00 53 E3 00 30 8C E5 03 E0 A0 01 0A 00 00 0A 7F 00 53 E3 04 00 00 9A ?? ?? ?? ?? 54 30 A0 E3 00 20 E0 E3 00 30 80 E5 07 00 00 EA 04 C0 8C E0 01 00 40 E2 00 00 50 E3 EE FF FF 1A 04 30 8D E2 03 00 5C E1 00 E0 85 15 02 20 60 E0 02 00 A0 E1 }
	condition:
		$pattern
}

rule __GI___fgetc_unlocked_beb825d2f521bcc80a96e370776fce02 {
	meta:
		aliases = "__fgetc_unlocked, __GI_getc_unlocked, getc_unlocked, fgetc_unlocked, __GI_fgetc_unlocked, __GI___fgetc_unlocked"
		size = "300"
		objfiles = "fgetc_unlockeds@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 20 90 E5 18 30 90 E5 00 40 A0 E1 03 00 52 E1 08 51 9F E5 01 00 D2 34 05 50 8F E0 0C D0 4D E2 10 20 84 35 3B 00 00 3A B0 30 D4 E1 83 30 03 E2 80 00 53 E3 03 00 00 8A 80 10 A0 E3 ?? ?? ?? ?? 00 00 50 E3 32 00 00 1A B0 20 D4 E1 02 00 12 E3 08 00 00 0A 01 30 02 E2 03 31 84 E0 24 30 D3 E5 01 20 42 E2 03 00 A0 E1 00 30 A0 E3 28 30 84 E5 B0 20 C4 E1 27 00 00 EA 10 10 94 E5 14 30 94 E5 01 00 53 E1 01 00 D1 14 10 10 84 15 21 00 00 1A 04 30 94 E5 02 00 73 E3 04 30 82 03 00 00 E0 03 B0 30 C4 01 1B 00 00 0A 03 0C 12 E3 02 00 00 0A 6C 30 9F E5 03 00 95 E7 ?? ?? ?? ?? 08 20 94 E5 0C 30 94 E5 }
	condition:
		$pattern
}

rule putc_unlocked_4ae31791216565c1b8edd92af6f943cb {
	meta:
		aliases = "__GI___fputc_unlocked, fputc_unlocked, __GI_putc_unlocked, __fputc_unlocked, putc_unlocked"
		size = "260"
		objfiles = "fputc_unlockeds@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 20 91 E5 1C 30 91 E5 0C D0 4D E2 03 00 52 E1 01 40 A0 E1 00 50 A0 E1 FF 30 00 32 01 30 C2 34 03 00 A0 31 10 20 81 35 32 00 00 3A B0 30 D1 E1 C0 30 03 E2 C0 00 53 E3 04 00 00 0A 01 00 A0 E1 80 10 A0 E3 ?? ?? ?? ?? 00 00 50 E3 28 00 00 1A 04 30 94 E5 02 00 73 E3 23 00 00 0A 0C 20 94 E5 08 30 94 E5 03 00 52 E1 18 00 00 0A 10 30 94 E5 03 00 52 E1 03 00 00 1A 04 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 1A 00 00 1A 10 30 94 E5 FF 10 05 E2 01 10 C3 E4 B0 20 D4 E1 10 30 84 E5 01 0C 12 E3 11 00 00 0A 0A 00 51 E3 0F 00 00 1A 04 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 0B 00 00 0A 10 30 94 E5 00 00 E0 E3 }
	condition:
		$pattern
}

rule getprotobyname_b3ef2266f4003768928f95e79ae308d2 {
	meta:
		aliases = "getprotobyname"
		size = "88"
		objfiles = "getprotos@libc.a"
	strings:
		$pattern = { 30 40 2D E9 14 D0 4D E2 00 50 A0 E1 34 40 9F E5 42 FE FF EB 0C 30 8D E2 00 30 8D E5 28 10 9F E5 28 30 9F E5 04 40 8F E0 03 20 94 E7 05 00 A0 E1 01 10 84 E0 18 30 9F E5 ?? ?? ?? ?? 0C 00 9D E5 14 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D 10 00 00 }
	condition:
		$pattern
}

rule getprotobynumber_a4eb04844ae3481d19f181357a41e839 {
	meta:
		aliases = "getprotobynumber"
		size = "88"
		objfiles = "getprotos@libc.a"
	strings:
		$pattern = { 30 40 2D E9 14 D0 4D E2 00 50 A0 E1 34 40 9F E5 9F FE FF EB 0C 30 8D E2 00 30 8D E5 28 10 9F E5 28 30 9F E5 04 40 8F E0 03 20 94 E7 05 00 A0 E1 01 10 84 E0 18 30 9F E5 ?? ?? ?? ?? 0C 00 9D E5 14 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D 10 00 00 }
	condition:
		$pattern
}

rule sem_wait_ecb3223939d5446b6b8c2f54d906131a {
	meta:
		aliases = "__new_sem_wait, sem_wait"
		size = "340"
		objfiles = "semaphores@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 14 D0 4D E2 00 50 A0 E1 4F FF FF EB 34 41 9F E5 34 31 9F E5 0C 00 8D E5 04 40 8F E0 03 30 84 E0 0C 10 9D E5 05 00 A0 E1 08 30 8D E5 04 50 8D E5 ?? ?? ?? ?? 08 30 95 E5 00 00 53 E3 04 00 00 DA 01 30 43 E2 08 30 85 E5 05 00 A0 E1 ?? ?? ?? ?? 39 00 00 EA 0C 20 9D E5 00 30 A0 E3 BA 31 C2 E5 0C 00 9D E5 04 10 8D E2 D2 FE FF EB 0C 30 9D E5 42 30 D3 E5 00 00 53 E3 04 00 00 0A 0C 30 9D E5 40 30 D3 E5 00 00 53 E3 01 40 A0 03 03 00 00 0A 0C 10 9D E5 0C 00 85 E2 A6 FE FF EB 00 40 A0 E3 05 00 A0 E1 ?? ?? ?? ?? 00 00 54 E3 04 00 00 0A 0C 00 9D E5 00 10 A0 E3 BE FE FF EB 00 00 E0 E3 1B 00 00 EA }
	condition:
		$pattern
}

rule __GI_gethostbyname_03687237ba0f99dc3f8cd40199d010a6 {
	meta:
		aliases = "gethostbyname, __GI_gethostbyname"
		size = "88"
		objfiles = "gethostbynames@libc.a"
	strings:
		$pattern = { 30 40 2D E9 14 D0 4D E2 00 50 A0 E1 ?? ?? ?? ?? 34 40 9F E5 34 20 9F E5 34 10 9F E5 04 40 8F E0 04 00 8D E5 0C C0 8D E2 02 20 84 E0 05 00 A0 E1 01 10 84 E0 73 3F A0 E3 00 C0 8D E5 ?? ?? ?? ?? 0C 00 9D E5 14 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _ppfs_prepargs_bf89cbdaf39ecac7ed227accca18d957 {
	meta:
		aliases = "_ppfs_prepargs"
		size = "64"
		objfiles = "_ppfs_prepargss@libc.a"
	strings:
		$pattern = { 30 40 2D E9 18 50 90 E5 04 D0 4D E2 00 00 55 E3 00 40 A0 E1 4C 10 80 E5 06 00 00 DA 00 30 A0 E3 08 30 80 E5 1C 50 80 E5 18 30 80 E5 04 30 80 E5 ?? ?? ?? ?? 18 50 84 E5 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI__rpc_dtablesize_5b1b178343933980e137f9faec8850b6 {
	meta:
		aliases = "_rpc_dtablesize, __GI__rpc_dtablesize"
		size = "60"
		objfiles = "rpc_dtablesizes@libc.a"
	strings:
		$pattern = { 30 40 2D E9 28 40 9F E5 28 50 9F E5 04 40 8F E0 05 30 94 E7 04 D0 4D E2 00 00 53 E3 01 00 00 1A ?? ?? ?? ?? 05 00 84 E7 05 00 94 E7 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_manager_event_c067d3212af2577f7af50295da2ca532 {
	meta:
		aliases = "__pthread_manager_event"
		size = "64"
		objfiles = "managers@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 2C 20 9F E5 2C 30 9F E5 02 20 8F E0 03 40 92 E7 00 50 A0 E1 00 10 A0 E3 1C 00 94 E5 04 D0 4D E2 ?? ?? ?? ?? 1C 00 94 E5 ?? ?? ?? ?? 05 00 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __rpc_thread_variables_e823a94a2d622e8b03ed664ef495cfc0 {
	meta:
		aliases = "__rpc_thread_variables"
		size = "340"
		objfiles = "rpc_threads@libc.a"
	strings:
		$pattern = { 30 40 2D E9 2C 51 9F E5 2C 31 9F E5 05 50 8F E0 03 30 95 E7 04 D0 4D E2 00 00 53 E3 02 00 00 0A 02 00 A0 E3 33 FF 2F E1 02 00 00 EA 0C 31 9F E5 03 30 95 E7 00 00 93 E5 00 00 50 E3 1B 00 00 1A FC 30 9F E5 FC 40 9F E5 03 30 95 E7 00 00 53 E3 04 00 00 0A F0 10 9F E5 04 00 85 E0 01 10 85 E0 33 FF 2F E1 05 00 00 EA 04 30 95 E7 00 00 53 E3 02 00 00 1A CE FF FF EB 01 30 A0 E3 04 30 85 E7 B4 30 9F E5 03 30 95 E7 00 00 53 E3 02 00 00 0A 02 00 A0 E3 33 FF 2F E1 02 00 00 EA 9C 30 9F E5 03 30 95 E7 00 00 93 E5 00 00 50 E3 01 00 00 0A 00 40 A0 E1 1C 00 00 EA 01 00 A0 E3 C8 10 A0 E3 ?? ?? ?? ?? 00 00 50 E3 }
	condition:
		$pattern
}

rule endttyent_0889018e45d78659344920a58731a36a {
	meta:
		aliases = "__GI_endttyent, endttyent"
		size = "72"
		objfiles = "getttyents@libc.a"
	strings:
		$pattern = { 30 40 2D E9 34 40 9F E5 34 50 9F E5 04 40 8F E0 05 00 94 E7 04 D0 4D E2 00 00 50 E3 01 00 80 02 04 00 00 0A ?? ?? ?? ?? 00 30 A0 E3 05 30 84 E7 01 00 90 E2 01 00 A0 13 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getusershell_6659d75f50dd25b3e84b0961b0ccfdba {
	meta:
		aliases = "getusershell"
		size = "76"
		objfiles = "usershells@libc.a"
	strings:
		$pattern = { 30 40 2D E9 38 40 9F E5 38 50 9F E5 04 40 8F E0 05 30 94 E7 04 D0 4D E2 00 00 53 E3 01 00 00 1A 8C FF FF EB 05 00 84 E7 05 30 94 E7 00 00 93 E5 00 00 50 E3 04 30 83 12 05 30 84 17 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule usleep_c151a7205cfd520fcc58ad7b000f4258 {
	meta:
		aliases = "usleep"
		size = "76"
		objfiles = "usleeps@libc.a"
	strings:
		$pattern = { 30 40 2D E9 3C 40 9F E5 0C D0 4D E2 04 10 A0 E1 00 50 A0 E1 ?? ?? ?? ?? 04 10 A0 E1 00 00 8D E5 05 00 A0 E1 ?? ?? ?? ?? FA 3F A0 E3 91 03 03 E0 0D 00 A0 E1 00 10 A0 E3 04 30 8D E5 ?? ?? ?? ?? 0C D0 8D E2 30 80 BD E8 40 42 0F 00 }
	condition:
		$pattern
}

rule putenv_7ece7c5f22331a4935c3080d6ab02d1c {
	meta:
		aliases = "putenv"
		size = "100"
		objfiles = "setenvs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 3D 10 A0 E3 04 D0 4D E2 00 50 A0 E1 ?? ?? ?? ?? 00 40 50 E2 0B 00 00 0A 04 10 65 E0 05 00 A0 E1 ?? ?? ?? ?? 05 20 A0 E1 00 10 A0 E3 01 30 A0 E3 00 40 A0 E1 ?? ?? ?? ?? 00 50 A0 E1 04 00 A0 E1 ?? ?? ?? ?? 02 00 00 EA 05 00 A0 E1 ?? ?? ?? ?? 04 50 A0 E1 05 00 A0 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __popcountsi2_7593fdd246081b7976fe832e0ffa4da7 {
	meta:
		aliases = "__popcountsi2"
		size = "84"
		objfiles = "_popcountsi2@libgcc.a"
	strings:
		$pattern = { 30 40 2D E9 40 50 9F E5 40 30 9F E5 05 50 8F E0 03 C0 95 E7 20 28 A0 E1 20 34 A0 E1 FF 20 02 E2 FF 30 03 E2 02 10 DC E7 03 40 DC E7 FF 20 00 E2 00 E0 A0 E1 02 00 DC E7 04 10 81 E0 2E 3C DC E7 01 00 80 E0 00 00 83 E0 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __open_etc_hosts_46e5e85d6df60ecf677fc9f84fa16305 {
	meta:
		aliases = "__open_etc_hosts"
		size = "96"
		objfiles = "read_etc_hosts_rs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 44 40 9F E5 44 30 9F E5 04 40 8F E0 40 00 9F E5 03 50 84 E0 04 D0 4D E2 00 00 84 E0 05 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 05 00 00 1A 24 00 9F E5 05 10 A0 E1 00 00 84 E0 04 D0 8D E2 30 40 BD E8 ?? ?? ?? ?? 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getlogin_r_9f148b79d44c67e0dab5553c72c7cca4 {
	meta:
		aliases = "getlogin_r"
		size = "96"
		objfiles = "getlogins@libc.a"
	strings:
		$pattern = { 30 40 2D E9 4C 30 9F E5 00 50 A0 E1 48 00 9F E5 03 30 8F E0 04 D0 4D E2 00 00 83 E0 01 40 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 00 E0 03 07 00 00 0A 00 10 A0 E1 04 20 A0 E1 05 00 A0 E1 ?? ?? ?? ?? 00 30 A0 E3 04 20 85 E0 01 30 42 E5 03 00 A0 E1 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_getspecific_49342489c308792624fafc9e6e6acbe4 {
	meta:
		aliases = "pthread_getspecific"
		size = "100"
		objfiles = "specifics@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 50 50 9F E5 01 0B 50 E3 04 D0 4D E2 00 40 A0 E1 05 50 8F E0 0C 00 00 2A B9 FF FF EB A4 32 A0 E1 03 01 80 E0 EC 00 90 E5 00 00 50 E3 06 00 00 0A 24 30 9F E5 03 30 85 E0 84 31 93 E7 00 00 53 E3 1F 30 04 12 03 01 90 17 00 00 00 1A 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __gnu_Unwind_Find_exidx_ffeeab30ba9bf4ca82022b3666eb5bab {
	meta:
		aliases = "__gnu_Unwind_Find_exidx"
		size = "104"
		objfiles = "find_exidxs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 54 30 9F E5 14 D0 4D E2 04 00 8D E5 4C 00 9F E5 03 30 8F E0 00 40 A0 E3 00 00 83 E0 01 50 A0 E1 04 10 8D E2 08 40 8D E5 ?? ?? ?? ?? 04 00 50 E1 04 00 A0 D1 06 00 00 DA 0C 30 9D E5 08 00 9D E5 07 20 83 E2 00 00 53 E3 02 30 A0 B1 C3 31 A0 E1 00 30 85 E5 14 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_strcasecmp_0594ab770f832ea669825f6cdbe218c4 {
	meta:
		aliases = "strcasecmp, __GI_strcasecmp"
		size = "104"
		objfiles = "strcasecmps@libc.a"
	strings:
		$pattern = { 30 40 2D E9 54 40 9F E5 00 C0 A0 E1 50 50 9F E5 01 E0 A0 E1 00 00 A0 E3 04 40 8F E0 0E 00 5C E1 08 00 00 0A 00 10 DC E5 00 30 DE E5 05 00 94 E7 83 30 A0 E1 81 10 A0 E1 F0 20 93 E1 F0 30 91 E1 02 00 53 E0 30 80 BD 18 00 30 DC E5 01 E0 8E E2 00 00 53 E3 01 C0 8C E2 EF FF FF 1A 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule setttyent_26dd1e3f656f3265ad6bf953b5e37af1 {
	meta:
		aliases = "__GI_setttyent, setttyent"
		size = "112"
		objfiles = "getttyents@libc.a"
	strings:
		$pattern = { 30 40 2D E9 54 40 9F E5 54 50 9F E5 04 40 8F E0 05 00 94 E7 04 D0 4D E2 00 00 50 E3 01 00 00 0A ?? ?? ?? ?? 0A 00 00 EA 38 00 9F E5 38 10 9F E5 00 00 84 E0 01 10 84 E0 ?? ?? ?? ?? 00 00 50 E3 05 00 84 E7 00 00 A0 01 02 00 00 0A 02 10 A0 E3 ?? ?? ?? ?? 01 00 A0 E3 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_manager_adjust_prio_fe0d20e836a578ba930322fc1fce2bff {
	meta:
		aliases = "__pthread_manager_adjust_prio"
		size = "108"
		objfiles = "managers@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 58 40 9F E5 58 30 9F E5 04 40 8F E0 03 30 94 E7 0C D0 4D E2 18 30 93 E5 00 50 A0 E1 03 00 50 E1 0C 00 00 DA 01 00 A0 E3 ?? ?? ?? ?? 30 30 9F E5 00 00 55 E1 03 40 94 E7 05 10 A0 A1 01 10 85 B2 08 20 8D E2 04 10 22 E5 14 00 94 E5 01 10 A0 E3 ?? ?? ?? ?? 18 50 84 E5 0C D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __do_global_dtors_aux_7c53e04009d3ccc20109e4ef6c7d78f6 {
	meta:
		aliases = "__do_global_dtors_aux"
		size = "244"
		objfiles = "crtbeginS"
	strings:
		$pattern = { 30 40 2D E9 5C 40 9F E5 5C 50 9F E5 04 40 8F E0 05 30 D4 E7 04 D0 4D E2 00 00 53 E3 0F 00 00 1A 48 30 9F E5 03 20 94 E7 00 00 52 E3 02 00 00 0A 3C 30 9F E5 03 00 94 E7 32 FF 2F E1 34 30 9F E5 03 30 94 E7 00 00 53 E3 02 00 00 0A 28 00 9F E5 00 00 84 E0 33 FF 2F E1 01 30 A0 E3 05 30 C4 E7 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 10 40 2D E9 50 40 9F E5 50 30 9F E5 04 40 8F E0 03 30 94 E7 00 00 53 E3 04 00 00 0A 40 00 9F E5 40 10 9F E5 00 00 84 E0 01 10 84 E0 33 FF 2F E1 34 30 9F E5 03 20 94 E7 03 00 84 E0 00 00 52 E3 10 80 BD 08 24 30 9F E5 }
	condition:
		$pattern
}

rule login_68e5a68ed85e9fb37d71151dbed25eef {
	meta:
		aliases = "login"
		size = "124"
		objfiles = "logins@libutil.a"
	strings:
		$pattern = { 30 40 2D E9 61 DF 4D E2 00 10 A0 E1 00 50 A0 E1 06 2D A0 E3 0D 00 A0 E1 50 40 9F E5 ?? ?? ?? ?? 4C 00 9F E5 04 40 8F E0 00 00 84 E0 ?? ?? ?? ?? ?? ?? ?? ?? 3C 30 9F E5 06 1D 8D E2 07 20 A0 E3 B3 20 81 E1 ?? ?? ?? ?? 08 10 85 E2 04 00 8D E5 20 20 A0 E3 08 00 8D E2 ?? ?? ?? ?? 05 00 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? 61 DF 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? 80 FE FF FF }
	condition:
		$pattern
}

rule mbrtowc_107025d4b087f9a0ea3b331a3c3e0ad1 {
	meta:
		aliases = "__GI_mbrtowc, mbrtowc"
		size = "148"
		objfiles = "mbrtowcs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 80 E0 9F E5 00 50 53 E2 0E E0 8F E0 1C D0 4D E2 00 40 A0 E1 01 C0 A0 E1 6C 30 9F 05 03 50 8E 00 00 00 5C E3 17 C0 CD 05 0C 40 A0 01 17 C0 8D 02 04 00 00 0A 00 30 DC E5 00 00 53 E3 0E 00 00 0A 00 00 52 E3 0C 00 00 0A 10 00 8D E2 0C 10 8D E2 00 20 E0 E3 01 30 A0 E3 0C C0 8D E5 00 50 8D E5 ?? ?? ?? ?? 00 00 50 E3 04 00 00 BA 00 00 54 E3 10 30 9D 15 00 30 84 15 00 00 00 EA 00 00 A0 E3 1C D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __aeabi_dadd_77ac3bb23899bacc1604783eb8a2590d {
	meta:
		aliases = "__adddf3, __aeabi_dadd"
		size = "684"
		objfiles = "_addsubdf3@libgcc.a"
	strings:
		$pattern = { 30 40 2D E9 81 40 A0 E1 83 50 A0 E1 05 00 34 E1 02 00 30 01 00 C0 94 11 02 C0 95 11 C4 CA F0 11 C5 CA F0 11 79 00 00 0A A4 4A A0 E1 A5 5A 74 E0 00 50 65 B2 06 00 00 DA 05 40 84 E0 02 20 20 E0 03 30 21 E0 00 00 22 E0 01 10 23 E0 02 20 20 E0 03 30 21 E0 36 00 55 E3 30 80 BD 88 02 01 11 E3 01 16 A0 E1 01 C6 A0 E3 21 16 8C E1 01 00 00 0A 00 00 70 E2 00 10 E1 E2 02 01 13 E3 03 36 A0 E1 23 36 8C E1 01 00 00 0A 00 20 72 E2 00 30 E3 E2 05 00 34 E1 57 00 00 0A 01 40 44 E2 20 E0 75 E2 05 00 00 BA 12 CE A0 E1 32 05 90 E0 00 10 A1 E2 13 0E 90 E0 53 15 B1 E0 06 00 00 EA 20 50 45 E2 20 E0 8E E2 01 00 52 E3 }
	condition:
		$pattern
}

rule sighold_7cd4af37d07fc7f4013468f684eda691 {
	meta:
		aliases = "sigrelse, sighold"
		size = "92"
		objfiles = "sigrelses@libc.a, sigholds@libc.a"
	strings:
		$pattern = { 30 40 2D E9 84 D0 4D E2 00 50 A0 E1 00 10 A0 E3 02 00 A0 E3 0D 20 A0 E1 ?? ?? ?? ?? 00 00 50 E3 0D 40 A0 E1 09 00 00 BA 05 10 A0 E1 0D 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 04 00 00 BA 0D 10 A0 E1 00 20 A0 E3 02 00 A0 E3 ?? ?? ?? ?? 00 00 00 EA 00 00 E0 E3 84 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule strsignal_7875d8718708d22d0cd33c5040d5abb8 {
	meta:
		aliases = "__GI_strsignal, strsignal"
		size = "164"
		objfiles = "strsignals@libc.a"
	strings:
		$pattern = { 30 40 2D E9 88 50 9F E5 1F 00 50 E3 0C D0 4D E2 00 20 A0 E1 05 50 8F E0 0B 00 00 8A 74 30 9F E5 00 10 A0 E1 03 40 85 E0 02 00 00 EA 00 00 53 E3 01 10 41 02 01 40 84 E2 00 00 51 E3 00 30 D4 E5 F9 FF FF 1A 00 00 53 E3 0E 00 00 1A 48 00 9F E5 09 10 E0 E3 00 00 85 E0 C2 3F A0 E1 00 10 8D E5 1A 00 80 E2 0A 10 81 E2 04 10 8D E5 ?? ?? ?? ?? 28 10 9F E5 0F 40 40 E2 01 10 85 E0 04 00 A0 E1 0F 20 A0 E3 ?? ?? ?? ?? 04 00 A0 E1 0C D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule siginterrupt_2f5e48e7523ed1cf5c6bf82610588d93 {
	meta:
		aliases = "siginterrupt"
		size = "152"
		objfiles = "sigintrs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 94 D0 4D E2 01 50 A0 E1 04 20 8D E2 00 10 A0 E3 00 40 A0 E1 ?? ?? ?? ?? 6C 30 9F E5 00 00 50 E3 03 30 8F E0 15 00 00 BA 00 00 55 E3 5C 20 9F E5 05 00 00 0A 02 00 83 E0 04 10 A0 E1 ?? ?? ?? ?? 88 30 9D E5 01 32 C3 E3 04 00 00 EA 02 00 83 E0 04 10 A0 E1 ?? ?? ?? ?? 88 30 9D E5 01 32 83 E3 04 00 A0 E1 04 10 8D E2 00 20 A0 E3 88 30 8D E5 ?? ?? ?? ?? 00 00 50 E3 00 00 A0 A3 00 00 00 AA 00 00 E0 E3 94 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _ppfs_init_d3a6798bd4d967b5a629ed125f860cb2 {
	meta:
		aliases = "_ppfs_init"
		size = "156"
		objfiles = "_ppfs_inits@libc.a"
	strings:
		$pattern = { 30 40 2D E9 98 20 A0 E3 00 40 A0 E1 01 50 A0 E1 04 D0 4D E2 00 10 A0 E3 ?? ?? ?? ?? 18 30 94 E5 00 50 84 E5 01 30 43 E2 18 30 84 E5 28 20 84 E2 09 30 A0 E3 08 10 A0 E3 01 30 53 E2 04 10 82 E4 FC FF FF 1A 05 20 A0 E1 0D 00 00 EA 25 00 50 E3 0A 00 00 1A 01 30 F2 E5 25 00 53 E3 07 00 00 0A 00 20 84 E5 04 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 00 E0 B3 06 00 00 BA 00 20 94 E5 00 00 00 EA 01 20 82 E2 00 00 D2 E5 00 00 50 E3 EE FF FF 1A 00 50 84 E5 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule clearenv_d32d4ebebdbc6c9f65f913cde9ba349b {
	meta:
		aliases = "clearenv"
		size = "196"
		objfiles = "setenvs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 98 50 9F E5 98 40 9F E5 05 50 8F E0 94 30 9F E5 14 D0 4D E2 04 40 85 E0 04 20 A0 E1 03 10 95 E7 0D 00 A0 E1 80 30 9F E5 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 74 30 9F E5 0F E0 A0 E1 03 F0 95 E7 6C 30 9F E5 6C 40 9F E5 03 30 95 E7 04 20 95 E7 00 00 93 E5 02 00 50 E1 04 00 00 1A 00 00 50 E3 02 00 00 0A ?? ?? ?? ?? 00 30 A0 E3 04 30 85 E7 3C 30 9F E5 00 40 A0 E3 03 30 95 E7 0D 00 A0 E1 00 40 83 E5 01 10 A0 E3 2C 30 9F E5 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 14 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule get_current_dir_name_03021f0d645d35f35439511b4d9be472 {
	meta:
		aliases = "get_current_dir_name"
		size = "188"
		objfiles = "getdirnames@libc.a"
	strings:
		$pattern = { 30 40 2D E9 A4 40 9F E5 A4 00 9F E5 04 40 8F E0 D4 D0 4D E2 00 00 84 E0 ?? ?? ?? ?? 00 50 50 E2 1D 00 00 0A 8C 00 9F E5 68 10 8D E2 00 00 84 E0 ?? ?? ?? ?? 00 00 50 E3 17 00 00 1A 05 00 A0 E1 0D 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 12 00 00 1A 00 20 9D E5 68 30 9D E5 03 00 52 E1 0E 00 00 1A 04 20 9D E5 6C 30 9D E5 03 00 52 E1 0A 00 00 1A 60 20 9D E5 C8 30 9D E5 03 00 52 E1 06 00 00 1A 64 20 9D E5 CC 30 9D E5 03 00 52 E1 02 00 00 1A 05 00 A0 E1 ?? ?? ?? ?? 02 00 00 EA 00 00 A0 E3 00 10 A0 E1 ?? ?? ?? ?? D4 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _dl_run_fini_array_8ca9b7d957fb07c85312c91ea46f29dc {
	meta:
		aliases = "_dl_run_fini_array"
		size = "64"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { 30 40 2D E9 A8 10 90 E5 04 D0 4D E2 00 00 51 E3 08 00 00 0A B0 30 90 E5 00 20 90 E5 23 41 A0 E1 02 50 81 E0 01 00 00 EA 0F E0 A0 E1 04 F1 95 E7 01 40 54 E2 FB FF FF 2A 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __stdio_READ_cd82d907ac9ba96b4c36837ac4a186ba {
	meta:
		aliases = "__stdio_READ"
		size = "84"
		objfiles = "_READs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 B0 30 D0 E1 00 40 A0 E1 04 50 13 E2 04 D0 4D E2 00 00 A0 13 0B 00 00 1A 00 00 52 E3 02 21 E0 B3 04 00 94 E5 ?? ?? ?? ?? 00 00 50 E3 05 00 00 CA B0 30 D4 E1 05 00 A0 11 04 30 83 03 08 30 83 13 B0 30 C4 01 B0 30 C4 11 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __stdio_trans2r_o_06bf76c252396ca264f8f24f929a69dd {
	meta:
		aliases = "__stdio_trans2r_o"
		size = "144"
		objfiles = "_trans2rs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 B0 30 D0 E1 04 D0 4D E2 03 00 11 E1 00 40 A0 E1 03 00 00 1A 22 0D 13 E3 04 00 00 1A 03 30 81 E1 B0 30 C0 E1 B0 30 D4 E1 10 50 13 E2 06 00 00 0A ?? ?? ?? ?? 09 30 A0 E3 00 30 80 E5 B0 30 D4 E1 00 00 E0 E3 08 30 83 E3 0C 00 00 EA 40 00 13 E3 07 00 00 0A ?? ?? ?? ?? 00 00 50 E3 F6 FF FF 1A B0 30 D4 E1 08 20 94 E5 40 30 C3 E3 1C 20 84 E5 B0 30 C4 E1 B0 30 D4 E1 05 00 A0 E1 01 30 83 E3 B0 30 C4 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __stdio_adjust_position_6e7a6c905d5c9017a5e0a01fec9d1813 {
	meta:
		aliases = "__stdio_adjust_position"
		size = "192"
		objfiles = "_adjust_poss@libc.a"
	strings:
		$pattern = { 30 40 2D E9 B0 C0 D0 E1 04 D0 4D E2 03 20 1C E2 01 50 A0 E1 02 E0 A0 01 0E 00 00 0A 01 E0 52 E2 0C 00 00 0A 02 0B 1C E3 0A 00 00 0A 02 00 5E E3 1E 00 00 0A 28 30 90 E5 00 00 53 E3 1B 00 00 1A 2C 30 90 E5 03 20 D0 E5 00 00 53 E3 02 30 D0 15 00 E0 62 E2 0E E0 63 10 40 00 1C E3 10 30 90 E5 08 20 90 15 14 20 90 05 0E 30 63 E0 02 40 83 E0 03 00 95 E8 04 20 50 E0 C4 3F C1 E0 01 00 53 E1 0C 00 85 E8 02 00 00 CA 02 00 00 1A 00 00 52 E1 00 00 00 9A 00 40 64 E2 00 00 54 E3 04 00 00 AA ?? ?? ?? ?? 4B 30 A0 E3 00 30 80 E5 00 00 00 EA 00 40 E0 E3 04 00 A0 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __rpc_thread_destroy_7b7f8924302d6dc3316c7b1032751142 {
	meta:
		aliases = "__rpc_thread_destroy"
		size = "224"
		objfiles = "rpc_threads@libc.a"
	strings:
		$pattern = { 30 40 2D E9 C0 50 9F E5 C0 30 9F E5 05 50 8F E0 03 30 95 E7 04 D0 4D E2 00 00 53 E3 03 00 00 0A 02 00 A0 E3 33 FF 2F E1 00 40 A0 E1 02 00 00 EA 9C 30 9F E5 03 30 95 E7 00 40 93 E5 00 00 54 E3 1F 00 00 0A 8C 30 9F E5 03 30 85 E0 03 00 54 E1 1B 00 00 0A ?? ?? ?? ?? ?? ?? ?? ?? 98 00 94 E5 ?? ?? ?? ?? 9C 00 94 E5 ?? ?? ?? ?? A0 00 94 E5 ?? ?? ?? ?? BC 00 94 E5 ?? ?? ?? ?? AC 00 94 E5 ?? ?? ?? ?? B0 00 94 E5 ?? ?? ?? ?? 04 00 A0 E1 ?? ?? ?? ?? 40 30 9F E5 03 20 95 E7 00 00 52 E3 04 00 00 0A 02 00 A0 E3 00 10 A0 E3 04 D0 8D E2 30 40 BD E8 ?? ?? ?? ?? 14 30 9F E5 03 30 95 E7 00 20 83 E5 04 D0 8D E2 }
	condition:
		$pattern
}

rule __GI_memchr_7e8b1d68db9dd5be9c79294f72a5fbf8 {
	meta:
		aliases = "memchr, __GI_memchr"
		size = "244"
		objfiles = "memchrs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 FF 10 01 E2 04 00 00 EA 00 30 D0 E5 01 20 42 E2 01 00 53 E1 30 80 BD 08 01 00 80 E2 00 00 52 E3 01 00 00 0A 03 00 10 E3 F6 FF FF 1A 01 34 81 E1 00 C0 A0 E1 03 58 83 E1 1C 00 00 EA 04 30 9C E4 04 20 42 E2 03 30 25 E0 00 00 83 E0 03 30 E0 E1 00 30 23 E0 0E E0 03 E0 00 00 5E E3 13 00 00 0A 04 30 5C E5 04 00 4C E2 01 00 53 E1 03 40 80 E2 30 80 BD 08 03 30 5C E5 01 E0 80 E2 01 00 53 E1 01 00 00 1A 0E 00 A0 E1 30 80 BD E8 02 30 5C E5 02 00 80 E2 01 00 53 E1 30 80 BD 08 01 30 5C E5 01 00 53 E1 01 00 00 1A 04 00 A0 E1 30 80 BD E8 03 00 52 E3 2C 00 9F E5 2C E0 9F E5 DE FF FF 8A 0C 00 A0 E1 }
	condition:
		$pattern
}

rule rindex_b140bff4fe62c55b4ac67220f35ba191 {
	meta:
		aliases = "__GI_strrchr, strrchr, rindex"
		size = "80"
		objfiles = "strrchrs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 FF 40 11 E2 04 D0 4D E2 00 30 A0 E1 00 50 A0 13 05 00 00 1A 04 10 A0 E1 04 D0 8D E2 30 40 BD E8 ?? ?? ?? ?? 00 50 A0 E1 01 30 80 E2 03 00 A0 E1 04 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 F8 FF FF 1A 05 00 A0 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule restore_core_regs_81e8d02abd170cfe3bc607f68179fe3b {
	meta:
		aliases = "__restore_core_regs, restore_core_regs"
		size = "20"
		objfiles = "libunwind@libgcc.a"
	strings:
		$pattern = { 34 10 80 E2 38 00 91 E8 38 00 2D E9 FF 0F 90 E8 00 E0 9D E8 }
	condition:
		$pattern
}

rule rpc_thread_multi_82c129ce4529c5f9a03b6aea1ac4bcd7 {
	meta:
		aliases = "rpc_thread_multi"
		size = "76"
		objfiles = "rpc_threads@libc.a"
	strings:
		$pattern = { 34 10 9F E5 34 30 9F E5 01 10 8F E0 03 30 91 E7 00 00 53 E3 28 20 9F E5 02 00 00 0A 02 10 81 E0 02 00 A0 E3 ?? ?? ?? ?? 02 30 81 E0 14 20 9F E5 02 20 91 E7 00 30 82 E5 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_find_self_a62b94f2b825f74f8e1a8cf7c2fbc8c9 {
	meta:
		aliases = "__pthread_find_self"
		size = "68"
		objfiles = "pthreads@libpthread.a"
	strings:
		$pattern = { 34 20 9F E5 34 30 9F E5 02 20 8F E0 03 30 92 E7 0D C0 A0 E1 20 10 83 E2 00 00 00 EA 10 10 81 E2 08 00 91 E5 00 00 5C E1 FB FF FF 8A 0C 30 91 E5 03 00 5C E1 F8 FF FF 3A 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __uClibc_main_9bdfe81723c585958b844a63d2cccb16 {
	meta:
		aliases = "__uClibc_main"
		size = "628"
		objfiles = "__uClibc_mains@libc.a"
	strings:
		$pattern = { 34 62 9F E5 02 80 A0 E1 04 C0 82 E2 00 E0 92 E5 28 22 9F E5 06 60 8F E0 01 51 A0 E1 01 90 A0 E1 02 10 96 E7 18 22 9F E5 78 D0 4D E2 02 40 96 E7 80 20 9D E5 05 C0 8C E0 0E 00 5C E1 00 20 81 E5 7C 10 9D E5 FC 21 9F E5 03 A0 A0 E1 05 30 88 00 02 10 86 E7 00 C0 84 E5 78 20 A0 E3 00 B0 A0 E1 00 30 84 05 0D 00 A0 E1 00 10 A0 E3 ?? ?? ?? ?? 00 20 94 E5 00 00 00 EA 01 20 A0 E1 04 30 92 E4 00 00 53 E3 02 10 A0 E1 FA FF FF 1A 02 40 A0 E1 0D 50 A0 E1 06 00 00 EA 0E 00 53 E3 03 00 00 8A 83 01 85 E0 04 10 A0 E1 08 20 A0 E3 ?? ?? ?? ?? 08 40 84 E2 00 30 94 E5 00 00 53 E3 F5 FF FF 1A 0D 00 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ftrylockfile_187ef0662c31ab8329f7872a991e0ca4 {
	meta:
		aliases = "funlockfile, flockfile, ftrylockfile"
		size = "8"
		objfiles = "ftrylockfiles@libc.a, flockfiles@libc.a, funlockfiles@libc.a"
	strings:
		$pattern = { 38 00 80 E2 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_brk_8877ff846e798483c737cef7f1eeea69 {
	meta:
		aliases = "brk, __GI_brk"
		size = "72"
		objfiles = "brks@libc.a"
	strings:
		$pattern = { 38 20 9F E5 80 40 2D E9 02 20 8F E0 00 30 A0 E1 2D 70 A0 E3 00 00 00 EF 03 00 50 E1 20 30 9F E5 03 00 82 E7 00 00 A0 23 80 80 BD 28 ?? ?? ?? ?? 0C 30 A0 E3 00 30 80 E5 00 00 E0 E3 80 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_scalbln_40a2c3d8a7e67c0810cd10162a8c0ae6 {
	meta:
		aliases = "scalbln, __GI_scalbln"
		size = "364"
		objfiles = "s_scalblns@libm.a"
	strings:
		$pattern = { 38 31 9F E5 F0 41 2D E9 03 30 01 E0 43 CA B0 E1 00 60 A0 E1 01 70 A0 E1 00 40 A0 E1 01 50 A0 E1 01 E0 A0 E1 02 80 A0 E1 0C 00 00 1A 02 31 C1 E3 00 30 93 E1 3E 00 00 0A 04 31 9F E5 00 20 A0 E3 ?? ?? ?? ?? F4 30 9F E5 00 60 A0 E1 03 30 01 E0 43 3A A0 E1 01 70 A0 E1 01 E0 A0 E1 36 C0 43 E2 E0 30 9F E5 03 00 5C E1 05 00 00 1A 06 00 A0 E1 07 10 A0 E1 06 20 A0 E1 07 30 A0 E1 ?? ?? ?? ?? 29 00 00 EA C0 20 9F E5 C0 30 9F E5 08 10 8C E0 03 00 51 E1 02 00 58 D1 07 00 00 DA 06 20 A0 E1 07 30 A0 E1 A8 00 9F E5 A8 10 9F E5 ?? ?? ?? ?? 9C 20 9F E5 9C 30 9F E5 1A 00 00 EA 98 30 9F E5 03 00 58 E1 07 00 00 BA }
	condition:
		$pattern
}

rule putchar_unlocked_d985d518aca2e6f2bf30ae4480ef14e2 {
	meta:
		aliases = "putchar_unlocked"
		size = "76"
		objfiles = "putchar_unlockeds@libc.a"
	strings:
		$pattern = { 3C 30 9F E5 3C 20 9F E5 03 30 8F E0 02 20 93 E7 04 E0 2D E5 00 10 92 E5 00 E0 A0 E1 10 C0 91 E5 1C 30 91 E5 03 00 5C E1 01 00 00 3A 04 E0 9D E4 ?? ?? ?? ?? FF 00 00 E2 01 00 CC E4 10 C0 81 E5 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule gai_strerror_46bde26e946b37cd1a6ee7037d9a7f5a {
	meta:
		aliases = "gai_strerror"
		size = "84"
		objfiles = "gai_strerrors@libc.a"
	strings:
		$pattern = { 40 10 9F E5 40 30 9F E5 01 10 8F E0 03 C0 81 E0 00 20 A0 E3 06 00 00 EA 82 31 9C E7 00 00 53 E1 02 00 00 1A 82 31 8C E0 04 00 93 E5 1E FF 2F E1 01 20 82 E2 0F 00 52 E3 F6 FF FF 9A 0C 30 9F E5 03 00 81 E0 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule srand48_r_57009a7cec4dd15d93896f1985d5ce47 {
	meta:
		aliases = "__GI_srand48_r, srand48_r"
		size = "72"
		objfiles = "srand48_rs@libc.a"
	strings:
		$pattern = { 40 38 A0 E1 B4 30 C1 E1 30 30 9F E5 10 40 2D E9 B0 30 C1 E1 01 30 A0 E3 BE 30 C1 E1 0B 30 A0 E3 BC 30 C1 E1 18 30 9F E5 B2 00 C1 E1 05 40 A0 E3 00 00 A0 E3 10 30 81 E5 14 40 81 E5 10 80 BD E8 0E 33 00 00 6D E6 EC DE }
	condition:
		$pattern
}

rule __GI_iswctype_255238fec23ba6d12ae069b7764df157 {
	meta:
		aliases = "iswctype, __GI_iswctype"
		size = "84"
		objfiles = "iswctypes@libc.a"
	strings:
		$pattern = { 40 C0 9F E5 7F 00 50 E3 0C 00 51 93 00 20 A0 E1 00 00 A0 83 01 00 A0 93 0C C0 8F E0 1E FF 2F 81 24 30 9F E5 81 10 A0 E1 03 00 9C E7 1C 30 9F E5 82 20 A0 E1 03 30 8C E0 B0 20 92 E1 B3 30 91 E1 03 00 02 E0 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_rint_902e47d2ee9a81603418f926a556f7db {
	meta:
		aliases = "rint, __GI_rint"
		size = "436"
		objfiles = "s_rints@libm.a"
	strings:
		$pattern = { 41 3A A0 E1 F0 4F 2D E9 83 3A A0 E1 A3 3A A0 E1 FF CF 43 E2 03 C0 4C E2 88 B1 9F E5 13 00 5C E3 0B B0 8F E0 04 D0 4D E2 00 60 A0 E1 01 70 A0 E1 00 40 A0 E1 01 50 A0 E1 01 E0 A0 E1 00 80 A0 E3 00 90 A0 E3 A1 AF A0 E1 30 00 00 CA 00 00 5C E3 1F 00 00 AA 02 31 C1 E3 00 30 93 E1 4D 00 00 0A FF 34 C1 E3 0F 36 C3 E3 00 30 83 E1 00 20 63 E2 03 20 82 E1 A1 08 A0 E1 2C 11 9F E5 22 26 A0 E1 02 27 02 E2 80 08 A0 E1 01 10 8B E0 00 40 82 E1 06 30 A0 E1 8A 11 81 E0 60 00 91 E8 03 20 A0 E1 05 00 A0 E1 04 30 A0 E1 06 10 A0 E1 ?? ?? ?? ?? 05 20 A0 E1 06 30 A0 E1 ?? ?? ?? ?? 02 21 C1 E3 8A 4F 82 E1 00 50 A0 E1 }
	condition:
		$pattern
}

rule _Unwind_GetCFA_c182b75700f10146f67821f2037a93c4 {
	meta:
		aliases = "_Unwind_GetCFA"
		size = "8"
		objfiles = "unwind_arm@libgcc.a"
	strings:
		$pattern = { 44 00 90 E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule __GI_scalbn_aac4f6422979b59a6c64b74d6825b575 {
	meta:
		aliases = "scalbn, __GI_scalbn"
		size = "376"
		objfiles = "s_scalbns@libm.a"
	strings:
		$pattern = { 44 31 9F E5 F0 41 2D E9 03 30 01 E0 43 CA B0 E1 00 60 A0 E1 01 70 A0 E1 00 40 A0 E1 01 50 A0 E1 01 E0 A0 E1 02 80 A0 E1 11 00 00 1A 02 31 C1 E3 00 30 93 E1 41 00 00 0A 10 31 9F E5 00 20 A0 E3 ?? ?? ?? ?? 08 31 9F E5 00 60 A0 E1 03 00 58 E1 01 70 A0 E1 00 00 A0 B1 01 10 A0 B1 29 00 00 BA E4 30 9F E5 07 E0 A0 E1 03 30 07 E0 43 3A A0 E1 36 C0 43 E2 DC 30 9F E5 03 00 5C E1 05 00 00 1A 06 00 A0 E1 07 10 A0 E1 06 20 A0 E1 07 30 A0 E1 ?? ?? ?? ?? 27 00 00 EA BC 30 9F E5 08 10 8C E0 03 00 51 E1 0A 00 00 CA 00 00 51 E3 7F 24 CE C3 0F 26 C2 C3 01 4A 82 C1 04 70 A0 C1 1F 00 00 CA 36 00 71 E3 12 00 00 CA }
	condition:
		$pattern
}

rule _call_via_lr_e6e0685d187f95a10f5a8726c19ba0de {
	meta:
		aliases = "_call_via_lr"
		size = "4"
		objfiles = "crti, _call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 }
	condition:
		$pattern
}

rule _interwork_r7_call_via_r0_cd6e5c47c0fd98eafc1e412f68a21783 {
	meta:
		aliases = "_interwork_r7_call_via_r0"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 10 E3 04 E0 07 05 38 E0 4F 02 10 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r11_call_via_r0_0cc52f5c64223414cdd78d06082a8414 {
	meta:
		aliases = "_interwork_r11_call_via_r0"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 10 E3 04 E0 0B 05 44 E0 4F 02 10 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_call_via_r0_2969b8428b7587aa057e1b48267ac107 {
	meta:
		aliases = "_interwork_call_via_r0"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 10 E3 08 E0 2D 05 28 E0 4F 02 10 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r7_call_via_r1_7e47d30f86de5c53e4c99ab88087b988 {
	meta:
		aliases = "_interwork_r7_call_via_r1"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 11 E3 04 E0 07 05 74 E0 4F 02 11 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r11_call_via_r1_62d145f8d66af0d51533050e3ae161f3 {
	meta:
		aliases = "_interwork_r11_call_via_r1"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 11 E3 04 E0 0B 05 80 E0 4F 02 11 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_call_via_r1_6a9fabb72fb6bc8d1d675a1e05f0a3ea {
	meta:
		aliases = "_interwork_call_via_r1"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 11 E3 08 E0 2D 05 64 E0 4F 02 11 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r7_call_via_r2_53e5a027f07ad9ac6547266b6277d061 {
	meta:
		aliases = "_interwork_r7_call_via_r2"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 12 E3 04 E0 07 05 B0 E0 4F 02 12 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r11_call_via_r2_8849532f7855cde217a7fd1815b9cb0d {
	meta:
		aliases = "_interwork_r11_call_via_r2"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 12 E3 04 E0 0B 05 BC E0 4F 02 12 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_call_via_r2_f2822a896c60857c726c0567c65459d4 {
	meta:
		aliases = "_interwork_call_via_r2"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 12 E3 08 E0 2D 05 A0 E0 4F 02 12 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r7_call_via_r3_5de590ee2010700879152c02b867398a {
	meta:
		aliases = "_interwork_r7_call_via_r3"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 13 E3 04 E0 07 05 EC E0 4F 02 13 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r11_call_via_r3_d86764429622c11f45cb5591afd9247a {
	meta:
		aliases = "_interwork_r11_call_via_r3"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 13 E3 04 E0 0B 05 F8 E0 4F 02 13 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_call_via_r3_17a4acbb8c61ce5c677896a8d305f9f7 {
	meta:
		aliases = "_interwork_call_via_r3"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 13 E3 08 E0 2D 05 DC E0 4F 02 13 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r7_call_via_r4_e11ff6e3610a4ce29e7845417add7fa0 {
	meta:
		aliases = "_interwork_r7_call_via_r4"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 14 E3 04 E0 07 05 4A EF 4F 02 14 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r11_call_via_r4_c51d6fb24daca1a5f9cd24b45651c47d {
	meta:
		aliases = "_interwork_r11_call_via_r4"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 14 E3 04 E0 0B 05 4D EF 4F 02 14 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_call_via_r4_25cfbee7ad9ae809e7115128b3e7d62a {
	meta:
		aliases = "_interwork_call_via_r4"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 14 E3 08 E0 2D 05 46 EF 4F 02 14 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r7_call_via_r5_06ab01324d5a2cf0965bebbf9569a8ff {
	meta:
		aliases = "_interwork_r7_call_via_r5"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 15 E3 04 E0 07 05 59 EF 4F 02 15 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r11_call_via_r5_4e4219b3b03348c8ea57778033d34c2c {
	meta:
		aliases = "_interwork_r11_call_via_r5"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 15 E3 04 E0 0B 05 17 EE 4F 02 15 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_call_via_r5_8320ef352b8132d1c297e50644d79a50 {
	meta:
		aliases = "_interwork_call_via_r5"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 15 E3 08 E0 2D 05 55 EF 4F 02 15 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r7_call_via_r6_6e80b2f9c8e607060dfa634c90efd058 {
	meta:
		aliases = "_interwork_r7_call_via_r6"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 16 E3 04 E0 07 05 1A EE 4F 02 16 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r11_call_via_r6_4150331f86443d853eb138cfa1f04853 {
	meta:
		aliases = "_interwork_r11_call_via_r6"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 16 E3 04 E0 0B 05 6B EF 4F 02 16 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_call_via_r6_e7a1a1eb3e384f0318c2e2746e80a204 {
	meta:
		aliases = "_interwork_call_via_r6"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 16 E3 08 E0 2D 05 19 EE 4F 02 16 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r7_call_via_r7_ef792db7b38106a801de6a14e6f628e3 {
	meta:
		aliases = "_interwork_r7_call_via_r7"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 17 E3 04 E0 07 05 77 EF 4F 02 17 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r11_call_via_r7_470f7128d5de26ae0998524b32c93ffd {
	meta:
		aliases = "_interwork_r11_call_via_r7"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 17 E3 04 E0 0B 05 7A EF 4F 02 17 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_call_via_r7_1fb275ede3de56a9ec61941e3f074004 {
	meta:
		aliases = "_interwork_call_via_r7"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 17 E3 08 E0 2D 05 73 EF 4F 02 17 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r7_call_via_r8_8f22422875454be180065fa452237aa5 {
	meta:
		aliases = "_interwork_r7_call_via_r8"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 18 E3 04 E0 07 05 86 EF 4F 02 18 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r11_call_via_r8_61c7015c69c6e8f62a5675e9a46df2b2 {
	meta:
		aliases = "_interwork_r11_call_via_r8"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 18 E3 04 E0 0B 05 89 EF 4F 02 18 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_call_via_r8_90024d9798bbd04031829b72ac9a3df5 {
	meta:
		aliases = "_interwork_call_via_r8"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 18 E3 08 E0 2D 05 82 EF 4F 02 18 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r7_call_via_r9_9b4f6571c4ca5c44389200cd21f5ddce {
	meta:
		aliases = "_interwork_r7_call_via_r9"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 19 E3 04 E0 07 05 95 EF 4F 02 19 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r11_call_via_r9_704ed936833b67ecd6ae88753e619977 {
	meta:
		aliases = "_interwork_r11_call_via_r9"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 19 E3 04 E0 0B 05 26 EE 4F 02 19 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_call_via_r9_63dbb7c036928640d39c7d309fdfe3af {
	meta:
		aliases = "_interwork_call_via_r9"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 19 E3 08 E0 2D 05 91 EF 4F 02 19 FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r7_call_via_sl_7743175a1dd970473d633047bcfb7a8a {
	meta:
		aliases = "_interwork_r7_call_via_sl"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 1A E3 04 E0 07 05 29 EE 4F 02 1A FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r11_call_via_sl_bd56a32a2e4ef891fe04dbdc3ec61eab {
	meta:
		aliases = "_interwork_r11_call_via_sl"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 1A E3 04 E0 0B 05 A7 EF 4F 02 1A FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_call_via_sl_1dd26d1645a256303f07360fe0cb479f {
	meta:
		aliases = "_interwork_call_via_sl"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 1A E3 08 E0 2D 05 0A ED 4F 02 1A FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r7_call_via_fp_4d24de803509f534b753cf3681ab664d {
	meta:
		aliases = "_interwork_r7_call_via_fp"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 1B E3 04 E0 07 05 B3 EF 4F 02 1B FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r11_call_via_fp_ad705c83e4e7e580f38eabd3db21fcfe {
	meta:
		aliases = "_interwork_r11_call_via_fp"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 1B E3 04 E0 0B 05 B6 EF 4F 02 1B FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_call_via_fp_58d5b9ee50d6980584ab7c5f0540832f {
	meta:
		aliases = "_interwork_call_via_fp"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 1B E3 08 E0 2D 05 AF EF 4F 02 1B FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r7_call_via_ip_24164adf0864dbd705ae0a8c2c63f4ce {
	meta:
		aliases = "_interwork_r7_call_via_ip"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 1C E3 04 E0 07 05 C2 EF 4F 02 1C FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r11_call_via_ip_7295c581812345f06ca00aac73b225a0 {
	meta:
		aliases = "_interwork_r11_call_via_ip"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 1C E3 04 E0 0B 05 C5 EF 4F 02 1C FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_call_via_ip_3955cf0449657f6e19e1465ee5edcbb4 {
	meta:
		aliases = "_interwork_call_via_ip"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 1C E3 08 E0 2D 05 BE EF 4F 02 1C FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r7_call_via_sp_507160bf2672de5e8440f5c81c42348a {
	meta:
		aliases = "_interwork_r7_call_via_sp"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 1D E3 04 E0 07 05 D1 EF 4F 02 1D FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_r11_call_via_sp_bc1f5d305f640df22bb0eb62c66f129e {
	meta:
		aliases = "_interwork_r11_call_via_sp"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 1D E3 04 E0 0B 05 35 EE 4F 02 1D FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_call_via_sp_f854cc5fbaf83083d9daabf62c97e111 {
	meta:
		aliases = "_interwork_call_via_sp"
		size = "20"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 1D E3 08 E0 2D 05 CD EF 4F 02 1D FF 2F E1 78 }
	condition:
		$pattern
}

rule _interwork_call_via_lr_1ccb92c45b8173b31e3fa5e8d804d546 {
	meta:
		aliases = "_interwork_call_via_lr"
		size = "24"
		objfiles = "_interwork_call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 01 00 1E E3 00 C0 2D 09 0E C0 A0 E1 DD EF 4F 02 1C FF 2F E1 }
	condition:
		$pattern
}

rule _call_via_r0_5b031b4d8ebcaa62c596fffaaee922e3 {
	meta:
		aliases = "_call_via_r0"
		size = "4"
		objfiles = "crti, _call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 08 }
	condition:
		$pattern
}

rule _call_via_r1_be5e4bba9c4a978962f728ed64696505 {
	meta:
		aliases = "_call_via_r1"
		size = "4"
		objfiles = "crti, _call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 10 }
	condition:
		$pattern
}

rule _call_via_r2_64ca69a4420d06e4a98997643578a571 {
	meta:
		aliases = "_call_via_r2"
		size = "4"
		objfiles = "crti, _call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 18 }
	condition:
		$pattern
}

rule _call_via_r3_cf57cde4e482f83413acab9492c899df {
	meta:
		aliases = "_call_via_r3"
		size = "4"
		objfiles = "crti, _call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 20 }
	condition:
		$pattern
}

rule _call_via_r4_0254669e680a389a879c100fc453c4dd {
	meta:
		aliases = "_call_via_r4"
		size = "4"
		objfiles = "crti, _call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 28 }
	condition:
		$pattern
}

rule _call_via_r5_8e926ce299e138048f65e09d6e44086c {
	meta:
		aliases = "_call_via_r5"
		size = "4"
		objfiles = "crti, _call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 30 }
	condition:
		$pattern
}

rule _call_via_r6_0659fc8bea273725fd0519eccd8c03f1 {
	meta:
		aliases = "_call_via_r6"
		size = "4"
		objfiles = "crti, _call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 38 }
	condition:
		$pattern
}

rule _call_via_r7_b683fac0a5aad27b348763bbd4f27784 {
	meta:
		aliases = "_call_via_r7"
		size = "4"
		objfiles = "crti, _call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 40 }
	condition:
		$pattern
}

rule _call_via_r8_8148cee4b834ebd4a829f1f4c6d01415 {
	meta:
		aliases = "_call_via_r8"
		size = "4"
		objfiles = "crti, _call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 48 }
	condition:
		$pattern
}

rule _call_via_r9_ed954fd74cfef475757f7e9338697496 {
	meta:
		aliases = "_call_via_r9"
		size = "4"
		objfiles = "crti, _call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 50 }
	condition:
		$pattern
}

rule _call_via_sl_435113baf57d7f208bdbf6eafd76947e {
	meta:
		aliases = "_call_via_sl"
		size = "4"
		objfiles = "crti, _call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 58 }
	condition:
		$pattern
}

rule _call_via_fp_0b311d623ed7fff8d87b6f18b1abf99b {
	meta:
		aliases = "_call_via_fp"
		size = "4"
		objfiles = "crti, _call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 60 }
	condition:
		$pattern
}

rule _call_via_ip_279723ec5ceeb1441e0fed23849fdf94 {
	meta:
		aliases = "_call_via_ip"
		size = "4"
		objfiles = "crti, _call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 68 }
	condition:
		$pattern
}

rule _call_via_sp_f99bc9628d188a4f57175adfb136cea9 {
	meta:
		aliases = "_call_via_sp"
		size = "4"
		objfiles = "crti, _call_via_rX@libgcc.a"
	strings:
		$pattern = { 47 C0 46 70 }
	condition:
		$pattern
}

rule __libc_allocate_rtsig_ee3f880ce24153246c94ce1091fd3747 {
	meta:
		aliases = "__libc_allocate_rtsig"
		size = "96"
		objfiles = "pthreads@libpthread.a, allocrtsigs@libc.a"
	strings:
		$pattern = { 4C 10 9F E5 04 E0 2D E5 48 E0 9F E5 01 10 8F E0 0E 20 91 E7 01 00 72 E3 0A 00 00 0A 38 C0 9F E5 0C 30 91 E7 03 00 52 E1 06 00 00 CA 00 00 50 E3 01 30 82 12 03 20 A0 01 01 30 43 02 0E 30 81 17 0C 30 81 07 00 00 00 EA 00 20 E0 E3 02 00 A0 E1 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clnt_sperrno_069408c45a4a959c56481291ef1d5313 {
	meta:
		aliases = "__GI_clnt_sperrno, clnt_sperrno"
		size = "100"
		objfiles = "clnt_perrors@libc.a"
	strings:
		$pattern = { 4C 10 9F E5 4C 30 9F E5 01 10 8F E0 03 C0 81 E0 00 20 A0 E3 09 00 00 EA 82 31 9C E7 00 00 53 E1 05 00 00 1A 82 31 8C E0 04 20 93 E5 28 30 9F E5 03 30 81 E0 03 00 82 E0 1E FF 2F E1 01 20 82 E2 11 00 52 E3 F3 FF FF 9A 10 30 9F E5 03 00 81 E0 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_abort_12423e9e9a916911ccbec5375f4b8232 {
	meta:
		aliases = "abort, __GI_abort"
		size = "360"
		objfiles = "aborts@libc.a"
	strings:
		$pattern = { 4C 51 9F E5 4C 01 9F E5 05 50 8F E0 11 DE 4D E2 00 00 85 E0 40 31 9F E5 0F E0 A0 E1 03 F0 95 E7 20 20 A0 E3 00 10 A0 E3 02 00 00 EA 11 0E 8D E2 02 31 80 E0 80 10 03 E5 01 20 52 E2 FA FF FF 5A 90 40 8D E2 04 00 A0 E1 06 10 A0 E3 ?? ?? ?? ?? 00 00 50 E3 03 00 00 1A 00 20 A0 E1 04 10 A0 E1 01 00 A0 E3 ?? ?? ?? ?? F0 20 9F E5 02 30 95 E7 00 00 53 E3 0D 00 00 1A 01 30 83 E2 02 30 85 E7 D0 40 9F E5 D8 30 9F E5 04 40 85 E0 04 00 A0 E1 0F E0 A0 E1 03 F0 95 E7 06 00 A0 E3 ?? ?? ?? ?? 04 00 A0 E1 B0 30 9F E5 0F E0 A0 E1 03 F0 95 E7 A8 20 9F E5 02 30 95 E7 01 00 53 E3 16 00 00 1A 01 30 83 E2 02 30 85 E7 }
	condition:
		$pattern
}

rule localeconv_9dc582fa8352b41c34daa7a999f107cb {
	meta:
		aliases = "__GI_localeconv, localeconv"
		size = "100"
		objfiles = "localeconvs@libc.a"
	strings:
		$pattern = { 50 00 9F E5 50 20 9F E5 50 30 9F E5 00 00 8F E0 03 30 80 E0 02 10 80 E0 02 30 80 E7 01 30 83 E2 01 C0 A0 E1 24 20 81 E2 04 30 A1 E5 02 00 51 E1 FC FF FF 3A 20 30 9F E5 28 20 8C E2 03 00 80 E0 35 10 80 E2 00 30 E0 E3 01 30 C2 E4 01 00 52 E1 FC FF FF 9A 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mblen_1d7671e0ca988f4269d4f9b220dcd0d2 {
	meta:
		aliases = "mblen"
		size = "100"
		objfiles = "mblens@libc.a"
	strings:
		$pattern = { 50 20 9F E5 00 C0 50 E2 10 40 2D E9 02 20 8F E0 03 00 00 1A 40 30 9F E5 0C 00 A0 E1 03 C0 82 E7 10 80 BD E8 00 30 DC E5 00 00 53 E3 03 00 A0 01 10 80 BD 08 20 30 9F E5 03 40 82 E0 04 20 A0 E1 ?? ?? ?? ?? 02 00 70 E3 10 30 9F 05 01 00 80 02 04 30 84 05 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? FF FF 00 00 }
	condition:
		$pattern
}

rule wctrans_3965b7ac578d308e5dfbf74871306298 {
	meta:
		aliases = "wctype, __GI_wctype, __GI_wctrans, wctrans"
		size = "96"
		objfiles = "wctypes@libc.a, wctranss@libc.a"
	strings:
		$pattern = { 50 20 9F E5 50 30 9F E5 02 20 8F E0 70 40 2D E9 03 10 82 E0 00 60 A0 E1 01 50 A0 E3 01 40 81 E2 06 00 A0 E1 04 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 01 00 00 1A 05 00 A0 E1 70 80 BD E8 01 30 54 E5 01 50 85 E2 03 00 D4 E7 03 10 84 E0 00 00 50 E3 F1 FF FF 1A 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule putwchar_bf78a26ba2514137c4f3bed92019806e {
	meta:
		aliases = "putwchar"
		size = "96"
		objfiles = "putwchars@libc.a"
	strings:
		$pattern = { 50 30 9F E5 50 20 9F E5 03 30 8F E0 02 20 93 E7 04 E0 2D E5 00 10 92 E5 00 E0 A0 E1 34 30 91 E5 00 00 53 E3 05 00 00 0A 10 C0 91 E5 1C 30 91 E5 03 00 5C E1 03 00 00 3A 04 E0 9D E4 ?? ?? ?? ?? 04 E0 9D E4 ?? ?? ?? ?? FF 00 00 E2 01 00 CC E4 10 C0 81 E5 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule perror_3ed5a3ec267cbcab7dc577a2758fac84 {
	meta:
		aliases = "__GI_perror, perror"
		size = "104"
		objfiles = "perrors@libc.a"
	strings:
		$pattern = { 50 C0 9F E5 00 20 50 E2 04 E0 2D E5 0C C0 8F E0 04 00 00 0A 00 30 D2 E5 00 00 53 E3 38 30 9F 15 03 E0 8C 10 03 00 00 1A 2C 30 9F E5 03 30 8C E0 02 E0 83 E2 0E 20 A0 E1 20 30 9F E5 20 10 9F E5 03 30 9C E7 01 10 8C E0 00 00 93 E5 0E 30 A0 E1 04 E0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _dl_unmap_cache_b371071bfc3033eac5ca9ca9cea31112 {
	meta:
		aliases = "_dl_unmap_cache"
		size = "104"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { 50 C0 9F E5 80 40 2D E9 4C E0 9F E5 0C C0 8F E0 0E 00 9C E7 01 30 40 E2 03 00 73 E3 00 00 E0 83 80 80 BD 88 34 30 9F E5 5B 70 A0 E3 03 10 9C E7 00 00 00 EF 01 0A 70 E3 24 20 9F 85 00 30 60 82 02 20 9C 87 00 30 82 85 00 30 A0 E3 03 00 A0 E1 0E 30 8C E7 80 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule a64l_bc6eaaa4204b21c7fd0635914a320524 {
	meta:
		aliases = "a64l"
		size = "100"
		objfiles = "a64ls@libc.a"
	strings:
		$pattern = { 54 30 9F E5 54 20 9F E5 03 30 8F E0 00 C0 A0 E3 04 E0 2D E5 0C 10 A0 E1 02 E0 83 E0 00 20 A0 E1 06 00 80 E2 00 30 D2 E5 01 20 82 E2 2E 30 43 E2 4C 00 53 E3 06 00 00 8A 03 30 DE E7 40 00 53 E3 03 00 00 0A 00 00 52 E1 13 C1 8C E1 06 10 81 E2 F3 FF FF 1A 0C 00 A0 E1 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule l64a_4ba2bf7d9b14db92822e4b3f9787de3e {
	meta:
		aliases = "l64a"
		size = "116"
		objfiles = "l64as@libc.a"
	strings:
		$pattern = { 5C 20 9F E5 00 00 50 E3 10 40 2D E9 02 20 8F E0 02 00 00 1A 4C 30 9F E5 03 00 82 E0 10 80 BD E8 44 E0 9F E5 44 30 9F E5 00 10 A0 E3 03 40 82 E0 0E C0 82 E0 03 00 00 EA 03 30 D4 E7 20 03 A0 E1 01 30 CC E7 01 10 81 E2 00 00 50 E3 3F 30 00 E2 F8 FF FF 1A 0E 30 82 E0 01 00 C3 E7 03 00 A0 E1 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __clzsi2_0a205c7fb9219773b019f8121497d79a {
	meta:
		aliases = "__clzsi2"
		size = "116"
		objfiles = "_clzsi2@libgcc.a"
	strings:
		$pattern = { 64 20 9F E5 01 08 50 E3 02 20 8F E0 0A 00 00 2A FF 00 50 E3 08 10 A0 83 00 10 A0 93 30 11 A0 E1 48 30 9F E5 18 C0 A0 83 20 C0 A0 93 03 20 92 E7 01 00 D2 E7 0C 00 60 E0 1E FF 2F E1 FF 34 E0 E3 03 00 50 E1 18 10 A0 83 10 10 A0 93 30 11 A0 E1 18 30 9F E5 08 C0 A0 83 10 C0 A0 93 03 20 92 E7 01 00 D2 E7 0C 00 60 E0 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __xpg_basename_a2299b48bbbb5ec58d02832d11bb120c {
	meta:
		aliases = "__xpg_basename"
		size = "120"
		objfiles = "__xpg_basenames@libc.a"
	strings:
		$pattern = { 68 20 9F E5 00 00 50 E3 02 20 8F E0 04 00 00 0A 00 30 D0 E5 00 00 53 E3 01 20 40 12 00 C0 A0 11 02 00 00 1A 48 30 9F E5 03 C0 82 E0 0D 00 00 EA 00 30 D0 E5 2F 00 53 E3 03 00 00 0A 01 20 82 E2 02 00 50 E1 00 C0 A0 81 0C 20 A0 81 01 10 F0 E5 00 00 51 E3 F5 FF FF 1A 00 30 DC E5 2F 00 53 E3 0C 20 A0 01 01 10 C2 E5 0C 00 A0 E1 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI___assert_484a245507c5a1e3e9973924614301ad {
	meta:
		aliases = "__assert, __GI___assert"
		size = "136"
		objfiles = "__asserts@libc.a"
	strings:
		$pattern = { 68 E0 9F E5 68 60 9F E5 0E E0 8F E0 06 C0 9E E7 10 D0 4D E2 00 00 5C E3 00 70 A0 E1 01 40 A0 E1 02 50 A0 E1 03 C0 A0 E1 0F 00 00 1A 44 30 9F E5 00 00 5C E3 03 20 9E E7 01 30 A0 E3 06 30 8E E7 34 30 9F E5 00 00 92 E5 03 20 9E E7 2C 30 9F 05 03 C0 8E 00 28 10 9F E5 04 30 A0 E1 01 10 8E E0 20 10 8D E8 08 70 8D E5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __ffssi2_953e0df118ff22bb8f041de9b34f84ac {
	meta:
		aliases = "__ffssi2"
		size = "124"
		objfiles = "_ffssi2@libgcc.a"
	strings:
		$pattern = { 6C 20 9F E5 00 00 50 E3 02 20 8F E0 1E FF 2F 01 00 30 60 E2 00 00 03 E0 01 08 50 E3 0A 00 00 3A FF 34 E0 E3 03 00 50 E1 18 10 A0 83 10 10 A0 93 30 01 A0 E1 3C 30 9F E5 01 C0 A0 E1 03 20 92 E7 00 10 D2 E7 0C 00 81 E0 1E FF 2F E1 FF 00 50 E3 08 10 A0 83 00 10 A0 93 30 01 A0 E1 14 30 9F E5 01 C0 A0 E1 03 20 92 E7 00 10 D2 E7 0C 00 81 E0 1E FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __absvdi2_9e7483b2565a3b59ce5050e5fcf80093 {
	meta:
		aliases = "__absvdi2"
		size = "44"
		objfiles = "_absvdi2@libgcc.a"
	strings:
		$pattern = { 70 00 2D E9 C1 3F A0 E1 C1 4F A0 E1 00 50 23 E0 01 60 24 E0 05 00 A0 E1 06 10 A0 E1 03 00 50 E0 04 10 C1 E0 70 00 BD E8 1E FF 2F E1 }
	condition:
		$pattern
}

rule dl_iterate_phdr_44e42968cb9d0b1378e62bd7ddfe0dbd {
	meta:
		aliases = "dl_iterate_phdr"
		size = "136"
		objfiles = "dl_iterate_phdrs@libc.a"
	strings:
		$pattern = { 70 20 9F E5 70 30 9F E5 02 20 8F E0 70 40 2D E9 03 30 92 E7 10 D0 4D E2 00 40 93 E5 00 60 A0 E1 00 00 54 E3 01 50 A0 E1 0D 00 00 0A 4C 30 9F E5 4C C0 9F E5 03 30 92 E7 0C C0 82 E0 00 E0 93 E5 00 30 A0 E3 0D 00 A0 E1 10 10 A0 E3 05 20 A0 E1 08 50 8D E8 BC 40 CD E1 36 FF 2F E1 00 00 50 E3 02 00 00 1A 06 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getenv_e3e1360bb569b647f77340fdd72d14a6 {
	meta:
		aliases = "__GI_getenv, getenv"
		size = "128"
		objfiles = "getenvs@libc.a"
	strings:
		$pattern = { 70 30 9F E5 70 20 9F E5 03 30 8F E0 F0 40 2D E9 02 20 93 E7 04 D0 4D E2 00 60 92 E5 00 70 A0 E1 00 00 56 E3 10 00 00 0A ?? ?? ?? ?? 00 50 A0 E1 07 00 00 EA ?? ?? ?? ?? 00 00 50 E3 05 20 84 E0 03 00 00 1A 05 30 D4 E7 3D 00 53 E3 01 00 82 02 06 00 00 0A 00 40 96 E5 07 00 A0 E1 00 10 54 E2 05 20 A0 E1 04 60 86 E2 F1 FF FF 1A 00 00 A0 E3 04 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_kill_other_threads_np_ba8d68f737b99f03bcf554e963ada797 {
	meta:
		aliases = "__pthread_kill_other_threads_np, pthread_kill_other_threads_np"
		size = "160"
		objfiles = "pthreads@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 00 A0 E3 00 10 A0 E1 90 D0 4D E2 90 FF FF EB 04 60 8D E2 ?? ?? ?? ?? 04 00 86 E2 ?? ?? ?? ?? 64 40 9F E5 64 30 9F E5 04 40 8F E0 03 30 94 E7 00 50 A0 E3 00 00 93 E5 06 10 A0 E1 05 20 A0 E1 88 50 8D E5 04 50 8D E5 ?? ?? ?? ?? 40 30 9F E5 06 10 A0 E1 03 30 94 E7 05 20 A0 E1 00 00 93 E5 ?? ?? ?? ?? 2C 30 9F E5 03 30 94 E7 00 00 93 E5 05 00 50 E1 02 00 00 DA 06 10 A0 E1 05 20 A0 E1 ?? ?? ?? ?? 90 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_rwlock_destroy_a23347d59ed9df3cd425ec38ae59263c {
	meta:
		aliases = "pthread_rwlock_destroy"
		size = "56"
		objfiles = "rwlocks@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 10 A0 E3 00 40 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 08 60 94 E5 0C 50 94 E5 ?? ?? ?? ?? 00 00 56 E3 00 00 55 D3 00 00 A0 03 01 00 A0 13 10 00 A0 13 70 80 BD E8 }
	condition:
		$pattern
}

rule pthread_rwlock_unlock_fb58e29752d661e2f7fd149e076327df {
	meta:
		aliases = "pthread_rwlock_unlock"
		size = "408"
		objfiles = "rwlocks@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 10 A0 E3 00 50 A0 E1 ?? ?? ?? ?? 0C 40 95 E5 00 00 54 E3 21 00 00 0A 00 FF FF EB 00 00 54 E1 21 00 00 1A 18 30 95 E5 00 60 A0 E3 06 00 53 E1 0C 60 85 E5 0B 00 00 0A 14 40 95 E5 06 00 54 E1 08 00 00 0A 08 30 94 E5 05 00 A0 E1 14 30 85 E5 08 60 84 E5 ?? ?? ?? ?? 04 00 A0 E1 EE FE FF EB 06 00 A0 E1 70 80 BD E8 00 40 A0 E3 10 60 95 E5 05 00 A0 E1 10 40 85 E5 ?? ?? ?? ?? 04 50 A0 E1 03 00 00 EA 08 40 96 E5 08 50 86 E5 E2 FE FF EB 04 60 A0 E1 00 00 56 E2 F9 FF FF 1A 3A 00 00 EA 08 30 95 E5 00 00 53 E3 03 00 00 1A 05 00 A0 E1 ?? ?? ?? ?? 01 00 A0 E3 70 80 BD E8 01 20 43 E2 00 00 52 E3 }
	condition:
		$pattern
}

rule updwtmp_c4dc3c13e65f44ddd382274023811c8e {
	meta:
		aliases = "updwtmp"
		size = "96"
		objfiles = "wtents@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 20 A0 E3 01 60 A0 E1 48 10 9F E5 ?? ?? ?? ?? 00 40 50 E2 70 80 BD B8 01 10 A0 E3 00 20 A0 E3 ?? ?? ?? ?? 00 50 50 E2 70 80 BD 18 06 10 A0 E1 04 00 A0 E1 06 2D A0 E3 ?? ?? ?? ?? 04 00 A0 E1 05 10 A0 E1 05 20 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 70 40 BD E8 ?? ?? ?? ?? 01 04 00 00 }
	condition:
		$pattern
}

rule __GI_strtof_fcf3199beb4d6b54a9356a34ac99bff1 {
	meta:
		aliases = "strtof, __GI_wcstof, wcstof, __GI_strtof"
		size = "52"
		objfiles = "wcstofs@libc.a, strtofs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 20 A0 E3 ?? ?? ?? ?? 01 50 A0 E1 00 40 A0 E1 ?? ?? ?? ?? 00 60 A0 E1 ?? ?? ?? ?? 04 20 A0 E1 05 30 A0 E1 ?? ?? ?? ?? 06 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule __GI_strtok_r_b0a4b66aa9aff750f8c920050a261d5f {
	meta:
		aliases = "strtok_r, __GI_strtok_r"
		size = "116"
		objfiles = "strtok_rs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 50 E2 00 40 92 05 02 50 A0 E1 04 00 A0 E1 01 60 A0 E1 ?? ?? ?? ?? 00 30 D4 E7 00 40 84 E0 00 00 53 E3 00 40 85 05 0E 00 00 0A 06 10 A0 E1 04 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 05 00 00 1A 00 10 A0 E1 04 00 A0 E1 ?? ?? ?? ?? 04 30 A0 E1 00 00 85 E5 03 00 00 EA 00 30 A0 E3 01 30 C0 E4 00 00 85 E5 04 30 A0 E1 03 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule __cxa_atexit_6d0d6a2255cde7a78e83734f595a7219 {
	meta:
		aliases = "__GI___cxa_atexit, __cxa_atexit"
		size = "64"
		objfiles = "__cxa_atexits@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 50 E2 01 50 A0 E1 02 60 A0 E1 04 00 A0 01 70 80 BD 08 ?? ?? ?? ?? 00 00 50 E3 03 30 A0 13 00 30 80 15 04 40 80 15 08 50 80 15 0C 60 80 15 00 00 E0 03 00 00 A0 13 70 80 BD E8 }
	condition:
		$pattern
}

rule tfind_70d0aac303907d39ff89396c0e6f0282 {
	meta:
		aliases = "__GI_tfind, tfind"
		size = "84"
		objfiles = "tfinds@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 51 E2 00 60 A0 E1 02 50 A0 E1 0D 00 00 0A 08 00 00 EA 00 10 91 E5 35 FF 2F E1 00 00 50 E3 01 00 00 1A 00 00 94 E5 70 80 BD E8 00 00 94 E5 04 40 80 B2 08 40 80 A2 00 10 94 E5 06 00 A0 E1 00 00 51 E3 F2 FF FF 1A 00 00 A0 E3 70 80 BD E8 }
	condition:
		$pattern
}

rule __encode_question_683f670eb5aeb78ebd7380332a620abc {
	meta:
		aliases = "__encode_question"
		size = "92"
		objfiles = "encodeqs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 A0 E1 00 00 90 E5 01 60 A0 E1 02 50 A0 E1 ?? ?? ?? ?? 00 00 50 E3 70 80 BD B8 05 30 60 E0 03 00 53 E3 00 00 E0 D3 70 80 BD D8 05 30 D4 E5 00 20 86 E0 00 30 C6 E7 04 30 94 E5 04 00 80 E2 01 30 C2 E5 09 30 D4 E5 02 30 C2 E5 08 30 94 E5 03 30 C2 E5 70 80 BD E8 }
	condition:
		$pattern
}

rule xprt_unregister_a3c8ae0e282a5298b3fb5d2693c6c0db {
	meta:
		aliases = "__GI_xprt_unregister, xprt_unregister"
		size = "152"
		objfiles = "svcs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 A0 E1 00 50 90 E5 ?? ?? ?? ?? 00 00 55 E1 70 80 BD A8 ?? ?? ?? ?? B4 10 90 E5 05 21 A0 E1 02 30 91 E7 04 00 53 E1 70 80 BD 18 00 30 A0 E3 01 0B 55 E3 02 30 81 E7 02 00 00 BA 00 40 A0 E3 00 60 E0 E3 0D 00 00 EA ?? ?? ?? ?? A5 C2 A0 E1 0C 31 90 E7 1F 10 05 E2 01 20 A0 E3 12 31 C3 E1 0C 31 80 E7 F4 FF FF EA ?? ?? ?? ?? 00 00 90 E5 84 31 90 E7 05 00 53 E1 84 61 80 07 01 40 84 E2 ?? ?? ?? ?? 00 30 90 E5 03 00 54 E1 F5 FF FF BA 70 80 BD E8 }
	condition:
		$pattern
}

rule __GI_strcspn_a8f53e2cf7b75c687982b4bf02555f95 {
	meta:
		aliases = "strcspn, __GI_strcspn"
		size = "64"
		objfiles = "strcspns@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 A0 E1 01 60 A0 E1 00 50 A0 E3 03 00 00 EA ?? ?? ?? ?? 00 00 50 E3 05 00 00 1A 01 50 85 E2 00 30 D4 E5 06 00 A0 E1 00 10 53 E2 01 40 84 E2 F6 FF FF 1A 05 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule obstack_free_13e67218e1e2b90f3050138a4ea685cf {
	meta:
		aliases = "obstack_free"
		size = "148"
		objfiles = "obstacks@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 A0 E1 04 00 90 E5 01 50 A0 E1 0D 00 00 EA 28 30 D4 E5 04 60 90 E5 01 00 13 E3 20 30 94 E5 03 00 00 0A 00 10 A0 E1 24 00 94 E5 33 FF 2F E1 00 00 00 EA 33 FF 2F E1 28 30 D4 E5 06 00 A0 E1 02 30 83 E3 28 30 C4 E5 00 00 50 E3 0C 00 00 0A 05 00 50 E1 ED FF FF 2A 00 30 90 E5 05 00 53 E1 EA FF FF 3A 00 00 50 E3 05 00 00 0A 08 50 84 E5 0C 50 84 E5 00 30 90 E5 04 00 84 E5 10 30 84 E5 70 80 BD E8 00 00 55 E3 70 80 BD 08 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_attr_setschedparam_194b0049eaf4fbc3b2b628aafbdf992d {
	meta:
		aliases = "__GI_pthread_attr_setschedparam, pthread_attr_setschedparam"
		size = "84"
		objfiles = "attrs@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 A0 E1 04 00 90 E5 01 60 A0 E1 ?? ?? ?? ?? 00 50 A0 E1 04 00 94 E5 ?? ?? ?? ?? 00 30 96 E5 00 00 53 E1 07 00 00 BA 05 00 53 E1 05 00 00 CA 08 00 84 E2 06 10 A0 E1 04 20 A0 E3 ?? ?? ?? ?? 00 00 A0 E3 70 80 BD E8 16 00 A0 E3 70 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_alt_lock_fd7cbecc06001b32740ac5b1e7b73b4d {
	meta:
		aliases = "__pthread_alt_lock"
		size = "124"
		objfiles = "spinlocks@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 A0 E1 10 D0 4D E2 04 00 80 E2 01 60 A0 E1 A3 FF FF EB 00 50 94 E5 00 00 55 E3 01 30 A0 03 05 20 A0 01 00 30 84 05 0A 00 00 0A 00 00 56 E3 01 00 00 1A C7 FF FF EB 00 60 A0 E1 00 30 A0 E3 0C 30 8D E5 04 30 8D E2 04 50 8D E5 00 30 84 E5 08 60 8D E5 01 20 A0 E3 00 30 A0 E3 04 30 84 E5 03 00 52 E1 01 00 00 0A 06 00 A0 E1 E1 FF FF EB 10 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule _obstack_begin_1_d37404b6e7798ef9028009ab6b344878 {
	meta:
		aliases = "_obstack_begin_1"
		size = "212"
		objfiles = "obstacks@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 A0 E1 28 00 D0 E5 00 00 52 E3 01 00 80 E3 28 00 C4 E5 02 60 A0 11 AC 20 9F E5 08 60 A0 03 28 00 D4 E5 00 00 51 E3 02 10 A0 01 14 C0 9D E5 03 20 A0 E1 10 30 9D E5 01 50 46 E2 01 00 10 E3 20 30 84 E5 1C 20 84 E5 00 10 84 E5 18 50 84 E5 24 C0 84 E5 02 00 00 0A 0C 00 A0 E1 32 FF 2F E1 01 00 00 EA 01 00 A0 E1 32 FF 2F E1 00 00 50 E3 04 00 84 E5 00 00 00 1A 83 00 00 EB 08 20 80 E2 00 10 94 E5 00 30 66 E2 02 20 85 E0 03 20 02 E0 01 10 80 E0 00 30 A0 E3 04 30 80 E5 0C 20 84 E5 08 20 84 E5 00 10 80 E5 28 30 D4 E5 01 00 A0 E3 02 30 C3 E3 28 30 C4 E5 28 30 D4 E5 10 10 84 E5 04 30 C3 E3 }
	condition:
		$pattern
}

rule _obstack_begin_8c637f321ebe0962d79c940bd05641e8 {
	meta:
		aliases = "_obstack_begin"
		size = "204"
		objfiles = "obstacks@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 A0 E1 28 00 D0 E5 00 00 52 E3 01 00 C0 E3 02 60 A0 11 28 00 C4 E5 A4 20 9F E5 08 60 A0 03 28 00 D4 E5 00 00 51 E3 02 10 A0 01 03 20 A0 E1 10 30 9D E5 01 50 46 E2 01 00 10 E3 20 30 84 E5 1C 20 84 E5 00 10 84 E5 18 50 84 E5 02 00 00 0A 24 00 94 E5 32 FF 2F E1 01 00 00 EA 01 00 A0 E1 32 FF 2F E1 00 00 50 E3 04 00 84 E5 00 00 00 1A B8 00 00 EB 08 20 80 E2 00 10 94 E5 00 30 66 E2 02 20 85 E0 03 20 02 E0 01 10 80 E0 00 30 A0 E3 04 30 80 E5 0C 20 84 E5 08 20 84 E5 00 10 80 E5 28 30 D4 E5 01 00 A0 E3 02 30 C3 E3 28 30 C4 E5 28 30 D4 E5 10 10 84 E5 04 30 C3 E3 28 30 C4 E5 70 80 BD E8 }
	condition:
		$pattern
}

rule strstr_dee742a899d8d686aff27efdc32575eb {
	meta:
		aliases = "__GI_strstr, strstr"
		size = "244"
		objfiles = "strstrs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 D1 E5 00 00 54 E3 70 80 BD 08 01 00 40 E2 01 30 F0 E5 00 00 53 E3 32 00 00 0A 04 00 53 E1 FA FF FF 1A 01 50 D1 E5 01 60 81 E2 00 00 55 E3 01 30 D0 15 01 00 80 12 70 80 BD 08 0D 00 00 EA 01 30 D0 E5 01 00 80 E2 07 00 00 EA 00 00 53 E3 24 00 00 0A 01 30 F0 E5 04 00 53 E1 04 00 00 0A 00 00 53 E3 1F 00 00 0A 01 30 F0 E5 04 00 53 E1 F5 FF FF 1A 01 30 F0 E5 05 00 53 E1 FA FF FF 1A 01 30 D0 E5 01 20 D6 E5 01 C0 80 E2 01 E0 86 E2 02 00 53 E1 01 00 40 E2 0F 00 00 1A 00 00 52 E3 70 80 BD 08 01 30 DC E5 01 20 DE E5 01 10 8C E2 02 00 53 E1 01 30 8E E2 01 C0 81 E2 01 E0 83 E2 05 00 00 1A }
	condition:
		$pattern
}

rule dlsym_300d03f077d5022120079dd3814df5eb {
	meta:
		aliases = "dlsym"
		size = "284"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { 70 40 2D E9 00 41 9F E5 00 00 50 E3 04 40 8F E0 0E 50 A0 E1 01 60 A0 E1 F0 30 9F 05 03 30 94 07 00 10 93 05 28 00 00 0A 01 00 70 E3 00 10 A0 E1 D8 30 9F E5 12 00 00 0A 03 30 94 E7 00 30 93 E5 03 00 50 E1 20 00 00 0A C4 30 9F E5 03 30 94 E7 00 30 93 E5 02 00 00 EA 00 00 53 E1 1A 00 00 0A 04 30 93 E5 00 00 53 E3 FA FF FF 1A A4 30 9F E5 00 00 A0 E3 03 20 94 E7 09 30 A0 E3 00 30 82 E5 70 80 BD E8 03 30 94 E7 00 E0 A0 E3 00 20 93 E5 0B 00 00 EA 00 00 92 E5 14 C0 90 E5 05 00 5C E1 06 00 00 2A 00 00 5E E3 02 00 00 0A 14 30 9E E5 0C 00 53 E1 01 00 00 2A 10 10 92 E5 00 E0 A0 E1 10 20 92 E5 00 00 52 E3 }
	condition:
		$pattern
}

rule tmpnam_502e385210c017bae814334f89fdd562 {
	meta:
		aliases = "tmpnam"
		size = "136"
		objfiles = "tmpnams@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 50 50 E2 18 D0 4D E2 05 40 A0 11 04 40 8D 02 00 20 A0 E3 04 00 A0 E1 14 10 A0 E3 02 30 A0 E1 ?? ?? ?? ?? 50 60 9F E5 00 00 50 E3 06 60 8F E0 0D 00 00 1A 04 00 A0 E1 03 10 A0 E3 ?? ?? ?? ?? 00 00 50 E3 08 00 00 1A 00 00 55 E3 07 00 00 1A 28 00 9F E5 04 10 A0 E1 00 00 86 E0 14 20 A0 E3 ?? ?? ?? ?? 00 50 A0 E1 00 00 00 EA 00 50 A0 E3 05 00 A0 E1 18 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_xdr_u_hyper_e0e02cdee4a0cc9db14a992195485170 {
	meta:
		aliases = "xdr_u_hyper, __GI_xdr_u_hyper"
		size = "224"
		objfiles = "xdrs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 50 90 E5 08 D0 4D E2 00 00 55 E3 00 40 A0 E1 01 60 A0 E1 12 00 00 1A 00 30 91 E5 04 10 91 E5 00 30 8D E5 04 10 8D E5 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 04 F0 93 E5 00 00 50 E3 05 00 A0 01 23 00 00 0A 04 00 A0 E1 04 30 94 E5 0D 10 A0 E1 0F E0 A0 E1 04 F0 93 E5 00 00 50 E2 01 00 A0 13 1B 00 00 EA 01 00 55 E3 14 00 00 1A 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 12 00 00 0A 04 00 A0 E1 04 30 94 E5 0D 10 A0 E1 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 0B 00 00 0A 0C 00 9D E8 00 40 A0 E3 03 40 A0 E1 00 30 A0 E3 02 30 83 E1 05 00 A0 E1 18 00 86 E8 04 00 00 EA 02 00 55 E3 }
	condition:
		$pattern
}

rule xdr_uint64_t_e411c4dcf4f1b90582727660b96afba4 {
	meta:
		aliases = "xdr_uint64_t"
		size = "216"
		objfiles = "xdr_intXX_ts@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 50 90 E5 08 D0 4D E2 01 00 55 E3 00 40 A0 E1 01 60 A0 E1 16 00 00 0A 03 00 00 3A 02 00 55 E3 01 00 A0 03 28 00 00 0A 26 00 00 EA 00 30 91 E5 04 10 91 E5 00 30 8D E5 04 10 8D E5 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 24 F0 93 E5 00 00 50 E3 1D 00 00 0A 04 00 A0 E1 04 30 94 E5 0D 10 A0 E1 0F E0 A0 E1 24 F0 93 E5 00 00 50 E2 01 00 A0 13 15 00 00 EA 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 0E 00 00 0A 04 00 A0 E1 04 30 94 E5 0D 10 A0 E1 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 07 00 00 0A 0C 00 9D E8 00 40 A0 E3 03 40 A0 E1 00 30 A0 E3 02 30 83 E1 05 00 A0 E1 18 00 86 E8 }
	condition:
		$pattern
}

rule wcscasecmp_afc651194794e6ad1376504a5c69699c {
	meta:
		aliases = "__GI_wcscasecmp, wcscasecmp"
		size = "116"
		objfiles = "wcscasecmps@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 50 A0 E1 01 60 A0 E1 04 00 00 EA 00 00 95 E5 04 60 86 E2 00 00 50 E3 70 80 BD 08 04 50 85 E2 00 30 95 E5 00 20 96 E5 03 00 A0 E1 02 00 53 E1 F5 FF FF 0A ?? ?? ?? ?? 00 40 A0 E1 00 00 96 E5 ?? ?? ?? ?? 00 00 54 E1 EF FF FF 0A 00 00 95 E5 ?? ?? ?? ?? 00 40 A0 E1 00 00 96 E5 ?? ?? ?? ?? 00 00 54 E1 01 00 A0 23 00 00 E0 33 70 80 BD E8 }
	condition:
		$pattern
}

rule pclose_d3c136dbf7e0e8ebe666ce7b38773b74 {
	meta:
		aliases = "pclose"
		size = "296"
		objfiles = "popens@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 51 9F E5 00 41 9F E5 05 50 8F E0 FC 30 9F E5 18 D0 4D E2 04 40 85 E0 04 20 A0 E1 03 10 95 E7 00 60 A0 E1 E8 30 9F E5 04 00 8D E2 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 D8 30 9F E5 0F E0 A0 E1 03 F0 95 E7 D0 20 9F E5 02 40 95 E7 00 00 54 E3 11 00 00 0A 04 30 94 E5 06 00 53 E1 00 30 94 05 02 30 85 07 0C 00 00 0A 04 20 A0 E1 00 40 94 E5 00 00 54 E3 03 00 00 1A ?? ?? ?? ?? 16 30 A0 E3 00 30 80 E5 04 00 00 EA 04 30 94 E5 06 00 53 E1 F4 FF FF 1A 00 30 94 E5 00 30 82 E5 04 00 8D E2 01 10 A0 E3 74 30 9F E5 0F E0 A0 E1 03 F0 95 E7 00 00 54 E3 10 00 00 0A 04 00 A0 E1 08 40 94 E5 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getrpcbyname_292eae11000033afd5bf63c380cdf99c {
	meta:
		aliases = "__GI_getrpcbyname, getrpcbyname"
		size = "104"
		objfiles = "getrpcents@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 00 00 A0 E3 ?? ?? ?? ?? 0E 00 00 EA 00 00 95 E5 06 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 0D 00 00 0A 04 40 95 E5 04 00 00 EA 06 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 07 00 00 0A 04 40 84 E2 00 00 94 E5 00 00 50 E3 F7 FF FF 1A ?? ?? ?? ?? 00 50 50 E2 ED FF FF 1A ?? ?? ?? ?? 05 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule _pthread_cleanup_push_b1f9c319bc2355d342ffe6b307b9a483 {
	meta:
		aliases = "_pthread_cleanup_push"
		size = "64"
		objfiles = "cancels@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 01 40 A0 E1 02 50 A0 E1 A0 FF FF EB 3C 30 90 E5 00 40 86 E5 00 00 53 E3 04 50 86 E5 0C 30 86 E5 02 00 00 0A 03 00 56 E1 00 30 A0 23 0C 30 86 25 3C 60 80 E5 70 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_cleanup_push_defer_62f71b333537177e2b6a0a988deb9f5e {
	meta:
		aliases = "_pthread_cleanup_push_defer, __pthread_cleanup_push_defer"
		size = "80"
		objfiles = "cancels@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 02 50 A0 E1 01 40 A0 E1 BF FF FF EB 00 40 86 E5 3C 20 90 E5 04 50 86 E5 41 30 D0 E5 00 00 52 E3 08 30 86 E5 0C 20 86 E5 02 00 00 0A 02 00 56 E1 00 30 A0 23 0C 30 86 25 00 30 A0 E3 3C 60 80 E5 41 30 C0 E5 70 80 BD E8 }
	condition:
		$pattern
}

rule __GI_strndup_30433c7d904dd28fa4e5f7dd43855000 {
	meta:
		aliases = "strndup, __GI_strndup"
		size = "60"
		objfiles = "strndups@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 01 00 80 E2 ?? ?? ?? ?? 00 50 50 E2 04 00 00 0A 06 10 A0 E1 04 20 A0 E1 ?? ?? ?? ?? 00 30 A0 E3 04 30 C5 E7 05 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule remove_5e50c20342098eea2de41cf01b94e4f9 {
	meta:
		aliases = "__GI_remove, remove"
		size = "64"
		objfiles = "removes@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 06 00 A0 E1 00 50 94 E5 ?? ?? ?? ?? 00 00 50 E3 70 80 BD A8 00 30 94 E5 14 00 53 E3 70 80 BD 18 06 00 A0 E1 00 50 84 E5 70 40 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wcsdup_6764501d31ff314f4f41525302b3f1e3 {
	meta:
		aliases = "wcsdup"
		size = "56"
		objfiles = "wcsdups@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 ?? ?? ?? ?? 01 00 80 E2 00 41 A0 E1 04 00 A0 E1 ?? ?? ?? ?? 00 50 50 E2 02 00 00 0A 06 10 A0 E1 04 20 A0 E1 ?? ?? ?? ?? 05 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule __GI_strdup_d1aca1ba0c8de7457b4489d7ade3fa3e {
	meta:
		aliases = "strdup, __GI_strdup"
		size = "52"
		objfiles = "strdups@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 ?? ?? ?? ?? 01 40 80 E2 04 00 A0 E1 ?? ?? ?? ?? 00 50 50 E2 02 00 00 0A 06 10 A0 E1 04 20 A0 E1 ?? ?? ?? ?? 05 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_perform_cleanup_e971b0e0dd846a8ec5faff3ea06eff53 {
	meta:
		aliases = "__pthread_perform_cleanup"
		size = "76"
		objfiles = "cancels@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 D4 FF FF EB 3C 40 90 E5 00 50 A0 E1 05 00 00 EA 06 00 54 E1 05 00 00 9A 04 00 94 E5 0F E0 A0 E1 00 F0 94 E5 0C 40 94 E5 00 00 54 E3 F7 FF FF 1A 74 31 95 E5 00 00 53 E3 70 80 BD 08 70 40 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule popen_3a494d345fd742da9bd0d893ecc04f47 {
	meta:
		aliases = "popen"
		size = "676"
		objfiles = "popens@libc.a"
	strings:
		$pattern = { 70 40 2D E9 01 40 A0 E1 00 30 D1 E5 68 12 9F E5 40 D0 4D E2 77 00 53 E3 01 10 8F E0 08 10 8D E5 0C 00 8D E5 09 00 00 0A 72 00 53 E3 01 20 A0 03 24 20 8D 05 07 00 00 0A ?? ?? ?? ?? 00 30 A0 E3 14 30 8D E5 16 30 83 E2 00 30 80 E5 87 00 00 EA 00 C0 A0 E3 24 C0 8D E5 0C 00 A0 E3 ?? ?? ?? ?? 00 30 50 E2 14 30 8D 05 80 00 00 0A 38 00 8D E2 18 30 8D E5 ?? ?? ?? ?? 00 00 50 E3 77 00 00 1A 24 00 9D E5 40 10 8D E2 01 30 60 E2 07 20 E0 E3 03 31 81 E0 02 30 93 E7 40 C0 8D E2 1C 30 8D E5 00 31 8C E0 02 30 93 E7 04 10 A0 E1 1C 00 9D E5 20 30 8D E5 ?? ?? ?? ?? 00 00 50 E3 14 00 8D E5 04 00 00 1A 1C 00 9D E5 }
	condition:
		$pattern
}

rule div_5159c31f4dc6ff34fad240d118884059 {
	meta:
		aliases = "div"
		size = "52"
		objfiles = "divs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 01 40 A0 E1 00 50 A0 E1 02 10 A0 E1 04 00 A0 E1 02 60 A0 E1 ?? ?? ?? ?? 96 00 03 E0 00 00 85 E5 04 40 63 E0 05 00 A0 E1 04 40 85 E5 70 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_cleanup_pop_restore_6af4bc8446a47d425e2bfb15e1c71146 {
	meta:
		aliases = "_pthread_cleanup_pop_restore, __pthread_cleanup_pop_restore"
		size = "92"
		objfiles = "cancels@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 01 40 A0 E1 00 50 A0 E1 91 FF FF EB 00 00 54 E3 00 60 A0 E1 02 00 00 0A 04 00 95 E5 0F E0 A0 E1 00 F0 95 E5 42 30 D6 E5 0C 20 95 E5 08 10 95 E5 00 00 53 E3 3C 20 86 E5 41 10 C6 E5 70 80 BD 08 B0 34 D6 E1 01 0C 53 E3 70 80 BD 18 00 00 E0 E3 0D 10 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_fputws_unlocked_76d7f65a2eff6062545881bfdee1e757 {
	meta:
		aliases = "fputws_unlocked, __GI_fputws_unlocked"
		size = "52"
		objfiles = "fputws_unlockeds@libc.a"
	strings:
		$pattern = { 70 40 2D E9 01 40 A0 E1 00 50 A0 E1 ?? ?? ?? ?? 00 60 A0 E1 06 10 A0 E1 05 00 A0 E1 04 20 A0 E1 ?? ?? ?? ?? 06 00 50 E1 00 00 E0 13 00 00 A0 03 70 80 BD E8 }
	condition:
		$pattern
}

rule __getdents_2737898f42bfe9e7f4d4c8222a44e7ea {
	meta:
		aliases = "__getdents"
		size = "112"
		objfiles = "getdentss@libc.a"
	strings:
		$pattern = { 70 40 2D E9 01 40 A0 E1 ?? ?? ?? ?? 00 50 50 E2 05 60 84 C0 0F 00 00 CA 12 00 00 EA B0 31 D4 E1 12 C0 D4 E5 B8 30 C4 E1 B8 20 D4 E1 08 30 94 E5 13 20 42 E2 04 30 84 E5 0A C0 C4 E5 ?? ?? ?? ?? 04 00 A0 E1 04 10 A0 E1 B8 20 D4 E1 ?? ?? ?? ?? B8 30 D4 E1 03 40 84 E0 06 00 54 E1 0B 00 84 E2 13 10 84 E2 EC FF FF 3A 05 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule __GI_fputs_unlocked_53d653423348e87b8bd0019ecb794cb8 {
	meta:
		aliases = "fputs_unlocked, __GI_fputs_unlocked"
		size = "52"
		objfiles = "fputs_unlockeds@libc.a"
	strings:
		$pattern = { 70 40 2D E9 01 50 A0 E1 00 40 A0 E1 ?? ?? ?? ?? 00 60 A0 E1 05 30 A0 E1 04 00 A0 E1 01 10 A0 E3 06 20 A0 E1 ?? ?? ?? ?? 06 00 50 E1 00 00 E0 13 70 80 BD E8 }
	condition:
		$pattern
}

rule pthread_attr_setguardsize_425f22391c4046a1f308c4105711c1f8 {
	meta:
		aliases = "__pthread_attr_setguardsize, pthread_attr_setguardsize"
		size = "64"
		objfiles = "attrs@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 01 50 A0 E1 00 60 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 01 00 40 E2 04 10 A0 E1 05 00 80 E0 ?? ?? ?? ?? 90 04 04 E0 20 30 96 E5 03 00 54 E1 16 00 A0 23 00 00 A0 33 14 40 86 35 70 80 BD E8 }
	condition:
		$pattern
}

rule __xstat64_conv_00ca9e22b39c2f0cc4e3ecc8ed7311d0 {
	meta:
		aliases = "__xstat64_conv"
		size = "200"
		objfiles = "xstatconvs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 01 60 A0 E1 00 50 A0 E1 00 10 A0 E3 68 20 A0 E3 06 00 A0 E1 ?? ?? ?? ?? 18 00 95 E8 0C 20 95 E5 18 00 86 E8 0C 20 86 E5 38 30 95 E5 18 10 95 E5 1C 00 95 E5 38 30 86 E5 48 20 95 E5 60 30 85 E2 18 00 93 E8 48 20 86 E5 50 20 95 E5 60 30 86 E5 64 40 86 E5 50 20 86 E5 58 20 95 E5 20 30 85 E2 18 00 93 E8 58 20 86 E5 4C 20 95 E5 20 30 86 E5 24 40 86 E5 4C 20 86 E5 10 30 95 E5 54 20 95 E5 10 30 86 E5 54 20 86 E5 30 30 85 E2 18 00 93 E8 30 30 86 E5 34 40 86 E5 5C 20 95 E5 14 30 95 E5 18 10 86 E5 14 30 86 E5 1C 00 86 E5 40 30 85 E2 18 00 93 E8 40 30 86 E5 44 40 86 E5 5C 20 86 E5 70 80 BD E8 }
	condition:
		$pattern
}

rule difftime_4900f90af1db7f6c94c0b822e733d7b8 {
	meta:
		aliases = "difftime"
		size = "52"
		objfiles = "difftimes@libc.a"
	strings:
		$pattern = { 70 40 2D E9 01 60 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 06 00 A0 E1 01 50 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 70 80 BD E8 }
	condition:
		$pattern
}

rule powf_951f9f286d45d3e19e3e5b5d081dd964 {
	meta:
		aliases = "atan2f, nextafterf, fmodf, remainderf, hypotf, copysignf, powf"
		size = "56"
		objfiles = "fmodfs@libm.a, powfs@libm.a, atan2fs@libm.a, remainderfs@libm.a, copysignfs@libm.a"
	strings:
		$pattern = { 70 40 2D E9 01 60 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 06 00 A0 E1 01 50 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? 70 80 BD E8 }
	condition:
		$pattern
}

rule __get_hosts_byaddr_r_d187d91e76961cb90d9838f265c98178 {
	meta:
		aliases = "__get_hosts_byaddr_r"
		size = "148"
		objfiles = "get_hosts_byaddr_rs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 02 00 52 E3 48 D0 4D E2 02 50 A0 E1 03 60 A0 E1 02 00 00 0A 0A 00 52 E3 19 00 00 1A 01 00 00 EA 04 00 51 E3 00 00 00 EA 10 00 51 E3 14 00 00 1A 1A 40 8D E2 00 10 A0 E1 04 20 A0 E1 2E 30 A0 E3 05 00 A0 E1 ?? ?? ?? ?? 58 C0 9D E5 04 10 A0 E1 04 C0 8D E5 5C C0 9D E5 05 20 A0 E1 08 C0 8D E5 60 C0 9D E5 02 30 A0 E3 0C C0 8D E5 64 C0 9D E5 00 00 A0 E3 00 60 8D E5 10 C0 8D E5 ?? ?? ?? ?? 00 00 00 EA 00 00 A0 E3 48 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule __GI_ldexp_20389978e8893bca23c869a3bc0b59db {
	meta:
		aliases = "ldexp, __GI_ldexp"
		size = "144"
		objfiles = "s_ldexps@libm.a"
	strings:
		$pattern = { 70 40 2D E9 02 60 A0 E1 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? ?? 00 00 50 E3 19 00 00 0A 04 00 A0 E1 05 10 A0 E1 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? ?? 00 00 50 E3 12 00 00 1A 06 20 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? ?? 00 00 50 E3 06 00 00 0A 04 00 A0 E1 05 10 A0 E1 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? ?? 00 00 50 E3 02 00 00 0A ?? ?? ?? ?? 22 30 A0 E3 00 30 80 E5 04 00 A0 E1 05 10 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule find_exidx_callback_c43b5e629b48b0a60f2feb858ddbce70 {
	meta:
		aliases = "find_exidx_callback"
		size = "124"
		objfiles = "find_exidxs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 08 10 90 E5 BC 40 D0 E1 00 50 90 E5 01 60 A0 E3 00 00 A0 E3 14 00 00 EA 00 30 91 E5 01 00 53 E3 09 00 00 1A 08 30 91 E5 00 E0 92 E5 03 C0 85 E0 0C 00 5E E1 0A 00 00 3A 14 30 91 E5 03 30 8C E0 03 00 5E E1 06 00 A0 31 05 00 00 EA 17 02 53 E3 08 30 91 05 05 30 83 00 04 30 82 05 14 30 91 05 08 30 82 05 01 40 44 E2 20 10 81 E2 00 00 54 E3 E8 FF FF 1A 70 80 BD E8 }
	condition:
		$pattern
}

rule recvmsg_173f22a68af03eaa3b97a2c5505ba556 {
	meta:
		aliases = "write, __GI_waitpid, accept, waitpid, msync, sendmsg, connect, read, lseek, recvmsg"
		size = "76"
		objfiles = "wrapsyscalls@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 08 D0 4D E2 00 40 A0 E1 01 50 A0 E1 02 60 A0 E1 04 10 8D E2 01 00 A0 E3 ?? ?? ?? ?? 05 10 A0 E1 06 20 A0 E1 04 00 A0 E1 ?? ?? ?? ?? 00 10 A0 E3 00 40 A0 E1 04 00 9D E5 ?? ?? ?? ?? 04 00 A0 E1 08 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule __GI_xdr_authunix_parms_1075c0ed6af91de3b3b41b09ad7004ac {
	meta:
		aliases = "xdr_authunix_parms, __GI_xdr_authunix_parms"
		size = "168"
		objfiles = "authunix_prots@libc.a"
	strings:
		$pattern = { 70 40 2D E9 08 D0 4D E2 00 50 A0 E1 01 40 A0 E1 ?? ?? ?? ?? 84 60 9F E5 00 00 50 E3 06 60 8F E0 1B 00 00 0A 05 00 A0 E1 04 10 84 E2 FF 20 A0 E3 ?? ?? ?? ?? 00 00 50 E3 15 00 00 0A 05 00 A0 E1 08 10 84 E2 ?? ?? ?? ?? 00 00 50 E3 10 00 00 0A 05 00 A0 E1 0C 10 84 E2 ?? ?? ?? ?? 00 00 50 E3 0B 00 00 0A 38 E0 9F E5 04 C0 A0 E3 0E E0 86 E0 05 00 A0 E1 10 20 84 E2 14 10 84 E2 10 30 A0 E3 00 50 8D E8 ?? ?? ?? ?? 00 00 50 E2 01 00 A0 13 00 00 00 EA 00 00 A0 E3 08 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_xdr_replymsg_f1d72696f3afd49925281e7c2b7cc59a {
	meta:
		aliases = "xdr_replymsg, __GI_xdr_replymsg"
		size = "124"
		objfiles = "rpc_prots@libc.a"
	strings:
		$pattern = { 70 40 2D E9 08 D0 4D E2 00 60 A0 E1 01 40 A0 E1 ?? ?? ?? ?? 58 50 9F E5 00 00 50 E3 05 50 8F E0 10 00 00 0A 06 00 A0 E1 04 10 84 E2 ?? ?? ?? ?? 00 00 50 E3 0B 00 00 0A 04 30 94 E5 01 00 53 E3 08 00 00 1A 2C 30 9F E5 00 C0 A0 E3 06 00 A0 E1 03 30 85 E0 0C 20 84 E2 08 10 84 E2 00 C0 8D E5 ?? ?? ?? ?? 00 00 00 EA 00 00 A0 E3 08 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule modff_64e67f2c0401d47bef3d3bed75ad3a64 {
	meta:
		aliases = "modff"
		size = "64"
		objfiles = "modffs@libm.a"
	strings:
		$pattern = { 70 40 2D E9 08 D0 4D E2 01 60 A0 E1 ?? ?? ?? ?? 0D 20 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 01 50 A0 E1 03 00 9D E8 ?? ?? ?? ?? 05 10 A0 E1 00 00 86 E5 04 00 A0 E1 ?? ?? ?? ?? 08 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule pthread_rwlock_tryrdlock_f4e6bd08f821c05be173bd0de487b9ba {
	meta:
		aliases = "pthread_rwlock_tryrdlock"
		size = "180"
		objfiles = "rwlocks@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 10 D0 4D E2 00 40 A0 E1 69 FF FF EB 10 30 8D E2 04 00 23 E5 08 20 8D E2 03 00 A0 E1 04 10 A0 E1 04 30 8D E2 BC FF FF EB 0C 10 9D E5 00 60 A0 E1 04 00 A0 E1 ?? ?? ?? ?? 00 10 A0 E3 04 00 A0 E1 13 FF FF EB 00 00 50 E3 08 30 94 15 10 50 A0 03 01 30 83 12 00 50 A0 13 08 30 84 15 04 00 A0 E1 ?? ?? ?? ?? 00 00 55 E3 0D 00 00 1A 00 00 56 E3 02 00 00 1A 04 30 9D E5 00 00 53 E3 08 00 00 0A 08 20 9D E5 00 00 52 E3 0C 20 9D 05 08 30 92 15 C8 31 92 05 01 30 83 12 01 30 83 02 08 30 82 15 C8 31 82 05 05 00 A0 E1 10 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule getservbyname_0ed68b82fc769bb790cf6920b01e5043 {
	meta:
		aliases = "getservbyname"
		size = "100"
		objfiles = "getservices@libc.a"
	strings:
		$pattern = { 70 40 2D E9 10 D0 4D E2 00 50 A0 E1 01 60 A0 E1 24 FE FF EB 38 30 9F E5 38 40 9F E5 00 30 8D E5 0C 30 8D E2 04 30 8D E5 2C 20 9F E5 2C 30 9F E5 04 40 8F E0 03 30 94 E7 05 00 A0 E1 06 10 A0 E1 02 20 84 E0 ?? ?? ?? ?? 0C 00 9D E5 10 D0 8D E2 70 80 BD E8 8D 10 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_getservbyport_4da1e995d18f7e6f5bb3e649ba092452 {
	meta:
		aliases = "getservbyport, __GI_getservbyport"
		size = "100"
		objfiles = "getservices@libc.a"
	strings:
		$pattern = { 70 40 2D E9 10 D0 4D E2 00 50 A0 E1 01 60 A0 E1 8C FE FF EB 38 30 9F E5 38 40 9F E5 00 30 8D E5 0C 30 8D E2 04 30 8D E5 2C 20 9F E5 2C 30 9F E5 04 40 8F E0 03 30 94 E7 05 00 A0 E1 06 10 A0 E1 02 20 84 E0 ?? ?? ?? ?? 0C 00 9D E5 10 D0 8D E2 70 80 BD E8 8D 10 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pread64_1aefa5cf902d089cae78eb96b187e64c {
	meta:
		aliases = "pread64"
		size = "88"
		objfiles = "wrapsyscalls@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 10 D0 4D E2 00 60 A0 E1 01 40 A0 E1 02 50 A0 E1 0C 10 8D E2 01 00 A0 E3 ?? ?? ?? ?? 04 10 A0 E1 05 20 A0 E1 06 00 A0 E1 20 30 8D E2 18 00 93 E8 18 00 8D E8 ?? ?? ?? ?? 00 10 A0 E3 00 40 A0 E1 0C 00 9D E5 ?? ?? ?? ?? 04 00 A0 E1 10 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule lseek64_4afd0f3a2f056d4966b7f6719fa8fb7b {
	meta:
		aliases = "lseek64"
		size = "92"
		objfiles = "wrapsyscalls@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 10 D0 4D E2 00 60 A0 E1 0C 10 8D E2 01 00 A0 E3 02 40 A0 E1 03 50 A0 E1 ?? ?? ?? ?? 20 10 9D E5 04 20 A0 E1 05 30 A0 E1 06 00 A0 E1 00 10 8D E5 ?? ?? ?? ?? 00 40 A0 E1 01 50 A0 E1 0C 00 9D E5 00 10 A0 E3 ?? ?? ?? ?? 04 00 A0 E1 05 10 A0 E1 10 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule lockf_98ba09d509bcd685b8b18d974bf88974 {
	meta:
		aliases = "__GI_lockf, lockf"
		size = "252"
		objfiles = "lockfs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 10 D0 4D E2 02 50 A0 E1 00 60 A0 E1 01 40 A0 E1 0D 00 A0 E1 00 10 A0 E3 10 20 A0 E3 ?? ?? ?? ?? 00 30 A0 E3 04 30 8D E5 01 30 A0 E3 08 50 8D E5 B2 30 CD E1 03 00 54 E3 04 F1 8F 90 24 00 00 EA 16 00 00 EA 18 00 00 EA 19 00 00 EA FF FF FF EA 0D 20 A0 E1 00 30 A0 E3 06 00 A0 E1 05 10 A0 E3 B0 30 CD E1 ?? ?? ?? ?? 00 00 50 E3 00 20 E0 B3 1D 00 00 BA F0 30 DD E1 02 00 53 E3 19 00 00 0A 0C 40 9D E5 ?? ?? ?? ?? 00 00 54 E1 15 00 00 0A ?? ?? ?? ?? 00 20 E0 E3 0D 30 A0 E3 0F 00 00 EA 06 10 A0 E3 02 30 A0 E3 03 00 00 EA 07 10 A0 E3 00 00 00 EA 06 10 A0 E3 01 30 A0 E3 0D 20 A0 E1 06 00 A0 E1 }
	condition:
		$pattern
}

rule pthread_rwlock_rdlock_0860e734e5cc2859719c4d6ac5a640d0 {
	meta:
		aliases = "pthread_rwlock_rdlock"
		size = "224"
		objfiles = "rwlocks@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 10 D0 4D E2 10 30 8D E2 00 20 A0 E3 04 20 23 E5 00 40 A0 E1 04 10 A0 E1 03 00 A0 E1 08 20 8D E2 04 30 8D E2 8F FF FF EB 10 60 84 E2 00 50 A0 E1 0C 30 9D E5 00 00 53 E3 01 00 00 1A 2F FF FF EB 0C 00 8D E5 04 00 A0 E1 0C 10 9D E5 ?? ?? ?? ?? 04 00 A0 E1 05 10 A0 E1 E0 FE FF EB 00 00 50 E3 06 00 A0 E1 06 00 00 1A 0C 10 9D E5 CF FE FF EB 04 00 A0 E1 ?? ?? ?? ?? 0C 00 9D E5 5B FF FF EB EA FF FF EA 08 30 94 E5 04 00 A0 E1 01 30 83 E2 08 30 84 E5 ?? ?? ?? ?? 00 00 55 E3 02 00 00 1A 04 30 9D E5 00 00 53 E3 08 00 00 0A 08 20 9D E5 00 00 52 E3 0C 20 9D 05 08 30 92 15 C8 31 92 05 01 30 83 12 }
	condition:
		$pattern
}

rule gethostbyname2_b4555e220569fca5c1b29489b4c2444b {
	meta:
		aliases = "gethostbyname2"
		size = "100"
		objfiles = "gethostbyname2s@libc.a"
	strings:
		$pattern = { 70 40 2D E9 18 D0 4D E2 00 50 A0 E1 01 60 A0 E1 ?? ?? ?? ?? 3C 40 9F E5 3C 30 9F E5 3C 20 9F E5 04 40 8F E0 76 CF A0 E3 08 00 8D E5 00 C0 8D E5 03 30 84 E0 14 C0 8D E2 05 00 A0 E1 06 10 A0 E1 02 20 84 E0 04 C0 8D E5 ?? ?? ?? ?? 14 00 9D E5 18 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_authnone_create_9dd2750fc0e140d0fba4fb922cddab8b {
	meta:
		aliases = "authnone_create, __GI_authnone_create"
		size = "228"
		objfiles = "auth_nones@libc.a"
	strings:
		$pattern = { 70 40 2D E9 18 D0 4D E2 ?? ?? ?? ?? 98 50 90 E5 C0 60 9F E5 00 00 55 E3 00 40 A0 E1 06 60 8F E0 06 00 00 1A 01 00 A0 E3 40 10 A0 E3 ?? ?? ?? ?? 00 00 50 E3 24 00 00 0A 00 50 A0 E1 98 00 84 E5 3C C0 95 E5 00 00 5C E3 1F 00 00 1A 88 30 9F E5 0C 40 85 E2 03 30 96 E7 07 00 93 E8 7C 30 9F E5 07 00 84 E8 03 30 86 E0 07 00 85 E8 20 30 85 E5 14 20 A0 E3 0C 30 A0 E1 0D 00 A0 E1 28 10 85 E2 ?? ?? ?? ?? 05 10 A0 E1 0D 00 A0 E1 ?? ?? ?? ?? 04 10 A0 E1 0D 00 A0 E1 ?? ?? ?? ?? 04 30 9D E5 0D 00 A0 E1 0F E0 A0 E1 10 F0 93 E5 3C 00 85 E5 04 30 9D E5 0D 60 A0 E1 1C 30 93 E5 00 00 53 E3 01 00 00 0A 0D 00 A0 E1 }
	condition:
		$pattern
}

rule __GI_if_nametoindex_c6f292ad2c133224eff1c5cd9120717e {
	meta:
		aliases = "if_nametoindex, __GI_if_nametoindex"
		size = "144"
		objfiles = "if_indexs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 20 D0 4D E2 00 60 A0 E1 ?? ?? ?? ?? 00 50 50 E2 19 00 00 BA 06 10 A0 E1 10 20 A0 E3 0D 00 A0 E1 ?? ?? ?? ?? 05 00 A0 E1 0D 20 A0 E1 54 10 9F E5 ?? ?? ?? ?? 00 00 50 E3 0D 40 A0 E1 0A 00 00 AA ?? ?? ?? ?? 00 40 90 E5 00 60 A0 E1 05 00 A0 E1 ?? ?? ?? ?? 16 00 54 E3 26 30 A0 03 00 00 A0 03 00 30 86 05 05 00 00 0A 03 00 00 EA 05 00 A0 E1 ?? ?? ?? ?? 10 00 9D E5 00 00 00 EA 00 00 A0 E3 20 D0 8D E2 70 80 BD E8 33 89 00 00 }
	condition:
		$pattern
}

rule __GI_tcgetattr_861f9593c740867eccd822ceb7fbbe5a {
	meta:
		aliases = "tcgetattr, __GI_tcgetattr"
		size = "120"
		objfiles = "tcgetattrs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 28 D0 4D E2 04 60 8D E2 01 40 A0 E1 06 20 A0 E1 58 10 9F E5 ?? ?? ?? ?? 00 50 50 E2 10 00 00 1A 08 20 9D E5 0C 10 9D E5 10 00 9D E5 14 C0 DD E5 04 30 9D E5 04 20 84 E5 08 10 84 E5 0C 00 84 E5 11 10 86 E2 13 20 A0 E3 00 30 84 E5 10 C0 C4 E5 11 00 84 E2 ?? ?? ?? ?? 05 10 A0 E1 0D 20 A0 E3 ?? ?? ?? ?? 05 00 A0 E1 28 D0 8D E2 70 80 BD E8 01 54 00 00 }
	condition:
		$pattern
}

rule valloc_8fbe5e0c290927efb4f28cf31fdfa1aa {
	meta:
		aliases = "valloc"
		size = "64"
		objfiles = "vallocs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 2C 40 9F E5 2C 50 9F E5 04 40 8F E0 05 30 94 E7 00 60 A0 E1 00 00 53 E3 01 00 00 1A ?? ?? ?? ?? 05 00 84 E7 05 00 94 E7 06 10 A0 E1 70 40 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule timegm_20db9ec8568715671cb1fd6f2f66a640 {
	meta:
		aliases = "timegm"
		size = "88"
		objfiles = "timegms@libc.a"
	strings:
		$pattern = { 70 40 2D E9 30 D0 4D E2 00 60 A0 E1 30 20 A0 E3 00 10 A0 E3 0D 00 A0 E1 30 40 9F E5 ?? ?? ?? ?? 2C 10 9F E5 04 40 8F E0 01 10 84 E0 10 00 8D E2 ?? ?? ?? ?? 06 00 A0 E1 0D 20 A0 E1 01 10 A0 E3 0D 50 A0 E1 ?? ?? ?? ?? 30 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fgetc_6c0091f6779aaa38eac715781cb23d78 {
	meta:
		aliases = "getc, __GI_fgetc, fgetc"
		size = "204"
		objfiles = "fgetcs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 34 30 90 E5 A8 60 9F E5 00 00 53 E3 10 D0 4D E2 00 50 A0 E1 06 60 8F E0 08 00 00 0A 10 20 90 E5 18 30 90 E5 03 00 52 E1 01 40 D2 34 10 20 80 35 1C 00 00 3A ?? ?? ?? ?? 00 40 A0 E1 19 00 00 EA 70 30 9F E5 38 40 80 E2 04 20 A0 E1 03 10 96 E7 0D 00 A0 E1 60 30 9F E5 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 54 30 9F E5 0F E0 A0 E1 03 F0 96 E7 10 20 95 E5 18 30 95 E5 03 00 52 E1 01 40 D2 34 10 20 85 35 02 00 00 3A 05 00 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __gnu_Unwind_RaiseException_3d95ffc07428e739a8788a7cbeb41c7d {
	meta:
		aliases = "__gnu_Unwind_RaiseException"
		size = "176"
		objfiles = "unwind_arm@libgcc.a"
	strings:
		$pattern = { 70 40 2D E9 3C 30 91 E5 13 DE 4D E2 40 30 81 E5 04 E0 8D E2 04 C0 81 E2 01 60 A0 E1 00 50 A0 E1 0F 00 BC E8 0F 00 AE E8 0F 00 BC E8 0F 00 AE E8 0F 00 BC E8 0F 00 AE E8 0F 00 9C E8 0F 00 8E E8 00 30 E0 E3 00 30 8D E5 05 00 A0 E1 40 10 9D E5 DA FE FF EB 00 00 50 E3 0B 00 00 1A 05 10 A0 E1 0D 20 A0 E1 0F E0 A0 E1 10 F0 95 E5 08 00 50 E3 00 40 A0 E1 F3 FF FF 0A 00 30 9D E5 01 00 13 E3 04 00 00 0A 06 00 54 E3 05 00 00 0A 09 00 A0 E3 13 DE 8D E2 70 80 BD E8 48 00 8D E2 ?? ?? ?? ?? F7 FF FF EA 05 00 A0 E1 06 10 A0 E1 A1 FF FF EB }
	condition:
		$pattern
}

rule __ns_name_uncompress_3278bc34061ddf029cae3ed6df73036c {
	meta:
		aliases = "__GI___ns_name_uncompress, __ns_name_uncompress"
		size = "84"
		objfiles = "ns_names@libc.a"
	strings:
		$pattern = { 70 40 2D E9 42 DF 4D E2 09 60 8D E2 FF C0 A0 E3 03 50 A0 E1 06 30 A0 E1 00 C0 8D E5 ?? ?? ?? ?? 01 00 70 E3 00 40 A0 E1 05 00 00 0A 06 00 A0 E1 05 10 A0 E1 18 21 9D E5 ?? ?? ?? ?? 01 00 70 E3 00 00 00 1A 00 40 E0 E3 04 00 A0 E1 42 DF 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule pthread_once_cancelhandler_1eb3a774bdc7a572c03f8645c1363db3 {
	meta:
		aliases = "pthread_once_cancelhandler"
		size = "100"
		objfiles = "mutexs@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 44 40 9F E5 44 50 9F E5 04 40 8F E0 40 30 9F E5 05 50 84 E0 00 60 A0 E1 03 30 84 E0 05 00 A0 E1 33 FF 2F E1 00 30 A0 E3 00 30 86 E5 24 30 9F E5 05 00 A0 E1 03 30 84 E0 33 FF 2F E1 18 00 9F E5 00 00 84 E0 70 40 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __uc_malloc_754186f92962383923f75011ef034fe0 {
	meta:
		aliases = "__GI___uc_malloc, __uc_malloc"
		size = "92"
		objfiles = "__uc_mallocs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 48 50 9F E5 48 60 9F E5 00 40 A0 E1 05 50 8F E0 04 00 A0 E1 ?? ?? ?? ?? 00 30 50 E2 01 30 A0 13 00 00 54 E3 01 30 83 03 00 00 53 E3 70 80 BD 18 06 30 95 E7 00 00 53 E3 01 00 00 1A 01 00 A0 E3 ?? ?? ?? ?? 04 00 A0 E1 33 FF 2F E1 EF FF FF EA ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __uClibc_fini_f8cd71a184ed40850b345341eda95304 {
	meta:
		aliases = "__GI___uClibc_fini, __uClibc_fini"
		size = "116"
		objfiles = "__uClibc_mains@libc.a"
	strings:
		$pattern = { 70 40 2D E9 54 20 9F E5 54 50 9F E5 54 30 9F E5 05 50 8F E0 03 30 62 E0 43 41 A0 E1 02 60 85 E0 01 00 00 EA 0F E0 A0 E1 04 F1 96 E7 01 40 54 E2 FB FF FF 2A 30 30 9F E5 03 30 95 E7 00 00 53 E3 00 00 00 0A 33 FF 2F E1 20 30 9F E5 03 30 95 E7 00 00 53 E3 70 80 BD 08 33 FF 2F E1 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sbrk_33d031c09b636a9c6054bfe0b7849677 {
	meta:
		aliases = "__GI_sbrk, sbrk"
		size = "104"
		objfiles = "sbrks@libc.a"
	strings:
		$pattern = { 70 40 2D E9 54 40 9F E5 54 60 9F E5 04 40 8F E0 06 30 94 E7 00 50 A0 E1 00 00 53 E3 03 00 00 1A 03 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 08 00 00 BA 06 00 94 E7 00 00 55 E3 00 40 A0 01 05 00 00 0A 00 40 A0 E1 05 00 80 E0 ?? ?? ?? ?? 00 00 50 E3 00 00 00 AA 00 40 E0 E3 04 00 A0 E1 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_setutent_2a2c662b6edaeb44d73eb39de38e00c2 {
	meta:
		aliases = "setutent, __GI_setutent"
		size = "128"
		objfiles = "utents@libc.a"
	strings:
		$pattern = { 70 40 2D E9 5C 40 9F E5 5C 50 9F E5 04 40 8F E0 58 30 9F E5 10 D0 4D E2 05 50 84 E0 03 10 94 E7 05 20 A0 E1 0D 00 A0 E1 44 30 9F E5 0F E0 A0 E1 03 F0 94 E7 3C 30 9F E5 05 00 A0 E1 0F E0 A0 E1 03 F0 94 E7 06 FF FF EB 0D 00 A0 E1 01 10 A0 E3 24 30 9F E5 0D 60 A0 E1 0F E0 A0 E1 03 F0 94 E7 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_closelog_9eee376bce6b2aff73912ac3e8498ebe {
	meta:
		aliases = "closelog, __GI_closelog"
		size = "132"
		objfiles = "syslogs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 60 40 9F E5 60 50 9F E5 04 40 8F E0 5C 30 9F E5 10 D0 4D E2 05 50 84 E0 03 10 94 E7 05 20 A0 E1 0D 00 A0 E1 48 30 9F E5 0F E0 A0 E1 03 F0 94 E7 40 30 9F E5 05 00 A0 E1 0F E0 A0 E1 03 F0 94 E7 00 00 A0 E3 C6 FF FF EB 0D 00 A0 E1 01 10 A0 E3 24 30 9F E5 0D 60 A0 E1 0F E0 A0 E1 03 F0 94 E7 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_getdomainname_f689cd0d2c6cdd48659b0f12de701fbe {
	meta:
		aliases = "__libc_getdomainname, getdomainname, __GI___libc_getdomainname, __GI_getdomainname"
		size = "116"
		objfiles = "getdomainnames@libc.a"
	strings:
		$pattern = { 70 40 2D E9 62 DF 4D E2 00 60 A0 E1 04 00 8D E2 02 00 40 E2 01 40 A0 E1 ?? ?? ?? ?? 01 00 70 E3 00 20 A0 01 0F 00 00 0A 51 5F 8D E2 03 50 85 E2 05 00 A0 E1 ?? ?? ?? ?? 01 00 80 E2 04 00 50 E1 04 00 00 9A ?? ?? ?? ?? 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 03 00 00 EA 06 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 00 20 A0 E3 02 00 A0 E1 62 DF 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule gethostname_30c4ece662b34fb3577fffefbc7f2814 {
	meta:
		aliases = "__GI_gethostname, gethostname"
		size = "116"
		objfiles = "gethostnames@libc.a"
	strings:
		$pattern = { 70 40 2D E9 62 DF 4D E2 04 40 8D E2 02 40 44 E2 00 60 A0 E1 04 00 A0 E1 01 50 A0 E1 ?? ?? ?? ?? 01 00 70 E3 00 20 A0 01 0E 00 00 0A 41 40 84 E2 04 00 A0 E1 ?? ?? ?? ?? 01 00 80 E2 05 00 50 E1 04 00 00 9A ?? ?? ?? ?? 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 03 00 00 EA 06 00 A0 E1 04 10 A0 E1 ?? ?? ?? ?? 00 20 A0 E3 02 00 A0 E1 62 DF 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule __GI_strncasecmp_e374e1ae7576ae44c29233411cce588e {
	meta:
		aliases = "strncasecmp, __GI_strncasecmp"
		size = "120"
		objfiles = "strncasecmps@libc.a"
	strings:
		$pattern = { 70 40 2D E9 64 50 9F E5 00 C0 A0 E1 60 60 9F E5 01 E0 A0 E1 02 40 A0 E1 00 00 A0 E3 05 50 8F E0 00 00 54 E3 01 40 44 E2 70 80 BD 08 0E 00 5C E1 08 00 00 0A 00 10 DC E5 00 30 DE E5 06 00 95 E7 83 30 A0 E1 81 10 A0 E1 F0 20 93 E1 F0 30 91 E1 02 00 53 E0 70 80 BD 18 00 30 DC E5 01 E0 8E E2 00 00 53 E3 01 C0 8C E2 EC FF FF 1A 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getutent_53c5d5307c98277e97a6c2ac1345e0c1 {
	meta:
		aliases = "getutent"
		size = "148"
		objfiles = "utents@libc.a"
	strings:
		$pattern = { 70 40 2D E9 6C 40 9F E5 6C 50 9F E5 04 40 8F E0 68 30 9F E5 10 D0 4D E2 05 50 84 E0 03 10 94 E7 05 20 A0 E1 0D 00 A0 E1 54 30 9F E5 0F E0 A0 E1 03 F0 94 E7 05 00 A0 E1 48 30 9F E5 0F E0 A0 E1 03 F0 94 E7 40 30 9F E5 0D 60 A0 E1 03 00 94 E7 56 FF FF EB 01 10 A0 E3 00 50 A0 E1 2C 30 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 94 E7 05 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_random_a32968a651b0f51f9262b01466d92674 {
	meta:
		aliases = "random, __GI_random"
		size = "148"
		objfiles = "randoms@libc.a"
	strings:
		$pattern = { 70 40 2D E9 6C 40 9F E5 6C 50 9F E5 18 D0 4D E2 04 40 8F E0 64 30 9F E5 05 50 84 E0 04 60 8D E2 03 10 94 E7 05 20 A0 E1 06 00 A0 E1 50 30 9F E5 0F E0 A0 E1 03 F0 94 E7 48 30 9F E5 05 00 A0 E1 0F E0 A0 E1 03 F0 94 E7 3C 00 9F E5 14 10 8D E2 00 00 84 E0 ?? ?? ?? ?? 06 00 A0 E1 01 10 A0 E3 28 30 9F E5 0F E0 A0 E1 03 F0 94 E7 14 00 9D E5 18 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule closelog_intern_5a90779021005aad1e4945fb5ac034e8 {
	meta:
		aliases = "closelog_intern"
		size = "152"
		objfiles = "syslogs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 6C 40 9F E5 6C 60 9F E5 04 40 8F E0 06 30 94 E7 00 50 A0 E1 01 00 73 E3 01 00 00 0A 03 00 A0 E1 ?? ?? ?? ?? 00 30 E0 E3 06 30 84 E7 48 30 9F E5 00 20 A0 E3 00 00 55 E3 03 20 84 E7 70 80 BD 18 38 30 9F E5 FF 10 A0 E3 03 10 84 E7 30 30 9F E5 30 20 9F E5 03 50 84 E7 2C 30 9F E5 02 20 84 E0 03 20 84 E7 24 30 9F E5 08 20 A0 E3 03 20 84 E7 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule setspent_0692517102b88dafb070e11c2e70cffd {
	meta:
		aliases = "setgrent, setpwent, setspent"
		size = "148"
		objfiles = "getpwent_rs@libc.a, getgrent_rs@libc.a, getspent_rs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 6C 50 9F E5 6C 40 9F E5 05 50 8F E0 68 30 9F E5 10 D0 4D E2 04 40 85 E0 03 10 95 E7 04 20 A0 E1 0D 00 A0 E1 54 30 9F E5 0F E0 A0 E1 03 F0 95 E7 4C 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 95 E7 40 30 9F E5 0D 60 A0 E1 03 00 95 E7 00 00 50 E3 00 00 00 0A ?? ?? ?? ?? 0D 00 A0 E1 01 10 A0 E3 24 30 9F E5 0F E0 A0 E1 03 F0 95 E7 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule setkey_32bc48698f0a40100502222e61dc60b8 {
	meta:
		aliases = "setkey"
		size = "132"
		objfiles = "dess@libcrypt.a"
	strings:
		$pattern = { 70 40 2D E9 70 20 9F E5 70 30 9F E5 08 D0 4D E2 02 20 8F E0 00 C0 A0 E3 03 60 82 E0 0D 40 A0 E1 0C 50 A0 E1 0E 00 00 EA 0C E0 84 E0 05 10 A0 E1 0C 50 C4 E7 07 00 00 EA 00 30 D0 E5 01 00 80 E2 01 00 13 E3 00 30 DE 15 01 20 D6 17 01 10 81 E2 02 30 83 11 00 30 CE 15 07 00 51 E3 F5 FF FF DA 01 C0 8C E2 07 00 5C E3 EE FF FF DA 04 00 A0 E1 E0 FD FF EB 08 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_tan_101c987062966ec78abade9271cb5d23 {
	meta:
		aliases = "tan, __GI_tan"
		size = "136"
		objfiles = "s_tans@libm.a"
	strings:
		$pattern = { 70 40 2D E9 74 30 9F E5 02 C1 C1 E3 03 00 5C E1 18 D0 4D E2 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 00 20 A0 D3 00 30 A0 D3 01 C0 A0 D3 0F 00 00 DA 4C 30 9F E5 03 00 5C E1 03 00 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 0A 00 00 EA 08 20 8D E2 ?? ?? ?? ?? 10 20 8D E2 0C 00 92 E8 01 C0 00 E2 8C C0 A0 E1 01 C0 6C E2 08 00 8D E2 03 00 90 E8 00 C0 8D E5 ?? ?? ?? ?? 18 D0 8D E2 70 80 BD E8 FB 21 E9 3F FF FF EF 7F }
	condition:
		$pattern
}

rule __GI_herror_ee65fee30ba01b5d6e219c258c785581 {
	meta:
		aliases = "herror, __GI_herror"
		size = "156"
		objfiles = "herrors@libc.a"
	strings:
		$pattern = { 70 40 2D E9 78 40 9F E5 00 50 50 E2 08 D0 4D E2 04 40 8F E0 04 00 00 0A 00 30 D5 E5 00 00 53 E3 60 30 9F 15 03 60 84 10 02 00 00 1A 54 30 9F E5 03 30 84 E0 02 60 83 E2 ?? ?? ?? ?? 00 00 90 E5 04 00 50 E3 40 30 9F 85 03 C0 84 80 3C 30 9F 95 03 30 84 90 00 C1 93 97 34 30 9F E5 34 10 9F E5 03 30 94 E7 01 10 84 E0 00 00 93 E5 05 20 A0 E1 06 30 A0 E1 00 C0 8D E5 ?? ?? ?? ?? 08 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tmpfile_1f6467c6097aa6d7d0ccad579804d995 {
	meta:
		aliases = "tmpfile64, tmpfile"
		size = "152"
		objfiles = "tmpfiles@libc.a"
	strings:
		$pattern = { 70 40 2D E9 7C 60 9F E5 01 DA 4D E2 10 40 8D E2 74 30 9F E5 06 60 8F E0 0F 40 44 E2 03 30 86 E0 04 00 A0 E1 64 10 9F E5 00 20 A0 E3 ?? ?? ?? ?? 00 00 50 E3 0F 00 00 1A 00 10 A0 E1 04 00 A0 E1 ?? ?? ?? ?? 00 50 50 E2 0A 00 00 BA 04 00 A0 E1 ?? ?? ?? ?? 38 10 9F E5 05 00 A0 E1 01 10 86 E0 ?? ?? ?? ?? 00 40 50 E2 03 00 00 1A 05 00 A0 E1 ?? ?? ?? ?? 00 00 00 EA 00 40 A0 E3 04 00 A0 E1 01 DA 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? FF 0F 00 00 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule gethostent_24d3b13a7ef50997686bfe26b8f3fada {
	meta:
		aliases = "gethostent"
		size = "172"
		objfiles = "gethostents@libc.a"
	strings:
		$pattern = { 70 40 2D E9 80 40 9F E5 80 50 9F E5 20 D0 4D E2 04 40 8F E0 78 30 9F E5 05 50 84 E0 0C 60 8D E2 03 10 94 E7 05 20 A0 E1 06 00 A0 E1 64 30 9F E5 0F E0 A0 E1 03 F0 94 E7 5C 30 9F E5 05 00 A0 E1 0F E0 A0 E1 03 F0 94 E7 ?? ?? ?? ?? 4C 10 9F E5 00 00 8D E5 48 00 9F E5 01 10 84 E0 8A 20 A0 E3 1C 30 8D E2 00 00 84 E0 ?? ?? ?? ?? 06 00 A0 E1 01 10 A0 E3 2C 30 9F E5 0F E0 A0 E1 03 F0 94 E7 1C 00 9D E5 20 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule setstate_8f595d5e713993e1b89dc7f1e5a7c9b7 {
	meta:
		aliases = "setstate"
		size = "168"
		objfiles = "randoms@libc.a"
	strings:
		$pattern = { 70 40 2D E9 80 60 9F E5 80 40 9F E5 06 60 8F E0 7C 30 9F E5 10 D0 4D E2 04 40 86 E0 04 20 A0 E1 03 10 96 E7 00 50 A0 E1 68 30 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 58 30 9F E5 0F E0 A0 E1 03 F0 96 E7 50 30 9F E5 05 00 A0 E1 03 30 86 E0 03 10 A0 E1 08 40 93 E5 ?? ?? ?? ?? 01 10 A0 E3 00 00 50 E3 34 30 9F E5 0D 00 A0 E1 00 40 A0 B3 04 40 44 A2 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule cfsetspeed_440d2e05d68d93e30acbecb39640cd4b {
	meta:
		aliases = "cfsetspeed"
		size = "160"
		objfiles = "cfsetspeeds@libc.a"
	strings:
		$pattern = { 70 40 2D E9 8C 20 9F E5 8C 30 9F E5 02 20 8F E0 00 60 A0 E1 03 C0 82 E0 01 50 A0 E1 00 00 A0 E3 14 00 00 EA 04 40 91 E5 04 00 55 E1 05 00 00 1A 05 10 A0 E1 06 00 A0 E1 ?? ?? ?? ?? 06 00 A0 E1 05 10 A0 E1 08 00 00 EA 80 31 9C E7 01 00 80 E2 03 00 55 E1 07 00 00 1A 04 10 A0 E1 06 00 A0 E1 ?? ?? ?? ?? 06 00 A0 E1 04 10 A0 E1 ?? ?? ?? ?? 00 00 A0 E3 70 80 BD E8 1F 00 50 E3 80 11 8C E0 E7 FF FF 9A ?? ?? ?? ?? 16 30 A0 E3 00 30 80 E5 00 00 E0 E3 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sem_post_007fd0b83a089a6c51c0d6dcaa47564f {
	meta:
		aliases = "__new_sem_post, sem_post"
		size = "308"
		objfiles = "semaphores@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 98 D0 4D E2 00 40 A0 E1 FA FE FF EB 54 60 90 E5 10 51 9F E5 00 00 56 E3 05 50 8F E0 20 00 00 1A 00 10 A0 E1 04 00 A0 E1 ?? ?? ?? ?? 0C 50 94 E5 00 00 55 E3 0F 00 00 1A 08 30 94 E5 06 01 73 E3 06 00 00 1A ?? ?? ?? ?? 22 30 A0 E3 00 30 80 E5 04 00 A0 E1 ?? ?? ?? ?? 00 20 E0 E3 2E 00 00 EA 01 30 83 E2 08 30 84 E5 04 00 A0 E1 ?? ?? ?? ?? 05 20 A0 E1 28 00 00 EA 08 30 95 E5 04 00 A0 E1 0C 30 84 E5 08 60 85 E5 ?? ?? ?? ?? 01 30 A0 E3 BA 31 C5 E5 05 00 A0 E1 ?? ?? ?? ?? 06 20 A0 E1 1D 00 00 EA 80 30 9F E5 03 30 95 E7 00 30 93 E5 00 00 53 E3 07 00 00 AA ?? ?? ?? ?? 00 00 50 E3 04 00 00 AA }
	condition:
		$pattern
}

rule getpw_f385a86ad37c568d244493f11cc398be {
	meta:
		aliases = "getpw"
		size = "176"
		objfiles = "getpws@libc.a"
	strings:
		$pattern = { 70 40 2D E9 9C 40 9F E5 00 50 51 E2 4E DF 4D E2 04 40 8F E0 04 00 00 1A ?? ?? ?? ?? 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 1B 00 00 EA 4D CF 8D E2 46 1F 8D E2 18 20 8D E2 01 3C A0 E3 00 C0 8D E5 ?? ?? ?? ?? 00 60 50 E2 12 00 00 1A 20 C1 9D E5 54 10 9F E5 00 C0 8D E5 24 C1 9D E5 18 21 9D E5 04 C0 8D E5 28 C1 9D E5 01 10 84 E0 08 C0 8D E5 2C C1 9D E5 05 00 A0 E1 0C C0 8D E5 30 C1 9D E5 1C 31 9D E5 10 C0 8D E5 ?? ?? ?? ?? 00 00 50 E3 06 20 A0 A1 00 00 00 AA 00 20 E0 E3 02 00 A0 E1 4E DF 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __old_sem_wait_eaf7a862b6293f4f9b710dabcc19d74d {
	meta:
		aliases = "__old_sem_wait"
		size = "480"
		objfiles = "oldsemaphores@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 B4 41 9F E5 B4 31 9F E5 04 40 8F E0 03 30 94 E7 10 D0 4D E2 00 30 93 E5 0D 20 A0 E1 03 00 5D E1 00 50 A0 E1 98 31 9F 25 0A 00 00 2A 94 31 9F E5 03 30 94 E7 00 30 93 E5 03 00 5D E1 07 00 00 3A 84 31 9F E5 03 30 94 E7 00 30 93 E5 03 00 5D E1 02 00 00 2A 74 31 9F E5 03 00 94 E7 0A 00 00 EA 6C 31 9F E5 03 30 94 E7 00 30 93 E5 00 00 53 E3 01 00 00 0A ?? ?? ?? ?? 03 00 00 EA A2 3A E0 E1 83 3A E0 E1 77 0F 43 E2 03 00 40 E2 44 21 9F E5 00 30 A0 E3 02 20 84 E0 0C 00 8D E5 04 30 8D E5 08 20 8D E5 04 60 8D E2 0C 00 9D E5 06 10 A0 E1 BC FF FF EB 00 10 95 E5 05 00 A0 E1 01 00 51 E3 00 30 A0 03 }
	condition:
		$pattern
}

rule getchar_885b16599a0ee7127d38fb1629b52d15 {
	meta:
		aliases = "getchar"
		size = "220"
		objfiles = "getchars@libc.a"
	strings:
		$pattern = { 70 40 2D E9 B8 60 9F E5 B8 30 9F E5 06 60 8F E0 03 30 96 E7 10 D0 4D E2 00 50 93 E5 34 30 95 E5 00 00 53 E3 09 00 00 0A 10 20 95 E5 18 30 95 E5 03 00 52 E1 01 40 D2 34 10 20 85 35 1D 00 00 3A 05 00 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 19 00 00 EA 74 30 9F E5 38 40 85 E2 04 20 A0 E1 03 10 96 E7 0D 00 A0 E1 64 30 9F E5 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 58 30 9F E5 0F E0 A0 E1 03 F0 96 E7 10 20 95 E5 18 30 95 E5 03 00 52 E1 01 40 D2 34 10 20 85 35 02 00 00 3A 05 00 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 0D 00 A0 E1 01 10 A0 E3 24 30 9F E5 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule bsd_signal_a3055c764d2f14daf71cedfda760f8c5 {
	meta:
		aliases = "__GI_signal, signal, __bsd_signal, bsd_signal"
		size = "208"
		objfiles = "signals@libc.a"
	strings:
		$pattern = { 70 40 2D E9 BC 50 9F E5 01 00 71 E3 00 00 50 13 46 DF 4D E2 00 40 A0 E1 00 30 A0 C3 01 30 A0 D3 05 50 8F E0 04 00 00 DA 40 00 50 E3 03 00 A0 D1 20 20 A0 D3 8C 10 8D D5 05 00 00 DA ?? ?? ?? ?? 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 1A 00 00 EA 88 00 03 E5 01 20 52 E2 46 1F 8D E2 02 31 81 E0 FA FF FF 5A 8C 60 8D E2 04 00 86 E2 04 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 0E 00 00 BA 48 00 9F E5 04 10 A0 E1 00 00 85 E0 ?? ?? ?? ?? 00 00 50 E3 01 32 A0 03 00 30 A0 13 0D 20 A0 E1 06 10 A0 E1 04 00 A0 E1 10 31 8D E5 ?? ?? ?? ?? 00 00 50 E3 00 20 9D A5 00 00 00 AA 00 20 E0 E3 02 00 A0 E1 46 DF 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule imaxabs_9e60e6755f51fc2f2cad304c792b98f3 {
	meta:
		aliases = "llabs, imaxabs"
		size = "40"
		objfiles = "llabss@libc.a"
	strings:
		$pattern = { 70 40 2D E9 C1 3F A0 E1 00 50 23 E0 01 60 23 E0 03 40 A0 E1 05 00 A0 E1 06 10 A0 E1 03 00 50 E0 04 10 C1 E0 70 80 BD E8 }
	condition:
		$pattern
}

rule xdr_opaque_c1326965c510689e096153d98be202f3 {
	meta:
		aliases = "__GI_xdr_opaque, xdr_opaque"
		size = "220"
		objfiles = "xdrs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 C4 60 9F E5 00 C0 52 E2 06 60 8F E0 00 40 A0 E1 29 00 00 0A 00 30 90 E5 03 20 1C E2 02 50 A0 01 04 50 62 12 01 00 53 E3 03 00 00 0A 12 00 00 3A 02 00 53 E3 22 00 00 1A 1F 00 00 EA 0C 20 A0 E1 04 30 90 E5 0F E0 A0 E1 08 F0 93 E5 00 00 50 E3 1B 00 00 0A 00 00 55 E3 17 00 00 0A 6C 10 9F E5 04 00 A0 E1 01 10 86 E0 05 20 A0 E1 04 30 94 E5 0F E0 A0 E1 08 F0 93 E5 70 80 BD E8 0C 20 A0 E1 04 30 90 E5 0F E0 A0 E1 0C F0 93 E5 00 00 50 E3 0B 00 00 0A 00 00 55 E3 07 00 00 0A 30 10 9F E5 04 00 A0 E1 01 10 86 E0 05 20 A0 E1 04 30 94 E5 0F E0 A0 E1 0C F0 93 E5 70 80 BD E8 01 00 A0 E3 70 80 BD E8 }
	condition:
		$pattern
}

rule pthread_key_delete_cb314163f37e8b6fc75a0d61eff940a4 {
	meta:
		aliases = "pthread_key_delete"
		size = "240"
		objfiles = "specifics@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 CC 50 9F E5 CC 30 9F E5 05 50 8F E0 03 60 85 E0 C4 30 9F E5 00 40 A0 E1 03 30 85 E0 06 00 A0 E1 33 FF 2F E1 01 0B 54 E3 04 00 00 2A AC 30 9F E5 03 00 85 E0 84 31 90 E7 00 00 53 E3 05 00 00 1A 06 00 A0 E1 98 30 9F E5 0F E0 A0 E1 03 F0 95 E7 16 00 A0 E3 70 80 BD E8 88 30 9F E5 00 20 A0 E3 03 30 95 E7 84 11 80 E0 00 30 93 E5 04 20 81 E5 01 00 73 E3 84 21 80 E7 0E 00 00 0A 1C FF FF EB A4 32 A0 E1 1F E0 04 E2 03 31 A0 E1 00 20 A0 E1 2C C0 D2 E5 02 10 83 E0 00 00 5C E3 02 00 00 1A EC 10 91 E5 00 00 51 E3 0E C1 81 17 00 20 92 E5 00 00 52 E1 F5 FF FF 1A 18 00 9F E5 20 30 9F E5 00 00 85 E0 }
	condition:
		$pattern
}

rule cos_501e4b578e07775acc3004e30d0adbe7 {
	meta:
		aliases = "__GI_cos, cos"
		size = "236"
		objfiles = "s_coss@libm.a"
	strings:
		$pattern = { 70 40 2D E9 D8 30 9F E5 02 C1 C1 E3 03 00 5C E1 18 D0 4D E2 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 00 20 A0 D3 00 30 A0 D3 13 00 00 DA B4 30 9F E5 03 00 5C E1 03 00 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 20 00 00 EA 08 20 8D E2 ?? ?? ?? ?? 03 C0 00 E2 01 00 5C E3 09 00 00 0A 02 00 5C E3 0E 00 00 0A 00 00 5C E3 08 00 8D E2 03 00 90 E8 10 20 8D E2 0C 00 92 E8 10 00 00 1A ?? ?? ?? ?? 11 00 00 EA 08 00 8D E2 03 00 90 E8 10 20 8D E2 0C 00 92 E8 00 C0 8D E5 ?? ?? ?? ?? 04 00 00 EA 08 00 8D E2 03 00 90 E8 10 20 8D E2 0C 00 92 E8 ?? ?? ?? ?? 00 20 A0 E1 02 31 81 E2 04 00 00 EA 01 C0 A0 E3 00 C0 8D E5 }
	condition:
		$pattern
}

rule __GI_sin_2e421e186908d0ad39bbb5b95819fe06 {
	meta:
		aliases = "sin, __GI_sin"
		size = "244"
		objfiles = "s_sins@libm.a"
	strings:
		$pattern = { 70 40 2D E9 E0 30 9F E5 02 C1 C1 E3 03 00 5C E1 18 D0 4D E2 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 00 20 A0 D3 00 30 A0 D3 00 C0 A0 D3 16 00 00 DA B8 30 9F E5 03 00 5C E1 05 00 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 21 00 00 EA 08 20 8D E2 ?? ?? ?? ?? 03 00 00 E2 01 00 50 E3 0B 00 00 0A 02 00 50 E3 0F 00 00 0A 00 00 50 E3 10 20 8D E2 0C 00 92 E8 08 00 8D E2 03 00 90 E8 11 00 00 1A 01 C0 A0 E3 00 C0 8D E5 ?? ?? ?? ?? EB FF FF EA 08 00 8D E2 03 00 90 E8 10 20 8D E2 0C 00 92 E8 ?? ?? ?? ?? E5 FF FF EA 01 C0 A0 E3 08 00 8D E2 03 00 90 E8 10 20 8D E2 0C 00 92 E8 00 C0 8D E5 }
	condition:
		$pattern
}

rule strchr_035f3a8afb6daf3b0f2493ad06acfb03 {
	meta:
		aliases = "__GI_strchr, index, strchr"
		size = "236"
		objfiles = "strchrs@libc.a"
	strings:
		$pattern = { 70 40 2D E9 FF 40 01 E2 05 00 00 EA 00 30 D0 E5 04 00 53 E1 70 80 BD 08 00 00 53 E3 2E 00 00 0A 01 00 80 E2 03 00 10 E3 F7 FF FF 1A 04 34 84 E1 00 50 A0 E1 03 68 83 E1 04 30 95 E4 A0 00 9F E5 06 20 23 E0 00 C0 82 E0 98 10 9F E5 00 00 83 E0 03 30 E0 E1 00 30 23 E0 01 E0 A0 E1 02 20 E0 E1 01 10 03 E0 0C 20 22 E0 00 00 51 E3 0E E0 02 E0 01 00 00 1A 00 00 5E E3 EE FF FF 0A 04 30 55 E5 04 00 45 E2 04 00 53 E1 70 80 BD 08 00 00 53 E3 11 00 00 0A 03 30 55 E5 01 00 80 E2 04 00 53 E1 70 80 BD 08 00 00 53 E3 0B 00 00 0A 01 30 D0 E5 01 00 80 E2 04 00 53 E1 70 80 BD 08 00 00 53 E3 05 00 00 0A 01 30 D0 E5 }
	condition:
		$pattern
}

rule __GI_strchrnul_665af9a80806f677968065fc3a70cb96 {
	meta:
		aliases = "strchrnul, __GI_strchrnul"
		size = "232"
		objfiles = "strchrnuls@libc.a"
	strings:
		$pattern = { 70 40 2D E9 FF 40 01 E2 05 00 00 EA 00 30 D0 E5 04 00 53 E1 70 80 BD 08 00 00 53 E3 70 80 BD 08 01 00 80 E2 03 00 10 E3 F7 FF FF 1A 04 34 84 E1 00 50 A0 E1 03 68 83 E1 04 30 95 E4 9C 00 9F E5 06 20 23 E0 00 C0 82 E0 94 10 9F E5 00 00 83 E0 03 30 E0 E1 00 30 23 E0 01 E0 A0 E1 02 20 E0 E1 01 10 03 E0 0C 20 22 E0 00 00 51 E3 0E E0 02 E0 01 00 00 1A 00 00 5E E3 EE FF FF 0A 04 30 55 E5 04 00 45 E2 04 00 53 E1 70 80 BD 08 00 00 53 E3 70 80 BD 08 03 30 55 E5 01 00 80 E2 04 00 53 E1 70 80 BD 08 00 00 53 E3 70 80 BD 08 01 30 D0 E5 01 00 80 E2 04 00 53 E1 70 80 BD 08 00 00 53 E3 70 80 BD 08 01 30 D0 E5 }
	condition:
		$pattern
}

rule __aeabi_ddiv_7a2e8357b9c85bb7f3d1cae4967c5cdf {
	meta:
		aliases = "__divdf3, __aeabi_ddiv"
		size = "516"
		objfiles = "_muldivdf3@libgcc.a"
	strings:
		$pattern = { 70 40 2D E9 FF C0 A0 E3 07 CC 8C E3 21 4A 1C E0 23 5A 1C 10 0C 00 34 11 0C 00 35 11 5C 00 00 0B 05 40 44 E0 03 E0 21 E0 03 56 92 E1 01 16 A0 E1 4B 00 00 0A 03 36 A0 E1 01 52 A0 E3 23 32 85 E1 22 3C 83 E1 02 24 A0 E1 21 52 85 E1 20 5C 85 E1 00 64 A0 E1 02 11 0E E2 03 00 55 E1 02 00 56 01 FD 40 A4 E2 03 4C 84 E2 01 00 00 2A A3 30 B0 E1 62 20 A0 E1 02 60 56 E0 03 50 C5 E0 A3 30 B0 E1 62 20 A0 E1 01 06 A0 E3 02 C7 A0 E3 02 E0 56 E0 03 E0 D5 E0 02 60 46 20 0E 50 A0 21 0C 00 80 21 A3 30 B0 E1 62 20 A0 E1 02 E0 56 E0 03 E0 D5 E0 02 60 46 20 0E 50 A0 21 AC 00 80 21 A3 30 B0 E1 62 20 A0 E1 02 E0 56 E0 }
	condition:
		$pattern
}

rule __aeabi_dmul_6fe461b36624ebd239fea70489ee76f6 {
	meta:
		aliases = "__muldf3, __aeabi_dmul"
		size = "620"
		objfiles = "_muldivdf3@libgcc.a"
	strings:
		$pattern = { 70 40 2D E9 FF C0 A0 E3 07 CC 8C E3 21 4A 1C E0 23 5A 1C 10 0C 00 34 11 0C 00 35 11 6F 00 00 0B 05 40 84 E0 03 60 21 E0 8C 1A C1 E1 8C 3A C3 E1 01 56 90 E1 03 56 92 11 01 16 81 E3 01 36 83 E3 1C 00 00 0A 90 C2 8E E0 00 50 A0 E3 91 E2 A5 E0 02 21 06 E2 90 E3 A5 E0 00 60 A0 E3 91 53 A6 E0 00 00 3C E3 01 E0 8E 13 FF 40 44 E2 02 0C 56 E3 03 4C C4 E2 02 00 00 2A 8E E0 B0 E1 05 50 B5 E0 06 60 A6 E0 86 15 82 E1 A5 1A 81 E1 85 05 A0 E1 AE 0A 80 E1 8E E5 A0 E1 FD C0 54 E2 07 0C 5C 83 0F 00 00 8A 02 01 5E E3 A0 E0 B0 01 00 00 B0 E2 04 1A A1 E0 70 80 BD E8 02 61 06 E2 01 10 86 E1 02 00 80 E1 03 10 21 E0 }
	condition:
		$pattern
}

rule __ffsdi2_96470b46cd0d598393d80c246ed9a735 {
	meta:
		aliases = "__ffsdi2"
		size = "132"
		objfiles = "_ffsdi2@libgcc.a"
	strings:
		$pattern = { 74 20 9F E5 00 00 50 E3 02 20 8F E0 00 10 A0 13 04 00 00 1A 00 00 51 E3 01 00 A0 01 1E FF 2F 01 01 00 A0 E1 20 10 A0 E3 00 30 60 E2 00 00 03 E0 01 08 50 E3 0B 00 00 3A FF 34 E0 E3 03 00 50 E1 18 C0 A0 83 10 C0 A0 93 0C 30 A0 E1 30 03 A0 E1 28 30 9F E5 01 C0 8C E0 03 20 92 E7 00 10 D2 E7 01 00 8C E0 1E FF 2F E1 FF 00 50 E3 08 C0 A0 83 00 C0 A0 93 0C 30 A0 E1 F3 FF FF EA ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __default_sa_restorer_48a77ee7a7211e5abfdeec230897e344 {
	meta:
		aliases = "__default_sa_restorer"
		size = "20"
		objfiles = "sigrestorers@libc.a"
	strings:
		$pattern = { 77 70 A0 E3 00 00 00 EF 00 00 A0 E1 AD 70 A0 E3 00 00 00 EF }
	condition:
		$pattern
}

rule confstr_29bad9d9bdec4dd4a5fe7939751abdbc {
	meta:
		aliases = "confstr"
		size = "140"
		objfiles = "confstrs@libc.a"
	strings:
		$pattern = { 7C 30 9F E5 70 40 2D E9 00 60 50 E2 03 30 8F E0 01 50 A0 E1 02 40 A0 E1 03 00 00 1A 00 00 52 E3 00 00 51 13 05 00 00 1A 12 00 00 EA ?? ?? ?? ?? 16 30 A0 E3 00 20 A0 E3 00 30 80 E5 0E 00 00 EA 0D 00 52 E3 3C 20 9F E5 04 00 00 9A 02 10 83 E0 05 00 A0 E1 0E 20 A0 E3 ?? ?? ?? ?? 05 00 00 EA 02 10 83 E0 05 00 A0 E1 01 20 44 E2 ?? ?? ?? ?? 04 30 85 E0 01 60 43 E5 0E 20 A0 E3 02 00 A0 E1 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule toascii_2ccac9b14a9537518d3263650df88e34 {
	meta:
		aliases = "toascii"
		size = "8"
		objfiles = "toasciis@libc.a"
	strings:
		$pattern = { 7F 00 00 E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule isascii_aee68e3233286477602dfd271d8046a0 {
	meta:
		aliases = "isascii"
		size = "16"
		objfiles = "isasciis@libc.a"
	strings:
		$pattern = { 7F 30 D0 E3 00 00 A0 13 01 00 A0 03 1E FF 2F E1 }
	condition:
		$pattern
}

rule btowc_f9ef031915a783f5bec1cb27025ac96e {
	meta:
		aliases = "__GI_btowc, wctob, btowc"
		size = "12"
		objfiles = "wctobs@libc.a, btowcs@libc.a"
	strings:
		$pattern = { 80 00 50 E3 00 00 E0 23 1E FF 2F E1 }
	condition:
		$pattern
}

rule __fixsfsi_49f7a348b91d309bae170b967578bb32 {
	meta:
		aliases = "__aeabi_f2iz, __fixsfsi"
		size = "92"
		objfiles = "_fixsfsi@libgcc.a"
	strings:
		$pattern = { 80 20 A0 E1 7F 04 52 E3 08 00 00 3A 9E 30 A0 E3 22 2C 53 E0 07 00 00 9A 00 34 A0 E1 02 31 83 E3 02 01 10 E3 33 02 A0 E1 00 00 60 12 1E FF 2F E1 00 00 A0 E3 1E FF 2F E1 61 00 72 E3 01 00 00 1A 80 24 B0 E1 02 00 00 1A 02 01 10 E2 02 01 E0 03 1E FF 2F E1 00 00 A0 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule __aeabi_fcmpun_833918f2f9dc87d1b8d9950d3860fa46 {
	meta:
		aliases = "__unordsf2, __aeabi_fcmpun"
		size = "56"
		objfiles = "_unordsf2@libgcc.a"
	strings:
		$pattern = { 80 20 A0 E1 81 30 A0 E1 42 CC F0 E1 01 00 00 1A 80 C4 B0 E1 05 00 00 1A 43 CC F0 E1 01 00 00 1A 81 C4 B0 E1 01 00 00 1A 00 00 A0 E3 1E FF 2F E1 01 00 A0 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule __fixunssfsi_d034d3d2744b5a0f446af94e88f6d438 {
	meta:
		aliases = "__aeabi_f2uiz, __fixunssfsi"
		size = "84"
		objfiles = "_fixunssfsi@libgcc.a"
	strings:
		$pattern = { 80 20 B0 E1 08 00 00 2A 7F 04 52 E3 06 00 00 3A 9E 30 A0 E3 22 2C 53 E0 05 00 00 4A 00 34 A0 E1 02 31 83 E3 33 02 A0 E1 1E FF 2F E1 00 00 A0 E3 1E FF 2F E1 61 00 72 E3 01 00 00 1A 80 24 B0 E1 01 00 00 1A 00 00 E0 E3 1E FF 2F E1 00 00 A0 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule __aeabi_fadd_17eb9c2cfb71e98151c08498dc9c9cd1 {
	meta:
		aliases = "__addsf3, __aeabi_fadd"
		size = "400"
		objfiles = "_addsubsf3@libgcc.a"
	strings:
		$pattern = { 80 20 B0 E1 81 30 B0 11 03 00 32 11 42 CC F0 11 43 CC F0 11 3C 00 00 0A 22 2C A0 E1 23 3C 72 E0 03 20 82 C0 01 10 20 C0 00 00 21 C0 01 10 20 C0 00 30 63 B2 19 00 53 E3 1E FF 2F 81 02 01 10 E3 02 05 80 E3 FF 04 C0 E3 00 00 60 12 02 01 11 E3 02 15 81 E3 FF 14 C1 E3 00 10 61 12 03 00 32 E1 23 00 00 0A 01 20 42 E2 51 03 90 E0 20 30 63 E2 11 13 A0 E1 02 31 00 E2 01 00 00 5A 00 10 71 E2 00 00 E0 E2 02 05 50 E3 0B 00 00 3A 01 04 50 E3 04 00 00 3A A0 00 B0 E1 61 10 A0 E1 01 20 82 E2 FE 00 52 E3 2D 00 00 2A 02 01 51 E3 82 0B A0 E0 01 00 C0 03 03 00 80 E1 1E FF 2F E1 81 10 B0 E1 00 00 A0 E0 02 05 10 E3 }
	condition:
		$pattern
}

rule __extendsfdf2_df254748f39f385f39776d50726d607e {
	meta:
		aliases = "__aeabi_f2d, __extendsfdf2"
		size = "64"
		objfiles = "_addsubdf3@libgcc.a"
	strings:
		$pattern = { 80 20 B0 E1 C2 11 A0 E1 61 10 A0 E1 02 0E A0 E1 FF 34 12 12 FF 04 33 13 0E 13 21 12 1E FF 2F 11 00 00 32 E3 FF 04 33 13 1E FF 2F 01 30 40 2D E9 0E 4D A0 E3 02 51 01 E2 02 11 C1 E3 83 FF FF EA }
	condition:
		$pattern
}

rule umount_b615de22345b1a4071ad91329ccf5db8 {
	meta:
		aliases = "umount"
		size = "52"
		objfiles = "umounts@libc.a"
	strings:
		$pattern = { 80 40 2D E9 00 10 A0 E3 34 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule reboot_4a20edc9dfe7892d2be12dcbb36ebf57 {
	meta:
		aliases = "reboot"
		size = "68"
		objfiles = "reboots@libc.a"
	strings:
		$pattern = { 80 40 2D E9 00 20 A0 E1 2C 10 9F E5 2C 00 9F E5 58 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 69 19 12 28 AD DE E1 FE }
	condition:
		$pattern
}

rule timer_delete_51f1acbb51581af558d33f3bafc8ac94 {
	meta:
		aliases = "timer_delete"
		size = "88"
		objfiles = "timer_deletes@librt.a"
	strings:
		$pattern = { 80 40 2D E9 00 30 A0 E1 44 70 9F E5 04 00 90 E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 04 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 20 E0 E3 00 30 80 E5 05 00 00 EA 00 00 50 E3 00 20 E0 13 02 00 00 1A 03 00 A0 E1 ?? ?? ?? ?? 07 20 A0 E1 02 00 A0 E1 80 80 BD E8 05 01 00 00 }
	condition:
		$pattern
}

rule mq_unlink_3c650809136d3fb1bf38c9a04c4a08dd {
	meta:
		aliases = "mq_unlink"
		size = "116"
		objfiles = "mq_unlinks@librt.a"
	strings:
		$pattern = { 80 40 2D E9 00 30 D0 E5 2F 00 53 E3 03 00 00 0A ?? ?? ?? ?? 00 20 E0 E3 16 30 A0 E3 10 00 00 EA 01 00 80 E2 44 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 00 20 57 E2 05 00 00 AA ?? ?? ?? ?? 00 30 90 E5 00 20 E0 E3 01 00 53 E3 0D 30 A0 03 00 30 80 E5 02 00 A0 E1 80 80 BD E8 13 01 00 00 }
	condition:
		$pattern
}

rule msgctl_77fdaed4ecc49fb9126b77925362e849 {
	meta:
		aliases = "msgctl"
		size = "52"
		objfiles = "msgctls@libc.a"
	strings:
		$pattern = { 80 40 2D E9 01 1C 81 E3 13 7E A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule shmctl_c7833e8c854181b6f573eba758076c55 {
	meta:
		aliases = "shmctl"
		size = "52"
		objfiles = "shmctls@libc.a"
	strings:
		$pattern = { 80 40 2D E9 01 1C 81 E3 4D 7F A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule signalfd_2d28e59b3ceb4a6601139671f7a97869 {
	meta:
		aliases = "signalfd"
		size = "60"
		objfiles = "signalfds@libc.a"
	strings:
		$pattern = { 80 40 2D E9 02 30 A0 E1 28 70 9F E5 08 20 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 63 01 00 00 }
	condition:
		$pattern
}

rule __GI_fork_8507dd978ab691c8bf52e83e3e69d6a5 {
	meta:
		aliases = "fork, __libc_fork, __GI_fork"
		size = "48"
		objfiles = "forks@libc.a"
	strings:
		$pattern = { 80 40 2D E9 02 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_read_57b72a885db20d1cce29a4eed5f6c0fd {
	meta:
		aliases = "read, __libc_read, __GI_read"
		size = "48"
		objfiles = "reads@libc.a"
	strings:
		$pattern = { 80 40 2D E9 03 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule timer_settime_8fdf9fa605f3a6a099049d6d655aa8a6 {
	meta:
		aliases = "timer_settime"
		size = "56"
		objfiles = "timer_settimes@librt.a"
	strings:
		$pattern = { 80 40 2D E9 04 00 90 E5 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 02 01 00 00 }
	condition:
		$pattern
}

rule timer_gettime_dac320109bd24bb9be3aa0037f33b9ca {
	meta:
		aliases = "timer_gettime"
		size = "56"
		objfiles = "timer_gettimes@librt.a"
	strings:
		$pattern = { 80 40 2D E9 04 00 90 E5 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 03 01 00 00 }
	condition:
		$pattern
}

rule timer_getoverrun_0dc4844346b8697de338e477d8939931 {
	meta:
		aliases = "timer_getoverrun"
		size = "52"
		objfiles = "timer_getoverrs@librt.a"
	strings:
		$pattern = { 80 40 2D E9 04 00 90 E5 41 7F A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_write_4365eb49eaf674778e473d59d5e2f234 {
	meta:
		aliases = "write, __libc_write, __GI_write"
		size = "48"
		objfiles = "writes@libc.a"
	strings:
		$pattern = { 80 40 2D E9 04 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule close_d076d7d97288932948a3c7b5174af981 {
	meta:
		aliases = "__libc_close, __GI_close, close"
		size = "48"
		objfiles = "closes@libc.a"
	strings:
		$pattern = { 80 40 2D E9 06 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule sigpending_5641cfcfdb7785f7cbc35fe1bbe0aeba {
	meta:
		aliases = "sigpending"
		size = "52"
		objfiles = "sigpendings@libc.a"
	strings:
		$pattern = { 80 40 2D E9 08 10 A0 E3 B0 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_sigsuspend_0e56626cb2fe5d4f5ba568a91438d84c {
	meta:
		aliases = "__libc_sigsuspend, sigsuspend, __GI_sigsuspend"
		size = "52"
		objfiles = "sigsuspends@libc.a"
	strings:
		$pattern = { 80 40 2D E9 08 10 A0 E3 B3 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule link_9f40f33edb1a8dd7641d272b21a60d85 {
	meta:
		aliases = "link"
		size = "48"
		objfiles = "links@libc.a"
	strings:
		$pattern = { 80 40 2D E9 09 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule unlink_fea00789ff306718bf29aeddc88aaf9f {
	meta:
		aliases = "__GI_unlink, unlink"
		size = "48"
		objfiles = "unlinks@libc.a"
	strings:
		$pattern = { 80 40 2D E9 0A 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule execve_9c7e46c8a60b338ec569ed8ad1a2d905 {
	meta:
		aliases = "__GI_execve, execve"
		size = "48"
		objfiles = "execves@libc.a"
	strings:
		$pattern = { 80 40 2D E9 0B 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_chdir_08c9eb9e01565a199588339ef5fe1462 {
	meta:
		aliases = "chdir, __GI_chdir"
		size = "48"
		objfiles = "chdirs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 0C 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule socketpair_99de32f84972524c573d541309f259f3 {
	meta:
		aliases = "socketpair"
		size = "48"
		objfiles = "socketpairs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 12 7E A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI___libc_lseek_5d536694acd07217d5a0f3ea24ab01b8 {
	meta:
		aliases = "__libc_lseek, __GI_lseek, lseek, __GI___libc_lseek"
		size = "48"
		objfiles = "lseeks@libc.a"
	strings:
		$pattern = { 80 40 2D E9 13 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_getpid_8468e5f45bf57eee5aa9188f024d67e2 {
	meta:
		aliases = "getpid, __libc_getpid, __GI_getpid"
		size = "48"
		objfiles = "getpids@libc.a"
	strings:
		$pattern = { 80 40 2D E9 14 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule pause_83d47177a454c30c1a484ac26f4a016b {
	meta:
		aliases = "__libc_pause, pause"
		size = "48"
		objfiles = "pauses@libc.a"
	strings:
		$pattern = { 80 40 2D E9 1D 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule access_4440c12577104839cc188f5b413eb5aa {
	meta:
		aliases = "access"
		size = "48"
		objfiles = "accesss@libc.a"
	strings:
		$pattern = { 80 40 2D E9 21 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule nice_c55850f8d7a3b5d3bc712cfbae67e09f {
	meta:
		aliases = "nice"
		size = "68"
		objfiles = "nices@libc.a"
	strings:
		$pattern = { 80 40 2D E9 22 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 04 00 00 EA 00 00 50 E3 02 00 00 1A 00 10 A0 E1 80 40 BD E8 ?? ?? ?? ?? 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule clock_settime_4ee75ee92e39e9659801548fa4822036 {
	meta:
		aliases = "clock_settime"
		size = "52"
		objfiles = "clock_settimes@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 06 01 00 00 }
	condition:
		$pattern
}

rule clock_gettime_bcad128f29dd7e385044411bc8a75d6c {
	meta:
		aliases = "clock_gettime"
		size = "52"
		objfiles = "clock_gettimes@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 07 01 00 00 }
	condition:
		$pattern
}

rule __GI_utimes_0a7e9ca23889b5a834ec60c5defffe4c {
	meta:
		aliases = "utimes, __GI_utimes"
		size = "52"
		objfiles = "utimess@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 0D 01 00 00 }
	condition:
		$pattern
}

rule __GI_socket_e3da5cac1372426f6371e20ad92ea3dd {
	meta:
		aliases = "socket, __GI_socket"
		size = "52"
		objfiles = "sockets@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 19 01 00 00 }
	condition:
		$pattern
}

rule bind_c1a6e3f52096dc52be699fa7bc594842 {
	meta:
		aliases = "__GI_bind, bind"
		size = "52"
		objfiles = "binds@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 1A 01 00 00 }
	condition:
		$pattern
}

rule __libc_connect_e00e30c7cc7be00c57fac699a3ee6ad3 {
	meta:
		aliases = "connect, __GI_connect, __libc_connect"
		size = "52"
		objfiles = "connects@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 1B 01 00 00 }
	condition:
		$pattern
}

rule accept_f0f26420228d422ed5304c9935537fec {
	meta:
		aliases = "__GI_accept, __libc_accept, accept"
		size = "52"
		objfiles = "accepts@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 1D 01 00 00 }
	condition:
		$pattern
}

rule getsockname_a2e23d167e98cc9b9327c2d21aa0bb6e {
	meta:
		aliases = "__GI_getsockname, getsockname"
		size = "52"
		objfiles = "getsocknames@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 1E 01 00 00 }
	condition:
		$pattern
}

rule getpeername_29b13e73bef7bae62339289993f353c2 {
	meta:
		aliases = "getpeername"
		size = "52"
		objfiles = "getpeernames@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 1F 01 00 00 }
	condition:
		$pattern
}

rule __GI_send_ab74dc1dc500e494e8e4bef0151ab0f0 {
	meta:
		aliases = "__libc_send, send, __GI_send"
		size = "52"
		objfiles = "sends@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 21 01 00 00 }
	condition:
		$pattern
}

rule __libc_recv_399caef5e3ad24a3911c3c8512f578c0 {
	meta:
		aliases = "recv, __GI_recv, __libc_recv"
		size = "52"
		objfiles = "recvs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 23 01 00 00 }
	condition:
		$pattern
}

rule shutdown_a0acc67a1da6ee04d19b5a62e138fe51 {
	meta:
		aliases = "shutdown"
		size = "52"
		objfiles = "shutdowns@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 25 01 00 00 }
	condition:
		$pattern
}

rule __GI_recvmsg_212fcba790658ecc2d019d3e7d14b369 {
	meta:
		aliases = "recvmsg, __libc_recvmsg, __GI_recvmsg"
		size = "52"
		objfiles = "recvmsgs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 29 01 00 00 }
	condition:
		$pattern
}

rule semop_6755445b0c851ab2d1034b35039b0a27 {
	meta:
		aliases = "semop"
		size = "52"
		objfiles = "semops@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 2A 01 00 00 }
	condition:
		$pattern
}

rule semget_f4186d7542026b43f552b54c93f078dd {
	meta:
		aliases = "semget"
		size = "52"
		objfiles = "semgets@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 2B 01 00 00 }
	condition:
		$pattern
}

rule msgsnd_cf48558b7ee2a7a1eeb50d88ef374676 {
	meta:
		aliases = "msgsnd"
		size = "52"
		objfiles = "msgsnds@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 2D 01 00 00 }
	condition:
		$pattern
}

rule msgget_a7b176ee3da51643b76f9d4430a45117 {
	meta:
		aliases = "msgget"
		size = "52"
		objfiles = "msggets@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 2F 01 00 00 }
	condition:
		$pattern
}

rule shmat_5e9fed0b4ecb9049ca4d861343ab96b1 {
	meta:
		aliases = "shmat"
		size = "52"
		objfiles = "shmats@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 31 01 00 00 }
	condition:
		$pattern
}

rule shmdt_d598ae76e5f0ffb8df3d86fc7f526f6e {
	meta:
		aliases = "shmdt"
		size = "52"
		objfiles = "shmdts@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 32 01 00 00 }
	condition:
		$pattern
}

rule shmget_02fc77fdf59675fe3cd88ece844a6583 {
	meta:
		aliases = "shmget"
		size = "52"
		objfiles = "shmgets@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 33 01 00 00 }
	condition:
		$pattern
}

rule inotify_add_watch_02f7c705cb391b6ab170c416f5060311 {
	meta:
		aliases = "inotify_add_watch"
		size = "52"
		objfiles = "inotifys@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 3D 01 00 00 }
	condition:
		$pattern
}

rule inotify_rm_watch_c6f1055e34761b7f97d613b753af77ad {
	meta:
		aliases = "inotify_rm_watch"
		size = "52"
		objfiles = "inotifys@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 3E 01 00 00 }
	condition:
		$pattern
}

rule tee_e30c1cbc7583d4f4b7812b81194817cd {
	meta:
		aliases = "tee"
		size = "52"
		objfiles = "tees@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 56 01 00 00 }
	condition:
		$pattern
}

rule vmsplice_d948209f6e8bce02a7c9d2a5f001ac84 {
	meta:
		aliases = "__GI_vmsplice, vmsplice"
		size = "52"
		objfiles = "vmsplices@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 57 01 00 00 }
	condition:
		$pattern
}

rule mq_setattr_fbcea7d406e8319b42668ec048a48375 {
	meta:
		aliases = "__GI_mq_setattr, mq_setattr"
		size = "52"
		objfiles = "mq_getsetattrs@librt.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 17 01 00 00 }
	condition:
		$pattern
}

rule sync_e00cb1431f06b49f21abb2756f184609 {
	meta:
		aliases = "sync"
		size = "40"
		objfiles = "syncs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 24 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_kill_694c449522a9febc48e7260005b732bf {
	meta:
		aliases = "kill, __GI_kill"
		size = "48"
		objfiles = "kills@libc.a"
	strings:
		$pattern = { 80 40 2D E9 25 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule rename_b08283de5eccb3a8f2c115e23a808ad6 {
	meta:
		aliases = "rename"
		size = "48"
		objfiles = "renames@libc.a"
	strings:
		$pattern = { 80 40 2D E9 26 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_rmdir_a5c830a42b1f66b1c8c7dca87cbd66b7 {
	meta:
		aliases = "rmdir, __GI_rmdir"
		size = "48"
		objfiles = "rmdirs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 28 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule dup_ad79b2e58fb0d10d9846acbc82dbe76d {
	meta:
		aliases = "dup"
		size = "48"
		objfiles = "dups@libc.a"
	strings:
		$pattern = { 80 40 2D E9 29 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule pipe_4ecce59c5885254ed73dda2a37214780 {
	meta:
		aliases = "__GI_pipe, pipe"
		size = "48"
		objfiles = "pipes@libc.a"
	strings:
		$pattern = { 80 40 2D E9 2A 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule times_91844cd40e91edd18e8bae3923220dfe {
	meta:
		aliases = "__GI_times, times"
		size = "48"
		objfiles = "timess@libc.a"
	strings:
		$pattern = { 80 40 2D E9 2B 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule acct_cdfb8556a4e95ea253ad4566edb4b8d4 {
	meta:
		aliases = "acct"
		size = "48"
		objfiles = "accts@libc.a"
	strings:
		$pattern = { 80 40 2D E9 33 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule umount2_95aa92c35e63b30f80e49638d5469596 {
	meta:
		aliases = "umount2"
		size = "48"
		objfiles = "umount2s@libc.a"
	strings:
		$pattern = { 80 40 2D E9 34 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_setpgid_b194f8b7087f38a5e3e8e03542e79f5b {
	meta:
		aliases = "setpgid, __GI_setpgid"
		size = "48"
		objfiles = "setpgids@libc.a"
	strings:
		$pattern = { 80 40 2D E9 39 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule chroot_2ce1a42e89ccf45534e1cb9f55ebb339 {
	meta:
		aliases = "chroot"
		size = "48"
		objfiles = "chroots@libc.a"
	strings:
		$pattern = { 80 40 2D E9 3D 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_dup2_718d9f7157f58726b562dc5063420851 {
	meta:
		aliases = "dup2, __GI_dup2"
		size = "48"
		objfiles = "dup2s@libc.a"
	strings:
		$pattern = { 80 40 2D E9 3F 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule getppid_70a21a82d8bb973d53c8947e5cfe26ba {
	meta:
		aliases = "getppid"
		size = "48"
		objfiles = "getppids@libc.a"
	strings:
		$pattern = { 80 40 2D E9 40 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule stat_6440d3293d76b30414822e2214cdd302 {
	meta:
		aliases = "__GI_stat, stat"
		size = "88"
		objfiles = "stats@libc.a"
	strings:
		$pattern = { 80 40 2D E9 40 D0 4D E2 01 30 A0 E1 6A 70 A0 E3 0D 10 A0 E1 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 04 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 70 E0 E3 00 30 80 E5 04 00 00 EA 00 00 50 E3 02 00 00 1A 0D 00 A0 E1 03 10 A0 E1 ?? ?? ?? ?? 07 00 A0 E1 40 D0 8D E2 80 80 BD E8 }
	condition:
		$pattern
}

rule lstat_4bf2c6026aad3ffa8455c4478ba731d9 {
	meta:
		aliases = "__GI_lstat, lstat"
		size = "88"
		objfiles = "lstats@libc.a"
	strings:
		$pattern = { 80 40 2D E9 40 D0 4D E2 01 30 A0 E1 6B 70 A0 E3 0D 10 A0 E1 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 04 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 70 E0 E3 00 30 80 E5 04 00 00 EA 00 00 50 E3 02 00 00 1A 0D 00 A0 E1 03 10 A0 E1 ?? ?? ?? ?? 07 00 A0 E1 40 D0 8D E2 80 80 BD E8 }
	condition:
		$pattern
}

rule fstat_8710ad4dbd01d833befea3b117ec1cc5 {
	meta:
		aliases = "__GI_fstat, fstat"
		size = "88"
		objfiles = "fstats@libc.a"
	strings:
		$pattern = { 80 40 2D E9 40 D0 4D E2 01 30 A0 E1 6C 70 A0 E3 0D 10 A0 E1 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 04 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 70 E0 E3 00 30 80 E5 04 00 00 EA 00 00 50 E3 02 00 00 1A 0D 00 A0 E1 03 10 A0 E1 ?? ?? ?? ?? 07 00 A0 E1 40 D0 8D E2 80 80 BD E8 }
	condition:
		$pattern
}

rule getpgrp_8c34418621b44040ac7591e10eb63d0d {
	meta:
		aliases = "getpgrp"
		size = "48"
		objfiles = "getpgrps@libc.a"
	strings:
		$pattern = { 80 40 2D E9 41 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_setsid_d38607d3c5cdfa6d3183b9c87e341863 {
	meta:
		aliases = "setsid, __GI_setsid"
		size = "48"
		objfiles = "setsids@libc.a"
	strings:
		$pattern = { 80 40 2D E9 42 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_clock_getres_4fe660334e76f3408f24b82d95c5de26 {
	meta:
		aliases = "clock_getres, __GI_clock_getres"
		size = "48"
		objfiles = "clock_getress@libc.a"
	strings:
		$pattern = { 80 40 2D E9 42 7F A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule waitid_ad2a76a5c3deff4082cc9f0185368327 {
	meta:
		aliases = "waitid"
		size = "48"
		objfiles = "waitids@libc.a"
	strings:
		$pattern = { 80 40 2D E9 46 7F A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule listen_4ecb05222292c547a13367713b5fc8be {
	meta:
		aliases = "__GI_listen, listen"
		size = "48"
		objfiles = "listens@libc.a"
	strings:
		$pattern = { 80 40 2D E9 47 7F A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule sethostname_99868dfc530d4f94d1cc7303be1a3413 {
	meta:
		aliases = "sethostname"
		size = "48"
		objfiles = "sethostnames@libc.a"
	strings:
		$pattern = { 80 40 2D E9 4A 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_sendmsg_b920ffcd03496ef037ed1a8ecc3b1ed6 {
	meta:
		aliases = "__libc_sendmsg, sendmsg, __GI_sendmsg"
		size = "48"
		objfiles = "sendmsgs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 4A 7F A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule setrlimit_300a3b8357425a0878e0ee5ae6f8179d {
	meta:
		aliases = "__GI_setrlimit, setrlimit"
		size = "48"
		objfiles = "setrlimits@libc.a"
	strings:
		$pattern = { 80 40 2D E9 4B 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule getrusage_30e10c7cd434e2d3f99e6c4264205db4 {
	meta:
		aliases = "getrusage"
		size = "48"
		objfiles = "getrusages@libc.a"
	strings:
		$pattern = { 80 40 2D E9 4D 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_gettimeofday_151137a2f85a4e1ba65b65d9bb00dc48 {
	meta:
		aliases = "gettimeofday, __GI_gettimeofday"
		size = "48"
		objfiles = "gettimeofdays@libc.a"
	strings:
		$pattern = { 80 40 2D E9 4E 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule semtimedop_bfc1002dcd2a47471769c567f3191e70 {
	meta:
		aliases = "semtimedop"
		size = "48"
		objfiles = "semtimedops@libc.a"
	strings:
		$pattern = { 80 40 2D E9 4E 7F A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule settimeofday_c18613d582e07ea1e6134b930169c67a {
	meta:
		aliases = "__GI_settimeofday, settimeofday"
		size = "48"
		objfiles = "settimeofdays@libc.a"
	strings:
		$pattern = { 80 40 2D E9 4F 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule inotify_init_ae6d46713adf32fbb9d3e09a72375abe {
	meta:
		aliases = "inotify_init"
		size = "48"
		objfiles = "inotifys@libc.a"
	strings:
		$pattern = { 80 40 2D E9 4F 7F A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule symlink_c939ee3fd4fc9bf2d3643c5e47369389 {
	meta:
		aliases = "symlink"
		size = "48"
		objfiles = "symlinks@libc.a"
	strings:
		$pattern = { 80 40 2D E9 53 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule readlink_326614a6f4f135be50bf36f44138289a {
	meta:
		aliases = "__GI_readlink, readlink"
		size = "48"
		objfiles = "readlinks@libc.a"
	strings:
		$pattern = { 80 40 2D E9 55 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule swapon_e83f01c97e360d0dfa8fafba8f3c3651 {
	meta:
		aliases = "swapon"
		size = "48"
		objfiles = "swapons@libc.a"
	strings:
		$pattern = { 80 40 2D E9 57 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_munmap_e087b9f3befce10da67f0d981021aca0 {
	meta:
		aliases = "munmap, __GI_munmap"
		size = "48"
		objfiles = "munmaps@libc.a"
	strings:
		$pattern = { 80 40 2D E9 5B 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule truncate_56e52819043a809796446281388ef64f {
	meta:
		aliases = "__GI_truncate, truncate"
		size = "48"
		objfiles = "truncates@libc.a"
	strings:
		$pattern = { 80 40 2D E9 5C 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule ftruncate_e3d8f61c41d31fc2668c136df1492c6e {
	meta:
		aliases = "__GI_ftruncate, ftruncate"
		size = "48"
		objfiles = "ftruncates@libc.a"
	strings:
		$pattern = { 80 40 2D E9 5D 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule getpriority_79ff4b38dc85cbd1f7513e21b3236ed9 {
	meta:
		aliases = "__GI_getpriority, getpriority"
		size = "52"
		objfiles = "getprioritys@libc.a"
	strings:
		$pattern = { 80 40 2D E9 60 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 00 00 57 E2 14 00 60 A2 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_setpriority_46731a8b257e08171743ec828de13927 {
	meta:
		aliases = "setpriority, __GI_setpriority"
		size = "48"
		objfiles = "setprioritys@libc.a"
	strings:
		$pattern = { 80 40 2D E9 61 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule statfs_a5c0cfdd584a40a8f7765946f1656021 {
	meta:
		aliases = "__GI___libc_statfs, __libc_statfs, __GI_statfs, statfs"
		size = "48"
		objfiles = "statfss@libc.a"
	strings:
		$pattern = { 80 40 2D E9 63 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule fstatfs_41f8dc6abdfa473b86017439803930f5 {
	meta:
		aliases = "__GI_fstatfs, __GI___libc_fstatfs, __libc_fstatfs, fstatfs"
		size = "48"
		objfiles = "fstatfss@libc.a"
	strings:
		$pattern = { 80 40 2D E9 64 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule klogctl_8f2b02509cfd9e5c941eba6e1c3c67b8 {
	meta:
		aliases = "klogctl"
		size = "48"
		objfiles = "klogctls@libc.a"
	strings:
		$pattern = { 80 40 2D E9 67 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule setitimer_8176e82a3c04010578d1d654b76ea01c {
	meta:
		aliases = "__GI_setitimer, setitimer"
		size = "48"
		objfiles = "setitimers@libc.a"
	strings:
		$pattern = { 80 40 2D E9 68 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_stat64_ee79d5b1dc14b54c1e7ad13fa90360f9 {
	meta:
		aliases = "stat64, __GI_stat64"
		size = "88"
		objfiles = "stat64s@libc.a"
	strings:
		$pattern = { 80 40 2D E9 68 D0 4D E2 01 30 A0 E1 C3 70 A0 E3 0D 10 A0 E1 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 04 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 70 E0 E3 00 30 80 E5 04 00 00 EA 00 00 50 E3 02 00 00 1A 0D 00 A0 E1 03 10 A0 E1 ?? ?? ?? ?? 07 00 A0 E1 68 D0 8D E2 80 80 BD E8 }
	condition:
		$pattern
}

rule lstat64_147352615166adbf7c760ca43cd947ee {
	meta:
		aliases = "__GI_lstat64, lstat64"
		size = "88"
		objfiles = "lstat64s@libc.a"
	strings:
		$pattern = { 80 40 2D E9 68 D0 4D E2 01 30 A0 E1 C4 70 A0 E3 0D 10 A0 E1 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 04 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 70 E0 E3 00 30 80 E5 04 00 00 EA 00 00 50 E3 02 00 00 1A 0D 00 A0 E1 03 10 A0 E1 ?? ?? ?? ?? 07 00 A0 E1 68 D0 8D E2 80 80 BD E8 }
	condition:
		$pattern
}

rule fstat64_4ff4f18aa7f100220bc1cf9c9b3902dc {
	meta:
		aliases = "__GI_fstat64, fstat64"
		size = "88"
		objfiles = "fstat64s@libc.a"
	strings:
		$pattern = { 80 40 2D E9 68 D0 4D E2 01 30 A0 E1 C5 70 A0 E3 0D 10 A0 E1 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 04 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 70 E0 E3 00 30 80 E5 04 00 00 EA 00 00 50 E3 02 00 00 1A 0D 00 A0 E1 03 10 A0 E1 ?? ?? ?? ?? 07 00 A0 E1 68 D0 8D E2 80 80 BD E8 }
	condition:
		$pattern
}

rule getitimer_17bf38fab24ccac962b78f23b9c9d002 {
	meta:
		aliases = "getitimer"
		size = "48"
		objfiles = "getitimers@libc.a"
	strings:
		$pattern = { 80 40 2D E9 69 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule vhangup_751e3e29fa3c6435e0e52b3f822a707d {
	meta:
		aliases = "vhangup"
		size = "48"
		objfiles = "vhangups@libc.a"
	strings:
		$pattern = { 80 40 2D E9 6F 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_wait4_1a7bd4710cdf6533e1c3689b1fd3801b {
	meta:
		aliases = "wait4, __GI_wait4"
		size = "48"
		objfiles = "wait4s@libc.a"
	strings:
		$pattern = { 80 40 2D E9 72 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule swapoff_1412f4b97387d37ad1bf16922e8ba8f7 {
	meta:
		aliases = "swapoff"
		size = "48"
		objfiles = "swapoffs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 73 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule sysinfo_ee788229349e0f498eff375012ae6a02 {
	meta:
		aliases = "sysinfo"
		size = "48"
		objfiles = "sysinfos@libc.a"
	strings:
		$pattern = { 80 40 2D E9 74 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __libc_fsync_35a6831ebb67715eeacc12e6b59d814a {
	meta:
		aliases = "fsync, __libc_fsync"
		size = "48"
		objfiles = "fsyncs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 76 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule setdomainname_89371a00ac6f0b4af800b50f39a69257 {
	meta:
		aliases = "setdomainname"
		size = "48"
		objfiles = "setdomainnames@libc.a"
	strings:
		$pattern = { 80 40 2D E9 79 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule uname_47591fa881c9ce36d83b0986d299e4cd {
	meta:
		aliases = "__GI_uname, uname"
		size = "48"
		objfiles = "unames@libc.a"
	strings:
		$pattern = { 80 40 2D E9 7A 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_adjtimex_0b70e0693c6afc94af39aaa4aac71bf5 {
	meta:
		aliases = "ntp_adjtime, adjtimex, __GI_adjtimex"
		size = "48"
		objfiles = "adjtimexs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 7C 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule mprotect_e8413e53d3c67a656436c746f762280d {
	meta:
		aliases = "mprotect"
		size = "48"
		objfiles = "mprotects@libc.a"
	strings:
		$pattern = { 80 40 2D E9 7D 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule delete_module_0374e101a64a267f3bc2b5c1631ff35b {
	meta:
		aliases = "delete_module"
		size = "48"
		objfiles = "delete_modules@libc.a"
	strings:
		$pattern = { 80 40 2D E9 81 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule quotactl_40c9d9d9d7520e63727eab244017b9e1 {
	meta:
		aliases = "quotactl"
		size = "48"
		objfiles = "quotactls@libc.a"
	strings:
		$pattern = { 80 40 2D E9 83 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule getpgid_b33e89ac67d703d537b4b98169f5d37e {
	meta:
		aliases = "getpgid"
		size = "48"
		objfiles = "getpgids@libc.a"
	strings:
		$pattern = { 80 40 2D E9 84 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule fchdir_ad19b9e9d9f5ab3faffbe84c756addd8 {
	meta:
		aliases = "__GI_fchdir, fchdir"
		size = "48"
		objfiles = "fchdirs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 85 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule bdflush_c4b4ef7aa508662e445d0f10ce68522e {
	meta:
		aliases = "bdflush"
		size = "48"
		objfiles = "bdflushs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 86 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule personality_dcdc3bf02ad7702e96fab21c7bf9d170 {
	meta:
		aliases = "personality"
		size = "48"
		objfiles = "personalitys@libc.a"
	strings:
		$pattern = { 80 40 2D E9 88 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule flock_667342bda2fc96508c404017222fd906 {
	meta:
		aliases = "flock"
		size = "48"
		objfiles = "flocks@libc.a"
	strings:
		$pattern = { 80 40 2D E9 8F 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule msync_b83b06048e148ffa6ac539739907687b {
	meta:
		aliases = "__libc_msync, msync"
		size = "48"
		objfiles = "msyncs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 90 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __libc_readv_bf4f6350ebd68ffb3b3f15fc8bd1805c {
	meta:
		aliases = "readv, __libc_readv"
		size = "48"
		objfiles = "readvs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 91 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __libc_writev_1024dc38c7cf29448db11da03948bc19 {
	meta:
		aliases = "writev, __libc_writev"
		size = "48"
		objfiles = "writevs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 92 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule getsid_300a91d25c09ef8090af4bd15149f19e {
	meta:
		aliases = "__GI_getsid, getsid"
		size = "48"
		objfiles = "getsids@libc.a"
	strings:
		$pattern = { 80 40 2D E9 93 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule fdatasync_818ed7faf68f06ab4df1f319ab7d80f2 {
	meta:
		aliases = "fdatasync"
		size = "48"
		objfiles = "fdatasyncs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 94 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule mlock_dc41e1c01a618d9fd57da5fc52087c2e {
	meta:
		aliases = "mlock"
		size = "48"
		objfiles = "mlocks@libc.a"
	strings:
		$pattern = { 80 40 2D E9 96 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule munlock_ac377d1fde66c77c2b4d22df3ff812da {
	meta:
		aliases = "munlock"
		size = "48"
		objfiles = "munlocks@libc.a"
	strings:
		$pattern = { 80 40 2D E9 97 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule mlockall_4766c52fca70f84a92302110a0d7c0c2 {
	meta:
		aliases = "mlockall"
		size = "48"
		objfiles = "mlockalls@libc.a"
	strings:
		$pattern = { 80 40 2D E9 98 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule munlockall_ae27aca016790c45393c087e028349a8 {
	meta:
		aliases = "munlockall"
		size = "48"
		objfiles = "munlockalls@libc.a"
	strings:
		$pattern = { 80 40 2D E9 99 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule sched_setparam_a817752bd6c9e255840ff74faed07def {
	meta:
		aliases = "sched_setparam"
		size = "48"
		objfiles = "sched_setparams@libc.a"
	strings:
		$pattern = { 80 40 2D E9 9A 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule sched_getparam_d5d8aeb69995a45dc0fdc39114a1d3f7 {
	meta:
		aliases = "sched_getparam"
		size = "48"
		objfiles = "sched_getparams@libc.a"
	strings:
		$pattern = { 80 40 2D E9 9B 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule sched_setscheduler_ae357cea10996688dda52848db677996 {
	meta:
		aliases = "sched_setscheduler"
		size = "48"
		objfiles = "sched_setschedulers@libc.a"
	strings:
		$pattern = { 80 40 2D E9 9C 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule sched_getscheduler_cdc36dffaae67cf195c98b206cd878d7 {
	meta:
		aliases = "sched_getscheduler"
		size = "48"
		objfiles = "sched_getschedulers@libc.a"
	strings:
		$pattern = { 80 40 2D E9 9D 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule sched_yield_e655066947badcf73fa28b5091ce4587 {
	meta:
		aliases = "sched_yield"
		size = "48"
		objfiles = "sched_yields@libc.a"
	strings:
		$pattern = { 80 40 2D E9 9E 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule sched_get_priority_max_43a53627b36da2b65f2e984e31b46b09 {
	meta:
		aliases = "sched_get_priority_max"
		size = "48"
		objfiles = "sched_get_priority_maxs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 9F 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule sched_get_priority_min_30b900a55a6596e799e9edcc6512de52 {
	meta:
		aliases = "sched_get_priority_min"
		size = "48"
		objfiles = "sched_get_priority_mins@libc.a"
	strings:
		$pattern = { 80 40 2D E9 A0 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule sched_rr_get_interval_d09991fa5d88edf439e63496593a455d {
	meta:
		aliases = "sched_rr_get_interval"
		size = "48"
		objfiles = "sched_rr_get_intervals@libc.a"
	strings:
		$pattern = { 80 40 2D E9 A1 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule nanosleep_cfe1b9dbcce4e57a50f411a416ca04df {
	meta:
		aliases = "__GI_nanosleep, __libc_nanosleep, nanosleep"
		size = "48"
		objfiles = "nanosleeps@libc.a"
	strings:
		$pattern = { 80 40 2D E9 A2 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_poll_22615bfa34707ed26b1b45d5575fa89f {
	meta:
		aliases = "poll, __libc_poll, __GI_poll"
		size = "48"
		objfiles = "polls@libc.a"
	strings:
		$pattern = { 80 40 2D E9 A8 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __syscall_rt_sigaction_8ab9c7e3a3c207d1d721bc2b8fcd494f {
	meta:
		aliases = "__syscall_rt_sigaction"
		size = "48"
		objfiles = "__syscall_rt_sigactions@libc.a"
	strings:
		$pattern = { 80 40 2D E9 AE 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule capget_96c00617ddf7763a71556b44370613c7 {
	meta:
		aliases = "capget"
		size = "48"
		objfiles = "capgets@libc.a"
	strings:
		$pattern = { 80 40 2D E9 B8 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule capset_0d34e716bbd1b86e6601b7846e05fd18 {
	meta:
		aliases = "capset"
		size = "48"
		objfiles = "capsets@libc.a"
	strings:
		$pattern = { 80 40 2D E9 B9 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule sigaltstack_74da0cc4cff6ebb0cd7082a60f27e0d6 {
	meta:
		aliases = "sigaltstack"
		size = "48"
		objfiles = "sigaltstacks@libc.a"
	strings:
		$pattern = { 80 40 2D E9 BA 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule sendfile_c8d48fea1c53197ccef6551de6e50a9c {
	meta:
		aliases = "sendfile"
		size = "48"
		objfiles = "sendfiles@libc.a"
	strings:
		$pattern = { 80 40 2D E9 BB 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule getrlimit_4e2f136bdfdb64858b590d2efd0689a5 {
	meta:
		aliases = "__GI_getrlimit, getrlimit"
		size = "48"
		objfiles = "getrlimits@libc.a"
	strings:
		$pattern = { 80 40 2D E9 BF 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 80 80 BD E8 }
	condition:
		$pattern
}

rule lchown_3d766866a12cc8a3d3d7fd4b928514f8 {
	meta:
		aliases = "lchown"
		size = "48"
		objfiles = "lchowns@libc.a"
	strings:
		$pattern = { 80 40 2D E9 C6 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule getuid_13992372ab6936987b89d2b922b1cca8 {
	meta:
		aliases = "__GI_getuid, getuid"
		size = "48"
		objfiles = "getuids@libc.a"
	strings:
		$pattern = { 80 40 2D E9 C7 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_getgid_17ccbc7d63f85caa30fb13e8006af649 {
	meta:
		aliases = "getgid, __GI_getgid"
		size = "48"
		objfiles = "getgids@libc.a"
	strings:
		$pattern = { 80 40 2D E9 C8 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule geteuid_8e221f2ab9e4122098ed83d19af2a2d9 {
	meta:
		aliases = "__GI_geteuid, geteuid"
		size = "48"
		objfiles = "geteuids@libc.a"
	strings:
		$pattern = { 80 40 2D E9 C9 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_getegid_0decc7fbaa603288f3fbccb90e9a302a {
	meta:
		aliases = "getegid, __GI_getegid"
		size = "48"
		objfiles = "getegids@libc.a"
	strings:
		$pattern = { 80 40 2D E9 CA 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule setreuid_56fcd5b6f1cafdae0f0db86d23ea5318 {
	meta:
		aliases = "__GI_setreuid, setreuid"
		size = "48"
		objfiles = "setreuids@libc.a"
	strings:
		$pattern = { 80 40 2D E9 CB 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule setregid_276e852a1c3ff6d537ff4409b438ca3b {
	meta:
		aliases = "__GI_setregid, setregid"
		size = "48"
		objfiles = "setregids@libc.a"
	strings:
		$pattern = { 80 40 2D E9 CC 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_getgroups_63159388bdee1acb3f085d4e75ec0436 {
	meta:
		aliases = "getgroups, __GI_getgroups"
		size = "48"
		objfiles = "getgroupss@libc.a"
	strings:
		$pattern = { 80 40 2D E9 CD 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule setgroups_0dbc3ea37568759b708541cb3afd3ea0 {
	meta:
		aliases = "__GI_setgroups, setgroups"
		size = "48"
		objfiles = "setgroupss@libc.a"
	strings:
		$pattern = { 80 40 2D E9 CE 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule fchown_04f3c6d85c8577ad8fcaee9678f39ab8 {
	meta:
		aliases = "fchown"
		size = "48"
		objfiles = "fchowns@libc.a"
	strings:
		$pattern = { 80 40 2D E9 CF 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule setresuid_621d91baca200d0d8b4aa890318e4a15 {
	meta:
		aliases = "__GI_setresuid, setresuid"
		size = "48"
		objfiles = "setresuids@libc.a"
	strings:
		$pattern = { 80 40 2D E9 D0 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule getresuid_49c783a5bf2d56429c33e2b025db6c46 {
	meta:
		aliases = "getresuid"
		size = "48"
		objfiles = "getresuids@libc.a"
	strings:
		$pattern = { 80 40 2D E9 D1 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_setresgid_4775852ab6873c00884fa9adae70609b {
	meta:
		aliases = "setresgid, __GI_setresgid"
		size = "48"
		objfiles = "setresgids@libc.a"
	strings:
		$pattern = { 80 40 2D E9 D2 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule getresgid_564cf9f906e94589d5607a45e353ed38 {
	meta:
		aliases = "getresgid"
		size = "48"
		objfiles = "getresgids@libc.a"
	strings:
		$pattern = { 80 40 2D E9 D3 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __GI_chown_2c08ee2b0b6f9111d54f6e6583f771d9 {
	meta:
		aliases = "chown, __GI_chown"
		size = "48"
		objfiles = "chowns@libc.a"
	strings:
		$pattern = { 80 40 2D E9 D4 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule setuid_adede8e95d44e1a3cb47e903ba60c98a {
	meta:
		aliases = "setuid"
		size = "48"
		objfiles = "setuids@libc.a"
	strings:
		$pattern = { 80 40 2D E9 D5 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule setgid_6b9260dd7fe80d74417d6ff699070329 {
	meta:
		aliases = "setgid"
		size = "48"
		objfiles = "setgids@libc.a"
	strings:
		$pattern = { 80 40 2D E9 D6 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule setfsuid_39b1e870f873652b4c87cc00f8f15a0b {
	meta:
		aliases = "setfsuid"
		size = "48"
		objfiles = "setfsuids@libc.a"
	strings:
		$pattern = { 80 40 2D E9 D7 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule setfsgid_bb4846146be0e0ff7f70722ccc842be8 {
	meta:
		aliases = "setfsgid"
		size = "48"
		objfiles = "setfsgids@libc.a"
	strings:
		$pattern = { 80 40 2D E9 D8 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule pivot_root_0f163ec0b9902ca8f7e42cd44225c995 {
	meta:
		aliases = "pivot_root"
		size = "48"
		objfiles = "pivot_roots@libc.a"
	strings:
		$pattern = { 80 40 2D E9 DA 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule mincore_b076dd87c9be836e18f155b9f133b4be {
	meta:
		aliases = "mincore"
		size = "48"
		objfiles = "mincores@libc.a"
	strings:
		$pattern = { 80 40 2D E9 DB 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule madvise_aff4f4b91f01087c67bf2444fcd9c217 {
	meta:
		aliases = "madvise"
		size = "48"
		objfiles = "madvises@libc.a"
	strings:
		$pattern = { 80 40 2D E9 DC 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule getxattr_519dd716375eca1a27d7ea62269ccb6d {
	meta:
		aliases = "getxattr"
		size = "48"
		objfiles = "xattrs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 E5 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule lgetxattr_c24daa9e58b3af95cee04aa3d9647885 {
	meta:
		aliases = "lgetxattr"
		size = "48"
		objfiles = "xattrs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 E6 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule fgetxattr_6721613ad2b1ff7d407f6109f1e4aa6f {
	meta:
		aliases = "fgetxattr"
		size = "48"
		objfiles = "xattrs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 E7 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule listxattr_d75ad4b9c3ace18632538583686eaff6 {
	meta:
		aliases = "listxattr"
		size = "48"
		objfiles = "xattrs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 E8 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule llistxattr_8af6609ef4fabffd3b1df92b3ec3a7fe {
	meta:
		aliases = "llistxattr"
		size = "48"
		objfiles = "xattrs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 E9 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule flistxattr_a2c993be2b5a6c76329508d9bee3be67 {
	meta:
		aliases = "flistxattr"
		size = "48"
		objfiles = "xattrs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 EA 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule removexattr_dc7cf31587425ac60f0d3b9eee18f2d1 {
	meta:
		aliases = "removexattr"
		size = "48"
		objfiles = "xattrs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 EB 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule lremovexattr_564cdeca51344fb888554875bf69905e {
	meta:
		aliases = "lremovexattr"
		size = "48"
		objfiles = "xattrs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 EC 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule fremovexattr_b1585ea0ed5eb429a96eecdb4e550a59 {
	meta:
		aliases = "fremovexattr"
		size = "48"
		objfiles = "xattrs@libc.a"
	strings:
		$pattern = { 80 40 2D E9 ED 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule sendfile64_0b0d24bf58e4a6f596c2518353273b47 {
	meta:
		aliases = "sendfile64"
		size = "48"
		objfiles = "sendfile64s@libc.a"
	strings:
		$pattern = { 80 40 2D E9 EF 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule epoll_create_197cfba3009dd440573ad8e4766520a1 {
	meta:
		aliases = "epoll_create"
		size = "48"
		objfiles = "epolls@libc.a"
	strings:
		$pattern = { 80 40 2D E9 FA 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule epoll_ctl_375d2bd115ffc59df6b9b985d034933c {
	meta:
		aliases = "epoll_ctl"
		size = "48"
		objfiles = "epolls@libc.a"
	strings:
		$pattern = { 80 40 2D E9 FB 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule epoll_wait_2730b5fc92a764c31bf1abb638fd85bf {
	meta:
		aliases = "epoll_wait"
		size = "48"
		objfiles = "epolls@libc.a"
	strings:
		$pattern = { 80 40 2D E9 FC 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 80 80 BD 98 ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 80 80 BD E8 }
	condition:
		$pattern
}

rule __fixdfsi_56abfb5b65e1955574f06634d771a323 {
	meta:
		aliases = "__aeabi_d2iz, __fixdfsi"
		size = "92"
		objfiles = "_fixdfsi@libgcc.a"
	strings:
		$pattern = { 81 20 A0 E1 02 26 92 E2 0C 00 00 2A 09 00 00 5A 3E 3E E0 E3 C2 2A 53 E0 0A 00 00 9A 81 35 A0 E1 02 31 83 E3 A0 3A 83 E1 02 01 11 E3 33 02 A0 E1 00 00 60 12 1E FF 2F E1 00 00 A0 E3 1E FF 2F E1 01 06 90 E1 02 00 00 1A 02 01 11 E2 02 01 E0 03 1E FF 2F E1 00 00 A0 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule __truncdfsf2_ba4c1d129ecec78b3b1e094bcf451d9d {
	meta:
		aliases = "__aeabi_d2f, __truncdfsf2"
		size = "160"
		objfiles = "_truncdfsf2@libgcc.a"
	strings:
		$pattern = { 81 20 A0 E1 07 32 52 E2 02 C6 53 22 7F C5 7C 22 06 00 00 9A 02 C1 01 E2 80 21 A0 E1 A0 0E 8C E1 02 01 52 E3 03 01 A0 E0 01 00 C0 03 1E FF 2F E1 01 01 11 E3 0F 00 00 1A 2E 26 93 E2 02 01 01 B2 1E FF 2F B1 01 16 81 E3 A2 2A A0 E1 18 20 62 E2 20 C0 62 E2 10 3C B0 E1 30 02 A0 E1 01 00 80 13 81 35 A0 E1 A3 35 A0 E1 13 0C 80 E1 33 32 A0 E1 83 30 A0 E1 E6 FF FF EA C2 3A F0 E1 03 00 00 1A 01 36 90 E1 7F 04 A0 13 03 05 80 13 1E FF 2F 11 02 01 01 E2 7F 04 80 E3 02 05 80 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule __fixunsdfsi_222b961882185abfb551a4fb2235b39a {
	meta:
		aliases = "__aeabi_d2uiz, __fixunsdfsi"
		size = "84"
		objfiles = "_fixunsdfsi@libgcc.a"
	strings:
		$pattern = { 81 20 B0 E1 0A 00 00 2A 02 26 92 E2 0A 00 00 2A 07 00 00 5A 3E 3E E0 E3 C2 2A 53 E0 08 00 00 4A 81 35 A0 E1 02 31 83 E3 A0 3A 83 E1 33 02 A0 E1 1E FF 2F E1 00 00 A0 E3 1E FF 2F E1 01 06 90 E1 01 00 00 1A 00 00 E0 E3 1E FF 2F E1 00 00 A0 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule __unorddf2_5dbd5d40e7b15190875b3022de8a4e97 {
	meta:
		aliases = "__aeabi_dcmpun, __unorddf2"
		size = "56"
		objfiles = "_unorddf2@libgcc.a"
	strings:
		$pattern = { 81 C0 A0 E1 CC CA F0 E1 01 00 00 1A 01 C6 90 E1 06 00 00 1A 83 C0 A0 E1 CC CA F0 E1 01 00 00 1A 03 C6 92 E1 01 00 00 1A 00 00 A0 E3 1E FF 2F E1 01 00 A0 E3 1E FF 2F E1 }
	condition:
		$pattern
}

rule pthread_setspecific_e19e345de87b4c9eb29bf9e2c69b1709 {
	meta:
		aliases = "pthread_setspecific"
		size = "148"
		objfiles = "specifics@libpthread.a"
	strings:
		$pattern = { 84 20 9F E5 01 0B 50 E3 F0 41 2D E9 02 20 8F E0 00 40 A0 E1 01 80 A0 E1 19 00 00 2A 6C 30 9F E5 03 30 82 E0 80 31 93 E7 00 00 53 E3 14 00 00 0A 55 FF FF EB A4 62 A0 E1 06 31 80 E0 E0 50 83 E2 0C 30 95 E5 00 70 A0 E1 00 00 53 E3 06 00 00 1A 20 00 A0 E3 04 10 A0 E3 ?? ?? ?? ?? 00 00 50 E3 0C 00 A0 03 F0 81 BD 08 0C 00 85 E5 06 31 87 E0 EC 20 93 E5 00 00 A0 E3 1F 30 04 E2 03 81 82 E7 F0 81 BD E8 16 00 A0 E3 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule exit_5ebf8fc647088561489a119e3c181576 {
	meta:
		aliases = "__GI_exit, exit"
		size = "172"
		objfiles = "exits@libc.a"
	strings:
		$pattern = { 84 50 9F E5 84 30 9F E5 05 50 8F E0 03 40 95 E7 7C 30 9F E5 10 D0 4D E2 03 10 95 E7 04 20 A0 E1 70 30 9F E5 00 60 A0 E1 0D 00 A0 E1 0F E0 A0 E1 03 F0 95 E7 60 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 95 E7 54 30 9F E5 03 30 95 E7 00 00 53 E3 01 00 00 0A 06 00 A0 E1 33 FF 2F E1 40 30 9F E5 0D 00 A0 E1 01 10 A0 E3 0F E0 A0 E1 03 F0 95 E7 ?? ?? ?? ?? 2C 30 9F E5 03 30 95 E0 00 00 00 0A 33 FF 2F E1 06 00 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_kill_b08855a6aea535783f4600fcc7b9de91 {
	meta:
		aliases = "pthread_kill"
		size = "152"
		objfiles = "signalss@libpthread.a"
	strings:
		$pattern = { 88 20 9F E5 88 30 9F E5 70 40 2D E9 02 20 8F E0 00 40 A0 E1 03 00 92 E7 04 3B A0 E1 23 3B A0 E1 03 52 80 E0 01 60 A0 E1 05 00 A0 E1 00 10 A0 E3 ?? ?? ?? ?? 08 20 95 E5 00 00 52 E3 02 00 00 0A 10 30 92 E5 04 00 53 E1 06 00 00 0A 05 00 A0 E1 ?? ?? ?? ?? 03 00 A0 E3 70 80 BD E8 ?? ?? ?? ?? 00 00 90 E5 70 80 BD E8 14 40 92 E5 05 00 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 06 10 A0 E1 ?? ?? ?? ?? 01 00 70 E3 F4 FF FF 0A 00 00 A0 E3 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_manager_sighandler_f0bf1f520c247e55af372176e8368837 {
	meta:
		aliases = "__pthread_manager_sighandler"
		size = "164"
		objfiles = "managers@libpthread.a"
	strings:
		$pattern = { 8C 00 9F E5 30 40 2D E9 88 30 9F E5 00 00 8F E0 03 30 90 E7 9C D0 4D E2 00 00 53 E3 00 30 A0 13 03 00 00 1A 70 30 9F E5 03 30 90 E7 00 30 53 E2 01 30 A0 13 00 00 53 E3 58 30 9F E5 01 20 A0 E3 03 20 80 E7 10 00 00 0A 50 30 9F E5 04 40 8D E2 03 50 90 E7 00 30 A0 E3 04 30 8D E5 06 30 83 E2 08 30 8D E5 04 10 A0 E1 94 20 A0 E3 00 00 95 E5 ?? ?? ?? ?? 01 00 70 E3 03 00 00 1A ?? ?? ?? ?? 00 30 90 E5 04 00 53 E3 F5 FF FF 0A 9C D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule truncate64_4129959a783efd4ccdc87608a693529b {
	meta:
		aliases = "truncate64"
		size = "76"
		objfiles = "truncate64s@libc.a"
	strings:
		$pattern = { 90 40 2D E9 02 10 A0 E1 03 20 A0 E1 C2 4F A0 E1 04 D0 4D E2 01 20 A0 E1 C1 70 A0 E3 00 10 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 04 D0 8D E2 90 80 BD E8 }
	condition:
		$pattern
}

rule __GI_ftruncate64_98dcaf60eeded248dfa4bd038f96945a {
	meta:
		aliases = "ftruncate64, __GI_ftruncate64"
		size = "76"
		objfiles = "ftruncate64s@libc.a"
	strings:
		$pattern = { 90 40 2D E9 02 10 A0 E1 03 20 A0 E1 C2 4F A0 E1 04 D0 4D E2 01 20 A0 E1 C2 70 A0 E3 00 10 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 00 00 A0 91 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 00 E0 E3 04 D0 8D E2 90 80 BD E8 }
	condition:
		$pattern
}

rule mount_4f43cdc7e32c1add8503c62452c4d410 {
	meta:
		aliases = "mount"
		size = "60"
		objfiles = "mounts@libc.a"
	strings:
		$pattern = { 90 40 2D E9 04 D0 4D E2 10 40 9D E5 15 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 03 00 00 9A ?? ?? ?? ?? 00 30 64 E2 00 30 80 E5 00 00 E0 E3 04 D0 8D E2 90 80 BD E8 }
	condition:
		$pattern
}

rule setsockopt_adb22b659458a743530fb7e9cf3b8db1 {
	meta:
		aliases = "__GI_setsockopt, setsockopt"
		size = "64"
		objfiles = "setsockopts@libc.a"
	strings:
		$pattern = { 90 40 2D E9 04 D0 4D E2 10 40 9D E5 28 70 9F E5 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 03 00 00 9A ?? ?? ?? ?? 00 30 64 E2 00 30 80 E5 00 00 E0 E3 04 D0 8D E2 90 80 BD E8 26 01 00 00 }
	condition:
		$pattern
}

rule getsockopt_f3a131e968f3c539c3bf04e9cda6d8f9 {
	meta:
		aliases = "getsockopt"
		size = "64"
		objfiles = "getsockopts@libc.a"
	strings:
		$pattern = { 90 40 2D E9 04 D0 4D E2 10 40 9D E5 28 70 9F E5 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 03 00 00 9A ?? ?? ?? ?? 00 30 64 E2 00 30 80 E5 00 00 E0 E3 04 D0 8D E2 90 80 BD E8 27 01 00 00 }
	condition:
		$pattern
}

rule msgrcv_f430c38dee48f0e74e828027be3718fd {
	meta:
		aliases = "msgrcv"
		size = "64"
		objfiles = "msgrcvs@libc.a"
	strings:
		$pattern = { 90 40 2D E9 04 D0 4D E2 10 40 9D E5 28 70 9F E5 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 03 00 00 9A ?? ?? ?? ?? 00 30 64 E2 00 30 80 E5 00 00 E0 E3 04 D0 8D E2 90 80 BD E8 2E 01 00 00 }
	condition:
		$pattern
}

rule init_module_c3c02ecbe45a79e3f30bd7f1a4e973f4 {
	meta:
		aliases = "init_module"
		size = "60"
		objfiles = "init_modules@libc.a"
	strings:
		$pattern = { 90 40 2D E9 04 D0 4D E2 10 40 9D E5 80 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 03 00 00 9A ?? ?? ?? ?? 00 30 64 E2 00 30 80 E5 00 00 E0 E3 04 D0 8D E2 90 80 BD E8 }
	condition:
		$pattern
}

rule __libc_select_e88f959c350b79beee4d70f23540b029 {
	meta:
		aliases = "select, __GI_select, __libc_select"
		size = "60"
		objfiles = "selects@libc.a"
	strings:
		$pattern = { 90 40 2D E9 04 D0 4D E2 10 40 9D E5 8E 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 03 00 00 9A ?? ?? ?? ?? 00 30 64 E2 00 30 80 E5 00 00 E0 E3 04 D0 8D E2 90 80 BD E8 }
	condition:
		$pattern
}

rule mremap_2b3521c19fe2aee76c3922edd4a69313 {
	meta:
		aliases = "__GI_mremap, mremap"
		size = "60"
		objfiles = "mremaps@libc.a"
	strings:
		$pattern = { 90 40 2D E9 04 D0 4D E2 10 40 9D E5 A3 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 03 00 00 9A ?? ?? ?? ?? 00 30 64 E2 00 30 80 E5 00 00 E0 E3 04 D0 8D E2 90 80 BD E8 }
	condition:
		$pattern
}

rule prctl_2e7f70c4e84e0f2a497436b0ace8bc0e {
	meta:
		aliases = "prctl"
		size = "60"
		objfiles = "prctls@libc.a"
	strings:
		$pattern = { 90 40 2D E9 04 D0 4D E2 10 40 9D E5 AC 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 03 00 00 9A ?? ?? ?? ?? 00 30 64 E2 00 30 80 E5 00 00 E0 E3 04 D0 8D E2 90 80 BD E8 }
	condition:
		$pattern
}

rule setxattr_2ef4c8bf084155798e31130961b5db8e {
	meta:
		aliases = "setxattr"
		size = "60"
		objfiles = "xattrs@libc.a"
	strings:
		$pattern = { 90 40 2D E9 04 D0 4D E2 10 40 9D E5 E2 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 03 00 00 9A ?? ?? ?? ?? 00 30 64 E2 00 30 80 E5 00 00 E0 E3 04 D0 8D E2 90 80 BD E8 }
	condition:
		$pattern
}

rule lsetxattr_b0f5c59ed4029665f710b85f6d10068c {
	meta:
		aliases = "lsetxattr"
		size = "60"
		objfiles = "xattrs@libc.a"
	strings:
		$pattern = { 90 40 2D E9 04 D0 4D E2 10 40 9D E5 E3 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 03 00 00 9A ?? ?? ?? ?? 00 30 64 E2 00 30 80 E5 00 00 E0 E3 04 D0 8D E2 90 80 BD E8 }
	condition:
		$pattern
}

rule fsetxattr_9f8d2968c5e8b2fe043b5dc8ca5eb911 {
	meta:
		aliases = "fsetxattr"
		size = "60"
		objfiles = "xattrs@libc.a"
	strings:
		$pattern = { 90 40 2D E9 04 D0 4D E2 10 40 9D E5 E4 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 03 00 00 9A ?? ?? ?? ?? 00 30 64 E2 00 30 80 E5 00 00 E0 E3 04 D0 8D E2 90 80 BD E8 }
	condition:
		$pattern
}

rule remap_file_pages_f67a08fb329eedd9bf52e44a7899d70c {
	meta:
		aliases = "remap_file_pages"
		size = "60"
		objfiles = "remap_file_pagess@libc.a"
	strings:
		$pattern = { 90 40 2D E9 04 D0 4D E2 10 40 9D E5 FD 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 03 00 00 9A ?? ?? ?? ?? 00 30 64 E2 00 30 80 E5 00 00 E0 E3 04 D0 8D E2 90 80 BD E8 }
	condition:
		$pattern
}

rule _dl_protect_relro_404acee1a5965d0a34e51bcc84b88bd5 {
	meta:
		aliases = "_dl_protect_relro"
		size = "196"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { 90 40 2D E9 A8 40 9F E5 A8 30 9F E5 04 40 8F E0 03 30 94 E7 00 C0 A0 E1 D4 10 90 E5 00 00 90 E5 00 20 93 E5 D8 30 9C E5 00 10 81 E0 00 20 62 E2 03 30 81 E0 02 30 03 E0 01 00 02 E0 03 00 50 E1 04 D0 4D E2 18 00 00 0A 03 10 60 E0 01 20 A0 E3 7D 70 A0 E3 00 00 00 EF 01 0A 70 E3 58 20 9F 85 00 30 60 82 02 20 94 87 00 30 82 85 01 00 00 8A 00 00 50 E3 0C 00 00 AA 40 10 9F E5 04 20 9C E5 01 10 84 E0 02 00 A0 E3 ?? ?? ?? ?? 01 70 A0 E3 00 00 A0 E3 00 00 00 EF 01 0A 70 E3 18 20 9F 85 00 30 60 82 02 20 94 87 00 30 82 85 04 D0 8D E2 90 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mknod_14343c5a1b31a6c7e80b1cfa071682c9 {
	meta:
		aliases = "__GI_mknod, mknod"
		size = "88"
		objfiles = "mknods@libc.a"
	strings:
		$pattern = { 90 40 2D E9 FF C0 02 E2 22 24 A0 E1 03 2C 82 E1 02 C4 8C E1 0C C8 A0 E1 01 18 A0 E1 04 D0 4D E2 2C 28 A0 E1 21 18 A0 E1 0E 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 07 00 A0 E1 04 D0 8D E2 90 80 BD E8 }
	condition:
		$pattern
}

rule __re_match_2_d8f9be94e943be947e6a3c4f45b805f8 {
	meta:
		aliases = "re_match_2, __re_match_2"
		size = "4"
		objfiles = "regex_olds@libc.a"
	strings:
		$pattern = { 91 F8 FF EA }
	condition:
		$pattern
}

rule __GI_frexp_438d171c25928fd0d63ae8ebd1ed8cfd {
	meta:
		aliases = "frexp, __GI_frexp"
		size = "164"
		objfiles = "s_frexps@libm.a"
	strings:
		$pattern = { 94 C0 9F E5 F0 41 2D E9 02 E1 C1 E3 02 80 A0 E1 0C 00 5E E1 00 20 A0 E3 00 50 A0 E1 01 60 A0 E1 00 30 A0 E1 01 40 A0 E1 01 70 A0 E1 00 20 88 E5 16 00 00 CA 03 30 9E E1 14 00 00 0A 01 06 5E E3 08 00 00 AA 54 30 9F E5 00 20 A0 E3 ?? ?? ?? ?? 35 30 E0 E3 00 50 A0 E1 01 40 A0 E1 01 70 A0 E1 00 30 88 E5 02 E1 C1 E3 00 30 98 E5 7F 04 C7 E3 FF 3F 43 E2 0F 06 C0 E3 02 30 43 E2 FF 25 80 E3 2E 3A 83 E0 02 26 82 E3 00 30 88 E5 02 60 A0 E1 05 00 A0 E1 06 10 A0 E1 F0 81 BD E8 FF FF EF 7F 00 00 50 43 }
	condition:
		$pattern
}

rule pthread_start_thread_c052503e9b77c2a66fce959cea6fc4e9 {
	meta:
		aliases = "pthread_start_thread"
		size = "248"
		objfiles = "managers@libpthread.a"
	strings:
		$pattern = { 98 D0 4D E2 00 40 A0 E1 ?? ?? ?? ?? 64 10 84 E2 14 00 84 E5 00 20 A0 E3 02 00 A0 E3 ?? ?? ?? ?? E4 10 94 E5 B8 50 9F E5 00 00 51 E3 05 50 8F E0 14 00 94 A5 E8 20 84 A2 08 00 00 AA A4 30 9F E5 03 30 95 E7 18 30 93 E5 00 00 53 E3 04 00 00 DA 00 10 A0 E3 98 20 8D E2 04 10 22 E5 14 00 94 E5 ?? ?? ?? ?? 80 30 9F E5 03 30 95 E7 00 30 93 E5 00 00 53 E3 15 00 00 0A 70 30 9F E5 03 30 95 E7 00 30 93 E5 00 00 53 E3 10 00 00 DA 60 30 9F E5 00 40 8D E5 03 60 95 E7 05 30 A0 E3 04 30 8D E5 00 00 96 E5 0D 10 A0 E1 94 20 A0 E3 ?? ?? ?? ?? 01 00 70 E3 03 00 00 1A ?? ?? ?? ?? 00 30 90 E5 04 00 53 E3 F5 FF FF 0A }
	condition:
		$pattern
}

rule __pthread_do_exit_5368f6103192bcbdab064c6244d0dee6 {
	meta:
		aliases = "__pthread_do_exit"
		size = "320"
		objfiles = "joins@libpthread.a"
	strings:
		$pattern = { 98 D0 4D E2 01 40 A0 E1 00 50 A0 E1 BF FF FF EB 01 30 A0 E3 40 30 C0 E5 00 30 A0 E3 00 60 A0 E1 41 30 C0 E5 04 00 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? 1C 00 96 E5 06 10 A0 E1 ?? ?? ?? ?? 9C 31 96 E5 E4 70 9F E5 00 00 53 E3 30 50 86 E5 07 70 8F E0 0D 00 00 0A D4 30 9F E5 A0 21 96 E5 03 30 97 E7 00 30 93 E5 02 30 83 E1 01 0C 13 E3 06 00 00 0A BC 30 9F E5 AC 61 86 E5 03 20 97 E7 09 30 A0 E3 A8 31 86 E5 00 60 82 E5 ?? ?? ?? ?? 38 40 96 E5 01 30 A0 E3 2C 30 C6 E5 1C 00 96 E5 ?? ?? ?? ?? 00 00 54 E3 01 00 00 0A 04 00 A0 E1 ?? ?? ?? ?? 80 30 9F E5 03 30 97 E7 00 40 93 E5 04 00 56 E1 17 00 00 1A 70 30 9F E5 }
	condition:
		$pattern
}

rule __pthread_initialize_c2cfb945707cc05fdf62abc602c93c7c {
	meta:
		aliases = "__pthread_initialize"
		size = "4"
		objfiles = "pthreads@libpthread.a"
	strings:
		$pattern = { 9B FE FF EA }
	condition:
		$pattern
}

rule _dl_linux_resolver_1c17ec58fed4fcb8c942dd591cd2633b {
	meta:
		aliases = "_dl_linux_resolver"
		size = "260"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { 9C 30 90 E5 F0 45 2D E9 81 61 83 E0 04 20 96 E5 00 40 A0 E1 58 00 90 E5 22 34 A0 E1 03 12 90 E7 C8 50 9F E5 FF 20 02 E2 54 30 94 E5 16 00 52 E3 04 D0 4D E2 01 80 83 E0 05 50 8F E0 0E 00 00 0A AC 30 9F E5 AC 10 9F E5 03 30 95 E7 01 10 85 E0 00 20 93 E5 02 00 A0 E3 ?? ?? ?? ?? 01 00 A0 E3 00 70 A0 E1 00 00 00 EF 01 0A 70 E3 88 20 9F 85 00 30 60 82 02 20 95 87 00 30 82 85 04 20 A0 E1 1C 10 94 E5 08 00 A0 E1 01 30 A0 E3 00 A0 96 E5 00 60 94 E5 ?? ?? ?? ?? 00 40 50 E2 0F 00 00 1A 4C 30 9F E5 54 10 9F E5 03 30 95 E7 01 10 85 E0 00 20 93 E5 02 00 80 E2 08 30 A0 E1 ?? ?? ?? ?? 01 00 A0 E3 00 70 A0 E1 }
	condition:
		$pattern
}

rule __GI_memcpy_e511a389f9fe0cc6331c9b2cfbb8cbb8 {
	meta:
		aliases = "__GI_memmove, memcpy, memmove, __GI_memcpy"
		size = "4"
		objfiles = "memcpys@libc.a, memmoves@libc.a"
	strings:
		$pattern = { ?? ?? ?? EA }
	condition:
		$pattern
}

rule __ieee754_cosh_4179cb95e3c8922ab292e5b09a036353 {
	meta:
		aliases = "__ieee754_cosh"
		size = "468"
		objfiles = "e_coshs@libm.a"
	strings:
		$pattern = { A0 31 9F E5 F0 41 2D E9 02 81 C1 E3 03 00 58 E1 01 40 A0 E1 00 20 A0 C1 01 30 A0 C1 5B 00 00 CA 84 31 9F E5 03 00 58 E1 1E 00 00 CA ?? ?? ?? ?? ?? ?? ?? ?? 00 20 A0 E3 70 31 9F E5 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? ?? F2 05 58 E3 00 60 A0 E1 01 70 A0 E1 50 00 00 BA 04 20 A0 E1 05 30 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 06 20 A0 E1 00 40 A0 E1 01 50 A0 E1 07 30 A0 E1 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 0C 31 9F E5 00 20 A0 E3 14 00 00 EA 04 31 9F E5 03 00 58 E1 13 00 00 CA ?? ?? ?? ?? ?? ?? ?? ?? 00 20 A0 E3 F0 30 9F E5 00 40 A0 E1 }
	condition:
		$pattern
}

rule _dl_run_init_array_a1524f63dbf8209d098894d8eba67166 {
	meta:
		aliases = "_dl_run_init_array"
		size = "64"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { A4 30 90 E5 00 10 90 E5 AC 20 90 E5 00 00 53 E3 70 40 2D E9 03 60 81 10 22 51 A0 11 00 40 A0 13 70 80 BD 08 02 00 00 EA 0F E0 A0 E1 04 F1 96 E7 01 40 84 E2 05 00 54 E1 FA FF FF 3A 70 80 BD E8 }
	condition:
		$pattern
}

rule __default_rt_sa_restorer_6b460454973514f80a6c2916bd230f02 {
	meta:
		aliases = "__default_rt_sa_restorer"
		size = "8"
		objfiles = "sigrestorers@libc.a"
	strings:
		$pattern = { AD 70 A0 E3 00 00 00 EF }
	condition:
		$pattern
}

rule __flbf_63d0a9ecb8ab207f3c00a5d8f7de89ed {
	meta:
		aliases = "__flbf"
		size = "12"
		objfiles = "__flbfs@libc.a"
	strings:
		$pattern = { B0 00 D0 E1 01 0C 00 E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule feof_unlocked_51c2e7dd82de05fe791783d30953bdc4 {
	meta:
		aliases = "feof_unlocked"
		size = "12"
		objfiles = "feof_unlockeds@libc.a"
	strings:
		$pattern = { B0 00 D0 E1 04 00 00 E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule ferror_unlocked_36480778ab19c95e2f5b2a059c2cbdb1 {
	meta:
		aliases = "ferror_unlocked"
		size = "12"
		objfiles = "ferror_unlockeds@libc.a"
	strings:
		$pattern = { B0 00 D0 E1 08 00 00 E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule __freadable_3729f5ecd4be5874657428798d3bead6 {
	meta:
		aliases = "__freadable"
		size = "20"
		objfiles = "__freadables@libc.a"
	strings:
		$pattern = { B0 00 D0 E1 20 02 A0 E1 01 00 20 E2 01 00 00 E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule __freading_e2c8cd9a45bf8fb8e3204515ea241cff {
	meta:
		aliases = "__freading"
		size = "12"
		objfiles = "__freadings@libc.a"
	strings:
		$pattern = { B0 00 D0 E1 23 00 00 E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule __fwriting_397cf4f7fdfa744b5e9d58fed5620150 {
	meta:
		aliases = "__fwriting"
		size = "12"
		objfiles = "__fwritings@libc.a"
	strings:
		$pattern = { B0 00 D0 E1 50 00 00 E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule __fwritable_881da6a2314b83223dedda892479f0a6 {
	meta:
		aliases = "__fwritable"
		size = "20"
		objfiles = "__fwritables@libc.a"
	strings:
		$pattern = { B0 00 D0 E1 A0 02 A0 E1 01 00 20 E2 01 00 00 E2 1E FF 2F E1 }
	condition:
		$pattern
}

rule __fpurge_2309a77efa5988d103f4f1f18fee999b {
	meta:
		aliases = "__fpurge"
		size = "52"
		objfiles = "__fpurges@libc.a"
	strings:
		$pattern = { B0 30 D0 E1 08 20 90 E5 00 10 A0 E3 43 30 C3 E3 B0 30 C0 E1 14 20 80 E5 02 10 C0 E5 18 20 80 E5 1C 20 80 E5 10 20 80 E5 28 10 80 E5 2C 10 80 E5 1E FF 2F E1 }
	condition:
		$pattern
}

rule clearerr_unlocked_7188f7073e4ad3955fabd6dfe7992825 {
	meta:
		aliases = "clearerr_unlocked"
		size = "16"
		objfiles = "clearerr_unlockeds@libc.a"
	strings:
		$pattern = { B0 30 D0 E1 0C 30 C3 E3 B0 30 C0 E1 1E FF 2F E1 }
	condition:
		$pattern
}

rule __fpending_38ff52c57ff8f673b7a529213329ac01 {
	meta:
		aliases = "__fpending"
		size = "28"
		objfiles = "__fpendings@libc.a"
	strings:
		$pattern = { B0 30 D0 E1 40 30 13 E2 08 20 90 15 10 30 90 15 03 00 A0 01 03 00 62 10 1E FF 2F E1 }
	condition:
		$pattern
}

rule __libc_posix_fadvise_8a628cd6391b617a9b76e1d321f46ba6 {
	meta:
		aliases = "posix_fadvise, __libc_posix_fadvise"
		size = "60"
		objfiles = "posix_fadvises@libc.a"
	strings:
		$pattern = { B0 40 2D E9 01 C0 A0 E1 02 50 A0 E1 02 40 A0 E1 C5 5F A0 E1 01 20 A0 E1 18 70 9F E5 03 10 A0 E1 CC 3F A0 E1 00 00 00 EF 01 0A 70 E3 00 00 A0 93 00 00 60 82 B0 80 BD E8 0E 01 00 00 }
	condition:
		$pattern
}

rule readahead_b2047d05eab8d9814de7dc303eed87f0 {
	meta:
		aliases = "readahead"
		size = "60"
		objfiles = "readaheads@libc.a"
	strings:
		$pattern = { B0 40 2D E9 03 10 A0 E1 03 50 A0 E1 E1 70 A0 E3 10 30 9D E5 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 B0 80 BD E8 }
	condition:
		$pattern
}

rule __GI_mmap_993a0b9fbb6777ac0b641910cd7a0fbc {
	meta:
		aliases = "mmap, __GI_mmap"
		size = "100"
		objfiles = "mmaps@libc.a"
	strings:
		$pattern = { B0 40 2D E9 14 50 9D E5 05 CA A0 E1 2C CA A0 E1 00 00 5C E3 04 00 00 0A ?? ?? ?? ?? 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 0B 00 00 EA 25 56 A0 E1 10 40 9D E5 C0 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 20 A0 E1 02 00 A0 E1 B0 80 BD E8 }
	condition:
		$pattern
}

rule __GI_sendto_f2b8140687b949d4d0727ec4e90b7079 {
	meta:
		aliases = "sendto, __libc_sendto, __GI_sendto"
		size = "60"
		objfiles = "sendtos@libc.a"
	strings:
		$pattern = { B0 40 2D E9 14 50 9D E5 10 40 9D E5 24 70 9F E5 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 B0 80 BD 98 ?? ?? ?? ?? 00 30 64 E2 00 30 80 E5 00 00 E0 E3 B0 80 BD E8 22 01 00 00 }
	condition:
		$pattern
}

rule __GI_recvfrom_bb819f9dbe8b5f1afccc7fce7cdcd349 {
	meta:
		aliases = "__libc_recvfrom, recvfrom, __GI_recvfrom"
		size = "56"
		objfiles = "recvfroms@libc.a"
	strings:
		$pattern = { B0 40 2D E9 14 50 9D E5 10 40 9D E5 49 7F A0 E3 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 B0 80 BD 98 ?? ?? ?? ?? 00 30 64 E2 00 30 80 E5 00 00 E0 E3 B0 80 BD E8 }
	condition:
		$pattern
}

rule splice_96ddbb980ca6663ce021c7cd2f26eb4b {
	meta:
		aliases = "__GI_splice, splice"
		size = "56"
		objfiles = "splices@libc.a"
	strings:
		$pattern = { B0 40 2D E9 14 50 9D E5 10 40 9D E5 55 7F A0 E3 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 00 00 A0 91 B0 80 BD 98 ?? ?? ?? ?? 00 30 64 E2 00 30 80 E5 00 00 E0 E3 B0 80 BD E8 }
	condition:
		$pattern
}

rule pthread_getschedparam_5fdc1884cf75bf0643ec3399d29f1521 {
	meta:
		aliases = "__GI_pthread_getschedparam, pthread_getschedparam"
		size = "192"
		objfiles = "pthreads@libpthread.a"
	strings:
		$pattern = { B0 C0 9F E5 F0 40 2D E9 AC 30 9F E5 0C C0 8F E0 00 50 A0 E1 03 00 9C E7 05 3B A0 E1 23 3B A0 E1 03 42 80 E0 04 00 A0 E1 04 D0 4D E2 01 70 A0 E1 00 10 A0 E3 02 60 A0 E1 ?? ?? ?? ?? 08 00 94 E5 00 00 50 E3 02 00 00 0A 10 30 90 E5 05 00 53 E1 0D 00 00 0A 04 00 A0 E1 ?? ?? ?? ?? 03 00 A0 E3 12 00 00 EA 05 00 A0 E1 06 10 A0 E1 ?? ?? ?? ?? 01 00 70 E3 00 00 A0 13 00 40 87 15 0B 00 00 1A ?? ?? ?? ?? 00 00 90 E5 08 00 00 EA 14 50 90 E5 04 00 A0 E1 ?? ?? ?? ?? 05 00 A0 E1 ?? ?? ?? ?? 01 00 70 E3 00 40 A0 E1 ED FF FF 1A F3 FF FF EA 04 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __drand48_iterate_b28f60ece1202246df84100757d2a855 {
	meta:
		aliases = "__drand48_iterate"
		size = "176"
		objfiles = "drand48_iters@libc.a"
	strings:
		$pattern = { BE 30 D1 E1 F0 40 2D E9 00 00 53 E3 01 E0 A0 E1 00 70 A0 E1 07 00 00 1A 8C 30 9F E5 05 40 A0 E3 10 30 81 E5 14 40 81 E5 01 20 A0 E3 0B 10 A0 E3 BC 10 CE E1 BE 20 CE E1 B4 30 D7 E1 B0 10 D7 E1 B2 C0 D7 E1 00 40 A0 E3 03 40 A0 E1 00 30 A0 E3 14 00 9E E5 01 30 83 E1 0C C8 A0 E1 0C 10 83 E1 90 01 0C E0 10 00 9E E5 04 20 A0 E1 90 C2 22 E0 90 31 84 E0 BC 50 DE E1 04 40 82 E0 05 10 93 E0 00 20 A4 E2 01 50 A0 E1 00 40 A0 E3 21 18 A0 E1 02 18 81 E1 02 60 A0 E1 04 00 A0 E1 B4 20 C7 E1 B2 10 C7 E1 B0 50 C7 E1 F0 80 BD E8 6D E6 EC DE }
	condition:
		$pattern
}

rule svcunixfd_create_bc0e6b3663d32c78bfee8255354b696f {
	meta:
		aliases = "svcfd_create, svcunixfd_create"
		size = "4"
		objfiles = "svc_tcps@libc.a, svc_unixs@libc.a"
	strings:
		$pattern = { BE FF FF EA }
	condition:
		$pattern
}

rule asinh_da6df899967755e9ed4535d4e05e7252 {
	meta:
		aliases = "__GI_asinh, asinh"
		size = "508"
		objfiles = "s_asinhs@libm.a"
	strings:
		$pattern = { D4 31 9F E5 F0 47 2D E9 02 41 C1 E3 03 00 54 E1 00 80 A0 E1 01 90 A0 E1 01 A0 A0 E1 03 00 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 65 00 00 EA A8 31 9F E5 03 00 54 E1 07 00 00 CA A0 21 9F E5 A0 31 9F E5 ?? ?? ?? ?? 00 20 A0 E3 98 31 9F E5 ?? ?? ?? ?? 00 00 50 E3 5C 00 00 1A 8C 31 9F E5 03 00 54 E1 07 00 00 DA 08 00 A0 E1 09 10 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? 74 21 9F E5 74 31 9F E5 ?? ?? ?? ?? 4B 00 00 EA 01 01 54 E3 27 00 00 DA 08 00 A0 E1 09 10 A0 E1 ?? ?? ?? ?? 08 20 A0 E1 00 40 A0 E1 01 50 A0 E1 09 30 A0 E1 08 00 A0 E1 09 10 A0 E1 ?? ?? ?? ?? 00 20 A0 E3 28 31 9F E5 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_manager_04f306388c58d43d9674434bf0fb33c7 {
	meta:
		aliases = "__pthread_manager"
		size = "2100"
		objfiles = "managers@libpthread.a"
	strings:
		$pattern = { D4 97 9F E5 D4 37 9F E5 09 90 8F E0 03 30 99 E7 5E DF 4D E2 50 20 83 E2 F0 40 8D E2 48 10 83 E2 4C 20 83 E5 44 10 83 E5 38 00 8D E5 04 00 A0 E1 ?? ?? ?? ?? A8 37 9F E5 04 00 A0 E1 03 30 99 E7 00 10 93 E5 ?? ?? ?? ?? 04 00 A0 E1 05 10 A0 E3 ?? ?? ?? ?? 8C 37 9F E5 03 30 99 E7 00 30 93 E5 00 00 53 E3 06 00 00 0A 7C 37 9F E5 03 30 99 E7 00 10 93 E5 00 00 51 E3 01 00 00 DA 04 00 A0 E1 ?? ?? ?? ?? F0 10 8D E2 00 20 A0 E3 02 00 A0 E3 ?? ?? ?? ?? 54 37 9F E5 5C 40 8D E2 03 30 99 E7 00 30 93 E5 18 00 93 E5 ?? ?? ?? ?? 38 00 9D E5 04 10 A0 E1 94 20 A0 E3 ?? ?? ?? ?? 01 00 70 E3 03 00 00 1A ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mq_timedreceive_679523e9cc514ad8096b1bd7e53c2fd4 {
	meta:
		aliases = "mq_timedreceive"
		size = "4"
		objfiles = "mq_receives@librt.a"
	strings:
		$pattern = { E7 FF FF EA }
	condition:
		$pattern
}

rule mq_timedsend_32d44b5a8b8fe3ebbcb7cb730e56dfeb {
	meta:
		aliases = "mq_timedsend"
		size = "4"
		objfiles = "mq_sends@librt.a"
	strings:
		$pattern = { E8 FF FF EA }
	condition:
		$pattern
}

rule __re_compile_fastmap_30a88f85bac5abe9879344c3e68d82dd {
	meta:
		aliases = "re_compile_fastmap, __re_compile_fastmap"
		size = "4"
		objfiles = "regex_olds@libc.a"
	strings:
		$pattern = { EC FE FF EA }
	condition:
		$pattern
}

rule tdelete_8bc03ffa364d4f44dbbacd1d52585f88 {
	meta:
		aliases = "tdelete"
		size = "232"
		objfiles = "tdeletes@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 00 51 E3 04 D0 4D E2 00 70 A0 E1 02 50 A0 E1 30 00 00 0A 00 60 91 E5 01 40 A0 E1 00 00 56 E3 04 00 00 EA 04 40 83 B2 08 40 83 A2 03 60 A0 E1 00 30 94 E5 00 00 53 E3 26 00 00 0A 00 30 94 E5 07 00 A0 E1 00 10 93 E5 35 FF 2F E1 00 00 50 E3 00 30 94 E5 F2 FF FF 1A 04 50 93 E5 08 10 93 E5 00 00 55 E3 05 00 00 0A 00 00 51 E3 14 00 00 0A 04 20 91 E5 00 00 52 E3 04 00 00 1A 04 50 81 E5 01 50 A0 E1 0E 00 00 EA 03 20 A0 E1 00 10 A0 E1 04 30 92 E5 02 00 A0 E1 00 00 53 E3 F9 FF FF 1A 08 30 92 E5 02 50 A0 E1 04 30 81 E5 00 30 94 E5 04 30 93 E5 04 30 82 E5 00 30 94 E5 08 30 93 E5 08 30 82 E5 }
	condition:
		$pattern
}

rule pthread_cond_broadcast_eaeecd5214ba7609f838fd481fd9b2fa {
	meta:
		aliases = "__GI_pthread_cond_broadcast, pthread_cond_broadcast"
		size = "96"
		objfiles = "condvars@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 00 10 A0 E3 01 50 A0 E1 00 40 A0 E1 04 D0 4D E2 ?? ?? ?? ?? 08 60 94 E5 04 00 A0 E1 08 50 84 E5 ?? ?? ?? ?? 05 70 A0 E1 01 50 85 E2 05 00 00 EA 08 40 96 E5 B9 51 C6 E5 08 70 86 E5 06 00 A0 E1 EC FF FF EB 04 60 A0 E1 00 00 56 E3 F7 FF FF 1A 06 00 A0 E1 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule __fixunsdfdi_aa32ae4cc1140e1e296a61c5ee95431b {
	meta:
		aliases = "__aeabi_d2ulz, __fixunsdfdi"
		size = "108"
		objfiles = "_fixunsdfdi@libgcc.a"
	strings:
		$pattern = { F0 40 2D E9 00 20 A0 E3 04 D0 4D E2 50 30 9F E5 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? 00 60 A0 E1 ?? ?? ?? ?? 00 20 A0 E3 34 30 9F E5 ?? ?? ?? ?? 04 20 A0 E1 05 30 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? 00 70 A0 E3 06 70 A0 E1 00 10 A0 E3 00 60 A0 E3 06 00 80 E1 07 10 81 E1 04 D0 8D E2 F0 80 BD E8 00 00 F0 3D 00 00 F0 C1 }
	condition:
		$pattern
}

rule __GI_rresvport_49a89a0e361d58daeca57c8107350994 {
	meta:
		aliases = "rresvport, __GI_rresvport"
		size = "188"
		objfiles = "rcmds@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 30 A0 E3 14 D0 4D E2 02 C0 A0 E3 00 50 A0 E1 03 20 A0 E1 02 00 A0 E3 01 10 A0 E3 B0 C0 CD E1 04 30 8D E5 ?? ?? ?? ?? 00 40 50 E2 1D 00 00 BA 0D 70 A0 E1 00 20 95 E5 0D 10 A0 E1 02 28 A0 E1 22 34 A0 E1 FF 3C 03 E2 22 3C 83 E1 04 00 A0 E1 10 20 A0 E3 B2 30 CD E1 ?? ?? ?? ?? 00 00 50 E3 11 00 00 AA ?? ?? ?? ?? 00 30 90 E5 00 60 A0 E1 62 00 53 E3 02 00 00 0A 04 00 A0 E1 ?? ?? ?? ?? 08 00 00 EA 00 30 95 E5 01 30 43 E2 02 0C 53 E3 00 30 85 E5 E6 FF FF 1A 04 00 A0 E1 ?? ?? ?? ?? 0B 30 A0 E3 00 30 86 E5 00 40 E0 E3 04 00 A0 E1 14 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule adjtime_18ebe0c8bbfe83ba44bb876d15f2baf4 {
	meta:
		aliases = "adjtime"
		size = "272"
		objfiles = "adjtimes@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 40 50 E2 84 D0 4D E2 01 60 A0 E1 18 00 00 0A 04 70 94 E5 E4 50 9F E5 07 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 00 30 94 E5 D4 20 9F E5 03 40 80 E0 86 3E 84 E2 01 30 83 E2 02 00 53 E1 04 00 00 9A ?? ?? ?? ?? 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 27 00 00 EA 07 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 95 04 04 E0 9C 30 9F E5 01 40 84 E0 18 00 8D E8 00 00 00 EA 00 40 8D E5 0D 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 20 E0 B3 19 00 00 BA 00 00 56 E3 06 20 A0 01 16 00 00 0A 04 40 9D E5 00 00 54 E3 0A 00 00 AA 00 00 64 E2 50 10 9F E5 ?? ?? ?? ?? 00 10 61 E2 04 10 86 E5 04 00 A0 E1 3C 10 9F E5 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tsearch_3ecfceef1aebbd787d3407a9e7c162e1 {
	meta:
		aliases = "__GI_tsearch, tsearch"
		size = "116"
		objfiles = "tsearchs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 40 51 E2 00 60 A0 E1 04 D0 4D E2 02 70 A0 E1 04 00 A0 01 13 00 00 0A 07 00 00 EA 00 10 95 E5 37 FF 2F E1 00 00 50 E3 00 00 94 05 0D 00 00 0A 00 00 94 E5 04 40 80 B2 08 40 80 A2 00 50 94 E5 06 00 A0 E1 00 00 55 E3 F3 FF FF 1A 0C 00 A0 E3 ?? ?? ?? ?? 00 00 50 E3 00 00 84 15 00 60 80 15 04 50 80 15 08 50 80 15 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule __heap_free_f2afeff3b617703b4d2ad8bc7f271632 {
	meta:
		aliases = "__heap_free"
		size = "248"
		objfiles = "heap_frees@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 40 90 E5 04 D0 4D E2 02 E0 81 E0 00 60 A0 E3 03 00 00 EA 01 00 53 E1 05 00 00 2A 04 60 A0 E1 04 40 94 E5 00 00 54 E3 0C 30 84 E2 F8 FF FF 1A 26 00 00 EA 00 C0 94 E5 03 30 6C E0 0E 00 53 E1 22 00 00 8A 0C 70 82 E0 0A 00 00 1A 00 00 56 E3 1B 00 00 0A 0C 30 86 E2 03 00 51 E1 18 00 00 1A 00 30 96 E5 08 20 96 E5 04 10 A0 E1 03 70 87 E0 DC FF FF EB 12 00 00 EA 04 50 94 E5 00 00 55 E3 0A 00 00 0A 00 C0 95 E5 0C 30 85 E2 03 30 6C E0 03 00 5E E1 05 00 00 1A 06 20 A0 E1 05 10 A0 E1 0C 70 87 E0 CF FF FF EB 05 40 A0 E1 04 00 00 EA 02 40 84 E0 05 30 A0 E1 06 20 A0 E1 04 10 A0 E1 C0 FF FF EB }
	condition:
		$pattern
}

rule __GI_closedir_6ba6c438924083c14b5ce599256360c7 {
	meta:
		aliases = "closedir, __GI_closedir"
		size = "196"
		objfiles = "closedirs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 40 90 E5 A0 70 9F E5 01 00 74 E3 14 D0 4D E2 00 60 A0 E1 07 70 8F E0 04 00 00 1A ?? ?? ?? ?? 09 30 A0 E3 04 20 A0 E1 00 30 80 E5 1B 00 00 EA 78 30 9F E5 18 40 80 E2 04 20 A0 E1 03 10 97 E7 0D 00 A0 E1 68 30 9F E5 0F E0 A0 E1 03 F0 97 E7 04 00 A0 E1 5C 30 9F E5 0F E0 A0 E1 03 F0 97 E7 00 30 E0 E3 01 10 A0 E3 00 40 96 E5 0D 00 A0 E1 00 30 86 E5 40 30 9F E5 0F E0 A0 E1 03 F0 97 E7 0C 00 96 E5 ?? ?? ?? ?? 06 00 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 ?? ?? ?? ?? 0D 50 A0 E1 00 20 A0 E1 02 00 A0 E1 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __encode_answer_78161a00db2ee7b21ed030195956d08d {
	meta:
		aliases = "__encode_answer"
		size = "216"
		objfiles = "encodeas@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 40 A0 E1 04 D0 4D E2 00 00 90 E5 01 70 A0 E1 02 60 A0 E1 ?? ?? ?? ?? 00 50 50 E2 29 00 00 BA 10 30 94 E5 06 20 65 E0 0A 30 83 E2 03 00 52 E1 00 50 E0 B3 23 00 00 BA 05 30 D4 E5 05 20 87 E0 05 30 C7 E7 04 30 94 E5 01 10 82 E2 01 30 C2 E5 09 30 D4 E5 01 20 81 E2 01 30 C1 E5 08 30 94 E5 01 10 82 E2 01 30 C2 E5 0F 30 D4 E5 01 20 81 E2 01 30 C1 E5 0E 30 D4 E5 01 10 82 E2 01 30 C2 E5 0D 30 D4 E5 01 20 81 E2 01 30 C1 E5 0C 30 94 E5 01 10 82 E2 01 30 C2 E5 11 30 D4 E5 01 20 81 E2 01 30 C1 E5 10 30 94 E5 02 00 82 E2 01 30 C2 E5 14 10 94 E5 10 20 94 E5 ?? ?? ?? ?? 10 30 94 E5 0A 30 83 E2 }
	condition:
		$pattern
}

rule _obstack_newchunk_557919b88b38b2ef72bb957351ee8c2c {
	meta:
		aliases = "_obstack_newchunk"
		size = "360"
		objfiles = "obstacks@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 40 A0 E1 08 20 94 E5 0C 00 90 E5 18 30 94 E5 00 70 62 E0 64 30 83 E2 07 30 83 E0 01 30 83 E0 00 20 94 E5 28 10 D4 E5 C7 31 83 E0 02 00 53 E1 03 50 A0 A1 02 50 A0 B1 01 00 11 E3 04 D0 4D E2 04 60 94 E5 1C 30 94 E5 03 00 00 0A 24 00 94 E5 05 10 A0 E1 33 FF 2F E1 01 00 00 EA 05 00 A0 E1 33 FF 2F E1 00 00 50 E3 00 00 00 1A 51 00 00 EB 18 30 94 E5 08 20 80 E2 06 00 53 E3 05 10 80 E0 03 20 82 E0 27 C1 A0 C1 10 10 84 E5 04 00 84 E5 00 10 80 E5 03 50 C2 E1 04 60 80 E5 00 30 A0 D3 01 10 4C C2 05 00 00 CA 07 00 00 EA 08 30 94 E5 01 21 A0 E1 02 30 93 E7 01 10 41 E2 02 30 85 E7 00 00 51 E3 }
	condition:
		$pattern
}

rule timer_create_030fc99b134410a825268b2abeae022e {
	meta:
		aliases = "timer_create"
		size = "180"
		objfiles = "timer_creates@librt.a"
	strings:
		$pattern = { F0 40 2D E9 00 50 51 E2 4C D0 4D E2 0C 50 8D 05 0E 30 A0 03 04 50 8D 02 08 30 8D 05 08 30 95 E5 00 70 A0 E1 02 00 53 E3 02 60 A0 E1 1B 00 00 0A 08 00 A0 E3 ?? ?? ?? ?? 00 40 50 E2 17 00 00 0A 07 00 A0 E1 04 40 8D E5 44 20 8D E2 05 10 A0 E1 58 70 9F E5 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 00 70 E0 E3 01 00 77 E3 05 00 00 0A 08 30 95 E5 00 40 86 E5 00 30 84 E5 44 30 9D E5 04 30 84 E5 03 00 00 EA 04 00 A0 E1 ?? ?? ?? ?? 00 00 00 EA 00 70 E0 E3 07 00 A0 E1 4C D0 8D E2 F0 80 BD E8 01 01 00 00 }
	condition:
		$pattern
}

rule __GI_wcsncasecmp_b2a7168806e4d1a9d83bb26d18e27d85 {
	meta:
		aliases = "wcsncasecmp, __GI_wcsncasecmp"
		size = "144"
		objfiles = "wcsncasecmps@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 50 A0 E1 04 D0 4D E2 01 70 A0 E1 02 60 A0 E1 04 00 00 EA 00 00 95 E5 04 70 87 E2 00 00 50 E3 17 00 00 0A 04 50 85 E2 00 00 56 E3 06 00 A0 01 13 00 00 0A 00 30 95 E5 00 20 97 E5 03 00 A0 E1 02 00 53 E1 01 60 46 E2 F1 FF FF 0A ?? ?? ?? ?? 00 40 A0 E1 00 00 97 E5 ?? ?? ?? ?? 00 00 54 E1 EB FF FF 0A 00 00 95 E5 ?? ?? ?? ?? 00 40 A0 E1 00 00 97 E5 ?? ?? ?? ?? 00 00 54 E1 00 00 E0 33 01 00 A0 23 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule __old_sem_post_1c970b216f1bf42a5e4a85ef13c76d76 {
	meta:
		aliases = "__old_sem_post"
		size = "224"
		objfiles = "oldsemaphores@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 00 50 A0 E1 0C D0 4D E2 03 70 A0 E3 00 40 95 E5 01 60 14 E2 07 20 A0 01 07 00 00 0A 06 01 74 E3 04 00 00 1A ?? ?? ?? ?? 22 30 A0 E3 00 20 E0 E3 00 30 80 E5 25 00 00 EA 02 20 84 E2 05 00 A0 E1 04 10 A0 E1 D0 FF FF EB 00 00 50 E3 EE FF FF 0A 00 00 56 E3 08 E0 8D 02 04 60 2E 05 0D 00 00 0A 19 00 00 EA 08 40 91 E5 0E C0 A0 E1 00 00 00 EA 08 C0 80 E2 00 00 9C E5 00 00 50 E3 03 00 00 0A 18 20 91 E5 18 30 90 E5 03 00 52 E1 F7 FF FF BA 08 00 81 E5 00 10 8C E5 01 00 54 E3 04 10 A0 E1 EF FF FF 1A 04 00 00 EA 08 30 92 E5 04 30 8D E5 08 40 82 E5 ?? ?? ?? ?? 00 00 00 EA 00 40 A0 E3 04 20 9D E5 }
	condition:
		$pattern
}

rule getcwd_30d3b2f33310d332282d6d615d2ca9f6 {
	meta:
		aliases = "__GI_getcwd, getcwd"
		size = "232"
		objfiles = "getcwds@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 51 E2 04 D0 4D E2 00 40 A0 E1 0B 00 00 1A 00 00 50 E3 04 00 00 0A ?? ?? ?? ?? 06 40 A0 E1 16 30 A0 E3 00 30 80 E5 2A 00 00 EA ?? ?? ?? ?? 01 0A 50 E3 00 70 A0 A1 01 7A A0 B3 03 00 00 EA 00 00 50 E3 06 70 A0 E1 00 50 A0 11 04 00 00 1A 07 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 1C 00 00 0A 00 50 A0 E1 07 10 A0 E1 05 00 A0 E1 B7 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 70 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 67 E2 00 30 80 E5 0B 00 00 EA 00 00 50 E3 09 00 00 BA 00 00 54 E3 00 00 56 03 03 00 00 1A 00 10 A0 E1 05 00 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 00 00 54 E3 05 40 A0 01 05 00 00 EA 00 00 54 E3 }
	condition:
		$pattern
}

rule __GI_fgets_unlocked_f020f664ca540e925467cf228081e00f {
	meta:
		aliases = "fgets_unlocked, __GI_fgets_unlocked"
		size = "156"
		objfiles = "fgets_unlockeds@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 51 E2 04 D0 4D E2 00 70 A0 E1 02 40 A0 E1 00 50 A0 C1 15 00 00 CA 1A 00 00 EA 10 20 94 E5 18 30 94 E5 03 00 52 E1 04 00 00 2A 01 30 D2 E4 01 30 C5 E4 0A 00 53 E3 10 20 84 E5 0A 00 00 EA 04 00 A0 E1 ?? ?? ?? ?? 01 00 70 E3 FF 30 00 E2 03 00 00 1A B0 30 D4 E1 08 00 13 E3 05 00 00 0A 08 00 00 EA 0A 00 53 E3 01 30 C5 E4 01 00 00 0A 01 60 56 E2 E8 FF FF 1A 07 00 55 E1 00 30 A0 83 00 30 C5 85 00 00 00 8A 00 70 A0 E3 07 00 A0 E1 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule hcreate_r_318c0d2e562cb623d77bc14d15aff97b {
	meta:
		aliases = "__GI_hcreate_r, hcreate_r"
		size = "180"
		objfiles = "hcreate_rs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 51 E2 04 D0 4D E2 04 00 00 1A ?? ?? ?? ?? 16 30 A0 E3 06 10 A0 E1 00 30 80 E5 20 00 00 EA 00 30 96 E5 00 00 53 E3 00 10 A0 13 01 50 80 03 03 70 A0 03 01 00 00 0A 19 00 00 EA 02 50 85 E2 07 40 A0 E1 00 00 00 EA 02 40 84 E2 94 04 03 E0 05 00 53 E1 04 10 A0 E1 05 00 A0 E1 02 00 00 2A ?? ?? ?? ?? 00 00 51 E3 F6 FF FF 1A 04 10 A0 E1 05 00 A0 E1 ?? ?? ?? ?? 00 00 51 E3 EE FF FF 0A 00 30 A0 E3 0C 10 A0 E3 08 30 86 E5 04 50 86 E5 01 00 85 E2 ?? ?? ?? ?? 00 00 86 E5 00 10 50 E2 01 10 A0 13 01 00 A0 E1 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule __GI_xdr_hyper_6abf58dba3a9a0244cfc7feb0074823d {
	meta:
		aliases = "xdr_hyper, __GI_xdr_hyper"
		size = "224"
		objfiles = "xdrs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 90 E5 0C D0 4D E2 00 00 56 E3 00 50 A0 E1 01 70 A0 E1 12 00 00 1A 00 10 91 E5 04 20 97 E5 06 00 8D E8 04 30 90 E5 04 10 8D E2 C2 4F A0 E1 0F E0 A0 E1 04 F0 93 E5 00 00 50 E3 06 00 A0 01 23 00 00 0A 05 00 A0 E1 04 30 95 E5 0D 10 A0 E1 0F E0 A0 E1 04 F0 93 E5 00 00 50 E2 01 00 A0 13 1B 00 00 EA 01 00 56 E3 14 00 00 1A 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 12 00 00 0A 05 00 A0 E1 04 30 95 E5 0D 10 A0 E1 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 0B 00 00 0A 0C 00 9D E8 C3 4F A0 E1 03 40 A0 E1 00 30 A0 E3 02 30 83 E1 06 00 A0 E1 18 00 87 E8 04 00 00 EA 02 00 56 E3 }
	condition:
		$pattern
}

rule xdr_int64_t_d1a8f52ff382b7d2f21047599eadc81e {
	meta:
		aliases = "xdr_int64_t"
		size = "216"
		objfiles = "xdr_intXX_ts@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 90 E5 0C D0 4D E2 01 00 56 E3 00 50 A0 E1 01 70 A0 E1 16 00 00 0A 03 00 00 3A 02 00 56 E3 01 00 A0 03 28 00 00 0A 26 00 00 EA 00 10 91 E5 04 20 97 E5 06 00 8D E8 04 30 90 E5 04 10 8D E2 C2 4F A0 E1 0F E0 A0 E1 24 F0 93 E5 00 00 50 E3 1D 00 00 0A 05 00 A0 E1 04 30 95 E5 0D 10 A0 E1 0F E0 A0 E1 24 F0 93 E5 00 00 50 E2 01 00 A0 13 15 00 00 EA 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 0E 00 00 0A 05 00 A0 E1 04 30 95 E5 0D 10 A0 E1 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 07 00 00 0A 0C 00 9D E8 C3 4F A0 E1 03 40 A0 E1 00 30 A0 E3 02 30 83 E1 06 00 A0 E1 18 00 87 E8 }
	condition:
		$pattern
}

rule __GI_fgetws_unlocked_75d6b01349f5bc10d0fdf3d8d4697295 {
	meta:
		aliases = "fgetws_unlocked, __GI_fgetws_unlocked"
		size = "92"
		objfiles = "fgetws_unlockeds@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 A0 E1 04 D0 4D E2 01 50 A0 E1 02 70 A0 E1 00 40 A0 E1 01 00 55 E3 07 00 A0 E1 01 50 45 E2 05 00 00 DA ?? ?? ?? ?? 01 00 70 E3 02 00 00 0A 0A 00 50 E3 04 00 84 E4 F5 FF FF 1A 06 00 54 E1 00 60 A0 03 00 30 A0 13 06 00 A0 E1 00 30 84 15 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_compare_and_swap_d3674bc197da4c2503f8899432d89b65 {
	meta:
		aliases = "__pthread_compare_and_swap"
		size = "68"
		objfiles = "spinlocks@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 A0 E1 04 D0 4D E2 03 00 A0 E1 03 50 A0 E1 01 40 A0 E1 02 70 A0 E1 7E FF FF EB 00 30 96 E5 04 00 53 E1 00 00 A0 13 00 70 86 05 01 00 A0 03 00 30 A0 E3 00 30 85 E5 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule __GI_sleep_02a915ba83ce997019df82ae6c1d0a06 {
	meta:
		aliases = "sleep, __GI_sleep"
		size = "416"
		objfiles = "sleeps@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 C0 50 E2 67 DF 4D E2 0C 00 A0 01 20 20 A0 13 00 10 A0 13 01 00 00 1A 5C 00 00 EA 88 10 03 E5 01 20 52 E2 66 0F 8D E2 02 31 80 E0 FA FF FF 5A 11 6E 8D E2 00 50 A0 E3 06 00 A0 E1 11 10 A0 E3 90 C1 8D E5 94 51 8D E5 ?? ?? ?? ?? 05 00 50 E1 4D 00 00 BA 90 40 8D E2 05 00 A0 E1 06 10 A0 E1 04 20 A0 E1 ?? ?? ?? ?? 05 00 50 E1 46 00 00 1A 04 00 A0 E1 11 10 A0 E3 ?? ?? ?? ?? 00 00 50 E3 20 30 A0 03 01 00 00 0A 31 00 00 EA 88 00 02 E5 01 30 53 E2 66 1F 8D E2 03 21 81 E0 FA FF FF 5A 11 0E 8D E2 11 10 A0 E3 ?? ?? ?? ?? 00 00 50 E3 35 00 00 BA 11 00 A0 E3 00 10 A0 E3 04 20 8D E2 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdr_pointer_1752510249b16c4fc0016f211ccca8f2 {
	meta:
		aliases = "xdr_pointer"
		size = "104"
		objfiles = "xdr_references@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 C0 91 E5 0C D0 4D E2 00 C0 5C E2 01 C0 A0 13 01 40 A0 E1 08 10 8D E2 04 C0 21 E5 02 60 A0 E1 03 70 A0 E1 00 50 A0 E1 ?? ?? ?? ?? 00 00 50 E3 09 00 00 0A 04 30 9D E5 00 00 53 E3 01 00 A0 03 00 30 84 05 04 00 00 0A 05 00 A0 E1 04 10 A0 E1 06 20 A0 E1 07 30 A0 E1 ?? ?? ?? ?? 0C D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule __GI_vdprintf_92e9c292b60ace5eed539f1589348f20 {
	meta:
		aliases = "vdprintf, __GI_vdprintf"
		size = "148"
		objfiles = "vdprintfs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 01 30 A0 E3 94 D0 4D E2 34 30 8D E5 90 30 8D E2 00 40 A0 E3 04 00 8D E5 01 50 A0 E1 02 60 A0 E1 38 00 8D E2 50 20 8D E2 0C 30 8D E5 D0 30 A0 E3 14 20 8D E5 08 20 8D E5 18 20 8D E5 1C 20 8D E5 10 20 8D E5 B0 30 CD E1 02 40 CD E5 2C 40 8D E5 ?? ?? ?? ?? 05 10 A0 E1 06 20 A0 E1 0D 00 A0 E1 20 40 8D E5 ?? ?? ?? ?? 00 40 50 E2 0D 70 A0 E1 03 00 00 DA 0D 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 40 E0 13 04 00 A0 E1 94 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule ldiv_f5904376ba8f842db7cd16e1b0ebf897 {
	meta:
		aliases = "ldiv"
		size = "88"
		objfiles = "ldivs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 01 40 A0 E1 04 D0 4D E2 02 10 A0 E1 00 70 A0 E1 04 00 A0 E1 02 60 A0 E1 ?? ?? ?? ?? 06 10 A0 E1 00 50 A0 E1 04 00 A0 E1 ?? ?? ?? ?? 00 00 54 E3 02 00 00 BA 00 00 51 E3 01 10 66 B0 01 50 85 B2 07 00 A0 E1 04 10 87 E5 00 50 87 E5 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule __GI_clnt_spcreateerror_5304967ac660e1765a65cf2cf06ebc90 {
	meta:
		aliases = "clnt_spcreateerror, __GI_clnt_spcreateerror"
		size = "296"
		objfiles = "clnt_perrors@libc.a"
	strings:
		$pattern = { F0 40 2D E9 01 DB 4D E2 04 D0 4D E2 00 40 A0 E1 EF FF FF EB 00 51 9F E5 00 70 50 E2 05 50 8F E0 39 00 00 0A ?? ?? ?? ?? F0 10 9F E5 04 20 A0 E1 00 60 A0 E1 01 10 85 E0 07 00 A0 E1 ?? ?? ?? ?? 00 40 87 E0 00 00 96 E5 ?? ?? ?? ?? 00 10 A0 E1 04 00 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 ?? ?? ?? ?? 00 30 96 E5 00 40 84 E0 0C 00 53 E3 10 00 00 0A 0E 00 53 E3 20 00 00 1A A4 10 9F E5 04 00 A0 E1 01 10 85 E0 ?? ?? ?? ?? 04 00 A0 E1 ?? ?? ?? ?? 00 40 84 E0 04 00 96 E5 ?? ?? ?? ?? 00 10 A0 E1 04 00 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 ?? ?? ?? ?? 10 00 00 EA 68 10 9F E5 04 00 A0 E1 01 10 85 E0 ?? ?? ?? ?? 04 00 A0 E1 }
	condition:
		$pattern
}

rule addmntent_2da994508c94e50cab3d520640ddcf60 {
	meta:
		aliases = "addmntent"
		size = "120"
		objfiles = "mntents@libc.a"
	strings:
		$pattern = { F0 40 2D E9 02 20 A0 E3 14 D0 4D E2 01 60 A0 E1 00 10 A0 E3 00 70 A0 E1 ?? ?? ?? ?? 4C 30 9F E5 00 00 50 E3 03 30 8F E0 01 00 A0 B3 0D 00 00 BA 3C 10 9F E5 08 C0 96 E5 0C E0 96 E5 10 40 96 E5 14 50 96 E5 00 20 96 E5 01 10 83 E0 07 00 A0 E1 04 30 96 E5 00 50 8D E8 08 40 8D E5 0C 50 8D E5 ?? ?? ?? ?? A0 0F A0 E1 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __fp_range_check_79519983d3c3deaefc44e2adea52f286 {
	meta:
		aliases = "__fp_range_check"
		size = "164"
		objfiles = "__fp_range_checks@libc.a"
	strings:
		$pattern = { F0 40 2D E9 02 60 A0 E1 04 D0 4D E2 00 20 A0 E3 03 70 A0 E1 84 30 9F E5 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 15 00 00 0A 04 00 A0 E1 05 10 A0 E1 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? ?? 00 00 50 E3 0E 00 00 1A 00 20 A0 E3 38 30 9F E5 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 02 00 00 1A ?? ?? ?? ?? 22 30 A0 E3 00 30 80 E5 04 D0 8D E2 F0 80 BD E8 00 00 D0 3F }
	condition:
		$pattern
}

rule writetcp_862b8815e2aa19aa03a367b1c4bdb503 {
	meta:
		aliases = "writetcp"
		size = "92"
		objfiles = "svc_tcps@libc.a"
	strings:
		$pattern = { F0 40 2D E9 02 60 A0 E1 04 D0 4D E2 00 70 A0 E1 01 50 A0 E1 02 40 A0 E1 09 00 00 EA 00 00 97 E5 ?? ?? ?? ?? 00 00 50 E3 2C 20 97 B5 00 30 A0 B3 00 60 E0 B3 00 30 82 B5 04 00 00 BA 00 50 85 E0 04 40 60 E0 00 20 54 E2 05 10 A0 E1 F2 FF FF CA 06 00 A0 E1 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule __GI_fwrite_unlocked_478de74424515cd59a445ee569b5733d {
	meta:
		aliases = "fwrite_unlocked, __GI_fwrite_unlocked"
		size = "172"
		objfiles = "fwrite_unlockeds@libc.a"
	strings:
		$pattern = { F0 40 2D E9 03 50 A0 E1 B0 30 D3 E1 04 D0 4D E2 C0 30 03 E2 C0 00 53 E3 00 70 A0 E1 01 40 A0 E1 02 60 A0 E1 04 00 00 0A 05 00 A0 E1 80 10 A0 E3 ?? ?? ?? ?? 00 00 50 E3 17 00 00 1A 00 00 54 E3 00 00 56 13 14 00 00 0A 00 00 E0 E3 04 10 A0 E1 ?? ?? ?? ?? 00 00 56 E1 07 00 00 8A 05 20 A0 E1 94 06 01 E0 07 00 A0 E1 ?? ?? ?? ?? 04 10 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 08 00 00 EA B0 30 D5 E1 08 30 83 E3 B0 30 C5 E1 ?? ?? ?? ?? 16 30 A0 E3 00 20 A0 E3 00 30 80 E5 00 00 00 EA 00 20 A0 E3 02 00 A0 E1 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule pthread_rwlock_wrlock_3e1efe78ad15e20c46fe185499d0cec7 {
	meta:
		aliases = "pthread_rwlock_wrlock"
		size = "116"
		objfiles = "rwlocks@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 04 D0 4D E2 00 40 A0 E1 14 70 80 E2 BD FF FF EB 00 50 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 08 30 94 E5 05 10 A0 E1 00 00 53 E3 07 00 A0 E1 02 00 00 1A 0C 60 94 E5 00 00 56 E3 05 00 00 0A 5C FF FF EB 04 00 A0 E1 ?? ?? ?? ?? 05 00 A0 E1 E8 FF FF EB EE FF FF EA 0C 50 84 E5 04 00 A0 E1 ?? ?? ?? ?? 06 00 A0 E1 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule __GI_xprt_register_2381d8fa6b230492925bd6d94a1abefb {
	meta:
		aliases = "xprt_register, __GI_xprt_register"
		size = "276"
		objfiles = "svcs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 04 D0 4D E2 00 50 A0 E1 ?? ?? ?? ?? B4 30 90 E5 00 40 A0 E1 00 00 53 E3 00 70 95 E5 05 00 00 1A ?? ?? ?? ?? 00 01 A0 E1 ?? ?? ?? ?? 00 00 50 E3 B4 00 84 E5 33 00 00 0A ?? ?? ?? ?? 00 00 57 E1 30 00 00 AA B4 30 94 E5 01 0B 57 E3 07 51 83 E7 06 00 00 AA ?? ?? ?? ?? A7 C2 A0 E1 0C 31 90 E7 1F 10 07 E2 01 20 A0 E3 12 31 83 E1 0C 31 80 E7 00 50 A0 E3 0C 00 00 EA ?? ?? ?? ?? 00 20 90 E5 85 11 A0 E1 85 31 92 E7 01 00 73 E3 05 00 00 1A 85 71 82 E7 00 30 90 E5 C3 20 A0 E3 01 30 83 E0 B4 20 C3 E1 17 00 00 EA 01 50 85 E2 ?? ?? ?? ?? 00 40 90 E5 00 60 A0 E1 04 00 55 E1 ED FF FF BA 01 40 84 E2 }
	condition:
		$pattern
}

rule daemon_c22506eefb0a46a2c7dc71fbb37bdf87 {
	meta:
		aliases = "daemon"
		size = "232"
		objfiles = "daemons@libc.a"
	strings:
		$pattern = { F0 40 2D E9 04 D0 4D E2 00 70 A0 E1 01 60 A0 E1 ?? ?? ?? ?? C0 50 9F E5 01 00 70 E3 00 40 A0 E1 05 50 8F E0 27 00 00 0A 00 00 50 E3 00 00 A0 13 06 00 00 1A ?? ?? ?? ?? 01 00 70 E3 21 00 00 0A ?? ?? ?? ?? 00 00 50 E3 01 00 00 0A 04 00 A0 E1 ?? ?? ?? ?? 00 00 57 E3 02 00 00 1A 7C 00 9F E5 00 00 85 E0 ?? ?? ?? ?? 00 00 56 E3 17 00 00 1A 6C 00 9F E5 02 10 A0 E3 00 00 85 E0 06 20 A0 E1 ?? ?? ?? ?? 01 00 70 E3 00 40 A0 E1 0F 00 00 0A 06 10 A0 E1 ?? ?? ?? ?? 01 10 A0 E3 04 00 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 02 10 A0 E3 ?? ?? ?? ?? 02 00 54 E3 05 00 00 DA 04 00 A0 E1 ?? ?? ?? ?? 06 00 A0 E1 02 00 00 EA }
	condition:
		$pattern
}

rule cabsf_31aab55712476cffcff1033dc1e454d7 {
	meta:
		aliases = "cargf, cabsf"
		size = "72"
		objfiles = "cargfs@libm.a, cabsfs@libm.a"
	strings:
		$pattern = { F0 40 2D E9 04 D0 4D E2 01 40 A0 E1 ?? ?? ?? ?? 00 60 A0 E1 04 00 A0 E1 01 70 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 00 40 A0 E1 01 50 A0 E1 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule __GI_fdim_d7183421a3ecbc787359df4ac90fa308 {
	meta:
		aliases = "fdim, __GI_fdim"
		size = "112"
		objfiles = "s_fdims@libm.a"
	strings:
		$pattern = { F0 40 2D E9 04 D0 4D E2 01 50 A0 E1 02 60 A0 E1 03 70 A0 E1 00 40 A0 E1 ?? ?? ?? ?? 01 00 50 E3 00 00 A0 93 40 10 9F 95 0D 00 00 9A 05 10 A0 E1 04 00 A0 E1 06 20 A0 E1 07 30 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 00 A0 03 00 10 A0 03 04 00 00 0A 04 00 A0 E1 05 10 A0 E1 06 20 A0 E1 07 30 A0 E1 ?? ?? ?? ?? 04 D0 8D E2 F0 80 BD E8 00 00 F0 7F }
	condition:
		$pattern
}

rule fmax_4a7bbf26e7c033370107f8588fff98ae {
	meta:
		aliases = "fmin, __GI_fmin, __GI_fmax, fmax"
		size = "108"
		objfiles = "s_fmaxs@libm.a, s_fmins@libm.a"
	strings:
		$pattern = { F0 40 2D E9 04 D0 4D E2 02 40 A0 E1 03 50 A0 E1 00 60 A0 E1 01 70 A0 E1 ?? ?? ?? ?? 00 00 50 E3 0D 00 00 0A 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 06 00 00 0A 06 00 A0 E1 07 10 A0 E1 04 20 A0 E1 05 30 A0 E1 ?? ?? ?? ?? 00 00 50 E3 01 00 00 1A 04 60 A0 E1 05 70 A0 E1 06 00 A0 E1 07 10 A0 E1 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule __ieee754_scalb_00547197184718ec778e4dc0d106915f {
	meta:
		aliases = "__ieee754_scalb"
		size = "356"
		objfiles = "e_scalbs@libm.a"
	strings:
		$pattern = { F0 40 2D E9 04 D0 4D E2 02 40 A0 E1 03 50 A0 E1 00 60 A0 E1 01 70 A0 E1 ?? ?? ?? ?? 00 00 50 E3 10 00 00 1A 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 0B 00 00 1A 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 11 00 00 1A 04 00 A0 E1 05 10 A0 E1 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? ?? 00 00 50 E3 05 00 00 0A 06 00 A0 E1 07 10 A0 E1 04 20 A0 E1 05 30 A0 E1 ?? ?? ?? ?? 32 00 00 EA 04 20 A0 E1 02 31 85 E2 06 00 A0 E1 07 10 A0 E1 0E 00 00 EA 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 04 20 A0 E1 05 30 A0 E1 ?? ?? ?? ?? 00 00 50 E3 08 00 00 1A 04 20 A0 E1 05 30 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule erand48_r_a0844169a28c111916947e9622c3e262 {
	meta:
		aliases = "__GI_erand48_r, erand48_r"
		size = "136"
		objfiles = "erand48_rs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 04 D0 4D E2 02 70 A0 E1 00 60 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 40 A0 E3 00 50 A0 E3 00 00 E0 B3 14 00 00 BA 02 51 C5 E3 01 31 C5 E3 B4 10 D6 E1 B2 00 D6 E1 FF 35 83 E3 03 56 83 E3 01 12 A0 E1 B0 20 D6 E1 20 16 81 E1 25 3A A0 E1 01 36 83 E1 02 22 A0 E1 63 56 A0 E1 00 4A 82 E1 04 00 A0 E1 05 10 A0 E1 00 20 A0 E3 10 30 9F E5 ?? ?? ?? ?? 03 00 87 E8 00 00 A0 E3 04 D0 8D E2 F0 80 BD E8 00 00 F0 3F }
	condition:
		$pattern
}

rule __pthread_reset_main_thread_6586577b220809f541d0dc3038897a3f {
	meta:
		aliases = "__pthread_reset_main_thread"
		size = "208"
		objfiles = "pthreads@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 04 D0 4D E2 18 FF FF EB 9C 60 9F E5 9C 30 9F E5 06 60 8F E0 03 70 96 E7 00 50 A0 E1 00 30 97 E5 01 00 73 E3 11 00 00 0A 84 30 9F E5 03 40 96 E7 00 00 94 E5 ?? ?? ?? ?? 78 30 9F E5 00 20 A0 E3 03 30 96 E7 00 20 84 E5 00 20 83 E5 00 00 97 E5 ?? ?? ?? ?? 60 30 9F E5 03 40 96 E7 00 00 94 E5 ?? ?? ?? ?? 00 30 E0 E3 00 30 87 E5 00 30 84 E5 ?? ?? ?? ?? 44 30 9F E5 14 00 85 E5 03 10 96 E7 3C 30 9F E5 00 50 81 E5 03 20 96 E7 34 30 9F E5 4C 20 85 E5 03 30 96 E7 00 50 85 E5 44 30 85 E5 04 50 85 E5 04 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __fixunssfdi_8b26bd8dd538106d96d21ba44787210b {
	meta:
		aliases = "__aeabi_f2ulz, __fixunssfdi"
		size = "112"
		objfiles = "_fixunssfdi@libgcc.a"
	strings:
		$pattern = { F0 40 2D E9 04 D0 4D E2 ?? ?? ?? ?? 00 20 A0 E3 50 30 9F E5 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? 00 60 A0 E1 ?? ?? ?? ?? 00 20 A0 E3 34 30 9F E5 ?? ?? ?? ?? 04 20 A0 E1 05 30 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? 00 70 A0 E3 06 70 A0 E1 00 10 A0 E3 00 60 A0 E3 06 00 80 E1 07 10 81 E1 04 D0 8D E2 F0 80 BD E8 00 00 F0 3D 00 00 F0 C1 }
	condition:
		$pattern
}

rule recv_182a055191d3009d3fb7eb9eab57946c {
	meta:
		aliases = "pread, pwrite, send, recv"
		size = "84"
		objfiles = "wrapsyscalls@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 0C D0 4D E2 00 40 A0 E1 01 50 A0 E1 02 60 A0 E1 03 70 A0 E1 04 10 8D E2 01 00 A0 E3 ?? ?? ?? ?? 05 10 A0 E1 06 20 A0 E1 07 30 A0 E1 04 00 A0 E1 ?? ?? ?? ?? 00 10 A0 E3 00 40 A0 E1 04 00 9D E5 ?? ?? ?? ?? 04 00 A0 E1 0C D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule unlockpt_72d59dd87b48b3d2488ef4405725d505 {
	meta:
		aliases = "unlockpt"
		size = "88"
		objfiles = "unlockpts@libc.a"
	strings:
		$pattern = { F0 40 2D E9 0C D0 4D E2 00 40 A0 E1 ?? ?? ?? ?? 00 70 A0 E3 08 20 8D E2 00 60 90 E5 00 50 A0 E1 04 70 22 E5 04 00 A0 E1 24 10 9F E5 ?? ?? ?? ?? 00 00 50 E3 04 00 00 0A 00 30 95 E5 16 00 53 E3 00 00 E0 13 00 60 85 05 07 00 A0 01 0C D0 8D E2 F0 80 BD E8 31 54 04 40 }
	condition:
		$pattern
}

rule __libc_lseek64_eb7b44327281505fdc292995fc2e32d5 {
	meta:
		aliases = "__GI_lseek64, lseek64, __libc_lseek64"
		size = "100"
		objfiles = "llseeks@libc.a"
	strings:
		$pattern = { F0 40 2D E9 0C D0 4D E2 03 60 A0 E1 03 10 A0 E1 02 50 A0 E1 20 40 9D E5 0D 30 A0 E1 8C 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 04 00 00 9A ?? ?? ?? ?? 00 30 64 E2 00 20 E0 E3 00 30 80 E5 01 00 00 EA 00 20 50 E2 02 00 00 0A 02 00 A0 E1 C0 1F A0 E1 00 00 00 EA 03 00 9D E8 0C D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule svc_unregister_5d25ca0aaabdae81a0764d4ff905645f {
	meta:
		aliases = "__GI_svc_unregister, svc_unregister"
		size = "96"
		objfiles = "svcs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 0C D0 4D E2 04 20 8D E2 00 60 A0 E1 01 70 A0 E1 46 FF FF EB 00 40 50 E2 0D 00 00 0A 04 30 9D E5 00 50 94 E5 00 00 53 E3 00 50 83 15 01 00 00 1A ?? ?? ?? ?? B8 50 80 E5 00 30 A0 E3 04 00 A0 E1 00 30 84 E5 ?? ?? ?? ?? 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? ?? 0C D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule __fresetlockfiles_720a0db22a0b6154aae5b1999bd6d68a {
	meta:
		aliases = "__fresetlockfiles"
		size = "116"
		objfiles = "lockfiles@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 0C D0 4D E2 04 40 8D E2 04 00 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 01 10 A0 E3 ?? ?? ?? ?? 40 60 9F E5 40 30 9F E5 06 60 8F E0 03 30 96 E7 38 70 9F E5 00 50 93 E5 02 00 00 EA 0F E0 A0 E1 07 F0 96 E7 20 50 95 E5 00 00 55 E3 38 00 85 E2 04 10 A0 E1 F8 FF FF 1A 04 00 A0 E1 ?? ?? ?? ?? 0C D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule lsearch_48f9a98293e1cfef6b0e137f6acf3adc {
	meta:
		aliases = "lsearch"
		size = "84"
		objfiles = "lsearchs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 0C D0 4D E2 20 C0 9D E5 00 70 A0 E1 00 C0 8D E5 01 60 A0 E1 02 40 A0 E1 03 50 A0 E1 ?? ?? ?? ?? 00 00 50 E3 07 00 00 1A 00 30 94 E5 07 10 A0 E1 93 65 20 E0 05 20 A0 E1 ?? ?? ?? ?? 00 30 94 E5 01 30 83 E2 00 30 84 E5 0C D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_timedsuspend_new_d54e91e75d830dba52906415346321c1 {
	meta:
		aliases = "__pthread_timedsuspend_new"
		size = "296"
		objfiles = "pthreads@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 10 21 9F E5 AB DF 4D E2 02 20 8F E0 0C 00 8D E5 04 20 8D E5 08 10 8D E5 10 00 8D E2 01 10 A0 E3 ?? ?? ?? ?? 00 00 50 E3 01 00 A0 13 34 00 00 1A 0C E0 9D E5 86 4F 8D E2 10 30 8D E2 24 30 8E E5 20 00 8E E5 04 00 A0 E1 ?? ?? ?? ?? C8 30 9F E5 04 20 9D E5 04 00 A0 E1 03 30 92 E7 BC 70 9F E5 00 10 93 E5 ?? ?? ?? ?? 04 10 A0 E1 01 00 A0 E3 66 2F 8D E2 ?? ?? ?? ?? FA 5F A0 E3 2A 6E 8D E2 A6 4F 8D E2 00 10 A0 E3 06 00 A0 E1 ?? ?? ?? ?? 08 30 9D E5 08 E0 9D E5 04 C0 93 E5 A4 32 9D E5 00 20 9E E5 95 03 03 E0 0C C0 63 E0 A0 32 9D E5 00 10 A0 E3 02 30 63 E0 01 00 5C E1 98 32 8D E5 01 30 43 B2 }
	condition:
		$pattern
}

rule __GI_opendir_c386254047311d17ab05390b03582325 {
	meta:
		aliases = "opendir, __GI_opendir"
		size = "268"
		objfiles = "opendirs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 12 1B A0 E3 5C D0 4D E2 ?? ?? ?? ?? EC 50 9F E5 00 70 50 E2 05 50 8F E0 00 60 A0 B3 34 00 00 BA 0D 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 05 00 00 BA 07 00 A0 E1 02 10 A0 E3 01 20 A0 E3 ?? ?? ?? ?? 00 00 50 E3 07 00 00 AA ?? ?? ?? ?? 00 50 A0 E1 07 00 A0 E1 00 40 95 E5 ?? ?? ?? ?? 00 60 A0 E3 00 40 85 E5 22 00 00 EA 30 00 A0 E3 ?? ?? ?? ?? 00 00 50 E3 12 00 00 0A 00 40 A0 E3 10 40 80 E5 30 30 9D E5 00 60 A0 E1 02 0C 53 E3 14 30 80 E5 02 3C A0 33 14 30 80 35 00 70 80 E5 08 40 80 E5 04 40 80 E5 14 10 96 E5 01 00 A0 E3 ?? ?? ?? ?? 00 00 50 E3 0C 00 86 E5 08 00 00 1A 06 00 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule recvfrom_f325aaf9ab9ec8c8bca1f8fa92eb442c {
	meta:
		aliases = "sendto, recvfrom"
		size = "100"
		objfiles = "wrapsyscalls@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 14 D0 4D E2 00 70 A0 E1 01 40 A0 E1 01 00 A0 E3 0C 10 8D E2 02 50 A0 E1 03 60 A0 E1 ?? ?? ?? ?? 28 C0 9D E5 04 10 A0 E1 00 C0 8D E5 2C C0 9D E5 05 20 A0 E1 06 30 A0 E1 07 00 A0 E1 04 C0 8D E5 ?? ?? ?? ?? 00 10 A0 E3 00 40 A0 E1 0C 00 9D E5 ?? ?? ?? ?? 04 00 A0 E1 14 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule pthread_cond_wait_f5f30470641f2988dc6ca3885c786b8d {
	meta:
		aliases = "__GI_pthread_cond_wait, pthread_cond_wait"
		size = "424"
		objfiles = "condvars@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 14 D0 4D E2 01 70 A0 E1 00 50 A0 E1 39 FF FF EB 0C 30 97 E5 78 61 9F E5 03 00 53 E3 00 00 53 13 0C 00 8D E5 06 60 8F E0 04 00 00 0A 0C 20 9D E5 08 30 97 E5 02 00 53 E1 16 00 A0 13 52 00 00 1A 50 31 9F E5 0C 20 9D E5 03 30 86 E0 08 30 8D E5 00 30 A0 E3 04 50 8D E5 B9 31 C2 E5 0C 00 9D E5 04 10 8D E2 F5 FE FF EB 05 00 A0 E1 0C 10 9D E5 ?? ?? ?? ?? 0C 30 9D E5 42 30 D3 E5 00 00 53 E3 04 00 00 0A 0C 30 9D E5 40 30 D3 E5 00 00 53 E3 01 40 A0 03 03 00 00 0A 0C 10 9D E5 08 00 85 E2 B1 FE FF EB 00 40 A0 E3 05 00 A0 E1 ?? ?? ?? ?? 00 00 54 E3 03 00 00 0A 0C 00 9D E5 00 10 A0 E3 DE FE FF EB }
	condition:
		$pattern
}

rule gethostbyaddr_f3a5d490d77c9aea2e76250e067f1ca5 {
	meta:
		aliases = "__GI_gethostbyaddr, gethostbyaddr"
		size = "112"
		objfiles = "gethostbyaddrs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 1C D0 4D E2 00 50 A0 E1 01 60 A0 E1 02 70 A0 E1 ?? ?? ?? ?? 44 40 9F E5 44 C0 9F E5 04 40 8F E0 0C C0 84 E0 3C 30 9F E5 00 C0 8D E5 76 CF A0 E3 0C 00 8D E5 04 C0 8D E5 03 30 84 E0 14 C0 8D E2 05 00 A0 E1 06 10 A0 E1 07 20 A0 E1 08 C0 8D E5 ?? ?? ?? ?? 14 00 9D E5 1C D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule if_indextoname_b3992c2d223756ee17f077a32498541c {
	meta:
		aliases = "if_indextoname"
		size = "136"
		objfiles = "if_indexs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 24 D0 4D E2 00 50 A0 E1 01 60 A0 E1 ?? ?? ?? ?? 00 40 50 E2 00 00 A0 B3 16 00 00 BA 5C 10 9F E5 0D 20 A0 E1 10 50 8D E5 ?? ?? ?? ?? 00 00 50 E3 0D 70 A0 E1 09 00 00 AA ?? ?? ?? ?? 00 50 A0 E1 04 00 A0 E1 00 40 95 E5 ?? ?? ?? ?? 13 00 54 E3 06 40 A0 03 00 00 A0 E3 00 40 85 E5 05 00 00 EA 04 00 A0 E1 ?? ?? ?? ?? 06 00 A0 E1 0D 10 A0 E1 10 20 A0 E3 ?? ?? ?? ?? 24 D0 8D E2 F0 80 BD E8 10 89 00 00 }
	condition:
		$pattern
}

rule putc_b65f605582c6a0ab8dce3817ccd6e789 {
	meta:
		aliases = "fputc, __GI_putc, __GI_fputc, putc"
		size = "228"
		objfiles = "fputcs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 30 91 E5 C0 60 9F E5 00 00 53 E3 06 60 8F E0 14 D0 4D E2 01 50 A0 E1 00 70 A0 E1 0A 00 00 0A 10 20 91 E5 1C 30 91 E5 03 00 52 E1 FF 30 00 32 01 30 C2 34 03 40 A0 31 10 20 81 35 1F 00 00 3A ?? ?? ?? ?? 00 40 A0 E1 1C 00 00 EA 7C 30 9F E5 38 40 81 E2 04 20 A0 E1 03 10 96 E7 0D 00 A0 E1 6C 30 9F E5 0F E0 A0 E1 03 F0 96 E7 64 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 96 E7 10 20 95 E5 1C 30 95 E5 03 00 52 E1 FF 30 07 32 01 30 C2 34 03 40 A0 31 10 20 85 35 03 00 00 3A 07 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 }
	condition:
		$pattern
}

rule feof_d1946ba5837e0049ce5ba2414a856761 {
	meta:
		aliases = "feof"
		size = "144"
		objfiles = "feofs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 70 90 E5 6C 50 9F E5 00 00 57 E3 14 D0 4D E2 00 60 A0 E1 05 50 8F E0 0B 00 00 1A 58 30 9F E5 38 40 80 E2 03 10 95 E7 0D 00 A0 E1 4C 30 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 3C 30 9F E5 0F E0 A0 E1 03 F0 95 E7 00 00 57 E3 B0 40 D6 E1 04 00 00 1A 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 95 E7 04 00 04 E2 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ferror_721984af8b5affcda7fb866fbfa089a1 {
	meta:
		aliases = "ferror"
		size = "144"
		objfiles = "ferrors@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 70 90 E5 6C 50 9F E5 00 00 57 E3 14 D0 4D E2 00 60 A0 E1 05 50 8F E0 0B 00 00 1A 58 30 9F E5 38 40 80 E2 03 10 95 E7 0D 00 A0 E1 4C 30 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 3C 30 9F E5 0F E0 A0 E1 03 F0 95 E7 00 00 57 E3 B0 40 D6 E1 04 00 00 1A 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 95 E7 08 00 04 E2 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clearerr_15825f3660f578cea8c3fe51c84e1570 {
	meta:
		aliases = "clearerr"
		size = "148"
		objfiles = "clearerrs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 70 90 E5 70 50 9F E5 00 00 57 E3 14 D0 4D E2 00 60 A0 E1 05 50 8F E0 0B 00 00 1A 5C 30 9F E5 38 40 80 E2 03 10 95 E7 0D 00 A0 E1 50 30 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 40 30 9F E5 0F E0 A0 E1 03 F0 95 E7 B0 30 D6 E1 00 00 57 E3 0C 30 C3 E3 B0 30 C6 E1 04 00 00 1A 0D 00 A0 E1 01 10 A0 E3 1C 30 9F E5 0F E0 A0 E1 03 F0 95 E7 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fileno_b722210ab1ecb9930c33941edc3e7d04 {
	meta:
		aliases = "__GI_fileno, __GI_fgetwc, fgetwc, getwc, fileno"
		size = "152"
		objfiles = "filenos@libc.a, fgetwcs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 70 90 E5 74 50 9F E5 00 00 57 E3 14 D0 4D E2 00 60 A0 E1 05 50 8F E0 0B 00 00 1A 60 30 9F E5 38 40 80 E2 03 10 95 E7 0D 00 A0 E1 54 30 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 44 30 9F E5 0F E0 A0 E1 03 F0 95 E7 06 00 A0 E1 ?? ?? ?? ?? 00 00 57 E3 00 40 A0 E1 04 00 00 1A 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule rewind_8a8815f193040cfc609ada375c9863f3 {
	meta:
		aliases = "__GI_rewind, rewind"
		size = "164"
		objfiles = "rewinds@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 70 90 E5 80 60 9F E5 00 00 57 E3 14 D0 4D E2 00 50 A0 E1 06 60 8F E0 0B 00 00 1A 6C 30 9F E5 38 40 80 E2 03 10 96 E7 0D 00 A0 E1 60 30 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 50 30 9F E5 0F E0 A0 E1 03 F0 96 E7 B0 30 D5 E1 00 10 A0 E3 08 30 C3 E3 B0 30 C5 E1 05 00 A0 E1 01 20 A0 E1 ?? ?? ?? ?? 00 00 57 E3 04 00 00 1A 0D 00 A0 E1 01 10 A0 E3 1C 30 9F E5 0F E0 A0 E1 03 F0 96 E7 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ftello64_77002f256829502bef98803308d8ef52 {
	meta:
		aliases = "__GI_ftello64, ftello64"
		size = "240"
		objfiles = "ftello64s@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 70 90 E5 CC 60 9F E5 1C D0 4D E2 00 00 57 E3 00 30 A0 E3 00 40 A0 E3 10 30 8D E5 14 40 8D E5 00 50 A0 E1 06 60 8F E0 0B 00 00 1A A8 30 9F E5 38 40 80 E2 03 10 96 E7 0D 00 A0 E1 9C 30 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 8C 30 9F E5 0F E0 A0 E1 03 F0 96 E7 B0 20 D5 E1 10 40 8D E2 11 2D 02 E2 11 0D 52 E3 01 20 A0 13 02 20 A0 03 05 00 A0 E1 04 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 04 00 00 BA 05 00 A0 E1 04 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 03 00 00 AA 00 30 E0 E3 00 40 E0 E3 10 30 8D E5 14 40 8D E5 00 00 57 E3 04 00 00 1A 0D 00 A0 E1 01 10 A0 E3 24 30 9F E5 0F E0 A0 E1 }
	condition:
		$pattern
}

rule ether_ntoa_r_e6916edb99cdc7f5f3ba1c10e825dcca {
	meta:
		aliases = "__GI_ether_ntoa_r, ether_ntoa_r"
		size = "88"
		objfiles = "ether_addrs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 44 C0 9F E5 01 60 A0 E1 40 10 9F E5 05 70 D0 E5 02 E0 D0 E5 03 40 D0 E5 04 50 D0 E5 0C C0 8F E0 00 20 D0 E5 01 30 D0 E5 14 D0 4D E2 01 10 8C E0 06 00 A0 E1 00 E0 8D E5 B0 00 8D E9 ?? ?? ?? ?? 06 00 A0 E1 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_tanh_f147a086116cd7174a9c61b3cfd6849b {
	meta:
		aliases = "tanh, __GI_tanh"
		size = "368"
		objfiles = "s_tanhs@libm.a"
	strings:
		$pattern = { F0 40 2D E9 54 31 9F E5 02 21 C1 E3 03 00 52 E1 04 D0 4D E2 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 01 70 A0 E1 13 00 00 DA 00 00 51 E3 08 00 00 BA 00 20 A0 E1 01 30 A0 E1 00 00 A0 E3 20 11 9F E5 ?? ?? ?? ?? 00 20 A0 E3 14 31 9F E5 ?? ?? ?? ?? 40 00 00 EA 00 20 A0 E1 01 30 A0 E1 00 00 A0 E3 FC 10 9F E5 ?? ?? ?? ?? 00 20 A0 E3 F0 30 9F E5 ?? ?? ?? ?? 37 00 00 EA E8 30 9F E5 03 00 52 E1 00 00 A0 C3 D8 10 9F C5 2D 00 00 CA F2 05 52 E3 08 00 00 AA 00 20 A0 E3 C4 30 9F E5 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 05 00 A0 E1 06 10 A0 E1 ?? ?? ?? ?? 27 00 00 EA AC 30 9F E5 03 00 52 E1 10 00 00 DA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_initialize_manager_26b6b4292b8c9663c893530053d11f7e {
	meta:
		aliases = "__pthread_initialize_manager"
		size = "684"
		objfiles = "pthreads@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 58 62 9F E5 58 32 9F E5 06 60 8F E0 03 30 96 E7 A4 D0 4D E2 00 20 93 E5 48 32 9F E5 00 00 52 E3 03 10 96 E7 01 30 A0 E3 00 30 81 E5 00 00 00 1A 6E FF FF EB 30 32 9F E5 03 40 96 E7 00 00 94 E5 80 00 A0 E1 20 00 40 E2 ?? ?? ?? ?? 1C 32 9F E5 00 00 50 E3 03 50 96 E7 00 00 85 E5 00 00 E0 03 7C 00 00 0A 08 32 9F E5 00 20 94 E5 03 70 96 E7 20 30 40 E2 82 30 83 E0 98 00 8D E2 00 30 87 E5 ?? ?? ?? ?? 01 00 70 E3 00 40 A0 E1 03 00 00 1A 00 00 95 E5 ?? ?? ?? ?? 04 00 A0 E1 6D 00 00 EA D0 31 9F E5 03 30 96 E7 00 20 93 E5 00 00 52 E3 C4 31 9F 15 03 30 96 17 9C 21 83 15 B8 31 9F E5 03 20 96 E7 }
	condition:
		$pattern
}

rule getnetbyaddr_6228aa89a4d18e77d066c30d1953defe {
	meta:
		aliases = "getnetbyaddr"
		size = "116"
		objfiles = "getnetbyads@libc.a"
	strings:
		$pattern = { F0 40 2D E9 60 50 9F E5 60 30 9F E5 05 50 8F E0 00 70 A0 E1 04 D0 4D E2 03 00 95 E7 01 60 A0 E1 ?? ?? ?? ?? 05 00 00 EA 08 30 94 E5 06 00 53 E1 02 00 00 1A 0C 30 94 E5 07 00 53 E1 02 00 00 0A ?? ?? ?? ?? 00 40 50 E2 F6 FF FF 1A 1C 30 9F E5 03 30 95 E7 00 00 53 E3 00 00 00 1A ?? ?? ?? ?? 04 00 A0 E1 04 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule psignal_cbcadb25ebc083a568b6879da35bc5e7 {
	meta:
		aliases = "psignal"
		size = "128"
		objfiles = "psignals@libc.a"
	strings:
		$pattern = { F0 40 2D E9 64 50 9F E5 00 60 51 E2 0C D0 4D E2 05 50 8F E0 04 00 00 0A 00 30 D6 E5 00 00 53 E3 4C 30 9F 15 03 70 85 10 03 00 00 1A 40 30 9F E5 03 30 85 E0 02 70 83 E2 07 60 A0 E1 34 30 9F E5 03 30 95 E7 00 40 93 E5 ?? ?? ?? ?? 28 10 9F E5 00 00 8D E5 01 10 85 E0 04 00 A0 E1 06 20 A0 E1 07 30 A0 E1 ?? ?? ?? ?? 0C D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI___dl_iterate_phdr_f7c54c48551428e0bf5c34bace7ce42b {
	meta:
		aliases = "__dl_iterate_phdr, __GI___dl_iterate_phdr"
		size = "128"
		objfiles = "dl_iterate_phdrs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 6C 30 9F E5 6C 20 9F E5 03 30 8F E0 02 20 93 E7 14 D0 4D E2 00 40 92 E5 00 60 A0 E1 01 50 A0 E1 00 C0 A0 E3 0D 70 A0 E1 09 00 00 EA 08 10 94 E8 D0 E0 94 E5 00 30 8D E5 BC 3C D4 E1 00 50 8D E9 BC 30 CD E1 36 FF 2F E1 00 C0 50 E2 05 00 00 1A 0C 40 94 E5 00 00 54 E3 0D 00 A0 E1 10 10 A0 E3 05 20 A0 E1 F0 FF FF 1A 0C 00 A0 E1 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sethostent_3342333a3218a8120797f2bda50b8f72 {
	meta:
		aliases = "sethostent"
		size = "148"
		objfiles = "gethostents@libc.a"
	strings:
		$pattern = { F0 40 2D E9 6C 40 9F E5 6C 50 9F E5 04 40 8F E0 68 30 9F E5 14 D0 4D E2 05 50 84 E0 03 10 94 E7 05 20 A0 E1 00 60 A0 E1 54 30 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 94 E7 05 00 A0 E1 44 30 9F E5 0F E0 A0 E1 03 F0 94 E7 3C 30 9F E5 00 60 56 E2 01 60 A0 13 03 60 84 E7 0D 00 A0 E1 01 10 A0 E3 28 30 9F E5 0D 70 A0 E1 0F E0 A0 E1 03 F0 94 E7 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_getutid_9bce1fb20f7bb40db5dd98d26c5f3e98 {
	meta:
		aliases = "getutid, __GI_getutid"
		size = "144"
		objfiles = "utents@libc.a"
	strings:
		$pattern = { F0 40 2D E9 6C 40 9F E5 6C 50 9F E5 04 40 8F E0 68 30 9F E5 14 D0 4D E2 05 50 84 E0 03 10 94 E7 05 20 A0 E1 00 60 A0 E1 54 30 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 94 E7 48 30 9F E5 05 00 A0 E1 0F E0 A0 E1 03 F0 94 E7 06 00 A0 E1 8E FF FF EB 01 10 A0 E3 00 50 A0 E1 2C 30 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 94 E7 0D 70 A0 E1 05 00 A0 E1 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule srandom_d33704ef6026bc65a92d4bddf4727183 {
	meta:
		aliases = "srand, srandom"
		size = "148"
		objfiles = "randoms@libc.a"
	strings:
		$pattern = { F0 40 2D E9 6C 40 9F E5 6C 50 9F E5 04 40 8F E0 68 30 9F E5 14 D0 4D E2 05 50 84 E0 03 10 94 E7 05 20 A0 E1 00 60 A0 E1 54 30 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 94 E7 48 30 9F E5 05 00 A0 E1 0F E0 A0 E1 03 F0 94 E7 3C 10 9F E5 06 00 A0 E1 01 10 84 E0 ?? ?? ?? ?? 0D 00 A0 E1 01 10 A0 E3 28 30 9F E5 0D 70 A0 E1 0F E0 A0 E1 03 F0 94 E7 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule strcasestr_c52b3afc11dfffc7bc438f2a9e35996c {
	meta:
		aliases = "__GI_strcasestr, strcasestr"
		size = "132"
		objfiles = "strcasestrs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 70 50 9F E5 00 40 A0 E1 01 60 A0 E1 68 70 9F E5 00 E0 A0 E1 01 C0 A0 E1 05 50 8F E0 00 30 DC E5 01 C0 8C E2 00 00 53 E3 83 10 A0 E1 01 00 00 1A 04 00 A0 E1 F0 80 BD E8 00 00 DE E5 01 E0 8E E2 00 00 53 E1 80 20 A0 E1 F3 FF FF 0A 07 30 95 E7 F3 20 92 E1 F3 30 91 E1 02 00 53 E1 EE FF FF 0A 01 40 84 E2 00 00 50 E3 04 E0 A0 E1 06 C0 A0 E1 E9 FF FF 1A F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule endpwent_020fea2f2e73c2e8031776f8b3639b24 {
	meta:
		aliases = "endgrent, endspent, endpwent"
		size = "156"
		objfiles = "getpwent_rs@libc.a, getgrent_rs@libc.a, getspent_rs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 74 50 9F E5 74 40 9F E5 05 50 8F E0 70 30 9F E5 14 D0 4D E2 04 40 85 E0 03 10 95 E7 04 20 A0 E1 0D 00 A0 E1 5C 30 9F E5 5C 60 9F E5 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 50 30 9F E5 0F E0 A0 E1 03 F0 95 E7 06 00 95 E7 0D 70 A0 E1 00 00 50 E3 02 00 00 0A ?? ?? ?? ?? 00 30 A0 E3 06 30 85 E7 0D 00 A0 E1 01 10 A0 E3 24 30 9F E5 0F E0 A0 E1 03 F0 95 E7 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule endutent_51b71a34a77c97ae4383b9faf2049d86 {
	meta:
		aliases = "endutent"
		size = "156"
		objfiles = "utents@libc.a"
	strings:
		$pattern = { F0 40 2D E9 74 50 9F E5 74 40 9F E5 05 50 8F E0 70 30 9F E5 14 D0 4D E2 04 40 85 E0 03 10 95 E7 04 20 A0 E1 0D 00 A0 E1 5C 30 9F E5 5C 60 9F E5 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 50 30 9F E5 0F E0 A0 E1 03 F0 95 E7 06 00 95 E7 0D 70 A0 E1 01 00 70 E3 00 00 00 0A ?? ?? ?? ?? 00 30 E0 E3 06 30 85 E7 0D 00 A0 E1 01 10 A0 E3 24 30 9F E5 0F E0 A0 E1 03 F0 95 E7 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule rewinddir_7f59c51038ea142ff2e23de0c7eea921 {
	meta:
		aliases = "rewinddir"
		size = "152"
		objfiles = "rewinddirs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 78 40 9F E5 78 30 9F E5 14 D0 4D E2 04 40 8F E0 18 60 80 E2 00 50 A0 E1 03 10 94 E7 06 20 A0 E1 0D 00 A0 E1 5C 30 9F E5 0F E0 A0 E1 03 F0 94 E7 54 30 9F E5 06 00 A0 E1 0F E0 A0 E1 03 F0 94 E7 00 10 A0 E3 01 20 A0 E1 00 00 95 E5 ?? ?? ?? ?? 00 30 A0 E3 10 30 85 E5 08 30 85 E5 04 30 85 E5 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0D 70 A0 E1 0F E0 A0 E1 03 F0 94 E7 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule endhostent_7044952bd82e2b3cf530b6efa80a7fc6 {
	meta:
		aliases = "endhostent"
		size = "168"
		objfiles = "gethostents@libc.a"
	strings:
		$pattern = { F0 40 2D E9 7C 50 9F E5 7C 40 9F E5 05 50 8F E0 78 30 9F E5 14 D0 4D E2 04 40 85 E0 03 10 95 E7 04 20 A0 E1 0D 00 A0 E1 64 30 9F E5 64 60 9F E5 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 58 30 9F E5 0F E0 A0 E1 03 F0 95 E7 06 00 95 E7 4C 30 9F E5 00 40 A0 E3 00 00 50 E3 0D 70 A0 E1 03 40 85 E7 01 00 00 0A ?? ?? ?? ?? 06 40 85 E7 0D 00 A0 E1 01 10 A0 E3 28 30 9F E5 0F E0 A0 E1 03 F0 95 E7 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule endnetent_a3dc7aa414448ddf58890e26638755c6 {
	meta:
		aliases = "__GI_endprotoent, endservent, __GI_endservent, __GI_endnetent, endprotoent, endnetent"
		size = "172"
		objfiles = "getnetents@libc.a, getservices@libc.a, getprotos@libc.a"
	strings:
		$pattern = { F0 40 2D E9 80 50 9F E5 80 40 9F E5 05 50 8F E0 7C 30 9F E5 14 D0 4D E2 04 40 85 E0 03 10 95 E7 04 20 A0 E1 0D 00 A0 E1 68 30 9F E5 68 60 9F E5 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 5C 30 9F E5 0F E0 A0 E1 03 F0 95 E7 06 00 95 E7 0D 70 A0 E1 00 00 50 E3 02 00 00 0A ?? ?? ?? ?? 00 30 A0 E3 06 30 85 E7 38 20 9F E5 00 30 A0 E3 02 30 85 E7 0D 00 A0 E1 01 10 A0 E3 28 30 9F E5 0F E0 A0 E1 03 F0 95 E7 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getnetbyname_cde3029bc2ace2795d9b26b8d7cd5642 {
	meta:
		aliases = "getnetbyname"
		size = "148"
		objfiles = "getnetbynms@libc.a"
	strings:
		$pattern = { F0 40 2D E9 80 60 9F E5 80 30 9F E5 06 60 8F E0 04 D0 4D E2 00 70 A0 E1 03 00 96 E7 ?? ?? ?? ?? 0E 00 00 EA 00 00 95 E5 07 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 0C 00 00 0A 04 40 95 E5 04 00 00 EA 07 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 06 00 00 0A 04 40 84 E2 00 00 94 E5 00 00 50 E3 F7 FF FF 1A ?? ?? ?? ?? 00 50 50 E2 ED FF FF 1A 1C 30 9F E5 03 30 96 E7 00 00 53 E3 00 00 00 1A ?? ?? ?? ?? 05 00 A0 E1 04 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __regerror_e7129570575277b6d81425cd43e742b0 {
	meta:
		aliases = "regerror, __regerror"
		size = "156"
		objfiles = "regex_olds@libc.a"
	strings:
		$pattern = { F0 40 2D E9 84 10 9F E5 10 00 50 E3 01 10 8F E0 04 D0 4D E2 02 70 A0 E1 03 60 A0 E1 00 00 00 9A ?? ?? ?? ?? 68 30 9F E5 03 30 81 E0 00 21 93 E7 60 30 9F E5 03 30 81 E0 03 40 82 E0 04 00 A0 E1 ?? ?? ?? ?? 00 00 56 E3 01 50 80 E2 0C 00 00 0A 06 00 55 E1 06 00 00 9A 07 00 A0 E1 04 10 A0 E1 01 20 46 E2 ?? ?? ?? ?? 00 30 A0 E3 00 30 C0 E5 03 00 00 EA 07 00 A0 E1 04 10 A0 E1 05 20 A0 E1 ?? ?? ?? ?? 05 00 A0 E1 04 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ulckpwdf_eaa5bc035117dbd216606a752dd5952e {
	meta:
		aliases = "ulckpwdf"
		size = "172"
		objfiles = "lckpwdfs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 84 60 9F E5 84 70 9F E5 06 60 8F E0 07 00 96 E7 14 D0 4D E2 01 00 70 E3 00 40 A0 01 17 00 00 0A 6C 40 9F E5 6C 30 9F E5 04 40 86 E0 03 10 96 E7 04 20 A0 E1 0D 00 A0 E1 5C 30 9F E5 0F E0 A0 E1 03 F0 96 E7 54 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 96 E7 07 00 96 E7 ?? ?? ?? ?? 00 30 E0 E3 00 40 A0 E1 07 30 86 E7 0D 00 A0 E1 01 10 A0 E3 2C 30 9F E5 0D 50 A0 E1 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_wait_for_restart_sig_7be2e385ab6c9dba612e4872a887012a {
	meta:
		aliases = "__pthread_wait_for_restart_signal"
		size = "112"
		objfiles = "pthreads@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 84 D0 4D E2 00 70 A0 E1 00 10 A0 E3 0D 20 A0 E1 02 00 A0 E3 0D 40 A0 E1 ?? ?? ?? ?? 40 60 9F E5 40 50 9F E5 06 60 8F E0 05 30 96 E7 0D 00 A0 E1 00 10 93 E5 ?? ?? ?? ?? 00 30 A0 E3 20 30 87 E5 0D 00 A0 E1 ?? ?? ?? ?? 05 30 96 E7 20 20 97 E5 00 30 93 E5 03 00 52 E1 F8 FF FF 1A 84 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ether_hostton_01132ef988ce0b1574d7df07969d6a55 {
	meta:
		aliases = "ether_hostton"
		size = "160"
		objfiles = "etherss@libc.a"
	strings:
		$pattern = { F0 40 2D E9 88 30 9F E5 00 70 A0 E1 01 60 A0 E1 80 00 9F E5 80 10 9F E5 03 30 8F E0 41 DF 4D E2 01 10 83 E0 00 00 83 E0 ?? ?? ?? ?? 00 50 50 E2 00 40 E0 03 13 00 00 0A 07 00 00 EA DB FF FF EB 00 10 50 E2 07 00 A0 E1 03 00 00 0A ?? ?? ?? ?? 00 00 50 E3 00 40 A0 01 08 00 00 0A 01 1C A0 E3 05 20 A0 E1 0D 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 06 10 A0 E1 0D 00 A0 E1 EF FF FF 1A 00 40 E0 E3 05 00 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 41 DF 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __exit_handler_a66fa24d42d644cff0d3380d836e3bbf {
	meta:
		aliases = "__exit_handler"
		size = "168"
		objfiles = "__exit_handlers@libc.a"
	strings:
		$pattern = { F0 40 2D E9 90 40 9F E5 90 60 9F E5 90 70 9F E5 04 D0 4D E2 04 40 8F E0 00 50 A0 E1 14 00 00 EA 00 30 94 E7 06 20 84 E7 01 20 93 E7 01 30 83 E0 02 00 52 E3 02 00 00 0A 03 00 52 E3 0C 00 00 1A 06 00 00 EA 04 20 93 E5 05 00 A0 E1 00 00 52 E3 07 00 00 0A 08 10 93 E5 32 FF 2F E1 04 00 00 EA 04 20 93 E5 00 00 52 E3 01 00 00 0A 08 00 93 E5 32 FF 2F E1 06 30 94 E7 07 00 A0 E1 01 20 43 E2 00 00 53 E3 02 12 A0 E1 E4 FF FF 1A 07 00 94 E7 04 D0 8D E2 F0 40 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __muldi3_3e946762cf432c31595665c777908eb0 {
	meta:
		aliases = "__aeabi_lmul, __muldi3"
		size = "72"
		objfiles = "_muldi3@libgcc.a"
	strings:
		$pattern = { F0 40 2D E9 92 01 0E E0 90 E3 25 E0 20 78 A0 E1 22 48 A0 E1 07 68 C0 E1 04 E8 C2 E1 96 0E 02 E0 97 0E 0E E0 94 06 06 E0 97 04 04 E0 06 60 9E E0 01 48 84 22 06 28 92 E0 26 48 A4 E0 02 00 A0 E1 04 10 85 E0 F0 80 BD E8 }
	condition:
		$pattern
}

rule __GI_setservent_8ebf68697e5cbec89a48a39009a7736a {
	meta:
		aliases = "setnetent, setprotoent, setservent, __GI_setprotoent, __GI_setnetent, __GI_setservent"
		size = "204"
		objfiles = "getnetents@libc.a, getservices@libc.a, getprotos@libc.a"
	strings:
		$pattern = { F0 40 2D E9 98 50 9F E5 98 40 9F E5 05 50 8F E0 94 30 9F E5 14 D0 4D E2 04 40 85 E0 03 10 95 E7 04 20 A0 E1 84 30 9F E5 00 70 A0 E1 80 60 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 70 30 9F E5 0F E0 A0 E1 03 F0 95 E7 06 00 95 E7 00 00 50 E3 06 00 00 1A 5C 00 9F E5 5C 10 9F E5 00 00 85 E0 01 10 85 E0 ?? ?? ?? ?? 06 00 85 E7 00 00 00 EA ?? ?? ?? ?? 00 00 57 E3 40 30 9F 15 01 20 A0 13 03 20 85 17 0D 00 A0 E1 01 10 A0 E3 30 30 9F E5 0F E0 A0 E1 03 F0 95 E7 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fflush_08b89046ab5eece82c81180a19c708ff {
	meta:
		aliases = "__GI_fflush, fflush"
		size = "192"
		objfiles = "fflushs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 9C 60 9F E5 00 50 50 E2 14 D0 4D E2 06 60 8F E0 1D 00 00 0A 8C 30 9F E5 03 30 96 E7 03 00 55 E1 19 00 00 0A 34 70 95 E5 00 00 57 E3 0B 00 00 1A 74 30 9F E5 38 40 85 E2 03 10 96 E7 0D 00 A0 E1 68 30 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 58 30 9F E5 0F E0 A0 E1 03 F0 96 E7 05 00 A0 E1 ?? ?? ?? ?? 00 00 57 E3 00 40 A0 E1 08 00 00 1A 0D 00 A0 E1 01 10 A0 E3 34 30 9F E5 0F E0 A0 E1 03 F0 96 E7 02 00 00 EA 05 00 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 04 00 A0 E1 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getutline_1b9b5523cb5207e2773383cfada73154 {
	meta:
		aliases = "getutline"
		size = "200"
		objfiles = "utents@libc.a"
	strings:
		$pattern = { F0 40 2D E9 A0 60 9F E5 A0 40 9F E5 06 60 8F E0 9C 30 9F E5 14 D0 4D E2 04 40 86 E0 03 10 96 E7 00 50 A0 E1 04 20 A0 E1 0D 00 A0 E1 84 30 9F E5 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 78 30 9F E5 0F E0 A0 E1 03 F0 96 E7 70 70 9F E5 08 50 85 E2 09 00 00 EA B0 30 D4 E1 06 30 43 E2 03 38 A0 E1 01 08 53 E3 04 00 00 8A 08 00 84 E2 05 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 03 00 00 0A 07 00 96 E7 05 FF FF EB 00 40 50 E2 F1 FF FF 1A 0D 00 A0 E1 01 10 A0 E3 28 30 9F E5 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _create_xid_9358755b3e2893a2090ad0bdae35af70 {
	meta:
		aliases = "_create_xid"
		size = "208"
		objfiles = "create_xids@libc.a"
	strings:
		$pattern = { F0 40 2D E9 A4 50 9F E5 A4 40 9F E5 05 50 8F E0 24 D0 4D E2 9C 30 9F E5 04 40 85 E0 04 70 8D E2 03 10 95 E7 04 20 A0 E1 07 00 A0 E1 88 30 9F E5 88 60 9F E5 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 7C 30 9F E5 0F E0 A0 E1 03 F0 95 E7 06 10 95 E7 00 00 51 E3 09 00 00 1A 14 00 8D E2 ?? ?? ?? ?? 18 30 9D E5 14 00 9D E5 58 10 9F E5 00 00 23 E0 01 10 85 E0 ?? ?? ?? ?? 01 30 A0 E3 06 30 85 E7 40 00 9F E5 1C 10 8D E2 00 00 85 E0 ?? ?? ?? ?? 07 00 A0 E1 01 10 A0 E3 2C 30 9F E5 0F E0 A0 E1 03 F0 95 E7 1C 00 9D E5 24 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getmntent_834f7cf8b5dfbe46613880511eebc918 {
	meta:
		aliases = "getmntent"
		size = "208"
		objfiles = "mntents@libc.a"
	strings:
		$pattern = { F0 40 2D E9 A4 50 9F E5 A4 40 9F E5 05 50 8F E0 A0 30 9F E5 14 D0 4D E2 04 40 85 E0 03 10 95 E7 04 20 A0 E1 90 30 9F E5 00 70 A0 E1 8C 60 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 95 E7 80 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 95 E7 06 30 95 E7 00 00 53 E3 05 00 00 1A 01 0A A0 E3 ?? ?? ?? ?? 00 00 50 E3 06 00 85 E7 00 00 00 1A ?? ?? ?? ?? 48 30 9F E5 4C 10 9F E5 03 20 95 E7 01 10 85 E0 07 00 A0 E1 01 3A A0 E3 ?? ?? ?? ?? 01 10 A0 E3 00 40 A0 E1 30 30 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_fgetwc_unlocked_e3bf049e4f8760cf81f94f2bb0b9bcc6 {
	meta:
		aliases = "getwc_unlocked, fgetwc_unlocked, __GI_fgetwc_unlocked"
		size = "416"
		objfiles = "fgetwc_unlockeds@libc.a"
	strings:
		$pattern = { F0 40 2D E9 B0 20 D0 E1 8C 31 9F E5 0C D0 4D E2 03 30 02 E0 02 0B 53 E3 00 40 A0 E1 04 00 00 8A 02 1B A0 E3 ?? ?? ?? ?? 00 00 50 E3 00 50 E0 13 56 00 00 1A B0 30 D4 E1 02 00 13 E3 10 00 00 0A 01 00 13 E3 03 00 00 1A 28 30 94 E5 00 00 53 E3 03 30 D4 05 00 00 00 0A 00 30 A0 E3 02 30 C4 E5 B0 30 D4 E1 01 20 03 E2 02 21 84 E0 01 30 43 E2 24 50 92 E5 B0 30 C4 E1 00 30 A0 E3 28 30 84 E5 3B 00 00 EA 08 30 94 E5 00 00 53 E3 05 00 00 1A 04 00 A0 E1 07 10 8D E2 D1 FF FF EB 0C 30 94 E5 01 30 83 E2 0C 30 84 E5 2C 30 94 E5 0D 70 A0 E1 00 00 53 E3 02 30 C4 05 2C 60 84 E2 10 20 94 E5 14 C0 94 E5 02 10 A0 E1 }
	condition:
		$pattern
}

rule __stdio_fwrite_ce57b94ab7371ddb58944f675bb5333d {
	meta:
		aliases = "__stdio_fwrite"
		size = "320"
		objfiles = "_fwrites@libc.a"
	strings:
		$pattern = { F0 40 2D E9 B0 30 D2 E1 04 D0 4D E2 02 4C 13 E2 02 50 A0 E1 00 70 A0 E1 01 60 A0 E1 3E 00 00 1A 04 30 92 E5 10 00 92 E5 02 00 73 E3 0C 30 92 E5 09 00 00 1A 03 40 60 E0 04 00 51 E1 01 40 A0 31 04 20 A0 E1 07 10 A0 E1 ?? ?? ?? ?? 10 30 95 E5 04 30 83 E0 10 30 85 E5 35 00 00 EA 03 30 60 E0 03 00 51 E1 24 00 00 8A 06 20 A0 E1 07 10 A0 E1 ?? ?? ?? ?? 10 30 95 E5 B0 20 D5 E1 06 30 83 E0 01 0C 12 E3 10 30 85 E5 29 00 00 0A 07 00 A0 E1 0A 10 A0 E3 06 20 A0 E1 ?? ?? ?? ?? 00 00 50 E3 23 00 00 0A 05 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 1F 00 00 0A 06 00 50 E1 00 40 A0 31 06 40 A0 21 06 30 64 E0 03 70 87 E0 }
	condition:
		$pattern
}

rule pututline_51ad96fc954300a62abc2c949de83330 {
	meta:
		aliases = "pututline"
		size = "220"
		objfiles = "utents@libc.a"
	strings:
		$pattern = { F0 40 2D E9 B0 50 9F E5 B0 40 9F E5 05 50 8F E0 AC 30 9F E5 14 D0 4D E2 04 40 85 E0 00 60 A0 E1 03 10 95 E7 04 20 A0 E1 98 70 9F E5 0D 00 A0 E1 94 30 9F E5 0F E0 A0 E1 03 F0 95 E7 8C 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 95 E7 01 20 A0 E3 7C 10 9F E5 07 00 95 E7 ?? ?? ?? ?? 06 00 A0 E1 C0 FF FF EB 00 10 50 E2 64 10 9F 15 01 20 A0 13 02 20 A0 03 07 00 95 17 07 00 95 07 ?? ?? ?? ?? 40 30 9F E5 06 10 A0 E1 03 00 95 E7 06 2D A0 E3 ?? ?? ?? ?? 01 10 A0 E3 06 0D 50 E3 34 30 9F E5 0D 00 A0 E1 00 60 A0 13 0F E0 A0 E1 03 F0 95 E7 06 00 A0 E1 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule utmpname_c58f7d0084dd74953bd8bdfa82271e83 {
	meta:
		aliases = "utmpname"
		size = "224"
		objfiles = "utents@libc.a"
	strings:
		$pattern = { F0 40 2D E9 B0 50 9F E5 B0 40 9F E5 05 50 8F E0 AC 30 9F E5 14 D0 4D E2 04 40 85 E0 03 10 95 E7 00 60 A0 E1 04 20 A0 E1 0D 00 A0 E1 94 30 9F E5 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 88 30 9F E5 0F E0 A0 E1 03 F0 95 E7 00 00 56 E3 0B 00 00 0A 78 70 9F E5 78 30 9F E5 07 00 95 E7 03 40 85 E0 04 00 50 E1 00 00 00 0A ?? ?? ?? ?? 06 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 04 00 A0 01 07 00 85 E7 50 40 9F E5 04 00 95 E7 01 00 70 E3 00 00 00 0A ?? ?? ?? ?? 00 30 E0 E3 04 30 85 E7 0D 00 A0 E1 01 10 A0 E3 30 30 9F E5 0F E0 A0 E1 03 F0 95 E7 00 00 A0 E3 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_onexit_process_e27f56f10c2bdba31d5616667f11bfbb {
	meta:
		aliases = "pthread_onexit_process"
		size = "216"
		objfiles = "pthreads@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 B4 50 9F E5 B4 30 9F E5 05 50 8F E0 03 70 95 E7 9C D0 4D E2 00 30 97 E5 00 60 A0 E1 00 00 53 E3 23 00 00 BA 46 FF FF EB 02 30 A0 E3 0C 60 8D E5 00 40 A0 E1 09 00 8D E9 04 60 8D E2 06 10 A0 E1 94 20 A0 E3 00 00 97 E5 ?? ?? ?? ?? 01 00 70 E3 03 00 00 1A ?? ?? ?? ?? 00 30 90 E5 04 00 53 E3 F5 FF FF 0A 04 00 A0 E1 E2 FF FF EB 50 30 9F E5 03 30 95 E7 00 30 93 E5 03 00 54 E1 0C 00 00 1A 40 30 9F E5 00 10 A0 E3 03 30 95 E7 02 21 A0 E3 14 00 93 E5 ?? ?? ?? ?? 2C 30 9F E5 03 10 95 E7 28 30 9F E5 03 20 95 E7 00 30 A0 E3 00 30 82 E5 00 30 81 E5 9C D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_readdir_70069e254a66d911b84c70404e833bcf {
	meta:
		aliases = "readdir, __GI_readdir"
		size = "216"
		objfiles = "readdirs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 B8 60 9F E5 B8 30 9F E5 06 60 8F E0 14 D0 4D E2 18 40 80 E2 03 10 96 E7 04 20 A0 E1 A4 30 9F E5 00 50 A0 E1 0D 00 A0 E1 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 90 30 9F E5 0F E0 A0 E1 03 F0 96 E7 00 70 A0 E3 0C 00 95 E9 02 00 53 E1 08 00 00 8A 00 00 95 E5 0C 10 95 E5 14 20 95 E5 ?? ?? ?? ?? 00 00 50 E3 00 40 A0 D3 0C 00 00 DA 08 00 85 E5 04 70 85 E5 04 20 95 E5 0C 00 95 E5 00 40 82 E0 04 10 94 E5 B8 30 D4 E1 10 10 85 E5 00 10 92 E7 02 30 83 E0 00 00 51 E3 04 30 85 E5 E8 FF FF 0A 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 14 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule gets_5bc28b42202b8ec26a218f0ecabc54b0 {
	meta:
		aliases = "gets"
		size = "224"
		objfiles = "getss@libc.a"
	strings:
		$pattern = { F0 40 2D E9 BC 60 9F E5 BC 30 9F E5 06 60 8F E0 03 40 96 E7 14 D0 4D E2 00 20 94 E5 00 50 A0 E1 34 70 92 E5 00 00 57 E3 01 00 00 0A 05 40 A0 E1 0D 00 00 EA 94 30 9F E5 0D 00 A0 E1 03 10 96 E7 38 20 82 E2 88 30 9F E5 0F E0 A0 E1 03 F0 96 E7 00 00 94 E5 7C 30 9F E5 38 00 80 E2 0F E0 A0 E1 03 F0 96 E7 F0 FF FF EA 01 40 84 E2 ?? ?? ?? ?? 01 00 70 E3 FF 30 00 E2 02 00 00 0A 0A 00 53 E3 00 30 C4 E5 F7 FF FF 1A 01 00 70 E3 04 00 55 11 00 30 A0 13 01 30 A0 03 00 50 A0 03 00 30 C4 15 00 00 57 E3 04 00 00 1A 0D 00 A0 E1 01 10 A0 E3 24 30 9F E5 0F E0 A0 E1 03 F0 96 E7 05 00 A0 E1 14 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule readdir64_ffdba9172e6ec69ee3195cd4dc7d2cc3 {
	meta:
		aliases = "__GI_readdir64, readdir64"
		size = "220"
		objfiles = "readdir64s@libc.a"
	strings:
		$pattern = { F0 40 2D E9 BC 60 9F E5 BC 30 9F E5 06 60 8F E0 14 D0 4D E2 18 40 80 E2 03 10 96 E7 04 20 A0 E1 A8 30 9F E5 00 50 A0 E1 0D 00 A0 E1 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 94 30 9F E5 0F E0 A0 E1 03 F0 96 E7 00 70 A0 E3 0C 00 95 E9 02 00 53 E1 08 00 00 8A 00 00 95 E5 0C 10 95 E5 14 20 95 E5 ?? ?? ?? ?? 00 00 50 E3 00 40 A0 D3 0D 00 00 DA 08 00 85 E5 04 70 85 E5 04 20 95 E5 0C 30 95 E5 03 40 82 E0 03 00 92 E7 04 10 94 E5 B0 31 D4 E1 08 C0 94 E5 02 30 83 E0 01 00 90 E1 04 30 85 E5 10 C0 85 E5 E7 FF FF 0A 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 14 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule __powisf2_33b4791f2a754296eafdcd35be0d8d2a {
	meta:
		aliases = "__powisf2"
		size = "144"
		objfiles = "_powisf2@libgcc.a"
	strings:
		$pattern = { F0 40 2D E9 C1 2F 21 E0 C1 2F 42 E0 01 00 12 E3 FE 35 A0 E3 00 60 A0 E1 04 D0 4D E2 01 70 A0 E1 00 50 A0 E1 03 60 A0 01 02 40 A0 E1 A4 40 B0 E1 05 00 A0 E1 05 10 A0 E1 0B 00 00 0A ?? ?? ?? ?? 01 00 14 E3 00 50 A0 E1 05 10 A0 E1 06 00 A0 E1 F5 FF FF 0A ?? ?? ?? ?? A4 40 B0 E1 00 60 A0 E1 05 10 A0 E1 05 00 A0 E1 F3 FF FF 1A 00 00 57 E3 03 00 00 AA 06 10 A0 E1 FE 05 A0 E3 ?? ?? ?? ?? 00 60 A0 E1 06 00 A0 E1 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule pthread_sigmask_3d458a4a2e6617661fc8a05c3e4f9a4c {
	meta:
		aliases = "pthread_sigmask"
		size = "228"
		objfiles = "signalss@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 C8 40 9F E5 00 30 51 E2 04 40 8F E0 84 D0 4D E2 00 60 A0 E1 02 70 A0 E1 21 00 00 0A 0D 00 A0 E1 80 20 A0 E3 0D 50 A0 E1 ?? ?? ?? ?? 01 00 56 E3 15 00 00 0A 02 00 56 E3 02 00 00 0A 00 00 56 E3 05 00 00 0A 15 00 00 EA 84 30 9F E5 0D 00 A0 E1 03 30 94 E7 00 10 93 E5 ?? ?? ?? ?? 74 30 9F E5 0D 00 A0 E1 03 30 94 E7 00 10 93 E5 ?? ?? ?? ?? 64 30 9F E5 03 30 94 E7 00 10 93 E5 00 00 51 E3 0D 00 A0 C1 04 00 00 CA 04 00 00 EA 40 30 9F E5 0D 00 A0 E1 03 30 94 E7 00 10 93 E5 ?? ?? ?? ?? 0D 30 A0 E1 06 00 A0 E1 03 10 A0 E1 07 20 A0 E1 ?? ?? ?? ?? 01 00 70 E3 00 00 A0 13 01 00 00 1A ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __close_nameservers_923c05ca0954813dbf3052510a29286d {
	meta:
		aliases = "__close_nameservers"
		size = "252"
		objfiles = "closenameserverss@libc.a"
	strings:
		$pattern = { F0 40 2D E9 C8 50 9F E5 C8 30 9F E5 05 50 8F E0 03 40 95 E7 C0 30 9F E5 14 D0 4D E2 04 20 A0 E1 03 10 95 E7 0D 00 A0 E1 B0 30 9F E5 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 A4 30 9F E5 0F E0 A0 E1 03 F0 95 E7 9C 30 9F E5 9C 40 9F E5 03 60 85 E0 00 70 A0 E3 04 00 00 EA 04 20 85 E7 02 01 96 E7 ?? ?? ?? ?? 04 30 95 E7 03 71 86 E7 04 30 95 E7 00 00 53 E3 01 20 43 E2 F6 FF FF CA 05 00 00 EA 04 20 85 E7 02 01 96 E7 ?? ?? ?? ?? 04 30 95 E7 03 71 86 E7 03 00 00 EA 50 30 9F E5 50 40 9F E5 03 60 85 E0 00 70 A0 E3 04 30 95 E7 00 00 53 E3 01 20 43 E2 F1 FF FF CA 0D 00 A0 E1 01 10 A0 E3 30 30 9F E5 0F E0 A0 E1 }
	condition:
		$pattern
}

rule initstate_r_868ba11d719be6d0cc3697f867280896 {
	meta:
		aliases = "__GI_initstate_r, initstate_r"
		size = "224"
		objfiles = "random_rs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 CC C0 9F E5 7F 00 52 E3 0C C0 8F E0 04 D0 4D E2 01 70 A0 E1 03 50 A0 E1 03 00 00 9A FF 00 52 E3 04 40 A0 83 03 40 A0 93 08 00 00 EA 1F 00 52 E3 03 00 00 8A 07 00 52 E3 00 40 A0 83 03 00 00 8A 1B 00 00 EA 3F 00 52 E3 02 40 A0 83 01 40 A0 93 80 30 9F E5 04 60 87 E2 03 30 8C E0 04 21 83 E0 14 10 92 E5 04 31 93 E7 01 21 86 E0 14 30 85 E5 18 20 85 E5 10 10 85 E5 0C 40 85 E5 08 60 85 E5 05 10 A0 E1 ?? ?? ?? ?? 00 00 54 E3 04 30 95 15 05 20 A0 13 03 30 66 10 43 31 A0 11 92 43 23 10 00 00 A0 E3 00 00 87 E5 04 00 A0 01 00 30 87 15 05 00 00 EA ?? ?? ?? ?? 16 40 A0 E3 00 40 80 E5 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule putchar_f5a598141cf5a9f4ab8ea7a79f148216 {
	meta:
		aliases = "putchar"
		size = "244"
		objfiles = "putchars@libc.a"
	strings:
		$pattern = { F0 40 2D E9 D0 60 9F E5 D0 30 9F E5 06 60 8F E0 03 30 96 E7 14 D0 4D E2 00 50 93 E5 00 70 A0 E1 34 30 95 E5 00 00 53 E3 0B 00 00 0A 10 20 95 E5 1C 30 95 E5 03 00 52 E1 FF 30 00 32 01 30 C2 34 03 40 A0 31 10 20 85 35 20 00 00 3A 05 10 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 1C 00 00 EA 80 30 9F E5 38 40 85 E2 03 10 96 E7 04 20 A0 E1 0D 00 A0 E1 70 30 9F E5 0F E0 A0 E1 03 F0 96 E7 68 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 96 E7 10 20 95 E5 1C 30 95 E5 03 00 52 E1 FF 30 07 32 01 30 C2 34 03 40 A0 31 10 20 85 35 03 00 00 3A 07 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 0D 00 A0 E1 01 10 A0 E3 24 30 9F E5 }
	condition:
		$pattern
}

rule __libc_sigaction_fda00698fc1ff63fa8f9df5ddebf2c33 {
	meta:
		aliases = "__GI_sigaction, sigaction, __libc_sigaction"
		size = "240"
		objfiles = "sigactions@libc.a"
	strings:
		$pattern = { F0 40 2D E9 D8 60 9F E5 00 40 51 E2 06 60 8F E0 47 DF 4D E2 00 70 A0 E1 02 50 A0 E1 15 00 00 0A 04 10 A0 E1 04 30 91 E4 80 20 A0 E3 98 00 8D E2 8C 30 8D E5 ?? ?? ?? ?? 84 20 94 E5 01 03 12 E3 88 30 94 15 90 20 8D E5 94 30 8D 15 06 00 00 1A 04 00 12 E3 8C 30 9F 15 8C 30 9F 05 03 10 96 E7 01 33 82 E3 94 10 8D E5 90 30 8D E5 00 00 54 E3 8C 10 8D 12 00 00 00 1A 00 10 A0 E3 00 00 55 E3 05 20 A0 01 0D 20 A0 11 08 30 A0 E3 07 00 A0 E1 ?? ?? ?? ?? 00 30 55 E2 01 30 A0 13 00 00 50 E3 00 30 A0 B3 00 00 53 E3 00 40 A0 E1 09 00 00 0A 00 30 9D E5 05 00 A0 E1 04 30 80 E4 0C 10 8D E2 80 20 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule re_comp_5b17844429db290c672b8cc9d055b854 {
	meta:
		aliases = "re_comp"
		size = "260"
		objfiles = "regex_olds@libc.a"
	strings:
		$pattern = { F0 40 2D E9 E0 50 9F E5 00 70 50 E2 05 50 8F E0 04 D0 4D E2 D4 40 9F E5 05 00 00 1A 04 30 95 E7 00 00 53 E3 2D 00 00 1A C4 30 9F E5 03 00 85 E0 2B 00 00 EA 04 30 95 E7 04 60 85 E0 00 00 53 E3 0F 00 00 1A C8 00 A0 E3 ?? ?? ?? ?? 00 00 50 E3 04 00 85 E7 06 00 00 0A C8 30 A0 E3 01 0C A0 E3 04 30 86 E5 ?? ?? ?? ?? 00 00 50 E3 10 00 86 E5 03 00 00 1A 7C 30 9F E5 03 30 85 E0 EA 00 83 E2 17 00 00 EA 64 40 9F E5 07 00 A0 E1 04 40 85 E0 1C 30 D4 E5 80 30 83 E3 1C 30 C4 E5 ?? ?? ?? ?? 54 30 9F E5 00 10 A0 E1 03 30 95 E7 07 00 A0 E1 00 20 93 E5 04 30 A0 E1 A9 F6 FF EB 00 00 50 E3 06 00 00 0A 34 30 9F E5 }
	condition:
		$pattern
}

rule strerror_r_eadd27cd37e2528e40b3af2878b172aa {
	meta:
		aliases = "__xpg_strerror_r, __GI___xpg_strerror_r, strerror_r"
		size = "252"
		objfiles = "__xpg_strerror_rs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 E4 60 9F E5 7C 00 50 E3 06 60 8F E0 44 D0 4D E2 00 C0 A0 E1 01 70 A0 E1 02 40 A0 E1 0B 00 00 8A C8 30 9F E5 03 50 86 E0 02 00 00 EA 00 00 53 E3 01 00 40 02 01 50 85 E2 00 00 50 E3 00 30 D5 E5 F9 FF FF 1A 00 00 53 E3 00 60 A0 11 0E 00 00 1A 09 10 E0 E3 0C 20 A0 E1 C2 3F A0 E1 00 10 8D E5 3F 00 8D E2 0A 10 81 E2 04 10 8D E5 ?? ?? ?? ?? 7C 10 9F E5 0E 50 40 E2 01 10 86 E0 05 00 A0 E1 0E 20 A0 E3 ?? ?? ?? ?? 16 60 A0 E3 05 00 A0 E1 ?? ?? ?? ?? 00 00 57 E3 00 40 A0 03 01 20 80 E2 04 00 52 E1 02 40 A0 91 22 60 A0 83 00 00 54 E3 06 00 00 0A 04 20 A0 E1 05 10 A0 E1 07 00 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __new_exitfn_c5cc55097d0f3861b87869d3045ea99f {
	meta:
		aliases = "__new_exitfn"
		size = "288"
		objfiles = "__exit_handlers@libc.a"
	strings:
		$pattern = { F0 40 2D E9 E8 50 9F E5 E8 30 9F E5 05 50 8F E0 03 40 95 E7 E0 30 9F E5 14 D0 4D E2 03 10 95 E7 04 20 A0 E1 0D 00 A0 E1 D0 30 9F E5 0F E0 A0 E1 03 F0 95 E7 C8 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 95 E7 BC 30 9F E5 BC 60 9F E5 03 30 95 E7 06 10 95 E7 01 30 83 E2 03 00 51 E1 0E 00 00 AA A8 70 9F E5 01 12 A0 E1 05 1D 81 E2 07 00 95 E7 ?? ?? ?? ?? 00 40 50 E2 03 00 00 1A ?? ?? ?? ?? 0C 30 A0 E3 00 30 80 E5 11 00 00 EA 06 30 95 E7 07 40 85 E7 14 30 83 E2 06 30 85 E7 64 E0 9F E5 68 30 9F E5 0E 10 95 E7 03 C0 95 E7 01 00 81 E2 01 30 A0 E3 01 12 A0 E1 54 20 9F E5 0C 30 81 E7 50 30 9F E5 02 20 85 E0 }
	condition:
		$pattern
}

rule rtime_1cffe504ac4fb89a5c195598faedc4f2 {
	meta:
		aliases = "__GI_rtime, rtime"
		size = "440"
		objfiles = "rtimes@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 00 52 E3 01 60 A0 03 02 60 A0 13 28 D0 4D E2 02 70 A0 E1 00 40 A0 E1 01 80 A0 E1 02 00 A0 E3 06 10 A0 E1 00 20 A0 E3 ?? ?? ?? ?? 00 50 50 E2 5A 00 00 BA 02 30 A0 E3 B0 30 C4 E1 02 00 56 E3 25 3C A0 E3 B2 30 C4 E1 2E 00 00 1A 10 C0 A0 E3 24 10 8D E2 04 20 A0 E3 00 30 A0 E3 10 10 8D E8 ?? ?? ?? ?? 00 00 50 E3 2B 00 00 BA 04 00 97 E5 FA 1F A0 E3 ?? ?? ?? ?? 00 20 97 E5 FA 3F A0 E3 92 03 26 E0 01 30 A0 E3 18 50 8D E5 BC 31 CD E1 18 70 8D E2 01 10 A0 E3 06 20 A0 E1 07 00 A0 E1 ?? ?? ?? ?? 00 40 50 E2 03 00 00 AA ?? ?? ?? ?? 00 30 90 E5 04 00 53 E3 F5 FF FF 0A 00 00 54 E3 04 00 00 CA }
	condition:
		$pattern
}

rule __GI_xdr_string_469f0efa155f97d099bab48ce4e6a905 {
	meta:
		aliases = "xdr_string, __GI_xdr_string"
		size = "300"
		objfiles = "xdrs@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 30 90 E5 10 71 9F E5 00 00 53 E3 07 70 8F E0 08 D0 4D E2 00 50 A0 E1 01 60 A0 E1 02 80 A0 E1 00 40 91 E5 04 00 00 0A 02 00 53 E3 07 00 00 1A 00 00 54 E3 02 00 00 1A 32 00 00 EA 00 00 54 E3 32 00 00 0A 04 00 A0 E1 ?? ?? ?? ?? 04 00 8D E5 05 00 A0 E1 04 10 8D E2 ?? ?? ?? ?? 00 00 50 E3 2A 00 00 0A 04 30 9D E5 08 00 53 E1 27 00 00 8A 00 20 95 E5 01 00 52 E3 03 00 00 0A 16 00 00 3A 02 00 52 E3 21 00 00 1A 18 00 00 EA 01 00 93 E2 1C 00 00 0A 00 00 54 E3 0C 00 00 1A ?? ?? ?? ?? 00 00 50 E3 00 40 A0 E1 00 00 86 E5 07 00 00 1A 68 30 9F E5 68 00 9F E5 03 30 97 E7 00 00 87 E0 00 10 93 E5 }
	condition:
		$pattern
}

rule regexec_f6d473b52a8ef2bd46316f915baff98b {
	meta:
		aliases = "__regexec, regexec"
		size = "320"
		objfiles = "regex_olds@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 40 A0 E1 38 D0 4D E2 01 00 A0 E1 02 50 A0 E1 01 70 A0 E1 03 80 A0 E1 ?? ?? ?? ?? 04 E0 A0 E1 0C C0 8D E2 00 60 A0 E1 0F 00 BE E8 0F 00 AC E8 0F 00 9E E8 0F 00 8C E8 50 20 9D E5 28 30 DD E5 01 10 02 E2 20 30 C3 E3 81 32 83 E1 28 30 CD E5 28 30 DD E5 82 22 A0 E1 40 30 C3 E3 40 20 02 E2 03 20 82 E1 1C 30 D4 E5 28 20 CD E5 28 20 DD E5 23 32 A0 E1 01 30 23 E2 00 00 55 E3 00 40 A0 03 01 40 03 12 02 20 C2 E3 04 20 82 E3 00 00 54 E3 28 20 CD E5 04 C0 A0 01 09 00 00 0A 85 01 A0 E1 2C 50 8D E5 ?? ?? ?? ?? 00 00 50 E3 01 00 A0 03 1F 00 00 0A 05 31 80 E0 34 30 8D E5 30 00 8D E5 2C C0 8D E2 }
	condition:
		$pattern
}

rule __pthread_alt_timedlock_8fc6908d227fb6a614ef766e44ed936a {
	meta:
		aliases = "__pthread_alt_timedlock"
		size = "280"
		objfiles = "spinlocks@libpthread.a"
	strings:
		$pattern = { F0 41 2D E9 00 41 9F E5 00 50 A0 E1 FC 00 9F E5 04 40 8F E0 00 00 84 E0 02 80 A0 E1 01 70 A0 E1 3A FF FF EB E8 20 9F E5 02 00 94 E7 00 00 50 E3 00 60 A0 11 00 30 96 15 00 60 A0 01 02 30 84 17 C8 30 9F E5 00 20 A0 E3 03 20 84 E7 02 00 56 E1 08 00 00 1A 0C 00 A0 E3 ?? ?? ?? ?? 00 60 50 E2 04 00 00 1A 05 00 A0 E1 07 10 A0 E1 ?? ?? ?? ?? 01 00 A0 E3 F0 81 BD E8 04 00 85 E2 23 FF FF EB 00 40 95 E5 00 00 54 E3 01 30 A0 03 04 20 A0 01 00 30 85 05 08 00 00 0A 00 00 57 E3 01 00 00 1A 47 FF FF EB 00 70 A0 E1 00 30 A0 E3 08 30 86 E5 90 00 86 E8 00 60 85 E5 01 20 A0 E3 00 30 A0 E3 04 30 85 E5 03 00 52 E1 }
	condition:
		$pattern
}

rule pthread_sighandler_rt_9b6cb49d0fb3df27fdc143bd74f41561 {
	meta:
		aliases = "pthread_sighandler_rt"
		size = "116"
		objfiles = "signalss@libpthread.a"
	strings:
		$pattern = { F0 41 2D E9 00 60 A0 E1 02 80 A0 E1 01 70 A0 E1 D2 FF FF EB 58 30 D0 E5 4C 20 9F E5 00 00 53 E3 00 30 A0 13 02 20 8F E0 00 50 A0 E1 20 60 80 15 58 30 C0 15 F0 81 BD 18 54 40 90 E5 2C 30 9F E5 00 00 54 E3 54 D0 80 05 03 30 82 E0 07 10 A0 E1 08 20 A0 E1 06 00 A0 E1 0F E0 A0 E1 06 F1 93 E7 00 00 54 E3 54 40 85 05 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_svc_getreq_poll_19ef7802fa131129ed87b91383138e39 {
	meta:
		aliases = "svc_getreq_poll, __GI_svc_getreq_poll"
		size = "124"
		objfiles = "svcs@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 60 A0 E3 00 70 A0 E1 01 80 A0 E1 06 50 A0 E1 10 00 00 EA 02 40 97 E7 01 00 74 E3 0C 00 00 0A B6 30 D1 E1 00 00 53 E3 09 00 00 0A 20 00 13 E3 04 00 A0 E1 01 60 86 E2 04 00 00 0A ?? ?? ?? ?? B4 30 90 E5 04 01 93 E7 ?? ?? ?? ?? 00 00 00 EA ?? ?? ?? ?? 01 50 85 E2 ?? ?? ?? ?? 00 30 90 E5 85 21 A0 E1 03 00 55 E1 08 00 56 B1 02 10 87 E0 E7 FF FF BA F0 81 BD E8 }
	condition:
		$pattern
}

rule pthread_detach_9b00588b6f16298c0181205c50d0e239 {
	meta:
		aliases = "pthread_detach"
		size = "280"
		objfiles = "joins@libpthread.a"
	strings:
		$pattern = { F0 41 2D E9 00 61 9F E5 00 31 9F E5 06 60 8F E0 03 20 96 E7 00 3B A0 E1 23 3B A0 E1 03 52 82 E0 98 D0 4D E2 00 40 A0 E1 00 10 A0 E3 05 00 A0 E1 ?? ?? ?? ?? 08 20 95 E5 00 00 52 E3 02 00 00 0A 10 70 92 E5 04 00 57 E1 03 00 00 0A 05 00 A0 E1 ?? ?? ?? ?? 03 00 A0 E3 29 00 00 EA 2D 40 D2 E5 00 00 54 E3 03 00 00 0A 05 00 A0 E1 ?? ?? ?? ?? 16 00 A0 E3 22 00 00 EA 38 30 92 E5 00 00 53 E3 03 00 00 0A 05 00 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 1B 00 00 EA 2C 40 D2 E5 01 80 A0 E3 2D 80 C2 E5 05 00 A0 E1 ?? ?? ?? ?? 00 00 54 E3 13 00 00 0A 5C 30 9F E5 03 40 96 E7 00 30 94 E5 00 00 53 E3 0E 00 00 BA BE FE FF EB }
	condition:
		$pattern
}

rule _dl_fixup_60190b1c4e610d3d6557b14a6396e190 {
	meta:
		aliases = "_dl_fixup"
		size = "308"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { F0 41 2D E9 00 80 A0 E1 10 00 90 E5 01 70 A0 E1 00 00 50 E3 02 00 00 0A ?? ?? ?? ?? 00 50 50 E2 41 00 00 1A 00 40 98 E5 5C 30 94 E5 B2 22 D4 E1 00 00 53 E3 01 50 A0 13 3B 00 00 1A 84 10 94 E5 88 50 94 E5 00 00 51 E3 18 00 00 0A 01 00 12 E3 16 00 00 1A C8 C0 94 E5 00 00 5C E3 0B 00 00 0A 00 E0 94 E5 8C 61 A0 E1 08 00 41 E2 08 00 80 E2 00 20 90 E5 01 C0 5C E2 02 30 9E E7 0E 30 83 E0 02 30 8E E7 F8 FF FF 1A 01 10 86 E0 05 50 66 E0 05 20 A0 E1 08 00 A0 E1 ?? ?? ?? ?? B2 32 D4 E1 00 50 A0 E1 01 30 83 E3 B2 32 C4 E1 00 00 00 EA 00 50 A0 E3 A0 30 94 E5 9C 10 94 E5 00 00 53 E3 02 70 A0 13 00 00 51 E3 }
	condition:
		$pattern
}

rule __GI_vsscanf_92339c4dad31b7584febb045cb716e5e {
	meta:
		aliases = "vsscanf, __GI_vsscanf"
		size = "132"
		objfiles = "vsscanfs@libc.a"
	strings:
		$pattern = { F0 41 2D E9 01 30 E0 E3 50 D0 4D E2 04 30 8D E5 03 30 83 E2 00 50 A0 E1 00 40 A0 E3 38 00 8D E2 34 30 8D E5 A1 30 A0 E3 01 60 A0 E1 02 70 A0 E1 B0 30 CD E1 02 40 CD E5 2C 40 8D E5 ?? ?? ?? ?? 20 40 8D E5 10 50 8D E5 08 50 8D E5 05 00 A0 E1 ?? ?? ?? ?? 06 10 A0 E1 00 30 85 E0 07 20 A0 E1 0D 00 A0 E1 0D 80 A0 E1 18 30 8D E5 1C 50 8D E5 0C 30 8D E5 14 30 8D E5 ?? ?? ?? ?? 50 D0 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule _fp_out_narrow_18cb239e7a02098748ce888f8f2dbaf3 {
	meta:
		aliases = "_fp_out_narrow"
		size = "132"
		objfiles = "_vfprintf_internals@libc.a"
	strings:
		$pattern = { F0 41 2D E9 01 50 A0 E1 80 10 11 E2 00 80 A0 E1 02 40 A0 E1 03 70 A0 E1 01 50 A0 01 0E 00 00 0A 03 00 A0 E1 ?? ?? ?? ?? 04 40 60 E0 00 00 54 E3 00 60 A0 E1 00 50 A0 D3 06 00 00 DA 7F 10 05 E2 08 00 A0 E1 04 20 A0 E1 D8 FF FF EB 04 00 50 E1 00 50 A0 E1 08 00 00 1A 06 40 A0 E1 00 00 54 E3 00 00 A0 D3 03 00 00 DA 07 00 A0 E1 04 10 A0 E1 08 20 A0 E1 ?? ?? ?? ?? 00 50 85 E0 05 00 A0 E1 F0 81 BD E8 }
	condition:
		$pattern
}

rule _fp_out_wide_65e8186040422cb757b1a1ddec886498 {
	meta:
		aliases = "_fp_out_wide"
		size = "168"
		objfiles = "_vfwprintf_internals@libc.a"
	strings:
		$pattern = { F0 41 2D E9 01 50 A0 E1 80 10 11 E2 58 D0 4D E2 00 80 A0 E1 02 40 A0 E1 03 70 A0 E1 01 50 A0 01 0E 00 00 0A 03 00 A0 E1 ?? ?? ?? ?? 04 40 60 E0 00 00 54 E3 00 60 A0 E1 00 50 A0 D3 06 00 00 DA 7F 10 05 E2 08 00 A0 E1 04 20 A0 E1 13 FE FF EB 04 00 50 E1 00 50 A0 E1 0F 00 00 1A 06 40 A0 E1 00 00 54 E3 0C 00 00 DA 00 10 A0 E3 58 30 8D E2 01 21 83 E0 01 30 D7 E7 01 10 81 E2 04 00 51 E1 54 30 02 E5 F8 FF FF BA 04 10 A0 E1 08 20 A0 E1 04 00 8D E2 ?? ?? ?? ?? 00 50 85 E0 05 00 A0 E1 58 D0 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule __decode_question_f9b614db1b3134a9afc2103deee05420 {
	meta:
		aliases = "__decode_question"
		size = "112"
		objfiles = "decodeqs@libc.a"
	strings:
		$pattern = { F0 41 2D E9 01 DC 4D E2 02 50 A0 E1 01 3C A0 E3 0D 20 A0 E1 00 70 A0 E1 01 60 A0 E1 ?? ?? ?? ?? 00 40 50 E2 0D 80 A0 E1 0D 00 00 BA 0D 00 A0 E1 ?? ?? ?? ?? 06 30 84 E0 00 00 85 E5 07 20 83 E0 03 10 D7 E7 01 30 D2 E5 04 40 84 E2 01 34 83 E1 04 30 85 E5 03 30 D2 E5 02 20 D2 E5 02 34 83 E1 08 30 85 E5 04 00 A0 E1 01 DC 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule __GI_vasprintf_c5d38b6a15a4530966c1ebb97c098b27 {
	meta:
		aliases = "vasprintf, __GI_vasprintf"
		size = "132"
		objfiles = "vasprintfs@libc.a"
	strings:
		$pattern = { F0 41 2D E9 02 60 A0 E1 00 50 A0 E1 01 70 A0 E1 00 00 A0 E3 08 D0 4D E2 00 10 A0 E1 07 20 A0 E1 06 30 A0 E1 04 60 8D E5 ?? ?? ?? ?? 00 80 A0 E3 00 40 50 E2 00 80 85 E5 0E 00 00 BA 01 40 84 E2 04 00 A0 E1 ?? ?? ?? ?? 08 00 50 E1 00 00 85 E5 08 00 00 0A 04 10 A0 E1 07 20 A0 E1 06 30 A0 E1 ?? ?? ?? ?? 00 40 50 E2 02 00 00 AA 00 00 95 E5 ?? ?? ?? ?? 00 80 85 E5 04 00 A0 E1 08 D0 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule __stdio_WRITE_6a0125475360332a0d31c4464f55b03a {
	meta:
		aliases = "__stdio_WRITE"
		size = "176"
		objfiles = "_WRITEs@libc.a"
	strings:
		$pattern = { F0 41 2D E9 02 70 A0 E1 00 40 A0 E1 01 60 A0 E1 02 50 A0 E1 02 81 E0 E3 00 00 55 E3 21 00 00 0A 08 20 A0 B1 05 20 A0 A1 06 10 A0 E1 04 00 94 E5 ?? ?? ?? ?? 00 00 50 E3 00 60 86 A0 05 50 60 A0 F4 FF FF AA B0 30 D4 E1 08 10 94 E5 0C 20 94 E5 08 30 83 E3 01 20 52 E0 B0 30 C4 E1 10 00 00 0A 05 00 52 E1 05 20 A0 21 00 30 D6 E5 01 60 86 E2 0A 00 53 E3 00 30 C1 E5 02 00 00 1A B0 30 D4 E1 01 0C 13 E3 02 00 00 1A 01 20 52 E2 01 10 81 E2 F4 FF FF 1A 08 30 94 E5 10 10 84 E5 01 30 63 E0 05 50 63 E0 07 70 65 E0 07 00 A0 E1 F0 81 BD E8 }
	condition:
		$pattern
}

rule writetcp_9bc9d71c47d3ef0812b0b2d83abb2009 {
	meta:
		aliases = "writetcp"
		size = "100"
		objfiles = "clnt_tcps@libc.a"
	strings:
		$pattern = { F0 41 2D E9 02 80 A0 E1 00 70 A0 E1 01 60 A0 E1 02 50 A0 E1 0D 00 00 EA 00 00 97 E5 ?? ?? ?? ?? 01 00 70 E3 00 40 A0 E1 06 00 00 1A ?? ?? ?? ?? 00 20 90 E5 03 30 A0 E3 04 80 A0 E1 24 30 87 E5 28 20 87 E5 04 00 00 EA 00 60 86 E0 05 50 60 E0 00 20 55 E2 06 10 A0 E1 EE FF FF CA 08 00 A0 E1 F0 81 BD E8 }
	condition:
		$pattern
}

rule writeunix_29ff49745ba72ba6ac8bb2ac88b098de {
	meta:
		aliases = "writeunix"
		size = "100"
		objfiles = "clnt_unixs@libc.a"
	strings:
		$pattern = { F0 41 2D E9 02 80 A0 E1 00 70 A0 E1 01 60 A0 E1 02 50 A0 E1 0D 00 00 EA 00 00 97 E5 C7 FF FF EB 01 00 70 E3 00 40 A0 E1 06 00 00 1A ?? ?? ?? ?? 00 20 90 E5 03 30 A0 E3 04 80 A0 E1 84 30 87 E5 88 20 87 E5 04 00 00 EA 00 60 86 E0 05 50 60 E0 00 20 55 E2 06 10 A0 E1 EE FF FF CA 08 00 A0 E1 F0 81 BD E8 }
	condition:
		$pattern
}

rule getgrouplist_63419f9d7004ab243618b03d37ab1e32 {
	meta:
		aliases = "getgrouplist"
		size = "124"
		objfiles = "getgrouplists@libc.a"
	strings:
		$pattern = { F0 41 2D E9 02 80 A0 E1 03 20 A0 E1 03 40 A0 E1 01 70 A0 E1 00 50 93 E5 ?? ?? ?? ?? 00 60 50 E2 04 00 00 1A 00 00 55 E3 01 50 A0 13 00 70 88 15 0F 00 00 1A 0D 00 00 EA 00 30 94 E5 03 00 55 E1 03 50 A0 A1 00 00 55 E3 03 00 00 0A 08 00 A0 E1 06 10 A0 E1 05 21 A0 E1 ?? ?? ?? ?? 06 00 A0 E1 ?? ?? ?? ?? 00 30 94 E5 03 00 55 E1 00 00 00 AA 00 50 E0 E3 05 00 A0 E1 F0 81 BD E8 }
	condition:
		$pattern
}

rule authunix_create_default_9ace72860e16a936b1fbb866e0c4200b {
	meta:
		aliases = "__GI_authunix_create_default, authunix_create_default"
		size = "176"
		objfiles = "auth_unixs@libc.a"
	strings:
		$pattern = { F0 41 2D E9 03 00 A0 E3 42 DF 4D E2 ?? ?? ?? ?? 00 40 50 E2 04 50 A0 01 04 00 00 0A 04 01 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 50 A0 11 10 00 00 0A 08 80 8D E2 08 00 A0 E1 FF 10 A0 E3 ?? ?? ?? ?? 01 00 70 E3 0A 00 00 0A 00 30 A0 E3 07 31 CD E5 ?? ?? ?? ?? 00 70 A0 E1 ?? ?? ?? ?? 05 10 A0 E1 00 60 A0 E1 04 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 00 00 AA ?? ?? ?? ?? 10 00 50 E3 00 30 A0 B1 10 30 A0 A3 07 10 A0 E1 06 20 A0 E1 08 00 A0 E1 00 50 8D E5 ?? ?? ?? ?? 00 40 A0 E1 05 00 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 42 DF 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule __GI_lockf64_d54f401ac1b8021aeb32d03cac0badb6 {
	meta:
		aliases = "lockf64, __GI_lockf64"
		size = "300"
		objfiles = "lockf64s@libc.a"
	strings:
		$pattern = { F0 41 2D E9 03 60 A0 E1 02 30 A0 E1 C3 4F A0 E1 04 00 56 E1 20 D0 4D E2 02 50 A0 E1 00 80 A0 E1 01 70 A0 E1 03 00 00 0A ?? ?? ?? ?? 00 20 E0 E3 4B 30 A0 E3 36 00 00 EA 0D 00 A0 E1 00 10 A0 E3 20 20 A0 E3 ?? ?? ?? ?? 00 40 A0 E3 00 30 A0 E3 08 30 8D E5 0C 40 8D E5 01 30 A0 E3 10 50 8D E5 14 60 8D E5 B2 30 CD E1 03 00 57 E3 07 F1 8F 90 24 00 00 EA 16 00 00 EA 18 00 00 EA 19 00 00 EA FF FF FF EA 0D 20 A0 E1 00 30 A0 E3 08 00 A0 E1 0C 10 A0 E3 B0 30 CD E1 ?? ?? ?? ?? 00 00 50 E3 00 20 E0 B3 1D 00 00 BA F0 30 DD E1 02 00 53 E3 19 00 00 0A 18 40 9D E5 ?? ?? ?? ?? 00 00 54 E1 15 00 00 0A ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_unsetenv_cccca82df73e23622d9e75d442a7bf1c {
	meta:
		aliases = "unsetenv, __GI_unsetenv"
		size = "300"
		objfiles = "setenvs@libc.a"
	strings:
		$pattern = { F0 41 2D E9 04 61 9F E5 00 70 50 E2 10 D0 4D E2 06 60 8F E0 06 00 00 0A 00 30 D7 E5 00 00 53 E3 03 00 00 0A 3D 10 A0 E3 ?? ?? ?? ?? 00 00 50 E3 04 00 00 0A ?? ?? ?? ?? 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 2E 00 00 EA 07 00 A0 E1 ?? ?? ?? ?? BC 40 9F E5 BC 30 9F E5 04 40 86 E0 03 10 96 E7 04 20 A0 E1 B0 30 9F E5 00 80 A0 E1 0D 00 A0 E1 0F E0 A0 E1 03 F0 96 E7 A0 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 96 E7 94 30 9F E5 03 30 96 E7 00 50 93 E5 11 00 00 EA 04 00 A0 E1 07 10 A0 E1 08 20 A0 E1 ?? ?? ?? ?? 00 00 50 E3 0A 00 00 1A 08 30 D4 E7 3D 00 53 E3 07 00 00 1A 05 10 A0 E1 04 30 91 E5 04 20 81 E2 }
	condition:
		$pattern
}

rule logwtmp_36de64dfb2ecd1d23b1ff8880b64bc4f {
	meta:
		aliases = "logwtmp"
		size = "192"
		objfiles = "logwtmps@libutil.a"
	strings:
		$pattern = { F0 41 2D E9 06 DD 4D E2 01 50 A0 E1 00 70 A0 E1 02 80 A0 E1 98 60 9F E5 0D 00 A0 E1 00 10 A0 E3 06 2D A0 E3 ?? ?? ?? ?? 00 00 55 E3 06 60 8F E0 03 00 00 0A 00 30 D5 E5 00 00 53 E3 07 20 A0 13 00 00 00 1A 08 20 A0 E3 68 30 9F E5 06 1D 8D E2 B3 20 81 E1 ?? ?? ?? ?? 07 10 A0 E1 04 00 8D E5 1F 20 A0 E3 08 00 8D E2 ?? ?? ?? ?? 05 10 A0 E1 1F 20 A0 E3 2C 00 8D E2 ?? ?? ?? ?? 08 10 A0 E1 FF 20 A0 E3 4C 00 8D E2 ?? ?? ?? ?? 00 10 A0 E3 55 0F 8D E2 ?? ?? ?? ?? 1C 00 9F E5 0D 10 A0 E1 00 00 86 E0 0D 40 A0 E1 ?? ?? ?? ?? 06 DD 8D E2 F0 81 BD E8 ?? ?? ?? ?? 80 FE FF FF ?? ?? ?? ?? }
	condition:
		$pattern
}

rule readtcp_2e6fbbd9e506ae028139ee70aba911bb {
	meta:
		aliases = "readtcp"
		size = "180"
		objfiles = "svc_tcps@libc.a"
	strings:
		$pattern = { F0 41 2D E9 08 D0 4D E2 00 40 90 E5 00 50 A0 E1 01 60 A0 E1 02 70 A0 E1 0D 80 A0 E1 01 30 A0 E3 01 10 A0 E3 84 20 9F E5 0D 00 A0 E1 00 40 8D E5 B4 30 CD E1 ?? ?? ?? ?? 01 00 70 E3 02 00 00 0A 00 00 50 E3 13 00 00 0A 04 00 00 EA ?? ?? ?? ?? 00 30 90 E5 04 00 53 E3 05 00 00 0A 0D 00 00 EA B6 30 DD E1 18 00 13 E3 0A 00 00 1A 20 00 13 E3 08 00 00 1A B6 30 DD E1 01 00 13 E3 E6 FF FF 0A 04 00 A0 E1 06 10 A0 E1 07 20 A0 E1 ?? ?? ?? ?? 00 00 50 E3 03 00 00 CA 2C 20 95 E5 00 30 A0 E3 00 30 82 E5 00 00 E0 E3 08 D0 8D E2 F0 81 BD E8 B8 88 00 00 }
	condition:
		$pattern
}

rule xdr_rmtcall_args_bf33467af51aea64abdbf509e6e1ff06 {
	meta:
		aliases = "__GI_xdr_rmtcall_args, xdr_rmtcall_args"
		size = "272"
		objfiles = "pmap_rmts@libc.a"
	strings:
		$pattern = { F0 41 2D E9 08 D0 4D E2 00 50 A0 E1 01 60 A0 E1 ?? ?? ?? ?? 00 00 50 E3 39 00 00 0A 05 00 A0 E1 04 10 86 E2 ?? ?? ?? ?? 00 00 50 E3 34 00 00 0A 05 00 A0 E1 08 10 86 E2 ?? ?? ?? ?? 00 00 50 E3 2F 00 00 0A 08 40 8D E2 00 30 A0 E3 04 30 24 E5 04 30 95 E5 05 00 A0 E1 0F E0 A0 E1 10 F0 93 E5 04 10 A0 E1 00 80 A0 E1 05 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 22 00 00 0A 04 30 95 E5 05 00 A0 E1 0F E0 A0 E1 10 F0 93 E5 10 10 96 E5 00 70 A0 E1 05 00 A0 E1 0F E0 A0 E1 14 F0 96 E5 00 00 50 E3 17 00 00 0A 04 30 95 E5 05 00 A0 E1 0F E0 A0 E1 10 F0 93 E5 00 30 67 E0 0C 30 A6 E5 08 10 A0 E1 04 30 95 E5 00 40 A0 E1 }
	condition:
		$pattern
}

rule encrypt_2347c7449859b561e5ee53f229c09717 {
	meta:
		aliases = "encrypt"
		size = "276"
		objfiles = "dess@libcrypt.a"
	strings:
		$pattern = { F0 41 2D E9 10 D0 4D E2 00 70 A0 E1 01 60 A0 E1 3E FC FF EB 00 00 A0 E3 B8 FD FF EB E8 40 9F E5 E8 30 9F E5 04 40 8F E0 00 C0 A0 E3 03 80 84 E0 07 00 A0 E1 0C 50 A0 E1 10 00 00 EA 10 20 8D E2 0C 31 82 E0 03 E0 A0 E1 05 10 A0 E1 08 50 03 E5 07 00 00 EA 00 30 D0 E5 01 00 80 E2 01 00 13 E3 01 31 98 17 08 20 1E 15 01 10 81 E2 02 30 83 11 08 30 0E 15 1F 00 51 E3 F5 FF FF DA 01 C0 8C E2 01 00 5C E3 EC FF FF DA 00 00 56 E3 08 20 8D E2 01 C0 A0 03 00 C0 E0 13 04 30 82 E2 08 00 9D E5 0C 10 9D E5 00 C0 8D E5 97 FE FF EB 5C 30 9F E5 00 C0 A0 E3 03 60 84 E0 0C 50 A0 E1 0A 00 00 EA 08 30 1E E5 00 21 96 E7 }
	condition:
		$pattern
}

rule __GI_xdr_union_b61b07c62681ca52efceadf160eb7915 {
	meta:
		aliases = "xdr_union, __GI_xdr_union"
		size = "124"
		objfiles = "xdrs@libc.a"
	strings:
		$pattern = { F0 41 2D E9 18 60 9D E5 01 50 A0 E1 02 80 A0 E1 03 40 A0 E1 00 70 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 10 95 15 F0 81 BD 08 08 00 00 EA 00 30 94 E5 08 40 84 E2 01 00 53 E1 04 00 00 1A 07 00 A0 E1 08 10 A0 E1 00 20 E0 E3 3C FF 2F E1 F0 81 BD E8 04 C0 94 E5 00 00 5C E3 F3 FF FF 1A 00 00 56 E3 06 00 A0 01 F0 81 BD 08 07 00 A0 E1 08 10 A0 E1 00 20 E0 E3 36 FF 2F E1 F0 81 BD E8 }
	condition:
		$pattern
}

rule lfind_a6b473ebb547d8eb02c69b7f8d81b5ac {
	meta:
		aliases = "__GI_lfind, lfind"
		size = "76"
		objfiles = "lfinds@libc.a"
	strings:
		$pattern = { F0 41 2D E9 18 80 9D E5 00 50 92 E5 00 70 A0 E1 01 40 A0 E1 03 60 A0 E1 05 00 00 EA 38 FF 2F E1 00 00 50 E3 01 00 00 1A 04 00 A0 E1 F0 81 BD E8 06 40 84 E0 01 50 55 E2 04 10 A0 E1 07 00 A0 E1 F5 FF FF 2A 00 00 A0 E3 F0 81 BD E8 }
	condition:
		$pattern
}

rule __GI_sgetspent_r_1f3b710496d8c098a20dca1a4888f2cb {
	meta:
		aliases = "sgetspent_r, __GI_sgetspent_r"
		size = "120"
		objfiles = "sgetspent_rs@libc.a"
	strings:
		$pattern = { F0 41 2D E9 18 80 9D E5 03 60 A0 E1 FF 00 53 E3 00 30 A0 E3 00 30 88 E5 01 70 A0 E1 02 40 A0 E1 00 50 A0 E1 04 00 00 8A ?? ?? ?? ?? 22 30 A0 E3 03 20 A0 E1 00 30 80 E5 0C 00 00 EA 02 00 50 E1 05 00 00 0A ?? ?? ?? ?? 06 00 50 E1 F5 FF FF 2A 05 10 A0 E1 04 00 A0 E1 ?? ?? ?? ?? 04 10 A0 E1 07 00 A0 E1 ?? ?? ?? ?? 00 20 50 E2 00 70 88 05 02 00 A0 E1 F0 81 BD E8 }
	condition:
		$pattern
}

rule fseeko64_0d0956749dab29e514ad9168eb92c9f4 {
	meta:
		aliases = "__GI_fseeko64, fseeko64"
		size = "316"
		objfiles = "fseeko64s@libc.a"
	strings:
		$pattern = { F0 41 2D E9 18 D0 4D E2 30 70 9D E5 14 61 9F E5 02 00 57 E3 10 20 8D E5 14 30 8D E5 06 60 8F E0 00 50 A0 E1 04 00 00 9A ?? ?? ?? ?? 00 40 E0 E3 16 30 A0 E3 00 30 80 E5 37 00 00 EA 34 80 90 E5 00 00 58 E3 0B 00 00 1A DC 30 9F E5 38 40 80 E2 03 10 96 E7 0D 00 A0 E1 D0 30 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 C0 30 9F E5 0F E0 A0 E1 03 F0 96 E7 B0 30 D5 E1 40 00 13 E3 03 00 00 0A 05 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 19 00 00 1A 01 00 57 E3 04 00 00 1A 05 00 A0 E1 10 10 8D E2 ?? ?? ?? ?? 00 00 50 E3 12 00 00 BA 07 20 A0 E1 05 00 A0 E1 10 10 8D E2 ?? ?? ?? ?? 00 00 50 E3 0C 00 00 BA }
	condition:
		$pattern
}

rule __aeabi_uwrite8_a9ef8298238c34571d006a12e5d83836 {
	meta:
		aliases = "__aeabi_uwrite8"
		size = "68"
		objfiles = "unaligned_funcs@libgcc.a"
	strings:
		$pattern = { F0 41 2D E9 21 CC A0 E1 20 E4 A0 E1 20 58 A0 E1 20 6C A0 E1 21 74 A0 E1 21 88 A0 E1 01 40 A0 E1 07 C0 C2 E5 01 E0 C2 E5 02 50 C2 E5 03 60 C2 E5 05 70 C2 E5 06 80 C2 E5 00 00 C2 E5 04 10 C2 E5 F0 81 BD E8 }
	condition:
		$pattern
}

rule sysctl_08e2aae08732b92f3980f63f51f2842d {
	meta:
		aliases = "sysctl"
		size = "120"
		objfiles = "sysctls@libc.a"
	strings:
		$pattern = { F0 41 2D E9 28 D0 4D E2 00 40 A0 E1 01 50 A0 E1 02 60 A0 E1 0D 00 A0 E1 00 10 A0 E3 28 20 A0 E3 03 70 A0 E1 ?? ?? ?? ?? 40 30 9D E5 0C 70 8D E5 10 30 8D E5 44 30 9D E5 0D 80 A0 E1 70 00 8D E8 14 30 8D E5 0D 00 A0 E1 95 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 28 D0 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule sigaction_024b0710001d9676b22428a4b6ee2204 {
	meta:
		aliases = "__GI_sigaction, sigaction"
		size = "340"
		objfiles = "signalss@libpthread.a"
	strings:
		$pattern = { F0 41 2D E9 2C 61 9F E5 2C 31 9F E5 06 60 8F E0 03 30 96 E7 90 D0 4D E2 00 30 93 E5 00 40 A0 E1 03 00 50 E1 02 80 A0 E1 01 70 A0 E1 3C 00 00 0A 08 31 9F E5 03 30 96 E7 00 30 93 E5 03 00 50 E1 37 00 00 0A F8 30 9F E5 03 30 96 E7 00 30 93 E5 03 00 50 E1 01 00 00 1A 00 00 50 E3 30 00 00 CA 00 00 57 E3 07 00 A0 01 17 00 00 0A 04 50 8D E2 05 00 A0 E1 8C 20 A0 E3 ?? ?? ?? ?? 00 30 97 E5 01 00 53 E3 00 30 A0 93 01 30 A0 83 00 00 54 E3 00 30 A0 D3 00 00 53 E3 0A 00 00 0A 40 00 54 E3 08 00 00 CA 84 30 97 E5 04 00 13 E3 94 30 9F 15 05 00 A0 11 90 30 9F 05 05 00 A0 01 03 30 86 E0 04 30 8D E5 00 00 00 EA }
	condition:
		$pattern
}

rule fsetpos_63a0734cef94c8950dd7872d9fe10553 {
	meta:
		aliases = "fsetpos"
		size = "192"
		objfiles = "fsetposs@libc.a"
	strings:
		$pattern = { F0 41 2D E9 34 80 90 E5 9C 70 9F E5 00 00 58 E3 10 D0 4D E2 00 50 A0 E1 07 70 8F E0 01 60 A0 E1 0B 00 00 1A 84 30 9F E5 38 40 80 E2 03 10 97 E7 0D 00 A0 E1 78 30 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 97 E7 04 00 A0 E1 68 30 9F E5 0F E0 A0 E1 03 F0 97 E7 05 00 A0 E1 00 10 96 E5 00 20 A0 E3 ?? ?? ?? ?? 00 40 50 E2 05 00 00 1A 04 30 96 E5 08 20 96 E5 2C 30 85 E5 30 20 85 E5 0C 30 96 E5 02 30 C5 E5 00 00 58 E3 04 00 00 1A 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 97 E7 04 00 A0 E1 10 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fgetpos_653e2ab3373e6d53dddda17d9a13cff3 {
	meta:
		aliases = "fgetpos"
		size = "192"
		objfiles = "fgetposs@libc.a"
	strings:
		$pattern = { F0 41 2D E9 34 80 90 E5 9C 70 9F E5 00 00 58 E3 10 D0 4D E2 00 50 A0 E1 07 70 8F E0 01 60 A0 E1 0B 00 00 1A 84 30 9F E5 38 40 80 E2 03 10 97 E7 0D 00 A0 E1 78 30 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 97 E7 04 00 A0 E1 68 30 9F E5 0F E0 A0 E1 03 F0 97 E7 05 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 00 86 E5 2C 30 95 A5 30 20 95 A5 04 30 86 A5 08 20 86 A5 02 30 D5 A5 00 40 E0 B3 00 40 A0 A3 0C 30 86 A5 00 00 58 E3 04 00 00 1A 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 97 E7 04 00 A0 E1 10 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fgetpos64_0394ee82f0d562deb0640c5767cb5e1a {
	meta:
		aliases = "fgetpos64"
		size = "192"
		objfiles = "fgetpos64s@libc.a"
	strings:
		$pattern = { F0 41 2D E9 34 80 90 E5 9C 70 9F E5 00 00 58 E3 10 D0 4D E2 00 50 A0 E1 07 70 8F E0 01 60 A0 E1 0B 00 00 1A 84 30 9F E5 38 40 80 E2 03 10 97 E7 0D 00 A0 E1 78 30 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 97 E7 04 00 A0 E1 68 30 9F E5 0F E0 A0 E1 03 F0 97 E7 05 00 A0 E1 ?? ?? ?? ?? 03 00 86 E8 00 00 51 E3 2C 30 95 A5 30 20 95 A5 08 30 86 A5 0C 20 86 A5 02 30 D5 A5 00 40 E0 B3 00 40 A0 A3 10 30 86 A5 00 00 58 E3 04 00 00 1A 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 97 E7 04 00 A0 E1 10 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fwide_d11d01a8840f13142f43aa405d4b484d {
	meta:
		aliases = "fwide"
		size = "196"
		objfiles = "fwides@libc.a"
	strings:
		$pattern = { F0 41 2D E9 34 80 90 E5 A0 60 9F E5 00 00 58 E3 10 D0 4D E2 00 50 A0 E1 06 60 8F E0 01 70 A0 E1 0B 00 00 1A 88 30 9F E5 38 40 80 E2 03 10 96 E7 0D 00 A0 E1 7C 30 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 6C 30 9F E5 0F E0 A0 E1 03 F0 96 E7 00 00 57 E3 07 00 00 0A B0 10 D5 E1 22 0D 11 E3 04 00 00 1A 00 00 57 E3 80 30 A0 D3 02 3B A0 C3 01 30 83 E1 B0 30 C5 E1 00 00 58 E3 B0 40 D5 E1 04 00 00 1A 0D 00 A0 E1 01 10 A0 E3 28 30 9F E5 0F E0 A0 E1 03 F0 96 E7 80 30 04 E2 02 0B 04 E2 00 00 63 E0 10 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fsetpos64_da757dfe8ac1e8c1569fd400dd7ab77f {
	meta:
		aliases = "fsetpos64"
		size = "196"
		objfiles = "fsetpos64s@libc.a"
	strings:
		$pattern = { F0 41 2D E9 34 80 90 E5 A0 70 9F E5 00 00 58 E3 18 D0 4D E2 00 50 A0 E1 07 70 8F E0 01 60 A0 E1 0B 00 00 1A 88 30 9F E5 38 40 80 E2 03 10 97 E7 08 00 8D E2 7C 30 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 97 E7 04 00 A0 E1 6C 30 9F E5 0F E0 A0 E1 03 F0 97 E7 0C 00 96 E8 00 10 A0 E3 05 00 A0 E1 00 10 8D E5 ?? ?? ?? ?? 00 40 50 E2 05 00 00 1A 08 30 96 E5 0C 20 96 E5 2C 30 85 E5 30 20 85 E5 10 30 96 E5 02 30 C5 E5 00 00 58 E3 04 00 00 1A 08 00 8D E2 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 97 E7 04 00 A0 E1 18 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ungetc_41ed9c763fdfdc82739411fe01ec9b32 {
	meta:
		aliases = "__GI_ungetc, ungetc"
		size = "356"
		objfiles = "ungetcs@libc.a"
	strings:
		$pattern = { F0 41 2D E9 34 80 91 E5 40 71 9F E5 00 00 58 E3 10 D0 4D E2 01 50 A0 E1 07 70 8F E0 00 60 A0 E1 0B 00 00 1A 28 31 9F E5 38 40 81 E2 0D 00 A0 E1 03 10 97 E7 04 20 A0 E1 18 31 9F E5 0F E0 A0 E1 03 F0 97 E7 04 00 A0 E1 0C 31 9F E5 0F E0 A0 E1 03 F0 97 E7 10 10 95 E5 18 30 95 E5 01 00 76 E3 03 00 51 11 0C 00 00 2A 08 30 95 E5 03 00 51 E1 09 00 00 9A 01 20 51 E5 FF 30 06 E2 03 00 52 E1 05 00 00 1A B0 30 D5 E1 01 20 41 E2 04 30 C3 E3 B0 30 C5 E1 10 20 85 E5 22 00 00 EA B0 30 D5 E1 83 30 03 E2 80 00 53 E3 04 00 00 8A 05 00 A0 E1 80 10 A0 E3 ?? ?? ?? ?? 00 00 50 E3 18 00 00 1A B0 20 D5 E1 02 00 12 E3 }
	condition:
		$pattern
}

rule __GI_fputs_ac1d452bfd8a3b35bd24e94d2878371f {
	meta:
		aliases = "putwc, __GI_fputws, fputwc, fputws, fputs, __GI_fputs"
		size = "160"
		objfiles = "fputss@libc.a, fputwcs@libc.a, fputwss@libc.a"
	strings:
		$pattern = { F0 41 2D E9 34 80 91 E5 7C 50 9F E5 00 00 58 E3 10 D0 4D E2 01 60 A0 E1 05 50 8F E0 00 70 A0 E1 0B 00 00 1A 64 30 9F E5 38 40 81 E2 0D 00 A0 E1 03 10 95 E7 04 20 A0 E1 54 30 9F E5 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 48 30 9F E5 0F E0 A0 E1 03 F0 95 E7 07 00 A0 E1 06 10 A0 E1 ?? ?? ?? ?? 00 00 58 E3 00 40 A0 E1 04 00 00 1A 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 10 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_ungetwc_efd9e308c914a285cabbac4f0f365368 {
	meta:
		aliases = "ungetwc, __GI_ungetwc"
		size = "284"
		objfiles = "ungetwcs@libc.a"
	strings:
		$pattern = { F0 41 2D E9 34 80 91 E5 F4 60 9F E5 00 00 58 E3 10 D0 4D E2 01 50 A0 E1 06 60 8F E0 00 70 A0 E1 0B 00 00 1A DC 30 9F E5 38 40 81 E2 0D 00 A0 E1 03 10 96 E7 04 20 A0 E1 CC 30 9F E5 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 C0 30 9F E5 0F E0 A0 E1 03 F0 96 E7 B0 20 D5 E1 B4 30 9F E5 03 30 02 E0 02 0B 53 E3 04 00 00 8A 05 00 A0 E1 02 1B A0 E3 ?? ?? ?? ?? 00 00 50 E3 16 00 00 1A B0 20 D5 E1 02 00 12 E3 04 00 00 0A 01 00 12 E3 11 00 00 1A 28 30 95 E5 00 00 53 E3 0E 00 00 1A 01 00 77 E3 0C 00 00 0A 01 30 82 E2 03 38 A0 E1 23 38 A0 E1 B0 30 C5 E1 B0 20 D5 E1 01 30 03 E2 04 20 C2 E3 03 31 85 E0 B0 20 C5 E1 }
	condition:
		$pattern
}

rule _stdio_openlist_dec_use_924acbd34f7106cdcec668e0a4e68fe2 {
	meta:
		aliases = "_stdio_openlist_dec_use"
		size = "368"
		objfiles = "fflush_unlockeds@libc.a"
	strings:
		$pattern = { F0 41 2D E9 38 61 9F E5 38 31 9F E5 06 60 8F E0 03 70 96 E7 30 31 9F E5 20 D0 4D E2 03 40 96 E7 28 31 9F E5 07 10 A0 E1 03 80 96 E7 04 20 A0 E1 10 00 8D E2 38 FF 2F E1 14 31 9F E5 04 00 A0 E1 03 50 96 E7 35 FF 2F E1 08 31 9F E5 03 30 96 E7 00 30 93 E5 01 00 53 E3 2D 00 00 1A F8 30 9F E5 03 30 96 E7 00 30 93 E5 00 00 53 E3 28 00 00 DA E8 30 9F E5 07 10 A0 E1 03 40 96 E7 0D 00 A0 E1 04 20 A0 E1 38 FF 2F E1 04 00 A0 E1 35 FF 2F E1 CC 30 9F E5 00 70 A0 E3 03 20 96 E7 03 80 A0 E1 00 40 92 E5 0F 00 00 EA B0 30 D4 E1 20 50 94 E5 02 20 03 E0 30 00 52 E3 04 70 A0 11 08 00 00 1A 00 00 57 E3 08 30 96 07 }
	condition:
		$pattern
}

rule pmap_unset_dfe7a7171ab1171fbd95dcc1f59a82d0 {
	meta:
		aliases = "__GI_pmap_unset, pmap_unset"
		size = "268"
		objfiles = "pmap_clnts@libc.a"
	strings:
		$pattern = { F0 41 2D E9 38 D0 4D E2 20 40 8D E2 00 30 E0 E3 00 80 A0 E1 04 00 A0 E1 34 30 8D E5 01 70 A0 E1 9F FF FF EB C8 50 9F E5 00 00 50 E3 05 50 8F E0 2C 00 00 0A BC 20 9F E5 04 00 A0 E1 02 30 85 E0 04 40 93 E5 19 EE A0 E3 02 30 95 E7 34 C0 8D E2 A4 10 9F E5 02 20 A0 E3 04 C0 8D E5 0C E0 8D E5 00 40 8D E5 08 E0 8D E5 ?? ?? ?? ?? 00 60 50 E2 1C 00 00 0A 00 30 A0 E3 1C 30 8D E5 18 30 8D E5 78 30 9F E5 78 10 9F E5 10 80 8D E5 14 70 8D E5 03 30 85 E0 6C 20 9F E5 04 40 96 E5 08 C0 8D E2 00 30 8D E5 01 10 85 E0 30 30 8D E2 03 00 91 E8 04 30 8D E5 02 20 85 E0 03 00 8C E8 10 30 8D E2 02 10 A0 E3 06 00 A0 E1 }
	condition:
		$pattern
}

rule clnt_sperror_091c511b4965c86ada2bfa351ab40b9f {
	meta:
		aliases = "__GI_clnt_sperror, clnt_sperror"
		size = "516"
		objfiles = "clnt_perrors@libc.a"
	strings:
		$pattern = { F0 41 2D E9 41 DE 4D E2 00 40 A0 E1 01 50 A0 E1 9A FF FF EB C4 71 9F E5 00 80 50 E2 07 70 8F E0 6B 00 00 0A 01 1B 8D E2 04 30 94 E5 04 00 A0 E1 04 10 81 E2 0F E0 A0 E1 08 F0 93 E5 A0 11 9F E5 05 20 A0 E1 01 10 87 E0 08 00 A0 E1 ?? ?? ?? ?? 00 40 88 E0 04 04 9D E5 ?? ?? ?? ?? 00 10 A0 E1 04 00 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 ?? ?? ?? ?? 04 34 9D E5 00 50 84 E0 11 00 53 E3 03 F1 8F 90 48 00 00 EA 4E 00 00 EA 4D 00 00 EA 4C 00 00 EA 0D 00 00 EA 0C 00 00 EA 49 00 00 EA 3E 00 00 EA 15 00 00 EA 46 00 00 EA 3B 00 00 EA 44 00 00 EA 43 00 00 EA 42 00 00 EA 41 00 00 EA 40 00 00 EA 3F 00 00 EA 3E 00 00 EA }
	condition:
		$pattern
}

rule __GI_vswscanf_1fc9fd6a8126ef17078551be7661736d {
	meta:
		aliases = "vswscanf, __GI_vswscanf"
		size = "132"
		objfiles = "vswscanfs@libc.a"
	strings:
		$pattern = { F0 41 2D E9 50 D0 4D E2 10 00 8D E5 08 00 8D E5 00 40 A0 E1 01 70 A0 E1 02 80 A0 E1 ?? ?? ?? ?? 02 30 E0 E3 04 30 8D E5 50 30 9F E5 00 21 84 E0 00 50 A0 E3 38 00 8D E2 B0 30 CD E1 82 3E 43 E2 14 20 8D E5 0C 20 8D E5 1C 40 8D E5 34 30 8D E5 18 40 8D E5 02 50 CD E5 2C 50 8D E5 ?? ?? ?? ?? 0D 00 A0 E1 07 10 A0 E1 08 20 A0 E1 0D 60 A0 E1 20 50 8D E5 ?? ?? ?? ?? 50 D0 8D E2 F0 81 BD E8 21 08 00 00 }
	condition:
		$pattern
}

rule __popcountdi2_1742b391a96d40dcc21d3fd6d4411189 {
	meta:
		aliases = "__popcountdi2"
		size = "108"
		objfiles = "_popcountdi2@libgcc.a"
	strings:
		$pattern = { F0 41 2D E9 58 70 9F E5 58 80 9F E5 07 70 8F E0 08 20 97 E7 FF 30 00 E2 00 50 A0 E1 01 60 A0 E1 03 E0 D2 E7 08 C0 A0 E3 35 3C A0 E1 20 20 6C E2 16 32 83 E1 20 10 5C E2 36 31 A0 51 08 00 97 E7 FF 30 03 E2 36 4C A0 E1 03 20 D0 E7 08 C0 8C E2 40 00 5C E3 02 E0 8E E0 F2 FF FF 1A 0E 00 A0 E1 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule malloc_97185b071b915bdf2e5c90ba157a89da {
	meta:
		aliases = "malloc"
		size = "388"
		objfiles = "mallocs@libc.a"
	strings:
		$pattern = { F0 41 2D E9 5C 61 9F E5 00 00 50 E3 06 60 8F E0 08 D0 4D E2 01 00 A0 03 01 00 00 0A 08 00 70 E3 49 00 00 8A 40 31 9F E5 04 20 80 E2 03 50 96 E7 38 31 9F E5 08 40 8D E2 04 20 24 E5 03 70 96 E7 05 00 A0 E1 37 FF 2F E1 24 31 9F E5 04 10 A0 E1 03 00 96 E7 ?? ?? ?? ?? 18 31 9F E5 00 40 A0 E1 05 00 A0 E1 0F E0 A0 E1 03 F0 96 E7 00 00 54 E3 31 00 00 1A 00 31 9F E5 04 10 9D E5 03 30 96 E7 00 40 93 E5 04 00 51 E1 04 30 81 20 01 30 43 22 00 20 64 22 02 40 03 20 E0 30 9F E5 03 00 96 E7 37 FF 2F E1 04 00 A0 E1 ?? ?? ?? ?? 01 00 70 E3 00 70 A0 01 05 00 00 0A 03 30 80 E2 03 70 C3 E3 07 00 50 E1 01 00 00 0A }
	condition:
		$pattern
}

rule __GI_openlog_cff2436884bc9e23d87ea3cc9b4ed45c {
	meta:
		aliases = "openlog, __GI_openlog"
		size = "412"
		objfiles = "syslogs@libc.a"
	strings:
		$pattern = { F0 41 2D E9 60 51 9F E5 60 41 9F E5 05 50 8F E0 5C 31 9F E5 10 D0 4D E2 04 40 85 E0 00 70 A0 E1 01 80 A0 E1 0D 00 A0 E1 03 10 95 E7 02 60 A0 E1 40 31 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 30 31 9F E5 0F E0 A0 E1 03 F0 95 E7 00 00 57 E3 24 31 9F 15 03 70 85 17 20 31 9F E5 00 00 56 E3 03 80 85 E7 02 00 00 0A FE 3F D6 E3 10 31 9F 05 03 60 85 07 0C 31 9F E5 03 30 95 E7 01 00 73 E3 02 80 A0 13 17 00 00 1A 02 80 A0 E3 EC 30 9F E5 03 30 95 E7 08 00 13 E3 12 00 00 0A 01 00 A0 E3 08 10 A0 E1 00 20 A0 E3 ?? ?? ?? ?? D4 40 9F E5 01 00 70 E3 04 00 85 E7 23 00 00 0A 01 20 A0 E3 02 10 A0 E3 }
	condition:
		$pattern
}

rule __cxa_finalize_43e9dab9499c39e82a6b6b5eb2a20de1 {
	meta:
		aliases = "__cxa_finalize"
		size = "124"
		objfiles = "__cxa_finalizes@libc.a"
	strings:
		$pattern = { F0 41 2D E9 64 50 9F E5 64 30 9F E5 05 50 8F E0 03 40 95 E7 5C 80 9F E5 00 60 A0 E1 00 70 A0 E3 0D 00 00 EA 08 10 95 E7 00 00 56 E3 01 20 80 E0 02 00 00 0A 0C 30 92 E5 03 00 56 E1 06 00 00 1A 01 30 90 E7 03 00 53 E3 03 00 00 1A 01 70 80 E7 08 00 92 E5 0F E0 A0 E1 04 F0 92 E5 00 00 54 E3 01 40 44 E2 04 02 A0 E1 ED FF FF 1A F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pmap_getmaps_49c1a97c9e07580abcaf9de7b07231ab {
	meta:
		aliases = "pmap_getmaps"
		size = "244"
		objfiles = "pm_getmapss@libc.a"
	strings:
		$pattern = { F0 41 2D E9 6F 3C A0 E3 20 D0 4D E2 00 C0 E0 E3 B2 30 C0 E1 18 C0 8D E5 33 C0 8C E2 00 C0 8D E5 00 70 A0 E3 7D CF A0 E3 B0 10 9F E5 02 20 A0 E3 18 30 8D E2 00 80 A0 E1 04 C0 8D E5 1C 70 8D E5 ?? ?? ?? ?? 98 60 9F E5 00 50 50 E2 06 60 8F E0 1D 00 00 0A 04 30 95 E5 88 20 9F E5 00 40 93 E5 3C 30 A0 E3 10 30 8D E5 7C 30 9F E5 14 70 8D E5 03 30 86 E0 00 30 8D E5 1C 30 8D E2 04 30 8D E5 08 C0 8D E2 10 10 8D E2 03 00 91 E8 02 20 86 E0 03 00 8C E8 07 30 A0 E1 05 00 A0 E1 04 10 A0 E3 34 FF 2F E1 07 00 50 E1 03 00 00 0A 3C 10 9F E5 05 00 A0 E1 01 10 86 E0 ?? ?? ?? ?? 05 00 A0 E1 04 30 95 E5 0F E0 A0 E1 }
	condition:
		$pattern
}

rule seekdir_afd247f4820f05bf03f92fd93f3af420 {
	meta:
		aliases = "seekdir"
		size = "156"
		objfiles = "seekdirs@libc.a"
	strings:
		$pattern = { F0 41 2D E9 7C 40 9F E5 7C 30 9F E5 10 D0 4D E2 04 40 8F E0 18 60 80 E2 00 50 A0 E1 06 20 A0 E1 01 70 A0 E1 0D 00 A0 E1 03 10 94 E7 5C 30 9F E5 0F E0 A0 E1 03 F0 94 E7 54 30 9F E5 06 00 A0 E1 0F E0 A0 E1 03 F0 94 E7 07 10 A0 E1 00 00 95 E5 00 20 A0 E3 ?? ?? ?? ?? 00 30 A0 E3 08 30 85 E5 10 00 85 E5 04 30 85 E5 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0D 80 A0 E1 0F E0 A0 E1 03 F0 94 E7 10 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _time_mktime_83b58883ef4ad318208f4de8d436d9f5 {
	meta:
		aliases = "_time_mktime"
		size = "168"
		objfiles = "_time_mktimes@libc.a"
	strings:
		$pattern = { F0 41 2D E9 80 40 9F E5 80 30 9F E5 04 40 8F E0 03 50 94 E7 78 30 9F E5 10 D0 4D E2 05 20 A0 E1 00 80 A0 E1 01 60 A0 E1 0D 00 A0 E1 03 10 94 E7 60 30 9F E5 0F E0 A0 E1 03 F0 94 E7 58 30 9F E5 05 00 A0 E1 0F E0 A0 E1 03 F0 94 E7 ?? ?? ?? ?? 48 20 9F E5 06 10 A0 E1 02 20 84 E0 08 00 A0 E1 ?? ?? ?? ?? 01 10 A0 E3 00 50 A0 E1 30 30 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 94 E7 0D 70 A0 E1 05 00 A0 E1 10 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sigqueue_133f7fe8197d48bc67a3fb6e1692d860 {
	meta:
		aliases = "sigqueue"
		size = "128"
		objfiles = "sigqueues@libc.a"
	strings:
		$pattern = { F0 41 2D E9 80 D0 4D E2 01 50 A0 E1 00 70 A0 E1 00 10 A0 E3 02 60 A0 E1 0D 00 A0 E1 80 20 A0 E3 00 80 E0 E3 ?? ?? ?? ?? 00 50 8D E5 08 80 8D E5 ?? ?? ?? ?? 0C 00 8D E5 ?? ?? ?? ?? 14 60 8D E5 10 00 8D E5 0D 20 A0 E1 07 00 A0 E1 05 10 A0 E1 B2 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 64 E2 00 30 80 E5 08 40 A0 E1 04 00 A0 E1 80 D0 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule universal_ddd474c7d2776eec214145f9570488cc {
	meta:
		aliases = "universal"
		size = "448"
		objfiles = "svc_simples@libc.a"
	strings:
		$pattern = { F0 41 2D E9 89 DD 4D E2 08 60 90 E5 28 D0 4D E2 8C 71 9F E5 00 00 56 E3 00 30 A0 E3 02 2A 8D E2 64 32 82 E5 07 70 8F E0 01 50 A0 E1 0C 00 00 1A 01 00 A0 E1 6C 11 9F E5 06 20 A0 E1 01 10 87 E0 ?? ?? ?? ?? 00 00 50 E3 52 00 00 1A 58 11 9F E5 04 20 A0 E3 01 10 87 E0 02 00 80 E2 ?? ?? ?? ?? 30 00 00 EA 00 80 90 E5 ?? ?? ?? ?? C0 40 90 E5 36 00 00 EA 04 30 94 E5 08 00 53 E1 32 00 00 1A 08 30 94 E5 06 00 53 E1 2F 00 00 1A 28 60 8D E2 24 60 46 E2 00 10 A0 E3 10 21 9F E5 06 00 A0 E1 ?? ?? ?? ?? 08 30 95 E5 05 00 A0 E1 0C 10 94 E5 06 20 A0 E1 0F E0 A0 E1 08 F0 93 E5 00 00 50 E3 02 00 00 1A 05 00 A0 E1 }
	condition:
		$pattern
}

rule localtime_r_8546288bba67e44521f9c3045b82b1df {
	meta:
		aliases = "__GI_localtime_r, localtime_r"
		size = "188"
		objfiles = "localtime_rs@libc.a"
	strings:
		$pattern = { F0 41 2D E9 90 40 9F E5 90 30 9F E5 04 40 8F E0 03 50 94 E7 88 30 9F E5 10 D0 4D E2 05 20 A0 E1 00 60 A0 E1 01 80 A0 E1 0D 00 A0 E1 03 10 94 E7 70 30 9F E5 0F E0 A0 E1 03 F0 94 E7 05 00 A0 E1 64 30 9F E5 0F E0 A0 E1 03 F0 94 E7 00 30 96 E5 58 00 9F E5 0D 70 A0 E1 00 00 53 E1 00 00 A0 C3 01 00 A0 D3 ?? ?? ?? ?? 44 20 9F E5 08 10 A0 E1 02 20 84 E0 06 00 A0 E1 ?? ?? ?? ?? 0D 00 A0 E1 01 10 A0 E3 2C 30 9F E5 0F E0 A0 E1 03 F0 94 E7 08 00 A0 E1 10 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF 4E 98 45 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_key_create_84b7fbfd62dda36539490c8831ed26ba {
	meta:
		aliases = "pthread_key_create"
		size = "184"
		objfiles = "specifics@libpthread.a"
	strings:
		$pattern = { F0 41 2D E9 94 50 9F E5 00 80 A0 E1 90 30 9F E5 90 00 9F E5 05 50 8F E0 03 30 85 E0 00 00 85 E0 01 70 A0 E1 33 FF 2F E1 7C 30 9F E5 7C 10 9F E5 03 20 85 E0 00 40 A0 E3 0F 00 00 EA 84 61 92 E7 00 00 56 E3 0B 00 00 1A 84 31 82 E0 54 00 9F E5 04 70 83 E5 01 30 A0 E3 84 31 82 E7 00 00 85 E0 4C 30 9F E5 0F E0 A0 E1 03 F0 95 E7 06 00 A0 E1 00 40 88 E5 F0 81 BD E8 01 40 84 E2 01 00 54 E1 ED FF FF DA 1C 00 9F E5 24 30 9F E5 00 00 85 E0 0F E0 A0 E1 03 F0 95 E7 0B 00 A0 E3 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF 03 00 00 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tcgetsid_916212edb7f1cf19e1907296ed30afa8 {
	meta:
		aliases = "tcgetsid"
		size = "180"
		objfiles = "tcgetsids@libc.a"
	strings:
		$pattern = { F0 41 2D E9 9C 50 9F E5 9C 80 9F E5 05 50 8F E0 08 30 95 E7 08 D0 4D E2 00 00 53 E3 00 70 A0 E1 0E 00 00 1A ?? ?? ?? ?? 80 10 9F E5 00 40 A0 E1 04 20 8D E2 07 00 A0 E1 00 60 94 E5 ?? ?? ?? ?? 00 00 50 E3 12 00 00 AA 00 30 94 E5 16 00 53 E3 11 00 00 1A 01 30 A0 E3 08 30 85 E7 00 60 84 E5 07 00 A0 E1 ?? ?? ?? ?? 01 00 70 E3 0A 00 00 0A ?? ?? ?? ?? 01 00 70 E3 04 00 8D E5 04 00 00 1A ?? ?? ?? ?? 00 30 90 E5 03 00 53 E3 16 30 83 02 00 30 80 05 04 00 9D E5 00 00 00 EA 00 00 E0 E3 08 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? 29 54 00 00 }
	condition:
		$pattern
}

rule _stdio_init_dbed106016f47d0bdc1154a776eb2945 {
	meta:
		aliases = "_stdio_init"
		size = "96"
		objfiles = "_stdios@libc.a"
	strings:
		$pattern = { F0 41 2D E9 ?? ?? ?? ?? 48 50 9F E5 48 60 9F E5 05 50 8F E0 00 70 A0 E1 00 00 A0 E3 B6 40 95 E1 00 80 97 E5 ?? ?? ?? ?? 01 00 60 E2 00 44 24 E0 B6 40 85 E1 01 00 A0 E3 06 50 85 E0 B0 45 D5 E1 ?? ?? ?? ?? 01 00 60 E2 00 44 24 E0 B0 45 C5 E1 00 80 87 E5 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule puts_718b030a7185157c5cf165f871b36ac1 {
	meta:
		aliases = "puts"
		size = "204"
		objfiles = "putss@libc.a"
	strings:
		$pattern = { F0 41 2D E9 A8 60 9F E5 A8 30 9F E5 06 60 8F E0 03 30 96 E7 10 D0 4D E2 00 50 93 E5 00 70 A0 E1 34 80 95 E5 00 00 58 E3 0B 00 00 1A 88 30 9F E5 38 40 85 E2 03 10 96 E7 0D 00 A0 E1 7C 30 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 6C 30 9F E5 0F E0 A0 E1 03 F0 96 E7 07 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 01 00 70 E3 00 40 A0 E1 05 00 00 0A 05 10 A0 E1 0A 00 A0 E3 ?? ?? ?? ?? 01 00 70 E3 00 40 A0 01 01 40 84 12 00 00 58 E3 04 00 00 1A 0D 00 A0 E1 01 10 A0 E3 24 30 9F E5 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 10 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _stdio_term_9f8f83c1915c10a0cb213009a8263105 {
	meta:
		aliases = "_stdio_term"
		size = "208"
		objfiles = "_stdios@libc.a"
	strings:
		$pattern = { F0 41 2D E9 B0 60 9F E5 B0 30 9F E5 06 60 8F E0 03 00 96 E7 ?? ?? ?? ?? A4 30 9F E5 A4 80 9F E5 03 00 96 E7 ?? ?? ?? ?? 9C 30 9F E5 01 70 A0 E3 03 30 96 E7 00 40 93 E5 0E 00 00 EA 0F E0 A0 E1 08 F0 96 E7 00 00 50 E3 05 00 A0 E1 06 00 00 0A 08 30 94 E5 30 20 A0 E3 B0 20 C4 E1 14 30 84 E5 18 30 84 E5 1C 30 84 E5 10 30 84 E5 34 70 84 E5 ?? ?? ?? ?? 20 40 94 E5 38 50 84 E2 00 00 54 E3 05 00 A0 E1 EC FF FF 1A 3C 30 9F E5 03 30 96 E7 00 40 93 E5 05 00 00 EA B0 30 D4 E1 40 00 13 E3 01 00 00 0A 04 00 A0 E1 ?? ?? ?? ?? 20 40 94 E5 00 00 54 E3 F7 FF FF 1A F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_cancel_d35b9fbb870059e0a8b8c9eb4b458670 {
	meta:
		aliases = "pthread_cancel"
		size = "260"
		objfiles = "cancels@libpthread.a"
	strings:
		$pattern = { F0 41 2D E9 EC 70 9F E5 EC 30 9F E5 07 70 8F E0 03 20 97 E7 00 3B A0 E1 23 3B A0 E1 03 62 82 E0 00 50 A0 E1 00 10 A0 E3 06 00 A0 E1 ?? ?? ?? ?? 08 40 96 E5 00 00 54 E3 02 00 00 0A 10 30 94 E5 05 00 53 E1 20 00 00 0A 06 00 A0 E1 ?? ?? ?? ?? 03 00 A0 E3 F0 81 BD E8 06 00 A0 E1 ?? ?? ?? ?? 10 00 00 EA BC 31 94 E5 14 80 94 E5 00 00 53 E3 03 50 A0 01 05 00 00 0A 00 00 93 E5 04 10 A0 E1 0F E0 A0 E1 04 F0 93 E5 00 50 A0 E1 B8 01 C4 E5 06 00 A0 E1 ?? ?? ?? ?? 00 00 55 E3 03 00 00 0A 04 00 A0 E1 ?? ?? ?? ?? 00 00 A0 E3 F0 81 BD E8 48 30 9F E5 08 00 A0 E1 03 30 97 E7 00 10 93 E5 ?? ?? ?? ?? 05 00 A0 E1 }
	condition:
		$pattern
}

rule __ieee754_sqrt_7bb464e37744e4311f564f8dd634a072 {
	meta:
		aliases = "__ieee754_sqrt"
		size = "572"
		objfiles = "e_sqrts@libm.a"
	strings:
		$pattern = { F0 43 2D E9 2C 22 9F E5 28 C2 9F E5 02 20 01 E0 0C 00 52 E1 04 D0 4D E2 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 01 E0 A0 E1 00 C0 A0 E1 00 80 A0 E3 00 90 A0 E3 08 00 00 1A 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 05 00 A0 E1 06 10 A0 E1 ?? ?? ?? ?? 0C 00 00 EA 00 00 51 E3 0D 00 00 CA 02 31 C1 E3 00 30 93 E1 6D 00 00 0A 00 00 51 E3 08 00 00 0A 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 00 50 A0 E1 01 60 A0 E1 62 00 00 EA 4E 3A B0 E1 03 10 A0 01 03 00 00 0A 0F 00 00 EA AC E5 A0 E1 15 10 41 E2 8C CA A0 E1 00 00 5E E3 FA FF FF 0A 00 20 A0 E3 01 00 00 EA }
	condition:
		$pattern
}

rule __ieee754_acosh_0bb4f295ac1de95c6bab1d31c1eef3c8 {
	meta:
		aliases = "__ieee754_acosh"
		size = "432"
		objfiles = "e_acoshs@libm.a"
	strings:
		$pattern = { F0 43 2D E9 8C 31 9F E5 04 D0 4D E2 03 00 51 E1 00 80 A0 E1 01 90 A0 E1 00 40 A0 E1 01 50 A0 E1 06 00 00 CA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 53 00 00 EA 54 31 9F E5 03 00 51 E1 09 00 00 DA F9 35 83 E2 03 00 51 E1 00 20 A0 C1 01 30 A0 C1 02 00 00 CA ?? ?? ?? ?? 34 21 9F E5 34 31 9F E5 ?? ?? ?? ?? 46 00 00 EA 03 31 81 E2 01 36 83 E2 00 30 93 E1 00 00 A0 03 00 10 A0 03 40 00 00 0A 01 01 59 E3 21 00 00 DA 08 20 A0 E1 09 30 A0 E1 ?? ?? ?? ?? 00 20 A0 E3 FC 30 9F E5 ?? ?? ?? ?? ?? ?? ?? ?? 08 20 A0 E1 00 40 A0 E1 01 50 A0 E1 09 30 A0 E1 08 00 A0 E1 09 10 A0 E1 }
	condition:
		$pattern
}

rule remquo_ae340347c66aebc55181034e6b40044f {
	meta:
		aliases = "__GI_remquo, remquo"
		size = "96"
		objfiles = "s_remquos@libm.a"
	strings:
		$pattern = { F0 43 2D E9 A3 CF A0 E1 04 D0 4D E2 A1 0F 5C E1 03 90 A0 E1 02 80 A0 E1 01 50 A0 03 00 50 E0 13 00 60 A0 E1 01 70 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? 20 40 9D E5 ?? ?? ?? ?? 7F 00 00 E2 95 00 03 E0 07 10 A0 E1 00 30 84 E5 06 00 A0 E1 08 20 A0 E1 09 30 A0 E1 04 D0 8D E2 F0 43 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_xdr_pmaplist_fd4dca800566d156493ec69e3701f622 {
	meta:
		aliases = "xdr_pmaplist, __GI_xdr_pmaplist"
		size = "188"
		objfiles = "pmap_prot2s@libc.a"
	strings:
		$pattern = { F0 45 2D E9 00 20 90 E5 A4 30 9F E5 02 00 52 E3 00 60 A0 13 01 60 A0 03 98 20 9F E5 0C D0 4D E2 03 30 8F E0 00 50 A0 E1 02 A0 83 E0 01 40 A0 E1 00 70 A0 E3 04 80 8D E2 00 30 94 E5 08 10 A0 E1 00 30 53 E2 01 30 A0 13 05 00 A0 E1 04 30 8D E5 ?? ?? ?? ?? 00 00 50 E3 04 10 A0 E1 14 20 A0 E3 0A 30 A0 E1 05 00 A0 E1 0E 00 00 0A 04 C0 9D E5 00 00 5C E3 01 00 A0 03 0B 00 00 0A 00 00 56 E3 00 C0 94 15 10 70 8C 12 ?? ?? ?? ?? 00 00 50 E3 04 00 00 0A 00 00 56 E3 00 30 94 05 07 40 A0 11 10 40 83 02 E3 FF FF EA 00 00 A0 E3 0C D0 8D E2 F0 85 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_once_6022104a512f2850ba373d0676613c0b {
	meta:
		aliases = "__pthread_once, pthread_once"
		size = "376"
		objfiles = "mutexs@libpthread.a"
	strings:
		$pattern = { F0 45 2D E9 00 30 90 E5 44 61 9F E5 02 00 53 E3 14 D0 4D E2 00 70 A0 E1 06 60 8F E0 01 A0 A0 E1 00 00 00 1A 47 00 00 EA 28 01 9F E5 28 31 9F E5 00 00 86 E0 03 30 86 E0 33 FF 2F E1 00 20 97 E5 03 30 02 E2 01 00 53 E3 08 00 00 1A 03 30 C2 E3 08 21 9F E5 02 20 96 E7 02 00 53 E1 00 30 A0 13 00 30 87 15 01 00 00 EA ?? ?? ?? ?? 03 00 00 EA EC 30 9F E5 03 50 86 E0 D8 30 9F E5 03 40 86 E0 00 80 97 E5 05 00 A0 E1 03 30 08 E2 01 00 53 E3 04 10 A0 E1 F3 FF FF 0A 00 00 58 E3 00 40 A0 13 1E 00 00 1A B4 30 9F E5 A8 40 9F E5 03 30 96 E7 04 40 86 E0 01 30 83 E3 00 30 87 E5 A4 30 9F E5 04 00 A0 E1 03 30 86 E0 }
	condition:
		$pattern
}

rule xdr_reference_c537d40c13fa3f72ddf3dc7acc429ab8 {
	meta:
		aliases = "__GI_xdr_reference, xdr_reference"
		size = "212"
		objfiles = "xdr_references@libc.a"
	strings:
		$pattern = { F0 45 2D E9 00 40 91 E5 B8 60 9F E5 00 00 54 E3 06 60 8F E0 04 D0 4D E2 01 80 A0 E1 00 50 A0 E1 02 70 A0 E1 03 A0 A0 E1 17 00 00 1A 00 30 90 E5 01 00 53 E3 03 00 00 0A 02 00 53 E3 01 60 A0 03 1D 00 00 0A 10 00 00 EA 02 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 40 A0 E1 00 00 88 E5 07 00 00 1A 64 30 9F E5 64 00 9F E5 03 30 96 E7 00 00 86 E0 00 10 93 E5 ?? ?? ?? ?? 04 60 A0 E1 0E 00 00 EA 07 20 A0 E1 00 10 A0 E3 ?? ?? ?? ?? 05 00 A0 E1 04 10 A0 E1 00 20 E0 E3 3A FF 2F E1 00 30 95 E5 00 60 A0 E1 02 00 53 E3 03 00 00 1A 04 00 A0 E1 ?? ?? ?? ?? 00 30 A0 E3 00 30 88 E5 06 00 A0 E1 04 D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule __pthread_alt_unlock_b2e65053240d60bdef012dfa8b3d7bb8 {
	meta:
		aliases = "__pthread_alt_unlock"
		size = "200"
		objfiles = "spinlocks@libpthread.a"
	strings:
		$pattern = { F0 45 2D E9 00 40 A0 E1 04 D0 4D E2 04 00 80 E2 70 FF FF EB 02 A1 A0 E3 00 00 94 E5 01 00 50 E3 00 30 A0 93 00 30 84 95 22 00 00 9A 04 50 A0 E1 00 70 A0 E1 04 80 A0 E1 0A 60 A0 E1 11 00 00 EA 08 30 90 E5 00 00 53 E3 06 00 00 0A 00 30 90 E5 00 30 85 E5 79 FF FF EB 04 00 55 E1 00 00 95 E5 08 00 00 1A 07 00 00 EA 04 30 90 E5 18 30 93 E5 06 00 53 E1 05 80 A0 A1 00 70 A0 A1 00 50 A0 E1 00 00 90 E5 03 60 A0 A1 01 00 50 E3 EB FF FF 1A 02 01 56 E3 DF FF FF 0A 08 30 87 E2 90 00 03 E1 00 00 50 E3 DB FF FF 1A 00 30 97 E5 04 00 97 E5 00 30 88 E5 ?? ?? ?? ?? 00 30 A0 E3 04 30 84 E5 04 D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule readtcp_fc05bb8350657fd165590fcfece46c21 {
	meta:
		aliases = "readtcp"
		size = "252"
		objfiles = "clnt_tcps@libc.a"
	strings:
		$pattern = { F0 45 2D E9 00 40 A0 E1 0C D0 4D E2 01 A0 A0 E1 0C 00 90 E5 FA 1F A0 E3 02 60 A0 E1 ?? ?? ?? ?? 08 20 94 E5 00 00 56 E3 FA 3F A0 E3 92 03 27 E0 06 50 A0 01 2D 00 00 0A 00 30 94 E5 01 20 A0 E3 B4 20 CD E1 00 30 8D E5 0D 80 A0 E1 01 10 A0 E3 07 20 A0 E1 0D 00 A0 E1 ?? ?? ?? ?? 01 00 70 E3 00 50 A0 E1 05 00 00 0A 00 00 50 E3 05 30 A0 03 00 50 E0 03 24 30 84 05 1C 00 00 0A 07 00 00 EA ?? ?? ?? ?? 00 30 90 E5 04 00 53 E3 EE FF FF 0A 04 30 A0 E3 24 30 84 E5 00 30 90 E5 0C 00 00 EA 0A 10 A0 E1 06 20 A0 E1 00 00 94 E5 ?? ?? ?? ?? 01 00 70 E3 00 50 A0 E1 07 00 00 0A 00 00 50 E3 0A 00 00 1A 04 30 A0 E3 }
	condition:
		$pattern
}

rule _Unwind_VRS_Pop_14c936fdd8e68175ee59e877305d73d0 {
	meta:
		aliases = "_Unwind_VRS_Pop"
		size = "320"
		objfiles = "unwind_arm@libgcc.a"
	strings:
		$pattern = { F0 45 2D E9 00 40 A0 E1 8C D0 4D E2 03 50 A0 E1 04 00 51 E3 01 F1 8F 90 0F 00 00 EA 13 00 00 EA 02 00 00 EA 0F 00 00 EA 0E 00 00 EA 0D 00 00 EA 01 00 53 E3 05 00 53 13 00 A0 A0 03 01 A0 A0 13 05 00 00 1A 02 68 A0 E1 26 68 A0 E1 22 78 A0 E1 07 30 86 E0 10 00 53 E3 17 00 00 9A 02 00 A0 E3 8C D0 8D E2 F0 85 BD E8 01 00 A0 E3 FB FF FF EA 00 00 53 E3 F8 FF FF 1A 02 08 A0 E1 38 C0 94 E5 20 08 A0 E1 03 10 A0 E1 01 30 A0 E3 13 31 10 E0 01 21 A0 E1 04 30 9C 14 01 10 81 E2 02 20 84 E0 04 30 82 15 10 00 51 E3 F6 FF FF 1A 02 0A 10 E2 38 C0 84 05 00 00 A0 13 E8 FF FF EA 00 30 90 E5 01 00 13 E3 18 00 00 1A }
	condition:
		$pattern
}

rule parse_printf_format_7ee19cc3b0bf7e64187805ebf80e2d2c {
	meta:
		aliases = "parse_printf_format"
		size = "312"
		objfiles = "parse_printf_formats@libc.a"
	strings:
		$pattern = { F0 45 2D E9 00 50 A0 E1 9C D0 4D E2 01 40 A0 E1 0D 00 A0 E1 05 10 A0 E1 02 60 A0 E1 ?? ?? ?? ?? 00 00 50 E3 0D 80 A0 E1 00 70 A0 B3 3E 00 00 BA 18 00 9D E5 00 00 50 E3 00 70 A0 D3 0D A0 A0 D1 07 80 A0 D1 35 00 00 DA 00 70 A0 E1 00 00 54 E1 04 10 A0 31 00 10 A0 21 00 20 A0 E3 01 00 00 EA 70 30 13 E5 04 30 86 E4 98 00 8D E2 01 00 52 E1 02 31 80 E0 01 20 82 E2 F8 FF FF 3A 2A 00 00 EA 25 00 53 E3 24 00 00 1A 01 30 F5 E5 25 00 53 E3 21 00 00 0A 0D 00 A0 E1 00 50 8D E5 ?? ?? ?? ?? 08 30 9D E5 00 50 9D E5 02 01 53 E3 03 00 00 1A 00 00 54 E3 01 70 87 E2 04 80 86 14 01 40 44 12 04 30 9D E5 02 01 53 E3 }
	condition:
		$pattern
}

rule pthread_atfork_c4b6b80b1115afb817ad4a01d103897a {
	meta:
		aliases = "pthread_atfork"
		size = "200"
		objfiles = "ptforks@libpthread.a"
	strings:
		$pattern = { F0 45 2D E9 00 70 A0 E1 04 D0 4D E2 18 00 A0 E3 01 80 A0 E1 02 A0 A0 E1 ?? ?? ?? ?? 88 50 9F E5 00 60 50 E2 05 50 8F E0 0C 00 80 02 1C 00 00 0A 78 40 9F E5 78 30 9F E5 04 40 85 E0 03 30 85 E0 04 00 A0 E1 33 FF 2F E1 68 00 9F E5 07 10 A0 E1 00 00 85 E0 06 20 A0 E1 00 30 A0 E3 69 FF FF EB 54 00 9F E5 08 10 A0 E1 00 00 85 E0 08 20 86 E2 01 30 A0 E3 63 FF FF EB 40 00 9F E5 0A 10 A0 E1 10 20 86 E2 00 00 85 E0 01 30 A0 E3 5D FF FF EB 04 00 A0 E1 28 30 9F E5 0F E0 A0 E1 03 F0 95 E7 00 00 A0 E3 04 D0 8D E2 F0 85 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __gnu_unwind_execute_02ad6aef1df3b18ba70126788c2cc568 {
	meta:
		aliases = "__gnu_unwind_execute"
		size = "1796"
		objfiles = "pr_support@libgcc.a"
	strings:
		$pattern = { F0 45 2D E9 00 70 A0 E1 14 D0 4D E2 01 50 A0 E1 00 A0 A0 E3 08 30 D5 E5 00 00 53 E3 01 30 43 12 08 30 C5 15 09 00 00 1A 09 30 D5 E5 00 00 53 E3 3D 00 00 0A 01 30 43 E2 04 20 95 E5 09 30 C5 E5 04 00 92 E4 03 30 A0 E3 05 00 85 E8 08 30 C5 E5 00 00 95 E5 20 4C A0 E1 FF C0 04 E2 00 04 A0 E1 B0 00 5C E3 00 00 85 E5 2F 00 00 0A 80 10 14 E2 32 00 00 0A F0 60 04 E2 80 00 56 E3 46 00 00 1A 08 30 D5 E5 00 00 53 E3 01 30 43 12 08 30 C5 15 0B 00 00 1A 09 30 D5 E5 00 00 53 E3 B0 20 A0 03 0B 00 00 0A 01 30 43 E2 04 20 95 E5 09 30 C5 E5 04 00 92 E4 03 30 A0 E3 04 20 85 E5 08 30 C5 E5 00 00 85 E5 00 30 A0 E1 }
	condition:
		$pattern
}

rule __GI_readdir64_r_58c63908957312372ee86f460bc180a0 {
	meta:
		aliases = "readdir64_r, __GI_readdir64_r"
		size = "288"
		objfiles = "readdir64_rs@libc.a"
	strings:
		$pattern = { F0 45 2D E9 00 71 9F E5 00 31 9F E5 07 70 8F E0 18 40 80 E2 14 D0 4D E2 00 50 A0 E1 01 A0 A0 E1 0D 00 A0 E1 03 10 97 E7 02 80 A0 E1 E0 30 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 97 E7 04 00 A0 E1 D0 30 9F E5 0F E0 A0 E1 03 F0 97 E7 00 60 A0 E3 06 40 A0 E1 0C 00 95 E9 02 00 53 E1 0E 00 00 8A 00 00 95 E5 0C 10 95 E5 14 20 95 E5 ?? ?? ?? ?? 00 00 50 E3 06 00 00 CA 00 30 A0 E3 00 30 88 E5 00 40 A0 01 16 00 00 0A ?? ?? ?? ?? 00 40 90 E5 13 00 00 EA 08 00 85 E5 04 40 85 E5 04 20 95 E5 0C 30 95 E5 03 60 82 E0 03 10 92 E7 B0 C1 D6 E1 04 30 96 E5 08 00 96 E5 02 20 8C E0 03 10 91 E1 04 20 85 E5 10 00 85 E5 }
	condition:
		$pattern
}

rule tcsetattr_0ed75f133e1d9f26bccde73d73b6ba16 {
	meta:
		aliases = "__GI_tcsetattr, tcsetattr"
		size = "300"
		objfiles = "tcsetattrs@libc.a"
	strings:
		$pattern = { F0 45 2D E9 01 00 51 E3 2C D0 4D E2 00 A0 A0 E1 02 60 A0 E1 05 00 00 0A 02 00 51 E3 0A 00 00 0A 00 00 51 E3 F0 80 9F 05 08 00 00 0A 01 00 00 EA E8 80 9F E5 05 00 00 EA ?? ?? ?? ?? 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 30 00 00 EA D0 80 9F E5 08 50 96 E8 0C 40 96 E5 10 50 D6 E5 04 70 8D E2 02 31 C3 E3 11 10 86 E2 13 20 A0 E3 11 00 87 E2 08 50 8D E9 10 40 8D E5 14 50 CD E5 ?? ?? ?? ?? 07 20 A0 E1 0A 00 A0 E1 08 10 A0 E1 ?? ?? ?? ?? 84 30 9F E5 00 20 A0 E1 00 00 50 E3 03 00 58 01 1A 00 00 1A ?? ?? ?? ?? 07 20 A0 E1 00 40 A0 E1 70 10 9F E5 0A 00 A0 E1 00 50 94 E5 ?? ?? ?? ?? 00 00 50 E3 00 20 A0 13 }
	condition:
		$pattern
}

rule __GI_svc_register_fe573af516fa31f74df7d884788f2c54 {
	meta:
		aliases = "svc_register, __GI_svc_register"
		size = "152"
		objfiles = "svcs@libc.a"
	strings:
		$pattern = { F0 45 2D E9 01 50 A0 E1 0C D0 4D E2 02 10 A0 E1 02 60 A0 E1 00 80 A0 E1 04 20 8D E2 05 00 A0 E1 03 70 A0 E1 28 A0 9D E5 1E FF FF EB 00 00 50 E3 03 00 00 0A 0C 30 90 E5 07 00 53 E1 12 00 00 1A 08 00 00 EA 10 00 A0 E3 ?? ?? ?? ?? 00 40 50 E2 0D 00 00 0A E0 00 84 E9 ?? ?? ?? ?? B8 30 90 E5 00 30 84 E5 B8 40 80 E5 00 00 5A E3 01 00 A0 03 06 00 00 0A 05 00 A0 E1 06 10 A0 E1 0A 20 A0 E1 B4 30 D8 E1 ?? ?? ?? ?? 00 00 00 EA 00 00 A0 E3 0C D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule __GI_xdr_bytes_35af6e7465271659b4761910d67e0386 {
	meta:
		aliases = "xdr_bytes, __GI_xdr_bytes"
		size = "264"
		objfiles = "xdrs@libc.a"
	strings:
		$pattern = { F0 45 2D E9 01 80 A0 E1 04 D0 4D E2 02 10 A0 E1 02 50 A0 E1 03 A0 A0 E1 00 60 A0 E1 00 40 98 E5 ?? ?? ?? ?? D0 70 9F E5 00 00 50 E3 07 70 8F E0 2C 00 00 0A 00 50 95 E5 0A 00 55 E1 02 00 00 9A 00 30 96 E5 02 00 53 E3 26 00 00 1A 00 30 96 E5 01 00 53 E3 03 00 00 0A 14 00 00 3A 02 00 53 E3 20 00 00 1A 17 00 00 EA 00 00 55 E3 1F 00 00 0A 00 00 54 E3 0D 00 00 1A 05 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 40 A0 E1 00 00 88 E5 07 00 00 1A 68 30 9F E5 68 00 9F E5 03 30 97 E7 00 00 87 E0 00 10 93 E5 ?? ?? ?? ?? 04 00 A0 E1 10 00 00 EA 06 00 A0 E1 04 10 A0 E1 05 20 A0 E1 04 D0 8D E2 F0 45 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule vsnprintf_b2d6c88fed0a423db930e876b167c7c6 {
	meta:
		aliases = "__GI_vsnprintf, vsnprintf"
		size = "176"
		objfiles = "vsnprintfs@libc.a"
	strings:
		$pattern = { F0 45 2D E9 01 C0 E0 E3 54 D0 4D E2 00 40 A0 E1 00 A0 A0 E3 38 00 8D E2 04 C0 8D E5 03 70 A0 E1 03 C0 8C E2 D0 30 A0 E3 01 50 A0 E1 02 60 A0 E1 34 C0 8D E5 B0 30 CD E1 02 A0 CD E5 2C A0 8D E5 ?? ?? ?? ?? 04 30 E0 E1 03 00 55 E1 03 50 A0 21 05 30 84 E0 0D 00 A0 E1 06 10 A0 E1 07 20 A0 E1 18 40 8D E5 1C 30 8D E5 20 A0 8D E5 08 40 8D E5 0C 30 8D E5 10 40 8D E5 14 40 8D E5 ?? ?? ?? ?? 0A 00 55 E1 0D 80 A0 E1 06 00 00 0A 0C 30 9D E5 10 20 9D E5 03 00 52 E1 01 30 42 02 10 30 8D 05 10 30 9D E5 00 A0 C3 E5 54 D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule __gcc_personality_v0_1b176e645eb81adc8efc4f23e49e3c8d {
	meta:
		aliases = "__gcc_personality_v0"
		size = "668"
		objfiles = "unwind_c@libgcc.a"
	strings:
		$pattern = { F0 45 2D E9 03 00 00 E2 01 00 50 E3 34 D0 4D E2 01 A0 A0 E1 02 70 A0 E1 09 00 00 0A 0A 00 A0 E1 07 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 09 00 A0 13 01 00 00 0A 34 D0 8D E2 F0 85 BD E8 08 00 A0 E3 FB FF FF EA 00 10 A0 E3 0C 20 A0 E3 01 30 A0 E1 20 80 8D E2 07 00 A0 E1 20 A0 8D E5 00 80 8D E5 ?? ?? ?? ?? 07 00 A0 E1 ?? ?? ?? ?? 00 50 50 E2 E9 FF FF 0A 00 00 57 E3 07 00 A0 01 01 00 00 0A 07 00 A0 E1 ?? ?? ?? ?? 08 00 8D E5 01 40 D5 E4 FF 00 54 E3 0C 00 8D 05 08 00 00 0A 07 10 A0 E1 04 00 A0 E1 B2 FF FF EB 05 20 A0 E1 00 10 A0 E1 0C 30 8D E2 04 00 A0 E1 46 FF FF EB 00 50 A0 E1 01 30 D5 E4 FF 00 53 E3 }
	condition:
		$pattern
}

rule memalign_edabf0526841d29ad97ca4aa2f369dd7 {
	meta:
		aliases = "memalign"
		size = "200"
		objfiles = "memaligns@libc.a"
	strings:
		$pattern = { F0 45 2D E9 03 10 81 E2 03 A0 C1 E3 04 D0 4D E2 00 40 A0 E1 80 00 8A E0 ?? ?? ?? ?? 9C 80 9F E5 00 00 50 E3 08 80 8F E0 22 00 00 0A 03 00 54 E3 20 00 00 9A 04 10 80 E0 01 30 41 E2 00 20 64 E2 02 60 03 E0 04 30 10 E5 04 50 40 E2 00 00 56 E1 03 70 85 E0 0A 00 00 0A 06 40 60 E0 0B 00 54 E3 0B 30 81 92 02 60 03 90 54 30 9F E5 06 40 60 90 05 10 A0 E1 03 00 98 E7 04 20 A0 E1 ?? ?? ?? ?? 04 50 85 E0 0A 40 86 E0 1C 30 84 E2 07 00 53 E1 07 40 A0 21 04 00 00 2A 24 30 9F E5 07 20 64 E0 03 00 98 E7 04 10 A0 E1 ?? ?? ?? ?? 04 30 65 E0 04 30 85 E4 05 00 A0 E1 04 D0 8D E2 F0 85 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svc_getreqset_e9b94909e9b23e78dd8ef9363528f624 {
	meta:
		aliases = "__GI_svc_getreqset, svc_getreqset"
		size = "100"
		objfiles = "svcs@libc.a"
	strings:
		$pattern = { F0 45 2D E9 04 D0 4D E2 00 40 A0 E1 ?? ?? ?? ?? 04 60 A0 E1 00 80 A0 E1 00 70 A0 E3 01 A0 A0 E3 0B 00 00 EA 00 40 96 E5 01 00 00 EA ?? ?? ?? ?? 1A 45 24 E0 04 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 01 50 40 E2 07 00 85 E0 F7 FF FF 1A 04 60 86 E2 20 70 87 E2 08 00 57 E1 F1 FF FF BA 04 D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule dladdr_fbc7bc6d87f5b322cf5fe40b7f0e0ecb {
	meta:
		aliases = "dladdr"
		size = "304"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { F0 45 2D E9 04 D0 4D E2 00 A0 A0 E1 01 40 A0 E1 ?? ?? ?? ?? 0C 31 9F E5 0C 21 9F E5 03 30 8F E0 02 20 93 E7 00 00 A0 E3 00 20 92 E5 09 00 00 EA 14 10 92 E5 0A 00 51 E1 05 00 00 2A 00 00 50 E3 02 00 00 0A 14 30 90 E5 01 00 53 E1 00 00 00 2A 02 00 A0 E1 0C 20 92 E5 00 00 52 E3 F3 FF FF 1A 00 00 50 E3 2D 00 00 0A 02 50 A0 E1 04 30 90 E5 14 20 90 E5 58 70 90 E5 54 80 90 E5 05 C0 A0 E1 05 E0 A0 E1 05 60 A0 E1 00 30 84 E5 04 20 84 E5 16 00 00 EA 2C 30 90 E5 0E 11 93 E7 0F 00 00 EA 04 20 93 E5 00 30 90 E5 03 20 82 E0 0A 00 52 E1 08 00 00 8A 02 00 56 E1 00 30 A0 23 01 30 A0 33 00 00 5C E3 01 30 83 03 }
	condition:
		$pattern
}

rule xdr_vector_1e64e612dff256b7e6097bd708c517e1 {
	meta:
		aliases = "xdr_vector"
		size = "88"
		objfiles = "xdr_arrays@libc.a"
	strings:
		$pattern = { F0 45 2D E9 04 D0 4D E2 20 A0 9D E5 00 80 A0 E1 02 70 A0 E1 03 60 A0 E1 01 40 A0 E1 00 50 A0 E3 02 00 00 EA 3A FF 2F E1 00 00 50 E3 07 00 00 0A 07 00 55 E1 04 10 A0 E1 08 00 A0 E1 00 20 E0 E3 06 40 84 E0 01 50 85 E2 F5 FF FF 3A 01 00 A0 E3 04 D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule putgrent_e8ea13c5c04d173f387765bed19efce4 {
	meta:
		aliases = "putgrent"
		size = "304"
		objfiles = "putgrents@libc.a"
	strings:
		$pattern = { F0 45 2D E9 08 71 9F E5 00 00 51 E3 00 00 50 13 1C D0 4D E2 00 50 A0 E1 01 60 A0 E1 07 70 8F E0 04 00 00 1A ?? ?? ?? ?? 00 40 E0 E3 16 30 A0 E3 00 30 80 E5 33 00 00 EA 34 A0 91 E5 00 00 5A E3 0B 00 00 1A CC 30 9F E5 38 40 81 E2 08 00 8D E2 03 10 97 E7 04 20 A0 E1 BC 30 9F E5 0F E0 A0 E1 03 F0 97 E7 04 00 A0 E1 B0 30 9F E5 0F E0 A0 E1 03 F0 97 E7 08 30 95 E5 A4 10 9F E5 00 30 8D E5 01 10 87 E0 06 00 A0 E1 0C 00 95 E8 ?? ?? ?? ?? 00 00 50 E3 13 00 00 BA 88 30 9F E5 0C 50 95 E5 03 30 87 E0 03 80 A0 E1 01 10 83 E2 00 40 95 E5 06 00 A0 E1 00 20 54 E2 04 50 85 E2 05 00 00 1A 06 10 A0 E1 0A 00 A0 E3 }
	condition:
		$pattern
}

rule sem_timedwait_765eada2c7f1cf0c2045ea3165aba527 {
	meta:
		aliases = "sem_timedwait"
		size = "452"
		objfiles = "semaphores@libpthread.a"
	strings:
		$pattern = { F0 45 2D E9 0C D0 4D E2 00 60 A0 E1 01 A0 A0 E1 BF FF FF EB 00 50 A0 E1 05 10 A0 E1 06 00 A0 E1 ?? ?? ?? ?? 08 30 96 E5 88 11 9F E5 00 00 53 E3 01 10 8F E0 04 00 00 DA 01 30 43 E2 08 30 86 E5 06 00 A0 E1 ?? ?? ?? ?? 56 00 00 EA 04 20 9A E5 64 31 9F E5 03 00 52 E1 05 00 00 9A 06 00 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? 00 20 E0 E3 16 30 A0 E3 32 00 00 EA 44 31 9F E5 00 60 8D E5 03 30 81 E0 04 30 8D E5 00 30 A0 E3 BA 31 C5 E5 05 00 A0 E1 0D 10 A0 E1 39 FF FF EB 42 30 D5 E5 00 00 53 E3 03 00 00 0A 40 30 D5 E5 00 00 53 E3 01 40 A0 03 03 00 00 0A 0C 00 86 E2 05 10 A0 E1 0F FF FF EB 00 40 A0 E3 06 00 A0 E1 }
	condition:
		$pattern
}

rule ___path_search_9d9b4f4c7b93c4ba13d62599312fb3d1 {
	meta:
		aliases = "___path_search"
		size = "304"
		objfiles = "tempnames@libc.a"
	strings:
		$pattern = { F0 45 2D E9 14 71 9F E5 00 60 53 E2 07 70 8F E0 0C D0 4D E2 00 A0 A0 E1 01 80 A0 E1 02 40 A0 E1 08 00 00 0A 00 30 D6 E5 00 00 53 E3 05 00 00 0A 06 00 A0 E1 ?? ?? ?? ?? 05 00 50 E3 00 50 A0 E1 05 50 A0 83 02 00 00 EA D4 30 9F E5 04 50 A0 E3 03 60 87 E0 00 00 54 E3 12 00 00 1A C4 30 9F E5 03 40 87 E0 04 00 A0 E1 15 FF FF EB 00 00 50 E3 0C 00 00 1A 04 00 A0 E1 04 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 03 00 00 0A 04 00 A0 E1 0C FF FF EB 00 00 50 E3 03 00 00 1A ?? ?? ?? ?? 00 20 E0 E3 02 30 A0 E3 11 00 00 EA 04 00 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 00 00 00 EA 01 20 42 E2 01 00 52 E3 04 30 82 E0 02 00 00 9A }
	condition:
		$pattern
}

rule registerrpc_0d12dc73d8d88f3a20e88eebb392d42b {
	meta:
		aliases = "registerrpc"
		size = "332"
		objfiles = "svc_simples@libc.a"
	strings:
		$pattern = { F0 45 2D E9 24 71 9F E5 00 A0 52 E2 07 70 8F E0 14 D0 4D E2 00 50 A0 E1 01 60 A0 E1 03 80 A0 E1 04 00 00 1A 08 11 9F E5 0C 00 8D E2 01 10 87 E0 ?? ?? ?? ?? 32 00 00 EA ?? ?? ?? ?? C4 30 90 E5 00 40 A0 E1 00 00 53 E3 05 00 00 1A 00 00 E0 E3 ?? ?? ?? ?? 00 00 50 E3 C4 00 84 E5 D4 00 9F 05 18 00 00 0A 06 10 A0 E1 05 00 A0 E1 ?? ?? ?? ?? 11 30 A0 E3 00 30 8D E5 BC 30 9F E5 C4 00 94 E5 03 30 87 E0 05 10 A0 E1 06 20 A0 E1 ?? ?? ?? ?? 00 00 50 E3 06 00 00 1A A0 10 9F E5 05 20 A0 E1 01 10 87 E0 06 30 A0 E1 0C 00 8D E2 ?? ?? ?? ?? 13 00 00 EA 18 00 A0 E3 ?? ?? ?? ?? 00 00 50 E3 04 00 00 1A 78 00 9F E5 }
	condition:
		$pattern
}

rule __psfs_parse_spec_11bd280f28659b5c83cb556da814db42 {
	meta:
		aliases = "__psfs_parse_spec"
		size = "680"
		objfiles = "__psfs_parse_specs@libc.a"
	strings:
		$pattern = { F0 45 2D E9 30 A0 90 E5 7C 42 9F E5 00 30 DA E5 04 40 8F E0 30 30 43 E2 09 00 53 E3 04 D0 4D E2 00 50 A0 83 01 60 A0 83 19 00 00 8A 5C E2 9F E5 00 50 A0 E3 0A C0 A0 E3 0E 00 55 E1 30 20 90 D5 01 30 D2 D4 30 20 80 D5 30 10 90 E5 30 30 43 D2 00 20 D1 E5 9C 35 25 D0 30 30 42 E2 09 00 53 E3 F4 FF FF 9A 24 00 52 E3 06 00 00 0A 24 30 90 E5 00 00 53 E3 01 30 E0 B3 40 50 80 B5 24 30 80 B5 39 00 00 BA 7A 00 00 EA 01 30 81 E2 30 30 80 E5 00 60 A0 E3 F8 31 9F E5 10 80 A0 E3 03 70 84 E0 07 10 A0 E1 08 C0 A0 E1 30 E0 90 E5 00 20 D1 E5 00 30 DE E5 03 00 52 E1 05 00 00 1A 45 30 D0 E5 01 20 8E E2 0C 30 83 E1 }
	condition:
		$pattern
}

rule __GI_vfwprintf_97157a68205717bd27ac666e24a800d8 {
	meta:
		aliases = "vfwprintf, __GI_vfwprintf"
		size = "208"
		objfiles = "vfwprintfs@libc.a"
	strings:
		$pattern = { F0 45 2D E9 34 70 90 E5 AC 60 9F E5 00 00 57 E3 06 60 8F E0 14 D0 4D E2 00 50 A0 E1 01 A0 A0 E1 02 80 A0 E1 0B 00 00 1A 90 30 9F E5 38 40 80 E2 03 10 96 E7 0D 00 A0 E1 84 30 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 74 30 9F E5 0F E0 A0 E1 03 F0 96 E7 B0 30 D5 E1 21 3D 03 E2 21 0D 53 E3 05 00 00 0A 05 00 A0 E1 02 1B A0 E3 ?? ?? ?? ?? 00 00 50 E3 00 40 E0 13 04 00 00 1A 05 00 A0 E1 0A 10 A0 E1 08 20 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 00 00 57 E3 04 00 00 1A 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 14 D0 8D E2 F0 85 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule vfprintf_4839199b2113cea12fd7239ed741aaff {
	meta:
		aliases = "__GI_vfprintf, vfprintf"
		size = "208"
		objfiles = "vfprintfs@libc.a"
	strings:
		$pattern = { F0 45 2D E9 34 70 90 E5 AC 60 9F E5 00 00 57 E3 06 60 8F E0 14 D0 4D E2 00 50 A0 E1 01 A0 A0 E1 02 80 A0 E1 0B 00 00 1A 90 30 9F E5 38 40 80 E2 03 10 96 E7 0D 00 A0 E1 84 30 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 74 30 9F E5 0F E0 A0 E1 03 F0 96 E7 B0 30 D5 E1 C0 30 03 E2 C0 00 53 E3 05 00 00 0A 05 00 A0 E1 80 10 A0 E3 ?? ?? ?? ?? 00 00 50 E3 00 40 E0 13 04 00 00 1A 05 00 A0 E1 0A 10 A0 E1 08 20 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 00 00 57 E3 04 00 00 1A 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 14 D0 8D E2 F0 85 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fgetws_80a0e42ffd524b56e8442fcf189f2671 {
	meta:
		aliases = "__GI_fgets, fgets, fgetws"
		size = "168"
		objfiles = "fgetss@libc.a, fgetwss@libc.a"
	strings:
		$pattern = { F0 45 2D E9 34 A0 92 E5 84 50 9F E5 00 00 5A E3 05 50 8F E0 14 D0 4D E2 02 60 A0 E1 00 80 A0 E1 01 70 A0 E1 0B 00 00 1A 68 30 9F E5 38 40 82 E2 03 10 95 E7 0D 00 A0 E1 5C 30 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 4C 30 9F E5 0F E0 A0 E1 03 F0 95 E7 08 00 A0 E1 07 10 A0 E1 06 20 A0 E1 ?? ?? ?? ?? 00 00 5A E3 00 40 A0 E1 04 00 00 1A 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 14 D0 8D E2 F0 85 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule round_8da0ae71b79a471cc903087d0585855a {
	meta:
		aliases = "__GI_round, round"
		size = "356"
		objfiles = "s_rounds@libm.a"
	strings:
		$pattern = { F0 45 2D E9 41 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF 6F 43 E2 03 60 46 E2 0C D0 4D E2 00 20 A0 E3 00 30 A0 E3 13 00 56 E3 00 70 A0 E1 01 80 A0 E1 00 40 A0 E1 01 50 A0 E1 01 A0 A0 E1 0C 00 8D E8 20 00 00 CA 00 00 56 E3 0D 00 00 AA 04 21 9F E5 04 31 9F E5 ?? ?? ?? ?? 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? ?? 00 00 50 E3 34 00 00 0A 01 00 76 E3 02 A1 08 E2 FF A5 8A 03 03 A6 8A 03 00 40 A0 E3 2E 00 00 EA D4 30 9F E5 53 56 A0 E1 01 30 05 E0 00 30 93 E1 2B 00 00 0A B8 20 9F E5 B8 30 9F E5 ?? ?? ?? ?? 00 30 A0 E3 00 20 A0 E3 ?? ?? ?? ?? 00 00 50 E3 02 37 A0 13 53 36 88 10 05 A0 C3 11 ED FF FF 1A 1D 00 00 EA }
	condition:
		$pattern
}

rule __form_query_4f9e737d54b412cabc04d49c27a8ae37 {
	meta:
		aliases = "__form_query"
		size = "136"
		objfiles = "formquerys@libc.a"
	strings:
		$pattern = { F0 45 2D E9 44 D0 4D E2 04 40 8D E2 60 A0 9D E5 03 80 A0 E1 00 50 A0 E1 01 60 A0 E1 02 70 A0 E1 00 10 A0 E3 30 20 A0 E3 04 00 A0 E1 ?? ?? ?? ?? 01 30 A0 E3 04 00 A0 E1 08 10 A0 E1 0A 20 A0 E1 04 50 8D E5 34 60 8D E5 38 70 8D E5 3C 30 8D E5 24 30 8D E5 ?? ?? ?? ?? 00 40 50 E2 06 00 00 BA 04 10 88 E0 0A 20 64 E0 34 00 8D E2 ?? ?? ?? ?? 00 00 50 E3 00 40 A0 B1 00 40 84 A0 04 00 A0 E1 44 D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule __GI_getmntent_r_79e56314aa7482a12bf5acb34c5386ce {
	meta:
		aliases = "getmntent_r, __GI_getmntent_r"
		size = "352"
		objfiles = "mntents@libc.a"
	strings:
		$pattern = { F0 45 2D E9 48 A1 9F E5 00 00 51 E3 00 00 50 13 0A A0 8F E0 0C D0 4D E2 00 70 A0 E1 01 50 A0 E1 02 40 A0 E1 03 80 A0 E1 45 00 00 0A 00 00 52 E3 43 00 00 0A 05 00 00 EA 00 30 D4 E5 0A 00 53 E3 23 00 53 13 00 60 A0 13 01 60 A0 03 06 00 00 1A 04 00 A0 E1 08 10 A0 E1 07 20 A0 E1 ?? ?? ?? ?? 00 00 50 E3 F3 FF FF 1A 35 00 00 EA E4 30 9F E5 08 70 8D E2 04 60 27 E5 03 80 8A E0 04 00 A0 E1 08 10 A0 E1 07 20 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 00 85 E5 2A 00 00 0A 06 00 A0 E1 08 10 A0 E1 07 20 A0 E1 ?? ?? ?? ?? 00 00 50 E3 04 00 85 E5 23 00 00 0A 06 00 A0 E1 08 10 A0 E1 07 20 A0 E1 ?? ?? ?? ?? 00 00 50 E3 }
	condition:
		$pattern
}

rule readunix_c29f7915ede236708bdc50dee71a1898 {
	meta:
		aliases = "readunix"
		size = "356"
		objfiles = "svc_unixs@libc.a"
	strings:
		$pattern = { F0 45 2D E9 4C 41 9F E5 3C D0 4D E2 00 A0 A0 E1 00 60 90 E5 01 70 A0 E1 02 80 A0 E1 2C 50 8D E2 04 40 8F E0 01 30 A0 E3 01 10 A0 E3 28 21 9F E5 05 00 A0 E1 2C 60 8D E5 B0 33 CD E1 ?? ?? ?? ?? 01 00 70 E3 02 00 00 0A 00 00 50 E3 3B 00 00 0A 04 00 00 EA ?? ?? ?? ?? 00 30 90 E5 04 00 53 E3 05 00 00 0A 35 00 00 EA B2 33 DD E1 18 00 13 E3 32 00 00 1A 20 00 13 E3 30 00 00 1A B2 33 DD E1 01 00 13 E3 E6 FF FF 0A 24 C0 8D E2 CC E0 9F E5 01 50 A0 E3 38 30 8D E2 10 C0 8D E5 1C C0 A0 E3 0E E0 84 E0 04 50 23 E5 00 40 A0 E3 1C C0 8D E5 05 10 A0 E1 04 C0 A0 E3 06 00 A0 E1 10 20 A0 E3 24 70 8D E5 28 80 8D E5 }
	condition:
		$pattern
}

rule dlinfo_f171b8211d1fa2ef75835fd9c8ee9564 {
	meta:
		aliases = "dlinfo"
		size = "404"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { F0 45 2D E9 5C 61 9F E5 5C 41 9F E5 06 60 8F E0 04 30 96 E7 54 11 9F E5 00 00 93 E5 14 D0 4D E2 01 10 86 E0 ?? ?? ?? ?? 44 31 9F E5 03 30 96 E7 00 50 93 E5 3C 31 9F E5 03 80 86 E0 38 31 9F E5 03 70 86 E0 0D 00 00 EA 1C 20 95 E5 00 00 96 E7 00 20 8D E5 18 20 95 E5 00 00 90 E5 02 21 97 E7 04 20 8D E5 B0 22 D5 E1 08 20 8D E5 04 20 95 E5 0C 20 8D E5 00 20 95 E5 ?? ?? ?? ?? 0C 50 95 E5 00 00 55 E3 05 30 A0 E1 08 10 A0 E1 04 00 A0 E1 EC FF FF 1A E4 30 9F E5 04 20 96 E7 E0 10 9F E5 03 40 96 E7 00 00 92 E5 01 10 86 E0 00 20 94 E5 ?? ?? ?? ?? CC 30 9F E5 00 40 94 E5 A8 70 9F E5 03 50 86 E0 05 00 00 EA }
	condition:
		$pattern
}

rule setlogmask_73931787bdf3d3b975d6769043b2913d {
	meta:
		aliases = "setlogmask"
		size = "152"
		objfiles = "syslogs@libc.a"
	strings:
		$pattern = { F0 45 2D E9 70 60 9F E5 70 A0 9F E5 06 60 8F E0 00 70 50 E2 14 D0 4D E2 0A 80 96 E7 13 00 00 0A 5C 40 9F E5 5C 30 9F E5 04 40 86 E0 03 10 96 E7 04 20 A0 E1 0D 00 A0 E1 4C 30 9F E5 0F E0 A0 E1 03 F0 96 E7 44 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 96 E7 0A 70 86 E7 0D 00 A0 E1 01 10 A0 E3 2C 30 9F E5 0D 50 A0 E1 0F E0 A0 E1 03 F0 96 E7 08 00 A0 E1 14 D0 8D E2 F0 85 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _dl_map_cache_5a80fc4c3b22cf1e9aeea7f18f6465cf {
	meta:
		aliases = "_dl_map_cache"
		size = "688"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { F0 45 2D E9 7C 62 9F E5 7C 82 9F E5 06 60 8F E0 08 00 96 E7 4C D0 4D E2 01 00 70 E3 97 00 00 0A 00 00 50 E3 94 00 00 1A 60 32 9F E5 08 10 8D E2 03 E0 86 E0 0E 00 A0 E1 6A 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 50 A0 E1 00 30 60 82 0A 00 00 8A 00 00 50 E3 0E 00 00 1A 00 20 A0 E1 00 10 A0 E1 05 70 A0 E3 0E 00 A0 E1 00 00 00 EF 01 0A 70 E3 00 C0 A0 E1 04 00 00 9A 00 30 60 E2 10 22 9F E5 02 20 96 E7 00 30 82 E5 01 00 00 EA 00 00 50 E3 04 00 00 AA 00 20 E0 E3 EC 31 9F E5 02 00 A0 E1 03 20 86 E7 75 00 00 EA 1C 10 9D E5 E4 A1 9F E5 01 30 A0 E3 00 40 A0 E1 0A 10 86 E7 03 20 A0 E1 05 00 A0 E1 C0 70 A0 E3 }
	condition:
		$pattern
}

rule __GI___res_init_54ca4113082ed526f10c05dee025a1de {
	meta:
		aliases = "__res_init, __GI___res_init"
		size = "444"
		objfiles = "res_inits@libc.a"
	strings:
		$pattern = { F0 45 2D E9 84 51 9F E5 84 31 9F E5 05 50 8F E0 03 40 95 E7 7C 31 9F E5 1C D0 4D E2 04 20 A0 E1 03 10 95 E7 04 00 8D E2 6C 31 9F E5 6C 61 9F E5 0F E0 A0 E1 03 F0 95 E7 64 31 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 95 E7 ?? ?? ?? ?? ?? ?? ?? ?? 06 40 95 E7 05 30 A0 E3 00 30 84 E5 04 30 A0 E3 04 30 84 E5 01 30 A0 E3 08 30 84 E5 ?? ?? ?? ?? 64 31 D4 E5 00 20 A0 E3 0E 30 C3 E3 01 30 83 E3 64 31 C4 E5 1C 31 9F E5 14 20 84 E5 03 C0 95 E7 00 30 E0 E3 C4 31 84 E5 B0 04 C4 E1 35 3C A0 E3 02 00 A0 E3 02 00 5C E1 B0 01 C4 E1 B2 31 C4 E1 0B 00 00 0A F0 30 9F E5 02 10 A0 E1 06 00 A0 E1 03 E0 85 E0 04 00 00 EA }
	condition:
		$pattern
}

rule initstate_2c6f06cd4b08e58cc361a3e74339e731 {
	meta:
		aliases = "initstate"
		size = "176"
		objfiles = "randoms@libc.a"
	strings:
		$pattern = { F0 45 2D E9 88 40 9F E5 88 50 9F E5 04 40 8F E0 84 30 9F E5 14 D0 4D E2 05 50 84 E0 00 A0 A0 E1 01 60 A0 E1 02 70 A0 E1 03 10 94 E7 05 20 A0 E1 0D 00 A0 E1 64 30 9F E5 0F E0 A0 E1 03 F0 94 E7 05 00 A0 E1 58 30 9F E5 0F E0 A0 E1 03 F0 94 E7 50 30 9F E5 06 10 A0 E1 03 30 84 E0 07 20 A0 E1 0A 00 A0 E1 08 50 93 E5 ?? ?? ?? ?? 0D 00 A0 E1 01 10 A0 E3 30 30 9F E5 0F E0 A0 E1 03 F0 94 E7 04 50 45 E2 0D 80 A0 E1 05 00 A0 E1 14 D0 8D E2 F0 85 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule error_at_line_e92766830d3d3bec420de5667bc2634f {
	meta:
		aliases = "__error_at_line, error_at_line"
		size = "456"
		objfiles = "errors@libc.a"
	strings:
		$pattern = { F0 45 2D E9 8C 51 9F E5 8C C1 9F E5 05 50 8F E0 0C C0 95 E7 00 A0 A0 E1 00 00 9C E5 0C D0 4D E2 00 00 50 E3 01 80 A0 E1 02 40 A0 E1 03 60 A0 E1 0E 00 00 0A 64 71 9F E5 07 30 95 E7 06 00 53 E1 07 00 00 1A 58 31 9F E5 03 00 95 E7 00 00 52 E1 4E 00 00 0A 02 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 4A 00 00 0A 38 31 9F E5 07 60 85 E7 03 40 85 E7 30 31 9F E5 03 30 95 E7 00 00 93 E5 ?? ?? ?? ?? 24 31 9F E5 03 30 95 E7 00 30 93 E5 00 00 53 E3 01 00 00 0A 33 FF 2F E1 07 00 00 EA 0C 31 9F E5 0C 11 9F E5 03 30 95 E7 01 10 85 E0 00 00 93 E5 00 31 9F E5 03 20 95 E7 ?? ?? ?? ?? 00 00 54 E3 07 00 00 0A E4 30 9F E5 }
	condition:
		$pattern
}

rule __libc_pselect_6740a488a8cc481a8277913f0929ccde {
	meta:
		aliases = "pselect, __libc_pselect"
		size = "164"
		objfiles = "pselects@libc.a"
	strings:
		$pattern = { F0 45 2D E9 94 D0 4D E2 B0 40 9D E5 00 A0 A0 E1 00 00 54 E3 01 60 A0 E1 02 70 A0 E1 03 80 A0 E1 B4 50 9D E5 05 00 00 0A 00 30 94 E5 04 00 94 E5 FA 1F A0 E3 88 30 8D E5 ?? ?? ?? ?? 8C 00 8D E5 00 00 55 E3 03 00 00 0A 02 00 A0 E3 05 10 A0 E1 08 20 8D E2 ?? ?? ?? ?? 00 00 54 E3 04 C0 A0 01 88 C0 8D 12 0A 00 A0 E1 06 10 A0 E1 07 20 A0 E1 08 30 A0 E1 00 C0 8D E5 ?? ?? ?? ?? 00 00 55 E3 00 40 A0 E1 03 00 00 0A 02 00 A0 E3 08 10 8D E2 00 20 A0 E3 ?? ?? ?? ?? 04 00 A0 E1 94 D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule pthread_join_28888ae0ef204e8c337c518e58cbafb9 {
	meta:
		aliases = "pthread_join"
		size = "516"
		objfiles = "joins@libpthread.a"
	strings:
		$pattern = { F0 45 2D E9 A4 D0 4D E2 00 70 A0 E1 01 A0 A0 E1 6C FF FF EB D8 81 9F E5 D8 31 9F E5 08 80 8F E0 03 20 98 E7 07 3B A0 E1 23 3B A0 E1 03 52 82 E0 C4 31 9F E5 9C 00 8D E5 03 30 88 E0 9C 10 9D E5 05 00 A0 E1 98 30 8D E5 94 50 8D E5 ?? ?? ?? ?? 08 40 95 E5 00 00 54 E3 02 00 00 0A 10 30 94 E5 07 00 53 E1 03 00 00 0A 05 00 A0 E1 ?? ?? ?? ?? 03 00 A0 E3 5C 00 00 EA 9C 30 9D E5 03 00 54 E1 03 00 00 1A 05 00 A0 E1 ?? ?? ?? ?? 23 00 A0 E3 55 00 00 EA 2D 30 D4 E5 00 00 53 E3 02 00 00 1A 38 30 94 E5 00 00 53 E3 03 00 00 0A 05 00 A0 E1 ?? ?? ?? ?? 16 00 A0 E3 4B 00 00 EA 2C 30 D4 E5 00 00 53 E3 2C 00 00 1A }
	condition:
		$pattern
}

rule __mulvdi3_81b434e466e8be99bb561546006dc78d {
	meta:
		aliases = "__mulvdi3"
		size = "408"
		objfiles = "_mulvdi3@libgcc.a"
	strings:
		$pattern = { F0 45 2D E9 C0 0F 51 E1 01 60 A0 E1 04 D0 4D E2 02 10 A0 E1 00 50 A0 E1 00 E0 A0 E1 03 20 A0 E1 06 00 00 1A C1 0F 53 E1 19 00 00 1A 91 35 C4 E0 03 00 A0 E1 04 10 A0 E1 04 D0 8D E2 F0 85 BD E8 C1 0F 53 E1 01 A0 A0 E1 26 00 00 1A 90 31 84 E0 03 70 A0 E1 04 00 A0 E1 96 31 84 E0 00 00 56 E3 04 40 61 B0 00 00 51 E3 1B 00 00 BA 00 10 A0 E3 03 00 90 E0 04 10 A1 E0 C0 3F A0 E1 01 00 53 E1 11 00 00 1A 00 80 A0 E1 08 10 A0 E1 07 00 A0 E1 E8 FF FF EA 91 35 84 E0 92 5E 86 E0 00 00 52 E3 06 60 6E B0 00 00 5E E3 03 70 A0 E1 04 00 A0 E1 06 00 00 BA 00 10 A0 E3 05 00 90 E0 06 10 A1 E0 C0 3F A0 E1 01 00 53 E1 }
	condition:
		$pattern
}

rule __powidf2_60ce462f16baff5b335ab31686a2a163 {
	meta:
		aliases = "__powidf2"
		size = "204"
		objfiles = "_powidf2@libgcc.a"
	strings:
		$pattern = { F0 45 2D E9 C2 3F 22 E0 C2 3F 43 E0 01 00 13 E3 B0 80 9F 05 04 D0 4D E2 02 A0 A0 E1 00 40 A0 E1 01 50 A0 E1 00 70 A0 11 01 80 A0 11 00 70 A0 03 03 60 A0 E1 A6 60 B0 E1 04 00 A0 E1 05 10 A0 E1 04 20 A0 E1 05 30 A0 E1 11 00 00 0A ?? ?? ?? ?? 01 00 16 E3 00 40 A0 E1 01 50 A0 E1 07 00 A0 E1 08 10 A0 E1 04 20 A0 E1 05 30 A0 E1 F0 FF FF 0A ?? ?? ?? ?? A6 60 B0 E1 00 70 A0 E1 01 80 A0 E1 04 00 A0 E1 05 10 A0 E1 04 20 A0 E1 05 30 A0 E1 ED FF FF 1A 00 00 5A E3 06 00 00 AA 07 20 A0 E1 08 30 A0 E1 00 00 A0 E3 18 10 9F E5 ?? ?? ?? ?? 00 70 A0 E1 01 80 A0 E1 07 00 A0 E1 08 10 A0 E1 04 D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule __GI_pthread_setschedparam_231e44efdfc128b1488415d4479f5c14 {
	meta:
		aliases = "pthread_setschedparam, __GI_pthread_setschedparam"
		size = "228"
		objfiles = "pthreads@libpthread.a"
	strings:
		$pattern = { F0 45 2D E9 CC A0 9F E5 CC 30 9F E5 0A A0 8F E0 00 70 A0 E1 03 00 9A E7 07 3B A0 E1 23 3B A0 E1 03 52 80 E0 04 D0 4D E2 01 60 A0 E1 05 00 A0 E1 00 10 A0 E3 02 80 A0 E1 ?? ?? ?? ?? 08 40 95 E5 00 00 54 E3 02 00 00 0A 10 30 94 E5 07 00 53 E1 17 00 00 0A 05 00 A0 E1 ?? ?? ?? ?? 03 00 A0 E3 1A 00 00 EA 05 00 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 90 E5 15 00 00 EA 00 00 56 E3 00 10 98 15 06 10 A0 01 18 10 84 E5 05 00 A0 E1 ?? ?? ?? ?? 48 30 9F E5 03 30 9A E7 00 30 93 E5 00 00 53 E3 01 00 00 BA 18 00 94 E5 ?? ?? ?? ?? 00 00 A0 E3 06 00 00 EA 14 00 94 E5 06 10 A0 E1 08 20 A0 E1 ?? ?? ?? ?? 01 00 70 E3 }
	condition:
		$pattern
}

rule __GI_inet_aton_462117eab2c19d20a4b5fb2a486c7611 {
	meta:
		aliases = "inet_aton, __GI_inet_aton"
		size = "244"
		objfiles = "inet_atons@libc.a"
	strings:
		$pattern = { F0 45 2D E9 E0 50 9F E5 00 00 50 E3 05 50 8F E0 01 60 A0 E1 32 00 00 0A 00 E0 A0 E3 CC A0 9F E5 01 40 A0 E3 0E 80 A0 E1 0A 70 A0 E3 1F 00 00 EA 00 30 D0 E5 0A 10 95 E7 83 30 A0 E1 B1 30 93 E1 08 00 13 E3 26 00 00 0A 08 C0 A0 E1 05 00 00 EA 9C 07 03 E0 30 30 43 E2 02 C0 83 E0 FF 00 5C E3 1F 00 00 CA 01 00 80 E2 00 20 D0 E5 82 30 A0 E1 B1 30 93 E1 08 00 13 E3 F4 FF FF 1A 04 00 54 E3 03 00 00 0A 2E 00 52 E3 15 00 00 1A 01 00 80 E2 04 00 00 EA 00 00 52 E3 01 00 80 E2 01 00 00 0A 20 00 13 E3 0E 00 00 0A 0E E4 8C E1 01 40 84 E2 04 00 54 E3 DD FF FF DA 00 00 56 E3 2E 2C A0 11 FF 38 0E 12 23 24 82 11 }
	condition:
		$pattern
}

rule readdir_r_c7b6c0bc45a9d179a35a485a9e6a4dfd {
	meta:
		aliases = "__GI_readdir_r, readdir_r"
		size = "284"
		objfiles = "readdir_rs@libc.a"
	strings:
		$pattern = { F0 45 2D E9 FC 60 9F E5 FC 30 9F E5 06 60 8F E0 18 40 80 E2 14 D0 4D E2 00 50 A0 E1 01 A0 A0 E1 0D 00 A0 E1 03 10 96 E7 02 80 A0 E1 DC 30 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 CC 30 9F E5 0F E0 A0 E1 03 F0 96 E7 00 70 A0 E3 07 40 A0 E1 0C 00 95 E9 02 00 53 E1 0E 00 00 8A 00 00 95 E5 0C 10 95 E5 14 20 95 E5 ?? ?? ?? ?? 00 00 50 E3 06 00 00 CA 00 30 A0 E3 00 30 88 E5 00 40 A0 01 15 00 00 0A ?? ?? ?? ?? 00 40 90 E5 12 00 00 EA 08 00 85 E5 04 40 85 E5 04 30 95 E5 0C 10 95 E5 01 70 83 E0 04 20 97 E5 B8 C0 D7 E1 10 20 85 E5 01 20 93 E7 03 30 8C E0 00 00 52 E3 04 30 85 E5 E2 FF FF 0A }
	condition:
		$pattern
}

rule __encode_dotted_7bb9988b5cffae0962f8335d10de3779 {
	meta:
		aliases = "__encode_dotted"
		size = "168"
		objfiles = "encodeds@libc.a"
	strings:
		$pattern = { F0 47 2D E9 00 40 A0 E1 01 80 A0 E1 02 90 A0 E1 00 A0 A0 E3 16 00 00 EA ?? ?? ?? ?? 00 60 50 E2 06 50 64 E0 02 00 00 1A 04 00 A0 E1 ?? ?? ?? ?? 00 50 A0 E1 01 70 8A E2 09 30 6A E0 00 00 55 E3 04 10 A0 E1 07 00 88 E0 05 20 A0 E1 01 30 43 E2 01 40 86 E2 11 00 00 0A 03 00 55 E1 0F 00 00 2A 0A 50 C8 E7 ?? ?? ?? ?? 00 00 56 E3 07 A0 85 E0 05 00 00 0A 00 00 54 E2 2E 10 A0 E3 02 00 00 0A 00 30 D4 E5 00 00 53 E3 E2 FF FF 1A 00 00 59 E3 00 30 A0 C3 01 00 8A C2 0A 30 C8 C7 F0 87 BD C8 00 00 E0 E3 F0 87 BD E8 }
	condition:
		$pattern
}

rule readunix_a5815a18ddfaa686e7b55422ad0e196e {
	meta:
		aliases = "readunix"
		size = "432"
		objfiles = "clnt_unixs@libc.a"
	strings:
		$pattern = { F0 47 2D E9 00 60 A0 E1 38 D0 4D E2 01 90 A0 E1 0C 00 90 E5 FA 1F A0 E3 02 70 A0 E1 ?? ?? ?? ?? 80 81 9F E5 08 20 96 E5 00 00 57 E3 FA 3F A0 E3 08 80 8F E0 92 03 25 E0 07 40 A0 01 56 00 00 0A 00 30 96 E5 01 20 A0 E3 B0 23 CD E1 2C 30 8D E5 2C A0 8D E2 01 10 A0 E3 05 20 A0 E1 0A 00 A0 E1 ?? ?? ?? ?? 01 00 70 E3 00 40 A0 E1 05 00 00 0A 00 00 50 E3 05 30 A0 03 00 40 E0 03 84 30 86 05 45 00 00 0A 07 00 00 EA ?? ?? ?? ?? 00 30 90 E5 04 00 53 E3 EE FF FF 0A 04 30 A0 E3 84 30 86 E5 00 30 90 E5 35 00 00 EA 00 A0 96 E5 24 C0 8D E2 F4 E0 9F E5 01 50 A0 E3 38 30 8D E2 10 C0 8D E5 18 C0 A0 E3 00 40 A0 E3 }
	condition:
		$pattern
}

rule regcomp_fac1cfffcc9d9bac4c8503b243d03d11 {
	meta:
		aliases = "__regcomp, regcomp"
		size = "360"
		objfiles = "regex_olds@libc.a"
	strings:
		$pattern = { F0 47 2D E9 01 00 12 E3 00 60 A0 E3 40 31 9F E5 02 50 A0 E1 3C 21 9F E5 00 40 A0 E1 00 60 80 E5 04 60 80 E5 08 60 80 E5 01 0C A0 E3 02 80 A0 01 03 80 A0 11 01 A0 A0 E1 ?? ?? ?? ?? 18 71 9F E5 02 30 15 E2 10 00 84 E5 07 70 8F E0 18 00 00 0A 01 0C A0 E3 ?? ?? ?? ?? 06 00 50 E1 14 00 84 E5 0C 50 A0 03 38 00 00 0A F0 90 9F E5 F0 E0 9F E5 06 10 A0 E1 0A 00 00 EA 09 30 97 E7 FF 20 01 E2 00 30 93 E5 14 C0 94 E5 B0 30 93 E1 01 00 13 E3 0E 30 97 17 00 30 93 15 00 20 D3 17 01 20 CC E7 01 10 81 E2 FF 00 51 E3 81 00 A0 E1 F1 FF FF 9A 00 00 00 EA 14 30 84 E5 1C 20 D4 E5 04 00 15 E3 80 30 C2 03 80 20 82 13 }
	condition:
		$pattern
}

rule __res_query_82e541090125db228c9ef39bebaba4c7 {
	meta:
		aliases = "__GI___res_query, __res_query"
		size = "352"
		objfiles = "res_querys@libc.a"
	strings:
		$pattern = { F0 47 2D E9 01 10 51 E2 01 10 A0 13 00 80 A0 E1 28 71 9F E5 00 00 50 E3 01 00 A0 11 01 00 81 03 48 D0 4D E2 00 10 A0 E3 00 00 50 E3 07 70 8F E0 44 10 8D E5 02 A0 A0 E1 03 90 A0 E1 03 00 00 0A ?? ?? ?? ?? 00 40 E0 E3 03 30 A0 E3 28 00 00 EA 0C 60 8D E2 00 10 A0 E1 28 20 A0 E3 06 00 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? D4 30 9F E5 34 50 8D E2 03 40 97 E7 CC 30 9F E5 04 20 A0 E1 03 10 97 E7 05 00 A0 E1 C0 30 9F E5 0F E0 A0 E1 03 F0 97 E7 04 00 A0 E1 B4 30 9F E5 0F E0 A0 E1 03 F0 97 E7 AC 30 9F E5 05 00 A0 E1 03 40 97 E7 01 10 A0 E3 A0 30 9F E5 0F E0 A0 E1 03 F0 97 E7 98 30 9F E5 04 20 A0 E1 44 C0 8D E2 }
	condition:
		$pattern
}

rule __decode_answer_8f8f4e6cb729933fca6dcf21d4243a7a {
	meta:
		aliases = "__decode_answer"
		size = "216"
		objfiles = "decodeas@libc.a"
	strings:
		$pattern = { F0 47 2D E9 01 DC 4D E2 02 70 A0 E1 03 50 A0 E1 0D 20 A0 E1 01 3C A0 E3 00 80 A0 E1 01 60 A0 E1 ?? ?? ?? ?? 00 40 50 E2 0D A0 A0 E1 26 00 00 BA 07 30 66 E0 0A 70 84 E2 07 90 53 E0 09 40 A0 41 21 00 00 4A 0D 00 A0 E1 ?? ?? ?? ?? 06 40 84 E0 00 00 85 E5 04 00 88 E0 04 20 D8 E7 01 30 D0 E5 02 E0 80 E2 02 34 83 E1 04 30 85 E5 02 10 D0 E5 01 30 DE E5 02 20 8E E2 01 34 83 E1 08 30 85 E5 03 30 D2 E5 02 10 DE E5 01 C0 D2 E5 01 3C 83 E1 02 20 D2 E5 0C 38 83 E1 02 34 83 E1 0C 30 85 E5 09 30 D0 E5 06 20 DE E5 0A 40 84 E2 02 34 83 E1 03 00 59 E1 0A 00 80 E2 18 40 85 E5 14 00 85 E5 10 30 85 E5 00 40 E0 B3 }
	condition:
		$pattern
}

rule __gnu_uldivmod_helper_b200b21ee3421b3908e5f4fb1d9321e4 {
	meta:
		aliases = "__gnu_ldivmod_helper, __gnu_uldivmod_helper"
		size = "68"
		objfiles = "bpabi@libgcc.a"
	strings:
		$pattern = { F0 47 2D E9 02 70 A0 E1 03 80 A0 E1 00 90 A0 E1 01 A0 A0 E1 ?? ?? ?? ?? 90 08 0C E0 90 37 84 E0 97 C1 22 E0 04 40 82 E0 20 20 9D E5 03 90 59 E0 04 A0 CA E0 00 50 A0 E1 01 60 A0 E1 00 06 82 E8 F0 87 BD E8 }
	condition:
		$pattern
}

rule __GI_fread_unlocked_a394801e4338642c48be6a203ad70eb8 {
	meta:
		aliases = "fread_unlocked, __GI_fread_unlocked"
		size = "368"
		objfiles = "fread_unlockeds@libc.a"
	strings:
		$pattern = { F0 47 2D E9 03 60 A0 E1 B0 30 D3 E1 54 A1 9F E5 83 30 03 E2 80 00 53 E3 0A A0 8F E0 00 50 A0 E1 01 80 A0 E1 02 40 A0 E1 04 00 00 8A 06 00 A0 E1 80 10 A0 E3 ?? ?? ?? ?? 00 00 50 E3 46 00 00 1A 00 00 58 E3 00 00 54 13 43 00 00 0A 00 00 E0 E3 08 10 A0 E1 ?? ?? ?? ?? 00 00 54 E1 36 00 00 8A 98 04 09 E0 05 70 A0 E1 00 00 A0 E3 09 50 A0 E1 06 00 00 EA 24 30 92 E5 01 50 55 E2 00 30 C7 E5 B0 10 C6 E1 28 00 86 E5 26 00 00 0A 01 70 87 E2 B0 30 D6 E1 01 20 03 E2 02 00 13 E3 02 21 86 E0 01 10 43 E2 F2 FF FF 1A 10 10 96 E5 14 30 96 E5 01 20 53 E0 0B 00 00 0A 02 00 55 E1 05 40 A0 31 02 40 A0 21 07 00 A0 E1 }
	condition:
		$pattern
}

rule _svcauth_unix_9417e9e0b29e68c4263bfa77581cb18e {
	meta:
		aliases = "_svcauth_unix"
		size = "580"
		objfiles = "svc_authuxs@libc.a"
	strings:
		$pattern = { F0 47 2D E9 18 60 90 E5 18 D0 4D E2 18 30 86 E2 46 2F 86 E2 04 30 86 E5 14 20 86 E5 20 80 91 E5 01 30 A0 E3 08 20 A0 E1 00 A0 A0 E1 01 70 A0 E1 0D 00 A0 E1 1C 10 91 E5 ?? ?? ?? ?? 0D 00 A0 E1 08 10 A0 E1 04 30 9D E5 0F E0 A0 E1 18 F0 93 E5 E4 91 9F E5 00 00 50 E3 09 90 8F E0 52 00 00 0A 00 40 A0 E1 04 10 94 E4 FF 28 01 E2 21 3C A0 E1 22 34 83 E1 FF 2C 01 E2 02 34 83 E1 01 3C 83 E1 00 30 86 E5 04 10 90 E5 FF 28 01 E2 21 3C A0 E1 22 34 83 E1 FF 2C 01 E2 02 34 83 E1 01 5C 83 E1 FF 00 55 E3 5A 00 00 8A 04 40 84 E2 04 10 A0 E1 05 20 A0 E1 04 00 96 E5 ?? ?? ?? ?? 04 30 96 E5 03 20 85 E2 00 00 A0 E3 }
	condition:
		$pattern
}

rule realloc_b4eae088aab67200d20fdcaaa5e4ff5a {
	meta:
		aliases = "realloc"
		size = "316"
		objfiles = "reallocs@libc.a"
	strings:
		$pattern = { F0 47 2D E9 1C A1 9F E5 00 40 51 E2 0A A0 8F E0 00 80 A0 E1 01 00 00 1A ?? ?? ?? ?? 01 00 00 EA 00 00 50 E3 02 00 00 1A 04 00 A0 E1 F0 47 BD E8 ?? ?? ?? ?? 07 30 84 E2 03 60 C3 E3 0B 00 56 E3 04 70 10 E5 0C 60 A0 93 07 00 56 E1 04 90 40 E2 1F 00 00 9A D0 30 9F E5 06 40 67 E0 03 50 9A E7 C8 30 9F E5 05 00 A0 E1 0F E0 A0 E1 03 F0 9A E7 BC 30 9F E5 04 20 A0 E1 07 10 89 E0 03 00 9A E7 ?? ?? ?? ?? AC 30 9F E5 00 40 A0 E1 05 00 A0 E1 0F E0 A0 E1 03 F0 9A E7 00 00 54 E3 07 30 84 10 04 30 08 15 1D 00 00 1A 04 00 46 E2 ?? ?? ?? ?? 00 40 50 E2 04 00 00 0A 04 20 47 E2 08 10 A0 E1 ?? ?? ?? ?? 08 00 A0 E1 }
	condition:
		$pattern
}

rule posix_fadvise64_86ee5b63a760a71c731d2160c9d5ae2f {
	meta:
		aliases = "__libc_posix_fadvise64, posix_fadvise64"
		size = "80"
		objfiles = "posix_fadvise64s@libc.a"
	strings:
		$pattern = { F0 47 2D E9 20 70 8D E2 80 01 97 E8 02 90 A0 E1 07 40 A0 E1 03 A0 A0 E1 08 50 A0 E1 C8 6F A0 E1 09 20 A0 E1 28 10 9D E5 1C 70 9F E5 00 00 00 EF 01 0A 70 E3 02 00 00 9A 26 00 70 E3 00 00 60 12 F0 87 BD 18 00 00 A0 E3 F0 87 BD E8 0E 01 00 00 }
	condition:
		$pattern
}

rule svcudp_enablecache_2de74de75336505a75f039b68425c496 {
	meta:
		aliases = "svcudp_enablecache"
		size = "312"
		objfiles = "svc_udps@libc.a"
	strings:
		$pattern = { F0 47 2D E9 30 90 90 E5 0C 51 9F E5 B0 81 99 E5 05 50 8F E0 00 00 58 E3 01 60 A0 E1 09 00 00 0A F8 30 9F E5 F8 20 9F E5 03 30 95 E7 F4 10 9F E5 00 00 93 E5 02 20 85 E0 01 10 85 E0 ?? ?? ?? ?? 00 00 A0 E3 F0 87 BD E8 2C 00 A0 E3 ?? ?? ?? ?? 00 70 50 E2 09 00 00 1A C0 30 9F E5 C8 20 9F E5 03 30 95 E7 BC 10 9F E5 00 00 93 E5 02 20 85 E0 01 10 85 E0 ?? ?? ?? ?? 07 00 A0 E1 F0 87 BD E8 06 A2 A0 E1 00 60 87 E5 0C 80 87 E5 0A 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 40 A0 E1 04 00 87 E5 78 30 9F 05 84 20 9F 05 03 30 95 07 00 00 93 05 0D 00 00 0A 0A 20 A0 E1 08 10 A0 E1 06 61 A0 E1 ?? ?? ?? ?? 06 00 A0 E1 }
	condition:
		$pattern
}

rule clntraw_create_9a1ecd5f464722e2545832390c616dfe {
	meta:
		aliases = "clntraw_create"
		size = "284"
		objfiles = "clnt_raws@libc.a"
	strings:
		$pattern = { F0 47 2D E9 30 D0 4D E2 00 80 A0 E1 01 A0 A0 E1 ?? ?? ?? ?? A0 40 90 E5 E4 70 9F E5 00 00 54 E3 07 70 8F E0 00 50 A0 E1 04 60 A0 11 06 00 00 1A 01 00 A0 E3 CC 10 9F E5 ?? ?? ?? ?? 00 00 50 E3 2C 00 00 0A 00 60 A0 E1 A0 00 85 E5 00 C0 A0 E3 0C 50 84 E2 8A 1D 86 E2 04 10 81 E2 0C 30 A0 E1 18 20 A0 E3 05 00 A0 E1 02 90 A0 E3 04 C0 8D E5 0C 80 8D E5 10 A0 8D E5 08 90 8D E5 ?? ?? ?? ?? 05 00 A0 E1 0D 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 02 00 00 1A 70 00 9F E5 00 00 87 E0 ?? ?? ?? ?? 10 30 94 E5 05 00 A0 E1 0F E0 A0 E1 10 F0 93 E5 58 30 9F E5 10 20 94 E5 03 00 86 E7 1C 30 92 E5 00 00 53 E3 01 00 00 0A }
	condition:
		$pattern
}

rule __GI_setvbuf_9a3b0fb176df9cf2adaa279d54041ef8 {
	meta:
		aliases = "setvbuf, __GI_setvbuf"
		size = "388"
		objfiles = "setvbufs@libc.a"
	strings:
		$pattern = { F0 47 2D E9 34 90 90 E5 5C A1 9F E5 00 00 59 E3 0A A0 8F E0 10 D0 4D E2 00 50 A0 E1 01 60 A0 E1 02 70 A0 E1 03 80 A0 E1 0B 00 00 1A 3C 31 9F E5 38 40 80 E2 03 10 9A E7 0D 00 A0 E1 30 31 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 9A E7 04 00 A0 E1 20 31 9F E5 0F E0 A0 E1 03 F0 9A E7 02 00 57 E3 04 00 00 9A ?? ?? ?? ?? 00 40 E0 E3 16 30 A0 E3 00 30 80 E5 32 00 00 EA B0 30 D5 E1 F8 20 9F E5 02 20 03 E0 00 00 52 E3 00 40 E0 13 2C 00 00 1A 00 00 58 E3 02 00 57 13 03 3C C3 E3 02 60 A0 01 07 34 83 E1 00 10 A0 13 01 10 A0 03 B0 30 C5 E1 06 80 A0 01 06 40 A0 01 0D 00 00 0A 00 00 56 E3 01 40 A0 11 0A 00 00 1A }
	condition:
		$pattern
}

rule __GI_fread_a29d4ec570f8ea9e2b5786d006147ab8 {
	meta:
		aliases = "fwrite, fread, __GI_fwrite, __GI_fread"
		size = "176"
		objfiles = "fwrites@libc.a, freads@libc.a"
	strings:
		$pattern = { F0 47 2D E9 34 90 93 E5 8C 50 9F E5 00 00 59 E3 05 50 8F E0 10 D0 4D E2 03 60 A0 E1 00 A0 A0 E1 01 70 A0 E1 02 80 A0 E1 0B 00 00 1A 38 40 83 E2 68 30 9F E5 0D 00 A0 E1 03 10 95 E7 04 20 A0 E1 5C 30 9F E5 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 50 30 9F E5 0F E0 A0 E1 03 F0 95 E7 0A 00 A0 E1 07 10 A0 E1 08 20 A0 E1 06 30 A0 E1 ?? ?? ?? ?? 00 00 59 E3 00 40 A0 E1 04 00 00 1A 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 10 D0 8D E2 F0 87 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_pmap_set_4aa44f8ceb496d7d05a1e2899321cb99 {
	meta:
		aliases = "pmap_set, __GI_pmap_set"
		size = "308"
		objfiles = "pmap_clnts@libc.a"
	strings:
		$pattern = { F0 47 2D E9 38 D0 4D E2 20 40 8D E2 00 C0 E0 E3 00 90 A0 E1 04 00 A0 E1 34 C0 8D E5 01 70 A0 E1 02 80 A0 E1 03 A0 A0 E1 5A FF FF EB E4 60 9F E5 00 00 50 E3 06 60 8F E0 33 00 00 0A D8 20 9F E5 04 00 A0 E1 02 30 86 E0 04 40 93 E5 19 EE A0 E3 02 30 96 E7 34 C0 8D E2 C0 10 9F E5 02 20 A0 E3 04 C0 8D E5 0C E0 8D E5 00 40 8D E5 08 E0 8D E5 ?? ?? ?? ?? 00 50 50 E2 23 00 00 0A A0 30 9F E5 A0 10 9F E5 10 90 8D E5 14 70 8D E5 18 80 8D E5 1C A0 8D E5 03 30 86 E0 8C 20 9F E5 04 40 95 E5 08 C0 8D E2 00 30 8D E5 01 10 86 E0 30 30 8D E2 03 00 91 E8 04 30 8D E5 02 20 86 E0 03 00 8C E8 10 30 8D E2 05 00 A0 E1 }
	condition:
		$pattern
}

rule __GI_ceil_5532adeb3a3017b6e75e4a9d9b601b1f {
	meta:
		aliases = "ceil, __GI_ceil"
		size = "396"
		objfiles = "s_ceils@libm.a"
	strings:
		$pattern = { F0 47 2D E9 41 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF 7F 43 E2 03 70 47 E2 08 D0 4D E2 00 20 A0 E3 00 30 A0 E3 13 00 57 E3 00 80 A0 E1 01 90 A0 E1 00 40 A0 E1 01 60 A0 E1 00 A0 A0 E1 0C 00 8D E8 00 50 A0 E1 23 00 00 CA 00 00 57 E3 0F 00 00 AA 24 21 9F E5 24 31 9F E5 ?? ?? ?? ?? 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? ?? 00 00 50 E3 3B 00 00 0A 00 00 59 E3 02 61 A0 B3 02 00 00 BA 06 30 98 E1 36 00 00 0A F8 60 9F E5 00 A0 A0 E3 33 00 00 EA F0 30 9F E5 53 47 A0 E1 01 30 04 E0 00 30 93 E1 31 00 00 0A D0 20 9F E5 D0 30 9F E5 ?? ?? ?? ?? 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? ?? 00 00 50 E3 26 00 00 0A 00 00 59 E3 }
	condition:
		$pattern
}

rule __GI_floor_d8bc5e7fb9ee7957ee72ab763fa69ccd {
	meta:
		aliases = "floor, __GI_floor"
		size = "404"
		objfiles = "s_floors@libm.a"
	strings:
		$pattern = { F0 47 2D E9 41 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF 7F 43 E2 03 70 47 E2 08 D0 4D E2 00 20 A0 E3 00 30 A0 E3 13 00 57 E3 00 80 A0 E1 01 90 A0 E1 00 40 A0 E1 01 60 A0 E1 00 A0 A0 E1 0C 00 8D E8 00 50 A0 E1 25 00 00 CA 00 00 57 E3 10 00 00 AA 2C 21 9F E5 2C 31 9F E5 ?? ?? ?? ?? 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? ?? 00 00 50 E3 3D 00 00 0A 00 00 59 E3 00 A0 A0 A3 0A 60 A0 A1 39 00 00 AA 02 31 C6 E3 0A 30 93 E1 FC 60 9F 15 11 00 00 1A 34 00 00 EA F4 30 9F E5 53 47 A0 E1 01 30 04 E0 00 30 93 E1 32 00 00 0A D4 20 9F E5 D4 30 9F E5 ?? ?? ?? ?? 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? ?? 00 00 50 E3 27 00 00 0A }
	condition:
		$pattern
}

rule read_encoded_value_with_base_ef1c218480080381811beece05d79a23 {
	meta:
		aliases = "read_encoded_value_with_base"
		size = "412"
		objfiles = "unwind_c@libgcc.a"
	strings:
		$pattern = { F0 47 2D E9 50 00 50 E3 08 D0 4D E2 00 70 A0 E1 01 80 A0 E1 02 60 A0 E1 03 A0 A0 E1 25 00 00 0A 0F 30 00 E2 02 90 A0 E1 0C 00 53 E3 03 F1 8F 90 4D 00 00 EA 0B 00 00 EA 4C 00 00 EA 51 00 00 EA 08 00 00 EA 20 00 00 EA 47 00 00 EA 46 00 00 EA 45 00 00 EA 44 00 00 EA 2C 00 00 EA 3B 00 00 EA 00 00 00 EA 18 00 00 EA 00 30 D2 E5 01 20 D2 E5 02 00 D6 E5 03 10 D6 E5 02 34 83 E1 00 38 83 E1 01 1C 83 E1 04 60 86 E2 00 00 51 E3 05 00 00 0A 70 30 07 E2 10 00 53 E3 09 80 A0 01 08 10 81 E0 80 00 17 E3 00 10 91 15 06 00 A0 E1 00 10 8A E5 08 D0 8D E2 F0 87 BD E8 03 30 82 E2 03 30 C3 E3 04 10 93 E4 03 60 A0 E1 }
	condition:
		$pattern
}

rule pthread_sighandler_553d874a57dd34cb387723ebcb3026dd {
	meta:
		aliases = "pthread_sighandler"
		size = "148"
		objfiles = "signalss@libpthread.a"
	strings:
		$pattern = { F0 47 2D E9 58 D0 4D E2 00 70 A0 E1 03 90 A0 E1 01 80 A0 E1 02 A0 A0 E1 B3 FF FF EB 58 30 D0 E5 64 C0 9F E5 00 00 53 E3 00 30 A0 13 0C C0 8F E0 00 50 A0 E1 20 70 80 15 58 30 C0 15 10 00 00 1A 54 60 90 E5 44 40 9F E5 00 00 56 E3 54 D0 80 05 78 10 8D E2 58 20 A0 E3 0D 00 A0 E1 04 40 8C E0 ?? ?? ?? ?? 07 00 A0 E1 08 10 A0 E1 0A 20 A0 E1 09 30 A0 E1 0F E0 A0 E1 07 F1 94 E7 00 00 56 E3 54 60 85 05 58 D0 8D E2 F0 87 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getrpcent_r_77c54845c1b2cedb1c5ac0b070054e4b {
	meta:
		aliases = "getrpcent_r"
		size = "172"
		objfiles = "getrpcents@libc.a"
	strings:
		$pattern = { F0 47 2D E9 88 40 9F E5 88 50 9F E5 18 D0 4D E2 04 40 8F E0 02 90 A0 E1 7C 20 9F E5 05 50 84 E0 08 70 8D E2 00 80 A0 E1 01 A0 A0 E1 07 00 A0 E1 02 10 94 E7 03 60 A0 E1 05 20 A0 E1 5C 30 9F E5 0F E0 A0 E1 03 F0 94 E7 54 30 9F E5 05 00 A0 E1 0F E0 A0 E1 03 F0 94 E7 ?? ?? ?? ?? 08 10 A0 E1 0A 20 A0 E1 09 30 A0 E1 00 60 8D E5 10 FF FF EB 01 10 A0 E3 00 50 A0 E1 28 30 9F E5 07 00 A0 E1 0F E0 A0 E1 03 F0 94 E7 05 00 A0 E1 18 D0 8D E2 F0 87 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getrpcbynumber_r_0720d52710d751050812a411a01fc74d {
	meta:
		aliases = "getrpcbynumber_r"
		size = "180"
		objfiles = "getrpcents@libc.a"
	strings:
		$pattern = { F0 47 2D E9 90 40 9F E5 90 50 9F E5 18 D0 4D E2 04 40 8F E0 02 A0 A0 E1 84 20 9F E5 05 50 84 E0 08 90 8D E2 00 70 A0 E1 01 80 A0 E1 09 00 A0 E1 02 10 94 E7 03 60 A0 E1 05 20 A0 E1 64 30 9F E5 0F E0 A0 E1 03 F0 94 E7 5C 30 9F E5 05 00 A0 E1 0F E0 A0 E1 03 F0 94 E7 07 00 A0 E1 ?? ?? ?? ?? 38 C0 9D E5 08 10 A0 E1 0A 20 A0 E1 06 30 A0 E1 00 C0 8D E5 57 FE FF EB 01 10 A0 E3 00 50 A0 E1 28 30 9F E5 09 00 A0 E1 0F E0 A0 E1 03 F0 94 E7 05 00 A0 E1 18 D0 8D E2 F0 87 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getrpcbyname_r_883e502330d26635844cfecec24acf86 {
	meta:
		aliases = "getrpcbyname_r"
		size = "180"
		objfiles = "getrpcents@libc.a"
	strings:
		$pattern = { F0 47 2D E9 90 40 9F E5 90 50 9F E5 18 D0 4D E2 04 40 8F E0 02 A0 A0 E1 84 20 9F E5 05 50 84 E0 08 90 8D E2 00 70 A0 E1 01 80 A0 E1 09 00 A0 E1 02 10 94 E7 03 60 A0 E1 05 20 A0 E1 64 30 9F E5 0F E0 A0 E1 03 F0 94 E7 5C 30 9F E5 05 00 A0 E1 0F E0 A0 E1 03 F0 94 E7 07 00 A0 E1 ?? ?? ?? ?? 38 C0 9D E5 08 10 A0 E1 0A 20 A0 E1 06 30 A0 E1 00 C0 8D E5 98 FE FF EB 01 10 A0 E3 00 50 A0 E1 28 30 9F E5 09 00 A0 E1 0F E0 A0 E1 03 F0 94 E7 05 00 A0 E1 18 D0 8D E2 F0 87 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svctcp_create_bd9b6a40384c3b9e22cc3fe92ebd545e {
	meta:
		aliases = "svctcp_create"
		size = "460"
		objfiles = "svc_tcps@libc.a"
	strings:
		$pattern = { F0 47 2D E9 A4 61 9F E5 18 D0 4D E2 01 00 70 E3 10 30 A0 E3 06 60 8F E0 00 50 A0 E1 14 30 8D E5 01 A0 A0 E1 02 90 A0 E1 00 70 A0 13 0B 00 00 1A 02 00 A0 E3 01 10 A0 E3 06 20 A0 E3 ?? ?? ?? ?? 00 50 50 E2 01 70 A0 A3 04 00 00 AA 60 01 9F E5 00 70 A0 E3 00 00 86 E0 ?? ?? ?? ?? 50 00 00 EA 04 40 8D E2 00 10 A0 E3 10 20 A0 E3 04 00 A0 E1 ?? ?? ?? ?? 02 30 A0 E3 05 00 A0 E1 04 10 A0 E1 B4 30 CD E1 ?? ?? ?? ?? 00 00 50 E3 05 00 00 0A 00 30 A0 E3 05 00 A0 E1 04 10 A0 E1 14 20 9D E5 B6 30 CD E1 ?? ?? ?? ?? 04 10 A0 E1 05 00 A0 E1 14 20 8D E2 ?? ?? ?? ?? 00 00 50 E3 04 00 00 1A 05 00 A0 E1 02 10 A0 E3 }
	condition:
		$pattern
}

rule __parsepwent_123397ca429dfeaf4f8971d9ca257543 {
	meta:
		aliases = "__parsepwent"
		size = "188"
		objfiles = "__parsepwents@libc.a"
	strings:
		$pattern = { F0 47 2D E9 A8 20 9F E5 A8 30 9F E5 08 D0 4D E2 02 20 8F E0 00 50 A0 E3 03 90 82 E0 00 70 A0 E1 01 40 A0 E1 04 A0 8D E2 05 80 A0 E1 06 30 05 E2 02 00 53 E3 04 00 A0 E1 3A 10 A0 E3 05 60 D9 E7 06 00 00 0A 06 00 55 E3 06 40 87 E7 13 00 00 0A ?? ?? ?? ?? 00 00 50 E3 0C 00 00 1A 11 00 00 EA 0A 20 A0 E3 04 00 A0 E1 0A 10 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 04 00 9D E5 04 00 50 E1 09 00 00 0A 00 30 D0 E5 3A 00 53 E3 06 00 00 1A 06 20 87 E7 01 80 C0 E4 00 40 A0 E1 01 50 85 E2 E2 FF FF EA 00 00 A0 E3 00 00 00 EA 00 00 E0 E3 08 D0 8D E2 F0 87 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ether_ntohost_9f436c77bc2c740a746faee9757a2828 {
	meta:
		aliases = "ether_ntohost"
		size = "196"
		objfiles = "etherss@libc.a"
	strings:
		$pattern = { F0 47 2D E9 AC 30 9F E5 00 90 A0 E1 01 A0 A0 E1 A4 00 9F E5 A4 10 9F E5 03 30 8F E0 42 DF 4D E2 01 10 83 E0 00 00 83 E0 ?? ?? ?? ?? 00 70 50 E2 00 40 E0 03 1C 00 00 0A 0C 00 00 EA B3 FF FF EB 00 50 50 E2 08 10 A0 E1 06 20 A0 E3 0A 00 A0 E1 0A 00 00 0A ?? ?? ?? ?? 00 40 50 E2 07 00 00 1A 09 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 0C 00 00 EA 04 60 8D E2 01 8C 8D E2 02 60 46 E2 02 80 88 E2 01 1C A0 E3 07 20 A0 E1 06 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 08 10 A0 E1 06 00 A0 E1 E6 FF FF 1A 00 40 E0 E3 07 00 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 42 DF 8D E2 F0 87 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getpass_1adadb12a9534c71a533c9ea1b411643 {
	meta:
		aliases = "getpass"
		size = "476"
		objfiles = "getpasss@libc.a"
	strings:
		$pattern = { F0 47 2D E9 B8 71 9F E5 00 90 A0 E1 B4 11 9F E5 B4 01 9F E5 07 70 8F E0 78 D0 4D E2 01 10 87 E0 00 00 87 E0 ?? ?? ?? ?? 00 60 50 E2 06 50 A0 11 05 00 00 1A 94 31 9F E5 03 20 97 E7 90 31 9F E5 00 60 92 E5 03 30 97 E7 00 50 93 E5 06 00 A0 E1 ?? ?? ?? ?? 0D 10 A0 E1 ?? ?? ?? ?? 00 80 50 E2 00 A0 A0 13 1D 00 00 1A 3C E0 8D E2 0D C0 A0 E1 0F 00 BC E8 0F 00 AE E8 0F 00 BC E8 0F 00 AE E8 0F 00 BC E8 0F 00 AE E8 07 00 9C E8 0C 30 9D E5 07 00 8E E8 09 30 C3 E3 06 00 A0 E1 0C 30 8D E5 ?? ?? ?? ?? 0D 20 A0 E1 02 10 A0 E3 ?? ?? ?? ?? 18 31 9F E5 01 A0 70 E2 00 A0 A0 33 03 30 97 E7 00 30 93 E5 03 00 56 E1 }
	condition:
		$pattern
}

rule pthread_create_4cfcf6bae26e58d73d950b40507be353 {
	meta:
		aliases = "pthread_create"
		size = "212"
		objfiles = "pthreads@libpthread.a"
	strings:
		$pattern = { F0 47 2D E9 C0 60 9F E5 C0 C0 9F E5 06 60 8F E0 0C C0 96 E7 00 90 A0 E1 00 00 9C E5 98 D0 4D E2 00 00 50 E3 01 A0 A0 E1 02 70 A0 E1 03 80 A0 E1 03 00 00 AA ?? ?? ?? ?? 00 00 50 E3 0B 00 A0 B3 1F 00 00 BA 7F FD FF EB 00 30 A0 E3 04 40 8D E2 00 50 A0 E1 03 10 A0 E1 02 00 A0 E3 14 20 84 E2 08 30 8D E5 0C A0 8D E5 10 70 8D E5 14 80 8D E5 04 50 8D E5 ?? ?? ?? ?? 50 30 9F E5 03 60 96 E7 04 10 A0 E1 94 20 A0 E3 00 00 96 E5 ?? ?? ?? ?? 01 00 70 E3 03 00 00 1A ?? ?? ?? ?? 00 30 90 E5 04 00 53 E3 F5 FF FF 0A 05 00 A0 E1 12 FE FF EB 34 30 95 E5 34 00 95 E5 00 00 53 E3 30 30 95 05 00 30 89 05 98 D0 8D E2 }
	condition:
		$pattern
}

rule __GI_getprotobynumber_r_61ab7bbe88015ccc2ad19758eff4a19a {
	meta:
		aliases = "getprotobynumber_r, __GI_getprotobynumber_r"
		size = "236"
		objfiles = "getprotos@libc.a"
	strings:
		$pattern = { F0 47 2D E9 C4 50 9F E5 C4 40 9F E5 05 50 8F E0 02 80 A0 E1 BC 20 9F E5 10 D0 4D E2 04 40 85 E0 00 A0 A0 E1 01 60 A0 E1 0D 00 A0 E1 02 10 95 E7 03 70 A0 E1 04 20 A0 E1 9C 30 9F E5 30 90 9D E5 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 8C 30 9F E5 0F E0 A0 E1 03 F0 95 E7 84 30 9F E5 03 00 95 E7 ?? ?? ?? ?? 02 00 00 EA 08 30 96 E5 0A 00 53 E1 06 00 00 0A 06 00 A0 E1 08 10 A0 E1 07 20 A0 E1 09 30 A0 E1 ?? ?? ?? ?? 00 40 50 E2 F5 FF FF 0A 4C 30 9F E5 03 30 95 E7 00 00 53 E3 00 00 00 1A ?? ?? ?? ?? 0D 00 A0 E1 01 10 A0 E3 34 30 9F E5 0F E0 A0 E1 03 F0 95 E7 00 00 99 E5 00 00 50 E3 04 00 A0 01 00 00 A0 13 }
	condition:
		$pattern
}

rule lckpwdf_a1e49f4e8d2f6824ec3c18bf1badf662 {
	meta:
		aliases = "lckpwdf"
		size = "500"
		objfiles = "lckpwdfs@libc.a"
	strings:
		$pattern = { F0 47 2D E9 C4 51 9F E5 C4 71 9F E5 05 50 8F E0 07 80 95 E7 8E DF 4D E2 01 00 78 E3 00 00 E0 13 68 00 00 1A AC 41 9F E5 AC 31 9F E5 04 40 85 E0 03 10 95 E7 04 20 A0 E1 86 0F 8D E2 9C 31 9F E5 0F E0 A0 E1 03 F0 95 E7 94 31 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 95 E7 88 01 9F E5 01 10 A0 E3 00 00 85 E0 ?? ?? ?? ?? 01 00 70 E3 07 00 85 E7 4E 00 00 0A 01 10 A0 E3 00 20 A0 E3 ?? ?? ?? ?? 01 00 70 E3 46 00 00 0A 01 20 80 E3 02 10 A0 E3 07 00 95 E7 ?? ?? ?? ?? 00 00 50 E3 40 00 00 BA 00 10 A0 E3 8C 20 A0 E3 0D 00 A0 E1 ?? ?? ?? ?? 34 31 9F E5 04 00 8D E2 03 30 85 E0 8C A0 8D E2 00 30 8D E5 00 60 A0 E3 }
	condition:
		$pattern
}

rule svc_run_8a3a20ffd1f47b3f9fa287abf61f7838 {
	meta:
		aliases = "svc_run"
		size = "240"
		objfiles = "svc_runs@libc.a"
	strings:
		$pattern = { F0 47 2D E9 DC A0 9F E5 00 90 A0 E3 0A A0 8F E0 ?? ?? ?? ?? 00 40 90 E5 00 80 A0 E1 00 00 54 E3 03 00 00 1A ?? ?? ?? ?? 00 30 90 E5 00 00 53 E3 F0 87 BD 08 84 01 A0 E1 ?? ?? ?? ?? 09 60 A0 E1 00 50 A0 E1 09 00 00 EA ?? ?? ?? ?? 00 30 90 E5 00 20 A0 E3 04 30 93 E7 04 30 85 E7 00 30 90 E5 B6 20 C7 E1 04 30 83 E0 B4 30 D3 E1 B4 30 C7 E1 00 10 98 E5 86 41 A0 E1 01 00 56 E1 04 70 85 E0 01 60 86 E2 EF FF FF BA 05 00 A0 E1 00 20 E0 E3 ?? ?? ?? ?? 01 00 70 E3 02 00 00 0A 00 00 50 E3 0D 00 00 0A 09 00 00 EA 05 00 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? 00 30 90 E5 04 00 53 E3 D3 FF FF 0A 24 00 9F E5 00 00 8A E0 }
	condition:
		$pattern
}

rule getpwent_r_5b93c9216302da9bec7e290df0865933 {
	meta:
		aliases = "getspent_r, getgrent_r, __GI_getspent_r, __GI_getgrent_r, __GI_getpwent_r, getpwent_r"
		size = "276"
		objfiles = "getpwent_rs@libc.a, getgrent_rs@libc.a, getspent_rs@libc.a"
	strings:
		$pattern = { F0 47 2D E9 E0 50 9F E5 E0 40 9F E5 05 50 8F E0 02 90 A0 E1 D8 20 9F E5 18 D0 4D E2 04 40 85 E0 03 60 A0 E1 00 80 A0 E1 C8 30 9F E5 08 00 8D E2 01 A0 A0 E1 C0 70 9F E5 02 10 95 E7 04 20 A0 E1 0F E0 A0 E1 03 F0 95 E7 B0 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 95 E7 07 30 95 E7 00 00 53 E3 00 30 A0 E3 00 30 86 E5 0C 00 00 1A 90 00 9F E5 90 10 9F E5 00 00 85 E0 01 10 85 E0 ?? ?? ?? ?? 00 00 50 E3 01 30 A0 13 07 00 85 E7 34 30 80 15 02 00 00 1A ?? ?? ?? ?? 00 40 90 E5 0A 00 00 EA 54 30 9F E5 60 00 9F E5 03 C0 95 E7 00 00 85 E0 0A 20 A0 E1 09 30 A0 E1 08 10 A0 E1 00 C0 8D E5 ?? ?? ?? ?? 00 40 50 E2 }
	condition:
		$pattern
}

rule __GI_gethostent_r_4f80c51125f99b4300b6b07c257fcf61 {
	meta:
		aliases = "gethostent_r, __GI_gethostent_r"
		size = "268"
		objfiles = "gethostents@libc.a"
	strings:
		$pattern = { F0 47 2D E9 E0 50 9F E5 E0 40 9F E5 05 50 8F E0 02 90 A0 E1 D8 20 9F E5 28 D0 4D E2 04 40 85 E0 00 80 A0 E1 01 A0 A0 E1 18 00 8D E2 02 10 95 E7 C0 60 9F E5 04 20 A0 E1 03 70 A0 E1 B8 30 9F E5 0F E0 A0 E1 03 F0 95 E7 B0 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 95 E7 06 30 95 E7 00 00 53 E3 05 00 00 1A ?? ?? ?? ?? 00 00 50 E3 06 00 85 E7 02 80 A0 03 00 00 87 05 13 00 00 0A 48 30 9D E5 70 60 9F E5 00 80 8D E5 10 30 8D E5 04 A0 8D E5 08 90 8D E5 0C 70 8D E5 01 30 A0 E3 06 00 95 E7 00 10 A0 E3 02 20 A0 E3 ?? ?? ?? ?? 50 30 9F E5 00 80 A0 E1 03 40 95 E7 00 00 54 E3 02 00 00 1A 06 00 95 E7 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule get_eit_entry_34b0bfa5efe3ea3157164541cce5e339 {
	meta:
		aliases = "get_eit_entry"
		size = "536"
		objfiles = "unwind_arm@libgcc.a"
	strings:
		$pattern = { F0 47 2D E9 F0 51 9F E5 F0 31 9F E5 05 50 8F E0 03 30 95 E7 08 D0 4D E2 00 00 53 E3 00 60 A0 E1 02 40 41 E2 09 00 00 0A 04 10 8D E2 04 00 A0 E1 33 FF 2F E1 00 00 50 E3 09 10 A0 03 10 00 86 05 0A 00 00 1A 01 00 A0 E1 08 D0 8D E2 F0 87 BD E8 AC 21 9F E5 AC 11 9F E5 02 30 95 E7 01 20 95 E7 03 30 62 E0 C3 31 A0 E1 04 30 8D E5 02 00 A0 E1 04 30 9D E5 00 00 53 E3 01 80 43 12 08 90 A0 11 00 A0 A0 13 06 00 00 1A 00 30 A0 E3 09 10 A0 E3 10 30 86 E5 EA FF FF EA 04 00 51 E1 1B 00 00 2A 01 A0 8E E2 0A 30 88 E0 A3 3F 83 E0 C3 E0 A0 E1 8E C1 A0 E1 0C 30 90 E7 0C 70 80 E0 01 01 13 E3 02 21 83 13 02 21 C3 03 }
	condition:
		$pattern
}

rule pmap_rmtcall_783ebfdf06681bf0ad7a156835fc822d {
	meta:
		aliases = "pmap_rmtcall"
		size = "280"
		objfiles = "pmap_rmts@libc.a"
	strings:
		$pattern = { F0 47 2D E9 F8 60 9F E5 F8 40 9F E5 06 60 8F E0 40 D0 4D E2 04 C0 86 E0 04 50 9C E5 40 E0 8D E2 00 C0 E0 E3 03 A0 A0 E1 6F 3C A0 E3 04 C0 2E E5 01 70 A0 E1 B2 30 C0 E1 02 80 A0 E1 04 30 96 E7 C4 10 9F E5 02 20 A0 E3 00 50 8D E5 00 90 A0 E1 04 E0 8D E5 ?? ?? ?? ?? 00 50 50 E2 10 40 A0 03 22 00 00 0A 64 30 9D E5 14 70 8D E5 24 30 8D E5 60 30 9D E5 18 80 8D E5 28 30 8D E5 78 30 9D E5 1C A0 8D E5 2C 30 8D E5 6C 30 9D E5 7C 20 9F E5 34 30 8D E5 68 30 9D E5 08 C0 8D E2 38 30 8D E5 6C 30 9F E5 04 40 95 E5 03 30 86 E0 00 30 8D E5 2C 30 8D E2 04 30 8D E5 70 10 8D E2 03 00 91 E8 14 30 8D E2 03 00 8C E8 }
	condition:
		$pattern
}

rule qsort_3a926748cec5461b5938be74e9974b11 {
	meta:
		aliases = "__GI_qsort, qsort"
		size = "204"
		objfiles = "qsorts@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 00 52 E3 01 00 51 13 0C D0 4D E2 01 50 A0 E1 02 A0 A0 E1 04 00 8D E5 03 B0 A0 E1 27 00 00 9A 00 40 A0 E3 03 70 A0 E3 01 60 41 E2 94 07 03 E0 06 00 A0 E1 07 10 A0 E1 01 40 83 E2 ?? ?? ?? ?? 00 00 54 E1 F8 FF FF 3A 9A 04 07 E0 95 0A 09 E0 07 80 A0 E1 08 60 A0 E1 04 30 9D E5 06 60 67 E0 06 40 83 E0 07 50 84 E0 04 00 A0 E1 05 10 A0 E1 3B FF 2F E1 00 00 50 E3 08 00 00 DA 0A 10 A0 E1 00 20 D4 E5 00 30 D5 E5 01 10 51 E2 01 30 C4 E4 01 20 C5 E4 F9 FF FF 1A 07 00 56 E1 ED FF FF 2A 0A 80 88 E0 09 00 58 E1 E9 FF FF 3A 07 00 6A E0 03 10 A0 E3 ?? ?? ?? ?? 00 70 50 E2 E3 FF FF 1A 0C D0 8D E2 }
	condition:
		$pattern
}

rule __ieee754_jn_3fcf4b48f69483fddc034e9ae4813edb {
	meta:
		aliases = "__ieee754_jn"
		size = "1916"
		objfiles = "e_jns@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 00 10 62 E2 02 10 81 E1 02 51 C3 E3 30 C7 9F E5 A1 1F 85 E1 4C D0 4D E2 0C 00 51 E1 02 60 A0 E1 03 70 A0 E1 02 E0 A0 E1 14 30 8D E5 03 40 A0 E1 04 00 8D E5 05 00 00 9A 02 00 A0 E1 03 10 A0 E1 ?? ?? ?? ?? 00 50 A0 E1 01 60 A0 E1 B8 01 00 EA 04 C0 9D E5 00 00 5C E3 08 00 00 AA 14 10 9D E5 02 41 87 E2 00 C0 6C E2 02 11 81 E2 02 60 A0 E1 04 70 A0 E1 04 C0 8D E5 14 10 8D E5 05 00 00 EA 04 00 00 1A 02 00 A0 E1 03 10 A0 E1 4C D0 8D E2 F0 4F BD E8 ?? ?? ?? ?? 04 20 9D E5 01 00 52 E3 04 00 00 1A 06 00 A0 E1 07 10 A0 E1 4C D0 8D E2 F0 4F BD E8 ?? ?? ?? ?? 0E E0 95 E1 84 26 9F E5 00 30 A0 13 }
	condition:
		$pattern
}

rule __ieee754_yn_5a2446c8e9d9ad1ed6f4f9fed71ecc13 {
	meta:
		aliases = "__ieee754_yn"
		size = "768"
		objfiles = "e_jns@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 00 10 62 E2 02 10 81 E1 02 61 C3 E3 D4 C2 9F E5 A1 1F 86 E1 0C 00 51 E1 0C D0 4D E2 02 70 A0 E1 03 80 A0 E1 03 50 A0 E1 02 E0 A0 E1 03 40 A0 E1 00 A0 A0 E1 03 00 00 9A 02 00 A0 E1 03 10 A0 E1 ?? ?? ?? ?? 06 00 00 EA 0E E0 96 E1 07 00 00 1A 94 12 9F E5 00 00 A0 E3 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? ?? 00 50 A0 E1 01 60 A0 E1 99 00 00 EA 00 00 53 E3 00 00 A0 B3 00 10 A0 B3 00 20 A0 B1 01 30 A0 B1 F5 FF FF BA 00 00 50 E3 00 A0 60 B2 01 30 0A B2 83 30 A0 B1 01 90 63 B2 06 00 00 BA 01 90 A0 13 04 00 00 1A 02 00 A0 E1 03 10 A0 E1 0C D0 8D E2 F0 4F BD E8 ?? ?? ?? ?? 01 00 5A E3 0A 00 00 1A }
	condition:
		$pattern
}

rule __GI_modf_efd12ee66ef3c058ae9649a490ed61b6 {
	meta:
		aliases = "modf, __GI_modf"
		size = "384"
		objfiles = "s_modfs@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 00 30 A0 E1 2C D0 4D E2 01 40 A0 E1 20 30 8D E5 24 40 8D E5 24 90 9D E5 00 40 A0 E3 49 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF CF 43 E2 03 C0 4C E2 00 30 A0 E3 03 70 A0 E1 04 80 A0 E1 13 00 5C E3 00 50 A0 E1 01 60 A0 E1 04 20 8D E5 18 30 8D E5 1C 40 8D E5 10 30 8D E5 14 40 8D E5 08 70 8D E5 0C 80 8D E5 03 A0 A0 E1 04 B0 A0 E1 20 E0 9D E5 1A 00 00 CA 00 00 5C E3 02 41 09 B2 00 30 A0 B3 18 00 82 B8 37 00 00 BA E8 30 9F E5 53 2C A0 E1 09 30 02 E0 0E C0 93 E1 07 00 00 1A 02 31 01 E2 04 40 9D E5 1C 30 8D E5 18 C0 8D E5 60 00 84 E8 18 50 8D E2 60 00 95 E8 2A 00 00 EA 02 20 C9 E1 00 70 A0 E3 }
	condition:
		$pattern
}

rule _time_t2tm_5a6ede12dedf37aa312e686d384d7217 {
	meta:
		aliases = "_time_t2tm"
		size = "500"
		objfiles = "_time_t2tms@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 30 A0 E3 CC 71 9F E5 CC B1 9F E5 1C 30 82 E5 C8 31 9F E5 07 70 8F E0 0C D0 4D E2 02 A0 A0 E1 00 50 90 E5 0B B0 81 E0 03 80 87 E0 02 60 A0 E1 B0 40 D8 E1 07 00 54 E3 04 90 A0 E1 0A 00 00 1A 05 00 A0 E1 04 10 A0 E1 ?? ?? ?? ?? 0B 00 81 E2 04 10 A0 E1 ?? ?? ?? ?? B2 30 D8 E1 04 10 8D E5 03 31 A0 E1 0B 50 85 E0 01 40 83 E2 05 00 A0 E1 04 10 A0 E1 ?? ?? ?? ?? 94 00 03 E0 03 50 55 E0 04 50 85 40 01 00 40 42 07 00 59 E3 05 00 00 1A 01 30 44 E2 03 00 55 E1 10 30 96 05 01 50 45 02 01 30 83 02 10 30 86 05 B2 30 F8 E1 3C 00 54 E3 00 50 86 D5 00 00 86 C5 04 C0 86 E2 00 50 A0 D1 00 00 53 E3 }
	condition:
		$pattern
}

rule realpath_eaa6cf55ee1c9f437ce807d696f18dd4 {
	meta:
		aliases = "realpath"
		size = "688"
		objfiles = "realpaths@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 50 50 E2 01 DA 4D E2 14 D0 4D E2 01 70 A0 E1 03 00 00 1A ?? ?? ?? ?? 05 70 A0 E1 16 30 A0 E3 5E 00 00 EA 00 40 D5 E5 00 00 54 E3 03 00 00 1A ?? ?? ?? ?? 04 70 A0 E1 02 30 A0 E3 57 00 00 EA ?? ?? ?? ?? 58 32 9F E5 00 20 A0 E1 03 00 50 E1 41 00 00 8A 01 0A 8D E2 0F 00 80 E2 00 00 62 E0 05 10 A0 E1 00 40 A0 E1 ?? ?? ?? ?? 00 30 D4 E5 FF BE 87 E2 2F 00 53 E3 07 50 A0 01 0E B0 8B E2 01 30 C5 04 01 40 84 02 0C 00 00 0A 07 00 A0 E1 10 12 9F E5 ?? ?? ?? ?? 00 00 50 E3 7B 00 00 0A 07 00 A0 E1 ?? ?? ?? ?? 00 50 87 E0 01 30 55 E5 2F 00 53 E3 2F 30 A0 13 00 30 C7 17 01 50 85 12 00 20 A0 E3 }
	condition:
		$pattern
}

rule _stdlib_wcsto_ll_6f99147faec4943b503929178f29faaa {
	meta:
		aliases = "_stdlib_wcsto_ll"
		size = "564"
		objfiles = "_stdlib_wcsto_lls@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 50 A0 E1 0C D0 4D E2 02 A0 A0 E1 00 70 A0 E1 04 10 8D E5 00 30 8D E5 00 00 00 EA 04 70 87 E2 00 00 97 E5 ?? ?? ?? ?? 00 00 50 E3 FA FF FF 1A 00 20 97 E5 2B 00 52 E3 04 00 00 0A 2D 00 52 E3 00 B0 A0 11 01 B0 A0 03 01 00 00 0A 01 00 00 EA 00 B0 A0 E1 04 70 87 E2 10 20 DA E3 05 00 A0 11 0E 00 00 1A 00 30 97 E5 0A A0 8A E2 30 00 53 E3 05 00 A0 11 07 00 00 1A 04 30 B7 E5 02 A0 4A E2 20 30 83 E3 78 00 53 E3 07 00 A0 01 07 00 A0 11 8A A0 A0 01 04 70 87 02 10 00 5A E3 10 A0 A0 A3 02 30 4A E2 22 00 53 E3 00 50 A0 93 00 60 A0 93 0A 80 A0 91 C8 9F A0 91 01 00 00 9A 37 00 00 EA 07 00 A0 E1 }
	condition:
		$pattern
}

rule getsubopt_9a18d7b1b3979fb0f5fcb0ab1f112e51 {
	meta:
		aliases = "getsubopt"
		size = "216"
		objfiles = "getsubopts@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 60 90 E5 0C D0 4D E2 04 10 8D E5 00 30 D6 E5 00 90 A0 E1 00 00 53 E3 02 B0 A0 E1 28 00 00 0A 2C 10 A0 E3 06 00 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 3D 10 A0 E3 06 00 A0 E1 04 20 66 E0 ?? ?? ?? ?? 00 00 50 E3 00 70 A0 11 04 70 A0 01 00 80 A0 E3 07 A0 66 E0 0F 00 00 EA ?? ?? ?? ?? 00 00 50 E3 0B 00 00 1A 0A 10 D5 E7 00 00 51 E3 08 00 00 1A 04 00 57 E1 01 10 87 12 00 10 8B E5 00 30 D4 E5 00 00 53 E3 00 30 A0 13 01 30 C4 14 00 40 89 E5 0C 00 00 EA 01 80 88 E2 04 30 9D E5 06 00 A0 E1 08 51 93 E7 0A 20 A0 E1 00 10 55 E2 E9 FF FF 1A 00 60 8B E5 00 30 D4 E5 00 00 53 E3 01 50 C4 14 00 40 89 E5 }
	condition:
		$pattern
}

rule _stdlib_wcsto_l_3b0e5bc915ab10286cb3ba9c2780f573 {
	meta:
		aliases = "_stdlib_wcsto_l"
		size = "408"
		objfiles = "_stdlib_wcsto_ls@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 60 A0 E1 04 D0 4D E2 01 90 A0 E1 02 50 A0 E1 03 B0 A0 E1 00 40 A0 E1 00 00 00 EA 04 40 84 E2 00 00 94 E5 ?? ?? ?? ?? 00 00 50 E3 FA FF FF 1A 00 20 94 E5 2B 00 52 E3 04 00 00 0A 2D 00 52 E3 00 70 A0 11 01 70 A0 03 01 00 00 0A 01 00 00 EA 00 70 A0 E1 04 40 84 E2 10 30 D5 E3 0D 00 00 1A 00 30 94 E5 0A 50 85 E2 30 00 53 E3 07 00 00 1A 04 30 B4 E5 02 50 45 E2 20 30 83 E3 78 00 53 E3 04 60 A0 01 04 60 A0 11 85 50 A0 01 04 40 84 02 10 00 55 E3 10 50 A0 A3 02 30 45 E2 22 00 53 E3 00 10 A0 83 29 00 00 8A 00 00 E0 E3 05 10 A0 E1 ?? ?? ?? ?? 00 00 E0 E3 01 30 A0 E1 05 10 A0 E1 FF A0 03 E2 }
	condition:
		$pattern
}

rule __GI_clnttcp_create_87addeeccedce431dc14d2d782c1f381 {
	meta:
		aliases = "clnttcp_create, __GI_clnttcp_create"
		size = "628"
		objfiles = "clnt_tcps@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 60 A0 E1 3C D0 4D E2 0C 00 A0 E3 01 90 A0 E1 02 B0 A0 E1 03 80 A0 E1 ?? ?? ?? ?? 00 70 A0 E1 64 00 A0 E3 ?? ?? ?? ?? 28 A2 9F E5 00 00 50 E3 00 00 57 13 00 50 A0 E1 0A A0 8F E0 0B 00 00 1A ?? ?? ?? ?? 10 32 9F E5 00 40 A0 E1 03 30 9A E7 08 02 9F E5 00 10 93 E5 00 00 8A E0 ?? ?? ?? ?? 0C 30 A0 E3 08 30 84 E5 00 30 84 E5 71 00 00 EA B2 30 D6 E1 00 00 53 E3 11 00 00 1A 06 00 A0 E1 09 10 A0 E1 0B 20 A0 E1 06 30 83 E2 ?? ?? ?? ?? 00 40 50 E2 05 00 00 1A 05 00 A0 E1 ?? ?? ?? ?? 07 00 A0 E1 ?? ?? ?? ?? 04 70 A0 E1 66 00 00 EA 24 34 A0 E1 FF 30 03 E2 FF 20 04 E2 02 34 83 E1 B2 30 C6 E1 }
	condition:
		$pattern
}

rule __GI_clntunix_create_255fda666c270180183deddf262680f3 {
	meta:
		aliases = "clntunix_create, __GI_clntunix_create"
		size = "560"
		objfiles = "clnt_unixs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 60 A0 E1 3C D0 4D E2 C4 00 A0 E3 02 B0 A0 E1 01 90 A0 E1 03 80 A0 E1 ?? ?? ?? ?? 00 50 A0 E1 0C 00 A0 E3 ?? ?? ?? ?? E4 A1 9F E5 00 00 55 E3 00 00 50 13 00 70 A0 E1 00 20 A0 13 01 20 A0 03 0A A0 8F E0 0B 00 00 1A ?? ?? ?? ?? C4 31 9F E5 00 40 A0 E1 03 30 9A E7 BC 01 9F E5 00 10 93 E5 00 00 8A E0 ?? ?? ?? ?? 0C 30 A0 E3 08 30 84 E5 00 30 84 E5 5E 00 00 EA 00 30 98 E5 00 00 53 E3 04 20 85 A5 1C 00 00 AA 01 00 A0 E3 00 10 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 00 00 88 E5 02 00 86 E2 ?? ?? ?? ?? 00 00 54 E3 00 20 A0 E1 07 00 00 BA 04 00 A0 E1 03 20 82 E2 06 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 }
	condition:
		$pattern
}

rule __open_nameservers_fb68bcb9ca8af596d34d30e8f96ebdb0 {
	meta:
		aliases = "__open_nameservers"
		size = "848"
		objfiles = "opennameserverss@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 63 9F E5 00 33 9F E5 06 60 8F E0 03 40 96 E7 F8 32 9F E5 C4 D0 4D E2 03 10 96 E7 04 20 A0 E1 B0 00 8D E2 E8 32 9F E5 0F E0 A0 E1 03 F0 96 E7 E0 32 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 96 E7 D4 32 9F E5 03 30 96 E7 00 00 53 E3 A6 00 00 CA C8 32 9F E5 C8 02 9F E5 03 40 86 E0 00 00 86 E0 04 10 A0 E1 ?? ?? ?? ?? 00 B0 50 E2 82 00 00 1A B0 02 9F E5 04 10 A0 E1 00 00 86 E0 ?? ?? ?? ?? 00 B0 50 E2 7C 00 00 1A 94 00 00 EA 01 00 80 E2 00 20 D0 E5 00 00 52 E3 82 10 A0 E1 04 00 00 0A 14 C0 9D E5 0C 30 96 E7 B3 30 91 E1 20 00 13 E3 F5 FF FF 1A 0A 00 52 E3 00 00 52 13 00 30 A0 13 01 30 A0 03 }
	condition:
		$pattern
}

rule get_myaddress_e629df25bbabf5049a247f955d3f3e3b {
	meta:
		aliases = "get_myaddress"
		size = "332"
		objfiles = "get_myaddresss@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 80 A0 E1 01 DA 4D E2 02 00 A0 E3 2C D0 4D E2 00 10 A0 E1 00 20 A0 E3 ?? ?? ?? ?? 0C 91 9F E5 00 A0 50 E2 09 90 8F E0 04 01 9F B5 0E 00 00 BA 01 3A A0 E3 28 C0 8D E2 03 E0 8D E0 28 C0 4C E2 01 2A 8D E2 EC 10 9F E5 20 20 82 E2 20 30 8E E5 24 C0 8E E5 ?? ?? ?? ?? 00 00 50 E3 00 B0 A0 A3 01 7A 8D A2 04 00 00 AA CC 00 9F E5 00 00 89 E0 ?? ?? ?? ?? 01 00 A0 E3 ?? ?? ?? ?? 01 3A 8D E2 24 50 93 E5 20 60 93 E5 1E 00 00 EA 05 40 A0 E1 07 C0 A0 E1 0F 00 B4 E8 0F 00 AC E8 0F 00 94 E8 0F 00 8C E8 0A 00 A0 E1 90 10 9F E5 07 20 A0 E1 ?? ?? ?? ?? 00 00 50 E3 84 00 9F B5 EA FF FF BA 01 EA 8D E2 }
	condition:
		$pattern
}

rule bsearch_50a051fecb3289e07d68f6a74c9beac1 {
	meta:
		aliases = "bsearch"
		size = "108"
		objfiles = "bsearchs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 90 53 E2 04 D0 4D E2 00 A0 A0 E1 01 80 A0 E1 02 50 A0 E1 28 B0 9D E5 00 70 A0 13 09 00 00 1A 0D 00 00 EA 99 84 26 E0 06 10 A0 E1 3B FF 2F E1 00 00 50 E3 01 70 84 C2 02 00 00 CA 06 00 A0 01 06 00 00 0A 04 50 A0 E1 05 30 67 E0 05 00 57 E1 A3 40 87 E0 0A 00 A0 E1 F1 FF FF 3A 00 00 A0 E3 04 D0 8D E2 F0 8F BD E8 }
	condition:
		$pattern
}

rule __decode_dotted_d20a7fa9e4fffb4fd793143938a21ec6 {
	meta:
		aliases = "__decode_dotted"
		size = "204"
		objfiles = "decodeds@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 A0 50 E2 0C D0 4D E2 00 80 A0 13 02 90 A0 E1 04 30 8D E5 01 B0 A0 13 08 00 A0 11 1F 00 00 1A 25 00 00 EA 00 00 5B E3 C0 30 04 E2 01 80 88 12 C0 00 53 E3 01 50 81 E2 07 00 00 1A 05 20 DA E7 00 00 5B E3 3F 30 04 E2 01 80 88 12 03 14 82 E1 00 70 A0 E1 00 B0 A0 E3 0F 00 00 EA 00 60 84 E0 04 30 9D E5 01 70 86 E2 03 00 57 E1 12 00 00 2A 05 10 8A E0 00 00 89 E0 04 20 A0 E1 ?? ?? ?? ?? 05 10 84 E0 01 30 DA E7 00 00 5B E3 04 80 88 10 00 00 53 E3 2E 30 A0 13 06 30 C9 E7 07 00 A0 E1 01 40 DA E7 00 00 54 E3 DD FF FF 1A 00 00 5B E3 01 80 88 12 08 00 A0 E1 00 00 00 EA 00 00 E0 E3 0C D0 8D E2 }
	condition:
		$pattern
}

rule __ieee754_atan2_24b228c9e5769f3b0131da69ecdfc4d2 {
	meta:
		aliases = "__ieee754_atan2"
		size = "652"
		objfiles = "e_atan2s@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 00 C0 62 E2 48 62 9F E5 02 C0 8C E1 02 91 C3 E3 AC CF 89 E1 0C D0 4D E2 06 00 5C E1 0C 00 8D E8 02 80 A0 E1 03 B0 A0 E1 00 40 A0 E1 01 50 A0 E1 00 60 A0 E1 01 70 A0 E1 00 E0 A0 E1 07 00 00 8A 00 C0 60 E2 00 C0 8C E1 02 71 C1 E3 00 62 9F E5 AC CF 87 E1 06 00 5C E1 01 A0 A0 E1 01 00 00 9A ?? ?? ?? ?? 74 00 00 EA 03 31 83 E2 01 36 83 E2 02 30 93 E1 02 00 00 1A 0C D0 8D E2 F0 4F BD E8 ?? ?? ?? ?? 4B 3F A0 E1 02 30 03 E2 0E E0 97 E1 A1 6F 83 E1 06 00 00 1A 03 00 56 E3 06 F1 8F 90 03 00 00 EA 66 00 00 EA 65 00 00 EA 21 00 00 EA 23 00 00 EA 08 80 99 E1 2D 00 00 0A 90 31 9F E5 03 00 59 E1 }
	condition:
		$pattern
}

rule _stdio_fopen_7714ad67cb0c7016f946cb0db1cd5925 {
	meta:
		aliases = "_stdio_fopen"
		size = "732"
		objfiles = "_fopens@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 C0 D1 E5 98 B2 9F E5 72 00 5C E3 0B B0 8F E0 24 D0 4D E2 00 60 A0 E1 02 90 A0 E1 03 50 A0 E1 10 00 00 0A 77 00 5C E3 78 42 9F 05 0E 00 00 0A 61 00 5C E3 70 42 9F 05 0B 00 00 0A ?? ?? ?? ?? 16 30 A0 E3 00 00 59 E3 00 30 80 E5 90 00 00 0A B0 30 D9 E1 02 0A 13 E3 8D 00 00 0A 09 00 A0 E1 ?? ?? ?? ?? 8A 00 00 EA 00 40 A0 E3 01 30 D1 E5 62 00 53 E3 01 30 A0 11 01 30 81 02 01 30 D3 E5 2B 00 53 E3 01 30 84 03 01 40 83 02 00 00 59 E3 09 00 00 1A 50 00 A0 E3 ?? ?? ?? ?? 00 90 50 E2 7C 00 00 0A 00 30 A0 E3 08 30 89 E5 02 3A A0 E3 B0 30 C9 E1 38 00 89 E2 ?? ?? ?? ?? 00 00 55 E3 13 00 00 BA }
	condition:
		$pattern
}

rule __ieee754_log2_880d08329c809fe2b723ebf0cb79cd92 {
	meta:
		aliases = "__ieee754_log2"
		size = "1032"
		objfiles = "e_log2s@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 01 06 51 E3 00 50 A0 E1 14 D0 4D E2 01 60 A0 E1 01 40 A0 E1 01 C0 A0 E1 00 00 A0 A3 1B 00 00 AA 02 31 C1 E3 05 30 93 E1 07 00 00 1A 05 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 01 30 A0 E1 58 13 9F E5 00 20 A0 E1 00 00 A0 E3 06 00 00 EA 00 00 51 E3 06 00 00 AA 05 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? C4 00 00 EA 00 20 A0 E3 24 33 9F E5 ?? ?? ?? ?? 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 01 C0 A0 E1 35 00 E0 E3 0C 33 9F E5 03 00 5C E1 05 00 A0 C1 06 10 A0 C1 05 20 A0 C1 06 30 A0 C1 B4 00 00 CA FF 14 CC E3 F0 22 9F E5 0F 16 C1 E3 FF 0F 40 E2 02 20 81 E0 03 00 40 E2 }
	condition:
		$pattern
}

rule __ieee754_log10_d8ccae70c103718039890155b54d330d {
	meta:
		aliases = "__ieee754_log10"
		size = "384"
		objfiles = "e_log10s@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 01 06 51 E3 00 A0 A0 E1 04 D0 4D E2 01 B0 A0 E1 01 40 A0 E1 01 60 A0 E1 00 00 A0 A3 15 00 00 AA 02 31 C1 E3 0A 30 93 E1 00 00 A0 03 24 11 9F 05 04 00 00 0A 00 00 5B E3 06 00 00 AA 0A 20 A0 E1 0B 30 A0 E1 ?? ?? ?? ?? 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? ?? 3D 00 00 EA 00 20 A0 E3 F8 30 9F E5 ?? ?? ?? ?? 00 A0 A0 E1 01 B0 A0 E1 01 40 A0 E1 01 60 A0 E1 35 00 E0 E3 E0 30 9F E5 03 00 56 E1 0A 00 A0 C1 0B 10 A0 C1 0A 20 A0 C1 0B 30 A0 C1 2D 00 00 CA FF 0F 40 E2 03 00 40 E2 46 0A 80 E0 A0 5F A0 E1 00 00 85 E0 ?? ?? ?? ?? FF 5F 65 E2 FF 24 C6 E3 0F 26 C2 E3 03 50 85 E2 05 4A 82 E1 00 80 A0 E1 }
	condition:
		$pattern
}

rule __ieee754_log_39dc35076d1c7d637f60adc637aec71e {
	meta:
		aliases = "__ieee754_log"
		size = "1492"
		objfiles = "e_logs@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 01 06 51 E3 1C D0 4D E2 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 01 70 A0 E1 00 C0 A0 A3 15 00 00 AA 02 31 C1 E3 00 30 93 E1 00 00 A0 03 28 15 9F 05 04 00 00 0A 00 00 56 E3 06 00 00 AA 05 20 A0 E1 06 30 A0 E1 ?? ?? ?? ?? 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? ?? 3E 01 00 EA 00 20 A0 E3 FC 34 9F E5 ?? ?? ?? ?? 35 C0 E0 E3 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 01 70 A0 E1 E4 34 9F E5 03 00 57 E1 05 00 A0 C1 06 10 A0 C1 05 20 A0 C1 06 30 A0 C1 34 00 00 CA FF A4 C7 E3 C8 E4 9F E5 0F A6 CA E3 0E E0 8A E0 C0 34 9F E5 01 E6 0E E2 FF CF 4C E2 03 30 2E E0 03 C0 4C E2 0A 20 83 E1 47 CA 8C E0 02 10 A0 E1 }
	condition:
		$pattern
}

rule __GI_rexec_af_fdf82c231d0361e5fb7902c2fc678b26 {
	meta:
		aliases = "rexec_af, __GI_rexec_af"
		size = "1112"
		objfiles = "rexecs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 18 A0 E1 65 DF 4D E2 20 74 9F E5 21 C4 A0 E1 1C 20 8D E5 10 20 8D E5 14 24 9F E5 05 5D 8D E2 07 70 8F E0 FF CC 0C E2 00 90 A0 E1 18 30 8D E5 14 30 8D E5 02 20 87 E0 21 3C 8C E1 05 00 A0 E1 01 CC 8D E2 20 10 A0 E3 B0 6C DC E1 16 4E 8D E2 ?? ?? ?? ?? 00 30 A0 E3 03 10 A0 E1 20 20 A0 E3 04 00 A0 E1 5F 31 CD E5 01 80 A0 E3 ?? ?? ?? ?? 00 00 99 E5 05 10 A0 E1 04 20 A0 E1 62 3F 8D E2 02 40 A0 E3 64 61 8D E5 68 81 8D E5 60 41 8D E5 ?? ?? ?? ?? 00 50 50 E2 E0 00 00 1A 88 31 9D E5 18 10 93 E5 00 00 51 E3 0D 00 00 0A 84 43 9F E5 84 23 9F E5 04 40 87 E0 04 00 A0 E1 ?? ?? ?? ?? 88 31 9D E5 }
	condition:
		$pattern
}

rule __ieee754_pow_19cc4aa72dc9b538f4daeb62c233d222 {
	meta:
		aliases = "__ieee754_pow"
		size = "4124"
		objfiles = "e_pows@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 01 60 A0 E1 10 1F 9F E5 84 D0 4D E2 3C 10 8D E5 03 40 A0 E1 3C C0 9D E5 40 20 8D E5 44 30 8D E5 02 71 C4 E3 02 30 A0 E1 00 50 A0 E1 0C C0 8F E0 02 00 A0 E1 03 20 97 E1 3C C0 8D E5 06 20 A0 E1 04 80 A0 E1 06 90 A0 E1 05 A0 A0 E1 04 E0 A0 E1 00 10 A0 03 C4 2E 9F 05 B2 00 00 0A C0 CE 9F E5 02 41 C6 E3 0C 00 54 E1 6C 20 8D E5 0F 00 00 CA 00 B0 A0 13 01 B0 A0 03 00 00 55 E3 00 30 A0 03 01 30 0B 12 00 00 53 E3 08 00 00 1A 0C 00 57 E1 06 00 00 CA 00 30 A0 13 01 30 A0 03 00 00 50 E3 00 30 A0 03 01 30 03 12 00 00 53 E3 05 00 00 0A 40 00 8D E2 03 00 90 E8 05 20 A0 E1 06 30 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __mulsc3_94639e122fc1b49543f2d836aaf8bc4c {
	meta:
		aliases = "__mulsc3"
		size = "1500"
		objfiles = "_mulsc3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 70 A0 E1 44 D0 4D E2 00 50 A0 E1 01 00 A0 E1 03 10 A0 E1 02 80 A0 E1 03 90 A0 E1 ?? ?? ?? ?? 68 60 9D E5 00 B0 A0 E1 06 10 A0 E1 08 00 A0 E1 ?? ?? ?? ?? 06 10 A0 E1 00 40 A0 E1 07 00 A0 E1 ?? ?? ?? ?? 09 10 A0 E1 2C 00 8D E5 08 00 A0 E1 ?? ?? ?? ?? 04 10 A0 E1 30 00 8D E5 0B 00 A0 E1 ?? ?? ?? ?? 30 10 9D E5 00 A0 A0 E1 2C 00 9D E5 ?? ?? ?? ?? 0A 10 A0 E1 34 00 8D E5 0A 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 05 00 00 0A 34 20 9D E5 05 00 A0 E1 00 A0 85 E5 04 20 85 E5 44 D0 8D E2 F0 8F BD E8 34 00 9D E5 00 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 F4 FF FF 1A 07 10 A0 E1 07 00 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __getgrouplist_internal_5d31a18abc2e738f8632b0464eeb99dc {
	meta:
		aliases = "__getgrouplist_internal"
		size = "308"
		objfiles = "__getgrouplist_internals@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 70 A0 E3 4B DF 4D E2 00 B0 A0 E1 00 70 82 E5 20 00 A0 E3 02 90 A0 E1 01 A0 A0 E1 ?? ?? ?? ?? F8 40 9F E5 00 00 50 E3 04 40 8F E0 00 80 A0 01 37 00 00 0A 00 A0 80 E5 00 80 A0 E1 E0 10 9F E5 E0 00 9F E5 01 10 84 E0 00 00 84 E0 ?? ?? ?? ?? 00 50 50 E2 2E 00 00 0A CC 30 9F E5 07 60 A0 E1 03 40 84 E0 46 3F 8D E2 10 30 8D E5 18 30 8D E2 14 40 8D E5 0C 30 8D E5 34 70 85 E5 19 00 00 EA 20 31 9D E5 0A 00 53 E1 24 41 9D 15 10 00 00 1A 14 00 00 EA ?? ?? ?? ?? 00 00 50 E3 0C 00 00 1A 07 00 16 E3 06 00 00 1A 06 11 A0 E1 20 10 81 E2 08 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 11 00 00 0A 00 80 A0 E1 }
	condition:
		$pattern
}

rule __GI_xdr_array_118e5bc3ecc3e962232be0a563860a96 {
	meta:
		aliases = "xdr_array, __GI_xdr_array"
		size = "340"
		objfiles = "xdr_arrays@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 90 A0 E1 04 D0 4D E2 02 10 A0 E1 02 40 A0 E1 03 80 A0 E1 00 A0 A0 E1 28 B0 9D E5 00 50 99 E5 ?? ?? ?? ?? 18 61 9F E5 00 00 50 E3 06 60 8F E0 3D 00 00 0A 00 70 94 E5 08 00 57 E1 04 00 00 8A 00 00 E0 E3 0B 10 A0 E1 ?? ?? ?? ?? 00 00 57 E1 02 00 00 9A 00 30 9A E5 02 00 53 E3 32 00 00 1A 00 00 55 E3 19 00 00 1A 00 30 9A E5 01 00 53 E3 02 00 00 0A 02 00 53 E3 14 00 00 1A 2C 00 00 EA 00 00 57 E3 2A 00 00 0A 97 0B 04 E0 04 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 00 50 A0 E1 00 00 89 E5 07 00 00 1A 9C 30 9F E5 9C 00 9F E5 03 30 96 E7 00 00 86 E0 00 10 93 E5 ?? ?? ?? ?? 05 40 A0 E1 1C 00 00 EA }
	condition:
		$pattern
}

rule openpty_4deec194b273c1472f74cc9c97a888d6 {
	meta:
		aliases = "__GI_openpty, openpty"
		size = "252"
		objfiles = "openptys@libutil.a"
	strings:
		$pattern = { F0 4F 2D E9 01 DA 4D E2 04 D0 4D E2 00 B0 A0 E1 02 00 A0 E3 01 90 A0 E1 02 60 A0 E1 03 80 A0 E1 ?? ?? ?? ?? 01 00 70 E3 00 50 A0 E1 00 00 A0 01 2C 00 00 0A ?? ?? ?? ?? 00 00 50 E3 26 00 00 1A 05 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 22 00 00 1A 05 00 A0 E1 0D 10 A0 E1 01 2A A0 E3 ?? ?? ?? ?? 00 A0 50 E2 0D 70 A0 E1 1B 00 00 1A 0D 00 A0 E1 7C 10 9F E5 ?? ?? ?? ?? 01 00 70 E3 00 40 A0 E1 15 00 00 0A 00 00 58 E3 02 00 00 0A 08 20 A0 E1 02 10 A0 E3 ?? ?? ?? ?? 01 2A 8D E2 28 20 92 E5 00 00 52 E3 02 00 00 0A 04 00 A0 E1 44 10 9F E5 ?? ?? ?? ?? 00 00 56 E3 00 50 8B E5 06 00 A0 01 00 40 89 E5 07 00 00 0A }
	condition:
		$pattern
}

rule __ieee754_y1_514a7c71cafb32de03bc5e0ef4df39ee {
	meta:
		aliases = "__ieee754_y1"
		size = "1256"
		objfiles = "e_j1s@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 02 31 C1 E3 1C D0 4D E2 0C 30 8D E5 0C C0 9D E5 54 34 9F E5 00 A0 A0 E1 03 00 5C E1 01 B0 A0 E1 00 40 A0 E1 01 50 A0 E1 0C 00 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 0A 00 A0 E1 0B 10 A0 E1 ?? ?? ?? ?? 01 30 A0 E1 18 14 9F E5 00 20 A0 E1 00 00 A0 E3 06 00 00 EA 0C 30 9D E5 00 30 93 E1 05 00 00 1A 00 14 9F E5 00 00 A0 E3 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? ?? F7 00 00 EA 00 00 51 E3 00 00 A0 B3 00 10 A0 B3 00 20 A0 B1 01 30 A0 B1 F7 FF FF BA 0C C0 9D E5 07 01 7C E3 6A 00 00 DA ?? ?? ?? ?? 00 60 A0 E1 01 70 A0 E1 0A 00 A0 E1 0B 10 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 }
	condition:
		$pattern
}

rule __ieee754_y0_a3a957344fec22494b6e69e234f93dd1 {
	meta:
		aliases = "__ieee754_y0"
		size = "1232"
		objfiles = "e_j0s@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 02 31 C1 E3 1C D0 4D E2 14 30 8D E5 14 C0 9D E5 3C 34 9F E5 00 80 A0 E1 03 00 5C E1 01 90 A0 E1 00 40 A0 E1 01 50 A0 E1 0C 00 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 08 00 A0 E1 09 10 A0 E1 ?? ?? ?? ?? 01 30 A0 E1 00 14 9F E5 00 20 A0 E1 00 00 A0 E3 06 00 00 EA 14 30 9D E5 00 30 93 E1 05 00 00 1A E8 13 9F E5 00 00 A0 E3 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? ?? F1 00 00 EA 00 00 51 E3 00 00 A0 B3 00 10 A0 B3 00 20 A0 B1 01 30 A0 B1 F7 FF FF BA 14 C0 9D E5 07 01 7C E3 68 00 00 DA ?? ?? ?? ?? 03 00 8D E8 08 00 A0 E1 09 10 A0 E1 ?? ?? ?? ?? 00 A0 A0 E1 01 B0 A0 E1 }
	condition:
		$pattern
}

rule __ieee754_j0_1e15a8e53592ad756a0ef1e56789839d {
	meta:
		aliases = "__ieee754_j0"
		size = "1256"
		objfiles = "e_j0s@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 02 31 C1 E3 2C D0 4D E2 1C 30 8D E5 1C 20 9D E5 60 34 9F E5 00 60 A0 E1 03 00 52 E1 01 70 A0 E1 01 40 A0 E1 07 00 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 01 30 A0 E1 3C 14 9F E5 00 20 A0 E1 00 00 A0 E3 4D 00 00 EA ?? ?? ?? ?? 1C 30 9D E5 00 A0 A0 E1 07 01 73 E3 01 B0 A0 E1 69 00 00 DA ?? ?? ?? ?? 03 00 8D E8 0A 00 A0 E1 0B 10 A0 E1 ?? ?? ?? ?? 00 80 A0 E1 01 90 A0 E1 08 20 A0 E1 09 30 A0 E1 03 00 9D E8 ?? ?? ?? ?? EC 33 9F E5 1C 20 9D E5 08 00 8D E5 0C 10 8D E5 03 00 52 E1 2A 00 00 CA 0A 20 A0 E1 0B 30 A0 E1 0A 00 A0 E1 0B 10 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? 08 20 A0 E1 00 40 A0 E1 }
	condition:
		$pattern
}

rule __ieee754_hypot_ae97dc662f50475517887c3f7b8b4837 {
	meta:
		aliases = "__ieee754_hypot"
		size = "1048"
		objfiles = "e_hypots@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 02 71 C1 E3 01 B0 A0 E1 02 11 C3 E3 07 00 51 E1 24 D0 4D E2 14 10 8D E5 14 70 8D C5 03 60 A0 E1 02 50 A0 E1 01 30 A0 C1 14 C0 9D E5 00 A0 A0 E1 03 70 A0 C1 00 00 A0 C1 05 00 A0 D1 0A 80 A0 D1 05 80 A0 C1 00 10 A0 E1 07 00 6C E0 0B 90 A0 D1 06 90 A0 C1 08 30 A0 E1 07 40 A0 E1 0F 05 50 E3 18 30 8D E5 1C 40 8D E5 01 A0 A0 E1 0C B0 A0 E1 05 00 00 DA 08 00 A0 E1 07 10 A0 E1 0A 20 A0 E1 0C 30 A0 E1 ?? ?? ?? ?? D6 00 00 EA 6C 33 9F E5 03 00 57 E1 00 00 A0 D3 10 00 8D D5 25 00 00 DA 5C 33 9F E5 03 00 57 E1 15 00 00 DA FF 24 C7 E3 0F 26 C2 E3 18 30 8D E2 18 00 93 E8 03 20 92 E1 03 50 A0 01 }
	condition:
		$pattern
}

rule __kernel_cos_462737ac52fd415bbbf5c47fddd294ce {
	meta:
		aliases = "__kernel_cos"
		size = "692"
		objfiles = "k_coss@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 02 81 C1 E3 14 D0 4D E2 F9 05 58 E3 00 A0 A0 E1 01 B0 A0 E1 00 40 A0 E1 01 50 A0 E1 0C 00 8D E8 00 60 A0 E3 00 70 A0 E3 04 00 00 AA ?? ?? ?? ?? 00 00 50 E3 00 00 A0 03 2C 12 9F 05 88 00 00 0A 0A 20 A0 E1 0B 30 A0 E1 0A 00 A0 E1 0B 10 A0 E1 ?? ?? ?? ?? 14 22 9F E5 14 32 9F E5 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? ?? 08 22 9F E5 08 32 9F E5 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? F0 21 9F E5 F0 31 9F E5 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? D8 21 9F E5 D8 31 9F E5 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 }
	condition:
		$pattern
}

rule __ieee754_remainder_8a576d41ab677d3194029f83dc7e2e80 {
	meta:
		aliases = "__ieee754_remainder"
		size = "520"
		objfiles = "e_remainders@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 02 91 C3 E3 0C D0 4D E2 02 C0 99 E1 02 A0 A0 E1 03 B0 A0 E1 00 60 A0 E1 01 70 A0 E1 02 80 A0 E1 00 40 A0 E1 01 50 A0 E1 04 00 8D E5 00 10 8D E5 0A 00 00 0A 00 E0 9D E5 B8 C1 9F E5 02 41 CE E3 0C 00 54 E1 05 00 00 CA 0C 00 59 E1 08 00 00 DA 02 C1 89 E2 01 C6 8C E2 02 C0 9C E1 11 00 00 0A ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 5E 00 00 EA 80 11 9F E5 01 00 59 E1 09 00 00 CA 02 00 A0 E1 03 10 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? ?? 00 60 A0 E1 01 70 A0 E1 04 30 9D E5 03 20 68 E0 04 30 69 E0 02 30 93 E1 05 00 00 1A 06 00 A0 E1 07 10 A0 E1 }
	condition:
		$pattern
}

rule __ieee754_fmod_abf2d2ad221be7bb7217a7b337488cd4 {
	meta:
		aliases = "__ieee754_fmod"
		size = "908"
		objfiles = "e_fmods@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 02 B1 C3 E3 24 D0 4D E2 02 40 9B E1 01 50 A0 E1 00 40 A0 E1 30 00 8D E8 04 50 9D E5 48 C3 9F E5 00 E0 A0 13 01 E0 A0 03 02 91 C5 E3 0C 00 59 E1 01 E0 8E C3 34 C3 9F E5 00 50 A0 E3 0C C0 8F E0 0C C0 8D E5 04 C0 9D E5 00 40 A0 E3 00 00 5E E3 18 40 8D E5 1C 50 8D E5 10 40 8D E5 14 50 8D E5 00 60 A0 E1 01 70 A0 E1 02 A0 A0 E1 00 80 9D E5 02 51 0C E2 05 00 00 1A 00 C0 62 E2 02 C0 8C E1 EC E2 9F E5 AC CF 8B E1 0E 00 5C E1 06 00 00 9A ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 00 60 A0 E1 01 70 A0 E1 AB 00 00 EA 0B 00 59 E1 07 00 00 CA 00 30 A0 A3 01 30 A0 B3 02 00 58 E1 01 30 83 33 }
	condition:
		$pattern
}

rule __kernel_sin_02edfd9e12a5142421c96ccd5460bcbc {
	meta:
		aliases = "__kernel_sin"
		size = "560"
		objfiles = "k_sins@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 02 C1 C1 E3 14 D0 4D E2 F9 05 5C E3 00 80 A0 E1 01 90 A0 E1 00 40 A0 E1 01 50 A0 E1 0C 00 8D E8 02 00 00 AA ?? ?? ?? ?? 00 00 50 E3 6D 00 00 0A 08 20 A0 E1 09 30 A0 E1 08 00 A0 E1 09 10 A0 E1 ?? ?? ?? ?? 08 20 A0 E1 09 30 A0 E1 00 60 A0 E1 01 70 A0 E1 ?? ?? ?? ?? 98 21 9F E5 08 00 8D E5 0C 10 8D E5 90 31 9F E5 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? ?? 84 21 9F E5 84 31 9F E5 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? ?? 6C 21 9F E5 6C 31 9F E5 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? ?? 54 21 9F E5 54 31 9F E5 ?? ?? ?? ?? 00 20 A0 E1 }
	condition:
		$pattern
}

rule __kernel_tan_234774623d4b7dd5e2c658baf632c839 {
	meta:
		aliases = "__kernel_tan"
		size = "1512"
		objfiles = "k_tans@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 02 C1 C1 E3 2C D0 4D E2 18 C0 8D E5 18 E0 9D E5 44 C5 9F E5 10 00 8D E5 14 10 8D E5 0C 00 5E E1 01 50 A0 E1 1C 10 8D E5 02 A0 A0 E1 03 B0 A0 E1 1B 00 00 CA ?? ?? ?? ?? 00 00 50 E3 3C 00 00 1A 18 00 9D E5 50 10 9D E5 10 30 8D E2 18 00 93 E8 01 20 81 E2 03 30 80 E1 02 30 93 E1 07 00 00 1A 10 00 8D E2 03 00 90 E8 ?? ?? ?? ?? 01 30 A0 E1 E8 14 9F E5 00 20 A0 E1 00 00 A0 E3 06 00 00 EA 50 20 9D E5 01 00 52 E3 2F 01 00 0A D0 14 9F E5 00 00 A0 E3 10 20 8D E2 0C 00 92 E8 ?? ?? ?? ?? 27 01 00 EA BC 34 9F E5 18 C0 9D E5 03 00 5C E1 1F 00 00 DA 1C E0 9D E5 00 00 5E E3 07 00 00 AA 10 00 9D E5 }
	condition:
		$pattern
}

rule _wstdio_fwrite_46003e1bcfa1b16ca249337f3ceeecdf {
	meta:
		aliases = "_wstdio_fwrite"
		size = "284"
		objfiles = "_wfwrites@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 04 30 92 E5 5C D0 4D E2 03 00 73 E3 02 50 A0 E1 00 70 A0 E1 01 60 A0 E1 0F 00 00 1A 10 00 92 E5 0C 30 92 E5 03 30 60 E0 43 31 A0 E1 01 00 53 E1 03 40 A0 31 01 40 A0 21 00 00 54 E3 32 00 00 0A 07 10 A0 E1 04 20 A0 E1 ?? ?? ?? ?? 10 30 95 E5 04 31 83 E0 10 30 85 E5 2B 00 00 EA B0 30 D2 E1 21 3D 03 E2 21 0D 53 E3 05 00 00 0A 02 00 A0 E1 02 1B A0 E3 ?? ?? ?? ?? 00 00 50 E3 00 80 A0 13 20 00 00 1A 54 30 8D E2 00 80 A0 E3 14 90 8D E2 2C A0 85 E2 01 B0 A0 E3 0C 30 8D E5 54 70 8D E5 12 00 00 EA 00 A0 8D E5 ?? ?? ?? ?? 00 40 A0 E1 01 30 88 E2 01 00 74 E3 05 20 A0 E1 09 00 A0 E1 03 31 87 E0 }
	condition:
		$pattern
}

rule __GI_inet_pton_c605fead7e746a6ae21ac8b0ab2e66fb {
	meta:
		aliases = "inet_pton, __GI_inet_pton"
		size = "540"
		objfiles = "ntops@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 04 42 9F E5 1C D0 4D E2 02 00 50 E3 04 40 8F E0 01 50 A0 E1 04 20 8D E5 02 00 00 0A 0A 00 50 E3 73 00 00 1A 03 00 00 EA 01 00 A0 E1 04 10 9D E5 BE FF FF EB 72 00 00 EA 08 00 8D E2 00 10 A0 E3 10 20 A0 E3 ?? ?? ?? ?? 00 30 D5 E5 00 60 A0 E1 3A 00 53 E3 10 80 80 E2 02 00 00 1A 01 30 F5 E5 3A 00 53 E3 60 00 00 1A A0 31 9F E5 00 90 A0 E3 03 40 84 E0 05 A0 A0 E1 09 B0 A0 E1 09 70 A0 E1 00 40 8D E5 30 00 00 EA 00 00 9D E5 04 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 01 50 85 E2 06 00 00 0A 00 20 9D E5 00 30 62 E0 07 72 83 E1 60 31 9F E5 03 00 57 E1 23 00 00 9A 4B 00 00 EA 3A 00 54 E3 15 00 00 1A }
	condition:
		$pattern
}

rule _dl_do_reloc_869386d64a27c2f92d540451baa1c475 {
	meta:
		aliases = "_dl_do_reloc"
		size = "436"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { F0 4F 2D E9 04 C0 92 E5 00 90 A0 E1 8C 61 9F E5 00 00 92 E5 00 20 99 E5 2C 84 B0 E1 06 60 8F E0 04 D0 4D E2 02 A0 80 E0 03 50 A0 E1 FF 40 0C E2 08 B0 A0 01 23 00 00 0A 08 72 A0 E1 07 00 93 E7 14 00 54 E3 28 20 9D E5 02 30 A0 03 00 30 A0 13 16 00 54 E3 01 30 83 03 00 00 82 E0 09 20 A0 E1 ?? ?? ?? ?? 00 B0 50 E2 07 30 85 E0 15 00 00 1A 0C 30 D3 E5 23 32 A0 E1 02 00 53 E3 11 00 00 0A 07 30 95 E7 28 10 9D E5 14 21 9F E5 03 30 81 E0 02 20 96 E7 0C 11 9F E5 00 20 92 E5 01 10 86 E0 02 00 80 E2 ?? ?? ?? ?? 01 00 A0 E3 00 70 A0 E1 00 00 00 EF 01 0A 70 E3 EC 20 9F 85 00 30 60 82 02 20 96 87 00 30 82 85 }
	condition:
		$pattern
}

rule __prefix_array_3a178e87a127f08d44c1fe9da1eae599 {
	meta:
		aliases = "__prefix_array"
		size = "192"
		objfiles = "globs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 04 D0 4D E2 01 70 A0 E1 02 B0 A0 E1 00 90 A0 E1 ?? ?? ?? ?? 01 00 50 E3 00 60 A0 E1 02 00 00 1A 00 30 D9 E5 2F 60 53 E2 01 60 A0 13 00 50 A0 E3 1B 00 00 EA 04 00 97 E7 ?? ?? ?? ?? 01 80 80 E2 01 00 88 E2 06 00 80 E0 ?? ?? ?? ?? 00 A0 50 E2 09 10 A0 E1 06 20 A0 E1 07 00 00 1A 01 00 00 EA 05 01 97 E7 ?? ?? ?? ?? 00 00 55 E3 01 50 45 E2 FA FF FF 1A 01 00 A0 E3 0D 00 00 EA ?? ?? ?? ?? 2F 30 A0 E3 01 30 C0 E4 08 20 A0 E1 04 10 97 E7 ?? ?? ?? ?? 04 00 97 E7 ?? ?? ?? ?? 01 50 85 E2 04 A0 87 E7 0B 00 55 E1 05 41 A0 E1 E0 FF FF 3A 00 00 A0 E3 04 D0 8D E2 F0 8F BD E8 }
	condition:
		$pattern
}

rule __encode_packet_fb2ec07717f7b3283a5d439a939b83d5 {
	meta:
		aliases = "__encode_packet"
		size = "320"
		objfiles = "encodeps@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 04 D0 4D E2 2C 40 9D E5 30 60 9D E5 01 A0 A0 E1 02 90 A0 E1 04 10 A0 E1 06 20 A0 E1 03 B0 A0 E1 00 80 A0 E1 ?? ?? ?? ?? 00 00 50 E3 40 00 00 BA 00 50 84 E0 00 70 A0 E3 06 40 60 E0 00 60 A0 E1 07 00 00 EA 07 01 9A E7 ?? ?? ?? ?? 00 00 50 E3 37 00 00 BA 00 60 86 E0 00 50 85 E0 04 40 60 E0 01 70 87 E2 20 30 98 E5 05 10 A0 E1 03 00 57 E1 04 20 A0 E1 F2 FF FF 3A 00 70 A0 E3 07 00 00 EA 07 01 99 E7 ?? ?? ?? ?? 00 00 50 E3 28 00 00 BA 00 60 86 E0 00 50 85 E0 04 40 60 E0 01 70 87 E2 24 30 98 E5 05 10 A0 E1 03 00 57 E1 04 20 A0 E1 F2 FF FF 3A 00 70 A0 E3 07 00 00 EA 07 01 9B E7 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_svc_getreq_common_df94a13eabf179fc1965a421aa730b9a {
	meta:
		aliases = "svc_getreq_common, __GI_svc_getreq_common"
		size = "472"
		objfiles = "svcs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 05 DC 4D E2 0C D0 4D E2 08 30 8D E2 D4 34 8D E5 66 3F 8D E2 E0 34 8D E5 00 40 A0 E1 ?? ?? ?? ?? B4 30 90 E5 A0 51 9F E5 04 41 93 E7 00 80 A0 E1 00 00 54 E3 05 50 8F E0 60 00 00 0A 8C 21 9F E5 4B BE 8D E2 CA 3F 8D E2 4F 7E 8D E2 4E AE 8D E2 00 20 8D E5 08 B0 8B E2 04 30 8D E5 04 70 87 E2 4D 6E 8D E2 01 90 A0 E3 08 A0 8A E2 08 30 94 E5 04 00 A0 E1 0B 10 A0 E1 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 40 00 00 0A C4 34 9D E5 D0 C4 9D E5 E8 34 8D E5 C8 34 9D E5 04 20 9D E5 EC 34 8D E5 CC 34 9D E5 00 00 5C E3 00 25 8D E5 F0 34 8D E5 07 00 96 E8 04 45 8D E5 07 00 87 E8 06 00 00 1A 00 20 9D E5 }
	condition:
		$pattern
}

rule writeunix_c538069613e68e968f9a47477b150080 {
	meta:
		aliases = "writeunix"
		size = "284"
		objfiles = "svc_unixs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 08 C1 9F E5 08 31 9F E5 0C C0 8F E0 44 D0 4D E2 03 70 8C E0 02 60 A0 E1 2C 30 8D E2 02 40 A0 E1 0C 20 87 E2 0C 20 8D E5 08 30 8D E5 38 20 8D E2 10 30 8D E2 00 A0 A0 E1 01 50 A0 E1 01 B0 A0 E3 18 90 A0 E3 04 20 8D E5 00 30 8D E5 2A 00 00 EA 00 80 9A E5 ?? ?? ?? ?? 2C 00 8D E5 ?? ?? ?? ?? 30 00 8D E5 ?? ?? ?? ?? 0C 20 A0 E3 34 00 8D E5 08 10 9D E5 0C 00 9D E5 ?? ?? ?? ?? 02 20 A0 E3 04 B0 87 E5 08 20 87 E5 00 90 87 E5 04 20 9D E5 00 30 A0 E3 28 30 8D E5 38 50 8D E5 3C 40 8D E5 18 20 8D E5 1C B0 8D E5 10 30 8D E5 14 30 8D E5 20 70 8D E5 24 90 8D E5 00 10 9D E5 00 20 A0 E3 08 00 A0 E1 }
	condition:
		$pattern
}

rule srandom_r_b8c0938e61e844f690e397b366f42209 {
	meta:
		aliases = "__GI_srandom_r, srandom_r"
		size = "208"
		objfiles = "random_rs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 0C 30 91 E5 0C D0 4D E2 04 00 53 E3 01 50 A0 E1 00 00 E0 83 27 00 00 8A 00 00 50 E3 08 60 91 E5 01 00 A0 03 00 00 53 E3 00 00 86 E5 20 00 00 0A 10 A0 91 E5 84 B0 9F E5 84 90 9F E5 00 40 A0 E1 06 80 A0 E1 01 70 A0 E3 08 00 00 EA ?? ?? ?? ?? 04 00 A0 E1 91 0B 04 E0 68 10 9F E5 ?? ?? ?? ?? 90 09 03 E0 03 40 54 E0 06 41 44 42 04 40 A8 E5 0A 00 57 E1 04 00 A0 E1 48 10 9F E5 01 70 87 E2 F1 FF FF BA 0A 30 A0 E3 9A 03 04 E0 14 30 95 E5 04 70 8D E2 03 31 86 E0 48 00 85 E8 00 00 00 EA ?? ?? ?? ?? 01 40 54 E2 05 00 A0 E1 07 10 A0 E1 FA FF FF 5A 00 00 A0 E3 0C D0 8D E2 F0 8F BD E8 A7 41 00 00 }
	condition:
		$pattern
}

rule _dl_lookup_hash_583ab3839e8e8bf95e0d3d8493cfca1d {
	meta:
		aliases = "_dl_lookup_hash"
		size = "340"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { F0 4F 2D E9 0C D0 4D E2 04 30 8D E5 00 B0 A0 E1 02 30 03 E2 01 60 A0 E1 02 80 A0 E1 00 A0 E0 E3 00 30 8D E5 3C 00 00 EA 00 50 96 E5 24 30 95 E5 23 34 A0 E1 01 30 23 E2 00 00 58 E3 00 30 A0 03 01 30 03 12 00 00 53 E3 0A 00 00 0A 05 00 58 E1 34 20 98 15 04 00 00 1A 06 00 00 EA 04 30 92 E5 05 00 53 E1 03 00 00 0A 00 20 92 E5 00 00 52 E3 F9 FF FF 1A 27 00 00 EA 00 30 9D E5 00 00 53 E3 02 00 00 0A 18 30 95 E5 01 00 53 E3 21 00 00 0A 28 10 95 E5 00 00 51 E3 1E 00 00 0A 01 00 7A E3 58 90 95 E5 0B C0 A0 01 01 A0 8A 02 04 00 00 0A 07 00 00 EA 0A 32 80 E0 0F 22 03 E2 03 30 22 E0 22 AC 23 E0 00 00 DC E5 }
	condition:
		$pattern
}

rule _uintmaxtostr_12a614533fdc08c7a4ce01609178ee01 {
	meta:
		aliases = "_uintmaxtostr"
		size = "344"
		objfiles = "_uintmaxtostrs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 0C D0 4D E2 30 70 9D E5 00 80 A0 E1 00 00 57 E3 02 50 A0 E1 03 60 A0 E1 07 00 00 AA 00 00 53 E3 00 70 67 E2 04 00 00 AA 01 20 A0 E3 00 50 75 E2 00 60 E6 E2 04 20 8D E5 01 00 00 EA 00 30 A0 E3 04 30 8D E5 00 A0 A0 E3 00 A0 C8 E5 07 10 A0 E1 00 00 E0 E3 ?? ?? ?? ?? 07 10 A0 E1 00 B0 A0 E1 00 00 E0 E3 ?? ?? ?? ?? 01 90 81 E2 07 00 59 E1 0A 90 A0 01 01 B0 8B 02 06 A0 A0 E1 05 60 A0 E1 00 00 5A E3 06 00 A0 E1 07 10 A0 E1 19 00 00 0A 0A 00 A0 E1 ?? ?? ?? ?? 0A 00 A0 E1 01 40 A0 E1 07 10 A0 E1 ?? ?? ?? ?? 07 10 A0 E1 00 A0 A0 E1 06 00 A0 E1 ?? ?? ?? ?? 99 04 05 E0 06 00 A0 E1 01 50 85 E0 }
	condition:
		$pattern
}

rule lldiv_a9ae4c0511937975ca4a58c0377da097 {
	meta:
		aliases = "imaxdiv, lldiv"
		size = "152"
		objfiles = "lldivs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 0C D0 4D E2 30 A0 8D E2 00 0C 9A E8 03 50 A0 E1 02 40 A0 E1 04 00 8D E5 03 10 A0 E1 02 00 A0 E1 0B 30 A0 E1 0A 20 A0 E1 ?? ?? ?? ?? 0A 20 A0 E1 00 80 A0 E1 01 90 A0 E1 04 00 A0 E1 05 10 A0 E1 0B 30 A0 E1 ?? ?? ?? ?? 00 00 55 E3 02 60 A0 E1 03 70 A0 E1 07 00 00 BA 00 00 53 E3 05 00 00 AA 01 30 A0 E3 03 80 98 E0 00 40 A0 E3 04 90 A9 E0 0A 60 56 E0 0B 70 C7 E0 04 30 9D E5 03 00 A0 E1 08 60 83 E5 0C 70 83 E5 00 03 83 E8 0C D0 8D E2 F0 8F BD E8 }
	condition:
		$pattern
}

rule __pthread_destroy_specifics_13530e29766a9f5f9fd0828f47181460 {
	meta:
		aliases = "__pthread_destroy_specifics"
		size = "280"
		objfiles = "specifics@libpthread.a"
	strings:
		$pattern = { F0 4F 2D E9 0C D0 4D E2 A5 FF FF EB FC 20 9F E5 FC 30 9F E5 02 20 8F E0 00 A0 A0 E3 01 10 A0 E3 03 30 82 E0 00 60 A0 E1 0A 70 A0 E1 01 B0 A0 E1 04 30 8D E5 1B 00 00 EA 05 31 86 E0 E0 20 83 E2 0C 30 92 E5 00 00 53 E3 02 90 A0 11 07 40 A0 11 85 82 A0 11 0A 00 00 1A 0E 00 00 EA 0C 30 99 E5 04 20 92 E5 04 01 93 E7 00 00 52 E3 00 00 50 13 02 00 00 0A 04 71 83 E7 32 FF 2F E1 0B 10 A0 E1 01 40 84 E2 04 00 9D E5 04 30 88 E0 1F 00 54 E3 83 21 80 E0 F0 FF FF DA 01 50 85 E2 1F 00 55 E3 E4 FF FF DA 01 A0 8A E2 03 00 5A E3 00 40 A0 C3 01 40 01 D2 00 00 54 E3 07 50 A0 11 07 10 A0 11 F5 FF FF 1A 1C 00 96 E5 }
	condition:
		$pattern
}

rule __GI_nextafter_ae7afefd9769728bf52883c0688246b3 {
	meta:
		aliases = "nextafter, __GI_nextafter"
		size = "544"
		objfiles = "s_nextafters@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 0C E2 9F E5 02 91 C1 E3 24 D0 4D E2 02 B0 A0 E1 03 C0 A0 E1 02 60 A0 E1 03 70 A0 E1 00 20 A0 E3 00 30 A0 E3 0E 00 59 E1 00 40 A0 E1 01 50 A0 E1 01 80 A0 E1 00 A0 A0 E1 10 20 8D E5 14 30 8D E5 08 20 8D E5 0C 30 8D E5 0C 00 8D E8 18 C0 8D E5 1C B0 8D E5 03 00 00 DA 02 31 89 E2 01 36 83 E2 00 30 93 E1 08 00 00 1A 02 31 C7 E3 0E 00 53 E1 07 60 A0 E1 09 00 00 DA 02 31 83 E2 1C 20 9D E5 01 36 83 E2 02 20 93 E1 04 00 00 0A 04 00 A0 E1 05 10 A0 E1 0B 20 A0 E1 0C 30 A0 E1 42 00 00 EA 0B 20 A0 E1 0C 30 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 51 00 00 1A 0A 90 99 E1 14 00 00 1A }
	condition:
		$pattern
}

rule _ppfs_parsespec_c1cadc6243aff88a861b49b840578568 {
	meta:
		aliases = "_ppfs_parsespec"
		size = "1240"
		objfiles = "_ppfs_parsespecs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 10 30 90 E5 44 D0 4D E2 80 E0 13 E2 00 20 A0 E3 08 30 A0 E3 94 44 9F E5 38 30 8D E5 28 20 8D E5 2C 20 8D E5 34 30 8D E5 00 70 A0 E1 04 40 8F E0 18 B0 90 E5 00 00 90 05 11 00 00 0A 02 00 A0 E1 00 30 97 E5 40 10 8D E2 00 31 83 E0 00 20 81 E0 04 10 53 E5 01 00 80 E2 38 10 42 E5 04 30 13 E5 03 00 51 E1 0E 01 00 1A 00 00 51 E3 01 00 00 0A 1F 00 50 E3 F1 FF FF 9A 00 30 A0 E3 27 30 CD E5 09 00 8D E2 28 34 9F E5 00 A0 A0 E3 24 24 9F E5 03 30 84 E0 0A 80 A0 E1 0A 50 A0 E1 02 91 A0 E3 04 20 8D E5 00 30 8D E5 00 00 00 EA 06 00 A0 E1 00 30 D0 E5 2A 00 53 E3 03 30 E0 03 40 10 8D 02 98 13 23 00 }
	condition:
		$pattern
}

rule svcudp_bufcreate_cc4d17d60002f0ac1b42b70d2ce95cc8 {
	meta:
		aliases = "__GI_svcudp_bufcreate, svcudp_bufcreate"
		size = "564"
		objfiles = "svc_udps@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 10 A2 9F E5 24 D0 4D E2 01 00 70 E3 10 30 A0 E3 0A A0 8F E0 00 70 A0 E1 1C 30 8D E5 01 80 A0 E1 02 60 A0 E1 00 50 A0 13 0B 00 00 1A 02 00 A0 E3 00 10 A0 E1 11 20 A0 E3 ?? ?? ?? ?? 00 70 50 E2 01 50 A0 A3 04 00 00 AA CC 01 9F E5 00 90 A0 E3 00 00 8A E0 ?? ?? ?? ?? 6B 00 00 EA 08 40 8D E2 00 10 A0 E3 10 20 A0 E3 04 00 A0 E1 ?? ?? ?? ?? 02 30 A0 E3 07 00 A0 E1 04 10 A0 E1 B8 30 CD E1 ?? ?? ?? ?? 00 00 50 E3 05 00 00 0A 00 30 A0 E3 07 00 A0 E1 04 10 A0 E1 1C 20 9D E5 BA 30 CD E1 ?? ?? ?? ?? 04 10 A0 E1 07 00 A0 E1 1C 20 8D E2 ?? ?? ?? ?? 00 B0 50 E2 09 00 00 0A 5C 01 9F E5 00 00 8A E0 }
	condition:
		$pattern
}

rule __GI_getservbyname_r_454652563763a02a63c99b6ff0447a25 {
	meta:
		aliases = "getservbyname_r, __GI_getservbyname_r"
		size = "316"
		objfiles = "getservices@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 14 51 9F E5 14 41 9F E5 05 50 8F E0 02 60 A0 E1 0C 21 9F E5 14 D0 4D E2 04 40 85 E0 00 80 A0 E1 01 70 A0 E1 0D 00 A0 E1 02 10 95 E7 03 90 A0 E1 04 20 A0 E1 EC 30 9F E5 3C B0 9D E5 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 DC 30 9F E5 0F E0 A0 E1 03 F0 95 E7 D4 30 9F E5 03 00 95 E7 ?? ?? ?? ?? 16 00 00 EA 08 00 A0 E1 00 10 96 E5 ?? ?? ?? ?? 00 00 50 E3 04 40 96 15 03 00 00 1A 08 00 00 EA ?? ?? ?? ?? 00 00 50 E3 05 00 00 0A 00 30 94 E5 08 00 A0 E1 00 10 53 E2 04 40 84 E2 F7 FF FF 1A 06 00 00 EA 00 00 57 E3 0B 00 00 0A 0C 00 96 E5 07 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 06 00 00 0A 06 00 A0 E1 }
	condition:
		$pattern
}

rule ether_aton_r_df1cc93057f758693130ef6269123975 {
	meta:
		aliases = "__GI_ether_aton_r, ether_aton_r"
		size = "300"
		objfiles = "ether_addrs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 14 A1 9F E5 14 B1 9F E5 14 91 9F E5 0A A0 8F E0 01 60 A0 E1 00 70 A0 E3 39 00 00 EA 00 30 D0 E5 0B 50 9A E7 83 C0 D5 E7 30 E0 4C E2 FF 20 0E E2 61 30 4C E2 09 00 52 E3 05 00 53 83 33 00 00 8A 09 40 9A E7 8C 30 A0 E1 B4 30 93 E1 08 00 13 E3 01 30 D0 E5 57 10 4C 02 83 C0 D5 E7 0E 10 A0 11 04 00 57 E3 00 80 A0 83 01 80 A0 93 3A 00 5C E3 00 30 A0 03 01 30 08 12 00 00 53 E3 01 00 80 E2 0A 00 00 1A 05 00 57 E3 00 30 A0 13 01 30 A0 03 00 00 5C E3 00 30 A0 03 00 00 53 E3 15 00 00 0A 8C 30 A0 E1 B4 30 93 E1 20 00 13 E3 11 00 00 1A 30 E0 4C E2 FF 20 0E E2 61 30 4C E2 09 00 52 E3 05 00 53 83 }
	condition:
		$pattern
}

rule pthread_cond_timedwait_db5f57fdf953eb7f310def5e5ef6a781 {
	meta:
		aliases = "__GI_pthread_cond_timedwait, pthread_cond_timedwait"
		size = "536"
		objfiles = "condvars@libpthread.a"
	strings:
		$pattern = { F0 4F 2D E9 14 D0 4D E2 01 70 A0 E1 00 50 A0 E1 02 B0 A0 E1 BE FF FF EB 0C 30 97 E5 E4 81 9F E5 03 00 53 E3 00 00 53 13 0C 00 8D E5 08 80 8F E0 04 00 00 0A 0C 20 9D E5 08 30 97 E5 02 00 53 E1 16 00 A0 13 6D 00 00 1A BC 31 9F E5 0C 20 9D E5 03 30 88 E0 08 30 8D E5 00 30 A0 E3 04 50 8D E5 B9 31 C2 E5 0C 00 9D E5 04 10 8D E2 7A FF FF EB 05 00 A0 E1 0C 10 9D E5 ?? ?? ?? ?? 0C 30 9D E5 42 30 D3 E5 00 00 53 E3 04 00 00 0A 0C 30 9D E5 40 30 D3 E5 00 00 53 E3 01 40 A0 03 03 00 00 0A 0C 10 9D E5 08 00 85 E2 36 FF FF EB 00 40 A0 E3 05 00 A0 E1 ?? ?? ?? ?? 00 00 54 E3 03 00 00 0A 0C 00 9D E5 00 10 A0 E3 }
	condition:
		$pattern
}

rule __GI___ns_name_unpack_3bf300a910a0262121d5aed65044fdaa {
	meta:
		aliases = "__ns_name_unpack, __GI___ns_name_unpack"
		size = "316"
		objfiles = "ns_names@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 14 D0 4D E2 02 A0 A0 E1 03 40 A0 E1 01 00 52 E1 00 20 A0 33 01 20 A0 23 38 30 9D E5 00 00 5A E1 01 20 82 33 03 30 84 E0 00 00 52 E3 01 80 A0 E1 00 70 A0 E1 0C 30 8D E5 2F 00 00 1A 02 90 A0 E1 0A 60 A0 E1 01 20 60 E0 00 C0 E0 E3 01 B0 6A E2 08 20 8D E5 2D 00 00 EA C0 30 15 E2 02 00 00 0A C0 00 53 E3 24 00 00 1A 11 00 00 EA 05 30 84 E0 0C 20 9D E5 01 30 83 E2 02 00 53 E1 1E 00 00 2A 05 60 81 E0 08 00 56 E1 1B 00 00 2A 01 50 C4 E4 01 30 89 E2 04 00 A0 E1 05 20 A0 E1 04 C0 8D E5 05 90 83 E0 ?? ?? ?? ?? 04 C0 9D E5 05 40 84 E0 16 00 00 EA 08 00 51 E1 0F 00 00 2A 01 30 D6 E5 3F 20 05 E2 }
	condition:
		$pattern
}

rule scandir64_4087f733b63ae0609f8b7fbf1052825a {
	meta:
		aliases = "scandir64"
		size = "340"
		objfiles = "scandir64s@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 14 D0 4D E2 08 10 8D E5 02 B0 A0 E1 04 30 8D E5 ?? ?? ?? ?? 00 80 50 E2 00 00 E0 03 49 00 00 0A ?? ?? ?? ?? 00 30 A0 E3 00 20 90 E5 00 50 A0 E1 03 70 A0 E1 03 60 A0 E1 03 A0 A0 E1 0C 20 8D E5 00 30 80 E5 1C 00 00 EA 00 00 5B E3 03 00 00 0A 3B FF 2F E1 00 00 50 E3 00 00 85 05 16 00 00 0A 00 30 A0 E3 0A 00 56 E1 00 30 85 E5 08 00 00 1A 03 00 56 E1 0A A0 A0 03 86 A0 A0 11 07 00 A0 E1 0A 11 A0 E1 ?? ?? ?? ?? 00 00 50 E3 0E 00 00 0A 00 70 A0 E1 B0 41 D9 E1 04 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 08 00 00 0A 09 10 A0 E1 04 20 A0 E1 ?? ?? ?? ?? 06 01 87 E7 01 60 86 E2 08 00 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule scandir_422a1c011771d7b06f8e945ee176fba3 {
	meta:
		aliases = "scandir"
		size = "340"
		objfiles = "scandirs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 14 D0 4D E2 08 10 8D E5 02 B0 A0 E1 04 30 8D E5 ?? ?? ?? ?? 00 80 50 E2 00 00 E0 03 49 00 00 0A ?? ?? ?? ?? 00 30 A0 E3 00 20 90 E5 00 50 A0 E1 03 70 A0 E1 03 60 A0 E1 03 A0 A0 E1 0C 20 8D E5 00 30 80 E5 1C 00 00 EA 00 00 5B E3 03 00 00 0A 3B FF 2F E1 00 00 50 E3 00 00 85 05 16 00 00 0A 00 30 A0 E3 0A 00 56 E1 00 30 85 E5 08 00 00 1A 03 00 56 E1 0A A0 A0 03 86 A0 A0 11 07 00 A0 E1 0A 11 A0 E1 ?? ?? ?? ?? 00 00 50 E3 0E 00 00 0A 00 70 A0 E1 B8 40 D9 E1 04 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 08 00 00 0A 09 10 A0 E1 04 20 A0 E1 ?? ?? ?? ?? 06 01 87 E7 01 60 86 E2 08 00 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __divsc3_a7ba6b5dac0f62c25e9f962ef06d8054 {
	meta:
		aliases = "__divsc3"
		size = "1380"
		objfiles = "_divsc3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 14 D0 4D E2 38 70 9D E5 03 A0 A0 E1 02 C1 C7 E3 02 31 C3 E3 00 00 8D E5 01 B0 A0 E1 03 00 A0 E1 0C 10 A0 E1 02 80 A0 E1 ?? ?? ?? ?? 00 00 50 E3 24 00 00 0A 07 10 A0 E1 0A 00 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 04 10 A0 E1 0A 00 A0 E1 ?? ?? ?? ?? 07 10 A0 E1 ?? ?? ?? ?? 04 10 A0 E1 00 50 A0 E1 0B 00 A0 E1 ?? ?? ?? ?? 08 10 A0 E1 ?? ?? ?? ?? 05 10 A0 E1 ?? ?? ?? ?? 04 10 A0 E1 00 90 A0 E1 08 00 A0 E1 ?? ?? ?? ?? 0B 10 A0 E1 ?? ?? ?? ?? 05 10 A0 E1 ?? ?? ?? ?? 00 60 A0 E1 09 00 A0 E1 09 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 21 00 00 0A 00 20 9D E5 02 00 A0 E1 00 90 82 E5 04 60 82 E5 14 D0 8D E2 }
	condition:
		$pattern
}

rule __GI_bindresvport_9f6496a9f85d48cac1f51837dddb796e {
	meta:
		aliases = "bindresvport, __GI_bindresvport"
		size = "308"
		objfiles = "bindresvports@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 18 61 9F E5 00 70 51 E2 14 D0 4D E2 06 60 8F E0 00 90 A0 E1 06 00 00 1A 10 20 A0 E3 0D 00 A0 E1 ?? ?? ?? ?? 0D 70 A0 E1 02 20 A0 E3 B0 20 CD E1 07 00 00 EA B0 30 D7 E1 02 00 53 E3 04 00 00 0A ?? ?? ?? ?? 60 30 A0 E3 00 C0 E0 E3 00 30 80 E5 2F 00 00 EA C8 40 9F E5 F4 30 96 E1 00 00 53 E3 04 00 00 1A ?? ?? ?? ?? 6A 1F A0 E3 ?? ?? ?? ?? 96 1F 81 E2 B4 10 86 E1 ?? ?? ?? ?? A4 B0 9F E5 62 30 A0 E3 00 A0 A0 E1 04 50 A0 E1 00 C0 E0 E3 00 80 A0 E3 00 30 80 E5 0F 00 00 EA B5 C0 96 E1 01 E0 8C E2 0E E8 A0 E1 0C C8 A0 E1 2E E8 A0 E1 2C 34 A0 E1 0E 48 A0 E1 FF 3C 03 E2 2C 3C 83 E1 44 08 5B E1 }
	condition:
		$pattern
}

rule __gnu_unwind_pr_common_15670769bd0348f302e836b88b4b0cad {
	meta:
		aliases = "__gnu_unwind_pr_common"
		size = "1336"
		objfiles = "unwind_arm@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 1C C5 9F E5 44 D0 4D E2 14 C0 8D E5 00 00 53 E3 01 80 A0 E1 4C 10 91 E5 18 30 8D E5 14 30 9D E5 04 E0 91 E4 03 30 8F E0 02 B0 A0 E1 03 20 00 E2 08 00 00 E2 14 30 8D E5 01 C0 A0 E1 24 20 8D E5 2C E0 8D E5 30 10 8D E5 20 00 8D E5 B3 00 00 1A 0E 34 A0 E1 2C 30 8D E5 18 30 9D E5 03 20 A0 E3 34 20 CD E5 35 30 CD E5 24 20 9D E5 50 30 98 E5 02 00 52 E3 38 C0 98 05 01 30 13 E2 00 30 A0 13 1C 30 8D 15 1C 30 8D 05 2F 00 00 1A 00 30 9C E5 00 00 53 E3 2C 00 00 0A 18 20 9D E5 48 E0 98 E5 02 00 52 E3 04 50 9C 05 B2 50 DC 11 03 60 A0 01 38 30 8D E2 B0 60 DC 11 08 70 8C 02 04 70 8C 12 0C 30 8D E5 }
	condition:
		$pattern
}

rule __add_to_environ_4b66bbc0142aaa05e1c6fd8d99b8a810 {
	meta:
		aliases = "__add_to_environ"
		size = "604"
		objfiles = "setenvs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 1C D0 4D E2 00 30 8D E5 01 A0 A0 E1 02 80 A0 E1 00 90 A0 E1 ?? ?? ?? ?? 18 72 9F E5 00 00 5A E3 07 70 8F E0 00 60 A0 E1 04 A0 8D 05 03 00 00 0A 0A 00 A0 E1 ?? ?? ?? ?? 01 00 80 E2 04 00 8D E5 F4 41 9F E5 F4 31 9F E5 04 40 87 E0 03 10 97 E7 04 20 A0 E1 08 00 8D E2 E4 31 9F E5 0F E0 A0 E1 03 F0 97 E7 DC 31 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 97 E7 D0 31 9F E5 03 30 97 E7 00 50 93 E5 00 00 55 E3 05 B0 A0 01 00 B0 A0 13 08 00 00 1A 11 00 00 EA ?? ?? ?? ?? 00 00 50 E3 02 00 00 1A 06 30 D4 E7 3D 00 53 E3 06 00 00 0A 01 B0 8B E2 04 50 85 E2 00 40 95 E5 09 10 A0 E1 00 00 54 E2 06 20 A0 E1 }
	condition:
		$pattern
}

rule __GI_ptsname_r_535a875ceac17737419886b9ee4423cf {
	meta:
		aliases = "ptsname_r, __GI_ptsname_r"
		size = "192"
		objfiles = "ptsnames@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 1C D0 4D E2 00 40 A0 E1 01 A0 A0 E1 02 90 A0 E1 ?? ?? ?? ?? 94 10 9F E5 00 60 A0 E1 14 20 8D E2 04 00 A0 E1 00 B0 96 E5 ?? ?? ?? ?? 80 70 9F E5 00 80 50 E2 19 30 A0 13 07 70 8F E0 00 30 86 15 03 00 A0 11 17 00 00 1A 14 20 9D E5 13 40 8D E2 C2 3F A0 E1 04 00 A0 E1 09 10 E0 E3 02 01 8D E8 ?? ?? ?? ?? 04 40 60 E0 0A 40 84 E2 04 00 59 E1 22 30 A0 33 00 50 A0 E1 00 30 86 35 03 00 A0 31 08 00 00 3A 2C 10 9F E5 0A 00 A0 E1 01 10 87 E0 ?? ?? ?? ?? 0A 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 08 00 A0 E1 00 B0 86 E5 1C D0 8D E2 F0 8F BD E8 30 54 04 80 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule re_search_2_2ff0bba03cff282f2c76835e27b5e39d {
	meta:
		aliases = "__re_search_2, re_search_2"
		size = "588"
		objfiles = "regex_olds@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 1C D0 4D E2 02 70 A0 E1 40 20 9D E5 44 40 9D E5 07 A0 82 E0 0A 00 54 E1 00 20 A0 D3 01 20 A0 C3 A4 2F 92 E1 00 60 A0 E1 14 10 8D E5 03 B0 A0 E1 48 50 9D E5 10 80 90 E5 14 90 90 E5 77 00 00 1A 04 30 95 E0 00 50 64 42 01 00 00 4A 0A 00 53 E1 0A 50 64 C0 08 30 96 E5 00 00 53 E3 00 00 55 13 0B 00 00 DA 00 30 96 E5 00 30 D3 E5 0B 00 53 E3 04 00 00 0A 09 00 53 E3 05 00 00 1A 1C 30 D6 E5 80 00 13 E3 02 00 00 1A 00 00 54 E3 63 00 00 CA 01 50 A0 E3 00 00 58 E3 06 00 00 0A 1C 30 D6 E5 08 00 13 E3 03 00 00 1A 06 00 A0 E1 ?? ?? ?? ?? 02 00 70 E3 5B 00 00 0A 0B 30 67 E0 10 30 8D E5 00 00 58 E3 }
	condition:
		$pattern
}

rule __GI_getprotoent_r_7d464093023aa74f5b3f9ab0e2340726 {
	meta:
		aliases = "getprotoent_r, __GI_getprotoent_r"
		size = "624"
		objfiles = "getprotos@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 1C D0 4D E2 04 30 8D E5 02 50 A0 E1 2C 62 9F E5 8B 00 52 E3 04 20 9D E5 00 30 A0 E3 06 60 8F E0 00 30 82 E5 00 90 A0 E1 01 80 A0 E1 04 00 00 8A ?? ?? ?? ?? 22 30 A0 E3 03 40 A0 E1 00 30 80 E5 7B 00 00 EA F8 41 9F E5 F8 31 9F E5 04 40 86 E0 03 10 96 E7 04 20 A0 E1 08 00 8D E2 E8 31 9F E5 0F E0 A0 E1 03 F0 96 E7 E0 31 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 96 E7 8C 30 45 E2 01 0A 53 E3 8C 70 88 E2 04 00 00 8A ?? ?? ?? ?? 22 30 A0 E3 03 40 A0 E1 00 30 80 E5 60 00 00 EA B0 41 9F E5 04 30 96 E7 00 00 53 E3 0A 00 00 1A A4 01 9F E5 A4 11 9F E5 00 00 86 E0 01 10 86 E0 ?? ?? ?? ?? 00 00 50 E3 }
	condition:
		$pattern
}

rule __strtofpmax_015919f7f5d3013a98ab9ac7c3ff8dfd {
	meta:
		aliases = "__strtofpmax"
		size = "944"
		objfiles = "__strtofpmaxs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 1C D0 4D E2 08 00 8D E5 84 33 9F E5 84 03 9F E5 08 80 9D E5 03 30 8F E0 02 B0 A0 E1 00 30 8D E5 04 10 8D E5 00 00 00 EA 01 80 88 E2 00 50 9D E5 00 20 D8 E5 00 50 95 E7 82 30 A0 E1 B5 30 93 E1 0C 50 8D E5 20 30 13 E2 F6 FF FF 1A 2B 00 52 E3 05 00 00 0A 2D 00 52 E3 01 10 A0 03 14 30 8D 15 14 10 8D 05 01 00 00 0A 01 00 00 EA 14 30 8D E5 01 80 88 E2 00 20 A0 E3 00 60 A0 E3 00 70 A0 E3 00 A0 E0 E3 10 20 8D E5 19 00 00 EA 00 00 5A E3 01 A0 8A B2 00 00 5A E3 06 00 A0 E1 07 10 A0 E1 00 20 A0 E3 F0 32 9F E5 01 80 88 E2 01 00 00 1A 30 00 59 E3 0E 00 00 0A 01 A0 8A E2 11 00 5A E3 0B 00 00 CA }
	condition:
		$pattern
}

rule hsearch_r_a5863051aba28db62d034fac7435805b {
	meta:
		aliases = "__GI_hsearch_r, hsearch_r"
		size = "460"
		objfiles = "hsearch_rs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 1C D0 4D E2 10 C0 8D E2 03 00 8C E8 08 20 8D E5 04 30 8D E5 00 B0 A0 E1 ?? ?? ?? ?? 14 10 9D E5 00 20 A0 E1 0C 10 8D E5 01 00 00 EA 02 30 DB E7 00 02 83 E0 01 20 52 E2 FB FF FF 2A 40 20 9D E5 04 90 92 E5 09 10 A0 E1 ?? ?? ?? ?? 00 00 51 E3 01 50 A0 11 01 50 A0 03 0C 30 A0 E3 95 03 03 E0 40 10 9D E5 00 A0 91 E5 03 20 9A E7 03 40 8A E0 00 00 52 E3 27 00 00 0A 05 00 52 E1 05 00 00 1A 0B 00 A0 E1 04 10 94 E5 ?? ?? ?? ?? 00 00 50 E3 04 30 84 02 18 00 00 0A 05 00 A0 E1 02 10 49 E2 ?? ?? ?? ?? 01 70 81 E2 09 30 67 E0 05 40 A0 E1 00 30 8D E5 07 00 54 E1 00 10 9D 95 04 40 67 80 01 40 84 90 }
	condition:
		$pattern
}

rule __udivdi3_5fb6cdb6c2bc88b535790c8df782a168 {
	meta:
		aliases = "__udivdi3"
		size = "1328"
		objfiles = "_udivdi3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 1C D0 4D E2 18 45 9F E5 00 70 A0 E3 00 80 A0 E3 00 00 53 E3 04 40 8F E0 01 60 A0 E1 80 01 8D E8 02 50 A0 E1 00 90 A0 E1 3E 00 00 1A 01 00 52 E1 58 00 00 9A 01 08 52 E3 22 01 00 3A FF 34 E0 E3 03 00 52 E1 18 30 A0 83 10 30 A0 93 08 C0 A0 83 10 C0 A0 93 35 03 A0 E1 C8 24 9F E5 02 10 94 E7 00 30 D1 E7 03 C0 5C E0 16 2C A0 11 20 30 6C 12 15 5C A0 11 39 63 82 11 25 88 A0 E1 08 10 A0 E1 06 00 A0 E1 19 9C A0 11 ?? ?? ?? ?? 08 10 A0 E1 00 A0 A0 E1 06 00 A0 E1 ?? ?? ?? ?? 05 78 A0 E1 27 78 A0 E1 97 0A 02 E0 29 38 A0 E1 01 48 83 E1 04 00 52 E1 05 00 00 9A 05 40 94 E0 01 A0 4A E2 02 00 00 2A }
	condition:
		$pattern
}

rule __divdc3_18b3733a810da144150d0264accfc63b {
	meta:
		aliases = "__divdc3"
		size = "2024"
		objfiles = "_divdc3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 1C D0 4D E2 48 10 9D E5 4C 40 9D E5 01 60 A0 E1 50 10 9D E5 02 71 C4 E3 01 40 A0 E1 54 10 9D E5 00 00 8D E5 02 51 C1 E3 02 A0 A0 E1 03 B0 A0 E1 06 00 A0 E1 07 10 A0 E1 04 20 A0 E1 05 30 A0 E1 ?? ?? ?? ?? 00 00 50 E3 3B 00 00 0A 50 20 8D E2 0C 00 92 E8 48 00 8D E2 03 00 90 E8 ?? ?? ?? ?? 00 40 A0 E1 01 50 A0 E1 04 20 A0 E1 05 30 A0 E1 48 00 8D E2 03 00 90 E8 ?? ?? ?? ?? 50 20 8D E2 0C 00 92 E8 ?? ?? ?? ?? 04 20 A0 E1 00 60 A0 E1 01 70 A0 E1 05 30 A0 E1 0A 00 A0 E1 0B 10 A0 E1 ?? ?? ?? ?? 40 20 8D E2 0C 00 92 E8 ?? ?? ?? ?? 06 20 A0 E1 07 30 A0 E1 ?? ?? ?? ?? 04 20 A0 E1 05 30 A0 E1 }
	condition:
		$pattern
}

rule __divdi3_58159e823000b966bd17271bce54786f {
	meta:
		aliases = "__divdi3"
		size = "1436"
		objfiles = "_divdi3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 1C D0 4D E2 84 85 9F E5 00 00 51 E3 00 40 A0 E3 00 50 A0 E3 00 C0 A0 A3 30 00 8D E8 08 80 8F E0 02 40 A0 E1 03 50 A0 E1 08 C0 8D A5 D6 00 00 BA 00 00 53 E3 DA 00 00 BA 00 00 55 E3 01 70 A0 E1 04 60 A0 E1 00 90 A0 E1 3D 00 00 1A 01 00 54 E1 4A 00 00 9A 01 08 54 E3 34 01 00 2A FF 00 54 E3 18 C0 A0 83 20 C0 A0 93 00 30 A0 93 08 30 A0 83 36 03 A0 E1 18 25 9F E5 02 10 98 E7 00 30 D1 E7 03 10 5C E0 17 21 A0 11 20 30 61 12 16 61 A0 11 39 73 82 11 26 88 A0 E1 19 91 A0 11 07 00 A0 E1 08 10 A0 E1 ?? ?? ?? ?? 08 10 A0 E1 00 A0 A0 E1 07 00 A0 E1 ?? ?? ?? ?? 06 78 A0 E1 27 78 A0 E1 97 0A 02 E0 }
	condition:
		$pattern
}

rule __umoddi3_0093c0b3c207319a7e660ff713b52952 {
	meta:
		aliases = "__umoddi3"
		size = "1284"
		objfiles = "_umoddi3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 1C D0 4D E2 EC 44 9F E5 00 50 A0 E3 00 60 A0 E3 00 00 53 E3 60 00 8D E8 04 40 8F E0 02 50 A0 E1 00 90 A0 E1 01 60 A0 E1 3E 00 00 1A 01 00 52 E1 5B 00 00 9A 01 08 52 E3 B8 00 00 3A FF 34 E0 E3 03 00 52 E1 18 30 A0 83 10 30 A0 93 08 C0 A0 83 10 C0 A0 93 35 03 A0 E1 9C 24 9F E5 02 10 94 E7 00 30 D1 E7 03 30 5C E0 03 B0 A0 11 16 2B A0 11 20 30 6B 12 15 5B A0 11 39 63 82 11 25 A8 A0 E1 0A 10 A0 E1 06 00 A0 E1 03 B0 A0 01 19 9B A0 11 ?? ?? ?? ?? 05 78 A0 E1 27 78 A0 E1 97 00 08 E0 0A 10 A0 E1 06 00 A0 E1 ?? ?? ?? ?? 29 38 A0 E1 01 48 83 E1 04 00 58 E1 03 00 00 9A 05 40 94 E0 01 00 00 2A }
	condition:
		$pattern
}

rule __GI_log1p_2d1cb36908a2e86a087d8af3f5c91104 {
	meta:
		aliases = "log1p, __GI_log1p"
		size = "1720"
		objfiles = "s_log1ps@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 24 36 9F E5 24 D0 4D E2 03 00 51 E1 00 50 A0 E1 01 60 A0 E1 01 40 A0 E1 01 C0 A0 E1 43 00 00 CA 08 36 9F E5 02 41 C1 E3 03 00 54 E1 11 00 00 DA 00 20 A0 E3 F8 35 9F E5 ?? ?? ?? ?? 00 00 50 E3 F0 15 9F 15 00 00 A0 13 00 20 A0 13 00 30 A0 13 06 00 00 1A 05 20 A0 E1 06 30 A0 E1 05 00 A0 E1 06 10 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 66 01 00 EA BC 35 9F E5 03 00 54 E1 1B 00 00 CA 00 20 A0 E3 B0 35 9F E5 ?? ?? ?? ?? 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? ?? A0 35 9F E5 00 00 50 E3 00 20 A0 E3 01 20 A0 13 03 00 54 E1 00 30 A0 C3 01 30 02 D2 00 00 53 E3 56 01 00 1A 05 20 A0 E1 }
	condition:
		$pattern
}

rule _dl_load_elf_shared_library_ad6d4453141d7b27aeb9927ac8b44ddb {
	meta:
		aliases = "_dl_load_elf_shared_library"
		size = "3192"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { F0 4F 2D E9 24 9C 9F E5 47 DF 4D E2 14 20 8D E5 00 20 A0 E3 09 90 8F E0 00 30 A0 E1 18 10 8D E5 02 10 A0 E1 14 00 9D E5 05 70 A0 E3 00 00 00 EF 01 0A 70 E3 38 00 8D E5 F4 1B 9F 85 00 30 60 82 01 10 99 87 00 30 81 85 02 00 00 8A 38 10 9D E5 00 00 51 E3 04 00 00 AA D8 3B 9F E5 02 60 A0 E1 03 20 99 E7 01 30 A0 E3 E7 02 00 EA D8 10 8D E2 6C 70 A0 E3 00 00 00 EF 01 0A 70 E3 B0 1B 9F 85 00 30 60 82 01 10 99 87 00 30 81 85 01 00 00 8A 00 00 50 E3 0E 00 00 AA 98 3B 9F E5 38 00 9D E5 03 10 99 E7 01 30 A0 E3 00 30 81 E5 06 70 A0 E3 00 00 00 EF 01 0A 70 E3 D5 02 00 9A 70 1B 9F E5 00 30 60 E2 01 10 99 E7 }
	condition:
		$pattern
}

rule __des_crypt_fc343b0de24de0c16160b4536a1f9503 {
	meta:
		aliases = "__des_crypt"
		size = "404"
		objfiles = "dess@libcrypt.a"
	strings:
		$pattern = { F0 4F 2D E9 24 D0 4D E2 00 40 A0 E1 01 50 A0 E1 F9 FB FF EB 6C 91 9F E5 10 20 8D E2 09 90 8F E0 02 00 A0 E1 05 00 00 EA 00 30 D4 E5 83 30 A0 E1 00 30 C2 E5 01 30 D2 E4 00 00 53 E3 01 40 84 12 02 30 60 E0 08 00 53 E3 F6 FF FF 1A 83 FD FF EB 00 40 D5 E5 30 21 9F E5 01 00 D5 E5 02 40 C9 E7 01 30 D5 E5 02 B0 89 E0 00 00 53 E3 04 30 A0 01 01 30 CB E5 CF FB FF EB 00 53 A0 E1 04 00 A0 E1 CC FB FF EB 00 00 85 E1 57 FD FF EB 00 00 A0 E3 19 C0 A0 E3 00 10 A0 E1 1C 20 8D E2 18 30 8D E2 00 C0 8D E5 53 FE FF EB 00 00 50 E3 0C 00 8D E5 00 00 A0 13 31 00 00 1A 1C A0 9D E5 18 20 9D E5 0A 18 A0 E1 22 18 81 E1 }
	condition:
		$pattern
}

rule __ieee754_acos_226895bcad9b03e4989d437180f75ec4 {
	meta:
		aliases = "__ieee754_acos"
		size = "1708"
		objfiles = "e_acoss@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 28 36 9F E5 02 21 C1 E3 03 00 52 E1 0C D0 4D E2 00 80 A0 E1 01 90 A0 E1 01 40 A0 E1 11 00 00 DA 03 21 82 E2 01 26 82 E2 00 20 92 E1 01 40 A0 E1 05 00 00 1A 00 00 51 E3 F4 05 9F D5 F4 15 9F D5 00 00 A0 C3 00 10 A0 C3 76 01 00 EA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 6F 01 00 EA CC 35 9F E5 03 00 52 E1 70 00 00 CA C4 35 9F E5 03 00 52 E1 B0 05 9F D5 BC 15 9F D5 67 01 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? AC 25 9F E5 AC 35 9F E5 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? ?? A0 25 9F E5 A0 35 9F E5 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 }
	condition:
		$pattern
}

rule __GI_erf_1ab8fc5a3890783e48c74597fc39db1e {
	meta:
		aliases = "erf, __GI_erf"
		size = "2832"
		objfiles = "s_erfs@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 28 39 9F E5 02 61 C1 E3 1C D0 4D E2 03 00 56 E1 00 80 A0 E1 01 90 A0 E1 01 40 A0 E1 04 10 8D E5 0F 00 00 DA A1 0F A0 E1 80 00 A0 E1 01 00 60 E2 ?? ?? ?? ?? 08 20 A0 E1 00 40 A0 E1 01 50 A0 E1 09 30 A0 E1 00 00 A0 E3 E4 18 9F E5 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 21 00 00 EA CC 38 9F E5 03 00 56 E1 77 00 00 CA C4 38 9F E5 03 00 56 E1 1D 00 00 CA 02 05 56 E3 12 00 00 AA 00 20 A0 E3 B0 38 9F E5 ?? ?? ?? ?? AC 28 9F E5 00 40 A0 E1 01 50 A0 E1 08 00 A0 E1 09 10 A0 E1 9C 38 9F E5 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? ?? 00 20 A0 E3 }
	condition:
		$pattern
}

rule __GI_pmap_getport_649935a63fedd8e4e1a2f964b460ee9c {
	meta:
		aliases = "pmap_getport, __GI_pmap_getport"
		size = "332"
		objfiles = "pm_getports@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 28 61 9F E5 28 E1 9F E5 06 60 8F E0 0E C0 86 E0 34 D0 4D E2 04 40 9C E5 02 A0 A0 E1 00 C0 E0 E3 6F 2C A0 E3 14 00 8D E5 01 80 A0 E1 B2 20 C0 E1 03 90 A0 E1 28 C0 8D E5 0E 30 96 E7 28 C0 8D E2 19 EE A0 E3 00 B0 A0 E3 E8 10 9F E5 02 20 A0 E3 04 C0 8D E5 0C E0 8D E5 00 40 8D E5 BE B2 CD E1 08 E0 8D E5 ?? ?? ?? ?? 00 50 50 E2 29 00 00 0A ?? ?? ?? ?? C0 30 9F E5 C0 10 9F E5 18 80 8D E5 1C A0 8D E5 20 90 8D E5 24 B0 8D E5 03 30 86 E0 AC 20 9F E5 04 40 95 E5 08 C0 8D E2 00 30 8D E5 01 10 86 E0 2E 30 8D E2 04 30 8D E5 00 70 A0 E1 02 20 86 E0 03 00 91 E8 18 30 8D E2 03 00 8C E8 05 00 A0 E1 }
	condition:
		$pattern
}

rule _stdlib_strto_ll_e96eaee1b439f3da49a3794336471e1d {
	meta:
		aliases = "_stdlib_strto_ll"
		size = "572"
		objfiles = "_stdlib_strto_lls@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 28 C2 9F E5 28 E2 9F E5 0C D0 4D E2 0C C0 8F E0 02 A0 A0 E1 00 70 A0 E1 04 10 8D E5 00 30 8D E5 00 00 00 EA 01 70 87 E2 00 10 D7 E5 0E 20 9C E7 81 30 A0 E1 B2 30 93 E1 20 30 13 E2 F8 FF FF 1A 2B 00 51 E3 04 00 00 0A 2D 00 51 E3 03 B0 A0 11 01 B0 A0 03 01 00 00 0A 01 00 00 EA 03 B0 A0 E1 01 70 87 E2 10 20 DA E3 0D 00 00 1A 00 30 D7 E5 0A A0 8A E2 30 00 53 E3 07 00 00 1A 01 30 F7 E5 02 A0 4A E2 20 30 83 E3 78 00 53 E3 07 00 A0 01 07 00 A0 11 8A A0 A0 01 01 70 87 02 10 00 5A E3 10 A0 A0 A3 02 30 4A E2 22 00 53 E3 00 50 A0 93 00 60 A0 93 0A 80 A0 91 C8 9F A0 91 01 00 00 9A 36 00 00 EA }
	condition:
		$pattern
}

rule __GI_getservent_r_641c9424ab4a26a577638d0001e549b0 {
	meta:
		aliases = "getservent_r, __GI_getservent_r"
		size = "672"
		objfiles = "getservices@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 2C D0 4D E2 14 30 8D E5 02 50 A0 E1 58 62 9F E5 8B 00 52 E3 14 20 9D E5 00 30 A0 E3 06 60 8F E0 00 30 82 E5 00 80 A0 E1 01 A0 A0 E1 04 00 00 8A ?? ?? ?? ?? 22 30 A0 E3 03 40 A0 E1 00 30 80 E5 86 00 00 EA 24 42 9F E5 24 32 9F E5 04 40 86 E0 03 10 96 E7 04 20 A0 E1 18 00 8D E2 14 32 9F E5 0F E0 A0 E1 03 F0 96 E7 0C 32 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 96 E7 8C 30 45 E2 01 0A 53 E3 8C B0 8A E2 02 00 00 8A ?? ?? ?? ?? 22 30 A0 E3 0D 00 00 EA E4 41 9F E5 04 30 96 E7 00 00 53 E3 0C 00 00 1A D8 01 9F E5 D8 11 9F E5 00 00 86 E0 01 10 86 E0 ?? ?? ?? ?? 00 00 50 E3 04 00 86 E7 04 00 00 1A }
	condition:
		$pattern
}

rule __moddi3_df912033c02403a7fe4ebe3f3d80e62a {
	meta:
		aliases = "__moddi3"
		size = "1456"
		objfiles = "_moddi3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 2C D0 4D E2 98 85 9F E5 00 00 51 E3 00 40 A0 E3 00 50 A0 E3 00 C0 A0 A3 30 00 8D E8 08 80 8F E0 02 40 A0 E1 03 50 A0 E1 08 C0 8D A5 D7 00 00 BA 00 00 53 E3 D2 00 00 BA 20 20 8D E2 00 00 55 E3 0C 20 8D E5 04 60 A0 E1 00 90 A0 E1 01 70 A0 E1 46 00 00 1A 01 00 54 E1 70 00 00 9A 01 08 54 E3 D5 00 00 3A FF 34 E0 E3 03 00 54 E1 18 30 A0 83 10 30 A0 93 08 C0 A0 83 10 C0 A0 93 36 03 A0 E1 20 25 9F E5 02 10 98 E7 00 30 D1 E7 03 30 5C E0 03 B0 A0 11 17 2B A0 11 20 30 6B 12 16 6B A0 11 39 73 82 11 26 A8 A0 E1 0A 10 A0 E1 07 00 A0 E1 03 B0 A0 01 19 9B A0 11 ?? ?? ?? ?? 06 58 A0 E1 25 58 A0 E1 }
	condition:
		$pattern
}

rule freopen64_273af46657fbbb75dcf7c6622e07a5a4 {
	meta:
		aliases = "freopen, freopen64"
		size = "416"
		objfiles = "freopens@libc.a, freopen64s@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 34 30 92 E5 68 61 9F E5 34 D0 4D E2 00 00 53 E3 06 60 8F E0 02 50 A0 E1 0C 30 8D E5 08 00 8D E5 04 10 8D E5 0B 00 00 1A 48 31 9F E5 38 40 82 E2 03 10 96 E7 20 00 8D E2 3C 31 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 2C 31 9F E5 0F E0 A0 E1 03 F0 96 E7 18 31 9F E5 10 80 8D E2 03 30 96 E7 08 00 A0 E1 00 30 8D E5 10 31 9F E5 00 10 9D E5 03 70 96 E7 FC 30 9F E5 07 20 A0 E1 03 B0 96 E7 3B FF 2F E1 F0 30 9F E5 07 00 A0 E1 03 90 96 E7 39 FF 2F E1 E8 30 9F E5 08 00 A0 E1 03 20 96 E7 E0 30 9F E5 01 10 A0 E3 03 A0 96 E7 00 30 92 E5 01 30 83 E2 00 30 82 E5 3A FF 2F E1 B0 40 D5 E1 }
	condition:
		$pattern
}

rule __GI_inet_network_e906cf78225efc546044017eed0adbce {
	meta:
		aliases = "inet_network, __GI_inet_network"
		size = "328"
		objfiles = "inet_nets@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 34 31 9F E5 34 71 9F E5 00 50 A0 E3 1C D0 4D E2 01 A0 A0 E3 14 30 8D E5 05 60 A0 E1 05 80 A0 E1 0A B0 A0 E3 07 70 8F E0 00 30 D0 E5 30 00 53 E3 08 10 A0 11 0B 40 A0 11 07 00 00 1A 01 30 F0 E5 58 00 53 E3 78 00 53 13 0A 10 A0 11 08 40 A0 13 01 00 80 02 08 10 A0 01 10 40 A0 03 08 C0 A0 E1 1E 00 00 EA 14 90 9D E5 04 E0 9D E5 09 90 97 E7 B9 30 9E E1 0C 90 8D E5 08 00 13 E3 0A 00 00 0A 08 00 54 E3 00 30 A0 13 01 30 A0 03 37 00 52 E3 00 30 A0 93 00 00 53 E3 23 00 00 1A 94 0C 03 E0 30 30 43 E2 02 C0 83 E0 08 00 00 EA 10 00 54 E3 0F 00 00 1A 10 00 13 E3 0D 00 00 0A 02 00 13 E3 41 30 A0 03 }
	condition:
		$pattern
}

rule __time_localtime_tzi_bfe607e249eb5e4b8015876f8b9deafc {
	meta:
		aliases = "__time_localtime_tzi"
		size = "852"
		objfiles = "_time_localtime_tzis@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 34 33 9F E5 34 C3 9F E5 03 30 8F E0 34 D0 4D E2 0C C0 83 E0 08 C0 8D E5 10 20 8D E5 20 C3 9F E5 08 20 9D E5 0C C0 83 E0 14 00 8D E5 01 70 A0 E1 00 00 A0 E3 2C 10 8D E2 10 20 82 E2 00 C0 8D E5 18 00 8D E5 0C 10 8D E5 04 20 8D E5 18 30 9D E5 18 20 A0 E3 93 02 02 E0 10 00 9D E5 14 10 9D E5 02 30 90 E7 00 00 91 E5 D8 12 9F E5 93 3A 63 E2 01 00 50 E1 2A 3D 83 E2 10 10 9D E5 00 30 63 C2 02 40 81 E0 00 30 83 E0 07 20 A0 E1 06 10 E0 D3 07 10 A0 C3 0C 00 9D E5 2C 30 8D E5 ?? ?? ?? ?? 18 20 9D E5 08 50 9D E5 20 20 87 E5 10 30 94 E4 00 30 63 E2 04 60 A0 E1 24 30 87 E5 03 00 00 EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getdelim_fda112bef6038be216c05189a6147a43 {
	meta:
		aliases = "__GI_getdelim, getdelim"
		size = "340"
		objfiles = "getdelims@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 34 81 9F E5 00 00 51 E3 00 00 50 13 08 80 8F E0 14 D0 4D E2 00 A0 A0 E1 01 70 A0 E1 02 B0 A0 E1 03 50 A0 E1 01 00 00 0A 00 00 53 E3 04 00 00 1A ?? ?? ?? ?? 00 50 E0 E3 16 30 A0 E3 00 30 80 E5 3A 00 00 EA 34 90 93 E5 00 00 59 E3 0B 00 00 1A 38 40 83 E2 E4 30 9F E5 0D 00 A0 E1 03 10 98 E7 04 20 A0 E1 D8 30 9F E5 0F E0 A0 E1 03 F0 98 E7 04 00 A0 E1 CC 30 9F E5 0F E0 A0 E1 03 F0 98 E7 00 40 9A E5 01 60 A0 E3 00 00 54 E3 00 40 87 05 00 10 97 E5 01 00 56 E1 0A 00 00 3A 04 00 A0 E1 40 10 81 E2 ?? ?? ?? ?? 00 00 50 E3 00 40 A0 E1 00 50 E0 03 16 00 00 0A 00 30 97 E5 00 00 8A E5 40 30 83 E2 }
	condition:
		$pattern
}

rule fclose_c72c075fb9468809c3be50e211799063 {
	meta:
		aliases = "__GI_fclose, fclose"
		size = "400"
		objfiles = "fcloses@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 34 90 90 E5 60 61 9F E5 00 00 59 E3 2C D0 4D E2 00 50 A0 E1 06 60 8F E0 0B 00 00 1A 4C 31 9F E5 38 40 80 E2 03 10 96 E7 18 00 8D E2 40 31 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 30 31 9F E5 0F E0 A0 E1 03 F0 96 E7 B0 30 D5 E1 40 00 13 E2 01 00 00 0A 05 00 A0 E1 ?? ?? ?? ?? 00 A0 A0 E1 04 00 95 E5 ?? ?? ?? ?? FC 30 9F E5 08 80 8D E2 03 30 96 E7 00 00 50 E3 04 30 8D E5 F4 30 9F E5 04 10 9D E5 03 70 96 E7 00 30 E0 E3 04 30 85 E5 D8 30 9F E5 07 20 A0 E1 03 30 96 E7 08 00 A0 E1 00 30 8D E5 00 A0 E0 B3 33 FF 2F E1 C0 30 9F E5 07 00 A0 E1 03 B0 96 E7 3B FF 2F E1 B8 30 9F E5 }
	condition:
		$pattern
}

rule putspent_4b3caed811f51c14fa98fb1b75fc2622 {
	meta:
		aliases = "putspent"
		size = "340"
		objfiles = "putspents@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 34 B0 91 E5 1C 51 9F E5 00 00 5B E3 14 D0 4D E2 01 60 A0 E1 05 50 8F E0 00 70 A0 E1 0B 00 00 1A 04 31 9F E5 38 40 81 E2 0D 00 A0 E1 03 10 95 E7 04 20 A0 E1 F4 30 9F E5 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 E8 30 9F E5 0F E0 A0 E1 03 F0 95 E7 0C 00 97 E8 00 00 53 E3 D8 30 9F 05 03 30 85 00 D4 10 9F E5 06 00 A0 E1 01 10 85 E0 ?? ?? ?? ?? 00 00 50 E3 20 00 00 BA C0 30 9F E5 00 40 A0 E3 03 80 85 E0 B8 30 9F E5 03 A0 88 E2 03 90 85 E0 08 00 00 EA 04 30 D9 E7 01 40 84 E2 03 20 97 E7 01 00 72 E3 08 10 A0 11 0A 10 A0 01 ?? ?? ?? ?? 00 00 50 E3 10 00 00 BA 05 00 54 E3 06 00 A0 E1 F3 FF FF 9A }
	condition:
		$pattern
}

rule __read_etc_hosts_r_abddedaa3d91178fa2836edc9240227b {
	meta:
		aliases = "__read_etc_hosts_r"
		size = "848"
		objfiles = "read_etc_hosts_rs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 3C C3 9F E5 2C D0 4D E2 08 C0 8D E5 54 60 9D E5 08 E0 9D E5 00 C0 66 E2 0E E0 8F E0 03 C0 1C E2 08 E0 8D E5 10 20 8D E5 18 00 8D E5 14 10 8D E5 0C 30 8D E5 50 90 9D E5 58 20 9D E5 03 00 00 0A 0C 00 52 E1 BA 00 00 3A 02 20 6C E0 0C 60 86 E0 1F 00 52 E3 B6 00 00 9A 0C 00 9D E5 20 10 86 E2 01 00 50 E3 24 10 8D E5 20 70 42 E2 27 00 00 0A 60 C0 9D E5 00 30 E0 E3 03 00 57 E3 00 30 8C E5 AB 00 00 9A 24 30 42 E2 07 00 53 E3 A8 00 00 9A 0F 00 57 E3 A6 00 00 9A 30 30 42 E2 07 00 53 E3 A3 00 00 9A 2C 70 42 E2 38 30 42 E2 07 00 53 E1 03 70 A0 31 2C 40 86 22 38 40 86 32 4F 00 57 E3 24 50 86 E2 }
	condition:
		$pattern
}

rule __udivmoddi4_159bf32399a2d90381e709c61a4a16b4 {
	meta:
		aliases = "__udivmoddi4"
		size = "1644"
		objfiles = "_udivmoddi4@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 3C D0 4D E2 54 46 9F E5 00 A0 A0 E3 00 B0 A0 E3 00 00 53 E3 04 40 8F E0 00 0C 8D E8 02 60 A0 E1 00 90 A0 E1 01 50 A0 E1 51 00 00 1A 01 00 52 E1 81 00 00 9A 01 08 52 E3 03 01 00 3A FF 34 E0 E3 03 00 52 E1 18 30 A0 83 10 30 A0 93 08 C0 A0 83 10 C0 A0 93 36 03 A0 E1 04 26 9F E5 02 10 94 E7 00 30 D1 E7 03 C0 5C E0 15 2C A0 11 20 30 6C 12 16 6C A0 11 39 53 82 11 26 88 A0 E1 08 10 A0 E1 05 00 A0 E1 19 9C A0 11 10 C0 8D E5 ?? ?? ?? ?? 08 10 A0 E1 14 00 8D E5 05 00 A0 E1 ?? ?? ?? ?? 06 78 A0 E1 14 20 9D E5 27 78 A0 E1 97 02 02 E0 29 38 A0 E1 01 48 83 E1 04 00 52 E1 08 00 00 9A 14 00 9D E5 }
	condition:
		$pattern
}

rule __GI_trunc_86d9907b2c50fa06f2ddc82003f00c58 {
	meta:
		aliases = "trunc, __GI_trunc"
		size = "220"
		objfiles = "s_truncs@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 41 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF 2F 43 E2 03 20 42 E2 00 A0 A0 E3 00 B0 A0 E3 0C D0 4D E2 13 00 52 E3 00 40 A0 E1 01 50 A0 E1 00 60 A0 E1 01 70 A0 E1 00 0C 8D E8 0A 80 A0 E1 0B 90 A0 E1 00 E0 A0 E1 0E 00 00 CA 00 00 52 E3 02 11 01 E2 00 A0 A0 B3 01 B0 A0 B1 0A 40 A0 B1 01 50 A0 B1 17 00 00 BA 68 30 9F E5 53 32 C5 E1 01 30 83 E1 04 30 8D E5 00 30 A0 E3 00 30 8D E5 30 00 9D E8 0F 00 00 EA 33 00 52 E3 07 00 00 DA 01 0B 52 E3 0B 00 00 1A 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 01 50 A0 E1 05 00 00 EA 14 20 42 E2 00 30 E0 E3 33 82 C0 E1 01 90 A0 E1 08 40 A0 E1 01 50 A0 E1 }
	condition:
		$pattern
}

rule __GI_vfwscanf_70ff872ecdf9c9a8ad0eef2c66fa9c31 {
	meta:
		aliases = "vfwscanf, __GI_vfwscanf"
		size = "1808"
		objfiles = "vfwscanfs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 45 DF 4D E2 28 60 8D E2 1C 00 8D E5 18 20 8D E5 00 30 E0 E3 01 50 A0 E1 06 00 A0 E1 00 10 A0 E3 24 20 A0 E3 4C 30 8D E5 ?? ?? ?? ?? 1C 00 9D E5 B4 16 9F E5 34 00 90 E5 01 10 8F E0 00 00 50 E3 20 00 8D E5 14 10 8D E5 0E 00 00 1A 1C 20 9D E5 98 36 9F E5 38 40 82 E2 03 10 91 E7 F4 00 8D E2 8C 36 9F E5 04 20 A0 E1 14 C0 9D E5 0F E0 A0 E1 03 F0 9C E7 04 00 A0 E1 78 36 9F E5 14 10 9D E5 0F E0 A0 E1 03 F0 91 E7 B4 40 8D E2 04 00 A0 E1 1C 10 9D E5 ?? ?? ?? ?? 14 20 9D E5 58 36 9F E5 41 0F 8D E2 03 30 82 E0 E0 30 8D E5 BC 30 9D E5 14 C0 9D E5 03 10 D3 E5 71 30 8D E2 0C 30 8D E5 10 00 8D E5 }
	condition:
		$pattern
}

rule fcloseall_91d6fcac919ba6f860d92886c9f801ea {
	meta:
		aliases = "fcloseall"
		size = "376"
		objfiles = "fclosealls@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 48 B1 9F E5 48 31 9F E5 0B B0 8F E0 03 30 9B E7 24 D0 4D E2 0C 30 8D E5 38 31 9F E5 10 50 8D E2 03 40 9B E7 30 31 9F E5 30 91 9F E5 04 20 A0 E1 03 80 9B E7 08 30 8D E5 0C 10 9D E5 05 00 A0 E1 38 FF 2F E1 09 70 9B E7 04 00 A0 E1 37 FF 2F E1 0C 31 9F E5 01 10 A0 E3 03 20 9B E7 04 A1 9F E5 00 30 92 E5 05 00 A0 E1 01 30 83 E0 00 30 82 E5 0A 60 9B E7 36 FF 2F E1 EC 30 9F E5 0C 10 9D E5 03 40 9B E7 05 00 A0 E1 04 20 A0 E1 38 FF 2F E1 04 00 A0 E1 37 FF 2F E1 D0 30 9F E5 05 00 A0 E1 03 30 9B E7 01 10 A0 E3 00 70 93 E5 36 FF 2F E1 08 30 9D E5 04 50 8D E5 00 50 A0 E3 00 30 8D E5 1C 00 00 EA }
	condition:
		$pattern
}

rule __parsegrent_a9afbb1be59cd33852700f6f4afa7d49 {
	meta:
		aliases = "__parsegrent"
		size = "356"
		objfiles = "__parsegrents@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 4C 81 9F E5 4C 31 9F E5 08 80 8F E0 00 50 A0 E3 0C D0 4D E2 00 70 A0 E1 00 B0 90 E5 01 40 A0 E1 03 90 88 E0 05 A0 A0 E1 01 00 55 E3 05 60 D9 E7 04 00 A0 E1 3A 10 A0 E3 01 50 85 E2 06 00 00 CA 06 40 87 E7 ?? ?? ?? ?? 00 00 50 E3 3D 00 00 0A 01 A0 C0 E4 00 40 A0 E1 F2 FF FF EA 0A 20 A0 E3 04 00 A0 E1 04 10 8D E2 ?? ?? ?? ?? 04 20 9D E5 06 00 87 E7 04 00 52 E1 32 00 00 0A 00 30 D2 E5 3A 00 53 E3 2F 00 00 1A 01 30 D2 E5 00 00 53 E3 01 00 A0 03 16 00 00 0A 2C 30 A0 E3 B8 E0 9F E5 00 30 C2 E5 01 00 A0 E3 00 C0 A0 E3 00 30 D2 E5 2C 00 53 E3 0B 00 00 1A 00 C0 C2 E5 01 30 F2 E5 01 00 80 E2 }
	condition:
		$pattern
}

rule __GI_statfs64_fd86dc4a564c1fe60556cb1a667eef3c {
	meta:
		aliases = "__GI_fstatfs64, statfs64, fstatfs64, __GI_statfs64"
		size = "192"
		objfiles = "fstatfs64s@libc.a, statfs64s@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 4C D0 4D E2 08 20 8D E2 01 B0 A0 E1 02 10 A0 E1 04 20 8D E5 ?? ?? ?? ?? 00 00 50 E3 00 00 E0 B3 23 00 00 BA 14 30 9D E5 0C E0 9D E5 03 40 A0 E1 00 50 A0 E3 10 40 8B E5 14 50 8B E5 20 40 9D E5 08 30 9D E5 10 10 9D E5 18 80 9D E5 1C 60 9D E5 00 50 A0 E3 2C A0 9D E5 28 40 8B E5 2C 50 8B E5 04 50 9D E5 00 20 A0 E3 30 C0 8B E2 08 40 8B E8 00 90 A0 E3 00 70 A0 E3 24 00 8D E2 08 10 8B E5 0C 20 8B E5 03 00 90 E8 18 80 8B E5 1C 90 8B E5 03 00 8C E8 20 60 8B E5 24 70 8B E5 38 A0 8B E5 40 00 8B E2 2C 10 85 E2 14 20 A0 E3 ?? ?? ?? ?? 00 00 A0 E3 4C D0 8D E2 F0 8F BD E8 }
	condition:
		$pattern
}

rule __psfs_do_numeric_327248bd115084763a95d0d585b0a896 {
	meta:
		aliases = "__psfs_do_numeric"
		size = "1392"
		objfiles = "__psfs_do_numerics@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 50 95 9F E5 50 35 9F E5 3C 20 90 E5 09 90 8F E0 03 30 89 E0 CC D0 4D E2 03 30 82 E0 01 00 52 E3 00 80 A0 E1 10 20 8D E5 01 40 A0 E1 01 70 53 E5 20 00 00 1A 24 35 9F E5 03 50 89 E0 04 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 03 00 00 BA 00 20 D5 E5 00 30 94 E5 03 00 52 E1 06 00 00 0A 04 00 A0 E1 ?? ?? ?? ?? F4 34 9F E5 03 30 89 E0 03 00 55 E1 10 00 00 9A 32 01 00 EA 01 60 F5 E5 00 00 56 E3 ED FF FF 1A 44 30 D8 E5 00 00 53 E3 2E 01 00 0A 34 30 98 E5 2C 00 98 E5 01 30 83 E2 34 30 88 E5 38 10 98 E5 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? ?? 06 00 A0 E1 25 01 00 EA 04 00 A0 E1 ?? ?? ?? ?? 00 30 94 E5 }
	condition:
		$pattern
}

rule __GI_statvfs_9c64959d12d230719bbf3e0c101d5bd0 {
	meta:
		aliases = "statvfs, fstatvfs, __GI_statvfs"
		size = "764"
		objfiles = "fstatvfss@libc.a, statvfss@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 52 DE 4D E2 04 D0 4D E2 01 40 A0 E1 13 1D 8D E2 04 10 81 E2 00 70 A0 E1 ?? ?? ?? ?? A0 62 9F E5 00 00 50 E3 06 60 8F E0 00 00 E0 B3 A1 00 00 BA CC 34 9D E5 D0 24 9D E5 D4 14 9D E5 D8 04 9D E5 DC C4 9D E5 08 30 84 E5 E0 34 9D E5 C8 E4 9D E5 20 30 84 E5 E8 34 9D E5 00 50 A0 E3 04 E0 84 E5 0C 20 84 E5 10 10 84 E5 14 00 84 E5 18 C0 84 E5 2C 30 84 E5 00 E0 84 E5 05 10 A0 E1 18 20 A0 E3 24 50 84 E5 30 00 84 E2 ?? ?? ?? ?? 18 30 94 E5 46 1E 8D E2 28 50 84 E5 1C 30 84 E5 07 00 A0 E1 08 10 81 E2 ?? ?? ?? ?? 05 00 50 E1 05 00 A0 B1 80 00 00 BA ?? ?? ?? ?? 08 32 9F E5 00 90 A0 E1 04 02 9F E5 }
	condition:
		$pattern
}

rule vsyslog_2c0576240cf37948742e553781e7e824 {
	meta:
		aliases = "__GI_vsyslog, vsyslog"
		size = "1052"
		objfiles = "syslogs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 53 DE 4D E2 0C D0 4D E2 49 4E 8D E2 08 40 84 E2 00 50 A0 E1 04 10 8D E5 00 20 8D E5 00 10 A0 E3 8C 20 A0 E3 04 00 A0 E1 98 73 9F E5 ?? ?? ?? ?? 94 33 9F E5 07 70 8F E0 03 30 87 E0 04 00 84 E2 98 34 8D E5 ?? ?? ?? ?? 01 2B 8D E2 04 10 A0 E1 0C 20 82 E2 0D 00 A0 E3 ?? ?? ?? ?? ?? ?? ?? ?? 68 43 9F E5 68 33 9F E5 00 90 A0 E1 04 40 87 E0 52 0E 8D E2 03 10 97 E7 04 20 A0 E1 04 00 80 E2 50 33 9F E5 00 B0 99 E5 0F E0 A0 E1 03 F0 97 E7 44 33 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 97 E7 38 33 9F E5 07 10 05 E2 03 20 97 E7 01 30 A0 E3 13 31 12 E0 B5 00 00 0A FF 2F C5 E3 03 20 C2 E3 00 00 52 E3 }
	condition:
		$pattern
}

rule _time_mktime_tzi_fee30a10861d5021a6b9c4bf5158b81f {
	meta:
		aliases = "_time_mktime_tzi"
		size = "808"
		objfiles = "_time_mktime_tzis@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 54 D0 4D E2 14 00 8D E5 20 A0 8D E2 02 B0 A0 E1 10 10 8D E5 2C 20 A0 E3 0A 00 A0 E1 14 10 9D E5 ?? ?? ?? ?? 28 30 DB E5 DC 72 9F E5 00 00 53 E3 40 30 8D 05 40 E0 9D E5 07 70 8F E0 00 00 5E E3 20 20 8A E2 1C E0 8D 05 04 00 00 0A 01 30 A0 C3 00 30 E0 D3 01 00 A0 E3 00 30 82 E5 1C 00 8D E5 14 40 9A E5 19 1E A0 E3 04 00 A0 E1 ?? ?? ?? ?? 10 60 9A E5 00 50 A0 E1 0C 10 A0 E3 06 00 A0 E1 18 50 8A E5 ?? ?? ?? ?? 0C 30 A0 E3 90 03 03 E0 19 8E A0 E3 95 08 02 E0 06 30 63 E0 04 40 80 E0 00 00 53 E3 04 20 62 E0 14 20 8A E5 01 20 42 B2 10 30 8A E5 14 20 8A B5 0C 30 83 B2 10 30 8A B5 14 30 9A E5 }
	condition:
		$pattern
}

rule __muldc3_acb3971ab28268d3ad6cb25debe4d595 {
	meta:
		aliases = "__muldc3"
		size = "2044"
		objfiles = "_muldc3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 54 D0 4D E2 80 A0 8D E2 00 0C 9A E8 0C 00 8D E8 88 70 8D E2 80 01 97 E8 03 10 A0 E1 00 90 A0 E1 0B 30 A0 E1 02 00 A0 E1 0A 20 A0 E1 ?? ?? ?? ?? 07 20 A0 E1 20 00 8D E5 24 10 8D E5 78 00 8D E2 03 00 90 E8 08 30 A0 E1 ?? ?? ?? ?? 07 20 A0 E1 28 00 8D E5 2C 10 8D E5 03 00 9D E8 08 30 A0 E1 ?? ?? ?? ?? 0A 20 A0 E1 30 00 8D E5 34 10 8D E5 78 00 8D E2 03 00 90 E8 0B 30 A0 E1 ?? ?? ?? ?? 28 20 8D E2 0C 00 92 E8 38 00 8D E5 3C 10 8D E5 20 00 8D E2 03 00 90 E8 ?? ?? ?? ?? 38 20 8D E2 0C 00 92 E8 40 00 8D E5 44 10 8D E5 30 00 8D E2 03 00 90 E8 ?? ?? ?? ?? 48 00 8D E5 4C 10 8D E5 40 00 8D E2 }
	condition:
		$pattern
}

rule fstatvfs64_5b389548dc0b00359bab6192fdab1573 {
	meta:
		aliases = "statvfs64, fstatvfs64"
		size = "812"
		objfiles = "statvfs64s@libc.a, fstatvfs64s@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 55 DE 4D E2 0C D0 4D E2 01 70 A0 E1 4E 1E 8D E2 00 90 A0 E1 ?? ?? ?? ?? D4 82 9F E5 00 00 50 E3 08 80 8F E0 00 00 E0 B3 AE 00 00 BA 10 35 9D E5 E4 24 9D E5 38 30 87 E5 18 35 9D E5 00 A0 A0 E3 44 30 87 E5 E8 34 9D E5 EC 44 9D E5 08 30 87 E5 0C 40 87 E5 4F 3E 8D E2 18 00 93 E8 F8 54 9D E5 FC 64 9D E5 10 30 87 E5 14 40 87 E5 05 3C 8D E2 18 00 93 E8 04 20 87 E5 00 20 87 E5 3C A0 87 E5 08 15 9D E5 0C 25 9D E5 48 00 87 E2 28 10 87 E5 2C 20 87 E5 20 30 87 E5 24 40 87 E5 0A 10 A0 E1 18 20 A0 E3 18 50 87 E5 1C 60 87 E5 ?? ?? ?? ?? 28 30 87 E2 18 00 93 E8 47 1E 8D E2 30 30 87 E5 34 40 87 E5 }
	condition:
		$pattern
}

rule _vfprintf_internal_aa2f92b2cc4e8b9e189dcab53911b879 {
	meta:
		aliases = "_vfprintf_internal"
		size = "1608"
		objfiles = "_vfprintf_internals@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 55 DF 4D E2 28 60 8D E2 00 B0 A0 E1 06 00 A0 E1 01 40 A0 E1 02 50 A0 E1 ?? ?? ?? ?? 08 16 9F E5 00 00 50 E3 01 10 8F E0 20 10 8D E5 0A 00 00 AA 28 40 9D E5 04 00 A0 E1 ?? ?? ?? ?? 00 10 50 E2 74 01 00 0A 04 00 A0 E1 0B 20 A0 E1 ?? ?? ?? ?? 00 30 E0 E3 24 30 8D E5 70 01 00 EA 05 10 A0 E1 06 00 A0 E1 ?? ?? ?? ?? 20 10 9D E5 BC 35 9F E5 BC C5 9F E5 03 30 81 E0 1C 30 8D E5 B4 35 9F E5 0C C0 8D E5 03 30 81 E0 18 30 8D E5 A8 35 9F E5 04 20 A0 E1 03 30 81 E0 14 30 8D E5 9C 35 9F E5 03 30 81 E0 10 30 8D E5 00 30 A0 E3 24 30 8D E5 00 30 D4 E5 00 00 53 E3 25 00 53 13 00 00 A0 03 01 00 A0 13 }
	condition:
		$pattern
}

rule __GI_getttyent_4f998745a47db9cc9b9445bedc578ec9 {
	meta:
		aliases = "getttyent, __GI_getttyent"
		size = "924"
		objfiles = "getttyents@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 58 53 9F E5 58 33 9F E5 05 50 8F E0 03 30 95 E7 14 D0 4D E2 00 00 53 E3 03 00 00 1A ?? ?? ?? ?? 00 00 50 E3 00 40 A0 01 C9 00 00 0A 34 43 9F E5 04 30 95 E7 00 00 53 E3 05 00 00 1A 01 0A A0 E3 ?? ?? ?? ?? 00 00 50 E3 04 00 85 E7 00 00 00 1A ?? ?? ?? ?? 08 43 9F E5 0C 33 9F E5 04 20 95 E7 03 10 95 E7 38 20 82 E2 0D 00 A0 E1 FC 32 9F E5 0F E0 A0 E1 03 F0 95 E7 04 00 95 E7 F0 32 9F E5 38 00 80 E2 0F E0 A0 E1 03 F0 95 E7 D4 82 9F E5 E0 72 9F E5 04 60 A0 E1 08 40 95 E7 01 1A A0 E3 04 00 A0 E1 06 20 95 E7 ?? ?? ?? ?? 00 00 50 E3 00 40 A0 01 A1 00 00 0A 04 00 A0 E1 0A 10 A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _dl_load_shared_library_a0414710e95e6107b6b15bbd68242fce {
	meta:
		aliases = "_dl_load_shared_library"
		size = "640"
		objfiles = "libdls@libdl.a"
	strings:
		$pattern = { F0 4F 2D E9 58 92 9F E5 58 C2 9F E5 09 90 8F E0 0C C0 99 E7 03 E0 A0 E1 00 30 A0 E3 00 30 8C E5 0C D0 4D E2 00 70 A0 E1 01 80 A0 E1 02 50 A0 E1 01 30 4E E2 01 20 F3 E5 00 00 52 E3 FC FF FF 1A 03 30 6E E0 01 0B 53 E3 02 00 A0 91 01 30 4E 92 02 00 00 9A 74 00 00 EA 2F 00 52 E3 03 00 A0 01 01 20 F3 E5 00 00 52 E3 FA FF FF 1A 00 00 50 E3 0E 40 A0 01 01 40 80 12 0E 00 54 E1 05 00 00 0A 0E 20 A0 E1 07 00 A0 E1 08 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 70 00 00 1A 00 00 55 E3 0A 00 00 0A 7C 30 95 E5 00 00 53 E3 07 00 00 0A 54 20 95 E5 04 00 A0 E1 02 20 83 E0 07 10 A0 E1 08 30 A0 E1 66 FF FF EB 00 00 50 E3 }
	condition:
		$pattern
}

rule cbrt_8e68c4d5c96015d10423c81f12df6f25 {
	meta:
		aliases = "__GI_cbrt, cbrt"
		size = "664"
		objfiles = "s_cbrts@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 5C 32 9F E5 02 21 C1 E3 14 D0 4D E2 00 80 A0 E3 00 90 A0 E3 02 41 01 E2 03 00 52 E1 00 60 A0 E1 01 70 A0 E1 01 50 A0 E1 00 03 8D E8 0C 40 8D E5 05 00 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 00 60 A0 E1 01 70 A0 E1 81 00 00 EA 00 30 A0 E1 03 30 92 E1 01 40 A0 E1 7D 00 00 0A 01 06 52 E3 02 40 A0 E1 00 A0 A0 E1 02 B0 A0 E1 10 00 00 AA 04 30 A0 E1 06 20 A0 E1 00 00 A0 E3 E4 11 9F E5 ?? ?? ?? ?? 00 50 A0 E1 01 00 A0 E1 03 10 A0 E3 ?? ?? ?? ?? 05 40 A0 E1 2A 54 80 E2 02 55 45 E2 87 5C 45 E2 6D 50 45 E2 04 80 A0 E1 05 90 A0 E1 09 00 00 EA 02 00 A0 E1 03 10 A0 E3 ?? ?? ?? ?? 2B 44 80 E2 }
	condition:
		$pattern
}

rule fork_6a76ed08432049577d0a56b17f2ea358 {
	meta:
		aliases = "__fork, fork"
		size = "412"
		objfiles = "ptforks@libpthread.a"
	strings:
		$pattern = { F0 4F 2D E9 5C 51 9F E5 5C 31 9F E5 05 50 8F E0 58 41 9F E5 03 90 85 E0 04 40 85 E0 0C D0 4D E2 09 00 A0 E1 34 FF 2F E1 44 31 9F E5 03 00 95 E7 40 31 9F E5 03 B0 95 E7 3C 31 9F E5 03 60 95 E7 E5 FF FF EB ?? ?? ?? ?? 30 31 9F E5 03 A0 95 E7 0A 00 A0 E1 34 FF 2F E1 24 31 9F E5 03 70 95 E7 07 00 A0 E1 34 FF 2F E1 ?? ?? ?? ?? 00 80 50 E2 2E 00 00 1A 0C 31 9F E5 03 60 95 E0 10 00 00 0A 04 40 8D E2 00 31 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 95 E7 F4 30 9F E5 08 10 A0 E1 04 00 A0 E1 0F E0 A0 E1 03 F0 95 E7 07 00 A0 E1 04 10 A0 E1 36 FF 2F E1 04 00 A0 E1 D4 30 9F E5 0F E0 A0 E1 03 F0 95 E7 0A 00 A0 E1 }
	condition:
		$pattern
}

rule strftime_6a2d2cfed564c5fdd5b5ac751028d132 {
	meta:
		aliases = "__GI_strftime, strftime"
		size = "1528"
		objfiles = "strftimes@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 5C D0 4D E2 20 10 8D E5 24 00 8D E5 00 10 A0 E3 03 00 A0 E1 02 50 A0 E1 1C 30 8D E5 ?? ?? ?? ?? BC 35 9F E5 BC 45 9F E5 03 00 50 E1 00 00 A0 C3 01 00 A0 D3 ?? ?? ?? ?? AC 35 9F E5 04 40 8F E0 03 30 84 E0 18 30 8D E5 A0 35 9F E5 40 00 8D E2 10 00 8D E5 03 30 84 E0 0C 30 8D E5 18 20 9D E5 10 30 9D E5 00 10 A0 E3 1A 20 82 E2 0B 30 83 E2 05 00 A0 E1 20 B0 9D E5 2C 10 8D E5 14 20 8D E5 08 30 8D E5 00 00 5B E3 52 01 00 0A 00 30 D0 E5 00 00 53 E3 0D 00 00 1A 2C C0 9D E5 00 00 5C E3 20 E0 9D 05 24 10 9D 05 0E 00 6B 00 00 C0 C1 05 49 01 00 0A 2C 20 9D E5 58 C0 8D E2 01 20 42 E2 02 31 8C E0 }
	condition:
		$pattern
}

rule xdrrec_create_09776f34186b2d85b6b3b58ddba2b17a {
	meta:
		aliases = "__GI_xdrrec_create, xdrrec_create"
		size = "300"
		objfiles = "xdr_recs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 63 00 51 E3 04 D0 4D E2 01 40 A0 E1 00 80 A0 E1 FA 4E A0 93 44 00 A0 E3 63 00 52 E3 02 50 A0 E1 03 A0 A0 E1 FA 5E A0 93 28 90 9D E5 2C B0 9D E5 ?? ?? ?? ?? 03 40 84 E2 03 70 C4 E3 03 50 85 E2 00 60 A0 E1 03 50 C5 E3 04 00 87 E2 05 00 80 E0 ?? ?? ?? ?? BC C0 9F E5 00 00 50 E3 00 00 56 13 00 40 A0 E1 0C C0 8F E0 0B 00 00 1A A8 30 9F E5 A8 00 9F E5 03 30 9C E7 00 00 8C E0 00 10 93 E5 ?? ?? ?? ?? 06 00 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 04 D0 8D E2 F0 4F BD E8 ?? ?? ?? ?? 03 30 10 E2 04 30 63 12 03 40 80 10 74 20 9F E5 07 10 84 E0 04 00 86 E5 01 E0 85 E0 02 20 8C E0 04 00 84 E2 00 C0 A0 E3 }
	condition:
		$pattern
}

rule __GI_atan_aa3a4d830f15a594e93841f8a748b8ac {
	meta:
		aliases = "atan, __GI_atan"
		size = "1288"
		objfiles = "s_atans@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 64 24 9F E5 64 34 9F E5 02 61 C1 E3 0C D0 4D E2 03 00 56 E1 02 20 8F E0 04 20 8D E5 00 80 A0 E1 01 90 A0 E1 01 40 A0 E1 01 B0 A0 E1 15 00 00 DA 3C 34 9F E5 00 40 A0 E1 03 00 56 E1 01 50 A0 E1 06 00 00 CA 00 30 A0 13 01 30 A0 03 00 00 50 E3 00 30 A0 03 01 30 03 12 00 00 53 E3 03 00 00 0A 08 20 A0 E1 09 30 A0 E1 ?? ?? ?? ?? F8 00 00 EA 00 00 51 E3 FC 83 9F D5 FC 93 9F D5 F4 83 9F C5 F8 93 9F C5 F4 00 00 EA F4 33 9F E5 03 00 56 E1 0B 00 00 CA 6F 37 43 E2 03 00 56 E1 5C 00 00 CA E0 23 9F E5 E0 33 9F E5 ?? ?? ?? ?? 00 20 A0 E3 D8 33 9F E5 ?? ?? ?? ?? 00 00 50 E3 E6 00 00 1A 53 00 00 EA }
	condition:
		$pattern
}

rule __GI_erfc_86ae8b518cd5613b34edd76f3a818eaf {
	meta:
		aliases = "erfc, __GI_erfc"
		size = "2888"
		objfiles = "s_erfs@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 64 39 9F E5 02 61 C1 E3 1C D0 4D E2 03 00 56 E1 00 80 A0 E1 01 90 A0 E1 00 40 A0 E1 01 50 A0 E1 01 A0 A0 E1 04 10 8D E5 0E 00 00 DA A1 0F A0 E1 80 00 A0 E1 ?? ?? ?? ?? 08 20 A0 E1 00 40 A0 E1 01 50 A0 E1 09 30 A0 E1 00 00 A0 E3 1C 19 9F E5 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 01 01 00 EA 04 39 9F E5 03 00 56 E1 7F 00 00 CA FC 38 9F E5 03 00 56 E1 00 20 A0 D1 01 30 A0 D1 60 00 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? E0 28 9F E5 E0 38 9F E5 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? ?? D4 28 9F E5 D4 38 9F E5 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 }
	condition:
		$pattern
}

rule gethostbyname_r_77f204f9343acfb2dde52d71a51633f3 {
	meta:
		aliases = "__GI_gethostbyname_r, gethostbyname_r"
		size = "920"
		objfiles = "gethostbyname_rs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 64 D0 4D E2 68 B3 9F E5 02 70 A0 E1 88 20 9D E5 00 00 50 E3 00 60 A0 E3 14 00 8D E5 0B B0 8F E0 01 A0 A0 E1 03 40 A0 E1 00 60 82 E5 16 00 A0 03 CD 00 00 0A ?? ?? ?? ?? 88 C0 9D E5 00 80 90 E5 00 60 80 E5 04 C0 8D E5 8C C0 9D E5 00 50 A0 E1 02 10 A0 E3 14 00 9D E5 0A 20 A0 E1 07 30 A0 E1 00 40 8D E5 08 C0 8D E5 ?? ?? ?? ?? 00 00 50 E3 BD 00 00 0A 8C 20 9D E5 00 30 92 E5 01 00 53 E3 06 00 00 0A 04 00 53 E3 04 00 00 0A 01 00 73 E3 B5 00 00 1A 00 30 95 E5 02 00 53 E3 B2 00 00 1A 00 30 67 E2 03 30 13 E2 00 80 85 E5 03 00 00 0A 03 00 54 E1 AB 00 00 3A 04 40 63 E0 03 70 87 E0 8C 30 9D E5 }
	condition:
		$pattern
}

rule inet_ntop_5cac38aacec0ce28fc7ff2458e43a4ef {
	meta:
		aliases = "__GI_inet_ntop, inet_ntop"
		size = "640"
		objfiles = "ntops@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 68 52 9F E5 5C D0 4D E2 02 00 50 E3 05 50 8F E0 01 80 A0 E1 04 20 8D E5 00 30 8D E5 02 00 00 0A 0A 00 50 E3 8A 00 00 1A 04 00 00 EA 01 00 A0 E1 00 20 9D E5 04 10 9D E5 94 FF FF EB 82 00 00 EA 38 00 8D E2 00 10 A0 E3 20 20 A0 E3 ?? ?? ?? ?? 00 00 A0 E3 08 30 80 E0 00 10 D8 E7 01 20 D3 E5 A0 3F 80 E0 01 24 82 E1 C3 30 A0 E1 02 00 80 E2 58 10 8D E2 03 31 81 E0 0F 00 50 E3 20 20 03 E5 F3 FF FF DA 00 60 E0 E3 00 10 A0 E3 06 20 A0 E1 06 C0 A0 E1 01 00 A0 E3 13 00 00 EA 58 E0 8D E2 01 31 8E E0 20 30 13 E5 00 00 53 E3 04 00 00 1A 01 00 72 E3 01 20 A0 01 00 40 A0 01 01 40 84 12 08 00 00 EA }
	condition:
		$pattern
}

rule gethostbyname2_r_cd4e4f993638456e908475df9b02c058 {
	meta:
		aliases = "__GI_gethostbyname2_r, gethostbyname2_r"
		size = "920"
		objfiles = "gethostbyname2_rs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 6C B3 9F E5 7C D0 4D E2 02 00 51 E3 0B B0 8F E0 01 40 A0 E1 02 60 A0 E1 03 70 A0 E1 00 A0 A0 E1 A0 90 9D E5 08 00 00 1A A4 C0 9D E5 02 10 A0 E1 00 C0 8D E5 A8 C0 9D E5 03 20 A0 E1 09 30 A0 E1 04 C0 8D E5 ?? ?? ?? ?? C7 00 00 EA 0A 00 51 E3 C2 00 00 1A ?? ?? ?? ?? A4 20 9D E5 00 80 A0 E3 00 00 5A E3 00 80 82 E5 BC 00 00 0A ?? ?? ?? ?? A4 C0 9D E5 00 30 90 E5 00 80 80 E5 04 C0 8D E5 A8 C0 9D E5 34 30 8D E5 00 50 A0 E1 04 10 A0 E1 0A 00 A0 E1 06 20 A0 E1 07 30 A0 E1 00 90 8D E5 08 C0 8D E5 ?? ?? ?? ?? 00 00 50 E3 AE 00 00 0A A8 20 9D E5 00 30 92 E5 01 00 53 E3 04 00 00 0A 04 00 53 E3 }
	condition:
		$pattern
}

rule strptime_8189f3d391240a1258844d3ccd2fe951 {
	meta:
		aliases = "__GI_strptime, strptime"
		size = "1168"
		objfiles = "strptimes@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 70 34 9F E5 74 D0 4D E2 03 30 8F E0 00 70 A0 E1 1C 20 8D E5 01 00 A0 E1 00 20 A0 E3 02 C1 A0 E3 18 30 8D E5 70 10 8D E2 02 31 81 E0 01 20 82 E2 0C 00 52 E3 4C C0 03 E5 F9 FF FF DA 38 34 9F E5 18 10 9D E5 34 24 9F E5 03 30 81 E0 14 20 8D E5 10 30 8D E5 3A 20 83 E2 00 60 A0 E1 68 30 8D E2 6C 00 8D E2 00 90 A0 E3 0C 20 8D E5 09 00 8D E9 00 30 D6 E5 00 00 53 E3 15 00 00 1A 00 00 59 E3 0E 00 00 1A 3C 30 9D E5 09 20 A0 E1 07 00 53 E3 3C 90 8D 05 70 10 8D E2 02 31 81 E0 4C 30 13 E5 02 01 53 E3 1C 00 9D 15 02 31 80 17 01 20 82 E2 07 00 52 E3 F6 FF FF DA 07 00 A0 E1 EB 00 00 EA 01 90 49 E2 }
	condition:
		$pattern
}

rule authunix_create_4858d6f079b9daa14a411e5b40686223 {
	meta:
		aliases = "__GI_authunix_create, authunix_create"
		size = "384"
		objfiles = "auth_unixs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 75 DF 4D E2 04 00 8D E5 28 00 A0 E3 01 A0 A0 E1 02 90 A0 E1 03 B0 A0 E1 ?? ?? ?? ?? 00 50 A0 E1 1B 0E A0 E3 ?? ?? ?? ?? 38 71 9F E5 00 00 50 E3 00 00 55 13 00 40 A0 E1 00 60 A0 13 01 60 A0 03 07 70 8F E0 0B 00 00 1A 1C 31 9F E5 1C 01 9F E5 03 30 97 E7 00 00 87 E0 00 10 93 E5 ?? ?? ?? ?? 05 00 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 ?? ?? ?? ?? 00 50 A0 E3 38 00 00 EA F4 30 9F E5 F4 20 9F E5 03 30 87 E0 02 20 97 E7 20 30 85 E5 24 00 85 E5 0C 30 80 E2 0C C0 85 E2 07 00 92 E8 07 00 83 E8 07 00 8C E8 06 10 A0 E1 18 60 84 E5 72 0F 8D E2 ?? ?? ?? ?? C8 C1 9D E5 08 30 8D E2 B0 C1 8D E5 04 C0 9D E5 }
	condition:
		$pattern
}

rule __pgsreader_bd41db777b17583a9bb756a81045a269 {
	meta:
		aliases = "__pgsreader"
		size = "416"
		objfiles = "__pgsreaders@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 78 61 9F E5 24 D0 4D E2 FF 00 53 E3 06 60 8F E0 03 70 A0 E1 0C 00 8D E5 01 90 A0 E1 02 50 A0 E1 48 80 9D E5 04 00 00 8A ?? ?? ?? ?? 22 30 A0 E3 03 40 A0 E1 00 30 80 E5 4D 00 00 EA 34 B0 98 E5 00 00 5B E3 07 00 00 0A 34 31 9F E5 34 11 9F E5 03 30 86 E0 00 40 A0 E3 07 A0 85 E0 08 10 8D E5 04 30 8D E5 0C 00 00 EA 1C 31 9F E5 38 40 88 E2 03 10 96 E7 10 00 8D E2 04 20 A0 E1 0C 31 9F E5 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 00 31 9F E5 0F E0 A0 E1 03 F0 96 E7 EA FF FF EA 05 00 A0 E1 07 10 A0 E1 08 20 A0 E1 ?? ?? ?? ?? 00 00 50 E3 04 00 00 1A B0 30 D8 E1 04 00 13 E3 22 40 A0 03 02 40 A0 13 }
	condition:
		$pattern
}

rule __ieee754_asin_b86bb9a911e599b9fe03be0943c2f049 {
	meta:
		aliases = "__ieee754_asin"
		size = "1544"
		objfiles = "e_asins@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 7C 35 9F E5 02 41 C1 E3 1C D0 4D E2 03 00 54 E1 00 80 A0 E1 01 90 A0 E1 0C 10 8D E5 1C 00 00 DA 03 21 84 E2 01 26 82 E2 00 20 92 E1 01 40 A0 E1 0E 00 00 1A 4C 25 9F E5 4C 35 9F E5 ?? ?? ?? ?? 48 25 9F E5 00 40 A0 E1 01 50 A0 E1 40 35 9F E5 08 00 A0 E1 09 10 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 05 10 A0 E1 76 00 00 EA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 00 80 A0 E1 01 90 A0 E1 37 01 00 EA FC 34 9F E5 03 00 54 E1 6C 00 00 CA F9 05 54 E3 08 00 00 AA EC 24 9F E5 EC 34 9F E5 ?? ?? ?? ?? 00 20 A0 E3 E4 34 9F E5 ?? ?? ?? ?? 00 00 50 E3 }
	condition:
		$pattern
}

rule vfscanf_77c25c4bf58beef571fdd345850e4cf3 {
	meta:
		aliases = "__GI_vfscanf, vfscanf"
		size = "1748"
		objfiles = "vfscanfs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 81 DF 4D E2 12 6E 8D E2 14 00 8D E5 10 20 8D E5 00 30 E0 E3 01 50 A0 E1 06 00 A0 E1 00 10 A0 E3 24 20 A0 E3 44 31 8D E5 ?? ?? ?? ?? 14 00 9D E5 78 96 9F E5 34 00 90 E5 09 90 8F E0 00 00 50 E3 1C 00 8D E5 0C 00 00 1A 14 10 9D E5 60 36 9F E5 38 40 81 E2 7B 0F 8D E2 03 10 99 E7 04 20 A0 E1 50 36 9F E5 0F E0 A0 E1 03 F0 99 E7 04 00 A0 E1 44 36 9F E5 0F E0 A0 E1 03 F0 99 E7 6B 4F 8D E2 04 00 A0 E1 14 10 9D E5 ?? ?? ?? ?? 2C 36 9F E5 00 20 A0 E3 03 30 89 E0 D8 31 8D E5 B4 31 9D E5 01 70 A0 E3 03 30 D3 E5 14 C6 9F E5 5A 1F 8D E2 C4 31 CD E5 DC 31 9D E5 7F 0F 8D E2 01 10 81 E2 02 A0 A0 E1 }
	condition:
		$pattern
}

rule __wcstofpmax_7f0f0f25d62edb048a9a3ab15cb0c483 {
	meta:
		aliases = "__wcstofpmax"
		size = "936"
		objfiles = "__wcstofpmaxs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 84 33 9F E5 1C D0 4D E2 03 30 8F E0 02 B0 A0 E1 00 60 A0 E1 0C 00 8D E5 04 30 8D E5 08 10 8D E5 00 00 00 EA 04 60 86 E2 00 00 96 E5 ?? ?? ?? ?? 00 00 50 E3 FA FF FF 1A 00 30 96 E5 2B 00 53 E3 05 00 00 0A 2D 00 53 E3 01 10 A0 03 14 00 8D 15 14 10 8D 05 01 00 00 0A 01 00 00 EA 14 00 8D E5 04 60 86 E2 24 23 9F E5 00 30 A0 E3 00 70 A0 E3 00 80 A0 E3 00 A0 E0 E3 00 20 8D E5 10 30 8D E5 19 00 00 EA 00 00 5A E3 01 A0 8A B2 00 00 5A E3 07 00 A0 E1 08 10 A0 E1 00 20 A0 E3 F0 32 9F E5 04 60 86 E2 01 00 00 1A 30 00 59 E3 0E 00 00 0A 01 A0 8A E2 11 00 5A E3 0B 00 00 CA ?? ?? ?? ?? 00 40 A0 E1 }
	condition:
		$pattern
}

rule gethostbyaddr_r_6e6bf7a39cde90cfadc37ebc1a21ca73 {
	meta:
		aliases = "__GI_gethostbyaddr_r, gethostbyaddr_r"
		size = "1020"
		objfiles = "gethostbyaddr_rs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 84 D0 4D E2 C0 93 9F E5 30 20 8D E5 B0 20 9D E5 00 40 50 E2 00 00 A0 E3 09 90 8F E0 01 80 A0 E1 03 A0 A0 E1 00 00 82 E5 A8 70 9D E5 AC 50 9D E5 E0 00 00 0A 00 10 A0 E1 28 20 A0 E3 44 00 8D E2 ?? ?? ?? ?? 30 30 9D E5 02 00 53 E3 02 00 00 0A 0A 00 53 E3 D7 00 00 1A 01 00 00 EA 04 00 58 E3 00 00 00 EA 10 00 58 E3 D2 00 00 1A B0 C0 9D E5 04 00 A0 E1 08 C0 8D E5 B4 C0 9D E5 08 10 A0 E1 30 20 9D E5 0A 30 A0 E1 00 70 8D E5 04 50 8D E5 0C C0 8D E5 ?? ?? ?? ?? 00 00 50 E3 C8 00 00 0A B4 20 9D E5 00 30 92 E5 01 00 53 E3 01 00 00 0A 04 00 53 E3 C2 00 00 1A ?? ?? ?? ?? B4 C0 9D E5 00 30 E0 E3 }
	condition:
		$pattern
}

rule __gen_tempname_bd9c90b2876cf955a6bbbbed467e4316 {
	meta:
		aliases = "__gen_tempname"
		size = "772"
		objfiles = "tempnames@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 8C D0 4D E2 10 10 8D E5 00 A0 A0 E1 ?? ?? ?? ?? 00 B0 A0 E1 0A 00 A0 E1 ?? ?? ?? ?? BC 42 9F E5 00 10 9B E5 05 00 50 E3 04 40 8F E0 1C 10 8D E5 16 00 00 9A 00 30 8A E0 A4 12 9F E5 06 30 43 E2 14 30 8D E5 01 10 84 E0 03 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 0D 00 00 1A 88 32 9F E5 18 00 8D E5 03 30 84 E0 00 30 8D E5 7C 32 9F E5 03 30 84 E0 0C 30 8D E5 74 32 9F E5 03 30 84 E0 08 30 8D E5 6C 32 9F E5 03 40 84 E0 04 40 8D E5 88 00 00 EA 00 00 E0 E3 16 30 A0 E3 8B 00 00 EA 0C 00 9D E5 00 10 A0 E3 ?? ?? ?? ?? 00 50 50 E2 04 00 00 AA 00 00 9D E5 02 1B A0 E3 ?? ?? ?? ?? 00 50 50 E2 08 00 00 BA }
	condition:
		$pattern
}

rule _vfwprintf_internal_c89c18b9e3397c74e10b927b771af630 {
	meta:
		aliases = "_vfwprintf_internal"
		size = "1808"
		objfiles = "_vfwprintf_internals@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 9B DF 4D E2 01 50 A0 E1 00 B0 A0 E1 00 10 A0 E3 02 60 A0 E1 4A 0F 8D E2 98 20 A0 E3 ?? ?? ?? ?? 40 C1 9D E5 9A 1F 8D E2 00 E0 A0 E3 01 C0 4C E2 04 50 21 E5 00 20 E0 E3 95 3F 8D E2 40 C1 8D E5 0E 00 A0 E1 80 C0 A0 E3 38 C1 8D E5 28 51 8D E5 54 E2 8D E5 ?? ?? ?? ?? 90 16 9F E5 01 00 70 E3 01 10 8F E0 20 10 8D E5 09 30 A0 13 15 2E 8D 12 08 10 A0 13 78 36 9F 05 03 30 81 00 28 31 8D 05 20 00 00 0A 01 30 53 E2 04 10 82 E4 FC FF FF 1A 05 20 A0 E1 4A 4F 8D E2 0C 00 00 EA 25 00 53 E3 09 00 00 1A 04 30 B2 E5 04 00 A0 E1 25 00 53 E3 05 00 00 0A 28 21 8D E5 ?? ?? ?? ?? 00 00 50 E3 10 00 00 BA }
	condition:
		$pattern
}

rule unwind_phase2_forced_fc5d485e87d92e3da98612bec08ad0ef {
	meta:
		aliases = "unwind_phase2_forced"
		size = "324"
		objfiles = "unwind_arm@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 9B DF 4D E2 4F 8F 8D E2 04 E0 81 E2 08 C0 A0 E1 00 50 A0 E1 02 40 A0 E1 0F 00 BE E8 0F 00 AC E8 0F 00 BE E8 0F 00 AC E8 0F 00 BE E8 0F 00 AC E8 00 70 A0 E3 0F 00 9E E8 0C 90 95 E5 18 A0 95 E5 0F 00 8C E8 05 00 A0 E1 78 11 9D E5 38 71 8D E5 63 FF FF EB 07 00 54 E1 07 40 A0 11 00 60 A0 E1 4E BF 8D 12 0A 70 87 12 01 00 00 1A 4E BF 8D E2 09 70 A0 E3 00 00 56 E3 70 31 9D 15 10 70 87 13 7C 31 8D 15 16 00 00 0A 00 B0 8D E5 04 A0 8D E5 07 10 A0 E1 01 00 A0 E3 05 20 A0 E1 05 30 A0 E1 39 FF 2F E1 00 00 50 E3 09 00 00 1A 00 00 56 E3 08 00 00 1A 0B 00 A0 E1 08 10 8D E2 13 2E A0 E3 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __res_querydomain_0a67f426a81f15b9e83f41817d53f574 {
	meta:
		aliases = "__GI___res_querydomain, __res_querydomain"
		size = "460"
		objfiles = "res_querys@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 9C 71 9F E5 9C C1 9F E5 07 70 8F E0 42 DE 4D E2 0C 40 97 E7 04 D0 4D E2 02 90 A0 E1 88 21 9F E5 41 5E 8D E2 00 60 A0 E1 01 80 A0 E1 05 00 A0 E1 02 10 97 E7 03 A0 A0 E1 04 20 A0 E1 6C 31 9F E5 48 B4 9D E5 0F E0 A0 E1 03 F0 97 E7 04 00 A0 E1 5C 31 9F E5 0F E0 A0 E1 03 F0 97 E7 54 31 9F E5 05 00 A0 E1 03 30 97 E7 01 10 A0 E3 08 40 93 E5 44 31 9F E5 0F E0 A0 E1 03 F0 97 E7 00 00 5B E3 00 00 56 13 04 00 00 0A 01 00 14 E3 06 00 00 1A ?? ?? ?? ?? 01 00 70 E3 03 00 00 1A ?? ?? ?? ?? 00 30 E0 E3 03 20 A0 E1 0A 00 00 EA 00 00 58 E3 1B 00 00 1A 06 00 A0 E1 ?? ?? ?? ?? FC 30 9F E5 01 20 80 E2 }
	condition:
		$pattern
}

rule __GI_fnmatch_78c74b9a2c93cc2627b1863cf7004042 {
	meta:
		aliases = "fnmatch, __GI_fnmatch"
		size = "1584"
		objfiles = "fnmatch_olds@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 A2 30 A0 E1 14 76 9F E5 01 30 23 E2 2C D0 4D E2 02 80 A0 E1 01 30 03 E2 10 60 02 E2 00 B6 9F E5 01 20 02 E2 FC 95 9F E5 08 30 8D E5 10 20 8D E5 04 30 08 E2 02 20 08 E2 07 70 8F E0 01 50 A0 E1 18 10 8D E5 0C 30 8D E5 04 20 8D E5 63 01 00 EA 00 00 56 E3 1C 60 8D E5 09 00 00 0A 80 00 1C E3 07 00 00 1A 0B 30 97 E7 8C E0 A0 E1 00 30 93 E5 BE 30 93 E1 01 00 13 E3 09 30 97 17 00 30 93 15 0E C0 D3 17 3F 00 5C E3 01 00 80 E2 08 00 00 0A 02 00 00 8A 2A 00 5C E3 3E 01 00 1A 3E 00 00 EA 5B 00 5C E3 97 00 00 0A 5C 00 5C E3 39 01 00 1A 15 00 00 EA 00 30 D5 E5 00 00 53 E3 52 01 00 0A 10 20 9D E5 }
	condition:
		$pattern
}

rule clnt_broadcast_d4dddf3337cf971cbba9e9bc9bcc36b6 {
	meta:
		aliases = "clnt_broadcast"
		size = "1676"
		objfiles = "pmap_rmts@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 A5 DD 4D E2 14 D0 4D E2 40 10 8D E5 3C 20 8D E5 38 30 8D E5 44 00 8D E5 ?? ?? ?? ?? 01 40 A0 E3 02 3A 8D E2 00 B0 A0 E1 02 00 A0 E3 00 10 A0 E1 11 20 A0 E3 48 49 83 E5 ?? ?? ?? ?? 00 A6 9F E5 00 80 50 E2 0A A0 8F E0 F8 05 9F B5 02 40 84 B2 23 01 00 BA A5 3D 8D E2 04 C0 A0 E3 04 10 A0 E1 06 20 A0 E3 08 30 83 E2 00 C0 8D E5 ?? ?? ?? ?? 00 00 50 E3 D0 05 9F B5 03 40 A0 B3 18 01 00 BA 29 EC 8D E2 C4 35 9F E5 90 C0 8D E2 34 C0 4C E2 B0 44 CE E1 29 2C 8D E2 02 EA 8D E2 08 00 A0 E1 AC 15 9F E5 34 20 82 E2 34 39 8E E5 38 C9 8E E5 3C 89 8E E5 ?? ?? ?? ?? 00 00 50 E3 05 00 00 AA 90 05 9F E5 }
	condition:
		$pattern
}

rule __parsespent_1bc5f678ec0afa7ea22df8eb57cbd979 {
	meta:
		aliases = "__parsespent"
		size = "188"
		objfiles = "__parsespents@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 A8 20 9F E5 A8 30 9F E5 0C D0 4D E2 02 20 8F E0 00 70 A0 E3 03 B0 82 E0 00 60 A0 E1 01 50 A0 E1 04 90 8D E2 00 A0 E0 E3 07 80 A0 E1 01 00 57 E3 05 00 A0 E1 3A 10 A0 E3 07 40 DB E7 04 00 00 CA 04 50 86 E7 ?? ?? ?? ?? 00 30 50 E2 10 00 00 1A 13 00 00 EA 05 00 A0 E1 09 10 A0 E1 0A 20 A0 E3 ?? ?? ?? ?? 04 30 9D E5 04 00 86 E7 05 00 53 E1 04 A0 86 07 08 00 57 E3 00 00 D3 E5 02 00 00 1A 00 00 50 E3 07 00 00 0A 05 00 00 EA 3A 00 50 E3 03 00 00 1A 01 80 C3 E4 03 50 A0 E1 01 70 87 E2 E1 FF FF EA 16 00 A0 E3 0C D0 8D E2 F0 8F BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __ieee754_lgamma_r_635fda014fe25741b8fc2e3b835e3510 {
	meta:
		aliases = "__ieee754_lgamma_r"
		size = "4592"
		objfiles = "e_lgamma_rs@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 A8 3F 9F E5 02 91 C1 E3 34 D0 4D E2 03 00 59 E1 01 30 A0 E3 00 A0 A0 E1 01 B0 A0 E1 00 40 A0 E1 01 50 A0 E1 20 10 8D E5 0C 20 8D E5 00 30 82 E5 03 00 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? D4 03 00 EA 04 40 99 E1 24 00 8D E5 A5 00 00 0A 5C 3F 9F E5 03 00 59 E1 0E 00 00 CA 20 20 9D E5 00 00 52 E3 06 00 00 AA 0C 40 9D E5 00 30 E0 E3 02 11 81 E2 00 30 84 E5 ?? ?? ?? ?? 18 00 8D E5 01 00 00 EA ?? ?? ?? ?? 18 00 8D E5 02 01 81 E2 1C 00 8D E5 C1 03 00 EA 20 40 9D E5 00 00 54 E3 00 20 A0 A3 00 30 A0 A3 10 20 8D A5 14 30 8D A5 AB 00 00 AA FC 3E 9F E5 03 00 59 E1 89 00 00 CA F4 3E 9F E5 }
	condition:
		$pattern
}

rule getpwuid_r_cb80679b9c2a42c3c9848a2db43a5993 {
	meta:
		aliases = "__GI_getgrgid_r, getgrgid_r, __GI_getpwuid_r, getpwuid_r"
		size = "196"
		objfiles = "getpwuid_rs@libc.a, getgrgid_rs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 A8 40 9F E5 0C D0 4D E2 30 B0 9D E5 00 90 A0 E1 01 60 A0 E1 98 00 9F E5 98 10 9F E5 04 40 8F E0 00 C0 A0 E3 00 C0 8B E5 00 00 84 E0 01 10 84 E0 02 80 A0 E1 03 70 A0 E1 ?? ?? ?? ?? 00 50 50 E2 02 00 00 1A ?? ?? ?? ?? 00 40 90 E5 14 00 00 EA 01 30 A0 E3 34 30 85 E5 5C 30 9F E5 03 A0 84 E0 0A 00 A0 E1 06 10 A0 E1 08 20 A0 E1 07 30 A0 E1 00 50 8D E5 ?? ?? ?? ?? 00 40 50 E2 04 00 00 1A 08 30 96 E5 09 00 53 E1 F4 FF FF 1A 00 60 8B E5 01 00 00 EA 02 00 54 E3 00 40 A0 03 05 00 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 0C D0 8D E2 F0 8F BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __kernel_rem_pio2_143f4e48c9b6638a7cad519bf295391f {
	meta:
		aliases = "__kernel_rem_pio2"
		size = "2776"
		objfiles = "k_rem_pio2s@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 A8 4A 9F E5 9D DF 4D E2 18 40 8D E5 18 C0 9D E5 02 40 A0 E1 01 30 43 E2 94 2A 9F E5 0C C0 8F E0 24 30 8D E5 98 32 9D E5 02 20 8C E0 03 21 92 E7 20 00 8D E5 1C 10 8D E5 03 00 44 E2 18 10 A0 E3 18 C0 8D E5 28 20 8D E5 ?? ?? ?? ?? C0 0F C0 E1 01 20 80 E2 18 30 A0 E3 92 03 03 E0 24 C0 9D E5 34 00 8D E5 04 B0 63 E0 00 40 6C E0 28 00 9D E5 00 50 A0 E3 0C 80 80 E0 00 60 A0 E3 00 70 A0 E3 0C 00 00 EA 00 00 54 E3 06 00 A0 B1 07 10 A0 B1 02 00 00 BA 9C 12 9D E5 04 01 91 E7 ?? ?? ?? ?? 27 2E 8D E2 85 31 82 E0 F0 00 03 E5 EC 10 03 E5 01 50 85 E2 01 40 84 E2 08 00 55 E1 F0 FF FF DA 00 70 A0 E3 }
	condition:
		$pattern
}

rule _stdlib_strto_l_32671f587d05512dc933ff7e79774263 {
	meta:
		aliases = "_stdlib_strto_l"
		size = "444"
		objfiles = "_stdlib_strto_ls@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 A8 C1 9F E5 A8 E1 9F E5 0C D0 4D E2 0C C0 8F E0 01 B0 A0 E1 02 50 A0 E1 00 40 A0 E1 04 30 8D E5 00 00 00 EA 01 40 84 E2 00 10 D4 E5 0E 20 9C E7 81 30 A0 E1 B2 30 93 E1 20 30 13 E2 F8 FF FF 1A 2B 00 51 E3 04 00 00 0A 2D 00 51 E3 03 70 A0 11 01 70 A0 03 01 00 00 0A 01 00 00 EA 03 70 A0 E1 01 40 84 E2 10 30 D5 E3 00 60 A0 11 0E 00 00 1A 00 30 D4 E5 0A 50 85 E2 30 00 53 E3 00 60 A0 11 07 00 00 1A 01 30 F4 E5 02 50 45 E2 20 30 83 E3 78 00 53 E3 04 60 A0 01 04 60 A0 11 85 50 A0 01 01 40 84 02 10 00 55 E3 10 50 A0 A3 02 30 45 E2 22 00 53 E3 00 C0 A0 83 2A 00 00 8A 00 00 E0 E3 05 10 A0 E1 }
	condition:
		$pattern
}

rule sigwait_cfe9e92d188c2a1854b24f775821e2d1 {
	meta:
		aliases = "sigwait"
		size = "424"
		objfiles = "signalss@libpthread.a"
	strings:
		$pattern = { F0 4F 2D E9 AB DF 4D E2 89 4F 8D E2 0C 10 8D E5 00 70 A0 E1 3A FF FF EB 70 61 9F E5 70 51 9F E5 06 60 8F E0 00 30 A0 E1 04 00 A0 E1 A4 32 8D E5 ?? ?? ?? ?? 05 30 96 E7 04 00 A0 E1 00 10 93 E5 ?? ?? ?? ?? 4C 31 9F E5 4C 21 9F E5 04 30 8D E5 48 31 9F E5 04 B0 A0 E1 03 90 86 E0 40 31 9F E5 01 40 A0 E3 03 A0 86 E0 66 8F 8D E2 08 20 8D E5 20 00 00 EA ?? ?? ?? ?? 00 00 50 E3 1C 00 00 0A 08 20 9D E5 02 30 96 E7 00 30 93 E5 03 00 54 E1 17 00 00 0A 05 30 96 E7 00 30 93 E5 03 00 54 E1 13 00 00 0A 04 20 9D E5 04 10 A0 E1 02 30 96 E7 0B 00 A0 E1 00 30 93 E5 03 00 54 E1 0C 00 00 0A ?? ?? ?? ?? 04 31 99 E7 }
	condition:
		$pattern
}

rule __res_search_7951ccfc0e9abc1b05b08c89cbac250c {
	meta:
		aliases = "__res_search"
		size = "980"
		objfiles = "res_querys@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 AC 63 9F E5 AC C3 9F E5 06 60 8F E0 0C C0 96 E7 4C D0 4D E2 2C C0 8D E5 9C C3 9F E5 38 50 8D E2 0C 40 96 E7 00 A0 A0 E1 28 10 8D E5 24 20 8D E5 2C 10 9D E5 04 20 A0 E1 05 00 A0 E1 03 B0 A0 E1 78 33 9F E5 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 6C 33 9F E5 0F E0 A0 E1 03 F0 96 E7 64 33 9F E5 05 00 A0 E1 03 30 96 E7 01 10 A0 E3 08 40 93 E5 54 33 9F E5 0F E0 A0 E1 03 F0 96 E7 00 00 5B E3 00 00 5A 13 04 00 00 0A 01 00 14 E3 07 00 00 1A ?? ?? ?? ?? 01 00 70 E3 04 00 00 1A ?? ?? ?? ?? 00 30 E0 E3 03 20 A0 E1 00 30 80 E5 BD 00 00 EA ?? ?? ?? ?? 00 40 A0 E3 00 40 80 E5 30 00 8D E5 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _fpmaxtostr_15553a9fec3ea6797741b49ef024cd62 {
	meta:
		aliases = "_fpmaxtostr"
		size = "2028"
		objfiles = "_fpmaxtostrs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 AC D0 4D E2 D0 C0 9D E5 B8 17 9F E5 08 90 DC E5 08 10 8D E5 20 10 89 E3 61 00 51 E3 65 10 A0 E3 92 10 CD E5 D0 10 9D E5 00 B0 9C E5 08 E0 9D E5 03 60 A0 E1 02 50 A0 E1 06 30 89 02 0C 20 91 E5 FF 90 03 02 0C 00 8D E5 00 00 5B E3 04 00 9C E5 00 30 A0 E3 0E E0 8F E0 06 B0 A0 B3 02 00 12 E3 08 E0 8D E5 A2 30 CD E5 14 00 8D E5 2B 30 83 12 02 00 00 1A 01 00 12 E3 01 00 00 0A 20 30 A0 E3 A2 30 CD E5 00 C0 A0 E3 06 30 A0 E1 05 00 A0 E1 06 10 A0 E1 05 20 A0 E1 30 C0 8D E5 A3 C0 CD E5 ?? ?? ?? ?? 00 00 50 E3 08 30 A0 03 30 30 8D 05 2C 00 00 0A 05 00 A0 E1 06 10 A0 E1 00 20 A0 E3 00 30 A0 E3 }
	condition:
		$pattern
}

rule getpwnam_r_b0838366df674130d74bde9a535500ea {
	meta:
		aliases = "getgrnam_r, __GI_getgrnam_r, __GI_getspnam_r, __GI_getpwnam_r, getspnam_r, getpwnam_r"
		size = "204"
		objfiles = "getpwnam_rs@libc.a, getspnam_rs@libc.a, getgrnam_rs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 B0 40 9F E5 0C D0 4D E2 30 B0 9D E5 00 A0 A0 E1 01 60 A0 E1 A0 00 9F E5 A0 10 9F E5 04 40 8F E0 00 C0 A0 E3 00 C0 8B E5 00 00 84 E0 01 10 84 E0 02 80 A0 E1 03 70 A0 E1 ?? ?? ?? ?? 00 50 50 E2 02 00 00 1A ?? ?? ?? ?? 00 40 90 E5 16 00 00 EA 01 30 A0 E3 34 30 85 E5 64 30 9F E5 03 90 84 E0 06 10 A0 E1 08 20 A0 E1 07 30 A0 E1 09 00 A0 E1 00 50 8D E5 ?? ?? ?? ?? 00 40 50 E2 0A 10 A0 E1 05 00 00 1A 00 00 96 E5 ?? ?? ?? ?? 00 00 50 E3 F2 FF FF 1A 00 60 8B E5 01 00 00 EA 02 00 54 E3 00 40 A0 03 05 00 A0 E1 ?? ?? ?? ?? 04 00 A0 E1 0C D0 8D E2 F0 8F BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svcunix_create_e8d4ffed53cd4106309c0088a024d064 {
	meta:
		aliases = "svcunix_create"
		size = "472"
		objfiles = "svc_unixs@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 B0 71 9F E5 01 00 70 E3 7C D0 4D E2 00 60 A0 E1 10 00 A0 E3 07 70 8F E0 74 00 8D E5 01 B0 A0 E1 02 90 A0 E1 03 40 A0 E1 00 80 A0 13 0B 00 00 1A 01 00 A0 E3 00 10 A0 E1 00 20 A0 E3 ?? ?? ?? ?? 00 60 50 E2 01 80 A0 A3 04 00 00 AA 68 01 9F E5 00 50 A0 E3 00 00 87 E0 ?? ?? ?? ?? 52 00 00 EA 06 50 8D E2 00 10 A0 E3 6E 20 A0 E3 05 00 A0 E1 ?? ?? ?? ?? 01 30 A0 E3 B6 30 CD E1 04 00 A0 E1 ?? ?? ?? ?? 01 30 80 E2 03 20 A0 E1 04 10 A0 E1 02 00 85 E2 74 30 8D E5 ?? ?? ?? ?? 74 20 9D E5 78 40 8D E2 02 20 82 E2 04 20 24 E5 05 10 A0 E1 06 00 A0 E1 ?? ?? ?? ?? 06 00 A0 E1 05 10 A0 E1 04 20 A0 E1 }
	condition:
		$pattern
}

rule __GI_ioperm_cdcc43bae7b3419dc1f7badb7cc83bc0 {
	meta:
		aliases = "ioperm, __GI_ioperm"
		size = "760"
		objfiles = "ioperms@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 B4 62 9F E5 B4 32 9F E5 06 60 8F E0 03 50 86 E0 0C C0 95 E5 47 DF 4D E2 00 00 5C E3 00 90 A0 E1 01 B0 A0 E1 0C 20 8D E5 76 00 00 1A 04 30 A0 E3 46 4F 8D E2 88 02 9F E5 04 30 24 E5 03 20 85 E0 00 00 86 E0 03 10 A0 E3 04 30 A0 E1 04 C0 8D E5 00 C0 8D E5 ?? ?? ?? ?? 00 C0 50 E2 0B 00 00 1A 60 02 9F E5 04 30 A0 E1 00 00 86 E0 03 10 A0 E3 08 20 85 E2 04 C0 8D E5 00 C0 8D E5 ?? ?? ?? ?? 00 00 50 E3 01 30 A0 03 0C 30 85 05 5D 00 00 0A 34 02 9F E5 14 70 8D E2 00 00 86 E0 07 10 A0 E1 FF 20 A0 E3 ?? ?? ?? ?? 00 00 50 E3 18 00 00 DA 46 3F 8D E2 00 20 83 E0 00 30 A0 E3 04 31 42 E5 08 32 9F E5 }
	condition:
		$pattern
}

rule __ns_name_ntop_637e4231d8133e742483b52e1ac5d2aa {
	meta:
		aliases = "__GI___ns_name_ntop, __ns_name_ntop"
		size = "464"
		objfiles = "ns_names@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 BC C1 9F E5 BC 31 9F E5 0C C0 8F E0 04 D0 4D E2 01 70 A0 E1 03 B0 8C E0 02 80 81 E0 00 A0 A0 E1 01 50 A0 E1 4B 00 00 EA C0 00 13 E3 03 90 A0 E1 57 00 00 1A 07 00 55 E1 07 50 A0 01 03 00 00 0A 08 00 55 E1 52 00 00 2A 2E 20 A0 E3 01 20 C5 E4 03 30 85 E0 08 00 53 E1 4D 00 00 2A 01 A0 8A E2 3A 00 00 EA 00 60 DA E5 2E 00 56 E3 0A 00 00 0A 03 00 00 8A 22 00 56 E3 07 00 00 0A 24 00 56 E3 04 00 00 EA 40 00 56 E3 03 00 00 0A 5C 00 56 E3 01 00 00 0A 3B 00 56 E3 42 00 00 1A 01 30 85 E2 08 00 53 E1 3A 00 00 2A 5C 20 A0 E3 01 60 C5 E5 00 20 C5 E5 01 50 83 E2 22 00 00 EA 03 30 85 E2 08 00 53 E1 }
	condition:
		$pattern
}

rule _getopt_internal_a486e232af6f0de9fb834b0eab45a45b {
	meta:
		aliases = "_getopt_internal"
		size = "2352"
		objfiles = "getopts@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 D8 78 9F E5 D8 C8 9F E5 07 70 8F E0 0C E0 97 E7 D0 C8 9F E5 34 D0 4D E2 0C C0 97 E7 C8 48 9F E5 00 C0 9C E5 00 E0 9E E5 20 C0 8D E5 20 50 9D E5 04 C0 87 E0 04 50 8C E5 10 20 8D E5 04 E0 87 E7 02 50 A0 E1 00 20 D2 E5 01 A0 A0 E1 3A 00 52 E3 20 10 9D E5 00 10 A0 03 00 00 50 E3 20 10 8D E5 14 00 8D E5 03 90 A0 E1 0A 02 00 DA 00 30 A0 E3 00 00 5E E3 08 30 8C E5 01 30 A0 03 04 30 87 07 02 00 00 0A 10 30 9C E5 00 00 53 E3 22 00 00 1A 54 38 9F E5 54 08 9F E5 03 20 97 E7 03 40 87 E0 00 50 A0 E3 20 20 84 E5 24 20 84 E5 00 00 87 E0 1C 50 84 E5 ?? ?? ?? ?? 10 20 9D E5 05 00 50 E0 01 00 A0 13 }
	condition:
		$pattern
}

rule __GI_ttyname_r_4269f1103ff9193d76415ea519b57084 {
	meta:
		aliases = "ttyname_r, __GI_ttyname_r"
		size = "364"
		objfiles = "ttynames@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 DC D0 4D E2 01 B0 A0 E1 60 10 8D E2 02 90 A0 E1 00 50 A0 E1 ?? ?? ?? ?? 40 41 9F E5 00 00 50 E3 04 40 8F E0 02 00 00 AA ?? ?? ?? ?? 00 40 90 E5 47 00 00 EA 05 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 40 00 00 0A 18 31 9F E5 B8 70 8D E2 03 00 84 E0 08 30 8D E2 04 30 8D E5 37 00 00 EA 01 60 80 E2 06 10 A0 E1 07 00 A0 E1 ?? ?? ?? ?? 06 00 A0 E1 ?? ?? ?? ?? 00 50 50 E2 1E A0 64 E2 04 80 87 E0 22 00 00 1A 29 00 00 EA ?? ?? ?? ?? 0A 00 50 E1 1E 00 00 8A 04 10 A0 E1 08 00 A0 E1 ?? ?? ?? ?? 07 00 A0 E1 04 10 9D E5 ?? ?? ?? ?? 00 40 50 E2 16 00 00 1A 18 30 9D E5 0F 3A 03 E2 02 0A 53 E3 12 00 00 1A }
	condition:
		$pattern
}

rule getservbyport_r_0c01f4fc596c8a05eca1dbbc8e85818b {
	meta:
		aliases = "__GI_getservbyport_r, getservbyport_r"
		size = "264"
		objfiles = "getservices@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 E0 50 9F E5 E0 40 9F E5 05 50 8F E0 02 60 A0 E1 D8 20 9F E5 14 D0 4D E2 04 40 85 E0 00 A0 A0 E1 01 70 A0 E1 0D 00 A0 E1 02 10 95 E7 03 80 A0 E1 04 20 A0 E1 B8 30 9F E5 38 B0 9D E5 3C 90 9D E5 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 A4 30 9F E5 0F E0 A0 E1 03 F0 95 E7 9C 30 9F E5 03 00 95 E7 ?? ?? ?? ?? 08 00 00 EA 08 30 96 E5 0A 00 53 E1 05 00 00 1A 00 10 57 E2 0A 00 00 0A 0C 00 96 E5 ?? ?? ?? ?? 00 00 50 E3 06 00 00 0A 08 10 A0 E1 0B 20 A0 E1 09 30 A0 E1 06 00 A0 E1 ?? ?? ?? ?? 00 40 50 E2 EF FF FF 0A 4C 30 9F E5 03 30 95 E7 00 00 53 E3 00 00 00 1A ?? ?? ?? ?? 0D 00 A0 E1 01 10 A0 E3 }
	condition:
		$pattern
}

rule __ieee754_j1_c851ae7258a64e5ee40de40fa013ac75 {
	meta:
		aliases = "__ieee754_j1"
		size = "1112"
		objfiles = "e_j1s@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 E8 33 9F E5 02 21 C1 E3 14 D0 4D E2 03 00 52 E1 00 A0 A0 E1 01 B0 A0 E1 01 40 A0 E1 06 00 8D E8 05 00 00 DA 00 20 A0 E1 01 30 A0 E1 00 00 A0 E3 BC 13 9F E5 ?? ?? ?? ?? EA 00 00 EA 04 30 9D E5 07 01 73 E3 72 00 00 DA ?? ?? ?? ?? 00 A0 A0 E1 01 B0 A0 E1 ?? ?? ?? ?? 00 60 A0 E1 01 70 A0 E1 0A 00 A0 E1 0B 10 A0 E1 ?? ?? ?? ?? 00 40 A0 E1 01 50 A0 E1 04 20 A0 E1 05 30 A0 E1 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? ?? 68 33 9F E5 04 20 9D E5 00 80 A0 E1 03 00 52 E1 01 90 A0 E1 2A 00 00 CA 0A 20 A0 E1 0B 30 A0 E1 0A 00 A0 E1 0B 10 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? 04 20 A0 E1 08 00 8D E5 0C 10 8D E5 }
	condition:
		$pattern
}

rule __GI_expm1_1078b4da81d6d82108796e8c22eff2bd {
	meta:
		aliases = "expm1, __GI_expm1"
		size = "1676"
		objfiles = "s_expm1s@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 EC 35 9F E5 02 C1 C1 E3 03 00 5C E1 14 D0 4D E2 00 80 A0 E1 01 90 A0 E1 01 40 A0 E1 02 51 01 E2 27 00 00 9A CC 35 9F E5 03 00 5C E1 15 00 00 9A C4 35 9F E5 03 00 5C E1 09 00 00 9A FF 24 C1 E3 0F 26 C2 E3 00 20 92 E1 01 40 A0 E1 00 20 A0 11 01 30 A0 11 22 01 00 1A 00 00 55 E3 60 01 00 0A 14 00 00 EA 94 25 9F E5 94 35 9F E5 ?? ?? ?? ?? 00 00 50 E3 8C 05 9F 15 8C 15 9F 15 00 20 A0 11 01 30 A0 11 0A 01 00 1A 00 00 55 E3 2C 00 00 0A 78 25 9F E5 78 35 9F E5 08 00 A0 E1 09 10 A0 E1 ?? ?? ?? ?? 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? ?? 00 00 50 E3 1E 00 00 0A 58 95 9F E5 00 80 A0 E3 47 01 00 EA }
	condition:
		$pattern
}

rule __GI_fflush_unlocked_2792599065212b7a44149382a521ac23 {
	meta:
		aliases = "fflush_unlocked, __GI_fflush_unlocked"
		size = "544"
		objfiles = "fflush_unlockeds@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 EC 91 9F E5 EC 31 9F E5 09 90 8F E0 03 30 99 E7 00 B0 A0 E1 03 00 50 E1 2C D0 4D E2 00 B0 A0 03 14 B0 8D 05 03 00 00 0A 01 2C A0 E3 00 00 5B E3 14 20 8D E5 5E 00 00 1A BC 31 9F E5 BC 21 9F E5 03 30 99 E7 18 50 8D E2 10 30 8D E5 B0 31 9F E5 10 10 9D E5 03 40 99 E7 A8 31 9F E5 08 20 8D E5 03 80 99 E7 04 20 A0 E1 0C 30 8D E5 05 00 A0 E1 38 FF 2F E1 08 30 9D E5 04 00 A0 E1 03 70 99 E7 37 FF 2F E1 80 31 9F E5 01 10 A0 E3 03 20 99 E7 78 A1 9F E5 00 30 92 E5 0A 60 99 E7 01 30 83 E0 00 30 82 E5 05 00 A0 E1 36 FF 2F E1 60 31 9F E5 10 10 9D E5 03 40 99 E7 05 00 A0 E1 04 20 A0 E1 38 FF 2F E1 }
	condition:
		$pattern
}

rule __ieee754_sinh_e4fdb355aba7b4a1842b2a5061066925 {
	meta:
		aliases = "__ieee754_sinh"
		size = "560"
		objfiles = "e_sinhs@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 F0 31 9F E5 02 41 C1 E3 03 00 54 E1 04 D0 4D E2 00 50 A0 E1 01 60 A0 E1 03 00 00 DA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 6C 00 00 EA C8 31 9F E5 00 00 51 E3 00 A0 A0 B3 C0 B1 9F B5 00 A0 A0 A3 BC B1 9F A5 03 00 54 E1 41 00 00 CA B4 31 9F E5 03 00 54 E1 07 00 00 CA AC 21 9F E5 AC 31 9F E5 ?? ?? ?? ?? 00 20 A0 E3 A4 31 9F E5 ?? ?? ?? ?? 00 00 50 E3 5B 00 00 1A 05 00 A0 E1 06 10 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? 88 31 9F E5 00 80 A0 E1 03 00 54 E1 01 90 A0 E1 1B 00 00 CA 00 20 A0 E1 01 30 A0 E1 ?? ?? ?? ?? 08 20 A0 E1 00 60 A0 E1 01 70 A0 E1 09 30 A0 E1 08 00 A0 E1 09 10 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _time_tzset_9c24d31e6da986ac736281e356939104 {
	meta:
		aliases = "_time_tzset"
		size = "1340"
		objfiles = "tzsets@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 F0 64 9F E5 F0 34 9F E5 06 60 8F E0 AC D0 4D E2 03 40 96 E7 00 30 A0 E3 A4 30 8D E5 DC 34 9F E5 04 20 A0 E1 03 10 96 E7 00 90 A0 E1 D0 34 9F E5 94 00 8D E2 0F E0 A0 E1 03 F0 96 E7 04 00 A0 E1 C0 34 9F E5 0F E0 A0 E1 03 F0 96 E7 B8 04 9F E5 00 00 86 E0 ?? ?? ?? ?? 00 40 50 E2 1F 00 00 1A A8 04 9F E5 04 10 A0 E1 00 00 86 E0 ?? ?? ?? ?? 00 70 50 E2 17 00 00 BA 44 40 A0 E3 20 50 8D E2 05 10 A0 E1 04 20 A0 E1 07 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 0C 00 00 BA 02 00 00 0A 00 40 54 E0 00 50 85 E0 F5 FF FF 1A 20 00 8D E2 00 00 55 E1 05 00 00 9A 01 30 55 E5 0A 00 53 E3 00 30 A0 03 00 40 A0 01 }
	condition:
		$pattern
}

rule __md5_crypt_a85e4cf41452efc0fec0bb14612916fd {
	meta:
		aliases = "__md5_crypt"
		size = "784"
		objfiles = "md5s@libcrypt.a"
	strings:
		$pattern = { F0 4F 2D E9 F0 B2 9F E5 F0 32 9F E5 0B B0 8F E0 01 40 A0 E1 03 30 8B E0 D4 D0 4D E2 03 20 A0 E3 00 30 8D E5 00 A0 A0 E1 03 10 A0 E1 04 00 A0 E1 ?? ?? ?? ?? 00 00 50 E3 04 80 A0 11 03 80 84 02 08 40 A0 E1 08 20 88 E2 00 00 00 EA 01 40 84 E2 00 30 D4 E5 00 00 53 E3 24 00 53 13 01 00 00 0A 02 00 54 E1 F8 FF FF 3A 64 60 8D E2 06 00 A0 E1 03 FF FF EB 0A 00 A0 E1 ?? ?? ?? ?? 00 70 A0 E1 0A 10 A0 E1 06 00 A0 E1 07 20 A0 E1 8A FF FF EB 68 12 9F E5 04 90 68 E0 01 10 8B E0 06 00 A0 E1 03 20 A0 E3 0C 40 8D E2 83 FF FF EB 08 10 A0 E1 09 20 A0 E1 06 00 A0 E1 7F FF FF EB 04 00 A0 E1 EF FE FF EB 04 00 A0 E1 }
	condition:
		$pattern
}

rule __ieee754_rem_pio2_e23a24bc3dc13f2853ad00c048bc029d {
	meta:
		aliases = "__ieee754_rem_pio2"
		size = "1620"
		objfiles = "e_rem_pio2s@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 F4 35 9F E5 F4 B5 9F E5 02 A1 C1 E3 3C D0 4D E2 03 00 5A E1 1C 10 8D E5 08 20 8D E5 00 60 A0 E1 01 70 A0 E1 01 40 A0 E1 0B B0 8F E0 07 00 00 CA 00 C0 A0 E3 00 30 A0 E3 00 40 A0 E3 18 C0 8D E5 08 30 82 E5 0C 40 82 E5 C0 00 82 E8 67 01 00 EA AC 35 9F E5 03 00 5A E1 58 00 00 CA 1C E0 9D E5 00 00 5E E3 28 00 00 DA 98 35 9F E5 98 25 9F E5 ?? ?? ?? ?? 8C 35 9F E5 00 60 A0 E1 03 00 5A E1 01 70 A0 E1 0C 00 00 0A 80 25 9F E5 80 35 9F E5 ?? ?? ?? ?? 08 C0 9D E5 00 20 A0 E1 01 30 A0 E1 03 00 8C E8 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? ?? 58 25 9F E5 58 35 9F E5 10 00 00 EA 54 25 9F E5 4C 35 9F E5 }
	condition:
		$pattern
}

rule getprotobyname_r_0a43edbc964530ae8c9f79d9984a5f37 {
	meta:
		aliases = "__GI_getprotobyname_r, getprotobyname_r"
		size = "284"
		objfiles = "getprotos@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 F4 50 9F E5 F4 40 9F E5 05 50 8F E0 02 90 A0 E1 EC 20 9F E5 14 D0 4D E2 04 40 85 E0 00 70 A0 E1 01 60 A0 E1 0D 00 A0 E1 02 10 95 E7 03 A0 A0 E1 04 20 A0 E1 CC 30 9F E5 38 B0 9D E5 0F E0 A0 E1 03 F0 95 E7 04 00 A0 E1 BC 30 9F E5 0F E0 A0 E1 03 F0 95 E7 B4 30 9F E5 03 00 95 E7 ?? ?? ?? ?? 0E 00 00 EA 00 00 96 E5 07 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 10 00 00 0A 04 40 96 E5 04 00 00 EA 07 10 A0 E1 ?? ?? ?? ?? 00 00 50 E3 0A 00 00 0A 04 40 84 E2 00 00 94 E5 00 00 50 E3 F7 FF FF 1A 06 00 A0 E1 09 10 A0 E1 0A 20 A0 E1 0B 30 A0 E1 ?? ?? ?? ?? 00 80 50 E2 E9 FF FF 0A 4C 30 9F E5 03 30 95 E7 }
	condition:
		$pattern
}

rule free_2f2024808b90dac60fbbae2fdd818d85 {
	meta:
		aliases = "free"
		size = "288"
		objfiles = "frees@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 F8 60 9F E5 00 40 50 E2 04 D0 4D E2 06 60 8F E0 38 00 00 0A E8 30 9F E5 04 50 14 E5 03 80 96 E7 E0 30 9F E5 08 00 A0 E1 03 90 96 E7 39 FF 2F E1 D4 30 9F E5 04 40 44 E2 03 B0 96 E7 05 20 A0 E1 04 10 A0 E1 0B 00 A0 E1 ?? ?? ?? ?? BC 30 9F E5 00 A0 90 E5 03 30 96 E7 00 50 A0 E1 00 30 93 E5 83 01 5A E1 0C 00 00 3A A4 30 9F E5 0C 40 80 E2 03 70 96 E7 07 00 A0 E1 39 FF 2F E1 00 00 A0 E3 ?? ?? ?? ?? 00 00 54 E1 05 00 00 0A 07 00 A0 E1 80 30 9F E5 0F E0 A0 E1 03 F0 96 E7 08 00 A0 E1 11 00 00 EA 04 20 95 E5 04 00 95 E5 00 00 52 E3 08 30 95 15 08 30 82 15 08 30 95 E5 00 00 53 E3 04 00 83 15 }
	condition:
		$pattern
}

rule __ieee754_exp_ebd7d04ea5a6b6760b77ab8b25ddc792 {
	meta:
		aliases = "__ieee754_exp"
		size = "1160"
		objfiles = "e_exps@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 FC 33 9F E5 FC 73 9F E5 02 C1 C1 E3 03 00 5C E1 07 70 8F E0 14 D0 4D E2 00 80 A0 E1 01 90 A0 E1 01 40 A0 E1 A1 6F A0 E1 1F 00 00 9A D8 33 9F E5 03 00 5C E1 09 00 00 9A FF 24 C1 E3 0F 26 C2 E3 00 20 92 E1 01 40 A0 E1 00 20 A0 11 01 30 A0 11 60 00 00 1A 00 00 56 E3 E5 00 00 0A 0F 00 00 EA A8 23 9F E5 A8 33 9F E5 ?? ?? ?? ?? 00 00 50 E3 A0 03 9F 15 A0 13 9F 15 00 20 A0 11 01 30 A0 11 D8 00 00 1A 08 00 A0 E1 09 10 A0 E1 8C 23 9F E5 8C 33 9F E5 ?? ?? ?? ?? 00 00 50 E3 18 00 00 0A 00 80 A0 E3 00 90 A0 E3 D1 00 00 EA 74 33 9F E5 03 00 5C E1 38 00 00 9A 6C 33 9F E5 03 00 5C E1 0F 00 00 8A }
	condition:
		$pattern
}

rule __GI_getnetent_99d740d0fd5419bc527bdb00595e12f4 {
	meta:
		aliases = "getnetent, __GI_getnetent"
		size = "580"
		objfiles = "getnetents@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 FC 61 9F E5 FC 41 9F E5 06 60 8F E0 F8 31 9F E5 14 D0 4D E2 04 40 86 E0 03 10 96 E7 04 20 A0 E1 0D 00 A0 E1 E4 31 9F E5 E4 51 9F E5 0F E0 A0 E1 03 F0 96 E7 DC 31 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 96 E7 05 30 96 E7 00 00 53 E3 07 00 00 1A C4 01 9F E5 C4 11 9F E5 00 00 86 E0 01 10 86 E0 ?? ?? ?? ?? 00 00 50 E3 05 00 86 E7 5B 00 00 0A AC 31 9F E5 AC 71 9F E5 03 90 86 E0 A8 31 9F E5 A8 B1 9F E5 03 A0 86 E0 00 80 A0 E3 07 30 96 E7 00 00 53 E3 05 00 00 1A 94 01 9F E5 ?? ?? ?? ?? 00 00 50 E3 07 00 86 E7 00 00 00 1A ?? ?? ?? ?? 07 00 96 E7 01 1A A0 E3 05 20 96 E7 ?? ?? ?? ?? 00 40 50 E2 }
	condition:
		$pattern
}

rule __GI_getaddrinfo_7dc4eb2c80403ea13ca621633b0e7dbf {
	meta:
		aliases = "getaddrinfo, __GI_getaddrinfo"
		size = "784"
		objfiles = "getaddrinfos@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 FC 72 9F E5 44 D0 4D E2 00 80 50 E2 00 00 A0 E3 07 70 8F E0 3C 00 8D E5 01 50 A0 E1 02 60 A0 E1 00 30 8D E5 05 00 00 0A 00 30 D8 E5 2A 00 53 E3 02 00 00 1A 01 30 D8 E5 00 00 53 E1 00 80 A0 01 00 00 55 E3 05 00 00 0A 00 30 D5 E5 2A 00 53 E3 02 00 00 1A 01 30 D5 E5 00 00 53 E3 00 50 A0 03 05 20 98 E1 A1 00 00 0A 00 00 56 E3 05 00 00 1A 10 40 8D E2 06 10 A0 E1 04 00 A0 E1 20 20 A0 E3 ?? ?? ?? ?? 04 60 A0 E1 00 20 96 E5 43 3E C2 E3 0F 30 C3 E3 00 00 53 E3 96 00 00 1A 01 30 78 E2 00 30 A0 33 A2 20 13 E0 92 00 00 1A 00 00 55 E3 1E 00 00 0A 00 30 D5 E5 00 00 53 E3 1B 00 00 0A 05 00 A0 E1 }
	condition:
		$pattern
}

rule __GI_getnameinfo_5ef0f09acac83dbbfbf4c229cb000183 {
	meta:
		aliases = "getnameinfo, __GI_getnameinfo"
		size = "796"
		objfiles = "getnameinfos@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 FC C2 9F E5 A9 DF 4D E2 01 40 A0 E1 02 A0 A0 E1 04 C0 8D E5 00 70 A0 E1 03 80 A0 E1 ?? ?? ?? ?? 08 00 8D E5 06 00 9D E9 D0 92 9D E5 00 20 92 E5 1F 00 D9 E3 01 10 8F E0 04 10 8D E5 14 20 8D E5 00 00 E0 13 AC 00 00 1A 00 00 57 E3 01 00 54 13 A8 00 00 9A B0 20 D7 E1 01 00 52 E3 07 00 00 0A 02 00 52 E3 01 00 00 1A 0F 00 54 E3 02 00 00 EA 0A 00 52 E3 9F 00 00 1A 1B 00 54 E3 9D 00 00 9A 00 30 5A E2 01 30 A0 13 00 C0 58 E2 01 C0 A0 13 0C 00 13 E1 0C 30 8D E5 10 C0 8D E5 5B 00 00 0A 02 00 52 E3 04 00 00 0A 0A 00 52 E3 02 00 00 0A 01 00 52 E3 55 00 00 1A 3F 00 00 EA 01 00 19 E3 2C 00 00 1A }
	condition:
		$pattern
}

rule __dns_lookup_c9291ea905188d0b55e60e09279a55d1 {
	meta:
		aliases = "__dns_lookup"
		size = "2104"
		objfiles = "dnslookups@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 FC D0 4D E2 3C 00 8D E5 02 0C A0 E3 38 10 8D E5 34 20 8D E5 30 30 8D E5 24 B1 9D E5 ?? ?? ?? ?? 00 A0 A0 E1 D0 07 9F E5 ?? ?? ?? ?? CC 87 9F E5 00 00 50 E3 00 00 5A 13 2C 00 8D E5 00 00 A0 13 01 00 A0 03 28 00 8D E5 08 80 8F E0 BD 01 00 0A 34 10 9D E5 00 00 51 E3 BA 01 00 0A 3C 20 9D E5 00 30 D2 E5 00 00 53 E3 B6 01 00 0A 02 00 A0 E1 ?? ?? ?? ?? 3C 30 9D E5 84 47 9F E5 00 00 83 E0 80 37 9F E5 04 40 88 E0 03 30 98 E7 D4 50 8D E2 40 30 8D E5 01 30 50 E5 6C 07 9F E5 2E 00 53 E3 00 30 A0 13 01 30 A0 03 24 00 8D E5 04 20 A0 E1 40 10 9D E5 05 00 A0 E1 58 30 8D E5 24 30 9D E5 0F E0 A0 E1 }
	condition:
		$pattern
}

rule inet_ntoa_r_9b804334698d43c7f9a789dc4d912945 {
	meta:
		aliases = "__GI_inet_ntoa_r, inet_ntoa_r"
		size = "136"
		objfiles = "inet_ntoas@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 FF 28 00 E2 20 3C A0 E1 22 34 83 E1 FF 2C 00 E2 00 50 A0 E3 02 34 83 E1 0C D0 4D E2 00 4C 83 E1 0F 10 81 E2 05 60 A0 E1 FF 70 A0 E3 00 80 A0 E3 09 B0 E0 E3 05 90 A0 E1 2E A0 A0 E3 06 00 00 EA 00 B0 8D E5 04 90 8D E5 ?? ?? ?? ?? 00 00 56 E3 01 10 40 E2 00 A0 C6 15 01 60 A0 E1 03 00 55 E3 04 20 07 E0 01 00 A0 E1 00 30 A0 E3 24 44 A0 E1 01 50 85 E2 F1 FF FF DA 01 00 81 E2 0C D0 8D E2 F0 8F BD E8 }
	condition:
		$pattern
}

rule __GI___fpclassify_f166c658b00396f156035f96947dd2e0 {
	meta:
		aliases = "__fpclassify, __GI___fpclassify"
		size = "84"
		objfiles = "s_fpclassifys@libm.a"
	strings:
		$pattern = { FF 24 C1 E3 44 C0 9F E5 0F 26 C2 E3 00 00 82 E1 0C C0 01 E0 0C 30 90 E1 10 40 2D E9 02 00 A0 03 01 40 A0 E1 10 80 BD 08 00 00 5C E3 03 00 A0 03 10 80 BD 08 14 30 9F E5 03 00 5C E1 04 00 A0 13 10 80 BD 18 01 00 70 E2 00 00 A0 33 10 80 BD E8 00 00 F0 7F }
	condition:
		$pattern
}

rule __GI_inet_netof_d5dff5463e0c402a65f071c7acb1639c {
	meta:
		aliases = "inet_netof, __GI_inet_netof"
		size = "52"
		objfiles = "inet_netofs@libc.a"
	strings:
		$pattern = { FF 28 00 E2 20 3C A0 E1 22 34 83 E1 FF 2C 00 E2 02 34 83 E1 00 0C 93 E1 20 0C A0 51 1E FF 2F 51 03 31 00 E2 02 01 53 E3 20 08 A0 01 20 04 A0 11 1E FF 2F E1 }
	condition:
		$pattern
}

rule inet_lnaof_4813647a0bb7e520bd51291a4daa6cc5 {
	meta:
		aliases = "inet_lnaof"
		size = "56"
		objfiles = "inet_lnaofs@libc.a"
	strings:
		$pattern = { FF 28 00 E2 20 3C A0 E1 22 34 83 E1 FF 2C 00 E2 02 34 83 E1 00 0C 93 E1 FF 04 C0 53 1E FF 2F 51 03 31 00 E2 02 01 53 E3 00 08 A0 01 20 08 A0 01 FF 00 00 12 1E FF 2F E1 }
	condition:
		$pattern
}

rule ustat_c37fdc1b40da83887da660880acbfd4e {
	meta:
		aliases = "ustat"
		size = "76"
		objfiles = "ustats@libc.a"
	strings:
		$pattern = { FF 30 00 E2 20 04 A0 E1 01 0C 80 E1 00 34 83 E1 03 38 A0 E1 B0 40 2D E9 02 10 A0 E1 23 08 A0 E1 3E 70 A0 E3 00 00 00 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? ?? 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 B0 80 BD E8 }
	condition:
		$pattern
}

rule __divsf3_de3e1c11ddabfc025197b61039f25186 {
	meta:
		aliases = "__aeabi_fdiv, __divsf3"
		size = "352"
		objfiles = "_muldivsf3@libgcc.a"
	strings:
		$pattern = { FF C0 A0 E3 A0 2B 1C E0 A1 3B 1C 10 0C 00 32 11 0C 00 33 11 3A 00 00 0A 03 20 42 E0 01 C0 20 E0 81 14 B0 E1 80 04 A0 E1 1C 00 00 0A 01 32 A0 E3 21 12 83 E1 20 32 83 E1 02 01 0C E2 01 00 53 E1 83 30 A0 31 7D 20 A2 E2 02 C5 A0 E3 01 00 53 E1 01 30 43 20 0C 00 80 21 A1 00 53 E1 A1 30 43 20 AC 00 80 21 21 01 53 E1 21 31 43 20 2C 01 80 21 A1 01 53 E1 A1 31 43 20 AC 01 80 21 03 32 B0 E1 2C C2 B0 11 F0 FF FF 1A FD 00 52 E3 9D FF FF 8A 01 00 53 E1 82 0B A0 E0 01 00 C0 03 1E FF 2F E1 02 C1 0C E2 A0 04 8C E1 7F 20 92 E2 FF 30 72 C2 82 0B 80 C1 1E FF 2F C1 02 05 80 E3 00 30 A0 E3 01 20 52 E2 8F FF FF EA }
	condition:
		$pattern
}

rule __aeabi_fmul_29e94953a23facf3a94623e07695cbbc {
	meta:
		aliases = "__mulsf3, __aeabi_fmul"
		size = "408"
		objfiles = "_muldivsf3@libgcc.a"
	strings:
		$pattern = { FF C0 A0 E3 A0 2B 1C E0 A1 3B 1C 10 0C 00 32 11 0C 00 33 11 3E 00 00 0A 03 20 82 E0 01 C0 20 E0 80 04 B0 E1 81 14 B0 11 10 00 00 0A 02 33 A0 E3 A0 02 83 E1 A1 12 83 E1 90 31 81 E0 02 01 0C E2 02 05 51 E3 81 10 A0 31 A3 1F 81 31 83 30 A0 31 01 00 80 E1 7F 20 C2 E2 FD 00 52 E3 0F 00 00 8A 02 01 53 E3 82 0B A0 E0 01 00 C0 03 1E FF 2F E1 00 00 30 E3 02 C1 0C E2 81 14 A0 01 A0 04 8C E1 A1 04 80 E1 7F 20 52 E2 FF 30 72 C2 82 0B 80 C1 1E FF 2F C1 02 05 80 E3 00 30 A0 E3 01 20 52 E2 35 00 00 CA 19 00 72 E3 02 01 00 D2 1E FF 2F D1 00 20 62 E2 80 10 B0 E1 31 12 A0 E1 20 20 62 E2 10 C2 A0 E1 61 00 B0 E1 }
	condition:
		$pattern
}

