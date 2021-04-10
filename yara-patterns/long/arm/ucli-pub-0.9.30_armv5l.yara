// YARA rules, version 0.1.1_2020_04_26

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

rule dyn_string_prepend_1ca868ecbb40d529392c04b89e6ca9d1 {
	meta:
		aliases = "dyn_string_prepend_cstr, dyn_string_prepend"
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
		objfiles = "strerror@libiberty.a, strsignal@libiberty.a"
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

rule init_error_tables_47d9d285c088b249efef9652bacd3c6d {
	meta:
		aliases = "init_signal_tables, init_error_tables"
		size = "386"
		objfiles = "strerror@libiberty.a, strsignal@libiberty.a"
	strings:
		$pattern = { ( CC | 55 ) 89 E5 57 56 53 83 EC 0C 8B 3D ?? ?? ?? ?? 85 FF 75 3D 8B 35 ?? ?? ?? ?? 85 F6 74 33 31 C9 31 D2 EB 0D 90 90 90 90 90 90 90 90 90 90 90 90 90 8B 82 ?? ?? ?? ?? 39 C8 7C 03 8D 48 01 8B 82 ?? ?? ?? ?? 83 C2 0C 85 C0 75 E6 89 0D ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 85 DB 0F 84 98 00 00 00 8B 0D ?? ?? ?? ?? 85 C9 74 08 83 C4 0C 5B 5E 5F 5D C3 A1 ?? ?? ?? ?? 8D 1C 85 00 00 00 00 89 1C 24 E8 ?? ?? ?? ?? 85 C0 A3 ?? ?? ?? ?? 74 DB 83 FB 07 89 C7 89 D8 76 0C F7 C7 04 00 00 00 0F 85 B9 00 00 00 89 C1 31 C0 8B 15 ?? ?? ?? ?? FC C1 E9 02 F3 AB 85 D2 A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 74 A8 8B 35 ?? ?? ?? ?? 31 DB }
	condition:
		$pattern
}

rule strtosigno_ab3aeed924bf497ecc467a649f6115cb {
	meta:
		aliases = "strtoerrno, strtosigno"
		size = "114"
		objfiles = "strerror@libiberty.a, strsignal@libiberty.a"
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
		objfiles = "strerror@libiberty.a, strsignal@libiberty.a"
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

rule pex_unix_pipe_d0a838e17f26e2f85d87f03e21452947 {
	meta:
		aliases = "pex_unix_close, pex_unix_pipe"
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

rule labs_982289527251259ce2e4944925414d59 {
	meta:
		aliases = "abs, labs"
		size = "12"
		objfiles = "labs@libc.a"
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

rule __ctzdi2_783696e5e00e37d2a045464128005b3e {
	meta:
		aliases = "__ctzdi2"
		size = "108"
		objfiles = "_ctzdi2@libgcc.a"
	strings:
		$pattern = { 00 00 50 E3 01 00 A0 01 00 30 60 E2 03 00 00 E0 00 10 A0 13 20 10 A0 03 01 08 50 E3 0B 00 00 2A FF 00 50 E3 00 C0 A0 93 08 C0 A0 83 0C 20 A0 91 0C 20 A0 81 30 22 A0 E1 28 30 9F E5 02 00 D3 E7 00 00 8C E0 01 00 40 E2 00 00 81 E0 0E F0 A0 E1 01 04 50 E3 10 C0 A0 33 18 C0 A0 23 0C 20 A0 31 0C 20 A0 21 F2 FF FF EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_mbsinit_2849e018bd148678449cb087855dceb9 {
	meta:
		aliases = "mbsinit, __GI_mbsinit"
		size = "32"
		objfiles = "mbsinit@libc.a"
	strings:
		$pattern = { 00 00 50 E3 01 30 A0 E3 02 00 00 0A 00 30 90 E5 01 30 73 E2 00 30 A0 33 03 00 A0 E1 0E F0 A0 E1 }
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

rule killpg_690251524c5865cf5d9a206be78aad3c {
	meta:
		aliases = "killpg"
		size = "44"
		objfiles = "killpg@libc.a"
	strings:
		$pattern = { 00 00 50 E3 04 E0 2D E5 00 00 60 E2 01 00 00 BA 04 E0 9D E4 ?? ?? ?? EA ?? ?? ?? EB 16 30 A0 E3 00 30 80 E5 00 00 E0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule __ffsdi2_c36b71ab5e359fd3a8c1ddd9b9f614d0 {
	meta:
		aliases = "__ffsdi2"
		size = "144"
		objfiles = "_ffsdi2@libgcc.a"
	strings:
		$pattern = { 00 00 50 E3 04 E0 2D E5 00 E0 A0 13 04 00 00 1A 00 00 51 E3 01 00 A0 01 04 F0 9D 04 01 00 A0 E1 20 E0 A0 E3 00 30 60 E2 03 00 00 E0 01 08 50 E3 0A 00 00 2A FF 00 50 E3 00 C0 A0 93 08 C0 A0 83 0C 10 A0 91 0C 10 A0 81 30 11 A0 E1 38 20 9F E5 01 30 D2 E7 03 30 8C E0 03 00 8E E0 04 F0 9D E4 01 04 50 E3 10 C0 A0 33 18 C0 A0 23 0C 10 A0 31 0C 10 A0 21 30 11 A0 E1 0C 20 9F E5 01 30 D2 E7 03 30 8C E0 03 00 8E E0 04 F0 9D E4 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __absvsi2_b0cb963d78245c44719cd21d8dfedf1d {
	meta:
		aliases = "__absvsi2"
		size = "28"
		objfiles = "_absvsi2@libgcc.a"
	strings:
		$pattern = { 00 00 50 E3 04 E0 2D E5 04 F0 9D A4 00 00 60 E2 00 00 50 E3 04 F0 9D A4 ?? ?? ?? EB }
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

rule __ffssi2_e42745e49dc01fb4094f87fe158b3ae2 {
	meta:
		aliases = "__ffssi2"
		size = "108"
		objfiles = "_ffssi2@libgcc.a"
	strings:
		$pattern = { 00 00 50 E3 0E F0 A0 01 00 30 60 E2 03 00 00 E0 01 08 50 E3 09 00 00 2A FF 00 50 E3 00 C0 A0 93 08 C0 A0 83 0C 30 A0 91 0C 30 A0 81 30 33 A0 E1 30 20 9F E5 03 10 D2 E7 01 00 8C E0 0E F0 A0 E1 01 04 50 E3 10 C0 A0 33 18 C0 A0 23 0C 30 A0 31 0C 30 A0 21 30 33 A0 E1 08 20 9F E5 03 10 D2 E7 01 00 8C E0 0E F0 A0 E1 ?? ?? ?? ?? }
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

rule __deregister_frame_info_bases_6dce36227d10368ee9dad2eeeb83b975 {
	meta:
		aliases = "__deregister_frame_info_bases"
		size = "220"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { 00 00 50 E3 10 40 2D E9 01 00 00 1A 00 00 A0 E3 10 80 BD E8 00 30 90 E5 00 00 53 E3 FA FF FF 0A AC 20 9F E5 00 40 92 E5 00 00 54 E3 04 00 00 1A 0A 00 00 EA 14 20 84 E2 14 40 94 E5 00 00 54 E3 06 00 00 0A 0C 30 94 E5 03 00 50 E1 F8 FF FF 1A 14 30 94 E5 00 30 82 E5 04 00 A0 E1 10 80 BD E8 70 30 9F E5 00 40 93 E5 00 00 54 E3 17 00 00 0A 03 10 A0 E1 07 00 00 EA 0C 30 94 E5 00 20 93 E5 02 00 50 E1 0C 00 00 0A 14 10 84 E2 14 40 94 E5 00 00 54 E3 0D 00 00 0A 10 30 D4 E5 01 00 13 E3 F4 FF FF 1A 0C 30 94 E5 03 00 50 E1 F5 FF FF 1A 14 30 94 E5 00 30 81 E5 E6 FF FF EA 14 30 94 E5 00 30 81 E5 0C 00 94 E5 }
	condition:
		$pattern
}

rule __register_frame_info_bases_86c7ea7068d356e3b55e94a5d8b42c28 {
	meta:
		aliases = "__register_frame_info_bases"
		size = "104"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { 00 00 50 E3 10 40 2D E9 02 E0 A0 E1 03 40 A0 E1 10 80 BD 08 00 30 90 E5 7F 2E A0 E3 00 00 53 E3 08 20 82 E2 38 C0 9F E5 10 80 BD 08 00 30 A0 E3 10 30 81 E5 07 30 83 E2 11 30 C1 E5 10 20 C1 E5 00 20 9C E5 08 30 43 E2 0C 00 81 E5 14 20 81 E5 00 30 81 E5 00 10 8C E5 04 E0 81 E5 08 40 81 E5 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_perror_f45a06fd72261bea109b239123f726cd {
	meta:
		aliases = "perror, __GI_perror"
		size = "72"
		objfiles = "perror@libc.a"
	strings:
		$pattern = { 00 00 50 E3 2C 10 9F E5 03 00 00 0A 00 30 D0 E5 00 00 53 E3 20 10 9F 15 00 00 00 1A 01 00 A0 E1 01 30 A0 E1 14 10 9F E5 00 20 A0 E1 00 00 91 E5 0C 10 9F E5 ?? ?? ?? EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule l64a_54b9f7e5296c308d7b198af903b9e8f7 {
	meta:
		aliases = "l64a"
		size = "80"
		objfiles = "l64a@libc.a"
	strings:
		$pattern = { 00 00 50 E3 38 00 9F 05 00 C0 A0 13 0E F0 A0 01 04 00 00 EA 2C 30 9F E5 01 30 D3 E7 20 03 A0 E1 0C 30 C2 E7 01 C0 8C E2 00 00 50 E3 3F 10 00 E2 14 20 9F E5 F6 FF FF 1A 0C 00 C2 E7 02 00 A0 E1 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wcstok_b7802eaca1dd7f35d342e3b39bfbe161 {
	meta:
		aliases = "wcstok"
		size = "108"
		objfiles = "wcstok@libc.a"
	strings:
		$pattern = { 00 00 50 E3 70 40 2D E9 00 40 A0 E1 02 60 A0 E1 01 50 A0 E1 02 00 00 1A 00 40 92 E5 00 00 54 E3 0F 00 00 0A 05 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 41 84 E0 00 30 94 E5 00 00 53 E3 04 00 A0 E1 03 40 A0 01 05 10 A0 E1 04 00 A0 01 03 00 00 0A ?? ?? ?? EB 00 00 50 E3 00 30 A0 13 04 30 80 14 00 00 86 E5 04 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule inet_aton_ddf00a6659175665bfe13c20e1532b90 {
	meta:
		aliases = "__GI_inet_aton, inet_aton"
		size = "236"
		objfiles = "inet_aton@libc.a"
	strings:
		$pattern = { 00 00 50 E3 F0 40 2D E9 01 70 A0 E1 00 50 A0 13 01 60 A0 13 23 00 00 1A 30 00 00 EA C4 30 9F E5 00 E0 93 E5 00 30 D0 E5 83 30 DE E7 08 00 13 E3 2A 00 00 0A 00 40 A0 E3 05 00 00 EA 0A 30 A0 E3 94 C3 23 E0 30 40 43 E2 FF 00 54 E3 23 00 00 CA 01 00 80 E2 00 C0 D0 E5 8C 30 A0 E1 0E 20 83 E0 0E 10 D3 E7 01 30 D2 E5 03 34 81 E1 08 00 13 E3 F1 FF FF 1A 03 00 56 E3 03 00 00 CA 2E 00 5C E3 16 00 00 1A 01 00 80 E2 04 00 00 EA 00 00 5C E3 01 00 80 E2 01 00 00 0A 20 00 13 E3 0F 00 00 0A 05 54 84 E1 01 60 86 E2 04 00 56 E3 DA FF FF DA 00 00 57 E3 FF 38 05 12 FF 2C 05 12 23 34 A0 11 02 24 A0 11 25 3C 83 11 }
	condition:
		$pattern
}

rule free_81b85fd1b291ec25cd5a06cbec4afe18 {
	meta:
		aliases = "free"
		size = "240"
		objfiles = "free@libc.a"
	strings:
		$pattern = { 00 00 50 E3 F0 41 2D E9 F0 81 BD 08 04 50 10 E5 C0 80 9F E5 04 40 40 E2 BC 70 9F E5 BC 00 9F E5 0F E0 A0 E1 07 F0 A0 E1 04 10 A0 E1 05 20 A0 E1 08 00 A0 E1 ?? ?? ?? EB A4 30 9F E5 00 60 90 E5 00 30 93 E5 83 01 56 E1 00 40 A0 E1 0B 00 00 3A 90 00 9F E5 0F E0 A0 E1 07 F0 A0 E1 00 00 A0 E3 ?? ?? ?? EB 0C 50 84 E2 00 00 55 E1 06 00 00 0A 70 00 9F E5 70 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 58 00 9F E5 F0 41 BD E8 ?? ?? ?? EA 04 20 94 E5 00 00 52 E3 08 30 94 15 08 30 82 15 08 20 94 E5 04 30 94 E5 00 00 52 E3 04 30 82 15 00 30 88 05 28 00 9F E5 30 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 66 E0 0C 00 80 E2 }
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

rule __clzdi2_cf4b6af2a8ea77cf86b3294a18248223 {
	meta:
		aliases = "__clzdi2"
		size = "100"
		objfiles = "_clzdi2@libgcc.a"
	strings:
		$pattern = { 00 00 51 E3 01 00 A0 11 20 10 A0 03 00 10 A0 13 01 08 50 E3 0B 00 00 2A FF 00 50 E3 00 C0 A0 93 08 C0 A0 83 0C 20 A0 91 0C 20 A0 81 30 22 A0 E1 28 30 9F E5 02 00 D3 E7 00 00 8C E0 20 00 60 E2 00 00 81 E0 0E F0 A0 E1 01 04 50 E3 10 C0 A0 33 18 C0 A0 23 0C 20 A0 31 0C 20 A0 21 F2 FF FF EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule start_fde_sort_36308d3edaf33867a740cafd5b4dc87b {
	meta:
		aliases = "start_fde_sort"
		size = "104"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { 00 00 51 E3 01 11 A0 E1 70 40 2D E9 08 40 81 E2 00 50 A0 E1 04 00 A0 E1 02 00 00 1A 00 30 A0 E3 03 00 A0 E1 70 80 BD E8 ?? ?? ?? EB 00 60 A0 E3 00 30 A0 E1 06 00 53 E1 04 00 A0 E1 00 30 85 E5 F5 FF FF 0A 04 60 83 E5 ?? ?? ?? EB 06 00 50 E1 01 30 A0 E3 01 30 A0 13 04 00 85 E5 04 60 80 15 03 00 A0 E1 70 80 BD E8 }
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

rule __GI_sigprocmask_49125f24d84405310ec875ccb582bb89 {
	meta:
		aliases = "sigprocmask, __GI_sigprocmask"
		size = "84"
		objfiles = "sigprocmask@libc.a"
	strings:
		$pattern = { 00 00 51 E3 02 00 50 13 10 40 2D E9 08 30 A0 E3 04 00 00 9A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 08 00 00 EA AF 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 20 A0 E1 02 00 A0 E1 10 80 BD E8 }
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

rule __GI_pthread_attr_setscope_2ecf6aa4300b95bc5f180bc7c8d83298 {
	meta:
		aliases = "pthread_attr_setscope, __GI_pthread_attr_setscope"
		size = "36"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 00 00 51 E3 03 00 00 0A 01 00 51 E3 16 00 A0 13 5F 00 A0 03 0E F0 A0 E1 10 10 80 E5 01 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __subvsi3_c32a68b599c31d598373daf601b5c273 {
	meta:
		aliases = "__subvsi3"
		size = "64"
		objfiles = "_subvsi3@libgcc.a"
	strings:
		$pattern = { 00 00 51 E3 04 E0 2D E5 00 30 61 E0 06 00 00 BA 03 00 50 E1 00 00 A0 A3 01 00 A0 B3 00 00 50 E3 05 00 00 1A 03 00 A0 E1 04 F0 9D E4 03 00 50 E1 00 00 A0 D3 01 00 A0 C3 F7 FF FF EA ?? ?? ?? EB }
	condition:
		$pattern
}

rule __addvsi3_0f287d13d7aa14b610ef1e16fa1a5af9 {
	meta:
		aliases = "__addvsi3"
		size = "64"
		objfiles = "_addvsi3@libgcc.a"
	strings:
		$pattern = { 00 00 51 E3 04 E0 2D E5 01 30 80 E0 06 00 00 BA 03 00 50 E1 00 00 A0 D3 01 00 A0 C3 00 00 50 E3 05 00 00 1A 03 00 A0 E1 04 F0 9D E4 03 00 50 E1 00 00 A0 A3 01 00 A0 B3 F7 FF FF EA ?? ?? ?? EB }
	condition:
		$pattern
}

rule __absvdi2_139521122981ed87cc5b497ecbb4c7e9 {
	meta:
		aliases = "__absvdi2"
		size = "32"
		objfiles = "_absvdi2@libgcc.a"
	strings:
		$pattern = { 00 00 51 E3 04 E0 2D E5 04 F0 9D A4 00 00 70 E2 00 10 E1 E2 00 00 51 E3 04 F0 9D A4 ?? ?? ?? EB }
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

rule strnlen_735e774e38bec0b88e38ad2db352f828 {
	meta:
		aliases = "__GI_strnlen, strnlen"
		size = "224"
		objfiles = "strnlen@libc.a"
	strings:
		$pattern = { 00 00 51 E3 10 40 2D E9 00 40 A0 E1 01 00 A0 01 10 80 BD 08 05 00 00 EA 00 00 51 E1 01 00 64 90 00 00 64 80 10 80 BD E8 02 00 A0 E1 25 00 00 EA 01 10 94 E0 00 10 E0 23 04 00 A0 E1 03 00 00 EA 00 30 D0 E5 00 00 53 E3 F2 FF FF 0A 01 00 80 E2 03 00 10 E3 F9 FF FF 1A 00 E0 A0 E1 15 00 00 EA 04 30 9E E4 02 20 83 E0 0C C0 02 E0 00 00 5C E3 0F 00 00 0A 04 30 5E E5 04 20 4E E2 00 00 53 E3 01 00 82 E2 E7 FF FF 0A 03 30 5E E5 00 00 53 E3 0C 00 00 0A 02 30 5E E5 00 00 53 E3 02 00 82 E2 08 00 00 0A 01 30 5E E5 00 00 53 E3 03 00 82 E2 04 00 00 0A 01 00 A0 E1 01 00 5E E1 14 20 9F E5 14 C0 9F E5 E5 FF FF 3A }
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

rule __GI___fsetlocking_b5fa6f4ca7ad70a56176125abbcdfaa6 {
	meta:
		aliases = "__fsetlocking, __GI___fsetlocking"
		size = "48"
		objfiles = "__fsetlocking@libc.a"
	strings:
		$pattern = { 00 00 51 E3 34 20 90 E5 04 00 00 0A 02 00 51 E3 01 30 A0 E3 10 30 9F 15 00 30 93 15 34 30 80 E5 01 00 02 E2 01 00 80 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __heap_link_free_area_after_753fecd2ab2aa20a651371344bdeccfc {
	meta:
		aliases = "__heap_link_free_area_after"
		size = "20"
		objfiles = "heap_free@libc.a"
	strings:
		$pattern = { 00 00 52 E3 00 10 80 05 04 10 82 15 08 20 81 E5 0E F0 A0 E1 }
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

rule __heap_link_free_area_5f27754305e4968a6af66027123117e7 {
	meta:
		aliases = "__heap_link_free_area"
		size = "32"
		objfiles = "heap_free@libc.a"
	strings:
		$pattern = { 00 00 52 E3 04 30 81 E5 08 20 81 E5 04 10 82 15 00 10 80 05 00 00 53 E3 08 10 83 15 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_strlcpy_69ed94810dea4437e0eb4302f7a181d2 {
	meta:
		aliases = "strxfrm, strlcpy, __GI_strxfrm, __GI_strlcpy"
		size = "76"
		objfiles = "strlcpy@libc.a"
	strings:
		$pattern = { 00 00 52 E3 04 D0 4D E2 00 C0 A0 E1 01 20 42 12 03 C0 8D 02 01 00 A0 E1 03 00 00 EA 00 00 52 E3 01 20 42 12 01 C0 8C 12 01 00 80 E2 00 30 D0 E5 00 30 CC E5 00 30 DC E5 00 00 53 E3 F6 FF FF 1A 00 00 61 E0 04 D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __wcslcpy_6bfd2276420604edc2ccbdaa243f7350 {
	meta:
		aliases = "wcsxfrm, __wcslcpy"
		size = "76"
		objfiles = "wcslcpy@libc.a"
	strings:
		$pattern = { 00 00 52 E3 04 D0 4D E2 00 C0 A0 E1 01 20 42 12 0D C0 A0 01 01 00 A0 E1 03 00 00 EA 00 00 52 E3 01 20 42 12 04 C0 8C 12 04 00 80 E2 00 30 90 E5 00 00 53 E3 00 30 8C E5 F7 FF FF 1A 00 00 61 E0 40 01 A0 E1 04 D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __old_sem_init_a904a06795bf20eaa34ac52d7c12ac7b {
	meta:
		aliases = "__old_sem_init"
		size = "84"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { 00 00 52 E3 04 E0 2D E5 00 C0 A0 E1 03 00 00 AA ?? ?? ?? EB 00 10 E0 E3 16 30 A0 E3 09 00 00 EA 82 30 A0 E1 00 00 51 E3 01 20 83 E2 04 10 8C 05 00 20 8C 05 01 10 A0 01 03 00 00 0A ?? ?? ?? EB 00 10 E0 E3 26 30 A0 E3 00 30 80 E5 01 00 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule sem_init_6c7598e69857589ed8757ecba1646d8e {
	meta:
		aliases = "__new_sem_init, sem_init"
		size = "84"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { 00 00 52 E3 04 E0 2D E5 03 00 00 AA ?? ?? ?? EB 00 C0 E0 E3 16 30 A0 E3 05 00 00 EA 00 00 51 E3 01 C0 A0 E1 04 00 00 0A ?? ?? ?? EB 00 C0 E0 E3 26 30 A0 E3 00 30 80 E5 03 00 00 EA 08 20 80 E5 0C 10 80 E5 00 10 80 E5 04 10 80 E5 0C 00 A0 E1 04 F0 9D E4 }
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

rule signalfd_e0f049251b692323f5b541bdfe7cf6bb {
	meta:
		aliases = "signalfd"
		size = "80"
		objfiles = "signalfd@libc.a"
	strings:
		$pattern = { 00 00 52 E3 10 40 2D E9 08 20 A0 E3 04 00 00 0A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 08 00 00 EA 5D 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 20 A0 E1 02 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule _Unwind_GetCFA_4a27a0e0a366adf8db2460263e53724d {
	meta:
		aliases = "_Unwind_GetCFA"
		size = "24"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { 00 00 90 E5 00 00 50 E3 00 30 A0 E1 28 30 90 15 03 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule uw_frame_state_for_4f198f499b66c5464abfbf6a8c0d235c {
	meta:
		aliases = "uw_frame_state_for"
		size = "36"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { 00 00 90 E5 00 00 50 E3 05 30 A0 E3 18 30 90 15 00 30 81 15 00 30 A0 13 00 00 81 05 03 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule fde_insert_164b571ad04f447660282f8e0e399579 {
	meta:
		aliases = "fde_insert"
		size = "40"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { 00 00 90 E5 00 00 50 E3 0E F0 A0 01 04 20 90 E5 02 31 A0 E1 00 30 83 E0 01 20 82 E2 08 10 83 E5 04 20 80 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule alphasort_83d05895d963825cf6af6500a45ff860 {
	meta:
		aliases = "alphasort"
		size = "20"
		objfiles = "alphasort@libc.a"
	strings:
		$pattern = { 00 00 90 E5 00 10 91 E5 0B 00 80 E2 0B 10 81 E2 ?? ?? ?? EA }
	condition:
		$pattern
}

rule alphasort64_e2b0c6410971199a5d896458bd818c1e {
	meta:
		aliases = "alphasort64"
		size = "20"
		objfiles = "alphasort64@libc.a"
	strings:
		$pattern = { 00 00 90 E5 00 10 91 E5 13 00 80 E2 13 10 81 E2 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __collated_compare_22a4fcb45d29d5a4028aab977873be33 {
	meta:
		aliases = "__collated_compare"
		size = "56"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { 00 00 90 E5 00 30 91 E5 03 00 50 E1 00 20 A0 E3 06 00 00 0A 00 00 50 E3 01 20 A0 E3 03 00 00 0A 00 10 53 E2 00 20 E0 E3 00 00 00 0A ?? ?? ?? EA 02 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule uw_identify_context_26e210e3a566ab2cbc6ef52b759ff955 {
	meta:
		aliases = "uw_identify_context"
		size = "8"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { 00 00 90 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule _Unwind_SjLj_Unregister_dd8fb2be0bd7eb75d0ce06a710995fd0 {
	meta:
		aliases = "_Unwind_SjLj_Unregister"
		size = "8"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { 00 00 90 E5 F9 FF FF EA }
	condition:
		$pattern
}

rule last_fde_e30947c7171c69f1bf3ce25aa10e8f1f {
	meta:
		aliases = "last_fde"
		size = "16"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { 00 00 91 E5 01 00 70 E2 00 00 A0 33 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI___errno_location_e58b6c68de6f2c99d5beb6298a089abb {
	meta:
		aliases = "__h_errno_location, __errno_location, __GI___h_errno_location, __libc_pthread_init, __GI___errno_location"
		size = "12"
		objfiles = "__h_errno_location@libc.a, libc_pthread_init@libc.a, __errno_location@libc.a"
	strings:
		$pattern = { 00 00 9F E5 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_mutexattr_getpshared_ce822670167e714100ef5d7d1cf95d8f {
	meta:
		aliases = "pthread_condattr_getpshared, pthread_mutexattr_getpshared, __pthread_mutexattr_getpshared"
		size = "12"
		objfiles = "mutex@libpthread.a, condvar@libpthread.a"
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

rule pthread_condattr_init_6784a51311637d8b420ae445bb38bfaa {
	meta:
		aliases = "_Unwind_GetTextRelBase, __pthread_mutex_unlock, _Unwind_GetDataRelBase, __gthread_mutex_unlock, __pthread_mutex_init, _Unwind_GetRegionStart, __pthread_return_0, _svcauth_null, pthread_condattr_destroy, __gthread_mutex_lock, __gthread_active_p, wcsftime, __pthread_mutex_lock, __udiv_w_sdiv, __pthread_mutex_trylock, _Unwind_FindEnclosingFunction, __GI_pthread_condattr_init, __GI_pthread_condattr_destroy, pthread_rwlockattr_destroy, __pthread_mutexattr_destroy, __GI_pthread_attr_destroy, __GI_wcsftime, xdrstdio_inline, authnone_refresh, pthread_attr_destroy, clntraw_control, pthread_mutexattr_destroy, grantpt, pthread_condattr_init"
		size = "8"
		objfiles = "_udiv_w_sdiv@libgcc.a, gthr_gnat@libgcc.a, auth_none@libc.a, wcsftime@libc.a, mutex@libpthread.a"
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

rule atoi_deef6c6063aa04a17c5a206f19cbcf02 {
	meta:
		aliases = "atoll, __GI_atoi, atol, __GI_atol, atoi"
		size = "12"
		objfiles = "atoll@libc.a, atol@libc.a"
	strings:
		$pattern = { 00 10 A0 E3 0A 20 A0 E3 ?? ?? ?? EA }
	condition:
		$pattern
}

rule mblen_06a2555f6241774853bc5bc19c97be6b {
	meta:
		aliases = "mblen"
		size = "88"
		objfiles = "mblen@libc.a"
	strings:
		$pattern = { 00 20 50 E2 44 30 9F 05 10 40 2D E9 02 C0 A0 E1 00 20 83 05 0B 00 00 0A 00 30 D2 E5 2C 40 9F E5 00 00 53 E3 04 20 A0 E1 03 C0 A0 E1 05 00 00 0A ?? ?? ?? EB 02 00 70 E3 14 30 9F 05 04 30 84 05 00 C0 E0 E3 00 C0 A0 11 0C 00 A0 E1 10 80 BD E8 ?? ?? ?? ?? FF FF 00 00 }
	condition:
		$pattern
}

rule __cmsg_nxthdr_f78486c09486e05d81fa1e14832e17ca {
	meta:
		aliases = "__GI___cmsg_nxthdr, __cmsg_nxthdr"
		size = "88"
		objfiles = "cmsg_nxthdr@libc.a"
	strings:
		$pattern = { 00 20 91 E5 03 30 82 E2 03 30 C3 E3 03 C0 81 E0 0B 00 52 E3 04 E0 2D E5 0C E0 8C E2 0A 00 00 9A 10 20 80 E2 05 00 92 E8 02 00 80 E0 00 00 5E E1 05 00 00 8A 03 30 91 E7 03 30 83 E2 03 30 C3 E3 03 30 8C E0 00 00 53 E1 00 00 00 9A 00 C0 A0 E3 0C 00 A0 E1 04 F0 9D E4 }
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

rule __GI_glob_pattern_p_7fb6e3cd8fbdbbc3bd9281b2da0fbc29 {
	meta:
		aliases = "glob_pattern_p, __GI_glob_pattern_p"
		size = "136"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 00 C0 A0 E3 18 00 00 EA 5B 00 50 E3 0A 00 00 0A 04 00 00 CA 2A 00 50 E3 17 00 00 0A 3F 00 50 E3 10 00 00 1A 14 00 00 EA 5C 00 50 E3 04 00 00 0A 5D 00 50 E3 0B 00 00 1A 08 00 00 EA 01 C0 A0 E3 08 00 00 EA 00 00 51 E3 06 00 00 0A 01 30 D2 E5 00 00 53 E3 01 30 82 E2 03 20 A0 11 01 00 00 EA 00 00 5C E3 04 00 00 1A 01 20 82 E2 00 00 D2 E5 00 00 50 E3 E3 FF FF 1A 0E F0 A0 E1 01 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule wcscmp_a3b541edbf35adc36810dbf35431bc47 {
	meta:
		aliases = "__GI_wcscoll, wcscoll, __GI_wcscmp, wcscmp"
		size = "52"
		objfiles = "wcscmp@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 01 00 00 EA 00 00 50 E3 0E F0 A0 01 00 00 92 E5 00 30 91 E5 03 00 50 E1 04 20 82 E2 04 10 81 E2 F7 FF FF 0A 00 00 E0 33 01 00 A0 23 0E F0 A0 E1 }
	condition:
		$pattern
}

rule exp2_3a1cca57f723b7c96aea9aacaf2b9ce9 {
	meta:
		aliases = "__GI_exp2, exp2"
		size = "20"
		objfiles = "w_exp2@libm.a"
	strings:
		$pattern = { 00 20 A0 E1 01 30 A0 E1 01 01 A0 E3 00 10 A0 E3 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __GI_strcat_b63f573c56518f74126d0772da1ace16 {
	meta:
		aliases = "strcat, __GI_strcat"
		size = "40"
		objfiles = "strcat@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 01 30 D2 E4 00 00 53 E3 FC FF FF 1A 02 20 42 E2 01 30 D1 E4 00 00 53 E3 01 30 E2 E5 FB FF FF 1A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule wcscpy_d68bd0605d92837eabff36f9190cae2e {
	meta:
		aliases = "__GI_wcscpy, wcscpy"
		size = "28"
		objfiles = "wcscpy@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 04 30 91 E4 00 30 82 E5 04 30 92 E4 00 00 53 E3 FA FF FF 1A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule wcscat_4df4ee1a38b2dae1f5d3feb15aa955c3 {
	meta:
		aliases = "__GI_wcscat, wcscat"
		size = "44"
		objfiles = "wcscat@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 04 30 92 E4 00 00 53 E3 FC FF FF 1A 04 20 42 E2 04 30 91 E4 00 30 82 E5 04 30 92 E4 00 00 53 E3 FA FF FF 1A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_wcspbrk_c0c8b9379f209dace67f4a5cd0f07759 {
	meta:
		aliases = "wcspbrk, __GI_wcspbrk"
		size = "64"
		objfiles = "wcspbrk@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 06 00 00 EA 00 00 5C E1 09 00 00 0A 00 C0 93 E5 00 00 5C E3 04 30 83 E2 F9 FF FF 1A 04 20 82 E2 00 00 92 E5 00 00 50 E3 0E F0 A0 01 01 30 A0 E1 F5 FF FF EA 02 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule strpbrk_ea1169131e64d00bd08ba22239794c86 {
	meta:
		aliases = "__GI_strpbrk, strpbrk"
		size = "64"
		objfiles = "strpbrk@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 06 00 00 EA 00 00 5C E1 09 00 00 0A 00 C0 D3 E5 00 00 5C E3 01 30 83 E2 F9 FF FF 1A 01 20 82 E2 00 00 D2 E5 00 00 50 E3 0E F0 A0 01 01 30 A0 E1 F5 FF FF EA 02 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule reboot_368eedc4b76cbdeaecb5ecbd9d42db43 {
	meta:
		aliases = "reboot"
		size = "64"
		objfiles = "reboot@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 10 40 2D E9 28 10 9F E5 28 00 9F E5 58 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 69 19 12 28 AD DE E1 FE }
	condition:
		$pattern
}

rule sigisemptyset_ca1171afab8cdb945ecf92cde5dd1da1 {
	meta:
		aliases = "sigisemptyset"
		size = "48"
		objfiles = "sigisempty@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 7C 00 90 E5 1F 30 A0 E3 00 00 00 EA 03 01 92 E7 00 00 50 E3 01 00 00 1A 01 30 53 E2 FA FF FF 5A 01 00 70 E2 00 00 A0 33 0E F0 A0 E1 }
	condition:
		$pattern
}

rule htonl_8cbfdf00e6e04ace8fbaab47e968117c {
	meta:
		aliases = "ntohl, htonl"
		size = "36"
		objfiles = "ntohl@libc.a"
	strings:
		$pattern = { 00 20 A0 E1 FF 38 00 E2 FF 0C 00 E2 23 34 A0 E1 00 04 A0 E1 02 0C 80 E1 22 3C 83 E1 00 00 83 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __libc_wait_db69692a147d487f1320fb8548949b2b {
	meta:
		aliases = "wait, __libc_wait"
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

rule fopen_4ce1a249bb60e6f00ba2676db9d4be65 {
	meta:
		aliases = "__GI_fopen, fopen"
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

rule twalk_9efd64aef99d547f1bbd669caf86cafa {
	meta:
		aliases = "twalk"
		size = "20"
		objfiles = "twalk@libc.a"
	strings:
		$pattern = { 00 20 A0 E3 02 00 50 E1 02 00 51 11 0E F0 A0 01 D5 FF FF EA }
	condition:
		$pattern
}

rule wctomb_4afa95a8a486a9236ef8873a120bbeb4 {
	meta:
		aliases = "wctomb"
		size = "16"
		objfiles = "wctomb@libc.a"
	strings:
		$pattern = { 00 20 A0 E3 02 00 50 E1 0E F0 A0 01 ?? ?? ?? EA }
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
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { 00 20 A0 E3 02 30 A0 E1 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __opensock_c0c976e995914d757126ab33768e94a5 {
	meta:
		aliases = "__opensock"
		size = "48"
		objfiles = "opensock@libc.a"
	strings:
		$pattern = { 00 20 A0 E3 04 E0 2D E5 02 10 A0 E3 0A 00 A0 E3 ?? ?? ?? EB 00 20 A0 E3 02 00 50 E1 04 F0 9D A4 02 00 A0 E3 00 10 A0 E1 04 E0 9D E4 ?? ?? ?? EA }
	condition:
		$pattern
}

rule gai_strerror_ef0d2c15895bd479ac4d58471cf89697 {
	meta:
		aliases = "gai_strerror"
		size = "64"
		objfiles = "gai_strerror@libc.a"
	strings:
		$pattern = { 00 20 A0 E3 06 00 00 EA 82 31 91 E7 00 00 53 E1 02 00 00 1A 82 31 81 E0 04 00 93 E5 0E F0 A0 E1 01 20 82 E2 0F 00 52 E3 08 10 9F E5 F5 FF FF 9A 04 00 9F E5 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clnt_sperrno_f928afccac45e333232ba5f1c4957ca6 {
	meta:
		aliases = "__GI_clnt_sperrno, clnt_sperrno"
		size = "76"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { 00 20 A0 E3 08 00 00 EA 82 31 91 E7 00 00 53 E1 04 00 00 1A 82 31 81 E0 04 20 93 E5 1C 30 9F E5 03 00 82 E0 0E F0 A0 E1 01 20 82 E2 11 00 52 E3 0C 10 9F E5 F3 FF FF 9A 08 00 9F E5 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
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

rule __decode_header_17e4dac6fc12519fbc3f18af99e92c39 {
	meta:
		aliases = "__decode_header"
		size = "184"
		objfiles = "decodeh@libc.a"
	strings:
		$pattern = { 00 20 D0 E5 01 30 D0 E5 02 34 83 E1 00 30 81 E5 02 30 D0 E5 A3 33 A0 E1 04 30 81 E5 02 30 D0 E5 A3 31 A0 E1 0F 30 03 E2 08 30 81 E5 02 30 D0 E5 23 31 A0 E1 01 30 03 E2 0C 30 81 E5 02 30 D0 E5 A3 30 A0 E1 01 30 03 E2 10 30 81 E5 02 30 D0 E5 01 30 03 E2 14 30 81 E5 03 30 D0 E5 A3 33 A0 E1 18 30 81 E5 03 30 D0 E5 0F 30 03 E2 1C 30 81 E5 04 20 D0 E5 05 30 D0 E5 02 34 83 E1 20 30 81 E5 06 20 D0 E5 07 30 D0 E5 02 34 83 E1 24 30 81 E5 08 20 D0 E5 09 30 D0 E5 02 34 83 E1 28 30 81 E5 0B 30 D0 E5 0A 20 D0 E5 0C 00 A0 E3 02 34 83 E1 2C 30 81 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_sigdelset_fd9ce6819bfc06c14eb42fa50fbc768c {
	meta:
		aliases = "sigismember, sigdelset, sigaddset, __GI_sigaddset, __GI_sigdelset"
		size = "48"
		objfiles = "sigaddset@libc.a, sigdelset@libc.a, sigismem@libc.a"
	strings:
		$pattern = { 00 30 51 E2 04 E0 2D E5 03 00 00 DA 40 00 53 E3 01 00 00 CA 04 E0 9D E4 ?? ?? ?? EA ?? ?? ?? EB 16 30 A0 E3 00 30 80 E5 00 00 E0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule sched_getaffinity_2d9c194c6d3c6769c6bb5cc7ebdd984c {
	meta:
		aliases = "sched_getaffinity"
		size = "96"
		objfiles = "sched_getaffinity@libc.a"
	strings:
		$pattern = { 00 30 51 E2 10 40 2D E9 03 10 A0 A1 02 11 E0 B3 02 C0 A0 E1 F2 00 90 EF 01 0A 70 E3 00 40 A0 E1 04 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 40 E0 E3 00 30 80 E5 04 00 00 EA 01 00 70 E3 03 20 60 E0 00 10 A0 E3 00 00 8C E0 01 00 00 1A 04 00 A0 E1 10 80 BD E8 ?? ?? ?? EB 00 00 A0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule mq_notify_1a1b8fdba55b744696caed7df62d1b47 {
	meta:
		aliases = "mq_notify"
		size = "92"
		objfiles = "mq_notify@librt.a"
	strings:
		$pattern = { 00 30 51 E2 10 40 2D E9 03 10 A0 E1 07 00 00 0A 08 30 93 E5 02 00 53 E3 04 00 00 1A ?? ?? ?? EB 26 30 A0 E3 00 20 E0 E3 00 30 80 E5 08 00 00 EA 16 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 20 A0 E1 02 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule tcsendbreak_a79f328e06347e3013b386e03ba4af3d {
	meta:
		aliases = "tcsendbreak"
		size = "64"
		objfiles = "tcsendbrk@libc.a"
	strings:
		$pattern = { 00 30 51 E2 10 40 2D E9 64 10 A0 E3 00 20 A0 E3 00 40 A0 E1 1C 10 9F D5 04 00 00 DA 63 00 83 E2 ?? ?? ?? EB 10 10 9F E5 00 20 A0 E1 04 00 A0 E1 10 40 BD E8 ?? ?? ?? EA 09 54 00 00 25 54 00 00 }
	condition:
		$pattern
}

rule xdrstdio_getbytes_f858632ebcd69b10d590e606c65bf536 {
	meta:
		aliases = "xdrstdio_putbytes, xdrstdio_getbytes"
		size = "60"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { 00 30 52 E2 01 20 A0 E3 04 E0 2D E5 00 C0 A0 E1 02 E0 A0 E1 01 00 A0 E1 03 10 A0 E1 04 00 00 0A 0C 30 9C E5 ?? ?? ?? EB 01 00 50 E3 00 E0 A0 13 01 E0 A0 03 0E 00 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule __ctzsi2_30915979fbc00e49c0f8924f30602d28 {
	meta:
		aliases = "__ctzsi2"
		size = "108"
		objfiles = "_ctzsi2@libgcc.a"
	strings:
		$pattern = { 00 30 60 E2 00 20 03 E0 01 08 52 E3 0A 00 00 2A 00 10 A0 E3 FF 00 52 E3 01 30 A0 E1 08 10 A0 83 01 30 A0 81 32 23 A0 E1 38 30 9F E5 02 00 D3 E7 00 00 81 E0 01 00 40 E2 0E F0 A0 E1 10 10 A0 E3 01 04 52 E3 01 30 A0 E1 18 10 A0 23 01 30 A0 21 32 23 A0 E1 0C 30 9F E5 02 00 D3 E7 00 00 81 E0 01 00 40 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_strcpy_8c3f5a2d05e94bc9d866a08920de3f8b {
	meta:
		aliases = "strcpy, __GI_strcpy"
		size = "28"
		objfiles = "strcpy@libc.a"
	strings:
		$pattern = { 00 30 61 E0 01 20 43 E2 01 30 D1 E4 00 00 53 E3 02 30 C1 E7 FB FF FF 1A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI___isnan_ceddce4d7f6c178fd2a81f23e2807caf {
	meta:
		aliases = "__isnan, isnan, __GI_isnan, __GI___isnan"
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
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { 00 30 90 E5 00 00 53 E3 04 E0 2D E5 04 F0 9D 04 ?? ?? ?? EB 04 E0 9D E4 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __GI_pthread_attr_getdetachsta_0b416f364d729a7dc563889c583f0308 {
	meta:
		aliases = "pthread_mutexattr_getkind_np, pthread_attr_getdetachstate, __pthread_mutexattr_getkind_np, pthread_rwlockattr_getkind_np, pthread_mutexattr_gettype, __pthread_mutexattr_gettype, __GI_pthread_attr_getdetachstate"
		size = "16"
		objfiles = "mutex@libpthread.a, rwlock@libpthread.a, attr@libpthread.a"
	strings:
		$pattern = { 00 30 90 E5 00 00 A0 E3 00 30 81 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __old_sem_getvalue_b6e7a18b6821b68d1c37bc06d18fdafc {
	meta:
		aliases = "__old_sem_getvalue"
		size = "28"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { 00 30 90 E5 00 00 A0 E3 A3 20 A0 E1 01 30 13 E2 00 20 81 15 00 30 81 05 0E F0 A0 E1 }
	condition:
		$pattern
}

rule uw_update_context_dda1628ae176658f9a59a09417a908a8 {
	meta:
		aliases = "uw_update_context"
		size = "16"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { 00 30 90 E5 00 20 93 E5 00 20 80 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule cfgetispeed_a837072302f9d8c314c42a5fea4e371e {
	meta:
		aliases = "cfgetispeed"
		size = "36"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { 00 30 90 E5 00 20 A0 E1 00 00 53 E3 0C 00 9F E5 08 30 92 A5 00 00 A0 B3 00 00 03 A0 0E F0 A0 E1 0F 10 00 00 }
	condition:
		$pattern
}

rule __old_sem_destroy_d80dc66b7e65814f2f5b23c34ebe9d9f {
	meta:
		aliases = "__old_sem_destroy"
		size = "40"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { 00 30 90 E5 01 00 13 E3 04 E0 2D E5 00 00 A0 E3 04 F0 9D 14 ?? ?? ?? EB 10 30 A0 E3 00 30 80 E5 00 00 E0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule __GI_wcschr_8f9641be45a7c338935ecf1836728c62 {
	meta:
		aliases = "wcschr, __GI_wcschr"
		size = "32"
		objfiles = "wcschr@libc.a"
	strings:
		$pattern = { 00 30 90 E5 01 00 53 E1 0E F0 A0 01 00 00 53 E3 04 00 80 E2 F9 FF FF 1A 00 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule _Unwind_SetIP_39c401ad514acf6b3badef9bf4d81e7a {
	meta:
		aliases = "_Unwind_SetIP"
		size = "16"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { 00 30 90 E5 01 10 41 E2 04 10 83 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule _Unwind_GetGR_21bd919f8185f4dceee4c1a78d855417 {
	meta:
		aliases = "_Unwind_GetGR"
		size = "20"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { 00 30 90 E5 01 11 A0 E1 03 10 81 E0 08 00 91 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule _Unwind_SetGR_1f5004d588e688dbd2aeaa09f17b8cb7 {
	meta:
		aliases = "_Unwind_SetGR"
		size = "20"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { 00 30 90 E5 01 11 A0 E1 03 10 81 E0 08 20 81 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule next_fde_3fd3e7f7d53743d2b0175d45d9ecf956 {
	meta:
		aliases = "next_fde"
		size = "16"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { 00 30 90 E5 03 00 80 E0 04 00 80 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule _Unwind_GetIP_ef0e0b7ba0ac0f6748f3518e0d3fec34 {
	meta:
		aliases = "_Unwind_GetIP"
		size = "16"
		objfiles = "unwind_sjlj@libgcc.a"
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
		objfiles = "unwind_sjlj@libgcc.a"
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

rule __heap_alloc_33493661288e179c6e779577de493c20 {
	meta:
		aliases = "__heap_alloc"
		size = "148"
		objfiles = "heap_alloc@libc.a"
	strings:
		$pattern = { 00 30 91 E5 10 40 2D E9 03 30 83 E2 03 20 C3 E3 01 40 A0 E1 0B 00 52 E3 00 10 A0 E1 00 00 90 E5 0C 20 A0 93 17 00 00 EA 00 C0 90 E5 02 00 5C E1 13 00 00 3A 2C 30 82 E2 03 00 5C E1 0C 30 62 20 00 30 80 25 0A 00 00 2A 04 20 90 E5 00 00 52 E3 08 30 90 15 08 30 82 15 08 30 90 E5 04 E0 90 E5 00 00 53 E3 04 E0 83 15 00 E0 81 05 0C 20 A0 11 0C 20 A0 01 00 30 6C E0 0C 00 83 E2 00 20 84 E5 10 80 BD E8 04 00 90 E5 00 00 50 E3 E5 FF FF 1A 10 80 BD E8 }
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

rule pthread_rwlockattr_init_9439624d8943723f7245d918097c6c83 {
	meta:
		aliases = "pthread_rwlockattr_init"
		size = "20"
		objfiles = "rwlock@libpthread.a"
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

rule wcsncmp_f760989844c2f247ee00da04ca159a1a {
	meta:
		aliases = "wcsncmp"
		size = "68"
		objfiles = "wcsncmp@libc.a"
	strings:
		$pattern = { 00 30 A0 E1 01 00 00 EA 00 00 50 E3 0A 00 00 0A 00 00 52 E3 01 20 42 E2 07 00 00 0A 00 00 93 E5 00 C0 91 E5 0C 00 50 E1 04 30 83 E2 04 10 81 E2 F4 FF FF 0A 00 00 6C E0 0E F0 A0 E1 00 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule basename_c7fc359c5fb109855bedf5da890bbcdb {
	meta:
		aliases = "__GI_basename, basename"
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

rule _Unwind_DeleteException_074c998747ac28376a70f03714b5795e {
	meta:
		aliases = "_Unwind_DeleteException"
		size = "40"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { 00 30 A0 E1 08 30 93 E5 00 00 53 E3 00 10 A0 E1 04 E0 2D E5 01 00 A0 E3 04 F0 9D 04 0F E0 A0 E1 03 F0 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule timer_delete_40ef0122a365662c03cf7188b11ea425 {
	meta:
		aliases = "timer_delete"
		size = "76"
		objfiles = "timer_delete@librt.a"
	strings:
		$pattern = { 00 30 A0 E1 10 40 2D E9 04 00 90 E5 05 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 02 00 00 EA 00 00 50 E3 03 00 A0 E1 01 00 00 0A 00 00 E0 E3 10 80 BD E8 ?? ?? ?? EB 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __floatunsisf_3339d73e77cce6fd8b42b8fa82077cd3 {
	meta:
		aliases = "__aeabi_ui2f, __floatunsisf"
		size = "40"
		objfiles = "_addsubsf3@libgcc.a"
	strings:
		$pattern = { 00 30 A0 E3 01 00 00 EA 02 31 10 E2 00 00 60 42 00 C0 B0 E1 0E F0 A0 01 4B 34 83 E3 00 10 A0 E1 00 00 A0 E3 13 00 00 EA }
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

rule pthread_mutex_init_3e4f0d50cc886495366a6677c49585d2 {
	meta:
		aliases = "__pthread_mutex_init, pthread_mutex_init"
		size = "48"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { 00 30 A0 E3 14 30 80 E5 00 00 51 E3 03 C0 A0 E3 00 C0 91 15 00 20 A0 E1 10 30 80 E5 00 00 A0 E3 0C C0 82 E5 08 00 82 E5 04 00 82 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __init_scan_cookie_401c9cad3ef3066e8a1c2aff922ed23c {
	meta:
		aliases = "__init_scan_cookie"
		size = "84"
		objfiles = "__scan_cookie@libc.a"
	strings:
		$pattern = { 00 30 A0 E3 19 30 C0 E5 08 10 80 E5 0C 30 80 E5 00 30 D1 E5 02 30 13 E2 03 C0 A0 E1 28 C0 91 15 2E 30 A0 E3 24 10 9F E5 00 20 A0 E3 38 30 80 E5 01 30 A0 E3 14 C0 80 E5 1B 20 C0 E5 3C 10 80 E5 34 30 80 E5 1A 20 C0 E5 30 10 80 E5 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _time_t2tm_57809e7c90f18ab7fdf4056358824181 {
	meta:
		aliases = "_time_t2tm"
		size = "484"
		objfiles = "_time_t2tm@libc.a"
	strings:
		$pattern = { 00 30 A0 E3 F0 4F 2D E9 1C 30 82 E5 00 50 90 E5 B4 71 9F E5 02 80 A0 E1 01 90 A0 E1 02 60 A0 E1 00 20 D7 E5 01 30 D7 E5 03 44 82 E1 07 00 54 E3 04 A0 A0 E1 0E 00 00 1A 04 10 A0 E1 05 00 A0 E1 ?? ?? ?? EB 04 10 A0 E1 0B 00 80 E2 ?? ?? ?? EB 02 30 D7 E5 03 10 D7 E5 70 21 9F E5 01 34 83 E1 03 31 A0 E1 02 20 89 E0 00 B0 A0 E1 02 50 85 E0 01 40 83 E2 05 00 A0 E1 04 10 A0 E1 ?? ?? ?? EB 94 00 03 E0 03 50 55 E0 04 50 85 40 01 00 40 42 07 00 5A E3 05 00 00 1A 01 30 44 E2 03 00 55 E1 10 30 96 05 01 30 83 02 10 30 86 05 01 50 45 02 02 70 87 E2 00 20 D7 E5 01 30 D7 E5 3C 00 54 E3 00 50 86 D5 00 00 86 C5 }
	condition:
		$pattern
}

rule __fpending_f1680cac8956264a0b06bfde6e1bca6b {
	meta:
		aliases = "__fpending"
		size = "28"
		objfiles = "__fpending@libc.a"
	strings:
		$pattern = { 00 30 D0 E5 40 30 13 E2 08 20 90 15 10 30 90 15 03 30 62 10 03 00 A0 E1 0E F0 A0 E1 }
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

rule ntohs_558f6a9dc3f01601f002ce7596af1acf {
	meta:
		aliases = "htons, ntohs"
		size = "20"
		objfiles = "ntohl@libc.a"
	strings:
		$pattern = { 00 38 A0 E1 23 04 A0 E1 FF 0C 00 E2 23 0C 80 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_ffs_f806211a6b5cfbd737a6f83bd721a0c3 {
	meta:
		aliases = "ffs, __GI_ffs"
		size = "92"
		objfiles = "ffs@libc.a"
	strings:
		$pattern = { 00 38 A0 E1 23 38 A0 E1 00 00 53 E3 40 08 A0 01 01 20 A0 13 11 20 A0 03 FF 00 10 E3 08 30 82 02 40 04 A0 01 FF 20 03 02 0F 00 10 E3 04 30 82 02 40 02 A0 01 FF 20 03 02 03 00 10 E3 02 30 82 02 40 01 A0 01 FF 20 03 02 00 00 50 E3 01 30 80 12 01 30 03 12 03 00 82 10 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_cancel_86d49d338387dfcbabacb7574b544426 {
	meta:
		aliases = "pthread_cancel"
		size = "248"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { 00 3B A0 E1 E4 20 9F E5 23 3B A0 E1 F0 40 2D E9 03 62 82 E0 00 50 A0 E1 00 10 A0 E3 06 00 A0 E1 ?? ?? ?? EB 08 40 96 E5 00 00 54 E3 04 00 00 0A 10 30 94 E5 05 50 53 E0 01 50 A0 13 00 00 55 E3 03 00 00 0A 06 00 A0 E1 ?? ?? ?? EB 03 00 A0 E3 F0 80 BD E8 42 30 D4 E5 40 20 D4 E5 00 30 53 E2 01 30 A0 13 01 00 52 E3 01 30 83 03 00 00 53 E3 01 30 A0 E3 42 30 C4 E5 03 00 00 0A 06 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 F0 80 BD E8 BC 31 94 E5 00 00 53 E3 14 70 94 E5 03 50 A0 01 05 00 00 0A 00 00 93 E5 04 10 A0 E1 0F E0 A0 E1 04 F0 93 E5 B8 01 C4 E5 00 50 A0 E1 06 00 A0 E1 ?? ?? ?? EB 00 00 55 E3 03 00 00 0A }
	condition:
		$pattern
}

rule verrx_861c9e3ef51d49fd16dd2857e7a2f968 {
	meta:
		aliases = "verr, __GI_verrx, __GI_verr, verrx"
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

rule atexit_2f32ce2913424f2158acd4be85840f34 {
	meta:
		aliases = "atexit"
		size = "52"
		objfiles = "atexits@uclibc_nonshared.a"
	strings:
		$pattern = { 00 44 2D E9 20 A0 9F E5 20 30 9F E5 0A A0 8F E0 03 30 9A E7 00 00 53 E3 03 20 A0 E1 00 20 93 15 00 10 A0 E3 00 44 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule frame_dummy_3094983950db5408376793b41e77b92b {
	meta:
		aliases = "frame_dummy"
		size = "128"
		objfiles = "crtbeginS"
	strings:
		$pattern = { 00 44 2D E9 54 A0 9F E5 54 30 9F E5 0A A0 8F E0 03 30 9A E7 4C 00 9F E5 4C 10 9F E5 00 00 53 E3 00 00 8A E0 01 10 8A E0 0F E0 A0 11 03 F0 A0 11 38 20 9F E5 02 30 9A E7 00 00 53 E3 02 00 8A E0 00 84 BD 08 28 30 9F E5 03 30 9A E7 00 00 53 E3 00 84 BD 08 0F E0 A0 E1 03 F0 A0 E1 00 84 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 E0 2D E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule _exit_9b20eaf9fd17ab39a318799c6d286209 {
	meta:
		aliases = "__GI__exit, _exit"
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
		objfiles = "Scrt1, crt1"
	strings:
		$pattern = { 00 B0 A0 E3 00 E0 A0 E3 04 10 9D E4 0D 20 A0 E1 04 20 2D E5 04 00 2D E5 10 C0 9F E5 04 C0 2D E5 0C 00 9F E5 0C 30 9F E5 ?? ?? ?? EA ?? ?? ?? EB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule dlsym_5416941021c6131fb0bc4ff5a883d371 {
	meta:
		aliases = "dlsym"
		size = "240"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 00 C0 50 E2 D8 30 9F 05 30 40 2D E9 00 C0 93 05 0E 40 A0 E1 01 50 A0 E1 23 00 00 0A 01 00 7C E3 BC 30 9F E5 0F 00 00 0A 00 30 93 E5 03 00 5C E1 B0 30 9F 15 00 30 93 15 03 00 00 1A 1A 00 00 EA 00 00 53 E1 18 00 00 0A 04 30 93 E5 00 00 53 E3 FA FF FF 1A 90 30 9F E5 09 20 A0 E3 00 00 A0 E3 00 20 83 E5 30 80 BD E8 00 20 93 E5 00 E0 A0 E3 0B 00 00 EA 00 00 92 E5 14 10 90 E5 04 00 51 E1 06 00 00 2A 00 00 5E E3 02 00 00 0A 14 30 9E E5 01 00 53 E1 01 00 00 2A 10 C0 92 E5 00 E0 A0 E1 10 20 92 E5 00 00 52 E3 F1 FF FF 1A 30 30 9F E5 00 30 93 E5 03 00 5C E1 00 20 A0 13 00 20 9C 05 02 31 A0 E3 05 00 A0 E1 }
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

rule end_fde_sort_6243e0d6fdfd9df1282246a501def43a {
	meta:
		aliases = "end_fde_sort"
		size = "240"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { 00 C0 91 E5 00 00 5C E3 F0 40 2D E9 01 40 A0 E1 00 50 A0 E1 02 70 A0 E1 02 00 00 0A 04 30 9C E5 03 00 52 E1 2D 00 00 1A 10 30 D5 E5 04 00 13 E3 AC 60 9F 15 18 00 00 0A 04 30 94 E5 00 00 53 E3 21 00 00 0A 0C 20 A0 E1 05 00 A0 E1 06 10 A0 E1 68 FC FF EB 04 00 94 E5 00 30 94 E5 04 10 90 E5 04 20 93 E5 01 20 82 E0 07 00 52 E1 1B 00 00 1A 00 20 A0 E1 06 10 A0 E1 05 00 A0 E1 DB FC FF EB 05 00 A0 E1 06 10 A0 E1 0C 00 94 E8 FD FC FF EB 04 00 94 E5 F0 40 BD E8 ?? ?? ?? EA 10 30 95 E5 07 30 C3 E3 83 3A A0 E1 A3 3A A0 E1 00 00 53 E3 30 10 9F E5 30 20 9F E5 04 30 94 E5 01 60 A0 11 02 60 A0 01 00 00 53 E3 }
	condition:
		$pattern
}

rule byte_compile_range_93f0ca81d5d05cd72f3d8bddd6fc28a4 {
	meta:
		aliases = "byte_compile_range"
		size = "184"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 00 C0 91 E5 30 40 2D E9 02 00 5C E1 03 E0 A0 E1 0C 20 8D E2 24 00 92 E8 0B 20 A0 03 23 00 00 0A 01 30 8C E2 00 30 81 E5 01 28 12 E2 00 10 DC E5 0B 20 A0 13 00 00 5E E3 FF 30 00 12 03 00 DE 17 01 40 DE 17 01 40 A0 01 16 00 00 EA FF 30 00 E2 00 00 5E E3 03 30 DE 17 A3 C1 A0 01 C3 C1 A0 11 FF 30 00 E2 00 00 5E E3 03 30 DE 17 A3 31 A0 01 C3 31 A0 11 00 00 5E E3 03 10 D5 E7 FF 30 00 12 03 20 DE 17 07 20 00 02 07 20 02 12 01 30 A0 E3 13 32 A0 E1 FF 30 03 E2 03 30 81 E1 0C 30 C5 E7 01 00 80 E2 00 20 A0 E3 04 00 50 E1 E6 FF FF 9A 02 00 A0 E1 30 80 BD E8 }
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

rule __longjmp_e3c9a09ca142c269ba8ced3f528f9960 {
	meta:
		aliases = "__GI___longjmp, __longjmp"
		size = "24"
		objfiles = "__longjmp@libc.a"
	strings:
		$pattern = { 00 C0 A0 E1 01 00 B0 E1 01 00 A0 03 F0 6F BC E8 0C 42 BC EC 0E F0 A0 E1 }
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

rule wcsncat_87d6ac91d7d040a89e26837436a42737 {
	meta:
		aliases = "wcsncat"
		size = "72"
		objfiles = "wcsncat@libc.a"
	strings:
		$pattern = { 00 C0 A0 E1 04 30 9C E4 00 00 53 E3 FC FF FF 1A 04 C0 4C E2 00 00 00 EA 04 C0 8C E2 00 00 52 E3 01 20 42 E2 04 00 00 0A 00 30 91 E5 00 00 53 E3 04 10 81 E2 00 30 8C E5 F6 FF FF 1A 00 30 A0 E3 00 30 8C E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __sigsetjmp_c984206a6fc01653ef345da47bc9e04a {
	meta:
		aliases = "__sigsetjmp"
		size = "16"
		objfiles = "setjmp@libc.a"
	strings:
		$pattern = { 00 C0 A0 E1 F0 6F AC E8 0C 42 AC EC ?? ?? ?? EA }
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

rule wcswidth_5766971e7b70bf24889e96eeeafba38b {
	meta:
		aliases = "__GI_wcswidth, wcswidth"
		size = "96"
		objfiles = "wcswidth@libc.a"
	strings:
		$pattern = { 00 C0 A0 E3 09 00 00 EA FF 00 52 E3 01 C0 8C E2 0F 00 00 CA 20 00 53 E3 00 30 A0 83 01 30 A0 93 1F 00 52 E3 01 30 83 D3 00 00 53 E3 08 00 00 1A 00 00 51 E3 01 10 41 E2 06 00 00 0A 00 20 90 E5 00 00 52 E3 04 00 80 E2 7F 30 42 E2 ED FF FF 1A 00 00 00 EA 00 C0 E0 E3 0C 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule read_uleb128_b76a2a73396711c17efdec92bf6dc6cf {
	meta:
		aliases = "read_uleb128"
		size = "40"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a, unwind_c@libgcc.a"
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

rule __gtdf2_a8d5193e8d8006a54a086450fcbe7256 {
	meta:
		aliases = "__gedf2, __gtdf2"
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

rule pthread_setcancelstate_98c0cd4fd826219594b6d064cf62a64d {
	meta:
		aliases = "__GI_pthread_setcancelstate, pthread_setcancelstate"
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

rule __pthread_mutexattr_setpshared_bb924e4b313734db1ba3e5e04b757f13 {
	meta:
		aliases = "pthread_mutexattr_setpshared, pthread_condattr_setpshared, __pthread_mutexattr_setpshared"
		size = "28"
		objfiles = "mutex@libpthread.a, condvar@libpthread.a"
	strings:
		$pattern = { 01 00 51 E3 16 00 A0 E3 0E F0 A0 81 00 00 51 E3 26 00 A0 13 00 00 A0 03 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_rwlockattr_setkind_np_3e61b1b831fc49ff3c6f8e576409b8d6 {
	meta:
		aliases = "pthread_attr_setdetachstate, __GI_pthread_attr_setdetachstate, pthread_rwlockattr_setkind_np"
		size = "24"
		objfiles = "rwlock@libpthread.a, attr@libpthread.a"
	strings:
		$pattern = { 01 00 51 E3 16 30 A0 E3 00 30 A0 93 00 10 80 95 03 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_rwlockattr_setpshared_6d60a3371d30affe446e661de84ad857 {
	meta:
		aliases = "pthread_rwlockattr_setpshared"
		size = "24"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { 01 00 51 E3 16 30 A0 E3 00 30 A0 93 04 10 80 95 03 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_attr_setinheritsched_de60d427eac1fab02a770377315e53ae {
	meta:
		aliases = "__GI_pthread_attr_setinheritsched, pthread_attr_setinheritsched"
		size = "24"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 01 00 51 E3 16 30 A0 E3 00 30 A0 93 0C 10 80 95 03 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __getutent_2d854503fd124084ae2893041a7d20f4 {
	meta:
		aliases = "__getutent"
		size = "60"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { 01 00 70 E3 04 E0 2D E5 28 10 9F E5 06 2D A0 E3 01 00 00 1A CD FF FF EB 03 00 00 EA ?? ?? ?? EB 06 0D 50 E3 0C 30 9F E5 00 00 00 0A 00 30 A0 E3 03 00 A0 E1 04 F0 9D E4 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI__stdlib_mb_cur_max_1ce4a30a252936ca418941b102aaafc1 {
	meta:
		aliases = "xdr_void, __GI_xdr_void, authnone_validate, old_sem_extricate_func, _stdlib_mb_cur_max, __GI__stdlib_mb_cur_max"
		size = "8"
		objfiles = "_stdlib_mb_cur_max@libc.a, xdr@libc.a, oldsemaphore@libpthread.a, auth_none@libc.a"
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

rule __clzsi2_698ca589111a3250876210eaf5110f5b {
	meta:
		aliases = "__clzsi2"
		size = "100"
		objfiles = "_clzsi2@libgcc.a"
	strings:
		$pattern = { 01 08 50 E3 0A 00 00 2A 00 10 A0 E3 FF 00 50 E3 01 20 A0 E1 08 10 A0 83 01 20 A0 81 30 22 A0 E1 38 30 9F E5 02 00 D3 E7 00 00 81 E0 20 00 60 E2 0E F0 A0 E1 10 10 A0 E3 01 04 50 E3 01 20 A0 E1 18 10 A0 23 01 20 A0 21 30 22 A0 E1 0C 30 9F E5 02 00 D3 E7 00 00 81 E0 20 00 60 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_attr_setstacksize_295abe221716a01065e96e3e36cdaca6 {
	meta:
		aliases = "__pthread_attr_setstacksize, pthread_attr_setstacksize"
		size = "24"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 01 09 51 E3 16 30 A0 E3 00 30 A0 23 20 10 80 25 03 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_getspecific_1abda4bec688409bdd7613f8088e7a5a {
	meta:
		aliases = "pthread_getspecific"
		size = "76"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { 01 0B 50 E3 10 40 2D E9 00 40 A0 E1 0B 00 00 2A C7 FF FF EB A4 32 A0 E1 03 01 80 E0 EC 20 90 E5 00 00 52 E3 05 00 00 0A 18 30 9F E5 84 31 93 E7 1F 00 04 E2 00 00 53 E3 00 01 92 17 10 80 BD 18 00 00 A0 E3 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_setspecific_4b8663fd1df2a0c457ce83dfe748a380 {
	meta:
		aliases = "pthread_setspecific"
		size = "136"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { 01 0B 50 E3 F0 41 2D E9 00 40 A0 E1 01 80 A0 E1 18 00 00 2A 68 30 9F E5 80 31 93 E7 00 00 53 E3 A0 72 A0 E1 13 00 00 0A 71 FF FF EB 04 10 A0 E3 00 60 A0 E1 97 61 23 E0 E0 50 83 E2 0C 30 95 E5 00 00 53 E3 20 00 A0 E3 04 00 00 1A ?? ?? ?? EB 00 00 50 E3 0C 10 A0 E3 07 00 00 0A 0C 00 85 E5 07 31 86 E0 EC 30 93 E5 1F 20 04 E2 00 10 A0 E3 02 81 83 E7 00 00 00 EA 16 10 A0 E3 01 00 A0 E1 F0 81 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _store_inttype_ccab085ab9a61a1681bbeecc3ad9ac71 {
	meta:
		aliases = "_store_inttype"
		size = "52"
		objfiles = "_store_inttype@libc.a"
	strings:
		$pattern = { 01 0C 51 E3 08 00 00 0A 02 0B 51 E3 01 00 00 1A 0C 00 80 E8 0E F0 A0 E1 02 0C 51 E3 42 C4 A0 E1 00 20 80 15 0E F0 A0 11 01 C0 C0 E5 00 20 C0 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __paritydi2_ab48d94266d382df00ebdf25317a226e {
	meta:
		aliases = "__paritydi2"
		size = "40"
		objfiles = "_paritydi2@libgcc.a"
	strings:
		$pattern = { 01 10 20 E0 21 18 21 E0 21 14 21 E0 21 12 21 E0 69 0C A0 E3 0F 10 01 E2 96 00 80 E2 50 01 A0 E1 01 00 00 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __sigismember_cd47bd13fa76ee3371e06c499250e6bc {
	meta:
		aliases = "__sigismember"
		size = "36"
		objfiles = "sigsetops@libc.a"
	strings:
		$pattern = { 01 10 41 E2 A1 32 A0 E1 03 21 90 E7 1F 10 01 E2 01 30 A0 E3 13 31 12 E0 00 00 A0 03 01 00 A0 13 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __sigaddset_c34af2b02df82895665c9ec02529b6aa {
	meta:
		aliases = "__sigaddset"
		size = "36"
		objfiles = "sigsetops@libc.a"
	strings:
		$pattern = { 01 10 41 E2 A1 C2 A0 E1 0C 31 90 E7 1F 10 01 E2 01 20 A0 E3 12 31 83 E1 0C 31 80 E7 00 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __sigdelset_72d374db4bb099eec68b3c50b166af99 {
	meta:
		aliases = "__sigdelset"
		size = "36"
		objfiles = "sigsetops@libc.a"
	strings:
		$pattern = { 01 10 41 E2 A1 C2 A0 E1 0C 31 90 E7 1F 10 01 E2 01 20 A0 E3 12 31 C3 E1 0C 31 80 E7 00 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule dlclose_af85920acdf6b2493199b29ad4839769 {
	meta:
		aliases = "dlclose"
		size = "8"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 01 10 A0 E3 3E FF FF EA }
	condition:
		$pattern
}

rule chmod_7571c1b2105f14b9715fa234ecace5a2 {
	meta:
		aliases = "__GI_chmod, chmod"
		size = "52"
		objfiles = "chmod@libc.a"
	strings:
		$pattern = { 01 18 A0 E1 10 40 2D E9 21 18 A0 E1 0F 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule mkdir_6d5cf74a16250c4a1a020a07d7e03ce4 {
	meta:
		aliases = "__GI_mkdir, mkdir"
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

rule __GI_memcmp_53b538cb10b98e19970157fe279f25da {
	meta:
		aliases = "bcmp, memcmp, __GI_memcmp"
		size = "44"
		objfiles = "memcmp@libc.a"
	strings:
		$pattern = { 01 20 52 E2 00 00 A0 43 0E F0 A0 41 02 C0 80 E0 01 20 D0 E4 01 30 D1 E4 00 00 5C E1 03 00 52 21 FA FF FF 0A 03 00 42 E0 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __aeabi_ul2f_e9ab21bd92fe35d5cf95b36f7354d805 {
	meta:
		aliases = "__floatundisf, __aeabi_ul2f"
		size = "216"
		objfiles = "_addsubsf3@libgcc.a"
	strings:
		$pattern = { 01 20 90 E1 08 81 00 0E 0E F0 A0 01 00 30 A0 E3 06 00 00 EA 01 20 90 E1 08 81 00 0E 0E F0 A0 01 02 31 11 E2 01 00 00 5A 00 00 70 E2 00 10 E1 E2 08 E0 2D E5 90 E0 8F E2 01 C0 B0 E1 00 C0 A0 01 00 10 A0 01 00 00 A0 03 5B 34 83 E3 01 32 43 02 02 35 43 E2 17 20 A0 E3 01 08 5C E3 2C C8 A0 21 10 20 42 22 01 0C 5C E3 2C C4 A0 21 08 20 42 22 10 00 5C E3 2C C2 A0 21 04 20 42 22 04 00 5C E3 02 20 42 22 AC 20 42 30 AC 21 52 E0 82 3B 43 E0 06 00 00 BA 11 32 83 E0 10 C2 A0 E1 20 20 62 E2 02 01 5C E3 30 02 A3 E0 01 00 C0 03 0E F0 A0 E1 20 20 82 E2 11 C2 A0 E1 20 20 62 E2 8C 00 90 E1 31 02 A3 E0 AC 0F C0 01 }
	condition:
		$pattern
}

rule __floatdisf_ee7c8678d6763054f1cc02fb3d3c7f93 {
	meta:
		aliases = "__aeabi_l2f, __floatdisf"
		size = "196"
		objfiles = "_addsubsf3@libgcc.a"
	strings:
		$pattern = { 01 20 90 E1 08 81 00 0E 0E F0 A0 01 02 31 11 E2 01 00 00 5A 00 00 70 E2 00 10 E1 E2 08 E0 2D E5 90 E0 8F E2 01 C0 B0 E1 00 C0 A0 01 00 10 A0 01 00 00 A0 03 5B 34 83 E3 01 32 43 02 02 35 43 E2 17 20 A0 E3 01 08 5C E3 2C C8 A0 21 10 20 42 22 01 0C 5C E3 2C C4 A0 21 08 20 42 22 10 00 5C E3 2C C2 A0 21 04 20 42 22 04 00 5C E3 02 20 42 22 AC 20 42 30 AC 21 52 E0 82 3B 43 E0 06 00 00 BA 11 32 83 E0 10 C2 A0 E1 20 20 62 E2 02 01 5C E3 30 02 A3 E0 01 00 C0 03 0E F0 A0 E1 20 20 82 E2 11 C2 A0 E1 20 20 62 E2 8C 00 90 E1 31 02 A3 E0 AC 0F C0 01 0E F0 A0 E1 04 00 2D E5 01 01 BD EC 08 F0 9D E4 }
	condition:
		$pattern
}

rule __floatdidf_2ebcbb6b767adcc7e674ac01ff6e44ac {
	meta:
		aliases = "__aeabi_l2d, __floatdidf"
		size = "128"
		objfiles = "_addsubdf3@libgcc.a"
	strings:
		$pattern = { 01 20 90 E1 88 81 00 0E 0E F0 A0 01 60 C0 8F E2 30 50 2D E9 02 51 11 E2 01 00 00 5A 00 00 70 E2 00 10 E1 E2 01 4B A0 E3 32 40 84 E2 00 C0 A0 E1 01 00 A0 E1 0C 10 A0 E1 20 CB B0 E1 46 FF FF 0A 03 20 A0 E3 AC C1 B0 E1 03 20 82 12 AC C1 B0 E1 03 20 82 12 AC 21 82 E0 20 30 62 E2 11 C3 A0 E1 31 12 A0 E1 10 13 81 E1 30 02 A0 E1 02 40 84 E0 39 FF FF EA 03 00 2D E9 02 81 BD EC 08 F0 9D E4 }
	condition:
		$pattern
}

rule __floatundidf_cf656e10414fd7a380e762773dd8bc16 {
	meta:
		aliases = "__aeabi_ul2d, __floatundidf"
		size = "156"
		objfiles = "_addsubdf3@libgcc.a"
	strings:
		$pattern = { 01 20 90 E1 88 81 00 0E 0E F0 A0 01 7C C0 8F E2 30 50 2D E9 00 50 A0 E3 08 00 00 EA 01 20 90 E1 88 81 00 0E 0E F0 A0 01 60 C0 8F E2 30 50 2D E9 02 51 11 E2 01 00 00 5A 00 00 70 E2 00 10 E1 E2 01 4B A0 E3 32 40 84 E2 00 C0 A0 E1 01 00 A0 E1 0C 10 A0 E1 20 CB B0 E1 46 FF FF 0A 03 20 A0 E3 AC C1 B0 E1 03 20 82 12 AC C1 B0 E1 03 20 82 12 AC 21 82 E0 20 30 62 E2 11 C3 A0 E1 31 12 A0 E1 10 13 81 E1 30 02 A0 E1 02 40 84 E0 39 FF FF EA 03 00 2D E9 02 81 BD EC 08 F0 9D E4 }
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
		aliases = "creat, __libc_creat64, __libc_creat, creat64"
		size = "16"
		objfiles = "creat64@libc.a, open@libc.a"
	strings:
		$pattern = { 01 20 A0 E1 00 10 9F E5 ?? ?? ?? EA 41 02 00 00 }
	condition:
		$pattern
}

rule mrand48_r_2145ca4e0ef4524858602e20f56948c7 {
	meta:
		aliases = "drand48_r, lrand48_r, __GI_lrand48_r, mrand48_r"
		size = "12"
		objfiles = "mrand48_r@libc.a, lrand48_r@libc.a, drand48_r@libc.a"
	strings:
		$pattern = { 01 20 A0 E1 00 10 A0 E1 ?? ?? ?? EA }
	condition:
		$pattern
}

rule gmtime_r_0efc9bd82418dead8553fc2005f25bf4 {
	meta:
		aliases = "bzero, mq_getattr, gmtime_r"
		size = "12"
		objfiles = "gmtime_r@libc.a, mq_getsetattr@librt.a, bzero@libc.a"
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

rule vwprintf_f2068c4f7ded18dcf76a6cb2fc8fc546 {
	meta:
		aliases = "vwscanf, __GI_vscanf, vscanf, vprintf, vwprintf"
		size = "28"
		objfiles = "vwscanf@libc.a, vprintf@libc.a, vscanf@libc.a, vwprintf@libc.a"
	strings:
		$pattern = { 01 20 A0 E1 0C 10 9F E5 00 30 A0 E1 00 00 91 E5 03 10 A0 E1 ?? ?? ?? EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __mulvsi3_8b7fa1fb013654b506d7c61d5d28caf9 {
	meta:
		aliases = "__mulvsi3"
		size = "40"
		objfiles = "_mulvsi3@libgcc.a"
	strings:
		$pattern = { 01 20 A0 E1 C2 3F A0 E1 10 40 2D E9 C0 1F A0 E1 ?? ?? ?? EB C0 2F A0 E1 01 00 52 E1 C1 4F A0 E1 10 80 BD 08 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __pthread_alt_trylock_2aa032a8a39ba9717a6d1f9987f9fc6d {
	meta:
		aliases = "__pthread_alt_trylock"
		size = "68"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { 01 20 A0 E3 04 30 80 E2 02 10 A0 E1 91 10 03 E1 00 00 51 E3 10 10 A0 E3 07 00 00 1A 00 30 90 E5 00 00 53 E3 10 10 A0 E3 01 00 00 1A 00 20 80 E5 03 10 A0 E1 00 30 A0 E3 04 30 80 E5 01 00 A0 E1 0E F0 A0 E1 }
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

rule swab_8b66894598bf9aadd1c16dac7159f92a {
	meta:
		aliases = "swab"
		size = "56"
		objfiles = "swab@libc.a"
	strings:
		$pattern = { 01 20 C2 E3 02 C0 80 E0 07 00 00 EA 00 30 D0 E5 01 20 D0 E5 03 24 82 E1 42 34 A0 E1 01 30 C1 E5 00 20 C1 E5 02 00 80 E2 02 10 81 E2 0C 00 50 E1 F5 FF FF 3A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_strcmp_5d8be841fab43937f1ba9f42fd8c1db7 {
	meta:
		aliases = "__GI_strcoll, strcoll, strcmp, __GI_strcmp"
		size = "28"
		objfiles = "strcmp@libc.a"
	strings:
		$pattern = { 01 20 D0 E4 01 30 D1 E4 01 00 52 E3 03 00 52 21 FA FF FF 0A 03 00 42 E0 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_towctrans_12e2a35773a9b59899685b132eb03574 {
	meta:
		aliases = "towctrans, __GI_towctrans"
		size = "72"
		objfiles = "towctrans@libc.a"
	strings:
		$pattern = { 01 30 41 E2 01 00 53 E3 10 40 2D E9 00 40 A0 E1 07 00 00 8A 7F 00 50 E3 08 00 00 8A 01 00 51 E3 01 00 00 1A 10 40 BD E8 ?? ?? ?? EA 10 40 BD E8 ?? ?? ?? EA ?? ?? ?? EB 16 30 A0 E3 00 30 80 E5 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule arm_modulus_344d4120ec97fb11a90410c9eac4b661 {
	meta:
		aliases = "arm_modulus"
		size = "104"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 01 30 A0 E1 00 20 A0 E3 01 00 00 EA 83 30 A0 E1 01 20 82 E2 00 00 53 E3 FB FF FF AA 09 00 00 EA 11 32 B0 E1 05 00 00 5A 0B 00 00 EA 00 00 63 E0 83 30 B0 E1 03 00 00 4A 01 00 53 E1 01 00 00 3A 03 00 50 E1 F8 FF FF 2A 01 20 42 E2 02 00 52 E3 F2 FF FF 8A 00 00 00 EA 00 00 61 E0 01 00 50 E1 FC FF FF 2A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __pthread_attr_setstackaddr_a1c0048739dddc6e599c947b7119d109 {
	meta:
		aliases = "pthread_attr_setstackaddr, __pthread_attr_setstackaddr"
		size = "20"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 01 30 A0 E3 18 30 80 E5 1C 10 80 E5 00 00 A0 E3 0E F0 A0 E1 }
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

rule __GI_stpcpy_4c59674ef8820c60a93048c6968f03e5 {
	meta:
		aliases = "stpcpy, __GI_stpcpy"
		size = "28"
		objfiles = "stpcpy@libc.a"
	strings:
		$pattern = { 01 30 D1 E4 00 30 C0 E5 01 30 D0 E4 00 00 53 E3 FA FF FF 1A 01 00 40 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_cfsetispeed_c9e1179cd63f59c6ee7e4ebb33b3d6b0 {
	meta:
		aliases = "cfsetispeed, __GI_cfsetispeed"
		size = "120"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { 01 3A C1 E3 0F 30 C3 E3 01 2A 41 E2 00 00 53 E3 04 E0 2D E5 01 20 42 E2 05 00 00 0A 0E 00 52 E3 03 00 00 9A ?? ?? ?? EB 00 C0 E0 E3 16 30 A0 E3 05 00 00 EA 00 30 90 E5 00 00 51 E3 02 21 C3 E3 01 C0 A0 E1 02 31 83 E3 01 00 00 1A 00 30 80 E5 06 00 00 EA 08 30 90 E5 01 3A C3 E3 0F 30 C3 E3 01 30 83 E1 00 20 80 E5 08 30 80 E5 00 C0 A0 E3 0C 00 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule __GI_cfsetospeed_da2d5be4c887b7ed7755abc4d78e4416 {
	meta:
		aliases = "cfsetospeed, __GI_cfsetospeed"
		size = "88"
		objfiles = "speed@libc.a"
	strings:
		$pattern = { 01 3A C1 E3 0F 30 C3 E3 01 2A 41 E2 00 00 53 E3 04 E0 2D E5 01 20 42 E2 06 00 00 0A 0E 00 52 E3 04 00 00 9A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 05 00 00 EA 08 30 90 E5 01 3A C3 E3 0F 30 C3 E3 01 30 83 E1 08 30 80 E5 00 20 A0 E3 02 00 A0 E1 04 F0 9D E4 }
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

rule siglongjmp_3e4dcf3378e0622d9849290bc13e9fa0 {
	meta:
		aliases = "siglongjmp"
		size = "24"
		objfiles = "ptlongjmp@libpthread.a"
	strings:
		$pattern = { 01 50 A0 E1 00 40 A0 E1 BC FF FF EB 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule longjmp_997fe4d902ca5f872e199c5d2809f5cd {
	meta:
		aliases = "longjmp"
		size = "24"
		objfiles = "ptlongjmp@libpthread.a"
	strings:
		$pattern = { 01 50 A0 E1 00 40 A0 E1 C2 FF FF EB 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB }
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

rule __ltsf2_3a855a9a3e166c4422d2040e24f2c5ac {
	meta:
		aliases = "__lesf2, __ltsf2"
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

rule __eqsf2_20190a500a376de588b255af7f06cddf {
	meta:
		aliases = "__cmpsf2, __nesf2, __eqsf2"
		size = "96"
		objfiles = "_cmpsf2@libgcc.a"
	strings:
		$pattern = { 01 C0 A0 E3 04 C0 0D E5 80 20 A0 E1 81 30 A0 E1 42 CC F0 E1 43 CC F0 11 06 00 00 0A A3 C0 92 E1 01 00 30 11 03 00 52 50 C1 0F A0 81 C1 0F E0 31 01 00 80 13 0E F0 A0 E1 42 CC F0 E1 01 00 00 1A 80 C4 B0 E1 03 00 00 1A 43 CC F0 E1 F2 FF FF 1A 81 C4 B0 E1 F0 FF FF 0A 04 00 1D E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __eqdf2_8d2cd9eee0fdc8c659f057219ecbfdad {
	meta:
		aliases = "__nedf2, __cmpdf2, __eqdf2"
		size = "132"
		objfiles = "_cmpdf2@libgcc.a"
	strings:
		$pattern = { 01 C0 A0 E3 04 C0 0D E5 80 C0 A0 E1 CC CA F0 E1 82 C0 A0 E1 CC CA F0 11 0D 00 00 0A 80 C0 91 E1 82 C0 93 01 02 00 30 11 03 00 31 01 00 00 A0 03 0E F0 A0 01 00 00 70 E3 02 00 30 E1 02 00 50 51 03 00 51 01 C2 0F A0 21 C2 0F E0 31 01 00 80 E3 0E F0 A0 E1 80 C0 A0 E1 CC CA F0 E1 01 00 00 1A 00 C6 91 E1 04 00 00 1A 82 C0 A0 E1 CC CA F0 E1 E9 FF FF 1A 02 C6 93 E1 E7 FF FF 0A 04 00 1D E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule wmemcmp_ece4e391670072b47a7311b825005169 {
	meta:
		aliases = "wmemcmp"
		size = "68"
		objfiles = "wmemcmp@libc.a"
	strings:
		$pattern = { 02 00 00 EA 04 00 80 E2 04 10 81 E2 01 20 42 E2 00 00 52 E3 04 00 00 0A 00 C0 90 E5 00 30 91 E5 03 00 5C E1 F6 FF FF 0A 01 00 00 EA 02 00 A0 E1 0E F0 A0 E1 03 00 5C E1 01 00 A0 23 00 00 E0 33 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __md5_to64_8819dba97432b174b319187adc602a05 {
	meta:
		aliases = "__md5_to64"
		size = "40"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { 02 00 00 EA 18 30 9F E5 0C 30 D3 E7 01 30 C0 E4 01 20 52 E2 3F C0 01 E2 21 13 A0 E1 F8 FF FF 5A 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_pthread_attr_setschedpoli_fe0f5d7d327d44897be78f4690289d74 {
	meta:
		aliases = "pthread_attr_setschedpolicy, __GI_pthread_attr_setschedpolicy"
		size = "24"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 02 00 51 E3 16 30 A0 E3 00 30 A0 93 04 10 80 95 03 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule _svcauth_short_ae78ace192a33af724e3cae5712c1237 {
	meta:
		aliases = "rendezvous_stat, svcraw_stat, svcudp_stat, _svcauth_short"
		size = "8"
		objfiles = "svc_udp@libc.a, svc_tcp@libc.a, svc_raw@libc.a, svc_authux@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { 02 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI___signbitf_4b8f21fb04c77b43d51bc2a86522ce44 {
	meta:
		aliases = "__signbit, __GI___signbit, __signbitf, __GI___signbitf"
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
		size = "1052"
		objfiles = "_addsubdf3@libgcc.a"
	strings:
		$pattern = { 02 01 20 E2 00 00 00 EA 02 21 22 E2 30 40 2D E9 80 40 A0 E1 82 50 A0 E1 05 00 34 E1 03 00 31 01 01 C0 94 11 03 C0 95 11 C4 CA F0 11 C5 CA F0 11 86 00 00 0A A4 4A A0 E1 A5 5A 74 E0 00 50 65 B2 06 00 00 DA 05 40 84 E0 03 30 21 E0 02 20 20 E0 01 10 23 E0 00 00 22 E0 03 30 21 E0 02 20 20 E0 36 00 55 E3 30 80 BD 88 02 01 10 E3 00 06 A0 E1 01 C6 A0 E3 20 06 8C E1 01 00 00 0A 00 10 71 E2 00 00 E0 E2 02 01 12 E3 02 26 A0 E1 22 26 8C E1 01 00 00 0A 00 30 73 E2 00 20 E2 E2 05 00 34 E1 64 00 00 0A 01 40 44 E2 20 E0 75 E2 05 00 00 BA 13 CE A0 E1 33 15 91 E0 00 00 A0 E2 12 1E 91 E0 52 05 B0 E0 06 00 00 EA }
	condition:
		$pattern
}

rule __aeabi_dneg_91f9f13c92a8ce442cf9c1dcc6a7dfff {
	meta:
		aliases = "__negdf2, __aeabi_fneg, __negsf2, __aeabi_dneg"
		size = "8"
		objfiles = "_negsf2@libgcc.a, _negdf2@libgcc.a"
	strings:
		$pattern = { 02 01 20 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI___finite_ac0a1ebf5981d9a162bf6b4acf085abd {
	meta:
		aliases = "finite, __GI_finite, __finite, __GI___finite"
		size = "20"
		objfiles = "s_finite@libm.a"
	strings:
		$pattern = { 02 01 C0 E3 02 01 80 E2 01 06 80 E2 A0 0F A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI___finitef_681e7729d5e81d284cf6a8e017d418bd {
	meta:
		aliases = "__finitef, finitef, __GI___finitef"
		size = "20"
		objfiles = "s_finitef@libm.a"
	strings:
		$pattern = { 02 01 C0 E3 02 01 80 E2 02 05 80 E2 A0 0F A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule isnanf_ae70b5bcd3313d6bee64d8873ca3e151 {
	meta:
		aliases = "__GI___isnanf, __isnanf, isnanf"
		size = "20"
		objfiles = "s_isnanf@libm.a"
	strings:
		$pattern = { 02 01 C0 E3 7F 04 60 E2 02 05 80 E2 A0 0F A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI___fpclassifyf_f1b5ba7f4e8b79785041243c9ebd544e {
	meta:
		aliases = "__fpclassifyf, __GI___fpclassifyf"
		size = "72"
		objfiles = "s_fpclassifyf@libm.a"
	strings:
		$pattern = { 02 01 D0 E3 02 30 A0 E3 0A 00 00 0A 02 05 50 E3 03 30 A0 E3 07 00 00 3A 20 30 9F E5 03 00 50 E1 04 30 A0 E3 03 00 00 9A 14 30 9F E5 03 00 50 E1 00 30 A0 83 01 30 A0 93 03 00 A0 E1 0E F0 A0 E1 FF FF 7F 7F 00 00 80 7F }
	condition:
		$pattern
}

rule __subsf3_b34ada2c1daace1c8e4bc2bc2cb95841 {
	meta:
		aliases = "__aeabi_fsub, __subsf3"
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

rule ilogb_ea4753f97924cad0541081a091de9547 {
	meta:
		aliases = "__GI_ilogb, ilogb"
		size = "144"
		objfiles = "s_ilogb@libm.a"
	strings:
		$pattern = { 02 21 C0 E3 01 06 52 E3 10 40 2D E9 01 40 A0 E1 14 00 00 AA 01 30 A0 E1 04 10 92 E1 06 01 A0 03 10 80 BD 08 00 00 52 E3 54 00 9F 05 02 00 00 0A 04 00 00 EA 01 00 40 E2 83 30 A0 E1 00 00 53 E3 FB FF FF CA 10 80 BD E8 38 00 9F E5 82 35 A0 E1 01 00 00 EA 01 00 40 E2 83 30 A0 E1 00 00 53 E3 FB FF FF CA 10 80 BD E8 1C 30 9F E5 03 00 52 E1 42 3A A0 D1 FF 0F 43 D2 02 01 E0 C3 03 00 40 D2 10 80 BD E8 ED FB FF FF 02 FC FF FF FF FF EF 7F }
	condition:
		$pattern
}

rule __GI_setenv_3852165bc678d1a6955c2fb37b9cba81 {
	meta:
		aliases = "setenv, __GI_setenv"
		size = "12"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { 02 30 A0 E1 00 20 A0 E3 ?? ?? ?? EA }
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

rule getline_74e87f63788bd739b15d97089f480aa5 {
	meta:
		aliases = "__GI_getline, getline"
		size = "12"
		objfiles = "getline@libc.a"
	strings:
		$pattern = { 02 30 A0 E1 0A 20 A0 E3 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __stdio_seek_84eff22b0743278606db2c59a4eaad60 {
	meta:
		aliases = "__stdio_seek"
		size = "48"
		objfiles = "_cs_funcs@libc.a"
	strings:
		$pattern = { 02 30 A0 E1 10 40 2D E9 04 00 90 E5 01 40 A0 E1 06 00 91 E8 ?? ?? ?? EB 00 00 51 E3 00 30 A0 E3 00 30 A0 B1 03 00 84 A8 03 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule fseeko_383b7bec52d509eb219b77b3119cabc4 {
	meta:
		aliases = "fseek, __GI_fseek, fseeko"
		size = "12"
		objfiles = "fseeko@libc.a"
	strings:
		$pattern = { 02 30 A0 E1 C1 2F A0 E1 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __floatsisf_7fa39d5d78fa261c5c85553ce7a8f431 {
	meta:
		aliases = "__aeabi_i2f, __floatsisf"
		size = "32"
		objfiles = "_addsubsf3@libgcc.a"
	strings:
		$pattern = { 02 31 10 E2 00 00 60 42 00 C0 B0 E1 0E F0 A0 01 4B 34 83 E3 00 10 A0 E1 00 00 A0 E3 13 00 00 EA }
	condition:
		$pattern
}

rule __GI_copysign_9eed1c7c30ec1260cf7effe0c609f275 {
	meta:
		aliases = "copysign, __GI_copysign"
		size = "36"
		objfiles = "s_copysign@libm.a"
	strings:
		$pattern = { 02 31 C0 E3 02 21 02 E2 02 00 83 E1 10 40 2D E9 00 30 A0 E1 01 40 A0 E1 18 00 2D E9 02 81 BD EC 10 80 BD E8 }
	condition:
		$pattern
}

rule __uClibc_main_5f66ce987e5216317c9051ac7dfb0486 {
	meta:
		aliases = "__uClibc_main"
		size = "580"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { 02 60 A0 E1 01 E1 82 E0 00 20 92 E5 78 D0 4D E2 04 C0 8E E2 02 00 5C E1 01 80 A0 E1 EC 21 9F E5 80 10 9D E5 E8 41 9F E5 00 10 82 E5 7C 10 9D E5 E0 21 9F E5 00 C0 84 E5 00 10 82 E5 00 A0 A0 E1 78 20 A0 E3 00 E0 84 05 0D 00 A0 E1 00 10 A0 E3 03 70 A0 E1 ?? ?? ?? EB 00 20 94 E5 00 00 00 EA 01 20 A0 E1 04 30 92 E4 00 00 53 E3 02 10 A0 E1 FA FF FF 1A 02 40 A0 E1 05 00 00 EA 0E 00 53 E3 83 01 8D 90 04 10 A0 91 08 20 A0 93 ?? ?? ?? 9B 08 40 84 E2 00 30 94 E5 00 00 53 E3 F6 FF FF 1A ?? ?? ?? EB 34 30 9D E5 5C 20 9D E5 00 00 53 E3 01 3A A0 03 01 00 72 E3 5C 21 9F E5 00 30 82 E5 09 00 00 1A ?? ?? ?? EB }
	condition:
		$pattern
}

rule dysize_52d353b04b82b8985653fce2006f4b83 {
	meta:
		aliases = "dysize"
		size = "76"
		objfiles = "dysize@libc.a"
	strings:
		$pattern = { 03 00 10 E3 10 40 2D E9 64 10 A0 E3 00 40 A0 E1 09 00 00 1A ?? ?? ?? EB 00 00 50 E3 19 1E A0 E3 04 00 A0 E1 02 00 00 1A ?? ?? ?? EB 00 00 50 E3 01 00 00 1A 08 00 9F E5 10 80 BD E8 04 00 9F E5 10 80 BD E8 6E 01 00 00 6D 01 00 00 }
	condition:
		$pattern
}

rule __ieee754_cosh_a89776e18cbd64657a28d9cc7c02802c {
	meta:
		aliases = "__ieee754_cosh"
		size = "300"
		objfiles = "e_cosh@libm.a"
	strings:
		$pattern = { 03 00 2D E9 02 81 BD EC 00 30 A0 E1 FC 30 9F E5 30 40 2D E9 02 51 C0 E3 03 00 55 E1 01 40 A0 E1 80 01 10 CE 30 80 BD C8 E4 30 9F E5 03 00 55 E1 0B 00 00 CA ?? ?? ?? EB 02 81 2D ED 03 00 BD E8 ?? ?? ?? EB F2 05 55 E3 80 A1 00 EE 89 01 00 EE 80 11 00 AE 82 01 12 AE 81 01 40 AE 89 01 00 AE 30 80 BD E8 AC 30 9F E5 03 00 55 E1 07 00 00 CA ?? ?? ?? EB 02 81 2D ED 03 00 BD E8 ?? ?? ?? EB 8E 11 50 EE 8E 01 10 EE 81 01 00 EE 30 80 BD E8 84 30 9F E5 03 00 55 E1 05 00 00 CA ?? ?? ?? EB 02 81 2D ED 03 00 BD E8 ?? ?? ?? EB 8E 01 10 EE 30 80 BD E8 64 30 9F E5 03 00 55 E1 02 81 2D ED 18 00 BD E8 04 00 00 DA }
	condition:
		$pattern
}

rule lrint_8f2b0e6c24561e91d5ab6bb6dc1bf6b0 {
	meta:
		aliases = "__GI_lrint, lrint"
		size = "268"
		objfiles = "s_lrint@libm.a"
	strings:
		$pattern = { 03 00 2D E9 02 81 BD EC 01 20 A0 E1 00 10 A0 E1 21 3A A0 E1 10 40 2D E9 83 3A A0 E1 A3 3A A0 E1 FF 3F 43 E2 03 30 43 E2 13 00 53 E3 08 D0 4D E2 A1 EF A0 E1 15 00 00 CA 01 00 73 E3 00 00 A0 B3 2E 00 00 BA BC 30 9F E5 8E 31 83 E0 00 91 93 ED 80 01 01 EE 00 81 8D ED 00 81 9D ED 81 01 20 EE 02 81 2D ED 18 00 BD E8 23 2A A0 E1 82 2A A0 E1 A2 2A A0 E1 FF 34 C3 E3 0F 36 C3 E3 41 2E 62 E2 01 36 83 E3 03 20 82 E2 33 02 A0 E1 19 00 00 EA 1E 00 53 E3 70 01 10 CE 18 00 00 CA 64 30 9F E5 8E 31 83 E0 00 91 93 ED 80 01 01 EE 00 81 8D ED 00 81 9D ED 81 01 20 EE 02 81 2D ED 03 00 BD E8 00 20 A0 E1 22 3A A0 E1 }
	condition:
		$pattern
}

rule __GI_rint_acb802c6fe06fa5fc0ecc0be596d88d7 {
	meta:
		aliases = "rint, __GI_rint"
		size = "368"
		objfiles = "s_rint@libm.a"
	strings:
		$pattern = { 03 00 2D E9 02 81 BD EC 01 20 A0 E1 00 10 A0 E1 41 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF CF 43 E2 03 C0 4C E2 01 00 A0 E1 13 00 5C E3 30 40 2D E9 02 10 A0 E1 00 40 A0 E3 00 50 A0 E3 A0 EF A0 E1 2F 00 00 CA 00 00 5C E3 1E 00 00 AA 02 31 C0 E3 02 30 93 E1 30 80 BD 08 FF 24 C0 E3 0F 26 C2 E3 02 20 81 E1 00 30 62 E2 03 20 82 E1 02 81 2D ED 18 00 BD E8 A0 08 A0 E1 22 26 A0 E1 E4 10 9F E5 02 27 02 E2 80 08 A0 E1 02 30 80 E1 8E 11 81 E0 00 91 91 ED 18 00 2D E9 02 A1 BD EC 82 01 01 EE 81 01 20 EE 02 81 2D ED 18 00 BD E8 02 81 2D ED 06 00 BD E8 02 31 C3 E3 8E 1F 83 E1 06 00 2D E9 02 81 BD EC 30 80 BD E8 }
	condition:
		$pattern
}

rule __fma_f475478a5a3f58db99cb96f3e655b855 {
	meta:
		aliases = "__GI_fma, __GI___fma, __fma"
		size = "32"
		objfiles = "s_fma@libm.a"
	strings:
		$pattern = { 03 00 2D E9 02 81 BD EC 0C 00 2D E9 02 A1 BD EC 82 11 10 EE 00 81 9D ED 80 01 01 EE 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __fixdfdi_c5912162814f1a2ed66753943fbf282c {
	meta:
		aliases = "__fixdfdi"
		size = "56"
		objfiles = "_fixdfdi@libgcc.a"
	strings:
		$pattern = { 03 00 2D E9 02 81 BD EC 18 F1 D0 EE 04 E0 2D E5 01 00 00 4A 04 E0 9D E4 ?? ?? ?? EA 80 81 10 EE 02 81 2D ED 03 00 BD E8 ?? ?? ?? EB 00 00 70 E2 00 10 E1 E2 04 F0 9D E4 }
	condition:
		$pattern
}

rule __GI_cbrt_deb8e33bd35214727026498541641aca {
	meta:
		aliases = "cbrt, __GI_cbrt"
		size = "400"
		objfiles = "s_cbrt@libm.a"
	strings:
		$pattern = { 03 00 2D E9 02 81 BD EC F0 47 2D E9 01 20 A0 E1 70 31 9F E5 00 10 A0 E1 02 C1 C1 E3 03 00 5C E1 02 81 2D ED 30 00 BD E8 03 C2 2D ED 02 A1 01 E2 00 80 A0 E3 00 90 A0 E3 80 01 00 CE 45 00 00 CA 05 40 9C E1 02 81 2D ED C0 00 BD E8 0C 60 A0 E1 40 00 00 0A 30 31 9F E5 00 40 A0 E3 01 06 5C E3 18 00 2D E9 02 81 BD EC 03 10 A0 E3 0C 00 A0 E1 00 50 A0 E3 C0 00 2D E9 02 C1 BD EC 09 00 00 AA 84 01 10 EE 02 81 2D ED 18 00 BD E8 03 00 A0 E1 02 81 2D ED 30 00 BD E8 ?? ?? ?? EB 2A 44 80 E2 02 45 44 E2 03 00 00 EA 03 10 A0 E3 ?? ?? ?? EB 2B 44 80 E2 06 46 44 E2 87 4C 44 E2 6D 40 44 E2 30 00 2D E9 02 B1 BD EC }
	condition:
		$pattern
}

rule __ieee754_fmod_67d01b15a9a0cb555890f00d440372bf {
	meta:
		aliases = "__ieee754_fmod"
		size = "816"
		objfiles = "e_fmod@libm.a"
	strings:
		$pattern = { 03 00 2D E9 02 81 BD EC F0 4D 2D E9 0C 00 2D E9 02 91 BD EC 03 40 A0 E1 02 30 A0 E1 02 E1 C3 E3 04 10 9E E1 02 81 2D ED 03 00 BD E8 EC 22 9F E5 00 30 A0 13 01 30 A0 03 02 C1 C0 E3 02 00 5C E1 01 30 83 C3 08 D0 4D E2 00 A0 A0 E3 00 B0 A0 E3 00 00 53 E3 04 50 A0 E1 00 0C 8D E8 01 40 A0 E1 02 81 00 E2 05 00 00 1A 00 30 65 E2 03 30 85 E1 A3 3F 8E E1 01 20 82 E2 02 00 53 E1 02 00 00 9A 81 01 10 EE 80 01 40 EE A2 00 00 EA 0E 00 5C E1 07 00 00 CA 00 30 A0 A3 01 30 A0 B3 05 00 51 E1 01 30 83 33 00 00 53 E3 9A 00 00 1A 05 00 51 E1 8A 00 00 0A 01 06 5C E3 11 00 00 AA 00 00 5C E3 5C 22 9F 05 04 30 A0 01 }
	condition:
		$pattern
}

rule round_3843768564d138a8ca17e78416124e12 {
	meta:
		aliases = "__GI_round, round"
		size = "284"
		objfiles = "s_round@libm.a"
	strings:
		$pattern = { 03 00 2D E9 02 91 BD EC 01 20 A0 E1 00 10 A0 E1 41 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF 0F 43 E2 03 00 40 E2 13 00 50 E3 30 40 2D E9 01 C0 A0 E1 00 40 A0 E3 02 10 A0 E1 00 50 A0 E3 18 00 00 CA 00 00 50 E3 09 00 00 AA 30 81 9F ED 80 01 01 EE 18 F1 D0 EE 27 00 00 DA 01 00 70 E3 02 C1 0C E2 FF C5 8C 03 03 C6 8C 03 00 10 A0 E3 21 00 00 EA A0 30 9F E5 53 20 A0 E1 02 30 0C E0 01 30 93 E1 20 00 00 0A 21 81 9F ED 80 01 01 EE 18 F1 D0 EE 02 37 A0 C3 53 30 8C C0 02 C0 C3 C1 F1 FF FF CA 14 00 00 EA 33 00 50 E3 02 00 00 DA 01 0B 50 E3 81 11 01 0E 13 00 00 EA 14 20 40 E2 00 30 E0 E3 33 E2 A0 E1 0E 00 11 E1 }
	condition:
		$pattern
}

rule ceil_55f785e92039ec4110ac153eeb286504 {
	meta:
		aliases = "__GI_ceil, ceil"
		size = "320"
		objfiles = "s_ceil@libm.a"
	strings:
		$pattern = { 03 00 2D E9 02 91 BD EC 01 20 A0 E1 00 10 A0 E1 41 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF CF 43 E2 03 C0 4C E2 13 00 5C E3 30 40 2D E9 01 00 A0 E1 00 40 A0 E3 02 10 A0 E1 00 50 A0 E3 1B 00 00 CA 00 00 5C E3 0B 00 00 AA 38 81 9F ED 80 01 01 EE 18 F1 D0 EE 2F 00 00 DA 00 00 50 E3 02 01 A0 B3 02 00 00 BA 02 30 90 E1 2A 00 00 0A C4 00 9F E5 00 10 A0 E3 27 00 00 EA BC 30 9F E5 53 2C A0 E1 02 30 00 E0 01 30 93 E1 26 00 00 0A 27 81 9F ED 80 01 01 EE 18 F1 D0 EE 1E 00 00 DA 00 00 50 E3 01 36 A0 C3 53 0C 80 C0 02 00 C0 E1 EF FF FF EA 33 00 5C E3 02 00 00 DA 01 0B 5C E3 81 11 01 0E 18 00 00 EA 14 20 4C E2 }
	condition:
		$pattern
}

rule floor_83ec37efb7010843df132f1975b3e247 {
	meta:
		aliases = "__GI_floor, floor"
		size = "328"
		objfiles = "s_floor@libm.a"
	strings:
		$pattern = { 03 00 2D E9 02 91 BD EC 01 20 A0 E1 00 10 A0 E1 41 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF CF 43 E2 03 C0 4C E2 13 00 5C E3 30 40 2D E9 01 00 A0 E1 00 40 A0 E3 02 10 A0 E1 00 50 A0 E3 1D 00 00 CA 00 00 5C E3 0C 00 00 AA 3A 81 9F ED 80 01 01 EE 18 F1 D0 EE 31 00 00 DA 00 00 50 E3 00 10 A0 A3 01 00 A0 A1 2D 00 00 AA 02 31 C0 E3 01 30 93 E1 C8 00 9F 15 0D 00 00 1A 28 00 00 EA C0 30 9F E5 53 2C A0 E1 02 30 00 E0 01 30 93 E1 27 00 00 0A 28 81 9F ED 80 01 01 EE 18 F1 D0 EE 1F 00 00 DA 00 00 50 E3 01 36 A0 B3 53 0C 80 B0 02 00 C0 E1 00 10 A0 E3 19 00 00 EA 33 00 5C E3 02 00 00 DA 01 0B 5C E3 81 11 01 0E }
	condition:
		$pattern
}

rule __fp_range_check_e9a6c58be3bdc7970bc8994119fbdcc1 {
	meta:
		aliases = "__fp_range_check"
		size = "80"
		objfiles = "__fp_range_check@libc.a"
	strings:
		$pattern = { 03 00 2D E9 02 91 BD EC 0E B1 9F ED 83 01 11 EE 10 F1 91 EE 04 E0 2D E5 0C 00 2D E9 02 A1 BD EC 04 F0 9D 14 18 F1 91 EE 04 F0 9D 04 83 01 12 EE 10 F1 92 EE 04 F0 9D 04 ?? ?? ?? EB 22 30 A0 E3 00 30 80 E5 04 F0 9D E4 00 00 D0 3F 00 00 00 00 }
	condition:
		$pattern
}

rule __ieee754_sinh_50cef0d8babc72466876a368d00ccbe1 {
	meta:
		aliases = "__ieee754_sinh"
		size = "320"
		objfiles = "e_sinh@libm.a"
	strings:
		$pattern = { 03 00 2D E9 02 91 BD EC 30 40 2D E9 00 30 A0 E1 08 31 9F E5 02 51 C0 E3 03 00 55 E1 03 C2 2D ED 01 40 A0 E1 81 11 01 CE 37 00 00 CA F0 30 9F E5 00 00 50 E3 8E C1 10 BE 8E C1 00 AE 03 00 55 E1 16 00 00 CA DC 30 9F E5 03 00 55 E1 03 00 00 CA 30 81 9F ED 80 01 01 EE 19 F1 D0 EE 2A 00 00 CA ?? ?? ?? EB 02 81 2D ED 03 00 BD E8 ?? ?? ?? EB B4 30 9F E5 80 A1 00 EE 03 00 55 E1 89 01 00 EE 82 11 12 DE 80 11 41 DE 80 01 42 CE 82 01 02 DE 81 01 20 DE 80 01 02 CE 80 11 14 EE 1A 00 00 EA 88 30 9F E5 03 00 55 E1 04 00 00 CA ?? ?? ?? EB 02 81 2D ED 03 00 BD E8 ?? ?? ?? EB F5 FF FF EA 6C 30 9F E5 03 00 55 E1 }
	condition:
		$pattern
}

rule __ieee754_atanh_06827e978a9e7631692bbb7c4a5cf64a {
	meta:
		aliases = "__ieee754_atanh"
		size = "208"
		objfiles = "e_atanh@libm.a"
	strings:
		$pattern = { 03 00 2D E9 02 91 BD EC 30 40 2D E9 01 40 A0 E1 00 20 64 E2 00 30 A0 E1 04 20 82 E1 02 11 C0 E3 9C 30 9F E5 A2 2F 81 E1 03 00 52 E1 81 01 21 8E 00 50 A0 E1 80 11 40 8E 1D 00 00 8A 03 00 51 E1 88 11 41 0E 1A 00 00 0A 78 30 9F E5 03 00 51 E1 03 00 00 CA 18 81 9F ED 80 01 01 EE 18 F1 D0 EE 13 00 00 CA 02 91 2D ED 18 00 BD E8 01 30 A0 E1 18 00 2D E9 02 81 BD EC 4C 20 9F E5 80 11 00 EE 02 00 51 E1 89 21 30 EE 80 01 11 DE 82 01 40 DE 80 11 01 DE 82 11 41 CE 02 91 2D ED 03 00 BD E8 ?? ?? ?? EB 00 00 55 E3 8E 01 10 EE 80 91 00 AE 80 91 10 BE 81 81 00 EE 30 80 BD E8 3C E4 37 7E 9C 75 00 88 00 00 F0 3F }
	condition:
		$pattern
}

rule __powidf2_9191a7be22e323285bb942e09a08998a {
	meta:
		aliases = "__powidf2"
		size = "64"
		objfiles = "_powidf2@libgcc.a"
	strings:
		$pattern = { 03 00 2D E9 02 91 BD EC C2 3F 22 E0 C2 3F 43 E0 01 00 13 E3 81 81 00 1E 89 81 00 0E 02 00 00 EA 01 00 13 E3 81 11 11 EE 81 01 10 1E A3 30 B0 E1 FA FF FF 1A 00 00 52 E3 89 01 50 BE 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __ieee754_sqrt_43912f0f5700eabebf44dab801d9af93 {
	meta:
		aliases = "__ieee754_sqrt"
		size = "500"
		objfiles = "e_sqrt@libm.a"
	strings:
		$pattern = { 03 00 2D E9 02 91 BD EC E0 21 9F E5 F0 43 2D E9 01 40 A0 E1 D4 11 9F E5 02 20 00 E0 01 00 52 E1 81 01 11 0E 00 30 A0 E1 04 10 A0 E1 00 80 A0 E3 00 90 A0 E3 80 11 01 0E 6A 00 00 0A 00 00 50 E3 06 00 00 CA 02 31 C0 E3 04 30 93 E1 65 00 00 0A 00 00 50 E3 81 01 21 1E 80 11 40 1E 61 00 00 1A 40 2A B0 E1 02 C0 A0 01 03 00 00 0A 0F 00 00 EA A1 05 A0 E1 15 C0 4C E2 81 1A A0 E1 00 00 50 E3 FA FF FF 0A 00 20 A0 E3 01 00 00 EA 80 00 A0 E1 01 20 82 E2 01 06 10 E3 FB FF FF 0A 20 30 62 E2 31 03 80 E1 0C 30 62 E0 11 12 A0 E1 01 20 83 E2 FF 7F 42 E2 FF 34 C0 E3 0F 36 C3 E3 03 70 47 E2 01 26 83 E3 01 00 17 E3 }
	condition:
		$pattern
}

rule __kernel_cos_ec348bebf8fb135f4ff7ae6a6cb4398f {
	meta:
		aliases = "__kernel_cos"
		size = "292"
		objfiles = "k_cos@libm.a"
	strings:
		$pattern = { 03 00 2D E9 02 A1 BD EC 02 01 C0 E3 F9 05 50 E3 06 42 6D ED 0C 00 2D E9 02 D1 BD EC 03 00 00 AA 72 31 10 EE 00 00 53 E3 89 81 00 EE 2A 00 00 0A 2B 81 9F ED 2C 91 9F ED 82 31 12 EE 80 01 13 EE 81 01 00 EE 2A 91 9F ED 80 01 13 EE 81 01 20 EE 29 91 9F ED 80 01 13 EE 81 01 00 EE 28 91 9F ED 80 01 13 EE 81 01 20 EE 27 91 9F ED A8 30 9F E5 80 01 13 EE 81 01 00 EE 03 00 50 E1 80 01 13 EE 06 00 00 CA 85 11 12 EE 80 01 13 EE 81 01 20 EE 8E 11 13 EE 80 11 21 EE 89 01 31 EE 0E 00 00 EA 78 30 9F E5 02 16 40 E2 03 00 50 E1 00 20 A0 E3 17 C1 9F ED 06 00 2D D9 02 C1 BD DC 80 11 13 EE 85 21 12 EE 8E 01 13 EE }
	condition:
		$pattern
}

rule __fixunsdfdi_6c107fd012dc5a4e54cdcd0118723ea1 {
	meta:
		aliases = "__fixunsdfdi"
		size = "160"
		objfiles = "_fixunsdfdi@libgcc.a"
	strings:
		$pattern = { 03 00 2D E9 02 A1 BD EC 1C 81 9F ED 1D 91 9F ED 80 01 12 EE 11 F1 D0 EE 81 01 20 AE 70 31 10 AE 70 31 10 BE 02 31 83 A2 00 00 53 E3 90 31 01 EE 16 81 9F BD 80 11 01 BE 16 81 9F ED 11 B1 9F ED 80 01 11 EE 80 01 02 EE 13 F1 D0 EE 04 40 2D E5 83 01 20 AE 00 40 A0 E3 03 10 A0 E1 70 31 10 AE 70 31 10 BE 02 31 83 A2 00 40 A0 E3 00 00 A0 E3 03 00 80 E1 04 10 81 E1 10 00 BD E8 0E F0 A0 E1 00 00 F0 3D 00 00 00 00 00 00 E0 41 00 00 00 00 00 00 F0 41 00 00 00 00 00 00 F0 C1 00 00 00 00 }
	condition:
		$pattern
}

rule __kernel_sin_1e9f832b92e74de68537e428dbb9332c {
	meta:
		aliases = "__kernel_sin"
		size = "236"
		objfiles = "k_sin@libm.a"
	strings:
		$pattern = { 03 00 2D E9 02 B1 BD EC 02 01 C0 E3 F9 05 50 E3 06 42 6D ED 0C 00 2D E9 02 D1 BD EC 02 00 00 AA 73 31 10 EE 00 00 53 E3 20 00 00 0A 22 81 9F ED 23 91 9F ED 83 21 13 EE 80 01 12 EE 81 01 20 EE 21 91 9F ED 80 01 12 EE 81 01 00 EE 20 91 9F ED 80 01 12 EE 81 01 20 EE 1F 91 9F ED 18 30 9D E5 80 01 12 EE 00 00 53 E3 81 01 00 EE 83 41 12 EE 05 00 00 1A 1A 91 9F ED 80 01 12 EE 81 01 20 EE 80 01 14 EE 80 31 03 EE 08 00 00 EA 80 01 14 EE 8E 11 15 EE 80 11 21 EE 11 81 9F ED 81 11 12 EE 85 11 21 EE 80 01 14 EE 80 11 01 EE 81 31 23 EE 83 81 00 EE 06 42 FD EC 0E F0 A0 E1 3A D9 E5 3D 7C D5 CF 5A E6 E5 5A 3E }
	condition:
		$pattern
}

rule iopl_05466fc9d332923cc48e528b31edcd70 {
	meta:
		aliases = "iopl"
		size = "76"
		objfiles = "iopl@libc.a"
	strings:
		$pattern = { 03 00 50 E3 04 E0 2D E5 00 30 A0 E1 04 00 00 DA ?? ?? ?? EB 16 30 A0 E3 00 C0 E0 E3 00 30 80 E5 07 00 00 EA 00 00 A0 E3 00 00 53 E1 01 18 A0 E3 01 20 A0 E3 03 C0 A0 E1 01 00 00 0A 04 E0 9D E4 ?? ?? ?? EA 0C 00 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule __ucmpdi2_8bbfe385868076ab3e61c80ab723987e {
	meta:
		aliases = "__ucmpdi2"
		size = "44"
		objfiles = "_ucmpdi2@libgcc.a"
	strings:
		$pattern = { 03 00 51 E1 00 C0 A0 E3 05 00 00 3A 03 00 00 8A 02 00 50 E1 02 00 00 3A 01 C0 8C E2 00 00 00 9A 02 C0 A0 E3 0C 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __cmpdi2_5a64e65962684319509f9aaba785fd6a {
	meta:
		aliases = "__cmpdi2"
		size = "44"
		objfiles = "_cmpdi2@libgcc.a"
	strings:
		$pattern = { 03 00 51 E1 00 C0 A0 E3 05 00 00 BA 03 00 00 CA 02 00 50 E1 02 00 00 3A 01 C0 8C E2 00 00 00 9A 02 C0 A0 E3 0C 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __pthread_mutexattr_setkind_np_3c914b406ca5167901c9388c5fe070ab {
	meta:
		aliases = "__pthread_mutexattr_settype, pthread_mutexattr_settype, pthread_mutexattr_setkind_np, __pthread_mutexattr_setkind_np"
		size = "24"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { 03 00 51 E3 16 30 A0 E3 00 30 A0 93 00 10 80 95 03 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_strncpy_2e8fe78503103d7d3cb4a920e7babcfa {
	meta:
		aliases = "strncpy, __GI_strncpy"
		size = "184"
		objfiles = "strncpy@libc.a"
	strings:
		$pattern = { 03 00 52 E3 04 E0 2D E5 01 C0 40 E2 1C 00 00 9A 22 E1 A0 E1 00 30 D1 E5 00 00 53 E3 01 30 EC E5 12 00 00 0A 01 30 D1 E5 00 00 53 E3 01 30 EC E5 01 10 81 E2 0D 00 00 0A 01 30 D1 E5 00 00 53 E3 01 30 EC E5 01 10 81 E2 08 00 00 0A 01 30 D1 E5 00 00 53 E3 01 30 EC E5 01 10 81 E2 03 00 00 0A 01 E0 5E E2 01 10 81 E2 05 00 00 0A E8 FF FF EA 0C 30 60 E0 02 30 63 E0 01 20 53 E2 04 F0 9D 04 07 00 00 EA 03 20 12 E2 04 F0 9D 04 01 30 D1 E4 01 20 52 E2 01 30 EC E5 04 F0 9D 04 00 00 53 E3 F9 FF FF 1A 00 30 A0 E3 01 20 52 E2 01 30 EC E5 FB FF FF 1A 04 F0 9D E4 }
	condition:
		$pattern
}

rule __GI_strncmp_ba433ebd6cb27e8a71b428e0aef3eb03 {
	meta:
		aliases = "strncmp, __GI_strncmp"
		size = "292"
		objfiles = "strncmp@libc.a"
	strings:
		$pattern = { 03 00 52 E3 F0 40 2D E9 00 E0 A0 E1 00 00 A0 93 00 C0 A0 91 3D 00 00 9A 05 00 00 EA 00 00 64 E0 F0 80 BD E8 00 00 61 E0 F0 80 BD E8 00 00 6C E0 F0 80 BD E8 22 51 A0 E1 00 00 DE E5 00 C0 D1 E5 0C 30 50 E0 01 30 A0 13 00 00 50 E3 01 30 83 03 00 00 53 E3 F4 FF FF 1A 01 C0 8E E2 01 00 DE E5 01 40 D1 E5 01 60 8C E2 01 30 86 E2 01 E0 83 E2 04 30 50 E0 01 30 A0 13 00 00 50 E3 01 30 83 03 01 10 81 E2 00 00 53 E3 01 70 81 E2 E2 FF FF 1A 01 00 DC E5 01 10 D1 E5 01 30 50 E0 01 30 A0 13 00 00 50 E3 01 30 83 03 00 00 53 E3 DC FF FF 1A 01 00 D6 E5 01 C0 D7 E5 01 30 87 E2 01 10 83 E2 0C 30 50 E0 01 30 A0 13 }
	condition:
		$pattern
}

rule memalign_53f3f4ca87dba1def3bfcb488b6758ec {
	meta:
		aliases = "memalign"
		size = "168"
		objfiles = "memalign@libc.a"
	strings:
		$pattern = { 03 10 81 E2 F0 41 2D E9 03 80 C1 E3 00 40 A0 E1 80 00 88 E0 ?? ?? ?? EB 00 00 50 E3 F0 81 BD 08 03 00 54 E3 F0 81 BD 98 04 10 80 E0 01 30 41 E2 00 20 64 E2 02 60 03 E0 04 30 10 E5 04 50 40 E2 00 00 56 E1 03 70 85 E0 09 00 00 0A 06 40 60 E0 0B 00 54 E3 0B 30 81 92 02 60 03 90 06 40 60 90 05 10 A0 E1 38 00 9F E5 04 20 A0 E1 ?? ?? ?? EB 04 50 85 E0 08 40 86 E0 1C 30 84 E2 07 00 53 E1 07 40 A0 21 07 20 64 30 14 00 9F 35 04 10 A0 31 ?? ?? ?? 3B 04 30 65 E0 04 30 85 E4 05 00 A0 E1 F0 81 BD E8 ?? ?? ?? ?? }
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
		objfiles = "_udivsi3@libgcc.a, _divsi3@libgcc.a"
	strings:
		$pattern = { 03 40 2D E9 ?? ?? ?? EB 06 40 BD E8 92 00 03 E0 03 10 41 E0 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_wmemchr_7fe271afb973ed2cab9fc3450c57d182 {
	meta:
		aliases = "wmemchr, __GI_wmemchr"
		size = "40"
		objfiles = "wmemchr@libc.a"
	strings:
		$pattern = { 04 00 00 EA 00 30 90 E5 01 00 53 E1 01 20 42 E2 0E F0 A0 01 04 00 80 E2 00 00 52 E3 F8 FF FF 1A 02 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule modff_64a5603c1a91cefd4a4b711d9f2a2368 {
	meta:
		aliases = "modff"
		size = "64"
		objfiles = "modff@libm.a"
	strings:
		$pattern = { 04 00 2D E5 01 01 BD EC 10 40 2D E9 80 81 00 EE 08 D0 4D E2 01 40 A0 E1 0D 20 A0 E1 02 81 2D ED 03 00 BD E8 ?? ?? ?? EB 00 91 9D ED 00 81 00 EE 01 91 00 EE 00 11 84 ED 08 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __fixsfdi_70ea2f2922c4df70dcb00e8a9affbb76 {
	meta:
		aliases = "__fixsfdi"
		size = "56"
		objfiles = "_fixsfdi@libgcc.a"
	strings:
		$pattern = { 04 00 2D E5 01 01 BD EC 18 F1 D0 EE 04 E0 2D E5 01 00 00 4A 04 E0 9D E4 ?? ?? ?? EA 00 81 10 EE 01 01 2D ED 04 00 9D E4 ?? ?? ?? EB 00 00 70 E2 00 10 E1 E2 04 F0 9D E4 }
	condition:
		$pattern
}

rule ldexpf_a5579dfc22c342b3b36eafc73e8b7b26 {
	meta:
		aliases = "frexpf, scalbnf, ldexpf"
		size = "40"
		objfiles = "ldexpf@libm.a, scalbnf@libm.a, frexpf@libm.a"
	strings:
		$pattern = { 04 00 2D E5 01 01 BD EC 80 81 00 EE 01 20 A0 E1 04 E0 2D E5 02 81 2D ED 03 00 BD E8 ?? ?? ?? EB 00 81 00 EE 04 F0 9D E4 }
	condition:
		$pattern
}

rule llrintf_e5565078b4a3ff105054e17ae631933c {
	meta:
		aliases = "lrintf, lroundf, llroundf, ilogbf, llrintf"
		size = "24"
		objfiles = "llroundf@libm.a, ilogbf@libm.a, lrintf@libm.a, llrintf@libm.a, lroundf@libm.a"
	strings:
		$pattern = { 04 00 2D E5 01 01 BD EC 80 81 00 EE 02 81 2D ED 03 00 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule atanf_c386b0b8d6d88ee3aff2ed44cc2cf262 {
	meta:
		aliases = "acoshf, logbf, erff, asinf, log1pf, cosf, sinhf, atanhf, roundf, sqrtf, log10f, coshf, cbrtf, erfcf, asinhf, expf, sinf, tanhf, rintf, fabsf, tanf, floorf, lgammaf, ceilf, truncf, acosf, logf, expm1f, atanf"
		size = "36"
		objfiles = "erfcf@libm.a, rintf@libm.a, sinf@libm.a, fabsf@libm.a, acoshf@libm.a"
	strings:
		$pattern = { 04 00 2D E5 01 01 BD EC 80 81 00 EE 04 E0 2D E5 02 81 2D ED 03 00 BD E8 ?? ?? ?? EB 00 81 00 EE 04 F0 9D E4 }
	condition:
		$pattern
}

rule __fixunssfdi_8231b7f2d5c42af36817bf0501baa619 {
	meta:
		aliases = "__fixunssfdi"
		size = "164"
		objfiles = "_fixunssfdi@libgcc.a"
	strings:
		$pattern = { 04 00 2D E5 01 01 BD EC 80 A1 00 EE 1C 81 9F ED 1D 91 9F ED 80 01 12 EE 11 F1 D0 EE 81 01 20 AE 70 31 10 AE 70 31 10 BE 02 31 83 A2 00 00 53 E3 90 31 01 EE 16 81 9F BD 80 11 01 BE 16 81 9F ED 11 B1 9F ED 80 01 11 EE 80 01 02 EE 13 F1 D0 EE 04 40 2D E5 83 01 20 AE 00 40 A0 E3 03 10 A0 E1 70 31 10 AE 70 31 10 BE 02 31 83 A2 00 40 A0 E3 00 00 A0 E3 03 00 80 E1 04 10 81 E1 10 00 BD E8 0E F0 A0 E1 00 00 F0 3D 00 00 00 00 00 00 E0 41 00 00 00 00 00 00 F0 41 00 00 00 00 00 00 F0 C1 00 00 00 00 }
	condition:
		$pattern
}

rule cargf_2a93a9e9cc2509f4c2a2869bb1a209cd {
	meta:
		aliases = "cargf"
		size = "44"
		objfiles = "cargf@libm.a"
	strings:
		$pattern = { 04 00 2D E5 01 11 BD EC 81 81 00 EE 04 E0 2D E5 02 81 2D ED 03 00 BD E8 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? EB 00 81 00 EE 04 F0 9D E4 }
	condition:
		$pattern
}

rule __powisf2_27050050a215ad03401e498eed2500f0 {
	meta:
		aliases = "__powisf2"
		size = "64"
		objfiles = "_powisf2@libgcc.a"
	strings:
		$pattern = { 04 00 2D E5 01 11 BD EC C1 3F 21 E0 C1 3F 43 E0 01 00 13 E3 01 81 00 1E 09 81 00 0E 02 00 00 EA 01 00 13 E3 01 11 91 EE 01 01 90 1E A3 30 B0 E1 FA FF FF 1A 00 00 51 E3 09 01 B0 BE 0E F0 A0 E1 }
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

rule hstrerror_69471f59a62b67f74488d858297ed925 {
	meta:
		aliases = "hstrerror"
		size = "32"
		objfiles = "herror@libc.a"
	strings:
		$pattern = { 04 00 50 E3 0C 30 9F E5 0C 30 9F 95 00 31 93 97 03 00 A0 E1 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_lock_e6f23b770d44af9eb159c5e287eb5b6a {
	meta:
		aliases = "__pthread_lock"
		size = "8"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { 04 00 80 E2 D6 FF FF EA }
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

rule copysignf_fb06d4f4c1b2fbb6e836ea8dafa001f6 {
	meta:
		aliases = "hypotf, remainderf, nextafterf, fmodf, atan2f, powf, copysignf"
		size = "56"
		objfiles = "powf@libm.a, nextafterf@libm.a, remainderf@libm.a, atan2f@libm.a, hypotf@libm.a"
	strings:
		$pattern = { 04 10 2D E5 01 11 BD EC 81 81 00 EE 02 81 2D ED 0C 00 BD E8 04 00 2D E5 01 01 BD EC 80 81 00 EE 04 E0 2D E5 02 81 2D ED 03 00 BD E8 ?? ?? ?? EB 00 81 00 EE 04 F0 9D E4 }
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

rule _obstack_memory_used_6ca6fdff20a6a6b0ea4b39ab0e705fc5 {
	meta:
		aliases = "_obstack_memory_used"
		size = "40"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { 04 20 90 E5 00 00 A0 E3 03 00 00 EA 00 30 92 E5 03 30 62 E0 04 20 92 E5 03 00 80 E0 00 00 52 E3 F9 FF FF 1A 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_mutex_timedlock_7d63bd8e284ddab6ec5d77db0bae44a5 {
	meta:
		aliases = "pthread_mutex_timedlock"
		size = "252"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { 04 20 91 E5 EC 30 9F E5 03 00 52 E1 70 40 2D E9 01 60 A0 E1 00 40 A0 E1 32 00 00 8A 0C 30 90 E5 03 00 53 E3 03 F1 9F 97 2E 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 10 00 80 E2 00 10 A0 E3 ?? ?? ?? EB 24 00 00 EA 97 FF FF EB 08 30 94 E5 00 00 53 E1 04 30 94 05 00 50 A0 E1 01 30 83 02 00 00 A0 03 05 00 00 0A 10 00 84 E2 05 10 A0 E1 ?? ?? ?? EB 00 30 A0 E3 08 50 84 E5 03 00 A0 E1 04 30 84 E5 70 80 BD E8 87 FF FF EB 08 30 94 E5 00 00 53 E1 00 50 A0 E1 23 00 A0 03 70 80 BD 08 06 20 A0 E1 10 00 84 E2 05 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 A0 13 08 50 84 15 70 80 BD 18 09 00 00 EA }
	condition:
		$pattern
}

rule globfree_160075541114568eaf84686c5688c956 {
	meta:
		aliases = "globfree64, __GI_globfree64, __GI_globfree, globfree"
		size = "84"
		objfiles = "glob@libc.a, glob64@libc.a"
	strings:
		$pattern = { 04 30 90 E5 00 00 53 E3 30 40 2D E9 00 40 A0 E1 00 50 A0 13 30 80 BD 08 05 00 00 EA 0C 00 94 E9 03 30 85 E0 03 31 92 E7 00 00 53 E2 01 50 85 E2 ?? ?? ?? 1B 00 30 94 E5 03 00 55 E1 F6 FF FF 3A 04 00 94 E5 ?? ?? ?? EB 00 30 A0 E3 04 30 84 E5 30 80 BD E8 }
	condition:
		$pattern
}

rule trecurse_1acc97984d5e83ee418282241abcd62e {
	meta:
		aliases = "trecurse"
		size = "148"
		objfiles = "twalk@libc.a"
	strings:
		$pattern = { 04 30 90 E5 00 00 53 E3 70 40 2D E9 01 60 A0 E1 00 40 A0 E1 00 10 A0 E3 02 50 A0 E1 03 00 00 1A 08 30 90 E5 01 00 53 E1 03 10 81 02 15 00 00 0A 04 00 A0 E1 05 20 A0 E1 0F E0 A0 E1 06 F0 A0 E1 04 00 94 E5 00 00 50 E3 06 10 A0 E1 01 20 85 E2 EA FF FF 1B 04 00 A0 E1 01 10 A0 E3 05 20 A0 E1 0F E0 A0 E1 06 F0 A0 E1 08 00 94 E5 00 00 50 E3 06 10 A0 E1 01 20 85 E2 E0 FF FF 1B 04 00 A0 E1 05 20 A0 E1 02 10 A0 E3 0F E0 A0 E1 06 F0 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule pthread_rwlockattr_getpshared_b1929ea2af7ddfbad2e7cee3aaf5d5bb {
	meta:
		aliases = "__GI_pthread_attr_getschedpolicy, pthread_attr_getschedpolicy, pthread_rwlockattr_getpshared"
		size = "16"
		objfiles = "rwlock@libpthread.a, attr@libpthread.a"
	strings:
		$pattern = { 04 30 90 E5 00 00 A0 E3 00 30 81 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule get_cie_cafe7272f04a798ce866e6562d8f6a08 {
	meta:
		aliases = "get_cie"
		size = "16"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { 04 30 90 E5 04 00 80 E2 00 00 63 E0 0E F0 A0 E1 }
	condition:
		$pattern
}

rule wcpcpy_23c792b298ca73e459275d8bd9f51e9a {
	meta:
		aliases = "wcpcpy"
		size = "28"
		objfiles = "wcpcpy@libc.a"
	strings:
		$pattern = { 04 30 91 E4 00 30 80 E5 04 30 90 E4 00 00 53 E3 FA FF FF 1A 04 00 40 E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule _Unwind_SjLj_SetContext_0ff2ef98c5068cd8f437f3a75361a871 {
	meta:
		aliases = "_Unwind_SjLj_SetContext"
		size = "16"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { 04 30 9F E5 00 00 83 E5 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __libc_current_sigrtmax_5762a499c2b87f8f0b5af31c6e1fff14 {
	meta:
		aliases = "__libc_current_sigrtmin, pthread_getconcurrency, _Unwind_SjLj_GetContext, __pthread_getconcurrency, __libc_current_sigrtmax"
		size = "16"
		objfiles = "allocrtsig@libc.a, pthread@libpthread.a, unwind_sjlj@libgcc.a"
	strings:
		$pattern = { 04 30 9F E5 00 00 93 E5 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getwchar_050e28cf6bc58150f630cc4dc9018b17 {
	meta:
		aliases = "getwchar_unlocked, _dl_app_fini_array, _dl_app_init_array, getwchar"
		size = "16"
		objfiles = "getwchar@libc.a, libdl@libdl.a, getwchar_unlocked@libc.a"
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

rule _dl_do_lazy_reloc_36d5f2895b0a330afe608e89c39c20b5 {
	meta:
		aliases = "_dl_do_lazy_reloc"
		size = "56"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 04 30 D2 E5 00 00 53 E3 03 10 A0 E1 00 00 90 E5 00 20 92 E5 05 00 00 0A 16 00 53 E3 02 30 90 07 00 30 83 00 02 30 80 07 00 10 E0 E3 00 10 A0 03 01 00 A0 E1 0E F0 A0 E1 }
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

rule _dl_do_reloc_96daabc0eab2c7163d4d6a2f1f2b582d {
	meta:
		aliases = "_dl_do_reloc"
		size = "384"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 04 C0 92 E5 F0 4F 2D E9 00 20 92 E5 00 A0 A0 E1 00 00 90 E5 2C 94 B0 E1 02 70 80 E0 03 60 A0 E1 24 B0 9D E5 FF 40 0C E2 1E 00 00 0A 09 52 A0 E1 05 00 93 E7 14 00 54 E3 02 30 A0 03 00 30 A0 13 16 00 54 E3 01 30 83 03 00 00 8B E0 0A 20 A0 E1 ?? ?? ?? EB 00 80 50 E2 05 30 86 E0 12 00 00 1A 0C 30 D3 E5 23 32 A0 E1 02 00 53 E3 0D 00 00 0A 05 30 96 E7 F4 20 9F E5 03 30 8B E0 00 20 92 E5 02 00 80 E2 E8 10 9F E5 ?? ?? ?? EB 01 00 A0 E3 01 00 90 EF 01 0A 70 E3 D8 30 9F 85 00 20 60 82 00 20 83 85 00 00 00 8A 00 80 A0 E3 14 00 54 E3 22 00 00 0A 06 00 00 CA 01 00 54 E3 0D 00 00 0A 02 00 54 E3 08 00 00 0A }
	condition:
		$pattern
}

rule __GI_strlcat_8ad4a356c8099e5f5d61ff3c0e46e322 {
	meta:
		aliases = "strlcat, __GI_strlcat"
		size = "92"
		objfiles = "strlcat@libc.a"
	strings:
		$pattern = { 04 D0 4D E2 00 C0 A0 E3 02 00 5C E1 03 00 8D 22 08 00 00 2A 00 30 D0 E5 00 00 53 E3 05 00 00 0A 01 00 80 E2 01 C0 8C E2 F6 FF FF EA 01 C0 8C E2 02 00 5C E1 01 00 80 32 00 30 D1 E5 00 30 C0 E5 00 30 D0 E5 00 00 53 E3 01 10 81 E2 F6 FF FF 1A 0C 00 A0 E1 04 D0 8D E2 0E F0 A0 E1 }
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

rule __GI_clntudp_create_a2173c75b3b2544054146bf439b99156 {
	meta:
		aliases = "clntudp_create, __GI_clntudp_create"
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

rule __libc_posix_fadvise64_f95cba641840df75a058c1ed708b6ef3 {
	meta:
		aliases = "posix_fadvise64, __libc_posix_fadvise64"
		size = "92"
		objfiles = "posix_fadvise64@libc.a"
	strings:
		$pattern = { 04 D0 4D E2 F0 41 2D E9 18 30 8D E5 18 30 8D E2 18 00 93 E8 02 70 A0 E1 04 50 A0 E1 C4 6F A0 E1 C2 8F A0 E1 03 40 A0 E1 02 30 A0 E1 01 20 A0 E1 20 10 9D E5 0E 01 90 EF 01 0A 70 E3 02 00 00 9A 26 00 70 E3 00 00 60 E2 00 00 00 1A 00 00 A0 E3 F0 41 BD E8 04 D0 8D E2 0E F0 A0 E1 }
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

rule clntudp_bufcreate_8e8057dfd567a84daeaa7f108a0a9085 {
	meta:
		aliases = "__GI_clntudp_bufcreate, clntudp_bufcreate"
		size = "620"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { 04 D0 4D E2 F0 4F 2D E9 00 40 A0 E1 40 D0 4D E2 0C 00 A0 E3 64 30 8D E5 01 B0 A0 E1 04 20 8D E5 6C 90 9D E5 ?? ?? ?? EB 70 30 9D E5 03 30 83 E2 03 80 C3 E3 74 30 9D E5 03 30 83 E2 00 60 A0 E1 03 70 C3 E3 64 00 88 E2 00 00 87 E0 ?? ?? ?? EB 00 00 50 E3 00 00 56 13 00 50 A0 E1 00 A0 A0 13 01 A0 A0 03 09 00 00 1A ?? ?? ?? EB E8 31 9F E5 00 40 A0 E1 00 10 93 E5 E0 01 9F E5 ?? ?? ?? EB 0C 30 A0 E3 08 30 84 E5 00 30 84 E5 65 00 00 EA 60 30 80 E2 07 30 83 E0 58 30 80 E5 02 20 D4 E5 03 30 D4 E5 03 34 92 E1 0D 00 00 1A 04 00 A0 E1 0B 10 A0 E1 04 20 9D E5 11 30 A0 E3 ?? ?? ?? EB 00 00 50 E3 57 00 00 0A }
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

rule xdrstdio_putint32_7e89f25fe63f4d34400386d80b8326f6 {
	meta:
		aliases = "xdrstdio_putlong, xdrstdio_putint32"
		size = "88"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 10 91 E5 FF 38 01 E2 FF 2C 01 E2 23 34 A0 E1 02 24 A0 E1 04 D0 4D E2 01 2C 82 E1 21 3C 83 E1 02 30 83 E1 04 20 8D E2 04 30 22 E5 04 10 A0 E3 0C 30 90 E5 01 20 A0 E3 0D 00 A0 E1 ?? ?? ?? EB 01 00 50 E3 00 00 A0 13 01 00 A0 03 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __GI_sigemptyset_d9e5b01e511b6638a8113e7d453ce6cb {
	meta:
		aliases = "sigemptyset, __GI_sigemptyset"
		size = "24"
		objfiles = "sigempty@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 10 A0 E3 80 20 A0 E3 ?? ?? ?? EB 00 00 A0 E3 04 F0 9D E4 }
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

rule putpwent_d55b100ac7cb05b21752f97c21b07a06 {
	meta:
		aliases = "putpwent"
		size = "132"
		objfiles = "putpwent@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 20 A0 E1 01 30 A0 E1 00 00 53 E3 00 00 52 13 01 00 A0 E1 14 D0 4D E2 5C 10 9F E5 04 00 00 1A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 0E 00 00 EA 08 30 92 E5 00 30 8D E5 0C 30 92 E5 04 30 8D E5 10 30 92 E5 08 30 8D E5 14 30 92 E5 0C 30 8D E5 18 30 92 E5 10 30 8D E5 0C 00 92 E8 ?? ?? ?? EB 00 00 50 E3 00 20 E0 B3 00 20 A0 A3 02 00 A0 E1 14 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wcsstr_4783cc83dd3ee7fec373a4b40b1a8513 {
	meta:
		aliases = "wcswcs, wcsstr"
		size = "72"
		objfiles = "wcsstr@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 20 A0 E1 01 30 A0 E1 00 C0 93 E5 00 00 5C E3 04 30 83 E2 04 F0 9D 04 00 E0 92 E5 0E 00 5C E1 04 20 82 E2 F7 FF FF 0A 04 00 80 E2 00 00 5E E3 00 20 A0 E1 01 30 A0 E1 F2 FF FF 1A 00 00 A0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule strtof_53d5be06ff56fa88aac1aa9144b597c7 {
	meta:
		aliases = "__GI_wcstof, __GI_strtof, wcstof, strtof"
		size = "56"
		objfiles = "strtof@libc.a, wcstof@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 20 A0 E3 03 C2 2D ED ?? ?? ?? EB 00 C1 00 EE 02 81 2D ED 0C 00 BD E8 84 81 00 EE 02 81 2D ED 03 00 BD E8 ?? ?? ?? EB 04 81 00 EE 03 C2 BD EC 00 80 BD E8 }
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

rule __GI_xdr_long_a7dfb98fbe1353d807e7b2a7ce0f51c5 {
	meta:
		aliases = "xdr_long, __GI_xdr_long"
		size = "72"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 30 90 E5 00 00 53 E3 03 00 00 1A 04 30 90 E5 0F E0 A0 E1 04 F0 93 E5 04 F0 9D E4 01 00 53 E3 03 00 00 1A 04 30 90 E5 0F E0 A0 E1 00 F0 93 E5 04 F0 9D E4 02 00 53 E3 00 00 A0 13 01 00 A0 03 04 F0 9D E4 }
	condition:
		$pattern
}

rule xdrrec_inline_51cbe260cc187e5f4a019fe750a877eb {
	meta:
		aliases = "xdrrec_inline"
		size = "120"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 30 90 E5 00 00 53 E3 0C C0 90 E5 02 00 00 0A 01 00 53 E3 14 00 00 1A 07 00 00 EA 10 20 8C E2 0C 00 92 E8 01 10 82 E0 03 00 51 E1 02 00 A0 E1 10 10 8C 95 04 F0 9D 94 0B 00 00 EA 34 E0 9C E5 0E 00 51 E1 08 00 00 8A 2C 20 8C E2 0C 00 92 E8 0E E0 61 E0 01 10 82 E0 03 00 51 E1 02 00 A0 E1 2C 10 8C 95 34 E0 8C 95 04 F0 9D 94 00 00 A0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule brk_dbc03bbc6a8590bc0bd34387be8dac2b {
	meta:
		aliases = "__GI_brk, brk"
		size = "60"
		objfiles = "brk@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 30 A0 E1 2D 00 90 EF 03 00 50 E1 20 30 9F E5 00 20 A0 E3 00 00 83 E5 03 00 00 2A ?? ?? ?? EB 0C 30 A0 E3 00 30 80 E5 00 20 E0 E3 02 00 A0 E1 04 F0 9D E4 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ualarm_8f8b7df3a79845a3021ae92ebf91a069 {
	meta:
		aliases = "ualarm"
		size = "80"
		objfiles = "ualarm@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 30 A0 E3 20 D0 4D E2 10 20 8D E2 04 10 8D E5 0C 00 8D E5 0D 10 A0 E1 03 00 A0 E1 00 30 8D E5 08 30 8D E5 ?? ?? ?? EB 00 00 50 E3 18 10 9D A5 10 20 9F A5 1C 30 9D A5 00 00 E0 E3 91 32 20 A0 20 D0 8D E2 00 80 BD E8 40 42 0F 00 }
	condition:
		$pattern
}

rule __heap_alloc_at_2e43b0b939203742a2059402ed5a76c7 {
	meta:
		aliases = "__heap_alloc_at"
		size = "140"
		objfiles = "heap_alloc_at@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 C0 90 E5 00 E0 A0 E1 1A 00 00 EA 00 00 9C E5 0C 30 60 E0 0C 30 83 E2 01 00 53 E1 14 00 00 8A 16 00 00 1A 03 30 82 E2 03 20 C3 E3 02 00 50 E1 12 00 00 3A 2C 30 82 E2 03 00 50 E1 00 30 62 20 00 30 8C 25 02 00 A0 21 04 F0 9D 24 04 20 9C E5 00 00 52 E3 08 30 9C 15 08 30 82 15 08 20 9C E5 04 30 9C E5 00 00 52 E3 04 30 82 15 00 30 8E 05 04 F0 9D E4 04 C0 9C E5 00 00 5C E3 E2 FF FF 1A 00 00 A0 E3 04 F0 9D E4 }
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

rule __GI_svc_getreq_1c2160acd17183472566472683068d39 {
	meta:
		aliases = "svc_getreq, __GI_svc_getreq"
		size = "68"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 C0 A0 E1 80 D0 4D E2 00 20 A0 E3 01 00 00 EA 00 30 A0 E3 80 30 01 E5 80 30 8D E2 1F 00 52 E3 02 11 83 E0 01 20 82 E2 F8 FF FF 9A 0D 00 A0 E1 00 C0 8D E5 ?? ?? ?? EB 80 D0 8D E2 00 80 BD E8 }
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

rule getopt_427c5a3de4a2b9d3a5f1e7f43531ff05 {
	meta:
		aliases = "getopt"
		size = "36"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 C0 A0 E3 08 D0 4D E2 0C 30 A0 E1 00 C0 8D E5 04 C0 8D E5 ?? ?? ?? EB 08 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __length_dotted_41c4e62dbda82877091a58dadcc25862 {
	meta:
		aliases = "__length_dotted"
		size = "76"
		objfiles = "lengthd@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 E0 50 E2 00 00 E0 03 04 F0 9D 04 01 00 00 EA 01 00 80 E2 09 00 00 EA 01 20 A0 E1 01 00 00 EA C0 00 5C E3 F9 FF FF 0A 02 30 DE E7 01 00 82 E2 00 00 53 E3 C0 C0 03 E2 03 20 80 E0 F7 FF FF 1A 00 00 61 E0 04 F0 9D E4 }
	condition:
		$pattern
}

rule __GI_wcsspn_34fc412af6f95f977ecc2a41a86f2114 {
	meta:
		aliases = "wcsspn, __GI_wcsspn"
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

rule __GI_stpncpy_776966f73a29450c77aa1fd3e3294f5a {
	meta:
		aliases = "stpncpy, __GI_stpncpy"
		size = "68"
		objfiles = "stpncpy@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 E0 A0 E1 0E C0 A0 E1 01 00 A0 E1 05 00 00 EA 00 30 D0 E5 00 30 CC E5 00 30 DC E5 00 00 53 E3 01 00 80 12 01 C0 8C E2 00 00 52 E3 01 20 42 E2 F6 FF FF 1A 00 00 61 E0 00 00 8E E0 04 F0 9D E4 }
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

rule a64l_2ed7b2d8698d7374ceb47fa9dce43b5c {
	meta:
		aliases = "a64l"
		size = "84"
		objfiles = "a64l@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 E0 A0 E3 00 10 A0 E1 0E C0 A0 E1 06 00 80 E2 00 30 D1 E5 2E 20 43 E2 4C 00 52 E3 01 10 81 E2 07 00 00 8A 20 30 9F E5 02 30 D3 E7 40 00 53 E3 03 00 00 0A 00 00 51 E1 13 EC 8E E1 06 C0 8C E2 F2 FF FF 1A 0E 00 A0 E1 04 F0 9D E4 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule strspn_284d2b8fb90d41061f022014f25065b0 {
	meta:
		aliases = "__GI_strspn, strspn"
		size = "80"
		objfiles = "strspn@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 E0 A0 E3 0A 00 00 EA 0C 00 52 E1 04 00 00 0A 00 C0 D3 E5 00 00 5C E3 01 30 83 E2 F9 FF FF 1A 07 00 00 EA 00 00 52 E3 05 00 00 0A 01 E0 8E E2 01 00 80 E2 00 20 D0 E5 00 00 52 E3 01 30 A0 11 F2 FF FF 1A 0E 00 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule read_sleb128_b038cde7faafd5b0953653836de8fa2c {
	meta:
		aliases = "read_sleb128"
		size = "72"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a, unwind_c@libgcc.a"
	strings:
		$pattern = { 04 E0 2D E5 00 E0 A0 E3 0E C0 A0 E1 01 20 D0 E4 7F 30 02 E2 80 00 12 E3 13 EC 8E E1 07 C0 8C E2 F9 FF FF 1A 1F 00 5C E3 04 00 00 8A 40 00 12 E3 01 30 A0 13 13 3C A0 11 00 30 63 12 03 E0 8E 11 00 E0 81 E5 04 F0 9D E4 }
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

rule __sysv_signal_5717603ce58c89e0080fbf7925710157 {
	meta:
		aliases = "sysv_signal, __sysv_signal"
		size = "124"
		objfiles = "sysv_signal@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 00 71 E3 00 00 50 13 46 DF 4D E2 03 00 00 DA 40 00 50 E3 20 C0 A0 D3 8C 10 8D D5 06 00 00 DA ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 0D 00 00 EA 00 30 A0 E3 88 30 02 E5 01 C0 5C E2 46 3F 8D E2 0C 21 83 E0 F9 FF FF 5A 0D 20 A0 E1 0E 32 A0 E3 8C 10 8D E2 10 31 8D E5 ?? ?? ?? EB 00 00 50 E3 00 20 9D A5 00 20 E0 B3 02 00 A0 E1 46 DF 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule clnttcp_control_ed77c4797aaa12f09d5537033986c655 {
	meta:
		aliases = "clnttcp_control"
		size = "404"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 10 41 E2 02 C0 A0 E1 08 00 90 E5 0E 00 51 E3 01 F1 9F 97 0E 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 E0 A0 E3 4A 00 00 EA 01 30 A0 E3 03 E0 A0 E1 01 00 00 EA 01 E0 A0 E3 00 30 A0 E3 04 30 80 E5 43 00 00 EA 0A 00 92 E8 01 20 A0 E3 02 E0 A0 E1 0C 30 80 E5 08 10 80 E5 10 20 80 E5 3C 00 00 EA 0C 20 90 E5 08 30 90 E5 01 E0 A0 E3 00 30 8C E5 04 20 8C E5 36 00 00 EA 14 30 80 E2 0F 00 93 E8 01 E0 A0 E3 0F 00 8C E8 31 00 00 EA 00 30 90 E5 }
	condition:
		$pattern
}

rule clntudp_control_7df132dc77eb389bd7111a5ba117178d {
	meta:
		aliases = "clntudp_control"
		size = "452"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 10 41 E2 02 C0 A0 E1 08 00 90 E5 0E 00 51 E3 01 F1 9F 97 0E 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 E0 A0 E3 56 00 00 EA 01 30 A0 E3 03 E0 A0 E1 01 00 00 EA 01 E0 A0 E3 00 30 A0 E3 04 30 80 E5 4F 00 00 EA 04 20 92 E5 00 30 9C E5 01 E0 A0 E3 24 30 80 E5 28 20 80 E5 49 00 00 EA 28 20 90 E5 24 30 90 E5 07 00 00 EA 04 20 92 E5 00 30 9C E5 01 E0 A0 E3 1C 30 80 E5 20 20 80 E5 40 00 00 EA 20 20 90 E5 1C 30 90 E5 01 E0 A0 E3 00 30 8C E5 }
	condition:
		$pattern
}

rule clntunix_control_aa81cf50da7ba43cc0a981a349cbb49f {
	meta:
		aliases = "clntunix_control"
		size = "400"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 10 41 E2 02 E0 A0 E1 08 C0 90 E5 0E 00 51 E3 01 F1 9F 97 0E 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 A0 E3 04 F0 9D E4 01 30 A0 E3 03 00 A0 E1 01 00 00 EA 01 00 A0 E3 00 30 A0 E3 04 30 8C E5 04 F0 9D E4 04 20 92 E5 00 30 9E E5 01 00 A0 E3 08 30 8C E5 0C 20 8C E5 04 F0 9D E4 0C 20 9C E5 08 30 9C E5 01 00 A0 E3 00 30 8E E5 04 20 8E E5 04 F0 9D E4 02 00 A0 E1 14 10 8C E2 70 20 A0 E3 ?? ?? ?? EB 01 00 A0 E3 04 F0 9D E4 00 30 9C E5 }
	condition:
		$pattern
}

rule svcerr_auth_291f45ce3c28f458eb2510a1a7c5e094 {
	meta:
		aliases = "__GI_svcerr_auth, svcerr_auth"
		size = "52"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 30 A0 E3 30 D0 4D E2 10 10 8D E5 0C 30 8D E5 04 30 8D E5 08 30 8D E5 0D 10 A0 E1 08 30 90 E5 0F E0 A0 E1 0C F0 93 E5 30 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule sigignore_00a1ce0d37765dba87afe9bbf8358039 {
	meta:
		aliases = "sigignore"
		size = "76"
		objfiles = "sigignore@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 30 A0 E3 8C D0 4D E2 20 10 A0 E3 00 30 8D E5 01 00 00 EA 00 30 A0 E3 88 30 02 E5 01 10 51 E2 8C 30 8D E2 01 21 83 E0 F9 FF FF 5A 00 30 A0 E3 03 20 A0 E1 0D 10 A0 E1 84 30 8D E5 ?? ?? ?? EB 8C D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __re_match_d7c521c64ea13c5d1f24f990991f3b0e {
	meta:
		aliases = "re_match, __re_match"
		size = "60"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 C0 A0 E1 10 D0 4D E2 00 10 A0 E3 04 30 8D E5 0C 30 A0 E1 14 C0 9D E5 02 E0 A0 E1 01 20 A0 E1 08 C0 8D E5 0C E0 8D E5 00 E0 8D E5 7A F8 FF EB 10 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __re_search_de99b3bc9eb29b2ed745888652e52299 {
	meta:
		aliases = "re_search, __re_search"
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

rule __GI_sigsetmask_d752458e905dad54887444c37f29b1df {
	meta:
		aliases = "sigsetmask, __GI_sigsetmask"
		size = "72"
		objfiles = "sigsetmask@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 DC 4D E2 80 00 8D E5 84 10 8D E2 1E 20 A0 E3 00 30 A0 E3 01 20 52 E2 04 30 81 E4 FB FF FF 5A 80 10 8D E2 0D 20 A0 E1 02 00 A0 E3 ?? ?? ?? EB 00 00 50 E3 00 00 9D A5 00 00 E0 B3 01 DC 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __GI_sigblock_9cff1bfa60288c556342c1f723a774ef {
	meta:
		aliases = "sigblock, __GI_sigblock"
		size = "68"
		objfiles = "sigblock@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 01 DC 4D E2 80 00 8D E5 84 20 8D E2 1E 30 A0 E3 00 00 A0 E3 01 30 53 E2 04 00 82 E4 FB FF FF 5A 80 10 8D E2 0D 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 9D A5 00 00 E0 B3 01 DC 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __re_compile_pattern_7ff9bec6c95cb78c0acfb41f601dfa8b {
	meta:
		aliases = "re_compile_pattern, __re_compile_pattern"
		size = "104"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 02 30 A0 E1 1C 20 D2 E5 06 20 C2 E3 1C 20 C3 E5 1C 20 D3 E5 10 20 C2 E3 1C 20 C3 E5 1C 20 D3 E5 82 2C E0 E1 A2 2C E0 E1 1C 20 C3 E5 24 20 9F E5 00 20 92 E5 02 F7 FF EB 00 00 50 E3 18 30 9F 15 00 20 A0 E1 00 21 93 17 10 30 9F 15 03 20 82 10 02 00 A0 E1 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
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

rule byte_insert_op1_6333ad624b85da6ee2699f27578b1b22 {
	meta:
		aliases = "byte_insert_op1"
		size = "44"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 03 C0 83 E2 01 E0 A0 E1 03 10 A0 E1 01 00 00 EA 01 30 71 E5 01 30 6C E5 0E 00 51 E1 FB FF FF 1A 04 E0 9D E4 E6 FF FF EA }
	condition:
		$pattern
}

rule memccpy_e5b612ced953410d8338b33f1a5a9d09 {
	meta:
		aliases = "__GI_memccpy, memccpy"
		size = "60"
		objfiles = "memccpy@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 03 C0 A0 E1 01 C0 4C E2 01 00 7C E3 FF E0 02 E2 06 00 00 0A 00 30 D1 E5 00 30 C0 E5 01 30 D0 E4 0E 00 53 E1 01 10 81 E2 04 F0 9D 04 F4 FF FF EA 00 00 A0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule re_set_registers_8870f530712982eb5f203953708899a9 {
	meta:
		aliases = "__re_set_registers, re_set_registers"
		size = "68"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 03 E0 A0 E1 1C 30 D0 E5 00 C0 52 E2 04 20 C3 E3 06 30 C3 E3 04 30 9D 15 02 20 82 E3 1C 20 C0 15 1C 30 C0 05 08 30 81 15 00 C0 81 15 04 E0 81 15 04 C0 81 05 00 C0 81 05 08 C0 81 05 04 F0 9D E4 }
	condition:
		$pattern
}

rule _dl_parse_dynamic_info_cb8979333d53034667c999cd11cf3409 {
	meta:
		aliases = "_dl_parse_dynamic_info"
		size = "292"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 04 E0 2D E5 03 E0 A0 E1 29 00 00 EA 21 00 5C E3 19 00 00 CA 04 30 90 E5 0C 31 81 E7 00 30 90 E5 15 00 5C E3 04 20 80 05 18 00 53 E3 1D 00 00 0A 1E 00 53 E3 02 00 00 1A 04 30 90 E5 08 00 13 E3 17 00 00 EA 16 00 53 E3 01 30 A0 03 58 30 81 05 16 00 00 0A 1D 00 53 E3 04 00 00 0A 0F 00 53 E3 12 00 00 1A 74 30 91 E5 00 00 53 E3 0F 00 00 0A 00 30 A0 E3 3C 30 81 E5 0C 00 00 EA 19 02 7C E3 0A 00 00 CA 69 02 7C E3 04 30 90 05 88 30 81 05 06 00 00 0A 59 02 7C E3 04 00 00 1A 04 30 90 E5 01 00 13 E3 01 00 00 0A 01 30 A0 E3 60 30 81 E5 08 00 80 E2 00 C0 90 E5 00 00 5C E3 D2 FF FF 1A 10 30 91 E5 00 00 53 E3 }
	condition:
		$pattern
}

rule __GI_wcsrtombs_bf53f3b73ff890a3d97f7f3c4b853e0c {
	meta:
		aliases = "wcsrtombs, __GI_wcsrtombs"
		size = "32"
		objfiles = "wcsrtombs@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 00 30 8D E5 02 30 A0 E1 00 20 E0 E3 ?? ?? ?? EB 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule getw_294fd728af615d4028cb3e0b8ded395f {
	meta:
		aliases = "getw"
		size = "48"
		objfiles = "getw@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 00 30 A0 E1 04 10 A0 E3 0D 00 A0 E1 01 20 A0 E3 ?? ?? ?? EB 00 00 50 E3 00 00 E0 E3 00 00 9D 15 04 D0 8D E2 00 80 BD E8 }
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

rule putwc_unlocked_43bac29c7cc3b325c5868d4a9081c576 {
	meta:
		aliases = "fputwc_unlocked, __GI_fputwc_unlocked, putwc_unlocked"
		size = "52"
		objfiles = "fputwc_unlocked@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 04 30 8D E2 04 00 23 E5 01 20 A0 E1 0D 00 A0 E1 01 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 00 00 E0 E3 00 00 9D 15 04 D0 8D E2 00 80 BD E8 }
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

rule inet_addr_c0d5cf6b180e5f71f276bd817d3cf53b {
	meta:
		aliases = "__GI_inet_addr, inet_addr"
		size = "36"
		objfiles = "inet_makeaddr@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 0D 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 E0 E3 00 00 9D 15 04 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule tgamma_67823d1947e322035288e5f8223757b3 {
	meta:
		aliases = "__GI_tgamma, tgamma"
		size = "36"
		objfiles = "w_tgamma@libm.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 0D 20 A0 E1 ?? ?? ?? EB 00 30 9D E5 00 00 53 E3 80 81 10 BE 04 D0 8D E2 00 80 BD E8 }
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

rule getspent_1130adb5b3a29e916cfe3279f1af88f3 {
	meta:
		aliases = "getpwent, getgrent, getspent"
		size = "48"
		objfiles = "getgrent@libc.a, getpwent@libc.a, getspent@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 18 10 9F E5 01 2C A0 E3 0D 30 A0 E1 10 00 9F E5 ?? ?? ?? EB 00 00 9D E5 04 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_tcgetpgrp_cb62d8b68138f59bd18d9b47be7be5d6 {
	meta:
		aliases = "tcgetpgrp, __GI_tcgetpgrp"
		size = "44"
		objfiles = "tcgetpgrp@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 18 10 9F E5 0D 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 E0 E3 00 00 9D A5 04 D0 8D E2 00 80 BD E8 0F 54 00 00 }
	condition:
		$pattern
}

rule getservent_e22010de886deedde13d7da978f48acc {
	meta:
		aliases = "getservent"
		size = "60"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 04 D0 4D E2 5E FF FF EB 1C 30 9F E5 1C 20 9F E5 00 10 93 E5 18 00 9F E5 0D 30 A0 E1 ?? ?? ?? EB 00 00 9D E5 04 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? 8D 10 00 00 ?? ?? ?? ?? }
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

rule call___do_global_ctors_aux_997de91c60dfeaa7966cf399b0caa4a3 {
	meta:
		aliases = "call_frame_dummy, call___do_global_ctors_aux"
		size = "8"
		objfiles = "crtendS, crtend, crtbeginT, crtbegin, crtbeginS"
	strings:
		$pattern = { 04 E0 2D E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule call___do_global_dtors_aux_c2685b7cac6e187ace2fd786b945821c {
	meta:
		aliases = "call___do_global_dtors_aux"
		size = "136"
		objfiles = "crtbeginS"
	strings:
		$pattern = { 04 E0 2D E5 04 F0 9D E4 00 44 2D E9 54 A0 9F E5 54 30 9F E5 0A A0 8F E0 03 30 9A E7 4C 00 9F E5 4C 10 9F E5 00 00 53 E3 00 00 8A E0 01 10 8A E0 0F E0 A0 11 03 F0 A0 11 38 20 9F E5 02 30 9A E7 00 00 53 E3 02 00 8A E0 00 84 BD 08 28 30 9F E5 03 30 9A E7 00 00 53 E3 00 84 BD 08 0F E0 A0 E1 03 F0 A0 E1 00 84 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 E0 2D E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule call___do_global_dtors_aux_6f94874d10abccbb5d36a8fd6fc3760e {
	meta:
		aliases = "call___do_global_dtors_aux"
		size = "104"
		objfiles = "crtbeginT, crtbegin"
	strings:
		$pattern = { 04 E0 2D E5 04 F0 9D E4 3C 30 9F E5 00 00 53 E3 04 E0 2D E5 34 00 9F E5 34 10 9F E5 0F E0 A0 11 03 F0 A0 11 2C 00 9F E5 00 30 90 E5 00 00 53 E3 24 30 9F E5 04 F0 9D 04 00 00 53 E3 04 F0 9D 04 0F E0 A0 E1 03 F0 A0 E1 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 E0 2D E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule __ieee754_scalb_872d2f97792b82a16b016b9b41915c3a {
	meta:
		aliases = "__ieee754_scalb"
		size = "240"
		objfiles = "e_scalb@libm.a"
	strings:
		$pattern = { 04 E0 2D E5 06 42 6D ED 0C 00 2D E9 02 C1 BD EC 03 00 2D E9 02 D1 BD EC ?? ?? ?? EB 00 00 50 E3 0B 00 00 1A 02 C1 2D ED 03 00 BD E8 ?? ?? ?? EB 00 00 50 E3 06 00 00 1A 02 C1 2D ED 03 00 BD E8 ?? ?? ?? EB 00 00 50 E3 06 00 00 1A 18 F1 D4 EE 01 00 00 DA 84 01 15 EE 1C 00 00 EA 84 81 10 EE 80 01 45 EE 19 00 00 EA 02 C1 2D ED 03 00 BD E8 ?? ?? ?? EB 14 F1 90 EE 84 01 24 1E 80 01 40 1E 12 00 00 1A 13 81 9F ED 10 F1 D4 EE 02 D1 2D CD 03 00 BD C8 4C 20 9F C5 05 00 00 CA 0F 81 9F ED 10 F1 D4 EE 05 00 00 5A 02 D1 2D ED 03 00 BD E8 34 20 9F E5 06 42 FD EC 04 E0 9D E4 ?? ?? ?? EA 02 D1 2D ED 03 00 BD E8 }
	condition:
		$pattern
}

rule __GI_fmin_666d93266f1fea91cbace6fe8107ec0d {
	meta:
		aliases = "fmin, __GI_fmin"
		size = "80"
		objfiles = "s_fmin@libm.a"
	strings:
		$pattern = { 04 E0 2D E5 06 42 6D ED 0C 00 2D E9 02 D1 BD EC 03 00 2D E9 02 C1 BD EC ?? ?? ?? EB 00 00 50 E3 02 D1 2D ED 03 00 BD E8 05 00 00 0A ?? ?? ?? EB 00 00 50 E3 01 00 00 0A 15 F1 D4 EE 00 00 00 4A 85 C1 00 EE 84 81 00 EE 06 42 FD EC 00 80 BD E8 }
	condition:
		$pattern
}

rule fmax_7b45ca3804dd4155ad6a7bf522872bae {
	meta:
		aliases = "__GI_fmax, fmax"
		size = "80"
		objfiles = "s_fmax@libm.a"
	strings:
		$pattern = { 04 E0 2D E5 06 42 6D ED 0C 00 2D E9 02 D1 BD EC 03 00 2D E9 02 C1 BD EC ?? ?? ?? EB 00 00 50 E3 02 D1 2D ED 03 00 BD E8 05 00 00 0A ?? ?? ?? EB 00 00 50 E3 01 00 00 0A 15 F1 D4 EE 00 00 00 CA 85 C1 00 EE 84 81 00 EE 06 42 FD EC 00 80 BD E8 }
	condition:
		$pattern
}

rule __GI_fdim_bcb08eca25aa434003834c451771a833 {
	meta:
		aliases = "fdim, __GI_fdim"
		size = "68"
		objfiles = "s_fdim@libm.a"
	strings:
		$pattern = { 04 E0 2D E5 06 42 6D ED 0C 00 2D E9 02 D1 BD EC 03 00 2D E9 02 C1 BD EC ?? ?? ?? EB 01 00 50 E3 05 81 9F ED 02 00 00 9A 15 F1 D4 EE 88 81 00 EE 85 01 24 CE 06 42 FD EC 00 80 BD E8 00 00 F0 7F 00 00 00 00 }
	condition:
		$pattern
}

rule clntudp_freeres_dd0418064793c5ba918787999e268bbb {
	meta:
		aliases = "clntudp_freeres"
		size = "40"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 08 00 90 E5 02 30 A0 E3 38 30 80 E5 01 30 A0 E1 38 00 80 E2 02 10 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule clnttcp_freeres_3404482161b4098f69a9ab6bb0bbe641 {
	meta:
		aliases = "clnttcp_freeres"
		size = "40"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 08 00 90 E5 02 30 A0 E3 4C 30 80 E5 01 30 A0 E1 4C 00 80 E2 02 10 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule clntunix_freeres_177310d07ba02c5e5cc7ccd6ebe006dd {
	meta:
		aliases = "clntunix_freeres"
		size = "40"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 08 00 90 E5 02 30 A0 E3 AC 30 80 E5 01 30 A0 E1 AC 00 80 E2 02 10 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule fgetspent_782ead4dc851d14a304b763550b392bd {
	meta:
		aliases = "fgetgrent, sgetspent, getgrgid, getpwnam, getgrnam, getspnam, getpwuid, fgetpwent, fgetspent"
		size = "52"
		objfiles = "fgetspent@libc.a, getgrnam@libc.a, getgrgid@libc.a, fgetgrent@libc.a, fgetpwent@libc.a"
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

rule __GI_getdtablesize_33840479c977229122907e50f1d40f55 {
	meta:
		aliases = "getdtablesize, __GI_getdtablesize"
		size = "40"
		objfiles = "getdtablesize@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 08 D0 4D E2 0D 10 A0 E1 07 00 A0 E3 ?? ?? ?? EB 00 00 50 E3 01 0C A0 E3 00 00 9D A5 08 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule erand48_fd375dfbffdaadc8216fb91d0c73a1b5 {
	meta:
		aliases = "erand48"
		size = "36"
		objfiles = "erand48@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 08 D0 4D E2 10 10 9F E5 0D 20 A0 E1 ?? ?? ?? EB 00 81 9D ED 08 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? }
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

rule __gthread_mutex_lock_6de4a177e5599d1717ee99c55f58ac5a {
	meta:
		aliases = "__gthread_mutex_unlock, __gthread_mutex_lock"
		size = "28"
		objfiles = "gthr_gnat@libgcc.a"
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

rule __ivaliduser_72bb803fc83960bf3c5f15842169c62b {
	meta:
		aliases = "__ivaliduser"
		size = "32"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 10 C0 9F E5 04 D0 4D E2 00 C0 8D E5 1B FF FF EB 04 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? }
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

rule clock_39d4e1725d73c64af7df2ad4f44ac13f {
	meta:
		aliases = "clock"
		size = "52"
		objfiles = "clock@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 10 D0 4D E2 0D 00 A0 E1 ?? ?? ?? EB 04 20 9D E5 00 30 9D E5 02 30 83 E0 0C 20 9F E5 93 02 00 E0 3E 01 C0 E3 10 D0 8D E2 00 80 BD E8 10 27 00 00 }
	condition:
		$pattern
}

rule xdrmem_getint32_71a4a45ff3f12f673b9c2e3e13bbf510 {
	meta:
		aliases = "xdrmem_getlong, xdrmem_getint32"
		size = "96"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 14 30 90 E5 03 00 53 E3 04 20 43 E2 00 E0 A0 E3 01 C0 A0 E1 0E 00 00 9A 0C 30 90 E5 14 20 80 E5 00 10 93 E5 FF 38 01 E2 FF 2C 01 E2 23 34 A0 E1 02 24 A0 E1 01 2C 82 E1 21 3C 83 E1 02 30 83 E1 00 30 8C E5 0C 30 90 E5 04 30 83 E2 0C 30 80 E5 01 E0 A0 E3 0E 00 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule mrand48_86fdf4ee84ebc235f19e8e735c9d8875 {
	meta:
		aliases = "lrand48, mrand48"
		size = "40"
		objfiles = "lrand48@libc.a, mrand48@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 18 00 9F E5 04 D0 4D E2 00 10 A0 E1 0D 20 A0 E1 ?? ?? ?? EB 00 00 9D E5 04 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule drand48_913c2ca7246500636b220ba4b73deead {
	meta:
		aliases = "drand48"
		size = "40"
		objfiles = "drand48@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 18 00 9F E5 08 D0 4D E2 00 10 A0 E1 0D 20 A0 E1 ?? ?? ?? EB 00 81 9D ED 08 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? }
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

rule sigandset_47dbeb51ff8f3b4e84dc02e8e0f19513 {
	meta:
		aliases = "sigandset"
		size = "48"
		objfiles = "sigandset@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 20 C0 A0 E3 02 E0 A0 E1 03 00 00 EA 0C 31 91 E7 0C 21 9E E7 02 30 03 E0 0C 31 80 E7 01 C0 5C E2 F9 FF FF 5A 00 00 A0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule sigorset_aae5b652d7e480f0f662805eabbf9422 {
	meta:
		aliases = "sigorset"
		size = "48"
		objfiles = "sigorset@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 20 C0 A0 E3 02 E0 A0 E1 03 00 00 EA 0C 31 91 E7 0C 21 9E E7 02 30 83 E1 0C 31 80 E7 01 C0 5C E2 F9 FF FF 5A 00 00 A0 E3 04 F0 9D E4 }
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

rule svcunix_freeargs_d342d7e6cf1a8094dd420a95939f141a {
	meta:
		aliases = "svctcp_freeargs, svcunix_freeargs"
		size = "40"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 2C 00 90 E5 02 30 A0 E3 08 30 80 E5 01 30 A0 E1 08 00 80 E2 02 10 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule svcunix_stat_5f395b6b7efede851f9ef83a3546e0ee {
	meta:
		aliases = "svctcp_stat, svcunix_stat"
		size = "48"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 2C 30 90 E5 08 00 83 E2 00 30 93 E5 00 00 53 E3 03 00 00 0A ?? ?? ?? EB 00 00 50 E3 02 30 A0 13 01 30 A0 03 03 00 A0 E1 04 F0 9D E4 }
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

rule svcudp_freeargs_47d022cc5c8aad2b90a348da9cdf5b41 {
	meta:
		aliases = "svcudp_freeargs"
		size = "40"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 30 00 90 E5 02 30 A0 E3 08 30 80 E5 01 30 A0 E1 08 00 80 E2 02 10 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule isatty_801c6a7883f0db4852f8793486b982e2 {
	meta:
		aliases = "__GI_isatty, isatty"
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

rule direxists_7f941113bef3b168e4932ac85ed35bf1 {
	meta:
		aliases = "direxists"
		size = "56"
		objfiles = "tempname@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 58 D0 4D E2 0D 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 A0 E3 04 00 00 1A 10 30 9D E5 0F 3A 03 E2 01 09 53 E3 00 00 A0 13 01 00 A0 03 58 D0 8D E2 00 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_manager_sighandler_7c668205be25a9c60fa27ece1b8a5ccb {
	meta:
		aliases = "__pthread_manager_sighandler"
		size = "144"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { 04 E0 2D E5 78 30 9F E5 00 30 93 E5 00 00 53 E3 94 D0 4D E2 00 30 A0 13 03 00 00 1A 64 30 9F E5 00 30 93 E5 00 30 53 E2 01 30 A0 13 00 00 53 E3 4C 30 9F E5 01 20 A0 E3 00 20 83 E5 0E 00 00 0A 00 30 A0 E3 00 30 8D E5 06 30 83 E2 04 30 8D E5 34 30 9F E5 0D 10 A0 E1 00 00 93 E5 94 20 A0 E3 ?? ?? ?? EB 01 00 70 E3 03 00 00 1A ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 F4 FF FF 0A 94 D0 8D E2 00 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
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

rule __GI_sysconf_20bb0d87d3f40a670dc581a9b013b535 {
	meta:
		aliases = "sysconf, __GI_sysconf"
		size = "944"
		objfiles = "sysconf@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 95 00 50 E3 00 F1 9F 97 97 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __length_question_cd1493930890233b6f7653f745af79ea {
	meta:
		aliases = "__length_question"
		size = "20"
		objfiles = "lengthq@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 ?? ?? ?? EB 00 00 50 E3 04 00 80 A2 04 F0 9D E4 }
	condition:
		$pattern
}

rule __GI_ftell_bf951bc17031556e0a73a0c404c867fd {
	meta:
		aliases = "ftello, ftell, __GI_ftell"
		size = "60"
		objfiles = "ftello@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 ?? ?? ?? EB 00 20 A0 E1 C2 3F A0 E1 00 00 52 E1 00 C0 A0 E1 01 00 00 1A 01 00 53 E1 03 00 00 0A ?? ?? ?? EB 4B 30 A0 E3 00 30 80 E5 00 C0 E0 E3 0C 00 A0 E1 04 F0 9D E4 }
	condition:
		$pattern
}

rule __GI_ctime_c4ff7ef54e5728e438def535189f6899 {
	meta:
		aliases = "ctime, __GI_ctime"
		size = "16"
		objfiles = "ctime@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 ?? ?? ?? EB 04 E0 9D E4 ?? ?? ?? EA }
	condition:
		$pattern
}

rule clnt_pcreateerror_8213424d9423719eb0f7c5bff68b7e51 {
	meta:
		aliases = "__GI_clnt_perror, clnt_perrno, clnt_perror, clnt_pcreateerror"
		size = "28"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 ?? ?? ?? EB 08 30 9F E5 00 10 93 E5 04 E0 9D E4 ?? ?? ?? EA ?? ?? ?? ?? }
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

rule __rpc_thread_createerr_3da7f22837d39c23c8cc8e54e3eb035e {
	meta:
		aliases = "__GI___rpc_thread_createerr, __rpc_thread_createerr"
		size = "40"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 ?? ?? ?? EB 10 30 9F E5 10 20 9F E5 03 00 50 E1 80 20 80 12 02 00 A0 E1 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __rpc_thread_svc_pollfd_7f392b161a6699f27c12c5d2f3980835 {
	meta:
		aliases = "__GI___rpc_thread_svc_pollfd, __rpc_thread_svc_pollfd"
		size = "40"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 ?? ?? ?? EB 10 30 9F E5 10 20 9F E5 03 00 50 E1 90 20 80 12 02 00 A0 E1 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI___rpc_thread_svc_max_poll_6eee1ce33fd267fca8563708438b4060 {
	meta:
		aliases = "__rpc_thread_svc_max_pollfd, __GI___rpc_thread_svc_max_pollfd"
		size = "40"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 ?? ?? ?? EB 10 30 9F E5 10 20 9F E5 03 00 50 E1 94 20 80 12 02 00 A0 E1 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule get_kernel_syms_a40f80df3b43c7c733efb6877e131639 {
	meta:
		aliases = "create_module, sem_close, sem_unlink, get_kernel_syms"
		size = "24"
		objfiles = "semaphore@libpthread.a, create_module@libc.a, get_kernel_syms@libc.a"
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

rule get_fde_encoding_6b86717b5ef6bf4ff16b2dd9f271895e {
	meta:
		aliases = "get_fde_encoding"
		size = "16"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { 04 E0 2D E5 AC FD FF EB 04 E0 9D E4 C6 FF FF EA }
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

rule __GI_sigfillset_b763fd66935e9ea754b153daaac547d7 {
	meta:
		aliases = "sigfillset, __GI_sigfillset"
		size = "24"
		objfiles = "sigfillset@libc.a"
	strings:
		$pattern = { 04 E0 2D E5 FF 10 A0 E3 80 20 A0 E3 ?? ?? ?? EB 00 00 A0 E3 04 F0 9D E4 }
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

rule __ieee754_jn_ddd2b22e0cb3dfcd50fd9a8d036d7d27 {
	meta:
		aliases = "__ieee754_jn"
		size = "980"
		objfiles = "e_jn@libm.a"
	strings:
		$pattern = { 06 00 2D E9 02 81 BD EC 70 40 2D E9 01 30 A0 E1 02 40 A0 E1 03 60 A0 E1 00 30 64 E2 03 30 84 E1 04 10 A0 E1 98 23 9F E5 02 41 C6 E3 A3 3F 84 E1 02 00 53 E1 0C 42 2D ED 00 50 A0 E1 80 11 00 8E D4 00 00 8A 00 00 50 E3 00 50 60 B2 80 81 10 BE 02 61 86 B2 00 00 55 E3 04 00 00 1A 02 81 2D ED 03 00 BD E8 0C 42 BD EC 70 40 BD E8 ?? ?? ?? EA 01 00 55 E3 04 00 00 1A 02 81 2D ED 03 00 BD E8 0C 42 BD EC 70 40 BD E8 ?? ?? ?? EA 01 10 94 E1 30 23 9F E5 00 30 A0 13 01 30 A0 03 02 00 54 E1 01 30 83 C3 00 00 53 E3 B7 00 00 1A 02 81 2D ED 03 00 BD E8 ?? ?? ?? EB 90 51 07 EE 10 F1 D7 EE 80 D1 00 EE 4A 00 00 8A }
	condition:
		$pattern
}

rule setlocale_5942532248756381805050e53584c53d {
	meta:
		aliases = "setlocale"
		size = "100"
		objfiles = "setlocale@libc.a"
	strings:
		$pattern = { 06 00 50 E3 04 E0 2D E5 01 30 A0 E1 10 00 00 8A 00 00 51 E3 0C 00 00 0A 00 20 D1 E5 00 00 52 E3 09 00 00 0A 43 00 52 E3 01 00 A0 E1 28 10 9F E5 02 00 00 1A 01 30 D3 E5 00 00 53 E3 02 00 00 0A ?? ?? ?? EB 00 00 50 E3 01 00 00 1A 0C 00 9F E5 04 F0 9D E4 00 00 A0 E3 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule seed48_r_021aae3a21f7cc6cc3a3dedf35ed8176 {
	meta:
		aliases = "__GI_seed48_r, seed48_r"
		size = "148"
		objfiles = "seed48_r@libc.a"
	strings:
		$pattern = { 06 20 A0 E3 30 40 2D E9 00 50 A0 E1 02 00 81 E0 01 40 A0 E1 ?? ?? ?? EB 05 20 D5 E5 04 30 D5 E5 02 34 83 E1 43 24 A0 E1 05 20 C4 E5 04 30 C4 E5 03 20 D5 E5 02 30 D5 E5 02 34 83 E1 43 24 A0 E1 03 20 C4 E5 02 30 C4 E5 01 30 D5 E5 00 20 D5 E5 03 24 82 E1 42 34 A0 E1 01 30 C4 E5 0B 30 A0 E3 0C 30 C4 E5 00 20 C4 E5 01 30 A0 E3 1C 20 9F E5 00 00 A0 E3 0E 30 C4 E5 05 30 A0 E3 0F 00 C4 E5 10 20 84 E5 14 30 84 E5 0D 00 C4 E5 30 80 BD E8 6D E6 EC DE }
	condition:
		$pattern
}

rule remove_from_queue_6a13bfc867faea2a2df61d0f141fd8e4 {
	meta:
		aliases = "remove_from_queue"
		size = "64"
		objfiles = "semaphore@libpthread.a, condvar@libpthread.a"
	strings:
		$pattern = { 08 00 00 EA 01 00 52 E1 05 00 00 1A 08 30 92 E5 01 10 A0 E3 00 30 80 E5 00 30 A0 E3 08 30 82 E5 04 00 00 EA 08 00 82 E2 00 20 90 E5 00 00 52 E3 F3 FF FF 1A 02 10 A0 E1 01 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_cond_destroy_c8d0b13dfce94003942f5d7c734678d1 {
	meta:
		aliases = "__GI_pthread_cond_destroy, pthread_cond_destroy"
		size = "20"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { 08 00 90 E5 00 00 50 E3 10 00 A0 13 00 00 A0 03 0E F0 A0 E1 }
	condition:
		$pattern
}

rule fde_unencoded_compare_127bab62809f4f08bf364830486a6908 {
	meta:
		aliases = "fde_unencoded_compare"
		size = "32"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { 08 00 91 E5 08 30 92 E5 03 00 50 E1 01 00 A0 E3 0E F0 A0 81 00 00 E0 E3 00 00 A0 23 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_attr_getschedparam_c256e41d96cdd7cf60e33b1238f854a6 {
	meta:
		aliases = "__GI_pthread_attr_getschedparam, pthread_attr_getschedparam"
		size = "32"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 08 30 80 E2 04 E0 2D E5 01 00 A0 E1 04 20 A0 E3 03 10 A0 E1 ?? ?? ?? EB 00 00 A0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule __new_sem_getvalue_3b8d4ddfd08b2a67e22760c2fb830277 {
	meta:
		aliases = "sem_getvalue, __new_sem_getvalue"
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

rule sigtimedwait_244e3cd8f60de8eebe219a8ca68c4f65 {
	meta:
		aliases = "__GI_sigtimedwait, sigtimedwait"
		size = "8"
		objfiles = "__rt_sigtimedwait@libc.a"
	strings:
		$pattern = { 08 30 A0 E3 F2 FF FF EA }
	condition:
		$pattern
}

rule __GI__seterr_reply_f706147a61590b010160461cb5026469 {
	meta:
		aliases = "_seterr_reply, __GI__seterr_reply"
		size = "288"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { 08 C0 90 E5 00 00 5C E3 02 00 00 0A 01 00 5C E3 2C 00 00 1A 1E 00 00 EA 18 20 90 E5 00 00 52 E3 00 C0 81 05 0E F0 A0 01 05 00 52 E3 02 F1 9F 97 12 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 08 30 A0 E3 00 00 00 EA 09 30 A0 E3 00 30 81 E5 1D 00 00 EA 0A 30 A0 E3 FB FF FF EA 0B 30 A0 E3 F9 FF FF EA 0C 30 A0 E3 F7 FF FF EA 00 30 A0 E3 F5 FF FF EA 10 30 A0 E3 00 30 81 E5 00 30 A0 E3 04 30 81 E5 0A 00 00 EA 0C 20 90 E5 01 00 52 E3 03 00 00 0A 06 00 52 E3 00 20 81 05 0A 00 00 0A 01 00 00 EA 07 30 A0 E3 E7 FF FF EA 10 30 A0 E3 08 10 81 E8 08 20 81 E5 03 00 00 EA }
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

rule __aeabi_fcmpgt_f52cbcbfa58e06c8588cd1fb7e67afd3 {
	meta:
		aliases = "__aeabi_dcmplt, __aeabi_dcmpgt, __aeabi_fcmplt, __aeabi_fcmpgt"
		size = "20"
		objfiles = "_cmpsf2@libgcc.a, _cmpdf2@libgcc.a"
	strings:
		$pattern = { 08 E0 2D E5 ?? ?? ?? EB 01 00 A0 33 00 00 A0 23 08 F0 9D E4 }
	condition:
		$pattern
}

rule __aeabi_dcmple_ff7f5d7fa2e5dc60f94d507ce6a3303e {
	meta:
		aliases = "__aeabi_fcmpge, __aeabi_fcmple, __aeabi_dcmpge, __aeabi_dcmple"
		size = "20"
		objfiles = "_cmpsf2@libgcc.a, _cmpdf2@libgcc.a"
	strings:
		$pattern = { 08 E0 2D E5 ?? ?? ?? EB 01 00 A0 93 00 00 A0 83 08 F0 9D E4 }
	condition:
		$pattern
}

rule __encode_header_97ff30f95ce942b30103a229ff6d6c10 {
	meta:
		aliases = "__encode_header"
		size = "232"
		objfiles = "encodeh@libc.a"
	strings:
		$pattern = { 0B 00 52 E3 10 40 2D E9 00 30 E0 E3 00 E0 A0 E1 01 40 A0 E1 31 00 00 DA 01 30 D0 E5 00 30 C1 E5 00 30 90 E5 01 30 C1 E5 0C 30 9E E5 04 20 9E E5 10 10 9E E5 08 00 90 E5 00 00 53 E3 04 30 A0 13 00 30 A0 03 00 00 52 E3 14 C0 9E E5 80 20 A0 13 00 20 A0 03 0F 00 00 E2 00 00 51 E3 02 10 A0 13 00 10 A0 03 80 31 83 E1 00 00 5C E3 01 30 83 13 01 20 82 E1 03 20 82 E1 02 20 C4 E5 18 20 8E E2 0C 00 92 E8 00 00 52 E3 0F 30 03 E2 80 20 A0 13 00 20 A0 03 03 20 82 E1 03 20 C4 E5 21 30 DE E5 04 30 C4 E5 20 30 9E E5 05 30 C4 E5 25 30 DE E5 06 30 C4 E5 24 30 9E E5 07 30 C4 E5 29 30 DE E5 08 30 C4 E5 28 30 9E E5 }
	condition:
		$pattern
}

rule __GI_nextafter_71cb453bb01afce78284079cd816dbfe {
	meta:
		aliases = "nextafter, __GI_nextafter"
		size = "384"
		objfiles = "s_nextafter@libm.a"
	strings:
		$pattern = { 0C 00 2D E9 02 81 BD EC F0 4F 2D E9 02 81 2D ED 30 00 BD E8 5C 31 9F E5 02 E1 C0 E3 00 60 A0 E3 00 70 A0 E3 03 00 5E E1 03 00 2D E9 02 91 BD EC 00 C0 A0 E1 06 A0 A0 E1 01 00 A0 E1 07 B0 A0 E1 06 80 A0 E1 07 90 A0 E1 05 10 A0 E1 03 00 00 DA 02 31 8E E2 01 36 83 E2 00 30 93 E1 08 00 00 1A 02 31 C4 E3 04 20 A0 E1 08 41 9F E5 04 00 53 E1 05 00 00 DA 02 31 83 E2 01 36 83 E2 01 30 93 E1 01 00 00 0A 80 11 01 EE 38 00 00 EA 10 F1 91 EE 36 00 00 0A 00 E0 9E E1 07 00 00 1A 02 61 02 E2 01 70 A0 E3 C0 00 2D E9 02 91 BD EC 81 01 11 EE 11 F1 90 EE 80 91 00 0E 2C 00 00 EA 00 00 5C E3 07 00 00 BA 02 00 5C E1 }
	condition:
		$pattern
}

rule __GI_snprintf_4a999803dcd64297aad8387dd2b093cb {
	meta:
		aliases = "swprintf, snprintf, __GI_snprintf"
		size = "48"
		objfiles = "snprintf@libc.a, swprintf@libc.a"
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

rule _Unwind_SjLj_Register_e9ba7229f5754868413277256518745e {
	meta:
		aliases = "_Unwind_SjLj_Register"
		size = "24"
		objfiles = "unwind_sjlj@libgcc.a"
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

rule rwlock_can_rdlock_8ab1cdb8be61490cebc1054dcbe6980b {
	meta:
		aliases = "rwlock_can_rdlock"
		size = "60"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { 0C 30 90 E5 00 00 53 E3 00 20 A0 E3 08 00 00 1A 18 30 90 E5 00 00 53 E3 01 20 A0 E3 04 00 00 0A 14 30 90 E5 00 00 53 E3 01 00 00 0A 00 20 51 E2 01 20 A0 13 02 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule sem_destroy_e783cba1aff0ebac6de07f955d771bd5 {
	meta:
		aliases = "__new_sem_destroy, sem_destroy"
		size = "40"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { 0C 30 90 E5 00 00 53 E3 04 E0 2D E5 03 00 A0 E1 04 F0 9D 04 ?? ?? ?? EB 10 30 A0 E3 00 30 80 E5 00 00 E0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule random_r_0e5c400037faa0e494e7b36dadfd2b1d {
	meta:
		aliases = "__GI_random_r, random_r"
		size = "144"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { 0C 30 90 E5 00 00 53 E3 30 40 2D E9 00 C0 A0 E1 01 50 A0 E1 08 E0 90 E5 08 00 00 1A 00 20 9E E5 64 30 9F E5 92 03 03 E0 03 3A 83 E2 39 30 83 E2 02 31 C3 E3 00 30 8E E5 00 30 81 E5 10 00 00 EA 00 20 90 E5 04 00 90 E5 00 30 92 E5 04 10 90 E4 01 30 83 E0 04 30 82 E4 18 40 9C E5 A3 30 A0 E1 04 00 52 E1 00 30 85 E5 0E 20 A0 21 00 30 A0 E1 02 00 00 2A 04 00 50 E1 00 30 A0 31 0E 30 A0 21 0C 00 8C E8 00 00 A0 E3 30 80 BD E8 6D 4E C6 41 }
	condition:
		$pattern
}

rule __GI_pthread_attr_getinheritsc_f4a72c6b38cc3b35220d755255df89ec {
	meta:
		aliases = "pthread_attr_getinheritsched, __GI_pthread_attr_getinheritsched"
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

rule pthread_mutex_lock_fb3403fab464001f9bdac0faf8566e07 {
	meta:
		aliases = "__pthread_mutex_lock, pthread_mutex_lock"
		size = "200"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { 0C 30 90 E5 30 40 2D E9 00 40 A0 E1 03 00 53 E3 03 F1 9F 97 03 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 16 00 A0 E3 30 80 BD E8 10 00 80 E2 00 10 A0 E3 ?? ?? ?? EB 00 00 A0 E3 30 80 BD E8 5A FF FF EB 08 30 94 E5 00 00 53 E1 04 30 94 05 00 50 A0 E1 01 30 83 02 00 00 A0 03 05 00 00 0A 10 00 84 E2 05 10 A0 E1 ?? ?? ?? EB 00 30 A0 E3 08 50 84 E5 03 00 A0 E1 04 30 84 E5 30 80 BD E8 4A FF FF EB 08 30 94 E5 00 00 53 E1 00 50 A0 E1 23 00 A0 03 30 80 BD 08 10 00 84 E2 05 10 A0 E1 ?? ?? ?? EB 00 00 A0 E3 08 50 84 E5 30 80 BD E8 10 00 80 E2 00 10 A0 E3 ?? ?? ?? EB 00 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_mutex_trylock_fad3deb1979dccf13144dba191a7c0fb {
	meta:
		aliases = "pthread_mutex_trylock, __pthread_mutex_trylock"
		size = "196"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { 0C 30 90 E5 30 40 2D E9 00 40 A0 E1 03 00 53 E3 03 F1 9F 97 03 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 16 50 A0 E3 22 00 00 EA 14 20 80 E2 01 30 A0 E3 93 30 02 E1 00 00 53 E3 10 50 A0 13 00 50 A0 03 1B 00 00 EA C0 FE FF EB 08 30 94 E5 00 00 53 E1 00 20 A0 E1 04 30 94 05 00 50 A0 03 01 30 83 02 04 30 84 05 12 00 00 0A 01 00 A0 E3 14 30 84 E2 90 00 03 E1 00 00 50 E3 00 50 A0 01 10 50 A0 13 08 20 84 05 04 50 84 05 09 00 00 EA 10 00 80 E2 4C FE FF EB 00 50 50 E2 05 00 00 1A AA FE FF EB 08 00 84 E5 02 00 00 EA 10 00 80 E2 30 40 BD E8 44 FE FF EA 05 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule pthread_mutex_unlock_7a4cebe44604351029f47bde258f57b5 {
	meta:
		aliases = "__pthread_mutex_unlock, pthread_mutex_unlock"
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

rule __getpagesize_6aca7dca1f2b24957f3bf3e4e87ab272 {
	meta:
		aliases = "getpagesize, __GI_getpagesize, __getpagesize"
		size = "24"
		objfiles = "getpagesize@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 00 00 93 E5 00 00 50 E3 01 0A A0 03 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule re_set_syntax_bb868efe73ff5e9c3feb73348674049b {
	meta:
		aliases = "__re_set_syntax, re_set_syntax"
		size = "24"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 00 20 93 E5 00 00 83 E5 02 00 A0 E1 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isupper_55d3e10101725d0f8e3754dd946fdbb1 {
	meta:
		aliases = "isupper"
		size = "24"
		objfiles = "isupper@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 00 30 93 E5 80 00 D3 E7 01 00 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule islower_4cca9653e96fce3420dad4e9dc705337 {
	meta:
		aliases = "islower"
		size = "24"
		objfiles = "islower@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 00 30 93 E5 80 00 D3 E7 02 00 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isalpha_1625fb5837213fc7fc0e3bb1c9975dfc {
	meta:
		aliases = "isalpha"
		size = "24"
		objfiles = "isalpha@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 00 30 93 E5 80 00 D3 E7 04 00 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isxdigit_2719db6323c80447fb8186dbc35afa8b {
	meta:
		aliases = "isxdigit"
		size = "24"
		objfiles = "isxdigit@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 00 30 93 E5 80 00 D3 E7 10 00 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isspace_4b5281112b120638e1ba531ff1df3449 {
	meta:
		aliases = "isspace"
		size = "24"
		objfiles = "isspace@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 00 30 93 E5 80 00 D3 E7 20 00 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isprint_8eb09ba1bc257f133a43bacdfa86e2e1 {
	meta:
		aliases = "isprint"
		size = "24"
		objfiles = "isprint@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 00 30 93 E5 80 00 D3 E7 40 00 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isgraph_8a62f0844d0d95c797dd1f702db436df {
	meta:
		aliases = "isgraph"
		size = "24"
		objfiles = "isgraph@libc.a"
	strings:
		$pattern = { 0C 30 9F E5 00 30 93 E5 80 00 D3 E7 80 00 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __gnat_install_locks_1ef71ec01ce244c73bfb0568abb96d1f {
	meta:
		aliases = "__gnat_install_locks"
		size = "28"
		objfiles = "gthr_gnat@libgcc.a"
	strings:
		$pattern = { 0C 30 9F E5 0C 20 9F E5 00 00 83 E5 00 10 82 E5 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __mulsc3_999c4ab945c2790de5c04f562d898dd8 {
	meta:
		aliases = "__mulsc3"
		size = "984"
		objfiles = "_mulsc3@libgcc.a"
	strings:
		$pattern = { 0C 42 2D ED 04 20 2D E5 01 11 BD EC 04 00 2D E5 01 71 BD EC 04 10 2D E5 01 51 BD EC 04 30 2D E5 01 61 BD EC 01 01 97 EE 06 41 95 EE 04 21 20 EE 12 F1 92 EE 28 D0 4D E2 06 31 97 EE 00 01 8D ED 05 01 91 EE 01 31 8D ED 00 31 03 EE 06 01 8D ED 07 31 8D ED 05 00 00 1A 01 21 2D ED 04 00 9D E4 1C 10 9D E5 28 D0 8D E2 0C 42 BD EC 0E F0 A0 E1 13 F1 93 EE F7 FF FF 0A 17 F1 97 EE 07 01 27 EE 00 30 A0 13 01 30 A0 03 10 F1 90 EE 00 30 A0 03 01 30 03 12 00 00 53 E3 2A 00 00 1A 15 F1 95 EE 05 31 25 EE 00 30 A0 13 01 30 A0 03 13 F1 93 EE 00 30 A0 03 01 30 03 12 00 00 53 E3 51 00 00 1A 16 F1 96 EE 00 00 A0 03 }
	condition:
		$pattern
}

rule __divsc3_4ff1eaa0271b623abeb9976de3784a68 {
	meta:
		aliases = "__divsc3"
		size = "736"
		objfiles = "_divsc3@libgcc.a"
	strings:
		$pattern = { 0C 42 2D ED 04 20 2D E5 01 51 BD EC 04 30 2D E5 01 61 BD EC 05 91 20 EE 06 81 20 EE 10 F1 D1 EE 04 D0 4D E2 04 00 2D E5 01 41 BD EC 04 10 2D E5 01 71 BD EC 11 00 00 5A 06 01 A5 EE 00 21 97 EE 00 11 95 EE 00 01 94 EE 01 11 06 EE 00 01 07 EE 04 21 22 EE 01 21 A2 EE 01 11 A0 EE 11 F1 91 EE 10 00 00 1A 01 11 2D ED 04 00 9D E4 01 21 2D ED 04 10 9D E4 04 D0 8D E2 0C 42 BD EC 0E F0 A0 E1 05 01 A6 EE 00 21 94 EE 00 11 96 EE 00 01 97 EE 01 11 05 EE 00 01 04 EE 02 21 27 EE 01 21 A2 EE 01 11 A0 EE EC FF FF EA 12 F1 92 EE EC FF FF 0A 18 F1 95 EE 01 00 00 1A 18 F1 96 EE 74 00 00 0A 14 F1 94 EE 00 20 A0 03 }
	condition:
		$pattern
}

rule setstate_r_e2fc556189e6423988751584e55301ea {
	meta:
		aliases = "__GI_setstate_r, setstate_r"
		size = "192"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { 0C C0 91 E5 F0 40 2D E9 00 00 5C E3 01 40 A0 E1 04 30 94 15 08 10 91 E5 03 30 61 10 43 31 A0 11 05 20 A0 13 92 C3 23 10 04 C0 01 05 04 30 01 15 04 60 80 E2 04 00 16 E5 05 10 A0 E3 ?? ?? ?? EB 74 20 9F E5 04 00 50 E3 00 31 82 E0 15 00 00 8A 14 50 93 E5 00 71 92 E7 00 00 50 E3 05 10 A0 E3 10 50 84 E5 14 70 84 E5 0C 00 84 E5 08 00 00 0A 04 00 16 E5 ?? ?? ?? EB 00 31 86 E0 04 30 84 E5 07 00 80 E0 05 10 A0 E1 ?? ?? ?? EB 00 01 86 E0 00 00 84 E5 05 31 86 E0 00 00 A0 E3 18 30 84 E5 08 60 84 E5 F0 80 BD E8 ?? ?? ?? EB 16 30 A0 E3 00 30 80 E5 00 00 E0 E3 F0 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule uw_install_context_699ea376682b9fb35fb13bbf856e6335 {
	meta:
		aliases = "uw_install_context"
		size = "48"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { 0D C0 A0 E1 00 D8 2D E9 00 00 91 E5 04 B0 4C E2 01 40 A0 E1 2F FF FF EB 00 30 94 E5 20 20 83 E2 04 10 92 E5 20 B0 93 E5 08 D0 92 E5 01 F0 A0 E1 }
	condition:
		$pattern
}

rule execl_c3641a48629ee725461f4159cd1146ac {
	meta:
		aliases = "__GI_execl, execl"
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

rule __GI_execle_e40bcf0191feef55cc4c67f378ada946 {
	meta:
		aliases = "execle, __GI_execle"
		size = "144"
		objfiles = "execle@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 0E 00 2D E9 10 D8 2D E9 10 B0 4C E2 04 D0 4D E2 08 30 8B E2 14 30 0B E5 00 E0 A0 E3 14 20 1B E5 00 30 92 E5 00 00 53 E3 04 30 82 E2 14 30 0B E5 01 E0 8E E2 F8 FF FF 1A 0E 31 A0 E1 08 30 83 E2 0D D0 63 E0 04 30 9B E5 00 30 8D E5 08 30 8B E2 14 30 0B E5 04 40 92 E5 0D 10 A0 E1 0D C0 A0 E1 14 30 1B E5 00 20 93 E5 01 E0 5E E2 04 30 83 E2 14 30 0B E5 04 20 AC E5 F8 FF FF 1A 04 20 A0 E1 ?? ?? ?? EB 10 D0 4B E2 10 A8 9D E8 }
	condition:
		$pattern
}

rule nanf_09a17718456e53f1f6e3d17a4c998105 {
	meta:
		aliases = "__GI_nanf, nanf"
		size = "120"
		objfiles = "nan@libm.a"
	strings:
		$pattern = { 0D C0 A0 E1 70 D8 2D E9 00 30 D0 E5 00 00 53 E3 04 B0 4C E2 0D 60 A0 E1 00 50 A0 E1 4C 30 9F 05 0E 00 00 0A ?? ?? ?? EB 0C 00 80 E2 03 00 C0 E3 0D D0 60 E0 05 20 A0 E1 34 10 9F E5 0D 00 A0 E1 ?? ?? ?? EB 0D 00 A0 E1 00 10 A0 E3 ?? ?? ?? EB 01 01 2D ED 04 30 9D E4 0D 40 A0 E1 06 D0 A0 E1 04 30 2D E5 01 01 BD EC 18 D0 4B E2 70 A8 9D E8 00 00 C0 7F ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_nan_6cd3213613cf7c61fb2cf3140baa6339 {
	meta:
		aliases = "nan, __GI_nan"
		size = "124"
		objfiles = "nan@libm.a"
	strings:
		$pattern = { 0D C0 A0 E1 70 D8 2D E9 00 30 D0 E5 00 00 53 E3 04 B0 4C E2 0D 60 A0 E1 00 50 A0 E1 50 10 9F E5 00 20 A0 E3 0E 00 00 0A ?? ?? ?? EB 0C 00 80 E2 03 00 C0 E3 0D D0 60 E0 05 20 A0 E1 34 10 9F E5 0D 00 A0 E1 ?? ?? ?? EB 0D 00 A0 E1 00 10 A0 E3 ?? ?? ?? EB 02 81 2D ED 06 00 BD E8 0D 40 A0 E1 06 D0 A0 E1 06 00 2D E9 02 81 BD EC 18 D0 4B E2 70 A8 9D E8 00 00 F8 7F ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __msgwrite_8e43120e3515c61d8bb2c4ffeecf5a04 {
	meta:
		aliases = "__msgwrite"
		size = "192"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 D8 2D E9 04 B0 4C E2 30 D0 4D E2 1C D0 4D E2 01 50 A0 E1 02 60 A0 E1 00 70 A0 E1 ?? ?? ?? EB 30 00 0B E5 ?? ?? ?? EB 2C 00 0B E5 ?? ?? ?? EB 30 10 4B E2 28 00 0B E5 0C 20 A0 E3 0C 00 8D E2 ?? ?? ?? EB 02 30 A0 E3 00 20 A0 E3 01 10 A0 E3 18 00 A0 E3 08 30 8D E5 24 30 4B E2 24 50 0B E5 20 60 0B E5 44 30 0B E5 40 10 0B E5 3C D0 0B E5 38 00 0B E5 34 20 0B E5 03 00 8D E8 4C 20 0B E5 48 20 0B E5 0D 40 A0 E1 4C 10 4B E2 00 20 A0 E3 07 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 04 00 00 AA ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 F5 FF FF 0A 00 00 E0 E3 1C D0 4B E2 F0 A8 9D E8 }
	condition:
		$pattern
}

rule gaih_inet_serv_d1a6b8d435eadbabdab1851af0a64397 {
	meta:
		aliases = "gaih_inet_serv"
		size = "204"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 D9 2D E9 04 B0 4C E2 1C D0 4D E2 00 70 A0 E1 01 40 A0 E1 02 80 A0 E1 03 60 A0 E1 01 5B A0 E3 06 30 85 E2 03 30 C3 E3 0D D0 63 E0 24 C0 4B E2 07 00 A0 E1 03 10 84 E2 34 20 4B E2 08 30 8D E2 20 10 8D E8 ?? ?? ?? EB 00 00 50 E3 85 50 A0 E1 03 00 00 1A 24 20 1B E5 00 00 52 E3 03 00 00 1A 0D 00 00 EA 22 00 50 E3 0B 00 00 1A EB FF FF EA 00 30 A0 E3 00 30 86 E5 00 30 D4 E5 03 3C A0 E1 43 3C A0 E1 04 30 86 E5 02 30 D4 E5 02 00 13 E3 0C 10 98 15 05 00 00 1A 01 00 00 EA 42 0F A0 E3 06 00 00 EA 01 30 D4 E5 03 3C A0 E1 43 1C A0 E1 08 10 86 E5 08 30 92 E5 0C 30 86 E5 00 00 A0 E3 20 D0 4B E2 }
	condition:
		$pattern
}

rule ruserok_0096bbc319f0d25960e1a01d2552a8ce {
	meta:
		aliases = "ruserok"
		size = "232"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 D9 2D E9 04 B0 4C E2 28 D0 4D E2 01 DB 4D E2 04 D0 4D E2 02 70 A0 E1 00 50 A0 E1 01 80 A0 E1 03 60 A0 E1 08 20 8D E2 01 4B A0 E3 0A 00 00 EA 2C 30 1B E5 01 00 73 E3 26 00 00 1A ?? ?? ?? EB 00 30 90 E5 22 00 53 E3 22 00 00 1A 06 30 84 E2 03 30 C3 E3 0D D0 63 E0 08 20 8D E2 24 C0 4B E2 04 30 A0 E1 00 C0 8D E5 40 10 4B E2 2C C0 4B E2 05 00 A0 E1 04 C0 8D E5 ?? ?? ?? EB 00 00 50 E3 84 40 A0 E1 E9 FF FF 1A 24 30 1B E5 00 00 53 E3 E6 FF FF 0A 10 40 93 E5 08 00 00 EA ?? ?? ?? EB 28 00 1B E5 08 10 A0 E1 07 20 A0 E1 06 30 A0 E1 00 50 8D E5 6C FF FF EB 00 00 50 E3 06 00 00 0A 00 30 94 E5 }
	condition:
		$pattern
}

rule search_for_named_library_92bdf9c156dd7f8ea1c73629ed3be6d8 {
	meta:
		aliases = "search_for_named_library"
		size = "388"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DD 2D E9 04 B0 4C E2 00 C0 52 E2 00 A0 A0 E1 01 80 A0 E1 03 70 A0 E1 53 00 00 0A 01 20 4C E2 01 30 F2 E5 00 00 53 E3 FC FF FF 1A 02 20 6C E0 07 30 82 E2 03 30 C3 E3 0D D0 63 E0 0D 40 A0 E1 02 DB 4D E2 08 D0 4D E2 01 00 4C E2 01 20 82 E2 0D 50 A0 E1 01 10 44 E2 02 00 00 EA 01 30 F0 E5 01 30 E1 E5 01 20 42 E2 00 00 52 E3 FA FF FF 1A 02 60 A0 E1 04 10 A0 E1 00 30 D4 E5 00 00 53 E3 3A 30 83 02 00 30 C4 05 00 30 D4 E5 01 60 A0 03 3A 00 53 E3 31 00 00 1A 00 30 A0 E3 00 30 C4 E5 00 30 D1 E5 00 00 53 E3 01 30 45 E2 C4 10 9F 05 03 20 A0 01 07 00 00 0A 03 20 A0 E1 01 10 41 E2 01 30 F1 E5 }
	condition:
		$pattern
}

rule getrpcport_539dffe2a04afa0fab850b871977b34a {
	meta:
		aliases = "getrpcport"
		size = "232"
		objfiles = "getrpcport@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DD 2D E9 04 B0 4C E2 34 D0 4D E2 01 DB 4D E2 04 D0 4D E2 02 80 A0 E1 00 60 A0 E1 01 70 A0 E1 03 A0 A0 E1 08 20 8D E2 01 4B A0 E3 0A 00 00 EA 2C 30 1B E5 01 00 73 E3 26 00 00 1A ?? ?? ?? EB 00 30 90 E5 22 00 53 E3 22 00 00 1A 06 30 84 E2 03 30 C3 E3 0D D0 63 E0 08 20 8D E2 28 C0 4B E2 04 30 A0 E1 00 C0 8D E5 50 10 4B E2 2C C0 4B E2 06 00 A0 E1 04 C0 8D E5 ?? ?? ?? EB 00 50 50 E2 84 40 A0 E1 E9 FF FF 1A 28 20 1B E5 00 00 52 E3 E6 FF FF 0A 10 30 92 E5 3C 40 4B E2 00 10 93 E5 0C 20 92 E5 04 00 84 E2 ?? ?? ?? EB 02 C0 A0 E3 04 00 A0 E1 07 10 A0 E1 08 20 A0 E1 0A 30 A0 E1 3C C0 4B E5 }
	condition:
		$pattern
}

rule link_exists_p_f57afc5ad34bf9daa5e2d57cf514d190 {
	meta:
		aliases = "link_exists_p"
		size = "168"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DD 2D E9 04 B0 4C E2 B0 D0 4D E2 00 60 A0 E1 02 00 A0 E1 01 40 A0 E1 02 70 A0 E1 03 A0 A0 E1 ?? ?? ?? EB 04 30 80 E0 08 30 83 E2 03 30 C3 E3 0D D0 63 E0 00 50 A0 E1 06 10 A0 E1 04 20 A0 E1 0D 00 A0 E1 ?? ?? ?? EB 01 20 A0 E3 4C 10 9F E5 ?? ?? ?? EB 07 10 A0 E1 01 20 85 E2 ?? ?? ?? EB 04 30 9B E5 02 0C 13 E3 0D 80 A0 E1 0D 00 A0 E1 7C 10 4B E2 02 00 00 0A 0F E0 A0 E1 20 F0 9A E5 02 00 00 EA 0D 00 A0 E1 D4 10 4B E2 ?? ?? ?? EB 01 00 70 E2 00 00 A0 33 24 D0 4B E2 F0 AD 9D E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule link_exists_p_dfd1bdd7971c075a2ffdfe0949675d64 {
	meta:
		aliases = "link_exists_p"
		size = "168"
		objfiles = "glob64@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DD 2D E9 04 B0 4C E2 C0 D0 4D E2 00 60 A0 E1 02 00 A0 E1 01 40 A0 E1 02 70 A0 E1 03 A0 A0 E1 ?? ?? ?? EB 04 30 80 E0 08 30 83 E2 03 30 C3 E3 0D D0 63 E0 00 50 A0 E1 06 10 A0 E1 04 20 A0 E1 0D 00 A0 E1 ?? ?? ?? EB 01 20 A0 E3 4C 10 9F E5 ?? ?? ?? EB 07 10 A0 E1 01 20 85 E2 ?? ?? ?? EB 04 30 9B E5 02 0C 13 E3 0D 80 A0 E1 0D 00 A0 E1 84 10 4B E2 02 00 00 0A 0F E0 A0 E1 20 F0 9A E5 02 00 00 EA 0D 00 A0 E1 E4 10 4B E2 ?? ?? ?? EB 01 00 70 E2 00 00 A0 33 24 D0 4B E2 F0 AD 9D E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule glob_cc1fb3ab5a796405c07de474a30eddc5 {
	meta:
		aliases = "__GI_glob, glob"
		size = "1328"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 00 00 53 E3 00 00 50 13 04 B0 4C E2 E8 D0 4D E2 03 50 A0 E1 01 80 A0 E1 0C 21 0B E5 00 90 A0 E1 03 00 00 0A 7E 7C C1 E3 FF 70 C7 E3 00 00 57 E3 04 00 00 0A ?? ?? ?? EB 16 30 A0 E3 00 10 E0 E3 00 30 80 E5 30 01 00 EA 08 20 11 E2 08 20 83 05 08 21 0B E5 2F 10 A0 E3 ?? ?? ?? EB 00 60 50 E2 0A 00 00 1A 05 0A 18 E3 2D 00 00 0A 00 30 D9 E5 7E 00 53 E3 2A 00 00 1A 09 00 A0 E1 ?? ?? ?? EB 09 40 A0 E1 00 A0 A0 E1 04 61 0B E5 27 00 00 EA 09 00 56 E1 7C 44 9F 05 01 30 89 02 01 A0 A0 03 04 31 0B 05 21 00 00 0A 06 A0 69 E0 07 30 8A E2 03 30 C3 E3 0D D0 63 E0 04 40 8D E2 04 00 A0 E1 }
	condition:
		$pattern
}

rule glob64_ddfee50c7db35b96df73fc88d3f1799e {
	meta:
		aliases = "__GI_glob64, glob64"
		size = "1328"
		objfiles = "glob64@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 00 00 53 E3 00 00 50 13 04 B0 4C E2 F8 D0 4D E2 03 50 A0 E1 01 80 A0 E1 1C 21 0B E5 00 90 A0 E1 03 00 00 0A 7E 7C C1 E3 FF 70 C7 E3 00 00 57 E3 04 00 00 0A ?? ?? ?? EB 16 30 A0 E3 00 10 E0 E3 00 30 80 E5 30 01 00 EA 08 20 11 E2 08 20 83 05 18 21 0B E5 2F 10 A0 E3 ?? ?? ?? EB 00 60 50 E2 0A 00 00 1A 05 0A 18 E3 2D 00 00 0A 00 30 D9 E5 7E 00 53 E3 2A 00 00 1A 09 00 A0 E1 ?? ?? ?? EB 09 40 A0 E1 00 A0 A0 E1 14 61 0B E5 27 00 00 EA 09 00 56 E1 7C 44 9F 05 01 30 89 02 01 A0 A0 03 14 31 0B 05 21 00 00 0A 06 A0 69 E0 07 30 8A E2 03 30 C3 E3 0D D0 63 E0 04 40 8D E2 04 00 A0 E1 }
	condition:
		$pattern
}

rule __GI_execvp_82a8c2a37086723744a3373df5f17c7d {
	meta:
		aliases = "execvp, __GI_execvp"
		size = "468"
		objfiles = "execvp@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 00 30 D0 E5 00 00 53 E3 04 B0 4C E2 00 50 A0 E1 01 A0 A0 E1 02 00 00 1A ?? ?? ?? EB 02 30 A0 E3 30 00 00 EA 2F 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 1D 00 00 0A 7C 31 9F E5 0A 10 A0 E1 00 20 93 E5 05 00 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 00 30 90 E5 08 00 53 E3 54 00 00 1A 00 10 A0 E3 00 00 00 EA 01 10 81 E2 01 21 A0 E1 02 30 9A E7 00 00 53 E3 FA FF FF 1A 0C 30 82 E2 0D D0 63 E0 04 30 9A E4 08 00 8D E2 0A 10 A0 E1 28 00 8D E8 ?? ?? ?? EB 20 31 9F E5 0D 10 A0 E1 00 20 93 E5 18 01 9F E5 0D 40 A0 E1 ?? ?? ?? EB 3F 00 00 EA 0C 01 9F E5 ?? ?? ?? EB 00 40 50 E2 04 41 9F 05 02 00 00 0A }
	condition:
		$pattern
}

rule rcmd_c5396a252dd38c89972530b2c1f7cca9 {
	meta:
		aliases = "rcmd"
		size = "1420"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 01 18 A0 E1 04 B0 4C E2 80 D0 4D E2 21 18 A0 E1 9C 20 0B E5 94 00 0B E5 A0 30 0B E5 98 10 0B E5 ?? ?? ?? EB 01 DB 4D E2 04 D0 4D E2 08 20 8D E2 01 5B A0 E3 8C 00 0B E5 10 00 00 EA 30 40 1B E5 01 00 74 E3 03 00 00 1A ?? ?? ?? EB 00 30 90 E5 22 00 53 E3 05 00 00 0A ?? ?? ?? EB 00 40 80 E5 94 10 1B E5 00 00 91 E5 ?? ?? ?? EB 31 01 00 EA 06 30 85 E2 03 30 C3 E3 0D D0 63 E0 08 20 8D E2 94 C0 1B E5 00 00 9C E5 38 C0 4B E2 05 30 A0 E1 00 C0 8D E5 88 10 4B E2 30 C0 4B E2 04 C0 8D E5 ?? ?? ?? EB 00 00 50 E3 85 50 A0 E1 E2 FF FF 1A 38 30 1B E5 00 00 53 E3 DF FF FF 0A 01 40 A0 E3 }
	condition:
		$pattern
}

rule dlopen_52b3f1202dc81c8164b1f0a7819d51f5 {
	meta:
		aliases = "dlopen"
		size = "1520"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 03 30 11 E2 04 B0 4C E2 18 D0 4D E2 01 50 A0 E1 0E 70 A0 E1 00 80 A0 E1 03 00 A0 01 94 35 9F 05 09 20 A0 03 00 20 83 05 60 01 00 0A 88 25 9F E5 00 30 D2 E5 00 60 A0 E3 00 00 53 E3 2C 60 0B E5 07 00 00 1A 01 30 83 E2 00 30 C2 E5 6C 25 9F E5 6C 35 9F E5 00 20 83 E5 68 25 9F E5 68 35 9F E5 00 20 83 E5 64 45 9F E5 00 00 58 E3 00 00 94 05 4E 01 00 0A ?? ?? ?? EB 00 00 94 E5 06 40 A0 E1 00 20 A0 E1 0A 00 00 EA 00 C0 92 E5 14 10 9C E5 07 00 51 E1 05 00 00 2A 00 00 54 E3 02 00 00 0A 14 30 94 E5 01 00 53 E1 00 00 00 2A 0C 40 A0 E1 10 20 92 E5 00 00 52 E3 F2 FF FF 1A 2C 00 0B E5 }
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

rule byte_re_compile_fastmap_202de8c51422f299379ebb2473a46d76 {
	meta:
		aliases = "byte_re_compile_fastmap"
		size = "1072"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 04 D0 4D E2 10 70 90 E5 08 30 90 E5 00 40 90 E5 00 50 A0 E1 18 D0 4D E2 00 10 A0 E3 07 00 A0 E1 01 2C A0 E3 03 90 84 E0 ?? ?? ?? EB 1C 30 D5 E5 08 30 83 E3 1C 30 C5 E5 1C 30 D5 E5 00 60 A0 E3 01 30 C3 E3 0D 00 A0 E1 01 A0 A0 E3 05 10 A0 E3 2C 60 0B E5 1C 30 C5 E5 01 00 00 EA 09 40 A0 E1 00 A0 A0 E3 09 00 54 E1 02 00 00 0A 00 30 D4 E5 01 00 53 E3 0B 00 00 1A 00 00 56 E3 1C 20 D5 E5 DB 00 00 0A 02 30 8A E1 01 30 03 E2 01 20 C2 E3 02 30 83 E1 1C 30 C5 E5 01 60 46 E2 06 41 90 E7 01 A0 A0 E3 EE FF FF EA 01 40 84 E2 1D 00 53 E3 03 F1 9F 97 CD 00 00 EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule if_nameindex_65314bb107050a238166f014ebae1f01 {
	meta:
		aliases = "__GI_if_nameindex, if_nameindex"
		size = "404"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 08 D0 4D E2 ?? ?? ?? EB 00 80 50 E2 25 00 00 BA 00 30 A0 E3 2C 30 0B E5 80 40 A0 E3 84 10 A0 E1 06 30 81 E2 03 30 C3 E3 0D D0 63 E0 2C 30 1B E5 01 20 8D E0 03 00 52 E1 01 40 84 E0 08 00 A0 E1 01 40 A0 11 30 20 4B E2 30 11 9F E5 2C D0 0B E5 30 40 0B E5 ?? ?? ?? EB 00 00 50 E3 0F 00 00 BA 30 00 1B E5 04 00 50 E1 EB FF FF 0A A0 92 A0 E1 89 01 A0 E1 08 00 80 E2 ?? ?? ?? EB 00 60 50 E2 00 70 A0 13 31 00 00 1A 08 00 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 69 30 A0 E3 00 30 80 E5 34 00 00 EA 08 00 A0 E1 ?? ?? ?? EB 00 60 A0 E3 30 00 00 EA 2C 30 1B E5 87 42 83 E0 04 00 A0 E1 }
	condition:
		$pattern
}

rule glob_in_dir_4b64b9f0a84275ad2a8448ba8af1c1cf {
	meta:
		aliases = "glob_in_dir"
		size = "1264"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 1E DE 4D E2 00 80 A0 E1 01 00 A0 E1 02 70 A0 E1 01 90 A0 E1 03 60 A0 E1 ?? ?? ?? EB 40 50 17 E2 00 02 0B E5 00 10 A0 13 01 10 A0 03 08 00 A0 E1 04 A0 9B E5 ?? ?? ?? EB 00 00 50 E3 35 00 00 1A 81 0E 17 E3 F8 01 0B 15 FC 01 0B 15 10 70 87 13 29 00 00 1A 00 00 55 E3 04 00 00 1A 08 00 A0 E1 5C 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 29 00 00 1A 08 00 A0 E1 ?? ?? ?? EB 00 12 1B E5 00 30 81 E0 08 30 83 E2 03 30 C3 E3 0D D0 63 E0 04 50 8D E2 00 40 A0 E1 09 10 A0 E1 00 22 1B E5 05 00 A0 E1 ?? ?? ?? EB 01 20 A0 E3 30 14 9F E5 ?? ?? ?? EB 08 10 A0 E1 01 20 84 E2 ?? ?? ?? EB }
	condition:
		$pattern
}

rule clntudp_call_e367868e12d13ee03cca209f22bc853a {
	meta:
		aliases = "clntudp_call"
		size = "1748"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 23 DC 4D E2 34 D0 4D E2 02 CA 4B E2 4C 03 0C E5 94 06 9F E5 28 C0 4B E2 00 10 8C E7 02 0A 4B E2 4C 03 10 E5 08 60 90 E5 1C E0 96 E5 FA CF A0 E3 9E 0C 04 E0 0C 10 A0 E1 02 CA 4B E2 20 00 96 E5 50 23 0C E5 54 33 0C E5 ?? ?? ?? EB 28 20 96 E5 00 C0 84 E0 02 3A 4B E2 01 00 72 E3 48 C3 03 E5 0C 30 8B E2 18 00 93 E8 10 00 00 1A 02 0A 4B E2 34 33 00 E5 38 43 00 E5 10 00 00 EA ?? ?? ?? EB 00 20 90 E5 03 30 A0 E3 05 00 00 EA 05 30 A0 E3 03 C0 A0 E1 2C 30 86 E5 80 01 00 EA 0C 20 92 E5 04 30 A0 E3 03 C0 A0 E1 30 20 86 E5 F8 FF FF EA 24 C0 96 E5 02 3A 4B E2 34 C3 03 E5 }
	condition:
		$pattern
}

rule iruserok2_d701969ef6b56a3631627f906a0f1af4 {
	meta:
		aliases = "iruserok2"
		size = "368"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 24 D0 4D E2 00 50 51 E2 00 A0 A0 E1 02 90 A0 E1 03 60 A0 E1 03 00 00 1A 38 01 9F E5 C8 FF FF EB 00 40 50 E2 01 00 00 1A 00 70 E0 E3 0A 00 00 EA 04 C0 9B E5 0A 10 A0 E1 06 20 A0 E1 09 30 A0 E1 00 C0 8D E5 D7 FE FF EB 00 70 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 00 57 E3 3B 00 00 0A F8 30 9F E5 00 30 93 E5 03 50 95 E1 36 00 00 0A 46 00 A0 E3 ?? ?? ?? EB 06 20 80 E2 03 20 C2 E3 0D D0 62 E0 00 30 A0 E1 2C C0 4B E2 06 00 A0 E1 48 10 4B E2 04 20 8D E2 00 C0 8D E5 ?? ?? ?? EB 00 00 50 E3 28 00 00 1A 2C 30 1B E5 00 00 53 E3 25 00 00 0A 14 00 93 E5 ?? ?? ?? EB 09 00 80 E2 }
	condition:
		$pattern
}

rule callrpc_5e3741c08f87cb8c148a29b40bf4c8c8 {
	meta:
		aliases = "callrpc"
		size = "620"
		objfiles = "clnt_simple@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 4C D0 4D E2 58 00 0B E5 5C 10 0B E5 60 20 0B E5 64 30 0B E5 ?? ?? ?? EB A4 50 90 E5 00 70 A0 E3 00 80 A0 E3 00 00 55 E3 00 40 A0 E1 07 90 A0 E1 08 A0 A0 E1 06 00 00 1A 01 00 A0 E3 18 10 A0 E3 ?? ?? ?? EB 00 50 50 E2 05 00 A0 01 81 00 00 0A A4 50 84 E5 14 40 95 E5 00 00 54 E3 05 00 00 1A 01 0C A0 E3 ?? ?? ?? EB 00 30 E0 E3 14 00 85 E5 00 40 C0 E5 04 30 85 E5 10 30 95 E5 00 00 53 E3 0C 00 00 0A 08 30 95 E5 5C 20 1B E5 02 00 53 E1 08 00 00 1A 0C 30 95 E5 60 20 1B E5 02 00 53 E1 04 00 00 1A 14 00 95 E5 58 10 1B E5 ?? ?? ?? EB 00 00 50 E3 54 00 00 0A 04 00 95 E5 }
	condition:
		$pattern
}

rule byte_re_match_2_internal_1a954c82a3a994f07b68f8dff7a2ffdf {
	meta:
		aliases = "byte_re_match_2_internal"
		size = "7644"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 78 D0 4D E2 18 C0 90 E5 98 00 0B E5 00 50 90 E5 08 00 90 E5 00 00 85 E0 7C 00 0B E5 98 00 1B E5 14 00 90 E5 18 D0 4D E2 9C 10 0B E5 00 00 5C E3 01 10 8C E2 A0 20 0B E5 03 90 A0 E1 10 60 9B E5 74 00 0B E5 0D A0 A0 E1 70 10 0B E5 09 00 00 1A 64 C0 0B E5 60 C0 0B E5 5C C0 0B E5 58 C0 0B E5 54 C0 0B E5 4C C0 0B E5 48 C0 0B E5 3C C0 0B E5 38 C0 0B E5 2B 00 00 EA 70 20 1B E5 02 31 A0 E1 04 30 83 E2 0D D0 63 E0 64 D0 0B E5 0D D0 63 E0 60 D0 0B E5 0D D0 63 E0 0D C0 A0 E1 0D D0 63 E0 0D 00 A0 E1 0D D0 63 E0 0D E0 A0 E1 0D D0 63 E0 60 10 1B E5 0D 40 A0 E1 64 70 1B E5 }
	condition:
		$pattern
}

rule gaih_inet_8b3172829cbedcc02362c0bccc89f2ef {
	meta:
		aliases = "gaih_inet"
		size = "2760"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 88 D0 4D E2 02 80 A0 E1 04 20 92 E5 0A 00 52 E3 00 00 52 13 A0 30 0B E5 00 30 98 05 4C 20 4B E2 A3 31 A0 01 2C 20 0B E5 00 20 A0 E3 00 C0 A0 13 01 C0 A0 03 01 30 03 02 30 20 0B E5 00 70 A0 E1 01 60 A0 E1 4C 00 4B E2 00 10 A0 E3 10 20 A0 E3 9C C0 0B 15 9C 30 0B 05 ?? ?? ?? EB 0C 00 98 E5 00 00 50 E3 01 00 00 0A 24 1A 9F E5 04 00 00 EA 08 30 98 E5 00 00 53 E3 FA FF FF 1A 1A 00 00 EA 08 10 81 E2 03 C0 D1 E5 00 00 5C E3 11 00 00 0A 08 20 98 E5 00 00 52 E3 03 00 00 0A 00 30 D1 E5 03 3C A0 E1 43 0C 52 E1 F4 FF FF 1A 00 00 50 E3 06 00 00 0A 02 30 D1 E5 02 00 13 E3 }
	condition:
		$pattern
}

rule clnt_create_60ac036fa08551c601ececa226381e92 {
	meta:
		aliases = "clnt_create"
		size = "648"
		objfiles = "clnt_generic@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 BC D0 4D E2 00 90 A0 E1 DC 30 0B E5 01 80 A0 E1 03 00 A0 E1 5C 12 9F E5 02 A0 A0 E1 ?? ?? ?? EB 00 50 50 E2 00 60 A0 E3 00 70 A0 E3 14 00 00 1A D8 40 4B E2 70 20 A0 E3 05 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 09 10 A0 E1 01 30 A0 E3 02 00 84 E2 D8 30 4B E5 D7 50 4B E5 ?? ?? ?? EB 00 C0 E0 E3 04 00 A0 E1 08 10 A0 E1 0A 20 A0 E1 30 30 4B E2 30 C0 0B E5 04 50 8D E5 00 50 8D E5 ?? ?? ?? EB 62 00 00 EA 01 DB 4D E2 04 D0 4D E2 08 20 8D E2 01 4B A0 E3 0E 00 00 EA 38 30 1B E5 01 00 73 E3 03 00 00 1A ?? ?? ?? EB 00 30 90 E5 22 00 53 E3 03 00 00 0A ?? ?? ?? EB 00 10 A0 E3 }
	condition:
		$pattern
}

rule glob_in_dir_070c57dff941df07af605b71b25a6fca {
	meta:
		aliases = "glob_in_dir"
		size = "1200"
		objfiles = "glob64@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 04 B0 4C E2 DC D0 4D E2 00 80 A0 E1 01 00 A0 E1 02 60 A0 E1 01 90 A0 E1 03 70 A0 E1 ?? ?? ?? EB 40 50 16 E2 FC 00 0B E5 00 10 A0 13 01 10 A0 03 08 00 A0 E1 04 A0 9B E5 ?? ?? ?? EB 00 00 50 E3 35 00 00 1A 81 0E 16 E3 F4 00 0B 15 F8 00 0B 15 10 60 86 13 29 00 00 1A 00 00 55 E3 04 00 00 1A 08 00 A0 E1 5C 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 29 00 00 1A 08 00 A0 E1 ?? ?? ?? EB FC 10 1B E5 00 30 81 E0 08 30 83 E2 03 30 C3 E3 0D D0 63 E0 04 50 8D E2 00 40 A0 E1 09 10 A0 E1 FC 20 1B E5 05 00 A0 E1 ?? ?? ?? EB 01 20 A0 E3 F0 13 9F E5 ?? ?? ?? EB 08 10 A0 E1 01 20 84 E2 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __getdents64_0744a5802eefb8b2883bd8a149ffd637 {
	meta:
		aliases = "__getdents64"
		size = "356"
		objfiles = "getdents64@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 06 30 82 E2 04 B0 4C E2 10 D0 4D E2 03 30 C3 E3 0D D0 63 E0 01 80 A0 E1 38 20 0B E5 0D A0 A0 E1 34 00 0B E5 0D 10 A0 E1 D9 00 90 EF 01 0A 70 E3 00 60 A0 E1 04 00 00 9A ?? ?? ?? EB 00 30 66 E2 00 60 E0 E3 00 30 80 E5 01 00 00 EA 01 00 70 E3 01 00 00 1A 06 10 A0 E1 3C 00 00 EA 00 20 E0 E3 00 30 E0 E3 08 50 A0 E1 0D 40 A0 E1 30 20 0B E5 2C 30 0B E5 2C 00 00 EA 01 20 D7 E5 10 30 D4 E5 02 34 83 E1 03 30 83 E2 03 30 C3 E3 03 90 85 E0 0C 00 59 E1 43 24 A0 E1 0B 00 00 9A 34 00 1B E5 30 10 4B E2 06 00 91 E8 00 30 A0 E3 ?? ?? ?? EB 08 00 55 E1 24 00 00 1A ?? ?? ?? EB 16 30 A0 E3 }
	condition:
		$pattern
}

rule ruserpass_aa1de8f9b4e1d10bd3d6193de28d5b6e {
	meta:
		aliases = "__GI_ruserpass, ruserpass"
		size = "832"
		objfiles = "ruserpass@libc.a"
	strings:
		$pattern = { 0D C0 A0 E1 F0 DF 2D E9 45 DE 4D E2 04 B0 4C E2 08 D0 4D E2 01 70 A0 E1 02 A0 A0 E1 00 60 A0 E1 ?? ?? ?? EB 00 40 A0 E1 ?? ?? ?? EB 00 00 54 E1 B4 00 00 1A ?? ?? ?? EB 00 40 A0 E1 ?? ?? ?? EB 00 00 54 E1 AF 00 00 1A C4 02 9F E5 ?? ?? ?? EB 00 40 50 E2 AB 00 00 0A ?? ?? ?? EB 0E 00 80 E2 03 00 C0 E3 0D D0 60 E0 04 10 A0 E1 0D 00 A0 E1 ?? ?? ?? EB 9C 12 9F E5 0D 00 A0 E1 ?? ?? ?? EB 0D 00 A0 E1 90 12 9F E5 ?? ?? ?? EB 8C 32 9F E5 00 00 50 E3 0D 50 A0 E1 00 40 A0 E1 00 00 83 E5 07 00 00 1A ?? ?? ?? EB 00 30 90 E5 02 00 53 E3 0D 10 A0 11 68 02 9F 15 ?? ?? ?? 1B 04 00 A0 E1 91 00 00 EA 47 4E 4B E2 }
	condition:
		$pattern
}

rule _init_522dd4955bdec9b323151dc7dcd03dcd {
	meta:
		aliases = "_fini, _init"
		size = "12"
		objfiles = "crti"
	strings:
		$pattern = { 0D C0 A0 E1 F8 DF 2D E9 04 B0 4C E2 }
	condition:
		$pattern
}

rule err_c8f1b022fb02968909268fe66e08fb7f {
	meta:
		aliases = "errx, err"
		size = "28"
		objfiles = "err@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 04 D0 4D E2 08 30 8D E2 03 20 A0 E1 04 10 9D E5 00 30 8D E5 ?? ?? ?? EB }
	condition:
		$pattern
}

rule open64_02cf525590869d2dd7643f9e28f64987 {
	meta:
		aliases = "__libc_open64, __GI_open64, __GI___libc_open64, open64"
		size = "60"
		objfiles = "open64@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 04 E0 2D E5 04 D0 4D E2 08 10 9D E5 40 30 11 E2 03 20 A0 E1 02 18 81 E3 10 30 8D 12 0C 20 9D 15 00 30 8D 15 ?? ?? ?? EB 04 D0 8D E2 04 E0 9D E4 0C D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_asprintf_b894f9a4909b4c2528ee0248ddf88a00 {
	meta:
		aliases = "fwscanf, fprintf, __GI_syslog, asprintf, __GI_fscanf, fscanf, dprintf, __GI_fprintf, __GI_sscanf, syslog, sscanf, fwprintf, swscanf, __GI_asprintf"
		size = "48"
		objfiles = "sscanf@libc.a, fprintf@libc.a, fwscanf@libc.a, fscanf@libc.a, asprintf@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 04 E0 2D E5 04 D0 4D E2 0C 30 8D E2 03 20 A0 E1 08 10 9D E5 00 30 8D E5 ?? ?? ?? EB 04 D0 8D E2 04 E0 9D E4 0C D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule sprintf_efcf0e00d2547f3073643f3d2cdf15ae {
	meta:
		aliases = "__GI_sprintf, sprintf"
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

rule mq_open_e1a97f0a891c8ec1bf3e54cdeb8a2d9f {
	meta:
		aliases = "mq_open"
		size = "144"
		objfiles = "mq_open@librt.a"
	strings:
		$pattern = { 0E 00 2D E9 10 40 2D E9 00 30 D0 E5 04 D0 4D E2 2F 00 53 E3 0C 10 9D E5 04 00 00 0A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 12 00 00 EA 40 30 11 E2 03 C0 A0 E1 18 30 8D 12 00 30 8D 15 10 30 9D 15 14 C0 9D 15 03 28 A0 E1 22 28 A0 E1 0C 30 A0 E1 01 00 80 E2 12 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 20 A0 E1 02 00 A0 E1 04 D0 8D E2 10 40 BD E8 0C D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_open_66dd849fbd999a9c9d5012720b4f2b9a {
	meta:
		aliases = "__GI___libc_open, __libc_open, open, __GI_open"
		size = "92"
		objfiles = "open@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 10 40 2D E9 04 D0 4D E2 0C 10 9D E5 40 30 11 E2 14 30 8D 12 00 30 8D 15 10 30 9D 15 03 28 A0 E1 22 28 A0 E1 05 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 04 D0 8D E2 10 40 BD E8 0C D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI___libc_fcntl_f0b55e1ff14b333842d11b73b016bc79 {
	meta:
		aliases = "fcntl, __libc_fcntl, __GI_fcntl, __GI___libc_fcntl"
		size = "116"
		objfiles = "__syscall_fcntl@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 10 40 2D E9 04 D0 4D E2 0C C0 9D E5 0C 30 4C E2 02 00 53 E3 14 30 8D E2 00 30 8D E5 10 30 9D E5 0C 10 A0 E1 03 20 A0 E1 01 00 00 8A ?? ?? ?? EB 0A 00 00 EA 03 20 A0 E1 0C 10 A0 E1 37 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 04 D0 8D E2 10 40 BD E8 0C D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_ioctl_ddb6a003763def04a11e78bcf4b29e6a {
	meta:
		aliases = "ioctl, __GI_ioctl"
		size = "80"
		objfiles = "ioctl@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 10 40 2D E9 04 D0 4D E2 14 30 8D E2 00 30 8D E5 0C 10 8D E2 06 00 91 E8 36 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 04 D0 8D E2 10 40 BD E8 0C D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __libc_fcntl64_ea772faf4a859bf12c55c86e5c62dd83 {
	meta:
		aliases = "__GI___libc_fcntl64, fcntl64, __GI_fcntl64, __libc_fcntl64"
		size = "80"
		objfiles = "__syscall_fcntl64@libc.a"
	strings:
		$pattern = { 0E 00 2D E9 10 40 2D E9 04 D0 4D E2 14 30 8D E2 00 30 8D E5 0C 10 8D E2 06 00 91 E8 DD 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 04 D0 8D E2 10 40 BD E8 0C D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule open64_cab87d0901014a7f96b83a750d00f80a {
	meta:
		aliases = "fcntl, open, open64"
		size = "88"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { 0E 00 2D E9 10 40 2D E9 08 D0 4D E2 00 40 A0 E1 04 10 8D E2 01 00 A0 E3 ?? ?? ?? EB 18 30 8D E2 10 10 8D E2 06 00 91 E8 04 00 A0 E1 00 30 8D E5 ?? ?? ?? EB 00 10 A0 E3 00 40 A0 E1 04 00 9D E5 ?? ?? ?? EB 04 00 A0 E1 08 D0 8D E2 10 40 BD E8 0C D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule _dl_dprintf_ad1ff7419e7510a05f313577d6aa1776 {
	meta:
		aliases = "_dl_dprintf"
		size = "900"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 0E 00 2D E9 F0 40 2D E9 1C D0 4D E2 30 E0 9D E5 00 00 5E E3 00 70 A0 E1 CE 00 00 0A 44 33 9F E5 00 50 A0 E3 00 10 93 E5 00 40 E0 E3 22 30 A0 E3 03 20 A0 E3 05 00 A0 E1 C0 00 90 EF 01 0A 70 E3 24 33 9F 85 00 20 60 82 00 20 83 85 04 00 A0 81 18 33 9F E5 01 00 70 E3 00 00 83 E5 0D 00 00 1A 1D 20 A0 E3 08 13 9F E5 07 00 A0 E1 04 00 90 EF 01 0A 70 E3 F0 32 9F 85 00 20 60 82 00 20 83 85 14 00 A0 E3 01 00 90 EF 01 0A 70 E3 D8 32 9F 85 00 20 60 82 00 20 83 85 D0 32 9F E5 01 C0 4E E2 00 60 93 E5 0C 20 A0 E1 01 30 F2 E5 00 00 53 E3 FC FF FF 1A AC 32 9F E5 00 30 93 E5 02 20 6E E0 01 30 43 E2 03 00 52 E1 }
	condition:
		$pattern
}

rule warnx_dd60735d76fdb5bc201ac5322c5bc580 {
	meta:
		aliases = "warn, warnx"
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

rule wscanf_0304853a5bbd79b71a43422fdd25bd20 {
	meta:
		aliases = "__GI_printf, wprintf, scanf, printf, wscanf"
		size = "60"
		objfiles = "printf@libc.a, wscanf@libc.a, wprintf@libc.a, scanf@libc.a"
	strings:
		$pattern = { 0F 00 2D E9 04 E0 2D E5 28 30 9F E5 04 D0 4D E2 0C C0 8D E2 00 00 93 E5 0C 20 A0 E1 08 10 9D E5 00 C0 8D E5 ?? ?? ?? EB 04 D0 8D E2 04 E0 9D E4 10 D0 8D E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ptrace_097913e1587ea5ed158658b8edadab97 {
	meta:
		aliases = "ptrace"
		size = "152"
		objfiles = "ptrace@libc.a"
	strings:
		$pattern = { 0F 00 2D E9 30 40 2D E9 08 D0 4D E2 14 50 9D E5 01 30 45 E2 02 00 53 E3 24 30 8D E2 00 30 8D E5 05 00 A0 E1 18 10 8D E2 0E 00 91 E8 04 30 8D 92 1A 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 30 E0 E1 A3 3F A0 E1 00 00 55 E3 00 30 A0 03 00 00 53 E3 04 20 A0 E1 05 00 00 0A 03 00 55 E3 03 00 00 8A ?? ?? ?? EB 00 30 A0 E3 04 20 9D E5 00 30 80 E5 02 00 A0 E1 08 D0 8D E2 30 40 BD E8 10 D0 8D E2 0E F0 A0 E1 }
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

rule __regerror_98186dcdcc2af2bd284323fbe4e4ab15 {
	meta:
		aliases = "regerror, __regerror"
		size = "124"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 10 00 50 E3 F0 40 2D E9 02 70 A0 E1 03 60 A0 E1 ?? ?? ?? 8B 58 30 9F E5 00 21 93 E7 54 30 9F E5 03 40 82 E0 04 00 A0 E1 ?? ?? ?? EB 00 00 56 E3 01 50 80 E2 0C 00 00 0A 06 00 55 E1 06 00 00 9A 07 00 A0 E1 04 10 A0 E1 01 20 46 E2 ?? ?? ?? EB 00 30 A0 E3 00 30 C0 E5 03 00 00 EA 07 00 A0 E1 04 10 A0 E1 05 20 A0 E1 ?? ?? ?? EB 05 00 A0 E1 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
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

rule __scan_ungetc_ecff4a1afceebe2acdbc29c3ed9541a2 {
	meta:
		aliases = "__scan_ungetc"
		size = "72"
		objfiles = "__scan_cookie@libc.a"
	strings:
		$pattern = { 10 30 90 E5 19 20 D0 E5 01 30 83 E2 02 00 52 E3 10 30 80 E5 04 00 00 1A 04 30 90 E5 00 30 80 E5 00 30 A0 E3 19 30 C0 E5 0E F0 A0 E1 00 00 52 E3 0C 30 90 05 01 20 82 02 01 30 43 02 19 20 C0 05 0C 30 80 05 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_free_ee6b184f4ea7f24881fdb514dc8d6f67 {
	meta:
		aliases = "pthread_free"
		size = "204"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { 10 30 90 E5 30 40 2D E9 03 3B A0 E1 A8 40 9F E5 23 3B A0 E1 03 42 84 E0 00 50 A0 E1 00 10 A0 E3 04 00 A0 E1 ?? ?? ?? EB 00 30 A0 E3 08 30 84 E5 00 30 E0 E3 0C 30 84 E5 04 00 A0 E1 ?? ?? ?? EB 78 20 9F E5 00 30 92 E5 C0 41 95 E5 01 30 43 E2 00 30 82 E5 01 00 00 EA 00 40 94 E5 ?? ?? ?? EB 00 00 54 E2 FB FF FF 1A C4 41 95 E5 01 00 00 EA 00 40 94 E5 ?? ?? ?? EB 00 00 54 E2 FB FF FF 1A 3C 30 9F E5 03 00 55 E1 30 80 BD 08 88 31 95 E5 00 00 53 E3 30 80 BD 18 90 11 95 E5 00 00 51 E3 8C 01 95 15 ?? ?? ?? 1B 18 00 9F E5 02 16 A0 E3 00 00 85 E0 30 40 BD E8 ?? ?? ?? EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __md5_Update_a5fa588d8ea25ef60b165b6ae8cb8dc2 {
	meta:
		aliases = "__md5_Update"
		size = "176"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { 10 30 90 E5 F0 41 2D E9 02 70 A0 E1 82 21 A0 E1 00 50 A0 E1 02 00 83 E0 02 00 50 E1 A3 31 A0 E1 3F 20 03 E2 14 30 95 35 01 30 83 32 14 30 85 35 14 30 95 E5 40 60 62 E2 A7 3E 83 E0 06 00 57 E1 10 00 85 E5 01 80 A0 E1 14 30 85 E5 00 40 A0 33 10 00 00 3A 18 40 85 E2 02 00 84 E0 06 20 A0 E1 ?? ?? ?? EB 04 10 A0 E1 05 00 A0 E1 78 FF FF EB 06 40 A0 E1 01 00 00 EA 75 FF FF EB 40 40 84 E2 3F 30 84 E2 07 00 53 E1 04 10 88 E0 05 00 A0 E1 F8 FF FF 3A 00 20 A0 E3 18 00 85 E2 02 00 80 E0 04 10 88 E0 07 20 64 E0 F0 41 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule atexit_db048bd4c54bb27079821d5d3bb0c757 {
	meta:
		aliases = "atexit"
		size = "28"
		objfiles = "atexit@libc.a"
	strings:
		$pattern = { 10 30 9F E5 00 00 53 E3 03 20 A0 E1 00 20 93 15 00 10 A0 E3 ?? ?? ?? EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __isinff_666c1aab445e9825e268f6860b79b830 {
	meta:
		aliases = "isinff, __GI___isinff, __isinff"
		size = "28"
		objfiles = "s_isinff@libm.a"
	strings:
		$pattern = { 10 30 9F E5 02 21 C0 E3 03 00 52 E1 40 0F A0 01 00 00 A0 13 0E F0 A0 E1 00 00 80 7F }
	condition:
		$pattern
}

rule __libc_system_db7a1251c6f64182bc97303843acefc2 {
	meta:
		aliases = "system, __libc_system"
		size = "312"
		objfiles = "system@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 00 50 E3 18 D0 4D E2 04 00 8D E5 01 00 A0 03 42 00 00 0A 01 10 A0 E3 03 00 A0 E3 ?? ?? ?? EB 01 10 A0 E3 08 00 8D E5 02 00 A0 E3 ?? ?? ?? EB 00 10 A0 E3 0C 00 8D E5 11 00 A0 E3 ?? ?? ?? EB 10 00 8D E5 ?? ?? ?? EB 00 40 50 E2 0A 00 00 AA 08 10 9D E5 03 00 A0 E3 ?? ?? ?? EB 0C 10 9D E5 02 00 A0 E3 ?? ?? ?? EB 10 10 9D E5 11 00 A0 E3 ?? ?? ?? EB 00 00 E0 E3 28 00 00 EA 10 00 00 1A 04 10 A0 E1 03 00 A0 E3 ?? ?? ?? EB 04 10 A0 E1 02 00 A0 E3 ?? ?? ?? EB 04 10 A0 E1 11 00 A0 E3 ?? ?? ?? EB 04 30 9D E5 78 00 9F E5 78 10 9F E5 78 20 9F E5 00 40 8D E5 ?? ?? ?? EB 7F 00 A0 E3 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __sigjmp_save_a1b54d70b076e9ad3bb9da9ed597cf50 {
	meta:
		aliases = "__sigjmp_save"
		size = "60"
		objfiles = "sigjmp@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 00 51 E3 00 40 A0 E1 00 00 A0 E3 00 10 A0 E1 5C 20 84 E2 03 00 00 0A ?? ?? ?? EB 00 00 50 E3 01 30 A0 E3 00 00 00 0A 00 30 A0 E3 00 00 A0 E3 58 30 84 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule tmpnam_r_744a2c3bf65e9211b3f96808e6e41a32 {
	meta:
		aliases = "tmpnam_r"
		size = "68"
		objfiles = "tmpnam_r@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 20 A0 E3 00 40 50 E2 14 10 A0 E3 02 30 A0 E1 07 00 00 0A ?? ?? ?? EB 00 00 50 E3 03 10 A0 E3 04 00 A0 E1 02 00 00 1A ?? ?? ?? EB 00 00 50 E3 00 00 00 0A 00 40 A0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __stdio_trans2w_o_fe1fb2daa4d5b02dc76e11b93d9eb5fb {
	meta:
		aliases = "__stdio_trans2w_o"
		size = "260"
		objfiles = "_trans2w@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 20 D0 E5 01 30 D0 E5 03 24 82 E1 01 00 12 E1 00 40 A0 E1 05 00 00 1A 22 0D 12 E3 08 00 00 1A 01 20 82 E1 42 34 A0 E1 01 30 C0 E5 00 20 C0 E5 00 20 D4 E5 01 30 D4 E5 03 C4 82 E1 20 00 1C E3 09 00 00 0A ?? ?? ?? EB 09 30 A0 E3 00 30 80 E5 00 30 94 E5 08 30 83 E3 43 24 A0 E1 00 00 E0 E3 01 20 C4 E5 00 30 C4 E5 10 80 BD E8 03 00 1C E3 16 00 00 0A 04 10 1C E2 0B 00 00 1A 14 20 94 E5 10 30 94 E5 03 00 52 E1 01 00 00 1A 02 00 1C E3 05 00 00 0A 01 0B 1C E3 01 20 A0 03 02 20 A0 13 ?? ?? ?? EB 00 00 50 E3 E8 FF FF 1A 00 30 94 E5 08 10 94 E5 03 30 C3 E3 43 24 A0 E1 01 20 C4 E5 14 10 84 E5 }
	condition:
		$pattern
}

rule strncat_b8749f549f2de5596f2dd7da6cba2a14 {
	meta:
		aliases = "__GI_strncat, strncat"
		size = "200"
		objfiles = "strncat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 30 A0 E1 00 40 A0 E1 01 C0 D3 E4 00 00 5C E3 FC FF FF 1A 03 00 52 E3 02 E0 43 E2 22 00 00 9A 22 01 A0 E1 00 30 D1 E5 00 00 53 E3 01 30 CE E5 01 C0 8E E2 20 00 00 0A 01 30 D1 E5 00 00 53 E3 01 30 CC E5 01 10 81 E2 01 C0 8C E2 1A 00 00 0A 01 30 D1 E5 00 00 53 E3 01 30 CC E5 01 10 81 E2 01 E0 8C E2 14 00 00 0A 01 C0 D1 E5 01 30 81 E2 00 00 5C E3 01 C0 CE E5 01 10 83 E2 01 E0 8E E2 0D 00 00 0A 01 00 50 E2 E5 FF FF 1A 03 20 02 E2 05 00 00 EA 00 C0 D1 E5 00 00 5C E3 01 20 42 E2 01 C0 EE E5 04 00 00 0A 01 10 81 E2 00 00 52 E3 F7 FF FF 1A 00 00 5C E3 01 20 CE 15 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule qzero_99daa2d832b05ef65535f813ddd91f67 {
	meta:
		aliases = "qone, qzero"
		size = "328"
		objfiles = "e_j0@libm.a, e_j1@libm.a"
	strings:
		$pattern = { 10 40 2D E9 00 30 A0 E1 0C 31 9F E5 02 21 C0 E3 03 00 52 E1 0C 42 2D ED 01 40 A0 E1 03 00 2D E9 02 F1 BD EC F4 00 9F E5 F4 10 9F E5 0E 00 00 CA F0 30 9F E5 03 00 52 E1 EC 00 9F E5 EC 10 9F E5 09 00 00 CA E8 30 9F E5 03 00 52 E1 E4 00 9F E5 E4 10 9F E5 04 00 00 CA E0 10 9F E5 07 01 72 E3 00 10 A0 D3 D8 00 9F E5 01 00 A0 D1 0A 91 91 ED 08 B1 91 ED 87 01 17 EE 89 01 50 EE 06 D1 91 ED 81 11 10 EE 83 11 01 EE 04 B1 91 ED 0A A1 90 ED 08 C1 90 ED 81 11 10 EE 06 E1 90 ED 85 11 01 EE 81 11 10 EE 83 11 01 EE 04 B1 90 ED 82 21 10 EE 84 21 02 EE 82 21 10 EE 02 C1 91 ED 86 21 02 EE 82 21 10 EE 83 21 02 EE }
	condition:
		$pattern
}

rule __GI_log1p_f7bdfb265507ec344af9a7fc450b95d5 {
	meta:
		aliases = "log1p, __GI_log1p"
		size = "832"
		objfiles = "s_log1p@libm.a"
	strings:
		$pattern = { 10 40 2D E9 00 30 A0 E1 10 33 9F E5 03 00 50 E1 09 C2 6D ED 03 00 2D E9 02 A1 BD EC 01 40 A0 E1 23 00 00 CA F8 32 9F E5 02 11 C0 E3 03 00 51 E1 05 00 00 DA 19 F1 B2 EE A0 81 9F 0D 82 01 22 1E 88 21 40 0E 80 21 40 1E 99 00 00 EA D4 32 9F E5 03 00 51 E1 0E 00 00 CA 9A 81 9F ED 80 01 02 EE 18 F1 D0 EE C0 22 9F E5 00 30 A0 D3 01 30 A0 C3 02 00 51 E1 00 30 A0 C3 01 30 03 D2 00 00 53 E3 82 01 12 0E 8E 91 10 0E 81 01 10 0E 80 21 02 0E 87 00 00 EA 94 32 9F E5 90 22 9F E5 03 30 80 E0 02 00 53 E1 82 B1 00 8E 00 10 A0 83 01 20 A0 83 02 00 00 8A 88 B1 00 EE 01 10 A0 E3 00 20 A0 E3 6C 32 9F E5 03 00 50 E1 }
	condition:
		$pattern
}

rule __GI_expm1_bdc51191cca5a024b69c81fbf4b49852 {
	meta:
		aliases = "expm1, __GI_expm1"
		size = "864"
		objfiles = "s_expm1@libm.a"
	strings:
		$pattern = { 10 40 2D E9 00 30 A0 E1 38 33 9F E5 09 C2 6D ED 01 40 A0 E1 03 00 2D E9 02 C1 BD EC 02 11 C0 E3 00 20 A0 E1 03 00 51 E1 02 01 02 E2 1C 00 00 9A 14 33 9F E5 03 00 51 E1 11 00 00 9A 0C 33 9F E5 03 00 51 E1 09 00 00 9A 02 C1 2D ED 18 00 BD E8 FF 24 C2 E3 0F 26 C2 E3 04 20 92 E1 84 41 04 1E 97 00 00 1A 00 00 50 E3 95 00 00 0A 0A 00 00 EA 96 81 9F ED 10 F1 D4 EE 96 81 9F CD 80 41 10 CE 8F 00 00 CA 00 00 50 E3 05 00 00 0A 93 81 9F ED 80 01 04 EE 18 F1 D0 EE 01 00 00 5A 89 C1 10 EE 87 00 00 EA A8 32 9F E5 03 00 51 E1 1D 00 00 9A A0 32 9F E5 03 00 51 E1 09 00 00 8A 00 00 50 E3 88 81 9F 0D 87 81 9F 1D }
	condition:
		$pattern
}

rule __ieee754_exp_06bb316c50f8928a2a7b52633f3b531c {
	meta:
		aliases = "__ieee754_exp"
		size = "648"
		objfiles = "e_exp@libm.a"
	strings:
		$pattern = { 10 40 2D E9 00 30 A0 E1 58 32 9F E5 03 00 2D E9 02 B1 BD EC 01 40 A0 E1 02 11 C0 E3 00 20 A0 E1 03 00 51 E1 06 42 6D ED A2 0F A0 E1 16 00 00 9A 34 32 9F E5 03 00 51 E1 09 00 00 9A 02 B1 2D ED 18 00 BD E8 FF 24 C2 E3 0F 26 C2 E3 04 20 92 E1 83 31 03 1E 68 00 00 1A 00 00 50 E3 66 00 00 0A 07 00 00 EA 67 81 9F ED 10 F1 D3 EE 67 81 9F CD 80 31 10 CE 60 00 00 CA 66 81 9F ED 10 F1 D3 EE 01 00 00 5A 88 B1 00 EE 5B 00 00 EA DC 31 9F E5 03 00 51 E1 1D 00 00 9A D4 31 9F E5 03 00 51 E1 80 11 A0 E1 0A 00 00 8A C8 31 9F E5 C8 21 9F E5 03 30 81 E0 00 81 93 ED 02 20 81 E0 00 D1 92 ED 00 30 60 E2 03 30 60 E0 }
	condition:
		$pattern
}

rule cos_8c2a0bbc839378299b2afb1fae9fecca {
	meta:
		aliases = "__GI_cos, cos"
		size = "196"
		objfiles = "s_cos@libm.a"
	strings:
		$pattern = { 10 40 2D E9 00 30 A0 E1 AC 30 9F E5 02 21 C0 E3 03 00 52 E1 14 D0 4D E2 03 00 2D E9 02 81 BD EC 01 40 A0 E1 00 20 A0 D3 00 30 A0 D3 0F 00 00 DA 88 30 9F E5 03 00 52 E1 80 01 20 CE 1C 00 00 CA 04 20 8D E2 ?? ?? ?? EB 03 C0 00 E2 01 00 5C E3 08 00 00 0A 02 00 5C E3 0C 00 00 0A 00 00 5C E3 03 00 9D E9 0C 20 8D E2 0C 00 92 E8 0D 00 00 1A ?? ?? ?? EB 0E 00 00 EA 03 00 9D E9 0C 20 8D E2 0C 00 92 E8 00 C0 8D E5 ?? ?? ?? EB 03 00 00 EA 03 00 9D E9 0C 20 8D E2 0C 00 92 E8 ?? ?? ?? EB 80 81 10 EE 02 00 00 EA 01 C0 A0 E3 00 C0 8D E5 ?? ?? ?? EB 14 D0 8D E2 10 80 BD E8 FB 21 E9 3F FF FF EF 7F }
	condition:
		$pattern
}

rule __GI_sin_66bf0de31d7cd5a713e0835d58e75b74 {
	meta:
		aliases = "sin, __GI_sin"
		size = "204"
		objfiles = "s_sin@libm.a"
	strings:
		$pattern = { 10 40 2D E9 00 30 A0 E1 B4 30 9F E5 02 21 C0 E3 03 00 52 E1 14 D0 4D E2 03 00 2D E9 02 81 BD EC 01 40 A0 E1 00 20 A0 D3 00 30 A0 D3 00 C0 A0 D3 10 00 00 DA 8C 30 9F E5 03 00 52 E1 80 01 20 CE 1D 00 00 CA 04 20 8D E2 ?? ?? ?? EB 03 00 00 E2 01 00 50 E3 0A 00 00 0A 02 00 50 E3 0D 00 00 0A 00 00 50 E3 0C 20 8D E2 0C 00 92 E8 03 00 9D E9 0F 00 00 1A 01 C0 A0 E3 00 C0 8D E5 ?? ?? ?? EB 0D 00 00 EA 03 00 9D E9 0C 20 8D E2 0C 00 92 E8 ?? ?? ?? EB 08 00 00 EA 01 C0 A0 E3 03 00 9D E9 0C 20 8D E2 0C 00 92 E8 00 C0 8D E5 ?? ?? ?? EB 00 00 00 EA ?? ?? ?? EB 80 81 10 EE 14 D0 8D E2 10 80 BD E8 FB 21 E9 3F }
	condition:
		$pattern
}

rule __ieee754_acos_248faae563defeacb76f5b5dfdfe3221 {
	meta:
		aliases = "__ieee754_acos"
		size = "768"
		objfiles = "e_acos@libm.a"
	strings:
		$pattern = { 10 40 2D E9 00 30 A0 E1 E4 32 9F E5 02 21 C0 E3 03 00 52 E1 06 42 6D ED 01 40 A0 E1 03 00 2D E9 02 C1 BD EC 0B 00 00 DA 02 C1 2D ED 18 00 BD E8 03 21 82 E2 01 26 82 E2 04 20 92 E1 84 01 24 1E 80 01 40 1E 8E 00 00 1A 8F 81 9F ED 00 00 50 E3 88 81 00 CE 8A 00 00 EA 98 32 9F E5 03 00 52 E1 29 00 00 CA 90 32 9F E5 03 00 52 E1 88 81 9F DD 83 00 00 DA 88 91 9F ED 89 81 9F ED 84 21 14 EE 81 11 12 EE 80 11 01 EE 87 81 9F ED 81 11 12 EE 80 11 21 EE 86 81 9F ED 87 B1 9F ED 80 01 12 EE 83 01 20 EE 86 B1 9F ED 81 11 12 EE 83 11 01 EE 85 B1 9F ED 80 01 12 EE 83 01 00 EE 84 B1 9F ED 81 11 12 EE 83 11 21 EE }
	condition:
		$pattern
}

rule pone_b66d47ad27871a062dcb0bab92732e55 {
	meta:
		aliases = "pzero, pone"
		size = "300"
		objfiles = "e_j0@libm.a, e_j1@libm.a"
	strings:
		$pattern = { 10 40 2D E9 00 30 A0 E1 F0 30 9F E5 02 21 C0 E3 03 00 52 E1 03 00 2D E9 02 81 BD EC 01 40 A0 E1 09 C2 6D ED D8 00 9F E5 D8 10 9F E5 0E 00 00 CA D4 30 9F E5 03 00 52 E1 D0 00 9F E5 D0 10 9F E5 09 00 00 CA CC 30 9F E5 03 00 52 E1 C8 00 9F E5 C8 10 9F E5 04 00 00 CA C4 10 9F E5 07 01 72 E3 00 10 A0 D3 BC 00 9F E5 01 00 A0 D1 0A A1 90 ED 08 B1 90 ED 08 91 91 ED 80 01 10 EE 89 01 50 EE 06 C1 91 ED 06 D1 90 ED 82 21 10 EE 83 21 02 EE 04 B1 90 ED 04 E1 91 ED 81 11 10 EE 82 21 10 EE 84 11 01 EE 85 21 02 EE 02 C1 91 ED 82 21 10 EE 83 21 02 EE 02 B1 90 ED 81 11 10 EE 86 11 01 EE 81 11 10 EE 84 11 01 EE }
	condition:
		$pattern
}

rule mq_unlink_2a37a7706a5a03eeea5760b7422e36ff {
	meta:
		aliases = "mq_unlink"
		size = "112"
		objfiles = "mq_unlink@librt.a"
	strings:
		$pattern = { 10 40 2D E9 00 30 D0 E5 2F 00 53 E3 01 00 80 E2 04 00 00 0A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 0F 00 00 EA 13 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 00 20 54 E2 05 00 00 AA ?? ?? ?? EB 00 30 90 E5 01 00 53 E3 0D 30 A0 03 00 30 80 E5 00 20 E0 E3 02 00 A0 E1 10 80 BD E8 }
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

rule __GI_hdestroy_r_3dc0eaf4579ccd6c547fa55158b6cdb9 {
	meta:
		aliases = "hdestroy_r, __GI_hdestroy_r"
		size = "48"
		objfiles = "hdestroy_r@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 50 E2 03 00 00 1A ?? ?? ?? EB 16 30 A0 E3 00 30 80 E5 10 80 BD E8 00 00 94 E5 ?? ?? ?? EB 00 30 A0 E3 00 30 84 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_dirfd_72deeb3556701f754638cf3f571c21c8 {
	meta:
		aliases = "dirfd, __GI_dirfd"
		size = "36"
		objfiles = "dirfd@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 90 E5 01 00 74 E3 02 00 00 1A ?? ?? ?? EB 09 30 A0 E3 00 30 80 E5 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __register_frame_04f6cec001481293e6082fd6d78cd74c {
	meta:
		aliases = "__register_frame"
		size = "44"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 00 30 94 E5 00 00 53 E3 18 00 A0 E3 10 80 BD 08 ?? ?? ?? EB 00 10 A0 E1 04 00 A0 E1 10 40 BD E8 ?? ?? ?? EA }
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

rule __uc_malloc_7df5cea9676fd9409a5aaf253d5326a9 {
	meta:
		aliases = "__GI___uc_malloc, __uc_malloc"
		size = "80"
		objfiles = "__uc_malloc@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 30 50 E2 01 30 A0 13 00 00 54 E3 01 30 83 03 00 00 53 E3 10 80 BD 18 1C 30 9F E5 00 30 93 E5 00 00 53 E3 01 00 A0 03 ?? ?? ?? 0B 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 EE FF FF EA ?? ?? ?? ?? }
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

rule __exit_handler_c345212084ab7d6c554db2ba15379416 {
	meta:
		aliases = "__exit_handler"
		size = "148"
		objfiles = "__exit_handler@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 15 00 00 EA 00 30 90 E5 0C 20 93 E7 02 00 52 E3 00 10 8E E5 0C 30 83 E0 02 00 00 0A 03 00 52 E3 0D 00 00 1A 07 00 00 EA 04 20 93 E5 00 00 52 E3 04 00 A0 E1 08 00 00 0A 08 10 93 E5 0F E0 A0 E1 02 F0 A0 E1 04 00 00 EA 04 20 93 E5 00 00 52 E3 08 00 93 15 0F E0 A0 11 02 F0 A0 11 20 E0 9F E5 00 30 9E E5 01 10 43 E2 00 00 53 E3 01 C2 A0 E1 10 00 9F E5 E2 FF FF 1A 00 00 90 E5 10 40 BD E8 ?? ?? ?? EA ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __register_frame_table_b734490cf8caa6f405a401125c57e0d8 {
	meta:
		aliases = "__register_frame_table"
		size = "32"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 18 00 A0 E3 ?? ?? ?? EB 00 10 A0 E1 04 00 A0 E1 10 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule pthread_handle_sigrestart_fdb77440c5006d53b0e272554566acfc {
	meta:
		aliases = "pthread_handle_sigrestart"
		size = "40"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 9A FD FF EB 24 30 90 E5 00 00 53 E3 20 40 80 E5 10 80 BD 08 03 00 A0 E1 01 10 A0 E3 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __ether_line_54764e8889d7e6ffa57c43fe762d90ac {
	meta:
		aliases = "__ether_line"
		size = "100"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 10 00 00 0A 00 00 00 EA 01 40 84 E2 00 30 D4 E5 00 00 53 E3 20 00 53 13 03 00 00 0A 09 00 53 E3 F8 FF FF 1A 00 00 00 EA 01 40 84 E2 00 30 D4 E5 00 00 53 E3 03 00 00 0A 09 00 53 E3 20 00 53 13 F8 FF FF 0A 00 00 00 EA 00 40 A0 E3 04 00 A0 E1 10 80 BD E8 }
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

rule raise_95d5c8be653a1bd4a1826b148e18757e {
	meta:
		aliases = "__raise, __GI_raise, raise"
		size = "24"
		objfiles = "raise@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 ?? ?? ?? EB 04 10 A0 E1 10 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule raise_da8c75e51a9881de934cefa8ce74739e {
	meta:
		aliases = "__GI_raise, raise"
		size = "48"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 ?? ?? ?? EB 04 10 A0 E1 ?? ?? ?? EB 00 40 50 E2 04 00 A0 E1 10 80 BD 08 ?? ?? ?? EB 00 40 80 E5 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_login_tty_4acd62c605cac9b67c4079685d6c53dd {
	meta:
		aliases = "login_tty, __GI_login_tty"
		size = "112"
		objfiles = "login_tty@libutil.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 ?? ?? ?? EB 58 10 9F E5 04 00 A0 E1 00 20 A0 E3 ?? ?? ?? EB 00 30 A0 E1 01 00 73 E3 00 10 A0 E3 04 00 A0 E1 0C 00 00 0A ?? ?? ?? EB 01 10 A0 E3 04 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 02 10 A0 E3 ?? ?? ?? EB 02 00 54 E3 04 00 A0 E1 00 30 A0 E3 01 00 00 DA ?? ?? ?? EB 00 30 A0 E3 03 00 A0 E1 10 80 BD E8 0E 54 00 00 }
	condition:
		$pattern
}

rule uw_init_context_f64966e63309cbf621ebcdb8abe2a486 {
	meta:
		aliases = "uw_init_context"
		size = "20"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 B9 FF FF EB 00 00 84 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule pthread_handle_sigcancel_e94209894b0f60adc134701c6646444a {
	meta:
		aliases = "pthread_handle_sigcancel"
		size = "180"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 C7 FD FF EB 90 20 9F E5 02 00 50 E1 02 00 00 1A 04 00 A0 E1 10 40 BD E8 ?? ?? ?? EA 7C 30 9F E5 00 30 93 E5 00 00 53 E3 09 00 00 0A 70 30 9F E5 00 30 93 E5 03 00 50 E1 14 00 92 05 00 10 A0 03 02 21 A0 03 ?? ?? ?? 0B 58 30 9F E5 00 00 93 E5 ?? ?? ?? EB 42 30 D0 E5 00 00 53 E3 10 80 BD 08 40 20 D0 E5 00 00 52 E3 10 80 BD 18 41 30 D0 E5 01 00 53 E3 00 00 E0 03 0D 10 A0 01 ?? ?? ?? 0B 28 30 90 E5 00 00 53 E3 10 80 BD 08 28 20 80 E5 01 10 A0 E3 03 00 A0 E1 ?? ?? ?? EB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_internal_tsd_get_4e5cef88c279f73ab3bbfe89e5ba038b {
	meta:
		aliases = "__pthread_internal_tsd_get"
		size = "24"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 D7 FF FF EB 04 01 80 E0 6C 01 90 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_internal_tsd_address_d81442a8f3c7e78f5b1ca3c32a9645d8 {
	meta:
		aliases = "__pthread_internal_tsd_address"
		size = "24"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E1 DD FF FF EB 04 01 80 E0 5B 0F 80 E2 10 80 BD E8 }
	condition:
		$pattern
}

rule mq_send_15553434ce78754dc7123c05ec661f1a {
	meta:
		aliases = "mq_send"
		size = "48"
		objfiles = "mq_send@librt.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E3 14 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule mq_receive_498ef75ea821e83094aae2ae1aa651da {
	meta:
		aliases = "mq_receive"
		size = "48"
		objfiles = "mq_receive@librt.a"
	strings:
		$pattern = { 10 40 2D E9 00 40 A0 E3 15 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_wcrtomb_f8d65b4cfd9751606c2590a88df04ac7 {
	meta:
		aliases = "wcrtomb, __GI_wcrtomb"
		size = "80"
		objfiles = "wcrtomb@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 C0 50 E2 1C D0 4D E2 04 C0 8D 02 01 E0 A0 E1 02 40 A0 E1 00 E0 A0 01 10 30 A0 E3 14 10 8D E2 01 20 A0 E3 0C 00 A0 E1 18 C0 8D E2 14 C0 8D E5 18 E0 8D E5 00 40 8D E5 ?? ?? ?? EB 00 00 50 E3 01 00 A0 03 1C D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule mbtowc_0abec315ed6a063f3b79ab220bc6d6c7 {
	meta:
		aliases = "mbtowc"
		size = "84"
		objfiles = "mbtowc@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 E0 51 E2 3C 30 9F 05 0E C0 A0 E1 00 E0 83 05 0A 00 00 0A 00 C0 DE E5 28 40 9F E5 00 00 5C E3 04 30 A0 E1 05 00 00 0A ?? ?? ?? EB 02 00 70 E3 14 30 9F 05 04 30 84 05 00 C0 E0 E3 00 C0 A0 11 0C 00 A0 E1 10 80 BD E8 ?? ?? ?? ?? FF FF 00 00 }
	condition:
		$pattern
}

rule strcasecmp_806f1992b366cb296bf70bbf859f9d7a {
	meta:
		aliases = "__GI_strcasecmp, strcasecmp"
		size = "124"
		objfiles = "strcasecmp@libc.a"
	strings:
		$pattern = { 10 40 2D E9 00 E0 A0 E1 01 40 A0 E1 00 00 A0 E3 04 00 5E E1 11 00 00 0A 58 30 9F E5 00 C0 DE E5 00 20 D4 E5 00 30 93 E5 8C C0 A0 E1 82 20 A0 E1 03 00 82 E0 03 10 8C E0 01 10 D1 E5 01 00 D0 E5 03 20 D2 E7 03 30 DC E7 00 0C A0 E1 01 1C A0 E1 41 38 83 E1 40 28 82 E1 02 00 53 E0 10 80 BD 18 00 30 DE E5 00 00 53 E3 01 40 84 E2 01 E0 8E E2 E6 FF FF 1A 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __register_frame_info_table_ba_2bd16ea7b10ee076b407d783c1840899 {
	meta:
		aliases = "__register_frame_info_table_bases"
		size = "88"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { 10 40 2D E9 00 E0 A0 E3 10 E0 81 E5 10 C0 D1 E5 02 C0 8C E3 10 C0 C1 E5 10 E0 91 E5 7F EE 8E E3 08 E0 8E E3 4E C4 A0 E1 11 C0 C1 E5 10 E0 C1 E5 1C 40 9F E5 00 C0 94 E5 0C 00 81 E5 00 00 E0 E3 14 C0 81 E5 00 00 81 E5 00 10 84 E5 0C 00 81 E9 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wcsnrtombs_772ecfa0c885fb922ef4f9dba3cdb32f {
	meta:
		aliases = "__GI_wcsnrtombs, wcsnrtombs"
		size = "188"
		objfiles = "wcsnrtombs@libc.a"
	strings:
		$pattern = { 10 40 2D E9 01 00 50 E1 00 00 50 13 02 E0 A0 E1 10 D0 4D E2 00 C0 A0 E1 01 20 A0 13 0E 00 00 1A 00 00 50 E3 0D C0 A0 E1 00 20 A0 01 00 30 E0 03 09 00 00 0A 06 00 00 EA ?? ?? ?? EB 54 30 A0 E3 00 20 E0 E3 00 30 80 E5 18 00 00 EA 03 E0 A0 E1 13 00 00 EA 0D C0 A0 E1 00 20 A0 E3 03 00 5E E1 0E 40 A0 31 03 40 A0 21 00 E0 91 E5 04 00 A0 E1 09 00 00 EA 00 30 9E E5 7F 00 53 E3 04 E0 8E E2 EC FF FF 8A 00 30 CC E5 00 30 DC E5 00 00 53 E3 ED FF FF 0A 02 C0 8C E0 01 00 40 E2 00 00 50 E3 F3 FF FF 1A 0D 00 5C E1 00 E0 81 15 04 20 60 E0 02 00 A0 E1 10 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __ieee754_log2_66434d59af003e0933317044e7671b50 {
	meta:
		aliases = "__ieee754_log2"
		size = "548"
		objfiles = "e_log2@libm.a"
	strings:
		$pattern = { 10 40 2D E9 01 06 50 E3 01 40 A0 E1 03 00 2D E9 02 91 BD EC 0C 42 2D ED 04 10 A0 E1 00 30 A0 E1 00 20 A0 E1 00 10 A0 A3 0F 00 00 AA 02 31 C2 E3 01 30 93 E1 5F 81 9F 0D 81 11 21 0E 81 61 40 0E 59 00 00 0A 00 00 52 E3 81 01 21 BE 80 61 40 BE 55 00 00 BA 59 81 9F ED 80 11 11 EE 02 91 2D ED 18 00 BD E8 35 10 E0 E3 03 20 A0 E1 9C 31 9F E5 03 00 52 E1 81 61 01 CE 4B 00 00 CA 02 91 2D ED 18 00 BD E8 FF E4 C2 E3 84 C1 9F E5 0F E6 CE E3 42 2A 81 E0 0C C0 8E E0 78 11 9F E5 01 C6 0C E2 01 10 2C E0 01 30 8E E1 18 00 2D E9 02 81 BD EC 02 00 8E E2 FF 2F 42 E2 FF 04 C0 E3 03 20 42 E2 0F 06 C0 E3 2C 2A 82 E0 }
	condition:
		$pattern
}

rule __ieee754_log10_01df28243ce5a339316fb1ed5a4438bc {
	meta:
		aliases = "__ieee754_log10"
		size = "264"
		objfiles = "e_log10@libm.a"
	strings:
		$pattern = { 10 40 2D E9 01 06 50 E3 01 40 A0 E1 04 20 A0 E1 03 C2 2D ED 03 00 2D E9 02 91 BD EC 00 30 A0 E1 00 20 A0 A3 0E 00 00 AA 02 31 C0 E3 02 30 93 E1 29 81 9F 0D 02 00 00 0A 00 00 50 E3 02 00 00 AA 81 01 21 EE 88 01 40 EE 21 00 00 EA 24 81 9F ED 80 11 11 EE 02 91 2D ED 18 00 BD E8 35 20 E0 E3 03 00 A0 E1 98 30 9F E5 03 00 50 E1 81 01 01 CE 17 00 00 CA 02 91 2D ED 18 00 BD E8 40 2A 82 E0 FF 2F 42 E2 03 20 42 E2 A2 CF A0 E1 FF 1F 6C E2 FF 04 C0 E3 0F 06 C0 E3 03 10 81 E2 01 3A 80 E1 0C 20 82 E0 03 00 A0 E1 04 10 A0 E1 90 21 04 EE ?? ?? ?? EB 0C 91 9F ED 81 01 10 EE 0C 91 9F ED 81 11 14 EE 80 11 01 EE }
	condition:
		$pattern
}

rule __ieee754_log_6322bea15b20817d591a87cae216dfa3 {
	meta:
		aliases = "__ieee754_log"
		size = "680"
		objfiles = "e_log@libm.a"
	strings:
		$pattern = { 10 40 2D E9 01 06 50 E3 03 00 2D E9 02 91 BD EC 00 30 A0 E1 00 20 A0 E1 09 C2 6D ED 01 40 A0 E1 00 00 A0 A3 0E 00 00 AA 02 31 C2 E3 04 30 93 E1 7D 81 9F 0D 02 00 00 0A 00 00 52 E3 02 00 00 AA 81 01 21 EE 88 01 40 EE 75 00 00 EA 78 81 9F ED 80 11 11 EE 02 91 2D ED 18 00 BD E8 35 00 E0 E3 03 20 A0 E1 28 32 9F E5 03 00 52 E1 81 01 01 CE 6B 00 00 CA 02 91 2D ED 18 00 BD E8 FF E4 C2 E3 10 C2 9F E5 0F E6 CE E3 42 0A 80 E0 0C C0 8E E0 04 22 9F E5 01 C6 0C E2 02 20 2C E0 02 30 8E E1 18 00 2D E9 02 81 BD EC 02 10 8E E2 FF 14 C1 E3 0F 16 C1 E3 FF 0F 40 E2 02 00 51 E3 03 00 40 E2 2C 1A 80 E0 89 51 20 EE }
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

rule _dl_strdup_b2dce3867191a03d5a5c08e2c8c2bcb7 {
	meta:
		aliases = "_dl_strdup"
		size = "68"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 10 40 2D E9 01 40 40 E2 00 20 A0 E1 04 00 A0 E1 01 30 F0 E5 00 00 53 E3 FC FF FF 1A 00 00 62 E0 01 00 80 E2 ?? ?? ?? EB 01 20 40 E2 01 30 F4 E5 01 30 E2 E5 00 30 D2 E5 00 00 53 E3 FA FF FF 1A 10 80 BD E8 }
	condition:
		$pattern
}

rule sigwait_3b0eef2647f8a1ad7c27e249a390d393 {
	meta:
		aliases = "__sigwait, __GI_sigwait, sigwait"
		size = "40"
		objfiles = "sigwait@libc.a"
	strings:
		$pattern = { 10 40 2D E9 01 40 A0 E1 00 10 A0 E3 ?? ?? ?? EB 01 00 70 E3 01 30 A0 E3 00 30 A0 13 00 00 84 15 03 00 A0 E1 10 80 BD E8 }
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

rule authnone_marshal_48285b963ce122eaa17ac686b2351718 {
	meta:
		aliases = "authnone_marshal"
		size = "64"
		objfiles = "auth_none@libc.a"
	strings:
		$pattern = { 10 40 2D E9 01 40 A0 E1 ?? ?? ?? EB 98 30 90 E5 00 00 53 E3 03 20 A0 E1 04 00 A0 E1 28 10 83 E2 04 00 00 0A 3C 20 93 E5 04 30 94 E5 0F E0 A0 E1 0C F0 93 E5 00 20 A0 E1 02 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule tempnam_a54290a5fc0e78934e93134e614ccf5e {
	meta:
		aliases = "tempnam"
		size = "92"
		objfiles = "tempnam@libc.a"
	strings:
		$pattern = { 10 40 2D E9 01 DA 4D E2 10 40 8D E2 0F 40 44 E2 00 20 A0 E1 01 30 A0 E1 04 00 A0 E1 34 10 9F E5 ?? ?? ?? EB 00 00 50 E3 03 10 A0 E3 04 00 A0 E1 05 00 00 1A ?? ?? ?? EB 00 00 50 E3 04 00 A0 E1 01 00 00 1A ?? ?? ?? EB 00 00 00 EA 00 00 A0 E3 01 DA 8D E2 10 80 BD E8 FF 0F 00 00 }
	condition:
		$pattern
}

rule fork_2524585996bf4fad60cd85e6024dca56 {
	meta:
		aliases = "__GI_fork, __libc_fork, fork"
		size = "44"
		objfiles = "fork@libc.a"
	strings:
		$pattern = { 10 40 2D E9 02 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
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

rule logb_034705ec2269ad6b82f2fc4d79f2bf96 {
	meta:
		aliases = "__GI_logb, logb"
		size = "104"
		objfiles = "s_logb@libm.a"
	strings:
		$pattern = { 10 40 2D E9 02 21 C0 E3 01 40 A0 E1 00 30 A0 E1 04 30 92 E1 03 00 2D E9 02 81 BD EC 03 00 00 1A ?? ?? ?? EB 89 91 10 EE 80 01 41 EE 10 80 BD E8 2C 30 9F E5 03 00 52 E1 42 1A A0 E1 80 01 10 CE 10 80 BD C8 FF 3F 41 E2 00 00 51 E3 03 30 43 E2 01 81 9F ED 90 31 00 1E 10 80 BD E8 00 F0 8F C0 00 00 00 00 FF FF EF 7F }
	condition:
		$pattern
}

rule __GI_fabs_b3fa49e51260fb776adf134e8b366610 {
	meta:
		aliases = "fabs, __GI_fabs"
		size = "24"
		objfiles = "s_fabs@libm.a"
	strings:
		$pattern = { 10 40 2D E9 02 31 C0 E3 01 40 A0 E1 18 00 2D E9 02 81 BD EC 10 80 BD E8 }
	condition:
		$pattern
}

rule ether_line_48fa96d5e875c4359a38e35f097dc431 {
	meta:
		aliases = "ether_line"
		size = "96"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { 10 40 2D E9 02 40 A0 E1 E3 FF FF EB 00 00 50 E3 00 00 E0 03 10 80 BD 08 07 00 00 EA 23 00 52 E3 09 00 00 0A 30 30 9F E5 00 30 93 E5 82 30 D3 E7 20 00 13 E3 04 00 00 1A 01 20 C4 E4 00 20 D0 E5 00 00 52 E3 01 00 80 E2 F3 FF FF 1A 00 30 A0 E3 03 00 A0 E1 00 30 C4 E5 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule frexp_7bec1bf4e8e2874a2e255006b78ed0a4 {
	meta:
		aliases = "__GI_frexp, frexp"
		size = "172"
		objfiles = "s_frexp@libm.a"
	strings:
		$pattern = { 10 40 2D E9 03 00 2D E9 02 91 BD EC 01 40 A0 E1 90 10 9F E5 02 C1 C0 E3 02 E0 A0 E1 01 00 5C E1 00 20 A0 E3 00 30 A0 E1 00 20 8E E5 04 30 A0 E1 18 00 00 CA 03 30 9C E1 16 00 00 0A 01 06 5C E3 07 00 00 AA 15 81 9F ED 80 11 11 EE 02 91 2D ED 18 00 BD E8 03 00 A0 E1 35 30 E0 E3 00 30 8E E5 02 C1 C0 E3 02 91 2D ED 06 00 BD E8 7F 04 C0 E3 0F 06 C0 E3 FF 15 80 E3 02 16 81 E3 06 00 2D E9 02 91 BD EC 00 30 9E E5 2C 3A 83 E0 FF 3F 43 E2 02 30 43 E2 00 30 8E E5 81 81 00 EE 10 80 BD E8 00 00 50 43 00 00 00 00 FF FF EF 7F }
	condition:
		$pattern
}

rule __GI_read_bf685557a51aad42b8ca7c6edcef2059 {
	meta:
		aliases = "read, __libc_read, __GI_read"
		size = "44"
		objfiles = "read@libc.a"
	strings:
		$pattern = { 10 40 2D E9 03 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
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

rule ldexp_0758ae163d1766be8eaee2ab4adbca7d {
	meta:
		aliases = "__GI_ldexp, ldexp"
		size = "112"
		objfiles = "s_ldexp@libm.a"
	strings:
		$pattern = { 10 40 2D E9 03 C2 2D ED 02 40 A0 E1 03 00 2D E9 02 C1 BD EC ?? ?? ?? EB 00 00 50 E3 10 00 00 0A 18 F1 94 EE 04 20 A0 E1 02 C1 2D ED 03 00 BD E8 0B 00 00 0A ?? ?? ?? EB 02 81 2D ED 03 00 BD E8 80 C1 00 EE ?? ?? ?? EB 00 00 50 E3 01 00 00 0A 18 F1 94 EE 02 00 00 1A ?? ?? ?? EB 22 30 A0 E3 00 30 80 E5 84 81 00 EE 03 C2 BD EC 10 80 BD E8 }
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

rule __GI_write_00b70833483ae7547e6dfc8ebd43121c {
	meta:
		aliases = "write, __libc_write, __GI_write"
		size = "44"
		objfiles = "write@libc.a"
	strings:
		$pattern = { 10 40 2D E9 04 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule xdrstdio_getint32_f57e8cd0a850ab55f6f9d612d38d62fc {
	meta:
		aliases = "xdrstdio_getlong, xdrstdio_getint32"
		size = "96"
		objfiles = "xdr_stdio@libc.a"
	strings:
		$pattern = { 10 40 2D E9 04 D0 4D E2 0C 30 90 E5 01 40 A0 E1 0D 00 A0 E1 04 10 A0 E3 01 20 A0 E3 ?? ?? ?? EB 01 00 50 E3 00 C0 A0 E1 00 00 A0 E3 09 00 00 1A 00 30 9D E5 FF 28 03 E2 FF 1C 03 E2 22 24 A0 E1 01 14 A0 E1 03 1C 81 E1 23 2C 82 E1 01 20 82 E1 00 20 84 E5 0C 00 A0 E1 04 D0 8D E2 10 80 BD E8 }
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

rule mbsnrtowcs_300aeaf4470fa6bcb08f56512cb422a8 {
	meta:
		aliases = "__GI_mbsnrtowcs, mbsnrtowcs"
		size = "204"
		objfiles = "mbsnrtowcs@libc.a"
	strings:
		$pattern = { 10 40 2D E9 04 D0 4D E2 0C C0 9D E5 B4 E0 9F E5 00 00 5C E3 0E C0 A0 01 0C 00 50 E1 00 00 50 13 01 40 A0 E1 00 E0 A0 E1 02 10 A0 E1 01 20 A0 13 0E 00 00 1A 00 00 50 E3 0D E0 A0 01 00 20 A0 01 00 30 E0 03 09 00 00 0A 06 00 00 EA 03 C0 A0 E1 16 00 00 EA ?? ?? ?? EB 54 30 A0 E3 00 20 E0 E3 00 30 80 E5 14 00 00 EA 0D E0 A0 E1 00 20 A0 E3 03 00 51 E1 03 10 A0 21 00 C0 94 E5 01 00 A0 E1 08 00 00 EA 00 30 DC E5 00 00 53 E3 01 C0 8C E2 00 30 8E E5 EC FF FF 0A 7F 00 53 E3 EC FF FF CA 02 E1 8E E0 01 00 40 E2 00 00 50 E3 F4 FF FF 1A 0D 00 5E E1 00 C0 84 15 01 20 60 E0 02 00 A0 E1 04 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __fresetlockfiles_f98de21b022f53ee4db12e322d47a256 {
	meta:
		aliases = "__fresetlockfiles"
		size = "96"
		objfiles = "lockfile@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 04 D0 4D E2 0D 00 A0 E1 ?? ?? ?? EB 0D 00 A0 E1 01 10 A0 E3 ?? ?? ?? EB 34 30 9F E5 00 40 93 E5 03 00 00 EA 2C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 20 40 94 E5 00 00 54 E3 38 00 84 E2 0D 10 A0 E1 F7 FF FF 1A 0D 00 A0 E1 ?? ?? ?? EB 04 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule close_06e8dc28926387eeb84f9d2d16b42772 {
	meta:
		aliases = "fsync, tcdrain, wait, system, close"
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

rule set_input_fragment_f55163e6a287f5dd75504a4639d53040 {
	meta:
		aliases = "set_input_fragment"
		size = "108"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 10 40 2D E9 04 D0 4D E2 0D 10 A0 E1 04 20 A0 E3 00 40 A0 E1 DB FF FF EB 00 00 50 E3 0F 00 00 0A 00 10 9D E5 FF 38 01 E2 FF 2C 01 E2 23 34 A0 E1 02 24 A0 E1 01 2C 82 E1 21 3C 83 E1 02 30 83 E1 00 00 53 E3 02 11 C3 E3 A3 2F A0 E1 38 20 84 E5 01 00 A0 E3 00 30 8D E5 34 10 84 15 00 00 00 1A 00 00 A0 E3 04 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __libc_close_9aaf12bb1410337042cee9181e612ffe {
	meta:
		aliases = "__GI_close, close, __libc_close"
		size = "44"
		objfiles = "close@libc.a"
	strings:
		$pattern = { 10 40 2D E9 06 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule clock_settime_c341da7103081706c4440a8528f5a1cf {
	meta:
		aliases = "clock_settime"
		size = "44"
		objfiles = "clock_settime@libc.a"
	strings:
		$pattern = { 10 40 2D E9 06 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
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

rule clock_gettime_522f680d61b71bb6ed259af92d936deb {
	meta:
		aliases = "clock_gettime"
		size = "44"
		objfiles = "clock_gettime@libc.a"
	strings:
		$pattern = { 10 40 2D E9 07 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_clock_getres_0324c7f4af5de7bb2efa07839868c1ad {
	meta:
		aliases = "clock_getres, __GI_clock_getres"
		size = "44"
		objfiles = "clock_getres@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
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

rule __GI_sigsuspend_d912cdcac22736d5130c4f477a585453 {
	meta:
		aliases = "__libc_sigsuspend, sigsuspend, __GI_sigsuspend"
		size = "48"
		objfiles = "sigsuspend@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 10 A0 E3 B3 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __stdio_wcommit_6da76afd6605b84b30cc6d143eac863f {
	meta:
		aliases = "__stdio_wcommit"
		size = "48"
		objfiles = "_wcommit@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 30 90 E5 10 20 90 E5 03 20 52 E0 00 40 A0 E1 03 10 A0 E1 10 30 80 15 ?? ?? ?? 1B 08 30 94 E5 10 00 94 E5 00 00 63 E0 10 80 BD E8 }
	condition:
		$pattern
}

rule mount_7db108b3bba7b46b0dc1bd8c717160e4 {
	meta:
		aliases = "mount"
		size = "48"
		objfiles = "mount@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 15 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_setsockopt_430a20655714774d678a001e5fb564cd {
	meta:
		aliases = "setsockopt, __GI_setsockopt"
		size = "48"
		objfiles = "setsockopt@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 26 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule getsockopt_3c1b7aa1ce2ea35ae7194f86df173830 {
	meta:
		aliases = "getsockopt"
		size = "48"
		objfiles = "getsockopt@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 27 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule msgrcv_ccebbacb1ce67ba191248de023a1eb8a {
	meta:
		aliases = "msgrcv"
		size = "48"
		objfiles = "msgrcv@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 2E 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule init_module_412e92a0d1e4590a3e3ad91042935913 {
	meta:
		aliases = "init_module"
		size = "48"
		objfiles = "init_module@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 80 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule select_39ddab70bdbf3a31fad1274de668677d {
	meta:
		aliases = "__GI_select, __libc_select, select"
		size = "48"
		objfiles = "select@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 8E 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_mremap_6763d9afeb7d63eca51273591fd6c94c {
	meta:
		aliases = "mremap, __GI_mremap"
		size = "48"
		objfiles = "mremap@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 A3 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule prctl_1eeed681533004f02d072b6e94f57a28 {
	meta:
		aliases = "prctl"
		size = "48"
		objfiles = "prctl@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 AC 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule setxattr_38320baf44bc4feb717a15c7d1c78113 {
	meta:
		aliases = "setxattr"
		size = "48"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 E2 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule lsetxattr_03aff1a903d029344f79926f6c176e3f {
	meta:
		aliases = "lsetxattr"
		size = "48"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 E3 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule fsetxattr_d859187af2b2d81ed4a25765de474021 {
	meta:
		aliases = "fsetxattr"
		size = "48"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 E4 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule remap_file_pages_4b119b7cc7fb20d162b75b111b8fc6b6 {
	meta:
		aliases = "remap_file_pages"
		size = "48"
		objfiles = "remap_file_pages@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 40 9D E5 FD 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule byte_insert_op2_f46f31954fa77ff30cb465dc34a6e594 {
	meta:
		aliases = "byte_insert_op2"
		size = "56"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 C0 9D E5 01 E0 A0 E1 03 40 A0 E1 0C 10 A0 E1 05 C0 8C E2 01 00 00 EA 01 30 71 E5 01 30 6C E5 0E 00 51 E1 FB FF FF 1A 04 30 A0 E1 10 40 BD E8 DD FF FF EA }
	condition:
		$pattern
}

rule getprotobyname_0b185543e9112af9d6e542b9c6906dfb {
	meta:
		aliases = "getprotobyname"
		size = "72"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 D0 4D E2 00 40 A0 E1 7F FE FF EB 24 30 9F E5 04 C0 8D E2 00 20 93 E5 04 00 A0 E1 18 10 9F E5 18 30 9F E5 00 C0 8D E5 ?? ?? ?? EB 04 00 9D E5 08 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? 8D 10 00 00 }
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

rule getprotobynumber_e898399d251b9afd46abba9a201ff5c3 {
	meta:
		aliases = "getprotobynumber"
		size = "72"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 D0 4D E2 00 40 A0 E1 D1 FE FF EB 24 30 9F E5 04 C0 8D E2 00 20 93 E5 04 00 A0 E1 18 10 9F E5 18 30 9F E5 00 C0 8D E5 ?? ?? ?? EB 04 00 9D E5 08 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? 8D 10 00 00 }
	condition:
		$pattern
}

rule getrlimit64_7af8c34f8bc6c9bdbf77aa304bb0da9d {
	meta:
		aliases = "getrlimit64"
		size = "116"
		objfiles = "getrlimit64@libc.a"
	strings:
		$pattern = { 10 40 2D E9 08 D0 4D E2 01 40 A0 E1 0D 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 E0 E3 12 00 00 BA 00 30 9D E5 01 00 73 E3 03 20 A0 E1 00 30 A0 E3 00 20 E0 03 00 30 E0 03 0C 00 84 E8 04 30 9D E5 01 00 73 E3 00 00 A0 E3 03 10 A0 E1 00 20 A0 E3 00 20 E0 03 00 30 E0 03 08 20 84 05 0C 30 84 05 08 10 84 15 0C 20 84 15 00 00 A0 13 08 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule setkey_a43953ec49c93cef88eedc05efca6f48 {
	meta:
		aliases = "setkey"
		size = "116"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { 10 40 2D E9 08 D0 4D E2 0D 40 A0 E1 00 C0 A0 E3 10 00 00 EA 00 30 A0 E3 03 10 A0 E1 0C E0 84 E0 0C 30 C4 E7 08 00 00 EA 00 30 D0 E5 01 00 13 E3 38 30 9F 15 01 20 D3 17 00 30 DE 15 02 30 83 11 00 30 CE 15 01 00 80 E2 01 10 81 E2 07 00 51 E3 F4 FF FF DA 01 C0 8C E2 07 00 5C E3 EC FF FF DA 04 00 A0 E1 DF FD FF EB 08 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule link_3e7bd68ce9533e50ad554b0f371af2fa {
	meta:
		aliases = "link"
		size = "44"
		objfiles = "link@libc.a"
	strings:
		$pattern = { 10 40 2D E9 09 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule asinh_1d106e19b49467c800c4899ad27568fe {
	meta:
		aliases = "__GI_asinh, asinh"
		size = "284"
		objfiles = "s_asinh@libm.a"
	strings:
		$pattern = { 10 40 2D E9 09 C2 6D ED 03 00 2D E9 02 D1 BD EC F8 30 9F E5 02 21 C0 E3 03 00 52 E1 00 40 A0 E1 85 51 05 CE 32 00 00 CA E4 30 9F E5 03 00 52 E1 03 00 00 CA 31 81 9F ED 80 01 05 EE 19 F1 D0 EE 2B 00 00 CA CC 30 9F E5 03 00 52 E1 06 00 00 DA ?? ?? ?? EB 02 81 2D ED 03 00 BD E8 ?? ?? ?? EB 28 91 9F ED 81 01 00 EE 1E 00 00 EA 01 01 52 E3 85 61 15 EE 0D 00 00 DA ?? ?? ?? EB 89 61 06 EE 02 E1 2D ED 03 00 BD E8 80 C1 00 EE ?? ?? ?? EB 84 01 00 EE 89 01 50 EE 84 41 04 EE 80 41 04 EE 02 C1 2D ED 03 00 BD E8 ?? ?? ?? EB 0D 00 00 EA 89 01 06 EE 02 81 2D ED 03 00 BD E8 ?? ?? ?? EB 02 D1 2D ED 03 00 BD E8 }
	condition:
		$pattern
}

rule unlink_4b7cb0d8f2679052b53140929f4f0068 {
	meta:
		aliases = "__GI_unlink, unlink"
		size = "44"
		objfiles = "unlink@libc.a"
	strings:
		$pattern = { 10 40 2D E9 0A 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_execve_f5907fc7ea28c344984ecab5860ed58b {
	meta:
		aliases = "execve, __GI_execve"
		size = "44"
		objfiles = "execve@libc.a"
	strings:
		$pattern = { 10 40 2D E9 0B 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_chdir_371cd2f0a7f01d355b452bc409c9a820 {
	meta:
		aliases = "chdir, __GI_chdir"
		size = "44"
		objfiles = "chdir@libc.a"
	strings:
		$pattern = { 10 40 2D E9 0C 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
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

rule __GI_xdrrec_skiprecord_f16dbce9fa5e98835ce4d27d47b32eeb {
	meta:
		aliases = "xdrrec_skiprecord, __GI_xdrrec_skiprecord"
		size = "112"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 10 40 2D E9 0C 40 90 E5 0B 00 00 EA 8E FF FF EB 00 00 50 E3 04 00 A0 E1 12 00 00 0A 38 30 94 E5 00 00 53 E3 00 30 A0 E3 34 30 84 E5 02 00 00 1A B9 FF FF EB 00 00 50 E3 0A 00 00 0A 34 30 94 E5 00 10 53 E2 04 00 A0 E1 EF FF FF CA 38 30 94 E5 00 00 53 E3 EC FF FF 0A 00 30 A0 E3 01 00 A0 E3 38 30 84 E5 10 80 BD E8 00 00 A0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule xdrrec_eof_f00c575f6bdfa9eedfb5bd952686f0db {
	meta:
		aliases = "__GI_xdrrec_eof, xdrrec_eof"
		size = "120"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 10 40 2D E9 0C 40 90 E5 0B 00 00 EA AC FF FF EB 00 00 50 E3 04 00 A0 E1 14 00 00 0A 38 30 94 E5 00 00 53 E3 00 30 A0 E3 34 30 84 E5 02 00 00 1A D7 FF FF EB 00 00 50 E3 0C 00 00 0A 34 30 94 E5 00 10 53 E2 04 00 A0 E1 EF FF FF CA 38 30 94 E5 00 00 53 E3 EC FF FF 0A 30 20 94 E5 2C 30 94 E5 02 00 53 E1 00 00 A0 13 01 00 A0 03 10 80 BD E8 01 00 A0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_localtime_6446048565b3ab2258d4e2ff685dc75d {
	meta:
		aliases = "localtime, __GI_localtime"
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

rule __ieee754_j0_95c2908a7b4bef3f539422d71542ab3e {
	meta:
		aliases = "__ieee754_j0"
		size = "600"
		objfiles = "e_j0@libm.a"
	strings:
		$pattern = { 10 40 2D E9 0C 42 2D ED 38 32 9F E5 02 41 C0 E3 03 00 54 E1 08 D0 4D E2 03 00 2D E9 02 81 BD EC 80 01 10 CE 89 01 50 CE 6B 00 00 CA ?? ?? ?? EB 07 01 74 E3 80 E1 00 EE 32 00 00 DA 02 81 2D ED 03 00 BD E8 ?? ?? ?? EB 02 E1 2D ED 03 00 BD E8 80 D1 00 EE ?? ?? ?? EB EC 31 9F E5 80 C1 00 EE 03 00 54 E1 80 01 25 EE 00 81 8D ED 84 71 05 EE 0A 00 00 CA 86 11 06 EE 02 91 2D ED 03 00 BD E8 ?? ?? ?? EB 84 11 15 EE 18 F1 D1 EE 80 81 10 EE 00 91 9D 4D 87 01 40 5E 00 81 8D 5D 81 71 40 4E 12 03 54 E3 06 00 00 DA 02 E1 2D ED 03 00 BD E8 ?? ?? ?? EB 4B 91 9F ED 81 11 17 EE 80 01 41 EE 45 00 00 EA 02 E1 2D ED }
	condition:
		$pattern
}

rule gethostbyname_3a522632acaa2f6f525a6fd7fc370f98 {
	meta:
		aliases = "__GI_gethostbyname, gethostbyname"
		size = "68"
		objfiles = "gethostbyname@libc.a"
	strings:
		$pattern = { 10 40 2D E9 0C D0 4D E2 00 40 A0 E1 ?? ?? ?? EB 08 C0 8D E2 04 00 8D E5 1C 10 9F E5 04 00 A0 E1 18 20 9F E5 73 3F A0 E3 00 C0 8D E5 ?? ?? ?? EB 08 00 9D E5 0C D0 8D E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdrrec_endofrecord_d2623339f4a3b7efab6e5ec2e04ec436 {
	meta:
		aliases = "__GI_xdrrec_endofrecord, xdrrec_endofrecord"
		size = "144"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 10 40 2D E9 0C E0 90 E5 00 00 51 E3 0E 00 A0 E1 01 10 A0 E3 07 00 00 1A 1C 30 9E E5 00 00 53 E3 04 00 00 1A 10 40 9E E5 14 20 9E E5 04 30 84 E2 02 00 53 E1 03 00 00 3A 00 30 A0 E3 1C 30 8E E5 10 40 BD E8 CB FF FF EA 18 C0 9E E5 04 20 6C E0 04 20 42 E2 02 21 82 E3 FF 38 02 E2 FF 1C 02 E2 23 34 A0 E1 01 14 A0 E1 02 1C 81 E1 22 3C 83 E1 01 30 83 E1 00 30 8C E5 10 20 9E E5 01 00 A0 E3 04 30 82 E2 10 30 8E E5 18 20 8E E5 10 80 BD E8 }
	condition:
		$pattern
}

rule time_5d596cb6be643f116c3c09f5893ab8c3 {
	meta:
		aliases = "__GI_time, time"
		size = "44"
		objfiles = "time@libc.a"
	strings:
		$pattern = { 10 40 2D E9 0D 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule utimes_005af2629c9c7886843b19d555f69de1 {
	meta:
		aliases = "__GI_utimes, utimes"
		size = "44"
		objfiles = "utimes@libc.a"
	strings:
		$pattern = { 10 40 2D E9 0D 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI___fgetc_unlocked_ba13e73ea0c557d155bb10f1906ac51b {
	meta:
		aliases = "__GI_getc_unlocked, __fgetc_unlocked, __GI_fgetc_unlocked, getc_unlocked, fgetc_unlocked, __GI___fgetc_unlocked"
		size = "304"
		objfiles = "fgetc_unlocked@libc.a"
	strings:
		$pattern = { 10 40 2D E9 10 20 90 E5 18 30 90 E5 03 00 52 E1 00 40 A0 E1 01 00 D2 34 04 D0 4D E2 10 20 84 35 3F 00 00 3A 00 30 D4 E5 83 30 03 E2 80 00 53 E3 03 00 00 8A 80 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 36 00 00 1A 00 20 D4 E5 01 30 D4 E5 03 24 82 E1 02 00 12 E3 09 00 00 0A 01 30 02 E2 03 31 84 E0 24 30 D3 E5 01 20 42 E2 42 14 A0 E1 03 00 A0 E1 00 30 A0 E3 28 30 84 E5 01 10 C4 E5 0C 00 00 EA 10 10 84 E2 0A 00 91 E8 01 00 53 E1 01 00 D1 14 10 10 84 15 22 00 00 1A 04 30 94 E5 02 00 73 E3 05 00 00 1A 04 20 82 E3 42 34 A0 E1 01 30 C4 E5 00 00 E0 E3 00 20 C4 E5 19 00 00 EA 03 0C 12 E3 64 00 9F 15 ?? ?? ?? 1B }
	condition:
		$pattern
}

rule __scan_getc_d835334ad16b5382ebb65ce2ad38c741 {
	meta:
		aliases = "__scan_getc"
		size = "136"
		objfiles = "__scan_cookie@libc.a"
	strings:
		$pattern = { 10 40 2D E9 10 30 90 E5 00 20 E0 E3 01 30 43 E2 02 10 A0 E1 00 20 80 E5 19 20 D0 E5 00 00 53 E3 10 30 80 E5 00 40 A0 E1 02 30 82 E3 0B 00 00 BA 00 00 52 E3 00 30 A0 13 19 30 C0 15 09 00 00 1A 0F E0 A0 E1 2C F0 90 E5 01 00 70 E3 00 10 A0 E1 04 00 84 15 03 00 00 1A 19 30 D4 E5 02 30 83 E3 19 30 C4 E5 05 00 00 EA 0C 30 94 E5 04 20 94 E5 01 30 83 E2 00 20 84 E5 0C 30 84 E5 02 10 A0 E1 01 00 A0 E1 10 80 BD E8 }
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

rule ftime_3b0e8acf5cc1efb186b73bc52b8832e2 {
	meta:
		aliases = "ftime"
		size = "116"
		objfiles = "ftime@libc.a"
	strings:
		$pattern = { 10 40 2D E9 10 D0 4D E2 0D 10 A0 E1 00 40 A0 E1 08 00 8D E2 ?? ?? ?? EB 00 00 50 E3 FA 1F A0 E3 00 00 E0 E3 10 00 00 BA 0C 00 9D E5 08 30 9D E5 F9 0F 80 E2 00 30 84 E5 03 00 80 E2 ?? ?? ?? EB 00 50 9D E8 40 24 A0 E1 4C 14 A0 E1 4E 34 A0 E1 09 30 C4 E5 05 20 C4 E5 07 10 C4 E5 06 C0 C4 E5 08 E0 C4 E5 04 00 C4 E5 00 00 A0 E3 10 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule setspent_d5417695485f9dd61faf5b229f59fe5f {
	meta:
		aliases = "setpwent, setgrent, setspent"
		size = "120"
		objfiles = "getpwent_r@libc.a, getspent_r@libc.a, getgrent_r@libc.a"
	strings:
		$pattern = { 10 40 2D E9 10 D0 4D E2 50 10 9F E5 50 20 9F E5 0D 00 A0 E1 4C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 44 30 9F E5 38 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 38 30 9F E5 00 00 93 E5 00 00 50 E3 0D 40 A0 E1 ?? ?? ?? 1B 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __libc_lseek_1c5db3e8619d1d4e5d97b6eb6bdd9db0 {
	meta:
		aliases = "lseek, __GI_lseek, __GI___libc_lseek, __libc_lseek"
		size = "44"
		objfiles = "lseek@libc.a"
	strings:
		$pattern = { 10 40 2D E9 13 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule getpid_469d8380ef2052ce3cf8519063e5c3a2 {
	meta:
		aliases = "__GI_getpid, __libc_getpid, getpid"
		size = "44"
		objfiles = "getpid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 14 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI___res_init_951b20a768a0be4f3997ab289c4e9ad4 {
	meta:
		aliases = "__res_init, __GI___res_init"
		size = "416"
		objfiles = "res_init@libc.a"
	strings:
		$pattern = { 10 40 2D E9 14 D0 4D E2 68 11 9F E5 68 21 9F E5 0D 00 A0 E1 64 31 9F E5 64 41 9F E5 0F E0 A0 E1 03 F0 A0 E1 5C 31 9F E5 4C 01 9F E5 0F E0 A0 E1 03 F0 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 05 30 A0 E3 00 30 84 E5 04 30 A0 E3 04 30 84 E5 01 30 A0 E3 08 30 84 E5 ?? ?? ?? EB 2C 31 9F E5 64 21 D4 E5 00 E0 93 E5 00 30 E0 E3 0E 20 C2 E3 C4 31 84 E5 03 30 83 E2 00 C0 A0 E3 01 20 82 E3 40 14 A0 E1 00 00 5E E3 10 30 C4 E5 33 30 83 E2 64 21 C4 E5 41 10 C4 E5 13 30 C4 E5 40 00 C4 E5 14 C0 84 E5 11 C0 C4 E5 12 C0 C4 E5 0C 20 A0 11 04 00 00 1A 07 00 00 EA D4 30 9F E5 02 31 93 E7 44 30 81 E5 01 20 82 E2 B8 30 9F E5 }
	condition:
		$pattern
}

rule umount_69deb570716c656469791a9382c050d4 {
	meta:
		aliases = "umount"
		size = "44"
		objfiles = "umount@libc.a"
	strings:
		$pattern = { 10 40 2D E9 16 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule mq_setattr_1fff7fa629e94ffb6e1a84b9b8ba7cb4 {
	meta:
		aliases = "__GI_mq_setattr, mq_setattr"
		size = "44"
		objfiles = "mq_getsetattr@librt.a"
	strings:
		$pattern = { 10 40 2D E9 17 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule waitid_6605705a0359a2415c884142e3d48a7a {
	meta:
		aliases = "waitid"
		size = "44"
		objfiles = "waitid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 18 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule _authenticate_de609a8a6813a961951df3a98de96f1a {
	meta:
		aliases = "__GI__authenticate, _authenticate"
		size = "112"
		objfiles = "svc_auth@libc.a"
	strings:
		$pattern = { 10 40 2D E9 18 30 81 E2 00 C0 A0 E1 01 E0 A0 E1 07 00 93 E8 0C 30 8C E2 07 00 83 E8 44 30 9F E5 00 20 93 E5 1C 30 9C E5 20 20 83 E5 0C 40 9C E5 1C 20 9C E5 00 30 A0 E3 03 00 54 E3 0C 00 A0 E1 0E 10 A0 E1 02 C0 A0 E3 28 30 82 E5 03 00 00 8A 14 30 9F E5 0F E0 A0 E1 04 F1 93 E7 00 C0 A0 E1 0C 00 A0 E1 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _rpc_dtablesize_6446cf8f42a30dc173625819f1c099fe {
	meta:
		aliases = "__GI__rpc_dtablesize, _rpc_dtablesize"
		size = "40"
		objfiles = "rpc_dtablesize@libc.a"
	strings:
		$pattern = { 10 40 2D E9 18 40 9F E5 00 30 94 E5 00 00 53 E3 01 00 00 1A ?? ?? ?? EB 00 00 84 E5 00 00 94 E5 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule stime_b66b626ee5014be90c3430dbbe79eee0 {
	meta:
		aliases = "stime"
		size = "44"
		objfiles = "stime@libc.a"
	strings:
		$pattern = { 10 40 2D E9 19 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_socket_e6a9817baaafc0b44e3a98b3c95b144f {
	meta:
		aliases = "socket, __GI_socket"
		size = "44"
		objfiles = "socket@libc.a"
	strings:
		$pattern = { 10 40 2D E9 19 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule bind_8b240186b9292a36d46880a74ac745f2 {
	meta:
		aliases = "__GI_bind, bind"
		size = "44"
		objfiles = "bind@libc.a"
	strings:
		$pattern = { 10 40 2D E9 1A 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule alarm_2efceee78001a931de9664df2bcad793 {
	meta:
		aliases = "__GI_alarm, alarm"
		size = "44"
		objfiles = "alarm@libc.a"
	strings:
		$pattern = { 10 40 2D E9 1B 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __libc_connect_d4bebb385350df7aa82cf409e3d70274 {
	meta:
		aliases = "connect, __GI_connect, __libc_connect"
		size = "44"
		objfiles = "connect@libc.a"
	strings:
		$pattern = { 10 40 2D E9 1B 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_listen_01f1c34fb5382b5976678335276ab797 {
	meta:
		aliases = "listen, __GI_listen"
		size = "44"
		objfiles = "listen@libc.a"
	strings:
		$pattern = { 10 40 2D E9 1C 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __libc_pause_0b084fe042a2a3a20a6a371bb9e66817 {
	meta:
		aliases = "pause, __libc_pause"
		size = "44"
		objfiles = "pause@libc.a"
	strings:
		$pattern = { 10 40 2D E9 1D 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_accept_28efbd00ad395acc08eccedaee805b0e {
	meta:
		aliases = "__libc_accept, accept, __GI_accept"
		size = "44"
		objfiles = "accept@libc.a"
	strings:
		$pattern = { 10 40 2D E9 1D 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_utime_01cd9075fe9473a384cc04e21a1bed4b {
	meta:
		aliases = "utime, __GI_utime"
		size = "44"
		objfiles = "utime@libc.a"
	strings:
		$pattern = { 10 40 2D E9 1E 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule getsockname_043c113415e10ded287f6abd775297ce {
	meta:
		aliases = "__GI_getsockname, getsockname"
		size = "44"
		objfiles = "getsockname@libc.a"
	strings:
		$pattern = { 10 40 2D E9 1E 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_strsignal_d47c9c09b809a97b65240cc0dcba693a {
	meta:
		aliases = "strsignal, __GI_strsignal"
		size = "132"
		objfiles = "strsignal@libc.a"
	strings:
		$pattern = { 10 40 2D E9 1F 00 50 E3 04 D0 4D E2 64 40 9F 95 00 30 A0 91 03 00 00 9A 07 00 00 EA 00 00 5C E3 01 40 84 E2 01 30 43 02 00 00 53 E3 00 C0 D4 E5 F9 FF FF 1A 00 00 5C E3 0B 00 00 1A 00 10 A0 E1 C1 2F A0 E1 00 C0 A0 E3 2C 00 9F E5 09 30 E0 E3 00 C0 8D E5 ?? ?? ?? EB 0F 40 40 E2 04 00 A0 E1 18 10 9F E5 0F 20 A0 E3 ?? ?? ?? EB 04 00 A0 E1 04 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getpeername_42027caee36f348cc0e69a356de5d563 {
	meta:
		aliases = "getpeername"
		size = "44"
		objfiles = "getpeername@libc.a"
	strings:
		$pattern = { 10 40 2D E9 1F 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule socketpair_40a4f5288f7c0368858deee9cc11f0cb {
	meta:
		aliases = "socketpair"
		size = "44"
		objfiles = "socketpair@libc.a"
	strings:
		$pattern = { 10 40 2D E9 20 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
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

rule dl_cleanup_d1a8c66339c68597517a830686b63640 {
	meta:
		aliases = "dl_cleanup"
		size = "48"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 10 40 2D E9 20 30 9F E5 00 40 93 E5 01 00 00 EA 04 40 94 E5 38 FF FF EB 00 00 54 E3 04 00 A0 E1 01 10 A0 E3 F9 FF FF 1A 10 80 BD E8 ?? ?? ?? ?? }
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

rule access_e15a7f5eed78007f9cf114df069480d5 {
	meta:
		aliases = "access"
		size = "44"
		objfiles = "access@libc.a"
	strings:
		$pattern = { 10 40 2D E9 21 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_send_d899d79c779491518398798b749b340e {
	meta:
		aliases = "send, __libc_send, __GI_send"
		size = "44"
		objfiles = "send@libc.a"
	strings:
		$pattern = { 10 40 2D E9 21 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule nice_903dafb6c7d5d0c1d1479b5d677bf4d4 {
	meta:
		aliases = "nice"
		size = "60"
		objfiles = "nice@libc.a"
	strings:
		$pattern = { 10 40 2D E9 22 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 03 00 00 EA 00 10 50 E2 01 00 00 1A 10 40 BD E8 ?? ?? ?? EA 00 00 E0 E3 10 80 BD E8 }
	condition:
		$pattern
}

rule recv_7bc5aad55f2b613060202a95cd712f74 {
	meta:
		aliases = "__GI_recv, __libc_recv, recv"
		size = "44"
		objfiles = "recv@libc.a"
	strings:
		$pattern = { 10 40 2D E9 23 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
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

rule _rpcdata_72cd5e8eb1ee50711aebc4a6a0722748 {
	meta:
		aliases = "_rpcdata"
		size = "56"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { 10 40 2D E9 24 40 9F E5 00 30 94 E5 00 00 53 E3 01 00 A0 E3 18 10 9F E5 02 00 00 1A ?? ?? ?? EB 00 00 84 E5 00 30 A0 E1 03 00 A0 E1 10 80 BD E8 ?? ?? ?? ?? B0 10 00 00 }
	condition:
		$pattern
}

rule __GI_kill_1fdc68a74bcc0d5f71a0ceb8b96ff2ad {
	meta:
		aliases = "kill, __GI_kill"
		size = "44"
		objfiles = "kill@libc.a"
	strings:
		$pattern = { 10 40 2D E9 25 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule shutdown_9d42103949344b442b7a4d5d2ec0017b {
	meta:
		aliases = "shutdown"
		size = "44"
		objfiles = "shutdown@libc.a"
	strings:
		$pattern = { 10 40 2D E9 25 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
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

rule __GI_rmdir_578fb6d5a60b37a2b585fa4364ab7a25 {
	meta:
		aliases = "rmdir, __GI_rmdir"
		size = "44"
		objfiles = "rmdir@libc.a"
	strings:
		$pattern = { 10 40 2D E9 28 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_sendmsg_db84ab334e99c1d74b80b111b38d38d8 {
	meta:
		aliases = "__libc_sendmsg, sendmsg, __GI_sendmsg"
		size = "44"
		objfiles = "sendmsg@libc.a"
	strings:
		$pattern = { 10 40 2D E9 28 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule endttyent_c147e4c256e273020a84ea6a9f887c78 {
	meta:
		aliases = "__GI_endttyent, endttyent"
		size = "56"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { 10 40 2D E9 28 40 9F E5 00 30 94 E5 00 00 53 E2 01 30 A0 E3 04 00 00 0A ?? ?? ?? EB 00 30 A0 E3 00 30 84 E5 01 30 90 E2 01 30 A0 13 03 00 A0 E1 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getusershell_a3deaf0a885a59db18d8ac674d31411a {
	meta:
		aliases = "getusershell"
		size = "56"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { 10 40 2D E9 28 40 9F E5 00 30 94 E5 00 00 53 E3 01 00 00 1A 9A FF FF EB 00 00 84 E5 00 30 94 E5 00 00 93 E5 04 20 83 E2 00 00 50 E3 00 20 84 15 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule dup_ab095a16334d071a2f310a46b03680a3 {
	meta:
		aliases = "dup"
		size = "44"
		objfiles = "dup@libc.a"
	strings:
		$pattern = { 10 40 2D E9 29 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __libc_recvmsg_96c515eabec1577af9641b30055fc3c1 {
	meta:
		aliases = "recvmsg, __GI_recvmsg, __libc_recvmsg"
		size = "44"
		objfiles = "recvmsg@libc.a"
	strings:
		$pattern = { 10 40 2D E9 29 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_pipe_aed4ccdd43f2fa6d2f8cd8734af889e9 {
	meta:
		aliases = "pipe, __GI_pipe"
		size = "44"
		objfiles = "pipe@libc.a"
	strings:
		$pattern = { 10 40 2D E9 2A 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule semop_8d29c77b2bc8648ad5408cf5bba6d47d {
	meta:
		aliases = "semop"
		size = "44"
		objfiles = "semop@libc.a"
	strings:
		$pattern = { 10 40 2D E9 2A 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule times_2278ffd97e7548b2d5c335edbd0dc459 {
	meta:
		aliases = "__GI_times, times"
		size = "44"
		objfiles = "times@libc.a"
	strings:
		$pattern = { 10 40 2D E9 2B 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule semget_c6b28afa063f0fd95ae8213d1b553ccb {
	meta:
		aliases = "semget"
		size = "44"
		objfiles = "semget@libc.a"
	strings:
		$pattern = { 10 40 2D E9 2B 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
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

rule msgsnd_f9c9447b50f40ee72c8d55ba43ec9c15 {
	meta:
		aliases = "msgsnd"
		size = "44"
		objfiles = "msgsnd@libc.a"
	strings:
		$pattern = { 10 40 2D E9 2D 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule msgget_8cb3a3e05a67f1e8d857a86e3d913754 {
	meta:
		aliases = "msgget"
		size = "44"
		objfiles = "msgget@libc.a"
	strings:
		$pattern = { 10 40 2D E9 2F 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_scalbln_c5dafc1f70d3786dad731b559ddbae1d {
	meta:
		aliases = "scalbln, __GI_scalbln"
		size = "336"
		objfiles = "s_scalbln@libm.a"
	strings:
		$pattern = { 10 40 2D E9 30 31 9F E5 03 30 00 E0 43 CA A0 E1 00 00 5C E3 03 00 2D E9 02 91 BD EC 00 E0 A0 E1 03 C2 2D ED 02 40 A0 E1 01 00 A0 E1 0B 00 00 1A 02 31 CE E3 03 00 90 E1 34 00 00 0A 36 81 9F ED 80 11 11 EE 02 91 2D ED 06 00 BD E8 E8 30 9F E5 01 E0 A0 E1 03 30 0E E0 43 3A A0 E1 36 C0 43 E2 D8 30 9F E5 03 00 5C E1 81 11 01 0E 27 00 00 0A CC 20 9F E5 CC 30 9F E5 04 10 8C E0 03 00 51 E1 02 00 54 D1 26 C1 9F CD 03 00 00 CA B8 30 9F E5 03 00 54 E1 07 00 00 AA 23 C1 9F ED 02 91 2D ED 0C 00 BD E8 02 C1 2D ED 03 00 BD E8 ?? ?? ?? EB 84 11 10 EE 15 00 00 EA 00 00 51 E3 07 00 00 DA 02 91 2D ED 18 00 BD E8 }
	condition:
		$pattern
}

rule shmat_2ba88f2eee97684d537748e4c9c2ef80 {
	meta:
		aliases = "shmat"
		size = "44"
		objfiles = "shmat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 31 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule shmdt_954e283e494bcc9886d9ef3319572593 {
	meta:
		aliases = "shmdt"
		size = "44"
		objfiles = "shmdt@libc.a"
	strings:
		$pattern = { 10 40 2D E9 32 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule acct_aca8d22039d2138a0ddfbff9c1a4d4f3 {
	meta:
		aliases = "acct"
		size = "44"
		objfiles = "acct@libc.a"
	strings:
		$pattern = { 10 40 2D E9 33 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule shmget_7b5e1531fb1597a4e8615d0e10999794 {
	meta:
		aliases = "shmget"
		size = "44"
		objfiles = "shmget@libc.a"
	strings:
		$pattern = { 10 40 2D E9 33 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule umount2_2925eb8ee7583bea2413b25a834f2c14 {
	meta:
		aliases = "umount2"
		size = "44"
		objfiles = "umount2@libc.a"
	strings:
		$pattern = { 10 40 2D E9 34 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule semtimedop_9db0f462b31b69115528953bc76b2ce2 {
	meta:
		aliases = "semtimedop"
		size = "44"
		objfiles = "semtimedop@libc.a"
	strings:
		$pattern = { 10 40 2D E9 38 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule setpgid_059d1baaddd61cc27f69341f35e582bb {
	meta:
		aliases = "__GI_setpgid, setpgid"
		size = "44"
		objfiles = "setpgid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 39 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule inotify_init_ce9cc06f9f9c030b6b28daacc4bba6bc {
	meta:
		aliases = "inotify_init"
		size = "44"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { 10 40 2D E9 3C 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
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

rule inotify_add_watch_3cb5d7f05140fc1490a1bdfc22ec8710 {
	meta:
		aliases = "inotify_add_watch"
		size = "44"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { 10 40 2D E9 3D 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule inotify_rm_watch_83cd1e001b41cb238fabdef837b7e1ef {
	meta:
		aliases = "inotify_rm_watch"
		size = "44"
		objfiles = "inotify@libc.a"
	strings:
		$pattern = { 10 40 2D E9 3E 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_dup2_c50f79143c3a5ba5051eea337de85898 {
	meta:
		aliases = "dup2, __GI_dup2"
		size = "44"
		objfiles = "dup2@libc.a"
	strings:
		$pattern = { 10 40 2D E9 3F 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule getppid_d0683287b2fd43f742b34d46b9c5b7db {
	meta:
		aliases = "getppid"
		size = "44"
		objfiles = "getppid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 40 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_scalbn_b69c5eead5ef3cd5dffdb31190b113b6 {
	meta:
		aliases = "scalbn, __GI_scalbn"
		size = "352"
		objfiles = "s_scalbn@libm.a"
	strings:
		$pattern = { 10 40 2D E9 40 31 9F E5 03 30 00 E0 43 CA A0 E1 00 00 5C E3 03 00 2D E9 02 91 BD EC 00 E0 A0 E1 03 C2 2D ED 01 00 A0 E1 11 00 00 1A 02 31 CE E3 03 00 90 E1 39 00 00 0A 3B 81 9F ED 0C 31 9F E5 80 11 11 EE 03 00 52 E1 02 91 2D ED 03 00 BD E8 05 00 00 BA F0 30 9F E5 00 E0 A0 E1 03 30 0E E0 43 3A A0 E1 36 C0 43 E2 01 00 00 EA 30 81 9F ED 29 00 00 EA D8 30 9F E5 03 00 5C E1 81 11 01 0E 26 00 00 0A CC 30 9F E5 02 10 8C E0 03 00 51 E1 0E 00 00 CA 00 00 51 E3 07 00 00 DA 02 91 2D ED 18 00 BD E8 7F 24 CE E3 0F 26 C2 E3 01 3A 82 E1 18 00 2D E9 02 91 BD EC 18 00 00 EA 36 00 71 E3 0C 00 00 CA 90 30 9F E5 }
	condition:
		$pattern
}

rule __GI_stat_4294cfedd76a8007e5e7289f454e5470 {
	meta:
		aliases = "stat, __GI_stat"
		size = "80"
		objfiles = "stat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 40 D0 4D E2 01 30 A0 E1 0D 10 A0 E1 6A 00 90 EF 01 0A 70 E3 00 40 A0 E1 04 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 40 E0 E3 00 30 80 E5 03 00 00 EA 00 00 50 E3 03 10 A0 E1 0D 00 A0 E1 ?? ?? ?? 0B 04 00 A0 E1 40 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_lstat_7bff15c9cc5420cf3daa667ac1649fd0 {
	meta:
		aliases = "lstat, __GI_lstat"
		size = "80"
		objfiles = "lstat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 40 D0 4D E2 01 30 A0 E1 0D 10 A0 E1 6B 00 90 EF 01 0A 70 E3 00 40 A0 E1 04 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 40 E0 E3 00 30 80 E5 03 00 00 EA 00 00 50 E3 03 10 A0 E1 0D 00 A0 E1 ?? ?? ?? 0B 04 00 A0 E1 40 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_fstat_f5a2118915707708581fcc2a59b6261a {
	meta:
		aliases = "fstat, __GI_fstat"
		size = "80"
		objfiles = "fstat@libc.a"
	strings:
		$pattern = { 10 40 2D E9 40 D0 4D E2 01 30 A0 E1 0D 10 A0 E1 6C 00 90 EF 01 0A 70 E3 00 40 A0 E1 04 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 40 E0 E3 00 30 80 E5 03 00 00 EA 00 00 50 E3 03 10 A0 E1 0D 00 A0 E1 ?? ?? ?? 0B 04 00 A0 E1 40 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule getpgrp_cad8a433af34b814f39ed515c36c0976 {
	meta:
		aliases = "getpgrp"
		size = "44"
		objfiles = "getpgrp@libc.a"
	strings:
		$pattern = { 10 40 2D E9 41 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule setsid_ec963187e4a0a497f88e6a88b12d4aec {
	meta:
		aliases = "__GI_setsid, setsid"
		size = "44"
		objfiles = "setsid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 42 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_setttyent_4bb84174d323b46b25045e7054382deb {
	meta:
		aliases = "setttyent, __GI_setttyent"
		size = "92"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { 10 40 2D E9 44 40 9F E5 00 30 94 E5 00 00 53 E3 03 00 A0 E1 38 10 9F E5 01 00 00 0A ?? ?? ?? EB 07 00 00 EA 2C 00 9F E5 ?? ?? ?? EB 00 00 50 E3 00 20 A0 E1 02 10 A0 E3 00 00 84 E5 01 00 00 0A ?? ?? ?? EB 01 20 A0 E3 02 00 A0 E1 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sethostname_95e23c31471d747c2f3fe8266eab410c {
	meta:
		aliases = "sethostname"
		size = "44"
		objfiles = "sethostname@libc.a"
	strings:
		$pattern = { 10 40 2D E9 4A 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_setrlimit_4f9c74ce4e601ed7ce7897705b256369 {
	meta:
		aliases = "setrlimit, __GI_setrlimit"
		size = "44"
		objfiles = "setrlimit@libc.a"
	strings:
		$pattern = { 10 40 2D E9 4B 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule getrusage_1a0ece375d64954b621e70fdd1f35f74 {
	meta:
		aliases = "getrusage"
		size = "44"
		objfiles = "getrusage@libc.a"
	strings:
		$pattern = { 10 40 2D E9 4D 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_gettimeofday_ee072eab22d8270454d1c020787439bd {
	meta:
		aliases = "gettimeofday, __GI_gettimeofday"
		size = "44"
		objfiles = "gettimeofday@libc.a"
	strings:
		$pattern = { 10 40 2D E9 4E 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule settimeofday_67739f7e98df4a44dc7248c14fb62b9a {
	meta:
		aliases = "__GI_settimeofday, settimeofday"
		size = "44"
		objfiles = "settimeofday@libc.a"
	strings:
		$pattern = { 10 40 2D E9 4F 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __uClibc_fini_f257d4cf4878ef277bcc8211f00ce6af {
	meta:
		aliases = "__GI___uClibc_fini, __uClibc_fini"
		size = "108"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { 10 40 2D E9 50 30 9F E5 50 20 9F E5 03 30 62 E0 43 41 A0 E1 02 00 00 EA 40 30 9F E5 0F E0 A0 E1 04 F1 93 E7 01 40 54 E2 FA FF FF 2A 30 30 9F E5 00 30 93 E5 00 00 53 E3 0F E0 A0 11 03 F0 A0 11 20 30 9F E5 00 30 93 E5 00 00 53 E3 10 80 BD 08 0F E0 A0 E1 03 F0 A0 E1 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule symlink_764b4e46e24b2c94b8b3e3ef9a040456 {
	meta:
		aliases = "symlink"
		size = "44"
		objfiles = "symlink@libc.a"
	strings:
		$pattern = { 10 40 2D E9 53 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule setup_salt_8cd6df75696841035729da2999bb3251 {
	meta:
		aliases = "setup_salt"
		size = "104"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { 10 40 2D E9 54 40 9F E5 00 30 94 E5 03 00 50 E1 10 80 BD 08 00 20 A0 E3 44 30 9F E5 02 E0 A0 E1 02 C5 A0 E3 01 10 A0 E3 00 00 84 E5 00 20 83 E5 05 00 00 EA 01 00 10 E1 00 30 92 15 0C 30 83 11 00 30 82 15 81 10 A0 E1 AC C0 A0 E1 17 00 5E E3 0C 20 9F E5 01 E0 8E E2 F5 FF FF DA 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule readlink_be8e5e7755c624af64685fffa4aedac8 {
	meta:
		aliases = "__GI_readlink, readlink"
		size = "44"
		objfiles = "readlink@libc.a"
	strings:
		$pattern = { 10 40 2D E9 55 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule tee_6bb484bc2cbcaa93e56f49c2920d296a {
	meta:
		aliases = "tee"
		size = "44"
		objfiles = "tee@libc.a"
	strings:
		$pattern = { 10 40 2D E9 56 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule swapon_807d78d500c31bf2a0979725b40c3ed1 {
	meta:
		aliases = "swapon"
		size = "44"
		objfiles = "swapon@libc.a"
	strings:
		$pattern = { 10 40 2D E9 57 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_vmsplice_e4d36bd339dfd97b7f11e03db3697725 {
	meta:
		aliases = "vmsplice, __GI_vmsplice"
		size = "44"
		objfiles = "vmsplice@libc.a"
	strings:
		$pattern = { 10 40 2D E9 57 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule ftok_ba290a538c1e2100cbdb34a75858133a {
	meta:
		aliases = "ftok"
		size = "64"
		objfiles = "ftok@libc.a"
	strings:
		$pattern = { 10 40 2D E9 58 D0 4D E2 01 40 A0 E1 0D 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 E0 E3 05 00 00 BA 0C 30 9D E5 00 20 DD E5 03 38 A0 E1 23 38 A0 E1 02 38 83 E1 04 0C 83 E1 58 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule munmap_7a098376eac4ec854c2a9416fc95c85b {
	meta:
		aliases = "__GI_munmap, munmap"
		size = "44"
		objfiles = "munmap@libc.a"
	strings:
		$pattern = { 10 40 2D E9 5B 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_truncate_1f6ff820ff59bc07764cd70fd0debe18 {
	meta:
		aliases = "truncate, __GI_truncate"
		size = "44"
		objfiles = "truncate@libc.a"
	strings:
		$pattern = { 10 40 2D E9 5C 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_ftruncate_920007dbab85e63c4c5fdc3a6279a08b {
	meta:
		aliases = "ftruncate, __GI_ftruncate"
		size = "44"
		objfiles = "ftruncate@libc.a"
	strings:
		$pattern = { 10 40 2D E9 5D 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
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

rule stat64_cccb4eb63a915ea386470b14fdb45705 {
	meta:
		aliases = "__GI_stat64, stat64"
		size = "80"
		objfiles = "stat64@libc.a"
	strings:
		$pattern = { 10 40 2D E9 60 D0 4D E2 01 30 A0 E1 0D 10 A0 E1 C3 00 90 EF 01 0A 70 E3 00 40 A0 E1 04 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 40 E0 E3 00 30 80 E5 03 00 00 EA 00 00 50 E3 03 10 A0 E1 0D 00 A0 E1 ?? ?? ?? 0B 04 00 A0 E1 60 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule lstat64_6deb4bd56f4b387a06449cf91f0335b4 {
	meta:
		aliases = "__GI_lstat64, lstat64"
		size = "80"
		objfiles = "lstat64@libc.a"
	strings:
		$pattern = { 10 40 2D E9 60 D0 4D E2 01 30 A0 E1 0D 10 A0 E1 C4 00 90 EF 01 0A 70 E3 00 40 A0 E1 04 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 40 E0 E3 00 30 80 E5 03 00 00 EA 00 00 50 E3 03 10 A0 E1 0D 00 A0 E1 ?? ?? ?? 0B 04 00 A0 E1 60 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_fstat64_6d234fa461a9bd563f4e79355794b50d {
	meta:
		aliases = "fstat64, __GI_fstat64"
		size = "80"
		objfiles = "fstat64@libc.a"
	strings:
		$pattern = { 10 40 2D E9 60 D0 4D E2 01 30 A0 E1 0D 10 A0 E1 C5 00 90 EF 01 0A 70 E3 00 40 A0 E1 04 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 40 E0 E3 00 30 80 E5 03 00 00 EA 00 00 50 E3 03 10 A0 E1 0D 00 A0 E1 ?? ?? ?? 0B 04 00 A0 E1 60 D0 8D E2 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_setpriority_3b2884e733f7509f79e83a77e1669702 {
	meta:
		aliases = "setpriority, __GI_setpriority"
		size = "44"
		objfiles = "setpriority@libc.a"
	strings:
		$pattern = { 10 40 2D E9 61 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule statfs_4cea80dfddb13661b86eb5c074c49684 {
	meta:
		aliases = "__GI_statfs, __GI___libc_statfs, __libc_statfs, statfs"
		size = "44"
		objfiles = "statfs@libc.a"
	strings:
		$pattern = { 10 40 2D E9 63 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule fstatfs_13e18167fcd35ec0ad4635dab87f29e6 {
	meta:
		aliases = "__libc_fstatfs, __GI_fstatfs, __GI___libc_fstatfs, fstatfs"
		size = "44"
		objfiles = "fstatfs@libc.a"
	strings:
		$pattern = { 10 40 2D E9 64 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __socketcall_2bb731470f552b2f0de583ddc6b0a474 {
	meta:
		aliases = "__socketcall"
		size = "44"
		objfiles = "__socketcall@libc.a"
	strings:
		$pattern = { 10 40 2D E9 66 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
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

rule setitimer_dc3ac984b8ca2b5a0f26ed1b3a84f44c {
	meta:
		aliases = "__GI_setitimer, setitimer"
		size = "44"
		objfiles = "setitimer@libc.a"
	strings:
		$pattern = { 10 40 2D E9 68 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule getitimer_338cd02139e198d7778c2d79a68d8876 {
	meta:
		aliases = "getitimer"
		size = "44"
		objfiles = "getitimer@libc.a"
	strings:
		$pattern = { 10 40 2D E9 69 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule vhangup_2e0a930b170e90a4c2d13293093892ec {
	meta:
		aliases = "vhangup"
		size = "44"
		objfiles = "vhangup@libc.a"
	strings:
		$pattern = { 10 40 2D E9 6F 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
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

rule swapoff_0fa47a911197432cd74891c3bcf28acc {
	meta:
		aliases = "swapoff"
		size = "44"
		objfiles = "swapoff@libc.a"
	strings:
		$pattern = { 10 40 2D E9 73 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule sysinfo_d277704de9f1677f5ad899e55dad2013 {
	meta:
		aliases = "sysinfo"
		size = "44"
		objfiles = "sysinfo@libc.a"
	strings:
		$pattern = { 10 40 2D E9 74 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_mbrtowc_5d89777af44696eaf26828749aa16fd9 {
	meta:
		aliases = "mbrtowc, __GI_mbrtowc"
		size = "132"
		objfiles = "mbrtowc@libc.a"
	strings:
		$pattern = { 10 40 2D E9 74 C0 9F E5 00 00 53 E3 10 D0 4D E2 03 E0 A0 11 0C E0 A0 01 00 C0 51 E2 00 40 A0 E1 0F C0 CD 05 0C 40 A0 01 0F C0 8D 02 05 00 00 0A 00 30 DC E5 00 00 53 E3 00 00 A0 E3 0D 00 00 0A 00 00 52 E1 0B 00 00 0A 08 00 8D E2 04 10 8D E2 00 20 E0 E3 01 30 A0 E3 04 C0 8D E5 00 E0 8D E5 ?? ?? ?? EB 00 00 50 E3 02 00 00 BA 00 00 54 E3 08 30 9D 15 00 30 84 15 10 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __libc_fsync_8a7cc91a41a6a50227e616d6b84611c6 {
	meta:
		aliases = "fsync, __libc_fsync"
		size = "44"
		objfiles = "fsync@libc.a"
	strings:
		$pattern = { 10 40 2D E9 76 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule getoffset_72ac92f748056b144551d9192e2a2a66 {
	meta:
		aliases = "getoffset"
		size = "136"
		objfiles = "tzset@libc.a"
	strings:
		$pattern = { 10 40 2D E9 78 40 9F E5 00 E0 A0 E3 00 C0 E0 E3 00 30 D0 E5 30 20 43 E2 FF 30 02 E2 09 00 53 E3 01 00 80 92 02 C0 A0 91 00 20 D0 E5 30 30 42 E2 09 00 53 E3 0A 30 A0 93 9C 23 23 90 01 40 84 E2 00 20 D4 E5 30 C0 43 92 01 00 80 92 02 00 5C E1 01 00 00 3A 00 00 A0 E3 10 80 BD E8 00 30 D0 E5 3A 00 53 E3 92 CE 2E E0 01 00 80 02 00 C0 A0 E3 00 C0 E0 03 01 00 52 E3 E4 FF FF 8A 00 E0 81 E5 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule setdomainname_d9e9c0bc675a2b2225f3333191d00b96 {
	meta:
		aliases = "setdomainname"
		size = "44"
		objfiles = "setdomainname@libc.a"
	strings:
		$pattern = { 10 40 2D E9 79 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule uname_da7aa5449021b7612d21411e7074532b {
	meta:
		aliases = "__GI_uname, uname"
		size = "44"
		objfiles = "uname@libc.a"
	strings:
		$pattern = { 10 40 2D E9 7A 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule adjtimex_94c6c0382b7ccee395b39598651fd493 {
	meta:
		aliases = "ntp_adjtime, __GI_adjtimex, adjtimex"
		size = "44"
		objfiles = "adjtimex@libc.a"
	strings:
		$pattern = { 10 40 2D E9 7C 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule mprotect_07bdcbff126d1431934cd7b68db86e58 {
	meta:
		aliases = "mprotect"
		size = "44"
		objfiles = "mprotect@libc.a"
	strings:
		$pattern = { 10 40 2D E9 7D 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_timedsuspend_new_1c4cc972f4d7b37ad6d66cc8e90e62ee {
	meta:
		aliases = "__pthread_timedsuspend_new"
		size = "256"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 7D DF 4D E2 04 00 8D E5 00 10 8D E5 08 00 8D E2 01 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 01 00 A0 13 2E 00 00 1A 04 20 9D E5 59 4F 8D E2 08 30 8D E2 24 30 82 E5 20 00 82 E5 04 00 A0 E1 ?? ?? ?? EB AC 30 9F E5 04 00 A0 E1 00 10 93 E5 ?? ?? ?? EB 04 10 A0 E1 01 00 A0 E3 E4 20 8D E2 ?? ?? ?? EB 00 10 A0 E3 7B 0F 8D E2 ?? ?? ?? EB F0 21 9D E5 FA 3F A0 E3 92 03 03 E0 00 E0 9D E5 04 10 9E E8 0C C0 63 E0 EC 31 9D E5 00 10 A0 E3 02 20 63 E0 01 00 5C E1 01 30 42 E2 E4 21 8D E5 E4 31 8D B5 50 E0 9F E5 E4 31 9D E5 0E E0 8C E0 E8 C1 8D E5 E8 E1 8D B5 00 00 53 E3 79 0F 8D E2 02 00 00 BA ?? ?? ?? EB }
	condition:
		$pattern
}

rule __GI_iswctype_ccea6d5ef654de1af261993723c5eb40 {
	meta:
		aliases = "iswctype, __GI_iswctype"
		size = "96"
		objfiles = "iswctype@libc.a"
	strings:
		$pattern = { 10 40 2D E9 7F 00 50 E3 0C 00 51 93 44 40 9F E5 81 20 A0 E1 00 30 A0 83 01 30 A0 93 80 C0 A0 E1 04 E0 82 E0 03 00 A0 E1 10 80 BD 88 28 30 9F E5 00 30 93 E5 04 20 D2 E7 03 00 8C E0 03 10 DC E7 01 30 DE E5 03 24 82 E1 01 30 D0 E5 03 14 81 E1 02 00 01 E0 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
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

rule delete_module_644751291bb4b7b366230411a99694c0 {
	meta:
		aliases = "delete_module"
		size = "44"
		objfiles = "delete_module@libc.a"
	strings:
		$pattern = { 10 40 2D E9 81 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule quotactl_0e8317d01865010bd69474dc9d03cabc {
	meta:
		aliases = "quotactl"
		size = "44"
		objfiles = "quotactl@libc.a"
	strings:
		$pattern = { 10 40 2D E9 83 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
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

rule __GI_fchdir_09de46f298dba6d8f2a5a2770508fb09 {
	meta:
		aliases = "fchdir, __GI_fchdir"
		size = "44"
		objfiles = "fchdir@libc.a"
	strings:
		$pattern = { 10 40 2D E9 85 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule bdflush_85cd2ee802097c4897d54417c29f4378 {
	meta:
		aliases = "bdflush"
		size = "44"
		objfiles = "bdflush@libc.a"
	strings:
		$pattern = { 10 40 2D E9 86 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule personality_3f5c0b2e123524738b2c84669dab2913 {
	meta:
		aliases = "personality"
		size = "44"
		objfiles = "personality@libc.a"
	strings:
		$pattern = { 10 40 2D E9 88 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule getrpcent_77a5957b1292764d3c4fe8c9b303a47e {
	meta:
		aliases = "__GI_getrpcent, getrpcent"
		size = "80"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { 10 40 2D E9 8D FF FF EB 00 40 50 E2 0B 00 00 0A 00 30 94 E5 00 00 53 E3 28 10 9F E5 28 00 9F E5 03 00 00 1A ?? ?? ?? EB 00 00 50 E3 00 00 84 E5 02 00 00 0A 04 00 A0 E1 10 40 BD E8 9E FF FF EA 00 00 A0 E3 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
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

rule __libc_msync_81767b5d40c01d6ccaefbba983abf305 {
	meta:
		aliases = "msync, __libc_msync"
		size = "44"
		objfiles = "msync@libc.a"
	strings:
		$pattern = { 10 40 2D E9 90 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __libc_readv_b75b5f303040cfc6054956f6a8aef350 {
	meta:
		aliases = "readv, __libc_readv"
		size = "44"
		objfiles = "readv@libc.a"
	strings:
		$pattern = { 10 40 2D E9 91 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __libc_writev_5a520301281f6d86ccd9644f7d396424 {
	meta:
		aliases = "writev, __libc_writev"
		size = "44"
		objfiles = "writev@libc.a"
	strings:
		$pattern = { 10 40 2D E9 92 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
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

rule fdatasync_970b08ac2cf97f202245a3922387b766 {
	meta:
		aliases = "fdatasync"
		size = "44"
		objfiles = "fdatasync@libc.a"
	strings:
		$pattern = { 10 40 2D E9 94 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule get_current_dir_name_a011fe0eed663716ea131c700e969947 {
	meta:
		aliases = "get_current_dir_name"
		size = "168"
		objfiles = "getdirname@libc.a"
	strings:
		$pattern = { 10 40 2D E9 94 00 9F E5 C0 D0 4D E2 ?? ?? ?? EB 00 40 50 E2 60 10 8D E2 84 00 9F E5 1A 00 00 0A ?? ?? ?? EB 00 00 50 E3 0D 10 A0 E1 04 00 A0 E1 15 00 00 1A ?? ?? ?? EB 00 00 50 E3 12 00 00 1A 00 20 9D E5 60 30 9D E5 03 00 52 E1 0E 00 00 1A 04 20 9D E5 64 30 9D E5 03 00 52 E1 0A 00 00 1A 58 20 9D E5 B8 30 9D E5 03 00 52 E1 06 00 00 1A 5C 20 9D E5 BC 30 9D E5 03 00 52 E1 04 00 A0 E1 01 00 00 1A ?? ?? ?? EB 02 00 00 EA 00 00 A0 E3 00 10 A0 E1 ?? ?? ?? EB C0 D0 8D E2 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule mlock_9d5c0086c84b03f0dd2b2b4318e9d6e3 {
	meta:
		aliases = "mlock"
		size = "44"
		objfiles = "mlock@libc.a"
	strings:
		$pattern = { 10 40 2D E9 96 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule munlock_fb2fb9393d2a726445538cce61ae87dc {
	meta:
		aliases = "munlock"
		size = "44"
		objfiles = "munlock@libc.a"
	strings:
		$pattern = { 10 40 2D E9 97 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule mlockall_279f72e479bf3288c00f9fccf319879d {
	meta:
		aliases = "mlockall"
		size = "44"
		objfiles = "mlockall@libc.a"
	strings:
		$pattern = { 10 40 2D E9 98 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule munlockall_99569feda4e6474cba6f70cfce1576bf {
	meta:
		aliases = "munlockall"
		size = "44"
		objfiles = "munlockall@libc.a"
	strings:
		$pattern = { 10 40 2D E9 99 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
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

rule sched_yield_5e30d95cd64cd97b5ee19cdc8b672ae3 {
	meta:
		aliases = "sched_yield"
		size = "44"
		objfiles = "sched_yield@libc.a"
	strings:
		$pattern = { 10 40 2D E9 9E 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule sched_get_priority_max_638a881ee1c16fdf20740668a39ad81c {
	meta:
		aliases = "sched_get_priority_max"
		size = "44"
		objfiles = "sched_get_priority_max@libc.a"
	strings:
		$pattern = { 10 40 2D E9 9F 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule _buf_d180fbc02e598bfbcb8d6fada03d914a {
	meta:
		aliases = "_buf"
		size = "44"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { 10 40 2D E9 ?? ?? ?? EB 00 40 A0 E1 9C 30 94 E5 00 00 53 E3 01 0C A0 E3 01 00 00 1A ?? ?? ?? EB 9C 00 84 E5 9C 00 94 E5 10 80 BD E8 }
	condition:
		$pattern
}

rule __rpc_thread_clnt_cleanup_c7848c9f6f9c7b58de810e6c7250d96e {
	meta:
		aliases = "__rpc_thread_clnt_cleanup"
		size = "56"
		objfiles = "clnt_simple@libc.a"
	strings:
		$pattern = { 10 40 2D E9 ?? ?? ?? EB A4 40 90 E5 00 00 54 E3 10 80 BD 08 00 30 94 E5 00 00 53 E3 03 00 A0 E1 04 30 93 15 0F E0 A0 11 10 F0 93 15 04 00 A0 E1 10 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule sched_get_priority_min_1bb11e21a62dc5fdde699e3680dbbb9b {
	meta:
		aliases = "sched_get_priority_min"
		size = "44"
		objfiles = "sched_get_priority_min@libc.a"
	strings:
		$pattern = { 10 40 2D E9 A0 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
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

rule nanosleep_13befc3f8b68b1fa1887db66d1897316 {
	meta:
		aliases = "__GI_nanosleep, __libc_nanosleep, nanosleep"
		size = "44"
		objfiles = "nanosleep@libc.a"
	strings:
		$pattern = { 10 40 2D E9 A2 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule poll_6c080141698de411c9e8b3ff9504a949 {
	meta:
		aliases = "__libc_poll, __GI_poll, poll"
		size = "44"
		objfiles = "poll@libc.a"
	strings:
		$pattern = { 10 40 2D E9 A8 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule pthread_key_delete_793d280054c2f063376b845a3a2800e3 {
	meta:
		aliases = "pthread_key_delete"
		size = "204"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { 10 40 2D E9 AC 30 9F E5 00 40 A0 E1 A8 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 01 0B 54 E3 03 00 00 2A 98 10 9F E5 84 31 91 E7 00 00 53 E3 05 00 00 1A 84 00 9F E5 88 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 16 00 A0 E3 10 80 BD E8 78 30 9F E5 00 30 93 E5 84 21 81 E0 01 00 73 E3 00 30 A0 E3 04 30 82 E5 84 31 81 E7 0D 00 00 0A 3F FF FF EB 1F E0 04 E2 A4 C2 A0 E1 00 30 A0 E1 2C 10 D3 E5 00 00 51 E3 0C 21 83 E0 02 00 00 1A EC 20 92 E5 00 00 52 E3 0E 11 82 17 00 30 93 E5 00 00 53 E1 F5 FF FF 1A 1C 30 9F E5 10 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 A0 E3 10 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __syscall_rt_sigaction_85f416c30829d9a1cad89e035c1482e6 {
	meta:
		aliases = "__syscall_rt_sigaction"
		size = "44"
		objfiles = "__syscall_rt_sigaction@libc.a"
	strings:
		$pattern = { 10 40 2D E9 AE 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __rt_sigtimedwait_b657ba695a4be14a609680fd09227ef0 {
	meta:
		aliases = "__rt_sigtimedwait"
		size = "44"
		objfiles = "__rt_sigtimedwait@libc.a"
	strings:
		$pattern = { 10 40 2D E9 B1 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule capget_934f1e2295481b5a5a14bbe7bfb31fb3 {
	meta:
		aliases = "capget"
		size = "44"
		objfiles = "capget@libc.a"
	strings:
		$pattern = { 10 40 2D E9 B8 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule capset_1c635fdc1b908c2558b35699876e1d37 {
	meta:
		aliases = "capset"
		size = "44"
		objfiles = "capset@libc.a"
	strings:
		$pattern = { 10 40 2D E9 B9 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule sigaltstack_cbdf59370184daaec4613e7aba0d33e1 {
	meta:
		aliases = "sigaltstack"
		size = "44"
		objfiles = "sigaltstack@libc.a"
	strings:
		$pattern = { 10 40 2D E9 BA 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule sendfile_0077a64cc77e1e487ca822d79b9689b0 {
	meta:
		aliases = "sendfile"
		size = "44"
		objfiles = "sendfile@libc.a"
	strings:
		$pattern = { 10 40 2D E9 BB 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_getrlimit_d89fa881e01c47c064d79fe5c1e2b52e {
	meta:
		aliases = "getrlimit, __GI_getrlimit"
		size = "44"
		objfiles = "getrlimit@libc.a"
	strings:
		$pattern = { 10 40 2D E9 BF 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule lchown_2b7295dbc43f519c0a31a055c6cb81db {
	meta:
		aliases = "lchown"
		size = "44"
		objfiles = "lchown@libc.a"
	strings:
		$pattern = { 10 40 2D E9 C6 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_getuid_000ef01839f7262156ded35f444d3e87 {
	meta:
		aliases = "getuid, __GI_getuid"
		size = "44"
		objfiles = "getuid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 C7 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule getgid_41762ea2fb33b608c1c3ae895950b654 {
	meta:
		aliases = "__GI_getgid, getgid"
		size = "44"
		objfiles = "getgid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 C8 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_geteuid_8b33ffd58d3152dd0763f16751f9f73b {
	meta:
		aliases = "geteuid, __GI_geteuid"
		size = "44"
		objfiles = "geteuid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 C9 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule getegid_93d63234e968e0df9bbdd92a9a29836a {
	meta:
		aliases = "__GI_getegid, getegid"
		size = "44"
		objfiles = "getegid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 CA 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule setreuid_1b860b6deb92c06f365c10e3041c532d {
	meta:
		aliases = "__GI_setreuid, setreuid"
		size = "44"
		objfiles = "setreuid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 CB 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule setregid_9b97936b42e1f254cba30fee6d55b8a4 {
	meta:
		aliases = "__GI_setregid, setregid"
		size = "44"
		objfiles = "setregid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 CC 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule getgroups_724014953cd1f4cb006787da7dc5a5ca {
	meta:
		aliases = "__GI_getgroups, getgroups"
		size = "44"
		objfiles = "getgroups@libc.a"
	strings:
		$pattern = { 10 40 2D E9 CD 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule setgroups_7296fd3b2c5e2d75d43f60d94dd59f59 {
	meta:
		aliases = "__GI_setgroups, setgroups"
		size = "44"
		objfiles = "setgroups@libc.a"
	strings:
		$pattern = { 10 40 2D E9 CE 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule fchown_339e3a0ed328c8a3b0b747bc9ad7a63a {
	meta:
		aliases = "fchown"
		size = "44"
		objfiles = "fchown@libc.a"
	strings:
		$pattern = { 10 40 2D E9 CF 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_setresuid_49ee6466fa07d5bc8fa43b20004e5ffd {
	meta:
		aliases = "setresuid, __GI_setresuid"
		size = "44"
		objfiles = "setresuid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 D0 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule getresuid_8137fc239be833577e20988d93797da8 {
	meta:
		aliases = "getresuid"
		size = "44"
		objfiles = "getresuid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 D1 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule setresgid_766fee6c1f086eaf32915194fbe9e261 {
	meta:
		aliases = "__GI_setresgid, setresgid"
		size = "44"
		objfiles = "setresgid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 D2 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule getresgid_f5b3c0a03282bd1d38aa52371e3e2fd8 {
	meta:
		aliases = "getresgid"
		size = "44"
		objfiles = "getresgid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 D3 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __GI_chown_2343d3d54a8f3ab1ad42f66c758d7814 {
	meta:
		aliases = "chown, __GI_chown"
		size = "44"
		objfiles = "chown@libc.a"
	strings:
		$pattern = { 10 40 2D E9 D4 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule setuid_f844931635d69d4739ed09a9e8d13164 {
	meta:
		aliases = "setuid"
		size = "44"
		objfiles = "setuid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 D5 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule setgid_20a165a616468d389ed834c14c158ac6 {
	meta:
		aliases = "setgid"
		size = "44"
		objfiles = "setgid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 D6 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule setfsuid_8fd3a58e5b615974d46251aa6b13d916 {
	meta:
		aliases = "setfsuid"
		size = "44"
		objfiles = "setfsuid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 D7 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule setfsgid_f57bf6c63c61a9010baba0c986b202e2 {
	meta:
		aliases = "setfsgid"
		size = "44"
		objfiles = "setfsgid@libc.a"
	strings:
		$pattern = { 10 40 2D E9 D8 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule pivot_root_e401136dcfcd28420615b83f8a4278e9 {
	meta:
		aliases = "pivot_root"
		size = "44"
		objfiles = "pivot_root@libc.a"
	strings:
		$pattern = { 10 40 2D E9 DA 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule mincore_15b482d056abefaae3f89fd7c52b4958 {
	meta:
		aliases = "mincore"
		size = "44"
		objfiles = "mincore@libc.a"
	strings:
		$pattern = { 10 40 2D E9 DB 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule madvise_42ffe4aaa55cbb85b40aa648a5114932 {
	meta:
		aliases = "madvise"
		size = "44"
		objfiles = "madvise@libc.a"
	strings:
		$pattern = { 10 40 2D E9 DC 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule getxattr_08a2145cca8139cbe4efe74fb3593e0d {
	meta:
		aliases = "getxattr"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 E5 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule lgetxattr_5d85be6fbde6a199a58d5627cce3efc3 {
	meta:
		aliases = "lgetxattr"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 E6 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule fgetxattr_6e2e7c926bffddaa8810ddf92b68fe57 {
	meta:
		aliases = "fgetxattr"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 E7 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule listxattr_2b2c7fdd4dd820daf45d77489bf434d9 {
	meta:
		aliases = "listxattr"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 E8 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule llistxattr_acd97d6bb8738157a87e56146a92f1b0 {
	meta:
		aliases = "llistxattr"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 E9 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule flistxattr_82988404fa6006fc2b9da87dbe189efa {
	meta:
		aliases = "flistxattr"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 EA 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule removexattr_02ecdac4ee20210515181aa95f82bc3e {
	meta:
		aliases = "removexattr"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 EB 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule lremovexattr_4f205722cdb9704e6a6560d20932dbf5 {
	meta:
		aliases = "lremovexattr"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 EC 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule fremovexattr_a68f735d5c772e00c9a8c9d2cfe6363b {
	meta:
		aliases = "fremovexattr"
		size = "44"
		objfiles = "xattr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 ED 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule sendfile64_b736873e61ef5e9526c023360d60b39c {
	meta:
		aliases = "sendfile64"
		size = "44"
		objfiles = "sendfile64@libc.a"
	strings:
		$pattern = { 10 40 2D E9 EF 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule epoll_create_22ee242f88ea7e78a559671324937e12 {
	meta:
		aliases = "epoll_create"
		size = "44"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { 10 40 2D E9 FA 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule epoll_ctl_f6caab29dc68f38eb2052f0489b683d3 {
	meta:
		aliases = "epoll_ctl"
		size = "44"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { 10 40 2D E9 FB 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule epoll_wait_1d5cfa6546635ca067895d9764933e19 {
	meta:
		aliases = "epoll_wait"
		size = "44"
		objfiles = "epoll@libc.a"
	strings:
		$pattern = { 10 40 2D E9 FC 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule memrchr_ebcf5b70f7fcdca45ae0afe3f8cafc07 {
	meta:
		aliases = "__GI_memrchr, memrchr"
		size = "236"
		objfiles = "memrchr@libc.a"
	strings:
		$pattern = { 10 40 2D E9 FF 10 01 E2 02 00 80 E0 03 00 00 EA 01 30 70 E5 01 00 53 E1 10 80 BD 08 01 20 42 E2 00 00 52 E3 01 00 00 0A 03 00 10 E3 F7 FF FF 1A 01 34 81 E1 03 48 83 E1 1D 00 00 EA 04 30 30 E5 03 30 24 E0 0C C0 83 E0 03 30 E0 E1 03 30 2C E0 0E E0 03 E0 00 00 5E E3 04 20 42 E2 14 00 00 0A 03 30 D0 E5 01 00 53 E1 02 C0 80 E2 03 30 80 E2 01 E0 80 E2 01 00 00 1A 03 00 A0 E1 10 80 BD E8 02 30 D0 E5 01 00 53 E1 01 00 00 1A 0C 00 A0 E1 10 80 BD E8 01 30 D0 E5 01 00 53 E1 01 00 00 1A 0E 00 A0 E1 10 80 BD E8 00 30 D0 E5 01 00 53 E1 10 80 BD 08 03 00 52 E3 24 C0 9F E5 24 E0 9F E5 DD FF FF 8A 02 00 00 EA }
	condition:
		$pattern
}

rule __do_global_ctors_aux_7a611837cc227f9318f1293723d6d074 {
	meta:
		aliases = "__do_global_ctors_aux"
		size = "76"
		objfiles = "crtendS"
	strings:
		$pattern = { 10 44 2D E9 30 A0 9F E5 30 30 9F E5 0A A0 8F E0 03 20 8A E0 04 30 12 E5 01 00 73 E3 04 40 42 E2 10 84 BD 08 0F E0 A0 E1 03 F0 A0 E1 04 30 34 E5 01 00 73 E3 FA FF FF 1A 10 84 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? 04 E0 2D E5 04 F0 9D E4 }
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

rule xdrmem_setpos_7839ad9ac769270a65cc6eec0fa601cb {
	meta:
		aliases = "xdrmem_setpos"
		size = "52"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { 14 20 90 E5 00 C0 A0 E1 0C 30 90 E5 10 00 90 E5 02 30 83 E0 00 10 81 E0 03 00 51 E1 03 20 61 E0 00 00 A0 E3 01 00 A0 D3 14 20 8C D5 0C 10 8C D5 0E F0 A0 E1 }
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

rule pthread_attr_getguardsize_71c31f4be323be3dc0c32d4c0e971b33 {
	meta:
		aliases = "__pthread_attr_getguardsize, pthread_attr_getguardsize"
		size = "16"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 14 30 90 E5 00 00 A0 E3 00 30 81 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule xdrmem_inline_8ffd76a93ff7c338fa52a11c948259d2 {
	meta:
		aliases = "xdrmem_inline"
		size = "40"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { 14 30 90 E5 01 00 53 E1 00 20 A0 E3 0C 20 90 25 03 C0 61 E0 01 30 82 20 0C 30 80 25 14 C0 80 25 02 00 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule xdrmem_putint32_afd8e155496a97aa79919054e723afae {
	meta:
		aliases = "xdrmem_putlong, xdrmem_putint32"
		size = "88"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { 14 30 90 E5 03 00 53 E3 04 20 43 E2 00 30 A0 E3 0E 00 00 9A 14 20 80 E5 00 10 91 E5 FF 38 01 E2 FF 2C 01 E2 23 34 A0 E1 02 24 A0 E1 01 2C 82 E1 21 3C 83 E1 0C 10 90 E5 02 30 83 E1 00 30 81 E5 0C 30 90 E5 04 30 83 E2 0C 30 80 E5 01 30 A0 E3 03 00 A0 E1 0E F0 A0 E1 }
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

rule _ppfs_setargs_df2e623d2b20a1e831e6e581f374e73e {
	meta:
		aliases = "_ppfs_setargs"
		size = "412"
		objfiles = "_ppfs_setargs@libc.a"
	strings:
		$pattern = { 18 10 90 E5 00 00 51 E3 10 40 2D E9 50 C0 80 E2 08 30 90 E5 48 00 00 1A 02 01 53 E3 05 00 00 1A 4C 30 90 E5 00 20 93 E5 04 30 83 E2 4C 30 80 E5 08 20 80 E5 50 20 80 E5 04 30 90 E5 02 01 53 E3 05 00 00 1A 4C 30 90 E5 00 20 93 E5 04 30 83 E2 4C 30 80 E5 04 20 80 E5 50 20 80 E5 01 E0 A0 E1 31 00 00 EA 0E 31 80 E0 28 20 93 E5 08 00 52 E3 2C 00 00 0A 4C 10 90 E5 07 00 00 CA 02 00 52 E3 18 00 00 0A 02 00 00 CA 00 00 52 E3 15 00 00 AA 1F 00 00 EA 07 00 52 E3 0B 00 00 EA 01 0B 52 E3 10 00 00 0A 04 00 00 CA 01 0C 52 E3 0D 00 00 0A 02 0C 52 E3 16 00 00 1A 0A 00 00 EA 02 0B 52 E3 03 00 00 0A CC 30 9F E5 }
	condition:
		$pattern
}

rule ispunct_34453b9b72ac3592e35d276b4bfedf24 {
	meta:
		aliases = "ispunct"
		size = "36"
		objfiles = "ispunct@libc.a"
	strings:
		$pattern = { 18 30 9F E5 00 30 93 E5 80 00 A0 E1 03 00 80 E0 01 00 D0 E5 00 04 A0 E1 01 0B 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isblank_04676f99c4c22d0c0ab44abf28ccb085 {
	meta:
		aliases = "isblank"
		size = "36"
		objfiles = "isblank@libc.a"
	strings:
		$pattern = { 18 30 9F E5 00 30 93 E5 80 00 A0 E1 03 00 80 E0 01 00 D0 E5 00 04 A0 E1 01 0C 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isalnum_03e245c133ace13950a353a77a7905ec {
	meta:
		aliases = "isalnum"
		size = "36"
		objfiles = "isalnum@libc.a"
	strings:
		$pattern = { 18 30 9F E5 00 30 93 E5 80 00 A0 E1 03 00 80 E0 01 00 D0 E5 00 04 A0 E1 02 0B 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule iscntrl_3410e46c7f1eacf3e49ac2c45d56a297 {
	meta:
		aliases = "iscntrl"
		size = "36"
		objfiles = "iscntrl@libc.a"
	strings:
		$pattern = { 18 30 9F E5 00 30 93 E5 80 00 A0 E1 03 00 80 E0 01 00 D0 E5 00 04 A0 E1 02 0C 00 E2 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule enqueue_87f857d09940efef44b7a93828aa85f2 {
	meta:
		aliases = "enqueue"
		size = "48"
		objfiles = "semaphore@libpthread.a, rwlock@libpthread.a, condvar@libpthread.a"
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

rule __pthread_attr_getstackaddr_b55cec3b28132e2b71195e212a7232e1 {
	meta:
		aliases = "pthread_attr_getstackaddr, __pthread_attr_getstackaddr"
		size = "16"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 1C 30 90 E5 00 00 A0 E3 00 30 81 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule rpc_thread_multi_ff14a5e206c4d6dafee65f3dd6fdf5f7 {
	meta:
		aliases = "rpc_thread_multi"
		size = "48"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { 1C 30 9F E5 00 00 53 E3 18 20 9F E5 18 30 9F 05 02 00 A0 E3 02 10 A0 E1 00 20 83 05 0E F0 A0 01 ?? ?? ?? EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
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

rule __open_etc_hosts_12a606e4081480b3a3ffb605a94d9477 {
	meta:
		aliases = "__open_etc_hosts"
		size = "52"
		objfiles = "read_etc_hosts_r@libc.a"
	strings:
		$pattern = { 20 10 9F E5 04 E0 2D E5 1C 00 9F E5 ?? ?? ?? EB 00 00 50 E3 0C 10 9F E5 04 F0 9D 14 0C 00 9F E5 04 E0 9D E4 ?? ?? ?? EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __aeabi_llsl_887a760ccd40f339c0b687063b63c0fc {
	meta:
		aliases = "__ashldi3, __aeabi_llsl"
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

rule __aeabi_lasr_bbd82ffebddc7de5630c025bd359f1aa {
	meta:
		aliases = "__ashrdi3, __aeabi_lasr"
		size = "28"
		objfiles = "_ashrdi3@libgcc.a"
	strings:
		$pattern = { 20 30 52 E2 20 C0 62 E2 30 02 A0 41 51 03 A0 51 11 0C 80 41 51 12 A0 E1 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __pthread_attr_getstacksize_6c5d6331f482f886c8d9ebd865b140ac {
	meta:
		aliases = "pthread_attr_getstacksize, __pthread_attr_getstacksize"
		size = "16"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 20 30 90 E5 00 00 A0 E3 00 30 81 E5 0E F0 A0 E1 }
	condition:
		$pattern
}

rule llrint_8153807b4d93d54c3105c62a3a07d9a0 {
	meta:
		aliases = "__GI_llrint, llrint"
		size = "380"
		objfiles = "s_llrint@libm.a"
	strings:
		$pattern = { 20 3A A0 E1 70 40 2D E9 83 3A A0 E1 A3 3A A0 E1 FF 2F 43 E2 03 20 42 E2 01 50 A0 E1 13 00 52 E3 08 D0 4D E2 03 00 2D E9 02 81 BD EC 00 40 A0 E1 05 E0 A0 E1 A0 6F A0 E1 1A 00 00 CA 34 31 9F E5 86 31 83 E0 00 91 93 ED 80 01 01 EE 00 81 8D ED 00 81 9D ED 81 01 20 EE 02 81 2D ED 18 00 BD E8 03 10 A0 E1 21 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF 2F 43 E2 03 20 42 E2 00 00 52 E3 00 00 A0 B3 00 10 A0 B3 35 00 00 BA FF 34 C1 E3 0F 36 C3 E3 01 36 83 E3 14 20 62 E2 33 32 A0 E1 03 00 A0 E1 00 10 A0 E3 2D 00 00 EA 3E 00 52 E3 29 00 00 CA 33 00 52 E3 0A 00 00 DA FF 34 C0 E3 0F 36 C3 E3 01 36 83 E3 00 40 A0 E3 }
	condition:
		$pattern
}

rule llround_97084ac8e2bc4bde0787fed56d0bf8fd {
	meta:
		aliases = "__GI_llround, llround"
		size = "268"
		objfiles = "s_llround@libm.a"
	strings:
		$pattern = { 20 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 F0 40 2D E9 FF 6F 43 E2 00 00 50 E3 03 60 46 E2 FF 24 C0 E3 01 70 A0 A3 00 70 E0 B3 0F 26 C2 E3 13 00 56 E3 00 40 A0 E1 01 50 A0 E1 01 26 82 E3 0E 00 00 CA 00 00 56 E3 05 00 00 AA 01 00 76 E3 00 00 A0 13 00 10 A0 13 07 00 A0 01 C0 1F A0 01 F0 80 BD E8 02 37 A0 E3 53 36 82 E0 14 20 66 E2 33 32 A0 E1 03 20 A0 E1 00 30 A0 E3 1F 00 00 EA 3E 00 56 E3 1B 00 00 CA 33 00 56 E3 08 00 00 DA 02 30 A0 E1 00 40 A0 E3 03 40 A0 E1 00 30 A0 E3 01 00 83 E1 34 20 46 E2 04 10 A0 E1 ?? ?? ?? EB 0D 00 00 EA 14 E0 46 E2 02 31 A0 E3 33 4E 81 E0 01 00 54 E1 01 20 82 32 14 00 56 E3 }
	condition:
		$pattern
}

rule lround_2a9361d65be3a041291c5f175a717782 {
	meta:
		aliases = "__GI_lround, lround"
		size = "164"
		objfiles = "s_lround@libm.a"
	strings:
		$pattern = { 20 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF CF 43 E2 00 00 50 E3 FF 24 C0 E3 03 C0 4C E2 10 40 2D E9 0F 26 C2 E3 01 40 A0 A3 00 40 E0 B3 13 00 5C E3 03 00 2D E9 02 81 BD EC 01 06 82 E3 0A 00 00 CA 00 00 5C E3 03 00 00 AA 01 00 7C E3 04 00 A0 01 00 00 A0 13 10 80 BD E8 02 37 A0 E3 53 3C 80 E0 14 20 6C E2 33 02 A0 E1 0B 00 00 EA 1E 00 5C E3 70 01 10 CE 10 80 BD C8 02 31 A0 E3 14 20 4C E2 33 E2 81 E0 01 00 5E E1 01 00 80 32 14 00 5C E3 34 30 6C 12 3E 33 A0 11 10 02 83 11 94 00 00 E0 10 80 BD E8 }
	condition:
		$pattern
}

rule dlerror_1c743bcfcbe21acf8a76cd7e72d3e992 {
	meta:
		aliases = "dlerror"
		size = "52"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 24 10 9F E5 00 20 91 E5 00 00 52 E3 02 00 A0 E1 0E F0 A0 01 00 30 A0 E3 00 30 81 E5 0C 30 9F E5 02 31 93 E7 03 00 A0 E1 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? }
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

rule getchar_unlocked_5319fbca9d0b4627d3727d5ac7815303 {
	meta:
		aliases = "__GI_getchar_unlocked, getchar_unlocked"
		size = "48"
		objfiles = "getchar_unlocked@libc.a"
	strings:
		$pattern = { 24 30 9F E5 00 10 93 E5 10 20 91 E5 18 30 91 E5 03 00 52 E1 01 00 A0 E1 00 00 00 3A ?? ?? ?? EA 01 00 D2 E4 10 20 81 E5 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sched_setaffinity_f501383a8564f59f3c9068ce48295ee1 {
	meta:
		aliases = "sched_setaffinity"
		size = "304"
		objfiles = "sched_setaffinity@libc.a"
	strings:
		$pattern = { 24 31 9F E5 00 30 93 E5 0D C0 A0 E1 00 00 53 E3 F0 DD 2D E9 04 B0 4C E2 00 A0 A0 E1 01 80 A0 E1 02 70 A0 E1 28 00 00 1A 84 D0 4D E2 0D 60 A0 E1 80 50 A0 E3 04 00 00 EA 0D D0 61 E0 02 30 8D E0 06 00 53 E1 02 50 A0 11 0D 60 A0 E1 ?? ?? ?? EB F2 00 90 EF 85 20 A0 E1 06 30 82 E2 03 10 C3 E3 16 00 70 E3 00 30 A0 13 01 30 A0 03 01 0A 70 E3 00 30 A0 93 00 00 53 E3 00 40 A0 E1 02 50 85 E0 EC FF FF 1A 01 0A 70 E3 00 30 A0 93 01 30 A0 83 00 00 50 E3 01 30 83 03 00 00 53 E3 88 30 9F 05 00 00 83 05 08 00 00 0A ?? ?? ?? EB 00 30 64 E2 00 20 E0 E3 02 00 00 EA ?? ?? ?? EB 00 20 E0 E3 16 30 A0 E3 00 30 80 E5 }
	condition:
		$pattern
}

rule putchar_unlocked_51f4a1b2d6ebdb74792c6d1a47344a6e {
	meta:
		aliases = "putchar_unlocked"
		size = "52"
		objfiles = "putchar_unlocked@libc.a"
	strings:
		$pattern = { 28 30 9F E5 00 C0 93 E5 10 20 9C E5 1C 30 9C E5 03 00 52 E1 0C 10 A0 E1 00 00 00 3A ?? ?? ?? EA 00 00 C2 E5 01 00 D2 E4 10 20 8C E5 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_isinf_e78d4744ea1c8324d0ef5c7b06edb03e {
	meta:
		aliases = "__GI___isinf, __isinf, isinf, __GI_isinf"
		size = "52"
		objfiles = "s_isinf@libm.a"
	strings:
		$pattern = { 28 30 9F E5 01 20 A0 E1 00 10 A0 E1 02 01 C0 E3 03 00 20 E0 02 00 80 E1 00 30 60 E2 03 00 80 E1 00 00 50 E3 41 0F A0 A1 00 00 A0 B3 0E F0 A0 E1 00 00 F0 7F }
	condition:
		$pattern
}

rule __do_global_ctors_aux_e9e186a8d3fb9868f5bb368c2fd42b05 {
	meta:
		aliases = "__do_global_ctors_aux"
		size = "60"
		objfiles = "crtend"
	strings:
		$pattern = { 28 30 9F E5 04 20 13 E5 01 00 72 E3 10 40 2D E9 04 40 43 E2 10 80 BD 08 0F E0 A0 E1 02 F0 A0 E1 04 20 34 E5 01 00 72 E3 FA FF FF 1A 10 80 BD E8 ?? ?? ?? ?? 04 E0 2D E5 04 F0 9D E4 }
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

rule _dl_load_shared_library_30897bd85f5c9f1192e4b05383a19c8b {
	meta:
		aliases = "_dl_load_shared_library"
		size = "588"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 2C C2 9F E5 F0 47 2D E9 00 E0 A0 E3 00 E0 8C E5 00 70 A0 E1 03 C0 A0 E1 01 80 A0 E1 02 50 A0 E1 01 30 43 E2 01 20 F3 E5 00 00 52 E3 FC FF FF 1A 03 30 6C E0 01 0B 53 E3 02 00 A0 91 01 30 4C 92 02 00 00 9A 70 00 00 EA 2F 00 52 E3 03 00 A0 01 01 20 F3 E5 00 00 52 E3 FA FF FF 1A 00 00 50 E3 0C 40 A0 01 01 40 80 12 0C 00 54 E1 05 00 00 0A 0C 20 A0 E1 07 00 A0 E1 08 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 F0 87 BD 18 00 00 55 E3 0A 00 00 0A 7C 30 95 E5 00 00 53 E3 07 00 00 0A 54 20 95 E5 04 00 A0 E1 02 20 83 E0 07 10 A0 E1 08 30 A0 E1 71 FF FF EB 00 00 50 E3 F0 87 BD 18 74 31 9F E5 00 20 93 E5 00 00 52 E3 }
	condition:
		$pattern
}

rule isdigit_2cc7b1353f57f0929448a034aadb83c8 {
	meta:
		aliases = "isdigit"
		size = "20"
		objfiles = "isdigit@libc.a"
	strings:
		$pattern = { 30 00 40 E2 09 00 50 E3 00 00 A0 83 01 00 A0 93 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __sigpause_fa64f854609f36a905fb46f486154bed {
	meta:
		aliases = "__GI___sigpause, __sigpause"
		size = "124"
		objfiles = "sigpause@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 00 51 E3 80 D0 4D E2 00 50 A0 E1 00 00 8D 05 0D 40 A0 E1 04 00 8D 02 1E 10 A0 03 0B 00 00 0A 00 00 A0 E3 00 10 A0 E1 0D 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 0C 00 00 BA 0D 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 04 00 00 AA 06 00 00 EA 00 30 A0 E3 01 10 51 E2 04 30 80 E4 FB FF FF 5A 0D 00 A0 E1 ?? ?? ?? EB 00 00 00 EA 00 00 E0 E3 80 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule pthread_kill_other_threads_np_32e0c5dc20cc859e55a92f49c7fb2ef3 {
	meta:
		aliases = "__pthread_kill_other_threads_np, pthread_kill_other_threads_np"
		size = "136"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 00 00 A0 E3 00 10 A0 E1 8C D0 4D E2 A5 FF FF EB 0D 50 A0 E1 ?? ?? ?? EB 04 00 8D E2 ?? ?? ?? EB 50 30 9F E5 00 40 A0 E3 00 00 93 E5 0D 10 A0 E1 04 20 A0 E1 84 40 8D E5 00 40 8D E5 ?? ?? ?? EB 34 30 9F E5 0D 10 A0 E1 00 00 93 E5 04 20 A0 E1 ?? ?? ?? EB 24 30 9F E5 00 30 93 E5 04 00 53 E1 0D 10 A0 E1 04 20 A0 E1 03 00 A0 E1 ?? ?? ?? CB 8C D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_pthread_cond_broadcast_db564df580e0b26598c542d0009d96ac {
	meta:
		aliases = "pthread_cond_broadcast, __GI_pthread_cond_broadcast"
		size = "88"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 00 10 A0 E3 00 40 A0 E1 ?? ?? ?? EB 00 30 A0 E3 08 50 94 E5 04 00 A0 E1 08 30 84 E5 ?? ?? ?? EB 07 00 00 EA 01 30 A0 E3 B9 31 C5 E5 00 30 A0 E3 08 40 95 E5 08 30 85 E5 05 00 A0 E1 ED FF FF EB 04 50 A0 E1 00 00 55 E3 F5 FF FF 1A 05 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule sem_trywait_d565e2e6bc80743bbfacd661d2217026 {
	meta:
		aliases = "__new_sem_trywait, sem_trywait"
		size = "72"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 00 10 A0 E3 00 40 A0 E1 ?? ?? ?? EB 08 30 94 E5 00 00 53 E3 01 30 43 E2 00 50 E0 E3 08 30 84 15 00 50 A0 13 02 00 00 1A ?? ?? ?? EB 0B 30 A0 E3 00 30 80 E5 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule pthread_rwlock_trywrlock_8df8a4b3857353a083284abb99ba8fd2 {
	meta:
		aliases = "pthread_rwlock_trywrlock"
		size = "76"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 00 10 A0 E3 00 40 A0 E1 ?? ?? ?? EB 08 30 94 E5 00 00 53 E3 06 00 00 1A 0C 30 94 E5 00 00 53 E3 03 50 A0 E1 02 00 00 1A D4 FF FF EB 0C 00 84 E5 00 00 00 EA 10 50 A0 E3 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_pthread_cond_signal_9d7454c80a2813ffac143f32fc309ecd {
	meta:
		aliases = "pthread_cond_signal, __GI_pthread_cond_signal"
		size = "80"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 00 10 A0 E3 00 50 A0 E1 ?? ?? ?? EB 08 40 95 E5 00 00 54 E3 08 30 94 15 08 30 85 15 00 30 A0 13 08 30 84 15 05 00 A0 E1 ?? ?? ?? EB 00 00 54 E3 03 00 00 0A 01 30 A0 E3 B9 31 C4 E5 04 00 A0 E1 BD FE FF EB 00 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule gethostid_95ca2aafd30d0bd96bdd4eab9524b376 {
	meta:
		aliases = "gethostid"
		size = "212"
		objfiles = "hostid@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 10 A0 E3 6F DF 4D E2 BC 00 9F E5 ?? ?? ?? EB 55 5F 8D E2 00 40 50 E2 03 50 85 E2 6E 1F 8D E2 04 20 A0 E3 08 00 00 BA ?? ?? ?? EB 00 00 50 E3 04 00 A0 E1 02 00 00 0A ?? ?? ?? EB B8 01 9D E5 1F 00 00 EA 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 40 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 17 00 00 BA 57 C1 DD E5 0C 20 8D E2 00 00 5C E3 05 00 A0 E1 01 20 42 E2 66 1F 8D E2 53 3F A0 E3 0F 00 00 0A 6D CF 8D E2 00 C0 8D E5 6B CF 8D E2 04 C0 8D E5 ?? ?? ?? EB B4 21 9D E5 00 00 52 E3 1B 0E 8D E2 06 00 00 0A 0C 20 82 E2 0C 00 92 E8 00 10 93 E5 ?? ?? ?? EB B0 31 9D E5 63 08 A0 E1 00 00 00 EA 00 00 A0 E3 }
	condition:
		$pattern
}

rule updwtmp_6ed48f8fbd7f690a40d3148eca428c75 {
	meta:
		aliases = "updwtmp"
		size = "96"
		objfiles = "wtent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 20 A0 E3 01 50 A0 E1 48 10 9F E5 ?? ?? ?? EB 00 40 50 E2 01 10 A0 E3 00 20 A0 E3 30 80 BD B8 ?? ?? ?? EB 05 10 A0 E1 00 50 50 E2 06 2D A0 E3 04 00 A0 E1 30 80 BD 18 ?? ?? ?? EB 04 00 A0 E1 05 10 A0 E1 05 20 A0 E1 ?? ?? ?? EB 04 00 A0 E1 30 40 BD E8 ?? ?? ?? EA 01 04 00 00 }
	condition:
		$pattern
}

rule __GI_strtod_fa5ffc814d4632835542af7add58e336 {
	meta:
		aliases = "__GI_wcstod, wcstod, strtod, __GI_strtod"
		size = "52"
		objfiles = "strtod@libc.a, wcstod@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 20 A0 E3 ?? ?? ?? EB 02 81 2D ED 30 00 BD E8 04 00 A0 E1 05 10 A0 E1 04 20 A0 E1 05 30 A0 E1 ?? ?? ?? EB 30 00 2D E9 02 81 BD EC 30 80 BD E8 }
	condition:
		$pattern
}

rule __stdio_trans2r_o_c9ce3729fa4af34b6a43cdb13cfa53b4 {
	meta:
		aliases = "__stdio_trans2r_o"
		size = "188"
		objfiles = "_trans2r@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 20 D0 E5 01 30 D0 E5 03 24 82 E1 01 00 12 E1 00 40 A0 E1 05 00 00 1A 22 0D 12 E3 08 00 00 1A 01 20 82 E1 42 34 A0 E1 01 30 C0 E5 00 20 C0 E5 00 20 D4 E5 01 30 D4 E5 03 34 82 E1 10 50 13 E2 09 00 00 0A ?? ?? ?? EB 09 30 A0 E3 00 30 80 E5 00 30 94 E5 08 30 83 E3 43 24 A0 E1 00 00 E0 E3 01 20 C4 E5 00 30 C4 E5 30 80 BD E8 40 00 13 E3 09 00 00 0A ?? ?? ?? EB 00 00 50 E3 F3 FF FF 1A 00 30 94 E5 08 20 94 E5 40 30 C3 E3 43 14 A0 E1 1C 20 84 E5 01 10 C4 E5 00 30 C4 E5 00 30 94 E5 01 30 83 E3 43 24 A0 E1 05 00 A0 E1 01 20 C4 E5 00 30 C4 E5 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_double_9a183c0db0253e52a6f8e52dd79f88c4 {
	meta:
		aliases = "xdr_double"
		size = "148"
		objfiles = "xdr_float@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 30 90 E5 01 00 53 E3 00 40 A0 E1 01 50 A0 E1 0F 00 00 0A 03 00 00 3A 02 00 53 E3 00 00 A0 13 01 00 A0 03 30 80 BD E8 04 30 90 E5 0F E0 A0 E1 04 F0 93 E5 00 00 50 E3 04 10 85 E2 04 00 A0 E1 10 00 00 0A 04 30 94 E5 0F E0 A0 E1 04 F0 93 E5 09 00 00 EA 04 30 90 E5 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 04 10 85 E2 04 00 A0 E1 05 00 00 0A 04 30 94 E5 0F E0 A0 E1 00 F0 93 E5 00 00 50 E2 01 00 A0 13 30 80 BD E8 00 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_rmtcallres_0e334e2a8f9fdeb21ef8d463b09f609f {
	meta:
		aliases = "__GI_xdr_rmtcallres, xdr_rmtcallres"
		size = "116"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 30 91 E5 04 D0 4D E2 01 40 A0 E1 04 10 8D E2 04 30 21 E5 04 20 A0 E3 0D 10 A0 E1 48 30 9F E5 00 50 A0 E1 ?? ?? ?? EB 00 00 50 E3 04 10 84 E2 05 00 A0 E1 09 00 00 0A ?? ?? ?? EB 00 00 50 E3 05 00 A0 E1 05 00 00 0A 00 30 9D E5 08 10 94 E5 00 30 84 E5 0F E0 A0 E1 0C F0 94 E5 00 00 00 EA 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdrrec_getlong_0601c4dce1e9f35668206f813f10bde4 {
	meta:
		aliases = "xdrrec_getlong"
		size = "196"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 30 A0 E1 0C C0 93 E5 34 30 9C E5 04 D0 4D E2 03 00 53 E3 01 50 A0 E1 04 20 A0 E3 0D 10 A0 E1 2C E0 9C E5 14 00 00 DA 30 30 9C E5 03 30 6E E0 03 00 53 E3 01 40 A0 E3 0F 00 00 DA 00 10 9E E5 FF 38 01 E2 FF 2C 01 E2 23 34 A0 E1 02 24 A0 E1 01 2C 82 E1 21 3C 83 E1 02 30 83 E1 00 30 85 E5 34 20 9C E5 2C 30 9C E5 04 20 42 E2 04 30 83 E2 2C 30 8C E5 34 20 8C E5 0D 00 00 EA 89 FF FF EB 00 00 50 E3 00 40 A0 E1 09 00 00 0A 00 30 9D E5 FF 28 03 E2 FF 1C 03 E2 22 24 A0 E1 01 14 A0 E1 03 1C 81 E1 23 2C 82 E1 01 20 82 E1 00 20 85 E5 01 40 A0 E3 04 00 A0 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule xdrrec_getint32_496b7add1c4a318aa3e85fd7512b52eb {
	meta:
		aliases = "xdrrec_getint32"
		size = "196"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 30 A0 E1 0C C0 93 E5 34 30 9C E5 04 D0 4D E2 03 00 53 E3 01 50 A0 E1 04 20 A0 E3 0D 10 A0 E1 2C E0 9C E5 14 00 00 DA 30 30 9C E5 03 30 6E E0 03 00 53 E3 01 40 A0 E3 0F 00 00 DA 00 10 9E E5 FF 38 01 E2 FF 2C 01 E2 23 34 A0 E1 02 24 A0 E1 01 2C 82 E1 21 3C 83 E1 02 30 83 E1 00 30 85 E5 34 20 9C E5 2C 30 9C E5 04 20 42 E2 04 30 83 E2 2C 30 8C E5 34 20 8C E5 0D 00 00 EA BA FF FF EB 00 00 50 E3 00 40 A0 E1 09 00 00 0A 00 30 9D E5 FF 28 03 E2 FF 1C 03 E2 22 24 A0 E1 01 14 A0 E1 03 1C 81 E1 23 2C 82 E1 01 20 82 E1 00 20 85 E5 01 40 A0 E3 04 00 A0 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_xdr_callhdr_82bd28838ca754f7846154571fafb159 {
	meta:
		aliases = "xdr_callhdr, __GI_xdr_callhdr"
		size = "136"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 30 A0 E3 04 30 81 E5 02 30 83 E2 08 30 81 E5 00 30 90 E5 00 00 53 E3 01 40 A0 E1 00 50 A0 E1 15 00 00 1A ?? ?? ?? EB 00 00 50 E3 04 10 84 E2 05 00 A0 E1 10 00 00 0A ?? ?? ?? EB 00 00 50 E3 08 10 84 E2 05 00 A0 E1 0B 00 00 0A ?? ?? ?? EB 00 00 50 E3 0C 10 84 E2 05 00 A0 E1 06 00 00 0A ?? ?? ?? EB 00 00 50 E3 10 10 84 E2 05 00 A0 E1 01 00 00 0A 30 40 BD E8 ?? ?? ?? EA 00 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule inet_pton4_e66c3fa7cb487c273c7fa9992f38c02b {
	meta:
		aliases = "inet_pton4"
		size = "204"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 30 A0 E3 04 D0 4D E2 00 40 A0 E1 01 50 A0 E1 03 E0 A0 E1 03 10 A0 E1 0D 00 A0 E1 00 30 CD E5 19 00 00 EA 09 00 53 E3 00 20 A0 E3 0D 00 00 8A 00 30 D0 E5 0A 20 82 E2 92 C3 23 E0 30 30 43 E2 FF 00 53 E3 1C 00 00 8A 00 00 51 E3 00 30 C0 E5 0D 00 00 1A 01 E0 8E E2 04 00 5E E3 01 10 81 E2 15 00 00 CA 08 00 00 EA 2E 00 5C E3 00 30 A0 13 01 30 01 02 00 00 53 E3 02 10 A0 E1 0E 00 00 0A 04 00 5E E3 0C 00 00 0A 01 20 E0 E5 01 C0 D4 E4 00 00 5C E3 30 30 4C E2 E1 FF FF 1A 03 00 5E E3 05 00 00 DA 05 00 A0 E1 0D 10 A0 E1 04 20 A0 E3 ?? ?? ?? EB 01 00 A0 E3 00 00 00 EA 00 00 A0 E3 04 D0 8D E2 }
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

rule getwc_unlocked_af1c42d92db412e0235bd1f9913d4b95 {
	meta:
		aliases = "__GI_fgetwc_unlocked, fgetwc_unlocked, getwc_unlocked"
		size = "440"
		objfiles = "fgetwc_unlocked@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 30 D0 E5 01 10 D0 E5 A0 21 9F E5 01 34 83 E1 02 20 03 E0 02 0B 52 E3 08 D0 4D E2 00 40 A0 E1 04 00 00 8A 02 1B A0 E3 ?? ?? ?? EB 00 00 50 E3 00 50 E0 13 5A 00 00 1A 00 20 D4 E5 01 30 D4 E5 03 34 82 E1 02 00 13 E3 14 00 00 0A 01 00 13 E3 03 00 00 1A 28 30 94 E5 00 00 53 E3 03 30 D4 05 00 00 00 0A 00 30 A0 E3 00 20 D4 E5 02 30 C4 E5 01 30 D4 E5 03 24 82 E1 01 30 02 E2 03 31 84 E0 01 20 42 E2 24 50 93 E5 42 34 A0 E1 01 30 C4 E5 00 30 A0 E3 28 30 84 E5 00 20 C4 E5 3A 00 00 EA 08 30 94 E5 00 00 53 E3 05 00 00 1A 04 00 A0 E1 07 10 8D E2 C9 FF FF EB 0C 30 94 E5 01 30 83 E2 0C 30 84 E5 }
	condition:
		$pattern
}

rule __stdio_READ_a2567efd10719f979f38de70827df2c7 {
	meta:
		aliases = "__stdio_READ"
		size = "92"
		objfiles = "_READ@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 30 D0 E5 04 50 13 E2 00 40 A0 E1 00 00 A0 E3 30 80 BD 18 00 00 52 E3 02 21 E0 B3 04 00 94 E5 ?? ?? ?? EB 00 00 50 E3 30 80 BD C8 00 30 94 E5 08 10 83 E3 04 30 83 E3 41 C4 A0 E1 43 24 A0 E1 05 00 A0 11 01 20 C4 05 00 30 C4 05 01 C0 C4 15 00 10 C4 15 30 80 BD E8 }
	condition:
		$pattern
}

rule herror_56f915119cf3bc557833957e462d5cce {
	meta:
		aliases = "__GI_herror, herror"
		size = "120"
		objfiles = "herror@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 50 E2 04 D0 4D E2 03 00 00 0A 00 30 D4 E5 00 00 53 E3 40 50 9F E5 00 00 00 1A 3C 50 9F E5 ?? ?? ?? EB 00 00 90 E5 04 00 50 E3 30 30 9F 95 30 C0 9F E5 00 C1 93 97 2C 30 9F E5 04 20 A0 E1 00 00 93 E5 24 10 9F E5 05 30 A0 E1 00 C0 8D E5 ?? ?? ?? EB 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getpw_9417d50d858437b59b56d0aa4380bb2c {
	meta:
		aliases = "getpw"
		size = "160"
		objfiles = "getpw@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 51 E2 4D DF 4D E2 14 20 8D E2 01 3C A0 E3 45 1F 8D E2 04 00 00 1A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 17 00 00 EA 13 CE 8D E2 00 C0 8D E5 ?? ?? ?? EB 00 50 50 E2 54 10 9F E5 04 00 A0 E1 0F 00 00 1A 1C C1 9D E5 00 C0 8D E5 20 C1 9D E5 04 C0 8D E5 24 C1 9D E5 08 C0 8D E5 28 C1 9D E5 0C C0 8D E5 2C C1 9D E5 45 2F 8D E2 0C 00 92 E8 10 C0 8D E5 ?? ?? ?? EB 00 00 50 E3 05 20 A0 E1 00 00 00 AA 00 20 E0 E3 02 00 A0 E1 4D DF 8D E2 30 80 BD E8 ?? ?? ?? ?? }
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

rule xdr_u_long_b7e287ce5bcbe13cc958ad02d9f6d8bb {
	meta:
		aliases = "__GI_xdr_u_long, xdr_u_long"
		size = "112"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 01 00 54 E3 04 D0 4D E2 01 50 A0 E1 04 00 00 0A 0D 00 00 3A 02 00 54 E3 01 00 A0 E3 0E 00 00 1A 0E 00 00 EA 04 30 90 E5 0D 10 A0 E1 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 00 30 9D 15 04 00 A0 E1 00 30 85 15 05 00 00 1A 03 00 00 EA 04 30 90 E5 0F E0 A0 E1 04 F0 93 E5 00 00 00 EA 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_uint8_t_8398b8a84f2085410d6aba77d3b9081a {
	meta:
		aliases = "xdr_uint8_t"
		size = "124"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 04 D0 4D E2 01 00 54 E3 01 50 A0 E1 0D 10 A0 E1 0C 00 00 0A 04 10 8D E2 03 00 00 3A 02 00 54 E3 01 00 A0 E3 0F 00 00 1A 0F 00 00 EA 00 30 D5 E5 04 20 90 E5 04 30 21 E5 0D 10 A0 E1 0F E0 A0 E1 24 F0 92 E5 08 00 00 EA 04 30 90 E5 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 00 30 9D 15 04 00 A0 E1 00 30 C5 15 00 00 00 1A 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_int8_t_3dc9bc59fd15523fa712126c3f08264a {
	meta:
		aliases = "xdr_int8_t"
		size = "132"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 04 D0 4D E2 01 00 54 E3 01 50 A0 E1 0D 10 A0 E1 0E 00 00 0A 04 10 8D E2 03 00 00 3A 02 00 54 E3 01 00 A0 E3 11 00 00 1A 11 00 00 EA 00 30 D5 E5 03 3C A0 E1 43 3C A0 E1 04 20 90 E5 04 30 21 E5 0D 10 A0 E1 0F E0 A0 E1 24 F0 92 E5 08 00 00 EA 04 30 90 E5 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 00 30 9D 15 04 00 A0 E1 00 30 C5 15 00 00 00 1A 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_xdr_u_short_9fe3eecff243985657f6f116f65e830c {
	meta:
		aliases = "xdr_u_short, __GI_xdr_u_short"
		size = "140"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 04 D0 4D E2 01 00 54 E3 01 50 A0 E1 0D 10 A0 E1 0E 00 00 0A 04 10 8D E2 03 00 00 3A 02 00 54 E3 01 00 A0 E3 13 00 00 1A 13 00 00 EA 01 30 D5 E5 00 20 D5 E5 03 24 82 E1 04 20 21 E5 0D 10 A0 E1 04 30 90 E5 0F E0 A0 E1 04 F0 93 E5 0A 00 00 EA 04 30 90 E5 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 04 00 A0 E1 00 20 9D 15 42 34 A0 11 01 30 C5 15 00 20 C5 15 00 00 00 1A 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_uint16_t_62b36bc28fef93870a52c5ef3b3da99e {
	meta:
		aliases = "xdr_uint16_t"
		size = "140"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 04 D0 4D E2 01 00 54 E3 01 50 A0 E1 0D 10 A0 E1 0E 00 00 0A 04 10 8D E2 03 00 00 3A 02 00 54 E3 01 00 A0 E3 13 00 00 1A 13 00 00 EA 01 30 D5 E5 00 20 D5 E5 03 24 82 E1 04 20 21 E5 0D 10 A0 E1 04 30 90 E5 0F E0 A0 E1 24 F0 93 E5 0A 00 00 EA 04 30 90 E5 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 04 00 A0 E1 00 20 9D 15 42 34 A0 11 01 30 C5 15 00 20 C5 15 00 00 00 1A 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_bool_4aeacfd46d971a81bee619d7d92bd050 {
	meta:
		aliases = "__GI_xdr_bool, xdr_bool"
		size = "144"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 04 D0 4D E2 01 00 54 E3 01 50 A0 E1 0D 10 A0 E1 0E 00 00 0A 04 10 8D E2 03 00 00 3A 02 00 54 E3 01 00 A0 E3 14 00 00 1A 14 00 00 EA 00 30 95 E5 00 30 53 E2 01 30 A0 13 04 20 90 E5 04 30 21 E5 0D 10 A0 E1 0F E0 A0 E1 04 F0 92 E5 0B 00 00 EA 04 30 90 E5 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 04 00 A0 E1 04 00 00 0A 00 30 9D E5 00 30 53 E2 01 30 A0 13 00 30 85 E5 00 00 00 EA 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_xdr_short_c7157cd8c044c2ae34e20e1a92ec433b {
	meta:
		aliases = "xdr_short, __GI_xdr_short"
		size = "144"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 04 D0 4D E2 01 00 54 E3 01 50 A0 E1 0D 10 A0 E1 0F 00 00 0A 04 10 8D E2 03 00 00 3A 02 00 54 E3 01 00 A0 E3 14 00 00 1A 14 00 00 EA 01 30 D5 E5 00 20 D5 E5 03 3C A0 E1 43 28 82 E1 04 20 21 E5 0D 10 A0 E1 04 30 90 E5 0F E0 A0 E1 04 F0 93 E5 0A 00 00 EA 04 30 90 E5 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 04 00 A0 E1 00 20 9D 15 42 34 A0 11 01 30 C5 15 00 20 C5 15 00 00 00 1A 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule xdr_int16_t_bc79c26839ecce68c06c8a01a7817d45 {
	meta:
		aliases = "xdr_int16_t"
		size = "144"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 90 E5 04 D0 4D E2 01 00 54 E3 01 50 A0 E1 0D 10 A0 E1 0F 00 00 0A 04 10 8D E2 03 00 00 3A 02 00 54 E3 01 00 A0 E3 14 00 00 1A 14 00 00 EA 01 30 D5 E5 00 20 D5 E5 03 3C A0 E1 43 28 82 E1 04 20 21 E5 0D 10 A0 E1 04 30 90 E5 0F E0 A0 E1 24 F0 93 E5 0A 00 00 EA 04 30 90 E5 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 04 00 A0 E1 00 20 9D 15 42 34 A0 11 01 30 C5 15 00 20 C5 15 00 00 00 1A 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule uw_advance_context_a079703732f85c6cf9ad203b77f7fc81 {
	meta:
		aliases = "uw_advance_context"
		size = "36"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 00 00 90 E5 01 50 A0 E1 ?? ?? ?? EB 04 00 A0 E1 05 10 A0 E1 30 40 BD E8 F2 FF FF EA }
	condition:
		$pattern
}

rule setegid_ddcfef4170f23c6e9c4081822c781c99 {
	meta:
		aliases = "__GI_seteuid, seteuid, setegid"
		size = "104"
		objfiles = "seteuid@libc.a, setegid@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 00 00 E0 E3 00 00 54 E1 04 10 A0 E1 00 20 A0 E1 04 50 A0 E1 03 00 00 1A ?? ?? ?? EB 16 30 A0 E3 00 30 80 E5 0B 00 00 EA ?? ?? ?? EB 01 00 70 E3 00 50 A0 E1 07 00 00 1A ?? ?? ?? EB 00 30 90 E5 26 00 53 E3 04 10 A0 E1 05 00 A0 E1 01 00 00 1A 30 40 BD E8 ?? ?? ?? EA 05 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_xprt_unregister_9193eb38017fe4ab74f161bc24f3f47b {
	meta:
		aliases = "xprt_unregister, __GI_xprt_unregister"
		size = "144"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 00 50 90 E5 ?? ?? ?? EB 00 00 55 E1 30 80 BD A8 ?? ?? ?? EB B4 10 90 E5 05 21 A0 E1 02 30 91 E7 04 00 53 E1 30 80 BD 18 00 40 A0 E3 01 0B 55 E3 02 40 81 E7 0E 00 00 AA ?? ?? ?? EB A5 C2 A0 E1 0C 31 90 E7 1F 10 05 E2 01 20 A0 E3 12 31 C3 E1 0C 31 80 E7 06 00 00 EA ?? ?? ?? EB 00 00 90 E5 84 31 90 E7 05 00 53 E1 00 30 E0 03 84 31 80 07 01 40 84 E2 ?? ?? ?? EB 00 30 90 E5 03 00 54 E1 F4 FF FF BA 30 80 BD E8 }
	condition:
		$pattern
}

rule __regfree_c451c3775b2f258fd2c2862acef7cbcc {
	meta:
		aliases = "regfree, __regfree"
		size = "72"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 00 50 A0 E3 00 00 90 E5 ?? ?? ?? EB 10 00 94 E5 00 50 84 E5 04 50 84 E5 08 50 84 E5 ?? ?? ?? EB 1C 30 D4 E5 08 30 C3 E3 1C 30 C4 E5 10 50 84 E5 14 00 94 E5 ?? ?? ?? EB 14 50 84 E5 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_carg_029674173c670bcb66c0b453e170d6d0 {
	meta:
		aliases = "carg, __GI_carg"
		size = "36"
		objfiles = "carg@libm.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 01 50 A0 E1 02 00 A0 E1 03 10 A0 E1 04 20 A0 E1 05 30 A0 E1 30 40 BD E8 ?? ?? ?? EA }
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

rule skip_input_bytes_918fefe99ee3895ac61c0ab388ec9464 {
	meta:
		aliases = "skip_input_bytes"
		size = "88"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 01 50 A0 E1 0C 00 00 EA 2C 10 84 E2 0A 00 91 E8 01 20 53 E0 03 00 00 1A E3 FF FF EB 00 00 50 E3 05 00 00 1A 30 80 BD E8 05 00 52 E1 05 20 A0 A1 02 30 81 E0 2C 30 84 E5 05 50 62 E0 00 00 55 E3 04 00 A0 E1 EF FF FF CA 01 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule on_exit_a362aea46076d648bf665178a09207ea {
	meta:
		aliases = "on_exit"
		size = "52"
		objfiles = "on_exit@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 30 E0 E3 02 30 A0 13 00 30 80 15 00 30 A0 13 04 40 80 15 08 50 80 15 03 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule significand_5c18abe51ebbf893080427e2e91bccd6 {
	meta:
		aliases = "__GI_significand, significand"
		size = "48"
		objfiles = "s_significand@libm.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 01 50 A0 E1 ?? ?? ?? EB 00 00 60 E2 90 01 00 EE 02 81 2D ED 0C 00 BD E8 04 00 A0 E1 05 10 A0 E1 30 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __pthread_internal_tsd_set_3180982e6d8e66c53a11dfca8625e9a0 {
	meta:
		aliases = "__pthread_internal_tsd_set"
		size = "32"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 01 50 A0 E1 D0 FF FF EB 04 01 80 E0 6C 51 80 E5 00 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule tdestroy_recurse_f026a0ad244c1e904b29e716f3d8decc {
	meta:
		aliases = "tdestroy_recurse"
		size = "64"
		objfiles = "tdestroy@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 04 00 90 E5 00 00 50 E3 01 50 A0 E1 F9 FF FF 1B 08 00 94 E5 00 00 50 E3 05 10 A0 E1 F5 FF FF 1B 00 00 94 E5 0F E0 A0 E1 05 F0 A0 E1 04 00 A0 E1 30 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule _obstack_begin_1_6cc6a3566e631efd231705840218a0d2 {
	meta:
		aliases = "_obstack_begin_1"
		size = "216"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 28 00 D0 E5 01 00 80 E3 28 00 C4 E5 00 00 52 E3 02 50 A0 11 28 00 D4 E5 AC 20 9F E5 04 50 A0 03 03 C0 A0 E1 00 00 51 E3 0C 30 8D E2 08 40 93 E8 02 10 A0 01 01 20 45 E2 01 00 10 E3 20 30 84 E5 18 20 84 E5 1C C0 84 E5 00 10 84 E5 24 E0 84 E5 03 00 00 0A 0E 00 A0 E1 0F E0 A0 E1 0C F0 A0 E1 02 00 00 EA 01 00 A0 E1 0F E0 A0 E1 0C F0 A0 E1 00 00 50 E3 04 00 84 E5 85 00 00 0B 05 20 80 E0 00 10 94 E5 00 30 65 E2 07 20 82 E2 03 20 02 E0 01 10 80 E0 00 30 A0 E3 04 30 80 E5 0C 20 84 E5 08 20 84 E5 00 10 80 E5 28 30 D4 E5 02 30 C3 E3 28 30 C4 E5 28 30 D4 E5 01 00 A0 E3 04 30 C3 E3 }
	condition:
		$pattern
}

rule _obstack_begin_6f3d139ef66c44347bc779adbdb99cdc {
	meta:
		aliases = "_obstack_begin"
		size = "208"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 28 00 D0 E5 01 00 C0 E3 28 00 C4 E5 00 00 52 E3 02 50 A0 11 28 00 D4 E5 A4 20 9F E5 04 50 A0 03 03 C0 A0 E1 00 00 51 E3 0C 30 9D E5 02 10 A0 01 01 20 45 E2 01 00 10 E3 20 30 84 E5 18 20 84 E5 1C C0 84 E5 00 10 84 E5 03 00 00 0A 24 00 94 E5 0F E0 A0 E1 0C F0 A0 E1 02 00 00 EA 01 00 A0 E1 0F E0 A0 E1 0C F0 A0 E1 00 00 50 E3 04 00 84 E5 BB 00 00 0B 05 20 80 E0 00 10 94 E5 00 30 65 E2 07 20 82 E2 03 20 02 E0 01 10 80 E0 00 30 A0 E3 04 30 80 E5 0C 20 84 E5 08 20 84 E5 00 10 80 E5 28 30 D4 E5 02 30 C3 E3 28 30 C4 E5 28 30 D4 E5 01 00 A0 E3 04 30 C3 E3 28 30 C4 E5 10 10 84 E5 }
	condition:
		$pattern
}

rule svcudp_destroy_fa3ab1fa61d55355804cc87f0fe3a8b8 {
	meta:
		aliases = "svcudp_destroy"
		size = "76"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 30 50 90 E5 ?? ?? ?? EB 00 00 94 E5 ?? ?? ?? EB 0C 30 95 E5 1C 30 93 E5 00 00 53 E3 08 00 85 E2 0F E0 A0 11 03 F0 A0 11 2C 00 94 E5 ?? ?? ?? EB 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 30 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __GI_strndup_60b81f81ec4ff4140e4bb5abf0a2e600 {
	meta:
		aliases = "strndup, __GI_strndup"
		size = "60"
		objfiles = "strndup@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 ?? ?? ?? EB 00 50 A0 E1 01 00 80 E2 ?? ?? ?? EB 04 10 A0 E1 00 40 50 E2 05 20 A0 E1 02 00 00 0A ?? ?? ?? EB 00 30 A0 E3 05 30 C4 E7 04 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule pthread_rwlock_wrlock_68e18432522d10e968a6793970fabe94 {
	meta:
		aliases = "pthread_rwlock_wrlock"
		size = "104"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E1 C9 FF FF EB 00 50 A0 E1 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 08 30 94 E5 00 00 53 E3 05 10 A0 E1 14 00 84 E2 02 00 00 1A 0C 30 94 E5 00 00 53 E3 05 00 00 0A 66 FF FF EB 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 EA FF FF EB EE FF FF EA 0C 50 84 E5 04 00 A0 E1 ?? ?? ?? EB 00 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule __md5_Encode_0f0ba023ea43a1610f95d3eaece13e89 {
	meta:
		aliases = "__md5_Encode"
		size = "92"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { 30 40 2D E9 00 40 A0 E3 02 50 A0 E1 04 20 A0 E1 0B 00 00 EA 0C 30 91 E7 04 30 C0 E7 0C 30 91 E7 23 34 A0 E1 01 30 CE E5 0C 30 91 E7 23 38 A0 E1 02 30 CE E5 0C 30 91 E7 23 3C A0 E1 03 30 CE E5 04 40 84 E2 05 00 54 E1 02 C1 A0 E1 04 E0 80 E0 01 20 82 E2 EE FF FF 3A 30 80 BD E8 }
	condition:
		$pattern
}

rule tmpnam_734e01e21039002cd16f3ab7eba3b4d2 {
	meta:
		aliases = "tmpnam"
		size = "120"
		objfiles = "tmpnam@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 50 E2 14 D0 4D E2 05 40 A0 E1 00 20 A0 E3 0D 40 A0 01 14 10 A0 E3 02 30 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 03 10 A0 E3 04 00 A0 E1 0A 00 00 1A ?? ?? ?? EB 00 00 50 E3 07 00 00 1A 00 00 55 E3 04 10 A0 E1 20 00 9F E5 14 20 A0 E3 03 00 00 1A ?? ?? ?? EB 00 50 A0 E1 00 00 00 EA 00 50 A0 E3 05 00 A0 E1 14 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? }
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

rule __pthread_set_own_extricate_if_9980b6c693ad4a309ce9d60c40320ef9 {
	meta:
		aliases = "__pthread_set_own_extricate_if"
		size = "68"
		objfiles = "semaphore@libpthread.a, oldsemaphore@libpthread.a, join@libpthread.a, condvar@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 51 E2 00 40 A0 E1 00 10 A0 E1 03 00 00 0A 40 30 D0 E5 00 00 53 E3 30 80 BD 18 01 00 00 EA 1C 00 90 E5 ?? ?? ?? EB 00 00 55 E3 BC 51 84 E5 30 80 BD 18 1C 00 94 E5 30 40 BD E8 ?? ?? ?? EA }
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

rule __GI_xdr_pmap_912b2e65ee0307eacbbcfe63f84fb1d7 {
	meta:
		aliases = "xdr_pmap, __GI_xdr_pmap"
		size = "88"
		objfiles = "pmap_prot@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 A0 E1 01 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 04 10 84 E2 05 00 A0 E1 0B 00 00 0A ?? ?? ?? EB 00 00 50 E3 08 10 84 E2 05 00 A0 E1 06 00 00 0A ?? ?? ?? EB 00 00 50 E3 0C 10 84 E2 05 00 A0 E1 01 00 00 0A 30 40 BD E8 ?? ?? ?? EA 00 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_mempcpy_5bfbebcf423b35f283059b773f8245b5 {
	meta:
		aliases = "mempcpy, __GI_mempcpy"
		size = "24"
		objfiles = "mempcpy@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 A0 E1 02 40 A0 E1 ?? ?? ?? EB 04 00 85 E0 30 80 BD E8 }
	condition:
		$pattern
}

rule flush_out_4b30cb559aaa33f90134af27eebc94ea {
	meta:
		aliases = "flush_out"
		size = "136"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 A0 E1 10 20 95 E5 18 00 90 E5 01 00 51 E3 02 20 60 E0 02 11 A0 03 00 10 A0 13 04 20 42 E2 01 20 82 E1 FF 38 02 E2 FF 1C 02 E2 23 34 A0 E1 01 14 A0 E1 02 1C 81 E1 22 3C 83 E1 01 30 83 E1 00 30 80 E5 0C 10 85 E2 12 00 91 E8 04 40 61 E0 00 00 95 E5 04 20 A0 E1 0F E0 A0 E1 08 F0 95 E5 04 00 50 E1 00 00 A0 E3 30 80 BD 18 0C 20 95 E5 01 00 A0 E3 04 30 82 E2 10 30 85 E5 18 20 85 E5 30 80 BD E8 }
	condition:
		$pattern
}

rule getlogin_r_edf64525155fd31e02f925dd1e5fd910 {
	meta:
		aliases = "getlogin_r"
		size = "68"
		objfiles = "getlogin@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 A0 E1 30 00 9F E5 01 40 A0 E1 ?? ?? ?? EB 00 10 50 E2 04 20 A0 E1 05 00 A0 E1 00 30 E0 E3 03 00 00 0A ?? ?? ?? EB 04 20 85 E0 00 30 A0 E3 01 30 42 E5 03 00 A0 E1 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule setrpcent_c222a744bb1ca543a69a552aae36afd5 {
	meta:
		aliases = "__GI_setrpcent, setrpcent"
		size = "100"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 A0 E1 52 FF FF EB 00 40 50 E2 30 80 BD 08 00 30 94 E5 00 00 53 E3 38 00 9F E5 38 10 9F E5 02 00 00 1A ?? ?? ?? EB 00 00 84 E5 01 00 00 EA 03 00 A0 E1 ?? ?? ?? EB 04 00 94 E5 ?? ?? ?? EB 0C 30 94 E5 05 30 83 E1 0C 30 84 E5 00 30 A0 E3 04 30 84 E5 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wcsdup_900cee880b3c0dff4d7a7f02c981a784 {
	meta:
		aliases = "wcsdup"
		size = "52"
		objfiles = "wcsdup@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 A0 E1 ?? ?? ?? EB 00 41 A0 E1 04 40 84 E2 04 00 A0 E1 ?? ?? ?? EB 04 20 A0 E1 00 40 50 E2 05 10 A0 E1 ?? ?? ?? 1B 04 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule strdup_f11a110e747f34cad9cc4832af2f9e04 {
	meta:
		aliases = "__GI_strdup, strdup"
		size = "48"
		objfiles = "strdup@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 A0 E1 ?? ?? ?? EB 01 40 80 E2 04 00 A0 E1 ?? ?? ?? EB 04 20 A0 E1 00 40 50 E2 05 10 A0 E1 ?? ?? ?? 1B 04 00 A0 E1 30 80 BD E8 }
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

rule getrpcbynumber_d8448cf638e426c2d712e1647fe238fe {
	meta:
		aliases = "__GI_getrpcbynumber, getrpcbynumber"
		size = "72"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 50 A0 E1 E7 FE FF EB 00 00 50 E3 00 40 A0 01 09 00 00 0A 00 00 A0 E3 ?? ?? ?? EB 02 00 00 EA 08 30 94 E5 05 00 53 E1 02 00 00 0A ?? ?? ?? EB 00 40 50 E2 F9 FF FF 1A ?? ?? ?? EB 04 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_vswprintf_35907b732f45f21f10e732358e6bbb22 {
	meta:
		aliases = "vswprintf, __GI_vswprintf"
		size = "176"
		objfiles = "vswprintf@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 C0 A0 E1 00 00 E0 E1 20 51 A0 E1 50 D0 4D E2 01 00 55 E1 01 50 A0 21 02 10 A0 E1 03 20 A0 E1 02 30 E0 E3 04 30 8D E5 53 30 83 E2 00 E0 A0 E3 05 41 8C E0 00 30 CD E5 0D 00 A0 E1 08 30 A0 E3 01 30 CD E5 20 E0 8D E5 0C 40 8D E5 1C C0 8D E5 02 E0 CD E5 2C E0 8D E5 08 C0 8D E5 10 C0 8D E5 14 C0 8D E5 18 C0 8D E5 ?? ?? ?? EB 10 20 9D E5 0C 30 9D E5 03 00 52 E1 05 00 00 1A 00 00 55 E3 04 30 42 E2 00 00 E0 E3 05 00 00 0A 10 30 8D E5 00 00 E0 E3 00 00 55 E3 10 30 9D 15 00 20 A0 13 00 20 83 15 50 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_strncasecmp_9de7fb1a91f490c857a5c5fc632556c5 {
	meta:
		aliases = "strncasecmp, __GI_strncasecmp"
		size = "140"
		objfiles = "strncasecmp@libc.a"
	strings:
		$pattern = { 30 40 2D E9 00 E0 A0 E1 01 40 A0 E1 02 50 A0 E1 00 00 A0 E3 00 00 55 E3 01 50 45 E2 30 80 BD 08 04 00 5E E1 11 00 00 0A 58 30 9F E5 00 C0 DE E5 00 20 D4 E5 00 30 93 E5 8C C0 A0 E1 82 20 A0 E1 03 00 82 E0 03 10 8C E0 01 10 D1 E5 01 00 D0 E5 03 20 D2 E7 03 30 DC E7 00 0C A0 E1 01 1C A0 E1 41 38 83 E1 40 28 82 E1 02 00 53 E0 30 80 BD 18 00 30 DE E5 00 00 53 E3 01 40 84 E2 01 E0 8E E2 E3 FF FF 1A 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule bsd_signal_44cf72c321bc526d2fc3fd9337b609c1 {
	meta:
		aliases = "__GI_signal, signal, __bsd_signal, bsd_signal"
		size = "184"
		objfiles = "signal@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 00 71 E3 00 00 50 13 46 DF 4D E2 00 40 A0 E1 03 00 00 DA 40 00 50 E3 20 00 A0 D3 8C 10 8D D5 06 00 00 DA ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 1A 00 00 EA 00 30 A0 E3 88 30 02 E5 01 00 50 E2 46 3F 8D E2 00 21 83 E0 F9 FF FF 5A 8C 50 8D E2 04 00 85 E2 04 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 0D 00 00 BA 04 10 A0 E1 3C 00 9F E5 ?? ?? ?? EB 00 00 50 E3 01 32 A0 03 00 30 A0 13 0D 20 A0 E1 05 10 A0 E1 04 00 A0 E1 10 31 8D E5 ?? ?? ?? EB 00 00 50 E3 00 20 9D A5 00 00 00 AA 00 20 E0 E3 02 00 A0 E1 46 DF 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdr_opaque_auth_65de213991f738f8856dab02aa6d0c87 {
	meta:
		aliases = "__GI_xdr_opaque_auth, xdr_opaque_auth"
		size = "48"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 40 A0 E1 00 50 A0 E1 ?? ?? ?? EB 00 00 50 E3 08 20 84 E2 04 10 84 E2 19 3E A0 E3 30 80 BD 08 05 00 A0 E1 30 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __GI_xdr_accepted_reply_1ae566e19030342ad1f302fb6454a359 {
	meta:
		aliases = "xdr_accepted_reply, __GI_xdr_accepted_reply"
		size = "140"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 40 A0 E1 00 50 A0 E1 ?? ?? ?? EB 00 00 50 E3 0C 10 84 E2 05 00 A0 E1 17 00 00 0A ?? ?? ?? EB 00 00 50 E3 14 00 00 0A 0C 30 94 E5 00 00 53 E3 05 00 A0 E1 04 00 00 0A 02 00 53 E3 10 10 84 E2 01 30 A0 E3 05 00 00 0A 0C 00 00 EA 10 10 94 E5 0F E0 A0 E1 14 F0 94 E5 00 30 A0 E1 07 00 00 EA ?? ?? ?? EB 00 00 50 E3 14 10 84 E2 05 00 A0 E1 01 00 00 0A 30 40 BD E8 ?? ?? ?? EA 00 30 A0 E3 03 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_xdr_rejected_reply_7b73d0ecd7b362f3c279bbc43fd9e292 {
	meta:
		aliases = "xdr_rejected_reply, __GI_xdr_rejected_reply"
		size = "108"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 40 A0 E1 00 50 A0 E1 ?? ?? ?? EB 00 00 50 E3 12 00 00 0A 00 30 94 E5 00 00 53 E3 04 10 84 E2 05 00 A0 E1 02 00 00 0A 01 00 53 E3 0B 00 00 1A 06 00 00 EA ?? ?? ?? EB 00 00 50 E3 08 10 84 E2 05 00 A0 E1 05 00 00 0A 30 40 BD E8 ?? ?? ?? EA 05 00 A0 E1 04 10 84 E2 30 40 BD E8 ?? ?? ?? EA 00 00 A0 E3 30 80 BD E8 }
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

rule svcraw_getargs_39c30baa197de0ee4d2accfe41fb16f4 {
	meta:
		aliases = "svcraw_getargs"
		size = "60"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 50 A0 E1 02 40 A0 E1 ?? ?? ?? EB BC 30 90 E5 8E 0D 83 E2 00 00 53 E3 14 00 80 E2 04 10 A0 E1 02 00 00 0A 0F E0 A0 E1 05 F0 A0 E1 00 30 A0 E1 03 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule svcraw_freeargs_406135daf03729f1c682c95e26d3b354 {
	meta:
		aliases = "svcraw_freeargs"
		size = "80"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 50 A0 E1 02 40 A0 E1 ?? ?? ?? EB BC C0 90 E5 8E 0D 8C E2 00 00 5C E3 0C 30 A0 E1 14 00 80 E2 04 10 A0 E1 05 00 00 0A 18 30 9F E5 02 20 A0 E3 03 20 8C E7 0F E0 A0 E1 05 F0 A0 E1 00 30 A0 E1 03 00 A0 E1 30 80 BD E8 94 23 00 00 }
	condition:
		$pattern
}

rule __GI_fdopen_bdaf298785e0c8366a00b1798955f30f {
	meta:
		aliases = "fdopen, __GI_fdopen"
		size = "56"
		objfiles = "fdopen@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 50 A0 E1 03 10 A0 E3 00 40 A0 E1 ?? ?? ?? EB 01 00 70 E3 05 10 A0 E1 04 30 A0 E1 00 20 A0 E3 01 00 00 0A 30 40 BD E8 ?? ?? ?? EA 00 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule __ether_line_w_bd9f4e8578007c601a24745a8be1f551 {
	meta:
		aliases = "__ether_line_w"
		size = "72"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 50 A0 E1 23 10 A0 E3 00 40 A0 E1 ?? ?? ?? EB 00 20 50 E2 0A 10 A0 E3 04 00 A0 E1 02 00 00 1A ?? ?? ?? EB 00 20 50 E2 01 00 00 0A 00 30 A0 E3 00 30 C2 E5 04 00 A0 E1 05 10 A0 E1 30 40 BD E8 BC FF FF EA }
	condition:
		$pattern
}

rule calloc_1cb1b000a03b4bc206cd9fd3a62b8725 {
	meta:
		aliases = "calloc"
		size = "88"
		objfiles = "calloc@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 50 A0 E1 90 05 04 E0 00 10 50 E2 04 00 A0 E1 07 00 00 0A ?? ?? ?? EB 00 00 55 E1 00 50 A0 E3 03 00 00 0A ?? ?? ?? EB 0C 30 A0 E3 00 30 80 E5 05 00 00 EA 04 00 A0 E1 ?? ?? ?? EB 00 50 50 E2 04 20 A0 E1 00 10 A0 E3 ?? ?? ?? 1B 05 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule svcraw_reply_739ed8276c560b72248f3f184b66dde4 {
	meta:
		aliases = "svcraw_reply"
		size = "120"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 50 A0 E1 ?? ?? ?? EB BC 20 90 E5 00 C0 A0 E3 8E 4D 82 E2 14 40 84 E2 0C 00 52 E1 0C 10 A0 E1 04 00 A0 E1 0F 00 00 0A 40 30 9F E5 03 C0 82 E7 04 30 94 E5 0F E0 A0 E1 14 F0 93 E5 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 04 00 A0 E1 04 00 00 0A 04 30 94 E5 0F E0 A0 E1 10 F0 93 E5 01 00 A0 E3 30 80 BD E8 00 00 A0 E3 30 80 BD E8 94 23 00 00 }
	condition:
		$pattern
}

rule svcraw_recv_f6b9d2842873bc7970da62be06dc0be0 {
	meta:
		aliases = "svcraw_recv"
		size = "100"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 50 A0 E1 ?? ?? ?? EB BC C0 90 E5 00 10 A0 E3 8E 4D 8C E2 14 40 84 E2 01 00 5C E1 04 00 A0 E1 0C 30 A0 E1 0A 00 00 0A 2C 20 9F E5 01 30 A0 E3 02 30 8C E7 04 30 94 E5 0F E0 A0 E1 14 F0 93 E5 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 30 50 E2 01 30 A0 13 03 00 A0 E1 30 80 BD E8 94 23 00 00 }
	condition:
		$pattern
}

rule posix_fadvise_e455a1b0ee59e783cfc9a08188469e1b {
	meta:
		aliases = "__libc_posix_fadvise, posix_fadvise"
		size = "56"
		objfiles = "posix_fadvise@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 C0 A0 E1 02 50 A0 E1 02 40 A0 E1 C5 5F A0 E1 01 20 A0 E1 03 10 A0 E1 CC 3F A0 E1 0E 01 90 EF 01 0A 70 E3 00 30 A0 E3 00 30 60 82 03 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule tmpfile64_94df50c9b5b4f031388b939ab141b51b {
	meta:
		aliases = "tmpfile, tmpfile64"
		size = "128"
		objfiles = "tmpfile@libc.a"
	strings:
		$pattern = { 30 40 2D E9 01 DA 4D E2 10 40 8D E2 0F 40 44 E2 5C 10 9F E5 00 20 A0 E3 58 30 9F E5 04 00 A0 E1 ?? ?? ?? EB 00 10 50 E2 04 00 A0 E1 0C 00 00 1A ?? ?? ?? EB 00 50 50 E2 04 00 A0 E1 08 00 00 BA ?? ?? ?? EB 05 00 A0 E1 2C 10 9F E5 ?? ?? ?? EB 00 40 50 E2 05 00 A0 E1 02 00 00 1A ?? ?? ?? EB 00 00 00 EA 00 40 A0 E3 04 00 A0 E1 01 DA 8D E2 30 80 BD E8 FF 0F 00 00 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sigset_c0483896039cf6711b2769124571086f {
	meta:
		aliases = "sigset"
		size = "312"
		objfiles = "sigset@libc.a"
	strings:
		$pattern = { 30 40 2D E9 02 00 51 E3 66 DF 4D E2 00 40 A0 E1 1E 10 81 02 02 00 00 0A 13 00 00 EA 00 30 A0 E3 80 30 02 E5 01 10 51 E2 66 3F 8D E2 01 21 83 E0 F9 FF FF 5A 46 5F 8D E2 04 10 A0 E1 05 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 36 00 00 BA 00 00 A0 E3 00 20 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 02 20 A0 A3 30 00 00 AA 2E 00 00 EA 01 00 71 E3 00 00 50 13 03 00 00 DA 40 00 50 E3 20 00 A0 D3 8C 10 8D D5 06 00 00 DA ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 23 00 00 EA 00 30 A0 E3 08 31 02 E5 01 00 50 E2 66 3F 8D E2 00 21 83 E0 F9 FF FF 5A 8C 10 8D E2 00 30 A0 E3 04 00 A0 E1 0D 20 A0 E1 10 31 8D E5 }
	condition:
		$pattern
}

rule __addvdi3_75492880fa9d1cbab6f1bb377ef5482a {
	meta:
		aliases = "__addvdi3"
		size = "108"
		objfiles = "_addvdi3@libgcc.a"
	strings:
		$pattern = { 30 40 2D E9 02 40 90 E0 03 50 A1 E0 00 00 53 E3 0D 00 00 BA 05 00 51 E1 00 30 A0 E3 06 00 00 DA 01 30 A0 E3 FF 30 03 E2 00 00 53 E3 0D 00 00 1A 04 00 A0 E1 05 10 A0 E1 30 80 BD E8 F8 FF FF 1A 04 00 50 E1 F6 FF FF 9A F4 FF FF EA 01 00 55 E1 00 30 A0 E3 F1 FF FF CA F1 FF FF 1A 00 00 54 E1 EF FF FF 9A ED FF FF EA ?? ?? ?? EB }
	condition:
		$pattern
}

rule clntraw_freeres_f1783c06cfcdfae134e07f10e6810d95 {
	meta:
		aliases = "clntraw_freeres"
		size = "68"
		objfiles = "clnt_raw@libc.a"
	strings:
		$pattern = { 30 40 2D E9 02 40 A0 E1 01 50 A0 E1 ?? ?? ?? EB A0 20 90 E5 00 00 52 E3 0C 00 82 E2 04 10 A0 E1 10 30 A0 E3 04 00 00 0A 02 30 A0 E3 0C 30 82 E5 0F E0 A0 E1 05 F0 A0 E1 00 30 A0 E1 03 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule nrand48_r_f499724f4ea2ed99fb5eb9b521ab20c7 {
	meta:
		aliases = "__GI_nrand48_r, nrand48_r"
		size = "72"
		objfiles = "nrand48_r@libc.a"
	strings:
		$pattern = { 30 40 2D E9 02 50 A0 E1 00 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 E0 E3 30 80 BD B8 03 00 D4 E5 02 30 D4 E5 04 20 D4 E5 05 10 D4 E5 00 34 83 E1 01 24 82 E1 A3 30 A0 E1 82 37 83 E1 00 00 A0 E3 00 30 85 E5 30 80 BD E8 }
	condition:
		$pattern
}

rule jrand48_r_32038e9aed2d6a46b7de8de8c3a738b3 {
	meta:
		aliases = "__GI_jrand48_r, jrand48_r"
		size = "68"
		objfiles = "jrand48_r@libc.a"
	strings:
		$pattern = { 30 40 2D E9 02 50 A0 E1 00 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 E0 E3 30 80 BD B8 03 00 D4 E5 04 20 D4 E5 05 10 D4 E5 02 30 D4 E5 01 24 82 E1 00 34 83 E1 02 38 83 E1 00 00 A0 E3 00 30 85 E5 30 80 BD E8 }
	condition:
		$pattern
}

rule truncate64_39e524ef97bb1c81627e447987e7f096 {
	meta:
		aliases = "truncate64"
		size = "48"
		objfiles = "truncate64@libc.a"
	strings:
		$pattern = { 30 40 2D E9 02 50 A0 E1 C1 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_ftruncate64_f52c4a6802803cf0708c523f25a0dbc5 {
	meta:
		aliases = "ftruncate64, __GI_ftruncate64"
		size = "48"
		objfiles = "ftruncate64@libc.a"
	strings:
		$pattern = { 30 40 2D E9 02 50 A0 E1 C2 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 30 80 BD E8 }
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

rule __ieee754_acosh_750931cb3838d235dc2a0bd79f8d1d89 {
	meta:
		aliases = "__ieee754_acosh"
		size = "256"
		objfiles = "e_acosh@libm.a"
	strings:
		$pattern = { 30 40 2D E9 03 C2 2D ED 03 00 2D E9 02 C1 BD EC E0 30 9F E5 03 00 50 E1 01 50 A0 E1 84 01 24 DE 00 40 A0 E1 80 01 40 DE 05 40 A0 E1 2D 00 00 DA C4 30 9F E5 03 00 50 E1 07 00 00 DA F9 35 83 E2 03 00 50 E1 84 01 04 CE 26 00 00 CA ?? ?? ?? EB 26 91 9F ED 81 01 00 EE 22 00 00 EA 03 31 80 E2 01 36 83 E2 05 30 93 E1 88 81 00 0E 1D 00 00 0A 01 01 50 E3 0E 00 00 DA 84 01 14 EE 89 01 20 EE 02 81 2D ED 03 00 BD E8 ?? ?? ?? EB 89 91 10 EE 80 01 04 EE 80 11 41 EE 84 01 04 EE 81 01 00 EE 02 81 2D ED 03 00 BD E8 03 C2 BD EC 30 40 BD E8 ?? ?? ?? EA 89 41 24 EE 84 01 14 EE 84 11 04 EE 80 11 01 EE 02 91 2D ED }
	condition:
		$pattern
}

rule sethostid_a65a7c78ef92c152e854e3e4d64cf58e {
	meta:
		aliases = "sethostid"
		size = "132"
		objfiles = "hostid@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 00 00 8D E5 ?? ?? ?? EB 00 00 50 E3 05 00 00 1A ?? ?? ?? EB 00 00 50 E3 41 10 A0 E3 69 2F A0 E3 50 00 9F E5 04 00 00 0A ?? ?? ?? EB 01 30 A0 E3 03 40 A0 E1 00 30 80 E5 0B 00 00 EA ?? ?? ?? EB 00 50 50 E2 0D 10 A0 E1 04 20 A0 E3 00 40 E0 E3 05 00 00 BA ?? ?? ?? EB 04 00 50 E3 05 00 A0 E1 00 40 E0 13 00 40 A0 03 ?? ?? ?? EB 04 00 A0 E1 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule nanosleep_84a9844dcfac7fc79dfc2ed874cb5c15 {
	meta:
		aliases = "__GI_nanosleep, nanosleep"
		size = "68"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 00 40 A0 E1 01 50 A0 E1 01 00 A0 E3 0D 10 A0 E1 ?? ?? ?? EB 05 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 10 A0 E3 00 40 A0 E1 00 00 9D E5 ?? ?? ?? EB 04 00 A0 E1 04 D0 8D E2 30 80 BD E8 }
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

rule join_extricate_func_b5e7f65ef83da8fa4c26061ddc8d8909 {
	meta:
		aliases = "join_extricate_func"
		size = "76"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 00 50 A0 E1 DC FF FF EB 00 00 8D E5 00 10 9D E5 05 00 A0 E1 ?? ?? ?? EB 08 20 95 E5 00 30 A0 E3 38 40 92 E5 05 00 A0 E1 38 30 82 E5 ?? ?? ?? EB 00 40 54 E2 01 40 A0 13 04 00 A0 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __GI_xdr_replymsg_4f0812de266f91145e32011ee6355fa7 {
	meta:
		aliases = "xdr_replymsg, __GI_xdr_replymsg"
		size = "108"
		objfiles = "rpc_prot@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 01 40 A0 E1 00 50 A0 E1 ?? ?? ?? EB 00 00 50 E3 04 10 84 E2 05 00 A0 E1 0D 00 00 0A ?? ?? ?? EB 00 00 50 E3 0A 00 00 0A 04 C0 94 E5 01 00 5C E3 05 00 A0 E1 0C 20 84 E2 08 10 84 E2 1C 30 9F E5 03 00 00 1A 00 C0 A0 E3 00 C0 8D E5 ?? ?? ?? EB 00 00 00 EA 00 00 A0 E3 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule initgroups_2e6e0d30a4328d13255e683cb182539d {
	meta:
		aliases = "initgroups"
		size = "76"
		objfiles = "initgroups@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 04 20 8D E2 02 31 E0 E3 04 30 22 E5 0D 20 A0 E1 ?? ?? ?? EB 00 40 50 E2 04 10 A0 E1 00 50 E0 E3 04 00 00 0A 00 00 9D E5 ?? ?? ?? EB 00 50 A0 E1 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 04 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule fgetspent_r_e8080a1c2fc51c486b5e54e9e6df8922 {
	meta:
		aliases = "fgetgrent_r, __GI_fgetpwent_r, __GI_fgetgrent_r, fgetpwent_r, __GI_fgetspent_r, fgetspent_r"
		size = "56"
		objfiles = "fgetgrent_r@libc.a, fgetspent_r@libc.a, fgetpwent_r@libc.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 10 50 9D E5 00 00 8D E5 00 00 A0 E3 00 00 85 E5 14 00 9F E5 01 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 40 85 05 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_reap_children_8c3b405d936dfe9a5b04f24e33681abf {
	meta:
		aliases = "pthread_reap_children"
		size = "312"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 04 D0 4D E2 3E 00 00 EA 14 31 9F E5 00 10 93 E5 00 50 91 E5 24 00 00 EA 14 30 95 E5 00 00 53 E1 00 20 95 E5 1F 00 00 1A 04 30 95 E5 04 30 82 E5 04 30 95 E5 1C 00 95 E5 00 20 83 E5 00 10 A0 E3 ?? ?? ?? EB 9C 31 95 E5 00 00 53 E3 01 30 A0 E3 2E 30 C5 E5 0B 00 00 0A C8 30 9F E5 A0 21 95 E5 00 30 93 E5 02 30 83 E1 02 0B 13 E3 05 00 00 0A 0C 30 A0 E3 A8 31 85 E5 AC 30 9F E5 AC 51 85 E5 00 50 83 E5 ?? ?? ?? EB 2D 40 D5 E5 1C 00 95 E5 ?? ?? ?? EB 00 00 54 E3 05 00 00 0A 05 00 A0 E1 A1 FF FF EB 02 00 00 EA 02 50 A0 E1 01 00 55 E1 D8 FF FF 1A 74 30 9F E5 00 30 93 E5 00 00 53 E3 04 00 00 0A }
	condition:
		$pattern
}

rule __GI_remquo_4572174d2c6bfb40cf820ee017b6dc09 {
	meta:
		aliases = "remquo, __GI_remquo"
		size = "128"
		objfiles = "s_remquo@libm.a"
	strings:
		$pattern = { 30 40 2D E9 06 42 6D ED 0C 00 2D E9 02 D1 BD EC 03 00 2D E9 02 C1 BD EC 03 40 A0 E1 02 30 A0 E1 A3 3F A0 E1 01 20 A0 E1 85 01 44 EE 00 10 A0 E1 A1 0F 53 E1 02 81 2D ED 03 00 BD E8 01 50 A0 03 00 50 E0 13 ?? ?? ?? EB 02 81 2D ED 03 00 BD E8 24 40 9D E5 ?? ?? ?? EB 7F 00 00 E2 90 05 03 E0 02 C1 2D ED 03 00 BD E8 00 30 84 E5 02 D1 2D ED 0C 00 BD E8 06 42 FD EC 30 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule clntudp_destroy_da8435ea74d93eb4f97f84650f0e14f9 {
	meta:
		aliases = "clntudp_destroy"
		size = "72"
		objfiles = "clnt_udp@libc.a"
	strings:
		$pattern = { 30 40 2D E9 08 40 90 E5 04 30 94 E5 00 00 53 E3 00 50 A0 E1 00 00 94 15 ?? ?? ?? 1B 3C 30 94 E5 1C 30 93 E5 00 00 53 E3 38 00 84 E2 0F E0 A0 11 03 F0 A0 11 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 30 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule clnttcp_destroy_f6dc84fa9c2c84c1c2f9b819417a9665 {
	meta:
		aliases = "clnttcp_destroy"
		size = "72"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { 30 40 2D E9 08 40 90 E5 04 30 94 E5 00 00 53 E3 00 50 A0 E1 00 00 94 15 ?? ?? ?? 1B 50 30 94 E5 1C 30 93 E5 00 00 53 E3 4C 00 84 E2 0F E0 A0 11 03 F0 A0 11 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 30 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule clntunix_destroy_b0862b6d756916624de900f315dedde6 {
	meta:
		aliases = "clntunix_destroy"
		size = "72"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { 30 40 2D E9 08 40 90 E5 04 30 94 E5 00 00 53 E3 00 50 A0 E1 00 00 94 15 ?? ?? ?? 1B B0 30 94 E5 1C 30 93 E5 00 00 53 E3 AC 00 84 E2 0F E0 A0 11 03 F0 A0 11 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 30 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule xdr_authunix_parms_9feb69bc0faf943160f8f37e380a6620 {
	meta:
		aliases = "__GI_xdr_authunix_parms, xdr_authunix_parms"
		size = "156"
		objfiles = "authunix_prot@libc.a"
	strings:
		$pattern = { 30 40 2D E9 08 D0 4D E2 01 40 A0 E1 00 50 A0 E1 ?? ?? ?? EB 00 00 50 E3 FF 20 A0 E3 04 10 84 E2 05 00 A0 E1 18 00 00 0A ?? ?? ?? EB 00 00 50 E3 08 10 84 E2 05 00 A0 E1 13 00 00 0A ?? ?? ?? EB 00 00 50 E3 0C 10 84 E2 05 00 A0 E1 0E 00 00 0A ?? ?? ?? EB 00 00 50 E3 10 20 84 E2 14 10 84 E2 10 30 A0 E3 05 00 A0 E1 07 00 00 0A 04 C0 A0 E3 00 C0 8D E5 1C C0 9F E5 04 C0 8D E5 ?? ?? ?? EB 00 00 50 E2 01 00 A0 13 00 00 00 EA 00 00 A0 E3 08 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_sendto_de6e362ba4aa771db66e18563e83195b {
	meta:
		aliases = "sendto, __libc_sendto, __GI_sendto"
		size = "52"
		objfiles = "sendto@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C 40 8D E2 30 00 94 E8 22 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule __libc_recvfrom_d67f0efab76e72f4fa9dd3edf6f4619e {
	meta:
		aliases = "recvfrom, __GI_recvfrom, __libc_recvfrom"
		size = "52"
		objfiles = "recvfrom@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C 40 8D E2 30 00 94 E8 24 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule splice_7acbbb3428e21670d469cb9485dc59cf {
	meta:
		aliases = "__GI_splice, splice"
		size = "52"
		objfiles = "splice@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C 40 8D E2 30 00 94 E8 54 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule __syscall_ipc_697c90781d24fe18dc024af22e987bb5 {
	meta:
		aliases = "__syscall_ipc"
		size = "52"
		objfiles = "__syscall_ipc@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C 40 8D E2 30 00 94 E8 75 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule xdrrec_getpos_a79d552106c66f3a61d3eda3bef5bdd1 {
	meta:
		aliases = "xdrrec_getpos"
		size = "108"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C 40 90 E5 01 20 A0 E3 00 50 A0 E1 00 10 A0 E3 00 00 94 E5 ?? ?? ?? EB 01 00 70 E3 00 20 A0 E1 30 80 BD 08 00 00 95 E5 00 00 50 E3 03 00 00 0A 01 00 50 E3 00 00 E0 E3 30 80 BD 18 04 00 00 EA 10 10 84 E2 0A 00 11 E8 01 30 43 E0 03 00 82 E0 30 80 BD E8 30 10 84 E2 0A 00 11 E8 01 30 43 E0 02 00 63 E0 30 80 BD E8 }
	condition:
		$pattern
}

rule xdrrec_putlong_a32ae3f72c47870d7f5491a1013cd3e8 {
	meta:
		aliases = "xdrrec_putlong"
		size = "128"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C 40 90 E5 10 C0 94 E5 14 30 94 E5 04 20 8C E2 03 00 52 E1 01 50 A0 E1 04 00 A0 E1 0C E0 A0 E1 00 10 A0 E3 10 20 84 E5 08 00 00 9A 01 30 A0 E3 10 C0 84 E5 1C 30 84 E5 89 FF FF EB 00 00 50 E3 30 80 BD 08 10 E0 94 E5 04 30 8E E2 10 30 84 E5 00 30 95 E5 FF 28 03 E2 FF 1C 03 E2 22 24 A0 E1 01 14 A0 E1 03 1C 81 E1 23 2C 82 E1 01 20 82 E1 01 00 A0 E3 00 20 8E E5 30 80 BD E8 }
	condition:
		$pattern
}

rule xdrrec_putint32_cfbf6666bb921308d618a711197c576e {
	meta:
		aliases = "xdrrec_putint32"
		size = "128"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C 40 90 E5 10 C0 94 E5 14 30 94 E5 04 20 8C E2 03 00 52 E1 01 50 A0 E1 04 00 A0 E1 0C E0 A0 E1 00 10 A0 E3 10 20 84 E5 08 00 00 9A 01 30 A0 E3 10 C0 84 E5 1C 30 84 E5 A9 FF FF EB 00 00 50 E3 30 80 BD 08 10 E0 94 E5 04 30 8E E2 10 30 84 E5 00 30 95 E5 FF 28 03 E2 FF 1C 03 E2 22 24 A0 E1 01 14 A0 E1 03 1C 81 E1 23 2C 82 E1 01 20 82 E1 01 00 A0 E3 00 20 8E E5 30 80 BD E8 }
	condition:
		$pattern
}

rule __ieee754_j1_4c6be46fbeb87b69fe9edbd49ddd3aee {
	meta:
		aliases = "__ieee754_j1"
		size = "536"
		objfiles = "e_j1@libm.a"
	strings:
		$pattern = { 30 40 2D E9 0C 42 2D ED 00 32 9F E5 02 41 C0 E3 03 00 54 E1 08 D0 4D E2 03 00 2D E9 02 C1 BD EC 00 50 A0 E1 89 01 54 CE 5F 00 00 CA 07 01 74 E3 37 00 00 DA ?? ?? ?? EB 02 81 2D ED 03 00 BD E8 80 D1 00 EE ?? ?? ?? EB 02 D1 2D ED 03 00 BD E8 80 E1 00 EE ?? ?? ?? EB B4 31 9F E5 80 C1 00 EE 86 81 10 EE 84 01 20 EE 03 00 54 E1 00 81 8D ED 84 71 26 EE 0A 00 00 CA 85 01 05 EE 02 81 2D ED 03 00 BD E8 ?? ?? ?? EB 80 91 00 EE 84 01 16 EE 18 F1 D0 EE 00 81 9D CD 87 11 41 DE 00 91 8D DD 80 71 41 CE 12 03 54 E3 06 00 00 DA 02 D1 2D ED 03 00 BD E8 ?? ?? ?? EB 3E 91 9F ED 81 11 17 EE 80 01 41 EE 0F 00 00 EA }
	condition:
		$pattern
}

rule erfc_7592dce513585da97601110f839093a0 {
	meta:
		aliases = "__GI_erfc, erfc"
		size = "1468"
		objfiles = "s_erf@libm.a"
	strings:
		$pattern = { 30 40 2D E9 0C 42 2D ED 8C 35 9F E5 02 41 C0 E3 03 00 54 E1 08 D0 4D E2 03 00 2D E9 02 C1 BD EC 00 50 A0 E1 05 00 00 DA A0 3F A0 E1 83 30 A0 E1 90 31 01 EE 89 01 54 EE 80 01 01 EE E3 00 00 EA 58 35 9F E5 03 00 54 E1 2A 00 00 CA 50 35 9F E5 03 00 54 E1 89 01 34 DE DC 00 00 DA DE 81 9F ED DF 91 9F ED 84 21 14 EE 80 01 12 EE 81 01 00 EE DD 91 9F ED DE B1 9F ED 81 11 12 EE 83 11 21 EE DD B1 9F ED 80 01 12 EE 83 01 00 EE DC B1 9F ED 81 11 12 EE 83 11 21 EE DB B1 9F ED 80 01 12 EE 83 01 00 EE DA B1 9F ED 81 11 12 EE 83 11 21 EE D9 B1 9F ED 80 01 12 EE 83 01 00 EE 80 01 12 EE 81 21 12 EE D6 91 9F ED }
	condition:
		$pattern
}

rule __GI_erf_1f5cb9f4551384dbb52bd9942a7f42bb {
	meta:
		aliases = "erf, __GI_erf"
		size = "1492"
		objfiles = "s_erf@libm.a"
	strings:
		$pattern = { 30 40 2D E9 0C 42 2D ED AC 35 9F E5 02 41 C0 E3 03 00 54 E1 08 D0 4D E2 03 00 2D E9 02 C1 BD EC 00 50 A0 E1 05 00 00 DA A0 3F A0 E1 83 30 A0 E1 01 30 63 E2 90 31 01 EE 89 01 54 EE 60 00 00 EA 78 35 9F E5 03 00 54 E1 2F 00 00 CA 70 35 9F E5 03 00 54 E1 0B 00 00 CA 02 05 54 E3 DE 81 9F BD DF 91 9F BD 80 01 14 BE 81 11 14 BE DE 81 9F AD 80 11 01 BE DE 81 9F BD 80 01 14 AE 80 01 11 BE 80 01 04 AE D1 00 00 EA DB 81 9F ED DC A1 9F ED 84 11 14 EE 80 01 11 EE 82 01 00 EE DA A1 9F ED DB B1 9F ED 82 21 11 EE 83 21 22 EE DA B1 9F ED 80 01 11 EE 83 01 00 EE D9 B1 9F ED 82 21 11 EE 83 21 22 EE D8 B1 9F ED }
	condition:
		$pattern
}

rule binary_search_unencoded_fdes_9a636fe3952ab30d437bb9e0d8031225 {
	meta:
		aliases = "binary_search_unencoded_fdes"
		size = "100"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { 30 40 2D E9 0C 50 90 E5 04 E0 95 E5 00 00 5E E3 01 40 A0 E1 10 00 00 0A 00 10 A0 E3 01 20 8E E0 A2 C0 A0 E1 0C 31 A0 E1 05 30 83 E0 08 00 93 E5 08 20 80 E2 0C 00 92 E8 04 00 52 E1 0C E0 A0 81 03 20 82 E0 02 00 00 8A 02 00 54 E1 30 80 BD 38 01 10 8C E2 0E 00 51 E1 EF FF FF 3A 00 00 A0 E3 30 80 BD E8 }
	condition:
		$pattern
}

rule getservbyname_8894c0d3716609475f368b4191e0ec9e {
	meta:
		aliases = "getservbyname"
		size = "84"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C D0 4D E2 00 40 A0 E1 01 50 A0 E1 62 FE FF EB 2C C0 9F E5 2C 30 9F E5 04 00 A0 E1 00 30 93 E5 05 10 A0 E1 00 C0 8D E5 1C 20 9F E5 08 C0 8D E2 04 C0 8D E5 ?? ?? ?? EB 08 00 9D E5 0C D0 8D E2 30 80 BD E8 8D 10 00 00 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_getservbyport_0331118864bbe09fbe9dc8dfcf44cb57 {
	meta:
		aliases = "getservbyport, __GI_getservbyport"
		size = "84"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { 30 40 2D E9 0C D0 4D E2 00 40 A0 E1 01 50 A0 E1 C0 FE FF EB 2C C0 9F E5 2C 30 9F E5 04 00 A0 E1 00 30 93 E5 05 10 A0 E1 00 C0 8D E5 1C 20 9F E5 08 C0 8D E2 04 C0 8D E5 ?? ?? ?? EB 08 00 9D E5 0C D0 8D E2 30 80 BD E8 8D 10 00 00 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __new_sem_wait_10a52235a3adb3515b6c05c277329238 {
	meta:
		aliases = "sem_wait, __new_sem_wait"
		size = "320"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 0C D0 4D E2 00 40 A0 E1 5D FF FF EB 24 31 9F E5 08 00 8D E5 08 10 9D E5 04 00 A0 E1 04 30 8D E5 00 40 8D E5 ?? ?? ?? EB 08 30 94 E5 00 00 53 E3 04 00 00 DA 01 30 43 E2 08 30 84 E5 04 00 A0 E1 ?? ?? ?? EB 38 00 00 EA 08 20 9D E5 00 30 A0 E3 BA 31 C2 E5 08 00 9D E5 0D 10 A0 E1 F1 FE FF EB 08 30 9D E5 42 30 D3 E5 00 00 53 E3 04 00 00 0A 08 30 9D E5 40 30 D3 E5 00 00 53 E3 01 50 A0 03 03 00 00 0A 08 10 9D E5 0C 00 84 E2 C5 FE FF EB 00 50 A0 E3 04 00 A0 E1 ?? ?? ?? EB 00 00 55 E3 03 00 00 0A 08 00 9D E5 00 10 A0 E3 DD FE FF EB 1A 00 00 EA 08 00 9D E5 62 FF FF EB 08 30 9D E5 BA 31 D3 E5 }
	condition:
		$pattern
}

rule encrypt_0e5f258e8cd4d25e88d70fca287f9c4f {
	meta:
		aliases = "encrypt"
		size = "248"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { 30 40 2D E9 0C D0 4D E2 00 50 A0 E1 01 40 A0 E1 85 FC FF EB 00 00 A0 E3 BB FD FF EB 05 10 A0 E1 00 E0 A0 E3 13 00 00 EA 00 20 A0 E3 0C C0 8D E2 0E 31 8C E0 02 00 A0 E1 08 20 03 E5 08 00 00 EA 00 30 D1 E5 01 00 13 E3 A4 30 9F 15 00 21 93 17 08 30 1C 15 02 30 83 11 08 30 0C 15 01 10 81 E2 01 00 80 E2 0C 30 8D E2 1F 00 50 E3 0E C1 83 E0 F2 FF FF DA 01 E0 8E E2 01 00 5E E3 E9 FF FF DA 00 00 54 E3 04 20 8D E2 01 C0 A0 03 00 C0 E0 13 03 00 9D E9 04 30 82 E2 00 C0 8D E5 A6 FE FF EB 00 C0 A0 E3 0D 00 00 EA 44 30 9F E5 01 21 93 E7 08 30 10 E5 02 00 13 E1 00 30 A0 03 01 30 A0 13 0E 30 C5 E7 01 10 81 E2 }
	condition:
		$pattern
}

rule pthread_rwlock_rdlock_f776fc7ec629abcc999e39a3d2c63192 {
	meta:
		aliases = "pthread_rwlock_rdlock"
		size = "220"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 0C D0 4D E2 0C 30 8D E2 00 20 A0 E3 04 20 23 E5 00 40 A0 E1 04 10 A0 E1 03 00 A0 E1 04 20 8D E2 0D 30 A0 E1 8F FF FF EB 00 50 A0 E1 08 30 9D E5 00 00 53 E3 01 00 00 1A 3D FF FF EB 08 00 8D E5 04 00 A0 E1 08 10 9D E5 ?? ?? ?? EB 04 00 A0 E1 05 10 A0 E1 EC FE FF EB 00 00 50 E3 10 00 84 E2 06 00 00 1A 08 10 9D E5 DB FE FF EB 04 00 A0 E1 ?? ?? ?? EB 08 00 9D E5 5F FF FF EB EA FF FF EA 08 30 94 E5 01 30 83 E2 08 30 84 E5 04 00 A0 E1 ?? ?? ?? EB 00 00 55 E3 02 00 00 1A 00 30 9D E5 00 00 53 E3 08 00 00 0A 04 20 9D E5 00 00 52 E3 08 20 9D 05 08 30 92 15 C8 31 92 05 01 30 83 12 01 30 83 02 }
	condition:
		$pattern
}

rule __GI_putc_unlocked_5e36d1201230a94a099b0e739248355a {
	meta:
		aliases = "__fputc_unlocked, __GI___fputc_unlocked, fputc_unlocked, putc_unlocked, __GI_putc_unlocked"
		size = "260"
		objfiles = "fputc_unlocked@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 20 91 E5 1C 30 91 E5 03 00 52 E1 04 D0 4D E2 01 40 A0 E1 00 50 A0 E1 FF 30 00 32 01 30 C2 34 03 00 A0 31 10 20 81 35 32 00 00 3A 00 30 D1 E5 C0 30 03 E2 C0 00 53 E3 04 00 00 0A 01 00 A0 E1 80 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 28 00 00 1A 04 30 94 E5 02 00 73 E3 23 00 00 0A 0C 20 94 E5 08 30 94 E5 03 00 52 E1 18 00 00 0A 10 30 94 E5 03 00 52 E1 03 00 00 1A 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 1A 00 00 1A 10 20 94 E5 FF 10 05 E2 01 10 C2 E4 01 30 D4 E5 01 00 13 E3 10 20 84 E5 11 00 00 0A 0A 00 51 E3 0F 00 00 1A 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 0B 00 00 0A 10 30 94 E5 00 00 E0 E3 }
	condition:
		$pattern
}

rule dlinfo_bff091877090048aa3c2a8b64ec10334 {
	meta:
		aliases = "dlinfo"
		size = "324"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 30 40 2D E9 10 31 9F E5 10 D0 4D E2 00 00 93 E5 08 11 9F E5 ?? ?? ?? EB 04 31 9F E5 00 40 93 E5 0F 00 00 EA 1C 20 94 E5 00 00 90 E5 00 20 8D E5 F0 20 9F E5 18 C0 94 E5 0C 21 92 E7 04 20 8D E5 20 20 D4 E5 21 C0 D4 E5 0C 24 82 E1 08 20 8D E5 04 20 94 E5 0C 20 8D E5 00 20 94 E5 ?? ?? ?? EB 0C 40 94 E5 00 00 54 E3 04 30 A0 E1 B8 10 9F E5 A4 00 9F E5 EA FF FF 1A B0 40 9F E5 00 00 90 E5 00 20 94 E5 A8 10 9F E5 ?? ?? ?? EB 00 40 94 E5 05 00 00 EA 00 20 94 E5 7C 30 9F E5 00 00 93 E5 04 30 92 E5 ?? ?? ?? EB 10 40 94 E5 00 00 54 E3 80 10 9F E5 F6 FF FF 1A 7C 30 9F E5 00 50 93 E5 10 00 00 EA 50 30 9F E5 }
	condition:
		$pattern
}

rule __GI_getttyent_9bf29823776265be86c1259e0239990b {
	meta:
		aliases = "getttyent, __GI_getttyent"
		size = "848"
		objfiles = "getttyent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 33 9F E5 00 30 93 E5 00 00 53 E3 10 D0 4D E2 03 00 00 1A ?? ?? ?? EB 00 00 50 E3 00 40 A0 01 B9 00 00 0A F0 42 9F E5 00 30 94 E5 00 00 53 E3 04 00 00 1A 01 0A A0 E3 ?? ?? ?? EB 00 00 50 E3 00 00 84 E5 ?? ?? ?? 0B C8 42 9F E5 00 20 94 E5 0D 00 A0 E1 C4 32 9F E5 38 20 82 E2 C0 12 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 94 E5 B4 32 9F E5 38 00 80 E2 0F E0 A0 E1 03 F0 A0 E1 98 32 9F E5 00 40 93 E5 8C 32 9F E5 04 00 A0 E1 00 20 93 E5 01 1A A0 E3 ?? ?? ?? EB 00 00 50 E3 87 00 00 0A 04 00 A0 E1 0A 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 0F 00 00 1A 5C 32 9F E5 00 00 93 E5 10 20 90 E5 18 30 90 E5 }
	condition:
		$pattern
}

rule __GI_mmap_d3c0b01bd45f8974e1139b28aec5a6b5 {
	meta:
		aliases = "mmap, __GI_mmap"
		size = "96"
		objfiles = "mmap@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 50 9D E5 05 CA A0 E1 2C CA A0 E1 00 00 5C E3 25 56 A0 E1 0C 40 9D E5 04 00 00 0A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 08 00 00 EA C0 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 20 A0 E1 02 00 A0 E1 30 80 BD E8 }
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

rule pututline_9ec301a4e7bf21b80730c04d9b1ce187 {
	meta:
		aliases = "pututline"
		size = "200"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 D0 4D E2 00 40 A0 E1 98 50 9F E5 0D 00 A0 E1 94 10 9F E5 94 20 9F E5 94 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 8C 30 9F E5 80 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 80 10 9F E5 01 20 A0 E3 00 00 95 E5 ?? ?? ?? EB 04 00 A0 E1 C3 FF FF EB 00 00 50 E3 00 00 95 15 60 10 9F E5 01 20 A0 E3 00 10 A0 01 02 20 A0 03 00 00 95 05 ?? ?? ?? EB 34 30 9F E5 04 10 A0 E1 06 2D A0 E3 00 00 93 E5 ?? ?? ?? EB 01 10 A0 E3 06 0D 50 E3 30 30 9F E5 0D 00 A0 E1 00 40 A0 13 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 FE FF FF ?? ?? ?? ?? }
	condition:
		$pattern
}

rule gethostbyname2_160ec223c9c4d79064784e46f5ba03a9 {
	meta:
		aliases = "gethostbyname2"
		size = "80"
		objfiles = "gethostbyname2@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 D0 4D E2 00 50 A0 E1 01 40 A0 E1 ?? ?? ?? EB 76 CF A0 E3 08 00 8D E5 00 C0 8D E5 04 10 A0 E1 0C C0 8D E2 05 00 A0 E1 14 20 9F E5 14 30 9F E5 04 C0 8D E5 ?? ?? ?? EB 0C 00 9D E5 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getutline_ae64c2d477524651127d323ff8bcfa71 {
	meta:
		aliases = "getutline"
		size = "172"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 D0 4D E2 00 50 A0 E1 80 10 9F E5 0D 00 A0 E1 7C 20 9F E5 7C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 74 30 9F E5 68 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 07 00 00 EA 00 30 94 E5 06 30 43 E2 03 38 A0 E1 01 08 53 E3 02 00 00 8A ?? ?? ?? EB 00 00 50 E3 06 00 00 0A 44 30 9F E5 00 00 93 E5 23 FF FF EB 00 40 50 E2 08 10 85 E2 08 00 84 E2 F0 FF FF 1A 0D 00 A0 E1 01 10 A0 E3 24 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __close_nameservers_c8ee15459268ecf11b5b7490a893296e {
	meta:
		aliases = "__close_nameservers"
		size = "216"
		objfiles = "closenameservers@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 D0 4D E2 0D 00 A0 E1 A0 10 9F E5 A0 20 9F E5 A0 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 98 30 9F E5 8C 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 00 EA 02 01 95 E7 00 20 84 E5 ?? ?? ?? EB 00 20 94 E5 00 30 A0 E3 02 31 85 E7 70 40 9F E5 00 30 94 E5 00 00 53 E3 68 50 9F E5 01 20 43 E2 F3 FF FF CA 05 00 00 EA 02 01 95 E7 00 20 84 E5 ?? ?? ?? EB 00 20 94 E5 00 30 A0 E3 02 31 85 E7 44 40 9F E5 00 30 94 E5 00 00 53 E3 3C 50 9F E5 01 20 43 E2 F3 FF FF CA 0D 00 A0 E1 01 10 A0 E3 2C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule endutent_0be14356bed1dbf2936e54671d4647db {
	meta:
		aliases = "endutent"
		size = "128"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 D0 4D E2 58 10 9F E5 58 20 9F E5 0D 00 A0 E1 54 30 9F E5 54 50 9F E5 0F E0 A0 E1 03 F0 A0 E1 40 00 9F E5 48 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 95 E5 01 00 70 E3 0D 40 A0 E1 ?? ?? ?? 1B 00 30 E0 E3 00 30 85 E5 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule endgrent_26d84ecd9db75c977707e547326f681c {
	meta:
		aliases = "endspent, endpwent, endgrent"
		size = "132"
		objfiles = "getpwent_r@libc.a, getspent_r@libc.a, getgrent_r@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 D0 4D E2 5C 10 9F E5 5C 20 9F E5 0D 00 A0 E1 58 30 9F E5 58 40 9F E5 0F E0 A0 E1 03 F0 A0 E1 50 30 9F E5 40 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 94 E5 00 00 53 E2 0D 50 A0 E1 02 00 00 0A ?? ?? ?? EB 00 30 A0 E3 00 30 84 E5 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule setstate_92fe32697601f286b472ee939275e8c4 {
	meta:
		aliases = "setstate"
		size = "140"
		objfiles = "random@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 D0 4D E2 64 20 9F E5 00 40 A0 E1 60 10 9F E5 0D 00 A0 E1 5C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 54 30 9F E5 44 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 48 30 9F E5 04 00 A0 E1 03 10 A0 E1 08 40 93 E5 ?? ?? ?? EB 01 10 A0 E3 00 00 50 E3 30 30 9F E5 0D 00 A0 E1 00 50 A0 E3 04 50 44 A2 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule endservent_d73a3e7b18aaff50f7cc98d100b071b3 {
	meta:
		aliases = "endnetent, __GI_endservent, endprotoent, __GI_endnetent, __GI_endprotoent, endservent"
		size = "148"
		objfiles = "getnetent@libc.a, getproto@libc.a, getservice@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 D0 4D E2 68 10 9F E5 68 20 9F E5 0D 00 A0 E1 64 30 9F E5 64 40 9F E5 0F E0 A0 E1 03 F0 A0 E1 5C 30 9F E5 4C 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 94 E5 00 00 53 E2 0D 50 A0 E1 02 00 00 0A ?? ?? ?? EB 00 30 A0 E3 00 30 84 E5 34 20 9F E5 00 30 A0 E3 00 30 82 E5 0D 00 A0 E1 01 10 A0 E3 24 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clearenv_1dc599249d8001f135df6f27a5eb6d43 {
	meta:
		aliases = "clearenv"
		size = "164"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 D0 4D E2 78 20 9F E5 78 10 9F E5 0D 00 A0 E1 74 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 6C 30 9F E5 5C 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 60 40 9F E5 60 30 9F E5 00 20 93 E5 00 30 94 E5 03 00 52 E1 00 50 A0 E3 04 00 00 1A 05 00 52 E1 02 00 A0 E1 01 00 00 0A ?? ?? ?? EB 00 50 84 E5 34 30 9F E5 0D 00 A0 E1 00 50 83 E5 01 10 A0 E3 28 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule setprotoent_54c1f17efcefbf29ba739962a0fb0528 {
	meta:
		aliases = "setnetent, __GI_setnetent, __GI_setprotoent, setservent, __GI_setservent, setprotoent"
		size = "176"
		objfiles = "getnetent@libc.a, getproto@libc.a, getservice@libc.a"
	strings:
		$pattern = { 30 40 2D E9 10 D0 4D E2 7C 10 9F E5 7C 20 9F E5 7C 30 9F E5 00 50 A0 E1 78 40 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 6C 30 9F E5 5C 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 94 E5 00 00 53 E3 58 00 9F E5 58 10 9F E5 02 00 00 1A ?? ?? ?? EB 00 00 84 E5 01 00 00 EA 03 00 A0 E1 ?? ?? ?? EB 00 00 55 E3 3C 30 9F 15 01 10 A0 E3 01 20 A0 11 00 20 83 15 0D 00 A0 E1 2C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
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

rule xdrmem_putbytes_e2259bad09aaed5faef41b21f36b90ab {
	meta:
		aliases = "xdrmem_putbytes"
		size = "64"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { 30 40 2D E9 14 30 90 E5 02 00 53 E1 00 40 A0 E1 02 50 A0 E1 03 C0 62 E0 00 00 A0 E3 30 80 BD 38 14 C0 84 E5 0C 00 94 E5 ?? ?? ?? EB 0C 30 94 E5 01 00 A0 E3 05 30 83 E0 0C 30 84 E5 30 80 BD E8 }
	condition:
		$pattern
}

rule xdrmem_getbytes_b98fde0bdb6fa2bb52202868dc932985 {
	meta:
		aliases = "xdrmem_getbytes"
		size = "72"
		objfiles = "xdr_mem@libc.a"
	strings:
		$pattern = { 30 40 2D E9 14 30 90 E5 02 00 53 E1 00 40 A0 E1 03 C0 62 E0 02 50 A0 E1 00 30 A0 E3 01 00 A0 E1 06 00 00 3A 14 C0 84 E5 0C 10 94 E5 ?? ?? ?? EB 0C 30 94 E5 05 30 83 E0 0C 30 84 E5 01 30 A0 E3 03 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule pclose_db63fa72dc5197aecc015b0fd4f3f979 {
	meta:
		aliases = "pclose"
		size = "256"
		objfiles = "popen@libc.a"
	strings:
		$pattern = { 30 40 2D E9 14 D0 4D E2 D8 20 9F E5 D8 10 9F E5 D8 30 9F E5 00 50 A0 E1 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 BC 00 9F E5 C4 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 BC 20 9F E5 00 40 92 E5 00 00 54 E3 0F 00 00 0A 09 00 00 EA ?? ?? ?? EB 16 30 A0 E3 00 30 80 E5 0A 00 00 EA 10 00 9D E5 1F 00 00 EA 04 20 A0 E1 00 40 94 E5 00 00 54 E3 F5 FF FF 0A 04 30 94 E5 05 00 53 E1 F8 FF FF 1A 00 30 94 E5 00 30 82 E5 0D 00 A0 E1 01 10 A0 E3 68 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 54 E3 0E 00 00 0A 04 00 A0 E1 08 40 94 E5 ?? ?? ?? EB 05 00 A0 E1 ?? ?? ?? EB 10 10 8D E2 00 20 A0 E3 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 }
	condition:
		$pattern
}

rule __GI_readdir_00cd576b798c28e85c94595c25879519 {
	meta:
		aliases = "readdir, __GI_readdir"
		size = "208"
		objfiles = "readdir@libc.a"
	strings:
		$pattern = { 30 40 2D E9 18 40 80 E2 10 D0 4D E2 AC 30 9F E5 00 50 A0 E1 A8 10 9F E5 0D 00 A0 E1 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 94 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 0C 00 95 E9 02 00 53 E1 09 00 00 8A 00 00 95 E5 0C 10 95 E5 14 20 95 E5 ?? ?? ?? EB 00 00 50 E3 00 40 A0 D3 0F 00 00 DA 00 30 A0 E3 04 30 85 E5 08 00 85 E5 04 20 95 E5 0C C0 95 E5 0C 40 82 E0 04 10 94 E5 08 30 D4 E5 09 00 D4 E5 10 10 85 E5 0C 10 92 E7 00 34 83 E1 03 20 82 E0 00 00 51 E3 04 20 85 E5 E5 FF FF 0A 0D 00 A0 E1 01 10 A0 E3 1C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule readdir64_392797c42c7ac28aac6bd1ce6ed241be {
	meta:
		aliases = "__GI_readdir64, readdir64"
		size = "212"
		objfiles = "readdir64@libc.a"
	strings:
		$pattern = { 30 40 2D E9 18 40 80 E2 10 D0 4D E2 B0 30 9F E5 00 50 A0 E1 AC 10 9F E5 0D 00 A0 E1 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 98 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 0C 00 95 E9 02 00 53 E1 09 00 00 8A 00 00 95 E5 0C 10 95 E5 14 20 95 E5 ?? ?? ?? EB 00 00 50 E3 00 40 A0 D3 10 00 00 DA 00 30 A0 E3 04 30 85 E5 08 00 85 E5 04 20 95 E5 0C 10 95 E5 01 40 82 E0 11 00 D4 E5 10 30 D4 E5 01 C0 92 E7 04 10 94 E5 00 34 83 E1 08 00 94 E5 03 20 82 E0 01 C0 9C E1 04 20 85 E5 10 00 85 E5 E4 FF FF 0A 0D 00 A0 E1 01 10 A0 E3 1C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _ppfs_prepargs_54e2295bb6eaffd26d3c5af4cd41f4fb {
	meta:
		aliases = "_ppfs_prepargs"
		size = "56"
		objfiles = "_ppfs_prepargs@libc.a"
	strings:
		$pattern = { 30 40 2D E9 18 50 90 E5 00 30 A0 E3 03 00 55 E1 00 40 A0 E1 4C 10 80 E5 30 80 BD D8 08 30 80 E5 1C 50 80 E5 18 30 80 E5 04 30 80 E5 ?? ?? ?? EB 18 50 84 E5 30 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_manager_event_ffb66d78a1d226ccee50a4d5d799fc07 {
	meta:
		aliases = "__pthread_manager_event"
		size = "44"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 1C 40 9F E5 00 50 A0 E1 00 10 A0 E3 1C 00 94 E5 ?? ?? ?? EB 1C 00 94 E5 ?? ?? ?? EB 05 00 A0 E1 ?? ?? ?? EB ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _create_xid_3b7df83216c7533bd24e5fe54c356778 {
	meta:
		aliases = "_create_xid"
		size = "176"
		objfiles = "create_xid@libc.a"
	strings:
		$pattern = { 30 40 2D E9 1C D0 4D E2 84 10 9F E5 84 20 9F E5 0D 00 A0 E1 80 30 9F E5 80 40 9F E5 0F E0 A0 E1 03 F0 A0 E1 78 30 9F E5 68 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 94 E5 00 10 53 E2 0D 50 A0 E1 10 00 8D E2 07 00 00 1A ?? ?? ?? EB 10 30 9D E5 14 00 9D E5 4C 10 9F E5 00 00 23 E0 ?? ?? ?? EB 01 30 A0 E3 00 30 84 E5 18 10 8D E2 34 00 9F E5 ?? ?? ?? EB 0D 00 A0 E1 01 10 A0 E3 28 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 18 00 9D E5 1C D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sigwait_c42ec84a811252ea212ea3cfdc224bba {
	meta:
		aliases = "sigwait"
		size = "368"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 1F DE 4D E2 5B 4F 8D E2 00 10 8D E5 00 50 A0 E1 54 FF FF EB 00 30 A0 E1 04 00 A0 E1 EC 31 8D E5 ?? ?? ?? EB 2C 31 9F E5 04 00 A0 E1 00 10 93 E5 ?? ?? ?? EB 01 40 A0 E3 20 00 00 EA ?? ?? ?? EB 00 00 50 E3 1C 00 00 0A 0C 31 9F E5 00 30 93 E5 03 00 54 E1 18 00 00 0A F8 30 9F E5 00 30 93 E5 03 00 54 E1 14 00 00 0A F0 30 9F E5 00 30 93 E5 03 00 54 E1 04 10 A0 E1 5B 0F 8D E2 0E 00 00 0A ?? ?? ?? EB D8 30 9F E5 04 31 93 E7 01 00 53 E3 E4 00 8D E2 08 00 00 8A C8 30 9F E5 E0 30 8D E5 ?? ?? ?? EB 00 30 A0 E3 03 20 A0 E1 04 00 A0 E1 E0 10 8D E2 64 31 8D E5 ?? ?? ?? EB 01 40 84 E2 41 00 54 E3 }
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

rule __GI_svc_sendreply_6b38662d8c38e1751cf68f4dbb2659a3 {
	meta:
		aliases = "svc_sendreply, __GI_svc_sendreply"
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

rule wait_node_free_2d32aa54a0dd6cb6ea074cca03134e0c {
	meta:
		aliases = "wait_node_free"
		size = "56"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 24 40 9F E5 00 50 A0 E1 04 00 A0 E1 E1 FF FF EB 18 30 9F E5 00 20 93 E5 00 50 83 E5 00 20 85 E5 00 30 A0 E3 00 30 84 E5 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
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

rule fill_input_buf_a9f90d56df78960d59ca96e383dc6f6c {
	meta:
		aliases = "fill_input_buf"
		size = "76"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 30 40 2D E9 30 20 90 E5 28 10 90 E5 24 30 90 E5 03 20 02 E2 02 50 81 E0 00 40 A0 E1 03 20 62 E0 05 10 A0 E1 00 00 90 E5 0F E0 A0 E1 20 F0 94 E5 01 00 70 E3 00 30 85 E0 00 00 A0 E3 01 00 A0 13 30 30 84 15 2C 50 84 15 30 80 BD E8 }
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

rule fgetc_f7f6643cdc5592e4f7a8d19279b7cd38 {
	meta:
		aliases = "__GI_fgetc, getc, fgetc"
		size = "188"
		objfiles = "fgetc@libc.a"
	strings:
		$pattern = { 30 40 2D E9 34 30 90 E5 38 50 80 E2 00 00 53 E3 10 D0 4D E2 90 10 9F E5 00 40 A0 E1 05 20 A0 E1 08 00 00 0A 10 20 90 E5 18 30 90 E5 03 00 52 E1 01 50 D2 34 10 20 80 35 18 00 00 3A ?? ?? ?? EB 00 50 A0 E1 15 00 00 EA 0D 00 A0 E1 5C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 50 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 10 20 94 E5 18 30 94 E5 03 00 52 E1 01 50 D2 34 04 00 A0 E1 10 20 84 35 01 00 00 3A ?? ?? ?? EB 00 50 A0 E1 0D 00 A0 E1 01 10 A0 E3 1C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
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

rule endrpcent_f8d46a9eebb70f75c7489b8e10d6b8a6 {
	meta:
		aliases = "__GI_endrpcent, endrpcent"
		size = "64"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 3A FF FF EB 00 40 50 E2 30 80 BD 08 0C 50 94 E5 00 00 55 E3 30 80 BD 18 04 00 94 E5 ?? ?? ?? EB 00 30 94 E5 00 00 53 E2 04 50 84 E5 30 80 BD 08 ?? ?? ?? EB 00 50 84 E5 30 80 BD E8 }
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

rule putenv_dc9ea16373c034eec10adf5c8cfc3392 {
	meta:
		aliases = "putenv"
		size = "92"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { 30 40 2D E9 3D 10 A0 E3 00 50 A0 E1 ?? ?? ?? EB 00 40 50 E2 04 10 65 E0 05 00 A0 E1 09 00 00 0A ?? ?? ?? EB 05 20 A0 E1 00 10 A0 E3 01 30 A0 E3 00 40 A0 E1 ?? ?? ?? EB 00 50 A0 E1 04 00 A0 E1 ?? ?? ?? EB 02 00 00 EA 05 00 A0 E1 ?? ?? ?? EB 04 50 A0 E1 05 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule sbrk_87868fbc624fb91e36b5a8f688f0ca76 {
	meta:
		aliases = "__GI_sbrk, sbrk"
		size = "88"
		objfiles = "sbrk@libc.a"
	strings:
		$pattern = { 30 40 2D E9 48 40 9F E5 00 30 94 E5 00 00 53 E3 00 50 A0 E1 03 00 A0 E1 02 00 00 1A ?? ?? ?? EB 00 00 50 E3 07 00 00 BA 00 30 94 E5 00 00 55 E3 03 40 A0 E1 05 00 83 E0 03 00 00 0A ?? ?? ?? EB 00 00 50 E3 00 00 00 AA 00 40 E0 E3 04 00 A0 E1 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __md5_Final_204f5961e463def9fc28a60b6a9b67fb {
	meta:
		aliases = "__md5_Final"
		size = "148"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { 30 40 2D E9 48 D0 4D E2 01 40 A0 E1 00 50 A0 E1 00 10 A0 E3 0D 00 A0 E1 40 20 A0 E3 ?? ?? ?? EB 40 00 8D E2 10 10 84 E2 7F 30 E0 E3 08 20 A0 E3 00 30 CD E5 29 FF FF EB 10 30 94 E5 A3 31 A0 E1 3F 30 03 E2 37 00 53 E3 38 20 63 E2 0D 10 A0 E1 78 20 63 82 04 00 A0 E1 BC FF FF EB 04 00 A0 E1 40 10 8D E2 08 20 A0 E3 B8 FF FF EB 05 00 A0 E1 04 10 A0 E1 10 20 A0 E3 18 FF FF EB 04 00 A0 E1 00 10 A0 E3 58 20 A0 E3 ?? ?? ?? EB 48 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_manager_adjust_prio_dc147ccfb224aef066909335b30d1ec1 {
	meta:
		aliases = "__pthread_manager_adjust_prio"
		size = "92"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 4C 30 9F E5 18 30 93 E5 00 50 A0 E1 03 00 55 E1 04 D0 4D E2 01 00 A0 E3 0B 00 00 DA ?? ?? ?? EB 2C 40 9F E5 00 00 55 E1 05 30 A0 E1 04 20 8D E2 01 30 85 B2 04 30 22 E5 14 00 94 E5 0D 20 A0 E1 01 10 A0 E3 ?? ?? ?? EB 18 50 84 E5 04 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_setutent_230cc54f3627e8771babadb189f1a3fd {
	meta:
		aliases = "setutent, __GI_setutent"
		size = "108"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 4C 40 9F E5 10 D0 4D E2 48 10 9F E5 04 20 A0 E1 0D 00 A0 E1 40 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 38 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 1D FF FF EB 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0D 50 A0 E1 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_closelog_47bc18d84ca104e57170c3d48d92de28 {
	meta:
		aliases = "closelog, __GI_closelog"
		size = "112"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { 30 40 2D E9 50 40 9F E5 10 D0 4D E2 4C 10 9F E5 04 20 A0 E1 0D 00 A0 E1 44 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 3C 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 00 00 A0 E3 CF FF FF EB 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0D 50 A0 E1 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __cxa_finalize_fc62ddb62f907e9e1ad41bab62fd1181 {
	meta:
		aliases = "__cxa_finalize"
		size = "108"
		objfiles = "__cxa_finalize@libc.a"
	strings:
		$pattern = { 30 40 2D E9 58 30 9F E5 00 40 93 E5 00 50 A0 E1 0E 00 00 EA 4C 30 9F E5 00 10 93 E5 00 00 55 E3 01 20 80 E0 02 00 00 0A 0C 30 92 E5 03 00 55 E1 06 00 00 1A 01 30 90 E7 03 00 53 E3 00 30 A0 03 01 30 80 07 08 00 92 05 0F E0 A0 01 04 F0 92 05 00 00 54 E3 01 40 44 E2 04 02 A0 E1 EC FF FF 1A 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
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

rule getutent_ffa6b9e09a9b7c1cc11079b4707082a4 {
	meta:
		aliases = "getutent"
		size = "128"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 5C 40 9F E5 10 D0 4D E2 04 20 A0 E1 54 10 9F E5 0D 00 A0 E1 50 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 44 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 3C 30 9F E5 00 00 93 E5 67 FF FF EB 01 10 A0 E3 00 40 A0 E1 2C 30 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 0D 50 A0 E1 04 00 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule closelog_intern_3116baa7f84f94ab0fb6b6dda87a0f8f {
	meta:
		aliases = "closelog_intern"
		size = "132"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { 30 40 2D E9 5C 50 9F E5 00 30 95 E5 01 00 73 E3 00 40 A0 E1 03 00 A0 E1 ?? ?? ?? 1B 00 30 E0 E3 00 30 85 E5 40 30 9F E5 00 20 A0 E3 00 00 54 E3 00 20 83 E5 30 80 BD 18 30 30 9F E5 30 20 9F E5 00 40 83 E5 2C 30 9F E5 00 20 83 E5 28 30 9F E5 08 20 A0 E3 00 20 83 E5 20 30 9F E5 F7 20 82 E2 00 20 83 E5 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __do_global_dtors_aux_f9a6147e5373e02e39b57c3ffec0225e {
	meta:
		aliases = "__do_global_dtors_aux"
		size = "224"
		objfiles = "crtbeginT, crtbegin"
	strings:
		$pattern = { 30 40 2D E9 5C 50 9F E5 00 30 D5 E5 00 00 53 E3 30 80 BD 18 50 40 9F E5 00 30 94 E5 00 20 93 E5 00 00 52 E3 07 00 00 0A 04 30 83 E2 00 30 84 E5 0F E0 A0 E1 02 F0 A0 E1 00 30 94 E5 00 20 93 E5 00 00 52 E3 F7 FF FF 1A 20 30 9F E5 00 00 53 E3 1C 00 9F 15 0F E0 A0 11 03 F0 A0 11 01 30 A0 E3 00 30 C5 E5 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 E0 2D E5 04 F0 9D E4 3C 30 9F E5 00 00 53 E3 04 E0 2D E5 34 00 9F E5 34 10 9F E5 0F E0 A0 11 03 F0 A0 11 2C 00 9F E5 00 30 90 E5 00 00 53 E3 24 30 9F E5 04 F0 9D 04 00 00 53 E3 04 F0 9D 04 0F E0 A0 E1 03 F0 A0 E1 04 F0 9D E4 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule atan_d445db50e5b528fbc73b9f231b48dfd8 {
	meta:
		aliases = "__GI_atan, atan"
		size = "648"
		objfiles = "s_atan@libm.a"
	strings:
		$pattern = { 30 40 2D E9 60 32 9F E5 02 41 C0 E3 03 00 54 E1 06 42 6D ED 00 50 A0 E1 03 00 2D E9 02 D1 BD EC 13 00 00 DA 44 32 9F E5 03 00 54 E1 00 30 A0 E1 01 40 A0 E1 06 00 00 CA 00 30 A0 13 01 30 A0 03 00 00 54 E3 00 30 A0 03 01 30 03 12 00 00 53 E3 01 00 00 0A 85 51 05 EE 62 00 00 EA 64 91 9F ED 65 81 9F ED 00 00 50 E3 81 D1 00 CE 80 D1 00 DE 5C 00 00 EA F8 31 9F E5 03 00 54 E1 07 00 00 CA 6F 37 43 E2 03 00 54 E1 21 00 00 CA 5C 81 9F ED 80 01 05 EE 19 F1 D0 EE 52 00 00 CA 1C 00 00 EA ?? ?? ?? EB CC 31 9F E5 03 00 54 E1 80 C1 00 EE 0B 00 00 CA 0D 38 43 E2 03 00 54 E1 80 01 00 DE 89 01 20 DE 8A 11 04 DE }
	condition:
		$pattern
}

rule gethostent_0ade62b9ecc8fa6f6885c5030f763570 {
	meta:
		aliases = "gethostent"
		size = "144"
		objfiles = "gethostent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 68 40 9F E5 18 D0 4D E2 04 50 8D E2 04 20 A0 E1 5C 10 9F E5 05 00 A0 E1 58 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 50 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 ?? ?? ?? EB 8A 20 A0 E3 00 00 8D E5 14 30 8D E2 34 10 9F E5 34 00 9F E5 ?? ?? ?? EB 05 00 A0 E1 01 10 A0 E3 28 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 14 00 9D E5 18 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_tan_1d92e6f3e360c550f98c20242b7dcc2d {
	meta:
		aliases = "tan, __GI_tan"
		size = "124"
		objfiles = "s_tan@libm.a"
	strings:
		$pattern = { 30 40 2D E9 68 C0 9F E5 00 40 A0 E1 02 41 C0 E3 0C 00 54 E1 14 D0 4D E2 00 20 A0 E3 00 30 A0 E3 03 00 2D E9 02 81 BD EC 01 50 A0 E1 01 C0 A0 D3 0B 00 00 DA 3C 30 9F E5 03 00 54 E1 04 20 8D E2 80 01 20 CE 08 00 00 CA ?? ?? ?? EB 01 C0 00 E2 8C C0 A0 E1 03 00 9D E9 0C 20 8D E2 0C 00 92 E8 01 C0 6C E2 00 C0 8D E5 ?? ?? ?? EB 14 D0 8D E2 30 80 BD E8 FB 21 E9 3F FF FF EF 7F }
	condition:
		$pattern
}

rule __kernel_tan_ab0c2650cf11e63cd9f485823584735c {
	meta:
		aliases = "__kernel_tan"
		size = "648"
		objfiles = "k_tan@libm.a"
	strings:
		$pattern = { 30 40 2D E9 74 C2 9F E5 02 E1 C0 E3 09 C2 6D ED 0C 00 5E E1 03 00 2D E9 02 D1 BD EC 00 40 A0 E1 01 50 A0 E1 0C 00 2D E9 02 E1 BD EC 30 C0 9D E5 0F 00 00 CA 75 31 10 EE 00 00 53 E3 0C 00 00 1A 01 40 A0 E1 00 30 A0 E1 04 20 8E E1 01 30 8C E2 03 20 92 E1 02 00 00 1A ?? ?? ?? EB 89 51 50 EE 65 00 00 EA 01 00 5C E3 89 81 10 1E 85 51 40 1E 61 00 00 EA 08 32 9F E5 03 00 5E E1 08 00 00 DA 60 91 9F ED 61 81 9F ED 00 00 54 E3 85 D1 10 BE 86 E1 10 BE 86 01 20 EE 85 11 21 EE 88 E1 00 EE 80 51 01 EE 5B 81 9F ED 5C 91 9F ED 85 41 15 EE 84 21 14 EE 80 01 12 EE 81 01 00 EE 59 91 9F ED 5A B1 9F ED 81 11 12 EE }
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

rule sigrelse_9b69ab9c53dd74b7c96a32968048927c {
	meta:
		aliases = "sighold, sigrelse"
		size = "92"
		objfiles = "sighold@libc.a, sigrelse@libc.a"
	strings:
		$pattern = { 30 40 2D E9 80 D0 4D E2 00 40 A0 E1 00 10 A0 E3 0D 20 A0 E1 02 00 A0 E3 ?? ?? ?? EB 00 00 50 E3 0D 50 A0 E1 04 10 A0 E1 0D 00 A0 E1 07 00 00 BA ?? ?? ?? EB 00 20 A0 E3 02 00 50 E1 0D 10 A0 E1 02 00 A0 E3 01 00 00 BA ?? ?? ?? EB 00 00 00 EA 00 00 E0 E3 80 D0 8D E2 30 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_wait_for_restart_sig_94b881cfe941202772a19c38e1e0ca8a {
	meta:
		aliases = "__pthread_wait_for_restart_signal"
		size = "96"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 80 D0 4D E2 00 50 A0 E1 00 10 A0 E3 0D 20 A0 E1 02 00 A0 E3 0D 40 A0 E1 ?? ?? ?? EB 34 30 9F E5 0D 00 A0 E1 00 10 93 E5 ?? ?? ?? EB 00 30 A0 E3 20 30 85 E5 0D 00 A0 E1 ?? ?? ?? EB 14 30 9F E5 00 20 93 E5 20 30 95 E5 02 00 53 E1 F8 FF FF 1A 80 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule siginterrupt_4a93961d753a3aaf7115f37831d62b40 {
	meta:
		aliases = "siginterrupt"
		size = "136"
		objfiles = "sigintr@libc.a"
	strings:
		$pattern = { 30 40 2D E9 8C D0 4D E2 01 50 A0 E1 0D 20 A0 E1 00 10 A0 E3 00 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 14 00 00 BA 00 00 55 E3 54 00 9F E5 04 10 A0 E1 03 00 00 0A ?? ?? ?? EB 84 30 9D E5 01 32 C3 E3 04 00 00 EA 04 10 A0 E1 34 00 9F E5 ?? ?? ?? EB 84 30 9D E5 01 32 83 E3 04 00 A0 E1 0D 10 A0 E1 00 20 A0 E3 84 30 8D E5 ?? ?? ?? EB 00 00 50 E3 00 00 A0 A3 00 00 00 AA 00 00 E0 E3 8C D0 8D E2 30 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __old_sem_wait_0b6101e8184192b28597d6fe535b5998 {
	meta:
		aliases = "__old_sem_wait"
		size = "440"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 90 31 9F E5 00 30 93 E5 0C D0 4D E2 03 00 5D E1 00 50 A0 E1 0D 20 A0 E1 7C 01 9F 25 16 00 00 2A 78 31 9F E5 00 30 93 E5 03 00 5D E1 04 00 00 3A 6C 31 9F E5 00 30 93 E5 03 00 5D E1 64 01 9F 35 0D 00 00 3A 60 31 9F E5 00 30 93 E5 00 00 53 E3 05 00 00 0A ?? ?? ?? EB 07 00 00 EA 08 30 9D E5 08 30 93 E5 00 30 81 E5 41 00 00 EA A2 3A E0 E1 83 3A E0 E1 77 0F 43 E2 03 00 40 E2 00 30 A0 E3 00 30 8D E5 24 31 9F E5 08 00 8D E5 04 30 8D E5 08 00 9D E5 0D 10 A0 E1 C6 FF FF EB 00 10 95 E5 01 00 51 E3 00 30 A0 03 01 30 01 12 00 00 53 E3 08 40 9D 05 08 30 9D 05 02 40 41 12 08 10 83 05 05 00 A0 E1 }
	condition:
		$pattern
}

rule pthread_onexit_process_1c060c14dea4cd06a99d6a811f57f13e {
	meta:
		aliases = "pthread_onexit_process"
		size = "180"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { 30 40 2D E9 94 30 9F E5 00 30 93 E5 00 00 53 E3 94 D0 4D E2 00 50 A0 E1 1E 00 00 BA 6C FF FF EB 02 30 A0 E3 29 00 8D E8 00 40 A0 E1 6C 30 9F E5 0D 10 A0 E1 00 00 93 E5 94 20 A0 E3 ?? ?? ?? EB 01 00 70 E3 03 00 00 1A ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 F4 FF FF 0A 04 00 A0 E1 E6 FF FF EB 3C 30 9F E5 00 30 93 E5 03 00 54 E1 09 00 00 1A 30 30 9F E5 02 21 A0 E3 14 00 93 E5 00 10 A0 E3 ?? ?? ?? EB 20 30 9F E5 00 20 A0 E3 00 20 83 E5 18 30 9F E5 00 20 83 E5 94 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _ppfs_init_0afc904bc6b5fdd0ae2a3c82c130fc8a {
	meta:
		aliases = "_ppfs_init"
		size = "152"
		objfiles = "_ppfs_init@libc.a"
	strings:
		$pattern = { 30 40 2D E9 98 20 A0 E3 00 40 A0 E1 01 50 A0 E1 00 10 A0 E3 ?? ?? ?? EB 18 30 94 E5 01 30 43 E2 18 30 84 E5 00 50 84 E5 28 10 84 E2 09 20 A0 E3 08 30 A0 E3 01 20 52 E2 04 30 81 E4 FB FF FF 1A 05 20 A0 E1 0E 00 00 EA 00 00 E0 E3 30 80 BD E8 25 00 50 E3 09 00 00 1A 01 30 F2 E5 25 00 53 E3 04 00 A0 E1 05 00 00 0A 00 20 84 E5 ?? ?? ?? EB 00 00 50 E3 F3 FF FF BA 00 20 94 E5 00 00 00 EA 01 20 82 E2 00 00 D2 E5 00 00 50 E3 EF FF FF 1A 00 50 84 E5 30 80 BD E8 }
	condition:
		$pattern
}

rule _stdio_term_d3818ca4dd4822acc838f9abcf4fb9dc {
	meta:
		aliases = "_stdio_term"
		size = "184"
		objfiles = "_stdio@libc.a"
	strings:
		$pattern = { 30 40 2D E9 9C 00 9F E5 ?? ?? ?? EB 98 00 9F E5 ?? ?? ?? EB 94 30 9F E5 00 40 93 E5 12 00 00 EA 8C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 50 E3 05 00 A0 E1 08 00 00 0A 08 30 94 E5 30 20 A0 E3 00 20 C4 E5 00 20 A0 E3 01 20 C4 E5 14 30 84 E5 18 30 84 E5 1C 30 84 E5 10 30 84 E5 01 30 A0 E3 34 30 84 E5 ?? ?? ?? EB 20 40 94 E5 38 50 84 E2 00 00 54 E3 05 00 A0 E1 E8 FF FF 1A 2C 30 9F E5 00 40 93 E5 04 00 00 EA 00 30 D4 E5 40 00 13 E3 04 00 A0 E1 ?? ?? ?? 1B 20 40 94 E5 00 00 54 E3 F8 FF FF 1A 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __setutent_e68b6a10dfd7110ef686c3e45ad28eac {
	meta:
		aliases = "__setutent"
		size = "176"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { 30 40 2D E9 9C 40 9F E5 00 30 94 E5 01 00 73 E3 94 50 9F E5 02 10 A0 E3 1C 00 00 1A 00 00 95 E5 ?? ?? ?? EB 00 10 A0 E3 01 00 50 E1 00 00 84 E5 04 00 00 AA 00 00 95 E5 ?? ?? ?? EB 00 00 50 E3 00 00 84 E5 0B 00 00 BA 01 10 A0 E3 00 20 A0 E3 00 00 94 E5 ?? ?? ?? EB 00 20 50 E2 02 10 A0 E3 01 20 82 E3 03 00 00 BA 00 00 94 E5 ?? ?? ?? EB 00 00 50 E3 05 00 00 AA 00 20 E0 E3 24 30 9F E5 02 00 A0 E1 00 20 83 E5 30 40 BD E8 ?? ?? ?? EA 10 30 9F E5 00 10 A0 E3 00 00 93 E5 01 20 A0 E1 30 40 BD E8 ?? ?? ?? EA ?? ?? ?? ?? ?? ?? ?? ?? }
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

rule svcraw_create_0e0c3c348fbbc5e941f762b9d136b8cf {
	meta:
		aliases = "svcraw_create"
		size = "152"
		objfiles = "svc_raw@libc.a"
	strings:
		$pattern = { 30 40 2D E9 ?? ?? ?? EB BC 50 90 E5 00 00 55 E3 70 10 9F E5 01 00 A0 E3 03 00 00 1A ?? ?? ?? EB 00 50 50 E2 05 00 A0 E1 30 80 BD 08 58 10 9F E5 58 30 9F E5 8E CD 85 E2 03 10 85 E7 50 20 9F E5 2C C0 8C E2 89 4D 85 E2 1C 30 83 E2 00 E0 A0 E3 03 C0 85 E7 24 40 84 E2 8E 0D 85 E2 20 30 43 E2 03 E0 C5 E7 14 00 80 E2 01 E0 C4 E5 02 E0 85 E7 05 10 A0 E1 02 30 A0 E3 ?? ?? ?? EB 89 0D 85 E2 20 00 80 E2 30 80 BD E8 3C 25 00 00 ?? ?? ?? ?? 68 22 00 00 60 22 00 00 }
	condition:
		$pattern
}

rule __ieee754_asin_463e54fa6c4c7cc0520c8576aba50922 {
	meta:
		aliases = "__ieee754_asin"
		size = "696"
		objfiles = "e_asin@libm.a"
	strings:
		$pattern = { 30 40 2D E9 A0 32 9F E5 02 41 C0 E3 03 00 54 E1 0C 42 2D ED 00 50 A0 E1 03 00 2D E9 02 C1 BD EC 0C 00 00 DA 03 21 84 E2 01 26 82 E2 01 40 A0 E1 04 20 92 E1 80 91 9F 0D 81 81 9F 0D 81 11 14 0E 80 01 14 0E 84 01 24 1E 00 30 A0 E1 81 41 00 0E 80 41 40 1E 75 00 00 EA 50 32 9F E5 03 00 54 E1 28 00 00 CA F9 05 54 E3 04 00 00 AA 76 81 9F ED 80 01 04 EE 19 F1 D0 EE 6C 00 00 CA 21 00 00 EA 73 91 9F ED 74 81 9F ED 84 21 14 EE 81 11 12 EE 80 11 01 EE 72 81 9F ED 81 11 12 EE 80 11 21 EE 71 81 9F ED 72 B1 9F ED 80 01 12 EE 83 01 20 EE 71 B1 9F ED 81 11 12 EE 83 11 01 EE 70 B1 9F ED 80 01 12 EE 83 01 00 EE }
	condition:
		$pattern
}

rule token_c248d04aa064ebe09cf675a70d3e8da6 {
	meta:
		aliases = "token"
		size = "476"
		objfiles = "ruserpass@libc.a"
	strings:
		$pattern = { 30 40 2D E9 BC 31 9F E5 00 30 93 E5 00 30 D3 E5 0C 00 13 E3 69 00 00 1A A8 31 9F E5 00 20 93 E5 10 10 92 E5 18 30 92 E5 03 00 51 E1 02 00 A0 E1 01 00 D1 34 10 10 82 35 ?? ?? ?? 2B 01 00 70 E3 09 30 40 E2 5D 00 00 0A 20 00 50 E3 01 00 53 13 F0 FF FF 9A 2C 00 50 E3 EE FF FF 0A 01 00 70 E3 56 00 00 0A 60 31 9F E5 22 00 50 E3 03 40 A0 01 0C 00 00 0A 19 00 00 EA 5C 00 50 E3 08 00 00 1A 40 31 9F E5 00 10 93 E5 10 20 91 E5 18 30 91 E5 03 00 52 E1 01 00 A0 E1 01 00 D2 34 10 20 81 35 ?? ?? ?? 2B 01 00 C4 E4 18 31 9F E5 00 20 93 E5 10 10 92 E5 18 30 92 E5 03 00 51 E1 02 00 A0 E1 01 00 D1 34 10 10 82 35 }
	condition:
		$pattern
}

rule __GI_strrchr_994a0f7b446ea6782fe4d5c2d1e735d6 {
	meta:
		aliases = "rindex, strrchr, __GI_strrchr"
		size = "68"
		objfiles = "strrchr@libc.a"
	strings:
		$pattern = { 30 40 2D E9 FF 40 11 E2 00 30 A0 E1 00 50 A0 13 04 00 00 1A 04 10 A0 E1 30 40 BD E8 ?? ?? ?? EA 00 50 A0 E1 01 30 80 E2 03 00 A0 E1 04 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 F8 FF FF 1A 05 00 A0 E1 30 80 BD E8 }
	condition:
		$pattern
}

rule rawmemchr_c108df450fa58a02efa5005a63a61fd2 {
	meta:
		aliases = "__GI_rawmemchr, rawmemchr"
		size = "184"
		objfiles = "rawmemchr@libc.a"
	strings:
		$pattern = { 30 40 2D E9 FF E0 01 E2 03 00 00 EA 00 30 D0 E5 0E 00 53 E1 30 80 BD 08 01 00 80 E2 03 00 10 E3 F9 FF FF 1A 0E 34 8E E1 00 C0 A0 E1 03 58 83 E1 04 30 9C E4 74 10 9F E5 03 30 25 E0 01 10 83 E0 6C 20 9F E5 03 30 E0 E1 03 10 21 E0 02 20 01 E0 00 00 52 E3 F5 FF FF 0A 04 30 5C E5 04 00 4C E2 0E 00 53 E1 03 40 80 E2 01 20 80 E2 02 10 80 E2 30 80 BD 08 03 30 5C E5 0E 00 53 E1 01 00 00 1A 02 00 A0 E1 30 80 BD E8 02 30 5C E5 0E 00 53 E1 01 00 00 1A 01 00 A0 E1 30 80 BD E8 01 30 5C E5 0E 00 53 E1 E1 FF FF 1A 04 00 A0 E1 30 80 BD E8 FF FE FE 7E 00 01 01 81 }
	condition:
		$pattern
}

rule __do_global_dtors_aux_45514295d9763c5ee1de6ad2172c9973 {
	meta:
		aliases = "__do_global_dtors_aux"
		size = "312"
		objfiles = "crtbeginS"
	strings:
		$pattern = { 30 44 2D E9 88 A0 9F E5 88 50 9F E5 0A A0 8F E0 05 30 DA E7 00 00 53 E3 30 84 BD 18 78 30 9F E5 03 20 9A E7 00 00 52 E3 70 30 9F 15 03 00 9A 17 0F E0 A0 11 02 F0 A0 11 64 40 9F E5 04 30 9A E7 00 20 93 E5 00 00 52 E3 07 00 00 0A 04 30 83 E2 04 30 8A E7 0F E0 A0 E1 02 F0 A0 E1 04 30 9A E7 00 20 93 E5 00 00 52 E3 F7 FF FF 1A 34 30 9F E5 03 30 9A E7 00 00 53 E3 2C 00 9F 15 00 00 8A 10 0F E0 A0 11 03 F0 A0 11 01 30 A0 E3 05 30 CA E7 30 84 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 E0 2D E5 04 F0 9D E4 00 44 2D E9 54 A0 9F E5 54 30 9F E5 0A A0 8F E0 }
	condition:
		$pattern
}

rule _promoted_size_60cb92df219dbd4520ab3ccc077f17de {
	meta:
		aliases = "_promoted_size"
		size = "76"
		objfiles = "_ppfs_parsespec@libc.a"
	strings:
		$pattern = { 38 10 9F E5 02 10 41 E2 01 30 D1 E5 00 20 D1 E5 03 3C A0 E1 43 28 82 E1 00 00 52 E1 02 00 00 0A 1C 30 9F E5 03 00 51 E1 F5 FF FF 8A 10 30 9F E5 10 20 9F E5 01 30 63 E0 C3 00 D2 E7 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __popcountsi2_b2e0d3debfb5f0c4e5545c10676b9cd8 {
	meta:
		aliases = "__popcountsi2"
		size = "68"
		objfiles = "_popcountsi2@libgcc.a"
	strings:
		$pattern = { 38 10 9F E5 20 24 A0 E1 FF 20 02 E2 FF C0 00 E2 20 38 A0 E1 10 40 2D E9 FF 30 03 E2 00 E0 A0 E1 02 40 D1 E7 0C 00 D1 E7 03 20 D1 E7 04 00 80 E0 2E 3C D1 E7 02 00 80 E0 00 00 83 E0 10 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule localeconv_e100aef6b85547709d476ceb8b150258 {
	meta:
		aliases = "__GI_localeconv, localeconv"
		size = "84"
		objfiles = "localeconv@libc.a"
	strings:
		$pattern = { 38 20 9F E5 38 30 9F E5 00 30 82 E5 34 30 9F E5 04 30 A2 E5 30 30 9F E5 03 00 52 E1 FA FF FF 3A 04 20 83 E2 00 30 E0 E3 01 30 C2 E4 1C 30 9F E5 03 00 52 E1 FA FF FF 9A 00 00 9F E5 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule frame_dummy_8b7c45873659e3f40b6738c229ca6bb0 {
	meta:
		aliases = "frame_dummy"
		size = "96"
		objfiles = "crtbeginT, crtbegin"
	strings:
		$pattern = { 3C 30 9F E5 00 00 53 E3 04 E0 2D E5 34 00 9F E5 34 10 9F E5 0F E0 A0 11 03 F0 A0 11 2C 00 9F E5 00 30 90 E5 00 00 53 E3 24 30 9F E5 04 F0 9D 04 00 00 53 E3 04 F0 9D 04 0F E0 A0 E1 03 F0 A0 E1 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 E0 2D E5 04 F0 9D E4 }
	condition:
		$pattern
}

rule __pthread_once_fork_child_d2f72e4e99f5b228c3c77706f2a09087 {
	meta:
		aliases = "__pthread_once_fork_child"
		size = "84"
		objfiles = "mutex@libpthread.a"
	strings:
		$pattern = { 3C 30 9F E5 04 E0 2D E5 00 10 A0 E3 34 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 10 A0 E3 28 00 9F E5 ?? ?? ?? EB 24 20 9F E5 00 30 92 E5 16 01 73 E3 04 10 83 E2 00 30 A0 C3 00 10 82 D5 00 30 82 C5 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
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

rule srand48_r_3df94586d0df9e02531ffa6401b9f9b8 {
	meta:
		aliases = "__GI_srand48_r, srand48_r"
		size = "104"
		objfiles = "srand48_r@libc.a"
	strings:
		$pattern = { 40 38 A0 E1 04 30 C1 E5 0E 30 A0 E3 10 40 2D E9 00 30 C1 E5 25 30 83 E2 01 30 C1 E5 0B 30 A0 E3 0C 30 C1 E5 01 30 A0 E3 00 C0 A0 E3 0E 30 C1 E5 2C 30 9F E5 40 E4 A0 E1 40 2C A0 E1 02 00 C1 E5 05 40 A0 E3 0C 00 A0 E1 05 20 C1 E5 03 E0 C1 E5 0F C0 C1 E5 10 30 81 E5 14 40 81 E5 0D C0 C1 E5 10 80 BD E8 6D E6 EC DE }
	condition:
		$pattern
}

rule __GI_trunc_37a6e7a881b395c131e009a1ec0d020c {
	meta:
		aliases = "trunc, __GI_trunc"
		size = "172"
		objfiles = "s_trunc@libm.a"
	strings:
		$pattern = { 40 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 FF 2F 43 E2 03 20 42 E2 F0 41 2D E9 13 00 52 E3 00 60 A0 E3 00 50 A0 E3 03 00 2D E9 02 81 BD EC 00 C0 A0 E1 01 E0 A0 E1 06 40 A0 E1 05 70 A0 E1 06 80 A0 E1 0C 00 00 CA 02 11 00 E2 00 00 52 E3 01 30 A0 E1 00 40 A0 E3 18 00 2D E9 02 81 BD EC 44 30 9F A5 53 32 CC A1 00 80 A0 A3 03 70 81 A1 80 01 2D A9 02 81 BD AC F0 81 BD E8 33 00 52 E3 00 50 A0 E1 14 10 42 E2 02 00 00 DA 01 0B 52 E3 80 01 00 0E F0 81 BD E8 00 30 E0 E3 33 61 CE E1 60 00 2D E9 02 81 BD EC F0 81 BD E8 FF FF 0F 00 }
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

rule __GI_abort_8b0811fa1a17af81a6c63192c974fa46 {
	meta:
		aliases = "abort, __GI_abort"
		size = "328"
		objfiles = "abort@libc.a"
	strings:
		$pattern = { 43 DF 4D E2 2C 01 9F E5 2C 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 20 10 A0 E3 03 00 00 EA 43 3F 8D E2 01 21 83 E0 00 30 A0 E3 80 30 02 E5 01 10 51 E2 F9 FF FF 5A 8C 40 8D E2 04 00 A0 E1 06 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 00 20 A0 01 04 10 A0 01 01 00 A0 03 ?? ?? ?? 0B E0 20 9F E5 00 30 92 E5 00 00 53 E3 0B 00 00 1A 01 30 83 E2 00 30 82 E5 CC 30 9F E5 BC 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 06 00 A0 E3 ?? ?? ?? EB A8 00 9F E5 A8 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 A0 C0 9F E5 00 30 9C E5 01 00 53 E3 16 00 00 1A 01 30 83 E2 00 10 A0 E3 0D 00 A0 E1 8C 20 A0 E3 00 30 8C E5 ?? ?? ?? EB 00 30 A0 E3 20 10 A0 E3 }
	condition:
		$pattern
}

rule __GI___uClibc_init_c695e9a3e3f4a2e94ca7660dd6831161 {
	meta:
		aliases = "__uClibc_init, __GI___uClibc_init"
		size = "92"
		objfiles = "__uClibc_main@libc.a"
	strings:
		$pattern = { 44 20 9F E5 00 30 92 E5 00 00 53 E3 04 E0 2D E5 38 10 9F E5 04 F0 9D 14 01 30 83 E2 00 30 82 E5 2C 30 9F E5 01 2A A0 E3 00 00 51 E3 00 20 83 E5 0F E0 A0 11 01 F0 A0 11 18 30 9F E5 00 00 53 E3 04 F0 9D 04 04 E0 9D E4 ?? ?? ?? EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __libc_allocate_rtsig_d2816507aa0205f1c6b6768641c30d7d {
	meta:
		aliases = "__libc_allocate_rtsig"
		size = "84"
		objfiles = "allocrtsig@libc.a, pthread@libpthread.a"
	strings:
		$pattern = { 44 C0 9F E5 00 20 9C E5 01 00 72 E3 04 E0 2D E5 38 E0 9F E5 09 00 00 0A 00 30 9E E5 03 00 52 E1 06 00 00 CA 00 00 50 E3 01 10 82 E2 01 00 43 E2 03 20 A0 01 00 10 8C 15 00 00 8E 05 00 00 00 EA 00 20 E0 E3 02 00 A0 E1 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _dl_unmap_cache_9f4ff8093016f06ac8a421f52f69a64b {
	meta:
		aliases = "_dl_unmap_cache"
		size = "88"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 44 C0 9F E5 00 30 9C E5 03 00 A0 E1 01 30 43 E2 03 00 73 E3 00 30 E0 E3 09 00 00 8A 2C 30 9F E5 00 10 93 E5 5B 00 90 EF 01 0A 70 E3 00 10 A0 E3 1C 30 9F 85 00 20 60 E2 00 10 8C E5 00 20 83 85 01 30 A0 E1 03 00 A0 E1 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_wctrans_f9f604f1c0d8c6f8ea0b2920bf5bd69b {
	meta:
		aliases = "wctrans, __GI_wctype, wctype, __GI_wctrans"
		size = "84"
		objfiles = "wctrans@libc.a, wctype@libc.a"
	strings:
		$pattern = { 48 10 9F E5 70 40 2D E9 00 60 A0 E1 01 50 A0 E3 01 40 81 E2 06 00 A0 E1 04 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 01 00 00 1A 05 00 A0 E1 70 80 BD E8 01 20 54 E5 02 30 D4 E7 00 00 53 E3 01 50 85 E2 02 10 84 E0 F1 FF FF 1A 00 00 A0 E3 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule putwchar_5bc317c498ac4e0d153fd695b1a80d06 {
	meta:
		aliases = "putwchar"
		size = "84"
		objfiles = "putwchar@libc.a"
	strings:
		$pattern = { 48 30 9F E5 00 C0 93 E5 34 30 9C E5 00 00 53 E3 04 E0 2D E5 0C 10 A0 E1 00 E0 A0 E1 05 00 00 0A 10 20 9C E5 1C 30 9C E5 03 00 52 E1 03 00 00 3A 04 E0 9D E4 ?? ?? ?? EA 04 E0 9D E4 ?? ?? ?? EA 00 00 C2 E5 01 00 D2 E4 10 20 8C E5 04 F0 9D E4 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule load_field_ee881b029730e31379f73c6bc532ccf1 {
	meta:
		aliases = "load_field"
		size = "92"
		objfiles = "strftime@libc.a"
	strings:
		$pattern = { 48 30 9F E5 07 00 50 E3 03 30 80 E0 00 20 A0 E1 3C C0 9F E5 00 01 91 E7 3A 30 D3 E5 04 00 00 0A 05 00 52 E3 03 C0 A0 E1 76 0E 80 02 24 C0 9F 05 0C 00 80 02 0C 00 50 E1 02 00 00 8A 03 00 52 E3 00 00 50 03 0E F0 A0 11 00 00 E0 E3 0E F0 A0 E1 ?? ?? ?? ?? 6D 01 00 00 0F 27 00 00 }
	condition:
		$pattern
}

rule pthread_kill_all_threads_a411b660034a7a07d0d6c13a66b99d31 {
	meta:
		aliases = "pthread_kill_all_threads"
		size = "84"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { 48 30 9F E5 70 40 2D E9 00 30 93 E5 00 40 93 E5 00 50 A0 E1 01 60 A0 E1 02 00 00 EA 14 00 94 E5 ?? ?? ?? EB 00 40 94 E5 20 30 9F E5 00 30 93 E5 03 00 54 E1 05 10 A0 E1 F7 FF FF 1A 00 00 56 E3 70 80 BD 08 14 00 94 E5 70 40 BD E8 ?? ?? ?? EA ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_nl_langinfo_5a6b63fa9e361587dd33dad8174a279c {
	meta:
		aliases = "nl_langinfo, __GI_nl_langinfo"
		size = "88"
		objfiles = "nl_langinfo@libc.a"
	strings:
		$pattern = { 4C 10 9F E5 FF C0 00 E2 40 04 A0 E1 05 00 50 E3 04 E0 2D E5 01 20 80 E0 0B 00 00 8A 00 30 D1 E7 01 20 D2 E5 0C 30 83 E0 02 00 53 E1 01 C0 83 E0 40 E0 03 E2 61 00 81 E2 03 00 00 2A 07 30 DC E5 8E 30 83 E0 00 00 83 E0 04 F0 9D E4 00 00 9F E5 04 F0 9D E4 ?? ?? ?? ?? }
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

rule __assert_b33cfb80ab1785e0cd114a021f9768d5 {
	meta:
		aliases = "__GI___assert, __assert"
		size = "112"
		objfiles = "__assert@libc.a"
	strings:
		$pattern = { 54 60 9F E5 00 C0 96 E5 00 00 5C E3 0C D0 4D E2 00 50 A0 E1 02 40 A0 E1 03 E0 A0 E1 0D 00 00 1A 38 30 9F E5 00 00 93 E5 34 30 9F E5 00 20 93 E5 30 30 9F E5 00 00 5E E3 03 E0 A0 01 01 C0 8C E2 01 30 A0 E1 20 10 9F E5 00 C0 86 E5 10 40 8D E8 08 50 8D E5 ?? ?? ?? EB ?? ?? ?? EB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __libc_longjmp_789ce6fea0e89014516e8152aa1f9b75 {
	meta:
		aliases = "siglongjmp, _longjmp, __libc_siglongjmp, longjmp, __libc_longjmp"
		size = "52"
		objfiles = "longjmp@libc.a"
	strings:
		$pattern = { 58 30 90 E5 00 00 53 E3 00 40 A0 E1 01 50 A0 E1 02 00 A0 13 5C 10 84 12 00 20 A0 13 ?? ?? ?? 1B 00 00 55 E3 05 10 A0 11 01 10 A0 03 04 00 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule thread_self_6a38e58861d7b8a62d9a592bdd001773 {
	meta:
		aliases = "thread_self"
		size = "124"
		objfiles = "join@libpthread.a, cancel@libpthread.a, semaphore@libpthread.a, signals@libpthread.a, spinlock@libpthread.a"
	strings:
		$pattern = { 5C 30 9F E5 00 30 93 E5 03 00 5D E1 0D 10 A0 E1 50 00 9F E5 0E F0 A0 21 4C 30 9F E5 00 30 93 E5 03 00 5D E1 04 00 00 3A 40 30 9F E5 00 30 93 E5 03 00 5D E1 38 00 9F E5 0E F0 A0 31 34 30 9F E5 00 20 93 E5 A1 3A E0 E1 83 3A E0 E1 00 00 52 E3 77 0F 43 E2 00 00 00 0A ?? ?? ?? EA 03 00 40 E2 0E F0 A0 E1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_getenv_bfc81d5c345e09c6f15d96c465c9bf43 {
	meta:
		aliases = "getenv, __GI_getenv"
		size = "108"
		objfiles = "getenv@libc.a"
	strings:
		$pattern = { 60 30 9F E5 F0 40 2D E9 00 60 93 E5 00 00 56 E3 00 70 A0 E1 11 00 00 0A ?? ?? ?? EB 00 50 A0 E1 08 00 00 EA ?? ?? ?? EB 00 00 50 E3 05 20 84 E0 04 00 00 1A 05 30 D4 E7 3D 00 53 E3 01 00 00 1A 01 00 82 E2 F0 80 BD E8 00 40 96 E5 00 10 54 E2 07 00 A0 E1 05 20 A0 E1 04 60 86 E2 F0 FF FF 1A 00 00 A0 E3 F0 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule xdrrec_create_bfacc62ef4d0e81e44981abb3a94c8d9 {
	meta:
		aliases = "__GI_xdrrec_create, xdrrec_create"
		size = "272"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 63 00 52 E3 F0 4F 2D E9 02 40 A0 E1 00 80 A0 E1 FA 4E A0 93 44 00 A0 E3 63 00 51 E3 01 50 A0 E1 03 A0 A0 E1 FA 5E A0 93 24 90 8D E2 00 0A 99 E8 ?? ?? ?? EB 03 40 84 E2 03 70 C4 E3 03 50 85 E2 00 60 A0 E1 03 50 C5 E3 04 00 87 E2 00 00 85 E0 ?? ?? ?? EB 00 40 A0 E1 00 00 54 E3 00 00 56 13 9C 00 9F E5 04 C0 A0 E1 00 E0 A0 13 01 E0 A0 03 07 00 00 1A 8C 30 9F E5 00 10 93 E5 ?? ?? ?? EB 06 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 F0 4F BD E8 ?? ?? ?? EA 03 30 C4 E3 03 00 14 E3 04 C0 83 12 01 30 A0 E3 05 20 8C E0 38 30 86 E5 58 30 9F E5 07 00 82 E0 04 10 8C E2 3C 50 86 E5 40 70 86 E5 04 40 86 E5 04 30 88 E5 }
	condition:
		$pattern
}

rule getnetbyname_172284a70b3866a56f99bc294b7adef7 {
	meta:
		aliases = "getnetbyname"
		size = "124"
		objfiles = "getnetbynm@libc.a"
	strings:
		$pattern = { 70 30 9F E5 70 40 2D E9 00 60 A0 E1 00 00 93 E5 ?? ?? ?? EB 0E 00 00 EA 00 00 95 E5 06 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 0C 00 00 0A 04 40 95 E5 02 00 00 EA ?? ?? ?? EB 00 00 50 E3 07 00 00 0A 00 30 94 E5 00 00 53 E2 06 10 A0 E1 04 40 84 E2 F7 FF FF 1A ?? ?? ?? EB 00 50 50 E2 ED FF FF 1A 10 30 9F E5 00 30 93 E5 00 00 53 E3 ?? ?? ?? 0B 05 00 A0 E1 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule malloc_e97b2442e078f26587c9ade53deb1e22 {
	meta:
		aliases = "malloc"
		size = "340"
		objfiles = "malloc@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 00 50 E3 04 D0 4D E2 01 00 A0 03 01 00 00 0A 08 00 70 E3 40 00 00 8A 04 30 80 E2 04 40 8D E2 04 30 24 E5 0C 01 9F E5 0C 51 9F E5 0F E0 A0 E1 05 F0 A0 E1 0D 10 A0 E1 00 01 9F E5 ?? ?? ?? EB FC 30 9F E5 00 40 A0 E1 E8 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 54 E3 2B 00 00 1A E4 30 9F E5 00 40 93 E5 00 30 9D E5 04 00 53 E1 04 30 83 20 01 30 43 22 00 20 64 22 02 40 03 20 C8 00 9F E5 0F E0 A0 E1 05 F0 A0 E1 04 00 A0 E1 ?? ?? ?? EB 01 00 70 E3 00 50 A0 01 04 00 00 0A 03 30 80 E2 03 50 C3 E3 05 00 50 E1 05 00 60 10 ?? ?? ?? 1B 94 00 9F E5 88 60 9F E5 0F E0 A0 E1 06 F0 A0 E1 01 00 75 E3 }
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

rule pthread_rwlock_unlock_fd0dda935fede7c395bb526cab5f2c0e {
	meta:
		aliases = "pthread_rwlock_unlock"
		size = "408"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 10 A0 E3 00 40 A0 E1 ?? ?? ?? EB 0C 50 94 E5 00 00 55 E3 21 00 00 0A 0E FF FF EB 00 00 55 E1 21 00 00 1A 18 30 94 E5 00 60 A0 E3 00 00 53 E3 0C 60 84 E5 0B 00 00 0A 14 50 94 E5 06 00 55 E1 08 00 00 0A 08 30 95 E5 04 00 A0 E1 14 30 84 E5 08 60 85 E5 ?? ?? ?? EB 05 00 A0 E1 FC FE FF EB 06 00 A0 E1 70 80 BD E8 00 30 A0 E3 10 50 94 E5 04 00 A0 E1 10 30 84 E5 ?? ?? ?? EB 04 00 00 EA 00 30 A0 E3 08 40 95 E5 08 30 85 E5 F0 FE FF EB 04 50 A0 E1 00 00 55 E2 F8 FF FF 1A 3A 00 00 EA 08 30 94 E5 00 00 53 E3 03 00 00 1A 04 00 A0 E1 ?? ?? ?? EB 01 00 A0 E3 70 80 BD E8 01 20 43 E2 00 00 52 E3 }
	condition:
		$pattern
}

rule cfsetspeed_246de3317fc617485b137817e9f45d05 {
	meta:
		aliases = "cfsetspeed"
		size = "144"
		objfiles = "cfsetspeed@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 20 A0 E3 00 60 A0 E1 01 50 A0 E1 14 00 00 EA 04 40 91 E5 04 00 55 E1 05 00 00 1A 05 10 A0 E1 06 00 A0 E1 ?? ?? ?? EB 06 00 A0 E1 05 10 A0 E1 08 00 00 EA 82 31 93 E7 03 00 55 E1 01 20 82 E2 07 00 00 1A 04 10 A0 E1 06 00 A0 E1 ?? ?? ?? EB 06 00 A0 E1 04 10 A0 E1 ?? ?? ?? EB 00 00 A0 E3 70 80 BD E8 1C 30 9F E5 1F 00 52 E3 82 11 83 E0 E6 FF FF 9A ?? ?? ?? EB 16 30 A0 E3 00 30 80 E5 00 00 E0 E3 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_sigmask_460a2b4a426e602e1259e6f9a2a08879 {
	meta:
		aliases = "pthread_sigmask"
		size = "196"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 30 51 E2 80 D0 4D E2 00 50 A0 E1 02 60 A0 E1 1C 00 00 0A 0D 00 A0 E1 80 20 A0 E3 0D 40 A0 E1 ?? ?? ?? EB 01 00 55 E3 11 00 00 0A 02 00 55 E3 02 00 00 0A 00 00 55 E3 04 00 00 0A 10 00 00 EA 6C 30 9F E5 0D 00 A0 E1 00 10 93 E5 ?? ?? ?? EB 60 30 9F E5 0D 00 A0 E1 00 10 93 E5 ?? ?? ?? EB 54 30 9F E5 00 10 93 E5 00 00 51 E3 04 00 00 DA 01 00 00 EA 38 30 9F E5 00 10 93 E5 0D 00 A0 E1 ?? ?? ?? EB 0D 30 A0 E1 05 00 A0 E1 03 10 A0 E1 06 20 A0 E1 ?? ?? ?? EB 01 00 70 E3 00 00 A0 13 01 00 00 1A ?? ?? ?? EB 00 00 90 E5 80 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_xdr_callmsg_0d0abceb779903deaa61c1f2ae8c1a44 {
	meta:
		aliases = "xdr_callmsg, __GI_xdr_callmsg"
		size = "1528"
		objfiles = "rpc_cmsg@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 30 90 E5 00 00 53 E3 00 60 A0 E1 01 50 A0 E1 8A 00 00 1A 20 10 91 E5 19 0E 51 E3 70 01 00 8A 2C 30 95 E5 19 0E 53 E3 6D 01 00 8A 03 10 81 E2 03 30 83 E2 03 10 C1 E3 03 30 C3 E3 28 10 81 E2 01 10 83 E0 04 30 90 E5 0F E0 A0 E1 18 F0 93 E5 00 C0 50 E2 79 00 00 0A 00 10 95 E5 FF 38 01 E2 FF 2C 01 E2 23 34 A0 E1 02 24 A0 E1 01 2C 82 E1 21 3C 83 E1 02 30 83 E1 0C 00 A0 E1 04 30 80 E4 04 10 95 E5 FF 38 01 E2 FF 2C 01 E2 23 34 A0 E1 02 24 A0 E1 01 2C 82 E1 21 3C 83 E1 02 30 83 E1 04 30 8C E5 04 30 95 E5 00 00 53 E3 4C 01 00 1A 08 10 95 E5 FF 38 01 E2 FF 2C 01 E2 23 34 A0 E1 02 24 A0 E1 }
	condition:
		$pattern
}

rule rresvport_0b7ff15b9d2c8adbcf5049f021591659 {
	meta:
		aliases = "__GI_rresvport, rresvport"
		size = "200"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 30 A0 E3 02 C0 A0 E3 10 D0 4D E2 00 50 A0 E1 03 20 A0 E1 0C 00 A0 E1 01 10 A0 E3 00 C0 CD E5 01 30 CD E5 04 30 8D E5 ?? ?? ?? EB 00 40 50 E2 03 00 00 AA 1E 00 00 EA 04 00 A0 E1 ?? ?? ?? EB 1B 00 00 EA 00 30 95 E5 03 38 A0 E1 23 C4 A0 E1 FF CC 0C E2 23 CC 8C E1 4C 34 A0 E1 0D 10 A0 E1 10 20 A0 E3 04 00 A0 E1 03 30 CD E5 02 C0 CD E5 ?? ?? ?? EB 00 00 50 E3 0E 00 00 AA ?? ?? ?? EB 00 30 90 E5 62 00 53 E3 00 60 A0 E1 E9 FF FF 1A 00 30 95 E5 01 30 43 E2 02 0C 53 E3 00 30 85 E5 E7 FF FF 1A 04 00 A0 E1 ?? ?? ?? EB 0B 30 A0 E3 00 30 86 E5 00 40 E0 E3 04 00 A0 E1 10 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule __GI_strtok_r_8d6edd1322a837f8fbb801aac77b9a20 {
	meta:
		aliases = "strtok_r, __GI_strtok_r"
		size = "116"
		objfiles = "strtok_r@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 50 E2 00 40 92 05 04 00 A0 E1 02 50 A0 E1 01 60 A0 E1 ?? ?? ?? EB 00 30 D4 E7 00 40 84 E0 00 00 53 E3 06 10 A0 E1 04 00 A0 E1 00 40 85 05 0C 00 00 0A ?? ?? ?? EB 00 20 50 E2 02 10 A0 E1 04 00 A0 E1 03 00 00 1A ?? ?? ?? EB 04 30 A0 E1 00 00 85 E5 03 00 00 EA 00 30 A0 E3 01 30 C2 E4 00 20 85 E5 04 30 A0 E1 03 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule __cxa_atexit_d807c494958ac756578834843b5a466a {
	meta:
		aliases = "__GI___cxa_atexit, __cxa_atexit"
		size = "60"
		objfiles = "__cxa_atexit@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 50 E2 04 30 A0 E1 01 50 A0 E1 02 60 A0 E1 06 00 00 0A ?? ?? ?? EB 00 00 50 E3 00 30 E0 E3 02 00 00 0A 03 30 A0 E3 78 00 80 E8 00 30 A0 E3 03 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule fflush_ea4d572162d26a7694e3d6a78c5592e4 {
	meta:
		aliases = "__GI_fflush, fflush"
		size = "172"
		objfiles = "fflush@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 50 E2 10 D0 4D E2 04 00 A0 E1 1B 00 00 0A 7C 30 9F E5 03 00 54 E1 18 00 00 0A 34 60 94 E5 38 50 84 E2 00 00 56 E3 05 20 A0 E1 64 10 9F E5 0D 00 A0 E1 06 00 00 1A 5C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 50 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 00 56 E3 00 40 A0 E1 01 10 A0 E3 0D 00 A0 E1 05 00 00 1A 2C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 01 00 00 EA ?? ?? ?? EB 00 40 A0 E1 04 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_tfind_99c71159affa23f88dc66a92d94d1da1 {
	meta:
		aliases = "tfind, __GI_tfind"
		size = "88"
		objfiles = "tfind@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 51 E2 00 60 A0 E1 02 50 A0 E1 0E 00 00 0A 09 00 00 EA 00 10 91 E5 0F E0 A0 E1 05 F0 A0 E1 00 00 50 E3 01 00 00 1A 00 00 94 E5 70 80 BD E8 00 30 94 E5 04 40 83 E2 08 40 83 A2 00 10 94 E5 00 00 51 E3 06 00 A0 E1 F1 FF FF 1A 00 00 A0 E3 70 80 BD E8 }
	condition:
		$pattern
}

rule sigaction_4e4d2c4f0bba6e7c425006ee7a6da10d {
	meta:
		aliases = "__libc_sigaction, __GI_sigaction, sigaction"
		size = "228"
		objfiles = "sigaction@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 51 E2 46 DF 4D E2 00 60 A0 E1 02 50 A0 E1 15 00 00 0A 04 10 A0 E1 04 30 91 E4 98 00 8D E2 80 20 A0 E3 8C 30 8D E5 ?? ?? ?? EB 84 10 94 E5 01 03 11 E3 88 30 94 15 90 10 8D E5 94 30 8D 15 06 00 00 1A 8C 20 9F E5 8C 30 9F E5 04 00 11 E3 02 30 A0 11 01 23 81 E3 94 30 8D E5 90 20 8D E5 00 00 54 E3 8C 10 8D 12 00 00 00 1A 00 10 A0 E3 00 00 55 E3 05 20 A0 01 0D 20 A0 11 08 30 A0 E3 06 00 A0 E1 ?? ?? ?? EB 00 30 55 E2 01 30 A0 13 00 00 50 E3 00 30 A0 B3 00 00 53 E3 00 40 A0 E1 09 00 00 0A 00 30 9D E5 05 00 A0 E1 04 30 80 E4 0C 10 8D E2 80 20 A0 E3 ?? ?? ?? EB 08 30 9D E5 88 30 85 E5 }
	condition:
		$pattern
}

rule svctcp_destroy_57a69fc3459101ac317c48bac8620769 {
	meta:
		aliases = "svcunix_destroy, svctcp_destroy"
		size = "100"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 A0 E1 00 50 A0 E1 2C 60 90 E5 ?? ?? ?? EB 04 00 94 E4 ?? ?? ?? EB 01 20 D4 E5 04 30 D5 E5 02 24 93 E1 00 30 A0 E3 05 30 C5 15 04 30 C5 15 05 00 00 1A 0C 30 96 E5 1C 30 93 E5 00 00 53 E3 08 00 86 E2 0F E0 A0 11 03 F0 A0 11 06 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 70 40 BD E8 ?? ?? ?? EA }
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

rule __GI_pthread_attr_setschedpara_bb047f0f417798337d0bd912b1112a99 {
	meta:
		aliases = "pthread_attr_setschedparam, __GI_pthread_attr_setschedparam"
		size = "84"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 A0 E1 04 00 90 E5 01 50 A0 E1 ?? ?? ?? EB 00 60 A0 E1 04 00 94 E5 ?? ?? ?? EB 00 30 95 E5 00 00 53 E1 07 00 00 BA 06 00 53 E1 08 00 84 E2 05 10 A0 E1 04 20 A0 E3 02 00 00 CA ?? ?? ?? EB 00 00 A0 E3 70 80 BD E8 16 00 A0 E3 70 80 BD E8 }
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

rule __GI_strstr_d3027e1c0f1b95378faf5c3ae47c405f {
	meta:
		aliases = "strstr, __GI_strstr"
		size = "248"
		objfiles = "strstr@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 40 D1 E5 00 00 54 E3 70 80 BD 08 01 00 40 E2 01 30 F0 E5 00 00 53 E3 33 00 00 0A 04 00 53 E1 FA FF FF 1A 01 50 D1 E5 00 00 55 E3 01 60 81 E2 70 80 BD 08 01 30 D0 E5 01 C0 80 E2 05 00 53 E1 0E 00 00 EA 01 30 D0 E5 01 C0 80 E2 07 00 00 EA 00 00 53 E3 24 00 00 0A 01 30 FC E5 04 00 53 E1 04 00 00 0A 00 00 53 E3 1F 00 00 0A 01 30 FC E5 04 00 53 E1 F5 FF FF 1A 01 30 FC E5 05 00 53 E1 FA FF FF 1A 01 30 DC E5 01 20 D6 E5 01 00 4C E2 02 00 53 E1 01 E0 86 E2 01 C0 8C E2 0F 00 00 1A 00 00 52 E3 70 80 BD 08 01 30 DC E5 01 20 DE E5 01 10 8C E2 02 00 53 E1 01 30 8E E2 01 C0 81 E2 01 E0 83 E2 }
	condition:
		$pattern
}

rule psignal_aec789a952bdd1524a6ae19624927c87 {
	meta:
		aliases = "psignal"
		size = "100"
		objfiles = "psignal@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 50 51 E2 04 D0 4D E2 40 60 9F E5 03 00 00 0A 00 30 D5 E5 00 00 53 E3 34 60 9F 15 00 00 00 1A 06 50 A0 E1 2C 30 9F E5 00 40 93 E5 ?? ?? ?? EB 05 20 A0 E1 00 00 8D E5 06 30 A0 E1 04 00 A0 E1 14 10 9F E5 ?? ?? ?? EB 04 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __encode_question_08c9e564c49aea066410cd98f953abf0 {
	meta:
		aliases = "__encode_question"
		size = "92"
		objfiles = "encodeq@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 50 A0 E1 00 00 90 E5 02 40 A0 E1 01 60 A0 E1 ?? ?? ?? EB 00 00 50 E3 04 40 60 E0 70 80 BD B8 03 00 54 E3 00 20 86 E0 00 00 E0 D3 70 80 BD D8 05 30 D5 E5 00 30 C6 E7 04 30 95 E5 01 30 C2 E5 09 30 D5 E5 02 30 C2 E5 08 30 95 E5 04 00 80 E2 03 30 C2 E5 70 80 BD E8 }
	condition:
		$pattern
}

rule wcscasecmp_b9a68faa33cfc056d49b51aec6654e81 {
	meta:
		aliases = "__GI_wcscasecmp, wcscasecmp"
		size = "116"
		objfiles = "wcscasecmp@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 50 A0 E1 01 60 A0 E1 04 00 00 EA 00 00 95 E5 00 00 50 E3 70 80 BD 08 04 50 85 E2 04 60 86 E2 00 20 95 E5 00 30 96 E5 03 00 52 E1 02 00 A0 E1 F5 FF FF 0A ?? ?? ?? EB 00 40 A0 E1 00 00 96 E5 ?? ?? ?? EB 00 00 54 E1 EF FF FF 0A 00 00 95 E5 ?? ?? ?? EB 00 40 A0 E1 00 00 96 E5 ?? ?? ?? EB 00 00 54 E1 00 00 E0 33 01 00 A0 23 70 80 BD E8 }
	condition:
		$pattern
}

rule xdrrec_setpos_b4b7c2363042a7875fa12c3354c3e64c {
	meta:
		aliases = "xdrrec_setpos"
		size = "176"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 50 A0 E1 01 60 A0 E1 0C 40 90 E5 DF FF FF EB 01 00 70 E3 00 30 A0 E1 20 00 00 0A 00 00 95 E5 00 00 50 E3 03 10 66 E0 02 00 00 0A 01 00 50 E3 1A 00 00 1A 0A 00 00 EA 10 30 94 E5 18 20 94 E5 03 00 61 E0 02 00 50 E1 14 00 00 9A 14 30 94 E5 03 00 50 E1 01 10 A0 33 10 00 84 35 10 00 00 3A 0E 00 00 EA 34 00 94 E5 00 00 51 E1 2C 20 94 E5 0A 00 00 AA 30 30 94 E5 02 20 61 E0 03 00 52 E1 06 00 00 8A 28 30 94 E5 03 00 52 E1 00 30 61 20 01 10 A0 23 34 30 84 25 2C 20 84 25 00 00 00 2A 00 10 A0 E3 01 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule __old_sem_post_63d29fd2eb23c5eb5f826602a9fbd61d {
	meta:
		aliases = "__old_sem_post"
		size = "216"
		objfiles = "oldsemaphore@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 50 A0 E1 04 D0 4D E2 00 40 95 E5 01 60 14 E2 03 20 A0 E3 07 00 00 0A 06 01 74 E3 02 20 84 E2 04 00 00 1A ?? ?? ?? EB 22 30 A0 E3 00 20 E0 E3 00 30 80 E5 23 00 00 EA 05 00 A0 E1 04 10 A0 E1 D3 FF FF EB 00 00 50 E3 EE FF FF 0A 00 00 56 E3 04 10 A0 01 00 60 8D 05 0E 00 00 0A 18 00 00 EA 08 E0 91 E5 0D C0 A0 E1 00 00 00 EA 08 C0 80 E2 00 00 9C E5 00 00 50 E3 03 00 00 0A 18 20 91 E5 18 30 90 E5 03 00 52 E1 F7 FF FF BA 08 00 81 E5 00 10 8C E5 0E 10 A0 E1 01 00 51 E3 EF FF FF 1A 04 00 00 EA 08 30 92 E5 00 30 8D E5 00 30 A0 E3 08 30 82 E5 ?? ?? ?? EB 00 20 9D E5 00 00 52 E2 F7 FF FF 1A }
	condition:
		$pattern
}

rule logout_dd16767a55a340ad9c520e967d5385b9 {
	meta:
		aliases = "logout"
		size = "184"
		objfiles = "logout@libutil.a"
	strings:
		$pattern = { 70 40 2D E9 00 50 A0 E1 06 DD 4D E2 A0 00 9F E5 ?? ?? ?? EB 00 60 A0 E3 01 00 70 E3 06 40 A0 E1 20 00 00 0A ?? ?? ?? EB 05 10 A0 E1 20 20 A0 E3 07 30 A0 E3 08 00 8D E2 00 30 CD E5 01 60 CD E5 ?? ?? ?? EB 0D 00 A0 E1 ?? ?? ?? EB 00 40 50 E2 06 10 A0 E1 20 20 A0 E3 2C 00 84 E2 0F 00 00 0A ?? ?? ?? EB 01 2C A0 E3 06 10 A0 E1 4C 00 84 E2 ?? ?? ?? EB 06 10 A0 E1 55 0F 84 E2 ?? ?? ?? EB 08 30 A0 E3 00 30 C4 E5 01 60 C4 E5 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 01 40 A0 E3 00 00 00 1A 00 40 A0 E3 ?? ?? ?? EB 04 00 A0 E1 06 DD 8D E2 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule remove_2ec7e5ec624b66e8ca409c797a31fe98 {
	meta:
		aliases = "__GI_remove, remove"
		size = "72"
		objfiles = "remove@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 50 A0 E1 ?? ?? ?? EB 00 40 A0 E1 05 00 A0 E1 00 60 94 E5 ?? ?? ?? EB 00 20 50 E2 06 00 00 AA 00 30 94 E5 14 00 53 E3 05 00 A0 E1 02 00 00 1A 00 60 84 E5 70 40 BD E8 ?? ?? ?? EA 02 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule confstr_d0118859addf11da14cc05ab989c17b1 {
	meta:
		aliases = "confstr"
		size = "128"
		objfiles = "confstr@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 50 E2 01 50 A0 E1 02 40 A0 E1 04 00 00 1A 00 00 52 E3 00 00 51 13 0E 20 A0 E3 05 00 00 1A 12 00 00 EA ?? ?? ?? EB 16 30 A0 E3 00 20 A0 E3 00 30 80 E5 0D 00 00 EA 0D 00 54 E3 01 00 A0 E1 0E 20 A0 E3 2C 10 9F E5 01 00 00 9A ?? ?? ?? EB 05 00 00 EA 05 00 A0 E1 18 10 9F E5 01 20 44 E2 ?? ?? ?? EB 04 30 85 E0 01 60 43 E5 0E 20 A0 E3 02 00 A0 E1 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule parse_lsda_header_fc2d5cd436b169e48e7d0f521170137c {
	meta:
		aliases = "parse_lsda_header"
		size = "188"
		objfiles = "unwind_c@libgcc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 50 E2 04 D0 4D E2 06 E0 A0 E1 02 50 A0 E1 01 40 A0 E1 01 00 00 0A ?? ?? ?? EB 00 E0 A0 E1 00 E0 85 E5 01 20 D4 E4 FF 00 52 E3 02 10 A0 E1 06 00 A0 E1 04 30 85 E2 04 C0 A0 E1 04 20 A0 E1 04 E0 85 05 01 00 00 0A DD FF FF EB 00 C0 A0 E1 01 30 DC E4 FF 00 53 E3 14 30 C5 E5 00 30 A0 03 0D 40 A0 E1 0C 20 A0 E1 0C 00 A0 E1 0D 10 A0 E1 0C 30 85 05 0D 40 A0 01 04 00 00 0A 3C FF FF EB 00 30 9D E5 03 30 80 E0 0C 30 85 E5 00 20 A0 E1 01 30 D2 E4 0D 10 A0 E1 15 30 C5 E5 02 00 A0 E1 33 FF FF EB 00 30 9D E5 03 20 80 E0 10 20 85 E5 04 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule re_comp_224a6b81f9b3caf0e2eb3319be9e7b3c {
	meta:
		aliases = "re_comp"
		size = "220"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 50 E2 B4 40 9F E5 04 00 00 1A 00 30 94 E5 00 00 53 E3 A8 00 9F 05 70 80 BD 08 25 00 00 EA 00 30 94 E5 00 00 53 E3 04 50 A0 E1 0D 00 00 1A C8 00 A0 E3 ?? ?? ?? EB 00 00 50 E3 00 00 84 E5 06 00 00 0A C8 30 A0 E3 01 0C A0 E3 04 30 84 E5 ?? ?? ?? EB 00 00 50 E3 10 00 84 E5 01 00 00 1A 60 00 9F E5 70 80 BD E8 50 40 9F E5 1C 30 D4 E5 83 3C E0 E1 A3 3C E0 E1 1C 30 C4 E5 06 00 A0 E1 ?? ?? ?? EB 40 30 9F E5 00 10 A0 E1 00 20 93 E5 06 00 A0 E1 04 30 A0 E1 20 F7 FF EB 00 00 50 E3 04 00 00 0A 24 30 9F E5 00 21 93 E7 20 30 9F E5 03 00 82 E0 70 80 BD E8 00 00 A0 E3 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule hcreate_r_88211142d15ff67804981acad6cfc65e {
	meta:
		aliases = "__GI_hcreate_r, hcreate_r"
		size = "168"
		objfiles = "hcreate_r@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 51 E2 04 00 00 1A ?? ?? ?? EB 16 30 A0 E3 06 10 A0 E1 00 30 80 E5 1F 00 00 EA 00 30 96 E5 00 00 53 E3 00 10 A0 13 01 40 80 03 01 00 00 0A 19 00 00 EA 02 40 84 E2 03 50 A0 E3 00 00 00 EA 02 50 85 E2 95 05 03 E0 04 00 53 E1 05 10 A0 E1 04 00 A0 E1 02 00 00 2A ?? ?? ?? EB 00 00 50 E3 F6 FF FF 1A 05 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 EE FF FF 0A 00 30 A0 E3 0C 10 A0 E3 08 30 86 E5 04 40 86 E5 01 00 84 E2 ?? ?? ?? EB 00 00 86 E5 00 10 50 E2 01 10 A0 13 01 00 A0 E1 70 80 BD E8 }
	condition:
		$pattern
}

rule __GI_xdr_u_hyper_b5d3eac42b33a6dc75fc9a50a668be64 {
	meta:
		aliases = "xdr_u_hyper, __GI_xdr_u_hyper"
		size = "232"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 90 E5 00 00 56 E3 08 D0 4D E2 00 40 A0 E1 01 50 A0 E1 12 00 00 1A 00 30 91 E5 04 10 91 E5 00 30 8D E5 04 10 8D E5 04 10 8D E2 04 30 90 E5 0F E0 A0 E1 04 F0 93 E5 00 00 50 E3 06 00 A0 01 25 00 00 0A 04 00 A0 E1 04 30 94 E5 0D 10 A0 E1 0F E0 A0 E1 04 F0 93 E5 00 00 50 E2 01 00 A0 13 1D 00 00 EA 01 00 56 E3 16 00 00 1A 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 14 00 00 0A 04 00 A0 E1 04 30 94 E5 0D 10 A0 E1 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 0D 00 00 0A 04 30 9D E5 04 30 85 E5 00 30 A0 E3 00 30 85 E5 00 20 9D E5 18 00 95 E8 06 00 A0 E1 02 30 83 E1 18 00 85 E8 }
	condition:
		$pattern
}

rule xdr_uint64_t_0c1bf83071d8bb9b34dbb7a0a8ae0554 {
	meta:
		aliases = "xdr_uint64_t"
		size = "224"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 90 E5 01 00 56 E3 08 D0 4D E2 00 40 A0 E1 01 50 A0 E1 16 00 00 0A 03 00 00 3A 02 00 56 E3 01 00 A0 03 2A 00 00 0A 28 00 00 EA 00 30 91 E5 04 10 91 E5 00 30 8D E5 04 10 8D E5 04 10 8D E2 04 30 90 E5 0F E0 A0 E1 24 F0 93 E5 00 00 50 E3 1F 00 00 0A 04 00 A0 E1 04 30 94 E5 0D 10 A0 E1 0F E0 A0 E1 24 F0 93 E5 00 00 50 E2 01 00 A0 13 17 00 00 EA 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 10 00 00 0A 04 00 A0 E1 04 30 94 E5 0D 10 A0 E1 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 09 00 00 0A 04 30 9D E5 04 30 85 E5 00 30 A0 E3 00 30 85 E5 00 20 9D E5 18 00 95 E8 06 00 A0 E1 }
	condition:
		$pattern
}

rule byte_common_op_match_null_stri_d2fd880b1ebe365cd22a5df8f24de8ec {
	meta:
		aliases = "byte_common_op_match_null_string_p"
		size = "320"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 00 00 90 E5 04 D0 4D E2 00 00 8D E5 00 C0 A0 E1 01 30 DC E4 0C 00 53 E3 00 C0 8D E5 02 50 A0 E1 08 00 00 8A 09 00 53 E3 3B 00 00 2A 06 00 53 E3 0E 00 00 0A 08 00 53 E3 33 00 00 0A 00 00 53 E3 35 00 00 0A 38 00 00 EA 15 00 53 E3 1E 00 00 0A 02 00 00 8A 0D 00 53 E3 33 00 00 1A 12 00 00 EA 1A 30 43 E2 03 00 53 E3 2F 00 00 8A 2A 00 00 EA 01 40 D0 E5 0D 00 A0 E1 4D 00 00 EB 04 41 A0 E1 04 30 D5 E7 03 30 03 E2 03 00 53 E3 04 20 95 07 03 30 00 02 03 20 C2 03 02 20 83 01 04 20 85 07 00 00 50 E3 1C 00 00 1A 1F 00 00 EA 01 30 DC E5 01 20 D0 E5 03 3C A0 E1 43 28 92 E0 03 30 80 52 }
	condition:
		$pattern
}

rule __GI_getrpcbyname_23160896e26b42ec41c579750ada4d3e {
	meta:
		aliases = "getrpcbyname, __GI_getrpcbyname"
		size = "104"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 00 00 A0 E3 ?? ?? ?? EB 0E 00 00 EA 00 00 95 E5 06 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 0D 00 00 0A 04 40 95 E5 02 00 00 EA ?? ?? ?? EB 00 00 50 E3 08 00 00 0A 00 30 94 E5 00 00 53 E2 06 10 A0 E1 04 40 84 E2 F7 FF FF 1A ?? ?? ?? EB 00 50 50 E2 ED FF FF 1A ?? ?? ?? EB 05 00 A0 E1 70 80 BD E8 }
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

rule pthread_attr_setguardsize_b93ff43739e686df7b9f78a1df48c81c {
	meta:
		aliases = "__pthread_attr_setguardsize, pthread_attr_setguardsize"
		size = "64"
		objfiles = "attr@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 01 40 A0 E1 ?? ?? ?? EB 00 50 A0 E1 00 40 84 E0 05 10 A0 E1 01 00 44 E2 ?? ?? ?? EB 90 05 05 E0 20 30 96 E5 03 00 55 E1 16 00 A0 E3 00 00 A0 33 14 50 86 35 70 80 BD E8 }
	condition:
		$pattern
}

rule daemon_f3df048b4a7a738fd12df9d279ff65f2 {
	meta:
		aliases = "daemon"
		size = "200"
		objfiles = "daemon@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 01 50 A0 E1 ?? ?? ?? EB 01 00 70 E3 00 40 A0 E1 24 00 00 0A 00 00 50 E3 00 00 A0 13 06 00 00 1A ?? ?? ?? EB 01 00 70 E3 1E 00 00 0A ?? ?? ?? EB 00 00 50 E3 01 00 00 0A 04 00 A0 E1 ?? ?? ?? EB 00 00 56 E3 6C 00 9F 05 ?? ?? ?? 0B 00 00 55 E3 16 00 00 1A 60 00 9F E5 02 10 A0 E3 05 20 A0 E1 ?? ?? ?? EB 01 00 70 E3 00 40 A0 E1 0F 00 00 0A 05 10 A0 E1 ?? ?? ?? EB 01 10 A0 E3 04 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 02 10 A0 E3 ?? ?? ?? EB 02 00 54 E3 05 00 00 DA 04 00 A0 E1 ?? ?? ?? EB 05 00 A0 E1 70 80 BD E8 00 00 E0 E3 70 80 BD E8 00 00 A0 E3 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_cleanup_push_defer_80c9bd9ce4fe1f1677c151cdfc1804c4 {
	meta:
		aliases = "_pthread_cleanup_push_defer, __pthread_cleanup_push_defer"
		size = "76"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 02 50 A0 E1 01 40 A0 E1 C8 FF FF EB 30 00 86 E8 3C 20 90 E5 41 30 D0 E5 00 00 52 E3 08 30 86 E5 0C 20 86 E5 02 00 00 0A 02 00 56 E1 00 30 A0 23 0C 30 86 25 00 30 A0 E3 3C 60 80 E5 41 30 C0 E5 70 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_acquire_bfc6d2673666689e50a197bd875a2dd1 {
	meta:
		aliases = "__pthread_acquire"
		size = "100"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 08 D0 4D E2 00 50 A0 E3 0C 00 00 EA 00 40 A0 E3 31 00 55 E3 0D 00 A0 E1 04 10 A0 E1 01 50 85 E2 01 00 00 CA ?? ?? ?? EB 04 00 00 EA 24 30 9F E5 00 40 8D E5 04 30 8D E5 ?? ?? ?? EB 04 50 A0 E1 01 30 A0 E3 93 30 06 E1 00 00 53 E3 EE FF FF 1A 08 D0 8D E2 70 80 BD E8 81 84 1E 00 }
	condition:
		$pattern
}

rule __getutid_84ae50658fbc30453b3ef703b6ba2ea8 {
	meta:
		aliases = "__getutid"
		size = "160"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 19 00 00 EA 01 30 D6 E5 00 C0 D6 E5 03 C4 8C E1 01 30 4C E2 03 38 A0 E1 0C E8 A0 E1 03 08 53 E3 4E E8 A0 E1 0C 58 A0 E1 05 00 00 8A 01 30 D4 E5 00 C0 D4 E5 03 3C A0 E1 43 C8 8C E1 45 08 5C E1 11 00 00 0A 08 00 5E E3 05 00 5E 13 03 00 00 0A 06 00 5E E3 01 00 00 0A 07 00 5E E3 02 00 00 1A ?? ?? ?? EB 00 00 50 E3 07 00 00 0A 20 30 9F E5 00 00 93 E5 D0 FF FF EB 00 40 50 E2 28 10 86 E2 04 20 A0 E3 28 00 84 E2 DD FF FF 1A 04 00 A0 E1 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __pthread_perform_cleanup_9e70bdbda4a7dcd38b6bebc38f5f9edb {
	meta:
		aliases = "__pthread_perform_cleanup"
		size = "76"
		objfiles = "cancel@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 00 60 A0 E1 DD FF FF EB 3C 40 90 E5 00 50 A0 E1 05 00 00 EA 06 00 54 E1 05 00 00 9A 04 00 94 E5 0F E0 A0 E1 00 F0 94 E5 0C 40 94 E5 00 00 54 E3 F7 FF FF 1A 74 31 95 E5 00 00 53 E3 70 80 BD 08 70 40 BD E8 ?? ?? ?? EA }
	condition:
		$pattern
}

rule __popcountdi2_6d72c60ad93b17028568227a8a0274be {
	meta:
		aliases = "__popcountdi2"
		size = "84"
		objfiles = "_popcountdi2@libgcc.a"
	strings:
		$pattern = { 70 40 2D E9 00 C0 A0 E3 40 E0 9F E5 00 50 A0 E1 01 60 A0 E1 0C 00 A0 E1 35 30 A0 E1 20 20 60 E2 16 32 83 E1 20 10 50 E2 36 31 A0 51 FF 30 03 E2 36 40 A0 E1 03 20 DE E7 08 00 80 E2 40 00 50 E3 02 C0 8C E0 F3 FF FF 1A 0C 00 A0 E1 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __stdio_adjust_position_68598c91a3fe24adf5466bfaa2725dd3 {
	meta:
		aliases = "__stdio_adjust_position"
		size = "204"
		objfiles = "_adjust_pos@libc.a"
	strings:
		$pattern = { 70 40 2D E9 01 30 D0 E5 00 20 D0 E5 03 E4 82 E1 03 30 1E E2 01 60 A0 E1 03 C0 A0 01 0F 00 00 0A 01 C0 53 E2 0D 00 00 0A 02 0B 1E E3 0B 00 00 0A 01 00 5C E3 21 00 00 CA 28 30 90 E5 00 00 53 E3 1E 00 00 1A 03 30 D0 E5 2C 20 90 E5 0C 30 63 E0 00 00 52 E3 01 C0 43 E2 02 30 D0 C5 0C C0 63 C0 40 00 1E E3 08 20 90 15 14 20 90 05 10 30 90 E5 02 30 63 E0 06 00 96 E8 03 50 8C E0 05 30 51 E0 C5 4F C2 E0 18 00 86 E8 04 30 96 E5 02 00 53 E1 03 00 00 CA 03 00 00 1A 00 30 96 E5 01 00 53 E1 00 00 00 9A 00 50 65 E2 00 00 55 E3 04 00 00 AA ?? ?? ?? EB 4B 30 A0 E3 00 30 80 E5 00 00 00 EA 00 50 E0 E3 05 00 A0 E1 }
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

rule fputws_unlocked_0c812d83ea9d970f7192c147d9775ccb {
	meta:
		aliases = "__GI_fputws_unlocked, fputws_unlocked"
		size = "52"
		objfiles = "fputws_unlocked@libc.a"
	strings:
		$pattern = { 70 40 2D E9 01 40 A0 E1 00 50 A0 E1 ?? ?? ?? EB 00 60 A0 E1 06 10 A0 E1 05 00 A0 E1 04 20 A0 E1 ?? ?? ?? EB 06 00 50 E1 00 00 E0 13 00 00 A0 03 70 80 BD E8 }
	condition:
		$pattern
}

rule read_encoded_value_0c6d02878350871bc572f23ae37809a7 {
	meta:
		aliases = "read_encoded_value"
		size = "56"
		objfiles = "unwind_c@libgcc.a"
	strings:
		$pattern = { 70 40 2D E9 01 40 A0 E1 FF 40 04 E2 00 10 A0 E1 04 00 A0 E1 02 50 A0 E1 03 60 A0 E1 D8 FF FF EB 05 20 A0 E1 00 10 A0 E1 06 30 A0 E1 04 00 A0 E1 70 40 BD E8 79 FF FF EA }
	condition:
		$pattern
}

rule fputs_unlocked_48e3905df4b4856817f022f6fcec5473 {
	meta:
		aliases = "__GI_fputs_unlocked, fputs_unlocked"
		size = "52"
		objfiles = "fputs_unlocked@libc.a"
	strings:
		$pattern = { 70 40 2D E9 01 50 A0 E1 00 40 A0 E1 ?? ?? ?? EB 00 60 A0 E1 05 30 A0 E1 04 00 A0 E1 01 10 A0 E3 06 20 A0 E1 ?? ?? ?? EB 06 00 50 E1 00 00 E0 13 70 80 BD E8 }
	condition:
		$pattern
}

rule byte_alt_match_null_string_p_91271090c9aad0e7eab5b7ce64f83dcc {
	meta:
		aliases = "byte_alt_match_null_string_p"
		size = "124"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { 70 40 2D E9 01 50 A0 E1 04 D0 4D E2 02 60 A0 E1 00 00 8D E5 0D 00 00 EA 00 30 DC E5 0F 00 53 E3 07 00 00 1A 00 E0 8D E5 01 20 DE E5 01 30 DC E5 02 2C A0 E1 42 38 83 E0 03 30 84 E0 00 30 8D E5 02 00 00 EA 9D FF FF EB 00 00 50 E3 08 00 00 0A 00 C0 9D E5 05 00 5C E1 0D 00 A0 E1 05 10 A0 E1 06 20 A0 E1 01 E0 8C E2 03 40 8C E2 E9 FF FF 3A 01 00 A0 E3 04 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule __libc_lseek64_dff4efe895f949610f8fff577ccbcde2 {
	meta:
		aliases = "lseek64, __GI_lseek64, __libc_lseek64"
		size = "100"
		objfiles = "llseek@libc.a"
	strings:
		$pattern = { 70 40 2D E9 01 50 A0 E1 08 D0 4D E2 02 60 A0 E1 02 10 A0 E1 03 40 A0 E1 05 20 A0 E1 0D 30 A0 E1 8C 00 90 EF 01 0A 70 E3 00 40 A0 E1 04 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 40 E0 E3 00 30 80 E5 01 00 00 EA 00 00 50 E3 02 00 00 0A 04 00 A0 E1 C0 1F A0 E1 00 00 00 EA 03 00 9D E8 08 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule __xstat_conv_10a745d5a72fee7417c2ce9e68ad7228 {
	meta:
		aliases = "__xstat_conv"
		size = "204"
		objfiles = "xstatconv@libc.a"
	strings:
		$pattern = { 70 40 2D E9 01 60 A0 E1 00 50 A0 E1 00 10 A0 E3 58 20 A0 E3 06 00 A0 E1 ?? ?? ?? EB 00 30 95 E5 04 20 95 E5 00 40 A0 E3 18 00 86 E8 0C 20 86 E5 09 20 D5 E5 08 30 D5 E5 02 34 83 E1 10 30 86 E5 0B 20 D5 E5 0A 30 D5 E5 02 34 83 E1 14 30 86 E5 0D 20 D5 E5 0C 30 D5 E5 02 34 83 E1 18 30 86 E5 14 30 95 E5 0E 00 D5 E5 0F C0 D5 E5 10 10 95 E5 2C 30 86 E5 18 30 95 E5 30 30 86 E5 1C 30 95 E5 34 30 86 E5 20 30 95 E5 38 30 86 E5 28 30 95 E5 40 30 86 E5 30 30 95 E5 48 30 86 E5 24 30 95 E5 3C 30 86 E5 2C 30 95 E5 0C 04 80 E1 00 20 A0 E3 1C 00 86 E5 20 10 86 E5 24 20 86 E5 44 30 86 E5 34 30 95 E5 4C 30 86 E5 }
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

rule addmntent_8601edbe065f681e698f975eba806805 {
	meta:
		aliases = "addmntent"
		size = "104"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { 70 40 2D E9 02 20 A0 E3 10 D0 4D E2 01 60 A0 E1 00 10 A0 E3 00 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 3C 10 9F E5 04 00 A0 E1 01 30 A0 E3 09 00 00 BA 08 C0 86 E2 00 50 9C E8 10 40 86 E2 30 00 94 E8 0C 00 96 E8 00 50 8D E8 08 40 8D E5 0C 50 8D E5 ?? ?? ?? EB A0 3F A0 E1 03 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? }
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

rule _charpad_eeecc28d713db49304a4b8165a41cbaa {
	meta:
		aliases = "_charpad"
		size = "76"
		objfiles = "_vfwprintf_internal@libc.a"
	strings:
		$pattern = { 70 40 2D E9 02 50 A0 E1 04 D0 4D E2 00 60 A0 E1 02 40 A0 E1 00 10 8D E5 00 00 00 EA 01 40 44 E2 00 00 54 E3 0D 00 A0 E1 01 10 A0 E3 06 20 A0 E1 02 00 00 0A ?? ?? ?? EB 01 00 50 E3 F6 FF FF 0A 05 00 64 E0 04 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule _charpad_169f0a233f86704eb783c58951641524 {
	meta:
		aliases = "_charpad"
		size = "76"
		objfiles = "_vfprintf_internal@libc.a"
	strings:
		$pattern = { 70 40 2D E9 02 50 A0 E1 04 D0 4D E2 00 60 A0 E1 02 40 A0 E1 03 10 CD E5 00 00 00 EA 01 40 44 E2 00 00 54 E3 03 00 8D E2 01 10 A0 E3 06 20 A0 E1 02 00 00 0A ?? ?? ?? EB 01 00 50 E3 F6 FF FF 0A 05 00 64 E0 04 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule sendmsg_1823f96336634c69108f5ddfbc5d7589 {
	meta:
		aliases = "lseek, write, accept, waitpid, read, recvmsg, msync, connect, __GI_waitpid, sendmsg"
		size = "76"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 04 D0 4D E2 00 40 A0 E1 01 50 A0 E1 02 60 A0 E1 0D 10 A0 E1 01 00 A0 E3 ?? ?? ?? EB 05 10 A0 E1 06 20 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 10 A0 E3 00 40 A0 E1 00 00 9D E5 ?? ?? ?? EB 04 00 A0 E1 04 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule __GI_ether_ntoa_r_8600950ba51f116eb718aecac334bf80 {
	meta:
		aliases = "ether_ntoa_r, __GI_ether_ntoa_r"
		size = "76"
		objfiles = "ether_addr@libc.a"
	strings:
		$pattern = { 70 40 2D E9 05 60 D0 E5 02 C0 D0 E5 03 E0 D0 E5 04 40 D0 E5 00 20 D0 E5 01 30 D0 E5 10 D0 4D E2 01 50 A0 E1 01 00 A0 E1 18 10 9F E5 00 50 8D E8 08 40 8D E5 0C 60 8D E5 ?? ?? ?? EB 05 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule svc_getreq_common_4c80d7fc6bbf26bad390800682abba95 {
	meta:
		aliases = "__GI_svc_getreq_common, svc_getreq_common"
		size = "416"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { 70 40 2D E9 05 DC 4D E2 19 3E 8D E2 D8 34 8D E5 00 40 A0 E1 CC D4 8D E5 ?? ?? ?? EB B4 30 90 E5 04 41 93 E7 00 00 54 E3 00 60 A0 E1 58 00 00 0A 4B 5E 8D E2 08 30 94 E5 04 00 A0 E1 05 10 A0 E1 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 43 00 00 0A 13 3D 8D E2 08 30 83 E2 07 00 93 E8 4E 3E 8D E2 0C 30 83 E2 07 00 83 E8 32 3E 8D E2 F8 34 8D E5 BC 34 9D E5 E0 34 8D E5 C0 34 9D E5 C8 C4 9D E5 E4 34 8D E5 C4 34 9D E5 00 00 5C E3 E8 34 8D E5 FC 44 8D E5 05 00 00 1A FC 30 9F E5 00 30 93 E5 20 30 84 E5 FC 34 9D E5 28 C0 83 E5 08 00 00 EA 05 10 A0 E1 4E 0E 8D E2 ?? ?? ?? EB 00 00 50 E3 03 00 00 0A 00 10 A0 E1 }
	condition:
		$pattern
}

rule __ieee754_yn_5f7a0d4015cb0a488f7458a8659d9624 {
	meta:
		aliases = "__ieee754_yn"
		size = "552"
		objfiles = "e_jn@libm.a"
	strings:
		$pattern = { 70 40 2D E9 06 42 6D ED 06 00 2D E9 02 D1 BD EC 02 40 A0 E1 01 30 A0 E1 03 E0 A0 E1 00 30 64 E2 03 30 84 E1 02 C1 CE E3 F0 21 9F E5 A3 3F 8C E1 02 00 53 E1 04 10 A0 E1 00 50 A0 E1 85 11 05 8E 71 00 00 8A 01 10 9C E1 89 81 10 0E 88 11 40 0E 6D 00 00 0A 00 00 5E E3 88 81 00 BE 80 11 40 BE 69 00 00 BA 00 00 50 E3 00 50 60 B2 01 30 05 B2 83 30 A0 B1 01 60 A0 A3 01 60 63 B2 00 00 55 E3 04 00 00 1A 02 D1 2D ED 03 00 BD E8 06 42 FD EC 70 40 BD E8 ?? ?? ?? EA 01 00 55 E3 05 00 00 1A 02 D1 2D ED 03 00 BD E8 ?? ?? ?? EB 90 61 01 EE 80 11 11 EE 54 00 00 EA 60 31 9F E5 03 00 5C E1 88 91 00 0E 50 00 00 0A }
	condition:
		$pattern
}

rule _Unwind_SjLj_Resume_b91d54f588c2523fd3687c7645538ec0 {
	meta:
		aliases = "_Unwind_SjLj_Resume"
		size = "96"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { 70 40 2D E9 08 D0 4D E2 04 60 8D E2 00 40 A0 E1 06 00 A0 E1 62 FF FF EB 0C 30 94 E5 04 20 9D E5 00 00 53 E3 00 20 8D E5 05 00 00 1A 04 00 A0 E1 0D 10 A0 E1 BC FF FF EB 07 00 50 E3 04 00 00 0A ?? ?? ?? EB 04 00 A0 E1 0D 10 A0 E1 5B FF FF EB F8 FF FF EA 06 00 A0 E1 0D 10 A0 E1 DB FF FF EB }
	condition:
		$pattern
}

rule get_cie_encoding_c7ccfa835df881942cc21308f87b3c27 {
	meta:
		aliases = "get_cie_encoding"
		size = "212"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { 70 40 2D E9 09 30 D0 E5 7A 00 53 E3 0C D0 4D E2 00 40 A0 E1 09 50 80 E2 02 00 00 0A 00 00 A0 E3 0C D0 8D E2 70 80 BD E8 05 00 A0 E1 ?? ?? ?? EB 04 60 8D E2 00 00 85 E0 06 10 A0 E1 01 00 80 E2 B6 FD FF EB 0D 10 A0 E1 BE FD FF EB 08 30 D4 E5 01 00 53 E3 01 00 80 02 06 10 A0 11 AF FD FF 1B 06 10 A0 E1 AD FD FF EB 00 20 A0 E1 01 00 D5 E5 52 00 50 E3 05 40 A0 11 07 00 00 1A 12 00 00 EA 4C 00 50 E3 01 20 82 E2 E3 FF FF 1A 02 00 D4 E5 52 00 50 E3 01 40 84 E2 0B 00 00 0A 50 00 50 E3 00 10 A0 E3 08 30 8D E2 F4 FF FF 1A 01 00 D2 E4 7F 00 00 E2 1C FF FF EB 00 20 A0 E1 02 00 D4 E5 52 00 50 E3 01 40 84 E2 }
	condition:
		$pattern
}

rule _Unwind_SjLj_Resume_or_Rethrow_a16eb65918b370c7f1b5afdffa7bd374 {
	meta:
		aliases = "_Unwind_SjLj_Resume_or_Rethrow"
		size = "92"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { 70 40 2D E9 0C 30 90 E5 00 00 53 E3 08 D0 4D E2 00 40 A0 E1 0A 00 00 0A 04 60 8D E2 06 00 A0 E1 FB FE FF EB 04 30 9D E5 04 00 A0 E1 0D 10 A0 E1 00 30 8D E5 FD FE FF EB 07 00 50 E3 03 00 00 0A ?? ?? ?? EB ?? ?? ?? EB 08 D0 8D E2 70 80 BD E8 06 00 A0 E1 0D 10 A0 E1 78 FF FF EB }
	condition:
		$pattern
}

rule __ieee754_y0_278896f90c4df3b9be5407985e49b8ff {
	meta:
		aliases = "__ieee754_y0"
		size = "620"
		objfiles = "e_j0@libm.a"
	strings:
		$pattern = { 70 40 2D E9 0C 42 2D ED 54 32 9F E5 02 61 C0 E3 01 50 A0 E1 03 00 56 E1 00 40 A0 E1 08 D0 4D E2 03 00 2D E9 02 E1 BD EC 05 40 A0 E1 86 01 16 CE 80 01 06 CE 89 01 50 CE 6C 00 00 CA 04 40 96 E1 89 81 10 0E 88 01 40 0E 68 00 00 0A 00 00 50 E3 88 91 00 BE 81 01 41 BE 64 00 00 BA 07 01 76 E3 30 00 00 DA ?? ?? ?? EB 02 E1 2D ED 03 00 BD E8 80 D1 00 EE ?? ?? ?? EB E8 31 9F E5 80 C1 00 EE 80 71 25 EE 03 00 56 E1 80 01 05 EE 00 81 8D ED 0A 00 00 CA 86 11 06 EE 02 91 2D ED 03 00 BD E8 ?? ?? ?? EB 84 11 15 EE 18 F1 D1 EE 80 81 10 EE 87 01 40 4E 00 91 9D 5D 00 81 8D 4D 81 71 40 5E 12 03 56 E3 06 00 00 DA }
	condition:
		$pattern
}

rule __ieee754_y1_45900b26e74c404cc21735f3fb0d6665 {
	meta:
		aliases = "__ieee754_y1"
		size = "624"
		objfiles = "e_j1@libm.a"
	strings:
		$pattern = { 70 40 2D E9 0C 42 2D ED 54 32 9F E5 02 61 C0 E3 01 50 A0 E1 03 00 56 E1 00 40 A0 E1 08 D0 4D E2 03 00 2D E9 02 E1 BD EC 05 40 A0 E1 86 01 16 CE 80 01 06 CE 89 01 50 CE 6C 00 00 CA 04 40 96 E1 89 81 10 0E 88 01 40 0E 68 00 00 0A 00 00 50 E3 88 91 00 BE 81 01 41 BE 64 00 00 BA 07 01 76 E3 32 00 00 DA ?? ?? ?? EB 02 E1 2D ED 03 00 BD E8 80 D1 00 EE ?? ?? ?? EB E8 31 9F E5 80 C1 00 EE 85 81 10 EE 84 71 20 EE 03 00 56 E1 84 01 25 EE 00 81 8D ED 0A 00 00 CA 86 11 06 EE 02 91 2D ED 03 00 BD E8 ?? ?? ?? EB 80 91 00 EE 84 01 15 EE 18 F1 D0 EE 87 11 41 CE 00 81 9D DD 00 91 8D CD 80 71 41 DE 12 03 56 E3 }
	condition:
		$pattern
}

rule pthread_rwlock_tryrdlock_e7b378bd9d3eae7be2dda053e6d5600f {
	meta:
		aliases = "pthread_rwlock_tryrdlock"
		size = "180"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 0C D0 4D E2 00 40 A0 E1 76 FF FF EB 0C 30 8D E2 04 00 23 E5 04 20 8D E2 03 00 A0 E1 04 10 A0 E1 0D 30 A0 E1 BC FF FF EB 08 10 9D E5 00 60 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 10 A0 E3 04 00 A0 E1 1E FF FF EB 00 00 50 E3 08 30 94 15 01 30 83 12 10 50 A0 E3 08 30 84 15 00 50 A0 13 04 00 A0 E1 ?? ?? ?? EB 00 00 55 E3 0D 00 00 1A 00 00 56 E3 02 00 00 1A 00 30 9D E5 00 00 53 E3 08 00 00 0A 04 20 9D E5 00 00 52 E3 08 20 9D 05 08 30 92 15 C8 31 92 05 01 30 83 12 01 30 83 02 08 30 82 15 C8 31 82 05 05 00 A0 E1 0C D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule pthread_cond_wait_26b79a488e94518f9157a1c5edf0a050 {
	meta:
		aliases = "__GI_pthread_cond_wait, pthread_cond_wait"
		size = "408"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 0C D0 4D E2 01 60 A0 E1 00 50 A0 E1 47 FF FF EB 0C 30 96 E5 03 00 53 E3 00 00 53 13 08 00 8D E5 04 00 00 0A 08 20 9D E5 08 30 96 E5 02 00 53 E1 16 00 A0 13 51 00 00 1A 48 31 9F E5 08 20 9D E5 04 30 8D E5 00 30 A0 E3 00 50 8D E5 B9 31 C2 E5 08 00 9D E5 0D 10 A0 E1 0C FF FF EB 05 00 A0 E1 08 10 9D E5 ?? ?? ?? EB 08 30 9D E5 42 30 D3 E5 00 00 53 E3 04 00 00 0A 08 30 9D E5 40 30 D3 E5 00 00 53 E3 01 40 A0 03 03 00 00 0A 08 10 9D E5 08 00 85 E2 C8 FE FF EB 00 40 A0 E3 05 00 A0 E1 ?? ?? ?? EB 00 00 54 E3 03 00 00 0A 08 00 9D E5 00 10 A0 E3 F5 FE FF EB 24 00 00 EA 06 00 A0 E1 C4 30 9F E5 }
	condition:
		$pattern
}

rule scan_getwc_ee5794f85f8714517329fe73707c79cd {
	meta:
		aliases = "scan_getwc"
		size = "192"
		objfiles = "vfscanf@libc.a"
	strings:
		$pattern = { 70 40 2D E9 10 30 90 E5 01 50 43 E2 00 00 55 E3 02 31 E0 A3 10 50 80 E5 08 D0 4D E2 00 40 A0 E1 02 60 E0 A3 10 30 80 A5 0B 00 00 AA 19 30 D0 E5 00 00 E0 E3 02 30 83 E3 19 30 C4 E5 1D 00 00 EA 00 C0 94 E5 07 C0 CD E5 ?? ?? ?? EB 00 60 50 E2 0E 00 00 AA 02 00 76 E3 07 00 00 1A 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 07 10 8D E2 01 20 A0 E3 1C 30 84 E2 0D 00 A0 E1 F0 FF FF AA 03 00 76 E3 00 30 E0 03 03 60 A0 01 01 00 00 0A 02 00 00 EA 00 30 9D E5 24 30 84 E5 04 00 00 EA ?? ?? ?? EB 54 30 A0 E3 00 30 80 E5 01 30 A0 E3 1B 30 C4 E5 10 50 84 E5 06 00 A0 E1 08 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule search_object_e0c69c11a24dc78fa662879158c9508e {
	meta:
		aliases = "search_object"
		size = "224"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { 70 40 2D E9 10 30 D0 E5 01 00 13 E3 00 40 A0 E1 01 50 A0 E1 13 00 00 0A 04 00 13 E3 0D 00 00 1A 10 30 94 E5 07 30 C3 E3 83 3A A0 E1 A3 3A A0 E1 00 00 53 E3 03 00 00 0A 04 00 A0 E1 05 10 A0 E1 70 40 BD E8 4A FD FF EA 04 00 A0 E1 05 10 A0 E1 70 40 BD E8 BE FC FF EA 04 00 A0 E1 05 10 A0 E1 70 40 BD E8 D7 FD FF EA 97 FF FF EB 00 30 94 E5 03 00 55 E1 09 00 00 3A 10 30 D4 E5 01 00 13 E3 E4 FF FF 1A 02 00 13 E3 06 00 00 1A 0C 10 94 E5 04 00 A0 E1 05 20 A0 E1 70 40 BD E8 31 FE FF EA 00 00 A0 E3 70 80 BD E8 0C 30 94 E5 00 10 93 E5 00 00 51 E3 F9 FF FF 0A 03 60 A0 E1 04 00 A0 E1 05 20 A0 E1 27 FE FF EB }
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

rule __GI_getnetent_c7df4cac2ab78d417c674e5a6339aa52 {
	meta:
		aliases = "getnetent, __GI_getnetent"
		size = "516"
		objfiles = "getnetent@libc.a"
	strings:
		$pattern = { 70 40 2D E9 10 D0 4D E2 0D 00 A0 E1 B4 11 9F E5 B4 21 9F E5 B4 31 9F E5 B4 41 9F E5 0F E0 A0 E1 03 F0 A0 E1 AC 31 9F E5 9C 01 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 94 E5 00 00 53 E3 05 00 00 1A 94 01 9F E5 94 11 9F E5 ?? ?? ?? EB 00 00 50 E3 00 00 84 E5 52 00 00 0A 84 41 9F E5 00 30 94 E5 00 00 53 E3 04 00 00 1A 78 01 9F E5 ?? ?? ?? EB 00 00 50 E3 00 00 84 E5 ?? ?? ?? 0B 60 31 9F E5 00 00 93 E5 48 31 9F E5 01 1A A0 E3 00 20 93 E5 ?? ?? ?? EB 00 40 50 E2 41 00 00 0A 00 30 D4 E5 23 00 53 E3 EB FF FF 0A 3C 11 9F E5 C5 FF FF EB 00 00 50 E3 E7 FF FF 0A 30 31 9F E5 00 50 A0 E3 00 50 C0 E5 28 11 9F E5 }
	condition:
		$pattern
}

rule endhostent_61443e7a101ae5412de971b1b4eb4aa7 {
	meta:
		aliases = "endhostent"
		size = "144"
		objfiles = "gethostent@libc.a"
	strings:
		$pattern = { 70 40 2D E9 10 D0 4D E2 64 10 9F E5 64 20 9F E5 0D 00 A0 E1 60 30 9F E5 60 50 9F E5 0F E0 A0 E1 03 F0 A0 E1 58 30 9F E5 48 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 95 E5 48 30 9F E5 00 40 A0 E3 00 00 50 E3 0D 60 A0 E1 00 40 83 E5 01 00 00 0A ?? ?? ?? EB 00 40 85 E5 0D 00 A0 E1 01 10 A0 E3 24 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __new_exitfn_4da0180e6e70c740211d7f9df456877a {
	meta:
		aliases = "__new_exitfn"
		size = "260"
		objfiles = "__exit_handler@libc.a"
	strings:
		$pattern = { 70 40 2D E9 10 D0 4D E2 CC 20 9F E5 CC 10 9F E5 0D 00 A0 E1 C8 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 C0 30 9F E5 B0 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 B4 30 9F E5 B4 50 9F E5 00 30 93 E5 00 20 95 E5 01 30 83 E2 02 12 A0 E1 03 00 52 E1 A0 60 9F E5 05 1D 81 E2 0B 00 00 AA 00 00 96 E5 ?? ?? ?? EB 00 40 50 E2 03 00 00 1A ?? ?? ?? EB 0C 30 A0 E3 00 30 80 E5 10 00 00 EA 00 30 95 E5 14 30 83 E2 00 40 86 E5 00 30 85 E5 5C E0 9F E5 60 30 9F E5 00 20 9E E5 00 00 93 E5 01 C0 82 E2 01 30 A0 E3 02 22 A0 E1 00 30 82 E7 48 10 9F E5 48 30 9F E5 00 C0 8E E5 00 10 83 E5 00 40 82 E0 0D 00 A0 E1 01 10 A0 E3 34 30 9F E5 }
	condition:
		$pattern
}

rule __GI_gethostbyaddr_21f16a76c958d8f1d4e978dde3c0e6a6 {
	meta:
		aliases = "gethostbyaddr, __GI_gethostbyaddr"
		size = "92"
		objfiles = "gethostbyaddr@libc.a"
	strings:
		$pattern = { 70 40 2D E9 14 D0 4D E2 00 60 A0 E1 01 40 A0 E1 02 50 A0 E1 ?? ?? ?? EB 34 C0 9F E5 00 C0 8D E5 76 CF A0 E3 0C 00 8D E5 04 C0 8D E5 04 10 A0 E1 10 C0 8D E2 06 00 A0 E1 05 20 A0 E1 14 30 9F E5 08 C0 8D E5 ?? ?? ?? EB 10 00 9D E5 14 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
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

rule authnone_create_0fee19cb5e83ecdfff8a3c7c5218b1bb {
	meta:
		aliases = "__GI_authnone_create, authnone_create"
		size = "204"
		objfiles = "auth_none@libc.a"
	strings:
		$pattern = { 70 40 2D E9 18 D0 4D E2 ?? ?? ?? EB 00 40 A0 E1 98 50 94 E5 00 00 55 E3 40 10 A0 E3 01 00 A0 E3 04 00 00 1A ?? ?? ?? EB 00 50 50 E2 05 00 A0 E1 21 00 00 0A 98 50 84 E5 3C 20 95 E5 00 30 52 E2 7C 00 9F E5 0C 40 85 E2 0D 60 A0 E1 19 00 00 1A 07 00 90 E8 6C C0 9F E5 07 00 84 E8 20 C0 85 E5 07 00 85 E8 14 20 A0 E3 0D 00 A0 E1 28 10 85 E2 ?? ?? ?? EB 05 10 A0 E1 0D 00 A0 E1 ?? ?? ?? EB 04 10 A0 E1 0D 00 A0 E1 ?? ?? ?? EB 04 30 9D E5 0D 00 A0 E1 0F E0 A0 E1 10 F0 93 E5 3C 00 85 E5 04 30 9D E5 1C 30 93 E5 00 00 53 E3 0D 00 A0 E1 0F E0 A0 11 03 F0 A0 11 05 00 A0 E1 18 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? }
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

rule __GI_if_nametoindex_73640d7116ae9bd1b16c522a7d9c989b {
	meta:
		aliases = "if_nametoindex, __GI_if_nametoindex"
		size = "144"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { 70 40 2D E9 20 D0 4D E2 00 40 A0 E1 ?? ?? ?? EB 00 50 50 E2 0D 60 A0 E1 04 10 A0 E1 10 20 A0 E3 0D 00 A0 E1 15 00 00 BA ?? ?? ?? EB 05 00 A0 E1 0D 20 A0 E1 50 10 9F E5 ?? ?? ?? EB 00 00 50 E3 05 00 A0 E1 0A 00 00 AA ?? ?? ?? EB 00 40 90 E5 00 60 A0 E1 05 00 A0 E1 ?? ?? ?? EB 16 00 54 E3 26 30 A0 03 00 00 A0 E3 00 30 86 05 04 00 00 0A 02 00 00 EA ?? ?? ?? EB 10 00 9D E5 00 00 00 EA 00 00 A0 E3 20 D0 8D E2 70 80 BD E8 33 89 00 00 }
	condition:
		$pattern
}

rule _stdio_openlist_dec_use_c0fb1ab3dda663e57aea9bfed89eea36 {
	meta:
		aliases = "_stdio_openlist_dec_use"
		size = "320"
		objfiles = "fflush_unlocked@libc.a"
	strings:
		$pattern = { 70 40 2D E9 20 D0 4D E2 10 00 8D E2 04 11 9F E5 04 21 9F E5 04 41 9F E5 0F E0 A0 E1 04 F0 A0 E1 FC 50 9F E5 F0 00 9F E5 0F E0 A0 E1 05 F0 A0 E1 F0 30 9F E5 00 30 93 E5 01 00 53 E3 2A 00 00 1A E4 30 9F E5 00 30 93 E5 00 00 53 E3 26 00 00 DA 0D 00 A0 E1 BC 10 9F E5 D0 20 9F E5 0F E0 A0 E1 04 F0 A0 E1 C4 00 9F E5 0F E0 A0 E1 05 F0 A0 E1 BC 30 9F E5 00 40 93 E5 00 60 A0 E3 10 00 00 EA 00 30 D4 E5 01 20 D4 E5 02 34 83 E1 01 10 03 E0 30 00 51 E3 20 50 94 E5 04 60 A0 11 07 00 00 1A 00 00 56 E3 88 30 9F 05 20 50 86 15 00 50 83 05 01 30 D4 E5 20 00 13 E3 04 00 A0 E1 ?? ?? ?? 1B 05 40 A0 E1 00 00 54 E3 }
	condition:
		$pattern
}

rule marshal_new_auth_1ad72bdad66671007cde520c22ebd57c {
	meta:
		aliases = "marshal_new_auth"
		size = "152"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { 70 40 2D E9 24 60 90 E5 18 D0 4D E2 00 40 A0 E1 19 2E A0 E3 00 30 A0 E3 0D 00 A0 E1 1C 10 86 E2 ?? ?? ?? EB 04 10 A0 E1 0D 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 0D 50 A0 E1 0C 10 84 E2 0D 00 A0 E1 03 00 00 0A ?? ?? ?? EB 00 00 50 E3 0D 00 A0 E1 02 00 00 1A 38 00 9F E5 ?? ?? ?? EB 03 00 00 EA 04 30 9D E5 0F E0 A0 E1 10 F0 93 E5 AC 01 86 E5 04 30 9D E5 1C 30 93 E5 00 00 53 E3 0D 00 A0 E1 0F E0 A0 11 03 F0 A0 11 01 00 A0 E3 18 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __psfs_parse_spec_7a014ebaebb3ae4aafe2792809723917 {
	meta:
		aliases = "__psfs_parse_spec"
		size = "648"
		objfiles = "__psfs_parse_spec@libc.a"
	strings:
		$pattern = { 70 40 2D E9 30 60 90 E5 00 30 D6 E5 30 30 43 E2 09 00 53 E3 00 40 A0 83 01 50 A0 83 1A 00 00 8A 00 40 A0 E3 44 32 9F E5 03 00 54 E1 05 00 00 CA 30 20 90 E5 01 10 D2 E4 0A 30 A0 E3 94 13 23 E0 30 20 80 E5 30 40 43 E2 30 10 90 E5 00 20 D1 E5 30 30 42 E2 09 00 53 E3 F1 FF FF 9A 24 00 52 E3 06 00 00 0A 24 30 90 E5 00 00 53 E3 01 30 E0 B3 40 40 80 B5 24 30 80 B5 39 00 00 BA 75 00 00 EA 01 30 81 E2 30 30 80 E5 00 50 A0 E3 E0 C1 9F E5 10 E0 A0 E3 30 10 90 E5 00 20 DC E5 00 30 D1 E5 03 00 52 E1 05 00 00 1A 45 30 D0 E5 01 20 81 E2 0E 30 83 E1 30 20 80 E5 45 30 C0 E5 F2 FF FF EA 01 30 FC E5 00 00 53 E3 }
	condition:
		$pattern
}

rule fputc_c4fd4094735b3eae18892e979e3dd13f {
	meta:
		aliases = "__GI_fputc, putc, __GI_putc, fputc"
		size = "204"
		objfiles = "fputc@libc.a"
	strings:
		$pattern = { 70 40 2D E9 34 30 91 E5 38 60 81 E2 00 00 53 E3 10 D0 4D E2 01 40 A0 E1 06 20 A0 E1 00 50 A0 E1 09 00 00 0A 10 20 91 E5 1C 30 91 E5 03 00 52 E1 00 00 C2 35 01 50 D2 34 10 20 81 35 1B 00 00 3A ?? ?? ?? EB 00 50 A0 E1 18 00 00 EA 68 10 9F E5 0D 00 A0 E1 64 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 5C 30 9F E5 06 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 10 20 94 E5 1C 30 94 E5 03 00 52 E1 04 10 A0 E1 05 00 A0 E1 00 50 C2 35 01 50 D2 34 10 20 84 35 01 00 00 3A ?? ?? ?? EB 00 50 A0 E1 0D 00 A0 E1 01 10 A0 E3 1C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule feof_5056fc4706f2677064cbed82cb73f535 {
	meta:
		aliases = "feof"
		size = "132"
		objfiles = "feof@libc.a"
	strings:
		$pattern = { 70 40 2D E9 34 60 90 E5 38 50 80 E2 10 D0 4D E2 00 00 56 E3 00 40 A0 E1 54 10 9F E5 05 20 A0 E1 0D 00 A0 E1 06 00 00 1A 48 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 3C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 01 20 D4 E5 00 30 D4 E5 00 00 56 E3 0D 00 A0 E1 01 10 A0 E3 02 44 83 E1 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 04 00 04 E2 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ferror_33b96cd17b6e29e1e17ac48cc47095e9 {
	meta:
		aliases = "ferror"
		size = "132"
		objfiles = "ferror@libc.a"
	strings:
		$pattern = { 70 40 2D E9 34 60 90 E5 38 50 80 E2 10 D0 4D E2 00 00 56 E3 00 40 A0 E1 54 10 9F E5 05 20 A0 E1 0D 00 A0 E1 06 00 00 1A 48 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 3C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 01 20 D4 E5 00 30 D4 E5 00 00 56 E3 0D 00 A0 E1 01 10 A0 E3 02 44 83 E1 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 08 00 04 E2 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_fgetwc_6278f64f31da0d811e9ad15ea4eadd84 {
	meta:
		aliases = "__GI_fileno, getwc, fileno, fgetwc, __GI_fgetwc"
		size = "132"
		objfiles = "fileno@libc.a, fgetwc@libc.a"
	strings:
		$pattern = { 70 40 2D E9 34 60 90 E5 38 50 80 E2 10 D0 4D E2 00 00 56 E3 00 40 A0 E1 54 10 9F E5 05 20 A0 E1 0D 00 A0 E1 06 00 00 1A 48 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 3C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 00 56 E3 00 40 A0 E1 01 10 A0 E3 0D 00 A0 E1 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 04 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule clearerr_e1686cf78cb4bce4511c0e818eba6632 {
	meta:
		aliases = "clearerr"
		size = "136"
		objfiles = "clearerr@libc.a"
	strings:
		$pattern = { 70 40 2D E9 34 60 90 E5 38 50 80 E2 10 D0 4D E2 00 00 56 E3 00 40 A0 E1 58 10 9F E5 05 20 A0 E1 0D 00 A0 E1 06 00 00 1A 4C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 40 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 94 E5 0C 30 C3 E3 43 24 A0 E1 00 00 56 E3 0D 00 A0 E1 01 10 A0 E3 01 20 C4 E5 00 30 C4 E5 18 30 9F 05 0F E0 A0 01 03 F0 A0 01 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_rewind_10a67a52e0408f748fae6024bf2ba7b0 {
	meta:
		aliases = "rewind, __GI_rewind"
		size = "152"
		objfiles = "rewind@libc.a"
	strings:
		$pattern = { 70 40 2D E9 34 60 90 E5 38 50 80 E2 10 D0 4D E2 00 00 56 E3 00 40 A0 E1 68 10 9F E5 05 20 A0 E1 0D 00 A0 E1 06 00 00 1A 5C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 50 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 C0 94 E5 08 C0 CC E3 00 10 A0 E3 4C 34 A0 E1 01 20 A0 E1 04 00 A0 E1 01 30 C4 E5 00 C0 C4 E5 ?? ?? ?? EB 00 00 56 E3 0D 00 A0 E1 01 10 A0 E3 18 30 9F 05 0F E0 A0 01 03 F0 A0 01 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __ns_name_uncompress_e4fa09e01a132a85c137424877563618 {
	meta:
		aliases = "__GI___ns_name_uncompress, __ns_name_uncompress"
		size = "84"
		objfiles = "ns_name@libc.a"
	strings:
		$pattern = { 70 40 2D E9 41 DF 4D E2 05 40 8D E2 03 50 A0 E1 FF C0 A0 E3 04 30 A0 E1 00 C0 8D E5 ?? ?? ?? EB 00 60 A0 E1 01 00 76 E3 05 10 A0 E1 04 00 A0 E1 14 21 9D E5 02 00 00 0A ?? ?? ?? EB 01 00 70 E3 00 00 00 1A 00 60 E0 E3 06 00 A0 E1 41 DF 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule srand_bc90e476496ce4e3f2c23b5f49d6b9d9 {
	meta:
		aliases = "srandom, srand"
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

rule __GI_getutid_71da5d2e715fb7ea0b46f1343fc4a39d {
	meta:
		aliases = "getutid, __GI_getutid"
		size = "124"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { 70 40 2D E9 5C 40 9F E5 10 D0 4D E2 04 20 A0 E1 54 10 9F E5 00 60 A0 E1 50 30 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 44 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 06 00 A0 E1 95 FF FF EB 01 10 A0 E3 00 40 A0 E1 28 30 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 0D 50 A0 E1 04 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule sethostent_fc5e7da197fe5f2dedb2b9f0e5bf268d {
	meta:
		aliases = "sethostent"
		size = "128"
		objfiles = "gethostent@libc.a"
	strings:
		$pattern = { 70 40 2D E9 5C 50 9F E5 10 D0 4D E2 58 10 9F E5 05 20 A0 E1 00 40 A0 E1 50 30 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 40 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 38 30 9F E5 00 40 54 E2 01 40 A0 13 00 40 83 E5 0D 00 A0 E1 01 10 A0 E3 24 30 9F E5 0D 60 A0 E1 0F E0 A0 E1 03 F0 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_getdomainname_873ed8ae67956d589da0df3009c45dde {
	meta:
		aliases = "__libc_getdomainname, getdomainname, __GI___libc_getdomainname, __GI_getdomainname"
		size = "116"
		objfiles = "getdomainname@libc.a"
	strings:
		$pattern = { 70 40 2D E9 62 DF 4D E2 00 50 A0 E1 0D 00 A0 E1 01 40 A0 E1 ?? ?? ?? EB 51 6F 8D E2 00 30 A0 E1 01 60 86 E2 01 00 73 E3 06 00 A0 E1 03 20 A0 E1 0C 00 00 0A ?? ?? ?? EB 01 00 80 E2 04 00 50 E1 06 10 A0 E1 05 00 A0 E1 04 00 00 9A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 01 00 00 EA ?? ?? ?? EB 00 20 A0 E3 02 00 A0 E1 62 DF 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule gethostname_beace9a7a0b00d1df1e99620dc877219 {
	meta:
		aliases = "__GI_gethostname, gethostname"
		size = "112"
		objfiles = "gethostname@libc.a"
	strings:
		$pattern = { 70 40 2D E9 62 DF 4D E2 00 60 A0 E1 0D 00 A0 E1 01 40 A0 E1 ?? ?? ?? EB 00 30 A0 E1 41 50 8D E2 01 00 73 E3 05 00 A0 E1 03 20 A0 E1 0C 00 00 0A ?? ?? ?? EB 01 00 80 E2 04 00 50 E1 05 10 A0 E1 06 00 A0 E1 04 00 00 9A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 01 00 00 EA ?? ?? ?? EB 00 20 A0 E3 02 00 A0 E1 62 DF 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule ulckpwdf_0fc725af23cd411f82fbb1e9d50d28e1 {
	meta:
		aliases = "ulckpwdf"
		size = "148"
		objfiles = "lckpwdf@libc.a"
	strings:
		$pattern = { 70 40 2D E9 70 40 9F E5 00 30 94 E5 10 D0 4D E2 01 00 73 E3 0D 60 A0 E1 60 10 9F E5 60 20 9F E5 0D 00 A0 E1 03 50 A0 E1 10 00 00 0A 54 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 4C 30 9F E5 40 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 94 E5 ?? ?? ?? EB 00 30 E0 E3 00 50 A0 E1 00 30 84 E5 0D 00 A0 E1 01 10 A0 E3 24 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __new_sem_post_d19e3f0f0a730e659144e8a6c5ddbc8f {
	meta:
		aliases = "sem_post, __new_sem_post"
		size = "280"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { 70 40 2D E9 94 D0 4D E2 00 40 A0 E1 0D FF FF EB 54 60 90 E5 00 00 56 E3 20 00 00 1A 00 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 0C 50 94 E5 00 00 55 E3 0F 00 00 1A 08 30 94 E5 06 01 73 E3 06 00 00 1A ?? ?? ?? EB 22 30 A0 E3 00 30 80 E5 04 00 A0 E1 ?? ?? ?? EB 00 20 E0 E3 2A 00 00 EA 01 30 83 E2 08 30 84 E5 04 00 A0 E1 ?? ?? ?? EB 05 20 A0 E1 24 00 00 EA 08 30 95 E5 04 00 A0 E1 0C 30 84 E5 08 60 85 E5 ?? ?? ?? EB 01 30 A0 E3 BA 31 C5 E5 05 00 A0 E1 ?? ?? ?? EB 06 20 A0 E1 19 00 00 EA 6C 30 9F E5 00 30 93 E5 00 00 53 E3 07 00 00 AA ?? ?? ?? EB 00 00 50 E3 04 00 00 AA ?? ?? ?? EB 0B 30 A0 E3 00 20 E0 E3 }
	condition:
		$pattern
}

rule gets_8dc0a167126f9db59de1b7a94e1e5a75 {
	meta:
		aliases = "gets"
		size = "200"
		objfiles = "gets@libc.a"
	strings:
		$pattern = { 70 40 2D E9 A8 40 9F E5 00 20 94 E5 34 60 92 E5 00 00 56 E3 10 D0 4D E2 00 50 A0 E1 01 00 00 0A 05 40 A0 E1 0C 00 00 EA 0D 00 A0 E1 38 20 82 E2 80 10 9F E5 80 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 94 E5 74 30 9F E5 38 00 80 E2 0F E0 A0 E1 03 F0 A0 E1 F1 FF FF EA 01 40 84 E2 ?? ?? ?? EB 01 00 70 E3 03 00 00 0A 00 00 C4 E5 00 30 D4 E5 0A 00 53 E3 F7 FF FF 1A 01 00 70 E3 04 00 55 11 00 30 A0 13 01 30 A0 03 00 50 A0 03 00 30 C4 15 00 00 56 E3 0D 00 A0 01 01 10 A0 03 20 30 9F 05 0F E0 A0 01 03 F0 A0 01 05 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
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

rule memchr_33a37b0930262a70262c92a57ea2807d {
	meta:
		aliases = "__GI_memchr, memchr"
		size = "252"
		objfiles = "memchr@libc.a"
	strings:
		$pattern = { 70 40 2D E9 FF 10 01 E2 04 00 00 EA 00 30 D0 E5 01 00 53 E1 01 20 42 E2 70 80 BD 08 01 00 80 E2 00 00 52 E3 01 00 00 0A 03 00 10 E3 F6 FF FF 1A 01 34 81 E1 00 C0 A0 E1 03 68 83 E1 1E 00 00 EA 04 30 9C E4 03 30 26 E0 00 00 83 E0 03 30 E0 E1 03 30 20 E0 0E E0 03 E0 00 00 5E E3 04 20 42 E2 15 00 00 0A 04 30 5C E5 04 00 4C E2 01 00 53 E1 03 50 80 E2 01 E0 80 E2 02 40 80 E2 70 80 BD 08 03 30 5C E5 01 00 53 E1 01 00 00 1A 0E 00 A0 E1 70 80 BD E8 02 30 5C E5 01 00 53 E1 01 00 00 1A 04 00 A0 E1 70 80 BD E8 01 30 5C E5 01 00 53 E1 01 00 00 1A 05 00 A0 E1 70 80 BD E8 03 00 52 E3 2C 00 9F E5 2C E0 9F E5 }
	condition:
		$pattern
}

rule __GI_inet_ntoa_r_917f8aad12efa9985f40fe29e25a8be8 {
	meta:
		aliases = "inet_ntoa_r, __GI_inet_ntoa_r"
		size = "128"
		objfiles = "inet_ntoa@libc.a"
	strings:
		$pattern = { 70 40 2D E9 FF 28 00 E2 FF 3C 00 E2 22 24 A0 E1 03 34 A0 E1 00 3C 83 E1 20 2C 82 E1 00 50 A0 E3 04 D0 4D E2 03 40 82 E1 0F C0 81 E2 05 60 A0 E1 07 00 00 EA 00 C0 A0 E3 00 C0 8D E5 ?? ?? ?? EB 00 00 56 E3 01 C0 40 E2 2E 30 A0 13 00 30 C6 15 0C 60 A0 E1 03 00 55 E3 FF 10 04 E2 00 20 A0 E3 0C 00 A0 E1 09 30 E0 E3 24 44 A0 E1 01 50 85 E2 EF FF FF DA 01 00 8C E2 04 D0 8D E2 70 80 BD E8 }
	condition:
		$pattern
}

rule strchr_c571a158f39387d1c6ea29ff3c72a64d {
	meta:
		aliases = "index, __GI_strchr, strchr"
		size = "264"
		objfiles = "strchr@libc.a"
	strings:
		$pattern = { 70 40 2D E9 FF 40 01 E2 05 00 00 EA 00 30 D0 E5 04 00 53 E1 70 80 BD 08 00 00 53 E3 01 00 80 E2 34 00 00 0A 03 00 10 E3 F7 FF FF 1A 04 34 84 E1 00 50 A0 E1 03 68 83 E1 04 10 95 E4 BC 00 9F E5 06 20 21 E0 00 C0 A0 E1 B4 30 9F E5 00 00 81 E0 01 10 E0 E1 01 00 20 E0 0C C0 82 E0 03 E0 A0 E1 02 20 E0 E1 03 30 00 E0 02 C0 2C E0 00 00 53 E3 0E E0 0C E0 01 00 00 1A 00 00 5E E3 ED FF FF 0A 04 10 55 E5 04 30 45 E2 01 00 83 E2 01 20 80 E2 04 00 51 E1 01 C0 82 E2 01 00 00 1A 03 00 A0 E1 70 80 BD E8 00 00 51 E3 12 00 00 0A 03 30 55 E5 04 00 53 E1 70 80 BD 08 00 00 53 E3 0D 00 00 0A 01 00 D0 E5 04 00 50 E1 }
	condition:
		$pattern
}

rule strchrnul_70b389a5276155eb21aeb4aa2216a999 {
	meta:
		aliases = "__GI_strchrnul, strchrnul"
		size = "256"
		objfiles = "strchrnul@libc.a"
	strings:
		$pattern = { 70 40 2D E9 FF 40 01 E2 05 00 00 EA 00 30 D0 E5 04 00 53 E1 70 80 BD 08 00 00 53 E3 70 80 BD 08 01 00 80 E2 03 00 10 E3 F7 FF FF 1A 04 34 84 E1 00 50 A0 E1 03 68 83 E1 04 10 95 E4 B4 00 9F E5 06 20 21 E0 00 C0 A0 E1 AC 30 9F E5 00 00 81 E0 01 10 E0 E1 01 00 20 E0 0C C0 82 E0 03 E0 A0 E1 02 20 E0 E1 03 30 00 E0 02 C0 2C E0 00 00 53 E3 0E E0 0C E0 01 00 00 1A 00 00 5E E3 ED FF FF 0A 04 30 55 E5 04 10 45 E2 01 00 81 E2 01 20 80 E2 04 00 53 E1 01 C0 82 E2 01 00 00 0A 00 00 53 E3 01 00 00 1A 01 00 A0 E1 70 80 BD E8 03 30 55 E5 04 00 53 E1 70 80 BD 08 00 00 53 E3 70 80 BD 08 01 00 D0 E5 04 00 50 E1 }
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

rule __GI_towupper_58e629f6e00e8183854acc07dd0c163f {
	meta:
		aliases = "towupper, __GI_towlower, towlower, __GI_towupper"
		size = "48"
		objfiles = "towlower@libc.a, towupper@libc.a"
	strings:
		$pattern = { 7F 00 50 E3 80 10 A0 E1 0E F0 A0 81 18 30 9F E5 00 30 93 E5 03 20 81 E0 03 10 D1 E7 01 30 D2 E5 03 3C A0 E1 43 08 81 E1 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_initstate_r_127469cffa9cf94d1f8f630d32ba5c6f {
	meta:
		aliases = "initstate_r, __GI_initstate_r"
		size = "200"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { 7F 00 52 E3 F0 40 2D E9 01 70 A0 E1 03 50 A0 E1 03 00 00 9A FF 00 52 E3 04 40 A0 83 03 40 A0 93 08 00 00 EA 1F 00 52 E3 03 00 00 8A 07 00 52 E3 00 40 A0 83 03 00 00 8A 1A 00 00 EA 3F 00 52 E3 02 40 A0 83 01 40 A0 93 74 20 9F E5 04 31 82 E0 14 10 93 E5 04 21 92 E7 04 60 87 E2 01 31 86 E0 18 30 85 E5 14 20 85 E5 10 10 85 E5 0C 40 85 E5 08 60 85 E5 05 10 A0 E1 ?? ?? ?? EB 00 00 54 E3 04 30 95 15 03 30 66 10 43 31 A0 11 05 20 A0 13 92 43 23 10 00 00 A0 E3 00 00 87 E5 04 00 A0 01 00 30 87 15 F0 80 BD E8 ?? ?? ?? EB 16 40 A0 E3 00 40 80 E5 ?? ?? ?? EB 00 40 80 E5 00 00 E0 E3 F0 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule isascii_98be199b4bc40b36ca693293cff31851 {
	meta:
		aliases = "isascii"
		size = "16"
		objfiles = "isascii@libc.a"
	strings:
		$pattern = { 7F 30 D0 E3 00 00 A0 13 01 00 A0 03 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_btowc_af3dfcf50b4a136e32fd17666457bac4 {
	meta:
		aliases = "btowc, wctob, __GI_btowc"
		size = "12"
		objfiles = "wctob@libc.a, btowc@libc.a"
	strings:
		$pattern = { 80 00 50 E3 00 00 E0 23 0E F0 A0 E1 }
	condition:
		$pattern
}

rule pthread_kill_51c2b42048cf82c9ea66b407a0422e6b {
	meta:
		aliases = "pthread_kill"
		size = "140"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { 80 20 9F E5 00 3B A0 E1 23 3B A0 E1 F0 40 2D E9 03 52 82 E0 00 40 A0 E1 01 70 A0 E1 05 00 A0 E1 00 10 A0 E3 ?? ?? ?? EB 08 20 95 E5 00 00 52 E3 05 00 A0 E1 04 00 00 0A 10 30 92 E5 04 60 53 E0 01 60 A0 13 00 00 56 E3 02 00 00 0A ?? ?? ?? EB 03 00 A0 E3 F0 80 BD E8 14 40 92 E5 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 07 10 A0 E1 ?? ?? ?? EB 01 00 70 E3 06 00 A0 E1 F0 80 BD 18 ?? ?? ?? EB 00 00 90 E5 F0 80 BD E8 ?? ?? ?? ?? }
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

rule __aeabi_d2f_5cb6735ce343b5da996d663553bc0bcf {
	meta:
		aliases = "__truncdfsf2, __aeabi_d2f"
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

rule __fixunssfsi_c609666c0d7d4b84305a36e14bdee41d {
	meta:
		aliases = "__aeabi_f2uiz, __fixunssfsi"
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

rule tolower_e3bb95780550d6148d1f13d2dfbb1206 {
	meta:
		aliases = "__GI_toupper, toupper, __GI_tolower, tolower"
		size = "52"
		objfiles = "toupper@libc.a, tolower@libc.a"
	strings:
		$pattern = { 80 30 80 E2 06 0D 53 E3 80 10 A0 E1 0E F0 A0 21 18 30 9F E5 00 30 93 E5 03 20 81 E0 03 10 D1 E7 01 30 D2 E5 03 3C A0 E1 43 08 81 E1 0E F0 A0 E1 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __aeabi_dcmpun_bffa2f105a05b3342d7139066f6bb49f {
	meta:
		aliases = "__unorddf2, __aeabi_dcmpun"
		size = "56"
		objfiles = "_unorddf2@libgcc.a"
	strings:
		$pattern = { 80 C0 A0 E1 CC CA F0 E1 01 00 00 1A 00 C6 91 E1 06 00 00 1A 82 C0 A0 E1 CC CA F0 E1 01 00 00 1A 02 C6 93 E1 01 00 00 1A 00 00 A0 E3 0E F0 A0 E1 01 00 A0 E3 0E F0 A0 E1 }
	condition:
		$pattern
}

rule _dl_protect_relro_313c771836fba49ef4dddaaa1bf9e0f1 {
	meta:
		aliases = "_dl_protect_relro"
		size = "156"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 88 20 9F E5 D4 10 90 E5 00 30 90 E5 D8 C0 90 E5 00 20 92 E5 01 30 83 E0 00 20 62 E2 0C C0 83 E0 02 C0 0C E0 02 30 03 E0 0C 00 53 E1 04 E0 2D E5 0C 10 63 E0 00 E0 A0 E1 01 20 A0 E3 03 00 A0 E1 04 F0 9D 04 7D 00 90 EF 01 0A 70 E3 40 30 9F 85 00 20 60 E2 00 20 83 85 01 00 00 8A 00 00 50 E3 04 F0 9D A4 04 20 9E E5 02 00 A0 E3 24 10 9F E5 ?? ?? ?? EB 00 00 A0 E3 01 00 90 EF 01 0A 70 E3 0C 30 9F 85 00 20 60 E2 00 20 83 85 04 F0 9D E4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule difftime_54df06b38ee5e51cf080150f7c29ea0c {
	meta:
		aliases = "difftime"
		size = "16"
		objfiles = "difftime@libc.a"
	strings:
		$pattern = { 90 01 01 EE 90 11 00 EE 80 01 21 EE 0E F0 A0 E1 }
	condition:
		$pattern
}

rule __pthread_do_exit_1f81f2272a32dbf75ce51093afa8448d {
	meta:
		aliases = "__pthread_do_exit"
		size = "284"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { 94 D0 4D E2 01 40 A0 E1 00 50 A0 E1 C8 FF FF EB 01 30 A0 E3 40 30 C0 E5 00 30 A0 E3 00 60 A0 E1 41 30 C0 E5 04 00 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 1C 00 96 E5 06 10 A0 E1 ?? ?? ?? EB 9C 31 96 E5 00 00 53 E3 30 50 86 E5 0B 00 00 0A B8 30 9F E5 A0 21 96 E5 00 30 93 E5 02 30 83 E1 01 0C 13 E3 05 00 00 0A 09 30 A0 E3 A8 31 86 E5 9C 30 9F E5 AC 61 86 E5 00 60 83 E5 ?? ?? ?? EB 38 40 96 E5 01 30 A0 E3 2C 30 C6 E5 1C 00 96 E5 ?? ?? ?? EB 00 00 54 E3 04 00 A0 11 ?? ?? ?? 1B 70 30 9F E5 00 40 93 E5 04 00 56 E1 15 00 00 1A 64 30 9F E5 00 30 93 E5 00 00 53 E3 11 00 00 BA 03 30 A0 E3 04 30 8D E5 00 40 8D E5 }
	condition:
		$pattern
}

rule __rpc_thread_destroy_d7f05b62a64ce6a9a9e0a1c780499601 {
	meta:
		aliases = "__rpc_thread_destroy"
		size = "176"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { 98 30 9F E5 10 40 2D E9 00 00 53 E3 90 30 9F 05 02 00 A0 E3 00 40 93 05 02 00 00 0A 0F E0 A0 E1 03 F0 A0 E1 00 40 A0 E1 00 00 54 E3 10 80 BD 08 70 30 9F E5 03 00 54 E1 10 80 BD 08 ?? ?? ?? EB ?? ?? ?? EB 98 00 94 E5 ?? ?? ?? EB 9C 00 94 E5 ?? ?? ?? EB A0 00 94 E5 ?? ?? ?? EB BC 00 94 E5 ?? ?? ?? EB AC 00 94 E5 ?? ?? ?? EB B0 00 94 E5 ?? ?? ?? EB 04 00 A0 E1 ?? ?? ?? EB 28 20 9F E5 00 10 A0 E3 01 00 52 E1 14 30 9F 05 02 00 A0 E3 00 20 83 05 10 80 BD 08 10 40 BD E8 ?? ?? ?? EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule puts_a09c04118fa6cc631c64705895f175e5 {
	meta:
		aliases = "puts"
		size = "180"
		objfiles = "puts@libc.a"
	strings:
		$pattern = { 98 30 9F E5 F0 40 2D E9 00 50 93 E5 34 70 95 E5 10 D0 4D E2 38 40 85 E2 00 00 57 E3 00 60 A0 E1 04 20 A0 E1 78 10 9F E5 0D 00 A0 E1 06 00 00 1A 70 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 64 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 10 A0 E1 06 00 A0 E1 ?? ?? ?? EB 00 40 A0 E1 01 00 74 E3 05 10 A0 E1 0A 00 A0 E3 03 00 00 0A ?? ?? ?? EB 01 00 70 E3 00 40 A0 01 01 40 84 12 00 00 57 E3 0D 00 A0 E1 01 10 A0 E3 20 30 9F 05 0F E0 A0 01 03 F0 A0 01 04 00 A0 E1 10 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_start_thread_82077b9b263c96801ccc45b2ff069668 {
	meta:
		aliases = "pthread_start_thread"
		size = "220"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { 98 D0 4D E2 00 40 A0 E1 ?? ?? ?? EB 64 10 84 E2 14 00 84 E5 00 20 A0 E3 02 00 A0 E3 ?? ?? ?? EB E4 10 94 E5 00 00 51 E3 14 00 94 A5 E8 20 84 A2 07 00 00 AA 90 30 9F E5 18 30 93 E5 00 00 53 E3 04 00 00 DA 00 10 A0 E3 98 20 8D E2 04 10 22 E5 14 00 94 E5 ?? ?? ?? EB 70 30 9F E5 00 30 93 E5 00 00 53 E3 13 00 00 0A 64 30 9F E5 00 30 93 E5 00 00 53 E3 0F 00 00 DA 05 30 A0 E3 04 30 8D E5 00 40 8D E5 4C 30 9F E5 0D 10 A0 E1 00 00 93 E5 94 20 A0 E3 ?? ?? ?? EB 01 00 70 E3 03 00 00 1A ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 F4 FF FF 0A 04 00 A0 E1 ?? ?? ?? EB 60 00 94 E5 0F E0 A0 E1 5C F0 94 E5 0D 10 A0 E1 }
	condition:
		$pattern
}

rule _dl_linux_resolver_3e0a55eeaa22933b3feb8dfbce785f3c {
	meta:
		aliases = "_dl_linux_resolver"
		size = "208"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { 9C 30 90 E5 F0 40 2D E9 81 61 83 E0 04 30 96 E5 58 C0 90 E5 23 24 A0 E1 00 40 A0 E1 02 C2 9C E7 FF 30 03 E2 54 20 94 E5 16 00 53 E3 02 00 A0 E3 88 10 9F E5 0C 50 82 E0 08 00 00 0A 80 30 9F E5 00 20 93 E5 ?? ?? ?? EB 01 00 A0 E3 01 00 90 EF 01 0A 70 E3 6C 30 9F 85 00 00 60 E2 00 00 83 85 1C 10 94 E5 04 20 A0 E1 01 30 A0 E3 05 00 A0 E1 00 70 96 E5 00 60 94 E5 ?? ?? ?? EB 00 40 50 E2 05 30 A0 E1 40 10 9F E5 02 00 A0 E3 08 00 00 1A 2C 20 9F E5 00 20 92 E5 ?? ?? ?? EB 01 00 A0 E3 01 00 90 EF 01 0A 70 E3 18 30 9F 85 00 20 60 E2 00 20 83 85 04 00 A0 E1 06 40 87 E7 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
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

rule getchar_87b1c6184a639912194516fe591e746a {
	meta:
		aliases = "getchar"
		size = "200"
		objfiles = "getchar@libc.a"
	strings:
		$pattern = { AC 30 9F E5 30 40 2D E9 00 40 93 E5 34 30 94 E5 10 D0 4D E2 38 50 84 E2 00 00 53 E3 94 10 9F E5 05 20 A0 E1 0D 00 A0 E1 09 00 00 0A 10 20 94 E5 18 30 94 E5 03 00 52 E1 01 50 D2 34 04 00 A0 E1 10 20 84 35 17 00 00 3A ?? ?? ?? EB 00 50 A0 E1 14 00 00 EA 60 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 54 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 10 20 94 E5 18 30 94 E5 03 00 52 E1 01 50 D2 34 04 00 A0 E1 10 20 84 35 01 00 00 3A ?? ?? ?? EB 00 50 A0 E1 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 10 D0 8D E2 30 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule tanh_2cd1e0e7b90209dd9074ab9703d666d6 {
	meta:
		aliases = "__GI_tanh, tanh"
		size = "200"
		objfiles = "s_tanh@libm.a"
	strings:
		$pattern = { B4 30 9F E5 02 21 C0 E3 03 00 52 E1 10 40 2D E9 03 00 2D E9 02 91 BD EC 00 40 A0 E1 04 00 00 DA 00 00 50 E3 89 01 51 EE 89 01 00 AE 89 01 20 BE 10 80 BD E8 84 30 9F E5 03 00 52 E1 89 81 00 CE 1A 00 00 CA F2 05 52 E3 02 00 00 AA 89 01 01 EE 80 01 11 EE 10 80 BD E8 64 30 9F E5 03 00 52 E1 09 00 00 DA ?? ?? ?? EB 80 01 00 EE 02 81 2D ED 03 00 BD E8 ?? ?? ?? EB 8A 91 10 EE 8A 01 00 EE 80 11 41 EE 89 01 01 EE 08 00 00 EA ?? ?? ?? EB 8A 91 10 EE 81 01 10 EE 02 81 2D ED 03 00 BD E8 ?? ?? ?? EB 8A 11 00 EE 80 81 10 EE 81 01 40 EE 00 00 54 E3 80 81 10 BE 10 80 BD E8 FF FF EF 7F FF FF 35 40 FF FF EF 3F }
	condition:
		$pattern
}

rule putchar_14a5b74bffa90d0ad9d07d933965639e {
	meta:
		aliases = "putchar"
		size = "216"
		objfiles = "putchar@libc.a"
	strings:
		$pattern = { BC 30 9F E5 70 40 2D E9 00 40 93 E5 34 30 94 E5 38 60 84 E2 00 00 53 E3 10 D0 4D E2 06 20 A0 E1 A0 10 9F E5 00 50 A0 E1 0A 00 00 0A 10 20 94 E5 1C 30 94 E5 03 00 52 E1 04 10 A0 E1 00 00 C2 35 01 50 D2 34 10 20 84 35 1A 00 00 3A ?? ?? ?? EB 00 50 A0 E1 17 00 00 EA 0D 00 A0 E1 68 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 60 30 9F E5 06 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 10 20 94 E5 1C 30 94 E5 03 00 52 E1 04 10 A0 E1 05 00 A0 E1 00 50 C2 35 01 50 D2 34 10 20 84 35 01 00 00 3A ?? ?? ?? EB 00 50 A0 E1 0D 00 A0 E1 01 10 A0 E3 20 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 10 D0 8D E2 70 80 BD E8 ?? ?? ?? ?? }
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

rule do_dlclose_ce42b4e6c8cc233be45f9fc3624c5999 {
	meta:
		aliases = "do_dlclose"
		size = "764"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { DC 32 9F E5 00 30 93 E5 03 00 50 E1 F0 45 2D E9 00 70 A0 E1 01 A0 A0 E1 AF 00 00 0A C4 32 9F E5 00 30 93 E5 00 10 A0 E3 03 00 00 EA 07 00 53 E1 08 00 00 0A 03 10 A0 E1 04 30 93 E5 00 00 53 E3 F9 FF FF 1A A0 32 9F E5 09 20 A0 E3 01 00 A0 E3 00 20 83 E5 F0 85 BD E8 00 00 51 E3 04 20 97 E5 80 32 9F 05 04 20 81 15 00 20 83 05 00 10 97 E5 20 20 D1 E5 21 30 D1 E5 03 24 82 E1 01 00 52 E3 00 80 A0 03 7B 00 00 0A 01 20 42 E2 42 34 A0 E1 07 00 A0 E1 21 30 C1 E5 20 20 C1 E5 ?? ?? ?? EB 00 00 A0 E3 F0 85 BD E8 08 30 97 E5 08 61 93 E7 20 30 96 E5 01 30 43 E2 43 24 A0 E1 21 20 C6 E5 20 30 C6 E5 21 20 D6 E5 }
	condition:
		$pattern
}

rule __rpc_thread_variables_e243b44ce13056c0da2b6d4c8db925c6 {
	meta:
		aliases = "__rpc_thread_variables"
		size = "260"
		objfiles = "rpc_thread@libc.a"
	strings:
		$pattern = { E4 30 9F E5 10 40 2D E9 00 00 53 E3 DC 30 9F 05 00 00 93 05 02 00 A0 13 0F E0 A0 11 03 F0 A0 11 00 40 50 E2 2E 00 00 1A C4 30 9F E5 00 00 53 E3 C0 40 9F E5 04 00 00 0A 04 00 A0 E1 B8 10 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 00 EA 00 30 94 E5 00 00 53 E3 02 00 00 1A DC FF FF EB 01 30 A0 E3 00 30 84 E5 80 30 9F E5 00 00 53 E3 7C 30 9F 05 00 00 93 05 02 00 A0 13 0F E0 A0 11 03 F0 A0 11 00 40 50 E2 16 00 00 1A 01 00 80 E2 C8 10 A0 E3 ?? ?? ?? EB 00 40 50 E2 09 00 00 0A 5C 30 9F E5 00 00 53 E3 44 30 9F 05 00 40 83 05 0C 00 00 0A 04 10 A0 E1 02 00 A0 E3 0F E0 A0 E1 03 F0 A0 E1 07 00 00 EA 20 30 9F E5 }
	condition:
		$pattern
}

rule __GI_getmntent_r_5a5dd3226d263aed553d5c66308d09cd {
	meta:
		aliases = "getmntent_r, __GI_getmntent_r"
		size = "316"
		objfiles = "mntent@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 00 51 E3 00 00 50 13 04 D0 4D E2 00 60 A0 E1 01 50 A0 E1 02 40 A0 E1 03 70 A0 E1 3F 00 00 0A 00 00 52 E3 3D 00 00 0A 05 00 00 EA 00 30 D4 E5 0A 00 53 E3 23 00 53 13 00 30 A0 13 01 30 A0 03 06 00 00 1A 04 00 A0 E1 07 10 A0 E1 06 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 F3 FF FF 1A 2F 00 00 EA 04 60 8D E2 04 30 26 E5 04 00 A0 E1 BC 10 9F E5 0D 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 85 E5 26 00 00 0A 00 00 A0 E3 A0 10 9F E5 0D 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 04 00 85 E5 1F 00 00 0A 00 00 A0 E3 84 10 9F E5 0D 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 08 00 85 E5 18 00 00 0A 6C 10 9F E5 0D 20 A0 E1 }
	condition:
		$pattern
}

rule putgrent_e9b815c617c1592e811c407a26bdf5e6 {
	meta:
		aliases = "putgrent"
		size = "276"
		objfiles = "putgrent@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 00 51 E3 00 00 50 13 14 D0 4D E2 00 50 A0 E1 01 60 A0 E1 04 00 00 1A ?? ?? ?? EB 00 40 E0 E3 16 30 A0 E3 00 30 80 E5 2E 00 00 EA 34 70 91 E5 00 00 57 E3 0A 00 00 1A 38 40 81 E2 04 00 8D E2 AC 30 9F E5 AC 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 9C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 08 30 95 E5 00 30 8D E5 06 00 A0 E1 88 10 9F E5 0C 00 95 E8 ?? ?? ?? EB 00 00 50 E3 11 00 00 BA 0C 50 95 E5 74 10 9F E5 00 40 95 E5 00 00 54 E3 06 00 A0 E1 04 20 A0 E1 04 50 85 E2 05 00 00 1A 06 10 A0 E1 0A 00 A0 E3 ?? ?? ?? EB 00 00 50 E3 04 00 00 BA 04 00 00 EA ?? ?? ?? EB 00 00 50 E3 }
	condition:
		$pattern
}

rule __GI_memmem_28fd88f8ed711bc6a87c23819c61ec56 {
	meta:
		aliases = "memmem, __GI_memmem"
		size = "112"
		objfiles = "memmem@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 00 53 E3 03 50 A0 E1 01 30 80 E0 00 40 A0 E1 02 60 A0 E1 03 70 65 E0 01 00 00 1A 04 00 A0 E1 F0 80 BD E8 05 00 51 E1 08 00 00 2A 0C 00 00 EA 00 C0 D4 E5 00 30 D6 E5 03 00 5C E1 02 00 00 1A ?? ?? ?? EB 00 00 50 E3 F3 FF FF 0A 01 40 84 E2 07 00 54 E1 01 00 84 E2 01 10 86 E2 01 20 45 E2 F2 FF FF 9A 00 00 A0 E3 F0 80 BD E8 }
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

rule __GI_xdr_pmaplist_ba3252ad76adccdf9670928b2b199ed0 {
	meta:
		aliases = "xdr_pmaplist, __GI_xdr_pmaplist"
		size = "172"
		objfiles = "pmap_prot2@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 30 90 E5 04 D0 4D E2 00 50 A0 E1 02 00 53 E3 00 60 A0 13 01 60 A0 03 01 40 A0 E1 00 70 A0 E3 00 00 00 EA 07 40 A0 E1 00 30 94 E5 04 10 8D E2 00 30 53 E2 01 30 A0 13 04 30 21 E5 05 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 04 10 A0 E1 14 20 A0 E3 4C 30 9F E5 05 00 A0 E1 0E 00 00 0A 00 C0 9D E5 00 00 5C E3 01 00 A0 03 0B 00 00 0A 00 00 56 E3 00 C0 94 15 10 70 8C 12 ?? ?? ?? EB 00 00 50 E3 04 00 00 0A 00 00 56 E3 00 30 94 05 10 40 83 02 E4 FF FF 0A E2 FF FF EA 00 00 A0 E3 04 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule byte_group_match_null_string_p_6c1b586717557be3ac3ea42ad0df4aa5 {
	meta:
		aliases = "byte_group_match_null_string_p"
		size = "336"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 30 90 E5 04 D0 4D E2 00 70 A0 E1 01 60 A0 E1 02 30 83 E2 02 50 A0 E1 39 00 00 EA 00 30 D1 E5 07 00 53 E3 38 00 00 0A 0F 00 53 E3 3A 00 00 1A 01 30 81 E2 00 30 8D E5 01 30 D3 E5 01 20 D1 E5 03 3C A0 E1 43 48 92 E0 03 30 81 E2 00 30 8D E5 17 00 00 5A 36 00 00 EA 00 10 8D E5 1C 00 00 EA C6 FF FF EB 00 00 50 E3 34 00 00 0A 00 30 9D E5 03 10 84 E0 00 10 8D E5 03 30 D4 E7 0F 00 53 E3 01 20 81 E2 03 00 81 E2 11 00 00 1A 00 20 8D E5 01 30 D2 E5 01 20 D1 E5 03 3C A0 E1 43 48 82 E0 00 00 8D E5 04 30 80 E0 03 30 53 E5 0E 00 53 E3 E8 FF FF 1A 00 30 9D E5 03 00 A0 E1 04 30 83 E0 03 10 43 E2 }
	condition:
		$pattern
}

rule popen_abff2757efbc2a39c167bb5f1519b405 {
	meta:
		aliases = "popen"
		size = "584"
		objfiles = "popen@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 30 D1 E5 34 D0 4D E2 77 00 53 E3 01 40 A0 E1 04 00 8D E5 09 00 00 0A 72 00 53 E3 01 00 A0 03 18 00 8D 05 07 00 00 0A ?? ?? ?? EB 00 10 A0 E3 16 30 A0 E3 08 10 8D E5 00 30 80 E5 74 00 00 EA 00 20 A0 E3 18 20 8D E5 0C 00 A0 E3 ?? ?? ?? EB 00 00 50 E3 0C 00 8D E5 08 00 8D 05 6C 00 00 0A 2C 00 8D E2 ?? ?? ?? EB 00 00 50 E3 64 00 00 1A 18 C0 9D E5 34 00 8D E2 01 30 6C E2 07 20 E0 E3 03 31 80 E0 02 30 93 E7 10 30 8D E5 0C 31 80 E0 02 30 93 E7 04 10 A0 E1 10 00 9D E5 14 30 8D E5 ?? ?? ?? EB 00 00 50 E3 08 00 8D E5 04 00 00 1A 10 00 9D E5 ?? ?? ?? EB 14 00 9D E5 ?? ?? ?? EB 4F 00 00 EA }
	condition:
		$pattern
}

rule adjtime_2967faea271b4cdda10b54b7aa770d29 {
	meta:
		aliases = "adjtime"
		size = "280"
		objfiles = "adjtime@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 40 50 E2 80 D0 4D E2 01 60 A0 E1 18 00 00 0A 04 70 94 E5 EC 50 9F E5 07 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 30 94 E5 03 40 80 E0 86 3E 84 E2 D4 20 9F E5 01 30 83 E2 02 00 53 E1 04 00 00 9A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 29 00 00 EA 07 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 94 05 23 E0 04 30 8D E5 A0 30 9F E5 00 30 8D E5 00 00 00 EA 00 40 8D E5 0D 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 20 E0 B3 1B 00 00 BA 00 00 56 E3 06 20 A0 01 18 00 00 0A 04 40 9D E5 00 00 54 E3 0C 00 00 AA 00 40 64 E2 58 10 9F E5 04 00 A0 E1 ?? ?? ?? EB 00 00 60 E2 04 00 86 E5 44 10 9F E5 04 00 A0 E1 }
	condition:
		$pattern
}

rule __GI_tsearch_c22020e5ca30fffffcb5cb5d88682473 {
	meta:
		aliases = "tsearch, __GI_tsearch"
		size = "116"
		objfiles = "tsearch@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 40 51 E2 00 60 A0 E1 02 70 A0 E1 04 00 A0 01 F0 80 BD 08 09 00 00 EA 00 00 94 E5 F0 80 BD E8 00 10 95 E5 0F E0 A0 E1 07 F0 A0 E1 00 00 50 E3 F8 FF FF 0A 00 30 94 E5 04 40 83 E2 08 40 83 A2 00 50 94 E5 00 00 55 E3 06 00 A0 E1 F3 FF FF 1A 0C 00 A0 E3 ?? ?? ?? EB 00 00 50 E3 00 00 84 15 00 60 80 15 04 50 80 15 08 50 80 15 F0 80 BD E8 }
	condition:
		$pattern
}

rule __heap_free_0cd8c390dae87dc84c6374ff0bd47a71 {
	meta:
		aliases = "__heap_free"
		size = "244"
		objfiles = "heap_free@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 40 90 E5 02 E0 81 E0 00 60 A0 E3 03 00 00 EA 01 00 53 E1 05 00 00 2A 04 60 A0 E1 04 40 94 E5 00 00 54 E3 0C 30 84 E2 F8 FF FF 1A 27 00 00 EA 00 C0 94 E5 04 30 6C E0 0C 30 83 E2 0E 00 53 E1 22 00 00 8A 02 70 8C E0 0A 00 00 1A 00 00 56 E3 1B 00 00 0A 0C 30 86 E2 03 00 51 E1 18 00 00 1A 00 30 96 E5 08 20 96 E5 04 10 A0 E1 03 70 87 E0 DC FF FF EB 12 00 00 EA 04 50 94 E5 00 00 55 E3 0A 00 00 0A 00 C0 95 E5 05 30 6C E0 0C 30 83 E2 03 00 5E E1 05 00 00 1A 06 20 A0 E1 05 10 A0 E1 0C 70 87 E0 CF FF FF EB 05 40 A0 E1 04 00 00 EA 02 40 84 E0 05 30 A0 E1 06 20 A0 E1 04 10 A0 E1 C0 FF FF EB }
	condition:
		$pattern
}

rule readtcp_29b7d5791519fab8dbda8cdbc397403f {
	meta:
		aliases = "readtcp"
		size = "200"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 40 90 E5 08 D0 4D E2 00 50 A0 E1 01 60 A0 E1 02 70 A0 E1 01 C0 A0 E3 00 30 A0 E3 0C 10 A0 E1 98 20 9F E5 0D 00 A0 E1 05 30 CD E5 00 40 8D E5 04 C0 CD E5 ?? ?? ?? EB 01 00 70 E3 02 00 00 0A 00 00 50 E3 17 00 00 0A 04 00 00 EA ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 09 00 00 0A 11 00 00 EA 06 30 DD E5 07 20 DD E5 02 34 83 E1 03 38 A0 E1 43 38 A0 E1 18 00 13 E3 0A 00 00 1A 20 00 13 E3 08 00 00 1A 06 30 DD E5 01 00 13 E3 E0 FF FF 0A 04 00 A0 E1 06 10 A0 E1 07 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 03 00 00 CA 2C 20 95 E5 00 30 A0 E3 00 30 82 E5 00 00 E0 E3 08 D0 8D E2 F0 80 BD E8 B8 88 00 00 }
	condition:
		$pattern
}

rule inet_network_24b6994088442812cdc605603f373bb8 {
	meta:
		aliases = "__GI_inet_network, inet_network"
		size = "280"
		objfiles = "inet_net@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 40 A0 E3 04 70 A0 E1 00 30 D0 E5 30 00 53 E3 00 50 A0 13 0A 60 A0 13 07 00 00 1A 01 30 F0 E5 58 00 53 E3 78 00 53 13 01 50 A0 13 08 60 A0 13 01 00 80 02 00 50 A0 03 10 60 A0 03 00 E0 A0 E3 1D 00 00 EA C4 30 9F E5 00 30 93 E5 03 20 81 E0 03 10 D1 E7 01 30 D2 E5 03 24 81 E1 08 00 12 E3 09 00 00 0A 08 00 56 E3 00 30 A0 13 01 30 A0 03 37 00 5C E3 00 30 A0 93 00 00 53 E3 20 00 00 1A 96 CE 23 E0 30 E0 43 E2 07 00 00 EA 10 00 56 E3 0D 00 00 1A 10 00 12 E3 0B 00 00 0A 02 00 12 E3 56 30 E0 13 36 30 E0 03 0E E2 83 E0 FF 00 5E E3 01 00 80 E2 01 50 A0 E3 11 00 00 8A 00 C0 D0 E5 00 00 5C E3 }
	condition:
		$pattern
}

rule tdelete_34bf8f558c0dc8c1085a7390d8abc293 {
	meta:
		aliases = "tdelete"
		size = "224"
		objfiles = "tdelete@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 50 51 E2 00 70 A0 E1 02 40 A0 E1 30 00 00 0A 00 60 95 E5 00 00 56 E3 04 00 00 EA 04 50 83 E2 08 50 83 A2 03 60 A0 E1 00 30 95 E5 00 00 53 E3 27 00 00 0A 00 30 95 E5 07 00 A0 E1 00 10 93 E5 0F E0 A0 E1 04 F0 A0 E1 00 00 50 E3 00 30 95 E5 F1 FF FF 1A 04 40 93 E5 00 00 54 E3 08 10 93 E5 05 00 00 0A 00 00 51 E3 14 00 00 0A 04 20 91 E5 00 00 52 E3 04 00 00 1A 04 40 81 E5 01 40 A0 E1 0E 00 00 EA 03 20 A0 E1 00 10 A0 E1 04 30 92 E5 00 00 53 E3 02 00 A0 E1 F9 FF FF 1A 08 30 92 E5 04 30 81 E5 00 30 95 E5 04 30 93 E5 04 30 82 E5 00 30 95 E5 08 30 93 E5 08 30 82 E5 02 40 A0 E1 00 00 95 E5 }
	condition:
		$pattern
}

rule __GI_closedir_1e4aadb5d803b7a953f979cab533d627 {
	meta:
		aliases = "closedir, __GI_closedir"
		size = "180"
		objfiles = "closedir@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 50 A0 E1 00 40 95 E5 10 D0 4D E2 18 60 80 E2 01 00 74 E3 0D 70 A0 E1 80 10 9F E5 06 20 A0 E1 0D 00 A0 E1 04 00 00 1A ?? ?? ?? EB 09 30 A0 E3 04 20 A0 E1 00 30 80 E5 15 00 00 EA 60 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 58 30 9F E5 06 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 00 30 E0 E3 01 10 A0 E3 00 40 95 E5 0D 00 A0 E1 00 30 85 E5 38 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 0C 00 95 E5 ?? ?? ?? EB 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 ?? ?? ?? EB 00 20 A0 E1 02 00 A0 E1 10 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule wcsncasecmp_e8b25035a49256924aa12eea75b59f51 {
	meta:
		aliases = "__GI_wcsncasecmp, wcsncasecmp"
		size = "140"
		objfiles = "wcsncasecmp@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 50 A0 E1 01 60 A0 E1 02 70 A0 E1 04 00 00 EA 00 30 95 E5 00 00 53 E3 18 00 00 0A 04 50 85 E2 04 60 86 E2 00 00 57 E3 01 70 47 E2 13 00 00 0A 00 30 95 E5 00 20 96 E5 02 00 53 E1 03 00 A0 E1 F2 FF FF 0A ?? ?? ?? EB 00 40 A0 E1 00 00 96 E5 ?? ?? ?? EB 00 00 54 E1 EC FF FF 0A 00 00 95 E5 ?? ?? ?? EB 00 40 A0 E1 00 00 96 E5 ?? ?? ?? EB 00 00 54 E1 01 00 A0 23 00 00 E0 33 F0 80 BD E8 00 00 A0 E3 F0 80 BD E8 }
	condition:
		$pattern
}

rule get_input_bytes_0d8914ab521fafc339f54b8ea1ce26b6 {
	meta:
		aliases = "get_input_bytes"
		size = "120"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 50 A0 E1 01 70 A0 E1 02 60 A0 E1 13 00 00 EA 2C 30 95 E5 30 20 95 E5 03 20 52 E0 03 10 A0 E1 03 00 00 1A CB FF FF EB 00 00 50 E3 0B 00 00 1A F0 80 BD E8 06 00 52 E1 02 40 A0 B1 06 40 A0 A1 07 00 A0 E1 04 20 A0 E1 ?? ?? ?? EB 2C 30 95 E5 04 30 83 E0 2C 30 85 E5 06 60 64 E0 04 70 87 E0 00 00 56 E3 05 00 A0 E1 E8 FF FF CA 01 00 A0 E3 F0 80 BD E8 }
	condition:
		$pattern
}

rule pthread_atfork_b487c51bebd4a05bf7a34538d5400e35 {
	meta:
		aliases = "pthread_atfork"
		size = "164"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 00 50 A0 E1 18 00 A0 E3 01 60 A0 E1 02 70 A0 E1 ?? ?? ?? EB 00 40 50 E2 0C 30 A0 E3 64 00 9F E5 16 00 00 0A 60 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 10 A0 E1 54 00 9F E5 04 20 A0 E1 00 30 A0 E3 71 FF FF EB 06 10 A0 E1 44 00 9F E5 08 20 84 E2 01 30 A0 E3 6C FF FF EB 07 10 A0 E1 10 20 84 E2 30 00 9F E5 01 30 A0 E3 67 FF FF EB 28 30 9F E5 10 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 A0 E3 03 00 A0 E1 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule parse_printf_format_90a097b0a369e09d460c433be472acce {
	meta:
		aliases = "parse_printf_format"
		size = "308"
		objfiles = "parse_printf_format@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 50 A0 E1 98 D0 4D E2 01 40 A0 E1 0D 00 A0 E1 05 10 A0 E1 02 60 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 70 A0 B3 3E 00 00 BA 18 00 9D E5 00 00 50 E3 00 70 A0 D3 37 00 00 DA 00 70 A0 E1 04 00 50 E1 00 10 A0 31 04 10 A0 21 00 20 A0 E3 01 00 00 EA 70 30 13 E5 04 30 86 E4 98 00 8D E2 01 00 52 E1 02 31 80 E0 01 20 82 E2 F8 FF FF 3A 2C 00 00 EA 25 00 53 E3 26 00 00 1A 01 30 F5 E5 25 00 53 E3 23 00 00 0A 0D 00 A0 E1 00 50 8D E5 ?? ?? ?? EB 08 30 9D E5 02 01 53 E3 00 50 9D E5 04 00 00 1A 00 00 54 E3 02 31 83 12 04 30 86 14 01 70 87 E2 01 40 44 12 04 30 9D E5 02 01 53 E3 04 00 00 1A 00 00 54 E3 }
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

rule unsetenv_e22885973b118dd8b8bf43101db354df {
	meta:
		aliases = "__GI_unsetenv, unsetenv"
		size = "272"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 50 E2 10 D0 4D E2 06 00 00 0A 00 30 D6 E5 00 00 53 E3 03 00 00 0A 3D 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 04 00 00 0A ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 2A 00 00 EA 06 00 A0 E1 ?? ?? ?? EB A8 10 9F E5 A8 20 9F E5 A8 30 9F E5 00 70 A0 E1 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 98 30 9F E5 8C 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 8C 30 9F E5 00 50 93 E5 11 00 00 EA 04 00 A0 E1 06 10 A0 E1 07 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 0A 00 00 1A 07 30 D4 E7 3D 00 53 E3 07 00 00 1A 05 20 A0 E1 04 30 92 E5 00 30 82 E5 00 00 53 E3 04 30 82 E2 03 20 A0 E1 01 00 00 0A F8 FF FF EA 04 50 85 E2 }
	condition:
		$pattern
}

rule __GI_fgets_unlocked_5f4fd26a45ee2211395d069bc3c55ef5 {
	meta:
		aliases = "fgets_unlocked, __GI_fgets_unlocked"
		size = "152"
		objfiles = "fgets_unlocked@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 51 E2 00 70 A0 E1 02 50 A0 E1 00 40 A0 C1 15 00 00 CA 1B 00 00 EA 10 20 95 E5 18 30 95 E5 03 00 52 E1 05 00 00 2A 01 30 D2 E4 00 30 C4 E5 01 30 D4 E4 0A 00 53 E3 10 20 85 E5 09 00 00 EA ?? ?? ?? EB 01 00 70 E3 03 00 00 1A 00 30 D5 E5 08 00 13 E3 07 00 00 0A 0A 00 00 EA 00 00 C4 E5 01 30 D4 E4 0A 00 53 E3 02 00 00 0A 01 60 56 E2 05 00 A0 E1 E7 FF FF 1A 07 00 54 E1 00 30 A0 83 00 30 C4 85 00 00 00 8A 00 70 A0 E3 07 00 A0 E1 F0 80 BD E8 }
	condition:
		$pattern
}

rule timer_create_8fe6f64d7f85fad2a00b421337cbc7fa {
	meta:
		aliases = "timer_create"
		size = "172"
		objfiles = "timer_create@librt.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 51 E2 44 D0 4D E2 08 60 8D 05 0E 30 A0 03 0D 60 A0 01 04 30 8D 05 08 30 96 E5 02 00 53 E3 00 40 A0 E1 02 70 A0 E1 1A 00 00 0A 08 00 A0 E3 ?? ?? ?? EB 00 50 50 E2 16 00 00 0A 00 50 8D E5 04 00 A0 E1 40 20 8D E2 06 10 A0 E1 01 01 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 01 00 74 E3 05 00 00 0A 08 30 96 E5 00 30 85 E5 40 30 9D E5 00 50 87 E5 04 30 85 E5 03 00 00 EA 05 00 A0 E1 ?? ?? ?? EB 00 00 00 EA 00 40 E0 E3 04 00 A0 E1 44 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule fgetws_unlocked_0df18a176a23c80083a1c128fd24b9c6 {
	meta:
		aliases = "__GI_fgetws_unlocked, fgetws_unlocked"
		size = "88"
		objfiles = "fgetws_unlocked@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 A0 E1 01 50 A0 E1 02 70 A0 E1 00 40 A0 E1 01 00 55 E3 07 00 A0 E1 01 50 45 E2 06 00 00 DA ?? ?? ?? EB 01 00 70 E3 03 00 00 0A 00 00 84 E5 04 30 94 E4 0A 00 53 E3 F4 FF FF 1A 06 00 54 E1 00 60 A0 03 00 30 A0 13 06 00 A0 E1 00 30 84 15 F0 80 BD E8 }
	condition:
		$pattern
}

rule __pthread_compare_and_swap_bf7811973d5feaaa7566878bf7521b85 {
	meta:
		aliases = "__pthread_compare_and_swap"
		size = "60"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 A0 E1 03 00 A0 E1 03 50 A0 E1 01 40 A0 E1 02 70 A0 E1 4A FF FF EB 00 30 96 E5 04 00 53 E1 00 00 A0 E3 00 70 86 05 01 00 A0 03 00 30 A0 E3 00 30 85 E5 F0 80 BD E8 }
	condition:
		$pattern
}

rule __parsespent_024ed69796edd62d2a6a53c5c31574fa {
	meta:
		aliases = "__parsespent"
		size = "172"
		objfiles = "__parsespent@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 A0 E1 04 D0 4D E2 01 40 A0 E1 00 70 A0 E3 8C 30 9F E5 01 00 57 E3 04 00 A0 E1 3A 10 A0 E3 0A 20 A0 E3 07 50 D3 E7 04 00 00 CA 05 40 86 E7 ?? ?? ?? EB 00 20 50 E2 11 00 00 1A 15 00 00 EA 04 00 A0 E1 0D 10 A0 E1 ?? ?? ?? EB 00 20 9D E5 04 00 52 E1 00 30 E0 03 05 00 86 E7 05 30 86 07 08 00 57 E3 00 30 D2 E5 03 00 00 1A 00 00 53 E3 00 00 A0 03 08 00 00 0A 06 00 00 EA 3A 00 53 E3 04 00 00 1A 00 30 A0 E3 01 30 C2 E4 01 70 87 E2 02 40 A0 E1 DD FF FF EA 16 00 A0 E3 04 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fde_mixed_encoding_compare_1234e4fe42c954261a4d46f551de7f86 {
	meta:
		aliases = "fde_mixed_encoding_compare"
		size = "144"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 A0 E1 08 D0 4D E2 01 00 A0 E1 02 70 A0 E1 01 50 A0 E1 C6 FF FF EB FF 40 00 E2 04 00 A0 E1 06 10 A0 E1 C2 FE FF EB 08 20 85 E2 00 10 A0 E1 04 30 8D E2 04 00 A0 E1 D3 FE FF EB 07 00 A0 E1 BB FF FF EB FF 40 00 E2 06 10 A0 E1 04 00 A0 E1 B7 FE FF EB 08 20 87 E2 00 10 A0 E1 0D 30 A0 E1 04 00 A0 E1 C8 FE FF EB 04 20 9D E5 00 30 9D E5 03 00 52 E1 01 00 A0 E3 01 00 00 8A 00 00 E0 E3 00 00 A0 23 08 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule __get_next_rpcent_fa5d898d05c3f69379ac3005cc242351 {
	meta:
		aliases = "__get_next_rpcent"
		size = "324"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 60 A0 E1 A8 50 86 E2 00 20 96 E5 01 1A A0 E3 05 00 A0 E1 ?? ?? ?? EB 00 30 50 E2 0A 40 A0 E3 05 00 A0 E1 2C 00 00 0A ?? ?? ?? EB 06 30 80 E0 A7 40 C3 E5 A8 30 D6 E5 23 10 A0 E3 01 00 53 E1 05 00 A0 E1 EE FF FF 0A ?? ?? ?? EB 00 30 50 E2 00 70 A0 E3 04 10 A0 E1 05 00 A0 E1 02 00 00 1A ?? ?? ?? EB 00 30 50 E2 E5 FF FF 0A 00 70 C3 E5 05 00 A0 E1 CF FF FF EB 00 00 50 E3 E0 FF FF 0A 01 70 C0 E4 00 40 A0 E1 9C 50 86 E5 00 00 00 EA 01 40 84 E2 00 30 D4 E5 09 00 53 E3 20 00 53 13 00 70 A0 13 01 70 A0 03 F8 FF FF 0A 04 00 A0 E1 ?? ?? ?? EB 10 50 86 E2 A4 00 86 E5 A0 50 86 E5 04 00 A0 E1 }
	condition:
		$pattern
}

rule getcwd_c7fca8c30ec2d477994425803e109971 {
	meta:
		aliases = "__GI_getcwd, getcwd"
		size = "216"
		objfiles = "getcwd@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 70 51 E2 00 50 A0 E1 0B 00 00 1A 00 00 50 E3 04 00 00 0A ?? ?? ?? EB 07 50 A0 E1 16 30 A0 E3 00 30 80 E5 28 00 00 EA ?? ?? ?? EB 01 0A 50 E3 00 40 A0 A1 01 4A A0 B3 03 00 00 EA 00 00 50 E3 07 40 A0 E1 00 60 A0 11 03 00 00 1A 04 00 A0 E1 ?? ?? ?? EB 00 60 50 E2 1A 00 00 0A 04 10 A0 E1 06 00 A0 E1 B7 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 0B 00 00 EA 00 00 50 E3 09 00 00 BA 00 00 55 E3 00 00 57 03 03 00 00 1A 00 10 A0 E1 06 00 A0 E1 ?? ?? ?? EB 00 50 A0 E1 00 00 55 E3 06 50 A0 01 05 00 00 EA 00 00 55 E3 02 00 00 1A 06 00 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __GI_xdr_hyper_e006939b4c92f0f2fdc2dffda88ead06 {
	meta:
		aliases = "xdr_hyper, __GI_xdr_hyper"
		size = "232"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 70 90 E5 00 00 57 E3 08 D0 4D E2 00 50 A0 E1 01 60 A0 E1 12 00 00 1A 00 10 91 E5 04 20 96 E5 06 00 8D E8 04 10 8D E2 04 30 90 E5 C2 4F A0 E1 0F E0 A0 E1 04 F0 93 E5 00 00 50 E3 07 00 A0 01 25 00 00 0A 05 00 A0 E1 04 30 95 E5 0D 10 A0 E1 0F E0 A0 E1 04 F0 93 E5 00 00 50 E2 01 00 A0 13 1D 00 00 EA 01 00 57 E3 16 00 00 1A 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 14 00 00 0A 05 00 A0 E1 04 30 95 E5 0D 10 A0 E1 0F E0 A0 E1 00 F0 93 E5 00 00 50 E3 0D 00 00 0A 04 30 9D E5 04 30 86 E5 00 30 A0 E3 00 30 86 E5 00 20 9D E5 18 00 96 E8 07 00 A0 E1 02 30 83 E1 18 00 86 E8 }
	condition:
		$pattern
}

rule xdr_int64_t_25c00c4174bb1dbf3380cf316d90badb {
	meta:
		aliases = "xdr_int64_t"
		size = "224"
		objfiles = "xdr_intXX_t@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 70 90 E5 01 00 57 E3 08 D0 4D E2 00 50 A0 E1 01 60 A0 E1 16 00 00 0A 03 00 00 3A 02 00 57 E3 01 00 A0 03 2A 00 00 0A 28 00 00 EA 00 10 91 E5 04 20 96 E5 06 00 8D E8 04 10 8D E2 04 30 90 E5 C2 4F A0 E1 0F E0 A0 E1 24 F0 93 E5 00 00 50 E3 1F 00 00 0A 05 00 A0 E1 04 30 95 E5 0D 10 A0 E1 0F E0 A0 E1 24 F0 93 E5 00 00 50 E2 01 00 A0 13 17 00 00 EA 04 30 90 E5 04 10 8D E2 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 10 00 00 0A 05 00 A0 E1 04 30 95 E5 0D 10 A0 E1 0F E0 A0 E1 20 F0 93 E5 00 00 50 E3 09 00 00 0A 04 30 9D E5 04 30 86 E5 00 30 A0 E3 00 30 86 E5 00 20 9D E5 18 00 96 E8 07 00 A0 E1 }
	condition:
		$pattern
}

rule pthread_sighandler_rt_9421a8122e74846d039a1286aebf338e {
	meta:
		aliases = "pthread_sighandler_rt"
		size = "100"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 00 70 A0 E1 01 40 A0 E1 02 50 A0 E1 DB FF FF EB 58 30 D0 E5 00 00 53 E3 00 60 A0 E1 00 30 A0 13 04 10 A0 E1 05 20 A0 E1 07 00 A0 E1 20 70 86 15 58 30 C6 15 F0 80 BD 18 54 40 96 E5 00 00 54 E3 54 D0 86 05 10 30 9F E5 0F E0 A0 E1 07 F1 93 E7 00 00 54 E3 54 40 86 05 F0 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ether_hostton_1c876d10a2a9c5f5f15011a075ab9c47 {
	meta:
		aliases = "ether_hostton"
		size = "144"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 70 A0 E1 01 DC 4D E2 01 60 A0 E1 70 00 9F E5 70 10 9F E5 ?? ?? ?? EB 00 50 50 E2 00 40 E0 03 14 00 00 0A 08 00 00 EA 00 40 A0 E1 0F 00 00 EA DF FF FF EB 00 10 50 E2 07 00 A0 E1 02 00 00 0A ?? ?? ?? EB 00 00 50 E3 F6 FF FF 0A 01 1C A0 E3 05 20 A0 E1 0D 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 06 10 A0 E1 0D 00 A0 E1 F0 FF FF 1A 00 40 E0 E3 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 01 DC 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __parsepwent_d7a21690197cf05e17bacacb7f5ae25d {
	meta:
		aliases = "__parsepwent"
		size = "168"
		objfiles = "__parsepwent@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 70 A0 E1 04 D0 4D E2 01 40 A0 E1 00 60 A0 E3 06 30 06 E2 02 00 53 E3 80 30 9F E5 04 00 A0 E1 3A 10 A0 E3 0A 20 A0 E3 06 50 D3 E7 06 00 00 0A 06 00 56 E3 05 40 87 E7 13 00 00 0A ?? ?? ?? EB 00 00 50 E3 0B 00 00 1A 11 00 00 EA 04 00 A0 E1 0D 10 A0 E1 ?? ?? ?? EB 00 20 A0 E1 00 00 9D E5 04 00 50 E1 0A 00 00 0A 00 30 D0 E5 3A 00 53 E3 07 00 00 1A 05 20 87 E7 00 30 A0 E3 01 30 C0 E4 01 60 86 E2 00 40 A0 E1 E0 FF FF EA 00 00 A0 E3 00 00 00 EA 00 00 E0 E3 04 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_sleep_c70ea4427269f6e29239b03e740df0fa {
	meta:
		aliases = "sleep, __GI_sleep"
		size = "420"
		objfiles = "sleep@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 C0 50 E2 65 DF 4D E2 20 10 A0 13 02 00 00 1A 5C 00 00 EA 00 30 A0 E3 88 30 02 E5 01 10 51 E2 65 3F 8D E2 01 21 83 E0 F9 FF FF 5A 43 6F 8D E2 00 50 A0 E3 06 00 A0 E1 11 10 A0 E3 8C C1 8D E5 90 51 8D E5 ?? ?? ?? EB 05 00 50 E1 4F 00 00 BA 8C 40 8D E2 05 00 A0 E1 06 10 A0 E1 04 20 A0 E1 ?? ?? ?? EB 05 00 50 E1 48 00 00 1A 11 10 A0 E3 04 00 A0 E1 ?? ?? ?? EB 05 00 50 E1 20 10 A0 03 02 00 00 0A 32 00 00 EA 00 30 A0 E3 88 30 02 E5 01 10 51 E2 65 3F 8D E2 01 21 83 E0 F9 FF FF 5A 43 0F 8D E2 11 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 36 00 00 BA 11 00 A0 E3 00 10 A0 E3 0D 20 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule xdr_pointer_b26dbee1205a995fb9afb9329a7fce5c {
	meta:
		aliases = "xdr_pointer"
		size = "120"
		objfiles = "xdr_reference@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 C0 91 E5 04 D0 4D E2 00 C0 5C E2 01 C0 A0 13 01 40 A0 E1 04 10 8D E2 04 C0 21 E5 0D 10 A0 E1 02 60 A0 E1 03 70 A0 E1 00 50 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 C0 A0 E1 0A 00 00 0A 00 E0 9D E5 00 00 5E E3 05 00 A0 E1 04 10 A0 E1 06 20 A0 E1 07 30 A0 E1 01 C0 A0 E3 00 E0 84 05 01 00 00 0A ?? ?? ?? EB 00 C0 A0 E1 0C 00 A0 E1 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule strcasestr_9842a09d14533d43e5bc38768d474f0a {
	meta:
		aliases = "__GI_strcasestr, strcasestr"
		size = "156"
		objfiles = "strcasestr@libc.a"
	strings:
		$pattern = { F0 40 2D E9 00 E0 A0 E1 01 70 A0 E1 00 50 A0 E1 01 40 A0 E1 00 30 D4 E5 00 00 53 E3 83 60 A0 E1 01 40 84 E2 01 00 00 1A 0E 00 A0 E1 F0 80 BD E8 00 C0 D5 E5 0C 00 53 E1 01 50 85 E2 8C 00 A0 E1 F3 FF FF 0A 4C 30 9F E5 00 30 93 E5 03 10 80 E0 03 20 86 E0 01 20 D2 E5 01 10 D1 E5 03 00 D0 E7 03 30 D6 E7 02 2C A0 E1 01 1C A0 E1 42 38 83 E1 41 08 80 E1 00 00 53 E1 E5 FF FF 0A 01 E0 8E E2 00 00 5C E3 0E 50 A0 E1 07 40 A0 E1 E0 FF FF 1A 00 00 A0 E3 F0 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __stdio_fwrite_5f977362e116d13f70a131d074143b99 {
	meta:
		aliases = "__stdio_fwrite"
		size = "312"
		objfiles = "_fwrite@libc.a"
	strings:
		$pattern = { F0 40 2D E9 01 30 D2 E5 03 34 A0 E1 02 4C 13 E2 02 50 A0 E1 00 70 A0 E1 01 60 A0 E1 3E 00 00 1A 04 30 92 E5 02 00 73 E3 10 00 92 E5 0C 30 92 E5 09 00 00 1A 03 40 60 E0 04 00 51 E1 01 40 A0 31 04 20 A0 E1 07 10 A0 E1 ?? ?? ?? EB 10 30 95 E5 04 30 83 E0 10 30 85 E5 34 00 00 EA 03 30 60 E0 03 00 51 E1 24 00 00 8A 06 20 A0 E1 07 10 A0 E1 ?? ?? ?? EB 10 30 95 E5 01 20 D5 E5 06 30 83 E0 01 00 12 E3 10 30 85 E5 28 00 00 0A 07 00 A0 E1 0A 10 A0 E3 06 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 22 00 00 0A 05 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 1E 00 00 0A 00 00 56 E1 06 40 A0 31 00 40 A0 21 06 30 64 E0 03 70 87 E0 }
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

rule __getdents_cf647e3c219b95793b8539e344f7df30 {
	meta:
		aliases = "__getdents"
		size = "148"
		objfiles = "getdents@libc.a"
	strings:
		$pattern = { F0 40 2D E9 01 40 A0 E1 ?? ?? ?? EB 00 60 50 E2 06 70 84 C0 17 00 00 CA 1B 00 00 EA 10 E0 94 E5 08 20 94 E5 12 C0 D4 E5 4E 34 A0 E1 08 E0 C4 E5 04 20 84 E5 0A C0 C4 E5 09 30 C4 E5 08 20 D4 E5 01 30 D5 E5 03 24 82 E1 13 20 42 E2 ?? ?? ?? EB 08 30 D4 E5 01 20 D5 E5 04 00 A0 E1 02 24 83 E1 04 10 A0 E1 ?? ?? ?? EB 08 30 D4 E5 01 20 D5 E5 02 34 83 E1 03 40 84 E0 07 00 54 E1 08 50 84 E2 13 10 84 E2 0B 00 84 E2 E3 FF FF 3A 06 00 A0 E1 F0 80 BD E8 }
	condition:
		$pattern
}

rule asctime_r_479599da9e53df4f90f719de5e41f0f8 {
	meta:
		aliases = "__GI_asctime_r, asctime_r"
		size = "292"
		objfiles = "asctime_r@libc.a"
	strings:
		$pattern = { F0 40 2D E9 01 60 A0 E1 00 70 A0 E1 00 11 9F E5 06 00 A0 E1 1A 20 A0 E3 ?? ?? ?? EB 18 10 97 E5 06 00 51 E3 EC 30 9F 95 03 20 A0 93 92 31 21 90 06 00 A0 91 ?? ?? ?? 9B 10 10 97 E5 0B 00 51 E3 D4 30 9F 95 03 20 A0 93 92 31 21 90 04 00 86 92 ?? ?? ?? 9B 14 30 97 E5 76 5E 83 E2 BC 30 9F E5 0C 50 85 E2 03 00 55 E1 13 40 86 E2 0C 00 00 8A 17 40 86 E2 05 00 A0 E1 0A 10 A0 E3 ?? ?? ?? EB 30 00 80 E2 00 00 C4 E5 0A 10 A0 E3 05 00 A0 E1 ?? ?? ?? EB 01 30 74 E5 3F 00 53 E3 00 50 A0 E1 F3 FF FF 0A 01 30 54 E5 03 60 97 E7 3F 30 A0 E3 63 00 56 E3 0A 10 A0 E3 06 00 A0 E1 01 50 44 E2 01 30 44 85 07 00 00 8A }
	condition:
		$pattern
}

rule ether_aton_r_dbb01057b705381befcf8def1a10225d {
	meta:
		aliases = "__GI_ether_aton_r, ether_aton_r"
		size = "276"
		objfiles = "ether_addr@libc.a"
	strings:
		$pattern = { F0 40 2D E9 01 60 A0 E1 00 70 A0 E3 38 00 00 EA F4 30 9F E5 00 50 93 E5 00 30 D0 E5 83 C0 D5 E7 30 E0 4C E2 FF 20 0E E2 61 30 4C E2 09 00 52 E3 05 00 53 83 31 00 00 8A D0 30 9F E5 00 10 93 E5 8C 30 D1 E7 08 00 13 E3 01 30 D0 E5 57 40 4C 02 83 C0 D5 E7 0E 40 A0 11 04 00 57 E3 00 50 A0 83 01 50 A0 93 3A 00 5C E3 00 30 A0 03 01 30 05 12 00 00 53 E3 01 00 80 E2 09 00 00 1A 05 00 57 E3 00 30 A0 13 01 30 A0 03 00 00 5C E3 00 30 A0 03 00 00 53 E3 13 00 00 0A 8C 30 D1 E7 20 00 13 E3 10 00 00 1A 30 E0 4C E2 FF 20 0E E2 61 30 4C E2 09 00 52 E3 05 00 53 83 10 00 00 8A 8C 30 D1 E7 08 00 13 E3 01 30 F0 E5 }
	condition:
		$pattern
}

rule clnt_spcreateerror_a9cba549ee5dfb0c743771ebdf3b16e7 {
	meta:
		aliases = "__GI_clnt_spcreateerror, clnt_spcreateerror"
		size = "256"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { F0 40 2D E9 01 DB 4D E2 00 40 A0 E1 F0 FF FF EB 00 60 50 E2 34 00 00 0A ?? ?? ?? EB 04 20 A0 E1 00 50 A0 E1 CC 10 9F E5 06 00 A0 E1 ?? ?? ?? EB 00 40 86 E0 00 00 95 E5 ?? ?? ?? EB 00 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 ?? ?? ?? EB 00 30 95 E5 00 40 84 E0 0C 00 53 E3 0D 70 A0 E1 94 10 9F E5 04 00 A0 E1 0D 00 00 0A 0E 00 53 E3 19 00 00 1A ?? ?? ?? EB 04 00 A0 E1 ?? ?? ?? EB 00 40 84 E0 04 00 95 E5 ?? ?? ?? EB 00 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 ?? ?? ?? EB 0C 00 00 EA ?? ?? ?? EB 04 00 A0 E1 ?? ?? ?? EB 01 2B A0 E3 00 40 84 E0 0D 10 A0 E1 08 00 95 E5 ?? ?? ?? EB 04 00 A0 E1 }
	condition:
		$pattern
}

rule __GI_clnt_sperror_56c7e3bff141ff6dd8cb76f5cf73ccc9 {
	meta:
		aliases = "clnt_sperror, __GI_clnt_sperror"
		size = "480"
		objfiles = "clnt_perror@libc.a"
	strings:
		$pattern = { F0 40 2D E9 01 DB 4D E2 0C D0 4D E2 00 40 A0 E1 01 50 A0 E1 A7 FF FF EB 00 70 50 E2 63 00 00 0A 04 30 94 E5 04 00 A0 E1 01 1B 8D E2 0F E0 A0 E1 08 F0 93 E5 05 20 A0 E1 80 11 9F E5 07 00 A0 E1 ?? ?? ?? EB 00 40 87 E0 00 04 9D E5 ?? ?? ?? EB 00 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 ?? ?? ?? EB 00 34 9D E5 00 50 84 E0 11 00 53 E3 03 F1 9F 97 43 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0D 10 A0 E1 01 2B A0 E3 }
	condition:
		$pattern
}

rule fseeko64_f4969b96dc30b14b2310e5155d494b02 {
	meta:
		aliases = "__GI_fseeko64, fseeko64"
		size = "304"
		objfiles = "fseeko64@libc.a"
	strings:
		$pattern = { F0 40 2D E9 02 00 53 E3 18 D0 4D E2 03 60 A0 E1 00 50 A0 E1 04 00 00 9A ?? ?? ?? EB 00 40 E0 E3 16 30 A0 E3 00 30 80 E5 39 00 00 EA 34 70 90 E5 00 00 57 E3 10 10 8D E5 14 20 8D E5 0A 00 00 1A 38 40 80 E2 D4 30 9F E5 0D 00 A0 E1 D0 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 C0 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 D5 E5 40 00 13 E3 03 00 00 0A 05 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 1B 00 00 1A 01 00 56 E3 04 00 00 1A 05 00 A0 E1 10 10 8D E2 ?? ?? ?? EB 00 00 50 E3 14 00 00 BA 06 20 A0 E1 05 00 A0 E1 10 10 8D E2 ?? ?? ?? EB 00 00 50 E3 0E 00 00 BA 00 30 95 E5 08 20 95 E5 00 00 A0 E3 }
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

rule erand48_r_e6f15e172875f10300f210b313b4ff3d {
	meta:
		aliases = "__GI_erand48_r, erand48_r"
		size = "140"
		objfiles = "erand48_r@libc.a"
	strings:
		$pattern = { F0 40 2D E9 02 70 A0 E1 00 60 A0 E1 ?? ?? ?? EB 00 40 A0 E3 02 41 C4 E3 01 31 C4 E3 FF 35 83 E3 00 00 50 E3 03 46 83 E3 00 00 E0 E3 00 50 A0 E3 24 EA A0 E1 F0 80 BD B8 03 20 D6 E5 02 00 D6 E5 05 30 D6 E5 04 10 D6 E5 02 04 80 E1 01 C0 D6 E5 00 20 D6 E5 03 14 81 E1 20 36 A0 E1 01 32 83 E1 0C 24 82 E1 03 E6 8E E1 02 22 A0 E1 00 5A 82 E1 6E 46 A0 E1 30 00 2D E9 02 91 BD EC 00 00 A0 E3 89 01 21 EE 00 81 87 ED F0 80 BD E8 }
	condition:
		$pattern
}

rule fwrite_unlocked_0906c40fe0a986ebc96eaf2381e5ae28 {
	meta:
		aliases = "__GI_fwrite_unlocked, fwrite_unlocked"
		size = "172"
		objfiles = "fwrite_unlocked@libc.a"
	strings:
		$pattern = { F0 40 2D E9 03 40 A0 E1 00 30 D3 E5 C0 30 03 E2 C0 00 53 E3 01 50 A0 E1 00 70 A0 E1 02 60 A0 E1 80 10 A0 E3 04 00 A0 E1 02 00 00 0A ?? ?? ?? EB 00 00 50 E3 19 00 00 1A 00 00 55 E3 00 00 56 13 05 10 A0 E1 00 00 E0 E3 14 00 00 0A ?? ?? ?? EB 00 00 56 E1 04 20 A0 E1 07 00 A0 E1 05 00 00 8A 96 05 01 E0 ?? ?? ?? EB 05 10 A0 E1 ?? ?? ?? EB 00 20 A0 E1 0A 00 00 EA 00 30 94 E5 08 30 83 E3 43 24 A0 E1 01 20 C4 E5 00 30 C4 E5 ?? ?? ?? EB 16 30 A0 E3 00 20 A0 E3 00 30 80 E5 00 00 00 EA 00 20 A0 E3 02 00 A0 E1 F0 80 BD E8 }
	condition:
		$pattern
}

rule lockf64_55bd3def29129ccc63ea6bbd3b92e847 {
	meta:
		aliases = "__GI_lockf64, lockf64"
		size = "328"
		objfiles = "lockf64@libc.a"
	strings:
		$pattern = { F0 40 2D E9 03 60 A0 E1 02 30 A0 E1 C3 4F A0 E1 04 00 56 E1 18 D0 4D E2 02 50 A0 E1 00 70 A0 E1 01 40 A0 E1 03 00 00 0A ?? ?? ?? EB 00 20 E0 E3 4B 30 A0 E3 2A 00 00 EA 18 20 A0 E3 0D 00 A0 E1 00 10 A0 E3 ?? ?? ?? EB 01 30 A0 E3 02 30 CD E5 00 30 A0 E3 03 30 CD E5 00 20 A0 E3 00 30 A0 E3 0C 50 8D E5 10 60 8D E5 0C 00 8D E9 03 00 54 E3 04 F1 9F 97 2B 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 30 A0 E3 0D 20 A0 E1 07 00 A0 E1 0C 10 A0 E3 01 30 CD E5 00 30 CD E5 ?? ?? ?? EB 00 00 50 E3 00 20 E0 B3 22 00 00 BA 01 30 DD E5 00 20 DD E5 03 3C A0 E1 43 28 82 E1 02 00 52 E3 1B 00 00 0A }
	condition:
		$pattern
}

rule __pthread_alt_lock_71f2bb88322a2dff2c548a01fba817b1 {
	meta:
		aliases = "__pthread_alt_lock"
		size = "116"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 04 60 80 E2 00 50 A0 E1 0C D0 4D E2 06 00 A0 E1 01 70 A0 E1 AF FF FF EB 00 40 95 E5 00 00 54 E3 01 30 A0 03 04 20 A0 E1 00 30 85 05 08 00 00 0A 00 00 57 E3 01 00 00 1A CF FF FF EB 00 70 A0 E1 00 30 A0 E3 00 D0 85 E5 08 30 8D E5 90 00 8D E8 01 20 A0 E3 00 30 A0 E3 00 30 86 E5 03 00 52 E1 07 00 A0 E1 E3 FF FF 1B 0C D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule recv_9f456afe647f211a108d8f577808cae8 {
	meta:
		aliases = "send, pread, pwrite, recv"
		size = "84"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 04 D0 4D E2 00 40 A0 E1 01 50 A0 E1 02 60 A0 E1 03 70 A0 E1 0D 10 A0 E1 01 00 A0 E3 ?? ?? ?? EB 05 10 A0 E1 06 20 A0 E1 07 30 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 10 A0 E3 00 40 A0 E1 00 00 9D E5 ?? ?? ?? EB 04 00 A0 E1 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule unlockpt_0e7689696ad569e4b7fd7bddc1273284 {
	meta:
		aliases = "unlockpt"
		size = "92"
		objfiles = "unlockpt@libc.a"
	strings:
		$pattern = { F0 40 2D E9 04 D0 4D E2 00 40 A0 E1 ?? ?? ?? EB 00 70 A0 E3 04 20 8D E2 00 60 90 E5 00 50 A0 E1 04 70 22 E5 04 00 A0 E1 0D 20 A0 E1 24 10 9F E5 ?? ?? ?? EB 00 00 50 E3 04 00 00 0A 00 30 95 E5 16 00 53 E3 00 60 85 05 00 00 E0 E3 07 00 A0 01 04 D0 8D E2 F0 80 BD E8 31 54 04 40 }
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

rule __GI_svc_unregister_99a661868c390cf6a859b698c4692b38 {
	meta:
		aliases = "svc_unregister, __GI_svc_unregister"
		size = "96"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { F0 40 2D E9 04 D0 4D E2 0D 20 A0 E1 01 70 A0 E1 00 60 A0 E1 54 FF FF EB 00 40 50 E2 0D 00 00 0A 00 30 9D E5 00 50 94 E5 00 00 53 E3 00 50 83 15 01 00 00 1A ?? ?? ?? EB B8 50 80 E5 00 30 A0 E3 04 00 A0 E1 00 30 84 E5 ?? ?? ?? EB 06 00 A0 E1 07 10 A0 E1 ?? ?? ?? EB 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule lsearch_4f518f943fcf6a0e13f77c877c39dcda {
	meta:
		aliases = "lsearch"
		size = "84"
		objfiles = "lsearch@libc.a"
	strings:
		$pattern = { F0 40 2D E9 04 D0 4D E2 18 C0 9D E5 02 50 A0 E1 03 60 A0 E1 01 70 A0 E1 00 40 A0 E1 00 C0 8D E5 ?? ?? ?? EB 00 00 50 E3 04 10 A0 E1 06 20 A0 E1 05 00 00 1A 00 30 95 E5 93 76 20 E0 ?? ?? ?? EB 00 30 95 E5 01 30 83 E2 00 30 85 E5 04 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule __ieee754_rem_pio2_37022758f5283aab75547c990eca1331 {
	meta:
		aliases = "__ieee754_rem_pio2"
		size = "844"
		objfiles = "e_rem_pio2@libm.a"
	strings:
		$pattern = { F0 40 2D E9 06 42 6D ED 00 30 A0 E1 1C 33 9F E5 02 51 C0 E3 03 00 55 E1 20 D0 4D E2 03 00 2D E9 02 91 BD EC 01 40 A0 E1 00 70 A0 E1 02 60 A0 E1 00 30 A0 D3 00 40 A0 D3 00 00 A0 D3 08 30 82 D5 0C 40 82 D5 6B 00 00 DA E4 32 9F E5 03 00 55 E1 21 00 00 CA 00 00 50 E3 10 00 00 DA A1 81 9F ED D0 32 9F E5 03 00 55 E1 80 31 21 EE 9F 91 9F 0D A0 81 9F 1D A1 81 9F 0D 81 11 23 0E 80 21 21 0E 80 21 23 1E 82 11 23 1E 82 11 21 0E 80 11 21 EE 01 00 A0 E3 02 91 86 ED 00 A1 86 ED 8E 00 00 EA 90 81 9F ED 8C 32 9F E5 03 00 55 E1 80 31 01 EE 8E 91 9F 0D 8F 81 9F 1D 90 81 9F 0D 81 11 03 0E 80 21 01 0E 80 21 03 1E }
	condition:
		$pattern
}

rule logwtmp_d1e7154004475b643bd51595e7d4a2f7 {
	meta:
		aliases = "logwtmp"
		size = "172"
		objfiles = "logwtmp@libutil.a"
	strings:
		$pattern = { F0 40 2D E9 06 DD 4D E2 01 50 A0 E1 00 60 A0 E1 02 70 A0 E1 00 10 A0 E3 06 2D A0 E3 0D 00 A0 E1 ?? ?? ?? EB 00 00 55 E3 03 00 00 0A 00 30 D5 E5 00 00 53 E3 07 20 A0 E3 00 00 00 1A 08 20 A0 E3 42 34 A0 E1 01 30 CD E5 00 20 CD E5 ?? ?? ?? EB 06 10 A0 E1 04 00 8D E5 1F 20 A0 E3 08 00 8D E2 ?? ?? ?? EB 05 10 A0 E1 1F 20 A0 E3 2C 00 8D E2 ?? ?? ?? EB 07 10 A0 E1 FF 20 A0 E3 4C 00 8D E2 ?? ?? ?? EB 00 10 A0 E3 55 0F 8D E2 ?? ?? ?? EB 0D 10 A0 E1 0C 00 9F E5 0D 40 A0 E1 ?? ?? ?? EB 06 DD 8D E2 F0 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __ieee754_atan2_0aa39c66b04a4bc1bae83297c4e48bd7 {
	meta:
		aliases = "__ieee754_atan2"
		size = "620"
		objfiles = "e_atan2@libm.a"
	strings:
		$pattern = { F0 40 2D E9 0C 00 2D E9 02 91 BD EC 03 40 A0 E1 02 30 A0 E1 03 70 A0 E1 00 30 64 E2 03 30 84 E1 04 E0 A0 E1 02 51 C7 E3 38 42 9F E5 A3 3F 85 E1 04 00 53 E1 01 30 A0 E1 03 00 2D E9 02 81 BD EC 00 20 A0 E1 03 C0 A0 E1 06 00 00 8A 00 30 63 E2 03 30 8C E1 02 21 C0 E3 A3 3F 82 E1 04 00 53 E1 00 60 A0 E1 01 00 00 9A 81 01 00 EE F0 80 BD E8 03 31 87 E2 01 36 83 E2 0E 30 93 E1 01 00 00 1A F0 40 BD E8 ?? ?? ?? EA 47 3F A0 E1 02 30 03 E2 0C C0 92 E1 A0 4F 83 E1 06 00 00 1A 03 00 54 E3 04 F1 9F 97 03 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0E E0 95 E1 25 00 00 0A A0 31 9F E5 03 00 55 E1 }
	condition:
		$pattern
}

rule _obstack_newchunk_ddbb27bd0eba97a5d3a1f1ab1ecfb961 {
	meta:
		aliases = "_obstack_newchunk"
		size = "368"
		objfiles = "obstack@libc.a"
	strings:
		$pattern = { F0 40 2D E9 0C 30 80 E2 88 00 13 E8 03 70 47 E0 18 20 90 E5 01 10 87 E0 C7 31 A0 E1 00 40 A0 E1 02 10 81 E0 64 30 83 E2 00 20 90 E5 28 00 D0 E5 03 10 81 E0 02 00 51 E1 01 50 A0 A1 02 50 A0 B1 01 00 10 E3 04 60 94 E5 1C 30 94 E5 04 00 00 0A 24 00 94 E5 05 10 A0 E1 0F E0 A0 E1 03 F0 A0 E1 02 00 00 EA 05 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 00 00 50 E3 52 00 00 0B 18 30 94 E5 08 20 80 E2 02 00 53 E3 05 10 80 E0 03 20 82 E0 27 C1 A0 C1 10 10 84 E5 04 00 84 E5 00 10 80 E5 03 50 C2 E1 04 60 80 E5 00 30 A0 D3 01 10 4C C2 05 00 00 CA 07 00 00 EA 08 30 94 E5 01 21 A0 E1 02 30 93 E7 02 30 85 E7 01 10 41 E2 }
	condition:
		$pattern
}

rule __GI_sigaction_7823dd2fc3bb2506d1ac76864e6b3700 {
	meta:
		aliases = "sigaction, __GI_sigaction"
		size = "304"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 0C 31 9F E5 00 30 93 E5 03 00 50 E1 8C D0 4D E2 00 40 A0 E1 02 70 A0 E1 01 50 A0 E1 37 00 00 0A F0 30 9F E5 00 30 93 E5 03 00 50 E1 33 00 00 0A E4 30 9F E5 00 30 93 E5 03 00 50 E1 01 00 00 1A 00 00 50 E3 2D 00 00 CA 00 00 55 E3 05 00 A0 01 16 00 00 0A 0D 00 A0 E1 8C 20 A0 E3 0D 60 A0 E1 ?? ?? ?? EB 00 30 95 E5 01 00 53 E3 00 30 A0 93 01 30 A0 83 00 00 54 E3 00 30 A0 D3 00 00 53 E3 09 00 00 0A 40 00 54 E3 07 00 00 CA 84 30 95 E5 04 00 13 E3 84 30 9F 15 84 30 9F 05 0D 00 A0 11 0D 00 A0 01 00 30 8D E5 00 00 00 EA 0D 00 A0 E1 00 10 A0 E1 07 20 A0 E1 04 00 A0 E1 ?? ?? ?? EB 01 00 70 E3 }
	condition:
		$pattern
}

rule xdrrec_getbytes_526ad46796d0916d913acf90994da04d {
	meta:
		aliases = "xdrrec_getbytes"
		size = "144"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { F0 40 2D E9 0C 50 90 E5 01 70 A0 E1 02 60 A0 E1 16 00 00 EA 34 20 95 E5 00 00 52 E3 06 00 00 1A 38 30 95 E5 00 00 53 E3 16 00 00 1A 9E FF FF EB 00 00 50 E3 0D 00 00 1A 12 00 00 EA 06 00 52 E1 02 40 A0 31 06 40 A0 21 05 00 A0 E1 04 20 A0 E1 77 FF FF EB 00 00 50 E3 06 60 64 E0 04 70 87 E0 08 00 00 0A 34 30 95 E5 03 30 64 E0 34 30 85 E5 00 00 56 E3 05 00 A0 E1 07 10 A0 E1 E4 FF FF 1A 01 00 A0 E3 F0 80 BD E8 00 00 A0 E3 F0 80 BD E8 }
	condition:
		$pattern
}

rule xdrrec_putbytes_bc8fd4b01439ddcff8c28190eacbfc48 {
	meta:
		aliases = "xdrrec_putbytes"
		size = "148"
		objfiles = "xdr_rec@libc.a"
	strings:
		$pattern = { F0 40 2D E9 0C 50 90 E5 01 70 A0 E1 02 60 A0 E1 1A 00 00 EA 10 00 85 E2 11 00 90 E8 04 40 60 E0 06 00 54 E1 06 40 A0 21 04 20 A0 E1 ?? ?? ?? EB 10 20 95 E5 04 60 56 E0 14 C0 95 E5 04 20 82 E0 00 30 A0 03 01 30 A0 13 00 10 A0 E3 0C 00 52 E1 00 30 A0 13 01 30 03 02 01 00 53 E1 05 00 A0 E1 04 70 87 E0 10 20 85 E5 04 00 00 0A 01 30 A0 E3 1C 30 85 E5 39 FE FF EB 00 00 50 E3 F0 80 BD 08 00 00 56 E3 07 10 A0 E1 E1 FF FF 1A 01 00 A0 E3 F0 80 BD E8 }
	condition:
		$pattern
}

rule sendto_772dc59a2a283d2b973f08b7b8fd7337 {
	meta:
		aliases = "recvfrom, sendto"
		size = "100"
		objfiles = "wrapsyscall@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 0C D0 4D E2 00 70 A0 E1 01 40 A0 E1 01 00 A0 E3 08 10 8D E2 02 50 A0 E1 03 60 A0 E1 ?? ?? ?? EB 20 C0 9D E5 00 C0 8D E5 24 C0 9D E5 04 10 A0 E1 05 20 A0 E1 06 30 A0 E1 07 00 A0 E1 04 C0 8D E5 ?? ?? ?? EB 00 10 A0 E3 00 40 A0 E1 08 00 9D E5 ?? ?? ?? EB 04 00 A0 E1 0C D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule init_object_caeeee8da30166f6042dad05118b4862 {
	meta:
		aliases = "init_object"
		size = "308"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { F0 40 2D E9 10 C0 90 E5 AC 25 B0 E1 08 D0 4D E2 00 50 A0 E1 02 60 A0 11 1B 00 00 1A 10 30 D0 E5 02 00 13 E3 3E 00 00 0A 0C 30 90 E5 00 10 93 E5 00 00 51 E3 01 60 A0 01 06 20 A0 01 0A 00 00 0A 03 40 A0 E1 02 60 A0 E1 05 00 A0 E1 31 FF FF EB 04 10 B4 E5 00 00 51 E3 00 60 86 E0 F9 FF FF 1A FF 24 C6 E3 10 C0 95 E5 0E 26 C2 E3 8C 3A A0 E1 A3 3A A0 E1 82 C5 83 E1 AC 05 56 E1 8C 3A A0 11 A3 3A A0 11 10 C0 85 E5 10 30 85 15 0D 00 A0 E1 06 10 A0 E1 70 FF FF EB 00 00 50 E3 0D 70 A0 E1 18 00 00 0A 10 30 D5 E5 02 00 13 E3 17 00 00 0A 0C 30 95 E5 00 20 93 E5 00 00 52 E3 06 00 00 0A 03 40 A0 E1 05 00 A0 E1 }
	condition:
		$pattern
}

rule utmpname_27abe80c9d11b840b91704e11d2dcfb9 {
	meta:
		aliases = "utmpname"
		size = "188"
		objfiles = "utent@libc.a"
	strings:
		$pattern = { F0 40 2D E9 10 D0 4D E2 00 40 A0 E1 88 10 9F E5 88 20 9F E5 0D 00 A0 E1 84 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 74 00 9F E5 78 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 54 E3 6C 70 9F E5 6C 60 9F E5 6C 50 9F E5 07 00 00 0A 00 00 96 E5 05 00 50 E1 ?? ?? ?? 1B 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 05 00 A0 01 00 00 86 E5 00 00 97 E5 01 00 70 E3 ?? ?? ?? 1B 00 30 E0 E3 0D 00 A0 E1 00 30 87 E5 01 10 A0 E3 2C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 A0 E3 10 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule openlog_d9b1846b22eb2a7049d3c54688182ea5 {
	meta:
		aliases = "__GI_openlog, openlog"
		size = "384"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { F0 40 2D E9 10 D0 4D E2 00 50 A0 E1 01 60 A0 E1 02 40 A0 E1 0D 00 A0 E1 34 11 9F E5 34 21 9F E5 34 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 2C 31 9F E5 20 01 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 55 E3 1C 31 9F 15 00 50 83 15 18 31 9F E5 00 00 54 E3 00 60 83 E5 02 00 00 0A FE 3F D4 E3 08 31 9F 05 00 40 83 05 04 31 9F E5 00 30 93 E5 01 00 73 E3 02 70 A0 13 17 00 00 1A 02 70 A0 E3 E4 30 9F E5 00 30 93 E5 08 00 13 E3 12 00 00 0A 01 00 A0 E3 07 10 A0 E1 00 20 A0 E3 ?? ?? ?? EB CC 40 9F E5 01 00 70 E3 00 00 84 E5 22 00 00 0A 01 20 A0 E3 02 10 A0 E3 ?? ?? ?? EB 00 40 94 E5 03 10 A0 E3 04 00 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __GI_opendir_48a7c49164ac94f9fbdfff55ee1f6558 {
	meta:
		aliases = "opendir, __GI_opendir"
		size = "252"
		objfiles = "opendir@libc.a"
	strings:
		$pattern = { F0 40 2D E9 12 1B A0 E3 58 D0 4D E2 ?? ?? ?? EB 00 70 50 E2 00 60 A0 B3 33 00 00 BA 0D 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 05 00 00 BA 07 00 A0 E1 02 10 A0 E3 01 20 A0 E3 ?? ?? ?? EB 00 00 50 E3 07 00 00 AA ?? ?? ?? EB 00 50 A0 E1 07 00 A0 E1 00 40 95 E5 ?? ?? ?? EB 00 60 A0 E3 00 40 85 E5 21 00 00 EA 30 00 A0 E3 ?? ?? ?? EB 00 60 50 E2 11 00 00 0A 00 40 A0 E3 10 40 86 E5 30 30 9D E5 02 0C 53 E3 14 30 86 E5 02 3C A0 33 14 30 86 35 00 70 86 E5 08 40 86 E5 04 40 86 E5 01 00 A0 E3 14 10 96 E5 ?? ?? ?? EB 00 00 50 E3 0C 00 86 E5 08 00 00 1A 06 00 A0 E1 ?? ?? ?? EB 07 00 A0 E1 ?? ?? ?? EB ?? ?? ?? EB }
	condition:
		$pattern
}

rule _Unwind_SjLj_RaiseException_12eafd0859350467d95ba2404de2b437 {
	meta:
		aliases = "_Unwind_SjLj_RaiseException"
		size = "212"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { F0 40 2D E9 14 D0 4D E2 10 70 8D E2 00 40 A0 E1 07 00 A0 E1 33 FF FF EB 10 30 9D E5 0C 50 8D E2 08 60 8D E2 0C 30 8D E5 11 00 00 EA 00 00 50 E3 16 00 00 1A 08 C0 9D E5 00 00 5C E3 09 00 00 0A 01 00 80 E2 0C 00 94 E8 00 10 A0 E1 30 00 8D E8 0F E0 A0 E1 0C F0 A0 E1 06 00 50 E3 0D 00 00 0A 08 00 50 E3 09 00 00 1A 05 00 A0 E1 06 10 A0 E1 0F FF FF EB 05 00 A0 E1 06 10 A0 E1 03 FF FF EB 05 00 50 E3 E8 FF FF 1A 14 D0 8D E2 F0 80 BD E8 03 00 A0 E3 FB FF FF EA 00 30 A0 E3 0C 30 84 E5 05 00 A0 E1 14 FF FF EB 10 30 9D E5 10 00 84 E5 05 10 A0 E1 04 00 A0 E1 0C 30 8D E5 6B FF FF EB 07 00 50 E3 EF FF FF 1A }
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

rule if_indextoname_c94331954daa4eb102e5ef1eb46050e1 {
	meta:
		aliases = "if_indextoname"
		size = "144"
		objfiles = "if_index@libc.a"
	strings:
		$pattern = { F0 40 2D E9 20 D0 4D E2 01 60 A0 E1 00 50 A0 E1 ?? ?? ?? EB 00 40 50 E2 0D 70 A0 E1 0D 20 A0 E1 64 10 9F E5 00 30 A0 E3 14 00 00 BA 10 50 8D E5 ?? ?? ?? EB 00 00 50 E3 04 00 A0 E1 09 00 00 AA ?? ?? ?? EB 00 50 A0 E1 04 00 A0 E1 00 40 95 E5 ?? ?? ?? EB 13 00 54 E3 06 40 A0 03 00 30 A0 E3 00 40 85 E5 05 00 00 EA ?? ?? ?? EB 06 00 A0 E1 0D 10 A0 E1 10 20 A0 E3 ?? ?? ?? EB 00 30 A0 E1 03 00 A0 E1 20 D0 8D E2 F0 80 BD E8 10 89 00 00 }
	condition:
		$pattern
}

rule __GI_tcgetattr_f53058a9eff366a9fe196a2c11a6afea {
	meta:
		aliases = "tcgetattr, __GI_tcgetattr"
		size = "108"
		objfiles = "tcgetattr@libc.a"
	strings:
		$pattern = { F0 40 2D E9 24 D0 4D E2 01 60 A0 E1 0D 20 A0 E1 50 10 9F E5 ?? ?? ?? EB 00 70 50 E2 0D 40 A0 E1 11 10 8D E2 13 20 A0 E3 11 00 86 E2 0A 00 00 1A 00 50 9D E9 0C 40 9D E5 10 50 DD E5 00 30 9D E5 08 50 86 E8 0C 40 86 E5 10 50 C6 E5 ?? ?? ?? EB 07 10 A0 E1 0D 20 A0 E3 ?? ?? ?? EB 07 00 A0 E1 24 D0 8D E2 F0 80 BD E8 01 54 00 00 }
	condition:
		$pattern
}

rule rendezvous_request_68a376d1ecdebc1539e57c59f36e8f37 {
	meta:
		aliases = "rendezvous_request"
		size = "120"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { F0 40 2D E9 2C 50 90 E5 14 D0 4D E2 00 40 A0 E1 00 00 94 E5 0D 10 A0 E1 10 20 8D E2 10 60 A0 E3 10 60 8D E5 ?? ?? ?? EB 00 00 50 E3 0D 70 A0 E1 04 00 00 AA ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 09 00 00 1A F1 FF FF EA 06 00 95 E8 B6 FE FF EB 0D 10 A0 E1 00 40 A0 E1 06 20 A0 E1 10 00 80 E2 ?? ?? ?? EB 10 30 9D E5 0C 30 84 E5 00 00 A0 E3 14 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule svctcp_recv_277ba73c39f882fb63c891a1853dfc24 {
	meta:
		aliases = "svctcp_recv"
		size = "72"
		objfiles = "svc_tcp@libc.a"
	strings:
		$pattern = { F0 40 2D E9 2C 60 90 E5 01 50 A0 E3 08 40 86 E2 01 70 A0 E1 08 50 86 E5 04 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 07 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 30 97 15 00 50 A0 01 00 00 86 05 05 00 A0 E1 04 30 86 15 F0 80 BD E8 }
	condition:
		$pattern
}

rule svcunix_recv_48eed19f1112b2bbbe78d97e80c39fe6 {
	meta:
		aliases = "svcunix_recv"
		size = "100"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { F0 40 2D E9 2C 60 90 E5 01 70 A0 E3 08 40 86 E2 01 50 A0 E1 08 70 86 E5 04 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 30 95 15 04 30 86 15 1C 30 A0 13 07 20 A0 E1 2C 30 85 15 00 20 A0 01 10 30 9F 15 00 00 86 05 02 00 A0 E1 28 30 85 15 24 70 85 15 F0 80 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule rendezvous_request_b2032310e63190f47cb34dc0529e4951 {
	meta:
		aliases = "rendezvous_request"
		size = "156"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { F0 40 2D E9 2C 70 90 E5 84 D0 4D E2 00 40 A0 E1 00 00 94 E5 70 30 A0 E3 0D 10 A0 E1 80 20 8D E2 80 30 8D E5 ?? ?? ?? EB 00 60 50 E2 04 00 00 AA ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 13 00 00 1A F2 FF FF EA 70 50 8D E2 00 10 A0 E3 10 20 A0 E3 05 00 A0 E1 ?? ?? ?? EB 01 30 A0 E3 70 30 CD E5 00 30 A0 E3 71 30 CD E5 06 00 A0 E1 06 00 97 E8 58 FE FF EB 05 10 A0 E1 00 40 A0 E1 10 20 A0 E3 10 00 80 E2 ?? ?? ?? EB 80 30 9D E5 0C 30 84 E5 00 00 A0 E3 84 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule fwide_ae25ab0ed1c0923ea659207af407709f {
	meta:
		aliases = "fwide"
		size = "200"
		objfiles = "fwide@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 70 90 E5 38 50 80 E2 10 D0 4D E2 00 00 57 E3 00 40 A0 E1 01 60 A0 E1 05 20 A0 E1 0D 00 A0 E1 8C 10 9F E5 06 00 00 1A 88 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 7C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 56 E3 0D 00 A0 E1 01 10 A0 E3 0B 00 00 0A 00 20 D4 E5 01 30 D4 E5 03 24 82 E1 22 0D 12 E3 06 00 00 1A 00 00 56 E3 80 30 A0 D3 02 3B A0 C3 03 30 82 E1 00 30 C4 E5 43 34 A0 E1 01 30 C4 E5 01 20 D4 E5 00 30 D4 E5 00 00 57 E3 02 44 83 E1 24 30 9F 05 0F E0 A0 01 03 F0 A0 01 80 30 04 E2 02 0B 04 E2 00 00 63 E0 10 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fsetpos_e8a10ad41ffe886c8a8f06b7ceef728d {
	meta:
		aliases = "fsetpos"
		size = "168"
		objfiles = "fsetpos@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 70 90 E5 38 60 80 E2 10 D0 4D E2 00 00 57 E3 00 50 A0 E1 01 40 A0 E1 06 20 A0 E1 0D 00 A0 E1 6C 10 9F E5 06 00 00 1A 68 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 06 00 A0 E1 5C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 10 94 E5 00 20 A0 E3 05 00 A0 E1 ?? ?? ?? EB 00 60 50 E2 01 10 A0 E3 0D 00 A0 E1 04 00 00 1A 04 10 94 E9 0C 30 94 E5 2C 20 85 E5 02 30 C5 E5 30 C0 85 E5 00 00 57 E3 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 06 00 A0 E1 10 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fsetpos64_b405c5b0efb7864e328d9e7b62d2d524 {
	meta:
		aliases = "fsetpos64"
		size = "172"
		objfiles = "fsetpos64@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 70 90 E5 38 60 80 E2 10 D0 4D E2 00 00 57 E3 00 50 A0 E1 01 40 A0 E1 06 20 A0 E1 0D 00 A0 E1 70 10 9F E5 06 00 00 1A 6C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 06 00 A0 E1 60 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 06 00 94 E8 00 30 A0 E3 05 00 A0 E1 ?? ?? ?? EB 00 60 50 E2 01 10 A0 E3 0D 00 A0 E1 05 00 00 1A 08 20 84 E2 04 10 92 E8 10 30 94 E5 2C 20 85 E5 02 30 C5 E5 30 C0 85 E5 00 00 57 E3 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 06 00 A0 E1 10 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule ungetc_429537dda697d0ac6c8100e29a069e6e {
	meta:
		aliases = "__GI_ungetc, ungetc"
		size = "368"
		objfiles = "ungetc@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 70 91 E5 00 00 57 E3 10 D0 4D E2 01 50 A0 E1 00 60 A0 E1 0A 00 00 1A 38 40 81 E2 0D 00 A0 E1 34 31 9F E5 34 11 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 24 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 10 10 95 E5 18 30 95 E5 01 00 76 E3 03 00 51 11 0E 00 00 2A 08 30 95 E5 03 00 51 E1 0B 00 00 9A 01 20 51 E5 FF 30 06 E2 03 00 52 E1 07 00 00 1A 00 30 95 E5 04 30 C3 E3 01 10 41 E2 43 24 A0 E1 01 20 C5 E5 10 10 85 E5 00 30 C5 E5 28 00 00 EA 00 30 D5 E5 83 30 03 E2 80 00 53 E3 04 00 00 8A 05 00 A0 E1 80 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 1E 00 00 1A 00 20 D5 E5 01 30 D5 E5 03 34 82 E1 }
	condition:
		$pattern
}

rule putspent_61ed188bf257aa8432ab23ba7a8be3b4 {
	meta:
		aliases = "putspent"
		size = "304"
		objfiles = "putspent@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 70 91 E5 00 00 57 E3 10 D0 4D E2 01 50 A0 E1 00 60 A0 E1 0A 00 00 1A 38 40 81 E2 0D 00 A0 E1 E0 30 9F E5 E0 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 D0 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 20 96 E5 00 00 52 E3 C0 30 9F E5 05 00 A0 E1 02 30 A0 11 B8 10 9F E5 00 20 96 E5 ?? ?? ?? EB 00 00 50 E3 00 40 A0 A3 09 00 00 AA 1A 00 00 EA A0 30 9F E5 04 30 D3 E7 03 20 96 E7 01 00 72 E3 0C 10 A0 01 ?? ?? ?? EB 00 00 50 E3 01 40 84 E2 11 00 00 BA 80 10 9F E5 05 00 54 E3 03 C0 81 E2 05 00 A0 E1 F1 FF FF 9A 20 20 96 E5 01 00 72 E3 03 00 00 0A 64 10 9F E5 ?? ?? ?? EB 00 00 50 E3 }
	condition:
		$pattern
}

rule ungetwc_0a45cbeea0adbc909d123491b6c8e675 {
	meta:
		aliases = "__GI_ungetwc, ungetwc"
		size = "296"
		objfiles = "ungetwc@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 70 91 E5 00 00 57 E3 10 D0 4D E2 01 50 A0 E1 00 60 A0 E1 0A 00 00 1A 38 40 81 E2 0D 00 A0 E1 E8 30 9F E5 E8 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 D8 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 D5 E5 01 10 D5 E5 C8 20 9F E5 01 34 83 E1 02 20 03 E0 02 0B 52 E3 04 00 00 8A 05 00 A0 E1 02 1B A0 E3 ?? ?? ?? EB 00 00 50 E3 1C 00 00 1A 00 20 D5 E5 01 30 D5 E5 03 34 82 E1 02 00 13 E3 04 00 00 0A 01 00 13 E3 15 00 00 1A 28 30 95 E5 00 00 53 E3 12 00 00 1A 01 00 76 E3 10 00 00 0A 00 30 95 E5 01 30 83 E2 00 30 C5 E5 00 20 D5 E5 43 34 A0 E1 01 20 02 E2 01 30 C5 E5 02 21 85 E0 }
	condition:
		$pattern
}

rule __GI_fputws_b5694f6fb4c32582fbb0d7738cd83f57 {
	meta:
		aliases = "fputs, fputws, putwc, __GI_fputs, fputwc, __GI_fputws"
		size = "140"
		objfiles = "fputwc@libc.a, fputws@libc.a, fputs@libc.a"
	strings:
		$pattern = { F0 40 2D E9 34 70 91 E5 38 50 81 E2 10 D0 4D E2 00 00 57 E3 01 40 A0 E1 00 60 A0 E1 05 20 A0 E1 54 10 9F E5 0D 00 A0 E1 06 00 00 1A 4C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 40 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 10 A0 E1 06 00 A0 E1 ?? ?? ?? EB 00 00 57 E3 00 40 A0 E1 01 10 A0 E3 0D 00 A0 E1 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 04 00 A0 E1 10 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pmap_unset_5da2d1f60b73dd496b1525becfad2764 {
	meta:
		aliases = "__GI_pmap_unset, pmap_unset"
		size = "236"
		objfiles = "pmap_clnt@libc.a"
	strings:
		$pattern = { F0 40 2D E9 38 D0 4D E2 20 40 8D E2 00 30 E0 E3 00 70 A0 E1 04 00 A0 E1 34 30 8D E5 01 60 A0 E1 9C FF FF EB 00 00 50 E3 A8 30 9F E5 19 5E A0 E3 A4 10 9F E5 02 20 A0 E3 04 00 A0 E1 22 00 00 0A 04 E0 93 E5 34 C0 8D E2 00 30 93 E5 04 C0 8D E5 0C 50 8D E5 08 50 8D E5 00 E0 8D E5 ?? ?? ?? EB 00 50 50 E2 00 C0 A0 E3 02 10 A0 E3 6C 20 9F E5 10 30 8D E2 14 00 00 0A 10 70 8D E5 14 60 8D E5 1C C0 8D E5 18 C0 8D E5 54 C0 9F E5 04 40 95 E5 00 C0 8D E5 30 C0 8D E2 04 C0 8D E5 44 C0 9F E5 C0 00 9C E8 08 60 8D E5 0C 70 8D E5 0F E0 A0 E1 00 F0 94 E5 05 00 A0 E1 04 30 95 E5 0F E0 A0 E1 10 F0 93 E5 30 00 9D E5 }
	condition:
		$pattern
}

rule _dl_map_cache_20a6b3d684be1235d6d0f20f1df17ab0 {
	meta:
		aliases = "_dl_map_cache"
		size = "628"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { F0 40 2D E9 44 E2 9F E5 00 00 9E E5 01 00 70 E3 44 D0 4D E2 8B 00 00 0A 00 00 50 E3 88 00 00 1A 2C 62 9F E5 04 10 8D E2 06 00 A0 E1 6A 00 90 EF 01 0A 70 E3 00 50 A0 E1 00 20 60 82 09 00 00 8A 00 00 50 E3 0C 00 00 1A 00 20 A0 E1 00 10 A0 E1 06 00 A0 E1 05 00 90 EF 01 0A 70 E3 00 C0 A0 E1 03 00 00 9A 00 20 60 E2 E8 31 9F E5 00 20 83 E5 01 00 00 EA 00 00 50 E3 04 00 00 AA 00 20 E0 E3 C8 31 9F E5 02 00 A0 E1 00 20 83 E5 6D 00 00 EA 18 10 9D E5 C0 71 9F E5 01 30 A0 E3 00 40 A0 E1 00 10 87 E5 03 20 A0 E1 05 00 A0 E1 C0 00 90 EF 01 0A 70 E3 9C 31 9F 85 00 20 60 82 00 00 E0 83 00 00 8E E5 00 20 83 85 }
	condition:
		$pattern
}

rule __pthread_reset_main_thread_22f411d0c8fb56a71553a25b373ad3b2 {
	meta:
		aliases = "__pthread_reset_main_thread"
		size = "160"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 45 FF FF EB 74 50 9F E5 00 30 95 E5 01 00 73 E3 6C 60 9F E5 6C 70 9F E5 00 40 A0 E1 0C 00 00 0A 00 00 96 E5 ?? ?? ?? EB 5C 20 9F E5 00 30 A0 E3 00 30 82 E5 00 00 95 E5 00 30 86 E5 ?? ?? ?? EB 00 00 97 E5 ?? ?? ?? EB 00 30 E0 E3 00 30 85 E5 00 30 87 E5 ?? ?? ?? EB 30 30 9F E5 4C 30 84 E5 2C 30 9F E5 00 40 83 E5 28 30 9F E5 14 00 84 E5 44 30 84 E5 00 40 84 E5 04 40 84 E5 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule initshells_99c40408c57666afafb26482207093d4 {
	meta:
		aliases = "initshells"
		size = "356"
		objfiles = "usershell@libc.a"
	strings:
		$pattern = { F0 40 2D E9 58 D0 4D E2 EF FF FF EB 38 01 9F E5 38 11 9F E5 ?? ?? ?? EB 00 60 50 E2 47 00 00 0A ?? ?? ?? EB 0D 10 A0 E1 ?? ?? ?? EB 01 00 70 E3 3F 00 00 0A 2C 00 9D E5 01 00 80 E2 ?? ?? ?? EB 0C 71 9F E5 00 00 50 E3 00 00 87 E5 38 00 00 0A 2C 00 9D E5 03 10 A0 E3 ?? ?? ?? EB 04 10 A0 E3 ?? ?? ?? EB EC 40 9F E5 00 00 50 E3 00 00 84 E5 2F 00 00 0A 06 00 A0 E1 02 10 A0 E3 ?? ?? ?? EB 00 50 94 E5 00 40 97 E5 2C 70 9D E5 19 00 00 EA 01 40 84 E2 00 30 D4 E5 23 00 53 E3 2F 00 53 13 01 00 00 0A 00 00 53 E3 F8 FF FF 1A 00 00 53 E3 23 00 53 13 00 40 85 15 01 00 00 1A 0D 00 00 EA 01 40 84 E2 90 30 9F E5 }
	condition:
		$pattern
}

rule setlogmask_cc21d027d6634a42e6c00fc67bd46985 {
	meta:
		aliases = "setlogmask"
		size = "128"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { F0 40 2D E9 5C 60 9F E5 10 D0 4D E2 00 50 50 E2 0D 70 A0 E1 50 10 9F E5 50 20 9F E5 0D 00 A0 E1 00 40 96 E5 0C 00 00 0A 44 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 3C 30 9F E5 30 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 0D 00 A0 E1 01 10 A0 E3 00 50 86 E5 24 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 10 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
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

rule pthread_key_create_63699dae8ef48f8855f963846dfad817 {
	meta:
		aliases = "pthread_key_create"
		size = "148"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 78 30 9F E5 00 70 A0 E1 74 00 9F E5 01 60 A0 E1 0F E0 A0 E1 03 F0 A0 E1 00 40 A0 E3 0E 00 00 EA 84 51 92 E7 00 00 55 E3 0A 00 00 1A 84 31 82 E0 04 60 83 E5 01 30 A0 E3 84 31 82 E7 40 00 9F E5 40 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 00 40 87 E5 F0 80 BD E8 01 40 84 E2 01 0B 54 E3 24 20 9F E5 ED FF FF BA 18 30 9F E5 10 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 0B 00 A0 E3 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_localtime_r_d365aeeb663f7bab53e9e98b3d2ece11 {
	meta:
		aliases = "localtime_r, __GI_localtime_r"
		size = "164"
		objfiles = "localtime_r@libc.a"
	strings:
		$pattern = { F0 40 2D E9 7C 40 9F E5 10 D0 4D E2 04 20 A0 E1 00 50 A0 E1 01 70 A0 E1 0D 00 A0 E1 68 10 9F E5 68 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 5C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 95 E5 50 00 9F E5 00 00 53 E1 00 00 A0 C3 01 00 A0 D3 ?? ?? ?? EB 07 10 A0 E1 3C 20 9F E5 05 00 A0 E1 ?? ?? ?? EB 0D 00 A0 E1 01 10 A0 E3 2C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 0D 60 A0 E1 07 00 A0 E1 10 D0 8D E2 F0 80 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF 4E 98 45 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule universal_edfe440a3b8af7c2b93c64a89c206803 {
	meta:
		aliases = "universal"
		size = "408"
		objfiles = "svc_simple@libc.a"
	strings:
		$pattern = { F0 40 2D E9 89 DD 4D E2 08 60 90 E5 24 D0 4D E2 00 30 A0 E3 02 2A 8D E2 00 00 56 E3 60 32 82 E5 01 50 A0 E1 0A 00 00 1A 01 00 A0 E1 06 20 A0 E1 48 11 9F E5 ?? ?? ?? EB 00 00 50 E3 4C 00 00 1A 3C 11 9F E5 04 20 A0 E3 02 00 80 E2 ?? ?? ?? EB 2B 00 00 EA 00 70 90 E5 ?? ?? ?? EB C0 40 90 E5 31 00 00 EA 04 30 94 E5 07 00 53 E1 2D 00 00 1A 08 30 94 E5 06 00 53 E1 2A 00 00 1A 00 10 A0 E3 00 21 9F E5 0D 00 A0 E1 ?? ?? ?? EB 08 30 95 E5 05 00 A0 E1 0C 10 94 E5 0D 20 A0 E1 0F E0 A0 E1 08 F0 93 E5 24 60 8D E2 00 00 50 E3 24 60 46 E2 2D 00 00 0A 0D 00 A0 E1 0F E0 A0 E1 00 F0 94 E5 00 00 50 E3 03 00 00 1A }
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

rule __pthread_destroy_specifics_08b90c3b06190e129c27aad197fda00a {
	meta:
		aliases = "__pthread_destroy_specifics"
		size = "244"
		objfiles = "specific@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 B7 FF FF EB 00 70 A0 E3 00 60 A0 E1 01 C0 A0 E3 1C 00 00 EA 04 31 86 E0 EC 30 93 E5 00 00 53 E3 00 50 A0 13 0D 00 00 1A 12 00 00 EA EC 10 91 E5 04 20 93 E5 05 31 91 E7 00 00 52 E3 00 00 53 13 03 00 A0 E1 04 00 00 0A 00 30 A0 E3 05 31 81 E7 0F E0 A0 E1 02 F0 A0 E1 01 C0 A0 E3 01 50 85 E2 84 30 9F E5 84 22 85 E0 1F 00 55 E3 04 11 86 E0 82 31 83 E0 EC FF FF DA 01 40 84 E2 1F 00 54 E3 E3 FF FF DA 01 70 87 E2 03 00 57 E3 00 40 A0 C3 01 40 0C D2 00 00 54 E3 00 C0 A0 13 0C 40 A0 11 F5 FF FF 1A 1C 00 96 E5 06 10 A0 E1 ?? ?? ?? EB 05 00 00 EA 0C 30 95 E5 00 00 53 E2 02 00 00 0A ?? ?? ?? EB }
	condition:
		$pattern
}

rule pthread_cleanup_upto_72470a5bd444635f6b1131b1fefbae7a {
	meta:
		aliases = "pthread_cleanup_upto"
		size = "232"
		objfiles = "ptlongjmp@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 C4 30 9F E5 00 30 93 E5 03 00 5D E1 0D 60 A0 E1 00 70 A0 E1 B4 50 9F 25 15 00 00 2A B0 30 9F E5 00 30 93 E5 03 00 5D E1 04 00 00 3A A4 30 9F E5 00 30 93 E5 03 00 5D E1 9C 50 9F 35 0C 00 00 3A 98 30 9F E5 00 30 93 E5 00 00 53 E3 04 00 00 0A ?? ?? ?? EB 00 50 A0 E1 05 00 00 EA 00 40 A0 E3 10 00 00 EA A6 3A E0 E1 83 3A E0 E1 77 5F 43 E2 03 50 45 E2 3C 40 95 E5 05 00 00 EA 06 00 54 E1 F5 FF FF 9A 04 00 94 E5 0F E0 A0 E1 00 F0 94 E5 0C 40 94 E5 00 00 54 E3 02 00 00 0A 20 30 97 E5 03 00 54 E1 F4 FF FF 3A 54 20 95 E5 00 00 52 E3 3C 40 85 E5 F0 80 BD 08 20 30 97 E5 03 00 52 E1 00 30 A0 33 }
	condition:
		$pattern
}

rule __GI_vdprintf_6b3ea58f1af4086e8073a7e8556d1a01 {
	meta:
		aliases = "vdprintf, __GI_vdprintf"
		size = "152"
		objfiles = "vdprintf@libc.a"
	strings:
		$pattern = { F0 40 2D E9 D0 30 A0 E3 90 D0 4D E2 00 30 CD E5 01 30 A0 E3 00 40 A0 E3 04 00 8D E5 01 60 A0 E1 02 70 A0 E1 38 00 8D E2 50 20 8D E2 34 30 8D E5 90 30 8D E2 14 20 8D E5 0C 30 8D E5 08 20 8D E5 18 20 8D E5 1C 20 8D E5 10 20 8D E5 01 40 CD E5 02 40 CD E5 2C 40 8D E5 ?? ?? ?? EB 06 10 A0 E1 07 20 A0 E1 0D 00 A0 E1 20 40 8D E5 ?? ?? ?? EB 00 40 50 E2 0D 50 A0 E1 0D 00 A0 E1 02 00 00 DA ?? ?? ?? EB 00 00 50 E3 00 40 E0 13 04 00 A0 E1 90 D0 8D E2 F0 80 BD E8 }
	condition:
		$pattern
}

rule pthread_detach_70a843e7e52a7bb36d92a9ec230e5e87 {
	meta:
		aliases = "pthread_detach"
		size = "256"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { F0 40 2D E9 EC 20 9F E5 00 3B A0 E1 23 3B A0 E1 03 52 82 E0 94 D0 4D E2 00 60 A0 E1 00 10 A0 E3 05 00 A0 E1 ?? ?? ?? EB 08 20 95 E5 00 00 52 E3 02 00 00 0A 10 30 92 E5 06 00 53 E1 03 00 00 0A 05 00 A0 E1 ?? ?? ?? EB 03 00 A0 E3 27 00 00 EA 2D 40 D2 E5 00 00 54 E3 03 00 00 0A 05 00 A0 E1 ?? ?? ?? EB 16 00 A0 E3 20 00 00 EA 38 30 92 E5 00 00 53 E3 03 00 00 0A 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 19 00 00 EA 2C 40 D2 E5 01 70 A0 E3 2D 70 C2 E5 05 00 A0 E1 ?? ?? ?? EB 00 00 54 E3 11 00 00 0A 50 30 9F E5 00 30 93 E5 00 00 53 E3 0D 00 00 BA DD FE FF EB 81 00 8D E8 08 60 8D E5 34 30 9F E5 0D 10 A0 E1 }
	condition:
		$pattern
}

rule vwarn_work_134d936f02e46e0ecf877428d272c6bc {
	meta:
		aliases = "vwarn_work"
		size = "248"
		objfiles = "err@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 00 52 E3 50 D0 4D E2 C0 50 9F E5 00 70 A0 E1 01 80 A0 E1 05 00 00 0A ?? ?? ?? EB 0D 10 A0 E1 00 00 90 E5 40 20 A0 E3 ?? ?? ?? EB A0 50 9F E5 A0 40 9F E5 00 30 94 E5 34 60 93 E5 00 00 56 E3 38 20 83 E2 40 00 8D E2 8C 10 9F E5 07 00 00 1A 88 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 94 E5 7C 30 9F E5 38 00 80 E2 0F E0 A0 E1 03 F0 A0 E1 70 30 9F E5 70 10 9F E5 00 20 93 E5 00 00 94 E5 ?? ?? ?? EB 00 00 57 E3 07 10 A0 E1 08 20 A0 E1 02 00 00 0A 00 00 94 E5 ?? ?? ?? EB 02 50 45 E2 05 10 A0 E1 00 00 94 E5 0D 20 A0 E1 ?? ?? ?? EB 00 00 56 E3 40 00 8D E2 01 10 A0 E3 2C 30 9F 05 0F E0 A0 01 }
	condition:
		$pattern
}

rule _time_tzset_9224c54e99bcadf484a8a8dd8154bc43 {
	meta:
		aliases = "_time_tzset"
		size = "1224"
		objfiles = "tzset@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 30 A0 E3 88 D0 4D E2 5C 14 9F E5 5C 24 9F E5 84 30 8D E5 00 80 A0 E1 54 34 9F E5 74 00 8D E2 0F E0 A0 E1 03 F0 A0 E1 48 34 9F E5 3C 04 9F E5 0F E0 A0 E1 03 F0 A0 E1 3C 04 9F E5 ?? ?? ?? EB 00 40 50 E2 1D 00 00 1A 30 04 9F E5 04 10 A0 E1 ?? ?? ?? EB 00 60 50 E2 16 00 00 BA 44 40 A0 E3 0D 50 A0 E1 05 10 A0 E1 04 20 A0 E1 06 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 0B 00 00 BA 02 00 00 0A 00 40 54 E0 00 50 85 E0 F5 FF FF 1A 0D 00 55 E1 05 00 00 9A 01 30 55 E5 0A 00 53 E3 00 30 A0 03 0D 40 A0 01 01 30 45 05 00 00 00 0A 00 40 A0 E3 06 00 A0 E1 ?? ?? ?? EB 00 00 54 E3 02 00 00 0A 00 30 D4 E5 }
	condition:
		$pattern
}

rule __GI_pthread_getschedparam_061b01c82b206d8b311eed5f5d1db743 {
	meta:
		aliases = "pthread_getschedparam, __GI_pthread_getschedparam"
		size = "172"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { F0 41 2D E9 00 3B A0 E1 00 40 A0 E1 94 00 9F E5 23 3B A0 E1 03 52 80 E0 05 00 A0 E1 01 80 A0 E1 00 10 A0 E3 02 70 A0 E1 ?? ?? ?? EB 08 20 95 E5 00 00 52 E3 05 00 A0 E1 04 00 00 0A 10 30 92 E5 04 60 53 E0 01 60 A0 13 00 00 56 E3 02 00 00 0A ?? ?? ?? EB 03 00 A0 E3 F0 81 BD E8 14 40 92 E5 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 ?? ?? ?? EB 00 50 A0 E1 01 00 75 E3 07 10 A0 E1 04 00 A0 E1 02 00 00 0A ?? ?? ?? EB 01 00 70 E3 02 00 00 1A ?? ?? ?? EB 00 00 90 E5 F0 81 BD E8 06 00 A0 E1 00 50 88 E5 F0 81 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_setschedparam_dd6d7785fb2219336c1750447250592c {
	meta:
		aliases = "__GI_pthread_setschedparam, pthread_setschedparam"
		size = "196"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { F0 41 2D E9 00 3B A0 E1 00 70 A0 E1 A8 00 9F E5 23 3B A0 E1 03 52 80 E0 01 60 A0 E1 05 00 A0 E1 00 10 A0 E3 02 80 A0 E1 ?? ?? ?? EB 08 40 95 E5 00 00 54 E3 02 00 00 0A 10 30 94 E5 07 00 53 E1 03 00 00 0A 05 00 A0 E1 ?? ?? ?? EB 03 00 A0 E3 F0 81 BD E8 14 00 94 E5 06 10 A0 E1 08 20 A0 E1 ?? ?? ?? EB 01 00 70 E3 04 00 00 1A 05 00 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 00 00 90 E5 F0 81 BD E8 00 00 56 E3 00 10 98 15 06 10 A0 01 18 10 84 E5 05 00 A0 E1 ?? ?? ?? EB 20 30 9F E5 00 30 93 E5 00 00 53 E3 00 00 A0 B3 F0 81 BD B8 18 00 94 E5 ?? ?? ?? EB 00 00 A0 E3 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule realloc_f593ae6b3af4a2dcff6a6ab4327adead {
	meta:
		aliases = "realloc"
		size = "280"
		objfiles = "realloc@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 40 51 E2 00 70 A0 E1 01 00 00 1A ?? ?? ?? EB 01 00 00 EA 00 00 50 E3 02 00 00 1A 04 00 A0 E1 F0 41 BD E8 ?? ?? ?? EA 07 30 84 E2 03 50 C3 E3 0B 00 55 E3 04 60 10 E5 0C 50 A0 93 06 00 55 E1 04 80 40 E2 1C 00 00 9A B4 30 9F E5 05 40 66 E0 B0 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 20 A0 E1 06 10 88 E0 A0 00 9F E5 ?? ?? ?? EB 9C 30 9F E5 00 40 A0 E1 8C 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 54 E3 04 30 86 10 04 30 07 15 1A 00 00 1A 04 00 45 E2 ?? ?? ?? EB 00 40 50 E2 04 00 00 0A 04 20 46 E2 07 10 A0 E1 ?? ?? ?? EB 07 00 A0 E1 ?? ?? ?? EB 04 70 A0 E1 0F 00 00 EA 1C 30 85 E2 06 00 53 E1 }
	condition:
		$pattern
}

rule __GI_xdr_reference_e283d0cb39a52ca2b794e159fdb12ca7 {
	meta:
		aliases = "xdr_reference, __GI_xdr_reference"
		size = "188"
		objfiles = "xdr_reference@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 40 91 E5 00 00 54 E3 01 70 A0 E1 02 60 A0 E1 03 80 A0 E1 00 50 A0 E1 15 00 00 1A 00 30 90 E5 01 00 53 E3 02 00 A0 E1 03 00 00 0A 02 00 53 E3 01 60 A0 E3 0E 00 00 1A 1A 00 00 EA ?? ?? ?? EB 00 00 50 E3 06 20 A0 E1 00 40 A0 E1 00 60 A0 E1 00 10 A0 E3 00 00 87 E5 04 00 00 1A 4C 30 9F E5 4C 00 9F E5 00 10 93 E5 ?? ?? ?? EB 0D 00 00 EA ?? ?? ?? EB 04 10 A0 E1 00 20 E0 E3 05 00 A0 E1 0F E0 A0 E1 08 F0 A0 E1 00 30 95 E5 02 00 53 E3 00 60 A0 E1 04 00 A0 E1 02 00 00 1A ?? ?? ?? EB 00 30 A0 E3 00 30 87 E5 06 00 A0 E1 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __encode_dotted_975d2c66c48e1204de4f772913a76648 {
	meta:
		aliases = "__encode_dotted"
		size = "168"
		objfiles = "encoded@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 40 A0 E1 01 60 A0 E1 02 80 A0 E1 00 70 A0 E3 16 00 00 EA ?? ?? ?? EB 00 50 50 E2 05 C0 64 E0 04 00 A0 E1 01 00 00 1A ?? ?? ?? EB 00 C0 A0 E1 01 E0 87 E2 08 30 67 E0 00 00 5C E3 04 10 A0 E1 0E 00 86 E0 0C 20 A0 E1 01 30 43 E2 01 40 85 E2 11 00 00 0A 03 00 5C E1 0F 00 00 2A 07 C0 C6 E7 0C 70 8E E0 ?? ?? ?? EB 00 00 55 E3 05 00 00 0A 00 00 54 E2 2E 10 A0 E3 02 00 00 0A 00 30 D4 E5 00 00 53 E3 E2 FF FF 1A 00 00 58 E3 00 30 A0 C3 01 00 87 C2 07 30 C6 C7 F0 81 BD C8 00 00 E0 E3 F0 81 BD E8 }
	condition:
		$pattern
}

rule __regexec_f04a988119f9554514cd4b50992b9460 {
	meta:
		aliases = "regexec, __regexec"
		size = "320"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 40 A0 E1 34 D0 4D E2 01 00 A0 E1 02 50 A0 E1 01 70 A0 E1 03 80 A0 E1 ?? ?? ?? EB 04 E0 A0 E1 00 60 A0 E1 0F 00 BE E8 08 C0 8D E2 0F 00 AC E8 0F 00 9E E8 0F 00 8C E8 4C 20 9D E5 24 30 DD E5 01 10 02 E2 20 30 C3 E3 81 32 83 E1 24 30 CD E5 24 30 DD E5 82 22 A0 E1 40 30 C3 E3 40 20 02 E2 03 20 82 E1 24 20 CD E5 1C 30 D4 E5 24 20 DD E5 23 32 A0 E1 01 30 23 E2 00 00 55 E3 00 40 A0 03 01 40 03 12 02 20 C2 E3 04 20 82 E3 00 00 54 E3 24 20 CD E5 04 C0 A0 01 09 00 00 0A 85 01 A0 E1 28 50 8D E5 ?? ?? ?? EB 00 00 50 E3 01 00 A0 03 1F 00 00 0A 05 31 80 E0 30 30 8D E5 2C 00 8D E5 28 C0 8D E2 }
	condition:
		$pattern
}

rule svc_getreqset_bca9440945371706911c556241cf0f92 {
	meta:
		aliases = "__GI_svc_getreqset, svc_getreqset"
		size = "96"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 40 A0 E1 ?? ?? ?? EB 04 60 A0 E1 00 80 A0 E1 00 70 A0 E3 0D 00 00 EA 00 40 96 E5 03 00 00 EA ?? ?? ?? EB 01 20 45 E2 01 30 A0 E3 13 42 24 E0 04 00 A0 E1 ?? ?? ?? EB 00 50 50 E2 05 00 87 E0 01 00 40 E2 F5 FF FF 1A 04 60 86 E2 20 70 87 E2 08 00 57 E1 EF FF FF BA F0 81 BD E8 }
	condition:
		$pattern
}

rule readunix_6f826a159cdc955ececc753d51e6ebbd {
	meta:
		aliases = "readunix"
		size = "352"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 50 90 E5 34 D0 4D E2 00 80 A0 E1 01 60 A0 E1 02 70 A0 E1 01 C0 A0 E3 00 30 A0 E3 0C 10 A0 E1 2C 21 9F E5 28 00 8D E2 2D 30 CD E5 28 50 8D E5 2C C0 CD E5 ?? ?? ?? EB 01 00 70 E3 02 00 00 0A 00 00 50 E3 3C 00 00 0A 04 00 00 EA ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 09 00 00 0A 36 00 00 EA 2E 30 DD E5 2F 20 DD E5 02 34 83 E1 03 38 A0 E1 43 38 A0 E1 18 00 13 E3 2F 00 00 1A 20 00 13 E3 2D 00 00 1A 2E 30 DD E5 01 00 13 E3 E0 FF FF 0A 20 C0 8D E2 0C C0 8D E5 B8 C0 9F E5 01 40 A0 E3 34 30 8D E2 14 C0 8D E5 1C C0 A0 E3 00 E0 A0 E3 04 40 23 E5 18 C0 8D E5 04 10 A0 E1 04 C0 A0 E3 05 00 A0 E1 }
	condition:
		$pattern
}

rule ___path_search_5e734b69385e4a89d0928573f5992e82 {
	meta:
		aliases = "___path_search"
		size = "280"
		objfiles = "tempname@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 60 53 E2 08 D0 4D E2 00 80 A0 E1 01 70 A0 E1 02 40 A0 E1 08 00 00 0A 00 30 D6 E5 00 00 53 E3 05 00 00 0A 06 00 A0 E1 ?? ?? ?? EB 05 00 50 E3 00 50 A0 E1 05 50 A0 83 01 00 00 EA C4 60 9F E5 04 50 A0 E3 00 00 54 E3 11 00 00 1A B8 00 9F E5 2D FF FF EB 00 00 50 E3 0C 00 00 1A A8 00 9F E5 00 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 03 00 00 0A 94 00 9F E5 24 FF FF EB 00 00 50 E3 03 00 00 1A ?? ?? ?? EB 00 20 E0 E3 02 30 A0 E3 12 00 00 EA 74 40 9F E5 04 00 A0 E1 ?? ?? ?? EB 00 20 A0 E1 00 00 00 EA 01 20 42 E2 01 00 52 E3 02 30 84 E0 02 00 00 9A 01 30 53 E5 2F 00 53 E3 F8 FF FF 0A 08 30 82 E2 }
	condition:
		$pattern
}

rule svc_getreq_poll_500c99eb5c0d7cd7b56f77b74a2e1aa6 {
	meta:
		aliases = "__GI_svc_getreq_poll, svc_getreq_poll"
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

rule __parsegrent_a6ccde39d6ec33e7e16c41e05a973c04 {
	meta:
		aliases = "__parsegrent"
		size = "336"
		objfiles = "__parsegrent@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 80 90 E5 04 D0 4D E2 00 70 A0 E1 01 40 A0 E1 00 50 A0 E3 28 31 9F E5 01 00 55 E3 05 60 D3 E7 04 00 A0 E1 3A 10 A0 E3 01 50 85 E2 07 00 00 CA 06 40 87 E7 ?? ?? ?? EB 00 00 50 E3 3D 00 00 0A 00 30 A0 E3 01 30 C0 E4 00 40 A0 E1 F0 FF FF EA 0D 10 A0 E1 04 00 A0 E1 0A 20 A0 E3 ?? ?? ?? EB 00 10 9D E5 04 00 51 E1 06 00 87 E7 31 00 00 0A 00 30 D1 E5 3A 00 53 E3 2E 00 00 1A 01 30 D1 E5 00 00 53 E3 01 00 A0 03 15 00 00 0A 2C 30 A0 E3 00 30 C1 E5 01 00 A0 E3 00 30 D1 E5 2C 00 53 E3 0C 00 00 1A 00 30 A0 E3 00 30 C1 E5 01 20 F1 E5 03 00 52 E1 01 00 80 E2 1E 00 00 0A 2C 00 52 E3 1C 00 00 0A }
	condition:
		$pattern
}

rule makefd_xprt_6e1e5f927afe962a4e116611b9dd16d5 {
	meta:
		aliases = "makefd_xprt"
		size = "228"
		objfiles = "svc_tcp@libc.a, svc_unix@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 80 A0 E1 08 D0 4D E2 4D 0F A0 E3 01 40 A0 E1 02 50 A0 E1 ?? ?? ?? EB 00 60 A0 E1 1B 0E A0 E3 ?? ?? ?? EB 00 70 A0 E1 00 00 57 E3 00 00 56 13 04 10 A0 E1 90 00 9F E5 05 20 A0 E1 06 30 A0 E1 00 40 A0 13 01 40 A0 03 08 00 00 1A 7C 30 9F E5 00 10 93 E5 ?? ?? ?? EB 06 00 A0 E1 ?? ?? ?? EB 07 00 A0 E1 ?? ?? ?? EB 00 60 A0 E3 13 00 00 EA 5C C0 9F E5 02 00 A0 E3 00 00 87 E5 00 C0 8D E5 50 C0 9F E5 08 00 87 E2 04 C0 8D E5 ?? ?? ?? EB 20 30 87 E2 24 30 86 E5 3C 30 9F E5 05 40 C6 E5 08 30 86 E5 00 80 86 E5 30 40 86 E5 2C 70 86 E5 0C 40 86 E5 04 40 C6 E5 06 00 A0 E1 ?? ?? ?? EB 06 00 A0 E1 }
	condition:
		$pattern
}

rule _dl_fixup_606e2c3488a9ed66e556d90d81f2de55 {
	meta:
		aliases = "_dl_fixup"
		size = "340"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { F0 41 2D E9 00 80 A0 E1 10 00 90 E5 00 00 50 E3 01 70 A0 E1 02 00 00 0A ?? ?? ?? EB 00 50 50 E2 49 00 00 1A 00 40 98 E5 5C 30 94 E5 22 10 D4 E5 23 20 D4 E5 00 00 53 E3 01 50 A0 13 02 34 81 E1 41 00 00 1A 84 10 94 E5 00 00 51 E3 88 50 94 E5 1B 00 00 0A 01 00 13 E3 19 00 00 1A C8 C0 94 E5 00 00 5C E3 0B 00 00 0A 00 E0 94 E5 8C 61 A0 E1 08 00 41 E2 08 00 80 E2 00 20 90 E5 02 30 9E E7 01 C0 5C E2 0E 30 83 E0 02 30 8E E7 F8 FF FF 1A 06 10 81 E0 05 50 66 E0 05 20 A0 E1 08 00 A0 E1 ?? ?? ?? EB 20 30 94 E5 23 38 A0 E1 01 30 83 E3 43 24 A0 E1 00 50 A0 E1 23 20 C4 E5 22 30 C4 E5 00 00 00 EA 00 50 A0 E3 }
	condition:
		$pattern
}

rule ether_ntohost_68a1cfc77aee9076ed84643365aeb864 {
	meta:
		aliases = "ether_ntohost"
		size = "176"
		objfiles = "ethers@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 80 A0 E1 42 DF 4D E2 01 70 A0 E1 90 00 9F E5 90 10 9F E5 ?? ?? ?? EB 00 60 50 E2 00 40 E0 03 1C 00 00 0A 0C 00 00 EA 08 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 15 00 00 EA B9 FF FF EB 05 10 A0 E1 00 50 50 E2 06 20 A0 E3 07 00 A0 E1 02 00 00 0A ?? ?? ?? EB 00 40 50 E2 F2 FF FF 0A 04 40 8D E2 02 40 44 E2 01 1C A0 E3 06 20 A0 E1 04 00 A0 E1 ?? ?? ?? EB 01 5C 8D E2 02 50 85 E2 00 00 50 E3 05 10 A0 E1 04 00 A0 E1 EA FF FF 1A 00 40 E0 E3 06 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 42 DF 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule _stdio_fopen_8b391104ee2d2b9dc2fff5918f83f589 {
	meta:
		aliases = "_stdio_fopen"
		size = "760"
		objfiles = "_fopen@libc.a"
	strings:
		$pattern = { F0 41 2D E9 00 C0 D1 E5 72 00 5C E3 20 D0 4D E2 00 60 A0 E1 02 80 A0 E1 03 50 A0 E1 10 00 00 0A 77 00 5C E3 9C 42 9F 05 0E 00 00 0A 61 00 5C E3 94 42 9F 05 0B 00 00 0A ?? ?? ?? EB 16 30 A0 E3 00 00 58 E3 00 30 80 E5 9A 00 00 0A 01 30 D8 E5 20 00 13 E3 97 00 00 0A 08 00 A0 E1 ?? ?? ?? EB 94 00 00 EA 00 40 A0 E3 01 30 D1 E5 62 00 53 E3 01 30 A0 11 01 30 81 02 01 30 D3 E5 2B 00 53 E3 01 30 84 03 01 40 83 02 00 00 58 E3 0A 00 00 1A 50 00 A0 E3 ?? ?? ?? EB 00 80 50 E2 86 00 00 0A 00 20 A0 E3 20 30 A0 E3 01 30 C8 E5 08 20 88 E5 00 20 C8 E5 38 00 88 E2 ?? ?? ?? EB 00 00 55 E3 13 00 00 BA 04 22 9F E5 }
	condition:
		$pattern
}

rule regcomp_0c9c4cd6d7a99dcc215626af40fd3d83 {
	meta:
		aliases = "__regcomp, regcomp"
		size = "340"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { F0 41 2D E9 01 00 12 E3 00 50 A0 E3 30 31 9F E5 02 60 A0 E1 2C 21 9F E5 00 40 A0 E1 00 50 80 E5 04 50 80 E5 08 50 80 E5 01 0C A0 E3 02 70 A0 01 03 70 A0 11 01 80 A0 E1 ?? ?? ?? EB 02 30 16 E2 10 00 84 E5 16 00 00 0A 01 0C A0 E3 ?? ?? ?? EB 05 00 50 E1 14 00 84 E5 0C 50 85 02 05 20 A0 11 0B 00 00 1A 34 00 00 EA DC 30 9F E5 00 30 93 E5 01 30 D3 E7 01 00 13 E3 D0 30 9F 15 00 30 93 15 14 00 94 E5 01 30 D3 17 FF 30 02 02 02 30 C0 E7 01 20 82 E2 FF 00 52 E3 82 10 A0 E1 F1 FF FF 9A 00 00 00 EA 14 30 84 E5 1C 30 D4 E5 04 00 16 E3 83 3C E0 11 A3 3C E0 11 7F 30 03 02 1C 30 C4 E5 40 20 C7 13 1C 30 D4 E5 }
	condition:
		$pattern
}

rule __gcc_personality_sj0_c91e7c6997a4c3d2a25202aeb9923618 {
	meta:
		aliases = "__gcc_personality_sj0"
		size = "216"
		objfiles = "unwind_c@libgcc.a"
	strings:
		$pattern = { F0 41 2D E9 01 00 50 E3 20 D0 4D E2 3C 80 9D E5 03 00 A0 13 01 00 00 0A 20 D0 8D E2 F0 81 BD E8 02 00 11 E3 01 00 00 1A 08 00 A0 E3 F9 FF FF EA 08 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 F9 FF FF 0A 00 10 A0 E1 0D 20 A0 E1 08 00 A0 E1 BC FF FF EB 00 50 A0 E1 08 00 A0 E1 ?? ?? ?? EB 01 40 40 E2 00 00 54 E3 1C 70 8D C2 18 60 8D C2 01 00 00 CA EC FF FF EA 01 40 44 E2 05 00 A0 E1 07 10 A0 E1 0D FF FF EB 06 10 A0 E1 0B FF FF EB 01 00 54 E3 00 50 A0 E1 F6 FF FF 1A 1C 30 9D E5 01 50 93 E2 E0 FF FF 0A 38 20 9D E5 08 00 A0 E1 00 10 A0 E3 ?? ?? ?? EB 08 00 A0 E1 04 10 A0 E1 00 20 A0 E3 ?? ?? ?? EB 08 00 A0 E1 }
	condition:
		$pattern
}

rule __GI_vsscanf_4f186c8986816f2ff73b35018495efb8 {
	meta:
		aliases = "vsscanf, __GI_vsscanf"
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

rule rwlock_have_already_08c5335a17ef736de83d894cd725748d {
	meta:
		aliases = "rwlock_have_already"
		size = "224"
		objfiles = "rwlock@libpthread.a"
	strings:
		$pattern = { F0 41 2D E9 01 50 A0 E1 18 10 91 E5 01 00 51 E3 00 60 A0 E1 00 40 90 E5 00 00 A0 13 02 80 A0 E1 03 70 A0 E1 00 20 A0 11 23 00 00 1A 00 00 54 E3 01 00 00 1A A4 FF FF EB 00 40 A0 E1 C0 01 94 E5 03 00 00 EA 04 30 90 E5 05 00 53 E1 03 00 00 0A 00 00 90 E5 00 00 50 E3 F9 FF FF 1A 01 00 00 EA 00 00 50 E3 16 00 00 1A C8 31 94 E5 00 00 53 E3 13 00 00 CA C4 01 94 E5 00 00 50 E3 00 30 90 15 C4 31 84 15 0C 00 A0 03 ?? ?? ?? 0B 00 00 50 E3 08 00 00 0A C0 31 94 E5 00 10 A0 E3 00 30 80 E5 01 20 A0 E1 01 30 A0 E3 08 30 80 E5 04 50 80 E5 C0 01 84 E5 04 00 00 EA 01 20 A0 E3 00 10 A0 E1 01 00 00 EA 00 20 A0 E3 }
	condition:
		$pattern
}

rule _fp_out_narrow_b85b893e76e09d0de7d27ad2977f65bf {
	meta:
		aliases = "_fp_out_narrow"
		size = "132"
		objfiles = "_vfprintf_internal@libc.a"
	strings:
		$pattern = { F0 41 2D E9 01 60 A0 E1 80 10 11 E2 00 80 A0 E1 02 40 A0 E1 03 70 A0 E1 01 60 A0 01 0F 00 00 0A 03 00 A0 E1 ?? ?? ?? EB 04 40 60 E0 00 00 54 E3 00 50 A0 E1 00 40 A0 D1 00 60 A0 D3 07 00 00 DA 7F 10 06 E2 08 00 A0 E1 04 20 A0 E1 D8 FF FF EB 04 00 50 E1 00 60 A0 E1 07 00 00 1A 05 40 A0 E1 00 00 54 E3 00 00 A0 D3 07 00 A0 C1 04 10 A0 C1 08 20 A0 C1 ?? ?? ?? CB 00 60 86 E0 06 00 A0 E1 F0 81 BD E8 }
	condition:
		$pattern
}

rule _fp_out_wide_6b27b885f4d42ddd6032368ffbd47d30 {
	meta:
		aliases = "_fp_out_wide"
		size = "172"
		objfiles = "_vfwprintf_internal@libc.a"
	strings:
		$pattern = { F0 41 2D E9 01 60 A0 E1 80 10 11 E2 54 D0 4D E2 00 80 A0 E1 02 40 A0 E1 03 70 A0 E1 01 60 A0 01 0F 00 00 0A 03 00 A0 E1 ?? ?? ?? EB 04 40 60 E0 00 00 54 E3 00 50 A0 E1 00 40 A0 D1 00 60 A0 D3 07 00 00 DA 7F 10 06 E2 08 00 A0 E1 04 20 A0 E1 2D FE FF EB 04 00 50 E1 00 60 A0 E1 0F 00 00 1A 05 40 A0 E1 00 00 54 E3 0C 00 00 DA 00 10 A0 E3 54 30 8D E2 01 21 83 E0 01 30 D7 E7 01 10 81 E2 04 00 51 E1 54 30 02 E5 F8 FF FF BA 04 10 A0 E1 08 20 A0 E1 0D 00 A0 E1 ?? ?? ?? EB 00 60 86 E0 06 00 A0 E1 54 D0 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule xdr_bytes_43947a1e4ab9e22e1316e0cf109228d3 {
	meta:
		aliases = "__GI_xdr_bytes, xdr_bytes"
		size = "232"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { F0 41 2D E9 01 80 A0 E1 02 10 A0 E1 02 50 A0 E1 03 70 A0 E1 00 60 A0 E1 00 40 98 E5 ?? ?? ?? EB 00 00 50 E3 29 00 00 0A 00 50 95 E5 07 00 55 E1 02 00 00 9A 00 30 96 E5 02 00 53 E3 23 00 00 1A 00 30 96 E5 01 00 53 E3 03 00 00 0A 12 00 00 3A 02 00 53 E3 1D 00 00 1A 14 00 00 EA 00 00 55 E3 1C 00 00 0A 00 00 54 E3 0B 00 00 1A 05 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 40 A0 E1 00 00 88 E5 05 00 00 1A 54 30 9F E5 54 00 9F E5 00 10 93 E5 ?? ?? ?? EB 04 00 A0 E1 F0 81 BD E8 06 00 A0 E1 04 10 A0 E1 05 20 A0 E1 F0 41 BD E8 ?? ?? ?? EA 00 00 54 E3 07 00 00 0A 04 00 A0 E1 ?? ?? ?? EB 00 30 A0 E3 01 00 A0 E3 }
	condition:
		$pattern
}

rule __decode_question_cf5d147d09b1e1d577b94181315cca37 {
	meta:
		aliases = "__decode_question"
		size = "112"
		objfiles = "decodeq@libc.a"
	strings:
		$pattern = { F0 41 2D E9 01 DC 4D E2 02 70 A0 E1 01 3C A0 E3 0D 20 A0 E1 01 40 A0 E1 00 80 A0 E1 ?? ?? ?? EB 00 60 50 E2 0D 50 A0 E1 0D 00 A0 E1 06 40 84 E0 0B 00 00 BA ?? ?? ?? EB 00 00 87 E5 04 20 88 E0 01 30 D2 E5 04 10 D8 E7 01 34 83 E1 04 30 87 E5 03 30 D2 E5 02 20 D2 E5 02 34 83 E1 08 30 87 E5 04 60 86 E2 06 00 A0 E1 01 DC 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule __GI_vasprintf_661ea30fcbf207beb525197391a10b75 {
	meta:
		aliases = "vasprintf, __GI_vasprintf"
		size = "132"
		objfiles = "vasprintf@libc.a"
	strings:
		$pattern = { F0 41 2D E9 02 50 A0 E1 00 60 A0 E1 01 70 A0 E1 00 00 A0 E3 04 D0 4D E2 00 10 A0 E1 07 20 A0 E1 05 30 A0 E1 00 50 8D E5 ?? ?? ?? EB 00 80 A0 E3 00 40 50 E2 00 80 86 E5 0E 00 00 BA 01 40 84 E2 04 00 A0 E1 ?? ?? ?? EB 08 00 50 E1 04 10 A0 E1 07 20 A0 E1 05 30 A0 E1 00 00 86 E5 05 00 00 0A ?? ?? ?? EB 00 40 50 E2 02 00 00 AA 00 00 96 E5 ?? ?? ?? EB 00 80 86 E5 04 00 A0 E1 04 D0 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule writeunix_2e054f94f0476771733dd205b8d7c239 {
	meta:
		aliases = "writeunix"
		size = "240"
		objfiles = "svc_unix@libc.a"
	strings:
		$pattern = { F0 41 2D E9 02 60 A0 E1 30 D0 4D E2 00 70 A0 E1 01 50 A0 E1 02 40 A0 E1 2D 00 00 EA 00 80 97 E5 ?? ?? ?? EB 1C 00 8D E5 ?? ?? ?? EB 20 00 8D E5 ?? ?? ?? EB 1C 10 8D E2 24 00 8D E5 0C 20 A0 E3 A0 00 9F E5 ?? ?? ?? EB 9C 20 9F E5 02 30 A0 E3 00 10 A0 E3 01 00 A0 E3 18 C0 A0 E3 08 30 82 E5 28 30 8D E2 08 30 8D E5 0C 00 8D E5 10 20 8D E5 14 C0 8D E5 18 10 8D E5 04 00 82 E5 00 C0 82 E5 28 50 8D E5 2C 40 8D E5 00 10 8D E5 04 10 8D E5 0D 10 A0 E1 00 20 A0 E3 08 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 08 00 00 AA ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 F5 FF FF 0A 2C 20 97 E5 00 30 A0 E3 00 60 E0 E3 00 30 82 E5 }
	condition:
		$pattern
}

rule __stdio_WRITE_1cff3addbd891fcb125f224561273398 {
	meta:
		aliases = "__stdio_WRITE"
		size = "188"
		objfiles = "_WRITE@libc.a"
	strings:
		$pattern = { F0 41 2D E9 02 80 A0 E1 00 40 A0 E1 01 70 A0 E1 02 50 A0 E1 00 00 55 E3 05 20 A0 E1 24 00 00 0A 02 21 E0 B3 07 10 A0 E1 04 00 94 E5 ?? ?? ?? EB 00 00 50 E3 05 60 A0 E1 00 70 87 A0 05 50 60 A0 F3 FF FF AA 00 30 94 E5 08 00 84 E2 05 00 90 E8 08 30 83 E3 43 14 A0 E1 00 20 52 E0 01 10 C4 E5 00 30 C4 E5 11 00 00 0A 05 00 52 E1 02 60 A0 91 00 30 D7 E5 00 30 C0 E5 00 30 D0 E5 0A 00 53 E3 01 70 87 E2 02 00 00 1A 01 30 D4 E5 01 00 13 E3 02 00 00 1A 01 60 56 E2 01 00 80 E2 F3 FF FF 1A 08 30 94 E5 10 00 84 E5 00 30 63 E0 05 50 63 E0 08 80 65 E0 08 00 A0 E1 F0 81 BD E8 }
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

rule getgrouplist_3886fced69f42ce37aaf9c0b9891d517 {
	meta:
		aliases = "getgrouplist"
		size = "120"
		objfiles = "getgrouplist@libc.a"
	strings:
		$pattern = { F0 41 2D E9 02 80 A0 E1 03 20 A0 E1 03 40 A0 E1 01 70 A0 E1 00 50 93 E5 ?? ?? ?? EB 00 60 50 E2 04 00 00 1A 00 00 55 E3 00 70 88 15 01 50 A0 E3 0E 00 00 1A 0C 00 00 EA 00 30 94 E5 03 00 55 E1 03 50 A0 A1 00 00 55 E3 08 00 A0 E1 05 21 A0 E1 06 10 A0 E1 ?? ?? ?? 1B 06 00 A0 E1 ?? ?? ?? EB 00 30 94 E5 03 00 55 E1 00 00 00 AA 00 50 E0 E3 05 00 A0 E1 F0 81 BD E8 }
	condition:
		$pattern
}

rule authunix_create_default_be4bfc2cb2c768ad0fd9b562cda37d1b {
	meta:
		aliases = "__GI_authunix_create_default, authunix_create_default"
		size = "172"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { F0 41 2D E9 03 00 A0 E3 41 DF 4D E2 ?? ?? ?? EB 00 40 50 E2 04 50 A0 01 03 00 00 0A 04 01 A0 E1 ?? ?? ?? EB 00 50 50 E2 10 00 00 0A 04 80 8D E2 08 00 A0 E1 FF 10 A0 E3 ?? ?? ?? EB 01 00 70 E3 0A 00 00 0A 00 30 A0 E3 03 31 CD E5 ?? ?? ?? EB 00 70 A0 E1 ?? ?? ?? EB 05 10 A0 E1 00 60 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 00 AA ?? ?? ?? EB 10 00 50 E3 00 30 A0 B1 10 30 A0 A3 07 10 A0 E1 06 20 A0 E1 08 00 A0 E1 00 50 8D E5 ?? ?? ?? EB 00 40 A0 E1 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 41 DF 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule __ieee754_remainder_f1e04aab43a52cbdc1596f13efcde173 {
	meta:
		aliases = "__ieee754_remainder"
		size = "296"
		objfiles = "e_remainder@libm.a"
	strings:
		$pattern = { F0 41 2D E9 03 40 A0 E1 06 42 6D ED 0C 00 2D E9 02 D1 BD EC 02 30 A0 E1 02 51 C3 E3 04 30 95 E1 03 00 2D E9 02 81 BD EC 01 70 A0 E1 0A 00 00 0A E8 30 9F E5 02 61 C0 E3 03 00 56 E1 00 80 A0 E1 05 00 00 CA 03 00 55 E1 06 00 00 DA 02 31 85 E2 01 36 83 E2 04 30 93 E1 02 00 00 0A 85 01 10 EE 80 01 40 EE 2B 00 00 EA B4 30 9F E5 03 00 55 E1 02 81 2D DD 03 00 BD D8 85 01 05 DE 02 81 2D DD 0C 00 BD D8 ?? ?? ?? DB 07 20 64 E0 06 30 65 E0 02 30 93 E1 88 01 10 0E 1E 00 00 0A 02 81 2D ED 03 00 BD E8 ?? ?? ?? EB 02 D1 2D ED 03 00 BD E8 80 C1 00 EE ?? ?? ?? EB 02 06 55 E3 80 91 00 EE 06 00 00 AA 84 01 04 EE }
	condition:
		$pattern
}

rule frame_heapsort_d3bdb8f9a8834c6aaaf04c4060b1a059 {
	meta:
		aliases = "frame_heapsort"
		size = "152"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { F0 41 2D E9 04 50 92 E5 A5 30 A0 E1 01 40 53 E2 04 D0 4D E2 00 80 A0 E1 01 70 A0 E1 08 60 82 E2 07 00 00 4A 04 30 A0 E1 08 00 A0 E1 07 10 A0 E1 06 20 A0 E1 00 50 8D E5 C3 FF FF EB 01 40 54 E2 F7 FF FF 5A 01 40 45 E2 00 00 54 E3 0F 00 00 DA 05 31 A0 E1 03 30 86 E0 04 50 43 E2 00 30 95 E5 00 20 96 E5 08 00 A0 E1 00 30 86 E5 07 10 A0 E1 04 20 05 E4 00 30 A0 E3 00 40 8D E5 06 20 A0 E1 01 40 44 E2 B0 FF FF EB 00 00 54 E3 F2 FF FF CA 04 D0 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule __GI_xdr_rmtcall_args_f44a354fc32a9124efd25609e6846524 {
	meta:
		aliases = "xdr_rmtcall_args, __GI_xdr_rmtcall_args"
		size = "272"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { F0 41 2D E9 04 D0 4D E2 00 50 A0 E1 01 60 A0 E1 ?? ?? ?? EB 00 00 50 E3 04 10 86 E2 05 00 A0 E1 37 00 00 0A ?? ?? ?? EB 00 00 50 E3 08 10 86 E2 05 00 A0 E1 32 00 00 0A ?? ?? ?? EB 00 00 50 E3 04 40 8D E2 05 00 A0 E1 2D 00 00 0A 00 30 A0 E3 04 30 24 E5 04 30 95 E5 0F E0 A0 E1 10 F0 93 E5 0D 10 A0 E1 00 80 A0 E1 05 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 05 00 A0 E1 21 00 00 0A 04 30 95 E5 0F E0 A0 E1 10 F0 93 E5 10 10 96 E5 00 70 A0 E1 05 00 A0 E1 0F E0 A0 E1 14 F0 96 E5 00 00 50 E3 05 00 A0 E1 16 00 00 0A 04 30 95 E5 0F E0 A0 E1 10 F0 93 E5 00 30 67 E0 0C 30 A6 E5 00 40 A0 E1 08 10 A0 E1 04 30 95 E5 }
	condition:
		$pattern
}

rule __GI_statvfs_14a69c532dec99beed4be05825177de3 {
	meta:
		aliases = "statvfs, fstatvfs, __GI_statvfs"
		size = "652"
		objfiles = "fstatvfs@libc.a, statvfs@libc.a"
	strings:
		$pattern = { F0 41 2D E9 05 DC 4D E2 0C D0 4D E2 01 40 A0 E1 4B 1E 8D E2 00 60 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 E0 B3 89 00 00 BA B8 34 9D E5 BC 24 9D E5 C0 14 9D E5 C4 04 9D E5 C8 C4 9D E5 08 30 84 E5 CC 34 9D E5 B4 E4 9D E5 20 30 84 E5 D4 34 9D E5 00 50 A0 E3 04 E0 84 E5 0C 20 84 E5 10 10 84 E5 14 00 84 E5 18 C0 84 E5 2C 30 84 E5 00 E0 84 E5 05 10 A0 E1 18 20 A0 E3 24 50 84 E5 30 00 84 E2 ?? ?? ?? EB 18 30 94 E5 45 1E 8D E2 1C 30 84 E5 28 50 84 E5 06 00 A0 E1 08 10 81 E2 ?? ?? ?? EB 05 00 50 E1 05 00 A0 B1 68 00 00 BA ?? ?? ?? EB A4 11 9F E5 00 70 A0 E1 A0 01 9F E5 00 80 97 E5 ?? ?? ?? EB 00 60 50 E2 }
	condition:
		$pattern
}

rule sem_timedwait_d93c76eaec61859c8e7f18656969c9ac {
	meta:
		aliases = "sem_timedwait"
		size = "432"
		objfiles = "semaphore@libpthread.a"
	strings:
		$pattern = { F0 41 2D E9 08 D0 4D E2 00 60 A0 E1 01 80 A0 E1 C8 FF FF EB 00 50 A0 E1 05 10 A0 E1 06 00 A0 E1 ?? ?? ?? EB 08 30 96 E5 00 00 53 E3 04 00 00 DA 01 30 43 E2 08 30 86 E5 06 00 A0 E1 ?? ?? ?? EB 54 00 00 EA 04 20 98 E5 58 31 9F E5 03 00 52 E1 05 00 00 9A 06 00 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 00 20 E0 E3 16 30 A0 E3 48 00 00 EA 38 31 9F E5 04 30 8D E5 00 30 A0 E3 00 60 8D E5 05 00 A0 E1 BA 31 C5 E5 0D 10 A0 E1 53 FF FF EB 42 30 D5 E5 00 00 53 E3 03 00 00 0A 40 30 D5 E5 00 00 53 E3 01 40 A0 03 03 00 00 0A 0C 00 86 E2 05 10 A0 E1 29 FF FF EB 00 40 A0 E3 06 00 A0 E1 ?? ?? ?? EB 00 00 54 E3 03 00 00 0A }
	condition:
		$pattern
}

rule _Unwind_Backtrace_ae1629ad087a265d5d0aa67f86f24617 {
	meta:
		aliases = "_Unwind_Backtrace"
		size = "124"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { F0 41 2D E9 08 D0 4D E2 04 50 8D E2 00 80 A0 E1 05 00 A0 E1 01 70 A0 E1 B5 FF FF EB 0D 60 A0 E1 08 00 00 EA 0F E0 A0 E1 08 F0 A0 E1 00 00 50 E3 0D 10 A0 E1 05 00 A0 E1 0B 00 00 1A 05 00 54 E3 0A 00 00 0A 9D FF FF EB 0D 10 A0 E1 05 00 A0 E1 91 FF FF EB 00 00 50 E3 05 00 50 13 00 40 A0 E1 07 10 A0 E1 05 00 A0 E1 ED FF FF 0A 03 40 A0 E3 04 00 A0 E1 08 D0 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule _Unwind_SjLj_ForcedUnwind_94e97810e4ba59c44bd339b68275d397 {
	meta:
		aliases = "_Unwind_SjLj_ForcedUnwind"
		size = "92"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { F0 41 2D E9 08 D0 4D E2 04 80 8D E2 00 40 A0 E1 08 00 A0 E1 01 50 A0 E1 02 60 A0 E1 48 FF FF EB 04 30 9D E5 0C 50 84 E5 10 60 84 E5 04 00 A0 E1 0D 10 A0 E1 00 30 8D E5 48 FF FF EB 07 00 50 E3 0D 70 A0 E1 01 00 00 0A 08 D0 8D E2 F0 81 BD E8 08 00 A0 E1 0D 10 A0 E1 C4 FF FF EB }
	condition:
		$pattern
}

rule _Unwind_RaiseException_Phase2_73994c4dee1c1ca238d3fff87bef88f9 {
	meta:
		aliases = "_Unwind_RaiseException_Phase2"
		size = "164"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { F0 41 2D E9 0C D0 4D E2 00 60 A0 E1 01 50 A0 E1 08 80 8D E2 12 00 00 EA 08 C0 9D E5 00 00 5C E3 0A 00 00 0A 0C 00 96 E8 01 00 A0 E3 00 60 8D E5 04 50 8D E5 02 10 87 E3 0F E0 A0 E1 0C F0 A0 E1 07 00 50 E3 13 00 00 0A 08 00 50 E3 10 00 00 1A 00 00 57 E3 11 00 00 1A 05 00 A0 E1 08 10 A0 E1 77 FF FF EB 08 10 A0 E1 05 00 A0 E1 6B FF FF EB 00 40 A0 E1 05 00 A0 E1 83 FF FF EB 10 30 96 E5 03 00 50 E1 04 70 A0 03 00 70 A0 13 00 00 54 E3 E0 FF FF 0A 02 00 A0 E3 0C D0 8D E2 F0 81 BD E8 ?? ?? ?? EB }
	condition:
		$pattern
}

rule fde_single_encoding_compare_cc589fcdaed50bd35673a2e0b64f1bf7 {
	meta:
		aliases = "fde_single_encoding_compare"
		size = "164"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { F0 41 2D E9 10 50 80 E2 00 40 A0 E1 01 30 D5 E5 10 00 D0 E5 03 04 80 E1 A0 01 A0 E1 08 D0 4D E2 01 60 A0 E1 FF 00 00 E2 04 10 A0 E1 02 80 A0 E1 50 FF FF EB 01 30 D5 E5 00 70 A0 E1 10 00 D4 E5 03 04 80 E1 A0 01 A0 E1 08 20 86 E2 07 10 A0 E1 04 30 8D E2 FF 00 00 E2 5C FF FF EB 01 30 D5 E5 10 00 D4 E5 03 04 80 E1 A0 01 A0 E1 08 20 88 E2 0D 30 A0 E1 FF 00 00 E2 07 10 A0 E1 53 FF FF EB 04 20 9D E5 00 30 9D E5 03 00 52 E1 01 00 A0 E3 01 00 00 8A 00 00 E0 E3 00 00 A0 23 08 D0 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule fcloseall_e6e70e7292cc469b4452236c7f62342a {
	meta:
		aliases = "fcloseall"
		size = "324"
		objfiles = "fcloseall@libc.a"
	strings:
		$pattern = { F0 41 2D E9 10 D0 4D E2 14 21 9F E5 14 11 9F E5 0D 00 A0 E1 10 61 9F E5 0F E0 A0 E1 06 F0 A0 E1 08 71 9F E5 F8 00 9F E5 0F E0 A0 E1 07 F0 A0 E1 FC 20 9F E5 00 30 92 E5 01 30 83 E2 00 30 82 E5 01 10 A0 E3 EC 50 9F E5 0D 00 A0 E1 0F E0 A0 E1 05 F0 A0 E1 CC 10 9F E5 DC 20 9F E5 0D 00 A0 E1 0F E0 A0 E1 06 F0 A0 E1 CC 00 9F E5 0F E0 A0 E1 07 F0 A0 E1 C4 30 9F E5 0D 00 A0 E1 01 10 A0 E3 00 40 93 E5 0F E0 A0 E1 05 F0 A0 E1 00 80 A0 E3 19 00 00 EA 34 70 94 E5 00 00 57 E3 20 60 94 E5 06 00 00 1A 80 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 74 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 D4 E5 30 30 03 E2 }
	condition:
		$pattern
}

rule getgrent_r_b2edef6aa4d48cb1821be1227c8cf3e8 {
	meta:
		aliases = "getpwent_r, __GI_getgrent_r, __GI_getspent_r, __GI_getpwent_r, getspent_r, getgrent_r"
		size = "240"
		objfiles = "getpwent_r@libc.a, getspent_r@libc.a, getgrent_r@libc.a"
	strings:
		$pattern = { F0 41 2D E9 14 D0 4D E2 03 50 A0 E1 00 60 A0 E1 B4 30 9F E5 04 00 8D E2 01 70 A0 E1 02 80 A0 E1 A8 10 9F E5 A8 20 9F E5 A8 40 9F E5 0F E0 A0 E1 03 F0 A0 E1 A0 30 9F E5 94 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 94 E5 00 00 53 E3 00 30 A0 E3 88 10 9F E5 88 00 9F E5 00 30 85 E5 08 00 00 1A ?? ?? ?? EB 00 00 50 E3 01 30 A0 13 00 00 84 E5 34 30 80 15 02 00 00 1A ?? ?? ?? EB 00 40 90 E5 09 00 00 EA 4C 30 9F E5 00 C0 93 E5 07 20 A0 E1 08 30 A0 E1 06 10 A0 E1 48 00 9F E5 00 C0 8D E5 ?? ?? ?? EB 00 40 50 E2 00 60 85 05 04 00 8D E2 01 10 A0 E3 30 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 14 D0 8D E2 }
	condition:
		$pattern
}

rule __GI_readdir64_r_7db56102642841fc0f336ca213732531 {
	meta:
		aliases = "readdir64_r, __GI_readdir64_r"
		size = "292"
		objfiles = "readdir64_r@libc.a"
	strings:
		$pattern = { F0 41 2D E9 18 40 80 E2 10 D0 4D E2 00 31 9F E5 00 50 A0 E1 01 80 A0 E1 0D 00 A0 E1 F4 10 9F E5 02 70 A0 E1 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 E0 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 60 A0 E3 0C 00 95 E9 02 00 53 E1 0F 00 00 8A 00 00 95 E5 0C 10 95 E5 14 20 95 E5 ?? ?? ?? EB 00 00 50 E3 06 00 00 CA 00 30 A0 E3 00 30 87 E5 00 40 A0 01 1C 00 00 0A ?? ?? ?? EB 00 40 90 E5 19 00 00 EA 00 30 A0 E3 04 30 85 E5 08 00 85 E5 04 20 95 E5 0C 00 95 E5 00 60 82 E0 10 E0 86 E2 01 10 DE E5 10 30 D6 E5 00 C0 92 E7 04 00 96 E5 01 34 83 E1 08 10 96 E5 03 20 82 E0 00 C0 9C E1 04 20 85 E5 10 10 85 E5 }
	condition:
		$pattern
}

rule readdir_r_17595d6030c6606a29ba6bb86895d891 {
	meta:
		aliases = "__GI_readdir_r, readdir_r"
		size = "288"
		objfiles = "readdir_r@libc.a"
	strings:
		$pattern = { F0 41 2D E9 18 40 80 E2 10 D0 4D E2 FC 30 9F E5 00 50 A0 E1 01 80 A0 E1 0D 00 A0 E1 F0 10 9F E5 02 70 A0 E1 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 DC 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 60 A0 E3 0C 00 95 E9 02 00 53 E1 0F 00 00 8A 00 00 95 E5 0C 10 95 E5 14 20 95 E5 ?? ?? ?? EB 00 00 50 E3 06 00 00 CA 00 30 A0 E3 00 30 87 E5 00 40 A0 01 1B 00 00 0A ?? ?? ?? EB 00 40 90 E5 18 00 00 EA 00 30 A0 E3 04 30 85 E5 08 00 85 E5 04 20 95 E5 0C C0 95 E5 0C 60 82 E0 04 10 96 E5 08 E0 86 E2 08 30 D6 E5 01 00 DE E5 10 10 85 E5 0C 10 92 E7 00 34 83 E1 03 20 82 E0 00 00 51 E3 04 20 85 E5 DE FF FF 0A }
	condition:
		$pattern
}

rule lfind_c6ce82c7da8bbafa483129ec4fb27072 {
	meta:
		aliases = "__GI_lfind, lfind"
		size = "80"
		objfiles = "lfind@libc.a"
	strings:
		$pattern = { F0 41 2D E9 18 80 9D E5 00 50 92 E5 00 70 A0 E1 01 40 A0 E1 03 60 A0 E1 06 00 00 EA 0F E0 A0 E1 08 F0 A0 E1 00 00 50 E3 01 00 00 1A 04 00 A0 E1 F0 81 BD E8 06 40 84 E0 01 50 55 E2 04 10 A0 E1 07 00 A0 E1 F4 FF FF 2A 00 00 A0 E3 F0 81 BD E8 }
	condition:
		$pattern
}

rule __GI_xdr_union_626193ad18df22a8cd1c4935f85d8688 {
	meta:
		aliases = "xdr_union, __GI_xdr_union"
		size = "136"
		objfiles = "xdr@libc.a"
	strings:
		$pattern = { F0 41 2D E9 18 80 9D E5 01 50 A0 E1 02 70 A0 E1 03 40 A0 E1 00 60 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 10 95 15 04 00 00 1A 14 00 00 EA 00 30 94 E5 01 00 53 E1 08 40 84 E2 0A 00 00 0A 04 C0 94 E5 00 00 5C E3 F8 FF FF 1A 00 00 58 E3 0B 00 00 0A 06 00 A0 E1 07 10 A0 E1 00 20 E0 E3 0F E0 A0 E1 08 F0 A0 E1 F0 81 BD E8 06 00 A0 E1 07 10 A0 E1 00 20 E0 E3 0F E0 A0 E1 0C F0 A0 E1 F0 81 BD E8 00 00 A0 E3 F0 81 BD E8 }
	condition:
		$pattern
}

rule sgetspent_r_12a2bc5d921a98cb614757ef952b2e38 {
	meta:
		aliases = "__GI_sgetspent_r, sgetspent_r"
		size = "120"
		objfiles = "sgetspent_r@libc.a"
	strings:
		$pattern = { F0 41 2D E9 18 80 9D E5 03 60 A0 E1 FF 00 53 E3 00 30 A0 E3 00 30 88 E5 02 40 A0 E1 01 70 A0 E1 00 50 A0 E1 04 00 00 8A ?? ?? ?? EB 22 30 A0 E3 03 20 A0 E1 00 30 80 E5 0C 00 00 EA 02 00 50 E1 05 00 00 0A ?? ?? ?? EB 06 00 50 E1 05 10 A0 E1 04 00 A0 E1 F3 FF FF 2A ?? ?? ?? EB 04 10 A0 E1 07 00 A0 E1 ?? ?? ?? EB 00 20 50 E2 00 70 88 05 02 00 A0 E1 F0 81 BD E8 }
	condition:
		$pattern
}

rule exchange_57d689c046194a6527a792c7c258779b {
	meta:
		aliases = "exchange"
		size = "200"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { F0 41 2D E9 20 60 81 E2 C0 00 96 E8 00 80 91 E5 01 C0 A0 E1 20 00 00 EA 07 10 66 E0 08 E0 67 E0 01 00 5E E1 00 10 A0 D3 00 40 A0 C3 04 00 00 CA 11 00 00 EA 05 20 90 E7 0E 30 90 E7 05 30 80 E7 0E 20 80 E7 04 30 86 E0 08 20 61 E0 03 51 A0 E1 01 00 54 E1 04 30 82 E0 03 E1 A0 E1 01 40 84 E2 F3 FF FF BA 02 80 A0 E1 0B 00 00 EA 04 20 90 E7 05 30 90 E7 04 30 80 E7 05 20 80 E7 01 30 86 E0 01 20 87 E0 0E 00 51 E1 03 41 A0 E1 02 51 A0 E1 01 10 81 E2 F4 FF FF BA 0E 60 86 E0 07 00 58 E1 06 00 57 C1 DB FF FF CA 00 30 9C E5 20 10 8C E2 06 00 91 E8 03 20 62 E0 02 10 81 E0 24 30 8C E5 20 10 8C E5 F0 81 BD E8 }
	condition:
		$pattern
}

rule sysctl_86046b1aab37ad3b834bb08c949c5fb0 {
	meta:
		aliases = "sysctl"
		size = "112"
		objfiles = "sysctl@libc.a"
	strings:
		$pattern = { F0 41 2D E9 28 D0 4D E2 00 40 A0 E1 01 50 A0 E1 02 60 A0 E1 0D 00 A0 E1 00 10 A0 E3 28 20 A0 E3 03 70 A0 E1 ?? ?? ?? EB 40 30 9D E5 10 30 8D E5 44 30 9D E5 0D 80 A0 E1 F0 00 8D E8 14 30 8D E5 0D 00 A0 E1 95 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 28 D0 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule svcudp_reply_0211854d3d41ff84f7580433c291cd72 {
	meta:
		aliases = "svcudp_reply"
		size = "616"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { F0 41 2D E9 30 70 90 E5 00 80 A0 E3 08 50 87 E2 01 40 A0 E1 08 D0 4D E2 08 10 A0 E1 04 30 95 E5 00 60 A0 E1 08 80 87 E5 05 00 A0 E1 0F E0 A0 E1 14 F0 93 E5 04 30 97 E5 04 10 A0 E1 00 30 84 E5 05 00 A0 E1 ?? ?? ?? EB 08 00 50 E1 7C 00 00 0A 04 30 95 E5 05 00 A0 E1 0F E0 A0 E1 10 F0 93 E5 3C 20 86 E2 0C 30 92 E5 08 00 53 E1 00 40 A0 E1 2C 10 96 E5 06 00 00 0A 34 10 86 E5 38 00 86 E5 02 10 A0 E1 00 00 96 E5 08 20 A0 E1 ?? ?? ?? EB 05 00 00 EA 0C E0 96 E5 00 00 96 E5 10 C0 86 E2 04 20 A0 E1 00 50 8D E8 ?? ?? ?? EB 04 00 50 E1 00 80 A0 E1 62 00 00 1A B0 31 97 E5 00 30 53 E2 01 30 A0 13 00 00 50 E3 }
	condition:
		$pattern
}

rule __GI_vfwprintf_0df06231186296093b977fdc69504a03 {
	meta:
		aliases = "vfwprintf, __GI_vfwprintf"
		size = "196"
		objfiles = "vfwprintf@libc.a"
	strings:
		$pattern = { F0 41 2D E9 34 70 90 E5 38 50 80 E2 10 D0 4D E2 00 00 57 E3 00 40 A0 E1 01 80 A0 E1 02 60 A0 E1 0D 00 A0 E1 88 10 9F E5 05 20 A0 E1 06 00 00 1A 80 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 74 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 D4 E5 01 20 D4 E5 02 34 83 E1 21 3D 03 E2 21 0D 53 E3 02 1B A0 E3 04 00 A0 E1 03 00 00 0A ?? ?? ?? EB 00 00 50 E3 00 50 E0 E3 04 00 00 1A 08 10 A0 E1 06 20 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 50 A0 E1 00 00 57 E3 0D 00 A0 E1 01 10 A0 E3 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 05 00 A0 E1 10 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fgetpos_60138dfb05e6d089c3c502f27343bb93 {
	meta:
		aliases = "fgetpos"
		size = "176"
		objfiles = "fgetpos@libc.a"
	strings:
		$pattern = { F0 41 2D E9 34 70 90 E5 38 60 80 E2 10 D0 4D E2 00 00 57 E3 00 40 A0 E1 01 50 A0 E1 06 20 A0 E1 0D 00 A0 E1 00 80 E0 E3 70 10 9F E5 06 00 00 1A 6C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 06 00 A0 E1 60 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 85 E5 06 00 00 BA 2C 30 94 E5 30 20 94 E5 04 30 85 E5 08 20 85 E5 02 30 D4 E5 0C 30 85 E5 00 80 A0 E3 00 00 57 E3 0D 00 A0 E1 01 10 A0 E3 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 08 00 A0 E1 10 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fgetpos64_0cbfd7a913089e1c87fd9d2420e8416f {
	meta:
		aliases = "fgetpos64"
		size = "180"
		objfiles = "fgetpos64@libc.a"
	strings:
		$pattern = { F0 41 2D E9 34 70 90 E5 38 60 80 E2 10 D0 4D E2 00 00 57 E3 00 50 A0 E1 01 40 A0 E1 06 20 A0 E1 0D 00 A0 E1 00 80 E0 E3 74 10 9F E5 06 00 00 1A 70 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 06 00 A0 E1 64 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 ?? ?? ?? EB 03 00 84 E8 04 30 94 E5 00 00 53 E3 06 00 00 BA 2C 30 95 E5 30 20 95 E5 08 30 84 E5 0C 20 84 E5 02 30 D5 E5 10 30 84 E5 00 80 A0 E3 00 00 57 E3 0D 00 A0 E1 01 10 A0 E3 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 08 00 A0 E1 10 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule vfprintf_12912f0df1b85656d3f192b227100828 {
	meta:
		aliases = "__GI_vfprintf, vfprintf"
		size = "188"
		objfiles = "vfprintf@libc.a"
	strings:
		$pattern = { F0 41 2D E9 34 80 90 E5 38 50 80 E2 10 D0 4D E2 00 00 58 E3 00 40 A0 E1 01 70 A0 E1 02 60 A0 E1 0D 00 A0 E1 80 10 9F E5 05 20 A0 E1 06 00 00 1A 78 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 6C 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 D4 E5 C0 30 03 E2 C0 00 53 E3 80 10 A0 E3 04 00 A0 E1 03 00 00 0A ?? ?? ?? EB 00 00 50 E3 00 50 E0 E3 04 00 00 1A 07 10 A0 E1 06 20 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 50 A0 E1 00 00 58 E3 0D 00 A0 E1 01 10 A0 E3 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 05 00 A0 E1 10 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule fgets_a82a09873b94efaf99422861299e73d7 {
	meta:
		aliases = "__GI_fgets, fgetws, fgets"
		size = "148"
		objfiles = "fgetws@libc.a, fgets@libc.a"
	strings:
		$pattern = { F0 41 2D E9 34 80 92 E5 10 D0 4D E2 38 50 82 E2 00 00 58 E3 02 40 A0 E1 00 70 A0 E1 01 60 A0 E1 05 20 A0 E1 0D 00 A0 E1 54 10 9F E5 06 00 00 1A 50 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 44 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 06 10 A0 E1 04 20 A0 E1 07 00 A0 E1 ?? ?? ?? EB 00 00 58 E3 00 40 A0 E1 01 10 A0 E3 0D 00 A0 E1 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 04 00 A0 E1 10 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
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

rule statvfs64_af945dd05cf63d309053834db119496d {
	meta:
		aliases = "fstatvfs64, statvfs64"
		size = "688"
		objfiles = "statvfs64@libc.a, fstatvfs64@libc.a"
	strings:
		$pattern = { F0 41 2D E9 53 DE 4D E2 01 40 A0 E1 13 1D 8D E2 00 60 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 00 E0 B3 94 00 00 BA F0 24 9D E5 C4 34 9D E5 38 20 84 E5 F8 24 9D E5 04 30 84 E5 44 20 84 E5 00 30 84 E5 C8 24 9D E5 CC 34 9D E5 08 20 84 E5 0C 30 84 E5 4D 2E 8D E2 0C 00 92 E8 10 20 84 E5 14 30 84 E5 D8 24 9D E5 DC 34 9D E5 18 20 84 E5 1C 30 84 E5 4E 2E 8D E2 0C 00 92 E8 20 20 84 E5 24 30 84 E5 E8 24 9D E5 EC 34 9D E5 00 50 A0 E3 28 20 84 E5 2C 30 84 E5 05 10 A0 E1 18 20 A0 E3 3C 50 84 E5 48 00 84 E2 ?? ?? ?? EB 28 20 84 E2 0C 00 92 E8 40 50 84 E5 30 20 84 E5 34 30 84 E5 06 00 A0 E1 46 1E 8D E2 ?? ?? ?? EB }
	condition:
		$pattern
}

rule fork_9773dd55a6f3148101c2ce0aea1d0d88 {
	meta:
		aliases = "__fork, fork"
		size = "404"
		objfiles = "ptfork@libpthread.a"
	strings:
		$pattern = { F0 41 2D E9 58 01 9F E5 58 41 9F E5 04 D0 4D E2 0F E0 A0 E1 04 F0 A0 E1 4C 31 9F E5 00 00 93 E5 48 31 9F E5 00 80 93 E5 44 31 9F E5 00 70 93 E5 E9 FF FF EB ?? ?? ?? EB 38 01 9F E5 0F E0 A0 E1 04 F0 A0 E1 30 01 9F E5 0F E0 A0 E1 04 F0 A0 E1 ?? ?? ?? EB 00 50 50 E2 20 41 9F E5 20 61 9F E5 14 01 9F E5 30 00 00 1A 00 00 56 E3 0D 40 A0 E1 0D 70 A0 E1 0D 00 A0 E1 0F 00 00 0A 04 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 FC 30 9F E5 05 10 A0 E1 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 D8 00 9F E5 0D 10 A0 E1 0F E0 A0 E1 06 F0 A0 E1 DC 30 9F E5 0D 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 05 10 A0 E1 B0 00 9F E5 0F E0 A0 E1 }
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

rule dl_iterate_phdr_3137716cf6c82eee34084b6f0aa16f90 {
	meta:
		aliases = "__dl_iterate_phdr, dl_iterate_phdr"
		size = "116"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { F0 41 2D E9 64 30 9F E5 00 60 93 E5 10 D0 4D E2 00 80 A0 E1 01 70 A0 E1 00 30 A0 E3 0B 00 00 EA CC 50 96 E5 08 10 96 E8 D0 E0 96 E5 45 44 A0 E1 08 50 8D E8 0D 40 CD E5 0C 50 CD E5 0F E0 A0 E1 08 F0 A0 E1 00 30 50 E2 05 00 00 1A 0C 60 96 E5 00 00 56 E3 0D 00 A0 E1 10 10 A0 E3 07 20 A0 E1 EE FF FF 1A 03 00 A0 E1 10 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pmap_getmaps_0884c205ec1c95986c6f35ba2c0cba97 {
	meta:
		aliases = "pmap_getmaps"
		size = "212"
		objfiles = "pm_getmaps@libc.a"
	strings:
		$pattern = { F0 41 2D E9 6F 30 A0 E3 18 D0 4D E2 00 40 A0 E3 00 C0 E0 E3 03 30 C0 E5 02 40 C0 E5 10 C0 8D E5 33 C0 8C E2 98 10 9F E5 02 20 A0 E3 10 30 8D E2 00 C0 8D E5 7D CF A0 E3 00 80 A0 E1 04 C0 8D E5 14 40 8D E5 ?? ?? ?? EB 00 70 50 E2 04 30 A0 E1 04 10 A0 E3 6C 20 9F E5 04 60 A0 E1 3C 50 A0 E3 11 00 00 0A 04 C0 97 E5 00 40 9C E5 58 C0 9F E5 00 C0 8D E5 14 C0 8D E2 04 C0 8D E5 08 50 8D E5 0C 60 8D E5 0F E0 A0 E1 04 F0 A0 E1 06 00 50 E1 38 10 9F E5 07 00 A0 E1 ?? ?? ?? 1B 07 00 A0 E1 04 30 97 E5 0F E0 A0 E1 10 F0 93 E5 14 00 9D E5 00 30 A0 E3 03 30 C8 E5 02 30 C8 E5 18 D0 8D E2 F0 81 BD E8 A0 86 01 00 }
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

rule __GI___xpg_strerror_r_11d471f2fcad9f86751fe23ace5164a9 {
	meta:
		aliases = "__xpg_strerror_r, strerror_r, __GI___xpg_strerror_r"
		size = "232"
		objfiles = "__xpg_strerror_r@libc.a"
	strings:
		$pattern = { F0 41 2D E9 7C 00 50 E3 00 C0 A0 E1 38 D0 4D E2 01 80 A0 E1 02 60 A0 E1 C0 50 9F 95 00 00 A0 91 03 00 00 9A 08 00 00 EA 00 00 53 E3 01 50 85 E2 01 00 40 02 00 00 50 E3 00 30 D5 E5 F9 FF FF 1A 00 00 53 E3 00 70 A0 11 0C 00 00 1A 0C 10 A0 E1 C1 2F A0 E1 09 30 E0 E3 00 C0 A0 E3 37 00 8D E2 00 C0 8D E5 ?? ?? ?? EB 0E 50 40 E2 05 00 A0 E1 6C 10 9F E5 0E 20 A0 E3 ?? ?? ?? EB 16 70 A0 E3 05 00 A0 E1 ?? ?? ?? EB 00 00 58 E3 01 40 80 E2 00 60 A0 03 06 00 54 E1 06 40 A0 81 22 70 A0 83 00 00 54 E3 06 00 00 0A 04 20 A0 E1 05 10 A0 E1 08 00 A0 E1 ?? ?? ?? EB 04 20 88 E0 00 30 A0 E3 01 30 42 E5 00 00 57 E3 }
	condition:
		$pattern
}

rule sigqueue_ecd144a7a4b09a469129b67e0c28cd80 {
	meta:
		aliases = "sigqueue"
		size = "124"
		objfiles = "sigqueue@libc.a"
	strings:
		$pattern = { F0 41 2D E9 80 D0 4D E2 01 50 A0 E1 00 70 A0 E1 00 10 A0 E3 02 60 A0 E1 0D 00 A0 E1 80 20 A0 E3 00 80 E0 E3 ?? ?? ?? EB 00 50 8D E5 08 80 8D E5 ?? ?? ?? EB 0C 00 8D E5 ?? ?? ?? EB 14 60 8D E5 10 00 8D E5 0D 20 A0 E1 05 10 A0 E1 07 00 A0 E1 B2 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 08 40 A0 E1 04 00 A0 E1 80 D0 8D E2 F0 81 BD E8 }
	condition:
		$pattern
}

rule svc_run_5c035dcb9169047f7184919ab4eade0a {
	meta:
		aliases = "svc_run"
		size = "240"
		objfiles = "svc_run@libc.a"
	strings:
		$pattern = { F0 41 2D E9 ?? ?? ?? EB 00 40 90 E5 00 00 54 E3 00 80 A0 E1 03 00 00 1A ?? ?? ?? EB 00 30 90 E5 00 00 53 E3 F0 81 BD 08 84 01 A0 E1 ?? ?? ?? EB 00 70 A0 E3 00 50 A0 E1 0E 00 00 EA ?? ?? ?? EB 00 30 90 E5 04 30 93 E7 04 30 85 E7 00 30 90 E5 04 30 83 E0 05 20 D3 E5 04 30 D3 E5 02 34 83 E1 43 14 A0 E1 00 20 A0 E3 07 20 C6 E5 05 10 C6 E5 04 30 C6 E5 06 20 C6 E5 00 10 98 E5 87 41 A0 E1 01 00 57 E1 04 60 85 E0 01 70 87 E2 EA FF FF BA 05 00 A0 E1 00 20 E0 E3 ?? ?? ?? EB 01 00 70 E3 02 00 00 0A 00 00 50 E3 0C 00 00 0A 08 00 00 EA 05 00 A0 E1 ?? ?? ?? EB ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 CE FF FF 0A }
	condition:
		$pattern
}

rule _stdio_init_a8f0892ef9e444a6c0b66bdd4862b6b1 {
	meta:
		aliases = "_stdio_init"
		size = "112"
		objfiles = "_stdio@libc.a"
	strings:
		$pattern = { F0 41 2D E9 ?? ?? ?? EB 5C 40 9F E5 01 30 D4 E5 00 60 D4 E5 00 70 A0 E1 00 00 A0 E3 03 64 86 E1 00 80 97 E5 ?? ?? ?? EB 01 00 60 E2 00 64 26 E0 51 30 D4 E5 50 50 D4 E5 46 24 A0 E1 01 00 A0 E3 03 54 85 E1 01 20 C4 E5 00 60 C4 E5 ?? ?? ?? EB 01 00 60 E2 00 54 25 E0 45 34 A0 E1 51 30 C4 E5 00 80 87 E5 50 50 C4 E5 F0 81 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule pthread_join_5767d2d6bae27a13afa5610d3ee2f909 {
	meta:
		aliases = "pthread_join"
		size = "480"
		objfiles = "join@libpthread.a"
	strings:
		$pattern = { F0 41 2D E9 A0 D0 4D E2 00 70 A0 E1 01 80 A0 E1 7E FF FF EB B8 21 9F E5 07 3B A0 E1 23 3B A0 E1 03 52 82 E0 9C 00 8D E5 A8 31 9F E5 9C 10 9D E5 05 00 A0 E1 98 30 8D E5 94 50 8D E5 ?? ?? ?? EB 08 40 95 E5 00 00 54 E3 02 00 00 0A 10 30 94 E5 07 00 53 E1 03 00 00 0A 05 00 A0 E1 ?? ?? ?? EB 03 00 A0 E3 58 00 00 EA 9C 30 9D E5 03 00 54 E1 03 00 00 1A 05 00 A0 E1 ?? ?? ?? EB 23 00 A0 E3 51 00 00 EA 2D 30 D4 E5 00 00 53 E3 02 00 00 1A 38 30 94 E5 00 00 53 E3 03 00 00 0A 05 00 A0 E1 ?? ?? ?? EB 16 00 A0 E3 47 00 00 EA 2C 30 D4 E5 00 00 53 E3 2B 00 00 1A 9C 00 9D E5 94 10 8D E2 41 FF FF EB 9C 30 9D E5 }
	condition:
		$pattern
}

rule pthread_create_28d0c80c925e077c13016ca210f920c5 {
	meta:
		aliases = "pthread_create"
		size = "188"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { F0 41 2D E9 AC C0 9F E5 00 C0 9C E5 00 00 5C E3 94 D0 4D E2 00 80 A0 E1 01 50 A0 E1 02 60 A0 E1 03 70 A0 E1 03 00 00 AA ?? ?? ?? EB 00 00 50 E3 0B 00 A0 B3 1D 00 00 BA EB FD FF EB 00 30 A0 E3 00 40 A0 E1 03 10 A0 E1 02 00 A0 E3 14 20 8D E2 08 50 8D E5 0C 60 8D E5 10 70 8D E5 00 40 8D E5 04 30 8D E5 ?? ?? ?? EB 48 30 9F E5 0D 10 A0 E1 00 00 93 E5 94 20 A0 E3 ?? ?? ?? EB 01 00 70 E3 03 00 00 1A ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 F4 FF FF 0A 04 00 A0 E1 5D FE FF EB 34 30 94 E5 00 00 53 E3 30 30 94 05 34 00 94 E5 00 30 88 05 94 D0 8D E2 F0 81 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule readtcp_a73d188f10bfa6514df63c4039e4cc15 {
	meta:
		aliases = "readtcp"
		size = "260"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { F0 41 2D E9 FA 3F A0 E3 08 C0 90 E5 08 D0 4D E2 00 50 A0 E1 01 80 A0 E1 0C 00 90 E5 03 10 A0 E1 02 60 A0 E1 9C 03 04 E0 ?? ?? ?? EB 00 00 56 E3 00 70 84 E0 06 40 A0 01 2E 00 00 0A 00 30 95 E5 00 30 8D E5 01 30 A0 E3 04 30 CD E5 00 30 A0 E3 05 30 CD E5 01 10 A0 E3 07 20 A0 E1 0D 00 A0 E1 ?? ?? ?? EB 01 00 70 E3 00 40 A0 E1 05 00 00 0A 00 00 50 E3 05 30 A0 03 00 40 E0 03 24 30 85 05 1C 00 00 0A 07 00 00 EA ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 EE FF FF 0A 04 30 A0 E3 24 30 85 E5 00 30 90 E5 0C 00 00 EA 08 10 A0 E1 06 20 A0 E1 00 00 95 E5 ?? ?? ?? EB 01 00 70 E3 00 40 A0 E1 07 00 00 0A 00 00 50 E3 }
	condition:
		$pattern
}

rule readunix_4c5d0bb159b91d107b9f898e6eda1e32 {
	meta:
		aliases = "readunix"
		size = "420"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { F0 41 2D E9 FA 3F A0 E3 08 C0 90 E5 34 D0 4D E2 00 50 A0 E1 01 80 A0 E1 0C 00 90 E5 03 10 A0 E1 02 60 A0 E1 9C 03 04 E0 ?? ?? ?? EB 00 00 56 E3 00 70 84 E0 06 40 A0 01 55 00 00 0A 00 30 95 E5 28 30 8D E5 01 30 A0 E3 2C 30 CD E5 00 30 A0 E3 2D 30 CD E5 01 10 A0 E3 07 20 A0 E1 28 00 8D E2 ?? ?? ?? EB 01 00 70 E3 00 40 A0 E1 05 00 00 0A 00 00 50 E3 05 30 A0 03 00 40 E0 03 84 30 85 05 43 00 00 0A 07 00 00 EA ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 EE FF FF 0A 04 30 A0 E3 84 30 85 E5 00 30 90 E5 33 00 00 EA 01 40 A0 E3 34 30 8D E2 04 40 23 E5 20 C0 8D E2 00 70 95 E5 0C C0 8D E5 D8 C0 9F E5 14 C0 8D E5 }
	condition:
		$pattern
}

rule __divdc3_24ae28dcd926b98e1233159482212289 {
	meta:
		aliases = "__divdc3"
		size = "1000"
		objfiles = "_divdc3@libgcc.a"
	strings:
		$pattern = { F0 43 2D E9 06 42 6D ED 34 60 8D E2 C0 00 96 E8 3C 80 8D E2 00 03 98 E8 C0 00 2D E9 02 81 BD EC 00 03 2D E9 02 A1 BD EC 80 91 20 EE 82 81 20 EE 10 F1 D1 EE 02 40 A0 E1 03 50 A0 E1 18 00 00 5A C0 00 2D E9 02 B1 BD EC 30 00 2D E9 02 C1 BD EC 82 01 43 EE 03 00 2D E9 02 D1 BD EC 80 11 13 EE 00 03 2D E9 02 B1 BD EC 80 21 14 EE 80 01 15 EE 81 11 03 EE 80 01 04 EE 85 21 22 EE 81 21 42 EE 81 11 40 EE 11 F1 91 EE 19 00 00 1A 02 91 2D ED 03 00 BD E8 02 A1 2D ED 0C 00 BD E8 06 42 FD EC F0 83 BD E8 00 03 2D E9 02 C1 BD EC C0 00 2D E9 02 D1 BD EC 03 00 2D E9 02 91 BD EC 85 01 44 EE 30 00 2D E9 02 B1 BD EC }
	condition:
		$pattern
}

rule __muldc3_5e2dc572bf826262ab4d9022eb016d97 {
	meta:
		aliases = "__muldc3"
		size = "1144"
		objfiles = "_muldc3@libgcc.a"
	strings:
		$pattern = { F0 43 2D E9 0C 42 2D ED 10 D0 4D E2 5C 80 8D E2 00 03 98 E8 64 60 8D E2 C0 00 96 E8 01 50 A0 E1 00 40 A0 E1 02 10 A0 E1 03 20 A0 E1 C0 00 2D E9 02 D1 BD EC 30 00 2D E9 02 81 BD EC 00 03 2D E9 02 91 BD EC 06 00 2D E9 02 A1 BD EC 81 31 10 EE 85 41 12 EE 00 03 2D E9 02 E1 BD EC 84 11 23 EE 06 00 2D E9 02 F1 BD EC 11 F1 91 EE 85 21 10 EE 87 51 16 EE 85 61 02 EE 06 00 00 1A 02 91 2D ED 03 00 BD E8 02 E1 2D ED 0C 00 BD E8 10 D0 8D E2 0C 42 BD EC F0 83 BD E8 16 F1 96 EE F6 FF FF 0A 10 F1 90 EE 80 01 20 EE 00 30 A0 13 01 30 A0 03 10 F1 90 EE 00 30 A0 03 01 30 03 12 00 00 53 E3 02 81 8D ED 42 00 00 1A }
	condition:
		$pattern
}

rule ftello64_67f007e0627c9c2dd46e310c68a97297 {
	meta:
		aliases = "__GI_ftello64, ftello64"
		size = "228"
		objfiles = "ftello64@libc.a"
	strings:
		$pattern = { F0 43 2D E9 34 60 90 E5 18 D0 4D E2 38 50 80 E2 00 80 A0 E3 00 90 A0 E3 00 00 56 E3 00 40 A0 E1 10 70 8D E2 A8 10 9F E5 05 20 A0 E1 0D 00 A0 E1 10 80 8D E5 14 90 8D E5 06 00 00 1A 94 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 88 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 20 D4 E5 01 30 D4 E5 03 24 82 E1 11 2D 02 E2 11 0D 52 E3 07 10 A0 E1 01 20 A0 13 02 20 A0 03 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 07 10 A0 E1 04 00 A0 E1 02 00 00 BA ?? ?? ?? EB 00 00 50 E3 03 00 00 AA 00 30 E0 E3 00 40 E0 E3 10 30 8D E5 14 40 8D E5 00 00 56 E3 0D 00 A0 E1 01 10 A0 E3 20 30 9F 05 0F E0 A0 01 03 F0 A0 01 10 00 8D E2 }
	condition:
		$pattern
}

rule __GI_rtime_e5ee85989ba997e2dbb256090caf24ab {
	meta:
		aliases = "rtime, __GI_rtime"
		size = "464"
		objfiles = "rtime@libc.a"
	strings:
		$pattern = { F0 45 2D E9 00 00 52 E3 01 60 A0 03 02 60 A0 13 28 D0 4D E2 02 70 A0 E1 00 40 A0 E1 01 A0 A0 E1 02 00 A0 E3 06 10 A0 E1 00 20 A0 E3 ?? ?? ?? EB 00 50 50 E2 60 00 00 BA 02 30 A0 E3 02 00 56 E3 00 30 C4 E5 00 60 A0 E3 23 30 83 E2 03 30 C4 E5 01 60 C4 E5 02 60 C4 E5 30 00 00 1A 24 80 8D E2 10 C0 A0 E3 08 10 A0 E1 04 20 A0 E3 06 30 A0 E1 10 10 8D E8 ?? ?? ?? EB 06 00 50 E1 2C 00 00 BA 00 20 97 E5 FA 3F A0 E3 04 00 97 E5 03 10 A0 E1 92 03 04 E0 ?? ?? ?? EB 01 30 A0 E3 1C 30 CD E5 1D 60 CD E5 18 50 8D E5 00 40 84 E0 01 10 A0 E3 04 20 A0 E1 18 00 8D E2 ?? ?? ?? EB 00 60 50 E2 03 00 00 AA ?? ?? ?? EB }
	condition:
		$pattern
}

rule bindresvport_6ee94b209b167950de844a0c7a55ca3f {
	meta:
		aliases = "__GI_bindresvport, bindresvport"
		size = "348"
		objfiles = "bindresvport@libc.a"
	strings:
		$pattern = { F0 45 2D E9 00 50 51 E2 10 D0 4D E2 00 A0 A0 E1 07 00 00 1A 0D 00 A0 E1 10 20 A0 E3 ?? ?? ?? EB 01 50 CD E5 02 30 A0 E3 0D 50 A0 E1 00 30 CD E5 09 00 00 EA 00 30 D5 E5 01 20 D5 E5 02 34 83 E1 02 00 53 E3 04 00 00 0A ?? ?? ?? EB 60 30 A0 E3 00 C0 E0 E3 00 30 80 E5 3A 00 00 EA F0 40 9F E5 01 30 D4 E5 00 20 D4 E5 03 3C A0 E1 43 38 92 E1 06 00 00 1A ?? ?? ?? EB 6A 1F A0 E3 ?? ?? ?? EB 96 0F 80 E2 40 34 A0 E1 01 30 C4 E5 00 00 C4 E5 ?? ?? ?? EB 00 70 A0 E3 62 30 A0 E3 00 80 A0 E1 00 C0 E0 E3 00 30 80 E5 18 00 00 EA 01 C0 D6 E5 00 30 D6 E5 0C 34 83 E1 01 C0 83 E2 03 38 A0 E1 23 E4 A0 E1 0C C8 A0 E1 }
	condition:
		$pattern
}

rule __muldi3_6d864de6618b17bae0eedde29e3a7d9b {
	meta:
		aliases = "__muldi3"
		size = "80"
		objfiles = "_muldi3@libgcc.a"
	strings:
		$pattern = { F0 45 2D E9 00 50 A0 E1 01 60 A0 E1 20 A8 A0 E1 22 18 A0 E1 0A 88 C0 E1 01 78 C2 E1 98 07 04 E0 9A 07 07 E0 91 08 08 E0 9A 01 01 E0 08 80 97 E0 01 18 81 22 08 48 94 E0 28 18 A1 E0 04 00 A0 E1 95 13 24 E0 92 46 21 E0 02 E0 A0 E1 F0 85 BD E8 }
	condition:
		$pattern
}

rule authunix_refresh_73c08ed7dd1f9f4590a95990a9fe0653 {
	meta:
		aliases = "authunix_refresh"
		size = "244"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { F0 45 2D E9 00 50 A0 E1 24 40 95 E5 04 10 95 E5 04 20 94 E5 38 D0 4D E2 00 60 A0 E3 02 00 51 E1 0D 70 A0 E1 01 30 A0 E3 18 A0 8D E2 0D 00 A0 E1 06 80 A0 E1 2B 00 00 0A 18 20 94 E5 01 20 82 E2 18 20 84 E5 1C 60 8D E5 2C 60 8D E5 06 00 94 E9 ?? ?? ?? EB 0A 10 A0 E1 0D 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 06 10 A0 E1 30 00 8D E2 06 80 A0 E1 10 00 00 0A ?? ?? ?? EB 30 30 9D E5 06 10 A0 E1 18 30 8D E5 00 60 8D E5 04 30 9D E5 0D 00 A0 E1 0F E0 A0 E1 14 F0 93 E5 0D 00 A0 E1 0A 10 A0 E1 ?? ?? ?? EB 00 80 50 E2 07 00 94 18 07 00 85 18 05 00 A0 11 AB FF FF 1B 02 30 A0 E3 18 10 8D E2 0D 00 A0 E1 00 30 8D E5 }
	condition:
		$pattern
}

rule __pthread_alt_unlock_9f3c6b6b576b3a10c8c772812a8745e7 {
	meta:
		aliases = "__pthread_alt_unlock"
		size = "200"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { F0 45 2D E9 00 60 A0 E1 04 80 80 E2 08 00 A0 E1 3D FF FF EB 00 00 96 E5 01 00 50 E3 00 30 A0 93 00 30 86 95 24 00 00 9A 00 20 A0 E1 02 A1 A0 E3 06 70 A0 E1 06 40 A0 E1 00 50 A0 E1 11 00 00 EA 08 30 92 E5 00 00 53 E3 06 00 00 0A 00 30 92 E5 00 30 84 E5 45 FF FF EB 06 00 54 E1 00 20 94 E5 08 00 00 1A 07 00 00 EA 04 30 92 E5 18 30 93 E5 0A 00 53 E1 04 70 A0 A1 02 50 A0 A1 02 40 A0 E1 00 20 92 E5 03 A0 A0 A1 01 00 52 E3 02 00 A0 E1 EA FF FF 1A 02 01 5A E3 DD FF FF 0A 08 30 85 E2 92 20 03 E1 00 00 52 E3 D9 FF FF 1A 00 30 95 E5 04 00 95 E5 00 30 87 E5 ?? ?? ?? EB 00 30 A0 E3 00 30 88 E5 F0 85 BD E8 }
	condition:
		$pattern
}

rule get_myaddress_b1bafbc9e183835717c59e7db01a30ce {
	meta:
		aliases = "get_myaddress"
		size = "340"
		objfiles = "get_myaddress@libc.a"
	strings:
		$pattern = { F0 45 2D E9 00 70 A0 E1 01 DA 4D E2 02 00 A0 E3 28 D0 4D E2 00 10 A0 E1 00 20 A0 E3 ?? ?? ?? EB 00 80 50 E2 14 01 9F B5 0D 00 00 BA 01 3A A0 E3 28 C0 8D E2 03 E0 8D E0 28 C0 4C E2 01 2A 8D E2 FC 10 9F E5 20 20 82 E2 20 30 8E E5 24 C0 8E E5 ?? ?? ?? EB 00 00 50 E3 00 A0 A0 A3 03 00 00 AA E0 00 9F E5 ?? ?? ?? EB 01 00 A0 E3 ?? ?? ?? EB 01 1A 8D E2 24 50 91 E5 20 60 91 E5 25 00 00 EA 05 40 A0 E1 0F 00 B4 E8 01 CA 8D E2 0F 00 AC E8 0F 00 94 E8 0F 00 8C E8 08 00 A0 E1 A8 10 9F E5 01 2A 8D E2 ?? ?? ?? EB 00 00 50 E3 9C 00 9F B5 EB FF FF BA 01 2A 8D E2 11 30 D2 E5 10 20 D2 E5 03 3C A0 E1 43 18 82 E1 }
	condition:
		$pattern
}

rule __get_myaddress_71c51718f9b6f329e05e277014a312c6 {
	meta:
		aliases = "__get_myaddress"
		size = "360"
		objfiles = "pmap_clnt@libc.a"
	strings:
		$pattern = { F0 45 2D E9 00 70 A0 E1 01 DA 4D E2 02 00 A0 E3 28 D0 4D E2 00 10 A0 E1 00 20 A0 E3 ?? ?? ?? EB 00 80 50 E2 28 01 9F B5 0D 00 00 BA 01 3A A0 E3 28 C0 8D E2 03 E0 8D E0 28 C0 4C E2 01 2A 8D E2 10 11 9F E5 20 20 82 E2 20 30 8E E5 24 C0 8E E5 ?? ?? ?? EB 00 00 50 E3 01 A0 A0 A3 0D 00 00 AA F4 00 9F E5 ?? ?? ?? EB 01 00 A0 E3 ?? ?? ?? EB 0F 00 94 E8 0F 00 87 E8 6F 30 A0 E3 03 30 C7 E5 00 30 A0 E3 02 30 C7 E5 08 00 A0 E1 ?? ?? ?? EB 01 00 A0 E3 2B 00 00 EA 01 1A 8D E2 24 50 91 E5 20 60 91 E5 1F 00 00 EA 05 40 A0 E1 0F 00 B4 E8 01 CA 8D E2 0F 00 AC E8 0F 00 94 E8 0F 00 8C E8 08 00 A0 E1 94 10 9F E5 }
	condition:
		$pattern
}

rule __pthread_alt_timedlock_986288f29b1539dbf975399c7f23831c {
	meta:
		aliases = "__pthread_alt_timedlock"
		size = "272"
		objfiles = "spinlock@libpthread.a"
	strings:
		$pattern = { F0 45 2D E9 00 70 A0 E1 F8 00 9F E5 02 A0 A0 E1 01 80 A0 E1 93 FF FF EB EC 20 9F E5 00 00 92 E5 00 00 50 E3 00 60 A0 11 00 30 96 15 00 60 A0 01 00 30 82 15 CC 30 9F E5 00 20 A0 E3 00 20 83 E5 02 00 56 E1 08 00 00 1A 0C 00 A0 E3 ?? ?? ?? EB 00 60 50 E2 04 00 00 1A 07 00 A0 E1 08 10 A0 E1 ?? ?? ?? EB 01 00 A0 E3 F0 85 BD E8 04 50 87 E2 05 00 A0 E1 7B FF FF EB 00 40 97 E5 00 00 54 E3 01 30 A0 03 04 20 A0 01 00 30 87 05 09 00 00 0A 00 00 58 E3 01 00 00 1A 9B FF FF EB 00 80 A0 E1 00 30 A0 E3 08 30 86 E5 00 40 86 E5 00 60 87 E5 04 80 86 E5 01 20 A0 E3 00 30 A0 E3 00 30 85 E5 03 00 52 E1 0B 00 00 0A }
	condition:
		$pattern
}

rule authunix_validate_7ed1bc07a01062274be97607b7a8f259 {
	meta:
		aliases = "authunix_validate"
		size = "148"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { F0 45 2D E9 00 A0 91 E5 18 D0 4D E2 02 00 5A E3 00 50 A0 E1 0D 80 A0 E1 01 30 A0 E3 0D 00 A0 E1 18 00 00 1A 24 40 95 E5 06 00 91 E9 ?? ?? ?? EB 10 30 94 E5 00 00 53 E2 0C 60 84 E2 02 00 00 0A ?? ?? ?? EB 00 30 A0 E3 10 30 84 E5 06 10 A0 E1 0D 00 A0 E1 ?? ?? ?? EB 00 70 50 E2 06 10 A0 E1 0D 00 A0 E1 07 00 96 18 03 00 00 1A 00 A0 8D E5 ?? ?? ?? EB 07 00 94 E8 10 70 84 E5 07 00 85 E8 05 00 A0 E1 7A FF FF EB 01 00 A0 E3 18 D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule dladdr_e533baf2cd6a9f53ca6ae6d3095efbfc {
	meta:
		aliases = "dladdr"
		size = "280"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { F0 45 2D E9 00 A0 A0 E1 01 40 A0 E1 ?? ?? ?? EB FC 30 9F E5 00 20 93 E5 00 00 A0 E3 09 00 00 EA 14 10 92 E5 0A 00 51 E1 05 00 00 2A 00 00 50 E3 02 00 00 0A 14 30 90 E5 01 00 53 E1 00 00 00 2A 02 00 A0 E1 0C 20 92 E5 00 00 52 E3 F3 FF FF 1A 00 00 50 E3 F0 85 BD 08 02 50 A0 E1 04 30 90 E5 14 20 90 E5 58 70 90 E5 54 80 90 E5 05 C0 A0 E1 05 E0 A0 E1 05 60 A0 E1 00 30 84 E5 04 20 84 E5 16 00 00 EA 2C 30 90 E5 0E 11 93 E7 0F 00 00 EA 04 20 93 E5 00 30 90 E5 02 20 83 E0 0A 00 52 E1 08 00 00 8A 02 00 56 E1 00 30 A0 23 01 30 A0 33 00 00 5C E3 01 30 83 03 00 00 53 E3 02 60 A0 11 01 C0 A0 13 01 50 A0 11 }
	condition:
		$pattern
}

rule tcsetattr_4f2dbb8696bff705a20f43bbab4d5358 {
	meta:
		aliases = "__GI_tcsetattr, tcsetattr"
		size = "300"
		objfiles = "tcsetattr@libc.a"
	strings:
		$pattern = { F0 45 2D E9 01 00 51 E3 24 D0 4D E2 00 A0 A0 E1 02 60 A0 E1 05 00 00 0A 02 00 51 E3 0A 00 00 0A 00 00 51 E3 F0 80 9F 05 08 00 00 0A 01 00 00 EA E8 80 9F E5 05 00 00 EA ?? ?? ?? EB 16 30 A0 E3 00 20 E0 E3 00 30 80 E5 30 00 00 EA D0 80 9F E5 08 50 96 E8 0C 40 96 E5 10 50 D6 E5 02 31 C3 E3 11 10 86 E2 13 20 A0 E3 11 00 8D E2 08 50 8D E8 0C 40 8D E5 10 50 CD E5 ?? ?? ?? EB 0D 20 A0 E1 0A 00 A0 E1 08 10 A0 E1 ?? ?? ?? EB 88 30 9F E5 00 00 50 E3 03 00 58 01 0D 70 A0 E1 00 20 A0 E1 1A 00 00 1A ?? ?? ?? EB 0D 20 A0 E1 00 50 A0 E1 70 10 9F E5 0A 00 A0 E1 00 40 95 E5 ?? ?? ?? EB 00 00 50 E3 00 20 A0 13 }
	condition:
		$pattern
}

rule __res_query_667ecca47840adb7c03f9783b441d264 {
	meta:
		aliases = "__GI___res_query, __res_query"
		size = "316"
		objfiles = "res_query@libc.a"
	strings:
		$pattern = { F0 45 2D E9 01 10 51 E2 01 10 A0 13 00 50 A0 E1 44 D0 4D E2 00 00 55 E3 01 C0 A0 11 01 C0 81 03 08 A0 8D E2 00 10 5C E2 02 60 A0 E1 30 70 8D E2 0A 00 A0 E1 00 40 E0 E3 03 80 A0 E1 28 20 A0 E3 02 00 00 0A ?? ?? ?? EB 03 30 A0 E3 20 00 00 EA 40 C0 8D E5 ?? ?? ?? EB ?? ?? ?? EB BC 20 9F E5 BC 10 9F E5 07 00 A0 E1 B8 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 B0 30 9F E5 A0 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 A4 30 9F E5 00 40 93 E5 07 00 A0 E1 01 10 A0 E3 98 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 04 20 A0 E1 40 C0 8D E2 05 00 A0 E1 06 10 A0 E1 80 30 9F E5 00 C0 8D E5 04 A0 8D E5 ?? ?? ?? EB 00 40 50 E2 04 00 00 AA }
	condition:
		$pattern
}

rule svc_register_58c62987b0742e44de7dd15aab728c70 {
	meta:
		aliases = "__GI_svc_register, svc_register"
		size = "164"
		objfiles = "svc@libc.a"
	strings:
		$pattern = { F0 45 2D E9 01 50 A0 E1 04 D0 4D E2 02 10 A0 E1 02 60 A0 E1 00 80 A0 E1 0D 20 A0 E1 05 00 A0 E1 03 70 A0 E1 20 A0 9D E5 2E FF FF EB 00 30 50 E2 10 00 A0 E3 03 00 00 0A 0C 30 93 E5 07 00 53 E1 13 00 00 1A 07 00 00 EA ?? ?? ?? EB 00 40 50 E2 0F 00 00 0A E0 00 84 E9 ?? ?? ?? EB B8 30 90 E5 00 30 84 E5 B8 40 80 E5 00 20 5A E2 05 00 A0 E1 06 10 A0 E1 01 30 A0 E3 06 00 00 0A 05 C0 D8 E5 04 30 D8 E5 0C 34 83 E1 ?? ?? ?? EB 00 30 A0 E1 00 00 00 EA 00 30 A0 E3 03 00 A0 E1 04 D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule fread_unlocked_8df28dcd91c0ae48f9b814bd6efe0a23 {
	meta:
		aliases = "__GI_fread_unlocked, fread_unlocked"
		size = "380"
		objfiles = "fread_unlocked@libc.a"
	strings:
		$pattern = { F0 45 2D E9 03 50 A0 E1 00 30 D3 E5 83 30 03 E2 80 00 53 E3 00 60 A0 E1 01 80 A0 E1 02 40 A0 E1 04 00 00 8A 05 00 A0 E1 80 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 4C 00 00 1A 00 00 58 E3 00 00 54 13 49 00 00 0A 00 00 E0 E3 08 10 A0 E1 ?? ?? ?? EB 00 00 54 E1 94 08 0A 90 06 70 A0 91 0A 60 A0 91 09 00 00 9A 36 00 00 EA 24 30 92 E5 01 60 56 E2 00 30 C7 E5 00 30 A0 E3 01 00 C5 E5 28 30 85 E5 00 10 C5 E5 29 00 00 0A 01 70 87 E2 01 20 D5 E5 00 30 D5 E5 02 34 83 E1 01 20 03 E2 01 10 43 E2 02 00 13 E3 02 21 85 E0 41 04 A0 E1 ED FF FF 1A 10 10 85 E2 0A 00 91 E8 01 20 53 E0 0B 00 00 0A 02 00 56 E1 06 40 A0 31 }
	condition:
		$pattern
}

rule __GI_vsnprintf_1b2afdcf5ab69f9397fd09879ffa150e {
	meta:
		aliases = "vsnprintf, __GI_vsnprintf"
		size = "176"
		objfiles = "vsnprintf@libc.a"
	strings:
		$pattern = { F0 45 2D E9 03 80 A0 E1 50 D0 4D E2 01 30 E0 E3 00 50 E0 E1 04 30 8D E5 D2 30 83 E2 00 40 A0 E1 00 A0 A0 E3 01 00 55 E1 01 50 A0 21 02 70 A0 E1 38 00 8D E2 00 30 CD E5 01 30 A0 E3 34 30 8D E5 01 A0 CD E5 02 A0 CD E5 2C A0 8D E5 ?? ?? ?? EB 05 30 84 E0 0D 00 A0 E1 07 10 A0 E1 08 20 A0 E1 18 40 8D E5 1C 30 8D E5 20 A0 8D E5 08 40 8D E5 0C 30 8D E5 10 40 8D E5 14 40 8D E5 ?? ?? ?? EB 0A 00 55 E1 0D 60 A0 E1 06 00 00 0A 10 20 9D E5 0C 30 9D E5 03 00 52 E1 01 20 42 E2 10 20 8D 05 10 30 9D E5 00 A0 C3 E5 50 D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule _wstdio_fwrite_3a3bde9b0e6be523c53a09f77c53edc7 {
	meta:
		aliases = "_wstdio_fwrite"
		size = "280"
		objfiles = "_wfwrite@libc.a"
	strings:
		$pattern = { F0 45 2D E9 04 30 92 E5 03 00 73 E3 48 D0 4D E2 02 50 A0 E1 00 80 A0 E1 01 60 A0 E1 0F 00 00 1A 10 00 92 E5 0C 30 92 E5 03 30 60 E0 43 31 A0 E1 03 00 51 E1 01 40 A0 31 03 40 A0 21 00 00 54 E3 31 00 00 0A 08 10 A0 E1 04 20 A0 E1 ?? ?? ?? EB 10 30 95 E5 04 31 83 E0 10 30 85 E5 2A 00 00 EA 00 30 D2 E5 01 20 D2 E5 02 34 83 E1 21 3D 03 E2 21 0D 53 E3 05 00 00 0A 05 00 A0 E1 02 1B A0 E3 ?? ?? ?? EB 00 00 50 E3 00 60 A0 13 1E 00 00 1A 00 70 A0 E3 44 80 8D E5 12 00 00 EA 00 C0 8D E5 ?? ?? ?? EB 00 40 A0 E1 01 30 87 E2 01 00 74 E3 0A 00 A0 E1 05 20 A0 E1 03 31 88 E0 11 00 00 0A 00 00 54 E3 01 40 84 02 }
	condition:
		$pattern
}

rule __ieee754_lgamma_r_0604f4e459c9856cb328f377279aa868 {
	meta:
		aliases = "__ieee754_lgamma_r"
		size = "2336"
		objfiles = "e_lgamma_r@libm.a"
	strings:
		$pattern = { F0 45 2D E9 0C 42 2D ED 03 00 2D E9 02 D1 BD EC 58 35 9F E5 02 61 C0 E3 03 00 56 E1 01 30 A0 E3 0C D0 4D E2 00 40 A0 E1 01 50 A0 E1 00 A0 A0 E1 02 70 A0 E1 00 30 82 E5 85 71 15 CE 33 02 00 CA 05 30 96 E1 05 80 A0 E1 70 00 00 0A 20 35 9F E5 03 00 56 E1 08 00 00 CA 00 00 50 E3 00 30 E0 B3 85 D1 10 BE 00 30 82 B5 02 D1 2D BD 03 00 BD B8 ?? ?? ?? EB 80 F1 10 EE 24 02 00 EA 00 00 50 E3 00 30 A0 A3 00 40 A0 A3 18 00 8D A9 70 00 00 AA E0 54 9F E5 05 00 56 E1 5C 00 00 CA D8 34 9F E5 02 41 C0 E3 03 00 54 E1 0A 00 00 CA ED 81 9F ED 80 01 15 EE 00 C0 A0 E3 02 81 2D ED 03 00 BD E8 00 20 A0 E3 00 30 A0 E3 }
	condition:
		$pattern
}

rule _Unwind_ForcedUnwind_Phase2_6121e28465fd9d090131720d3909ce73 {
	meta:
		aliases = "_Unwind_ForcedUnwind_Phase2"
		size = "200"
		objfiles = "unwind_sjlj@libgcc.a"
	strings:
		$pattern = { F0 45 2D E9 0C A0 90 E5 10 D0 4D E2 10 70 90 E5 00 60 A0 E1 01 50 A0 E1 0C 80 8D E2 1D 00 00 EA 05 00 54 E3 0C 00 96 E8 1A 10 A0 03 0A 10 A0 13 00 60 8D E5 A0 00 8D E9 0F E0 A0 E1 0A F0 A0 E1 00 00 50 E3 0A 10 A0 E3 01 00 A0 E3 19 00 00 1A 05 00 54 E3 18 00 00 0A 0C C0 9D E5 00 00 5C E3 09 00 00 0A 0C 00 96 E8 00 60 8D E5 04 50 8D E5 0F E0 A0 E1 0C F0 A0 E1 07 00 50 E3 00 40 A0 E1 0D 00 00 0A 08 00 50 E3 0A 00 00 1A 05 00 A0 E1 08 10 A0 E1 C9 FF FF EB 08 10 A0 E1 05 00 A0 E1 B9 FF FF EB 00 00 50 E3 05 00 50 13 00 40 A0 E1 01 00 A0 E3 D9 FF FF 0A 02 40 A0 E3 04 00 A0 E1 10 D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule pthread_cond_timedwait_1e66e92b1ed1db46c2e1ec86c9ebb185 {
	meta:
		aliases = "__GI_pthread_cond_timedwait, pthread_cond_timedwait"
		size = "516"
		objfiles = "condvar@libpthread.a"
	strings:
		$pattern = { F0 45 2D E9 0C D0 4D E2 01 60 A0 E1 00 50 A0 E1 02 A0 A0 E1 C7 FF FF EB 0C 30 96 E5 03 00 53 E3 00 00 53 13 08 00 8D E5 04 00 00 0A 08 20 9D E5 08 30 96 E5 02 00 53 E1 16 00 A0 13 6B 00 00 1A B0 31 9F E5 08 20 9D E5 04 30 8D E5 00 30 A0 E3 00 50 8D E5 B9 31 C2 E5 08 00 9D E5 0D 10 A0 E1 8C FF FF EB 05 00 A0 E1 08 10 9D E5 ?? ?? ?? EB 08 30 9D E5 42 30 D3 E5 00 00 53 E3 04 00 00 0A 08 30 9D E5 40 30 D3 E5 00 00 53 E3 01 40 A0 03 03 00 00 0A 08 10 9D E5 08 00 85 E2 48 FF FF EB 00 40 A0 E3 05 00 A0 E1 ?? ?? ?? EB 00 00 54 E3 03 00 00 0A 08 00 9D E5 00 10 A0 E3 75 FF FF EB 35 00 00 EA 06 00 A0 E1 }
	condition:
		$pattern
}

rule _dl_add_elf_hash_table_7484bbc60481dc20fc4a1909ab6dba0c {
	meta:
		aliases = "_dl_add_elf_hash_table"
		size = "288"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { F0 45 2D E9 10 51 9F E5 00 40 95 E5 00 00 54 E3 00 70 A0 E1 01 60 A0 E1 02 80 A0 E1 03 A0 A0 E1 0C 00 00 1A E8 00 A0 E3 ?? ?? ?? EB E8 20 A0 E3 00 40 A0 E1 00 10 A0 E1 00 00 85 E5 01 00 00 EA 00 30 A0 E3 01 30 C1 E4 01 20 52 E2 FB FF FF 2A 10 00 00 EA 03 40 A0 E1 0C 30 94 E5 00 00 53 E3 FB FF FF 1A E8 00 A0 E3 ?? ?? ?? EB E8 20 A0 E3 00 10 A0 E1 0C 00 84 E5 01 00 00 EA 00 30 A0 E3 01 30 C1 E4 01 20 52 E2 FB FF FF 2A 0C 30 94 E5 10 40 83 E5 03 40 A0 E1 00 50 A0 E3 0C 50 84 E5 22 50 C4 E5 23 50 C4 E5 07 00 A0 E1 ?? ?? ?? EB 10 10 98 E5 03 30 A0 E3 05 00 51 E1 01 04 84 E9 18 30 84 E5 08 00 00 0A }
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

rule _svcauth_unix_aed34a540152846ad8926c3f459ccf90 {
	meta:
		aliases = "_svcauth_unix"
		size = "588"
		objfiles = "svc_authux@libc.a"
	strings:
		$pattern = { F0 45 2D E9 18 60 90 E5 18 30 86 E2 46 2F 86 E2 04 30 86 E5 14 20 86 E5 20 80 91 E5 18 D0 4D E2 08 20 A0 E1 01 30 A0 E3 00 A0 A0 E1 01 70 A0 E1 0D 00 A0 E1 1C 10 91 E5 ?? ?? ?? EB 0D 00 A0 E1 08 10 A0 E1 04 30 9D E5 0F E0 A0 E1 18 F0 93 E5 00 00 50 E3 57 00 00 0A 00 40 A0 E1 04 10 94 E4 FF 38 01 E2 FF 2C 01 E2 23 34 A0 E1 02 24 A0 E1 01 2C 82 E1 21 3C 83 E1 02 30 83 E1 00 30 86 E5 04 10 90 E5 FF 28 01 E2 FF 3C 01 E2 22 24 A0 E1 03 34 A0 E1 01 3C 83 E1 21 2C 82 E1 03 50 82 E1 FF 00 55 E3 5D 00 00 8A 04 40 84 E2 04 10 A0 E1 05 20 A0 E1 04 00 96 E5 ?? ?? ?? EB 04 30 96 E5 00 00 A0 E3 05 00 C3 E7 }
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

rule svcudp_enablecache_00849fa5506afc22a5efd5c17fe89d08 {
	meta:
		aliases = "svcudp_enablecache"
		size = "256"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { F0 45 2D E9 30 A0 90 E5 B0 61 9A E5 00 00 56 E3 01 40 A0 E1 CC 20 9F E5 2C 00 A0 E3 C8 10 9F E5 04 00 00 0A C4 30 9F E5 00 00 93 E5 ?? ?? ?? EB 00 00 A0 E3 F0 85 BD E8 ?? ?? ?? EB 04 72 A0 E1 00 50 50 E2 A0 10 9F E5 A4 20 9F E5 07 00 A0 E1 04 00 00 1A 94 30 9F E5 00 00 93 E5 ?? ?? ?? EB 05 00 A0 E1 F0 85 BD E8 00 40 85 E5 0C 60 85 E5 ?? ?? ?? EB 00 00 50 E3 04 81 A0 E1 68 10 9F E5 00 40 A0 E1 6C 20 9F E5 04 00 85 E5 0A 00 00 0A 07 20 A0 E1 06 10 A0 E1 ?? ?? ?? EB 08 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 40 A0 E1 38 10 9F E5 44 20 9F E5 08 00 85 E5 04 00 00 1A 2C 30 9F E5 00 00 93 E5 ?? ?? ?? EB }
	condition:
		$pattern
}

rule clntraw_create_3a1acf6d0bb255cf16896bdf82d9c3b0 {
	meta:
		aliases = "clntraw_create"
		size = "264"
		objfiles = "clnt_raw@libc.a"
	strings:
		$pattern = { F0 45 2D E9 30 D0 4D E2 00 70 A0 E1 01 80 A0 E1 ?? ?? ?? EB A0 60 90 E5 00 00 56 E3 00 40 A0 E1 06 50 A0 11 06 00 00 1A 01 00 A0 E3 C0 10 9F E5 ?? ?? ?? EB 00 50 50 E2 06 40 A0 01 29 00 00 0A A0 50 84 E5 00 C0 A0 E3 0C 40 86 E2 8A 1D 85 E2 04 10 81 E2 0C 30 A0 E1 18 20 A0 E3 04 00 A0 E1 02 A0 A0 E3 04 C0 8D E5 0C 70 8D E5 10 80 8D E5 08 A0 8D E5 ?? ?? ?? EB 04 00 A0 E1 0D 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 68 00 9F 05 ?? ?? ?? 0B 04 30 94 E5 04 00 A0 E1 0F E0 A0 E1 10 F0 93 E5 54 30 9F E5 03 00 85 E7 04 30 94 E5 1C 30 93 E5 00 00 53 E3 04 00 A0 11 0F E0 A0 11 03 F0 A0 11 04 00 A0 E1 24 10 85 E2 }
	condition:
		$pattern
}

rule __GI_fread_a50d1194eb339694f9cf9dcc3881b23c {
	meta:
		aliases = "fread, fwrite, __GI_fwrite, __GI_fread"
		size = "156"
		objfiles = "fread@libc.a, fwrite@libc.a"
	strings:
		$pattern = { F0 45 2D E9 34 80 93 E5 10 D0 4D E2 38 50 83 E2 00 00 58 E3 00 A0 A0 E1 01 70 A0 E1 02 60 A0 E1 03 40 A0 E1 0D 00 A0 E1 5C 10 9F E5 05 20 A0 E1 06 00 00 1A 54 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 48 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 07 10 A0 E1 04 30 A0 E1 06 20 A0 E1 0A 00 A0 E1 ?? ?? ?? EB 00 00 58 E3 00 40 A0 E1 01 10 A0 E3 0D 00 A0 E1 1C 30 9F 05 0F E0 A0 01 03 F0 A0 01 04 00 A0 E1 10 D0 8D E2 F0 85 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_setvbuf_6056c8e4fa5afa090b3b5e1cc2f74a99 {
	meta:
		aliases = "setvbuf, __GI_setvbuf"
		size = "420"
		objfiles = "setvbuf@libc.a"
	strings:
		$pattern = { F0 45 2D E9 34 A0 90 E5 00 00 5A E3 10 D0 4D E2 00 50 A0 E1 01 60 A0 E1 02 70 A0 E1 03 80 A0 E1 0A 00 00 1A 38 40 80 E2 60 31 9F E5 0D 00 A0 E1 5C 11 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 4C 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 02 00 57 E3 04 00 00 9A ?? ?? ?? EB 00 40 E0 E3 16 30 A0 E3 00 30 80 E5 3F 00 00 EA 00 20 D5 E5 01 30 D5 E5 20 01 9F E5 03 24 82 E1 00 00 02 E0 00 00 50 E3 00 40 E0 13 37 00 00 1A 03 2C C2 E3 42 34 A0 E1 00 20 C5 E5 01 30 C5 E5 00 30 95 E5 00 00 58 E3 02 00 57 13 07 34 83 E1 00 60 A0 01 43 24 A0 E1 00 10 A0 13 01 10 A0 03 01 20 C5 E5 00 30 C5 E5 06 80 A0 01 }
	condition:
		$pattern
}

rule __GI_pmap_set_574d4e76ac94030f8e9eba4c2becbe91 {
	meta:
		aliases = "pmap_set, __GI_pmap_set"
		size = "276"
		objfiles = "pmap_clnt@libc.a"
	strings:
		$pattern = { F0 45 2D E9 38 D0 4D E2 20 40 8D E2 03 38 A0 E1 00 C0 E0 E3 00 A0 A0 E1 04 00 A0 E1 01 60 A0 E1 02 70 A0 E1 23 88 A0 E1 34 C0 8D E5 5E FF FF EB 00 00 50 E3 C0 30 9F E5 19 5E A0 E3 BC 10 9F E5 02 20 A0 E3 04 00 A0 E1 28 00 00 0A 04 E0 93 E5 34 C0 8D E2 00 30 93 E5 0C 50 8D E5 08 50 8D E5 04 C0 8D E5 00 E0 8D E5 ?? ?? ?? EB 00 50 50 E2 01 10 A0 E3 88 20 9F E5 10 30 8D E2 1B 00 00 0A 14 60 8D E5 18 70 8D E5 10 A0 8D E5 1C 80 8D E5 70 C0 9F E5 04 40 95 E5 00 C0 8D E5 30 C0 8D E2 04 C0 8D E5 60 C0 9F E5 C0 00 9C E8 08 60 8D E5 0C 70 8D E5 0F E0 A0 E1 00 F0 94 E5 00 00 50 E3 48 10 9F E5 05 00 A0 E1 }
	condition:
		$pattern
}

rule __form_query_a4ddaa6fcb3d363dcba5226306495348 {
	meta:
		aliases = "__form_query"
		size = "132"
		objfiles = "formquery@libc.a"
	strings:
		$pattern = { F0 45 2D E9 3C D0 4D E2 58 A0 9D E5 03 80 A0 E1 00 50 A0 E1 01 60 A0 E1 02 70 A0 E1 00 10 A0 E3 30 20 A0 E3 0D 00 A0 E1 ?? ?? ?? EB 01 30 A0 E3 08 10 A0 E1 0A 20 A0 E1 0D 00 A0 E1 00 50 8D E5 30 60 8D E5 34 70 8D E5 38 30 8D E5 20 30 8D E5 ?? ?? ?? EB 00 40 50 E2 04 10 88 E0 0A 20 64 E0 30 00 8D E2 03 00 00 BA ?? ?? ?? EB 00 00 50 E3 00 40 A0 B1 00 40 84 A0 04 00 A0 E1 3C D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule pmap_rmtcall_562bfcdcbbda90b4785b47773a4539ef {
	meta:
		aliases = "pmap_rmtcall"
		size = "264"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { F0 45 2D E9 3C D0 4D E2 E8 40 9F E5 3C E0 8D E2 00 C0 E0 E3 04 C0 2E E5 01 C0 8C E2 04 50 94 E5 02 C0 C0 E5 6F C0 8C E2 03 C0 C0 E5 01 70 A0 E1 02 80 A0 E1 C0 10 9F E5 02 20 A0 E3 03 A0 A0 E1 00 30 94 E5 00 50 8D E5 00 60 A0 E1 04 E0 8D E5 ?? ?? ?? EB 00 50 50 E2 05 10 A0 E3 9C 20 9F E5 10 30 8D E2 10 40 A0 E3 1C 00 00 0A 5C C0 9D E5 20 C0 8D E5 58 C0 9D E5 24 C0 8D E5 70 C0 9D E5 28 C0 8D E5 64 C0 9D E5 30 C0 8D E5 60 C0 9D E5 10 70 8D E5 14 80 8D E5 34 C0 8D E5 18 A0 8D E5 5C C0 9F E5 68 70 8D E2 80 01 97 E8 04 40 95 E5 00 C0 8D E5 28 C0 8D E2 04 C0 8D E5 08 70 8D E5 0C 80 8D E5 0F E0 A0 E1 }
	condition:
		$pattern
}

rule _Unwind_Find_FDE_4a372b956600653709d8ba3d155c83a7 {
	meta:
		aliases = "_Unwind_Find_FDE"
		size = "352"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { F0 45 2D E9 4C A1 9F E5 00 50 9A E5 00 00 55 E3 04 D0 4D E2 00 40 A0 E1 01 70 A0 E1 03 00 00 1A 23 00 00 EA 14 50 95 E5 00 00 55 E3 20 00 00 0A 00 30 95 E5 03 00 54 E1 F9 FF FF 3A 05 00 A0 E1 04 10 A0 E1 B5 FF FF EB 00 60 50 E2 18 00 00 0A 04 30 95 E5 00 30 87 E5 08 20 95 E5 04 20 87 E5 10 10 D5 E5 11 30 D5 E5 03 34 81 E1 A3 31 A0 E1 04 00 11 E3 FF 00 03 E2 33 00 00 1A FF 40 00 E2 05 10 A0 E1 04 00 A0 E1 92 FC FF EB 0D 30 A0 E1 00 10 A0 E1 08 20 86 E2 04 00 A0 E1 A3 FC FF EB 00 30 9D E5 08 30 87 E5 06 00 A0 E1 04 D0 8D E2 F0 85 BD E8 A0 80 9F E5 00 60 A0 E3 00 50 98 E5 00 00 55 E3 F7 FF FF 0A }
	condition:
		$pattern
}

rule pthread_sighandler_bf564bdb0d73f8625ce76e98f9d526a1 {
	meta:
		aliases = "pthread_sighandler"
		size = "132"
		objfiles = "signals@libpthread.a"
	strings:
		$pattern = { F0 45 2D E9 58 D0 4D E2 00 60 A0 E1 01 70 A0 E1 02 80 A0 E1 03 A0 A0 E1 C0 FF FF EB 58 30 D0 E5 00 00 53 E3 00 50 A0 E1 00 30 A0 13 0D 00 A0 E1 74 10 8D E2 58 20 A0 E3 20 60 85 15 58 30 C5 15 0C 00 00 1A 54 40 95 E5 00 00 54 E3 54 D0 85 05 ?? ?? ?? EB 06 00 A0 E1 07 10 A0 E1 08 20 A0 E1 0A 30 A0 E1 14 C0 9F E5 0F E0 A0 E1 06 F1 9C E7 00 00 54 E3 54 40 85 05 58 D0 8D E2 F0 85 BD E8 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_ioperm_c004d2c6f79662c5c1c5f14fcff18a69 {
	meta:
		aliases = "ioperm, __GI_ioperm"
		size = "680"
		objfiles = "ioperm@libc.a"
	strings:
		$pattern = { F0 45 2D E9 64 52 9F E5 0C C0 95 E5 00 00 5C E3 43 DF 4D E2 00 70 A0 E1 01 80 A0 E1 02 A0 A0 E1 68 00 00 1A 04 30 A0 E3 43 4F 8D E2 04 30 24 E5 03 20 85 E0 38 02 9F E5 03 10 A0 E3 04 30 A0 E1 04 C0 8D E5 00 C0 8D E5 ?? ?? ?? EB 00 C0 50 E2 0A 00 00 1A 04 30 A0 E1 18 02 9F E5 03 10 A0 E3 08 20 85 E2 04 C0 8D E5 00 C0 8D E5 ?? ?? ?? EB 00 00 50 E3 01 30 A0 03 0C 30 85 05 51 00 00 0A 08 40 8D E2 F0 01 9F E5 04 10 A0 E1 FF 20 A0 E3 ?? ?? ?? EB 00 00 50 E3 14 00 00 DA 43 3F 8D E2 00 20 83 E0 00 30 A0 E3 04 31 42 E5 CC 31 9F E5 00 20 93 E5 08 30 DD E5 83 30 D2 E7 08 00 13 E3 2E 00 00 0A B8 21 9F E5 }
	condition:
		$pattern
}

rule getrpcent_r_8886f6b4f85f6dd3684aad93c3949065 {
	meta:
		aliases = "getrpcent_r"
		size = "152"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { F0 45 2D E9 78 40 9F E5 14 D0 4D E2 04 A0 8D E2 00 60 A0 E1 01 70 A0 E1 02 80 A0 E1 64 10 9F E5 04 20 A0 E1 0A 00 A0 E1 03 50 A0 E1 58 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 50 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 ?? ?? ?? EB 06 10 A0 E1 07 20 A0 E1 08 30 A0 E1 00 50 8D E5 20 FF FF EB 01 10 A0 E3 00 40 A0 E1 24 30 9F E5 0A 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 14 D0 8D E2 F0 85 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getrpcbynumber_r_1bafd7f82454d0f17a41189df80cb1bf {
	meta:
		aliases = "getrpcbynumber_r"
		size = "160"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { F0 45 2D E9 80 40 9F E5 14 D0 4D E2 04 A0 8D E2 00 60 A0 E1 01 70 A0 E1 02 80 A0 E1 6C 10 9F E5 04 20 A0 E1 0A 00 A0 E1 03 50 A0 E1 60 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 58 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 06 00 A0 E1 ?? ?? ?? EB 30 C0 9D E5 07 10 A0 E1 08 20 A0 E1 05 30 A0 E1 00 C0 8D E5 7B FE FF EB 01 10 A0 E3 00 40 A0 E1 24 30 9F E5 0A 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 14 D0 8D E2 F0 85 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getrpcbyname_r_b9c72f6c691a39d1f149a3e41c6733c9 {
	meta:
		aliases = "getrpcbyname_r"
		size = "160"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { F0 45 2D E9 80 40 9F E5 14 D0 4D E2 04 A0 8D E2 00 60 A0 E1 01 70 A0 E1 02 80 A0 E1 6C 10 9F E5 04 20 A0 E1 0A 00 A0 E1 03 50 A0 E1 60 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 58 30 9F E5 04 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 06 00 A0 E1 ?? ?? ?? EB 30 C0 9D E5 07 10 A0 E1 08 20 A0 E1 05 30 A0 E1 00 C0 8D E5 B5 FE FF EB 01 10 A0 E3 00 40 A0 E1 24 30 9F E5 0A 00 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 14 D0 8D E2 F0 85 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
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

rule pthread_initialize_f4a6a0afd511cc9edab7b88997c79ece {
	meta:
		aliases = "pthread_initialize"
		size = "456"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { F0 45 2D E9 88 21 9F E5 00 40 92 E5 00 00 54 E3 45 DF 4D E2 5C 00 00 1A 01 35 4D E2 A3 3A A0 E1 83 3A A0 E1 00 30 82 E5 ?? ?? ?? EB 64 31 9F E5 64 21 9F E5 00 50 93 E5 60 31 9F E5 4C 30 82 E5 5C 31 9F E5 00 40 83 E5 58 31 9F E5 14 00 82 E5 44 30 82 E5 04 00 00 EA 34 30 95 E5 01 00 53 E3 00 30 A0 13 34 30 85 15 20 50 95 E5 00 00 55 E3 F8 FF FF 1A 43 4F 8D E2 04 10 A0 E1 03 00 A0 E3 ?? ?? ?? EB ?? ?? ?? EB 80 00 A0 E1 0C 31 9D E5 02 26 60 E2 02 00 53 E1 04 10 A0 81 03 00 A0 83 0C 21 8D 85 ?? ?? ?? 8B FC 30 9F E5 04 40 8D E2 04 00 A0 E1 00 30 8D E5 0D 60 A0 E1 ?? ?? ?? EB E8 70 9F E5 05 20 A0 E1 }
	condition:
		$pattern
}

rule getprotoent_r_d7f6052a2c2f9aa1b7f5e3c9d63e4fae {
	meta:
		aliases = "__GI_getprotoent_r, getprotoent_r"
		size = "548"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { F0 45 2D E9 8B 00 52 E3 03 A0 A0 E1 00 30 A0 E3 10 D0 4D E2 02 40 A0 E1 00 30 8A E5 00 80 A0 E1 01 70 A0 E1 04 00 00 8A ?? ?? ?? EB 22 30 A0 E3 03 40 A0 E1 00 30 80 E5 6C 00 00 EA 0D 00 A0 E1 B4 11 9F E5 B4 21 9F E5 B4 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 AC 31 9F E5 A0 01 9F E5 0F E0 A0 E1 03 F0 A0 E1 8C 30 44 E2 01 0A 53 E3 8C 60 87 E2 04 00 00 8A ?? ?? ?? EB 22 30 A0 E3 03 40 A0 E1 00 30 80 E5 54 00 00 EA 7C 41 9F E5 00 30 94 E5 00 00 53 E3 0A 00 00 1A 70 01 9F E5 70 11 9F E5 ?? ?? ?? EB 00 00 50 E3 00 00 84 E5 04 00 00 1A ?? ?? ?? EB 00 40 90 E5 47 00 00 EA 02 40 A0 E3 45 00 00 EA 40 31 9F E5 }
	condition:
		$pattern
}

rule __libc_pselect_debd8f6bdbcc752ff50d3c043e31a85a {
	meta:
		aliases = "pselect, __libc_pselect"
		size = "156"
		objfiles = "pselect@libc.a"
	strings:
		$pattern = { F0 45 2D E9 8C D0 4D E2 A8 40 9D E5 00 00 54 E3 01 80 A0 E1 00 A0 A0 E1 FA 1F A0 E3 02 60 A0 E1 03 70 A0 E1 AC 50 9D E5 04 00 00 0A 00 30 94 E5 04 00 94 E5 84 30 8D E5 ?? ?? ?? EB 88 00 8D E5 00 00 55 E3 05 10 A0 E1 04 20 8D E2 02 00 A0 E3 ?? ?? ?? 1B 00 00 54 E3 84 C0 8D E2 08 10 A0 E1 04 C0 A0 01 06 20 A0 E1 07 30 A0 E1 0A 00 A0 E1 00 C0 8D E5 ?? ?? ?? EB 00 00 55 E3 00 40 A0 E1 04 10 8D E2 02 00 A0 E3 00 20 A0 E3 ?? ?? ?? 1B 04 00 A0 E1 8C D0 8D E2 F0 85 BD E8 }
	condition:
		$pattern
}

rule __open_nameservers_82f550179e4ec694fe5ee2ca3574fd09 {
	meta:
		aliases = "__open_nameservers"
		size = "724"
		objfiles = "opennameservers@libc.a"
	strings:
		$pattern = { F0 45 2D E9 A4 D0 4D E2 94 00 8D E2 80 12 9F E5 80 22 9F E5 80 32 9F E5 0F E0 A0 E1 03 F0 A0 E1 78 32 9F E5 6C 02 9F E5 0F E0 A0 E1 03 F0 A0 E1 6C 32 9F E5 00 30 93 E5 00 00 53 E3 8D 00 00 CA 60 02 9F E5 60 12 9F E5 ?? ?? ?? EB 00 A0 50 E2 7A 00 00 1A 54 02 9F E5 4C 12 9F E5 ?? ?? ?? EB 00 A0 50 E2 75 00 00 1A 7F 00 00 EA 01 00 80 E2 00 20 D0 E5 00 00 52 E3 04 00 00 0A 30 32 9F E5 00 30 93 E5 82 30 D3 E7 20 00 13 E3 F6 FF FF 1A 0A 00 52 E3 00 00 52 13 00 30 A0 13 01 30 A0 03 66 00 00 0A 23 00 52 E3 03 80 A0 11 1D 00 00 1A 62 00 00 EA A4 20 8D E2 08 31 82 E0 24 00 03 E5 00 00 00 EA 01 00 80 E2 }
	condition:
		$pattern
}

rule lckpwdf_55fa908697cafae22bf1ccf7d5f096f3 {
	meta:
		aliases = "lckpwdf"
		size = "472"
		objfiles = "lckpwdf@libc.a"
	strings:
		$pattern = { F0 45 2D E9 AC 61 9F E5 00 70 96 E5 01 00 77 E3 8E DF 4D E2 00 00 E0 13 64 00 00 1A 98 11 9F E5 98 21 9F E5 86 0F 8D E2 94 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 8C 31 9F E5 80 01 9F E5 0F E0 A0 E1 03 F0 A0 E1 80 01 9F E5 01 10 A0 E3 ?? ?? ?? EB 01 00 70 E3 00 00 86 E5 4E 00 00 0A 01 10 A0 E3 00 20 A0 E3 ?? ?? ?? EB 01 00 70 E3 46 00 00 0A 01 20 80 E3 02 10 A0 E3 00 00 96 E5 ?? ?? ?? EB 00 00 50 E3 40 00 00 BA 00 10 A0 E3 8C 20 A0 E3 0D 00 A0 E1 ?? ?? ?? EB 30 31 9F E5 04 00 8D E2 8C 80 8D E2 00 30 8D E5 00 50 A0 E3 ?? ?? ?? EB 0D 10 A0 E1 0E 00 A0 E3 08 20 A0 E1 84 50 8D E5 ?? ?? ?? EB 05 00 50 E1 }
	condition:
		$pattern
}

rule fflush_unlocked_41b7218c0d5958a6b4663388f92635c5 {
	meta:
		aliases = "__GI_fflush_unlocked, fflush_unlocked"
		size = "484"
		objfiles = "fflush_unlocked@libc.a"
	strings:
		$pattern = { F0 45 2D E9 B4 31 9F E5 03 00 50 E1 00 80 A0 E1 00 80 A0 03 10 D0 4D E2 08 A0 A0 01 02 00 00 0A 00 00 58 E3 01 AC A0 E3 52 00 00 1A 90 21 9F E5 90 11 9F E5 90 61 9F E5 0D 00 A0 E1 0F E0 A0 E1 06 F0 A0 E1 84 71 9F E5 74 01 9F E5 0F E0 A0 E1 07 F0 A0 E1 78 21 9F E5 00 30 92 E5 01 30 83 E2 00 30 82 E5 6C 51 9F E5 01 10 A0 E3 0D 00 A0 E1 0F E0 A0 E1 05 F0 A0 E1 48 11 9F E5 58 21 9F E5 0D 00 A0 E1 0F E0 A0 E1 06 F0 A0 E1 48 01 9F E5 0F E0 A0 E1 07 F0 A0 E1 20 31 9F E5 0D 00 A0 E1 01 10 A0 E3 00 60 93 E5 0F E0 A0 E1 05 F0 A0 E1 0D 40 A0 E1 08 50 A0 E1 2A 00 00 EA 00 30 D6 E5 40 00 13 E3 26 00 00 0A }
	condition:
		$pattern
}

rule getdelim_0efd3a826bef5732f6a1ad945c1b9cbb {
	meta:
		aliases = "__GI_getdelim, getdelim"
		size = "316"
		objfiles = "getdelim@libc.a"
	strings:
		$pattern = { F0 47 2D E9 00 00 51 E3 00 00 50 13 10 D0 4D E2 00 80 A0 E1 01 60 A0 E1 02 90 A0 E1 03 50 A0 E1 01 00 00 0A 00 00 53 E3 06 00 00 1A ?? ?? ?? EB 00 50 E0 E3 16 30 A0 E3 00 30 80 E5 37 00 00 EA 00 50 E0 E3 2F 00 00 EA 34 A0 93 E5 00 00 5A E3 0A 00 00 1A 38 40 83 E2 0D 00 A0 E1 C8 30 9F E5 C8 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 B8 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 40 98 E5 00 00 54 E3 00 40 86 05 01 70 A0 E3 00 30 96 E5 03 00 57 E1 04 00 A0 E1 40 10 83 E2 06 00 00 3A ?? ?? ?? EB 00 40 50 E2 E3 FF FF 0A 00 30 96 E5 40 30 83 E2 00 30 86 E5 00 40 88 E5 10 20 95 E5 18 30 95 E5 }
	condition:
		$pattern
}

rule add_fdes_5a58a6f1392b4874aec20aa0fa5c0465 {
	meta:
		aliases = "add_fdes"
		size = "288"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { F0 47 2D E9 00 60 A0 E1 10 30 D0 E5 11 00 D0 E5 00 34 83 E1 A3 31 A0 E1 FF 70 03 E2 04 D0 4D E2 01 A0 A0 E1 07 00 A0 E1 06 10 A0 E1 02 50 A0 E1 2F FE FF EB 00 90 A0 E3 00 80 A0 E1 0A 00 00 EA 00 00 57 E3 21 00 00 1A 08 30 95 E5 00 00 53 E3 02 00 00 0A 0A 00 A0 E1 05 10 A0 E1 21 FD FF EB 05 00 A0 E1 D5 FC FF EB 00 50 A0 E1 06 00 A0 E1 05 10 A0 E1 D5 FC FF EB 00 00 50 E3 25 00 00 1A 04 30 95 E5 00 00 53 E3 F4 FF FF 0A 10 30 D6 E5 04 00 13 E3 E9 FF FF 0A 05 00 A0 E1 C3 FC FF EB 00 00 59 E1 00 40 A0 E1 E4 FF FF 0A DB FE FF EB 06 10 A0 E1 00 70 A0 E1 FF 00 00 E2 0C FE FF EB 00 00 57 E3 00 80 A0 E1 }
	condition:
		$pattern
}

rule linear_search_fdes_b1b336232ab371427003a0c989330bf7 {
	meta:
		aliases = "linear_search_fdes"
		size = "348"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { F0 47 2D E9 00 60 A0 E1 10 30 D0 E5 11 00 D0 E5 00 34 83 E1 A3 31 A0 E1 FF 70 03 E2 08 D0 4D E2 01 50 A0 E1 07 00 A0 E1 06 10 A0 E1 02 A0 A0 E1 86 FE FF EB 00 90 A0 E3 00 80 A0 E1 0E 00 00 EA 00 00 57 E3 25 00 00 1A 08 10 95 E5 04 10 8D E5 0C 30 95 E5 00 00 51 E3 00 30 8D E5 03 00 00 0A 00 30 9D E5 0A 20 61 E0 03 00 52 E1 35 00 00 3A 05 00 A0 E1 28 FD FF EB 00 50 A0 E1 06 00 A0 E1 05 10 A0 E1 28 FD FF EB 00 00 50 E3 30 00 00 1A 04 30 95 E5 00 00 53 E3 F4 FF FF 0A 10 30 D6 E5 04 00 13 E3 E5 FF FF 0A 05 00 A0 E1 16 FD FF EB 00 00 59 E1 00 40 A0 E1 E0 FF FF 0A 2E FF FF EB 06 10 A0 E1 00 70 A0 E1 }
	condition:
		$pattern
}

rule clnttcp_create_99bf99a12ce4fa51c0fc874f50173d93 {
	meta:
		aliases = "__GI_clnttcp_create, clnttcp_create"
		size = "604"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { F0 47 2D E9 00 60 A0 E1 38 D0 4D E2 0C 00 A0 E3 01 A0 A0 E1 02 90 A0 E1 03 70 A0 E1 ?? ?? ?? EB 00 80 A0 E1 64 00 A0 E3 ?? ?? ?? EB 00 00 50 E3 00 00 58 13 00 50 A0 E1 09 00 00 1A ?? ?? ?? EB 00 32 9F E5 00 40 A0 E1 00 10 93 E5 F8 01 9F E5 ?? ?? ?? EB 0C 30 A0 E3 08 30 84 E5 00 30 84 E5 70 00 00 EA 02 20 D6 E5 03 30 D6 E5 03 34 92 E1 13 00 00 1A 06 00 A0 E1 0A 10 A0 E1 09 20 A0 E1 06 30 A0 E3 ?? ?? ?? EB 00 40 50 E2 05 00 00 1A 05 00 A0 E1 ?? ?? ?? EB 08 00 A0 E1 ?? ?? ?? EB 04 80 A0 E1 64 00 00 EA 24 34 A0 E1 FF 20 04 E2 FF 30 03 E2 02 34 83 E1 43 24 A0 E1 03 20 C6 E5 02 30 C6 E5 00 30 97 E5 }
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

rule __md5_crypt_2cea0fa99ea71d144a1f2cecf870bd48 {
	meta:
		aliases = "__md5_crypt"
		size = "704"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { F0 47 2D E9 01 40 A0 E1 C4 D0 4D E2 00 80 A0 E1 9C 12 9F E5 04 00 A0 E1 03 20 A0 E3 ?? ?? ?? EB 00 00 50 E3 04 70 A0 11 03 70 84 02 07 50 A0 E1 00 00 00 EA 01 50 85 E2 00 30 D5 E5 00 00 53 E3 24 00 53 13 08 20 87 E2 01 00 00 0A 02 00 55 E1 F7 FF FF 3A 58 40 8D E2 04 00 A0 E1 11 FF FF EB 08 00 A0 E1 ?? ?? ?? EB 00 60 A0 E1 08 10 A0 E1 04 00 A0 E1 06 20 A0 E1 8F FF FF EB 05 A0 67 E0 04 00 A0 E1 28 12 9F E5 03 20 A0 E3 8A FF FF EB 04 00 A0 E1 07 10 A0 E1 0A 20 A0 E1 86 FF FF EB 0D 00 A0 E1 FF FE FF EB 0D 00 A0 E1 08 10 A0 E1 06 20 A0 E1 80 FF FF EB 0D 00 A0 E1 07 10 A0 E1 0A 20 A0 E1 7C FF FF EB }
	condition:
		$pattern
}

rule __getgrouplist_internal_11fbb13d5db5bdbbcf4c1f07eb3c4db7 {
	meta:
		aliases = "__getgrouplist_internal"
		size = "252"
		objfiles = "__getgrouplist_internal@libc.a"
	strings:
		$pattern = { F0 47 2D E9 01 40 A0 E3 45 DF 4D E2 00 90 A0 E1 00 40 82 E5 20 00 A0 E3 02 A0 A0 E1 01 80 A0 E1 ?? ?? ?? EB 00 50 50 E2 2D 00 00 0A 00 80 85 E5 B8 00 9F E5 B8 10 9F E5 ?? ?? ?? EB 00 60 50 E2 04 70 A0 11 34 40 86 15 1A 00 00 1A 24 00 00 EA 0C 31 9D E5 08 00 53 E1 10 41 9D 15 10 00 00 1A 14 00 00 EA ?? ?? ?? EB 00 00 50 E3 0C 00 00 1A 07 00 17 E3 06 00 00 1A 07 11 A0 E1 20 10 81 E2 05 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 11 00 00 0A 00 50 A0 E1 0C 31 9D E5 07 31 85 E7 01 70 87 E2 04 00 00 EA 00 30 94 E5 00 00 53 E2 09 10 A0 E1 04 40 84 E2 EA FF FF 1A 38 00 9F E5 41 1F 8D E2 04 20 8D E2 01 3C A0 E3 }
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

rule __decode_answer_42a1df9228a4c068cc7287b3ef2b19cb {
	meta:
		aliases = "__decode_answer"
		size = "220"
		objfiles = "decodea@libc.a"
	strings:
		$pattern = { F0 47 2D E9 01 DC 4D E2 02 50 A0 E1 03 60 A0 E1 0D 20 A0 E1 01 3C A0 E3 01 40 A0 E1 00 A0 A0 E1 ?? ?? ?? EB 00 70 50 E2 07 80 84 E0 0D 90 A0 E1 05 50 68 E0 25 00 00 BA 0A 50 55 E2 0D 00 A0 E1 08 40 8A E0 05 70 A0 41 20 00 00 4A ?? ?? ?? EB 00 00 86 E5 08 20 DA E7 01 30 D4 E5 02 34 83 E1 04 30 86 E5 02 10 84 E2 02 20 D4 E5 01 30 D1 E5 02 34 83 E1 08 30 86 E5 02 20 81 E2 01 30 D2 E5 02 00 D1 E5 03 C0 D2 E5 03 38 A0 E1 02 20 D2 E5 00 3C 83 E1 0C 30 83 E1 02 34 83 E1 0C 30 86 E5 06 20 D1 E5 09 30 D4 E5 0A 00 84 E2 02 34 83 E1 0A 20 88 E2 03 00 55 E1 0A 10 83 E2 18 20 86 E5 14 00 86 E5 10 30 86 E5 }
	condition:
		$pattern
}

rule inet_ntop_1cc2832af1b2b175c9f9f3d43b4d8822 {
	meta:
		aliases = "__GI_inet_ntop, inet_ntop"
		size = "608"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { F0 47 2D E9 02 00 50 E3 50 D0 4D E2 01 80 A0 E1 02 90 A0 E1 03 A0 A0 E1 02 00 00 0A 0A 00 50 E3 85 00 00 1A 04 00 00 EA 01 00 A0 E1 02 10 A0 E1 03 20 A0 E1 98 FF FF EB 7D 00 00 EA 00 10 A0 E3 30 00 8D E2 20 20 A0 E3 ?? ?? ?? EB 00 10 A0 E3 04 00 00 EA 01 30 D2 E5 01 20 D8 E7 02 34 83 E1 20 30 00 E5 02 10 81 E2 A1 3F 81 E0 C3 30 A0 E1 50 C0 8D E2 0F 00 51 E3 01 20 88 E0 03 01 8C E0 F3 FF FF DA 00 60 E0 E3 00 10 A0 E3 06 20 A0 E1 13 00 00 EA 50 00 8D E2 01 31 80 E0 20 30 13 E5 00 00 53 E3 04 00 00 1A 01 00 72 E3 01 20 A0 01 01 40 A0 03 01 40 84 12 08 00 00 EA 01 00 72 E3 06 00 00 0A 01 00 76 E3 }
	condition:
		$pattern
}

rule __strtofpmax_5c710e5ed4bc9e5bfe0bdf9c2a2086ac {
	meta:
		aliases = "__strtofpmax"
		size = "652"
		objfiles = "__strtofpmax@libc.a"
	strings:
		$pattern = { F0 47 2D E9 03 C2 2D ED 00 A0 A0 E1 01 90 A0 E1 02 50 A0 E1 00 40 A0 E1 00 00 00 EA 01 40 84 E2 58 32 9F E5 00 10 D4 E5 00 60 93 E5 81 30 D6 E7 20 30 13 E2 F8 FF FF 1A 2B 00 51 E3 04 00 00 0A 2D 00 51 E3 03 80 A0 11 01 80 A0 03 01 00 00 0A 01 00 00 EA 03 80 A0 E1 01 40 84 E2 88 C1 00 EE 00 00 A0 E3 00 20 E0 E3 0C 00 00 EA 00 00 52 E3 01 20 82 B2 00 00 52 E3 01 40 84 E2 01 00 00 1A 30 00 51 E3 05 00 00 0A 01 20 82 E2 11 00 52 E3 30 30 41 E2 90 31 01 DE 8F 01 14 DE 81 41 00 DE 00 10 D4 E5 81 30 D6 E7 08 00 13 E3 EE FF FF 1A 2E 00 51 E3 00 00 50 03 01 40 84 02 04 00 A0 01 F6 FF FF 0A 00 00 52 E3 }
	condition:
		$pattern
}

rule __wcstofpmax_4a7e7609e4985d588019a3c85e1fac1e {
	meta:
		aliases = "__wcstofpmax"
		size = "656"
		objfiles = "__wcstofpmax@libc.a"
	strings:
		$pattern = { F0 47 2D E9 03 C2 2D ED 00 A0 A0 E1 01 90 A0 E1 02 50 A0 E1 00 40 A0 E1 00 00 00 EA 04 40 84 E2 00 00 94 E5 ?? ?? ?? EB 00 00 50 E3 FA FF FF 1A 00 30 94 E5 2B 00 53 E3 04 00 00 0A 2D 00 53 E3 00 80 A0 11 01 80 A0 03 01 00 00 0A 01 00 00 EA 00 80 A0 E1 04 40 84 E2 88 C1 00 EE 00 00 A0 E3 00 20 E0 E3 0C 00 00 EA 00 00 52 E3 01 20 82 B2 00 00 52 E3 04 40 84 E2 01 00 00 1A 30 00 51 E3 05 00 00 0A 01 20 82 E2 11 00 52 E3 30 30 41 E2 90 31 01 DE 8F 01 14 DE 81 41 00 DE E0 31 9F E5 00 10 94 E5 00 60 93 E5 81 30 D6 E7 08 00 13 E3 EC FF FF 1A 2E 00 51 E3 00 00 50 03 04 40 84 02 04 00 A0 01 F4 FF FF 0A }
	condition:
		$pattern
}

rule __GI_getpwuid_r_d059c4ebfab1936be1f69c7e7258a6bc {
	meta:
		aliases = "getpwuid_r, __GI_getgrgid_r, getgrgid_r, __GI_getpwuid_r"
		size = "168"
		objfiles = "getpwuid_r@libc.a, getgrgid_r@libc.a"
	strings:
		$pattern = { F0 47 2D E9 04 D0 4D E2 24 90 9D E5 00 C0 A0 E3 00 C0 89 E5 00 A0 A0 E1 01 60 A0 E1 78 00 9F E5 78 10 9F E5 03 70 A0 E1 02 80 A0 E1 ?? ?? ?? EB 00 50 50 E2 01 30 A0 13 34 30 85 15 02 00 00 1A ?? ?? ?? EB 00 40 90 E5 10 00 00 EA 50 00 9F E5 06 10 A0 E1 08 20 A0 E1 07 30 A0 E1 00 50 8D E5 ?? ?? ?? EB 00 40 50 E2 04 00 00 1A 08 30 96 E5 0A 00 53 E1 F4 FF FF 1A 00 60 89 E5 01 00 00 EA 02 00 54 E3 00 40 A0 03 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 04 D0 8D E2 F0 87 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule getspnam_r_f0f9c54b72d68aa234b440f56dbd90cc {
	meta:
		aliases = "getgrnam_r, __GI_getspnam_r, __GI_getgrnam_r, __GI_getpwnam_r, getpwnam_r, getspnam_r"
		size = "176"
		objfiles = "getspnam_r@libc.a, getgrnam_r@libc.a, getpwnam_r@libc.a"
	strings:
		$pattern = { F0 47 2D E9 04 D0 4D E2 24 90 9D E5 00 C0 A0 E3 00 C0 89 E5 00 A0 A0 E1 01 60 A0 E1 80 00 9F E5 80 10 9F E5 03 70 A0 E1 02 80 A0 E1 ?? ?? ?? EB 00 50 50 E2 01 30 A0 13 34 30 85 15 02 00 00 1A ?? ?? ?? EB 00 40 90 E5 12 00 00 EA 06 10 A0 E1 08 20 A0 E1 07 30 A0 E1 4C 00 9F E5 00 50 8D E5 ?? ?? ?? EB 00 40 50 E2 0A 10 A0 E1 05 00 00 1A 00 00 96 E5 ?? ?? ?? EB 00 00 50 E3 F2 FF FF 1A 00 60 89 E5 01 00 00 EA 02 00 54 E3 00 40 A0 03 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 04 D0 8D E2 F0 87 BD E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_srandom_r_9663d25b7490c1f58f5325bdb8d7cdc1 {
	meta:
		aliases = "srandom_r, __GI_srandom_r"
		size = "204"
		objfiles = "random_r@libc.a"
	strings:
		$pattern = { F0 47 2D E9 0C 30 91 E5 04 00 53 E3 04 D0 4D E2 01 60 A0 E1 00 00 E0 83 26 00 00 8A 00 00 50 E3 08 70 91 E5 01 00 A0 03 00 00 53 E3 00 00 87 E5 1F 00 00 0A 10 90 91 E5 00 50 A0 E1 07 A0 A0 E1 01 80 A0 E3 0A 00 00 EA ?? ?? ?? EB 6C 30 9F E5 6C 10 9F E5 90 03 04 E0 05 00 A0 E1 ?? ?? ?? EB 60 30 9F E5 90 03 03 E0 03 50 54 E0 06 51 45 42 04 50 AA E5 09 00 58 E1 05 00 A0 E1 40 10 9F E5 01 80 88 E2 EF FF FF BA 0A 30 A0 E3 99 03 04 E0 14 30 96 E5 03 31 87 E0 88 00 86 E8 00 00 00 EA ?? ?? ?? EB 01 40 54 E2 06 00 A0 E1 0D 10 A0 E1 FA FF FF 5A 00 00 A0 E3 04 D0 8D E2 F0 87 BD E8 A7 41 00 00 1D F3 01 00 }
	condition:
		$pattern
}

rule __ieee754_pow_7c4b1f2a647981b4a7349ae720d65f0f {
	meta:
		aliases = "__ieee754_pow"
		size = "2188"
		objfiles = "e_pow@libm.a"
	strings:
		$pattern = { F0 47 2D E9 0C 42 2D ED 03 00 2D E9 02 C1 BD EC 03 40 A0 E1 04 10 A0 E1 20 D0 4D E2 02 41 C2 E3 08 20 8D E5 0C 30 8D E5 02 60 A0 E1 01 30 94 E1 02 C1 2D ED 0C 00 BD E8 03 80 A0 E1 60 36 9F 05 90 00 00 0A 02 70 A0 E1 58 26 9F E5 02 51 C7 E3 02 00 55 E1 0F 00 00 CA 00 90 A0 13 01 90 A0 03 00 00 58 E3 00 30 A0 03 01 30 09 12 00 00 53 E3 08 00 00 1A 02 00 54 E1 06 00 00 CA 00 30 A0 13 01 30 A0 03 00 00 51 E3 00 30 A0 03 01 30 03 12 00 00 53 E3 02 00 00 0A 02 81 9D ED 84 01 00 EE F4 01 00 EA 00 00 57 E3 1A 00 00 AA F8 35 9F E5 03 00 54 E1 02 A0 A0 C3 17 00 00 CA EC 35 9F E5 03 00 54 E1 13 00 00 DA }
	condition:
		$pattern
}

rule _ppfs_parsespec_448dcca7ddc581f6e948af907770b306 {
	meta:
		aliases = "_ppfs_parsespec"
		size = "1220"
		objfiles = "_ppfs_parsespec@libc.a"
	strings:
		$pattern = { F0 47 2D E9 10 30 90 E5 38 D0 4D E2 80 40 13 E2 00 20 A0 E3 08 30 A0 E3 30 30 8D E5 20 20 8D E5 24 20 8D E5 2C 30 8D E5 00 70 A0 E1 18 90 90 E5 00 10 90 05 17 00 00 0A 03 00 00 EA 00 50 A0 E1 7F 00 00 EA 01 60 86 E2 85 00 00 EA 02 00 A0 E1 00 30 97 E5 00 31 83 E0 04 10 13 E5 38 C0 8D E2 00 20 8C E0 38 10 42 E5 38 20 52 E5 04 30 13 E5 03 00 52 E1 01 00 80 E2 05 01 00 1A 00 00 52 E3 01 00 00 0A 1F 00 50 E3 F0 FF FF 9A 00 30 A0 E3 1F 30 CD E5 01 10 8D E2 00 80 A0 E3 08 E0 A0 E1 00 00 00 EA 06 10 A0 E1 00 30 D1 E5 2A 00 53 E3 03 30 E0 03 38 20 8D 02 9E 23 22 00 01 60 A0 11 04 30 83 02 01 60 81 02 }
	condition:
		$pattern
}

rule getprotobyname_r_b1fc52706bbd8c8157278512515ac858 {
	meta:
		aliases = "__GI_getprotobyname_r, getprotobyname_r"
		size = "256"
		objfiles = "getproto@libc.a"
	strings:
		$pattern = { F0 47 2D E9 10 D0 4D E2 00 60 A0 E1 01 50 A0 E1 0D 00 A0 E1 CC 10 9F E5 02 A0 A0 E1 03 80 A0 E1 C4 20 9F E5 C4 30 9F E5 30 90 9D E5 0F E0 A0 E1 03 F0 A0 E1 B8 30 9F E5 AC 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 AC 30 9F E5 00 00 93 E5 ?? ?? ?? EB 0E 00 00 EA 00 00 95 E5 06 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 10 00 00 0A 04 40 95 E5 02 00 00 EA ?? ?? ?? EB 00 00 50 E3 0B 00 00 0A 00 30 94 E5 00 00 53 E2 06 10 A0 E1 04 40 84 E2 F7 FF FF 1A 05 00 A0 E1 0A 10 A0 E1 08 20 A0 E1 09 30 A0 E1 ?? ?? ?? EB 00 70 50 E2 E9 FF FF 0A 44 30 9F E5 00 30 93 E5 00 00 53 E3 ?? ?? ?? 0B 0D 00 A0 E1 01 10 A0 E3 30 30 9F E5 }
	condition:
		$pattern
}

rule getservbyport_r_19178cacccb92ecb88c9e7f488ad4ec6 {
	meta:
		aliases = "__GI_getservbyport_r, getservbyport_r"
		size = "240"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { F0 47 2D E9 10 D0 4D E2 00 80 A0 E1 01 60 A0 E1 0D 00 A0 E1 BC 10 9F E5 02 40 A0 E1 03 70 A0 E1 B4 20 9F E5 B4 30 9F E5 30 90 8D E2 00 06 99 E8 0F E0 A0 E1 03 F0 A0 E1 A4 30 9F E5 98 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 98 30 9F E5 00 00 93 E5 ?? ?? ?? EB 08 00 00 EA 08 30 94 E5 08 00 53 E1 05 00 00 1A 00 00 56 E3 0B 00 00 0A 0C 00 94 E5 ?? ?? ?? EB 00 00 50 E3 07 00 00 0A 07 10 A0 E1 09 20 A0 E1 0A 30 A0 E1 04 00 A0 E1 ?? ?? ?? EB 00 50 50 E2 06 10 A0 E1 EE FF FF 0A 44 30 9F E5 00 30 93 E5 00 00 53 E3 ?? ?? ?? 0B 0D 00 A0 E1 01 10 A0 E3 30 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 9A E5 00 00 50 E3 }
	condition:
		$pattern
}

rule __GI_ptsname_r_b238450cb7944dc9d9b6d049cc2540f4 {
	meta:
		aliases = "ptsname_r, __GI_ptsname_r"
		size = "180"
		objfiles = "ptsname@libc.a"
	strings:
		$pattern = { F0 47 2D E9 14 D0 4D E2 00 40 A0 E1 01 80 A0 E1 02 A0 A0 E1 ?? ?? ?? EB 10 20 8D E2 00 50 A0 E1 84 10 9F E5 04 00 A0 E1 00 90 95 E5 ?? ?? ?? EB 04 70 8D E2 00 60 50 E2 19 20 A0 E3 09 30 E0 E3 0B 00 87 E2 00 20 85 15 02 30 A0 11 13 00 00 1A 10 10 9D E5 C1 2F A0 E1 00 60 8D E5 ?? ?? ?? EB 00 40 A0 E1 07 30 64 E0 15 30 83 E2 22 20 A0 E3 03 00 5A E1 34 10 9F E5 08 00 A0 E1 02 30 A0 E1 00 20 85 35 05 00 00 3A ?? ?? ?? EB 08 00 A0 E1 04 10 A0 E1 ?? ?? ?? EB 00 90 85 E5 06 30 A0 E1 03 00 A0 E1 14 D0 8D E2 F0 87 BD E8 30 54 04 80 ?? ?? ?? ?? }
	condition:
		$pattern
}

rule __GI_gethostent_r_37c78c686b5d374ce8fa928fe002bb80 {
	meta:
		aliases = "gethostent_r, __GI_gethostent_r"
		size = "240"
		objfiles = "gethostent@libc.a"
	strings:
		$pattern = { F0 47 2D E9 24 D0 4D E2 C4 50 9F E5 00 80 A0 E1 01 A0 A0 E1 14 00 8D E2 B8 10 9F E5 02 90 A0 E1 03 40 A0 E1 B0 20 9F E5 B0 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 A8 30 9F E5 9C 00 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 95 E5 00 00 53 E3 05 60 A0 E1 05 00 00 1A ?? ?? ?? EB 00 00 50 E3 02 70 A0 E3 00 00 85 E5 00 00 84 05 11 00 00 0A 44 C0 9D E5 01 30 A0 E3 00 10 A0 E3 02 20 A0 E3 00 00 95 E5 0C 40 8D E5 00 05 8D E8 08 90 8D E5 10 C0 8D E5 ?? ?? ?? EB 4C 30 9F E5 00 40 93 E5 00 00 54 E3 00 70 A0 E1 02 00 00 1A 00 00 95 E5 ?? ?? ?? EB 00 40 85 E5 14 00 8D E2 01 10 A0 E3 28 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 }
	condition:
		$pattern
}

rule __GI_pmap_getport_1af8394b2a45f648fe5b7e4b6f1e9239 {
	meta:
		aliases = "pmap_getport, __GI_pmap_getport"
		size = "324"
		objfiles = "pm_getport@libc.a"
	strings:
		$pattern = { F0 47 2D E9 24 E1 9F E5 6F C0 A0 E3 28 D0 4D E2 03 C0 C0 E5 04 40 9E E5 00 60 A0 E3 00 C0 E0 E3 02 60 C0 E5 01 80 A0 E1 20 C0 8D E5 02 A0 A0 E1 20 C0 8D E2 03 90 A0 E1 F4 10 9F E5 00 30 9E E5 02 20 A0 E3 19 EE A0 E3 00 40 8D E5 00 70 A0 E1 04 C0 8D E5 0C E0 8D E5 26 60 CD E5 27 60 CD E5 08 E0 8D E5 ?? ?? ?? EB 00 40 50 E2 27 00 00 0A ?? ?? ?? EB 10 80 8D E5 14 A0 8D E5 18 90 8D E5 1C 60 8D E5 AC 30 9F E5 04 C0 94 E5 00 30 8D E5 26 30 8D E2 04 30 8D E5 9C 30 9F E5 06 00 93 E8 00 50 A0 E1 08 10 8D E5 0C 20 8D E5 10 30 8D E2 88 20 9F E5 03 10 A0 E3 04 00 A0 E1 0F E0 A0 E1 00 F0 9C E5 06 00 50 E1 }
	condition:
		$pattern
}

rule svcudp_recv_fcd64995378fced9d0b5c9cdedd204dc {
	meta:
		aliases = "svcudp_recv"
		size = "552"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { F0 47 2D E9 30 50 90 E5 0C D0 4D E2 00 60 A0 E1 01 80 A0 E1 3C 70 86 E2 0C 30 97 E5 10 00 A0 E3 00 20 A0 E3 08 00 8D E5 02 00 53 E1 58 40 86 E2 07 10 A0 E1 2C C0 96 E5 34 A0 86 E2 00 E0 86 E0 10 00 00 0A 34 C0 86 E5 00 30 95 E5 04 30 8A E5 01 30 A0 E3 0C 30 87 E5 DB 30 83 E2 14 30 87 E5 04 00 87 E5 10 40 87 E5 08 A0 87 E5 3C E0 86 E5 00 00 96 E5 ?? ?? ?? EB 00 00 50 E3 04 30 97 A5 08 30 8D A5 06 00 00 EA 00 20 95 E5 00 00 96 E5 0C 10 A0 E1 08 C0 8D E2 00 E0 8D E5 04 C0 8D E5 ?? ?? ?? EB 08 30 9D E5 01 00 70 E3 0C 30 86 E5 04 00 00 1A ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 D3 FF FF 0A 52 00 00 EA }
	condition:
		$pattern
}

rule __GI_fclose_6d0fb8c20371ce42871f8643c2883d8c {
	meta:
		aliases = "fclose, __GI_fclose"
		size = "384"
		objfiles = "fclose@libc.a"
	strings:
		$pattern = { F0 47 2D E9 34 80 90 E5 38 50 80 E2 20 D0 4D E2 00 00 58 E3 00 40 A0 E1 44 11 9F E5 05 20 A0 E1 10 00 8D E2 06 00 00 1A 38 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 05 00 A0 E1 2C 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 30 D4 E5 40 30 13 E2 04 00 A0 E1 03 70 A0 E1 01 00 00 0A ?? ?? ?? EB 00 70 A0 E1 04 00 94 E5 ?? ?? ?? EB 00 30 E0 E3 00 00 50 E3 04 30 84 E5 F4 20 9F E5 E4 10 9F E5 0D 00 A0 E1 E0 90 9F E5 03 70 A0 B1 DC A0 9F E5 0F E0 A0 E1 09 F0 A0 E1 D4 00 9F E5 0F E0 A0 E1 0A F0 A0 E1 CC 20 9F E5 00 30 92 E5 01 30 83 E2 00 30 82 E5 0D 00 A0 E1 01 10 A0 E3 B8 50 9F E5 0F E0 A0 E1 05 F0 A0 E1 00 30 94 E5 }
	condition:
		$pattern
}

rule __res_querydomain_ea6925d3e97ac6261cf65ac4b56de75c {
	meta:
		aliases = "__GI___res_querydomain, __res_querydomain"
		size = "436"
		objfiles = "res_query@libc.a"
	strings:
		$pattern = { F0 47 2D E9 41 DE 4D E2 08 D0 4D E2 01 4B 8D E2 08 40 84 E2 00 60 A0 E1 01 70 A0 E1 04 00 A0 E1 6C 11 9F E5 02 A0 A0 E1 03 80 A0 E1 64 21 9F E5 64 31 9F E5 38 94 9D E5 0F E0 A0 E1 03 F0 A0 E1 58 31 9F E5 4C 01 9F E5 0F E0 A0 E1 03 F0 A0 E1 4C 31 9F E5 04 00 A0 E1 01 10 A0 E3 08 40 93 E5 40 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 59 E3 00 00 56 13 04 00 00 0A 01 00 14 E3 06 00 00 1A ?? ?? ?? EB 01 00 70 E3 03 00 00 1A ?? ?? ?? EB 00 30 E0 E3 03 20 A0 E1 0A 00 00 EA 00 00 57 E3 1C 00 00 1A 06 00 A0 E1 ?? ?? ?? EB F8 30 9F E5 01 20 80 E2 03 00 52 E1 04 00 00 9A ?? ?? ?? EB 00 20 E0 E3 03 30 A0 E3 }
	condition:
		$pattern
}

rule des_init_ace84f996fdd893c06461a36a5dc7703 {
	meta:
		aliases = "des_init"
		size = "1248"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { F0 47 2D E9 58 34 9F E5 00 30 93 E5 01 00 53 E3 02 DC 4D E2 10 01 00 0A 48 34 9F E5 00 20 A0 E3 00 20 83 E5 40 34 9F E5 00 20 83 E5 3C 34 9F E5 00 20 83 E5 38 34 9F E5 02 C0 A0 E1 00 20 83 E5 10 00 00 EA 01 30 D3 E7 00 32 42 E5 01 30 00 E2 20 10 00 E2 03 12 81 E1 80 3D A0 E1 23 1E 81 E1 10 34 9F E5 0C 23 A0 E1 02 EC 8D E2 03 30 82 E0 3F 00 50 E3 0E 20 82 E0 00 20 82 E0 01 00 80 E2 EF FF FF DA 01 C0 8C E2 07 00 5C E3 00 00 A0 D3 ED FF FF DA 00 E0 A0 E3 12 00 00 EA 00 22 52 E5 C0 31 55 E5 02 32 83 E1 0C 30 C4 E7 02 2C 8D E2 8E 33 82 E0 01 50 83 E0 00 20 83 E0 B8 33 9F E5 3F 00 51 E3 00 C3 81 E1 }
	condition:
		$pattern
}

rule getservent_r_8dbf201a0f314970649b6a2e13550b41 {
	meta:
		aliases = "__GI_getservent_r, getservent_r"
		size = "580"
		objfiles = "getservice@libc.a"
	strings:
		$pattern = { F0 47 2D E9 8B 00 52 E3 03 90 A0 E1 00 30 A0 E3 10 D0 4D E2 02 40 A0 E1 00 30 89 E5 00 60 A0 E1 01 80 A0 E1 04 00 00 8A ?? ?? ?? EB 22 30 A0 E3 03 40 A0 E1 00 30 80 E5 73 00 00 EA 0D 00 A0 E1 D0 11 9F E5 D0 21 9F E5 D0 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 C8 31 9F E5 BC 01 9F E5 0F E0 A0 E1 03 F0 A0 E1 8C 30 44 E2 01 0A 53 E3 8C A0 88 E2 02 00 00 8A ?? ?? ?? EB 22 30 A0 E3 0B 00 00 EA A0 41 9F E5 00 30 94 E5 00 00 53 E3 0A 00 00 1A 94 01 9F E5 94 11 9F E5 ?? ?? ?? EB 00 00 50 E3 00 00 84 E5 04 00 00 1A ?? ?? ?? EB 05 30 A0 E3 03 40 A0 E1 00 30 80 E5 4E 00 00 EA 64 31 9F E5 0A 00 A0 E1 00 20 93 E5 }
	condition:
		$pattern
}

rule __pgsreader_6f2f38577038c0182900623caf222b4a {
	meta:
		aliases = "__pgsreader"
		size = "368"
		objfiles = "__pgsreader@libc.a"
	strings:
		$pattern = { F0 47 2D E9 FF 00 53 E3 10 D0 4D E2 03 60 A0 E1 00 A0 A0 E1 01 80 A0 E1 02 50 A0 E1 30 70 9D E5 06 00 00 8A ?? ?? ?? EB 22 30 A0 E3 03 40 A0 E1 00 30 80 E5 44 00 00 EA 02 40 A0 E3 3C 00 00 EA 34 90 97 E5 00 00 59 E3 0A 00 00 1A 38 40 87 E2 0D 00 A0 E1 FC 30 9F E5 FC 10 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 EC 30 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 40 A0 E3 05 00 A0 E1 06 10 A0 E1 07 20 A0 E1 ?? ?? ?? EB 00 00 50 E3 04 00 00 1A 00 30 D7 E5 04 00 13 E3 22 40 A0 03 23 00 00 0A E3 FF FF EA 05 00 A0 E1 ?? ?? ?? EB 01 20 40 E2 02 30 D5 E7 0A 00 53 E3 00 30 A0 03 02 30 C5 07 03 00 00 0A }
	condition:
		$pattern
}

rule read_encoded_value_with_base_d73a98cb50f1db025f6d94dd1030a793 {
	meta:
		aliases = "read_encoded_value_with_base"
		size = "356"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a, unwind_c@libgcc.a"
	strings:
		$pattern = { F0 47 2D E9 FF 80 00 E2 50 00 58 E3 04 D0 4D E2 01 A0 A0 E1 02 70 A0 E1 03 90 A0 E1 23 00 00 0A 0F 30 00 E2 0C 00 53 E3 03 F1 9F 97 41 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 30 D2 E5 01 20 D2 E5 02 00 D7 E5 02 34 83 E1 03 10 D7 E5 00 38 83 E1 01 1C 83 E1 04 00 87 E2 00 00 51 E3 05 00 00 0A 70 30 08 E2 10 00 53 E3 07 A0 A0 01 0A 10 81 E0 80 00 18 E3 00 10 91 15 00 10 89 E5 04 D0 8D E2 F0 87 BD E8 03 30 82 E2 03 30 C3 E3 04 10 93 E4 03 00 A0 E1 F7 FF FF EA 01 00 D2 E5 }
	condition:
		$pattern
}

rule __ieee754_hypot_3e50c4333c1c3886658df199d26e9382 {
	meta:
		aliases = "__ieee754_hypot"
		size = "608"
		objfiles = "e_hypot@libm.a"
	strings:
		$pattern = { F0 4D 2D E9 02 C1 C0 E3 02 E1 C2 E3 0C 00 5E E1 01 80 A0 E1 03 60 A0 E1 0E 30 A0 C1 08 10 A0 C1 0C E0 A0 C1 06 10 A0 D1 03 C0 A0 C1 06 B0 A0 C1 08 B0 A0 D1 02 A0 A0 C1 02 50 A0 E1 0B 40 A0 E1 01 20 A0 E1 0C 30 A0 E1 0E 10 A0 E1 0C 42 2D ED 18 00 2D E9 02 D1 BD EC 06 00 2D E9 02 E1 BD EC 00 A0 A0 D1 00 70 A0 E1 0C 00 6E E0 0F 05 50 E3 86 01 05 CE 72 00 00 CA CC 31 9F E5 03 00 5C E1 00 50 A0 D3 1D 00 00 DA C0 31 9F E5 03 00 5C E1 0D 00 00 DA 02 D1 2D ED 18 00 BD E8 FF 24 CC E3 0F 26 C2 E3 04 20 92 E1 02 E1 2D ED 18 00 BD E8 9C 21 9F E5 02 20 2E E0 85 81 00 0E 86 01 05 1E 04 20 92 E1 86 81 00 0E }
	condition:
		$pattern
}

rule modf_b5b235acada7255e1b5aa5e831aa437b {
	meta:
		aliases = "__GI_modf, modf"
		size = "356"
		objfiles = "s_modf@libm.a"
	strings:
		$pattern = { F0 4D 2D E9 18 D0 4D E2 10 00 8D E5 14 10 8D E5 10 C0 9D E5 4C 3A A0 E1 83 3A A0 E1 A3 3A A0 E1 03 00 2D E9 02 91 BD EC FF 1F 43 E2 03 10 41 E2 00 30 A0 E3 02 E0 A0 E1 00 20 A0 E3 02 50 A0 E1 03 60 A0 E1 13 00 51 E3 08 20 8D E5 0C 30 8D E5 02 A0 A0 E1 03 B0 A0 E1 60 00 8D E8 02 70 A0 E1 03 80 A0 E1 14 00 9D E5 1B 00 00 CA 00 00 51 E3 05 00 00 AA 00 30 A0 E3 02 21 0C E2 03 40 A0 E1 02 30 A0 E1 18 00 8E E8 31 00 00 EA CC 30 9F E5 53 21 A0 E1 02 30 0C E0 00 10 93 E1 07 00 00 1A 02 91 2D ED 18 00 BD E8 02 31 03 E2 08 30 8D E5 0C 10 8D E5 00 91 8E ED 02 91 9D ED 24 00 00 EA 02 A0 CC E1 00 B0 A0 E3 }
	condition:
		$pattern
}

rule __divdi3_04fe0c07c712413a41afb48016938a62 {
	meta:
		aliases = "__divdi3"
		size = "1420"
		objfiles = "_divdi3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 00 51 E3 18 D0 4D E2 00 40 A0 E3 00 50 A0 E3 00 C0 A0 A3 30 00 8D E8 08 C0 8D A5 02 40 A0 E1 03 50 A0 E1 D6 00 00 BA 00 00 53 E3 CE 00 00 BA 00 00 55 E3 01 70 A0 E1 04 60 A0 E1 00 90 A0 E1 6B 00 00 1A 01 00 54 E1 78 00 00 8A 00 00 54 E3 33 01 00 0A 01 08 56 E3 CE 00 00 2A FF 00 56 E3 08 00 A0 83 05 30 A0 91 05 00 A0 91 00 30 A0 81 36 13 A0 E1 08 25 9F E5 01 30 D2 E7 03 30 80 E0 20 B0 73 E2 06 A8 A0 01 07 40 66 00 2A A8 A0 01 26 88 A0 01 01 B0 A0 03 2D 00 00 0A 20 30 6B E2 37 43 A0 E1 39 33 A0 E1 16 6B A0 E1 17 7B 83 E1 26 88 A0 E1 08 10 A0 E1 04 00 A0 E1 14 70 8D E5 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __moddi3_4c230d80a7cb2c4e87c55b625a8a3da4 {
	meta:
		aliases = "__moddi3"
		size = "1484"
		objfiles = "_moddi3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 00 51 E3 24 D0 4D E2 00 40 A0 E3 00 50 A0 E3 00 C0 A0 A3 30 00 8D E8 08 C0 8D A5 02 40 A0 E1 03 50 A0 E1 D9 00 00 BA 00 00 53 E3 D4 00 00 BA 00 00 55 E3 04 60 A0 E1 00 90 A0 E1 01 70 A0 E1 5E 00 00 1A 01 00 54 E1 8D 00 00 8A 00 00 54 E3 D9 00 00 0A 01 08 56 E3 D1 00 00 2A FF 00 56 E3 08 00 A0 83 05 30 A0 91 05 00 A0 91 00 30 A0 81 36 13 A0 E1 48 25 9F E5 01 30 D2 E7 03 30 80 E0 20 B0 73 E2 06 A8 A0 01 07 40 66 00 2A A8 A0 01 14 B0 8D 05 26 88 A0 01 26 00 00 0A 16 6B A0 E1 20 30 6B E2 37 43 A0 E1 39 33 A0 E1 26 88 A0 E1 08 10 A0 E1 04 00 A0 E1 17 7B 83 E1 14 B0 8D E5 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __GI_qsort_0a15a3fb361bfffb342e5b95fe9fa4b3 {
	meta:
		aliases = "qsort, __GI_qsort"
		size = "200"
		objfiles = "qsort@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 00 52 E3 01 00 51 13 04 D0 4D E2 01 50 A0 E1 02 A0 A0 E1 00 00 8D E5 03 B0 A0 E1 26 00 00 9A 00 40 A0 E3 03 10 A0 E3 94 01 03 E0 01 00 45 E2 01 40 83 E2 ?? ?? ?? EB 00 00 54 E1 F8 FF FF 3A 9A 04 07 E0 9A 05 09 E0 07 80 A0 E1 08 60 A0 E1 00 30 9D E5 06 60 67 E0 06 40 83 E0 07 50 84 E0 04 00 A0 E1 05 10 A0 E1 0F E0 A0 E1 0B F0 A0 E1 00 00 50 E3 08 00 00 DA 0A 10 A0 E1 00 20 D4 E5 00 30 D5 E5 01 10 51 E2 01 30 C4 E4 01 20 C5 E4 F9 FF FF 1A 07 00 56 E1 EC FF FF 2A 0A 80 88 E0 09 00 58 E1 E8 FF FF 3A 07 00 6A E0 03 10 A0 E3 ?? ?? ?? EB 00 70 50 E2 E2 FF FF 1A 04 D0 8D E2 F0 8F BD E8 }
	condition:
		$pattern
}

rule __udivdi3_8bed399e2f0b883f4a31e20d10f96daa {
	meta:
		aliases = "__udivdi3"
		size = "1324"
		objfiles = "_udivdi3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 00 53 E3 02 40 A0 E1 14 D0 4D E2 03 50 A0 E1 00 20 A0 E3 00 30 A0 E3 01 70 A0 E1 0C 00 8D E8 04 60 A0 E1 00 B0 A0 E1 6B 00 00 1A 01 00 54 E1 84 00 00 8A 00 00 54 E3 1B 01 00 0A 01 08 56 E3 13 01 00 2A FF 00 56 E3 08 00 A0 83 05 30 A0 91 05 00 A0 91 00 30 A0 81 36 13 A0 E1 C0 24 9F E5 01 30 D2 E7 03 30 80 E0 20 90 73 E2 06 A8 A0 01 07 40 66 00 2A A8 A0 01 26 88 A0 01 01 90 A0 03 2D 00 00 0A 20 30 69 E2 37 43 A0 E1 3B 33 A0 E1 16 69 A0 E1 17 79 83 E1 26 88 A0 E1 08 10 A0 E1 04 00 A0 E1 10 70 8D E5 ?? ?? ?? EB 08 10 A0 E1 00 70 A0 E1 04 00 A0 E1 ?? ?? ?? EB 06 A8 A0 E1 2A A8 A0 E1 }
	condition:
		$pattern
}

rule __umoddi3_9ec8c5cf8c849a7f538c0f9de6222fb4 {
	meta:
		aliases = "__umoddi3"
		size = "1320"
		objfiles = "_umoddi3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 00 53 E3 02 40 A0 E1 18 D0 4D E2 03 50 A0 E1 00 20 A0 E3 00 30 A0 E3 0C 00 8D E8 04 60 A0 E1 00 90 A0 E1 01 70 A0 E1 5E 00 00 1A 01 00 54 E1 79 00 00 8A 00 00 54 E3 BA 00 00 0A 01 08 56 E3 B2 00 00 2A FF 00 56 E3 08 00 A0 83 05 30 A0 91 05 00 A0 91 00 30 A0 81 36 13 A0 E1 BC 24 9F E5 01 30 D2 E7 03 30 80 E0 20 B0 73 E2 06 A8 A0 01 07 40 66 00 2A A8 A0 01 10 B0 8D 05 26 88 A0 01 26 00 00 0A 16 6B A0 E1 20 30 6B E2 37 43 A0 E1 39 33 A0 E1 26 88 A0 E1 08 10 A0 E1 04 00 A0 E1 17 7B 83 E1 10 B0 8D E5 ?? ?? ?? EB 06 A8 A0 E1 2A A8 A0 E1 90 0A 05 E0 08 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __udivmoddi4_19b83f60059d2e6d2aa99de62e88d5ab {
	meta:
		aliases = "__udivmoddi4"
		size = "1632"
		objfiles = "_udivmoddi4@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 00 53 E3 2C D0 4D E2 00 A0 A0 E3 00 B0 A0 E3 02 40 A0 E1 03 50 A0 E1 00 0C 8D E8 02 60 A0 E1 0C 00 8D E5 01 70 A0 E1 77 00 00 1A 01 00 52 E1 A7 00 00 8A 00 00 52 E3 FB 00 00 0A 01 08 56 E3 F3 00 00 2A FF 00 56 E3 08 00 A0 83 05 30 A0 91 05 00 A0 91 00 30 A0 81 36 13 A0 E1 F4 25 9F E5 01 30 D2 E7 03 30 80 E0 20 30 73 E2 14 30 8D E5 06 98 A0 01 01 30 A0 03 07 40 66 00 29 98 A0 01 26 88 A0 01 10 30 8D 05 34 00 00 0A 14 10 9D E5 0C 20 9D E5 20 30 61 E2 37 43 A0 E1 32 33 A0 E1 16 61 A0 E1 14 20 9D E5 17 72 83 E1 26 88 A0 E1 08 10 A0 E1 04 00 A0 E1 24 70 8D E5 ?? ?? ?? EB 08 10 A0 E1 }
	condition:
		$pattern
}

rule _stdlib_wcsto_ll_c370b86cb5490cdf86edefbc8a5e52cc {
	meta:
		aliases = "_stdlib_wcsto_ll"
		size = "548"
		objfiles = "_stdlib_wcsto_ll@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 40 A0 E1 08 D0 4D E2 01 90 A0 E1 02 80 A0 E1 03 B0 A0 E1 00 70 A0 E1 00 00 00 EA 04 70 87 E2 00 00 97 E5 ?? ?? ?? EB 00 00 50 E3 FA FF FF 1A 00 20 97 E5 2B 00 52 E3 04 00 00 0A 2D 00 52 E3 00 A0 A0 11 01 A0 A0 03 01 00 00 0A 01 00 00 EA 00 A0 A0 E1 04 70 87 E2 10 10 D8 E3 04 00 A0 11 0E 00 00 1A 00 30 97 E5 30 00 53 E3 0A 80 88 E2 04 00 A0 11 07 00 00 1A 04 30 B7 E5 20 30 83 E3 78 00 53 E3 02 80 48 E2 07 00 A0 01 07 00 A0 11 88 80 A0 01 04 70 87 02 10 00 58 E3 10 80 A0 A3 02 30 48 E2 22 00 53 E3 00 40 A0 93 00 50 A0 93 01 00 00 9A 37 00 00 EA 07 00 A0 E1 00 20 97 E5 30 30 42 E2 }
	condition:
		$pattern
}

rule des_setkey_576433fc5d6e772a0351c6c76a8fe21b {
	meta:
		aliases = "des_setkey"
		size = "968"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { F0 4F 2D E9 00 40 A0 E1 4C D0 4D E2 A9 FE FF EB 00 50 94 E8 FF 08 0E E2 FF 18 0C E2 FF 3C 0C E2 FF 2C 0E E2 21 14 A0 E1 03 34 A0 E1 20 04 A0 E1 02 24 A0 E1 0C 3C 83 E1 0E 2C 82 E1 2C 1C 81 E1 2E 0C 80 E1 03 10 81 E1 02 B0 80 E1 40 10 8D E5 0B 10 91 E1 08 00 00 0A 3C 33 9F E5 40 00 9D E5 00 30 93 E5 03 00 50 E1 03 00 00 1A 2C 33 9F E5 00 30 93 E5 03 00 5B E1 C5 00 00 0A 40 10 9D E5 40 20 9D E5 18 E3 9F E5 81 00 A0 E1 A2 37 A0 E1 10 13 9F E5 7F 3F 03 E2 01 80 83 E0 7F 0F 00 E2 0E 30 83 E0 A2 23 A0 E1 01 60 80 E0 00 32 93 E5 7F 2F 02 E2 01 A0 82 E0 1C 60 8D E5 0E 20 82 E0 30 30 8D E5 00 24 92 E5 }
	condition:
		$pattern
}

rule realpath_6bdf56f7a73f5b6e1fc01223375359c5 {
	meta:
		aliases = "realpath"
		size = "684"
		objfiles = "realpath@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 50 50 E2 01 DA 4D E2 04 D0 4D E2 01 70 A0 E1 03 00 00 1A ?? ?? ?? EB 05 70 A0 E1 16 30 A0 E3 05 00 00 EA 00 40 D5 E5 00 00 54 E3 04 00 00 1A ?? ?? ?? EB 04 70 A0 E1 02 30 A0 E3 00 30 80 E5 91 00 00 EA ?? ?? ?? EB 4C 32 9F E5 03 00 50 E1 80 00 00 8A 04 30 8D E2 03 60 60 E0 FF 4E 86 E2 0F 40 84 E2 05 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB FF 3F D6 E5 2F 00 53 E3 FF 9E 87 E2 07 50 A0 01 0E 90 89 E2 01 30 C5 04 01 4A 86 02 0C 00 00 0A 07 00 A0 E1 04 12 9F E5 ?? ?? ?? EB 00 00 50 E3 78 00 00 0A 07 00 A0 E1 ?? ?? ?? EB 00 50 87 E0 01 30 55 E5 2F 00 53 E3 2F 30 A0 13 00 30 C7 17 01 50 85 12 }
	condition:
		$pattern
}

rule __encode_answer_4b8f55c85a888c524677c4678d5936bb {
	meta:
		aliases = "__encode_answer"
		size = "224"
		objfiles = "encodea@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 50 A0 E1 04 D0 4D E2 00 00 90 E5 02 40 A0 E1 01 70 A0 E1 ?? ?? ?? EB 00 60 50 E2 04 80 66 E0 2A 00 00 BA 06 20 87 E0 01 10 82 E2 01 C0 81 E2 01 E0 8C E2 01 40 8E E2 01 A0 84 E2 01 90 8A E2 01 B0 89 E2 01 30 8B E2 00 30 8D E5 02 00 83 E2 10 30 95 E5 0A 30 83 E2 03 00 58 E1 00 60 E0 B3 1A 00 00 BA 05 30 D5 E5 06 30 C7 E7 04 30 95 E5 01 30 C2 E5 09 30 D5 E5 01 30 C1 E5 08 30 95 E5 01 30 CC E5 0F 30 D5 E5 01 30 CE E5 0E 30 D5 E5 01 30 C4 E5 0D 30 D5 E5 01 30 CA E5 0C 30 95 E5 01 30 C9 E5 11 30 D5 E5 01 30 CB E5 00 20 9D E5 10 30 95 E5 01 30 C2 E5 14 10 95 E5 10 20 95 E5 ?? ?? ?? EB }
	condition:
		$pattern
}

rule getsubopt_7c9a35ba883fbfc08d6cc5e6bb70eb71 {
	meta:
		aliases = "getsubopt"
		size = "216"
		objfiles = "getsubopt@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 60 90 E5 00 30 D6 E5 04 D0 4D E2 00 00 53 E3 00 90 A0 E1 00 10 8D E5 02 B0 A0 E1 28 00 00 0A 2C 10 A0 E3 06 00 A0 E1 ?? ?? ?? EB 00 40 A0 E1 3D 10 A0 E3 06 00 A0 E1 04 20 66 E0 ?? ?? ?? EB 00 00 50 E3 00 70 A0 11 04 70 A0 01 00 A0 A0 E3 0F 00 00 EA ?? ?? ?? EB 00 00 50 E3 0B 00 00 1A 08 10 D5 E7 00 00 51 E3 08 00 00 1A 04 00 57 E1 01 10 87 12 00 10 8B E5 00 30 D4 E5 00 00 53 E3 00 30 A0 13 01 30 C4 14 00 40 89 E5 0D 00 00 EA 01 A0 8A E2 00 30 9D E5 0A 51 93 E7 07 80 66 E0 00 10 55 E2 06 00 A0 E1 08 20 A0 E1 E8 FF FF 1A 00 60 8B E5 00 30 D4 E5 00 00 53 E3 01 50 C4 14 00 40 89 E5 }
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

rule _uintmaxtostr_aaecd3135229e12c4894dcd06a2d0952 {
	meta:
		aliases = "_uintmaxtostr"
		size = "336"
		objfiles = "_uintmaxtostr@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 70 53 E2 04 D0 4D E2 00 80 A0 E1 01 50 A0 E1 02 60 A0 E1 07 00 00 AA 00 00 52 E3 00 70 67 E2 04 00 00 AA 01 20 A0 E3 00 50 75 E2 00 60 E6 E2 00 20 8D E5 01 00 00 EA 00 30 A0 E3 00 30 8D E5 00 A0 A0 E3 00 A0 C8 E5 07 10 A0 E1 00 00 E0 E3 ?? ?? ?? EB 07 10 A0 E1 00 B0 A0 E1 00 00 E0 E3 ?? ?? ?? EB 01 90 80 E2 07 00 59 E1 0A 90 A0 01 01 B0 8B 02 06 A0 A0 E1 05 60 A0 E1 00 00 5A E3 0A 00 A0 E1 07 10 A0 E1 16 00 00 0A ?? ?? ?? EB 07 10 A0 E1 00 40 A0 E1 0A 00 A0 E1 ?? ?? ?? EB 07 10 A0 E1 00 A0 A0 E1 06 00 A0 E1 ?? ?? ?? EB 07 10 A0 E1 94 09 25 E0 06 00 A0 E1 ?? ?? ?? EB 07 10 A0 E1 }
	condition:
		$pattern
}

rule getaddrinfo_20020f8392201172c41de0346ff7818b {
	meta:
		aliases = "__GI_getaddrinfo, getaddrinfo"
		size = "764"
		objfiles = "getaddrinfo@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 80 50 E2 40 D0 4D E2 00 00 A0 E3 3C 00 8D E5 01 50 A0 E1 02 60 A0 E1 00 30 8D E5 05 00 00 0A 00 30 D8 E5 2A 00 53 E3 02 00 00 1A 01 30 D8 E5 00 00 53 E1 00 80 A0 01 00 00 55 E3 05 00 00 0A 00 30 D5 E5 2A 00 53 E3 02 00 00 1A 01 30 D5 E5 00 00 53 E3 00 50 A0 03 05 20 98 E1 9F 00 00 0A 00 00 56 E3 05 00 00 1A 10 40 8D E2 06 10 A0 E1 04 00 A0 E1 20 20 A0 E3 ?? ?? ?? EB 04 60 A0 E1 00 20 96 E5 43 3E C2 E3 0F 30 C3 E3 00 00 53 E3 94 00 00 1A 01 30 78 E2 00 30 A0 33 A2 20 13 E0 90 00 00 1A 00 00 55 E3 1E 00 00 0A 00 30 D5 E5 00 00 53 E3 1B 00 00 0A 05 00 A0 E1 38 10 8D E2 0A 20 A0 E3 }
	condition:
		$pattern
}

rule _dl_parse_a46172dd692b091102fbaf9d703e22ee {
	meta:
		aliases = "_dl_parse"
		size = "264"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { F0 4F 2D E9 00 80 A0 E3 54 90 80 E2 00 0A 99 E8 0C D0 4D E2 A3 31 A0 E1 00 70 A0 E1 02 60 A0 E1 08 A0 A0 E1 0A 00 8D E9 26 00 00 EA 04 40 96 E5 30 C0 9D E5 00 90 8D E5 0F E0 A0 E1 0C F0 A0 E1 24 54 A0 E1 00 40 50 E2 A0 10 9F E5 02 00 A0 E3 1A 00 00 0A 98 30 9F E5 00 20 93 E5 ?? ?? ?? EB 00 00 55 E3 02 00 A0 E3 88 10 9F E5 05 22 9B 17 02 20 89 10 ?? ?? ?? 1B 00 00 54 E3 02 00 A0 E3 74 10 9F E5 07 00 00 AA 04 20 D6 E5 ?? ?? ?? EB 00 00 64 E2 01 00 90 EF 01 0A 70 E3 5C 30 9F 85 00 00 60 E2 00 00 83 85 00 00 54 E3 02 00 A0 E3 4C 10 9F E5 01 00 00 DA ?? ?? ?? EB 04 80 88 E0 01 A0 8A E2 08 60 86 E2 }
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

rule __decode_dotted_f23dfcd252f5adc37489ff18427d2d1c {
	meta:
		aliases = "__decode_dotted"
		size = "204"
		objfiles = "decoded@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 A0 50 E2 04 D0 4D E2 00 80 A0 13 02 90 A0 E1 00 30 8D E5 01 B0 A0 13 08 00 A0 11 1F 00 00 1A 25 00 00 EA 00 00 5B E3 C0 30 04 E2 01 80 88 12 C0 00 53 E3 01 50 81 E2 07 00 00 1A 05 20 DA E7 00 00 5B E3 3F 30 04 E2 01 80 88 12 03 14 82 E1 00 70 A0 E1 00 B0 A0 E3 0F 00 00 EA 04 60 80 E0 00 30 9D E5 01 70 86 E2 03 00 57 E1 12 00 00 2A 05 10 8A E0 00 00 89 E0 04 20 A0 E1 ?? ?? ?? EB 04 10 85 E0 01 30 DA E7 00 00 5B E3 04 80 88 10 00 00 53 E3 2E 30 A0 13 06 30 C9 E7 07 00 A0 E1 01 40 DA E7 00 00 54 E3 DD FF FF 1A 00 00 5B E3 01 80 88 12 08 00 A0 E1 00 00 00 EA 00 00 E0 E3 04 D0 8D E2 }
	condition:
		$pattern
}

rule classify_object_over_fdes_672c29e033c0e90820d4b6266a65c4cc {
	meta:
		aliases = "classify_object_over_fdes"
		size = "324"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 A0 A0 E3 7F BE A0 E3 08 D0 4D E2 00 50 A0 E1 01 40 A0 E1 08 B0 8B E2 0A 80 A0 E1 0A 90 A0 E1 00 A0 8D E5 02 00 00 EA 04 00 A0 E1 9A FC FF EB 00 40 A0 E1 05 00 A0 E1 04 10 A0 E1 9A FC FF EB 00 00 50 E3 33 00 00 1A 04 30 94 E5 00 00 53 E3 F4 FF FF 0A 04 00 A0 E1 8B FC FF EB 00 00 58 E1 00 70 A0 E1 FF 60 09 02 15 00 00 0A A2 FE FF EB FF 60 00 E2 00 90 A0 E1 05 10 A0 E1 06 00 A0 E1 D2 FD FF EB 00 00 8D E5 10 20 95 E5 07 30 C2 E3 83 3A A0 E1 A3 3A A0 E1 0B 00 53 E1 20 00 00 0A 10 20 D5 E5 11 30 D5 E5 03 34 82 E1 A3 31 A0 E1 FF 30 03 E2 03 00 59 E1 04 30 82 13 10 30 C5 15 07 80 A0 E1 }
	condition:
		$pattern
}

rule openpty_479cc0bd02b6b260eeefefcefa74ab25 {
	meta:
		aliases = "__GI_openpty, openpty"
		size = "236"
		objfiles = "openpty@libutil.a"
	strings:
		$pattern = { F0 4F 2D E9 00 B0 A0 E1 01 DA 4D E2 02 00 A0 E3 01 90 A0 E1 02 60 A0 E1 03 80 A0 E1 ?? ?? ?? EB 01 00 70 E3 00 50 A0 E1 00 00 A0 01 2A 00 00 0A ?? ?? ?? EB 00 00 50 E3 24 00 00 1A 05 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 20 00 00 1A 05 00 A0 E1 0D 10 A0 E1 01 2A A0 E3 ?? ?? ?? EB 00 A0 50 E2 0D 70 A0 E1 19 00 00 1A 0D 00 A0 E1 70 10 9F E5 ?? ?? ?? EB 01 00 70 E3 00 40 A0 E1 13 00 00 0A 00 00 58 E3 08 20 A0 11 02 10 A0 13 ?? ?? ?? 1B 01 2A 8D E2 24 20 92 E5 00 00 52 E3 04 00 A0 11 40 10 9F 15 ?? ?? ?? 1B 00 00 56 E3 00 50 8B E5 06 00 A0 01 00 40 89 E5 07 00 00 0A 06 00 A0 E1 0D 10 A0 E1 ?? ?? ?? EB }
	condition:
		$pattern
}

rule __GI_authunix_create_9fbd3fbcd7648ffd32dde440528782c6 {
	meta:
		aliases = "authunix_create, __GI_authunix_create"
		size = "340"
		objfiles = "auth_unix@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 00 B0 A0 E1 72 DF 4D E2 28 00 A0 E3 01 80 A0 E1 02 A0 A0 E1 03 90 A0 E1 ?? ?? ?? EB 00 50 A0 E1 1B 0E A0 E3 ?? ?? ?? EB 00 00 50 E3 00 00 55 13 00 40 A0 E1 00 60 A0 13 01 60 A0 03 09 00 00 1A F8 30 9F E5 F8 00 9F E5 00 10 93 E5 ?? ?? ?? EB 05 00 A0 E1 ?? ?? ?? EB 04 00 A0 E1 ?? ?? ?? EB 00 50 A0 E3 32 00 00 EA D8 30 9F E5 24 00 85 E5 20 30 85 E5 D0 30 9F E5 07 00 93 E8 0C 30 84 E2 07 00 83 E8 0C 30 85 E2 07 00 83 E8 06 10 A0 E1 18 60 84 E5 07 0D 8D E2 ?? ?? ?? EB C0 C1 9D E5 19 7E 8D E2 A8 C1 8D E5 EC C1 9D E5 06 30 A0 E1 0D 10 A0 E1 19 2E A0 E3 07 00 A0 E1 BC C1 8D E5 AC B1 8D E5 }
	condition:
		$pattern
}

rule __md5_Transform_a9e13e82c9d2e66faf53e7f8dbffa928 {
	meta:
		aliases = "__md5_Transform"
		size = "428"
		objfiles = "md5@libcrypt.a"
	strings:
		$pattern = { F0 4F 2D E9 00 C0 A0 E3 50 D0 4D E2 00 70 A0 E1 01 40 A0 E1 0C E0 A0 E1 0B 00 00 EA 02 30 D0 E5 0C 20 D4 E7 01 10 D0 E5 03 00 D0 E5 03 38 A0 E1 00 3C 83 E1 01 24 82 E1 03 20 82 E1 10 30 8D E2 0E 21 83 E7 04 C0 8C E2 01 E0 8E E2 3F 00 5C E3 0C 00 84 E0 F0 FF FF 9A 40 11 9F E5 07 80 A0 E1 04 B0 98 E4 08 10 8D E5 34 21 9F E5 0C 10 87 E2 70 00 97 E9 2C 91 9F E5 08 30 87 E2 04 10 8D E5 00 A0 A0 E3 0B 10 A0 E1 0C 20 8D E5 00 30 8D E5 2C 00 00 EA 0F 00 1A E3 04 90 89 02 03 00 53 E3 03 F1 9F 97 03 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 E0 A0 E1 0D 00 00 EA 05 30 04 E0 04 20 C6 E1 }
	condition:
		$pattern
}

rule svcudp_bufcreate_2967875070e19242f175bf4e7bb02fc6 {
	meta:
		aliases = "__GI_svcudp_bufcreate, svcudp_bufcreate"
		size = "544"
		objfiles = "svc_udp@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 00 70 E3 1C D0 4D E2 10 30 A0 E3 00 60 A0 E1 18 30 8D E5 01 B0 A0 E1 02 80 A0 E1 00 70 A0 13 0A 00 00 1A 02 00 A0 E3 00 10 A0 E1 11 20 A0 E3 ?? ?? ?? EB 00 60 50 E2 01 70 A0 A3 03 00 00 AA C0 01 9F E5 ?? ?? ?? EB 00 A0 A0 E3 6A 00 00 EA 04 40 8D E2 00 10 A0 E3 10 20 A0 E3 04 00 A0 E1 ?? ?? ?? EB 00 50 A0 E3 02 30 A0 E3 06 00 A0 E1 04 10 A0 E1 04 30 CD E5 05 50 CD E5 ?? ?? ?? EB 05 00 50 E1 05 00 00 0A 06 00 A0 E1 04 10 A0 E1 18 20 9D E5 06 50 CD E5 07 50 CD E5 ?? ?? ?? EB 04 10 A0 E1 06 00 A0 E1 18 20 8D E2 ?? ?? ?? EB 00 90 50 E2 08 00 00 0A 4C 01 9F E5 ?? ?? ?? EB 00 00 57 E3 }
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

rule __GI_rexec_af_2461658c6e2aa4386449726a07e85887 {
	meta:
		aliases = "rexec_af, __GI_rexec_af"
		size = "1052"
		objfiles = "rexec@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 18 A0 E1 61 DF 4D E2 21 C4 A0 E1 FF CC 0C E2 55 6F 8D E2 00 80 A0 E1 10 20 8D E5 0C 30 8D E5 B0 41 9D E5 06 00 A0 E1 02 90 A0 E1 03 B0 A0 E1 C0 23 9F E5 21 3C 8C E1 20 10 A0 E3 4D 5F 8D E2 AC A1 9D E5 ?? ?? ?? EB 00 30 A0 E3 03 10 A0 E1 20 20 A0 E3 05 00 A0 E1 04 48 A0 E1 73 31 CD E5 24 48 A0 E1 ?? ?? ?? EB 02 70 A0 E3 00 00 98 E5 06 10 A0 E1 05 20 A0 E1 01 60 A0 E3 5F 3F 8D E2 38 41 8D E5 3C 61 8D E5 34 71 8D E5 ?? ?? ?? EB 00 50 50 E2 D3 00 00 1A 7C 31 9D E5 18 10 93 E5 00 00 51 E3 0C 00 00 0A 4C 43 9F E5 4C 23 9F E5 04 00 A0 E1 ?? ?? ?? EB 00 54 C4 E5 00 40 88 E5 7C 31 9D E5 }
	condition:
		$pattern
}

rule __prefix_array_68d52301a22fb770537bc701904dd968 {
	meta:
		aliases = "__prefix_array"
		size = "184"
		objfiles = "glob@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 70 A0 E1 02 B0 A0 E1 00 90 A0 E1 ?? ?? ?? EB 01 00 50 E3 00 60 A0 E1 02 00 00 1A 00 30 D9 E5 2F 60 53 E2 01 60 A0 13 00 50 A0 E3 1B 00 00 EA 04 00 97 E7 ?? ?? ?? EB 01 80 80 E2 01 00 88 E2 00 00 86 E0 ?? ?? ?? EB 00 A0 50 E2 09 10 A0 E1 06 20 A0 E1 07 00 00 1A 01 00 00 EA 05 01 97 E7 ?? ?? ?? EB 00 00 55 E3 01 50 45 E2 FA FF FF 1A 01 00 A0 E3 F0 8F BD E8 ?? ?? ?? EB 2F 30 A0 E3 01 30 C0 E4 08 20 A0 E1 04 10 97 E7 ?? ?? ?? EB 04 00 97 E7 ?? ?? ?? EB 04 A0 87 E7 01 50 85 E2 0B 00 55 E1 05 41 A0 E1 E0 FF FF 3A 00 00 A0 E3 F0 8F BD E8 }
	condition:
		$pattern
}

rule _dl_lookup_hash_3be76ecaf52d51281490065a4a770f1a {
	meta:
		aliases = "_dl_lookup_hash"
		size = "328"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { F0 4F 2D E9 01 70 A0 E1 04 D0 4D E2 02 80 A0 E1 03 B0 A0 E1 00 A0 E0 E3 00 00 8D E5 3B 00 00 EA 00 50 97 E5 24 30 95 E5 23 34 A0 E1 01 30 23 E2 00 00 58 E3 00 30 A0 03 01 30 03 12 00 00 53 E3 0A 00 00 0A 05 00 58 E1 34 20 98 15 04 00 00 1A 06 00 00 EA 04 30 92 E5 05 00 53 E1 03 00 00 0A 00 20 92 E5 00 00 52 E3 F9 FF FF 1A 26 00 00 EA 02 00 1B E3 02 00 00 0A 18 30 95 E5 01 00 53 E3 21 00 00 0A 28 10 95 E5 00 00 51 E3 1E 00 00 0A 01 00 7A E3 58 90 95 E5 00 C0 9D 05 01 A0 8A 02 05 00 00 0A 07 00 00 EA 0A 32 80 E0 0F 22 03 E2 02 30 23 E0 22 AC 23 E0 01 C0 8C E2 00 00 DC E5 00 00 50 E3 F7 FF FF 1A }
	condition:
		$pattern
}

rule __ns_name_ntop_498fbbd3e928aee3ca4b7ccaf8b612f1 {
	meta:
		aliases = "__GI___ns_name_ntop, __ns_name_ntop"
		size = "424"
		objfiles = "ns_name@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 80 A0 E1 02 A0 81 E0 00 B0 A0 E1 01 60 A0 E1 4D 00 00 EA C0 00 19 E3 5A 00 00 1A 08 00 56 E1 08 60 A0 01 03 00 00 0A 0A 00 56 E1 55 00 00 2A 2E 30 A0 E3 01 30 C6 E4 09 30 86 E0 0A 00 53 E1 50 00 00 2A 01 B0 8B E2 3D 00 00 EA 00 70 DB E5 2E 00 57 E3 0A 00 00 0A 03 00 00 CA 22 00 57 E3 07 00 00 0A 24 00 57 E3 04 00 00 EA 40 00 57 E3 03 00 00 0A 5C 00 57 E3 01 00 00 0A 3B 00 57 E3 07 00 00 1A 01 20 86 E2 0A 00 52 E1 3D 00 00 2A 5C 30 A0 E3 01 70 C6 E5 00 30 C6 E5 01 60 82 E2 25 00 00 EA 21 30 47 E2 5D 00 53 E3 1F 00 00 9A 03 30 86 E2 0A 00 53 E1 32 00 00 2A 06 40 A0 E1 5C 30 A0 E3 }
	condition:
		$pattern
}

rule __time_localtime_tzi_ce5989daee32ab9be019b981114dd650 {
	meta:
		aliases = "__time_localtime_tzi"
		size = "852"
		objfiles = "_time_localtime_tzi@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 80 A0 E1 1C D0 4D E2 00 10 A0 E3 04 00 8D E5 00 20 8D E5 08 10 8D E5 08 10 9D E5 18 30 A0 E3 93 01 01 E0 00 30 9D E5 01 20 93 E7 04 30 9D E5 00 00 93 E5 00 33 9F E5 03 00 50 E1 93 3A 62 E2 2A 3D 83 E2 00 20 9D E5 00 30 63 C2 03 30 80 E0 1C 00 8D E2 01 40 82 E0 04 30 20 E5 06 10 E0 D3 07 10 A0 C3 08 20 A0 E1 ?? ?? ?? EB 08 30 9D E5 20 30 88 E5 10 30 94 E4 C0 52 9F E5 00 30 63 E2 04 60 A0 E1 24 30 88 E5 03 00 00 EA ?? ?? ?? EB 00 00 50 E3 16 00 00 0A 00 50 95 E5 04 40 85 E2 00 00 55 E3 04 00 A0 E1 06 10 A0 E1 F6 FF FF 1A 06 00 A0 E1 07 10 A0 E3 ?? ?? ?? EB 06 00 50 E3 0D 00 00 8A }
	condition:
		$pattern
}

rule __GI_xdr_array_62feb7a2a7caa3d1e7fef89e9f03a08e {
	meta:
		aliases = "xdr_array, __GI_xdr_array"
		size = "316"
		objfiles = "xdr_array@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 90 A0 E1 02 10 A0 E1 02 50 A0 E1 03 60 A0 E1 00 A0 A0 E1 24 B0 9D E5 00 40 99 E5 ?? ?? ?? EB 00 00 50 E3 3C 00 00 0A 00 70 95 E5 06 00 57 E1 04 00 00 8A 00 00 E0 E3 0B 10 A0 E1 ?? ?? ?? EB 00 00 57 E1 02 00 00 9A 00 30 9A E5 02 00 53 E3 31 00 00 1A 00 00 54 E3 17 00 00 1A 00 30 9A E5 01 00 53 E3 02 00 00 0A 02 00 53 E3 12 00 00 1A 2B 00 00 EA 00 00 57 E3 29 00 00 0A 9B 07 05 E0 05 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 40 A0 E1 00 00 89 E5 05 00 00 1A 90 30 9F E5 90 00 9F E5 00 10 93 E5 ?? ?? ?? EB 04 50 A0 E1 1D 00 00 EA 05 20 A0 E1 00 10 A0 E3 ?? ?? ?? EB 00 60 A0 E3 01 50 A0 E3 }
	condition:
		$pattern
}

rule _stdlib_strto_l_60b7c395fdda2dfe347fe308583b3613 {
	meta:
		aliases = "_stdlib_strto_l"
		size = "408"
		objfiles = "_stdlib_strto_l@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 90 A0 E1 02 50 A0 E1 03 B0 A0 E1 00 40 A0 E1 00 00 00 EA 01 40 84 E2 70 31 9F E5 00 20 D4 E5 00 30 93 E5 82 30 D3 E7 20 30 13 E2 F8 FF FF 1A 2B 00 52 E3 04 00 00 0A 2D 00 52 E3 03 70 A0 11 01 70 A0 03 01 00 00 0A 01 00 00 EA 03 70 A0 E1 01 40 84 E2 10 30 D5 E3 00 60 A0 11 0E 00 00 1A 00 30 D4 E5 30 00 53 E3 0A 50 85 E2 00 60 A0 11 07 00 00 1A 01 30 F4 E5 20 30 83 E3 78 00 53 E3 02 50 45 E2 04 60 A0 01 04 60 A0 11 85 50 A0 01 01 40 84 02 10 00 55 E3 10 50 A0 A3 02 30 45 E2 22 00 53 E3 00 C0 A0 83 28 00 00 8A 05 10 A0 E1 00 00 E0 E3 ?? ?? ?? EB 05 10 A0 E1 00 30 A0 E1 00 00 E0 E3 }
	condition:
		$pattern
}

rule fnmatch_dadf297b52747c05de708fc9b954158b {
	meta:
		aliases = "__GI_fnmatch, fnmatch"
		size = "1488"
		objfiles = "fnmatch_old@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 90 A0 E1 02 70 A0 E1 01 50 A0 E1 5D 01 00 EA 10 80 17 E2 09 00 00 0A 80 00 1E E3 07 00 00 1A 9C 35 9F E5 00 30 93 E5 8E 20 A0 E1 02 30 D3 E7 01 00 13 E3 8C 35 9F 15 00 30 93 15 02 E0 D3 17 3F 00 5E E3 01 00 80 E2 08 00 00 0A 02 00 00 CA 2A 00 5E E3 34 01 00 1A 3D 00 00 EA 5B 00 5E E3 8F 00 00 0A 5C 00 5E E3 2F 01 00 1A 11 00 00 EA 00 30 D5 E5 00 00 53 E3 4D 01 00 0A 01 20 17 E2 01 00 00 0A 2F 00 53 E3 49 01 00 0A 04 00 17 E3 3B 01 00 0A 2E 00 53 E3 39 01 00 1A 09 00 55 E1 43 01 00 0A 00 00 52 E3 35 01 00 0A 01 30 55 E5 2F 00 53 E3 0A 01 00 EA 02 00 17 E3 0E 00 00 1A 01 E0 D0 E4 }
	condition:
		$pattern
}

rule _stdlib_strto_ll_d6963d966a85f492546773beb5a766f6 {
	meta:
		aliases = "_stdlib_strto_ll"
		size = "540"
		objfiles = "_stdlib_strto_ll@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 01 90 A0 E1 08 D0 4D E2 02 80 A0 E1 03 B0 A0 E1 00 70 A0 E1 00 00 00 EA 01 70 87 E2 F0 31 9F E5 00 20 D7 E5 00 30 93 E5 82 30 D3 E7 20 30 13 E2 F8 FF FF 1A 2B 00 52 E3 04 00 00 0A 2D 00 52 E3 03 A0 A0 11 01 A0 A0 03 01 00 00 0A 01 00 00 EA 03 A0 A0 E1 01 70 87 E2 10 10 D8 E3 0D 00 00 1A 00 30 D7 E5 30 00 53 E3 0A 80 88 E2 07 00 00 1A 01 30 F7 E5 20 30 83 E3 78 00 53 E3 02 80 48 E2 07 00 A0 01 07 00 A0 11 88 80 A0 01 01 70 87 02 10 00 58 E3 10 80 A0 A3 02 30 48 E2 22 00 53 E3 00 40 A0 93 00 50 A0 93 01 00 00 9A 36 00 00 EA 07 00 A0 E1 00 20 D7 E5 30 30 42 E2 FF 60 03 E2 09 00 56 E3 }
	condition:
		$pattern
}

rule __GI_inet_pton_011cb0f2682d05a99bb539cecda36aa7 {
	meta:
		aliases = "inet_pton, __GI_inet_pton"
		size = "528"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 02 00 50 E3 18 D0 4D E2 01 60 A0 E1 00 20 8D E5 02 00 00 0A 0A 00 50 E3 71 00 00 1A 04 00 00 EA 01 00 A0 E1 00 10 9D E5 C0 FF FF EB 00 20 A0 E1 71 00 00 EA 08 00 8D E2 00 10 A0 E3 10 20 A0 E3 ?? ?? ?? EB 00 30 D6 E5 3A 00 53 E3 00 40 A0 E1 10 80 80 E2 02 00 00 1A 01 30 F6 E5 3A 00 53 E3 64 00 00 1A 00 B0 A0 E3 06 A0 A0 E1 0B 70 A0 E1 04 B0 8D E5 32 00 00 EA 88 91 9F E5 05 10 A0 E1 09 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 01 60 86 E2 04 00 00 0A 00 30 69 E0 07 72 83 E1 01 08 57 E3 25 00 00 3A 53 00 00 EA 3A 00 55 E3 16 00 00 1A 04 30 9D E5 00 00 53 E3 04 00 00 1A 00 00 5B E3 4C 00 00 1A }
	condition:
		$pattern
}

rule gethostbyname2_r_12e9804ae70ca5c97a846fff6a47fc32 {
	meta:
		aliases = "__GI_gethostbyname2_r, gethostbyname2_r"
		size = "788"
		objfiles = "gethostbyname2_r@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 02 00 51 E3 50 D0 4D E2 01 40 A0 E1 02 60 A0 E1 03 70 A0 E1 00 A0 A0 E1 74 90 9D E5 7C B0 9D E5 07 00 00 1A 78 C0 9D E5 02 10 A0 E1 03 20 A0 E1 09 30 A0 E1 00 C0 8D E5 04 B0 8D E5 ?? ?? ?? EB A9 00 00 EA 0A 00 51 E3 A1 00 00 1A ?? ?? ?? EB 78 20 9D E5 00 80 A0 E3 00 00 5A E3 00 80 82 E5 9B 00 00 0A ?? ?? ?? EB 00 30 90 E5 78 C0 9D E5 00 80 80 E5 10 30 8D E5 00 50 A0 E1 04 10 A0 E1 0A 00 A0 E1 06 20 A0 E1 07 30 A0 E1 00 12 8D E8 08 B0 8D E5 ?? ?? ?? EB 00 00 50 E3 92 00 00 0A 00 30 9B E5 01 00 53 E3 04 00 00 0A 04 00 53 E3 09 00 00 0A 01 00 73 E3 8B 00 00 1A 03 00 00 EA 02 00 50 E3 }
	condition:
		$pattern
}

rule fde_split_1d49b53fd651c6c2ed05c29c2641eee5 {
	meta:
		aliases = "fde_split"
		size = "324"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 02 60 A0 E1 04 20 92 E5 00 00 52 E3 08 D0 4D E2 02 50 A0 01 00 20 8D E5 00 90 A0 E1 01 A0 A0 E1 03 70 A0 E1 05 40 A0 01 3F 00 00 0A 03 B0 A0 E1 04 81 9F E5 00 30 A0 E3 00 20 9D E5 01 10 83 E2 08 40 A0 E1 01 00 52 E1 06 50 A0 E1 04 10 8D E5 08 40 8B E5 1D 00 00 0A 03 31 A0 E1 08 30 83 E2 03 40 86 E0 08 00 54 E1 05 00 00 1A 0F 00 00 EA 08 40 92 E5 00 30 A0 E3 08 00 54 E1 08 30 82 E5 0A 00 00 0A 00 20 94 E5 09 00 A0 E1 0C 10 95 E5 0F E0 A0 E1 0A F0 A0 E1 08 30 86 E2 04 30 63 E0 03 30 C3 E3 00 00 50 E3 07 20 83 E0 EF FF FF BA 0C 00 9D E8 01 10 83 E2 04 B0 8B E2 01 00 52 E1 04 50 85 E2 }
	condition:
		$pattern
}

rule __GI___ns_name_unpack_adb7f11fc63af0ade086670761f54385 {
	meta:
		aliases = "__ns_name_unpack, __GI___ns_name_unpack"
		size = "300"
		objfiles = "ns_name@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 02 A0 A0 E1 04 D0 4D E2 01 00 52 E1 00 20 A0 33 01 20 A0 23 00 00 5A E1 01 20 82 33 03 40 A0 E1 28 30 9D E5 00 00 52 E3 01 80 A0 E1 00 70 A0 E1 03 B0 84 E0 02 90 A0 01 0A 60 A0 01 00 C0 E0 03 2E 00 00 0A 28 00 00 EA C0 30 15 E2 02 00 00 0A C0 00 53 E3 24 00 00 1A 10 00 00 EA 05 30 84 E0 01 30 83 E2 0B 00 53 E1 1F 00 00 2A 05 60 81 E0 08 00 56 E1 1C 00 00 2A 01 50 C4 E4 01 30 89 E2 04 00 A0 E1 05 20 A0 E1 00 C0 8D E5 03 90 85 E0 ?? ?? ?? EB 00 C0 9D E5 05 40 84 E0 17 00 00 EA 08 00 51 E1 10 00 00 2A 00 00 5C E3 01 30 6A B0 01 C0 83 B2 01 30 D6 E5 3F 20 05 E2 02 34 83 E1 03 60 97 E0 }
	condition:
		$pattern
}

rule __ivaliduser2_6aaffb9cf78910cc25dddc549521807e {
	meta:
		aliases = "__ivaliduser2"
		size = "892"
		objfiles = "rcmd@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 03 90 A0 E1 34 D0 4D E2 00 30 A0 E3 00 A0 A0 E1 02 B0 A0 E1 08 10 8D E5 2C 30 8D E5 30 30 8D E5 C4 00 00 EA 2C 20 8D E2 0C 00 92 E8 02 30 83 E0 00 20 A0 E3 01 20 43 E5 30 40 9D E5 04 10 A0 E1 00 20 D1 E5 00 00 52 E3 01 10 81 E2 04 00 00 0A 10 33 9F E5 00 30 93 E5 82 30 D3 E7 20 00 13 E3 F6 FF FF 1A 23 00 52 E3 00 00 52 13 B1 00 00 0A 04 00 A0 E1 0A 10 A0 E3 ?? ?? ?? EB 00 00 50 E3 17 00 00 1A 10 20 9A E5 18 30 9A E5 03 00 52 E1 0A 00 A0 21 07 00 00 2A 03 00 00 EA 10 20 9A E5 18 30 9A E5 03 00 52 E1 02 00 00 2A 01 30 D2 E4 10 20 8A E5 01 00 00 EA ?? ?? ?? EB 00 30 A0 E1 0A 00 53 E3 }
	condition:
		$pattern
}

rule frame_downheap_4ab259d25af6bd6db1f87f93b13d01c3 {
	meta:
		aliases = "frame_downheap"
		size = "180"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 03 C0 A0 E1 24 90 9D E5 83 30 A0 E1 01 40 83 E2 09 00 54 E1 00 A0 A0 E1 01 B0 A0 E1 02 50 A0 E1 F0 8F BD A8 0C 80 A0 E1 10 00 00 EA 08 11 95 E7 0A 00 A0 E1 00 20 97 E5 0F E0 A0 E1 0B F0 A0 E1 84 30 A0 E1 00 00 50 E3 01 10 83 E2 F0 8F BD A8 08 21 95 E7 00 30 97 E5 01 00 59 E1 08 31 85 E7 04 80 A0 E1 00 20 87 E5 01 40 A0 E1 0E 00 00 DA 01 60 84 E2 04 21 A0 E1 06 00 59 E1 02 70 85 E0 0A 00 A0 E1 E8 FF FF DA 02 10 95 E7 04 20 97 E5 0F E0 A0 E1 0B F0 A0 E1 06 31 A0 E1 00 00 50 E3 03 70 85 B0 06 40 A0 B1 DF FF FF EA F0 8F BD E8 }
	condition:
		$pattern
}

rule _fpmaxtostr_2877fd8b624823e43e6a80429660fee0 {
	meta:
		aliases = "_fpmaxtostr"
		size = "1640"
		objfiles = "_fpmaxtostr@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 03 C2 2D ED 08 70 D3 E5 03 B0 A0 E1 20 30 87 E3 94 D0 4D E2 61 00 53 E3 65 30 A0 E3 7E 30 CD E5 00 80 9B E5 06 30 87 02 06 00 2D E9 02 C1 BD EC 0C 20 9B E5 04 10 9B E5 FF 70 03 02 00 00 58 E3 00 30 A0 E3 06 80 A0 B3 02 00 12 E3 8E 30 CD E5 03 00 8D E8 2B 30 83 12 02 00 00 1A 01 00 12 E3 01 00 00 0A 20 30 A0 E3 8E 30 CD E5 14 F1 94 EE 00 30 A0 E3 1C 30 8D E5 8F 30 CD E5 08 30 83 12 1C 30 8D 15 10 00 00 1A 18 F1 94 EE 06 00 00 1A 89 01 54 EE 18 F1 D0 EE 2D 30 A0 43 00 90 E0 53 00 90 E0 43 8E 30 CD 45 36 00 00 EA 18 F1 D4 EE CB 81 9F ED 84 C1 10 4E 2D 30 A0 43 80 01 14 EE 8E 30 CD 45 }
	condition:
		$pattern
}

rule __kernel_rem_pio2_74c80d3361c78c03e386e181159d230c {
	meta:
		aliases = "__kernel_rem_pio2"
		size = "1744"
		objfiles = "k_rem_pio2@libm.a"
	strings:
		$pattern = { F0 4F 2D E9 03 C2 2D ED 8D DF 4D E2 01 80 43 E2 02 40 A0 E1 00 35 9F E5 00 00 8D E5 03 00 42 E2 64 22 9D E5 01 70 A0 E1 18 10 A0 E3 02 91 93 E7 ?? ?? ?? EB 17 30 E0 E3 00 00 50 E3 00 B0 A0 A1 00 B0 A0 B3 9B 43 23 E0 0B 20 68 E0 18 50 43 E2 09 00 88 E0 00 10 A0 E3 08 00 00 EA 00 00 52 E3 68 62 9D A5 02 31 96 A7 90 31 00 AE 8D CF 8D E2 81 31 8C E0 3C 81 03 ED 01 20 82 E2 01 10 81 E2 00 00 51 E1 88 81 00 EE F3 FF FF DA 00 00 A0 E3 0F 00 00 EA 00 81 93 ED 3C 91 11 ED 81 01 10 EE 80 21 02 EE 00 30 88 E0 00 C0 9D E5 03 30 62 E0 8D 6F 8D E2 08 00 52 E1 83 11 86 E0 82 31 8C E0 01 20 82 E2 F2 FF FF DA }
	condition:
		$pattern
}

rule fde_merge_d0704edf87ac1c4b5d1767646cfe9ef2 {
	meta:
		aliases = "fde_merge"
		size = "240"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 04 C0 93 E5 08 D0 4D E2 00 00 5C E3 00 30 8D E5 04 00 8D E5 01 B0 A0 E1 02 80 A0 E1 30 00 00 0A 04 70 92 E5 01 90 4C E2 00 20 9D E5 09 31 A0 E1 02 30 83 E0 00 00 57 E3 08 A0 93 E5 0C 30 87 10 01 30 43 12 03 31 A0 11 08 60 83 10 06 00 00 1A 0F 00 00 EA 08 30 95 E5 00 00 54 E3 08 30 86 E5 04 60 46 E2 12 00 00 0A 04 70 A0 E1 01 40 47 E2 04 31 A0 E1 08 50 83 E0 04 00 9D E5 08 10 95 E5 0A 20 A0 E1 0F E0 A0 E1 0B F0 A0 E1 00 00 50 E3 EF FF FF CA 07 30 89 E0 03 31 A0 E1 08 30 83 E0 00 00 59 E3 08 A0 83 E5 08 00 00 0A 09 C0 A0 E1 DB FF FF EA 04 70 A0 E1 07 30 89 E0 03 31 A0 E1 08 30 83 E0 }
	condition:
		$pattern
}

rule binary_search_mixed_encoding_f_4a6e94d5d70c923837d16d49664dd6a5 {
	meta:
		aliases = "binary_search_mixed_encoding_fdes"
		size = "184"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 0C D0 4D E2 00 00 8D E5 0C B0 90 E5 04 80 9B E5 00 00 58 E3 01 90 A0 E1 21 00 00 0A 00 A0 A0 E3 0A 20 88 E0 A2 70 A0 E1 07 31 A0 E1 0B 30 83 E0 08 60 93 E5 06 00 A0 E1 EB FF FF EB FF 40 00 E2 00 50 A0 E1 00 10 9D E5 04 00 A0 E1 E6 FE FF EB 08 20 86 E2 00 10 A0 E1 08 30 8D E2 04 00 A0 E1 F7 FE FF EB 00 10 A0 E3 00 20 A0 E1 04 30 8D E2 0F 00 05 E2 F2 FE FF EB 08 20 9D E5 09 00 52 E1 07 80 A0 81 04 00 00 8A 04 30 9D E5 03 30 82 E0 09 00 53 E1 03 00 00 8A 01 A0 87 E2 08 00 5A E1 DE FF FF 3A 00 60 A0 E3 06 00 A0 E1 0C D0 8D E2 F0 8F BD E8 }
	condition:
		$pattern
}

rule scandir_ff2246fce058a929e8acde31cf9a003e {
	meta:
		aliases = "scandir"
		size = "344"
		objfiles = "scandir@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 0C D0 4D E2 04 10 8D E5 02 B0 A0 E1 00 30 8D E5 ?? ?? ?? EB 00 A0 50 E2 00 00 E0 03 4A 00 00 0A ?? ?? ?? EB 00 30 A0 E3 00 20 90 E5 00 50 A0 E1 03 80 A0 E1 03 90 A0 E1 03 60 A0 E1 08 20 8D E5 00 30 80 E5 1F 00 00 EA 00 00 5B E3 04 00 00 0A 0F E0 A0 E1 0B F0 A0 E1 00 00 50 E3 00 00 85 05 18 00 00 0A 00 30 A0 E3 09 00 56 E1 00 30 85 E5 08 00 00 1A 03 00 56 E1 0A 90 A0 03 86 90 A0 11 08 00 A0 E1 09 11 A0 E1 ?? ?? ?? EB 00 00 50 E3 10 00 00 0A 00 80 A0 E1 08 20 D7 E5 09 30 D7 E5 03 44 82 E1 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 08 00 00 0A 07 10 A0 E1 04 20 A0 E1 ?? ?? ?? EB 06 01 88 E7 }
	condition:
		$pattern
}

rule scandir64_22d81524f14cd1dc9f87f48dd9ad6a91 {
	meta:
		aliases = "scandir64"
		size = "344"
		objfiles = "scandir64@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 0C D0 4D E2 04 10 8D E5 02 B0 A0 E1 00 30 8D E5 ?? ?? ?? EB 00 A0 50 E2 00 00 E0 03 4A 00 00 0A ?? ?? ?? EB 00 30 A0 E3 00 20 90 E5 00 50 A0 E1 03 80 A0 E1 03 90 A0 E1 03 60 A0 E1 08 20 8D E5 00 30 80 E5 1F 00 00 EA 00 00 5B E3 04 00 00 0A 0F E0 A0 E1 0B F0 A0 E1 00 00 50 E3 00 00 85 05 18 00 00 0A 00 30 A0 E3 09 00 56 E1 00 30 85 E5 08 00 00 1A 03 00 56 E1 0A 90 A0 03 86 90 A0 11 08 00 A0 E1 09 11 A0 E1 ?? ?? ?? EB 00 00 50 E3 10 00 00 0A 00 80 A0 E1 10 20 D7 E5 11 30 D7 E5 03 44 82 E1 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 08 00 00 0A 07 10 A0 E1 04 20 A0 E1 ?? ?? ?? EB 06 01 88 E7 }
	condition:
		$pattern
}

rule __GI_hsearch_r_69c20622ba75fc57006178397a7454ba {
	meta:
		aliases = "hsearch_r, __GI_hsearch_r"
		size = "456"
		objfiles = "hsearch_r@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 0C D0 4D E2 04 20 8D E5 00 30 8D E5 08 10 8D E5 00 40 A0 E1 ?? ?? ?? EB 04 B0 A0 E1 00 20 A0 E1 01 00 00 EA 02 30 DB E7 00 02 83 E0 01 20 52 E2 FB FF FF 2A 30 10 9D E5 04 90 91 E5 09 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 00 50 A0 11 01 50 A0 03 0C 30 A0 E3 95 03 03 E0 30 20 9D E5 00 A0 92 E5 03 20 9A E7 00 00 52 E3 03 60 8A E0 23 00 00 0A 05 00 52 E1 08 00 00 1A 0B 00 A0 E1 04 10 96 E5 ?? ?? ?? EB 00 00 50 E3 00 10 9D 05 04 30 86 02 01 C0 A0 03 00 30 81 05 46 00 00 0A 05 00 A0 E1 02 10 49 E2 ?? ?? ?? EB 05 40 A0 E1 01 80 80 E2 08 00 54 E1 04 30 89 E0 03 40 68 90 04 40 68 80 05 00 54 E1 }
	condition:
		$pattern
}

rule __drand48_iterate_f16b167de126f5afc1b2eaf80dc76132 {
	meta:
		aliases = "__drand48_iterate"
		size = "252"
		objfiles = "drand48_iter@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 0F 30 D1 E5 0E 20 D1 E5 04 D0 4D E2 03 24 92 E1 04 30 80 E2 01 50 A0 E1 00 80 A0 E1 00 30 8D E5 02 90 80 E2 09 00 00 1A 0B 30 A0 E3 0C 30 C1 E5 01 30 A0 E3 0E 30 C1 E5 B4 30 9F E5 05 40 A0 E3 10 30 81 E5 14 40 81 E5 0F 20 C1 E5 0D 20 C1 E5 00 40 9D E5 01 C0 D9 E5 01 E0 D4 E5 04 00 D8 E5 00 10 D8 E5 01 30 D8 E5 02 20 D8 E5 0E 64 80 E1 03 A4 81 E1 0C 24 82 E1 00 30 A0 E3 00 70 A0 E3 0A 30 83 E1 02 28 A0 E1 02 00 83 E1 06 10 A0 E1 10 20 85 E2 0C 00 92 E8 ?? ?? ?? EB 0D C0 D5 E5 0C 20 D5 E5 0C 34 82 E1 03 50 90 E0 00 60 A1 E2 25 38 A0 E1 06 38 83 E1 02 30 C8 E5 43 C4 A0 E1 45 04 A0 E1 }
	condition:
		$pattern
}

rule binary_search_single_encoding__d34c03c2b15be55c8d1444d5a1167d59 {
	meta:
		aliases = "binary_search_single_encoding_fdes"
		size = "204"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
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

rule _vfprintf_internal_63601cbc0e190466c633b496959e94d3 {
	meta:
		aliases = "_vfprintf_internal"
		size = "1524"
		objfiles = "_vfprintf_internal@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 13 DE 4D E2 08 60 8D E2 00 B0 A0 E1 06 00 A0 E1 02 50 A0 E1 01 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 0C 00 00 AA 08 40 9D E5 04 00 A0 E1 ?? ?? ?? EB 00 10 50 E2 00 20 E0 03 04 20 8D 05 63 01 00 0A 04 00 A0 E1 0B 20 A0 E1 ?? ?? ?? EB 00 30 E0 E3 04 30 8D E5 5D 01 00 EA 06 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 C0 A0 E3 04 C0 8D E5 51 01 00 EA 00 30 D4 E5 00 00 53 E3 25 00 53 13 00 00 A0 03 01 00 A0 13 01 40 84 12 F8 FF FF 1A 02 00 54 E1 0A 00 00 0A 04 50 62 E0 00 00 55 E3 02 00 A0 C1 05 10 A0 C1 0B 20 A0 C1 ?? ?? ?? CB 05 00 50 E1 44 01 00 1A 04 E0 9D E5 05 E0 8E E0 04 E0 8D E5 00 30 D4 E5 }
	condition:
		$pattern
}

rule __add_to_environ_7d94a8daf85d80da114242749cbcf161 {
	meta:
		aliases = "__add_to_environ"
		size = "552"
		objfiles = "setenv@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 14 D0 4D E2 00 30 8D E5 01 80 A0 E1 02 70 A0 E1 00 A0 A0 E1 ?? ?? ?? EB 00 00 58 E3 00 60 A0 E1 08 B0 A0 01 02 00 00 0A 08 00 A0 E1 ?? ?? ?? EB 01 B0 80 E2 04 00 8D E2 C8 11 9F E5 C8 21 9F E5 C8 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 C0 31 9F E5 B4 01 9F E5 0F E0 A0 E1 03 F0 A0 E1 B4 31 9F E5 00 50 93 E5 00 00 55 E3 05 90 A0 01 00 90 A0 13 08 00 00 1A 11 00 00 EA ?? ?? ?? EB 00 00 50 E3 02 00 00 1A 06 30 D4 E7 3D 00 53 E3 06 00 00 0A 01 90 89 E2 04 50 85 E2 00 40 95 E5 00 00 54 E2 0A 10 A0 E1 06 20 A0 E1 F2 FF FF 1A 00 00 55 E3 02 00 00 0A 00 30 95 E5 00 00 53 E3 2F 00 00 1A 54 31 9F E5 }
	condition:
		$pattern
}

rule re_search_2_f4cfbc173420b0aaafad956201379866 {
	meta:
		aliases = "__re_search_2, re_search_2"
		size = "568"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 14 D0 4D E2 02 70 A0 E1 38 20 8D E2 14 00 92 E8 02 A0 87 E0 0A 00 54 E1 00 20 A0 D3 01 20 A0 C3 A4 2F 92 E1 00 60 A0 E1 10 10 8D E5 03 B0 A0 E1 40 50 9D E5 10 80 80 E2 00 03 98 E8 76 00 00 1A 05 30 94 E0 00 50 64 42 01 00 00 4A 0A 00 53 E1 0A 50 64 C0 08 30 96 E5 00 00 53 E3 00 00 55 13 0B 00 00 DA 00 30 96 E5 00 30 D3 E5 0B 00 53 E3 04 00 00 0A 09 00 53 E3 05 00 00 1A 1C 30 D6 E5 80 00 13 E3 02 00 00 1A 00 00 54 E3 62 00 00 CA 01 50 A0 E3 00 00 58 E3 06 00 00 0A 1C 30 D6 E5 08 00 13 E3 03 00 00 1A 06 00 A0 E1 ?? ?? ?? EB 02 00 70 E3 5A 00 00 0A 00 00 58 E3 0A 00 54 11 36 00 00 AA }
	condition:
		$pattern
}

rule __des_crypt_b14a1314e41d430c0d45b8a0ba71750f {
	meta:
		aliases = "__des_crypt"
		size = "388"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { F0 4F 2D E9 18 D0 4D E2 00 40 A0 E1 01 50 A0 E1 47 FC FF EB 08 20 8D E2 05 00 00 EA 00 30 D4 E5 83 30 A0 E1 00 30 C2 E5 01 30 D2 E4 00 00 53 E3 01 40 84 12 08 00 8D E2 02 30 60 E0 08 00 53 E3 F5 FF FF 1A 8C FD FF EB 2C 31 9F E5 00 60 D5 E5 01 00 D5 E5 00 60 C3 E5 01 10 D5 E5 00 00 51 E3 00 10 D3 05 10 B1 9F E5 01 10 CB E5 1E FC FF EB 00 43 A0 E1 06 00 A0 E1 1B FC FF EB 00 00 84 E1 63 FD FF EB 00 00 A0 E3 19 C0 A0 E3 00 10 A0 E1 14 20 8D E2 10 30 8D E2 00 C0 8D E5 68 FE FF EB 00 00 50 E3 04 00 8D E5 00 00 A0 13 30 00 00 1A 10 20 8D E2 04 04 92 E8 22 18 A0 E1 0A 18 81 E1 02 21 A0 E1 B4 30 9F E5 }
	condition:
		$pattern
}

rule inet_ntop4_fd1c0eae35c6ad233fdaf4962733faca {
	meta:
		aliases = "inet_ntop4"
		size = "356"
		objfiles = "ntop@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 1C D0 4D E2 04 10 8D E5 00 20 8D E5 48 11 9F E5 02 20 A0 E3 00 B0 A0 E1 0B 00 8D E2 ?? ?? ?? EB 0D 00 8D E2 00 10 A0 E3 0F 20 A0 E3 ?? ?? ?? EB 00 30 A0 E3 03 80 A0 E1 2D 00 00 EA 08 40 DB E7 01 70 83 E2 1C 20 8D E2 04 00 A0 E1 07 A0 82 E0 ?? ?? ?? EB 30 30 80 E2 11 30 45 E5 11 30 55 E5 30 00 53 E3 08 90 8B E0 0A 10 A0 E3 04 00 A0 E1 09 00 00 1A ?? ?? ?? EB 0A 10 A0 E3 FF 00 00 E2 ?? ?? ?? EB 30 00 80 E2 11 00 45 E5 11 30 55 E5 30 00 53 E3 07 60 A0 11 08 00 00 EA 0A 10 A0 E3 04 00 A0 E1 ?? ?? ?? EB 0A 10 A0 E3 FF 00 00 E2 ?? ?? ?? EB 30 00 80 E2 11 00 4A E5 01 60 87 E2 00 00 D9 E5 }
	condition:
		$pattern
}

rule __read_etc_hosts_r_c28eca19793df226f64219c91d42c95a {
	meta:
		aliases = "__read_etc_hosts_r"
		size = "808"
		objfiles = "read_etc_hosts_r@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 1C D0 4D E2 44 40 9D E5 00 C0 64 E2 03 C0 1C E2 04 20 8D E5 0C 00 8D E5 08 10 8D E5 00 30 8D E5 40 90 9D E5 48 20 9D E5 03 00 00 0A 0C 00 52 E1 B6 00 00 3A 02 20 6C E0 0C 40 84 E0 1F 00 52 E3 B2 00 00 9A 00 00 9D E5 01 00 50 E3 20 B0 84 E2 20 80 42 E2 48 00 00 0A 50 10 9D E5 00 30 E0 E3 03 00 58 E3 00 30 81 E5 A8 00 00 9A 24 30 42 E2 07 00 53 E3 A5 00 00 9A 0F 00 58 E3 A3 00 00 9A 30 30 42 E2 07 00 53 E3 A0 00 00 9A 2C 80 42 E2 38 30 42 E2 08 00 53 E1 03 80 A0 31 2C 50 84 22 38 50 84 32 4F 00 58 E3 24 60 84 E2 30 A0 84 E2 96 00 00 9A ?? ?? ?? EB 00 00 50 E3 0C 00 8D E5 0B 70 A0 11 }
	condition:
		$pattern
}

rule __GI_vfscanf_bfb2a9bd84f1e8650ff80c24382210fc {
	meta:
		aliases = "vfscanf, __GI_vfscanf"
		size = "1660"
		objfiles = "vfscanf@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 1E DE 4D E2 00 A0 A0 E1 00 30 E0 E3 01 50 A0 E1 02 80 A0 E1 01 0C 8D E2 00 10 A0 E3 24 20 A0 E3 24 31 8D E5 ?? ?? ?? EB 34 B0 9A E5 00 00 5B E3 0A 00 00 1A 38 40 8A E2 73 0F 8D E2 18 36 9F E5 18 16 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 08 36 9F E5 0F E0 A0 E1 03 F0 A0 E1 63 0F 8D E2 0A 10 A0 E1 ?? ?? ?? EB F4 35 9F E5 B8 31 8D E5 94 31 9D E5 03 30 D3 E5 A4 31 CD E5 BC 31 9D E5 01 70 A0 E3 C8 31 8D E5 00 30 A0 E3 34 31 8D E5 46 01 00 EA A5 21 DD E5 01 30 A0 E3 02 11 E0 E3 44 31 CD E5 01 20 02 E2 00 30 A0 E3 45 31 CD E5 A5 21 CD E5 9C 11 8D E5 40 11 8D E5 A4 35 9F E5 }
	condition:
		$pattern
}

rule __copy_rpcent_1549703a5d53db3b158c637321cd094e {
	meta:
		aliases = "__copy_rpcent"
		size = "268"
		objfiles = "getrpcent@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 24 B0 9D E5 00 90 50 E2 00 60 A0 E3 01 50 A0 E1 02 A0 A0 E1 03 40 A0 E1 00 60 8B E5 02 00 80 02 F0 8F BD 08 01 00 A0 E1 0C 20 A0 E3 06 10 A0 E1 ?? ?? ?? EB 06 10 A0 E1 04 20 A0 E1 0A 00 A0 E1 ?? ?? ?? EB 0C 00 99 E9 08 30 85 E5 06 10 A0 E1 01 31 92 E7 00 00 53 E3 01 10 81 E2 FB FF FF 1A 01 31 A0 E1 03 00 54 E1 24 00 00 3A 04 80 63 E0 01 60 41 E2 03 70 8A E0 04 A0 85 E5 0F 00 00 EA 04 30 99 E5 04 00 93 E7 ?? ?? ?? EB 01 C0 80 E2 0C 00 58 E1 0C 20 A0 E1 08 80 6C E0 17 00 00 3A 04 30 95 E5 04 70 83 E7 04 00 95 E5 04 30 99 E5 04 00 90 E7 04 10 93 E7 0C 70 87 E0 ?? ?? ?? EB 01 60 46 E2 }
	condition:
		$pattern
}

rule __encode_packet_f1217fdccc4487b8af463384287bc2f3 {
	meta:
		aliases = "__encode_packet"
		size = "312"
		objfiles = "encodep@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 28 40 8D E2 50 00 94 E8 01 A0 A0 E1 02 90 A0 E1 04 10 A0 E1 06 20 A0 E1 03 B0 A0 E1 00 80 A0 E1 ?? ?? ?? EB 00 00 50 E3 F0 8F BD B8 00 50 84 E0 00 70 A0 E3 06 40 60 E0 00 60 A0 E1 07 00 00 EA 07 01 9A E7 ?? ?? ?? EB 00 00 50 E3 01 70 87 E2 F0 8F BD B8 00 60 86 E0 00 50 85 E0 04 40 60 E0 20 30 98 E5 03 00 57 E1 05 10 A0 E1 04 20 A0 E1 F2 FF FF 3A 00 70 A0 E3 07 00 00 EA 07 01 99 E7 ?? ?? ?? EB 00 00 50 E3 01 70 87 E2 F0 8F BD B8 00 60 86 E0 00 50 85 E0 04 40 60 E0 24 30 98 E5 03 00 57 E1 05 10 A0 E1 04 20 A0 E1 F2 FF FF 3A 00 70 A0 E3 07 00 00 EA 07 01 9B E7 ?? ?? ?? EB 00 00 50 E3 }
	condition:
		$pattern
}

rule __res_search_ce2194f9075b9847392c66514d931b8f {
	meta:
		aliases = "__res_search"
		size = "864"
		objfiles = "res_query@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 28 D0 4D E2 18 40 8D E2 00 A0 A0 E1 0C 10 8D E5 04 00 A0 E1 24 13 9F E5 08 20 8D E5 03 90 A0 E1 1C 23 9F E5 1C 33 9F E5 0F E0 A0 E1 03 F0 A0 E1 14 33 9F E5 08 03 9F E5 0F E0 A0 E1 03 F0 A0 E1 08 33 9F E5 04 00 A0 E1 01 10 A0 E3 08 40 93 E5 FC 32 9F E5 0F E0 A0 E1 03 F0 A0 E1 00 00 59 E3 00 00 5A 13 04 00 00 0A 01 00 14 E3 07 00 00 1A ?? ?? ?? EB 01 00 70 E3 04 00 00 1A ?? ?? ?? EB 00 30 E0 E3 03 20 A0 E1 00 30 80 E5 A8 00 00 EA ?? ?? ?? EB 00 40 A0 E3 00 40 80 E5 10 00 8D E5 ?? ?? ?? EB 04 80 A0 E1 01 30 A0 E3 00 60 A0 E1 0A 20 A0 E1 00 30 80 E5 02 00 00 EA 2E 00 53 E3 01 80 88 02 }
	condition:
		$pattern
}

rule clnt_broadcast_8b181b1118cae36b8a4351c59d97f47f {
	meta:
		aliases = "clnt_broadcast"
		size = "1536"
		objfiles = "pmap_rmt@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 29 DC 4D E2 14 D0 4D E2 10 10 8D E5 0C 20 8D E5 08 30 8D E5 14 00 8D E5 ?? ?? ?? EB 01 50 A0 E3 02 3A 8D E2 00 90 A0 E1 02 00 A0 E3 00 10 A0 E1 11 20 A0 E3 08 59 83 E5 ?? ?? ?? EB 00 A0 50 E2 74 05 9F B5 09 00 00 BA 29 3C 8D E2 04 C0 A0 E3 05 10 A0 E1 06 20 A0 E3 08 30 83 E2 00 C0 8D E5 ?? ?? ?? EB 00 00 50 E3 03 00 00 AA 4C 05 9F E5 ?? ?? ?? EB 03 40 A0 E3 45 01 00 EA 40 35 9F E5 54 C0 8D E2 02 EA 8D E2 34 C0 4C E2 00 40 A0 E3 A3 2D 8D E2 0A 00 A0 E1 28 15 9F E5 38 20 82 E2 04 59 CE E5 F8 38 8E E5 FC C8 8E E5 00 A9 8E E5 05 49 CE E5 ?? ?? ?? EB 04 00 50 E1 03 00 00 AA 04 05 9F E5 }
	condition:
		$pattern
}

rule freopen_8f8cfa7fb4c86b223c77187643707b11 {
	meta:
		aliases = "freopen64, freopen"
		size = "400"
		objfiles = "freopen@libc.a, freopen64@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 34 A0 92 E5 20 D0 4D E2 38 50 82 E2 00 00 5A E3 02 40 A0 E1 00 90 A0 E1 01 80 A0 E1 0D 60 A0 E1 48 B1 9F E5 48 71 9F E5 05 20 A0 E1 10 00 8D E2 40 11 9F E5 05 00 00 1A 0F E0 A0 E1 0B F0 A0 E1 05 00 A0 E1 30 31 9F E5 0F E0 A0 E1 03 F0 A0 E1 28 21 9F E5 1C 11 9F E5 0D 00 A0 E1 0F E0 A0 E1 0B F0 A0 E1 10 31 9F E5 10 01 9F E5 0F E0 A0 E1 03 F0 A0 E1 08 21 9F E5 00 30 92 E5 01 30 83 E2 00 30 82 E5 0D 00 A0 E1 01 10 A0 E3 0F E0 A0 E1 07 F0 A0 E1 00 20 D4 E5 01 30 D4 E5 03 54 82 E1 06 2A C5 E3 00 20 C4 E5 00 30 D4 E5 30 30 03 E2 42 24 A0 E1 30 00 53 E3 04 00 A0 E1 01 20 C4 E5 11 00 00 0A }
	condition:
		$pattern
}

rule clnttcp_call_7f35283dec6456a354ea0c21745e5f8d {
	meta:
		aliases = "clnttcp_call"
		size = "708"
		objfiles = "clnt_tcp@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 3C D0 4D E2 08 10 8D E5 08 40 90 E5 10 10 94 E5 04 20 8D E5 00 30 8D E5 68 20 8D E2 0C 00 92 E8 00 00 51 E3 08 20 84 05 0C 30 84 05 60 30 9D E5 00 00 53 E3 00 80 A0 E1 4C 50 84 E2 30 A0 84 E2 0E 00 00 1A 08 30 94 E5 00 00 53 E3 0B 00 00 1A 0C 30 94 E5 00 70 53 E2 01 70 A0 13 08 00 00 EA 03 30 A0 E3 02 00 00 EA 07 00 A0 E1 8F 00 00 EA 05 30 A0 E3 03 00 A0 E1 24 30 84 E5 8B 00 00 EA 01 70 A0 E3 02 90 A0 E3 00 30 A0 E3 00 30 85 E5 24 30 84 E5 00 30 9A E5 01 30 43 E2 00 30 8A E5 FF E8 03 E2 FF CC 03 E2 2E E4 A0 E1 0C C4 A0 E1 03 CC 8C E1 23 EC 8E E1 05 00 A0 E1 04 30 95 E5 30 10 84 E2 }
	condition:
		$pattern
}

rule clntunix_call_dc7a93a62c51120550e163f615430b4b {
	meta:
		aliases = "clntunix_call"
		size = "708"
		objfiles = "clnt_unix@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 3C D0 4D E2 08 10 8D E5 08 40 90 E5 10 10 94 E5 04 20 8D E5 00 30 8D E5 68 20 8D E2 0C 00 92 E8 00 00 51 E3 08 20 84 05 0C 30 84 05 60 30 9D E5 00 00 53 E3 00 80 A0 E1 AC 50 84 E2 90 A0 84 E2 0E 00 00 1A 08 30 94 E5 00 00 53 E3 0B 00 00 1A 0C 30 94 E5 00 70 53 E2 01 70 A0 13 08 00 00 EA 03 30 A0 E3 02 00 00 EA 07 00 A0 E1 8F 00 00 EA 05 30 A0 E3 03 00 A0 E1 84 30 84 E5 8B 00 00 EA 01 70 A0 E3 02 90 A0 E3 00 30 A0 E3 00 30 85 E5 84 30 84 E5 00 30 9A E5 01 30 43 E2 00 30 8A E5 FF E8 03 E2 FF CC 03 E2 2E E4 A0 E1 0C C4 A0 E1 03 CC 8C E1 23 EC 8E E1 05 00 A0 E1 04 30 95 E5 90 10 84 E2 }
	condition:
		$pattern
}

rule clntraw_call_f7078f104fa559257417da2710bc1947 {
	meta:
		aliases = "clntraw_call"
		size = "520"
		objfiles = "clnt_raw@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 40 D0 4D E2 00 10 8D E5 00 70 A0 E1 02 90 A0 E1 03 A0 A0 E1 ?? ?? ?? EB A0 60 90 E5 00 00 56 E3 68 B0 9D E5 0C 40 86 E2 10 50 A0 03 6E 00 00 0A 00 50 A0 E3 05 10 A0 E1 04 30 94 E5 00 50 84 E5 04 00 A0 E1 0F E0 A0 E1 14 F0 93 E5 8A 1D 86 E2 04 10 81 E2 00 30 91 E5 98 21 9F E5 01 30 83 E2 02 30 86 E7 90 31 9F E5 04 00 A0 E1 03 20 96 E7 04 30 94 E5 0F E0 A0 E1 0C F0 93 E5 05 00 50 E1 04 80 8D E2 0D 10 A0 E1 04 00 A0 E1 55 00 00 0A 04 30 94 E5 0F E0 A0 E1 04 F0 93 E5 05 00 50 E1 04 10 A0 E1 4F 00 00 0A 00 30 97 E5 03 00 A0 E1 20 30 93 E5 0F E0 A0 E1 04 F0 93 E5 05 00 50 E1 0A 10 A0 E1 }
	condition:
		$pattern
}

rule strftime_9f67298efc8ec13f3a4dc0193efca617 {
	meta:
		aliases = "__GI_strftime, strftime"
		size = "1440"
		objfiles = "strftime@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 40 D0 4D E2 08 10 8D E5 0C 00 8D E5 00 10 A0 E3 03 00 A0 E1 02 40 A0 E1 04 30 8D E5 ?? ?? ?? EB 68 35 9F E5 03 00 50 E1 00 00 A0 C3 01 00 A0 D3 ?? ?? ?? EB 00 10 A0 E3 08 B0 9D E5 14 10 8D E5 04 00 A0 E1 00 00 5B E3 4D 01 00 0A 00 30 D0 E5 00 00 53 E3 0D 00 00 1A 14 20 9D E5 00 00 52 E3 08 30 8D 02 08 40 93 08 03 00 6B 00 00 20 CE 05 44 01 00 0A 14 00 9D E5 40 10 8D E2 01 00 40 E2 00 31 81 E0 14 00 8D E5 28 00 13 E5 EC FF FF EA 25 00 53 E3 00 90 A0 11 09 40 A0 11 04 00 00 1A 01 30 D0 E5 25 00 53 E3 01 90 80 E2 02 00 00 1A 00 40 A0 E1 01 A0 A0 E3 22 01 00 EA 45 00 53 E3 4F 00 53 13 }
	condition:
		$pattern
}

rule do_des_8fc31373e60ff87ecb980fd6c131abe2 {
	meta:
		aliases = "do_des"
		size = "1104"
		objfiles = "des@libcrypt.a"
	strings:
		$pattern = { F0 4F 2D E9 40 D0 4D E2 64 40 9D E5 00 00 54 E3 00 70 A0 E1 01 E0 A0 E1 28 20 8D E5 24 30 8D E5 01 00 A0 03 FC 00 00 0A F4 83 9F C5 F4 93 9F C5 38 80 8D C5 3C 90 8D C5 06 00 00 CA 64 10 9D E5 E4 C3 9F E5 E4 03 9F E5 00 10 61 E2 38 C0 8D E5 3C 00 8D E5 64 10 8D E5 D4 03 9F E5 D4 23 9F E5 27 37 A0 E1 27 4C A0 E1 FF 3F 03 E2 02 80 83 E0 FF 60 07 E2 2C 40 8D E5 00 30 83 E0 2E 1C A0 E1 2E C7 A0 E1 06 61 A0 E1 FF 50 0E E2 00 34 93 E5 00 84 98 E5 2C 90 9D E5 02 B0 86 E0 01 11 A0 E1 FF CF 0C E2 05 51 A0 E1 02 A0 81 E0 1C 30 8D E5 14 80 8D E5 09 31 90 E7 02 80 8C E0 02 90 85 E0 00 10 81 E0 00 60 86 E0 }
	condition:
		$pattern
}

rule statfs64_eed6bc0edb1ed2367ff44708c2a19634 {
	meta:
		aliases = "fstatfs64, __GI_statfs64, __GI_fstatfs64, statfs64"
		size = "204"
		objfiles = "fstatfs64@libc.a, statfs64@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 44 D0 4D E2 04 40 8D E2 01 B0 A0 E1 04 10 A0 E1 ?? ?? ?? EB 00 00 50 E3 2C 10 84 E2 40 00 8B E2 00 30 E0 E3 14 20 A0 E3 23 00 00 BA 20 30 9D E5 00 30 8D E5 0C 30 9D E5 03 40 A0 E1 00 50 A0 E3 10 30 9D E5 08 40 8B E5 0C 50 8B E5 03 40 A0 E1 00 50 A0 E3 10 40 8B E5 14 50 8B E5 1C 50 9D E5 14 80 9D E5 05 30 A0 E1 00 40 A0 E3 18 60 9D E5 08 C0 9D E5 24 E0 9D E5 28 A0 9D E5 28 30 8B E5 2C 40 8B E5 04 30 9D E5 00 40 9D E5 00 90 A0 E3 00 70 A0 E3 08 10 8B E8 18 80 8B E5 1C 90 8B E5 20 60 8B E5 24 70 8B E5 34 E0 8B E5 30 40 8B E5 38 A0 8B E5 ?? ?? ?? EB 00 30 A0 E3 03 00 A0 E1 44 D0 8D E2 }
	condition:
		$pattern
}

rule strptime_d88a731dcd4bd12ffc34a1b164f08997 {
	meta:
		aliases = "__GI_strptime, strptime"
		size = "1092"
		objfiles = "strptime@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 50 D0 4D E2 00 20 8D E5 00 70 A0 E1 00 C0 A0 E3 01 00 A0 E1 50 10 8D E2 0C 21 81 E0 01 C0 8C E2 02 31 A0 E3 0C 00 5C E3 4C 30 02 E5 F8 FF FF DA 00 60 A0 E1 00 90 A0 E3 00 30 D6 E5 00 00 53 E3 15 00 00 1A 00 00 59 E3 0E 00 00 1A 1C 30 9D E5 07 00 53 E3 1C 90 8D 05 09 20 A0 E1 50 00 8D E2 02 31 80 E0 4C 30 13 E5 02 01 53 E3 00 10 9D 15 02 31 81 17 01 20 82 E2 07 00 52 E3 F6 FF FF DA 07 00 A0 E1 E7 00 00 EA 01 90 49 E2 50 20 8D E2 09 31 82 E0 18 60 13 E5 E6 FF FF EA 25 00 53 E3 CC 00 00 1A 01 30 F6 E5 25 00 53 E3 C9 00 00 0A 45 00 53 E3 4F 00 53 13 3F 00 A0 13 03 00 00 1A 4F 00 53 E3 }
	condition:
		$pattern
}

rule gethostbyname_r_1b4269d555f1e795e305f02233b730ed {
	meta:
		aliases = "__GI_gethostbyname_r, gethostbyname_r"
		size = "884"
		objfiles = "gethostbyname_r@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 50 D0 4D E2 02 70 A0 E1 74 20 9D E5 00 B0 50 E2 00 60 A0 E3 01 A0 A0 E1 03 40 A0 E1 00 60 82 E5 16 00 80 02 C8 00 00 0A ?? ?? ?? EB 74 C0 9D E5 00 80 90 E5 00 60 80 E5 04 C0 8D E5 78 C0 9D E5 00 50 A0 E1 02 10 A0 E3 0B 00 A0 E1 0A 20 A0 E1 07 30 A0 E1 00 40 8D E5 08 C0 8D E5 ?? ?? ?? EB 00 00 50 E3 B8 00 00 0A 78 20 9D E5 00 30 92 E5 01 00 53 E3 06 00 00 0A 04 00 53 E3 04 00 00 0A 01 00 73 E3 B0 00 00 1A 00 30 95 E5 02 00 53 E3 AD 00 00 1A 00 30 67 E2 03 30 13 E2 00 80 85 E5 03 00 00 0A 03 00 54 E1 A6 00 00 3A 04 40 63 E0 03 70 87 E0 78 30 9D E5 00 C0 E0 E3 03 00 54 E3 00 C0 83 E5 }
	condition:
		$pattern
}

rule vsyslog_fb4f9c84a24f299bfbd2c332d25e6341 {
	meta:
		aliases = "__GI_vsyslog, vsyslog"
		size = "980"
		objfiles = "syslog@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 52 DE 4D E2 0C D0 4D E2 12 4D 8D E2 0C 40 84 E2 00 50 A0 E1 01 90 A0 E1 02 B0 A0 E1 00 10 A0 E3 8C 20 A0 E3 04 00 A0 E1 ?? ?? ?? EB 50 33 9F E5 04 00 84 E2 8C 34 8D E5 ?? ?? ?? EB 04 10 A0 E1 01 2B 8D E2 0D 00 A0 E3 ?? ?? ?? EB ?? ?? ?? EB 00 A0 A0 E1 51 0E 8D E2 28 13 9F E5 28 23 9F E5 08 00 80 E2 24 33 9F E5 00 60 9A E5 0F E0 A0 E1 03 F0 A0 E1 18 33 9F E5 0C 03 9F E5 0F E0 A0 E1 03 F0 A0 E1 0C 33 9F E5 00 10 93 E5 07 20 05 E2 01 30 A0 E3 13 32 11 E0 AC 00 00 0A FF 2F C5 E3 03 20 C2 E3 00 00 52 E3 A8 00 00 1A E8 32 9F E5 00 30 93 E5 00 00 53 E3 03 00 00 BA DC 32 9F E5 00 30 93 E5 }
	condition:
		$pattern
}

rule gethostbyaddr_r_6ababfa8f64fb02fb68350c64050dae1 {
	meta:
		aliases = "__GI_gethostbyaddr_r, gethostbyaddr_r"
		size = "912"
		objfiles = "gethostbyaddr_r@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 58 D0 4D E2 10 20 8D E5 84 20 9D E5 00 40 50 E2 00 00 A0 E3 01 80 A0 E1 03 A0 A0 E1 00 00 82 E5 7C 70 9D E5 80 50 9D E5 C0 00 00 0A 00 10 A0 E1 28 20 A0 E3 1C 00 8D E2 ?? ?? ?? EB 10 30 9D E5 02 00 53 E3 02 00 00 0A 0A 00 53 E3 B7 00 00 1A 01 00 00 EA 04 00 58 E3 00 00 00 EA 10 00 58 E3 B2 00 00 1A 84 C0 9D E5 08 C0 8D E5 88 C0 9D E5 04 00 A0 E1 08 10 A0 E1 10 20 9D E5 0A 30 A0 E1 00 70 8D E5 04 50 8D E5 0C C0 8D E5 ?? ?? ?? EB 00 00 50 E3 B0 00 00 0A 88 20 9D E5 00 30 92 E5 01 00 53 E3 01 00 00 0A 04 00 53 E3 AA 00 00 1A ?? ?? ?? EB 88 C0 9D E5 00 30 E0 E3 03 00 55 E3 00 30 8C E5 }
	condition:
		$pattern
}

rule _time_mktime_tzi_532b1a75f19be3379020350e92913a3c {
	meta:
		aliases = "_time_mktime_tzi"
		size = "888"
		objfiles = "_time_mktime_tzi@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 64 D0 4D E2 20 00 8D E5 34 90 8D E2 18 20 8D E5 1C 10 8D E5 2C 20 A0 E3 20 10 9D E5 09 00 A0 E1 ?? ?? ?? EB 18 10 9D E5 28 30 D1 E5 00 00 53 E3 54 30 8D 05 54 E0 9D E5 00 00 5E E3 20 20 89 E2 30 E0 8D 05 04 00 00 0A 01 30 A0 C3 00 30 E0 D3 00 30 82 E5 01 20 A0 E3 30 20 8D E5 14 40 99 E5 19 1E A0 E3 04 00 A0 E1 ?? ?? ?? EB 19 8E A0 E3 90 08 03 E0 10 50 99 E5 00 20 A0 E1 0C 10 A0 E3 05 00 A0 E1 04 40 63 E0 18 20 89 E5 ?? ?? ?? EB 0C 30 A0 E3 90 03 03 E0 05 30 63 E0 00 00 53 E3 00 20 84 E0 14 20 89 E5 01 20 42 B2 14 20 89 B5 10 30 89 E5 0C 30 83 B2 10 30 89 B5 14 30 99 E5 14 40 89 E2 }
	condition:
		$pattern
}

rule __gen_tempname_ff14e2956d37bf12a6f9c6138312e041 {
	meta:
		aliases = "__gen_tempname"
		size = "696"
		objfiles = "tempname@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 78 D0 4D E2 00 90 A0 E1 00 10 8D E5 ?? ?? ?? EB 00 B0 A0 E1 09 00 A0 E1 ?? ?? ?? EB 00 20 9B E5 05 00 50 E3 0C 20 8D E5 08 00 00 9A 00 30 89 E0 06 30 43 E2 04 30 8D E5 03 00 A0 E1 54 12 9F E5 ?? ?? ?? EB 00 00 50 E3 08 00 8D 05 86 00 00 0A 00 00 E0 E3 16 30 A0 E3 89 00 00 EA 38 02 9F E5 00 10 A0 E3 ?? ?? ?? EB 00 50 50 E2 04 00 00 AA 28 02 9F E5 02 1B A0 E3 ?? ?? ?? EB 00 50 50 E2 08 00 00 BA 72 10 8D E2 06 20 A0 E3 05 00 A0 E1 ?? ?? ?? EB 00 40 A0 E1 05 00 A0 E1 ?? ?? ?? EB 06 00 54 E3 37 00 00 0A 00 10 A0 E3 68 00 8D E2 ?? ?? ?? EB 6C 30 9D E5 C3 4F A0 E1 04 48 A0 E1 68 20 9D E5 }
	condition:
		$pattern
}

rule byte_regex_compile_1a300b052452eaf288553bc6b5a073a2 {
	meta:
		aliases = "byte_regex_compile"
		size = "8924"
		objfiles = "regex_old@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 7B DF 4D E2 10 00 8D E5 0C 20 8D E5 10 20 9D E5 E4 21 8D E5 03 50 A0 E1 14 30 93 E5 01 10 82 E0 0A 0D A0 E3 18 10 8D E5 1C 30 8D E5 ?? ?? ?? EB 00 00 50 E3 44 00 8D E5 7E 08 00 0A 1C 30 D5 E5 08 30 C3 E3 1C 30 C5 E5 1C 30 D5 E5 40 30 C3 E3 1C 30 C5 E5 1C 30 D5 E5 20 30 C3 E3 1C 30 C5 E5 44 3F 9F E5 00 40 93 E5 0C C0 9D E5 00 30 A0 E3 00 00 54 E3 18 30 85 E5 0C C0 85 E5 08 30 85 E5 16 00 00 1A 04 10 A0 E1 20 0F 9F E5 01 2C A0 E3 ?? ?? ?? EB 04 10 A0 E1 08 00 00 EA 10 3F 9F E5 00 30 93 E5 03 30 82 E0 01 30 D3 E5 08 00 13 E3 F8 3E 9F 15 01 20 A0 13 01 20 C3 17 01 10 81 E2 FF 00 51 E3 }
	condition:
		$pattern
}

rule _vfwprintf_internal_600875f308e7c0c83a045da6ad610540 {
	meta:
		aliases = "_vfwprintf_internal"
		size = "1704"
		objfiles = "_vfwprintf_internal@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 91 DF 4D E2 01 50 A0 E1 00 B0 A0 E1 00 10 A0 E3 02 40 A0 E1 42 0F 8D E2 98 20 A0 E3 ?? ?? ?? EB 20 C1 9D E5 00 E0 A0 E3 91 1F 8D E2 01 C0 4C E2 23 3E 8D E2 20 C1 8D E5 04 50 21 E5 80 C0 A0 E3 0E 00 A0 E1 00 20 E0 E3 18 C1 8D E5 08 51 8D E5 30 E2 8D E5 ?? ?? ?? EB 01 00 70 E3 28 36 9F 05 08 31 8D 05 27 00 00 0A 09 20 A0 E3 13 1E 8D E2 08 30 A0 E3 01 20 52 E2 04 30 81 E4 FB FF FF 1A 05 20 A0 E1 0C 00 00 EA 25 00 53 E3 09 00 00 1A 04 30 B2 E5 25 00 53 E3 42 0F 8D E2 05 00 00 0A 08 21 8D E5 ?? ?? ?? EB 00 00 50 E3 15 00 00 BA 08 21 9D E5 00 00 00 EA 04 20 82 E2 00 30 92 E5 00 00 53 E3 }
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

rule __mulvdi3_f34b4d09534fbbced524ae2e67c25b47 {
	meta:
		aliases = "__mulvdi3"
		size = "568"
		objfiles = "_mulvdi3@libgcc.a"
	strings:
		$pattern = { F0 4F 2D E9 C0 0F 51 E1 0C D0 4D E2 00 80 A0 E1 01 90 A0 E1 01 A0 A0 E1 00 B0 A0 E1 02 60 A0 E1 03 70 A0 E1 07 00 00 1A C2 0F 53 E1 03 80 A0 E1 24 00 00 1A C0 1F A0 E1 C2 3F A0 E1 ?? ?? ?? EB 0C D0 8D E2 F0 8F BD E8 C6 0F 53 E1 08 20 8D E5 3E 00 00 1A 06 40 A0 E1 00 50 A0 E3 04 20 A0 E1 05 30 A0 E1 00 10 A0 E3 ?? ?? ?? EB 09 20 A0 E1 00 30 A0 E3 03 00 8D E8 04 00 A0 E1 05 10 A0 E1 ?? ?? ?? EB 00 00 59 E3 08 20 9D B5 08 30 9D E5 01 10 62 B0 00 00 53 E3 29 00 00 BA 04 C0 9D E5 0C 60 A0 E1 00 70 A0 E3 00 60 96 E0 01 70 A7 E0 C6 3F A0 E1 07 00 53 E1 1D 00 00 1A 04 60 8D E5 03 00 9D E8 DD FF FF EA }
	condition:
		$pattern
}

rule __dns_lookup_fc00ac4a7d35b05acab9a6eae2a511da {
	meta:
		aliases = "__dns_lookup"
		size = "2060"
		objfiles = "dnslookup@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 C8 D0 4D E2 10 00 8D E5 02 0C A0 E3 0C 10 8D E5 08 20 8D E5 04 30 8D E5 F0 80 9D E5 ?? ?? ?? EB 00 70 A0 E1 A8 07 9F E5 ?? ?? ?? EB 00 00 50 E3 00 00 57 13 00 00 8D E5 00 50 A0 13 01 50 A0 03 B7 01 00 0A 08 10 9D E5 00 00 51 E3 B4 01 00 0A 10 20 9D E5 00 30 D2 E5 00 00 53 E3 B0 01 00 0A 02 00 A0 E1 ?? ?? ?? EB 10 30 9D E5 00 00 83 E0 01 30 50 E5 A4 40 8D E2 2E 00 53 E3 00 30 A0 13 01 30 A0 03 4C 27 9F E5 4C 17 9F E5 04 00 A0 E1 24 30 8D E5 44 37 9F E5 0F E0 A0 E1 03 F0 A0 E1 3C 37 9F E5 2C 07 9F E5 0F E0 A0 E1 03 F0 A0 E1 30 37 9F E5 08 10 9D E5 00 00 93 E5 ?? ?? ?? EB 24 37 9F E5 }
	condition:
		$pattern
}

rule __GI_ttyname_r_24fe08221d9c44fc2d73801b8dfe30b5 {
	meta:
		aliases = "ttyname_r, __GI_ttyname_r"
		size = "348"
		objfiles = "ttyname@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 D0 D0 4D E2 01 B0 A0 E1 58 10 8D E2 02 90 A0 E1 00 40 A0 E1 ?? ?? ?? EB 00 00 50 E3 02 00 00 AA ?? ?? ?? EB 00 40 90 E5 46 00 00 EA 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 14 01 9F 15 3B 00 00 1A 3D 00 00 EA 01 70 80 E2 B0 40 8D E2 07 10 A0 E1 04 00 A0 E1 ?? ?? ?? EB 07 00 A0 E1 ?? ?? ?? EB 00 60 50 E2 05 A0 84 E0 1E 80 65 E2 23 00 00 1A 2B 00 00 EA ?? ?? ?? EB 08 00 50 E1 05 10 A0 E1 0A 00 A0 E1 1D 00 00 8A ?? ?? ?? EB 04 00 A0 E1 0D 10 A0 E1 ?? ?? ?? EB 00 50 50 E2 17 00 00 1A 10 30 9D E5 0F 3A 03 E2 02 0A 53 E3 13 00 00 1A 78 20 9D E5 20 30 9D E5 03 00 52 E1 0F 00 00 1A 7C 20 9D E5 }
	condition:
		$pattern
}

rule __psfs_do_numeric_c1a8f29f620425d7f080bd44f3b2a79a {
	meta:
		aliases = "__psfs_do_numeric"
		size = "1280"
		objfiles = "__psfs_do_numeric@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 DC 34 9F E5 3C B0 90 E5 03 30 8B E0 01 00 5B E3 B0 D0 4D E2 00 70 A0 E1 01 40 A0 E1 01 80 53 E5 1E 00 00 1A BC 54 9F E5 04 00 A0 E1 ?? ?? ?? EB 00 00 50 E3 03 00 00 BA 00 20 D5 E5 00 30 94 E5 03 00 52 E1 05 00 00 0A 04 00 A0 E1 ?? ?? ?? EB 90 34 9F E5 03 00 55 E1 10 00 00 9A 1B 01 00 EA 01 60 F5 E5 00 00 56 E3 EE FF FF 1A 44 30 D7 E5 00 00 53 E3 17 01 00 0A 34 30 97 E5 01 30 83 E2 34 30 87 E5 2C 00 97 E5 38 10 97 E5 00 20 A0 E3 00 30 A0 E3 ?? ?? ?? EB 06 00 A0 E1 0E 01 00 EA 04 00 A0 E1 ?? ?? ?? EB 00 30 94 E5 00 00 53 E3 00 00 E0 B3 08 01 00 BA 2D 00 53 E3 2B 00 53 13 05 50 8D E2 }
	condition:
		$pattern
}

rule _getopt_internal_1dd7ee7e894ee89a5791fd43d51c96cf {
	meta:
		aliases = "_getopt_internal"
		size = "2108"
		objfiles = "getopt@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 E8 C7 9F E5 00 40 9C E5 E4 C7 9F E5 E4 E7 9F E5 00 C0 9C E5 24 D0 4D E2 10 10 8E E8 04 20 8D E5 00 20 D2 E5 3A 00 52 E3 00 C0 A0 03 00 00 50 E3 14 C0 8D E5 08 00 8D E5 01 70 A0 E1 03 60 A0 E1 DC 01 00 DA 00 30 A0 E3 00 00 54 E3 08 30 8E E5 01 30 A0 03 00 30 8E 05 02 00 00 0A 10 30 9E E5 00 00 53 E3 1F 00 00 1A 88 47 9F E5 00 30 94 E5 00 50 A0 E3 20 30 84 E5 24 30 84 E5 78 07 9F E5 1C 50 84 E5 ?? ?? ?? EB 05 00 50 E0 01 00 A0 13 04 20 9D E5 18 00 84 E5 00 30 D2 E5 2D 00 53 E3 01 20 82 02 04 20 8D 05 02 30 A0 03 09 00 00 0A 2B 00 53 E3 04 30 9D 05 01 30 83 02 04 30 8D 05 02 00 00 0A }
	condition:
		$pattern
}

rule vfwscanf_791ab91dd68fa4730745f1a55e9a234c {
	meta:
		aliases = "__GI_vfwscanf, vfwscanf"
		size = "1740"
		objfiles = "vfwscanf@libc.a"
	strings:
		$pattern = { F0 4F 2D E9 F0 D0 4D E2 00 90 A0 E1 00 30 E0 E3 01 50 A0 E1 02 A0 A0 E1 00 10 A0 E3 08 00 8D E2 24 20 A0 E3 2C 30 8D E5 ?? ?? ?? EB 34 10 99 E5 00 00 51 E3 00 10 8D E5 0A 00 00 1A 38 40 89 E2 D4 00 8D E2 64 36 9F E5 64 16 9F E5 04 20 A0 E1 0F E0 A0 E1 03 F0 A0 E1 04 00 A0 E1 54 36 9F E5 0F E0 A0 E1 03 F0 A0 E1 94 00 8D E2 09 10 A0 E1 ?? ?? ?? EB 40 36 9F E5 C0 30 8D E5 9C 30 9D E5 03 30 D3 E5 AC 30 CD E5 30 36 9F E5 05 40 A0 E1 D0 30 8D E5 01 70 A0 E3 00 30 A0 E3 3C 30 8D E5 50 01 00 EA AD 20 DD E5 01 30 A0 E3 02 11 E0 E3 4C 30 CD E5 01 20 02 E2 00 30 A0 E3 4D 30 CD E5 AD 20 CD E5 A4 10 8D E5 }
	condition:
		$pattern
}

rule _dl_load_elf_shared_library_52721270965018f6a477c15cfa09b66a {
	meta:
		aliases = "_dl_load_elf_shared_library"
		size = "2840"
		objfiles = "libdl@libdl.a"
	strings:
		$pattern = { F0 4F 2D E9 F8 D0 4D E2 04 20 8D E5 00 20 A0 E3 00 30 A0 E1 08 10 8D E5 04 00 9D E5 02 10 A0 E1 05 00 90 EF 01 0A 70 E3 00 A0 A0 E1 A4 3A 9F 85 00 10 60 82 00 10 83 85 01 00 00 8A 00 00 50 E3 03 00 00 AA 90 3A 9F E5 02 60 A0 E1 01 20 A0 E3 21 00 00 EA B8 10 8D E2 6C 00 90 EF 01 0A 70 E3 70 3A 9F 85 00 10 60 82 00 10 83 85 01 00 00 8A 00 00 50 E3 0B 00 00 AA 5C 3A 9F E5 01 10 A0 E3 00 10 83 E5 0A 00 A0 E1 06 00 90 EF 01 0A 70 E3 8C 02 00 9A 3C 3A 9F E5 00 10 60 E2 02 60 A0 E1 00 10 83 E5 88 02 00 EA 00 00 53 E3 0C 00 00 0A C1 30 DD E5 03 34 A0 E1 02 5B 13 E2 08 00 00 1A 0A 00 A0 E1 06 00 90 EF }
	condition:
		$pattern
}

rule __pthread_initialize_manager_f99ea09772eac9ea5398fbf37181b37b {
	meta:
		aliases = "__pthread_initialize_manager"
		size = "580"
		objfiles = "pthread@libpthread.a"
	strings:
		$pattern = { F8 31 9F E5 70 40 2D E9 00 20 93 E5 F0 31 9F E5 00 10 93 E5 00 00 52 E3 01 30 A0 E3 9C D0 4D E2 00 30 81 E5 83 FF FF 0B D8 41 9F E5 00 00 94 E5 80 00 A0 E1 20 00 40 E2 ?? ?? ?? EB C8 51 9F E5 00 00 50 E3 00 00 85 E5 00 00 E0 03 69 00 00 0A 00 30 94 E5 B4 61 9F E5 83 30 80 E0 20 30 43 E2 94 00 8D E2 00 30 86 E5 ?? ?? ?? EB 01 00 70 E3 00 40 A0 E1 02 00 00 1A 00 00 95 E5 ?? ?? ?? EB 37 00 00 EA 88 31 9F E5 00 20 93 E5 00 00 52 E3 80 31 9F 15 9C 21 83 15 78 21 9F E5 9C 31 92 E5 00 00 53 E3 1E 00 00 0A 6C 31 9F E5 A0 21 92 E5 00 30 93 E5 02 30 83 E1 80 00 13 E3 18 00 00 0A 58 51 9F E5 00 10 A0 E3 }
	condition:
		$pattern
}

rule __pthread_manager_da389aba83f1cd0beee08de616a0c200 {
	meta:
		aliases = "__pthread_manager"
		size = "1880"
		objfiles = "manager@libpthread.a"
	strings:
		$pattern = { F8 36 9F E5 52 DF 4D E2 50 20 83 E2 C0 40 8D E2 48 10 83 E2 4C 20 83 E5 44 10 83 E5 0C 00 8D E5 04 00 A0 E1 ?? ?? ?? EB D4 36 9F E5 04 00 A0 E1 00 10 93 E5 ?? ?? ?? EB 04 00 A0 E1 05 10 A0 E3 ?? ?? ?? EB BC 36 9F E5 00 30 93 E5 00 00 53 E3 04 00 00 0A B0 36 9F E5 00 10 93 E5 00 00 51 E3 04 00 A0 C1 ?? ?? ?? CB 02 00 A0 E3 C0 10 8D E2 00 20 A0 E3 ?? ?? ?? EB 90 36 9F E5 00 30 93 E5 18 00 93 E5 ?? ?? ?? EB 0C 00 9D E5 2C 10 8D E2 94 20 A0 E3 ?? ?? ?? EB 01 00 70 E3 03 00 00 1A ?? ?? ?? EB 00 30 90 E5 04 00 53 E3 F5 FF FF 0A 01 30 A0 E3 0C 10 9D E5 44 31 CD E5 00 30 A0 E3 45 31 CD E5 40 11 8D E5 }
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

rule __GI___fpclassify_b5c383c0ca503f5d25f546ada7ab898f {
	meta:
		aliases = "__fpclassify, __GI___fpclassify"
		size = "84"
		objfiles = "s_fpclassify@libm.a"
	strings:
		$pattern = { FF 24 C0 E3 44 C0 9F E5 10 40 2D E9 0F 26 C2 E3 01 40 A0 E1 0C C0 00 E0 04 20 82 E1 02 30 9C E1 02 00 A0 E3 10 80 BD 08 00 00 5C E3 03 00 A0 E3 10 80 BD 08 14 30 9F E5 03 00 5C E1 04 00 A0 E3 10 80 BD 18 01 00 72 E2 00 00 A0 33 10 80 BD E8 00 00 F0 7F }
	condition:
		$pattern
}

rule inet_netof_3fc7321e537f8a2755ea0851d0ea49b0 {
	meta:
		aliases = "__GI_inet_netof, inet_netof"
		size = "56"
		objfiles = "inet_netof@libc.a"
	strings:
		$pattern = { FF 28 00 E2 FF 3C 00 E2 22 24 A0 E1 03 34 A0 E1 00 3C 83 E1 20 2C 82 E1 03 20 92 E1 03 31 02 E2 22 0C A0 E1 0E F0 A0 51 02 01 53 E3 22 08 A0 E1 22 04 A0 11 0E F0 A0 E1 }
	condition:
		$pattern
}

rule inet_lnaof_75070186a1fb7d169ab6805df7b474fb {
	meta:
		aliases = "inet_lnaof"
		size = "60"
		objfiles = "inet_lnaof@libc.a"
	strings:
		$pattern = { FF 28 00 E2 FF 3C 00 E2 22 24 A0 E1 03 34 A0 E1 00 3C 83 E1 20 2C 82 E1 03 20 92 E1 03 31 02 E2 FF 04 C2 E3 0E F0 A0 51 02 08 A0 E1 02 01 53 E3 20 08 A0 E1 FF 00 02 12 0E F0 A0 E1 }
	condition:
		$pattern
}

rule ustat_533c66249d4beda92f4f12e453c2c6c9 {
	meta:
		aliases = "ustat"
		size = "72"
		objfiles = "ustat@libc.a"
	strings:
		$pattern = { FF 30 00 E2 20 04 A0 E1 01 0C 80 E1 00 34 83 E1 03 38 A0 E1 10 40 2D E9 23 08 A0 E1 02 10 A0 E1 3E 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule base_from_object_5eaa9111861cb2cec1376dd1f76ae6ed {
	meta:
		aliases = "base_from_object"
		size = "88"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { FF 30 00 E2 FF 00 53 E3 04 E0 2D E5 0C 00 00 0A 70 00 00 E2 20 00 50 E3 04 00 91 05 04 F0 9D 04 05 00 00 DA 30 00 50 E3 08 00 91 05 04 F0 9D 04 50 00 50 E3 02 00 00 0A ?? ?? ?? EB 00 00 50 E3 01 00 00 1A 00 00 A0 E3 04 F0 9D E4 10 00 50 E3 FB FF FF 0A ?? ?? ?? EB }
	condition:
		$pattern
}

rule base_of_encoded_value_ccadb3a97f00021d069e9e4b75e7b1f6 {
	meta:
		aliases = "base_of_encoded_value"
		size = "124"
		objfiles = "unwind_c@libgcc.a"
	strings:
		$pattern = { FF 30 00 E2 FF 00 53 E3 04 E0 2D E5 0C 00 00 0A 70 00 00 E2 20 00 50 E3 0B 00 00 0A 06 00 00 DA 40 00 50 E3 0E 00 00 0A 50 00 50 E3 04 00 00 0A 30 00 50 E3 0D 00 00 0A ?? ?? ?? EB 00 00 50 E3 04 00 00 1A 00 00 A0 E3 04 F0 9D E4 01 00 A0 E1 04 E0 9D E4 ?? ?? ?? EA 10 00 50 E3 F8 FF FF 0A ?? ?? ?? EB 01 00 A0 E1 04 E0 9D E4 ?? ?? ?? EA 01 00 A0 E1 04 E0 9D E4 ?? ?? ?? EA }
	condition:
		$pattern
}

rule size_of_encoded_value_9867f1f829869477a1050510190c38e7 {
	meta:
		aliases = "size_of_encoded_value"
		size = "88"
		objfiles = "unwind_dw2_fde_glibc@libgcc.a"
	strings:
		$pattern = { FF 30 00 E2 FF 00 53 E3 04 E0 2D E5 0F 00 00 0A 07 30 00 E2 04 00 53 E3 03 F1 9F 97 04 00 00 EA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 00 A0 E3 04 F0 9D E4 04 00 A0 E3 04 F0 9D E4 08 00 A0 E3 04 F0 9D E4 00 00 A0 E3 04 F0 9D E4 }
	condition:
		$pattern
}

rule __GI_inet_makeaddr_018b47d373f93112b9ad722cff2f0cc3 {
	meta:
		aliases = "inet_makeaddr, __GI_inet_makeaddr"
		size = "108"
		objfiles = "inet_addr@libc.a"
	strings:
		$pattern = { FF 34 C1 E3 7F 00 50 E3 04 D0 4D E2 00 3C 83 E1 0A 00 00 9A 01 38 A0 E1 23 38 A0 E1 01 08 50 E3 00 38 83 E1 05 00 00 3A FF 30 01 E2 01 04 50 E3 01 10 80 E1 00 34 83 E1 00 10 8D 25 00 00 00 2A 00 30 8D E5 00 20 9D E5 FF 38 02 E2 FF 0C 02 E2 23 34 A0 E1 00 04 A0 E1 02 0C 80 E1 22 3C 83 E1 00 00 83 E1 04 D0 8D E2 0E F0 A0 E1 }
	condition:
		$pattern
}

rule mknod_fa0dcfb2ccfe5be6b77d2ce2bca87ac2 {
	meta:
		aliases = "__GI_mknod, mknod"
		size = "76"
		objfiles = "mknod@libc.a"
	strings:
		$pattern = { FF C0 02 E2 22 24 A0 E1 03 2C 82 E1 02 C4 8C E1 0C C8 A0 E1 01 18 A0 E1 10 40 2D E9 2C 28 A0 E1 21 18 A0 E1 0E 00 90 EF 01 0A 70 E3 00 40 A0 E1 03 00 00 9A ?? ?? ?? EB 00 30 64 E2 00 30 80 E5 00 40 E0 E3 04 00 A0 E1 10 80 BD E8 }
	condition:
		$pattern
}

rule __divsf3_e4310a7c63851085d2eb7182590a33a7 {
	meta:
		aliases = "__aeabi_fdiv, __divsf3"
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

