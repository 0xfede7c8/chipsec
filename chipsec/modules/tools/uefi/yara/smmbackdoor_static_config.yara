rule smmbackdoor_static_config_VariableGuid {
        meta:
                description = "DXE SMM Backdoor by cr4sh"
	strings:
		// A few hex definitions demonstrating
		$hex_string3 = { 85 2e 45 3a }
                $hex_string1 =     /\xc7\x45.\x85\x2e\x45\x3a.{,20}\xc7\x45.\xca\xa7\x8f\x43.{,20}\xc7\x45.\xa5\xcb\xad\x3a.{,20}\xc7\x45.\x70\xc5\xd0\x1b/
	condition:
		// Match any file containing 
		$hex_string1 or $hex_string3
}
