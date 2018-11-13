rule smmbackdoor_static_markers {
        meta:
                description = "DXE SMM Backdoor by cr4sh"
	strings:
		// A few hex definitions demonstrating
		$hex_string1 = { 65 48 8b 04 25 }
	        $hex_string2 = "SmmBackdoor"
	        $hex_string3 = "INFECTED"
	condition:
		// Match any file containing 
		$hex_string1 or $hex_string2 or $hex_string3
}
