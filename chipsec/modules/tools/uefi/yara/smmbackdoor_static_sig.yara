rule smmbackdoor_static_sig {
        meta:
                description = "DXE SMM Backdoor by cr4sh"
	strings:
		// A few hex definitions demonstrating
		$setwp_string = /\x50\x0f\x20\xc0\x0d\x00\x00\x01\x00\x0f\x22\xc0\x58\xc3/
	condition:
		// Match any file containing 
		$setwp_string
}
