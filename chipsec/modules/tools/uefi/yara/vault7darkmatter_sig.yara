rule vault7darkmatter_sig {
        meta:
                description = "Dark Matter an implant that persists in the EFI firmware of an Apple MacBook Air computer"
        strings:
                // A few hex definitions demonstrating
                $hex_string1 = "DarkMatter"
                $hex_string2 = "DarkSeaSkies"
                $hex_string4 = "DerStarke"
                $hex_string5 = "SeaPea"
                $hex_string6 = "NightSkies"
                $hex_string7 = "xxtea"
        condition:
                // Match any file containing 
                $hex_string1 or $hex_string2 or $hex_string4 or $hex_string5 or $hex_string6 or $hex_string7 
}
