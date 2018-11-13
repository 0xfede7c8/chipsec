rule lojax_sig {
        meta:
                description = "Lojax is the first UEFI implant found in the wild"
        strings:
                $string1 = "NtfsDxe"
                $string2 = "rpcnetp.exe" wide ascii
                $string3 = "autoche.exe" wide ascii
                $string4 = "HttpSendRequestA"
                $string5 = "svchost.exe"

        condition:
                $string1 and $string2 and $string3 and $string4 and $string5
}
