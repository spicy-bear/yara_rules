rule Shellcode_IAT_Thunk_Pattern
{
    meta:
        description = "Detects characteristic IAT thunk pattern with indirect jumps"
        author = "spicybear"
        date = "2025-11-07"
        severity = "medium"
        hash = "194e3e3ac9565493a54e0d2e250cac3938d1ff1e4642e6d45d0d5dab8b07b74f"
        
    strings:
        // Indirect jump through IAT: JMP [0x40Cxxx]
        $iat_jmp1 = { FF 25 ?? ?? ?? ?? }
        
        // Specific IAT addresses from analysis
        $iat1 = { FF 25 14 C1 40 00 }  // JMP [0x40C114]
        $iat2 = { FF 25 04 C1 40 00 }  // JMP [0x40C104]
        $iat3 = { FF 25 28 C1 40 00 }  // JMP [0x40C128]
        $iat4 = { FF 25 BC C0 40 00 }  // JMP [0x40C0BC]
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            // Many IAT thunks
            #iat_jmp1 > 20 or
            // Specific known addresses
            3 of ($iat*)
        )
}
