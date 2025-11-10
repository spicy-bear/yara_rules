rule Complete_Shellcode_Delphi_Loader
{
    meta:
        description = "High-confidence detection combining multiple indicators"
        author = "spicybear"
        date = "2025-11-07"
        severity = "critical"
        hash = "194e3e3ac9565493a54e0d2e250cac3938d1ff1e4642e6d45d0d5dab8b07b74f"
        
    strings:
        // Anti-manual execution
        $str1 = "Executing manually will not work" ascii wide
        
        // Delphi
        $str2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii wide
        
        // XOR patterns
        $xor1 = { 0F B6 ?? 03 ?? 99 F7 ?? 85 ?? 75 ?? 8B ?? 48 }
        $xor2 = { 32 [1-3] 88 }
        
        // VM opcodes
        $vm1 = { 3D 92 00 00 C0 }
        $vm2 = { 3D 8E 00 00 C0 }
        $vm3 = { B0 ( 03 | 04 | 05 | 06 | 07 | 08 | 09 ) C3 }
        
        // Memory manipulation APIs
        $api1 = "VirtualAlloc" ascii
        $api2 = "GetProcAddress" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        $str1 and                        // Must have anti-manual execution
        ($str2 or 2 of ($api*)) and     // Delphi or suspicious APIs
        (
            ($xor1 and $xor2) or         // XOR decryption present
            (2 of ($vm*))                // Or VM present
        )
}
