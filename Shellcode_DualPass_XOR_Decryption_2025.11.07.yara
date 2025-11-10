rule Shellcode_DualPass_XOR_Decryption
{
    meta:
        description = "Detects dual-pass XOR decryption shellcode with position-based and cyclic key decryption"
        author = "spicybear""
        date = "2025-11-07"
        severity = "high"
        reference = "Custom shellcode analysis"
        hash = "194e3e3ac9565493a54e0d2e250cac3938d1ff1e4642e6d45d0d5dab8b07b74f"
        
    strings:
        // Position-based XOR: XOR with (length - position)
        $pos_xor1 = { 8B ?? 2B ?? 32 ?? [0-10] 88 }
        $pos_xor2 = { 29 ?? 30 ?? [0-10] 88 }
        
        // Cyclic key advancement with wrap-to-end behavior
        $cyclic1 = { 0F B6 ?? 03 ?? 99 F7 ?? 85 ?? 75 ?? 8B ?? 48 }
        
        // XOR with indexed key access - simplified
        $key_xor1 = { 32 ?? ?? 88 }
        $key_xor2 = { 30 ?? ?? 88 }
        
        // Function epilogue with exception handler cleanup
        $cleanup = { 64 89 ?? 68 ?? ?? ?? ?? 8D ?? 8B ?? B9 03 00 00 00 E8 }
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            // Dual-pass decryption: needs both position-based and cyclic patterns
            (($pos_xor1 or $pos_xor2) and $cyclic1 and ($key_xor1 or $key_xor2)) or
            // Strong match with cleanup pattern
            ($cyclic1 and $cleanup and (#key_xor1 + #key_xor2) > 3)
        )
}