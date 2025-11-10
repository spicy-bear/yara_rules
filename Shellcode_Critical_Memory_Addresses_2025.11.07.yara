rule Shellcode_Critical_Memory_Addresses
{
    meta:
        description = "Detects specific hardcoded memory addresses used in XOR decryption and VM"
        author = "spicybear"
        date = "2025-11-07"
        severity = "high"
        hash_specific = "true"
        hash = "194e3e3ac9565493a54e0d2e250cac3938d1ff1e4642e6d45d0d5dab8b07b74f"
        
    strings:
        // Critical address: 0x00408A0C (XOR key reference)
        $key_addr1 = { 8B 15 0C 8A 40 00 }     // MOV EDX, [0x408A0C]
        $key_addr2 = { 8B [1] 0C 8A 40 00 }    // MOV REG, [0x408A0C]
        
        // Critical address: 0x0040A1C8 (opcode handler table)
        $vm_table1 = { C5 C8 A1 40 00 }        // Part of [EAX*8 + 0x40A1C8]
        $vm_table2 = { 8B [2-3] C8 A1 40 00 } 
        
        // Exception frame: 0x00408BA7
        $except_frame = { 68 A7 8B 40 00 }     // PUSH 0x408BA7
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            // XOR key address (referenced 4 times)
            (#key_addr1 + #key_addr2) >= 2 or
            // VM table address
            ($vm_table1 or $vm_table2) or
            // Exception frame
            $except_frame
        )
}
