rule Bytecode_Handler_Table_Structure
{
    meta:
        description = "Detects bytecode handler function pointer table structure"
        author = "spicybear"
        date = "2025-11-07"
        severity = "high"
        hash = "194e3e3ac9565493a54e0d2e250cac3938d1ff1e4642e6d45d0d5dab8b07b74f"

    strings:
        // 8-byte aligned function pointer table access
        // MOV EAX, [EAX*8 + table_addr]
        $table1 = { 8B 04 C5 ?? ?? ?? ?? C3 }
        $table2 = { 8B 84 C5 ?? ?? ?? ?? }
        
        // Call through EAX after table lookup
        $call_handler = { FF D0 }  // CALL EAX
        
        // Opcode mapping function signature - simplified pattern
        $map_sig1 = { 8B 00 3D ?? ?? ?? ?? 7F }
        $map_sig2 = { B0 ?? C3 }  // MOV AL, opcode; RET
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            ($table1 or $table2) and
            #call_handler > 5 and
            ($map_sig1 and #map_sig2 > 5)
        )
}