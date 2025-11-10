rule Bytecode_VM_Opcode_Obfuscation
{
    meta:
        description = "Detects bytecode VM with obfuscated opcodes using large negative constants"
        author = "spicybear"
        date = "2025-11-07"
        severity = "high"
        hash = "194e3e3ac9565493a54e0d2e250cac3938d1ff1e4642e6d45d0d5dab8b07b74f"
        
    strings:
        // Obfuscated opcode constants (negative values near 0xC0000000)
        $opc1 = { 3D 92 00 00 C0 }  // CMP EAX, 0xC0000092
        $opc2 = { 3D 8E 00 00 C0 }  // CMP EAX, 0xC000008E
        $opc3 = { 3D 96 00 00 C0 }  // CMP EAX, 0xC0000096
        $opc4 = { 3D FD 00 00 C0 }  // CMP EAX, 0xC00000FD
        $opc5 = { 3D 05 00 00 C0 }  // CMP EAX, 0xC0000005
        $opc6 = { 05 71 FF FF 3F }  // ADD EAX, 0x3FFFFF71
        
        // Opcode dispatcher pattern: lookup handler from table
        // MOV EAX, [EAX*8 + handler_table]
        $dispatch1 = { 8B 04 C5 ?? ?? ?? ?? }
        $dispatch2 = { 8B 84 C5 ?? ?? ?? ?? }
        
        // Return small opcode values (split into individual patterns)
        $ret_opc1 = { B0 03 C3 }  // MOV AL, 3; RET
        $ret_opc2 = { B0 04 C3 }  // MOV AL, 4; RET
        $ret_opc3 = { B0 05 C3 }  // MOV AL, 5; RET
        $ret_opc4 = { B0 06 C3 }  // MOV AL, 6; RET
        $ret_opc5 = { B0 07 C3 }  // MOV AL, 7; RET
        $ret_opc6 = { B0 08 C3 }  // MOV AL, 8; RET
        $ret_opc7 = { B0 09 C3 }  // MOV AL, 9; RET
        $ret_opc8 = { B0 0B C3 }  // MOV AL, 0xB; RET
        $ret_opc9 = { B0 0C C3 }  // MOV AL, 0xC; RET
        $ret_opc10 = { B0 0D C3 } // MOV AL, 0xD; RET
        $ret_opc11 = { B0 0E C3 } // MOV AL, 0xE; RET
        $ret_opc12 = { B0 16 C3 } // MOV AL, 0x16; RET
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            // Multiple obfuscated opcode checks
            (#opc1 + #opc2 + #opc3 + #opc4 + #opc5 + #opc6) >= 4 and
            // With dispatcher patterns
            ($dispatch1 or $dispatch2) and
            // At least 5 different return opcodes present
            (#ret_opc1 + #ret_opc2 + #ret_opc3 + #ret_opc4 + #ret_opc5 + 
             #ret_opc6 + #ret_opc7 + #ret_opc8 + #ret_opc9 + #ret_opc10 + 
             #ret_opc11 + #ret_opc12) >= 5
        )
}