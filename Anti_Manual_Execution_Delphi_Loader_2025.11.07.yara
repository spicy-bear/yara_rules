rule Anti_Manual_Execution_Delphi_Loader
{
    meta:
        description = "Detects Delphi loader with anti-manual execution protection"
        author = "spicybear"
        date = "2025-11-07"
        severity = "medium"
        hash = "194e3e3ac9565493a54e0d2e250cac3938d1ff1e4642e6d45d0d5dab8b07b74f"
        
    strings:
        // Anti-manual execution string
        $manual_exec = "Executing manually will not work" ascii wide
        
        // Delphi signature strings
        $delphi1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii wide
        $delphi2 = "Software\\Borland\\Delphi\\Locales" ascii wide
        $delphi3 = "FPUMaskValue" ascii wide
        
        // Delphi exception classes
        $except1 = "EInOutError" ascii
        $except2 = "EZeroDivide" ascii
        $except3 = "EInvalidPointer" ascii
        
        // Delphi system units
        $unit1 = "System" ascii
        $unit2 = "SysUtils" ascii
        $unit3 = "SysInit" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        $manual_exec and
        (
            // Strong Delphi indicators
            (2 of ($delphi*)) or
            (2 of ($except*)) or
            (all of ($unit*))
        )
}
