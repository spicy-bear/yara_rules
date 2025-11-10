rule Malicious_API_Import_Combination
{
    meta:
        description = "Detects suspicious combination of API imports for process injection/manipulation"
        author = "spicybear"
        date = "2025-11-07"
        severity = "medium"
        hash = "194e3e3ac9565493a54e0d2e250cac3938d1ff1e4642e6d45d0d5dab8b07b74f"
        
    strings:
        // Memory manipulation
        $api1 = "VirtualAlloc" ascii
        $api2 = "VirtualFree" ascii
        $api3 = "VirtualQuery" ascii
        
        // Process/Thread manipulation
        $api4 = "GetModuleHandleA" ascii
        $api5 = "GetProcAddress" ascii
        $api6 = "LoadLibraryA" ascii
        
        // Critical sections (thread sync - unusual for simple apps)
        $api7 = "InitializeCriticalSection" ascii
        $api8 = "EnterCriticalSection" ascii
        $api9 = "LeaveCriticalSection" ascii
        
        // Exception handling
        $api10 = "UnhandledExceptionFilter" ascii
        $api11 = "RaiseException" ascii
        $api12 = "RtlUnwind" ascii
        
        // Thread local storage (TLS - used by malware)
        $api13 = "TlsGetValue" ascii
        $api14 = "TlsSetValue" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            // Memory + dynamic loading + critical sections
            (2 of ($api1, $api2, $api3)) and
            (2 of ($api4, $api5, $api6)) and
            (2 of ($api7, $api8, $api9))
        ) and
        (
            // Plus exception handling or TLS
            (1 of ($api10, $api11, $api12)) or
            (all of ($api13, $api14))
        )
}
