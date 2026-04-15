rule HKTL_PicusSim2026_CoffLoader_BOF
{
    meta:
        description = "Detects CoffLoader - a standalone BOF (Beacon Object File) loader that executes COFF object files outside of Cobalt Strike. Used for in-process post-exploitation."
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        reference = "https://github.com/trustedsec/COFFLoader"
        mitre_attack = "T1106"
        score = 90

    strings:
        $s1 = "COFFLoader" ascii wide
        $s2 = "coffloader" ascii wide
        $s3 = "RunCOFF" ascii wide
        $s4 = ".bof" ascii wide
        $s5 = "BeaconPrintf" ascii wide
        $s6 = "BeaconDataParse" ascii wide
        $s7 = "BeaconFormatAlloc" ascii wide
        $s8 = "BeaconOutput" ascii wide
        $s9 = "go_callback" ascii wide

        $coff_magic1 = { 4C 01 }  // IMAGE_FILE_MACHINE_I386
        $coff_magic2 = { 64 86 }  // IMAGE_FILE_MACHINE_AMD64

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (any of ($s*)) or
            (3 of ($s5, $s6, $s7, $s8))
        )
}

rule HKTL_PicusSim2026_BOF_ObjectFile
{
    meta:
        description = "Detects compiled Beacon Object Files (.bof) - COFF objects with Beacon API imports used for in-memory post-exploitation"
        author = "Loaded Potato - Picus Simulation 2026-04-12"
        date = "2026-04-13"
        mitre_attack = "T1106"
        score = 85

    strings:
        $beacon1 = "BeaconPrintf" ascii
        $beacon2 = "BeaconDataParse" ascii
        $beacon3 = "BeaconFormatAlloc" ascii
        $beacon4 = "BeaconOutput" ascii
        $beacon5 = "BeaconFormatPrintf" ascii
        $beacon6 = "BeaconGetSpawnTo" ascii
        $beacon7 = "BeaconInjectProcess" ascii
        $beacon8 = "BeaconUseToken" ascii

        $adcs1 = "adcs_enum" ascii
        $adcs2 = "CA_NAME" ascii
        $adcs3 = "enrollmentServices" ascii

    condition:
        (
            (uint16(0) == 0x4C01 or uint16(0) == 0x8664) and  // COFF magic
            filesize < 1MB and
            2 of ($beacon*)
        ) or
        (
            filesize < 1MB and
            3 of ($beacon*) and
            any of ($adcs*)
        )
}
