rule PicusRedReport2026_SesameOp_CloudC2 {
    meta:
        description = "Detects SesameOp backdoor - routes all C2 traffic through OpenAI Assistants API using stolen API keys, masking communications as legitimate AI development. Espionage-focused. Picus Red Report 2026 T1071, T1059.009."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1071, T1059.009"
        malware_family = "SesameOp"

    strings:
        $s_name = "SesameOp" ascii wide nocase
        $api_openai1 = "api.openai.com" ascii wide
        $api_openai2 = "assistants" ascii wide
        $api_openai3 = "Authorization: Bearer sk-" ascii wide
        $api_openai4 = "openai" ascii wide nocase
        $c2_thread = "/v1/threads" ascii wide
        $c2_message = "/v1/messages" ascii wide
        $c2_run = "/v1/runs" ascii wide
        $encrypt1 = "AES" ascii wide
        $encrypt2 = "decrypt" ascii wide nocase
        $encrypt3 = "encrypt" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            $s_name or
            (2 of ($api_openai*) and any of ($c2_*)) or
            (any of ($c2_*) and any of ($api_openai*) and any of ($encrypt*))
        )
}
