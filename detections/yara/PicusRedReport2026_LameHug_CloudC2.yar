rule PicusRedReport2026_LameHug_CloudC2 {
    meta:
        description = "Detects LameHug malware - uses cloud APIs (OpenAI, AWS Lambda) as covert C2 channels, embedding commands in what appears to be legitimate AI prompts or cloud function calls. Classified as superficial AI use. Picus Red Report 2026 T1071."
        author = "Loaded Potato - Picus Red Report 2026 Analysis"
        date = "2026-04-09"
        reference = "https://www.picussecurity.com/red-report-2026"
        mitre_attack = "T1071"
        malware_family = "LameHug"

    strings:
        $s_name = "LameHug" ascii wide nocase
        $cloud1 = "api.openai.com" ascii wide
        $cloud2 = "lambda-url" ascii wide
        $cloud3 = "execute-api" ascii wide
        $cloud4 = "amazonaws.com" ascii wide
        $cloud5 = "sk-" ascii wide
        $cmd1 = "cmd.exe" ascii wide
        $cmd2 = "powershell" ascii wide nocase
        $cmd3 = "/bin/sh" ascii
        $encrypt1 = "base64" ascii wide nocase
        $encrypt2 = "decrypt" ascii wide nocase

    condition:
        filesize < 10MB and
        (
            $s_name or
            (2 of ($cloud*) and any of ($cmd*) and any of ($encrypt*))
        )
}
