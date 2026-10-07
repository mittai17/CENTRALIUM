/*
 * Centralium core rules - original, SAFE detection content. No real malware.
 * meta: severity (info|low|medium|high|critical), verdict (malicious|suspicious; malicious => known-bad
 * short-circuit), family, version, mitre (comma list), attack_stage.
 */

rule CENT_EICAR_Test_File
{
    meta:
        rule_id = "CENT-YARA-0001"
        family = "test"
        severity = "high"
        verdict = "malicious"
        version = "1"
        description = "EICAR antivirus test file (harmless industry test string)"
    strings:
        $head = "X5O!P%@AP[4" ascii
        $tail = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" ascii
    condition:
        filesize < 1KB and $head at 0 and $tail
}

rule CENT_Suspicious_PowerShell_Download_Cradle
{
    meta:
        rule_id = "CENT-YARA-0002"
        family = "script.downloader"
        severity = "high"
        verdict = "suspicious"
        version = "1"
        mitre = "T1059.001,T1105"
        attack_stage = "EXECUTION"
        description = "PowerShell in-memory download-and-execute cradle"
    strings:
        $iex1 = "IEX" nocase ascii wide
        $iex2 = "Invoke-Expression" nocase ascii wide
        $dl1 = "DownloadString" nocase ascii wide
        $dl2 = "Net.WebClient" nocase ascii wide
        $dl3 = "Invoke-WebRequest" nocase ascii wide
        $dl4 = "Start-BitsTransfer" nocase ascii wide
        $hid = "-WindowStyle Hidden" nocase ascii wide
        $enc = "-EncodedCommand" nocase ascii wide
    condition:
        filesize < 2MB and (1 of ($iex*)) and (1 of ($dl*)) and (1 of ($hid, $enc) or #dl1 > 0)
}

rule CENT_Ransom_Note_Like_Text
{
    meta:
        rule_id = "CENT-YARA-0003"
        family = "ransomware.note"
        severity = "high"
        verdict = "suspicious"
        version = "1"
        mitre = "T1486"
        attack_stage = "IMPACT"
        description = "Text resembling a ransom note (files encrypted, payment demand, contact instructions)"
    strings:
        $a1 = "your files have been encrypted" nocase
        $a2 = "all your files are encrypted" nocase
        $b1 = "bitcoin" nocase
        $b2 = "monero" nocase
        $b3 = "decryption key" nocase
        $b4 = "decrypt your files" nocase
        $c1 = ".onion" nocase
        $c2 = "do not try to" nocase
        $c3 = "within 72 hours" nocase
    condition:
        filesize < 200KB and 1 of ($a*) and 2 of ($b*, $c*)
}

rule CENT_Webshell_Generic_Pattern
{
    meta:
        rule_id = "CENT-YARA-0004"
        family = "webshell"
        severity = "high"
        verdict = "suspicious"
        version = "1"
        mitre = "T1505.003"
        attack_stage = "PERSISTENCE"
        description = "Server-side script passing request input to an execution/eval sink"
    strings:
        $php_sink1 = /(eval|assert|system|passthru|shell_exec|exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $php_sink2 = /eval\s*\(\s*base64_decode\s*\(/ nocase
        $jsp = /Runtime\.getRuntime\(\)\.exec\(\s*request\.getParameter/
        $asp = /eval\s*\(\s*Request(\.Form)?\s*[\(\[]/ nocase
        $tag1 = "<?php" nocase
        $tag2 = "<%"
    condition:
        filesize < 1MB and (any of ($tag*)) and any of ($php_sink*, $jsp, $asp)
}
