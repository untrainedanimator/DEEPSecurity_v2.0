/*
 * DEEPSecurity v3.1 starter YARA pack.
 *
 * This file ships with a small set of well-known, public-domain
 * signatures so an operator who flips DEEPSEC_MEMORY_SCAN_YARA_ENABLED=true
 * gets useful signal on day one. Drop additional ``.yar`` / ``.yara``
 * files into this directory to extend coverage; they're loaded
 * automatically on the next scan (the rules cache invalidates on
 * directory mtime).
 *
 * Recommended public rule packs to layer in:
 *   - github.com/Yara-Rules/rules               (broad coverage)
 *   - github.com/Neo23x0/signature-base         (Florian Roth's set)
 *   - github.com/elastic/protections-artifacts  (Elastic, MIT-licensed)
 *
 * Severity convention (read by inspector.scan_pid):
 *   meta.severity = "low" | "medium" | "high" | "critical"
 *
 * Tags convention (carried into the audit-log details):
 *   include the MITRE technique sub-id where applicable, e.g. "T1003"
 */


rule DEEPSEC_Mimikatz_Strings
{
    meta:
        author      = "DEEPSecurity"
        description = "Detects Mimikatz-style identifier strings in memory"
        severity    = "high"
        reference   = "https://github.com/gentilkiwi/mimikatz"
        mitre       = "T1003.001"

    strings:
        $a = "sekurlsa::logonPasswords" ascii nocase
        $b = "kerberos::list" ascii nocase
        $c = "lsadump::sam" ascii nocase
        $d = "privilege::debug" ascii nocase
        $e = "mimikatz # " ascii nocase

    condition:
        2 of them
}


rule DEEPSEC_CobaltStrike_Beacon_Markers
{
    meta:
        author      = "DEEPSecurity"
        description = "Detects strings characteristic of an in-memory Cobalt Strike beacon"
        severity    = "critical"
        reference   = "https://attack.mitre.org/software/S0154/"
        mitre       = "T1071.001"

    strings:
        // Beacon C2 protocol artefacts (public, documented in many
        // Cobalt Strike post-mortems — Mandiant, Talos, etc.).
        $a = "%s as %s\\%s: %d" ascii
        $b = "beacon.x64.dll" ascii nocase
        $c = "beacon.dll" ascii nocase
        $d = "ReflectiveLoader" ascii
        $e = "license_id" ascii nocase
        $f = "sleep_mask" ascii nocase

    condition:
        3 of them
}


rule DEEPSEC_Reflective_DLL_Loader
{
    meta:
        author      = "DEEPSecurity"
        description = "Detects ReflectiveLoader / sRDI markers — fileless DLL injection"
        severity    = "high"
        mitre       = "T1620"

    strings:
        $a = "ReflectiveLoader" ascii
        $b = "_ReflectiveLoader@4" ascii
        $c = "0x80000000" ascii  // typical PE relocation marker text
        $d = "VirtualAlloc" ascii
        $e = "RtlMoveMemory" ascii

    condition:
        $a and 2 of ($b, $c, $d, $e)
}


rule DEEPSEC_PE_Header_In_Heap
{
    meta:
        author      = "DEEPSecurity"
        description = "PE header (MZ/PE) bytes inside a writable heap — possible loaded payload"
        severity    = "medium"
        mitre       = "T1055"
        note        = "Noisier rule. Flip severity to low if false-positive rate is high in your env."

    strings:
        // MZ followed by typical PE start at offset 0x3c — finds
        // unmapped DLLs/EXEs sitting in heap memory.
        $mz_pe = { 4D 5A [56-256] 50 45 00 00 }

    condition:
        $mz_pe
}
