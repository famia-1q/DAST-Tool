/*
    iSeeWaves DAST-Tool - Extended Starter Ruleset
    ------------------------------------------------
    Original, generic detection patterns written for this project.
    No content copied from third-party rule repositories, so this file
    carries no external licensing restrictions - safe to include in a
    commercial client handover as-is.

    This is a REASONABLE BASELINE, not a substitute for a maintained
    threat-intel feed. See the accompanying README section on adding a
    properly licensed ruleset (e.g. YARA-Forge's "core" license-clean
    feed) alongside this one for production malware-family coverage.

    Rules are grouped by category. Add more .yar files to this
    directory as needed - it's scanned recursively.
*/

// ---------------------------------------------------------------------
// Packing / obfuscation
// ---------------------------------------------------------------------

rule Suspicious_Packer_Section_Names
{
    meta:
        description = "Section names commonly added by packers/protectors"
        severity = "Medium"
        category = "packing"

    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $aspack = ".aspack" ascii
        $themida = ".themida" ascii
        $vmp = ".vmp0" ascii
        $petite = ".petite" ascii
        $mpress = ".MPRESS1" ascii

    condition:
        any of them
}

rule High_Entropy_Section_Indicator
{
    meta:
        description = "Common packer stub marker strings indicating runtime unpacking"
        severity = "Medium"
        category = "packing"

    strings:
        $s1 = "This program cannot be run in DOS mode" ascii
        $s3 = "UPX!" ascii

    condition:
        $s3 and not $s1
}

// ---------------------------------------------------------------------
// Droppers / embedded payloads
// ---------------------------------------------------------------------

rule Embedded_PE_In_Overlay
{
    meta:
        description = "A second embedded MZ/PE header, often used for droppers/stub loaders"
        severity = "High"
        category = "dropper"

    strings:
        $mz = "MZ"
        $pe = "PE\x00\x00"

    condition:
        #mz > 1 and $pe
}

rule Embedded_Base64_PE_Header
{
    meta:
        description = "Base64-encoded MZ header (TVqQ...), a common way to smuggle a second-stage PE"
        severity = "High"
        category = "dropper"

    strings:
        $b64mz = "TVqQAAMAAAAEAAAA" ascii

    condition:
        $b64mz
}

// ---------------------------------------------------------------------
// Command execution / reverse shells
// ---------------------------------------------------------------------

rule Suspicious_Reverse_Shell_Strings
{
    meta:
        description = "Common reverse-shell / remote-exec strings"
        severity = "High"
        category = "execution"

    strings:
        $s1 = "/bin/sh -i" ascii
        $s2 = "cmd.exe /c" ascii nocase
        $s3 = "nc -e" ascii
        $s4 = "bash -i >&" ascii
        $s5 = "powershell -enc" ascii nocase
        $s6 = "powershell -encodedcommand" ascii nocase
        $s7 = "IEX(New-Object Net.WebClient)" ascii nocase

    condition:
        any of them
}

rule Suspicious_Living_Off_The_Land_Binaries
{
    meta:
        description = "References to common LOLBins used for execution/download in living-off-the-land attacks"
        severity = "Medium"
        category = "execution"

    strings:
        $s1 = "certutil -urlcache" ascii nocase
        $s2 = "bitsadmin /transfer" ascii nocase
        $s3 = "mshta.exe" ascii nocase
        $s4 = "regsvr32 /s /n /u /i:" ascii nocase
        $s5 = "rundll32.exe javascript:" ascii nocase

    condition:
        any of them
}

// ---------------------------------------------------------------------
// Credential harvesting / secrets
// ---------------------------------------------------------------------

rule Hardcoded_Credential_Pattern
{
    meta:
        description = "Hardcoded credential-like assignment patterns in source or config"
        severity = "Medium"
        category = "credentials"

    strings:
        $s1 = /(password|passwd|pwd)\s*[:=]\s*["'][^"'\s]{4,}["']/ nocase
        $s2 = /(api[_-]?key|apikey)\s*[:=]\s*["'][A-Za-z0-9_\-]{10,}["']/ nocase
        $s3 = /(secret[_-]?key)\s*[:=]\s*["'][A-Za-z0-9_\-]{10,}["']/ nocase

    condition:
        any of them
}

rule AWS_Access_Key_Pattern
{
    meta:
        description = "String matching AWS access key ID format (AKIA...)"
        severity = "High"
        category = "credentials"

    strings:
        $aws = /AKIA[0-9A-Z]{16}/

    condition:
        $aws
}

rule Private_Key_Header
{
    meta:
        description = "Embedded PEM private key material"
        severity = "Critical"
        category = "credentials"

    strings:
        $rsa = "-----BEGIN RSA PRIVATE KEY-----" ascii
        $ec = "-----BEGIN EC PRIVATE KEY-----" ascii
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii
        $generic = "-----BEGIN PRIVATE KEY-----" ascii

    condition:
        any of them
}

// ---------------------------------------------------------------------
// Network indicators
// ---------------------------------------------------------------------

rule Hardcoded_IPv4_Address
{
    meta:
        description = "Hardcoded IPv4 addresses (potential C2/callback) - expect noise, review manually"
        severity = "Low"
        category = "network"

    strings:
        $ip = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ ascii

    condition:
        $ip
}

rule Suspicious_Onion_Address
{
    meta:
        description = "Tor .onion address string, worth reviewing in context"
        severity = "Medium"
        category = "network"

    strings:
        $onion = /[a-z2-7]{16,56}\.onion/ ascii nocase

    condition:
        $onion
}

// ---------------------------------------------------------------------
// Ransomware / destructive indicators
// ---------------------------------------------------------------------

rule Ransom_Note_Language
{
    meta:
        description = "Common ransom-note phrasing"
        severity = "Critical"
        category = "ransomware"

    strings:
        $s1 = "your files have been encrypted" ascii nocase
        $s2 = "decrypt your files" ascii nocase
        $s3 = "pay the ransom" ascii nocase
        $s4 = "bitcoin wallet" ascii nocase

    condition:
        2 of them
}

// ---------------------------------------------------------------------
// Cryptomining
// ---------------------------------------------------------------------

rule Cryptominer_Strings
{
    meta:
        description = "Strings commonly associated with embedded cryptocurrency miners"
        severity = "Medium"
        category = "cryptomining"

    strings:
        $s1 = "stratum+tcp://" ascii nocase
        $s2 = "xmrig" ascii nocase
        $s3 = "cryptonight" ascii nocase
        $s4 = "monero" ascii nocase

    condition:
        any of them
}

// ---------------------------------------------------------------------
// Sandbox / analysis evasion
// ---------------------------------------------------------------------

rule Anti_Analysis_Strings
{
    meta:
        description = "Strings suggesting sandbox/VM/debugger evasion checks"
        severity = "Medium"
        category = "evasion"

    strings:
        $s1 = "IsDebuggerPresent" ascii
        $s2 = "CheckRemoteDebuggerPresent" ascii
        $s3 = "vmware" ascii nocase
        $s4 = "virtualbox" ascii nocase
        $s5 = "sbiedll.dll" ascii nocase
        $s6 = "SbieDll" ascii

    condition:
        2 of them
}

// ---------------------------------------------------------------------
// Web shells (relevant given ZAP/web pipeline overlap)
// ---------------------------------------------------------------------

rule PHP_Webshell_Indicators
{
    meta:
        description = "Common PHP web-shell execution primitives"
