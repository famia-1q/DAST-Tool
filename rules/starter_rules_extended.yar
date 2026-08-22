/*
    iSeeWaves DAST-Tool - Extended Starter Ruleset
    ------------------------------------------------
    Original, generic detection patterns written for this project.
    No content copied from third-party rule repositories, so this file
    carries no external licensing restrictions - safe to include in a
    commercial client handover as-is.

    This is a REASONABLE BASELINE, not a substitute for a maintained
    threat-intel feed. See README for adding a properly licensed
    ruleset (e.g. YARA-Forge's "core" feed) alongside this one.

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
        description = "UPX runtime-unpacker stub marker, without the normal DOS-stub string preceding it - suggests a modified/stripped stub"
        severity = "Medium"
        category = "packing"

    strings:
        $dos_stub = "This program cannot be run in DOS mode" ascii
        $upx_marker = "UPX!" ascii

    condition:
        $upx_marker and not $dos_stub
}

// ---------------------------------------------------------------------
// Droppers / embedded payloads
// ---------------------------------------------------------------------

rule Embedded_PE_In_Overlay
{
    meta:
        description = "A second full MZ+PE header pair (valid e_lfanew offset to a real PE signature), suggesting an embedded/dropped executable rather than incidental byte overlap"
        severity = "High"
        category = "dropper"

    strings:
        // MZ header followed by a plausible e_lfanew (PE offset) and the actual PE signature
        // shortly after - far more specific than a loose "MZ" + "PE" substring match, which
        // produces false positives on ordinary compiled binaries.
        $mz_pe_pair = /MZ.{56,64}PE\x00\x00/

    condition:
        #mz_pe_pair >= 1
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
        description = "Hardcoded non-loopback, non-broadcast IPv4 address - excludes 127.x/0.0.0.0/255.255.255.255 which are near-universal in compiled binaries and not meaningful signal on their own"
        severity = "Low"
        category = "network"

    strings:
        $ip = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ ascii
        $loopback = "127.0.0.1" ascii
        $unspecified = "0.0.0.0" ascii
        $broadcast = "255.255.255.255" ascii

    condition:
        $ip and not (
            $loopback in (@ip[1]-3..@ip[1]+3) or
            $unspecified in (@ip[1]-3..@ip[1]+3) or
            $broadcast in (@ip[1]-3..@ip[1]+3)
        )
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
// Web shells
// ---------------------------------------------------------------------

rule PHP_Webshell_Indicators
{
    meta:
        description = "Common PHP web-shell execution primitives"
        severity = "High"
        category = "webshell"

    strings:
        $s1 = "eval($_POST" ascii
        $s2 = "eval($_GET" ascii
        $s3 = "eval($_REQUEST" ascii
        $s4 = "system($_" ascii
        $s5 = "assert($_" ascii
        $s6 = "base64_decode($_" ascii
        $s7 = "shell_exec($_" ascii

    condition:
        any of them
}

// ---------------------------------------------------------------------
// Mobile (APK) specific
// ---------------------------------------------------------------------

rule Android_Root_Detection_Bypass_Strings
{
    meta:
        description = "Strings suggesting root-check bypass or su-binary interaction in decompiled smali/manifest"
        severity = "Medium"
        category = "mobile"

    strings:
        $s1 = "/system/bin/su" ascii
        $s2 = "/system/xbin/su" ascii
        $s3 = "Superuser.apk" ascii
        $s4 = "com.noshufou.android.su" ascii
        $s5 = "Runtime.getRuntime().exec(\"su" ascii

    condition:
        any of them
}

rule Android_Insecure_Network_Config
{
    meta:
        description = "Signs of cleartext traffic or trust-all TLS configuration in decompiled output"
        severity = "High"
        category = "mobile"

    strings:
        $s1 = "android:usesCleartextTraffic=\"true\"" ascii
        $s2 = "ALLOW_ALL_HOSTNAME_VERIFIER" ascii
        $s3 = "TrustAllCerts" ascii
        $s4 = "X509TrustManager" ascii

    condition:
        any of them
}
