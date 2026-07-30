

## 🚀 Supported Analysis Pipelines

This tool features a unified, sequential orchestration engine with Zero-Trust cleanup:

1. **Web/API** (`http://` or `https://`): OWASP ZAP ➔ Nikto
2. **Mobile** (`.apk` / `.ipa`): MobSF Static/Dynamic Analysis
3. **Windows Executables** (`.exe`): pefile (Metadata) ➔ Manalyze (Deep Inspection) ➔ YARA (Pattern Matching)
4. **Linux Packages** (`.deb`): dpkg-deb (Extraction) ➔ LIEF (ELF Metadata) ➔ checksec (Security Features) ➔ YARA (Pattern Matching)

*Note: All pipelines enforce Zero-Trust by securely deleting temporary binary data immediately after analysis, and gracefully handle network/Docker timeouts without crashing.*
