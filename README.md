# PolfileReaderReloaded

> *Resurrected from Microsoft's own abandoned 2016 reference implementation. Now actually works.*

A PowerShell module for parsing Windows Group Policy Registry `.pol` files. Reads binary policy files and extracts registry key/value entries with full type support, deletion marker detection, and clean object output.

##  Features

- **Parse .pol files** — Read `registry.pol` from local/domain Group Policy
- **Full type support** — `REG_SZ`, `REG_DWORD`, `REG_QWORD`, `REG_BINARY`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`
- **Deletion detection** — `**del.` prefixed values properly flagged with `IsDeletion = True`
- **Pipeline support** — Pipe file paths directly into `Read-PolFile`
- **Clean output** — No spam, no cryptic warnings, just structured `GPRegistryPolicy` objects
- **Helper functions** — `New-GPRegistryPolicy`, `Get-RegType`, enum-backed type safety

## 📦 Installation

```powershell
# Clone the repo
git clone https://github.com/Nyxthecoder/PolfileReaderReloaded.git

# Import the module
Import-Module .\PolfileReaderReloaded\PolfileReaderReloaded.psd1
