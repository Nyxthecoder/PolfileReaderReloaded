# Constants
$script:REGFILE_SIGNATURE    = 0x67655250  # 'PReg' in ASCII
$script:REGISTRY_FILE_VERSION = 1

# Enums
enum RegType {
    REG_NONE                       = 0
    REG_SZ                         = 1
    REG_EXPAND_SZ                  = 2
    REG_BINARY                     = 3
    REG_DWORD                      = 4
    REG_DWORD_BIG_ENDIAN           = 5
    REG_LINK                       = 6
    REG_MULTI_SZ                   = 7
    REG_RESOURCE_LIST              = 8
    REG_FULL_RESOURCE_DESCRIPTOR   = 9
    REG_RESOURCE_REQUIREMENTS_LIST = 10
    REG_QWORD                      = 11
}

# Simple class without problematic methods
class GPRegistryPolicy {
    [string] $KeyName
    [string] $ValueName
    [RegType] $ValueType
    [int] $ValueLength
    [object] $ValueData
    [bool] $IsDeletion

    GPRegistryPolicy() {
        $this.KeyName     = $null
        $this.ValueName   = $null
        $this.ValueType   = [RegType]::REG_NONE
        $this.ValueLength = 0
        $this.ValueData   = $null
        $this.IsDeletion  = $false
    }

    GPRegistryPolicy([string]$KeyName, [string]$ValueName, [RegType]$ValueType, [int]$ValueLength, [object]$ValueData) {
        $this.KeyName     = $KeyName
        $this.ValueName   = $ValueName
        $this.ValueType   = $ValueType
        $this.ValueLength = $ValueLength
        $this.ValueData   = $ValueData
        $this.IsDeletion  = $ValueName.StartsWith('**del.')
    }
}

# Helper function to get string representation of RegType
function Get-RegTypeString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [RegType]$ValueType
    )
    
    switch ($ValueType) {
        ([RegType]::REG_NONE)      { return "None" }
        ([RegType]::REG_SZ)        { return "String" }
        ([RegType]::REG_EXPAND_SZ) { return "ExpandString" }
        ([RegType]::REG_BINARY)    { return "Binary" }
        ([RegType]::REG_DWORD)     { return "DWord" }
        ([RegType]::REG_MULTI_SZ)  { return "MultiString" }
        ([RegType]::REG_QWORD)     { return "QWord" }
        default                    { return "Unknown" }
    }
}

# Helper function to convert string to RegType
function Get-RegTypeFromString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Type
    )
    
    switch ($Type) {
        "None"         { return [RegType]::REG_NONE }
        "String"       { return [RegType]::REG_SZ }
        "ExpandString" { return [RegType]::REG_EXPAND_SZ }
        "Binary"       { return [RegType]::REG_BINARY }
        "DWord"        { return [RegType]::REG_DWORD }
        "MultiString"  { return [RegType]::REG_MULTI_SZ }
        "QWord"        { return [RegType]::REG_QWORD }
        default        { return [RegType]::REG_NONE }
    }
}

# Your improved functions
function New-GPRegistryPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$KeyName,

        [Parameter(Position=1)]
        [string]$ValueName = $null,

        [Parameter(Position=2)]
        [RegType]$ValueType = [RegType]::REG_NONE,

        [Parameter(Position=3)]
        [int]$ValueLength = $null,

        [Parameter(Position=4)]
        [object]$ValueData = $null
    )

    return [GPRegistryPolicy]::new($KeyName, $ValueName, $ValueType, $ValueLength, $ValueData)
}

function Get-RegType {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$Type
    )
    return Get-RegTypeFromString -Type $Type
}

function Read-PolFile {
    [CmdletBinding()]
    [Alias('Parse-PolFile')]
    [OutputType([System.Collections.Generic.List`1[GPRegistryPolicy]])]
    param (
        [Parameter(Mandatory, Position=0, ValueFromPipeline)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Path
    )

    process {
        try {
            # Read file as bytes
            [byte[]]$policyBytes = [System.IO.File]::ReadAllBytes($Path)

            # Validate signature
            if ($policyBytes.Length -lt 4) {
                throw "File is too small to be a valid .pol file."
            }
            
            $signature = [System.Text.Encoding]::ASCII.GetString($policyBytes[0..3])
            if ($signature -ne 'PReg') {
                throw "Invalid .pol file header in '$Path'. Expected 'PReg' signature, got '$signature'."
            }

            # Validate version
            if ($policyBytes.Length -lt 8) {
                throw "File is too small to contain version information."
            }
            
            $version = [System.BitConverter]::ToInt32($policyBytes, 4)
            if ($version -ne $script:REGISTRY_FILE_VERSION) {
                throw "Unsupported .pol file version in '$Path'. Expected version $($script:REGISTRY_FILE_VERSION), got $version."
            }

            # Initialize results
            $registryPolicies = [System.Collections.Generic.List[GPRegistryPolicy]]::new()
            $currentPosition = 8  # Skip signature (4) + version (4)

            while ($currentPosition -lt $policyBytes.Length - 1) {
                # Check if we have enough room for at least the opening bracket
                if ($currentPosition + 2 -gt $policyBytes.Length) {
                    break
                }

                # Parse key name (between [ and ;) - Unicode encoded
                if ($policyBytes[$currentPosition] -ne 0x5B) {  # '['
                    throw "Invalid format: Expected '[' at position $currentPosition. Found byte: $($policyBytes[$currentPosition])"
                }
                $currentPosition += 2  # Skip '[' (Unicode)

                # Extract key name by scanning for semicolon byte by byte
                $keyNameBytes = [System.Collections.Generic.List[byte]]::new()
                while ($currentPosition + 1 -lt $policyBytes.Length) {
                    if ($policyBytes[$currentPosition] -eq 0x3B -and $policyBytes[$currentPosition + 1] -eq 0x00) {
                        $currentPosition += 2  # Skip ';'
                        break
                    }
                    $keyNameBytes.Add($policyBytes[$currentPosition])
                    $keyNameBytes.Add($policyBytes[$currentPosition + 1])
                    $currentPosition += 2
                }
                $keyName = [System.Text.Encoding]::Unicode.GetString($keyNameBytes.ToArray()).TrimEnd([char]0)

                # Extract value name by scanning for semicolon
                $valueNameBytes = [System.Collections.Generic.List[byte]]::new()
                while ($currentPosition + 1 -lt $policyBytes.Length) {
                    if ($policyBytes[$currentPosition] -eq 0x3B -and $policyBytes[$currentPosition + 1] -eq 0x00) {
                        $currentPosition += 2  # Skip ';'
                        break
                    }
                    $valueNameBytes.Add($policyBytes[$currentPosition])
                    $valueNameBytes.Add($policyBytes[$currentPosition + 1])
                    $currentPosition += 2
                }
                $valueName = [System.Text.Encoding]::Unicode.GetString($valueNameBytes.ToArray()).TrimEnd([char]0)

                # Parse value type (4 bytes, little-endian)
                if ($currentPosition + 4 -gt $policyBytes.Length) {
                    throw "Unexpected end of file while reading value type."
                }
                $valueType = [System.BitConverter]::ToInt32($policyBytes, $currentPosition)
                $currentPosition += 4
                
                # Skip semicolon after type
                if ($policyBytes[$currentPosition] -ne 0x3B) {  # ';'
                    throw "Invalid format: Expected ';' after value type at position $currentPosition."
                }
                $currentPosition += 2

                # Parse value length (4 bytes)
                if ($currentPosition + 4 -gt $policyBytes.Length) {
                    throw "Unexpected end of file while reading value length."
                }
                $valueLength = [System.BitConverter]::ToInt32($policyBytes, $currentPosition)
                $currentPosition += 4
                
                # Skip semicolon after length
                if ($policyBytes[$currentPosition] -ne 0x3B) {  # ';'
                    throw "Invalid format: Expected ';' after value length at position $currentPosition."
                }
                $currentPosition += 2

                # Parse value data
                $valueData = $null
                if ($currentPosition + $valueLength -gt $policyBytes.Length) {
                    Write-Warning "Value data exceeds file length. Truncating."
                    $valueLength = $policyBytes.Length - $currentPosition
                }

                switch ($valueType) {
                    1 {  # REG_SZ
                        if ($valueLength -ge 2) {
                            $valueData = [System.Text.Encoding]::Unicode.GetString($policyBytes, $currentPosition, $valueLength - 2)
                        }
                        $currentPosition += $valueLength
                    }
                    2 {  # REG_EXPAND_SZ
                        if ($valueLength -ge 2) {
                            $valueData = [System.Text.Encoding]::Unicode.GetString($policyBytes, $currentPosition, $valueLength - 2)
                        }
                        $currentPosition += $valueLength
                    }
                    7 {  # REG_MULTI_SZ
                        if ($valueLength -ge 2) {
                            $valueData = [System.Text.Encoding]::Unicode.GetString($policyBytes, $currentPosition, $valueLength - 2)
                        }
                        $currentPosition += $valueLength
                    }
                    3 {  # REG_BINARY
                        if ($valueLength -gt 0) {
                            $valueData = $policyBytes[$currentPosition..($currentPosition + $valueLength - 1)]
                        }
                        $currentPosition += $valueLength
                    }
                    4 {  # REG_DWORD
                        if ($valueLength -ge 4) {
                            $valueData = [System.BitConverter]::ToInt32($policyBytes, $currentPosition)
                        }
                        $currentPosition += 4  # DWORD is always 4 bytes regardless of length field
                    }
                    11 { # REG_QWORD
                        if ($valueLength -ge 8) {
                            $valueData = [System.BitConverter]::ToInt64($policyBytes, $currentPosition)
                        }
                        $currentPosition += 8  # QWORD is always 8 bytes
                    }
                    default {
                        Write-Warning "Unknown registry type encountered: $valueType. Skipping $valueLength bytes."
                        $currentPosition += $valueLength
                    }
                }

                # Skip closing ']'
                if ($currentPosition + 2 -gt $policyBytes.Length) {
                    Write-Warning "Missing closing bracket at end of file."
                    break
                }
                if ($policyBytes[$currentPosition] -ne 0x5D) {  # ']'
                    Write-Warning "Expected ']' at position $currentPosition but found $($policyBytes[$currentPosition]). Attempting to continue."
                    # Try to find the next ']'
                    while ($currentPosition + 1 -lt $policyBytes.Length -and 
                           !($policyBytes[$currentPosition] -eq 0x5D -and $policyBytes[$currentPosition + 1] -eq 0x00)) {
                        $currentPosition++
                    }
                }
                $currentPosition += 2

                # Add to results
                $policy = [GPRegistryPolicy]::new($keyName, $valueName, $valueType, $valueLength, $valueData)
                $registryPolicies.Add($policy)
            }

            return $registryPolicies
        }
        catch {
            Write-Error "Failed to parse .pol file: $_"
            throw
        }
    }
}

# --- Original Functions (Placeholders) ---
function Read-RegistryPolicies {
    Write-Warning "Read-RegistryPolicies is not yet implemented in this version."
}

function New-RegistrySettingsEntry {
    Write-Warning "New-RegistrySettingsEntry is not yet implemented in this version."
}

function New-GPRegistryPolicyFile {
    Write-Warning "New-GPRegistryPolicyFile is not yet implemented in this version."
}

function Add-RegistryPolicies {
    Write-Warning "Add-RegistryPolicies is not yet implemented in this version."
}

# Export all public functions
Export-ModuleMember -Function @(
    'Read-PolFile',
    'Read-RegistryPolicies',
    'New-RegistrySettingsEntry',
    'New-GPRegistryPolicyFile',
    'Add-RegistryPolicies',
    'New-GPRegistryPolicy',
    'Get-RegType',
    'Get-RegTypeString',
    'Get-RegTypeFromString'
)