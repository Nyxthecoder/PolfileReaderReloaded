@{
    RootModule = 'PolfileReaderReloaded.psm1'
    ModuleVersion = '1.1.0'
    GUID = 'a410fcce-a7fd-43ca-af4c-95e97cd3eb44'
    Author = 'Nyx Inoue, Lumi Yuuki'
    CompanyName = 'NyxCoders LLC'
    Copyright = '(c) 2026 NyxCoders. All rights reserved.'
    Description = 'Module with parser cmdlets to work with GP Registry Policy .pol files. Improved error handling, performance, and pipeline support.'
    PowerShellVersion = '5.0'
    PrivateData = @{
        PSData = @{
            Tags = @('GroupPolicy', 'Registry', 'Policy', 'GPO', 'Windows')
            LicenseUri = 'https://github.com/Nyxthecoder/PolfileReaderReloaded/blob/main/LICENSE'
            ProjectUri = 'https://github.com/Nyxthecoder/PolfileReaderReloaded'
        }
    }
    FunctionsToExport = @(
        'Read-PolFile',
        'New-GPRegistryPolicy',
        'Get-RegType',
        'Get-RegTypeString',
        'Get-RegTypeFromString'
    )
    AliasesToExport = @(
        'Parse-PolFile'
    )
}
