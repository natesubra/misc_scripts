#Requires -RunAsAdministrator
#Requires -Version 5.0
[CmdletBinding()]
param ()

# "Disables" Defender by adding exclusions and turning off advanced bits. Run this under an elevated powershell prompt
# Defender will be essentially gutted/disabled without messing with any files/underlying services. Windows Security center will still display that AV is working etc.

# WARNING: This is intended to be run on fully patched machines. It will fail if run on older versions of Windows 10/11.
# WARNING: This is intended to work on RE/Malware research machines and it's ability to alter MDE configurations will depend on how MDE policy is configured. 
# WARNING: TL;DR This is not intended to be run on a managed device.

# Get the max value we can set some of the parameters to
$maxUInt = [uint32]::MaxValue

# Generate a list of all drive letters
# Per MS Ref 3, wildcards are only allowed at the end of a path
[string[]] $genDrivelist = ([char[]]('A'[0]..'Z'[0])).foreach({
        "${_}:\*"
    }) + '\\*' + '?:\*'

# Get all file associations
[string[]] $genExtensions = ((& cmd.exe /c assoc).Split('=')).Where({ $_ -like '.*' }) + '.*'

# Ref 1 https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference
# Ref 2 https://learn.microsoft.com/en-us/powershell/module/defender/add-mppreference
# Ref 3 https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-process-opened-file-exclusions-microsoft-defender-antivirus?view=o365-worldwide
# Ref 4 https://learn.microsoft.com/en-us/previous-versions/windows/desktop/defender/msft-mppreference
# Ref 5 https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-extension-file-exclusions-microsoft-defender-antivirus?view=o365-worldwide#use-wildcards-in-the-file-name-and-folder-path-or-extension-exclusion-lists
# Useful/Credit:
# https://powershell.one/wmi/root/microsoft/windows/defender/msft_mppreference
# https://cloudbrothers.info/guide-to-defender-exclusions/
# https://github.com/dgoldman-msft/Get-MpPreferences/blob/main/Get-MpPreferences.ps1
# https://blog.quarkslab.com/guided-tour-inside-windefenders-network-inspection-driver.html

# To get the value types for each parameter, run the following:
# `Get-MpPreference | get-member`
# OR `Get-CimInstance -ClassName MSFT_MpPreference -Namespace root/microsoft/windows/defender -Property * | get-member`
# `Get-Help Set-MpPreference` also contains good information but is lacking on many of the types

# DefaultActions Map
# 1 == Clean
# 2 == Quarantine
# 3 == Remove
# 4 == Allow
# 8 == User Defined
# 9 == NoAction
# 10 == Block

$paramHash = [ordered] @{
    AllowDatagramProcessingOnWinServer            = $False
    AllowNetworkProtectionDownLevel               = $False
    AllowNetworkProtectionOnWinServer             = $False
    ApplyDisableNetworkScanningtoIOAV             = $True
    AttackSurfaceReductionOnlyExclusions          = '*'
    AttackSurfaceReductionRules_Actions           = 'Audit' # Audit == 2, https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide
    CheckForSignaturesBeforeRunningScan           = $False
    CloudBlockLevel                               = 1 # 1 == Not Configured
    CloudExtendedTimeout                          = 0 # TODO: Need to confirm that 0 in this instance isn't infinite
    DisableArchiveScanning                        = $True
    DisableBehaviorMonitoring                     = $True # If on retail, this will consistently re-enable itself
    DisableBlockAtFirstSeen                       = $True
    DisableCatchupFullScan                        = $True
    DisableCatchupQuickScan                       = $True
    DisableCpuThrottleOnIdleScans                 = $False
    DisableDatagramProcessing                     = $True
    DisableDnsOverTcpParsing                      = $True
    DisableDnsParsing                             = $True
    DisableEmailScanning                          = $True
    DisableFtpParsing                             = $True
    DisableHttpParsing                            = $True
    DisableInboundConnectionFiltering             = $True
    DisableIntrusionPreventionSystem              = $True
    DisableIOAVProtection                         = $True
    DisableNetworkProtectionPerfTelemetry         = $True
    DisablePrivacyMode                            = $True
    DisableQuicParsing                            = $True
    DisableRdpParsing                             = $True
    DisableRealtimeMonitoring                     = $True
    DisableRemovableDriveScanning                 = $True
    DisableRestorePoint                           = $True
    DisableScanningMappedNetworkDrivesForFullScan = $True
    DisableScanningNetworkFiles                   = $True
    DisableScriptScanning                         = $True # If on retail, this will consistently re-enable itself
    DisableSmtpParsing                            = $True
    DisableSshParsing                             = $True
    DisableTamperProtection                       = $True # If on retail, this will consistently re-enable itself and sometimes fail to set correctly: Error 0x%1!x!
    DisableTDTFeature                             = $True
    DisableTlsParsing                             = $True
    EnableControlledFolderAccess                  = 'Disabled'
    EnableDnsSinkhole                             = $False
    EnableFileHashComputation                     = $False
    EnableLowCpuPriority                          = $True
    EnableNetworkProtection                       = 'Disabled'
    ExclusionExtension                            = $genExtensions
    ExclusionIPAddress                            = '0.0.0.0/0', '*', '*.*.*.*' # Not clear what data types go here
    ExclusionPath                                 = $genDrivelist
    ExclusionProcess                              = $genDrivelist
    ForceUseProxyOnly                             = $True
    HighThreatDefaultAction                       = 'Allow'
    LowThreatDefaultAction                        = 'Allow'
    MAPSReporting                                 = 'Disabled'
    MeteredConnectionUpdates                      = $False
    ModerateThreatDefaultAction                   = 'Allow'
    ProxyBypass                                   = $False
    ProxyServer                                   = 'http://localhost:12345'
    PUAProtection                                 = 'Disabled'
    RealTimeScanDirection                         = 2 # has to be set, 2 is outgoing files only
    RemediationScheduleDay                        = 8 # 8 == Never / Default
    ScanAvgCPULoadFactor                          = 5 # 5-100
    ScanScheduleDay                               = 8 # 8 == Never / Default
    SevereThreatDefaultAction                     = 'Allow'
    SignatureBlobUpdateInterval                   = $maxUInt
    SignatureDefinitionUpdateFileSharesSources    = '\\localhost\C$'
    SignatureDisableUpdateOnStartupWithoutEngine  = $True
    SignatureFallbackOrder                        = 'FileShares'
    SignatureScheduleDay                          = 8 # 8 == Never
    SignatureUpdateCatchupInterval                = $maxUInt
    SubmitSamplesConsent                          = 'NeverSend'
    UnknownThreatDefaultAction                    = 'Allow'
}

# Try each parameter since they may vary based on OS version
$paramHash.keys.ForEach({
        $curParam = @{
            "$_" = $paramHash["$_"]
        }
        Write-Host -NoNewline "Setting $_ to: "
        Write-Host -ForegroundColor Green "$($paramHash["$_"])"
        Set-MpPreference @curParam -ErrorAction Continue -Force
    })
