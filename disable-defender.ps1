#Requires -RunAsAdministrator
[CmdletBinding()]
param ()

# "Disables" Defender by adding exclusions and turning off advanced bits. Run this under an elevated powershell prompt
# Defender will be essentially gutted/disabled without messing with any files/underlying services. Windows Security center will still display that AV is working etc.
# WARNING: This is intended to work on RE/Malware research machines and it's ability to alter MDE configurations will depend on how MDE policy is configured.

#region vars
$maxUInt = 4294967295
[string[]] $genDrivelist = ([char[]]('A'[0]..'Z'[0])).foreach({
            "${_}:\"
        })) + '*'
[string[]] $genExtensions = ((& cmd.exe /c assoc).Split('=')).Where({ $_ -like '.*' }).Replace('.', '') + '*'
#endregion vars

# Ref https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference
# Ref https://learn.microsoft.com/en-us/powershell/module/defender/add-mppreference
# Useful:
# https://cloudbrothers.info/guide-to-defender-exclusions/
# https://github.com/dgoldman-msft/Get-MpPreferences/blob/main/Get-MpPreferences.ps1
# https://blog.quarkslab.com/guided-tour-inside-windefenders-network-inspection-driver.html
$paramHash = @{
    AttackSurfaceReductionOnlyExclusions          = '*'
    AttackSurfaceReductionRules_Actions           = 'Disabled'
    AllowDatagramProcessingOnWinServer            = $False
    AllowNetworkProtectionDownLevel               = $False
    AllowNetworkProtectionOnWinServer             = $False
    CheckForSignaturesBeforeRunningScan           = $False
    CloudBlockLevel                               = 1 # 1 == Not Configured
    CloudExtendedTimeout                          = 0 # Need to confirm that 0 in this instance isn't infinite
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
    DisableRdpParsing                             = $True
    DisableRealtimeMonitoring                     = $True
    DisableRemovableDriveScanning                 = $True
    DisableRestorePoint                           = $True
    DisableScanningMappedNetworkDrivesForFullScan = $True
    DisableScanningNetworkFiles                   = $True
    DisableScriptScanning                         = $True
    DisableSmtpParsing                            = $True
    DisableSshParsing                             = $True
    DisableTamperProtection                       = $True
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
    ExclusionProcess                              = '*'
    ForceUseProxyOnly                             = $True
    HighThreatDefaultAction                       = 'Allow'
    LowThreatDefaultAction                        = 'Allow'
    MAPSReporting                                 = 'Disabled'
    MeteredConnectionUpdates                      = $False
    ModerateThreatDefaultAction                   = 'Allow'
    ProxyServer                                   = 'http://localhost:12345'
    ProxyBypass                                   = $False
    PUAProtection                                 = 'Disabled'
    RealTimeScanDirection                         = 2 # has to be set, 2 is outgoing files only
    RemediationScheduleDay                        = 8 # 8 == Never / Default
    ScanAvgCPULoadFactor                          = 5 # 5-100
    ScanScheduleDay                               = 8 # 8 == Never / Default
    SevereThreatDefaultAction                     = 2 # 2 == Ignore
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
        Write-Verbose "Setting $_"
        Set-MpPreference @curParam -ErrorAction Continue -Verbose -Force
    })
