<#
.SYNOPSIS
    A PowerShell based memory scanner, intended to find unencrypted JWTs in memory (O365 etc)
.NOTES
    Windows only
.EXAMPLE
    To search a specific process:
    .\Search-ProcessMemory -ProcessPID 1234 -SearchString "eyJ0eX"
    
    To search all processes belonging to the active user:
    $myprocs = tasklist /v /fo csv | ConvertFrom-CSV | Where-Object {$_."User Name" -match $ENV:USERNAME }
    foreach ($proc in $myprocs) { .\Search-ProcessMemory.ps1 -ProcessPID $proc.PID }
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [int] $ProcessPID,
    [Parameter()]
    [string] $SearchString = "eyJ0eX"
)

# Validate that a process with the given PID exists
$Proc = Get-Process -Id $ProcessPID -ErrorAction SilentlyContinue
if (-Not $Proc) {
    Write-Host "Process with PID $ProcessPID does not exist."
    return
}

try {
    Add-Type -ErrorAction SilentlyContinue -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;

    public class Kernel32 {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }
    }
"@
} catch {}

# Constants
$PROCESS_VM_READ = 0x0010
$PROCESS_QUERY_INFORMATION = 0x0400
$MEM_COMMIT = 0x1000

# Open the process
Write-Host -ForegroundColor Cyan "Opening process $ProcessPID, $($Proc.Name)"
$processHandle = [Kernel32]::OpenProcess($PROCESS_VM_READ -bor $PROCESS_QUERY_INFORMATION, $false, $ProcessPID)
if ($processHandle -eq [IntPtr]::Zero) {
    Write-Host "Failed to open process. Check if the PID is correct and if you have necessary permissions."
    return
}

# Initialize variables
$address = [IntPtr]::Zero
$buffer = New-Object byte[] 4096
$bytesRead = 0

# Create a StringBuilder to hold the string data we read
$stringBuilder = New-Object System.Text.StringBuilder

$uniqueLines = @{}

try {
    # Loop through the process's memory
    while ($true) {
        $mInfo = New-Object Kernel32+MEMORY_BASIC_INFORMATION
        $mInfoSize = [System.Runtime.InteropServices.Marshal]::SizeOf($mInfo)
        
        $res = [Kernel32]::VirtualQueryEx($processHandle, $address, [ref]$mInfo, $mInfoSize)
        
        if ($res -eq 0) {
            $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "VirtualQueryEx returned 0, stopping memory scan. Last error code: $errorCode"
            break
        }

        if ($mInfo.State -eq $MEM_COMMIT) {
            $readSuccess = [Kernel32]::ReadProcessMemory($processHandle, $mInfo.BaseAddress, $buffer, $buffer.Length, [ref]$bytesRead)

            if ($readSuccess -and $bytesRead -gt 0) {
                $stringData = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
                $lines = $stringData -split "`0"  # Split null-terminated strings
                
                foreach ($line in $lines) {
                    if ($line -match [regex]::Escape($SearchString)) {
                        # Add the line to the hash set if it's a new, unique match
                        $splitline = $SearchString + ($line -split "$SearchString")[-1] # Split the line by spaces and take the last part
                        $uniqueLines[$splitline] = $null
                    }
                }
                $null = $stringBuilder.Append($stringData)
            }
        }

        $address = $mInfo.BaseAddress + $mInfo.RegionSize.ToInt64()
    }

    # Print all unique lines
    if ($uniqueLines.Count -eq 0) {
        Write-Host "No matches found."
        return
    } else {
        Write-Host "Unique entries found:"
        $uniqueLines.Keys | ForEach-Object { Write-Host "`n$_`n" }
    }
} finally {
    # Close the process handle
    [Kernel32]::CloseHandle($processHandle) | Out-Null
}
