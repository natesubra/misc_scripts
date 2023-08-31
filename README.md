# Miscellaneous Scripts

## Files

- [build-rubeus.ps1](build-rubeus.ps1) - Build Rubeus from source while removing commonly checked for indicators
- [disable-defender.ps1](disable-defender.ps1) - Script that defangs defender by disabling most of it's components and creating exceptions that disable scanning
- [posh_profile_hook.ps1](posh_profile_hook.ps1) - An example of a profile hook that will execute a script when a new powershell session is started, used to discover potential privilege escalation or persistence opportunities related to PowerShell profiles
- [Search-ProcessMemory.ps1](Search-ProcessMemory.ps1) - Search the memory of a process for a string, primarily written to search for JWT tokens stored in memory (credit to [mrd0x](https://mrd0x.com/stealing-tokens-from-office-applications/) for the idea)
