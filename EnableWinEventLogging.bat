@echo off
cls

::#######################################################################
:: SET THE LOG SIZE - What local size they will be
:: ---------------------
:: 540100100 will give you 7 days of local Event Logs with everything logging (Security and Sysmon)
:: Other logs do not create as much quantity, so lower numbers are fine

wevtutil sl Security /ms:540100100
wevtutil sl Application /ms:256000100
wevtutil sl Setup /ms:256000100
wevtutil sl System /ms:256000100
wevtutil sl "Windows Powershell" /ms:256000100
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:540100100

::#######################################################################
:: SET Events to log the Command Line if Patch MS15-015 KB3031432 is installed (Win7 and Win 2008, built-in for Win8 & Win2012)
:: ---------------------

reg add "hklm\software\microsoft\windows\currentversion\policies\system\audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1

:: ---------------------

::#######################################################################
::  Force Advance Audit Policy

reg add "hklm\System\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1

:: ---------------------

::#######################################################################
:: Creates profile.ps1 in the correct location - SET Command variables for PowerShell - Enables default profile to collect PowerShell Command Line parameters and allows .PS1 to execute
::  Allows local powershell scripts to run

powershell Set-ExecutionPolicy RemoteSigned

echo Get-Item "hklm:\software\microsoft\windows\currentversion\policies\system\audit" > c:\windows\system32\WindowsPowerShell\v1.0\profile.ps1
echo $LogCommandHealthEvent = $true >> c:\windows\system32\WindowsPowerShell\v1.0\profile.ps1
echo $LogCommandLifecycleEvent = $true >> c:\windows\system32\WindowsPowerShell\v1.0\profile.ps1

:: ---------------------

::#######################################################################
:: ---------------------

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell" /v ExecutionPolicy /t REG_SZ /d "RemoteSigned" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging," /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableInvocationHeader /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f

mkdir C:\temp

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\temp" /f

::#######################################################################
:: CAPTURE THE SETTINGS - BEFORE they have been modified
:: ---------------------

Auditpol /get /category:* > C:\temp\AuditPol_BEFORE_%computername%.txt

:: ---------------------

::#######################################################################
:: Account Logon
:: ---------------------

Auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
Auditpol /set /subcategory:"Kerberos Authentication Service" /success:disable /failure:disable
Auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:disable /failure:disable
Auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable


::#######################################################################
:: ACCOUNT MANAGEMENT
:: ---------------------
:: Sets - the entire category - Auditpol /set /category:"Account Management" /success:enable /failure:enable

Auditpol /set /subcategory:"Application Group Management" /success:disable /failure:disable
Auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable
Auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

:: ---------------------

::#######################################################################
:: Detailed Tracking
:: ---------------------

Auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
Auditpol /set /subcategory:"DPAPI Activity" /success:disable /failure:disable
Auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable
Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

::#######################################################################
:: DS Access
:: ---------------------

Auditpol /set /subcategory:"Detailed Directory Service Replication" /success:disable /failure:disable
Auditpol /set /subcategory:"Directory Service Access" /success:disable /failure:disable
Auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
Auditpol /set /subcategory:"Directory Service Replication" /success:disable /failure:disable

:: ---------------------

::#######################################################################
:: Logon/Logoff
:: ---------------------

Auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
Auditpol /set /subcategory:{54849625-5478-4994-A5BA-3E3B0328C30D} /success:enable /failure:disable
Auditpol /set /subcategory:"IPsec Extended Mode" /success:disable /failure:disable
Auditpol /set /subcategory:"IPsec Main Mode" /success:disable /failure:disable
Auditpol /set /subcategory:"IPsec Quick Mode" /success:disable /failure:disable
Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
Auditpol /set /subcategory:"Logon" /success:enable /failure:enable 
Auditpol /set /subcategory:"Network Policy Server" /success:disable /failure:disable
Auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
Auditpol /set /subcategory:"Special Logon" /success:enable /failure:disable

:: ---------------------

::#######################################################################
:: Object Access
:: ---------------------

Auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
Auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
Auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable

::
::  Will generate a lot of events if Files and Reg keys are audited so only audit locations that are not noisy
::

Auditpol /set /subcategory:"File Share" /success:enable /failure:enable
Auditpol /set /subcategory:"File System" /success:enable /failure:enable

::
:: WARNING:  Requires the Windows Firewall to be in at least an ALLOW ALLOW configuration in Group Ploicy
::

Auditpol /set /subcategory:"Filtering Platform Connection" /success:disabled /failure:disable
Auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:disable /failure:disable
Auditpol /set /subcategory:"Handle Manipulation" /success:disable /failure:disable
Auditpol /set /subcategory:"Kernel Object" /success:disable /failure:disable
Auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
Auditpol /set /subcategory:"Registry" /success:enable
Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
Auditpol /set /subcategory:"SAM" /success:disable /failure:disable

:: ---------------------

::#######################################################################
:: Policy Change
:: ---------------------

Auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable

::
::  Enable if you use Windows Firewall to monitor changes
::

Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:disable /failure:disable

Auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Other Policy Change Events" /success:disable /failure:enable

:: ---------------------

::#######################################################################
:: Privilege Use
:: ---------------------

Auditpol /set /subcategory:"Other Privilege Use Events" /success:disable /failure:disable
Auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:disable /failure:disable
Auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

:: ---------------------

::#######################################################################
:: SYSTEM
:: ---------------------

Auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
Auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable
Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

:: ---------------------

::#######################################################################
:: OTHER
:: ---------------------

Auditpol /set /subcategory:{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148} /success:enable /failure:enable

:: ---------------------

::#######################################################################
:: CAPTURE THE SETTINGS - AFTER they have been modified
:: ---------------------

Auditpol /get /category:* > C:\temp\AuditPol_AFTER_%computername%.txt

:: ---------------------

::
:: The End
::
