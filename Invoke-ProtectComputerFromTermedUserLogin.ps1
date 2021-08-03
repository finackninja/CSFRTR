
<#PSScriptInfo

.VERSION 1.31

.GUID 1583b204-6525-452a-8ae5-4c53ba2ae1fd

.AUTHOR finackninja

.COMPANYNAME 

.COPYRIGHT 

.TAGS

.LICENSEURI https://github.com/finackninja/CSFRTR/blob/main/LICENSE

.PROJECTURI https://github.com/finackninja/CSFRTR

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
    
.PRIVATEDATA

#>

<#
.SYNOPSIS
    Protects a Windows computer endpoint upon user termination from the terminated user.
.DESCRIPTION
    This script is designed to run through CrowdStrike Falcon realtime response (RTR) in order to protect a Windows computer endpoint in a terminated user's possession. It takes the following actions:

    * Log off all users
    * Disables cached credentials.
    * Changes local account passwords.
    * Clears Kerberos tickets.
    * Shuts down the computer.
#>

[CmdletBinding()]
Param ()

$ExcludedLocalAccounts = @(
    'DefaultAccount',
    'WDAGUtilityAccount'
)

# Log off all current user sessions

Invoke-CimMethod -ClassName Win32_Operatingsystem -ComputerName . -MethodName Win32Shutdown -Arguments @{ Flags = 4 }

# Disable cached credentials.
try {
    if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount | Select-Object -ExpandProperty CachedLogonsCount) -ne 0) {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount -Value 0
    }
    Write-Warning -Messaage 'This change requires a reboot to take effect! Please reboot the computer when it is appropriate to do so.'
}
catch {
    Write-Warning -Message 'Unable to disable cached credentials.'
}

# Change local account passwords.

function Get-RandomCharacters($length, $characters) {
    $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
    $private:ofs=''
    return [String]$characters[$random]
}

function Scramble-String([string]$inputString){     
    $characterArray = $inputString.ToCharArray()   
    $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
    $outputString = -join $scrambledStringArray
    return $outputString 
}

Get-LocalUser | Where-Object {$ExcludedLocalAccounts -notcontains $_.Name} | ForEach-Object {
    $Password = $null
    
    try {
        try{
            add-type -AssemblyName System.Web
            [system.web.security.membership]
            $Password = [system.web.security.membership]::generatepassword(20,4)
        }
        catch{
            Write-Error -Message 'Unable to load system.web assembly'
            # generate 4 numbers which add up to 16
            Do{
                $total = 0
                $numberofcharactersperitem  = Get-Random -minimum 4 -maximum 10 -count 4
                $numberofcharactersperitem | ForEach-Object {$total += $_}
            } Until ($total -ge 20)

           $password = Get-RandomCharacters -length $numberofcharactersperitem[0] -characters 'abcdefghijklmnopqrstuvwxyz'
           $password = $password + (Get-RandomCharacters -length $numberofcharactersperitem[1] -characters 'ABCDEFGHKLMNOPRSTUVWXYZ')
           $password = $password + (Get-RandomCharacters -length $numberofcharactersperitem[2] -characters '1234567890')
           $password = $password + (Get-RandomCharacters -length $numberofcharactersperitem[3] -characters "~!@#$%^&*_-+=`|\(){}[]:;`"'<>,.?/'")

           $password = Scramble-String($password)
           $password
        }
        $_ | Set-LocalUser -Password $Password -ErrorAction Stop
        $Password.Dispose()
    }
    catch {
        Write-Warning -Message "Unable to change the password for $($_.Name)."
    }
}

# Clear all Kerberos tickets. Run as a separate job because sometimes this part hangs for an unknown reason.
Start-Job -ScriptBlock {
    Get-CimInstance -ClassName 'Win32_LogonSession' -ErrorAction Stop | Where-Object {$_.AuthenticationPackage -ne 'NTLM'} | ForEach-Object {
        klist.exe purge -li ([Convert]::ToString($_.LogonId, 16)) 
    }
}
# Provide a cushion to allow the Kerberos ticket clear job an opportunity to complete.
Start-Sleep -Seconds 5

# Shutdown the computer once completed
Stop-Computer -Force
