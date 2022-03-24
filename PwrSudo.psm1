
$keyfile = $env:HOMEDRIVE+$env:HOMEPATH+'/.ssh/id_rsa_sudo'
$keyfilePub =  $keyfile+'.pub'

function global:Test-IsUnix
{
  return (($PSVersionTable.PSEdition -eq 'Core') -and ($PSVersionTable.Platform -eq 'Unix'))
}

function global:Test-IsAdmin
{
  $isUnix = Test-IsUnix
  if ($isUnix) {
    return ((id -u) -eq 0)
  } else {
    $wi = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $wp = new-object 'System.Security.Principal.WindowsPrincipal' $wi
    $wp.IsInRole("Administrators") -eq 1
  }
}

function global:Open-Elevated
{
  param([switch]$wait)
  $file, [string]$arguments = $args;

  if (!(Test-IsAdmin))
  {
    $psi = new-object System.Diagnostics.ProcessStartInfo $file;
    $psi.Arguments = $arguments;
    $psi.Verb = "runas";

    $p = [System.Diagnostics.Process]::Start($psi);
    if ($wait.IsPresent)
    {
        $p.WaitForExit()
    }
  }
  else
  {
    & $file $args
  }
}

function global:Enable-SSH
{
  param($shell = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")

  Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
  Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
  Set-Service -Name sshd -StartupType 'Automatic'
  Set-Service -Name ssh-agent -StartupType 'Automatic'
  New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
  if (!(Test-Path "HKLM:\SOFTWARE\OpenSSH"))
  {
     mkdir "HKLM:\SOFTWARE\OpenSSH"
  }

  New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value $shell -PropertyType String -Force
  Get-Service ssh-agent | Restart-Service
  Get-Service sshd | Restart-Service
}

function global:Add-AdministratorsAuthorizedKeys()
{
  param($newKey)

  $serverKeys = "C:\ProgramData\ssh\administrators_authorized_keys"
  if ($null -ne $newKey)
  {
    $when = [datetime]::Now.ToString("y/MM/dd HH:mm:ss");
    Add-Content -Value "# Added by PSSudo.psm1 on $when for key $keyFile" $serverKeys -Encoding UTF8 -Force
    Add-Content -Value $newKey $serverKeys -Encoding UTF8 -Force
  }
  $acl = Get-Acl $serverKeys
  $acl.SetAccessRuleProtection($true, $false)
  $administratorsRule = New-Object system.security.accesscontrol.filesystemaccessrule("Administrators","FullControl","Allow")
  $systemRule = New-Object system.security.accesscontrol.filesystemaccessrule("SYSTEM","FullControl","Allow")
  $acl.SetAccessRule($administratorsRule)
  $acl.SetAccessRule($systemRule)
  $acl | Set-Acl
}

if ("Core" -eq $psedition)
{
  $_shell = "pwsh"
}
else
{
  $_shell = "powershell"
}

function global:Enable-Execute-Elevated
{
  if (!(Test-IsAdmin))
  {
     Open-Elevated -wait $_shell -Ex ByPass -c Enable-Execute-Elevated
     return;
  }

  $gsudoCmd = (get-command gsudo -ErrorAction Ignore)

  if ($null -eq $gsudoCmd)
  {
    $scoopCmd = (get-command scoop -ErrorAction Ignore)
    if ($null -eq $scoopCmd)
    {
      Invoke-Expression (New-Object System.Net.WebClient).DownloadString('https://get.scoop.sh')
    }
    scoop install gsudo
    gsudo config cachemode auto
    gsudo cache on
  }
}

function global:Execute-Elevated {
  param()
  $gsudoCmd = (get-command gsudo -ErrorAction Ignore)
  if ($null -eq $gsudoCmd)
  {
    Write-Error "gsudo not found, run Enable-Execute-Elevated"
  }
  gsudo $args
}

Export-ModuleMember -Function Enable-Execute-Elevated
Export-ModuleMember -Function Execute-Elevated
Export-ModuleMember -Function Open-Elevated
Export-ModuleMember -Function Add-AdministratorsAuthorizedKeys

set-alias elevate Open-Elevated -scope global
if (!(Test-IsUnix)) {
  set-alias sudo Execute-Elevated -scope global
}

