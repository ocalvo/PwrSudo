
function global:Test-IsUnix
{
  return (($PSVersionTable.PSEdition -eq 'Core') -and ($PSVersionTable.Platform -eq 'Unix'))
}

function global:Test-IsAdmin
{
  if (Test-IsUnix) {
    return ((id -u) -eq 0)
  } else {
    $wi = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $wp = New-Object 'System.Security.Principal.WindowsPrincipal' $wi
    $wp.IsInRole("Administrators") -eq 1
  }
}

function global:Open-Elevated
{
  param([switch]$wait)
  $file, [string]$arguments = $args

  if (!(Test-IsAdmin))
  {
    $psi = New-Object System.Diagnostics.ProcessStartInfo $file
    $psi.Arguments = $arguments
    $psi.Verb = "runas"
    $p = [System.Diagnostics.Process]::Start($psi)
    if ($wait.IsPresent) { $p.WaitForExit() }
  }
  else
  {
    & $file $args
  }
}

function global:Enable-Execute-Elevated
{
  if (Test-IsUnix) {
    Write-Host "On Unix, native sudo is used. No setup needed."
    return
  }

  if (!(Test-IsAdmin))
  {
    $shell = if ("Core" -eq $PSEdition) { "pwsh" } else { "powershell" }
    Open-Elevated -wait $shell -Ex ByPass -c Enable-Execute-Elevated
    return
  }

  if ($null -eq (Get-Command gsudo -ErrorAction Ignore))
  {
    if ($null -eq (Get-Command scoop -ErrorAction Ignore))
    {
      Invoke-Expression (New-Object System.Net.WebClient).DownloadString('https://get.scoop.sh')
    }
    scoop install gsudo
  }

  gsudo config CacheMode auto
  gsudo config CacheDuration 00:30:00
}

function global:Execute-Elevated
{
  param()
  if ($null -eq (Get-Command gsudo -ErrorAction Ignore))
  {
    Write-Error "gsudo not found, run Enable-Execute-Elevated"
    return
  }
  gsudo $args
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
    New-Item "HKLM:\SOFTWARE\OpenSSH" | Out-Null
  }
  New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value $shell -PropertyType String -Force
  Restart-Service ssh-agent
  Restart-Service sshd
}

function global:Add-AdministratorsAuthorizedKeys
{
  param($newKey)

  $serverKeys = "C:\ProgramData\ssh\administrators_authorized_keys"
  if ($null -ne $newKey)
  {
    $when = [datetime]::Now.ToString("y/MM/dd HH:mm:ss")
    Add-Content -Value "# Added by PwrSudo on $when" $serverKeys -Encoding UTF8 -Force
    Add-Content -Value $newKey $serverKeys -Encoding UTF8 -Force
  }
  $acl = Get-Acl $serverKeys
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","Allow")))
  $acl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","Allow")))
  $acl | Set-Acl
}

Export-ModuleMember -Function Test-IsUnix, Test-IsAdmin
Export-ModuleMember -Function Open-Elevated, Execute-Elevated, Enable-Execute-Elevated
Export-ModuleMember -Function Enable-SSH, Add-AdministratorsAuthorizedKeys

Set-Alias elevate Open-Elevated -Scope Global
if (!(Test-IsUnix)) {
  Set-Alias sudo Execute-Elevated -Scope Global
}
