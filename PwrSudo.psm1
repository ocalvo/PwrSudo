
$keyfile = $env:HOMEDRIVE+$env:HOMEPATH+'/.ssh/id_rsa_sudo'
$keyfilePub =  $keyfile+'.pub'

function global:Test-IsAdmin
{
    $wi = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $wp = new-object 'System.Security.Principal.WindowsPrincipal' $wi
    $wp.IsInRole("Administrators") -eq 1
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
  Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
  Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
  Set-Service -Name sshd -StartupType 'Automatic'
  Set-Service -Name ssh-agent -StartupType 'Automatic'
  New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
  New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
  Start-Service ssh-agent
  Start-Service sshd
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

function global:Enable-Execute-Elevated
{
  if (!(Test-IsAdmin))
  {
     Open-Elevated -wait powershell -c Enable-Execute-Elevated
     return;
  }

  $service = get-service sshd* | select -first 1
  if ($null -eq $service)
  {
    Enable-SSH
  }

  if (!(test-path $keyfile))
  {
    ssh-keygen -t rsa -f $keyfile -q -P `"`"
  }
  #Start-Service ssh-agent
  #ssh-add $keyfilePub

  Add-AdministratorsAuthorizedKeys (Get-Content $keyfilePub)
}

function global:Execute-Elevated {
  param([switch]$wait,$cmd)

  [string]$arguments = $args;

  if (!(Test-IsAdmin))
  {
    if (!(Test-Path $keyfile))
    {
       Enable-Execute-Elevated
    }
    $service = get-service sshd* | select -first 1
    if ($null -eq $service)
    {
       throw "Failed to start SSHD"
    }
    else
    {
        if ($service.Status -ne 'Running')
        {
           Open-Elevated -wait powershell -c Start-Service SSHD
        }
    }
    if ($null -ne $cmd)
    {
      [string[]]$command = ("cd",(pwd).Path,";",$cmd)
      $command+=$args
    }
    ssh -i $keyfile $env:USERDOMAIN\$env:USERNAME@localhost $command
  }
  else
  {
    powershell -c $cmd $args
  }
}

Export-ModuleMember -Function Enable-Execute-Elevated
Export-ModuleMember -Function Execute-Elevated
Export-ModuleMember -Function Open-Elevated
Export-ModuleMember -Function Add-AdministratorsAuthorizedKeys

set-alias elevate Open-Elevated -scope global
set-alias sudo Execute-Elevated -scope global

