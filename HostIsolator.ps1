#################################################################################################
#.Synopsis 
#    Isolate, and desolate host using the Windows Firewall.
#
#.Description 
#    You can run this script with MEDC, Domain Group Policy, PSRemoting , etc., on your target
#    host, then it will restrict all the inbound and outbound connections to only allowed hosts.
#
#.How to run
#    Fill allowHosts variable with your proper hosts (for example specify IP of your SIEM and  
#    FQDN of your EDR) then run the script with proper parameter.
#
#.Parameter isolator
#    Isolate the host.
#
#.Parameter desolator
#    Desolate the host.
#
#.Example 
#    HostIsolator.ps1 isolate
#
#.Notes 
#    Author: Moein Mashayekhi, https://github.com/MoeinMashayekhi/HostIsolator
#    version: 1.0
#    Creadted: 20.Jun.2022
#################################################################################################


# Specify allowed hosts.
$allowedHosts = "192.168.1.10", "192.168.2.14" , "google.com"

# Default backup paths.
$firewallStatusPath = "$env:TEMP\FirewallStatusBackup.txt"
$firewallRulesPath = "$env:TEMP\FirewallRulesBackup.txt"
$backupHostFilePath = "$env:TEMP\HostFileBackup.txt"

function HostIsolator {
    CleanFiles
    $currentFirewallStatus = Get-NetFirewallProfile
    $convertedFirewallCurrentStatus = foreach ($status in $currentFirewallStatus) {
        [PSCustomObject]@{
            Name = $status.Name
            Enabled = $status.Enabled
            DefaultInboundAction = $status.DefaultInboundAction
            DefaultOutboundAction = $status.DefaultOutboundAction
        }
    }

    foreach ($convertedStatus in $convertedFirewallCurrentStatus) {
        Add-Content -Path $firewallStatusPath -Value "$($convertedStatus.Name),$($convertedStatus.Enabled),$($convertedStatus.DefaultInboundAction),$($convertedStatus.DefaultOutboundAction)"
    }
    $currentFirewallRules = Get-NetFirewallRule | Where-Object {$_.Enabled -eq "True"} | Select-Object Name
    foreach ($rule in $currentFirewallRules) {
        Add-Content -Path $firewallRulesPath -Value "$($rule.Name)"
    }

    Get-Content -Path "$($ENV:windir)/system32/drivers/etc/hosts" > $backupHostFilePath
    $convertedAllowedHosts = foreach ($allowedHost in $allowedHosts) {
        $ipVerification = [ipaddress]::TryParse($allowedHost ,[ref][ipaddress]::Loopback)
        if ($ipVerification) {
            $ipList = $allowedHost
        }
        else {
            $ipList = (Resolve-DnsName -Name $allowedHost).ipaddress
        }
        foreach ($ip in $ipList) {
            [PSCustomObject]@{
            Hostname = $allowedHost
            IP = $ip
            }
        }
    }

    foreach ($convertedHost in $convertedAllowedHosts) {
        Add-Content -Path "$($ENV:windir)/system32/drivers/etc/hosts" -Value "`n$($convertedHost.IP)`t`t$($convertedHost.Hostname)"
    }

    Start-Sleep -Seconds 2
    Get-DnsClientServerAddress | Set-DnsClientServerAddress -ServerAddresses 127.0.0.1
    Clear-DnsClientCache
    get-NetFirewallProfile | Set-NetFirewallProfile -Enabled:True
    Get-NetFirewallRule | Set-NetFirewallRule -Enabled:False
    New-NetFirewallRule -DisplayName "Outbound Allowed IP For Isolation" -Direction Outbound -Enabled:True -Action Allow -RemoteAddress $convertedAllowedHosts.IP 
    get-netfirewallprofile | Set-NetFirewallProfile -DefaultOutboundAction Block
    New-NetFirewallRule -DisplayName "Inbound Allowed IP For Isolation" -Direction Inbound -Enabled:True -Action Allow -RemoteAddress $convertedAllowedHosts.IP 
    get-netfirewallprofile | Set-NetFirewallProfile -DefaultInboundAction Block
}

function HostDesolator {
    if (Test-Path $firewallRulesPath) {
        $previousRules = Get-Content $firewallRulesPath
        foreach ($rule in $previousRules) {
            Set-NetFirewallRule -Name $rule -Enabled True
        }
        Start-Sleep -Seconds 2
    }
    else {
        Get-NetFirewallRule -Direction Outbound | Set-NetFirewallRule -Enabled:True
        Get-NetFirewallRule -Direction Inbound | Set-NetFirewallRule -Enabled:True
    }

    Remove-NetFirewallRule -DisplayName "Outbound Allowed IP For Isolation" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "Inbound Allowed IP For Isolation" -ErrorAction SilentlyContinue

    if (Test-Path $firewallStatusPath) {
        $previousStatus = Import-Csv -Path $firewallStatusPath -Delimiter "," -Header "Name","Enabled","DefaultInboundAction","DefaultOutboundAction"
        foreach ($status in $previousStatus) {
            Set-NetFirewallProfile -Name $status.Name -Enabled $status.Enabled -DefaultInboundAction $status.DefaultInboundAction -DefaultOutboundAction $status.DefaultOutboundAction
        }
        Start-Sleep -Seconds 2
    }
    else {
        get-netfirewallprofile | Set-NetFirewallProfile -Enabled True -DefaultInboundAction NotConfigured -DefaultOutboundAction NotConfigured
    }

    if (Test-Path $backupHostFilePath) {
        Remove-Item -Path "$($ENV:windir)/system32/drivers/etc/hosts"
        Copy-Item $backupHostFilePath "$($ENV:windir)/system32/drivers/etc/hosts"
        Start-Sleep -Seconds 2
    }

    Get-dnsclientserveraddress | Set-DnsClientServerAddress -ResetServerAddresses
    CleanFiles
}

function CleanFiles {
    Remove-Item $firewallRulesPath -ErrorAction SilentlyContinue
	Remove-Item $firewallStatusPath -ErrorAction SilentlyContinue
    Remove-Item $backupHostFilePath -ErrorAction SilentlyContinue
}

if ($args[0] -ne $null) {
    $inputArg = $args[0].ToString().ToLower() 
    if ($inputArg -eq "isolate" ){
        HostIsolator    
    }
    elseif ($inputArg -eq "desolate" ){
        HostDesolator
    }
    else {
    Write-Host "Invalid parameter!"
    }
}
else {
    Write-Host "Please specify the parameter!"
}