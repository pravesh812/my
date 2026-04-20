# ============================================
# WinRM Hardened Setup Script (NTLM Based)
# Description:
# This script securely configures WinRM by:
# - Creating an HTTPS listener using a self-signed certificate
# - Disabling Basic authentication
# - Enabling NTLM/Negotiate authentication
# - Blocking unencrypted communication
# - Configuring a firewall rule for port 5986 (HTTPS)
# - Enabling LocalAccountTokenFilterPolicy for local account access
# ============================================

$ErrorActionPreference = 'Stop'

Write-Output "=== Starting WinRM Hardened Setup for Harness (NTLM) ==="

# Allow script execution temporarily
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# (Optional) Set Admin password - use secure method in production
# net user Administrator "mypassword!"

# Get hostname (AWS IMDSv2 fallback supported)
try {
    $token = Invoke-RestMethod `
        -Headers @{"X-aws-ec2-metadata-token-ttl-seconds" = "21600"} `
        -Method PUT `
        -Uri "http://169.254.169.254/latest/api/token"

    $hostname = Invoke-RestMethod `
        -Headers @{"X-aws-ec2-metadata-token" = $token} `
        -Method GET `
        -Uri "http://169.254.169.254/latest/meta-data/hostname"
}
catch {
    $hostname = $env:COMPUTERNAME
}

Write-Output "Hostname: $hostname"

# Enable and start WinRM
Set-Service WinRM -StartupType Automatic
Start-Service WinRM

Enable-PSRemoting -Force

# Remove existing listeners
Get-ChildItem WSMan:\localhost\Listener | ForEach-Object {
    $transport = ($_.Keys -split '=')[1]
    Remove-WSManInstance `
        -ResourceURI 'winrm/config/Listener' `
        -SelectorSet @{ Address = '*'; Transport = $transport }
}

Write-Output "Old listeners removed"

# Create self-signed certificate
$cert = New-SelfSignedCertificate `
    -DnsName $hostname `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -NotAfter (Get-Date).AddYears(3)

$thumbprint = $cert.Thumbprint

# Create HTTPS listener
New-WSManInstance `
    -ResourceURI 'winrm/config/Listener' `
    -SelectorSet @{ Transport = 'HTTPS'; Address = '*' } `
    -ValueSet @{ Hostname = $hostname; CertificateThumbprint = $thumbprint }

Write-Output "HTTPS listener created"

# Harden authentication settings
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
Set-Item WSMan:\localhost\Client\Auth\Basic -Value $false
Set-Item WSMan:\localhost\Service\Auth\Negotiate -Value $true
Set-Item WSMan:\localhost\Service\Auth\CredSSP -Value $false

# Disallow unencrypted traffic
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false
Set-Item WSMan:\localhost\Client\AllowUnencrypted -Value $false

# Fix remote UAC restrictions for local accounts
New-ItemProperty `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "LocalAccountTokenFilterPolicy" `
    -Value 1 `
    -PropertyType DWORD `
    -Force

Write-Output "LocalAccountTokenFilterPolicy enabled"

# Configure firewall
netsh advfirewall firewall delete rule name="Windows Remote Management (HTTP-In)" 2>$null

New-NetFirewallRule `
    -DisplayName "WinRM HTTPS 5986" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 5986 `
    -Action Allow

Write-Output "Firewall configured"

# Restart WinRM to apply changes
Restart-Service WinRM

# Validation
Write-Output "=== VALIDATION ==="
winrm enumerate winrm/config/listener
winrm get winrm/config/service/auth

Write-Output "=== WinRM setup completed successfully ==="
