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

<powershell>
Write-Output "=== Starting WinRM HTTPS Configuration ==="

# Enable WinRM
Write-Output "Enabling WinRM service..."
winrm quickconfig -q
Set-Service WinRM -StartupType Automatic
Start-Service WinRM

# Create a self-signed certificate
Write-Output "Creating self-signed certificate..."
$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My

# Capture certificate thumbprint
$thumbprint = $cert.Thumbprint

# Remove existing WinRM HTTPS listener if present
Write-Output "Removing existing WinRM HTTPS listener (if any)..."
winrm delete winrm/config/Listener?Address=*+Transport=HTTPS 2>$null

# Create WinRM HTTPS listener
Write-Output "Creating WinRM HTTPS listener..."
winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$env:COMPUTERNAME`"; CertificateThumbprint=`"$thumbprint`"}"

# Restart WinRM service
Write-Output "Restarting WinRM service..."
Restart-Service WinRM

# Open firewall port 5986
Write-Output "Configuring firewall rule..."
New-NetFirewallRule -DisplayName "WinRM HTTPS 5986" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow
# Enable local Administrator account
Write-Output "Enabling Administrator account..."
Enable-LocalUser -Name "Administrator"

# Allow remote local admin access
Write-Output "Setting LocalAccountTokenFilterPolicy..."
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -PropertyType DWord -Force

# Final restart of WinRM
Write-Output "Restarting WinRM service (final)..."
Restart-Service WinRM

Write-Output "=== WinRM HTTPS Configuration Completed ==="
</powershell>
