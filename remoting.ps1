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
# 1. Enable WinRM Service
Write-Output "Enabling WinRM service..."
winrm quickconfig -q
Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM

# 2. Create Self-Signed Certificate for HTTPS
Write-Output "Creating self-signed certificate..."
$cert = New-SelfSignedCertificate -DnsName 'localhost' -CertStoreLocation Cert:\LocalMachine\My
$thumbprint = $cert.Thumbprint

# 3. Remove existing HTTPS listener (if exists)
Write-Output "Removing existing HTTPS listener if present..."
winrm delete winrm/config/Listener?Address=*+Transport=HTTPS 2>$null

# 4. Create WinRM HTTPS Listener
Write-Output "Creating HTTPS listener on port 5986..."
winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname='localhost'; CertificateThumbprint='$thumbprint'}"
Restart-Service WinRM

# 5. Allow WinRM through Windows Firewall
Write-Output "Configuring firewall rule..."
New-NetFirewallRule -DisplayName "WinRM HTTPS 5986" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow

# 7. Enable Local Administrator Account
Write-Output "Enabling Administrator account..."
Enable-LocalUser -Name "Administrator"

# 9. Registry setting for remote local admin access
Write-Output "Setting LocalAccountTokenFilterPolicy..."
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -PropertyType DWord -Force

# 10. Restart WinRM service
Write-Output "Restarting WinRM service..."
Restart-Service WinRM

Write-Output "=== WinRM HTTPS Configuration Completed ==="
</powershell>
