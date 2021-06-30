<#
.SYNOPSIS
Get Untrusted host certificates
.DESCRIPTION
TPM enabled VMs requires the existence of the Untrusted Guardian certificates stored in the Shielded VM Local Certificates store
In case of a cluster, each node will have their own self signed certificate for this purpose
VM migration requires that the target node must have the same UG certificates as the source node
This script will help to extract certs from the store
.NOTES
Requires administrative access

  Version:        1.0
  Author:         Rózsa Gábor
  Creation Date:  2021-06-30
  Purpose/Change: Original version
#>

#Requires -RunAsAdministrator

#basic variables
$Computer = $Env:Computername

Write-Host "Initiating Untrusted Guardian cert export" -ForegroundColor Green
$CertificatePassword = Read-Host -Prompt 'Please enter a password to secure the certificate files' -AsSecureString

#UG check
$UntrustedGuardian = Get-HgsGuardian -Name UntrustedGuardian
if (!$UntrustedGuardian) {
    Write-Host "Creating Untrusted Guardian certificates" -ForegroundColor Yellow
    $UntrustedGuardian = New-HgsGuardian -Name UntrustedGuardian -GenerateCertificates
}

#getting certs
$encryptionCertificate = Get-Item -Path "Cert:\LocalMachine\Shielded VM Local Certificates\$($UntrustedGuardian.EncryptionCertificate.Thumbprint)"
$signingCertificate = Get-Item -Path "Cert:\LocalMachine\Shielded VM Local Certificates\$($UntrustedGuardian.SigningCertificate.Thumbprint)"

#private key check
if (-not ($encryptionCertificate.HasPrivateKey -and $signingCertificate.HasPrivateKey)) {
    throw 'One or both of the certificates in the guardian do not have private keys. ' + `
        'Please ensure the private keys are available on the local system for this guardian.'
}

#export
Export-PfxCertificate -Cert $encryptionCertificate -FilePath "c:\temp\$Computer-TPMencryption.pfx" -Password $CertificatePassword
Export-PfxCertificate -Cert $signingCertificate -FilePath "c:\temp\$Computer-TPMsigning.pfx" -Password $CertificatePassword

#finish
Write-Host "Finished exporting the UG certs." -ForegroundColor Green