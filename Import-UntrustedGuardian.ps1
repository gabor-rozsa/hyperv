<#
.SYNOPSIS
Import Untrusted Guardian certificates
.DESCRIPTION
TPM enabled VMs requires the existence of the Untrusted Guardian certificates stored in the Shielded VM Local Certificates store
In case of a cluster, each node will have their own self signed certificate for this purpose
VM migration requires that the target node must have the same UG certificates as the source node
This script will help to imports certs to the store
.NOTES
Requires administrative access

  Version:        1.0
  Author:         Rózsa Gábor
  Creation Date:  2021-06-30
  Purpose/Change: Original version
#>

#Requires -RunAsAdministrator

#basic variables
$CertPath = "c:\temp"

Write-Host "Initiating Untrusted Guardian cert import" -ForegroundColor Green

#getting the pfx password
$CertificatePassword = Read-Host -Prompt 'Please enter the password that was used to secure the certificate files' -AsSecureString

#getting all matching certificates
$Certs = Get-ChildItem -Path $CertPath | Where-Object { $_.name -like "*TPM*" -and $_.Extension -eq '.pfx' }


$CertSigning = get-childitem "Cert:\localmachine\Shielded VM Local Certificates" | where-object { $_.Subject -like "*Signing*" }

#looping import
foreach ($cert in $Certs) {
    try {
        $certshortname = $cert.name.substring(0, 10)
        if ($CertSigning.subject -notlike "*$certshortname*") {
            $dummy = Import-PfxCertificate -exportable -FilePath $cert -CertStoreLocation "Cert:\localmachine\Shielded VM Local Certificates" -Password $CertificatePassword 
            Write-Host "$cert.name imported"
        }
        else {
            Write-Host "$cert.name is already present in the store" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "An error occured importing $cert.name" -ForegroundColor Red
    }

}

#finish
Write-Host "Finished importing the UG certs." -ForegroundColor Green
