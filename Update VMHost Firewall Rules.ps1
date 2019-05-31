##Variables
$vCenter = "Your.VCSA.Here" #Provide your $vCenter Server FQDN
$Datacenter = "Data Center" #Datacenter Name; Note: This is Case Sensite
$Cluster = "Cluster" #Cluster Name; Note: This is Case Sensite
$AdminAccount = "Administrator@vsphere.local" #Typically the administrator account is used here
$AdminPassword = Read-Host "Please type the administrator@vsphere.local password in" #Note: This must be the administrator@vsphere.local account password
$VICEngineBundleExtractedLocation = "C:\VIC\vic_v1.5.2.tar\vic_v1.5.2\vic" #Folder Location of the VIC-Machine-Windows.exe
$OpenSSLLocation = "C:\Program Files\OpenSSL-Win64\bin" #x64 Version

$OPENSSL = get-item "C:\Program Files\OpenSSL-Win64\bin\OpenSSL.exe" -ErrorAction SilentlyContinue ##x64 version 
IF(!$OPENSSL)
{
	Write-Warning "OpenSSL is not installed"
	Write-Warning "Please download and install OpenSSL"
	Write-Warning "Download similar to version Win64 OpenSSL v1.1.1b Light"
	Write-Warning "https://slproweb.com/products/Win32OpenSSL.html"
	Write-Warning "Example downlod would be https://slproweb.com/download/Win64OpenSSL_Light-1_1_1b.msi"
	write-host "Press any key to continue..."
	[void][System.Console]::ReadKey($true)
	#Start-Sleep
	#EXIT
}else{
	Write-Host "Verified: OpenSSL has been properly installed" -ForegroundColor Green
}

###Verify that OpenSSL is installed
IF($OPENSSL)
{ 
	#Get VCSA SSL Certificate Thumbprint
	#Reference https://askubuntu.com/questions/156620/how-to-verify-the-ssl-fingerprint-by-command-line-wget-curl
	CD $OpenSSLLocation
	$FULLPORT = $vCenter+":443"
	Write-Warning "Attempting to get SSL Thumbprint of VCSA. This will take a moment."
	$THUMB = .\openssl s_client -connect $FULLPORT |& .\openssl x509 -fingerprint -noout
	$ThumbPrint = $THUMB.split('=')[-1]
	Write-Host "VCSA Thumbprint is"
	Write-Host $ThumbPrint -ForegroundColor Green

	#Change Directories to the VIC-Machine-Windows.exe location
	cd $VICEngineBundleExtractedLocation

	#Set Firewall rules on cluster to allow Docker Management
	$Output = .\vic-machine-windows update firewall --target $vCenter/$Datacenter --user $AdminAccount --password $AdminPassword --compute-resource $Cluster --thumbprint $Thumbprint --allow
	$Output
	IF($Output -like "*Command completed successfully*")
	{
		Write-Host "Host Firewall Rules Updated Successfully" -ForegroundColor Green
	}Else {
		Write-Error "Host Firewall Rules Did NOT Update Successfully"
	}
	####END OF SCRIPT
}
Write-Host "vSphere Cluster"$Cluster"Firewall Rules Successfully Configured"

Write-Host "This script has completed its tasks"
