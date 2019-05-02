<#
    .NOTES
	===========================================================================
	Created by:		Russell Hamker
	Date:			April 11, 2019
	Version:		1.0
	Twitter:		@butch7903
	GitHub:			https://github.com/butch7903
	===========================================================================

	.SYNOPSIS
		This script automates the full server build process for vSphere Integrated Containers. This includes generating all certificates
		using a Windows CA and CA Template. You must open this script and change the variables to match your environment and then execute
		the PS1 file.

	.DESCRIPTION
		Use this script to build the vSphere Integrated Containers Appliance. Fill in the variables and then simply run this script to
		automate the process of deploying vSphere Integrated Containers.

	.NOTES
		
#>

##Check if Modules are installed, if so load them, else install them
if (Get-InstalledModule -Name VMware.PowerCLI -MinimumVersion 11.1.0) {
	Write-Host "-----------------------------------------------------------------------------------------------------------------------"
	Write-Host "PowerShell Module VMware PowerCLI required minimum version was found previously installed"
	Write-Host "Importing PowerShell Module VMware PowerCLI"
	Import-Module -Name VMware.PowerCLI
	Write-Host "Importing PowerShell Module VMware PowerCLI Completed"
	$POWERCLIVERSION = get-installedmodule VMware.PowerCLI | Select Name, Version
	Write-Host "PowerCLI Version is:"($POWERCLIVERSION.Version)
	Write-Host "-----------------------------------------------------------------------------------------------------------------------"
	#CLEAR
} else {
	Write-Host "-----------------------------------------------------------------------------------------------------------------------"
	Write-Host "PowerShell Module VMware PowerCLI does not exist"
	Write-Host "Setting Micrsoft PowerShell Gallery as a Trusted Repository"
	Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
	Write-Host "Verifying that NuGet is at minimum version 2.8.5.201 to proceed with update"
	Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false
	Write-Host "Uninstalling any older versions of the VMware PowerCLI Module"
	Get-InstalledModule -Name VMware.PowerCLI -AllVersions | Uninstall-Module -Force
	Write-Host "Checking if VMware PowerCLI is still showing as Installed"
	$POWERCLI = Import-Module VMware.PowerCLI -ErrorAction SilentlyContinue
	IF($POWERCLI)
	{
		Write-Host "VMware PowerCLI Version Found"
		Write-Host "Upgrading VMware PowerCLI to Current"
		Remove-Module VMware.PowerCLI -ErrorAction SilentlyContinue
		Update-Module -Name VMware.PowerCLI -Scope AllUsers -Force
	}Else{
		Write-Host "Installing Newest version of VMware PowerCLI PowerShell Module"
		Install-Module -Name VMware.PowerCLI -Scope AllUsers -Force
	}
	Write-Host "Creating a Desktop shortcut to the VMware PowerCLI Module"
	$AppLocation = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
	$Arguments = '-noe -c "Import-Module VMware.PowerCLI"'
	$WshShell = New-Object -ComObject WScript.Shell
	$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\VMware PowerCLI.lnk")
	$Shortcut.TargetPath = $AppLocation
	$Shortcut.Arguments = $Arguments
	$ShortCut.Hotkey = "CTRL+SHIFT+V"
	$Shortcut.IconLocation = "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe,1"
	$Shortcut.Description ="Launch VMware PowerCLI"
	$Shortcut.WorkingDirectory ="C:\"
	$Shortcut.Save()
	Write-Host "Shortcut Created"
	Write-Host "You may use the CTRL+SHIFT+V method to open VMware PowerCLI"
	Write-Host "Importing PowerShell Module VMware PowerCLI"
	Import-Module -Name VMware.PowerCLI
	Write-Host "PowerShell Module VMware PowerCLI Loaded"
	$POWERCLIVERSION = get-installedmodule VMware.PowerCLI | Select Name, Version
	Write-Host "PowerCLI Version is:"($POWERCLIVERSION.Version)
	Write-Host "-----------------------------------------------------------------------------------------------------------------------"
	#Clear
}

##Setting PowerCLI To Ignore Certificate Issues
Write-Host "Setting PowerCli to ignore Certificate issues"
Write-Host "This is a known issue to cause OVA imports to fail"
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Scope AllUsers -Confirm:$false

##VIC Certicate Variables
$VICNAME = "HAMVICA01" #Short name for your VICA (not FQDN)
$VICIP = "192.168.1.64" #Example 10.27.1.12
$VICNETMASK = "255.255.255.0" #Example 255.255.255.0
$VICGATEWAY = "192.168.1.1" #Example 192.168.1.1
$VICDOMAIN = "hamker.local"
$CERTTEMPLATE = "CertificateTemplate:VmwareWebServer" #To List the Certiicate Templates to get the right 1 #certutil -template | Select-String -Pattern TemplatePropCommonName #Example CertificateTemplate:Vmware6.0WebServer
$VICNAME = $VICNAME.ToLower() #VICNAME Should be lower case
$VICFQDN = "$VICNAME.$VICDOMAIN"
$COUNTRY = "US" #2 Letter Country Code
$STATE = "KS" #Your State
$CITY = "Wichita" #Your City
$COMPANY = "Hamker Tech" #Your Company
$DEPARTMENT = "IT" #Your Department

#Standard Variables
$CERTLOCATION = "C:\Certs"
$VICCertLocationGet = Get-Item "$CERTLOCATION\VIC" -ErrorAction SilentlyContinue
$VICCertLocation = "$CERTLOCATION\VIC"
$VICKEYGET = Get-Item "$VICCertLocation\$VICNAME.key" -ErrorAction SilentlyContinue
$VICKEY = "$VICCertLocation\$VICNAME.key" # This is in RSA format
$VICKEYPEMGET = Get-Item "$VICCertLocation\$VICNAME-key.pem" -ErrorAction SilentlyContinue
$VICKEYPEM = "$VICCertLocation\$VICNAME-key.pem" # This is in PEM format
$VICCSRGET = Get-Item "$VICCertLocation\$VICNAME.csr" -ErrorAction SilentlyContinue
$VICCSR = "$VICCertLocation\$VICNAME.csr"
$VICCERGET = Get-Item "$VICCertLocation\$VICNAME.cer" -ErrorAction SilentlyContinue
$VICCER = "$VICCertLocation\$VICNAME.cer" #This is in DER format
$VICPEMGET = Get-Item "$VICCertLocation\$VICNAME.pem" -ErrorAction SilentlyContinue
$VICPEM = "$VICCertLocation\$VICNAME.pem" # This is in PEM format

#Certificate Customizable Variables
$CAFILELOCATION = "C:\certs\CAs\Combined\CombinedCA_HAMCA01-CA-PEM.pem" #Make sure you put your Combined CA PEM file somewhere it can be copied over easily from #Example C:\Certs\CA\Combined\CombinedCA_HAMCA01-CA-PEM.pem
$CACERT = "$VICCertLocation\CA.pem" #This must be in PEM format, note this is copied from a network location typically #Example CombinedCA_HAMCA01-CA-PEM.pem
$CERTIFICATESERVER = "HAMCA01.hamker.local" #FQDN of the Certificate server you are getting your certs from #Example HAMCA01.hamker.local
$OpenSSLLocation = "C:\Program Files\OpenSSL-Win64\bin" #x64 Version

#OVA Deployment Settings
$VCSA = "hamvc01.hamker.local" #FQDN of VCSA
$OVAPATH = "C:\VMware\VIC\1.5.2\vic-v1.5.2-7206-92ebfaf5.ova" #File Location of VICA OVA File
$CLUSTER = "Cluster" #VMware cluster to deploy to
$OVADATASTORE = "HAMNAS03_iSCSI" #Datastore to deploy OVA to
$OVAPORTGROUP = "(1) Server" #Network Port group to deploy OVA to
$VICPERMITROOTLOGIN = "True" #Specifies whether root user can log in using SSH. Default is True
$VICAPPLIANCEPORT = "9443" #Port used to access VICA primary interface. Used to connect VCSA to VICA and has links to VICA other sites. Default is 9443
$VICDEFAULTUSERS = "False" #Uncheck to skip creation of Example Users. Default is True
$VICUSERPREFIX = "" #Username prefix to be used to create Example Users for vSphere Integrated Containers. Default is vic1
$VICUSERPASSWORD = "" #Password to be used to create Example Users. The password must follow the rules set for vSphere.
$VICMGMTPORTALPORT = "8282" #Port to use for VICA Management Portal Access. 443 will redirect to this address. Default is 8282
$VICDNSSERVER1 = "192.168.1.32"
$VICDNSSERVER2 = "192.168.1.33"
$VICDNSSERVERS = "$VICDNSSERVER1 $VICDNSSERVER2" #The domain name server IP Addresses for this VM (space separated). Leave blank if DHCP is desired.
$VICDNSSEARCHPATH = "hamker.local" #The domain search path (space separated domain names) for this VM. Leave blank if DHCP is desired.
$VICNTPSERVERS = "192.168.1.32 192.168.1.33" #The NTP server IP Addresses for this VM (space separated). Leave blank if DHCP is desired.
$VICHTTPPROXY = "" #The HTTP Proxy setting: http://PROXY_SERVER:PORT or http://USER:PASSWORD@PROXY_SERVER:PORT. Leave blank if no http proxy is required.
$VICHTTPSPROXY = "" #The HTTPS Proxy setting: http(s)://PROXY_SERVER:PORT or http(s)://USER:PASSWORD@PROXY_SERVER:PORT. Leave blank if no https proxy is required.
$VICNOPROXYLIST = "" #Bypass proxy settings for these hosts and domains (comma separated). Leave blank if no proxy is required.
$VICREGISTRYPORT = "443" #Specifies the port on which registry will be published. Default is 443
$VICNOTARYPORT = "4443" #Specifies the port on which Notary will be published.. Default is 4443
$VICGARBAGECOLLECTION = "True" #When setting this to true, registry performs garbage collection everytime it boots up. Default is False

#Standard OVA Deployment Variables
$VCSACREDS = Get-Credential -Message "Please specify a VCSA User account with Admin rights to deploy a VM with"
$OVAPASSWORD = Read-Host "Please type a Password for the VIC Root account"


##Logging Info
#Get Date Info for naming of snapshot variable
$LOGDATE = Get-Date -format "MMM-dd-yyyy_HH-mm"
#Specify Log File Info
$LOGFILENAME = "Log_" + $VICNAME + "_" + $LOGDATE + ".txt"
#Create Log Folder
$LogFolder = $VICCertLocation+"\Log"
If (Test-Path $LogFolder){
	Write-Host "Log Directory Created. Continuing..."
}Else{
	New-Item $LogFolder -type directory
}
#Specify Log File
$LOGFILE = $VICCertLocation+"\Log\"+$LOGFILENAME

##Starting Logging
Start-Transcript -path $LOGFILE -Append


###Test if OpenSSL is Installed
##Specify OpenSSL version. If you have a 64-bit OS, use the x64 version. If you have a 32-bit OS, use the x86 version
#$OPENSSL = get-item "C:\Program Files (x86)\OpenSSL-Win32\bin\OpenSSL.exe" -ErrorAction SilentlyContinue ##x86 version
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
	#CNF Config
	$CNF = "[ req ]
	default_md = sha512
	default_bits = 2048
	default_keyfile = key.key
	distinguished_name = req_distinguished_name
	encrypt_key = no
	prompt = no
	string_mask = nombstr
	req_extensions = v3_req

	[ v3_req ]
	basicConstraints = CA:false
	keyUsage = keyEncipherment, digitalSignature, keyAgreement
	extendedKeyUsage = serverAuth, clientAuth
	subjectAltName = @alt_names

	[ alt_names ]
	DNS.1 = $VICFQDN
	IP.1 = $VICIP

	[ req_distinguished_name ]
	C=$COUNTRY
	ST=$STATE
	L=$CITY
	O=$COMPANY
	OU=$DEPARTMENT
	CN=$VICFQDN
	"

	#Open OpenSSL EXE Location
	Write-Host "-----------------------------------------------------------------------------------------------------------------------"
	Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
	Write-Host "Starting Certifacte Creation Process"
	CD $OpenSSLLocation
	
	#Make new VIC Cert Folder for storing all the Cert files
	IF(!$VICCertLocationGet)
	{
		New-Item -Path $VICCertLocation -ItemType "directory" -ErrorAction SilentlyContinue
		Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
	}else {
		Write-Host "VIC Folder already created at" $VICCertLocation -ForegroundColor Green
		Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
	}
	
	#Make VIC Config file
	$CFGFILE = New-Item -Path $VICCertLocation -Name "$VICNAME.cfg" -ItemType "file" -Force
	#$CNF | Out-File -FilePath $CFGFILE
	
	#Write contents to Config file from $CNF Variable
	Set-Content -Path $CFGFILE -Value $CNF
	$CFGFILEFULLNAME = $cfgfile.fullname
	
	IF(!$VICKEYGET)
	{
		#Open OpenSSL EXE Location
		CD $OpenSSLLocation
		.\openssl genrsa -out $VICKEY 2048
		Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
	}else {
		Write-Host "Key.key already generated at" $VICKEY -ForegroundColor Green
		Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
	}
	
	IF(!$VICKEYPEMGET)
	{
		Write-Host "VICA-key.pem file does not exist"
		Write-Host "Generating VICA-key.pem file"
		#Open OpenSSL EXE Location
		CD $OpenSSLLocation
		.\openssl pkcs8 -topk8 -in $VICKEY -outform PEM -nocrypt -out $VICKEYPEM
		Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
	}else {
		Write-Host "Key.pem already generated at" $VICKEYPEM -ForegroundColor Green
		Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
	}

	IF(!$VICCSRGET)
	{
		Write-Host "VICA CSR File Not Found"
		Write-Host "Generating VICA CSR"
		#Open OpenSSL EXE Location
		CD $OpenSSLLocation
		.\openssl req -config $CFGFILEFULLNAME -new -key $VICKEY -out $VICCSR
		Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
	}else {
		Write-Host "Server.csr already generated at" $VICCSR -ForegroundColor Green
		Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
	}
	
	$CA = certutil -config $CERTIFICATESERVER -ping
	$CA = $CA[1]
	$CA = $CA.Replace("Server "," ")
	$CA = $CA.SubString(0, $CA.IndexOf('ICertRequest2'))
	$CA = $CA.Replace('"','')
	$CA = $CA.Replace(' ','')

	#To List the Certiicate Templates to get the right 1
	#certutil -template | Select-String -Pattern TemplatePropCommonName
	#Detailed Example certutil -template | Select-String -Pattern Vmware6.0WebServer
	
	#Generate CER
	IF(!$VICCERGET)
	{
		certreq -submit -attrib $CERTTEMPLATE -Kerberos -config $CERTIFICATESERVER\$CA $VICCSR $VICCER
		Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
	}else {
		Write-Host "Server.Cer already generated at" $VICCER -ForegroundColor Green
		Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
	}
	
	#Convert CER to PEM
	IF(!$VICPEMGET)
	{
		#Open OpenSSL EXE Location
		CD $OpenSSLLocation
		.\openssl x509 -in $VICCER -outform PEM -out $VICPEM
		Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
	}else {
		Write-Host "Server.pem already generated at" $VICPEM -ForegroundColor Green
		Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
	}
	
	#Copy CA Cert to Local Workstation
	#Place your CA Cert to the VIC folder
	Write-Host "Copying CA PEM File to VIC Cert folder"
	Copy-Item $CAFILELOCATION $CACERT -ErrorAction SilentlyContinue
	Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")

	Write-Host "VIC Certificate Generation Process Completed" $VICCSR -ForegroundColor Green
	Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
	Write-Host "-----------------------------------------------------------------------------------------------------------------------"
}

#Generate DNS record for VICA
try
{
	$DNSCHK = [System.Net.DNS]::GetHostAddresses($VICNAME)
}
catch
{
	$DNSEXIST = "false"
}
IF(!$DNSCHK)
{
	Write-Host "DNS Entry not found for VIC Applaince. Attempting to generate DNS entry"
	Add-DnsServerResourceRecordA -Name $VICNAME -ZoneName $VICDOMAIN -AllowUpdateAny -IPv4Address $VICIP -ComputerName $VICDNSSERVER1
}Else{
	Write-Host "DNS Entry has already been created for VIC Appliance. Continuing..."
}

###Create VIC
#Starting
Write-Host "Starting vCenter VIC Customizations" -ForegroundColor Green

##Disconnect from any open vCenter Sessions
#This can cause problems if there are any
Write-Host "-----------------------------------------------------------------------------------------------------------------------"
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
Write-Host "Disconnecting from any Open vCenter Sessions"
TRY
{Disconnect-VIServer * -Confirm:$false}
CATCH
{Write-Host "No Open vCenter Sessions found"}
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
Write-Host "-----------------------------------------------------------------------------------------------------------------------"

##Connect to vCenter Server
Write-Host "-----------------------------------------------------------------------------------------------------------------------"
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
Write-Host "Connecting to vCenter "$VCSA
$VCENTER = Connect-VIServer -server $VCSA -Credential $VCSACREDS
$VCENTER
Write-Host "Connected to vCenter "
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
Write-Host "-----------------------------------------------------------------------------------------------------------------------"

##Deploy OVA
Write-Host "-----------------------------------------------------------------------------------------------------------------------"
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
#Reference: https://pubs.vmware.com/vsphere-6-5/index.jsp?topic=%2Fcom.vmware.powercli.cmdletref.doc%2FGet-OvfConfiguration.html
Write-Host "Deploying OVA to"$VCSA" on VMware Host"$VMHOST
#Get Configuration info from OVA
$OVAConfig = Get-OvfConfiguration -Ovf $OVAPATH
$VMHOST = Get-Cluster -Name $CLUSTER | Get-VMHost | Where-Object {$_.ConnectionState -eq "Connected"} | Get-Random
$PORTGROUP = Get-VirtualPortGroup -Host $VMHOST -Name $OVAPORTGROUP

#Fill In info for OVA
#Appliance
$OVAConfig.appliance.root_pwd.value = $OVAPASSWORD
$OVAConfig.appliance.permit_root_login.Value = $VICPERMITROOTLOGIN #Default is TRUE
Get-Content $VICPEM | foreach{$VICPEMOUT = $VICPEMOUT  + $_}
$OVAConfig.appliance.tls_cert.Value = $VICPEMOUT #Paste the content of the PEM encoded certificate file. Leave blank for a generated self-signed certificate.
Get-Content $VICKEYPEM | foreach{$VICKEYPEMOUT = $VICKEYPEMOUT  + $_}
$OVAConfig.appliance.tls_cert_key.Value = $VICKEYPEMOUT #Paste the content of the unencrypted PEM encoded certificate key file. Leave blank for a generated key.
Get-Content $CACERT | foreach{$CACERTOUT = $CACERTOUT  + $_}
$OVAConfig.appliance.ca_cert.Value = $CACERTOUT #Paste the content of the PEM encoded CA certificate that signed the TLS Certificate. Leave blank for a generated self-signed certificate.
$OVAConfig.appliance.config_port.Value = $VICAPPLIANCEPORT #Default is 9443. Specifies the port on which the Getting Started Page and Appliance Configuration will be published.
#Default Users
$OVAConfig.default_users.create_def_users.Value = $VICDEFAULTUSERS #Uncheck to skip creation of Example Users. Default is True
$OVAConfig.default_users.def_user_prefix.Value = $VICUSERPREFIX #Username prefix to be used to create Example Users for vSphere Integrated Containers. Default is vic
$OVAConfig.default_users.def_user_password.Value = $VICUSERPASSWORD #Password to be used to create Example Users. The password must follow the rules set for vSphere.
#IP Protocol
$OVAConfig.IpAssignment.IpProtocol.Value = "IPv4" #This is the Network Protocol to use. Either IPv4 or IPv6
#Management Portal Port
$OVAConfig.management_portal.management_portal_port.Value = $VICMGMTPORTALPORT #Default is 8282. Specifies the port on which Management Portal will be published.
#Network
$OVAConfig.Network.ip0.Value = $VICIP #VICA IP Address
$OVAConfig.Network.netmask0.Value = $VICNETMASK #VICA Network Mask
$OVAConfig.Network.gateway.Value = $VICGATEWAY #VICA Network Gateway
$OVAConfig.Network.DNS.Value = $VICDNSSERVERS #VICA DNS Servers
$OVAConfig.Network.searchpath.Value = $VICDNSSEARCHPATH #VICA DNS Search Path. List the DNS domains you want it to see
$OVAConfig.Network.fqdn.Value = $VICFQDN #The fully qualified domain name of this VM. Leave blank if DHCP is desired.
$OVAConfig.Network.ntp.Value = $VICNTPSERVERS #VICA NTP Servers. 
$OVAConfig.Network.http_proxy.Value = $VICHTTPPROXY #VICA HTTP Proxy
$OVAConfig.Network.https_proxy.Value = $VICHTTPSPROXY #VICA HTTPS Proxy
$OVAConfig.Network.no_proxy_list.Value = $VICNOPROXYLIST #VICA No Proxy List
#NetworkMapping
$OVAConfig.NetworkMapping.Network.Value = $PORTGROUP #Port Group (I Think, this is not well documented)
#Registry
$OVAConfig.registry.registry_port.Value = $VICREGISTRYPORT #VICA Registry Port
$OVAConfig.registry.notary_port.Value = $VICNOTARYPORT #VICA Notary Port
$OVAConfig.registry.gc_enabled.Value = $VICGARBAGECOLLECTION #VICA Garabage Collection True/False

#List OVAConfig Details
Write-Host "Listing OVA Config Contents:"
Write-Host "Root Password:"#$OVAConfig.appliance.root_pwd.value
Write-Host "Permit Root Login:"$OVAConfig.appliance.permit_root_login.Value
Write-Host "TLS Cert:"$OVAConfig.appliance.tls_cert.Value
Write-Host "TLS Cert Key:"$OVAConfig.appliance.tls_cert_key.Value
Write-Host "CA Cert:"$OVAConfig.appliance.ca_cert.Value
Write-Host "VIC Appliance Network Port:"$OVAConfig.appliance.config_port.Value
Write-Host "Create Default Users:"$OVAConfig.default_users.create_def_users.Value
Write-Host "Create Default Users Name:"$OVAConfig.default_users.def_user_prefix.Value
Write-Host "Create Default Users Password:"$OVAConfig.default_users.def_user_password.Value
Write-Host "VIC Appliance Network Protocol:"$OVAConfig.IpAssignment.IpProtocol.Value
Write-Host "VIC Applaince Management Portal Port:"$OVAConfig.management_portal.management_portal_port.Value
Write-Host "VIC Appliance IP:"$OVAConfig.Network.ip0.Value
Write-Host "VIC Appliance Netmask:"$OVAConfig.Network.netmask0.Value
Write-Host "VIC Appliance Gateway:"$OVAConfig.Network.gateway.Value
Write-Host "VIC Appliance DNS Servers:"$OVAConfig.Network.DNS.Value
Write-Host "VIC Appliance DNS Search Path:"$OVAConfig.Network.searchpath.Value
Write-Host "VIC Appliance FQDN:"$OVAConfig.Network.fqdn.Value
Write-Host "VIC Appliance NTP Servers:"$OVAConfig.Network.ntp.Value
Write-Host "VIC Appliance HTTP Proxy:"$OVAConfig.Network.http_proxy.Value
Write-Host "VIC Appliance HTTPS Proxy:"$OVAConfig.Network.https_proxy.Value
Write-Host "VIC Appliance No Proxy List:"$OVAConfig.Network.no_proxy_list.Value
Write-Host "VIC Appliance Portgroup:"$OVAConfig.NetworkMapping.Network.Value
Write-Host "VIC Appliance Registry Port:"$OVAConfig.registry.registry_port.Value
Write-Host "VIC Appliance Notary Port:"$OVAConfig.registry.notary_port.Value
Write-Host "VIC Appliance Garbage Collection:"$OVAConfig.registry.gc_enabled.Value
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
Write-Host "-----------------------------------------------------------------------------------------------------------------------"

#Deploy
Write-Host "-----------------------------------------------------------------------------------------------------------------------"
Write-Host "Deploying vSphere Integrated Containers Applaince..." -foregroundcolor "yellow"
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
$VICVM = Import-VApp -Source $OVAPATH -OvfConfiguration $OVAConfig -Name $VICNAME.toUpper() -VMHost $VMHOST -Datastore $OVADATASTORE -DiskStorageFormat "Thick"
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
Write-Host "OVA Deployment Completed"
Write-Host "-----------------------------------------------------------------------------------------------------------------------"

##Upgrade Hardware Version to Current prior to first poweron
Write-Host "-----------------------------------------------------------------------------------------------------------------------"
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
Write-Host "Upgrading Virtual Hardware to Current Version"
$VMHOSTDETAILS = Get-VMHost $VMHOST
$VMHOSTVERSION = $VMHOSTDETAILS.VERSION
IF($VMHOSTVERSION -eq "6.7.0")
{
	Write-Host "VMHost "$VMHOST" is running ESXi 6.7.0"
	$VMEXPECTEDVERSION = "v14"
	$VMVERSION = Get-VM $VICNAME | Select Version
	$VMVERSION = $VMVERSION.Version
	IF($VMEXPECTEDVERSION -notmatch $VMVERSION)
	{
		Write-Host "Upgrading VM "$VICNAME" to match VMHost ESXi version"
		Set-VM -VM (Get-VM -Name $VICNAME) -Version v14 -Confirm:$false
	}ELSE{
	Write-Host "VM is presently at Current Hardware Version for VMHost "$VMHOST
	}
}
IF($VMHOSTVERSION -eq "6.5.0")
{
	Write-Host "VMHost "$VMHOST" is running ESXi 6.5.0"
	$VMEXPECTEDVERSION = "v13"
	$VMVERSION = Get-VM $VICNAME | Select Version
	$VMVERSION = $VMVERSION.Version
	IF($VMEXPECTEDVERSION -notmatch $VMVERSION)
	{
		Write-Host "Upgrading VM "$VICNAME" to match VMHost ESXi version"
		Set-VM -VM (Get-VM -Name $VICNAME) -Version v13 -Confirm:$false
	}ELSE{
	Write-Host "VM is presently at Current Hardware Version for VMHost "$VMHOST
	}
}
IF($VMHOSTVERSION -eq "6.0.0")
{
	Write-Host "VMHost "$VMHOST" is running ESXi 6.0.0"
	$VMEXPECTEDVERSION = "v11"
	$VMVERSION = Get-VM $VICNAME | Select Version
	$VMVERSION = $VMVERSION.Version
	IF($VMEXPECTEDVERSION -notmatch $VMVERSION)
	{
		Write-Host "Upgrading VM "$VICNAME" to match VMHost ESXi version"
		Set-VM -VM (Get-VM -Name $VICNAME) -Version v11 -Confirm:$false
	}ELSE{
	Write-Host "VM is presently at Current Hardware Version for VMHost "$VMHOST
	}
}
Write-Host "Upgrading Virtual Hardware to Current Version Completed"
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
Write-Host "-----------------------------------------------------------------------------------------------------------------------"

#Start vSphere Integrated Containers Appliance
Write-Host "-----------------------------------------------------------------------------------------------------------------------"
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
Write-Host "Starting $VICNAME" -foregroundcolor "yellow"
Start-VM -VM $VICVM | Out-Null
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
Write-Host "-----------------------------------------------------------------------------------------------------------------------"

#Notify User of Completion
Write-Host "-----------------------------------------------------------------------------------------------------------------------"
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
Write-Host "vSphere Integrated Containers Appliance Deployment Completed"
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
Write-Host "-----------------------------------------------------------------------------------------------------------------------"

#Open VIC VM Console
Write-Host "-----------------------------------------------------------------------------------------------------------------------"
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
#Checking if VMRC is Installed
Write-Host "Checking if VMRC is Installed"
$VMRC = get-item "C:\Program Files (x86)\VMware\VMware Remote Console\vmrc.exe" -ErrorAction SilentlyContinue
IF($VMRC)
{
	Write-Host "Opening Console of vSphere Integrated Containers Appliance"$VICNAME
	Open-VMConsoleWindow -VM $VICNAME
}Else{
	Write-Warning "VMware Remote Console Application is not installed."
	Write-Warning "Skipping opening VMRC to"$VICNAME
}
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
Write-Host "-----------------------------------------------------------------------------------------------------------------------"

#Open VIC Web Interface
Write-Host "-----------------------------------------------------------------------------------------------------------------------"
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
$URL = "http://$VICFQDN"
Start-Process -FilePath $URL
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
Write-Host "-----------------------------------------------------------------------------------------------------------------------"

##Disconnect from vCenter
Write-Host "-----------------------------------------------------------------------------------------------------------------------"
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
Write-Host "Disconnecting from vCenter"
disconnect-viserver $VCENTER -confirm:$false
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
Write-Host "-----------------------------------------------------------------------------------------------------------------------"

##Stopping Logging
#Note: Must stop transcriptting prior to sending email report with attached log file
Write-Host "-----------------------------------------------------------------------------------------------------------------------"
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
Write-Host "All Processes Completed"
Write-Host "Stopping Transcript"
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
Write-Host "-----------------------------------------------------------------------------------------------------------------------"
Stop-Transcript

Write-Host "This script has completed its tasks"

