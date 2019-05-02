##VCH Customizable Variables
$VCHNAME = "VCH_NAME_HERE" #Short Name for VCH
$VCHNAME = $VCHNAME.ToLower() #VCHNAME Should be lower case
$VCHFQDN = "$VCHNAME.YourDomain.Here" #specify your Domain here, Example $VCHNAME.hamker.local
$VCHIP = "VCH_IP_Here" #Standard IPv4 IP. Example 10.1.170.75
$VCHSUBNET = "24" #Subnet. Example 24
$CERTTEMPLATE = "CertificateTemplate:VmwareWebServer" #To List the Certiicate Templates to get the right 1 #certutil -template | Select-String -Pattern TemplatePropCommonName
#Cert Info
$COUNTRY = “US” #2 Letter Country Code. Example US
$STATE = “Kansas” #State Name. Example Kansas
$CITY = “Wichita” #City Name. Example Wichita
$COMPANY = “Hamker Tech” #Company Name. Example Hamker Tech
$ORG = “IT” #Company Organization. Example IT
#Standard Variables
$VCHCertLocationGet = Get-Item "C:\Certs\VCH_CERTS\$VCHNAME\" -ErrorAction SilentlyContinue
$VCHCertLocation = "C:\Certs\VCH_CERTS\$VCHNAME"
$SERVERKEYGET = Get-Item "$VCHCertLocation\$VCHNAME.key" -ErrorAction SilentlyContinue
$SERVERKEY = "$VCHCertLocation\$VCHNAME.key" # This must be in RSA format!!!
$SERVERCSRGET = Get-Item "$VCHCertLocation\$VCHNAME.csr" -ErrorAction SilentlyContinue
$SERVERCSR = "$VCHCertLocation\$VCHNAME.csr"
$SERVERCERGET = Get-Item "$VCHCertLocation\$VCHNAME.cer" -ErrorAction SilentlyContinue
$SERVERCER = "$VCHCertLocation\$VCHNAME.cer"
$SERVERPEMGET = Get-Item "$VCHCertLocation\$VCHNAME.pem" -ErrorAction SilentlyContinue
$SERVERPEM = "$VCHCertLocation\$VCHNAME.pem" # This must be in PEM format
#Customizable Variables
$CACERTLOCATION = "C:\certs\VIC\CA.pem"
$CACERT = "$VCHCertLocation\CA.pem" #This must be in PEM format, note this is copied from a network location typically
$REGISTRYCALOCATION = "C:\certs\VIC\CA.pem" #This is the registry CA.crt file you download from the VIC Web interface
$REGISTRYCACERT = "C:\certs\VIC\CA.pem" #This is copied from the network to the local VCH folder. This is your CA Authority Cert you installed on the VIC.
$CERTIFICATESERVER = "FQDN.OfCA.Server" #Example hamca01.hamker.local 
$OpenSSLLocation = "C:\Program Files\OpenSSL-Win64\bin" #x64 Version
#$OpenSSLLocation = "C:\Program Files (x86)\OpenSSL-Win32\bin" #x86 Version

##VCH Creation Variables
$PROJECT = "your_project_name_here" #This should be lower case. This should match the project the VCH is used for. This is part of the Container Naming Convention.
$DATACENTER = "vCenter_Datacenter" #Note: This is Case Sensite. Example Datacenter
$CLUSTER = "vCenter_Cluster" #Compute resource path, e.g. myCluster Note: This is Case Sensite
#Storage
$DATASTORE1 = "vCenter_Datastore_here" #First Datastore. This is also the Default Datastore
$DATASTORE2 = "vCenter_Datastore_here" #Second Datastore. This is also volume_store_2
$ImageStore = $DATASTORE1 #This is the datastore used to store the images. This is typically 8GB or less.
#Note default volume name is required: https://vmware.github.io/vic-product/assets/files/html/1.1/vic_app_dev/ts_volume_store_error.html
$VolumeStore1 = "$DATASTORE1/"+$VCHNAME+":default"	#Specify a list of location and label for volume store, label must be unique per VCH, nfs stores can have mount options specified as query parameters in the url target.
$VolumeStore2 = "$DATASTORE2/"+$VCHNAME+":volume_store_2"	#Examples for a vsphere backed volume store are:  "datastore/path:label" or "datastore:label" or "ds://my-datastore-name:store-label"
$BaseImageSize = "8" #Specify the size of the base image from which all other images are created e.g. 8GB/8000MB (default: "8GB")
#Examples for nfs back volume stores are: "nfs://127.0.0.1/path/to/share/point?uid=1234&gid=5678&proto=tcp:my-volume-store-label" or "nfs://my-store/path/to/share/point:my-label"
#Networking
#Public IP details
$PublicNetwork = "vCenter_PortGroup_Here" #This is the portgroup used for the Public Network. In this config this is also the management network
$PublicNetworkIP = "$VCHIP/$VCHSUBNET" #sets the Public IP as a static IP with the one specified
$BridgeNetwork = "vCenter_PortGroup_Here" #This is the portgroup of the Bridge Network you created previously. This is for VCH Internal communication only. Must be /16 or larger.
$sep = $VCHIP.lastindexof(".") 
$network = $VCHIP.substring(0,$sep) 
$PublicNetworkGW = "$network.1" #sets the Public IP Default Gateway
$PublicNetworkDNS1 = "DNS_IPv4_IP_Here" #DNS1 IP. Example 192.168.1.32
$PublicNetworkDNS2 = "DNS_IPv4_IP_Here" #DNS2 IP. Example 192.168.1.33
#Bridge Network details
$BridgeNetworkRange = "IP_Here/Subnet_here" #The IP range from which bridge networks are allocated (default: "172.16.0.0/12"). Example 10.12.0.0/16
#Resource Pool Configuration
$Memory = "0" #VCH resource pool memory limit in MB (unlimited=0) (default: <nil>)
$CPU = "0" #VCH resource pool vCPUs limit in MHz (unlimited=0) (default: <nil>)
#Standard Variables
$VICEngineBundleExtractedLocation = "C:\VIC\vic_v1.5.2.tar\vic_v1.5.2\vic" #This is where you extracted the VIC Engine Bundle EXEs to
$VCSA = "FQDN.VCSA.Here" #REQUIRED. ESXi or vCenter connection URL, specifying a datacenter if multiple exist e.g. root:password@VC-FQDN/datacenter (default: <nil>) [%VIC_MACHINE_TARGET%]. Example hamvc01.hamker.local
$User = "administrator@vsphere.local" #ESX or vCenter user [%VIC_MACHINE_USER%]
$UserPasswordTitle = 'Please Provide the Administrator@vsphere.local User Password'
$UserPasswordMsg
[void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
$UserPassword = [Microsoft.VisualBasic.Interaction]::InputBox($UserPasswordMsg, $UserPasswordTitle) #Note: This must be the administrator@vsphere.local account password
$ThumbPrint = $null #Note: this is queried from the OpenSSl Client below to get the thumbprint automatically from the Target URL
$OPSUSER = "UserAccount@vsphere.local" #The user with which the VCH operates after creation. Defaults to the credential supplied with target (default: <nil>). This is the user account that will interact with vCenter and the VCH. Example svc_vmdocker@vsphere.local
$OPSPASSWORD = "OPS_User_Password_Here" #Password or token for the operations user. Defaults to the credential supplied with target (default: <nil>)
#SysLog Address
$SYSLOGAddress = "udp://FQDN.Syslog.Server:514" #Address of the syslog server to send Virtual Container Host logs to. Must be in the format transport://host[:port], where transport is udp or tcp. port defaults to 514 if not specified. Example udp://loginsight.hamker.local:514
$ContainerNamingConvention = "$VCHNAME-{name}-$PROJECT"
#Proxy Settings (If needed)
$HTTPPROXY = "http://"+"FQDNofProxyHere:80" #Your HTTP Proxy Server Address
$HTTPSPROXY = "https://"+"FQDNofProxyHere:80" #Your HTTP Proxy Server Address
#VCH vCenter TAG
$VCHTAGNAME = "Virtual Container Host"#Used for vROPs Monitoring and simple vCenter grouping

##Logging Info
#Get Date Info for naming of snapshot variable
$LOGDATE = Get-Date -format "MMM-dd-yyyy_HH-mm"
#Specify Log File Info
$LOGFILENAME = "Log_" + $VCHNAME + "_" + $LOGDATE + ".txt"
#Create Log Folder
$LogFolder = $VCHCertLocation+"\Log"
If (Test-Path $LogFolder){
	Write-Host "Log Directory Created. Continuing..."
}Else{
	New-Item $LogFolder -type directory
}
#Specify Log File
$LOGFILE = $VCHCertLocation+"\Log\"+$LOGFILENAME

##Starting Logging
Start-Transcript -path $LOGFILE -Append


##Test if OpenSSL is Installed
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

##Verify that OpenSSL is installed
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
	DNS.1 = $VCHFQDN
	IP.1 = $VCHIP

	[ req_distinguished_name ]
	C=$COUNTRY
	ST=$STATE
	L=$CITY
	O=$COMPANY
	OU=$ORG
	CN=$VCHFQDN
	"

	#Open OpenSSL EXE Location
	CD $OpenSSLLocation
	
	#Make new VCH Cert Folder for storing all the Cert files
	IF(!$VCHCertLocationGet)
	{
		New-Item -Path $VCHCertLocation -ItemType "directory" -ErrorAction SilentlyContinue
	}else {
		Write-Host "VCH Folder already created at" $VCHCertLocation -ForegroundColor Green
	}
	
	#Make VCH Config file
	$CFGFILE = New-Item -Path $VCHCertLocation -Name "$VCHNAME.cfg" -ItemType "file" -Force
	#$CNF | Out-File -FilePath $CFGFILE
	
	#Write contents to Config file from $CNF Variable
	Set-Content -Path $CFGFILE -Value $CNF
	$CFGFILEFULLNAME = $cfgfile.fullname
	
	IF(!$SERVERKEYGET)
	{
		#Open OpenSSL EXE Location
		CD $OpenSSLLocation
		.\openssl genrsa -out $SERVERKEY 2048
	}else {
		Write-Host "Key.key already generated at" $SERVERKEY -ForegroundColor Green
	}

	IF(!$SERVERCSRGET)
	{
		#Open OpenSSL EXE Location
		CD $OpenSSLLocation
		.\openssl req -config $CFGFILEFULLNAME -new -key $SERVERKEY -out $SERVERCSR
	}else {
		Write-Host "Server.csr already generated at" $SERVERCSR -ForegroundColor Green
	}
	
	$CA = certutil â€“config $CERTIFICATESERVER -ping
	$CA = $CA[1]
	$CA = $CA.Replace("Server "," ")
	$CA = $CA.SubString(0, $CA.IndexOf('ICertRequest2'))
	$CA = $CA.Replace('"','')
	$CA = $CA.Replace(' ','')

	#To List the Certiicate Templates to get the right 1
	#certutil -template | Select-String -Pattern TemplatePropCommonName
	#Detailed Example certutil -template | Select-String -Pattern Vmware6.0WebServer
	
	#Generate CER
	IF(!$SERVERCERGET)
	{
		certreq -submit -attrib $CERTTEMPLATE -Kerberos -config $CERTIFICATESERVER\$CA $SERVERCSR $SERVERCER
	}else {
		Write-Host "Server.Cer already generated at" $SERVERCER -ForegroundColor Green
	}
	
	#Convert CER to PEM
	IF(!$SERVERPEMGET)
	{
		#Open OpenSSL EXE Location
		CD $OpenSSLLocation
		.\openssl x509 -in $SERVERCER -outform PEM -out $SERVERPEM
	}else {
		Write-Host "Server.pem already generated at" $SERVERPEM -ForegroundColor Green
	}
	
	#Copy CA Cert to Local Workstation
	#Place your CA Cert on a DC to make easily available to all users
	cp $CACERTLOCATION $VCHCertLocation -ErrorAction SilentlyContinue
	
	#Copy CA Cert to Local Workstation
	#Place your CA Cert on a DC to make easily available to all users
	cp $REGISTRYCALOCATION $VCHCertLocation -ErrorAction SilentlyContinue

	Write-Host "VCH Certificate Generation Process Completed" $SERVERCSR -ForegroundColor Green
}

##Create VCH
#Get VCSA SSL Certificate Thumbprint
#Reference https://askubuntu.com/questions/156620/how-to-verify-the-ssl-fingerprint-by-command-line-wget-curl
CD $OpenSSLLocation
$FULLPORT = $VCSA+":443"
Write-Warning "Attempting to get SSL Thumbprint of VCSA. This will take a moment."
$THUMB = .\openssl s_client -connect $FULLPORT |& .\openssl x509 -fingerprint -noout
$ThumbPrint = $THUMB.split('=')[-1]
#$ThumbPrint = "30:47:03:1b:51:17:99:2d:57:52:a5:c6:52:c5:ee:64:7d:0e:02:8d"
Write-Host "VCSA Thumbprint is"
Write-Host $ThumbPrint -ForegroundColor Green

#Change Directories to VIC-Machine-Windows.exe
cd $VICEngineBundleExtractedLocation

#remove any old VCH's with the same name prior to creating (clean up if necessary)
.\vic-machine-windows delete `
--target $VCSA/$DATACENTER --user $User --password $UserPassword --thumbprint $ThumbPrint `
--name $VCHNAME --compute-resource $CLUSTER `
--force

#Create new VCH with self signed certs (required to generate client certificates)
Write-Host "Generating new VCH "$VCHNAME
#.\vic-machine-windows create --x #Gets command details
Write-Host "
VCSA $VCSA
Datacenter $DATACENTER
User $User
Password YeahRight-ThisShouldNotBeIntheLogs
Thumbprint $ThumbPrint
VCHName $VCHNAME
VCHFQDN $VCHFQDN
ComputerResource $CLUSTER
ImageStore $ImageStore
BaseImageSize $BaseImageSize
VolumeStore1 $VolumeStore1
VolumeStore2 $VolumeStore2
BridgeNetwork $BridgeNetwork
BridgeNetworkRange $BridgeNetworkRange
PublicNetwork $PublicNetwork
PublicIP $PublicNetworkIP
PublicGateway $PublicNetworkGW
Memory $Memory
CPU $CPU
DNS1 $PublicNetworkDNS1
DNS2 $PublicNetworkDNS2
TLSServerKey $SERVERKEY
TLSServerCert $SERVERPEM
CACert $CACERT
SysLogServer $SYSLOGAddress
OpsUser $OPSUSER
ContainerNamingConvention $ContainerNamingConvention
RegistryCA Cert $REGISTRYCACERT
HTTP Proxy $HTTPPROXY
HTTPS Proxy $HTTPSPROXY
"
.\vic-machine-windows create --target $VCSA/$DATACENTER --user $User --password $UserPassword --thumbprint $ThumbPrint --name $VCHNAME `
--tls-cname $VCHFQDN --compute-resource $CLUSTER `
--image-store $ImageStore --base-image-size $BaseImageSize `
--volume-store $VolumeStore1 --volume-store $VolumeStore2 `
--bridge-network $BridgeNetwork --bridge-network-range $BridgeNetworkRange `
--public-network $PublicNetwork --public-network-ip $PublicNetworkIP --public-network-gateway $PublicNetworkGW `
--memory $Memory --cpu $CPU `
--dns-server $PublicNetworkDNS1 --dns-server $PublicNetworkDNS2 `
--tls-server-key $SERVERKEY --tls-server-cert $SERVERPEM --tls-ca $CACERT `
--syslog-address $SYSLOGAddress `
--ops-user $OPSUSER --ops-password $OPSPASSWORD --ops-grant-perms `
--container-name-convention $ContainerNamingConvention `
--registry-ca $REGISTRYCACERT `
--debug 1 `
#--http-proxy $HTTPPROXY --https-proxy $HTTPSPROXY
#comment out proxy line if you dont use it

#list
Write-Host "List VCH's"
.\vic-machine-windows.exe ls --target $VCSA/$DATACENTER --user $User --password $UserPassword --thumbprint $ThumbPrint

Import-Module VMware.PowerCLI
##Disconnect from any open vCenter Sessions,
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
$VISERVER = Connect-VIServer -server $VCSA -User $User -Password $UserPassword
$VISERVER
Write-Host "Connected to vCenter "
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
Write-Host "-----------------------------------------------------------------------------------------------------------------------"

##Add Tag to VCH ResourcePool
#Note this is used for vROPS Monitoring
Write-Host "-----------------------------------------------------------------------------------------------------------------------"
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
Write-Host "Adding Tag to VCH"$VCHNAME
#Getting VCH TAG
$VCHTAG = Get-Tag -Name $VCHTAGNAME
#Get VCH ResourcePool
$VCHRESOURCEPOOL = Get-ResourcePool $VCHNAME
#Tag VCH ResourcePool
$VCHRESOURCEPOOL | New-TagAssignment -Tag $VCHTAG
Write-Host "VCH Tag Completed for"$VCHNAME
Write-Host (Get-Date -format "MMM-dd-yyyy_HH-mm-ss")
Write-Host "-----------------------------------------------------------------------------------------------------------------------"

##Disconnect from any open vCenter Sessions,
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

#Stop Logging
Write-host "Stopping Logging"
Stop-Transcript

#Completed
Write-Host "VCH Creation Process Completed"
 