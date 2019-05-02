##Test if OpenSSL is Installed
$OPENSSL = get-item "C:\Program Files\OpenSSL-Win64\bin\OpenSSL.exe" -ErrorAction SilentlyContinue ##x64 is only supported version 
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
}

##Test if Docker for Windows is installed
$DOCKEREXE = Get-Item "C:\Program Files\Docker\Docker\Docker for Windows.exe" -ErrorAction SilentlyContinue
IF(!$DOCKEREXE)
{
	Write-Warning "Docker for Windows is not installed"
	Write-Warning "Docker for Windows is required to test Docker API connectivity"
	Write-Warning "Please download and install Docker for Windows"
	Write-Warning "Note: Docker for Windows only supports x64 based Windows Operating Systems"
	Write-Warning "https://hub.docker.com/editions/community/docker-ce-desktop-windows"
	write-host "Press any key to continue..."
	[void][System.Console]::ReadKey($true)
	#EXIT
}

##Verify that Docker and OpenSSL are installed
IF($OPENSSL -And $DOCKEREXE)
{
	#Standard Variables
	$Computer = ($env:computername).tolower()
	$Computername = "$env:computername.$env:userdnsdomain"
	$Computername = $Computername.tolower()
	$DockerCertLocationGet = Get-Item "C:\Certs\DockerCert" -ErrorAction SilentlyContinue
	$DockerCertLocation = "C:\Certs\DockerCert"
	$SERVERKEYGET = Get-Item "$DockerCertLocation\$Computer.key" -ErrorAction SilentlyContinue
	$SERVERKEY = "$DockerCertLocation\$Computer.key"
	$SERVERCSRGET = Get-Item "$DockerCertLocation\$Computer.csr" -ErrorAction SilentlyContinue
	$SERVERCSR = "$DockerCertLocation\$Computer.csr"
	$SERVERCERGET = Get-Item "$DockerCertLocation\$Computer.cer" -ErrorAction SilentlyContinue
	$SERVERCER = "$DockerCertLocation\$Computer.cer"
	$DOCKERFOLDER = "$env:USERPROFILE\.docker\machine\certs"

	#Customizable Variables
	$CATEMPLATE = "CertificateTemplate:VmwareWebServer"
	$CAFILELOCATION = "C:\Certs\CAs\Combined\CombinedCA_HAMCA01-CA-PEM.pem"
	$CACERT = "$DockerCertLocation\CA.pem"
	$VCH = "buildvch01.speedycash.ict:2376" #This is the test VCH you are testing against
	$CERTIFICATESERVER = "hamca01.hamker.local"
	$OpenSSLLocation = "C:\Program Files\OpenSSL-Win64\bin" #x64 Version
	#$OpenSSLLocation = "C:\Program Files (x86)\OpenSSL-Win32\bin" #x86 Version
	

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
	DNS.1 = $computername

	[ req_distinguished_name ]
	C=US
	ST=Kansas
	L=Wichita
	O=Hamker Tech
	OU=IT
	CN=$computername"

	#Open OpenSSL EXE Location
	CD $OpenSSLLocation
	
	#Make new Docker Cert Folder for storing all the Cert files
	IF(!$DockerCertLocationGet)
	{
		New-Item -Path $DockerCertLocation -ItemType "directory" -ErrorAction SilentlyContinue
	}else {
		Write-Host "Docker Folder already created at" $DockerCertLocation -ForegroundColor Green
	}
	
	#Make Computer Config file
	$CFGFILE = New-Item -Path $DockerCertLocation -Name "$Computer.cfg" -ItemType "file" -Force
	#$CNF | Out-File -FilePath $CFGFILE
	
	#Write contents to Config file from $CNF Variable
	Set-Content -Path $CFGFILE -Value $CNF
	$CFGFILEFULLNAME = $cfgfile.fullname
	
	IF(!$SERVERKEYGET)
	{
		.\openssl genrsa -out $SERVERKEY 2048
	}else {
		Write-Host "Key.key already generated at" $SERVERKEY -ForegroundColor Green
	}

	IF(!$SERVERCSRGET)
	{
		.\openssl req -config $CFGFILEFULLNAME -new -key $SERVERKEY -out $SERVERCSR
	}else {
		Write-Host "Server.csr already generated at" $SERVERCSR -ForegroundColor Green
	}
	
	$CA = certutil –config $CERTIFICATESERVER -ping
	$CA = $CA[1]
	$CA = $CA.Replace("Server "," ")
	$CA = $CA.SubString(0, $CA.IndexOf('ICertRequest2'))
	$CA = $CA.Replace('"','')
	$CA = $CA.Replace(' ','')

	#To List the Certifcate Templates to get the right 1
	#certutil -template | Select-String -Pattern TemplatePropCommonName
	
	#Generate CER
	IF(!$SERVERCERGET)
	{
		certreq -submit -attrib $CATEMPLATE -Kerberos -config $CERTIFICATESERVER\$CA $SERVERCSR $SERVERCER
	}else {
		Write-Host "Server.Cer already generated at" $SERVERCER -ForegroundColor Green
	}
	
	#Copy CA Cert to Local Workstation
	#Place your CA Cert on a DC to make easily available to all users
	Copy-Item $CAFILELOCATION -Destination $DockerCertLocation -ErrorAction SilentlyContinue
	Get-ChildItem $DockerCertLocation | Where {$_.name -like "CombinedCA*"}| Rename-Item -NewName $CACERT
	#cp $CAFILELOCATION $DockerCertLocation -ErrorAction SilentlyContinue

	#Test Connectivity To vCH using Docker.exe
	Write-Host "Testing Docker API connectivity to vCH"$VCH -ForegroundColor Green
	docker -H $VCH --tlscacert=$CACERT --tlscert=$SERVERCER --tlskey=$SERVERKEY --tlsverify info
}

#Reference : https://dille.name/blog/2016/11/08/using-a-microsoft-ca-to-secure-docker/

<#

##Use below for running commands against Docker Moving Forward
#Standard Variables
$Computer = ($env:computername).tolower()
$DockerCertLocation = "C:\Certs\DockerCert"
$SERVERKEY = "$DockerCertLocation\$Computer.key"
$SERVERCER = "$DockerCertLocation\$Computer.cer"
#Customizable Variables
$CACERT = "$DockerCertLocation\ICTCERT-fullchain.pem"
$VCH = "buildvch01.speedycash.ict:2376" #This is the test VCH you are testing against
$REGISTRY = "ictvica01.speedycash.ict"
#Test VCH Connectivity via Info
docker -H $VCH --tlscacert=$CACERT --tlscert=$SERVERCER --tlskey=$SERVERKEY --tlsverify info
#Test Registy Connectivity
docker login $REGISTRY

#>