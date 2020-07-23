Param (
    [Parameter(Mandatory = $true)]
    [string]
    $AzureUserName,

    [string]
    $AzurePassword,

    [string]
    $AzureTenantID,

    [string]
    $AzureSubscriptionID,

    [string]
    $ODLID,
    
    [string]
    $DeploymentID
)

#Disable-InternetExplorerESC
Function Disable-InternetExplorerESC
    {
        $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
        $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
        Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force -ErrorAction SilentlyContinue -Verbose
        Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force -ErrorAction SilentlyContinue -Verbose
        #Stop-Process -Name Explorer -Force
        Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green -Verbose
    }

#Enable-InternetExplorerESC
Function Enable-IEFileDownload
    {
        $HKLM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
        $HKCU = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
        Set-ItemProperty -Path $HKLM -Name "1803" -Value 0 -ErrorAction SilentlyContinue -Verbose
        Set-ItemProperty -Path $HKCU -Name "1803" -Value 0 -ErrorAction SilentlyContinue -Verbose
        Set-ItemProperty -Path $HKLM -Name "1604" -Value 0 -ErrorAction SilentlyContinue -Verbose
        Set-ItemProperty -Path $HKCU -Name "1604" -Value 0 -ErrorAction SilentlyContinue -Verbose
    }

#Disable Server Manager NetworkPopup
Function DisableServerMgrNetworkPopup
    {
        cd HKLM:\
        New-Item -Path HKLM:\System\CurrentControlSet\Control\Network -Name NewNetworkWindowOff -Force 
	Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask -Verbose
    }

#Disable CreateLabFilesDirectory
Function CreateLabFilesDirectory
    {
        New-Item -ItemType directory -Path C:\LabFiles -force
    }

#Disable DisableWindowsFirewall
Function DisableWindowsFirewall
    {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

    }

#Install Edge-Chromium
Function InstallEdgeChromium
    {
        #Download and Install edge
        $WebClient = New-Object System.Net.WebClient
        $WebClient.DownloadFile("http://dl.delivery.mp.microsoft.com/filestreamingservice/files/6d88cf6b-a578-468f-9ef9-2fea92f7e733/MicrosoftEdgeEnterpriseX64.msi","C:\Packages\MicrosoftEdgeBetaEnterpriseX64.msi")
        sleep 5
        
	Start-Process msiexec.exe -Wait '/I C:\Packages\MicrosoftEdgeBetaEnterpriseX64.msi /qn' -Verbose 
        sleep 5
        $WshShell = New-Object -comObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut("C:\Users\Public\Desktop\Azure Portal.lnk")
        $Shortcut.TargetPath = """C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"""
        $argA = """https://portal.azure.com"""
        $Shortcut.Arguments = $argA 
        $Shortcut.Save()
    }

#Create Azure Credential File on Desktop
Function CreateCredFile($AzureUserName, $AzurePassword, $AzureTenantID, $AzureSubscriptionID, $DeploymentID)
    {
        $WebClient = New-Object System.Net.WebClient
        $WebClient.DownloadFile("https://raw.githubusercontent.com/CloudLabs-Samples/Workshop-Setup/main/setup/azure/scripts/AzureCreds.txt","C:\LabFiles\AzureCreds.txt")
        $WebClient.DownloadFile("https://raw.githubusercontent.com/CloudLabs-Samples/Workshop-Setup/main/setup/azure/scripts/AzureCreds.ps1","C:\LabFiles\AzureCreds.ps1")
        
        New-Item -ItemType directory -Path C:\LabFiles -force

        (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "AzureUserNameValue", "$AzureUserName"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"
        (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "AzurePasswordValue", "$AzurePassword"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"
        (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "AzureTenantIDValue", "$AzureTenantID"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"
        (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "AzureSubscriptionIDValue", "$AzureSubscriptionID"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"
        (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "DeploymentIDValue", "$DeploymentID"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"
                 
        (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "AzureUserNameValue", "$AzureUserName"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
        (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "AzurePasswordValue", "$AzurePassword"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
        (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "AzureTenantIDValue", "$AzureTenantID"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
        (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "AzureSubscriptionIDValue", "$AzureSubscriptionID"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
        (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "DeploymentIDValue", "$DeploymentID"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"

        Copy-Item "C:\LabFiles\AzureCreds.txt" -Destination "C:\Users\Public\Desktop"
    }

#Create InstallAzPowerShellModule
Function InstallAzPowerShellModule
    {
        Install-PackageProvider NuGet -Force
        Set-PSRepository PSGallery -InstallationPolicy Trusted
        Install-Module Az -Repository PSGallery -Force -AllowClobber
    }

#Create InstallPowerBIDesktop
Function InstallPowerBIDesktop
    {
        $WebClient = New-Object System.Net.WebClient
        $WebClient.DownloadFile("https://download.microsoft.com/download/8/8/0/880BCA75-79DD-466A-927D-1ABF1F5454B0/PBIDesktopSetup_x64.exe","C:\Packages\PBIDesktop_x64.exe")
        Start-Process -FilePath "C:\Packages\PBIDesktop_x64.exe" -ArgumentList '-quiet','ACCEPT_EULA=1'
    }

#Install Chocolatey
Function InstallChocolatey
    {   
        #[Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls
        #[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" 
        $env:chocolateyUseWindowsCompression = 'true'
        Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) -Verbose
        choco feature enable -n allowGlobalConfirmation
    }

Function Expand-ZIPFile($file, $destination)
    {
	$shell = new-object -com shell.application
	$zip = $shell.NameSpace($file)
	foreach($item in $zip.items())
           {
	       $shell.Namespace($destination).copyhere($item)
           }
    }

Start-Transcript -Path C:\WindowsAzure\Logs\CloudLabsCustomScriptExtension.txt -Append
[Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" 

# Run Functions
Disable-InternetExplorerESC
Enable-IEFileDownload
DisableServerMgrNetworkPopup
CreateLabFilesDirectory
DisableWindowsFirewall
InstallEdgeChromium
CreateCredFile $AzureUserName $AzurePassword $AzureTenantID $AzureSubscriptionID $DeploymentID $ODLID
InstallAzPowerShellModule
InstallPowerBIDesktop
InstallChocolatey
Expand-ZIPFile -File "C:\azure-synapse-analytics-day-master.zip" -Destination "C:\LabFiles\"

Add-Content -Path "C:\LabFiles\AzureCreds.txt" -Value "ODLID= $ODLID" -PassThru

choco install dotnetcore-sdk --force
sleep 10

$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile("https://raw.githubusercontent.com/CloudLabs-Samples/Workshop-Setup/main/setup/azure/scripts/post-install-script02.ps1","C:\LabFiles\post-install-script02.ps1")

sleep 20

$securePassword = $AzurePassword | ConvertTo-SecureString -AsPlainText -Force
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $AzureUserName, $SecurePassword

Connect-AzAccount -Credential $cred | Out-Null

# Template deployment
$resourceGroupName = (Get-AzResourceGroup | Where-Object { $_.ResourceGroupName -like "*Synapse-AIAD-*" }).ResourceGroupName
$deploymentId =  (Get-AzResourceGroup -Name $resourceGroupName).Tags["DeploymentId"]

New-AzResourceGroupDeployment -ResourceGroupName $resourceGroupName `
  -TemplateUri "https://raw.githubusercontent.com/CloudLabs-Samples/Workshop-Setup/main/setup/azure/innertemplates/deploy-synapse-workspace.json" `
  -deploymentId $deploymentId -AsJob
  
New-AzRoleAssignment -ResourceGroupName $resourceGroupName -ErrorAction Ignore -ObjectId "37548b2e-e5ab-4d2b-b0da-4d812f56c30e" -RoleDefinitionName "Owner"

sleep 20
Stop-Transcript
