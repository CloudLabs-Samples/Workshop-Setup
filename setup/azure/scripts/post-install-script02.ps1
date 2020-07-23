. C:\LabFiles\AzureCreds.ps1

$userName = $AzureUserName
$password = $AzurePassword

$securePassword = $password | ConvertTo-SecureString -AsPlainText -Force
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $userName, $SecurePassword

Connect-AzAccount -Credential $cred | Out-Null

$resourceGroupName = (Get-AzResourceGroup | Where-Object { $_.ResourceGroupName -like "*Synapse-AIAD-*" }).ResourceGroupName
$deploymentId =  (Get-AzResourceGroup -Name $resourceGroupName).Tags["DeploymentId"]

# Template deployment
New-AzResourceGroupDeployment -ResourceGroupName $resourceGroupName `
  -TemplateUri "https://raw.githubusercontent.com/CloudLabs-Samples/Workshop-Setup/main/setup/azure/innertemplates/deploy-synapse-workspace.json" `
  -deploymentId $deploymentId

New-AzRoleAssignment -ResourceGroupName $resourceGroupName -ErrorAction Ignore -ObjectId "37548b2e-e5ab-4d2b-b0da-4d812f56c30e" -RoleDefinitionName "Owner"

sleep 20
Unregister-ScheduledTask -TaskName "Setup" -Confirm:$false

