#Author: Simon Binder
#Blog: bindertech.se
#Twitter: @Bindertech
#Thanks to: @daltondhcp

#This script is supposed to run prior to the start of each now Windows 10 servicing upgrade. Remember to change the versionname.

#Using Azure Automation
#Replace the -Name parameter with your Automation Account

#$Credential = Get-AutomationPSCredential -Name 'Global Admin'

Param(
  [Parameter(Mandatory=$True,HelpMessage='Enter Windows 10 release number, for example 1709',Position=1)]
   [string]$WindowsVersion
	
)

Connect-AzureAD

#Enter the Windows 10 version you want to deploy in $WindowsVersion. Change the names (or add additional rings) as you like, but remember to change any other corresponding scripts.

$WaaSGroups = "$WindowsVersion-SAC-T - Technical", "$WindowsVersion-SAC-T Compatibility", "$WindowsVersion-SAC-B - First Ring", "$WindowsVersion-SAC-B - Second Ring", "$WindowsVersion-Compatibility Issues", "$WindowsVersion-Self-Service Deferred"  

foreach ($WaaSGroup in $WaaSGroups){

	New-AzureADGroup -Description "$WaaSGroup" -DisplayName "$WaaSGroup" -SecurityEnabled $true -MailEnabled $false -MailNickName 'NotSet'

}