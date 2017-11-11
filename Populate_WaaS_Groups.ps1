#Author: Simon Binder
#Blog: bindertech.se
#Twitter: @Bindertech
#Thanks to: @daltondhcp

<#Using Azure Automation
#Replace both the -Name values to suit your environment.

$Credential = Get-AutomationPSCredential -Name 'Global Admin'
$WindowsVersion = Get-AutomationVariable -Name 'WindowsVersion'
Connect-AzureAD -Credential $Credential
#>

#Run manually

Param(
  [Parameter(Mandatory=$True,HelpMessage='Enter Windows 10 release number, for example 1709',Position=1)]
   [string]$WindowsVersion
	
)

#Sets a bunch of variables. Assumes that you have run the Create_WaaS_Group.ps1 script first. 
#Else, change names according to your organizations standard.

$devices = Get-AzureADDevice -All:$True | Where-Object {$_.DeviceOSType -eq 'Windows'} | Select-Object -ExpandProperty ObjectID
$AppGroups = Get-AzureADGroup -SearchString 'App-' | Select-Object -ExpandProperty ObjectID
$SACTGroup = Get-AzureADGroup -SearchString "$WindowsVersion-SAC-T Compatibility" | Select-Object -ExpandProperty ObjectID
$SACBGroups = Get-AzureADGroup -SearchString "$WindowsVersion-SAC-B" | Select-Object -ExpandProperty ObjectID
$WaaSGroups = Get-AzureADGroup -SearchString "$WindowsVersion-SAC" | Select-Object -ExpandProperty ObjectID
$DeferralGroups = ((Get-AzureADGroup -SearchString "$WindowsVersion-Compatibility" | Select-Object -ExpandProperty ObjectID)), ((Get-AzureADGroup -SearchString "$WindowsVersion-Self-Service" | Select-Object -ExpandProperty ObjectID))

#Gets all devices in the groups used for Deferral

$DeferredDevices = foreach ($Deferralgroup in $Deferralgroups){

										Get-AzureADGroupMember -ObjectId $Deferralgroup | Where-Object {$_.ObjectType -eq 'Device'}
									 }
									
#Gets all devices already in any of the groups used for Windows Servicing									

$MemberDevices = foreach ($WaaSGroup in $WaaSGroups){

									Get-AzureADGroupMember -ObjectId $WaaSGroup | Where-Object {$_.ObjectType -eq 'Device'}

								 }

#Gets all devices already in the Compatibibility group
									
$ExistingSACTMembers = Get-AzureADGroupMember -ObjectId $SACTGroup | Where-Object {$_.ObjectType -eq 'Device'} | Select-Object -ExpandProperty ObjectID

#Populates the Semi Annual Channel Targeted Group buy looking for all groups used for application assignments. 
#Members are then choosen randomly.

$SACTMembers = @()
foreach ($AppGroup in $AppGroups) {

	$UserMembers = Get-AzureADGroupMember -ObjectId $AppGroup | Where-Object {$_.ObjectType -eq 'User'}
	$PossibleDevices = @()
	foreach ($UserMember in $UserMembers) {
	
		$ObjectID = $UserMember.ObjectId
		$WIndowsDevices = @(Get-AzureADUserOwnedDevice -ObjectId $ObjectID | Where-Object {$_.DeviceOSType -eq 'Windows'} | Select-Object -ExpandProperty ObjectID)
			
		foreach ($WindowsDevice in $WindowsDevices) {
		
			if ($WindowsDevice -notin $DeferredDevices.ObjectID){	
			
				$PossibleDevices += $WindowsDevice
			}
		}
		
	}
	
	$UserDevice = $PossibleDevices | Get-Random 
	$DeviceMember = Get-AzureADGroupMember -ObjectId $AppGroup | Where-Object {$_.ObjectType -eq 'Device'} | Where-Object {$_.DeviceOSType -eq 'Windows'} | Get-Random | Select-Object -ExpandProperty ObjectID
	$AllDevices = $UserDevice, $DeviceMember
	$SACTMembers += $AllDevices | Get-Random

}
	
foreach ($SACTMember in $SACTMembers) {

		if ($ExistingSACTMembers -match $SACTMember){

			("$SACTMember is already a member of the SAC-T group")

		}
		Else { 

			Add-AzureADGroupMember -ObjectId $SACTGroup -RefObjectId $SACTMember 

		}
}

#AssignedDevices gathers all devices already assigned to a Windows Servicing group, 
#to later be able to exclude them from other groups, or from being added a second time.

$AssignedDevices = $DeferredDevices.ObjectID, $MemberDevices.ObjectID

#Adds the remaining/new Windows devices to the different Semi Annual Channel Broadly groups at random.

foreach ($device in $devices) {

		if ($AssignedDevices -match $device){

			("$Device is already a member of a SAC-B or deferral Group")

		}

		Else { 

			Add-AzureADGroupMember -ObjectId ($SACBGroups | Get-Random) -RefObjectId $device

		}
}
