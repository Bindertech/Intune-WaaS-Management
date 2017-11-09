#Author: Simon Binder
#Blog: bindertech.se
#Twitter: @Bindertech
#Thanks to: @daltondhcp

#Using Azure Automation
#Replace the -Name parameter with your Automation Account

#$Credential = Get-AutomationPSCredential -Name 'Global Admin'

Param(
  [Parameter(Mandatory=$True,HelpMessage='Enter Windows 10 release number, for example 1709',Position=1)]
   [string]$WindowsVersion
	
)

Connect-AzureAD

#Sets variable for WaaS-groups, Device & User Members of the Self-Service group.

#Sets the Self-Service Group in Script. Remove # from the rows below to enable prompting for group name (Not recommended)

$group = Get-AzureADGroup -SearchString "$WindowsVersion-Self-Service Deferred" | Select-Object -ExpandProperty ObjectID
#$groupname = Read-Host -Prompt 'Input group name'
#$group = Get-AzureADGroup -SearchString $groupname | Select-Object -ExpandProperty ObjectID


$WaaSGroups = Get-AzureADGroup -SearchString "$WindowsVersion-SAC" | Select-Object -ExpandProperty ObjectID
$DeviceMembers = Get-AzureADGroupMember -ObjectId $group -All:$True | Where-Object {$_.ObjectType -eq 'Device'} 
$users = Get-AzureADGroupMember -ObjectId $group -All:$True | Where-Object {$_.ObjectType -eq 'User'}  | Get-AzureADUser | Select-Object -ExpandProperty UserPrincipalName 

#Gets all Windows-devices that have each user-member as owner. 
#If they already are members they will be skipt and if not the devices will be added to the group


foreach ($user in $users){

	$devices = Get-AzureADUserOwnedDevice -ObjectId $user | Where-Object {$_.DeviceOSType -eq 'Windows'} | Select-Object -ExpandProperty ObjectID
	foreach ($device in $devices){  

		if ($DeviceMembers -match $device){
		
			('{0} is already a member of the group' -f $Device)
		
		}
			
		Else{ 
		
			Add-AzureADGroupMember -ObjectId $group -RefObjectId $device 
		
		}
    
	} 
  
}


#Gets all deferred devices from users in the group and check if they are members of any other WaaS-group. If so, they are removed.

$deferreddevices= $Users | ForEach-Object{

													 Get-AzureADUserOwnedDevice -ObjectId $user | Where-Object {$_.DeviceOSType -eq 'Windows'} | Select-Object -ExpandProperty ObjectID
						
													}


foreach ($deferreddevice in $deferreddevices){

	foreach ($WaaSGroup in $WaaSGroups){
  
		$WaaSMember = Get-AzureADGroupMember -ObjectId $WaaSgroup -All:$True | Where-Object {$_.ObjectType -eq 'Device'} | Select-Object -ExpandProperty ObjectID
  
		if ($deferreddevice -in $WaaSMember){
			
			Remove-AzureADGroupMember -ObjectId $WaaSGroup -MemberId $deferreddevice
		}
  
	}
}

#Gets all devices in the group and compares to the deferred devices. If a device is member, but not have its user in the group, its removed.

foreach ($DeviceMember in $DeviceMembers){
  
	$MemberObjectID = ($Devicemember | Select-Object -ExpandProperty ObjectID ) 
  
	if ($MemberObjectID -notin $deferreddevices){
	
		Remove-AzureADGroupMember -ObjectId $group -MemberId $MemberObjectID 
		#If you want to re-add previously deferred machines to a specific group enable the lines below
		#Add-AzureADGroupMember -ObjectId $RestoreGroup
	}

}