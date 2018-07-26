#Author: Simon Binder
#Blog: bindertech.se
#Twitter: @Bindertech
#Thanks to: @daltondhcp, @davefalkus, @NickolajA and the Intune product group.
#Most functions is copied from the Powershell Intune Samples: https://github.com/microsoftgraph/powershell-intune-samples
#Script requires the Azure AD Powershell module or the Azure AD Preview Powershell module to run

# Import required modules
try {
  Import-Module -Name AzureAD -ErrorAction Stop
  Import-Module -Name PSIntuneAuth -ErrorAction Stop
}
catch {
  Write-Warning -Message "Failed to import modules"
}

function Get-AuthToken {

  <#
      .SYNOPSIS
      This function is used to authenticate with the Graph API REST interface
      .DESCRIPTION
      The function authenticate with the Graph API Interface with the tenant name
      .EXAMPLE
      Get-AuthToken
      Authenticates you with the Graph API interface
      .NOTES
      NAME: Get-AuthToken
  #>

  [cmdletbinding()]

  param
  (
    [Parameter(Mandatory=$true)]
    $User
  )

  $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User

  $tenant = $userUpn.Host

  Write-Host "Checking for AzureAD module..."

  $AadModule = Get-Module -Name "AzureAD" -ListAvailable

  if ($AadModule -eq $null) {

    Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
    $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

  }

  if ($AadModule -eq $null) {
    write-host
    write-host "AzureAD Powershell module not installed..." -f Red
    write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
    write-host "Script can't continue..." -f Red
    write-host
    exit
  }

  # Getting path to ActiveDirectory Assemblies
  # If the module count is greater than 1 find the latest version

  if($AadModule.count -gt 1){

    $Latest_Version = ($AadModule | select version | Sort-Object)[-1]

    $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }

    # Checking if there are multiple versions of the same module found

    if($AadModule.count -gt 1){

      $aadModule = $AadModule | select -Unique

    }

    $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

  }

  else {

    $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

  }

  [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null

  [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

  $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"

  $redirectUri = "urn:ietf:wg:oauth:2.0:oob"

  $resourceAppIdURI = "https://graph.microsoft.com"

  $authority = "https://login.microsoftonline.com/$Tenant"

  try {

    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

    $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")

    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result

    # If the accesstoken is valid then create the authentication header

    if($authResult.AccessToken){

      # Creating header for Authorization token

      $authHeader = @{
        'Content-Type'='application/json'
        'Authorization'="Bearer " + $authResult.AccessToken
        'ExpiresOn'=$authResult.ExpiresOn
      }

      return $authHeader

    }

    else {

      Write-Host
      Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
      Write-Host
      break

    }

  }

  catch {

    write-host $_.Exception.Message -f Red
    write-host $_.Exception.ItemName -f Red
    write-host
    break

  }

}

####################################################

Function Get-AADDevice(){

  <#
      .SYNOPSIS
      This function is used to get an AAD Device from the Graph API REST interface
      .DESCRIPTION
      The function connects to the Graph API Interface and gets an AAD Device registered with AAD
      .EXAMPLE
      Get-AADDevice -DeviceID $DeviceID
      Returns an AAD Device from Azure AD
      .NOTES
      NAME: Get-AADDevice
  #>

  [cmdletbinding()]

  param
  (
    $DeviceID
  )

  # Defining Variables
  $graphApiVersion = "v1.0"
  $Resource = "devices"
    
  try {

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=deviceId eq '$DeviceID'"

    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value 

  }

  catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

  }

}

####################################################

Function Get-ManagedDevices(){

  <#
      .SYNOPSIS
      This function is used to get Intune Managed Devices from the Graph API REST interface
      .DESCRIPTION
      The function connects to the Graph API Interface and gets any Intune Managed Device
      .EXAMPLE
      Get-ManagedDevices
      Returns all managed devices but excludes EAS devices registered within the Intune Service
      .EXAMPLE
      Get-ManagedDevices -IncludeEAS
      Returns all managed devices including EAS devices registered within the Intune Service
      .NOTES
      NAME: Get-ManagedDevices
  #>

  [cmdletbinding()]

  param
  (
    [switch]$IncludeEAS,
    [switch]$ExcludeMDM
  )

  # Defining Variables
  $graphApiVersion = "beta"
  $Resource = "deviceManagement/managedDevices"

  try {

    $Count_Params = 0

    if($IncludeEAS.IsPresent){ $Count_Params++ }
    if($ExcludeMDM.IsPresent){ $Count_Params++ }
        
    if($Count_Params -gt 1){

      write-warning "Multiple parameters set, specify a single parameter -IncludeEAS, -ExcludeMDM or no parameter against the function"
      Write-Host
      break

    }
        
    elseif($IncludeEAS){

      $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"

    }

    elseif($ExcludeMDM){

      $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource`?`$filter=managementAgent eq 'eas'"

    }
        
    else {
    
      $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource`?`$filter=managementAgent eq 'mdm' and managementAgent eq 'easmdm'"
      Write-Warning "EAS Devices are excluded by default, please use -IncludeEAS if you want to include those devices"
      Write-Host

    }

    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
  }

  catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

  }

}

####################################################

Function Get-ManagedDeviceUser(){

  <#
      .SYNOPSIS
      This function is used to get a Managed Device username from the Graph API REST interface
      .DESCRIPTION
      The function connects to the Graph API Interface and gets a managed device users registered with Intune MDM
      .EXAMPLE
      Get-ManagedDeviceUser -DeviceID $DeviceID
      Returns a managed device user registered in Intune
      .NOTES
      NAME: Get-ManagedDeviceUser
  #>

  [cmdletbinding()]

  param
  (
    [Parameter(Mandatory=$true,HelpMessage="DeviceID (guid) for the device on must be specified:")]
    $DeviceID
  )

  # Defining Variables
  $graphApiVersion = "beta"
  $Resource = "deviceManagement/manageddevices('$DeviceID')?`$select=userId"

  try {

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Write-Verbose $uri
    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).userId

  }

  catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

  }

}

####################################################

# Read credentials and variables

$AADCredential = Get-AutomationPSCredential -Name "WaaSAccount"
$Credential = Get-AutomationPSCredential -Name "WaaSAccount"
$AppClientID = Get-AutomationVariable -Name "AppClientID"
$WindowsVersion = Get-AutomationVariable -Name "WindowsVersion"
$Tenantname = Get-AutomationVariable -Name "Tenantname"
$DefaultGroup = Get-AutomationVariable -Name "DefaultGroup"
$Groups = New-object Microsoft.Open.AzureAD.Model.GroupIdsForMembershipCheck


# Acquire authentication token
try {
    Write-Output -InputObject "Attempting to retrieve authentication token"
    $AuthToken = Get-MSIntuneAuthToken -TenantName $Tenantname -ClientID $AppClientID -Credential $Credential
    if ($AuthToken -ne $null) {
        Write-Output -InputObject "Successfully retrieved authentication token"
    }
}
catch [System.Exception] {
    Write-Warning -Message "Failed to retrieve authentication token"
}

Connect-AzureAD -Credential $AADCredential

#Sets variable for WaaS-groups, Device & User Members of the Self-Service group.

#Sets the Self-Service Group in Script.

$group = Get-AzureADGroup -SearchString "$WindowsVersion-Self-Service Deferred" | Select-Object -ExpandProperty ObjectID
$SearchGroups = Get-AzureADGroup -SearchString "$WindowsVersion-SAC"
$WaaSGroups = Get-AzureADGroup -SearchString "$WindowsVersion-SAC" | Select-Object -ExpandProperty ObjectID
$DeviceMembers = Get-AzureADGroupMember -ObjectId $group -All:$True | Where-Object {$_.ObjectType -eq 'Device'} 
$users = Get-AzureADGroupMember -ObjectId $group -All:$True | Where-Object {$_.ObjectType -eq 'User'}  | Get-AzureADUser | Select-Object -ExpandProperty UserPrincipalName 

#Gets all Windows-devices that have each user-member as owner. 
#If they already are members they will be skipt and if not the devices will be added to the group


foreach ($user in $users){
    
  $Groups.GroupIds = $WaaSGroups
  $GroupID = Select-AzureADGroupIdsUserIsMemberOf -ObjectId $user -GroupIdsForMembershipCheck $Groups

  if ($GroupID -ne $null) {
                           $TatooMember = Get-AzureADGroup | Where-Object ObjectID -eq $GroupID | Select-Object -First 1 -ExpandProperty DisplayName 
                           Set-AzureADUser -ObjectId $User -FacsimileTelephoneNumber $Tatoomember
        
        foreach ($UniqueGroupID in $GroupID) {
                                              $MemberRing = Get-AzureADGroup | Where-Object ObjectID -eq $UniqueGroupID | Select-Object -ExpandProperty ObjectID
                                              $MemberUser = Get-AzureADUser -Filter "userPrincipalName eq '$User'" | Select-Object -ExpandProperty ObjectID
                                              Remove-AzureADGroupMember -ObjectId $MemberRing -MemberId $MemberUser
        }

  }
  

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

$deferreddevices = $Users | ForEach-Object{

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

#Gets all devices in the group and compares to the deferred devices. If a device is member, but not have its user in the group, its removed. Also re-adds the user to any previous deployment- or pilot-ring.

foreach ($DeviceMember in $DeviceMembers){
  
        $MemberObjectID = ($Devicemember | Select-Object -ExpandProperty ObjectID ) 
  
  if ($MemberObjectID -notin $deferreddevices){
	
    Remove-AzureADGroupMember -ObjectId $group -MemberId $MemberObjectID
 
        
    #If you want to re-add previously deferred machines to a specific group enable the lines below
    
        $DeviceID = $DeviceMember | Select-Object -ExpandProperty DeviceID
        $IntuneDevice = Get-ManagedDevices -IncludeEAS | Where-Object -Property AzureADDeviceID -EQ $DeviceID  | Select-Object -First 1 -ExpandProperty id 
        $OwnerID = Get-ManagedDeviceUser -DeviceID $IntuneDevice
        $Owner = Get-AzureADUser -ObjectID $OwnerID
        $GroupName = $Owner | Select-Object -ExpandProperty FacsimileTelephoneNumber

        if ($GroupName -eq $null) {

                                    
                                    $IntuneOwner = Get-AzureADDeviceRegisteredOwner -ObjectId $MemberobjectID | Where-Object -Property UserPrincipalName -NE $Owner.UserPrincipalName
                                    $MultipleOwners = $IntuneOwner.FacsimileTelephoneNumber
                                                    

                                    if ($MultipleOwners -ne $null) {

                                                $RestoreGroup = Get-AzureADGroup -SearchString $MultipleOwners | Select-Object -ExpandProperty ObjectID
                                                $Groups.GroupIds = $RestoreGroup
                                                $CheckGroup = Select-AzureADGroupIdsUserIsMemberOf -ObjectId $IntuneOwner.UserPrincipalName -GroupIdsForMembershipCheck $Groups
        
                                                    if ($CheckGroup -eq $Null) {            
                                                                            Add-AzureADGroupMember -ObjectId $RestoreGroup -RefObjectId $IntuneOwner.ObjectId
                                                                            Add-AzureADGroupMember -ObjectId $RestoreGroup -RefObjectId $MemberObjectID 
                                                                               }
                                                    else {
                                                            Add-AzureADGroupMember -ObjectId $RestoreGroup -RefObjectId $MemberObjectID 
                                                          }
                                                          }
                                                                    
                                    else {


                                            if ($DefaultGroup -ne $Null) {
                                                "No previous membership detected, assigning device and owner to default group $DefaultGroup"
                                                 Add-AzureADGroupMember -ObjectId $DefaultGroup -RefObjectId $MemberobjectID
                                                 Add-AzureADGroupMember -ObjectId $RestoreGroup -RefObjectId $Owner
                                                 }
                                            else {
                                                'No default restore group assigned, device will be removed from deferral group'
                                                 }
                                                 }
                                    }
                                                
        else {

                                                $RestoreGroup = Get-AzureADGroup -SearchString $GroupName | Select-Object -ExpandProperty ObjectID
                                                $Groups.GroupIds = $RestoreGroup
                                                $CheckGroup = Select-AzureADGroupIdsUserIsMemberOf -ObjectId $Owner.UserPrincipalName -GroupIdsForMembershipCheck $Groups
        
                                                    if ($CheckGroup -eq $Null) {            
                                                                            Add-AzureADGroupMember -ObjectId $RestoreGroup -RefObjectId $Owner.ObjectId
                                                                            Add-AzureADGroupMember -ObjectId $RestoreGroup -RefObjectId $MemberObjectID 
                                                                                }

                                                                                else {
                                                            Add-AzureADGroupMember -ObjectId $RestoreGroup -RefObjectId $MemberObjectID 
                                                          }

        }

            
  }
        

}

