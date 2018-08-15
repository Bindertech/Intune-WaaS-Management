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

Function Get-IntuneApplication(){

  <#
      .SYNOPSIS
      This function is used to get applications from the Graph API REST interface
      .DESCRIPTION
      The function connects to the Graph API Interface and gets any applications added
      .EXAMPLE
      Get-IntuneApplication
      Returns any applications configured in Intune
      .NOTES
      NAME: Get-IntuneApplication
  #>

  [cmdletbinding()]

  $graphApiVersion = "Beta"
  $Resource = "deviceAppManagement/mobileApps"
    
  try {
        
    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | ? { (!($_.'@odata.type').Contains("managed")) }

  }
    
  catch {

    $ex = $_.Exception
    Write-Host "Request to $Uri failed with HTTP Status $([int]$ex.Response.StatusCode) $($ex.Response.StatusDescription)" -f Red
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

Function Get-ApplicationAssignment(){

  <#
      .SYNOPSIS
      This function is used to get an application assignment from the Graph API REST interface
      .DESCRIPTION
      The function connects to the Graph API Interface and gets an application assignment
      .EXAMPLE
      Get-ApplicationAssignment
      Returns an Application Assignment configured in Intune
      .NOTES
      NAME: Get-ApplicationAssignment
  #>

  [cmdletbinding()]

  param
  (
    $ApplicationId
  )

  $graphApiVersion = "Beta"
  $Resource = "deviceAppManagement/mobileApps/$ApplicationId/?`$expand=categories,assignments"
    
  try {
        
    if(!$ApplicationId){

      write-host "No Application Id specified, specify a valid Application Id" -f Red
      break

    }

    else {
        
      $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
      (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)
        
    }
    
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

Function Remove-EmptyApplicationAssignments(){

<#
.SYNOPSIS
This function is used to remove orphan Azure AD group application assignments using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface loops through all apps and removes any assignments where the Azure AD Group has been deleted
.EXAMPLE
Remove-EmptyApplicationAssignments
Loops through all apps with assignments, keeping the valid once (including exclusions) and removes orphaned assignments
.NOTES
NAME: Remove-EmptyApplicationAssignments
ERRORMESSAGE: If orphaned group assignments (orphaned = the Azure AD group has been deleted from Azure AD) this function will thrown an errormessage from Get-AADGroup. This is expected but the function will continue and remove the orphaned group

#>

[cmdletbinding()]

$graphApiVersion = "Beta"

  try {

      $AllApps = (Get-IntuneApplication).id

      foreach ($ApplicationId in $AllApps) {

      $AssignedGroups = (Get-ApplicationAssignment -ApplicationId $ApplicationId).assignments

      if($AssignedGroups){

      $App_Count = @($AssignedGroups).count
      $i = 1

# Creating header of JSON File
$JSON = @"

{
    "mobileAppAssignments": [

"@

# Looping through all existing assignments and adding them to the JSON object
foreach($Assignment in $AssignedGroups){

$ExistingTargetGroupId = $Assignment.target.GroupId
$ExistingInstallIntent = $Assignment.intent


# Finding out if the assignment is targeted to All User or All Devices and adding it to JSON object
    
      if(!$ExistingTargetGroupId){

            if ($Assignment.target.'@odata.type' -match '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                                    
$JSON += @"
    
    {
      "@odata.type": "#microsoft.graph.mobileAppAssignment",
      "target": {
        "@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget"
      },
      "intent": "$ExistingInstallIntent"
"@
                                    
            }
                                                                                                                                                                       

            elseif ($Assignment.target.'@odata.type' -match '#microsoft.graph.allDevicesAssignmentTarget') { 
                                    
                                    
$JSON += @"
    
    {
      "@odata.type": "#microsoft.graph.mobileAppAssignment",
      "target": {
        "@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"
      },
      "intent": "$ExistingInstallIntent"
"@
                                    
                                    
            }

      }

# Testing the Azure AD group object ID to see if the group exist in Azure AD. If not, the foreach loop will exit without adding the assignment to JSON. Note, this will throw an error message created from Get-AADGroup, but will continue

      else{
    
      try {
    
          Get-AADGroup -id $ExistingTargetGroupId -ErrorAction SilentlyContinue  | Out-Null
    
          }
    
      catch {

             'This group does not exist in Azure AD'
      }

# Finding out if the assignment is an exclusion of an Azure AD Group and adding the assignment to JSON

      if($Assignment.target.'@odata.type' -match '#microsoft.graph.exclusionGroupAssignmentTarget'){

$JSON += @"
    
    {
      "@odata.type": "#microsoft.graph.mobileAppAssignment",
      "target": {
        "@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget",
        "groupId": "$ExistingTargetGroupId"
      },
      "intent": "$ExistingInstallIntent"
"@

      }

# Adding the group assignment to JSON

      else{

$JSON += @"
    
    {
      "@odata.type": "#microsoft.graph.mobileAppAssignment",
      "target": {
        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
        "groupId": "$ExistingTargetGroupId"
      },
      "intent": "$ExistingInstallIntent"
"@

      }

      }
            
      if($i -ne $App_Count){

$JSON += @"

    },

"@

      }

      else {

$JSON += @"

    }

"@

      }



$i++

}

# Adding close of JSON object
$JSON += @"

    ]
}

"@
        
$Resource = "deviceAppManagement/mobileApps/$ApplicationId/assign"
$uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

      }

      }

  }

# This will throw an error message if try fails - but not if the message is $null
    
  catch {

  $ex = $_.Exception
  if($ex) {
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

}


####################################################

Function Get-AADGroup(){

  <#
      .SYNOPSIS
      This function is used to get AAD Groups from the Graph API REST interface
      .DESCRIPTION
      The function connects to the Graph API Interface and gets any Groups registered with AAD
      .EXAMPLE
      Get-AADGroup
      Returns all users registered with Azure AD
      .NOTES
      NAME: Get-AADGroup
  #>

  [cmdletbinding()]

  param
  (
    $GroupName,
    $id,
    [switch]$Members
  )

  # Defining Variables
  $graphApiVersion = "v1.0"
  $Group_resource = "groups"
    
  try {

    if($id){

      $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=id eq '$id'"
      (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

    }
        
    elseif($GroupName -eq "" -or $GroupName -eq $null){
        
      $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)"
      (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
        
    }

    else {
            
      if(!$Members){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=displayname eq '$GroupName'"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
            
      }
            
      elseif($Members){
            
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=displayname eq '$GroupName'"
        $Group = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
            
        if($Group){

          $GID = $Group.id

          $Group.displayName
          write-host

          $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)/$GID/Members"
          (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

        }

      }
        
    }

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
$TargetOSVersion = Get-AutomationVariable -name "TargetOSVersion"
#Replace with Automation Variables before production
$TechPilot = '758ba924-7961-4453-a3bf-da6040cea6d3'
$ApplicationPilot = '3141ba35-8f3d-41df-bd5c-4633c971af65'
$DeploymentRings = '836c8ef0-a604-4d5d-8d9b-ca92fedcd573','8f7b9464-4293-4929-92cd-a7cb28eeb8c3'
#Required for now, its the Windows 10 buildnumber without dots
$TargetOSVersion = 10017134165


# Acquire authentication token
try {
  Write-Output -InputObject "Attempting to retrieve authentication token"
  $AuthToken = Get-MSIntuneAuthToken -TenantName $Tenantname -ClientID $AppClientID -Credential $Credential
  if ($AuthToken -ne $null) {
    Write-Output -InputObject "Successfully retrieved authentication token"
  }
}
catch  {
  Write-Warning -Message "Failed to retrieve authentication token"
}

Connect-AzureAD -Credential $AADCredential

#Getting all Windows Devices from Intune, removing already upgraded machines.

$AllWindowsDevices = Get-ManagedDevices | Where-Object -Property 'OperatingSystem' -EQ 'Windows'
$AllOldWindowsDevices = New-Object 'System.Collections.Generic.List[System.Object]'
foreach ($WindowsDevice in $AllWindowsDevices) { 

  $NewVersion = $WindowsDevice | Select-Object -ExpandProperty osVersion
  $Newversion = $NewVersion -replace '\.',''
  $WindowsDevice.osVersion="$NewVersion"
    
  if ($WindowsDevice.osVersion -lt $TargetOSVersion) {
    
    $AllOldWindowsDevices.Add($WindowsDevice)

  }

}

#Populating the application pilot group.

#Getting all unique models, selecting machines at random. Finding the Intune-device owner and adding it and all of its devices to the Application Pilot group.

$AllModels = $AlloldWindowsDevices | Sort-Object -Property model -Unique | Select-Object Devicename, model, id, osVersion

foreach ($Model in $AllModels) {
          
  $OwnerID = Get-ManagedDeviceUser -DeviceID $Model.id
  $Owner = Get-AzureADUser -ObjectID $OwnerID
  #Ensure to add device and user to group
  try {
    Add-AzureADGroupMember -ObjectId $ApplicationPilot -RefObjectId $Owner.ObjectId 
  }
  catch {$DisplayName = $Owner.DisplayName
  
  "$Displayname is already a member of this group"} 
  
  $MemberDevices = Get-AzureADUserOwnedDevice -ObjectId $OwnerID | Where-Object {$_.DeviceOSType -eq 'Windows'} | Select-Object -ExpandProperty ObjectID

  foreach ($MemberDevice in $MemberDevices) {

    try {
      Add-AzureADGroupMember -ObjectId $Groups -RefObjectId $MemberDevice
    }

    catch {
      "$MemberDevice is already a member of $Groups"

    }     

  }

}


#Cleaning up all orphaned assignments prior to getting application groups.

Remove-EmptyApplicationAssignments

#Getting all Windows apps, LOB and O365 deployments, selecting machines at random. Finding the Intune-device owner and adding it and all of its devices to the Application Pilot group.

$Groups = $ApplicationPilot
$AllApps = Get-IntuneApplication
$AllWindowsApps = New-Object 'System.Collections.Generic.List[System.Object]'
foreach ($App in $AllApps) {

  $StoreApp = $App | Where-Object -Property '@odata.type' -Match '#microsoft.graph.microsoftStoreForBusinessApp'

  if ($StoreApp -ne $null) {

    $AllWindowsApps.Add($StoreApp)

  }

  $MSI = $App | Where-Object -Property '@odata.type' -Match '#microsoft.graph.windowsMobileMSI'

  if ($MSI -ne $null) {

    $AllWindowsApps.Add($MSI)

  }


  $Office = $App | Where-Object -Property '@odata.type' -Match '#microsoft.graph.officeSuiteApp'

  if ($Office -ne $null) {

    $AllWindowsApps.Add($Office)

  }

  $Appx = $App | Where-Object -Property '@odata.type' -Match '#microsoft.graph.officeSuiteApp'

  if ($Appx -ne $null) {

    $AllWindowsApps.Add($Appx)

  }

}

foreach ($WindowsApp in $AllWindowsApps) {

  $Group = Get-ApplicationAssignment -ApplicationId $WindowsApp.id | Select-Object -ExpandProperty 'assignments' | Select-Object -ExpandProperty 'target'

  if ($Group.'@odata.type' -eq $null) {"$Group This is not assigned to any group"}

  elseif ($Group.'@odata.type' -match '#microsoft.graph.allLicensedUsersAssignmentTarget') {'This is assigned to all Users'}

  elseif ($Group.'@odata.type' -match '#microsoft.graph.allDevicesAssignmentTarget') {'This is assigned to all Devices'}

  elseif ($Group.'@odata.type' -match '#microsoft.graph.groupAssignmentTarget') {
    
    try {
        $AppGroupMembers = Get-AzureADGroupMember -ObjectId $group.groupId -All:$True | Group-Object 'ObjectType' -AsHashTable -AsString
    }
    Catch {"The group with ID $Group.groupid does no longer exist"}

    if ($AppGroupMembers.user -ne $null) {
  
      $AppGroupUserMembers = $AppGroupMembers                                          
      $CurrentMembers = Get-AzureADGroupMember -ObjectId $Groups -All:$True | Group-Object 'ObjectType' -AsHashTable -AsString
                                            
                                            if ($CurrentMembers -ne $null) {

                                              $Compared = Compare-Object -ReferenceObject $AppGroupUserMembers.user.objectid -DifferenceObject $CurrentMembers.user.objectid -IncludeEqual | Where-Object -Property 'SideIndicator' -Match '==' | Select-Object -ExpandProperty 'InputObject'
                                              
                                              foreach ($Object in $Compared) {

                                                                              if ($AppGroupUserMembers.user.objectid -contains $Object) {$AppGroupUserMembers = $AppGroupUserMembers.User.ObjectID -ne $Compared
                                                                                                                                     

                                                                              }

                                                                                $RandomMembers = $AppGroupUserMembers | Random -Count 2

                                                                                foreach ($Member in $RandomMembers) {

                                                                                $MemberDevices = Get-AzureADUserOwnedDevice -ObjectId $Member | Where-Object {$_.DeviceOSType -eq 'Windows'} | Select-Object -ExpandProperty ObjectID

                                                                                foreach ($MemberDevice in $MemberDevices) {

                                                                                try {

                                                                                  Add-AzureADGroupMember -ObjectId $Groups -RefObjectId $MemberDevice

                                                                                  }

                                                                                catch {

                                                                                "$MemberDevice is already a member of $Groups"

                                                                                }


                                                                                }

                                                                                try {

                                                                                Add-AzureADGroupMember -ObjectId $Groups -RefObjectId $Member

                                                                                }

                                                                                catch {

                                                                                "$MemberDevice is already a member of $Groups"

                                                                                }

                                                                              }
                                                                            }
                                                                          }

                                                                        }


    if ($AppGroupMembers.Device -ne $null) {
  
      $AppGroupDeviceMembers = $AppGroupMembers                                          
      $CurrentMembers = Get-AzureADGroupMember -ObjectId $Groups -All:$True | Group-Object 'ObjectType' -AsHashTable -AsString
                                            
                                            if ($CurrentMembers -ne $null) {

                                              $Compared = Compare-Object -ReferenceObject $AppGroupDeviceMembers.Device.objectid -DifferenceObject $CurrentMembers.Device.objectid -IncludeEqual | Where-Object -Property 'SideIndicator' -Match '==' | Select-Object -ExpandProperty 'InputObject'
                                              
                                              foreach ($Object in $Compared) {

                                                                              if ($AppGroupDeviceMembers.user.objectid -contains $Object) {$AppGroupDeviceMembers = $AppGroupDeviceMembers.User.ObjectID -ne $Compared
                                                                                                                                     

                                                                              }


                                                                                $RandomMembers = $AppGroupDeviceMembers | Random -Count 2

                                                                                foreach ($Member in $RandomMembers) {

                                                                                $MemberUsers = Get-ManagedDeviceUser -DeviceID $AppGroupDeviceMembers.Device.DeviceID
                                                                                #May need to add code to handle multiple owners

                                                                                foreach ($MemberUser in $MemberUsers) {
                                                                                
                                                                                  try {

                                                                                    Add-AzureADGroupMember -ObjectId $Groups -RefObjectId $MemberUser
                                                                                  }
                                                                                  
                                                                                  catch {

                                                                                    "$MemberUser is already a member of $Groups"

                                                                                  }

                                                                                }

                                                                                try {

                                                                                Add-AzureADGroupMember -ObjectId $Groups -RefObjectId $Member

                                                                                }

                                                                                catch {

                                                                                "$Member is already a member of $Groups"

                                                                                }

                                                                              }
                                                                            }
                                                                          }

                                                                        }

                                                                      }

}