# Script to clean up disabled users
# -Ricky Sosa

Import-Module ActiveDirectory

# ------------------------------------------------------------------------------------
# Various Variables (Tabbed lines are the ones you mostly want to set)
# ------------------------------------------------------------------------------------

# Output Color
    $Color = "Yellow"

# Current Date
$CurrentDate = Get-Date
$CurrentDate = $CurrentDate.ToString('MM-dd-yyyy')

# Set the number of days since last logon
    $DaysInactive = 90
$InactiveDate = (Get-Date).Adddays(-($DaysInactive))
  
# Exclude Group
    $FHsgExcludeDisableScript = Get-ADGroup "FHsgExcludeDisableScript" -Properties DistinguishedName, Members
    $ExclusionGroup = $FHsgExcludeDisableScript

# Search OU's
    $FHOUDN = "OU=Users,OU=MCC,DC=millcreek,DC=local"
    $MCCOUDN = "OU=UsersOU,OU=MCC,OU=SitesOU,DC=millcreek,DC=local"
    $OVOUDN = "OU=UsersOU,OU=OJV,OU=SitesOU,DC=millcreek,DC=local"
    $FHOVOUDN = "OU=Users,OU=OV,DC=millcreek,DC=local"
    $OUS = "$FHOUDN","$MCCOUDN","$OVOUDN","$FHOVOUDN"

# Exclude OU's
    $FHITOUDN = "OU=Information Systems,OU=Users,OU=MCC,DC=millcreek,DC=local"
    $ExcludeOU = $FHITOUDN

# CSV Output Files with date
    $InactiveUsersFile = "C:\ScriptOutput\InactiveUsers\InactiveUsers-$CurrentDate.csv"
    $DisabledUserGroupsFile = "C:\ScriptOutput\DisabledUserGroups\DisabledUserGroups-$CurrentDate.csv"

# Disabled Users Groups
    $MCCsgDisabledUsers = Get-ADGroup -Identity MCCsgDisabledUsers
    $OJVsgDisabledUsers = Get-ADGroup -Identity OJVsgDisabledUsers
    $MCCsgDisabledUsersID = (Get-ADGroup $MCCsgDisabledUsers).SID.Value.split('-')[-1]
    $OJVsgDisabledUsersID = (Get-ADGroup $OJVsgDisabledUsers).SID.Value.split('-')[-1]

# Disable Users OU's
    $MCCDisabledOU = Get-ADOrganizationalUnit -Identity "OU=DisabledOU,OU=MCC,OU=SitesOU,DC=millcreek,DC=local"
    $OJVDisabledOU = Get-ADOrganizationalUnit -Identity "OU=DisabledOU,OU=OJV,OU=SitesOU,DC=millcreek,DC=local"

# Email Variables
    $EmailTo = "ricky@systemgoit.com", "jonl@foresthome.org"
    $EmailSubject = "Disabled User List from $CurrentDate"
    $EmailSMTPServer = "smtp.office365.com"
    $EmailFrom = "itcloudadmin@foresthome.org"
    $EmailAttachments = "$InactiveUsersFile", "$DisabledUserGroupsFile"

# Credential Manager Module 
$CredManagerPath = "C:\Users\svc_adscripts\Documents\Credentials\CredentialManager.psm1"


# ---------------------------------------------
# Script starts here
# ---------------------------------------------


# This gets all enabled users that havent logged on in the last 90 days, from the OU's listed above, that arent service accounts
$InitialUsers = $OUS | Foreach { Get-ADUser -Filter { LastLogonDate -lt $InactiveDate -and Enabled -eq $true -and SamAccountName -notlike "*svc*" } -SearchBase $_ -Properties LastLogonDate, MemberOf, SamAccountName} | Where-Object {$_.distinguishedName -notlike "*,$ExcludeOU"} | Select-Object @{ Name="Username"; Expression={$_.SamAccountName} }, Name, LastLogonDate, DistinguishedName, SamAccountName, MemberOf

# Removes any users from the FHsgExcludeDisableScript group
$Users = @()
Foreach ($Person in $InitialUsers) {
$ExcludeGroups = $ExclusionGroup.Members
$ExcludeCheck = $false
$Person.MemberOf | ForEach-Object {if($_ -in $ExcludeGroups){$ExcludeCheck = $true}}
if ($ExcludeCheck -eq $false){$Users += $Person}
}

# Export results to CSV with date
$Users | Export-Csv -Path $InactiveUsersFile -Append -NoTypeInformation

# Disable Inactive Users
ForEach ($ADUser in $Users)
{ 
  $DistName = $ADUser.DistinguishedName
  Disable-ADAccount -Identity $DistName
  $DisabledStatus = Get-ADUser -Filter { DistinguishedName -eq $DistName } | Select-Object Name, Enabled
  if ( $DisabledStatus.Enabled -eq $false) { Write-Host $ADUser.Name "is now disabled" -ForegroundColor $Color }
  Elseif ( $DisabledStatus.Enabled -eq $true) { Write-Host $ADUser.Name "is not disabled" -ForegroundColor Red } 
}

"`n" # new line for spacing

# Get each users groups and writes them to a file
ForEach ($ADUser in $Users)
{
    $ADUserName = $ADUser.SamAccountName
    $UserGroups = $ADUserName | Get-ADPrincipalGroupMembership | Select-Object SamAccountName
    $UserGroupNames = $UserGroups.SamAccountName
    $UserAndGroups = @()
    $UserGroupNames | ForEach-Object {
    $UserAndGroups = [PSCustomObject]@{
                       User = $ADUserName;
                       Groups = (@($UserGroupNames) | Out-String).Trim()
                                       }
                                 }
    $UserAndGroups | Export-Csv -Path $DisabledUserGroupsFile -Append -NoTypeInformation
    
}

Write-Host "Exported Users and Groups to $DisabledUserGroupsFile" -ForegroundColor $Color

"`n" # new line for spacing

# Adds to appropriate DisabledUsers group and sets it as primary, also hides from the GAL
ForEach ($ADUser in $Users)
{
    Set-ADUser $ADUser.SamAccountName -Replace @{msExchHideFromAddressLists=$true}   

       If ($ADUser.DistinguishedName -like "*,$FHOUDN" -or $ADUser.DistinguishedName -like "*,$MCCOUDN")
        {
             Add-ADGroupMember -Identity $MCCsgDisabledUsers -Members $ADUser.SamAccountName
             Set-ADUser $ADUser.SamAccountName -Replace @{primaryGroupID=$MCCsgDisabledUsersID}
             Write-Host "Adding" $Aduser.Name "to" $MCCsgDisabledUsers.Name -ForegroundColor $Color
        }
       ElseIf ($ADUser.DistinguishedName -like "*,$OVOUDN" -or $ADUser.DistinguishedName -like "*,$FHOVOUDN")
        {
            Add-ADGroupMember -Identity $OJVsgDisabledUsers -Members $ADUser.SamAccountName
            Set-ADUser $ADUser.DistinguishedName -Replace @{primaryGroupID=$OJVsgDisabledUsersID}
            Write-Host "Adding" $Aduser.Name "to" $OJVsgDisabledUsers.Name -ForegroundColor $Color
        }
    
}

"`n" # new line for spacing

# Removes Users from all groups except appropriate DisabledUsers group
ForEach ($ADUser in $Users)
{
      $GroupName = Get-ADPrincipalGroupMembership -Identity $ADUser.SamAccountName | Where-Object { $_.SamAccountName -notlike "*DisabledUsers*" }
      $InGroup = Get-ADPrincipalGroupMembership -Identity $ADUser.SamAccountName | Where-Object { $_.SamAccountName -notlike "*DisabledUsers*" }
      Write-Host "Removing" $ADUser.Name "from groups" -ForegroundColor $Color 
        while ($InGroup -ne $null) {
                                     $InGroup | ForEach-Object { Remove-ADGroupMember -Identity $_ -Members $ADUser.SamAccountName -Confirm:$false }
                                     Write-Host "." -NoNewline -ForegroundColor Green
                                     $InGroup = Get-ADPrincipalGroupMembership -Identity $ADUser.SamAccountName | Where-Object { $_.SamAccountName -notlike "*DisabledUsers*" }
                                    }
"`n" # new line for spacing
      $GroupName | ForEach-Object { Write-Host "Removed" $ADUser.Name "from" $_.Name -ForegroundColor $Color  }
}

"`n" # new line for spacing

# Moves to appropriate Disabled OU
ForEach ($ADUser in $Users)
{
    If ($ADUser.DistinguishedName -like "*,$FHOUDN" -or $ADUser.DistinguishedName -like "*,$MCCOUDN")
        {
        Move-ADObject $ADUser.DistinguishedName -TargetPath $MCCDisabledOU
        Write-Host "Moving" $ADUser.Name ('to MCC\{0}' -f $OJVDisabledOU.Name) -ForegroundColor $Color
        }
    ElseIf ($ADUser.DistinguishedName -like "*,$OVOUDN" -or $ADUser.DistinguishedName -like "*,$FHOVOUDN")
        {
        Move-ADObject $ADUser.DistinguishedName -TargetPath $OJVDisabledOU
        Write-Host "Moving" $ADUser.Name ('to OJV\{0}' -f $OJVDisabledOU.Name) -ForegroundColor $Color
        }
}

# Send Email with log files to admins
$UsersNames = ($Users.Name -join "
")
Import-Module $CredManagerPath
$EmailITAdminCred = Get-StoredCredential ITAdmin
$EmailBody = "The following users have been inactive for 90+ days therefore their accounts have been disabled. Attached is the user list and their group memberships.`n`n$UsersNames"
Send-MailMessage -UseSsl -Credential $EmailITAdminCred -To $EmailTo -From $EmailFrom -SmtpServer $EmailSMTPServer -Attachments $EmailAttachments -Body $EmailBody -Subject $EmailSubject
