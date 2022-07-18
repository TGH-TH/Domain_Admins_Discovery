#### Domain Admins discovery script
#### Read Only - will make no changes just gather info
#### v0.1 TGH
#### Tier0 workstream


$results=@() # create empty array for the results to go in
$onlineDCs=@() # create empty array for the online Domain Controllers to go in
$now=Get-Date # set todays date as a varible - will be used to create the timespan for the 'days ago' attribute
#$DomainAdminMembers=(Get-ADGroup -Identity 'Domain Admins' -Properties members,samaccountname).members # get full DN of all Domain Admin member accounts
$DomainAdminMembers=(Get-ADGroup -Identity ((get-adgroup -filter * | ? {$_.SID -like '*-512'}).name) -Properties members,samaccountname).members # get full DN of all Domain Admin member accounts
$DomainControllers=Get-ADDomainController -filter * # get all domain controllers in the local AD domain
$ADdomain=Get-ADDomain # get local AD domain details

# writing script information to the screen
write-host -ForegroundColor Gray "Analysing Domain controllers in the " -NoNewline; write-host -ForegroundColor Green $ADdomain.dnsroot -NoNewline; Write-Host -ForegroundColor Gray " Active Directory domain"
Write-Host -ForegroundColor Green $DomainControllers.count -NoNewline; write-host -ForegroundColor Gray " Domain Controllers discovered"
Write-Host -ForegroundColor Gray "Checking for online domain controllers to collect the 'lastlogon' attribute as its not replicated"


<#
Handily (NOT) the lastlogon AD user attribute is not replicated across domain controllers thus
we have to scan each domain controller to retrieve its value and then find the latest
To do that we have to build a list of Domain Controllers and filter that list to online 
Domain Controllers only
#>

foreach($DomainController in $DomainControllers)
{
write-host -ForegroundColor Gray "Checking if " -NoNewline; Write-Host -ForegroundColor Green $DomainController.HostName -NoNewline; Write-Host -ForegroundColor Gray " is online - " -NoNewline
if(Test-Connection -ComputerName $DomainController.hostname -Quiet)
{
$onlineDCs += $DomainController
Write-Host -ForegroundColor Green "Success"
}else
{
Write-Host -ForegroundColor Red "Failure - this DC will not be checked for the 'lastlogon' Active Directory attribute"
}
}

<#
Now we have an array of online domain controllers and the list of users we are ready
to begin the main loop
#>


foreach($DomainAdminMember in $DomainAdminMembers)
{
$result=New-Object PSobject
$lastlogonArray=@()
$DomainAdminUser=Get-ADUser -Identity $DomainAdminMember -Properties samaccountname,PasswordExpired,Enabled # get AD user basic info

# add initial info to a custom PSObject

$result | Add-Member -MemberType NoteProperty -Name "samaccountname" -value $DomainAdminUser.samaccountname
$result | Add-Member -MemberType NoteProperty -Name "PasswordExpired" -value $DomainAdminUser.passwordexpired
$result | Add-Member -MemberType NoteProperty -Name "Enabled" -value $DomainAdminUser.Enabled

# begin the merry-go-round of checking all online DCs for the lastlogon attribute

foreach($DC in $onlineDCs)
{
# get the last logon attribute from every online DC and add it to an array
$lastlogonArray += [datetime]::FromFileTime((Get-ADUser -Server $DC.HostName $DomainAdminUser -Properties lastlogon).lastlogon)
}

$lastlogon=$lastlogonArray | Sort-Object -Descending | Select-Object -First 1 # select the most recent lastlong attribute from the above array

# add the lastlogon data to the custom PSobject as well as the contrived 'Days since logon' attribute for clarity

$result | Add-Member -MemberType NoteProperty -Name "lastlogon" -value $lastlogon
$result | Add-Member -MemberType NoteProperty -Name "Days since logon" -value (New-TimeSpan -Start $lastlogon -End $now).Days
$results=$results+$result # add the custom PSobject to the array that will form all the user data


}
$results | Out-GridView -Title "Domain Administrator details in the $($ADdomain.dnsroot) domain" # visually output data
if(!(test-path -Path $env:TEMP\TIER0)){New-Item -Path $env:TEMP\TIER0 -ItemType Directory}  # create a tmp folder for the csv export
$results | Export-Csv -Path $env:TEMP\TIER0\$($ADdomain.DNSRoot)_DomainAdmins_details.csv -NoTypeInformation # create the csv export
ii $env:TEMP\TIER0 # open the folder containing the CSV export for convenience
