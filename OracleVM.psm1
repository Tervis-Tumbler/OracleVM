Function Install-OracleVMPowershell{
    Set-OracleVMCredentialID
}

Function Set-OracleVMCredentialIDPath {
    Param (
        [Parameter(Mandatory)]$OracleVMCredentialIDPath
    )
    [Environment]::SetEnvironmentVariable( "OracleVMCredentialIDPath", $OracleVMCredentialIDPath, "User" )
}

Function Get-OracleVMCredentialIDPath {
    if ($env:OracleVMCredentialIDPath) {
        $env:OracleVMCredentialIDPath
    } else {
        Throw "Set-OracleVMCredentialID has not been run yet or PowerShell needs to be closed and reopened to see that the `$env:OracleVMCredentialIDPath has a value"
    }
}

Function Set-OracleVMCredentialID {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]$OracleVMCredentialID
    )    
    New-SecureStringFile -OutputFile $env:USERPROFILE\OracleVMCredentialID -SecureString $($OracleVMCredentialID | ConvertTo-SecureString -AsPlainText -Force)
    Set-OracleVMCredentialIDPath -OracleVMCredentialIDPath $env:USERPROFILE\OracleVMCredentialID
}

Function Get-OracleVMCredentialID {
    [CmdletBinding()]
    param ()
    Get-SecureStringFile -InputFile $(Get-OracleVMCredentialIDPath)
}

function Get-OVMCLIConnectionInformation {
    $OracleVMCLIPasswordstateEntry = Get-PasswordstateEntryDetails -PasswordID "2613"
    $OVMCLIConnectionInformation = [pscustomobject][ordered]@{
#        ComputerName = $OracleVMCLIPasswordstateEntry.URL
        ComputerName = ([System.Uri]$OracleVMCLIPasswordstateEntry.URL).host
        Port = $OracleVMCLIPasswordstateEntry.GenericField1
        Credential = Get-PasswordstateCredential -PasswordID "2613"
    }
    $OVMCLIConnectionInformation
}

function Get-OVMVMDiskMappingList{
#    param(
#        [Parameter(Mandatory)]$Computername,
#        [Parameter(Mandatory)]$Port,
#        [Parameter(Mandatory)]$Credential
#    )
    $OVMCLIConnectionInformation = Get-OVMCLIConnectionInformation
    $Computername = $OVMCLIConnectionInformation.ComputerName
    $Port = $OVMCLIConnectionInformation.Port
    $Credential = $OVMCLIConnectionInformation.Credential

    $OVMListVMDiskMappingTemplate = @"
  id:{OVMDiskID*:0004fb0000130000961a44e256fa4b31}  name:{OVMDiskMappingName:0004fb0000130000961a44e256fa4b31}
  id:{OVMDiskID*:0004fb000013000036c13078180c37ff}  name:{OVMDiskMappingName:0004fb000013000036c13078180c37ff}
  id:{OVMDiskID*:0004fb0000130000d5c315c8229da893}  name:{OVMDiskMappingName:0004fb0000130000d5c315c8229da893}
  id:{OVMDiskID*:0004fb00001300009bf7c129696d3437}  name:{OVMDiskMappingName:0004fb00001300009bf7c129696d3437}
"@
    $SSHSession = New-SSHSession -Credential $credential -ComputerName $Computername -Port $Port -AcceptKey
    $SCRIPTCommand="list vmdiskmapping"
    $Output = $(Invoke-SSHCommand -SSHSession $(get-sshsession) -Command $SCRIPTCommand).Output
    Remove-SSHSession $SSHSession | Out-Null
    #$VMDiskMappingList = $output -replace "`r", "" | ConvertFrom-String -TemplateContent $OVMListVMDiskMappingTemplate
    $output -replace "`r", "" | ConvertFrom-String -TemplateContent $OVMListVMDiskMappingTemplate
}

function Get-OVMPhysicalDiskList{
#    param(
#        [Parameter(Mandatory)]$Computername,
#        [Parameter(Mandatory)]$Port,
#        [Parameter(Mandatory)]$Credential
#    )
    $OVMCLIConnectionInformation = Get-OVMCLIConnectionInformation
    $Computername = $OVMCLIConnectionInformation.ComputerName
    $Port = $OVMCLIConnectionInformation.Port
    $Credential = $OVMCLIConnectionInformation.Credential

    $OVMListPhysicalDiskTemplate  = @"
  id:{OVMDiskID*:0004fb00001800008188f5f91b172e9d}  name:{OVMDiskName:DGC (1)}
  id:{OVMDiskID*:0004fb0000180000ab97f53fa7b80933}  name:{OVMDiskName:DGC (4)}
  id:{OVMDiskID*:0004fb0000180000ad940807b7ce1f2a}  name:{OVMDiskName:ebsdb-prd_ebsdata2;}
  id:{OVMDiskID*:0004fb00001800006fb85369964810a2}  name:{OVMDiskName:eps-odbee01_u01_500;}
# id:{OVMDiskID*:0004fb0000180000597bf2f8ed83c402}  name:{OVMDiskName:ebsdb-prd_ebs-ebsdata;}
"@
    $SSHSession = New-SSHSession -Credential $credential -ComputerName $Computername -Port $Port -AcceptKey
    $SCRIPTCommand="list physicaldisk"
    $SSHCommandString = "Invoke-SshCommand -computername $OVMCLIHost -Command `"$SCRIPTCommand `""
    $Output = $(Invoke-SSHCommand -SSHSession $(get-sshsession) -Command $SCRIPTCommand).Output
    Remove-SSHSession $SSHSession | Out-Null
    #$PhysicalDiskList = $output | ConvertFrom-String -TemplateContent $OVMListPhysicalDiskTemplate  
    $output | ConvertFrom-String -TemplateContent $OVMListPhysicalDiskTemplate  
}

function Get-OVMPhysicalDiskDetails{
#    param(
#        [Parameter(Mandatory)]$Computername,
#        [Parameter(Mandatory)]$Port,
#        [Parameter(Mandatory)]$Credential
#    )
    $OVMCLIConnectionInformation = Get-OVMCLIConnectionInformation
    $Computername = $OVMCLIConnectionInformation.ComputerName
    $Port = $OVMCLIConnectionInformation.Port
    $Credential = $OVMCLIConnectionInformation.Credential

    $OVMShowPhysicalDiskTemplate = @"
OVM> show physicaldisk id=0004fb00001800008188f5f91b172e9d
Command: show physicaldisk id=0004fb00001800008188f5f91b172e9d
Status: Success
Time: 2017-08-08 09:43:08,874 EDT
Data: 
  Name = {DISKNAME*:DGC (1)}
  Id = {DiskID:0004fb00001800008188f5f91b172e9d}
  Size (GiB) = {Size:200.0}
  Shareable = No
  Page83 ID = {SANID:3600601601110190080a4f954c48de311}
  Thin Provision = Yes
  VolumeGroup = Generic_SAN_Volume_Group @ Unmanaged FibreChannel Storage Array  [FibreChannel Volume Group]
  San Server = Unmanaged FibreChannel Storage Array
OVM> show physicaldisk id=0004fb0000180000c4f4751fb6765018
Command: show physicaldisk id=0004fb0000180000c4f4751fb6765018
Status: Success
Time: 2016-10-19 09:15:36,407 EDT
Data: 
  Name = {DISKNAME*:soa-db_dbdata;}
  Id = {DiskID:0004fb0000180000c4f4751fb6765018}
  Size (GiB) = {Size:200.0}
  Shareable = No
  Page83 ID = {SANID:3600601603dc12e004c4398f6fd67e311}
  Thin Provision = Yes
  VolumeGroup = Generic_SAN_Volume_Group @ Unmanaged FibreChannel Storage Array  [FibreChannel Volume Group]
  San Server = Unmanaged FibreChannel Storage Array
OVM> show physicaldisk id=0004fb00001800005cebfbb37acaea1a
Command: show physicaldisk id=0004fb00001800005cebfbb37acaea1a
Status: Success
Time: 2016-10-19 09:15:36,419 EDT
Data: 
  Name = {DISKNAME*:p-odbee02_obia-obiadata;}
  Id = {DiskID:0004fb00001800005cebfbb37acaea1a}
  Size (GiB) = {Size:500.0}
  Shareable = No
  Page83 ID = {SANID:3600601603dc12e00505e0a5162a9e311}
  Thin Provision = Yes
  VolumeGroup = Generic_SAN_Volume_Group @ Unmanaged FibreChannel Storage Array  [FibreChannel Volume Group]
  San Server = Unmanaged FibreChannel Storage Array
OVM> show physicaldisk id=0004fb0000180000ad940807b7ce1f2a
Command: show physicaldisk id=0004fb0000180000ad940807b7ce1f2a
Status: Success
Time: 2017-08-08 09:43:08,909 EDT
Data: 
  Name = {DISKNAME*:EBSAPPS-PRD_U01_New}
  Id = {DiskID:0004fb0000180000ad940807b7ce1f2a}
  Size (GiB) = {Size:2048.0}
  Shareable = No
  Page83 ID = {SANID:36006016020b038001bc5331d4f4ee411}
  Thin Provision = Yes
  VolumeGroup = Generic_SAN_Volume_Group @ Unmanaged FibreChannel Storage Array  [FibreChannel Volume Group]
  San Server = Unmanaged FibreChannel Storage Array
"@
#    $VNXLUNs = Get-LUNSFromVNX -TervisStorageArraySelection All
    $OVMPhysicalDiskList = (Get-OVMPhysicalDiskList -Credential $credential -ComputerName $Computername -Port $Port)
    $OVMPhysicalDiskList | % {
        $SCRIPTCommand += "show physicaldisk id=$($_.OVMDiskID);"
    }
    $SSHSession = New-SSHSession -Credential $credential -ComputerName $Computername -Port $Port -AcceptKey
    $Output = $(Invoke-SSHCommand -SSHSession $(get-sshsession) -Command $SCRIPTCommand).Output
    Remove-SSHSession $SSHSession | Out-Null
    $PhysicalDiskDetailList = $output -replace "`r", "" | ConvertFrom-String -TemplateContent $OVMShowPhysicalDiskTemplate
#    foreach ($PhysicalDisk in $PhysicalDiskDetailList){
#            $LUN = $VNXLUNs | where {($_.LUNUID -replace ":","") -like ($PhysicalDisk.SANID).Substring(1)}
#            if ($LUN){
#                $PhysicalDisk | Add-Member Array $LUN.Array -Force
#            }
#            else{
#                $PhysicalDisk | Add-Member Array "NA" -Force
#            }
#    }
    $PhysicalDiskDetailList
}

function Get-OVMVMDiskMappingDetails{
#    param(
#        [Parameter(Mandatory)]$Computername,
#        [Parameter(Mandatory)]$Port,
#        [Parameter(Mandatory)]$Credential
#    )
    $OVMCLIConnectionInformation = Get-OVMCLIConnectionInformation
    $Computername = $OVMCLIConnectionInformation.ComputerName
    $Port = $OVMCLIConnectionInformation.Port
    $Credential = $OVMCLIConnectionInformation.Credential
    $VNXLUNs = Get-LUNSFromVNX -TervisStorageArraySelection All
    $OVMVMDiskMappingList = Get-OVMVMDiskMappingList -Credential $credential -ComputerName $Computername -Port $Port
    $OVMVMDiskMappingList | %{
        $SCRIPTCommand += "show vmdiskmapping id=$($_.OVMDiskID);"
    }
    $SSHSession = New-SSHSession -Credential $credential -ComputerName $Computername -Port $Port -AcceptKey
    $RawVMDiskMappingOutput = $(Invoke-SSHCommand -SSHSession $(get-sshsession) -Command $SCRIPTCommand).Output
    Remove-SSHSession $SSHSession | Out-Null
    $OVMPhysicalDiskDetailList = Get-OVMPhysicalDiskDetails   

    
        $MappedVMDisklist = @()
        $SplitRawVMDiskMappingOutput = $RawVMDiskMappingOutput.split("`n")
        $TrimmedRawVMDiskMappingOutput= $SplitRawVMDiskMappingOutput[0..($SplitRawVMDiskMappingOutput.Count - 2)]
    do{
        $CurrentDiskMapping = $TrimmedRawVMDiskMappingOutput[0..10]
        $DiskIDLine = $CurrentDiskMapping[9].Trim() -replace " ","" -replace "\["," " -replace "\]","" -split "=" -split " "
        if ($DiskIDLine.count -lt 3){
            $Diskname = "NA"
        }
        else{$Diskname = ($CurrentDiskMapping[9].Trim() -replace " ","" -replace "\["," " -replace "\]","" -split "=" -split " ")[2]}
    
        $MappedVMDisk = [pscustomobject][ordered]@{
            DiskName = $Diskname
            DiskID = ($CurrentDiskMapping[9].Trim() -replace " ","" -replace "\["," " -replace "\]","" -split "=" -split " ")[1]
            Slot = ($CurrentDiskMapping[7].Trim() -replace " ","" -split "=")[1]
            VMName = ($CurrentDiskMapping[10].Trim() -replace " ","" -replace "\["," " -replace "\]","" -split "=" -split " ")[2]
        }
        $MappedVMDiskList += $MappedVMDisk
        $TrimmedRawVMDiskMappingOutput = $TrimmedRawVMDiskMappingOutput[11..($TrimmedRawVMDiskMappingOutput.count)]
    }While($TrimmedRawVMDiskMappingOutput)

    ForEach ($MappedVMDisk in $MappedVMDisklist){
            ForEach ($Entry in $OVMPhysicalDiskDetailList){
                if($Entry.DiskID -like "*$($MappedVMDisk.DiskID)"){
                    $Array = ($VNXLUNs | where {($_.LUNUID -replace ":","") -match ($Entry.SANID).Substring(1)}).Array
                     $MappedVMDisk | Add-Member Size $Entry.Size
                     $MappedVMDisk | Add-Member SANID $Entry.SANID
                     $MappedVMDisk | Add-Member LUNUID ($Entry.SANID.substring(1))
                     $MappedVMDisk | Add-Member Array $Array
                }
            }
            if(!$MappedVMDisk.SANID){
                $MappedVMDisk | Add-Member Size "NA"
                $MappedVMDisk | Add-Member SANID "NA"
                $MappedVMDisk | Add-Member LUNUID "NA"
                $MappedVMDisk | Add-Member Array "NA"
                }
    }    
    $MappedVMDisklist
}

function Get-OVMStorageMappingDetails {
    $VNXLUNs = Get-LUNSFromVNX -TervisStorageArraySelection All
    $OVMDiskMappingDetails = Get-OVMVMDiskMappingDetails
    Foreach ($OVMDiskMapping in $OVMDiskmappingdetails) {
        if ($LUN = ($VNXLUNs | where {($_.LUNUID -replace ":","") -eq $OVMDiskMapping.LUNUID})) {
           [pscustomobject][ordered]@{
               VM = $OVMDiskMapping.VMName
               VNXLUNName = $LUN.LUNName
               OVMDiskName = $OVMDiskMapping.DiskName
               DiskNumber = $OVMDiskMapping.Slot
               Array = $LUN.Array
               Size = ($LUN.LUNCapacity / 1kb)
               OVMDiskID = $OVMDiskMapping.DiskID
               LUNUID =  if ($LUN.LUNUID){$LUN.LUNUID}else{"NA"}
            }
        }
    
    }
}

function Get-OVMGuestDiskDetails {
    param(
        [parameter(Mandatory)]$Computer
    )
    $OVMStorageMappingDetails = Get-OVMStorageMappingDetails
    $LinuxStorageMapping = Get-LinuxStorageMapping -Hostname $Computer | where Devname -NotMatch "dm-"
    Foreach ($LinuxDiskMapping in $LinuxStorageMapping){
            if($Mapping = ($OVMStorageMappingDetails | where {$LinuxDiskMapping.Devname -eq ("xvd" + (Convert-NumberToLetter -Number $_.DiskNumber)) -and $_.VM -eq $Computer })){
                $LinuxDiskMapping | Add-Member -MemberType NoteProperty -Name SANDisk -Value $Mapping.VNXLUNName -force
                $LinuxDiskMapping | Add-Member -MemberType NoteProperty -Name Size -Value $Mapping.Size -force
                $LinuxDiskMapping | Add-Member -MemberType NoteProperty -Name Array -Value $Mapping.Array -force
            }
            else {
                $LinuxDiskMapping | Add-Member -MemberType NoteProperty -Name SANDisk -Value "NA" -force
                $LinuxDiskMapping | Add-Member -MemberType NoteProperty -Name Size -Value "NA" -force
                $LinuxDiskMapping | Add-Member -MemberType NoteProperty -Name Array -Value $Mapping.Array -force    
            }
    }
    $LinuxStorageMapping
}

Function Get-OVMPhysicalDisksNotAttached{
#    param(
#        [Parameter(Mandatory)]$Computername,
#        [Parameter(Mandatory)]$Port,
#        [Parameter(Mandatory)]$Credential
#    )
    $OVMCLIConnectionInformation = Get-OVMCLIConnectionInformation
    $Computername = $OVMCLIConnectionInformation.ComputerName
    $Port = $OVMCLIConnectionInformation.Port
    $Credential = $OVMCLIConnectionInformation.Credential
    $VNXLUNs = Get-LUNSFromVNX -TervisStorageArraySelection All
    $OVMPhysicalDiskDetailList = Get-OVMPhysicalDiskDetails -Credential $credential -ComputerName $Computername -Port $Port
    $OVMVMDiskMappingDetails = Get-OVMVMDiskMappingDetails -Credential $credential -ComputerName $Computername -Port $Port
    ForEach ($PhysicalDisk in $OVMPhysicalDiskDetailList){
        if($OVMVMDiskMappingDetails.DiskName -notcontains $PhysicalDisk.DiskName){
            $LUN = $VNXLUNs | where {($_.LUNUID -replace ":","") -like ($PhysicalDisk.SANID).Substring(1)}
            if ($LUN){
                $PhysicalDisk | Add-Member Array $LUN.Array -Force
            }
            else{
                $PhysicalDisk | Add-Member Array "NA" -Force
            }

            $PhysicalDisk
        }
    }

}

Function Get-OracleServerDefinition{
    Param(
        [Parameter(Mandatory)]
        $Computername
    )
    $OracleServerDefinitions | where Computername -eq $Computername
}

function set-TervisOracleODBEEServerConfiguration{
    Param(
        [Parameter(Mandatory)]
        $Computername
    )
    $FQDN = $Computername + ".tervis.prv"
    $OracleLinuxDefaultRootCredential = Get-PasswordstateCredential -PasswordID "4040"
    $SSHSession = New-SSHSession -Credential $OracleLinuxDefaultRootCredential -ComputerName $Computername -AcceptKey
    $OracleServerDefinition = Get-OracleServerDefinition -Computername $Computername

    ForEach ($DefinitionPreScript in $OracleServerDefinition.PreInstallScripts) {
        Invoke-SSHCommand -SSHSession $(get-sshsession) -Command $script
    }
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command $OracleServerDefinition.PuppetConfiguration
    Invoke-SSHCommand -SSHSession $(get-sshsession) -Command "puppet apply /etc/puppet/manifests/SFTPServer.pp"


    Remove-SSHSession $SSHSession | Out-Null

}

function Invoke-MatchOVMBlockIDtoGuestDeviceName {

    
    $Vdev = xm block-list $Domain
    xenstore-ls ### match 'frontend' with 'dev' - coorelates Vdev to Guest devicename (/dev/xvd?)
    xm block-detach $Domain $Vdev
}

function Invoke-OVMXenstorels {
    param(
        [parameter(Mandatory)]$Computername,
        [parameter(Mandatory)]$Credential
    )
    New-SSHSession -ComputerName $Computername -Credential $Credential | Out-Null
    $CommandOutput = Invoke-SSHCommand -SSHSession $SshSessions -Command {xenstore-ls}
    Remove-SSHSession $SshSessions | Out-Null
    $CommandOutput.output

}

function Invoke-OVMXMList {
    param(
        [parameter(Mandatory)]$Computername,
        [parameter(Mandatory)]$Credential
    )
    $XMListTemplate = @"
Name                                        ID   Mem VCPUs      State   Time(s)
{DomainID*:0004fb0000060000c5fee5922b83ac28}             {ID:1} 250000    16     r----- 5447521.2
Domain-0                                     0  3152    20     r----- 259938.1
"@
    New-SSHSession -ComputerName $Computername -Credential $Credential | Out-Null
    $CommandOutput = Invoke-SSHCommand -SSHSession $SshSessions -Command {xm list}
    $CommandOutput.output | ConvertFrom-String -TemplateContent $XMListTemplate     
    Remove-SSHSession $SshSessions | Out-Null

}

function Get-OVMXenBlockID {
    param(
        [parameter(Mandatory)]$Computername,
        [parameter(Mandatory)]$DomainID,
        [parameter(Mandatory)]$Credential
    )
    New-SSHSession -ComputerName $Computername -Credential $Credential | Out-Null
    $command = "xenstore-ls /local/domain/$DomainID"
    $CommandOutput = Invoke-SSHCommand -SSHSession $SshSessions -Command $command
    $CommandOutput.output | ConvertFrom-String -TemplateContent $XenstoreLSTemplate
    Remove-SSHSession $SshSessions | Out-Null


}

function Get-OVMBlockDeviceDetail{
    param(
        [parameter(Mandatory)]$Computername,
        [parameter(Mandatory)]$DevicePath,
        [parameter(Mandatory)]$Credential
    )
    New-SSHSession -ComputerName $Computername -Credential $Credential | Out-Null
    $command = "xenstore-ls $DevicePath"
    $CommandOutput = Invoke-SSHCommand -SSHSession $SshSessions -Command $command
    Remove-SSHSession $SshSessions | Out-Null

    $CommandOutput.output | ConvertFrom-StringUsingRegexCaptureGroup -Regex @"
domain = "(?<Domain>[^"]*)"
frontend = "(?<Frontend>[^"]*)"
uuid = "(?<UUID>[^"]*)"
bootable = "(?<Bootable>[^"]*)"
dev = "(?<Device>[^"]*)"
state = "(?<State>[^"]*)"
params = "(?<Params>[^"]*)"
mode = "(?<Mode>[^"]*)"
online = "(?<Online>[^"]*)"
frontend-id = "(?<FrontendID>[^"]*)"
type = "(?<Type>[^"]*)"
physical-device = "(?<PhysicalDevice>[^"]*)"
hotplug-status = "(?<Hotplug>[^"]*)"
feature-flush-cache = "(?<FeatureFlushCache>[^"]*)"
discard-secure = "(?<DiscardSecure>[^"]*)"
feature-discard = "(?<FeatureDiscard>[^"]*)"
feature-barrier = "(?<FeatureBarrier>[^"]*)"
sectors = "(?<Sectors>[^"]*)"
info = "(?<Info>[^"]*)"
sector-size = "(?<SectorSize>[^"]*)"
"@
}

function invoke-OVMAPIRequest {
    $URI= "https://inf-ovmmanager01/ovm/core/wsapi/soap"
    
    
    
    
    $username = 'admin'  
    $password = ''
    $target = "Daily Whatsis Roundup"  
    
    $hdrs = @{"X-Requested-With"="powershell"}  
    $base = "https://qualysapi.qualys.com/api/2.0/fo"  
    $body = "action=login&username=$username&password=$password"  
    Invoke-RestMethod -Headers $hdrs -Uri "$base/session/" -Method Post -Body $body -SessionVariable sess
    
    
    
    $username = "username"  
    $password = "password"  
    $password_base64 = ConvertTo-SecureString $password -AsPlainText -Force  
    $creds = New-Object System.Management.Automation.PSCredential ($username, $password_base64)  
    $headers = @{"X-Requested-With"="powershell"}  
    $url = "https://qualysapi.qualys.com/about.php"  
    Invoke-RestMethod -Headers $headers -Uri $url -Method 
}

function Invoke-OracleVMManagerAPICall{
    param(
        [parameter(Mandatory)]$Method,
        [parameter(Mandatory)]$URIPath,
        $InputJSON
    )
    
    $OVMManagerPasswordstateEntryDetails = Get-PasswordstateEntryDetails -PasswordID 4157
    $username = $OVMManagerPasswordstateEntryDetails.Username
    $password = $OVMManagerPasswordstateEntryDetails.Password
    $URL = "https://" + ([System.Uri]$OVMManagerPasswordstateEntryDetails.url).Authority + "/ovm/core/wsapi/rest" + $URIPath
    add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate,
                                      WebRequest request, int certificateProblem) {
        return true;
    }
 }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    $credPair = "$($username):$($password)"
    $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add('Authorization',"Basic $encodedCredentials")
    $headers.Add('Accept',"application/json")
    $headers.Add('Content-Type',"application/json")

    if($Method -eq "GET"){
        Invoke-RestMethod -Uri $URL -Method Get -Headers $headers -UseBasicParsing -verbose
    }
    if($Method -eq "PUT"){
        Invoke-RestMethod -Uri $url -Method Put -Headers $headers -Body $InputJSON -UseBasicParsing -verbose
    }
    if($Method -eq "POST"){
        Invoke-RestMethod -Uri $url -Method POST -Headers $headers -Body $InputJSON -UseBasicParsing -verbose
    }
    if($Method -eq "DELETE"){
        Invoke-RestMethod -Uri $url -Method DELETE -Headers $headers -Body $InputJSON -UseBasicParsing -verbose
    }
#    $output = $responseData.Content | ConvertFrom-Json
}
function Get-OVMVirtualMachines {
    param(
        [parameter(Mandatory,ParameterSetName="Name")]$Name,
        [parameter(Mandatory,ParameterSetName="ID")]$ID
    )
    if ($ID){
        Invoke-OracleVMManagerAPICall -Method GET -URIPath "/Vm/$VMID"
    }
    Else{
        $VMListing = Invoke-OracleVMManagerAPICall -Method get -URIPath "/Vm"
        if ($Name){
            $VMListing | where name -eq $Name
        }
        else {
            $VMListing
        }
    }
}

function Invoke-OVMSendMessagetoVM {
    param(
        [parameter(mandatory)]$VMID,
        [parameter(Mandatory,ValueFromPipelineByPropertyName)]$JSON
    )
    Invoke-OracleVMManagerAPICall -Method put `
    -URIPath "/Vm/$VMID/sendMessage?logFlag=Yes" `
    -InputJSON $JSON
}

function Get-OVMJob {
    param(
        [parameter(ParameterSetName="ByID")]$JobID,
        [parameter(ParameterSetName="AllJobs")]$StartTime,
        [parameter(ParameterSetName="AllJobs")]$EndTime,
        [parameter(ParameterSetName="AllJobs")]$MaxJobs,
        [parameter(ParameterSetName="ActiveJobs")][switch]$Active,
        [parameter(ParameterSetName="ByID")][switch]$Transcript
    )

    if ($PSCmdlet.ParameterSetName -eq "ByID"){
        $URIPath = "/Job/$JobID"
        if($Transcript){
            $URIPath += "/transcript"
        }
    }
    if ($PSCmdlet.ParameterSetName -eq "AllJobs"){
        $URIPath = "/Job/id?startTime=$StartTime&endTime=$EndTime&maxJobs=$MaxJobs"
    }
    if ($PSCmdlet.ParameterSetName -eq "ActiveJobs"){
        $URIPath = "/Job/active"
    }
    Invoke-OracleVMManagerAPICall -Method GET -URIPath $URIPath
}

function Invoke-OVMCloneVM {
    param(
        [parameter(mandatory)]$VMID,
        [parameter(mandatory)]$ServerPoolID,
        $RepositoryID,
        $VMCloneDefinitionID,
        $TemplateID = "False"
    )
        
    $URIPath = "/Vm/$VMID/clone?serverPoolId=$ServerPoolID&createTemplate=false"
    
    if($RepositoryID){
        $URIPath += "&repositoryId=$RepositoryID"
    }
    if($VMCloneDefinitionID){
        $URIPath += "&vmCloneDefinitionId=$VMCloneDefinitionID&createTemplate=false"
    }
    $CloneResult = Invoke-OracleVMManagerAPICall -Method PUT -URIPath $URIPath
    do{
        Start-Sleep 1
        $CloneJob = Get-OVMJob -JobID $CloneResult.id.value
    }while($CloneJob.done -eq $false)
    Get-OVMVirtualMachines -Name $CloneJob.resultId.name    
}

$XenstoreTemplate = @"
tool = ""
 xenstored = ""
local = ""
 domain = ""
  0 = ""
   vm = "/vm/00000000-0000-0000-0000-000000000000"
   device = ""
   control = ""
    platform-feature-multiprocessor-suspend = "1"
   error = ""
   memory = ""
    target = "3227648"
   guest = ""
   hvmpv = ""
   data = ""
   cpu = ""
    15 = ""
     availability = "online"
    3 = ""
     availability = "online"
    8 = ""
     availability = "online"
    9 = ""
     availability = "online"
    6 = ""
     availability = "online"
    5 = ""
     availability = "online"
    13 = ""
     availability = "online"
    0 = ""
     availability = "online"
    18 = ""
     availability = "online"
    17 = ""
     availability = "online"
    12 = ""
     availability = "online"
    14 = ""
     availability = "online"
    19 = ""
     availability = "online"
    2 = ""
     availability = "online"
    11 = ""
     availability = "online"
    1 = ""
     availability = "online"
    7 = ""
     availability = "online"
    16 = ""
     availability = "online"
    4 = ""
     availability = "online"
    10 = ""
     availability = "online"
   description = ""
   console = ""
    limit = "1048576"
    type = "xenconsoled"
   name = "Domain-0"
   domid = "{DomID*:0}"
   backend = ""
    vkbd = ""
     1 = ""
      0 = ""
       frontend-id = "1"
       domain = "0004fb0000060000c5fee5922b83ac28"
       frontend = "/local/domain/1/device/vkbd/0"
       state = "4"
       online = "1"
       feature-abs-pointer = "1"
       hotplug-status = "connected"
    vfb = ""
     1 = ""
      0 = ""
       vncunused = "1"
       domain = "0004fb0000060000c5fee5922b83ac28"
       vnc = "1"
       uuid = "7614df2f-02d2-c31c-f1f2-479f12c6b89f"
       vnclisten = "127.0.0.1"
       frontend = "/local/domain/1/device/vfb/0"
       state = "4"
       keymap = "en-us"
       online = "1"
       frontend-id = "1"
       xauthority = "/root/.Xauthority"
       feature-resize = "1"
       hotplug-status = "connected"
       location = "127.0.0.1:5900"
       request-update = "1"
    vbd = ""
     1 = ""
      {BlockID*:51712} = ""
       domain = "{Domain:0004fb0000060000c5fee5922b83ac28}"
       frontend = "{FrontendPath:/local/domain/1/device/vbd/51712}"
       uuid = "4ebe3c81-ba8c-ae08-e229-7c1fe41c5d26"
       bootable = "1"
       dev = "{Device:xvda}"
       state = "4"
       params = "/OVS/Repositories/0004fb00000300007a71d85fde7ca820/VirtualD\..."
       mode = "w"
       online = "1"
       frontend-id = "1"
       type = "file"
       node = "/dev/loop2"
       physical-device = "7:2"
       hotplug-status = "connected"
       feature-flush-cache = "1"
       feature-discard = "0"
       feature-barrier = "1"
       sectors = "25165824"
       info = "0"
       sector-size = "512"
      {BlockID*:51760} = ""
       domain = "{Domain:0004fb0000060000c5fee5922b83ac28}"
       frontend = "{FrontendPath:/local/domain/1/device/vbd/51760}"
       uuid = "d4c45327-6bc8-4e54-0a0a-c44720801b28"
       bootable = "0"
       dev = "{Device:xvdd}"
       state = "4"
       params = "/OVS/Repositories/0004fb00000300007a71d85fde7ca820/VirtualD\..."
       mode = "w"
       online = "1"
       frontend-id = "1"
       type = "file"
       node = "/dev/loop1"
       physical-device = "7:1"
       hotplug-status = "connected"
       feature-flush-cache = "1"
       feature-discard = "0"
       feature-barrier = "1"
       sectors = "33554432"
       info = "0"
       sector-size = "512"
      {BlockID*:51856} = ""
       domain = "{Domain:0004fb0000060000c5fee5922b83ac28}"
       frontend = "{FrontendPath:/local/domain/1/device/vbd/51856}"
       uuid = "102e14d2-511e-be62-94ef-51e1302edd4e"
       bootable = "0"
       dev = "{Device:xvdj}"
       state = "4"
       params = "/dev/mapper/36006016020b03800f117af276337e411"
       mode = "w"
       online = "1"
       frontend-id = "1"
       type = "phy"
       physical-device = "fc:8"
       hotplug-status = "connected"
       feature-flush-cache = "1"
       discard-secure = "0"
       feature-discard = "0"
       feature-barrier = "1"
       sectors = "3145728000"
       info = "0"
       sector-size = "512"
      51872 = ""
       domain = "0004fb0000060000c5fee5922b83ac28"
       frontend = "/local/domain/1/device/vbd/51872"
       uuid = "93014a2f-b89f-e3ab-d871-c602ec4d26bc"
       bootable = "0"
       dev = "xvdk"
       state = "4"
       params = "/OVS/Repositories/0004fb00000300007a71d85fde7ca820/VirtualD\..."
       mode = "w"
       online = "1"
       frontend-id = "1"
       type = "file"
       node = "/dev/loop0"
       physical-device = "7:0"
       hotplug-status = "connected"
       feature-flush-cache = "1"
       feature-discard = "0"
       feature-barrier = "1"
       sectors = "62914560"
       info = "0"
       sector-size = "512"
      51888 = ""
       domain = "0004fb0000060000c5fee5922b83ac28"
       frontend = "/local/domain/1/device/vbd/51888"
       uuid = "faaccc1b-6ac4-3441-deba-fc7ec6292818"
       bootable = "0"
       dev = "xvdl"
       state = "4"
       params = "/dev/mapper/36006016020b03800283daf7f92ffe311"
       mode = "w"
       online = "1"
       frontend-id = "1"
       type = "phy"
       physical-device = "fc:2"
       hotplug-status = "connected"
       feature-flush-cache = "1"
       discard-secure = "0"
       feature-discard = "0"
       feature-barrier = "1"
       sectors = "2147483648"
       info = "0"
       sector-size = "512"
      51904 = ""
       domain = "0004fb0000060000c5fee5922b83ac28"
       frontend = "/local/domain/1/device/vbd/51904"
       uuid = "a053328a-591c-36e6-ed7b-3919d5a8f732"
       bootable = "0"
       dev = "xvdm"
       state = "4"
       params = "/dev/mapper/36006016020b03800c9d0d06792ffe311"
       mode = "w"
       online = "1"
       frontend-id = "1"
       type = "phy"
       physical-device = "fc:1"
       hotplug-status = "connected"
       feature-flush-cache = "1"
       discard-secure = "0"
       feature-discard = "0"
       feature-barrier = "1"
       sectors = "1048576000"
       info = "0"
       sector-size = "512"
      51920 = ""
       domain = "0004fb0000060000c5fee5922b83ac28"
       frontend = "/local/domain/1/device/vbd/51920"
       uuid = "9b861dba-9492-0f2a-0bdb-95861f026c22"
       bootable = "0"
       dev = "xvdn"
       state = "4"
       params = "/dev/mapper/36006016020b038001738c0b57624e411"
       mode = "w"
       online = "1"
       frontend-id = "1"
       type = "phy"
       physical-device = "fc:3"
       hotplug-status = "connected"
       feature-flush-cache = "1"
       discard-secure = "0"
       feature-discard = "0"
       feature-barrier = "1"
       sectors = "2147483648"
       info = "0"
       sector-size = "512"
      51952 = ""
       domain = "0004fb0000060000c5fee5922b83ac28"
       frontend = "/local/domain/1/device/vbd/51952"
       uuid = "c63ec58a-76a3-5cc5-b4bf-261c1ce2e01b"
       bootable = "0"
       dev = "xvdp"
       state = "4"
       params = "/dev/mapper/36006016020b03800ec77e62fef98e511"
       mode = "w"
       online = "1"
       frontend-id = "1"
       type = "phy"
       physical-device = "fc:b"
       hotplug-status = "connected"
       feature-flush-cache = "1"
       discard-granularity = "512"
       discard-alignment = "0"
       discard-secure = "0"
       feature-discard = "1"
       feature-barrier = "1"
       sectors = "8589934592"
       info = "0"
       sector-size = "512"
      268439552 = ""
       domain = "0004fb0000060000c5fee5922b83ac28"
       frontend = "/local/domain/1/device/vbd/268439552"
       uuid = "f91666f6-0ce0-6456-0e7b-2f56242e986c"
       bootable = "0"
       dev = "xvdq"
       state = "4"
       params = "/dev/mapper/36006016020b03800d89aa641ef98e511"
       mode = "w"
       online = "1"
       frontend-id = "1"
       type = "phy"
       physical-device = "fc:c"
       hotplug-status = "connected"
       feature-flush-cache = "1"
       discard-granularity = "512"
       discard-alignment = "0"
       discard-secure = "0"
       feature-discard = "1"
       feature-barrier = "1"
       sectors = "8589934592"
       info = "0"
       sector-size = "512"
      268439808 = ""
       domain = "0004fb0000060000c5fee5922b83ac28"
       frontend = "/local/domain/1/device/vbd/268439808"
       uuid = "4204a71d-9d4b-9947-1e8b-fa2ac5ce27b5"
       bootable = "0"
       dev = "xvdr"
       state = "4"
       params = "/dev/mapper/36006016020b03800b72a01ad67f7e511"
       mode = "w"
       online = "1"
       frontend-id = "1"
       type = "phy"
       physical-device = "fc:9"
       hotplug-status = "connected"
       feature-flush-cache = "1"
       discard-secure = "0"
       feature-discard = "0"
       feature-barrier = "1"
       sectors = "1048576000"
       info = "0"
       sector-size = "512"
    vif = ""
     1 = ""
      0 = ""
       bridge = "0004fb00103588d"
       domain = "0004fb0000060000c5fee5922b83ac28"
       handle = "0"
       uuid = "456c8e29-7396-3125-6839-e728aa12bee8"
       script = "/etc/xen/scripts/vif-bridge"
       state = "4"
       frontend = "/local/domain/1/device/vif/0"
       mac = "00:21:f6:1c:2b:5a"
       online = "1"
       frontend-id = "1"
       feature-sg = "1"
       feature-gso-tcpv4 = "1"
       feature-rx-copy = "1"
       feature-rx-flip = "0"
       hotplug-status = "connected"
    console = ""
     1 = ""
      0 = ""
       domain = "0004fb0000060000c5fee5922b83ac28"
       protocol = "vt100"
       uuid = "18a3763f-c8d0-0282-2ed2-b6f985174871"
       frontend = "/local/domain/1/device/console/0"
       state = "4"
       location = "2"
       online = "1"
       frontend-id = "1"
       hotplug-status = "connected"
   device-model = ""
    1 = ""
     state = "running"
  1 = ""
   vm = "/vm/0004fb00-0006-0000-c5fe-e5922b83ac28"
   device = ""
    vkbd = ""
     0 = ""
      protocol = "x86_64-abi"
      state = "4"
      backend-id = "0"
      backend = "/local/domain/0/backend/vkbd/1/0"
      request-abs-pointer = "1"
      page-ref = "2341224"
      page-gref = "8"
      event-channel = "116"
    vfb = ""
     0 = ""
      protocol = "x86_64-abi"
      state = "4"
      backend-id = "0"
      backend = "/local/domain/0/backend/vfb/1/0"
      page-ref = "2349472"
      event-channel = "115"
      feature-update = "1"
    vbd = ""
     51712 = ""
      virtual-device = "51712"
      device-type = "disk"
      protocol = "x86_64-abi"
      backend-id = "0"
      state = "4"
      backend = "/local/domain/0/backend/vbd/1/51712"
      ring-ref = "9"
      event-channel = "117"
      feature-persistent = "1"
     51760 = ""
      virtual-device = "51760"
      device-type = "disk"
      protocol = "x86_64-abi"
      backend-id = "0"
      state = "4"
      backend = "/local/domain/0/backend/vbd/1/51760"
      ring-ref = "10"
      event-channel = "118"
      feature-persistent = "1"
     51856 = ""
      virtual-device = "51856"
      device-type = "disk"
      protocol = "x86_64-abi"
      backend-id = "0"
      state = "4"
      backend = "/local/domain/0/backend/vbd/1/51856"
      ring-ref = "11"
      event-channel = "119"
      feature-persistent = "1"
     51872 = ""
      virtual-device = "51872"
      device-type = "disk"
      protocol = "x86_64-abi"
      backend-id = "0"
      state = "4"
      backend = "/local/domain/0/backend/vbd/1/51872"
      ring-ref = "12"
      event-channel = "120"
      feature-persistent = "1"
     51888 = ""
      virtual-device = "51888"
      device-type = "disk"
      protocol = "x86_64-abi"
      backend-id = "0"
      state = "4"
      backend = "/local/domain/0/backend/vbd/1/51888"
      ring-ref = "14"
      event-channel = "121"
      feature-persistent = "1"
     51904 = ""
      virtual-device = "51904"
      device-type = "disk"
      protocol = "x86_64-abi"
      backend-id = "0"
      state = "4"
      backend = "/local/domain/0/backend/vbd/1/51904"
      ring-ref = "15"
      event-channel = "122"
      feature-persistent = "1"
     51920 = ""
      virtual-device = "51920"
      device-type = "disk"
      protocol = "x86_64-abi"
      backend-id = "0"
      state = "4"
      backend = "/local/domain/0/backend/vbd/1/51920"
      ring-ref = "16"
      event-channel = "123"
      feature-persistent = "1"
     51952 = ""
      virtual-device = "51952"
      device-type = "disk"
      protocol = "x86_64-abi"
      backend-id = "0"
      state = "4"
      backend = "/local/domain/0/backend/vbd/1/51952"
      ring-ref = "18"
      event-channel = "124"
      feature-persistent = "1"
     268439552 = ""
      virtual-device-ext = "268439552"
      state = "4"
      device-type = "disk"
      protocol = "x86_64-abi"
      backend-id = "0"
      backend = "/local/domain/0/backend/vbd/1/268439552"
      ring-ref = "19"
      event-channel = "125"
      feature-persistent = "1"
     268439808 = ""
      virtual-device-ext = "268439808"
      state = "4"
      device-type = "disk"
      protocol = "x86_64-abi"
      backend-id = "0"
      backend = "/local/domain/0/backend/vbd/1/268439808"
      ring-ref = "20"
      event-channel = "126"
      feature-persistent = "1"
    vif = ""
     0 = ""
      mac = "00:21:f6:1c:2b:5a"
      handle = "0"
      protocol = "x86_64-abi"
      backend-id = "0"
      state = "4"
      backend = "/local/domain/0/backend/vif/1/0"
      tx-ring-ref = "415"
      rx-ring-ref = "416"
      event-channel = "127"
      request-rx-copy = "1"
      feature-rx-notify = "1"
      feature-sg = "1"
      feature-gso-tcpv4 = "1"
    console = ""
     0 = ""
      protocol = "x86_64-abi"
      state = "1"
      backend-id = "0"
      backend = "/local/domain/0/backend/console/1/0"
   control = ""
    platform-feature-multiprocessor-suspend = "1"
   error = ""
   memory = ""
    target = "256000000"
   guest = ""
   hvmpv = ""
   data = ""
   console = ""
    tty = "/dev/pts/2"
    ring-ref = "34791160"
    port = "2"
    limit = "1048576"
    type = "ioemu"
    vnc-port = "5900"
    vnc-listen = "127.0.0.1"
   device-misc = ""
    vif = ""
     nextDeviceID = "1"
    console = ""
     nextDeviceID = "1"
   image = ""
    device-model-fifo = "/var/run/xend/dm-1-1505263975.fifo"
    device-model-pid = "13452"
    entry = "18446744071589106176"
    loader = "generic"
    hv-start-low = "18446603336221196288"
    guest-os = "linux"
    hypercall-page = "18446744071578849280"
    guest-version = "2.6"
    pae-mode = "yes"
    paddr-offset = "0"
    virt-base = "18446744071562067968"
    suspend-cancel = "1"
    features = ""
     pae-pgdir-above-4gb = "1"
     writable-page-tables = "0"
    xen-version = "xen-3.0"
   cpu = ""
    3 = ""
     availability = "online"
    6 = ""
     availability = "online"
    14 = ""
     availability = "online"
    13 = ""
     availability = "online"
    11 = ""
     availability = "online"
    1 = ""
     availability = "online"
    7 = ""
     availability = "online"
    4 = ""
     availability = "online"
    15 = ""
     availability = "online"
    8 = ""
     availability = "online"
    9 = ""
     availability = "online"
    5 = ""
     availability = "online"
    0 = ""
     availability = "online"
    12 = ""
     availability = "online"
    2 = ""
     availability = "online"
    10 = ""
     availability = "online"
   store = ""
    ring-ref = "34791161"
    port = "1"
   description = ""
   name = "0004fb0000060000c5fee5922b83ac28"
   domid = "{DomID*:1}"
   serial = ""
    0 = ""
     tty = "/dev/pts/1"
 pool = ""
  0 = ""
   other_config = ""
   description = "Pool-0"
   uuid = "ec70e4ec-0595-9497-5c14-2da6fd5f6c94"
   name = "Pool-0"
vm = ""
 00000000-0000-0000-0000-000000000000 = ""
  on_xend_stop = "ignore"
  pool_name = "Pool-0"
  shadow_memory = "0"
  uuid = "00000000-0000-0000-0000-000000000000"
  on_reboot = "restart"
  image = "(linux (kernel '') (expose_host_uuid 0) (superpages 0) (tsc_mode \..."
   ostype = "linux"
   kernel = ""
   cmdline = ""
   ramdisk = ""
  on_poweroff = "destroy"
  bootloader_args = ""
  on_xend_start = "ignore"
  on_crash = "restart"
  xend = ""
   restart_count = "0"
  vcpus = "20"
  vcpu_avail = "1048575"
  bootloader = ""
  name = "Domain-0"
 0004fb00-0006-0000-c5fe-e5922b83ac28 = ""
  image = "(linux (kernel '') (expose_host_uuid 0) (superpages 0) (tsc_mode \..."
   ostype = "linux"
   kernel = "/var/run/xend/boot/boot_kernel.1Qsf2_"
   cmdline = "ro root=LABEL=/ numa=off "
   ramdisk = "/var/run/xend/boot/boot_ramdisk.LaCKAd"
  device = ""
   vkbd = ""
    0 = ""
     frontend = "/local/domain/1/device/vkbd/0"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vkbd/1/0"
   vfb = ""
    0 = ""
     frontend = "/local/domain/1/device/vfb/0"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vfb/1/0"
   vbd = ""
    51712 = ""
     frontend = "/local/domain/1/device/vbd/51712"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vbd/1/51712"
    51760 = ""
     frontend = "/local/domain/1/device/vbd/51760"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vbd/1/51760"
    51856 = ""
     frontend = "/local/domain/1/device/vbd/51856"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vbd/1/51856"
    51872 = ""
     frontend = "/local/domain/1/device/vbd/51872"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vbd/1/51872"
    51888 = ""
     frontend = "/local/domain/1/device/vbd/51888"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vbd/1/51888"
    51904 = ""
     frontend = "/local/domain/1/device/vbd/51904"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vbd/1/51904"
    51920 = ""
     frontend = "/local/domain/1/device/vbd/51920"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vbd/1/51920"
    51952 = ""
     frontend = "/local/domain/1/device/vbd/51952"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vbd/1/51952"
    268439552 = ""
     frontend = "/local/domain/1/device/vbd/268439552"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vbd/1/268439552"
    268439808 = ""
     frontend = "/local/domain/1/device/vbd/268439808"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vbd/1/268439808"
   vif = ""
    0 = ""
     frontend = "/local/domain/1/device/vif/0"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/vif/1/0"
   console = ""
    0 = ""
     frontend = "/local/domain/1/device/console/0"
     frontend-id = "1"
     backend-id = "0"
     backend = "/local/domain/0/backend/console/1/0"
  on_xend_stop = "ignore"
  pool_name = "Pool-0"
  shadow_memory = "0"
  uuid = "0004fb00-0006-0000-c5fe-e5922b83ac28"
  on_reboot = "restart"
  start_time = "1505263975.5"
  on_poweroff = "destroy"
  bootloader_args = "-q"
  on_xend_start = "ignore"
  on_crash = "restart"
  xend = ""
   restart_count = "0"
  vcpus = "16"
  vcpu_avail = "65535"
  bootloader = "/usr/bin/pygrub"
  name = "0004fb0000060000c5fee5922b83ac28"
"@

$XMListTemplate = @"
Name                                        ID   Mem VCPUs      State   Time(s)
{DomainID*:0004fb0000060000c5fee5922b83ac28}             {ID:1} 250000    16     r----- 5447521.2
Domain-0                                     0  3152    20     r----- 259938.1
"@

$XenstoreLSTemplate = @"
vm = "/vm/0004fb00-0006-0000-c5fe-e5922b83ac28"
device = ""
 vkbd = ""
  0 = ""
   protocol = "x86_64-abi"
   state = "4"
   backend-id = "0"
   backend = "/local/domain/0/backend/vkbd/1/0"
   request-abs-pointer = "1"
   page-ref = "2341224"
   page-gref = "8"
   event-channel = "116"
 vfb = ""
  0 = ""
   protocol = "x86_64-abi"
   state = "4"
   backend-id = "0"
   backend = "/local/domain/0/backend/vfb/1/0"
   page-ref = "2349472"
   event-channel = "115"
   feature-update = "1"
 vbd = ""
  51712 = ""
   virtual-device = "{VirtualDevice*:51712}"
   device-type = "disk"
   protocol = "x86_64-abi"
   backend-id = "0"
   state = "4"
   backend = "{DevicePath:/local/domain/0/backend/vbd/1/51712}"
   ring-ref = "9"
   event-channel = "117"
   feature-persistent = "1"
  51760 = ""
   virtual-device = "{VirtualDevice*:51760}"
   device-type = "disk"
   protocol = "x86_64-abi"
   backend-id = "0"
   state = "4"
   backend = "/local/domain/0/backend/vbd/1/51760"
   ring-ref = "10"
   event-channel = "118"
   feature-persistent = "1"
  51856 = ""
   virtual-device = "51856"
   device-type = "disk"
   protocol = "x86_64-abi"
   backend-id = "0"
   state = "4"
   backend = "/local/domain/0/backend/vbd/1/51856"
   ring-ref = "11"
   event-channel = "119"
   feature-persistent = "1"
  51872 = ""
   virtual-device = "51872"
   device-type = "disk"
   protocol = "x86_64-abi"
   backend-id = "0"
   state = "4"
   backend = "/local/domain/0/backend/vbd/1/51872"
   ring-ref = "12"
   event-channel = "120"
   feature-persistent = "1"
  51888 = ""
   virtual-device = "51888"
   device-type = "disk"
   protocol = "x86_64-abi"
   backend-id = "0"
   state = "4"
   backend = "/local/domain/0/backend/vbd/1/51888"
   ring-ref = "14"
   event-channel = "121"
   feature-persistent = "1"
  51904 = ""
   virtual-device = "51904"
   device-type = "disk"
   protocol = "x86_64-abi"
   backend-id = "0"
   state = "4"
   backend = "/local/domain/0/backend/vbd/1/51904"
   ring-ref = "15"
   event-channel = "122"
   feature-persistent = "1"
  51920 = ""
   virtual-device = "51920"
   device-type = "disk"
   protocol = "x86_64-abi"
   backend-id = "0"
   state = "4"
   backend = "/local/domain/0/backend/vbd/1/51920"
   ring-ref = "16"
   event-channel = "123"
   feature-persistent = "1"
  51952 = ""
   virtual-device = "51952"
   device-type = "disk"
   protocol = "x86_64-abi"
   backend-id = "0"
   state = "4"
   backend = "/local/domain/0/backend/vbd/1/51952"
   ring-ref = "18"
   event-channel = "124"
   feature-persistent = "1"
  268439552 = ""
   virtual-device-ext = "268439552"
   state = "4"
   device-type = "disk"
   protocol = "x86_64-abi"
   backend-id = "0"
   backend = "/local/domain/0/backend/vbd/1/268439552"
   ring-ref = "19"
   event-channel = "125"
   feature-persistent = "1"
  268439808 = ""
   virtual-device-ext = "268439808"
   state = "4"
   device-type = "disk"
   protocol = "x86_64-abi"
   backend-id = "0"
   backend = "/local/domain/0/backend/vbd/1/268439808"
   ring-ref = "20"
   event-channel = "126"
   feature-persistent = "1"
 vif = ""
  0 = ""
   mac = "00:21:f6:1c:2b:5a"
   handle = "0"
   protocol = "x86_64-abi"
   backend-id = "0"
   state = "4"
   backend = "/local/domain/0/backend/vif/1/0"
   tx-ring-ref = "415"
   rx-ring-ref = "416"
   event-channel = "127"
   request-rx-copy = "1"
   feature-rx-notify = "1"
   feature-sg = "1"
   feature-gso-tcpv4 = "1"
 console = ""
  0 = ""
   protocol = "x86_64-abi"
   state = "1"
   backend-id = "0"
   backend = "/local/domain/0/backend/console/1/0"
control = ""
 platform-feature-multiprocessor-suspend = "1"
error = ""
memory = ""
 target = "256000000"
guest = ""
hvmpv = ""
data = ""
console = ""
 tty = "/dev/pts/2"
 ring-ref = "34791160"
 port = "2"
 limit = "1048576"
 type = "ioemu"
 vnc-port = "5900"
 vnc-listen = "127.0.0.1"
device-misc = ""
 vif = ""
  nextDeviceID = "1"
 console = ""
  nextDeviceID = "1"
image = ""
 device-model-fifo = "/var/run/xend/dm-1-1505263975.fifo"
 device-model-pid = "13452"
 entry = "18446744071589106176"
 loader = "generic"
 hv-start-low = "18446603336221196288"
 guest-os = "linux"
 hypercall-page = "18446744071578849280"
 guest-version = "2.6"
 pae-mode = "yes"
 paddr-offset = "0"
 virt-base = "18446744071562067968"
 suspend-cancel = "1"
 features = ""
  pae-pgdir-above-4gb = "1"
  writable-page-tables = "0"
 xen-version = "xen-3.0"
cpu = ""
 3 = ""
  availability = "online"
 6 = ""
  availability = "online"
 14 = ""
  availability = "online"
 13 = ""
  availability = "online"
 11 = ""
  availability = "online"
 1 = ""
  availability = "online"
 7 = ""
  availability = "online"
 4 = ""
  availability = "online"
 15 = ""
  availability = "online"
 8 = ""
  availability = "online"
 9 = ""
  availability = "online"
 5 = ""
  availability = "online"
 0 = ""
  availability = "online"
 12 = ""
  availability = "online"
 2 = ""
  availability = "online"
 10 = ""
  availability = "online"
store = ""
 ring-ref = "34791161"
 port = "1"
description = ""
name = "0004fb0000060000c5fee5922b83ac28"
domid = "1"
serial = ""
 0 = ""
  tty = "/dev/pts/1"
"@

$BlockDeviceDetailTemplate2 = @"
domain = "{DomainID*:0004fb0000060000c5fee5922b83ac28}"
frontend = "{Frontend:/local/domain/1/device/vbd/51856}"
uuid = "102e14d2-511e-be62-94ef-51e1302edd4e"
bootable = "{Bootable:0}"
dev = "{Device:xvdj}"
state = "{State:4}"
params = "{Params:/dev/mapper/36006016020b03800f117af276337e411}"
mode = "{Mode:w}"
online = "{Online:1}"
frontend-id = "{FrontendID:1}"
type = "{Type:phy}"
physical-device = "{PhysicalDevice:fc:8}"
hotplug-status = "{HotplugStatus:connected}"
feature-flush-cache = "{FeatureFlushCache:1}"
discard-secure = "{DiscardSecure:0}"
feature-discard = "{FeatureDiscard:0}"
feature-barrier = "{FeatureBarrier:1}"
sectors = "{Sectors:3145728000}"
info = "{Info:0}"
sector-size = "{SectorSize:512}"
"@