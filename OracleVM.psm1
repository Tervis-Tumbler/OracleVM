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
        ComputerName = $OracleVMCLIPasswordstateEntry.URL
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
"@
    $OVMPhysicalDiskList = (Get-OVMPhysicalDiskList -Credential $credential -ComputerName $Computername -Port $Port)
    $OVMPhysicalDiskList | % {
        $SCRIPTCommand += "show physicaldisk id=$($_.OVMDiskID);"
    }
    $SSHSession = New-SSHSession -Credential $credential -ComputerName $Computername -Port $Port -AcceptKey
    $Output = $(Invoke-SSHCommand -SSHSession $(get-sshsession) -Command $SCRIPTCommand).Output
    Remove-SSHSession $SSHSession | Out-Null
#    $PhysicalDiskDetailList = $output -replace "`r", "" | ConvertFrom-String -TemplateContent $OVMShowPhysicalDiskTemplate
    $output -replace "`r", "" | ConvertFrom-String -TemplateContent $OVMShowPhysicalDiskTemplate
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

    $OVMVMDiskMappingList = Get-OVMVMDiskMappingList -Credential $credential -ComputerName $Computername -Port $Port
    $OVMVMDiskMappingList | %{
        $SCRIPTCommand += "show vmdiskmapping id=$($_.OVMDiskID);"
    }
    $SSHSession = New-SSHSession -Credential $credential -ComputerName $Computername -Port $Port -AcceptKey
    $Output = $(Invoke-SSHCommand -SSHSession $(get-sshsession) -Command $SCRIPTCommand).Output
    Remove-SSHSession $SSHSession | Out-Null
   
    
        $MappedVMDisklist = @()
        $Output = $Output.split("`n")
        $Output = $Output[0..($Output.Count - 2)]
    do{
        $CurrentDiskMapping = $Output[0..10]
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
        $Output = $Output[11..($Output.count)]
    }While($Output)

    ForEach ($MappedVMDisk in $MappedVMDisklist){
            ForEach ($Entry in $OVMPhysicalDiskDetailList){
                if($Entry.DiskID -like "*$($MappedVMDisk.DiskID)"){
                     $MappedVMDisk | Add-Member Size $Entry.Size
                     $MappedVMDisk | Add-Member SANID $Entry.SANID
                }
            }
            if(!$MappedVMDisk.SANID){
                $MappedVMDisk | Add-Member Size "NA"
                $MappedVMDisk | Add-Member SANID "NA"
                }
    }    
    $MappedVMDisklist
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

    $OVMPhysicalDiskDetailList = Get-OVMPhysicalDiskDetails -Credential $credential -ComputerName $Computername -Port $Port
    $OVMVMDiskMappingDetails = Get-OVMVMDiskMappingDetails -Credential $credential -ComputerName $Computername -Port $Port
    ForEach ($PhysicalDisk in $OVMPhysicalDiskDetailList){
        if($OVMVMDiskMappingDetails.DiskName -notcontains $PhysicalDisk.DiskName){
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