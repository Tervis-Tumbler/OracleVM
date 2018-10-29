$ModulePath = (Get-Module -ListAvailable OracleVM).ModuleBase
. $ModulePath\OracleVMStringTemplates.ps1

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
    param(
        [switch]$IncludePlainText
    )
    $OracleVMCLIPasswordstateEntry = Get-PasswordstatePassword -ID "4157"
    $OVMCLIConnectionInformation = [pscustomobject][ordered]@{
        ComputerName = ([System.Uri]$OracleVMCLIPasswordstateEntry.URL).host
        Port = $OracleVMCLIPasswordstateEntry.GenericField1
        Credential = Get-PasswordstatePassword -ID "4157" -AsCredential
    }
    if($IncludePlainText){
        $OVMCLIConnectionInformation | Add-Member -MemberType NoteProperty -Name Username -Value $($OracleVMCLIPasswordstateEntry.username) -PassThru |
        Add-Member -MemberType NoteProperty Password -Value $($OracleVMCLIPasswordstateEntry.password)
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


function set-TervisOracleODBEEServerConfiguration{
    Param(
        [Parameter(Mandatory)]
        $Computername
    )
    $FQDN = $Computername + ".tervis.prv"
    $OracleLinuxDefaultRootCredential = Get-PasswordstatePassword -ID "4040" -AsCredential
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
        [parameter(Mandatory,ValueFromPipelineByPropertyName)]$Computername,
        [parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        $Domain
    )
    $XMListTemplate = @"
Name                                        ID   Mem VCPUs      State   Time(s)
{DomainID*:0004fb0000060000c5fee5922b83ac28}             {ID:1} 250000    16     r----- 5447521.2
Domain-0                                     0  3152    20     r----- 259938.1
"@
    $SSHCommand = "xm list $Domain"
    $CommandOutput = Invoke-SSHCommand -SSHSession $SshSessions -Command $SSHCommand
    $CommandOutput.output | ConvertFrom-String -TemplateContent $XMListTemplate     
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

function Install-OVMTemplatePackages{
    rm -F /etc/yum.repos.d/public-yum-ol7.repo
    curl -o /etc/yum.repos.d/public-yum-ol7.repo http://public-yum.oracle.com/public-yum-ol7.repo
    sed -i -e '/\[ol7_addons\]/,/^\[/s/enabled=0/enabled=1/' /etc/yum.repos.d/public-yum-ol7.repo
    yum -y install ovmd xenstoreprovider python-simplejson ovm-template-config ovm-template-config-authentication ovm-template-config-network
    systemctl enable ovmd.service
    systemctl enable ovm-template-initial-config.service
    systemctl start ovmd.service
}

function Invoke-OVMPrepareTemplateVMForFirstBoot{
    ovmd -s cleanup
    sed -i 's/^INITIAL_CONFIG=.*/INITIAL_CONFIG=yes/g' /etc/sysconfig/ovm-template-initial-config
    ###Shutdown###
}

function Add-NodeOracleVMProperty {
    param (
        [Parameter(ValueFromPipeline)]$Node,
        [Switch]$PassThru
    )
    process {
        $Node | Add-Member -MemberType NoteProperty -Name VM -PassThru:$PassThru -Force -Value $(
            Get-OVMVirtualMachines -Name $Node.ComputerName
        )        
    }
}

function Add-NodeOracleIPAddressProperty {
    param (
        [Parameter(ValueFromPipeline)]$Node,
        [Switch]$PassThru
    )
    process {
        $Node | Add-Member -MemberType ScriptProperty -Force -Name IPAddress -Value {
            $VirtualNIC = Get-OVMVirtualNic -VirtualNicID $This.VM.virtualnicids.value
            $MacAddress = Get-OVMVirtualNicMacAddress -VirtualNicID $VirtualNIC.id.value
            $VMNetworkMacAddress = ($MacAddress -replace ':', '-')
            Find-DHCPServerv4LeaseIPAddress -MACAddressWithDashes $VMNetworkMacAddress -AsString
        }
        if ($PassThru) { $Node }
    }
}

function Remove-TervisOracleVM {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, ValueFromPipeline)]$VM,
        [Switch]$DeleteVirtualDisks
    )
    process {
        $VirtualNIC = Get-OVMVirtualNic -VirtualNicID $vm.virtualnicids.value
        $MacAddress = Get-OVMVirtualNicMacAddress -VirtualNicID $VirtualNIC.id.value
        $VMNetworkMacAddress = ($MacAddress -replace ':', '-')
        $VM.ID | Stop-OVMVirtualMachine
        Remove-TervisDHCPReservationAndLease -MacAddressWithDashes $VMNetworkMacAddress
        Remove-TervisDNSRecord -ComputerName $VM.Name
        Remove-TervisADComputerObject -ComputerName $VM.Name

#        if ($DeleteVHDs) {
#            Invoke-Command -ComputerName $VM.ComputerName -ScriptBlock {
#                $Using:VM.Name | 
#                Get-VMHardDiskDrive | 
#                Remove-Item -Confirm
#            }
#        }
        if($DeleteVirtualDisks){
            $VM | Remove-OVMVirtualMachine -DeleteVirtualDisks    
        }
        else{
            $VM | Remove-OVMVirtualMachine
        }
        Remove-TervisApplicationNodeRDMSession -ComputerName $VM.Name

    }
}

function Set-TervisDHCPForOracleVM {
    param(
        [parameter(Mandatory, ValueFromPipeline)]$VM,
        [Parameter(Mandatory)]$DHCPScope,
        [switch]$PassThru
    )
    $VirtualNIC = Get-OVMVirtualNic -VirtualNicID $vm.virtualnicids.value
    $MacAddress = Get-OVMVirtualNicMacAddress -VirtualNicID $VirtualNIC.id.value
    $VMNetworkMacAddress = ($MacAddress -replace ':', '-')
    $DHCPServerName = Get-DhcpServerInDC | select -First 1 -ExpandProperty DNSName
    $FreeIPAddress = $DHCPScope | Get-DhcpServerv4FreeIPAddress -ComputerName $DHCPServerName
    $DHCPScope | Add-DhcpServerv4Reservation -ClientId $VMNetworkMacAddress -ComputerName $DHCPServerName -IPAddress $FreeIPAddress -Name $VM.Name -Description $VM.Name

    if($PassThru) {$VM}
}

function Invoke-OVMVMControlOnRemoteServer{
    param(
        [parameter(Mandatory)]$VMName,
        [parameter(Mandatory)]$Command,
        [parameter(Mandatory)]$CPUThreadList,
        [parameter(Mandatory)]$SSHSession
    )
    $OracleVMAdminPasswordstateDetails = Get-PasswordstatePassword -ID 4157
    $SSHCommand = "ovm_vmcontrol -username $($OracleVMAdminPasswordstateDetails.Username) -p $($OracleVMAdminPasswordstateDetails.Password)  "
    
    Invoke-SSHCommand -SSHSession $SSHSession -Command $SSHCommand
#    ovm_vmcontrol { -u username } [ -p password | -E ] { -h hostname } { -c command } { -v vm_name | -U vm_uuid } [ -s cpu_thread_list ... ]


}

Function Set-OVMVirtualMachineConfigurationFromDefinition{
    param(
        [parameter(ValueFromPipelineByPropertyName,mandatory)]$Computername,
        [switch]$ASync
    )
    process{
        $VM = Get-OVMVirtualMachines -Name $Computername
        $VMDefinition = Get-OracleServerDefinition -Computername $Computername
        $OVMServerNodeCredential = Find-PasswordstatePassword -Search "Oracle VM Cluster Node Root" -AsCredential
        $SshSession = New-SSHSession -ComputerName $($VM.serverId.name) -Credential $OVMServerNodeCredential
        Set-OVMVirtualMachineResourcesCPU -VMID $VM.id.value -CPUCount $VMDefinition.CPUCount -CPUCountLimit $VMDefinition.CPUCountLimit
        Set-OVMVirtualMachineResourcesMemory -VMID $VM.id.value -Memory $VMDefinition.Memory -MemoryLimit $VMDefinition.MemoryLimit
        Set-OVMVirtualMachineCPUPinning -VMID $VM.id.value -CPUs $VMDefinition.PinnedCPUs -SSHSession $SshSession
        Remove-SSHSession -SSHSession $SshSession
    }
}

function Get-XenPMGetCPUTopology {
    param (
        [Parameter(Mandatory)]$Computername,
        [Parameter(Mandatory)]$SSHSession
    )
    $XenPMGetCpuTopologyCommand = "xenpm get-cpu-topology"
    $XenPMGetCPUTopologyOutput = (Invoke-SSHCommand -Command $XenPMGetCpuTopologyCommand -SSHSession $SshSession).output
    $XenPMGetCPUTopologyOutput | ConvertFrom-String -TemplateContent $XenPMGetCpuTopologyStringTemplate
}

function Invoke-OVMVCPUList {
    param(
        [parameter(Mandatory,ValueFromPipelineByPropertyName)]$Computername,
        [parameter(Mandatory,ValueFromPipelineByPropertyName)]$SSHSession,
        $Domain
    )
    $SSHCommand = "xm vcpu-list $Domain"
    $CommandOutput = Invoke-SSHCommand -SSHSession $SshSessions -Command $SSHCommand
    $CommandOutput.Output | ConvertFrom-String -PropertyNames Name,ID,VCPU,CPU,State,Time,"CPU Affinity"
    #    $CommandOutput.output | ConvertFrom-String -TemplateContent $XMListTemplate     
}
