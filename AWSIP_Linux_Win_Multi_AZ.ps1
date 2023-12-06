Start-Transcript -Path "/home/manuel/testing.log" -append -force
Write-host AWS Powershell Tools  availability check

#Set-PSDebug -Trace 2

$versions = {4,5,5.1}
#\\\\\\\\\\\\\\\\\\\\\\\\\\\\
DO 
{
    if ((($PSVersionTable).PSEdition -like "core") -and (($PSVersionTable).PSversion.Major -ge "6"))
      {
          try {
                Write-Host attempting initial import AWSPowerShell.NetCore
                Import-Module -name AWSPowerShell.NetCore -Scope  Global -force
              }
          catch  {
                    Do {
                        Write-Host installing AWSPowerShell.NetCore
                        Install-Module -name AWSPowerShell.NetCore -Scope  AllUsers -force
                        } until (((Get-Module -ListAvailable).Name) -contains "AWSPowerShell.NetCore*")
                  }
          if( (( Get-Module -ListAvailable).Name) -contains "AWSPowerShell.NetCore*")
             {write-host AWSPowerShell.NetCore Support Added}
      }


    if ((($PSVersionTable).PSEdition -like "desktop") -and (($PSVersionTable).PSversion.Major -in $versions))
      {
        try {

              Write-Host attempting initial import AWSPowerShell.NetCore
              Import-Module -name AWSPowerShell.NetCore -Scope  Global -force
            }
            catch {
                    Do{
                        Write-Host installing AWSPowerShell.NetCore
                        Install-Module -name AWSPowerShell.NetCore -Scope  AllUsers -force
                      } until (((Get-Module -ListAvailable).Name) -contains "AWSPowerShell.NetCore*")
                  }
      }


    if ((($PSVersionTable).PSEdition -like "desktop")  -and (($PSVersionTable).PSversion.Major -eq "3"))
      {

        Write-Host attempting initial import AWSPowerShell
        try {
            Import-Module -name AWSPowerShell -Scope  Global -force
            }
          catch  { Write-Host installing AWSPowerShell Module
                    Do {
                        try
                          {
                            Install-Module -name AWSPowerShell -Scope  AllUsers -force
                          }
                            catch {
                                    Do {

                                        Write-Host Getting PS-Get Module
                                        invoke-webrequest -Uri https://psg-prod-eastus.azureedge.net/packages/powershellget.2.2.5.nupkg -OutFile 'c:\temp\AWSPowerShell.zip'
                                        Expand-archive "C:\temp\AWSPowerShell.zip" "C:\temp\AWSPowerShell"
                                        Move-item "C:\temp\AWSPowerShell\PowerShellGet.psd1" "C:\Program Files\WindowsPowerShell\Modules"
                                        Import-Module -Name PowerShellGet -Scope Global -Force
                                        Update-Module -Name PowerShellGet
                                        } until (((Get-Module -ListAvailable).Name) -contains "PowerShellGet*")
                                  }

                      } until (((Get-Module -ListAvailable).Name) -contains "AWSPowerShell*")
                  }
        }
} until (((Get-Module -ListAvailable).Name) -contains "AWSPowerShell*" -or  "AWSPowerShell.NetCore*")  

#Initialize-AWSDefaultConfiguration -ProfileName aws -Scope Global
#-------------------------------------------------------------------------------------------------------------------------------

$Regions = Get-AWSRegion
Write-host $Regions
#
#
#
DO {

Foreach ($Region in $Regions)
{

Do  {

      Write-host Processing $Region
      $Instances = ((Get-EC2Instance -Region $Region).Instances.InstanceID)

          IF ($Instances -like "i-*")


             {

          #    {
                 DO {Write-host START LOG
                        Get-Date
                        #Set-PSDebug -Trace 2
                        #Start-Sleep -Seconds 120
                        Write-host Processing $Region internal


                        Write-Host "Checking OS Type"

                                  IF ($IsWindows -Like "True")

                                     {
                                                 write-host Inspecting Registry [AWSIP] registry key  [<<outer loop>>]
                                                 if(Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP')
                                                     {write-host [AWSIP] registry key is present}
                                                 else
                                                     {
                                                       New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP"
                                                       New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region"
                                                       New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\config"
                                                       $RDPGroup = New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\Config" -Name "RDPGroup" -Value "0"
                                                       $SSHGroup = New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\Config" -Name "SSHGroup" -Value "0"
                                                       $NEWRDPGroup = New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\Config" -Name "NEWRDPGroup" -Value "0"
                                                       $NEWSSHGroup = New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\\$region\Config" -Name "NEWSSHGroup" -Value "0"
                                                       $OLDIP = New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\Config" -Name "OLDIP" -Value "0"  -PropertyType "String"
                                                       $MYIP = New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\\$region\Config" -Name "MYIP" -Value "0"  -PropertyType "String"
                                                     }
                                      }

                                  IF ($IsWindows -Like "False")
                                    {

                                      if(Test-Path -Path "/var/log/AWSIP/") #always evaluates to false, needs double quotes
                                        {write-host [AWSIP] folders are present}
                                       else
                                           {

                                            New-Item -Path "/var/log" -Name "AWSIP" -ItemType "directory"
                                            New-Item -Path "/var/log/AWSIP" -Name "$Region" -ItemType "directory"
                                            New-Item -Path "/var/log/AWSIP/$Region" -Name "config" -ItemType "directory"


                                            chmod -R +0777 "/var/log/AWSIP"

                                            New-Item -Path "/var/log/AWSIP/$Region/config/" -Name "RDPGroup.log"  -ItemType "file"
                                            New-Item -Path "/var/log/AWSIP/$Region/config/" -Name "SSHGroup.log" -ItemType "file"
                                            New-Item -Path "/var/log/AWSIP/$Region/config/" -Name "NEWRDPGroup.log" -ItemType "file"
                                            New-Item -Path "/var/log/AWSIP/$Region/config/" -Name "NEWSSHGroup.log" -ItemType "file"
                                            New-Item -Path "/var/log/AWSIP/$Region/config/" -Name "OLDIP.log" -ItemType "file"
                                            New-Item -Path "/var/log/AWSIP/$Region/config/" -Name "MYIP.log" -ItemType "file"



                                            chmod -R +0777 "/var/log/AWSIP"


                                            set-content -Path  /var/log/AWSIP/$Region/config/RDPGroup.log  -Value 0
                                            set-content -Path  /var/log/AWSIP/$Region/config/SSHGroup.log  -Value 0
                                            set-content -Path  /var/log/AWSIP/$Region/config/NEWRDPGroup.log  -Value 0
                                            set-content -Path  /var/log/AWSIP/$Region/config/NEWSSHGroup.log  -Value 0
                                            set-content -Path  /var/log/AWSIP/$Region/config/OLDIP.log -Value 0
                                            set-content -Path  /var/log/AWSIP/$Region/config/MYIP.log -Value 0

                                            #needs to be checked get values from API on first run
                                            $RDPGroup = get-content -Path  /var/log/AWSIP/$Region/config/RDPGroup.log
                                            $SSHGroup = get-content -Path  /var/log/AWSIP/$Region/config/SSHGroup.log
                                            $NEWRDPGroup = get-content -Path  /var/log/AWSIP/$Region/config/NEWRDPGroup.log
                                            $NEWSSHGroup = get-content -Path  /var/log/AWSIP/$Region/config/NEWSSHGroup.log
                                            $OLDIP = get-content -Path  /var/log/AWSIP/$Region/config/OLDIP.log
                                            $MYIP = get-content -Path  /var/log/AWSIP/$Region/config/MYIP.log
                                           }
                                    }

                         #Group Check (sanity check) RDP
                           IF ((Get-EC2SecurityGroup -Region $Region -GroupName "RDP").GroupId -like "sg-*")
                                      {
                                       #Linux
                                       IF($IsWindows -Like "False")
                                         {set-content -Path  /var/log/AWSIP/$Region/config/RDPGroup.log  -Value 1}
                                       #windows
                                       IF($IsWindows -Like "True")
                                         {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\Config" -Name "RDPGroup" -Value "1"}
                                       $RDPGroup = "1"
                                      }

                                      #no need to zero values they are set to zero at creation and exit
                         #Group Check (sanity check) SSH
                           IF ((Get-EC2SecurityGroup -Region $Region -GroupName "SSH").GroupId -like "sg-*")
                                      {
                                       #Linux
                                       IF($IsWindows -Like "False")
                                         {set-content -Path  /var/log/AWSIP/$Region/config/SSHGroup.log  -Value 1}
                                       #Windows
                                       IF($IsWindows -Like "True")
                                         {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\Config" -Name "SSHGroup" -Value "1"}
                                       $SSHGroup = "1"
                                      }
                                      #no need to zero values they are set to zero at creation and exit



                         #FirstRun_Check
                         IF (($SSHGroup -and $RDPGroup -eq '0') -and ($NEWRDPGroup -and $NEWRDPGROUP -eq '0') -and ($OLDIP -and $MYIP -eq '0'))
                         {set-variable -name FIRSTRUN -value "1"} else {set-variable -name FIRSTRUN -value "0"}



                        #######
                        write-host checking current public ip      [<<outer loop>>]

                        Do  {
                             try{
                                 write-host "checking API-1"
                                 $webip = Invoke-RestMethod -Uri 'https://ip.seeip.org?format=json'
                                 }
                                 catch {
                                       write-host "checking API-2"
                                        $webip = Invoke-RestMethod -Uri 'https://api.ipify.org?format=text'
                                        }
                                        Finally{
                                               write-host "checking API-3"
                                               $webip = Invoke-RestMethod -Uri 'https://checkip.amazonaws.com?format=json'
                                               }
                             }
                        until ($webip -like "*.*")



                        $Sub = "/32"
                        $MyIP = $webip.trim()+$sub


                      IF ($IsWindows -Like "True")
                         {
                          SET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\Config" -Name "MYIP" -Value "$MYIP"
                         }   

                         IF($IsWindows -Like "False")
                              {
                               Set-content -Path  /var/log/AWSIP/$Region/config/MYIP.log -Value $MYIP
                              }



                  #///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



                           if (($RDPGROUP -eq '1') -and ($SSHGroup -eq '1'))
                               {
                                     $instances = ((Get-EC2Instance -Region $Region).Instances).InstanceID
                                           write-host Instances enumerated  [<<outer loop>>]


                                            $RDP = (Get-EC2SecurityGroup -Region $Region -GroupName "RDP").GroupId
                                            $SSH = (Get-EC2SecurityGroup -Region $Region -GroupName "SSH").GroupId

                                                    Write-host "START Instance vs SG Group evaluation"
                                                     Foreach ($instance in $instances)
                                                      {
                                                        IF(((Get-EC2Instance -Region $Region -InstanceId $instance).Instances.securitygroups.GroupName -notcontains "RDP") -or  ((Get-EC2Instance -Region $Region -InstanceId $instance).Instances.securitygroups.GroupName -notcontains "SSH"))

                                                          { write-host Evaluating Groups for instance $instance
                                                            Do
                                                              {


                                                                               if (((Get-EC2Instance -Region $Region -InstanceId $instance).Instances.securitygroups.GroupName -notcontains "SSH") -and ((Get-EC2Instance -Region $Region $instance).Instances.Platform -notcontains "Windows" ))

                                                                                  {write-host NO_SSH_GROUP LINKED TO Linux_INSTANCE $instance

                                                                                                    Do{

                                                                                                      $instanceGroups = ((Get-EC2Instance -Region $Region Attribute -InstanceId $instance -Attribute groupSet).Groups).Groupid

                                                                                                      $commandstring = ($SSH,$instanceGroups) -split ' '
                                                                                                      Edit-EC2InstanceAttribute -InstanceId $instance -Group $commandstring
                                                                                                      } until((Get-EC2Instance -Region $Region -InstanceId $instance).Instances.securitygroups.GroupName -contains "SSH")
                                                                                   }
                                                                                         if((Get-EC2Instance -Region $Region -InstanceId $instance).Instances.securitygroups.GroupName -contains "SSH") {write-host SSH-GROUP linked to $instance}






                                                                                 if (((Get-EC2Instance -Region $Region -InstanceId $instance).Instances.securitygroups.GroupName -notcontains "RDP") -and  ((Get-EC2Instance -Region $Region $instance).Instances.Platform -contains "Windows" ))

                                                                                 {write-host NO_RDP_GROUP LINKED TO Windows_INSTANCE $instance      [>>inner loop<<]

                                                                             Do{

                                                                                          $instanceGroups = ((Get-EC2Instance -Region $RegionAttribute -InstanceId $instance -Attribute groupSet).Groups).Groupid

                                                                                          $commandstring = ($RDP,$instanceGroups) -split ' '

                                                                                          Edit-EC2InstanceAttribute -InstanceId $instance -Group $commandstring
                                                                      } until((Get-EC2Instance -Region $Region -InstanceId $instance).Instances.securitygroups.GroupName -contains "RDP")
                                                                          }
                                                                     if((Get-EC2Instance -Region $Region -InstanceId $instance).Instances.securitygroups.GroupName -contains "RDP") {write-host RDP-GROUP linked to $instance}


                                                             } until (((Get-EC2Instance -Region $Region -InstanceId $instance).Instances.securitygroups.GroupName -contains "RDP") -or ((Get-EC2Instance -Region $Region -InstanceId $instance).Instances.securitygroups.GroupName -contains "SSH"))
                                                               write-host "END Instance vs Group remediation"   [>>inner loop<<]

                                                          } write-host "END Instance vs Group evaluation" $instance    [>>inner loop<<]
                                                      }

                               }




                                           #OS Check:
                                        IF ($IsWindows -Like "True")

                                           {
                                             If ($FirstRun -eq '0')
                                                {$OLDIP = (GET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\Config" -Name "OLDIP").OLDIP}
                                                IF(($MYIP -ne $OLDIP) -and ($MYIP -ne "0") -and ($OLDIP -ne "0"))

                                                {write-host IP ADDRESSES out of SYNC!!!!! [outer loop]} elseif
                                                (($MYIP -eq $OLDIP) -and ($MYIP -ne "0")-and($OLDIP -ne "0"))
                                                {write-host IP ADDRESSES IN SYNC [<<outer loop>>]}
                                           }
                                        
                                           IF($IsWindows -Like "False")
                                            {
                                               $OLDIP = (get-content -Path  /var/log/AWSIP/$Region/config/OLDIP.log)
                                               IF(($MYIP -ne $OLDIP) -and ($MYIP -ne "0")-and($OLDIP -ne "0"))

                                               {write-host IP ADDRESSES out of SYNC!!!!! [outer loop]} elseif
                                               (($MYIP -eq $OLDIP) -and ($MYIP -ne "0")-and($OLDIP -ne "0"))
                                               {write-host IP ADDRESSES IN SYNC [<<outer loop>>]}
                                            }



                                       IF($IsWindows -Like "True")
                                           {

                                            $RDPGROUP = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\Config" -name "RDPGroup").RDPGROUP
                                            $SSHGROUP = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\Config" -name "SSHGroup").SSHGROUP
                                           }
                                         
                                       IF($IsWindows -Like "False")
                                          {

                                            $SSHGroup = (get-content -Path  /var/log/AWSIP/$Region/config/SSHGroup.log)
                                            $RDPGroup = (get-content -Path  /var/log/AWSIP/$Region/config/RDPGroup.log)
                                          }

                                       #
                                        If (($RDPGroup -or $SSHGroup -eq '0') -or ($FIRSTRUN -eq '1'))
                                         {

                                                     DO
                                                      {
                                                                        DO
                                                                         {
                                                                         Try
                                                                         {
                                                                         $OLDRDPGroup = (Get-EC2SecurityGroup -Region $Region -GroupName RDP).GroupId
                                                                         }
                                                                         Catch
                                                                         {
                                                                         write-host RDP GROUP DOES NOT EXIST,Creating.............[RDP Group Creation loop] [>>Inner loop<<]
                                                                         $NEWRDPGroup = New-EC2SecurityGroup -Region $Region -GroupName RDP -Description "Windows remote Access"
                                                                         }
                                                                         finally
                                                                         {
                                                                         if ($NEWRDPGroup -like "sg-*")
                                                                         {write-host  RDP Group Exists [RDP Group Creation loop]  [>>Inner loop<<]}
                                                                          }


                                                                         }until (($NEWRDPGroup -like "sg-*") -or ($OLDRDPGroup -like "sg-*"))


                                                                        DO
                                                                         {
                                                                          Try
                                                                           {
                                                                             $OLDSSHGroup = (Get-EC2SecurityGroup -Region $Region -GroupName SSH).GroupId
                                                                           }
                                                                          Catch
                                                                           {
                                                                             write-host SSH GROUP DOES NOT EXIST,Creating.............[SSH Group Creation loop] [>>Inner loop<<]
                                                                             $NEWSSHGroup = New-EC2SecurityGroup -Region $Region -GroupName SSH -Description "Linux remote Access"
                                                                           }
                                                                           finally
                                                                           {
                                                                             if ($NEWSSHGroup -like "sg-*")
                                                                                {write-host  SSH Group Exists. [SSH Group Creation loop]  [>>Inner loop<<]}
                                                                           }

                                                                         }until (($NEWSSHGroup -like "sg-*") -or ($OLDSSHGroup -like "sg-*"))

                                                      } until ((($NEWRDPGroup -like "sg-*") -and ($NEWSSHGroup -like "sg-*")) -or (($OLDRDPGroup -like "sg-*") -and ($OLDSSHGroup -like "sg-*")))
                                        #




                                                     #Start Paranoia  (Group existence)

                                                    #Windows:
                                                     IF ($IsWindows -Like "True")
                                                            
                                                             {
                                                              IF  ((($OLDSSHGroup -like "sg-*") -or ($NEWSSHGroup -like "sg-*")) -and (Get-EC2SecurityGroup -Region $Region -GroupName "SSH").GroupId -like "sg-*")
                                                                  {SET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\Config" -Name "SSHGroup" -Value "1"}
                                                              IF  ($NEWSSHGroup -like "sg-*")
                                                                  {SET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\Config" -Name "NEWSSHGroup" -Value "1"}


                                                              IF  ((($OLDRDPGroup -like "sg-*") -or ($NEWRDPGroup -like "sg-*")) -and (Get-EC2SecurityGroup -Region $Region -GroupName "RDP").GroupId -like "sg-*")
                                                                  {SET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\Config" -Name "RDPGroup" -Value "1"}
                                                                  IF  ($NEWRDPGroup -like "sg-*")
                                                                  {SET-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\Config" -Name "NEWRDPGroup" -Value "1"}
                                                             }       
                                                                          
                                                                        #Linux:
                                                                        IF ($IsWindows -Like "False")

                                                                          {
                                                                            IF ((($OLDSSHGroup -like "sg-*") -or ($NEWSSHGroup -like "sg-*")) -and (Get-EC2SecurityGroup -Region $Region -GroupName "SSH").GroupId -like "sg-*")
                                                                                {$SSHGroup = set-content -Path  /var/log/AWSIP/$Region/config/SSHGroup.log  -Value "1"} else
                                                                                {$SSHGroup = set-content -Path  /var/log/AWSIP/$Region/config/SSHGroup.log  -Value "0"}
                                                                            IF  ($NEWSSHGroup -like "sg-*")
                                                                                {$NEWSSHGroup = set-content -Path  /var/log/AWSIP/$Region/config/NEWSSHGroup.log  -Value "1"}


                                                                            IF ((($OLDRDPGroup -like "sg-*") -or ($NEWRDPGroup -like "sg-*")) -and (Get-EC2SecurityGroup -Region $Region -GroupName "RDP").GroupId -like "sg-*")
                                                                                {$RDPGroup = set-content -Path  /var/log/AWSIP/$Region/config/RDPGroup.log  -Value "1"} else
                                                                                {$RDPGroup = set-content -Path  /var/log/AWSIP/$Region/config/RDPGroup.log  -Value "0"}

                                                                            IF ($NEWRDPGroup -like "sg-*")
                                                                               {$NEWRDPGroup = set-content -Path  /var/log/AWSIP/$Region/config/NEWRDPGroup.log  -Value "1"}
                                                                          }
                                         }             #END Paranoia  (Group existence)

                                      #///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


                                                    #Start Set Variables
                                                     If ($IsWindows -Like "True")
                                                        {

                                                         $RDPGROUP = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\Config" -name "RDPGroup").RDPGroup
                                                         $SSHGROUP = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\Config" -name "SSHGroup").SSHGroup
                                                         $NEWRDPGROUP = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\Config" -name "NEWRDPGroup").NEWRDPGroup
                                                         $NEWSSHGROUP = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\Config" -name "NEWSSHGroup").NEWSSHGroup
                                                         $RDP = (Get-EC2SecurityGroup -Region $Region -GroupName "RDP").GroupId
                                                         $SSH = (Get-EC2SecurityGroup -Region $Region -GroupName "SSH").GroupId
                                                         $OLDIP = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\Config" -name "OLDIP").OLDIP
                                                        }           
                                                               IF ($IsWindows -Like "False")
                                                                    {

                                                                     $RDPGroup = get-content -Path  /var/log/AWSIP/$Region/config/RDPGroup.log
                                                                     $SSHGroup = get-content -Path  /var/log/AWSIP/$Region/config/SSHGroup.log
                                                                     $NEWRDPGroup = get-content -Path  /var/log/AWSIP/$Region/config/NEWRDPGroup.log
                                                                     $NEWSSHGroup = get-content -Path  /var/log/AWSIP/$Region/config/NEWSSHGroup.log
                                                                     $RDP = (Get-EC2SecurityGroup -Region $Region -GroupName "RDP").GroupId
                                                                     $SSH = (Get-EC2SecurityGroup -Region $Region -GroupName "SSH").GroupId
                                                                     $OLDIP = get-content -Path  /var/log/AWSIP/$Region/config/OLDIP.log
                                                                    }
                                                    #END Set Variables



                                           # Grant Permissions
                                                       IF ((($OLDIP -ne $MYIP) -and ($NEWRDPGroup -eq "1")) -or ($FIRSTRUN -eq '1') )
                                                                  {
                                                                  Write-host NEW Groups Adding Permssions
                                                                  $ip1 = @{ IpProtocol="tcp"; FromPort="22"; ToPort="22"; IpRanges="$MYIP"}
                                                                  $ip2 = @{ IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges="$MYIP"}
                                                                  Grant-EC2SecurityGroupIngress -Region $Region -GroupID $SSH -IpPermission @( $ip1 )
                                                                  Grant-EC2SecurityGroupIngress -Region $Region -GroupID $RDP -IpPermission @( $ip2 )
                                                                  }
                                                                    elseif
                                           # Revoke Permissions
                                                                          (($OLDIP -ne $MYIP) -and ($RDPGROUP -eq "1") -and ($FIRSTRUN -eq '0'))
                                                                                {
                                                                                Write-host Groups Exist  Removing Old Permissions before Adding Permissions
                                                                                $ip1 = @{ IpProtocol="tcp"; FromPort="22"; ToPort="22"; IpRanges="$OLDIP"}
                                                                                $ip2 = @{ IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges="$OLDIP"}
                                                                                Revoke-EC2SecurityGroupIngress -Region $Region -GroupID $SSH -IpPermission @( $ip1 )
                                                                                Revoke-EC2SecurityGroupIngress -Region $Region -GroupID $RDP -IpPermission @( $ip2 )
                                                                                #
                                                                                Write-host Adding Permissions After Removal
                                                                                $ip1 = @{ IpProtocol="tcp"; FromPort="22"; ToPort="22"; IpRanges="$MYIP"}
                                                                                $ip2 = @{ IpProtocol="tcp"; FromPort="3389"; ToPort="3389"; IpRanges="$MYIP"}
                                                                                Grant-EC2SecurityGroupIngress -Region $Region -GroupID $SSH -IpPermission @( $ip1 )
                                                                                Grant-EC2SecurityGroupIngress -Region $Region -GroupID $RDP -IpPermission @( $ip2 )
                                                                                }
                                           # END Permissions



                                           # Set Variables and Values  for New Groups before exiting pass
                                                           IF   ($IsWindows -Like "True")
                                                                   {

                                                                        If ($RDPGroup -eq '1' -and $SSHGRoup -eq '1' -and $FirstRun -eq '0')
                                                                        {
                                                                         Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\Config" -Name "NEWRDPGroup" -Value "0"
                                                                         Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AWSIP\$region\Config" -Name "NEWSSHGroup" -Value "0"
                                                                         Set-Variable -name NEWRDPGroup -Value '0'
                                                                         Set-Variable -name NEWSSHGroup -Value '0'
                                                                        }
                                                                   }                
                                                                           IF ($IsWindows -Like "False")
                                                                                    {
                                                                                      if($RDPGroup -eq '1' -and $SSHGRoup -eq '1' -and $FirstRun -eq '0')
                                                                                       {
                                                                                        set-content -Path  /var/log/AWSIP/$Region/config/NEWRDPGroup.log  -Value '0'
                                                                                        set-content -Path  /var/log/AWSIP/$Region/config/NEWSSHGroup.log  -Value '0'
                                                                                        Set-Variable -name NEWRDPGroup -Value '0'
                                                                                        Set-Variable -name NEWSSHGroup -Value '0'
                                                                                       }

                                                                                    }
                       $Region = "complete"   #Required to escape the loop         #End of Normal Run , Clear Variables .
                       #Clear The Variables , one pass per region .
                       Clear-Variable -Name Instance
                       Clear-Variable -Name Instances
                       Clear-Variable -Name RDP
                       Clear-Variable -Name SSH
                       Clear-Variable -Name SSHGroup
                       Clear-Variable -Name RDPGroup
                       Clear-Variable -Name NEWSSHGroup
                       Clear-Variable -Name NEWSSHGroup

                       } until ($Region = "complete")  #Required to escape the loop





             }

                         ELSE {write-host Region $Region skipped
                              $Region = "skipped"   #Mark Skipped Region
                              }



    }  until ($Region -like "skipped")



  }

} until ($Process -eq "0") #Condition is never met , so IT NEVER ENDS  HAHHAHAHAHAHAHAAHAH!!

#//////////////////////////////////\\\\\\\\\\\\\\\\\\\//////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\////////////////////////////\\\\\\\\\





