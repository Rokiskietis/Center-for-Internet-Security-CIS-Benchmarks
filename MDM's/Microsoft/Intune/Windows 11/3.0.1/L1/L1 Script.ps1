# Ensure Microsoft Graph is installed
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
}

# Predefined OMA-URIs for IG Levels
$IGLevels = @{
    "IG 1" = @(
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventEnablingLockScreenCamera"; 
            "value" = "<enabled/>"; 
            "dataType" = "String"; 
            "desc" = "Prevent enabling lock screen camera" 
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventLockScreenSlideShow"; 
            "value" = "<enabled/>"; 
            "dataType" = "String"; 
            "desc" = "Prevent enabling lock screen slide show" 
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ApplyUACRestrictionsToLocalAccountsOnNetworkLogon"; 
            "value" = "<enabled/>"; 
            "dataType" = "String"; 
            "desc" = "Apply UAC restrictions to local accounts on network logons" 
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPv6SourceRoutingProtectionLevel"; 
            "value" = '<enabled/><data id="DisableIPSourceRoutingIPv6" value="2"/>'; 
            "dataType" = "String"; 
            "desc" = "IPv6 source routing protection level"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPSourceRoutingProtectionLevel"; 
            "value" = '<enabled/><data id="DisableIPSourceRouting" value="2"/>'; 
            "dataType" = "String"; 
            "desc" = "IP source routing protection level"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/AllowICMPRedirectsToOverrideOSPFGeneratedRoutes"; 
            "value" = '<disabled/>'; 
            "dataType" = "String"; 
            "desc" = "Allow ICMP redirects to override OSPF generated routes"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/AllowTheComputerToIgnoreNetBIOSNameReleaseRequestsExceptFromWINSServers"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Allow the computer to ignore NetBIOS name release requests except from WINS servers"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_MSS-legacy/Pol_MSS_ScreenSaverGracePeriod"; 
            "value" = '<enabled/><data id="ScreenSaverGracePeriod" value="5"/>'; 
            "dataType" = "String"; 
            "desc" = "The time in seconds before the screen saver grace period expires 5 or fewer seconds"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_MSS-legacy/Pol_MSS_WarningLevel"; 
            "value" = '<enabled/><data id="WarningLevel" value="90"/>'; 
            "dataType" = "String"; 
            "desc" = "Percentage threshold for the security event log at which the system will generate a warning"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/Connectivity/ProhibitInstallationAndConfigurationOfNetworkBridge"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Prohibit installation and configuration of Network Bridge on your DNS domain network"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_NetworkConnections/NC_ShowSharedAccessUI"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Prohibit use of Internet Connection Sharing on your DNS domain network"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_NetworkConnections/NC_StdDomainUserSetLocation"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Require domain users to elevate when setting a network's location"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/Connectivity/HardenedUNCPaths"; 
            "value" = '<enabled/><data id="Pol_HardenedPaths" value="\\NETLOGONRequireMutualAuthentication=1,RequireIntegrity=1\\SYSVOLRequireMutualAuthentication=1,RequireIntegrity=1"/>'; 
            "dataType" = "String"; 
            "desc" = "Hardened UNC Paths"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_WCM/WCM_MinimizeConnections"; 
            "value" = '<enabled/><data id="WCM_MinimizeConnections_Options" value="3"/>'; 
            "dataType" = "String"; 
            "desc" = "Minimize the number of simultaneous connections to the Internet or a Windows Domain"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/WindowsConnectionManager/ProhitConnectionToNonDomainNetworksWhenConnectedToDomainAuthenticatedNetwork"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Prohibit connection to non-domain networks when connected to domain authenticated network"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/WirelessDisplay/RequirePinForPairing"; 
            "value" = '1'; 
            "dataType" = "Integer"; 
            "desc" = "Require PIN pairing"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_Printing2/RegisterSpoolerRemoteRpcEndPoint"; 
            "value" = '<disabled/>'; 
            "dataType" = "String"; 
            "desc" = "Allow Print Spooler to accept client connections"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/Printers/PointAndPrintRestrictions"; 
            "value" = '<data id="PointAndPrint_TrustedServers_Chk" value="false"/><data id="PointAndPrint_TrustedServers_Edit" value=""/><data id="PointAndPrint_TrustedForest_Chk" value="false"/><data id="PointAndPrint_NoWarningNoElevationOnInstall_Enum" value="0"/><data id="PointAndPrint_NoWarningNoElevationOnUpdate_Enum" value="0"/'; 
            "dataType" = "String"; 
            "desc" = "Point and Print Restrictions: When updating or installg drivers for an existing connection"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/WindowsLogon/DisableLockScreenAppNotifications"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Turn off toast notifications on the lock screen (User)"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_CredSsp/AllowEncryptionOracle"; 
            "value" = '<enabled/><data id="AllowEncryptionOracleDrop" value="0"/>'; 
            "dataType" = "String"; 
            "desc" = "Encryption Oracle Remediation"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_GroupPolicy/CSE_Registry"; 
            "value" = '<enabled/><data id="CSE_NOBACKGROUND10" value="false"/>'; 
            "dataType" = "String"; 
            "desc" = "Configure security policy processing"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_GroupPolicy/DisableBackgroundPolicy"; 
            "value" = '<disabled/>'; 
            "dataType" = "String"; 
            "desc" = "Turn off background refresh of Group Policy"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_Logon/BlockUserFromShowingAccountDetailsOnSignin"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Block user from showing account details on sign-in"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/WindowsLogon/DontDisplayNetworkSelectionUI"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Do not display network selection UI"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_Logon/DontEnumerateConnectedUsers"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Do not enumerate connected users on domain-joined computers"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/WindowsLogon/EnumerateLocalUsersOnDomainJoinedComputers"; 
            "value" = '<disabled/>'; 
            "dataType" = "String"; 
            "desc" = "Enumerate local users on domain-joined computers"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/Autoplay/DisallowAutoplayForNonVolumeDevices"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Disallow Autoplay for non-volume devices"
         }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/Autoplay/SetDefaultAutoRunBehavior"; 
            "value" = '<enabled/><data id="NoAutorun_Dropdown" value="1"/>'; 
            "dataType" = "String"; 
            "desc" = "Default behavior for AutoRun: Do not execute any autorun commands"
         }
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/Autoplay/TurnOffAutoPlay"; 
            "value" = '<enabled/><data id="Autorun_Box" value="255"/>'; 
            "dataType" = "String"; 
            "desc" = "Turn off Autoplay on All drives"
         }
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/CredentialsUI/DisablePasswordReveal"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Do not display the password reveal button"
         }
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/CredentialsUI/EnumerateAdministrators"; 
            "value" = '<disabled/>'; 
            "dataType" = "String"; 
            "desc" = "Enumerate administrator accounts on elevation"
         }
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_CredUI/NoLocalPasswordResetQuestions"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Prevent the use of security questions for local accounts"
         }
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_Log_AutoBackup_1"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Control Event Log behavior when the log file reaches its maximum size"
         }
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/EventLogService/SpecifyMaximumFileSizeApplicationLog"; 
            "value" = '<enabled/><data id="Channel_LogMaxSize" value="102400"/>'; 
            "dataType" = "String"; 
            "desc" = "Specify the maximum log file size (KB) Enabled: 32,768 or greater"
         }
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_Log_AutoBackup_2"; 
            "value" = '<disabled/>'; 
            "dataType" = "String"; 
            "desc" = "Control Event Log behavior when the log file reaches its maximum size"
         }
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/EventLogService/SpecifyMaximumFileSizeSecurityLog"; 
            "value" = '<enabled/><data id="Channel_LogMaxSize" value="2097152"/>'; 
            "dataType" = "String"; 
            "desc" = "Specify the maximum log file size (KB) Enabled: 196,608 or greater"
         } 
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_Log_AutoBackup_3"; 
            "value" = '<disabled/>'; 
            "dataType" = "String"; 
            "desc" = "Control Event Log behavior when the log file reaches its maximum size"
         }   
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_LogMaxSize_3"; 
            "value" = '<enabled/><data id="Channel_LogMaxSize" value="102400"/>'; 
            "dataType" = "String"; 
            "desc" = "Specify the maximum log file size (KB) Enabled: 32,768 or greater"
         }  
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_Log_AutoBackup_4"; 
            "value" = '<disabled/>'; 
            "dataType" = "String"; 
            "desc" = "Control Event Log behavior when the log file reaches its maximum size"
         }  
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/EventLogService/SpecifyMaximumFileSizeSystemLog"; 
            "value" = '<enabled/><data id="Channel_LogMaxSize" value="204800"/>'; 
            "dataType" = "String"; 
            "desc" = "Specify the maximum log file size (KB) Enabled: 32,768 or greater"
         }      
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_MSAPolicy/MicrosoftAccount_DisableUserAuth"; 
            "value" = '<enabled/><data id="Channel_LogMaxSize" value="204800"/>'; 
            "dataType" = "String"; 
            "desc" = "Block all consumer Microsoft account user authentication"
         } 
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_MicrosoftDefenderAntivirus/DisableAntiSpywareDefender"; 
            "value" = '<disabled/>'; 
            "dataType" = "String"; 
            "desc" = "Turn off Microsoft Defender Antivirus: Disabled"
         } 
         @{ 
            "omaUri" = "./User/Vendor/MSFT/Policy/Config/ADMX_Sharing/NoInplaceSharing"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Prevent users from sharing files within their profile"
         } 
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/DoNotAllowPasswordSaving"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Do not allow passwords to be saved"
         } 
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_TerminalServer/TS_SESSIONS_Idle_Limit_2"; 
            "value" = '<enabled/><data id="TS_SESSIONS_IdleLimitText" value="900000"/>'; 
            "dataType" = "String"; 
            "desc" = "RDP: Time limit for active but idle Remote Desktop Services sessions Enabled 15 minutes"
         } 
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_TerminalServer/TS_SESSIONS_Disconnected_Timeout_2"; 
            "value" = '<enabled/><data id="TS_SESSIONS_EndDisconnected" value="60000"/>'; 
            "dataType" = "String"; 
            "desc" = "RDP: Set time limit for disconnected sessions Enabled 1 minute"
         } 
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_TerminalServer/TS_TEMP_DELETE"; 
            "value" = '<disabled/>'; 
            "dataType" = "String"; 
            "desc" = "Do not delete temp folders upon exit"
         }                   
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/WindowsLogon/AllowAutomaticRestartSignOn"; 
            "value" = '<disabled/>'; 
            "dataType" = "String"; 
            "desc" = "Sign-in and lock last interactive user automatically after a restart"
         } 
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/Audit/ObjectAccess_AuditFileShare"; 
            "value" = '3'; 
            "dataType" = "Integer"; 
            "desc" = "Audit File Share Access: Success and Failure "
         } 
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/Audit/ObjectAccess_AuditDetailedFileShare"; 
            "value" = '2'; 
            "dataType" = "Integer"; 
            "desc" = "Object Access Audit Detailed File Share: Failure"
         } 
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/Defender/AllowEmailScanning"; 
            "value" = '1'; 
            "dataType" = "Integer"; 
            "desc" = "Allow Email Scanning"
         }      
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/Defender/AllowFullScanRemovableDriveScanning"; 
            "value" = '1'; 
            "dataType" = "Integer"; 
            "desc" = "Allow Full Scan Removable Drive Scanning"
         }
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/Defender/AllowRealtimeMonitoring"; 
            "value" = '1'; 
            "dataType" = "Integer"; 
            "desc" = "Allow Realtime Monitoring: Allowed"
         } 
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/Defender/AllowIOAVProtection"; 
            "value" = '1'; 
            "dataType" = "Integer"; 
            "desc" = "Allow scanning of all downloaded files and attachments: Allowed"
         } 
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/ADMX_MicrosoftDefenderAntivirus/MpEngine_EnableFileHashComputation"; 
            "value" = '<enabled/>'; 
            "dataType" = "String"; 
            "desc" = "Enable File Hash Computation: Enable"
         } 
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/Defender/PUAProtection"; 
            "value" = '1'; 
            "dataType" = "Integer"; 
            "desc" = "PUA Protection on"
         }   
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/DeliveryOptimization/DODownloadMode"; 
            "value" = '3'; 
            "dataType" = "Integer"; 
            "desc" = "PUA Protection on HTTP blended with Internet Peering"
         }
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/DeviceLock/AlphanumericDevicePasswordRequired"; 
            "value" = '2'; 
            "dataType" = "Integer"; 
            "desc" = "Alphanumeric Device Password Required: Password, Numeric PIN, or Alphanumeric PIN required "
         }
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/DeviceLock/DevicePasswordExpiration"; 
            "value" = '0'; 
            "dataType" = "Integer"; 
            "desc" = "Device Password Expiration: 365 or fewer days, but not 0"
         }
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/DeviceLock/DevicePasswordHistory"; 
            "value" = '24'; 
            "dataType" = "Integer"; 
            "desc" = "Device Password History: 24 or more password(s)"
         }
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/DeviceLock/MinDevicePasswordComplexCharacters"; 
            "value" = '3'; 
            "dataType" = "Integer"; 
            "desc" = "Device Password History: 24 or more password(s): Digits lowercase letters and uppercase letters are required"
         }
         @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/DeviceLock/MinDevicePasswordLength"; 
            "value" = '14'; 
            "dataType" = "Integer"; 
            "desc" = "Min Device Password Length: 14 or more character(s)"
        }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/DeviceLock/MinimumPasswordAge"; 
            "value" = '90'; 
            "dataType" = "Integer"; 
            "desc" = "Minimum Password Age: 1 or more day(s)"
        }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/Experience/DoNotShowFeedbackNotifications"; 
            "value" = 'true'; 
            "dataType" = "Boolean"; 
            "desc" = "Enable Domain Network Firewall: True"
        }
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/DomainProfile/DefaultInboundAction"; 
            "value" = '1'; 
            "dataType" = "Integer"; 
            "desc" = "Enable Domain Network Firewall: Default Inbound Action for Domain Profile: Block"
        }     
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/DomainProfile/DisableInboundNotifications"; 
            "value" = 'true'; 
            "dataType" = "Boolean"; 
            "desc" = "Enable Domain Network Firewall: Disable Inbound Notifications: True"
        }    
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/DomainProfile/EnableLogDroppedPackets"; 
            "value" = 'true'; 
            "dataType" = "Boolean"; 
            "desc" = "Enable Domain Network Firewall: Enable Log Dropped Packets Yes: Enable Logging Of Dropped Packets "
        }    
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/DomainProfile/EnableLogSuccessConnections"; 
            "value" = 'true'; 
            "dataType" = "Boolean"; 
            "desc" = "Enable Domain Network Firewall: Enable Log Success Connections Enable Logging Of Successful Connections"
        }
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/DomainProfile/LogFilePath"; 
            "value" = '%SystemRoot%\System32\logfiles\firewall\domainfw.log'; 
            "dataType" = "String"; 
            "desc" = "Enable Domain Network Firewall: Log File Path %SystemRoot%\System32\logfiles\firewall\domainfw.log"
        }
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/DomainProfile/LogMaxFileSize"; 
            "value" = '16384'; 
            "dataType" = "Integer"; 
            "desc" = "Enable Domain Network Firewall: Log Max File Size: 16,384 KB or greater "
        }
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/EnableFirewall"; 
            "value" = 'true'; 
            "dataType" = "Boolean"; 
            "desc" = "Enable Private Network Firewal: True"
        } 
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/DefaultInboundAction"; 
            "value" = '1'; 
            "dataType" = "Integer"; 
            "desc" = "Enable Private Network Firewall: Default Inbound Action for Private Profile: Block"
        } 
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/DisableInboundNotifications"; 
            "value" = 'true'; 
            "dataType" = "Boolean"; 
            "desc" = "Enable Private Network Firewall: Disable Inbound Notifications: True"
        } 
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/EnableLogSuccessConnections"; 
            "value" = 'true'; 
            "dataType" = "Boolean"; 
            "desc" = "Enable Private Network Firewall: Enable Log Success Connections: Enable Logging Of Successful Connections "
        }
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/EnableLogDroppedPackets"; 
            "value" = 'true'; 
            "dataType" = "Boolean"; 
            "desc" = "Enable Private Network Firewall: Enable Log Dropped Packets: Yes: Enable Logging Of Dropped Packets"
        }
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/LogFilePath"; 
            "value" = '%SystemRoot%\System32\logfiles\firewall\privatefw.log'; 
            "dataType" = "String"; 
            "desc" = "Enable Private Network Firewall: Log File Path: %SystemRoot%\System32\logfiles\firewall\privatefw.log "
        }
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/LogMaxFileSize"; 
            "value" = '16384'; 
            "dataType" = "Integer"; 
            "desc" = "Enable Private Network Firewall: Log Max File Size: 16,384 KB or greater"
        }
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/PublicProfile/EnableFirewall"; 
            "value" = 'true'; 
            "dataType" = "Boolean"; 
            "desc" = "Enable Public Network Firewall"
        }
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/PublicProfile/AllowLocalIpsecPolicyMerge"; 
            "value" = 'false'; 
            "dataType" = "Boolean"; 
            "desc" = "Enable Public Network Firewall: Allow Local Ipsec Policy Merge: False"
        }
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/PublicProfile/AllowLocalPolicyMerge"; 
            "value" = 'false'; 
            "dataType" = "Boolean"; 
            "desc" = "Enable Public Network Firewall: Allow Local Policy Merge: False"
        }
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/PublicProfile/DefaultInboundAction"; 
            "value" = '16384'; 
            "dataType" = "Integer"; 
            "desc" = "Enable Public Network Firewall: Default Inbound Action for Public Profile: Block"
        }
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/PublicProfile/DisableInboundNotifications"; 
            "value" = 'true'; 
            "dataType" = "Boolean"; 
            "desc" = "Enable Public Network Firewall: Disable Inbound Notifications: True"
        }
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/PublicProfile/EnableLogDroppedPackets"; 
            "value" = 'true'; 
            "dataType" = "Boolean"; 
            "desc" = "Enable Public Network Firewall: Enable Log Dropped Packets Yes: Enable Logging Of Dropped Packets "
        }
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/PublicProfile/EnableLogSuccessConnections"; 
            "value" = 'true'; 
            "dataType" = "Boolean"; 
            "desc" = "Enable Public Network Firewall: Enable Log Success Connections: Enable Logging Of Successful Connections"
        }
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/PublicProfile/LogFilePath"; 
            "value" = '%SystemRoot%\System32\logfiles\firewall\publicfw.log'; 
            "dataType" = "String"; 
            "desc" = "Enable Public Network Firewall: Log File Path: %SystemRoot%\System32\logfiles\firewall\publicfw.log"
        }
        @{ 
            "omaUri" = "./Vendor/MSFT/Firewall/MdmStore/PublicProfile/LogMaxFileSize"; 
            "value" = '16384'; 
            "dataType" = "Integer"; 
            "desc" = "Enable Public Network Firewall: Log Max File Size: 16,384 KB or greater"
        }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/Accounts_EnableGuestAccountStatus"; 
            "value" = '1'; 
            "dataType" = "Integer"; 
            "desc" = "Accounts: Enable Guest account status: Disabled"
        }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/Accounts_LimitLocalAccountUseOfBlankPasswordsToConsoleLogonOnly"; 
            "value" = '1'; 
            "dataType" = "Integer"; 
            "desc" = "Accounts: Limit local account use of blank passwords to console logon only: Enabled"
        }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/Accounts_RenameAdministratorAccount"; 
            "value" = 'ATEA'; 
            "dataType" = "String"; 
            "desc" = "Accounts: Rename administrator account to ATEA"
        }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/Accounts_RenameGuestAccount"; 
            "value" = 'ATEAGUEST'; 
            "dataType" = "String"; 
            "desc" = "Accounts: Rename guest account to ATEAGUEST"
        }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/InteractiveLogon_DoNotDisplayLastSignedIn"; 
            "value" = '1'; 
            "dataType" = "Integer"; 
            "desc" = "Interactive logon: Do not display last signed-in"
        }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/InteractiveLogon_MachineInactivityLimit"; 
            "value" = '900'; 
            "dataType" = "Integer"; 
            "desc" = "Interactive logon: Machine inactivity limit: 900 or fewer second(s), but not 0"
        }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/InteractiveLogon_MessageTextForUsersAttemptingToLogOn"; 
            "value" = 'Jūsų norimas tekstas (1)'; 
            "dataType" = "String"; 
            "desc" = "Interactive logon: Message text for users attempting to log on"
        }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/InteractiveLogon_MessageTitleForUsersAttemptingToLogOn"; 
            "value" = 'Jūsų norimas tekstas (2)'; 
            "dataType" = "String"; 
            "desc" = "Interactive logon: Message title for users attempting to log on"
        }
         )
    "IG 2" = @(
        @{ "omaUri" = "./Device/Vendor/MSFT/Policy/Config/UserRights/ChangeSystemTime"; "value" = "AdministratorsLOCAL SERVICE"; "dataType" = "String"; "desc" = "Sets change system time" }
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/SmartScreen/EnableSmartScreenInShell"; 
            "value" = '1'; 
            "dataType" = "Integer"; 
            "desc" = "Configure Windows Defender SmartScreen Enabled: Warn and prevent bypass"
         }     
        )
    "IG 3" = @(
        @{ "omaUri" = "./Device/Vendor/MSFT/Policy/Config/AboveLock/AllowActionCenterNotifications"; "value" = "0"; "dataType" = "Integer"; "desc" = "Disables action center notifications" }
    )
    "Level 1" = @(
        @{ "omaUri" = "./Device/Vendor/MSFT/Policy/Config/AboveLock/DisableLockScreen"; "value" = "true"; "dataType" = "Boolean"; "desc" = "Disables lock screen" }
    )
    "Level 2" = @(
        @{ "omaUri" = "./Device/Vendor/MSFT/Policy/Config/Experience/DisableWindowsConsumerFeatures"; "value" = "1"; "dataType" = "Integer"; "desc" = "Disables consumer features" }
    )
}
# Predefined OMA-URIs for MSOFFICE Levels
$MSOFFICE = @{
    "MSOFFICE IG 1" = @(
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventEnablingLockScreenCamera"; 
            "value" = "<enabled/>"; 
            "dataType" = "String"; 
            "desc" = "Prevent enabling lock screen camera" 
         }
    )
     "MSOFFICE IG 2" = @(
        @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventEnablingLockScreenCamera"; 
            "value" = "<enabled/>"; 
            "dataType" = "String"; 
            "desc" = "Prevent enabling lock screen camera" 
         }
    )
     "MSOFFICE IG 3" = @(
            @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventEnablingLockScreenCamera"; 
            "value" = "<enabled/>"; 
            "dataType" = "String"; 
            "desc" = "Prevent enabling lock screen camera" 
        }
    )
        "MSOFFICE Level 1" = @(
            @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventEnablingLockScreenCamera"; 
            "value" = "<enabled/>"; 
            "dataType" = "String"; 
            "desc" = "Prevent enabling lock screen camera" 
        }
    )
        "MSOFFICE Level 2" = @(
            @{ 
            "omaUri" = "./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventEnablingLockScreenCamera"; 
            "value" = "<enabled/>"; 
            "dataType" = "String"; 
            "desc" = "Prevent enabling lock screen camera" 
     } 
    )
}

# Function to authenticate with Microsoft Graph
function Connect-ToIntune {
    Write-Host "🔄 Logging into Microsoft Intune..." -ForegroundColor Cyan
    try {
        # Connect to Microsoft Graph with required scope and suppress welcome message
        Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All" -NoWelcome

        # Retrieve the authenticated user context
        $context = Get-MgContext

        if ($context.Account) {
            Write-Host "✅ Successfully authenticated with Intune as: $($context.Account)" -ForegroundColor Green
            # Store authenticated user in a global variable for menu display
            $global:IntuneUser = $context.Account
        } else {
            Write-Host "✅ Successfully authenticated with Intune, but unable to retrieve account details." -ForegroundColor Yellow
            $global:IntuneUser = "Unknown"
        }

    } catch {
        Write-Host "❌ Error: Failed to authenticate with Intune." -ForegroundColor Red
    }
}

# Function to get existing Intune policy ID
function Get-IntuneProfileId {
    param ([string]$profileName)
    $profiles = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
    
    foreach ($profile in $profiles.value) {
        if ($profile.displayName -eq $profileName) {
            return $profile.id
        }
    }
    return $null
}

# Function to apply Settings from IGLevels only
function Apply-OMASettings {
    param (
        [string]$level,
        [switch]$DebugMode  # Enable debugging messages
    )

    Write-Host "`n🔄 Starting OMA-URI policy application for level: $level..." -ForegroundColor Cyan
    Start-Sleep -Seconds 5  # Delay for readability

    $omaSettings = $IGLevels[$level]
    
    if ($null -eq $omaSettings) {
        Write-Host "❌ No settings found for $level." -ForegroundColor Red
        return
    }

    # Categorize settings
    $deviceSettings = @()
    $userSettings = @()
    $vendorSettings = @()
    $unrecognizedSettings = @()
    $duplicates = @()

    # Retrieve existing settings for this level
    $profileName = "CIS Benchmark - $level (Device)"
    $existingSettings = @()
    $profileId = Get-IntuneProfileId -profileName $profileName

    if ($profileId) {
        Write-Host "`n🔄 Retrieving existing settings for profile '$profileName'..." -ForegroundColor Cyan
        Start-Sleep -Seconds 5
        $existingSettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$profileId"
        $existingOmaSettings = $existingSettings.omaSettings | ForEach-Object { $_.omaUri }
    } else {
        $existingOmaSettings = @()
    }

    foreach ($setting in $omaSettings) {
        if ($existingOmaSettings -contains $setting.omaUri) {
            # If the setting is a duplicate, track it
            $duplicates += $setting
        }
        elseif ($setting.omaUri -match "\.\/Device\/.*") {
            $deviceSettings += $setting
        }
        elseif ($setting.omaUri -match "\.\/User\/.*") {
            $userSettings += $setting
        }
        elseif ($setting.omaUri -match "\.\/Vendor\/.*") {
            # Ensure ./Vendor/ settings go under Device Profile
            $vendorSettings += $setting
        }
        else {
            # If the setting doesn't belong to ./Device, ./User, or ./Vendor, categorize under ./Device
            $setting.omaUri = "./Device/" + $setting.omaUri
            $deviceSettings += $setting
        }
    }

# Notify about duplicates with a more readable format
    if ($duplicates.Count -gt 0) {
        Write-Host "`n⚠️ Skipped duplicate settings that already exist in the policy:" -ForegroundColor Yellow

        # Define user Documents path
        $userDocuments = [System.Environment]::GetFolderPath("MyDocuments")
        $folderPath = "$userDocuments\AteaDeployment"

        # Create folder if it doesn't exist
        if (!(Test-Path -Path $folderPath)) {
            New-Item -ItemType Directory -Path $folderPath | Out-Null
        }

        # Format the filename with date-time (DD-MM-HH)
        $timestamp = (Get-Date -Format "dd-MM-HH")
        $filePath = "$folderPath\Duplicates-$timestamp.csv"

        # Save to CSV silently
        $duplicates | Select-Object @{Name="Display Name"; Expression={$_.desc}}, @{Name="OMA-URI"; Expression={$_.omaUri}} | Export-Csv -Path $filePath -NoTypeInformation

        Write-Host "`n✅ CSV file saved at: $filePath" -ForegroundColor Green

        # Display GUI table
        $duplicates | Select-Object @{Name="Display Name"; Expression={$_.desc}}, @{Name="OMA-URI"; Expression={$_.omaUri}} | Out-GridView -Title "Skipped Duplicate Settings"
    }

    # Apply policies with more detailed debugging
    $policiesCreated = 0

    if ($deviceSettings.Count -gt 0) {
        Write-Host "`n📌 Applying Device settings ($($deviceSettings.Count) items) for $level..." -ForegroundColor Cyan
        Start-Sleep -Seconds 5
        Apply-IntunePolicy -level $level -settings $deviceSettings -profileType "Device" -DebugMode:$DebugMode
        $policiesCreated++
    }

    if ($vendorSettings.Count -gt 0) {
        Write-Host "`n📌 Applying Vendor settings ($($vendorSettings.Count) items) under Device profile for $level..." -ForegroundColor Cyan
        Start-Sleep -Seconds 5
        Apply-IntunePolicy -level $level -settings $vendorSettings -profileType "Device" -DebugMode:$DebugMode
        $policiesCreated++
    }

    if ($userSettings.Count -gt 0) {
        Write-Host "`n📌 Applying User settings ($($userSettings.Count) items) for $level..." -ForegroundColor Cyan
        Start-Sleep -Seconds 5
        Apply-IntunePolicy -level $level -settings $userSettings -profileType "Users" -DebugMode:$DebugMode
        $policiesCreated++
    }

    # Summary output
    if ($policiesCreated -gt 0) {
        Write-Host "`n✅ Successfully created $policiesCreated policy(ies) for $level." -ForegroundColor Green
    } else {
        Write-Host "`n⚠️ No policies were created for $level." -ForegroundColor Yellow
    }
    
    # Log the result to a file
    $logEntry = "$(Get-Date) - Level: $level - Created: $policiesCreated policies - Duplicates Skipped: $($duplicates.Count) - Vendor Settings Applied: $($vendorSettings.Count)"
    Add-Content -Path ".\OMASettings_Log.txt" -Value $logEntry

    Start-Sleep -Seconds 5  # Final pause before returning to the menu
}

# Function to create/update Intune policies with debugging
function Apply-IntunePolicy {
    param (
        [string]$level,
        [array]$settings,
        [string]$profileType,
        [switch]$DebugMode
    )

    $profileName = "CIS Benchmark - $level ($profileType)"
    Write-Host "`n📋 Checking if profile '$profileName' exists..." -ForegroundColor Cyan
    Start-Sleep -Seconds 5

    $profileId = Get-IntuneProfileId -profileName $profileName
    
    if ($DebugMode) {
        if ($profileId) {
            Write-Host "🔍 Debug Info: Profile '$profileName' found with ID: $profileId" -ForegroundColor Cyan
        } else {
            Write-Host "🔍 Debug Info: Profile '$profileName' does not exist. A new one will be created." -ForegroundColor Cyan
        }
        Start-Sleep -Seconds 5
    }

    $keepExisting = $true
    if ($profileId) {
        do {
            $response = Read-Host "Do you want to keep existing settings? (Yes/No)"
            if ($response -eq "No") {
                $keepExisting = $false
            } elseif ($response -eq "Yes") {
                $keepExisting = $true
            } else {
                Write-Host "❌ Invalid input. Please enter 'Yes' or 'No'." -ForegroundColor Red
            }
        } until ($response -eq "Yes" -or $response -eq "No")
    }

    $formattedOmaSettings = @()
    $existingOmaSettings = @()

    if ($keepExisting -and $profileId) {
        Write-Host "`n🔄 Retrieving existing settings for profile '$profileName'..." -ForegroundColor Cyan
        Start-Sleep -Seconds 5
        $existingSettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$profileId"
        $existingOmaSettings = $existingSettings.omaSettings
        $formattedOmaSettings += $existingOmaSettings
    }

    foreach ($setting in $settings) {
        $omaUri = $setting.omaUri
        $existingEntry = $existingOmaSettings | Where-Object { $_.omaUri -eq $omaUri }
        if (-not $existingEntry) {
            $value = $setting.value
            $omaType = switch ($setting.dataType) {
                "Integer" { "#microsoft.graph.omaSettingInteger"; $value = [int]$value }
                "Boolean" { "#microsoft.graph.omaSettingBoolean"; $value = [bool]$value }
                Default { "#microsoft.graph.omaSettingString" }
            }

            $formattedOmaSettings += @{ "@odata.type" = $omaType; "displayName" = $setting.desc; "omaUri" = $omaUri; "value" = $value }
        }
    }

    Start-Sleep -Seconds 5

    $profileBody = @{ "@odata.type" = "#microsoft.graph.windows10CustomConfiguration"; "displayName" = $profileName; "omaSettings" = $formattedOmaSettings }
    $jsonBody = $profileBody | ConvertTo-Json -Depth 10 -Compress
    
    try {
        if ($profileId) {
            Write-Host "`n🔄 Updating existing profile: $profileName..." -ForegroundColor Cyan
            Start-Sleep -Seconds 5
            Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$profileId" -Body $jsonBody -ContentType "application/json" | Out-Null
            Write-Host "✅ Profile updated successfully: $profileName" -ForegroundColor Green
        } else {
            Write-Host "`n🔄 Creating new profile: $profileName..." -ForegroundColor Cyan
            Start-Sleep -Seconds 5
            Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations" -Body $jsonBody -ContentType "application/json" | Out-Null
            Write-Host "✅ New profile created successfully: $profileName" -ForegroundColor Green
        }
    } catch {
        Write-Host "❌ Error updating or creating profile: $_" -ForegroundColor Red
    }

    Start-Sleep -Seconds 5
}

Add-Type -AssemblyName System.Windows.Forms

# Function to launch file explorer and select a file
function Get-FilePath {
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.InitialDirectory = [System.Environment]::GetFolderPath('MyDocuments')
    $dialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $dialog.RestoreDirectory = $true
    
    if ($dialog.ShowDialog() -eq 'OK') {
        return $dialog.FileName
    } else {
        Write-Host "No file selected."
        return $null
    }
}

# Function to Add a CSV Configuration
function Add-CSV {
    Write-Host "📂 Select CSV file for upload..." -ForegroundColor Cyan
    $csvFilePath = Get-FilePath
    if (-Not $csvFilePath) {
        Write-Host "❌ Error: CSV file not found or user canceled." -ForegroundColor Red
        return
    }
    
    Write-Host "🗉 Enter the base policy name to update or create:" -ForegroundColor Cyan
    $basePolicyName = Read-Host "Policy Name"
    
    $csvData = Import-Csv -Path $csvFilePath
    if ($csvData.Count -eq 0) {
        Write-Host "❌ Error: CSV file is empty!" -ForegroundColor Red
        return
    }
    
    # Trim spaces in omaUri field to avoid filtering issues
    $csvData | ForEach-Object { $_.omaUri = $_.omaUri.Trim() }
    
    # Debugging: Print all OMA-URI entries before filtering
    Write-Host "📜 Full list of OMA-URIs found in CSV (after trimming):" -ForegroundColor Cyan
    foreach ($entry in $csvData) {
        Write-Host "   - [$($entry.omaUri)]" -ForegroundColor Yellow
    }
    
    # Adjust filtering using -like for better wildcard matching
    $deviceSettings = @($csvData | Where-Object { $_.omaUri -like "*/Device/*" })
    $userSettings = @($csvData | Where-Object { $_.omaUri -like "*/User/*" })
    
    Write-Host "✅ Identified $($deviceSettings.Count) Device settings and $($userSettings.Count) User settings." -ForegroundColor Green
    
    if ($deviceSettings.Count -gt 0) {
        Write-Host "➡️ Processing Device Policy: $basePolicyName (Device)" -ForegroundColor Cyan
        Process-Policy "$basePolicyName (Device)" $deviceSettings
    }
    
    if ($userSettings.Count -gt 0) {
        Write-Host "➡️ Processing User Policy: $basePolicyName (User) with $($userSettings.Count) settings." -ForegroundColor Cyan
        foreach ($entry in $userSettings) {
            Write-Host "   📌 Found User Setting: [$($entry.omaUri)]" -ForegroundColor Cyan
        }
        Process-Policy "$basePolicyName (User)" $userSettings
    } else {
        Write-Host "⚠️ No User settings found! Skipping User policy creation." -ForegroundColor Yellow
        Write-Host "🔎 Debug: Double-checking all OMA-URIs in CSV to verify filtering." -ForegroundColor Magenta
        foreach ($entry in $csvData) {
            Write-Host "   🛑 Unmatched Entry: [$($entry.omaUri)]" -ForegroundColor Red
        }
    }
}

function Process-Policy {
    param (
        [string]$policyName,
        [array]$settingsData
    )

    if ($settingsData.Count -eq 0) {
        Write-Host "⚠️ No settings provided for policy: $policyName. Skipping..." -ForegroundColor Yellow
        return
    }
    
    Write-Host "🔄 Processing policy: $policyName with $($settingsData.Count) settings..." -ForegroundColor Cyan
    $profileId = Get-IntuneProfileId -profileName $policyName
    
    if (-not $profileId) {
        Write-Host "🆕 No existing profile found. Creating a new one..." -ForegroundColor Green
    } else {
        Write-Host "✅ Existing profile found: $policyName. Updating it..." -ForegroundColor Yellow
        do {
            $response = Read-Host "Do you want to keep existing settings? (Yes/No)"
            if ($response -eq "No") {
                $keepExisting = $false
            } elseif ($response -eq "Yes") {
                $keepExisting = $true
            } else {
                Write-Host "❌ Invalid input. Please enter 'Yes' or 'No'." -ForegroundColor Red
            }
        } until ($response -eq "Yes" -or $response -eq "No")
    }
    
    $formattedOmaSettings = @()
    $existingOmaSettings = @()
    if ($profileId -and $keepExisting) {
        $existingSettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$profileId"
        $existingOmaSettings = $existingSettings.omaSettings
        $formattedOmaSettings += $existingOmaSettings
    }
    
    foreach ($row in $settingsData) {
        $omaUri = $row.omaUri
        $existingEntry = $existingOmaSettings | Where-Object { $_.omaUri -eq $omaUri }
        
        $value = $row.value
        $omaType = "#microsoft.graph.omaSettingString"
        
        if ($value -match '^\d+$') {
            $value = [int]$value
            $omaType = "#microsoft.graph.omaSettingInteger"
        } elseif ($value -match '^(true|false)$') {
            $value = [bool]$value
            $omaType = "#microsoft.graph.omaSettingBoolean"
        }

        $displayName = $row.displayName
        $description = $row.description
        
        if (-not $existingEntry) {
            $formattedOmaSettings += @{
                "@odata.type" = $omaType
                "displayName" = $displayName
                "omaUri" = $omaUri
                "value" = $value
                "description" = $description
            }
        }
    }
    
    $profileBody = @{
        "@odata.type" = "#microsoft.graph.windows10CustomConfiguration"
        "displayName" = $policyName
        "omaSettings" = $formattedOmaSettings
    }
    $jsonBody = $profileBody | ConvertTo-Json -Depth 10 -Compress
    try {
        if ($profileId) {
            Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$profileId" -Body $jsonBody -ContentType "application/json"
            Write-Host "✅ Policy updated successfully: $policyName" -ForegroundColor Green
        } else {
            Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations" -Body $jsonBody -ContentType "application/json"
            Write-Host "✅ New policy created successfully: $policyName" -ForegroundColor Green
        }
    } catch {
        Write-Host "❌ Error updating or creating policy: $_" -ForegroundColor Red
    }
}

# Submenu for Intune Windows 10/11 Configuration Policies
function Show-IntuneMenu {
    while ($true) {
        Clear-Host  # Clears the screen for a cleaner UI

        # Explicitly reset text color to default (White)
        Write-Host "" -ForegroundColor White  

        if ($global:IntuneUser) {
            Write-Host "✅ Logged into Microsoft Intune as: $global:IntuneUser" -ForegroundColor Green
        } else {
            Write-Host "❌ Not logged into Microsoft Intune." -ForegroundColor Red
        }

        Write-Host "`n🔧 Intune Windows 10/11 Configuration Policies" -ForegroundColor Cyan
        if ($global:IntuneUser) {
            Write-Host "1. 🔄 Re-login to Microsoft Intune"
        } else {
            Write-Host "1. 🔑 Login to Microsoft Intune"
        }
        Write-Host "2. Apply IG 1 Policy"
        Write-Host "3. Apply IG 2 Policy"
        Write-Host "4. Apply IG 3 Policy"
        Write-Host "5. Apply Level 1 Policy"
        Write-Host "6. Apply Level 2 Policy"
        Write-Host "7. 📂 Upload from File"
        Write-Host "8. 🔙 Back to Main Menu"
        
        $choice = Read-Host "Select an option"

        switch ($choice) {
            "1" { 
                Connect-ToIntune 
                Start-Sleep -Seconds 5  # Short delay to ensure readability
            }
            "2" { Apply-OMASettings -level "IG 1" }
            "3" { Apply-OMASettings -level "IG 2" }
            "4" { Apply-OMASettings -level "IG 3" }
            "5" { Apply-OMASettings -level "Level 1" }
            "6" { Apply-OMASettings -level "Level 2" }
            "7" { Add-CSV }
            "8" { return }
            default { 
                Write-Host "❌ Invalid option, please try again." -ForegroundColor Red 
                Start-Sleep -Seconds 5  # Short delay for readability
            }
        }
    }
}

# Main menu
function Show-MainMenu {
    while ($true) {
        Write-Host "📌 Main Menu" -ForegroundColor Cyan
        Write-Host "1. Intune Windows 10/11 Configuration Policies"
        Write-Host "2. Placeholder for Future Features"
        Write-Host "3. Exit Script (Return to PowerShell Prompt)"
        
        $choice = Read-Host "Select an option"
        switch ($choice) {
            "1" { Show-IntuneMenu }
            "2" { Write-Host "🚧 Feature under development. Returning to main menu..." -ForegroundColor Yellow }
            "3" { Write-Host "✅ Returning to PowerShell..."; return }
            default { Write-Host "❌ Invalid option. Please enter a number between 1 and 3." -ForegroundColor Red }
        }
    }
}

# Start the Main Menu
Show-MainMenu