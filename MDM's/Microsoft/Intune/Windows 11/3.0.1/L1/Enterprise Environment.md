# Corporate/Enterprise Environment Level - 1

# 1.0 - Above Lock

## 1.1 'Allow Cortana Above Lock' is set to 'Block'

>[!NOTE]
>Access to any computer resource should not be allowed when the device is locked

>[!TIP]
>Automated Remediation

>[!CAUTION]
>The system will need to be unlocked for the user to interact with Cortana using speech.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/AboveLock/AllowActionCenterNotifications
```
|Value|Description|
|---|---|
|0| Disabled Not allowed|
|1|(Default) Enabled. (The user can interact with Cortana using speech while the system is locked.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Allow Cortana above lock screen\u0027 is set to \u0027Blocked\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/AboveLock/AllowCortanaAboveLock",
            "value": 0
        },
```


```
Audit:

1. Navigate to the following registry location and note the WinningProvider GUID. This value confirms under which User GUID the policy is set.

HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\AboveLock:AllowCortanaAboveLock_WinningProvider


2. Navigate to the following registry location and confirm the value is set to 0.

HKLM\SOFTWARE\Microsoft\PolicyManager\Providers\{GUID}\Default\Device\AboveLock:AllowCortanaAboveLock

```

# 3.1.3 - Personalization

## 3.1.3.1 - 'Enable screen saver (User)' is set to 'Enabled'
 

>[!NOTE]
>This policy setting enables/disables the use of desktop screen savers.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If a user forgets to lock their computer when they walk away, it is possible that a
passerby will hijack it. Configuring a timed screen saver with password lock will help to
protect against these hijacks.



```
OMA-URI (User)
./User/Vendor/MSFT/Policy/Config/ADMX_ControlPanelDisplay/CPL_Personalization_EnableScreenSaver
```
|Value|Description|
|---|---|
| < enabled/ > |Enable|
| < disabled/ > |Disable|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.3 Configure Automated Session Locking on Enterprise Assets|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Enable screen saver\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./User/Vendor/MSFT/Policy/Config/ADMX_ControlPanelDisplay/CPL_Personalization_EnableScreenSaver",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_SZ value of 1.
HKU\[USER SID]\Software\Policies\Microsoft\Windows\Control Panel\Desktop:ScreenSaveActive
```


## 3.1.3.2 - 'Prevent enabling lock screen camera' is set to 'Enabled'

>[!NOTE]
>Disables the lock screen camera toggle switch in PC Settings and prevents a camera
from being invoked on the lock screen

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If you enable this setting, users will no longer be able to enable or disable lock screen
camera access in PC Settings, and the camera cannot be invoked on the lock screen.


```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventEnablingLockScreenCamera
```
|Value|Description|
|---|---|
| < enabled/ > |Enable|
| < disabled/ > |Disable|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Prevent enabling lock screen camera\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventEnablingLockScreenCamera",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization:NoLockScreenCamera
```



## 3.1.3.3 - 'Prevent enabling lock screen slide show' is set to 'Enabled'
	
>[!NOTE]
>Disables the lock screen slide show settings in PC Settings and prevents a slide show
from playing on the lock screen

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If you enable this setting, users will no longer be able to modify slide show settings in
PC Settings, and no slide show will ever start.



```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventLockScreenSlideShow
```
|Value|Description|
|---|---|
| < enabled/ > |Enable|
| < disabled/ > |Disabled. (Users can enable a slide show that will run after they lock the machine.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Prevent enabling lock screen slide show\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventLockScreenSlideShow",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization:NoLockScreenSlideshow
```


# 3.4 -  MS Security Guide

## 3.4.1 - 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled' 

>[!NOTE]
>This setting controls whether local accounts can be used for remote administration via
network logon (e.g., NET USE, connecting to C$, etc.). Local accounts are at high risk
for credential theft when the same account and password is configured on multiple
systems. Enabling this policy significantly reduces that risk.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ApplyUACRestrictionsToLocalAccountsOnNetworkLogon
```
|Value|Description|
|---|---|
| < enabled/ > |Applies UAC token-filtering to local accounts on network logons. Membership in powerful group such as Administrators is disabled and powerful privileges are removed from the resulting access token|
| < disabled/ > |Allows local accounts to have full administrative rights when authenticating via network logon|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|7|4.3 the Use of Dedicated Administrative Accounts|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Apply UAC restrictions to local accounts on network logons\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ApplyUACRestrictionsToLocalAccountsOnNetworkLogon",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:LocalAccountTokenFilterPolicy

```

## 3.4.2 - 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver '
	
>[!NOTE]
>This setting configures the start type for the Server Message Block version 1 (SMBv1) client driver service (MRxSmb10), which is recommended to be disabled.


>[!TIP]
>Automated Remedation

>[!CAUTION]
Some legacy OSes (e.g. Windows XP, Server 2003 or older), applications and
appliances may no longer be able to communicate with the system once SMBv1 is
disabled. We recommend careful testing be performed to determine the impact prior to
configuring this as a widespread control, and where possible, remediate any
incompatibilities found with the vendor of the incompatible system.



```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ConfigureSMBV1ClientDriver
```
|Value|Description|
|---|---|
| < enabled/ > |Disable driver|
| < disabled/ > |Enable Driver|
| < enabled/><data id="Pol_SecGuide_SMB1ClientDriver" value="4" / > | Custom settings (Recommended)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Only Approved Ports, Protocols and Services Are Running ||:orange_circle:|:large_blue_circle:|Level - 1|
|7|14.3 Disable Workstation to Workstation Communication||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Configure SMB v1 client driver\u0027 is set to \u0027Enabled: Disable driver (recommended)\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ConfigureSMBV1ClientDriver",
            "value": "\u003cenabled/\u003e\u003cdata id=\"Pol_SecGuide_SMB1ClientDriver\" value=\"4\" /\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 4.
HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10:Start
```


## 3.4.3 - 'Configure SMB v1 server' is set to 'Disabled' 
	
>[!NOTE]
>This setting configures the server-side processing of the Server Message Block version 1 (SMBv1) protocol.


>[!TIP]
>Automated Remedation

>[!CAUTION]
Some legacy OSes (e.g. Windows XP, Server 2003 or older), applications and
appliances may no longer be able to communicate with the system once SMBv1 is
disabled. We recommend careful testing be performed to determine the impact prior to
configuring this as a widespread control, and where possible, remediate any
incompatibilities found with the vendor of the incompatible system.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ConfigureSMBV1Server
```
|Value|Description|
|---|---|
| < enabled/ > |Enable Driver|
| < disabled/ > |Disable driver|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Only Approved Ports, Protocols and Services Are Running ||:orange_circle:|:large_blue_circle:|Level - 1|
|7|14.3 Disable Workstation to Workstation Communication||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Configure SMB v1 server\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ConfigureSMBV1Server",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters:SMB1
```

## 3.4.4 - 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'

>[!NOTE]
>Windows includes support for Structured Exception Handling Overwrite Protection (SEHOP). We recommend enabling this feature to improve the security profile of the computer.


>[!TIP]
>Automated Remedation

>[!CAUTION]
After you enable SEHOP, existing versions of Cygwin, Skype, and Armadillo-protected
applications may not work correctly.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/EnableStructuredExceptionHandlingOverwriteProtection
```
|Value|Description|
|---|---|
| < enabled/ > |Enable Driver|
| < disabled/ > |Disable driver|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.5 Enable Anti-Exploitation Features||:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.3 Enable Operating System Anti-Exploitation Features/Deploy Anti-Exploit Technologies||:orange_circle:|:large_blue_circle:|Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Enable Structured Exception Handling Overwrite Protection (SEHOP)\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/EnableStructuredExceptionHandlingOverwriteProtection",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel:DisableExceptionChainValidation
```

## 3.4.5 - 'WDigest Authentication' is set to 'Disabled'


>[!NOTE]
>When WDigest authentication is enabled, Lsass.exe retains a copy of the user's plaintext password in memory, where it can be at risk of theft. If this setting is not configured, WDigest authentication is disabled in Windows 8.1 and in Windows Server 2012 R2; it is enabled by default in earlier versions of Windows and Windows Server.

>[!TIP]
>Automated Remedation

>[!CAUTION]
None - this is also the default configuration for Windows 8.1 or newer

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/WDigestAuthentication
```
|Value|Description|
|---|---|
| < enabled/ > |Lsass.exe retains a copy of the user's plaintext password in memory, where it is at risk of theft|
| < disabled/ > |Lsass.exe does not retain a copy of the user's plaintext password in memory|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.11 Encrypt Sensitive Data at Rest||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.4 Encrypt or Hash all Authentication Credentials||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027WDigest Authentication\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/WDigestAuthentication",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest:UseLogonCredential
```

# 3.5 - MSS

## 3.5.1 - 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled' 

>[!NOTE]
>This setting is separate from the Welcome screen feature in Windows XP and Windows
Vista; if that feature is disabled, this setting is not disabled. If you configure a computer
for automatic logon, anyone who can physically gain access to the computer can also
gain access to everything that is on the computer, including any network or networks to
which the computer is connected. Also, if you enable automatic logon, the password is
stored in the registry in plaintext, and the specific registry key that stores this value is
remotely readable by the Authenticated Users group.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None


```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPSourceRoutingProtectionLevel
```
|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled|
| < enabled/><data id="DisableIPSourceRouting" value="2" / > |Custom Settings (Recommended)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.11 Encrypt Sensitive Data at Rest||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.4 Encrypt or Hash all Authentication Credentials||:orange_circle:|:large_blue_circle:|Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)\u0027 is set to \u0027Enabled: Highest protection, source routing is completely disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPSourceRoutingProtectionLevel",
            "value": "\u003cenabled/\u003e\u003cdata id=\"DisableIPSourceRouting\" value=\"2\" /\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:AutoAdminLogon
```

## 3.5.2 - 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'

>[!NOTE]
>IP source routing is a mechanism that allows the sender to determine the IP route that a
datagram should follow through the network.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>All incoming source routed packets will be dropped


```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPv6SourceRoutingProtectionLevel
```
|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled|
| < enabled/><data id="DisableIPSourceRoutingIPv6" value="2" / > |Custom Settings (Recommended)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|X|Not Mapped Yet|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|X|Not Mapped Yet|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)\u0027 is set to \u0027Enabled: Highest protection, source routing is completely disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPv6SourceRoutingProtectionLevel",
            "value": "\u003cenabled/\u003e\u003cdata id=\"DisableIPSourceRoutingIPv6\" value=\"2\" /\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 2.
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters:DisableIPSourceRouting

```

## 3.5.3 - 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'

>[!NOTE]
>IP source routing is a mechanism that allows the sender to determine the IP route that a
datagram should take through the network. It is recommended to configure this setting
to Not Defined for enterprise environments and to Highest Protection for high security
environments to completely disable source routing.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>All incoming source routed packets will be dropped


```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPSourceRoutingProtectionLevel
```
|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled|
| < enabled/><data id="DisableIPSourceRouting" value="2" / > |Custom Settings (Recommended) |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|X|Not Mapped Yet|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|X|Not Mapped Yet|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)\u0027 is set to \u0027Enabled: Highest protection, source routing is completely disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPSourceRoutingProtectionLevel",
            "value": "\u003cenabled/\u003e\u003cdata id=\"DisableIPSourceRouting\" value=\"2\" /\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 2.
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters:DisableIPSourceRouting
```

## 3.5.5 - 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'

>[!NOTE]
>Internet Control Message Protocol (ICMP) redirects cause the IPv4 stack to plumb host
routes. These routes override the Open Shortest Path First (OSPF) generated routes.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>When Routing and Remote Access Service (RRAS) is configured as an autonomous
system boundary router (ASBR), it does not correctly import connected interface subnet
routes. Instead, this router injects host routes into the OSPF routes. However, the
OSPF router cannot be used as an ASBR router, and when connected interface subnet
routes are imported into OSPF the result is confusing routing tables with strange routing
paths.


```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/MSSLegacy/AllowICMPRedirectsToOverrideOSPFGeneratedRoutes
```
|Value|Description|
|---|---|
| < enabled/ > |Enabled. (ICMP redirects can override OSPF-generated routes.)|
| < disabled/ > |Disabled|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.1 Establish and Maintain a Secure Configuration Process|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/AllowICMPRedirectsToOverrideOSPFGeneratedRoutes",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters:EnableICMPRedirect
```

## 3.5.7 -  'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled' 

>[!NOTE]
>NetBIOS over TCP/IP is a network protocol that among other things provides a way to
easily resolve NetBIOS names that are registered on Windows-based systems to the IP
addresses that are configured on those systems. This setting determines whether the
computer releases its NetBIOS name when it receives a name-release request.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/MSSLegacy/AllowTheComputerToIgnoreNetBIOSNameReleaseRequestsExceptFromWINSServers
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled |
| < disabled/ > |Disabled|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.2 Establish and Maintain a Secure Configuration Process for Network Infrastructure|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|5.1 Establish Secure Configurations|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|


```
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/AllowTheComputerToIgnoreNetBIOSNameReleaseRequestsExceptFromWINSServers",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters:NoNameReleaseOnDemand
```
## 3.5.9 - 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled' 

>[!NOTE]
>The DLL search order can be configured to search for DLLs that are requested by
running processes in one of two ways:
• Search folders specified in the system path first, and then search the current
working folder.
• Search current working folder first, and then search the folders specified in the
system path.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_MSS-legacy/Pol_MSS_SafeDllSearchMode
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled |
| < disabled/ > |Disabled|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.5 Enable Anti-Exploitation Features||:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.3 Enable Operating System Anti-Exploitation Features/Deploy Anti-Exploit Technologies||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_MSS-legacy/Pol_MSS_SafeDllSearchMode",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager:SafeDllSearchMode
```

## 3.5.10 - 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'


>[!NOTE]
>Windows includes a grace period between when the screen saver is launched and
when the console is actually locked automatically when screen saver locking is enabled.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Users will have to enter their passwords to resume their console sessions as soon as
the grace period ends after screen saver activation.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_MSS-legacy/Pol_MSS_ScreenSaverGracePeriod
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled |
| < disabled/ > |Disabled|
| < enabled/><data id="ScreenSaverGracePeriod" value="5"/ > |Custom Settings (Recommended)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.3 Configure Automatic Session Locking on Enterprise Assets|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)\u0027 is set to \u0027Enabled: 5 or fewer seconds\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_MSS-legacy/Pol_MSS_ScreenSaverGracePeriod",
            "value": "\u003cenabled/\u003e\u003cdata id=\"ScreenSaverGracePeriod\" value=\"5\"/\u003e"
        },
```

```
Audit: Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 5.
HKLM\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Winlogon:ScreenSaverGracePeriod
```

## 3.5.13 - 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'

>[!NOTE]
>This setting can generate a security audit in the Security event log when the log reaches
a user-defined threshold.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>An audit event will be generated when the Security log reaches the 90% percent full
threshold (or whatever lower value may be set) unless the log is configured to overwrite
events as needed.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_MSS-legacy/Pol_MSS_WarningLevel
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled |
| < disabled > |Disabled|
| < enabled/><data id="WarningLevel" value="90"/ > |Custom Settings (Recommended)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.3 Adequate Audit Log Storage|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.4 adequate storage for logs|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning\u0027 is set to \u0027Enabled: 90% or less\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_MSS-legacy/Pol_MSS_WarningLevel",
            "value": "\u003cenabled/\u003e\u003cdata id=\"WarningLevel\" value=\"90\"/\u003e"
        },
```

```
Audit: 
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 90.
HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security:WarningLevel
```
# 3.6.4 - DNS Client

## 3.6.4.1 - 'Turn off multicast name resolution' is set to 'Enabled'

>[!NOTE]
>LLMNR is a secondary name resolution protocol. With LLMNR, queries are sent using
multicast over a local network link on a single subnet from a client computer to another
client computer on the same subnet that also has LLMNR enabled. LLMNR does not
require a DNS server or DNS client configuration, and provides name resolution in
scenarios in which conventional DNS name resolution is not possible.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>In the event DNS is unavailable a system will be unable to request it from other systems
on the same subnet

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_DnsClient/Turn_Off_Multicast
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (LLMNR will be enabled on all available network adapters.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|


```
Script: 
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Turn off multicast name resolution\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_DnsClient/Turn_Off_Multicast",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient:EnableMulticast
```
# 3.6.9 - Network Connections

## 3.6.9.1 - 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'

>[!NOTE]
>You can use this procedure to control a user's ability to install and configure a Network Bridge

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Users cannot create or configure a Network Bridge

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/Connectivity/ProhibitInstallationAndConfigurationOfNetworkBridge
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Users are able create and modify the configuration of Network Bridges. Membership in the local Administrators group, or equivalent, is the minimum required to complete this procedure.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.2 Establish and Maintain a Secure Configuration Process for Network Infrastructure|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|11.3 Use Automated Tools to Verify Standard Device Configurations and Detect Changes||:orange_circle:|:large_blue_circle:|Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Prohibit installation and configuration of Network Bridge on your DNS domain network\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Connectivity/ProhibitInstallationAndConfigurationOfNetworkBridge",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit: 
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections:NC_AllowNetBridge_NLA
```

## 3.6.9.2 - 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'

>[!NOTE]
>Although this "legacy" setting traditionally applied to the use of Internet Connection Sharing (ICS) in Windows 2000, Windows XP & Server 2003, this setting now freshly applies to the Mobile Hotspot feature in Windows 10 & Server 2016.


>[!TIP]
>Automated Remedation

>[!CAUTION]
>Mobile Hotspot cannot be enabled or configured by Administrators and non Administrators alike.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_NetworkConnections/NC_ShowSharedAccessUI
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (All users are allowed to turn on Mobile Hotspot.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": \u0027Prohibit use of Internet Connection Sharing on your DNS domain network\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_NetworkConnections/NC_ShowSharedAccessUI",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections:NC_ShowSharedAccessUI
```

## 3.6.9.3 - 'Require domain users to elevate when setting a network's location' is set to 'Enabled' 

>[!NOTE]
>This policy setting determines whether to require domain users to elevate when setting a network's location.


>[!TIP]
>Automated Remedation

>[!CAUTION]
>Domain users must elevate when setting a network's location.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_NetworkConnections/NC_StdDomainUserSetLocation
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disable/ > |Disabled. (Users can set a network's location without elevating.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Mapped Yet||||Level - 1|
|7|4.3 the Use of Dedicated Administrative Accounts|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Require domain users to elevate when setting a network\u0027s location\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_NetworkConnections/NC_StdDomainUserSetLocation",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit: 
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections:NC_StdDomainUserSetLocation
```

## 3.6.11.1 - 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares' 

>[!NOTE]
>This policy setting configures secure access to UNC paths

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Windows only allows access to the specified UNC paths after fulfilling additional security requirements.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/Connectivity/HardenedUNCPaths
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Users can set a network's location without elevating.)|
| < enabled/><data id="Pol_HardenedPaths" value="\\*\NETLOGONRequireMutualAuthentication=1,RequireIntegrity=1\\*\SYSVOLRequireMutualAuthentication=1,RequireIntegrity=1"/ > | Custom Settings (Recommended)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Mapped Yet||||Level - 1|
|7|Not Mapped Yet||||Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Hardened UNC Paths\u0027 is set to \u0027Enabled, with \"Require Mutual Authentication\" and \"Require Integrity\" set for all NETLOGON and SYSVOL shares\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Connectivity/HardenedUNCPaths",
            "value": "\u003cenabled/\u003e\u003cdata id=\"Pol_HardenedPaths\" value=\"\\\\*\\NETLOGONRequireMutualAuthentication=1,RequireIntegrity=1\\\\*\\SYSVOLRequireMutualAuthentication=1,RequireIntegrity=1\"/\u003e"
        },
```

```
Audit: 

Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry locations with a REG_SZ value of RequireMutualAuthentication=1, RequireIntegrity=1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths:\\*\NETLOGON
HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths:\\*\SYSVOL
```

# 3.6.18 - Windows Connection Manager

## 3.6.18.1 - 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet' 

>[!NOTE]
>This policy setting prevents computers from establishing multiple simultaneous connections to either the Internet or to a Windows domain.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>While connected to an Ethernet connection, Windows won't allow use of a WLAN
(automatically or manually) until Ethernet is disconnected. However, if a cellular data
connection is available, it will always stay connected for services that require it, but no
Internet traffic will be routed over cellular if an Ethernet or WLAN connection is present.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_WCM/WCM_MinimizeConnections
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled: 1 = Minimize simultaneous connections. (Any new automatic internet connection is blocked when the computer has at least one active internet connection to a preferred type of network. The order of preference (from most preferred to least preferred) is: Ethernet, WLAN, then cellular. Ethernet is always preferred when connected. Users can still manually connect to any network.)|
| < disabled/ > |Disabled|
| < enabled/><data id="WCM_MinimizeConnections_Options" value="3"/ > |Custom Settings (Recommended)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.1 Establish and Maintain a Secure Configuration Process|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|15.5 Limit Wireless Access on Client Devices|||:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Minimize the number of simultaneous connections to the Internet or a Windows Domain\u0027 is set to \u0027Enabled: 3 = Prevent Wi-Fi when on Ethernet\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_WCM/WCM_MinimizeConnections",
            "value": "\u003cenabled/\u003e\u003cdata id=\"WCM_MinimizeConnections_Options\" value=\"3\"/\u003e"
        },
```

```
Audit: 
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 3.
HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy:fMinimizeConnections
```

## 3.6.18.2 - 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to'Enabled' 

>[!NOTE]
>This policy setting prevents computers from connecting to both a domain based network and a non-domain based network at the same time

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The computer responds to automatic and manual network connection attempts based
on the following circumstances:
Automatic connection attempts - When the computer is already connected to a domain
based network, all automatic connection attempts to non-domain networks are blocked.
- When the computer is already connected to a non-domain based network, automatic
connection attempts to domain based networks are blocked.
Manual connection attempts - When the computer is already connected to either a nondomain based network or a domain based network over media other than Ethernet, and
a user attempts to create a manual connection to an additional network in violation of
this policy setting, the existing network connection is disconnected and the manual
connection is allowed. - When the computer is already connected to either a nondomain based network or a domain based network over Ethernet, and a user attempts
to create a manual connection to an additional network in violation of this policy setting,
the existing Ethernet connection is maintained and the manual connection attempt is
blocked.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/WindowsConnectionManager/ProhitConnectionToNonDomainNetworksWhenConnectedToDomainAuthenticatedNetwork
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Connections to both domain and non-domain networks are simultaneously allowed.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|12.4 Deny Communication over Unauthorized Ports|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|Not Mapped Yet|||||Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Prohibit connection to non-domain networks when connected to domain authenticated network\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/WindowsConnectionManager/ProhitConnectionToNonDomainNetworksWhenConnectedToDomainAuthenticatedNetwork",
            "value": "\u003cenabled/\u003e"
        },
```

``` 
Audit: 
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy:fBlockNonDomain
```
# 3.6.19 - Wireless Display

## 3.6.19.1 - 'Require PIN pairing' is set to 'Enabled'


>[!NOTE]
>This policy setting controls whether or not a PIN is required for pairing to a wireless display device

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The pairing ceremony for connecting to new wireless display devices will always require a PIN.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/WirelessDisplay/RequirePinForPairing
```

|Value|Description|
|---|---|
|1|Enabled|
|0|Disabled. (A PIN is not required for pairing to a wireless display device.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Mapped Yet|||||Level - 1|
|7|Not Mapped Yet|||||Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Require pin for pairing\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/WirelessDisplay/RequirePinForPairing",
            "value": 1
        },
```

```
Audit: 
1. Navigate to the following registry location and note the WinningProvider GUID. This value confirms under which User GUID the policy is set.
HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\ADMX_wlansvc:SetPINEnforced_WinningProvider

2. Navigate to the following registry location and confirm the value is set to <enabled/>.
HKLM\SOFTWARE\Microsoft\PolicyManager\Providers\{GUID}\Default\Device\ADMX_wlansvc:SetPINEnforced

```

# 3.7 - Printers

## 3.7.1 - 'Allow Print Spooler to accept client connections' is set to 'Disabled' 

>[!NOTE]
>This policy setting controls whether the Print Spooler service will accept client connections.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Provided that the Print Spooler service is not disabled, users will continue to be able to
print from their workstation. However, the workstation's Print Spooler service will not
accept client connections or allow users to share printers. Note that all printers that
were already shared will continue to be shared.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_Printing2/RegisterSpoolerRemoteRpcEndPoint
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled. (The Print Spooler will always accept client connections.)|
| < disabled/ > |Disabled|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.1 Establish and Maintain a Secure Configuration Process|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Allow Print Spooler to accept client connections\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_Printing2/RegisterSpoolerRemoteRpcEndPoint",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit: 
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 2.
HKLM\Software\Policies\Microsoft\WindowsNT\Printers:RegisterSpoolerRemoteRpcEndPoint

```

## 3.7.2 - 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt' 

## 3.7.3 - 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt' 
>[!NOTE]
>This policy setting controls whether computers will show a warning and a security
elevation prompt when users create a new printer connection using Point and Print.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/Printers/PointAndPrintRestrictions
```
|Value|Description|
|---|---|
| < enabled/ > |Enabled. (Windows computers will show a warning and a security elevation prompt when users create a new printer connection using Point and Print.)|
| < disabled/ > |Disabled|
| < enabled/>
| < data id="PointAndPrint_TrustedServers_Chk" value="false"/> <data id="PointAndPrint_TrustedServers_Edit" value=""/> <data id="PointAndPrint_TrustedForest_Chk" value="false"/> <data id="PointAndPrint_NoWarningNoElevationOnInstall_Enum" value="0"/> <data id="PointAndPrint_NoWarningNoElevationOnUpdate_Enum" value="0"/ > | Custom Settings (Recommended)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Mapped Yet|||||Level - 1|
|7|Not Mapped Yet|||||Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Point and Print Restrictions: When installing drivers for a new connection\u0027 is set to \u0027Enabled: Show warning and elevation prompt\u0027  \u0027Point and Print Restrictions: When updating drivers for an existing connection\u0027 is set to \u0027Enabled: Show warning and elevation prompt\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Printers/PointAndPrintRestrictions",
            "value": "\u003cenabled/\u003e\n\u003cdata id=\"PointAndPrint_TrustedServers_Chk\" value=\"false\"/\u003e\n\u003cdata id=\"PointAndPrint_TrustedServers_Edit\" value=\"\"/\u003e\n\u003cdata id=\"PointAndPrint_TrustedForest_Chk\" value=\"false\"/\u003e\n\u003cdata id=\"PointAndPrint_NoWarningNoElevationOnInstall_Enum\" value=\"0\"/\u003e\n\u003cdata id=\"PointAndPrint_NoWarningNoElevationOnUpdate_Enum\" value=\"0\"/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set asprescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\Software\Policies\Microsoft\WindowsNT\Printers\PointAndPrint:NoWarningNoElevationOnInstall

Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\Software\Policies\Microsoft\WindowsNT\Printers\PointAndPrint:UpdatePromptSettings
```

# 3.9.1 - Notifications

## 3.9.1.1 - 'Turn off toast notifications on the lock screen (User)' is set to 'Enabled' 

>[!NOTE]
>This policy setting turns off toast notifications on the lock screen

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Applications will not be able to raise toast notifications on the lock screen.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/WindowsLogon/DisableLockScreenAppNotifications
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Toast notifications on the lock screen are enabled and can be turned off by the administrator or user.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": " \u0027Turn off app notifications on the lock screen\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/WindowsLogon/DisableLockScreenAppNotifications",
            "value": "\u003cenabled/\u003e"
        },
```
```
Audit: 
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKU\[USERSID]\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications:NoToastApplicationNotificationOnLockScreen
```

# 3.10.4 - Audit Process Creation

## 3.10.4.1 - 'Include command line in process creation events' is set to 'Enabled' 

>[!NOTE]
>This policy setting controls whether the process creation command line text is logged in
security audit events when a new process has been created.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Process command line information will be included in the event logs, which can contain
sensitive or private information such as passwords or user data.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_AuditSettings/IncludeCmdLine
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Process command line information will not be included in Audit Process Creation events.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.8 Collect Command-Line Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.4 Encrypt or Hash all Authentication Credentials||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Include command line in process creation events\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_AuditSettings/IncludeCmdLine",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit: 
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit:ProcessCreationIncludeCmdLine_Enabled
```

# 3.10.5 - Credentials Delegation

## 3.10.5.1 - 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients' 

>[!NOTE]
>Some versions of the CredSSP protocol that is used by some applications (such as
Remote Desktop Connection) are vulnerable to an encryption oracle attack against the
client. This policy controls compatibility with vulnerable clients and servers and allows
you to set the level of protection desired for the encryption oracle vulnerability.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Client applications which use CredSSP will not be able to fall back to the insecure
versions and services using CredSSP will not accept unpatched clients. This setting
should not be deployed until all remote hosts support the newest version, which is
achieved by ensuring that all Microsoft security updates at least through May 2018 are
installed.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_CredSsp/AllowEncryptionOracle
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled|
| < enabled/> <data id="AllowEncryptionOracleDrop" value="0"/ > | Custom Settings (Recommended)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.5 Enable Anti-Exploitation Features||:orange_circle:|:large_blue_circle:|Level - 1|
|7|3.4 Deploy Automated Operating System Patch Management Tools|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Encryption Oracle Remediation\u0027 is set to \u0027Enabled: Force Updated Clients\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_CredSsp/AllowEncryptionOracle",
            "value": "\u003cenabled/\u003e\n\u003cdata id=\"AllowEncryptionOracleDrop\" value=\"0\"/\u003e"
        },
```

```
Audit: 
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters:AllowEncryptionOracle
```

## 3.10.5.2 - 'Remote host allows delegation of nonexportable credentials' is set to 'Enabled' 

>[!NOTE]
>Remote host allows delegation of non-exportable credentials. When using credential
delegation, devices provide an exportable version of credentials to the remote host. This
exposes users to the risk of credential theft from attackers on the remote host. The
Restricted Admin Mode and Windows Defender Remote Credential Guard features are
two options to help protect against this risk.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The host will support the Restricted Admin Mode and Windows Defender Remote
Credential Guard features.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/CredentialsDelegation/RemoteHostAllowsDelegationOfNonExportableCredentials
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Restricted Admin Mode and Windows Defender Remote Credential Guard are not supported. Users will always need to pass their credentials to the host.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Yet Mapped||||Level - 1|
|7|16.5 Encrypt Transmittal of Username and Authentication Credentials||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Remote host allows delegation of non-exportable credentials\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/CredentialsDelegation/RemoteHostAllowsDelegationOfNonExportableCredentials",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation:AllowProtectedCreds
```

# 3.10.9.1 - Device Installation Restrictions

## 3.10.9.2 - 'Prevent device metadata retrieval from the Internet' is set to 'Enabled' 
>[!NOTE]
>This policy setting allows you to prevent Windows from retrieving device metadata from
the Internet.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Standard users without administrator privileges will not be able to install associated
third-party utility software for peripheral devices. This may limit the use of advanced
features of those devices unless/until an administrator installs the associated utility
software for the device.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/DeviceInstallation/PreventDeviceMetadataFromNetwork
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (The setting in the Device Installation Settings dialog box controls whetherWindows retrieves device metadata from the Internet.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|2.5 Allowlist Authorized Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|10.5 Enable Anti-Exploitation Features||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Prevent device metadata retrieval from the Internet\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceInstallation/PreventDeviceMetadataFromNetwork",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceMetadata:PreventDeviceMetadataFromNetwork
```

# 3.10.13 - Early Launch Antimalware

## 3.10.13.1 - 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical' 

>[!NOTE]
>This policy setting allows you to specify which boot-start drivers are initialized based on
a classification determined by an Early Launch Antimalware boot-start driver. The Early
Launch Antimalware boot-start driver can return the following classifications for each
boot-start driver:
• Good: The driver has been signed and has not been tampered with.
• Bad: The driver has been identified as malware. It is recommended that you do
not allow known bad drivers to be initialized.
• Bad, but required for boot: The driver has been identified as malware, but the
computer cannot successfully boot without loading this driver.
• Unknown: This driver has not been attested to by your malware detection
application and has not been classified by the Early Launch Antimalware bootstart driver.
If you enable this policy setting you will be able to choose which boot-start drivers to
initialize the next time the computer is started.
If your malware detection application does not include an Early Launch Antimalware
boot-start driver or if your Early Launch Antimalware boot-start driver has been
disabled, this setting has no effect and all boot-start drivers are initialized.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/System/BootStartDriverInitialization
```
|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Boot-start drivers determined to be Good, Unknown or Bad but Boot Critical are initialized and the initialization of drivers determined to be bad is skipped.)|
| < enabled/> <data id="SelectDriverLoadPolicy" value="3"/ > | Custom Settings (Recommended)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.5 Enable Anti-Exploitation Features||:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.3 Enable Operating System Anti-Exploitation Features/Deploy Anti-Exploit Technologies||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Boot-Start Driver Initialization Policy\u0027 is set to \u0027Enabled: Good, unknown and bad but critical\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/System/BootStartDriverInitialization",
            "value": "\u003cenabled/\u003e\n\u003cdata id=\"SelectDriverLoadPolicy\" value=\"3\"/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 3.
HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch:DriverLoadPolicy
```
# 3.10.19 - Group Policy

## 3.10.19.1 - 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'

## 3.10.19.2 - 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'

## 3.10.19.3 - 'Configure security policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'

## 3.10.19.4 - 'Configure security policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'

>[!NOTE]
>The "Do not apply during periodic background processing" option prevents the system
from updating affected registry policies in the background while the computer is in use.
When background updates are disabled, registry policy changes will not take effect until
the next user logon or system restart.
This setting affects all policy settings within the Administrative Templates folder and any
other policies that store values in the registry.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Group Policy settings within the Administrative Templates folder (and other policies that
store values in the registry) will be reapplied even when the system is in use, which may
have a slight impact on performance.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_GroupPolicy/CSE_Registry
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Group policies are not reapplied until the next logon or restart or Group policies are not reapplied if they have not been changed.)|
| < enabled/> <data id="CSE_NOBACKGROUND10" value="false"/> <data id="CSE_NOCHANGES10" value="false"/ > | Custom Settings (Recommended)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.1 Establish and Maintain a Secure Configuration Process|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|5.4 Deploy System Configuration Management Tools||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Configure registry policy processing: Do not apply during periodic background processing\u0027 is set to \u0027Enabled: FALSE\u0027 \u0027Configure registry policy processing: Process even if the Group Policy objects have not changed\u0027 is set to \u0027Enabled: TRUE\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_GroupPolicy/CSE_Registry",
            "value": "\u003cenabled/\u003e\n\u003cdata id=\"CSE_NOBACKGROUND10\" value=\"false\"/\u003e\n\u003cdata id=\"CSE_NOCHANGES10\" value=\"false\"/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}:NoBackgroundPolicy

Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}:NoGPOListChanges

Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}:NoBackgroundPolicy

Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2- A4EA-00C04F79F83A}:NoGPOListChanges
```
## 3.10.19.5 - 'Continue experiences on this device' is set to 'Disabled

>[!NOTE]
>This policy setting determines whether the Windows device is allowed to participate in
cross-device experiences (continue experiences).

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The Windows device will not be discoverable by other devices, and cannot participate in
cross-device experiences..

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_GroupPolicy/EnableCDP
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Continue experiences on this device\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_GroupPolicy/EnableCDP",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit: 
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\System:EnableCdp
```

## 3.10.19.6 - 'Turn off background refresh of Group Policy' is set to 'Disabled'
>[!NOTE]
>This policy setting prevents Group Policy from being updated while the computer is in
use. This policy setting applies to Group Policy for computers, users and Domain
Controllers.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_GroupPolicy/DisableBackgroundPolicy
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Updates can be applied while users are working.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.1 Establish and Maintain a Secure Configuration Process|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|5.4 Deploy System Configuration Management Tools||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Turn off background refresh of Group Policy\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_GroupPolicy/DisableBackgroundPolicy",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with the key not existing.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:DisableBkGndGroupPolicy
```
# 3.10.20.1 - Internet Communication settings

## 3.10.20.1.2 - 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'

>[!NOTE]
>This policy setting controls whether the computer can download print driver packages
over HTTP. To set up HTTP printing, printer drivers that are not available in the
standard operating system installation might need to be downloaded over HTTP.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Print drivers cannot be downloaded over HTTP

```
OMA-URI (Device)
./User/Vendor/MSFT/Policy/Config/ADMX_ICM/DisableWebPnPDownload_1
```
|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled.(Users can download print drivers over HTTP.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Yet Mapped||||Level - 1|
|7|2.7 Utilize Application Whitelisting|||:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Turn off downloading of print drivers over HTTP\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./User/Vendor/MSFT/Policy/Config/ADMX_ICM/DisableWebPnPDownload_1",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers:DisableWebPnPDownload
```
## 3.10.20.1.5 - 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
>[!NOTE]
>This policy setting controls whether Windows will download a list of providers for the
Web publishing and online ordering wizards.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Windows is prevented from downloading providers; only the service providers cached in
the local registry are displayed.

```
OMA-URI (Device)
./User/Vendor/MSFT/Policy/Config/ADMX_ICM/ShellPreventWPWDownload_1
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (A list of providers is downloaded when the user uses the web publishing or online ordering wizards.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|7.4 Maintain and Enforce Network-Based URL Filters||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Turn off Internet download for Web publishing and online ordering wizards\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./User/Vendor/MSFT/Policy/Config/ADMX_ICM/ShellPreventWPWDownload_1",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoWebServices
```

# 3.10.25 - Logon

## 3.10.25.1 - 'Block user from showing account details on sign-in' is set to 'Enabled' 
>[!NOTE]
>This policy prevents the user from showing account details (email address or user
name) on the sign-in screen.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Users cannot choose to show account details on the sign-in screen.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_Logon/BlockUserFromShowingAccountDetailsOnSignin
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Users may choose to show account details on the sign-in screen.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.1 Establish and Maintain a Secure Configuration Process|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|5.1 Establish Secure Configurations|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Block user from showing account details on sign-in\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_Logon/BlockUserFromShowingAccountDetailsOnSignin",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\System:BlockUserFromShowingAccountDetailsOnSignin
```

## 3.10.25.2 - 'Do not display network selection UI' is set to 'Enabled' 
>[!NOTE]
>This policy setting allows you to control whether anyone can interact with available
networks UI on the logon screen.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The PC's network connectivity state cannot be changed without signing into Windows.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/WindowsLogon/DontDisplayNetworkSelectionUI
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Any user can disconnect the PC from the network or can connect the PC to other available networks without signing into Windows.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Yet Mapped||||Level - 1|
|8|Not Yet Mapped||||Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Do not display network selection UI\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/WindowsLogon/DontDisplayNetworkSelectionUI",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\System:DontDisplayNetworkSelectionUI
```

## 3.10.25.3 - 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'

>[!NOTE]
>This policy setting prevents connected users from being enumerated on domain-joined
computers.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The Logon UI will not enumerate any connected users on domain-joined computers

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_Logon/DontEnumerateConnectedUsers
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Connected users will be enumerated on domain-joined computers.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Yet Mapped||||Level - 1|
|8|Not Yet Mapped||||Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Do not enumerate connected users on domain-joined computers\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_Logon/DontEnumerateConnectedUsers",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\System:DontEnumerateConnectedUsers
```

## 3.10.25.4 - 'Enumerate local users on domain-joined computers' is set to 'Disabled'

>[!NOTE]
>This policy setting allows local users to be enumerated on domain-joined computers.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/WindowsLogon/EnumerateLocalUsersOnDomainJoinedComputers
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (The Logon UI will not enumerate local users on domain-joined computers.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Yet Mapped||||Level - 1|
|8|Not Yet Mapped||||Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Enumerate local users on domain-joined computers\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/WindowsLogon/EnumerateLocalUsersOnDomainJoinedComputers",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\System:EnumerateLocalUsers
```

## 3.10.25.5 - 'Turn off app notifications on the lock screen' is set to 'Enabled' 

>[!NOTE]
>This policy setting allows you to prevent app notifications from appearing on the lock
screen.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>No app notifications are displayed on the lock screen.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/WindowsLogon/DisableLockScreenAppNotifications
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Users can choose which apps display notifications on the lock screen.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Turn off app notifications on the lock screen\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/WindowsLogon/DisableLockScreenAppNotifications",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1. 
HKLM\SOFTWARE\Policies\Microsoft\Windows\System:DisableLockScreenAppNotifications

```

## 3.10.25.6 - 'Turn off picture password sign-in' is set to 'Enabled' 

>[!NOTE]
>This policy setting allows you to control whether a domain user can sign in using a
picture password.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Users will not be able to set up or sign in with a picture password.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/CredentialProviders/BlockPicturePassword
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Users can set up and use a picture password.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Turn off picture password sign-in\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/CredentialProviders/BlockPicturePassword",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\System:BlockDomainPicturePassword
```

## 3.10.25.7 - 'Turn on convenience PIN sign-in' is set to 'Disabled'

>[!NOTE]
>This policy setting allows you to control whether a user can sign in using a convenience
PIN.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/CredentialProviders/AllowPINLogon
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled.(Users can set up and use a picture password.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Turn on convenience PIN sign-in\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/CredentialProviders/AllowPINLogon",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\System:AllowDomainPINLogon
```

# 3.10.28.5 - Sleep Settings

## 3.10.28.5.1 - 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'

>[!NOTE]
>This policy setting allows you to control the network connectivity state in standby on
modern standby-capable systems.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Network connectivity in standby (while on battery) is not guaranteed. This connectivity
restriction currently only applies to WLAN networks only, but is subject to change
(according to Microsoft).

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_Power/DCConnectivityInStandby_2
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled. (Network connectivity will be maintained in standby while on battery.)|
| < disabled/ > |Disabled|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|9.2 Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|
|8|Not Yet Mapped||||Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": \u0027Allow network connectivity during connected-standby (on battery)\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_Power/DCConnectivityInStandby_2",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9:DCSettingIndex
```

## 3.10.28.5.2 - 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'

>[!NOTE]
>This policy setting allows you to control the network connectivity state in standby on
modern standby-capable systems.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Network connectivity in standby (while on battery) is not guaranteed. This connectivity
restriction currently only applies to WLAN networks only, but is subject to change
(according to Microsoft).

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_Power/ACConnectivityInStandby_2
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled. (Network connectivity will be maintained in standby while plugged in).|
| < disabled/ > |Disabled|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|9.2 Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|
|8|Not Yet Mapped||||Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Allow network connectivity during connected-standby (plugged in)\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_Power/ACConnectivityInStandby_2",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9:ACSettingIndex
```

## 3.10.28.5.5 - 'Require a password when a computer wakes (on battery)' is set to 'Enabled'

>[!NOTE]
>Specifies whether or not the user is prompted for a password when the system resumes
from sleep.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

|Value|Description|
|---|---|
| < enabled/ > |Enabled. (The user is prompted for a password when the system resumes from sleep while on battery.)|
| < disabled/ > |Disabled|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle|:orange_circle:|:large_blue_circle:|Level - 1|
|8|Not Yet Mapped||||Level - 1|

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/Power/RequirePasswordWhenComputerWakesOnBattery
```

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Require a password when a computer wakes (on battery)\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Power/RequirePasswordWhenComputerWakesOnBattery",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51:DCSettingIndex
```

## 3.10.28.5.6 - 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'

>[!NOTE]
>Specifies whether or not the user is prompted for a password when the system resumes
from sleep.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None
```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/Power/RequirePasswordWhenComputerWakesOnBattery
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled. (The user is prompted for a password when the system resumes from sleep while plugged in.)|
| < disabled/ > |Disabled|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle|:orange_circle:|:large_blue_circle:|Level - 1|
|8|Not Yet Mapped||||Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Require a password when a computer wakes (plugged in)\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Power/RequirePasswordWhenComputerWakesPluggedIn",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51:ACSettingIndex
```

# 3.10.29 - Remote Assistance

## 3.10.29.1 - 'Configure Offer Remote Assistance' is set to 'Disabled'

>[!NOTE]
>This policy setting allows you to turn on or turn off Offer (Unsolicited) Remote Assistance on this computer.
Help desk and support personnel will not be able to proactively offer assistance,
although they can still respond to user assistance requests.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None
```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/RemoteAssistance/UnsolicitedRemoteAssistance
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled.|
| < disabled/ > |Disabled. (Users on this computer cannot get help from their corporate technical support staff using Offer (Unsolicited) Remote Assistance.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Configure Offer Remote Assistance\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/RemoteAssistance/UnsolicitedRemoteAssistance",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fAllowUnsolicited
```

## 3.10.29.2 - 'Configure Solicited Remote Assistance' is set to 'Disabled'

>[!NOTE]
>This policy setting allows you to turn on or turn off Solicited (Ask for) Remote Assistance
on this computer.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Users on this computer cannot use e-mail or file transfer to ask someone for help. Also,
users cannot use instant messaging programs to allow connections to this computer

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/RemoteAssistance/SolicitedRemoteAssistance
```

|Value|Description|
|---|---|
| < enabled/ > |Users can turn on or turn off Solicited (Ask for) Remote Assistance themselves in System Properties in Control Panel. Users can also configure Remote Assistance settings.|
| < disabled/ > |Disabled.|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Configure Solicited Remote Assistance\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/RemoteAssistance/SolicitedRemoteAssistance",
            "value": "\u003cdisabled/\u003e"
        },,
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fAllowToGetHelp
```

# 3.10.30 - Remote Procedure Call

## 3.10.30.1 - 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'

>[!NOTE]
>This policy setting controls whether RPC clients authenticate with the Endpoint Mapper
Service when the call they are making contains authentication information. The
Endpoint Mapper Service on computers running Windows NT4 (all service packs)
cannot process authentication information supplied in this manner. This policy setting
can cause a specific issue with 1-way forest trusts if it is applied to the trusting domain
DCs (see Microsoft KB3073942), so we do not recommend applying it to Domain
Controllers

>[!TIP]
>Automated Remedation

>[!CAUTION]
>RPC clients will authenticate to the Endpoint Mapper Service for calls that contain
authentication information. Clients making such calls will not be able to communicate
with the Windows NT4 Server Endpoint Mapper Service.


```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/RemoteProcedureCall/RPCEndpointMapperClientAuthentication
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (RPC clients will not authenticate to the Endpoint Mapper Service, but they will be able to communicate with the Windows NT4 Server Endpoint Mapper Service.).|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|7|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Enable RPC Endpoint Mapper Client Authentication\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/RemoteProcedureCall/RPCEndpointMapperClientAuthentication",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc:EnableAuthEpResolution
```

## 3.10.30.2 - 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'

>[!NOTE]
>This policy setting controls how the RPC server runtime handles unauthenticated RPC
clients connecting to RPC servers.
This policy setting impacts all RPC applications. In a domain environment this policy
setting should be used with caution as it can impact a wide range of functionality
including group policy processing itself. Reverting a change to this policy setting can
require manual intervention on each affected machine. This policy setting should
never be applied to a Domain Controller.
A client will be considered an authenticated client if it uses a named pipe to
communicate with the server or if it uses RPC Security. RPC Interfaces that have
specifically requested to be accessible by unauthenticated clients may be exempt from
this restriction, depending on the selected value for this policy setting.
-- "None" allows all RPC clients to connect to RPC Servers running on the machine on
which the policy setting is applied.
-- "Authenticated" allows only authenticated RPC Clients (per the definition above) to
connect to RPC Servers running on the machine on which the policy setting is applied.
Exemptions are granted to interfaces that have requested them.
-- "Authenticated without exceptions" allows only authenticated RPC Clients (per the
definition above) to connect to RPC Servers running on the machine on which the policy
setting is applied. No exceptions are allowed. This value has the potential to cause
serious problems and is not recommended.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/RemoteProcedureCall/RestrictUnauthenticatedRPCClients
```
|Value|Description|
|---|---|
| < enabled/ > |Enabled: Authenticated. (Only authenticated RPC clients are allowed to connect to RPC servers running on the machine. Exemptions are granted to interfaces that have requested them.)|
| < disabled/ > |Disabled|
| < enabled/ > <data id="RpcRestrictRemoteClientsList" value="1"/> | Custom Settings (Recommended} |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|7|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Restrict Unauthenticated RPC clients\u0027 is set to \u0027Enabled: Authenticated\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/RemoteProcedureCall/RestrictUnauthenticatedRPCClients",
            "value": "\u003cenabled/\u003e\n\u003cdata id=\"RpcRestrictRemoteClientsList\" value=\"1\"/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc:RestrictRemoteClients
```

# 3.10.42.1 - Time Providers

## 3.10.42.1.1 - 'Enable Windows NTP Client' is set to 'Enabled' 

>[!NOTE]
>This policy setting specifies whether the Windows NTP Client is enabled. Enabling the
Windows NTP Client allows synchronization from a systems computer clock to NTP
server(s).

>[!TIP]
>Automated Remedation

>[!CAUTION]
>System time will be synced to the configured NTP server(s)

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_W32Time/W32TIME_POLICY_ENABLE_NTPCLIENT
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (The local computer clock does not synchronize time with NTP servers.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.4 Standardize Time Synchronization||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.1 Utilize Three Synchronized Time Sources||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "displayName": "\u0027Enable Windows NTP Client\u0027 is set to \u0027Enabled\u0027",",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_W32Time/W32TIME_POLICY_ENABLE_NTPCLIENT",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient:Enabled
```

## 3.10.42.1.2 - 'Enable Windows NTP Server' is set to 'Disabled' 

>[!NOTE]
>This policy setting specifies whether the Windows NTP Server is enabled. Disabling this
setting prevents the system from acting as a NTP Server (time source) to service NTP
requests from other systems (NTP Clients).

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (The computer cannot service NTP requests from other computers.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.4 Standardize Time Synchronization||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.1 Utilize Three Synchronized Time Sources||:orange_circle:|:large_blue_circle:|Level - 1|

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_W32Time/W32TIME_POLICY_ENABLE_NTPSERVER
```

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "displayName": "\u0027Enable Windows NTP Server\u0027 is set to \u0027Disabled\u0027",",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_W32Time/W32TIME_POLICY_ENABLE_NTPSERVER",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer:Enabled
```

# 3.11.3 - App runtime

## 3.11.3.1 - 'Allow Microsoft accounts to be optional' is set to 'Enabled

>[!NOTE]
>This policy setting lets you control whether Microsoft accounts are optional for Windows
Store apps that require an account to sign in. This policy only affects Windows Store
apps that support it.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Windows Store apps that typically require a Microsoft account to sign in will allow users
to sign in with an enterprise account instead

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Users will need to sign in with a Microsoft account.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|5.6 Centralize Account Management||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.2 Configure Centralized Point of Authentication||:orange_circle:|:large_blue_circle:|Level - 1|

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/AppRuntime/AllowMicrosoftAccountsToBeOptional
```

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Allow Microsoft accounts to be optional\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/AppRuntime/AllowMicrosoftAccountsToBeOptional",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:MSAOptional
```

# 3.11.5 - Attachment Manager

## 3.11.5.1 - 'Do not preserve zone information in file attachments (User)' is set to 'Disabled'

>[!NOTE]
>This policy setting allows you to manage whether Windows marks file attachments with
information about their zone of origin (such as restricted, Internet, intranet, local). This
requires NTFS in order to function correctly, and will fail without notice on FAT32. By
not preserving the zone information, Windows cannot make proper risk assessments.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (User)
./User/Vendor/MSFT/Policy/Config/AttachmentManager/DoNotPreserveZoneInformation
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Windows marks file attachments with their zone information.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Yet Mapped|||||
|8|Not Yet Mapped|||||

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Do not preserve zone information in file attachments\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./User/Vendor/MSFT/Policy/Config/AttachmentManager/DoNotPreserveZoneInformation",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 2.
HKU\[USERSID]\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments:SaveZoneInformation
```

## 3.11.5.2 - 'Notify antivirus programs when opening attachments (User)' is set to 'Enabled'

>[!NOTE]
>This policy setting manages the behavior for notifying registered antivirus programs. If
multiple programs are registered, they will all be notified.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Windows tells the registered antivirus program(s) to scan the file when a user opens a
file attachment. If the antivirus program fails, the attachment is blocked from being
opened.

```
OMA-URI (User)
./User/Vendor/MSFT/Policy/Config/AttachmentManager/NotifyAntivirusPrograms
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Windows does not call the registered antivirus program(s) when file attachments are opened.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.1 Deploy and Maintain Anti-Malware Software|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.1 Utilize Centrally Managed Anti-malware Software||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Notify antivirus programs when opening attachments\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./User/Vendor/MSFT/Policy/Config/AttachmentManager/NotifyAntivirusPrograms",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 3.
HKU\[USERSID]\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments:ScanWithAntiVirus
```

# 3.11.6 - AutoPlay Policies

## 3.11.6.1 - 'Disallow Autoplay for non-volume devices' is set to 'Enabled' 

>[!NOTE]
>This policy setting disallows AutoPlay for MTP devices like cameras or phones.


>[!TIP]
>Automated Remedation

>[!CAUTION]
>AutoPlay will not be allowed for MTP devices like cameras or phones.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/Autoplay/DisallowAutoplayForNonVolumeDevices
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (AutoPlay is enabled for non-volume devices.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.3 Disable Autorun and Autoplay for Removable Media|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7| 8.5 Configure Devices Not To Auto-run Content|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Disallow Autoplay for non-volume devices\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Autoplay/DisallowAutoplayForNonVolumeDevices",
            "value": "\u003cenabled/\u003e"
        },
```


```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer:NoAutoplayfornonVolume
```
## 3.11.6.2 - 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'

>[!NOTE]
>This policy setting sets the default behavior for Autorun commands.


>[!TIP]
>Automated Remedation

>[!CAUTION]
>AutoRun commands will be completely disabled.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/Autoplay/SetDefaultAutoRunBehavior
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Windows will prompt the user whether autorun command is to be run.)|
| < enabled/ >< data id="NoAutorun_Dropdown" value="1"/ > |Custom Settings (Recommended)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.3 Disable Autorun and Autoplay for Removable Media|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7| 8.5 Configure Devices Not To Auto-run Content|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Set the default behavior for AutoRun\u0027 is set to \u0027Enabled: Do not execute any autorun commands\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Autoplay/SetDefaultAutoRunBehavior",
            "value": "\u003cenabled/\u003e\u003cdata id=\"NoAutorun_Dropdown\" value=\"1\"/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoAutorun
```
## 3.11.6.3 - 'Turn off Autoplay' is set to 'Enabled: All drives'

>[!NOTE]
>Autoplay starts to read from a drive as soon as you insert media in the drive, which
causes the setup file for programs or audio media to start immediately. An attacker
could use this feature to launch a program to damage the computer or data on the
computer. Autoplay is disabled by default on some removable drive types, such as
floppy disk and network drives, but not on CD-ROM drives.


>[!TIP]
>Automated Remedation

>[!CAUTION]
>Autoplay will be disabled - users will have to manually launch setup or installation
programs that are provided on removable media.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/Autoplay/TurnOffAutoPlay
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Autoplay is enabled.)|
| < enabled/ > < data id="Autorun_Box" value="255"/ > |Custom Settings (Recommended)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.3 Disable Autorun and Autoplay for Removable Media|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7| 8.5 Configure Devices Not To Auto-run Content|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Turn off Autoplay\u0027 is set to \u0027Enabled: All drives\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Autoplay/TurnOffAutoPlay",
            "value": "\u003cenabled/\u003e\n\u003cdata id=\"Autorun_Box\" value=\"255\"/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 255.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoDriveTypeAutoRun
```

## 3.11.8 - Credential User Interface

## 3.11.8.1 - 'Do not display the password reveal button' is set to 'Enabled' 

>[!NOTE]
>This policy setting allows you to configure the display of the password reveal button in
password entry user experiences.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The password reveal button will not be displayed after a user types a password in the
password entry text box.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/Autoplay/TurnOffAutoPlay
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (The password reveal button is displayed after a user types a password in the password entry text box. If the user clicks on the button, the typed password is displayed on-screen in plain text.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Yet Mapped|||||
|8|Not Yet Mapped|||||

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Do not display the password reveal button\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/CredentialsUI/DisablePasswordReveal",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI:DisablePasswordReveal
```

## 3.11.8.2 - 'Enumerate administrator accounts on elevation' is set to 'Disabled'

>[!NOTE]
>This policy setting controls whether administrator accounts are displayed when a user
attempts to elevate a running application.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/CredentialsUI/EnumerateAdministrators
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Users will be required to always type in a username and password to elevate.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Yet Mapped|||||
|8|Not Yet Mapped|||||

```
Script:
       {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Enumerate administrator accounts on elevation\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/CredentialsUI/EnumerateAdministrators",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI:EnumerateAdministrators
```

## 3.11.8.3 - 'Prevent the use of security questions for local accounts' is set to 'Enabled'

>[!NOTE]
>This policy setting controls whether security questions can be used to reset local
account passwords. The security question feature does not apply to domain accounts,
only local accounts on the workstation.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Local user accounts will not be able to set up and use security questions to reset their
passwords.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_CredUI/NoLocalPasswordResetQuestions
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Not Configured. (Local user accounts are able to set up and use security questions to reset their passwords.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Yet Mapped|||||
|8|Not Yet Mapped|||||

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "18.9.16.3 (L1) Ensure \u0027Prevent the use of security questions for local accounts\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_CredUI/NoLocalPasswordResetQuestions",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\System:NoLocalPasswordResetQuestions
```

# 3.11.15.1 - Application

## 3.11.15.1.1 - 'Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'

>[!NOTE]
>This policy setting controls Event Log behavior when the log file reaches its maximum
size

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_Log_AutoBackup_1
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (When a log file reaches its maximum size, new events overwrite old events.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.3 Ensure Adequate Audit Log Storage|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.4 Ensure adequate storage for logs||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Application: Control Event Log behavior when the log file reaches its maximum size\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_Log_AutoBackup_1",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_SZ value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application:Retention
```
## 3.11.15.1.2 - 'Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater

>[!NOTE]
>This policy setting specifies the maximum size of the log file in kilobytes. The maximum
log file size can be configured between 1 megabyte (1,024 kilobytes) and 4 terabytes
(4,194,240 kilobytes) in kilobyte increments.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>When event logs fill to capacity, they will stop recording information unless the retention
method for each is set so that the computer will overwrite the oldest entries with the
most recent ones. To mitigate the risk of loss of recent data, you can configure the
retention method so that older events are overwritten as needed.
The consequence of this configuration is that older events will be removed from the
logs. Attackers can take advantage of such a configuration, because they can generate
a large number of extraneous events to overwrite any evidence of their attack. These
risks can be somewhat reduced if you automate the archival and backup of event log
data.
Ideally, all specifically monitored events should be sent to a server that uses Microsoft
System Center Operations Manager (SCOM) or some other automated monitoring tool.
Such a configuration is particularly important because an attacker who successfully
compromises a server could clear the Security log. If all events are sent to a monitoring
server, then you will be able to gather forensic information about the attacker's activities.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_Log_AutoBackup_1
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (The default log size is 20,480 KB - this value can be changed by the local administrator using the Log Properties dialog.)|
| < enabled/ > < data id="Channel_LogMaxSize" value="102400"/ >|Custom Settings (Recommended) |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.3 Ensure Adequate Audit Log Storage|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.4 Ensure adequate storage for logs||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Application: Specify the maximum log file size (KB)\u0027 is set to \u0027Enabled: 32,768 or greater\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/EventLogService/SpecifyMaximumFileSizeApplicationLog",
            "value": "\u003cenabled/\u003e\n\u003cdata id=\"Channel_LogMaxSize\" value=\"102400\"/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 32768 or greater.
HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application:MaxSize
```

# 3.11.15.2 - Security

## 3.11.15.2.1 - 'Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled

>[!NOTE]
>This policy setting controls Event Log behavior when the log file reaches its maximum
size.


>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_Log_AutoBackup_1
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (When a log file reaches its maximum size, new events overwrite old events.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.3 Ensure Adequate Audit Log Storage|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.4 Ensure adequate storage for logs||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
		{
			"@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Application: Control Event Log behavior when the log file reaches its maximum size\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_Log_AutoBackup_1",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_SZ value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security:Retention
```

## 3.11.15.2.2 - 'Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'

>[!NOTE]
>This policy setting specifies the maximum size of the log file in kilobytes. The maximum
log file size can be configured between 1 megabyte (1,024 kilobytes) and 4 terabytes
(4,194,240 kilobytes) in kilobyte increments.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>When event logs fill to capacity, they will stop recording information unless the retention
method for each is set so that the computer will overwrite the oldest entries with the
most recent ones. To mitigate the risk of loss of recent data, you can configure the
retention method so that older events are overwritten as needed.
The consequence of this configuration is that older events will be removed from the
logs. Attackers can take advantage of such a configuration, because they can generate
a large number of extraneous events to overwrite any evidence of their attack. These
risks can be somewhat reduced if you automate the archival and backup of event log
data.
Ideally, all specifically monitored events should be sent to a server that uses Microsoft
System Center Operations Manager (SCOM) or some other automated monitoring tool.
Such a configuration is particularly important because an attacker who successfully
compromises a server could clear the Security log. If all events are sent to a monitoring
server, then you will be able to gather forensic information about the attacker's activities.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/EventLogService/SpecifyMaximumFileSizeSecurityLog
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (The default log size is 20,480 KB - this value can be changed by the local administrator using the Log Properties dialog.)|
| < enabled/ > < data id="Channel_LogMaxSize" value="2097152"/ > |Custom Settings (Recommended) |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.3 Ensure Adequate Audit Log Storage|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.4 Ensure adequate storage for logs||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Security: Specify the maximum log file size (KB)\u0027 is set to \u0027Enabled: 196,608 or greater\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/EventLogService/SpecifyMaximumFileSizeSecurityLog",
            "value": "\u003cenabled/\u003e\u003cdata id=\"Channel_LogMaxSize\" value=\"2097152\"/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 196608 or greater.
HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security:MaxSize
```
# 3.11.15.3 - Setup

## 3.11.15.3.1 - 'Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled' 

>[!NOTE]
>This policy setting controls Event Log behavior when the log file reaches its maximum
size.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_Log_AutoBackup_2
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (When a log file reaches its maximum size, new events overwrite old events.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.3 Ensure Adequate Audit Log Storage|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.4 Ensure adequate storage for logs||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Security: Control Event Log behavior when the log file reaches its maximum size\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_Log_AutoBackup_2",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_SZ value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup:Retention
```

## 3.11.15.3.2 - 'Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'

>[!NOTE]
>This policy setting specifies the maximum size of the log file in kilobytes. The maximum
log file size can be configured between 1 megabyte (1,024 kilobytes) and 4 terabytes
(4,194,240 kilobytes) in kilobyte increments.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>When event logs fill to capacity, they will stop recording information unless the retention
method for each is set so that the computer will overwrite the oldest entries with the
most recent ones. To mitigate the risk of loss of recent data, you can configure the
retention method so that older events are overwritten as needed.
The consequence of this configuration is that older events will be removed from the
logs. Attackers can take advantage of such a configuration, because they can generate
a large number of extraneous events to overwrite any evidence of their attack. These
risks can be somewhat reduced if you automate the archival and backup of event log
data.
Ideally, all specifically monitored events should be sent to a server that uses Microsoft
System Center Operations Manager (SCOM) or some other automated monitoring tool.
Such a configuration is particularly important because an attacker who successfully
compromises a server could clear the Security log. If all events are sent to a monitoring
server, then you will be able to gather forensic information about the attacker's activities.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_LogMaxSize_3
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (The default log size is 20,480 KB - this value can be changed by the local administrator using the Log Properties dialog.)|
| < enabled/ > <data id="Channel_LogMaxSize" value="102400"/ > |Custom Settings (Recommended) |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.3 Ensure Adequate Audit Log Storage|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.4 Ensure adequate storage for logs||:orange_circle:|:large_blue_circle:|Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Setup: Specify the maximum log file size (KB)\u0027 is set to \u0027Enabled: 32,768 or greater\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_LogMaxSize_3",
            "value": "\u003cenabled/\u003e\u003cdata id=\"Channel_LogMaxSize\" value=\"102400\"/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 32768 or greater.
HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup:MaxSize
```

# 3.11.15.4 - System

## 3.11.15.4.1 - 'Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled' 

>[!NOTE]
>This policy setting controls Event Log behavior when the log file reaches its maximum
size.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_Log_AutoBackup_4
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (When a log file reaches its maximum size, new events overwrite old events.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.3 Ensure Adequate Audit Log Storage|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.4 Ensure adequate storage for logs||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027System: Control Event Log behavior when the log file reaches its maximum size\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_Log_AutoBackup_4",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_SZ value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System:Retention
```

## 3.11.15.4.2 - 'Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater' 

>[!NOTE]
>This policy setting specifies the maximum size of the log file in kilobytes. The maximum
log file size can be configured between 1 megabyte (1,024 kilobytes) and 4 terabytes
(4,194,240 kilobytes) in kilobyte increments.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>When event logs fill to capacity, they will stop recording information unless the retention
method for each is set so that the computer will overwrite the oldest entries with the
most recent ones. To mitigate the risk of loss of recent data, you can configure the
retention method so that older events are overwritten as needed.
The consequence of this configuration is that older events will be removed from the
logs. Attackers can take advantage of such a configuration, because they can generate
a large number of extraneous events to overwrite any evidence of their attack. These
risks can be somewhat reduced if you automate the archival and backup of event log
data.
Ideally, all specifically monitored events should be sent to a server that uses Microsoft
System Center Operations Manager (SCOM) or some other automated monitoring tool.
Such a configuration is particularly important because an attacker who successfully
compromises a server could clear the Security log. If all events are sent to a monitoring
server, then you will be able to gather forensic information about the attacker's activities.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/EventLogService/SpecifyMaximumFileSizeSystemLog
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (The default log size is 20,480 KB - this value can be changed by the local administrator using the Log Properties dialog.)|
| < enabled/ > < data id="Channel_LogMaxSize" value="204800"/ >| Custom Settings (Recommended) |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.3 Ensure Adequate Audit Log Storage|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.4 Ensure adequate storage for logs||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027System: Specify the maximum log file size (KB)\u0027 is set to \u0027Enabled: 32,768 or greater\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/EventLogService/SpecifyMaximumFileSizeSystemLog",
            "value": "\u003cenabled/\u003e\u003cdata id=\"Channel_LogMaxSize\" value=\"204800\"/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 32768 or greater.
HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System:MaxSize
```

# 3.11.18 - File Explorer

## 3.11.18.1 -'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'

>[!NOTE]
>This policy setting allows you to manage the behavior of Windows Defender
SmartScreen. Windows Defender SmartScreen helps keep PCs safer by warning users
before running unrecognized programs downloaded from the Internet. Some information
is sent to Microsoft about files and programs run on PCs with this feature enabled.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Users will be warned and prevented from running unrecognized programs downloaded
from the Internet.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/SmartScreen/EnableSmartScreenInShell
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Windows Defender SmartScreen behavior is managed by administrators on the PC by using Windows Defender SmartScreen Settings in Action Center.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.5 Enable Anti-Exploitation Features||:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.3 Enable Operating System Anti-Exploitation Features/ Deploy Anti-Exploit Technologies||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Configure Windows Defender SmartScreen\u0027 is set to \u0027Enabled: Warn and prevent bypass\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/SmartScreen/EnableSmartScreenInShell",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry locations with a REG_DWORD value of 1:
HKLM\SOFTWARE\Policies\Microsoft\Windows\System:EnableSmartScreen
```

## 3.11.18.2 - 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'

>[!NOTE]
>Disabling Data Execution Prevention can allow certain legacy plug-in applications to
function without terminating Explorer.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/FileExplorer/TurnOffDataExecutionPreventionForExplorer
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Data Execution Prevention will block certain types of malware from exploiting Explorer.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.5 Enable Anti-Exploitation Features||:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.3 Enable Operating System Anti-Exploitation Features/ Deploy Anti-Exploit Technologies||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Turn off Data Execution Prevention for Explorer\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/FileExplorer/TurnOffDataExecutionPreventionForExplorer",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer:NoDataExecutionPrevention
```

## 3.11.18.3 - 'Turn off heap termination on corruption' is set to 'Disabled'

>[!NOTE]
>Without heap termination on corruption, legacy plug-in applications may continue to
function when a File Explorer session has become corrupt. Ensuring that heap
termination on corruption is active will prevent this.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/FileExplorer/TurnOffHeapTerminationOnCorruption
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Heap termination on corruption is enabled.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Turn off heap termination on corruption\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/FileExplorer/TurnOffHeapTerminationOnCorruption",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0
HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer:NoHeapTerminationOnCorruption
```

## 3.11.18.4 - 'Turn off shell protocol protected mode' is set to 'Disabled'

>[!NOTE]
>This policy setting allows you to configure the amount of functionality that the shell
protocol can have. When using the full functionality of this protocol, applications can
open folders and launch files. The protected mode reduces the functionality of this
protocol allowing applications to only open a limited set of folders. Applications are not
able to open files with this protocol when it is in the protected mode. It is recommended
to leave this protocol in the protected mode to increase the security of Windows.


>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_WindowsExplorer/ShellProtocolProtectedModeTitle_2
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (The protocol is in the protected mode, allowing applications to only open a limited set of folders.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.3 Enable Operating System Anti-Exploitation Features/Deploy Anti-Exploit Technologies ||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Turn off shell protocol protected mode\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_WindowsExplorer/ShellProtocolProtectedModeTitle_2",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:PreXPSP2ShellProtocolBehavior
```
# 3.11.20 - Home Group


## 3.11.20.1 - 'Prevent the computer from joining a homegroup' is set to 'Enabled'

>[!NOTE]
>By default, users can add their computer to a HomeGroup on a home network


>[!TIP]
>Automated Remedation

>[!CAUTION]
>A user on this computer will not be able to add this computer to a HomeGroup. This
setting does not affect other network sharing features. Mobile users who access printers
and other shared devices on their home networks will not be able to leverage the ease
of use provided by HomeGroup functionality.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_Sharing/DisableHomeGroup
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (A user can add their computer to a HomeGroup. However, data on a domainjoined computer is not shared with the HomeGroup.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Prevent the computer from joining a homegroup\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_Sharing/DisableHomeGroup",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\HomeGroup:DisableHomeGroup
```

# 3.11.27 - Microsoft Account

## 3.11.27.1 - 'Block all consumer Microsoft account user authentication' is set to 'Enabled' 

>[!NOTE]
>This setting determines whether applications and services on the device can utilize new
consumer Microsoft account authentication via the Windows OnlineID and
WebAccountManager APIs.


>[!TIP]
>Automated Remedation

>[!CAUTION]
>All applications and services on the device will be prevented from new authentications
using consumer Microsoft accounts via the Windows OnlineID and WebAccountManager
APIs. Authentications performed directly by the user in web browsers or in apps that
use OAuth will remain unaffected.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_MSAPolicy/MicrosoftAccount_DisableUserAuth
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Applications and services on the device will be permitted to authenticate using consumer Microsoft accounts via the Windows OnlineID and WebAccountManager APIs.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|5.6 Centralize Account Management||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.8 Disable Any Unassociated Accounts|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Block all consumer Microsoft account user authentication\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_MSAPolicy/MicrosoftAccount_DisableUserAuth",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount:DisableUserAuth
```

# 3.11.28.3 - MAPS

## 3.11.28.3.1 - 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'

>[!NOTE]
>This policy setting configures a local override for the configuration to join Microsoft
Active Protection Service (MAPS), which Microsoft renamed to Windows Defender
Antivirus Cloud Protection Service and then Microsoft Defender Antivirus Cloud
Protection Service. This setting can only be set by Group Policy.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_MicrosoftDefenderAntivirus/Spynet_LocalSettingOverrideSpynetReporting
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Group Policy will take priority over the local preference setting.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Ensure Only Approved Ports, Protocols and Services Are Running|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Configure local setting override for reporting to Microsoft MAPS\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_MicrosoftDefenderAntivirus/Spynet_LocalSettingOverrideSpynetReporting",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\WindowsDefender\Spynet:LocalSettingOverrideSpynetReporting
```

# 3.11.28.10 - Reporting

## 3.11.28.11 - 'Turn off Microsoft Defender Antivirus' is set to 'Disabled'

>[!NOTE]
>This policy setting turns off Microsoft Defender Antivirus. If the setting is configured to
Disabled, Microsoft Defender Antivirus runs and computers are scanned for malware
and other potentially unwanted software

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_MicrosoftDefenderAntivirus/DisableAntiSpywareDefender
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Microsoft Defender Antivirus runs and computers are scanned for malware and other potentially unwanted software.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.1 Deploy and Maintain Anti-Malware Software|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.1 Utilize Centrally Managed Anti-malware Software|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Turn off Microsoft Defender Antivirus\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_MicrosoftDefenderAntivirus/DisableAntiSpywareDefender",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender:DisableAntiSpyware
```

## 3.11.31.1 - 'Prevent users from sharing files within their profile. (User)' is set to 'Enabled'

>[!NOTE]
>This policy setting determines whether users can share files within their profile. By
default, users are allowed to share files within their profile to other users on their
network after an administrator opts in the computer. An administrator can opt in the
computer by using the sharing wizard to share a file within their profile.


>[!TIP]
>Automated Remedation

>[!CAUTION]
>Users cannot share files within their profile using the sharing wizard. Also, the sharing
wizard cannot create a share at %root%\Users and can only be used to create SMB
shares on folders.

```
OMA-URI (User)
./User/Vendor/MSFT/Policy/Config/ADMX_Sharing/NoInplaceSharing
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Users can share files out of their user profile after an administrator has opted in the computer.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Mapped Yet|||||
|7|14.6 Protect Information through Access Control Lists|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Prevent users from sharing files within their profile\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./User/Vendor/MSFT/Policy/Config/ADMX_Sharing/NoInplaceSharing",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKU\[USERSID]\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoInplaceSharing
```

# 3.11.36.3.1 - RemoteFX USB Device Redirection

## 3.11.36.3.2 - 'Do not allow passwords to be saved' is set to 'Enabled' 

>[!NOTE]
>This policy setting helps prevent Remote Desktop clients from saving passwords on a
computer.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The password saving checkbox will be disabled for Remote Desktop clients and users
will not be able to save passwords.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/DoNotAllowPasswordSavingg
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Users will be able to save passwords using Remote Desktop Connection.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Mapped Yet|||||
|8|Not Mapped Yet|||||

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Do not allow passwords to be saved\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/DoNotAllowPasswordSaving",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\TerminalServices:DisablePasswordSaving

```

# 3.11.36.4.3 - Device and Resource Redirection

## 3.11.36.4.3.2 - 'Do not allow drive redirection' is set to 'Enabled'

>[!NOTE]
>This policy setting prevents users from sharing the local drives on their client computers
to Remote Desktop Servers that they access. Mapped drives appear in the session
folder tree in Windows Explorer in the following format:
\\TSClient\<driveletter>$
If local drives are shared they are left vulnerable to intruders who want to exploit the
data that is stored on them.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Drive redirection will not be possible. In most situations, traditional network drive
mapping to file shares (including administrative shares) performed manually by the
connected user will serve as a capable substitute to still allow file transfers when
needed.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/DoNotAllowDriveRedirection
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (An RD Session Host maps client drives automatically upon connection.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle|Level - 1|
|8|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Do not allow drive redirection\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/DoNotAllowDriveRedirection",
            "value": "\u003cenabled/\u003e"
        },
```

```
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fDisableCdm
```

# 3.11.36.4.9 - Security

##  3.11.36.4.9.1 - 'Always prompt for password upon connection' is set to 'Enabled' 

>[!NOTE]
>This policy setting specifies whether Remote Desktop Services always prompts the
client computer for a password upon connection. You can use this policy setting to
enforce a password prompt for users who log on to Remote Desktop Services, even if
they already provided the password in the Remote Desktop Connection client.
>[!TIP]
>Automated Remedation

>[!CAUTION]
>Users cannot automatically log on to Remote Desktop Services by supplying their
passwords in the Remote Desktop Connection client. They will be prompted for a
password to log on.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/PromptForPasswordUponConnection
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Remote Desktop Services allows users to automatically log on if they enter a password in the Remote Desktop Connection client.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Mapped Yet|||||
|8|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Always prompt for password upon connection\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/PromptForPasswordUponConnection",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\TerminalServices:fPromptForPassword
```

## 3.11.36.4.9.2 - 'Require secure RPC communication' is set to 'Enabled

>[!NOTE]
>This policy setting allows you to specify whether Remote Desktop Services requires
secure Remote Procedure Call (RPC) communication with all clients or allows
unsecured communication.
You can use this policy setting to strengthen the security of RPC communication with
clients by allowing only authenticated and encrypted requests.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Remote Desktop Services accepts requests from RPC clients that support secure
requests, and does not allow unsecured communication with untrusted clients.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/RequireSecureRPCCommunication
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Remote Desktop Services always requests security for all RPC traffic. However, unsecured communication is allowed for RPC clients that do not respond tothe request.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle|Level - 1|
|8|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Require secure RPC communication\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/RequireSecureRPCCommunication",
            "value": "\u003cenabled/\u003e"
        },
```

```
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\TerminalServices:fPromptForPassword
```

## 3.11.36.4.9.3 - 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL

>[!NOTE]
>This policy setting specifies whether to require the use of a specific security layer to
secure communications between clients and RD Session Host servers during Remote
Desktop Protocol (RDP) connections.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>TLS 1.0 will be required to authenticate to the RD Session Host server. If TLS is not
supported, the connection fails.
Note: By default, this setting will use a self-signed certificate for RDP connections. If
your organization has established the use of a Public Key Infrastructure (PKI) for
SSL/TLS encryption, then we recommend that you also configure the Server
authentication certificate template setting to instruct RDP to use a certificate from your
PKI instead of a self-signed one. Note that the certificate template used for this purpose
must have “Client Authentication” configured as an Intended Purpose. Note also that a
valid, non-expired certificate using the specified template must already be installed on
the workstation for it to work.
Note #2: Some third party two-factor authentication solutions (e.g. RSA Authentication
Agent) can be negatively affected by this setting, as the SSL/TLS security layer will
expect the user's Windows password upon initial connection attempt (before the RDP
logon screen), and once successfully authenticated, pass the credential along to that
Windows session on the RDP host (to complete the login). If a two-factor agent is
present and expecting a different credential at the RDP logon screen, this initial
connection may result in a failed logon attempt, and also effectively cause a “double
logon” requirement for each and every new RDP session.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_TerminalServer/TS_SECURITY_LAYER_POLICY
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled|
| < enabled/ > < data id="TS_SECURITY_LAYER" value="2"/ >| Custom Settings (Recommended)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle|Level - 1|
|8|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Require use of specific security layer for remote (RDP) connections\u0027 is set to \u0027Enabled: SSL\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_TerminalServer/TS_SECURITY_LAYER_POLICY",
            "value": "\u003cenabled/\u003e\n\u003cdata id=\"TS_SECURITY_LAYER\" value=\"2\"/\u003e"
        },
```

```
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 2.
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:SecurityLayer
```

## 3.11.36.4.9.4 - 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled' 

>[!NOTE]
>This policy setting allows you to specify whether to require user authentication for
remote connections to the RD Session Host server by using Network Level
Authentication.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Only client computers that support Network Level Authentication can connect to the RD
Session Host server.
Note: Some third party two-factor authentication solutions (e.g. RSA Authentication
Agent) can be negatively affected by this setting, as Network Level Authentication will
expect the user's Windows password upon initial connection attempt (before the RDP
logon screen), and once successfully authenticated, pass the credential along to that
Windows session on the RDP host (to complete the login). If a two-factor agent is
present and expecting a different credential at the RDP logon screen, this initial
connection may result in a failed logon attempt, and also effectively cause a “double
logon” requirement for each and every new RDP session.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_TerminalServer/TS_USER_AUTHENTICATION_POLICY
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle|Level - 1|
|8|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Require user authentication for remote connections by using Network Level Authentication\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_TerminalServer/TS_USER_AUTHENTICATION_POLICY",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\TerminalServices:UserAuthentication
```

## 3.11.36.4.9.5 -'Set client connection encryption level' is set to 'Enabled: High Level'

>[!NOTE]
>This policy setting specifies whether to require the use of a specific encryption level to
secure communications between client computers and RD Session Host servers during
Remote Desktop Protocol (RDP) connections. This policy only applies when you are
using native RDP encryption. However, native RDP encryption (as opposed to SSL
encryption) is not recommended. This policy does not apply to SSL encryption.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/ClientConnectionEncryptionLevel
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled: High Level. (All communications between clients and RD Session Host servers during remote connections using native RDP encryption must be 128-bit strength. Clients that do not support 128-bit encryption will be unable to establish Remote Desktop Server sessions.)|
| < disabled/ > |Disabled|
| < enabled/ > < data id="TS_ENCRYPTION_LEVEL" value="3"/ >| Custom Settings (Recommended)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle|Level - 1|
|8|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Set client connection encryption level\u0027 is set to \u0027Enabled: High Level\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/ClientConnectionEncryptionLevel",
            "value": "\u003cenabled/\u003e\n\u003cdata id=\"TS_ENCRYPTION_LEVEL\" value=\"3\"/\u003e"
        },
```

```
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 3.
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\TerminalServices:MinEncryptionLevel
```

## 3.11.36.4.11 - Temporary folders

## 3.11.36.4.11.1 - 'Do not delete temp folders upon exit' is set to 'Disabled' 

>[!NOTE]

>This policy setting specifies whether Remote Desktop Services retains a user's persession temporary folders at logoff.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_TerminalServer/TS_TEMP_DELETE
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Temporary folders are deleted when a user logs off.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.4 Enforce Data Retention|:green_circle:|:orange_circle:|:large_blue_circle|Level - 1|
|8|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Do not delete temp folders upon exit\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_TerminalServer/TS_TEMP_DELETE",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\TerminalServices:DeleteTempDirsOnExit
```

# 3.11.37 - RSS Feeds

## 3.11.37.1 - 'Prevent downloading of enclosures' is set to 'Enabled'

>[!NOTE]
>This policy setting prevents the user from having enclosures (file attachments)
downloaded from an RSS feed to the user's computer.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Users cannot set the Feed Sync Engine to download an enclosure through the Feed
property page. Developers cannot change the download setting through feed APIs.


```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/InternetExplorer/DisableEnclosureDownloading
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (Users can set the Feed Sync Engine to download an enclosure through the Feed property page. Developers can change the download setting through the Feed APIs.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|9.4 Restrict Unnecessary or Unauthorized Browser and Email Client Extensions|:green_circle:|:orange_circle:|:large_blue_circle|Level - 1|
|8|7.2 Disable Unnecessary or Unauthorized Browser or Email Client Plugins||:orange_circle:|:large_blue_circle|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Prevent downloading of enclosures\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/InternetExplorer/DisableEnclosureDownloading",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\InternetExplorer\Feeds:DisableEnclosureDownload
```

# 3.11.42 - Store

## 3.11.42.1 - 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled'

>[!NOTE]
>Enables or disables the Microsoft Store offer to update to the latest version of Windows

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The Microsoft Store application will not offer updates to the latest version of Windows.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_WindowsStore/DisableOSUpgrade_2
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled|
| < disabled/ > |Disabled. (The Microsoft Store application will offer updates to the latest version of Windows.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Mapped Yet|||||
|8|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "18.9.75.3 (L1) Ensure \u0027Turn off the offer to update to the latest version of Windows\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_WindowsStore/DisableOSUpgrade_2",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\WindowsStore:DisableOSUpgrade
```

# 3.11.50 - Windows Logon Options

## 3.11.50.1 - 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled'

>[!NOTE]
>This policy setting controls whether a device will automatically sign-in the last interactive
user after Windows Update restarts the system.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The device does not store the user's credentials for automatic sign-in after a Windows
Update restart. The users' lock screen apps are not restarted after the system restarts.
The user is required to present the logon credentials in order to proceed after restart.


```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/WindowsLogon/AllowAutomaticRestartSignOn
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled. (The device securely saves the user's credentials (including the user name, domain and encrypted password) to configure automatic sign-in after a Windows Update restart. After the Windows Update restart, the user is automatically signed-in and the session is automatically locked with all the lock screen apps configured for that user.)|
| < disabled/ > |Disabled.|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Mapped Yet|||||
|8|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Sign-in and lock last interactive user automatically after a restart\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/WindowsLogon/AllowAutomaticRestartSignOn",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:DisableAutomaticRestartSignOn
```

#3.11.54 - Windows PowerShell

## 3.11.54.1 - 'Turn on PowerShell Script Block Logging' is set to 'Enabled'

>[!NOTE]
>This policy setting enables logging of all PowerShell script input to the Applications
and Services Logs\Microsoft\Windows\PowerShell\Operational Event Log channel.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>PowerShell script input will be logged to the Applications and Services
Logs\Microsoft\Windows\PowerShell\Operational Event Log channel, which can
contain credentials and sensitive information.
Warning: There are potential risks of capturing credentials and sensitive information in
the PowerShell logs, which could be exposed to users who have read-access to those
logs. Microsoft provides a feature called "Protected Event Logging" to better secure
event log data.


```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/WindowsPowerShell/TurnOnPowerShellScriptBlockLogging
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled. (PowerShell will log script blocks the first time they are used.)|
| < disabled/ > |Disabled.|
| < enabled/ > < data id="EnableScriptBlockInvocationLogging" value="true"/ > | Custom Settings (Recommended)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.8 Collect Command-Line Audit Logs||:orange_circle:|:large_blue_circle|Level - 1|
|8|8.8 Enable Command-line Audit Logging||:orange_circle:|:large_blue_circle|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Turn on PowerShell Script Block Logging\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/WindowsPowerShell/TurnOnPowerShellScriptBlockLogging",
            "value": "\u003cenabled/\u003e\n\u003cdata id=\"EnableScriptBlockInvocationLogging\" value=\"true\"/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging:EnableScriptBlockLogging
```

## 3.11.54.2 - 'Turn on PowerShell Transcription' is set to 'Enabled' 

>[!NOTE]
>This Policy setting lets you capture the input and output of Windows PowerShell
commands into text-based transcripts.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>PowerShell transcript input will be logged to the PowerShell_transcript output file,
which is saved to the My Documents folder of each users´ profile by default.
Warning: There are potential risks of capturing credentials and sensitive information in
the PowerShell_transcript output file, which could be exposed to users who have
read-access to the file.
Warning #2: PowerShell Transcription is not compatible with the natively installed
PowerShell v4 on Microsoft Windows 10 Release 1511 and Server 2012 R2 and below.
If this recommendation is set as prescribed, PowerShell will need to be updated to at
least v5.1 or newer


```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/ADMX_PowerShellExecutionPolicy/EnableTranscripting
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled.|
| < disabled/ > |Disabled. (Transcription of PowerShell-based applications is disabled by default, although transcription can still be enabled through the Start-Transcript cmdlet.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.8 Collect Command-Line Audit Logs||:orange_circle:|:large_blue_circle|Level - 1|
|8|8.8 Enable Command-line Audit Logging||:orange_circle:|:large_blue_circle|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Turn on PowerShell Transcription\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_PowerShellExecutionPolicy/EnableTranscripting",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription:EnableTranscripting
```

# 3.11.55.1 - WinRM Client

## 3.11.55.1.1 - 'Allow Basic authentication' is set to 'Disabled' 

>[!NOTE]
>This policy setting allows you to manage whether the Windows Remote Management
(WinRM) client uses Basic authentication.
Note: Clients that use Microsoft's Exchange Online service (Office 365) will require an
exception to this recommendation, to instead have this setting set to Enabled.
Exchange Online uses Basic authentication over HTTPS, and so the Exchange Online
authentication traffic will still be safely encrypted.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/RemoteManagement/AllowBasicAuthentication_Client
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled.|
| < disabled/ > |Disabled. (The WinRM client does not use Basic authentication.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle|Level - 1|
|8|16.5 Encrypt Transmittal of Username and Authentication Credentials||:orange_circle:|:large_blue_circle|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Allow Basic authentication\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/RemoteManagement/AllowBasicAuthentication_Client",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client:AllowBasic
```

## 3.11.55.1.2 - 'Allow unencrypted traffic' is set to 'Disabled'

>[!NOTE]
>This policy setting allows you to manage whether the Windows Remote Management
(WinRM) client sends and receives unencrypted messages over the network.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/RemoteManagement/AllowUnencryptedTraffic_Client
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled.|
| < disabled/ > |Disabled. (The WinRM client sends or receives only encrypted messages over the network.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle|Level - 1|
|7|14.4 Encrypt All Sensitive Information in Transit||:orange_circle:|:large_blue_circle|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Allow unencrypted traffic\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/RemoteManagement/AllowUnencryptedTraffic_Client",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client:AllowUnencryptedTraffic
```

## 3.11.55.1.3 - 'Disallow Digest authentication' is set to 'Enabled'

>[!NOTE]
>This policy setting allows you to manage whether the Windows Remote Management
(WinRM) client will not use Digest authentication.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The WinRM client will not use Digest authentication.

```
OMA-URI (Device)
./Device/Vendor/MSFT/Policy/Config/RemoteManagement/DisallowDigestAuthentication
```

|Value|Description|
|---|---|
| < enabled/ > |Enabled.|
| < disabled/ > |DDisabled. (The WinRM client will use Digest authentication.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle|Level - 1|
|7|16.5 Encrypt Transmittal of Username and Authentication Credentials||:orange_circle:|:large_blue_circle|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Disallow Digest authentication\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/RemoteManagement/DisallowDigestAuthentication",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client:AllowDigest
```
# 3.11.55.2 - WinRM Service

## 3.11.55.2.1 - 'Allow Basic authentication' is set to 'Disabled'