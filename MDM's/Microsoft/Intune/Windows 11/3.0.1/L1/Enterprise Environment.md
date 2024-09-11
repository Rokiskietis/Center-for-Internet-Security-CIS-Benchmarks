# Corporate/Enterprise Environment Level - 1

# 1.0 - Above Lock

## 1.1 Ensure 'Allow Cortana Above Lock' is set to 'Block'

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

## 3.1.3.1 - Ensure 'Enable screen saver (User)' is set to 'Enabled'
 

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
|Enabled|Enable|
|Disabled|Disable|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.3 Configure Automated Session Locking on Enterprise Assets|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "Ensure \u0027Enable screen saver\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./User/Vendor/MSFT/Policy/Config/ADMX_ControlPanelDisplay/CPL_Personalization_EnableScreenSaver",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_SZ value of 1.
HKU\[USER SID]\Software\Policies\Microsoft\Windows\Control Panel\Desktop:ScreenSaveActive
```


## 3.1.3.2 - Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'

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
|Enabled|Enable|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "Ensure \u0027Prevent enabling lock screen camera\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventEnablingLockScreenCamera",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization:NoLockScreenCamera
```



## 3.1.3.3 - Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
	
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
|Enabled|Enable|
|Disabled|Disabled. (Users can enable a slide show that will run after they lock the machine.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "Ensure \u0027Prevent enabling lock screen slide show\u0027 is set to \u0027Enabled\u0027",
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

## 3.4.1 - Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled' 

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
|Enabled|Applies UAC token-filtering to local accounts on network logons. Membership in powerful group such as Administrators is disabled and powerful privileges are removed from the resulting access token|
|Disabled|Allows local accounts to have full administrative rights when authenticating via network logon|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|7|4.3 Ensure the Use of Dedicated Administrative Accounts|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "Ensure \u0027Apply UAC restrictions to local accounts on network logons\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ApplyUACRestrictionsToLocalAccountsOnNetworkLogon",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:LocalAccountTokenFilterPolicy

```

## 3.4.2 - Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver '
	
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
|Enabled|Disable driver|
|Disabled|Enable Driver|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Ensure Only Approved Ports, Protocols and Services Are Running ||:orange_circle:|:large_blue_circle:|Level - 1|
|7|14.3 Disable Workstation to Workstation Communication||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "18.3.2 (L1) Ensure \u0027Configure SMB v1 client driver\u0027 is set to \u0027Enabled: Disable driver (recommended)\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ConfigureSMBV1ClientDriver",
            "value": "\u003cenabled/\u003e\u003cdata id=\"Pol_SecGuide_SMB1ClientDriver\" value=\"4\" /\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 4.
HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10:Start
```


## 3.4.3 - Ensure 'Configure SMB v1 server' is set to 'Disabled' 
	
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
|Enabled|Enable Driver|
|Disabled|Disable driver|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Ensure Only Approved Ports, Protocols and Services Are Running ||:orange_circle:|:large_blue_circle:|Level - 1|
|7|14.3 Disable Workstation to Workstation Communication||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "Ensure \u0027Configure SMB v1 server\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ConfigureSMBV1Server",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters:SMB1
```

## 3.4.4 - Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'

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
|Enabled|Enable Driver|
|Disabled|Disable driver|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.5 Enable Anti-Exploitation Features||:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.3 Enable Operating System Anti-Exploitation Features/Deploy Anti-Exploit Technologies||:orange_circle:|:large_blue_circle:|Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "Ensure \u0027Enable Structured Exception Handling Overwrite Protection (SEHOP)\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/EnableStructuredExceptionHandlingOverwriteProtection",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel:DisableExceptionChainValidation
```

## 3.4.5 - Ensure 'WDigest Authentication' is set to 'Disabled'


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
|Enabled|Lsass.exe retains a copy of the user's plaintext password in memory, where it is at risk of theft|
|Disabled|Lsass.exe does not retain a copy of the user's plaintext password in memory|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.11 Encrypt Sensitive Data at Rest||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.4 Encrypt or Hash all Authentication Credentials||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "Ensure \u0027WDigest Authentication\u0027 is set to \u0027Disabled\u0027",
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

## 3.5.1 - Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled' 

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
|Enabled|Enabled|
|Disabled|Disabled|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.11 Encrypt Sensitive Data at Rest||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.4 Encrypt or Hash all Authentication Credentials||:orange_circle:|:large_blue_circle:|Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "Ensure \u0027MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)\u0027 is set to \u0027Enabled: Highest protection, source routing is completely disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPSourceRoutingProtectionLevel",
            "value": "\u003cenabled/\u003e\u003cdata id=\"DisableIPSourceRouting\" value=\"2\" /\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:AutoAdminLogon
```

## 3.5.2 - Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'

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
|Enabled|Enabled|
|Disabled|Disabled|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|X|Not Mapped Yet|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|X|Not Mapped Yet|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "Ensure \u0027MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)\u0027 is set to \u0027Enabled: Highest protection, source routing is completely disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPv6SourceRoutingProtectionLevel",
            "value": "\u003cenabled/\u003e\u003cdata id=\"DisableIPSourceRoutingIPv6\" value=\"2\" /\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 2.
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters:DisableIPSourceRouting

```

## 3.5.3 - Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'

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
|Enabled|Enabled|
|Disabled|Disabled|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|X|Not Mapped Yet|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|X|Not Mapped Yet|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "Ensure \u0027MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)\u0027 is set to \u0027Enabled: Highest protection, source routing is completely disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPSourceRoutingProtectionLevel",
            "value": "\u003cenabled/\u003e\u003cdata id=\"DisableIPSourceRouting\" value=\"2\" /\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 2.
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters:DisableIPSourceRouting
```

## 3.5.5 - Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'

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
./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPSourceRoutingProtectionLevel
```
|Value|Description|
|---|---|
|Enabled|Enabled. (ICMP redirects can override OSPF-generated routes.)|
|Disabled|Disabled|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.1 Establish and Maintain a Secure Configuration Process|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "Ensure \u0027MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/AllowICMPRedirectsToOverrideOSPFGeneratedRoutes",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters:EnableICMPRedirect
```

## 3.5.7 -  Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled' 

>[!NOTE]
>NetBIOS over TCP/IP is a network protocol that among other things provides a way to
easily resolve NetBIOS names that are registered on Windows-based systems to the IP
addresses that are configured on those systems. This setting determines whether the
computer releases its NetBIOS name when it receives a name-release request.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

|Value|Description|
|---|---|
|Enabled|Enabled |
|Disabled|Disabled|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.2 Establish and Maintain a Secure Configuration Process for Network Infrastructure|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|5.1 Establish Secure Configurations|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|


```
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "Ensure \u0027MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/AllowTheComputerToIgnoreNetBIOSNameReleaseRequestsExceptFromWINSServers",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters:NoNameReleaseOnDemand
```
## 3.5.9 - Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled' 

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

|Value|Description|
|---|---|
|Enabled|Enabled |
|Disabled|Disabled|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.5 Enable Anti-Exploitation Features||:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.3 Enable Operating System Anti-Exploitation Features/Deploy Anti-Exploit Technologies||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "Ensure \u0027MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_MSS-legacy/Pol_MSS_SafeDllSearchMode",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager:SafeDllSearchMode
```

## 3.5.10 - Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'


>[!NOTE]
>Windows includes a grace period between when the screen saver is launched and
when the console is actually locked automatically when screen saver locking is enabled.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Users will have to enter their passwords to resume their console sessions as soon as
the grace period ends after screen saver activation.


|Value|Description|
|---|---|
|Enabled|Enabled |
|Disabled|Disabled|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.3 Configure Automatic Session Locking on Enterprise Assets|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "Ensure \u0027MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)\u0027 is set to \u0027Enabled: 5 or fewer seconds\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_MSS-legacy/Pol_MSS_ScreenSaverGracePeriod",
            "value": "\u003cenabled/\u003e\u003cdata id=\"ScreenSaverGracePeriod\" value=\"5\"/\u003e"
        },
```

```
Audit: Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 5.
HKLM\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Winlogon:ScreenSaverGracePeriod
```

## 3.5.13 - Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'

>[!NOTE]
>This setting can generate a security audit in the Security event log when the log reaches
a user-defined threshold.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>An audit event will be generated when the Security log reaches the 90% percent full
threshold (or whatever lower value may be set) unless the log is configured to overwrite
events as needed.


|Value|Description|
|---|---|
|Enabled|Enabled |
|Disabled|Disabled|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.3 Ensure Adequate Audit Log Storage|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.4 Ensure adequate storage for logs|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "Ensure \u0027MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning\u0027 is set to \u0027Enabled: 90% or less\u0027",
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

## 3.6.4.1 - Ensure 'Turn off multicast name resolution' is set to 'Enabled'

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


|Value|Description|
|---|---|
|Enabled|Enabled|
|Disabled|Disabled. (LLMNR will be enabled on all available network adapters.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|


```
Script: 
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "Ensure \u0027Turn off multicast name resolution\u0027 is set to \u0027Enabled\u0027",
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

## 3.6.9.1 - Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'

>[!NOTE]
>You can use this procedure to control a user's ability to install and configure a Network Bridge

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Users cannot create or configure a Network Bridge


|Value|Description|
|---|---|
|Enabled|Enabled|
|Disabled|Disabled. (Users are able create and modify the configuration of Network Bridges. Membership in the local Administrators group, or equivalent, is the minimum required to complete this procedure.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.2 Establish and Maintain a Secure Configuration Process for Network Infrastructure|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|11.3 Use Automated Tools to Verify Standard Device Configurations and Detect Changes||:orange_circle:|:large_blue_circle:|Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "Ensure \u0027Prohibit installation and configuration of Network Bridge on your DNS domain network\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Connectivity/ProhibitInstallationAndConfigurationOfNetworkBridge",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit: 
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections:NC_AllowNetBridge_NLA
```

## 3.6.9.2 - Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'

>[!NOTE]
>Although this "legacy" setting traditionally applied to the use of Internet Connection Sharing (ICS) in Windows 2000, Windows XP & Server 2003, this setting now freshly applies to the Mobile Hotspot feature in Windows 10 & Server 2016.


>[!TIP]
>Automated Remedation

>[!CAUTION]
>Mobile Hotspot cannot be enabled or configured by Administrators and nonAdministrators alike.


|Value|Description|
|---|---|
|Enabled|Enabled|
|Disabled|Disabled. (All users are allowed to turn on Mobile Hotspot.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": Ensure \u0027Prohibit use of Internet Connection Sharing on your DNS domain network\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_NetworkConnections/NC_ShowSharedAccessUI",
            "value": "\u003cenabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections:NC_ShowSharedAccessUI
```

## 3.6.9.3 - Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled' 

>[!NOTE]
>This policy setting determines whether to require domain users to elevate when setting a network's location.


>[!TIP]
>Automated Remedation

>[!CAUTION]
>Domain users must elevate when setting a network's location.


|Value|Description|
|---|---|
|Enabled|Enabled|
|Disabled|Disabled. (Users can set a network's location without elevating.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Mapped Yet|||Level - 1|
|7|4.3 Ensure the Use of Dedicated Administrative Accounts|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "Ensure \u0027Require domain users to elevate when setting a network\u0027s location\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_NetworkConnections/NC_StdDomainUserSetLocation",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit: 
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections:NC_StdDomainUserSetLocation
```

