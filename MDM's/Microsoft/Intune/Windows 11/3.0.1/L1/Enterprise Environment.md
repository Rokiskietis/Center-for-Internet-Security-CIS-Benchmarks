# Corporate/Enterprise Environment Level - 1

### Unicode to text: https://r12a.github.io/app-conversion/

### CSP - https://learn.microsoft.com/en-us/windows/client-management/mdm/

>[!IMPORTANT]
>Fix Scripts: omaSettingBoolean if true/false, omaSettingInteger if 0/1/2 , omaSettingString if text

# 1.0 - Above Lock

## 1.1 'Allow Cortana Above Lock' is set to 'Block'

>[!NOTE]
>Access to any computer resource should not be allowed when the device is locked

>[!TIP]
>Automated Remediation

>[!CAUTION]
>The system will need to be unlocked for the user to interact with Cortana using speech.

```
OMA-URI
./Device/Vendor/MSFT/Policy/Config/AboveLock/AllowActionCenterNotifications
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|Not applicable|✔ Windows 10, version 1507 [10.0.10240] and later|
|❌ User|||

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
OMA-URI 
./User/Vendor/MSFT/Policy/Config/ADMX_ControlPanelDisplay/CPL_Personalization_EnableScreenSaver
```

|Scope | Editions| Applicable OS |
|---|---|---|
|❌ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|✔ User|✔ Enterprise|✔  Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enable|
| \<disabled/> |Disable|

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
OMA-URI
./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventEnablingLockScreenCamera
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enable|
| \<disabled/> |Disable|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventLockScreenSlideShow
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enable|
| \<disabled/> |Disabled. (Users can enable a slide show that will run after they lock the machine.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ApplyUACRestrictionsToLocalAccountsOnNetworkLogon
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Applies UAC token-filtering to local accounts on network logons. Membership in powerful group such as Administrators is disabled and powerful privileges are removed from the resulting access token|
| \<disabled/> |Allows local accounts to have full administrative rights when authenticating via network logon|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ConfigureSMBV1ClientDriver
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Disable driver|
| \<disabled/> |Enable Driver|
| \<enabled/>\<data id="Pol_SecGuide_SMB1ClientDriver" value="4"/> | Custom settings (Recommended)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ConfigureSMBV1Server
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enable Driver|
| \<disabled/> |Disable driver|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/EnableStructuredExceptionHandlingOverwriteProtection
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enable Driver|
| \<disabled/> |Disable driver|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/WDigestAuthentication
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Lsass.exe retains a copy of the user's plaintext password in memory, where it is at risk of theft|
| \<disabled/> |Lsass.exe does not retain a copy of the user's plaintext password in memory|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPSourceRoutingProtectionLevel
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled|
| \<enabled/>\<data id="DisableIPSourceRouting" value="2"/> |Custom Settings (Recommended)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPv6SourceRoutingProtectionLevel
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled|
| \<enabled/>\<data id="DisableIPSourceRoutingIPv6" value="2"/> |Custom Settings (Recommended)|

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
OMA-URI
./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPSourceRoutingProtectionLevel
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled|
| \<enabled/>\<data id="DisableIPSourceRouting" value="2"/> |Custom Settings (Recommended) |

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/MSSLegacy/AllowICMPRedirectsToOverrideOSPFGeneratedRoutes
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled. (ICMP redirects can override OSPF-generated routes.)|
| \<disabled/> |Disabled|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/MSSLegacy/AllowTheComputerToIgnoreNetBIOSNameReleaseRequestsExceptFromWINSServers
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled |
| \<disabled/> |Disabled|

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
OMA-URI
./Device/Vendor/MSFT/Policy/Config/ADMX_MSS-legacy/Pol_MSS_SafeDllSearchMode
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled |
| \<disabled/> |Disabled|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_MSS-legacy/Pol_MSS_ScreenSaverGracePeriod
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled |
| \<disabled/> |Disabled|
| \<enabled/>\<data id="ScreenSaverGracePeriod" value="5"/> |Custom Settings (Recommended)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_MSS-legacy/Pol_MSS_WarningLevel
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled |
| \<disabled/> |Disabled|
| \<enabled/>\<data id="WarningLevel" value="90"/> |Custom Settings (Recommended)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_DnsClient/Turn_Off_Multicast
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (LLMNR will be enabled on all available network adapters.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Connectivity/ProhibitInstallationAndConfigurationOfNetworkBridge
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Users are able create and modify the configuration of Network Bridges. Membership in the local Administrators group, or equivalent, is the minimum required to complete this procedure.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_NetworkConnections/NC_ShowSharedAccessUI
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (All users are allowed to turn on Mobile Hotspot.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_NetworkConnections/NC_StdDomainUserSetLocation
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disable/> |Disabled. (Users can set a network's location without elevating.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Connectivity/HardenedUNCPaths
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Users can set a network's location without elevating.)|
| \<enabled/>\<data id="Pol_HardenedPaths" value="\\*\NETLOGONRequireMutualAuthentication=1,RequireIntegrity=1\\*\SYSVOLRequireMutualAuthentication=1,RequireIntegrity=1"/> | Custom Settings (Recommended)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_WCM/WCM_MinimizeConnections
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and late|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled: 1 = Minimize simultaneous connections. (Any new automatic internet connection is blocked when the computer has at least one active internet connection to a preferred type of network. The order of preference (from most preferred to least preferred) is: Ethernet, WLAN, then cellular. Ethernet is always preferred when connected. Users can still manually connect to any network.)|
| \<disabled/> |Disabled|
| \<enabled/>\<data id="WCM_MinimizeConnections_Options" value="3"/> |Custom Settings (Recommended)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/WindowsConnectionManager/ProhitConnectionToNonDomainNetworksWhenConnectedToDomainAuthenticatedNetwork
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Connections to both domain and non-domain networks are simultaneously allowed.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/WirelessDisplay/RequirePinForPairing
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1607 [10.0.14393] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_Printing2/RegisterSpoolerRemoteRpcEndPoint
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled. (The Print Spooler will always accept client connections.)|
| \<disabled/> |Disabled|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Printers/PointAndPrintRestrictions
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled. (Windows computers will show a warning and a security elevation prompt when users create a new printer connection using Point and Print.)|
| \<disabled/> |Disabled|
| \<enabled/>
| \<data id="PointAndPrint_TrustedServers_Chk" value="false"/>\<data id="PointAndPrint_TrustedServers_Edit" value=""/>\<data id="PointAndPrint_TrustedForest_Chk" value="false"/>\<data id="PointAndPrint_NoWarningNoElevationOnInstall_Enum" value="0"/>\<data id="PointAndPrint_NoWarningNoElevationOnUpdate_Enum" value="0"/> | Custom Settings (Recommended)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/WindowsLogon/DisableLockScreenAppNotifications
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Toast notifications on the lock screen are enabled and can be turned off by the administrator or user.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_AuditSettings/IncludeCmdLine
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Process command line information will not be included in Audit Process Creation events.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_CredSsp/AllowEncryptionOracle
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled|
| \<enabled/>\<data id="AllowEncryptionOracleDrop" value="0"/> | Custom Settings (Recommended)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/CredentialsDelegation/RemoteHostAllowsDelegationOfNonExportableCredentials
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Restricted Admin Mode and Windows Defender Remote Credential Guard are not supported. Users will always need to pass their credentials to the host.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/DeviceInstallation/PreventDeviceMetadataFromNetwork
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1809 [10.0.17763] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (The setting in the Device Installation Settings dialog box controls whetherWindows retrieves device metadata from the Internet.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/System/BootStartDriverInitialization
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Boot-start drivers determined to be Good, Unknown or Bad but Boot Critical are initialized and the initialization of drivers determined to be bad is skipped.)|
| \<enabled/>\<data id="SelectDriverLoadPolicy" value="3"/> | Custom Settings (Recommended)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_GroupPolicy/CSE_Registry
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Group policies are not reapplied until the next logon or restart or Group policies are not reapplied if they have not been changed.)|
| \<enabled/>\<data id="CSE_NOBACKGROUND10" value="false"/><data id="CSE_NOCHANGES10" value="false"/> | Custom Settings (Recommended)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_GroupPolicy/EnableCDP
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_GroupPolicy/DisableBackgroundPolicy
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Updates can be applied while users are working.)|

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
OMA-URI 
./User/Vendor/MSFT/Policy/Config/ADMX_ICM/DisableWebPnPDownload_1
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled.(Users can download print drivers over HTTP.)|

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
OMA-URI 
./User/Vendor/MSFT/Policy/Config/ADMX_ICM/ShellPreventWPWDownload_1
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (A list of providers is downloaded when the user uses the web publishing or online ordering wizards.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_Logon/BlockUserFromShowingAccountDetailsOnSignin
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| <enabled/> |Enabled|
| <disabled/> |Disabled. (Users may choose to show account details on the sign-in screen.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/WindowsLogon/DontDisplayNetworkSelectionUI
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC||

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Any user can disconnect the PC from the network or can connect the PC to other available networks without signing into Windows.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_Logon/DontEnumerateConnectedUsers
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Connected users will be enumerated on domain-joined computers.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/WindowsLogon/EnumerateLocalUsersOnDomainJoinedComputers
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (The Logon UI will not enumerate local users on domain-joined computers.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/WindowsLogon/DisableLockScreenAppNotifications
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Users can choose which apps display notifications on the lock screen.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/CredentialProviders/BlockPicturePassword
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Users can set up and use a picture password.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/CredentialProviders/AllowPINLogon
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled.(Users can set up and use a picture password.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_Power/DCConnectivityInStandby_2
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later |
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled. (Network connectivity will be maintained in standby while on battery.)|
| \<disabled/> |Disabled|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_Power/ACConnectivityInStandby_2
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later |
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled. (Network connectivity will be maintained in standby while plugged in).|
| \<disabled/> |Disabled|

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

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Power/RequirePasswordWhenComputerWakesOnBattery
```
|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled. (The user is prompted for a password when the system resumes from sleep while on battery.)|
| \<disabled/> |Disabled|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle|:orange_circle:|:large_blue_circle:|Level - 1|
|8|Not Yet Mapped||||Level - 1|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Power/RequirePasswordWhenComputerWakesOnBattery
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled. (The user is prompted for a password when the system resumes from sleep while plugged in.)|
| \<disabled/> |Disabled|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/RemoteAssistance/UnsolicitedRemoteAssistance
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled.|
| \<disabled/> |Disabled. (Users on this computer cannot get help from their corporate technical support staff using Offer (Unsolicited) Remote Assistance.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/RemoteAssistance/SolicitedRemoteAssistance
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Users can turn on or turn off Solicited (Ask for) Remote Assistance themselves in System Properties in Control Panel. Users can also configure Remote Assistance settings.|
| \<disabled/> |Disabled.|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/RemoteProcedureCall/RPCEndpointMapperClientAuthentication
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (RPC clients will not authenticate to the Endpoint Mapper Service, but they will be able to communicate with the Windows NT4 Server Endpoint Mapper Service.).|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/RemoteProcedureCall/RestrictUnauthenticatedRPCClients
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled: Authenticated. (Only authenticated RPC clients are allowed to connect to RPC servers running on the machine. Exemptions are granted to interfaces that have requested them.)|
| \<disabled/> |Disabled|
| \<enabled/>\<data id="RpcRestrictRemoteClientsList" value="1"/> | Custom Settings (Recommended} |

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_W32Time/W32TIME_POLICY_ENABLE_NTPCLIENT
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (The local computer clock does not synchronize time with NTP servers.)|

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

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_W32Time/W32TIME_POLICY_ENABLE_NTPSERVER
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (The computer cannot service NTP requests from other computers.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.4 Standardize Time Synchronization||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.1 Utilize Three Synchronized Time Sources||:orange_circle:|:large_blue_circle:|Level - 1|

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

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/AppRuntime/AllowMicrosoftAccountsToBeOptional
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Users will need to sign in with a Microsoft account.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|5.6 Centralize Account Management||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.2 Configure Centralized Point of Authentication||:orange_circle:|:large_blue_circle:|Level - 1|

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

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Windows marks file attachments with their zone information.)|

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

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Windows does not call the registered antivirus program(s) when file attachments are opened.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Autoplay/DisallowAutoplayForNonVolumeDevices
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (AutoPlay is enabled for non-volume devices.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Autoplay/SetDefaultAutoRunBehavior
```
```
OMA-URI
./User/Vendor/MSFT/Policy/Config/Autoplay/SetDefaultAutoRunBehavior
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|✔ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Windows will prompt the user whether autorun command is to be run.)|
| \<enabled/>\<data id="NoAutorun_Dropdown" value="1"/> |Custom Settings (Recommended)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Autoplay/TurnOffAutoPlay
```
```
OMA-URI
./User/Vendor/MSFT/Policy/Config/Autoplay/TurnOffAutoPlay
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|✔ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Autoplay is enabled.)|
| \<enabled/>\<data id="Autorun_Box" value="255"/> |Custom Settings (Recommended)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/CredentialsUI/DisablePasswordReveal
```
```
OMA-URI
./User/Vendor/MSFT/Policy/Config/CredentialsUI/DisablePasswordReveal
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|✔ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (The password reveal button is displayed after a user types a password in the password entry text box. If the user clicks on the button, the typed password is displayed on-screen in plain text.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/CredentialsUI/EnumerateAdministrators
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|


|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Users will be required to always type in a username and password to elevate.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_CredUI/NoLocalPasswordResetQuestions
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Not Configured. (Local user accounts are able to set up and use security questions to reset their passwords.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_Log_AutoBackup_1
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (When a log file reaches its maximum size, new events overwrite old events.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/EventLogService/SpecifyMaximumFileSizeApplicationLog
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (The default log size is 20,480 KB - this value can be changed by the local administrator using the Log Properties dialog.)|
| \<enabled/>\<data id="Channel_LogMaxSize" value="102400"/>|Custom Settings (Recommended) |

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_Log_AutoBackup_2
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (When a log file reaches its maximum size, new events overwrite old events.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.3 Ensure Adequate Audit Log Storage|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.4 Ensure adequate storage for logs||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
		{
			"@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Application: Control Event Log behavior when the log file reaches its maximum size\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_Log_AutoBackup_2",
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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/EventLogService/SpecifyMaximumFileSizeSecurityLog
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (The default log size is 20,480 KB - this value can be changed by the local administrator using the Log Properties dialog.)|
| \<enabled/>\<data id="Channel_LogMaxSize" value="2097152"/> |Custom Settings (Recommended) |

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_Log_AutoBackup_3
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (When a log file reaches its maximum size, new events overwrite old events.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.3 Ensure Adequate Audit Log Storage|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.4 Ensure adequate storage for logs||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Security: Control Event Log behavior when the log file reaches its maximum size\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_Log_AutoBackup_3",
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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_LogMaxSize_3
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (The default log size is 20,480 KB - this value can be changed by the local administrator using the Log Properties dialog.)|
| \<enabled/>\<data id="Channel_LogMaxSize" value="102400"/> |Custom Settings (Recommended) |

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_EventLog/Channel_Log_AutoBackup_4
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (When a log file reaches its maximum size, new events overwrite old events.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/EventLogService/SpecifyMaximumFileSizeSystemLog
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (The default log size is 20,480 KB - this value can be changed by the local administrator using the Log Properties dialog.)|
| \<enabled/>\<data id="Channel_LogMaxSize" value="204800"/>| Custom Settings (Recommended) |

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/SmartScreen/EnableSmartScreenInShell
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1|Enabled|
| 2 |Disabled. (Windows Defender SmartScreen behavior is managed by administrators on the PC by using Windows Defender SmartScreen Settings in Action Center.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/FileExplorer/TurnOffDataExecutionPreventionForExplorer
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Data Execution Prevention will block certain types of malware from exploiting Explorer.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/FileExplorer/TurnOffHeapTerminationOnCorruption
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Heap termination on corruption is enabled.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_WindowsExplorer/ShellProtocolProtectedModeTitle_2
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (The protocol is in the protected mode, allowing applications to only open a limited set of folders.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_Sharing/DisableHomeGroup
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (A user can add their computer to a HomeGroup. However, data on a domainjoined computer is not shared with the HomeGroup.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_MSAPolicy/MicrosoftAccount_DisableUserAuth
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Applications and services on the device will be permitted to authenticate using consumer Microsoft accounts via the Windows OnlineID and WebAccountManager APIs.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_MicrosoftDefenderAntivirus/Spynet_LocalSettingOverrideSpynetReporting
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Group Policy will take priority over the local preference setting.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_MicrosoftDefenderAntivirus/DisableAntiSpywareDefender
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Microsoft Defender Antivirus runs and computers are scanned for malware and other potentially unwanted software.)|

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
OMA-URI
./User/Vendor/MSFT/Policy/Config/ADMX_Sharing/NoInplaceSharing
```

|Scope | Editions| Applicable OS |
|---|---|---|
|❌ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|✔ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Users can share files out of their user profile after an administrator has opted in the computer.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/DoNotAllowPasswordSaving
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Users will be able to save passwords using Remote Desktop Connection.)|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/DoNotAllowDriveRedirection
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (An RD Session Host maps client drives automatically upon connection.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|
|8|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

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
Audit:
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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/PromptForPasswordUponConnection
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Remote Desktop Services allows users to automatically log on if they enter a password in the Remote Desktop Connection client.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Mapped Yet|||||
|8|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

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
Audit:
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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/RequireSecureRPCCommunication
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Remote Desktop Services always requests security for all RPC traffic. However, unsecured communication is allowed for RPC clients that do not respond tothe request.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle:|Level - 1|
|8|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

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
Audit:
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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_TerminalServer/TS_SECURITY_LAYER_POLICY
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled|
| \<enabled/>\<data id="TS_SECURITY_LAYER" value="2"/>| Custom Settings (Recommended)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle:|Level - 1|
|8|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

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
Audit:
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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_TerminalServer/TS_USER_AUTHENTICATION_POLICY
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle:|Level - 1|
|8|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

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
Audit:
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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/ClientConnectionEncryptionLevel
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled: High Level. (All communications between clients and RD Session Host servers during remote connections using native RDP encryption must be 128-bit strength. Clients that do not support 128-bit encryption will be unable to establish Remote Desktop Server sessions.)|
| \<disabled/> |Disabled|
| \<enabled/>\<data id="TS_ENCRYPTION_LEVEL" value="3"/>| Custom Settings (Recommended)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle:|Level - 1|
|8|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

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
Audit:
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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_TerminalServer/TS_TEMP_DELETE
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Temporary folders are deleted when a user logs off.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.4 Enforce Data Retention|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|8|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/InternetExplorer/DisableEnclosureDownloading
```
```
OMA-URI
./User/Vendor/MSFT/Policy/Config/InternetExplorer/DisableEnclosureDownloading
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1703 [10.0.15063] and later|
|✔ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (Users can set the Feed Sync Engine to download an enclosure through the Feed property page. Developers can change the download setting through the Feed APIs.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|9.4 Restrict Unnecessary or Unauthorized Browser and Email Client Extensions|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|8|7.2 Disable Unnecessary or Unauthorized Browser or Email Client Plugins||:orange_circle:|:large_blue_circle:|Level - 1|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_WindowsStore/DisableOSUpgrade_2
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 2004 with KB5005101 [10.0.19041.1202] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 20H2 with KB5005101 [10.0.19042.1202] and later|
| |✔ Education|✔ Windows 10, version 21H1 with KB5005101 [10.0.19043.1202] and later|
| |✔ Windows SE|✔ Windows 11, version 21H2 [10.0.22000] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled|
| \<disabled/> |Disabled. (The Microsoft Store application will offer updates to the latest version of Windows.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Mapped Yet|||||
|8|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/WindowsLogon/AllowAutomaticRestartSignOn
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1903 [10.0.18362] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|


|Value|Description|
|---|---|
| \<enabled/> |Enabled. (The device securely saves the user's credentials (including the user name, domain and encrypted password) to configure automatic sign-in after a Windows Update restart. After the Windows Update restart, the user is automatically signed-in and the session is automatically locked with all the lock screen apps configured for that user.)|
| \<disabled/> |Disabled.|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|Not Mapped Yet|||||
|8|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

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

# 3.11.54 - Windows PowerShell

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/WindowsPowerShell/TurnOnPowerShellScriptBlockLogging
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|✔ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled. (PowerShell will log script blocks the first time they are used.)|
| \<disabled/> |Disabled.|
| \<enabled/>\<data id="EnableScriptBlockInvocationLogging" value="true"/> | Custom Settings (Recommended)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.8 Collect Command-Line Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|8|8.8 Enable Command-line Audit Logging||:orange_circle:|:large_blue_circle:|Level - 1|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ADMX_PowerShellExecutionPolicy/EnableTranscripting
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|✔ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled.|
| \<disabled/> |Disabled. (Transcription of PowerShell-based applications is disabled by default, although transcription can still be enabled through the Start-Transcript cmdlet.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.8 Collect Command-Line Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|8|8.8 Enable Command-line Audit Logging||:orange_circle:|:large_blue_circle:|Level - 1|

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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/RemoteManagement/AllowBasicAuthentication_Client
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled.|
| \<disabled/> |Disabled. (The WinRM client does not use Basic authentication.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle:|Level - 1|
|8|16.5 Encrypt Transmittal of Username and Authentication Credentials||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Allow Basic authentication Service\u0027 is set to \u0027Disabled\u0027",
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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/RemoteManagement/AllowBasicAuthentication_Service
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|


|Value|Description|
|---|---|
| \<enabled/> |Enabled.|
| \<disabled/> |Disabled. (The WinRM client sends or receives only encrypted messages over the network.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle:|Level - 1|
|7|14.4 Encrypt All Sensitive Information in Transit||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Allow unencrypted traffic\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/RemoteManagement/AllowBasicAuthentication_Service",
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
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/RemoteManagement/DisallowDigestAuthentication
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled.|
| \<disabled/> |Disabled. (The WinRM client will use Digest authentication.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.5 Encrypt Transmittal of Username and Authentication Credentials||:orange_circle:|:large_blue_circle:|Level - 1|

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

## 3.11.55.2.1 - 'Allow Basic authentication(Service)' is set to 'Disabled'

>[!NOTE]
>This policy setting allows you to manage whether the Windows Remote Management
(WinRM) service accepts Basic authentication from a remote client.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/RemoteManagement/AllowBasicAuthentication_Client
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| \<enabled/> |Enabled.|
| \<disabled/> |Disabled. (The WinRM service will not accept Basic authentication from a remote client.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.5 Encrypt Transmittal of Username and Authentication Credentials||:orange_circle:|:large_blue_circle:|Level - 1|

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
HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service:AllowBasic
```

## 3.11.55.2.3 - 'Allow unencrypted traffic' is set to 'Disabled'

>[!NOTE]
>This policy setting allows you to manage whether the Windows Remote Management
(WinRM) service sends and receives unencrypted messages over the network.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/RemoteManagement/AllowUnencryptedTraffic_Service
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|


|Value|Description|
|---|---|
| \<enabled/> |Enabled.|
| \<disabled/> |Disabled. (The WinRM service sends or receives only encrypted messages over the network.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle:|Level - 1|
|7|14.4 Encrypt All Sensitive Information in Transit||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Allow unencrypted traffic\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/RemoteManagement/AllowUnencryptedTraffic_Service",
            "value": "\u003cdisabled/\u003e"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service:AllowUnencryptedTraffic
```

## 3.11.55.2.4 - 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'

>[!NOTE]
>This policy setting allows you to manage whether the Windows Remote Management
(WinRM) service will allow RunAs credentials to be stored for any plug-ins.
Note: If you enable and then disable this policy setting, any values that were previously
configured for RunAsPassword will need to be reset.


>[!TIP]
>Automated Remedation

>[!CAUTION]
>The WinRM service will not allow the RunAsUser or RunAsPassword configuration values
to be set for any plug-ins. If a plug-in has already set the RunAsUser and RunAsPassword
configuration values, the RunAsPassword configuration value will be erased from the
credential store on the computer.
If this setting is later Disabled again, any values that were previously configured for
RunAsPassword will need to be reset.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/RemoteManagement/DisallowStoringOfRunAsCredentials
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|


|Value|Description|
|---|---|
| \<enabled/> |Enabled.|
| \<disabled/> |Disabled. (The WinRM service will allow the RunAsUser and RunAsPassword configuration values to be set for plug-ins and the RunAsPassword value will be stored securely.)|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|0.0 Explicitly Not Mapped||||Level - 1|
|7|14.3 Disable Workstation to Workstation Communication||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Disallow WinRM from storing RunAs credentials\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/RemoteManagement/DisallowStoringOfRunAsCredentials",
            "value": "\u003cenabled/\u003e"
        },,
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service:DisableRunAs
```

# 5 Auditing

## 5.1 - 'Account Logon Audit Credential Validation' is set to 'Success and Failure'

>[!NOTE]
>This subcategory reports the results of validation tests on credentials submitted for a
user account logon request. These events occur on the computer that is authoritative for
the credentials. For domain accounts, the Domain Controller is authoritative, whereas
for local accounts, the local computer is authoritative. In domain environments, most of
the Account Logon events occur in the Security log of the Domain Controllers that are
authoritative for the domain accounts. However, these events can occur on other
computers in the organization when local accounts are used to log on. Events for this
subcategory include:
• 4774: An account was mapped for logon.
• 4775: An account could not be mapped for logon.
• 4776: The Domain Controller attempted to validate the credentials for an
account.
• 4777: The Domain Controller failed to validate the credentials for an account.


>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in
your organization, security incidents might not be detected or not enough evidence will
be available for network forensic analysis after security incidents occur. However, if
audit settings are too severe, critically important entries in the Security log may be
obscured by all of the meaningless entries and computer performance and the available
amount of data storage may be seriously affected. Companies that operate in certain
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/AccountLogon_AuditCredentialValidation
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|


|Value|Description|
|---|---|
| 0 | (Default) Off/None |
| 1 | Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Disallow WinRM from storing RunAs credentials\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/AccountLogon_AuditCredentialValidation",
            "value": 3
        },,
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"Credential Validation"
```

## 5.2 - 'Account Logon Logoff Audit Account Lockout' is set to include 'Failure' 

>[!NOTE]
>This subcategory reports when a user's account is locked out as a result of too many
failed logon attempts. Events for this subcategory include:
• 4625: An account failed to log on.


>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in
your organization, security incidents might not be detected or not enough evidence will
be available for network forensic analysis after security incidents occur. However, if
audit settings are too severe, critically important entries in the Security log may be
obscured by all of the meaningless entries and computer performance and the available
amount of data storage may be seriously affected. Companies that operate in certain
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/AccountLogonLogoff_AuditAccountLockout
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Off/None |
| 1 |(Default)  Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.6 Maintain an Inventory of Accounts||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Disallow WinRM from storing RunAs credentials\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/AccountLogonLogoff_AuditAccountLockout",
            "value": 2
        },,
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"Account Lockout"
```

## 5.3 - 'Account Logon Logoff Audit Group Membership' is set to include 'Success' 

>[!NOTE]
>This policy allows you to audit the group membership information in the user’s logon
token. Events in this subcategory are generated on the computer on which a logon
session is created. For an interactive logon, the security audit event is generated on the
computer that the user logged on to. For a network logon, such as accessing a shared
folder on the network, the security audit event is generated on the computer hosting the
resource.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in
your organization, security incidents might not be detected or not enough evidence will
be available for network forensic analysis after security incidents occur. However, if
audit settings are too severe, critically important entries in the Security log may be
obscured by all of the meaningless entries and computer performance and the available
amount of data storage may be seriously affected. Companies that operate in certain
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/AccountLogonLogoff_AuditGroupMembership
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 |(Default)  Off/None |
| 1 | Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|4.8 Log and Alert on Changes to Administrative Group Membership||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.6 Maintain an Inventory of Accounts||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Disallow WinRM from storing RunAs credentials\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/AccountLogonLogoff_AuditGroupMembership",
            "value": 1
        },,
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"Group Membership"
```

## 5.4 - 'Account Logon Logoff Audit Logoff' is set to include 'Success' 

>[!NOTE]
>This subcategory reports when a user logs off from the system. These events occur on
the accessed computer. For interactive logons, the generation of these events occurs
on the computer that is logged on to. If a network logon takes place to access a share,
these events generate on the computer that hosts the accessed resource. If you
configure this setting to No auditing, it is difficult or impossible to determine which user
has accessed or attempted to access organization computers. Events for this
subcategory include:
• 4634: An account was logged off.
• 4647: User initiated logoff.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in
your organization, security incidents might not be detected or not enough evidence will
be available for network forensic analysis after security incidents occur. However, if
audit settings are too severe, critically important entries in the Security log may be
obscured by all of the meaningless entries and computer performance and the available
amount of data storage may be seriously affected. Companies that operate in certain
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/AccountLogonLogoff_AuditLogoff
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 |(Default)  Off/None |
| 1 | Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.13 Alert on Account Login Behavior Deviation|||:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Audit Logoff\u0027 is set to include \u0027Success\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/AccountLogonLogoff_AuditLogoff",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"Logoff"
```

## 5.5 - 'Account Logon Logoff Audit Logon' is set to 'Success and Failure'

>[!NOTE]
>This subcategory reports when a user attempts to log on to the system. These events
occur on the accessed computer. For interactive logons, the generation of these events
occurs on the computer that is logged on to. If a network logon takes place to access a
share, these events generate on the computer that hosts the accessed resource. If you
configure this setting to No auditing, it is difficult or impossible to determine which user
has accessed or attempted to access organization computers. Events for this
subcategory include:
• 4624: An account was successfully logged on.
• 4625: An account failed to log on.
• 4648: A logon was attempted using explicit credentials.
• 4675: SIDs were filtered.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in
your organization, security incidents might not be detected or not enough evidence will
be available for network forensic analysis after security incidents occur. However, if
audit settings are too severe, critically important entries in the Security log may be
obscured by all of the meaningless entries and computer performance and the available
amount of data storage may be seriously affected. Companies that operate in certain
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/AccountLogonLogoff_AuditLogon
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Off/None |
| 1 |(Default) Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.13 Alert on Account Login Behavior Deviation|||:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Audit Logon\u0027 is set to \u0027Success and Failure\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/AccountLogonLogoff_AuditLogon",
            "value": 3
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"Logon"
```

## 5.6 - 'Account Management Audit Application Group Management' is set to 'Success and Failure'

>[!NOTE]
>This policy setting allows you to audit events generated by changes to application
groups such as the following:
• Application group is created, changed, or deleted.
• Member is added or removed from an application group.
Application groups are utilized by Windows Authorization Manager, which is a flexible
framework created by Microsoft for integrating role-based access control (RBAC) into
applications. More information on Windows Authorization Manager is available at MSDN
- Windows Authorization Manager.
Note: Although Microsoft "Deprecated" Windows Authorization Manager (AzMan) in
Windows Server 2012 and 2012 R2, this feature still exists in the OS (unimproved), and
therefore should still be audited.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in
your organization, security incidents might not be detected or not enough evidence will
be available for network forensic analysis after security incidents occur. However, if
audit settings are too severe, critically important entries in the Security log may be
obscured by all of the meaningless entries and computer performance and the available
amount of data storage may be seriously affected. Companies that operate in certain
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/AccountManagement_AuditApplicationGroupManagement
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Off/None |
| 1 |(Default) Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "Ensure \u0027Audit Application Group Management\u0027 is set to \u0027Success and Failure\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/AccountManagement_AuditApplicationGroupManagement",
            "value": 3
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"Application Group Management"
```

## 5.7 - 'Audit Authentication Policy Change' is set to include 'Success'

>[!NOTE]
>This subcategory reports changes in authentication policy. Events for this subcategory
include:
• 4706: A new trust was created to a domain.
• 4707: A trust to a domain was removed.
• 4713: Kerberos policy was changed.
• 4716: Trusted domain information was modified.
• 4717: System security access was granted to an account.
• 4718: System security access was removed from an account.
• 4739: Domain Policy was changed.
• 4864: A namespace collision was detected.
• 4865: A trusted forest information entry was added.
• 4866: A trusted forest information entry was removed.
• 4867: A trusted forest information entry was modified.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in
your organization, security incidents might not be detected or not enough evidence will
be available for network forensic analysis after security incidents occur. However, if
audit settings are too severe, critically important entries in the Security log may be
obscured by all of the meaningless entries and computer performance and the available
amount of data storage may be seriously affected. Companies that operate in certain
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/PolicyChange_AuditAuthenticationPolicyChange
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Off/None |
| 1 |(Default) Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|5.5 Implement Automated Configuration Monitoring Systems||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Audit Authentication Policy Change\u0027 is set to include \u0027Success\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/PolicyChange_AuditAuthenticationPolicyChange",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"Authentication Policy Change"
```

## 5.8 - 'Audit Authorization Policy Change' is set to include 'Success'

>[!NOTE]
>This subcategory reports changes in authorization policy. Events for this subcategory
include:
• 4703: A user right was adjusted.
• 4704: A user right was assigned.
• 4705: A user right was removed.
• 4670: Permissions on an object were changed.
• 4911: Resource attributes of the object were changed.
• 4913: Central Access Policy on the object was changed.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in
your organization, security incidents might not be detected or not enough evidence will
be available for network forensic analysis after security incidents occur. However, if
audit settings are too severe, critically important entries in the Security log may be
obscured by all of the meaningless entries and computer performance and the available
amount of data storage may be seriously affected. Companies that operate in certain
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/PolicyChange_AuditAuthorizationPolicyChange
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Off/None |
| 1 |(Default) Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|5.5 Implement Automated Configuration Monitoring Systems||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Audit Authorization Policy Change\u0027 is set to include \u0027Success\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/PolicyChange_AuditAuthorizationPolicyChange",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"Authorization Policy Change"
```

## 5.9 - 'Audit Changes to Audit Policy' is set to include 'Success'

>[!NOTE]
>This subcategory reports changes in audit policy including SACL changes. Events for
this subcategory include:
• 4715: The audit policy (SACL) on an object was changed.
• 4719: System audit policy was changed.
• 4902: The Per-user audit policy table was created.
• 4904: An attempt was made to register a security event source.
• 4905: An attempt was made to unregister a security event source.
• 4906: The CrashOnAuditFail value has changed.
• 4907: Auditing settings on object were changed.
• 4908: Special Groups Logon table modified.
• 4912: Per User Audit Policy was changed.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in
your organization, security incidents might not be detected or not enough evidence will
be available for network forensic analysis after security incidents occur. However, if
audit settings are too severe, critically important entries in the Security log may be
obscured by all of the meaningless entries and computer performance and the available
amount of data storage may be seriously affected. Companies that operate in certain
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/PolicyChange_AuditPolicyChange
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Off/None |
| 1 |(Default) Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|5.5 Implement Automated Configuration Monitoring Systems||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Audit Audit Policy Change\u0027 is set to include \u0027Success\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/PolicyChange_AuditPolicyChange",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"Audit Policy Change"
```

## 5.10 - 'Audit File Share Access' is set to 'Success and Failure'

>[!NOTE]
>This policy setting allows you to audit attempts to access a shared folder.
Note: There are no system access control lists (SACLs) for shared folders. If this policy
setting is enabled, access to all shared folders on the system is audited.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in
your organization, security incidents might not be detected or not enough evidence will
be available for network forensic analysis after security incidents occur. However, if
audit settings are too severe, critically important entries in the Security log may be
obscured by all of the meaningless entries and computer performance and the available
amount of data storage may be seriously affected. Companies that operate in certain
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/ObjectAccess_AuditFileShare
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|


|Value|Description|
|---|---|
| 0 |(Default) Off/None |
| 1 | Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|14.6 Protect Information through Access Control Lists|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Audit File Share\u0027 is set to \u0027Success and Failure\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/ObjectAccess_AuditFileShare",
            "value": 3
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"File Share"
```

## 5.11 - 'Audit Other Logon Logoff Events' is set to 'Success and Failure' 

>[!NOTE]
>This subcategory reports other logon/logoff-related events, such as Remote Desktop 
Services session disconnects and reconnects, using RunAs to run processes under a 
different account, and locking and unlocking a workstation. Events for this subcategory 
include:
• 4649: A replay attack was detected.
• 4778: A session was reconnected to a Window Station.
• 4779: A session was disconnected from a Window Station.
• 4800: The workstation was locked.
• 4801: The workstation was unlocked.
• 4802: The screen saver was invoked.
• 4803: The screen saver was dismissed.
• 5378: The requested credentials delegation was disallowed by policy.
• 5632: A request was made to authenticate to a wireless network.
• 5633: A request was made to authenticate to a wired network.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in
your organization, security incidents might not be detected or not enough evidence will
be available for network forensic analysis after security incidents occur. However, if
audit settings are too severe, critically important entries in the Security log may be
obscured by all of the meaningless entries and computer performance and the available
amount of data storage may be seriously affected. Companies that operate in certain
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/AccountLogonLogoff_AuditOtherLogonLogoffEvents
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 |(Default) Off/None |
| 1 | Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.13 Alert on Account Login Behavior Deviation|||:large_blue_circle:|Level - 1|

```
Script:
       {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Audit Other Logon/Logoff Events\u0027 is set to \u0027Success and Failure\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/AccountLogonLogoff_AuditOtherLogonLogoffEvents",
            "value": 3
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"Other Logon/Logoff Events"
```

## 5.12 - 'Audit Security Group Management' is set to include 'Success' 

>[!NOTE]
>This subcategory reports each event of security group management, such as when a 
security group is created, changed, or deleted or when a member is added to or 
removed from a security group. If you enable this Audit policy setting, administrators 
can track events to detect malicious, accidental, and authorized creation of security 
group accounts. Events for this subcategory include:
• 4727: A security-enabled global group was created.
• 4728: A member was added to a security-enabled global group.
• 4729: A member was removed from a security-enabled global group.
• 4730: A security-enabled global group was deleted.
• 4731: A security-enabled local group was created.
• 4732: A member was added to a security-enabled local group.
• 4733: A member was removed from a security-enabled local group.
• 4734: A security-enabled local group was deleted.
• 4735: A security-enabled local group was changed.
• 4737: A security-enabled global group was changed.
• 4754: A security-enabled universal group was created.
• 4755: A security-enabled universal group was changed.
• 4756: A member was added to a security-enabled universal group.
• 4757: A member was removed from a security-enabled universal group.
• 4758: A security-enabled universal group was deleted.
• 4764: A group's type was changed.


>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in
your organization, security incidents might not be detected or not enough evidence will
be available for network forensic analysis after security incidents occur. However, if
audit settings are too severe, critically important entries in the Security log may be
obscured by all of the meaningless entries and computer performance and the available
amount of data storage may be seriously affected. Companies that operate in certain
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/AccountManagement_AuditSecurityGroupManagement
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Off/None |
| 1 |(Default) Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.6 Maintain an Inventory of Accounts||:orange_circle|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Audit Security Group Management\u0027 is set to include \u0027Success\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/AccountManagement_AuditSecurityGroupManagement",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"Security Group Management"
```

## 5.13 - 'Audit Security System Extension' is set to include 'Success'

>[!NOTE]
>This subcategory reports the loading of extension code such as authentication 
packages by the security subsystem. Events for this subcategory include:
• 4610: An authentication package has been loaded by the Local Security 
Authority.
• 4611: A trusted logon process has been registered with the Local Security 
Authority.
• 4614: A notification package has been loaded by the Security Account Manager.
• 4622: A security package has been loaded by the Local Security Authority.
• 4697: A service was installed in the system.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in 
your organization, security incidents might not be detected or not enough evidence will 
be available for network forensic analysis after security incidents occur. However, if 
audit settings are too severe, critically important entries in the Security log may be 
obscured by all of the meaningless entries and computer performance and the available 
amount of data storage may be seriously affected. Companies that operate in certain 
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/System_AuditSecuritySystemExtension
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 |(Default) Off/None |
| 1 | Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Audit Security System Extension\u0027 is set to include \u0027Success\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/System_AuditSecuritySystemExtension",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"Security System Extension"
```

## 5.14 - 'Audit Special Logon' is set to include 'Success' 

>[!NOTE]
>This subcategory reports when a special logon is used. A special logon is a logon that 
has administrator-equivalent privileges and can be used to elevate a process to a higher 
level. Events for this subcategory include:
• 4964 : Special groups have been assigned to a new logon.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in 
your organization, security incidents might not be detected or not enough evidence will 
be available for network forensic analysis after security incidents occur. However, if 
audit settings are too severe, critically important entries in the Security log may be 
obscured by all of the meaningless entries and computer performance and the available 
amount of data storage may be seriously affected. Companies that operate in certain 
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/AccountLogonLogoff_AuditSpecialLogon
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 |(Default) Off/None |
| 1 | Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.13 Alert on Account Login Behavior Deviation|||:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "17.5.6 (L1) Ensure \u0027Audit Special Logon\u0027 is set to include \u0027Success\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/AccountLogonLogoff_AuditSpecialLogon",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"Special Logon"
```

## 5.15 - 'Audit User Account Management' is set to 'Success and Failure'

>[!NOTE]
>This subcategory reports each event of user account management, such as when a 
user account is created, changed, or deleted; a user account is renamed, disabled, or 
enabled; or a password is set or changed. If you enable this Audit policy setting, 
administrators can track events to detect malicious, accidental, and authorized creation 
of user accounts. Events for this subcategory include:
• 4720: A user account was created.
• 4722: A user account was enabled.
• 4723: An attempt was made to change an account's password.
• 4724: An attempt was made to reset an account's password.
• 4725: A user account was disabled.
• 4726: A user account was deleted.
• 4738: A user account was changed.
• 4740: A user account was locked out.
• 4765: SID History was added to an account.
• 4766: An attempt to add SID History to an account failed.
• 4767: A user account was unlocked.
• 4780: The ACL was set on accounts which are members of administrators 
groups.
• 4781: The name of an account was changed:
• 4794: An attempt was made to set the Directory Services Restore Mode.
• 5376: Credential Manager credentials were backed up.
• 5377: Credential Manager credentials were restored from a backup..

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in 
your organization, security incidents might not be detected or not enough evidence will 
be available for network forensic analysis after security incidents occur. However, if 
audit settings are too severe, critically important entries in the Security log may be 
obscured by all of the meaningless entries and computer performance and the available 
amount of data storage may be seriously affected. Companies that operate in certain 
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/AccountManagement_AuditUserAccountManagement
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Off/None |
| 1 |(Default) Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Audit User Account Management\u0027 is set to \u0027Success and Failure\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/AccountManagement_AuditUserAccountManagement",
            "value": 3
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"User Account Management"
```

## 5.16 - 'Detailed Tracking Audit PNP Activity' is set to include 'Success'

>[!NOTE]
>This policy setting allows you to audit when plug and play detects an external device.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in 
your organization, security incidents might not be detected or not enough evidence will 
be available for network forensic analysis after security incidents occur. However, if 
audit settings are too severe, critically important entries in the Security log may be 
obscured by all of the meaningless entries and computer performance and the available 
amount of data storage may be seriously affected. Companies that operate in certain 
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/DetailedTracking_AuditPNPActivity
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 |(Default) Off/None |
| 1 | Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Audit PNP Activity\u0027 is set to include \u0027Success\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/DetailedTracking_AuditPNPActivity",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"PNP Activity"
```

## 5.17 - 'Detailed Tracking Audit Process Creation' is set to include 'Success' 

>[!NOTE]
>This subcategory reports the creation of a process and the name of the program or user 
that created it. Events for this subcategory include:
• 4688: A new process has been created.
• 4696: A primary token was assigned to process.
Refer to Microsoft Knowledge Base article 947226: Description of security events in 
Windows Vista and in Windows Server 2008 for the most recent information about this 
setting.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in 
your organization, security incidents might not be detected or not enough evidence will 
be available for network forensic analysis after security incidents occur. However, if 
audit settings are too severe, critically important entries in the Security log may be 
obscured by all of the meaningless entries and computer performance and the available 
amount of data storage may be seriously affected. Companies that operate in certain 
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/DetailedTracking_AuditProcessCreation
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|


|Value|Description|
|---|---|
| 0 |(Default) Off/None |
| 1 | Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "17.3.2 (L1) Ensure \u0027Audit Process Creation\u0027 is set to include \u0027Success\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/DetailedTracking_AuditProcessCreation",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"Process Creation"
```

## 5.18 - 'Object Access Audit Detailed File Share' is set to include 'Failure'

>[!NOTE]
>This subcategory allows you to audit attempts to access files and folders on a shared 
folder. Events for this subcategory include:
• 5145: network share object was checked to see whether client can be granted 
desired access.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in 
your organization, security incidents might not be detected or not enough evidence will 
be available for network forensic analysis after security incidents occur. However, if 
audit settings are too severe, critically important entries in the Security log may be 
obscured by all of the meaningless entries and computer performance and the available 
amount of data storage may be seriously affected. Companies that operate in certain 
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/ObjectAccess_AuditDetailedFileShare
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 |(Default) Off/None |
| 1 | Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|
|7|14.6 Protect Information through Access Control Lists|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Audit Detailed File Share\u0027 is set to include \u0027Failure\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/ObjectAccess_AuditDetailedFileShare",
            "value": 2
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"Detailed File Share"
```

## 5.19 - 'Object Access Audit Other Object Access  Events' is set to 'Success and Failure'

>[!NOTE]
>This policy setting allows you to audit events generated by the management of task 
scheduler jobs or COM+ objects.
For scheduler jobs, the following are audited:
• Job created.
• Job deleted.
• Job enabled.
• Job disabled.
• Job updated.
For COM+ objects, the following are audited:
• Catalog object added.
• Catalog object updated.
• Catalog object deleted.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in 
your organization, security incidents might not be detected or not enough evidence will 
be available for network forensic analysis after security incidents occur. However, if 
audit settings are too severe, critically important entries in the Security log may be 
obscured by all of the meaningless entries and computer performance and the available 
amount of data storage may be seriously affected. Companies that operate in certain 
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/ObjectAccess_AuditOtherObjectAccessEvents
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 |(Default) Off/None |
| 1 | Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Audit Other Object Access Events\u0027 is set to \u0027Success and Failure\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/ObjectAccess_AuditOtherObjectAccessEvents",
            "value": 3
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"Audit Other Object Access Events"
```

## 5.20 - 'Object Access Audit Removable Storage' is set to 'Success and Failure' 

>[!NOTE]
>This policy setting allows you to audit user attempts to access file system objects on a 
removable storage device. A security audit event is generated only for all objects for all 
types of access requested. If you configure this policy setting, an audit event is 
generated each time an account accesses a file system object on a removable storage. 
Success audits record successful attempts and Failure audits record unsuccessful 
attempts. If you do not configure this policy setting, no audit event is generated when an 
account accesses a file system object on a removable storage.
The recommended state for this setting is: Success and Failure

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in 
your organization, security incidents might not be detected or not enough evidence will 
be available for network forensic analysis after security incidents occur. However, if 
audit settings are too severe, critically important entries in the Security log may be 
obscured by all of the meaningless entries and computer performance and the available 
amount of data storage may be seriously affected. Companies that operate in certain 
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/ObjectAccess_AuditRemovableStorage
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 |(Default) Off/None |
| 1 | Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Audit Removable Storage\u0027 is set to \u0027Success and Failure\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/ObjectAccess_AuditRemovableStorage",
            "value": 3
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"Removable Storage"
```

## 5.21 - 'Policy Change Audit MPSSVC Rule Level Policy Change' is set to 'Success and Failure' 

>[!NOTE]
>This subcategory determines whether the operating system generates audit events 
when changes are made to policy rules for the Microsoft Protection Service 
(MPSSVC.exe). Events for this subcategory include:
• 4944: The following policy was active when the Windows Firewall started.
• 4945: A rule was listed when the Windows Firewall started.
• 4946: A change has been made to Windows Firewall exception list. A rule was 
added.
• 4947: A change has been made to Windows Firewall exception list. A rule was 
modified.
• 4948: A change has been made to Windows Firewall exception list. A rule was 
deleted.
• 4949: Windows Firewall settings were restored to the default values.
• 4950: A Windows Firewall setting has changed.
• 4951: A rule has been ignored because its major version number was not 
recognized by Windows Firewall.
• 4952: Parts of a rule have been ignored because its minor version number was 
not recognized by Windows Firewall. The other parts of the rule will be enforced.
• 4953: A rule has been ignored by Windows Firewall because it could not parse 
the rule.
• 4954: Windows Firewall Group Policy settings have changed. The new settings 
have been applied.
• 4956: Windows Firewall has changed the active profile.
• 4957: Windows Firewall did not apply the following rule.
• 4958: Windows Firewall did not apply the following rule because the rule referred 
to items not configured on this computer.


>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in 
your organization, security incidents might not be detected or not enough evidence will 
be available for network forensic analysis after security incidents occur. However, if 
audit settings are too severe, critically important entries in the Security log may be 
obscured by all of the meaningless entries and computer performance and the available 
amount of data storage may be seriously affected. Companies that operate in certain 
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/PolicyChange_AuditMPSSVCRuleLevelPolicyChange
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 |(Default) Off/None |
| 1 | Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|
|7|5.5 Implement Automated Configuration Monitoring Systems||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Audit MPSSVC Rule-Level Policy Change\u0027 is set to \u0027Success and Failure\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/PolicyChange_AuditMPSSVCRuleLevelPolicyChange",
            "value": 3
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"MPSSVC Rule-Level Policy Change"
```

## 5.22 - 'Policy Change Audit Other Policy Change Events' is set to include 'Failure' 

>[!NOTE]
>This subcategory contains events about EFS Data Recovery Agent policy changes, 
changes in Windows Filtering Platform filter, status on Security policy settings updates 
for local Group Policy settings, Central Access Policy changes, and detailed 
troubleshooting events for Cryptographic Next Generation (CNG) operations.
• 5063: A cryptographic provider operation was attempted.
• 5064: A cryptographic context operation was attempted.
• 5065: A cryptographic context modification was attempted.
• 5066: A cryptographic function operation was attempted.
• 5067: A cryptographic function modification was attempted.
• 5068: A cryptographic function provider operation was attempted.
• 5069: A cryptographic function property operation was attempted.
• 5070: A cryptographic function property modification was attempted.
• 6145: One or more errors occurred while processing security policy in the group 
policy objects.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in 
your organization, security incidents might not be detected or not enough evidence will 
be available for network forensic analysis after security incidents occur. However, if 
audit settings are too severe, critically important entries in the Security log may be 
obscured by all of the meaningless entries and computer performance and the available 
amount of data storage may be seriously affected. Companies that operate in certain 
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/PolicyChange_AuditOtherPolicyChangeEvents
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 |(Default) Off/None |
| 1 | Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|
|7|5.5 Implement Automated Configuration Monitoring Systems||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "17.7.5 (L1) Ensure \u0027Audit Other Policy Change Events\u0027 is set to include \u0027Failure\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/PolicyChange_AuditOtherPolicyChangeEvents",
            "value": 2
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"Other Policy Change Events"
```

## 5.23 - 'Privilege Use Audit Sensitive Privilege Use' is set to 'Success and Failure' 

>[!NOTE]
>This subcategory reports when a user account or service uses a sensitive privilege. A 
sensitive privilege includes the following user rights:
• Act as part of the operating system
• Back up files and directories
• Create a token object
• Debug programs
• Enable computer and user accounts to be trusted for delegation
• Generate security audits
• Impersonate a client after authentication
• Load and unload device drivers
• Manage auditing and security log
• Modify firmware environment values
• Replace a process-level token
• Restore files and directories
• Take ownership of files or other objects
Auditing this subcategory will create a high volume of events. Events for this 
subcategory include:
• 4672: Special privileges assigned to new logon.
• 4673: A privileged service was called.
• 4674: An operation was attempted on a privileged object.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in 
your organization, security incidents might not be detected or not enough evidence will 
be available for network forensic analysis after security incidents occur. However, if 
audit settings are too severe, critically important entries in the Security log may be 
obscured by all of the meaningless entries and computer performance and the available 
amount of data storage may be seriously affected. Companies that operate in certain 
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/PrivilegeUse_AuditSensitivePrivilegeUse
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 |(Default) Off/None |
| 1 | Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Audit Sensitive Privilege Use\u0027 is set to \u0027Success and Failure\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/PrivilegeUse_AuditSensitivePrivilegeUse",
            "value": 3
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"Sensitive Privilege Use"
```

## 5.23 - 'System Audit I Psec Driver' is set to 'Success and Failure' 

>[!NOTE]
>This subcategory reports on the activities of the Internet Protocol security (IPsec) driver. 
Events for this subcategory include:
• 4960: IPsec dropped an inbound packet that failed an integrity check. If this 
problem persists, it could indicate a network issue or that packets are being 
modified in transit to this computer. Verify that the packets sent from the remote 
computer are the same as those received by this computer. This error might also 
indicate interoperability problems with other IPsec implementations.
• 4961: IPsec dropped an inbound packet that failed a replay check. If this problem 
persists, it could indicate a replay attack against this computer.
• 4962: IPsec dropped an inbound packet that failed a replay check. The inbound 
packet had too low a sequence number to ensure it was not a replay.
• 4963: IPsec dropped an inbound clear text packet that should have been 
secured. This is usually due to the remote computer changing its IPsec policy 
without informing this computer. This could also be a spoofing attack attempt.
• 4965: IPsec received a packet from a remote computer with an incorrect Security 
Parameter Index (SPI). This is usually caused by malfunctioning hardware that is 
corrupting packets. If these errors persist, verify that the packets sent from the 
remote computer are the same as those received by this computer. This error 
may also indicate interoperability problems with other IPsec implementations. In 
that case, if connectivity is not impeded, then these events can be ignored.
• 5478: IPsec Services has started successfully.
• 5479: IPsec Services has been shut down successfully. The shutdown of IPsec 
Services can put the computer at greater risk of network attack or expose the 
computer to potential security risks.
• 5480: IPsec Services failed to get the complete list of network interfaces on the 
computer. This poses a potential security risk because some of the network 
interfaces may not get the protection provided by the applied IPsec filters. Use 
the IP Security Monitor snap-in to diagnose the problem.
• 5483: IPsec Services failed to initialize RPC server. IPsec Services could not be 
started.
Page 493
• 5484: IPsec Services has experienced a critical failure and has been shut down. 
The shutdown of IPsec Services can put the computer at greater risk of network 
attack or expose the computer to potential security risks.
• 5485: IPsec Services failed to process some IPsec filters on a plug-and-play 
event for network interfaces. This poses a potential security risk because some 
of the network interfaces may not get the protection provided by the applied 
IPsec filters. Use the IP Security Monitor snap-in to diagnose the problem..

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in 
your organization, security incidents might not be detected or not enough evidence will 
be available for network forensic analysis after security incidents occur. However, if 
audit settings are too severe, critically important entries in the Security log may be 
obscured by all of the meaningless entries and computer performance and the available 
amount of data storage may be seriously affected. Companies that operate in certain 
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/System_AuditIPsecDriver
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 |(Default) Off/None |
| 1 | Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Audit IPsec Driver\u0027 is set to \u0027Success and Failure\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/System_AuditIPsecDriver",
            "value": 3
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"IPsec Driver"
```

## 5.25 - 'System Audit Other System Events' is set to 'Success and Failure

>[!NOTE]
>This subcategory reports on other system events. Events for this subcategory include:
• 5024 : The Windows Firewall Service has started successfully.
• 5025 : The Windows Firewall Service has been stopped.
• 5027 : The Windows Firewall Service was unable to retrieve the security policy 
from the local storage. The service will continue enforcing the current policy.
• 5028 : The Windows Firewall Service was unable to parse the new security 
policy. The service will continue with currently enforced policy.
• 5029: The Windows Firewall Service failed to initialize the driver. The service will 
continue to enforce the current policy.
• 5030: The Windows Firewall Service failed to start.
• 5032: Windows Firewall was unable to notify the user that it blocked an 
application from accepting incoming connections on the network.
• 5033 : The Windows Firewall Driver has started successfully.
• 5034 : The Windows Firewall Driver has been stopped.
• 5035 : The Windows Firewall Driver failed to start.
• 5037 : The Windows Firewall Driver detected critical runtime error. Terminating.
• 5058: Key file operation.
• 5059: Key migration operation.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in 
your organization, security incidents might not be detected or not enough evidence will 
be available for network forensic analysis after security incidents occur. However, if 
audit settings are too severe, critically important entries in the Security log may be 
obscured by all of the meaningless entries and computer performance and the available 
amount of data storage may be seriously affected. Companies that operate in certain 
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/System_AuditOtherSystemEvents
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Off/None |
| 1 | Success |
| 2 | Failure |
| 3	|(Default) Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Audit Other System Events\u0027 is set to \u0027Success and Failure\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/System_AuditOtherSystemEvents",
            "value": 3
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"Other System Events"
```

## 5.26 - 'System Audit Security State Change' is set to include 'Success' 

>[!NOTE]
>This subcategory reports changes in security state of the system, such as when the 
security subsystem starts and stops. Events for this subcategory include:
• 4608: Windows is starting up.
• 4609: Windows is shutting down.
• 4616: The system time was changed.
• 4621: Administrator recovered system from CrashOnAuditFail. Users who are not 
administrators will now be allowed to log on. Some audit-able activity might not 
have been recorded.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in 
your organization, security incidents might not be detected or not enough evidence will 
be available for network forensic analysis after security incidents occur. However, if 
audit settings are too severe, critically important entries in the Security log may be 
obscured by all of the meaningless entries and computer performance and the available 
amount of data storage may be seriously affected. Companies that operate in certain 
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/System_AuditSecurityStateChange
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Off/None |
| 1 |(Default) Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Audit Security State Change\u0027 is set to include \u0027Success\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/System_AuditSecurityStateChange",
            "value": 3
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"Security State Change"
```

## 5.27 - 'System Audit System Integrity' is set to 'Success and Failure'

>[!NOTE]
>This subcategory reports on violations of integrity of the security subsystem. Events for 
this subcategory include:
• 4612 : Internal resources allocated for the queuing of audit messages have been 
exhausted, leading to the loss of some audits.
• 4615 : Invalid use of LPC port.
• 4618 : A monitored security event pattern has occurred.
• 4816 : RPC detected an integrity violation while decrypting an incoming 
message.
• 5038 : Code integrity determined that the image hash of a file is not valid. The file 
could be corrupt due to unauthorized modification or the invalid hash could 
indicate a potential disk device error.
• 5056: A cryptographic self test was performed.
• 5057: A cryptographic primitive operation failed.
• 5060: Verification operation failed.
• 5061: Cryptographic operation.
• 5062: A kernel-mode cryptographic self test was performed.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If no audit settings are configured, or if audit settings are too lax on the computers in 
your organization, security incidents might not be detected or not enough evidence will 
be available for network forensic analysis after security incidents occur. However, if 
audit settings are too severe, critically important entries in the Security log may be 
obscured by all of the meaningless entries and computer performance and the available 
amount of data storage may be seriously affected. Companies that operate in certain 
regulated industries may have legal obligations to log certain events or activities.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Audit/System_AuditSystemIntegrity
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 with KB4516045 [10.0.17134.1039] and later|
|❌ User|✔ Enterprise|✔ Windows 10, version 1809 with KB4516077 [10.0.17763.774] and later|
| |✔ Education|✔ Windows 10, version 1903 with KB4512941 [10.0.18362.329] and later|
| |✔ Windows SE|✔ Windows 10, version 2004 [10.0.19041] and later|
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Off/None |
| 1 |(Default) Success |
| 2 | Failure |
| 3	| Success+Failure |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Audit System Integrity\u0027 is set to \u0027Success and Failure\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Audit/System_AuditSystemIntegrity",
            "value": 3
        }
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
OR
To audit the system using auditpol.exe, perform the following and confirm it is set as prescribed:
auditpol /get /subcategory:"System Integrity"
```

# 21 - Defender

## 21.1 - 'Allow Behavior Monitoring' is set to 'Allowed

>[!NOTE]
>This policy setting allows you to configure behavior monitoring for Microsoft Defender 
Antivirus

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Defender/AllowBehaviorMonitoring
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1607 [10.0.14393] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|


|Value|Description|
|---|---|
| 0 | Not allowed. Turns off behavior monitoring. |
| 1 | Allowed. Turns on real-time behavior monitoring. |


|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.7 Use Behavior-Based Anti-Malware Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.1 Utilize Centrally Managed Anti-malware Software||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Allow Behavior Monitoring\u0027 is set to \u0027Allowed\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Defender/AllowBehaviorMonitoring",
            "value": 1
        }
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a  REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager:AllowBehaviorMonitoring"
```

## 21.2 - 'Allow Email Scanning' is set to 'Allowed' 

>[!NOTE]
>This policy setting allows you to configure e-mail scanning. When e-mail scanning is 
enabled, the engine will parse the mailbox and mail files, according to their specific 
format, in order to analyze the mail bodies and attachments. Several e-mail formats are 
currently supported, for example: pst (Outlook), dbx, mbx, mime (Outlook Express), 
binhex (Mac).

>[!TIP]
>Automated Remedation

>[!CAUTION]
>E-mail scanning by Microsoft Defender Antivirus will be enabled.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Defender/AllowEmailScanning
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1607 [10.0.14393] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|


|Value|Description|
|---|---|
| 0 | Not allowed. Turns off email scanning. |
| 1 | Allowed. Turns on email scanning. |


|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.7 Use Behavior-Based Anti-Malware Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.1 Utilize Centrally Managed Anti-malware Software||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Allow Email Scanning\u0027 is set to \u0027Allowed\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Defender/AllowEmailScanning",
            "value": 1
        }
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a  REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager:AllowEmailScanning
```

## 21.3 - 'Allow Full Scan Removable Drive Scanning' is set to 'Allowed'

>[!NOTE]
>This policy setting allows you to manage whether or not to scan for malicious software 
and unwanted software in the contents of removable drives, such as USB flash drives, 
when running a full scan.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Removable drives will be scanned during any type of scan by Microsoft Defender Antivirus

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Defender/AllowFullScanRemovableDriveScanning
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1607 [10.0.14393] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Not allowed. Turns off scanning on removable drives.|
| 1 | Allowed. Scans removable drives. |


|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.4 Configure Automatic Anti-Malware Scanning of Removable Media||:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.4 Configure Anti-Malware Scanning of Removable Devices|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Allow Full Scan Removable Drive Scanning\u0027 is set to \u0027Allowed\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Defender/AllowFullScanRemovableDriveScanning",
            "value": 1
        }
```

```
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a  REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager:AllowFullScanRemovableDriveScanning
```

## 21.4 - 'Allow Realtime Monitoring' is set to 'Allowed'

>[!NOTE]
>This policy setting allows you to manage whether or not to scan for malicious software 
and unwanted software in the contents of removable drives, such as USB flash drives, 
when running a full scan.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Removable drives will be scanned during any type of scan by Microsoft Defender Antivirus

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Defender/AllowRealtimeMonitoring
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1607 [10.0.14393] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|


|Value|Description|
|---|---|
| 0 | Not allowed. Turns off scanning on removable drives.|
| 1 | Allowed. Scans removable drives. |


|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.1 Deploy and Maintain Anti-Malware Software|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.1 Utilize Centrally Managed Anti-malware Software||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Allow Realtime Monitoring\u0027 is set to \u0027Allowed\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Defender/AllowRealtimeMonitoring",
            "value": 1
        }
```

```
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a  REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager:AllowRealtimeMonitoring
```

## 21.5 - 'Allow scanning of all downloaded files and attachments' is set to 'Allowed'

>[!NOTE]
>This policy setting configures scanning for all downloaded files and attachments

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Defender/AllowIOAVProtection
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1607 [10.0.14393] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Not allowed.|
| 1 | Allowed. |


|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.1 Deploy and Maintain Anti-Malware Software|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.1 Utilize Centrally Managed Anti-malware Software||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Allow scanning of all downloaded files and attachments\u0027 is set to \u0027Allowed\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Defender/AllowIOAVProtection",
            "value": 1
        }
```

```
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a  REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager:AllowIOAVProtection
```

## 21.6 - 'Allow Script Scanning' is set to 'Allowed'

>[!NOTE]
>This policy setting allows script scanning to be turned on/off. Script scanning intercepts 
scripts then scans them before they are executed on the system

>[!TIP]
>Automated Remedation

>[!CAUTION]
>This setting are not applied when tamper protection is enabled.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Defender/AllowScriptScanning
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1607 [10.0.14393] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Not allowed.|
| 1 | Allowed. |


|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.7 Use Behavior-Based Anti-Malware Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.1 Utilize Centrally Managed Anti-malware Software||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Allow Script Scanning\u0027 is set to \u0027Allowed\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Defender/AllowScriptScanning",
            "value": 1
        }
```

```
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a  REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager:AllowScriptScanning
```

## 21.7 - 'Attack Surface Reduction rules' are configured 

>[!NOTE]
>This policy setting sets the Attack Surface Reduction rules

>[!TIP]
>Automated Remedation

>[!CAUTION]
>When a rule is triggered, a notification will be displayed from the Action Center.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|GUID=StateValue|Description|
|---|---|
| GUID=0 | Disable (Disable the attack surface reduction rule) |
| GUID=1 | Block (Enable the attack surface reduction rule) |
| GUID=2 | Audit (Evaluate how the attack surface reduction rule would impact your organization if enabled) |
| GUID=6 | Warn (Enable the attack surface reduction rule but allow the end-user to bypass the block) |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.5 Enable Anti-Exploitation Features||:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.3 Enable Operating System Anti-Exploitation Features/ Deploy Anti-Exploit Technologies||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Attack Surface Reduction rules\u0027 are \u0027configured\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules",
            "value": "56a863a9-875e-4185-98a7-b882c64b5ce5=1|7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c=1|d4f940ab-401b-4efc-aadc-ad5f3c50688a=1|9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=1|be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=1|5beb7efe-fd9a-4556-801d-275e5ffc04cc=1|d3e037e1-3eb8-44c8-a917-57927947596d=1|3b576869-a4ec-4529-8536-b80a7769e899=1|75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84=1|26190899-1602-49e8-8b27-eb1d0a1ce869=1|e6db77e5-3df2-4cf1-b95a-636979351e5b=1|b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4=1|92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b=1|"
        }
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location:
SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager Type: REG_SZ Value Name: ASRRules
```

```
Custom Settings:
GUID Reference:
56a863a9-875e-4185-98a7-b882c64b5ce5 - Block abuse of exploited vulnerable signed drivers 
7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c - Block Adobe Reader from creating child processes
d4f940ab-401b-4efc-aadc-ad5f3c50688a - Block all Office applications from creating child processes
9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 - Block credential stealing from the Windows local security authority subsystem
be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 - Block executable content from email client and webmail
5beb7efe-fd9a-4556-801d-275e5ffc04cc - Block execution of potentially obfuscated scripts
d3e037e1-3eb8-44c8-a917-57927947596d - Block JavaScript or VBScript from launching downloaded executable content
3b576869-a4ec-4529-8536-b80a7769e899 - Block Office applications from creating executable content
75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 - Block Office applications from injecting code into other processes
26190899-1602-49e8-8b27-eb1d0a1ce869 - Block Office communication application from creating child processes
e6db77e5-3df2-4cf1-b95a-636979351e5b - Block persistence through WMI event subscription
b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 - Block untrusted and unsigned processes that run from USB
92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b - Block Win32 API calls from Office macros
```

## 21.9 - 'Enable Network Protection' is set to 'Enabled (block mode)'

>[!NOTE]
>This policy setting controls Microsoft Defender Exploit Guard network protection.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Users and applications will not be able to access dangerous domains

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Defender/EnableNetworkProtection
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | (Default)	Disabled |
| 1 | Enabled (block mode) |
| 2 | Enabled (audit mode) |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|9.3 Maintain and Enforce Network-Based URL Filters||:orange_circle:|:large_blue_circle:|Level - 1|
|8|10.5 Enable Anti-Exploitation Features||:orange_circle:|:large_blue_circle:|Level - 1|
|7|7.4 Maintain and Enforce Network-Based URL Filters||:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.3 Enable Operating System Anti-Exploitation Features/ Deploy Anti-Exploit Technologies||:orange_circle:|:large_blue_circle:|Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Prevent users and apps from accessing dangerous websites\u0027 is set to \u0027Enabled: Block\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Defender/EnableNetworkProtection",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager:EnableNetworkProtection
```

## 21.10 - 'PUA Protection' is set to 'PUA Protection on'

>[!NOTE]
>This policy setting controls detection and action for Potentially Unwanted Applications (PUA), which are sneaky unwanted application bundlers or their bundled applications, that can deliver adware or malware


>[!TIP]
>Automated Remedation

>[!CAUTION]
>Applications that are identified by Microsoft as PUA will be blocked at download and install time.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Defender/PUAProtection
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1607 [10.0.14393] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | (Default)	PUA Protection off. Windows Defender won't protect against potentially unwanted applications. |
| 1 | PUA Protection on. Detected items are blocked. They will show in history along with other threats. |
| 2 | Audit mode. Windows Defender will detect potentially unwanted applications, but take no action. You can review information about the applications Windows Defender would've taken action against by searching for events created by Windows Defender in the Event Viewer. |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.1 Deploy and Maintain Anti-Malware Software|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|2.7 Utilize Application Whitelisting|||:large_blue_circle:|Level - 1|
|7|8.1 Utilize Centrally Managed Anti-malware Software||:orange_circle:|:large_blue_circle:|Level - 1|



```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Configure detection for potentially unwanted applications\u0027 is set to \u0027Enabled: Block\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Defender/PUAProtection",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager:PUAProtection
```

#22 - Delivery Optimization

## 22.1 - 'DO Download Mode' is NOT set to 'HTTP blended with Internet Peering'

>[!NOTE]
>This policy setting specifies the download method that Delivery Optimization can use in downloads of Windows Updates, Apps and App updates. The following methods are supported:
•
0 = HTTP only, no peering.
•
1 = HTTP blended with peering behind the same NAT.
•
2 = HTTP blended with peering across a private group. Peering occurs on devices in the same Active Directory Site (if exist) or the same domain by default. When this option is selected, peering will cross NATs. To create a custom group use Group ID in combination with Mode 2.
•
3 = HTTP blended with Internet Peering.
•
99 = Simple download mode with no peering. Delivery Optimization downloads using HTTP only and does not attempt to contact the Delivery Optimization cloud services.
•
100 = Bypass mode. Do not use Delivery Optimization and use BITS instead.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Machines will not be able to download updates from peers on the Internet. If set to Enabled: HTTP only (0), Enabled: Simple (99), or Enabled: Bypass (100), machines will not be able to download updates from other machines on the same LAN.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/DeliveryOptimization/DODownloadMode
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1507 [10.0.10240] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | (Default)	HTTP only, no peering. |
| 1 | HTTP blended with peering behind the same NAT. |
| 2 | When this option is selected, peering will cross NATs. To create a custom group use Group ID in combination with Mode 2. |
| 3 | HTTP blended with Internet peering.|
| 99 | Simple download mode with no peering. Delivery Optimization downloads using HTTP only and doesn't attempt to contact the Delivery Optimization cloud services. Added in Windows 10, version 1607. |
| 100 | Bypass mode. Windows 10: Don't use Delivery Optimization and use BITS instead. Windows 11: Deprecated, use Simple mode instead.|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|7.3 Perform Automated Operating System Patch Management|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|3.4 Deploy Automated Operating System Patch Management Tools|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|




```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Download Mode\u0027 is NOT set to \u0027Enabled: Internet\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeliveryOptimization/DODownloadMode",
            "value": 3
        },
```

```
Audit:
Navigate to the following registry location and note the WinningProvider GUID.
This value confirms under which User GUID the policy is set
HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\DeliveryOptimization:DODownloadMode_WinningProvider

Navigate to the following registry location and confirm the value is set to anything other than 3.
HKLM\SOFTWARE\Microsoft\PolicyManager\Providers\{GUID}\Default\Device\DeliveryOptimization:DODownloadMode
```

# 23 - Device Guard

## 23.1 - 'Enable Virtualization Based Security' is set to 'Enable virtualization based security'

>[!NOTE]
>This policy setting specifies whether Virtualization Based Security is enabled. Virtualization Based Security uses the Windows Hypervisor to provide support for security services.
Note: Virtualization Based Security requires a 64-bit version of Windows with Secure Boot enabled, which in turn requires that Windows was installed with a UEFI BIOS configuration, not a Legacy BIOS configuration. In addition, if running Windows on a virtual machine, the hardware-assisted CPU virtualization feature (Intel VT-x or AMD-V) must be exposed by the host to the guest VM.

>[!NOTE]
>Note: Credential Guard and Device Guard are not currently supported when using Azure IaaS VMs.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>All drivers on the system must be compatible with this feature or the system may crash. Ensure that this policy setting is only deployed to computers which are known to be compatible.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/DeviceGuard/EnableVirtualizationBasedSecurity
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |❌ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | (Default)	Disable virtualization based security. |
| 1 | Enable virtualization based security. |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.5 Enable Anti-Exploitation Features||:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.3 Enable Operating System Anti-Exploitation Features/ Deploy Anti-Exploit Technologies||:orange_circle:|:large_blue_circle:|Level - 1|




```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Configure detection for potentially unwanted applications\u0027 is set to \u0027Enabled: Block\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceGuard/EnableVirtualizationBasedSecurity",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard:EnableVirtualizationBasedSecurity
```

## 23.2 - 'Configure System Guard Launch' is set to 'Unmanaged Enables Secure Launch if supported by hardware'

>[!NOTE]
>Secure Launch protects the Virtualization Based Security environment from exploited vulnerabilities in device firmware.
Note: Credential Guard and Device Guard are not currently supported when using Azure IaaS VMs.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Warning: All drivers on the system must be compatible with this feature or the system may crash. Ensure that this policy setting is only deployed to computers which are known to be compatible.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/DeviceGuard/ConfigureSystemGuardLaunch
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1809 [10.0.17763] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | (Default)	Unmanaged Configurable by Administrative user. |
| 1 | Unmanaged Enables Secure Launch if supported by hardware. |
| 2 | Unmanaged Disables Secure Launch. |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.5 Enable Anti-Exploitation Features||:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.3 Enable Operating System Anti-Exploitation Features/ Deploy Anti-Exploit Technologies||:orange_circle:|:large_blue_circle:|Level - 1|




```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Configure System Guard Launch\u0027 is set to \u0027Unmanaged Enables Secure Launch if supported by hardware\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceGuard/ConfigureSystemGuardLaunch",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard:ConfigureSystemGuardLaunch
```

## 23.3 - 'Require Platform Security Features' is set to 'Turns on VBS with Secure Boot' or higher

>[!NOTE]
>This policy setting specifies whether Virtualization Based Security (VBS) is enabled. VBS uses the Windows Hypervisor to provide support for security services.
Note: VBS requires a 64-bit version of Windows with Secure Boot enabled, which in turn requires that Windows was installed with a UEFI BIOS configuration, not a Legacy BIOS configuration. In addition, if running Windows on a virtual machine, the hardware-assisted CPU virtualization feature (Intel VT-x or AMD-V) must be exposed by the host to the guest VM.

>[!NOTE]
>Note: Credential Guard and Device Guard are not currently supported when using Azure IaaS VMs.


>[!TIP]
>Automated Remedation

>[!CAUTION]
>Choosing the Secure Boot option provides the system with as much protection as is supported by the computer’s hardware. A system with input/output memory management units (IOMMUs) will have Secure Boot with DMA protection. A system without IOMMUs will simply have Secure Boot enabled without DMA protection.
Choosing the Secure Boot with DMA protection option requires the system to have IOMMUs in order to enable VBS. Without IOMMU hardware support, VBS will be disabled.
Warning: All drivers on the system must be compatible with this feature or the system may crash. Ensure that this policy setting is only deployed to computers which are known to be compatible.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/DeviceGuard/RequirePlatformSecurityFeatures
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|❌ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |❌ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1 | (Default)	Turns on VBS with Secure Boot. |
| 3 | Turns on VBS with Secure Boot and direct memory access (DMA). DMA requires hardware support. |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.5 Enable Anti-Exploitation Features||:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.3 Enable Operating System Anti-Exploitation Features/ Deploy Anti-Exploit Technologies||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Require Platform Security Features\u0027 is set to \u0027Turns on VBS with Secure Boot or higher\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceGuard/RequirePlatformSecurityFeatures",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1 or 3.
HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard:RequirePlatformSecurityFeatures
```

## 23.4 - 'Credential Guard' is set to 'Enabled with UEFI lock' 

>[!NOTE]
>This setting lets users turn on Credential Guard with virtualization-based security to help protect credentials. The "Enabled with UEFI lock" option ensures that Credential Guard cannot be disabled remotely. In order to disable the feature, you must set the Group Policy to "Disabled" as well as remove the security functionality from each computer, with a physically present user, in order to clear configuration persisted in UEFI.
Note: Virtualization Based Security requires a 64-bit version of Windows with Secure Boot enabled, which in turn requires that Windows was installed with a UEFI BIOS configuration, not a Legacy BIOS configuration. In addition, if running Windows on a virtual machine, the hardware-assisted CPU virtualization feature (Intel VT-x or AMD-V) must be exposed by the host to the guest VM.

>[!NOTE]
>Note: Credential Guard and Device Guard are not currently supported when using Azure IaaS VMs.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Warning: All drivers on the system must be compatible with this feature or the system may crash. Ensure that this policy setting is only deployed to computers which are known to be compatible.

>[!CAUTION]
>Warning: Once this setting is turned on and active, Credential Guard cannot be disabled solely via GPO or any other remote method. After removing the setting from GPO, the features must also be manually disabled locally at the machine using the steps provided at this link:

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/DeviceGuard/LsaCfgFlags
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|❌ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |❌ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | (Default)	(Disabled) Turns off Credential Guard remotely if configured previously without UEFI Lock. |
| 1 | (Enabled with UEFI lock) Turns on Credential Guard with UEFI lock |
| 2 | (Enabled without lock) Turns on Credential Guard without UEFI lock.|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|10.5 Enable Anti-Exploitation Features||:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.3 Enable Operating System Anti-Exploitation Features/ Deploy Anti-Exploit Technologies||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Require Platform Security Features\u0027 is set to \u0027Turns on VBS with Secure Boot or higher\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceGuard/LsaCfgFlags",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard:RequirePlatformSecurityFeatures
```

# 24 - Device lock

## 24.1 - 'Alphanumeric Device Password Required' is set to 'Password, Numeric PIN, or Alphanumeric PIN required' 

>[!NOTE]
>This policy setting determines the type of PIN or password required. This policy only
applies if the DeviceLock/DevicePasswordEnabled policy is set to 0. In settings catalog
this setting is a pre-requisite for "Min Device Password Complex Characters".

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If an organization is using Windows Hello for Business, the the Device Lock password
settings can impact PIN polices if those policies are not first defined elsewhere.
Windows will follow the Windows Hello for Business policies for PINs if this key exists: 
HKLM\SOFTWARE\Microsoft\Policies\PassportForWork\<Tenant-ID>\Device\Policies.
Otherwise, it will follow Device Lock policies.


```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/DeviceLock/AlphanumericDevicePasswordRequired
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1507 [10.0.10240] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Password or Alphanumeric PIN required. |
| 1 | Password or Numeric PIN required. |
| 2 | (Default) Password, Numeric PIN, or Alphanumeric PIN required.|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|5.2 Use Unique Passwords|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.2 Configure Centralized Point of Authentication||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Alphanumeric Device Password Required\u0027 is set to \u0027Password, Numeric PIN, or Alphanumeric PIN required\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceLock/AlphanumericDevicePasswordRequired",
            "value": 2
        },
```

```
Audit:
Navigate to the following registry location and note the WinningProvider GUID. This value confirms under which User GUID the policy is set.
HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock:AlphanumericDevicePasswordRequired_WinningProvider

Navigate to the following registry location and confirm the value is set to 2.
HKLM\SOFTWARE\Microsoft\PolicyManager\Providers\{GUID}\Default\Device\DeviceLock:AlphanumericDevicePasswordRequired
```

## 24.2 - 'Device Password Expiration' is set to '365 or fewer days, but not 0'

>[!NOTE]
>This policy setting defines how long a user can use their password before it expires.
Values for this policy setting range from 0 to 730 days. If you set the value to 0, the
password will never expire.
Because attackers can crack passwords, the more frequently you change the password
the less opportunity an attacker has to use a cracked password. However, the lower this
value is set, the higher the potential for an increase in calls to help desk support due to
users having to change their password or forgetting which password is current.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If the Maximum password age setting is too low, users are required to change their
passwords very often. Such a configuration can reduce security in the organization,
because users might write their passwords in an insecure location or lose them. If the
value for this policy setting is too high, the level of security within an organization is
reduced because it allows potential attackers more time in which to discover user
passwords or to use compromised accounts.

>[!CAUTION]
>Warning: If an organization is using Windows Hello for Business, the the Device
Lock password settings can impact PIN polices if those policies are not first defined
elsewhere. Windows will follow the Windows Hello for Business policies for PINs if this
key exists: HKLM\SOFTWARE\Microsoft\Policies\PassportForWork\<TenantID>\Device\Policies. Otherwise, it will follow Device Lock policies.


```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/DeviceLock/DevicePasswordExpiration
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1507 [10.0.10240] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | 0 (Default)(Recommended) |
| X | Allowed Range: [0-730]  |


|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|5.2 Use Unique Passwords|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.2 Configure Centralized Point of Authentication||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Device Password Expiration\u0027 is set to \u0027365 or fewer days, but not 0\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceLock/DevicePasswordExpiration",
            "value": 0
        },
```

```
Audit:
Navigate to the following registry location and note the WinningProvider GUID. This value confirms under which User GUID the policy is set.
HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock:DevicePasswordExpiration_WinningProvider

Navigate to the following registry location and confirm the value is set to 365 or fewer days, but not 0.
HKLM\SOFTWARE\Microsoft\PolicyManager\Providers\{GUID}\Default\Device\DeviceLock:DevicePasswordExpiration
```

## 24.3 - 'Device Password History' is set to '24 or more password(s)' 

>[!NOTE]
>This policy setting determines the number of renewed, unique passwords that have to
be associated with a user account before you can reuse an old password. In an Intune
managed environment this setting applies to local user accounts and not Entra ID
accounts. 
The value includes the user's current password. This value denotes that with a setting of
1, the user can't reuse their current password when choosing a new password, while a
setting of 5 means that a user can't set their new password to their current password or
any of their previous four passwords.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The major impact of this configuration is that users must create a new password every
time they are required to change their old one. If users are required to change their
passwords to new unique values, there is an increased risk of users who write their
passwords somewhere so that they do not forget them. Another risk is that users may
create passwords that change incrementally (for example, password01, password02,
and so on) to facilitate memorization but make them easier to guess.

>[!CAUTION]
>Warning: If an organization is using Windows Hello for Business, the the Device
Lock password settings can impact PIN polices if those policies are not first defined
elsewhere. Windows will follow the Windows Hello for Business policies for PINs if this
key exists: HKLM\SOFTWARE\Microsoft\Policies\PassportForWork\<TenantID>\Device\Policies. Otherwise, it will follow Device Lock policies.


```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/DeviceLock/DevicePasswordHistory
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1507 [10.0.10240] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | 0 (Default)(Recommended) |
| X | Allowed Range: [0-50]  |


|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|5.2 Use Unique Passwords|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.2 Configure Centralized Point of Authentication||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Device Password History\u0027 is set to \u002724 or more passwords\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceLock/DevicePasswordHistory",
            "value": 24
        },
```

```
Audit:
Navigate to the following registry location and note the WinningProvider GUID. This value confirms under which User GUID the policy is set.
HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock:DevicePasswordHistory_WinningProvider

Navigate to the following registry location and confirm the value is set to 2.
HKLM\SOFTWARE\Microsoft\PolicyManager\Providers\{GUID}\Default\Device\DeviceLock:DevicePasswordHistory
```

## 24.4 - 'Min Device Password Complex Characters' is set to 'Digits lowercase letters and uppercase letters are required' 

>[!NOTE]
>This policy setting determines the number of renewed, unique passwords that have to
be associated with a user account before you can reuse an old password. In an Intune
managed environment this setting applies to local user accounts and not Entra ID
accounts. 
The value includes the user's current password. This value denotes that with a setting of
1, the user can't reuse their current password when choosing a new password, while a
setting of 5 means that a user can't set their new password to their current password or
any of their previous four passwords.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The major impact of this configuration is that users must create a new password every
time they are required to change their old one. If users are required to change their
passwords to new unique values, there is an increased risk of users who write their
passwords somewhere so that they do not forget them. Another risk is that users may
create passwords that change incrementally (for example, password01, password02,
and so on) to facilitate memorization but make them easier to guess.

>[!CAUTION]
>Warning: If an organization is using Windows Hello for Business, the the Device
Lock password settings can impact PIN polices if those policies are not first defined
elsewhere. Windows will follow the Windows Hello for Business policies for PINs if this
key exists: HKLM\SOFTWARE\Microsoft\Policies\PassportForWork\<TenantID>\Device\Policies. Otherwise, it will follow Device Lock policies.


```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/DeviceLock/MinDevicePasswordComplexCharacters
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1507 [10.0.10240] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1 | Digits only. |
| 2 | Digits and lowercase letters are required.  |
| 3 | Digits lowercase letters and uppercase letters are required. Not supported in desktop Microsoft accounts and domain accounts.  |
| 4 | Digits lowercase letters uppercase letters and special characters are required. Not supported in desktop.  |


|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|5.2 Use Unique Passwords|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.2 Configure Centralized Point of Authentication||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Min Device Password Complex Characters\u0027 is set to \u0027Digits lowercase letters and uppercase letters are required\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceLock/MinDevicePasswordComplexCharacters",
            "value": 24
        },
```

```
Audit:
Navigate to the following registry location and note the WinningProvider GUID. This value confirms under which User GUID the policy is set.
HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock:DevicePasswordHistory_WinningProvider

Navigate to the following registry location and confirm the value is set to 2.
HKLM\SOFTWARE\Microsoft\PolicyManager\Providers\{GUID}\Default\Device\DeviceLock:DevicePasswordHistory
```

## 24.5 - 'Min Device Password Length' is set to '14 or more character(s)'

>[!NOTE]
>This policy setting determines the least number of characters that make up a password
for a local user account. There are many different theories about how to determine the
best password length for an organization, but perhaps "passphrase" is a better term
than "password." In Microsoft Windows 2000 or newer, passphrases can be quite long
and can include spaces. Therefore, a phrase such as "I want to drink a $5 milkshake" is
a valid passphrase; it is a considerably stronger password than an 8 or 10 character
string of random numbers and letters, and yet is easier to remember. Users must be
educated about the proper selection and maintenance of passwords, especially around
password length. In enterprise environments, the ideal value for the Minimum password
length setting is 14 characters, however you should adjust this value to meet your
organization's business requirements.


>[!TIP]
>Automated Remedation

>[!CAUTION]
>Requirements for extremely long passwords can actually decrease the security of an
organization, because users might leave the information in an insecure location or lose
it. If very long passwords are required, mistyped passwords could cause account
lockouts and increase the volume of help desk calls. If your organization has issues with
forgotten passwords due to password length requirements, consider teaching your
users about passphrases, which are often easier to remember and, due to the larger
number of character combinations, much harder to discover.


>[!CAUTION]
>Warning: If an organization is using Windows Hello for Business, the the Device
Lock password settings can impact PIN polices if those policies are not first defined
elsewhere. Windows will follow the Windows Hello for Business policies for PINs if this
key exists: HKLM\SOFTWARE\Microsoft\Policies\PassportForWork\<TenantID>\Device\Policies. Otherwise, it will follow Device Lock policies


```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/DeviceLock/MinDevicePasswordLength
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1507 [10.0.10240] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 14 | 14 (Recommended) |
| X | Allowed Range: [4-16]  |


|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|5.2 Use Unique Passwords|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|4.4 Use Unique Passwords||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.2 Configure Centralized Point of Authentication||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Min Device Password Length\u0027 is set to \u002714 or more characters\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceLock/MinDevicePasswordLength",
            "value": 14
        },
```

```
Audit:
Navigate to the following registry location and note the WinningProvider GUID. This value confirms under which User GUID the policy is set.
HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock:MinDevicePasswordLength_WinningProvider

Navigate to the following registry location and confirm the value is set to 14 (or higher).
HKLM\SOFTWARE\Microsoft\PolicyManager\Providers\{GUID}\Default\Device\DeviceLock:MinDevicePasswordLength
```

## 24.6 - 'Minimum Password Age' is set to '1 or more day(s)'

>[!NOTE]
>This security setting determines the period of time (in days) that a password must be
used before the user can change it. You can set a value between 1 and 998 days, or
you can allow changes immediately by setting the number of days to 0.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If an administrator sets a password for a user but wants that user to change the
password when the user first logs on, the administrator must select the User must
change password at next logon check box, or the user will not be able to change the
password until the next day.

>[!CAUTION]
>Warning: If an organization is using Windows Hello for Business, the the Device
Lock password settings can impact PIN polices if those policies are not first defined
elsewhere. Windows will follow the Windows Hello for Business policies for PINs if this
key exists: HKLM\SOFTWARE\Microsoft\Policies\PassportForWork\<TenantID>\Device\Policies. Otherwise, it will follow Device Lock policies.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/DeviceLock/MinimumPasswordAge
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1 | 1 (Recommended) |
| 90 | 90 (Realistic Recommendation) |
| X | Allowed Range: [0-998]  |

 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|5.2 Use Unique Passwords|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.10 Ensure All Accounts Have An Expiration Date||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Minimum Password Age\u0027 is set to \u00271 or more day\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/DeviceLock/MinimumPasswordAge",
            "value": 90
        },
```

```
Audit:
Navigate to the following registry location and note the WinningProvider GUID. This value confirms under which User GUID the policy is set.
HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock:MinimumPasswordAge_WinningProvider

Navigate to the following registry location and confirm the value is set to 0.
HKLM\SOFTWARE\Microsoft\PolicyManager\Providers\{GUID}\Default\Device\DeviceLock:MinimumPasswordAge
```

# 30 - Experience

## 30.1 - 'Allow Cortana' is set to 'Block'

>[!NOTE]
>This policy setting specifies whether Cortana is allowed on the device.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Cortana will be turned off. Users will still be able to use search to find things on the
device and on the Internet.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Experience/AllowCortana
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1507 [10.0.10240] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Not allowed. |
| 1 |(Default) Allowed.|
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Allow Cortana\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Experience/AllowCortana",
            "value": 0
        },
```

```
Audit:
Navigate to the following registry location and note the WinningProvider GUID. This value confirms under which User GUID the policy is set.
HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience:AllowCortana_WinningProvider

Navigate to the following registry location and confirm the value is set to 0.
HKLM\SOFTWARE\Microsoft\PolicyManager\Providers\{GUID}\Default\Device\Experience:AllowCortana
```

## 30.2 - 'Allow Spotlight Collection (User)' is set to '0'

>[!NOTE]
>This policy setting removes the Spotlight collection setting in Personalization, rendering
the user unable to select and subsequently download daily images from Microsoft to the
system desktop.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The Spotlight collection feature will not be available as an option in Personalization
settings, so users will not be able to download daily images from Microsoft.



```
OMA-URI 
./User/Vendor/MSFT/Policy/Config/Experience/AllowSpotlightCollection
```

|Scope | Editions| Applicable OS |
|---|---|---|
|❌ Device|❌ Pro|✔ Windows 11, version 21H2 [10.0.22000] and later|
|✔ User|✔ Enterprise||
| |✔ Education||
| |❌ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Not allowed. |
| 1 |(Default) Allowed.|
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Allow Spotlight Collection User\u0027 is set to \u00270\u0027",
            "omaUri": "./User/Vendor/MSFT/Policy/Config/Experience/AllowSpotlightCollection",
            "value": 0
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Microsoft\PolicyManager\current\[sid]\Experience:AllowSpotlightCollection
```

## 30.4 - 'Disable Consumer Account State Content' is set to 'Enabled'

>[!NOTE]
>This policy setting determines whether cloud consumer account state content is allowed
in all Windows experiences.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Users will not be able to use Microsoft consumer accounts on the system, and
associated Windows experiences will instead present default fallback content.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Experience/DisableConsumerAccountStateContent
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|❌ Pro|✔ Windows 11, version 21H2 [10.0.22000] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |❌ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Disabled. |
| 1 | Enabled.|
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|5.6 Centralize Account Management||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Disable Consumer Account State Content\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Experience/DisableConsumerAccountStateContent",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent:DisableConsumerAccountStateContent
```

## 30.5 - 'Do not show feedback notifications' is set to 'Feedback notifications are disabled'

>[!NOTE]
>This policy setting allows an organization to prevent its devices from showing feedback
questions from Microsoft.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Users will no longer see feedback notifications through the Windows Feedback app

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Experience/DoNotShowFeedbackNotifications
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1607 [10.0.14393] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Feedback notifications aren't disabled. The actual state of feedback notifications on the device will then depend on what GP has configured or what the user has configured locally. |
| 1 | Feedback notifications are disabled.|
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|0.0 Explicitly Not Mapped||:orange_circle:|:large_blue_circle:|Level - 1|
|8|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Do not show feedback notifications\u0027 is set to \u0027Feedback notifications are disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/Experience/DoNotShowFeedbackNotifications",
            "value": 1
        },
```

```
Audit:
Navigate to the following registry location and note the WinningProvider GUID. This value confirms under which User GUID the policy is set.
HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Experience:DoNotShowFeedbackNotifications_WinningProvider

Navigate to the following registry location and confirm the value is set to 1.
HKLM\SOFTWARE\Microsoft\PolicyManager\Providers\{GUID}\Default\Device\Experience:DoNotShowFeedbackNotifications
```

# 35 - Firewall

## 35.1 - 'Enable Domain Network Firewall' is set to 'True'

>[!NOTE]
>Select True (recommended) to have Windows Firewall with Advanced Security use the
settings for this profile to filter network traffic. If you select False, Windows Firewall with
Advanced Security will not use any of the firewall rules or connection security rules for
this profile.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/Experience/DoNotShowFeedbackNotifications
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| true | Enables Windows Firewall. |
| false | Disables Windows Firewall.|
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.5 Implement and Manage a Firewall on End-User Devices|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingBoolean",
            "displayName": "\u0027Windows Firewall: Domain: Firewall state\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/DomainProfile/EnableFirewall",
            "value": true
        },
```

```
Audit:
Navigate to the following registry location and confirm the value is set to 1.
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\DomainProfile:EnableFirewall
```

## 35.2 - 'Enable Domain Network Firewall: Default Inbound Action for Domain Profile' is set to 'Block

>[!NOTE]
>This setting determines the behavior for inbound connections that do not match an
inbound firewall rule

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/DomainProfile/DefaultInboundAction
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Allow Inbound By Default. |
| 1 | Block Inbound By Default.|
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.5 Implement and Manage a Firewall on End-User Devices|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|11.2 Document Traffic Configuration Rules||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Windows Firewall: Domain: Inbound connections\u0027 is set to \u0027Block\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/DomainProfile/DefaultInboundAction",
            "value": 1
        },
```

```
Audit:
Navigate to the following registry location and confirm the value is set to 1.
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\DomainProfile:DefaultInboundAction
```

## 35.3 - 'Enable Domain Network Firewall: Disable Inbound Notifications' is set to 'True'

>[!NOTE]
>Select this option to have Windows Firewall with Advanced Security display notifications
to the user when a program is blocked from receiving inbound connections.


>[!TIP]
>Automated Remedation

>[!CAUTION]
>Windows Firewall will not display a notification when a program is blocked from
receiving inbound connections

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/DomainProfile/DisableInboundNotifications
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| false | Firewall May Display Notification. |
| true | Firewall Must Not Display Notification |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.5 Implement and Manage a Firewall on End-User Devices|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|11.2 Document Traffic Configuration Rules||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Enable Domain Network Firewall: Disable Inbound Notifications\u0027 is set to \u0027True\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/DomainProfile/DisableInboundNotifications",
            "value": true
        },
```

```
Audit:
Navigate to the following registry location and confirm the value is set to 1.
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\DomainProfile:DisableNotifications
```

## 35.4 - 'Enable Domain Network Firewall: Enable Log Dropped Packets' is set to 'Yes: Enable Logging Of Dropped Packets'

>[!NOTE]
>Use this option to log when Windows Firewall with Advanced Security discards an
inbound packet for any reason. The log records why and when the packet was dropped.
Look for entries with the word DROP in the action column of the log

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Information about dropped packets will be recorded in the firewall log file.

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/DomainProfile/EnableLogDroppedPackets
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 11, version 22H2 [10.0.22621] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| false | Disable Logging Of Dropped Packets. |
| true | Enable Logging Of Dropped Packets. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.5 Implement and Manage a Firewall on End-User Devices|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.5 Collect Detailed Audit Logs|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|
|8|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Enable Domain Network Firewall: Enable Log Dropped Packets\u0027 is set to \u0027Yes: Enable Logging Of Dropped Packets\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/DomainProfile/EnableLogDroppedPackets",
            "value": true
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\DomainProfile\Logging:LogDroppedPackets
```

## 35.5 - 'Enable Domain Network Firewall: Enable Log Success Connections' is set to 'Enable Logging Of Successful Connections'

>[!NOTE]
>Use this option to log when Windows Firewall with Advanced Security allows an
inbound connection. The log records why and when the connection was formed. Look
for entries with the word ALLOW in the action column of the log.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Information about successful connections will be recorded in the firewall log file.

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/DomainProfile/EnableLogSuccessConnections
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 11, version 22H2 [10.0.22621] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| false | Disable Logging Of Successful Connections. |
| true | Enable Logging Of Successful Connections. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.5 Implement and Manage a Firewall on End-User Devices|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|8.5 Collect Detailed Audit Logs|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|
|8|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Enable Domain Network Firewall: Enable Log Success Connections\u0027 is set to \u0027Enable Logging Of Successful Connections\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/DomainProfile/EnableLogSuccessConnections",
            "value": true
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\DomainProfile\Logging:LogSuccessfulConnections
```

## 35.6 - 'Enable Domain Network Firewall: Log File Path' is set to '%SystemRoot%\System32\logfiles\firewall\domainfw.log'

>[!NOTE]
>Use this option to specify the path and name of the file in which Windows Firewall will
write its log information.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The log file will be stored in the specified file.

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/DomainProfile/LogFilePath
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 11, version 22H2 [10.0.22621] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| %systemroot%\system32\LogFiles\Firewall\pfirewall.log | Default Value |
| %SystemRoot%\System32\logfiles\firewall\domainfw.log | Custom Settings (Recommended) |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.2 Collect Audit Logs|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Loggin|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Enable Domain Network Firewall: Log File Path\u0027 is set to \u0027%SystemRoot%\System32\logfiles\firewall\domainfw.log\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/DomainProfile/LogFilePath",
            "value": %SystemRoot%\System32\logfiles\firewall\domainfw.log
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_SZ value of %SystemRoot%\System32\logfiles\firewall\domainfw.log.
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\DomainProfile\Logging:LogFilePath
```
## 35.7 - 'Enable Domain Network Firewall: Log Max File Size' is set to '16,384 KB or greater'

>[!NOTE]
>Use this option to specify the size limit of the file in which Windows Firewall will write its
log information

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The log file size will be limited to the specified size, old events will be overwritten by
newer ones when the limit is reached.

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/DomainProfile/LogMaxFileSize
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 11, version 22H2 [10.0.22621] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1024 | Default value |
| 16384 | Custom Settings (Recommended) |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.3 Ensure Adequate Audit Log Storage|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.4 Ensure adequate storage for logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Enable Domain Network Firewall: Log Max File Size\u0027 is set to \u002716,384 KB or greater\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/DomainProfile/LogMaxFileSize",
            "value": 16384
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 16384.
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\DomainProfile\Logging:LogFileSize
```

## 35.8 - 'Enable Private Network Firewall' is set to 'True'

>[!NOTE]
>Select True (recommended) to have Windows Firewall with Advanced Security use the
settings for this profile to filter network traffic. If you select False, Windows Firewall with
Advanced Security will not use any of the firewall rules or connection security rules for
this profile

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None.

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/EnableFirewall
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 11, version 22H2 [10.0.22621] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| false | Disable Firewall. |
| true | Enable Firewall. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.5 Implement and Manage a Firewall on End-User Devices|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Enable Domain Network Firewall: Log Max File Size\u0027 is set to \u002716,384 KB or greater\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/EnableFirewall",
            "value": 16384
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\StandardProfile:EnableFirewall
```

## 35.9 - 'Enable Private Network Firewall: Default Inbound Action for Private Profile' is set to 'Block'

>[!NOTE]
>This setting determines the behavior for inbound connections that do not match an
inbound firewall rule.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None.

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/DefaultInboundAction
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Allow Inbound By Default. |
| 1 | Block Inbound By Default. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.5 Implement and Manage a Firewall on End-User Devices|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|11.2 Document Traffic Configuration Rules||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Windows Firewall: Private: Inbound connections\u0027 is set to \u0027Block\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/DefaultInboundAction",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\StandardProfile:DefaultInboundAction
```

## 35.10 - 'Enable Private Network Firewall: Disable Inbound Notifications' is set to 'True'

>[!NOTE]
>Select this option to have Windows Firewall with Advanced Security display notifications
to the user when a program is blocked from receiving inbound connections.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Windows Firewall will not display a notification when a program is blocked from
receiving inbound connections.

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/DisableInboundNotifications
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| false | (Default) Firewall May Display Notification. |
| true | Firewall Must Not Display Notification. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.5 Implement and Manage a Firewall on End-User Devices|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|11.2 Document Traffic Configuration Rules||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Windows Firewall: Private: Inbound connections\u0027 is set to \u0027Block\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/DisableInboundNotifications",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\StandardProfile:DisableNotifications
```

## 35.11 - 'Enable Private Network Firewall: Enable Log Success Connections' is set to 'Enable Logging Of Successful Connections' 

>[!NOTE]
>Use this option to log when Windows Firewall with Advanced Security allows an
inbound connection. The log records why and when the connection was formed. Look
for entries with the word ALLOW in the action column of the log.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Information about successful connections will be recorded in the firewall log file.

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/EnableLogSuccessConnections
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 11, version 22H2 [10.0.22621] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| false | (Default) Disable Logging Of Successful Connections. |
| true | Enable Logging Of Successful Connections. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.5 Implement and Manage a Firewall on End-User Devices|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Enable Private Network Firewall: Enable Log Success Connections\u0027 is set to \u0027Enable Logging Of Successful Connections\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/EnableLogSuccessConnections",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\StandardProfile\Logging:LogSuccessfulConnections
```

## 35.12 - 'Enable Private Network Firewall: Enable Log Dropped Packets' is set to 'Yes: Enable Logging Of Dropped Packets'

>[!NOTE]
>Use this option to log when Windows Firewall with Advanced Security discards an
inbound packet for any reason. The log records why and when the packet was dropped.
Look for entries with the word DROP in the action column of the log.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Information about dropped packets will be recorded in the firewall log file.

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/EnableLogDroppedPackets
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 11, version 22H2 [10.0.22621] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| false | (Default) Disable Logging Of Dropped Packets. |
| true | Enable Logging Of Dropped Packets. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.5 Implement and Manage a Firewall on End-User Devices|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Enable Private Network Firewall: Enable Log Dropped Packets\u0027 is set to \u0027Yes: Enable Logging Of Dropped Packets\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/EnableLogDroppedPackets",
            "value": true
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\StandardProfile\Logging:LogDroppedPackets
```

## 35.13 - 'Enable Private Network Firewall: Log File Path' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log' 

>[!NOTE]
>Use this option to specify the path and name of the file in which Windows Firewall will
write its log information.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The log file will be stored in the specified file

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/LogFilePath
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 11, version 22H2 [10.0.22621] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| %SystemRoot%\System32\logfiles\firewall\pfirewall.log | (Default) |
| %SystemRoot%\System32\logfiles\firewall\privatefw.log | Custom Settings (Recommended) |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.2 Collect Audit Logs|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Enable Private Network Firewall: Log File Path\u0027 is set to \u0027%SystemRoot%\System32\logfiles\firewall\privatefw.log\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/LogFilePath",
            "value": %SystemRoot%\System32\logfiles\firewall\privatefw.log
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_SZ value of %SystemRoot%\System32\logfiles\firewall\privatefw.log.
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\StandardProfile\Logging:LogFilePath
```

## 35.14 - 'Enable Private Network Firewall: Log Max File Size' is set to '16,384 KB or greater'

>[!NOTE]
>Use this option to specify the size limit of the file in which Windows Firewall will write its
log information.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The log file size will be limited to the specified size, old events will be overwritten by
newer ones when the limit is reached.

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/LogMaxFileSize
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 11, version 22H2 [10.0.22621] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1024 | (Default value) |
| 16384 | Custom Settings (Recommended) |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.2 Collect Audit Logs|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Enable Private Network Firewall: Log Max File Size\u0027 is set to \u002716,384 KB or greater\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/LogMaxFileSize",
            "value": 16384
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 16384.
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\StandardProfile\Logging:LogFileSize
```

## 35.15 - 'Enable Public Network Firewall' is set to 'True' 

>[!NOTE]
>Select True (recommended) to have Windows Firewall with Advanced Security use the
settings for this profile to filter network traffic. If you select False, Windows Firewall with
Advanced Security will not use any of the firewall rules or connection security rules for
this profile.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/PublicProfile/EnableFirewall
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| false | Disable Firewall. |
| true  | (default) Enable Firewall.|
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.5 Implement and Manage a Firewall on End-User Devices|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Enable Public Network Firewall\u0027 is set to \u0027True\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/PublicProfile/EnableFirewall",
            "value": true
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\PublicProfile:EnableFirewall
```

## 35.16 - 'Enable Public Network Firewall: Allow Local Ipsec Policy Merge' is set to 'False'

>[!NOTE]
>This setting controls whether local administrators are allowed to create connection
security rules that apply together with connection security rules configured by Group
Policy.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Administrators can still create local connection security rules, but the rules will not be
applied.

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/PublicProfile/AllowLocalIpsecPolicyMerge
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| false | AllowLocalIpsecPolicyMerge Off. |
| true  | (default) AllowLocalIpsecPolicyMerge On|
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.5 Implement and Manage a Firewall on End-User Devices|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|11.2 Document Traffic Configuration Rules||:orange_circle:|:large_blue_circle:|Level - 1|
```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Enable Public Network Firewall: Allow Local Ipsec Policy Merge\u0027 is set to \u0027False\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/PublicProfile/AllowLocalIpsecPolicyMerge",
            "value": false
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\PublicProfile:AllowLocalIPsecPolicyMerge
```

## 35.17 - 'Enable Public Network Firewall: Allow Local Policy Merge' is set to 'False'

>[!NOTE]
>This setting controls whether local administrators are allowed to create local firewall
rules that apply together with firewall rules configured by Group Policy

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Administrators can still create firewall rules, but the rules will not be applied.

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/PublicProfile/AllowLocalPolicyMerge
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| false | AllowLocalPolicyMerge Off.. |
| true  | (default) AllowLocalPolicyMerge On.|
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.5 Implement and Manage a Firewall on End-User Devices|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|11.3 Use Automated Tools to Verify Standard Device Configurations and Detect Changes||:orange_circle:|:large_blue_circle:|Level - 1|
```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Enable Public Network Firewall: Allow Local Policy Merge\u0027 is set to \u0027False\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/PublicProfile/AllowLocalPolicyMerge",
            "value": false
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\PublicProfile:AllowLocalPolicyMerge
```

## 35.18 - 'Enable Public Network Firewall: Default Inbound Action for Public Profile' is set to 'Block

>[!NOTE]
>This setting determines the behavior for inbound connections that do not match an
inbound firewall rule.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/PublicProfile/DefaultInboundAction
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Allow Inbound By Default. |
| 1  | (default) Block Inbound By Default.|
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.5 Implement and Manage a Firewall on End-User Devices|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|11.2 Document Traffic Configuration Rules||:orange_circle:|:large_blue_circle:|Level - 1|
```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Enable Public Network Firewall: Default Inbound Action for Public Profile\u0027 is set to \u0027Block\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/PublicProfile/DefaultInboundAction",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\PublicProfile:DefaultInboundAction
```

## 35.19 - 'Enable Public Network Firewall: Disable Inbound Notifications' is set to 'True'

>[!NOTE]
>Select this option to have Windows Firewall with Advanced Security display notifications
to the user when a program is blocked from receiving inbound connections.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Windows Firewall will not display a notification when a program is blocked from
receiving inbound connections.

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/PublicProfile/DisableInboundNotifications
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| true | Firewall May Display Notification. |
| false  | Firewall Must Not Display Notification. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.5 Implement and Manage a Firewall on End-User Devices|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|11.2 Document Traffic Configuration Rules||:orange_circle:|:large_blue_circle:|Level - 1|
```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Enable Public Network Firewall: Disable Inbound Notifications\u0027 is set to \u0027True\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/PublicProfile/DisableInboundNotifications",
            "value": true
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\PublicProfile:DisableNotifications
```

## 35.20 - 'Enable Public Network Firewall: Enable Log Dropped Packets' is set to 'Yes: Enable Logging Of Dropped Packets'

>[!NOTE]
>Use this option to log when Windows Firewall with Advanced Security discards an
inbound packet for any reason. The log records why and when the packet was dropped.
Look for entries with the word DROP in the action column of the log.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Information about dropped packets will be recorded in the firewall log file.

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/PublicProfile/EnableLogDroppedPackets
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 11, version 22H2 [10.0.22621] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| false | (default) Disable Logging Of Dropped Packets. |
| true  | Enable Logging Of Dropped Packets. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.5 Implement and Manage a Firewall on End-User Devices|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Enable Public Network Firewall: Disable Inbound Notifications\u0027 is set to \u0027True\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/PublicProfile/EnableLogDroppedPackets",
            "value": true
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\PublicProfile\Logging:LogDroppedPackets
```

## 35.21 - 'Enable Public Network Firewall: Enable Log Success Connections' is set to 'Enable Logging Of Successful Connections' 

>[!NOTE]
>Use this option to log when Windows Firewall with Advanced Security allows an
inbound connection. The log records why and when the connection was formed. Look
for entries with the word ALLOW in the action column of the log.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Information about successful connections will be recorded in the firewall log file.

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/PublicProfile/EnableLogSuccessConnections
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 11, version 22H2 [10.0.22621] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| false | (default) Disable Logging Of Successful Connections. |
| true  | Enable Logging Of Successful Connections. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.5 Implement and Manage a Firewall on End-User Devices|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Enable Public Network Firewall: Enable Log Success Connections\u0027 is set to \u0027True\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/PublicProfile/EnableLogSuccessConnections",
            "value": true
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\PublicProfile\Logging:LogSuccessfulConnections
```

## 35.22 - 'Enable Public Network Firewall: Log File Path' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log' 

>[!NOTE]
>Use this option to specify the path and name of the file in which Windows Firewall will
write its log information.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The log file will be stored in the specified file.

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/PublicProfile/LogFilePath
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 11, version 22H2 [10.0.22621] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| %systemroot%\system32\LogFiles\Firewall\pfirewall.log | (default)  |
| %SystemRoot%\System32\logfiles\firewall\publicfw.log  | Custom Settings (Recommended) |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.2 Collect Audit Logs|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|8|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Enable Public Network Firewall: Log File Path\u0027 is set to \u0027publicfw.log\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/PublicProfile/LogFilePath",
            "value": %SystemRoot%\System32\logfiles\firewall\publicfw.log
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_SZ value of %SystemRoot%\System32\logfiles\firewall\publicfw.log.
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\PublicProfile\Logging:LogFilePath
```

## 35.23 - 'Enable Public Network Firewall: Log Max File Size' is set to '16,384 KB or greater'

>[!NOTE]
>Use this option to specify the size limit of the file in which Windows Firewall will write its
log information.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The log file size will be limited to the specified size, old events will be overwritten by
newer ones when the limit is reached

```
OMA-URI 
./Vendor/MSFT/Firewall/MdmStore/PublicProfile/LogMaxFileSize
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 11, version 22H2 [10.0.22621] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1024 | (default value)  |
| 16384 | Custom Settings (Recommended) |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.3 Ensure Adequate Audit Log Storage|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|8|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.4 Apply Host-based Firewalls or Port Filtering|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Enable Public Network Firewall: Log Max File Size\u0027 is set to \u0027 16,384 KB or greater\u0027",
            "omaUri": "./Vendor/MSFT/Firewall/MdmStore/PublicProfile/LogMaxFileSize",
            "value": 16384
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 16384.
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Mdm\PublicProfile\Logging:LogFileSize
```

# 42 - Lanman Workstation

## 42.1 - 'Enable insecure guest logons' is set to 'Disabled' 

>[!NOTE]
>This policy setting determines if the SMB client will allow insecure guest logons to an
SMB server.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The SMB client will reject insecure guest logons. This was not originally the default
behavior in older versions of Windows

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LanmanWorkstation/EnableInsecureGuestLogons
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | (default) 	Disabled.  |
| 1 | Enabled. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|0.0 Explicitly Not Mapped|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|
```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Enable insecure guest logons\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LanmanWorkstation/EnableInsecureGuestLogons",
            "value": 0
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation:AllowInsecureGuestAuth
```

# 45 - Local Policies Security Options

## 45.1 - 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'

>[!NOTE]
>This policy setting prevents users from adding new Microsoft accounts on this computer.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Users will not be able to log onto the computer with their Microsoft account

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/Accounts_BlockMicrosoftAccounts
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | (default)	Disabled (users will be able to use Microsoft accounts with Windows) |
| 1 | Enabled (users can't add Microsoft accounts). |
| 3 | Users can't add or log on with Microsoft accounts.|
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|5.6 Centralize Account Management||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.2 Configure Centralized Point of Authentication||:orange_circle:|:large_blue_circle:|Level - 1|
```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Accounts: Block Microsoft accounts\u0027 is set to \u0027Users can't add or log on with Microsoft accounts\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/Accounts_BlockMicrosoftAccounts",
            "value": 3
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 3.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:NoConnectedUser
```

## 45.2 - 'Accounts: Enable Guest account status' is set to 'Disabled'

>[!NOTE]
>This policy setting determines whether the Guest account is enabled or disabled. The Guest account allows unauthenticated network users to gain access to the system.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>All network users will need to authenticate before they can access shared resources. If you disable the Guest account and the Network Access: Sharing and Security Model option is set to Guest Only, network logons, such as those performed by the Microsoft Network Server (SMB Service), will fail.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/Accounts_EnableGuestAccountStatus
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Disabled |
| 1 | Enabled |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.7 Manage Default Accounts on Enterprise Assets and Software|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.8 Disable Any Unassociated Accounts|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Accounts: Enable Guest account status\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/Accounts_EnableGuestAccountStatus",
            "value": 0
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
XXX
```

## 45.3 - 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'

>[!NOTE]
>This policy setting determines whether local accounts that are not password protected can be used to log on from locations other than the physical computer console. If you enable this policy setting, local accounts that have blank passwords will not be able to log on to the network from remote client computers. Such accounts will only be able to log on at the keyboard of the computer.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/Accounts_LimitLocalAccountUseOfBlankPasswordsToConsoleLogonOnly
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Disabled |
| 1 | Enabled |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|5.2 Use Unique Passwords|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|4.4 Use Unique Passwords||:orange_circle:|:large_blue_circle:|Level - 1|
```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Accounts: Limit local account use of blank passwords to console logon only\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/Accounts_LimitLocalAccountUseOfBlankPasswordsToConsoleLogonOnly",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SYSTEM\CurrentControlSet\Control\Lsa:LimitBlankPasswordUse
```

## 45.4 - 'Accounts: Rename administrator account'

>[!NOTE]
>The built-in local administrator account is a well-known account name that attackers will target. It is recommended to choose another name for this account, and to avoid names that denote administrative or elevated access accounts. Be sure to also change the default description for the local administrator (through the Computer Management console).

>[!TIP]
>Automated Remedation

>[!CAUTION]
>You will have to inform users who are authorized to use this account of the new account name

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/Accounts_RenameAdministratorAccount
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| Administrator | Default |
| XXX | Custom Settings (Recommended) |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.7 Manage Default Accounts on Enterprise Assets and Software|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Accounts: Rename administrator account\u0027 is set to \u0027to ATEA\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/Accounts_RenameAdministratorAccount",
            "value": ATEA
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
XXX
```

## 45.5 -  'Accounts: Rename guest account'

>[!NOTE]
>The built-in local guest account is another well-known name to attackers. It is recommended to rename this account to something that does not indicate its purpose. Even if you disable this account, which is recommended, ensure that you rename it for added security.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>There should be little impact, because the Guest account is disabled by default.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/Accounts_RenameGuestAccount
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| Administrator | Default |
| XXX | Custom Settings (Recommended) |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.7 Manage Default Accounts on Enterprise Assets and Software|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Accounts: Rename administrator account\u0027 is set to \u0027to ATEA Guest\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/Accounts_RenameGuestAccount",
            "value": ATEAGuest
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed.
XXX
```

## 45.7 - 'Interactive logon: Do not display last signed-in' is set to 'Enabled'

>[!NOTE]
>This policy setting determines whether the account name of the last user to log on to the client computers in your organization will be displayed in each computer's respective Windows logon screen. Enable this policy setting to prevent intruders from collecting account names visually from the screens of desktop or laptop computers in your organization.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The name of the last user to successfully log on will not be displayed in the Windows logon screen.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/InteractiveLogon_DoNotDisplayLastSignedIn
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Disabled (username will be shown). |
| 1 | Enabled (username won't be shown). |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.1 Establish and Maintain a Secure Configuration Process|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|5.1 Establish Secure Configurations|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Interactive logon: Do not display last signed-in\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/InteractiveLogon_DoNotDisplayLastSignedIn",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:DontDisplayLastUserName
```

## 45.8 - 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'

>[!NOTE]
>This policy setting determines whether users must press CTRL+ALT+DEL before they log on.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Users must press CTRL+ALT+DEL before they log on to Windows unless they use a smart card for Windows logon. A smart card is a tamper-proof device that stores security information.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/InteractiveLogon_DoNotRequireCTRLALTDEL
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Disabled |
| 1 | Enabled (a user isn't required to press CTRL+ALT+DEL to log on) |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|0.0 Explicitly Not Mapped|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|0.0 Explicitly Not Mapped|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Interactive logon: Do not require CTRL+ALT+DEL\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/InteractiveLogon_DoNotRequireCTRLALTDEL",
            "value": 0
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of `0.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:DisableCAD
```

## 45.9 - 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'

>[!NOTE]
>Windows notices inactivity of a logon session, and if the amount of inactive time exceeds the inactivity limit, then the screen saver will run, locking the session.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The screen saver will automatically activate when the computer has been unattended for the amount of time specified. The impact should be minimal since the screen saver is enabled by default.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/InteractiveLogon_MachineInactivityLimit
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Default Value |
| 900 | Custom Settings (Recommended)|
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.3 Configure Automatic Session Locking on Enterprise Assets|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Interactive logon: Machine inactivity limit\u0027 is set to \u0027 900 or fewer second(s), but not 0 \u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/InteractiveLogon_MachineInactivityLimit",
            "value": 900
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 900 or less, but not 0
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:InactivityTimeoutSecs
```

## 45.10 - 'Interactive logon: Message text for users attempting to log on'

>[!NOTE]
>This policy setting specifies a text message that displays to users when they log on. Set the following group policy to a value that is consistent with the security and operational requirements of your organization.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Users will have to acknowledge a dialog box containing the configured text before they can log on to the computer.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/InteractiveLogon_MessageTextForUsersAttemptingToLogOn
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| No message | Default Value |
| Text | Recommended Value|
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|0.0 Explicitly Not Mapped|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|0.0 Explicitly Not Mapped|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Interactive logon: Message text for users attempting to log on\u0027 is set to \u0027 Custom Text\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/InteractiveLogon_MessageTextForUsersAttemptingToLogOn",
            "value": Text
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_SZ value of text.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:LegalNoticeText
```

## 45.11 - 'Interactive logon: Message title for users attempting to log on'

>[!NOTE]
>This policy setting specifies the text displayed in the title bar of the window that users see when they log on to the system. Configure this setting in a manner that is consistent with the security and operational requirements of your organization.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Users will have to acknowledge a dialog box with the configured title before they can log on to the computer.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/InteractiveLogon_MessageTitleForUsersAttemptingToLogOn
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| No message | Default Value |
| Text | Recommended Value|
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|0.0 Explicitly Not Mapped|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|0.0 Explicitly Not Mapped|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Interactive logon: Message title for users attempting to log on\u0027 is set to \u0027 Custom Text\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/InteractiveLogon_MessageTitleForUsersAttemptingToLogOn",
            "value": Text
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_SZ value of text.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:LegalNoticeCaption
```

## 45.12 - 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher 

>[!NOTE]
>This policy setting determines what happens when the smart card for a logged-on user is removed from the smart card reader.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If you select Lock Workstation, the workstation is locked when the smart card is removed, allowing users to leave the area, take their smart card with them, and still maintain a protected session.
If you select Force Logoff, users are automatically logged off when their smart card is removed.
If you select Disconnect if a Remote Desktop Services session, removal of the smart card disconnects the session without logging the users off. This allows the user to insert the smart card and resume the session later, or at another smart card reader-equipped computer, without having to log on again. If the session is local, this policy will function identically to Lock Workstation.
Enforcing this setting on computers used by people who must log onto multiple computers in order to perform their duties could be frustrating and lower productivity. For example, if network administrators are limited to a single account but need to log into several computers simultaneously in order to effectively manage the network enforcing this setting will limit them to logging onto one computer at a time. For these reasons it is recommended that this setting only be enforced on workstations used for purposes commonly associated with typical users such as document creation and emai


```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/InteractiveLogon_SmartCardRemovalBehavior
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | No Action. |
| 1 | Lock Workstation.|
| 2 | Force Logoff.|
| 3 | Disconnect if a Remote Desktop Services session.|
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.3 Configure Automatic Session Locking on Enterprise Assets|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Interactive logon: Smart card removal behavior\u0027 is set to \u0027 Lock Workstation\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/InteractiveLogon_SmartCardRemovalBehavior",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_SZ value of 1, 2 or 3.
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:ScRemoveOption
```

## 45.13 - 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'

>[!NOTE]
>This policy setting determines whether packet signing is required by the SMB client component.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The Microsoft network client will not communicate with a Microsoft network server unless that server agrees to perform SMB packet signing.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/MicrosoftNetworkClient_DigitallySignCommunicationsAlways
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1809 [10.0.17763] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1 | Enable. |
| 0 | Disable. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Microsoft network client: Digitally sign communications always\u0027 is set to \u0027 Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/MicrosoftNetworkClient_DigitallySignCommunicationsAlways",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters:RequireSecuritySignature
```

## 45.14 - 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'

>[!NOTE]
>This policy setting determines whether the SMB client will attempt to negotiate SMB packet signing.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/MicrosoftNetworkClient_DigitallySignCommunicationsIfServerAgrees
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1 | Enable. |
| 0 | Disable. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Microsoft network client: Digitally sign communications\u0027 is set to \u0027 Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/MicrosoftNetworkClient_DigitallySignCommunicationsIfServerAgrees",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters:EnableSecuritySignature
```

## 45.15 - 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'

>[!NOTE]
>This policy setting determines whether the SMB redirector will send plaintext passwords during authentication to third-party SMB servers that do not support password encryption.
It is recommended that you disable this policy setting unless there is a strong business case to enable it. If this policy setting is enabled, unencrypted passwords will be allowed across the network.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/MicrosoftNetworkClient_SendUnencryptedPasswordToThirdPartySMBServers
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1 | Enable. |
| 0 | Disable. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.4 Encrypt or Hash all Authentication Credentials||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Microsoft network client: Send unencrypted password to third-party SMB servers\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/MicrosoftNetworkClient_SendUnencryptedPasswordToThirdPartySMBServers",
            "value": 0
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters:EnablePlainTextPassword
```

## 45.16 - 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'

>[!NOTE]
>This policy setting determines whether packet signing is required by the SMB server component. Enable this policy setting in a mixed environment to prevent downstream clients from using the workstation as a network server.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The Microsoft network server will not communicate with a Microsoft network client unless that client agrees to perform SMB packet signing.

>[!CAUTION]
>Implementation of SMB signing may negatively affect performance, because each packet needs to be signed and verified. If these settings are enabled on a server that is performing multiple roles, such as a small business server that is serving as a Domain Controller, file server, print server, and application server performance may be substantially slowed. Additionally, if you configure computers to ignore all unsigned SMB communications, older applications and operating systems will not be able to connect. However, if you completely disable all SMB signing, computers will be vulnerable to session hijacking attacks.


```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/MicrosoftNetworkServer_DigitallySignCommunicationsAlways
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1 | Enable. |
| 0 | Disable. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.4 Encrypt or Hash all Authentication Credentials||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Microsoft network server: Digitally sign communications allways\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/MicrosoftNetworkServer_DigitallySignCommunicationsAlways",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:RequireSecuritySignature
```

## 45.17 - 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'

>[!NOTE]
>This policy setting determines whether the SMB server will negotiate SMB packet signing with clients that request it. If no signing request comes from the client, a connection will be allowed without a signature if the Microsoft network server: Digitally sign communications (always) setting is not enabled.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The Microsoft network server will negotiate SMB packet signing as requested by the client. That is, if packet signing has been enabled on the client, packet signing will be negotiated.

>[!CAUTION]
>Implementation of SMB signing may negatively affect performance, because each packet needs to be signed and verified. If these settings are enabled on a server that is performing multiple roles, such as a small business server that is serving as a Domain Controller, file server, print server, and application server performance may be substantially slowed. Additionally, if you configure computers to ignore all unsigned SMB communications, older applications and operating systems will not be able to connect. However, if you completely disable all SMB signing, computers will be vulnerable to session hijacking attacks.


```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/MicrosoftNetworkServer_DigitallySignCommunicationsIfClientAgrees
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1 | Enable. |
| 0 | Disable. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Microsoft network server: Digitally sign communications\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/MicrosoftNetworkServer_DigitallySignCommunicationsIfClientAgrees",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:EnableSecuritySignature
```

## 45.18 - 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'

>[!NOTE]
>This policy setting controls the ability of anonymous users to enumerate the accounts in the Security Accounts Manager (SAM). If you enable this policy setting, users with anonymous connections will not be able to enumerate domain account user names on the systems in your environment. This policy setting also allows additional restrictions on anonymous connections.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None


```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkAccess_DoNotAllowAnonymousEnumerationOfSAMAccounts
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1 | Enable. |
| 0 | Disable. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|0.0 Explicitly Not Mapped||||Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Network access: Do not allow anonymous enumeration of SAM accounts\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkAccess_DoNotAllowAnonymousEnumerationOfSAMAccounts",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SYSTEM\CurrentControlSet\Control\Lsa:RestrictAnonymousSAM
```

## 45.19 - 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'

>[!NOTE]
>This policy setting controls the ability of anonymous users to enumerate SAM accounts as well as shares. If you enable this policy setting, anonymous users will not be able to enumerate domain account user names and network share names on the systems in your environment.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>It will be impossible to establish trusts with Windows NT 4.0-based domains. Also, client computers that run older versions of the Windows operating system such as Windows NT 3.51 and Windows 95 will experience problems when they try to use resources on the server. Users who access file and print servers anonymously will be unable to list the shared network resources on those servers; the users will have to authenticate before they can view the lists of shared folders and printers. However, even with this policy setting enabled, anonymous users will have access to resources with permissions that explicitly include the built-in group, ANONYMOUS LOGON.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkAccess_DoNotAllowAnonymousEnumerationOfSamAccountsAndShares
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1 | Enable. |
| 0 | Disable. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|0.0 Explicitly Not Mapped||||Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Network access: Do not allow anonymous enumeration of SAM accounts and shares\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkAccess_DoNotAllowAnonymousEnumerationOfSamAccountsAndShares",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SYSTEM\CurrentControlSet\Control\Lsa:RestrictAnonymous
```
## 45.20 - 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'

>[!NOTE]
>When enabled, this policy setting restricts anonymous access to only those shares and pipes that are named in the Network access: Named pipes that can be accessed anonymously and Network access: Shares that can be accessed anonymously settings. This policy setting controls null session access to shares on your computers by adding RestrictNullSessAccess with the value 1 in the

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkAccess_RestrictAnonymousAccessToNamedPipesAndShares
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1 | Enable. |
| 0 | Disable. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|0.0 Explicitly Not Mapped||||Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Network access: Restrict anonymous access to Named Pipes and Shares\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkAccess_RestrictAnonymousAccessToNamedPipesAndShares",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:RestrictNullSessAccess
```

## 45.21 - 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'

>[!NOTE]
>This policy setting allows you to restrict remote RPC connections to SAM. 

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkAccess_RestrictClientsAllowedToMakeRemoteCallsToSAM
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1709 [10.0.16299] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| O:BAG:BAD:(A;;RC;;;BA) | Custom Settings (Recommended) |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|0.0 Explicitly Not Mapped||||Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingString",
            "displayName": "\u0027Network access: Restrict clients allowed to make remote calls to SAM\u0027 is set to \u0027Administrators: Remote Access: Allow\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkAccess_RestrictClientsAllowedToMakeRemoteCallsToSAM",
            "value": "O:BAG:BAD:(A;;RC;;;BA)"
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_SZ value of O:BAG:BAD:(A;;RC;;;BA).
HKLM\SYSTEM\CurrentControlSet\Control\Lsa:restrictremotesam
O:BAG:BAD:(A;;RC;;;BA)
```

## 45.22 - 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Allow'

>[!NOTE]
>This policy setting determines whether Local System services that use Negotiate when reverting to NTLM authentication can use the computer identity.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Services running as Local System that use Negotiate when reverting to NTLM authentication will use the computer identity. This might cause some authentication requests between Windows operating systems to fail and log an error.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkSecurity_AllowLocalSystemToUseComputerIdentityForNTLM
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1809 [10.0.17763] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1 | 	Allow. |
| 0 | 	Block. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|0.0 Explicitly Not Mapped||||Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Network security: Allow Local System to use computer identity for NTLM\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkSecurity_AllowLocalSystemToUseComputerIdentityForNTLM",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SYSTEM\CurrentControlSet\Control\Lsa:UseMachineId
```
## 45.23 - 'Network Security: Allow PKU2U authentication requests' is set to 'Block'

>[!NOTE]
>This setting determines if online identities are able to authenticate to this computer

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkSecurity_AllowPKU2UAuthenticationRequests
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1809 [10.0.17763] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1 | 	Allow. |
| 0 | 	Block. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.1 Establish and Maintain a Secure Configuration Process|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Network Security: Allow PKU2U authentication requests\u0027 is set to \u0027Block\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkSecurity_AllowPKU2UAuthenticationRequests",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u:AllowOnlineID
```

## 45.24 - 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'

>[!NOTE]
>This policy setting determines whether the LAN Manager (LM) hash value for the new password is stored when the password is changed. The LM hash is relatively weak and prone to attack compared to the cryptographically stronger Microsoft Windows NT hash. Since LM hashes are stored on the local computer in the security database, passwords can then be easily compromised if the database is attacked.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkSecurity_DoNotStoreLANManagerHashValueOnNextPasswordChange
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1 | 	Enable. |
| 0 | 	Disable. |
 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.11 Encrypt Sensitive Data at Rest||:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.4 Encrypt or Hash all Authentication Credentials||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Network security: Do not store LAN Manager hash value on next password change\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkSecurity_DoNotStoreLANManagerHashValueOnNextPasswordChange",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SYSTEM\CurrentControlSet\Control\Lsa:NoLMHash
```

## 45.25 - 'Network security: LAN Manager authentication level' is set to 'Send LM and NTLMv2 responses only. Refuse LM and NTLM'

>[!NOTE]
>LAN Manager (LM) was a family of early Microsoft client/server software (predating Windows NT) that allowed users to link personal computers together on a single network. LM network capabilities included transparent file and print sharing, user security features, and network administration tools. In Active Directory domains, the Kerberos protocol is the default authentication protocol. However, if the Kerberos protocol is not negotiated for some reason, Active Directory will use LM, NTLM, or NTLMv2. LAN Manager authentication includes the LM, NTLM, and NTLM version 2 (NTLMv2) variants, and is the protocol that is used to authenticate all Windows clients when they perform the following operations:
• Join a domain
• Authenticate between Active Directory forests
• Authenticate to down-level domains
• Authenticate to computers that do not run Windows 2000, Windows Server 2003, or Windows XP
• Authenticate to computers that are not in the domain

The Network security: LAN Manager authentication level setting determines which challenge/response authentication protocol is used for network logons. This choice affects the level of authentication protocol used by clients, the level of session security negotiated, and the level of authentication accepted by servers.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Clients use NTLMv2 authentication only and use NTLMv2 session security if the server supports it; Domain Controllers refuse LM and NTLM (accept only NTLMv2 authentication). Clients that do not support NTLMv2 authentication will not be able to authenticate in the domain and access domain resources by using LM and NTLM.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkSecurity_LANManagerAuthenticationLevel
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Send LM and NTLM responses. |
| 1 | Send LM and NTLM-use NTLMv2 session security if negotiated |
| 2 | Send LM and NTLM responses only. |
| 3 | Send LM and NTLMv2 responses only. |
| 4 | Send LM and NTLMv2 responses only. Refuse LM. |
| 5 | Send LM and NTLMv2 responses only. Refuse LM and NTLM. |

 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Network security: LAN Manager authentication level\u0027 is set to \u0027Send LM and NTLMv2 responses only. Refuse LM and NTLM\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkSecurity_LANManagerAuthenticationLevel",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 5.
HKLM\SYSTEM\CurrentControlSet\Control\Lsa:LmCompatibilityLevel
```

## 45.26 - 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLM and 128-bit encryption'

>[!NOTE]
>This policy setting determines which behaviors are allowed by clients for applications using the NTLM Security Support Provider (SSP). The SSP Interface (SSPI) is used by applications that need authentication services. The setting does not modify how the authentication sequence works but instead require certain behaviors in applications that use the SSPI.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>NTLM connections will fail if NTLMv2 protocol and strong encryption (128-bit) are not both negotiated. Client applications that are enforcing these settings will be unable to communicate with older servers that do not support them.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkSecurity_MinimumSessionSecurityForNTLMSSPBasedClients
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | None. |
| 524288 | Require NTLMv2 session security. |
| 536870912 | Require 128-bit encryption. |
| 537395200 | Require NTLM and 128-bit encryption.. |


 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle:|Level - 1|
|7|12.5 Configure Monitoring Systems to Record Network Packets||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Network security: Minimum session security for NTLM SSP based (including secure RPC) clients\u0027 is set to \u0027Require NTLM and 128-bit encryption\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkSecurity_MinimumSessionSecurityForNTLMSSPBasedClients",
            "value": 537395200
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 537395200.
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0:NTLMMinClientSec
```

## 45.27 - 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLM and 128-bit encryption'

>[!NOTE]
>This policy setting determines which behaviors are allowed by servers for applications using the NTLM Security Support Provider (SSP). The SSP Interface (SSPI) is used by applications that need authentication services. The setting does not modify how the authentication sequence works but instead require certain behaviors in applications that use the SSPI.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>NTLM connections will fail if NTLMv2 protocol and strong encryption (128-bit) are not both negotiated. Server applications that are enforcing these settings will be unable to communicate with older servers that do not support them.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkSecurity_MinimumSessionSecurityForNTLMSSPBasedServers
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | None. |
| 524288 | Require NTLMv2 session security. |
| 536870912 | Require 128-bit encryption. |
| 537395200 | Require NTLM and 128-bit encryption.. |


 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.10 Encrypt Sensitive Data in Transit||:orange_circle:|:large_blue_circle:|Level - 1|
|7|12.5 Configure Monitoring Systems to Record Network Packets||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Network security: Minimum session security for NTLM SSP based (including secure RPC) servers\u0027 is set to \u0027Require NTLM and 128-bit encryption\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkSecurity_MinimumSessionSecurityForNTLMSSPBasedServers",
            "value": 537395200
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 537395200.
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0:NTLMMinServerSec
```

## 45.28 - 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts'

>[!NOTE]
>This policy setting allows the auditing of incoming NTLM traffic. Events for this setting are recorded in the operational event log (e.g. Applications and Services Log\Microsoft\Windows\NTLM).

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The event log will contain information on incoming NTLM authentication traffic.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkSecurity_RestrictNTLM_AuditIncomingNTLMTraffic
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Disable. |
| 1 | Enable auditing for domain accounts. |
| 2 | Enable auditing for all accounts. |


 
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|8.5 Collect Detailed Audit Logs||:orange_circle:|:large_blue_circle:|Level - 1|
|7|6.3 Enable Detailed Logging||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Network security: Restrict NTLM: Audit Incoming NTLM Traffic\u0027 is set to \u0027Enable auditing for all accounts\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/NetworkSecurity_RestrictNTLM_AuditIncomingNTLMTraffic",
            "value": 2
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 2.
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0:AuditReceivingNTLMTraffic
```

## 45.29 - 'User Account Control: Behavior of the elevation prompt for administrators' is set to 'Prompt for consent on the secure desktop' or higher

>[!NOTE]
>This policy setting controls the behavior of the elevation prompt for administrators.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>When an operation (including execution of a Windows binary) requires elevation of privilege, the user is prompted on the secure desktop to select either Permit or Deny. If the user selects Permit, the operation continues with the user's highest available privilege.

>[!CAUTION]
> Warning:
Windows Autopilot - Policy Conflicts: This policy requires a reboot to apply. As a result, prompts may appear when modifying user account control (UAC) settings during the Out of the Box Experience (OOBE) using the device Enrollment Status Page (ESP). Increased prompts are more likely if the device reboots after policies are applied. To work around this issue, the policies can be targeted to users instead of devices so that they apply later in the process. An exception to this recommendation may be needed if Windows AutoPilot is used.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/UserAccountControl_BehaviorOfTheElevationPromptForAdministratorProtection
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1 | Prompt for credentials on the secure desktop. |
| 2 | Prompt for consent on the secure desktop |


|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|0|0.0 Explicitly Not Mapped||||Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027User Account Control: Behavior of the elevation prompt for administrators\u0027 is set to \u0027Prompt for consent on the secure desktop\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/UserAccountControl_BehaviorOfTheElevationPromptForAdministratorProtection",
            "value": 2
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1 or 2.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:ConsentPromptBehaviorAdmin
```

## 45.30 - 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'

>[!NOTE]
>This policy setting controls the behavior of the elevation prompt for standard users.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>When an operation requires elevation of privilege, a configurable access denied error message is displayed. An enterprise that is running desktops as standard user may choose this setting to reduce help desk calls.

>[!CAUTION]
>Note: With this setting configured as recommended, the default error message displayed when a user attempts to perform an operation or run a program requiring privilege elevation (without Administrator rights) is "This program will not run. This program is blocked by group policy. For more information, contact your system administrator." Some users who are not used to seeing this message may believe that the operation or program they attempted to run is specifically blocked by group policy, as that is what the message seems to imply. This message may therefore result in user questions as to why that specific operation/program is blocked, when in fact, the problem is that they need to perform the operation or run the program with an Administrative account (or "Run as Administrator" if it is already an Administrator account), and they are not doing that.

>[!CAUTION]
>Note #2: When using third-party remote support tools, this recommendation could prevent Administrators from entering their administrative credentials. In this case, an exception to this recommendation will be needed.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/UserAccountControl_BehaviorOfTheElevationPromptForStandardUsers
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Automatically deny elevation requests. |
| 1 | Prompt for credentials on the secure desktop. |
| 3 |Prompt for credentials. | 


|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|0|0.0 Explicitly Not Mapped||||Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027User Account Control: Behavior of the elevation prompt for standard users\u0027 is set to \u0027Automatically deny elevation requests\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/UserAccountControl_BehaviorOfTheElevationPromptForStandardUsers",
            "value": 0
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:ConsentPromptBehaviorUser
```

## 45.31 - 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'

>[!NOTE]
>This policy setting controls the behavior of application installation detection for the computer.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>When an application installation package is detected that requires elevation of privilege, the user is prompted to enter an administrative user name and password. If the user enters valid credentials, the operation continues with the applicable privilege.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/UserAccountControl_DetectApplicationInstallationsAndPromptForElevation
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1 | Enable. |
| 0 | Disable. |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|0|0.0 Explicitly Not Mapped||||Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027User Account Control: Detect application installations and prompt for elevation\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/UserAccountControl_DetectApplicationInstallationsAndPromptForElevation",
            "value": 0
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableInstallerDetection
```

## 45.32 - 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'

>[!NOTE]
>This policy setting controls whether applications that request to run with a User Interface Accessibility (UIAccess) integrity level must reside in a secure location in the file system. Secure locations are limited to the following:
•…\Program Files\, including subfolders
•…\Windows\System32\
•…\Program Files (x86)\, including subfolders (for 64-bit versions of Windows)

>[!NOTE]
> Windows enforces a public key infrastructure (PKI) signature check on any interactive application that requests to run with a UIAccess integrity level regardless of the state of this security setting.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/UserAccountControl_OnlyElevateUIAccessApplicationsThatAreInstalledInSecureLocations
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Disabled: Application runs with UIAccess integrity even if it doesn't reside in a secure location. |
| 1 | Enabled: Application runs with UIAccess integrity only if it resides in secure location. |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|0|0.0 Explicitly Not Mapped||||Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027User Account Control: Only elevate UIAccess applications that are installed in secure locations\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/UserAccountControl_OnlyElevateUIAccessApplicationsThatAreInstalledInSecureLocations",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableSecureUIAPaths
```

## 45.33 - 'User Account Control: Use Admin Approval Mode' is set to 'Enabled'

>[!NOTE]
>This policy setting controls the behavior of Admin Approval Mode for the built-in Administrator account.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>The built-in Administrator account uses Admin Approval Mode. Users that log on using the local Administrator account will be prompted for consent whenever a program requests an elevation in privilege, just like any other user would.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/UserAccountControl_UseAdminApprovalMode
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1 | Enable. |
| 0 | Disable. |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|0|0.0 Explicitly Not Mapped||||Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027User Account Control: Use Admin Approval Mode\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/UserAccountControl_UseAdminApprovalMode",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:FilterAdministratorToken
```

## 45.34 - 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'

>[!NOTE]
>This policy setting controls whether the elevation request prompt is displayed on the interactive user's desktop or the secure desktop.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/UserAccountControl_SwitchToTheSecureDesktopWhenPromptingForElevation
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1 | Enable. |
| 0 | Disable. |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|0|0.0 Explicitly Not Mapped||||Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027User Account Control: Switch to the secure desktop when prompting for elevation\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/UserAccountControl_SwitchToTheSecureDesktopWhenPromptingForElevation",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:PromptOnSecureDesktop
```

## 45.35 - 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled

>[!NOTE]
>This policy setting controls the behavior of all User Account Control (UAC) policy settings for the computer. If you change this policy setting, you must restart your computer.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None. Users and administrators will need to learn to work with UAC prompts and adjust their work habits to use least privilege operations.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/UserAccountControl_RunAllAdministratorsInAdminApprovalMode
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1 | Enable. |
| 0 | Disable. |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|0|0.0 Explicitly Not Mapped||||Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027User Account Control: Run all administrators in Admin Approval Mode\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/UserAccountControl_RunAllAdministratorsInAdminApprovalMode",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:PromptOnSecureDesktopHKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableLUA
```

## 45.36 - 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'

>[!NOTE]
>This policy setting controls whether application write failures are redirected to defined registry and file system locations. This policy setting mitigates applications that run as administrator and write run-time application data to:
•%ProgramFiles%
•%windir%
•%windir%\System32
•HKLM\SOFTWARE

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None. 

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/UserAccountControl_VirtualizeFileAndRegistryWriteFailuresToPerUserLocations
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 1 | Enable. |
| 0 | Disable. |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|0|0.0 Explicitly Not Mapped||||Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027User Account Control: Virtualize file and registry write failures to per-user locations\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/LocalPoliciesSecurityOptions/UserAccountControl_VirtualizeFileAndRegistryWriteFailuresToPerUserLocations",
            "value": 1
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableVirtualization
```
# 48 - Microsoft App Store

## 48.1 - 'Allow apps from the Microsoft app store to auto update' is set to 'Allowed'

>[!NOTE]
>This setting enables or disables the automatic download and installation of Microsoft Store app updates.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None. 

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ApplicationManagement/AllowAppStoreAutoUpdate
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1507 [10.0.10240] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Not allowed. |
| 1 | Allowed. |
| 2 | Not configured. |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|7.3 Perform Automated Operating System Patch Management|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Allow apps from the Microsoft app store to auto update\u0027 is set to \u0027Allowed\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ApplicationManagement/AllowAppStoreAutoUpdate",
            "value": 1
        },
```

```
Audit:
Navigate to the following registry location and note the WinningProvider GUID. This value confirms under which User GUID the policy is set.
HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\ApplicationManagement:AllowAppStoreAutoUpdate_WinningProvider

Navigate to the following registry location and confirm the value is set to 1.
HKLM\SOFTWARE\Microsoft\PolicyManager\Providers\{GUID}\Default\Device\ApplicationManagement:AllowAppStoreAutoUpdate
```

## 48.2 - 'Allow Game DVR' is set to 'Block'

>[!NOTE]
>This setting enables or disables the Windows Game Recording and Broadcasting features.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Windows Game Recording will not be allowed.

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ApplicationManagement/AllowGameDVR
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1507 [10.0.10240] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Not allowed. |
| 1 | Allowed. |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Allow apps from the Microsoft app store to auto update\u0027 is set to \u0027Allowed\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ApplicationManagement/AllowGameDVR",
            "value": 0
        },
```

```
Audit:
Navigate to the following registry location and note the WinningProvider GUID. This value confirms under which User GUID the policy is set.
HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\ApplicationManagement:AllowGameDVR_WinningProvider

Navigate to the following registry location and confirm the value is set to 0.
HKLM\SOFTWARE\Microsoft\PolicyManager\Providers\{GUID}\Default\Device\ApplicationManagement:AllowGameDVR
```

## 48.4 - 'MSI Allow user control over installs' is set to 'Disabled'

>[!NOTE]
>This setting controls whether users are permitted to change installation options that typically are available only to system administrators. The security features of Windows Installer normally prevent users from changing installation options that are typically reserved for system administrators, such as specifying the directory to which files are installed. If Windows Installer detects that an installation package has permitted the user to change a protected option, it stops the installation and displays a message. These security features operate only when the installation program is running in a privileged security context in which it has access to directories denied to the user.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ApplicationManagement/MSIAllowUserControlOverInstall
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|❌ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Disabled. The security features of Windows Installer prevent users from changing installation options typically reserved for system administrators, such as specifying the directory to which files are installed. |
| 1 | Enabled. Some of the security features of Windows Installer are bypassed. It permits installations to complete that otherwise would be halted due to a security violation. |

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|0.0 Explicitly Not Mapped||||Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027MSI Allow user control over installs\u0027 is set to \u0027Enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ApplicationManagement/MSIAllowUserControlOverInstall",
            "value": 0
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer:EnableUserControl
```

## 48.5 - 'MSI Always install with elevated privileges' is set to 'Disabled'

>[!NOTE]
>This setting controls whether or not Windows Installer should use system permissions when it installs any program on the system

>[!TIP]
>Automated Remedation

>[!CAUTION]
>None

>[!CAUTION]
>Skilled users can take advantage of the permissions this policy setting grants to change their privileges and gain permanent access to restricted files and folders. Note that the User Configuration version of this policy setting isn't guaranteed to be secure.

```
OMA-URI 
./User/Vendor/MSFT/Policy/Config/ApplicationManagement/MSIAlwaysInstallWithElevatedPrivileges
```
```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ApplicationManagement/MSIAlwaysInstallWithElevatedPrivileges
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|✔ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|✔ User|✔ Enterprise||
| |✔ Education||
| |✔ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Disabled. The system applies the current user's permissions when it installs programs that a system administrator doesn't distribute or offer. |
| 1 | Enabled. Privileges are extended to all programs. These privileges are usually reserved for programs that have been assigned to the user (offered on the desktop), assigned to the computer (installed automatically), or made available in Add or Remove Programs in Control Panel. This profile setting lets users install programs that require access to directories that the user might not have permission to view or change, including directories on highly restricted computers.|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|0.0 Explicitly Not Mapped||||Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027MSI Always install with elevated privileges\u0027 is set to \u0027Disabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ApplicationManagement/MSIAlwaysInstallWithElevatedPrivileges",
            "value": 0
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 0.
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer:AlwaysInstallElevated
```

## 48.7 - 'Require Private Store Only' is set to 'Only Private store is enabled'

>[!NOTE]
>This policy setting denies access to the retail catalog in the Microsoft Store, but displays the private store.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>Users will not be able to view the retail catalog in the Microsoft Store, but they will be able to view apps in the private store.


```
OMA-URI 
./User/Vendor/MSFT/Policy/Config/ApplicationManagement/RequirePrivateStoreOnly
```
```
OMA-URI 
./Device/Vendor/MSFT/Policy/Config/ApplicationManagement/RequirePrivateStoreOnly
```

|Scope | Editions| Applicable OS |
|---|---|---|
|✔ Device|❌ Pro|✔ Windows 10, version 1803 [10.0.17134] and later|
|✔ User|✔ Enterprise||
| |✔ Education||
| |❌ Windows SE||
| |✔ IoT Enterprise / IoT Enterprise LTSC|

|Value|Description|
|---|---|
| 0 | Allow both public and Private store. Users can access the retail catalog in the Microsoft Store.  |
| 1 | Only Private store is enabled. Users won't be able to view the retail catalog in the Microsoft Store, but they will be able to view apps in the private store.|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|2.5 Allowlist Authorized Software||:orange_circle:|:large_blue_circle:|Level - 1|


```
Script:
        {
            "@odata.type": "#microsoft.graph.omaSettingInteger",
            "displayName": "\u0027Require Private Store Only\u0027 is set to \u0027Only Private store is enabled\u0027",
            "omaUri": "./Device/Vendor/MSFT/Policy/Config/ApplicationManagement/RequirePrivateStoreOnly",
            "value": 0
        },
```

```
Audit:
Navigate to the UI Path articulated in the Remediation section and confirm it is set as prescribed. This group policy setting is backed by the following registry location with a REG_DWORD value of 1.
HKLM\SOFTWARE\Policies\Microsoft\WindowsStore:RequirePrivateStoreOnly
```

# 58 - Privacy
