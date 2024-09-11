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

1. Navigate to the following registry location and note the WinningProvider GUID.
This value confirms under which User GUID the policy is set.

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


OMA-URI (User)
```
./User/Vendor/MSFT/Policy/Config/ADMX_ControlPanelDisplay/CPL_Personalization_EnableScreenSaver
```
|Value|Description|
|---|---|
|Enabled|Enable|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.3 Configure Automated Session Locking on Enterprise Assets|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|


## 3.1.3.2 - Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'

>[!NOTE]
>Disables the lock screen camera toggle switch in PC Settings and prevents a camera
from being invoked on the lock screen

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If you enable this setting, users will no longer be able to enable or disable lock screen
camera access in PC Settings, and the camera cannot be invoked on the lock screen.

OMA-URI (Device)
```
./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventEnablingLockScreenCamera
```
|Value|Description|
|---|---|
|Enabled|Enable|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|


## 3.1.3.3 - Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
	
>[!NOTE]
>Disables the lock screen slide show settings in PC Settings and prevents a slide show
from playing on the lock screen

>[!TIP]
>Automated Remedation

>[!CAUTION]
>If you enable this setting, users will no longer be able to modify slide show settings in
PC Settings, and no slide show will ever start.


OMA-URI (Device)
```
./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventLockScreenSlideShow
```
|Value|Description|
|---|---|
|Enabled|Enable|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

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


OMA-URI (Device)
```
./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ApplyUACRestrictionsToLocalAccountsOnNetworkLogon
```
|Value|Description|
|---|---|
|Enabled|Applies UAC token-filtering to local accounts on network logons. Membership in powerful group such as Administrators is disabled and powerful privileges are removed from the resulting access token|
|Disabled|Allows local accounts to have full administrative rights when authenticating via network logon|

|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|7|4.3 Ensure the Use of Dedicated Administrative Accounts|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

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


OMA-URI (Device)
```
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


OMA-URI (Device)
```
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

## 3.4.4 - Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'

>[!NOTE]
>Windows includes support for Structured Exception Handling Overwrite Protection (SEHOP). We recommend enabling this feature to improve the security profile of the computer.


>[!TIP]
>Automated Remedation

>[!CAUTION]
After you enable SEHOP, existing versions of Cygwin, Skype, and Armadillo-protected
applications may not work correctly.



OMA-URI (Device)
```
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

## 3.4.5 - Ensure 'WDigest Authentication' is set to 'Disabled'


>[!NOTE]
>When WDigest authentication is enabled, Lsass.exe retains a copy of the user's plaintext password in memory, where it can be at risk of theft. If this setting is not configured, WDigest authentication is disabled in Windows 8.1 and in Windows Server 2012 R2; it is enabled by default in earlier versions of Windows and Windows Server.

>[!TIP]
>Automated Remedation

>[!CAUTION]
None - this is also the default configuration for Windows 8.1 or newer



OMA-URI (Device)
```
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

OMA-URI (Device)
```
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

## 3.5.2 - Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'

>[!NOTE]
>IP source routing is a mechanism that allows the sender to determine the IP route that a
datagram should follow through the network.

>[!TIP]
>Automated Remedation

>[!CAUTION]
>All incoming source routed packets will be dropped

OMA-URI (Device)
```
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