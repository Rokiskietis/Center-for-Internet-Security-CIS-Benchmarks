# Unsupervised (BYOD) Level - 1

# 2.1 - App Store, Doc Wiewing, Gaming

## 2.1.1 - Ensure "Block viewing corporate documents in unmanaged apps" is set to "Yes"

>[!NOTE]
>This prevents viewing corporate documents in unmanaged apps.

>[!TIP]
>Manual Remedation

>[!CAUTION]
>Third-party keyboards may not function correctly with this restriction set.

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.3 Configure Data Access Control Lists|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|14.6 Protect Information through Access Control Lists|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

## 2.1.2 - Ensure "Treat AirDrop as an unmanaged destination" is set to "Yes"


>[!NOTE]
>This forces AirDrop to be considered an unmanaged drop target.

>[!TIP]
>Manual Remedation


Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.3 Configure Data Access Control Lists|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|14.6 Protect Information through Access Control Lists|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|


## 2.1.3 - Ensure "Allow copy/paste to be affected by managed open-in" is set to "Yes"

>[!NOTE]
>This enforces copy/paste restrictions based on configured Block viewing corporate documents in unmanaged apps and Block viewing non-corporate documents in corporate apps.

>[!TIP]
>Manual Remedation


Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.3 Configure Data Access Control Lists|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|14.6 Protect Information through Access Control Lists|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

# 2.2 - Biuld-in Apps

## 2.2.1  - Ensure "Block Siri while device is locked" is set to "Yes"
	
>[!NOTE]
>This prevents access to Siri when the device is locked.

>[!TIP]
>Manual Remedation

>[!CAUTION]
The end user must unlock the device before interacting with Siri.


Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.3 Configure Automatic Session Locking on Enterprise Assets|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|


## 2.2.2 - Ensure "Require Safari fraud warnings" is set to "Yes"

>[!NOTE]
>This enforces the feature to display fraud warnings within the Safari web browser.

>[!TIP]
>Manual Remedation


Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|9.4 Configure Automatic Session Locking on Enterprise Assets||:orange_circle:|:large_blue_circle:|Level - 1|
|7|7.2 Disable Unnecessary or Unauthorized Browser or Email Client Plugins||:orange_circle:|:large_blue_circle:|Level - 1|

# 2.3 - Cloud and Storage

## 2.3.1 - Ensure "Force encrypted backup" is set to "Yes
	
>[!NOTE]
>This requires device backups to be stored in an encrypted state.


>[!TIP]
>Manual Remedation

>[!CAUTION]
End users must configure a password for the encrypted backup, the complexity of which is not managed.


Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|9.4 Protect Recovery Data|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|7.2 - Ensure Protection of Backups|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

## 2.3.2 - Ensure "Block managed apps from storing data in iCloud" is set to "Yes"
	
>[!NOTE]
>This prevents managed apps from storing and syncing data to the user's iCloud account.


>[!TIP]
>Manual Remedation

>[!CAUTION]
Data created within apps on the device may be lost if the end user has not transferred it to another device.


Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|2.3 Address Unauthorized Software|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|13.4 Only Allow Access to Authorized Cloud Storage or Email Providers||:orange_circle:|:large_blue_circle:|Level - 1|

## 2.3.3 - Ensure "Block backup of enterprise books" is set to "Yes"
	
>[!NOTE]
>This prevents backing up of enterprise books.

>[!TIP]
>Manual Remedation

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|2.3 Address Unauthorized Software|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|13.4 Only Allow Access to Authorized Cloud Storage or Email Providers||:orange_circle:|:large_blue_circle:|Level - 1|

## 2.3.4 - Ensure "Block notes and highlights sync for enterprise books" is set to "Yes"
	
>[!NOTE]
>This prevents syncing notes and highlights in enterprise books.


>[!TIP]
>Manual Remedation

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|2.3 Address Unauthorized Software|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|13.4 Only Allow Access to Authorized Cloud Storage or Email Providers||:orange_circle:|:large_blue_circle:|Level - 1|

## 2.3.5 - Ensure "Block iCloud Photos sync" is set to "Yes"
	
>[!NOTE]
>This prevents photo stream syncing to iCloud.

>[!TIP]
>Manual Remedation

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|2.3 Address Unauthorized Software|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|13.4 Only Allow Access to Authorized Cloud Storage or Email Providers||:orange_circle:|:large_blue_circle:|Level - 1|	


## 2.3.6 - Ensure "Block iCloud Photo Library" is set to "Yes"
	
>[!NOTE]
>This prevents photo Library syncing to iCloud.

>[!TIP]
>Manual Remedation

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|2.3 Address Unauthorized Software|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|13.4 Only Allow Access to Authorized Cloud Storage or Email Providers||:orange_circle:|:large_blue_circle:|Level - 1|	

## 2.3.7 - Ensure "Block My Photo Stream" is set to "Yes"
	
>[!NOTE]
>This disables iCloud Photo Sharing.

>[!TIP]
>Manual Remedation

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|2.3 Address Unauthorized Software|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|13.4 Only Allow Access to Authorized Cloud Storage or Email Providers||:orange_circle:|:large_blue_circle:|Level - 1|	

## 2.3.8 - Ensure "Block Handoff" is set to "Yes"

>[!NOTE]
>This prevents Apple's Handoff data-sharing mechanism, allowing users to carry on tasks on another iOS/iPadOS or macOS device.

>[!TIP]
>Manual Remedation

>[!CAUTION]
Handoff does not enforce managed application boundaries. This allows managed application data to be moved to the unmanaged application space on another device, which may allow for intentional or unintentional data leakage.

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.3 Address Unauthorized Software|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|14.6 Only Allow Access to Authorized Cloud Storage or Email Providers|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|	

# 2.4 - Connected Devices

## 2.4.1 - Ensure "Force Apple Watch wrist detection" is set to "Yes"

>[!NOTE]
>This restriction forces wrist detection to be enabled to paired Apple Watches. When enforced, the Apple Watch won't display notifications when it's not being worn. The Apple Watch will also lock itself when it has been removed from a user's wrist.

>[!TIP]
>Manual Remedation

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.3 Configure Data Access Control List|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|14.6 Protect Information through Access Control Lists|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|	

## 2.4.2 - Ensure "Require AirPlay outgoing requests pairing password" is set to "Yes"


>[!NOTE]
>This restriction enforces the requirement of a pairing password when using AirPlay to stream content to a new Apple device.

>[!TIP]
>Manual Remedation

>[!CAUTION]
Users will have to authenticate to new Airplay devices via a password before first use.

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.3 Configure Data Access Control Lists|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|14.6 Protect Information through Access Control Lists|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|	

## 2.4.3 - Ensure "Block Apple Watch auto unlock" is set to "Yes"

>[!NOTE]
>This will restrict users from being able to automatically unlock their Apple Watch when they unlock their iOS/iPadOS device.

>[!TIP]
>Manual Remedation

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.3 Configure Data Access Control Lists|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|14.6 Protect Information through Access Control Lists|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|	

# 2.5 - General

## 2.5.1 - Ensure "Block sending diagnostic and usage data to Apple" is set to "Yes"

>[!NOTE]
>Apple provides a mechanism to send diagnostic and analytics data back to them in order to help improve the platform. This information sent to Apple may contain internal organizational information that should not be disclosed to third parties.

>[!TIP]
>Manual Remedation

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Ensure Only Approved Ports, Protocols and Services Are Running|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

## 2.5.2 - Ensure "Block screenshots and screen recording" is set to "Yes"	

>[!NOTE]
>This recommendation limits screen recording and the ability to screenshot from the device.

>[!TIP]
>Manual Remedation

>[!CAUTION]
>Screenshots and screen recordings will be disabled entirely.

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|3.3 Configure Data Access Control Lists|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|14.6 Protect Information through Access Control List|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

## 2.5.4 - Ensure "Force limited ad tracking" is set to "Yes"

>[!NOTE]
>This recommendation disables the ad identifier that is used to link advertisement information to a device.

>[!TIP]
>Manual Remedation

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

## 2.5.5 - Ensure "Block trusting new enterprise app authors" is set to "Yes"

>[!NOTE]
>This recommendation disables application installation by end users from outside the Apple App Store or Mobile Device Management (MDM) deployment.

>[!TIP]
>Manual Remedation

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|2.3 Address Unauthorized Software|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|2.6 Address unapproved software|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

## 2.5.6 - Ensure "Limit Apple personalized advertising" is set to "Yes"

>[!NOTE]
>Apple provides a framework that allows advertisers to target Apple users with advertisements relevant to them and their interests by means of a unique identifier. For such personalized advertisements to be delivered, however, detailed information is collected, correlated, and made available to advertisers. This information is valuable to both advertisers and attackers and has been used with other metadata to reveal users' identities.

>[!TIP]
>Manual Remedation

>[!CAUTION]
>Users will see generic advertising rather than targeted advertising. Apple has warned that this will reduce the number of relevant ads.

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software||:orange_circle:|:large_blue_circle:|Level - 1|
|7|9.2 Ensure Only Approved Ports, Protocols and Services Are Running||:orange_circle:|:large_blue_circle:|Level - 1|

# 2.6 - Locked Screen Experience

## 2.6.1 - Ensure "Block Control Center access in lock screen" is set to "Yes"

>[!NOTE]
>This restriction prevents access to the Control Center on the lock screen. Passcode/Face ID must be set for this to apply.

>[!TIP]
>Manual Remedation

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.3 Configure Automatic Session Locking on Enterprise Assets|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|


## 2.6.3 - Ensure "Block Today view in lock screen" is set to "Yes"

>[!NOTE]
>This restriction prevents access to the Today View and search on the lock screen. This can be seen by swiping left on the lock screen. A Passcode/Face ID must be set for this to apply.

>[!TIP]
>Manual Remedation

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.3 CConfigure Automatic Session Locking on Enterprise Assets|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

## 2.6.4 - Ensure "Block Wallet notifications in lock screen" is set to "Yes"

>[!NOTE]
>This restriction prevents access to the Apple Wallet while the screen is locked. Passcode/Face ID must be set for this to apply.

>[!TIP]
>Manual Remedation

>[!CAUTION]
>The device will need to be unlocked to access the Wallet.

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.3 Configure Automatic Session Locking on Enterprise Assets|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

# 2.7 - Password

## 2.7.1 - Ensure "Require password" is set to "Yes"

>[!NOTE]
>This restriction enforces a password to be set on the device.

>[!TIP]
>Manual Remedation

>[!CAUTION]
>A user will need to set a password to use the device.

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|5.2 Use Unique Passwords|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|4.4 Use Unique Passwords||:orange_circle:|:large_blue_circle:|Level - 1|

## 2.7.2 - Ensure "Block simple passwords" is set to "Yes"

>[!NOTE]
>This restriction enforces a block on simple passwords on the device. Passwords such as 1234 and 0000 would be blocked.

>[!TIP]
>Manual Remedation

>[!CAUTION]
>Those with passwords that do not meet this requirement will be prompted to set a new device password.

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|5.2 Use Unique Passwords|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|4.4 Use Unique Passwords||:orange_circle:|:large_blue_circle:|Level - 1|


## 2.7.4 - Ensure "Minimum password length" is set to "6" or greater

>[!NOTE]
>This restriction requires the password length set on the device to be 6 or greater.

>[!TIP]
>Manual Remedation

>[!CAUTION]
>Those with passwords that do not meet this requirement will be prompted to set a new device password.

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|5.2 Use Unique Passwords|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|4.4 Use Unique Passwords||:orange_circle:|:large_blue_circle:|Level - 1|

## 2.7.5 - Ensure "Maximum minutes after screen lock before password is required" is set to "Immediately"

>[!NOTE]
>This restriction disables any grace period where a password is not required to be entered after the screen has locked.

>[!TIP]
>Manual Remedation

>[!CAUTION]
>Those with passwords that do not meet this requirement will be prompted to set a new device password.

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.3 Configure Automatic Session Locking on Enterprise Assets|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

## 2.7.6 - Ensure "Maximum minutes of inactivity until screen locks" is set to "2" or less

>[!NOTE]
>This restriction sets the maximum time of inactivity before the device will be automatically locked.

>[!TIP]
>Manual Remedation

>[!CAUTION]
>This is not enforced during certain activities, such as watching video content.

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.3 Configure Automatic Session Locking on Enterprise Assets|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|


# 2.8 - Wireless

## 2.8.1 - Ensure "Block voice dialing while device is locked" is set to "Yes"

>[!NOTE]
>This restriction blocks initiating phone calls from a locked device. Voice dialing is handled separately from Siri.

>[!TIP]
>Manual Remedation

>[!CAUTION]
>A passcode/password will be required to unlock the device.

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.3 Configure Automatic Session Locking on Enterprise Assets|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 1|

