
# Unsupervised (BYOD)

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
	