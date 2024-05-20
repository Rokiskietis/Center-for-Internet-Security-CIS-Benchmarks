# Unsupervised (BYOD) Level - 2

# 2.5 - General

## 2.5.3 - Ensure "Block untrusted TLS certificates" is set to "Yes"

>[!NOTE]
>This recommendation blocks untrusted Transport Layer Security (TLS) certificates.

>[!TIP]
>Manual Remedation

>[!CAUTION]
>The device automatically rejects untrusted HTTPS certificates without prompting the user. Services using self-signed certificates will not function.

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.1 Establish and Maintain a Secure Configuration Process|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 2|
|7|5.1 Establish Secure Configurations|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 2|

# 2.6 - Locked Screen Experience

## 2.6.2 - Ensure "Block Notifications Center access in lock screen" is set to "Yes" 

>[!NOTE]
>This restriction prevents access to the Notifications Center on the lock screen. This does not restrict or limit information displayed from notifications, only older notifications that are stored in the notification center. This is usually visible by swiping up on the lock screen.

>[!TIP]
>Manual Remedation

Script to Remediation
```
Remediation
Script
```
|Controls Version|Control|IG1|IG2|IG3|Level|
|---|---|---|---|---|---|
|8|4.3 CConfigure Automatic Session Locking on Enterprise Assets|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 2|
|7|16.11 Lock Workstation Sessions After Inactivity|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 2|

# 2.7 - Password

## 2.7.3 - Ensure "Required password type" is set to "Alphanumeric"

>[!NOTE]
>This restriction enforces an alphanumeric password on the device. Numeric-only passcode pins would not be allowed.

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
|8|5.2 Use Unique Passwords|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 2|
|7|4.4 Use Unique Passwords||:orange_circle:|:large_blue_circle:|Level - 2|

## 2.7.7 - Ensure "Block Touch ID and Face ID unlock" is set to "Yes"

>[!NOTE]
>This restriction blocks Touch ID and Face ID being used to unlock the device. A standard passcode/password will be the only form of authentication to unlock the device.
If this is not set, passcode/password will still be required after a device power-cycles or the device has been reported as lost.

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
|8|3.3 Configure Data Access Control Lists|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 2|
|7|14.6 Protect Information through Access Control Lists|:green_circle:|:orange_circle:|:large_blue_circle:|Level - 2|
