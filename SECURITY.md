# Security Policy

**Last updated: 2026-11-02**

## 1. Purpose and Scope

This policy is available in Japanese ([セキュリティポリシー](docs/SECURITY-ja.md)) and English. If there is any discrepancy between the two, the Japanese version prevails.

This policy describes the security positioning of **TCAndroidKey** (the "App"), its protection mechanisms, known limitations, measures expected of users, and how to report vulnerabilities.

## 2. Security Positioning

The App is **a testing tool for web applications that use FIDO / FIDO2 (WebAuthn)**. Its protection mechanisms aim to prevent mistakes and unintended authentication during testing. They do not provide security equivalent to physical security keys such as YubiKey.

The main differences from a physical security key are:

- Authentication runs as an Android app, not on dedicated hardware. It is affected by vulnerabilities in the device's operating system and in the App itself.
- The App is not FIDO Certified.
- The App has no attestation (vendor certificate) that proves the authenticity of the authenticator.
- Keys cannot be backed up, transferred, or restored.

For these reasons, **do not use the App as a replacement for a physical security key, and register it only with test accounts and test environments** ([Terms of Use](docs/TERMS.md), Sections 2 and 3).

## 3. Protection Mechanisms

| Item | Description |
|---|---|
| Private key storage | An EC P-256 key is generated for each registration inside the Android Keystore (StrongBox when available, otherwise the TEE). Keys cannot be taken out of the device |
| User verification | Registration and authentication require prior user verification with a biometric (Class 3), such as a fingerprint, or the screen lock credential |
| Acceptance limits | The App responds only while its screen is in the foreground and within the acceptance window after verification (15 to 300 seconds, default 60). By default, one verification allows only one registration or authentication (one-time authorization) |
| Outside the window | Outside the acceptance window, the App does not expose the NFC FIDO applet at all (it behaves as if it does not exist) |
| Stop / leaving the foreground | When acceptance is stopped or the App leaves the foreground, operations in progress or being continued are also invalidated |
| Device lock | While the device is locked, the operating system prevents both NFC responses and key use |
| Key usage period | Keys can sign only within 300 seconds after user authentication and only while the device is unlocked (defense in depth by the Android Keystore) |
| Metadata | Metadata such as RP IDs and user names is stored encrypted with an AES-256-GCM key in the Android Keystore |
| Backup | All data is excluded from Android backup and device transfer |
| Screen | Screenshots and screen sharing are blocked |
| Logs | The event log is kept in memory only. RP IDs, user names, and connected host names are not written to the system log (logcat) |
| Network | The App does not communicate over the internet |
| Deletion / protection settings | Deleting keys and weakening protection settings (such as turning off one-time authorization) require user verification |

## 4. Known Limitations and Residual Risks

As a testing tool, the App accepts the following limitations and risks. They are not treated as vulnerabilities.

| Limitation / risk | Description |
|---|---|
| Identifying the requester | Within the acceptance window, the App cannot distinguish requests from nearby NFC readers and other clients. Even with one-time authorization, it cannot single out a malicious reader that sends the first request |
| Running as an app | Authentication runs in the App's process, so it is affected by vulnerabilities in the operating system or the App, and by devices modified by rooting or similar means |
| Shared debug signing key | Development builds are signed with a shared signing key published in the repository. If a malicious APK signed with the same key is installed as an update, it may take over the App's data and keys and use them |
| Metadata rollback | Tampering with or corruption of the encrypted metadata is detected, but replacing it with an earlier legitimate file (rolling back the signature counter) is not |
| PIN | clientPIN (verification by PIN) is not supported. User verification uses the device's biometrics or screen lock |
| Attestation | The App has no vendor attestation and supports only `none` or self attestation |
| Bluetooth HID | Experimental. It may not work depending on the host environment |
| Key operations already started | A Keystore operation that started before acceptance was stopped cannot itself be cancelled (after stopping, no new key operation is started and results are not sent) |

## 5. Measures Expected of Users

- Set a screen lock on the device and keep the operating system up to date.
- Install only APK files that you built yourself or obtained directly from the developer.
- Do not register the App with production services or important accounts; use it only with test accounts and test environments.
- Delete keys when you finish testing. If you no longer use the App, uninstall it (all keys are deleted).
- Do not leave the device unattended while the App is accepting authentication ("Ready to authenticate" is shown).

## 6. Supported Versions

Security fixes are provided only for the latest version (the latest source code in the repository).

## 7. Reporting a Vulnerability

If you discover a vulnerability in the App, please do not create a public Issue. Report it by email to [tecogonaz@kusugami-lab.net](mailto:tecogonaz@kusugami-lab.net). I will respond as quickly as possible.

Where possible, please include:

- the version (commit) of the App, and the device and Android version
- steps to reproduce and the expected impact
- the client used (operating system, browser, NFC reader, and so on)

As a rule, the known limitations and residual risks in Section 4, and issues caused by rooted or modified devices or by APK files built by third parties, are out of scope.

I do not guarantee individual responses, fixes, or the timing of fixes for every report.

## 8. Changes to This Policy

This policy may be updated in response to changes in the App, the environment in which it is used, laws and regulations, and so on. Changes and the last updated date are published in the source code repository.
