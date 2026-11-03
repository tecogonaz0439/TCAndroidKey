# Terms of Use

**Last updated: 2026-11-03**

## 1. Scope

These Terms of Use (the "Terms") set out the conditions for using **Security Key Emulator** (Japanese name セキュリティキーエミュレータ, project name TCSecurityKeyEmulator; the "App").

By installing, launching, or using the App, you are deemed to have agreed to these Terms. If you do not agree, do not use the App.

These Terms are available in Japanese ([利用規約](TERMS-ja.md)) and English. If there is any discrepancy between the two, the Japanese version prevails.

These Terms govern the use of the App and do not restrict any rights granted under the Apache License, Version 2.0, to use, reproduce, modify, or distribute the source code, object code, derivative works, or redistributions. Those matters are governed by the [LICENSE](../LICENSE).

## 2. What the App Is

The App makes an Android device act as a FIDO2 (CTAP 2.0) security key. It is **a testing tool for checking registration and authentication in web applications that use FIDO / FIDO2 (WebAuthn)**.

**The App is not intended to be used as a replacement for physical security keys such as YubiKey.** Do not use the App as an everyday authentication method, as multi-factor authentication for production services, or as a means of account recovery.

The App is not FIDO Certified. It is not provided, approved, sponsored, or endorsed by the FIDO Alliance, Yubico, Google, or any other third party. FIDO, FIDO2, WebAuthn, YubiKey, Android, and other names are trademarks or registered trademarks of their respective owners.

## 3. Conditions of Use

You must observe the following when using the App.

- **Register the App only with test accounts and test environments.** Do not register it with production services or important accounts.
- Test only web applications (relying parties) that you manage yourself, or that you have been permitted to test by their administrators.
- Set a screen lock (PIN, pattern, or password) on the device that runs the App, and do not hand the device to others while the App's keys can be used.
- When you finish testing, delete the keys on the App's "Credentials" screen and also delete the registrations on the web application under test.

## 4. Keys and Data

### 4.1 Keys

The App generates a private key for each registration inside the Android Keystore (StrongBox or TEE). Private keys cannot be taken out of the device, and the App cannot export them.

Private keys are excluded from Android backup and device transfer. **Keys are lost and cannot be recovered** when the App is uninstalled, the App's data is cleared, the device is reset, the screen lock is disabled, and so on. If you can no longer sign in to a test account because a key was lost, recovery depends on the means provided by the web application under test.

### 4.2 Data on the Device

The App stores the following data in its private storage on the device.

| Data | Contents | How it is stored |
|---|---|---|
| Credential metadata | RP ID and RP name, user ID, user name and display name, public key, creation and last-use dates, signature counter | Encrypted with a key in the Android Keystore |
| Settings | Theme, acceptance window, one-time authorization, and other settings | App private storage |
| Event log | Results of registrations and authentications, RP IDs, user names, and so on | Memory only (erased when the App exits) |

This data is excluded from Android backup and device transfer. Part of the event log (command names and results only, without RP IDs or user names) is also written to the Android system log (logcat) for development purposes.

You can delete the stored data with the delete functions on the App's "Credentials" screen, by clearing the App's storage from the Android app info screen, or by uninstalling the App.

### 4.3 Information the App Does Not Send

The App does not communicate over the internet (it does not have the internet permission). It does not ask you to register a name, email address, or similar information, and it does not collect location, device identifiers, or advertising IDs. It does not use advertising, analytics, or crash reporting SDKs.

The only information the App sends outside the device is FIDO2 responses (public keys, signatures, credential IDs, user IDs, user names, and so on) to clients that you connect over NFC or Bluetooth (PCs, browsers, other Android devices, and so on). How those clients and web applications handle that information is governed by their providers' terms and policies.

## 5. Permissions

The App uses the following Android permissions.

| Permission | Purpose |
|---|---|
| NFC | To act as a security key through NFC card emulation |
| Use biometrics (USE_BIOMETRIC) | To verify the user before registration and authentication, and before deletions and setting changes |
| Nearby devices (BLUETOOTH_CONNECT / BLUETOOTH_ADVERTISE) | To act as a Bluetooth HID security key (experimental; only when enabled in the settings) |

## 6. Distribution and APK Files

The App is not currently distributed through any app store. The source code is published in the GitHub repository.

- Source code: https://github.com/tecogonaz0439/TCSecurityKeyEmulator

Development builds (debug builds) are signed with a shared signing key that is published in the repository, so that the App can be updated in place. **Third parties can therefore create APK files with the same signature.** Install only APK files that you built yourself or obtained directly from the developer, and check the source, the authenticity of the file, and the risks of installing it yourself.

We do not guarantee the safety, integrity, authenticity, operation, or support of APK files obtained from sources other than the official ones, APK files modified or rebuilt by third parties, or derivative versions.

The App is not sold and does not offer in-app purchases, advertising, or subscriptions.

## 7. Open Source License

The App's source code is published under the Apache License, Version 2.0. You may use, reproduce, modify, and distribute the source code and object code in accordance with that license. The App uses open source libraries such as AndroidX and Jetpack Compose under their respective licenses.

If you distribute a modified or derivative version using the App's name, icon, screens, descriptions, or other elements, do not make it appear to be an official, certified, or approved version of the FIDO Alliance or any other third party. When distributing a modified version, comply with the Apache License, Version 2.0, applicable laws, the terms of the distribution channel, and the rights of third parties.

Issues, pull requests, patches, translations, documentation, ideas, and other contributions to the source code repository may be incorporated into the App under the Apache License, Version 2.0, unless other terms are stated explicitly at the time of contribution.

## 8. External Clients and Services

The App is used together with external clients and services such as PC and smartphone operating systems, browsers, NFC readers, and the web applications under test. Their use is governed by their providers' terms, policies, and conditions.

We do not guarantee compatibility with any particular client, operating system, browser, NFC reader, or web application. Connection over Bluetooth HID is an experimental feature, and its operation is not guaranteed.

## 9. Prohibited Conduct

You must not:

- violate laws and regulations, public order and morals, the rights of third parties, or these Terms;
- use the App to register with, authenticate to, or test third-party web services, systems, or accounts without the permission of their administrators;
- use the App or a modified version to impersonate others, bypass authentication improperly, or gain unauthorized access;
- provide the App to third parties as an authenticator for production services, or present or describe the App as a physical security key or a certified authenticator;
- use or distribute the App or a modified version for malware, malicious code, phishing, fraud, or any other purpose of deceiving users;
- place excessive load on, or cause failures in or interference with, the App, clients, web services, or third-party devices or networks; or
- engage in any other conduct that we reasonably determine to be outside the normal scope of use of the App (Sections 2 and 3).

## 10. Changes, Suspension, and Termination

We may change the App's features, specifications, display, supported operating systems, supported devices, distribution methods, documentation, Security Policy, and these Terms as necessary.

We may suspend or end the distribution, updates, provision, or support of the App for security reasons, maintenance, changes in external specifications or services, legal requirements, or other unavoidable circumstances.

If we change these Terms, the revised Terms take effect when they are published in the repository, in the App, or by any other method we consider appropriate. If you use the App after the change, you are deemed to have agreed to the revised Terms.

## 11. No Warranty

The App is provided free of charge, as is and as available. We make no warranty as to the App's accuracy, completeness, usefulness, availability, continuity, security, freedom from errors, conformance to the FIDO / WebAuthn specifications, fitness for a particular purpose, non-infringement of third-party rights, compatibility with devices, operating systems, or clients, or the retention or recovery of keys or data.

## 12. Limitation of Liability

To the maximum extent permitted by law, we are not liable for any damage suffered by you or any third party in connection with the App. This includes being unable to sign in to an account because a key was lost, unauthorized access resulting from using the App as a replacement for a physical security key, and effects on the web applications or accounts under test.

Even where we cannot be exempted from liability by law, except in cases of our intent or gross negligence, our liability is limited to ordinary and direct damage actually incurred. We are not liable for special, indirect, incidental, or consequential damages, lost profits, loss of data, business interruption, device failure, or claims from third parties.

## 13. Use by Minors

Minors must obtain the consent of a parent or other legal guardian before using the App. If a minor uses the App, the minor is deemed to have obtained that consent.

## 14. Governing Law and Jurisdiction

These Terms and any disputes relating to the App are governed by the laws of Japan, including their formation, validity, interpretation, and performance.

The Takamatsu District Court has exclusive jurisdiction as the court of first instance for any dispute between us and you relating to these Terms or the App.

## 15. Contact

For questions about these Terms, the App, or the license, please use the [Issues of the GitHub repository](https://github.com/tecogonaz0439/TCSecurityKeyEmulator/issues). Issues are public, so do not include personal or confidential information.

Report vulnerabilities as described in the [Security Policy](../SECURITY.md), not through Issues.

We do not guarantee individual responses, investigations, fixes, updates, or support for every inquiry.
