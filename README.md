[日本語版はこちら](README-ja.md)

# TCAndroidKey

**TCAndroidKey** is an Android app that turns an Android device into a **FIDO2 (CTAP 2.0) security key** for **testing web applications that use FIDO / FIDO2 (WebAuthn)**. Hold the device to an NFC reader connected to a PC (or to another Android device) to try passkey and security-key registration and sign-in on the web application you are developing.

> [!IMPORTANT]
> **This app is a testing tool. Do not use it as a replacement for physical security keys such as YubiKey.**
> Register it only with test accounts and test environments, not with production services or important accounts.
> The app is not FIDO Certified, and keys cannot be backed up or recovered (uninstalling the app deletes them).
> See the [Terms of Use](docs/TERMS.md) and the [Security Policy](SECURITY.md).

**This app is not provided, approved, or endorsed by the FIDO Alliance, Yubico, Google, or any other third party.**

## Features

- **FIDO2 security key over NFC** — Host-based card emulation (HCE) of the FIDO applet; CTAP 2.0 commands MakeCredential, GetAssertion, GetNextAssertion, GetInfo, Selection, and Reset (optional)
- **Passkeys and non-discoverable credentials** — ES256 (ECDSA P-256), multiple accounts per site, `none` or packed self attestation
- **Keys in the Android Keystore** — A private key is generated for each registration in StrongBox (or the TEE) and never leaves the device; delete keys individually or all at once
- **Authentication only when you allow it** — Only while the app is on screen, only within a short window after fingerprint (or screen lock) verification, and by default only once per verification
- **Event log** — Results of each registration and authentication (kept in memory only)
- **No Google Play services** — Works on business devices without GMS; no internet permission
- **Bluetooth HID (experimental)** — CTAPHID over the Bluetooth HID Device profile
- **English and Japanese** — Including the per-app language setting

USB is not supported: an Android app cannot act as a USB HID device without root.

## Requirements

- Android 15 (API 35) or later, with NFC and host-based card emulation
- A screen lock (and preferably a Class 3 biometric such as a fingerprint)
- A client: for example, a Windows PC with a PC/SC NFC reader, or another Android device with NFC

## How to Obtain

The app is not distributed through app stores or GitHub Releases yet. Build the APK from source:

```bash
scripts/cicd/build-apk.sh
```

The APK is written to `build/cicd/apk/TCAndroidKey-debug.apk`. See [Cloud build](docs/CLOUD-BUILD.md) or [Local build on macOS](docs/LOCAL-BUILD-macOS.md) for setting up the build environment.

Debug builds are signed with a shared key published in this repository, so that you can update the app in place (uninstalling it deletes all keys). Because anyone can create an APK with the same signature, install only APKs that you built yourself or obtained directly from the developer.

## Usage

1. Set a screen lock and a fingerprint on the device, and turn on NFC.
2. Open the app and tap **Verify and start**, then verify with your fingerprint.
3. While **Ready to authenticate** is shown, hold the back of the device to the NFC reader.

See [Testing](docs/TESTING.md) for step-by-step checks on Windows, macOS, and Android, including a Python script based on [python-fido2](https://github.com/Yubico/python-fido2).

## Compatibility

| Client | Connection | Status |
|---|---|---|
| Windows 11 (Edge / Chrome) | NFC (PC/SC reader) | Expected to work; being tested |
| python-fido2 2.0.0 (low-level `Ctap2`) | NFC (PC/SC reader) | Response format verified |
| Android (Chrome) | NFC | Expected to work; being tested |
| macOS (Chrome) | NFC | Not supported by the browser |
| Windows / macOS browsers | Bluetooth HID | Experimental |

Known limitations (no clientPIN, CTAP 2.0 only, no U2F, no extensions, and so on) are listed in the [design documents](docs/design/appendix/C_roadmap.md).

## Documentation

| Document | Contents |
|---|---|
| [Design documents](docs/design/README.md) | Basic design, detailed design, and appendices (Japanese) |
| [Cloud build](docs/CLOUD-BUILD.md) | Building the APK in a cloud environment (Japanese) |
| [Local build on macOS](docs/LOCAL-BUILD-macOS.md) | Building with Android Studio on macOS (Japanese) |
| [Testing](docs/TESTING.md) | Testing on Windows, macOS, and Android (Japanese) |

## Repository

- **GitHub**: [tecogonaz0439/TCAndroidKey](https://github.com/tecogonaz0439/TCAndroidKey)

```
fido-core/   FIDO2 protocol implementation (CBOR, CTAP2, NFC APDU, CTAPHID, authorization gate). Pure Kotlin with unit tests
app/         Android app (Keystore, HCE service, Bluetooth HID, Compose UI)
scripts/     Cloud setup, build / verify / install scripts, and test scripts (python-fido2)
docs/        Design documents, build and test guides, terms of use, security policy
```

Please report issues and submit pull requests in this repository. Report vulnerabilities by email as described in the [Security Policy](SECURITY.md), not in public Issues.

## Links

- Terms of Use: [English](docs/TERMS.md) / [Japanese](docs/TERMS-ja.md)
- Security Policy: [English](SECURITY.md) / [Japanese](docs/SECURITY-ja.md)

## License

The source code is licensed under the [Apache License, Version 2.0](LICENSE).

The app's UI is based on [TCSameuraDamMonitor-android](https://github.com/tecogonaz0439/TCSameuraDamMonitor-android).
