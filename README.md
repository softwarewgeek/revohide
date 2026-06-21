# Revohide Dopamine

> A modified build of [Dopamine2-roothide](https://github.com/roothide/Dopamine2-roothide) with enhanced jailbreak detection bypass for banking and financial apps.

**iOS 15.0 – 15.8.x** and **iOS 16.0 – 16.7.16** • ARM64 and ARM64e

---

## What is this?

Revohide Dopamine is a free, pre-built version of the Dopamine2 jailbreak tool with an added layer that hides the jailbreak from apps that actively try to detect it — including banking apps like Revolut.

The detection bypass works by intercepting low-level system calls that apps use to check whether the device has been rebooted or resprung. It presents a consistent, clean state so apps see no signs of the jailbreak being active.

No subscription. No tracking. No strings attached.

---

## Supported iOS versions

| iOS version | Status |
|-------------|--------|
| 15.0 – 15.8.x | Supported |
| 16.0 – 16.7.16 | Supported |

---

## How to install

**Requires [TrollStore](https://github.com/opa334/TrollStore) to be installed on your device.**

1. Download the latest `.tipa` file from the [Releases](../../releases/latest) page
2. Open **TrollStore** on your device
3. Tap **+** and select the downloaded `.tipa` file
4. Tap **Install**

> If TrollStore shows a file type error, rename `.tipa` to `.ipa` before importing.

---

## Features added on top of stock Dopamine

- **Jailbreak detection bypass** — Hooks the system calls apps use to detect resprings. Banking apps, finance apps, and others that check boot state will see a clean device.
- **Multi-respring safe** — Continues working after Sileo installs tweaks, manual SpringBoard restarts, or any other event that resprings the device.
- **Diagnostic log viewer** — Available in Dopamine Settings → Revohide. Enable Hook Logging to watch what is being intercepted in real time.
- **Blood Sky theme** — Set as the default theme.

---

## Credits

This project exists entirely because of the work of others. All core jailbreak functionality is their work — this fork only adds the detection bypass layer on top.

| Project | Author | Role |
|---------|--------|------|
| [Dopamine2-roothide](https://github.com/roothide/Dopamine2-roothide) | [roothide](https://github.com/roothide) | The jailbreak this is based on |
| [Dopamine](https://github.com/opa334/Dopamine) | [opa334](https://github.com/opa334) | Original Dopamine jailbreak |
| [ElleKit](https://github.com/evelyneee/ellekit) | [evelyne](https://github.com/evelyneee) | Hooking framework used internally |
| [TrollStore](https://github.com/opa334/TrollStore) | [opa334](https://github.com/opa334) | Required to install the .tipa |

---

## Disclaimer

This tool is provided free of charge and is not affiliated with any of the projects listed above. Use at your own risk. The original authors retain all rights to their work.
