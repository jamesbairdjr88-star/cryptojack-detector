# Cryptojack Companion (Android)

Kotlin + Jetpack Compose companion app for the `cryptojack-detector` host tool. It fetches the
detector's JSON report from a machine you own and shows what was flagged, why, and how strongly.

The app is **read-only by design**: it never sends commands to the host, never kills processes, and
holds no credentials beyond an optional bearer token you supply.

## Features

- Summary card: host, processes scanned, scan duration, and an at-a-glance verdict.
- Flagged-process list sorted by confidence score, with severity chips (CRITICAL / WARNING / INFO).
- Detail sheet explaining every scoring signal that fired (sustained CPU, miner name/argument
  signatures, mining-pool connections, suspicious binary paths) and its weight.
- Detector host settings stored locally with DataStore, optional bearer-token auth.
- Built-in demo report so the UI is reviewable without a live host.

## Stack

| Layer | Choice |
| --- | --- |
| Language | Kotlin 1.9 |
| UI | Jetpack Compose + Material 3 |
| State | ViewModel + StateFlow |
| Networking | OkHttp + kotlinx.serialization |
| Storage | DataStore Preferences |
| Min / target SDK | 26 / 34 |

## Project layout

```
android/
  app/src/main/java/com/jamesbaird/cryptojack/
    MainActivity.kt              entry point, wires state to screens
    data/Models.kt               ScanReport / Finding / Signal + severity rules
    data/DetectorApi.kt          read-only HTTP client for GET /report.json
    data/ScanRepository.kt       result wrapping + demo data
    data/SettingsStore.kt        DataStore-backed host settings
    ui/ScanViewModel.kt          UI state machine
    ui/DashboardScreen.kt        summary + findings list
    ui/Sheets.kt                 detail sheet, settings sheet
    ui/theme/Theme.kt            Material 3 color scheme
```

## Running it

1. Open the `android/` folder in Android Studio (Hedgehog or newer) and let it sync.
2. If you build from the CLI, generate the wrapper first: `gradle wrapper`, then `./gradlew assembleDebug`.
3. Launch the app. With no host configured it shows the demo report.
4. Tap the gear icon, enter your detector base URL (for example `http://192.168.1.20:8787`), and save.

## Expected report format

The app expects `GET <baseUrl>/report.json`:

```json
{
  "host": "workstation",
  "generated_at": "2026-09-12T02:30:00Z",
  "scan_duration_sec": 1.8,
  "processes_scanned": 214,
  "findings": [
    {
      "pid": 4821,
      "name": "xmrig",
      "exe": "/tmp/.cache/xmrig",
      "username": "james",
      "score": 92,
      "cpu_percent": 388.4,
      "signals": [
        { "id": "name_match", "label": "Known miner signature", "detail": "Binary name matches xmrig", "weight": 35 }
      ]
    }
  ]
}
```

Unknown JSON fields are ignored, so the detector can add signals without breaking the app.

Severity thresholds: score >= 70 CRITICAL, >= 40 WARNING, otherwise INFO — matching the detector's
tuned 40% CPU floor from its evaluation harness.

## Scope and ethics

Use only on machines you own or are explicitly authorized to monitor. Plain HTTP is fine on a trusted
LAN; put it behind HTTPS or a VPN if the report is reachable from anywhere else.

## License

MIT.
