# Hermès Core

Local-first Windows/Linux/macOS client: Ed25519 device identity, DPAPI on Windows, HTTPS pairing.

This repository is the **client** (runtime + Windows installer). It is not the WhatsApp relay, billing, or central Lynq servers.

## Downloads

Windows installer (PE): [HermesCoreSetup-0.1.2.exe](https://github.com/Maximus780112/hermes-core/releases/tag/v0.1.2)

SHA256 `9a8b08d99630d246fd61254bf525a3fbd91566e4d732fbf880596b85cf263746`

This project uses SignPath Foundation for code signing.

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org). See the [Code signing policy](CODE_SIGNING_POLICY.md).

Until SignPath Foundation accepts the project, the published installer remains unsigned.

## Windows installer

Engineering-certified unsigned PE (do not confuse with the old `.vbs` ZIP).

Install is user-scope (`%LOCALAPPDATA%\Programs\HermesCore\`). Identity stays in `%LOCALAPPDATA%\HermesCore\identity.json` (DPAPI). Uninstall keeps identity unless you opt in to purge.

## License

Apache License 2.0. Third-party redistributables: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Privacy

This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.

## Build Windows installer (unsigned)

Requires: Python 3.11+, Zig 0.14.1 (`zig` on PATH).

```
python3 windows-installer/build.py
```

Output: `windows-installer/dist/HermesCoreSetup-0.1.2.exe`
