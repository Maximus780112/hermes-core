# Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org)

Status: **pending SignPath Foundation approval**. Releases until approval are unsigned.

## What will be signed

- `HermesCoreSetup-<version>.exe` — the Windows GUI installer (PE), built from this repository.

Upstream binaries bundled *inside* the installer (CPython embed, cryptography, cffi, pycparser) are **not** signed with this project's certificate.

## Build and signing process

- Artifacts are built from this repository.
- Only CI-built artifacts will be submitted to SignPath once the project is accepted.
- The private key is held by SignPath (HSM). This project does not store the private key.

## Team roles

- Authors (commit access): [Maximus780112](https://github.com/Maximus780112)
- Reviewers: [Maximus780112](https://github.com/Maximus780112)
- Approvers: [Maximus780112](https://github.com/Maximus780112)
- Policy: external pull requests are reviewed by the maintainer before merge.

## Privacy

This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.

Pairing, if requested by the user, contacts only the HTTPS endpoint the user chooses.
