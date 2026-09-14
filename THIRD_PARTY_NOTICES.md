# Third-party notices

The Hermès Core Windows installer redistributes the following Open Source
components. They are **not** Authenticode-signed with the Hermès/SignPath
certificate; they are included as upstream binaries inside the installer
(permitted by SignPath Foundation terms for unsigned upstream OSS).

## CPython 3.12.10 embeddable (Windows x64)

- Source: https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip
- SHA256: 4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3
- License: Python Software Foundation License
- https://docs.python.org/3/license.html

## cryptography 50.0.0 (cp311-abi3 win_amd64)

- License: Apache License 2.0 or BSD
- https://pypi.org/project/cryptography/50.0.0/

## cffi 2.0.0 (cp312 win_amd64)

- License: MIT
- https://pypi.org/project/cffi/2.0.0/

## pycparser 2.23

- License: BSD
- https://pypi.org/project/pycparser/2.23/

Build-only (not shipped to users): Zig 0.14.1, used to cross-compile the
Windows PE launcher/installer from Linux.
