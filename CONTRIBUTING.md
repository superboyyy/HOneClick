# Contributing

## Before submitting

- Test on the documented device and kernel whenever possible.
- Include the exact HOneClick version, device model, kernel release, and reproduction steps.
- Remove device serial numbers, account identifiers, IP addresses, and personal paths from logs and screenshots.
- Do not submit unrelated firmware files, proprietary kernel images, or extracted applications.
- Do not add third-party binaries unless their origin, version, license, checksum, and corresponding source requirements are documented.

## Code changes

- Keep device-specific constants isolated from UI and general process handling.
- Add the exact expected behavior when adding or changing a log marker.
- Treat root-file permissions, process identity, and race timing as security-sensitive code.
- Prefer clear failure messages over silent retries.
- Keep device and kernel compatibility profiles explicit; do not claim a new kernel/device is supported without test evidence.

## License

By contributing original code, you agree that it may be distributed under the repository's MIT License. Contributions derived from another project must retain their original license and attribution and cannot be relicensed by this project.
