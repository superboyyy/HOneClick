# Security Policy

## Supported scope

Security reports are accepted for the current HOneClick source and the exact device/kernel combinations documented in [README.md](README.md).

This project performs privileged kernel operations. Reports about unexpected reboot, memory corruption, privilege persistence, authorization bypass, unsafe file permissions, command injection, or unintended data access are especially relevant.

## Reporting a vulnerability

Please use GitHub's private security advisory feature instead of opening a public issue containing a working exploit, sensitive kernel addresses, device identifiers, or personal logs.

If private advisories are unavailable, contact the repository owner through the GitHub profile linked in the application footer and request a private reporting channel.

Please include:

- HOneClick version code and APK SHA-256
- Device model and Android build
- Kernel release string
- Reproduction steps
- Relevant logs with serial numbers, account information, and other personal data removed
- Whether the issue affects confidentiality, integrity, data availability, or device safety

## Safety boundaries

- Test only devices you own or are explicitly authorized to modify.
- Back up important data before running the exploit chain.
- Do not use the project on shared, managed, production, or third-party devices.
- Do not publish a new exploit variant for an unpatched third-party device without responsible coordination.

No response-time or remediation-time guarantee is provided.
