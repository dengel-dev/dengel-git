# Security

Use the GitHub Advisories page for private reports affecting Dengel Git or
its bundled RustGit crate.

[Report a vulnerability privately](https://github.com/dengel-dev/dengel-git/security/advisories/new)

Include the version from `dengel-git --version`, operating system, the affected
operation, and any relevant logs with credentials and repository data removed.
Keep vulnerability details in the private report while maintainers investigate.

Run the listener with a dedicated account and trusted repository directories.
For network use, configure per-repository credentials and a TLS reverse proxy
with request timeouts and connection limits. Keep the backend on loopback
or a private interface restricted to the proxy. Protect token files, backups,
and the repository filesystem with operator-only permissions.
