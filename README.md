# Repository Layout

This root now separates platform code from target applications.

- `security-platform/`: The security scanning platform (infra, frontend, workers, workflows)
- `target-app/`: Example target repository (business code scanned by SAST)
- `demo-vuln-target/`: Optional vulnerable demo target for pentest demonstrations
