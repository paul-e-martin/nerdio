## v0.5.7 (2025-03-19)

### Refactor

- update documentation and clean up commented-out code in windows-base.ps1 (#20)

## v0.5.6 (2025-03-19)

### Refactor

- update tags in EntraIDWindowsCredentialManager.ps1 for clarity (#19)

## v0.5.5 (2025-03-19)

### Refactor

- update variable assignments and script name in EntraIDWindowsCredentialManager.ps1 (#18)

## v0.5.4 (2025-03-19)

### Refactor

- remove fslogix-entra-id.ps1 script and add EntraIDWindowsCredentialManager.ps1 for credential management (#17)

## v0.5.3 (2025-03-18)

### Refactor

- comment out sensitive operations in windows-base.ps1 and add fslogix-entra-id.ps1 script (#16)

## v0.5.2 (2025-03-07)

### Refactor

- remove bloatware removal script (#15)

## v0.5.1 (2025-03-07)

### Refactor

- update firewall rules and enable built-in Administrator account in CIS hardening script (#14)

## v0.5.0 (2025-03-07)

### Feat

- added cis hardening (#13)

## v0.4.4 (2025-03-05)

### Refactor

- Correct variable assignment and improve output messages in language setup script (#12)

## v0.4.3 (2025-03-05)

### Refactor

- Check for existing VM extensions before installation in Entra ID and Integrated Monitoring scripts (#11)

## v0.4.2 (2025-03-05)

### Refactor

- Simplify variable initialization and context setup in Entra ID and Integrated Monitoring scripts (#10)

## v0.4.1 (2025-03-05)

### Refactor

- Remove logging setup from Entra ID and Integrated Monitoring scripts for cleaner execution (#9)

## v0.4.0 (2025-03-05)

### Feat

- Migrate Entra ID and Integrated Monitoring scripts to new directory structure (#8)

## v0.3.2 (2025-03-05)

### Fix

- Update execution mode to Combined in Entra ID and Integrated Monitoring scripts; add BingSearch to removal list (#7)

## v0.3.1 (2025-03-04)

### Fix

- Correct variable casing in language setup script for consistency (#6)

## v0.3.0 (2025-03-04)

### Feat

- Add file cleanup after Windows package installation in language setup script (#5)

## v0.2.1 (2025-03-04)

### Fix

- Correct assignment operator in language setup script condition (#4)

## v0.2.0 (2025-03-04)

### Feat

- Add logging functionality to PowerShell scripts for better traceability (#3)

## v0.1.1 (2025-03-04)

### Fix

- Update language setup script to use blob storage for language packs and capabilities (#2)

## v0.1.0 (2025-03-04)

### Feat

- Refactor language setup scripts to dynamically set primary and secondary languages, input methods, and time zones based on secure and inherited variables (#1)
