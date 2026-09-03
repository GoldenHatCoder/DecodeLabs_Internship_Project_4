# System Vulnerability Auditor

**Project made by M Luqman Shoaib**

A Windows-first defensive cybersecurity desktop application for **real, read-only endpoint security posture auditing**. It collects local evidence, prioritizes security findings, provides operational inventory, supports before/after verification, and generates evidence-rich reports.

> The application is an auditing and hardening-verification tool. It does not exploit vulnerabilities, crack passwords, bypass authentication, or automatically change Windows security settings.

## Version 3.0 — What improved

Version 3.0 focuses on usability and reporting quality rather than simply adding more buttons.

### Modern cybersecurity UI

- Dark SOC/security-operations visual design
- Cleaner spacing, typography and hierarchy
- Persistent workspace navigation
- Security posture score ring
- Status distribution bars
- Priority queue on the dashboard
- Dedicated Findings, Inventory, Reports and Guide workspaces
- Clear read-only/defensive mode indicator
- Live scan progress and completion state
- Double-click priority finding to inspect evidence

### More useful workflow

**Scan → Prioritize → Investigate → Remediate → Re-scan → Compare → Report**

The application automatically keeps the previous scan snapshot locally so a later scan can be compared against the earlier state.

### Stronger reports

The new HTML report is designed to be useful as an actual security assessment deliverable. It contains:

- Executive summary
- Security posture score
- Host and operating-system metadata
- Scan duration and timestamps
- PASS/WARNING/FAIL/MANUAL counts
- Risk overview by severity
- Score delta versus the previous scan when available
- Priority remediation plan
- Complete findings summary
- Detailed evidence appendix
- Remediation guidance for every finding
- Hardened verification workflow
- Safety/privacy note

Additional outputs remain available in Markdown, JSON and CSV.

## Capabilities

### Software & patch management

- OS and system baseline
- Pending operating-system updates
- Registered antivirus / endpoint protection
- Microsoft Defender protection state

### Identity & access

- Password policy
- Account lockout policy
- MFA verification guidance
- Guest account status
- Local administrator memberships
- Local user inventory
- User Account Control (UAC)

### Endpoint hygiene

- Automatic screen lock
- Disk encryption / BitLocker state
- Secure Boot

### Network exposure

- Windows Firewall profiles
- SMBv1 state
- Remote Desktop exposure
- Listening TCP services
- Network shares
- Active SMB sessions

### Application and system hardening

- PowerShell execution policy
- Automatic Windows services inventory
- Startup program inventory

## Finding model

Every control returns structured evidence with:

- **Status:** PASS, WARNING, FAIL, MANUAL, INFO or N/A
- **Severity:** Critical, High, Medium, Low, Info or Manual
- **Priority:** P1–P4
- **Domain:** security area being assessed
- **Evidence:** information collected from the local machine
- **Description:** why the control matters
- **Remediation:** what an administrator should review or change
- **Timestamp:** when the evidence was collected

The application intentionally uses `MANUAL` where local evidence cannot truthfully prove an external or contextual security property. MFA is an example: a local Windows scan cannot reliably prove the configuration of an external identity provider.

## Important scope note

This is a **security posture auditor**, not a complete vulnerability-management platform or CVE scanner.

For example:

- A listening port is an exposure that needs review, not automatically a vulnerability.
- A registered antivirus product does not prove every endpoint protection feature is correctly configured.
- A PASS result means the local check observed the expected state; it does not guarantee the computer is secure.
- The score is a prioritization aid, not CVSS, compliance certification, or a penetration-test result.

## Requirements

- Windows 10 or Windows 11 recommended
- Python 3.10+
- PowerShell available
- Standard Python library only for the source application

No third-party Python packages are required to run the source version.

## Run from source

Open PowerShell in the project directory:

```powershell
python app.py
```

or:

```powershell
py app.py
```

For the most complete Windows results, run the application with appropriate administrative permissions. Some Windows commands and security APIs can return limited information without elevation.

## Using the application

### 1. Dashboard

Start with **RUN FULL AUDIT** for the complete control set.

Use **QUICK AUDIT** when you want the most important security controls first.

The dashboard shows:

- Overall posture score
- High-risk controls
- Warnings
- Manual verification items
- Number of controls checked
- Priority findings
- Recommended next actions

### 2. Findings

Use the Findings workspace to:

- Search by keyword
- Filter by status
- Filter by security domain
- Select a finding
- Read the evidence
- Read the remediation guidance
- Copy a finding to the clipboard

### 3. Inventory

Review operational information collected during the scan:

- TCP listeners and owning processes/PIDs
- Local users
- Automatic services
- Startup programs
- Network shares
- SMB sessions

Inventory is intentionally separated from vulnerability findings because visibility does not automatically mean a security defect.

### 4. Remediation and verification

The application does not modify the system. Use your approved Windows/security procedures to remediate issues.

Then run the application again.

The application keeps the previous scan snapshot and provides **COMPARE LAST SCAN** so you can see:

- Improved controls
- Worsened controls
- Unchanged controls
- Previous score
- Current score
- Score delta

## Reports

### HTML — recommended

Use the HTML report when you need a polished, browser-readable assessment.

It is useful for:

- University submissions
- Project demonstrations
- Security review evidence
- Remediation documentation
- Before/after verification
- Presentations and portfolio work

### Markdown

Useful for:

- GitHub
- Coursework
- Documentation
- Human-readable audit notes

### JSON

Useful for:

- Automation
- Structured storage
- Future dashboards
- Data processing
- API integration later

### CSV

Useful for:

- Excel
- Sorting and filtering
- Security review tables
- Data analysis

## Build a Windows executable

Install PyInstaller:

```powershell
python -m pip install pyinstaller
```

Build:

```powershell
pyinstaller --onefile --windowed --name SystemVulnerabilityAuditor app.py
```

The executable will be placed in:

```text
dist\SystemVulnerabilityAuditor.exe
```

## Privacy and safe use

Use the application only on systems you own or are explicitly authorized to assess.

The application is designed to be read-only. It does not:

- change firewall settings
- disable accounts
- change passwords
- install updates
- change BitLocker settings
- exploit vulnerabilities
- crack credentials
- bypass authentication

Do not place these in reports:

- Passwords
- MFA codes
- Recovery keys
- API tokens
- Session tokens
- Private keys
- Other confidential credentials

The generated local snapshot is stored under `reports/` and is ignored by Git by default because it contains machine-specific evidence.

## Limitations

Results depend on Windows edition, installed components, permissions, local policy and system state. Some commands may be unavailable or return incomplete information.

The application deliberately avoids pretending it can prove things it cannot directly observe.

## Project requirements coverage

- [x] Real working desktop application
- [x] Modern cybersecurity-focused UI/UX
- [x] Full and quick audit modes
- [x] Real local evidence collection
- [x] Security posture score
- [x] Findings, severity and priority
- [x] Search and filtering
- [x] Endpoint/network inventory
- [x] Re-scan and before/after comparison
- [x] Evidence-rich HTML report
- [x] Markdown, JSON and CSV exports
