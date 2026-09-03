# Security Notes

## Intended use

System Vulnerability Auditor is intended for defensive security assessment of computers that the operator owns or is explicitly authorized to audit.

## Design

The application performs read-only local checks. It does not intentionally exploit vulnerabilities or make security-setting changes.

## Sensitive data

Do not place credentials, MFA codes, recovery keys, API tokens, session tokens or private keys into exported reports or Git repositories.

## Reporting a problem

If you discover a security issue in this project, document the issue, affected component, reproduction conditions and potential impact without including real credentials or private data.
