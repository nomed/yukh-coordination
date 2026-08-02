# Security policy

Yukh Coordination is in foundation and has not published a production release.

Do not report vulnerabilities, credentials, private transcripts, or sensitive adopter data in public issues. Use GitHub's private vulnerability reporting for this repository when available.

## Security invariants

- deny channel access by default;
- never embed credentials or unrestricted logs in events;
- treat participant announcements as claims until authenticated;
- treat evidence references as unverified until independently checked;
- do not infer authority from presence, message order, or display name;
- preserve an audit trail for accepted handoffs and claim transitions.
