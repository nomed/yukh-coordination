# Session 2026-08-13 — CLI executable composition

Issue #6 composes the previously delivered bootstrap, local custody, request
authorization, event builder, receipt verifier and HTTP client in the real
`yukh-coordination` executable.

The executable accepts one absolute closed configuration path, one inherited
root-key descriptor and, only for bootstrap, one inherited connected local
socket to an external-token supervisor. The socket exchange sends the public
P-256 JWK and receives one short-lived token bound to its exact thumbprint.
Tokens, root keys and private proof keys never enter flags, environment values,
configuration or output.

Qualification covers a complete HTTPS bootstrap through the executable and
then independently reopens the encrypted custody database to verify the stored
participant session. Full repository tests and vet remain required before
delivery. Packaging, a user-facing supervisor and watch composition remain
separate increments; this work authorizes no live traffic or deployment.
