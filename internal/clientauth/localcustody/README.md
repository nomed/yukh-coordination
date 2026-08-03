# RFC-0018 local custody foundation

This package owns the environment-neutral encrypted SQLite implementation of
the RFC-0014 `CredentialStore` and `ProofSignerStore` ports.

It deliberately has no D-Bus, GNOME Keyring, KeePassXC, libsecret, environment
discovery or executable dependency. A caller supplies one exact `RootKeySource`.
The future optional workstation adapter may obtain that root key from an
explicit Secret Service connection; a server profile will use a separately
accepted workload-identity and remote KMS/secret-store composition.

SQLite owns exact revisions, compare-and-set and signer lifecycle state. Every
session and PKCS #8 signer payload is encrypted with domain-separated
XChaCha20-Poly1305 before it reaches SQLite, its WAL or shared-memory files.

