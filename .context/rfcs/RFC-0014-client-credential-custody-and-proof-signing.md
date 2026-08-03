# RFC-0014: Client credential custody and proof signing

- Status: Accepted
- Authors: Nomed with implementation support
- Created: 2026-08-03
- Governing issue: #6
- Governing architecture: RFC-0008, RFC-0009, RFC-0010 and RFC-0013

The project owner explicitly accepted this RFC on 2026-08-03 after reviewing
and correcting the signer lifecycle. Acceptance authorizes only the neutral
client-authentication refactor and conformance work described below. Concrete
adapters and deployment remain separately gated.

## Decision requested

Replace only the RFC-0013 client-custody model with three explicit,
provider-neutral boundaries:

1. a credential store for the recoverable relay session capability and its
   public metadata;
2. a proof signer whose private ES256 key is never exposed through the neutral
   client API;
3. an external-token source that bootstraps the relay session from an explicitly
   selected human or workload identity mechanism.

This separation permits local port-chains and remote secret/KMS compositions
without pretending that their authentication, key-export, availability and
consistency guarantees are equivalent.

Acceptance authorizes a separately reviewed refactor of the existing
`internal/clientauth` foundation and conformance fakes. It does not select or
authorize a concrete Secret Service, Vaultwarden, Google Cloud, HashiCorp Vault,
GitHub, KMS, HSM or TPM adapter; provision cloud resources; add credentials;
modify the relay protocol; introduce delegation; or deploy an executable.

## Supersession boundary

On acceptance, this RFC supersedes only the three paragraphs under RFC-0013
`Configuration and session custody` that require a locally generated private
key to be stored inside one operating-system credential set. All other
RFC-0013 command, event, output, replay, qualification and rollout decisions
remain unchanged.

RFC-0009 and RFC-0010 remain unchanged. The relay still receives the same
strict ES256 DPoP proof and binds the session to the exact RFC 7638 public-key
thumbprint. Key placement is a client concern and cannot weaken the wire
contract or the relay verifier.

## Why the current boundary is too narrow

The current foundation places the token, public session metadata and private
ECDSA key in one in-process value behind one `CredentialStore`. That is a valid
first local implementation, but it cannot accurately model all intended
execution environments:

- a desktop keyring stores recoverable secret bytes and signs in the client;
- a remote secret manager returns secret bytes over an authenticated channel;
- a KMS, HSM, TPM or secure enclave performs signing without returning the
  private key;
- a remote store itself needs an independently established caller identity;
- GitHub Actions secrets can inject values into a job but are not a general
  read-after-write secret-store API for the CLI.

A lowest-common-denominator `Load` method would make non-exportable keys appear
exportable and would hide the bootstrap credential needed to reach a remote
backend. Moving a static secret from a file into another secret store does not
remove the root-secret problem.

## Closed client composition

The client is constructed with exactly one named custody profile. A profile
binds one credential store, one proof-signer store and one external-token
source. Selection is explicit configuration; adapters are never discovered
from ambient provider variables, command availability, desktop detection or a
fallback chain.

Conceptually, the neutral boundaries are:

~~~go
type SessionRecord struct {
    SpecVersion           string
    ParticipantInstanceID string
    SessionEpoch          uint64
    SessionToken          Secret
    IssuedAt              time.Time
    ExpiresAt             time.Time
    ProofKeyReference     string
    ProofJWKThumbprint    [32]byte
}

type CredentialStore interface {
    Load(ctx context.Context, profile string) (StoredSession, error)
    Save(ctx context.Context, profile string, expected Revision,
        record SessionRecord) (Revision, error)
    Delete(ctx context.Context, profile string, expected Revision) error
}

type ProofSignerStore interface {
    ProvisionP256(ctx context.Context, profile string) (ProvisionedSigner, error)
    Open(ctx context.Context, keyReference string) (ProofSigner, error)
    Retire(ctx context.Context, keyReference string) error
}

type ProofSigner interface {
    KeyReference() string
    PublicJWK() PublicP256JWK
    SignES256(ctx context.Context, signingInput []byte) ([64]byte, error)
}

type ExternalTokenSource interface {
    Acquire(ctx context.Context, proofJWK PublicP256JWK) (BoundAccessToken, error)
}
~~~

These are semantic sketches, not accepted Go signatures. The implementation
must use closed values, independent size/time bounds and stable sanitized error
classes. `Secret`, private provider clients, raw environment collections and
generic claim maps do not cross the neutral boundary.

`StoredSession` contains the closed record and one opaque immutable revision.
`Save` and `Delete` are compare-and-set operations against an exact revision,
including an explicit absent revision for first creation. A store without
conditional mutation cannot qualify for a persistent profile. This prevents two
bootstrap attempts from silently replacing the same logical participant
session. Provider revisions are not printed or treated as relay authority.

`ProofSigner` returns the fixed-width JOSE ES256 `R || S` result for the exact
bounded signing input or a closed failure. An adapter that receives a DER ECDSA
signature must validate its canonical positive integers, range and P-256
signature before converting it. The client independently verifies every
returned signature with `PublicJWK` before sending the proof.

The private key is not returned by `ProofSigner`, serialized in `SessionRecord`
or available to command/output code. A local software adapter may necessarily
hold private material transiently inside its signer implementation. A remote
KMS, HSM, TPM or secure-enclave adapter must keep it non-exportable. Both expose
the same public key and signature semantics, not the same custody claim.

`ProvisionedSigner` states whether the operation created a new key or resolved
an already provisioned exact key for that profile. A signer belongs to one
logical participant profile and may survive sequential relay-session renewal.
It is not created blindly for every short-lived relay token. Rotation is an
explicit operation allowed only when no usable session remains bound to the old
thumbprint; inability to prove that condition fails closed.

## Session and signer binding

The credential store persists one versioned session record containing the
opaque relay token, public session identity, exact expiry, proof-key reference
and expected JWK thumbprint. It does not contain private key bytes.

For every request the client:

1. loads and fully validates the session record;
2. opens exactly the referenced signer;
3. derives the RFC 7638 thumbprint from the signer's returned public JWK;
4. constant-time compares it with the stored session thumbprint;
5. creates a fresh bounded proof and verifies the returned signature locally;
6. sends the request only if every step succeeds.

A missing, changed, disabled, destroyed, wrong-algorithm or ambiguous signer
invalidates the session locally. The client never substitutes a newly created
key because the relay session is bound to the original thumbprint.

Credential-store data is untrusted on load. A remote version alias such as
`latest` is not an authoritative signer reference. Records and keys use exact,
immutable provider versions or locally immutable identifiers.

## Bootstrap transaction and partial failure

Bootstrap is an ordered saga across independent systems, not an atomic
transaction:

1. provision or resolve the one exact P-256 signer bound to the selected
   participant profile;
2. acquire an external RFC-9068 token whose `cnf.jkt` binds that public key;
3. call the RFC-0009 relay bootstrap with a proof from that signer;
4. validate the complete relay response;
5. persist one session record referencing the same signer and thumbprint;
6. report success only after an exact load/open/binding verification.

Failure before relay session creation triggers bounded signer cleanup only when
this attempt created the signer and the backend supports provable retirement.
It never retires a pre-existing profile key. Failure or ambiguity after the
relay creates a session but before local persistence never returns success; the
unreachable relay session expires naturally and is not recreated under the same
assumed identity. Cleanup is best effort and auditable, but cleanup uncertainty
cannot turn failure into success.

The first client profile has no public session-revocation endpoint, so the CLI
must not claim immediate remote revocation after a local delete. `session leave`
removes only the exact current session record through revision-checked CAS and
reports only what it can prove. It never retires the participant-profile signer.
Signer rotation or retirement is a separate, explicit profile-lifecycle
operation and is not part of the v1 command surface. Only a newly provisioned
signer belonging to a bootstrap attempt that failed before creating a relay
session is eligible for automatic bounded retirement. Adding relay revocation
requires a separate HTTP contract.

## Root identity and remote-backend authentication

Every remote backend requires an identity established independently of the
secret it protects. Each adapter declares exactly one authentication profile.
The golden path prefers short-lived, externally attested identity:

- interactive user authentication for a user vault;
- workload identity or instance identity for cloud execution;
- OIDC/JWT exchange with bound issuer, audience, subject and workload
  attributes for CI or hosted agents;
- a caller-owned file descriptor or restrictive agent token sink only when an
  external supervisor owns renewal and file lifecycle.

Long-lived service-account keys, client secrets, personal access tokens and
Vault AppRole `secret_id` values are not golden-path bootstrap mechanisms. If a
future adapter permits one for compatibility, its source must be explicit and
must not be the same remote backend whose authentication it unlocks.

Provider default-credential chains are rejected because they commonly inspect
environment variables, local files and multiple metadata sources. An adapter
may use a specifically configured metadata or federation source with exact
audience, endpoint/trust policy and timeout. It may not silently try the next
source after authentication failure.

Backend identity authenticates access to custody; it does not become Yukh
participant identity by implication. The external authorization server remains
responsible for issuing the exact DPoP-bound access token accepted by RFC-0010.
This RFC adds no participant delegation or cross-principal impersonation.

## Backend capability declaration

Each concrete profile must document and qualify at least:

- local, remote or hardware security boundary;
- whether private key material is recoverable by the adapter;
- exact authentication source and token lifetime;
- supported P-256/ES256 input and signature formats;
- record and key version/rotation semantics;
- consistency and ambiguous-write behavior;
- deletion, disablement and residual recovery semantics;
- audit evidence and secret-redaction guarantees;
- network, offline and locked-store failure behavior;
- tenant/project/location and data-residency boundary.

The constructor validates an exact capability profile. Unsupported or changed
capabilities fail closed. There is no runtime fallback from KMS to software,
remote to local, locked to plaintext or one provider to another.

## Candidate profiles, not selections

The following compositions illustrate the boundary and are not authorized
implementations:

### Linux desktop

Freedesktop Secret Service stores the session record and encrypted private-key
material. A local software `ProofSigner` loads the key only while signing. The
login-session D-Bus service and collection must be explicitly selected. A
missing bus, locked collection or prompt requirement is a closed custody
failure, not a headless fallback.

### Google Cloud workload

Google Secret Manager may store the session record and Cloud KMS owns one exact
`EC_SIGN_P256_SHA256` asymmetric key version per logical participant profile,
not one key per short-lived relay session. The adapter obtains short-lived
access through an explicitly configured workload identity or federation
profile. It verifies request/response integrity metadata and the returned KMS
signature before use.

This composition is not selectable until it proves how a restarted client
resolves the exact committed session-record version. Secret Manager's `latest`
or an alias alone is insufficient because immediate access through those names
does not have the same strong-consistency guarantee as access by returned
version number. Adding a separate authoritative pointer store requires its own
atomicity and failure analysis rather than being hidden inside this profile.

### HashiCorp Vault workload

A versioned secret engine stores the session record and Transit or another
qualified signing engine owns the key. Authentication uses one explicit
JWT/OIDC, Kubernetes or supervised agent profile with narrow policy. A static
Vault token in configuration or environment is rejected.

### Vaultwarden user vault

Vaultwarden may be evaluated through the compatible Bitwarden client API for an
interactive user profile. Vault unlock/session handling is part of that
adapter's threat model. It is not presumed to implement Bitwarden Secrets
Manager, and it is not a headless golden path until its root-authentication and
session-custody loop is independently resolved.

### GitHub-hosted execution

GitHub repository, environment, Codespaces and Actions secrets are not a
`CredentialStore` adapter because the CLI cannot generally read back a value
through `gh secret`. GitHub Actions may act as an explicit OIDC identity source
for a remote store/KMS. The resulting cloud token and Yukh session must not be
written back to GitHub Secrets, logs, outputs, caches or artifacts.

## Session isolation

A remote backend does not turn one relay session into shared coordination
memory. Each logical participant profile owns one proof key and at most one
current session record. The key may persist across sequential session renewal,
but separate profiles never share it. Profiles and key references include a
bounded, non-secret scope so separate agents do not accidentally load one
identity.

Using one profile concurrently across hosts makes those processes
cryptographically indistinguishable to the relay. It is forbidden by the golden
paths. Explicit session continuation after process restart may reopen the same
record and signer, but delegation, cloning and transfer between principals
require a future RFC.

## Errors and observability

Exit code `8` is refined to mean credential-custody or proof-signer failure,
whether the selected adapter is local or remote. Exit code `3` remains external
or relay-session authentication unavailable. Provider error bodies, resource
names containing tenant information, tokens, proof bytes, public-key coordinates
and backend identity claims are sanitized to bounded stable diagnostics.

Metrics may identify only the configured adapter class and stable outcome.
Trace attributes never include profile names when they can reveal user,
repository, project, tenant, key or location information.

## Qualification

The neutral refactor must prove with deterministic fakes:

- token records contain a signer reference and thumbprint but no private key;
- absent-create and exact-revision compare-and-set reject concurrent session
  replacement and stale deletion;
- command/output code cannot obtain private key material from the signer port;
- exact JWK/thumbprint binding is checked for every request;
- changed, missing, wrong-curve, wrong-algorithm and destroyed keys fail closed;
- DER-to-JOSE conversion rejects malformed, out-of-range and non-verifying
  signatures;
- every returned signature is locally verified before network use;
- bootstrap partial failures never report a usable session;
- cleanup ambiguity cannot retire a pre-existing signer or create key
  substitution or credential fallback;
- `session leave` deletes only the exact session revision and never retires the
  participant-profile signer;
- sequential session renewal may retain the exact profile key, while concurrent
  profile sharing and implicit rotation are rejected;
- two profiles cannot be tried for one operation;
- provider/default credential discovery and environment-carried secrets are
  absent;
- store, signer and identity-provider errors are bounded and redacted;
- concurrent processes do not implicitly share one participant session.

Every concrete adapter requires separate real-service integration tests,
failure injection and an accepted threat/capability record. Neutral fakes cannot
qualify a provider.

## Compatibility and migration

The accepted HTTP and DPoP wire profiles do not change. Existing sessions can be
migrated only if the original private key is imported into a signer profile that
preserves the exact public key and thumbprint, and the target profile explicitly
supports secure import. Otherwise the old session is deleted locally and a new
bootstrap creates a new signer and relay session.

The current `SessionCredentials` private-key field and combined
`CredentialStore` are foundation code, not a released public API. After
acceptance they are replaced in one reviewed refactor; compatibility wrappers
that expose the key or silently emulate the old store are forbidden.

## Alternatives rejected

- **One generic secret blob:** hides non-exportable signing and permits accidental
  private-key export.
- **Remote secret store alone:** moves rather than solves the root-credential
  problem and cannot represent KMS signing.
- **Automatic best available backend:** makes identity and custody depend on
  ambient machine state and creates silent downgrade paths.
- **GitHub Secrets as the session database:** values are injection-oriented and
  not generally readable through the management CLI; session rotation would
  also couple runtime identity to repository administration.
- **Static service credential as the golden path:** creates a longer-lived and
  often more powerful secret than the short-lived Yukh session it protects.
- **One shared remote session for all agents:** erases participant attribution
  and turns custody into impersonation.
- **Client-side encryption with a local static wrapping key:** can be a defense
  layer but does not eliminate the need to custody the wrapping key.

## References

- [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession](https://www.rfc-editor.org/rfc/rfc9449)
- [Freedesktop Secret Service API](https://specifications.freedesktop.org/secret-service/latest-single/)
- [Google Cloud Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
- [Google Secret Manager access contract](https://cloud.google.com/secret-manager/docs/access-secret-version)
- [Google Cloud KMS asymmetric signing](https://cloud.google.com/kms/docs/create-validate-signatures)
- [HashiCorp Vault JWT/OIDC authentication](https://developer.hashicorp.com/vault/docs/auth/jwt)
- [GitHub Actions OIDC for Google Cloud](https://docs.github.com/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-google-cloud-platform)
- [GitHub CLI secret commands](https://cli.github.com/manual/gh_secret)
- [Vaultwarden compatibility statement](https://github.com/dani-garcia/vaultwarden)
