# RFC-0020: Google Cloud workload custody profile

- Status: Accepted
- Authors: Nomed with implementation support
- Created: 2026-08-03
- Governing issue: #77
- Governing architecture: RFC-0014

The project owner explicitly accepted this RFC on 2026-08-03. Acceptance
authorizes only the separately reviewed implementation increments described
below. It does not provision resources, grant IAM access, introduce
credentials, select an external-token source, bootstrap a relay session, wire
commands or authorize deployment.

## Decision requested

Select the first headless server composition for the RFC-0014
`CredentialStore` and `ProofSignerStore` ports. One explicitly configured
Google Cloud Workload Identity Federation principal accesses:

1. one private Cloud Storage object whose immutable object generation is the
   session-record revision;
2. one pre-provisioned, exact Cloud KMS `AES_256_GCM` CryptoKeyVersion that
   encrypts and authenticates the record through `rawEncrypt` and `rawDecrypt`;
3. one pre-provisioned, exact Cloud KMS `EC_SIGN_P256_SHA256`
   CryptoKeyVersion that performs non-exportable DPoP signing.

The profile is named `gcp-workload-v1`. It is a provider-specific adapter
composition inside Yukh Coordination, not a protocol feature or a portable
claim about every cloud provider.

Acceptance authorizes only a separately reviewed implementation increment. It
does not provision Google Cloud resources, grant IAM access, introduce
credentials, select an RFC-0014 `ExternalTokenSource`, bootstrap a relay
session, add CLI configuration, deploy a process, or change a wire contract.

## Why this composition

A persistent RFC-0014 store requires absent-create and exact-revision
compare-and-set. Cloud Storage supplies an immutable generation for each object
version, generation-match preconditions including the special absent value
`0`, atomic individual-object operations, and strong read-after-write and
read-after-delete consistency. One object can therefore be both the encrypted
record and its revision authority.

Google Secret Manager is rejected for this profile. A secret version is useful
for immutable secret material, but selecting a committed current version would
require an alias or a second authoritative pointer. That would reintroduce a
cross-resource saga and an ambiguity window solely to emulate the CAS contract
that Cloud Storage already provides. Secret Manager remains a possible adapter
for a different contract; it is not used as an approximate `CredentialStore`.

Cloud KMS `rawEncrypt` is selected instead of `CryptoKey.encrypt` because the
raw API addresses one exact CryptoKeyVersion. The profile never follows a
movable primary version. The signing API likewise addresses one exact
CryptoKeyVersion. Rotation is consequently an explicit profile replacement,
not an ambient infrastructure change observed halfway through an operation.

## Closed configuration

Construction receives one closed configuration value with all of the
following:

- exact Google Cloud project number, workload identity pool and provider
  resource names;
- exact STS audience and one caller-supplied, typed subject-token source;
- expected immutable external subject and any required immutable mapped
  attributes;
- exact bucket name, location policy and opaque object prefix;
- exact encryption CryptoKeyVersion resource name, required algorithm and
  protection level;
- exact signing CryptoKeyVersion resource name, required algorithm and
  protection level;
- independent connect, request and total-operation deadlines plus bounded
  retry counts;
- maximum plaintext plus AAD size, fixed to at most 8 KiB in v1 so the same
  record bound qualifies for both SOFTWARE and HSM raw encryption, plus an
  independent bound on the complete stored envelope;
- declared bucket versioning, soft-delete, retention and residency posture.

The subject-token source is a typed dependency, not an unrestricted Google
external-account JSON document. It may read only the explicitly selected
supervisor-owned file descriptor, OIDC endpoint or platform metadata endpoint.
It cannot execute a command, inspect arbitrary environment variables, search
well-known files, invoke the Google Cloud CLI, or fall through to another
source. The exact issuer/provider trust policy remains cloud-side; the adapter
pins the expected provider resource, audience, subject and attributes locally
as defense in depth.

Application Default Credentials, service-account JSON keys, client secrets,
refresh-token files and implicit service-account impersonation are forbidden.
The golden path grants the federated principal direct access to the three exact
resources. A deployment that requires service-account impersonation needs a
new profile and threat analysis; it cannot silently enable it here.

WIF exchanges produce short-lived Google access tokens. Tokens remain only in
memory, are refreshed through the same exact source, are never stored in the
session object and are discarded when the profile closes. Authentication
failure never selects another identity source.

## Resource ownership and provisioning boundary

Bucket, object policy, workload identity pool/provider, IAM bindings and both
KMS keys are infrastructure-owned prerequisites. The runtime principal has no
resource-create, key-create, key-version-create, primary-version-update,
disable, destroy, undelete, policy-write or list permission.

`ProvisionP256(profile)` therefore does not create a key. It resolves the exact
configured signing version, validates its name, enabled state, algorithm,
protection level and public key, and returns `created=false`. `Open` accepts
only that exact version reference. `Retire` is unsupported by the runtime
profile and fails closed. Infrastructure rotation must first create a new
named profile and complete the RFC-0014 session-lifecycle procedure; changing
the configured version beneath an existing profile is forbidden.

The encryption version follows the same immutable rule. A disabled, destroyed,
wrong-purpose, wrong-algorithm, wrong-protection-level or differently named
version is custody unavailable, never a reason to use the key's primary
version or a local software fallback.

## Session object and revision contract

One logical Yukh profile maps to exactly one object name:

~~~text
<configured-prefix>/<base64url(sha256("yukh-gcp-profile-v1\x00" || profile))>
~~~

Raw profile names never enter object names, metadata, logs or telemetry. The
bucket and object name are configuration, not discovery inputs. Listing is not
used or permitted.

The live Cloud Storage object is the sole authoritative record. Its immutable
generation, encoded as a bounded opaque RFC-0014 `Revision`, is returned by
`Load` and successful `Save`. ETags, metagenerations, timestamps, object
versions selected by aliases and application sequence counters are not
revisions.

- `Load` retrieves the complete live object and its generation in one bounded
  operation, disables decompressive transformation, validates the provider
  CRC32C over the complete body, decrypts and validates the closed record, and
  returns that exact generation.
- absent `Save` uploads one complete object with `ifGenerationMatch=0`;
- replacement `Save` uploads one complete object with
  `ifGenerationMatch=<expected generation>`;
- `Delete` deletes only with `ifGenerationMatch=<expected generation>`;
- `412 Precondition Failed` is the stable RFC-0014 conflict class;
- reads never request a noncurrent generation and never use a cache.

Every upload supplies the complete-body CRC32C for server-side validation.
Partial and composite uploads are forbidden. A success response is accepted
only when it names the expected bucket/object, returns a nonzero generation and
reports the expected CRC32C. The returned generation is then used for one
exact-generation verification read before `Save` reports success.

Each candidate plaintext contains a random 128-bit operation identifier. If a
write response is lost, the adapter performs a bounded live-object read. It
reports success only when checksum, decryption, closed validation and operation
identifier prove that the candidate is now live; it then returns the observed
generation. A different live candidate is a conflict. Absence or unresolved
provider state after the bounded check is an indeterminate custody failure, not
permission to repeat without the original precondition or overwrite state.

After an ambiguous delete, absence proves the target is no longer live. The
same generation permits a bounded retry with the same precondition. A different
live generation is a conflict and is never deleted. This profile does not
claim multi-object or Cloud-Storage/KMS atomicity; it needs none for a single
encrypted object and pre-provisioned keys.

## Authenticated encryption envelope

The object is one closed, canonical binary envelope with fixed fields and
bounds. It contains only:

- envelope version and algorithm identifiers;
- exact encryption CryptoKeyVersion reference;
- KMS-returned AES-GCM initialization vector, tag length and ciphertext;
- the canonical AAD needed for decryption.

The AAD domain-separates `yukh-gcp-workload-custody-v1` and binds the envelope
version, opaque profile digest, exact bucket/object identity, exact encryption
version, exact signing version and expected RFC 7638 signer thumbprint. The
same canonical bytes and their CRC32C are sent to `rawEncrypt` and
`rawDecrypt`. The session record, including token and operation identifier, is
entirely encrypted.

For every encryption call the adapter supplies plaintext and AAD CRC32C,
requires the corresponding `verified*` fields, checks the returned key-version
name and protection level, and validates ciphertext and IV CRC32C. Decryption
is invoked at the exact version URL, requires the request-verification fields
and expected protection level, validates plaintext CRC32C, and rejects any
AAD, IV, tag, size or plaintext-schema mismatch. CRC32C detects transport
corruption; AES-GCM and the exact AAD provide cryptographic integrity. CRC32C
is never described as an authenticator.

The Cloud Storage generation cannot be included in KMS AAD because Google
assigns it only after encryption and upload. Generation supplies conditional
mutation authority, while AES-GCM supplies content authenticity; the RFC does
not pretend these independent provider operations form one transaction. An
actor authorized both to decrypt and overwrite the object can replay a prior
valid plaintext as a new generation. Preventing a fully authorized custody
principal from doing so requires a separate append-only witness or control
plane and is outside this profile's trust boundary. Expiry and relay-side
session binding still reject unusable replayed sessions.

## Proof signer behavior

At construction and `Open`, the adapter retrieves the exact signing version's
public key, verifies response name, algorithm, protection level and CRC32C,
parses one P-256 SubjectPublicKeyInfo value, derives the closed public JWK and
computes its RFC 7638 thumbprint. It must equal the profile and session-record
thumbprints in constant time.

For `SignES256` the adapter:

1. enforces the RFC-0014 signing-input bound and computes SHA-256 locally;
2. sends only that digest and its CRC32C to `asymmetricSign` on the exact
   `EC_SIGN_P256_SHA256` version;
3. requires `verifiedDigestCrc32c`, the exact response key name and protection
   level, and a matching signature CRC32C;
4. strictly parses the returned ASN.1 DER ECDSA signature, rejects noncanonical,
   negative, zero, oversized or out-of-range integers, and converts it to the
   fixed 64-byte JOSE `R || S` form;
5. verifies the signature locally against the exact public JWK and original
   signing input before returning it.

The private signing key is never exportable through the adapter. Public keys,
coordinates, signatures, digests and thumbprints are not secret, but they are
still excluded from logs and provider-error text under RFC-0014.

## IAM, audit and deployment posture

The federated principal receives only object get/create/overwrite/delete on the
one bounded object prefix, raw encrypt/decrypt on the one encryption key, and
public-key read/sign on the one signing key. Because Google Cloud IAM policy is
normally attached above an individual KMS version, resource selection and
response-name validation additionally constrain each operation to the exact
configured version. The principal receives no bucket listing or administration
and no KMS administration.

The bucket must be private with public access prevention and uniform
bucket-level access. The v1 golden path requires object versioning disabled,
soft-delete retention set to zero, and no object retention hold because relay
session tokens are short-lived custody state, not backup material. A deployment
that retains noncurrent or soft-deleted ciphertext must declare the recovery
window and residual deletion semantics in a new capability profile.

Bucket location and both KMS locations are explicit and reviewed as one
residency policy. The RFC makes no claim that a location string alone satisfies
an organization's legal or regulatory requirements.

Cloud Audit Logs are deployment evidence, not protocol events and not the Yukh
security audit ledger. Operator-visible provider logs must not contain object
bodies, AAD, session records, subject tokens, Google access tokens, DPoP
signatures or public-key coordinates. Provider request identifiers may be kept
only in restricted diagnostics and are never exposed through ordinary CLI
output.

## Failure and threat analysis

The profile fails closed on identity exchange failure, WIF subject/audience or
attribute mismatch, permission denial, timeout, quota exhaustion, KMS or
Storage unavailability, checksum mismatch, ambiguous state after bounded
resolution, wrong resource/version/protection level, malformed ciphertext,
authentication-tag failure, invalid session schema, signer/thumbprint mismatch
or invalid signature.

Stable public classes remain RFC-0014 absence, conflict, invalid credential and
custody unavailable. Google project, pool, provider, bucket, object and KMS
resource names; IAM policy detail; subject claims; endpoints; request IDs; and
raw provider messages are sanitized from returned errors. Retries are bounded,
use only operations safe under the original generation precondition and honor
caller cancellation and total deadlines.

The trusted boundary includes the selected external identity issuer, Google
STS/IAM, Cloud Storage, Cloud KMS, the exact IAM and workload-identity policies,
Google control-plane administrators and the process memory while it holds a
decrypted session record. Compromise of any of these may expose the relay token
or authorize signing. KMS separation prevents Storage-only compromise from
recovering plaintext or producing DPoP proofs; Storage generation CAS prevents
ordinary concurrent clients from silently replacing a record. It does not
protect against a principal legitimately authorized to use both services.

No profile may be described as HSM-backed unless both configured KMS responses
prove the required HSM protection level and deployment evidence covers the
exact resources. SOFTWARE is a distinct accepted capability only when selected
explicitly; the adapter never upgrades or downgrades between them.

## Qualification

An implementation proposal must provide deterministic provider fakes and
bounded integration evidence for at least:

- exact WIF audience/source/subject selection and rejection of ADC, executable
  sources, environment discovery, service-account keys and fallback;
- absent create, exact replacement, stale replacement and stale delete using
  Cloud Storage generations;
- strong-read verification, whole-object CRC32C and no ranged, transformed,
  composite, listed or noncurrent reads;
- lost create/update/delete responses resolved without blind overwrite;
- raw AES-GCM request/response checksums, exact version/AAD/IV/tag validation,
  size limits and authentication failure;
- wrong, disabled, destroyed, substituted, aliased or unexpectedly rotated KMS
  versions failing closed;
- exact P-256 public-key parsing, thumbprint binding, DER-to-JOSE conversion and
  local signature verification;
- zero private-key export and zero secret/provider-detail leakage through
  errors, logs, metrics and traces;
- independent Storage, KMS and identity outage, denial, timeout, quota and
  cancellation paths with bounded retries;
- least-privilege negative tests for list, administration, key lifecycle and
  access outside the selected object and keys;
- declared region, bucket lifecycle and audit configuration evidence.

No live cloud credential, resource name or tenant detail belongs in repository
fixtures or `.context/`. Integration qualification uses an isolated ephemeral
project supplied by the execution environment and publishes only sanitized
evidence.

## Compatibility and rollout

This profile implements existing RFC-0014 ports and changes neither DPoP nor
relay protocols. The existing environment-neutral local-custody foundation and
the proposed Secret Service workstation composition remain separate profiles;
there is no automatic migration or fallback between them.

Rollout is gated in four independently reviewed increments: provider-neutral
test doubles and envelope codecs; Cloud Storage `CredentialStore`; Cloud KMS
`ProofSignerStore` plus raw encryption boundary; then explicit composition and
isolated integration qualification. External-token selection, bootstrap,
command wiring and deployment remain separate even after those increments.

Rollback removes profile selection and IAM grants without rewriting another
profile's data. Disabling or destroying KMS versions before the bound relay
session expires can make custody unrecoverable and therefore requires an
operator-owned lifecycle procedure rather than an application rollback.

## Rejected alternatives

- **Secret Manager plus `latest` or an alias:** movable selection is not an
  exact RFC-0014 revision.
- **Secret Manager plus a pointer object:** creates an unnecessary two-resource
  commit and recovery saga.
- **Cloud Storage plaintext protected only by IAM:** exposes the relay token to
  Storage readers and backups and collapses custody into storage authorization.
- **`CryptoKey.encrypt` on a key's primary version:** observes a movable version
  and permits implicit rotation.
- **Runtime KMS key creation:** expands the workload principal into a key
  administrator and makes bootstrap cleanup a cross-service lifecycle saga.
- **Service-account key file or client secret:** reintroduces the long-lived
  bootstrap secret this server profile is designed to avoid.
- **Application Default Credentials:** discovers ambient identities and may
  silently change source across environments.
- **Automatic local/remote or HSM/software fallback:** changes the custody claim
  after construction.
- **GitHub Actions secrets as the record store:** injection is not a
  revision-checked read/write custody API; GitHub OIDC may instead be the exact
  external subject-token source for WIF.

## Open questions

No architectural question blocks owner review. Exact Google client-library
versions, typed configuration syntax and resource-provisioning examples belong
to the separately authorized implementation and deployment increments.

## References

- [Workload Identity Federation](https://docs.cloud.google.com/iam/docs/workload-identity-federation)
- [Workload Identity Federation best practices](https://docs.cloud.google.com/iam/docs/best-practices-for-using-workload-identity-federation)
- [Cloud Storage consistency](https://docs.cloud.google.com/storage/docs/consistency)
- [Cloud Storage request preconditions](https://docs.cloud.google.com/storage/docs/request-preconditions)
- [Cloud Storage checksum validation](https://docs.cloud.google.com/storage/docs/data-validation)
- [Cloud KMS raw encryption](https://docs.cloud.google.com/kms/docs/raw-encryption)
- [Cloud KMS `rawEncrypt` API](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/rawEncrypt)
- [Cloud KMS `rawDecrypt` API](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/rawDecrypt)
- [Cloud KMS `asymmetricSign` API](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign)
- [Cloud KMS `getPublicKey` API](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/getPublicKey)
- [Cloud KMS key purposes and algorithms](https://docs.cloud.google.com/kms/docs/algorithms)
