# RFC-0024 offline trust and policy ceremony plan

- Status: accepted design plan; execution forbidden
- Recorded: 2026-08-04
- Governing issue: #147
- Accepted architecture: RFC-0024
- Governing deployment profile: RFC-0022

This redacted plan is review material only. It contains no private target,
endpoint, account, personal identity, custody locator, certificate, key, token,
credential or secret path. Exact private inputs belong only in the mode-`0600`
operator record outside the repository.

## Preconditions

Every item must be `PASS` before a ceremony-execution approval may be asked:

| Check | Required evidence | Current state |
|---|---|---|
| RFC-0024 accepted | explicit owner decision and merged accepted record | PASS AFTER MERGE |
| exact private server identity | private record review | PENDING PRIVATE REVIEW |
| volatile workspace | tmpfs, swap excluded and restrictive mount | PENDING EXECUTION REVIEW |
| network isolation | new namespace with loopback down and no inherited sockets | PENDING EXECUTION REVIEW |
| entropy | kernel readiness and closed health outcome | PENDING EXECUTION REVIEW |
| toolchain | exact binaries and SHA-256 digests | PENDING EXECUTION REVIEW |
| encrypted custody | three distinct tested destinations with recovery check | PENDING PRIVATE REVIEW |
| destruction | fixed identifier and dry-run outcome | PENDING EXECUTION REVIEW |

Any pending or failed precondition stops before key generation.

## Closed durable artifacts

Ceremony A may produce only these artifacts after separate approval:

| Artifact | Algorithm / shape | Public evidence |
|---|---|---|
| private staging root | reviewed TLS root algorithm and bounded validity | key ID, algorithm, validity and trust-bundle SHA-256 |
| exact server identity | reviewed leaf algorithm, exact private SAN, bounded validity | identity digest and certificate SHA-256 |
| policy signing identity | Ed25519 | key ID and public-key SHA-256 |
| registration template | canonical JSON with typed unfilled ephemeral slots | template SHA-256 |
| five-action policy | canonical JSON, no wildcard | policy SHA-256 |
| bootstrap NATS policy | canonical, three-bucket bootstrap-only operations | policy SHA-256 |
| runtime NATS policy | canonical, fixed three-bucket runtime operations | policy SHA-256 |

The root, leaf and policy private keys enter distinct encrypted custody records.
The canonical documents contain no credential or private infrastructure value.

## Execution phases

1. **Open:** verify approval identity, tool/input digest inventory, private
   server identity and empty volatile workspace.
2. **Isolate:** enter the reviewed network namespace, prove no route or open
   inherited network descriptor, set restrictive umask and fixed locale/time.
3. **Generate:** create root, leaf and policy identities under distinct
   purposes; write only to the volatile workspace.
4. **Canonicalize:** construct policy documents and registration template with
   the reviewed dependency-free canonicalizer.
5. **Digest:** compute SHA-256 over exact DER/PEM or canonical JSON bytes as
   defined by the private runbook; never digest display text.
6. **Custody:** transfer private artifacts directly into their distinct
   encrypted records; immediately test public reopen/verification without
   displaying private bytes.
7. **Verify:** start a fresh logical reviewer checkpoint and independently
   recompute public digests from custody-reopened public artifacts.
8. **Close:** emit either a complete closed success receipt or destroy all
   outputs and emit one closed failure receipt.

## Fixed abort rules

Abort and destroy on unexpected file, network availability, weak entropy,
digest mismatch, wrong SAN, invalid chain, key-purpose reuse, custody failure,
noncanonical JSON, missing action, wildcard permission, partial output or any
tool output containing a private value.

Failure never keeps a subset of keys, retries generation silently or promotes
an unreviewed digest. A new attempt requires a new execution approval.

## Step-5 deferred artifacts

Ceremony A explicitly does not create:

- opaque workload token or token digest;
- ephemeral P-256 DPoP private key or thumbprint;
- filled or signed registration;
- capability keyring;
- NATS bootstrap/runtime credential;
- Kubernetes Secret or registry credential.

Those values remain behind the separately approved RFC-0022 step-5 runbook.
The signed-registration digest is mandatory step-6 evidence.

## Public receipt

The eventual public receipt is a closed object containing only schema/profile,
accepted source and OCI identities, toolchain digests, artifact-type digests,
public key IDs, validity bounds, checkpoint times, role-conflict acceptance,
outcome and destruction identifier. Unknown fields reject. It contains no
arbitrary error or private locator.

## Authorization boundary

Merging this accepted design plan does not authorize ceremony execution.
Generation requires a complete private execution record and a new explicit
owner approval. Registry, target, namespace, provisioning, workload, listener
and traffic remain outside Ceremony A.
