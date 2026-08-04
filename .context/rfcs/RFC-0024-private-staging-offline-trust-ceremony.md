# RFC-0024: Private staging offline trust and policy ceremony

- Status: Draft
- Authors: Nomed with implementation support
- Created: 2026-08-04
- Governing issue: #147
- Governing architecture: RFC-0022

This proposal resolves an authorization-order ambiguity discovered while
preparing the RFC-0022 operator packet. It changes no accepted behavior until
the project owner explicitly accepts it. Drafting and review authorize no key,
certificate, token, credential, registration, infrastructure or traffic.

## Summary

Split private-staging identity preparation into two independently approved
ceremonies:

1. an offline, no-target trust and policy ceremony that may create the private
   trust root, exact server identity, offline policy-signing identity and
   canonical policy artifacts after its own explicit owner approval;
2. the existing RFC-0022 step-5 provisioning ceremony that may create the
   short-lived token, ephemeral DPoP key and signed registration only when the
   service can proceed immediately to the no-traffic step-6 review.

The pre-step-5 packet binds the trust, server identity, policy key, canonical
registration template and policy digests. The actual signed-registration
digest is necessarily produced during step 5 and is mandatory step-6 evidence
before any live-window approval can be requested.

## Problem

The reconciled RFC-0022 deployment plan requires a signed-registration digest
in the complete packet before step-5 approval. RFC-0022 also requires that the
registration contain the token digest, DPoP public-key thumbprint and a window
of no more than fifteen minutes, while token and DPoP generation remain
forbidden before step 5.

Those requirements cannot simultaneously be met honestly. Generating the
ephemeral credential early makes it expire before provisioning review;
inventing a digest fabricates evidence; silently treating the field as a plan
changes the accepted gate without a record.

## Goals

- make durable trust and policy inputs independently reviewable before any
  target or registry access;
- retain distinct explicit approval for every private-key generation event;
- keep ephemeral workload identity inside the bounded step-5/step-6 interval;
- bind all public evidence through canonical SHA-256 digests without exposing
  private identities or secret material;
- preserve a second independent approval for live synthetic traffic;
- make abort, destruction, rotation and custody outcomes explicit.

## Non-goals

- choosing a production PKI, HSM, KMS or multi-party key ceremony;
- creating or contacting a Kubernetes namespace, registry or workload;
- generating NATS or workload credentials during design review;
- weakening the five-action policy, DPoP, expiry or exact-target rules;
- authorizing provider execution, protected mutation or production use.

## Ceremony A — durable offline trust and policy

Ceremony A requires a new explicit owner approval after review of the complete
execution-forbidden plan. It runs in a volatile, swap-excluded workspace with
network namespace isolation, restrictive umask, verified cryptographic
toolchain and a prevalidated encrypted custody destination.

It creates exactly:

- one private staging trust root and identifier;
- one server leaf key and certificate for the exact private identity held only
  in the private operator record;
- one offline Ed25519 policy-signing key and public key identifier;
- one canonical closed registration template with token digest, DPoP
  thumbprint and issuance window represented as typed unfilled slots;
- one canonical five-action policy document;
- distinct canonical NATS bootstrap and runtime policy documents.

It emits public evidence containing only toolchain identity, algorithms,
canonical artifact digests, public key identifiers, validity bounds and a
closed success or destruction receipt. It emits no endpoint, account, host,
personal identity, private path, certificate body, key, token or credential.

Private keys move directly from volatile memory into distinct encrypted
custody records. Plaintext intermediates never enter disk-backed storage,
clipboard, shell history, logs, command arguments, environment variables or
repository files. Failure destroys every partial output and produces only a
closed failure receipt.

Ceremony A does not create a token, DPoP key, signed registration, capability
keyring or NATS credential and does not contact the selected target.

## Step 5 — ephemeral identity completion

After Ceremony A evidence is bound into the reviewed packet, the existing
step-5 approval may authorize target provisioning and the following bounded
identity completion:

1. generate one uniformly random 256-bit token and one ephemeral P-256 DPoP
   key with the same validity window of at most fifteen minutes;
2. derive only the token digest and public JWK thumbprint;
3. fill the exact canonical registration template, sign it with the offline
   policy key and record the registration digest;
4. deliver token and DPoP private key only through the MCP descriptor boundary;
5. install only the signed public registration on Coordination;
6. collect no-traffic readiness and audit evidence before expiry.

Any inability to reach step-6 review inside the remaining credential window
aborts, revokes/destroys the ephemeral identity and requires a new explicit
step-5 execution decision. Nothing is reused.

## Packet semantics

Before requesting step-5 approval, the packet must contain:

- trust-bundle, server-identity and policy-public-key digests;
- canonical registration-template digest;
- canonical five-action and distinct NATS policy digests;
- exact validity and expiry bounds;
- encrypted-custody and destruction outcomes;
- all other RFC-0022 pre-provisioning fields.

The signed-registration digest has state
`DEFERRED_TO_APPROVED_STEP_5`, not `PASS` or an invented value. Step 5 cannot
complete successfully without producing it, and step 6 cannot pass without
independently verifying it. Step 7 remains forbidden until step 6 passes.

## Roles and custody

The project owner may retain the previously accepted first-staging role
consolidation. The ceremony still has two logical checkpoints separated in
time:

- operator checkpoint: toolchain, inputs, generation and encrypted transfer;
- reviewer checkpoint: reopen public artifacts from custody, independently
  recompute digests and decide `PASS` or `DESTROY`.

One human may perform both checkpoints only by recording the role conflict and
performing a fresh verification process. This is not independent-person
witnessing and remains a staging residual risk.

Root, leaf and policy private keys use distinct custody records and identifiers.
The trust root never signs workload registrations; the policy key never signs
TLS identities. Rotation never changes both authorities without a new packet.

## Qualification and authorization sequence

1. Review and explicitly accept or reject this RFC.
2. Review the exact execution-forbidden Ceremony A runbook.
3. Obtain explicit owner approval for Ceremony A only.
4. Execute offline, review digests and either retain encrypted outputs or
   destroy every output.
5. Complete the pre-step-5 packet with Ceremony A evidence.
6. Obtain the separate RFC-0022 step-5 provisioning approval.
7. Provision and create the ephemeral identity; record signed-registration
   evidence without traffic.
8. Perform step-6 review.
9. Obtain a second explicit approval for the bounded synthetic window.

Acceptance of this RFC would authorize only the later separately reviewed
implementation of the ceremony plan. It would not itself authorize steps 3–9.

## Threats and controls

| Threat | Control |
|---|---|
| fabricated pre-step-5 registration digest | explicit deferred state plus mandatory step-6 digest verification |
| durable plaintext private key | volatile no-swap workspace and direct encrypted-custody transfer |
| cross-use of authorities | distinct root, leaf and policy keys with closed purposes |
| stale ephemeral credential | generation only during approved step 5, <=15-minute window, abort on review delay |
| endpoint substitution | exact private identity from the private record and trust/server digest binding |
| policy broadening | canonical five-action document and separate bootstrap/runtime NATS policy digests |
| hidden network or exfiltration | isolated network namespace and closed tool/input inventory |
| incomplete failure cleanup | fail-closed destruction receipt and rejection of partial success |

Residual risk remains because one owner performs both logical checkpoints and
encrypted custody is software-backed. That risk is acceptable only for this
bounded private staging proof and cannot be inherited by production.

## Compatibility

Public RFC-0015 bytes, DPoP validation, authorization, storage, audit and MCP
consumer contracts do not change. This proposal changes only the order and
evidence semantics of private deployment preparation. Production requires a
separate profile.

## Decision requested

The project owner should explicitly accept or revise the two-ceremony split and
the `DEFERRED_TO_APPROVED_STEP_5` signed-registration state. Silence or approval
of earlier RFC-0022 work is not acceptance of this draft.
