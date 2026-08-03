import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { canonicalize, parseJson } from "../lib/canonical-json.mjs";
import { domainDigest, replay, TranscriptError } from "../lib/replay.mjs";

const CHANNEL = "https://coord.example/channels/project-release";
const WORK = "https://example.test/issues/42";
const ids = {
  claimA: "01989f0e-56b7-7001-815e-a7748f7f0001",
  claimB: "01989f0e-56b7-7001-815e-a7748f7f0002",
  eventA: "01989f0e-56b7-7001-815e-a7748f7f0011",
  eventB: "01989f0e-56b7-7001-815e-a7748f7f0012",
  release: "01989f0e-56b7-7001-815e-a7748f7f0013",
  offer: "01989f0e-56b7-7001-815e-a7748f7f0014",
  handoff: "01989f0e-56b7-7001-815e-a7748f7f0015",
  accept: "01989f0e-56b7-7001-815e-a7748f7f0016",
  successor: "01989f0e-56b7-7001-815e-a7748f7f0017",
  acceptAgain: "01989f0e-56b7-7001-815e-a7748f7f0018",
  offerTwo: "01989f0e-56b7-7001-815e-a7748f7f0019",
  handoffTwo: "01989f0e-56b7-7001-815e-a7748f7f001a",
  verify: "01989f0e-56b7-7001-815e-a7748f7f001b",
  instanceA: "01989f0e-56b7-7001-815e-a7748f7f0101",
  instanceB: "01989f0e-56b7-7001-815e-a7748f7f0102",
};

function event(id, type, data, participant = "session:a", causation) {
  return {
    specversion: "0.1", id, type, channel: CHANNEL, source: "urn:test:client",
    participant: { id: participant, kind: "session" }, work: { uri: WORK },
    time: "2026-08-02T16:00:00.000Z", correlation_id: type === "claim" ? id : ids.eventA,
    ...(causation ? { causation_id: causation } : {}), data, evidence: [], extensions: {},
  };
}

function record(eventValue, sequence, instance = ids.instanceA) {
  const eventDigest = `sha-256:${createHash("sha256").update(canonicalize(eventValue), "utf8").digest("hex")}`;
  return {
    event: eventValue, receipt_verified: true,
    receipt: { event_id: eventValue.id, event_digest: eventDigest, tenant_id: "tenant:example", channel_id: "channel:project-release", channel_uri: CHANNEL, transcript_epoch: 0, sequence, participant_id: eventValue.participant.id, participant_instance_id: instance, append_outcome: "appended", signature_algorithm: "ed25519" },
  };
}

function transcript(records, overrides = {}) {
  return { specversion: "0.1", metadata: { tenant_id: "tenant:example", channel_id: "channel:project-release", channel_uri: CHANNEL }, transcript_epoch: 0, declared_completeness: "complete", origin_sequence: 1, high_water_sequence: records.length, high_water_receipt_verified: true, lifecycle: "active", records, ...overrides };
}

const claimA = () => event(ids.eventA, "claim", { claim_id: ids.claimA, generation: "0", scope: "implementation", boundary: "A", expected_active_claims: [] });
const claimB = () => event(ids.eventB, "claim", { claim_id: ids.claimB, generation: "0", scope: "review", boundary: "B", expected_active_claims: [] }, "session:b");

test("canonical JSON and duplicate-member parsing are deterministic", () => {
  assert.equal(canonicalize({ z: "é", a: [true, 1, null] }), '{"a":[true,1,null],"z":"é"}');
  assert.throws(() => parseJson('{"a":1,"a":2}'), /duplicate member/);
  assert.throws(() => canonicalize("\ud800"), /unpaired/);
});

test("reorders by receipt sequence, deduplicates exact records, and preserves conflict", () => {
  const first = record(claimA(), 1);
  const second = record(claimB(), 2, ids.instanceB);
  const result = replay(transcript([second, first, structuredClone(first)], { high_water_sequence: 2 }), WORK);
  assert.equal(result.projection.state, "conflicting");
  assert.deepEqual(result.projection.contenders, [ids.claimA, ids.claimB]);
  assert.equal(result.projection.diagnostics[0].code, "CLAIM_CONFLICT");
  assert.equal(result.projection.diagnostics[0].sequence, 2);
  assert.equal(result.projection.completeness, "complete");
  assert.equal(result.conformance.transcript_id, "9b00766d-15a7-52a8-b8db-1815edb755dd");
});

test("release resolves a conflict without arrival-time winner election", () => {
  const release = event(ids.release, "release", { claim_id: ids.claimB, generation: "0", parent_claim_event_id: ids.eventB, outcome: "withdrawn" }, "session:b", ids.eventB);
  release.correlation_id = ids.eventB;
  const result = replay(transcript([record(claimA(), 1), record(claimB(), 2, ids.instanceB), record(release, 3, ids.instanceB)]), WORK);
  assert.equal(result.projection.state, "claimed");
  assert.deepEqual(result.projection.contenders, [ids.claimA]);
  assert.deepEqual(result.projection.diagnostics, []);
});

test("valid handoff acceptance remains non-authoritative until successor claim", () => {
  const offer = event(ids.offer, "handoff_offer", { handoff_id: ids.handoff, claim_id: ids.claimA, generation: "0", parent_claim_event_id: ids.eventA, to_participant_instance_id: ids.instanceB, boundary: "A", boundary_digest: `sha-256:${"1".repeat(64)}`, evidence_set_digest: `sha-256:${"2".repeat(64)}`, next_action: "continue", unresolved_risks: [] }, "session:a", ids.eventA);
  const accept = event(ids.accept, "handoff_accept", { handoff_id: ids.handoff, offer_event_id: ids.offer, source_claim_event_id: ids.eventA, claim_id: ids.claimA, generation: "0", boundary_digest: `sha-256:${"1".repeat(64)}`, evidence_set_digest: `sha-256:${"2".repeat(64)}` }, "session:b", ids.offer);
  const before = replay(transcript([record(claimA(), 1), record(offer, 2), record(accept, 3, ids.instanceB)]), WORK);
  assert.equal(before.projection.state, "claimed");
  assert.equal(before.projection.diagnostics[0].code, "HANDOFF_ACCEPTED_UNCLAIMED");
  const successor = event(ids.successor, "claim", { claim_id: ids.claimB, generation: "0", scope: "implementation", boundary: "B", expected_active_claims: [ids.claimA], predecessor_handoff_event: ids.accept }, "session:b", ids.accept);
  const after = replay(transcript([record(claimA(), 1), record(offer, 2), record(accept, 3, ids.instanceB), record(successor, 4, ids.instanceB)]), WORK);
  assert.equal(after.projection.state, "conflicting");
  assert.equal(after.projection.diagnostics.some((item) => item.code === "HANDOFF_ACCEPTED_UNCLAIMED"), false);
});

test("late acceptance is rejected as an impossible admitted event", () => {
  const offerData = { handoff_id: ids.handoff, claim_id: ids.claimA, generation: "0", parent_claim_event_id: ids.eventA, to_participant_instance_id: ids.instanceB, boundary: "A", boundary_digest: `sha-256:${"1".repeat(64)}`, evidence_set_digest: `sha-256:${"2".repeat(64)}`, next_action: "continue", unresolved_risks: [] };
  const offer = event(ids.offer, "handoff_offer", offerData, "session:a", ids.eventA);
  const release = event(ids.release, "release", { claim_id: ids.claimA, generation: "0", parent_claim_event_id: ids.offer, outcome: "withdrawn" }, "session:a", ids.offer);
  const acceptData = { handoff_id: ids.handoff, offer_event_id: ids.offer, source_claim_event_id: ids.eventA, claim_id: ids.claimA, generation: "0", boundary_digest: offerData.boundary_digest, evidence_set_digest: offerData.evidence_set_digest };
  const accept = event(ids.accept, "handoff_accept", acceptData, "session:b", ids.offer);
  assert.throws(() => replay(transcript([record(claimA(), 1), record(offer, 2), record(release, 3), record(accept, 4, ids.instanceB)]), WORK), (error) => error instanceof TranscriptError && error.code === "HANDOFF_PRECONDITION_FAILED");
});

test("a second acceptance cannot overwrite the first", () => {
  const offerData = { handoff_id: ids.handoff, claim_id: ids.claimA, generation: "0", parent_claim_event_id: ids.eventA, to_participant_instance_id: ids.instanceB, boundary: "A", boundary_digest: `sha-256:${"1".repeat(64)}`, evidence_set_digest: `sha-256:${"2".repeat(64)}`, next_action: "continue", unresolved_risks: [] };
  const offer = event(ids.offer, "handoff_offer", offerData, "session:a", ids.eventA);
  const acceptData = { handoff_id: ids.handoff, offer_event_id: ids.offer, source_claim_event_id: ids.eventA, claim_id: ids.claimA, generation: "0", boundary_digest: offerData.boundary_digest, evidence_set_digest: offerData.evidence_set_digest };
  const accept = event(ids.accept, "handoff_accept", acceptData, "session:b", ids.offer);
  const acceptAgain = event(ids.acceptAgain, "handoff_accept", acceptData, "session:b", ids.offer);
  assert.throws(() => replay(transcript([record(claimA(), 1), record(offer, 2), record(accept, 3, ids.instanceB), record(acceptAgain, 4, ids.instanceB)]), WORK), (error) => error.code === "HANDOFF_PRECONDITION_FAILED");
});

test("offers chain from the last lifecycle event and either current offer may be accepted", () => {
  const oneData = { handoff_id: ids.handoff, claim_id: ids.claimA, generation: "0", parent_claim_event_id: ids.eventA, to_participant_instance_id: ids.instanceB, boundary: "A", boundary_digest: `sha-256:${"1".repeat(64)}`, evidence_set_digest: `sha-256:${"2".repeat(64)}`, next_action: "one", unresolved_risks: [] };
  const one = event(ids.offer, "handoff_offer", oneData, "session:a", ids.eventA);
  const twoData = { ...oneData, handoff_id: ids.handoffTwo, parent_claim_event_id: ids.offer, next_action: "two" };
  const two = event(ids.offerTwo, "handoff_offer", twoData, "session:a", ids.offer);
  const offered = replay(transcript([record(claimA(), 1), record(one, 2), record(two, 3)]), WORK);
  assert.equal(offered.projection.state, "handoff_offered");
  assert.deepEqual(offered.projection.handoff_offer_ids, [ids.handoff, ids.handoffTwo].sort());
  const acceptData = { handoff_id: ids.handoff, offer_event_id: ids.offer, source_claim_event_id: ids.eventA, claim_id: ids.claimA, generation: "0", boundary_digest: oneData.boundary_digest, evidence_set_digest: oneData.evidence_set_digest };
  const accept = event(ids.accept, "handoff_accept", acceptData, "session:b", ids.offer);
  const accepted = replay(transcript([record(claimA(), 1), record(one, 2), record(two, 3), record(accept, 4, ids.instanceB)]), WORK);
  assert.equal(accepted.projection.state, "claimed");
  assert.deepEqual(accepted.projection.handoff_offer_ids, []);
  const acceptTwoData = { ...acceptData, handoff_id: ids.handoffTwo, offer_event_id: ids.offerTwo };
  const acceptTwo = event(ids.acceptAgain, "handoff_accept", acceptTwoData, "session:b", ids.offerTwo);
  const acceptedTwo = replay(transcript([record(claimA(), 1), record(one, 2), record(two, 3), record(acceptTwo, 4, ids.instanceB)]), WORK);
  assert.equal(acceptedTwo.projection.diagnostics[0].event_id, ids.acceptAgain);
});

test("evidence verification binds one descriptor and enforces outcome shape", () => {
  const descriptor = { uri: "https://evidence.example/run/1", media_type: "application/json", digest: { algorithm: "sha-256", value: "a".repeat(64) }, declared_size: "12" };
  const parent = claimA(); parent.evidence = [descriptor];
  const data = { referenced_event_id: ids.eventA, descriptor_digest: domainDigest("yukh.evidence-descriptor.v0.1\0", descriptor), uri: descriptor.uri, algorithm: "sha-256", expected_digest: `sha-256:${"a".repeat(64)}`, observed_digest: `sha-256:${"a".repeat(64)}`, outcome: "verified", method: "fixture", verified_at: "2026-08-02T16:00:01.000Z", verifier_policy_version: "v1" };
  const verification = event(ids.verify, "evidence_verification", data, "service:verifier", ids.eventA);
  assert.equal(replay(transcript([record(parent, 1), record(verification, 2)]), WORK).projection.final, true);
  verification.data.uri = "https://evidence.example/wrong";
  assert.throws(() => replay(transcript([record(parent, 1), record(verification, 2)]), WORK), (error) => error.code === "INVALID_PAYLOAD");
});

test("zero or ambiguous evidence descriptor binding is INVALID_REFERENCE", () => {
  const descriptor = { uri: "https://evidence.example/run/1", media_type: "application/json", digest: { algorithm: "sha-256", value: "a".repeat(64) }, declared_size: "12" };
  const data = { referenced_event_id: ids.eventA, descriptor_digest: domainDigest("yukh.evidence-descriptor.v0.1\0", descriptor), uri: descriptor.uri, algorithm: "sha-256", expected_digest: `sha-256:${"a".repeat(64)}`, observed_digest: `sha-256:${"a".repeat(64)}`, outcome: "verified", method: "fixture", verified_at: "2026-08-02T16:00:01.000Z", verifier_policy_version: "v1" };
  const verification = event(ids.verify, "evidence_verification", data, "service:verifier", ids.eventA);
  const absent = claimA();
  assert.throws(() => replay(transcript([record(absent, 1), record(verification, 2)]), WORK), (error) => error.code === "INVALID_REFERENCE");
  const ambiguous = claimA(); ambiguous.evidence = [descriptor, structuredClone(descriptor)];
  assert.throws(() => replay(transcript([record(ambiguous, 1), record(verification, 2)]), WORK), (error) => error.code === "INVALID_REFERENCE");
});

test("admission collisions are distinct from forensic incompleteness", () => {
  const original = record(claimA(), 1);
  const changedEvent = structuredClone(original); changedEvent.event.data.boundary = "changed"; changedEvent.receipt.event_digest = `sha-256:${createHash("sha256").update(canonicalize(changedEvent.event)).digest("hex")}`;
  assert.throws(() => replay(transcript([original, changedEvent], { high_water_sequence: 1 }), WORK), (error) => error.code === "ID_COLLISION");
  const changedReceipt = structuredClone(original); changedReceipt.receipt.participant_instance_id = ids.instanceB;
  assert.throws(() => replay(transcript([original, changedReceipt], { high_water_sequence: 1 }), WORK), (error) => error.code === "INVALID_RECEIPT");
  const other = record(claimB(), 1, ids.instanceB);
  assert.throws(() => replay(transcript([original, other], { high_water_sequence: 1 }), WORK), (error) => error.code === "INVALID_RECEIPT");
  original.receipt_verified = false;
  const forensic = replay(transcript([original]), WORK);
  assert.deepEqual(forensic.conformance.reasons, ["unverified-receipt"]);
  assert.equal(forensic.projection.completeness, "incomplete");
});

test("gaps and non-active lifecycle produce independent diagnostics", () => {
  const result = replay(transcript([record(claimA(), 1)], { high_water_sequence: 2, lifecycle: "redacted" }), WORK);
  assert.deepEqual(result.conformance.reasons, ["non-active-lifecycle", "sequence-gap"]);
  assert.deepEqual(result.projection.diagnostics.map((item) => item.code), ["INCOMPLETE_TRANSCRIPT", "NON_ACTIVE_TRANSCRIPT"]);
});

test("forensic high-water outcomes use the frozen reason vocabulary", () => {
  const beyond = record(claimB(), 2, ids.instanceB);
  const result = replay(transcript([record(claimA(), 1), beyond], { high_water_sequence: 1, high_water_receipt_verified: false }), WORK);
  assert.deepEqual(result.conformance.reasons, ["record-after-high-water", "unverified-high-water"]);
  assert.equal(result.projection.state, "claimed");
  assert.equal(result.projection.final, false);
});

test("non-origin and deleted exports are incomplete with both diagnostics", () => {
  const result = replay(transcript([record(claimA(), 1)], { origin_sequence: 2, lifecycle: "deleted" }), WORK);
  assert.equal(result.projection.completeness, "incomplete");
  assert.equal(result.projection.lifecycle, "deleted");
  assert.equal(result.projection.final, false);
  assert.deepEqual(result.projection.diagnostics.map((item) => item.code), ["INCOMPLETE_TRANSCRIPT", "NON_ACTIVE_TRANSCRIPT"]);
});

test("CLI accepts JSONL and emits canonical output", async () => {
  const directory = await mkdtemp(join(tmpdir(), "yukh-js-replay-"));
  const header = transcript([], { high_water_sequence: 1 }); delete header.records;
  const path = join(directory, "transcript.jsonl");
  await writeFile(path, `${JSON.stringify({ transcript: header })}\n${JSON.stringify(record(claimA(), 1))}\n`);
  const execution = spawnSync(process.execPath, ["js/bin/replay.mjs", "--input", path, "--work", WORK], { cwd: process.cwd(), encoding: "utf8" });
  assert.equal(execution.status, 0, execution.stderr);
  const output = parseJson(execution.stdout);
  assert.equal(output.projection.state, "claimed");
  assert.equal(execution.stdout.trim(), canonicalize(output));
});
