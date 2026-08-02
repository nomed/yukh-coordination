import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { canonicalize, parseJson } from "../js/lib/canonical-json.mjs";
import { replay } from "../js/lib/replay.mjs";

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
    receipt: { event_id: eventValue.id, event_digest: eventDigest, tenant_id: "tenant:example", channel_id: "channel:project-release", channel_uri: CHANNEL, transcript_epoch: 0, sequence, participant_id: eventValue.participant.id, participant_instance_id: instance },
  };
}

function transcript(records, overrides = {}) {
  return { tenant_id: "tenant:example", channel_id: "channel:project-release", channel_uri: CHANNEL, transcript_epoch: 0, origin_sequence: 1, high_water_sequence: records.length, high_water_receipt_verified: true, lifecycle: "active", records, ...overrides };
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

test("late and multiple acceptance falsify transcript completeness", () => {
  const offerData = { handoff_id: ids.handoff, claim_id: ids.claimA, generation: "0", parent_claim_event_id: ids.eventA, to_participant_instance_id: ids.instanceB, boundary: "A", boundary_digest: `sha-256:${"1".repeat(64)}`, evidence_set_digest: `sha-256:${"2".repeat(64)}`, next_action: "continue", unresolved_risks: [] };
  const offer = event(ids.offer, "handoff_offer", offerData, "session:a", ids.eventA);
  const release = event(ids.release, "release", { claim_id: ids.claimA, generation: "0", parent_claim_event_id: ids.eventA, outcome: "withdrawn" }, "session:a", ids.eventA);
  const acceptData = { handoff_id: ids.handoff, offer_event_id: ids.offer, source_claim_event_id: ids.eventA, claim_id: ids.claimA, generation: "0", boundary_digest: offerData.boundary_digest, evidence_set_digest: offerData.evidence_set_digest };
  const accept = event(ids.accept, "handoff_accept", acceptData, "session:b", ids.offer);
  const result = replay(transcript([record(claimA(), 1), record(offer, 2), record(release, 3), record(accept, 4, ids.instanceB)]), WORK);
  assert.equal(result.projection.final, false);
  assert.ok(result.conformance.reasons.includes("handoff-precondition-failed"));
  assert.equal(result.projection.diagnostics.at(-1).code, "INCOMPLETE_TRANSCRIPT");
});

test("a second acceptance cannot overwrite the first", () => {
  const offerData = { handoff_id: ids.handoff, claim_id: ids.claimA, generation: "0", parent_claim_event_id: ids.eventA, to_participant_instance_id: ids.instanceB, boundary: "A", boundary_digest: `sha-256:${"1".repeat(64)}`, evidence_set_digest: `sha-256:${"2".repeat(64)}`, next_action: "continue", unresolved_risks: [] };
  const offer = event(ids.offer, "handoff_offer", offerData, "session:a", ids.eventA);
  const acceptData = { handoff_id: ids.handoff, offer_event_id: ids.offer, source_claim_event_id: ids.eventA, claim_id: ids.claimA, generation: "0", boundary_digest: offerData.boundary_digest, evidence_set_digest: offerData.evidence_set_digest };
  const accept = event(ids.accept, "handoff_accept", acceptData, "session:b", ids.offer);
  const acceptAgain = event(ids.acceptAgain, "handoff_accept", acceptData, "session:b", ids.offer);
  const result = replay(transcript([record(claimA(), 1), record(offer, 2), record(accept, 3, ids.instanceB), record(acceptAgain, 4, ids.instanceB)]), WORK);
  assert.equal(result.projection.final, false);
  assert.ok(result.conformance.reasons.includes("handoff-precondition-failed"));
  assert.equal(result.projection.diagnostics.filter((item) => item.code === "HANDOFF_ACCEPTED_UNCLAIMED").length, 1);
});

test("gaps and non-active lifecycle produce independent diagnostics", () => {
  const result = replay(transcript([record(claimA(), 1)], { high_water_sequence: 2, lifecycle: "redacted" }), WORK);
  assert.deepEqual(result.conformance.reasons, ["non-active-lifecycle", "sequence-gap"]);
  assert.deepEqual(result.projection.diagnostics.map((item) => item.code), ["INCOMPLETE_TRANSCRIPT", "NON_ACTIVE_TRANSCRIPT"]);
});

test("CLI accepts JSONL and emits canonical output", async () => {
  const directory = await mkdtemp(join(tmpdir(), "yukh-js-replay-"));
  const header = transcript([], { high_water_sequence: 1 }); delete header.records;
  const path = join(directory, "transcript.jsonl");
  await writeFile(path, `${JSON.stringify({ kind: "transcript", ...header })}\n${JSON.stringify({ kind: "record", ...record(claimA(), 1) })}\n`);
  const execution = spawnSync(process.execPath, ["js/bin/replay.mjs", "--input", path, "--work", WORK], { cwd: process.cwd(), encoding: "utf8" });
  assert.equal(execution.status, 0, execution.stderr);
  const output = parseJson(execution.stdout);
  assert.equal(output.projection.state, "claimed");
  assert.equal(execution.stdout.trim(), canonicalize(output));
});
