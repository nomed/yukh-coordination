import { createHash } from "node:crypto";
import { canonicalize } from "./canonical-json.mjs";

const TRANSCRIPT_NAMESPACE = "44a2ca5605fd5e2caba3ef07363b75ae";
const lexical = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const digest = (value) => `sha-256:${createHash("sha256").update(canonicalize(value), "utf8").digest("hex")}`;
const keyOf = (data) => `${data.claim_id}\0${data.generation}`;

function uuid5(namespaceHex, name) {
  const bytes = Buffer.concat([Buffer.from(namespaceHex, "hex"), Buffer.from(name, "utf8")]);
  const hash = createHash("sha1").update(bytes).digest().subarray(0, 16);
  hash[6] = (hash[6] & 0x0f) | 0x50;
  hash[8] = (hash[8] & 0x3f) | 0x80;
  const hex = hash.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function transcriptId(meta) {
  return uuid5(TRANSCRIPT_NAMESPACE, `${meta.tenant_id}\0${meta.channel_uri}\0${meta.transcript_epoch}`);
}

function normalize(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new TypeError("transcript must be an object");
  if (!Array.isArray(input.records)) throw new TypeError("transcript.records must be an array");
  return {
    tenant_id: input.tenant_id,
    channel_id: input.channel_id,
    channel_uri: input.channel_uri,
    transcript_epoch: input.transcript_epoch,
    origin_sequence: input.origin_sequence ?? 1,
    high_water_sequence: input.high_water_sequence,
    high_water_receipt_verified: input.high_water_receipt_verified === true,
    lifecycle: input.lifecycle ?? "active",
    records: input.records,
  };
}

export function replay(rawInput, workUri) {
  const input = normalize(rawInput);
  const transcriptIdentifier = transcriptId(input);
  const reasons = new Set();
  const bySequence = new Map();
  const byEventId = new Map();

  for (const record of input.records) {
    const { event, receipt } = record ?? {};
    if (!event || !receipt) { reasons.add("invalid-record"); continue; }
    let canonicalEvent;
    try { canonicalEvent = canonicalize(event); } catch { reasons.add("invalid-event-json"); continue; }
    const eventDigest = `sha-256:${createHash("sha256").update(canonicalEvent, "utf8").digest("hex")}`;
    if (receipt.event_id !== event.id || receipt.event_digest !== eventDigest) reasons.add("event-digest-mismatch");
    if (receipt.tenant_id !== input.tenant_id || receipt.channel_id !== input.channel_id || receipt.channel_uri !== input.channel_uri || event.channel !== input.channel_uri || receipt.transcript_epoch !== input.transcript_epoch) reasons.add("transcript-binding-mismatch");
    if (receipt.participant_id !== event.participant?.id) reasons.add("participant-binding-mismatch");
    if (record.receipt_verified !== true) reasons.add("unverified-receipt");
    const priorEvent = byEventId.get(event.id);
    if (priorEvent && priorEvent !== canonicalEvent) reasons.add("event-id-collision");
    else byEventId.set(event.id, canonicalEvent);
    const priorSequence = bySequence.get(receipt.sequence);
    if (priorSequence) {
      if (priorSequence.canonicalEvent !== canonicalEvent || canonicalize(priorSequence.receipt) !== canonicalize(receipt)) reasons.add("sequence-collision");
      continue;
    }
    bySequence.set(receipt.sequence, { event, receipt, canonicalEvent });
  }

  const records = [...bySequence.values()].sort((a, b) => a.receipt.sequence - b.receipt.sequence);
  const asOf = input.high_water_sequence ?? (records.at(-1)?.receipt.sequence ?? 1);
  if (input.origin_sequence !== 1) reasons.add("missing-origin");
  if (!input.high_water_receipt_verified) reasons.add("unverified-high-water");
  if (!Number.isSafeInteger(asOf) || asOf < 1) reasons.add("invalid-high-water");
  for (let sequence = 1; sequence <= asOf; sequence += 1) if (!bySequence.has(sequence)) reasons.add("sequence-gap");
  if (records.some(({ receipt }) => receipt.sequence > asOf)) reasons.add("record-after-high-water");
  if (input.lifecycle !== "active") reasons.add("non-active-lifecycle");

  const accepted = new Map(records.map((record) => [record.event.id, record]));
  const claims = new Map();
  const offers = new Map();
  const acceptedHandoffs = new Map();
  const successorAcceptances = new Set();
  let conflictTrigger = null;
  let previousActiveCount = 0;

  for (const record of records) {
    if (record.receipt.sequence > asOf) continue;
    const { event, receipt } = record;
    const data = event.data ?? {};
    if (event.work?.uri !== workUri) continue;
    const causalRecord = event.causation_id ? accepted.get(event.causation_id) : undefined;
    if (event.causation_id && (!causalRecord || causalRecord.receipt.sequence >= receipt.sequence)) reasons.add("unresolved-causation");
    if (event.type === "claim") {
      const key = keyOf(data);
      if (claims.has(key)) reasons.add("reused-claim-generation");
      else {
        claims.set(key, { claimId: data.claim_id, generation: data.generation, eventId: event.id, active: true, sequence: receipt.sequence });
        if (data.predecessor_handoff_event) {
          const predecessor = acceptedHandoffs.get(data.predecessor_handoff_event);
          if (!predecessor || predecessor.receipt.sequence >= receipt.sequence) reasons.add("invalid-predecessor-handoff");
          else successorAcceptances.add(data.predecessor_handoff_event);
        }
      }
    } else if (event.type === "release") {
      const claim = claims.get(keyOf(data));
      if (!claim || !claim.active || data.parent_claim_event_id !== claim.eventId || event.causation_id !== claim.eventId) reasons.add("invalid-release");
      else claim.active = false;
    } else if (event.type === "handoff_offer") {
      const claim = claims.get(keyOf(data));
      if (!claim || !claim.active || data.parent_claim_event_id !== claim.eventId || event.causation_id !== claim.eventId) reasons.add("invalid-handoff-offer");
      else offers.set(event.id, { event, receipt, claim, current: true, accepted: false });
    } else if (event.type === "handoff_accept") {
      const offer = offers.get(data.offer_event_id);
      const bindingMatches = offer && data.handoff_id === offer.event.data.handoff_id && data.claim_id === offer.event.data.claim_id && data.generation === offer.event.data.generation && data.source_claim_event_id === offer.event.data.parent_claim_event_id && data.boundary_digest === offer.event.data.boundary_digest && data.evidence_set_digest === offer.event.data.evidence_set_digest;
      const participantMatches = offer && receipt.participant_instance_id === offer.event.data.to_participant_instance_id;
      if (!offer || !offer.current || offer.accepted || !offer.claim.active || !bindingMatches || !participantMatches || event.causation_id !== data.offer_event_id) reasons.add("handoff-precondition-failed");
      else {
        offer.accepted = true; offer.current = false;
        acceptedHandoffs.set(event.id, { event, receipt, claim: offer.claim });
      }
    }
    const activeCount = [...claims.values()].filter((claim) => claim.active).length;
    if (previousActiveCount < 2 && activeCount >= 2) conflictTrigger = receipt.sequence;
    if (activeCount < 2) conflictTrigger = null;
    previousActiveCount = activeCount;
  }

  const active = [...claims.values()].filter((claim) => claim.active).sort((a, b) => lexical(a.claimId, b.claimId));
  let state = claims.size === 0 ? "unclaimed" : active.length === 0 ? "released" : active.length > 1 ? "conflicting" : "claimed";
  let currentOffers = [];
  if (active.length === 1) {
    currentOffers = [...offers.values()].filter((offer) => offer.current && offer.claim === active[0]).map((offer) => offer.event.data.handoff_id).sort(lexical);
    if (currentOffers.length) state = "handoff_offered";
  }
  const diagnostics = [];
  if (state === "conflicting") {
    const contenderEventIds = active.map((claim) => claim.eventId).sort(lexical);
    diagnostics.push({ sequence: conflictTrigger, code: "CLAIM_CONFLICT", severity: "warning", primary_id: contenderEventIds[0], contender_ids: active.map((claim) => claim.claimId).sort(lexical), contender_event_ids: contenderEventIds });
  }
  for (const [acceptanceId, handoff] of acceptedHandoffs) {
    if (!successorAcceptances.has(acceptanceId)) diagnostics.push({ sequence: handoff.receipt.sequence, code: "HANDOFF_ACCEPTED_UNCLAIMED", severity: "warning", primary_id: acceptanceId, event_id: acceptanceId, claim_id: handoff.claim.claimId });
  }
  const completeness = reasons.size === 0 ? "complete" : "incomplete";
  if (completeness === "incomplete") diagnostics.push({ sequence: asOf, code: "INCOMPLETE_TRANSCRIPT", severity: "error", primary_id: transcriptIdentifier });
  if (input.lifecycle !== "active") diagnostics.push({ sequence: asOf, code: "NON_ACTIVE_TRANSCRIPT", severity: "error", primary_id: transcriptIdentifier });
  diagnostics.sort((a, b) => a.sequence - b.sequence || lexical(a.code, b.code) || lexical(a.primary_id, b.primary_id));
  const projection = {
      specversion: "0.1", channel_id: input.channel_id, work_uri: workUri, state,
      contenders: active.map((claim) => claim.claimId).sort(lexical), handoff_offer_ids: state === "conflicting" ? [] : currentOffers,
      diagnostics, diagnostics_high_water_sequence: asOf, as_of_sequence: asOf,
      completeness, lifecycle: input.lifecycle, final: completeness === "complete" && input.lifecycle === "active",
  };
  return { projection, conformance: { transcript_id: transcriptIdentifier, reasons: [...reasons].sort(lexical), projection_digest: digest(projection) } };
}

export function canonicalProjection(result) {
  return canonicalize(result.projection);
}
