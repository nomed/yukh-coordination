import { createHash } from "node:crypto";
import { canonicalize } from "./canonical-json.mjs";

const TRANSCRIPT_NAMESPACE = "44a2ca5605fd5e2caba3ef07363b75ae";
const WORK_TYPES = new Set(["claim", "progress", "question", "answer", "review_request", "verdict", "handoff_offer", "handoff_accept", "release", "evidence_verification"]);
const ROOT_TYPES = new Set(["claim", "question", "review_request"]);
const CHILD_TYPES = new Set([...WORK_TYPES].filter((kind) => !ROOT_TYPES.has(kind)));
const lexical = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const keyOf = (data) => `${data.claim_id}\0${data.generation}`;

export class TranscriptError extends Error {
  constructor(code, message) { super(message); this.name = "TranscriptError"; this.code = code; }
}

const requireValue = (condition, code, message) => { if (!condition) throw new TranscriptError(code, message); };
export const sha256 = (bytes) => `sha-256:${createHash("sha256").update(bytes).digest("hex")}`;
export const canonicalDigest = (value) => sha256(Buffer.from(canonicalize(value), "utf8"));
export const domainDigest = (prefix, value) => sha256(Buffer.concat([Buffer.from(prefix, "utf8"), Buffer.from(canonicalize(value), "utf8")]));

function uuid5(namespaceHex, name) {
  const hash = createHash("sha1").update(Buffer.concat([Buffer.from(namespaceHex, "hex"), Buffer.from(name, "utf8")])).digest().subarray(0, 16);
  hash[6] = (hash[6] & 0x0f) | 0x50; hash[8] = (hash[8] & 0x3f) | 0x80;
  const hex = hash.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function normalize(input) {
  requireValue(input && typeof input === "object" && !Array.isArray(input), "INVALID_TRANSCRIPT", "transcript must be an object");
  const metadata = input.metadata;
  requireValue(metadata && typeof metadata === "object" && !Array.isArray(metadata), "INVALID_TRANSCRIPT", "metadata must be an object");
  for (const field of ["tenant_id", "channel_id", "channel_uri"]) requireValue(typeof metadata[field] === "string" && metadata[field], "INVALID_TRANSCRIPT", `metadata.${field} required`);
  requireValue(input.specversion === undefined || input.specversion === "0.1", "UNSUPPORTED_VERSION", "unsupported transcript version");
  requireValue(Number.isSafeInteger(input.transcript_epoch) && input.transcript_epoch >= 0, "INVALID_TRANSCRIPT", "invalid transcript_epoch");
  requireValue(input.declared_completeness === "complete" || input.declared_completeness === "incomplete", "INVALID_TRANSCRIPT", "invalid declared_completeness");
  requireValue(["active", "redacted", "deleted"].includes(input.lifecycle), "INVALID_TRANSCRIPT", "invalid lifecycle");
  requireValue(Number.isSafeInteger(input.high_water_sequence) && input.high_water_sequence >= 1, "INVALID_TRANSCRIPT", "invalid high_water_sequence");
  requireValue(Number.isSafeInteger(input.origin_sequence) && input.origin_sequence >= 1, "INVALID_TRANSCRIPT", "invalid origin_sequence");
  requireValue(typeof input.high_water_receipt_verified === "boolean", "INVALID_TRANSCRIPT", "high_water_receipt_verified must be boolean");
  requireValue(Array.isArray(input.records), "INVALID_TRANSCRIPT", "records must be an array");
  return { ...input, ...metadata };
}

function transcriptId(input) {
  return uuid5(TRANSCRIPT_NAMESPACE, `${input.tenant_id}\0${input.channel_uri}\0${input.transcript_epoch}`);
}

function validateRecordBinding(input, event, receipt) {
  requireValue(receipt.event_id === event.id, "INVALID_RECEIPT", "receipt event mismatch");
  requireValue(receipt.event_digest === canonicalDigest(event), "EVENT_DIGEST_MISMATCH", "event digest mismatch");
  requireValue(receipt.tenant_id === input.tenant_id, "CROSS_CHANNEL_REFERENCE", "tenant mismatch");
  requireValue(receipt.channel_id === input.channel_id && receipt.channel_uri === input.channel_uri && event.channel === input.channel_uri, "CROSS_CHANNEL_REFERENCE", "channel mismatch");
  requireValue(receipt.transcript_epoch === input.transcript_epoch, "INVALID_RECEIPT", "transcript epoch mismatch");
  requireValue(receipt.participant_id === event.participant?.id, "INVALID_RECEIPT", "participant label mismatch");
  requireValue(receipt.append_outcome === "appended" && receipt.signature_algorithm === "ed25519", "INVALID_RECEIPT", "invalid admitted receipt");
  requireValue(typeof receipt.participant_instance_id === "string", "INVALID_RECEIPT", "participant instance required");
}

function descriptorDigest(descriptor) {
  return domainDigest("yukh.evidence-descriptor.v0.1\0", descriptor);
}

export function replay(rawInput, workUri) {
  const input = normalize(rawInput);
  const transcriptIdentifier = transcriptId(input);
  const reasons = new Set();
  const byEventId = new Map(); const bySequence = new Map(); const normalized = [];

  for (const [index, record] of input.records.entries()) {
    requireValue(record && typeof record === "object" && record.event && record.receipt && typeof record.receipt_verified === "boolean", "INVALID_TRANSCRIPT", `records[${index}] requires event, receipt, receipt_verified`);
    const eventBytes = canonicalize(record.event); const receiptBytes = canonicalize(record.receipt);
    requireValue(Number.isSafeInteger(record.receipt.sequence) && record.receipt.sequence >= 1, "INVALID_RECEIPT", "invalid sequence");
    normalized.push({ ...record, eventBytes, receiptBytes });
  }
  normalized.sort((left, right) => left.receipt.sequence - right.receipt.sequence || lexical(left.eventBytes, right.eventBytes));

  const records = [];
  for (const record of normalized) {
    const priorEvent = byEventId.get(record.event.id);
    if (priorEvent) {
      requireValue(priorEvent.eventBytes === record.eventBytes, "event-id-collision", `event id collision: ${record.event.id}`);
      requireValue(priorEvent.receiptBytes === record.receiptBytes && priorEvent.receipt_verified === record.receipt_verified, "receipt-mismatch", "exact duplicate event has changed receipt or verification result");
      continue;
    }
    requireValue(!bySequence.has(record.receipt.sequence), "sequence-collision", `sequence reused: ${record.receipt.sequence}`);
    validateRecordBinding(input, record.event, record.receipt);
    byEventId.set(record.event.id, record); bySequence.set(record.receipt.sequence, record); records.push(record);
  }

  let incomplete = input.declared_completeness === "incomplete" || input.origin_sequence !== 1 || !input.high_water_receipt_verified || input.lifecycle !== "active";
  if (!input.high_water_receipt_verified) reasons.add("unverified-high-water");
  if (input.lifecycle !== "active") reasons.add("non-active-lifecycle");
  if (records.some((record) => !record.receipt_verified)) { incomplete = true; reasons.add("unverified-receipt"); }
  for (let sequence = 1; sequence <= input.high_water_sequence; sequence += 1) if (!bySequence.has(sequence)) { incomplete = true; reasons.add("sequence-gap"); }
  if (records.some(({ receipt }) => receipt.sequence > input.high_water_sequence)) { incomplete = true; reasons.add("record-after-high-water"); }

  const claims = new Map(); const usedClaims = new Set(); const offersByEvent = new Map(); const acceptedWithoutSuccessor = new Map();
  const conflictTrigger = new Map(); let claimHistory = false;
  const active = () => [...claims.values()].filter((claim) => claim.active);
  const updateConflict = (sequence) => { if (active().length > 1 && !conflictTrigger.has(workUri)) conflictTrigger.set(workUri, sequence); else if (active().length <= 1) conflictTrigger.delete(workUri); };

  for (const record of records) {
    const { event, receipt } = record; const data = event.data ?? {};
    if (receipt.sequence > input.high_water_sequence) continue;
    if (event.work?.uri !== workUri) continue;
    if (CHILD_TYPES.has(event.type)) {
      const parent = byEventId.get(event.causation_id);
      requireValue(parent && parent.receipt.sequence < receipt.sequence, "UNRESOLVED_CAUSATION", "missing or forward causation");
      requireValue(parent.event.channel === event.channel && parent.event.work?.uri === workUri, "CROSS_CHANNEL_REFERENCE", "causal scope mismatch");
      requireValue(parent.event.correlation_id === event.correlation_id, "INVALID_REFERENCE", "correlation mismatch");
    }
    if (ROOT_TYPES.has(event.type)) requireValue(event.correlation_id === event.id, "INVALID_REFERENCE", "root correlation mismatch");

    if (event.type === "claim") {
      claimHistory = true;
      const key = keyOf(data); requireValue(!usedClaims.has(key), "INVALID_CLAIM_TRANSITION", "claim generation reused");
      if (data.predecessor_handoff_event) {
        requireValue(acceptedWithoutSuccessor.has(data.predecessor_handoff_event) && event.causation_id === data.predecessor_handoff_event, "INVALID_CLAIM_TRANSITION", "invalid predecessor handoff");
        acceptedWithoutSuccessor.delete(data.predecessor_handoff_event);
      }
      requireValue(active().length < 32, "RESOURCE_LIMIT", "active claim limit");
      claims.set(key, { claimId: data.claim_id, generation: data.generation, eventId: event.id, active: true, lastLifecycleEvent: event.id, offers: new Map() });
      usedClaims.add(key); updateConflict(receipt.sequence);
    } else if (["progress", "release", "handoff_offer"].includes(event.type)) {
      const claim = claims.get(keyOf(data));
      const transitionCode = event.type === "handoff_offer" ? "invalid-handoff-offer" : "INVALID_CLAIM_TRANSITION";
      requireValue(claim && claim.active, transitionCode, "unknown or inactive claim");
      requireValue(data.parent_claim_event_id === claim.lastLifecycleEvent && event.causation_id === claim.lastLifecycleEvent, transitionCode, "claim lifecycle parent mismatch");
      if (event.type === "progress") claim.lastLifecycleEvent = event.id;
      if (event.type === "release") { claim.active = false; claim.lastLifecycleEvent = event.id; claim.offers.clear(); updateConflict(receipt.sequence); }
      if (event.type === "handoff_offer") {
        requireValue(claim.offers.size < 32, "RESOURCE_LIMIT", "active handoff offer limit");
        const offer = { event, receipt, claim, accepted: false };
        claim.offers.set(event.id, offer); offersByEvent.set(event.id, offer); claim.lastLifecycleEvent = event.id;
      }
    } else if (event.type === "handoff_accept") {
      const offer = offersByEvent.get(data.offer_event_id); requireValue(offer, "handoff-precondition-failed", "unknown handoff offer");
      const offerData = offer.event.data; const claim = offer.claim;
      requireValue(claim.active && !offer.accepted && claim.offers.has(data.offer_event_id), "handoff-precondition-failed", "handoff is not current");
      requireValue(receipt.participant_instance_id === offerData.to_participant_instance_id, "handoff-precondition-failed", "wrong handoff recipient");
      requireValue(data.handoff_id === offerData.handoff_id && data.claim_id === claim.claimId && data.generation === claim.generation && data.source_claim_event_id === claim.eventId && data.boundary_digest === offerData.boundary_digest && data.evidence_set_digest === offerData.evidence_set_digest, "handoff-precondition-failed", "handoff binding changed");
      offer.accepted = true; claim.offers.clear(); claim.lastLifecycleEvent = event.id;
      acceptedWithoutSuccessor.set(event.id, { claimId: claim.claimId, sequence: receipt.sequence });
    } else if (["answer", "verdict", "evidence_verification"].includes(event.type)) {
      const parentField = event.type === "answer" ? "question_event_id" : event.type === "verdict" ? "review_event_id" : "referenced_event_id";
      requireValue(data[parentField] === event.causation_id, "INVALID_REFERENCE", `${parentField} must equal causation`);
      const parent = byEventId.get(data[parentField]); requireValue(parent, "INVALID_REFERENCE", "referenced event missing");
      if (event.type === "answer") requireValue(parent.event.type === "question", "INVALID_REFERENCE", "answer parent is not question");
      if (event.type === "verdict") requireValue(parent.event.type === "review_request", "INVALID_REFERENCE", "verdict parent is not review request");
      if (event.type === "evidence_verification") {
        requireValue(["verified", "mismatch", "unavailable", "unauthorized", "inconclusive"].includes(data.outcome), "evidence-binding-failed", "invalid evidence outcome");
        if (["verified", "mismatch"].includes(data.outcome)) requireValue(typeof data.observed_digest === "string" && data.reason === undefined, "evidence-binding-failed", "observed digest required and reason forbidden");
        else requireValue(typeof data.reason === "string" && data.observed_digest === undefined, "evidence-binding-failed", "reason required and observed digest forbidden");
        const matches = (parent.event.evidence ?? []).filter((descriptor) => descriptorDigest(descriptor) === data.descriptor_digest);
        requireValue(matches.length === 1, "evidence-binding-failed", "descriptor binding missing or ambiguous");
        const descriptor = matches[0];
        requireValue(data.uri === descriptor.uri && data.algorithm === descriptor.digest?.algorithm && data.expected_digest === `sha-256:${descriptor.digest?.value ?? ""}`, "evidence-binding-failed", "descriptor fields differ");
      }
    }
  }

  const contenders = active().sort((a, b) => lexical(a.claimId, b.claimId));
  let state = !claimHistory ? "unclaimed" : contenders.length === 0 ? "released" : contenders.length > 1 ? "conflicting" : "claimed";
  let handoffIds = [];
  if (contenders.length === 1) {
    handoffIds = [...contenders[0].offers.values()].map((offer) => offer.event.data.handoff_id).sort(lexical);
    if (handoffIds.length) state = "handoff_offered";
  }
  const diagnostics = [];
  if (state === "conflicting") {
    const eventIds = contenders.map((claim) => claim.eventId).sort(lexical);
    diagnostics.push({ sequence: conflictTrigger.get(workUri), code: "CLAIM_CONFLICT", severity: "warning", primary_id: eventIds[0], contender_ids: contenders.map((claim) => claim.claimId), contender_event_ids: eventIds });
    handoffIds = [];
  }
  for (const [eventId, accepted] of acceptedWithoutSuccessor) diagnostics.push({ sequence: accepted.sequence, code: "HANDOFF_ACCEPTED_UNCLAIMED", severity: "warning", primary_id: eventId, event_id: eventId, claim_id: accepted.claimId });
  const completeness = incomplete ? "incomplete" : "complete";
  if (incomplete) diagnostics.push({ sequence: input.high_water_sequence, code: "INCOMPLETE_TRANSCRIPT", severity: "error", primary_id: transcriptIdentifier });
  if (input.lifecycle !== "active") diagnostics.push({ sequence: input.high_water_sequence, code: "NON_ACTIVE_TRANSCRIPT", severity: "error", primary_id: transcriptIdentifier });
  diagnostics.sort((a, b) => a.sequence - b.sequence || lexical(a.code, b.code) || lexical(a.primary_id, b.primary_id));
  const projection = { specversion: "0.1", channel_id: input.channel_id, work_uri: workUri, state, contenders: contenders.map((claim) => claim.claimId), handoff_offer_ids: handoffIds, diagnostics, diagnostics_high_water_sequence: input.high_water_sequence, as_of_sequence: input.high_water_sequence, completeness, lifecycle: input.lifecycle, final: completeness === "complete" && input.lifecycle === "active" };
  return { projection, conformance: { transcript_id: transcriptIdentifier, reasons: [...reasons].sort(lexical), projection_digest: canonicalDigest(projection) } };
}

export function canonicalProjection(result) { return canonicalize(result.projection); }
