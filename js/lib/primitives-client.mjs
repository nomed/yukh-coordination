import { canonicalize, parseJson } from "./canonical-json.mjs";

const MEDIA_TYPE = "application/yukh-coordination-primitives+json;version=1";
const DIGEST = /^[a-f0-9]{64}$/u;
const MAX_MESSAGE_BYTES = 4096;
const MAX_CAPABILITY_CHARS = 3800;
const PROBLEM_CODES = new Set(["unauthenticated", "access_denied", "conflict", "replayed", "stale_fence", "temporarily_unavailable", "invariant_violation", "invalid_request"]);

export class LeaseCapability {
  #value;
  constructor(value) {
    if (typeof value !== "string" || value.length === 0 || value.length > MAX_CAPABILITY_CHARS) throw new TypeError("invalid capability");
    this.#value = value;
    Object.freeze(this);
  }
  revealForRequest() { return this.#value; }
  toString() { return "LeaseCapability{REDACTED}"; }
  toJSON() { throw new TypeError("capability is not serializable"); }
}

export class PrimitivesClient {
  #base; #authenticate; #deadline; #transport;
  constructor({ baseUri, authenticate, deadlineMs, transport = globalThis.fetch }) {
    const parsed = new URL(baseUri);
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== "/" || baseUri.endsWith("/")) throw new TypeError("invalid base URI");
    if (typeof authenticate !== "function" || typeof transport !== "function" || !Number.isInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > 5000) throw new TypeError("invalid client configuration");
    this.#base = baseUri; this.#authenticate = authenticate; this.#deadline = deadlineMs; this.#transport = transport;
  }

  consumeNonce(input) { return this.#call("/coordination-primitives/v1/nonces:consume", closed(input, ["epoch", "expires_at", "scope_digest", "value_digest"]), new Set(["consumed", "replayed"]), false); }
  acquire(input) { return this.#call("/coordination-primitives/v1/leases:acquire", closed(input, ["epoch", "expires_at", "holder_digest", "scope_digest"]), new Set(["acquired"]), true); }
  inspect(capability) { return this.#call("/coordination-primitives/v1/leases:inspect", { lease_capability: reveal(capability) }, new Set(["valid", "expired", "released", "stale"]), false); }
  renew(capability, expiresAt) { return this.#call("/coordination-primitives/v1/leases:renew", { expires_at: expiresAt, lease_capability: reveal(capability) }, new Set(["renewed"]), true); }
  release(capability) { return this.#call("/coordination-primitives/v1/leases:release", { lease_capability: reveal(capability) }, new Set(["released"]), false); }

  async #call(path, body, outcomes, leaseResult) {
    validateBody(body);
    const requestBody = canonicalize(body);
    if (new TextEncoder().encode(requestBody).byteLength > MAX_MESSAGE_BYTES) throw new TypeError("request exceeds message limit");
    const target = `${this.#base}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#deadline);
    try {
      const material = await withAbort(Promise.resolve(this.#authenticate({ method: "POST", targetUri: target })), controller.signal);
      if (!material || typeof material.credential !== "string" || typeof material.proof !== "string" || material.credential.length === 0 || material.proof.split(".").length !== 3) throw stable("unauthenticated");
      const response = await withAbort(Promise.resolve(this.#transport(target, { method: "POST", redirect: "manual", signal: controller.signal, headers: { Authorization: `DPoP ${material.credential}`, DPoP: material.proof, "Content-Type": MEDIA_TYPE }, body: requestBody })), controller.signal);
      if (!response || response.type === "opaqueredirect" || response.status >= 300 && response.status < 400) throw stable("temporarily_unavailable");
      const contentType = response.headers?.get?.("content-type")?.split(";").map((part) => part.trim()).join(";");
      if (contentType !== MEDIA_TYPE) throw stable("invariant_violation");
      const text = await readBoundedBody(response, MAX_MESSAGE_BYTES, controller.signal);
      let parsed; try { parsed = parseJson(text); } catch { throw stable("invariant_violation"); }
      if (canonicalize(parsed) !== text) throw stable("invariant_violation");
      if (!response.ok) {
        if (!validProblem(parsed, response.status)) throw stable("invariant_violation");
        throw stable(parsed.code);
      }
      validateSuccess(parsed, outcomes, leaseResult);
      if (leaseResult) parsed.lease_capability = new LeaseCapability(parsed.lease_capability);
      return Object.freeze(parsed);
    } catch (error) {
      if (PROBLEM_CODES.has(error?.code)) throw error;
      throw stable("temporarily_unavailable");
    } finally {
      clearTimeout(timer);
    }
  }
}

function reveal(value) { if (!(value instanceof LeaseCapability)) throw new TypeError("invalid capability"); return value.revealForRequest(); }
function closed(input, keys) { if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).sort().join("\n") !== [...keys].sort().join("\n")) throw new TypeError("invalid input"); return { ...input }; }
function validateBody(body) {
  for (const [key, value] of Object.entries(body)) {
    if (key.endsWith("_digest") && !DIGEST.test(value)) throw new TypeError("invalid digest");
    if (key === "epoch" && (!Number.isSafeInteger(value) || value < 1)) throw new TypeError("invalid epoch");
    if (key === "expires_at" && !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) throw new TypeError("invalid expiry");
  }
}
function stable(code) { const error = new Error(code); error.code = code; return error; }

async function readBoundedBody(response, limit, signal) {
  const reader = response?.body?.getReader?.();
  if (!reader) throw stable("invariant_violation");
  const chunks = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await withAbort(reader.read(), signal);
      if (done) break;
      if (!(value instanceof Uint8Array)) throw stable("invariant_violation");
      length += value.byteLength;
      if (length > limit) {
        await reader.cancel();
        throw stable("invariant_violation");
      }
      chunks.push(value);
    }
  } catch (error) {
    if (signal.aborted) await reader.cancel().catch(() => {});
    if (error?.code === "invariant_violation") throw error;
    throw stable("temporarily_unavailable");
  } finally {
    reader.releaseLock?.();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw stable("invariant_violation");
  }
}

function exactObject(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join("\n") === [...keys].sort().join("\n");
}
function validProblem(value, status) {
  return exactObject(value, ["code", "status", "title", "type"]) && PROBLEM_CODES.has(value.code) && value.status === status && value.title === value.code && value.type === `urn:yukh:coordination-primitives:problem:${value.code}`;
}
function validateSuccess(value, outcomes, leaseResult) {
  const keys = leaseResult ? ["expires_at", "fencing_token", "lease_capability", "outcome", "specversion"] : ["outcome", "specversion"];
  if (!exactObject(value, keys) || value.specversion !== "1" || !outcomes.has(value.outcome)) throw stable("invariant_violation");
  if (!leaseResult) return;
  if (!Number.isSafeInteger(value.fencing_token) || value.fencing_token < 1 || typeof value.expires_at !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value.expires_at) || typeof value.lease_capability !== "string" || value.lease_capability.length === 0 || value.lease_capability.length > MAX_CAPABILITY_CHARS) throw stable("invariant_violation");
}
function withAbort(promise, signal) {
  if (signal.aborted) return Promise.reject(stable("temporarily_unavailable"));
  return new Promise((resolve, reject) => {
    const abort = () => reject(stable("temporarily_unavailable"));
    signal.addEventListener("abort", abort, { once: true });
    promise.then(
      (value) => { signal.removeEventListener("abort", abort); resolve(value); },
      (error) => { signal.removeEventListener("abort", abort); reject(error); },
    );
  });
}

export { MEDIA_TYPE };
