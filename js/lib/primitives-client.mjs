import { canonicalize, parseJson } from "./canonical-json.mjs";

const MEDIA_TYPE = "application/yukh-coordination-primitives+json;version=1";
const DIGEST = /^[a-f0-9]{64}$/u;

export class LeaseCapability {
  #value;
  constructor(value) {
    if (typeof value !== "string" || value.length === 0 || value.length > 4096) throw new TypeError("invalid capability");
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

  consumeNonce(input) { return this.#call("/coordination-primitives/v1/nonces:consume", closed(input, ["epoch", "expires_at", "scope_digest", "value_digest"])); }
  acquire(input) { return this.#call("/coordination-primitives/v1/leases:acquire", closed(input, ["epoch", "expires_at", "holder_digest", "scope_digest"])); }
  inspect(capability) { return this.#call("/coordination-primitives/v1/leases:inspect", { lease_capability: reveal(capability) }); }
  renew(capability, expiresAt) { return this.#call("/coordination-primitives/v1/leases:renew", { expires_at: expiresAt, lease_capability: reveal(capability) }); }
  release(capability) { return this.#call("/coordination-primitives/v1/leases:release", { lease_capability: reveal(capability) }); }

  async #call(path, body) {
    validateBody(body);
    const target = `${this.#base}${path}`;
    const material = await this.#authenticate({ method: "POST", targetUri: target });
    if (!material || typeof material.credential !== "string" || typeof material.proof !== "string" || material.credential.length === 0 || material.proof.split(".").length !== 3) throw stable("unauthenticated");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#deadline);
    let response;
    try {
      response = await this.#transport(target, { method: "POST", redirect: "manual", signal: controller.signal, headers: { Authorization: `DPoP ${material.credential}`, DPoP: material.proof, "Content-Type": MEDIA_TYPE }, body: canonicalize(body) });
    } catch {
      throw stable("temporarily_unavailable");
    } finally { clearTimeout(timer); }
    if (!response || response.type === "opaqueredirect" || response.status >= 300 && response.status < 400) throw stable("temporarily_unavailable");
    const contentType = response.headers?.get?.("content-type")?.split(";").map((part) => part.trim()).join(";");
    if (contentType !== MEDIA_TYPE) throw stable("invariant_violation");
    const text = await response.text();
    if (Buffer.byteLength(text, "utf8") > 4096) throw stable("invariant_violation");
    let parsed; try { parsed = parseJson(text); } catch { throw stable("invariant_violation"); }
    if (canonicalize(parsed) !== text) throw stable("invariant_violation");
    if (!response.ok) throw stable(typeof parsed.code === "string" ? parsed.code : "temporarily_unavailable");
    if (parsed.specversion !== "1" || typeof parsed.outcome !== "string") throw stable("invariant_violation");
    if (typeof parsed.lease_capability === "string") parsed.lease_capability = new LeaseCapability(parsed.lease_capability);
    return Object.freeze(parsed);
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

export { MEDIA_TYPE };
