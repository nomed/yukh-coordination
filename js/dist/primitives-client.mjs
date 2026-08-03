// Generated deterministically by .github/scripts/build-primitives-client.mjs.
function assertScalar(value) {
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new TypeError("canonical JSON does not support non-finite numbers");
  }
  if (typeof value === "string") {
    for (let index = 0; index < value.length; index += 1) {
      const unit = value.charCodeAt(index);
      if (unit >= 0xd800 && unit <= 0xdbff) {
        const next = value.charCodeAt(index + 1);
        if (!(next >= 0xdc00 && next <= 0xdfff)) {
          throw new TypeError("unpaired high surrogate");
        }
        index += 1;
      } else if (unit >= 0xdc00 && unit <= 0xdfff) {
        throw new TypeError("unpaired low surrogate");
      }
    }
  }
}

function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
    assertScalar(value);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (typeof value !== "object") {
    throw new TypeError(`unsupported JSON value: ${typeof value}`);
  }
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${canonicalize(key)}:${canonicalize(value[key])}`).join(",")}}`;
}

// JSON.parse accepts duplicate members. Conformance input must not silently
// collapse them, so this deliberately small parser rejects them at every depth.
function parseJson(text) {
  let offset = 0;
  const fail = (message) => { throw new SyntaxError(`${message} at byte ${Buffer.byteLength(text.slice(0, offset), "utf8")}`); };
  const whitespace = () => { while (/\s/u.test(text[offset] ?? "")) offset += 1; };
  const string = () => {
    const start = offset;
    if (text[offset++] !== '"') fail("expected string");
    let escaped = false;
    while (offset < text.length) {
      const char = text[offset++];
      if (!escaped && char === '"') {
        const value = JSON.parse(text.slice(start, offset));
        assertScalar(value);
        return value;
      }
      if (!escaped && char.charCodeAt(0) < 0x20) fail("control character in string");
      if (!escaped && char === "\\") escaped = true;
      else escaped = false;
    }
    fail("unterminated string");
  };
  const value = () => {
    whitespace();
    const char = text[offset];
    if (char === '"') return string();
    if (char === "{") {
      offset += 1; whitespace();
      const result = {}; const seen = new Set();
      if (text[offset] === "}") { offset += 1; return result; }
      while (true) {
        whitespace(); const key = string();
        if (seen.has(key)) fail(`duplicate member ${JSON.stringify(key)}`);
        seen.add(key); whitespace();
        if (text[offset++] !== ":") fail("expected colon");
        result[key] = value(); whitespace();
        const delimiter = text[offset++];
        if (delimiter === "}") return result;
        if (delimiter !== ",") fail("expected comma or closing brace");
      }
    }
    if (char === "[") {
      offset += 1; whitespace(); const result = [];
      if (text[offset] === "]") { offset += 1; return result; }
      while (true) {
        result.push(value()); whitespace();
        const delimiter = text[offset++];
        if (delimiter === "]") return result;
        if (delimiter !== ",") fail("expected comma or closing bracket");
      }
    }
    const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/u.exec(text.slice(offset));
    if (!match) fail("invalid JSON value");
    offset += match[0].length;
    return JSON.parse(match[0]);
  };
  if (text.charCodeAt(0) === 0xfeff) fail("BOM is forbidden");
  const result = value(); whitespace();
  if (offset !== text.length) fail("trailing content");
  return result;
}

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
    const text = await readBoundedBody(response, 4096);
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

async function readBoundedBody(response, limit) {
  const reader = response?.body?.getReader?.();
  if (!reader) throw stable("invariant_violation");
  const chunks = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
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

export { MEDIA_TYPE };
