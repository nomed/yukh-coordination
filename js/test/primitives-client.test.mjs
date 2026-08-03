import assert from "node:assert/strict";
import test from "node:test";
import { LeaseCapability, MEDIA_TYPE, PrimitivesClient } from "../lib/primitives-client.mjs";
import { canonicalize } from "../lib/canonical-json.mjs";

const digest = "a".repeat(64);
const response = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, type: "basic", headers: { get: () => MEDIA_TYPE }, text: async () => canonicalize(body) });

test("client performs one canonical no-redirect request", async () => {
  const calls = [];
  const client = new PrimitivesClient({ baseUri: "https://coordination.invalid", deadlineMs: 1000, authenticate: async (request) => ({ credential: "secret", proof: "a.b.c", request }), transport: async (...args) => { calls.push(args); return response({ outcome: "acquired", specversion: "1", lease_capability: "opaque", fencing_token: 1, expires_at: "2026-08-03T12:00:30.000Z" }); } });
  const result = await client.acquire({ epoch: 1, expires_at: "2026-08-03T12:00:30.000Z", holder_digest: digest, scope_digest: digest });
  assert.equal(calls.length, 1);
  assert.equal(calls[0][1].redirect, "manual");
  assert.equal(calls[0][1].body, `{"epoch":1,"expires_at":"2026-08-03T12:00:30.000Z","holder_digest":"${digest}","scope_digest":"${digest}"}`);
  assert.equal(result.lease_capability.toString(), "LeaseCapability{REDACTED}");
  assert.throws(() => JSON.stringify(result.lease_capability), /not serializable/u);
});

test("client does not retry transport failure or redirect", async () => {
  let calls = 0;
  const client = new PrimitivesClient({ baseUri: "https://coordination.invalid", deadlineMs: 1000, authenticate: async () => ({ credential: "secret", proof: "a.b.c" }), transport: async () => { calls += 1; throw new Error("provider body secret"); } });
  await assert.rejects(client.inspect(new LeaseCapability("opaque")), (error) => error.code === "temporarily_unavailable" && !error.message.includes("secret"));
  assert.equal(calls, 1);
});

test("client rejects ambient or malformed configuration", () => {
  assert.throws(() => new PrimitivesClient({ baseUri: "http://coordination.invalid", deadlineMs: 1000, authenticate() {} }), /invalid base URI/u);
  assert.throws(() => new PrimitivesClient({ baseUri: "https://coordination.invalid", deadlineMs: 5001, authenticate() {} }), /invalid client configuration/u);
});
