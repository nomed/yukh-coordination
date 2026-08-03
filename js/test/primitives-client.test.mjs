import assert from "node:assert/strict";
import test from "node:test";
import { LeaseCapability, MEDIA_TYPE, PrimitivesClient } from "../lib/primitives-client.mjs";
import { canonicalize } from "../lib/canonical-json.mjs";

const digest = "a".repeat(64);
const streamed = (chunks) => new ReadableStream({
  start(controller) {
    for (const chunk of chunks) controller.enqueue(typeof chunk === "string" ? new TextEncoder().encode(chunk) : chunk);
    controller.close();
  },
});
const response = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, type: "basic", headers: { get: () => MEDIA_TYPE }, body: streamed([canonicalize(body)]) });

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

test("client bounds the response while streaming before allocation", async () => {
  let cancelled = false;
  const body = new ReadableStream({
    pull(controller) {
      controller.enqueue(new Uint8Array(2049));
    },
    cancel() { cancelled = true; },
  });
  const client = new PrimitivesClient({
    baseUri: "https://coordination.invalid",
    deadlineMs: 1000,
    authenticate: async () => ({ credential: "secret", proof: "a.b.c" }),
    transport: async () => ({ ok: true, status: 200, type: "basic", headers: { get: () => MEDIA_TYPE }, body }),
  });
  await assert.rejects(client.inspect(new LeaseCapability("opaque")), (error) => error.code === "invariant_violation");
  assert.equal(cancelled, true);
});

test("client rejects malformed UTF-8 without exposing response bytes", async () => {
  const client = new PrimitivesClient({
    baseUri: "https://coordination.invalid",
    deadlineMs: 1000,
    authenticate: async () => ({ credential: "secret", proof: "a.b.c" }),
    transport: async () => ({ ok: true, status: 200, type: "basic", headers: { get: () => MEDIA_TYPE }, body: streamed([new Uint8Array([0xff])]) }),
  });
  await assert.rejects(client.inspect(new LeaseCapability("opaque")), (error) => error.code === "invariant_violation" && !error.message.includes("255"));
});
