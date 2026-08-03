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
	const typed = new PrimitivesClient({ baseUri: "https://coordination.invalid", deadlineMs: 1000, authenticate: async () => ({ credential: "secret", proof: "a.b.c" }), transport: async () => { throw new TypeError("provider body secret"); } });
	await assert.rejects(typed.inspect(new LeaseCapability("opaque")), (error) => error.code === "temporarily_unavailable" && !error.message.includes("secret"));
});

test("client rejects ambient configuration and ignores proxy environment", async () => {
  assert.throws(() => new PrimitivesClient({ baseUri: "http://coordination.invalid", deadlineMs: 1000, authenticate() {} }), /invalid base URI/u);
  assert.throws(() => new PrimitivesClient({ baseUri: "https://coordination.invalid", deadlineMs: 5001, authenticate() {} }), /invalid client configuration/u);
  const prior = process.env.HTTPS_PROXY;
  process.env.HTTPS_PROXY = "http://ambient-proxy.invalid";
  try {
    let target;
    const client = new PrimitivesClient({ baseUri: "https://coordination.invalid", deadlineMs: 1000, authenticate: async () => ({ credential: "secret", proof: "a.b.c" }), transport: async (observed) => { target = observed; return response({ outcome: "valid", specversion: "1" }); } });
    await client.inspect(new LeaseCapability("opaque"));
    assert.equal(target, "https://coordination.invalid/coordination-primitives/v1/leases:inspect");
  } finally {
    if (prior === undefined) delete process.env.HTTPS_PROXY; else process.env.HTTPS_PROXY = prior;
  }
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

test("client deadline covers authentication, headers, and streamed response", async () => {
  const never = () => new Promise(() => {});
  let client = new PrimitivesClient({ baseUri: "https://coordination.invalid", deadlineMs: 10, authenticate: never, transport: async () => { throw new Error("must not run"); } });
  await assert.rejects(client.inspect(new LeaseCapability("opaque")), (error) => error.code === "temporarily_unavailable");

  client = new PrimitivesClient({ baseUri: "https://coordination.invalid", deadlineMs: 10, authenticate: async () => ({ credential: "secret", proof: "a.b.c" }), transport: never });
  await assert.rejects(client.inspect(new LeaseCapability("opaque")), (error) => error.code === "temporarily_unavailable");

  const body = new ReadableStream({ pull() {} });
  client = new PrimitivesClient({ baseUri: "https://coordination.invalid", deadlineMs: 10, authenticate: async () => ({ credential: "secret", proof: "a.b.c" }), transport: async () => ({ ok: true, status: 200, type: "basic", headers: { get: () => MEDIA_TYPE }, body }) });
  await assert.rejects(client.inspect(new LeaseCapability("opaque")), (error) => error.code === "temporarily_unavailable");

	const hostileBody = { getReader: () => ({ read: () => new Promise(() => {}), cancel: () => new Promise(() => {}), releaseLock() {} }) };
	client = new PrimitivesClient({ baseUri: "https://coordination.invalid", deadlineMs: 10, authenticate: async () => ({ credential: "secret", proof: "a.b.c" }), transport: async () => ({ ok: true, status: 200, type: "basic", headers: { get: () => MEDIA_TYPE }, body: hostileBody }) });
	await assert.rejects(client.inspect(new LeaseCapability("opaque")), (error) => error.code === "temporarily_unavailable");
});

test("client accepts only closed route-specific success and problem shapes", async () => {
  const make = (result, status = 200) => new PrimitivesClient({ baseUri: "https://coordination.invalid", deadlineMs: 1000, authenticate: async () => ({ credential: "secret", proof: "a.b.c" }), transport: async () => response(result, status) });
  await assert.rejects(make({ outcome: "owner_selected_text", specversion: "1" }).inspect(new LeaseCapability("opaque")), (error) => error.code === "invariant_violation" && !error.message.includes("owner_selected"));
  await assert.rejects(make({ extra: true, outcome: "valid", specversion: "1" }).inspect(new LeaseCapability("opaque")), (error) => error.code === "invariant_violation");
  await assert.rejects(make({ code: "provider body secret", status: 503, title: "provider body secret", type: "urn:yukh:coordination-primitives:problem:provider_body_secret" }, 503).inspect(new LeaseCapability("opaque")), (error) => error.code === "invariant_violation" && !error.message.includes("secret"));
  await assert.rejects(make({ code: "temporarily_unavailable", status: 500, title: "temporarily_unavailable", type: "urn:yukh:coordination-primitives:problem:temporarily_unavailable" }, 503).inspect(new LeaseCapability("opaque")), (error) => error.code === "invariant_violation");
	await assert.rejects(make({ code: "unauthenticated", status: 503, title: "unauthenticated", type: "urn:yukh:coordination-primitives:problem:unauthenticated" }, 503).inspect(new LeaseCapability("opaque")), (error) => error.code === "invariant_violation");
});

test("client rejects capabilities that cannot fit a complete 4 KiB message", async () => {
  assert.throws(() => new LeaseCapability("x".repeat(3801)), /invalid capability/u);
});

test("client bounds authentication material before transport", async () => {
	let calls = 0;
	for (const material of [{ credential: "x".repeat(8193), proof: "a.b.c" }, { credential: "x", proof: `${"a".repeat(8192)}.${"b".repeat(8192)}.c` }]) {
		const client = new PrimitivesClient({ baseUri: "https://coordination.invalid", deadlineMs: 1000, authenticate: async () => material, transport: async () => { calls += 1; } });
		await assert.rejects(client.inspect(new LeaseCapability("opaque")), (error) => error.code === "unauthenticated");
	}
	assert.equal(calls, 0);
});
