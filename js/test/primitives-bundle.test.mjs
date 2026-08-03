import assert from "node:assert/strict";
import test from "node:test";
import { MEDIA_TYPE, PrimitivesClient } from "../dist/primitives-client.mjs";

test("committed Node 24 bundle runs only against its injected in-process target", async (context) => {
  const ambientFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error("ambient network forbidden"); };
  context.after(() => { globalThis.fetch = ambientFetch; });
  let calls = 0;
  const target = "https://synthetic.invalid/coordination-primitives/v1/leases:acquire";
  const transport = async (observed, request) => {
    calls += 1;
    assert.equal(observed, target);
    assert.equal(request.redirect, "manual");
    return new Response('{"expires_at":"2026-08-03T12:00:30.000Z","fencing_token":1,"lease_capability":"opaque","outcome":"acquired","specversion":"1"}', {
      status: 200,
      headers: { "Content-Type": MEDIA_TYPE },
    });
  };
  const client = new PrimitivesClient({
    baseUri: "https://synthetic.invalid",
    deadlineMs: 1000,
    authenticate: async ({ method, targetUri }) => {
      assert.equal(method, "POST");
      assert.equal(targetUri, target);
      return { credential: "synthetic", proof: "a.b.c" };
    },
    transport,
  });
  const digest = "a".repeat(64);
  const result = await client.acquire({ epoch: 1, expires_at: "2026-08-03T12:00:30.000Z", holder_digest: digest, scope_digest: digest });
  assert.equal(result.outcome, "acquired");
  assert.equal(calls, 1);
});
