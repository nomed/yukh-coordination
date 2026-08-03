import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, request as httpsRequest } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
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

test("committed Node 24 bundle crosses one contained synthetic HTTPS boundary", async (context) => {
  const directory = mkdtempSync(join(tmpdir(), "yukh-primitives-"));
  context.after(() => rmSync(directory, { force: true, recursive: true }));
  const keyPath = join(directory, "key.pem");
  const certPath = join(directory, "cert.pem");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", keyPath, "-out", certPath], { stdio: "ignore" });
  const certificate = readFileSync(certPath);
  let calls = 0;
  const server = createServer({ cert: certificate, key: readFileSync(keyPath) }, (request, response) => {
    calls += 1;
    assert.equal(request.method, "POST");
    assert.equal(request.url, "/coordination-primitives/v1/leases:acquire");
    response.writeHead(200, { "Content-Type": MEDIA_TYPE });
    response.end('{"expires_at":"2026-08-03T12:00:30.000Z","fencing_token":1,"lease_capability":"opaque","outcome":"acquired","specversion":"1"}');
  });
  await new Promise((resolve, reject) => server.listen(0, "127.0.0.1", resolve).once("error", reject));
  context.after(() => server.close());
  const { port } = server.address();
  const baseUri = `https://127.0.0.1:${port}`;
  const transport = (target, options) => new Promise((resolve, reject) => {
    const parsed = new URL(target);
    if (parsed.hostname !== "127.0.0.1" || parsed.port !== String(port)) return reject(new Error("external network forbidden"));
    const outgoing = httpsRequest(parsed, { ca: certificate, headers: options.headers, method: options.method, signal: options.signal }, (incoming) => resolve({
      ok: incoming.statusCode >= 200 && incoming.statusCode < 300,
      status: incoming.statusCode,
      type: "basic",
      headers: { get: (name) => incoming.headers[name.toLowerCase()] },
      body: Readable.toWeb(incoming),
    }));
    outgoing.once("error", reject);
    outgoing.end(options.body);
  });
  const client = new PrimitivesClient({ baseUri, deadlineMs: 1000, authenticate: async () => ({ credential: "synthetic", proof: "a.b.c" }), transport });
  const digest = "a".repeat(64);
  const result = await client.acquire({ epoch: 1, expires_at: "2026-08-03T12:00:30.000Z", holder_digest: digest, scope_digest: digest });
  assert.equal(result.outcome, "acquired");
  assert.equal(calls, 1);
});
