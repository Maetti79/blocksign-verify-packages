const assert = require("node:assert/strict");
const { createHmac } = require("node:crypto");
const { test } = require("node:test");
const contract = require("../../tests/contract.json");
const {
  VerifyClient,
  VerifyWebhookError,
  buildVerificationUrl,
  isCorroborated,
  parseWebhook,
  verifyWebhookSignature,
} = require("../../dist");

const link = "https://verify.blocksign.io/v/example?language=de&uid=old&uid=older";
const uid = contract.verification.uid;

test("verification link encodes the uid and replaces both placeholders", () => {
  const url = new URL(buildVerificationUrl(link, uid));
  assert.deepEqual(url.searchParams.getAll("uid"), [uid]);
  assert.equal(url.searchParams.get("language"), "de");
  assert.throws(() => buildVerificationUrl("https://verify.blocksign.io.example/v/test", uid), TypeError);
  assert.throws(() => buildVerificationUrl(link, " "), TypeError);
});

test("Check sends the configured API key and returns the verification for the requested uid", async () => {
  const client = new VerifyClient({
    apiKey: "example-check-key",
    fetch: async (url, options) => {
      assert.equal(url.origin, "https://verify.blocksign.io");
      assert.equal(url.pathname, "/api/check");
      assert.equal(url.searchParams.get("uid"), uid);
      assert.equal(new Headers(options.headers).get("X-API-Key"), "example-check-key");
      assert.equal(options.redirect, "manual");
      assert.ok(options.signal instanceof AbortSignal);
      return Response.json(contract.verification);
    },
  });

  assert.deepEqual(await client.checkVerification(uid), contract.verification);
  await assert.rejects(new VerifyClient().checkVerification(uid), TypeError);
  const mismatch = new VerifyClient({
    apiKey: "example-check-key",
    fetch: async () => Response.json(contract.verification),
  });
  await assert.rejects(mismatch.checkVerification("another-user"), { name: "VerifyApiError", kind: "response" });
});

test("the server verdict gates corroboration for schema version 2", () => {
  const result = contract.verification;
  assert.equal(isCorroborated(result), true);
  assert.equal(isCorroborated({ ...result, schemaVersion: undefined }), false);
  assert.equal(isCorroborated({ ...result, status: "completed_unverified" }), false);
  assert.equal(isCorroborated({ ...result, verdict: undefined }), false);
  assert.equal(isCorroborated({ ...result, verdict: { server: { corroborated: "true" } } }), false);
  assert.equal(isCorroborated({ ...result, verdict: { server: { corroborated: false } } }), false);
});

test("meeting proof goes to the public endpoint without a key and preserves the meeting binding", async () => {
  const proof = "part+token/=&#";
  const client = new VerifyClient({
    apiKey: "example-check-key",
    fetch: async (url, options) => {
      assert.equal(url.pathname, "/api/proof/verify");
      assert.equal(url.searchParams.get("proof"), proof);
      assert.equal(new Headers(options.headers).has("X-API-Key"), false);
      return Response.json(contract.validProof);
    },
  });
  assert.deepEqual(await client.verifyMeetingProof(proof), contract.validProof);
});

test("proof rejection is a result, including the legacy response for absent proof", async () => {
  for (const reason of ["malformed", "bad_signature", "expired"]) {
    const client = new VerifyClient({ fetch: async () => Response.json({ valid: false, reason }) });
    assert.deepEqual(await client.verifyMeetingProof("dummy"), { valid: false, reason });
  }
  for (const status of [200, 400]) {
    const client = new VerifyClient({
      fetch: async (url) => {
        assert.equal(url.searchParams.has("proof"), false);
        return status === 200
          ? Response.json({ valid: false, reason: "missing" })
          : Response.json({ valid: false, error: "Missing proof query parameter" }, { status });
      },
    });
    assert.deepEqual(await client.verifyMeetingProof(), { valid: false, reason: "missing" });
  }
});

test("HTTP, transport and malformed responses are SDK errors", async () => {
  const failures = [
    [503, Response.json({ valid: false }, { status: 503 }), "http", true],
    [429, new Response(null, { status: 429 }), "http", true],
    [404, new Response(null, { status: 404 }), "http", false],
    [302, new Response(null, { status: 302 }), "http", false],
    [200, new Response("not JSON"), "response", false],
    [200, Response.json({ valid: true }), "response", false],
  ];

  for (const [status, response, kind, retryable] of failures) {
    const client = new VerifyClient({ fetch: async () => response });
    await assert.rejects(client.verifyMeetingProof("dummy"), { name: "VerifyApiError", status, kind, retryable });
  }

  const offline = new VerifyClient({ fetch: async () => { throw new Error("offline"); } });
  await assert.rejects(offline.verifyMeetingProof("dummy"), {
    name: "VerifyApiError", status: null, kind: "transport", retryable: true,
  });
});

test("webhook authentication uses raw bytes and precedes payload parsing", () => {
  const { rawBody, secret, signature } = contract.webhook;
  assert.equal(verifyWebhookSignature(Buffer.from(rawBody), signature, secret), true);
  assert.equal(verifyWebhookSignature(rawBody, signature, ""), false);
  const event = parseWebhook(rawBody, signature, secret);
  assert.equal(event.uid, null);
  assert.equal(isCorroborated(event), true);

  for (const badSignature of [undefined, signature + "\n", "z".repeat(64)]) {
    assert.equal(verifyWebhookSignature(rawBody, badSignature, secret), false);
  }
  assert.throws(() => parseWebhook(rawBody.trim(), signature, secret), VerifyWebhookError);
  const signedInvalid = createHmac("sha256", secret).update("[]").digest("hex");
  assert.throws(() => parseWebhook("[]", signedInvalid, secret), { kind: "payload" });
});
