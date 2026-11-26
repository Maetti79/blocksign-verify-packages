# BlockSign Verify SDKs

Server-side integrations for [BlockSign Verify](https://verify.blocksign.io/). Both packages can build verification links, retrieve results by UID, authenticate webhooks, and validate CallShield meeting proofs.

| Package | Runtime | Package name |
| --- | --- | --- |
| TypeScript | Node.js 22+ | `@blocksign/verify` |
| PHP | PHP 8.2+ with cURL | `blocksign/verify` |

## Install from GitHub

For Node.js, npm builds the SDK from source during installation. The package includes TypeScript declarations and works with ES module imports or CommonJS `require`.

```sh
npm install git+https://github.com/Maetti79/blocksign-verify-packages.git#main
```

For PHP, add the VCS repository and install with Composer.

```sh
composer config repositories.blocksign-verify vcs https://github.com/Maetti79/blocksign-verify-packages.git
composer require blocksign/verify:dev-main
```

Set `BLOCKSIGN_VERIFY_LINK` to the current static verification link from **Integration** in the Verify dashboard. Keep `BLOCKSIGN_VERIFY_API_KEY` and `BLOCKSIGN_VERIFY_WEBHOOK_SECRET` in your backend configuration.

## 1. Redirect and check the result

Generate an opaque UID for each onboarding attempt. Store it with the authenticated user or pending onboarding session and set the success and failure redirect URLs in your Verify settings. Use the stored UID to look up the result and compare it with the UID returned by the redirect. Both redirect URLs are navigation signals. Grant access only after your backend checks the result.

### TypeScript

```ts
import {
  VerifyClient,
  buildVerificationUrl,
  isCorroborated,
} from "@blocksign/verify";

const verificationLink = process.env.BLOCKSIGN_VERIFY_LINK!;
const client = new VerifyClient({ apiKey: process.env.BLOCKSIGN_VERIFY_API_KEY });

export function onboardingUrl(storedUid: string): string {
  return buildVerificationUrl(verificationLink, storedUid);
}

export async function confirmOnboarding(storedUid: string, redirectUid: string): Promise<boolean> {
  if (redirectUid !== storedUid) return false;
  return isCorroborated(await client.checkVerification(storedUid));
}
```

### PHP

```php
use BlockSign\Verify\VerifyClient;

$client = new VerifyClient(apiKey: getenv('BLOCKSIGN_VERIFY_API_KEY') ?: null);

// Use this URL in the initial signup route.
$url = VerifyClient::buildVerificationUrl((string) getenv('BLOCKSIGN_VERIFY_LINK'), $storedUid);

// In the redirect handler, load $storedUid from the current onboarding session.
$allow = $redirectUid === $storedUid
    && VerifyClient::isCorroborated($client->checkVerification($storedUid));
```

Both SDKs require `schemaVersion === 2`, `status === "completed"`, and `verdict.server.corroborated === true` for this decision. A response with `completed_unverified` or a legacy response without the server verdict fails the check. Fields such as `isHuman`, `livenessScore`, `faceMatch`, and `18years` are device reports. Server corroboration means that submitted measurements cleared the server's threshold. It does not attest to their origin or establish document authenticity, identity, or age.

## 2. Receive signed webhooks

Set the webhook URL and a signing secret in Verify settings. Pass the exact request bytes and the `X-BlockSign-Signature` header to the SDK. The signature is a hex HMAC-SHA256 digest of the body using the configured webhook secret. Verify can retry deliveries, so use `sessionId` as an idempotency key within the webhook configuration and acknowledge deliveries you already processed.

### TypeScript with a Fetch API request

```ts
import { isCorroborated, parseWebhook } from "@blocksign/verify";

export async function readVerificationWebhook(request: Request) {
  const event = parseWebhook(
    new Uint8Array(await request.arrayBuffer()),
    request.headers.get("X-BlockSign-Signature"),
    process.env.BLOCKSIGN_VERIFY_WEBHOOK_SECRET!,
  );
  return { event, corroborated: isCorroborated(event) };
}
```

### PHP

```php
use BlockSign\Verify\VerifyClient;
use BlockSign\Verify\Webhook;

$event = Webhook::parse(
    (string) file_get_contents('php://input'),
    $_SERVER['HTTP_X_BLOCKSIGN_SIGNATURE'] ?? null,
    (string) getenv('BLOCKSIGN_VERIFY_WEBHOOK_SECRET'),
);
$corroborated = VerifyClient::isCorroborated($event);
```

A bad or missing signature throws `VerifyWebhookError` with `kind = "signature"`. A successfully signed body with an invalid event envelope throws the same error type with `kind = "payload"`. Catch these in your request handler and reject the delivery before updating your application. The UID can be `null` for sessions created outside a static onboarding link.

## 3. Validate a CallShield meeting proof

The proof endpoint is public. For access to a particular meeting, check `valid`, `human`, and the expected meeting channel and identifier. If access requires a proof from a particular Verify workspace, also compare the returned `orgId` with your expected organization ID.

```ts
const proofResult = await new VerifyClient().verifyMeetingProof(proof);
const allowMeeting = proofResult.valid && proofResult.human &&
  proofResult.meeting.channel === "teams" &&
  proofResult.meeting.meetingId === expectedMeetingId;
```

```php
$proofResult = (new VerifyClient())->verifyMeetingProof($proof);
$allowMeeting = $proofResult['valid'] && $proofResult['human']
    && $proofResult['meeting']['channel'] === 'teams'
    && $proofResult['meeting']['meetingId'] === $expectedMeetingId;
```

An absent, malformed, expired, or incorrectly signed proof returns `valid: false` with a reason. Check the body even when the HTTP status is 200. Transport failures and unsuccessful HTTP responses throw `VerifyApiError`. The error exposes `kind`, `status`, and `retryable`. Retryable errors include network and timeout failures, HTTP 408, 429, and 5xx. The client leaves retry timing to the caller. A missing Check session surfaces as an HTTP 404 error.

## Development

```sh
npm ci
npm test
composer install
composer test
```

Both test suites use shared fixtures for the verification response, HMAC webhook, and meeting proof. This repository contains both packages. They are available directly from GitHub.
