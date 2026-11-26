<?php

declare(strict_types=1);

require dirname(__DIR__, 2) . '/vendor/autoload.php';

use BlockSign\Verify\VerifyApiError;
use BlockSign\Verify\VerifyClient;
use BlockSign\Verify\VerifyWebhookError;
use BlockSign\Verify\Webhook;

function same(mixed $expected, mixed $actual): void
{
    if ($expected !== $actual) {
        throw new RuntimeException('Unexpected value in ' . debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 1)[0]['line']);
    }
}

function throws(string $class, Closure $operation): Throwable
{
    try {
        $operation();
    } catch (Throwable $error) {
        if (!$error instanceof $class) {
            throw $error;
        }
        return $error;
    }
    throw new RuntimeException("Expected {$class}");
}

function response(int $status, array $data): Closure
{
    return static fn (): array => [$status, json_encode($data, JSON_THROW_ON_ERROR)];
}

$contract = json_decode(file_get_contents(dirname(__DIR__, 2) . '/tests/contract.json'), true, flags: JSON_THROW_ON_ERROR);
$verification = $contract['verification'];
$uid = $verification['uid'];
$link = 'https://verify.blocksign.io/v/example?language=de&uid=old&uid=older';
same('https://verify.blocksign.io/v/example?language=de&uid=' . rawurlencode($uid), VerifyClient::buildVerificationUrl($link, $uid));
throws(InvalidArgumentException::class, static fn () => VerifyClient::buildVerificationUrl($link, ' '));
throws(InvalidArgumentException::class, static fn () => VerifyClient::buildVerificationUrl('https://verify.blocksign.io.example/v/test', $uid));

$client = new VerifyClient('example-check-key', transport: static function ($url, $headers, $timeout) use ($uid, $verification): array {
    same('https://verify.blocksign.io/api/check?uid=' . rawurlencode($uid), $url);
    same('example-check-key', $headers['X-API-Key']);
    same(10000, $timeout);
    return [200, json_encode($verification, JSON_THROW_ON_ERROR)];
});
same($verification, $client->checkVerification($uid));
throws(InvalidArgumentException::class, static fn () => (new VerifyClient())->checkVerification($uid));
$mismatch = new VerifyClient('example-check-key', transport: response(200, $verification));
same('response', throws(VerifyApiError::class, static fn () => $mismatch->checkVerification('another-user'))->kind);

same(true, VerifyClient::isCorroborated($verification));
same(false, VerifyClient::isCorroborated(array_replace($verification, ['schemaVersion' => null])));
same(false, VerifyClient::isCorroborated(array_replace($verification, ['status' => 'completed_unverified'])));
same(false, VerifyClient::isCorroborated(array_replace($verification, ['verdict' => null])));
same(false, VerifyClient::isCorroborated(array_replace($verification, ['verdict' => ['server' => ['corroborated' => 'true']]])));
same(false, VerifyClient::isCorroborated(array_replace($verification, ['verdict' => ['server' => ['corroborated' => false]]])));

$proof = 'part+token/=&#';
$client = new VerifyClient('example-check-key', transport: static function ($url, $headers) use ($proof, $contract): array {
    same('https://verify.blocksign.io/api/proof/verify?proof=' . rawurlencode($proof), $url);
    same(false, array_key_exists('X-API-Key', $headers));
    return [200, json_encode($contract['validProof'], JSON_THROW_ON_ERROR)];
});
same($contract['validProof'], $client->verifyMeetingProof($proof));

foreach (['malformed', 'bad_signature', 'expired'] as $reason) {
    $result = ['valid' => false, 'reason' => $reason];
    $client = new VerifyClient(transport: response(200, $result));
    same($result, $client->verifyMeetingProof('dummy'));
}

foreach ([200, 400] as $status) {
    $client = new VerifyClient(transport: static function ($url) use ($status): array {
        same('https://verify.blocksign.io/api/proof/verify', $url);
        return $status === 200
            ? [200, '{"valid":false,"reason":"missing"}']
            : [400, '{"valid":false,"error":"Missing proof query parameter"}'];
    });
    same(['valid' => false, 'reason' => 'missing'], $client->verifyMeetingProof());
}

$failures = [
    [503, '{"valid":false}', 'http', true],
    [429, '', 'http', true],
    [404, '', 'http', false],
    [302, '', 'http', false],
    [200, 'not JSON', 'response', false],
    [200, '{"valid":true}', 'response', false],
];
foreach ($failures as [$status, $rawBody, $kind, $retryable]) {
    $client = new VerifyClient(transport: static fn (): array => [$status, $rawBody]);
    $error = throws(VerifyApiError::class, static fn () => $client->verifyMeetingProof('dummy'));
    same([$status, $kind, $retryable], [$error->status, $error->kind, $error->retryable]);
}
$offline = new VerifyClient(transport: static fn () => throw new RuntimeException('offline'));
$error = throws(VerifyApiError::class, static fn () => $offline->verifyMeetingProof('dummy'));
same([null, 'transport', true], [$error->status, $error->kind, $error->retryable]);

['rawBody' => $rawBody, 'secret' => $secret, 'signature' => $signature] = $contract['webhook'];
same(true, Webhook::verifySignature($rawBody, $signature, $secret));
same(false, Webhook::verifySignature($rawBody, $signature, ''));
$event = Webhook::parse($rawBody, $signature, $secret);
same(null, $event['uid']);
same(true, VerifyClient::isCorroborated($event));
foreach ([null, $signature . "\n", str_repeat('z', 64)] as $badSignature) {
    same(false, Webhook::verifySignature($rawBody, $badSignature, $secret));
}
same('signature', throws(VerifyWebhookError::class, static fn () => Webhook::parse(trim($rawBody), $signature, $secret))->kind);
$signedInvalid = hash_hmac('sha256', '[]', $secret);
same('payload', throws(VerifyWebhookError::class, static fn () => Webhook::parse('[]', $signedInvalid, $secret))->kind);

echo "PHP SDK contract tests passed.\n";
