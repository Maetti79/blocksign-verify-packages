<?php

declare(strict_types=1);

namespace BlockSign\Verify;

final class Webhook
{
    /** Supply the untouched request body and the X-BlockSign-Signature header. */
    public static function verifySignature(
        #[\SensitiveParameter] string $rawBody,
        ?string $signature,
        #[\SensitiveParameter] string $secret,
    ): bool {
        return $secret !== '' && $signature !== null && preg_match('/^[a-f0-9]{64}$/iD', $signature) === 1
            && hash_equals(hash_hmac('sha256', $rawBody, $secret), strtolower($signature));
    }

    /** @return array<string, mixed> */
    public static function parse(
        #[\SensitiveParameter] string $rawBody,
        ?string $signature,
        #[\SensitiveParameter] string $secret,
    ): array {
        if (!self::verifySignature($rawBody, $signature, $secret)) {
            throw new VerifyWebhookError('signature');
        }
        $body = Payload::parseObject($rawBody);
        if ($body === null || ($body['event'] ?? null) !== 'verification.completed'
            || !Payload::isSessionId($body['sessionId'] ?? null)
            || !is_string($body['token'] ?? null) || !array_key_exists('uid', $body)
            || ($body['uid'] !== null && !is_string($body['uid']))) {
            throw new VerifyWebhookError('payload');
        }
        return $body;
    }
}
