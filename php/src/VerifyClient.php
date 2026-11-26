<?php

declare(strict_types=1);

namespace BlockSign\Verify;

use Closure;
use InvalidArgumentException;
use Throwable;

final class VerifyClient
{
    private const ORIGIN = 'https://verify.blocksign.io';

    /** @param (Closure(string, array<string, string>, int): array{int, string})|null $transport */
    public function __construct(
        #[\SensitiveParameter] private readonly ?string $apiKey = null,
        private readonly int $timeoutMs = 10000,
        private readonly ?Closure $transport = null,
    ) {
        if ($timeoutMs < 1 || $timeoutMs > 2147483647) {
            throw new InvalidArgumentException('timeoutMs must be a positive number of milliseconds up to 2147483647.');
        }
    }

    /** @return array<string, mixed> */
    public function checkVerification(string $uid): array
    {
        self::requireUid($uid);
        if ($this->apiKey === null || trim($this->apiKey) === '' || preg_match('/[\r\n\x00]/', $this->apiKey)) {
            throw new InvalidArgumentException('A valid API key is required to check a verification.');
        }
        [$body, $status] = $this->get('/api/check', ['uid' => $uid], $this->apiKey);
        if (($body['uid'] ?? null) !== $uid || !Payload::isSessionId($body['sessionId'] ?? null)
            || !is_string($body['status'] ?? null)) {
            throw new VerifyApiError('response', $status);
        }
        return $body;
    }

    /**
     * @return array{valid: false, reason: string}|array{valid: true, sessionId: int,
     *     orgId?: int, human: bool, meeting: array{channel: string, meetingId: ?string}, expiresAt: string}
     */
    public function verifyMeetingProof(#[\SensitiveParameter] ?string $proof = null): array
    {
        $missing = $proof === null || $proof === '';
        [$body, $status] = $this->get('/api/proof/verify', $missing ? [] : ['proof' => $proof], missingProof: $missing);
        if (($body['valid'] ?? null) === false && is_string($body['reason'] ?? null) && $body['reason'] !== '') {
            return $body;
        }
        $meeting = $body['meeting'] ?? null;
        if (($body['valid'] ?? null) === true && Payload::isSessionId($body['sessionId'] ?? null)
            && (!array_key_exists('orgId', $body) || Payload::isSessionId($body['orgId']))
            && is_bool($body['human'] ?? null) && is_array($meeting)
            && is_string($meeting['channel'] ?? null) && array_key_exists('meetingId', $meeting)
            && ($meeting['meetingId'] === null || is_string($meeting['meetingId']))
            && is_string($body['expiresAt'] ?? null) && strtotime($body['expiresAt']) !== false) {
            return $body;
        }
        throw new VerifyApiError('response', $status);
    }

    /** Use the current static link from the Verify dashboard. */
    public static function buildVerificationUrl(string $verificationLink, string $uid): string
    {
        self::requireUid($uid);
        $url = parse_url($verificationLink);
        if ($url === false || preg_match('/[\x00-\x20\x7f]/', $verificationLink)
            || str_contains($verificationLink, '\\') || strtolower($url['scheme'] ?? '') !== 'https'
            || strtolower($url['host'] ?? '') !== 'verify.blocksign.io'
            || ($url['port'] ?? 443) !== 443 || isset($url['user']) || isset($url['pass'])
            || !preg_match('~^/v/[^/]+/?$~D', $url['path'] ?? '')
            || preg_match('~^/v/(?:\.|%2e){1,2}/?$~iD', $url['path'])) {
            throw new InvalidArgumentException('Expected a static https://verify.blocksign.io/v/ verification link.');
        }

        $query = [];
        foreach (explode('&', $url['query'] ?? '') as $parameter) {
            $key = urldecode(explode('=', $parameter, 2)[0]);
            if ($parameter !== '' && $key !== 'uid') {
                $query[] = $parameter;
            }
        }
        $query[] = 'uid=' . rawurlencode($uid);

        return self::ORIGIN . $url['path'] . '?' . implode('&', $query)
            . (isset($url['fragment']) ? '#' . $url['fragment'] : '');
    }

    /** Call on a successful Check response or an authenticated webhook. */
    public static function isCorroborated(array $result): bool
    {
        $verdict = $result['verdict'] ?? null;
        $server = is_array($verdict) ? ($verdict['server'] ?? null) : null;
        return ($result['schemaVersion'] ?? null) === 2
            && ($result['status'] ?? null) === 'completed'
            && is_array($server) && ($server['corroborated'] ?? null) === true;
    }

    /** @return array{array<string, mixed>, int} */
    private function get(
        string $path,
        #[\SensitiveParameter] array $query,
        #[\SensitiveParameter] ?string $apiKey = null,
        bool $missingProof = false,
    ): array {
        $url = self::ORIGIN . $path;
        if ($query !== []) {
            $url .= '?' . http_build_query($query, encoding_type: PHP_QUERY_RFC3986);
        }
        $headers = ['Accept' => 'application/json', 'Cache-Control' => 'no-store'];
        if ($apiKey !== null) {
            $headers['X-API-Key'] = $apiKey;
        }

        $transport = $this->transport ?? self::curlGet(...);
        try {
            [$status, $rawBody] = $transport($url, $headers, $this->timeoutMs);
        } catch (Throwable) {
            throw new VerifyApiError('transport');
        }
        $legacyMissing = $missingProof && $status === 400;
        if (($status < 200 || $status >= 300) && !$legacyMissing) {
            throw new VerifyApiError('http', $status);
        }

        $body = Payload::parseObject($rawBody);
        if ($legacyMissing) {
            if (($body['valid'] ?? null) === false && (($body['reason'] ?? null) === 'missing'
                || ($body['error'] ?? null) === 'Missing proof query parameter')) {
                return [['valid' => false, 'reason' => 'missing'], $status];
            }
            throw new VerifyApiError('http', $status);
        }
        if ($body === null) {
            throw new VerifyApiError('response', $status);
        }
        return [$body, $status];
    }

    /** @return array{int, string} */
    private static function curlGet(#[\SensitiveParameter] string $url, #[\SensitiveParameter] array $headers, int $timeoutMs): array
    {
        $handle = curl_init($url);
        if ($handle === false) {
            throw new VerifyApiError('transport');
        }
        $headerLines = [];
        foreach ($headers as $name => $value) {
            $headerLines[] = $name . ': ' . $value;
        }
        curl_setopt_array($handle, [
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT_MS => $timeoutMs,
        ]);
        $rawBody = curl_exec($handle);
        if ($rawBody === false) {
            throw new VerifyApiError('transport');
        }
        return [(int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE), $rawBody];
    }

    private static function requireUid(string $uid): void
    {
        if (trim($uid) === '' || preg_match('//u', $uid) !== 1) {
            throw new InvalidArgumentException('uid must be a non-empty UTF-8 string.');
        }
    }
}
