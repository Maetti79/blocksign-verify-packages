<?php

declare(strict_types=1);

namespace BlockSign\Verify;

use RuntimeException;

final class VerifyApiError extends RuntimeException
{
    public readonly bool $retryable;

    public function __construct(
        public readonly string $kind,
        public readonly ?int $status = null,
    ) {
        parent::__construct(match ($kind) {
            'http' => "BlockSign Verify returned HTTP {$status}.",
            'transport' => 'BlockSign Verify request failed.',
            default => 'BlockSign Verify returned an unexpected response.',
        });

        $this->retryable = $kind === 'transport'
            || ($kind === 'http' && ($status === 408 || $status === 429 || $status >= 500));
    }
}
