<?php

declare(strict_types=1);

namespace BlockSign\Verify;

use RuntimeException;

final class VerifyWebhookError extends RuntimeException
{
    public function __construct(public readonly string $kind)
    {
        parent::__construct($kind === 'signature'
            ? 'Invalid BlockSign Verify webhook signature.'
            : 'Invalid BlockSign Verify webhook payload.');
    }
}
