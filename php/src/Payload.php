<?php

declare(strict_types=1);

namespace BlockSign\Verify;

use JsonException;

/** @internal */
final class Payload
{
    public static function isSessionId(mixed $value): bool
    {
        return is_int($value) && $value > 0 && $value <= 9007199254740991;
    }

    /** @return array<string, mixed>|null */
    public static function parseObject(#[\SensitiveParameter] string $json): ?array
    {
        if (!str_starts_with(ltrim($json, " \n\r\t"), '{')) {
            return null;
        }
        try {
            return json_decode($json, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }
    }
}
