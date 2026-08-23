<?php

declare(strict_types=1);

namespace SlopShop\Admin\View;

/**
 * Context-aware output encoding.
 *
 * Every template in the back office routes its interpolations through one of
 * these helpers.
 */
final class Escaper
{
    private const ENCODING = 'UTF-8';

    /** Flags used for every HTML encode. */
    private const HTML_FLAGS = ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5;

    /**
     * Encodes for HTML text and for quoted attribute values.
     */
    public static function html(?string $value): string
    {
        return htmlspecialchars($value ?? '', self::HTML_FLAGS, self::ENCODING);
    }

    /**
     * Encodes for a URL query component.
     */
    public static function urlComponent(?string $value): string
    {
        return rawurlencode($value ?? '');
    }

    /**
     * Encodes a value for embedding in a script block as a JSON literal.
     */
    public static function jsonForScript(mixed $value): string
    {
        $encoded = json_encode(
            $value,
            JSON_THROW_ON_ERROR
                | JSON_UNESCAPED_UNICODE
                | JSON_HEX_TAG
                | JSON_HEX_AMP
                | JSON_HEX_APOS
                | JSON_HEX_QUOT
        );

        return $encoded;
    }

    /**
     * Formats an amount held in minor units for display.
     */
    public static function money(int $amountMinor, string $currency): string
    {
        $major = intdiv($amountMinor, 100);
        $minor = abs($amountMinor % 100);
        $formatted = number_format((float) $major, 0, '.', ',') . '.' . str_pad(
            (string) $minor,
            2,
            '0',
            STR_PAD_LEFT
        );

        return self::html($currency . ' ' . $formatted);
    }

    /**
     * Renders an ISO-8601 timestamp, or an em dash when absent.
     */
    public static function timestamp(?string $iso8601): string
    {
        if ($iso8601 === null || $iso8601 === '') {
            return '&mdash;';
        }

        $parsed = \DateTimeImmutable::createFromFormat(\DateTimeInterface::ATOM, $iso8601);
        if ($parsed === false) {
            return '&mdash;';
        }

        return self::html($parsed->format('Y-m-d H:i'));
    }
}
