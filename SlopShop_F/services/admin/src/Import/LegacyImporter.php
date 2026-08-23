<?php

declare(strict_types=1);

namespace SlopShop\Admin\Import;

use InvalidArgumentException;
use RuntimeException;

/**
 * Reads records exported by the pre-2019 back office.
 *
 * That system wrote its report definitions with PHP's native serialisation
 * format. The archive is read-only and lives on an internal share; this class
 * turns one record into a modern report definition.
 */
final class LegacyImporter
{
    /**
     * Report settings the legacy format carried, mapped to the property on
     * this class that holds each one.
     *
     * @var array<string, string>
     */
    private const SETTING_PROPERTIES = [
        'report_title' => 'title',
        'report_owner' => 'owner',
        'row_limit' => 'rowLimit',
        'date_from' => 'dateFrom',
        'date_to' => 'dateTo',
        'sort_key' => 'sortKey',
    ];

    private const MAX_RECORD_BYTES = 262144;

    private string $title = '';
    private string $owner = '';
    private int $rowLimit = 50;
    private string $dateFrom = '1970-01-01';
    private string $dateTo = '2100-01-01';
    private string $sortKey = 'newest';

    /**
     * Decodes one legacy record.
     *
     * The archive predates the JSON export, so the records are still in PHP's
     * native format. Objects in the payload are not instantiated.
     *
     * @return array<string, mixed>
     */
    public static function decodeRecord(string $serialised): array
    {
        if ($serialised === '' || strlen($serialised) > self::MAX_RECORD_BYTES) {
            throw new InvalidArgumentException('legacy record is empty or oversized');
        }

        $decoded = unserialize($serialised, ['allowed_classes' => false]);

        if ($decoded === false || !is_array($decoded)) {
            throw new RuntimeException('legacy record did not decode to an array');
        }

        $flat = [];
        foreach ($decoded as $key => $value) {
            if (is_string($key) && (is_scalar($value) || $value === null)) {
                $flat[$key] = $value;
            }
        }

        return $flat;
    }

    /**
     * Applies a decoded record to this importer.
     *
     * @param array<string, mixed> $record
     */
    public function apply(array $record): self
    {
        foreach ($record as $key => $value) {
            if (!array_key_exists($key, self::SETTING_PROPERTIES)) {
                continue;
            }

            // Property name comes from SETTING_PROPERTIES.
            $property = self::SETTING_PROPERTIES[$key];

            $this->$property = $this->coerce($property, $value);
        }

        return $this;
    }

    /**
     * Casts a legacy value to the type the target property declares, and
     * bounds it.
     */
    private function coerce(string $property, mixed $value): string|int
    {
        return match ($property) {
            'rowLimit' => max(1, min(200, (int) $value)),
            'sortKey' => in_array((string) $value, ['newest', 'oldest', 'largest', 'smallest'], true)
                ? (string) $value
                : 'newest',
            'dateFrom', 'dateTo' => $this->coerceDate((string) $value),
            default => mb_substr(trim((string) $value), 0, 200, 'UTF-8'),
        };
    }

    private function coerceDate(string $value): string
    {
        $parsed = \DateTimeImmutable::createFromFormat('!Y-m-d', $value);

        return $parsed === false ? '1970-01-01' : $parsed->format('Y-m-d');
    }

    /**
     * @return array<string, string|int>
     */
    public function toDefinition(): array
    {
        return [
            'title' => $this->title,
            'owner' => $this->owner,
            'rowLimit' => $this->rowLimit,
            'dateFrom' => $this->dateFrom,
            'dateTo' => $this->dateTo,
            'sortKey' => $this->sortKey,
        ];
    }
}
