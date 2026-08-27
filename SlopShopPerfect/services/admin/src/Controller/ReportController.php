<?php

declare(strict_types=1);

namespace SlopShop\Admin\Controller;

use PDO;
use SlopShop\Admin\Db\Connection;
use SlopShop\Admin\View\Escaper;

/**
 * Back-office reports.
 *
 * Filters arrive as query parameters. The ORDER BY fragment is looked up in a
 * fixed table by key.
 */
final class ReportController
{
    /** Report keys mapped to the ORDER BY fragment each one selects. */
    private const ORDERINGS = [
        'newest' => 'placed_at DESC, order_id ASC',
        'oldest' => 'placed_at ASC, order_id ASC',
        'largest' => 'total_minor DESC, order_id ASC',
        'smallest' => 'total_minor ASC, order_id ASC',
    ];

    private const STATUSES = [
        'PENDING',
        'AUTHORISED',
        'FULFILLING',
        'SHIPPED',
        'CANCELLED',
        'REFUNDED',
    ];

    private const MAX_ROWS = 200;

    /**
     * @param array<string, mixed> $query
     * @return list<array<string, mixed>>
     */
    public function ordersReport(array $query): array
    {
        $orderKey = $this->orderingKey($query['sort'] ?? null);
        $status = $this->statusFilter($query['status'] ?? null);
        $from = $this->dateFilter($query['from'] ?? null) ?? '1970-01-01';
        $to = $this->dateFilter($query['to'] ?? null) ?? date('Y-m-d');
        $limit = $this->limit($query['limit'] ?? null);

        $sql = <<<SQL
            SELECT o.id            AS order_id,
                   o.status        AS status,
                   o.currency      AS currency,
                   o.total_minor   AS total_minor,
                   o.created_at    AS placed_at,
                   c.display_name  AS customer_name
              FROM orders o
              JOIN customers c ON c.id = o.customer_id
             WHERE o.created_at >= :from::date
               AND o.created_at <  (:to::date + INTERVAL '1 day')
               AND (:statusFilter::text IS NULL OR o.status = :statusMatch)
             ORDER BY {$this->orderingFragment($orderKey)}
             LIMIT :limit
            SQL;

        $statement = Connection::get()->prepare($sql);
        $statement->bindValue(':from', $from, PDO::PARAM_STR);
        $statement->bindValue(':to', $to, PDO::PARAM_STR);
        $statusType = $status === null ? PDO::PARAM_NULL : PDO::PARAM_STR;
        $statement->bindValue(':statusFilter', $status, $statusType);
        $statement->bindValue(':statusMatch', $status, $statusType);
        $statement->bindValue(':limit', $limit, PDO::PARAM_INT);
        $statement->execute();

        /** @var list<array<string, mixed>> $rows */
        $rows = $statement->fetchAll();

        return $rows;
    }

    /**
     * @param list<array<string, mixed>> $rows
     */
    public function renderOrdersTable(array $rows): string
    {
        $html = '<table class="report"><thead><tr>'
            . '<th>Order</th><th>Customer</th><th>Status</th><th>Total</th><th>Placed</th>'
            . '</tr></thead><tbody>';

        foreach ($rows as $row) {
            $html .= '<tr>'
                . '<td>' . Escaper::html((string) $row['order_id']) . '</td>'
                . '<td>' . Escaper::html((string) $row['customer_name']) . '</td>'
                . '<td>' . Escaper::html((string) $row['status']) . '</td>'
                . '<td>' . Escaper::money((int) $row['total_minor'], (string) $row['currency']) . '</td>'
                . '<td>' . Escaper::timestamp(
                    $this->toAtom((string) $row['placed_at'])
                ) . '</td>'
                . '</tr>';
        }

        return $html . '</tbody></table>';
    }

    private function toAtom(string $timestamp): ?string
    {
        $parsed = date_create_immutable($timestamp);

        return $parsed === false ? null : $parsed->format(\DateTimeInterface::ATOM);
    }

    private function orderingKey(mixed $raw): string
    {
        return is_string($raw) && array_key_exists($raw, self::ORDERINGS) ? $raw : 'newest';
    }

    /**
     * Translates a key into its ORDER BY fragment.
     */
    private function orderingFragment(string $key): string
    {
        return self::ORDERINGS[$key];
    }

    private function statusFilter(mixed $raw): ?string
    {
        return is_string($raw) && in_array($raw, self::STATUSES, true) ? $raw : null;
    }

    private function dateFilter(mixed $raw): ?string
    {
        if (!is_string($raw)) {
            return null;
        }

        $parsed = \DateTimeImmutable::createFromFormat('!Y-m-d', $raw);
        if ($parsed === false) {
            return null;
        }

        return $parsed->format('Y-m-d');
    }

    private function limit(mixed $raw): int
    {
        $parsed = filter_var($raw, FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1, 'max_range' => self::MAX_ROWS, 'default' => 50],
        ]);

        return $parsed;
    }
}
