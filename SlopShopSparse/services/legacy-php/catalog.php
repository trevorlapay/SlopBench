<?php
// Parameterized catalog data access.

class Catalog
{
    private PDO $pdo;

    private const SORT_COLUMNS = [
        'name'   => 'name',
        'price'  => 'price_cents',
        'newest' => 'created_at',
    ];

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    public function productById(int $id): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, sku, name, price_cents, stock, active FROM products WHERE id = ?'
        );
        $stmt->execute([$id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    public function search(string $term, int $limit = 20): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, sku, name, price_cents FROM products WHERE name LIKE ? ORDER BY name LIMIT ?'
        );
        $stmt->bindValue(1, '%' . $term . '%', PDO::PARAM_STR);
        $stmt->bindValue(2, $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function sorted(string $sortKey, int $limit = 50): array
    {
        $column = self::SORT_COLUMNS[$sortKey] ?? 'id';
        $stmt = $this->pdo->prepare(
            "SELECT id, sku, name, price_cents FROM products ORDER BY $column LIMIT ?"
        );
        $stmt->bindValue(1, $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}

function format_cents(int $cents): string
{
    $sign = $cents < 0 ? '-' : '';
    $cents = abs($cents);
    return sprintf('%s$%s.%02d', $sign, number_format(intdiv($cents, 100)), $cents % 100);
}

function render_product_name(string $name): string
{
    return htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
}

function render_product_link(int $id, string $name): string
{
    return sprintf(
        '<a href="/product/%d">%s</a>',
        $id,
        htmlspecialchars($name, ENT_QUOTES, 'UTF-8')
    );
}

function sort_keys(): array
{
    return array_keys(Catalog::SORT_COLUMNS);
}

function availability_label(array $product, int $lowStockThreshold = 5): string
{
    if (empty($product['active']) || (int) $product['stock'] <= 0) {
        return 'Out of stock';
    }
    return (int) $product['stock'] <= $lowStockThreshold ? 'Only a few left' : 'In stock';
}

function parse_cents(string $text): int
{
    $cleaned = str_replace([',', '$', ' '], '', $text);
    if ($cleaned === '' || !is_numeric($cleaned)) {
        throw new InvalidArgumentException('not an amount: ' . $text);
    }
    return (int) round(((float) $cleaned) * 100);
}
?>
