<?php
// Session cart operations (pure logic; no direct superglobal sinks).

class ShoppingCart
{
    private const MIN_QTY = 1;
    private const MAX_QTY = 99;

    private array $items = [];

    private static function clampQuantity($value): int
    {
        $n = (int) $value;
        if ($n < self::MIN_QTY) {
            return self::MIN_QTY;
        }
        return min(self::MAX_QTY, $n);
    }

    public function add(int $productId, int $priceCents, int $quantity = 1): void
    {
        $quantity = self::clampQuantity($quantity);
        if (isset($this->items[$productId])) {
            $this->items[$productId]['quantity'] =
                self::clampQuantity($this->items[$productId]['quantity'] + $quantity);
        } else {
            $this->items[$productId] = ['price_cents' => $priceCents, 'quantity' => $quantity];
        }
    }

    public function remove(int $productId): void
    {
        unset($this->items[$productId]);
    }

    public function setQuantity(int $productId, int $quantity): void
    {
        if (!isset($this->items[$productId])) {
            return;
        }
        if ($quantity <= 0) {
            $this->remove($productId);
        } else {
            $this->items[$productId]['quantity'] = self::clampQuantity($quantity);
        }
    }

    public function count(): int
    {
        return array_sum(array_column($this->items, 'quantity'));
    }

    public function subtotalCents(): int
    {
        $total = 0;
        foreach ($this->items as $item) {
            $total += $item['price_cents'] * $item['quantity'];
        }
        return $total;
    }

    public function isEmpty(): bool
    {
        return empty($this->items);
    }

    public function has(int $productId): bool
    {
        return isset($this->items[$productId]);
    }

    public function quantityOf(int $productId): int
    {
        return $this->items[$productId]['quantity'] ?? 0;
    }

    public function lineTotalCents(int $productId): int
    {
        if (!$this->has($productId)) {
            return 0;
        }
        $item = $this->items[$productId];
        return $item['price_cents'] * $item['quantity'];
    }

    public function merge(ShoppingCart $other): void
    {
        foreach ($other->snapshot() as $productId => $item) {
            $this->add($productId, $item['price_cents'], $item['quantity']);
        }
    }

    public function snapshot(): array
    {
        return $this->items;
    }

    public function clear(): void
    {
        $this->items = [];
    }

    public function heaviestLine(): ?int
    {
        $best = null;
        $bestTotal = -1;
        foreach ($this->items as $productId => $item) {
            $total = $item['price_cents'] * $item['quantity'];
            if ($total > $bestTotal) {
                $bestTotal = $total;
                $best = $productId;
            }
        }
        return $best;
    }
}
?>
