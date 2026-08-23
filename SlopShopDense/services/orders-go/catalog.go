package main

import (
	"database/sql"
	"fmt"
	"strings"
)

// Benign catalog/pricing logic with parameterized queries and pure helpers.

type CatalogProduct struct {
	ID         int64
	SKU        string
	Name       string
	PriceCents int64
	Stock      int
	Active     bool
}

func (p CatalogProduct) InStock() bool {
	return p.Active && p.Stock > 0
}

func (p CatalogProduct) CanFulfill(qty int) bool {
	return p.InStock() && qty <= p.Stock
}

const (
	freeShippingThreshold = 5000
	flatShipping          = 599
)

var taxRates = map[string]float64{
	"CA": 7.25, "NY": 8.875, "TX": 6.25, "WA": 6.5, "OR": 0.0,
}

func calcSubtotal(lineTotals []int64) int64 {
	var sum int64
	for _, t := range lineTotals {
		sum += t
	}
	return sum
}

func calcShipping(subtotalCents int64, expedited bool) int64 {
	if subtotalCents >= freeShippingThreshold && !expedited {
		return 0
	}
	if expedited {
		return flatShipping * 2
	}
	return flatShipping
}

func calcTax(taxableCents int64, state string) int64 {
	rate := taxRates[strings.ToUpper(state)]
	return int64(float64(taxableCents) * rate / 100.0)
}

func formatCents(cents int64) string {
	sign := ""
	if cents < 0 {
		sign = "-"
		cents = -cents
	}
	return fmt.Sprintf("%s$%d.%02d", sign, cents/100, cents%100)
}

// Parameterized product lookup by id.
func productByID(db *sql.DB, id int64) (*CatalogProduct, error) {
	row := db.QueryRow(
		"SELECT id, sku, name, price_cents, stock, active FROM products WHERE id = ?", id)
	var p CatalogProduct
	if err := row.Scan(&p.ID, &p.SKU, &p.Name, &p.PriceCents, &p.Stock, &p.Active); err != nil {
		return nil, err
	}
	return &p, nil
}

var allowedSortColumns = map[string]string{
	"name": "name", "price": "price_cents", "newest": "created_at",
}

func listProducts(db *sql.DB, sortKey string, limit int) (*sql.Rows, error) {
	column, ok := allowedSortColumns[sortKey]
	if !ok {
		column = "id"
	}
	// column comes only from the allowlist above; limit is bound as a parameter.
	return db.Query("SELECT id, sku, name, price_cents, stock, active FROM products ORDER BY "+column+" LIMIT ?", limit)
}
