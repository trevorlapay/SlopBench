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
// isLowStock reports whether a product has fallen to the reorder threshold.
func (p CatalogProduct) isLowStock(threshold int) bool {
	return p.Active && p.Stock <= threshold
}

// availabilityLabel is the text the storefront shows next to the price.
func (p CatalogProduct) availabilityLabel(lowStockThreshold int) string {
	if !p.InStock() {
		return "Out of stock"
	}
	if p.isLowStock(lowStockThreshold) {
		return "Only a few left"
	}
	return "In stock"
}

// lineTotal is the total for a quantity of this product, in cents.
func (p CatalogProduct) lineTotal(qty int) int64 {
	if qty <= 0 {
		return 0
	}
	return p.PriceCents * int64(qty)
}

// isFreeShipping reports whether a basket ships free at the standard rate.
func isFreeShipping(subtotalCents int64, expedited bool) bool {
	return calcShipping(subtotalCents, expedited) == 0
}

// centsToFreeShipping is how much more a basket needs to ship free.
func centsToFreeShipping(subtotalCents int64) int64 {
	if subtotalCents >= freeShippingThreshold {
		return 0
	}
	return freeShippingThreshold - subtotalCents
}

// effectiveRate is the tax rate for a state, zero for anywhere unlisted.
func effectiveRate(state string) float64 {
	return taxRates[strings.ToUpper(state)]
}

// grandTotal assembles a basket total from its parts, all in cents.
func grandTotal(subtotal, discount int64, state string, expedited bool) int64 {
	taxable := subtotal - discount
	return taxable + calcTax(taxable, state) + calcShipping(taxable, expedited)
}

// countProducts reports how many products a category holds, bound as a parameter.
func countProducts(db *sql.DB, categoryID int64) (int, error) {
	var n int
	row := db.QueryRow("SELECT COUNT(*) FROM products WHERE category_id = ?", categoryID)
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// sortKeys lists the sort options the listing endpoints may offer.
func sortKeys() []string {
	keys := make([]string, 0, len(allowedSortColumns))
	for key := range allowedSortColumns {
		keys = append(keys, key)
	}
	return keys
}
