// Package model holds the catalogue's domain types.
package model

import "time"

// Availability enumerates the states a listing may be in.
type Availability string

const (
	AvailabilityInStock    Availability = "in_stock"
	AvailabilityBackorder  Availability = "backorder"
	AvailabilityDiscontinued Availability = "discontinued"
)

// Valid reports whether a is one of the known states.
func (a Availability) Valid() bool {
	switch a {
	case AvailabilityInStock, AvailabilityBackorder, AvailabilityDiscontinued:
		return true
	default:
		return false
	}
}

// Product is a single listing. Prices are held in minor units to avoid any
// floating point representation of money.
type Product struct {
	ID           string       `json:"id"`
	SellerID     string       `json:"sellerId"`
	Name         string       `json:"name"`
	Description  string       `json:"description"`
	PriceMinor   int64        `json:"priceMinor"`
	Currency     string       `json:"currency"`
	Availability Availability `json:"availability"`
	ThumbnailURL string       `json:"thumbnailUrl"`
	CreatedAt    time.Time    `json:"createdAt"`
	UpdatedAt    time.Time    `json:"updatedAt"`
}

// Page is one slice of a listing query.
type Page struct {
	Items []Product `json:"items"`
	Total int64     `json:"total"`
}
