package main

import "testing"

func TestCalcSubtotal(t *testing.T) {
	got := calcSubtotal([]int64{1000, 250, 250})
	if got != 1500 {
		t.Fatalf("subtotal = %d, want 1500", got)
	}
}

func TestCalcShipping(t *testing.T) {
	if calcShipping(6000, false) != 0 {
		t.Error("orders over threshold should ship free")
	}
	if calcShipping(4000, false) != flatShipping {
		t.Error("orders under threshold pay flat shipping")
	}
	if calcShipping(9999, true) != flatShipping*2 {
		t.Error("expedited is never free")
	}
}

func TestCalcTax(t *testing.T) {
	if calcTax(10000, "OR") != 0 {
		t.Error("OR has no sales tax")
	}
	if calcTax(10000, "ca") == 0 {
		t.Error("CA tax should be non-zero and case-insensitive")
	}
}

func TestFormatCents(t *testing.T) {
	if formatCents(123456) != "$1234.56" {
		t.Errorf("got %q", formatCents(123456))
	}
	if formatCents(-99) != "-$0.99" {
		t.Errorf("got %q", formatCents(-99))
	}
}

func TestClampQuantity(t *testing.T) {
	if clampQuantity(0, 1, 99) != 1 {
		t.Error("below lo clamps to lo")
	}
	if clampQuantity(500, 1, 99) != 99 {
		t.Error("above hi clamps to hi")
	}
}

func TestValidators(t *testing.T) {
	if !validSKU("AB-1234") || validSKU("nope") {
		t.Error("SKU validation")
	}
	if !validEmail("a@b.co") || validEmail("bad") {
		t.Error("email validation")
	}
}
func TestAvailabilityLabel(t *testing.T) {
	inStock := CatalogProduct{Active: true, Stock: 50}
	if inStock.availabilityLabel(5) != "In stock" {
		t.Errorf("got %q", inStock.availabilityLabel(5))
	}
	low := CatalogProduct{Active: true, Stock: 2}
	if low.availabilityLabel(5) != "Only a few left" {
		t.Errorf("got %q", low.availabilityLabel(5))
	}
	gone := CatalogProduct{Active: true, Stock: 0}
	if gone.availabilityLabel(5) != "Out of stock" {
		t.Errorf("got %q", gone.availabilityLabel(5))
	}
}

func TestLineTotal(t *testing.T) {
	p := CatalogProduct{PriceCents: 250}
	if p.lineTotal(4) != 1000 {
		t.Errorf("got %d", p.lineTotal(4))
	}
	if p.lineTotal(-1) != 0 {
		t.Error("negative quantities contribute nothing")
	}
}

func TestFreeShippingHelpers(t *testing.T) {
	if !isFreeShipping(6000, false) {
		t.Error("orders over the threshold ship free")
	}
	if centsToFreeShipping(4000) != freeShippingThreshold-4000 {
		t.Error("remaining amount is wrong")
	}
	if centsToFreeShipping(999999) != 0 {
		t.Error("remaining amount never goes negative")
	}
}

func TestGrandTotalIsConsistent(t *testing.T) {
	total := grandTotal(2000, 200, "CA", false)
	taxable := int64(1800)
	want := taxable + calcTax(taxable, "CA") + calcShipping(taxable, false)
	if total != want {
		t.Errorf("total = %d, want %d", total, want)
	}
}

func TestLocalRedirect(t *testing.T) {
	if _, ok := localRedirect("//evil.example"); ok {
		t.Error("protocol-relative targets are not local")
	}
	if got, ok := localRedirect("/orders"); !ok || got != "/orders" {
		t.Errorf("got %q ok=%v", got, ok)
	}
}

func TestControlCharacters(t *testing.T) {
	if !hasControlCharacters("bad\x01value") {
		t.Error("control characters should be detected")
	}
	if hasControlCharacters("ordinary value") {
		t.Error("plain text has no control characters")
	}
}
