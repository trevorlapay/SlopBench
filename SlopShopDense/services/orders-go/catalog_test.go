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
