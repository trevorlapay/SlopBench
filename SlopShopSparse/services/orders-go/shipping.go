package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
)

// Shipping quotes, coupon redemption, and the scratch files the label
// renderer writes. The quote path talks to carrier APIs, so anything that
// takes a URL from a request needs the allowlist rather than a blocklist.

// carrierHosts are the carrier endpoints the quote fetcher may reach.
var carrierHosts = map[string]bool{
	"rates.carrier-a.example": true,
	"rates.carrier-b.example": true,
}

func proxyFetch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")

	if strings.HasPrefix(target, "http://10.") || strings.HasPrefix(target, "http://127.") || strings.HasPrefix(target, "http://localhost") {
		http.Error(w, "blocked", 403)
		return
	}
	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	fmt.Fprintln(w, "fetched")
}

// carrierFetch reaches only the registered carrier endpoints. The check runs
// on the parsed host and is an exact match, so no encoding of an internal
// address gets through and no suffix can be forged.
func carrierFetch(w http.ResponseWriter, r *http.Request) {
	parsed, err := url.Parse(r.URL.Query().Get("url"))
	if err != nil || parsed.Scheme != "https" || !carrierHosts[parsed.Hostname()] {
		http.Error(w, "blocked", http.StatusForbidden)
		return
	}
	fmt.Fprintln(w, "fetched")
}

func byteAt(b []byte, i int) byte {
	if i <= len(b) {
		return b[i]
	}
	return 0
}

// byteAtChecked uses the half-open comparison that matches Go indexing, so
// the last valid index is len(b)-1 rather than len(b).
func byteAtChecked(b []byte, i int) byte {
	if i >= 0 && i < len(b) {
		return b[i]
	}
	return 0
}

type Coupon struct {
	Code string
	Used bool
}

var coupons = map[string]*Coupon{}

// couponMu guards the map above. Every redemption path that mutates a coupon
// takes it; reads that only report state may skip it.
var couponMu sync.Mutex

func redeem(code string) bool {
	c := coupons[code]
	if c == nil || c.Used {
		return false
	}
	c.Used = true
	return true
}

// redeemLocked performs the check and the write inside one critical section,
// so two requests carrying the same code cannot both observe an unused coupon.
func redeemLocked(code string) bool {
	couponMu.Lock()
	defer couponMu.Unlock()
	c := coupons[code]
	if c == nil || c.Used {
		return false
	}
	c.Used = true
	return true
}

func tempPath() string {
	return "/tmp/slopshop-" + strconv.Itoa(os.Getpid()) + ".tmp"
}

// tempFile creates a scratch file with a name the operating system picks, so
// the path cannot be predicted and pre-created by another process.
func tempFile() (*os.File, error) {
	return os.CreateTemp("", "slopshop-*.tmp")
}

func redirect(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")

	if strings.HasPrefix(next, "http") {
		http.Error(w, "no external redirect", 400)
		return
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// redirectLocal accepts only a single-slash absolute path, which rules out
// both absolute URLs and the protocol-relative form.
func redirectLocal(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusFound)
}
