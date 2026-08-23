package main

import (
	"net/url"
	"regexp"
)

var (
	skuPattern   = regexp.MustCompile(`^[A-Z]{2,4}-[0-9]{4,8}$`)
	slugPattern  = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	emailPattern = regexp.MustCompile(`^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,}$`)
)

func validSKU(s string) bool   { return skuPattern.MatchString(s) }
func validSlug(s string) bool  { return slugPattern.MatchString(s) }
func validEmail(s string) bool { return emailPattern.MatchString(s) }

func clampQuantity(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

// safeRedirect returns next only if it targets an allowlisted host over http(s).
func safeRedirect(next string, allowed map[string]bool) (string, bool) {
	u, err := url.Parse(next)
	if err != nil {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	if !allowed[u.Host] {
		return "", false
	}
	return u.String(), true
}
