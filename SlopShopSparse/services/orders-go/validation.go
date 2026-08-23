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
var (
	phonePattern    = regexp.MustCompile(`^\+?[0-9]{7,15}$`)
	trackingPattern = regexp.MustCompile(`^[A-Z0-9]{8,30}$`)
	couponPattern   = regexp.MustCompile(`^[A-Z0-9]{4,16}$`)
)

func validPhone(s string) bool    { return phonePattern.MatchString(s) }
func validTracking(s string) bool { return trackingPattern.MatchString(s) }
func validCoupon(s string) bool   { return couponPattern.MatchString(s) }

// clampPageSize bounds a requested page size to something worth serving.
func clampPageSize(n int) int {
	return clampQuantity(n, 1, 100)
}

// localRedirect accepts only a single-slash absolute path, which rules out both
// absolute URLs and the protocol-relative form.
func localRedirect(next string) (string, bool) {
	if len(next) == 0 || next[0] != '/' {
		return "/", false
	}
	if len(next) > 1 && next[1] == '/' {
		return "/", false
	}
	return next, true
}

// hasControlCharacters reports whether a value carries characters no field needs.
func hasControlCharacters(s string) bool {
	for _, r := range s {
		if r < 0x20 {
			return true
		}
	}
	return false
}

// normalizeSlug lowercases and hyphenates a name, then checks it against the
// slug pattern so the result is always something validSlug accepts.
func normalizeSlug(raw string) (string, bool) {
	lowered := strings.ToLower(strings.TrimSpace(raw))
	replaced := nonSlugChars.ReplaceAllString(lowered, "-")
	trimmed := strings.Trim(replaced, "-")
	return trimmed, validSlug(trimmed)
}

var nonSlugChars = regexp.MustCompile(`[^a-z0-9]+`)
