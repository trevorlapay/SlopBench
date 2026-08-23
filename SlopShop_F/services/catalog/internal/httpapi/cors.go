package httpapi

import (
	"net/http"
	"strings"
)

// The catalogue is called from the storefront and from the seller console.
// Both are first-party origins served from this repository's own deployment.
var allowedOrigins = map[string]struct{}{
	"https://slopshop.example":         {},
	"https://www.slopshop.example":     {},
	"https://sellers.slopshop.example": {},
}

const (
	allowedMethods = "GET, POST, PATCH, OPTIONS"
	allowedHeaders = "Authorization, Content-Type, X-Request-Id"
	maxAgeSeconds  = "600"
)

// originAllowed reports whether the origin is one of the three first-party
// origins.
func originAllowed(origin string) bool {
	_, ok := allowedOrigins[origin]
	return ok
}

// withCORS answers preflights and adds the response headers a permitted origin
// needs.
//
// The Origin header is echoed rather than a wildcard because the endpoints
// carry credentials, and a wildcard is not valid alongside
// Access-Control-Allow-Credentials.
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Add("Vary", "Origin")

		origin := r.Header.Get("Origin")
		if origin == "" {
			// Not a cross-origin request.
			next.ServeHTTP(w, r)
			return
		}

		if !originAllowed(origin) {
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		header.Set("Access-Control-Allow-Origin", origin)
		header.Set("Access-Control-Allow-Credentials", "true")

		if r.Method == http.MethodOptions {
			header.Add("Vary", "Access-Control-Request-Method")
			header.Add("Vary", "Access-Control-Request-Headers")
			header.Set("Access-Control-Allow-Methods", allowedMethods)
			header.Set("Access-Control-Allow-Headers", allowedHeaders)
			header.Set("Access-Control-Max-Age", maxAgeSeconds)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		header.Set("Access-Control-Expose-Headers", "X-Request-Id")
		next.ServeHTTP(w, r)
	})
}

// requestedMethodAllowed is used by the preflight path to reject a method the
// API does not implement before any handler is consulted.
func requestedMethodAllowed(requested string) bool {
	if requested == "" {
		return false
	}
	for _, method := range strings.Split(allowedMethods, ", ") {
		if strings.EqualFold(method, requested) {
			return true
		}
	}
	return false
}
