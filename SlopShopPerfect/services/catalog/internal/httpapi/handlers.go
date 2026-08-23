// Package httpapi exposes the catalogue over HTTP.
package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/slopshop/catalog/internal/model"
	"github.com/slopshop/catalog/internal/store"
	"github.com/slopshop/catalog/internal/validate"
)


// Server wires the store to the router.
type Server struct {
	store        *store.Store
	serviceToken []byte
	log          *slog.Logger
}

// NewServer returns a Server. serviceToken is the shared secret first-party
// callers present.
func NewServer(s *store.Store, serviceToken []byte, log *slog.Logger) *Server {
	return &Server{store: s, serviceToken: serviceToken, log: log}
}

// Routes builds the mux.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/products", s.authenticated(s.listProducts))
	mux.HandleFunc("GET /v1/products/{id}", s.authenticated(s.getProduct))
	mux.HandleFunc("PATCH /v1/products/{id}/availability", s.authenticated(s.setAvailability))
	mux.HandleFunc("GET /healthz", s.healthz)
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// authenticated rejects any request that does not present the service token.
func (s *Server) authenticated(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scheme, presented, found := strings.Cut(r.Header.Get("Authorization"), " ")
		if !found || !strings.EqualFold(scheme, "Bearer") {
			writeError(w, http.StatusUnauthorized, "unauthenticated")
			return
		}

		presentedDigest := sha256.Sum256([]byte(presented))
		expectedDigest := sha256.Sum256(s.serviceToken)
		if !hmac.Equal(presentedDigest[:], expectedDigest[:]) {
			writeError(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		next(w, r)
	}
}

func (s *Server) listProducts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	term := ""
	if raw := q.Get("q"); raw != "" {
		validated, err := validate.SearchTerm(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_query")
			return
		}
		term = validated
	}

	page := atoiDefault(q.Get("page"), 1)
	perPage := atoiDefault(q.Get("per_page"), 24)
	page, perPage, err := validate.Pagination(page, perPage)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_pagination")
		return
	}

	sort := q.Get("sort")
	if sort == "" {
		sort = "relevance"
	}
	if _, err := validate.SortClause(sort); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_sort")
		return
	}

	result, err := s.store.List(r.Context(), store.ListParams{
		Term: term, Sort: sort, Page: page, PerPage: perPage,
	})
	if err != nil {
		s.log.Error("list products failed", slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) getProduct(w http.ResponseWriter, r *http.Request) {
	id, err := validate.UUID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_product_id")
		return
	}

	product, err := s.store.Get(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found")
	case err != nil:
		s.log.Error("get product failed", slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "internal_error")
	default:
		writeJSON(w, http.StatusOK, product)
	}
}

func (s *Server) setAvailability(w http.ResponseWriter, r *http.Request) {
	id, err := validate.UUID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_product_id")
		return
	}

	var body struct {
		SellerID     string `json:"sellerId"`
		Availability string `json:"availability"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body")
		return
	}

	sellerID, err := validate.UUID(body.SellerID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_seller_id")
		return
	}

	err = s.store.SetAvailability(r.Context(), id, sellerID, model.Availability(body.Availability))
	switch {
	case errors.Is(err, validate.ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid_availability")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found")
	case err != nil:
		s.log.Error("set availability failed", slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "internal_error")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func atoiDefault(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return -1
	}
	return n
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeError emits a fixed error code.
func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
