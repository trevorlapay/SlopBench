// Package validate contains the input rules shared by the catalogue handlers.
package validate

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	MaxQueryLength       = 64
	MaxNameLength        = 200
	MaxDescriptionLength = 4000
	MaxPerPage           = 100
	MaxPage              = 500
)

var ErrInvalid = errors.New("invalid input")

// SortColumns maps the sort keys accepted on the wire to the ORDER BY fragment
// each one selects.
var SortColumns = map[string]string{
	"relevance":  "rank DESC, created_at DESC",
	"price_asc":  "price_minor ASC, id ASC",
	"price_desc": "price_minor DESC, id ASC",
	"newest":     "created_at DESC, id ASC",
}

// SortClause returns the ORDER BY fragment for key, or an error when key is not
// one of the four supported values.
func SortClause(key string) (string, error) {
	clause, ok := SortColumns[key]
	if !ok {
		return "", fmt.Errorf("%w: unsupported sort %q", ErrInvalid, key)
	}
	return clause, nil
}

// UUID parses a canonical UUID, rejecting anything else.
func UUID(raw string) (string, error) {
	parsed, err := uuid.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: not a uuid", ErrInvalid)
	}
	return parsed.String(), nil
}

// SearchTerm bounds a free-text term and requires valid UTF-8.
func SearchTerm(raw string) (string, error) {
	if !utf8.ValidString(raw) {
		return "", fmt.Errorf("%w: search term is not valid utf-8", ErrInvalid)
	}
	if n := utf8.RuneCountInString(raw); n == 0 || n > MaxQueryLength {
		return "", fmt.Errorf("%w: search term must be 1..%d characters", ErrInvalid, MaxQueryLength)
	}
	return raw, nil
}

// Pagination clamps page and perPage into the supported ranges.
func Pagination(page, perPage int) (int, int, error) {
	if page < 1 || page > MaxPage {
		return 0, 0, fmt.Errorf("%w: page must be 1..%d", ErrInvalid, MaxPage)
	}
	if perPage < 1 || perPage > MaxPerPage {
		return 0, 0, fmt.Errorf("%w: per_page must be 1..%d", ErrInvalid, MaxPerPage)
	}
	return page, perPage, nil
}
