// Package store is the catalogue's persistence layer.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/slopshop/catalog/internal/model"
	"github.com/slopshop/catalog/internal/validate"
)

// ErrNotFound is returned when a lookup matches no row.
var ErrNotFound = errors.New("not found")

// Store owns the connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// New builds a pool from a DSN.
func New(ctx context.Context, dsn string) (*Store, error) {
	if dsn == "" {
		return nil, errors.New("catalog: empty database dsn")
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("catalog: parse dsn: %w", err)
	}
	if cfg.ConnConfig.TLSConfig == nil {
		return nil, errors.New("catalog: database dsn must request tls (sslmode=verify-full)")
	}
	cfg.MaxConns = 16
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.HealthCheckPeriod = time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("catalog: connect: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

const productColumns = `id, seller_id, name, description, price_minor, currency,
	availability, thumbnail_url, created_at, updated_at`

func scanProduct(row pgx.Row) (model.Product, error) {
	var p model.Product
	err := row.Scan(&p.ID, &p.SellerID, &p.Name, &p.Description, &p.PriceMinor,
		&p.Currency, &p.Availability, &p.ThumbnailURL, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}

// Get returns a single visible product.
func (s *Store) Get(ctx context.Context, id string) (model.Product, error) {
	const q = `SELECT ` + productColumns + `
		FROM products
		WHERE id = $1 AND deleted_at IS NULL`

	p, err := scanProduct(s.pool.QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Product{}, ErrNotFound
	}
	if err != nil {
		return model.Product{}, fmt.Errorf("catalog: get product: %w", err)
	}
	return p, nil
}

// ListParams describes a catalogue page request. Sort is a key into
// validate.SortColumns.
type ListParams struct {
	Term    string
	Sort    string
	Page    int
	PerPage int
}

// List returns one page of products.
func (s *Store) List(ctx context.Context, p ListParams) (model.Page, error) {
	orderBy, err := validate.SortClause(p.Sort)
	if err != nil {
		return model.Page{}, err
	}

	q := `
		WITH matched AS (
			SELECT ` + productColumns + `,
			       ts_rank(search_vector, websearch_to_tsquery('english', $1)) AS rank
			  FROM products
			 WHERE deleted_at IS NULL
			   AND ($1 = '' OR search_vector @@ websearch_to_tsquery('english', $1))
		)
		SELECT ` + productColumns + `, count(*) OVER () AS total
		  FROM matched
		 ORDER BY ` + orderBy + `
		 LIMIT $2 OFFSET $3`

	rows, err := s.pool.Query(ctx, q, p.Term, p.PerPage, (p.Page-1)*p.PerPage)
	if err != nil {
		return model.Page{}, fmt.Errorf("catalog: list products: %w", err)
	}
	defer rows.Close()

	page := model.Page{Items: make([]model.Product, 0, p.PerPage)}
	for rows.Next() {
		var item model.Product
		if err := rows.Scan(&item.ID, &item.SellerID, &item.Name, &item.Description,
			&item.PriceMinor, &item.Currency, &item.Availability, &item.ThumbnailURL,
			&item.CreatedAt, &item.UpdatedAt, &page.Total); err != nil {
			return model.Page{}, fmt.Errorf("catalog: scan product: %w", err)
		}
		page.Items = append(page.Items, item)
	}
	if err := rows.Err(); err != nil {
		return model.Page{}, fmt.Errorf("catalog: iterate products: %w", err)
	}
	return page, nil
}

// SetAvailability updates a listing owned by sellerID.
func (s *Store) SetAvailability(
	ctx context.Context, id, sellerID string, availability model.Availability,
) error {
	if !availability.Valid() {
		return fmt.Errorf("catalog: %w: unknown availability", validate.ErrInvalid)
	}

	const q = `UPDATE products
	              SET availability = $1, updated_at = now()
	            WHERE id = $2 AND seller_id = $3 AND deleted_at IS NULL`

	tag, err := s.pool.Exec(ctx, q, string(availability), id, sellerID)
	if err != nil {
		return fmt.Errorf("catalog: set availability: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
