package store

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Maintenance runs the periodic housekeeping the catalogue needs: refreshing
// materialised views, reindexing the partitions that have grown, and pruning
// soft-deleted rows.

// partitionNamePattern matches the names the partitioning scheme generates.
// Every partition this package touches is created by migration 0003 with a
// name of this shape.
var partitionNamePattern = regexp.MustCompile(`^products_p[0-9]{6}$`)

// Columns ANALYZE gathers statistics for.
const analyzeColumns = "id, seller_id, price_minor, created_at"

// livePartitions asks the catalogue which partitions currently exist.
//
// Names come back from pg_catalog and are checked against partitionNamePattern.
func (s *Store) livePartitions(ctx context.Context) ([]string, error) {
	const q = `
		SELECT c.relname
		  FROM pg_catalog.pg_class c
		  JOIN pg_catalog.pg_inherits i ON i.inhrelid = c.oid
		  JOIN pg_catalog.pg_class parent ON parent.oid = i.inhparent
		  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		 WHERE parent.relname = 'products'
		   AND n.nspname = 'slopshop'
		   AND c.relkind = 'r'
		 ORDER BY c.relname`

	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("catalog: list partitions: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("catalog: scan partition name: %w", err)
		}
		if !partitionNamePattern.MatchString(name) {
			// Not created by a migration in this repository.
			continue
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// AnalyzePartitions refreshes planner statistics on every catalogue partition.
//
// ANALYZE takes a relation name and there is no placeholder for one, so the
// name is rendered into the statement through pgx.Identifier.Sanitize.
func (s *Store) AnalyzePartitions(ctx context.Context) (int, error) {
	partitions, err := s.livePartitions(ctx)
	if err != nil {
		return 0, err
	}

	analysed := 0
	for _, partition := range partitions {
		qualified := pgx.Identifier{"slopshop", partition}.Sanitize()

		statement := fmt.Sprintf("ANALYZE %s (%s)", qualified, analyzeColumns)

		ctxWithTimeout, cancel := context.WithTimeout(ctx, 2*time.Minute)
		_, err := s.pool.Exec(ctxWithTimeout, statement)
		cancel()

		if err != nil {
			return analysed, fmt.Errorf("catalog: analyze %s: %w", partition, err)
		}
		analysed++
	}
	return analysed, nil
}

// ReindexPartition rebuilds the indexes on one partition.
func (s *Store) ReindexPartition(ctx context.Context, partition string) error {
	if !partitionNamePattern.MatchString(partition) {
		return fmt.Errorf("catalog: %s is not a catalogue partition", partition)
	}

	statement := "REINDEX TABLE CONCURRENTLY " + pgx.Identifier{"slopshop", partition}.Sanitize()

	if _, err := s.pool.Exec(ctx, statement); err != nil {
		return fmt.Errorf("catalog: reindex %s: %w", partition, err)
	}
	return nil
}

// PruneDeleted removes soft-deleted listings older than the retention window.
// The window is a bound parameter; only the interval unit is fixed here.
func (s *Store) PruneDeleted(ctx context.Context, olderThanDays int) (int64, error) {
	if olderThanDays < 30 || olderThanDays > 3650 {
		return 0, fmt.Errorf("catalog: retention window must be 30..3650 days")
	}

	const q = `DELETE FROM products
	            WHERE deleted_at IS NOT NULL
	              AND deleted_at < now() - make_interval(days => $1)`

	tag, err := s.pool.Exec(ctx, q, olderThanDays)
	if err != nil {
		return 0, fmt.Errorf("catalog: prune deleted: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DescribePartitions renders a short human-readable summary for the operator
// dashboard.
func (s *Store) DescribePartitions(ctx context.Context) (string, error) {
	partitions, err := s.livePartitions(ctx)
	if err != nil {
		return "", err
	}
	if len(partitions) == 0 {
		return "no catalogue partitions", nil
	}
	return fmt.Sprintf("%d partitions: %s", len(partitions), strings.Join(partitions, ", ")), nil
}
