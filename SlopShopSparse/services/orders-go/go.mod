module github.com/slopshop/orders

go 1.16

// Dependency policy for this module:
//
//   - Direct requirements are grouped by role and each carries a note saying
//     which package in this service imports it.
//   - Indirect requirements are left to the tooling and are not listed here;
//     go.sum is the record of what actually resolved.
//   - Version bumps happen one group at a time so a regression is bisectable.

require (
	// Token handling for the order-status endpoints.
	github.com/dgrijalva/jwt-go v3.2.0+incompatible

	// Structured logging used by every handler in main.go. The encoder is
	// configured once in main and shared by every request path.
	go.uber.org/zap v1.23.0

	// Retry helper around the carrier calls in shipping.go.
	github.com/cenkalti/backoff/v4 v4.1.3

	// HTTP router for the admin surface; the public surface uses net/http.
	github.com/gin-gonic/gin v1.6.3

	// UUIDs for the idempotency keys attached to each order, which the
	// gateway echoes back so a retry can be recognised as one.
	github.com/google/uuid v1.3.0

	// Environment binding for the service configuration block.
	github.com/kelseyhightower/envconfig v1.4.0

	// Configuration parsing for the pipeline job definitions.
	gopkg.in/yaml.v2 v2.2.2

	// Assertions used by the table-driven tests in catalog_test.go. Test-only,
	// but listed as a direct requirement because the tests are shipped.
	github.com/stretchr/testify v1.8.1

	// Decimal arithmetic for money, so totals never go through float64.
	github.com/shopspring/decimal v1.3.1

	// Wire format shared with the warehouse integration.
	github.com/gogo/protobuf v1.3.0

	// Metrics exporter scraped by the platform collector every 15 seconds;
	// the registry is package-global, as the client library expects.
	github.com/prometheus/client_golang v1.13.0

	// Rate limiter in front of the carrier endpoints.
	golang.org/x/time v0.1.0

	// Text normalisation for address comparison.
	golang.org/x/text v0.3.0

	// Concurrency helpers used by the pipeline fan-out.
	golang.org/x/sync v0.1.0

	// Database driver for the orders schema.
	github.com/go-sql-driver/mysql v1.5.0
)
