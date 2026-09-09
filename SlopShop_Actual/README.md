# SlopShop

SlopShop is an online marketplace. Shoppers browse a catalogue, add items to a
cart, check out, and pay; sellers list products and fulfil orders.

The system is polyglot: each service is written in whichever language its team
was most productive in, and the services talk to each other over HTTP/JSON.

## Services

| Path | Language | Responsibility |
|------|----------|----------------|
| `services/backoffice-php/` | PHP | Back-office reporting, imports, admin |
| `services/catalog-python/` | Python | Catalogue, search indexing, recommendations |
| `services/edge-rust/` | Rust | Edge proxy, TLS termination, rate limiting |
| `services/imaging-c/` | C/C++ | Thumbnailing and image processing |
| `services/notifications-ruby/` | Ruby | Email and webhook notifications |
| `services/orders-go/` | Go | Order lifecycle, fulfilment, shipping |
| `services/payments-csharp/` | C# | Charge authorisation, ledger, settlement |
| `services/search-java/` | Java | Full-text search and merchandising |
| `services/storefront-node/` | JavaScript/TypeScript | Public web surface, cart, checkout |

## Layout

    services/     one directory per service, split into components
    infra/        container image and CI pipeline

## Local development

Each service builds with its own language toolchain (`pip`, `go build`, `mvn`, `dotnet build`, `cargo build`, `composer install`,
`npm install`, `bundle`, `make`).
