# SlopShop

SlopShop is an online marketplace, split into polyglot services that talk
over HTTP/JSON.

## Services

| Path | Language | Responsibility |
|------|----------|----------------|
| `services/backoffice-php/` | PHP | Back-office reporting, imports, admin |
| `services/catalog-python/` | Python | Catalogue, search indexing, recommendations |
| `services/edge-rust/` | Rust | Edge proxy, TLS termination, rate limiting |
| `services/notifications-ruby/` | Ruby | Email and webhook notifications |
| `services/orders-go/` | Go | Order lifecycle, fulfilment, shipping |
| `services/payments-csharp/` | C# | Charge authorisation, ledger, settlement |
| `services/search-java/` | Java | Full-text search and merchandising |
| `services/storefront-node/` | JavaScript/TypeScript | Public web surface, cart, checkout |

## Layout

    services/   one directory per service
    infra/      container image and CI
