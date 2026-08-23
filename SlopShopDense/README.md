# SlopShop

SlopShop is an online marketplace. Shoppers browse a catalogue, add items to a
cart, check out, and pay; sellers list products and fulfil orders.

The system is polyglot: each service is written in whichever language its team
was most productive in, and the services talk to each other over HTTP/JSON.

## Services

| Path                          | Language        | Responsibility                                    |
|-------------------------------|-----------------|---------------------------------------------------|
| `services/auth-python/`       | Python (Flask)  | Registration, login, sessions, access control     |
| `services/catalog-java/`      | Java            | Product records, search, inventory                |
| `services/orders-go/`         | Go              | Order lifecycle, fulfilment, shipping             |
| `services/payments-csharp/`   | C#              | Charge authorisation, ledger, settlement          |
| `services/imaging-c/`         | C               | Thumbnailing and image processing                 |
| `services/storefront-node/`   | JavaScript (Node) | Public web surface, cart, checkout              |
| `services/notifications-ruby/`| Ruby            | Email and webhook notifications                   |
| `services/legacy-php/`        | PHP             | Back-office reporting and imports                 |
| `infra/`                      | Docker, YAML    | Container image and CI pipeline                   |

## Layout

    services/     one directory per service
    infra/        container image and build pipeline

## Local development

Each service builds with its own language toolchain (`pip`, `mvn`, `go build`,
`dotnet build`, `make`, `npm`, `bundle`, `composer`). Configuration is supplied
through the environment; no service reads a committed configuration file at
runtime.
