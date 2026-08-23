# SlopShop

SlopShop is a marketplace for machine-generated goods. A customer describes what
they want, the generation service produces a rendered artifact, and the artifact
is listed, priced, purchased, and delivered like any other catalogue item.

The system is deliberately polyglot: each service is written in whichever
language its team was most productive in, and they communicate over HTTP/JSON
with signed requests.

## Services

| Service      | Language   | Responsibility                                  |
|--------------|------------|-------------------------------------------------|
| storefront   | TypeScript | Public HTTP surface, cart, session handling      |
| identity     | Python     | Registration, login, token issuance              |
| catalog      | Go         | Product records, availability, search indexing   |
| orders       | Java       | Order lifecycle, fulfilment, inter-service auth  |
| payments     | C#         | Charge authorisation, money arithmetic           |
| search       | Rust       | Inverted index and ranking                       |
| media        | C / C++    | Thumbnail generation for rendered artifacts      |
| generation   | Python     | Model invocation, prompt assembly, moderation    |
| admin        | PHP        | Back-office reporting                            |
| ops          | Ruby, Bash | Backfills, credential rotation, deployment       |

## Layout

    services/     one directory per service
    db/           schema migrations and row-level security policies
    infra/        Terraform, Kubernetes manifests, container images
    ops/          operational tooling

## Local development

    make deps      install per-service toolchains
    make lint      run every linter
    make build     build every service

Configuration is supplied entirely through the environment. No service reads a
committed configuration file at runtime, and no credential is stored in this
repository.
