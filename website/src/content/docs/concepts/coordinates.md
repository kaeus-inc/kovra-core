---
title: Coordinates
description: How kovra addresses a secret — a three-segment URI, never the value itself.
---

You never refer to a secret by its value. You refer to it by its **coordinate** —
a stable three-segment address:

```text
secret:<env>/<component>/<key>
```

For example:

```text
secret:dev/db/password
secret:prod/stripe/api-key
secret:staging/app/jwt-signing-key
```

The three segments are always present — there is **no short form**. That's
deliberate: it removes the ambiguity of "is this segment the environment or the
component?" and makes every coordinate read the same way.

| Segment | Meaning | Examples |
|---------|---------|----------|
| `env` | The environment | `dev`, `staging`, `prod` |
| `component` | The thing the secret belongs to | `db`, `stripe`, `app` |
| `key` | The specific secret | `password`, `api-key`, `url` |

## Environment interpolation

The **environment** segment — and only that segment — may be the placeholder
`${ENV}`, which is substituted at run time from the `--env` flag:

```text
secret:${ENV}/db/password
```

```bash
kovra run --env dev --... # ${ENV} → dev
kovra run --env prod --... # ${ENV} → prod
```

This is what lets one [`.env.refs`](/concepts/env-refs/) file serve every
environment. Interpolation anywhere else (`${COMPONENT}`, or any other `${…}`) is
**rejected**, never silently passed through.

## Scope selector

By default a coordinate resolves with the project vault overriding the global
vault. Prefix the address with `//global/` to **ignore the project override** and
resolve only against the global vault:

```text
secret://global/dev/db/password
```

## Keypair half selector

For [asymmetric keypairs](/concepts/vault/), an optional trailing fragment selects
which half of the key an operation acts on:

```text
secret:dev/ssh/deploy#public # the public key — free, non-secret
secret:dev/ssh/deploy#private # the private key — never returned to your context
```

The fragment is part of the *request*, not the stored address: a coordinate and
its `#public` / `#private` forms file under the same vault record. For a plain
literal or a reference, the fragment is meaningless and ignored.
