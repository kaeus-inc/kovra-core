---
title: Coordenadas
description: Cómo kovra direcciona un secreto — una URI de tres segmentos, nunca el valor en sí.
---

Nunca te refieres a un secreto por su valor. Te refieres a él por su **coordenada** — una dirección estable de tres segmentos:

```text
secret:<env>/<component>/<key>
```

Por ejemplo:

```text
secret:dev/db/password
secret:prod/stripe/api-key
secret:staging/app/jwt-signing-key
```

Los tres segmentos siempre están presentes — no existe **forma abreviada**. Esto es deliberado: elimina la ambigüedad de "¿este segmento es el entorno o el componente?" y hace que toda coordenada se lea de la misma manera.

| Segmento | Significado | Ejemplos |
|---------|---------|----------|
| `env` | El entorno | `dev`, `staging`, `prod` |
| `component` | El elemento al que pertenece el secreto | `db`, `stripe`, `app` |
| `key` | El secreto específico | `password`, `api-key`, `url` |

## Interpolación de entorno

El segmento de **entorno** — y solo ese segmento — puede ser el marcador de posición `${ENV}`, que se sustituye en tiempo de ejecución con el flag `--env`:

```text
secret:${ENV}/db/password
```

```bash
kovra run --env dev --... # ${ENV} → dev
kovra run --env prod --... # ${ENV} → prod
```

Esto es lo que permite que un solo archivo [`.env.refs`](/es/concepts/env-refs/) sirva para todos los entornos. La interpolación en cualquier otro lugar (`${COMPONENT}`, o cualquier otro `${…}`) es **rechazada**, nunca pasa silenciosamente.

## Selector de ámbito

Por defecto una coordenada se resuelve con el vault de proyecto sobreescribiendo al vault global. Prefija la dirección con `//global/` para **ignorar la sobreescritura del proyecto** y resolver únicamente contra el vault global:

```text
secret://global/dev/db/password
```

## Selector de mitad de par de claves

Para [pares de claves asimétricas](/es/concepts/vault/), un fragmento final opcional selecciona sobre qué mitad de la clave opera la acción:

```text
secret:dev/ssh/deploy#public # la clave pública — libre, no secreta
secret:dev/ssh/deploy#private # la clave privada — nunca devuelta a tu contexto
```

El fragmento es parte de la *solicitud*, no de la dirección almacenada: una coordenada y sus formas `#public` / `#private` se archivan bajo el mismo registro del vault. Para un literal o una referencia simples, el fragmento carece de significado y se ignora.
