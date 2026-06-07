---
title: Configuración
description: Todas las variables de entorno y archivos de configuración que lee kovra, en un solo lugar.
---

Esta es la referencia completa de cómo se configura kovra: las variables de entorno
que lee y los archivos que utiliza.

## Variables de entorno

| Variable | Predeterminado | Qué hace |
| --- | --- | --- |
| `KOVRA_VAULT_DIR` | `~/.vaults` | Sobreescribe la raíz del registro del vault. |
| `KOVRA_PASSPHRASE` | *(no definida)* | Activa el [modo passphrase](/es/operations/headless-ci/): deriva la clave maestra con Argon2id en lugar de usar el keyring del SO. |
| `KOVRA_CONFIRMER` | `biometric` (cae a `file`) | Canal de confirmación: `biometric` (Touch ID / Windows Hello) o `file` (el broker `kovra approve`). |
| `KOVRA_UI_NO_CONFIRM` | *(no definida)* | Omite la confirmación de lanzamiento de la Web UI (equivalente a `kovra ui --no-confirm`). |
| `KOVRA_RECIPIENT_KEY` | *(no definida)* | Clave privada ed25519 usada por `kovra unpack` (en lugar de `--identity-file`); se mantiene fuera de argv. |
| `KOVRA_MCP_ENVIRONMENTS` | `*` | Alcance de la sesión MCP — entornos direccionables (lista separada por comas, o `*` para cualquiera). |
| `KOVRA_MCP_PROJECTS` | `*` | Alcance de la sesión MCP — proyectos direccionables (lista separada por comas, o `*` para cualquiera). |

## El directorio del vault

La raíz del registro (por defecto `~/.vaults`, o `KOVRA_VAULT_DIR`) contiene:

```text
~/.vaults/
  global/            # the global vault — sealed per-secret records + a sealed index
  projects/
    <name>/          # one directory per project vault, same layout
  kdf.salt           # passphrase-mode only: the non-secret Argon2 salt
```

Cada registro está sellado en reposo; las coordenadas no quedan expuestas como
nombres de archivo en texto plano. Consulta **[Criptografía](/es/security/cryptography/)** para el formato en reposo.

## `.mcp.json`

`kovra setup` registra el servidor MCP aquí para que tu agente pueda iniciarlo. El
bloque `env` lleva el **alcance de la sesión MCP**:

```json
{
  "mcpServers": {
    "kovra": {
      "command": "kovra-mcp",
      "env": {
        "KOVRA_MCP_ENVIRONMENTS": "dev,test",
        "KOVRA_MCP_PROJECTS": "my-app"
      }
    }
  }
}
```

Esto delimita lo que un agente sobre MCP puede direccionar (`*` = cualquiera). Es
distinto de `agent.toml`, que limita el alcance del **ssh-agent**.

## `agent.toml` — el alcance del ssh-agent

El [ssh-agent gobernado](/es/guides/ssh-agent/) lee su alcance desde
`<vault-root>/agent.toml`. El formato es intencionalmente mínimo — dos claves de
arreglo, con comentarios `#`:

```toml
# <vault-root>/agent.toml — kovra ssh-agent scope
environments = ["dev", "test"]   # omit (or []) → any environment
projects     = ["api"]           # omit (or []) → global + any project
```

Dos cosas **no** son configurables aquí, por diseño: el conjunto de operaciones
está fijo en *metadata + inject* (un ssh-agent **nunca** revela una clave privada), y
cuando el archivo está ausente el agente sirve cualquier entorno/proyecto — sin
revelar nunca, y requiriendo siempre un [bioProve](/es/operations/attended-confirmation/)
en cada firma `high`/`prod`.

## La gramática de `.env.refs`

`.env.refs` mapea nombres de variables de entorno locales a **fuentes**. Contiene
direcciones, nunca valores, por lo que es seguro commitearlo. Un mapeo por línea:

| Forma | Significado |
| --- | --- |
| `project = <name>` | Vincula el archivo a un vault de proyecto (la resolución lo apunta). |
| `NAME=secret:<env>/<comp>/<key>` | Una **coordenada de vault**. Puede usar `${ENV}`; un `\| fallback` opcional se aplica si no resuelve. |
| `NAME=secret://global/<env>/<comp>/<key>` | Fuerza la resolución contra el vault **global**, omitiendo el proyecto. |
| `NAME=${env:VAR}` | Un **passthrough** desde el entorno de ejecución. Soporta `${env:VAR \| fallback}`. |
| `NAME=literal` | Un valor **literal** (no un secreto), p. ej. `PORT=8080`. |

Reglas que lo mantienen seguro:

- **Nunca valores** — solo direcciones, por lo que un `.env.refs` filtrado no expone nada.
- **`${ENV}`** es sustituido por `kovra run --env <e>` dentro del segmento de
  entorno de una coordenada; **`${env:VAR}`** lee del entorno circundante.
- **La interpolación entre variables es rechazada** — no puedes componer un secreto
  dentro del string de otra variable (ese string compuesto quedaría registrado).
- **La resolución es un único paso ordenado** sobre el archivo.

Consulta **[El contrato de .env.refs](/es/concepts/env-refs/)** para la versión narrativa.
