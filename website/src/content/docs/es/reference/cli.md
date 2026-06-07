---
title: Referencia de la CLI
description: Todos los comandos de kovra, agrupados por función. Ejecuta `kovra <command> --help` para ver las opciones completas.
---

Este es el mapa de la CLI de `kovra`. Cada comando pasa por el mismo
[proceso de decisión de política](/es/security/decision/); ejecuta `kovra <command> --help` para
ver sus flags y argumentos exactos.

## Configuración y vault

| Comando | Qué hace |
| --- | --- |
| `kovra init` | Inicializa el registro del vault y la clave maestra. |
| `kovra setup` | Incorpora el repositorio actual: verifica el vault, registra el servidor MCP en `.mcp.json` e inserta el bloque de convenciones en `CLAUDE.md`. |

## Secretos

| Comando | Qué hace |
| --- | --- |
| `kovra add <coord>` | Crea un secreto (valor mediante prompt oculto o `--stdin`; nunca por argv). |
| `kovra set <coord>` | Actualiza el valor de un secreto. |
| `kovra edit <coord>` | Edita metadatos (sensibilidad / descripción / referencia); reducir la sensibilidad es una degradación protegida. |
| `kovra rm <coord>` | Elimina un secreto. |
| `kovra list` | Lista los secretos — solo metadatos, nunca valores. |
| `kovra show <coord>` | Revela un valor en stdout (`high` requiere <span class="bioprove">bioProve</span>; `inject-only` nunca). |
| `kovra generate <coord>` | Genera un valor aleatorio del lado del servidor; nunca se imprime. |
| `kovra import <coord> --from op://…` | Copia un valor desde 1Password al vault como literal. |

## Inyección

| Comando | Qué hace |
| --- | --- |
| `kovra run --env <e> -- <cmd>` | Resuelve un `.env.refs` y ejecuta un comando con los valores inyectados en el proceso hijo. `--allow` agrega un ejecutable a la lista permitida para `high`/`prod`. |

## Credenciales tipadas

| Comando | Qué hace |
| --- | --- |
| `kovra code <coord>` | Imprime el código TOTP actual (nunca la semilla). |
| `kovra keygen <coord>` | Genera y custodia un par de claves asimétricas (la mitad privada nunca en disco). |
| `kovra pubkey <coord>` | Imprime la clave pública OpenSSH de un par de claves (sin restricciones). |
| `kovra sign / verify` | Firma datos con la clave privada / verifica una firma. |
| `kovra encrypt / decrypt` | Cifra hacia / descifra con un par de claves `ed25519`. |
| `kovra ssh-add <coord>` | Carga una clave custodiada en el ssh-agent en ejecución, solo en memoria. |
| `kovra ssh-agent` | Ejecuta kovra como un ssh-agent gobernado (firma en memoria; `high`/`prod` requieren confirmación por firma). |

## Proveedores

| Comando | Qué hace |
| --- | --- |
| `kovra add <coord> --reference azure-kv://…` | Almacena un puntero a Azure Key Vault. |
| `kovra add <coord> --reference aws-sm://…` | Almacena un puntero a AWS Secrets Manager. |

Las referencias se resuelven en tiempo de ejecución bajo tu propia identidad. Consulta
[Referencias en la nube](/es/guides/references/).

## Compartir e intercambio USB

| Comando | Qué hace |
| --- | --- |
| `kovra package` | Sella un entorno que no sea `prod` con la clave del destinatario; escribe el paquete y un token de acceso separado. |
| `kovra unpack` | Abre un paquete sellado con tu identidad privada. |
| `kovra exchange init / seal / register-token / open` | Arranque USB sin conexión de una máquina sin kovra (solo macOS). |

## Confirmación

| Comando | Qué hace |
| --- | --- |
| `kovra confirm <text>` | Solicita una confirmación humana asistida (sale con 0 si se aprueba) — para que un host/app controle su propia acción. |
| `kovra approve [id]` | Aprueba o deniega una confirmación pendiente desde otra sesión (el broker de archivos como alternativa a la biometría). |

## Web UI

| Comando | Qué hace |
| --- | --- |
| `kovra ui` | Levanta la UI de administración loopback bajo demanda (`--docker` para ejecutarla en un contenedor). |

## Higiene y mantenimiento

| Comando | Qué hace |
| --- | --- |
| `kovra scaffold` | Escanea el código fuente en busca de referencias a variables de entorno y propone un `.env.refs` (solo lee nombres, nunca valores). |
| `kovra doctor` (`lint`) | Valida la configuración de secretos de un proyecto; solo coordenadas y estado, nunca un valor. |
| `kovra hooks` | Gestiona git hooks que mantienen los secretos fuera de los commits. |
| `kovra audit` | Consulta el registro de auditoría — coordenadas, huellas digitales truncadas, marcas de tiempo, origen; nunca un valor. |
| `kovra key export / import` | Respalda / restaura la clave maestra del vault (recuperación ante desastres). |
