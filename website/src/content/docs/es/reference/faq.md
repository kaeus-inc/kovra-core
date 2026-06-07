---
title: Preguntas frecuentes
description: Respuestas breves y directas a las preguntas que la gente hace antes de adoptar kovra.
---

## ¿kovra envía algo a la nube?

No. kovra es una herramienta **local** — el vault vive en tu máquina y nada se
transmite como efecto secundario del uso normal. Las únicas llamadas de red ocurren
cuando *tú* usas una [referencia en la nube](/es/guides/references/) (kovra la
resuelve bajo tu propia identidad del proveedor) o cuando compartes deliberadamente
[un paquete](/es/guides/sharing/). No hay telemetría ni llamadas a casa.

## ¿Funciona sin conexión?

Sí. Todo excepto las [referencias en la nube](/es/guides/references/) (que, por
definición, llaman a tu proveedor de nube) funciona sin red en absoluto.

## ¿Qué sale realmente de mi máquina?

Por defecto, nada. Un secreto solo se mueve cuando lo **compartes** explícitamente
(un paquete sellado, cifrado para el destinatario) o cuando una **referencia en la
nube** se resuelve contra tu proveedor. Incluso en ese caso, el texto plano nunca se
escribe en disco, en argv ni en el contexto de un agente.

## ¿Es seguro commitear `.env.refs`?

Sí — ese es el propósito. Contiene **direcciones, no valores**. Un `.env.refs`
filtrado expone dónde viven los secretos, nunca los secretos en sí. Agrega un
[git hook](/es/operations/git-hooks/) como salvaguarda contra commitear valores reales
por accidente.

## ¿Puede un agente de IA leer mis secretos?

Puede *usarlos*, no *ver* los sensibles. Un agente sobre MCP opera bajo un
[alcance](/es/concepts/agent-scope/) y nunca recibe el texto plano de un secreto
`high`, `prod` o `inject-only`. Lo único que puede leer es un secreto ordinario que
hayas marcado explícitamente como revelable.

## ¿Dónde se almacenan mis secretos?

En un vault cifrado bajo `~/.vaults` (o `KOVRA_VAULT_DIR`). Cada entrada está sellada;
consulta [Configuración](/es/reference/configuration/) y
[Criptografía](/es/security/cryptography/).

## ¿Es gratuito? ¿Cuál es la licencia?

Está disponible como **código fuente** bajo la Business Source License 1.1, y cada
versión pasa a Apache-2.0 cuatro años después de su lanzamiento. Consulta
[Licencia](/es/project/license/).

## ¿kovra es un servidor o un daemon?

No. Es una CLI local. La [Web UI](/es/guides/web-ui/) es **bajo demanda y solo
loopback** — no queda expuesta a la red y se apaga cuando está inactiva.

## ¿Necesito el servidor MCP?

Solo para usar kovra desde un agente de IA. La CLI y el vault funcionan solos;
`kovra-mcp` es el puente opcional para Claude Code y otros clientes MCP.

## ¿Qué pasa si pierdo mi máquina o mi Keychain?

Restaura desde una copia de seguridad de la clave — consulta
[Respaldo y recuperación](/es/operations/backup-recovery/). Haz ese respaldo
*antes* de necesitarlo.

## ¿Qué plataformas son compatibles?

macOS en Apple Silicon es la plataforma de referencia actualmente. Windows (Windows Hello +
Credential Manager) y Linux están en el roadmap.
