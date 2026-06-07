---
title: Glosario
description: El vocabulario de kovra en un solo lugar.
---

**bioProve** — la palabra de kovra para una verificación biométrica asistida (Touch ID en macOS,
Windows Hello en Windows) que autoriza una acción sensible. Se usa como verbo:
"kovra te pide que lo bioPruebas."

**Coordinate** — la dirección de un secreto, `secret:<env>/<component>/<key>` (p. ej.
`secret:dev/db/password`). Consulta [Coordenadas](/es/concepts/coordinates/).

**Entorno / componente / clave** — los tres segmentos de una coordenada: la etapa de
despliegue (`dev`, `prod`, …), la parte del sistema y el secreto específico.

**Vault** — el almacén local y cifrado de tus secretos. Uno global más uno por
proyecto. Consulta [El vault](/es/concepts/vault/).

**Clave maestra** — la clave de 256 bits que cifra cada entrada del vault; custodiada
en el keyring del SO (o derivada en modo passphrase). La raíz de confianza.

**Sensitivity** — el nivel de protección que kovra aplica a un secreto: `low`, `medium`, `high`
o `inject-only`. Consulta [Niveles de sensibilidad](/es/concepts/sensitivity/).

**Scope** — el límite de capacidades bajo el que opera una sesión (especialmente un
agente): qué operaciones, proyectos y entornos puede direccionar. Consulta
[Alcance del agente](/es/concepts/agent-scope/).

**Operación** — lo que una entidad llamante puede hacer con un valor: leer
**metadatos**, **inyectar** (entregar a través de un proceso) o **revelar** (devolver
el texto plano al llamante).

**Reveal** — traer un valor en texto plano de vuelta a manos del llamante. La ruta
protegida; nunca permitida para `inject-only`, y nunca a un agente para `high`/`prod`.

**Injection** — entregar un valor *a través* de una operación al entorno de un proceso
hijo; el valor nunca vuelve al llamante. Consulta
[El contrato de .env.refs](/es/concepts/env-refs/).

**Literal** — una entrada del vault que contiene un valor real (a diferencia de una
referencia o una credencial tipada).

**Reference** — una entrada del vault que apunta a un valor en un gestor de secretos
en la nube (`azure-kv://`, `aws-sm://`), resuelta en tiempo de ejecución bajo tu propia
identidad. Consulta [Referencias en la nube](/es/guides/references/).

**Fingerprint** — un hash BLAKE3 corto y truncado de un valor, mostrado en `list` para
confirmar "¿es este el mismo valor?" sin revelarlo.

**Package** — un paquete cifrado de secretos que no son de producción, sellado con la
clave del destinatario para compartir. Consulta [Paquetes sellados](/es/guides/sharing/).

**Access token** — una credencial separada, de canal secundario, que autoriza el
consumo desatendido de las entradas sensibles de un paquete.

**Allowlist** — el conjunto de ejecutables revisados en los que puede inyectarse un
valor `high`/`prod`. Independiente del prompt de confirmación.

**Broker** — el canal de confirmación de kovra: un prompt biométrico, o el broker de
archivos multiplataforma `kovra approve` cuando la biometría no está disponible.

**`.env.refs`** — el archivo committable que mapea nombres de variables de entorno a
coordenadas — direcciones, nunca valores.

**`agent.toml`** — el archivo en la raíz del vault que delimita el alcance del
[ssh-agent gobernado](/es/guides/ssh-agent/).

**MCP** — el Model Context Protocol; la forma en que kovra expone herramientas
gobernadas a los agentes de IA. Consulta [kovra sobre MCP](/es/agents/mcp/).
