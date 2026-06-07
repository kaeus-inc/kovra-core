---
title: Referencia de herramientas MCP
description: El conjunto completo de herramientas que kovra expone sobre MCP, lo que devuelve cada una y la política que las rige.
---

Estas son las herramientas que kovra expone a un cliente MCP como Claude Code. Cada
una pasa por la decisión de política única de kovra; la tabla indica qué se devuelve
y la regla que lo rige. **Ninguna herramienta devuelve jamás un texto plano sensible**
— `reveal` es la única herramienta que devuelve valores, y solo dentro de una excepción
muy acotada.

Las coordenadas siguen la [gramática de coordenadas](/es/concepts/coordinates/);
cualquier cosa fuera del [alcance](/es/concepts/agent-scope/) de la sesión es
**indireccionable** y nunca aparece.

## Leer metadatos

| Herramienta | Devuelve | Regla que la rige |
| --- | --- | --- |
| `list` | Metadatos de cada secreto direccionable — coordenada, sensibilidad, modo, huella digital, indicadores | Los valores nunca se devuelven; los secretos fuera del alcance están ausentes |
| `status` | Metadatos de una coordenada | Produce error si la coordenada no es direccionable en esta sesión |
| `fingerprint` | Una huella digital corta y **truncada** de un valor | Truncada por diseño — suficiente para comparar, nunca para reconstruir |

## Usar un valor

| Herramienta | Devuelve | Regla que la rige |
| --- | --- | --- |
| `inject_run` | `{status, stdout, stderr}` con los valores del vault **enmascarados** | Los valores van al entorno del proceso hijo, nunca al contexto del llamador. `high`/`prod` requiere un ejecutable en la lista de permitidos **y** un `kovra approve` asistido |
| `reveal` | El valor en texto plano, al contexto | Permitido **solo** para un secreto marcado como revelable que sea no `prod` y no `high`. `prod` / `high` / `inject-only` nunca se devuelven |

## Crear y gestionar

| Herramienta | Devuelve | Regla que la rige |
| --- | --- | --- |
| `set` | Los nuevos metadatos (no el valor) | Un secreto `prod` nace como `high` |
| `generate` | Solo metadatos | El valor se genera en el servidor y se almacena; nunca se devuelve |
| `edit_metadata` | Metadatos actualizados | Edita sensibilidad / descripción / `revealable` / referencia; **reducir** la sensibilidad se audita por separado |
| `delete` | Confirmación | Produce error si la coordenada no es direccionable en esta sesión |

## El patrón detrás de la tabla

Tres propiedades se mantienen en cada fila, y vale la pena nombrarlas porque son la
razón por la que se puede confiar en un agente con estas herramientas:

1. **Leer metadatos siempre es seguro** — listar, diagnosticar y obtener huellas
 digitales nunca tocan un valor.
2. **Usar un valor nunca lo revela** — `inject_run` entrega un secreto *a través de*
 un proceso y lo enmascara a la salida.
3. **Crear un valor nunca lo expone** — `set` y `generate` devuelven solo metadatos,
 por lo que una credencial recién generada nunca pasa por el contexto del modelo.

La única excepción — `reveal` — es deliberadamente la herramienta más restringida de
todas. Consulta [kovra sobre MCP](/es/agents/mcp/) para la versión narrativa y
[el proceso de decisión](/es/security/decision/) para saber exactamente cómo se
juzga cada llamada.
