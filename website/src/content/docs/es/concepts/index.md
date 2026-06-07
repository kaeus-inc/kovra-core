---
title: Conceptos
description: Las pocas ideas que hacen funcionar a kovra — el vault, las coordenadas, los niveles de sensibilidad, el alcance del agente y el contrato .env.refs.
---

kovra está construido sobre un pequeño conjunto de ideas que encajan entre sí. Aprende estas cinco y el resto de la herramienta se desprende naturalmente.

- **[El vault](/es/concepts/vault/)** — donde viven los secretos: un almacén local cifrado, por proyecto o global, con su llave maestra en el llavero del sistema operativo.
- **[Coordenadas](/es/concepts/coordinates/)** — cómo se direcciona un secreto: `secret:<env>/<component>/<key>`, nunca por su valor.
- **[Niveles de sensibilidad](/es/concepts/sensitivity/)** — qué tan protector es kovra con cada secreto: `low`, `medium`, `high` e `inject-only` — más lo que el entorno `prod` agrega encima.
- **[Alcance del agente](/es/concepts/agent-scope/)** — el límite de capacidades que permite a un agente de IA *usar* secretos sin *ver* los sensibles.
- **[El contrato `.env.refs`](/es/concepts/env-refs/)** — el archivo que se puede commitear y mapea los nombres de variables de entorno a coordenadas, guardando direcciones pero nunca valores.

## El modelo en una frase

Tú **direccionas** un secreto por su coordenada, el vault lo **custodia**, su **sensibilidad** decide cómo puede entregarse, tu **alcance** decide quién puede solicitarlo, y `.env.refs` lo **conecta** a los procesos que lo necesitan — de modo que un valor se *usa* sin nunca ser *visto*.
