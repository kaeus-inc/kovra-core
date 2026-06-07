---
title: Modelo de amenaza
description: Qué protege kovra, contra qué adversarios protege y — con honestidad — qué queda fuera del alcance.
---

kovra está construido alrededor de un único trabajo: permitir que tus herramientas y agentes de IA **usen** secretos sin **ver** los sensibles. Esta página lo establece con claridad — los activos que custodia, los adversarios contra los que está diseñado y los límites que **no** cruza. Una herramienta de seguridad que exagera sus garantías es peor que una que es honesta sobre ellas.

## Activos

- **Valores secretos** — literales, las mitades privadas de [pares de claves](/es/guides/keypairs/) y semillas [TOTP](/es/guides/totp/).
- **La clave maestra** — la raíz de confianza que cifra todo el vault.
- **La integridad del rastro de auditoría** — un registro fiel de lo que ocurrió.

## Para qué está diseñado kovra

- **Un agente de IA comprometido o secuestrado mediante inyección de prompts que exfiltra secretos.** Un agente opera bajo un [alcance](/es/concepts/agent-scope/) y nunca recibe el texto plano de un secreto `high`, `prod` o `inject-only`. Las coordenadas fuera del alcance son *no direccionables* — no existen para esa sesión, por lo que un agente manipulado no puede acceder a lo que nunca se le concedió.
- **Un programa que lee de vuelta un valor que se le dio.** Enviar un valor `high`/`prod` a un programa que el propio agente escribió anularía el propósito, por lo que esas inyecciones solo están permitidas hacia un ejecutable **revisado y en la lista de permitidos**.
- **Texto plano que se filtra a los lugares donde habitualmente se filtra.** Los valores nunca llegan a un log, al disco, en argv, al historial del shell ni a la ventana de contexto de un modelo.
- **Un secreto comprometido accidentalmente.** Un [hook de pre-commit](/es/operations/git-hooks/) escanea los cambios en staging y bloquea el commit.
- **Un paquete compartido que cae en las manos equivocadas.** Un [paquete sellado](/es/guides/sharing/) está cifrado para la clave del destinatario, y sus entradas sensibles necesitan adicionalmente un token fuera de banda — la posesión del archivo no es acceso.
- **Una laptop perdida o robada, o una inspección casual del disco.** Cada registro está cifrado en reposo bajo la clave maestra (custodiada en el keyring del SO, o derivada con Argon2id), y las coordenadas no están expuestas como nombres de archivo en texto plano.

## Garantías dentro del alcance

- Las **revelaciones** e **inyecciones** sensibles requieren un <span class="bioprove">bioProve</span> deliberado — nunca ocurren solas, y nunca a petición de un agente para `high`/`prod`.
- El aviso de confirmación es construido por kovra a partir de la solicitud **real**, por lo que no puede ser falsificado por un llamador.
- El rastro de auditoría registra cada resultado **sin** almacenar un valor ni una huella digital completa.

## Fuera del alcance — los límites honestos

- **La última milla.** Una vez que un valor es entregado al proceso que lo necesita, vive en la memoria de ese proceso bajo las reglas de ese programa. kovra asegura la *custodia y la entrega*, no lo que un programa hace con un valor después de tenerlo.
- **Un host comprometido.** kovra confía en el keyring del sistema operativo, el subsistema biométrico y la integridad propia de la máquina. Un compromiso a nivel de root, un keylogger a nivel de kernel o malware leyendo la memoria de otro proceso está fuera de lo que puede defender una herramienta en espacio de usuario.
- **Un humano (o programa) que tú autorizas.** kovra hace que una acción sensible sea **deliberada y atribuible** — no la hace imposible. Si haces <span class="bioprove">bioProve</span> de una acción mala, o incluyes un programa malicioso en la lista de permitidos, kovra lo ejecutará y lo registrará.
- **Autenticidad del remitente en paquetes.** Un [paquete sellado](/es/guides/sharing/) demuestra *quién puede leerlo*, no *quién lo escribió* — es confidencialidad, no una firma.
- **Confianza en el proveedor de nube.** Una [referencia de nube](/es/guides/references/) se resuelve bajo tu identidad de proveedor; el proveedor aún ve lo que siempre vería.

## Supuestos de confianza

kovra asume: tu máquina y tu SO no están ya comprometidos; el keyring del SO y el aviso biométrico se comportan como la plataforma pretende; y las bibliotecas criptográficas verificadas sobre las que se construye son sólidas. **No implementa criptografía propia** — consulta [Criptografía](/es/security/cryptography/).
