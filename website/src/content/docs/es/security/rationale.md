---
title: Secretos en la era de los agentes de IA
description: La justificación de diseño detrás de kovra — el problema, las tensiones, las implicaciones, la solución y un relato honesto de sus riesgos y limitaciones.
tableOfContents:
 minHeadingLevel: 2
 maxHeadingLevel: 2
---

<a class="cta-pdf" href="/secrets-in-the-age-of-ai-agents.pdf" download>↓&nbsp;&nbsp;Descargar en PDF</a>

:::note[Qué es esto]
Este es el **whitepaper de kovra** — un artículo de justificación de diseño, no un paper de investigación. No hace afirmaciones empíricas ni reporta experimentos; argumenta a partir de un problema real y observable y de principios de seguridad establecidos hacia las decisiones específicas que toma kovra — y es honesto sobre lo que esas decisiones **no** garantizan. Cada afirmación de diseño a continuación se corresponde con un comportamiento que la herramienta realmente impone.
:::

## El problema

Un secreto solo es útil cuando algo lo usa. Por eso los secretos pasan su vida en movimiento: escritos en terminales, exportados a shells, incluidos en archivos `.env`, copiados entre un gestor de contraseñas y una configuración, pegados en una docena de líneas `export`. Cada paso deja un residuo — en el historial del shell, en los listados de procesos, en los logs, en un archivo que sobrevive a su propósito. La respuesta habitual de la industria es una lista de verificación: *no pegues eso ahí, rota esto, limpia esos logs.* Las listas de verificación pierden ante la comodidad, de manera predecible, porque el camino inseguro es el fácil y el camino seguro genera fricción.

Entonces un nuevo actor entra en escena: el **agente de codificación con IA**. Lo apuntas a tu repositorio para trabajar más rápido y, al hacerlo, le concedes el mismo alcance que tienes tú. Puede abrir cada `.env`, leer cada configuración, desplazarse por tu historial de shell. Los secretos que estaban meramente *dispersos* ahora son *legibles para un lector automatizado que actúa sobre lo que lee.*

Este es el problema que kovra existe para abordar: **un desarrollador necesita que sus herramientas — y ahora sus agentes — usen secretos, mientras el menor número posible de entidades los ve en texto plano, y mientras el camino fácil sea también el seguro.**

## Las tensiones

El problema es difícil porque es un nudo de tensiones genuinas, no una característica faltante. Nombrarlas con honestidad es la única manera de razonar sobre una solución.

- **Uso versus exposición.** Un secreto debe estar en texto plano *en algún lugar* en el momento de uso — un controlador de base de datos necesita la contraseña real. No puedes usar un valor y garantizar al mismo tiempo que nadie lo ve. El objetivo realista es *reducir el conjunto de entidades que lo ven, y la duración*, no llegar a cero.

- **Conveniencia versus control.** Cada control que agregas (un aviso, una lista de permitidos, una confirmación) es fricción, y la fricción es exactamente lo que empuja a la gente de vuelta al `.env` en texto plano. Un control demasiado pesado no se usa; la seguridad que no se usa no es seguridad.

- **Utilidad del agente versus contención del agente.** Un agente es valioso *porque* puede ejecutar tus comandos y acceder a tus sistemas. La misma capacidad es el riesgo. Bloquearlo de todo lo hace inútil; dejar que lea todo lo hace peligroso.

- **Un principal de confianza que puede ser manipulado.** Los modelos de amenaza clásicos asumen un principal que por defecto es confiable y ocasionalmente traiciona. Un agente LLM es diferente en naturaleza: es **manipulable por el contenido que lee**. Un README envenenado, un mensaje de error fabricado, el docstring de una dependencia maliciosa pueden redirigirlo. El límite teórico de lo que podría filtrar es el mismo que para un humano; la *frecuencia esperada* de un intento es mayor, y el detonante puede ser datos, no intención.

## Las implicaciones

Tomar esas tensiones en serio lleva a varias conclusiones antes de escribir ningún código.

1. **Contención, no prevención.** Dado que un valor debe estar en texto plano en el punto de uso, el objetivo de diseño es reducir la superficie y mantener los valores *más peligrosos* alejados de los lectores *menos confiables* — no prometer lo imposible.

2. **Seguro por defecto, y hacer que lo seguro sea conveniente.** Si el camino seguro es más difícil que pegar un secreto, el camino seguro pierde. La herramienta debe hacer que *usar un secreto correctamente* sea al menos tan fácil como usarlo descuidadamente — de lo contrario, sus propios controles seleccionan ser eludidos.

3. **Los metadatos no son texto plano.** Un agente puede ser enormemente útil sabiendo solo que un secreto *existe*, cómo se llama y cuán sensible es — sin ver jamás su valor. La unidad correcta para darle a un agente son **metadatos más la capacidad de ejecutar cosas**, no el valor.

4. **El límite pertenece a un solo lugar.** Si cada interfaz (CLI, interfaz web, canal del agente) reimplementa "qué está permitido", divergirán, y la implementación más débil se convierte en la política de facto. La regla debe vivir en un núcleo que cada interfaz consume.

5. **Ciertos riesgos son responsabilidad del humano, que los asume deliberadamente.** Hay momentos en que una persona genuinamente necesita un valor en pantalla. La respuesta no es prohibirlo, sino convertirlo en un acto *deliberado, atendido y auditado* — nunca por defecto, nunca algo que un agente pueda desencadenar por sí solo.

## La solución

El modelo de kovra es una respuesta directa a esas implicaciones. Su forma es "**dejar que las cosas usen secretos sin verlos, y poner cada excepción detrás de un acto humano deliberado.**"

### Usar, no ver

Las herramientas y los agentes obtienen valores mediante **inyección**: kovra resuelve un secreto y lo coloca directamente en el entorno de un proceso hijo, nunca en el disco, en `argv` ni en el historial del shell. El proceso *usa* el valor; nada en tu flujo de trabajo lo *muestra*. Un archivo [`.env.refs`](/es/concepts/env-refs/) committable mapea nombres de variables a **coordenadas** — direcciones, no valores — para que el cableado sea compartible mientras los secretos permanecen en el vault.

### Metadatos para agentes, texto plano retenido

Un agente se conecta a través de un servidor MCP bajo un **[alcance](/es/concepts/agent-scope/)** — una capacidad que indica qué puede direccionar y hacer. Lee *metadatos* libremente e *inyecta* secretos en los comandos que ejecuta, para que esos comandos funcionen — pero el texto plano de tus secretos sensibles nunca llega a la ventana de contexto del modelo, que es el único lugar donde un ataque de inyección de prompts podría exfiltrarlo.

### La sensibilidad decide la entrega; el entorno agrega un piso

Cada secreto lleva un [nivel de sensibilidad](/es/concepts/sensitivity/). `low` y `medium` fluyen directamente; `high` requiere un <span class="bioprove">bioProve</span> antes de cualquier entrega; `inject-only` nunca se revela en absoluto. El entorno `prod` agrega un piso estructural encima — un secreto `prod` nace con nivel `high`, no puede empaquetarse para compartir sin conexión, y su texto plano solo puede llegar al contexto de un agente a través de una revelación iniciada por un humano y confirmada.

### Mantener el ejecutor fuera del control del agente

Para el caso más peligroso — inyectar un secreto `high`/`prod` — kovra agrega una **lista de permitidos de ejecutables**: el valor solo puede inyectarse en un ejecutable revisado y en la lista de permitidos, no en un script ad-hoc que el agente acabe de escribir. Este es el punto central. Un proceso que el agente creó puede imprimir su propio entorno; la inyección por sí sola no contiene nada de un ejecutor que el agente controla. La contención proviene de que el ejecutable esté *fuera* de ese control.

### Un núcleo, avisos autoritativos

La política vive en el **núcleo**; la CLI, el wrapper, la interfaz web y el servidor MCP consumen sus decisiones y nunca las rederivan. Cuando se requiere una confirmación, el texto del aviso es construido por el núcleo a partir de los hechos observados — el comando resuelto, la coordenada, la sensibilidad — y nunca es suministrado por el llamador, por lo que un atacante no puede falsificar un aviso tranquilizador.

## La criptografía

kovra utiliza deliberadamente un **conjunto pequeño de primitivas modernas y bien revisadas** del ecosistema de criptografía de Rust, de manera estándar. No hay criptografía propia aquí — el trabajo interesante y específico de kovra vive en la *política*, no en inventar cifrados. Cada elección se corresponde con una tarea. Para la referencia completa — parámetros exactos, tamaños de clave y la biblioteca detrás de cada primitiva — consulta [Criptografía](/es/security/cryptography/).

| Primitiva | Dónde se usa | Por qué esta |
|-----------|--------------|--------------|
| ChaCha20-Poly1305 | Cifrado en reposo (cada entrada del vault) | Autenticado, tiempo constante en software |
| Argon2id | Derivación de clave desde una passphrase | Resistente a fuerza bruta por uso intensivo de memoria |
| BLAKE3 | Huellas digitales de secretos | Rápido, moderno; almacenado truncado |
| ed25519 (RSA para compatibilidad) | Credenciales de par de claves, firma, sellado | Pequeño, rápido, difícil de usar mal |
| age (X25519 + ChaCha20-Poly1305) | Paquetes sin conexión, copia de seguridad de clave maestra | Basado en destinatario, auditado, sin configuraciones riesgosas |
| secrecy / zeroize | Manejo en memoria | Reduce la ventana de texto plano |

### Cifrado en reposo — ChaCha20-Poly1305

Cada entrada en el vault está sellada con **ChaCha20-Poly1305** AEAD. Un AEAD proporciona confidencialidad *e* integridad en un solo paso: un texto cifrado manipulado falla la autenticación en lugar de descifrarse como basura plausible. Lo elegimos sobre AES-GCM porque es **de tiempo constante en software puro** — no depende de la aceleración de hardware AES para evitar side channels de temporización de caché — por lo que se comporta de manera idéntica y segura en cualquier máquina donde se ejecute kovra.

### Derivación de clave desde una passphrase — Argon2id

Cuando un vault está protegido por una passphrase en lugar del keychain del SO, la clave de cifrado se deriva con **Argon2id** — el estándar actual de hashing de contraseñas. Es **resistente a memoria**, lo que hace que la fuerza bruta con GPU y ASIC sea costosa, y la variante `id` resiste tanto los ataques de side channel como los de intercambio tiempo-memoria. Una passphrase humana tiene baja entropía; un KDF resistente a memoria es lo que hace que sea seguro usarla como clave.

### Identidad y huellas digitales — BLAKE3

Los secretos reciben una huella digital con **BLAKE3**, lo que proporciona una identidad estable y resistente a colisiones para un valor *sin revelarlo*. kovra solo almacena y muestra una huella digital **truncada** — nunca una suficientemente larga como para que alguien confirme un valor adivinado comparando su hash. El truncamiento es una medida deliberada contra la fuerza bruta, no un atajo.

### Claves asimétricas — ed25519 (RSA para compatibilidad)

Las credenciales de par de claves tienen como valor predeterminado **ed25519** (EdDSA): claves pequeñas, firmas deterministas rápidas y sin parámetros que puedan salir mal. **RSA** está soportado pero limitado a firma/verificación y compatibilidad SSH — nunca cifrado asimétrico, porque el cifrado RSA invita a errores de padding-oracle. Las claves se generan y almacenan en **formato OpenSSH** (vía `ssh-key`), por lo que interoperan limpiamente con el ssh-agent y las herramientas estándar. El cifrado asimétrico *es exclusivamente* ed25519.

### Compartición sellada y copia de seguridad de clave — age

Los paquetes sin conexión y la copia de seguridad cifrada de la clave maestra están sellados con **age** (acuerdo de clave X25519 + ChaCha20-Poly1305, con codificación ASCII). age es un formato pequeño, auditado y con opinión, **sin configuraciones que puedan usarse mal**, y está **basado en destinatario** — un paquete está sellado para *quién es el destinatario* (su clave pública), que es exactamente la propiedad que kovra quiere: autorización anclada a identidad, no a posesión de un archivo. En modo passphrase, el mismo formato respalda la exportación de la clave maestra, para que una copia de seguridad pueda recuperarse con cualquier implementación de age en una emergencia.

### Higiene de memoria — secrecy y zeroize

No son algoritmos, pero forman parte de la misma disciplina: los valores que contienen secretos están envueltos para que nunca lleguen a logs o salidas de depuración, y su memoria se **zeroiza** al liberarse — reduciendo la ventana en la que un texto plano vive en la memoria del proceso. No cambia el límite de la última milla, pero lo reduce.

## Los riesgos

Una herramienta de seguridad introduce sus propios riesgos; pretender lo contrario sería lo opuesto a la intención de este artículo.

- **La clave maestra es una única raíz de confianza.** Una clave por vault cifra todo. Piérdela y el vault es irrecuperable; filtrala y el cifrado en reposo pierde su sentido. kovra la custodia en el keychain del SO y ofrece una copia de seguridad cifrada y protegida por passphrase — pero la concentración de confianza es real, y la higiene de clave es ahora *tu* hábito más importante.

- **La herramienta es parte de tu cadena de suministro.** kovra se ejecuta en tu máquina con acceso a tus secretos. Un compromiso del binario, sus dependencias o su construcción es un compromiso de todo lo que custodia. Esto es inherente a cualquier gestor de secretos y es la razón de una superficie de dependencias pequeña y una postura conservadora — no es un riesgo que desaparece.

- **Fatiga de confirmación.** Los avisos son un control solo mientras se leen. Pide demasiado y la gente los aprueba de manera refleja, razón por la que kovra activa por *sensibilidad* en lugar de avisar para todo — pero un vault con niveles mal asignados puede igualmente entrenarte a hacer clic en "aprobar" sin mirar.

- **Un aviso convincente sigue siendo una decisión humana.** El texto de aviso autoritativo eleva el listón contra los avisos falsificados, pero el humano aún puede aprobar una acción de aspecto legítimo pero genuinamente mala. La herramienta informa la decisión; no la toma.

## Las limitaciones

Estas no son brechas que se cerrarán en una versión posterior. Son propiedades del problema, y nombrarlas es lo que hace que el resto del artículo sea honesto.

- **La última milla es inevitable.** En el instante de uso, el texto plano vive en la memoria de un proceso, y quien controle ese proceso puede leerlo. Ninguna herramienta puede entregar un valor a tu aplicación mientras impide que la aplicación lo lea. Como todo gestor de secretos serio, kovra **no** intenta evitar que el principal autorizado lea el secreto. Invierte en cifrado, control de acceso, auditoría y reducción de superficie: mitigaciones de "asume la brecha", todas probabilísticas.

- **Para un secreto verdaderamente crítico, la contención vive en *cómo se usa la herramienta*.** La protección robusta para un valor `prod` crítico es que el agente no controle el ejecutable que lo recibe — artefactos de despliegue revisados, no scripts ad-hoc del agente. El vault habilita esa disciplina; no puede imponerla por ti.

- **kovra gobierna el evento de autenticación, no la sesión que abre.** Cuando kovra firma un desafío SSH o inyecta una contraseña de base de datos, gobierna *ese* momento. La sesión que se abre después está fuera de su alcance; kovra no es un proxy de red ni un sandbox de ejecución.

- **Un host comprometido está fuera del alcance.** kovra defiende contra la *dispersión* de secretos y contra que un agente *lea* lo que no debería. No es una defensa contra malware con tus privilegios, un keylogger a nivel de kernel o un atacante que ya controla tu máquina.

- **La amenaza del agente se reduce, no se elimina.** Mantener el texto plano fuera del contexto del modelo cierra la vía de *exfiltración por inyección de prompts* para los secretos sensibles. Eso no hace que un agente sea confiable, y no impide que un agente use mal un valor para el que se le concedió legitimamente el *uso*.

## En resumen

kovra no pretende resolver la gestión de secretos; ese problema tiene un límite demostrado y este artículo lo ha nombrado. Lo que hace es alinear el camino *fácil* con el camino *seguro*, reducir lo que ve un secreto en texto plano y ubicar al agente de IA en el lado correcto de una línea metadatos-versus-texto-plano — con cada excepción convertida en un acto humano deliberado, atendido y auditado. Eso es una mejora significativa y honesta en un entorno donde el lector de tus secretos ahora es automatizado y manipulable. No es, ni pretende ser, la abolición de la última milla.
